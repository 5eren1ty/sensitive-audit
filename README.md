# sensitive-audit

`sensitive-audit` checks whether known sensitive file content appears in a copied directory tree, even when files were renamed or moved.

It is intended for Linux environments where:

- the source tree contains files that must not appear in a copy
- you have a list of sensitive source paths
- destination paths may differ from source paths
- the copy process itself is outside your control
- performance matters on very large trees

The tool indexes sensitive source files by content hash, then scans the destination using a staged filter:

```text
file size -> partial BLAKE3 hash -> full BLAKE3 hash confirmation
```

Most destination files are rejected by size alone. Confirmed matches are written as JSONL and optionally CSV.

## Status

This is a practical prototype suitable for validation and controlled operational testing. It has been tested with a generated fixture containing renamed sensitive leaks, same-size non-matches, and same-prefix non-matches.

## Assumptions

- Use one SQLite database per sensitive source root.
- Use the same `--partial-bytes` value for indexing and scanning.
- Pass destination roots consistently; cache scopes use the root path string.
- Store the SQLite database and reports on local storage when possible, not on the NFS tree being scanned.
- `scan-dest` exits with code `2` when matches are found. That is intentional for CI and batch jobs.
- SQLite metadata is committed in batches. The default `--commit-every 1000` limits data loss on interruption without committing every file.

For RHEL8/NFS deployments, expect traversal, metadata, and file-open latency to matter more than raw hash speed. Tune by measuring on the real mounted filesystems.

## Build

Prebuilt binaries are attached to GitHub Releases:

```bash
curl -L -o sensitive-audit.tar.gz \
  https://github.com/5eren1ty/sensitive-audit/releases/download/v0.1.0/sensitive-audit-v0.1.0-x86_64-rhel8.tar.gz
tar -xzf sensitive-audit.tar.gz
sudo install -m 0755 sensitive-audit-v0.1.0-x86_64-rhel8/sensitive-audit /usr/local/bin/sensitive-audit
```

Replace `v0.1.0` with the release tag you want to install.

Release binaries are built inside a UBI8 container for RHEL8-compatible Linux userspace. You can also build from source:

Install Rust on the target or build host, then:

```bash
git clone <repo-url>
cd sensitive-audit
cargo build --release
```

The binary will be:

```bash
target/release/sensitive-audit
```

Copy that binary to the target host if you build elsewhere.

## Sensitive Path List

Create a UTF-8 text file containing paths relative to the sensitive source root:

```text
finance/payroll/export.csv
users/alice/private.key
archive/client-a/secrets.tar
```

Blank lines and lines starting with `#` are ignored.

## Basic Usage

Index sensitive source files:

```bash
sensitive-audit index-sensitive \
  --root /mnt/source \
  --list sensitive-paths.txt \
  --db /var/tmp/sensitive-audit/audit.db \
  --min-size-bytes 0
```

Scan the destination:

```bash
sensitive-audit scan-dest \
  --root /mnt/copied-data \
  --db /var/tmp/sensitive-audit/audit.db \
  --report /var/tmp/sensitive-audit/matches.jsonl \
  --csv /var/tmp/sensitive-audit/matches.csv \
  --min-size-bytes 0
```

Use `--min-size-bytes` to ignore small sensitive files and small destination files. For example, `--min-size-bytes 4096` will not index sensitive files below 4 KiB and will skip destination files below 4 KiB while scanning.

By default, `scan-dest` skips symbolic links. Use `--follow-links` only when symlink targets are intentionally in audit scope. A followed symlink can point outside the destination root, which can add NFS overhead and scan content you did not mean to include.

Summarize the database:

```bash
sensitive-audit db-summary --db /var/tmp/sensitive-audit/audit.db
```

Prune destination metadata and hash-cache rows that were not seen in the latest scan of a root:

```bash
sensitive-audit prune-dest \
  --db /var/tmp/sensitive-audit/audit.db \
  --root /mnt/copied-data
```

`prune-dest` only trusts finished scans. If a scan was interrupted, its partial run is ignored for pruning.

## Outputs

JSONL report, one object per confirmed match:

```json
{"dest_path":"/mnt/copied-data/renamed/file.bin","source_path":"/mnt/source/sensitive/file.bin","size":1234,"hash_algorithm":"blake3","full_hash":"..."}
```

CSV report columns:

```text
dest_path,source_path,size,hash_algorithm,full_hash
```

Metrics are printed to stdout as JSON. Important scan fields:

- `files_seen`: destination files visited
- `metadata_cached`: destination file metadata rows persisted
- `files_skipped_min_size`: files rejected by `--min-size-bytes`
- `files_skipped_size`: files rejected by size
- `size_candidates`: files whose size matched at least one sensitive file
- `partial_hashed`: files read for partial-hash filtering
- `partial_candidates`: files whose size and partial hash matched sensitive content
- `full_hashed`: extra full-file hash passes after partial-hash filtering
- `matches_found`: confirmed sensitive content matches
- `bytes_hashed`: bytes read for hashing in that run

On a second unchanged scan, `bytes_hashed` can be `0`. That means the scanner still walked the destination and refreshed metadata, but all size-candidate hashes were reused from the SQLite cache because path, size, mtime, root, and `partial_bytes` matched previous cached records.

## Validation With Docker

The repository includes a Docker-based fixture harness for Windows or other development hosts.

Build the lab image:

```bash
docker compose build
```

Run the end-to-end fixture test:

```bash
docker compose run --rm audit-lab bash /workspace/scripts/run-fixture-test.sh
```

The fixture generator creates normal copied files plus deterministic edge cases:

- small sensitive file copied under a different destination path
- large sensitive file copied under a different destination path
- same-size destination file with different content
- large destination file with the same first 64 KiB as a sensitive file but a different tail

The comparison step verifies that only expected sensitive leaks are reported.

For faster local filesystem behavior, use the named-volume override:

```bash
docker compose -f docker-compose.yml -f docker-compose.linux-volume.yml run --rm audit-lab bash /workspace/scripts/run-fixture-test.sh
```

## RHEL8 Notes

A UBI8 compatibility image is included:

```bash
docker compose -f docker-compose.yml -f docker-compose.ubi8.yml build
```

The UBI8 image is useful for userland compatibility checks, but it does not reproduce NFS performance unless the scanned directories are actual NFS mounts. For production timing, test on the real RHEL8 host and NFS mounts.

## Maintainer Release Process

Create and push a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions will build the RHEL8-compatible binary in UBI8 and attach a `.tar.gz` plus `.sha256` checksum to the GitHub Release.
