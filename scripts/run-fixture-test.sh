#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${LAB_ROOT:-/lab}"
DB="$LAB_ROOT/audit/audit.db"
REPORT="$LAB_ROOT/audit/matches.jsonl"
CSV="$LAB_ROOT/audit/matches.csv"
SECOND_REPORT="$LAB_ROOT/audit/matches-second.jsonl"
SECOND_CSV="$LAB_ROOT/audit/matches-second.csv"
MIN_SIZE_REPORT="$LAB_ROOT/audit/matches-min-size.jsonl"
MIN_SIZE_CSV="$LAB_ROOT/audit/matches-min-size.csv"
FOLLOW_LINKS_REPORT="$LAB_ROOT/audit/matches-follow-links.jsonl"
FOLLOW_LINKS_CSV="$LAB_ROOT/audit/matches-follow-links.csv"
THREADS_REPORT="$LAB_ROOT/audit/matches-threads.jsonl"
THREADS_CSV="$LAB_ROOT/audit/matches-threads.csv"
INDEX_METRICS="$LAB_ROOT/audit/index-metrics.json"
SCAN_METRICS="$LAB_ROOT/audit/scan-metrics.json"
MIN_SIZE_METRICS="$LAB_ROOT/audit/scan-min-size-metrics.json"
FOLLOW_LINKS_METRICS="$LAB_ROOT/audit/scan-follow-links-metrics.json"
THREADS_METRICS="$LAB_ROOT/audit/scan-threads-metrics.json"
SECOND_SCAN_METRICS="$LAB_ROOT/audit/scan-second-metrics.json"
INDEX_PROGRESS_LOG="$LAB_ROOT/audit/index-progress.stderr"
SCAN_PROGRESS_LOG="$LAB_ROOT/audit/scan-progress.stderr"
SUMMARY="$LAB_ROOT/audit/db-summary.json"
SUMMARY_ROOT="$LAB_ROOT/audit/db-summary-root.json"
SUMMARY_LIST="$LAB_ROOT/audit/db-summary-list.json"

mkdir -p "$LAB_ROOT/audit"

python3 /workspace/scripts/generate-fixture.py \
  --lab-root "$LAB_ROOT" \
  --small-files "${SMALL_FILES:-5000}" \
  --large-files "${LARGE_FILES:-8}" \
  --large-min-mib "${LARGE_MIN_MIB:-1}" \
  --large-max-mib "${LARGE_MAX_MIB:-4}" \
  --force

python3 /workspace/scripts/verify-fixture.py

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/sensitive-paths.txt" \
  --db "$DB" \
  --progress-every-files 1 \
  > "$INDEX_METRICS" \
  2> "$INDEX_PROGRESS_LOG"

grep -q "index progress:" "$INDEX_PROGRESS_LOG"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$INDEX_METRICS" \
  --require-field files_per_second \
  --require-field elapsed_ms

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$REPORT" \
  --csv "$CSV" \
  --progress-every-files 1000 \
  > "$SCAN_METRICS" \
  2> "$SCAN_PROGRESS_LOG"
scan_status=$?
set -e
if [[ "$scan_status" != "2" ]]; then
  echo "expected scan-dest to exit 2 when fixture leaks are found, got $scan_status" >&2
  exit 1
fi

grep -q "scan progress:" "$SCAN_PROGRESS_LOG"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$SCAN_METRICS" \
  --require-field files_per_second \
  --require-field files_seen \
  --require-field matches_found

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-leaks.tsv" \
  --report "$REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$MIN_SIZE_REPORT" \
  --csv "$MIN_SIZE_CSV" \
  --min-size-bytes 32 \
  > "$MIN_SIZE_METRICS"
min_size_status=$?
set -e
if [[ "$min_size_status" != "2" ]]; then
  echo "expected min-size scan-dest to exit 2 when fixture leaks are found, got $min_size_status" >&2
  exit 1
fi

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$MIN_SIZE_METRICS" \
  --require-field files_per_second \
  --require-field files_skipped_min_size

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-leaks.tsv" \
  --report "$MIN_SIZE_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest" \
  --min-size-bytes 32

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$FOLLOW_LINKS_REPORT" \
  --csv "$FOLLOW_LINKS_CSV" \
  --follow-links \
  > "$FOLLOW_LINKS_METRICS"
follow_links_status=$?
set -e
if [[ "$follow_links_status" != "2" ]]; then
  echo "expected follow-links scan-dest to exit 2 when fixture leaks are found, got $follow_links_status" >&2
  exit 1
fi

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$FOLLOW_LINKS_METRICS" \
  --require-field files_per_second \
  --require-field matches_found

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-leaks.tsv" \
  --extra-expected "$LAB_ROOT/manifests/expected-symlink-leaks.tsv" \
  --report "$FOLLOW_LINKS_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$THREADS_REPORT" \
  --csv "$THREADS_CSV" \
  --threads 4 \
  > "$THREADS_METRICS"
threads_status=$?
set -e
if [[ "$threads_status" != "2" ]]; then
  echo "expected threaded scan-dest to exit 2 when fixture leaks are found, got $threads_status" >&2
  exit 1
fi

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$THREADS_METRICS" \
  --require-field files_per_second \
  --require-field matches_found

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-leaks.tsv" \
  --report "$THREADS_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$SECOND_REPORT" \
  --csv "$SECOND_CSV" \
  > "$SECOND_SCAN_METRICS"
second_status=$?
set -e
if [[ "$second_status" != "2" ]]; then
  echo "expected second scan-dest to exit 2 when fixture leaks are found, got $second_status" >&2
  exit 1
fi

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$SECOND_SCAN_METRICS" \
  --require-field files_per_second \
  --require-field cache_hits

cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$DB" > "$SUMMARY"
cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$DB" --root "$LAB_ROOT/dest" > "$SUMMARY_ROOT"
cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$DB" --list "$LAB_ROOT/manifests/sensitive-paths.txt" > "$SUMMARY_LIST"

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY" \
  --require-field index.sensitive_files \
  --require-field index.distinct_sizes \
  --require-field scan_runs.total \
  --require-field scan_runs.latest_finished

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY_ROOT" \
  --require-field destination.root \
  --require-field destination.cache_rows \
  --require-field destination.cache_full_hash_rows \
  --require-field destination.latest_finished

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY_LIST" \
  --require-field manifest.listed_paths \
  --require-field manifest.already_indexed \
  --require-field manifest.missing_from_index

echo "fixture test passed"
