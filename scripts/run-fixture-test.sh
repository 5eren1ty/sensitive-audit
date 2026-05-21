#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${LAB_ROOT:-/lab}"
DB="$LAB_ROOT/audit/audit.db"
DIR_DB="$LAB_ROOT/audit/audit-directory.db"
ABS_DB="$LAB_ROOT/audit/audit-absolute.db"
MIXED_DB="$LAB_ROOT/audit/audit-mixed.db"
ABS_MIXED_DB="$LAB_ROOT/audit/audit-absolute-mixed.db"
MISSING_DB="$LAB_ROOT/audit/audit-missing.db"
NON_FILE_DB="$LAB_ROOT/audit/audit-non-file.db"
MIN_SIZE_INDEX_DB="$LAB_ROOT/audit/audit-min-size-index.db"
REPORT="$LAB_ROOT/audit/matches.jsonl"
CSV="$LAB_ROOT/audit/matches.csv"
DIR_REPORT="$LAB_ROOT/audit/matches-directory.jsonl"
DIR_CSV="$LAB_ROOT/audit/matches-directory.csv"
ABS_REPORT="$LAB_ROOT/audit/matches-absolute.jsonl"
ABS_CSV="$LAB_ROOT/audit/matches-absolute.csv"
MIXED_REPORT="$LAB_ROOT/audit/matches-mixed.jsonl"
MIXED_CSV="$LAB_ROOT/audit/matches-mixed.csv"
ABS_MIXED_REPORT="$LAB_ROOT/audit/matches-absolute-mixed.jsonl"
ABS_MIXED_CSV="$LAB_ROOT/audit/matches-absolute-mixed.csv"
SECOND_REPORT="$LAB_ROOT/audit/matches-second.jsonl"
SECOND_CSV="$LAB_ROOT/audit/matches-second.csv"
MIN_SIZE_REPORT="$LAB_ROOT/audit/matches-min-size.jsonl"
MIN_SIZE_CSV="$LAB_ROOT/audit/matches-min-size.csv"
FOLLOW_LINKS_REPORT="$LAB_ROOT/audit/matches-follow-links.jsonl"
FOLLOW_LINKS_CSV="$LAB_ROOT/audit/matches-follow-links.csv"
THREADS_REPORT="$LAB_ROOT/audit/matches-threads.jsonl"
THREADS_CSV="$LAB_ROOT/audit/matches-threads.csv"
INDEX_METRICS="$LAB_ROOT/audit/index-metrics.json"
DIR_INDEX_METRICS="$LAB_ROOT/audit/index-directory-metrics.json"
ABS_INDEX_METRICS="$LAB_ROOT/audit/index-absolute-metrics.json"
MIXED_INDEX_METRICS="$LAB_ROOT/audit/index-mixed-metrics.json"
ABS_MIXED_INDEX_METRICS="$LAB_ROOT/audit/index-absolute-mixed-metrics.json"
MISSING_INDEX_METRICS="$LAB_ROOT/audit/index-missing-metrics.json"
NON_FILE_INDEX_METRICS="$LAB_ROOT/audit/index-non-file-metrics.json"
MIN_SIZE_INDEX_METRICS="$LAB_ROOT/audit/index-min-size-filter-metrics.json"
SCAN_METRICS="$LAB_ROOT/audit/scan-metrics.json"
DIR_SCAN_METRICS="$LAB_ROOT/audit/scan-directory-metrics.json"
ABS_SCAN_METRICS="$LAB_ROOT/audit/scan-absolute-metrics.json"
MIXED_SCAN_METRICS="$LAB_ROOT/audit/scan-mixed-metrics.json"
ABS_MIXED_SCAN_METRICS="$LAB_ROOT/audit/scan-absolute-mixed-metrics.json"
MIN_SIZE_METRICS="$LAB_ROOT/audit/scan-min-size-metrics.json"
FOLLOW_LINKS_METRICS="$LAB_ROOT/audit/scan-follow-links-metrics.json"
THREADS_METRICS="$LAB_ROOT/audit/scan-threads-metrics.json"
SECOND_SCAN_METRICS="$LAB_ROOT/audit/scan-second-metrics.json"
INDEX_PROGRESS_LOG="$LAB_ROOT/audit/index-progress.stderr"
SCAN_PROGRESS_LOG="$LAB_ROOT/audit/scan-progress.stderr"
SUMMARY="$LAB_ROOT/audit/db-summary.json"
SUMMARY_ROOT="$LAB_ROOT/audit/db-summary-root.json"
SUMMARY_LIST="$LAB_ROOT/audit/db-summary-list.json"
SUMMARY_DIR_LIST="$LAB_ROOT/audit/db-summary-directory-list.json"
SUMMARY_ABS_LIST="$LAB_ROOT/audit/db-summary-absolute-list.json"
SUMMARY_MIXED_LIST="$LAB_ROOT/audit/db-summary-mixed-list.json"
SUMMARY_ABS_MIXED_LIST="$LAB_ROOT/audit/db-summary-absolute-mixed-list.json"

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
grep -q "files_per_second=" "$INDEX_PROGRESS_LOG"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$INDEX_METRICS" \
  --require-field files_per_second \
  --require-field elapsed_ms \
  --require-field manifest_entries_seen \
  --require-field files_discovered

set +e
cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/invalid-absolute-with-root.txt" \
  --db "$LAB_ROOT/audit/invalid-root.db" \
  > /dev/null 2> /dev/null
invalid_absolute_status=$?
cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --list "$LAB_ROOT/manifests/invalid-relative-without-root.txt" \
  --db "$LAB_ROOT/audit/invalid-absolute.db" \
  > /dev/null 2> /dev/null
invalid_relative_status=$?
cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --list "$LAB_ROOT/manifests/sensitive-absolute-paths.txt" \
  --db "$DB" \
  --no-clear-existing \
  > /dev/null 2> /dev/null
mode_mismatch_status=$?
cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/invalid-mixed-with-root.txt" \
  --db "$LAB_ROOT/audit/invalid-mixed-root.db" \
  > /dev/null 2> /dev/null
invalid_mixed_root_status=$?
cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --list "$LAB_ROOT/manifests/invalid-mixed-without-root.txt" \
  --db "$LAB_ROOT/audit/invalid-mixed-absolute.db" \
  > /dev/null 2> /dev/null
invalid_mixed_absolute_status=$?
set -e
if [[ "$invalid_absolute_status" == "0" ]]; then
  echo "expected absolute manifest entry with --root to fail" >&2
  exit 1
fi
if [[ "$invalid_relative_status" == "0" ]]; then
  echo "expected relative manifest entry without --root to fail" >&2
  exit 1
fi
if [[ "$mode_mismatch_status" == "0" ]]; then
  echo "expected --no-clear-existing mode mismatch to fail" >&2
  exit 1
fi
if [[ "$invalid_mixed_root_status" == "0" ]]; then
  echo "expected mixed absolute/relative manifest with --root to fail" >&2
  exit 1
fi
if [[ "$invalid_mixed_absolute_status" == "0" ]]; then
  echo "expected mixed absolute/relative manifest without --root to fail" >&2
  exit 1
fi

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/sensitive-directory-paths.txt" \
  --db "$DIR_DB" \
  > "$DIR_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$DIR_INDEX_METRICS" \
  --require-field manifest_directory_entries \
  --require-field duplicate_files_skipped \
  --require-field files_discovered \
  --expect-ge manifest_directory_entries=2 \
  --expect-ge manifest_file_entries=1 \
  --expect-ge duplicate_files_skipped=1 \
  --expect-gt files_indexed=0

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DIR_DB" \
  --report "$DIR_REPORT" \
  --csv "$DIR_CSV" \
  > "$DIR_SCAN_METRICS"
dir_scan_status=$?
set -e
if [[ "$dir_scan_status" != "2" ]]; then
  echo "expected directory manifest scan-dest to exit 2 when fixture leaks are found, got $dir_scan_status" >&2
  exit 1
fi

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-directory-leaks.tsv" \
  --report "$DIR_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/sensitive-mixed-paths.txt" \
  --db "$MIXED_DB" \
  > "$MIXED_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$MIXED_INDEX_METRICS" \
  --require-field manifest_directory_entries \
  --require-field manifest_file_entries \
  --require-field duplicate_files_skipped \
  --require-field skipped_non_files \
  --expect-ge manifest_directory_entries=3 \
  --expect-ge manifest_file_entries=2 \
  --expect-ge duplicate_files_skipped=3 \
  --expect-ge skipped_non_files=1 \
  --expect-gt files_indexed=0

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$MIXED_DB" \
  --report "$MIXED_REPORT" \
  --csv "$MIXED_CSV" \
  > "$MIXED_SCAN_METRICS"
mixed_scan_status=$?
set -e
if [[ "$mixed_scan_status" != "2" ]]; then
  echo "expected mixed manifest scan-dest to exit 2 when fixture leaks are found, got $mixed_scan_status" >&2
  exit 1
fi

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-mixed-leaks.tsv" \
  --report "$MIXED_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/missing-relative-paths.txt" \
  --db "$MISSING_DB" \
  > "$MISSING_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$MISSING_INDEX_METRICS" \
  --require-field missing_paths \
  --require-field files_indexed \
  --expect-ge missing_paths=2 \
  --expect-eq files_indexed=1

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/non-file-relative-paths.txt" \
  --db "$NON_FILE_DB" \
  > "$NON_FILE_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$NON_FILE_INDEX_METRICS" \
  --require-field skipped_non_files \
  --require-field manifest_directory_entries \
  --expect-ge skipped_non_files=1 \
  --expect-ge manifest_directory_entries=1 \
  --expect-eq files_indexed=0 \
  --expect-eq files_discovered=0

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --root "$LAB_ROOT/source" \
  --list "$LAB_ROOT/manifests/sensitive-directory-paths.txt" \
  --db "$MIN_SIZE_INDEX_DB" \
  --min-size-bytes 32 \
  > "$MIN_SIZE_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$MIN_SIZE_INDEX_METRICS" \
  --require-field files_skipped_min_size \
  --expect-ge files_skipped_min_size=1 \
  --expect-gt files_indexed=0

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$MIN_SIZE_INDEX_DB" \
  --report "$LAB_ROOT/audit/matches-min-size-index.jsonl" \
  --csv "$LAB_ROOT/audit/matches-min-size-index.csv" \
  > "$LAB_ROOT/audit/scan-min-size-index-metrics.json"
min_size_index_scan_status=$?
set -e
if [[ "$min_size_index_scan_status" != "2" ]]; then
  echo "expected min-size index scan-dest to exit 2 when fixture leaks are found, got $min_size_index_scan_status" >&2
  exit 1
fi

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-directory-leaks.tsv" \
  --report "$LAB_ROOT/audit/matches-min-size-index.jsonl" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest" \
  --min-size-bytes 32

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --list "$LAB_ROOT/manifests/sensitive-absolute-paths.txt" \
  --db "$ABS_DB" \
  > "$ABS_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$ABS_INDEX_METRICS" \
  --require-field manifest_directory_entries \
  --require-field manifest_file_entries \
  --require-field files_discovered \
  --expect-ge manifest_directory_entries=1 \
  --expect-ge manifest_file_entries=1 \
  --expect-gt files_indexed=0

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$ABS_DB" \
  --report "$ABS_REPORT" \
  --csv "$ABS_CSV" \
  > "$ABS_SCAN_METRICS"
abs_scan_status=$?
set -e
if [[ "$abs_scan_status" != "2" ]]; then
  echo "expected absolute manifest scan-dest to exit 2 when fixture leaks are found, got $abs_scan_status" >&2
  exit 1
fi

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-absolute-leaks.tsv" \
  --report "$ABS_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

cargo run --manifest-path /workspace/Cargo.toml -- index-sensitive \
  --list "$LAB_ROOT/manifests/sensitive-absolute-mixed-paths.txt" \
  --db "$ABS_MIXED_DB" \
  > "$ABS_MIXED_INDEX_METRICS"

python3 /workspace/scripts/validate-metrics.py \
  --metrics "$ABS_MIXED_INDEX_METRICS" \
  --require-field manifest_directory_entries \
  --require-field manifest_file_entries \
  --require-field duplicate_files_skipped \
  --expect-ge manifest_directory_entries=2 \
  --expect-ge manifest_file_entries=2 \
  --expect-ge duplicate_files_skipped=1 \
  --expect-gt files_indexed=0

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$ABS_MIXED_DB" \
  --report "$ABS_MIXED_REPORT" \
  --csv "$ABS_MIXED_CSV" \
  > "$ABS_MIXED_SCAN_METRICS"
abs_mixed_scan_status=$?
set -e
if [[ "$abs_mixed_scan_status" != "2" ]]; then
  echo "expected absolute mixed manifest scan-dest to exit 2 when fixture leaks are found, got $abs_mixed_scan_status" >&2
  exit 1
fi

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-absolute-mixed-leaks.tsv" \
  --report "$ABS_MIXED_REPORT" \
  --source-root "$LAB_ROOT/source" \
  --dest-root "$LAB_ROOT/dest"

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
grep -q "files_per_second=" "$SCAN_PROGRESS_LOG"

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
cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$DIR_DB" --list "$LAB_ROOT/manifests/sensitive-directory-paths.txt" > "$SUMMARY_DIR_LIST"
cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$ABS_DB" --list "$LAB_ROOT/manifests/sensitive-absolute-paths.txt" > "$SUMMARY_ABS_LIST"
cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$MIXED_DB" --list "$LAB_ROOT/manifests/sensitive-mixed-paths.txt" > "$SUMMARY_MIXED_LIST"
cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$ABS_MIXED_DB" --list "$LAB_ROOT/manifests/sensitive-absolute-mixed-paths.txt" > "$SUMMARY_ABS_MIXED_LIST"

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
  --require-field manifest.manifest_entries \
  --require-field manifest.files_discovered \
  --require-field manifest.already_indexed \
  --require-field manifest.missing_from_index \
  --expect-eq source_path_mode=root_relative \
  --expect-eq manifest.source_path_mode=root_relative \
  --expect-eq manifest.missing_from_index=0 \
  --expect-eq manifest.extra_indexed_not_in_list=0

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY_DIR_LIST" \
  --require-field manifest.manifest_directory_entries \
  --require-field manifest.duplicate_files_skipped \
  --require-field manifest.files_discovered \
  --require-field manifest.already_indexed \
  --expect-eq manifest.source_path_mode=root_relative \
  --expect-eq manifest.missing_from_index=0 \
  --expect-eq manifest.extra_indexed_not_in_list=0 \
  --expect-ge manifest.duplicate_files_skipped=1

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY_ABS_LIST" \
  --require-field source_path_mode \
  --require-field manifest.source_path_mode \
  --require-field manifest.manifest_directory_entries \
  --require-field manifest.files_discovered \
  --expect-eq source_path_mode=absolute \
  --expect-eq manifest.source_path_mode=absolute \
  --expect-eq manifest.missing_from_index=0 \
  --expect-eq manifest.extra_indexed_not_in_list=0

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY_MIXED_LIST" \
  --require-field manifest.manifest_directory_entries \
  --require-field manifest.manifest_file_entries \
  --require-field manifest.duplicate_files_skipped \
  --require-field manifest.skipped_non_files \
  --expect-eq source_path_mode=root_relative \
  --expect-eq manifest.source_path_mode=root_relative \
  --expect-eq manifest.missing_from_index=0 \
  --expect-eq manifest.extra_indexed_not_in_list=0 \
  --expect-ge manifest.duplicate_files_skipped=3 \
  --expect-ge manifest.skipped_non_files=1

python3 /workspace/scripts/validate-summary.py \
  --summary "$SUMMARY_ABS_MIXED_LIST" \
  --require-field manifest.manifest_directory_entries \
  --require-field manifest.manifest_file_entries \
  --require-field manifest.duplicate_files_skipped \
  --expect-eq source_path_mode=absolute \
  --expect-eq manifest.source_path_mode=absolute \
  --expect-eq manifest.missing_from_index=0 \
  --expect-eq manifest.extra_indexed_not_in_list=0 \
  --expect-ge manifest.duplicate_files_skipped=1

echo "fixture test passed"
