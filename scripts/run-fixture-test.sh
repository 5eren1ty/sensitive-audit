#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="${LAB_ROOT:-/lab}"
DB="$LAB_ROOT/audit/audit.db"
REPORT="$LAB_ROOT/audit/matches.jsonl"
CSV="$LAB_ROOT/audit/matches.csv"
SECOND_REPORT="$LAB_ROOT/audit/matches-second.jsonl"
SECOND_CSV="$LAB_ROOT/audit/matches-second.csv"

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
  --db "$DB"

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$REPORT" \
  --csv "$CSV"
scan_status=$?
set -e
if [[ "$scan_status" != "2" ]]; then
  echo "expected scan-dest to exit 2 when fixture leaks are found, got $scan_status" >&2
  exit 1
fi

python3 /workspace/scripts/compare-report.py \
  --expected "$LAB_ROOT/manifests/expected-leaks.tsv" \
  --report "$REPORT"

set +e
cargo run --manifest-path /workspace/Cargo.toml -- scan-dest \
  --root "$LAB_ROOT/dest" \
  --db "$DB" \
  --report "$SECOND_REPORT" \
  --csv "$SECOND_CSV"
second_status=$?
set -e
if [[ "$second_status" != "2" ]]; then
  echo "expected second scan-dest to exit 2 when fixture leaks are found, got $second_status" >&2
  exit 1
fi

cargo run --manifest-path /workspace/Cargo.toml -- db-summary --db "$DB"

echo "fixture test passed"
