#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Compare scanner JSONL output to fixture ground truth.")
    parser.add_argument("--expected", required=True, help="expected-leaks.tsv")
    parser.add_argument("--report", required=True, help="scanner JSONL report")
    parser.add_argument("--source-root", required=True, help="source root used for indexing")
    parser.add_argument("--dest-root", required=True, help="destination root used for scanning")
    return parser.parse_args()


def main():
    args = parse_args()
    expected_path = Path(args.expected)
    report_path = Path(args.report)
    source_root = Path(args.source_root).resolve()
    dest_root = Path(args.dest_root).resolve()

    expected = set()
    with expected_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            expected.add((
                str(source_root / row["source_rel"]),
                str(dest_root / row["dest_rel"]),
            ))

    actual = set()
    rows = 0
    with report_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows += 1
            item = json.loads(line)
            if "source_rel" in item or "dest_rel" in item:
                raise SystemExit("report contains legacy relative path fields")
            actual.add((item["source_path"], item["dest_path"]))

    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    result = {
        "expected": len(expected),
        "actual_rows": rows,
        "actual_unique_pairs": len(actual),
        "missing": len(missing),
        "unexpected": len(unexpected),
        "ok": not missing and not unexpected,
    }
    print(json.dumps(result, indent=2))

    if missing:
        print("missing pairs:")
        for source_path, dest_path in missing[:20]:
            print(f"{source_path}\t{dest_path}")
    if unexpected:
        print("unexpected pairs:")
        for source_path, dest_path in unexpected[:20]:
            print(f"{source_path}\t{dest_path}")

    if missing or unexpected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
