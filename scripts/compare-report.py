#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Compare scanner JSONL output to fixture ground truth.")
    parser.add_argument("--expected", required=True, help="expected-leaks.tsv")
    parser.add_argument("--report", required=True, help="scanner JSONL report")
    return parser.parse_args()


def main():
    args = parse_args()
    expected_path = Path(args.expected)
    report_path = Path(args.report)

    expected = set()
    with expected_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            expected.add((row["source_rel"], row["dest_rel"]))

    actual = set()
    rows = 0
    with report_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows += 1
            item = json.loads(line)
            actual.add((item["source_rel"], item["dest_rel"]))

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
        for source_rel, dest_rel in missing[:20]:
            print(f"{source_rel}\t{dest_rel}")
    if unexpected:
        print("unexpected pairs:")
        for source_rel, dest_rel in unexpected[:20]:
            print(f"{source_rel}\t{dest_rel}")

    if missing or unexpected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

