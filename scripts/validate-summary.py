#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Validate db-summary JSON fields.")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--require-field", action="append", default=[])
    return parser.parse_args()


def has_field(data, field):
    current = data
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False
    return True


def main():
    args = parse_args()
    data = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    missing = [field for field in args.require_field if not has_field(data, field)]
    if missing:
        raise SystemExit(f"missing summary fields: {', '.join(missing)}")
    print(json.dumps({"summary": args.summary, "ok": True}, indent=2))


if __name__ == "__main__":
    main()
