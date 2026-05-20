#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Validate final metrics JSON emitted on stdout.")
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--require-field", action="append", default=[])
    return parser.parse_args()


def main():
    args = parse_args()
    data = json.loads(Path(args.metrics).read_text(encoding="utf-8"))
    missing = [field for field in args.require_field if field not in data]
    if missing:
        raise SystemExit(f"missing metrics fields: {', '.join(missing)}")
    print(json.dumps({"metrics": args.metrics, "ok": True}, indent=2))


if __name__ == "__main__":
    main()
