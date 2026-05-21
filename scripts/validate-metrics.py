#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Validate final metrics JSON emitted on stdout.")
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--require-field", action="append", default=[])
    parser.add_argument("--expect-eq", action="append", default=[], metavar="FIELD=VALUE")
    parser.add_argument("--expect-ge", action="append", default=[], metavar="FIELD=VALUE")
    parser.add_argument("--expect-gt", action="append", default=[], metavar="FIELD=VALUE")
    return parser.parse_args()


def parse_expectation(item):
    if "=" not in item:
        raise SystemExit(f"expectation must be FIELD=VALUE: {item}")
    field, value = item.split("=", 1)
    return field, parse_value(value)


def parse_value(value):
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def require_number(field, value):
    if not isinstance(value, (int, float)):
        raise SystemExit(f"{field} is not numeric: {value!r}")
    return value


def main():
    args = parse_args()
    data = json.loads(Path(args.metrics).read_text(encoding="utf-8"))
    missing = [field for field in args.require_field if field not in data]
    if missing:
        raise SystemExit(f"missing metrics fields: {', '.join(missing)}")

    errors = []
    for item in args.expect_eq:
        field, expected = parse_expectation(item)
        actual = data.get(field)
        if actual != expected:
            errors.append(f"{field}: expected {expected!r}, got {actual!r}")
    for item in args.expect_ge:
        field, expected = parse_expectation(item)
        actual = require_number(field, data.get(field))
        expected = require_number(field, expected)
        if actual < expected:
            errors.append(f"{field}: expected >= {expected!r}, got {actual!r}")
    for item in args.expect_gt:
        field, expected = parse_expectation(item)
        actual = require_number(field, data.get(field))
        expected = require_number(field, expected)
        if actual <= expected:
            errors.append(f"{field}: expected > {expected!r}, got {actual!r}")
    if errors:
        raise SystemExit("metrics expectation failures:\n" + "\n".join(errors))

    print(json.dumps({"metrics": args.metrics, "ok": True}, indent=2))


if __name__ == "__main__":
    main()
