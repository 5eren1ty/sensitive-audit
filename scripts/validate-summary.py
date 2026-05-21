#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Validate db-summary JSON fields.")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--require-field", action="append", default=[])
    parser.add_argument("--expect-eq", action="append", default=[], metavar="FIELD=VALUE")
    parser.add_argument("--expect-ge", action="append", default=[], metavar="FIELD=VALUE")
    parser.add_argument("--expect-gt", action="append", default=[], metavar="FIELD=VALUE")
    return parser.parse_args()


def lookup_field(data, field):
    current = data
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(field)
    return current


def has_field(data, field):
    try:
        lookup_field(data, field)
        return True
    except KeyError:
        return False


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
    data = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    missing = [field for field in args.require_field if not has_field(data, field)]
    if missing:
        raise SystemExit(f"missing summary fields: {', '.join(missing)}")

    errors = []
    for item in args.expect_eq:
        field, expected = parse_expectation(item)
        try:
            actual = lookup_field(data, field)
        except KeyError:
            errors.append(f"{field}: missing")
            continue
        if actual != expected:
            errors.append(f"{field}: expected {expected!r}, got {actual!r}")
    for item in args.expect_ge:
        field, expected = parse_expectation(item)
        try:
            actual = lookup_field(data, field)
        except KeyError:
            errors.append(f"{field}: missing")
            continue
        actual = require_number(field, actual)
        expected = require_number(field, expected)
        if actual < expected:
            errors.append(f"{field}: expected >= {expected!r}, got {actual!r}")
    for item in args.expect_gt:
        field, expected = parse_expectation(item)
        try:
            actual = lookup_field(data, field)
        except KeyError:
            errors.append(f"{field}: missing")
            continue
        actual = require_number(field, actual)
        expected = require_number(field, expected)
        if actual <= expected:
            errors.append(f"{field}: expected > {expected!r}, got {actual!r}")
    if errors:
        raise SystemExit("summary expectation failures:\n" + "\n".join(errors))

    print(json.dumps({"summary": args.summary, "ok": True}, indent=2))


if __name__ == "__main__":
    main()
