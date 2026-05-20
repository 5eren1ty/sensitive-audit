#!/usr/bin/env python3
import csv
import json
import os
from pathlib import Path


def main():
    lab_root = Path(os.environ.get("LAB_ROOT", "/lab"))
    manifest_root = lab_root / "manifests"
    source_root = lab_root / "source"
    dest_root = lab_root / "dest"

    summary_path = manifest_root / "dataset-summary.json"
    leaks_path = manifest_root / "expected-leaks.tsv"
    sensitive_path = manifest_root / "sensitive-paths.txt"

    if not summary_path.exists():
        raise SystemExit(f"Missing {summary_path}. Generate the fixture first.")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    sensitive_paths = [
        line.strip()
        for line in sensitive_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    missing_sensitive = [
        item for item in sensitive_paths if not (source_root / item).is_file()
    ]

    missing_leaks = []
    with leaks_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            source = source_root / row["source_rel"]
            dest = dest_root / row["dest_rel"]
            if not source.is_file() or not dest.is_file():
                missing_leaks.append(row)
            elif source.stat().st_size != dest.stat().st_size:
                missing_leaks.append(row)

    print(json.dumps({
        "summary": summary,
        "sensitive_paths_checked": len(sensitive_paths),
        "missing_sensitive_sources": len(missing_sensitive),
        "missing_or_size_mismatched_leaks": len(missing_leaks),
        "ok": not missing_sensitive and not missing_leaks,
    }, indent=2))

    if missing_sensitive or missing_leaks:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

