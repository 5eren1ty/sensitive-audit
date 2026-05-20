#!/usr/bin/env python3
import argparse
import json
import os
import random
import shutil
import string
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a Linux filesystem fixture with renamed sensitive leaks."
    )
    parser.add_argument("--lab-root", default=os.environ.get("LAB_ROOT", "/lab"))
    parser.add_argument("--small-files", type=int, default=100_000)
    parser.add_argument("--large-files", type=int, default=24)
    parser.add_argument("--small-min-bytes", type=int, default=64)
    parser.add_argument("--small-max-bytes", type=int, default=4096)
    parser.add_argument("--large-min-mib", type=int, default=8)
    parser.add_argument("--large-max-mib", type=int, default=64)
    parser.add_argument("--sensitive-every", type=int, default=997)
    parser.add_argument("--copy-fraction", type=float, default=0.35)
    parser.add_argument("--leak-fraction", type=float, default=0.20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-edge-cases", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def reset_dir(path: Path, force: bool):
    if path.exists():
        if not force:
            raise SystemExit(f"{path} already exists. Re-run with --force to replace it.")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def random_name(rng: random.Random, prefix: str, suffix: str = ".bin") -> str:
    alphabet = string.ascii_lowercase + string.digits
    token = "".join(rng.choice(alphabet) for _ in range(12))
    return f"{prefix}-{token}{suffix}"


def write_bytes(path: Path, size: int, rng: random.Random):
    path.parent.mkdir(parents=True, exist_ok=True)
    block = rng.randbytes(min(size, 1024 * 1024))
    remaining = size
    with path.open("wb") as fh:
        while remaining > 0:
            chunk = block[: min(remaining, len(block))]
            fh.write(chunk)
            remaining -= len(chunk)


def write_pattern(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def main():
    args = parse_args()
    rng = random.Random(args.seed)

    lab_root = Path(args.lab_root)
    source_root = lab_root / "source"
    dest_root = lab_root / "dest"
    manifest_root = lab_root / "manifests"

    reset_dir(source_root, args.force)
    reset_dir(dest_root, args.force)
    reset_dir(manifest_root, args.force)

    sensitive_paths = []
    expected_leaks = []
    expected_symlink_leaks = []
    normal_copies = 0
    sensitive_files = 0

    for i in range(args.small_files):
        bucket = f"{i % 1000:04d}"
        subdir = f"{(i // 1000) % 1000:04d}"
        is_sensitive = i % args.sensitive_every == 0
        base = "sensitive" if is_sensitive else "data"
        source_path = source_root / base / bucket / subdir / random_name(rng, f"small-{i:08d}")
        size = rng.randint(args.small_min_bytes, args.small_max_bytes)
        write_bytes(source_path, size, rng)

        if is_sensitive:
            sensitive_files += 1
            sensitive_paths.append(rel(source_path, source_root))
            if rng.random() < args.leak_fraction:
                dest_path = dest_root / "renamed" / bucket / random_name(rng, f"leaked-small-{i:08d}")
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, dest_path)
                expected_leaks.append((rel(source_path, source_root), rel(dest_path, dest_root), "small-sensitive"))
        elif rng.random() < args.copy_fraction:
            dest_path = dest_root / "copied" / subdir / random_name(rng, f"normal-small-{i:08d}")
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, dest_path)
            normal_copies += 1

    for i in range(args.large_files):
        is_sensitive = i % 5 == 0
        base = "sensitive-large" if is_sensitive else "large"
        source_path = source_root / base / f"group-{i % 16:02d}" / random_name(rng, f"large-{i:04d}")
        size = rng.randint(args.large_min_mib, args.large_max_mib) * 1024 * 1024
        write_bytes(source_path, size, rng)

        if is_sensitive:
            sensitive_files += 1
            sensitive_paths.append(rel(source_path, source_root))
            if rng.random() < max(args.leak_fraction, 0.5):
                dest_path = dest_root / "renamed-large" / random_name(rng, f"leaked-large-{i:04d}")
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, dest_path)
                expected_leaks.append((rel(source_path, source_root), rel(dest_path, dest_root), "large-sensitive"))
        elif rng.random() < args.copy_fraction:
            dest_path = dest_root / "copied-large" / random_name(rng, f"normal-large-{i:04d}")
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, dest_path)
            normal_copies += 1

    if not args.no_edge_cases:
        edge_root = source_root / "sensitive-edge"
        edge_dest = dest_root / "renamed-edge"

        small_source = edge_root / "small-exact-leak.txt"
        small_content = b"edge-case-small-sensitive\n"
        write_pattern(small_source, small_content)
        sensitive_files += 1
        sensitive_paths.append(rel(small_source, source_root))
        small_dest = edge_dest / "small-renamed-copy.data"
        small_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(small_source, small_dest)
        expected_leaks.append((rel(small_source, source_root), rel(small_dest, dest_root), "edge-small-sensitive"))

        large_prefix = b"A" * (64 * 1024)
        large_source = edge_root / "large-exact-leak.bin"
        large_content = large_prefix + b"B" * (96 * 1024)
        write_pattern(large_source, large_content)
        sensitive_files += 1
        sensitive_paths.append(rel(large_source, source_root))
        large_dest = edge_dest / "large-renamed-copy.data"
        large_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(large_source, large_dest)
        expected_leaks.append((rel(large_source, source_root), rel(large_dest, dest_root), "edge-large-sensitive"))

        same_size_nonmatch = dest_root / "edge-nonmatches" / "same-size-different-content.bin"
        write_pattern(same_size_nonmatch, b"C" * len(large_content))

        same_prefix_nonmatch = dest_root / "edge-nonmatches" / "same-prefix-different-tail.bin"
        write_pattern(same_prefix_nonmatch, large_prefix + b"D" * (96 * 1024))

        min_size_root = source_root / "sensitive-min-size"
        min_size_dest = dest_root / "renamed-min-size"
        for name, payload in [
            ("below-threshold.txt", b"small-sensitive-under-thirty-two"),
            ("at-threshold.txt", b"A" * 32),
            ("above-threshold.txt", b"B" * 33),
        ]:
            source = min_size_root / name
            write_pattern(source, payload)
            sensitive_files += 1
            sensitive_paths.append(rel(source, source_root))
            dest = min_size_dest / f"copy-{name}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
            expected_leaks.append((rel(source, source_root), rel(dest, dest_root), "edge-min-size"))

        symlink_source = edge_root / "symlink-target-sensitive.bin"
        write_pattern(symlink_source, b"symlink-sensitive-target" * 8)
        sensitive_files += 1
        sensitive_paths.append(rel(symlink_source, source_root))
        symlink_dest = dest_root / "symlinked" / "sensitive-link.bin"
        symlink_dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            symlink_dest.symlink_to(symlink_source)
            expected_symlink_leaks.append((rel(symlink_source, source_root), rel(symlink_dest, dest_root), "edge-symlink-sensitive"))
        except OSError:
            pass

    if sensitive_paths and not expected_leaks:
        source_rel = sensitive_paths[0]
        source_path = source_root / source_rel
        dest_path = dest_root / "renamed" / "forced-sensitive-leak.bin"
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, dest_path)
        expected_leaks.append((source_rel, rel(dest_path, dest_root), "forced-sensitive"))

    sensitive_manifest = manifest_root / "sensitive-paths.txt"
    sensitive_manifest.write_text("\n".join(sensitive_paths) + "\n", encoding="utf-8")

    leaks_manifest = manifest_root / "expected-leaks.tsv"
    with leaks_manifest.open("w", encoding="utf-8") as fh:
        fh.write("source_rel\tdest_rel\treason\n")
        for source_rel, dest_rel, reason in expected_leaks:
            fh.write(f"{source_rel}\t{dest_rel}\t{reason}\n")

    symlink_leaks_manifest = manifest_root / "expected-symlink-leaks.tsv"
    with symlink_leaks_manifest.open("w", encoding="utf-8") as fh:
        fh.write("source_rel\tdest_rel\treason\n")
        for source_rel, dest_rel, reason in expected_symlink_leaks:
            fh.write(f"{source_rel}\t{dest_rel}\t{reason}\n")

    summary = {
        "seed": args.seed,
        "small_files": args.small_files,
        "large_files": args.large_files,
        "sensitive_files": sensitive_files,
        "normal_copies": normal_copies,
        "expected_leaks": len(expected_leaks),
        "source_root": str(source_root),
        "dest_root": str(dest_root),
        "sensitive_manifest": str(sensitive_manifest),
        "expected_leaks_manifest": str(leaks_manifest),
        "expected_symlink_leaks": len(expected_symlink_leaks),
        "expected_symlink_leaks_manifest": str(symlink_leaks_manifest),
    }
    (manifest_root / "dataset-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
