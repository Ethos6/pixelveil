from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .core import PixelVeilError, clean_file, inspect_file
from .gui import launch_gui


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pixelveil",
        description="Inspect and remove common image metadata locally, without re-encoding pixels.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="report metadata categories without printing their values")
    inspect.add_argument("files", nargs="+", type=Path)
    inspect.add_argument("--recursive", action="store_true", help="include supported images inside input folders")
    inspect.add_argument("--json", action="store_true", help="write a machine-readable report")

    clean = sub.add_parser("clean", help="write cleaned copies and verify encoded image data is unchanged")
    clean.add_argument("files", nargs="+", type=Path)
    clean.add_argument("--output-dir", type=Path, help="write all copies to this directory")
    clean.add_argument("--remove-provenance", action="store_true", help="also remove detected C2PA/provenance blocks")
    clean.add_argument("--recursive", action="store_true", help="include supported images inside input folders")
    clean.add_argument("--json", action="store_true", help="write a machine-readable report")

    diff = sub.add_parser("diff", help="compare metadata categories and encoded image payload hashes")
    diff.add_argument("original", type=Path)
    diff.add_argument("cleaned", type=Path)
    diff.add_argument("--json", action="store_true", help="write a machine-readable report")

    sub.add_parser("gui", help="open the optional Tk desktop interface")
    return parser


SUPPORTED_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".gif"}


def _expand_paths(paths: list[Path], recursive: bool) -> list[Path]:
    expanded: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path.is_dir():
            if recursive:
                candidates = path.rglob("*")
            else:
                candidates = path.glob("*")
            for candidate in candidates:
                if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                    if ".cleaned." not in candidate.name and candidate.resolve() not in seen:
                        expanded.append(candidate)
                        seen.add(candidate.resolve())
        else:
            expanded.append(path)
    return expanded


def _inspect(paths: list[Path], as_json: bool) -> int:
    rows: list[dict[str, object]] = []
    failures = 0
    for path in paths:
        try:
            scan = inspect_file(path)
            row = {"file": path.name, **scan.to_dict()}
            rows.append(row)
            if not as_json:
                kinds = ", ".join(str(item["kind"]) for item in scan.findings) or "none detected"
                print(f"{path.name}: {scan.format}; metadata markers: {kinds}")
                for warning in scan.warnings:
                    print(f"  note: {warning}")
        except (PixelVeilError, OSError, ValueError) as exc:
            failures += 1
            rows.append({"file": path.name, "error": str(exc)})
            if not as_json:
                print(f"{path.name}: error: {exc}", file=sys.stderr)
    if as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 1 if failures else 0


def _clean(paths: list[Path], output_dir: Path | None, remove_provenance: bool, as_json: bool) -> int:
    rows: list[dict[str, object]] = []
    failures = 0
    for path in paths:
        try:
            target, result = clean_file(path, output_dir, remove_provenance=remove_provenance)
            row = {"file": path.name, "output": target.name, **result.to_dict()}
            rows.append(row)
            if not as_json:
                removed = ", ".join(str(item["kind"]) for item in result.removed) or "no supported metadata markers found"
                print(f"{path.name} -> {target.name}: removed {removed}; encoded image data verified unchanged")
                for item in result.remaining:
                    print(f"  preserved: {item['kind']} ({item['container']})")
                for warning in result.warnings:
                    print(f"  note: {warning}")
        except (PixelVeilError, OSError, ValueError) as exc:
            failures += 1
            rows.append({"file": path.name, "error": str(exc)})
            if not as_json:
                print(f"{path.name}: error: {exc}", file=sys.stderr)
    if as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 1 if failures else 0


def _diff(original: Path, cleaned: Path, as_json: bool) -> int:
    try:
        before = inspect_file(original)
        after = inspect_file(cleaned)
    except (PixelVeilError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2) if as_json else f"error: {exc}", file=sys.stderr)
        return 1
    before_kinds = sorted({str(item["kind"]) for item in before.findings})
    after_kinds = sorted({str(item["kind"]) for item in after.findings})
    payload_unchanged = before.image_payload_sha256 == after.image_payload_sha256
    report = {
        "original": original.name,
        "cleaned": cleaned.name,
        "format_matches": before.format == after.format,
        "image_payload_unchanged": payload_unchanged,
        "original_findings": before_kinds,
        "cleaned_findings": after_kinds,
        "removed_categories": sorted(set(before_kinds) - set(after_kinds)),
        "remaining_categories": after_kinds,
    }
    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"format matches: {report['format_matches']}")
        print(f"encoded image payload unchanged: {payload_unchanged}")
        print(f"removed categories: {', '.join(report['removed_categories']) or 'none'}")
        print(f"remaining categories: {', '.join(after_kinds) or 'none detected'}")
    return 0 if report["format_matches"] and payload_unchanged else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "inspect":
        return _inspect(_expand_paths(args.files, args.recursive), args.json)
    if args.command == "clean":
        return _clean(_expand_paths(args.files, args.recursive), args.output_dir, args.remove_provenance, args.json)
    if args.command == "diff":
        return _diff(args.original, args.cleaned, args.json)
    if args.command == "gui":
        try:
            launch_gui()
        except RuntimeError as exc:
            print(f"PixelVeil GUI unavailable: {exc}", file=sys.stderr)
            return 1
        return 0
    return 2
