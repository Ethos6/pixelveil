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
    inspect.add_argument("--json", action="store_true", help="write a machine-readable report")

    clean = sub.add_parser("clean", help="write cleaned copies and verify encoded image data is unchanged")
    clean.add_argument("files", nargs="+", type=Path)
    clean.add_argument("--output-dir", type=Path, help="write all copies to this directory")
    clean.add_argument("--remove-provenance", action="store_true", help="also remove detected C2PA/provenance blocks")
    clean.add_argument("--json", action="store_true", help="write a machine-readable report")

    sub.add_parser("gui", help="open the optional Tk desktop interface")
    return parser


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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "inspect":
        return _inspect(args.files, args.json)
    if args.command == "clean":
        return _clean(args.files, args.output_dir, args.remove_provenance, args.json)
    if args.command == "gui":
        try:
            launch_gui()
        except RuntimeError as exc:
            print(f"PixelVeil GUI unavailable: {exc}", file=sys.stderr)
            return 1
        return 0
    return 2
