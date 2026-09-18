#!/usr/bin/env python3
"""Compare two independently built KDBG binary/public-symbol sets."""

from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path, PurePosixPath

import validate_release as release


USER_BINARY_SYMBOL_PAIRS = tuple(
    pair for pair in release.BINARY_SYMBOL_PAIRS
    if not pair[0].casefold().endswith(".sys")
)
DRIVER_BINARY_SYMBOL_PAIRS = tuple(
    pair for pair in release.BINARY_SYMBOL_PAIRS
    if pair[0].casefold().endswith(".sys")
)


def _release_layout(root: Path) -> tuple[Path, Path, bool]:
    root = root.resolve()
    packaged_main = root / release.PACKAGE_NAME
    packaged_symbols = root / release.SYMBOLS_NAME
    if packaged_main.is_dir() and packaged_symbols.is_dir():
        return packaged_main, packaged_symbols, True
    if root.name == release.PACKAGE_NAME:
        sibling = root.parent / release.SYMBOLS_NAME
        if sibling.is_dir():
            return root, sibling, True
    if root.name == release.SYMBOLS_NAME:
        sibling = root.parent / release.PACKAGE_NAME
        if sibling.is_dir():
            return sibling, root, True
    return root, root, False


def _artifact_paths(
    main_root: Path,
    symbols_root: Path,
    packaged: bool,
    binary_relative: str,
    pdb_relative: str,
) -> tuple[Path, Path]:
    if packaged:
        return (
            main_root / PurePosixPath(binary_relative),
            symbols_root / PurePosixPath(pdb_relative),
        )
    return (
        main_root / PurePosixPath(binary_relative).name,
        symbols_root / PurePosixPath(pdb_relative).name,
    )


def _inspect_side(
    side: str,
    binary: Path,
    pdb: Path,
    expected_pdb_name: str,
    forbidden_paths: tuple[str, ...],
    errors: list[str],
) -> dict[str, object] | None:
    if not binary.is_file() or binary.stat().st_size == 0:
        errors.append(f"{side} binary is missing or empty: {binary.name}")
        return None
    if not pdb.is_file() or pdb.stat().st_size == 0:
        errors.append(f"{side} PDB is missing or empty: {pdb.name}")
        return None

    try:
        _machine, _imports, _version, codeview = release.parse_pe(binary)
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        errors.append(f"{side} PE is invalid ({binary.name}): {exc}")
        return None
    if codeview is None:
        errors.append(f"{side} PE has no RSDS CodeView identity: {binary.name}")
        return None
    pe_guid, pe_age, embedded_path = codeview
    embedded_name = re.split(r"[\\/]", embedded_path)[-1]
    if (embedded_path != embedded_name or
            embedded_name.casefold() != expected_pdb_name.casefold()):
        errors.append(
            f"{side} PE CodeView is not the expected basename: {binary.name}")

    try:
        pdb_guid, pdb_age = release.parse_pdb_identity(pdb)
    except (OSError, ValueError, struct.error) as exc:
        errors.append(f"{side} PDB identity is invalid ({pdb.name}): {exc}")
        return None
    if pe_guid != pdb_guid or pe_age != pdb_age:
        errors.append(f"{side} PE/PDB GUID+age mismatch: {binary.name}")

    release.validate_pdb_path_policy(pdb, forbidden_paths, errors)
    return {
        "binary_sha256": release.sha256(binary),
        "pdb_sha256": release.sha256(pdb),
        "codeview_pdb_basename": embedded_name,
        "guid": pe_guid.hex(),
        "age": pe_age,
    }


def compare_symbol_builds(
    left_root: Path,
    right_root: Path,
    *,
    forbidden_paths: tuple[str, ...] = (),
    require_drivers: bool = False,
) -> dict[str, object]:
    left_main, left_symbols, left_packaged = _release_layout(left_root)
    right_main, right_symbols, right_packaged = _release_layout(right_root)
    pairs = list(USER_BINARY_SYMBOL_PAIRS)
    if require_drivers:
        pairs.extend(DRIVER_BINARY_SYMBOL_PAIRS)

    errors: list[str] = []
    records: list[dict[str, object]] = []
    binary_equal_count = 0
    pdb_equal_count = 0
    for binary_relative, pdb_relative in pairs:
        expected_pdb_name = PurePosixPath(pdb_relative).name
        left_binary, left_pdb = _artifact_paths(
            left_main, left_symbols, left_packaged,
            binary_relative, pdb_relative)
        right_binary, right_pdb = _artifact_paths(
            right_main, right_symbols, right_packaged,
            binary_relative, pdb_relative)
        left = _inspect_side(
            "left", left_binary, left_pdb, expected_pdb_name,
            forbidden_paths, errors)
        right = _inspect_side(
            "right", right_binary, right_pdb, expected_pdb_name,
            forbidden_paths, errors)

        record: dict[str, object] = {
            "binary": binary_relative,
            "pdb": pdb_relative,
            "binary_byte_equal": False,
            "pdb_byte_equal": False,
        }
        if left is not None and right is not None:
            binary_equal = left["binary_sha256"] == right["binary_sha256"]
            pdb_equal = left["pdb_sha256"] == right["pdb_sha256"]
            identity_equal = (
                left["codeview_pdb_basename"].casefold() ==
                right["codeview_pdb_basename"].casefold() and
                left["guid"] == right["guid"] and
                left["age"] == right["age"]
            )
            record.update({
                "binary_byte_equal": binary_equal,
                "binary_sha256": left["binary_sha256"],
                "codeview_pdb_basename": left["codeview_pdb_basename"],
                "guid": left["guid"],
                "age": left["age"],
                "pdb_byte_equal": pdb_equal,
                "left_pdb_sha256": left["pdb_sha256"],
                "right_pdb_sha256": right["pdb_sha256"],
            })
            if binary_equal:
                binary_equal_count += 1
            else:
                errors.append(
                    f"cross-build binary bytes differ: {binary_relative}")
            if pdb_equal:
                pdb_equal_count += 1
            if not identity_equal:
                errors.append(
                    f"cross-build CodeView GUID+age/basename differ: "
                    f"{binary_relative}")
        records.append(record)

    return {
        "schema": "kdbg.symbol-build-comparison.v1",
        "success": not errors,
        "mode": "user-and-driver" if require_drivers else "user-only",
        "summary": {
            "pair_count": len(pairs),
            "binary_byte_equal_count": binary_equal_count,
            "pdb_byte_equal_count": pdb_equal_count,
            "pdb_byte_equality_required": False,
        },
        "pairs": records,
        "errors": errors,
    }


def deterministic_json(report: dict[str, object]) -> str:
    return json.dumps(
        report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--forbid-symbol-path", action="append", default=[])
    parser.add_argument("--require-drivers", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    forbidden_paths = tuple(
        str(Path(value).resolve()) for value in args.forbid_symbol_path)
    report = compare_symbol_builds(
        args.left,
        args.right,
        forbidden_paths=forbidden_paths,
        require_drivers=args.require_drivers,
    )
    output = deterministic_json(report)
    if args.output is None:
        print(output, end="")
    else:
        args.output.write_text(output, encoding="utf-8", newline="\n")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
