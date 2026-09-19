#!/usr/bin/env python3
"""Deterministic contract tests for the live-run release validator."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock


VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "tools" / "validate_release.py"
SPEC = importlib.util.spec_from_file_location("kdbg_validate_release", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load validate_release.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

COMPARE_PATH = Path(__file__).resolve().parents[1] / "tools" / "compare_symbol_builds.py"
COMPARE_SPEC = importlib.util.spec_from_file_location(
    "kdbg_compare_symbol_builds", COMPARE_PATH)
if COMPARE_SPEC is None or COMPARE_SPEC.loader is None:
    raise RuntimeError("unable to load compare_symbol_builds.py")
sys.modules.setdefault("validate_release", VALIDATOR)
COMPARE = importlib.util.module_from_spec(COMPARE_SPEC)
COMPARE_SPEC.loader.exec_module(COMPARE)


def probe(crc32: int) -> dict[str, object]:
    return {
        "generation": 7,
        "byte_count": 4096,
        "virtual_address": 0x140000000,
        "physical_address": 0x100000,
        "pfn": 0x100,
        "crc32": crc32,
    }


def session(
    successful_writes: int,
    transferred: int = 0,
    successful_reads: int = 10,
) -> dict[str, object]:
    return {
        "flags": 1,
        "owner_pid": 4242,
        "current_pid": 4242,
        "open_handle_count": 1,
        "successful_reads": successful_reads,
        "successful_writes": successful_writes,
        "rejected_writes": 0,
        "last_physical_write_status": 0,
        "last_physical_write_stage": 4 if transferred else 0,
        "last_physical_write_transferred": transferred,
        "write_enabled": False,
    }


def operation(name: str, byte_count: int) -> dict[str, object]:
    return {
        "name": name,
        "requested_bytes": byte_count,
        "completed_bytes": byte_count,
        "latency_ms": 0.25,
        "passed": True,
    }


def comparison(name: str, expected: int, actual: int | None = None) -> dict[str, object]:
    return {
        "name": name,
        "byte_count": 4096,
        "mismatch_count": 0,
        "expected_crc32": expected,
        "actual_crc32": expected if actual is None else actual,
        "match": True,
    }


def valid_write_report() -> dict[str, object]:
    fixture_hash = "01" * 32
    return {
        "schema": "kdbg.live-verify.v1",
        "mode": "probe-write-rollback",
        "success": True,
        "cancelled": False,
        "operator_confirmed_disposable_vm": True,
        "snapshot_id": "checkpoint-123",
        "system": {
            "generated_utc": "2026-09-16T00:00:00.000Z",
            "os_name": "Windows",
            "os_major": 10,
            "os_minor": 0,
            "os_build": 26100,
            "architecture": "x64",
            "tool_version": "1.1.0",
            "build_id": "fixture",
        },
        "runtime_identity": {
            "verified": True,
            "verifier": {
                "package_relative_path": "tools/kdbg_live_verify.exe",
                "sha256": fixture_hash,
            },
            "kdbg_service": {
                "name": "KDBG",
                "binary": {
                    "package_relative_path": "drivers/KDbgDriver.sys",
                    "sha256": fixture_hash,
                },
                "service_type": 1,
                "current_state": 4,
                "running_kernel_driver": True,
            },
            "probe_service": {
                "name": "KDBGProbe",
                "binary": {
                    "package_relative_path": "drivers/KDbgProbe.sys",
                    "sha256": fixture_hash,
                },
                "service_type": 1,
                "current_state": 4,
                "running_kernel_driver": True,
            },
        },
        "backend": {
            "name": "KDbgDriver",
            "abi_version": 6,
            "connected": True,
            "write_enabled": False,
            "is_mock": False,
        },
        "probe_before": probe(0x11111111),
        "probe_after_write": probe(0x22222222),
        "probe_after_rollback": probe(0x11111111),
        "session_before": session(10),
        "session_after_apply": session(11, 8, 16),
        "session_final": session(12, 4096, 20),
        "latency": {
            "read_samples_ms": [0.1, 0.2, 0.3],
            "read_median_ms": 0.2,
            "read_p95_ms": 0.3,
        },
        "operations": [
            operation("load_baseline", 4096),
            operation("independent_read_sample", 4096),
            operation("one_shot_apply", 8),
            operation("independent_reload_after_write", 4096),
            operation("rollback_full_page", 4096),
            operation("independent_read_after_rollback", 4096),
        ],
        "comparisons": [
            comparison("baseline_vs_preflight", 0x11111111),
            comparison("expected_vs_write_readback", 0x22222222),
            comparison("expected_vs_independent_reload", 0x22222222),
            comparison("baseline_vs_rollback_readback", 0x11111111),
            comparison("baseline_vs_post_rollback_read", 0x11111111),
        ],
        "write_cleanup": {
            "edit_offset": 0x100,
            "edit_length": 8,
            "apply_requested_bytes": 8,
            "rollback_requested_bytes": 4096,
            "rollback_attempted": True,
            "rollback_verified": True,
            "final_relock_attempted": True,
            "final_gate_locked": True,
        },
        "errors": [],
    }


def valid_write_report_abi7() -> dict[str, object]:
    report = copy.deepcopy(valid_write_report())
    report["backend"]["abi_version"] = 7  # type: ignore[index]
    report["backend"]["supports_physical_page_compare_write"] = True  # type: ignore[index]
    report["session_after_apply"] = session(11, 4096, 14)
    report["session_final"] = session(12, 4096, 16)
    return report


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid_test_gif(
    *, width: int = 320, height: int = 180,
    frames: int = 20, delay_cs: int = 100,
) -> bytes:
    data = bytearray(b"GIF89a")
    data.extend(struct.pack("<HHBBB", width, height, 0x80, 0, 0))
    data.extend(b"\x00\x00\x00\xff\xff\xff")
    for _ in range(frames):
        data.extend(b"\x21\xf9\x04\x00")
        data.extend(struct.pack("<H", delay_cs))
        data.extend(b"\x00\x00")
        data.extend(b"\x2c")
        data.extend(struct.pack("<HHHHB", 0, 0, 1, 1, 0))
        data.extend(b"\x02\x02\x44\x01\x00")
    data.extend(b"\x3b")
    return bytes(data)


def valid_tool_versions() -> dict[str, str]:
    return {
        "msvc_compiler": "19.44.35213",
        "msvc_toolset": "14.44.35207",
        "windows_sdk": "10.0.26100.0",
        "wdk": "10.0.26100.0",
        "powershell": "7.5.3",
        "cmake": "cmake version 4.0.1",
        "python": "Python 3.13.7",
        "syft": "1.31.0",
    }


def valid_main_metadata() -> dict[str, object]:
    return {
        "schema": "kdbg.build-metadata.v1",
        "product": "KDBG",
        "version": VALIDATOR.VERSION,
        "configuration": "Release",
        "architecture": "x64",
        "minimum_windows_build": VALIDATOR.MIN_WINDOWS_BUILD,
        "package_name": VALIDATOR.PACKAGE_NAME,
        "source_revision": "snapshot-sha256:" + "ab" * 32,
        "source_snapshot_scope": "kdbg.source-snapshot.v1",
        "source_snapshot_sha256": "ab" * 32,
        "source_file_count": 42,
        "catalogs": list(VALIDATOR.EXPECTED_CATALOGS),
        "symbols_package": VALIDATOR.SYMBOLS_NAME,
        "tool_versions": valid_tool_versions(),
        "reproducible_commands": ["build", "validate"],
    }


def valid_symbols_metadata() -> dict[str, object]:
    metadata = valid_main_metadata()
    metadata["schema"] = "kdbg.symbols-metadata.v1"
    metadata["package_name"] = VALIDATOR.SYMBOLS_NAME
    metadata["path_policy"] = {
        "schema": "kdbg.symbol-path-policy.v1",
        "logical_root": "KDBG_ROOT",
        "scan_scope": ["raw", "logical-streams"],
        "encodings": ["ascii", "utf-16le"],
        "permitted_stable_aliases": ["R:\\", "K:\\"],
        "stable_aliases_are_private": False,
        "private_paths_present": False,
    }
    metadata.pop("catalogs")
    metadata.pop("symbols_package")
    metadata.pop("reproducible_commands")
    return metadata


def minimal_pe_with_codeview(
    guid: bytes, age: int, pdb_path: str,
) -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<II", data, optional + 112 + 6 * 8, 0x1100, 28)
    section = optional + 0xF0
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    record = b"RSDS" + guid + struct.pack("<I", age) + pdb_path.encode() + b"\0"
    struct.pack_into(
        "<IIHHIIII", data, 0x300,
        0, 0, 0, 0, 2, len(record), 0x1140, 0x340,
    )
    data[0x340:0x340 + len(record)] = record
    return bytes(data)


def minimal_pdb(guid: bytes, age: int) -> bytes:
    block_size = 512
    data = bytearray(block_size * 5)
    data[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    struct.pack_into("<6I", data, 32, block_size, 0, 5, 16, 0, 1)
    struct.pack_into("<I", data, block_size, 2)
    directory = block_size * 2
    struct.pack_into("<I", data, directory, 2)
    struct.pack_into("<II", data, directory + 4, 0xFFFFFFFF, 28)
    struct.pack_into("<I", data, directory + 12, 3)
    info = block_size * 3
    struct.pack_into("<III", data, info, 20000404, 0, age)
    data[info + 12:info + 28] = guid
    return bytes(data)


def pdb_with_extra_stream(
    guid: bytes,
    age: int,
    payload: bytes,
    *,
    stream_blocks: tuple[int, ...] | None = None,
) -> bytes:
    block_size = 512
    if stream_blocks is None:
        block_count = (len(payload) + block_size - 1) // block_size
        stream_blocks = tuple(range(4, 4 + block_count))
    required_blocks = (len(payload) + block_size - 1) // block_size
    if len(stream_blocks) != required_blocks:
        raise ValueError("stream block count does not cover payload")
    total_blocks = max((3, *stream_blocks)) + 1
    data = bytearray(block_size * total_blocks)
    data[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    directory_size = 20 + 4 * len(stream_blocks)
    struct.pack_into(
        "<6I", data, 32,
        block_size, 0, total_blocks, directory_size, 0, 1,
    )
    struct.pack_into("<I", data, block_size, 2)
    directory = block_size * 2
    struct.pack_into("<I", data, directory, 3)
    struct.pack_into(
        "<III", data, directory + 4, 0xFFFFFFFF, 28, len(payload))
    struct.pack_into("<I", data, directory + 16, 3)
    struct.pack_into(
        f"<{len(stream_blocks)}I", data, directory + 20, *stream_blocks)
    info = block_size * 3
    struct.pack_into("<III", data, info, 20000404, 0, age)
    data[info + 12:info + 28] = guid
    for index, block in enumerate(stream_blocks):
        start = index * block_size
        chunk = payload[start:start + block_size]
        offset = block * block_size
        data[offset:offset + len(chunk)] = chunk
    return bytes(data)


def build_flat_symbol_comparison_root(
    root: Path,
    *,
    pdb_variant: str,
    include_drivers: bool = False,
) -> None:
    pairs = list(COMPARE.USER_BINARY_SYMBOL_PAIRS)
    if include_drivers:
        pairs.extend(COMPARE.DRIVER_BINARY_SYMBOL_PAIRS)
    root.mkdir(parents=True, exist_ok=True)
    for binary_relative, pdb_relative in pairs:
        binary_name = Path(binary_relative).name
        pdb_name = Path(pdb_relative).name
        guid = hashlib.sha256(binary_relative.encode("ascii")).digest()[:16]
        (root / binary_name).write_bytes(
            minimal_pe_with_codeview(guid, 1, pdb_name))
        payload = f"KDBG_ROOT/{pdb_variant}/{pdb_name}\0".encode("ascii")
        (root / pdb_name).write_bytes(
            pdb_with_extra_stream(guid, 1, payload))


def build_analysis_metadata(
    evidence_dir: Path, package: Path, symbols: Path, abi_version: int = 6,
) -> Path:
    process_page = bytes((index * 7 + 3) & 0xFF for index in range(4096))
    process_page_path = evidence_dir / "process-read.bin"
    physical_page_path = evidence_dir / "physical-read.bin"
    process_page_path.write_bytes(process_page)
    physical_page_path.write_bytes(process_page)
    kernel_module_base = 0xFFFFF80000000000
    kernel_header = (package / "drivers/KDbgDriver.sys").read_bytes()[:512]
    kernel_live_header = bytearray(kernel_header)
    struct.pack_into("<Q", kernel_live_header, 0x98 + 24, kernel_module_base)
    (evidence_dir / "kernel-live-header.bin").write_bytes(kernel_live_header)
    (evidence_dir / "kernel-local-header.bin").write_bytes(kernel_header)
    kernel_read = bytes(range(32))
    (evidence_dir / "kernel-read.bin").write_bytes(kernel_read)
    evidence_pdb = evidence_dir / "KDbgDriver.pdb"
    evidence_pdb.write_bytes((symbols / "drivers/KDbgDriver.pdb").read_bytes())

    owner_pid = 4242
    owner_va = 0x20000000
    owner_pa = 0x200000
    owner_pfn = owner_pa >> 12
    dtb = 0x300000
    generation = 11
    current_crc = f"{zlib.crc32(process_page) & 0xFFFFFFFF:08x}"
    fixture_info = {
        "schema": "kdbg.process-fixture.v1",
        "ok": True,
        "command": "INFO",
        "protocol_version": 1,
        "pid": owner_pid,
        "process_start_id": "0x123456789abcdef",
        "fixture_nonce": "0123456789abcdef0123456789abcdef",
        "image_basename": "kdbg_process_fixture.exe",
        "virtual_address": hex(owner_va),
        "byte_count": 4096,
        "generation": generation,
        "baseline_crc32": "0x" + current_crc,
        "current_crc32": "0x" + current_crc,
        "virtual_locked": True,
        "pipe_name": r"\\.\pipe\KDBG.ProcessFixture.test",
        "corpus": {"signed32": 32, "freeze_value": 128},
    }
    fixture_info_path = evidence_dir / "fixture-info.json"
    fixture_info_path.write_text(json.dumps(fixture_info), encoding="utf-8")

    steps = [
        ("PML4", 0, 0x300000, 0x301007, 0x301),
        ("PDPT", 0, 0x301000, 0x302007, 0x302),
        ("PD", 0x100, 0x302800, 0x303007, 0x303),
        ("PT", 0, 0x303000, 0x200007, owner_pfn),
    ]
    analysis = {
        "schema": "kdbg-analysis-live-evidence-v1",
        "captured_utc": "2026-09-16T00:15:00Z",
        "driver_abi_version": abi_version,
        "process": {
            "pid": owner_pid,
            "process_start_id": 0x123456789ABCDEF,
            "image_basename": "kdbg_process_fixture.exe",
            "image_sha256": file_sha256(package / "tools/kdbg_process_fixture.exe"),
            "protocol_version": 1,
            "fixture_nonce": "0123456789abcdef0123456789abcdef",
            "virtual_address": owner_va,
            "byte_count": 4096,
            "generation": generation,
            "baseline_crc32": current_crc,
            "current_crc32": current_crc,
            "virtual_locked": True,
            "fixture_info_file": fixture_info_path.name,
            "fixture_info_sha256": file_sha256(fixture_info_path),
        },
        "ownership": {
            "pid": owner_pid,
            "provider": "selected-process-page-table-scan",
            "source": "selected-process-page-table-scan",
            "pfn": owner_pfn,
            "physical_address": owner_pa,
            "virtual_address": owner_va,
            "pte_address": 0x303000,
            "pte_value": 0x200007,
            "page_size": 4096,
            "mapping_type": "4 KiB page",
            "confidence": "high",
            "shared": False,
            "writable": True,
            "user_accessible": True,
            "no_execute": False,
            "query_generation": generation,
        },
        "page_table": {
            "pid": owner_pid,
            "directory_table_base": dtb,
            "virtual_address": owner_va,
            "physical_address": owner_pa,
            "pfn": owner_pfn,
            "page_size": 4096,
            "page_offset": 0,
            "la57": False,
            "translated": True,
            "effective_writable": True,
            "effective_user": True,
            "effective_nx": False,
            "steps": [
                {
                    "level": level,
                    "index": index,
                    "entry_physical_address": entry_pa,
                    "entry_value": entry_value,
                    "next_pfn": next_pfn,
                    "present": True,
                    "writable": True,
                    "user": True,
                    "page_size": False,
                    "no_execute": False,
                }
                for level, index, entry_pa, entry_value, next_pfn in steps
            ],
        },
        "revalidation": {
            "process_identity_unchanged": True,
            "dtb_unchanged": True,
            "walk_unchanged": True,
            "process_start_id_before": 0x123456789ABCDEF,
            "process_start_id_after": 0x123456789ABCDEF,
            "dtb_before": dtb,
            "dtb_after": dtb,
            "translated_before_pa": owner_pa,
            "translated_after_pa": owner_pa,
        },
        "page_files": {
            "process_read": process_page_path.name,
            "physical_read": physical_page_path.name,
        },
        "page_sha256": {
            "process_read": file_sha256(process_page_path),
            "physical_read": file_sha256(physical_page_path),
        },
        "page_bytes": 4096,
        "page_match": True,
        "kernel_explorer": {
            "module": {
                "name": "KDbgDriver.sys",
                "package_relative_path": "drivers/KDbgDriver.sys",
                "image_sha256": file_sha256(
                    package / "drivers/KDbgDriver.sys"),
                "machine": 0x8664,
                "base": kernel_module_base,
                "size": 0x100000,
                "pe_timestamp": 1,
                "image_size": 0x100000,
                "header_bytes": 512,
                "live_header_file": "kernel-live-header.bin",
                "live_header_sha256": file_sha256(
                    evidence_dir / "kernel-live-header.bin"),
                "local_header_file": "kernel-local-header.bin",
                "local_header_sha256": file_sha256(
                    evidence_dir / "kernel-local-header.bin"),
                "headers_match": True,
                "header_match_mode": "exact-except-loader-image-base",
                "image_base_offset": 0x98 + 24,
                "live_image_base": kernel_module_base,
                "local_preferred_image_base": 0x0000000140000000,
            },
            "symbol": {
                "pdb_name": "KDbgDriver.pdb",
                "pdb_file": "KDbgDriver.pdb",
                "package_relative_path": "drivers/KDbgDriver.pdb",
                "pdb_sha256": file_sha256(evidence_pdb),
                "pe_guid": "0123456789abcdef0123456789abcdef",
                "pdb_guid": "0123456789abcdef0123456789abcdef",
                "pe_age": 1,
                "pdb_age": 1,
                "exact_match": True,
                "symbol_name": "FixtureSymbol",
                "symbol_address": kernel_module_base + 0x1000,
                "displacement": 0,
            },
            "read": {
                "address": kernel_module_base + 0x1000,
                "requested_bytes": 32,
                "completed_bytes": 32,
                "file": "kernel-read.bin",
                "sha256": file_sha256(evidence_dir / "kernel-read.bin"),
            },
            "disassembly": {
                "architecture": "x64",
                "formatter": "intel",
                "start_address": kernel_module_base + 0x1000,
                "consumed_bytes": 16,
                "instruction_count": 4,
                "truncated": False,
            },
        },
    }
    path = evidence_dir / "analysis.json"
    path.write_text(json.dumps(analysis), encoding="utf-8")
    return path


def build_live_bundle(
    root: Path, abi_version: int = 6,
) -> tuple[Path, Path, Path]:
    package = root / VALIDATOR.PACKAGE_NAME
    symbols = root / VALIDATOR.SYMBOLS_NAME
    evidence_dir = root / "evidence"
    package.mkdir()
    symbols.mkdir()
    evidence_dir.mkdir()

    main_files = (
        "KDBG.exe",
        "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
        "tools/kdbg_live_verify.exe",
        "tools/kdbg_process_fixture.exe",
        "drivers/KDbgDriver.sys",
        "drivers/KDbgProbe.sys",
    )
    for index, relative in enumerate(main_files):
        target = package / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(f"main-{index}".encode())
    fixture_driver = bytearray(512)
    fixture_driver[:2] = b"MZ"
    struct.pack_into("<I", fixture_driver, 0x3C, 0x80)
    fixture_driver[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", fixture_driver, 0x84,
        0x8664, 1, 1, 0, 0, 0xF0, 0,
    )
    struct.pack_into("<H", fixture_driver, 0x98, 0x20B)
    struct.pack_into("<Q", fixture_driver, 0x98 + 24, 0x0000000140000000)
    struct.pack_into("<I", fixture_driver, 0x98 + 56, 0x100000)
    struct.pack_into("<I", fixture_driver, 0x98 + 60, 512)
    (package / "drivers/KDbgDriver.sys").write_bytes(fixture_driver)
    for index, relative in enumerate(VALIDATOR.SYMBOLS_REQUIRED):
        target = symbols / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(f"symbol-{index}".encode())
    (package / "SHA256SUMS.txt").write_text("fixture main manifest\n", encoding="ascii")
    (symbols / "SHA256SUMS.txt").write_text("fixture symbols manifest\n", encoding="ascii")

    baseline = bytes(index & 0xFF for index in range(4096))
    expected = bytearray(baseline)
    mask = (0x4B, 0x44, 0x42, 0x47, 0xA5, 0x5A, 0x3C, 0xC3)
    for index, value in enumerate(mask):
        expected[0x100 + index] ^= value
    pages = {
        "baseline.bin": baseline,
        "preflight.bin": baseline,
        "expected-after.bin": bytes(expected),
        "readback.bin": bytes(expected),
        "independent-reload.bin": bytes(expected),
        "rollback.bin": baseline,
    }
    for name, data in pages.items():
        (evidence_dir / name).write_bytes(data)

    baseline_crc = zlib.crc32(baseline) & 0xFFFFFFFF
    expected_crc = zlib.crc32(expected) & 0xFFFFFFFF
    report = (valid_write_report_abi7()
              if abi_version == 7 else valid_write_report())
    runtime_identity = report["runtime_identity"]
    runtime_identity["verifier"]["sha256"] = file_sha256(  # type: ignore[index]
        package / "tools/kdbg_live_verify.exe")
    runtime_identity["kdbg_service"]["binary"]["sha256"] = file_sha256(  # type: ignore[index]
        package / "drivers/KDbgDriver.sys")
    runtime_identity["probe_service"]["binary"]["sha256"] = file_sha256(  # type: ignore[index]
        package / "drivers/KDbgProbe.sys")
    for name in ("probe_before", "probe_after_rollback"):
        report[name]["crc32"] = baseline_crc  # type: ignore[index]
    report["probe_after_write"]["crc32"] = expected_crc  # type: ignore[index]
    report["comparisons"] = [
        comparison("baseline_vs_preflight", baseline_crc),
        comparison("expected_vs_write_readback", expected_crc),
        comparison("expected_vs_independent_reload", expected_crc),
        comparison("baseline_vs_rollback_readback", baseline_crc),
        comparison("baseline_vs_post_rollback_read", baseline_crc),
    ]
    report_path = evidence_dir / "live-run.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    gui_metadata = {
        "schema": "kdbg-physical-live-evidence-v1",
        "timestamp_utc": "2026-09-16T00:00:00.000Z",
        "page_size": 4096,
        "driver_abi_version": abi_version,
        "pfn": "0x100",
        "physical_address": "0x100000",
        "edit_offset": 0x100,
        "edit_length": 8,
        "edit_xor_mask": VALIDATOR.PROBE_EDIT_MASK.hex(),
        "page_files": {
            "baseline": "baseline.bin",
            "preflight": "preflight.bin",
            "expected_after": "expected-after.bin",
            "readback": "readback.bin",
            "independent_reload": "independent-reload.bin",
            "rollback": "rollback.bin",
        },
        "dirty_runs": [{"offset": 0x100, "length": 8}],
        "write_gate_relocked": True,
        "preflight_match": True,
        "full_readback_match": True,
        "independent_reload_match": True,
        "rollback_match": True,
        "probe": {},
    }
    for name, source in (
        ("baseline", report["probe_before"]),
        ("after_write", report["probe_after_write"]),
        ("after_reload", report["probe_after_write"]),
        ("after_rollback", report["probe_after_rollback"]),
    ):
        gui_metadata["probe"][name] = {  # type: ignore[index]
            "generation": source["generation"],
            "byte_count": source["byte_count"],
            "virtual_address": hex(source["virtual_address"]),
            "physical_address": hex(source["physical_address"]),
            "pfn": hex(source["pfn"]),
            "crc32": f"0x{source['crc32']:08x}",
        }
    gui_path = evidence_dir / "metadata.json"
    gui_path.write_text(json.dumps(gui_metadata), encoding="utf-8")
    analysis_path = build_analysis_metadata(
        evidence_dir, package, symbols, abi_version)
    (evidence_dir / "commands.log").write_text("fixture command log\n", encoding="utf-8")
    (evidence_dir / "demo.gif").write_bytes(valid_test_gif())
    scene_review = {
        "schema": "kdbg.demo-scene-review.v1",
        "video_file": "demo.gif",
        "video_sha256": file_sha256(evidence_dir / "demo.gif"),
        "reviewer": "release-reviewer",
        "reviewed_utc": "2026-09-16T00:10:00Z",
        "private_paths_redacted": True,
        "unrelated_process_data_redacted": True,
        "scenes": [
            {
                "id": identifier,
                "start_ms": index * 1000,
                "end_ms": (index + 1) * 1000,
                "observed": True,
                "notes": f"Observed {identifier}",
            }
            for index, identifier in enumerate(VALIDATOR.DEMO_SCENE_ORDER)
        ],
    }
    scene_review_path = evidence_dir / "scene-review.json"
    scene_review_path.write_text(json.dumps(scene_review), encoding="utf-8")

    evidence = {
        "schema": "kdbg.live-evidence.v4",
        "timestamp_utc": "2026-09-16T00:20:00.000Z",
        "os_build": 26100,
        "package_version": "1.1.0",
        "abi_version": abi_version,
        "pfn": "0x100",
        "physical_address": "0x100000",
        "page_size": 4096,
        "artifact_sha256": {
            relative: file_sha256(package / relative) for relative in main_files
        },
        "symbol_sha256": {
            relative: file_sha256(symbols / relative)
            for relative in VALIDATOR.SYMBOLS_REQUIRED
        },
        "package_manifest_sha256": file_sha256(package / "SHA256SUMS.txt"),
        "symbols_manifest_sha256": file_sha256(symbols / "SHA256SUMS.txt"),
        "baseline_bytes": 4096,
        "preflight_bytes": 4096,
        "readback_bytes": 4096,
        "reload_bytes": 4096,
        "rollback_bytes": 4096,
        "baseline_sha256": file_sha256(evidence_dir / "baseline.bin"),
        "expected_after_sha256": file_sha256(evidence_dir / "expected-after.bin"),
        "readback_sha256": file_sha256(evidence_dir / "readback.bin"),
        "independent_reload_sha256": file_sha256(evidence_dir / "independent-reload.bin"),
        "rollback_sha256": file_sha256(evidence_dir / "rollback.bin"),
        "baseline_file": "baseline.bin",
        "preflight_file": "preflight.bin",
        "expected_after_file": "expected-after.bin",
        "readback_file": "readback.bin",
        "independent_reload_file": "independent-reload.bin",
        "rollback_file": "rollback.bin",
        "probe_generation_before": 7,
        "probe_generation_after_write": 7,
        "probe_generation_after_rollback": 7,
        "probe_crc32_before": f"0x{baseline_crc:08x}",
        "probe_crc32_after_write": f"0x{expected_crc:08x}",
        "probe_crc32_after_rollback": f"0x{baseline_crc:08x}",
        "edit_xor_mask": VALIDATOR.PROBE_EDIT_MASK.hex(),
        "dirty_runs": [{"offset": 0x100, "length": 8}],
        "gui_metadata_file": "metadata.json",
        "gui_metadata_sha256": file_sha256(gui_path),
        "analysis_metadata_file": "analysis.json",
        "analysis_metadata_sha256": file_sha256(analysis_path),
        "command_log_file": "commands.log",
        "command_log_sha256": file_sha256(evidence_dir / "commands.log"),
        "video_file": "demo.gif",
        "video_sha256": file_sha256(evidence_dir / "demo.gif"),
        "video_media": {
            "format": "gif", "width": 320, "height": 180,
            "frame_count": 20, "duration_ms": 20000,
        },
        "scene_review_file": "scene-review.json",
        "scene_review_sha256": file_sha256(scene_review_path),
        "live_run_report_file": "live-run.json",
        "live_run_report_sha256": file_sha256(report_path),
        "demo_scenes": list(VALIDATOR.DEMO_SCENE_ORDER),
    }
    for field in VALIDATOR.TRUE_EVIDENCE_FIELDS:
        evidence[field] = True
    evidence_path = evidence_dir / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    return evidence_path, package, symbols


def build_baremetal_bundle(root: Path) -> tuple[Path, Path]:
    package = root / "package"
    evidence_dir = root / "baremetal-evidence"
    (package / "drivers").mkdir(parents=True)
    evidence_dir.mkdir()
    source_hash = "ab" * 32
    manifest = package / "SHA256SUMS.txt"
    manifest.write_text("00" * 32 + "  fixture.bin\n", encoding="utf-8")
    (package / "BUILD-METADATA.json").write_text(json.dumps({
        "source_snapshot_sha256": source_hash,
    }), encoding="utf-8")
    for name in ("KDbgDriver.cat", "KDbgProbe.cat"):
        (package / "drivers" / name).write_bytes((name + "-signed").encode())

    baseline = bytearray((index * 13 + 7) & 0xFF for index in range(4096))
    expected = bytearray(baseline)
    for index, mask in enumerate(VALIDATOR.PROBE_EDIT_MASK):
        expected[VALIDATOR.PROBE_EDIT_OFFSET + index] ^= mask
    page_payloads = {
        "baseline": bytes(baseline),
        "preflight": bytes(baseline),
        "expected_after": bytes(expected),
        "readback": bytes(expected),
        "independent_reload": bytes(expected),
        "rollback": bytes(baseline),
    }
    artifact_paths: dict[str, Path] = {}
    for name, payload in page_payloads.items():
        artifact_paths[name] = evidence_dir / f"{name}.bin"
        artifact_paths[name].write_bytes(payload)

    runtime_identity = "11" * 32
    boot_before = "22" * 32
    pfn = 0x12345
    cleanup_report = {
        "schema": "kdbg.win11-baremetal-cleanup-report.v1",
        "success": True,
        "runtime_host_machine_identity_sha256": runtime_identity,
        "boot_id_sha256": boot_before,
        "final_gate_locked": True,
        "services": {"KDBG": "absent", "KDBGProbe": "absent"},
        "devices": {"KDBG": "absent", "KDBGProbe": "absent"},
        "errors": [],
    }
    for name, value in (
        ("cleanup_report", cleanup_report),
    ):
        artifact_paths[name] = evidence_dir / f"{name}.json"
        artifact_paths[name].write_text(json.dumps(value), encoding="utf-8")
    artifact_paths["package_archive"] = evidence_dir / "KDBG-package.zip"
    with zipfile.ZipFile(
        artifact_paths["package_archive"], "w", zipfile.ZIP_DEFLATED
    ) as bundle:
        for package_file in sorted(path for path in package.rglob("*") if path.is_file()):
            relative = package_file.relative_to(package).as_posix()
            bundle.write(package_file, f"{VALIDATOR.PACKAGE_NAME}/{relative}")
    package_hash = file_sha256(artifact_paths["package_archive"])
    signer_thumbprint = "44" * 20
    signer_certificate_hash = "55" * 32
    signature_report = {
        "schema": "kdbg.win11-baremetal-signature-report.v1",
        "verified": True,
        "status": "Valid",
        "verification_command": "Get-AuthenticodeSignature",
        "exit_code": 0,
        "package_sha256": package_hash,
        "signer_thumbprint": signer_thumbprint,
        "signer_certificate_sha256": signer_certificate_hash,
        "catalogs": [
            {
                "package_relative_path": f"drivers/{name}",
                "sha256": file_sha256(package / "drivers" / name),
            }
            for name in ("KDbgDriver.cat", "KDbgProbe.cat")
        ],
    }
    artifact_paths["signature_report"] = evidence_dir / "signature_report.json"
    artifact_paths["signature_report"].write_text(
        json.dumps(signature_report), encoding="utf-8")
    comparison_names = [
        ("baseline_vs_preflight", "baseline", "preflight"),
        ("expected_vs_write_readback", "expected_after", "readback"),
        ("expected_vs_independent_reload", "expected_after", "independent_reload"),
        ("baseline_vs_rollback_readback", "baseline", "rollback"),
    ]
    live_report = {
        "schema": "kdbg.live-verify.v2",
        "mode": "baremetal-probe-write-rollback",
        "success": True,
        "cancelled": False,
        "operator_confirmed_disposable_vm": False,
        "snapshot_id": "",
        "errors": [],
        "baremetal_contract": {
            "target_profile": "LocalHost",
            "probe_identity_fresh_at_rollback": True,
            "rollback_suppressed_stale_identity": False,
        },
        "backend": {
            "name": "KDbgDriver",
            "abi_version": 7,
            "connected": True,
            "write_enabled": False,
            "is_mock": False,
            "supports_physical_page_compare_write": True,
        },
        "probe_before": probe(0x11111111),
        "probe_after_write": probe(0x22222222),
        "probe_after_rollback": probe(0x11111111),
        "write_cleanup": {
            "edit_offset": VALIDATOR.PROBE_EDIT_OFFSET,
            "edit_length": 8,
            "apply_requested_bytes": 8,
            "user_dirty_bytes": 8,
            "apply_driver_transferred_bytes": 4096,
            "rollback_requested_bytes": 4096,
            "rollback_driver_transferred_bytes": 4096,
            "rollback_attempted": True,
            "rollback_verified": True,
            "final_relock_attempted": True,
            "final_gate_locked": True,
        },
        "raw_page_artifacts": [
            {
                "role": name,
                "file_name": artifact_paths[name].name,
                "sha256": file_sha256(artifact_paths[name]),
                "byte_count": 4096,
                "written": True,
            }
            for name in page_payloads
        ],
        "comparisons": [
            comparison(
                name,
                zlib.crc32(artifact_paths[expected_name].read_bytes()) & 0xFFFFFFFF,
                zlib.crc32(artifact_paths[actual_name].read_bytes()) & 0xFFFFFFFF,
            )
            for name, expected_name, actual_name in comparison_names
        ],
    }
    for name in ("probe_before", "probe_after_write", "probe_after_rollback"):
        live_report[name]["pfn"] = pfn
        live_report[name]["physical_address"] = pfn << 12
    artifact_paths["live_run_report"] = evidence_dir / "live-run.json"
    artifact_paths["live_run_report"].write_text(
        json.dumps(live_report), encoding="utf-8")
    artifacts = {
        name: {
            "file": path.name,
            "sha256": file_sha256(path),
            "bytes": path.stat().st_size,
        }
        for name, path in artifact_paths.items()
    }
    evidence = {
        "schema": VALIDATOR.BAREMETAL_EVIDENCE_SCHEMA,
        "lane": "bare-metal-runtime-host",
        "success": True,
        "dry_run": False,
        "completed_utc": "2026-09-19T00:10:00Z",
        "roles": {
            "runtime_host": {
                "role": "runtime_host",
                "machine_identity_sha256": runtime_identity,
                "boot_id_before_sha256": boot_before,
                "os_name": "Windows",
                "os_build": 26100,
                "architecture": "x64",
                "execution_context": "bare-metal",
                "is_virtual_machine": False,
                "hypervisor_present": True,
            },
            "orchestrator_host": {
                "role": "orchestrator_host",
                "machine_identity_sha256": runtime_identity,
            },
        },
        "package": {
            "package_sha256": package_hash,
            "manifest_sha256": file_sha256(manifest),
            "source_snapshot_sha256": source_hash,
            "signer_thumbprint": signer_thumbprint,
            "signer_certificate_sha256": signer_certificate_hash,
            "signature_status": "Valid",
        },
        "binding": {
            "runtime_host_machine_identity_sha256": runtime_identity,
            "boot_id_before_sha256": boot_before,
            "package_sha256": package_hash,
            "source_snapshot_sha256": source_hash,
            "signer_thumbprint": signer_thumbprint,
        },
        "target": {
            "provider": "KDbgProbe",
            "discovery": "IOCTL_KDBG_PROBE_GET_INFO",
            "ownership": "KDbgProbe-owned contiguous page",
            "probe_derived": True,
            "raw_user_pfn": False,
            "pfn": pfn,
            "physical_address": pfn << 12,
            "page_size": 4096,
            "generation": 7,
        },
        "backend": {
            "name": "KDbgDriver",
            "connected": True,
            "is_mock": False,
            "abi_version": 7,
            "write_enabled_final": False,
            "capabilities": ["compare-write-page-v1"],
        },
        "artifacts": artifacts,
        "transaction": {
            "status": "passed",
            "physical_read_4096": True,
            "preflight_full_match": True,
            "one_shot_unlock": True,
            "unlock_consumed": True,
            "dirty_bytes": 8,
            "driver_requested_bytes": 4096,
            "driver_transferred_bytes": 4096,
            "full_readback_match": True,
            "independent_reload_match": True,
            "rollback_requested_bytes": 4096,
            "rollback_completed_bytes": 4096,
            "rollback_full_match": True,
            "final_gate_locked": True,
            "edit_offset": VALIDATOR.PROBE_EDIT_OFFSET,
            "edit_length": 8,
            "edit_xor_mask": VALIDATOR.PROBE_EDIT_MASK.hex(),
            "runtime_host_machine_identity_sha256": runtime_identity,
            "boot_id_sha256": boot_before,
            "abi_version": 7,
            "operation": "compare-write-page-v1",
            "compare_bytes": 4096,
        },
        "cleanup": {
            "uninstall_completed": True,
            "services_absent": True,
            "devices_absent": True,
            "errors": [],
        },
        "errors": [],
    }
    evidence_path = evidence_dir / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    return evidence_path, package


class BareMetalHostEvidenceValidatorTests(unittest.TestCase):
    def validate_mutation(self, mutate=None) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="kdbg-baremetal-evidence-") as directory:
            evidence_path, package = build_baremetal_bundle(Path(directory))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            if mutate is not None:
                mutate(evidence, evidence_path.parent)
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_baremetal_host_evidence(
                evidence_path, package, errors)
            return errors

    @staticmethod
    def rewrite_artifact(
        evidence: dict, directory: Path, name: str, value: dict,
    ) -> None:
        path = directory / evidence["artifacts"][name]["file"]
        path.write_text(json.dumps(value), encoding="utf-8")
        evidence["artifacts"][name]["sha256"] = file_sha256(path)
        evidence["artifacts"][name]["bytes"] = path.stat().st_size

    def test_valid_baremetal_evidence_allows_same_host_orchestrator(self) -> None:
        self.assertEqual([], self.validate_mutation())

    def test_guest_report_cannot_masquerade_as_baremetal(self) -> None:
        def mutate(evidence: dict, _: Path) -> None:
            evidence["guest_validation_passed"] = True
            evidence["roles"]["runtime_host"]["execution_context"] = (
                "virtual-machine-guest")
            evidence["roles"]["runtime_host"]["is_virtual_machine"] = True

        errors = self.validate_mutation(mutate)
        self.assertTrue(any("cannot masquerade" in error for error in errors), errors)
        self.assertTrue(any("bare-metal execution context" in error for error in errors), errors)

    def test_runtime_machine_binding_mismatch_is_rejected(self) -> None:
        def mutate(evidence: dict, _: Path) -> None:
            evidence["binding"]["runtime_host_machine_identity_sha256"] = "ff" * 32

        self.assertTrue(any(
            "binding identity mismatch" in error
            for error in self.validate_mutation(mutate)
        ))

    def test_cleanup_observation_failure_is_rejected(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            report_path = directory / evidence["artifacts"]["cleanup_report"]["file"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["services"]["KDBG"] = "running"
            self.rewrite_artifact(evidence, directory, "cleanup_report", report)

        self.assertTrue(any(
            "cleanup observation report" in error
            for error in self.validate_mutation(mutate)
        ))

    def test_abi_v6_or_missing_compare_write_is_rejected(self) -> None:
        def mutate(evidence: dict, _: Path) -> None:
            evidence["backend"]["abi_version"] = 6
            evidence["backend"]["capabilities"] = []
            evidence["transaction"]["abi_version"] = 6
            evidence["transaction"]["operation"] = "legacy-write"

        errors = self.validate_mutation(mutate)
        self.assertTrue(any("ABI v7" in error for error in errors), errors)

    def test_live_report_missing_compare_write_capability_is_rejected(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            report_path = directory / evidence["artifacts"]["live_run_report"]["file"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            del report["backend"]["supports_physical_page_compare_write"]
            self.rewrite_artifact(
                evidence, directory, "live_run_report", report)

        self.assertTrue(any(
            "backend is not locked ABI v7" in error
            for error in self.validate_mutation(mutate)
        ))

    def test_package_archive_bytes_are_actually_bound(self) -> None:
        def mutate(_: dict, directory: Path) -> None:
            (directory / "KDBG-package.zip").write_bytes(b"different package")

        self.assertTrue(any(
            "artifact byte count mismatch: package_archive" in error or
            "artifact hash mismatch: package_archive" in error
            for error in self.validate_mutation(mutate)
        ))

    def test_archive_tree_mismatch_is_rejected_even_with_updated_hash(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            archive = directory / evidence["artifacts"]["package_archive"]["file"]
            with zipfile.ZipFile(archive, "a", zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr(f"{VALIDATOR.PACKAGE_NAME}/extra.bin", b"extra")
            digest = file_sha256(archive)
            evidence["artifacts"]["package_archive"]["sha256"] = digest
            evidence["artifacts"]["package_archive"]["bytes"] = archive.stat().st_size
            evidence["package"]["package_sha256"] = digest
            evidence["binding"]["package_sha256"] = digest
            signature_path = directory / evidence["artifacts"]["signature_report"]["file"]
            signature = json.loads(signature_path.read_text(encoding="utf-8"))
            signature["package_sha256"] = digest
            self.rewrite_artifact(evidence, directory, "signature_report", signature)

        self.assertTrue(any(
            "archive file set does not match" in error
            for error in self.validate_mutation(mutate)
        ))

    def test_missing_live_verifier_report_is_rejected(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            report = directory / evidence["artifacts"]["live_run_report"]["file"]
            report.unlink()

        self.assertTrue(any(
            "artifact live_run_report" in error
            for error in self.validate_mutation(mutate)
        ))

    def test_live_verifier_page_hash_mismatch_is_rejected(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            report_path = directory / evidence["artifacts"]["live_run_report"]["file"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            readback = next(
                item for item in report["raw_page_artifacts"]
                if item["role"] == "readback")
            readback["sha256"] = "ff" * 32
            self.rewrite_artifact(evidence, directory, "live_run_report", report)

        self.assertTrue(any(
            "page binding mismatch: readback" in error
            for error in self.validate_mutation(mutate)
        ))


class LiveRunValidatorTests(unittest.TestCase):
    def validate(self, report: dict[str, object]) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="kdbg-validator-") as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_live_run(path, errors)
            return errors

    def validate_bundle_mutation(self, mutate) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="kdbg-live-bundle-") as directory:
            evidence_path, package, symbols = build_live_bundle(Path(directory))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            mutate(evidence, evidence_path.parent)
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_live(evidence_path, package, symbols, errors)
            return errors

    def test_valid_write_report(self) -> None:
        self.assertEqual([], self.validate(valid_write_report()))

    def test_valid_abi7_write_report(self) -> None:
        self.assertEqual([], self.validate(valid_write_report_abi7()))

    def test_valid_abi7_live_bundle(self) -> None:
        with tempfile.TemporaryDirectory(
                prefix="kdbg-abi7-live-bundle-") as directory:
            evidence, package, symbols = build_live_bundle(
                Path(directory), abi_version=7)
            errors: list[str] = []
            VALIDATOR.validate_live(evidence, package, symbols, errors)
            self.assertEqual([], errors)

    def test_abi7_write_report_requires_compare_write_capability(self) -> None:
        report = valid_write_report_abi7()
        del report["backend"]["supports_physical_page_compare_write"]  # type: ignore[index]
        self.assertTrue(any(
            "exact-page compare/write capability" in error
            for error in self.validate(report)
        ))

    def test_mock_backend_is_rejected(self) -> None:
        report = valid_write_report()
        report["backend"]["is_mock"] = True  # type: ignore[index]
        self.assertTrue(any("non-mock" in error for error in self.validate(report)))

    def test_missing_rollback_counter_is_rejected(self) -> None:
        report = valid_write_report()
        report["session_final"]["successful_writes"] = 11  # type: ignore[index]
        self.assertTrue(any("apply plus rollback" in error for error in self.validate(report)))

    def test_final_open_gate_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["write_cleanup"]["final_gate_locked"] = False  # type: ignore[index]
        report["session_final"]["write_enabled"] = True  # type: ignore[index]
        errors = self.validate(report)
        self.assertTrue(any("final write gate" in error for error in errors))
        self.assertTrue(any("one locked controller" in error for error in errors))

    def test_wrong_edit_range_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["write_cleanup"]["edit_offset"] = 0x108  # type: ignore[index]
        self.assertTrue(any(
            "cleanup contract" in error for error in self.validate(report)
        ))

    def test_missing_named_comparison_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["comparisons"] = report["comparisons"][:-1]  # type: ignore[index]
        self.assertTrue(any(
            "lacks unique full-page comparison" in error
            for error in self.validate(report)
        ))

    def test_forged_latency_summary_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["latency"]["read_p95_ms"] = 99.0  # type: ignore[index]
        self.assertTrue(any(
            "read_p95_ms does not match" in error
            for error in self.validate(report)
        ))

    def test_zero_probe_pfn_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        for name in ("probe_before", "probe_after_write", "probe_after_rollback"):
            report[name]["pfn"] = 0  # type: ignore[index]
            report[name]["physical_address"] = 0  # type: ignore[index]
        self.assertTrue(any(
            "PFN is zero" in error for error in self.validate(report)
        ))

    def test_probe_generation_change_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["probe_after_write"]["generation"] = 8  # type: ignore[index]
        errors = self.validate(report)
        self.assertTrue(any(
            "Probe generation changed" in error for error in errors
        ))

    def test_old_windows_build_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["system"]["os_build"] = VALIDATOR.MIN_WINDOWS_BUILD - 1  # type: ignore[index]
        self.assertTrue(any(
            "19041 or newer" in error for error in self.validate(report)
        ))

    def test_unverified_runtime_identity_is_rejected(self) -> None:
        report = copy.deepcopy(valid_write_report())
        report["runtime_identity"]["verified"] = False  # type: ignore[index]
        report["runtime_identity"]["kdbg_service"]["current_state"] = 1  # type: ignore[index]
        errors = self.validate(report)
        self.assertTrue(any("not verified" in error for error in errors))
        self.assertTrue(any("running kernel driver" in error for error in errors))

    def test_v4_bundle_binds_raw_pages_and_symbols(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-live-bundle-") as directory:
            evidence, package, symbols = build_live_bundle(Path(directory))
            errors: list[str] = []
            VALIDATOR.validate_live(evidence, package, symbols, errors)
            self.assertEqual([], errors)

    def test_v4_bundle_accepts_gui_compact_utc_timestamp(self) -> None:
        def compact_timestamp(evidence: dict, directory: Path) -> None:
            metadata_path = directory / evidence["gui_metadata_file"]
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["timestamp_utc"] = "20260916-000000-123Z"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            evidence["gui_metadata_sha256"] = file_sha256(metadata_path)

        self.assertEqual([], self.validate_bundle_mutation(compact_timestamp))

    def test_v4_bundle_rejects_malformed_gui_compact_timestamp(self) -> None:
        def malformed_timestamp(evidence: dict, directory: Path) -> None:
            metadata_path = directory / evidence["gui_metadata_file"]
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["timestamp_utc"] = "20260916-000000Z"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            evidence["gui_metadata_sha256"] = file_sha256(metadata_path)

        errors = self.validate_bundle_mutation(malformed_timestamp)
        self.assertTrue(any(
            "invalid GUI metadata timestamp_utc" in error for error in errors
        ), errors)

    def test_live_evidence_generator_hashes_every_required_symbol(self) -> None:
        generator = (
            VALIDATOR_PATH.parent / "new_live_evidence.ps1"
        ).read_text(encoding="utf-8-sig")
        block = re.search(
            r"\$SymbolHashes\s*=\s*\[ordered\]@\{\}\s*"
            r"foreach\s*\(\$Relative\s+in\s+@\((.*?)\)\)\s*\{",
            generator,
            re.DOTALL,
        )
        self.assertIsNotNone(block, "generator symbol list was not found")
        symbol_list = block.group(1) if block is not None else ""
        for relative in VALIDATOR.SYMBOLS_REQUIRED:
            with self.subTest(relative=relative):
                self.assertIn(f'"{relative}"', symbol_list)

    def test_v4_bundle_rejects_missing_setup_symbol_hash(self) -> None:
        def missing_setup_hash(evidence: dict, _: Path) -> None:
            del evidence["symbol_sha256"]["KDBGSetup.pdb"]

        errors = self.validate_bundle_mutation(missing_setup_hash)
        self.assertTrue(any(
            "symbol_sha256.KDBGSetup.pdb" in error for error in errors
        ), errors)

    def test_v4_bundle_rejects_rehashed_pages_not_from_live_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-live-bundle-") as directory:
            evidence_path, package, symbols = build_live_bundle(Path(directory))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            for name, hash_field in (
                ("expected-after.bin", "expected_after_sha256"),
                ("readback.bin", "readback_sha256"),
                ("independent-reload.bin", "independent_reload_sha256"),
            ):
                page = evidence_path.parent / name
                data = bytearray(page.read_bytes())
                data[0x200] ^= 0xFF
                page.write_bytes(data)
                evidence[hash_field] = file_sha256(page)
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_live(evidence_path, package, symbols, errors)
            self.assertTrue(any("raw page CRC" in error for error in errors))

    def test_v4_bundle_rejects_runtime_package_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-live-bundle-") as directory:
            evidence_path, package, symbols = build_live_bundle(Path(directory))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            report_path = evidence_path.parent / evidence["live_run_report_file"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["runtime_identity"]["kdbg_service"]["binary"]["sha256"] = "ab" * 32
            report_path.write_text(json.dumps(report), encoding="utf-8")
            evidence["live_run_report_sha256"] = file_sha256(report_path)
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_live(evidence_path, package, symbols, errors)
            self.assertTrue(any(
                "runtime identity hash" in error for error in errors
            ))

    def test_v4_bundle_rejects_wrong_raw_xor_pattern(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            expected = directory / evidence["expected_after_file"]
            data = bytearray(expected.read_bytes())
            data[VALIDATOR.PROBE_EDIT_OFFSET] ^= 0x01
            expected.write_bytes(data)
            evidence["expected_after_sha256"] = file_sha256(expected)

        errors = self.validate_bundle_mutation(mutate)
        self.assertTrue(any("exact Probe 8-byte XOR pattern" in error for error in errors))

    def test_v4_bundle_rejects_each_probe_run_binding(self) -> None:
        mutations = (
            ("os_build", lambda e, _: e.__setitem__("os_build", 26000),
             "os_build does not match"),
            ("probe_generation", lambda e, _: e.__setitem__(
                "probe_generation_before", e["probe_generation_before"] + 1),
             "probe_generation_before does not match"),
            ("probe_crc", lambda e, _: e.__setitem__(
                "probe_crc32_after_write", "0x12345678"),
             "probe_crc32_after_write does not match"),
            ("edit_xor_mask", lambda e, _: e.__setitem__(
                "edit_xor_mask", "00" * 8), "edit_xor_mask does not match"),
            ("pfn", lambda e, _: e.__setitem__("pfn", "0x101"),
             "Probe PFN/mode do not match"),
            ("physical_address", lambda e, _: e.__setitem__(
                "physical_address", "0x101000"),
             "PFN/PA does not match live run"),
        )
        for name, mutate, expected_error in mutations:
            with self.subTest(binding=name):
                errors = self.validate_bundle_mutation(mutate)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_v4_bundle_rejects_analysis_cross_invariant_mutations(self) -> None:
        def analysis_mutation(change):
            def mutate(evidence: dict, directory: Path) -> None:
                path = directory / evidence["analysis_metadata_file"]
                analysis = json.loads(path.read_text(encoding="utf-8"))
                change(analysis, directory)
                path.write_text(json.dumps(analysis), encoding="utf-8")
                evidence["analysis_metadata_sha256"] = file_sha256(path)
            return mutate

        mutations = (
            (lambda a, _: a["ownership"].__setitem__("pid", 4243),
             "ownership PID does not match fixture PID"),
            (lambda a, _: a["ownership"].__setitem__("pfn", 0x100),
             "distinct from the Probe transaction PFN"),
            (lambda a, _: a["process"].__setitem__("virtual_address", 0x20001000),
             "process VA does not match ownership target"),
            (lambda a, _: a["ownership"].__setitem__(
                "provider", "memprocfs-bridge"),
             "provider must be selected-process-page-table-scan"),
            (lambda a, _: a["ownership"].__setitem__("shared", True),
             "mapping must not be shared"),
            (lambda a, _: a["process"].__setitem__("protocol_version", 2),
             "protocol_version must be exactly 1"),
            (lambda a, _: a["page_table"]["steps"][1].__setitem__(
                "entry_physical_address", 0x301008),
             "breaks the x64 walk chain"),
            (lambda a, _: a["ownership"].__setitem__(
                "pte_value", 0x200003),
             "leaf value does not match ownership PTE value"),
            (lambda a, _: a["page_table"]["steps"][2].__setitem__(
                "entry_value", 0x303087),
             "page_size does not match entry_value"),
            (lambda a, _: a["page_table"].__setitem__(
                "directory_table_base", 0x300001),
             "directory-table base must be a valid aligned x64 address"),
            (lambda a, _: a["page_files"].__setitem__(
                "physical_read", a["page_files"]["process_read"]),
             "must be distinct sibling files"),
            (lambda a, _: a["kernel_explorer"]["symbol"].__setitem__(
                "pdb_name", "KDbgProbe.pdb"),
             "PDB name does not match the evidence PDB filename"),
            (lambda a, _: a["kernel_explorer"]["module"].__setitem__(
                "image_sha256", "ab" * 32),
             "module image hash does not match the package"),
            (lambda a, _: a["kernel_explorer"]["module"].__setitem__(
                "header_bytes", 1024),
             "header length does not match header_bytes"),
            (lambda a, _: a["kernel_explorer"]["module"].__setitem__(
                "header_match_mode", "exact"),
             "header match mode must account only for loader ImageBase"),
            (lambda a, _: a["kernel_explorer"]["module"].__setitem__(
                "live_image_base", 0xFFFFF80000001000),
             "ImageBase metadata does not match the captured headers"),
            (lambda a, _: a["kernel_explorer"]["module"].__setitem__(
                "machine", 0x14C),
             "module machine must be x64"),
            (lambda a, _: a["kernel_explorer"]["symbol"].__setitem__(
                "displacement", 1),
             "read address does not match symbol plus displacement"),
        )
        for change, expected_error in mutations:
            with self.subTest(expected_error=expected_error):
                errors = self.validate_bundle_mutation(analysis_mutation(change))
                self.assertTrue(
                    any(expected_error in error for error in errors), errors)

    def test_v4_bundle_rejects_live_header_change_outside_image_base(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            analysis_path = directory / evidence["analysis_metadata_file"]
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            module = analysis["kernel_explorer"]["module"]
            live_header = directory / module["live_header_file"]
            changed = bytearray(live_header.read_bytes())
            changed[0x40] ^= 0x01
            live_header.write_bytes(changed)
            module["live_header_sha256"] = file_sha256(live_header)
            analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
            evidence["analysis_metadata_sha256"] = file_sha256(analysis_path)

        errors = self.validate_bundle_mutation(mutate)
        self.assertTrue(
            any("differ beyond the loader-applied ImageBase" in error
                for error in errors), errors)

    def test_v4_bundle_rejects_fixture_info_and_page_crc_substitution(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            analysis_path = directory / evidence["analysis_metadata_file"]
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            info_path = directory / analysis["process"]["fixture_info_file"]
            info = json.loads(info_path.read_text(encoding="utf-8"))
            info["generation"] += 1
            info_path.write_text(json.dumps(info), encoding="utf-8")
            analysis["process"]["fixture_info_sha256"] = file_sha256(info_path)
            process_page = directory / analysis["page_files"]["process_read"]
            page = bytearray(process_page.read_bytes())
            page[0] ^= 0xFF
            process_page.write_bytes(page)
            analysis["page_sha256"]["process_read"] = file_sha256(process_page)
            analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
            evidence["analysis_metadata_sha256"] = file_sha256(analysis_path)

        errors = self.validate_bundle_mutation(mutate)
        self.assertTrue(any("fixture INFO generation" in error for error in errors), errors)
        self.assertTrue(any("current CRC32" in error for error in errors), errors)
        self.assertTrue(any("physical 4 KiB pages do not match" in error for error in errors), errors)

    def test_v4_bundle_rejects_noncanonical_crc_prefix_and_case(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            analysis_path = directory / evidence["analysis_metadata_file"]
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            analysis["process"]["baseline_crc32"] = "0x12345678"
            info_path = directory / analysis["process"]["fixture_info_file"]
            info = json.loads(info_path.read_text(encoding="utf-8"))
            info["current_crc32"] = "0xABCDEF12"
            info_path.write_text(json.dumps(info), encoding="utf-8")
            analysis["process"]["fixture_info_sha256"] = file_sha256(info_path)
            analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
            evidence["analysis_metadata_sha256"] = file_sha256(analysis_path)

        errors = self.validate_bundle_mutation(mutate)
        self.assertTrue(any("process baseline_crc32 must be lowercase bare CRC32" in e
                            for e in errors), errors)
        self.assertTrue(any("fixture INFO current_crc32 must be lowercase" in e
                            for e in errors), errors)

    def test_v4_bundle_rejects_invalid_gif_media_contracts(self) -> None:
        def replace_gif(payload: bytes):
            def mutate(evidence: dict, directory: Path) -> None:
                video = directory / evidence["video_file"]
                video.write_bytes(payload)
                evidence["video_sha256"] = file_sha256(video)
            return mutate

        invalid_media = (
            (b"GIF89a fixture", "not a valid evidence GIF"),
            (valid_test_gif(width=1, height=1), "logical dimensions"),
            (valid_test_gif(frames=1), "at least 20 frames"),
            (valid_test_gif(delay_cs=1), "at least 20000 milliseconds"),
            (valid_test_gif().replace(b"\x02\x02\x44\x01\x00",
                                      b"\x02\x02\x00\x00\x00"),
             "LZW stream"),
        )
        for payload, expected_error in invalid_media:
            with self.subTest(expected_error=expected_error):
                errors = self.validate_bundle_mutation(replace_gif(payload))
                self.assertTrue(any(expected_error in error for error in errors), errors)

    def test_v4_bundle_rejects_forged_media_metadata(self) -> None:
        def forged_metadata(evidence: dict, _: Path) -> None:
            evidence["video_media"]["frame_count"] = 999

        self.assertTrue(any(
            "video_media does not match" in error
            for error in self.validate_bundle_mutation(forged_metadata)
        ))

    def test_v4_bundle_rejects_fake_gif_even_when_rehashed(self) -> None:
        def fake_gif(evidence: dict, directory: Path) -> None:
            video = directory / evidence["video_file"]
            video.write_bytes(b"GIF89a fixture")
            evidence["video_sha256"] = file_sha256(video)

        self.assertTrue(any(
            "not a valid evidence GIF" in error
            for error in self.validate_bundle_mutation(fake_gif)
        ))

    def test_v4_bundle_rejects_gui_metadata_substitution(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            metadata_path = directory / evidence["gui_metadata_file"]
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["probe"]["baseline"]["generation"] += 1
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            evidence["gui_metadata_sha256"] = file_sha256(metadata_path)

        errors = self.validate_bundle_mutation(mutate)
        self.assertTrue(any("GUI metadata Probe identity" in error for error in errors))

    def test_v4_bundle_requires_hash_bound_scene_review(self) -> None:
        def mutate(evidence: dict, directory: Path) -> None:
            review_path = directory / evidence["scene_review_file"]
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["scenes"][6]["observed"] = False
            review["scenes"][6]["notes"] = ""
            review_path.write_text(json.dumps(review), encoding="utf-8")
            evidence["scene_review_sha256"] = file_sha256(review_path)

        errors = self.validate_bundle_mutation(mutate)
        self.assertTrue(any("did not mark observed" in error for error in errors))
        self.assertTrue(any("notes are empty" in error for error in errors))

        def reorder(evidence: dict, _: Path) -> None:
            evidence["demo_scenes"] = list(reversed(evidence["demo_scenes"]))

        errors = self.validate_bundle_mutation(reorder)
        self.assertTrue(any("exactly once and in order" in error for error in errors))


class SymbolBuildComparisonTests(unittest.TestCase):
    def test_comparison_requires_binary_equality_not_pdb_byte_equality(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-symbol-compare-") as directory:
            root = Path(directory)
            left = root / "left"
            right = root / "right"
            build_flat_symbol_comparison_root(left, pdb_variant="left")
            build_flat_symbol_comparison_root(right, pdb_variant="right")

            report = COMPARE.compare_symbol_builds(left, right)
            self.assertTrue(report["success"], report["errors"])
            summary = report["summary"]
            self.assertEqual(5, summary["pair_count"])
            self.assertEqual(5, summary["binary_byte_equal_count"])
            self.assertEqual(0, summary["pdb_byte_equal_count"])
            self.assertFalse(summary["pdb_byte_equality_required"])
            self.assertEqual(
                COMPARE.deterministic_json(report),
                COMPARE.deterministic_json(
                    COMPARE.compare_symbol_builds(left, right)),
            )

    def test_comparison_rejects_binary_byte_difference(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-symbol-binary-") as directory:
            root = Path(directory)
            left = root / "left"
            right = root / "right"
            build_flat_symbol_comparison_root(left, pdb_variant="same")
            build_flat_symbol_comparison_root(right, pdb_variant="same")
            binary = right / "KDBG.exe"
            changed = bytearray(binary.read_bytes())
            changed[-1] ^= 0x5A
            binary.write_bytes(changed)

            report = COMPARE.compare_symbol_builds(left, right)
            self.assertFalse(report["success"])
            self.assertTrue(any(
                "cross-build binary bytes differ: KDBG.exe" in error
                for error in report["errors"]
            ), report["errors"])

    def test_comparison_redacts_forbidden_pdb_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-symbol-redact-") as directory:
            root = Path(directory)
            left = root / "left"
            right = root / "right"
            build_flat_symbol_comparison_root(left, pdb_variant="same")
            build_flat_symbol_comparison_root(right, pdb_variant="same")
            forbidden = r"E:\agent\checkout"
            guid = hashlib.sha256(b"KDBG.exe").digest()[:16]
            (right / "KDBG.pdb").write_bytes(pdb_with_extra_stream(
                guid, 1, (forbidden + r"\src\private.cpp").encode("ascii")))

            report = COMPARE.compare_symbol_builds(
                left, right, forbidden_paths=(forbidden,))
            rendered = COMPARE.deterministic_json(report)
            self.assertFalse(report["success"])
            self.assertIn("category=configured-root", rendered)
            self.assertNotIn(forbidden, rendered)

    def test_driver_pairs_are_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-symbol-drivers-") as directory:
            root = Path(directory)
            left = root / "left"
            right = root / "right"
            build_flat_symbol_comparison_root(left, pdb_variant="same")
            build_flat_symbol_comparison_root(right, pdb_variant="same")

            user_report = COMPARE.compare_symbol_builds(left, right)
            self.assertTrue(user_report["success"], user_report["errors"])
            driver_report = COMPARE.compare_symbol_builds(
                left, right, require_drivers=True)
            self.assertFalse(driver_report["success"])
            self.assertEqual(7, driver_report["summary"]["pair_count"])
            self.assertTrue(any(
                "KDbgDriver.sys" in error for error in driver_report["errors"]
            ), driver_report["errors"])


class PackageProvenanceValidatorTests(unittest.TestCase):
    def test_setup_artifacts_are_release_gated(self) -> None:
        self.assertIn("KDBGSetup.exe", VALIDATOR.MAIN_REQUIRED)
        self.assertIn("tools/setup.ps1", VALIDATOR.MAIN_REQUIRED)
        self.assertIn("tools/setup_contract.psm1", VALIDATOR.MAIN_REQUIRED)
        self.assertIn("tools/TargetProfile.psm1", VALIDATOR.MAIN_REQUIRED)
        self.assertIn("KDBGSetup.pdb", VALIDATOR.SYMBOLS_REQUIRED)
        self.assertIn(
            ("KDBGSetup.exe", "KDBGSetup.pdb"),
            VALIDATOR.BINARY_SYMBOL_PAIRS,
        )
        self.assertIn(
            "src/tools/setup/setup.ps1", VALIDATOR.SOURCE_REQUIRED)
        self.assertIn(
            "src/tests/setup_contract_tests.ps1", VALIDATOR.SOURCE_REQUIRED)
        self.assertIn(
            "src/tools/package/TargetProfile.psm1", VALIDATOR.SOURCE_REQUIRED)
        self.assertIn(
            "src/tools/win11_baremetal_validation/Invoke-Win11BareMetalValidation.ps1",
            VALIDATOR.SOURCE_REQUIRED,
        )

    def test_commercial_operations_contract_is_source_gated(self) -> None:
        for relative in (
            "src/tools/validate_commercial_operations.py",
            "src/tests/test_validate_commercial_operations.py",
            ".github/SECURITY.md",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/support_request.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
        ):
            self.assertIn(relative, VALIDATOR.SOURCE_REQUIRED)

    def test_setup_lifecycle_validator_requires_purge_and_root_contracts(self) -> None:
        source_root = VALIDATOR_PATH.parents[1]
        with tempfile.TemporaryDirectory(prefix="kdbg-setup-contract-") as directory:
            package = Path(directory)
            tools = package / "tools"
            tools.mkdir()
            setup = (source_root / "tools/setup/setup.ps1").read_text(
                encoding="utf-8-sig")
            (tools / "setup.ps1").write_text(
                setup.replace("PURGE_SCHEDULED", "PURGE_OMITTED"),
                encoding="utf-8",
            )
            (tools / "setup_contract.psm1").write_bytes(
                (source_root / "tools/setup/setup_contract.psm1").read_bytes())
            errors: list[str] = []
            VALIDATOR.validate_lifecycle(package, errors)
            self.assertTrue(any(
                "tools/setup.ps1 lacks lifecycle marker: PURGE_SCHEDULED" in error
                for error in errors
            ), errors)

    def test_release_document_contract_accepts_complete_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-release-docs-") as directory:
            root = Path(directory)
            for relative, tokens in VALIDATOR.PACKAGE_RELEASE_DOCUMENT_REQUIREMENTS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(tokens), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_release_documents(
                root,
                VALIDATOR.PACKAGE_RELEASE_DOCUMENT_REQUIREMENTS,
                "packaged release document",
                errors,
            )
            self.assertEqual([], errors)

    def test_release_document_contract_rejects_missing_file_and_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-release-docs-negative-") as directory:
            root = Path(directory)
            for relative, tokens in VALIDATOR.PACKAGE_RELEASE_DOCUMENT_REQUIREMENTS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(tokens), encoding="utf-8")
            (root / "docs/PRIVACY.md").unlink()
            support = root / "docs/SUPPORT.md"
            support.write_text("Supported scope only", encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_release_documents(
                root,
                VALIDATOR.PACKAGE_RELEASE_DOCUMENT_REQUIREMENTS,
                "packaged release document",
                errors,
            )
            self.assertTrue(any(
                "packaged release document missing: docs/PRIVACY.md" in error
                for error in errors
            ))
            self.assertTrue(any(
                "marker missing in docs/SUPPORT.md: Support lifecycle" in error
                for error in errors
            ))

    def test_release_pe_rejects_dynamic_msvc_runtime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-static-crt-") as directory:
            binary = Path(directory) / "KDBG.exe"
            binary.write_bytes(b"MZ")
            with mock.patch.object(
                VALIDATOR,
                "parse_pe",
                return_value=(
                    0x8664,
                    {"kernel32.dll", "vcruntime140.dll"},
                    (1, 0, 0, 0),
                    None,
                ),
            ):
                errors: list[str] = []
                VALIDATOR.validate_pe(binary, True, errors)
            self.assertTrue(any(
                "dynamic MSVC CRT vcruntime140.dll" in error
                for error in errors
            ))

    def test_release_pe_accepts_current_product_version(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-current-version-") as directory:
            binary = Path(directory) / "KDBG.exe"
            binary.write_bytes(b"MZ")
            current_version = tuple(
                int(component) for component in VALIDATOR.VERSION.split(".")
            ) + (0,)
            with mock.patch.object(
                VALIDATOR,
                "parse_pe",
                return_value=(0x8664, {"kernel32.dll"}, current_version, None),
            ):
                errors: list[str] = []
                VALIDATOR.validate_pe(binary, True, errors)
            self.assertEqual(errors, [])

    def test_process_fixture_pe_rejects_non_x64_and_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-fixture-pe-") as directory:
            binary = Path(directory) / "kdbg_process_fixture.exe"
            binary.write_bytes(b"MZ")
            with mock.patch.object(
                VALIDATOR,
                "parse_pe",
                return_value=(0x14C, {"kernel32.dll"}, (2, 0, 0, 0), None),
            ):
                errors: list[str] = []
                VALIDATOR.validate_pe(binary, True, errors)
            self.assertTrue(any("is not x64" in error for error in errors))
            self.assertTrue(any("version mismatch" in error for error in errors))

    def test_lock_accepts_hash_pinned_package_and_rejects_bad_hash(self) -> None:
        source_lock = VALIDATOR_PATH.parents[2] / "THIRD_PARTY.lock.json"
        document = json.loads(source_lock.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="kdbg-package-pin-") as directory:
            path = Path(directory) / "THIRD_PARTY.lock.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_lock_document(path, "test lock", errors)
            self.assertEqual([], errors)

            dependency = next(
                item for item in document["dependencies"]
                if item["name"] == "Microsoft.Windows.WDK.x64"
            )
            dependency["sha512"] = "not-a-package-hash"
            path.write_text(json.dumps(document), encoding="utf-8")
            errors = []
            VALIDATOR.validate_lock_document(path, "test lock", errors)
            self.assertTrue(any("hash-locked package" in error for error in errors))

    def test_packaged_validator_infers_main_and_symbols_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-default-targets-") as directory:
            package = Path(directory) / VALIDATOR.PACKAGE_NAME
            script = package / "tools" / "validate_release.py"
            source_mode, main, symbols = VALIDATOR.infer_default_validation_targets(script)
            self.assertFalse(source_mode)
            self.assertEqual(package.resolve(), main)
            self.assertEqual(
                (package.parent / VALIDATOR.SYMBOLS_NAME).resolve(), symbols)

    def test_packaged_validator_does_not_require_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-package-only-") as directory:
            root = Path(directory)
            script = root / VALIDATOR.PACKAGE_NAME / "tools" / "validate_release.py"
            script.parent.mkdir(parents=True)
            script.write_bytes(VALIDATOR_PATH.read_bytes())
            report = root / "live-run.json"
            report.write_text(json.dumps(valid_write_report()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--live-run-report", str(report)],
                cwd=root,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertNotIn("THIRD_PARTY.lock.json", result.stdout + result.stderr)

    def test_main_metadata_requires_exact_catalogs_and_full_toolchain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-package-metadata-") as directory:
            package = Path(directory)
            drivers = package / "drivers"
            drivers.mkdir()
            for relative in VALIDATOR.EXPECTED_CATALOGS:
                (package / relative).write_bytes(b"catalog")
            metadata = valid_main_metadata()
            (package / "BUILD-METADATA.json").write_text(
                json.dumps(metadata), encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_metadata(package, errors)
            self.assertEqual([], errors)

            metadata["catalogs"] = ["drivers/KDbgDriver.cat"]
            metadata["tool_versions"].pop("wdk")  # type: ignore[union-attr]
            (package / "BUILD-METADATA.json").write_text(
                json.dumps(metadata), encoding="utf-8")
            errors = []
            VALIDATOR.validate_metadata(package, errors)
            self.assertTrue(any("both packaged driver CAT" in e for e in errors))
            self.assertTrue(any("tool version is missing: wdk" in e for e in errors))

    def test_product_source_scope_requires_and_verifies_canonical_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-source-manifest-") as directory:
            package = Path(directory)
            record = (
                ("ff" * 32) + "  docs/QUICKSTART.md\n" +
                ("11" * 32) + "  src/core/product.cpp\n"
            )
            (package / VALIDATOR.SOURCE_SNAPSHOT_MANIFEST).write_bytes(
                record.encode("utf-8"))
            metadata = valid_main_metadata()
            metadata.update({
                "source_snapshot_scope": VALIDATOR.PRODUCT_SOURCE_SNAPSHOT_SCOPE,
                "source_snapshot_sha256": hashlib.sha256(
                    record.encode("utf-8")).hexdigest(),
                "source_file_count": 2,
                "source_snapshot_manifest": VALIDATOR.SOURCE_SNAPSHOT_MANIFEST,
                "source_snapshot_policy": {
                    "root_files": ["README.md"],
                    "documentation_files": ["docs/QUICKSTART.md"],
                    "scan_roots": ["src", "licenses"],
                    "excluded_paths": [
                        "docs/exec-plans/**",
                        "docs/VALIDATION_REPORT.md",
                        "docs/TRACEABILITY_MATRIX.md",
                    ],
                    "ignored_directory_names": ["out"],
                    "ignored_extensions": [".obj"],
                },
            })
            errors: list[str] = []
            VALIDATOR.validate_source_provenance(metadata, "metadata", errors)
            VALIDATOR.validate_source_snapshot_manifest(
                package, metadata, "metadata", errors)
            self.assertEqual([], errors)

            metadata["source_snapshot_policy"]["excluded_paths"].remove(  # type: ignore[index]
                "docs/VALIDATION_REPORT.md")
            (package / VALIDATOR.SOURCE_SNAPSHOT_MANIFEST).write_bytes(
                record.replace("11", "22", 1).encode("utf-8"))
            errors = []
            VALIDATOR.validate_source_provenance(metadata, "metadata", errors)
            VALIDATOR.validate_source_snapshot_manifest(
                package, metadata, "metadata", errors)
            self.assertTrue(any("omits mutable ledgers" in e for e in errors))
            self.assertTrue(any("manifest digest mismatch" in e for e in errors))

    def test_inf_catalog_pairing_is_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-inf-catalog-") as directory:
            package = Path(directory)
            drivers = package / "drivers"
            drivers.mkdir()
            (drivers / "KDbgDriver.inf").write_text(
                "[Version]\nCatalogFile=KDbgDriver.cat\n", encoding="utf-8")
            (drivers / "KDbgProbe.inf").write_text(
                "[Version]\nCatalogFile=KDbgProbe.cat\n", encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.validate_inf_catalogs(package, errors)
            self.assertEqual([], errors)

            (drivers / "KDbgProbe.inf").write_text(
                "[Version]\nCatalogFile=wrong.cat\nCatalogFile.NTamd64=KDbgProbe.cat\n",
                encoding="utf-8")
            errors = []
            VALIDATOR.validate_inf_catalogs(package, errors)
            self.assertTrue(any("exactly one CatalogFile" in e for e in errors))

    def test_main_and_symbols_provenance_must_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-package-pair-") as directory:
            package = Path(directory) / VALIDATOR.PACKAGE_NAME
            symbols = Path(directory) / VALIDATOR.SYMBOLS_NAME
            package.mkdir()
            symbols.mkdir()
            main_metadata = valid_main_metadata()
            symbols_metadata = valid_symbols_metadata()
            errors: list[str] = []
            VALIDATOR.validate_package_pair(
                package, symbols, main_metadata, symbols_metadata, errors)
            self.assertEqual([], errors)

            symbols_metadata["source_snapshot_sha256"] = "cd" * 32
            symbols_metadata["tool_versions"] = dict(valid_tool_versions())
            symbols_metadata["tool_versions"]["wdk"] = "10.0.22621.0"  # type: ignore[index]
            errors = []
            VALIDATOR.validate_package_pair(
                package, symbols, main_metadata, symbols_metadata, errors)
            self.assertTrue(any(
                "source_snapshot_sha256" in error for error in errors))
            self.assertTrue(any("tool_versions" in error for error in errors))

    def test_main_and_symbols_optional_release_epoch_must_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-package-epoch-") as directory:
            package = Path(directory) / VALIDATOR.PACKAGE_NAME
            symbols = Path(directory) / VALIDATOR.SYMBOLS_NAME
            package.mkdir()
            symbols.mkdir()
            main_metadata = valid_main_metadata()
            symbols_metadata = valid_symbols_metadata()

            main_metadata["release_epoch"] = "public-symbols-2"
            symbols_metadata["release_epoch"] = "public-symbols-2"
            errors: list[str] = []
            VALIDATOR.validate_package_pair(
                package, symbols, main_metadata, symbols_metadata, errors)
            self.assertEqual([], errors)

            symbols_metadata.pop("release_epoch")
            errors = []
            VALIDATOR.validate_package_pair(
                package, symbols, main_metadata, symbols_metadata, errors)
            self.assertTrue(any(
                "symbols package release_epoch is missing or invalid" in error
                for error in errors
            ), errors)
            self.assertTrue(any(
                "release_epoch mismatch" in error for error in errors), errors)

            symbols_metadata["release_epoch"] = "different-epoch"
            errors = []
            VALIDATOR.validate_package_pair(
                package, symbols, main_metadata, symbols_metadata, errors)
            self.assertTrue(any(
                "release_epoch mismatch" in error for error in errors), errors)

    def test_symbols_path_policy_metadata_is_exact(self) -> None:
        metadata = valid_symbols_metadata()
        errors: list[str] = []
        VALIDATOR.validate_symbol_path_policy_metadata(metadata, errors)
        self.assertEqual([], errors)

        policy = dict(metadata["path_policy"])
        policy["private_paths_present"] = True
        policy["scan_scope"] = ["raw"]
        metadata["path_policy"] = policy
        errors = []
        VALIDATOR.validate_symbol_path_policy_metadata(metadata, errors)
        self.assertTrue(any(
            "private_paths_present mismatch" in error for error in errors), errors)
        self.assertTrue(any("scan_scope mismatch" in error for error in errors), errors)

    def test_pe_and_pdb_guid_age_and_private_path_are_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-codeview-") as directory:
            root = Path(directory)
            guid = bytes(range(16))
            binary = root / "KDBG.exe"
            pdb = root / "KDBG.pdb"
            binary.write_bytes(minimal_pe_with_codeview(guid, 7, "KDBG.pdb"))
            pdb.write_bytes(minimal_pdb(guid, 7))
            errors: list[str] = []
            VALIDATOR.validate_binary_symbol_pair(binary, pdb, errors)
            self.assertEqual([], errors)

            pdb.write_bytes(minimal_pdb(guid, 8))
            errors = []
            VALIDATOR.validate_binary_symbol_pair(binary, pdb, errors)
            self.assertTrue(any("GUID+age mismatch" in e for e in errors))

            binary.write_bytes(minimal_pe_with_codeview(
                guid, 7, r"C:\Users\builder\KDBG.pdb"))
            pdb.write_bytes(minimal_pdb(guid, 7))
            errors = []
            VALIDATOR.validate_binary_symbol_pair(binary, pdb, errors)
            self.assertTrue(any("leaks a build path" in e for e in errors))

    def test_pdb_path_policy_rejects_ascii_and_utf16_without_echo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-pdb-paths-") as directory:
            pdb = Path(directory) / "KDBG.pdb"
            guid = bytes(range(16))
            ascii_path = r"E:\agent\checkout\src\private.cpp"
            utf16_path = r"C:\Users\builder\secret.cpp"
            home_path = "/home/builder/KDBG/src/private.cpp"
            unc_path = r"\\buildhost\share\KDBG\src\private.cpp"
            payload = (
                ascii_path.encode("ascii") + b"\0padding\0" +
                utf16_path.encode("utf-16le") + b"\0\0" +
                home_path.encode("ascii") + b"\0" +
                unc_path.encode("ascii") + b"\0"
            )
            pdb.write_bytes(pdb_with_extra_stream(guid, 7, payload))
            errors: list[str] = []
            VALIDATOR.validate_pdb_path_policy(
                pdb, (r"E:\agent\checkout",), errors)
            joined = "\n".join(errors)
            self.assertIn("category=configured-root encoding=ascii", joined)
            self.assertIn("category=user-profile encoding=utf-16le", joined)
            self.assertIn("category=user-profile encoding=ascii", joined)
            self.assertIn("category=kdbg-checkout encoding=ascii", joined)
            self.assertIn("location_sha256=", joined)
            self.assertNotIn(ascii_path, joined)
            self.assertNotIn(utf16_path, joined)
            self.assertNotIn(home_path, joined)
            self.assertNotIn(unc_path, joined)

    def test_pdb_path_policy_reconstructs_split_msf_streams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-pdb-split-") as directory:
            pdb = Path(directory) / "KDBG.pdb"
            guid = bytes(range(16))
            split_prefix = b"D:\\KD"
            payload = (
                b"A" * (512 - len(split_prefix)) + split_prefix +
                b"BG\\src\\split.cpp\0"
            )
            pdb.write_bytes(pdb_with_extra_stream(
                guid, 7, payload, stream_blocks=(4, 6)))
            errors: list[str] = []
            VALIDATOR.validate_pdb_path_policy(pdb, (), errors)
            self.assertTrue(any(
                "category=kdbg-checkout encoding=ascii" in error
                for error in errors
            ), errors)

    def test_pdb_path_policy_accepts_drive_root_as_forbidden_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-pdb-drive-root-") as directory:
            pdb = Path(directory) / "KDBG.pdb"
            pdb.write_bytes(pdb_with_extra_stream(
                bytes(range(16)), 7, b"R:\\src\\private.cpp\0"))
            errors: list[str] = []
            VALIDATOR.validate_pdb_path_policy(pdb, ("R:\\",), errors)
            self.assertTrue(any(
                "category=configured-root encoding=ascii" in error
                for error in errors
            ), errors)

    def test_pdb_path_policy_allows_virtual_and_public_toolchain_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-pdb-public-") as directory:
            pdb = Path(directory) / "KDBG.pdb"
            payload = (
                b"KDBG_ROOT/src/core/memory.cpp\0"
                b"C:\\Program Files (x86)\\Microsoft Visual Studio\\VC\\include\\vector\0"
                b"C:\\Windows\\System32\\public.pdb\0"
            )
            pdb.write_bytes(pdb_with_extra_stream(bytes(range(16)), 7, payload))
            errors: list[str] = []
            VALIDATOR.validate_pdb_path_policy(pdb, (), errors)
            self.assertEqual([], errors)

    def test_pdb_path_policy_validates_extra_recursive_pdb(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-symbol-extra-") as directory:
            symbols = Path(directory) / VALIDATOR.SYMBOLS_NAME
            extra = symbols / "nested/extra.pdb"
            extra.parent.mkdir(parents=True)
            extra.write_bytes(pdb_with_extra_stream(
                bytes(range(16)), 7,
                b"D:\\KDBG\\out\\private\\extra.obj\0"))
            errors: list[str] = []
            VALIDATOR.validate_symbols(symbols, errors)
            self.assertTrue(any(
                "file=extra.pdb category=kdbg-checkout" in error
                for error in errors
            ), errors)

    def test_pdb_path_policy_rejects_malformed_stream_map(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-pdb-malformed-") as directory:
            pdb = Path(directory) / "KDBG.pdb"
            payload = b"A" * 513
            pdb.write_bytes(pdb_with_extra_stream(
                bytes(range(16)), 7, payload, stream_blocks=(4, 4)))
            errors: list[str] = []
            VALIDATOR.validate_pdb_path_policy(pdb, (), errors)
            self.assertTrue(any(
                "invalid PDB structure KDBG.pdb: duplicate block" in error
                for error in errors
            ), errors)


def load_tests(loader, tests, pattern):
    """Keep the fail-closed commercial gate regression in the CTest entrypoint."""
    path = Path(__file__).with_name("test_validate_commercial_operations.py")
    spec = importlib.util.spec_from_file_location(
        "kdbg_commercial_operations_tests", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tests.addTests(loader.loadTestsFromModule(module))
    return tests


if __name__ == "__main__":
    unittest.main()
