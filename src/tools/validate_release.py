#!/usr/bin/env python3
"""Validate KDBG source, Windows packages, and live-VM evidence independently."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

VERSION = "1.0.0"
PACKAGE_NAME = f"KDBG-{VERSION}-win-x64"
SYMBOLS_NAME = f"{PACKAGE_NAME}-symbols"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
PRIVATE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\Users\\[^\\\s]+|/home/[^/\s]+|/Users/[^/\s]+)", re.I
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)

MAIN_REQUIRED = (
    "KDBG.exe",
    "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
    "drivers/KDbgDriver.sys",
    "drivers/KDbgProbe.sys",
    "drivers/KDbgDriver.inf",
    "drivers/KDbgProbe.inf",
    "config/app.example.json",
    "config/safety_policy.example.json",
    "tools/install.ps1",
    "tools/uninstall.ps1",
    "tools/diagnose.ps1",
    "docs/QUICKSTART.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/TROUBLESHOOTING.md",
    "licenses/LICENSE-PROJECT.txt",
    "licenses/MIT-kn-live-dbg.txt",
    "licenses/MIT-PTView.txt",
    "licenses/MIT-Dear-ImGui.txt",
    "licenses/MIT-imgui-memory-editor.txt",
    "licenses/MIT-Zydis.txt",
    "licenses/MIT-Zycore.txt",
    "licenses/THIRD-PARTY-NOTICES.txt",
    "BUILD-METADATA.json",
    "SBOM.spdx.json",
    "SHA256SUMS.txt",
)

SOURCE_REQUIRED = (
    "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY.lock.json",
    "docs/SECURITY.md", "docs/KNOWN_LIMITATIONS.md", "docs/USER_GUIDE.md",
    "docs/DEVELOPER_GUIDE.md", "docs/RELEASE_CHECKLIST.md",
    "docs/DEMO_SCRIPT.md", "docs/TEST_MATRIX.md", "docs/QUICKSTART.md",
    "docs/OPERATOR_GUIDE.md", "docs/TROUBLESHOOTING.md",
    "docs/LICENSE_AND_ATTRIBUTION.md", "licenses/LICENSE-PROJECT.txt",
    "licenses/MIT-kn-live-dbg.txt", "licenses/MIT-PTView.txt",
    "licenses/MIT-Dear-ImGui.txt", "licenses/MIT-imgui-memory-editor.txt",
    "licenses/MIT-Zydis.txt", "licenses/MIT-Zycore.txt",
    "licenses/THIRD-PARTY-NOTICES.txt",
)

TRUE_EVIDENCE_FIELDS = (
    "dedicated_vm_confirmed", "snapshot_confirmed", "probe_target_confirmed",
    "preflight_match", "write_gate_relocked", "full_readback_match",
    "independent_reload_match", "rollback_match", "private_paths_redacted",
    "unrelated_process_data_redacted", "video_reviewed",
)
DEMO_SCENES = {
    "driver_probe_ready", "probe_pfn_discovery", "physical_read_4096",
    "hex_edit_and_diff", "undo_redo", "typed_pfn_unlock",
    "write_and_readback", "independent_reload", "rollback_baseline",
    "pfn_owner_pid_va_pte", "page_table_walk", "process_first_next_scan",
    "address_list_verified_freeze", "pointer_scan", "zydis_disassembly",
    "snapshot_diff", "about_version",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], cwd: Path, label: str, errors: list[str]) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode:
        errors.append(
            f"{label} failed (exit {result.returncode}):\n{result.stdout}{result.stderr}"
        )


def load_json(path: Path, label: str, errors: list[str]) -> dict | None:
    if not path.is_file():
        errors.append(f"{label} not found: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid {label}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{label} root must be an object")
        return None
    return value


def validate_lock(root: Path, errors: list[str]) -> dict[str, dict]:
    lock = load_json(root / "THIRD_PARTY.lock.json", "THIRD_PARTY.lock.json", errors)
    if lock is None:
        return {}
    dependencies = lock.get("dependencies")
    if not isinstance(dependencies, list):
        errors.append("THIRD_PARTY.lock.json dependencies must be an array")
        return {}
    by_name: dict[str, dict] = {}
    for item in dependencies:
        if not isinstance(item, dict):
            errors.append("dependency entry must be an object")
            continue
        for field in ("name", "url", "revision", "license", "integration"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"dependency {item.get('name', '<unnamed>')} lacks {field}")
        name, revision = item.get("name"), item.get("revision")
        if isinstance(name, str):
            if name in by_name:
                errors.append(f"duplicate dependency lock entry: {name}")
            by_name[name] = item
        if isinstance(revision, str) and not re.fullmatch(r"[0-9a-f]{40}", revision):
            errors.append(f"dependency revision is not an immutable commit: {name}={revision}")
    required = {
        "ocornut/imgui", "ocornut/imgui_club/imgui_memory_editor",
        "zyantific/zydis", "zyantific/zycore-c", "ufrisk/MemProcFS",
    }
    for name in sorted(required - by_name.keys()):
        errors.append(f"required dependency lock entry is missing: {name}")
    cmake_path = root / "src/cmake/Dependencies.cmake"
    if not cmake_path.is_file():
        errors.append("missing src/cmake/Dependencies.cmake")
    else:
        cmake = cmake_path.read_text(encoding="utf-8")
        for name in (
            "ocornut/imgui", "ocornut/imgui_club/imgui_memory_editor",
            "zyantific/zydis",
        ):
            item = by_name.get(name)
            if item and item["revision"] not in cmake:
                errors.append(
                    f"CMake pin does not match THIRD_PARTY.lock.json: "
                    f"{name}={item['revision']}"
                )
    return by_name


def validate_source(root: Path, errors: list[str]) -> None:
    run([sys.executable, str(root / "src/tools/verify_layout.py")], root,
        "layout validation", errors)
    for relative in SOURCE_REQUIRED:
        if not (root / relative).is_file():
            errors.append(f"required source/release file missing: {relative}")
    cmake_project = root / "src/CMakeLists.txt"
    if cmake_project.is_file() and not re.search(
        r"project\s*\(\s*KDBG\s+VERSION\s+1\.0\.0\b",
        cmake_project.read_text(encoding="utf-8", errors="ignore"),
        re.IGNORECASE,
    ):
        errors.append("src/CMakeLists.txt does not declare KDBG VERSION 1.0.0")
    markers = {
        "src/shared/KDbgIoctl.h": (
            "IOCTL_KDBG_READ_PHYSICAL", "IOCTL_KDBG_WRITE_PHYSICAL",
            "KDBG_WRITE_ACK_MAGIC",
        ),
        "src/driver/KDbgDriver/Driver.cpp": (
            "IoCreateDeviceSecure", "MmGetPhysicalMemoryRanges",
            "IOCTL_KDBG_WRITE_PROCESS_MEMORY",
        ),
        "src/driver/KDbgProbe/Driver.cpp": (
            "MmAllocateContiguousMemorySpecifyCache", "IOCTL_KDBG_PROBE_GET_INFO",
        ),
        "src/core/memory/PhysicalPageSession.cpp": (
            "Preflight", "ApplyAndVerify", "RollbackBaseline",
        ),
        "src/plugins/memprocfs_bridge/main.cpp": (
            "LoadLibraryW", "VMMDLL_Map_GetPfnEx", "VMMDLL_MemFree",
        ),
    }
    for relative, tokens in markers.items():
        path = root / relative
        if not path.is_file():
            errors.append(f"missing implementation file: {relative}")
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for token in tokens:
            if token not in text:
                errors.append(f"{relative}: missing implementation marker {token}")
    candidates = (
        root / "out/build/core-debug/tests/kdbg_core_tests",
        root / "out/build/core-debug/tests/kdbg_core_tests.exe",
    )
    binary = next((path for path in candidates if path.is_file()), None)
    if binary is None or binary.stat().st_size == 0:
        errors.append("portable core test binary is absent or empty; build core-debug first")
    else:
        run([str(binary)], root, "portable core test binary", errors)


def parse_pe(path: Path) -> tuple[int, set[str], tuple[int, int, int, int] | None]:
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("missing DOS MZ header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if optional + optional_size > len(data):
        raise ValueError("truncated optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96 if magic == 0x10B else -1)
    if directories < optional:
        raise ValueError(f"unsupported PE magic 0x{magic:04x}")
    section_table = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise ValueError("truncated section table")
        virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", data, offset + 8)
        sections.append((rva, max(virtual_size, raw_size), raw, raw_size))

    def file_offset(rva: int) -> int:
        for base, span, raw, raw_size in sections:
            if base <= rva < base + span:
                result = raw + rva - base
                if result >= len(data) or result >= raw + raw_size:
                    break
                return result
        raise ValueError(f"unmapped RVA 0x{rva:x}")

    def directory(index: int) -> tuple[int, int]:
        offset = directories + index * 8
        if offset + 8 > optional + optional_size:
            return (0, 0)
        return struct.unpack_from("<II", data, offset)

    imports: set[str] = set()
    import_rva, _ = directory(1)
    if import_rva:
        cursor = file_offset(import_rva)
        while cursor + 20 <= len(data):
            fields = struct.unpack_from("<IIIII", data, cursor)
            if fields == (0, 0, 0, 0, 0):
                break
            name = file_offset(fields[3])
            end = data.find(b"\0", name)
            if end < 0:
                raise ValueError("unterminated import name")
            imports.add(data[name:end].decode("ascii").casefold())
            cursor += 20

    version: tuple[int, int, int, int] | None = None
    resource_rva, _ = directory(2)
    if resource_rva:
        base = file_offset(resource_rva)

        def resource_entries(relative: int) -> list[tuple[int, int]]:
            offset = base + relative
            if offset + 16 > len(data):
                raise ValueError("truncated resource directory")
            named, ids = struct.unpack_from("<HH", data, offset + 12)
            return [
                struct.unpack_from("<II", data, offset + 16 + index * 8)
                for index in range(named + ids)
            ]

        type_entry = next((e for e in resource_entries(0)
                           if not e[0] & 0x80000000 and e[0] == 16), None)
        if type_entry and type_entry[1] & 0x80000000:
            names = resource_entries(type_entry[1] & 0x7fffffff)
            if names and names[0][1] & 0x80000000:
                languages = resource_entries(names[0][1] & 0x7fffffff)
                if languages and not languages[0][1] & 0x80000000:
                    entry = base + languages[0][1]
                    blob_rva, size = struct.unpack_from("<II", data, entry)
                    blob_start = file_offset(blob_rva)
                    blob = data[blob_start:blob_start + size]
                    cursor = 6
                    while cursor + 2 <= len(blob):
                        char = struct.unpack_from("<H", blob, cursor)[0]
                        cursor += 2
                        if char == 0:
                            break
                    cursor = (cursor + 3) & ~3
                    if cursor + 52 <= len(blob):
                        fixed = struct.unpack_from("<13I", blob, cursor)
                        if fixed[0] == 0xFEEF04BD:
                            version = (
                                fixed[2] >> 16, fixed[2] & 0xffff,
                                fixed[3] >> 16, fixed[3] & 0xffff,
                            )
    return machine, imports, version


def validate_pe(path: Path, version_required: bool, errors: list[str]) -> None:
    if not path.is_file():
        return
    if path.stat().st_size == 0:
        errors.append(f"release binary is empty: {path}")
        return
    try:
        machine, imports, version = parse_pe(path)
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        errors.append(f"invalid PE binary {path}: {exc}")
        return
    if machine != 0x8664:
        errors.append(f"release binary is not x64: {path} machine=0x{machine:04x}")
    debug_dll = re.compile(
        r"^(?:msvcp\d+d|msvcr\d+d|vcruntime\d+(?:_\d+)?d|ucrtbased)\.dll$", re.I
    )
    for imported in sorted(imports):
        if debug_dll.match(imported):
            errors.append(f"release binary imports Debug CRT {imported}: {path}")
    if version_required and version is None:
        errors.append(f"release executable has no VERSIONINFO: {path}")
    elif version_required and version[:3] != (1, 0, 0):
        errors.append(f"release executable version mismatch: {path} has {version}")


def safe_relative(value: str) -> str | None:
    if not value or "\\" in value or "\x00" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return None
    return path.as_posix()


def file_set(package: Path) -> set[str]:
    return {path.relative_to(package).as_posix()
            for path in package.rglob("*") if path.is_file()}


def validate_sums(package: Path, errors: list[str]) -> None:
    manifest = package / "SHA256SUMS.txt"
    if not manifest.is_file():
        return
    entries: dict[str, str] = {}
    try:
        lines = manifest.read_text(encoding="ascii", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        errors.append(f"invalid SHA256SUMS.txt: {exc}")
        return
    for number, line in enumerate(lines, 1):
        try:
            expected, raw_path = line.split("  ", 1)
        except ValueError:
            errors.append(f"invalid SHA256SUMS.txt line {number}")
            continue
        relative = safe_relative(raw_path)
        if relative is None:
            errors.append(f"unsafe SHA256SUMS.txt path on line {number}: {raw_path}")
            continue
        if relative == "SHA256SUMS.txt":
            errors.append("SHA256SUMS.txt must not hash itself")
        elif relative in entries:
            errors.append(f"duplicate SHA256SUMS.txt path: {relative}")
        elif not SHA_RE.fullmatch(expected):
            errors.append(f"invalid lowercase SHA-256 on line {number}")
        else:
            entries[relative] = expected
    actual = file_set(package) - {"SHA256SUMS.txt"}
    for relative in sorted(actual - entries.keys()):
        errors.append(f"package file is not covered by SHA256SUMS.txt: {relative}")
    for relative in sorted(entries.keys() - actual):
        errors.append(f"SHA256SUMS.txt references missing file: {relative}")
    for relative in sorted(actual & entries.keys()):
        if sha256(package / PurePosixPath(relative)) != entries[relative]:
            errors.append(f"SHA256SUMS.txt hash mismatch: {relative}")


def validate_metadata(package: Path, errors: list[str]) -> None:
    metadata = load_json(package / "BUILD-METADATA.json", "BUILD-METADATA.json", errors)
    if metadata is None:
        return
    expected = {
        "schema": "kdbg.build-metadata.v1", "product": "KDBG", "version": VERSION,
        "configuration": "Release", "architecture": "x64",
        "package_name": PACKAGE_NAME,
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            errors.append(f"BUILD-METADATA.json {field} mismatch")
    if not isinstance(metadata.get("source_revision"), str) or not metadata["source_revision"].strip():
        errors.append("BUILD-METADATA.json source_revision is missing")
    if metadata.get("source_snapshot_scope") != "kdbg.source-snapshot.v1":
        errors.append("BUILD-METADATA.json source_snapshot_scope mismatch")
    if not isinstance(metadata.get("source_snapshot_sha256"), str) or not SHA_RE.fullmatch(
        metadata["source_snapshot_sha256"]
    ):
        errors.append("BUILD-METADATA.json source_snapshot_sha256 is invalid")
    if not isinstance(metadata.get("source_file_count"), int) or metadata["source_file_count"] <= 0:
        errors.append("BUILD-METADATA.json source_file_count is invalid")
    commands = metadata.get("reproducible_commands")
    if not isinstance(commands, list) or not commands or not all(
        isinstance(command, str) and command.strip() for command in commands
    ):
        errors.append("BUILD-METADATA.json requires reproducible_commands")
    actual_catalogs = sorted(path.relative_to(package).as_posix()
                             for path in (package / "drivers").glob("*.cat"))
    if metadata.get("catalogs") != actual_catalogs:
        errors.append("BUILD-METADATA.json catalogs do not match packaged CAT files")


def validate_sbom(package: Path, errors: list[str]) -> None:
    sbom = load_json(package / "SBOM.spdx.json", "SBOM.spdx.json", errors)
    if sbom is None:
        return
    if sbom.get("spdxVersion") != "SPDX-2.3":
        errors.append("SBOM.spdx.json must use SPDX-2.3")
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        errors.append("SBOM.spdx.json packages must be an array")
        return
    names = {item.get("name") for item in packages if isinstance(item, dict)}
    required = {
        "KDBG", "ocornut/imgui", "ocornut/imgui_club/imgui_memory_editor",
        "zyantific/zydis", "zyantific/zycore-c",
    }
    for name in sorted(required - names):
        errors.append(f"SBOM.spdx.json missing package: {name}")


def validate_package(package: Path, errors: list[str]) -> None:
    if not package.is_dir():
        errors.append(f"Windows package directory not found: {package}")
        return
    if package.name != PACKAGE_NAME:
        errors.append(f"Windows package directory must be named {PACKAGE_NAME}")
    for relative in MAIN_REQUIRED:
        path = package / PurePosixPath(relative)
        if not path.is_file():
            errors.append(f"Windows package missing: {relative}")
        elif path.stat().st_size == 0:
            errors.append(f"Windows package contains empty file: {relative}")
    for path in package.rglob("*.pdb"):
        errors.append(f"PDB must be in the separate symbols package: {path}")
    validate_pe(package / "KDBG.exe", True, errors)
    validate_pe(package / "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe", True, errors)
    validate_pe(package / "drivers/KDbgDriver.sys", False, errors)
    validate_pe(package / "drivers/KDbgProbe.sys", False, errors)
    for name in ("KDbgDriver", "KDbgProbe"):
        path = package / f"drivers/{name}.inf"
        if path.is_file():
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            match = re.search(r"^DriverVer\s*=\s*[^,]+,([0-9.]+)\s*$", text, re.M)
            if match is None or match.group(1) != "1.0.0.0":
                errors.append(f"INF version mismatch: {path}")
    validate_metadata(package, errors)
    validate_sbom(package, errors)
    for path in package.rglob("*"):
        if path.is_file() and path.suffix.casefold() in {".md", ".txt", ".json", ".ps1", ".inf"}:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            if PRIVATE_PATH_RE.search(text):
                errors.append(f"package contains a private user path: {path}")
            if EMAIL_RE.search(text):
                errors.append(f"package contains an email address: {path}")
    validate_sums(package, errors)


def validate_symbols(package: Path, errors: list[str]) -> None:
    if not package.is_dir():
        errors.append(f"symbols package directory not found: {package}")
        return
    if package.name != SYMBOLS_NAME:
        errors.append(f"symbols package directory must be named {SYMBOLS_NAME}")
    files = file_set(package)
    pdbs = [name for name in files if name.casefold().endswith(".pdb")]
    if not pdbs:
        errors.append("symbols package contains no PDB files")
    for relative in files:
        if not relative.casefold().endswith(".pdb") and relative not in {
            "BUILD-METADATA.json", "SHA256SUMS.txt"
        }:
            errors.append(f"unexpected file in symbols package: {relative}")
        if (package / PurePosixPath(relative)).stat().st_size == 0:
            errors.append(f"empty file in symbols package: {relative}")
    metadata = load_json(package / "BUILD-METADATA.json", "symbols metadata", errors)
    if metadata:
        expected = {"version": VERSION, "configuration": "Release",
                    "architecture": "x64", "package_name": SYMBOLS_NAME}
        for field, value in expected.items():
            if metadata.get(field) != value:
                errors.append(f"symbols metadata {field} mismatch")
    validate_sums(package, errors)


def require_sha(value: object, field: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        errors.append(f"live evidence field must be lowercase SHA-256: {field}")


def integer(value: object, field: str, errors: list[str]) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    errors.append(f"live evidence field is not an integer: {field}")
    return None


def validate_live(path: Path, package: Path | None, errors: list[str]) -> None:
    evidence = load_json(path, "live evidence JSON", errors)
    if evidence is None:
        return
    if package is None:
        errors.append("--live-evidence requires --windows-package")
        return
    if evidence.get("schema") != "kdbg.live-evidence.v2":
        errors.append("live evidence schema must be kdbg.live-evidence.v2")
    if evidence.get("package_version") != VERSION or evidence.get("abi_version") != 6:
        errors.append("live evidence product or ABI version mismatch")
    try:
        timestamp = datetime.fromisoformat(str(evidence.get("timestamp_utc", "")).replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
            raise ValueError("not UTC")
    except ValueError as exc:
        errors.append(f"invalid live evidence timestamp_utc: {exc}")
    if not isinstance(evidence.get("os_build"), str) or not evidence["os_build"].strip():
        errors.append("live evidence os_build is missing")
    for field in TRUE_EVIDENCE_FIELDS:
        if evidence.get(field) is not True:
            errors.append(f"live evidence field is not true: {field}")
    pfn = integer(evidence.get("pfn"), "pfn", errors)
    physical = integer(evidence.get("physical_address"), "physical_address", errors)
    if pfn is not None and (pfn <= 0 or pfn > ((1 << 64) - 1) >> 12):
        errors.append("live evidence PFN is zero or overflows PFN << 12")
    if pfn is not None and physical is not None and physical != pfn << 12:
        errors.append("live physical_address does not equal PFN << 12")
    if evidence.get("page_size") != 4096:
        errors.append("live evidence page_size must be 4096")
    for field in ("baseline_bytes", "preflight_bytes", "readback_bytes",
                  "reload_bytes", "rollback_bytes"):
        if evidence.get(field) != 4096:
            errors.append(f"live evidence {field} must be 4096")
    for field in ("baseline_sha256", "expected_after_sha256", "readback_sha256",
                  "independent_reload_sha256", "rollback_sha256",
                  "command_log_sha256", "video_sha256"):
        require_sha(evidence.get(field), field, errors)
    expected = evidence.get("expected_after_sha256")
    if evidence.get("readback_sha256") != expected:
        errors.append("readback hash does not match expected-after hash")
    if evidence.get("independent_reload_sha256") != expected:
        errors.append("reload hash does not match expected-after hash")
    if evidence.get("rollback_sha256") != evidence.get("baseline_sha256"):
        errors.append("rollback hash does not match baseline hash")
    artifacts = evidence.get("artifact_sha256")
    required_artifacts = (
        "KDBG.exe", "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
        "drivers/KDbgDriver.sys", "drivers/KDbgProbe.sys",
    )
    if not isinstance(artifacts, dict):
        errors.append("live evidence artifact_sha256 must be an object")
    else:
        for relative in required_artifacts:
            value = artifacts.get(relative)
            require_sha(value, f"artifact_sha256.{relative}", errors)
            artifact = package / PurePosixPath(relative)
            if artifact.is_file() and isinstance(value, str) and value != sha256(artifact):
                errors.append(f"live evidence artifact hash mismatch: {relative}")
    for field in ("probe_generation_before", "probe_generation_after_write",
                  "probe_generation_after_rollback"):
        integer(evidence.get(field), field, errors)
    for field in ("probe_crc32_before", "probe_crc32_after_write",
                  "probe_crc32_after_rollback"):
        if not isinstance(evidence.get(field), str) or not re.fullmatch(
            r"0x[0-9a-fA-F]{8}", evidence[field]
        ):
            errors.append(f"live evidence {field} must be an eight-digit CRC32")
    if evidence.get("probe_crc32_before") != evidence.get("probe_crc32_after_rollback"):
        errors.append("rollback Probe CRC does not match baseline")
    runs = evidence.get("dirty_runs")
    if not isinstance(runs, list) or not runs:
        errors.append("live evidence dirty_runs must be non-empty")
    else:
        for index, item in enumerate(runs):
            offset = item.get("offset") if isinstance(item, dict) else None
            length = item.get("length") if isinstance(item, dict) else None
            if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length <= 0 or offset + length > 4096:
                errors.append(f"dirty_runs[{index}] is outside the 4 KiB page")
    ownership = evidence.get("ownership_evidence")
    if not isinstance(ownership, dict):
        errors.append("ownership_evidence must be an object")
    else:
        for field in ("pid", "va", "pte"):
            integer(ownership.get(field), f"ownership_evidence.{field}", errors)
        if ownership.get("pfn") != evidence.get("pfn"):
            errors.append("ownership PFN does not match live PFN")
    page_table = evidence.get("page_table_evidence")
    if not isinstance(page_table, dict):
        errors.append("page_table_evidence must be an object")
    else:
        final_pfn = integer(page_table.get("final_pfn"), "page_table.final_pfn", errors)
        if pfn is not None and final_pfn != pfn:
            errors.append("page-table final PFN does not match live PFN")
        levels = page_table.get("levels")
        if not isinstance(levels, list) or not levels or not all(
            level in {"PML5", "PML4", "PDPT", "PD", "PT"} for level in levels
        ):
            errors.append("page-table levels are missing or invalid")
    scenes = evidence.get("demo_scenes")
    if not isinstance(scenes, list) or not all(isinstance(scene, str) for scene in scenes):
        errors.append("demo_scenes must be an array of strings")
    else:
        missing = DEMO_SCENES - set(scenes)
        if missing:
            errors.append("missing demo scenes: " + ", ".join(sorted(missing)))
    for file_field, hash_field in (("command_log_file", "command_log_sha256"),
                                   ("video_file", "video_sha256")):
        relative = evidence.get(file_field)
        if not isinstance(relative, str) or safe_relative(relative) is None or "/" in relative:
            errors.append(f"{file_field} must be a safe sibling filename")
            continue
        artifact = path.parent / relative
        if not artifact.is_file() or artifact.stat().st_size == 0:
            errors.append(f"evidence artifact missing or empty: {artifact}")
        elif sha256(artifact) != evidence.get(hash_field):
            errors.append(f"evidence artifact hash mismatch: {artifact}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-complete", action="store_true")
    parser.add_argument("--windows-package", type=Path)
    parser.add_argument("--symbols-package", type=Path)
    parser.add_argument("--live-evidence", type=Path)
    parser.add_argument("--artifact", action="append", default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    errors: list[str] = []
    if not any((args.source_complete, args.windows_package, args.symbols_package,
                args.live_evidence)):
        args.source_complete = True
    if args.source_complete:
        validate_source(root, errors)
    package = args.windows_package.resolve() if args.windows_package else None
    if package:
        validate_package(package, errors)
    if args.symbols_package:
        validate_symbols(args.symbols_package.resolve(), errors)
    if args.live_evidence:
        validate_live(args.live_evidence.resolve(), package, errors)
    validate_lock(root, errors)
    hashes: dict[str, str] = {}
    for value in args.artifact:
        artifact = Path(value)
        if not artifact.is_file() or artifact.stat().st_size == 0:
            errors.append(f"artifact not found or empty: {artifact}")
        else:
            hashes[str(artifact)] = sha256(artifact)
    if hashes:
        print("Artifact SHA-256:")
        for path, digest in hashes.items():
            print(f" - {path}: {digest}")
    if errors:
        print("Release validation FAILED")
        for error in errors:
            print(f" - {error}")
        return 1
    gates: list[str] = []
    if args.source_complete: gates.append("source-complete")
    if package: gates.append("windows-package")
    if args.symbols_package: gates.append("symbols-package")
    if args.live_evidence: gates.append("live-vm")
    print("Release validation PASS: " + ", ".join(gates))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
