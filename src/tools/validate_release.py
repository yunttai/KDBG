#!/usr/bin/env python3
"""Validate KDBG source, Windows packages, and live-VM evidence independently."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

VERSION = "1.1.0"
VERSION_TRIPLE = tuple(int(component) for component in VERSION.split("."))
MIN_WINDOWS_BUILD = 19041
PROBE_EDIT_OFFSET = 0x100
PROBE_EDIT_MASK = bytes((0x4B, 0x44, 0x42, 0x47, 0xA5, 0x5A, 0x3C, 0xC3))
PAGE_TABLE_LEVELS = (
    ("PML4", "PDPT", "PD", "PT"),
    ("PML5", "PML4", "PDPT", "PD", "PT"),
)
GIF_MIN_WIDTH = 320
GIF_MIN_HEIGHT = 180
GIF_MAX_WIDTH = 7680
GIF_MAX_HEIGHT = 4320
GIF_MIN_FRAMES = 20
GIF_MAX_FRAMES = 100_000
GIF_MIN_DURATION_MS = 20_000
GIF_MAX_DURATION_MS = 8 * 60 * 60 * 1_000
PACKAGE_NAME = f"KDBG-{VERSION}-win-x64"
SYMBOLS_NAME = f"{PACKAGE_NAME}-symbols"
EXPECTED_CATALOGS = (
    "drivers/KDbgDriver.cat",
    "drivers/KDbgProbe.cat",
)
REQUIRED_TOOL_VERSIONS = (
    "msvc_compiler", "msvc_toolset", "windows_sdk", "wdk",
    "powershell", "cmake", "python", "syft",
)
SYMBOLS_REQUIRED = (
    "KDBG.pdb",
    "KDBGSetup.pdb",
    "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.pdb",
    "tools/kdbg_live_verify.pdb",
    "tools/kdbg_process_fixture.pdb",
    "drivers/KDbgDriver.pdb",
    "drivers/KDbgProbe.pdb",
)
BINARY_SYMBOL_PAIRS = (
    ("KDBG.exe", "KDBG.pdb"),
    ("KDBGSetup.exe", "KDBGSetup.pdb"),
    ("plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
     "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.pdb"),
    ("tools/kdbg_live_verify.exe", "tools/kdbg_live_verify.pdb"),
    ("tools/kdbg_process_fixture.exe", "tools/kdbg_process_fixture.pdb"),
    ("drivers/KDbgDriver.sys", "drivers/KDbgDriver.pdb"),
    ("drivers/KDbgProbe.sys", "drivers/KDbgProbe.pdb"),
)
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
LEGACY_SOURCE_SNAPSHOT_SCOPE = "kdbg.source-snapshot.v1"
PRODUCT_SOURCE_SNAPSHOT_SCOPE = "kdbg.product-source.v1"
SOURCE_SNAPSHOT_MANIFEST = "SOURCE-SNAPSHOT-SHA256SUMS.txt"
PRODUCT_SOURCE_POLICY_KEYS = {
    "root_files", "documentation_files", "scan_roots", "excluded_paths",
    "ignored_directory_names", "ignored_extensions",
}
PRODUCT_SOURCE_REQUIRED_EXCLUSIONS = {
    "docs/exec-plans/**",
    "docs/VALIDATION_REPORT.md",
    "docs/TRACEABILITY_MATRIX.md",
}
GUI_COMPACT_UTC_RE = re.compile(
    r"^(?P<date>\d{8})-(?P<time>\d{6})-(?P<milliseconds>\d{3})Z$"
)
PRIVATE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\Users\\[^\\\s]+|/home/[^/\s]+|/Users/[^/\s]+)", re.I
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PDB_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")
PDB_UTF16LE_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
PDB_USER_PROFILE_RE = re.compile(
    r"(?:[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]|"
    r"/(?:home|Users)/)",
    re.I,
)
PDB_KDBG_CHECKOUT_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])"
    r"(?:[^\\/\x00\r\n]+[\\/])*KDBG[\\/](?:src|out|\.git)(?:[\\/]|$)",
    re.I,
)


def parse_gui_utc_timestamp(value: object) -> datetime:
    """Parse GUI evidence UTC while retaining compatibility with ISO exports."""
    text = str(value)
    compact = GUI_COMPACT_UTC_RE.fullmatch(text)
    if compact is not None:
        parsed = datetime.strptime(
            compact.group("date") + compact.group("time") +
            compact.group("milliseconds"),
            "%Y%m%d%H%M%S%f",
        ).replace(tzinfo=timezone.utc)
    else:
        if re.match(r"^\d{8}-", text):
            raise ValueError("malformed compact GUI UTC timestamp")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if (parsed.tzinfo is None or
            parsed.utcoffset() != timezone.utc.utcoffset(parsed)):
        raise ValueError("not UTC")
    return parsed

MAIN_REQUIRED = (
    "KDBG.exe",
    "KDBGSetup.exe",
    "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
    "drivers/KDbgDriver.sys",
    "drivers/KDbgProbe.sys",
    "drivers/KDbgDriver.inf",
    "drivers/KDbgProbe.inf",
    "drivers/KDbgDriver.cat",
    "drivers/KDbgProbe.cat",
    "config/app.example.json",
    "config/safety_policy.example.json",
    "tools/install.ps1",
    "tools/start.ps1",
    "tools/run.ps1",
    "tools/stop.ps1",
    "tools/uninstall.ps1",
    "tools/diagnose.ps1",
    "tools/setup.ps1",
    "tools/setup_contract.psm1",
    "tools/TargetProfile.psm1",
    "tools/kdbg_live_verify.exe",
    "tools/kdbg_process_fixture.exe",
    "tools/new_live_evidence.ps1",
    "tools/capture_demo.ps1",
    "tools/live-evidence.example.json",
    "tools/validate_release.py",
    "docs/QUICKSTART.md",
    "docs/OPERATOR_GUIDE.md",
    "docs/TROUBLESHOOTING.md",
    "docs/LIVE_VERIFY.md",
    "docs/SECURITY.md",
    "docs/SUPPORT.md",
    "docs/PRIVACY.md",
    "docs/LICENSE_AND_EULA.md",
    "docs/UPDATE_AND_ROLLBACK.md",
    "docs/VULNERABILITY_DISCLOSURE.md",
    "docs/RELEASE_NOTES.md",
    "docs/PROCESS_FIXTURE.md",
    "licenses/LICENSE-PROJECT.txt",
    "licenses/MIT-kn-live-dbg.txt",
    "licenses/MIT-PTView.txt",
    "licenses/MIT-Dear-ImGui.txt",
    "licenses/MIT-imgui-memory-editor.txt",
    "licenses/MIT-Zydis.txt",
    "licenses/MIT-Zycore.txt",
    "licenses/THIRD-PARTY-NOTICES.txt",
    "licenses/THIRD_PARTY.lock.json",
    "BUILD-METADATA.json",
    "SBOM.spdx.json",
    "SHA256SUMS.txt",
)

SOURCE_REQUIRED = (
    "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY.lock.json",
    "docs/SECURITY.md", "docs/KNOWN_LIMITATIONS.md", "docs/USER_GUIDE.md",
    "docs/SUPPORT.md", "docs/PRIVACY.md", "docs/LICENSE_AND_EULA.md",
    "docs/UPDATE_AND_ROLLBACK.md", "docs/VULNERABILITY_DISCLOSURE.md",
    "docs/DEVELOPER_GUIDE.md", "docs/RELEASE_CHECKLIST.md",
    "docs/DEMO_SCRIPT.md", "docs/TEST_MATRIX.md", "docs/QUICKSTART.md",
    "docs/OPERATOR_GUIDE.md", "docs/TROUBLESHOOTING.md",
    "docs/PROCESS_FIXTURE.md",
    "docs/LICENSE_AND_ATTRIBUTION.md", "licenses/LICENSE-PROJECT.txt",
    "licenses/MIT-kn-live-dbg.txt", "licenses/MIT-PTView.txt",
    "licenses/MIT-Dear-ImGui.txt", "licenses/MIT-imgui-memory-editor.txt",
    "licenses/MIT-Zydis.txt", "licenses/MIT-Zycore.txt",
    "licenses/THIRD-PARTY-NOTICES.txt",
    "src/tools/package/diagnose.ps1", "src/tools/package/install.ps1",
    "src/tools/package/TargetProfile.psm1",
    "src/tools/win11_baremetal_validation/README.md",
    "src/tools/win11_baremetal_validation/Invoke-Win11BareMetalValidation.ps1",
    "src/tools/win11_baremetal_validation/Win11BareMetalValidation.Contract.Tests.ps1",
    "src/tools/package/start.ps1", "src/tools/package/run.ps1",
    "src/tools/package/stop.ps1", "src/tools/package/uninstall.ps1",
    "src/tools/setup/main.cpp", "src/tools/setup/setup.ps1",
    "src/tools/setup/test_setup.ps1",
    "src/tools/setup/setup_contract.psm1",
    "src/tools/setup/resources/KDBGSetup.manifest",
    "src/tools/setup/resources/KDBGSetup.rc",
    "src/tests/package_lifecycle_tests.ps1",
    "src/tests/setup_contract_tests.ps1",
    "src/tests/process_fixture_tests.ps1",
    "src/tests/test_validate_release.py",
    "src/tools/compare_symbol_builds.py",
    "src/tools/build_public_release.ps1",
    "src/tools/build_drivers.ps1",
    "src/tools/build_drivers_nuget.ps1",
    "src/driver/WdkBootstrap/KDBG.WdkBootstrap.csproj",
    "src/driver/WdkBootstrap/packages.lock.json",
    "src/tools/new_live_evidence.ps1",
    "src/tools/capture_demo.ps1",
    "src/tools/validate_commercial_operations.py",
    "src/tests/test_validate_commercial_operations.py",
    ".github/SECURITY.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/support_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    "src/tools/live_verify/CMakeLists.txt",
    "src/tools/live_verify/LiveVerify.cpp",
    "src/tools/live_verify/LiveVerify.h",
    "src/tools/live_verify/main.cpp",
    "src/tools/live_verify/resources/kdbg_live_verify.rc",
    "src/tools/live_verify/tests/live_verify_tests.cpp",
    "src/tools/live_verify/README.md",
    "src/core/memory/ProbeEvidencePattern.h",
    "src/fixtures/process_fixture/main.cpp",
    "src/fixtures/process_fixture/README.md",
    "src/fixtures/process_fixture/resources/kdbg_process_fixture.rc",
    "src/CMakeLists.txt",
    "src/cmake/CompilerWarnings.cmake",
    "src/driver/KDbgDriver/KDbgDriver.vcxproj",
    "src/driver/KDbgProbe/KDbgProbe.vcxproj",
)

SOURCE_RELEASE_DOCUMENT_REQUIREMENTS = {
    "docs/SECURITY.md": (
        "Vulnerability intake", "production signing",
        "VULNERABILITY_DISCLOSURE.md",
    ),
    "docs/SUPPORT.md": (
        "Supported scope", "Support lifecycle", "diagnose.ps1 -VerifyPackage",
        "no paid SLA", "VULNERABILITY_DISCLOSURE.md",
    ),
    "docs/PRIVACY.md": (
        "No telemetry", "%LOCALAPPDATA%\\KDBG", "PurgeUserData", "crash dumps",
    ),
    "docs/LICENSE_AND_EULA.md": (
        "MIT License", "not add a separate proprietary", "THIRD-PARTY-NOTICES.txt",
        "redistribution",
    ),
    "docs/UPDATE_AND_ROLLBACK.md": (
        "Update channel", "manual, offline", "SHA256SUMS.txt", "stop.ps1",
        "Rollback procedure", "commercial-ready",
    ),
    "docs/VULNERABILITY_DISCLOSURE.md": (
        "Vulnerability intake", "private", "Coordinated handling",
        "no fixed response", "commercial support gate remains incomplete",
    ),
    "docs/PROCESS_FIXTURE.md": (
        "kdbg.process-fixture.v1", "4096", "VirtualLock", "named-pipe",
    ),
    "CHANGELOG.md": ("Unreleased", "1.1.0", "Current source gate"),
}

PACKAGE_RELEASE_DOCUMENT_REQUIREMENTS = {
    **{
        relative: tokens
        for relative, tokens in SOURCE_RELEASE_DOCUMENT_REQUIREMENTS.items()
        if relative != "CHANGELOG.md"
    },
    "docs/RELEASE_NOTES.md": ("Unreleased", "1.1.0", "Current source gate"),
}

TRUE_EVIDENCE_FIELDS = (
    "dedicated_vm_confirmed", "snapshot_confirmed", "probe_target_confirmed",
    "preflight_match", "write_gate_relocked", "full_readback_match",
    "independent_reload_match", "rollback_match", "private_paths_redacted",
    "unrelated_process_data_redacted", "video_reviewed",
)
BAREMETAL_EVIDENCE_SCHEMA = "kdbg.win11-baremetal-validation.v1"
BAREMETAL_REQUIRED_ARTIFACTS = (
    "baseline", "preflight", "expected_after", "readback",
    "independent_reload", "rollback", "package_archive", "signature_report",
    "cleanup_report", "live_run_report",
)
DEMO_SCENE_ORDER = (
    "driver_probe_ready", "probe_pfn_discovery", "physical_read_4096",
    "hex_edit_and_diff", "undo_redo", "typed_pfn_unlock",
    "write_and_readback", "independent_reload", "rollback_baseline",
    "pfn_owner_pid_va_pte", "page_table_walk", "process_first_next_scan",
    "address_list_verified_freeze", "pointer_scan", "zydis_disassembly",
    "snapshot_diff", "kernel_module_catalog", "kernel_symbol_resolution",
    "kernel_read_disassembly", "about_version",
)


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


def validate_powershell_syntax(
    paths: list[Path], errors: list[str], *, required: bool = False
) -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        if required:
            errors.append("PowerShell is required to parse packaged lifecycle scripts")
        return
    parser = (
        "$tokens=$null; $parseErrors=$null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "$env:KDBG_VALIDATE_PS1,[ref]$tokens,[ref]$parseErrors); "
        "if($parseErrors.Count -gt 0){"
        "$parseErrors | ForEach-Object {[Console]::Error.WriteLine($_.Message)}; exit 1}"
    )
    for path in paths:
        if not path.is_file():
            continue
        environment = os.environ.copy()
        environment["KDBG_VALIDATE_PS1"] = str(path)
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", parser],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            env=environment,
        )
        if result.returncode:
            detail = (result.stdout + result.stderr).strip()
            errors.append(f"PowerShell syntax validation failed: {path}: {detail}")


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


def validate_lock_document(
    path: Path, label: str, errors: list[str]
) -> dict[str, dict]:
    lock = load_json(path, label, errors)
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
            package_hash = item.get("sha512")
            integration = item.get("integration")
            try:
                decoded_hash = base64.b64decode(
                    package_hash, validate=True
                ) if isinstance(package_hash, str) else b""
            except (ValueError, TypeError):
                decoded_hash = b""
            locked_package = (
                re.fullmatch(r"\d+\.\d+\.\d+\.\d+", revision) is not None
                and len(decoded_hash) == 64
                and isinstance(integration, str)
                and "locked" in integration.casefold()
            )
            if not locked_package:
                errors.append(
                    f"dependency revision is not an immutable commit or "
                    f"hash-locked package: {name}={revision}"
                )
    required = {
        "ocornut/imgui", "ocornut/imgui_club/imgui_memory_editor",
        "zyantific/zydis", "zyantific/zycore-c", "ufrisk/MemProcFS",
    }
    for name in sorted(required - by_name.keys()):
        errors.append(f"required dependency lock entry is missing: {name}")
    return by_name


def validate_lock(root: Path, errors: list[str]) -> dict[str, dict]:
    by_name = validate_lock_document(
        root / "THIRD_PARTY.lock.json", "THIRD_PARTY.lock.json", errors)
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


def validate_packaged_lock(package: Path, errors: list[str]) -> None:
    validate_lock_document(
        package / "licenses/THIRD_PARTY.lock.json",
        "packaged THIRD_PARTY.lock.json",
        errors,
    )


def validate_release_documents(
    root: Path,
    requirements: dict[str, tuple[str, ...]],
    label: str,
    errors: list[str],
) -> None:
    """Require the operational/commercial document contract and its markers."""
    for relative, tokens in requirements.items():
        path = root / PurePosixPath(relative)
        if not path.is_file():
            errors.append(f"{label} missing: {relative}")
            continue
        if path.stat().st_size == 0:
            errors.append(f"{label} is empty: {relative}")
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore").casefold()
        normalized = re.sub(r"\s+", " ", text)
        for token in tokens:
            if re.sub(r"\s+", " ", token.casefold()) not in normalized:
                errors.append(f"{label} marker missing in {relative}: {token}")


def validate_source(root: Path, errors: list[str]) -> None:
    run([sys.executable, str(root / "src/tools/verify_layout.py")], root,
        "layout validation", errors)
    for relative in SOURCE_REQUIRED:
        if not (root / relative).is_file():
            errors.append(f"required source/release file missing: {relative}")
    validate_release_documents(
        root, SOURCE_RELEASE_DOCUMENT_REQUIREMENTS,
        "source release document", errors,
    )
    run(
        [
            sys.executable,
            str(root / "src/tools/validate_commercial_operations.py"),
            "--source-contract",
        ],
        root,
        "commercial source contract validation",
        errors,
    )
    validate_powershell_syntax(
        [
            root / "src/tools/build.ps1",
            root / "src/tools/build_public_release.ps1",
            root / "src/tools/build_drivers.ps1",
            root / "src/tools/build_drivers_nuget.ps1",
            root / "src/tools/package_windows.ps1",
            root / "src/tools/run.ps1",
            root / "src/tools/new_live_evidence.ps1",
            root / "src/tools/capture_demo.ps1",
            root / "src/tests/package_lifecycle_tests.ps1",
            root / "src/tools/setup/setup.ps1",
            root / "src/tools/setup/setup_contract.psm1",
            root / "src/tests/setup_contract_tests.ps1",
            root / "src/tools/win11_baremetal_validation/Invoke-Win11BareMetalValidation.ps1",
            root / "src/tools/win11_baremetal_validation/Win11BareMetalValidation.Contract.Tests.ps1",
            *(root / relative for relative in SOURCE_REQUIRED
              if relative.startswith("src/tools/package/") and relative.endswith(".ps1")),
        ],
        errors,
    )
    cmake_project = root / "src/CMakeLists.txt"
    if cmake_project.is_file() and not re.search(
        r"project\s*\(\s*KDBG\s+VERSION\s+1\.1\.0\b",
        cmake_project.read_text(encoding="utf-8", errors="ignore"),
        re.IGNORECASE,
    ):
        errors.append("src/CMakeLists.txt does not declare KDBG VERSION 1.1.0")
    markers = {
        "src/shared/KDbgIoctl.h": (
            "IOCTL_KDBG_READ_PHYSICAL", "IOCTL_KDBG_WRITE_PHYSICAL",
            "KDBG_WRITE_ACK_MAGIC", "IOCTL_KDBG_COMPARE_WRITE_PHYSICAL_PAGE",
            "KDBG_VERSION_FLAG_PHYSICAL_PAGE_COMPARE_WRITE",
        ),
        "src/driver/KDbgDriver/Driver.cpp": (
            "IoCreateDeviceSecure", "MmGetPhysicalMemoryRanges",
            "IOCTL_KDBG_WRITE_PROCESS_MEMORY",
            "IOCTL_KDBG_COMPARE_WRITE_PHYSICAL_PAGE",
        ),
        "src/driver/KDbgProbe/Driver.cpp": (
            "MmAllocateContiguousMemorySpecifyCache", "IOCTL_KDBG_PROBE_GET_INFO",
        ),
        "src/core/memory/PhysicalPageSession.cpp": (
            "Preflight", "ApplyAndVerify", "RollbackBaseline",
            "CompareWritePhysicalPage",
        ),
        "src/core/memory/KDbgBackend.cpp": (
            "KDBG_VERSION_FLAG_PHYSICAL_PAGE_COMPARE_WRITE",
            "IOCTL_KDBG_COMPARE_WRITE_PHYSICAL_PAGE",
            "KDbgBackend::CompareWritePhysicalPage",
        ),
        "src/core/memory/ProbeEvidencePattern.h": (
            "kProbeEvidenceEditOffset", "0x100U",
            "0x4BU", "0x44U", "0x42U", "0x47U",
            "0xA5U", "0x5AU", "0x3CU", "0xC3U",
        ),
        "src/tools/setup/main.cpp": (
            "KDBG Setup 1.1.0", "Install", "Repair", "Update",
            "Uninstall", "tools", "setup.ps1", "publisher signing is a separate release gate",
        ),
        "src/tools/setup/setup.ps1": (
            "RequireTrustedDriverSignatures", "ProgramFiles",
            "tools\\install.ps1", "tools\\uninstall.ps1",
            "DistributionSource", "SetupStaging", "InstalledProduct",
            "UninstallString", "Prepare-ExactPackagePurge",
            "Commit-ExactPackagePurge", "kdbg.setup-purge.v1",
            "PURGE_SCHEDULED", "Package purge is pending, not complete",
        ),
        "src/tools/setup/setup_contract.psm1": (
            "kdbg.setup-transaction.v1", "prior_moved", "new_committed",
            "rollback_completed", "last-known-good backup preserved",
        ),
        "src/tools/setup/resources/KDBGSetup.manifest": (
            "requireAdministrator", 'uiAccess="false"',
        ),
        "src/plugins/memprocfs_bridge/main.cpp": (
            "LoadLibraryExW", "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR",
            "LOAD_LIBRARY_SEARCH_SYSTEM32", "VMMDLL_Map_GetPfnEx",
            "VMMDLL_MemFree",
        ),
        "src/tools/live_verify/LiveVerify.cpp": (
            "baseline_vs_preflight", "expected_vs_independent_reload",
            "RollbackBaseline", "final_gate_locked",
        ),
        "src/tools/live_verify/main.cpp": (
            "SetConsoleCtrlHandler", "backend.Open", "probe.Open",
        ),
        "src/tools/new_live_evidence.ps1": (
            "scene_review_file", "scene_review_sha256", "kdbg.live-evidence.v4",
            "outside the immutable main and symbols packages", "KDBGSetup.pdb",
        ),
        "src/tools/capture_demo.ps1": (
            "kdbg.demo-scene-review.v1", "SceneReviewTemplate", "start_ms",
        ),
        "src/CMakeLists.txt": (
            "kdbg_enable_release_symbols(KDBG)",
            "kdbg_enable_release_symbols(kdbg_live_verify)",
            "kdbg_enable_release_symbols(kdbg_memprocfs_bridge)",
            "CMAKE_MSVC_RUNTIME_LIBRARY",
            "MultiThreaded$<$<CONFIG:Debug>:Debug>",
            "/experimental:deterministic", "/pathmap:", "KDBG_BUILD_ID",
        ),
        "src/cmake/CompilerWarnings.cmake": (
            "function(kdbg_enable_release_symbols target)",
            "/DEBUG:FULL", "/PDBALTPATH:%_PDB%", "PDB_OUTPUT_DIRECTORY",
            "/Z7", "/Brepro",
        ),
        "src/driver/KDbgDriver/KDbgDriver.vcxproj": (
            "<GenerateDebugInformation>true</GenerateDebugInformation>",
            "/PDBALTPATH:%_PDB%", "/experimental:deterministic", "/Z7",
            "/pathmap:", "/Brepro",
        ),
        "src/driver/KDbgProbe/KDbgProbe.vcxproj": (
            "<GenerateDebugInformation>true</GenerateDebugInformation>",
            "/PDBALTPATH:%_PDB%", "/experimental:deterministic", "/Z7",
            "/pathmap:", "/Brepro",
        ),
        "src/tools/build_drivers.ps1": (
            ".pdb was not found after a successful MSBuild invocation",
            ".cat was not found after a successful MSBuild invocation",
            "build_drivers_nuget.ps1", "WdkMode",
        ),
        "src/tools/build_public_release.ps1": (
            "subst", "KDBG_REPRODUCIBLE_RELEASE_SYMBOLS", "EpochName",
            "-ForbiddenSymbolPath",
        ),
        "src/tools/compare_symbol_builds.py": (
            "kdbg.symbol-build-comparison.v1", "binary_byte_equal",
            "pdb_byte_equality_required", "validate_pdb_path_policy",
            "--require-drivers", "--forbid-symbol-path",
        ),
        "src/tools/build_drivers_nuget.ps1": (
            "microsoft.windows.wdk.x64", "10.0.26100.2454",
            "/PDBALTPATH:%_PDB%", "Inf2Cat", "Assert-PackageHash",
            "BufferOverflowFastFailK.lib", '"/Z7"',
            "/experimental:deterministic", "/pathmap:", "/BREPRO",
            "[IO.FileShare]::None",
            '"kdbg-nuget-$Configuration-$WdkPackageVersion"',
        ),
        "src/driver/WdkBootstrap/KDBG.WdkBootstrap.csproj": (
            "Microsoft.Windows.WDK.x64", "[10.0.26100.2454]",
            "RestorePackagesWithLockFile",
        ),
        "src/driver/WdkBootstrap/packages.lock.json": (
            "Microsoft.Windows.WDK.x64", "contentHash",
        ),
        "src/tools/package_windows.ps1": (
            "Pinned Microsoft.Windows.WDK.x64 package hash mismatch",
            "NuGet $PinnedWdkPackageVersion",
            "SECURITY.md", "SUPPORT.md", "PRIVACY.md",
            "LICENSE_AND_EULA.md", "UPDATE_AND_ROLLBACK.md",
            "VULNERABILITY_DISCLOSURE.md", "RELEASE_NOTES.md",
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

    package_start = root / "src/tools/package/start.ps1"
    if package_start.is_file():
        start_text = package_start.read_text(encoding="utf-8", errors="ignore")
        start_call = start_text.find("Start-Service -Name $Name")
        journal_call = start_text.find("$Started.Add($Name)", start_call)
        running_wait = start_text.find("$Service.WaitForStatus(", start_call)
        if not (0 <= start_call < journal_call < running_wait):
            errors.append(
                "package start must journal a successful Start-Service before "
                "waiting for Running so timeout rollback includes it"
            )
    candidates = (
        root / "out/build/core-debug/tests/kdbg_core_tests",
        root / "out/build/core-debug/tests/kdbg_core_tests.exe",
    )
    binary = next((path for path in candidates if path.is_file()), None)
    if binary is None or binary.stat().st_size == 0:
        errors.append("portable core test binary is absent or empty; build core-debug first")
    else:
        run([str(binary)], root, "portable core test binary", errors)


def parse_pe(
    path: Path,
) -> tuple[
    int,
    set[str],
    tuple[int, int, int, int] | None,
    tuple[bytes, int, str] | None,
]:
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
    codeview_records: list[tuple[bytes, int, str]] = []
    debug_rva, debug_size = directory(6)
    if debug_rva:
        if debug_size % 28 != 0:
            raise ValueError("misaligned PE debug directory")
        cursor = file_offset(debug_rva)
        for index in range(debug_size // 28):
            entry = cursor + index * 28
            if entry + 28 > len(data):
                raise ValueError("truncated PE debug directory")
            fields = struct.unpack_from("<IIHHIIII", data, entry)
            if fields[4] != 2:
                continue
            size, raw = fields[5], fields[7]
            if size < 24 or raw > len(data) or size > len(data) - raw:
                raise ValueError("invalid CodeView debug record bounds")
            record = data[raw:raw + size]
            if record[:4] != b"RSDS":
                continue
            end = record.find(b"\0", 24)
            if end < 0:
                raise ValueError("unterminated CodeView PDB path")
            codeview_records.append((
                record[4:20],
                struct.unpack_from("<I", record, 20)[0],
                record[24:end].decode("utf-8"),
            ))
    if len(codeview_records) > 1:
        raise ValueError("multiple RSDS CodeView records")
    return machine, imports, version, (
        codeview_records[0] if codeview_records else None)


def validate_pe(path: Path, version_required: bool, errors: list[str]) -> None:
    if not path.is_file():
        return
    if path.stat().st_size == 0:
        errors.append(f"release binary is empty: {path}")
        return
    try:
        machine, imports, version, _ = parse_pe(path)
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        errors.append(f"invalid PE binary {path}: {exc}")
        return
    if machine != 0x8664:
        errors.append(f"release binary is not x64: {path} machine=0x{machine:04x}")
    dynamic_msvc_crt = re.compile(
        r"^(?:msvcp\d+(?:_\d+)?d?|msvcr\d+d?|"
        r"vcruntime\d+(?:_\d+)?d?|ucrtbased)\.dll$",
        re.I,
    )
    for imported in sorted(imports):
        if dynamic_msvc_crt.match(imported):
            errors.append(
                f"release binary imports dynamic MSVC CRT {imported}: {path}"
            )
    if version_required and version is None:
        errors.append(f"release executable has no VERSIONINFO: {path}")
    elif version_required and version[:3] != VERSION_TRIPLE:
        errors.append(f"release executable version mismatch: {path} has {version}")


def parse_msf_streams(path: Path) -> tuple[bytes, list[bytes | None]]:
    """Read an MSF 7.0 file and reconstruct every logical stream."""
    data = path.read_bytes()
    signature = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    if len(data) < 56 or data[:32] != signature:
        raise ValueError("missing MSF 7.0 signature")
    (block_size, _free_map, block_count, directory_size,
     _reserved, block_map) = struct.unpack_from("<6I", data, 32)
    if (block_size < 512 or block_size > 65536 or
            block_size & (block_size - 1)):
        raise ValueError("invalid MSF block size")
    if block_count == 0 or block_count > len(data) // block_size:
        raise ValueError("invalid MSF block count")
    if directory_size == 0 or directory_size > block_count * block_size:
        raise ValueError("invalid MSF directory size")
    directory_blocks = (directory_size + block_size - 1) // block_size
    if block_map >= block_count:
        raise ValueError("invalid MSF directory block map")
    map_offset = block_map * block_size
    map_bytes = directory_blocks * 4
    if map_bytes > block_size:
        raise ValueError("MSF directory block map exceeds one block")
    if map_offset > len(data) or map_bytes > len(data) - map_offset:
        raise ValueError("truncated MSF directory block map")
    block_numbers = struct.unpack_from(
        f"<{directory_blocks}I", data, map_offset)
    directory = bytearray()
    for block in block_numbers:
        offset = block * block_size
        if block >= block_count or offset > len(data) - block_size:
            raise ValueError("invalid MSF directory block")
        directory.extend(data[offset:offset + block_size])
    del directory[directory_size:]
    if len(directory) < 4:
        raise ValueError("truncated MSF stream directory")
    stream_count = struct.unpack_from("<I", directory, 0)[0]
    if stream_count < 2 or stream_count > 1_000_000:
        raise ValueError("invalid MSF stream count")
    sizes_end = 4 + stream_count * 4
    if sizes_end > len(directory):
        raise ValueError("truncated MSF stream sizes")
    stream_sizes = struct.unpack_from(f"<{stream_count}I", directory, 4)
    cursor = sizes_end
    stream_blocks: list[tuple[int, ...] | None] = []
    for size in stream_sizes:
        if size == 0xFFFFFFFF:
            stream_blocks.append(None)
            continue
        count = (size + block_size - 1) // block_size
        end = cursor + count * 4
        if end > len(directory):
            raise ValueError("truncated MSF stream block list")
        blocks = struct.unpack_from(f"<{count}I", directory, cursor) if count else ()
        cursor = end
        if len(set(blocks)) != len(blocks):
            raise ValueError("duplicate block in MSF stream")
        stream_blocks.append(blocks)
    if cursor != len(directory):
        raise ValueError("unexpected bytes in MSF stream directory")

    streams: list[bytes | None] = []
    for size, blocks in zip(stream_sizes, stream_blocks):
        if size == 0xFFFFFFFF or blocks is None:
            streams.append(None)
            continue
        stream = bytearray()
        for block in blocks:
            offset = block * block_size
            if block >= block_count or offset > len(data) - block_size:
                raise ValueError("invalid MSF stream block")
            stream.extend(data[offset:offset + block_size])
        del stream[size:]
        if len(stream) != size:
            raise ValueError("truncated MSF stream")
        streams.append(bytes(stream))
    return data, streams


def parse_pdb_identity(path: Path) -> tuple[bytes, int]:
    _data, streams = parse_msf_streams(path)
    if len(streams) < 2 or streams[1] is None or len(streams[1]) < 28:
        raise ValueError("missing PDB information stream")
    info = streams[1]
    version = struct.unpack_from("<I", info, 0)[0]
    if version != 20000404:
        raise ValueError("unsupported PDB information stream version")
    age = struct.unpack_from("<I", info, 8)[0]
    guid = bytes(info[12:28])
    return guid, age


def _normalized_symbol_path(value: str) -> str:
    return value.replace("\\", "/").rstrip("/").casefold()


def _normalized_forbidden_symbol_path(value: str) -> str:
    normalized = value.replace("\\", "/").casefold()
    if re.fullmatch(r"[a-z]:/?", normalized):
        return normalized[:2] + "/"
    return normalized.rstrip("/")


def _symbol_path_matches(
    text: str, forbidden_paths: tuple[str, ...],
) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    for match in PDB_USER_PROFILE_RE.finditer(text):
        matches.append(("user-profile", match.start(), match.end()))
    for match in PDB_KDBG_CHECKOUT_RE.finditer(text):
        matches.append(("kdbg-checkout", match.start(), match.end()))

    normalized = _normalized_symbol_path(text)
    for forbidden in forbidden_paths:
        needle = _normalized_forbidden_symbol_path(forbidden)
        if len(needle) < 3:
            continue
        start = 0
        while True:
            index = normalized.find(needle, start)
            if index < 0:
                break
            matches.append(("configured-root", index, index + len(needle)))
            start = index + len(needle)
    return matches


def validate_pdb_path_policy(
    path: Path, forbidden_paths: tuple[str, ...], errors: list[str],
) -> None:
    """Reject private build paths without reproducing their literals in output."""
    try:
        raw, streams = parse_msf_streams(path)
    except (OSError, ValueError, struct.error) as exc:
        errors.append(f"invalid PDB structure {path.name}: {exc}")
        return

    payloads: list[tuple[str, bytes]] = [("raw", raw)]
    payloads.extend(
        (f"stream-{index}", stream)
        for index, stream in enumerate(streams)
        if stream is not None
    )
    seen: set[tuple[str, str, str]] = set()
    for scope, payload in payloads:
        encoded_runs = (
            ("ascii", PDB_ASCII_RUN_RE, "ascii"),
            ("utf-16le", PDB_UTF16LE_RUN_RE, "utf-16le"),
        )
        for encoding, pattern, codec in encoded_runs:
            for run in pattern.finditer(payload):
                text = run.group().decode(codec, errors="strict")
                for category, match_start, match_end in _symbol_path_matches(
                    text, forbidden_paths
                ):
                    matched = _normalized_symbol_path(
                        text[match_start:match_end])
                    key = (category, encoding, matched)
                    if key in seen:
                        continue
                    seen.add(key)
                    byte_scale = 2 if encoding == "utf-16le" else 1
                    byte_offset = run.start() + match_start * byte_scale
                    location = hashlib.sha256(
                        f"{scope}:{encoding}:{byte_offset}".encode("ascii")
                    ).hexdigest()[:16]
                    errors.append(
                        "PDB path policy violation: "
                        f"file={path.name} category={category} "
                        f"encoding={encoding} location_sha256={location}"
                    )


def validate_binary_symbol_pair(
    binary: Path, pdb: Path, errors: list[str]
) -> None:
    if not binary.is_file() or not pdb.is_file():
        return
    try:
        _machine, _imports, _version, codeview = parse_pe(binary)
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        errors.append(f"cannot read PE CodeView identity {binary}: {exc}")
        return
    if codeview is None:
        errors.append(f"release binary has no RSDS CodeView identity: {binary}")
        return
    try:
        pdb_guid, pdb_age = parse_pdb_identity(pdb)
    except (OSError, ValueError, struct.error) as exc:
        errors.append(f"cannot read PDB identity {pdb}: {exc}")
        return
    pe_guid, pe_age, embedded_path = codeview
    embedded_name = re.split(r"[\\/]", embedded_path)[-1]
    if embedded_name.casefold() != pdb.name.casefold():
        errors.append(
            f"PE CodeView PDB name does not match symbols package: {binary}")
    if embedded_path != embedded_name:
        errors.append(f"PE CodeView leaks a build path instead of a PDB basename: {binary}")
    if pe_guid != pdb_guid or pe_age != pdb_age:
        errors.append(f"PE/PDB GUID+age mismatch: {binary} vs {pdb}")


def safe_relative(value: str) -> str | None:
    if not value or "\\" in value or ":" in value or "\x00" in value:
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


def validate_source_provenance(
    metadata: dict, label: str, errors: list[str]
) -> None:
    if (not isinstance(metadata.get("source_revision"), str) or
            not metadata["source_revision"].strip()):
        errors.append(f"{label} source_revision is missing")
    scope = metadata.get("source_snapshot_scope")
    if scope not in {
        LEGACY_SOURCE_SNAPSHOT_SCOPE, PRODUCT_SOURCE_SNAPSHOT_SCOPE,
    }:
        errors.append(f"{label} source_snapshot_scope mismatch")
    if scope == PRODUCT_SOURCE_SNAPSHOT_SCOPE:
        policy = metadata.get("source_snapshot_policy")
        if not isinstance(policy, dict) or set(policy) != PRODUCT_SOURCE_POLICY_KEYS:
            errors.append(f"{label} source_snapshot_policy is invalid")
        else:
            for field in PRODUCT_SOURCE_POLICY_KEYS:
                values = policy.get(field)
                if (not isinstance(values, list) or not values or
                        not all(isinstance(value, str) and value
                                for value in values)):
                    errors.append(
                        f"{label} source_snapshot_policy.{field} is invalid")
            excluded = policy.get("excluded_paths")
            if (isinstance(excluded, list) and
                    not PRODUCT_SOURCE_REQUIRED_EXCLUSIONS.issubset(excluded)):
                errors.append(
                    f"{label} source_snapshot_policy omits mutable ledgers")
            scan_roots = policy.get("scan_roots")
            if (isinstance(scan_roots, list) and
                    not {"src", "licenses"}.issubset(scan_roots)):
                errors.append(
                    f"{label} source_snapshot_policy omits product roots")
        if metadata.get("source_snapshot_manifest") != SOURCE_SNAPSHOT_MANIFEST:
            errors.append(f"{label} source_snapshot_manifest mismatch")
    snapshot_sha = metadata.get("source_snapshot_sha256")
    if not isinstance(snapshot_sha, str) or not SHA_RE.fullmatch(snapshot_sha):
        errors.append(f"{label} source_snapshot_sha256 is invalid")
    file_count = metadata.get("source_file_count")
    if (not isinstance(file_count, int) or isinstance(file_count, bool) or
            file_count <= 0):
        errors.append(f"{label} source_file_count is invalid")


def validate_source_snapshot_manifest(
    package: Path, metadata: dict, label: str, errors: list[str]
) -> None:
    if metadata.get("source_snapshot_scope") != PRODUCT_SOURCE_SNAPSHOT_SCOPE:
        return
    path = package / SOURCE_SNAPSHOT_MANIFEST
    if not path.is_file():
        errors.append(f"{label} source snapshot manifest is missing")
        return
    raw = path.read_bytes()
    if not raw or b"\r" in raw or not raw.endswith(b"\n"):
        errors.append(f"{label} source snapshot manifest is not canonical LF text")
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{label} source snapshot manifest is not UTF-8")
        return
    records = text[:-1].split("\n")
    record_re = re.compile(r"^([0-9a-f]{64})  ([^\\\r\n]+)$")
    matches = [record_re.fullmatch(record) for record in records]
    paths = [match.group(2) for match in matches if match is not None]
    if (not records or len(matches) != len(paths) or
            paths != sorted(paths) or len(paths) != len(set(paths)) or
            any(PurePosixPath(path).is_absolute() or
                any(part in {"", ".", ".."}
                    for part in PurePosixPath(path).parts)
                for path in paths)):
        errors.append(f"{label} source snapshot manifest records are invalid")
    if len(records) != metadata.get("source_file_count"):
        errors.append(f"{label} source snapshot manifest count mismatch")
    if hashlib.sha256(raw).hexdigest() != metadata.get("source_snapshot_sha256"):
        errors.append(f"{label} source snapshot manifest digest mismatch")


def validate_tool_versions(
    metadata: dict, label: str, errors: list[str]
) -> None:
    tool_versions = metadata.get("tool_versions")
    if not isinstance(tool_versions, dict):
        errors.append(f"{label} requires tool_versions")
        return
    for tool in REQUIRED_TOOL_VERSIONS:
        value = tool_versions.get(tool)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{label} tool version is missing: {tool}")


def validate_metadata(package: Path, errors: list[str]) -> dict | None:
    metadata = load_json(package / "BUILD-METADATA.json", "BUILD-METADATA.json", errors)
    if metadata is None:
        return None
    expected = {
        "schema": "kdbg.build-metadata.v1", "product": "KDBG", "version": VERSION,
        "configuration": "Release", "architecture": "x64",
        "package_name": PACKAGE_NAME,
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            errors.append(f"BUILD-METADATA.json {field} mismatch")
    if metadata.get("minimum_windows_build") != MIN_WINDOWS_BUILD:
        errors.append("BUILD-METADATA.json minimum_windows_build mismatch")
    validate_source_provenance(metadata, "BUILD-METADATA.json", errors)
    validate_source_snapshot_manifest(
        package, metadata, "BUILD-METADATA.json", errors)
    commands = metadata.get("reproducible_commands")
    if not isinstance(commands, list) or not commands or not all(
        isinstance(command, str) and command.strip() for command in commands
    ):
        errors.append("BUILD-METADATA.json requires reproducible_commands")
    validate_tool_versions(metadata, "BUILD-METADATA.json", errors)
    actual_catalogs = sorted(path.relative_to(package).as_posix()
                             for path in (package / "drivers").glob("*.cat"))
    if (metadata.get("catalogs") != list(EXPECTED_CATALOGS) or
            actual_catalogs != list(EXPECTED_CATALOGS)):
        errors.append(
            "BUILD-METADATA.json catalogs must exactly match both packaged driver CAT files")
    if metadata.get("symbols_package") != SYMBOLS_NAME:
        errors.append("BUILD-METADATA.json symbols_package mismatch")
    return metadata


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


def validate_lifecycle(package: Path, errors: list[str]) -> None:
    required_tokens = {
        "tools/TargetProfile.psm1": (
            "Assert-KdbgTargetProfile", "Get-KdbgMachineBindingSha256",
            "DisposableVm", "LocalHost",
        ),
        "tools/diagnose.ps1": (
            "VerifyPackage", "RequireInstalled", "RequireRunning",
            "SHA256SUMS.txt", "Get-AuthenticodeSignature",
            "DistributionSource", "SetupStaging", "InstalledProduct",
        ),
        "tools/install.ps1": (
            "ConfirmDedicatedVm", "ConfirmSnapshot",
            "diagnose.ps1", "start.ps1", "PackageRootMode",
        ),
        "tools/start.ps1": (
            "ConfirmDedicatedVm", "ConfirmSnapshot", "RequireInstalled",
            "RequireRunning", "PackageRootMode",
        ),
        "tools/run.ps1": (
            "ConfirmDedicatedVm", "ConfirmSnapshot", "StartDrivers",
            "StopDriversOnExit", "RequireRunning", "PackageRootMode",
        ),
        "tools/stop.ps1": ("KDBGProbe", "KDBG"),
        "tools/uninstall.ps1": (
            "ConfirmKdbgServices", "stop.ps1",
            "Package files and user data were retained", "PackageRootMode",
            "kdbg.setup-purge.v1", "PURGE_SCHEDULED",
        ),
        "tools/setup.ps1": (
            "RequireTrustedDriverSignatures", "tools\\install.ps1",
            "tools\\uninstall.ps1", "UninstallString", "WScript.Shell",
            "Prepare-ExactPackagePurge", "Commit-ExactPackagePurge",
            "Assert-NoReparsePoints",
            "DistributionSource", "SetupStaging", "InstalledProduct",
            "kdbg.setup-purge.v1", "PURGE_SCHEDULED",
        ),
        "tools/setup_contract.psm1": (
            "kdbg.setup-contract.v1", "Install", "Repair", "Update",
            "Uninstall", "MutatesDriverServicesOnlyThroughPackageLifecycle",
            "kdbg.setup-transaction.v1", "last-known-good backup preserved",
        ),
        "tools/new_live_evidence.ps1": (
            "kdbg.live-evidence.v4", "scene_review_file",
            "validate_release.py", "outside the immutable main and symbols packages",
            "KDBGSetup.pdb",
        ),
        "tools/capture_demo.ps1": (
            "kdbg.demo-scene-review.v1", "SceneReviewTemplate",
            "private_paths_redacted",
        ),
    }
    for relative, tokens in required_tokens.items():
        path = package / PurePosixPath(relative)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        for token in tokens:
            if token not in text:
                errors.append(f"{relative} lacks lifecycle marker: {token}")
    validate_powershell_syntax(
        [package / PurePosixPath(relative) for relative in required_tokens],
        errors,
        required=True,
    )
    documentation_tokens = {
        "docs/QUICKSTART.md": ("diagnose.ps1", "install.ps1", "run.ps1", "uninstall.ps1"),
        "docs/OPERATOR_GUIDE.md": ("Update", "Recovery", "Migration", "stop.ps1"),
        "docs/TROUBLESHOOTING.md": ("diagnose.ps1", "RequireRunning", "snapshot"),
    }
    for relative, tokens in documentation_tokens.items():
        path = package / PurePosixPath(relative)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        for token in tokens:
            if token not in text:
                errors.append(f"{relative} lacks operator marker: {token}")


def validate_inf_catalogs(package: Path, errors: list[str]) -> None:
    for driver_name, expected_catalog in (
        ("KDbgDriver", "KDbgDriver.cat"),
        ("KDbgProbe", "KDbgProbe.cat"),
    ):
        path = package / f"drivers/{driver_name}.inf"
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        matches = re.findall(
            r"^\s*CatalogFile(?:\.[^=\s]+)?\s*=\s*([^;\r\n]+?)\s*(?:;.*)?$",
            text, re.M | re.I,
        )
        if len(matches) != 1:
            errors.append(
                f"{driver_name}.inf must declare exactly one CatalogFile")
            continue
        declared = matches[0].strip().strip('"')
        if declared.casefold() != expected_catalog.casefold():
            errors.append(
                f"{driver_name}.inf CatalogFile must be {expected_catalog}")


def validate_package(package: Path, errors: list[str]) -> dict | None:
    if not package.is_dir():
        errors.append(f"Windows package directory not found: {package}")
        return None
    if package.name != PACKAGE_NAME:
        errors.append(f"Windows package directory must be named {PACKAGE_NAME}")
    for relative in MAIN_REQUIRED:
        path = package / PurePosixPath(relative)
        if not path.is_file():
            errors.append(f"Windows package missing: {relative}")
        elif path.stat().st_size == 0:
            errors.append(f"Windows package contains empty file: {relative}")
    validate_release_documents(
        package, PACKAGE_RELEASE_DOCUMENT_REQUIREMENTS,
        "packaged release document", errors,
    )
    for path in package.rglob("*.pdb"):
        errors.append(f"PDB must be in the separate symbols package: {path}")
    validate_pe(package / "KDBG.exe", True, errors)
    validate_pe(package / "KDBGSetup.exe", True, errors)
    validate_pe(package / "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe", True, errors)
    validate_pe(package / "tools/kdbg_live_verify.exe", True, errors)
    validate_pe(package / "tools/kdbg_process_fixture.exe", True, errors)
    validate_pe(package / "drivers/KDbgDriver.sys", False, errors)
    validate_pe(package / "drivers/KDbgProbe.sys", False, errors)
    for name in ("KDbgDriver", "KDbgProbe"):
        path = package / f"drivers/{name}.inf"
        if path.is_file():
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            match = re.search(r"^DriverVer\s*=\s*[^,]+,([0-9.]+)\s*$", text, re.M)
            if match is None or match.group(1) != "1.1.0.0":
                errors.append(f"INF version mismatch: {path}")
    validate_inf_catalogs(package, errors)
    metadata = validate_metadata(package, errors)
    validate_sbom(package, errors)
    validate_packaged_lock(package, errors)
    validate_lifecycle(package, errors)
    for path in package.rglob("*"):
        if path.is_file() and path.suffix.casefold() in {".md", ".txt", ".json", ".ps1", ".inf"}:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            if PRIVATE_PATH_RE.search(text):
                errors.append(f"package contains a private user path: {path}")
            if EMAIL_RE.search(text):
                errors.append(f"package contains an email address: {path}")
    validate_sums(package, errors)
    return metadata


def validate_symbol_path_policy_metadata(
    metadata: dict[str, object], errors: list[str],
) -> None:
    policy = metadata.get("path_policy")
    if not isinstance(policy, dict):
        errors.append("symbols metadata path_policy is missing")
        return
    expected_scalars = {
        "schema": "kdbg.symbol-path-policy.v1",
        "logical_root": "KDBG_ROOT",
        "private_paths_present": False,
    }
    for field, expected in expected_scalars.items():
        if policy.get(field) != expected:
            errors.append(f"symbols metadata path_policy {field} mismatch")
    if policy.get("scan_scope") != ["raw", "logical-streams"]:
        errors.append("symbols metadata path_policy scan_scope mismatch")
    if policy.get("encodings") != ["ascii", "utf-16le"]:
        errors.append("symbols metadata path_policy encodings mismatch")
    if policy.get("permitted_stable_aliases") != ["R:\\", "K:\\"]:
        errors.append(
            "symbols metadata path_policy permitted_stable_aliases mismatch")
    if policy.get("stable_aliases_are_private") is not False:
        errors.append(
            "symbols metadata path_policy stable_aliases_are_private mismatch")


def validate_symbols(
    package: Path,
    errors: list[str],
    forbidden_symbol_paths: tuple[str, ...] = (),
) -> dict | None:
    if not package.is_dir():
        errors.append(f"symbols package directory not found: {package}")
        return None
    if package.name != SYMBOLS_NAME:
        errors.append(f"symbols package directory must be named {SYMBOLS_NAME}")
    files = file_set(package)
    pdbs = [name for name in files if name.casefold().endswith(".pdb")]
    if not pdbs:
        errors.append("symbols package contains no PDB files")
    for relative in SYMBOLS_REQUIRED:
        if relative not in files:
            errors.append(f"symbols package missing required PDB: {relative}")
    for relative in files:
        if not relative.casefold().endswith(".pdb") and relative not in {
            "BUILD-METADATA.json", SOURCE_SNAPSHOT_MANIFEST, "SHA256SUMS.txt"
        }:
            errors.append(f"unexpected file in symbols package: {relative}")
        if (package / PurePosixPath(relative)).stat().st_size == 0:
            errors.append(f"empty file in symbols package: {relative}")
    for relative in sorted(pdbs):
        validate_pdb_path_policy(
            package / PurePosixPath(relative), forbidden_symbol_paths, errors)
    metadata = load_json(package / "BUILD-METADATA.json", "symbols metadata", errors)
    if metadata:
        expected = {"schema": "kdbg.symbols-metadata.v1", "product": "KDBG",
                    "version": VERSION, "configuration": "Release",
                    "architecture": "x64", "package_name": SYMBOLS_NAME,
                    "minimum_windows_build": MIN_WINDOWS_BUILD}
        for field, value in expected.items():
            if metadata.get(field) != value:
                errors.append(f"symbols metadata {field} mismatch")
        validate_source_provenance(metadata, "symbols metadata", errors)
        validate_source_snapshot_manifest(
            package, metadata, "symbols metadata", errors)
        validate_tool_versions(metadata, "symbols metadata", errors)
        validate_symbol_path_policy_metadata(metadata, errors)
    validate_sums(package, errors)
    return metadata


def validate_package_pair(
    package: Path,
    symbols: Path,
    main_metadata: dict | None,
    symbols_metadata: dict | None,
    errors: list[str],
) -> None:
    if main_metadata is None or symbols_metadata is None:
        return
    main_epoch = main_metadata.get("release_epoch")
    symbols_epoch = symbols_metadata.get("release_epoch")
    if main_epoch is not None or symbols_epoch is not None:
        epoch_re = re.compile(
            r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$"
        )
        if (not isinstance(main_epoch, str) or
                epoch_re.fullmatch(main_epoch) is None):
            errors.append("main package release_epoch is missing or invalid")
        if (not isinstance(symbols_epoch, str) or
                epoch_re.fullmatch(symbols_epoch) is None):
            errors.append("symbols package release_epoch is missing or invalid")
        if main_epoch != symbols_epoch:
            errors.append("main/symbols package release_epoch mismatch")
    for field in (
        "source_revision",
        "source_snapshot_scope",
        "source_snapshot_sha256",
        "source_file_count",
        "source_snapshot_manifest",
        "source_snapshot_policy",
        "tool_versions",
    ):
        if main_metadata.get(field) != symbols_metadata.get(field):
            errors.append(
                f"main/symbols package provenance mismatch: {field}")
    for binary_relative, pdb_relative in BINARY_SYMBOL_PAIRS:
        validate_binary_symbol_pair(
            package / PurePosixPath(binary_relative),
            symbols / PurePosixPath(pdb_relative),
            errors,
        )


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


def validate_gif_lzw(payload: bytes, minimum_code_size: int, pixels: int) -> None:
    clear_code = 1 << minimum_code_size
    end_code = clear_code + 1
    dictionary: dict[int, bytes] = {
        value: bytes((value,)) for value in range(clear_code)
    }
    next_code = end_code + 1
    code_size = minimum_code_size + 1
    bit_offset = 0
    previous: bytes | None = None
    output_count = 0
    saw_clear = False
    saw_end = False

    def read_code() -> int | None:
        nonlocal bit_offset
        if bit_offset + code_size > len(payload) * 8:
            return None
        value = 0
        for bit in range(code_size):
            absolute = bit_offset + bit
            value |= ((payload[absolute // 8] >> (absolute % 8)) & 1) << bit
        bit_offset += code_size
        return value

    while True:
        code = read_code()
        if code is None:
            break
        if code == clear_code:
            dictionary = {value: bytes((value,)) for value in range(clear_code)}
            next_code = end_code + 1
            code_size = minimum_code_size + 1
            previous = None
            saw_clear = True
            continue
        if not saw_clear:
            raise ValueError("GIF LZW stream does not begin with a clear code")
        if code == end_code:
            saw_end = True
            break
        if code in dictionary:
            entry = dictionary[code]
        elif code == next_code and previous is not None:
            entry = previous + previous[:1]
        else:
            raise ValueError("GIF LZW stream references an invalid code")
        output_count += len(entry)
        if output_count > pixels:
            raise ValueError("GIF LZW stream expands beyond the frame rectangle")
        if previous is not None and next_code < 4096:
            dictionary[next_code] = previous + entry[:1]
            next_code += 1
            if next_code == (1 << code_size) and code_size < 12:
                code_size += 1
        previous = entry
    if not saw_end:
        raise ValueError("GIF LZW stream has no end code")
    if output_count != pixels:
        raise ValueError("GIF LZW stream does not fill the frame rectangle")


def parse_gif(path: Path) -> dict[str, int | str]:
    """Parse enough of GIF89a to prove a bounded, timed multi-frame container."""
    data = path.read_bytes()
    if len(data) < 14 or data[:6] not in {b"GIF87a", b"GIF89a"}:
        raise ValueError("missing GIF87a/GIF89a signature or logical screen")
    width, height = struct.unpack_from("<HH", data, 6)
    if not (GIF_MIN_WIDTH <= width <= GIF_MAX_WIDTH and
            GIF_MIN_HEIGHT <= height <= GIF_MAX_HEIGHT):
        raise ValueError(
            f"logical dimensions must be {GIF_MIN_WIDTH}x{GIF_MIN_HEIGHT} through "
            f"{GIF_MAX_WIDTH}x{GIF_MAX_HEIGHT}")

    cursor = 13
    packed = data[10]
    if packed & 0x80:
        cursor += 3 * (1 << ((packed & 0x07) + 1))
    if cursor > len(data):
        raise ValueError("truncated global color table")

    frames = 0
    duration_ms = 0
    pending_delay_ms = 0
    saw_trailer = False

    def consume_sub_blocks(offset: int) -> tuple[int, int]:
        payload_bytes = 0
        while True:
            if offset >= len(data):
                raise ValueError("unterminated GIF data sub-blocks")
            size = data[offset]
            offset += 1
            if size == 0:
                return offset, payload_bytes
            if offset + size > len(data):
                raise ValueError("truncated GIF data sub-block")
            payload_bytes += size
            offset += size

    while cursor < len(data):
        marker = data[cursor]
        cursor += 1
        if marker == 0x3B:
            saw_trailer = True
            if cursor != len(data):
                raise ValueError("bytes follow the GIF trailer")
            break
        if marker == 0x21:
            if cursor >= len(data):
                raise ValueError("truncated GIF extension label")
            label = data[cursor]
            cursor += 1
            if label == 0xF9:
                if cursor + 6 > len(data) or data[cursor] != 4 or data[cursor + 5] != 0:
                    raise ValueError("malformed graphic control extension")
                pending_delay_ms = struct.unpack_from("<H", data, cursor + 2)[0] * 10
                cursor += 6
            else:
                cursor, _ = consume_sub_blocks(cursor)
            continue
        if marker != 0x2C:
            raise ValueError(f"unexpected GIF block marker 0x{marker:02x}")
        if cursor + 9 > len(data):
            raise ValueError("truncated GIF image descriptor")
        left, top, frame_width, frame_height = struct.unpack_from("<HHHH", data, cursor)
        image_packed = data[cursor + 8]
        cursor += 9
        if (frame_width == 0 or frame_height == 0 or
                left + frame_width > width or top + frame_height > height):
            raise ValueError("GIF frame rectangle is empty or outside the logical screen")
        if image_packed & 0x80:
            cursor += 3 * (1 << ((image_packed & 0x07) + 1))
        if cursor >= len(data):
            raise ValueError("truncated GIF image data")
        minimum_code_size = data[cursor]
        cursor += 1
        if not 2 <= minimum_code_size <= 8:
            raise ValueError("invalid GIF LZW minimum code size")
        payload_start = cursor
        cursor, payload_bytes = consume_sub_blocks(cursor)
        if payload_bytes == 0:
            raise ValueError("GIF frame has no compressed image data")
        compressed = bytearray()
        sub_cursor = payload_start
        while data[sub_cursor] != 0:
            size = data[sub_cursor]
            sub_cursor += 1
            compressed.extend(data[sub_cursor:sub_cursor + size])
            sub_cursor += size
        validate_gif_lzw(
            bytes(compressed), minimum_code_size, frame_width * frame_height)
        frames += 1
        if frames > GIF_MAX_FRAMES:
            raise ValueError(f"GIF frame count exceeds {GIF_MAX_FRAMES}")
        duration_ms += pending_delay_ms
        pending_delay_ms = 0
        if duration_ms > GIF_MAX_DURATION_MS:
            raise ValueError("GIF duration exceeds the eight-hour evidence limit")

    if not saw_trailer:
        raise ValueError("GIF trailer is missing")
    if frames < GIF_MIN_FRAMES:
        raise ValueError(f"GIF must contain at least {GIF_MIN_FRAMES} frames")
    if duration_ms < GIF_MIN_DURATION_MS:
        raise ValueError(
            f"GIF duration must be at least {GIF_MIN_DURATION_MS} milliseconds")
    return {
        "format": "gif",
        "width": width,
        "height": height,
        "frame_count": frames,
        "duration_ms": duration_ms,
    }


def validate_scene_review(
    path: Path,
    video_name: str,
    video_sha256: str,
    duration_ms: int,
    evidence_timestamp: datetime | None,
    errors: list[str],
) -> list[str]:
    review = load_json(path, "scene review", errors)
    if review is None:
        return []
    if review.get("schema") != "kdbg.demo-scene-review.v1":
        errors.append("scene review schema mismatch")
    if review.get("video_file") != video_name:
        errors.append("scene review video_file does not match the evidence GIF")
    if review.get("video_sha256") != video_sha256:
        errors.append("scene review video_sha256 does not match the evidence GIF")
    reviewer = review.get("reviewer")
    if (not isinstance(reviewer, str) or len(reviewer.strip()) < 2 or
            re.search(r"(?:<|replace|placeholder|unknown|fixture|todo)",
                      reviewer, re.I)):
        errors.append("scene review reviewer is empty or a placeholder")
    try:
        reviewed = datetime.fromisoformat(
            str(review.get("reviewed_utc", "")).replace("Z", "+00:00"))
        if (reviewed.tzinfo is None or
                reviewed.utcoffset() != timezone.utc.utcoffset(reviewed)):
            raise ValueError("not UTC")
        if evidence_timestamp is not None and reviewed > evidence_timestamp:
            errors.append("scene review postdates the final evidence timestamp")
        if reviewed.timestamp() > datetime.now(timezone.utc).timestamp() + 300:
            errors.append("scene review reviewed_utc is in the future")
    except (TypeError, ValueError) as exc:
        errors.append(f"invalid scene review reviewed_utc: {exc}")
    for field in ("private_paths_redacted", "unrelated_process_data_redacted"):
        if review.get(field) is not True:
            errors.append(f"scene review field is not true: {field}")
    scenes = review.get("scenes")
    if not isinstance(scenes, list):
        errors.append("scene review scenes must be an array")
        return []
    identifiers: list[str] = []
    previous_end = 0
    for index, scene in enumerate(scenes):
        if not isinstance(scene, dict):
            errors.append(f"scene review entry {index} must be an object")
            continue
        identifier = scene.get("id")
        if not isinstance(identifier, str):
            errors.append(f"scene review entry {index} has no scene id")
            continue
        identifiers.append(identifier)
        start = scene.get("start_ms")
        end = scene.get("end_ms")
        if (not isinstance(start, int) or isinstance(start, bool) or
                not isinstance(end, int) or isinstance(end, bool) or
                start < 0 or start >= end or end > duration_ms or
                end - start < 500):
            errors.append(
                f"scene review timing is outside the GIF duration: {identifier}")
        elif start < previous_end:
            errors.append("scene review timings overlap or are not in presentation order")
        else:
            previous_end = end
        if scene.get("observed") is not True:
            errors.append(f"scene review did not mark observed: {identifier}")
        notes = scene.get("notes")
        if (not isinstance(notes, str) or len(notes.strip()) < 4 or
                re.search(r"(?:<|replace|placeholder|unknown|fixture|todo)",
                          notes, re.I)):
            errors.append(
                f"scene review notes are empty or a placeholder: {identifier}")
    if identifiers != list(DEMO_SCENE_ORDER):
        errors.append("scene review must contain every required scene exactly once and in order")
    return identifiers


def validate_runtime_identity(
    report: dict[str, object], errors: list[str]
) -> dict[str, str]:
    """Validate the verifier and running driver identities captured pre-open."""
    identity = report.get("runtime_identity")
    if not isinstance(identity, dict):
        errors.append("live run runtime_identity record is missing")
        return {}
    if identity.get("verified") is not True:
        errors.append("live run runtime identity is not verified")

    artifacts: dict[str, str] = {}

    def checked_file(value: object, field: str, expected_path: str) -> None:
        if not isinstance(value, dict):
            errors.append(f"live run runtime identity {field} is missing")
            return
        if value.get("package_relative_path") != expected_path:
            errors.append(
                f"live run runtime identity {field} path must be {expected_path}")
        digest = value.get("sha256")
        if not isinstance(digest, str) or not SHA_RE.fullmatch(digest):
            errors.append(
                f"live run runtime identity {field} SHA-256 is invalid")
            return
        artifacts[expected_path] = digest

    checked_file(
        identity.get("verifier"), "verifier", "tools/kdbg_live_verify.exe")
    for field, service_name, relative_path in (
        ("kdbg_service", "KDBG", "drivers/KDbgDriver.sys"),
        ("probe_service", "KDBGProbe", "drivers/KDbgProbe.sys"),
    ):
        service = identity.get(field)
        if not isinstance(service, dict):
            errors.append(f"live run runtime identity {field} is missing")
            continue
        if (service.get("name") != service_name or
                service.get("service_type") != 1 or
                service.get("current_state") != 4 or
                service.get("running_kernel_driver") is not True):
            errors.append(
                f"live run runtime identity {field} is not a running kernel driver")
        checked_file(service.get("binary"), f"{field}.binary", relative_path)
    return artifacts


def _safe_evidence_file(
    directory: Path, relative: object, label: str, errors: list[str],
) -> Path | None:
    if (not isinstance(relative, str) or safe_relative(relative) is None or
            "/" in relative or "\\" in relative):
        errors.append(f"{label} must be a safe sibling filename")
        return None
    artifact = directory / relative
    if artifact.is_symlink():
        errors.append(f"{label} must not be a symbolic link")
        return None
    if not artifact.is_file():
        errors.append(f"{label} is missing: {artifact}")
        return None
    return artifact


def validate_analysis_metadata(
    path: Path,
    package: Path,
    symbols: Path | None,
    final_timestamp: datetime | None,
    probe_pfn: int | None,
    expected_abi: int | None,
    errors: list[str],
) -> dict[str, int | None]:
    """Validate the independent user mapping and Kernel Explorer proof."""
    result: dict[str, int | None] = {
        "pid": None, "process_start_id": None, "va": None, "pa": None,
        "pfn": None, "pte": None, "dtb": None,
    }
    data = load_json(path, "analysis metadata", errors)
    if data is None:
        return result
    if data.get("schema") != "kdbg-analysis-live-evidence-v1":
        errors.append("analysis metadata schema must be kdbg-analysis-live-evidence-v1")
    if (expected_abi not in {6, 7} or
            data.get("driver_abi_version") != expected_abi):
        errors.append("analysis metadata driver ABI does not match final evidence")
    try:
        captured = datetime.fromisoformat(
            str(data.get("captured_utc", "")).replace("Z", "+00:00"))
        if (captured.tzinfo is None or
                captured.utcoffset() != timezone.utc.utcoffset(captured)):
            raise ValueError("not UTC")
        if final_timestamp is not None and captured > final_timestamp:
            errors.append("analysis metadata timestamp is later than final evidence")
    except ValueError as exc:
        errors.append(f"invalid analysis metadata captured_utc: {exc}")

    process = data.get("process")
    if not isinstance(process, dict):
        errors.append("analysis process identity must be an object")
        process = {}
    pid = integer(process.get("pid"), "analysis.process.pid", errors)
    process_start = integer(
        process.get("process_start_id"), "analysis.process.process_start_id", errors)
    result["pid"], result["process_start_id"] = pid, process_start
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        errors.append("analysis process PID must be a non-zero uint32")
    if process_start is not None and process_start <= 0:
        errors.append("analysis process_start_id must be non-zero")
    if process.get("image_basename") != "kdbg_process_fixture.exe":
        errors.append("analysis process image_basename must be kdbg_process_fixture.exe")
    image_hash = process.get("image_sha256")
    require_sha(image_hash, "analysis.process.image_sha256", errors)
    fixture_image = package / "tools/kdbg_process_fixture.exe"
    if (fixture_image.is_file() and isinstance(image_hash, str) and
            image_hash != sha256(fixture_image)):
        errors.append("analysis process image hash does not match packaged fixture")
    protocol = process.get("protocol_version")
    if protocol != 1 or isinstance(protocol, bool):
        errors.append("analysis protocol_version must be exactly 1")
    nonce = process.get("fixture_nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        errors.append("analysis fixture_nonce must be exactly 16 lowercase hex bytes")
    process_va = integer(
        process.get("virtual_address"), "analysis.process.virtual_address", errors)
    if process.get("byte_count") != 4096:
        errors.append("analysis process byte_count must be exactly 4096")
    if process.get("virtual_locked") is not True:
        errors.append("analysis fixture page must be VirtualLock-backed")
    process_generation = process.get("generation")
    if (not isinstance(process_generation, int) or
            isinstance(process_generation, bool) or process_generation <= 0):
        errors.append("analysis process generation must be positive")
    for field in ("baseline_crc32", "current_crc32"):
        if (not isinstance(process.get(field), str) or
                not re.fullmatch(r"[0-9a-f]{8}", process[field])):
            errors.append(f"analysis process {field} must be lowercase bare CRC32")

    fixture_info_file = _safe_evidence_file(
        path.parent, process.get("fixture_info_file"),
        "analysis fixture INFO JSON", errors)
    require_sha(process.get("fixture_info_sha256"),
                "analysis.process.fixture_info_sha256", errors)
    fixture_info: dict[str, object] = {}
    if fixture_info_file is not None:
        if sha256(fixture_info_file) != process.get("fixture_info_sha256"):
            errors.append("analysis fixture INFO JSON hash mismatch")
        loaded_info = load_json(fixture_info_file, "fixture INFO JSON", errors)
        if loaded_info is not None:
            fixture_info = loaded_info
    if fixture_info:
        expected_info = {
            "schema": "kdbg.process-fixture.v1",
            "protocol_version": 1,
            "pid": pid,
            "process_start_id": process_start,
            "fixture_nonce": nonce,
            "image_basename": "kdbg_process_fixture.exe",
            "virtual_address": process_va,
            "byte_count": 4096,
            "generation": process_generation,
            "virtual_locked": True,
        }
        for field, expected in expected_info.items():
            actual = fixture_info.get(field)
            if field in {"pid", "process_start_id", "virtual_address"}:
                actual = integer(actual, f"fixture INFO {field}", errors)
            if actual != expected:
                errors.append(
                    f"fixture INFO {field} does not match analysis process identity")
        for field in ("baseline_crc32", "current_crc32"):
            fixture_crc = fixture_info.get(field)
            if (not isinstance(fixture_crc, str) or
                    not re.fullmatch(r"0x[0-9a-f]{8}", fixture_crc)):
                errors.append(
                    f"fixture INFO {field} must be lowercase 0x-prefixed CRC32")
            elif (isinstance(process.get(field), str) and
                    fixture_crc[2:] != process[field]):
                errors.append(
                    f"fixture INFO {field} does not match analysis process CRC32")
        if fixture_info.get("ok") is not True or fixture_info.get("command") != "INFO":
            errors.append("fixture INFO JSON is not a successful INFO response")
        pipe_name = fixture_info.get("pipe_name")
        if (not isinstance(pipe_name, str) or
                not pipe_name.startswith(r"\\.\pipe\KDBG.ProcessFixture.")):
            errors.append("fixture INFO JSON has an invalid local named-pipe identity")
        corpus = fixture_info.get("corpus")
        if not isinstance(corpus, dict) or not corpus:
            errors.append("fixture INFO JSON is missing the deterministic corpus map")

    ownership = data.get("ownership")
    if not isinstance(ownership, dict):
        errors.append("analysis ownership must be an object")
        ownership = {}
    owner_pid = integer(ownership.get("pid", pid), "analysis.ownership.pid", errors)
    owner_va = integer(
        ownership.get("virtual_address"), "analysis.ownership.virtual_address", errors)
    owner_pa = integer(
        ownership.get("physical_address"), "analysis.ownership.physical_address", errors)
    owner_pfn = integer(ownership.get("pfn"), "analysis.ownership.pfn", errors)
    owner_pte = integer(
        ownership.get("pte_address"), "analysis.ownership.pte_address", errors)
    owner_pte_value = integer(
        ownership.get("pte_value"), "analysis.ownership.pte_value", errors)
    result.update(pid=owner_pid, va=owner_va, pa=owner_pa, pfn=owner_pfn, pte=owner_pte)
    if owner_pid != pid:
        errors.append("analysis ownership PID does not match fixture PID")
    if owner_va != process_va:
        errors.append("analysis process VA does not match ownership target")
    if owner_va is not None and not 0 < owner_va < (1 << 47):
        errors.append("analysis ownership VA must be a canonical lower-half user address")
    if owner_va is not None and owner_va & 0xFFF:
        errors.append("analysis ownership VA must be 4 KiB aligned")
    if owner_pfn is not None and (owner_pfn <= 0 or owner_pfn > 0xFFFFFFFFFF):
        errors.append("analysis ownership PFN must fit the x64 40-bit PFN field")
    if owner_pfn is not None and owner_pfn == probe_pfn:
        errors.append("analysis ownership PFN must be distinct from the Probe transaction PFN")
    if owner_pfn is not None and owner_pa != owner_pfn << 12:
        errors.append("analysis ownership physical address does not equal PFN << 12")
    if owner_pte is not None and (
            owner_pte <= 0 or owner_pte > 0x000FFFFFFFFFFFF8 or owner_pte & 7):
        errors.append(
            "analysis ownership PTE must be a non-zero aligned x64 physical address")
    if (ownership.get("page_size") != 4096 or
            ownership.get("mapping_type") != "4 KiB page"):
        errors.append("analysis ownership must describe an exact 4 KiB mapping")
    for field in ("shared", "writable", "user_accessible", "no_execute"):
        if not isinstance(ownership.get(field), bool):
            errors.append(f"analysis ownership {field} must be boolean")
    if ownership.get("writable") is not True or ownership.get("user_accessible") is not True:
        errors.append("analysis ownership fixture mapping must be user-accessible and writable")
    if ownership.get("shared") is not False:
        errors.append("analysis dedicated fixture mapping must not be shared")
    for field in ("provider", "source"):
        if ownership.get(field) != "selected-process-page-table-scan":
            errors.append(
                f"analysis ownership {field} must be selected-process-page-table-scan")
    if ownership.get("confidence") != "high":
        errors.append("analysis ownership confidence must be high")
    generation = ownership.get("query_generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
        errors.append("analysis ownership query_generation must be positive")

    walk = data.get("page_table")
    if not isinstance(walk, dict):
        errors.append("analysis page_table must be an object")
        walk = {}
    walk_pid = integer(walk.get("pid"), "analysis.page_table.pid", errors)
    dtb = integer(
        walk.get("directory_table_base"), "analysis.page_table.directory_table_base", errors)
    walk_va = integer(walk.get("virtual_address"), "analysis.page_table.virtual_address", errors)
    walk_pa = integer(walk.get("physical_address"), "analysis.page_table.physical_address", errors)
    walk_pfn = integer(walk.get("pfn"), "analysis.page_table.pfn", errors)
    result["dtb"] = dtb
    x64_entry_address_mask = 0x000FFFFFFFFFF000
    if (dtb is not None and
            (dtb <= 0 or dtb & 0xFFF or dtb & ~x64_entry_address_mask)):
        errors.append(
            "analysis page-table directory-table base must be a valid aligned x64 address")
    if (walk_pid, walk_va, walk_pa, walk_pfn) != (owner_pid, owner_va, owner_pa, owner_pfn):
        errors.append("analysis page-table target does not match ownership target")
    if walk.get("translated") is not True or walk.get("page_size") != 4096:
        errors.append("analysis page-table walk must be a translated 4 KiB mapping")
    if walk.get("page_offset") != 0:
        errors.append("analysis page-table fixture offset must be zero")
    la57 = walk.get("la57")
    if not isinstance(la57, bool):
        errors.append("analysis page-table la57 must be boolean")
    for field in ("effective_writable", "effective_user", "effective_nx"):
        if not isinstance(walk.get(field), bool):
            errors.append(f"analysis page-table {field} must be boolean")
    if walk.get("effective_writable") is not True or walk.get("effective_user") is not True:
        errors.append("analysis page-table effective permissions must allow the user fixture")
    steps = walk.get("steps")
    expected_levels = list(PAGE_TABLE_LEVELS[1 if la57 is True else 0])
    if (not isinstance(steps, list) or
            [step.get("level") if isinstance(step, dict) else None for step in steps] != expected_levels):
        errors.append("analysis page-table steps are not the exact ordered x64 walk")
        steps = []
    shifts = {"PML5": 48, "PML4": 39, "PDPT": 30, "PD": 21, "PT": 12}
    previous_next_pfn: int | None = None
    for index, step in enumerate(steps):
        level = step.get("level")
        expected_index = ((owner_va or 0) >> shifts[str(level)]) & 0x1FF
        if step.get("index") != expected_index:
            errors.append(f"analysis page-table {level} index does not match VA")
        entry_pa = integer(
            step.get("entry_physical_address"),
            f"analysis.page_table.steps[{index}].entry_physical_address", errors)
        entry_value = integer(
            step.get("entry_value"),
            f"analysis.page_table.steps[{index}].entry_value", errors)
        next_pfn = integer(
            step.get("next_pfn"),
            f"analysis.page_table.steps[{index}].next_pfn", errors)
        for field, value in (("entry_physical_address", entry_pa),
                             ("entry_value", entry_value),
                             ("next_pfn", next_pfn)):
            if value is not None and value <= 0:
                errors.append(f"analysis page-table {level} {field} must be non-zero")
        if entry_pa is not None and entry_pa > 0x000FFFFFFFFFFFF8:
            errors.append(f"analysis page-table {level} entry address exceeds x64 physical width")
        if entry_value is not None and entry_value > 0xFFFFFFFFFFFFFFFF:
            errors.append(f"analysis page-table {level} entry value exceeds uint64")
        if next_pfn is not None and next_pfn > 0xFFFFFFFFFF:
            errors.append(f"analysis page-table {level} next PFN exceeds 40 bits")
        if entry_pa is not None and entry_pa & 7:
            errors.append(f"analysis page-table {level} entry address is not aligned")
        for field in ("present", "writable", "user", "page_size", "no_execute"):
            if not isinstance(step.get(field), bool):
                errors.append(f"analysis page-table {level} {field} must be boolean")
        if step.get("present") is not True:
            errors.append(f"analysis page-table {level} is not present")
        if entry_value is not None:
            decoded = {
                "present": bool(entry_value & 0x1),
                "writable": bool(entry_value & 0x2),
                "user": bool(entry_value & 0x4),
                "page_size": bool(entry_value & 0x80),
                "no_execute": bool(entry_value & (1 << 63)),
            }
            for field, expected in decoded.items():
                if step.get(field) != expected:
                    errors.append(
                        f"analysis page-table {level} {field} does not match entry_value")
            decoded_pfn = (entry_value & x64_entry_address_mask) >> 12
            if next_pfn != decoded_pfn:
                errors.append(
                    f"analysis page-table {level} next_pfn does not match entry_value")
        if step.get("page_size") is not False:
            errors.append(
                f"analysis page-table {level} sets PS for an exact 4 KiB walk")
        expected_entry_pa = None
        if index == 0 and dtb is not None:
            expected_entry_pa = (dtb & x64_entry_address_mask) + expected_index * 8
        elif previous_next_pfn is not None:
            expected_entry_pa = (previous_next_pfn << 12) + expected_index * 8
        if expected_entry_pa is not None and entry_pa != expected_entry_pa:
            errors.append(
                f"analysis page-table {level} entry address breaks the x64 walk chain")
        previous_next_pfn = next_pfn
    if steps:
        leaf = steps[-1]
        if integer(leaf.get("entry_physical_address"), "analysis leaf PTE", []) != owner_pte:
            errors.append("analysis page-table leaf entry does not match ownership PTE")
        if integer(leaf.get("entry_value"), "analysis leaf PTE value", []) != owner_pte_value:
            errors.append("analysis page-table leaf value does not match ownership PTE value")
        if integer(leaf.get("next_pfn"), "analysis leaf PFN", []) != owner_pfn:
            errors.append("analysis page-table leaf PFN does not match ownership PFN")
        effective_writable = all(step.get("writable") is True for step in steps)
        effective_user = all(step.get("user") is True for step in steps)
        effective_nx = any(step.get("no_execute") is True for step in steps)
        if (walk.get("effective_writable"), walk.get("effective_user"),
                walk.get("effective_nx")) != (
                    effective_writable, effective_user, effective_nx):
            errors.append("analysis effective page permissions do not match walk steps")
        if ((ownership.get("writable"), ownership.get("user_accessible"),
             ownership.get("no_execute")) !=
                (effective_writable, effective_user, effective_nx)):
            errors.append(
                "analysis ownership permissions do not match the complete page walk")

    revalidation = data.get("revalidation")
    if not isinstance(revalidation, dict):
        errors.append("analysis revalidation must be an object")
        revalidation = {}
    for field in ("process_identity_unchanged", "dtb_unchanged", "walk_unchanged"):
        if revalidation.get(field) is not True:
            errors.append(f"analysis revalidation failed: {field}")
    if (integer(revalidation.get("process_start_id_before"),
                "process_start_id_before", errors) != process_start or
            integer(revalidation.get("process_start_id_after"),
                    "process_start_id_after", errors) != process_start):
        errors.append("analysis process identity token changed during revalidation")
    if (integer(revalidation.get("dtb_before"), "dtb_before", errors) != dtb or
            integer(revalidation.get("dtb_after"), "dtb_after", errors) != dtb):
        errors.append("analysis directory-table base changed during revalidation")
    if (integer(revalidation.get("translated_before_pa"), "translated_before_pa", errors) != owner_pa or
            integer(revalidation.get("translated_after_pa"), "translated_after_pa", errors) != owner_pa):
        errors.append("analysis translated PA changed during revalidation")

    page_files = data.get("page_files")
    page_hashes = data.get("page_sha256")
    if not isinstance(page_files, dict) or not isinstance(page_hashes, dict):
        errors.append("analysis page_files/page_sha256 must be objects")
    else:
        pages: list[Path] = []
        process_page_bytes: bytes | None = None
        for field in ("process_read", "physical_read"):
            require_sha(page_hashes.get(field), f"analysis.page_sha256.{field}", errors)
            artifact = _safe_evidence_file(path.parent, page_files.get(field),
                                           f"analysis {field} page", errors)
            if artifact is not None:
                pages.append(artifact)
                if artifact.stat().st_size != 4096:
                    errors.append(f"analysis {field} page must be exactly 4096 bytes")
                elif sha256(artifact) != page_hashes.get(field):
                    errors.append(f"analysis {field} page hash mismatch")
                elif field == "process_read":
                    process_page_bytes = artifact.read_bytes()
        if len(pages) == 2 and pages[0].resolve() == pages[1].resolve():
            errors.append(
                "analysis process and physical reads must be distinct sibling files")
        if len(pages) == 2 and pages[0].read_bytes() != pages[1].read_bytes():
            errors.append("analysis process and physical 4 KiB pages do not match")
        if process_page_bytes is not None:
            current_crc = f"{zlib.crc32(process_page_bytes) & 0xFFFFFFFF:08x}"
            if process.get("current_crc32") != current_crc:
                errors.append(
                    "analysis fixture current CRC32 does not match process-read page")
    if data.get("page_bytes") != 4096 or data.get("page_match") is not True:
        errors.append("analysis physical mapping read contract did not pass")

    kernel = data.get("kernel_explorer")
    if not isinstance(kernel, dict):
        errors.append("analysis kernel_explorer must be an object")
        kernel = {}
    module = kernel.get("module")
    if not isinstance(module, dict):
        errors.append("analysis kernel module proof must be an object")
        module = {}
    module_name = module.get("name")
    if (not isinstance(module_name, str) or not module_name or
            module_name != Path(module_name).name or PRIVATE_PATH_RE.search(module_name)):
        errors.append("analysis kernel module name must be a safe basename")
    driver_provenance = {
        "KDbgDriver.sys": ("drivers/KDbgDriver.sys", "drivers/KDbgDriver.pdb"),
        "KDbgProbe.sys": ("drivers/KDbgProbe.sys", "drivers/KDbgProbe.pdb"),
    }
    provenance = driver_provenance.get(module_name)
    if provenance is None:
        errors.append(
            "analysis kernel module must be KDbgDriver.sys or KDbgProbe.sys")
    else:
        image_relative, pdb_relative = provenance
        if module.get("package_relative_path") != image_relative:
            errors.append("analysis kernel module package-relative path is invalid")
        require_sha(module.get("image_sha256"),
                    "analysis.kernel.module.image_sha256", errors)
        packaged_image = package / PurePosixPath(image_relative)
        if (packaged_image.is_file() and
                module.get("image_sha256") != sha256(packaged_image)):
            errors.append(
                "analysis kernel module image hash does not match the package")
    module_base = integer(module.get("base"), "analysis.kernel.module.base", errors)
    module_size = integer(module.get("size"), "analysis.kernel.module.size", errors)
    if module.get("machine") != 0x8664:
        errors.append("analysis kernel module machine must be x64 0x8664")
    if module_base is not None and module_base < 0xFFFF800000000000:
        errors.append("analysis kernel module base must be canonical high-half")
    if module_size is not None and not 1 <= module_size <= 0x40000000:
        errors.append("analysis kernel module size is invalid")
    if (module_base is not None and module_size is not None and
            module_base + module_size > (1 << 64)):
        errors.append("analysis kernel module range overflows uint64")
    for field in ("pe_timestamp", "image_size"):
        value = module.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"analysis kernel module {field} must be positive")
    if module_size is not None and module.get("image_size") != module_size:
        errors.append("analysis live PE image size does not match selected module size")
    header_bytes = module.get("header_bytes")
    if (not isinstance(header_bytes, int) or isinstance(header_bytes, bool) or
            not 256 <= header_bytes <= 4096):
        errors.append("analysis kernel PE header length must be 256-4096 bytes")
    header_paths: dict[str, Path] = {}
    for prefix in ("live", "local"):
        require_sha(module.get(f"{prefix}_header_sha256"),
                    f"analysis.kernel.module.{prefix}_header_sha256", errors)
        header = _safe_evidence_file(
            path.parent, module.get(f"{prefix}_header_file"),
            f"analysis kernel {prefix} header", errors)
        if header is not None:
            header_paths[prefix] = header
            if header.stat().st_size != header_bytes:
                errors.append(
                    f"analysis kernel {prefix} header length does not match header_bytes")
            elif sha256(header) != module.get(f"{prefix}_header_sha256"):
                errors.append(f"analysis kernel {prefix} header hash mismatch")
    if module.get("headers_match") is not True:
        errors.append("analysis live/local kernel PE headers did not pass comparison")
    if module.get("header_match_mode") != "exact-except-loader-image-base":
        errors.append(
            "analysis kernel header match mode must account only for loader ImageBase")
    image_base_offset = integer(
        module.get("image_base_offset"),
        "analysis.kernel.module.image_base_offset", errors)
    live_image_base = integer(
        module.get("live_image_base"),
        "analysis.kernel.module.live_image_base", errors)
    local_preferred_image_base = integer(
        module.get("local_preferred_image_base"),
        "analysis.kernel.module.local_preferred_image_base", errors)
    if provenance is not None and "local" in header_paths:
        packaged_image = package / PurePosixPath(provenance[0])
        local_header = header_paths["local"].read_bytes()
        if (packaged_image.is_file() and
                packaged_image.read_bytes()[:len(local_header)] != local_header):
            errors.append(
                "analysis local kernel header does not match the packaged driver image")
    if "live" in header_paths and "local" in header_paths:
        live_header = header_paths["live"].read_bytes()
        local_header = header_paths["local"].read_bytes()
        try:
            def parse_header(value: bytes, label: str) -> tuple[int, ...]:
                if value[:2] != b"MZ" or len(value) < 64:
                    raise ValueError(f"{label} is missing the DOS header")
                pe_offset = struct.unpack_from("<I", value, 0x3C)[0]
                if (pe_offset + 24 > len(value) or
                        value[pe_offset:pe_offset + 4] != b"PE\0\0"):
                    raise ValueError(f"{label} is missing the PE header")
                section_count = struct.unpack_from("<H", value, pe_offset + 6)[0]
                machine = struct.unpack_from("<H", value, pe_offset + 4)[0]
                timestamp = struct.unpack_from("<I", value, pe_offset + 8)[0]
                optional_size = struct.unpack_from("<H", value, pe_offset + 20)[0]
                optional_offset = pe_offset + 24
                if (optional_size < 68 or optional_offset + optional_size > len(value) or
                        struct.unpack_from("<H", value, optional_offset)[0] != 0x20B):
                    raise ValueError(f"{label} has an invalid PE32+ optional header")
                section_table_end = (
                    optional_offset + optional_size + section_count * 40)
                image_size = struct.unpack_from(
                    "<I", value, optional_offset + 56)[0]
                size_of_headers = struct.unpack_from(
                    "<I", value, optional_offset + 60)[0]
                if (size_of_headers != len(value) or
                        section_table_end > size_of_headers):
                    raise ValueError(
                        f"{label} SizeOfHeaders does not cover the section table")
                runtime_image_base_offset = optional_offset + 24
                preferred_base = struct.unpack_from(
                    "<Q", value, runtime_image_base_offset)[0]
                return (pe_offset, machine, timestamp, image_size,
                        runtime_image_base_offset, preferred_base)

            live_values = parse_header(live_header, "live header")
            local_values = parse_header(local_header, "local header")
            if live_values[:5] != local_values[:5]:
                raise ValueError("live/local PE structural metadata differs")
            actual_image_base_offset = live_values[4]
            if (image_base_offset != actual_image_base_offset or
                    live_image_base != live_values[5] or
                    local_preferred_image_base != local_values[5]):
                raise ValueError("ImageBase metadata does not match the captured headers")
            if module_base is not None and live_values[5] != module_base:
                raise ValueError("live ImageBase does not match the selected module base")
            if ((live_values[1], live_values[2], live_values[3]) !=
                    (module.get("machine"), module.get("pe_timestamp"),
                     module.get("image_size"))):
                raise ValueError(
                    "machine/timestamp/image-size metadata does not match the PE header")
            normalized_live = bytearray(live_header)
            normalized_local = bytearray(local_header)
            normalized_live[actual_image_base_offset:actual_image_base_offset + 8] = b"\0" * 8
            normalized_local[actual_image_base_offset:actual_image_base_offset + 8] = b"\0" * 8
            if normalized_live != normalized_local:
                raise ValueError(
                    "live/local bytes differ beyond the loader-applied ImageBase")
        except (ValueError, struct.error) as exc:
            errors.append(f"analysis kernel PE header identity is invalid: {exc}")

    symbol = kernel.get("symbol")
    if not isinstance(symbol, dict):
        errors.append("analysis kernel symbol proof must be an object")
        symbol = {}
    pdb_name = symbol.get("pdb_name")
    if (not isinstance(pdb_name, str) or not pdb_name.lower().endswith(".pdb") or
            pdb_name != Path(pdb_name).name or PRIVATE_PATH_RE.search(pdb_name)):
        errors.append("analysis PDB name must be a safe basename")
    pdb_file_name = symbol.get("pdb_file")
    if (isinstance(pdb_name, str) and isinstance(pdb_file_name, str) and
            pdb_name != Path(pdb_file_name).name):
        errors.append("analysis PDB name does not match the evidence PDB filename")
    require_sha(symbol.get("pdb_sha256"), "analysis.kernel.symbol.pdb_sha256", errors)
    pdb_file = _safe_evidence_file(
        path.parent, symbol.get("pdb_file"), "analysis kernel PDB", errors)
    if pdb_file is not None and sha256(pdb_file) != symbol.get("pdb_sha256"):
        errors.append("analysis kernel PDB hash mismatch")
    if provenance is not None:
        _image_relative, pdb_relative = provenance
        if symbol.get("package_relative_path") != pdb_relative:
            errors.append("analysis kernel PDB package-relative path is invalid")
        packaged_pdb = symbols / PurePosixPath(pdb_relative) if symbols else None
        if (packaged_pdb is not None and packaged_pdb.is_file() and
                symbol.get("pdb_sha256") != sha256(packaged_pdb)):
            errors.append(
                "analysis kernel PDB hash does not match the symbols package")
    guid_re = r"[0-9a-f]{32}"
    if (not isinstance(symbol.get("pe_guid"), str) or
            not re.fullmatch(guid_re, symbol["pe_guid"])):
        errors.append("analysis PE CodeView GUID must be lowercase hex")
    if (symbol.get("pdb_guid") != symbol.get("pe_guid") or
            symbol.get("pdb_age") != symbol.get("pe_age") or
            not isinstance(symbol.get("pe_age"), int) or symbol.get("pe_age", 0) <= 0 or
            symbol.get("exact_match") is not True):
        errors.append("analysis PDB GUID+age does not exactly match the PE CodeView record")
    symbol_address = integer(
        symbol.get("symbol_address"), "analysis.kernel.symbol.symbol_address", errors)
    displacement = integer(
        symbol.get("displacement"), "analysis.kernel.symbol.displacement", errors)
    if displacement is not None and not 0 <= displacement <= 0xFFFFFFFF:
        errors.append("analysis kernel symbol displacement is invalid")
    if (module_base is not None and module_size is not None and symbol_address is not None and
            not module_base <= symbol_address < module_base + module_size):
        errors.append("analysis resolved symbol is outside the selected module")
    symbol_name = symbol.get("symbol_name")
    if (not isinstance(symbol_name, str) or not symbol_name.strip() or
            PRIVATE_PATH_RE.search(symbol_name)):
        errors.append("analysis resolved symbol name is missing or unsafe")

    read = kernel.get("read")
    if not isinstance(read, dict):
        errors.append("analysis kernel read proof must be an object")
        read = {}
    read_address = integer(read.get("address"), "analysis.kernel.read.address", errors)
    if (symbol_address is not None and displacement is not None and
            read_address != symbol_address + displacement):
        errors.append(
            "analysis kernel read address does not match symbol plus displacement")
    requested = read.get("requested_bytes")
    completed = read.get("completed_bytes")
    if (not isinstance(requested, int) or isinstance(requested, bool) or
            not 1 <= requested <= 1024 * 1024 or completed != requested):
        errors.append("analysis kernel read must be exact and bounded to 1 MiB")
    if (module_base is not None and module_size is not None and
            isinstance(read_address, int) and isinstance(completed, int) and
            not (module_base <= read_address and read_address + completed <= module_base + module_size)):
        errors.append("analysis kernel read is outside the selected module")
    require_sha(read.get("sha256"), "analysis.kernel.read.sha256", errors)
    read_file = _safe_evidence_file(
        path.parent, read.get("file"), "analysis kernel read file", errors)
    if read_file is not None and isinstance(completed, int):
        if read_file.stat().st_size != completed:
            errors.append("analysis kernel read file length does not match completed bytes")
        elif sha256(read_file) != read.get("sha256"):
            errors.append("analysis kernel read file hash mismatch")

    disassembly = kernel.get("disassembly")
    if not isinstance(disassembly, dict):
        errors.append("analysis kernel disassembly proof must be an object")
        disassembly = {}
    consumed = disassembly.get("consumed_bytes")
    instructions = disassembly.get("instruction_count")
    if (disassembly.get("architecture") != "x64" or
            disassembly.get("formatter") != "intel" or
            integer(disassembly.get("start_address"), "analysis disassembly address", errors) != read_address or
            not isinstance(consumed, int) or isinstance(consumed, bool) or
            not isinstance(completed, int) or not 1 <= consumed <= completed or
            not isinstance(instructions, int) or isinstance(instructions, bool) or
            not 1 <= instructions <= consumed or
            not isinstance(disassembly.get("truncated"), bool)):
        errors.append("analysis kernel disassembly is not a bounded exact x64/Intel decode")
    return result


def validate_live(
    path: Path,
    package: Path | None,
    symbols: Path | None,
    errors: list[str],
) -> None:
    evidence = load_json(path, "live evidence JSON", errors)
    if evidence is None:
        return
    if package is None:
        errors.append("--live-evidence requires --windows-package")
        return
    if symbols is None:
        errors.append("--live-evidence requires --symbols-package")
    if evidence.get("schema") != "kdbg.live-evidence.v4":
        errors.append("live evidence schema must be kdbg.live-evidence.v4")
    evidence_abi = evidence.get("abi_version")
    if (evidence.get("package_version") != VERSION or
            evidence_abi not in {6, 7}):
        errors.append("live evidence product or ABI version mismatch")
    timestamp: datetime | None = None
    try:
        timestamp = datetime.fromisoformat(str(evidence.get("timestamp_utc", "")).replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
            raise ValueError("not UTC")
        if timestamp.timestamp() > datetime.now(timezone.utc).timestamp() + 300:
            raise ValueError("timestamp is in the future")
    except ValueError as exc:
        errors.append(f"invalid live evidence timestamp_utc: {exc}")
    os_build = evidence.get("os_build")
    if (not isinstance(os_build, int) or isinstance(os_build, bool) or
            os_build < MIN_WINDOWS_BUILD):
        errors.append(
            f"live evidence os_build must be an integer at least {MIN_WINDOWS_BUILD}")
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
                  "package_manifest_sha256", "symbols_manifest_sha256",
                   "gui_metadata_sha256", "command_log_sha256", "video_sha256",
                   "scene_review_sha256", "live_run_report_sha256",
                   "analysis_metadata_sha256"):
        require_sha(evidence.get(field), field, errors)
    expected = evidence.get("expected_after_sha256")
    if evidence.get("readback_sha256") != expected:
        errors.append("readback hash does not match expected-after hash")
    if evidence.get("independent_reload_sha256") != expected:
        errors.append("reload hash does not match expected-after hash")
    if evidence.get("rollback_sha256") != evidence.get("baseline_sha256"):
        errors.append("rollback hash does not match baseline hash")
    if evidence.get("edit_xor_mask") != PROBE_EDIT_MASK.hex():
        errors.append("live evidence edit_xor_mask does not match the Probe contract")
    artifacts = evidence.get("artifact_sha256")
    required_artifacts = (
        "KDBG.exe", "plugins/memprocfs_bridge/kdbg_memprocfs_bridge.exe",
        "tools/kdbg_live_verify.exe", "tools/kdbg_process_fixture.exe",
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
    package_manifest = package / "SHA256SUMS.txt"
    if (package_manifest.is_file() and
            evidence.get("package_manifest_sha256") != sha256(package_manifest)):
        errors.append("live evidence main-package manifest hash mismatch")
    symbol_hashes = evidence.get("symbol_sha256")
    if not isinstance(symbol_hashes, dict):
        errors.append("live evidence symbol_sha256 must be an object")
    else:
        for relative in SYMBOLS_REQUIRED:
            value = symbol_hashes.get(relative)
            require_sha(value, f"symbol_sha256.{relative}", errors)
            if symbols is not None:
                artifact = symbols / PurePosixPath(relative)
                if (artifact.is_file() and isinstance(value, str) and
                        value != sha256(artifact)):
                    errors.append(f"live evidence symbol hash mismatch: {relative}")
    if symbols is not None:
        symbols_manifest = symbols / "SHA256SUMS.txt"
        if (symbols_manifest.is_file() and
                evidence.get("symbols_manifest_sha256") != sha256(symbols_manifest)):
            errors.append("live evidence symbols-package manifest hash mismatch")
    for field in ("probe_generation_before", "probe_generation_after_write",
                  "probe_generation_after_rollback"):
        value = integer(evidence.get(field), field, errors)
        if value is not None and not 1 <= value <= 0xFFFFFFFF:
            errors.append(f"live evidence {field} must be a non-zero uint32")
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
    analysis_values: dict[str, int | None] = {
        "pid": None, "process_start_id": None, "va": None, "pa": None,
        "pfn": None, "pte": None, "dtb": None,
    }
    scenes = evidence.get("demo_scenes")
    if not isinstance(scenes, list) or not all(isinstance(scene, str) for scene in scenes):
        errors.append("demo_scenes must be an array of strings")
    elif scenes != list(DEMO_SCENE_ORDER):
        errors.append("demo_scenes must contain every required scene exactly once and in order")
    raw_page_fields = (
        ("baseline_file", "baseline_sha256"),
        ("preflight_file", "baseline_sha256"),
        ("expected_after_file", "expected_after_sha256"),
        ("readback_file", "readback_sha256"),
        ("independent_reload_file", "independent_reload_sha256"),
        ("rollback_file", "rollback_sha256"),
    )
    raw_pages: dict[str, Path] = {}
    referenced_names: set[str] = set()
    for file_field, hash_field in raw_page_fields:
        relative = evidence.get(file_field)
        if not isinstance(relative, str) or safe_relative(relative) is None or "/" in relative or "\\" in relative:
            errors.append(f"{file_field} must be a safe sibling filename")
            continue
        name_key = relative.casefold()
        if name_key == path.name.casefold() or name_key in referenced_names:
            errors.append(f"{file_field} must reference a distinct non-output sibling file")
            continue
        referenced_names.add(name_key)
        artifact = path.parent / relative
        raw_pages[file_field] = artifact
        if artifact.is_symlink():
            errors.append(f"raw page evidence must not be a symbolic link: {artifact}")
        elif not artifact.is_file() or artifact.stat().st_size != 4096:
            errors.append(f"raw page evidence must be exactly 4096 bytes: {artifact}")
        elif sha256(artifact) != evidence.get(hash_field):
            errors.append(f"raw page evidence hash mismatch: {artifact}")

    if all(
        field in raw_pages and not raw_pages[field].is_symlink() and
        raw_pages[field].is_file() and
        raw_pages[field].stat().st_size == 4096
        for field, _ in raw_page_fields
    ):
        baseline_bytes = raw_pages["baseline_file"].read_bytes()
        preflight_bytes = raw_pages["preflight_file"].read_bytes()
        expected_bytes = raw_pages["expected_after_file"].read_bytes()
        readback_bytes = raw_pages["readback_file"].read_bytes()
        reload_bytes = raw_pages["independent_reload_file"].read_bytes()
        rollback_bytes = raw_pages["rollback_file"].read_bytes()
        if preflight_bytes != baseline_bytes:
            errors.append("raw preflight page does not exactly equal baseline")
        if readback_bytes != expected_bytes or reload_bytes != expected_bytes:
            errors.append("raw read-back/reload pages do not exactly equal expected-after")
        if rollback_bytes != baseline_bytes:
            errors.append("raw rollback page does not exactly equal baseline")
        actual_mask = bytes(
            baseline_bytes[PROBE_EDIT_OFFSET + index] ^
            expected_bytes[PROBE_EDIT_OFFSET + index]
            for index in range(len(PROBE_EDIT_MASK))
        )
        outside_changed = any(
            before != after
            for index, (before, after) in enumerate(zip(baseline_bytes, expected_bytes))
            if not PROBE_EDIT_OFFSET <= index < PROBE_EDIT_OFFSET + len(PROBE_EDIT_MASK)
        )
        if actual_mask != PROBE_EDIT_MASK or outside_changed:
            errors.append(
                "raw baseline-to-expected bytes do not match the exact Probe 8-byte XOR pattern")

        page_crc_bindings = (
            ("probe_crc32_before", baseline_bytes),
            ("probe_crc32_after_write", expected_bytes),
            ("probe_crc32_after_rollback", rollback_bytes),
        )
        for field, page_bytes in page_crc_bindings:
            value = evidence.get(field)
            if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", value):
                if int(value, 16) != zlib.crc32(page_bytes) & 0xFFFFFFFF:
                    errors.append(f"{field} does not match its raw page CRC32")

    artifact_paths: dict[str, Path] = {}
    for file_field, hash_field in (("gui_metadata_file", "gui_metadata_sha256"),
                                   ("analysis_metadata_file", "analysis_metadata_sha256"),
                                   ("command_log_file", "command_log_sha256"),
                                   ("video_file", "video_sha256"),
                                   ("scene_review_file", "scene_review_sha256"),
                                   ("live_run_report_file", "live_run_report_sha256")):
        relative = evidence.get(file_field)
        if not isinstance(relative, str) or safe_relative(relative) is None or "/" in relative or "\\" in relative:
            errors.append(f"{file_field} must be a safe sibling filename")
            continue
        name_key = relative.casefold()
        if name_key == path.name.casefold() or name_key in referenced_names:
            errors.append(f"{file_field} must reference a distinct non-output sibling file")
            continue
        referenced_names.add(name_key)
        artifact = path.parent / relative
        artifact_paths[file_field] = artifact
        if artifact.is_symlink():
            errors.append(f"evidence artifact must not be a symbolic link: {artifact}")
        elif not artifact.is_file() or artifact.stat().st_size == 0:
            errors.append(f"evidence artifact missing or empty: {artifact}")
        elif sha256(artifact) != evidence.get(hash_field):
            errors.append(f"evidence artifact hash mismatch: {artifact}")

    analysis_path = artifact_paths.get("analysis_metadata_file")
    if (analysis_path is not None and not analysis_path.is_symlink() and
            analysis_path.is_file() and analysis_path.stat().st_size > 0):
        analysis_values = validate_analysis_metadata(
            analysis_path, package, symbols, timestamp, pfn,
            evidence_abi if evidence_abi in {6, 7} else None, errors)

    gui_metadata: dict | None = None
    gui_path = artifact_paths.get("gui_metadata_file")
    if (gui_path is not None and not gui_path.is_symlink() and
            gui_path.is_file() and gui_path.stat().st_size > 0):
        gui_metadata = load_json(gui_path, "referenced GUI metadata", errors)
        if gui_metadata is not None:
            try:
                gui_timestamp = parse_gui_utc_timestamp(
                    gui_metadata.get("timestamp_utc", ""))
                if timestamp is not None and gui_timestamp > timestamp:
                    errors.append("GUI metadata timestamp is later than final evidence")
            except ValueError as exc:
                errors.append(f"invalid GUI metadata timestamp_utc: {exc}")
            if (gui_metadata.get("schema") != "kdbg-physical-live-evidence-v1" or
                    gui_metadata.get("page_size") != 4096 or
                    gui_metadata.get("driver_abi_version") != evidence_abi or
                    gui_metadata.get("edit_offset") != PROBE_EDIT_OFFSET or
                    gui_metadata.get("edit_length") != len(PROBE_EDIT_MASK) or
                    gui_metadata.get("edit_xor_mask") != PROBE_EDIT_MASK.hex() or
                    gui_metadata.get("dirty_runs") != evidence.get("dirty_runs")):
                errors.append("GUI metadata does not match the exact v4 Probe transaction")
            for field in (
                "write_gate_relocked", "preflight_match", "full_readback_match",
                "independent_reload_match", "rollback_match",
            ):
                if gui_metadata.get(field) is not True:
                    errors.append(f"GUI metadata field is not true: {field}")
            gui_pfn = integer(gui_metadata.get("pfn"), "gui_metadata.pfn", errors)
            gui_pa = integer(
                gui_metadata.get("physical_address"),
                "gui_metadata.physical_address", errors)
            if gui_pfn != pfn or gui_pa != physical:
                errors.append("GUI metadata PFN/PA does not match final evidence")
            page_files = gui_metadata.get("page_files")
            expected_page_files = {
                "baseline": evidence.get("baseline_file"),
                "preflight": evidence.get("preflight_file"),
                "expected_after": evidence.get("expected_after_file"),
                "readback": evidence.get("readback_file"),
                "independent_reload": evidence.get("independent_reload_file"),
                "rollback": evidence.get("rollback_file"),
            }
            if page_files != expected_page_files:
                errors.append("GUI metadata page files do not match final evidence")
            gui_probe = gui_metadata.get("probe")
            if not isinstance(gui_probe, dict):
                errors.append("GUI metadata Probe records are missing")
            else:
                gui_probe_bindings = (
                    ("baseline", "probe_generation_before", "probe_crc32_before"),
                    ("after_write", "probe_generation_after_write", "probe_crc32_after_write"),
                    ("after_reload", "probe_generation_after_write", "probe_crc32_after_write"),
                    ("after_rollback", "probe_generation_after_rollback", "probe_crc32_after_rollback"),
                )
                gui_probe_virtual_addresses: list[int] = []
                for probe_name, generation_field, crc_field in gui_probe_bindings:
                    record = gui_probe.get(probe_name)
                    if not isinstance(record, dict):
                        errors.append(f"GUI metadata Probe record is missing: {probe_name}")
                        continue
                    record_va = integer(
                        record.get("virtual_address"),
                        f"gui_probe.{probe_name}.virtual_address", errors)
                    if isinstance(record_va, int):
                        gui_probe_virtual_addresses.append(record_va)
                    if (integer(record.get("pfn"), f"gui_probe.{probe_name}.pfn", errors) != pfn or
                            integer(record.get("physical_address"),
                                    f"gui_probe.{probe_name}.physical_address", errors) != physical or
                            record.get("byte_count") != 4096 or
                            record.get("generation") != evidence.get(generation_field)):
                        errors.append(
                            f"GUI metadata Probe identity does not match evidence: {probe_name}")
                    crc_text = record.get("crc32")
                    if (not isinstance(crc_text, str) or
                            crc_text.casefold() != evidence.get(crc_field)):
                        errors.append(
                            f"GUI metadata Probe CRC does not match evidence: {probe_name}")
                if (len(gui_probe_virtual_addresses) != 4 or
                        len(set(gui_probe_virtual_addresses)) != 1):
                    errors.append("GUI metadata Probe virtual address changed between stages")
                elif gui_probe_virtual_addresses[0] == analysis_values.get("va"):
                    errors.append(
                        "analysis ownership VA must be distinct from the Probe virtual address")

    parsed_media: dict[str, int | str] | None = None
    video = artifact_paths.get("video_file")
    if (video is not None and not video.is_symlink() and
            video.is_file() and video.stat().st_size > 0):
        media = evidence.get("video_media")
        if not isinstance(media, dict):
            errors.append("video_media must be an object")
        try:
            parsed_media = parse_gif(video)
        except (OSError, ValueError, struct.error) as exc:
            errors.append(f"video_file is not a valid evidence GIF: {exc}")
        else:
            if media != parsed_media:
                errors.append("video_media does not match the parsed GIF container")

    scene_review = artifact_paths.get("scene_review_file")
    if (scene_review is not None and not scene_review.is_symlink() and
            scene_review.is_file() and scene_review.stat().st_size > 0 and
            parsed_media is not None and video is not None):
        review_scenes = validate_scene_review(
            scene_review,
            video.name,
            evidence.get("video_sha256", ""),
            int(parsed_media["duration_ms"]),
            timestamp,
            errors,
        )
        if isinstance(scenes, list) and review_scenes != scenes:
            errors.append("demo_scenes do not match the hash-bound scene review")

    live_run_path = artifact_paths.get("live_run_report_file")
    if live_run_path is not None and not live_run_path.is_symlink():
        if live_run_path.is_file():
            validate_live_run(live_run_path, errors)
            live_run = load_json(live_run_path, "referenced live run report", errors)
            if live_run is not None:
                runtime_artifacts = validate_runtime_identity(live_run, [])
                if isinstance(artifacts, dict):
                    for relative, digest in runtime_artifacts.items():
                        if artifacts.get(relative) != digest:
                            errors.append(
                                "live runtime identity hash does not match "
                                f"packaged artifact: {relative}")
                before = live_run.get("probe_before")
                if (live_run.get("mode") != "probe-write-rollback" or
                        not isinstance(before, dict) or
                        integer(before.get("pfn"), "live_run.probe_before.pfn", errors) != pfn):
                    errors.append("final evidence and live run Probe PFN/mode do not match")
                live_backend = live_run.get("backend")
                if (not isinstance(live_backend, dict) or
                        live_backend.get("abi_version") != evidence_abi):
                    errors.append("final evidence ABI does not match the live run")
                system = live_run.get("system")
                if (not isinstance(system, dict) or
                        system.get("os_build") != evidence.get("os_build")):
                    errors.append("final evidence os_build does not match the live run")
                if isinstance(system, dict):
                    try:
                        generated = datetime.fromisoformat(
                            str(system.get("generated_utc", "")).replace("Z", "+00:00"))
                        if (generated.tzinfo is None or
                                generated.utcoffset() != timezone.utc.utcoffset(generated)):
                            raise ValueError("not UTC")
                        if timestamp is not None and generated > timestamp:
                            errors.append("live run timestamp is later than final evidence")
                    except ValueError as exc:
                        errors.append(f"invalid live run generated_utc binding: {exc}")
                probe_bindings = (
                    ("probe_before", "probe_generation_before", "probe_crc32_before"),
                    ("probe_after_write", "probe_generation_after_write", "probe_crc32_after_write"),
                    ("probe_after_rollback", "probe_generation_after_rollback", "probe_crc32_after_rollback"),
                )
                probe_virtual_addresses: list[int] = []
                for probe_name, generation_field, crc_field in probe_bindings:
                    probe_record = live_run.get(probe_name)
                    if not isinstance(probe_record, dict):
                        errors.append(f"cannot bind evidence to live run {probe_name}")
                        continue
                    if (probe_record.get("pfn") != pfn or
                            probe_record.get("physical_address") != physical):
                        errors.append(
                            f"final evidence PFN/PA does not match live run {probe_name}")
                    if probe_record.get("generation") != evidence.get(generation_field):
                        errors.append(
                            f"final evidence {generation_field} does not match live run")
                    crc_text = evidence.get(crc_field)
                    crc_value = (
                        int(crc_text, 16)
                        if isinstance(crc_text, str) and
                        re.fullmatch(r"0x[0-9a-fA-F]{8}", crc_text)
                        else None
                    )
                    if probe_record.get("crc32") != crc_value:
                        errors.append(
                            f"final evidence {crc_field} does not match live run")
                    virtual_address = probe_record.get("virtual_address")
                    if isinstance(virtual_address, int) and not isinstance(virtual_address, bool):
                        probe_virtual_addresses.append(virtual_address)
                if (len(probe_virtual_addresses) != 3 or
                        len(set(probe_virtual_addresses)) != 1):
                    errors.append("live run Probe virtual address changed between stages")
                else:
                    if analysis_values.get("va") == probe_virtual_addresses[0]:
                        errors.append(
                            "analysis ownership VA must be distinct from the live Probe virtual address")
                cleanup = live_run.get("write_cleanup")
                if (not isinstance(cleanup, dict) or
                        cleanup.get("edit_offset") != 0x100 or
                        cleanup.get("edit_length") != 8 or
                        evidence.get("dirty_runs") != [{"offset": 0x100, "length": 8}]):
                    errors.append("final evidence and live run edit range do not match")
                comparisons = live_run.get("comparisons")
                by_name = {
                    item.get("name"): item
                    for item in comparisons
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                } if isinstance(comparisons, list) else {}
                bindings = (
                    ("baseline_vs_preflight", "baseline_file", "preflight_file"),
                    ("expected_vs_write_readback", "expected_after_file", "readback_file"),
                    ("expected_vs_independent_reload", "expected_after_file", "independent_reload_file"),
                    ("baseline_vs_rollback_readback", "baseline_file", "rollback_file"),
                )
                for comparison_name, expected_field, actual_field in bindings:
                    comparison = by_name.get(comparison_name)
                    expected_path = raw_pages.get(expected_field)
                    actual_path = raw_pages.get(actual_field)
                    if (not isinstance(comparison, dict) or
                            expected_path is None or actual_path is None or
                            expected_path.is_symlink() or actual_path.is_symlink() or
                            not expected_path.is_file() or not actual_path.is_file()):
                        errors.append(
                            f"cannot bind raw pages to live comparison: {comparison_name}")
                        continue
                    expected_crc = zlib.crc32(expected_path.read_bytes()) & 0xFFFFFFFF
                    actual_crc = zlib.crc32(actual_path.read_bytes()) & 0xFFFFFFFF
                    if (comparison.get("expected_crc32") != expected_crc or
                            comparison.get("actual_crc32") != actual_crc):
                        errors.append(
                            f"raw page CRC does not match live comparison: {comparison_name}")


def validate_live_run(path: Path, errors: list[str]) -> None:
    """Validate the machine-readable result emitted by kdbg_live_verify.

    This is the controlled write/read-back/rollback run record, not the final
    conference evidence bundle (which additionally requires video, hashes,
    ownership, and page-table scenes through --live-evidence).
    """
    report = load_json(path, "live verification run report", errors)
    if report is None:
        return
    schema = report.get("schema")
    if schema not in {"kdbg.live-verify.v1", "kdbg.live-verify.raw-pfn.v1"}:
        errors.append(
            "live run schema must be kdbg.live-verify.v1 or "
            "kdbg.live-verify.raw-pfn.v1"
        )
    mode = report.get("mode")
    if mode not in {
        "read-only", "probe-write-rollback",
        "baremetal-raw-pfn-write-rollback",
    }:
        errors.append("live run mode is invalid")
    raw_pfn_mode = schema == "kdbg.live-verify.raw-pfn.v1" or mode == "baremetal-raw-pfn-write-rollback"
    if raw_pfn_mode:
        contract = report.get("raw_pfn_contract")
        if (not isinstance(contract, dict) or
                contract.get("target_profile") != "LocalHost" or
                contract.get("target_kind") != "RawPfn" or
                contract.get("target_provenance") != "manual PFN entry" or
                contract.get("raw_pfn_derived_from_probe") is not True):
            errors.append("Raw-PFN live run target contract is invalid")
        else:
            target_pfn = integer(contract.get("pfn"), "raw_pfn_contract.pfn", errors)
            target_physical = integer(
                contract.get("physical_address"),
                "raw_pfn_contract.physical_address", errors)
            if (target_pfn is not None and target_physical is not None and
                    target_physical != target_pfn << 12):
                errors.append("Raw-PFN target PFN/physical address mismatch")
    if report.get("success") is not True or report.get("cancelled") is not False:
        errors.append("live run must report successful, non-cancelled completion")
    if report.get("errors") != []:
        errors.append("live run contains one or more recorded errors")

    system = report.get("system")
    if not isinstance(system, dict):
        errors.append("live run system record is missing")
    else:
        if system.get("os_name") != "Windows" or system.get("architecture") != "x64":
            errors.append("live run must originate from Windows x64")
        if (not isinstance(system.get("os_build"), int) or
                isinstance(system.get("os_build"), bool) or
                system.get("os_build", 0) < MIN_WINDOWS_BUILD):
            errors.append(
                f"live run requires Windows x64 build {MIN_WINDOWS_BUILD} or newer")
        try:
            generated = datetime.fromisoformat(
                str(system.get("generated_utc", "")).replace("Z", "+00:00")
            )
            if generated.tzinfo is None or generated.utcoffset() != timezone.utc.utcoffset(generated):
                raise ValueError("not UTC")
        except ValueError as exc:
            errors.append(f"invalid live run generated_utc: {exc}")

    validate_runtime_identity(report, errors)

    backend = report.get("backend")
    backend_abi: int | None = None
    if not isinstance(backend, dict):
        errors.append("live run backend record is missing")
    elif (not isinstance(backend.get("name"), str) or not backend.get("name") or
          backend.get("connected") is not True or
          backend.get("is_mock") is not False or
          backend.get("write_enabled") is not False or
          backend.get("abi_version") not in {6, 7}):
        errors.append("live run requires a connected, locked, non-mock ABI v6/v7 backend")
    else:
        backend_abi = backend.get("abi_version")
        if (backend_abi == 7 and
                backend.get("supports_physical_page_compare_write") is not True):
            errors.append(
                "ABI v7 live run lacks the exact-page compare/write capability")

    def checked_probe(name: str) -> dict | None:
        probe = report.get(name)
        if not isinstance(probe, dict):
            errors.append(f"live run {name} is missing")
            return None
        pfn = integer(probe.get("pfn"), f"{name}.pfn", errors)
        physical = integer(
            probe.get("physical_address"), f"{name}.physical_address", errors)
        if probe.get("byte_count") != 4096:
            errors.append(f"live run {name} must identify 4096 bytes")
        if pfn is not None and (pfn <= 0 or pfn > ((1 << 64) - 1) >> 12):
            errors.append(f"live run {name} PFN is zero or overflows PFN << 12")
        if pfn is not None and physical is not None and physical != pfn << 12:
            errors.append(f"live run {name} PFN/physical address mismatch")
        for field in ("generation", "virtual_address", "crc32"):
            value = probe.get(field)
            maximum = 0xFFFFFFFF if field in {"generation", "crc32"} else (1 << 64) - 1
            if (not isinstance(value, int) or isinstance(value, bool) or
                    value < 0 or value > maximum or
                    (field in {"generation", "virtual_address"} and value == 0)):
                errors.append(f"live run {name}.{field} is invalid")
        return probe

    def checked_session(name: str) -> dict | None:
        session = report.get(name)
        if not isinstance(session, dict):
            errors.append(f"live run {name} is missing")
            return None
        owner = session.get("owner_pid")
        current = session.get("current_pid")
        if (not isinstance(owner, int) or isinstance(owner, bool) or owner <= 0 or
                not isinstance(current, int) or isinstance(current, bool) or
                owner != current or session.get("flags") != 0x1 or
                session.get("open_handle_count") != 1 or
                session.get("write_enabled") is not False):
            errors.append(f"live run {name} does not prove one locked controller")
        for field in (
            "flags", "successful_reads", "successful_writes", "rejected_writes",
            "last_physical_write_status", "last_physical_write_stage",
            "last_physical_write_transferred",
        ):
            value = session.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"live run {name}.{field} is invalid")
        return session

    probe_before = checked_probe("probe_before")
    session_before = checked_session("session_before")
    session_final = checked_session("session_final")
    if raw_pfn_mode and probe_before:
        contract = report.get("raw_pfn_contract")
        if isinstance(contract, dict):
            if contract.get("pfn") != probe_before.get("pfn"):
                errors.append("Raw-PFN target must match the live Probe PFN")
            if contract.get("physical_address") != probe_before.get("physical_address"):
                errors.append("Raw-PFN target must match the live Probe physical address")

    latency = report.get("latency")
    if not isinstance(latency, dict):
        errors.append("live run latency record is missing")
    else:
        samples = latency.get("read_samples_ms")
        if not isinstance(samples, list) or not 1 <= len(samples) <= 64 or not all(
            isinstance(value, (int, float)) and not isinstance(value, bool) and
            math.isfinite(value) and value >= 0 for value in samples
        ):
            errors.append("live run latency samples are invalid")
            samples = None
        for field in ("read_median_ms", "read_p95_ms"):
            value = latency.get(field)
            if (not isinstance(value, (int, float)) or isinstance(value, bool) or
                    not math.isfinite(value) or value < 0):
                errors.append(f"live run latency {field} is invalid")
        if isinstance(samples, list) and samples:
            ordered = sorted(samples)
            count = len(ordered)
            expected_median = (
                ordered[count // 2]
                if count % 2 else
                (ordered[count // 2 - 1] + ordered[count // 2]) / 2.0
            )
            expected_p95 = ordered[max(math.ceil(0.95 * count), 1) - 1]
            median = latency.get("read_median_ms")
            p95 = latency.get("read_p95_ms")
            if (isinstance(median, (int, float)) and
                    not math.isclose(median, expected_median, abs_tol=1e-5)):
                errors.append("live run read_median_ms does not match latency samples")
            if (isinstance(p95, (int, float)) and
                    not math.isclose(p95, expected_p95, abs_tol=1e-5)):
                errors.append("live run read_p95_ms does not match latency samples")

    operations = report.get("operations")
    operation_by_name: dict[str, list[dict]] = {}
    if not isinstance(operations, list) or not operations:
        errors.append("live run operations are missing")
    else:
        for index, operation in enumerate(operations):
            if not isinstance(operation, dict) or not isinstance(operation.get("name"), str):
                errors.append(f"live run operation {index} is invalid")
                continue
            operation_by_name.setdefault(operation["name"], []).append(operation)
            requested = operation.get("requested_bytes")
            completed = operation.get("completed_bytes")
            operation_latency = operation.get("latency_ms")
            if (operation.get("passed") is not True or
                    not isinstance(requested, int) or requested < 0 or
                    not isinstance(completed, int) or completed < 0 or
                    not isinstance(operation_latency, (int, float)) or
                    isinstance(operation_latency, bool) or
                    not math.isfinite(operation_latency) or operation_latency < 0 or
                    (requested > 0 and completed != requested)):
                errors.append(f"live run operation failed exact-count contract: {operation['name']}")
        if "load_baseline" not in operation_by_name or "independent_read_sample" not in operation_by_name:
            errors.append("live run lacks baseline and independent 4 KiB reads")

    comparisons = report.get("comparisons")
    comparison_by_name: dict[str, list[dict]] = {}
    if not isinstance(comparisons, list) or not comparisons:
        errors.append("live run full-page comparisons are missing")
    else:
        for index, comparison in enumerate(comparisons):
            if (not isinstance(comparison, dict) or
                    comparison.get("byte_count") != 4096 or
                    comparison.get("mismatch_count") != 0 or
                    comparison.get("match") is not True):
                errors.append(f"live run comparison {index} did not prove a full-page match")
                continue
            name = comparison.get("name")
            expected_crc = comparison.get("expected_crc32")
            actual_crc = comparison.get("actual_crc32")
            if (not isinstance(name, str) or not name or
                    not isinstance(expected_crc, int) or isinstance(expected_crc, bool) or
                    not 0 <= expected_crc <= 0xFFFFFFFF or
                    not isinstance(actual_crc, int) or isinstance(actual_crc, bool) or
                    not 0 <= actual_crc <= 0xFFFFFFFF):
                errors.append(f"live run comparison {index} has invalid identity or CRC32")
                continue
            comparison_by_name.setdefault(name, []).append(comparison)

    cleanup = report.get("write_cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("final_gate_locked") is not True:
        errors.append("live run does not prove the final write gate is locked")
        cleanup = {}

    if mode in {"probe-write-rollback", "baremetal-raw-pfn-write-rollback"}:
        if mode == "probe-write-rollback":
            if (report.get("operator_confirmed_disposable_vm") is not True or
                    not isinstance(report.get("snapshot_id"), str) or
                    not report.get("snapshot_id")):
                errors.append("write run lacks disposable-VM and snapshot confirmation")
        elif (report.get("operator_confirmed_disposable_vm") is not False or
              report.get("snapshot_id") != ""):
            errors.append("Raw-PFN run must not assert disposable-VM confirmation")
        probe_after_write = checked_probe("probe_after_write")
        probe_after_rollback = checked_probe("probe_after_rollback")
        session_after_apply = checked_session("session_after_apply")
        required = {
            "one_shot_apply": 8,
            "independent_reload_after_write": 4096,
            "rollback_full_page": 4096,
            "independent_read_after_rollback": 4096,
        }
        for name, byte_count in required.items():
            records = operation_by_name.get(name, [])
            if len(records) != 1 or records[0].get("requested_bytes") != byte_count:
                errors.append(f"write run lacks exact {name} evidence")
        if (cleanup.get("apply_requested_bytes") != 8 or
                cleanup.get("edit_offset") != 0x100 or
                cleanup.get("edit_length") != 8 or
                cleanup.get("rollback_requested_bytes") != 4096 or
                cleanup.get("rollback_attempted") is not True or
                cleanup.get("rollback_verified") is not True or
                cleanup.get("final_relock_attempted") is not True):
            errors.append("write run cleanup contract is incomplete")
        for name in (
            "baseline_vs_preflight",
            "expected_vs_write_readback",
            "expected_vs_independent_reload",
            "baseline_vs_rollback_readback",
            "baseline_vs_post_rollback_read",
        ):
            if len(comparison_by_name.get(name, [])) != 1:
                errors.append(f"write run lacks unique full-page comparison: {name}")
        if probe_before and probe_after_write and probe_after_rollback:
            if not (probe_before.get("pfn") == probe_after_write.get("pfn") ==
                    probe_after_rollback.get("pfn")):
                errors.append("write run Probe PFN changed")
            if not (probe_before.get("generation") ==
                    probe_after_write.get("generation") ==
                    probe_after_rollback.get("generation")):
                errors.append("write run Probe generation changed")
            if probe_before.get("crc32") != probe_after_rollback.get("crc32"):
                errors.append("write run Probe CRC was not restored")
        if session_before and session_after_apply and session_final:
            before_writes = session_before.get("successful_writes")
            applied_writes = session_after_apply.get("successful_writes")
            final_writes = session_final.get("successful_writes")
            if not (isinstance(before_writes, int) and
                    applied_writes == before_writes + 1 and
                    final_writes == applied_writes + 1):
                errors.append("write run session counters do not prove apply plus rollback")
            if session_final.get("last_physical_write_transferred") != 4096:
                errors.append("write run final driver acknowledgement is not a full-page rollback")
            expected_apply_transfer = 4096 if backend_abi == 7 else 8
            if (session_after_apply.get("last_physical_write_status") != 0 or
                    session_after_apply.get("last_physical_write_stage") != 4 or
                    session_after_apply.get("last_physical_write_transferred") !=
                        expected_apply_transfer):
                errors.append(
                    "write run apply acknowledgement does not match its ABI transaction")
            if (session_final.get("last_physical_write_status") != 0 or
                    session_final.get("last_physical_write_stage") != 4):
                errors.append("write run rollback acknowledgement is not complete")
            before_reads = session_before.get("successful_reads")
            applied_reads = session_after_apply.get("successful_reads")
            final_reads = session_final.get("successful_reads")
            sample_count = len(samples) if isinstance(samples, list) else 0
            apply_read_delta = sample_count + (1 if backend_abi == 7 else 3)
            rollback_read_delta = 2 if backend_abi == 7 else 4
            if (not isinstance(before_reads, int) or
                    not isinstance(applied_reads, int) or
                    not isinstance(final_reads, int) or
                    applied_reads < before_reads + apply_read_delta or
                    final_reads < applied_reads + rollback_read_delta):
                errors.append("write run read counters do not cover every independent full-page read")
            if not (
                session_before.get("rejected_writes") ==
                session_after_apply.get("rejected_writes") ==
                session_final.get("rejected_writes")
            ):
                errors.append("write run unexpectedly changed the rejected-write counter")
    elif mode == "read-only" and report.get("operator_confirmed_disposable_vm") is not False:
        errors.append("read-only run must not assert write-mode confirmation")


def validate_baremetal_package_archive(
    archive: Path, package: Path, errors: list[str],
) -> None:
    """Bind the archived release bytes to the extracted package tree."""
    try:
        with zipfile.ZipFile(archive, "r") as bundle:
            records: dict[str, zipfile.ZipInfo] = {}
            for item in bundle.infolist():
                if item.is_dir():
                    continue
                name = item.filename.replace("\\", "/")
                safe = safe_relative(name)
                if safe is None or item.flag_bits & 0x1:
                    raise ValueError("unsafe or encrypted archive entry")
                parts = PurePosixPath(safe).parts
                if parts and parts[0] == PACKAGE_NAME:
                    parts = parts[1:]
                if not parts:
                    raise ValueError("empty package-relative archive entry")
                relative = PurePosixPath(*parts).as_posix()
                if relative in records:
                    raise ValueError("duplicate package-relative archive entry")
                records[relative] = item
            actual = file_set(package)
            if set(records) != actual:
                errors.append(
                    "bare-metal package archive file set does not match the "
                    "extracted Windows package"
                )
                return
            for relative, item in records.items():
                digest = hashlib.sha256(bundle.read(item)).hexdigest()
                if digest != sha256(package / PurePosixPath(relative)):
                    errors.append(
                        "bare-metal package archive content mismatch: " + relative
                    )
                    return
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        errors.append(f"invalid bare-metal package archive: {exc}")


def validate_baremetal_host_evidence(
    path: Path,
    package: Path | None,
    errors: list[str],
) -> None:
    """Validate a completed bare-metal runtime-host Probe transaction.

    This gate is intentionally independent from the Hyper-V guest gate.  A
    skeleton/dry-run report, a guest report, or an unbound set of page files
    can never satisfy it.
    """
    evidence = load_json(path, "bare-metal host evidence JSON", errors)
    if evidence is None:
        return
    if evidence.get("schema") != BAREMETAL_EVIDENCE_SCHEMA:
        errors.append(
            f"bare-metal evidence schema must be {BAREMETAL_EVIDENCE_SCHEMA}"
        )
    if evidence.get("lane") != "bare-metal-runtime-host":
        errors.append("bare-metal evidence lane must be bare-metal-runtime-host")
    if evidence.get("success") is not True or evidence.get("dry_run") is not False:
        errors.append("bare-metal evidence must be a successful non-dry-run record")
    if evidence.get("errors") != []:
        errors.append("bare-metal evidence contains one or more recorded errors")
    if any(field in evidence for field in (
        "guest", "guest_validation_passed", "vm_name", "checkpoint",
        "operator_confirmed_disposable_vm", "snapshot_id",
    )):
        errors.append("guest/VM evidence cannot masquerade as bare-metal evidence")
    serialized = path.read_text(encoding="utf-8-sig", errors="ignore")
    if PRIVATE_PATH_RE.search(serialized):
        errors.append("bare-metal evidence leaks a private user path")

    try:
        completed = datetime.fromisoformat(
            str(evidence.get("completed_utc", "")).replace("Z", "+00:00")
        )
        if (completed.tzinfo is None or
                completed.utcoffset() != timezone.utc.utcoffset(completed)):
            raise ValueError("not UTC")
        if completed.timestamp() > datetime.now(timezone.utc).timestamp() + 300:
            raise ValueError("timestamp is in the future")
    except ValueError as exc:
        errors.append(f"invalid bare-metal completed_utc: {exc}")

    roles = evidence.get("roles")
    if not isinstance(roles, dict):
        errors.append("bare-metal evidence roles must be an object")
        roles = {}
    runtime_host = roles.get("runtime_host")
    orchestrator_host = roles.get("orchestrator_host")
    if not isinstance(runtime_host, dict):
        errors.append("bare-metal runtime_host identity is missing")
        runtime_host = {}
    if not isinstance(orchestrator_host, dict):
        errors.append("bare-metal orchestrator_host identity is missing")
        orchestrator_host = {}
    runtime_identity = runtime_host.get("machine_identity_sha256")
    orchestrator_identity = orchestrator_host.get("machine_identity_sha256")
    require_sha(runtime_identity, "roles.runtime_host.machine_identity_sha256", errors)
    require_sha(
        orchestrator_identity,
        "roles.orchestrator_host.machine_identity_sha256",
        errors,
    )
    if (runtime_host.get("role") != "runtime_host" or
            runtime_host.get("execution_context") != "bare-metal" or
            runtime_host.get("is_virtual_machine") is not False):
        errors.append("runtime_host is not bound to a bare-metal execution context")
    if not isinstance(runtime_host.get("hypervisor_present"), bool):
        errors.append("runtime_host hypervisor_present observation is missing")
    if (runtime_host.get("os_name") != "Windows" or
            runtime_host.get("architecture") != "x64" or
            not isinstance(runtime_host.get("os_build"), int) or
            isinstance(runtime_host.get("os_build"), bool) or
            runtime_host.get("os_build", 0) < MIN_WINDOWS_BUILD):
        errors.append(
            f"runtime_host must be Windows x64 build {MIN_WINDOWS_BUILD} or newer"
        )
    if orchestrator_host.get("role") != "orchestrator_host":
        errors.append("orchestrator_host role is invalid")
    boot_before = runtime_host.get("boot_id_before_sha256")
    require_sha(boot_before, "roles.runtime_host.boot_id_before_sha256", errors)

    package_record = evidence.get("package")
    if not isinstance(package_record, dict):
        errors.append("bare-metal package binding is missing")
        package_record = {}
    for field in (
        "package_sha256", "manifest_sha256", "source_snapshot_sha256",
        "signer_certificate_sha256",
    ):
        require_sha(package_record.get(field), f"package.{field}", errors)
    thumbprint = package_record.get("signer_thumbprint")
    if (not isinstance(thumbprint, str) or
            re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", thumbprint) is None):
        errors.append("package.signer_thumbprint must be lowercase SHA-1/SHA-256 hex")
    if package_record.get("signature_status") != "Valid":
        errors.append("bare-metal package signer status is not Valid")
    if package is None:
        errors.append("--baremetal-host-evidence requires --windows-package")
    else:
        metadata = load_json(
            package / "BUILD-METADATA.json", "bare-metal package metadata", errors
        )
        if metadata is not None and (
            package_record.get("source_snapshot_sha256") !=
            metadata.get("source_snapshot_sha256")
        ):
            errors.append("bare-metal source hash does not match the Windows package")
        manifest = package / "SHA256SUMS.txt"
        if (manifest.is_file() and
                package_record.get("manifest_sha256") != sha256(manifest)):
            errors.append("bare-metal manifest hash does not match the Windows package")

    binding = evidence.get("binding")
    if not isinstance(binding, dict):
        errors.append("bare-metal evidence binding is missing")
        binding = {}
    binding_pairs = (
        ("runtime_host_machine_identity_sha256", runtime_identity),
        ("boot_id_before_sha256", boot_before),
        ("package_sha256", package_record.get("package_sha256")),
        ("source_snapshot_sha256", package_record.get("source_snapshot_sha256")),
        ("signer_thumbprint", thumbprint),
    )
    for field, expected in binding_pairs:
        if binding.get(field) != expected:
            errors.append(f"bare-metal binding identity mismatch: {field}")

    target = evidence.get("target")
    if not isinstance(target, dict):
        errors.append("bare-metal Probe target is missing")
        target = {}
    pfn = integer(target.get("pfn"), "target.pfn", errors)
    physical = integer(target.get("physical_address"), "target.physical_address", errors)
    if (pfn is not None and (pfn <= 0 or pfn > ((1 << 64) - 1) >> 12)):
        errors.append("bare-metal Probe PFN is zero or overflows PFN << 12")
    if pfn is not None and physical is not None and physical != pfn << 12:
        errors.append("bare-metal target physical_address does not equal PFN << 12")
    if (target.get("provider") != "KDbgProbe" or
            target.get("discovery") != "IOCTL_KDBG_PROBE_GET_INFO" or
            target.get("ownership") != "KDbgProbe-owned contiguous page" or
            target.get("probe_derived") is not True or
            target.get("raw_user_pfn") is not False or
            target.get("page_size") != 4096 or
            not isinstance(target.get("generation"), int) or
            isinstance(target.get("generation"), bool) or
            target.get("generation", 0) <= 0):
        errors.append("bare-metal live evidence target is not a Probe-derived 4 KiB PFN")

    backend = evidence.get("backend")
    if not isinstance(backend, dict):
        errors.append("bare-metal backend capability record is missing")
        backend = {}
    if (backend.get("name") != "KDbgDriver" or
            backend.get("connected") is not True or
            backend.get("is_mock") is not False or
            backend.get("abi_version") != 7 or
            backend.get("write_enabled_final") is not False or
            backend.get("capabilities") != ["compare-write-page-v1"]):
        errors.append(
            "bare-metal evidence requires locked non-mock ABI v7 compare-write-page-v1"
        )

    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("bare-metal evidence artifacts must be an object")
        artifacts = {}
    artifact_paths: dict[str, Path] = {}
    for name in BAREMETAL_REQUIRED_ARTIFACTS:
        record = artifacts.get(name)
        if not isinstance(record, dict):
            errors.append(f"bare-metal artifact record is missing: {name}")
            continue
        require_sha(record.get("sha256"), f"artifacts.{name}.sha256", errors)
        artifact = _safe_evidence_file(
            path.parent, record.get("file"), f"bare-metal artifact {name}", errors
        )
        if artifact is None:
            continue
        artifact_paths[name] = artifact
        if artifact.stat().st_size != record.get("bytes"):
            errors.append(f"bare-metal artifact byte count mismatch: {name}")
        if sha256(artifact) != record.get("sha256"):
            errors.append(f"bare-metal artifact hash mismatch: {name}")
        if (name in {
                "baseline", "preflight", "expected_after", "readback",
                "independent_reload", "rollback",
            } and
                artifact.stat().st_size != 4096):
            errors.append(f"bare-metal page artifact must be exactly 4096 bytes: {name}")

    package_archive = artifact_paths.get("package_archive")
    if (package_archive is not None and
            sha256(package_archive) != package_record.get("package_sha256")):
        errors.append("bare-metal package archive hash does not match package binding")
    if package_archive is not None and package is not None:
        validate_baremetal_package_archive(package_archive, package, errors)

    signature_report_path = artifact_paths.get("signature_report")
    if signature_report_path is not None:
        signature_report = load_json(
            signature_report_path, "bare-metal signature report", errors
        )
        if signature_report is not None:
            if (signature_report.get("schema") !=
                    "kdbg.win11-baremetal-signature-report.v1" or
                    signature_report.get("verified") is not True or
                    signature_report.get("status") != "Valid" or
                    signature_report.get("verification_command") !=
                    "Get-AuthenticodeSignature" or
                    signature_report.get("exit_code") != 0):
                errors.append("bare-metal signature report did not prove Valid status")
            for field in (
                "package_sha256", "signer_thumbprint",
                "signer_certificate_sha256",
            ):
                if signature_report.get(field) != package_record.get(field):
                    errors.append(
                        f"bare-metal signature report binding mismatch: {field}"
                    )
            catalogs = signature_report.get("catalogs")
            expected_catalog_paths = set(EXPECTED_CATALOGS)
            if not isinstance(catalogs, list) or len(catalogs) != 2:
                errors.append("bare-metal signature report must bind both driver catalogs")
            else:
                seen_catalogs: set[str] = set()
                for record in catalogs:
                    if not isinstance(record, dict):
                        errors.append("bare-metal signature catalog record is invalid")
                        continue
                    relative = record.get("package_relative_path")
                    digest = record.get("sha256")
                    if relative not in expected_catalog_paths or relative in seen_catalogs:
                        errors.append("bare-metal signature catalog path is invalid")
                        continue
                    seen_catalogs.add(relative)
                    catalog_path = package / PurePosixPath(relative) if package else None
                    if (catalog_path is None or not catalog_path.is_file() or
                            digest != sha256(catalog_path)):
                        errors.append(
                            f"bare-metal signature catalog hash mismatch: {relative}"
                        )
                if seen_catalogs != expected_catalog_paths:
                    errors.append("bare-metal signature report catalog set is incomplete")

    baseline = artifact_paths.get("baseline")
    preflight = artifact_paths.get("preflight")
    expected_after = artifact_paths.get("expected_after")
    readback = artifact_paths.get("readback")
    independent_reload = artifact_paths.get("independent_reload")
    rollback = artifact_paths.get("rollback")
    if baseline and preflight and baseline.read_bytes() != preflight.read_bytes():
        errors.append("bare-metal preflight page does not match baseline")
    if expected_after and readback and expected_after.read_bytes() != readback.read_bytes():
        errors.append("bare-metal full read-back does not match expected page")
    if expected_after and independent_reload and (
            expected_after.read_bytes() != independent_reload.read_bytes()):
        errors.append("bare-metal independent reload does not match expected page")
    if baseline and rollback and baseline.read_bytes() != rollback.read_bytes():
        errors.append("bare-metal rollback does not restore the full baseline page")
    if baseline and expected_after:
        before = baseline.read_bytes()
        after = expected_after.read_bytes()
        differences = [index for index, pair in enumerate(zip(before, after))
                       if pair[0] != pair[1]]
        if differences != list(range(PROBE_EDIT_OFFSET, PROBE_EDIT_OFFSET + 8)):
            errors.append("bare-metal expected page is not the exact 8-byte Probe edit")
        elif bytes(before[index] ^ after[index] for index in differences) != PROBE_EDIT_MASK:
            errors.append("bare-metal expected page does not use the fixed Probe edit mask")

    live_report: dict | None = None
    live_report_path = artifact_paths.get("live_run_report")
    if live_report_path is not None:
        live_report = load_json(
            live_report_path, "bare-metal live verifier report", errors
        )
        if live_report is not None:
            if (live_report.get("schema") != "kdbg.live-verify.v2" or
                    live_report.get("mode") !=
                    "baremetal-probe-write-rollback" or
                    live_report.get("success") is not True or
                    live_report.get("cancelled") is not False or
                    live_report.get("errors") != [] or
                    live_report.get("operator_confirmed_disposable_vm") is not False or
                    live_report.get("snapshot_id") != ""):
                errors.append("bare-metal live verifier report is not a successful v2 run")
            contract = live_report.get("baremetal_contract")
            if not isinstance(contract, dict):
                errors.append("bare-metal live verifier contract is missing")
                contract = {}
            if (contract.get("target_profile") != "LocalHost" or
                    contract.get("probe_identity_fresh_at_rollback") is not True or
                    contract.get("rollback_suppressed_stale_identity") is not False):
                errors.append("bare-metal live verifier contract binding is invalid")
            report_backend = live_report.get("backend")
            if not isinstance(report_backend, dict) or (
                report_backend.get("name") not in {"KDbgDriver", "kdbg-live"} or
                report_backend.get("abi_version") != 7 or
                report_backend.get("connected") is not True or
                report_backend.get("is_mock") is not False or
                report_backend.get("write_enabled") is not False or
                report_backend.get(
                    "supports_physical_page_compare_write") is not True
            ):
                errors.append("bare-metal live verifier backend is not locked ABI v7")
            probes = [
                live_report.get(name) for name in (
                    "probe_before", "probe_after_write", "probe_after_rollback")
            ]
            if (not all(isinstance(probe, dict) for probe in probes) or
                    any(probe.get("pfn") != pfn for probe in probes
                        if isinstance(probe, dict)) or
                    any(probe.get("generation") != target.get("generation")
                        for probe in probes if isinstance(probe, dict)) or
                    any(probe.get("byte_count") != 4096 for probe in probes
                        if isinstance(probe, dict))):
                errors.append("bare-metal live verifier Probe identity mismatch")
            report_cleanup = live_report.get("write_cleanup")
            if not isinstance(report_cleanup, dict) or (
                report_cleanup.get("edit_offset") != PROBE_EDIT_OFFSET or
                report_cleanup.get("edit_length") != 8 or
                report_cleanup.get("user_dirty_bytes") != 8 or
                report_cleanup.get("apply_driver_transferred_bytes") != 4096 or
                report_cleanup.get("rollback_requested_bytes") != 4096 or
                report_cleanup.get("rollback_driver_transferred_bytes") != 4096 or
                report_cleanup.get("rollback_attempted") is not True or
                report_cleanup.get("rollback_verified") is not True or
                report_cleanup.get("final_relock_attempted") is not True or
                report_cleanup.get("final_gate_locked") is not True
            ):
                errors.append("bare-metal live verifier write/rollback contract is invalid")
            raw_page_records = live_report.get("raw_page_artifacts")
            report_pages: dict[str, dict] = {}
            if not isinstance(raw_page_records, list):
                errors.append("bare-metal live verifier raw_page_artifacts are missing")
            else:
                for record in raw_page_records:
                    if (not isinstance(record, dict) or
                            not isinstance(record.get("role"), str) or
                            record["role"] in report_pages):
                        errors.append("bare-metal live verifier raw page record is invalid")
                        continue
                    report_pages[record["role"]] = record
            for name in (
                "baseline", "preflight", "expected_after", "readback",
                "independent_reload", "rollback",
            ):
                raw_record = artifacts.get(name)
                report_record = report_pages.get(name)
                if not isinstance(raw_record, dict) or not isinstance(report_record, dict):
                    errors.append(
                        f"bare-metal live verifier page artifact is missing: {name}"
                    )
                    continue
                raw_path = artifact_paths.get(name)
                expected_crc = (
                    zlib.crc32(raw_path.read_bytes()) & 0xFFFFFFFF
                    if raw_path is not None else None
                )
                if (report_record.get("file_name") != raw_record.get("file") or
                        report_record.get("sha256") != raw_record.get("sha256") or
                        report_record.get("byte_count") != 4096 or
                        report_record.get("written") is not True or
                        ("crc32" in report_record and
                         report_record.get("crc32") != expected_crc)):
                    errors.append(
                        f"bare-metal live verifier page binding mismatch: {name}"
                    )
            comparison_by_name = {
                item.get("name"): item
                for item in live_report.get("comparisons", [])
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            crc_pairs = {
                "baseline_vs_preflight": ("baseline", "preflight"),
                "expected_vs_write_readback": ("expected_after", "readback"),
                "expected_vs_independent_reload":
                    ("expected_after", "independent_reload"),
                "baseline_vs_rollback_readback": ("baseline", "rollback"),
            }
            for comparison_name, (expected_name, actual_name) in crc_pairs.items():
                comparison_record = comparison_by_name.get(comparison_name)
                expected_path = artifact_paths.get(expected_name)
                actual_path = artifact_paths.get(actual_name)
                if (not isinstance(comparison_record, dict) or
                        expected_path is None or actual_path is None or
                        comparison_record.get("byte_count") != 4096 or
                        comparison_record.get("mismatch_count") != 0 or
                        comparison_record.get("match") is not True or
                        comparison_record.get("expected_crc32") !=
                        zlib.crc32(expected_path.read_bytes()) & 0xFFFFFFFF or
                        comparison_record.get("actual_crc32") !=
                        zlib.crc32(actual_path.read_bytes()) & 0xFFFFFFFF):
                    errors.append(
                        "bare-metal live verifier comparison binding mismatch: "
                        + comparison_name
                    )

    transaction = evidence.get("transaction")
    if not isinstance(transaction, dict):
        errors.append("bare-metal transaction record is missing")
        transaction = {}
    required_transaction = {
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
    }
    for field, expected in required_transaction.items():
        if transaction.get(field) != expected:
            errors.append(f"bare-metal transaction contract mismatch: {field}")
    if (transaction.get("edit_offset") != PROBE_EDIT_OFFSET or
            transaction.get("edit_length") != 8 or
            transaction.get("edit_xor_mask") != PROBE_EDIT_MASK.hex()):
        errors.append("bare-metal transaction edit identity is invalid")
    if transaction.get("runtime_host_machine_identity_sha256") != runtime_identity:
        errors.append("bare-metal transaction runtime-host identity mismatch")
    if transaction.get("boot_id_sha256") != boot_before:
        errors.append("bare-metal transaction boot identity mismatch")
    if (transaction.get("abi_version") != 7 or
            transaction.get("operation") != "compare-write-page-v1" or
            transaction.get("compare_bytes") != 4096):
        errors.append("bare-metal transaction lacks ABI v7 compare-write evidence")
    if live_report is not None:
        live_cleanup = live_report.get("write_cleanup")
        if not isinstance(live_cleanup, dict) or (
            transaction.get("dirty_bytes") !=
            live_cleanup.get("user_dirty_bytes") or
            transaction.get("driver_transferred_bytes") !=
            live_cleanup.get("apply_driver_transferred_bytes") or
            transaction.get("rollback_completed_bytes") !=
            live_cleanup.get("rollback_driver_transferred_bytes") or
            transaction.get("final_gate_locked") !=
            live_cleanup.get("final_gate_locked")
        ):
            errors.append("bare-metal transaction summary does not match live report")

    cleanup = evidence.get("cleanup")
    if not isinstance(cleanup, dict):
        errors.append("bare-metal cleanup record is missing")
        cleanup = {}
    for field in (
        "uninstall_completed", "services_absent", "devices_absent",
    ):
        if cleanup.get(field) is not True:
            errors.append(f"bare-metal cleanup did not prove: {field}")
    if cleanup.get("errors") != []:
        errors.append("bare-metal cleanup contains recorded errors")

    cleanup_report_path = artifact_paths.get("cleanup_report")
    if cleanup_report_path is not None:
        cleanup_report = load_json(
            cleanup_report_path, "bare-metal cleanup report", errors
        )
        if cleanup_report is not None and (
            cleanup_report.get("schema") !=
            "kdbg.win11-baremetal-cleanup-report.v1" or
            cleanup_report.get("success") is not True or
            cleanup_report.get("runtime_host_machine_identity_sha256") !=
            runtime_identity or
            cleanup_report.get("boot_id_sha256") != boot_before or
            cleanup_report.get("final_gate_locked") is not True or
            cleanup_report.get("services") != {
                "KDBG": "absent", "KDBGProbe": "absent"} or
            cleanup_report.get("devices") != {
                "KDBG": "absent", "KDBGProbe": "absent"} or
            cleanup_report.get("errors") != []
        ):
            errors.append("bare-metal cleanup observation report is invalid")


def infer_default_validation_targets(
    script_path: Path,
) -> tuple[bool, Path | None, Path | None]:
    candidate = script_path.resolve().parent.parent
    if candidate.name == PACKAGE_NAME:
        return False, candidate, candidate.parent / SYMBOLS_NAME
    return True, None, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-complete", action="store_true")
    parser.add_argument("--windows-package", type=Path)
    parser.add_argument("--symbols-package", type=Path)
    parser.add_argument("--live-evidence", type=Path)
    parser.add_argument("--live-run-report", type=Path)
    parser.add_argument(
        "--baremetal-host-evidence",
        type=Path,
        help=(
            "validate a completed kdbg.win11-baremetal-validation.v1 "
            "runtime-host evidence record"
        ),
    )
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument(
        "--forbid-symbol-path",
        action="append",
        default=[],
        help=(
            "reject this private source/build root if found inside any PDB; "
            "repeat for every build root"
        ),
    )
    args = parser.parse_args()
    script_path = Path(__file__).resolve()
    root = script_path.parents[2]
    errors: list[str] = []
    if not any((args.source_complete, args.windows_package, args.symbols_package,
                args.live_evidence, args.live_run_report,
                args.baremetal_host_evidence)):
        (args.source_complete, args.windows_package,
         args.symbols_package) = infer_default_validation_targets(script_path)
    if args.source_complete:
        validate_source(root, errors)
        validate_lock(root, errors)
    package = args.windows_package.resolve() if args.windows_package else None
    symbols = args.symbols_package.resolve() if args.symbols_package else None
    if package is not None and args.symbols_package is None:
        errors.append(
            "--windows-package requires the matching --symbols-package; "
            "release binaries and debugging symbols are one validated pair"
        )
    main_metadata = validate_package(package, errors) if package else None
    forbidden_symbol_paths = tuple(
        str(Path(value).resolve()) for value in args.forbid_symbol_path
    )
    symbols_metadata = validate_symbols(
        symbols, errors, forbidden_symbol_paths) if symbols else None
    if package is not None and symbols is not None:
        validate_package_pair(
            package, symbols, main_metadata, symbols_metadata, errors)
    if args.live_evidence:
        validate_live(args.live_evidence.resolve(), package, symbols, errors)
    if args.live_run_report:
        validate_live_run(args.live_run_report.resolve(), errors)
    if args.baremetal_host_evidence:
        validate_baremetal_host_evidence(
            args.baremetal_host_evidence.resolve(), package, errors
        )
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
    if args.live_evidence: gates.append("live-VM-verified")
    if args.live_run_report: gates.append("live-device-run-report")
    if args.baremetal_host_evidence:
        gates.append("bare-metal-host-read-only-verified")
        gates.append("bare-metal-host-probe-write-verified")
    print("Release validation PASS: " + ", ".join(gates))
    print("Gate table:")
    print(f" - source-complete: {'PASS' if args.source_complete else 'NOT RUN'}")
    windows_build_verified = package is not None and symbols is not None
    print(
        " - Windows-build-verified: "
        + ("PASS" if windows_build_verified else "NOT RUN")
    )
    print(f" - live-VM-verified: {'PASS' if args.live_evidence else 'NOT RUN'}")
    print(f" - live-device-run-report: {'PASS' if args.live_run_report else 'NOT RUN'}")
    print(
        " - bare-metal-host-read-only-verified: "
        + ("PASS" if args.baremetal_host_evidence else "NOT RUN")
    )
    print(
        " - bare-metal-host-probe-write-verified: "
        + ("PASS" if args.baremetal_host_evidence else "NOT RUN")
    )
    print(" - bare-metal-host-raw-pfn-live-write: NOT RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
