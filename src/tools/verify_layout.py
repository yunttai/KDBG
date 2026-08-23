#!/usr/bin/env python3
"""Validate the Codex-only KDBG repository and src-only product layout."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

REQUIRED = (
    "README.md",
    "AGENTS.md",
    "ARTIFACT_MANIFEST.md",
    "THIRD_PARTY.lock.json",
    ".codex/config.toml",
    ".codex/agents/kdbg-supervisor.toml",
    ".codex/agents/kernel-driver.toml",
    ".codex/agents/memory-core.toml",
    ".codex/agents/gui.toml",
    ".codex/agents/pfn-analysis.toml",
    ".codex/agents/qa-safety.toml",
    ".codex/agents/release-evidence.toml",
    ".agents/skills/kdbg-orchestrate/SKILL.md",
    ".agents/skills/implement-live-backend/SKILL.md",
    ".agents/skills/implement-memory-scan/SKILL.md",
    "docs/PRD.md",
    "docs/ARCHITECTURE.md",
    "docs/TEST_PLAN.md",
    "docs/TRACEABILITY_MATRIX.md",
    "docs/IMPLEMENTATION_STATUS.md",
    "docs/VALIDATION_REPORT.md",
    "docs/exec-plans/STATUS.md",
    "docs/exec-plans/active/windows-live-validation.md",
    "src/AGENTS.md",
    "src/core/AGENTS.md",
    "src/driver/AGENTS.md",
    "src/app/AGENTS.md",
    "src/tests/AGENTS.md",
    "src/CMakeLists.txt",
    "src/CMakePresets.json",
    "src/shared/KDbgIoctl.h",
    "src/shared/KDbgProbeIoctl.h",
    "src/driver/KDBGDrivers.sln",
    "src/driver/KDbgDriver/Driver.cpp",
    "src/driver/KDbgProbe/Driver.cpp",
    "src/core/memory/KDbgBackend.cpp",
    "src/core/scanner/MemoryScanner.cpp",
    "src/core/scanner/WatchList.cpp",
    "src/core/snapshot/MemorySnapshot.cpp",
    "src/core/pfn/PageTableReverseMapper.cpp",
    "src/plugins/memprocfs_bridge/main.cpp",
    "src/app/ui/SnapshotPanel.cpp",
    "src/app/ui/MemoryMapPanel.cpp",
    "src/app/ui/ProcessMemoryPanel.cpp",
    "src/tests/test_advanced.cpp",
    "src/tools/build_drivers.ps1",
    "src/tools/package_windows.ps1",
    "src/tools/manage_drivers.ps1",
    "src/tools/live-evidence.example.json",
    "src/config/app.example.json",
    "src/config/safety_policy.example.json",
)

EXPECTED_AGENT_COUNT = 7
EXPECTED_SKILL_COUNT = 10
AGENT_FIELDS = ("name", "description", "developer_instructions")
SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
    ".py", ".ps1", ".cmake", ".rc", ".inf", ".vcxproj", ".sln",
}
LEGACY_TOKENS = (
    "physical-memory-editor-harness",
    "pme.harness",
    "mock-debug",
    "live-debug",
    "run_mock.ps1",
    "import_kn_live_dbg.ps1",
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def check_skill_frontmatter(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return [f"{path}: missing YAML frontmatter"]
    end = text.find("\n---\n", 4)
    if end < 0:
        return [f"{path}: unterminated YAML frontmatter"]
    frontmatter = text[4:end]
    parsed: dict[str, str] = {}
    for line in frontmatter.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    for field in ("name", "description"):
        if not parsed.get(field):
            errors.append(f"{path}: missing non-empty frontmatter field {field}")
    expected_name = path.parent.name
    if parsed.get("name") != expected_name:
        errors.append(
            f"{path}: skill name {parsed.get('name')!r} must match directory {expected_name!r}"
        )
    return errors


def validate_cmake_sources(root: Path, errors: list[str]) -> None:
    cmake_files = [root / "src/CMakeLists.txt", root / "src/tests/CMakeLists.txt"]
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])((?:app|core|plugins|tests)/[A-Za-z0-9_./+-]+\.(?:cxx|cpp|cc|c|rc))(?![A-Za-z0-9_])"
    )
    for cmake_path in cmake_files:
        text = cmake_path.read_text(encoding="utf-8")
        base = cmake_path.parent
        for relative in sorted(set(pattern.findall(text))):
            candidate = base / relative
            if not candidate.is_file():
                errors.append(
                    f"CMake source reference does not exist: {candidate.relative_to(root)}"
                )


def scan_legacy_tokens(root: Path, errors: list[str]) -> None:
    candidates: list[Path] = []
    for entry in (root / "README.md", root / "AGENTS.md", root / "ARTIFACT_MANIFEST.md"):
        candidates.append(entry)
    for folder in (root / "docs", root / "src"):
        for path in folder.rglob("*"):
            if path.is_file() and path.suffix.lower() in {
                ".md", ".json", ".toml", ".py", ".ps1", ".cmake", ".txt"
            }:
                candidates.append(path)
    validator_path = Path(__file__).resolve()
    for path in candidates:
        if path.resolve() == validator_path:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").casefold()
        for token in LEGACY_TOKENS:
            if token.casefold() in text:
                errors.append(
                    f"legacy token {token!r} remains in {path.relative_to(root)}"
                )


def main() -> int:
    root = repository_root()
    errors: list[str] = []

    for relative in REQUIRED:
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")

    if (root / "_workspace").exists():
        errors.append("obsolete _workspace directory must be migrated to docs/exec-plans")
    if (root / ".claude").exists() or (root / "CLAUDE.md").exists():
        errors.append("non-Codex agent configuration exists in the repository")

    lock_path = root / "THIRD_PARTY.lock.json"
    if lock_path.is_file():
        try:
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            dependencies = lock.get("dependencies")
            if not isinstance(dependencies, list) or len(dependencies) < 8:
                errors.append("THIRD_PARTY.lock.json is unexpectedly incomplete")
            else:
                seen: set[str] = set()
                for dependency in dependencies:
                    name = dependency.get("name")
                    if not isinstance(name, str) or not name:
                        errors.append("dependency entry has no name")
                        continue
                    if name in seen:
                        errors.append(f"duplicate dependency lock entry: {name}")
                    seen.add(name)
                    if not dependency.get("revision"):
                        errors.append(f"dependency lacks pinned revision: {name}")
                    if not dependency.get("license"):
                        errors.append(f"dependency lacks license metadata: {name}")
                    if not dependency.get("integration"):
                        errors.append(f"dependency lacks integration mode: {name}")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid THIRD_PARTY.lock.json: {exc}")

    config_path = root / ".codex/config.toml"
    if config_path.is_file():
        try:
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            agents = config.get("agents", {})
            if agents.get("enabled") is not True:
                errors.append(".codex/config.toml must enable project agents")
            if int(agents.get("max_concurrent_threads_per_session", 0)) < 2:
                errors.append("Codex concurrent-agent cap must be at least 2")
        except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
            errors.append(f"invalid .codex/config.toml: {exc}")

    agent_files = sorted((root / ".codex/agents").glob("*.toml"))
    if len(agent_files) != EXPECTED_AGENT_COUNT:
        errors.append(
            f"expected {EXPECTED_AGENT_COUNT} project agents, found {len(agent_files)}"
        )
    agent_names: set[str] = set()
    for path in agent_files:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"invalid agent TOML {path.relative_to(root)}: {exc}")
            continue
        for field in AGENT_FIELDS:
            if not isinstance(data.get(field), str) or not data[field].strip():
                errors.append(f"{path.relative_to(root)}: missing non-empty {field}")
        name = data.get("name")
        if isinstance(name, str):
            if name in agent_names:
                errors.append(f"duplicate project-agent name: {name}")
            agent_names.add(name)

    skill_files = sorted((root / ".agents/skills").glob("*/SKILL.md"))
    if len(skill_files) != EXPECTED_SKILL_COUNT:
        errors.append(
            f"expected {EXPECTED_SKILL_COUNT} repository skills, found {len(skill_files)}"
        )
    for path in skill_files:
        errors.extend(check_skill_frontmatter(path))

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in {"src", "out"}:
            continue
        errors.append(f"product/developer source outside src/: {relative}")

    forbidden_direct_integrations = (
        "Kernel-Bridge/API/",
        "DBKKernel/",
        "Windows-Kernel-Explorer/binaries",
    )
    for path in (root / "src").rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {
            ".c", ".cc", ".cpp", ".h", ".hpp", ".cmake"
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for token in forbidden_direct_integrations:
            if token in text:
                errors.append(
                    f"forbidden direct integration token in {path.relative_to(root)}: {token}"
                )

    shared_headers = list((root / "src").rglob("*Ioctl.h"))
    names = [path.name.casefold() for path in shared_headers]
    if names.count("kdbgioctl.h") != 1:
        errors.append("exactly one KDbgIoctl.h must exist")
    if names.count("kdbgprobeioctl.h") != 1:
        errors.append("exactly one KDbgProbeIoctl.h must exist")

    obsolete_scripts = (
        "src/tools/run_mock.ps1",
        "src/tools/run_live.ps1",
        "src/tools/import_kn_live_dbg.ps1",
    )
    for relative in obsolete_scripts:
        if (root / relative).exists():
            errors.append(f"obsolete script still exists: {relative}")

    validate_cmake_sources(root, errors)
    scan_legacy_tokens(root, errors)

    if errors:
        print("Layout validation FAILED")
        for error in errors:
            print(f" - {error}")
        return 1

    print("Layout validation PASS")
    print(f"Project agents: {len(agent_files)}")
    print(f"Repository skills: {len(skill_files)}")
    print("Product/developer source root: src/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
