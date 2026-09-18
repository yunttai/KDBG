#!/usr/bin/env python3
"""Validate one recovered Win11 GUI run and build a bound demo manifest.

This tool is offline-only.  It never connects to or mutates a VM.  It rejects
anything other than a successful, restored, powered-off, full 24-frame capture
whose review state is still CAPTURED_UNREVIEWED.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Sequence

from compose_demo import DemoError


HASH = re.compile(r"[0-9a-f]{64}")
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
EXPECTED = (
    ("01-driver-probe-ready", "driver_probe_ready"),
    ("02-probe-pfn-discovery", "probe_pfn_discovery"),
    ("03-physical-read-4096", "physical_read_4096"),
    ("04-hex-edit-and-diff", "hex_edit_and_diff"),
    ("05-undo-redo-staged", "undo_redo"),
    ("06-undo-redo-dirty-zero", "undo_redo"),
    ("07-undo-redo-restored", "undo_redo"),
    ("08-typed-pfn-unlock", "typed_pfn_unlock"),
    ("09-write-and-readback", "write_and_readback"),
    ("10-independent-reload", "independent_reload"),
    ("11-rollback-baseline", "rollback_baseline"),
    ("12-pfn-owner-pid-va-pte", "pfn_owner_pid_va_pte"),
    ("13-page-table-walk", "page_table_walk"),
    ("14-process-first-scan", "process_first_next_scan"),
    ("15-process-next-scan", "process_first_next_scan"),
    ("16-address-list-freeze", "address_list_verified_freeze"),
    ("17-address-list-restored", "address_list_verified_freeze"),
    ("18-pointer-scan", "pointer_scan"),
    ("19-zydis-disassembly", "zydis_disassembly"),
    ("20-snapshot-diff", "snapshot_diff"),
    ("21-kernel-module-catalog", "kernel_module_catalog"),
    ("22-kernel-symbol-resolution", "kernel_symbol_resolution"),
    ("23-kernel-read-disassembly", "kernel_read_disassembly"),
    ("24-about-version", "about_version"),
)

# Source-coordinate crops are deliberately conservative and remain within the
# harness' required 1024x768 capture surface.  Cropping causes the compositor
# to zoom the relevant panel without inventing content.
SCENES = {
    "driver_probe_ready": ("Driver and probe ready", "Exact package is loaded; devices are ready", None),
    "probe_pfn_discovery": ("Probe PFN discovery", "Known probe allocation and PFN are visible", None),
    "physical_read_4096": ("Exact 4 KiB physical read", "Baseline page and byte count are visible", (40, 80, 944, 410)),
    "hex_edit_and_diff": ("Local hex edit and diff", "Dirty bytes remain local before apply", (40, 150, 944, 350)),
    "undo_redo": ("Undo and redo staged bytes", "Staged, clean, and restored states are shown in order", (40, 150, 944, 350)),
    "typed_pfn_unlock": ("Typed PFN one-shot unlock", "Typed confirmation opens only the single apply gate", (250, 0, 520, 330)),
    "write_and_readback": ("Write and full read-back", "One-shot apply and 4096-byte verification are visible", (40, 80, 944, 410)),
    "independent_reload": ("Independent page reload", "A fresh read preserves the verified bytes", (40, 80, 944, 410)),
    "rollback_baseline": ("Rollback to baseline", "Baseline restoration and the re-locked gate are visible", (40, 80, 944, 430)),
    "pfn_owner_pid_va_pte": ("PFN owner and VA evidence", "PID, virtual address, and PTE mapping are visible", (500, 60, 524, 650)),
    "page_table_walk": ("Page-table walk", "Translation levels and entry flags are readable", (735, 70, 289, 640)),
    "process_first_next_scan": ("First and next process scan", "The candidate set narrows across both captured states", (200, 340, 650, 428)),
    "address_list_verified_freeze": ("Verified address-list freeze", "Armed freeze and restored state are shown in order", (200, 340, 650, 428)),
    "pointer_scan": ("Pointer scan", "Resolved pointer paths are visible in the lower results panel", (200, 340, 650, 428)),
    "zydis_disassembly": ("Zydis disassembly", "Decoded fixture instructions are visible", (200, 340, 650, 428)),
    "snapshot_diff": ("Snapshot diff", "Changed bytes are visible in the comparison panel", (200, 340, 650, 428)),
    "kernel_module_catalog": ("Kernel module catalog", "The module catalog and selection are visible", (200, 320, 700, 448)),
    "kernel_symbol_resolution": ("Kernel symbol resolution", "PDB-backed symbol resolution is visible", (200, 300, 730, 468)),
    "kernel_read_disassembly": ("Kernel read and disassembly", "Read results and decoded instructions are visible", (180, 300, 780, 468)),
    "about_version": ("Version and build identity", "The final product version and build identity are visible", None),
}


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: bytes, name: str) -> dict[str, object]:
    try:
        result = json.loads(value.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DemoError(f"invalid JSON record: {name}") from exc
    if not isinstance(result, dict):
        raise DemoError(f"JSON record is not an object: {name}")
    return result


def _read_json(path: Path, name: str) -> tuple[dict[str, object], bytes]:
    if not path.is_file():
        raise DemoError(f"missing required host record: {name}")
    data = path.read_bytes()
    return _json_bytes(data, name), data


def _validate_hash(value: object, name: str) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise DemoError(f"{name} must be lowercase SHA-256")
    return value


def _safe_entries(archive: zipfile.ZipFile, archive_name: str) -> dict[str, zipfile.ZipInfo]:
    entries: dict[str, zipfile.ZipInfo] = {}
    seen: set[str] = set()
    total = 0
    for info in archive.infolist():
        name = info.filename
        path = PurePosixPath(name)
        mode = (info.external_attr >> 16) & 0o170000
        unsafe = (
            not name
            or "\\" in name
            or path.is_absolute()
            or any(part in ("", ".", "..") for part in path.parts)
            or re.match(r"^[A-Za-z]:", name) is not None
            or mode == 0o120000
            or info.flag_bits & 0x1
            or info.file_size > MAX_ENTRY_BYTES
        )
        key = name.casefold()
        if unsafe or key in seen:
            raise DemoError(f"{archive_name} has an unsafe or duplicate entry: {name}")
        seen.add(key)
        if info.is_dir():
            continue
        total += info.file_size
        if total > MAX_ARCHIVE_BYTES:
            raise DemoError(f"{archive_name} expands beyond the evidence limit")
        entries[key] = info
    if not entries:
        raise DemoError(f"{archive_name} is empty")
    return entries


def _entry_bytes(
    archive: zipfile.ZipFile, entries: dict[str, zipfile.ZipInfo], name: str, archive_name: str
) -> bytes:
    info = entries.get(name.casefold())
    if info is None or info.filename != name:
        raise DemoError(f"{archive_name} is missing exact entry: {name}")
    try:
        return archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise DemoError(f"unable to read {archive_name} entry: {name}") from exc


def _require(value: bool, message: str) -> None:
    if not value:
        raise DemoError(message)


def _canonical_capture_hash(captures: list[dict[str, str]]) -> str:
    data = json.dumps(captures, separators=(",", ":"), ensure_ascii=True) + "\n"
    return hashlib.sha256(data.encode("ascii")).hexdigest()


def build_manifest(run_dir: Path, output_manifest: Path, frames_dir: Path) -> dict[str, object]:
    run_dir = run_dir.resolve()
    output_manifest = output_manifest.resolve()
    frames_dir = frames_dir.resolve()
    if not run_dir.is_dir():
        raise DemoError("run directory does not exist")
    if frames_dir.parent != output_manifest.parent or frames_dir.name in ("", ".", ".."):
        raise DemoError("frames directory must be a direct child of the manifest directory")
    if output_manifest.exists():
        raise DemoError("refusing to overwrite an existing manifest")
    if frames_dir.exists() and any(frames_dir.iterdir()):
        raise DemoError("refusing to write into a non-empty frames directory")

    host, host_bytes = _read_json(run_dir / "host-orchestrator-summary.json", "host summary")
    preflight, preflight_bytes = _read_json(run_dir / "host-preflight.json", "host preflight")
    archive_path = run_dir / "guest-evidence.zip"
    if not archive_path.is_file():
        raise DemoError("missing recovered guest-evidence.zip")
    archive_sha = _sha_file(archive_path)

    _require(host.get("schema") == "kdbg.win11-extended-gui-host-orchestrator.v1", "host summary schema mismatch")
    for name in (
        "success", "capture_succeeded", "postboot_readiness_succeeded",
        "guest_cleanup_succeeded", "evidence_recovered",
        "autologon_secret_cleared_after_explorer",
    ):
        _require(host.get(name) is True, f"host summary did not prove {name}")
    _require(host.get("execution_status") == "CAPTURED_UNREVIEWED", "host capture is not CAPTURED_UNREVIEWED")
    _require(host.get("capture_mode") == "full", "host capture mode is not full")
    _require(host.get("evidence_pass") is False and host.get("human_review_complete") is False,
             "host summary falsely claims review or evidence PASS")
    _require(host.get("primary_error") is None and host.get("cleanup_errors") == [], "host summary contains errors")
    _require(isinstance(host.get("vm"), dict) and host["vm"].get("final_off") is True,
             "host summary does not prove final VM Off")
    _require(isinstance(host.get("checkpoint"), dict) and host["checkpoint"].get("restored") is True,
             "host summary does not prove checkpoint restore")
    host_archive = host.get("guest_evidence_archive")
    _require(isinstance(host_archive, dict) and host_archive.get("file") == "guest-evidence.zip",
             "host summary has no exact recovered guest archive")
    _require(_validate_hash(host_archive.get("sha256"), "guest evidence archive") == archive_sha,
             "recovered guest evidence archive hash mismatch")

    _require(preflight.get("schema") == "kdbg.win11-extended-gui-host-preflight.v1", "host preflight schema mismatch")
    artifacts = preflight.get("artifacts")
    _require(isinstance(artifacts, dict), "host preflight artifacts are missing")
    package_sha = _validate_hash(artifacts.get("package", {}).get("sha256") if isinstance(artifacts.get("package"), dict) else None, "package hash")
    symbols_sha = _validate_hash(artifacts.get("symbols", {}).get("sha256") if isinstance(artifacts.get("symbols"), dict) else None, "symbols hash")
    certificate_sha = _validate_hash(artifacts.get("certificate", {}).get("sha256") if isinstance(artifacts.get("certificate"), dict) else None, "certificate hash")
    source_sha = _validate_hash(artifacts.get("source_snapshot_sha256"), "source snapshot hash")

    required_records = (
        "capture-run.json", "guest-capture-summary.json", "guest-cleanup.json",
        "postboot-readiness.json", "postboot-readonly-probe.json", "captures.zip",
    )
    record_bytes: dict[str, bytes] = {}
    extracted: dict[str, bytes] = {}
    with zipfile.ZipFile(archive_path, "r") as guest_zip:
        guest_entries = _safe_entries(guest_zip, "guest evidence archive")
        for name in required_records:
            record_bytes[name] = _entry_bytes(guest_zip, guest_entries, name, "guest evidence archive")
        capture = _json_bytes(record_bytes["capture-run.json"], "capture-run.json")
        guest_summary = _json_bytes(record_bytes["guest-capture-summary.json"], "guest-capture-summary.json")
        cleanup = _json_bytes(record_bytes["guest-cleanup.json"], "guest-cleanup.json")
        readiness = _json_bytes(record_bytes["postboot-readiness.json"], "postboot-readiness.json")
        probe = _json_bytes(record_bytes["postboot-readonly-probe.json"], "postboot-readonly-probe.json")

        _require(capture.get("schema") == "kdbg.win11-extended-gui-capture-result.v1", "capture result schema mismatch")
        _require(capture.get("harness_valid") is True and capture.get("live_capture_status") == "CAPTURED_UNREVIEWED",
                 "capture result is not a valid CAPTURED_UNREVIEWED run")
        _require(capture.get("calibration_smoke") is False, "calibration smoke cannot produce a final video")
        _require(capture.get("evidence_pass") is False and capture.get("human_review_complete") is False,
                 "capture result falsely claims review or evidence PASS")
        _require(capture.get("capture_count") == 24 and capture.get("frame_count") == 24 and capture.get("scene_count") == 20,
                 "capture result must contain exactly 24 frames and 20 scenes")
        raw_captures = capture.get("captures")
        _require(isinstance(raw_captures, list) and len(raw_captures) == 24, "capture list must contain 24 entries")
        expected_capture_entries = {f"captures/{step_id}.png" for step_id, _ in EXPECTED}
        actual_capture_entries = {
            info.filename
            for info in guest_entries.values()
            if info.filename.startswith("captures/") and info.filename.lower().endswith(".png")
        }
        _require(actual_capture_entries == expected_capture_entries,
                 "guest evidence archive does not contain the exact 24 capture PNGs")

        ordered: list[dict[str, str]] = []
        for index, (item, expected) in enumerate(zip(raw_captures, EXPECTED)):
            _require(isinstance(item, dict), f"capture {index} is not an object")
            step_id, scene_id = expected
            _require(item.get("step_id") == step_id and item.get("scene_id") == scene_id,
                     f"capture order mismatch at index {index}")
            filename = item.get("file")
            _require(isinstance(filename, str) and filename == f"{step_id}.png" and Path(filename).name == filename,
                     f"capture {index} filename mismatch")
            digest = _validate_hash(item.get("sha256"), f"capture {index} hash")
            _require(item.get("width") == 1024 and item.get("height") == 768,
                     f"capture {index} dimensions are not 1024x768")
            duration_ms = item.get("duration_ms")
            _require(isinstance(duration_ms, int) and not isinstance(duration_ms, bool) and 100 <= duration_ms <= 30000,
                     f"capture {index} duration is invalid")
            image = _entry_bytes(guest_zip, guest_entries, f"captures/{filename}", "guest evidence archive")
            _require(_sha_bytes(image) == digest, f"capture {index} PNG hash mismatch")
            extracted[filename] = image
            ordered.append({"step_id": step_id, "scene_id": scene_id, "file": filename, "sha256": digest})

    _require(guest_summary.get("schema") == "kdbg.win11-extended-gui-guest-capture.v1" and guest_summary.get("success") is True,
             "guest capture summary is not successful")
    _require(guest_summary.get("mode") == "full" and guest_summary.get("capture_status") == "CAPTURED_UNREVIEWED",
             "guest capture summary is not a full unreviewed capture")
    _require(guest_summary.get("capture_count") == 24 and guest_summary.get("scene_count") == 20,
             "guest capture summary counts mismatch")
    _require(guest_summary.get("package_sha256") == package_sha and guest_summary.get("source_snapshot_sha256") == source_sha,
             "guest package/source hashes do not match host preflight")
    _require(guest_summary.get("evidence_pass") is False and guest_summary.get("human_review_complete") is False,
             "guest summary falsely claims review or evidence PASS")

    _require(cleanup.get("schema") == "kdbg.win11-extended-gui-guest-cleanup.v1" and cleanup.get("success") is True,
             "guest cleanup is not successful")
    _require(cleanup.get("autologon_secret_present") is False and cleanup.get("errors") == [],
             "guest cleanup retained a secret or reported errors")
    for group in ("tasks", "services"):
        values = cleanup.get(group)
        _require(isinstance(values, list) and values and all(isinstance(v, dict) and v.get("present") is False for v in values),
                 f"guest cleanup did not remove all {group}")

    _require(readiness.get("schema") == "kdbg.win11-extended-gui-postboot-readiness.v1" and readiness.get("success") is True,
             "postboot readiness record is not successful")
    backend = readiness.get("backend")
    verifier = readiness.get("verifier")
    services = readiness.get("services")
    _require(isinstance(backend, dict) and backend.get("connected") is True and backend.get("abi_version") == 6 and backend.get("gate_locked") is True,
             "postboot backend readiness is incomplete")
    _require(isinstance(verifier, dict) and verifier.get("exit_code") == 0 and verifier.get("exited_before_gui") is True,
             "postboot verifier did not complete before the GUI")
    _require(isinstance(services, list) and {v.get("name") for v in services if isinstance(v, dict)} == {"KDBG", "KDBGProbe"}
             and all(v.get("status") == "Running" for v in services if isinstance(v, dict)),
             "postboot driver services were not both running")
    _require(probe.get("schema") == "kdbg.live-verify.v1" and probe.get("success") is True,
             "postboot read-only probe record is not successful")
    probe_backend = probe.get("backend")
    probe_cleanup = probe.get("write_cleanup")
    _require(isinstance(probe_backend, dict) and probe_backend.get("connected") is True and probe_backend.get("abi_version") == 6,
             "postboot probe backend identity mismatch")
    _require(isinstance(probe_cleanup, dict) and probe_cleanup.get("final_gate_locked") is True,
             "postboot probe did not finish with the write gate locked")

    capture_archive_sha = _validate_hash(
        capture.get("capture_archive", {}).get("sha256") if isinstance(capture.get("capture_archive"), dict) else None,
        "guest capture archive hash",
    )
    _require(_sha_bytes(record_bytes["captures.zip"]) == capture_archive_sha,
             "guest capture archive hash mismatch")
    with zipfile.ZipFile(io.BytesIO(record_bytes["captures.zip"]), "r") as capture_zip:
        nested_entries = _safe_entries(capture_zip, "guest capture archive")
        _require(len(nested_entries) == 24, "guest capture archive must contain exactly 24 PNGs")
        for item in ordered:
            image = _entry_bytes(capture_zip, nested_entries, item["file"], "guest capture archive")
            _require(_sha_bytes(image) == item["sha256"], f"nested capture hash mismatch: {item['file']}")

    grouped: dict[str, list[dict[str, object]]] = {}
    for item, raw in zip(ordered, raw_captures):
        grouped.setdefault(item["scene_id"], []).append(
            {
                "image": f"{frames_dir.name}/{item['file']}",
                "sha256": item["sha256"],
                "duration_seconds": int(raw["duration_ms"]) / 1000.0,
            }
        )
    scenes: list[dict[str, object]] = []
    for scene_id in dict.fromkeys(scene for _, scene in EXPECTED):
        label, cue, crop = SCENES[scene_id]
        frames = grouped[scene_id]
        if crop is not None:
            for frame in frames:
                frame["crop"] = {"x": crop[0], "y": crop[1], "width": crop[2], "height": crop[3]}
        scenes.append({"id": scene_id, "label": label, "cue": cue, "frames": frames})

    record_hashes = {
        "host_orchestrator_summary": _sha_bytes(host_bytes),
        "host_preflight": _sha_bytes(preflight_bytes),
        "capture_run": _sha_bytes(record_bytes["capture-run.json"]),
        "guest_capture_summary": _sha_bytes(record_bytes["guest-capture-summary.json"]),
        "guest_cleanup": _sha_bytes(record_bytes["guest-cleanup.json"]),
        "postboot_readiness": _sha_bytes(record_bytes["postboot-readiness.json"]),
        "postboot_readonly_probe": _sha_bytes(record_bytes["postboot-readonly-probe.json"]),
    }
    binding = {
        "schema": "kdbg.demo-evidence-binding.v1",
        "capture_status": "CAPTURED_UNREVIEWED",
        "evidence_pass": False,
        "human_review_complete": False,
        "artifacts": {
            "package_sha256": package_sha,
            "symbols_sha256": symbols_sha,
            "certificate_sha256": certificate_sha,
            "source_snapshot_sha256": source_sha,
        },
        "archives": {
            "host_recovered_guest_evidence_sha256": archive_sha,
            "guest_capture_archive_sha256": capture_archive_sha,
        },
        "records": record_hashes,
        "capture_set": {
            "capture_count": 24,
            "scene_count": 20,
            "ordered_capture_set_sha256": _canonical_capture_hash(ordered),
            "captures": ordered,
        },
    }
    manifest = {
        "schema_version": 2,
        "title": "KDBG controlled-VM evidence",
        "fps": 10,
        "evidence_binding": binding,
        "scenes": scenes,
    }

    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    frames_dir.mkdir(parents=True, exist_ok=True)
    for name in sorted(extracted):
        destination = frames_dir / name
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(extracted[name])
        os.replace(temporary, destination)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{output_manifest.name}.", dir=output_manifest.parent)
    os.close(handle)
    temporary_manifest = Path(temporary_name)
    try:
        temporary_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        os.replace(temporary_manifest, output_manifest)
    finally:
        temporary_manifest.unlink(missing_ok=True)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="recovered final Win11 GUI run directory")
    parser.add_argument("--output-manifest", required=True, type=Path, help="new compositor manifest path")
    parser.add_argument("--frames-dir", type=Path, help="new/empty extracted-frame directory; defaults to manifest-dir/frames")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = args.output_manifest.resolve()
    frames = args.frames_dir.resolve() if args.frames_dir else output.parent / "frames"
    try:
        manifest = build_manifest(args.run_dir, output, frames)
    except (DemoError, OSError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": "PASS",
        "manifest": output.name,
        "scene_count": len(manifest["scenes"]),
        "capture_count": manifest["evidence_binding"]["capture_set"]["capture_count"],
        "capture_status": "CAPTURED_UNREVIEWED",
        "human_review_complete": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
