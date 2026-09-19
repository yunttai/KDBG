from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from PIL import Image

import build_gui_demo_manifest
import compose_demo


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
    return stream.getvalue()


class GuiDemoManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.package_sha = "1" * 64
        self.symbols_sha = "2" * 64
        self.certificate_sha = "3" * 64
        self.source_sha = "4" * 64
        self._write_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _png(self, index: int) -> bytes:
        stream = io.BytesIO()
        Image.new("RGB", (1024, 768), (index * 7 % 255, index * 11 % 255, index * 17 % 255)).save(
            stream, format="PNG", compress_level=9
        )
        return stream.getvalue()

    def _write_fixture(
        self,
        *,
        extra_entry: tuple[str, bytes] | None = None,
        abi_version: int = 6,
    ) -> None:
        captures: list[dict[str, object]] = []
        images: dict[str, bytes] = {}
        for index, (step_id, scene_id) in enumerate(build_gui_demo_manifest.EXPECTED, 1):
            filename = f"{step_id}.png"
            image = self._png(index)
            images[filename] = image
            captures.append(
                {
                    "step_id": step_id,
                    "scene_id": scene_id,
                    "phase": "fixture",
                    "duration_ms": 100,
                    "file": filename,
                    "sha256": sha(image),
                    "width": 1024,
                    "height": 768,
                }
            )
        capture_archive = zip_bytes(images)
        capture_run = {
            "schema": "kdbg.win11-extended-gui-capture-result.v1",
            "harness_valid": True,
            "live_capture_status": "CAPTURED_UNREVIEWED",
            "evidence_pass": False,
            "human_review_complete": False,
            "calibration_smoke": False,
            "capture_count": 24,
            "frame_count": 24,
            "scene_count": 20,
            "captures": captures,
            "capture_archive": {"path": r"C:\evidence\captures.zip", "sha256": sha(capture_archive)},
        }
        guest_summary = {
            "schema": "kdbg.win11-extended-gui-guest-capture.v1",
            "success": True,
            "mode": "full",
            "capture_status": "CAPTURED_UNREVIEWED",
            "capture_count": 24,
            "scene_count": 20,
            "package_sha256": self.package_sha,
            "source_snapshot_sha256": self.source_sha,
            "evidence_pass": False,
            "human_review_complete": False,
        }
        cleanup = {
            "schema": "kdbg.win11-extended-gui-guest-cleanup.v1",
            "success": True,
            "autologon_secret_present": False,
            "tasks": [{"name": "task", "present": False}],
            "services": [{"name": "KDBG", "present": False}, {"name": "KDBGProbe", "present": False}],
            "errors": [],
        }
        readiness = {
            "schema": "kdbg.win11-extended-gui-postboot-readiness.v1",
            "success": True,
            "services": [{"name": "KDBG", "status": "Running"}, {"name": "KDBGProbe", "status": "Running"}],
            "verifier": {"exit_code": 0, "exited_before_gui": True},
            "backend": {
                "connected": True,
                "abi_version": abi_version,
                "gate_locked": True,
                **({"supports_physical_page_compare_write": True}
                   if abi_version == 7 else {}),
            },
        }
        probe = {
            "schema": "kdbg.live-verify.v1",
            "success": True,
            "backend": {
                "connected": True,
                "abi_version": abi_version,
                **({"supports_physical_page_compare_write": True}
                   if abi_version == 7 else {}),
            },
            "write_cleanup": {"final_gate_locked": True},
        }
        guest_entries = {
            "capture-run.json": json_bytes(capture_run),
            "guest-capture-summary.json": json_bytes(guest_summary),
            "guest-cleanup.json": json_bytes(cleanup),
            "postboot-readiness.json": json_bytes(readiness),
            "postboot-readonly-probe.json": json_bytes(probe),
            "captures.zip": capture_archive,
        }
        guest_entries.update({f"captures/{name}": value for name, value in images.items()})
        if extra_entry is not None:
            guest_entries[extra_entry[0]] = extra_entry[1]
        guest_archive = zip_bytes(guest_entries)
        (self.run / "guest-evidence.zip").write_bytes(guest_archive)
        host = {
            "schema": "kdbg.win11-extended-gui-host-orchestrator.v1",
            "success": True,
            "execution_status": "CAPTURED_UNREVIEWED",
            "capture_mode": "full",
            "vm": {"final_off": True},
            "checkpoint": {"restored": True},
            "capture_succeeded": True,
            "postboot_readiness_succeeded": True,
            "guest_cleanup_succeeded": True,
            "evidence_recovered": True,
            "autologon_secret_cleared_after_explorer": True,
            "evidence_pass": False,
            "human_review_complete": False,
            "guest_evidence_archive": {"file": "guest-evidence.zip", "sha256": sha(guest_archive)},
            "primary_error": None,
            "cleanup_errors": [],
        }
        preflight = {
            "schema": "kdbg.win11-extended-gui-host-preflight.v1",
            "artifacts": {
                "package": {"sha256": self.package_sha},
                "symbols": {"sha256": self.symbols_sha},
                "certificate": {"sha256": self.certificate_sha},
                "source_snapshot_sha256": self.source_sha,
            },
        }
        (self.run / "host-orchestrator-summary.json").write_bytes(json_bytes(host))
        (self.run / "host-preflight.json").write_bytes(json_bytes(preflight))

    def test_builds_bound_20_scene_manifest_and_composes(self) -> None:
        manifest_path = self.root / "demo" / "scenes.json"
        frames = self.root / "demo" / "frames"
        raw = build_gui_demo_manifest.build_manifest(self.run, manifest_path, frames)
        second_manifest = self.root / "demo-second" / "scenes.json"
        build_gui_demo_manifest.build_manifest(
            self.run, second_manifest, self.root / "demo-second" / "frames"
        )
        self.assertEqual(len(raw["scenes"]), 20)
        self.assertEqual(sum(len(scene["frames"]) for scene in raw["scenes"]), 24)
        self.assertEqual(len(list(frames.glob("*.png"))), 24)
        self.assertNotIn(str(self.root), manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest_path.read_bytes(), second_manifest.read_bytes())
        self.assertFalse(raw["evidence_binding"]["human_review_complete"])

        manifest = compose_demo.load_manifest(manifest_path, None)
        self.assertEqual(manifest.frame_count, 24)
        report = compose_demo.compose(
            manifest,
            self.root / "bound.mp4",
            self.root / "bound.report.json",
            None,
            None,
        )
        self.assertEqual(report["verification"]["frame_count"]["decoded"], 24)
        self.assertEqual(report["evidence_binding"]["artifacts"]["package_sha256"], self.package_sha)
        self.assertFalse(report["review"]["human_review_complete"])

    def test_accepts_current_abi7_capture_contract(self) -> None:
        self._write_fixture(abi_version=7)
        raw = build_gui_demo_manifest.build_manifest(
            self.run,
            self.root / "abi7" / "scenes.json",
            self.root / "abi7" / "frames",
        )
        self.assertEqual(len(raw["scenes"]), 20)

    def test_rejects_capture_hash_mismatch(self) -> None:
        archive_path = self.run / "guest-evidence.zip"
        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}
        entries["captures/01-driver-probe-ready.png"] = b"tampered"
        guest_archive = zip_bytes(entries)
        archive_path.write_bytes(guest_archive)
        host_path = self.run / "host-orchestrator-summary.json"
        host = json.loads(host_path.read_text(encoding="utf-8"))
        host["guest_evidence_archive"]["sha256"] = sha(guest_archive)
        host_path.write_bytes(json_bytes(host))
        with self.assertRaisesRegex(compose_demo.DemoError, "PNG hash mismatch"):
            build_gui_demo_manifest.build_manifest(
                self.run, self.root / "bad.json", self.root / "bad-frames"
            )

    def test_compositor_rejects_frames_detached_from_evidence_binding(self) -> None:
        manifest_path = self.root / "demo" / "scenes.json"
        build_gui_demo_manifest.build_manifest(
            self.run, manifest_path, self.root / "demo" / "frames"
        )
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        undo_scene = next(scene for scene in raw["scenes"] if scene["id"] == "undo_redo")
        undo_scene["frames"][0], undo_scene["frames"][1] = (
            undo_scene["frames"][1], undo_scene["frames"][0]
        )
        detached = self.root / "demo" / "detached.json"
        detached.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(compose_demo.DemoError, "ordered evidence binding"):
            compose_demo.load_manifest(detached, None)

    def test_rejects_archive_path_traversal(self) -> None:
        self._write_fixture(extra_entry=("../escape.txt", b"no"))
        with self.assertRaisesRegex(compose_demo.DemoError, "unsafe or duplicate"):
            build_gui_demo_manifest.build_manifest(
                self.run, self.root / "bad.json", self.root / "bad-frames"
            )


if __name__ == "__main__":
    unittest.main()
