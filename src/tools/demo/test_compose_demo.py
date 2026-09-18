from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

import compose_demo


class ComposeDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.frames = self.root / "frames"
        self.frames.mkdir()
        self._write_png("01.png", (25, 60, 180))
        self._write_png("02.png", (40, 170, 80))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_png(self, name: str, color: tuple[int, int, int]) -> None:
        image = Image.new("RGB", (640, 360), color)
        image.save(self.frames / name, format="PNG", compress_level=9)

    def _write_manifest(self, *, title: str = "KDBG deterministic demo") -> Path:
        path = self.root / "scenes.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "title": title,
                    "fps": 5,
                    "scenes": [
                        {
                            "id": "pfn-read",
                            "label": "PFN discovery and exact 4 KiB read",
                            "cue": "Probe page selected; baseline visible",
                            "image": "01.png",
                            "duration_seconds": 0.4,
                        },
                        {
                            "id": "readback",
                            "label": "Apply and full read-back match",
                            "cue": "One-shot write consumed; 4096/4096 bytes verified",
                            "image": "02.png",
                            "duration_seconds": 0.6,
                        },
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def test_compose_verify_and_companions_are_deterministic(self) -> None:
        manifest_path = self._write_manifest()
        manifest = compose_demo.load_manifest(manifest_path, self.frames)

        hashes: list[str] = []
        for suffix in ("a", "b"):
            output = self.root / f"demo-{suffix}.mp4"
            report_path = self.root / f"demo-{suffix}.json"
            gif_path = self.root / f"demo-{suffix}.gif"
            sheet_path = self.root / f"demo-{suffix}-sheet.png"
            report = compose_demo.compose(
                manifest,
                output,
                report_path,
                gif_path,
                sheet_path,
            )
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["manifest"]["frame_count"], 5)
            self.assertEqual(report["verification"]["frame_count"]["decoded"], 5)
            self.assertEqual(report["verification"]["dimensions"]["width"], 1920)
            self.assertNotIn(str(self.root), report_path.read_text(encoding="utf-8"))
            self.assertTrue(gif_path.is_file())
            self.assertTrue(sheet_path.is_file())
            hashes.append(report["artifact"]["sha256"])

        self.assertEqual(hashes[0], hashes[1])

        capture = cv2.VideoCapture(str(self.root / "demo-a.mp4"))
        ok, decoded = capture.read()
        capture.release()
        self.assertTrue(ok)
        self.assertEqual(decoded.shape, (1080, 1920, 3))

    def test_rejects_private_path_in_rendered_label(self) -> None:
        manifest_path = self._write_manifest(title=r"Captured from C:\Users\private")
        with self.assertRaisesRegex(compose_demo.DemoError, "private path"):
            compose_demo.load_manifest(manifest_path, self.frames)

    def test_rejects_missing_png(self) -> None:
        manifest_path = self._write_manifest()
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["scenes"][0]["image"] = "missing.png"
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(compose_demo.DemoError, "existing PNG"):
            compose_demo.load_manifest(manifest_path, self.frames)

    def test_rejects_png_hash_mismatch_and_path_traversal(self) -> None:
        manifest_path = self._write_manifest()
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["schema_version"] = 2
        raw["scenes"][0]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(compose_demo.DemoError, "PNG hash mismatch"):
            compose_demo.load_manifest(manifest_path, self.frames)

        raw["scenes"][0].pop("sha256")
        raw["scenes"][0]["image"] = "../outside.png"
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(compose_demo.DemoError, "path traversal"):
            compose_demo.load_manifest(manifest_path, self.frames)

    def test_source_coordinate_crop_is_zoomed_and_bounds_checked(self) -> None:
        manifest_path = self._write_manifest()
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["schema_version"] = 2
        raw["scenes"][0]["crop"] = {"x": 320, "y": 0, "width": 320, "height": 360}
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        manifest = compose_demo.load_manifest(manifest_path, self.frames)
        frame = compose_demo.render_scene_frame(manifest, manifest.scenes[0], 0)
        self.assertEqual(frame.shape, (1080, 1920, 3))

        raw["scenes"][0]["crop"] = {"x": 600, "y": 0, "width": 320, "height": 360}
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        invalid = compose_demo.load_manifest(manifest_path, self.frames)
        with self.assertRaisesRegex(compose_demo.DemoError, "crop exceeds"):
            compose_demo.render_scene_frame(invalid, invalid.scenes[0], 0)

    def test_rendered_frame_has_expected_layout(self) -> None:
        manifest = compose_demo.load_manifest(self._write_manifest(), self.frames)
        frame = compose_demo.render_scene_frame(manifest, manifest.scenes[0], 0)
        self.assertEqual(frame.shape, (1080, 1920, 3))
        self.assertEqual(frame.dtype, np.uint8)
        self.assertGreater(int(frame[: compose_demo.HEADER_HEIGHT].std()), 0)


if __name__ == "__main__":
    unittest.main()
