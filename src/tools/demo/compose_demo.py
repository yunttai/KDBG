#!/usr/bin/env python3
"""Deterministically compose and verify KDBG video-only evidence.

The compositor deliberately does not capture a VM.  It turns already captured
PNG evidence into a fixed-layout MP4 and verifies the encoded artifact by
decoding every frame before publishing it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

import cv2
import numpy as np


SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = (1, SCHEMA_VERSION)
REPORT_SCHEMA_VERSION = 2
WIDTH = 1920
HEIGHT = 1080
CODEC = "mp4v"
HEADER_HEIGHT = 132
FOOTER_HEIGHT = 56
BACKGROUND = (24, 16, 11)  # BGR
PANEL = (40, 32, 25)
TEXT = (245, 245, 245)
MUTED_TEXT = (190, 200, 210)
ACCENT = (64, 191, 255)
SAFE_TEXT = re.compile(r"^[\x20-\x7e]+$")
DRIVE_PATH = re.compile(r"(?i)(?:^|\s)[a-z]:[\\/]")
PRIVATE_MARKERS = ("\\users\\", "/users/", "\\home\\", "/home/", "appdata")


class DemoError(RuntimeError):
    """Raised for an invalid manifest or failed artifact verification."""


@dataclass(frozen=True)
class SourceFrame:
    source_name: str
    image_path: Path
    image_sha256: str
    frame_count: int
    crop: tuple[int, int, int, int] | None


@dataclass(frozen=True)
class Scene:
    scene_id: str
    label: str
    cue: str
    source_frames: tuple[SourceFrame, ...]

    @property
    def frame_count(self) -> int:
        return sum(frame.frame_count for frame in self.source_frames)


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    title: str
    fps: float
    scenes: tuple[Scene, ...]
    evidence_binding: dict[str, object] | None

    @property
    def frame_count(self) -> int:
        return sum(scene.frame_count for scene in self.scenes)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_text(value: object, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise DemoError(f"{field} must be a string")
    text = " ".join(value.split())
    if not text or len(text) > maximum or not SAFE_TEXT.fullmatch(text):
        raise DemoError(
            f"{field} must contain 1-{maximum} printable ASCII characters"
        )
    lowered = text.lower()
    if DRIVE_PATH.search(text) or "file://" in lowered or any(
        marker in lowered for marker in PRIVATE_MARKERS
    ):
        raise DemoError(f"{field} must not contain a local or private path")
    return text


def _positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DemoError(f"{field} must be a positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise DemoError(f"{field} must be a positive finite number")
    return result


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise DemoError(f"{field} must be lowercase SHA-256")
    return value


def _basename(value: object, field: str, *, suffix: str | None = None) -> str:
    if not isinstance(value, str) or not value or value in (".", ".."):
        raise DemoError(f"{field} must be a file basename")
    if value != Path(value).name or "/" in value or "\\" in value:
        raise DemoError(f"{field} must not contain a path")
    if suffix is not None and not value.lower().endswith(suffix):
        raise DemoError(f"{field} must end with {suffix}")
    return value


def _validate_evidence_binding(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("schema") != "kdbg.demo-evidence-binding.v1":
        raise DemoError("evidence_binding schema is invalid")
    if value.get("capture_status") != "CAPTURED_UNREVIEWED":
        raise DemoError("evidence_binding must remain CAPTURED_UNREVIEWED")
    if value.get("evidence_pass") is not False or value.get("human_review_complete") is not False:
        raise DemoError("evidence_binding must not claim evidence PASS or human review")

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict):
        raise DemoError("evidence_binding.artifacts must be an object")
    for name in ("package_sha256", "symbols_sha256", "certificate_sha256", "source_snapshot_sha256"):
        _hash(artifacts.get(name), f"evidence_binding.artifacts.{name}")

    archives = value.get("archives")
    if not isinstance(archives, dict):
        raise DemoError("evidence_binding.archives must be an object")
    for name in ("host_recovered_guest_evidence_sha256", "guest_capture_archive_sha256"):
        _hash(archives.get(name), f"evidence_binding.archives.{name}")

    records = value.get("records")
    if not isinstance(records, dict) or not records:
        raise DemoError("evidence_binding.records must be a non-empty object")
    for name, digest in records.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name):
            raise DemoError("evidence_binding.records keys are invalid")
        _hash(digest, f"evidence_binding.records.{name}")

    capture_set = value.get("capture_set")
    if not isinstance(capture_set, dict):
        raise DemoError("evidence_binding.capture_set must be an object")
    if capture_set.get("capture_count") != 24 or capture_set.get("scene_count") != 20:
        raise DemoError("evidence_binding must bind exactly 24 captures and 20 scenes")
    captures = capture_set.get("captures")
    if not isinstance(captures, list) or len(captures) != 24:
        raise DemoError("evidence_binding.capture_set.captures must contain 24 entries")
    canonical: list[dict[str, str]] = []
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict):
            raise DemoError(f"evidence_binding capture {index} must be an object")
        step_id = _safe_text(capture.get("step_id"), f"capture[{index}].step_id", maximum=64)
        scene_id = _safe_text(capture.get("scene_id"), f"capture[{index}].scene_id", maximum=64)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", scene_id):
            raise DemoError(f"capture[{index}].scene_id is invalid")
        filename = _basename(capture.get("file"), f"capture[{index}].file", suffix=".png")
        digest = _hash(capture.get("sha256"), f"capture[{index}].sha256")
        canonical.append({"step_id": step_id, "scene_id": scene_id, "file": filename, "sha256": digest})
    ordered_digest = hashlib.sha256(
        (json.dumps(canonical, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    ).hexdigest()
    if _hash(capture_set.get("ordered_capture_set_sha256"), "ordered_capture_set_sha256") != ordered_digest:
        raise DemoError("evidence_binding ordered capture-set hash mismatch")
    return value


def _load_crop(value: object, field: str) -> tuple[int, int, int, int] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"x", "y", "width", "height"}:
        raise DemoError(f"{field} must contain x, y, width, and height")
    numbers: list[int] = []
    for name in ("x", "y", "width", "height"):
        item = value[name]
        if isinstance(item, bool) or not isinstance(item, int):
            raise DemoError(f"{field}.{name} must be an integer")
        numbers.append(item)
    x, y, width, height = numbers
    if x < 0 or y < 0 or width < 1 or height < 1:
        raise DemoError(f"{field} must be a positive source-coordinate rectangle")
    return x, y, width, height


def _resolve_image(base: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise DemoError(f"{field} must be a PNG path")
    candidate = Path(value)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        if any(part == ".." for part in candidate.parts):
            raise DemoError(f"{field} contains path traversal")
        resolved = (base / candidate).resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise DemoError(f"{field} escapes the image root") from exc
    if resolved.suffix.lower() != ".png" or not resolved.is_file():
        raise DemoError(f"{field} does not reference an existing PNG")
    return resolved


def load_manifest(manifest_path: Path, image_root: Path | None) -> Manifest:
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DemoError(f"unable to read scene manifest: {exc}") from exc

    if not isinstance(raw, dict) or raw.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise DemoError(
            f"scene manifest schema_version must be one of {SUPPORTED_SCHEMA_VERSIONS}"
        )
    schema_version = int(raw["schema_version"])

    title = _safe_text(raw.get("title", "KDBG evidence demonstration"), "title", maximum=80)
    fps = _positive_number(raw.get("fps", 10), "fps")
    if fps > 60:
        raise DemoError("fps must not exceed 60")

    raw_scenes = raw.get("scenes")
    if not isinstance(raw_scenes, list) or not raw_scenes:
        raise DemoError("scenes must be a non-empty array")

    base = image_root.resolve() if image_root else manifest_path.resolve().parent
    scenes: list[Scene] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_scenes):
        if not isinstance(item, dict):
            raise DemoError(f"scenes[{index}] must be an object")
        scene_id = _safe_text(item.get("id"), f"scenes[{index}].id", maximum=48)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", scene_id):
            raise DemoError(f"scenes[{index}].id must use lowercase letters, digits, '-' or '_'")
        if scene_id in seen_ids:
            raise DemoError(f"duplicate scene id: {scene_id}")
        seen_ids.add(scene_id)

        label = _safe_text(item.get("label"), f"scenes[{index}].label", maximum=100)
        cue = _safe_text(item.get("cue", "Evidence frame"), f"scenes[{index}].cue", maximum=120)
        raw_frames = item.get("frames")
        if raw_frames is None:
            raw_frames = [
                {
                    "image": item.get("image"),
                    "sha256": item.get("sha256"),
                    "crop": item.get("crop"),
                    "duration_seconds": item.get("duration_seconds", 2),
                }
            ]
        if not isinstance(raw_frames, list) or not raw_frames:
            raise DemoError(f"scenes[{index}].frames must be a non-empty array")
        source_frames: list[SourceFrame] = []
        for frame_index, raw_frame in enumerate(raw_frames):
            if not isinstance(raw_frame, dict):
                raise DemoError(f"scenes[{index}].frames[{frame_index}] must be an object")
            prefix = f"scenes[{index}].frames[{frame_index}]"
            image_path = _resolve_image(base, raw_frame.get("image"), f"{prefix}.image")
            actual_digest = _sha256(image_path)
            expected_digest = raw_frame.get("sha256")
            if expected_digest is not None and _hash(expected_digest, f"{prefix}.sha256") != actual_digest:
                raise DemoError(f"scene '{scene_id}' PNG hash mismatch")
            duration = _positive_number(
                raw_frame.get("duration_seconds", 2), f"{prefix}.duration_seconds"
            )
            frame_count = int(round(duration * fps))
            if frame_count < 1:
                raise DemoError(f"scene '{scene_id}' frame duration produces no frames")
            source_frames.append(
                SourceFrame(
                    source_name=image_path.name,
                    image_path=image_path,
                    image_sha256=actual_digest,
                    frame_count=frame_count,
                    crop=_load_crop(raw_frame.get("crop"), f"{prefix}.crop"),
                )
            )
        scenes.append(
            Scene(
                scene_id=scene_id,
                label=label,
                cue=cue,
                source_frames=tuple(source_frames),
            )
        )

    evidence_binding = None
    if raw.get("evidence_binding") is not None:
        evidence_binding = _validate_evidence_binding(raw["evidence_binding"])
        expected_frames = [
            (capture["scene_id"], capture["file"], capture["sha256"])
            for capture in evidence_binding["capture_set"]["captures"]
        ]
        actual_frames = [
            (scene.scene_id, source_frame.source_name, source_frame.image_sha256)
            for scene in scenes
            for source_frame in scene.source_frames
        ]
        if actual_frames != expected_frames:
            raise DemoError("scene frames do not match the ordered evidence binding")
    manifest = Manifest(
        schema_version=schema_version,
        title=title,
        fps=fps,
        scenes=tuple(scenes),
        evidence_binding=evidence_binding,
    )
    if manifest.frame_count > 60 * 60 * fps:
        raise DemoError("video duration must not exceed one hour")
    return manifest


def _fit_text(text: str, maximum_width: int, preferred_scale: float, minimum_scale: float) -> float:
    scale = preferred_scale
    while scale > minimum_scale:
        width, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, scale, 2)[0]
        if width <= maximum_width:
            return scale
        scale -= 0.05
    return minimum_scale


def _put_text(frame: np.ndarray, text: str, origin: tuple[int, int], scale: float, color: tuple[int, int, int]) -> None:
    cv2.putText(
        frame,
        text,
        origin,
        cv2.FONT_HERSHEY_SIMPLEX,
        scale,
        color,
        2,
        cv2.LINE_AA,
    )


def render_scene_frame(
    manifest: Manifest,
    scene: Scene,
    index: int,
    source_frame: SourceFrame | None = None,
) -> np.ndarray:
    selected = source_frame or scene.source_frames[0]
    source = cv2.imread(str(selected.image_path), cv2.IMREAD_COLOR)
    if source is None or source.ndim != 3 or source.shape[2] != 3:
        raise DemoError(f"scene '{scene.scene_id}' PNG could not be decoded as RGB")

    if selected.crop is not None:
        crop_x, crop_y, crop_width, crop_height = selected.crop
        source_height, source_width = source.shape[:2]
        if crop_x + crop_width > source_width or crop_y + crop_height > source_height:
            raise DemoError(f"scene '{scene.scene_id}' crop exceeds the source PNG")
        source = source[crop_y : crop_y + crop_height, crop_x : crop_x + crop_width]

    frame = np.full((HEIGHT, WIDTH, 3), BACKGROUND, dtype=np.uint8)
    frame[:HEADER_HEIGHT, :] = PANEL
    frame[HEIGHT - FOOTER_HEIGHT :, :] = PANEL

    content_top = HEADER_HEIGHT
    content_height = HEIGHT - HEADER_HEIGHT - FOOTER_HEIGHT
    src_height, src_width = source.shape[:2]
    scale = min(WIDTH / src_width, content_height / src_height)
    resized_width = max(1, int(round(src_width * scale)))
    resized_height = max(1, int(round(src_height * scale)))
    interpolation = cv2.INTER_AREA if scale < 1.0 else cv2.INTER_CUBIC
    resized = cv2.resize(source, (resized_width, resized_height), interpolation=interpolation)
    x = (WIDTH - resized_width) // 2
    y = content_top + (content_height - resized_height) // 2
    frame[y : y + resized_height, x : x + resized_width] = resized

    label_scale = _fit_text(scene.label, WIDTH - 330, 1.12, 0.72)
    cue_scale = _fit_text(scene.cue, WIDTH - 96, 0.72, 0.52)
    _put_text(frame, scene.label, (48, 56), label_scale, TEXT)
    _put_text(frame, scene.cue, (48, 105), cue_scale, MUTED_TEXT)
    scene_counter = f"{index + 1:02d}/{len(manifest.scenes):02d}"
    _put_text(frame, scene_counter, (WIDTH - 176, 62), 0.88, ACCENT)

    footer = f"{manifest.title} | controlled VM evidence | {scene.scene_id}"
    footer_scale = _fit_text(footer, WIDTH - 96, 0.60, 0.42)
    _put_text(frame, footer, (48, HEIGHT - 18), footer_scale, MUTED_TEXT)
    return frame


def iter_frames(manifest: Manifest) -> Iterator[tuple[int, np.ndarray]]:
    for scene_index, scene in enumerate(manifest.scenes):
        for source_frame in scene.source_frames:
            frame = render_scene_frame(manifest, scene, scene_index, source_frame)
            for _ in range(source_frame.frame_count):
                # Consumers must not mutate a shared scene buffer.
                yield scene_index, frame.copy()


def _temporary_path(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(
        prefix=f".{destination.stem}.", suffix=destination.suffix, dir=destination.parent
    )
    os.close(handle)
    path = Path(name)
    path.unlink()
    return path


def verify_video(path: Path, expected_fps: float, expected_frames: int) -> dict[str, object]:
    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        raise DemoError("encoded MP4 could not be opened")
    advertised_fps = float(capture.get(cv2.CAP_PROP_FPS))
    advertised_frames = int(round(capture.get(cv2.CAP_PROP_FRAME_COUNT)))
    decoded_frames = 0
    dimensions_ok = True
    while True:
        ok, frame = capture.read()
        if not ok:
            break
        decoded_frames += 1
        dimensions_ok = dimensions_ok and frame.shape[:2] == (HEIGHT, WIDTH)
    capture.release()

    fps_ok = math.isclose(advertised_fps, expected_fps, rel_tol=0.0, abs_tol=0.05)
    frame_count_ok = decoded_frames == expected_frames and advertised_frames == expected_frames
    if not dimensions_ok or not fps_ok or not frame_count_ok:
        raise DemoError(
            "encoded MP4 verification failed: "
            f"dimensions_ok={dimensions_ok}, fps={advertised_fps}, "
            f"advertised_frames={advertised_frames}, decoded_frames={decoded_frames}"
        )
    return {
        "open": True,
        "dimensions": {"width": WIDTH, "height": HEIGHT, "pass": True},
        "fps": {"expected": expected_fps, "actual": advertised_fps, "pass": True},
        "frame_count": {
            "expected": expected_frames,
            "advertised": advertised_frames,
            "decoded": decoded_frames,
            "pass": True,
        },
        "duration_seconds": {
            "expected": expected_frames / expected_fps,
            "actual": decoded_frames / advertised_fps,
            "pass": math.isclose(
                decoded_frames / advertised_fps,
                expected_frames / expected_fps,
                rel_tol=0.0,
                abs_tol=max(0.05, 1.0 / expected_fps),
            ),
        },
    }


def _save_gif(
    frames: Sequence[np.ndarray], frame_counts: Sequence[int], path: Path, fps: float
) -> None:
    from PIL import Image

    if not frames or len(frames) != len(frame_counts):
        raise DemoError("GIF requires at least one rendered frame")
    images = [Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)) for frame in frames]
    durations = [max(1, int(round(frame_count * 1000.0 / fps))) for frame_count in frame_counts]
    temporary = _temporary_path(path)
    try:
        images[0].save(
            temporary,
            format="GIF",
            save_all=True,
            append_images=images[1:],
            duration=durations,
            loop=0,
            optimize=False,
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _save_contact_sheet(frames: Sequence[np.ndarray], path: Path) -> None:
    from PIL import Image, ImageDraw

    if not frames:
        raise DemoError("contact sheet requires at least one rendered frame")
    thumbnail_width = 480
    thumbnail_height = 270
    columns = min(3, len(frames))
    rows = int(math.ceil(len(frames) / columns))
    sheet = Image.new("RGB", (columns * thumbnail_width, rows * thumbnail_height), "#0b1018")
    draw = ImageDraw.Draw(sheet)
    for index, frame in enumerate(frames):
        image = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        image = image.resize((thumbnail_width, thumbnail_height), Image.Resampling.LANCZOS)
        x = (index % columns) * thumbnail_width
        y = (index // columns) * thumbnail_height
        sheet.paste(image, (x, y))
        draw.rectangle((x, y, x + 42, y + 24), fill="#192028")
        draw.text((x + 8, y + 5), f"{index + 1:02d}", fill="#ffffff")
    temporary = _temporary_path(path)
    try:
        sheet.save(temporary, format="PNG", optimize=False, compress_level=9)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _artifact_record(path: Path) -> dict[str, object]:
    return {"name": path.name, "sha256": _sha256(path), "byte_size": path.stat().st_size}


def compose(
    manifest: Manifest,
    output: Path,
    report_path: Path,
    gif_path: Path | None,
    contact_sheet_path: Path | None,
) -> dict[str, object]:
    output = output.resolve()
    report_path = report_path.resolve()
    if output.suffix.lower() != ".mp4":
        raise DemoError("output must use the .mp4 extension")
    if report_path.suffix.lower() != ".json":
        raise DemoError("report must use the .json extension")
    if gif_path is not None and gif_path.suffix.lower() != ".gif":
        raise DemoError("GIF output must use the .gif extension")
    if contact_sheet_path is not None and contact_sheet_path.suffix.lower() != ".png":
        raise DemoError("contact-sheet output must use the .png extension")
    destinations = [output, report_path]
    destinations.extend(path.resolve() for path in (gif_path, contact_sheet_path) if path is not None)
    if len(destinations) != len(set(destinations)):
        raise DemoError("output destinations must be distinct")

    temporary_video = _temporary_path(output)
    writer = cv2.VideoWriter(
        str(temporary_video),
        cv2.VideoWriter_fourcc(*CODEC),
        manifest.fps,
        (WIDTH, HEIGHT),
    )
    if not writer.isOpened():
        temporary_video.unlink(missing_ok=True)
        raise DemoError("OpenCV could not open an mp4v VideoWriter")

    representative_frames: dict[int, np.ndarray] = {}
    try:
        for scene_index, frame in iter_frames(manifest):
            writer.write(frame)
            representative_frames.setdefault(scene_index, frame)
    except Exception:
        writer.release()
        temporary_video.unlink(missing_ok=True)
        raise
    writer.release()

    verification = verify_video(temporary_video, manifest.fps, manifest.frame_count)
    os.replace(temporary_video, output)

    companions: list[dict[str, object]] = []
    ordered = [representative_frames[index] for index in range(len(manifest.scenes))]
    if gif_path is not None:
        gif_path = gif_path.resolve()
        _save_gif(ordered, [scene.frame_count for scene in manifest.scenes], gif_path, manifest.fps)
        companions.append(
            {
                "type": "gif",
                "timing": "one exact rendered representative frame per scene with accumulated duration",
                **_artifact_record(gif_path),
            }
        )
    if contact_sheet_path is not None:
        contact_sheet_path = contact_sheet_path.resolve()
        _save_contact_sheet(ordered, contact_sheet_path)
        companions.append({"type": "contact_sheet", **_artifact_record(contact_sheet_path)})

    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "PASS",
        "scope": "offline compositor verification only; no live-VM claim",
        "review": {
            "capture_status": (
                manifest.evidence_binding.get("capture_status")
                if manifest.evidence_binding is not None
                else "UNBOUND_MEDIA_ONLY"
            ),
            "evidence_pass": False,
            "human_review_complete": False,
        },
        "renderer": {
            "codec": CODEC,
            "opencv_version": cv2.__version__,
            "width": WIDTH,
            "height": HEIGHT,
            "fps": manifest.fps,
        },
        "manifest": {
            "schema_version": manifest.schema_version,
            "title": manifest.title,
            "scene_count": len(manifest.scenes),
            "frame_count": manifest.frame_count,
            "scenes": [
                {
                    "id": scene.scene_id,
                    "label": scene.label,
                    "cue": scene.cue,
                    "source_frames": [
                        {
                            "source_name": source_frame.source_name,
                            "source_png_sha256": source_frame.image_sha256,
                            "crop": (
                                {
                                    "x": source_frame.crop[0],
                                    "y": source_frame.crop[1],
                                    "width": source_frame.crop[2],
                                    "height": source_frame.crop[3],
                                }
                                if source_frame.crop is not None
                                else None
                            ),
                            "frame_count": source_frame.frame_count,
                        }
                        for source_frame in scene.source_frames
                    ],
                    "frame_count": scene.frame_count,
                }
                for scene in manifest.scenes
            ],
        },
        "evidence_binding": manifest.evidence_binding,
        "artifact": {"type": "mp4", **_artifact_record(output)},
        "verification": verification,
        "companions": companions,
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_report = _temporary_path(report_path)
    try:
        temporary_report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        os.replace(temporary_report, report_path)
    finally:
        temporary_report.unlink(missing_ok=True)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="ordered JSON scene manifest")
    parser.add_argument("--image-root", type=Path, help="base directory for relative PNG paths")
    parser.add_argument("--output", required=True, type=Path, help="destination 1920x1080 MP4")
    parser.add_argument("--report", required=True, type=Path, help="destination JSON verification report")
    parser.add_argument("--gif", type=Path, help="optional full-frame companion GIF")
    parser.add_argument("--contact-sheet", type=Path, help="optional one-frame-per-scene PNG")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest.resolve(), args.image_root)
        report = compose(
            manifest=manifest,
            output=args.output,
            report_path=args.report,
            gif_path=args.gif,
            contact_sheet_path=args.contact_sheet,
        )
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
