# KDBG video-only evidence compositor

`build_gui_demo_manifest.py` validates one recovered **final** Win11 GUI run,
extracts its 24 hash-checked PNGs, and emits a 20-scene compositor manifest.
`compose_demo.py` converts that manifest into a verified 1920x1080 MP4. Neither
tool starts, connects to, or modifies a VM.

The builder fails closed unless all of these facts agree:

- the host orchestrator succeeded in `full` mode with status
  `CAPTURED_UNREVIEWED`;
- postboot readiness completed before the GUI, both driver services ran, ABI 6
  was connected, and the write gate was locked;
- guest cleanup succeeded with no remaining harness tasks, services, or
  AutoLogon secret;
- the exact checkpoint was restored and the final VM state was Off;
- host preflight package/symbol/certificate/source hashes match the guest
  summary;
- the recovered guest evidence ZIP and its nested capture ZIP match their
  recorded hashes; and
- exactly 24 ordered 1024x768 PNGs, covering the required 20 scenes, match both
  archives and every per-frame SHA-256.

Unsafe ZIP names, duplicate names, path traversal, missing records, count/order
drift, and any hash mismatch are rejected. The resulting evidence binding is
carried into the compositor report but is never rendered onto a video frame.
It deliberately keeps `evidence_pass` and `human_review_complete` false.

The tool writes the video with OpenCV's `mp4v` codec, decodes every encoded
frame, verifies dimensions/FPS/frame count/duration, computes SHA-256, and then
publishes the MP4 and JSON report with atomic replacement. Reports contain
artifact basenames and source PNG hashes, not source or destination paths.
Rendered title/label/cue values are printable ASCII and reject common private
path forms. Schema 2 scenes may contain multiple ordered source frames and an
optional source-coordinate crop. Crops zoom existing pixels only and are bounds
checked after the PNG is decoded.

## Usage

For final Win11 evidence, first build the bound manifest from a fresh output
directory:

```powershell
python .\src\tools\demo\build_gui_demo_manifest.py `
  --run-dir .\out\win11-gui-final\run-YYYYMMDDTHHMMSSZ-xxxxxxxx `
  --output-manifest .\out\demo\scenes.json `
  --frames-dir .\out\demo\frames
```

The frames directory must be a direct child of the manifest directory. This
keeps every image reference portable and traversal-free; the compositor can
therefore resolve the generated manifest without `--image-root`.

Then compose the media:

```powershell
python .\src\tools\demo\compose_demo.py `
  --manifest .\out\demo\scenes.json `
  --output .\out\demo\KDBG-demo.mp4 `
  --report .\out\demo\KDBG-demo.report.json `
  --gif .\out\demo\KDBG-demo.gif `
  --contact-sheet .\out\demo\KDBG-demo.contact-sheet.png
```

The 20-scene manifest preserves all 24 captures: repeated undo/redo, scan, and
freeze states are sequential source frames inside their shared scene. The GIF
and contact sheet use the first exact rendered representative frame per scene.
The GIF preserves each scene's accumulated duration instead of retaining
duplicate full-HD frames in memory.

The compositor's `PASS` means that the MP4 fully decoded with the requested
dimensions, FPS, duration, and frame count. It does not convert the bound
`CAPTURED_UNREVIEWED` run into a human-reviewed evidence PASS; a human must
still review readability, privacy, and claim accuracy.

## Deterministic self-test

```powershell
python -m unittest discover -s .\src\tools\demo -p "test_*.py" -v
```

The tests create a synthetic 24-frame host/guest evidence chain, validate both
archives, build and compose its 20-scene manifest, exercise traversal and hash
tampering failures, render twice, check equal MP4 hashes, fully decode the
output, exercise both Pillow companions, and verify that private paths are
rejected from rendered labels.
