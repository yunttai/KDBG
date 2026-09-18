from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import source_snapshot


class SourceSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "tree"
        self.root.mkdir()
        self.scope_path = self.base / "scope.json"
        self.manifest = self.base / "SOURCE-SHA256SUMS.txt"
        self.metadata = self.base / "SOURCE-MANIFEST.json"
        self._write_scope()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_scope(self) -> None:
        self.scope_path.write_text(
            json.dumps(
                {
                    "schema": "kdbg.source-scope.v1",
                    "scope_version": "fixture.v1",
                    "include": ["README.md", "src/**"],
                    "exclude": ["**/__pycache__/**", "**/*.obj"],
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def _write(self, relative: str, content: bytes) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def _seed(self) -> None:
        self._write("README.md", b"fixture\n")
        self._write("src/zeta.txt", b"z\n")
        self._write("src/alpha.txt", b"a\n")

    def test_include_exclude_and_scope_binding(self) -> None:
        self._seed()
        self._write("ignored.txt", b"outside scope")
        self._write("src/cache.obj", b"excluded extension")
        self._write("src/__pycache__/cache.pyc", b"excluded directory")
        scope = source_snapshot.load_scope(self.scope_path)
        snapshot = source_snapshot.capture_tree(self.root, scope)
        self.assertEqual(
            [record.path for record in snapshot.records],
            ["README.md", "src/alpha.txt", "src/zeta.txt"],
        )
        metadata = source_snapshot.build_metadata(snapshot, scope)
        self.assertEqual(metadata["count"], 3)
        self.assertEqual(metadata["scope_version"], "fixture.v1")
        self.assertEqual(metadata["scope_sha256"], scope.sha256)

    def test_manifest_is_lf_sorted_and_repeatable(self) -> None:
        self._seed()
        first = source_snapshot.write_snapshot(
            self.root, self.scope_path, self.manifest, self.metadata)
        first_bytes = self.manifest.read_bytes()
        first_metadata = self.metadata.read_bytes()
        second = source_snapshot.write_snapshot(
            self.root, self.scope_path, self.manifest, self.metadata)
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first_bytes, self.manifest.read_bytes())
        self.assertEqual(first_metadata, self.metadata.read_bytes())
        self.assertNotIn(b"\r", first_bytes)
        self.assertTrue(first_bytes.endswith(b"\n"))
        paths = [line.split("  ", 1)[1] for line in first_bytes.decode().splitlines()]
        self.assertEqual(paths, sorted(paths))

    def test_content_and_path_changes_are_reported(self) -> None:
        self._seed()
        after = self.base / "after"
        shutil.copytree(self.root, after)
        (after / "src/alpha.txt").write_bytes(b"changed\n")
        (after / "src/zeta.txt").rename(after / "src/renamed.txt")
        diff = source_snapshot.assert_equal_trees(self.root, after, self.scope_path)
        self.assertFalse(diff.equal)
        self.assertEqual(diff.changed, ("src/alpha.txt",))
        self.assertEqual(diff.missing_from_after, ("src/zeta.txt",))
        self.assertEqual(diff.extra_in_after, ("src/renamed.txt",))

    def test_verify_rejects_missing_extra_and_tampered_files(self) -> None:
        self._seed()
        source_snapshot.write_snapshot(
            self.root, self.scope_path, self.manifest, self.metadata)

        verified = source_snapshot.verify_snapshot(
            self.root, self.scope_path, self.manifest, self.metadata)
        self.assertEqual(verified.count, 3)

        (self.root / "src/alpha.txt").unlink()
        with self.assertRaisesRegex(source_snapshot.SnapshotError, "missing=src/alpha.txt"):
            source_snapshot.verify_snapshot(
                self.root, self.scope_path, self.manifest, self.metadata)

        self._write("src/alpha.txt", b"a\n")
        self._write("src/extra.txt", b"extra\n")
        with self.assertRaisesRegex(source_snapshot.SnapshotError, "extra=src/extra.txt"):
            source_snapshot.verify_snapshot(
                self.root, self.scope_path, self.manifest, self.metadata)

        (self.root / "src/extra.txt").unlink()
        self._write("src/alpha.txt", b"tampered\n")
        with self.assertRaisesRegex(source_snapshot.SnapshotError, "tampered=src/alpha.txt"):
            source_snapshot.verify_snapshot(
                self.root, self.scope_path, self.manifest, self.metadata)

    def test_verify_rejects_tampered_manifest_and_metadata(self) -> None:
        self._seed()
        source_snapshot.write_snapshot(
            self.root, self.scope_path, self.manifest, self.metadata)
        lines = self.manifest.read_text(encoding="utf-8").splitlines()
        lines[0] = "0" * 64 + lines[0][64:]
        self.manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(source_snapshot.SnapshotError, "metadata digest"):
            source_snapshot.verify_snapshot(
                self.root, self.scope_path, self.manifest, self.metadata)

        source_snapshot.write_snapshot(
            self.root, self.scope_path, self.manifest, self.metadata)
        metadata = json.loads(self.metadata.read_text(encoding="utf-8"))
        metadata["count"] += 1
        self.metadata.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(source_snapshot.SnapshotError, "metadata count"):
            source_snapshot.verify_snapshot(
                self.root, self.scope_path, self.manifest, self.metadata)

    def test_rejects_output_inside_selected_scope(self) -> None:
        self._seed()
        with self.assertRaisesRegex(source_snapshot.SnapshotError, "inside its own selected"):
            source_snapshot.write_snapshot(
                self.root,
                self.scope_path,
                self.root / "src/SOURCE-SHA256SUMS.txt",
                self.metadata,
            )

    def test_cli_assert_equal_fails_closed(self) -> None:
        self._seed()
        after = self.base / "after"
        shutil.copytree(self.root, after)
        self.assertEqual(
            source_snapshot.main([
                "assert-equal", "--before-root", str(self.root),
                "--after-root", str(after), "--scope", str(self.scope_path),
            ]),
            0,
        )
        (after / "src/alpha.txt").write_bytes(b"different")
        self.assertEqual(
            source_snapshot.main([
                "assert-equal", "--before-root", str(self.root),
                "--after-root", str(after), "--scope", str(self.scope_path),
            ]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
