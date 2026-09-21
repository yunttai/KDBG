#!/usr/bin/env python3
"""Create and verify deterministic, scope-bound source manifests.

The manifest is UTF-8 with LF line endings and one record per line::

    <lowercase sha256><two spaces><POSIX relative path>

File content is hashed byte-for-byte. The digest in the companion JSON is the
SHA-256 of the exact manifest bytes, including the final LF.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


SCOPE_SCHEMA = "kdbg.source-scope.v1"
METADATA_SCHEMA = "kdbg.source-manifest-metadata.v1"
RECORD_RE = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class SnapshotError(RuntimeError):
    """Raised when snapshot input or verification is invalid."""


@dataclass(frozen=True, order=True)
class Record:
    path: str
    sha256: str


@dataclass(frozen=True)
class ScopeConfig:
    version: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    sha256: str


@dataclass(frozen=True)
class Snapshot:
    records: tuple[Record, ...]

    @property
    def manifest_bytes(self) -> bytes:
        text = "".join(f"{record.sha256}  {record.path}\n" for record in self.records)
        return text.encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.manifest_bytes).hexdigest()

    @property
    def count(self) -> int:
        return len(self.records)


@dataclass(frozen=True)
class EqualityDiff:
    before_digest: str
    after_digest: str
    missing_from_after: tuple[str, ...]
    extra_in_after: tuple[str, ...]
    changed: tuple[str, ...]

    @property
    def equal(self) -> bool:
        return not (self.missing_from_after or self.extra_in_after or self.changed)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError as exc:
        raise SnapshotError(f"unable to hash file {path}: {exc}") from exc
    return hasher.hexdigest()


def _validate_relative_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SnapshotError(f"{label} must be a non-empty string")
    if "\\" in value or "\r" in value or "\n" in value or "\0" in value:
        raise SnapshotError(f"{label} must use safe POSIX relative syntax: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise SnapshotError(f"{label} must use safe POSIX relative syntax: {value!r}")
    if path.as_posix() != value:
        raise SnapshotError(f"{label} is not a canonical POSIX relative path: {value!r}")
    return value


def _validate_pattern(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SnapshotError(f"{label} must be a string")
    value = _validate_relative_path(value, label)
    for part in value.split("/"):
        if "**" in part and part != "**":
            raise SnapshotError(f"{label} uses '**' inside a path component: {value!r}")
    return value


def load_scope(path: Path) -> ScopeConfig:
    """Load and strictly validate a scope file, binding its raw-byte hash."""
    try:
        raw_bytes = path.read_bytes()
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"unable to load scope config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SnapshotError("scope config root must be a JSON object")
    allowed = {"schema", "scope_version", "include", "exclude"}
    unexpected = sorted(set(raw) - allowed)
    if unexpected:
        raise SnapshotError(f"scope config has unexpected keys: {', '.join(unexpected)}")
    if raw.get("schema") != SCOPE_SCHEMA:
        raise SnapshotError(f"scope config schema must be {SCOPE_SCHEMA}")
    version = raw.get("scope_version")
    if not isinstance(version, str) or not version.strip():
        raise SnapshotError("scope_version must be a non-empty string")
    includes = raw.get("include")
    excludes = raw.get("exclude", [])
    if not isinstance(includes, list) or not includes:
        raise SnapshotError("include must be a non-empty JSON array")
    if not isinstance(excludes, list):
        raise SnapshotError("exclude must be a JSON array")
    include = tuple(_validate_pattern(item, f"include[{index}]")
                    for index, item in enumerate(includes))
    exclude = tuple(_validate_pattern(item, f"exclude[{index}]")
                    for index, item in enumerate(excludes))
    if len(set(include)) != len(include) or len(set(exclude)) != len(exclude):
        raise SnapshotError("scope config contains duplicate patterns")
    return ScopeConfig(
        version=version,
        include=include,
        exclude=exclude,
        sha256=_sha256_bytes(raw_bytes),
    )


def _glob_matches(pattern: str, relative: str) -> bool:
    """Match POSIX paths with component-local wildcards and recursive '**'."""
    pattern_parts = pattern.split("/")
    path_parts = relative.split("/")

    def match(pattern_index: int, path_index: int) -> bool:
        while pattern_index < len(pattern_parts):
            part = pattern_parts[pattern_index]
            if part == "**":
                if pattern_index + 1 == len(pattern_parts):
                    return True
                return any(match(pattern_index + 1, candidate)
                           for candidate in range(path_index, len(path_parts) + 1))
            if path_index >= len(path_parts) or not fnmatch.fnmatchcase(path_parts[path_index], part):
                return False
            pattern_index += 1
            path_index += 1
        return path_index == len(path_parts)

    return match(0, 0)


def _selected(relative: str, scope: ScopeConfig) -> bool:
    return (any(_glob_matches(pattern, relative) for pattern in scope.include)
            and not any(_glob_matches(pattern, relative) for pattern in scope.exclude))


def _literal_prefix(pattern: str) -> tuple[str, ...]:
    parts: list[str] = []
    for part in pattern.split("/"):
        if part == "**" or any(character in part for character in "*?["):
            break
        parts.append(part)
    return tuple(parts)


def _candidate_paths(root: Path, scope: ScopeConfig) -> Iterable[Path]:
    """Yield candidate files without traversing unrelated repo roots."""
    search_roots: set[Path] = set()
    for pattern in scope.include:
        prefix = _literal_prefix(pattern)
        search_roots.add(root.joinpath(*prefix) if prefix else root)

    yielded: set[str] = set()
    for search_root in sorted(search_roots, key=lambda item: item.as_posix()):
        if search_root.is_symlink():
            relative = search_root.relative_to(root).as_posix()
            if _selected(relative, scope):
                raise SnapshotError(f"selected path is a symlink: {relative}")
            continue
        if search_root.is_file():
            candidates = (search_root,)
        elif search_root.is_dir():
            candidates_list: list[Path] = []
            for directory, directories, files in os.walk(search_root, followlinks=False):
                directory_path = Path(directory)
                kept_directories: list[str] = []
                for name in sorted(directories):
                    child = directory_path / name
                    relative = child.relative_to(root).as_posix()
                    if child.is_symlink():
                        if _selected(relative, scope):
                            raise SnapshotError(f"selected path is a symlink: {relative}")
                        continue
                    probe = f"{relative}/__kdbg_scope_probe__"
                    if any(_glob_matches(pattern, probe) for pattern in scope.exclude):
                        continue
                    kept_directories.append(name)
                directories[:] = kept_directories
                candidates_list.extend(directory_path / name for name in sorted(files))
            candidates = candidates_list
        else:
            continue
        for candidate in candidates:
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError as exc:
                raise SnapshotError(f"candidate escaped root: {candidate}") from exc
            if relative in yielded or not _selected(relative, scope):
                continue
            if candidate.is_symlink():
                raise SnapshotError(f"selected path is a symlink: {relative}")
            if not candidate.is_file():
                raise SnapshotError(f"selected path is not a regular file: {relative}")
            yielded.add(relative)
            yield candidate


def capture_tree(root: Path, scope: ScopeConfig) -> Snapshot:
    """Hash every regular file selected by *scope* under *root*."""
    root = root.resolve()
    if not root.is_dir():
        raise SnapshotError(f"snapshot root is not a directory: {root}")
    records = [
        Record(candidate.relative_to(root).as_posix(), _sha256_file(candidate))
        for candidate in _candidate_paths(root, scope)
    ]
    records.sort(key=lambda record: record.path)
    if not records:
        raise SnapshotError("scope selected zero files")
    return Snapshot(tuple(records))


def parse_manifest(data: bytes) -> Snapshot:
    """Parse a canonical manifest and reject alternate encodings or ordering."""
    if not data or not data.endswith(b"\n") or b"\r" in data:
        raise SnapshotError("manifest must be non-empty LF text with a final LF")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"manifest is not valid UTF-8: {exc}") from exc
    records: list[Record] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = RECORD_RE.fullmatch(line)
        if match is None:
            raise SnapshotError(f"malformed manifest record at line {line_number}")
        relative = _validate_relative_path(match.group(2), f"manifest line {line_number} path")
        records.append(Record(relative, match.group(1)))
    paths = [record.path for record in records]
    if paths != sorted(paths):
        raise SnapshotError("manifest records are not sorted by relative path")
    if len(paths) != len(set(paths)):
        raise SnapshotError("manifest contains duplicate paths")
    snapshot = Snapshot(tuple(records))
    if snapshot.manifest_bytes != data:
        raise SnapshotError("manifest is not in canonical record form")
    return snapshot


def build_metadata(snapshot: Snapshot, scope: ScopeConfig) -> dict[str, object]:
    return {
        "schema": METADATA_SCHEMA,
        "digest": snapshot.digest,
        "count": snapshot.count,
        "scope_version": scope.version,
        "scope_sha256": scope.sha256,
        "content_hash": "sha256",
        "record_format": "sha256  relative/path",
        "path_order": "ordinal-posix-relative-path",
    }


def _metadata_bytes(metadata: dict[str, object]) -> bytes:
    return (json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _atomic_write(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise SnapshotError(f"unable to write {path}: {exc}") from exc


def write_snapshot(
    root: Path,
    scope_path: Path,
    manifest_path: Path,
    metadata_path: Path,
) -> Snapshot:
    """Capture a tree and atomically write its manifest and companion JSON."""
    scope = load_scope(scope_path)
    snapshot = capture_tree(root, scope)
    resolved_root = root.resolve()
    if manifest_path.resolve() == metadata_path.resolve():
        raise SnapshotError("manifest and metadata outputs must be different paths")
    for label, output in (("manifest", manifest_path), ("metadata", metadata_path)):
        output_resolved = output.resolve()
        try:
            relative = output_resolved.relative_to(resolved_root).as_posix()
        except ValueError:
            continue
        if _selected(relative, scope):
            raise SnapshotError(
                f"{label} output is inside its own selected source scope: {relative}")
    _atomic_write(manifest_path, snapshot.manifest_bytes)
    _atomic_write(metadata_path, _metadata_bytes(build_metadata(snapshot, scope)))
    return snapshot


def _load_metadata(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"unable to load metadata {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SnapshotError("metadata root must be a JSON object")
    required = {
        "schema", "digest", "count", "scope_version", "scope_sha256",
        "content_hash", "record_format", "path_order",
    }
    if set(raw) != required:
        missing = sorted(required - set(raw))
        unexpected = sorted(set(raw) - required)
        details = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unexpected:
            details.append(f"unexpected={','.join(unexpected)}")
        raise SnapshotError(f"metadata keys are invalid ({'; '.join(details)})")
    if raw.get("schema") != METADATA_SCHEMA:
        raise SnapshotError(f"metadata schema must be {METADATA_SCHEMA}")
    if not isinstance(raw.get("digest"), str) or not SHA256_RE.fullmatch(str(raw["digest"])):
        raise SnapshotError("metadata digest is not a lowercase SHA-256")
    if not isinstance(raw.get("count"), int) or isinstance(raw.get("count"), bool) or raw["count"] < 1:
        raise SnapshotError("metadata count must be a positive integer")
    if raw.get("content_hash") != "sha256":
        raise SnapshotError("metadata content_hash must be sha256")
    if raw.get("record_format") != "sha256  relative/path":
        raise SnapshotError("metadata record_format mismatch")
    if raw.get("path_order") != "ordinal-posix-relative-path":
        raise SnapshotError("metadata path_order mismatch")
    return raw


def _diff(before: Snapshot, after: Snapshot) -> EqualityDiff:
    before_map = {record.path: record.sha256 for record in before.records}
    after_map = {record.path: record.sha256 for record in after.records}
    return EqualityDiff(
        before_digest=before.digest,
        after_digest=after.digest,
        missing_from_after=tuple(sorted(before_map.keys() - after_map.keys())),
        extra_in_after=tuple(sorted(after_map.keys() - before_map.keys())),
        changed=tuple(sorted(
            path for path in before_map.keys() & after_map.keys()
            if before_map[path] != after_map[path]
        )),
    )


def verify_snapshot(
    root: Path,
    scope_path: Path,
    manifest_path: Path,
    metadata_path: Path,
) -> Snapshot:
    """Verify metadata, exact manifest bytes, and the selected archived tree."""
    scope = load_scope(scope_path)
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise SnapshotError(f"unable to read manifest {manifest_path}: {exc}") from exc
    expected = parse_manifest(manifest_bytes)
    metadata = _load_metadata(metadata_path)
    if metadata["scope_version"] != scope.version:
        raise SnapshotError("metadata scope_version does not match scope config")
    if metadata["scope_sha256"] != scope.sha256:
        raise SnapshotError("metadata scope_sha256 does not match scope config")
    if metadata["digest"] != expected.digest:
        raise SnapshotError("metadata digest does not match manifest bytes")
    if metadata["count"] != expected.count:
        raise SnapshotError("metadata count does not match manifest record count")
    actual = capture_tree(root, scope)
    diff = _diff(expected, actual)
    if not diff.equal:
        details = []
        if diff.missing_from_after:
            details.append("missing=" + ",".join(diff.missing_from_after))
        if diff.extra_in_after:
            details.append("extra=" + ",".join(diff.extra_in_after))
        if diff.changed:
            details.append("tampered=" + ",".join(diff.changed))
        raise SnapshotError("tree does not match manifest (" + "; ".join(details) + ")")
    if actual.digest != expected.digest:
        raise SnapshotError("tree digest does not match manifest digest")
    return actual


def assert_equal_trees(before_root: Path, after_root: Path, scope_path: Path) -> EqualityDiff:
    """Compare two selected trees without writing or trusting stored artifacts."""
    scope = load_scope(scope_path)
    return _diff(capture_tree(before_root, scope), capture_tree(after_root, scope))


def _result(snapshot: Snapshot, scope: ScopeConfig, status: str) -> dict[str, object]:
    return {
        "status": status,
        "digest": snapshot.digest,
        "count": snapshot.count,
        "scope_version": scope.version,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="write a manifest and schema JSON")
    generate.add_argument("--root", required=True, type=Path)
    generate.add_argument("--scope", required=True, type=Path)
    generate.add_argument("--manifest", required=True, type=Path)
    generate.add_argument("--metadata", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="verify an archived tree and artifacts")
    verify.add_argument("--root", required=True, type=Path)
    verify.add_argument("--scope", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--metadata", required=True, type=Path)

    compare = subparsers.add_parser("assert-equal", help="assert selected before/after trees are equal")
    compare.add_argument("--before-root", required=True, type=Path)
    compare.add_argument("--after-root", required=True, type=Path)
    compare.add_argument("--scope", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        scope = load_scope(args.scope)
        if args.command == "generate":
            snapshot = write_snapshot(args.root, args.scope, args.manifest, args.metadata)
            payload = _result(snapshot, scope, "GENERATED")
        elif args.command == "verify":
            snapshot = verify_snapshot(args.root, args.scope, args.manifest, args.metadata)
            payload = _result(snapshot, scope, "PASS")
        else:
            diff = assert_equal_trees(args.before_root, args.after_root, args.scope)
            payload = {
                "status": "PASS" if diff.equal else "FAIL",
                "equal": diff.equal,
                "scope_version": scope.version,
                "before_digest": diff.before_digest,
                "after_digest": diff.after_digest,
                "missing_from_after": list(diff.missing_from_after),
                "extra_in_after": list(diff.extra_in_after),
                "changed": list(diff.changed),
            }
            print(json.dumps(payload, sort_keys=True))
            return 0 if diff.equal else 1
        print(json.dumps(payload, sort_keys=True))
        return 0
    except SnapshotError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
