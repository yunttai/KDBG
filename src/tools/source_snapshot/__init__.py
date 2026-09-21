"""Deterministic source snapshot manifests for KDBG release provenance."""

from .source_snapshot import (
    EqualityDiff,
    Record,
    ScopeConfig,
    Snapshot,
    SnapshotError,
    assert_equal_trees,
    build_metadata,
    capture_tree,
    load_scope,
    parse_manifest,
    verify_snapshot,
    write_snapshot,
)

__all__ = [
    "EqualityDiff",
    "Record",
    "ScopeConfig",
    "Snapshot",
    "SnapshotError",
    "assert_equal_trees",
    "build_metadata",
    "capture_tree",
    "load_scope",
    "parse_manifest",
    "verify_snapshot",
    "write_snapshot",
]
