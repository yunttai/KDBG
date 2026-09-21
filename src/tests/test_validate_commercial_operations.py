from __future__ import annotations

import importlib.util
import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "src/tools/validate_commercial_operations.py"
SPEC = importlib.util.spec_from_file_location("kdbg_commercial_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class CommercialOperationsValidatorTests(unittest.TestCase):
    def make_evidence(self, directory: Path) -> Path:
        now = datetime.now(timezone.utc) - timedelta(minutes=1)
        submitted = now - timedelta(minutes=3)
        delivered = now - timedelta(minutes=2)
        acknowledged = now - timedelta(minutes=1)
        evidence = {
            "schema": VALIDATOR.SCHEMA,
            "repository_url": VALIDATOR.REPOSITORY_URL,
            "support_route": VALIDATOR.SUPPORT_URL,
            "security_route": VALIDATOR.SECURITY_URL,
            "assigned_owner": VALIDATOR.ASSIGNED_OWNER,
            "verified_utc": utc(now),
            "issues_enabled": True,
            "private_vulnerability_reporting_enabled": True,
            "secret_scanning_enabled": True,
            "secret_scanning_push_protection_enabled": True,
            "dependabot_security_updates_enabled": True,
            "notification_delivery_verified": True,
            "redaction_review_completed": True,
            "support_acknowledgement_drill": {
                "completed": True,
                "case_id": "support-case-42",
                "submitted_utc": utc(submitted),
                "acknowledged_utc": utc(acknowledged),
            },
            "security_acknowledgement_drill": {
                "completed": True,
                "case_id": "security-advisory-17",
                "submitted_utc": utc(submitted),
                "acknowledged_utc": utc(acknowledged),
            },
            "artifacts": [],
        }
        for role in sorted(VALIDATOR.REQUIRED_ARTIFACT_ROLES):
            channel = "support" if role.startswith("support_") else "security"
            route = (
                VALIDATOR.SUPPORT_URL
                if channel == "support"
                else VALIDATOR.SECURITY_URL
            )
            drill = evidence[f"{channel}_acknowledgement_drill"]
            if role.endswith("_notification_delivery"):
                artifact_value = {
                    "schema": VALIDATOR.NOTIFICATION_SCHEMA,
                    "role": role,
                    "route": route,
                    "case_id": drill["case_id"],
                    "assigned_owner": VALIDATOR.ASSIGNED_OWNER,
                    "delivered": True,
                    "delivered_utc": utc(delivered),
                    "provider_event_id": f"github-event-{channel}-42",
                    "destination": {
                        "account_identifier": VALIDATOR.REDACTED_ACCOUNT_IDENTIFIER,
                        "redacted": True,
                    },
                }
            else:
                artifact_value = {
                    "schema": VALIDATOR.ACKNOWLEDGEMENT_SCHEMA,
                    "role": role,
                    "route": route,
                    "case_id": drill["case_id"],
                    "assigned_owner": VALIDATOR.ASSIGNED_OWNER,
                    "submitted_utc": drill["submitted_utc"],
                    "acknowledged_utc": drill["acknowledged_utc"],
                    "acknowledged_by": VALIDATOR.ASSIGNED_OWNER,
                    "acknowledged": True,
                    "redaction_reviewed": True,
                }
            artifact = directory / f"{role}.json"
            artifact.write_text(
                json.dumps(artifact_value, sort_keys=True) + "\n", encoding="utf-8"
            )
            evidence["artifacts"].append(
                {
                    "role": role,
                    "file": artifact.name,
                    "sha256": VALIDATOR.sha256(artifact),
                }
            )
        path = directory / "commercial-operations-evidence.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        return path

    def mutate(self, path: Path, callback) -> list[str]:
        evidence = json.loads(path.read_text(encoding="utf-8"))
        callback(evidence)
        path.write_text(json.dumps(evidence), encoding="utf-8")
        return VALIDATOR.validate_commercial_evidence(path)

    def mutate_artifact(self, path: Path, role: str, callback) -> list[str]:
        evidence = json.loads(path.read_text(encoding="utf-8"))
        record = next(item for item in evidence["artifacts"] if item["role"] == role)
        artifact = path.parent / record["file"]
        value = json.loads(artifact.read_text(encoding="utf-8"))
        callback(value)
        artifact.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        record["sha256"] = VALIDATOR.sha256(artifact)
        path.write_text(json.dumps(evidence), encoding="utf-8")
        return VALIDATOR.validate_commercial_evidence(path)

    def test_repository_source_contract_passes(self) -> None:
        self.assertEqual([], VALIDATOR.validate_source_contract(ROOT))

    def test_source_contract_does_not_promote_commercial_gate(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = VALIDATOR.main(["--source-contract"])
        self.assertEqual(0, result)
        self.assertIn("commercial-source-contract: PASS", output.getvalue())
        self.assertIn("commercial-operations: NOT RUN", output.getvalue())

    def test_complete_hash_bound_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            self.assertEqual([], VALIDATOR.validate_commercial_evidence(path))

    def test_document_keywords_are_not_evidence(self) -> None:
        errors = VALIDATOR.validate_commercial_evidence(ROOT / "docs/SUPPORT.md")
        self.assertTrue(any("invalid commercial operations evidence JSON" in e for e in errors))

    def test_unverified_notification_delivery_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            errors = self.mutate(
                path, lambda value: value.__setitem__("notification_delivery_verified", False)
            )
            self.assertTrue(any("notification_delivery_verified" in e for e in errors))

    def test_missing_acknowledgement_drill_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            errors = self.mutate(
                path, lambda value: value.pop("security_acknowledgement_drill")
            )
            self.assertTrue(any("security acknowledgement drill is missing" in e for e in errors))

    def test_placeholder_case_id_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))

            def change(value: dict) -> None:
                value["support_acknowledgement_drill"]["case_id"] = "TODO"

            errors = self.mutate(path, change)
            self.assertTrue(any("case_id is empty or a placeholder" in e for e in errors))

    def test_wrong_route_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            errors = self.mutate(
                path, lambda value: value.__setitem__("support_route", "https://example.com")
            )
            self.assertTrue(any("support_route must equal" in e for e in errors))

    def test_tampered_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            root = Path(directory)
            path = self.make_evidence(root)
            (root / "support_acknowledgement.json").write_text("tampered\n", encoding="utf-8")
            errors = VALIDATOR.validate_commercial_evidence(path)
            self.assertTrue(any("artifact hash mismatch" in e for e in errors))

    def test_rehashed_arbitrary_text_artifact_fails_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            root = Path(directory)
            path = self.make_evidence(root)
            evidence = json.loads(path.read_text(encoding="utf-8"))
            record = next(
                item
                for item in evidence["artifacts"]
                if item["role"] == "support_notification_delivery"
            )
            artifact = root / record["file"]
            artifact.write_text("redacted proof\n", encoding="utf-8")
            record["sha256"] = VALIDATOR.sha256(artifact)
            path.write_text(json.dumps(evidence), encoding="utf-8")
            errors = VALIDATOR.validate_commercial_evidence(path)
            self.assertTrue(any("artifact is not valid JSON" in e for e in errors))

    def test_notification_case_id_cross_binding_is_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            errors = self.mutate_artifact(
                path,
                "support_notification_delivery",
                lambda value: value.__setitem__("case_id", "different-case-99"),
            )
            self.assertTrue(any("case_id cross-binding mismatch" in e for e in errors))

    def test_artifact_role_spoof_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            errors = self.mutate_artifact(
                path,
                "security_acknowledgement",
                lambda value: value.__setitem__("role", "support_acknowledgement"),
            )
            self.assertTrue(any("role cross-binding mismatch" in e for e in errors))

    def test_unredacted_notification_destination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))

            def change(value: dict) -> None:
                value["destination"] = {
                    "account_identifier": "owner@example.com",
                    "redacted": False,
                }

            errors = self.mutate_artifact(
                path, "security_notification_delivery", change
            )
            self.assertTrue(any("destination is not safely redacted" in e for e in errors))

    def test_acknowledgement_timestamp_cross_binding_is_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            changed = utc(datetime.now(timezone.utc) - timedelta(minutes=20))
            errors = self.mutate_artifact(
                path,
                "support_acknowledgement",
                lambda value: value.__setitem__("submitted_utc", changed),
            )
            self.assertTrue(any("acknowledgement submission mismatch" in e for e in errors))

    def test_directory_artifact_is_rejected_as_non_regular(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            root = Path(directory)
            path = self.make_evidence(root)
            artifact = root / "security_acknowledgement.json"
            artifact.unlink()
            artifact.mkdir()
            errors = VALIDATOR.validate_commercial_evidence(path)
            self.assertTrue(any("must be a plain regular file" in e for e in errors))

    def test_symlink_artifact_metadata_is_rejected(self) -> None:
        metadata = SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        self.assertFalse(VALIDATOR.is_plain_regular_metadata(metadata))

    def test_reparse_artifact_metadata_is_rejected(self) -> None:
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_file_attributes=reparse,
        )
        self.assertFalse(VALIDATOR.is_plain_regular_metadata(metadata))

    def test_future_verification_timestamp_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kdbg-commercial-") as directory:
            path = self.make_evidence(Path(directory))
            future = utc(datetime.now(timezone.utc) + timedelta(hours=1))
            errors = self.mutate(
                path, lambda value: value.__setitem__("verified_utc", future)
            )
            self.assertTrue(any("invalid verified_utc" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
