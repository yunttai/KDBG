#!/usr/bin/env python3
"""Validate KDBG commercial support/security operations without network access.

The source-contract mode proves only that published routes, ownership, intake
fields, and fail-closed wording are present. Commercial readiness additionally
requires a separate, hash-bound evidence record for notification delivery and
support/security acknowledgement drills.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath


SCHEMA = "kdbg.commercial-operations-evidence.v1"
REPOSITORY_URL = "https://github.com/yunttai/KDBG"
SUPPORT_URL = "https://github.com/yunttai/KDBG/issues/new/choose"
SECURITY_URL = "https://github.com/yunttai/KDBG/security/advisories/new"
ASSIGNED_OWNER = "yunttai"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_RE = re.compile(
    r"(?:<|replace|placeholder|unknown|fixture|todo|tbd|example\.com)", re.I
)
REQUIRED_ARTIFACT_ROLES = {
    "support_notification_delivery",
    "support_acknowledgement",
    "security_notification_delivery",
    "security_acknowledgement",
}
NOTIFICATION_SCHEMA = "kdbg.commercial-notification-delivery.v1"
ACKNOWLEDGEMENT_SCHEMA = "kdbg.commercial-acknowledgement.v1"
REDACTED_ACCOUNT_IDENTIFIER = "[REDACTED]"


SOURCE_CONTRACT = {
    "docs/SUPPORT.md": (
        REPOSITORY_URL,
        SUPPORT_URL,
        SECURITY_URL,
        ASSIGNED_OWNER,
        "notification delivery",
        "acknowledgement drill",
        "commercial-ready",
    ),
    "docs/SECURITY.md": (
        REPOSITORY_URL,
        SECURITY_URL,
        ASSIGNED_OWNER,
        "Private vulnerability reporting is enabled",
        "secret scanning",
        "push protection",
        "Dependabot security updates",
        "notification delivery",
        "commercial-operations",
    ),
    "docs/VULNERABILITY_DISCLOSURE.md": (
        REPOSITORY_URL,
        SUPPORT_URL,
        SECURITY_URL,
        ASSIGNED_OWNER,
        "notification delivery",
        "acknowledgement drill",
        "commercial support gate remains incomplete",
    ),
    ".github/SECURITY.md": (
        SUPPORT_URL,
        SECURITY_URL,
        ASSIGNED_OWNER,
        "main and symbols ZIP SHA-256",
        "Windows build",
        "reproduction steps",
        "redacted",
    ),
    ".github/ISSUE_TEMPLATE/bug_report.md": (
        "KDBG version",
        "Main ZIP SHA-256",
        "Symbols ZIP SHA-256",
        "Windows build",
        "Reproduction",
        "Redaction confirmation",
        SECURITY_URL,
    ),
    ".github/ISSUE_TEMPLATE/support_request.yml": (
        "KDBG version",
        "Main ZIP SHA-256",
        "Symbols ZIP SHA-256",
        "Windows build",
        "Exact failing command",
        "Reproduction steps",
        "Redacted diagnostics",
        "required: true",
    ),
    ".github/ISSUE_TEMPLATE/config.yml": (
        "blank_issues_enabled: false",
        SECURITY_URL,
        "Private security report",
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, errors: list[str]) -> dict | None:
    if not path.is_file():
        errors.append(f"commercial operations evidence not found: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"invalid commercial operations evidence JSON: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append("commercial operations evidence root must be an object")
        return None
    return value


def parse_utc(value: object, field: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError("timestamp is not UTC")
        parsed = parsed.astimezone(timezone.utc)
        if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("timestamp is in the future")
        return parsed
    except ValueError as exc:
        errors.append(f"invalid {field}: {exc}")
        return None


def validate_source_contract(root: Path) -> list[str]:
    errors: list[str] = []
    for relative, tokens in SOURCE_CONTRACT.items():
        path = root / PurePosixPath(relative)
        if not path.is_file():
            errors.append(f"commercial source contract file missing: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            errors.append(f"unable to read commercial source contract {relative}: {exc}")
            continue
        normalized = re.sub(r"\s+", " ", text)
        for token in tokens:
            if re.sub(r"\s+", " ", token) not in normalized:
                errors.append(
                    f"commercial source contract marker missing in {relative}: {token}"
                )

    support_template = root / ".github/ISSUE_TEMPLATE/support_request.yml"
    if support_template.is_file():
        text = support_template.read_text(encoding="utf-8-sig", errors="replace")
        if text.count("required: true") < 8:
            errors.append(
                "support request template must require all identity, reproduction, "
                "diagnostic, and redaction fields"
            )
    return errors


def validate_drill(
    value: object,
    name: str,
    evidence_verified_utc: datetime | None,
    errors: list[str],
) -> dict[str, object]:
    result: dict[str, object] = {
        "case_id": None,
        "submitted_utc": None,
        "acknowledged_utc": None,
    }
    if not isinstance(value, dict):
        errors.append(f"{name} acknowledgement drill is missing")
        return result
    if value.get("completed") is not True:
        errors.append(f"{name} acknowledgement drill is not completed")
    case_id = value.get("case_id")
    if (
        not isinstance(case_id, str)
        or not case_id.strip()
        or PLACEHOLDER_RE.search(case_id) is not None
    ):
        errors.append(f"{name} acknowledgement drill case_id is empty or a placeholder")
    else:
        result["case_id"] = case_id
    submitted = parse_utc(value.get("submitted_utc"), f"{name}.submitted_utc", errors)
    acknowledged = parse_utc(
        value.get("acknowledged_utc"), f"{name}.acknowledged_utc", errors
    )
    if submitted is not None and acknowledged is not None and acknowledged < submitted:
        errors.append(f"{name} acknowledgement predates submission")
    if (
        acknowledged is not None
        and evidence_verified_utc is not None
        and acknowledged > evidence_verified_utc
    ):
        errors.append(f"{name} acknowledgement postdates evidence verification")
    result["submitted_utc"] = submitted
    result["acknowledged_utc"] = acknowledged
    return result


def load_artifact_json(path: Path, role: str, errors: list[str]) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"commercial operations artifact is not valid JSON: {role}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"commercial operations artifact root must be an object: {role}")
        return None
    return value


def is_symlink_or_reparse_metadata(metadata: object) -> bool:
    mode = getattr(metadata, "st_mode", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(mode) or bool(attributes & reparse_flag)


def is_plain_regular_metadata(metadata: object) -> bool:
    mode = getattr(metadata, "st_mode", 0)
    return (
        stat.S_ISREG(mode)
        and not is_symlink_or_reparse_metadata(metadata)
    )


def validate_exact_artifact_identity(
    artifact: dict,
    role: str,
    schema: str,
    route: str,
    drill: dict[str, object],
    errors: list[str],
) -> None:
    expected = {
        "schema": schema,
        "role": role,
        "route": route,
        "case_id": drill.get("case_id"),
        "assigned_owner": ASSIGNED_OWNER,
    }
    for field, value in expected.items():
        if artifact.get(field) != value:
            errors.append(f"commercial operations artifact {role}.{field} cross-binding mismatch")


def validate_notification_artifact(
    artifact: dict,
    role: str,
    route: str,
    drill: dict[str, object],
    verified_utc: datetime | None,
    errors: list[str],
) -> None:
    validate_exact_artifact_identity(
        artifact, role, NOTIFICATION_SCHEMA, route, drill, errors
    )
    if artifact.get("delivered") is not True:
        errors.append(f"commercial operations notification was not delivered: {role}")
    event_id = artifact.get("provider_event_id")
    if (
        not isinstance(event_id, str)
        or not event_id.strip()
        or PLACEHOLDER_RE.search(event_id) is not None
    ):
        errors.append(f"commercial operations notification event id is invalid: {role}")
    destination = artifact.get("destination")
    if (
        not isinstance(destination, dict)
        or destination.get("redacted") is not True
        or destination.get("account_identifier") != REDACTED_ACCOUNT_IDENTIFIER
    ):
        errors.append(
            f"commercial operations notification destination is not safely redacted: {role}"
        )
    delivered = parse_utc(
        artifact.get("delivered_utc"), f"{role}.delivered_utc", errors
    )
    submitted = drill.get("submitted_utc")
    acknowledged = drill.get("acknowledged_utc")
    if isinstance(delivered, datetime):
        if isinstance(submitted, datetime) and delivered < submitted:
            errors.append(f"commercial operations notification predates submission: {role}")
        if isinstance(acknowledged, datetime) and delivered > acknowledged:
            errors.append(f"commercial operations notification postdates acknowledgement: {role}")
        if isinstance(verified_utc, datetime) and delivered > verified_utc:
            errors.append(f"commercial operations notification postdates verification: {role}")


def validate_acknowledgement_artifact(
    artifact: dict,
    role: str,
    route: str,
    drill: dict[str, object],
    verified_utc: datetime | None,
    errors: list[str],
) -> None:
    validate_exact_artifact_identity(
        artifact, role, ACKNOWLEDGEMENT_SCHEMA, route, drill, errors
    )
    if artifact.get("acknowledged") is not True:
        errors.append(f"commercial operations acknowledgement is not confirmed: {role}")
    if artifact.get("acknowledged_by") != ASSIGNED_OWNER:
        errors.append(f"commercial operations acknowledgement owner mismatch: {role}")
    if artifact.get("redaction_reviewed") is not True:
        errors.append(f"commercial operations acknowledgement lacks redaction review: {role}")
    submitted = parse_utc(
        artifact.get("submitted_utc"), f"{role}.submitted_utc", errors
    )
    acknowledged = parse_utc(
        artifact.get("acknowledged_utc"), f"{role}.acknowledged_utc", errors
    )
    expected_submitted = drill.get("submitted_utc")
    expected_acknowledged = drill.get("acknowledged_utc")
    if submitted != expected_submitted:
        errors.append(f"commercial operations acknowledgement submission mismatch: {role}")
    if acknowledged != expected_acknowledged:
        errors.append(f"commercial operations acknowledgement timestamp mismatch: {role}")
    if isinstance(acknowledged, datetime) and isinstance(verified_utc, datetime):
        if acknowledged > verified_utc:
            errors.append(f"commercial operations acknowledgement postdates verification: {role}")


def validate_artifacts(
    evidence_path: Path,
    value: object,
    verified_utc: datetime | None,
    drills: dict[str, dict[str, object]],
    errors: list[str],
) -> None:
    if not isinstance(value, list):
        errors.append("commercial operations artifacts must be an array")
        return
    evidence_root = evidence_path.resolve().parent
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"commercial operations artifact {index} is not an object")
            continue
        role = item.get("role")
        relative = item.get("file")
        expected_hash = item.get("sha256")
        if not isinstance(role, str) or role not in REQUIRED_ARTIFACT_ROLES:
            errors.append(f"commercial operations artifact {index} has an invalid role")
            continue
        if role in seen:
            errors.append(f"duplicate commercial operations artifact role: {role}")
        seen.add(role)
        if (
            not isinstance(relative, str)
            or not relative
            or PurePosixPath(relative).is_absolute()
            or ".." in PurePosixPath(relative).parts
        ):
            errors.append(f"commercial operations artifact path is invalid: {role}")
            continue
        relative_path = PurePosixPath(relative)
        lexical_artifact = evidence_root / relative_path
        cursor = evidence_root
        metadata = None
        try:
            for part in relative_path.parts:
                cursor = cursor / part
                metadata = cursor.lstat()
                if (
                    cursor != lexical_artifact
                    and is_symlink_or_reparse_metadata(metadata)
                ):
                    raise ValueError("symlink or reparse point")
            if metadata is None or not is_plain_regular_metadata(metadata):
                raise ValueError("not a regular file")
        except (OSError, ValueError) as exc:
            errors.append(
                f"commercial operations artifact must be a plain regular file: {role}: {exc}"
            )
            continue
        artifact = lexical_artifact.resolve()
        try:
            artifact.relative_to(evidence_root)
        except ValueError:
            errors.append(f"commercial operations artifact escapes evidence root: {role}")
            continue
        if artifact.stat().st_size == 0:
            errors.append(f"commercial operations artifact is missing or empty: {role}")
            continue
        if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
            errors.append(f"commercial operations artifact hash is invalid: {role}")
        elif sha256(artifact) != expected_hash:
            errors.append(f"commercial operations artifact hash mismatch: {role}")
            continue
        artifact_json = load_artifact_json(artifact, role, errors)
        if artifact_json is None:
            continue
        channel = "support" if role.startswith("support_") else "security"
        route = SUPPORT_URL if channel == "support" else SECURITY_URL
        drill = drills[channel]
        if role.endswith("_notification_delivery"):
            validate_notification_artifact(
                artifact_json, role, route, drill, verified_utc, errors
            )
        else:
            validate_acknowledgement_artifact(
                artifact_json, role, route, drill, verified_utc, errors
            )
    for role in sorted(REQUIRED_ARTIFACT_ROLES - seen):
        errors.append(f"commercial operations artifact role is missing: {role}")


def validate_commercial_evidence(path: Path) -> list[str]:
    errors: list[str] = []
    evidence = load_json(path, errors)
    if evidence is None:
        return errors
    exact_fields = {
        "schema": SCHEMA,
        "repository_url": REPOSITORY_URL,
        "support_route": SUPPORT_URL,
        "security_route": SECURITY_URL,
        "assigned_owner": ASSIGNED_OWNER,
    }
    for field, expected in exact_fields.items():
        if evidence.get(field) != expected:
            errors.append(f"commercial operations {field} must equal {expected}")
    for field in (
        "issues_enabled",
        "private_vulnerability_reporting_enabled",
        "secret_scanning_enabled",
        "secret_scanning_push_protection_enabled",
        "dependabot_security_updates_enabled",
        "notification_delivery_verified",
        "redaction_review_completed",
    ):
        if evidence.get(field) is not True:
            errors.append(f"commercial operations {field} must be true")
    verified = parse_utc(evidence.get("verified_utc"), "verified_utc", errors)
    support_drill = validate_drill(
        evidence.get("support_acknowledgement_drill"), "support", verified, errors
    )
    security_drill = validate_drill(
        evidence.get("security_acknowledgement_drill"), "security", verified, errors
    )
    validate_artifacts(
        path,
        evidence.get("artifacts"),
        verified,
        {"support": support_drill, "security": security_drill},
        errors,
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-contract", action="store_true")
    mode.add_argument("--commercial-ready-evidence", type=Path)
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[2]
    source_errors = validate_source_contract(root)
    evidence_errors: list[str] = []
    if args.commercial_ready_evidence is not None:
        evidence_errors = validate_commercial_evidence(
            args.commercial_ready_evidence.resolve()
        )
    errors = source_errors + evidence_errors
    if errors:
        print("Commercial operations validation FAILED")
        for error in errors:
            print(f" - {error}")
        print("Gate table:")
        print(f" - commercial-source-contract: {'FAIL' if source_errors else 'PASS'}")
        print(" - commercial-operations: FAIL")
        return 1

    print("Commercial source contract PASS")
    print("Gate table:")
    print(" - commercial-source-contract: PASS")
    if args.source_contract:
        print(" - commercial-operations: NOT RUN")
    else:
        print(" - commercial-operations: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
