#!/usr/bin/env python3
"""Validate request-scoped On-Prem application-writer fence evidence.

Evidence is accepted only from the separately provisioned, trusted verifier
invoked by ``dr_environment_control.sh``. This module validates its contract;
it does not turn operator-provided text into proof and does not perform fencing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone


SCHEMA = "hospital-dr-app-writer-fence/v1"
MAX_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
ROLES = {"web", "emr"}
HOST_PROBE = "ssh_host_probe"
INDEPENDENT_METHODS = {"independent_network_fence", "independent_hypervisor_fence"}
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
SHA256_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")


class EvidenceError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _parse_time(value: object) -> float:
    if not isinstance(value, str) or not value:
        raise EvidenceError("verified_at_missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("verified_at_invalid") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("verified_at_timezone_missing")
    return parsed.astimezone(timezone.utc).timestamp()


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate_json_key")
        result[key] = value
    return result


def _require_text(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(reason)
    return value.strip()


def _safe_reference(value: object, reason: str) -> str:
    text = _require_text(value, reason)
    if len(text) > 128 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", text):
        raise EvidenceError(reason)
    return text


def _validate_subject(subject, role, expected, controller_id):
    if not isinstance(subject, dict) or subject.get("role") != role:
        raise EvidenceError(f"{role}_subject_invalid")
    method = subject.get("method")
    if method == HOST_PROBE:
        expected_host = _safe_reference(expected.get("host_id"), f"{role}_host_identity_not_configured")
        expected_fingerprint = _require_text(
            expected.get("host_key_fingerprint"), f"{role}_host_key_not_configured"
        )
        if not SHA256_FINGERPRINT_RE.fullmatch(expected_fingerprint):
            raise EvidenceError(f"{role}_expected_host_key_fingerprint_invalid")
        host_id = _safe_reference(subject.get("host_id"), f"{role}_host_identity_invalid")
        if host_id != expected_host:
            raise EvidenceError(f"{role}_host_identity_mismatch")
        fingerprint = subject.get("host_key_fingerprint")
        if fingerprint != expected_fingerprint:
            raise EvidenceError(f"{role}_host_key_mismatch")
        process_count = subject.get("writer_process_count")
        if (
            subject.get("writer_state") != "STOPPED"
            or isinstance(process_count, bool)
            or not isinstance(process_count, int)
            or process_count != 0
        ):
            raise EvidenceError(f"{role}_writer_not_stopped")
        evidence_id = _safe_reference(subject.get("evidence_id"), f"{role}_evidence_id_missing")
        summary = {
            "identity": host_id,
            "proof_ref": evidence_id,
            "host_key_fingerprint": fingerprint,
        }
    elif method in INDEPENDENT_METHODS:
        expected_target = _safe_reference(
            expected.get("fence_target_id"), f"{role}_fence_target_not_configured"
        )
        expected_controller = _safe_reference(
            controller_id, "fence_controller_identity_not_configured"
        )
        target_id = _safe_reference(subject.get("target_id"), f"{role}_fence_target_invalid")
        actual_controller = _safe_reference(
            subject.get("controller_id"), "fence_controller_identity_invalid"
        )
        if target_id != expected_target:
            raise EvidenceError(f"{role}_fence_target_mismatch")
        if actual_controller != expected_controller:
            raise EvidenceError("fence_controller_identity_mismatch")
        rule_id = _safe_reference(subject.get("rule_id"), f"{role}_fence_rule_missing")
        if subject.get("writer_state") != "ISOLATED":
            raise EvidenceError(f"{role}_writer_not_isolated")
        evidence_id = _safe_reference(subject.get("evidence_id"), f"{role}_evidence_id_missing")
        summary = {
            "identity": target_id,
            "proof_ref": evidence_id,
            "controller_id": actual_controller,
            "rule_id": rule_id,
        }
    else:
        raise EvidenceError(f"{role}_evidence_method_invalid")

    if subject.get("write_path_state") != "BLOCKED":
        raise EvidenceError(f"{role}_write_path_not_blocked")
    if subject.get("readback") != "VERIFIED":
        raise EvidenceError(f"{role}_fence_readback_unverified")
    return method, summary


def validate_evidence(
    payload,
    *,
    request_id: str,
    phase: str,
    expected: dict,
    controller_id: str,
    now: float | None = None,
    max_age_seconds: int = MAX_AGE_SECONDS,
):
    """Validate a fresh, exact-request proof for both application writers."""
    now = datetime.now(timezone.utc).timestamp() if now is None else float(now)
    if not UUID_RE.fullmatch(str(request_id or "")):
        raise EvidenceError("request_id_invalid")
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise EvidenceError("schema_invalid")
    if payload.get("request_id") != request_id:
        raise EvidenceError("request_id_mismatch")
    if payload.get("phase") != phase:
        raise EvidenceError("phase_mismatch")
    if payload.get("result") != "VERIFIED":
        failure_code = payload.get("failure_code")
        if isinstance(failure_code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", failure_code):
            raise EvidenceError(failure_code)
        raise EvidenceError("provider_result_not_verified")
    verified_at = _parse_time(payload.get("verified_at"))
    age = now - verified_at
    if age < -MAX_FUTURE_SKEW_SECONDS:
        raise EvidenceError("evidence_from_future")
    if age > max_age_seconds:
        raise EvidenceError("evidence_stale")

    subjects = payload.get("subjects")
    if not isinstance(subjects, list) or len(subjects) != len(ROLES):
        raise EvidenceError("application_subjects_incomplete")
    by_role = {}
    for subject in subjects:
        if not isinstance(subject, dict):
            raise EvidenceError("application_subject_invalid")
        role = subject.get("role")
        if role not in ROLES or role in by_role:
            raise EvidenceError("application_subjects_ambiguous")
        by_role[role] = subject
    if set(by_role) != ROLES:
        raise EvidenceError("application_subjects_incomplete")

    validated = {
        role: _validate_subject(by_role[role], role, expected.get(role, {}), controller_id)
        for role in sorted(ROLES)
    }
    methods = {role: value[0] for role, value in validated.items()}
    if methods["web"] != methods["emr"]:
        raise EvidenceError("mixed_fence_methods_not_supported")
    return {
        "verified_at": payload["verified_at"],
        "method": methods["web"],
        "request_id": request_id,
        "phase": phase,
        "subjects": {role: value[1] for role, value in validated.items()},
        "proof_sha256": hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def _load_json(raw: str):
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except EvidenceError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence_json_invalid") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--web-host-id", default="")
    parser.add_argument("--web-host-key-fingerprint", default="")
    parser.add_argument("--emr-host-id", default="")
    parser.add_argument("--emr-host-key-fingerprint", default="")
    parser.add_argument("--web-fence-target-id", default="")
    parser.add_argument("--emr-fence-target-id", default="")
    parser.add_argument("--fence-controller-id", default="")
    args = parser.parse_args(argv)
    try:
        payload = _load_json(sys.stdin.read())
        result = validate_evidence(
            payload,
            request_id=args.request_id,
            phase=args.phase,
            expected={
                "web": {
                    "host_id": args.web_host_id,
                    "host_key_fingerprint": args.web_host_key_fingerprint,
                    "fence_target_id": args.web_fence_target_id,
                },
                "emr": {
                    "host_id": args.emr_host_id,
                    "host_key_fingerprint": args.emr_host_key_fingerprint,
                    "fence_target_id": args.emr_fence_target_id,
                },
            },
            controller_id=args.fence_controller_id,
        )
    except EvidenceError as exc:
        print(f"APP_WRITER_FENCE=BLOCKED reason={exc.reason}")
        return 1
    web = result["subjects"]["web"]
    emr = result["subjects"]["emr"]
    proof_details = [
        f"web_identity={web['identity']}",
        f"web_proof_ref={web['proof_ref']}",
        f"emr_identity={emr['identity']}",
        f"emr_proof_ref={emr['proof_ref']}",
    ]
    if "host_key_fingerprint" in web:
        proof_details.extend(
            [
                f"web_host_key={web['host_key_fingerprint']}",
                f"emr_host_key={emr['host_key_fingerprint']}",
            ]
        )
    else:
        proof_details.extend(
            [
                f"fence_controller={web['controller_id']}",
                f"web_fence_rule={web['rule_id']}",
                f"emr_fence_rule={emr['rule_id']}",
            ]
        )
    print(
        "APP_WRITER_FENCE=VERIFIED "
        f"request_id={result['request_id']} phase={result['phase']} "
        f"method={result['method']} verified_at={result['verified_at']} "
        + " ".join(proof_details)
        + " "
        f"proof_sha256={result['proof_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
