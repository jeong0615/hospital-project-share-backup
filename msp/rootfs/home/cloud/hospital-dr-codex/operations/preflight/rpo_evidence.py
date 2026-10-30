#!/usr/bin/env python3
"""Validate operator-supplied, read-only Native Replication evidence.

The helper never connects to MySQL and never starts or changes replication.
The live test operator may export a JSON evidence file from the approved
read-only checks.  Until ``DB_NR_ENABLED=true`` and a complete evidence file
are supplied, the result is explicitly ``NR_NOT_READY`` rather than a fake
zero lag or zero-loss claim.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = (
    "source_log_file",
    "source_log_pos",
    "replica_log_file",
    "replica_log_pos",
    "seconds_behind_source",
    "last_dump_at",
    "incident_at",
    "last_replicated_at",
)
RPO_TARGET_SECONDS = 15 * 60


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _positive_int(value: Any) -> bool:
    try:
        return int(value) >= 0
    except (TypeError, ValueError):
        return False


def collect(input_path: Path | None, *, nr_enabled: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "captured_at": now(),
        "rpo_target": "RPO_15_MINUTES",
        "rpo_target_seconds": RPO_TARGET_SECONDS,
        "rpo_seconds": None,
        "rpo_value_status": "NOT_MEASURED",
        "rpo_value_reason": "RECOVERED_DATA_CUTOFF_NOT_VERIFIED",
        "rpo_status": "NR_NOT_READY",
        "measured": False,
        "reason": "DB_NR_ENABLED_FALSE",
    }
    if str(nr_enabled).strip().lower() != "true":
        return result
    if input_path is None or not input_path.is_file():
        result["reason"] = "EVIDENCE_FILE_MISSING"
        return result
    try:
        evidence = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        result["reason"] = "EVIDENCE_FILE_INVALID"
        return result
    if not isinstance(evidence, dict):
        result["reason"] = "EVIDENCE_OBJECT_INVALID"
        return result
    missing = [field for field in REQUIRED_FIELDS if evidence.get(field) in (None, "")]
    if missing:
        result["reason"] = "EVIDENCE_FIELDS_MISSING"
        result["missing_fields"] = missing
        return result
    numeric = ("source_log_pos", "replica_log_pos", "seconds_behind_source")
    invalid = [field for field in numeric if not _positive_int(evidence.get(field))]
    if invalid:
        result["reason"] = "EVIDENCE_NUMERIC_FIELDS_INVALID"
        result["invalid_fields"] = invalid
        return result
    result.update(
        {
            "rpo_status": "MEASURED",
            "measured": True,
            "source_log_file": str(evidence["source_log_file"]),
            "source_log_pos": int(evidence["source_log_pos"]),
            "replica_log_file": str(evidence["replica_log_file"]),
            "replica_log_pos": int(evidence["replica_log_pos"]),
            "seconds_behind_source": int(evidence["seconds_behind_source"]),
            "last_dump_at": str(evidence["last_dump_at"]),
            "incident_at": str(evidence["incident_at"]),
            "last_replicated_at": str(evidence["last_replicated_at"]),
        }
    )
    return result


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o640)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--db-nr-enabled", default=os.environ.get("DB_NR_ENABLED", "false"))
    args = parser.parse_args(argv)
    result = collect(args.input, nr_enabled=args.db_nr_enabled)
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if result["rpo_status"] == "MEASURED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
