#!/usr/bin/env python3
"""Create a private, presentation-safe Markdown summary for one ChatOps run.

Read-only formatter: it never queries infrastructure or starts a DR workflow.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from operations.preflight.rto_rpo_evidence_collector import collect_evidence  # noqa: E402

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAFE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
MOCK_RE = re.compile(r"\b(?:MOCK|DRY[-_ ]?RUN|TEST[_ -]?MODE)\b", re.IGNORECASE)
REQUEST_STATES = {
    "PENDING", "PARTIALLY_APPROVED", "EXECUTING", "SUCCEEDED", "FAILED",
    "PARTIAL_FAILURE", "DB_RESTORED_NOT_FAILOVER_COMPLETE",
    "APPS_READY_NOT_DNS_SWITCHED", "CANCELLED", "EXPIRED",
}
LOG_OK = {
    "execution_started": "Workflow process started; streaming sanitized output.",
    "aws": "[AWS VALIDATION] Approved DR instance set is running and passed instance status checks.",
    "db": "[DB PROMOTION] Same DR DB identity verified after restart; read_only=0 super_read_only=0; hospital_db SELECT probe passed.",
    "apps": "[VALIDATION] Web and EMR reached the approved DR DB endpoint and passed the non-identifying SELECT health probe.",
    "apps_containers": "[VALIDATION] DR Web and EMR container health passed over the approved SSH management path.",
    "nat": "[NAT VALIDATION] Existing read-only status verifier returned an accepted state.",
    "dns": "[DNS] DR public health passed after both records were verified.",
    "completed": "Full DR failover completed.",
    "dr_active": "[DR STATE] DR_ACTIVE persisted after full failover verification.",
}
LOG_FAIL = {
    "aws": ("[START ERROR]", "[AWS VALIDATION ERROR]"),
    "db": ("[DB PROMOTION ERROR]", "[DB PROMOTION PARTIAL_FAILURE]"),
    "apps": ("[APPLICATION ERROR]", "[APPLICATION VALIDATION ERROR]"),
    "nat": ("[NAT VALIDATION ERROR]",),
    "dns": ("[DNS ERROR]", "[DNS ROLLBACK ERROR]", "[VALIDATION ERROR]"),
}
def fmt_time(value: Any) -> str | None:
    if value is None or isinstance(value, bool) or str(value).strip() == "":
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d+(?:\.\d+)?", str(value).strip()):
            epoch = float(value)
            if not math.isfinite(epoch):
                return None
            dt = datetime.fromtimestamp(epoch, timezone.utc)
        else:
            raw = str(value).strip()
            dt = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
            if dt.tzinfo is None:
                return None
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def read_request(path: Path, request_id: str) -> tuple[str, dict[str, Any] | None]:
    try:
        meta = path.lstat()
        if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
            return "INVALID", None
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='approval_requests'"
            ).fetchone()
            if not exists:
                return "INVALID", None
            row = db.execute(
                "SELECT * FROM approval_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if row is None:
                return "NOT_FOUND", None
            columns = [item[1] for item in db.execute("PRAGMA table_info(approval_requests)")]
            result = dict(zip(columns, row))
    except FileNotFoundError:
        return "MISSING", None
    except (OSError, sqlite3.Error, ValueError):
        return "UNREADABLE", None
    try:
        incidents = json.loads(result.get("incidents") or "[]")
        approvers = json.loads(result.get("approvers") or "[]")
    except (TypeError, json.JSONDecodeError):
        return "INVALID", None
    if not isinstance(incidents, list) or not isinstance(approvers, list):
        return "INVALID", None
    result["incidents"] = [item for item in incidents if isinstance(item, dict)]
    result["approvers"] = [str(item) for item in approvers if item is not None and str(item)]
    return "FOUND", result


def choose_run_pair(incidents: list[dict[str, Any]], request_id: str, timeline: Path):
    pairs: set[tuple[str, str]] = set()
    incident_runs: dict[str, set[str]] = {}
    for incident in incidents:
        incident_id = str(incident.get("incident_id") or "")
        run_id = str(incident.get("rto_run_id") or "")
        if not SAFE_ID.fullmatch(incident_id):
            continue
        if not run_id:
            prefix = "zabbix" if str(incident.get("source") or "").lower() == "zabbix" else "chatops"
            run_id = f"{prefix}-{incident_id}"
        if SAFE_ID.fullmatch(run_id):
            pairs.add((run_id, incident_id))
            incident_runs.setdefault(incident_id, set()).add(run_id)
    if len(pairs) == 1:
        return next(iter(pairs))
    if not timeline.is_file():
        return None
    try:
        document = json.loads(timeline.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    runs = document.get("runs", []) if isinstance(document, dict) else []
    if not isinstance(runs, list):
        return None
    matches = []
    for run in runs if isinstance(runs, list) else []:
        stages = run.get("stages") if isinstance(run, dict) else None
        run_id = str(run.get("run_id") or "") if isinstance(run, dict) else ""
        if not isinstance(stages, dict) or not SAFE_ID.fullmatch(run_id):
            continue
        has_request = any(
            isinstance(stage, dict) and str(stage.get("approval_id") or "") == request_id
            for stage in stages.values()
        )
        if not has_request:
            continue
        event_ids = {
            str(stage.get("event_id"))
            for stage in stages.values()
            if isinstance(stage, dict) and stage.get("event_id")
        }
        linked = [incident_id for incident_id in incident_runs if incident_id in event_ids]
        if len(linked) == 1:
            matches.append((run_id, linked[0]))
    return matches[0] if len(matches) == 1 else None


def timeline_request_linked(path: Path, run_id: str | None, incident_id: str | None, request_id: str):
    """Require one run linked to both this incident and this ChatOps request."""
    if not run_id or not incident_id:
        return False, None, None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, None, None
    runs = document.get("runs", []) if isinstance(document, dict) else []
    if not isinstance(runs, list):
        return False, None, None
    matches = [run for run in runs if isinstance(run, dict) and run.get("run_id") == run_id]
    if len(matches) != 1 or not isinstance(matches[0].get("stages"), dict):
        return False, None, None
    stages = matches[0]["stages"]
    incident_linked = any(
        isinstance(stage, dict) and str(stage.get("event_id") or "") == incident_id
        for stage in stages.values()
    )
    request_linked = any(
        isinstance(stage, dict) and str(stage.get("approval_id") or "") == request_id
        for stage in stages.values()
    )
    second_approval_at = None
    for stage_name in ("second_approval_at", "failover_approved_at"):
        stage = stages.get(stage_name)
        if isinstance(stage, dict) and str(stage.get("approval_id") or "") == request_id:
            event_id = str(stage.get("event_id") or "")
            if not event_id or event_id == incident_id:
                second_approval_at = fmt_time(stage.get("at"))
                break
    execution_started_at = None
    started = stages.get("failover_started_at")
    if isinstance(started, dict) and str(started.get("approval_id") or "") == request_id:
        event_id = str(started.get("event_id") or "")
        if not event_id or event_id == incident_id:
            execution_started_at = fmt_time(started.get("at"))
    return incident_linked and request_linked, second_approval_at, execution_started_at


def read_log(path: Path, request_id: str):
    ok = {key: False for key in LOG_OK}
    ok["request_bound"] = False
    failed = {key: False for key in LOG_FAIL}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
                return "INVALID", ok, failed, False
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(8 * 1024 * 1024 + 1)
        finally:
            if fd >= 0:
                os.close(fd)
    except FileNotFoundError:
        return "MISSING", ok, failed, False
    except OSError:
        return "UNREADABLE", ok, failed, False
    if len(raw) > 8 * 1024 * 1024:
        return "INVALID", ok, failed, False
    text = raw.decode("utf-8", errors="replace")
    lines = set(text.splitlines())
    ok = {key: marker in text for key, marker in LOG_OK.items()}
    ok["request_bound"] = f"[CORRELATION] request_id={request_id}" in lines
    failed = {key: any(marker in text for marker in markers) for key, markers in LOG_FAIL.items()}
    return "READ", ok, failed, MOCK_RE.search(text) is not None


def read_dr_state(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128:
                return "UNVERIFIED"
            with os.fdopen(fd, "r", encoding="ascii") as stream:
                fd = -1
                value = stream.read(129).strip()
        finally:
            if fd >= 0:
                os.close(fd)
    except (OSError, UnicodeError):
        return "UNVERIFIED"
    allowed = {"IDLE", "FAILOVER_EXECUTING", "DR_ACTIVE", "FAILBACK_EXECUTING", "FAILED", "PARTIAL_FAILURE"}
    return value if value in allowed else "UNVERIFIED"


def build_report_data(
    *, request_id: str, state_db: Path, audit: Path, timeline: Path,
    timing_log: Path | None, rpo_input: Path | None, db_nr_enabled: str,
    dr_state: Path, execution_log: Path, evidence_mode: str = "MOCK",
) -> dict[str, Any]:
    if not SAFE_ID.fullmatch(request_id):
        raise ValueError("invalid request_id")
    source_status, row = read_request(state_db, request_id)
    log_status, log_ok, log_failed, log_mock = read_log(execution_log, request_id)
    current_state = read_dr_state(dr_state)
    mock = evidence_mode == "MOCK" or log_mock or bool(
        row and any(
            item.get("test_mode") is True or str(item.get("test_mode") or "").lower() in {"1", "true", "yes"}
            for item in row["incidents"]
        )
    )
    pair = choose_run_pair(row["incidents"], request_id, timeline) if row else None
    evidence = None
    if pair:
        run_id, incident_id = pair
        try:
            evidence = collect_evidence(
                run_id=run_id, incident_id=incident_id, timeline_path=timeline,
                state_db_path=state_db, audit_path=audit, timing_path=timing_log,
                rpo_input_path=rpo_input, db_nr_enabled=db_nr_enabled,
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            evidence = None
    else:
        run_id = incident_id = None
    timeline_bound, timeline_second_approval, timeline_execution_started = timeline_request_linked(
        timeline, run_id, incident_id, request_id
    )

    rto = evidence["rto"] if evidence else {
        "rto_status": "NOT_MEASURED", "rto_seconds": None, "events": {},
        "validation_errors": [], "measurement_basis": "UNKNOWN",
    }
    rpo = evidence["rpo"] if evidence else {"rpo_status": "NOT_MEASURED", "rpo_seconds": None}
    events = rto.get("events") or {}
    state = str(row.get("status") or "UNKNOWN").upper() if row else "UNKNOWN"
    action = str(row.get("action") or "UNKNOWN").lower() if row else "UNKNOWN"
    execution_id = str(row.get("execution_id") or "") if row else ""
    display_execution_id = execution_id if SAFE_ID.fullmatch(execution_id) else "UNVERIFIED"
    display_state = state if state in REQUEST_STATES else "UNKNOWN"
    display_action = action if action in {"failover", "failback"} else "UNKNOWN"
    approvers = row.get("approvers", []) if row else []
    two_person = bool(
        row and row.get("approval_required") == 2 and len(approvers) == 2
        and len(set(approvers)) == 2 and row.get("first_approved_at") is not None
        and row.get("execution_started_at") is not None
    )

    def evidence_stage(name: str, success_key: str, requires: tuple[str, ...] = ()):
        if not log_ok.get("request_bound"):
            return {"status": "UNVERIFIED", "detail": "요청 ID 상관관계 표식이 확인되지 않음"}
        if log_failed.get(name):
            return {"status": "FAILED", "detail": "요청 로그에서 실패 표식 확인; 원문 생략"}
        if log_status == "READ" and log_ok.get(success_key) and all(log_ok.get(key) for key in requires):
            return {"status": "VERIFIED", "detail": "요청별 실행 로그의 허용된 성공 표식"}
        return {"status": "UNVERIFIED", "detail": "요청별 성공 증거 없음"}

    def not_reached(previous: str):
        return {"status": "UNVERIFIED", "detail": f"선행 단계({previous}) 검증 증거 없음; 실행 여부 미확인"}

    aws_stage = evidence_stage("aws", "aws")
    db_stage = (
        not_reached("AWS DR 준비") if aws_stage["status"] != "VERIFIED"
        else evidence_stage("db", "db")
    )
    apps_stage = (
        not_reached("DB 승격") if db_stage["status"] != "VERIFIED"
        else evidence_stage("apps", "apps", ("apps_containers",))
    )
    nat_stage = (
        not_reached("Web/EMR 복구") if apps_stage["status"] != "VERIFIED"
        else evidence_stage("nat", "nat")
    )
    dns_stage = (
        not_reached("NAT 상태 검증") if nat_stage["status"] != "VERIFIED"
        else evidence_stage("dns", "dns")
    )
    dr_active_stage = (
        not_reached("DNS 전환 및 공개 Health") if dns_stage["status"] != "VERIFIED"
        else evidence_stage("dr_active", "dr_active")
    )
    events_complete = timeline_bound and all(
        isinstance(events.get(key), dict) and events[key].get("at")
        for key in ("aws_service_healthy_at", "traffic_recovered_at", "failover_completed_at")
    )
    execution_started = bool(
        SAFE_ID.fullmatch(execution_id) and log_status == "READ"
        and log_ok["request_bound"] and log_ok["execution_started"]
    )
    full_completed = bool(
        log_status == "READ" and log_ok["request_bound"]
        and log_ok["completed"] and log_ok["dr_active"]
    )

    if source_status != "FOUND":
        overall = "UNVERIFIED"
    elif state == "FAILED":
        overall = "FAILED"
    elif state == "PARTIAL_FAILURE":
        overall = "BLOCKED"
    elif state != "SUCCEEDED":
        overall = "BLOCKED"
    elif mock:
        overall = "UNVERIFIED"
    elif not (
        action == "failover" and two_person and execution_started
        and aws_stage["status"] == "VERIFIED"
        and db_stage["status"] == "VERIFIED" and apps_stage["status"] == "VERIFIED"
        and nat_stage["status"] == "VERIFIED" and dns_stage["status"] == "VERIFIED"
        and dr_active_stage["status"] == "VERIFIED" and full_completed
        and current_state == "DR_ACTIVE"
        and events_complete and not rto.get("validation_errors")
    ):
        overall = "UNVERIFIED"
    else:
        overall = "SUCCESS"

    current_stage = (
        {"status": "VERIFIED", "detail": f"현재값={current_state}; 수집 시점 값이며 과거 상태 이력 아님"}
        if current_state != "UNVERIFIED"
        else {"status": "UNVERIFIED", "detail": "DR state 파일을 읽지 못함"}
    )
    incidents = row.get("incidents", []) if row else []
    latest = incidents[-1] if incidents else {}
    result_code = str(row.get("result") or "") if row else ""
    if not SAFE_CODE.fullmatch(result_code):
        result_code = "UNKNOWN"
    second_time = timeline_second_approval
    if not second_time and row and row.get("execution_started_at") is not None:
        second_time = (fmt_time(row["execution_started_at"]) or "UNVERIFIED") + " (2인 승인 전이 시각; 별도 시각 필드 없음)"

    def time_event(name: str) -> str:
        if not timeline_bound:
            return "UNVERIFIED"
        value = events.get(name)
        return str(value.get("at")) if isinstance(value, dict) and value.get("at") else "UNVERIFIED"

    rto_seconds = rto.get("rto_seconds") if timeline_bound else None
    rpo_seconds = rpo.get("rpo_seconds")
    sources = (evidence or {}).get("summary", {}).get("sources", {})
    return {
        "request_id": request_id, "source_status": source_status, "request_status": display_state,
        "request_result": result_code, "action": display_action, "execution_id": display_execution_id,
        "run_id": run_id if timeline_bound else "UNVERIFIED",
        "incident_id": incident_id or (str(latest.get("incident_id")) if SAFE_ID.fullmatch(str(latest.get("incident_id") or "")) else "UNVERIFIED"),
        "approver_count": len(set(approvers)), "approval_status": "VERIFIED" if two_person else "UNVERIFIED",
        "created_at": fmt_time(row.get("created_at")) if row else None,
        "incident_at": time_event("incident_detected_at"), "zabbix_at": time_event("zabbix_problem_at"),
        "first_approval_at": fmt_time(row.get("first_approved_at")) if row else None,
        "second_approval_at": second_time or "UNVERIFIED",
        "execution_start_status": "VERIFIED" if execution_started else "UNVERIFIED",
        "execution_log_correlation_status": "VERIFIED" if log_ok["request_bound"] else "UNVERIFIED",
        "execution_started_at": timeline_execution_started or "UNVERIFIED",
        "request_finished_at": fmt_time(row.get("finished_at")) if row else None,
        "service_recovered_at": time_event("aws_service_healthy_at"),
        "dns_recovered_at": time_event("traffic_recovered_at"),
        "failover_completed_at": (
            time_event("failover_completed_at") if overall == "SUCCESS" else "UNVERIFIED"
        ),
        "rto_seconds": rto_seconds if rto_seconds is not None else "NOT_MEASURED",
        "rto_status": rto.get("rto_status", "NOT_MEASURED") if timeline_bound else "NOT_MEASURED",
        "rto_basis": rto.get("measurement_basis", "UNKNOWN"),
        "rpo_seconds": rpo_seconds if rpo_seconds is not None else "NOT_MEASURED",
        "rpo_status": rpo.get("rpo_status", "NOT_MEASURED") if rpo_seconds is not None else "NOT_MEASURED",
        "rpo_evidence_status": rpo.get("rpo_status", "NOT_MEASURED"),
        "rpo_recovered_data_at": (
            fmt_time(rpo.get("last_replicated_at")) or "UNVERIFIED"
        ) if rpo_seconds is not None else "NOT_MEASURED",
        "current_state": current_state, "log_status": log_status,
        "audit_status": sources.get("chatops_audit", {}).get("status", "UNVERIFIED"),
        "timeline_status": (
            "PASS" if timeline_bound else
            ("UNVERIFIED" if sources.get("rto_timeline", {}).get("status") == "PASS"
             else sources.get("rto_timeline", {}).get("status", "UNVERIFIED"))
        ),
        "stages": {
            "요청 ID·실행 로그 연결": {
                "status": "VERIFIED" if log_ok["request_bound"] else "UNVERIFIED",
                "detail": "요청별 실행 로그의 정확한 request_id 표식" if log_ok["request_bound"] else "요청 ID 상관관계 표식 없음",
            },
            "AWS DR 준비": aws_stage,
            "DB 승격 및 쓰기 검증": db_stage,
            "Web/EMR 복구 검증": apps_stage,
            "NAT 상태 검증": nat_stage,
            "DNS 전환·readback·공개 Health": dns_stage,
            "최종 DR_ACTIVE 기록": dr_active_stage,
            "현재 DR 상태": current_stage,
        },
        "overall": overall,
        "mode": "MOCK/TEST — 실제 실행 증거 아님" if mock else "REAL 입력 모드 — 원자료 진위 별도 인증 아님",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# 병원 DR Failover 실행 증거 요약", "",
        f"> 증거 모드: {data['mode']}",
        f"> 전체 결과: {data['overall']}", "",
        f"- 보고서 생성 시각(UTC): {data['generated_at']}",
        f"- ChatOps 요청 ID: {data['request_id']}",
        f"- 실행 ID: {data['execution_id']}",
        f"- RTO run ID: {data['run_id']}",
        f"- 감지 이벤트 ID: {data['incident_id']}",
        f"- ChatOps 상태/결과 코드: {data['request_status']} / {data['request_result']}",
        f"- 요청 로그: {data['log_status']}; 감사 로그: {data['audit_status']}; timeline: {data['timeline_status']}", "",
        "## 실행 타임라인", "", "| 항목 | 기록 |", "|---|---|",
        f"| 장애 감지 | {data['incident_at']} |",
        f"| Zabbix Problem | {data['zabbix_at']} |",
        f"| 승인자 | {data['approver_count']}/2; {data['approval_status']} |",
        f"| 1차 승인 | {data['first_approval_at'] or 'UNVERIFIED'} |",
        f"| 2차 승인 | {data['second_approval_at']} |",
        f"| 실행 프로세스 시작 표식 | {data['execution_start_status']} |",
        f"| 실행 로그 요청 ID 연결 | {data['execution_log_correlation_status']} |",
        f"| 실행 시작 | {data['execution_started_at'] or 'UNVERIFIED'} |",
        f"| 요청 종료/결과 기록 | {data['request_finished_at'] or 'UNVERIFIED'} |",
        f"| 서비스 복구 | {data['service_recovered_at']} |",
        f"| DNS 트래픽 복구 | {data['dns_recovered_at']} |",
        f"| Failover 완료 | {data['failover_completed_at']} |", "",
        "## 단계별 확인", "", "| 단계 | 상태 | 근거 |", "|---|---|---|",
    ]
    for name, stage in data["stages"].items():
        lines.append(f"| {name} | {stage['status']} | {stage['detail']} |")
    lines.extend([
        "", "## RTO / RPO", "",
        f"- RTO: {data['rto_seconds']}초; 상태 {data['rto_status']}; 기준 {data['rto_basis']}.",
        f"- RPO: {data['rpo_seconds']}초; 측정 상태 {data['rpo_status']} (증거 상태 {data['rpo_evidence_status']}); 복구 데이터 기준시각 {data['rpo_recovered_data_at']}.",
        "- 복구 데이터 기준시각이 확인되지 않으면 RPO는 NOT_MEASURED로 유지합니다.", "",
        "## 판정 제한", "",
        "- DR state 파일은 수집 시점의 현재값이며 과거 상태 이력으로 취급하지 않습니다.",
        "- 요청별 로그는 허용된 표식만 검색하며 원문 로그를 보고서에 복사하지 않습니다.",
        "- 승인자 ID, 환자정보, SQL, 인증정보는 보고서에 포함하지 않습니다.",
        "- DR_ACTIVE 또는 ChatOps 성공 상태 하나만으로 전체 SUCCESS를 판정하지 않습니다.", "",
    ])
    return "\n".join(lines)


def write_report(path: Path, content: str) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or parent.resolve() != parent.absolute():
        raise OSError("report directory contains a symbolic link")
    metadata = parent.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise OSError("report directory must be owned by current user and private")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    state_dir = Path(os.environ.get("DR_STATE_DIR", "/var/lib/hospital-dr"))
    state_db = Path(os.environ.get("CHATOPS_STATE_DB", str(state_dir / "chatops_state.sqlite3")))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--state-db", type=Path, default=state_db)
    parser.add_argument("--audit", type=Path, default=Path(os.environ.get("CHATOPS_AUDIT_FILE", str(state_dir / "audit/chatops_audit.jsonl"))))
    parser.add_argument("--timeline", type=Path, default=Path(os.environ.get("DR_RTO_TIMELINE_FILE", str(state_dir / "rto_timeline.json"))))
    parser.add_argument("--timing-log", type=Path, default=Path(os.environ["DR_TIMING_FILE"]) if os.environ.get("DR_TIMING_FILE") else None)
    parser.add_argument("--rpo-input", type=Path)
    parser.add_argument("--db-nr-enabled", default=os.environ.get("DB_NR_ENABLED", "false"))
    parser.add_argument("--dr-state", type=Path, default=Path(os.environ.get("DR_STATE_FILE", str(state_dir / "dr_state"))))
    parser.add_argument("--execution-log", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--evidence-mode", choices=("REAL", "MOCK"), default="MOCK",
        help="default MOCK fails closed; use REAL only for actual, request-correlated runtime records",
    )
    args = parser.parse_args(argv)
    if not SAFE_ID.fullmatch(args.request_id):
        parser.error("--request-id must contain only safe identifier characters")
    log_dir = Path(os.environ.get("CHATOPS_EXECUTION_LOG_DIR", str(state_db.parent / "execution-logs")))
    log_path = args.execution_log or log_dir / f"{args.request_id}.log"
    output = args.output or Path(os.environ.get("DR_EVIDENCE_ROOT", str(state_db.parent / "evidence"))) / f"failover-{args.request_id}.md"
    try:
        data = build_report_data(
            request_id=args.request_id, state_db=args.state_db, audit=args.audit,
            timeline=args.timeline, timing_log=args.timing_log, rpo_input=args.rpo_input,
            db_nr_enabled=args.db_nr_enabled, dr_state=args.dr_state,
            execution_log=log_path, evidence_mode=args.evidence_mode,
        )
        write_report(output, render_markdown(data))
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"EVIDENCE_REPORT_ERROR={type(exc).__name__}", file=sys.stderr)
        return 2
    print(f"REQUEST_ID={args.request_id}")
    print(f"OVERALL={data['overall']}")
    print(f"REPORT={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
