#!/usr/bin/env python3
"""Fail-closed shared lease state machine for Dump restore vs. cost shutdown.

This module is deliberately not wired to the restore controller or the cost
guard Lambda. A caller must provide an AWS STS identity provider, use the
configured DynamoDB table, and handle the returned state before taking any
external action. The DynamoDB implementation uses the low-level client API
and does not import boto3, so the state machine can be unit-tested offline.
"""

from __future__ import annotations

import math
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping


CONTROL_PK = "HOSPITAL_DR#DUMP_RESTORE"
CONTROL_SK = "CONTROL"
AUDIT_PK = "HOSPITAL_DR#DUMP_RESTORE_AUDIT"
MAX_LEASE_SECONDS = 7 * 24 * 60 * 60
_ACTOR_ARN_RE = re.compile(r"^arn:[A-Za-z0-9-]+:(?:iam|sts)::[0-9]{12}:[^*?\s]+$")
_CONTROL_FIELDS = frozenset(
    {
        "state",
        "operation_id",
        "actor_arn",
        "acquired_at",
        "expires_at",
        "max_expires_at",
        "renewed_at",
        "renew_count",
        "revision",
        "updated_at",
        "last_event_id",
        "pending_shutdown_id",
        "pending_shutdown_actor_arn",
        "pending_shutdown_at",
        "shutdown_ready",
        "last_dump_operation_id",
        "last_dump_status",
        "last_dump_finished_at",
        "last_shutdown_id",
        "last_shutdown_status",
        "last_shutdown_finished_at",
    }
)
_LEASE_FIELDS = (
    "operation_id",
    "actor_arn",
    "acquired_at",
    "expires_at",
    "max_expires_at",
    "renewed_at",
    "renew_count",
)
_KNOWN_STATES = frozenset(
    {
        "DUMP_ACTIVE",
        "DUMP_COMPLETED",
        "DUMP_FAILED",
        "SHUTDOWN_CLAIMED",
        "SHUTDOWN_PENDING",
        "SHUTDOWN_COMPLETED",
        "SHUTDOWN_FAILED",
    }
)
class LeaseError(RuntimeError):
    """Base class for safe, non-secret lease errors."""


class InvalidLeaseConfiguration(LeaseError):
    pass


class InvalidOperationId(LeaseError):
    pass


class LeaseAuthorizationError(LeaseError):
    pass


class LeaseBusy(LeaseError):
    pass


class LeaseExpired(LeaseError):
    pass


class LeaseConflict(LeaseError):
    """A conditional transaction lost a race; the caller must re-read."""


class LeaseStoreUnavailable(LeaseError):
    """State is unknown, so no external work may proceed."""


@dataclass(frozen=True)
class LeaseConfig:
    """Deployment-selected timing contract; values are never guessed here."""

    lease_seconds: int
    renew_interval_seconds: int
    max_duration_seconds: int

    def __post_init__(self) -> None:
        values = (self.lease_seconds, self.renew_interval_seconds, self.max_duration_seconds)
        if any(type(value) is not int or value <= 0 for value in values):
            raise InvalidLeaseConfiguration("lease timing values must be positive integers")
        if self.renew_interval_seconds >= self.lease_seconds:
            raise InvalidLeaseConfiguration("renew interval must be shorter than the lease")
        if self.max_duration_seconds < self.lease_seconds:
            raise InvalidLeaseConfiguration("maximum duration must cover at least one lease")
        if self.max_duration_seconds > MAX_LEASE_SECONDS:
            raise InvalidLeaseConfiguration("maximum lease duration exceeds the seven-day safety ceiling")


def _normalize_operation_id(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidOperationId("operation ID must be a UUID")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidOperationId("operation ID must be a UUID") from exc


def _valid_actor_arn(value: str) -> bool:
    return isinstance(value, str) and bool(_ACTOR_ARN_RE.fullmatch(value))


def _canonical_actor_arn(value: str) -> str:
    """Map a standard STS assumed-role session ARN to its IAM role ARN."""
    if not _valid_actor_arn(value):
        raise LeaseAuthorizationError("actor must be an authenticated AWS principal ARN")
    match = re.fullmatch(
        r"arn:([^:]+):sts::([0-9]{12}):assumed-role/([^/]+)/[^/]+",
        value,
    )
    if match:
        partition, account, role_name = match.groups()
        return f"arn:{partition}:iam::{account}:role/{role_name}"
    return value


def _timestamp(value: int | float | None) -> float:
    result = time.time() if value is None else value
    if isinstance(result, bool) or not isinstance(result, (int, float)):
        raise LeaseError("timestamp must be a finite Unix time")
    if not math.isfinite(float(result)) or result <= 0:
        raise LeaseError("timestamp must be a positive finite Unix time")
    return float(result)


def _is_epoch(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and value > 0
    )


def _to_attribute(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise LeaseStoreUnavailable("non-finite number cannot be stored")
        return {"N": str(value)}
    raise LeaseStoreUnavailable("unsupported state attribute type")


def _from_attribute(value: Mapping[str, Any]) -> Any:
    if not isinstance(value, Mapping) or len(value) != 1:
        raise LeaseStoreUnavailable("DynamoDB returned a malformed attribute")
    kind, payload = next(iter(value.items()))
    if kind == "S" and isinstance(payload, str):
        return payload
    if kind == "N" and isinstance(payload, str):
        try:
            numeric = float(payload)
        except ValueError as exc:
            raise LeaseStoreUnavailable("DynamoDB returned a malformed number") from exc
        if not math.isfinite(numeric):
            raise LeaseStoreUnavailable("DynamoDB returned a non-finite number")
        return int(numeric) if numeric.is_integer() else numeric
    if kind == "BOOL" and isinstance(payload, bool):
        return payload
    raise LeaseStoreUnavailable("DynamoDB returned an unsupported attribute")


class DynamoDBLeaseStore:
    """Minimal low-level DynamoDB adapter with strong reads and atomic audit."""

    def __init__(self, client: Any, table_name: str):
        if not isinstance(table_name, str) or not table_name.strip():
            raise ValueError("table_name is required")
        self._client = client
        self.table_name = table_name

    @staticmethod
    def _error_code(error: Exception) -> str:
        response = getattr(error, "response", None)
        if isinstance(response, Mapping):
            return str(response.get("Error", {}).get("Code", ""))
        return ""

    def read_control(self) -> dict[str, Any] | None:
        try:
            response = self._client.get_item(
                TableName=self.table_name,
                Key={"pk": {"S": CONTROL_PK}, "sk": {"S": CONTROL_SK}},
                ConsistentRead=True,
            )
        except Exception as exc:  # AWS SDK exceptions vary by runtime.
            raise LeaseStoreUnavailable("lease state read failed") from exc
        item = response.get("Item") if isinstance(response, Mapping) else None
        if item is None:
            return None
        if not isinstance(item, Mapping):
            raise LeaseStoreUnavailable("lease control record is malformed")
        decoded = {str(key): _from_attribute(value) for key, value in item.items()}
        if decoded.get("pk") != CONTROL_PK or decoded.get("sk") != CONTROL_SK:
            raise LeaseStoreUnavailable("lease control key is invalid")
        if not isinstance(decoded.get("state"), str) or type(decoded.get("revision")) is not int:
            raise LeaseStoreUnavailable("lease control record is incomplete")
        return decoded

    def commit(
        self,
        expected: Mapping[str, Any] | None,
        desired: Mapping[str, Any],
        audit_event: Mapping[str, Any],
    ) -> None:
        if desired.get("pk") != CONTROL_PK or desired.get("sk") != CONTROL_SK:
            raise LeaseStoreUnavailable("refusing an unexpected control key")
        if audit_event.get("pk") != AUDIT_PK or not str(audit_event.get("sk", "")).startswith("AUDIT#"):
            raise LeaseStoreUnavailable("refusing an unexpected audit key")

        names: dict[str, str] = {"#pk": "pk"}
        values: dict[str, Any] = {}
        if expected is None:
            condition = "attribute_not_exists(#pk)"
        else:
            if type(expected.get("revision")) is not int or not isinstance(expected.get("state"), str):
                raise LeaseStoreUnavailable("expected control revision is malformed")
            names.update({"#revision": "revision", "#state": "state"})
            values[":expected_revision"] = _to_attribute(expected["revision"])
            values[":expected_state"] = _to_attribute(expected["state"])
            condition = "#revision = :expected_revision AND #state = :expected_state"

        set_terms = []
        remove_terms = []
        for index, key in enumerate(sorted(key for key in desired if key not in {"pk", "sk"})):
            alias = f"#set{index}"
            token = f":set{index}"
            names[alias] = key
            values[token] = _to_attribute(desired[key])
            set_terms.append(f"{alias} = {token}")

        desired_fields = set(desired) | {"pk", "sk"}
        for index, key in enumerate(sorted(_CONTROL_FIELDS - desired_fields)):
            alias = f"#remove{index}"
            names[alias] = key
            remove_terms.append(alias)

        update_expression = "SET " + ", ".join(set_terms)
        if remove_terms:
            update_expression += " REMOVE " + ", ".join(remove_terms)

        update: dict[str, Any] = {
            "TableName": self.table_name,
            "Key": {"pk": {"S": CONTROL_PK}, "sk": {"S": CONTROL_SK}},
            "UpdateExpression": update_expression,
            "ConditionExpression": condition,
            "ExpressionAttributeNames": names,
        }
        if values:
            update["ExpressionAttributeValues"] = values

        transaction = {
            "TransactItems": [
                {"Update": update},
                {
                    "Put": {
                        "TableName": self.table_name,
                        "Item": {key: _to_attribute(value) for key, value in audit_event.items()},
                        "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                    }
                },
            ],
            "ReturnConsumedCapacity": "NONE",
        }
        try:
            self._client.transact_write_items(**transaction)
        except Exception as exc:
            code = self._error_code(exc)
            if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
                raise LeaseConflict("lease state changed concurrently") from exc
            raise LeaseStoreUnavailable("lease state transaction failed") from exc


def sts_principal_provider(sts_client: Any) -> Callable[[], str]:
    """Return a provider that derives identity from AWS STS, never a request field."""
    def current_principal() -> str:
        try:
            identity = sts_client.get_caller_identity()
            arn = identity["Arn"]
            account = identity["Account"]
        except Exception as exc:
            raise LeaseAuthorizationError("AWS caller identity could not be verified") from exc
        if (
            not isinstance(arn, str)
            or not isinstance(account, str)
            or not re.fullmatch(r"[0-9]{12}", account)
            or f"::{account}:" not in arn
        ):
            raise LeaseAuthorizationError("AWS caller identity response is invalid")
        return arn

    return current_principal


class LeaseCoordinator:
    """Validated state transitions shared by a restore controller and cost guard."""

    def __init__(
        self,
        store: Any,
        config: LeaseConfig,
        *,
        dump_actors: Iterable[str],
        shutdown_actors: Iterable[str],
        principal_provider: Callable[[], str],
        max_cas_attempts: int = 3,
    ):
        self.store = store
        self.config = config
        self.dump_actors = frozenset(_canonical_actor_arn(actor) for actor in dump_actors)
        self.shutdown_actors = frozenset(_canonical_actor_arn(actor) for actor in shutdown_actors)
        if not callable(principal_provider):
            raise LeaseAuthorizationError("an authenticated principal provider is required")
        self.principal_provider = principal_provider
        if not self.dump_actors or not self.shutdown_actors:
            raise LeaseAuthorizationError("both actor allowlists must be explicitly configured")
        if any(not _valid_actor_arn(actor) for actor in self.dump_actors | self.shutdown_actors):
            raise LeaseAuthorizationError("actor allowlists must contain exact AWS principal ARNs")
        if type(max_cas_attempts) is not int or max_cas_attempts < 1 or max_cas_attempts > 10:
            raise ValueError("max_cas_attempts must be between 1 and 10")
        self.max_cas_attempts = max_cas_attempts

    def _current_actor(self) -> str:
        try:
            actor_arn = self.principal_provider()
        except Exception as exc:
            raise LeaseAuthorizationError("AWS caller identity could not be verified") from exc
        return _canonical_actor_arn(actor_arn)

    def _authorize(self, capability: str) -> str:
        allowed = self.dump_actors if capability == "dump" else self.shutdown_actors
        canonical = self._current_actor()
        if canonical not in allowed:
            raise LeaseAuthorizationError("actor is not authorized for this lease operation")
        return canonical

    def _read(self) -> dict[str, Any] | None:
        try:
            current = self.store.read_control()
        except LeaseError:
            raise
        except Exception as exc:
            raise LeaseStoreUnavailable("lease state read failed") from exc
        if current is not None:
            self._validate_control_record(current)
        return current

    @staticmethod
    def _validate_control_record(record: Mapping[str, Any]) -> None:
        state = record.get("state")
        if state not in _KNOWN_STATES or type(record.get("revision")) is not int or record["revision"] < 1:
            raise LeaseStoreUnavailable("lease control state is unknown or malformed")

        if state in {"DUMP_ACTIVE", "SHUTDOWN_CLAIMED"}:
            required = ("operation_id", "actor_arn", "acquired_at", "expires_at", "max_expires_at", "renew_count")
            if any(field not in record for field in required):
                raise LeaseStoreUnavailable("active lease record is incomplete")
            _normalize_operation_id(record["operation_id"])
            if not _valid_actor_arn(record["actor_arn"]) or _canonical_actor_arn(record["actor_arn"]) != record["actor_arn"]:
                raise LeaseStoreUnavailable("active lease actor is invalid")
            if any(not _is_epoch(record[field]) for field in ("acquired_at", "expires_at", "max_expires_at")):
                raise LeaseStoreUnavailable("active lease timestamps are invalid")
            if record["expires_at"] > record["max_expires_at"] or record["max_expires_at"] < record["acquired_at"]:
                raise LeaseStoreUnavailable("active lease expiry bounds are inconsistent")
            if type(record["renew_count"]) is not int or record["renew_count"] < 0:
                raise LeaseStoreUnavailable("active lease renewal counter is invalid")
            if "renewed_at" in record and (
                not _is_epoch(record["renewed_at"])
            ):
                raise LeaseStoreUnavailable("active lease renewal timestamp is invalid")

        elif state == "SHUTDOWN_PENDING":
            try:
                _normalize_operation_id(record.get("pending_shutdown_id"))
            except InvalidOperationId as exc:
                raise LeaseStoreUnavailable("pending shutdown ID is invalid") from exc
            if not _valid_actor_arn(record.get("pending_shutdown_actor_arn")):
                raise LeaseStoreUnavailable("pending shutdown actor is invalid")
            if not _is_epoch(record.get("pending_shutdown_at")):
                raise LeaseStoreUnavailable("pending shutdown timestamp is invalid")
            if "operation_id" in record:
                if record.get("shutdown_ready") is True:
                    raise LeaseStoreUnavailable("pending shutdown cannot be ready while a Dump owner remains")
                required = ("actor_arn", "acquired_at", "expires_at", "max_expires_at", "renew_count")
                if any(field not in record for field in required) or not _valid_actor_arn(record.get("actor_arn")):
                    raise LeaseStoreUnavailable("pending Dump owner record is incomplete")
                _normalize_operation_id(record["operation_id"])
                if any(not _is_epoch(record[field]) for field in ("acquired_at", "expires_at", "max_expires_at")):
                    raise LeaseStoreUnavailable("pending Dump lease timestamps are invalid")
                if type(record.get("renew_count")) is not int or record["renew_count"] < 0:
                    raise LeaseStoreUnavailable("pending Dump renewal counter is invalid")
            elif not (
                record.get("shutdown_ready") is True
                and record.get("last_dump_status") in {"DUMP_COMPLETED", "DUMP_FAILED"}
                and _is_epoch(record.get("last_dump_finished_at"))
            ):
                raise LeaseStoreUnavailable("pending shutdown has no released Dump owner")

        else:
            if any(field in record for field in _LEASE_FIELDS):
                raise LeaseStoreUnavailable("terminal lease state still has an owner")
            if state in {"DUMP_COMPLETED", "DUMP_FAILED"}:
                if record.get("last_dump_status") != state:
                    raise LeaseStoreUnavailable("terminal Dump status is inconsistent")
                _normalize_operation_id(record.get("last_dump_operation_id"))
            if state in {"SHUTDOWN_COMPLETED", "SHUTDOWN_FAILED"}:
                if record.get("last_shutdown_status") != state:
                    raise LeaseStoreUnavailable("terminal shutdown status is inconsistent")
                _normalize_operation_id(record.get("last_shutdown_id"))

    def _commit(
        self,
        current: Mapping[str, Any] | None,
        *,
        state: str,
        actor_arn: str,
        now: float,
        event_type: str,
        reason: str,
        operation_id: str | None,
        updates: Mapping[str, Any] | None = None,
        remove: Iterable[str] = (),
    ) -> dict[str, Any]:
        previous = dict(current) if current is not None else {"pk": CONTROL_PK, "sk": CONTROL_SK}
        target = dict(previous)
        for field in remove:
            target.pop(field, None)
        target.update(updates or {})
        from_state = str(previous.get("state", "NONE"))
        revision = (int(previous.get("revision", 0)) if current else 0) + 1
        event_id = str(uuid.uuid4())
        target.update(
            {
                "state": state,
                "revision": revision,
                "updated_at": now,
                "last_event_id": event_id,
            }
        )
        event: dict[str, Any] = {
            "pk": AUDIT_PK,
            "sk": f"AUDIT#{int(now * 1_000_000):020d}#{event_id}",
            "event_id": event_id,
            "event_type": event_type,
            "from_state": from_state,
            "to_state": state,
            "actor_arn": actor_arn,
            "occurred_at": now,
            "reason_code": reason,
            "revision": revision,
        }
        if operation_id is not None:
            event["operation_id"] = operation_id
        if "expires_at" in target:
            event["lease_expires_at"] = target["expires_at"]
        try:
            self.store.commit(current, target, event)
        except LeaseError:
            raise
        except Exception as exc:
            raise LeaseStoreUnavailable("lease state transaction failed") from exc
        return target

    def _new_lease(self, operation_id: str, actor_arn: str, now: float) -> dict[str, Any]:
        return {
            "operation_id": operation_id,
            "actor_arn": actor_arn,
            "acquired_at": now,
            "expires_at": now + self.config.lease_seconds,
            "max_expires_at": now + self.config.max_duration_seconds,
            "renew_count": 0,
        }

    @staticmethod
    def _lease_is_current(record: Mapping[str, Any], now: float) -> bool:
        expiry = record.get("expires_at")
        maximum = record.get("max_expires_at")
        return (
            isinstance(expiry, (int, float))
            and not isinstance(expiry, bool)
            and isinstance(maximum, (int, float))
            and not isinstance(maximum, bool)
            and now < float(expiry)
            and now < float(maximum)
        )

    @staticmethod
    def _require_owner(record: Mapping[str, Any], operation_id: str, actor_arn: str) -> None:
        if record.get("operation_id") != operation_id or record.get("actor_arn") != actor_arn:
            raise LeaseAuthorizationError("lease owner or operation ID does not match")

    def start_dump(self, operation_id: str, *, now: int | float | None = None) -> dict[str, Any]:
        actor_arn = self._authorize("dump")
        operation_id = _normalize_operation_id(operation_id)
        now_value = _timestamp(now)
        for _ in range(self.max_cas_attempts):
            current = self._read()
            state = current.get("state") if current else None
            if state not in {None, "DUMP_COMPLETED", "DUMP_FAILED", "SHUTDOWN_COMPLETED"}:
                raise LeaseBusy("another operation or unresolved shutdown owns the control record")
            if current and operation_id in {
                current.get("operation_id"),
                current.get("last_dump_operation_id"),
                current.get("last_shutdown_id"),
            }:
                raise LeaseBusy("operation ID has already been used in the current control record")
            try:
                return self._commit(
                    current,
                    state="DUMP_ACTIVE",
                    actor_arn=actor_arn,
                    now=now_value,
                    event_type="DUMP_LEASE_ACQUIRED",
                    reason="AUTHORIZED_DUMP_START",
                    operation_id=operation_id,
                    updates=self._new_lease(operation_id, actor_arn, now_value),
                    remove=("pending_shutdown_id", "pending_shutdown_actor_arn", "pending_shutdown_at", "shutdown_ready"),
                )
            except LeaseConflict:
                continue
        raise LeaseConflict("control record remained contended; no work was started")

    def request_shutdown(
        self,
        shutdown_id: str,
        *,
        now: int | float | None = None,
    ) -> dict[str, Any]:
        """Record a cost-guard claim, or defer it behind an active dump lease."""
        actor_arn = self._authorize("shutdown")
        shutdown_id = _normalize_operation_id(shutdown_id)
        now_value = _timestamp(now)
        for _ in range(self.max_cas_attempts):
            current = self._read()
            state = current.get("state") if current else None

            if state in {"DUMP_ACTIVE", "SHUTDOWN_PENDING"}:
                if state == "SHUTDOWN_PENDING":
                    existing_id = current.get("pending_shutdown_id")
                    existing_actor = current.get("pending_shutdown_actor_arn")
                    if existing_id != shutdown_id or existing_actor != actor_arn:
                        raise LeaseBusy("a different shutdown claim is already pending")
                    if current.get("shutdown_ready") is True and "operation_id" not in current:
                        if (
                            current.get("last_dump_status") not in {"DUMP_COMPLETED", "DUMP_FAILED"}
                            or not isinstance(current.get("last_dump_finished_at"), (int, float))
                            or isinstance(current.get("last_dump_finished_at"), bool)
                        ):
                            raise LeaseStoreUnavailable("pending shutdown handoff record is incomplete")
                        try:
                            return self._commit(
                                current,
                                state="SHUTDOWN_CLAIMED",
                                actor_arn=actor_arn,
                                now=now_value,
                                event_type="SHUTDOWN_CLAIMED",
                                reason="DEFERRED_DUMP_RELEASED",
                                operation_id=shutdown_id,
                                updates=self._new_lease(shutdown_id, actor_arn, now_value),
                                remove=("pending_shutdown_id", "pending_shutdown_actor_arn", "pending_shutdown_at", "shutdown_ready"),
                            )
                        except LeaseConflict:
                            continue
                    # An expired dump lease is not proof that its SSH/restore process stopped.
                    # Keep shutdown deferred until an owner finishes or a later explicit
                    # reconciliation contract proves the old operation is quiescent.
                    return dict(current)

                try:
                    return self._commit(
                        current,
                        state="SHUTDOWN_PENDING",
                        actor_arn=actor_arn,
                        now=now_value,
                        event_type="SHUTDOWN_DEFERRED",
                        reason=("ACTIVE_DUMP_LEASE" if self._lease_is_current(current, now_value) else "EXPIRED_DUMP_REQUIRES_RECONCILIATION"),
                        operation_id=str(current.get("operation_id", "")) or None,
                        updates={
                            "pending_shutdown_id": shutdown_id,
                            "pending_shutdown_actor_arn": actor_arn,
                            "pending_shutdown_at": now_value,
                            "shutdown_ready": False,
                        },
                    )
                except LeaseConflict:
                    continue

            if state == "SHUTDOWN_CLAIMED":
                if current.get("operation_id") == shutdown_id and current.get("actor_arn") == actor_arn:
                    if self._lease_is_current(current, now_value):
                        return dict(current)
                    raise LeaseExpired("shutdown claim expired; explicit reconciliation is required")
                raise LeaseBusy("another shutdown claim has not been reconciled")

            if state not in {None, "DUMP_COMPLETED", "DUMP_FAILED", "SHUTDOWN_COMPLETED", "SHUTDOWN_FAILED"}:
                raise LeaseBusy("control state does not permit a shutdown claim")
            if current and current.get("last_shutdown_id") == shutdown_id:
                raise LeaseBusy("shutdown ID has already been used")
            try:
                return self._commit(
                    current,
                    state="SHUTDOWN_CLAIMED",
                    actor_arn=actor_arn,
                    now=now_value,
                    event_type="SHUTDOWN_CLAIMED",
                    reason="AUTHORIZED_COST_GUARD_CLAIM",
                    operation_id=shutdown_id,
                    updates=self._new_lease(shutdown_id, actor_arn, now_value),
                    remove=("pending_shutdown_id", "pending_shutdown_actor_arn", "pending_shutdown_at", "shutdown_ready"),
                )
            except LeaseConflict:
                continue
        raise LeaseConflict("control record remained contended; no shutdown was claimed")

    def renew(self, operation_id: str, *, now: int | float | None = None) -> dict[str, Any]:
        operation_id = _normalize_operation_id(operation_id)
        now_value = _timestamp(now)
        authenticated_actor = self._current_actor()
        if authenticated_actor not in self.dump_actors | self.shutdown_actors:
            raise LeaseAuthorizationError("actor is not authorized for lease renewal")
        for _ in range(self.max_cas_attempts):
            current = self._read()
            if current is None:
                raise LeaseBusy("no lease exists")
            state = current.get("state")
            if state in {"DUMP_ACTIVE", "SHUTDOWN_PENDING"} and current.get("operation_id") == operation_id:
                if authenticated_actor not in self.dump_actors:
                    raise LeaseAuthorizationError("actor is not authorized to renew a Dump lease")
            elif state == "SHUTDOWN_CLAIMED" and current.get("operation_id") == operation_id:
                if authenticated_actor not in self.shutdown_actors:
                    raise LeaseAuthorizationError("actor is not authorized to renew a shutdown claim")
            else:
                raise LeaseAuthorizationError("operation does not own a renewable lease")
            self._require_owner(current, operation_id, authenticated_actor)
            if not self._lease_is_current(current, now_value):
                raise LeaseExpired("expired lease cannot be renewed")
            last_renewal = current.get("renewed_at", current.get("acquired_at"))
            if not isinstance(last_renewal, (int, float)) or now_value - float(last_renewal) < self.config.renew_interval_seconds:
                raise LeaseError("lease renewal was requested before the configured interval")
            new_expiry = min(now_value + self.config.lease_seconds, float(current["max_expires_at"]))
            if new_expiry <= now_value:
                raise LeaseExpired("maximum lease duration has elapsed")
            try:
                return self._commit(
                    current,
                    state=str(state),
                    actor_arn=authenticated_actor,
                    now=now_value,
                    event_type="LEASE_RENEWED",
                    reason="OWNER_RENEWAL_WITHIN_CONFIGURED_LIMITS",
                    operation_id=operation_id,
                    updates={
                        "expires_at": new_expiry,
                        "renewed_at": now_value,
                        "renew_count": int(current.get("renew_count", 0)) + 1,
                    },
                )
            except LeaseConflict:
                continue
        raise LeaseConflict("control record remained contended; lease was not renewed")

    def finish_dump(
        self,
        operation_id: str,
        *,
        succeeded: bool,
        now: int | float | None = None,
    ) -> dict[str, Any]:
        actor_arn = self._authorize("dump")
        operation_id = _normalize_operation_id(operation_id)
        if type(succeeded) is not bool:
            raise ValueError("succeeded must be a boolean")
        now_value = _timestamp(now)
        for _ in range(self.max_cas_attempts):
            current = self._read()
            if current is None or current.get("state") not in {"DUMP_ACTIVE", "SHUTDOWN_PENDING"}:
                raise LeaseBusy("no active dump lease can be completed")
            self._require_owner(current, operation_id, actor_arn)
            if not self._lease_is_current(current, now_value):
                raise LeaseExpired("expired lease cannot be released or completed")
            dump_status = "DUMP_COMPLETED" if succeeded else "DUMP_FAILED"
            pending_shutdown = current.get("state") == "SHUTDOWN_PENDING"
            target_state = "SHUTDOWN_PENDING" if pending_shutdown else dump_status
            remove = _LEASE_FIELDS
            updates: dict[str, Any] = {
                "last_dump_operation_id": operation_id,
                "last_dump_status": dump_status,
                "last_dump_finished_at": now_value,
            }
            if pending_shutdown:
                updates["shutdown_ready"] = True
            try:
                return self._commit(
                    current,
                    state=target_state,
                    actor_arn=actor_arn,
                    now=now_value,
                    event_type=dump_status,
                    reason="DUMP_OWNER_REPORTED_TERMINAL_RESULT",
                    operation_id=operation_id,
                    updates=updates,
                    remove=remove,
                )
            except LeaseConflict:
                continue
        raise LeaseConflict("control record remained contended; dump completion was not recorded")

    def finish_shutdown(
        self,
        shutdown_id: str,
        *,
        succeeded: bool,
        now: int | float | None = None,
    ) -> dict[str, Any]:
        actor_arn = self._authorize("shutdown")
        shutdown_id = _normalize_operation_id(shutdown_id)
        if type(succeeded) is not bool:
            raise ValueError("succeeded must be a boolean")
        now_value = _timestamp(now)
        for _ in range(self.max_cas_attempts):
            current = self._read()
            if current is None or current.get("state") != "SHUTDOWN_CLAIMED":
                raise LeaseBusy("no active shutdown claim can be completed")
            self._require_owner(current, shutdown_id, actor_arn)
            if not self._lease_is_current(current, now_value):
                raise LeaseExpired("expired shutdown claim cannot be released or completed")
            terminal = "SHUTDOWN_COMPLETED" if succeeded else "SHUTDOWN_FAILED"
            try:
                return self._commit(
                    current,
                    state=terminal,
                    actor_arn=actor_arn,
                    now=now_value,
                    event_type=terminal,
                    reason="COST_GUARD_REPORTED_TERMINAL_RESULT",
                    operation_id=shutdown_id,
                    updates={
                        "last_shutdown_id": shutdown_id,
                        "last_shutdown_status": terminal,
                        "last_shutdown_finished_at": now_value,
                    },
                    remove=_LEASE_FIELDS,
                )
            except LeaseConflict:
                continue
        raise LeaseConflict("control record remained contended; shutdown completion was not recorded")
