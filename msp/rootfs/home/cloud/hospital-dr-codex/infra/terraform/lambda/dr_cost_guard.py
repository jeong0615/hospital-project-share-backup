import ipaddress
import json
import os
import urllib.request

import boto3


ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")
INSTANCE_NAMES = {
    "web": "Hospital-Real-Web-Server",
    "doc": "Hospital-DR-Doc-Server",
    "db": "Hospital-DR-DB-Server",
}
INSTANCE_ID_MAP = os.environ.get("INSTANCE_ID_MAP", "")
CF_TOKEN_PARAM_NAME = os.environ.get("CF_TOKEN_PARAM_NAME", "")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "")
CF_RECORD_ID = os.environ.get("CF_RECORD_ID", "")
CF_EMR_RECORD_ID = os.environ.get("CF_EMR_RECORD_ID", "")
CF_DOMAIN = os.environ.get("CF_DOMAIN", "hospital-web.pp.ua")
CF_EMR_DOMAIN = os.environ.get("CF_EMR_DOMAIN", "emr.hospital-web.pp.ua")
DR_ORIGIN_IP = os.environ.get("DR_ORIGIN_IP", "")
ONPREM_TUNNEL_HOST = os.environ.get("ONPREM_TUNNEL_HOST", "")
ONPREM_EMR_DNS_IP = os.environ.get("ONPREM_EMR_DNS_IP", "")
NAT_EIP_NAME = os.environ.get("NAT_EIP_NAME", "")
NAT_EIP_PURPOSE = os.environ.get("NAT_EIP_PURPOSE", "")
_cf_api_token_cache = None


class GuardError(Exception):
    def __init__(self, reason_code):
        super().__init__(reason_code)
        self.reason_code = reason_code


def tag_value(resource, key):
    for tag in resource.get("Tags", []):
        if tag.get("Key") == key:
            return tag.get("Value", "")
    return ""


def configured_instance_ids():
    try:
        mapping = json.loads(INSTANCE_ID_MAP)
    except (TypeError, ValueError):
        raise GuardError("INSTANCE_ID_MAP_INVALID") from None
    if not isinstance(mapping, dict) or set(mapping) != set(INSTANCE_NAMES):
        raise GuardError("INSTANCE_ID_MAP_INCOMPLETE")
    ids = [mapping.get(role) for role in ("web", "doc", "db")]
    if any(not isinstance(item, str) or not item.startswith("i-") for item in ids):
        raise GuardError("INSTANCE_ID_MAP_INVALID")
    if len(set(ids)) != len(ids):
        raise GuardError("INSTANCE_ID_MAP_DUPLICATE")
    return mapping


def _describe_expected_instances():
    expected = configured_instance_ids()
    expected_by_id = {instance_id: role for role, instance_id in expected.items()}
    response = ec2.describe_instances(InstanceIds=list(expected_by_id))
    found = {}
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            role = expected_by_id.get(instance_id)
            if role is None or instance_id in found:
                raise GuardError("EC2_IDENTITY_MISMATCH")
            if tag_value(instance, "Name") != INSTANCE_NAMES[role]:
                raise GuardError("EC2_IDENTITY_MISMATCH")
            state = instance.get("State", {}).get("Name")
            if state not in {"pending", "running", "stopped", "stopping"}:
                raise GuardError("EC2_STATE_UNSAFE")
            found[instance_id] = state
    if set(found) != set(expected_by_id):
        raise GuardError("EC2_IDENTITY_INCOMPLETE")
    return expected, found


def cleanup_detached_nat_eips():
    if not NAT_EIP_NAME or not NAT_EIP_PURPOSE:
        raise GuardError("NAT_EIP_CLEANUP_CONFIGURATION_INCOMPLETE")
    response = ec2.describe_addresses(
        Filters=[
            {"Name": "tag:Name", "Values": [NAT_EIP_NAME]},
            {"Name": "tag:Purpose", "Values": [NAT_EIP_PURPOSE]},
        ]
    )
    result = {
        "status": "SUCCESS",
        "released_count": 0,
        "preserved_count": 0,
        "associated_count": 0,
        "failed_count": 0,
    }
    for address in response.get("Addresses", []):
        if tag_value(address, "Name") != NAT_EIP_NAME or tag_value(address, "Purpose") != NAT_EIP_PURPOSE:
            continue
        if tag_value(address, "Preserve").strip().lower() in {"true", "1", "yes"}:
            result["preserved_count"] += 1
            continue
        if any(address.get(key) for key in ("AssociationId", "NetworkInterfaceId", "InstanceId")):
            result["associated_count"] += 1
            continue
        allocation_id = address.get("AllocationId")
        if not allocation_id:
            result["failed_count"] += 1
            continue
        try:
            ec2.release_address(AllocationId=allocation_id)
            result["released_count"] += 1
        except Exception:
            result["failed_count"] += 1
    if result["failed_count"]:
        result["status"] = "PARTIAL_FAILURE" if result["released_count"] else "FAILED"
    return result


def get_cloudflare_api_token():
    global _cf_api_token_cache
    if _cf_api_token_cache:
        return _cf_api_token_cache
    if not CF_TOKEN_PARAM_NAME:
        raise GuardError("CLOUDFLARE_TOKEN_PARAMETER_UNCONFIGURED")
    response = ssm.get_parameter(Name=CF_TOKEN_PARAM_NAME, WithDecryption=True)
    _cf_api_token_cache = response["Parameter"]["Value"]
    if not _cf_api_token_cache:
        raise GuardError("CLOUDFLARE_TOKEN_UNAVAILABLE")
    return _cf_api_token_cache


def _normalize_name(value):
    return str(value or "").rstrip(".").lower()


def _global_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_global


def _dns_configuration():
    required = (
        CF_TOKEN_PARAM_NAME,
        CF_ZONE_ID,
        CF_RECORD_ID,
        CF_EMR_RECORD_ID,
        CF_DOMAIN,
        CF_EMR_DOMAIN,
        ONPREM_TUNNEL_HOST,
    )
    if not all(required) or not _global_ipv4(DR_ORIGIN_IP) or not _global_ipv4(ONPREM_EMR_DNS_IP):
        raise GuardError("DNS_CONFIGURATION_INCOMPLETE")
    if CF_RECORD_ID == CF_EMR_RECORD_ID or _normalize_name(CF_DOMAIN) == _normalize_name(CF_EMR_DOMAIN):
        raise GuardError("DNS_RECORD_IDENTITY_DUPLICATE")
    return {
        "web": {
            "id": CF_RECORD_ID,
            "name": CF_DOMAIN,
            "origin_type": "A",
            "origin_content": DR_ORIGIN_IP,
            "target_type": "CNAME",
            "target_content": ONPREM_TUNNEL_HOST,
        },
        "emr": {
            "id": CF_EMR_RECORD_ID,
            "name": CF_EMR_DOMAIN,
            "origin_type": "A",
            "origin_content": DR_ORIGIN_IP,
            "target_type": "A",
            "target_content": ONPREM_EMR_DNS_IP,
        },
    }


def _cloudflare_request(method, record_id, token, payload=None):
    url = (
        f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}"
        f"/dns_records/{record_id}"
    )
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        document = json.loads(response.read().decode("utf-8"))
    if not document.get("success") or not isinstance(document.get("result"), dict):
        raise GuardError("CLOUDFLARE_API_REJECTED")
    return document["result"]


def _record_snapshot(record, config):
    if (
        record.get("id") != config["id"]
        or record.get("zone_id") != CF_ZONE_ID
        or _normalize_name(record.get("name")) != _normalize_name(config["name"])
        or record.get("proxied") is not True
    ):
        raise GuardError("DNS_RECORD_IDENTITY_MISMATCH")
    record_type = record.get("type")
    content = record.get("content")
    origin_matches = (
        record_type == config["origin_type"]
        and content == config["origin_content"]
    )
    target_matches = (
        record_type == config["target_type"]
        and _normalize_name(content) == _normalize_name(config["target_content"])
    )
    if not (origin_matches or target_matches):
        raise GuardError("DNS_CURRENT_TARGET_UNEXPECTED")
    snapshot = {
        "type": record_type,
        "name": record["name"],
        "content": content,
        "proxied": True,
    }
    if isinstance(record.get("ttl"), int):
        snapshot["ttl"] = record["ttl"]
    return snapshot, target_matches


def _record_matches(record, config, record_type, content):
    return (
        record.get("id") == config["id"]
        and record.get("zone_id") == CF_ZONE_ID
        and _normalize_name(record.get("name")) == _normalize_name(config["name"])
        and record.get("type") == record_type
        and _normalize_name(record.get("content")) == _normalize_name(content)
        and record.get("proxied") is True
    )


def _patch_and_readback(role, config, snapshot, token, record_type, content):
    payload = {
        "type": record_type,
        "name": config["name"],
        "content": content,
        "proxied": True,
    }
    if "ttl" in snapshot:
        payload["ttl"] = snapshot["ttl"]
    _cloudflare_request("PATCH", config["id"], token, payload)
    readback = _cloudflare_request("GET", config["id"], token)
    if not _record_matches(readback, config, record_type, content):
        raise GuardError(f"DNS_{role.upper()}_READBACK_MISMATCH")


def switch_dns_to_onpremises():
    record_status = {
        "web": "UNVERIFIED",
        "emr": "UNVERIFIED",
    }
    rollback_status = "NOT_REQUIRED"
    touched = []
    try:
        configuration = _dns_configuration()
        token = get_cloudflare_api_token()
        preflight = {}
        for role in ("web", "emr"):
            config = configuration[role]
            current = _cloudflare_request("GET", config["id"], token)
            snapshot, already_target = _record_snapshot(current, config)
            preflight[role] = {"snapshot": snapshot, "already_target": already_target}
            record_status[role] = "ALREADY_ONPREM_VERIFIED" if already_target else "PREFLIGHT_VERIFIED"

        target_pair = (preflight["web"]["already_target"], preflight["emr"]["already_target"])
        # Accept both fully-known endpoints and the exact Web-only fallback
        # produced by the deployed legacy Lambda; reject the opposite split.
        if target_pair not in {(False, False), (True, False), (True, True)}:
            raise GuardError("DNS_PAIR_STATE_CONFLICT")

        for role in ("web", "emr"):
            config = configuration[role]
            state = preflight[role]
            if state["already_target"]:
                continue
            # Mark touched before the request: an API timeout can occur after
            # Cloudflare applied the update, so compensation must still run.
            touched.append(role)
            record_status[role] = "UPDATE_ATTEMPTED"
            _patch_and_readback(
                role,
                config,
                state["snapshot"],
                token,
                config["target_type"],
                config["target_content"],
            )
            record_status[role] = "UPDATED_READBACK_VERIFIED"
        return {
            "status": "VERIFIED",
            "reason_code": "DNS_PAIR_ONPREM_READBACK_VERIFIED",
            "web_status": record_status["web"],
            "emr_status": record_status["emr"],
            "rollback_status": rollback_status,
        }
    except Exception as error:
        reason_code = error.reason_code if isinstance(error, GuardError) else "DNS_OPERATION_FAILED"
        if touched:
            rollback_failed = False
            for role in reversed(touched):
                try:
                    config = configuration[role]
                    snapshot = preflight[role]["snapshot"]
                    _cloudflare_request("PATCH", config["id"], token, snapshot)
                    restored = _cloudflare_request("GET", config["id"], token)
                    if not _record_matches(
                        restored, config, snapshot["type"], snapshot["content"]
                    ):
                        raise GuardError("DNS_ROLLBACK_READBACK_MISMATCH")
                    record_status[role] = "ROLLED_BACK_READBACK_VERIFIED"
                except Exception:
                    rollback_failed = True
                    record_status[role] = "ROLLBACK_UNVERIFIED"
            rollback_status = "PARTIAL_FAILURE" if rollback_failed else "RESTORED_READBACK_VERIFIED"
        status = "PARTIAL_FAILURE" if touched else "BLOCKED"
        return {
            "status": status,
            "reason_code": reason_code,
            "web_status": record_status["web"],
            "emr_status": record_status["emr"],
            "rollback_status": rollback_status,
        }


def lambda_handler(event, _context):
    action = (event or {}).get("action", "shutdown")
    result = {"action": action}

    if action == "selftest":
        try:
            result["cloudflare_token_available"] = bool(get_cloudflare_api_token())
        except Exception:
            result["cloudflare_token_available"] = False
        return result

    if action == "shutdown":
        result["dr_state_status"] = "UNVERIFIED_NOT_CONNECTED"
        try:
            _describe_expected_instances()
            result["ec2_identity_status"] = "VERIFIED"
        except GuardError as error:
            result["ec2_identity_status"] = error.reason_code
            result["dns_status"] = "NOT_ATTEMPTED"
            result["ec2_stop_status"] = "NOT_ATTEMPTED"
            result["shutdown_status"] = "BLOCKED"
            result["workflow_status"] = "BLOCKED"
            print(json.dumps(result, sort_keys=True))
            return result
        except Exception:
            result["ec2_identity_status"] = "UNVERIFIED"
            result["dns_status"] = "NOT_ATTEMPTED"
            result["ec2_stop_status"] = "NOT_ATTEMPTED"
            result["shutdown_status"] = "BLOCKED"
            result["workflow_status"] = "BLOCKED"
            print(json.dumps(result, sort_keys=True))
            return result

        dns_result = switch_dns_to_onpremises()
        result["dns_status"] = dns_result["status"]
        result["dns_reason_code"] = dns_result["reason_code"]
        result["dns_web_status"] = dns_result["web_status"]
        result["dns_emr_status"] = dns_result["emr_status"]
        result["dns_rollback_status"] = dns_result["rollback_status"]
        if dns_result["status"] != "VERIFIED":
            result["ec2_stop_status"] = "NOT_ATTEMPTED"
            result["shutdown_status"] = dns_result["status"]
            result["workflow_status"] = dns_result["status"]
            print(json.dumps(result, sort_keys=True))
            return result

        # EC2 lifecycle is operator-managed. This scheduled action may restore
        # DNS after its checks, but must never stop the existing DR instances.
        result["ec2_stop_status"] = "NOT_ATTEMPTED_OPERATOR_MANAGED"
        result["shutdown_status"] = "DNS_VERIFIED_EC2_UNCHANGED"
        # Local ChatOps DR state is not readable from this Lambda.
        result["workflow_status"] = "UNVERIFIED_DR_STATE_NOT_CONNECTED"
        print(json.dumps(result, sort_keys=True))
        return result

    if action == "cleanup":
        # 19:20 cleanup is separate from shutdown and only releases explicitly
        # tagged, detached, non-preserved NAT egress addresses. It never deletes
        # a NAT Gateway and never runs as part of the 19:00 shutdown action.
        try:
            result.update(cleanup_detached_nat_eips())
        except Exception:
            result.update(
                {
                    "status": "FAILED_OR_UNVERIFIED",
                    "reason_code": "EIP_CLEANUP_FAILED_OR_UNVERIFIED",
                }
            )
        print(json.dumps(result, sort_keys=True))
        return result

    result["status"] = "BLOCKED"
    result["reason_code"] = "UNKNOWN_ACTION"
    print(json.dumps(result, sort_keys=True))
    return result
