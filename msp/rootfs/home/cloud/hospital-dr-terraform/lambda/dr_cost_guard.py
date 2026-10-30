import os
import json
import urllib.request

import boto3


ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")
INSTANCE_NAMES = set(os.environ.get("INSTANCE_NAMES", "").split(","))
CF_TOKEN_PARAM_NAME = os.environ.get("CF_TOKEN_PARAM_NAME", "")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "")
CF_RECORD_ID = os.environ.get("CF_RECORD_ID", "")
CF_DOMAIN = os.environ.get("CF_DOMAIN", "hospital-web.pp.ua")
ONPREM_TUNNEL_HOST = os.environ.get("ONPREM_TUNNEL_HOST", "")
_cf_api_token_cache = None


def tag_value(resource, key):
    for tag in resource.get("Tags", []):
        if tag.get("Key") == key:
            return tag.get("Value", "")
    return ""


def stop_dr_instances():
    response = ec2.describe_instances(
        Filters=[
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running"],
            }
        ]
    )
    instance_ids = []
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            if tag_value(instance, "Name") in INSTANCE_NAMES:
                instance_ids.append(instance["InstanceId"])

    if instance_ids:
        ec2.stop_instances(InstanceIds=instance_ids)
    return instance_ids


def get_cloudflare_api_token():
    global _cf_api_token_cache
    if _cf_api_token_cache:
        return _cf_api_token_cache
    if not CF_TOKEN_PARAM_NAME:
        raise RuntimeError("Cloudflare token parameter name is not configured")

    response = ssm.get_parameter(
        Name=CF_TOKEN_PARAM_NAME,
        WithDecryption=True,
    )
    _cf_api_token_cache = response["Parameter"]["Value"]
    return _cf_api_token_cache


def switch_dns_to_onpremises():
    if not all([CF_TOKEN_PARAM_NAME, CF_ZONE_ID, CF_RECORD_ID, ONPREM_TUNNEL_HOST]):
        raise RuntimeError("Cloudflare failback configuration is incomplete")
    cf_api_token = get_cloudflare_api_token()

    payload = json.dumps(
        {
            "type": "CNAME",
            "name": CF_DOMAIN,
            "content": ONPREM_TUNNEL_HOST,
            "ttl": 1,
            "proxied": True,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{CF_RECORD_ID}",
        data=payload,
        method="PUT",
        headers={
            "Authorization": f"Bearer {cf_api_token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("success"):
        raise RuntimeError(f"Cloudflare failback failed: {result.get('errors', [])}")
    return ONPREM_TUNNEL_HOST


def lambda_handler(event, _context):
    action = (event or {}).get("action", "shutdown")
    result = {"action": action}

    if action == "selftest":
        result["cloudflare_token_available"] = bool(get_cloudflare_api_token())
        return result

    if action == "shutdown":
        try:
            result["dns_failback"] = switch_dns_to_onpremises()
        except Exception as error:
            result["dns_failback_error"] = str(error)
        result["stopped_instances"] = stop_dr_instances()
        result["nat_lifecycle"] = "MANUAL_ONLY_OPERATIONS_NAT"
    elif action == "cleanup":
        # Keep compatibility with an already-deployed invocation while making
        # the old automatic cleanup harmless. NAT is controlled only by the
        # explicit operations/nat entrypoints.
        result["nat_lifecycle"] = "MANUAL_ONLY_OPERATIONS_NAT"
    print(result)
    return result
