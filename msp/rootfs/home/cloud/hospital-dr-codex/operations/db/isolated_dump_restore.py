#!/usr/bin/env python3
"""Read-only AWS preflight and explicit Ansible orchestration for isolated dump validation.

This tool never starts/stops EC2, edits AWS resources, changes DR state, or calls
ChatOps/DNS. It targets only the opt-in isolated restore instance.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operations.db.isolated_restore_host import (  # noqa: E402
    PRODUCTION_DB_INSTANCE_ID,
    PROTECTED_PRIVATE_IPS,
    RestoreError,
    parse_master_status,
)
from operations.db.backup_manifest import (  # noqa: E402
    ManifestError,
    sha256_file,
    verify_manifest_files,
)

ISOLATED_NAME = "Hospital-DR-Dump-Restore-Isolated"
ISOLATED_ROLE = "isolated-dump-restore-validation"
ISOLATED_SG_NAME = "hospital-dr-dump-restore-isolated-sg"
ISOLATED_SERVICE_SG_NAME = "hospital-dr-dump-restore-service-sg"
WEB_NAME = "Hospital-Real-Web-Server"
DOC_NAME = "Hospital-DR-Doc-Server"
WEB_PRIVATE_IP = "IP_REDACTED"
DOC_PRIVATE_IP = "IP_REDACTED"
ISOLATED_SERVICE_PORT = 3307
BACKUP_NAME_RE = re.compile(r"db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc\Z")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class PreflightError(RuntimeError):
    """A safe, non-secret failure category for an isolated restore check."""


def _aws_json(arguments: list[str], *, runner=subprocess.run) -> dict:
    result = runner(
        ["aws", *arguments, "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PreflightError("AWS_READ_ONLY_QUERY_FAILED")
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PreflightError("AWS_READ_ONLY_RESPONSE_INVALID") from exc


def _instances(response: dict) -> list[dict]:
    return [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]


def _tags(resource: dict) -> dict[str, str]:
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in resource.get("Tags", [])}


def validate_backup_pair(
    backup_path: Path, expected_sha256: str, *, expected_sidecar_sha256: str = "",
    expected_manifest_sha256: str = "", allow_legacy_manual: bool = False,
) -> dict:
    if not BACKUP_NAME_RE.fullmatch(backup_path.name) or backup_path.is_symlink() or not backup_path.is_file():
        raise PreflightError("BACKUP_ARTIFACT_INVALID")
    if not SHA256_RE.fullmatch(expected_sha256):
        raise PreflightError("EXPECTED_CHECKSUM_INVALID")
    status_path = backup_path.with_name(backup_path.name.removesuffix(".sql.gz.enc") + ".master_status")
    manifest_path = backup_path.with_name(backup_path.name.removesuffix(".sql.gz.enc") + ".manifest.json")
    if status_path.is_symlink() or not status_path.is_file():
        raise PreflightError("MASTER_STATUS_MISSING")
    try:
        with backup_path.open("rb") as stream:
            if stream.read(8) != b"Salted__":
                raise PreflightError("ENCRYPTED_CONTAINER_INVALID")
        binlog_file, binlog_position = parse_master_status(status_path)
    except (OSError, RestoreError) as exc:
        code = exc.code if isinstance(exc, RestoreError) else "BACKUP_PAIR_UNREADABLE"
        raise PreflightError(code) from exc
    if manifest_path.is_symlink():
        raise PreflightError("BACKUP_MANIFEST_INVALID")
    if manifest_path.is_file():
        try:
            manifest_result = verify_manifest_files(
                backup_path, status_path, manifest_path,
                expected_sha256=expected_sha256,
                expected_sidecar_sha256=expected_sidecar_sha256,
                expected_manifest_sha256=expected_manifest_sha256,
            )
        except ManifestError as exc:
            raise PreflightError(exc.code) from exc
        manifest_status = "PASS"
        manifest_sha256 = manifest_result["manifest_sha256"]
        manifest_object_key = manifest_result["manifest_object_key"]
        data_reference_at = manifest_result.get("data_reference_at")
        data_reference_time_status = manifest_result.get("data_reference_time_status", "UNVERIFIED")
        dump_object_key = manifest_result["dump_object_key"]
        sidecar_object_key = manifest_result["sidecar_object_key"]
    else:
        if not allow_legacy_manual or manifest_path.exists() or expected_manifest_sha256:
            raise PreflightError("BACKUP_MANIFEST_LEGACY_UNVERIFIED")
        if expected_sidecar_sha256 and (
            not SHA256_RE.fullmatch(expected_sidecar_sha256)
            or hashlib.sha256(status_path.read_bytes()).hexdigest() != expected_sidecar_sha256.lower()
        ):
            raise PreflightError("MASTER_STATUS_CHECKSUM_MISMATCH")
        actual_sha256, _ = sha256_file(backup_path)
        if actual_sha256 != expected_sha256.lower():
            raise PreflightError("BACKUP_CHECKSUM_MISMATCH")
        manifest_result = None
        manifest_status = "ABSENT"
        manifest_sha256 = None
        manifest_object_key = None
        data_reference_at = None
        data_reference_time_status = "NOT_MEASURED"
        dump_object_key = None
        sidecar_object_key = None
    sidecar_sha256 = hashlib.sha256(status_path.read_bytes()).hexdigest()
    return {
        "backup_path": str(backup_path.resolve()),
        "status_path": str(status_path.resolve()),
        "manifest_path": str(manifest_path.resolve()) if manifest_path.is_file() else None,
        "dump_object_key": dump_object_key,
        "sidecar_object_key": sidecar_object_key,
        "manifest_object_key": manifest_object_key,
        "sha256": expected_sha256.lower(),
        "sidecar_sha256": sidecar_sha256,
        "manifest_sha256": manifest_sha256,
        "manifest_status": manifest_status,
        "restore_mode": "LEGACY_MANUAL" if manifest_status == "ABSENT" else "MANIFEST_VERIFIED",
        "master_status_file": binlog_file,
        "master_status_position": binlog_position,
        "data_reference_at": data_reference_at,
        "data_reference_time_status": data_reference_time_status,
        "expected_rpo": {"status": "NOT_MEASURED", "seconds": None}
        if manifest_status == "ABSENT" else None,
    }


def _one_instance(response: dict) -> dict:
    instances = _instances(response)
    if len(instances) != 1:
        raise PreflightError("AWS_INSTANCE_IDENTITY_NOT_UNIQUE")
    return instances[0]


def _sg_ingress_is_ssh_only_from(group: dict, expected_source_groups: set[str]) -> bool:
    permissions = group.get("IpPermissions", [])
    if len(permissions) != 1:
        return False
    rule = permissions[0]
    source_groups = sorted(
        str(source.get("GroupId", "")) for source in rule.get("UserIdGroupPairs", [])
    )
    return (
        rule.get("IpProtocol") == "tcp"
        and rule.get("FromPort") == 22
        and rule.get("ToPort") == 22
        and len(source_groups) == 1
        and source_groups[0] in expected_source_groups
        and not rule.get("IpRanges")
        and not rule.get("Ipv6Ranges")
        and not rule.get("PrefixListIds")
    )


def _sg_egress_is_restricted(group: dict) -> bool:
    permissions = group.get("IpPermissionsEgress", [])
    normalized = set()
    for rule in permissions:
        if (
            rule.get("IpProtocol") != "tcp"
            or rule.get("FromPort") != rule.get("ToPort")
            or rule.get("IpRanges") != [{"CidrIp": "IP_REDACTED/0"}]
            or rule.get("Ipv6Ranges")
            or rule.get("UserIdGroupPairs")
            or rule.get("PrefixListIds")
        ):
            return False
        normalized.add(rule.get("FromPort"))
    return normalized == {80, 443} and len(permissions) == 2


def _sg_port_is_only_from_groups(group: dict, direction: str, port: int, expected_groups: set[str]) -> bool:
    key = "IpPermissions" if direction == "ingress" else "IpPermissionsEgress"
    permissions = group.get(key, [])
    if len(permissions) != 1:
        return False
    rule = permissions[0]
    source_groups = {
        str(source.get("GroupId", "")) for source in rule.get("UserIdGroupPairs", [])
    }
    return (
        rule.get("IpProtocol") == "tcp"
        and rule.get("FromPort") == port
        and rule.get("ToPort") == port
        and source_groups == expected_groups
        and len(rule.get("UserIdGroupPairs", [])) == len(expected_groups)
        and not rule.get("IpRanges")
        and not rule.get("Ipv6Ranges")
        and not rule.get("PrefixListIds")
    )


def validate_aws_isolated_target(
    *,
    region: str,
    instance_id: str,
    private_ip: str,
    data_volume_id: str,
    stage_volume_id: str,
    service_security_group_id: str | None = None,
    require_service_sg_attached: bool = False,
    runner=subprocess.run,
) -> dict:
    if instance_id == PRODUCTION_DB_INSTANCE_ID or private_ip in PROTECTED_PRIVATE_IPS:
        raise PreflightError("PROTECTED_DATABASE_TARGET_FORBIDDEN")
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
        raise PreflightError("ISOLATED_INSTANCE_ID_INVALID")
    if not re.fullmatch(r"10\.20\.30\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])", private_ip):
        raise PreflightError("ISOLATED_PRIVATE_IP_INVALID")
    if private_ip == "IP_REDACTED" or data_volume_id == stage_volume_id:
        raise PreflightError("ISOLATED_RESOURCE_COLLISION")
    if not all(re.fullmatch(r"vol-[0-9a-f]{8,32}", value) for value in (data_volume_id, stage_volume_id)):
        raise PreflightError("ISOLATED_VOLUME_ID_INVALID")

    instance = _one_instance(
        _aws_json(["ec2", "describe-instances", "--region", region, "--instance-ids", instance_id], runner=runner)
    )
    tags = _tags(instance)
    if (
        tags.get("Name") != ISOLATED_NAME
        or tags.get("Role") != ISOLATED_ROLE
        or instance.get("InstanceId") != instance_id
        or instance.get("PrivateIpAddress") != private_ip
        or instance.get("State", {}).get("Name") != "running"
        or instance.get("PublicIpAddress")
    ):
        raise PreflightError("ISOLATED_INSTANCE_IDENTITY_MISMATCH")
    metadata_options = instance.get("MetadataOptions", {})
    if (
        metadata_options.get("HttpTokens") != "required"
        or metadata_options.get("HttpPutResponseHopLimit") != 1
        or metadata_options.get("InstanceMetadataTags") != "enabled"
    ):
        raise PreflightError("ISOLATED_INSTANCE_METADATA_POLICY_UNSAFE")
    if instance.get("IamInstanceProfile"):
        raise PreflightError("ISOLATED_INSTANCE_IAM_PROFILE_UNEXPECTED")
    instance_sgs = instance.get("SecurityGroups", [])
    attached_sg_ids = {str(group.get("GroupId", "")) for group in instance_sgs}
    if not attached_sg_ids or "" in attached_sg_ids:
        raise PreflightError("ISOLATED_SECURITY_GROUP_SET_INVALID")
    if service_security_group_id and not re.fullmatch(r"sg-[0-9a-f]{8,32}", service_security_group_id):
        raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_ID_INVALID")

    web_instances = _instances(
        _aws_json(
            [
                "ec2", "describe-instances", "--region", region,
                "--filters", f"Name=tag:Name,Values={WEB_NAME}",
            ],
            runner=runner,
        )
    )
    if len(web_instances) != 1:
        raise PreflightError("WEB_BASTION_SECURITY_GROUP_NOT_UNIQUE")
    web_vpc = web_instances[0].get("VpcId")
    web_sgs = {str(group.get("GroupId", "")) for group in web_instances[0].get("SecurityGroups", [])}
    if not web_sgs or instance.get("VpcId") != web_vpc:
        raise PreflightError("ISOLATED_HOST_VPC_MISMATCH")

    app_source_sgs = set(web_sgs)
    doc_sgs: set[str] = set()
    if service_security_group_id:
        doc_instances = _instances(
            _aws_json(
                [
                    "ec2", "describe-instances", "--region", region,
                    "--filters", f"Name=tag:Name,Values={DOC_NAME}",
                ],
                runner=runner,
            )
        )
        if len(doc_instances) != 1:
            raise PreflightError("DOC_SERVICE_SECURITY_GROUP_NOT_UNIQUE")
        doc = doc_instances[0]
        doc_sgs = {str(group.get("GroupId", "")) for group in doc.get("SecurityGroups", [])}
        if (
            doc.get("PrivateIpAddress") != DOC_PRIVATE_IP
            or doc.get("VpcId") != web_vpc
            or not doc_sgs
            or doc.get("State", {}).get("Name") not in {"running", "stopped"}
            or web_instances[0].get("PrivateIpAddress") != WEB_PRIVATE_IP
            or web_instances[0].get("State", {}).get("Name") not in {"running", "stopped"}
        ):
            raise PreflightError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")
        app_source_sgs.update(doc_sgs)

    subnet_id = str(instance.get("SubnetId", ""))
    subnet_response = _aws_json(
        ["ec2", "describe-subnets", "--region", region, "--subnet-ids", subnet_id],
        runner=runner,
    ).get("Subnets", [])
    if len(subnet_response) != 1:
        raise PreflightError("ISOLATED_SUBNET_UNAVAILABLE")
    subnet = subnet_response[0]
    try:
        ip_is_in_subnet = ipaddress.ip_address(private_ip) in ipaddress.ip_network(subnet["CidrBlock"])
    except (KeyError, ValueError) as exc:
        raise PreflightError("ISOLATED_SUBNET_CIDR_INVALID") from exc
    if (
        subnet.get("SubnetId") != subnet_id
        or _tags(subnet).get("Name") != "Hospital-DR-Private-DB-Subnet"
        or subnet.get("VpcId") != instance.get("VpcId")
        or subnet.get("MapPublicIpOnLaunch", False)
        or not ip_is_in_subnet
    ):
        raise PreflightError("ISOLATED_SUBNET_IDENTITY_MISMATCH")

    group_ids_to_describe = set(attached_sg_ids)
    if service_security_group_id:
        group_ids_to_describe.add(service_security_group_id)
    if service_security_group_id:
        group_ids_to_describe.update(app_source_sgs)
    security_groups = _aws_json(
        ["ec2", "describe-security-groups", "--region", region, "--group-ids", *sorted(group_ids_to_describe)],
        runner=runner,
    ).get("SecurityGroups", [])
    by_group_id = {str(group.get("GroupId", "")): group for group in security_groups}
    if set(by_group_id) != group_ids_to_describe:
        raise PreflightError("ISOLATED_SECURITY_GROUP_UNAVAILABLE")
    isolated_candidates = [group for group in security_groups if group.get("GroupName") == ISOLATED_SG_NAME]
    if len(isolated_candidates) != 1:
        raise PreflightError("ISOLATED_SECURITY_GROUP_IDENTITY_MISMATCH")
    isolated_sg = isolated_candidates[0]
    isolated_sg_id = str(isolated_sg.get("GroupId", ""))
    if isolated_sg_id not in attached_sg_ids or isolated_sg.get("VpcId") != instance.get("VpcId"):
        raise PreflightError("ISOLATED_SECURITY_GROUP_IDENTITY_MISMATCH")
    if not _sg_ingress_is_ssh_only_from(isolated_sg, web_sgs):
        raise PreflightError("ISOLATED_SECURITY_GROUP_INGRESS_UNSAFE")
    if not _sg_egress_is_restricted(isolated_sg):
        raise PreflightError("ISOLATED_SECURITY_GROUP_EGRESS_UNSAFE")

    service_sg_attached = False
    if service_security_group_id:
        service_group = by_group_id.get(service_security_group_id)
        if (
            not service_group
            or service_group.get("GroupName") != ISOLATED_SERVICE_SG_NAME
            or service_group.get("VpcId") != instance.get("VpcId")
        ):
            raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_IDENTITY_MISMATCH")
        allowed_instance_sgs = {isolated_sg_id, service_security_group_id}
        if attached_sg_ids not in ({isolated_sg_id}, allowed_instance_sgs):
            raise PreflightError("ISOLATED_SECURITY_GROUP_SET_INVALID")
        service_sg_attached = service_security_group_id in attached_sg_ids
        if require_service_sg_attached and not service_sg_attached:
            raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_NOT_ATTACHED")
        for source_group_id in app_source_sgs:
            source_group = by_group_id.get(source_group_id)
            expected_name = "hospital-dr-web-sg" if source_group_id in web_sgs else "hospital-dr-doc-sg"
            if not source_group or source_group.get("GroupName") != expected_name:
                raise PreflightError("DR_APP_SECURITY_GROUP_IDENTITY_INVALID")
        if not _sg_port_is_only_from_groups(
            service_group, "ingress", ISOLATED_SERVICE_PORT, app_source_sgs
        ):
            raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_INGRESS_UNSAFE")
        if not _sg_port_is_only_from_groups(
            service_group, "egress", ISOLATED_SERVICE_PORT, app_source_sgs
        ):
            raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_EGRESS_UNSAFE")
        interfaces = _aws_json(
            [
                "ec2", "describe-network-interfaces", "--region", region,
                "--filters", f"Name=group-id,Values={service_security_group_id}",
            ],
            runner=runner,
        ).get("NetworkInterfaces", [])
        if service_sg_attached:
            if (
                len(interfaces) != 1
                or interfaces[0].get("Attachment", {}).get("InstanceId") != instance_id
                or interfaces[0].get("PrivateIpAddress") != private_ip
            ):
                raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_ATTACHMENT_UNSAFE")
        elif interfaces:
            raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_ALREADY_IN_USE")
    elif len(attached_sg_ids) != 1:
        raise PreflightError("ISOLATED_SECURITY_GROUP_SET_INVALID")

    root_id = None
    for mapping in instance.get("BlockDeviceMappings", []):
        if mapping.get("DeviceName") == instance.get("RootDeviceName"):
            root_id = mapping.get("Ebs", {}).get("VolumeId")
    all_volume_ids = [root_id, data_volume_id, stage_volume_id]
    if not root_id or len(set(all_volume_ids)) != 3:
        raise PreflightError("ISOLATED_EBS_DEVICE_SET_INVALID")
    volumes = _aws_json(
        ["ec2", "describe-volumes", "--region", region, "--volume-ids", *all_volume_ids],
        runner=runner,
    ).get("Volumes", [])
    by_id = {str(volume.get("VolumeId")): volume for volume in volumes}
    if set(by_id) != set(all_volume_ids):
        raise PreflightError("ISOLATED_EBS_VOLUME_SET_MISMATCH")
    if any(not volume.get("Encrypted") for volume in volumes):
        raise PreflightError("ISOLATED_EBS_ENCRYPTION_REQUIRED")
    root_volume = by_id[root_id]
    root_attachments = root_volume.get("Attachments", [])
    if (
        root_volume.get("State") != "in-use"
        or len(root_attachments) != 1
        or root_attachments[0].get("InstanceId") != instance_id
        or root_attachments[0].get("Device") != instance.get("RootDeviceName")
    ):
        raise PreflightError("ISOLATED_ROOT_EBS_ATTACHMENT_MISMATCH")
    for volume_id, expected_device, expected_name, expected_role in (
        (data_volume_id, "/dev/sdf", "Hospital-DR-Dump-Restore-Isolated-Data", "isolated-dump-restore-data"),
        (stage_volume_id, "/dev/sdg", "Hospital-DR-Dump-Restore-Isolated-Stage", "isolated-dump-restore-staging"),
    ):
        volume = by_id[volume_id]
        tags = _tags(volume)
        attachments = volume.get("Attachments", [])
        if (
            volume.get("State") != "in-use"
            or len(attachments) != 1
            or attachments[0].get("InstanceId") != instance_id
            or attachments[0].get("Device") != expected_device
            or volume.get("AvailabilityZone") != instance.get("Placement", {}).get("AvailabilityZone")
            or tags.get("Role") != expected_role
            or tags.get("Name") != expected_name
        ):
            raise PreflightError("ISOLATED_EBS_ATTACHMENT_MISMATCH")
    return {
        "instance_id": instance_id,
        "private_ip": private_ip,
        "data_volume_id": data_volume_id,
        "stage_volume_id": stage_volume_id,
        "instance_state": "running",
        "security_group_id": isolated_sg_id,
        "service_security_group_id": service_security_group_id or "",
        "service_security_group_attached": service_sg_attached,
        "vpc_id": str(instance.get("VpcId", "")),
        "subnet_id": subnet_id,
    }


def _run_ansible_isolated_service(args, *, prepare: bool, password: str | None = None) -> int:
    if not args.ssh_key or not Path(args.ssh_key).is_file() or not os.access(args.ssh_key, os.R_OK):
        raise PreflightError("SSH_KEY_UNAVAILABLE")
    for selected in (args.ssh_config, args.known_hosts):
        if not selected or not Path(selected).is_file() or not os.access(selected, os.R_OK):
            raise PreflightError("SSH_TRANSPORT_CONFIG_UNAVAILABLE")
    playbook = REPO_ROOT / "automation/ansible/isolated_db_service_prepare.yml"
    if not playbook.is_file():
        raise PreflightError("ISOLATED_DB_SERVICE_PLAYBOOK_MISSING")
    temporary_parent = None
    if prepare:
        if password is None:
            raise PreflightError("SERVICE_DB_PASSWORD_UNAVAILABLE")
        tmpfs = Path("/dev/shm")
        if not tmpfs.is_dir():
            raise PreflightError("SECRET_TMPFS_UNAVAILABLE")
        try:
            mount_check = subprocess.run(
                ["findmnt", "-n", "-o", "FSTYPE", "--target", str(tmpfs)],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise PreflightError("SECRET_TMPFS_UNAVAILABLE") from exc
        if mount_check.returncode != 0 or mount_check.stdout.strip() != "tmpfs":
            raise PreflightError("SECRET_TMPFS_UNAVAILABLE")
        temporary_parent = str(tmpfs)
    with tempfile.TemporaryDirectory(
        prefix="hospital-dr-isolated-service-", dir=temporary_parent
    ) as temporary:
        temp_root = Path(temporary)
        temp_root.chmod(0o700)
        ssh_config_path = temp_root / "ssh_config"
        inventory_path = temp_root / "inventory.ini"
        vars_path = temp_root / "vars.json"
        proxy = shlex.join(["ssh", "-F", args.ssh_config, "-W", "%h:%p", "dr-web"])
        _write_private(
            ssh_config_path,
            "\n".join((
                "Host isolated-dump-restore",
                f"  HostName {args.private_ip}",
                f"  HostKeyAlias {args.private_ip}",
                "  User ubuntu",
                f"  IdentityFile {args.ssh_key}",
                "  IdentitiesOnly yes",
                "  BatchMode yes",
                "  ConnectTimeout 15",
                "  StrictHostKeyChecking accept-new",
                f"  UserKnownHostsFile {args.known_hosts}",
                "  GlobalKnownHostsFile /dev/null",
                f"  ProxyCommand {proxy}",
                "",
            )),
        )
        _write_private(
            inventory_path,
            "[isolated_dump_restore]\n"
            "isolated-dump-restore ansible_connection=ssh ansible_host=isolated-dump-restore "
            f"ansible_ssh_common_args={shlex.quote('-F ' + str(ssh_config_path))}\n",
        )
        vars_data = {
            "dump_db_service_request_id": args.request_id,
            "dump_restore_expected_instance_id": args.instance_id,
            "dump_restore_expected_private_ip": args.private_ip,
            "dump_restore_expected_data_volume_id": args.data_volume_id,
            "dump_restore_expected_stage_volume_id": args.stage_volume_id,
            "dump_restore_expected_sha256": args.expected_sha256.lower(),
            "dump_db_service_port": ISOLATED_SERVICE_PORT,
            "dump_db_service_prepare": bool(prepare),
            "dump_db_service_prepare_confirm": bool(prepare),
        }
        if prepare:
            vars_data["dump_db_service_password"] = password
        _write_private(vars_path, json.dumps(vars_data, sort_keys=True))
        try:
            result = subprocess.run(
                ["ansible-playbook", "-i", str(inventory_path), "-e", f"@{vars_path}", str(playbook)],
                check=False,
            )
        except OSError as exc:
            raise PreflightError("ISOLATED_DB_SERVICE_ANSIBLE_UNAVAILABLE") from exc
        return result.returncode


def _set_isolated_instance_groups(
    *, region: str, instance_id: str, group_ids: list[str], runner=subprocess.run
) -> None:
    result = runner(
        [
            "aws", "ec2", "modify-instance-attribute", "--region", region,
            "--instance-id", instance_id, "--groups", *group_ids,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_ATTACH_FAILED")


def _service_password(path: Path) -> str:
    from operations.db.isolated_db_service_host import read_service_password

    try:
        return read_service_password(path, owner_uid=os.geteuid())
    except (OSError, ValueError, RestoreError) as exc:
        code = getattr(exc, "code", "SERVICE_DB_PASSWORD_FILE_INVALID")
        raise PreflightError(code) from exc


def _write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def run_ansible_restore(args, backup: dict) -> int:
    if not args.ssh_key or not Path(args.ssh_key).is_file() or not os.access(args.ssh_key, os.R_OK):
        raise PreflightError("SSH_KEY_UNAVAILABLE")
    for selected in (args.ssh_config, args.known_hosts):
        if not selected or not Path(selected).is_file() or not os.access(selected, os.R_OK):
            raise PreflightError("SSH_TRANSPORT_CONFIG_UNAVAILABLE")
    if not args.key_file or not Path(args.key_file).is_file():
        raise PreflightError("ENCRYPTION_KEY_FILE_UNAVAILABLE")
    key_stat = Path(args.key_file).stat()
    if key_stat.st_uid != os.geteuid() or key_stat.st_mode & 0o077 or key_stat.st_size == 0:
        raise PreflightError("ENCRYPTION_KEY_FILE_PERMISSIONS_INVALID")

    playbook = REPO_ROOT / "automation/ansible/dump_restore_isolated.yml"
    if not playbook.is_file():
        raise PreflightError("ISOLATED_RESTORE_PLAYBOOK_MISSING")
    with tempfile.TemporaryDirectory(prefix="hospital-dr-isolated-restore-") as temporary:
        temp_root = Path(temporary)
        temp_root.chmod(0o700)
        ssh_config_path = temp_root / "ssh_config"
        inventory_path = temp_root / "inventory.ini"
        vars_path = temp_root / "vars.json"
        proxy = shlex.join(["ssh", "-F", args.ssh_config, "-W", "%h:%p", "dr-web"])
        ssh_config = "\n".join(
            (
                "Host isolated-dump-restore",
                f"  HostName {args.private_ip}",
                f"  HostKeyAlias {args.private_ip}",
                "  User ubuntu",
                f"  IdentityFile {args.ssh_key}",
                "  IdentitiesOnly yes",
                "  BatchMode yes",
                "  ConnectTimeout 15",
                "  StrictHostKeyChecking accept-new",
                f"  UserKnownHostsFile {args.known_hosts}",
                "  GlobalKnownHostsFile /dev/null",
                f"  ProxyCommand {proxy}",
                "",
            )
        )
        _write_private(ssh_config_path, ssh_config)
        _write_private(
            inventory_path,
            "[isolated_dump_restore]\n"
            "isolated-dump-restore ansible_connection=ssh ansible_host=isolated-dump-restore "
            f"ansible_ssh_common_args={shlex.quote('-F ' + str(ssh_config_path))}\n",
        )
        vars_data = {
            "dump_restore_confirm": True,
            "dump_restore_expected_instance_id": args.instance_id,
            "dump_restore_expected_private_ip": args.private_ip,
            "dump_restore_expected_data_volume_id": args.data_volume_id,
            "dump_restore_expected_stage_volume_id": args.stage_volume_id,
            "dump_restore_backup_controller_path": backup["backup_path"],
            "dump_restore_master_status_controller_path": backup["status_path"],
            "dump_restore_expected_sha256": backup["sha256"],
            "dump_restore_request_id": args.request_id,
            "dump_restore_key_controller_path": str(Path(args.key_file).resolve()),
        }
        _write_private(vars_path, json.dumps(vars_data, sort_keys=True))
        command = [
            "ansible-playbook",
            "-i", str(inventory_path),
            "-e", f"@{vars_path}",
            str(playbook),
        ]
        result = subprocess.run(command, check=False)
        return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "restore", "service-preflight", "prepare-service"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--data-volume-id", required=True)
    parser.add_argument("--stage-volume-id", required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--request-id", default="")
    parser.add_argument("--key-file")
    parser.add_argument("--ssh-key", default=os.environ.get("SSH_KEY"))
    parser.add_argument("--ssh-config", default=os.environ.get("DR_SSH_CONFIG_FILE"))
    parser.add_argument("--known-hosts", default=os.environ.get("DR_SSH_KNOWN_HOSTS_FILE"))
    parser.add_argument("--confirm-isolated-restore", action="store_true")
    parser.add_argument("--service-security-group-id")
    parser.add_argument("--service-password-file", type=Path)
    parser.add_argument("--confirm-isolated-service-prepare", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.region != "ap-northeast-2":
            raise PreflightError("AWS_REGION_NOT_APPROVED")
        if args.mode in {"service-preflight", "prepare-service"}:
            if os.environ.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
                raise PreflightError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
            if os.environ.get("DUMP_RESTORE_EXECUTOR", "").strip():
                raise PreflightError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_UNSET")
            if args.mode == "prepare-service":
                if os.environ.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
                    raise PreflightError("APPROVED_SECRET_WRAPPER_REQUIRED")
                if not args.confirm_isolated_service_prepare:
                    raise PreflightError("EXPLICIT_ISOLATED_SERVICE_PREPARE_CONFIRMATION_REQUIRED")
                if not args.service_password_file:
                    raise PreflightError("SERVICE_DB_PASSWORD_FILE_UNAVAILABLE")
        if args.mode == "restore":
            if os.environ.get("ISOLATED_DUMP_RESTORE_WRAPPER") != "1":
                raise PreflightError("APPROVED_SECRET_WRAPPER_REQUIRED")
            if os.environ.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false":
                raise PreflightError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_DISABLED")
            if os.environ.get("DUMP_RESTORE_EXECUTOR", "").strip():
                raise PreflightError("CHATOPS_DUMP_EXECUTOR_MUST_REMAIN_UNSET")
            if not args.confirm_isolated_restore:
                raise PreflightError("EXPLICIT_ISOLATED_RESTORE_CONFIRMATION_REQUIRED")
            if args.request_id:
                try:
                    if str(uuid.UUID(args.request_id)) != args.request_id.lower():
                        raise ValueError("non-canonical request id")
                except (ValueError, TypeError, AttributeError) as exc:
                    raise PreflightError("RESTORE_REQUEST_ID_INVALID") from exc
        backup = validate_backup_pair(args.backup, args.expected_sha256)
        if args.mode in {"preflight", "restore"}:
            validate_aws_isolated_target(
                region=args.region,
                instance_id=args.instance_id,
                private_ip=args.private_ip,
                data_volume_id=args.data_volume_id,
                stage_volume_id=args.stage_volume_id,
            )
        else:
            if not args.service_security_group_id:
                raise PreflightError("ISOLATED_SERVICE_SECURITY_GROUP_ID_REQUIRED")
            target = validate_aws_isolated_target(
                region=args.region,
                instance_id=args.instance_id,
                private_ip=args.private_ip,
                data_volume_id=args.data_volume_id,
                stage_volume_id=args.stage_volume_id,
                service_security_group_id=args.service_security_group_id,
                require_service_sg_attached=args.mode == "service-preflight",
            )
            if args.mode == "service-preflight":
                result = _run_ansible_isolated_service(args, prepare=False)
                if result != 0:
                    raise PreflightError("ISOLATED_DB_SERVICE_REMOTE_PREFLIGHT_FAILED")
                print("ISOLATED_DB_SERVICE_PREFLIGHT=PASS network_group_validated=true")
                return 0

            # Revalidate restore completion on the instance before attaching
            # the dedicated service SG. The preflight playbook is read-only.
            remote_preflight = _run_ansible_isolated_service(args, prepare=False)
            if remote_preflight != 0:
                if target["service_security_group_attached"]:
                    try:
                        _set_isolated_instance_groups(
                            region=args.region,
                            instance_id=args.instance_id,
                            group_ids=[target["security_group_id"]],
                        )
                        validate_aws_isolated_target(
                            region=args.region,
                            instance_id=args.instance_id,
                            private_ip=args.private_ip,
                            data_volume_id=args.data_volume_id,
                            stage_volume_id=args.stage_volume_id,
                        )
                    except PreflightError as rollback_error:
                        raise PreflightError("ISOLATED_SERVICE_NETWORK_ROLLBACK_FAILED") from rollback_error
                raise PreflightError("ISOLATED_DB_SERVICE_REMOTE_PREFLIGHT_FAILED")
            password = _service_password(args.service_password_file)
            base_sg_id = target["security_group_id"]
            try:
                if not target["service_security_group_attached"]:
                    _set_isolated_instance_groups(
                        region=args.region,
                        instance_id=args.instance_id,
                        group_ids=[base_sg_id, args.service_security_group_id],
                    )
                target = validate_aws_isolated_target(
                    region=args.region,
                    instance_id=args.instance_id,
                    private_ip=args.private_ip,
                    data_volume_id=args.data_volume_id,
                    stage_volume_id=args.stage_volume_id,
                    service_security_group_id=args.service_security_group_id,
                    require_service_sg_attached=True,
                )
                prepared = _run_ansible_isolated_service(args, prepare=True, password=password)
                if prepared != 0:
                    raise PreflightError("ISOLATED_DB_SERVICE_LISTENER_PREPARATION_FAILED")
                validate_aws_isolated_target(
                    region=args.region,
                    instance_id=args.instance_id,
                    private_ip=args.private_ip,
                    data_volume_id=args.data_volume_id,
                    stage_volume_id=args.stage_volume_id,
                    service_security_group_id=args.service_security_group_id,
                    require_service_sg_attached=True,
                )
            except PreflightError:
                try:
                    _set_isolated_instance_groups(
                        region=args.region,
                        instance_id=args.instance_id,
                        group_ids=[base_sg_id],
                    )
                    validate_aws_isolated_target(
                        region=args.region,
                        instance_id=args.instance_id,
                        private_ip=args.private_ip,
                        data_volume_id=args.data_volume_id,
                        stage_volume_id=args.stage_volume_id,
                    )
                except PreflightError as rollback_error:
                    raise PreflightError("ISOLATED_SERVICE_NETWORK_ROLLBACK_FAILED") from rollback_error
                raise
            finally:
                password = ""
            print("ISOLATED_DB_SERVICE_PREPARED=PASS mysql_read_only=true super_read_only=true")
            return 0
        if args.mode == "preflight":
            print("ISOLATED_DUMP_PREFLIGHT=PASS")
            return 0
        result = run_ansible_restore(args, backup)
        if result == 0:
            print("ISOLATED_DUMP_RESTORE_PLAYBOOK=COMPLETED")
        else:
            print(f"ISOLATED_DUMP_RESTORE_PLAYBOOK=FAILED exit={result}", file=sys.stderr)
        return result
    except PreflightError as exc:
        print(f"ISOLATED_DUMP_PREFLIGHT=BLOCKED reason={exc}", file=sys.stderr)
        return 1
    except OSError:
        print("ISOLATED_DUMP_PREFLIGHT=BLOCKED reason=LOCAL_TOOL_OR_FILE_UNAVAILABLE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
