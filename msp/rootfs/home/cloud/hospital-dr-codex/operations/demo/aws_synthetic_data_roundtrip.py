#!/usr/bin/env python3
"""One-shot synthetic AWS data handoff rehearsal (local MySQL -> AWS SQLite -> MySQL).

This is deliberately separate from production Failover/Failback executors. The
AWS side uses Python's built-in SQLite because the isolated Canary AMI has no
MySQL server and its egress policy does not permit package-repository access.
Only fixed synthetic A/B rows are transferred through SSM Run Command.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ACCOUNT_ID = "AWS_ACCOUNT_ID_REDACTED"
REGION = "ap-northeast-2"
INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
VPC_ID = "AWS_RESOURCE_ID_REDACTED"
CANARY_RUN_ID = "snc-20261017-a1"
PRODUCTION_INSTANCE_IDS = {"AWS_RESOURCE_ID_REDACTED"}
DEMO_ROWS = [(1, "A", "Synthetic source record A"), (2, "B", "Synthetic DR record B")]


class DemoError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _run(args: list[str], *, timeout: int = 30, stdin: str | None = None) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            args,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DemoError("COMMAND_TIMEOUT") from exc
    if result.returncode:
        raise DemoError("COMMAND_FAILED")
    return result


def _aws_json(*args: str, timeout: int = 30) -> dict:
    result = _run(["aws", *args, "--region", REGION, "--output", "json"], timeout=timeout)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DemoError("AWS_RESPONSE_INVALID") from exc


def _instance() -> dict:
    if INSTANCE_ID in PRODUCTION_INSTANCE_IDS:
        raise DemoError("PRODUCTION_TARGET_FORBIDDEN")
    response = _aws_json("ec2", "describe-instances", "--instance-ids", INSTANCE_ID)
    try:
        instance = response["Reservations"][0]["Instances"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise DemoError("SYNTHETIC_INSTANCE_NOT_FOUND") from exc
    tags = {item.get("Key"): item.get("Value") for item in instance.get("Tags", [])}
    if (
        instance.get("InstanceId") != INSTANCE_ID
        or instance.get("VpcId") != VPC_ID
        or tags.get("CanaryRunId") != CANARY_RUN_ID
        or tags.get("Environment") != "synthetic"
        or tags.get("DataClass") != "synthetic-only"
        or not tags.get("Name", "").endswith("-emr")
    ):
        raise DemoError("SYNTHETIC_INSTANCE_IDENTITY_MISMATCH")
    return instance


def _ssm(code: str) -> str:
    encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
    command = f"printf '%s' '{encoded}' | base64 -d | python3"
    params = json.dumps({"commands": [command]}, separators=(",", ":"))
    sent = _run(
        [
            "aws", "ssm", "send-command", "--region", REGION,
            "--instance-ids", INSTANCE_ID, "--document-name", "AWS-RunShellScript",
            "--timeout-seconds", "30", "--parameters", params,
            "--query", "Command.CommandId", "--output", "text",
        ],
        timeout=30,
    )
    command_id = sent.stdout.strip()
    if not command_id:
        raise DemoError("SSM_COMMAND_ID_MISSING")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        invocation = _aws_json(
            "ssm", "get-command-invocation", "--command-id", command_id,
            "--instance-id", INSTANCE_ID,
            timeout=20,
        )
        status = invocation.get("Status")
        if status in {"Success", "Failed", "Cancelled", "TimedOut"}:
            if status != "Success" or invocation.get("ResponseCode") != 0:
                raise DemoError("SSM_REMOTE_STEP_FAILED")
            return invocation.get("StandardOutputContent", "").strip()
        time.sleep(2)
    raise DemoError("SSM_REMOTE_STEP_TIMEOUT")


def _wait_state(expected: str, timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = _instance().get("State", {}).get("Name")
        if state == expected:
            return
        time.sleep(3)
    raise DemoError(f"EC2_STATE_{expected.upper()}_TIMEOUT")


def _wait_ssm(timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = _aws_json(
            "ssm", "describe-instance-information", "--filters",
            f"Key=InstanceIds,Values={INSTANCE_ID}",
        )
        items = response.get("InstanceInformationList", [])
        if items and items[0].get("PingStatus") == "Online":
            return
        time.sleep(3)
    raise DemoError("SSM_ONLINE_TIMEOUT")


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _portable_dump(rows: list[tuple[int, str, str]], *, create_table: bool) -> str:
    parts = []
    if create_table:
        parts.append(
            "CREATE TABLE demo_records (record_id INTEGER PRIMARY KEY, "
            "code VARCHAR(16) NOT NULL UNIQUE, payload VARCHAR(255) NOT NULL);"
        )
    for record_id, code, payload in rows:
        parts.append(
            "REPLACE INTO demo_records(record_id,code,payload) VALUES "
            f"({int(record_id)},{_sql_literal(code)},{_sql_literal(payload)});"
        )
    return "\n".join(parts) + "\n"


def _local_mysql() -> tuple[Path, dict[str, str], subprocess.Popen, object]:
    mysqld, mysql, mysqladmin = (shutil.which(name) for name in ("mysqld", "mysql", "mysqladmin"))
    if not all((mysqld, mysql, mysqladmin)) or os.geteuid() == 0:
        raise DemoError("LOCAL_MYSQL_TEST_TOOLS_UNAVAILABLE")
    root = Path(tempfile.mkdtemp(prefix="hospital-dr-aws-demo-")).resolve()
    root.chmod(0o700)
    datadir = root / "source"
    datadir.mkdir(mode=0o700)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(root), "LANG": "C.UTF-8"}
    basedir = str(Path(mysqld).resolve().parent.parent)
    try:
        _run(
            [mysqld, "--no-defaults", "--initialize-insecure", f"--basedir={basedir}", f"--datadir={datadir}"],
            timeout=120,
        )
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    with socket.socket() as listener:
        listener.bind(("IP_REDACTED", 0))
        port = listener.getsockname()[1]
    log = (root / "mysqld.log").open("ab")
    process = subprocess.Popen(
        [
            mysqld, "--no-defaults", f"--basedir={basedir}", f"--datadir={datadir}",
            f"--socket={datadir / 'mysql.sock'}", f"--pid-file={datadir / 'mysql.pid'}",
            f"--log-error={datadir / 'error.log'}", "--bind-address=IP_REDACTED",
            f"--port={port}", "--mysqlx=0", "--skip-networking",
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log.close()
            shutil.rmtree(root, ignore_errors=True)
            raise DemoError("LOCAL_MYSQL_EXITED_DURING_START")
        try:
            ping = subprocess.run(
                [mysqladmin, "--no-defaults", "--protocol=socket", f"--socket={datadir / 'mysql.sock'}", "--user=root", "ping"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired:
            time.sleep(1)
            continue
        if ping.returncode == 0:
            return root, {"MYSQL": mysql, "MYSQLADMIN": mysqladmin, "DATADIR": str(datadir), "PORT": str(port), "BASEDIR": basedir}, process, log
        time.sleep(1)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    log.close()
    shutil.rmtree(root, ignore_errors=True)
    raise DemoError("LOCAL_MYSQL_START_TIMEOUT")


def _mysql_call(mysql: str, datadir: str, args: list[str], *, stdin: str | None = None) -> str:
    result = _run(
        [mysql, "--no-defaults", "--protocol=socket", f"--socket={datadir}/mysql.sock", "--user=root", *args],
        timeout=60,
        stdin=stdin,
    )
    return result.stdout.strip()


def run_demo() -> dict:
    account = _run(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], timeout=20).stdout.strip()
    if account != ACCOUNT_ID:
        raise DemoError("AWS_ACCOUNT_MISMATCH")
    instance = _instance()
    original_state = instance.get("State", {}).get("Name")
    if original_state not in {"stopped", "running"}:
        raise DemoError("SYNTHETIC_INSTANCE_BUSY")
    root = None
    mysql_info = None
    source_process = None
    log = None
    remote_db = f"/var/tmp/hospital-dr-demo-{CANARY_RUN_ID}-{secrets.token_hex(4)}.sqlite3"
    remote_may_exist = False
    succeeded = False
    try:
        if original_state == "stopped":
            _run(["aws", "ec2", "start-instances", "--region", REGION, "--instance-ids", INSTANCE_ID], timeout=30)
            _wait_state("running")
        _wait_ssm()
        root, mysql_info, source_process, log = _local_mysql()
        mysql = mysql_info["MYSQL"]
        datadir = mysql_info["DATADIR"]
        _mysql_call(
            mysql,
            datadir,
            [],
            stdin=(
                "CREATE DATABASE hospital_demo; "
                "CREATE TABLE hospital_demo.demo_records "
                "(record_id INTEGER PRIMARY KEY, code VARCHAR(16) NOT NULL UNIQUE, payload VARCHAR(255) NOT NULL); "
                "INSERT INTO hospital_demo.demo_records VALUES (1,'A','Synthetic source record A');"
            ),
        )
        source_rows = _mysql_call(
            mysql,
            datadir,
            ["--database=hospital_demo", "--batch", "--skip-column-names", "-e", "SELECT record_id,code,payload FROM demo_records ORDER BY record_id"],
        ).splitlines()
        if source_rows != ["1\tA\tSynthetic source record A"]:
            raise DemoError("SOURCE_A_VERIFY_FAILED")
        failover_dump = _portable_dump([DEMO_ROWS[0]], create_table=True)
        failover_hash = hashlib.sha256(failover_dump.encode()).hexdigest()
        remote_restore = (
            "import base64,hashlib,json,os,sqlite3\n"
            f"p={remote_db!r}\n"
            f"sql=base64.b64decode({base64.b64encode(failover_dump.encode()).decode()!r}).decode()\n"
            "os.umask(0o077)\n"
            "if os.path.lexists(p): raise SystemExit('DEMO_DB_ALREADY_EXISTS')\n"
            "fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)\n"
            "c=sqlite3.connect(p); c.executescript(sql); rows=c.execute('SELECT code,payload FROM demo_records ORDER BY record_id').fetchall(); c.close(); os.chmod(p,0o600)\n"
            "assert rows == [('A','Synthetic source record A')]\n"
            "print(json.dumps({'phase':'FAILOVER_RESTORE','codes':[r[0] for r in rows],'dump_sha256':hashlib.sha256(sql.encode()).hexdigest(),'mode':oct(os.stat(p).st_mode & 0o777)}))\n"
        )
        remote_may_exist = True
        restored = json.loads(_ssm(remote_restore))
        if restored.get("phase") != "FAILOVER_RESTORE" or restored.get("codes") != ["A"] or restored.get("dump_sha256") != failover_hash or restored.get("mode") != "0o600":
            raise DemoError("AWS_A_RESTORE_VERIFY_FAILED")
        remote_add_b = (
            "import json,sqlite3\n"
            f"c=sqlite3.connect({remote_db!r})\n"
            "c.execute(\"INSERT INTO demo_records VALUES (2,'B','Synthetic DR record B')\"); c.commit()\n"
            "rows=c.execute('SELECT code,payload FROM demo_records ORDER BY record_id').fetchall(); c.close()\n"
            "assert rows == [('A','Synthetic source record A'),('B','Synthetic DR record B')]\n"
            "print(json.dumps({'phase':'DR_WRITE_READ','codes':[r[0] for r in rows],'count':len(rows)}))\n"
        )
        dr = json.loads(_ssm(remote_add_b))
        if dr.get("phase") != "DR_WRITE_READ" or dr.get("codes") != ["A", "B"] or dr.get("count") != 2:
            raise DemoError("AWS_B_WRITE_READ_VERIFY_FAILED")
        remote_dump = (
            "import base64,hashlib,json,sqlite3\n"
            f"c=sqlite3.connect({remote_db!r})\n"
            "rows=c.execute('SELECT record_id,code,payload FROM demo_records ORDER BY record_id').fetchall(); c.close()\n"
            "assert [r[1] for r in rows] == ['A','B']\n"
            "sql=''.join(\"REPLACE INTO demo_records(record_id,code,payload) VALUES (%d,'%s','%s');\\n\" % r for r in rows)\n"
            "print(json.dumps({'phase':'FAILBACK_DUMP','sql_b64':base64.b64encode(sql.encode()).decode(),'sha256':hashlib.sha256(sql.encode()).hexdigest(),'count':len(rows)}))\n"
        )
        dumped = json.loads(_ssm(remote_dump))
        if dumped.get("phase") != "FAILBACK_DUMP" or dumped.get("count") != 2:
            raise DemoError("AWS_FAILBACK_DUMP_INVALID")
        try:
            failback_dump = base64.b64decode(dumped["sql_b64"], validate=True).decode("utf-8")
        except (KeyError, ValueError, UnicodeError) as exc:
            raise DemoError("AWS_FAILBACK_DUMP_INVALID") from exc
        if hashlib.sha256(failback_dump.encode()).hexdigest() != dumped.get("sha256"):
            raise DemoError("AWS_FAILBACK_DUMP_HASH_MISMATCH")
        _mysql_call(mysql, datadir, ["--database=hospital_demo"], stdin=failback_dump)
        final_rows = _mysql_call(
            mysql,
            datadir,
            ["--database=hospital_demo", "--batch", "--skip-column-names", "-e", "SELECT record_id,code,payload FROM demo_records ORDER BY record_id"],
        ).splitlines()
        expected = ["1\tA\tSynthetic source record A", "2\tB\tSynthetic DR record B"]
        if final_rows != expected:
            raise DemoError("SOURCE_A_B_FAILBACK_VERIFY_FAILED")
        succeeded = True
        return {
            "AWS_DEMO_FAILOVER": "PASS",
            "AWS_DEMO_FAILBACK": "PASS",
            "DATA_A_B": "PASS",
            "AWS_DEMO_ENGINE": "SQLite on isolated Canary EMR",
            "SOURCE_ROLE_ENGINE": "temporary local MySQL",
            "FAILOVER_DUMP_SHA256": failover_hash,
            "FAILBACK_DUMP_SHA256": dumped["sha256"],
            "AWS_DB_FILE": remote_db,
            "AWS_INSTANCE_FINAL_STATE": "stopped" if original_state == "stopped" else "running (preserved)",
            "LIMITATION": "Synthetic portable SQL handoff only; not MySQL-to-MySQL or production application validation.",
        }
    finally:
        if source_process is not None and source_process.poll() is None:
            try:
                subprocess.run(
                    [mysql_info["MYSQLADMIN"], "--no-defaults", "--protocol=socket", f"--socket={mysql_info['DATADIR']}/mysql.sock", "--user=root", "shutdown"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                source_process.wait(timeout=10)
            except Exception:
                source_process.terminate()
                try:
                    source_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    source_process.kill()
                    source_process.wait(timeout=5)
        if log is not None:
            log.close()
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)
        if not succeeded and remote_may_exist:
            cleanup = (
                "import os\n"
                f"p={remote_db!r}\n"
                "if os.path.isfile(p) and not os.path.islink(p): os.unlink(p)\n"
                "print('SYNTHETIC_DB_CLEANED')\n"
            )
            try:
                _ssm(cleanup)
            except Exception:
                pass
        if original_state == "stopped":
            current = _instance().get("State", {}).get("Name")
            if current != "stopped":
                _run(["aws", "ec2", "stop-instances", "--region", REGION, "--instance-ids", INSTANCE_ID], timeout=30)
                _wait_state("stopped")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-synthetic-demo", action="store_true", help="allow start/stop of the fixed synthetic Canary EMR")
    args = parser.parse_args()
    if not args.confirm_synthetic_demo:
        print("BLOCKED: use --confirm-synthetic-demo; this command starts/stops only the fixed synthetic EMR.")
        return 2
    try:
        print(json.dumps(run_demo(), sort_keys=True))
        return 0
    except DemoError as exc:
        print(json.dumps({"STATUS": "BLOCKED", "REASON_CODE": exc.code}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"STATUS": "BLOCKED", "REASON_CODE": "UNEXPECTED_ERROR"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
