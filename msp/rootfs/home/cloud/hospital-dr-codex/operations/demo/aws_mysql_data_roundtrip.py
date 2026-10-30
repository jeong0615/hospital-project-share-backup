#!/usr/bin/env python3
"""Real MySQL A/B dump roundtrip on the isolated synthetic Canary EC2 only.

This is a demo harness, not the production Failover/Failback executor. It uses
the existing synthetic EMR instance and SSM; MySQL listens on loopback only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from operations.demo import aws_synthetic_data_roundtrip as common

INSTANCE_ID = common.INSTANCE_ID
VPC_ID = common.VPC_ID
CANARY_RUN_ID = common.CANARY_RUN_ID
EXPECTED_ROWS = [
    "1\tA\tSynthetic source record A",
    "2\tB\tSynthetic DR record B",
]
FORBIDDEN_INSTANCE_IDS = common.PRODUCTION_INSTANCE_IDS
MYSQL_BASE_CONFIG = "/etc/my.cnf"
MYSQL_DEMO_CONFIG = "/etc/my.cnf.d/99-hospital-synthetic-demo.cnf"
MYSQL_CONFIG_INCLUDE = "!includedir /etc/my.cnf.d"
DATABASE_NAME = "hospital_demo"


class MySQLDemoError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _identity_error(instance: dict) -> str | None:
    tags = {item.get("Key"): item.get("Value") for item in instance.get("Tags", [])}
    instance_id = instance.get("InstanceId")
    if instance_id in FORBIDDEN_INSTANCE_IDS or instance_id != INSTANCE_ID:
        return "TARGET_INSTANCE_FORBIDDEN"
    if (
        instance.get("VpcId") != VPC_ID
        or tags.get("CanaryRunId") != CANARY_RUN_ID
        or tags.get("Environment") != "synthetic"
        or tags.get("DataClass") != "synthetic-only"
        or not tags.get("Name", "").endswith("-emr")
        or instance.get("PublicIpAddress")
    ):
        return "SYNTHETIC_TARGET_IDENTITY_MISMATCH"
    if instance.get("State", {}).get("Name") != "stopped":
        return "SYNTHETIC_TARGET_MUST_START_STOPPED"
    return None


def _parse_json(text: str, code: str) -> dict:
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise MySQLDemoError(code) from exc
    if not isinstance(value, dict):
        raise MySQLDemoError(code)
    return value


def _mysql_query(info: dict, sql: str, *, database: str | None = None) -> str:
    args = [
        info["MYSQL"], "--no-defaults", "--protocol=socket",
        f"--socket={info['DATADIR']}/mysql.sock", "--user=root",
        "--batch", "--skip-column-names",
    ]
    if database:
        args.append(f"--database={database}")
    args.extend(["-e", sql])
    return common._run(args, timeout=60).stdout.strip()


def _local_dump(info: dict) -> str:
    args = [
        info["MYSQLDUMP"], "--no-defaults", "--protocol=socket",
        f"--socket={info['DATADIR']}/mysql.sock", "--user=root",
        "--skip-comments", "--compact", "--set-gtid-purged=OFF",
        "--no-tablespaces", "--databases", "hospital_demo",
    ]
    dump = common._run(args, timeout=60).stdout
    if "CREATE TABLE" not in dump or "Synthetic source record A" not in dump:
        raise MySQLDemoError("SOURCE_MYSQLDUMP_CONTENT_INVALID")
    return dump


def _existing_demo_state_is_safe(databases: list[str], tables: list[str], rows: list[str]) -> bool:
    system_databases = {"information_schema", "mysql", "performance_schema", "sys"}
    if set(databases) - system_databases - {"hospital_demo"}:
        return False
    if "hospital_demo" not in databases:
        return not tables and not rows
    if tables not in ([], ["demo_records"]):
        return False
    allowed_states = ([], [EXPECTED_ROWS[0]], EXPECTED_ROWS)
    return rows in allowed_states


def _remote_prepare_script(reset_existing: bool) -> str:
    script = r'''import glob,grp,hashlib,json,os,pwd,secrets,shutil,socket,stat,subprocess,tempfile,time
reset_existing=__RESET_EXISTING__
def run(args, input_text=None, timeout=120):
    p=subprocess.run(args,input=input_text,text=True,capture_output=True,timeout=timeout)
    if p.returncode: raise RuntimeError('REMOTE_MYSQL_SETUP_FAILED')
    return p.stdout.strip()
def query(sql):
    p=subprocess.run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket=/var/lib/mysql/mysql.sock','--batch','--skip-column-names','-e',sql],text=True,capture_output=True,timeout=30)
    if p.returncode: raise RuntimeError('REMOTE_MYSQL_PREFLIGHT_FAILED')
    return p.stdout.strip().splitlines()
def ensure_config_include():
    base='/etc/my.cnf'; backup='/etc/my.cnf.hospital-synthetic-demo.baseline'; directive='!includedir /etc/my.cnf.d'
    if not os.path.isfile(base) or os.path.islink(base): raise RuntimeError('MYSQL_BASE_CONFIG_INVALID')
    st=os.stat(base)
    if st.st_uid != 0 or (st.st_mode & 0o022): raise RuntimeError('MYSQL_BASE_CONFIG_PERMISSIONS_INVALID')
    with open(base,'rb') as f: original=f.read()
    has_directive=directive in [line.strip() for line in original.decode('utf-8').splitlines()]
    if has_directive:
        prefix=(directive+'\n').encode()
        if not original.startswith(prefix): raise RuntimeError('MYSQL_BASE_CONFIG_INCLUDE_POSITION_INVALID')
        if os.path.exists(backup):
            if os.path.islink(backup): raise RuntimeError('MYSQL_BASE_CONFIG_BACKUP_PERMISSIONS_INVALID')
            bs=os.stat(backup)
            if not stat.S_ISREG(bs.st_mode) or bs.st_uid != 0 or (bs.st_mode & 0o777) != 0o600: raise RuntimeError('MYSQL_BASE_CONFIG_BACKUP_PERMISSIONS_INVALID')
            with open(backup,'rb') as f: baseline=f.read()
            if baseline not in (original[len(prefix):], original): raise RuntimeError('MYSQL_BASE_CONFIG_DRIFT')
            return baseline
        fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as f: f.write(original); f.flush(); os.fsync(f.fileno())
        os.chown(backup,0,0)
        return original
    if os.path.exists(backup):
        if os.path.islink(backup): raise RuntimeError('MYSQL_BASE_CONFIG_BACKUP_PERMISSIONS_INVALID')
        bs=os.stat(backup)
        if not stat.S_ISREG(bs.st_mode) or bs.st_uid != 0 or (bs.st_mode & 0o777) != 0o600: raise RuntimeError('MYSQL_BASE_CONFIG_BACKUP_PERMISSIONS_INVALID')
        with open(backup,'rb') as f: baseline=f.read()
        if baseline != original: raise RuntimeError('MYSQL_BASE_CONFIG_DRIFT')
    else:
        fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as f: f.write(original); f.flush(); os.fsync(f.fileno())
        os.chown(backup,0,0)
    updated=(directive+'\n').encode()+original
    fd,tmp=tempfile.mkstemp(prefix='.my.cnf.synthetic.',dir='/etc')
    try:
        with os.fdopen(fd,'wb') as f: f.write(updated); f.flush(); os.fsync(f.fileno())
        os.chown(tmp,0,0); os.chmod(tmp,stat.S_IMODE(st.st_mode)); os.replace(tmp,base)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return original
def check_runtime_config():
    bind=query('SELECT @@global.bind_address')
    if bind != ['IP_REDACTED']: raise RuntimeError('MYSQL_BIND_ADDRESS_NOT_LOCAL')
    defaults=run(['/usr/bin/my_print_defaults','--defaults-file=/etc/my.cnf','mysqld'],timeout=15).splitlines()
    binds=[x.split('=',1)[1] for x in defaults if x.startswith('--bind-address=')]
    if not binds or any(x not in ('IP_REDACTED','::1') for x in binds): raise RuntimeError('MYSQL_CONFIG_BIND_NOT_LOCAL')
    if not any(x.lower() in ('--mysqlx=off','--skip-mysqlx','--mysqlx=0') for x in defaults): raise RuntimeError('MYSQL_CONFIG_MYSQLX_NOT_DISABLED')
    ss=shutil.which('ss')
    if not ss: raise RuntimeError('MYSQL_LISTENER_INSPECTION_TOOL_MISSING')
    inspected=subprocess.run([ss,'-H','-lnt'],text=True,capture_output=True,timeout=10)
    if inspected.returncode: raise RuntimeError('MYSQL_LISTENER_INSPECTION_FAILED')
    endpoints=[line.split()[3] for line in inspected.stdout.splitlines() if len(line.split()) >= 4 and (':3306' in line or ':33060' in line)]
    if endpoints != ['AWS_PUBLIC_IP_REDACTED:3306']: raise RuntimeError('MYSQL_LISTENER_NOT_LOOPBACK_ONLY')
    return 'IP_REDACTED:3306'
rpm=run(['rpm','-q','mysql-community-server'])
if rpm != 'mysql-community-server-8.0.44-1.el9.x86_64': raise RuntimeError('MYSQL_PACKAGE_VERSION_MISMATCH')
state=subprocess.run(['systemctl','is-active','mysqld'],text=True,capture_output=True)
if state.stdout.strip() == 'active' and not reset_existing: raise RuntimeError('MYSQL_SERVICE_ALREADY_ACTIVE')
if state.stdout.strip() == 'active': run(['systemctl','stop','mysqld'])
datadir='/var/lib/mysql'
config='/etc/my.cnf.d/99-hospital-synthetic-demo.cnf'
backup_config='/etc/my.cnf.hospital-synthetic-demo.baseline'
expected_config='[mysqld]\nbind-address=IP_REDACTED\nmysqlx=OFF\n'
if not os.path.isdir(datadir): raise RuntimeError('MYSQL_DATADIR_MISSING')
existing_data=bool(os.listdir(datadir))
if existing_data:
    if not reset_existing: raise RuntimeError('MYSQL_DATADIR_NOT_EMPTY_USE_EXPLICIT_RESET')
    if not os.path.isfile(config) or open(config).read() != expected_config: raise RuntimeError('MYSQL_DEMO_CONFIG_MISMATCH')
    cs=os.stat(config); cred='/root/.my.cnf'
    if cs.st_uid != 0 or (cs.st_mode & 0o777) != 0o644: raise RuntimeError('MYSQL_DEMO_CONFIG_PERMISSIONS_MISMATCH')
    if not os.path.isfile(cred): raise RuntimeError('MYSQL_ROOT_CREDENTIAL_FILE_MISSING')
    st=os.stat(cred)
    if st.st_uid != 0 or (st.st_mode & 0o777) != 0o600: raise RuntimeError('MYSQL_ROOT_CREDENTIAL_PERMISSIONS_MISMATCH')
    if sorted(os.path.basename(p) for p in glob.glob('/etc/my.cnf.d/*.cnf')) != ['99-hospital-synthetic-demo.cnf']: raise RuntimeError('MYSQL_CONFIG_FRAGMENT_SET_UNEXPECTED')
    base_bytes=ensure_config_include()
    enabled=subprocess.run(['systemctl','is-enabled','mysqld'],text=True,capture_output=True).stdout.strip()
    if enabled != 'disabled': raise RuntimeError('MYSQL_AUTOSTART_NOT_DISABLED')
    run(['systemctl','start','mysqld'],timeout=120)
    sockfile='/var/lib/mysql/mysql.sock'; deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        p=subprocess.run(['/usr/bin/mysqladmin','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket='+sockfile,'ping'],capture_output=True,text=True)
        if p.returncode==0: break
        time.sleep(2)
    else: raise RuntimeError('MYSQL_START_TIMEOUT')
    version=run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket='+sockfile,'--batch','--skip-column-names','-e','SELECT VERSION()'])
    if not version.startswith('8.0.44'): raise RuntimeError('MYSQL_VERSION_UNEXPECTED')
    listener=check_runtime_config()
    enabled=subprocess.run(['systemctl','is-enabled','mysqld'],text=True,capture_output=True).stdout.strip()
    if enabled != 'disabled': raise RuntimeError('MYSQL_AUTOSTART_NOT_DISABLED')
    databases=query('SHOW DATABASES')
    tables=query('SHOW FULL TABLES FROM hospital_demo') if 'hospital_demo' in databases else []
    table_names=[line.split('\t',1)[0] for line in tables]
    rows=query('SELECT record_id,code,payload FROM hospital_demo.demo_records ORDER BY record_id') if table_names == ['demo_records'] else []
    expected=[['1\tA\tSynthetic source record A'],['1\tA\tSynthetic source record A','2\tB\tSynthetic DR record B'],[]]
    if set(databases)-{'information_schema','mysql','performance_schema','sys','hospital_demo'}: raise RuntimeError('UNEXPECTED_DATABASE_PRESENT')
    if 'hospital_demo' not in databases:
        if tables or rows: raise RuntimeError('SYNTHETIC_DATABASE_STATE_INCONSISTENT')
    elif tables not in ([],['demo_records\tBASE TABLE']) or table_names not in ([],['demo_records']) or rows not in expected:
        raise RuntimeError('SYNTHETIC_DATABASE_CONTENT_MISMATCH')
    if table_names == ['demo_records']:
        columns=query('SHOW COLUMNS FROM hospital_demo.demo_records')
        if [line.split('\t',1)[0] for line in columns] != ['record_id','code','payload']: raise RuntimeError('SYNTHETIC_TABLE_SCHEMA_MISMATCH')
    for sql in ["SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='hospital_demo'",
                "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='hospital_demo'",
                "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='hospital_demo'"]:
        if query(sql) != ['0']: raise RuntimeError('SYNTHETIC_DATABASE_OBJECTS_UNEXPECTED')
    run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket='+sockfile,'-e','DROP DATABASE IF EXISTS hospital_demo'])
    print(json.dumps({'phase':'MYSQL_READY','version':version,'listener':listener,'autostart':'disabled','reset':'validated-synthetic-database-only','mysql_base_config_backup':backup_config,'mysql_base_config_backup_sha256':hashlib.sha256(base_bytes).hexdigest()}))
    raise SystemExit(0)
else:
    if reset_existing or os.path.lexists(config) or os.path.lexists('/root/.my.cnf'): raise RuntimeError('MYSQL_EMPTY_DATADIR_STATE_MISMATCH')
    fd=os.open(config,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
    with os.fdopen(fd,'w') as f: f.write(expected_config)
    os.chown(config,0,0)
    if sorted(os.path.basename(p) for p in glob.glob('/etc/my.cnf.d/*.cnf')) != ['99-hospital-synthetic-demo.cnf']: raise RuntimeError('MYSQL_CONFIG_FRAGMENT_SET_UNEXPECTED')
    base_bytes=ensure_config_include()
    run(['systemctl','disable','mysqld'])
    mysql_user=pwd.getpwnam('mysql'); mysql_group=grp.getgrnam('mysql')
    os.chown(datadir,mysql_user.pw_uid,mysql_group.gr_gid)
    run(['/usr/sbin/mysqld','--initialize-insecure','--user=mysql'],timeout=180)
    run(['systemctl','start','mysqld'],timeout=120)
sockfile='/var/lib/mysql/mysql.sock'; deadline=time.monotonic()+90
while time.monotonic()<deadline:
    p=subprocess.run(['/usr/bin/mysqladmin','--no-defaults','--protocol=socket','--socket='+sockfile,'--user=root','ping'],capture_output=True,text=True)
    if p.returncode==0: break
    time.sleep(2)
else: raise RuntimeError('MYSQL_START_TIMEOUT')
password=secrets.token_urlsafe(36)
sql="ALTER USER 'root'@'localhost' IDENTIFIED BY '"+password+"';"
run(['/usr/bin/mysql','--no-defaults','--protocol=socket','--socket='+sockfile,'--user=root'],input_text=sql)
fd=os.open('/root/.my.cnf',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as f: f.write('[client]\nuser=root\npassword="'+password+'"\n')
os.chown('/root/.my.cnf',0,0)
version=run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket='+sockfile,'--batch','--skip-column-names','-e','SELECT VERSION()'])
if not version.startswith('8.0.44'): raise RuntimeError('MYSQL_VERSION_UNEXPECTED')
listener=check_runtime_config()
with socket.create_connection(('IP_REDACTED',3306),timeout=3): pass
print(json.dumps({'phase':'MYSQL_READY','version':version,'listener':listener,'autostart':'disabled','mysql_base_config_backup':backup_config,'mysql_base_config_backup_sha256':hashlib.sha256(base_bytes).hexdigest()}))
'''
    script = script.replace("__RESET_EXISTING__", repr(reset_existing))
    compile(script, "<synthetic-mysql-bootstrap>", "exec")
    return script


def _remote_prepare(reset_existing: bool) -> dict:
    return _parse_json(common._ssm(_remote_prepare_script(reset_existing)), "REMOTE_MYSQL_BOOTSTRAP_OUTPUT_INVALID")


def _remote_mysql(sql: str) -> dict:
    encoded = base64.b64encode(sql.encode("utf-8")).decode("ascii")
    script = f'''import base64,json,subprocess
sql=base64.b64decode({encoded!r}).decode('utf-8')
p=subprocess.run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket=/var/lib/mysql/mysql.sock'],input=sql,text=True,capture_output=True,timeout=60)
if p.returncode: raise RuntimeError('REMOTE_MYSQL_SQL_FAILED')
q=subprocess.run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket=/var/lib/mysql/mysql.sock','--batch','--skip-column-names','-e','SELECT record_id,code,payload FROM hospital_demo.demo_records ORDER BY record_id'],text=True,capture_output=True,timeout=30)
if q.returncode: raise RuntimeError('REMOTE_MYSQL_QUERY_FAILED')
print(json.dumps({{'phase':'MYSQL_ROWS','rows':q.stdout.strip().splitlines()}}))
'''
    return _parse_json(common._ssm(script), "REMOTE_MYSQL_OUTPUT_INVALID")


def _remote_failback_dump() -> str:
    script = r'''import base64,hashlib,json,subprocess
p=subprocess.run(['/usr/bin/mysqldump','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket=/var/lib/mysql/mysql.sock','--skip-comments','--compact','--replace','--no-create-info','--set-gtid-purged=OFF','--no-tablespaces','hospital_demo','demo_records'],text=True,capture_output=True,timeout=60)
if p.returncode: raise RuntimeError('REMOTE_MYSQLDUMP_FAILED')
sql=p.stdout
print(json.dumps({'phase':'FAILBACK_DUMP','count':2,'sha256':hashlib.sha256(sql.encode()).hexdigest(),'sql_b64':base64.b64encode(sql.encode()).decode()}))
'''
    response = _parse_json(common._ssm(script), "FAILBACK_DUMP_OUTPUT_INVALID")
    return _validate_failback_dump(response)


def _validate_failback_dump(response: dict) -> str:
    if response.get("phase") != "FAILBACK_DUMP" or response.get("count") != 2:
        raise MySQLDemoError("FAILBACK_DUMP_CONTENT_INVALID")
    try:
        dump = base64.b64decode(response["sql_b64"], validate=True).decode("utf-8")
    except (KeyError, ValueError, UnicodeError) as exc:
        raise MySQLDemoError("FAILBACK_DUMP_ENCODING_INVALID") from exc
    if hashlib.sha256(dump.encode()).hexdigest() != response.get("sha256"):
        raise MySQLDemoError("FAILBACK_DUMP_HASH_MISMATCH")
    if "REPLACE INTO `demo_records`" not in dump and "REPLACE INTO demo_records" not in dump:
        raise MySQLDemoError("FAILBACK_DUMP_NOT_IDEMPOTENT")
    return dump


def _run_demo(*, reset_existing: bool) -> dict:
    started = time.monotonic()
    caller = common._run(
        ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], timeout=20
    ).stdout.strip()
    if caller != common.ACCOUNT_ID:
        raise MySQLDemoError("AWS_ACCOUNT_MISMATCH")
    instance = common._instance()
    identity_error = _identity_error(instance)
    if identity_error:
        raise MySQLDemoError(identity_error)

    instance_start_requested = False
    mysql_info = source_process = source_log = local_root = None
    result = None
    try:
        instance_start_requested = True
        common._run(["aws", "ec2", "start-instances", "--region", common.REGION,
                     "--instance-ids", INSTANCE_ID], timeout=30)
        common._wait_state("running", timeout=180)
        common._wait_ssm(timeout=150)
        bootstrap = _remote_prepare(reset_existing)
        if bootstrap.get("phase") != "MYSQL_READY" or bootstrap.get("listener") != "IP_REDACTED:3306":
            raise MySQLDemoError("AWS_MYSQL_READY_CHECK_FAILED")
        baseline_hash = bootstrap.get("mysql_base_config_backup_sha256")
        if (
            bootstrap.get("autostart") != "disabled"
            or not isinstance(baseline_hash, str)
            or len(baseline_hash) != 64
            or any(char not in "0123456789abcdef" for char in baseline_hash)
        ):
            raise MySQLDemoError("MYSQL_CONFIG_BASELINE_PROOF_MISSING")

        local_root, mysql_info, source_process, source_log = common._local_mysql()
        mysql_info["MYSQLDUMP"] = shutil.which("mysqldump")
        if not mysql_info["MYSQLDUMP"]:
            raise MySQLDemoError("LOCAL_MYSQLDUMP_UNAVAILABLE")
        common._mysql_call(mysql_info["MYSQL"], mysql_info["DATADIR"], [], stdin=(
            "CREATE DATABASE hospital_demo; "
            "CREATE TABLE hospital_demo.demo_records (record_id INT PRIMARY KEY, "
            "code VARCHAR(16) NOT NULL UNIQUE, payload VARCHAR(255) NOT NULL); "
            "INSERT INTO hospital_demo.demo_records VALUES (1,'A','Synthetic source record A');"
        ))
        source_version = _mysql_query(mysql_info, "SELECT VERSION()")
        source_rows = _mysql_query(
            mysql_info, "SELECT record_id,code,payload FROM demo_records ORDER BY record_id",
            database="hospital_demo",
        ).splitlines()
        if source_rows != ["1\tA\tSynthetic source record A"]:
            raise MySQLDemoError("SOURCE_MYSQL_A_VERIFY_FAILED")

        failover_dump = _local_dump(mysql_info)
        failover_hash = hashlib.sha256(failover_dump.encode()).hexdigest()
        restored = _remote_mysql(failover_dump)
        if restored.get("phase") != "MYSQL_ROWS" or restored.get("rows") != source_rows:
            raise MySQLDemoError("AWS_MYSQL_A_RESTORE_VERIFY_FAILED")
        version = _parse_json(common._ssm(
            "import json,subprocess\np=subprocess.run(['/usr/bin/mysql','--defaults-extra-file=/root/.my.cnf','--protocol=socket','--socket=/var/lib/mysql/mysql.sock','--batch','--skip-column-names','-e','SELECT VERSION()'],text=True,capture_output=True,timeout=20)\nif p.returncode: raise RuntimeError('MYSQL_VERSION_QUERY_FAILED')\nprint(json.dumps({'version':p.stdout.strip()}))"
        ), "AWS_MYSQL_VERSION_OUTPUT_INVALID")
        aws_version = version.get("version")
        if not aws_version or not aws_version.startswith("8.0.44"):
            raise MySQLDemoError("AWS_MYSQL_VERSION_UNEXPECTED")

        after_b = _remote_mysql(
            "INSERT INTO hospital_demo.demo_records VALUES (2,'B','Synthetic DR record B');"
        )
        if after_b.get("rows") != EXPECTED_ROWS:
            raise MySQLDemoError("AWS_MYSQL_A_B_VERIFY_FAILED")
        failback_dump = _remote_failback_dump()
        common._mysql_call(mysql_info["MYSQL"], mysql_info["DATADIR"],
                           ["--database=hospital_demo"], stdin=failback_dump)
        final_source_rows = _mysql_query(
            mysql_info, "SELECT record_id,code,payload FROM demo_records ORDER BY record_id",
            database="hospital_demo",
        ).splitlines()
        if final_source_rows != EXPECTED_ROWS:
            raise MySQLDemoError("SOURCE_MYSQL_A_B_FAILBACK_VERIFY_FAILED")
        result = {
            "AWS_MYSQL_FAILOVER": "PASS",
            "AWS_MYSQL_FAILBACK": "PASS",
            "DATA_A_B": "PASS",
            "SOURCE_MYSQL_VERSION": source_version,
            "AWS_MYSQL_VERSION": aws_version,
            "MYSQL_LISTENER": bootstrap.get("listener"),
            "MYSQL_AUTOSTART": bootstrap.get("autostart"),
            "MYSQL_BASE_CONFIG_BACKUP_SHA256": bootstrap.get("mysql_base_config_backup_sha256"),
            "FAILOVER_DUMP_SHA256": failover_hash,
            "FAILBACK_DUMP_SHA256": hashlib.sha256(failback_dump.encode()).hexdigest(),
            "FAILOVER_ROWS": ["A"],
            "AWS_ROWS_AFTER_B": ["A", "B"],
            "SOURCE_ROWS_AFTER_FAILBACK": ["A", "B"],
            "AWS_TARGET": INSTANCE_ID,
            "ELAPSED_SECONDS": round(time.monotonic() - started, 1),
            "SCOPE": "isolated synthetic MySQL on Canary EMR; not production DR or application E2E",
        }
    finally:
        if source_process is not None and source_process.poll() is None:
            try:
                common._run(
                    [mysql_info["MYSQLADMIN"], "--no-defaults", "--protocol=socket",
                     f"--socket={mysql_info['DATADIR']}/mysql.sock", "--user=root", "shutdown"], timeout=10
                )
                source_process.wait(timeout=10)
            except Exception:
                source_process.terminate()
                try:
                    source_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    source_process.kill()
                    source_process.wait(timeout=5)
        if source_log:
            source_log.close()
        if local_root:
            shutil.rmtree(local_root, ignore_errors=True)
        if instance_start_requested:
            current = common._instance().get("State", {}).get("Name")
            if current == "pending":
                common._wait_state("running", timeout=180)
                current = "running"
            if current == "running":
                try:
                    common._ssm(
                        "import subprocess\nsubprocess.run(['systemctl','stop','mysqld'],capture_output=True,timeout=45)"
                    )
                except Exception:
                    pass
                common._run(["aws", "ec2", "stop-instances", "--region", common.REGION,
                             "--instance-ids", INSTANCE_ID], timeout=30)
                common._wait_state("stopped", timeout=240)
            elif current == "stopping":
                common._wait_state("stopped", timeout=240)
            elif current != "stopped":
                raise MySQLDemoError("AWS_INSTANCE_CLEANUP_STATE_UNKNOWN")
    if result is None:
        raise MySQLDemoError("DEMO_DID_NOT_COMPLETE")
    result["AWS_INSTANCE_FINAL_STATE"] = "stopped"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-synthetic-mysql-demo", action="store_true")
    parser.add_argument(
        "--reset-existing-synthetic-db",
        action="store_true",
        help="reset only the verified synthetic hospital_demo database on the pinned Canary EC2",
    )
    args = parser.parse_args()
    if not args.confirm_synthetic_mysql_demo:
        print(json.dumps({"STATUS": "BLOCKED", "REASON_CODE": "EXPLICIT_CONFIRMATION_REQUIRED"}))
        return 2
    try:
        print(json.dumps(_run_demo(reset_existing=args.reset_existing_synthetic_db), sort_keys=True))
        return 0
    except MySQLDemoError as exc:
        print(json.dumps({"STATUS": "BLOCKED", "REASON_CODE": exc.code}, sort_keys=True))
        return 1
    except common.DemoError as exc:
        print(json.dumps({"STATUS": "BLOCKED", "REASON_CODE": exc.code}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"STATUS": "BLOCKED", "REASON_CODE": "UNEXPECTED_ERROR"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
