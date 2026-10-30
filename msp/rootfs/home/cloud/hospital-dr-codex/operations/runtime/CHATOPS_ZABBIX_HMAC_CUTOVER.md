# ChatOps / Zabbix HMAC 통합 전환 절차

이 문서는 운영 반영 준비 절차다. 작성 시점에는 Runtime, Sender, 비밀 설정,
Zabbix Action을 변경하거나 서비스를 재시작하지 않았다.

## 현재 확인 결과

- ChatOps systemd는 `/home/cloud/dr_project`에서 실행하며
  `DR_SECRET_FILE=/home/cloud/hospital-dr-secrets/dr.env`를 읽는다.
- Zabbix Compose의 `zabbix-server`는
  `/home/cloud/send_slack.sh`를 컨테이너의
  `/usr/lib/zabbix/alertscripts/send_slack.sh`에 읽기 전용 bind mount하고,
  `/home/cloud/zabbix/.env_srv`를 `env_file`로 사용한다.
- 두 파일 모두 `ZABBIX_PRODUCTION_ACTION_HMAC_KEY`가 없다. `dr.env`는
  `0600`; `.env_srv`는 현재 `0664`이므로, 키를 넣기 전에 `.env_srv`를
  `0600`, `cloud:cloud`로 제한해야 한다. 키 검증기는 이 상태를 BLOCKED로
  처리한다.
- Canonical Sender는 Production 및 전용 `zabbix_test_action` 요청에 같은
  HMAC 키를 사용한다. 기존 운영 Sender는 구버전이며 서명을 보내지 않는다.
- 현재 `dr.env`의 관리자 ID 설정은 서로 다른 ID 3개로 보이지만, 과거
  사전점검은 유효 관리자 1명으로 판정했다. 실제 승인 전 실행 중 프로세스가
  읽는 설정과 관리자 권한 목록을 비밀·식별자 노출 없이 다시 대조해야 한다.
- 현재 동기화 dry-run 결과는 `chatops_core.py` 하나다. Runtime의 같은 파일은
  Canonical보다 크게 뒤처져 있어 이 파일만 별도로 배포하지 않는다.
- 운영 SQLite는 `/var/lib/hospital-dr/chatops_state.sqlite3`이며, 읽기 전용
  확인 당시 승인 테이블의 20개 열과 활성 요청 인덱스가 현재
  Canonical/Runtime 계약과 일치했다. 192개 행 중
  `PENDING`/`PARTIALLY_APPROVED`/`EXECUTING`은 0건이었다. 주요 Lock의 커널
  잠금과 실행 프로세스도 관찰되지 않았으나 이는 조회 시점의 스냅샷이므로
  유지보수 직전에 다시 확인한다.
- `/home/cloud/dr_project/chatops_state.sqlite3`는 서비스가 사용하지 않는
  별도 파일이다. 읽기 전용 확인에서 스키마가 현재 계약과 달랐고 PENDING
  행도 있었다. 이 파일은 운영 백업·복구·동기화 대상으로 삼지 않는다.
- ChatOps 서비스와 Zabbix proxy 서비스는 active이고, 호스트에서 5000/5001
  listener가 확인됐다. Docker daemon/container 내부 환경은 sudo 읽기 권한이
  없어 확인되지 않았다.
- 읽기 전용 Zabbix API 결과: 6.0.45. Trigger 24712는 비활성(`status=1`),
  현재 값은 PROBLEM이며 실제 식은 OR이다. Action 3
  `Cloud_Slack_DR_Trigger`는 활성(`status=0`)이고, 현재 필터는
  `evaltype=0`의 두 조건뿐이다: `DR_Escalate=1`과 condition type 16 /
  operator 11. Canonical은 네 태그 AND와 suppression 제외를 포함한 다섯
  조건을 요구한다. 연결 Media `Slack DR Trigger`(ID 40)는 활성이다. 별도
  `Slack DR Test Trigger` Media Type(ID 45)도 활성이다. Broad Test Action은
  비활성이고 Problem operation drift가 확인됐다. 그 Action의 recovery
  operation은 `Slack Failback Test`를 호출하므로 Failback 제외 범위에서는
  활성화하지 않는다. Media Type 직접 테스트는 Action 필터를 검증하지 않는
  별도 경로다. 어떤 운영 Zabbix 설정도 변경하지 않았다.
- 기존 Web Failover 사전점검은 AWS read-only 및 Cloudflare token/DNS GET을
  수행했다. DB EC2는 running, Web/EMR EC2는 stopped다. 따라서 현재 Web/EMR
  container Health와 Ansible 연결은 실패했다. Web NAT 판정은
  `BLACKHOLE / NOT_READY`; Web 인스턴스가 stopped이고 기본 경로가 blackhole이며
  NAT Gateway는 없고, 분리된 NAT EIP는 보존 상태다. `READY_FOR_BLACKHOLE_RECOVERY`
  는 출력되지 않았으며 정상 NAT READY로 취급하지 않았다.
- 같은 사전점검에서 Cloudflare SSM 토큰은 활성 상태로 확인됐고 Web/EMR의
  On-Prem 원본 DNS readback 및 보존된 원복 snapshot이 일치했다. DNS 쓰기 권한은
  변경 요청을 보내지 않아 미검증이다.
- Production Trigger 검사는 독립 Monitoring Path 신호 부재로 BLOCKED다.
  기존 SNMP availability 항목은 Production Monitoring Path의 독립 증거로
  인정되지 않는다. 현장 검증 전 Trigger 24712를 활성화하면 안 된다.

## 통제된 전환 순서

이 순서 전체를 승인된 유지보수 창에서만 수행한다. 중간 상태에서는
Production Action을 재개하지 않는다.

먼저 사용자가 인증한 **같은 MSP 터미널**에서 아래를 실행한다. sudo 인증은 Codex
실행 세션과 공유되지 않는다. 두 번째 명령이 실패하면 여기서 멈추고 그 터미널에서
재인증한다.

```bash
cd /home/cloud/hospital-dr-codex
sudo -v && sudo -n true && printf 'SUDO_AUTH=OK\n'
```

1. 운영 SQLite의 활성 요청 수와 프로세스/Lock을 다시 확인한다. 활성 요청은
   반드시 0이어야 한다. `sync_chatops_runtime.sh`도 재시작 직전 동일한 DB와 Lock을
   자체 검사한다.

   ```bash
   python3 - <<'PY'
   import sqlite3
   db = sqlite3.connect('file:/var/lib/hospital-dr/chatops_state.sqlite3?mode=ro', uri=True)
   count = db.execute("SELECT COUNT(*) FROM approval_requests WHERE status IN ('PENDING','PARTIALLY_APPROVED','EXECUTING')").fetchone()[0]
   db.close()
   print(f'ACTIVE_APPROVAL_REQUESTS={count}')
   if count:
       raise SystemExit('CUTOVER=BLOCKED active_requests')
   PY
   sudo lslocks -n -o PID,COMMAND,PATH | awk 'tolower($0) ~ /hospital|chatops|dr_project/ {print; found=1} END {if (!found) print "DR_LOCKS=FREE"}'
   ```

   관련 Lock/실행이 있거나 확인이 불가능하면 중단한다.
2. 승인된 유지보수 시작 시 Action 3만 일시 정지한다. 아래 코드는 기존
   `configure_chatops.py`의 API client와 기존 Zabbix API 설정을 재사용하며, 먼저
   Action ID·이름·Event source를 확인하고 `status`만 `0→1`로 바꾼 뒤 readback한다.
   이 명령은 Production Trigger 24712나 Action 조건·미디어를 수정하지 않는다.

   ```bash
   python3 - <<'PY'
   from operations.zabbix.configure_chatops import ZabbixClient, load_settings
   settings = load_settings('/home/cloud/hospital-dr-ansible/roles/web_deploy/files/.env')
   api = ZabbixClient(settings)
   api.authenticate()
   params = {'output': ['actionid', 'name', 'status', 'eventsource'], 'actionids': ['3']}
   rows = api.call('action.get', params)
   if len(rows) != 1 or rows[0].get('actionid') != '3' or rows[0].get('name') != 'Cloud_Slack_DR_Trigger' or rows[0].get('eventsource') != '0':
       raise SystemExit('ACTION3_PAUSE=BLOCKED identity_mismatch')
   status = str(rows[0].get('status'))
   if status == '0':
       api.call('action.update', {'actionid': '3', 'status': '1'})
   elif status != '1':
       raise SystemExit('ACTION3_PAUSE=BLOCKED unexpected_status')
   verify = api.call('action.get', params)
   if len(verify) != 1 or str(verify[0].get('status')) != '1':
       raise SystemExit('ACTION3_PAUSE=READBACK_FAILED')
   print('ACTION3_PAUSE=PASS status=disabled')
   PY
   ```

   이번 승인에서는 Action 3 재활성화가 제외됐으므로, 이후 성공·실패와 무관하게
   비활성 상태를 유지한다. Trigger 24712도 현재 비활성 상태를 유지하며 변경하지 않는다.
3. 기존 Sender와 두 환경 파일을 제한된 백업 디렉터리에 보존한다. 백업에는
   Secret이 포함되므로 아래처럼 디렉터리 `0700`, Secret 파일 `0600`을 사용한다.

   ```bash
   umask 077
   stamp=$(date -u +%Y%m%dT%H%M%SZ)
   backup="/home/cloud/backups/chatops-zabbix-cutover/$stamp"
   sudo install -d -o cloud -g cloud -m 0700 "$backup"
   sudo cp -a /home/cloud/send_slack.sh "$backup/send_slack.sh"
   sudo cp -a /home/cloud/hospital-dr-secrets/dr.env "$backup/dr.env"
   sudo cp -a /home/cloud/zabbix/.env_srv "$backup/.env_srv"
   sudo chmod 0600 "$backup/dr.env" "$backup/.env_srv"
   printf 'BACKUP_DIR=%s\n' "$backup"
   ```

4. 실제 운영 SQLite만 SQLite Online Backup API로 백업하고, integrity와 권한을
   확인한다. 이 절차는 승인 기록을 포함하는 일관된 스냅샷을 만들며 원본을
   수정하지 않는다. `$backup`은 2단계에서 출력된 경로여야 한다. 승인된
   유지보수 창 전에는 실행하지 않는다.

   ```bash
   sudo -u cloud install -d -m 0700 "$backup/sqlite"
   sudo -u cloud env CHATOPS_BACKUP_DIR="$backup/sqlite" python3 - <<'PY'
   import os, sqlite3, tempfile
   from datetime import datetime, timezone
   from pathlib import Path
   from urllib.parse import quote

   source = Path('/var/lib/hospital-dr/chatops_state.sqlite3')
   out_dir = Path(os.environ['CHATOPS_BACKUP_DIR'])
   final = out_dir / 'chatops_state.sqlite3'
   if not source.is_file() or final.exists():
       raise SystemExit('SQLITE_BACKUP=BLOCKED source_missing_or_destination_exists')
   os.umask(0o077)
   os.chmod(out_dir, 0o700)
   fd, temp_name = tempfile.mkstemp(prefix='.chatops_state.', suffix='.tmp', dir=out_dir)
   os.close(fd)
   temp = Path(temp_name)
   src = dst = None
   try:
       uri = 'file:' + quote(str(source), safe='/') + '?mode=ro'
       src = sqlite3.connect(uri, uri=True, timeout=30)
       src.execute('PRAGMA query_only=ON')
       dst = sqlite3.connect(str(temp), timeout=30)
       src.backup(dst, pages=256, sleep=0.1)
       check = dst.execute('PRAGMA integrity_check').fetchone()[0]
       dst.close(); dst = None
       src.close(); src = None
       if check != 'ok':
           raise RuntimeError('integrity_check_failed')
       os.chmod(temp, 0o600)
       with temp.open('rb+') as f:
           os.fsync(f.fileno())
       os.replace(temp, final)
       dir_fd = os.open(out_dir, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
       try: os.fsync(dir_fd)
       finally: os.close(dir_fd)
       print('SQLITE_BACKUP=PASS')
       print('INTEGRITY_CHECK=ok')
       print('BACKUP_UTC=' + datetime.now(timezone.utc).isoformat())
       print('BACKUP_PATH=' + str(final))
       print('BACKUP_MODE=%04o' % (final.stat().st_mode & 0o777))
   finally:
       if dst is not None: dst.close()
       if src is not None: src.close()
       if temp.exists(): temp.unlink()
   PY
   ```

   유지보수 기록에는 출력된 UTC 시각·경로와 `SQLITE_BACKUP=PASS`,
   `INTEGRITY_CHECK=ok`, `BACKUP_MODE=600`을 남긴다. 대상은 반드시
   `/var/lib/hospital-dr/chatops_state.sqlite3`다. 프로젝트 디렉터리의 동명
   SQLite는 열거나 복사하지 않는다. 코드/Sender/환경 롤백 때 이 스냅샷으로
   운영 DB를 되돌리지 않는다. 승인 데이터는 컷오버 중 계속 운영 DB에 남아야
   하며, SQLite 복구는 별도 장애 판단·승인 없이는 금지한다.

5. `.env_srv` 권한을 `cloud:cloud`, `0600`으로 제한하고 Compose 입력 파일의
   접근 가능 여부를 값 노출 없이 확인한다. 승인된 유지보수 단계에서만 수행한다.

   ```bash
   sudo chown cloud:cloud /home/cloud/zabbix/.env_srv
   sudo chmod 0600 /home/cloud/zabbix/.env_srv
   sudo test "$(stat -c '%U:%G:%a' /home/cloud/zabbix/.env_srv)" = 'cloud:cloud:600'
   sudo -u cloud test -r /home/cloud/zabbix/.env_srv
   sudo /usr/bin/docker compose --project-directory /home/cloud/zabbix \
     -f /home/cloud/zabbix/docker-compose.yml config --quiet
   ```

6. HMAC 키는 현재 두 파일에 없다. 승인된 유지보수에서만 기존 지정 Secret 파일
   두 곳에 같은 키를 생성·기록한다. 아래 명령은 키를 argv, shell history,
   환경 출력, 로그에 넣지 않고, `secrets` CSPRNG로 48바이트 키를 만들어
   메모리에서 각 파일을 같은 디렉터리의 임시 파일로 원자 교체한다. 첫 파일만
   바뀌는 등 오류가 나면 Action을 계속 정지하고 서비스를 재시작하지 말며,
   2단계 백업에서 두 파일 모두 복구한 뒤 원인을 해결한다.

   ```bash
   sudo python3 - <<'PY'
   import os, pwd, re, secrets, tempfile
   from pathlib import Path

   name = 'ZABBIX_PRODUCTION_ACTION_HMAC_KEY'
   paths = [Path('/home/cloud/hospital-dr-secrets/dr.env'),
            Path('/home/cloud/zabbix/.env_srv')]
   uid, gid = pwd.getpwnam('cloud').pw_uid, pwd.getpwnam('cloud').pw_gid
   pattern = re.compile(rb'^[ \t]*(?:export[ \t]+)?' + name.encode() + rb'[ \t]*=.*$', re.M)
   originals = []
   for path in paths:
       if path.is_symlink() or not path.is_file():
           raise SystemExit('HMAC_KEY_WRITE=BLOCKED invalid_file')
       data = path.read_bytes()
       if len(pattern.findall(data)) > 1:
           raise SystemExit('HMAC_KEY_WRITE=BLOCKED duplicate_definition')
       originals.append(data)
   key = secrets.token_urlsafe(48).encode('ascii')
   outputs = []
   for data in originals:
       line = name.encode() + b'=' + key
       if pattern.search(data):
           data = pattern.sub(line, data, count=1)
       else:
           data += (b'' if not data or data.endswith(b'\n') else b'\n') + line + b'\n'
       outputs.append(data)
   for path, data in zip(paths, outputs):
       fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
       try:
           os.fchown(fd, uid, gid); os.fchmod(fd, 0o600)
           with os.fdopen(fd, 'wb') as f:
               f.write(data); f.flush(); os.fsync(f.fileno())
           os.replace(tmp, path)
           dfd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
           try: os.fsync(dfd)
           finally: os.close(dfd)
       except Exception:
           try: os.unlink(tmp)
           except FileNotFoundError: pass
           raise
   print('HMAC_KEY_WRITE=PASS')
   print('HMAC_FILES=2')
   PY
   ```

   출력은 키를 포함하지 않는다. 이어서 두 파일의 소유자·모드와
   `verify_chatops_hmac_keys.py` 결과를 확인한다. 결과가 `HMAC_KEYS=MATCH`가
   아니면 재시작·컨테이너 재생성·테스트 전송을 진행하지 않는다.
7. `cloud` 사용자로 파일 내용이 아닌 일치 여부만 검사한다.

   ```bash
   python3 /home/cloud/hospital-dr-codex/operations/zabbix/verify_chatops_hmac_keys.py \
     --chatops-env /home/cloud/hospital-dr-secrets/dr.env \
     --zabbix-env /home/cloud/zabbix/.env_srv
   ```

   결과가 `HMAC_KEYS=MATCH`가 아니면 진행하지 않는다.
8. Canonical Sender를 임시 경로에 설치하고 `bash -n` 검사 후 같은 파일시스템
   안에서 `/home/cloud/send_slack.sh`로 원자 교체한다. 실제 교체 명령은 아래와
   같고 기존 bind mount 경로를 유지한다.

   ```bash
   sudo install -o cloud -g cloud -m 0755 \
     /home/cloud/hospital-dr-codex/operations/chatops/send_slack.sh \
     /home/cloud/.send_slack.sh.next
   sudo bash -n /home/cloud/.send_slack.sh.next
   sudo mv -f /home/cloud/.send_slack.sh.next /home/cloud/send_slack.sh
   ```

9. 승인된 Docker 관리자 권한으로 Zabbix server 컨테이너만 재생성해 새
   `.env_srv`를 주입한다. Compose 설정 전체 출력이나 `docker inspect`의 환경
   전체 출력은 금지한다. 환경변수는 값 대신 `SET/MISSING`만 검증한다.

   ```bash
   sudo /usr/bin/docker compose --project-directory /home/cloud/zabbix \
     -f /home/cloud/zabbix/docker-compose.yml up -d --no-deps --force-recreate zabbix-server
   sudo /usr/bin/docker compose --project-directory /home/cloud/zabbix \
     -f /home/cloud/zabbix/docker-compose.yml exec -T zabbix-server sh -c \
     'test -n "${ZABBIX_PRODUCTION_ACTION_HMAC_KEY:-}" && echo HMAC_ENV=SET || echo HMAC_ENV=MISSING'
   ```

10. Runtime 반영 직전 운영 SQLite(`/var/lib/hospital-dr/chatops_state.sqlite3`)
   의 활성 요청, 실행 프로세스와 실제 Lock을 다시 검사한다. 이 검사에는
   `/home/cloud/dr_project/chatops_state.sqlite3`를 사용하지 않는다. 서로 다른
   두 명의 실제 승인 관리자가 유효한지 실행 중 ChatOps 권한 경로와 대조한다.
   활성 요청·프로세스·Lock이 있거나 관리자 수가 불명확하면 중단한다.
11. 아래의 기존 ChatOps 동기화 스크립트로 allowlist 변경분을 백업·동기화하고
   검증 후 ChatOps 서비스를 한 번 재시작한다.

   ```bash
   sudo bash /home/cloud/hospital-dr-codex/operations/runtime/sync_chatops_runtime.sh --restart
   ```

   현재 dry-run에서 예상된 변경은 `chatops_core.py` 하나다. 실행 당시 다른
   대상이 나오면 중단한다. 이 스크립트는 변경 전 Runtime 모듈 백업을 만들고
   compile/import 또는 재시작 검증 실패 시 동기화된 Python 파일을 복구한다.
12. 파일 간 키 일치, Zabbix 컨테이너 내 키의 존재 여부(값 미출력),
   `hospital-dr-chatops.service` active/MainPID, Runtime import, 최근 오류 로그를
   확인한다. ChatOps HTTP는 기존 proxy 경로와 `/chatops/request` 수신 계약으로
   확인한다.
13. Production Action은 계속 정지 상태로 둔 채, 서명 생성 측과 ChatOps의
    유효/무효 HMAC 검증을 먼저 확인한다. 무효 서명은 거부되고 요청 행이
    생성되지 않아야 한다. 승인된 유지보수 창에서만 아래 요청을 보내며, 이
    잘못된 서명은 인증 검사 단계에서 403으로 거부돼야 한다.

    ```bash
    body='{"action":"failover","source":"zabbix_test_action","test_mode":true}'
    stamp=$(date +%s)
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
      -X POST http://IP_REDACTED:5000/chatops/request \
      -H 'Content-Type: application/json' \
      -H "X-ChatOps-Zabbix-Timestamp: $stamp" \
      -H "X-ChatOps-Zabbix-Signature: v1=$(printf '0%.0s' {1..64})" \
      --data-binary "$body")
    test "$code" = 403 && printf 'INVALID_HMAC=REJECTED HTTP=%s\n' "$code"
    ```
14. 별도 승인 후 Media Type 45의 UI `Test`로 서명된 테스트 메시지 하나를
    보낼 수 있다. 이 UI는 Zabbix Server에서 스크립트를 직접 호출하므로
    Sender→HMAC→Proxy→ChatOps→Slack만 검증하며 Action 3 또는 테스트 Action의
    필터는 검증하지 않는다. 테스트 입력은 기존 계약대로
    `__zabbix_test__`, subject, message 순서이며 message에는 다음 필드가
    있어야 한다: `Action name: Cloud_Slack_DR_Broad_Test_Mode`, 고유한 양의
    숫자 Event ID/Trigger ID, `Event source: 0`, `Host`, `Status: PROBLEM`,
    `Event age`, `Event tags JSON`, `Time`. 도착한 Slack 메시지의 테스트 표시와
    요청 ID를 확인하고 SQLite에서 해당 요청이 `test_mode=true`인지를 읽기
    전용으로 대조한다. 메시지 수신만 검증하는 이번 컷오버에서는 Slack의 승인
    버튼을 누르지 않는다. 테스트 요청은 실제 Executor를 호출하지 않으며,
    별도 승인을 받아 테스트 승인 콜백까지 검증하는 경우에만 최종 결과에서
    `executor_started=false`, `AWS_DB_DNS=NOT_TOUCHED`, `REAL_E2E=NOT_TESTED`를
    확인한다. 동일 Event ID replay는 새 요청이나 중복 Slack 메시지를 만들지
    않아야 한다. 이 테스트는 실제 운영 Trigger/Action을 활성화하지 않는다.
15. Broad Test Action은 현재 비활성이며 Problem operation drift가 있다. 기존
    recovery operation이 `Slack Failback Test`를 호출하므로 이번 Failback 제외
    범위에서 수정하거나 활성화하지 않는다. 기존
    `configure_broad_test_mode.py --enable`도 이 recovery operation을 구성하므로
    실행하지 않는다. Action 필터 자체의 테스트가 필요하면 Problem-only,
    Failover-test 전용 host/condition만 허용하고 recovery/update operation은
    비워 둔 별도 계약을 준비한 뒤 별도 승인해야 한다. 그때까지 Media Type 직접
    테스트만 전달 경로 검사로 사용할 수 있으며 Action 필터 테스트는 미완료다.
    Production Action 재개는 별도 운영 승인으로 결정한다. Trigger 24712는 독립
    Monitoring Path 검증과 AND/300초 정책 운영 readback 전까지 비활성 유지한다.

## 유지보수 영향

- Production Action을 정지하는 동안 Zabbix 자동 Failover 알림 전달은 중단된다.
  현재 Trigger 24712는 이미 비활성이지만 Action의 기존 상태도 변경 전후
  readback하고, 유지보수 완료 후 별도 승인 없이 임의 재개하지 않는다.
- Zabbix Server 컨테이너 재생성 중 alert-script 실행이 잠시 불가능할 수 있고,
  ChatOps 재시작 중 `/chatops/request` 수신이 잠시 중단된다. 시작 전 활성 요청
  0건과 Lock 부재를 재확인한다.
- 이 컷오버는 AWS, DB, DNS를 변경하지 않으며 실제 Failover Executor를 호출하지
  않는다. Trigger 24712는 계속 비활성으로 둔다.

## 재검증 명령

```bash
bash /home/cloud/hospital-dr-codex/operations/runtime/sync_chatops_runtime.sh --dry-run
bash -n /home/cloud/hospital-dr-codex/operations/chatops/send_slack.sh
python3 -m unittest \
  tests.test_chatops_approval \
  tests.test_zabbix_action_sender \
  tests.test_zabbix_broad_test_mode \
  tests.test_verify_chatops_hmac_keys \
  tests.test_chatops_runtime_sync
```

## 롤백

실패하면 Production Action은 정지 상태로 둔다. 먼저 새 승인/실행/Lock이
없는지 확인한다. 승인된 백업에서 `dr.env`, `.env_srv`, Sender를 원래 경로와
권한으로 복구하고 Zabbix server 컨테이너를 재생성한다. 아래의 `backup`과
`CHATOPS_BACKUP`은 실제 출력 경로로 설정해야 한다.

```bash
sudo install -o cloud -g cloud -m 0600 "$backup/dr.env" \
  /home/cloud/hospital-dr-secrets/dr.env
sudo install -o cloud -g cloud -m 0600 "$backup/.env_srv" \
  /home/cloud/zabbix/.env_srv
sudo install -o cloud -g cloud -m 0755 "$backup/send_slack.sh" \
  /home/cloud/.send_slack.sh.rollback
sudo mv -f /home/cloud/.send_slack.sh.rollback /home/cloud/send_slack.sh
sudo /usr/bin/docker compose --project-directory /home/cloud/zabbix \
  -f /home/cloud/zabbix/docker-compose.yml up -d --no-deps --force-recreate zabbix-server
sudo install -o cloud -g cloud -m 0644 "$CHATOPS_BACKUP/chatops_core.py" \
  /home/cloud/dr_project/.chatops_core.py.rollback
sudo mv -f /home/cloud/dr_project/.chatops_core.py.rollback \
  /home/cloud/dr_project/chatops_core.py
sudo systemctl restart hospital-dr-chatops.service
```

복구 후 두 서비스의 상태와 로그를 확인한다. 활성 작업이 있거나 백업 무결성이 불확실하면 자동
복구를 시도하지 말고 중단한다. `dr.env`/`.env_srv` 복구는 `sudo install -m 0600`
으로 원래 경로에 적용하고, Sender는 백업본을 임시 파일에 설치한 뒤 `mv`로
원자 복구한다. Runtime의 실제 변경은 dry-run상 `chatops_core.py` 하나이므로,
실행기가 출력한 `CHATOPS_BACKUP` 경로의 그 파일을
`/home/cloud/dr_project/chatops_core.py`에 복구한다. 그 후 승인된 절차로
Zabbix server 컨테이너와 ChatOps service만 각각 재생성/재시작한다. 이 절차는
이번에 실행하지 않았다. Online Backup 스냅샷은 보존 자료이며 코드·Sender·환경
롤백에 사용하지 않는다. SQLite를 과거 시점으로 복구하면 컷오버 이후의 승인,
취소 및 감사 기록이 사라질 수 있으므로 별도 사고 복구 승인 없이는 복원하지 않는다.

## 운영 적용을 막는 현재 조건

- HMAC 키가 두 런타임 파일에 아직 구성되지 않았고 `.env_srv` 권한이 넓다.
- 현재 파일의 관리자 ID 수(3)와 과거 유효 관리자 사전점검(1)이 불일치한다.
  실제 두 관리자 권한을 실행 경로에서 확인하기 전에는 승인 테스트를 진행하지 않는다.
- 실제 Zabbix sender 컨테이너의 환경 반영은 sudo Docker 접근 부재로 확인되지
  않았다.
- Action 3 필터와 메시지 메타데이터가 Canonical 계약과 다르다.
- Media Type 45 직접 테스트는 Action 필터를 검증하지 않는다. Broad Test Action은
  recovery에서 Failback 테스트를 호출하므로 현 범위에서는 사용할 수 없다.
- Trigger 24712는 OR 식인 채 비활성이고, 독립 Monitoring Path 입력/신호가
  없다. 이는 별도 Zabbix 정책 반영 전까지 운영 감지 경로를 차단한다.

따라서 현재 통합 운영 전환은 **NO-GO**다. 보고된 코드 테스트 PASS는 Slack
운영 전달 또는 실제 Failover 성공을 뜻하지 않는다.
