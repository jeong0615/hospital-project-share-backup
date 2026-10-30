# AWS Web·EMR 기동 및 NAT 검증 Runbook

이 문서는 별도 운영 승인 후 제한된 테스트 창에서만 사용한다. 작성 중 EC2 시작·중지, NAT/Route/SG/IAM 변경, DB 쓰기, DNS 변경은 수행하지 않았다. `full_failover.sh`와 `dr_environment_control.sh start`는 DB 승격, 앱 기동, DNS/DR 상태 변경을 포함하므로 이 독립 테스트에서 실행하지 않는다.

## 현재 기준선 (ap-northeast-2; 2026-10-17 읽기 전용 재확인)

| 역할 | EC2 / 상태 | VPC / Subnet / Private IP | ENI / 보안그룹 | SSM |
|---|---|---|---|---|
| Web + NAT 후보 | `AWS_RESOURCE_ID_REDACTED` / stopped | `AWS_RESOURCE_ID_REDACTED` / `AWS_RESOURCE_ID_REDACTED` / `AWS_PUBLIC_IP_REDACTED`; EIP `AWS_PUBLIC_IP_REDACTED` | `AWS_RESOURCE_ID_REDACTED`, `AWS_RESOURCE_ID_REDACTED`, Source/Dest Check=false | stopped라 Online 미요구. 시작 후 확인 필요 |
| EMR/Doc | `AWS_RESOURCE_ID_REDACTED` / stopped | 같은 VPC / `AWS_RESOURCE_ID_REDACTED` / `AWS_PUBLIC_IP_REDACTED`; 공인 IP 없음 | `AWS_RESOURCE_ID_REDACTED`, `AWS_RESOURCE_ID_REDACTED`, Source/Dest Check=true | stopped라 Online 미요구. Web을 통한 SSH 경로 사용 |
| DR DB | `AWS_RESOURCE_ID_REDACTED` / running | 같은 VPC / `AWS_RESOURCE_ID_REDACTED` / `AWS_PUBLIC_IP_REDACTED` | `AWS_RESOURCE_ID_REDACTED`, `AWS_RESOURCE_ID_REDACTED`, Source/Dest Check=true | 사용자가 제공한 상태. 현재 SSM/MySQL은 기동 승인된 현장에서 재확인 |

- Web subnet의 route table `AWS_RESOURCE_ID_REDACTED`는 IGW 기본경로가 active이며 Web EIP가 Web ENI에 연결돼 있다. EMR·DB subnet은 private route table `AWS_RESOURCE_ID_REDACTED`을 사용한다. 기본 `AWS_PUBLIC_IP_REDACTED/0` 및 `AWS_PUBLIC_IP_REDACTED/24`는 현재 Web ENI 대상 `blackhole`; NAT Gateway는 존재하지 않는다. 분리된 NAT EIP `AWS_PUBLIC_IP_REDACTED`는 할당돼 있지만 미연결이다.
- Web SG는 Cloudflare 출발지의 TCP 80/443 및 승인된 On-Prem IP의 UDP 51820을 허용하고 egress는 전체 허용이다. EMR SG는 Web SG로부터 TCP 22/80, DB SG는 Web/EMR SG로부터 TCP 3306을 허용한다. 기본 NACL은 양방향 허용 규칙이다. 이번에 SG/NACL은 변경하지 않았다.
- SSM interface endpoint `ssm`, `ssmmessages` 두 개는 available, DB subnet, Private DNS enabled다. 실제 Web instance role에는 `AmazonSSMManagedInstanceCore`가 연결돼 있으나 endpoint SG TCP 443 ingress는 DB SG만 허용하고 Web SG는 없다. Private DNS가 켜져 있어 Web의 private endpoint 경로는 현재 차단된다. Web이 stopped여서 SSM Online은 확인되지 않았다. 시작 전 endpoint SG에 Web SG source TCP 443을 승인된 최소 변경으로 추가하고, 시작 후 SSM Online을 readback해야 한다. SSH direct fallback은 허용하지 않는다. Canonical Terraform의 Web/EMR role과 운영 IAM 사이 차이는 별도 drift로 남는다. EMR은 기존 Web SSM jump 후 VPC 내부 TCP 22 경로를 사용하며 EMR 직접 SSM Online을 전제하지 않는다.
- 세 root EBS는 각 8 GiB gp2, unencrypted이며 EC2 종료 시 삭제 설정(`DeleteOnTermination=true`)이다. **stop/start는 디스크를 보존하지만 terminate하면 root volume이 삭제될 수 있으므로 terminate 금지.** 확인된 snapshot은 DB와 EMR에 각각 2026-09-12 생성본이 있고 Web root snapshot은 조회되지 않았다. 이번 점검에서 snapshot은 만들지 않았다.
- Web/EMR Ansible 배포는 Docker 컨테이너(`hospital-dr-web`, `hospital-dr-emr`)를 `--restart unless-stopped`로 실행한다. Docker는 enabled이며 Web은 nginx, EMR은 apache2 reverse proxy를 사용한다. 따라서 EC2 시작 시 Docker 및 기존 컨테이너가 자동 기동할 수 있다. 실제 부팅 readback 전에는 자동 기동을 확정하지 않지만 이를 예상 위험으로 취급한다. 호스트 앱 포트는 TCP 3000이다.
- `/__hospital_dr/health`는 Web/EMR 모두 DB `SELECT 1`을 확인하고 정상 HTTP 204, 실패 HTTP 503을 반환한다. `/api/patients`는 호출하지 않는다. 앱 DB endpoint 계약은 `AWS_PUBLIC_IP_REDACTED:3306`; SG 및 VPC local route로 경로는 구성돼 있지만 Web/EMR stopped라 앱 인증/실제 연결은 `PENDING_LIVE_TEST`다. 2026-10-17 DB SSM read-only 조회에서는 AWS DB 신원과 `read_only=ON`, `super_read_only=ON` 및 startup config를 확인했다.
- Web/EMR 앱에는 요청 경로를 통해 DB `INSERT`/`UPDATE`/`DELETE` 기능이 있다. 코드 검색으로 기동 시 DB 쓰기를 수행하는 background scheduler/cron은 발견되지 않았다(이것은 실환경 프로세스 전수 검증을 대체하지 않음). 앱 startup probe와 `/__hospital_dr/health`는 `SELECT`만 한다. 테스트 중 환자 API, 로그인/업무 쓰기 요청, 외부 사용 트래픽은 금지한다. 앱을 자동 기동하기 전 DR DB의 신원과 `read_only=ON`, `super_read_only=ON` 및 영구 설정을 읽기 전용으로 확인한다. 확인 불가면 앱을 시작하지 않고 `PENDING_DB`로 멈춘다.
- Web NAT Ansible role은 opt-in이며 `site.yml`에 포함되지 않는다. 실제 Web에 적용됐다는 live guest 증거는 아직 없다. Runtime SSM inventory 생성기는 `[web_servers]` 그룹만 만든다. NAT apply/disable playbook은 이 실제 그룹을 대상으로 하도록 정합화했다. Web 시작만으로 IP forwarding, systemd NAT service, iptables 규칙이나 실제 private egress가 준비됐다고 볼 수 없다. 분리 NAT EIP는 Web EIP와 별도이며 Web NAT Instance 경로에서는 사용하지 않는다. 현재 Web SG에는 Terraform NAT mode가 추가하는 private-subnet forwarding ingress가 없어, NAT final validation에는 별도 최소 SG rule 반영도 필요하다.

## NAT 2단계 판정

`operations/nat_instance/web_nat_instance_status.sh`는 AWS 제어면만 읽는다. Web ENI 대상 route가 active이고 Web이 running이어도 출력은 `CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE_CANDIDATE`, `NAT_INSTANCE_STATUS=PENDING_LIVE_TEST`, `NAT_BOOTSTRAP_STATUS=READY_FOR_GUEST_CONFIGURATION`다. 이것은 최종 READY가 아니다. Web이 stopped이고 기존 blackhole route가 정확히 Web ENI를 가리키면 `NAT_BOOTSTRAP_STATUS=READY_TO_START_WEB`만 뜻한다.

**Bootstrap 준비**는 Web 실행, 동일 Web ENI를 대상으로 한 active private route, Web guest forwarding 구성을 확인하는 단계다. **최종 READY**는 여기에 EMR에서의 실제 egress가 Web EIP `AWS_PUBLIC_IP_REDACTED`임을 더해 기존 `web_failover_preflight.sh` 또는 Failover Executor가 내는 `NAT_INSTANCE_STATUS=READY`, `CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE` 계약이다. AWS-only candidate나 `READY_TO_START_WEB`을 최종 READY로 표시하지 않는다.

전체 Failover Executor의 승인된 일반·긴급 공통 경로는 다음 순서로 처리한다: 2인 승인 및 요청별 RPO/기존 DR DB 데이터 확인 → DB 복구/승격 → Web만 시작 및 정확한 EC2 신원·SSM Online 확인 → AWS EIP/ENI/Source-Dest Check/active route readback → **기존 opt-in Ansible NAT 역할을 SSM transport로 `[web_servers]` 한정 적용** → Web guest persistence/rule readback 및 AWS 재확인 → EMR 시작 → EMR SSM 경유 관리 연결과 실제 Web EIP egress 검증 → 최종 NAT READY → Web/EMR 서비스·DB 연결 Health → Cloudflare DNS transaction/readback → 실제 공용 Health → `DR_ACTIVE` 및 Slack 결과. On-Prem writer 상태는 확인하지 않으며, 원본이 계속 쓰기 가능하면 split-brain 위험이 있다. NAT bootstrap candidate는 최종 READY가 아니며, 어느 단계든 실패하면 이후 단계로 가지 않는다.

NAT 역할은 `operations/finops/dr_environment_control.sh start`의 일반 Failover 실행에서만, DB 승격이 성공하고 persistent state가 `FAILOVER_EXECUTING`이며 현재 요청 ID가 유효한 경우 실행된다. 사전검사 및 `SKIP_DNS=true` preparation 경로는 이 역할을 호출하지 않는다. Controller는 Canonical playbook 경로, SSM SSH config, 정확히 하나의 `dr-web` inventory host, `--limit web_servers`, target EC2 ID, known_hosts 검증과 timeout을 검사한다. 역할은 Web에서 IMDSv2를 통해 EC2 ID/private IP/VPC/subnet/ENI를 다시 대조한 뒤에만 변경한다. 실패나 timeout은 `PARTIAL_FAILURE`로 남으며 자동 재실행하지 않는다.

역할은 `iptables`가 이미 설치되어 있는지 확인하며 패키지를 설치·제거하지 않는다. 변경 대상은 `/etc/sysctl.d/99-hospital-dr-web-nat.conf`, 전용 controller/systemd oneshot, 프로젝트 소유 두 iptables chain 및 런타임 `ip_forward`다. Apply 전에 기존 파일·소유권·권한·체크섬, 서비스 상태, 런타임 forwarding, firewall baseline을 private state에 기록한다. 정확히 같은 role-owned chains가 이미 있으면 재구성하지 않고, 불명확한 기존 chain이나 drift는 차단한다. Remove/실패 복구는 기록된 파일 체크섬과 runtime을 대조한 뒤 실제 변경분만 복원하며, 보존 백업도 SHA256/0600/root 소유를 확인한다. 다른 서비스 설정이나 공유 iptables 패키지를 제거하지 않는다. AWS route, ENI, Source/Dest Check, SG, IAM은 수정하지 않는다. 따라서 Web 부팅 뒤 route가 여전히 `blackhole`이면 role 전에 fail-closed 중단한다. 현재 확인된 route target은 기대 Web ENI지만 현재 state는 blackhole이며, 이 상태를 role이 자동 복구하지 않는다.

EMR 이미지/ECR pull 또는 apt 작업이 필요하면 NAT bootstrap이 먼저 끝나야 한다. NAT 역할/route/SG가 준비되지 않았다면 `PENDING_NETWORK_BOOTSTRAP`에서 중단한다. NAT Gateway 생성·재연결은 대안으로 쓰지 않고, `AWS_PUBLIC_IP_REDACTED/24`, VPC 내부 및 On-Prem 목적지 제외 규칙을 유지한다.

## 승인된 테스트 창에서의 절차

### 0. 시작 전 재확인 — 읽기 전용

```bash
set -euo pipefail
export AWS_REGION=ap-northeast-2
aws ec2 describe-instances --region "$AWS_REGION" \
  --instance-ids AWS_RESOURCE_ID_REDACTED AWS_RESOURCE_ID_REDACTED AWS_RESOURCE_ID_REDACTED \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Vpc:VpcId,Subnet:SubnetId,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,SourceDestCheck:SourceDestCheck,ENIs:NetworkInterfaces[].NetworkInterfaceId,Volumes:BlockDeviceMappings[].Ebs.VolumeId}' --output table
aws ec2 describe-instance-status --region "$AWS_REGION" --include-all-instances \
  --instance-ids AWS_RESOURCE_ID_REDACTED AWS_RESOURCE_ID_REDACTED AWS_RESOURCE_ID_REDACTED \
  --query 'InstanceStatuses[].{Id:InstanceId,State:InstanceState.Name,Instance:InstanceStatus.Status,System:SystemStatus.Status}' --output table
aws ec2 describe-route-tables --region "$AWS_REGION" --route-table-ids AWS_RESOURCE_ID_REDACTED \
  --query 'RouteTables[].Routes[].{CIDR:DestinationCidrBlock,State:State,ENI:NetworkInterfaceId,NAT:NatGatewayId}' --output table
AWS_REGION="$AWS_REGION" operations/nat_instance/web_nat_instance_status.sh || true
```

세 인스턴스 신원과 시작 전 상태를 기록한다. 예상과 다르거나 실행 중 DR workflow/lock이 있으면 취소한다. DB가 현재 running이라는 이유만으로 준비됐다고 보지 않는다. 앱 부팅 전에 기존 SSM SSH 경로로 DB identity, runtime read-only와 persisted read-only를 읽기 전용 조회한다. 아래는 이미 준비한 `dr-db` SSM alias를 사용하는 예이며, 값은 현장 readback으로 승인된 DB 신원과 대조한다.

```bash
set -euo pipefail
cd /home/cloud/hospital-dr-codex
source operations/runtime_paths.sh
source "$DR_SSM_SSH_HELPER"
dr_load_secret_file
dr_resolve_ssh_key_config
dr_validate_ssh_key_files
dr_prepare_ssh_known_hosts
dr_ssm_write_ssh_config "$AWS_REGION" AWS_RESOURCE_ID_REDACTED "$SSH_KEY" \
  "$DR_SSH_KNOWN_HOSTS_FILE" AWS_PUBLIC_IP_REDACTED AWS_PUBLIC_IP_REDACTED AWS_RESOURCE_ID_REDACTED
dr_ssm_wait_for_ssh "approved DR DB SSM" dr-db 18 5
dr_ssm_ssh dr-db 'sudo mysql --defaults-file=/etc/mysql/debian.cnf --batch --raw --skip-column-names -e \
"SELECT @@server_uuid,@@server_id,@@hostname,@@port,@@global.read_only,@@global.super_read_only; SELECT VARIABLE_NAME,UPPER(VARIABLE_VALUE) FROM performance_schema.persisted_variables WHERE VARIABLE_NAME IN (0x726561645f6f6e6c79,0x73757065725f726561645f6f6e6c79) ORDER BY VARIABLE_NAME; SELECT VARIABLE_NAME,VARIABLE_SOURCE,VARIABLE_PATH FROM performance_schema.variables_info WHERE VARIABLE_NAME IN (0x726561645f6f6e6c79,0x73757065725f726561645f6f6e6c79) ORDER BY VARIABLE_NAME"'
dr_ssm_ssh dr-db 'sudo my_print_defaults mysqld | grep -E "^--(read_only|super_read_only)="'
```

신원 불일치, MySQL 접근 실패, runtime 값 중 하나라도 `1`이 아님, 또는 지속 설정을 입증할 수 없으면 `PENDING_DB`로 멈추고 Web/EMR을 시작하지 않는다. 지속 설정은 `performance_schema.persisted_variables`의 두 값이 모두 `ON`이거나, 그 결과가 비어 있을 때 `performance_schema.variables_info`가 두 변수의 source/path를 명시하고 `my_print_defaults mysqld`에서 충돌 없이 두 값이 모두 `ON`임을 확인해야 한다. 설정 출처가 모호하거나 `OFF`가 하나라도 있으면 차단한다. 이 테스트는 읽기만 수행하고 DB를 writable로 만들지 않는다. 테스트 중 환자 API/업무 쓰기 요청 및 외부 사용자 트래픽은 허용하지 않는다.

### 1. Web만 시작 및 SSM 확인

아래는 **별도 AWS 기동 승인 이후에만** 실행한다. 이 단계는 DNS·DB·DR 상태를 바꾸지 않는다.

```bash
aws ec2 start-instances --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED \
  --query 'StartingInstances[].{Id:InstanceId,Previous:PreviousState.Name,Current:CurrentState.Name}' --output table
aws ec2 wait instance-running --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED
aws ec2 wait instance-status-ok --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED
aws ssm describe-instance-information --region "$AWS_REGION" \
  --filters Key=InstanceIds,Values=AWS_RESOURCE_ID_REDACTED \
  --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus,Agent:AgentVersion}' --output table
```

SSM Online이 아니면 direct SSH로 우회하지 않는다. 이후 점검용 SSH 설정은 기존 SSM helper와 known_hosts를 재사용한다.

```bash
cd /home/cloud/hospital-dr-codex
source operations/runtime_paths.sh
source "$DR_SSM_SSH_HELPER"
dr_load_secret_file
dr_resolve_ssh_key_config
dr_validate_ssh_key_files
dr_prepare_ssh_known_hosts
web_id="$(dr_ssm_discover_web_instance_id "$AWS_REGION" AWS_PUBLIC_IP_REDACTED)"
test "$web_id" = AWS_RESOURCE_ID_REDACTED
dr_ssm_write_ssh_config "$AWS_REGION" "$web_id" "$SSH_KEY" \
  "$DR_SSH_KNOWN_HOSTS_FILE" AWS_PUBLIC_IP_REDACTED AWS_PUBLIC_IP_REDACTED AWS_RESOURCE_ID_REDACTED
dr_ssm_write_ansible_inventory "$DR_ANSIBLE_DIR/inventory.ini" "$SSH_KEY" "$DR_SSH_CONFIG_FILE"
dr_ssm_wait_for_ssh "approved Web SSM" dr-web 18 5
```

Web 상태와 민감정보 없는 Health만 확인한다.

```bash
dr_ssm_ssh dr-web 'set -eu
sudo systemctl is-active docker nginx
sudo docker inspect --format "{{.State.Running}}|{{.State.Health.Status}}" hospital-dr-web
code=$(curl --silent --show-error --max-time 10 -o /dev/null -w "%{http_code}" http://IP_REDACTED:3000/__hospital_dr/health)
printf "WEB_HEALTH_HTTP=%s\n" "$code"
test "$code" = 204'
```

HTTP 503이면 DB 또는 앱 문제다. `PENDING_DB`로 기록하고 환자 API, 컨테이너 환경변수, SQL 로그를 덤프하지 않는다. 컨테이너가 없거나 이미지가 필요하다는 이유로 이 테스트에서 Ansible app deployment/ECR pull을 실행하지 않는다.

### 2. NAT bootstrap — EMR보다 먼저

```bash
set +e
nat_output="$(AWS_REGION="$AWS_REGION" operations/nat_instance/web_nat_instance_status.sh 2>&1)"
nat_rc=$?
set -e
printf '%s\n' "$nat_output"
printf 'NAT_CONTROLLER_EXIT=%s\n' "$nat_rc"
test "$nat_rc" -eq 2
grep -qx 'CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE_CANDIDATE' <<< "$nat_output"
grep -qx 'NAT_INSTANCE_STATUS=PENDING_LIVE_TEST' <<< "$nat_output"
grep -qx 'NAT_BOOTSTRAP_STATUS=READY_FOR_GUEST_CONFIGURATION' <<< "$nat_output"
```

이 결과는 AWS 상태상 후보라는 뜻일 뿐 최종 READY가 아니다. 여기서 route가 active가 아니거나 ENI target이 `AWS_RESOURCE_ID_REDACTED`와 다르면 EMR을 시작하지 않는다. Web EIP가 Web ENI에 붙어 있고 Source/Dest Check=false인지, Web SG가 승인된 private CIDR forwarding을 허용하는지, subnet NACL이 왕복 트래픽을 막지 않는지 읽기 전용으로 확인한다. NAT SG 범위가 불명확하면 현장 확인을 요청하고 열지 않는다.

```bash
set -euo pipefail
aws ec2 describe-addresses --region "$AWS_REGION" --public-ips AWS_PUBLIC_IP_REDACTED \
  --query 'Addresses[].{PublicIP:PublicIp,Instance:InstanceId,ENI:NetworkInterfaceId,Association:AssociationId}' --output table
aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids AWS_RESOURCE_ID_REDACTED \
  --query 'SecurityGroups[].{GroupId:GroupId,Ingress:IpPermissions,Egress:IpPermissionsEgress}' --output json
aws ec2 describe-network-acls --region "$AWS_REGION" \
  --filters Name=association.subnet-id,Values=AWS_RESOURCE_ID_REDACTED,AWS_RESOURCE_ID_REDACTED \
  --query 'NetworkAcls[].{AclId:NetworkAclId,Entries:Entries,Associations:Associations}' --output json
dr_ssm_ssh dr-web 'set -eu
printf "NAT_SERVICE_ENABLED="; systemctl is-enabled hospital-dr-web-nat.service 2>/dev/null || true
printf "NAT_SERVICE_ACTIVE="; systemctl is-active hospital-dr-web-nat.service 2>/dev/null || true
printf "IP_FORWARD="; sysctl -n net.ipv4.ip_forward 2>/dev/null || true
ip -4 route show
sudo iptables -S HOSPITAL-DR-NAT-FWD 2>/dev/null || true
sudo iptables -t nat -S HOSPITAL-DR-NAT-POSTROUTING 2>/dev/null || true
if sudo test -x /usr/local/sbin/hospital-dr-web-nat-instance; then sudo /usr/local/sbin/hospital-dr-web-nat-instance verify; else echo NAT_GUEST_STATUS=NOT_INSTALLED; fi'
```

아래 수동 role 점검/apply 절차는 **분리된 AWS-only 테스트에 대해 별도 승인을 받은 경우에만** 사용한다. 전체 Failover 경로에서는 운영자가 role을 따로 실행하지 않는다. Executor가 승인·Fence·DB 승격 이후 자동 호출하고 실패를 기록한다. 이 runbook에서는 먼저 무변경 check-mode를 실행한다.

```bash
ansible-playbook -i "$DR_ANSIBLE_DIR/inventory.ini" \
  automation/ansible/aws_web_nat_instance.yml --limit web_servers --check --diff \
  -e aws_web_nat_instance_enabled=true -e aws_web_nat_instance_action=apply
```

`--check`에서 host identity, role defaults, 변경 diff 및 privilege 조건을 검토한다. 분리된 AWS-only 테스트에서의 실제 apply는 **그 테스트에 대한 별도 운영 승인을 받은 경우에만** 실행한다:

```bash
AWS_WEB_NAT_INSTANCE_ENABLED=true ansible-playbook -i "$DR_ANSIBLE_DIR/inventory.ini" \
  automation/ansible/aws_web_nat_instance.yml --limit web_servers \
  -e aws_web_nat_instance_enabled=true -e aws_web_nat_instance_action=apply
```

이 role은 `iptables`가 사전 설치돼 있는지 확인하되 설치하지 않고, `/etc/sysctl.d/99-hospital-dr-web-nat.conf`에 `ip_forward=1` 기록, 전용 controller와 systemd oneshot 설치, role-owned chain 적용 및 부팅 시 활성화를 수행한다. `site.yml`은 이 role을 호출하지 않는다. Apply 전 root 전용 baseline을 보존하며, remove는 checksum·runtime drift가 없을 때만 기존 파일·mode·uid/gid·서비스 active/enabled 상태·`ip_forward`와 firewall baseline을 복구한다. firewall baseline이 원래 absent였으면 정확히 role이 만든 chain만 제거하고, baseline이 exact였으면 그대로 보존한다. `iptables`는 공유 패키지이므로 제거하지 않는다. `site.yml`은 이 role을 호출하지 않는다. 이 role은 route/SG를 바꾸지 않으며 이를 보완하지도 않는다. Apply 후 아래 게스트 검증과 AWS route readback을 재수행한다.

```bash
dr_ssm_ssh dr-web 'sudo /usr/local/sbin/hospital-dr-web-nat-instance verify'
```

`NAT_GUEST_STATUS=READY`가 정확히 한 번 나오고 명령 종료 코드가 0이어야 한다. Role의 systemd service는 enabled `multi-user.target` oneshot이며 부팅 시 project-owned NAT 규칙을 재적용한다. sysctl 파일은 WireGuard와 forwarding을 공유할 수 있으므로 role이 임의로 제거하지 않는다. Remove는 apply 전에 기록한 원래 sysctl 내용과 런타임 값을 복구하며, baseline이 없거나 drift/백업 무결성 오류가 있으면 차단하고 baseline을 보존한다. role이 원래 없던 NAT chain만 소유권 표식과 정확한 ruleset이 모두 확인될 때 제거한다. 이 작업이 AWS route를 원복하지는 않는다.


Web guest `READY`와 정확한 active route가 확인되면 NAT bootstrap은 완료 후보이며 EMR 시작을 허용할 조건이 갖춰진다. 최종 NAT READY는 아직 아니다. `doc_deploy`는 apt와 ECR `docker pull`을 수행하므로 EMR 컨테이너/이미지가 없거나 재배포 필요 시 이 bootstrap을 먼저 완료해야 한다. 기존 이미지/컨테이너가 있는지는 EMR 부팅 후 read-only `docker inspect`로 확인한다. 없고 bootstrap이 미완료면 `PENDING_NETWORK_BOOTSTRAP`으로 중단한다.

### 3. EMR 시작 및 앱 검증 — NAT bootstrap 확인 뒤

DB 사전 확인, Web SSM/Health 및 NAT guest/route 설정 확인이 통과한 경우에만, 별도 승인 아래 EMR을 시작한다. EMR 기동 후 기존 컨테이너와 이미지가 없는 것으로 확인되면 Ansible 배포를 즉시 실행하지 말고 위의 NAT-before-ECR 조건을 먼저 만족시킨다.

```bash
aws ec2 start-instances --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED \
  --query 'StartingInstances[].{Id:InstanceId,Previous:PreviousState.Name,Current:CurrentState.Name}' --output table
aws ec2 wait instance-running --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED
aws ec2 wait instance-status-ok --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED
dr_ssm_wait_for_ssh "EMR through Web SSM jump" dr-doc 18 5
```

```bash
dr_ssm_ssh dr-doc 'set -eu
sudo systemctl is-active docker apache2
sudo docker inspect --format "{{.State.Running}}|{{.State.Health.Status}}" hospital-dr-emr
code=$(curl --silent --show-error --max-time 10 -o /dev/null -w "%{http_code}" http://IP_REDACTED:3000/__hospital_dr/health)
printf "EMR_HEALTH_HTTP=%s\n" "$code"
test "$code" = 204'
```

204는 DB `SELECT 1`까지 성공했다는 뜻이다. 503, SSM/SSH 실패, EC2 status check 실패 시 다음 단계와 DNS 변경 없이 안전 중단한다.

### 4. 최종 NAT readiness — EMR 실제 송신 검증 뒤

```bash
dr_ssm_ssh dr-doc 'curl --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com/'
bash operations/runtime/web_failover_preflight.sh
```

첫 명령의 결과에서 `AWS_PUBLIC_IP_REDACTED`만 확인한다. Read-only preflight에는 다른 차단 항목이 있을 수 있다. 그 결과에 `READY: WEB_NAT_INSTANCE_RUNNER_GATE`와 `NAT_INSTANCE_STATUS=READY`, `CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE`가 있을 때만 기존 최종 NAT 계약을 통과한 것이다. `web_nat_instance_status.sh` 자체는 최종 READY를 출력하지 않으며 계속 `PENDING_LIVE_TEST`/`WEB_NAT_INSTANCE_CANDIDATE`를 출력하는 것이 정상이다. EMR egress가 다르거나 실패하면 DNS를 건드리지 않고 중단한다. 이 작업에서는 route 변경이 승인되지 않았으며, route 복구/변경은 `docs/runbooks/NAT_INSTANCE_MIGRATION.md`의 저장 plan/guard를 별도 승인받아야 한다.

## 실패·종료와 비용

- 시작 전 상태와 비교해 이번에 시작한 EC2만 역순으로 정리한다: EMR 먼저, 그다음 Web. DB는 이번 작업에서 시작/중지하지 않는다(현재 기준 running). 기존에 running이던 인스턴스는 중지하지 않는다.
- DNS, Terraform, route, SG, IAM, DB, Zabbix는 변경하지 않는다. NAT Ansible role 또는 route를 별도 승인으로 적용했다면 이 일반 종료 절차만으로 원래 상태가 되지 않는다. 기존 NAT rollback 문서를 따르고 변경별 readback을 수행한다. Route rollback 전에 Web을 먼저 중지하면 blackhole이 될 수 있으므로 검토 없이 rollback 순서를 바꾸지 않는다.
- 원래 stopped였던 Web/EMR의 테스트 종료 명령(별도 stop 승인 필요):

```bash
aws ec2 stop-instances --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED AWS_RESOURCE_ID_REDACTED \
  --query 'StoppingInstances[].{Id:InstanceId,Previous:PreviousState.Name,Current:CurrentState.Name}' --output table
aws ec2 wait instance-stopped --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED AWS_RESOURCE_ID_REDACTED
```

- 비용 항목: 실행 중 Web/EMR EC2 시간, 공인 IPv4/EIP 사용료, outbound/data-transfer 및 이미지 다운로드, 계속 보유 중인 EBS storage, 이미 생성돼 있는 SSM interface endpoint 시간/데이터 비용. NAT Gateway는 현재 없어 새 비용을 만들지 않는다. 정확한 단가는 승인된 테스트 시점의 서울 리전 요금으로 계산한다. 인스턴스를 terminate하지 않으며 EIP를 해제하지 않는다.

## 현재 실행 판정

이번 읽기 전용 AWS 상태는 리소스 신원 일치, Web/EMR stopped, DB EC2 running, Web EIP가 정확한 Web instance/ENI/private IP에 연결됨, Source/Dest Check=false, private default route와 `AWS_PUBLIC_IP_REDACTED/24` route가 기대 Web ENI를 대상으로 하지만 `blackhole`임을 확인했다. Web/EMR SSM 세션, 컨테이너, 앱 DB 연결/HTTP 204, Web guest NAT rules 및 private egress는 `PENDING_LIVE_TEST`; DB 런타임 및 시작 시 read-only 설정은 현장 SSM 조회로 확인했지만 Web/EMR 애플리케이션 경로는 검증되지 않았다. Web/EMR 시작은 외부 트래픽/egress 격리 및 SSM endpoint SG 사전조건을 별도 승인으로 해결하기 전까지 차단한다.

전체 Failover 실기동은 Runbook의 순차 시작 절차와 별개로 Slack의 기존 일반 또는 긴급 2인 승인 경로로만 시작한다. 두 진입점은 같은 `operations/failover/full_failover.sh` 및 `dr_environment_control.sh start` 경로를 사용한다. Executor가 DB 승격 이후 Web NAT 역할을 자동 적용하고, EMR 실제 egress 및 최종 READY를 앱 Health와 DNS보다 먼저 요구한다. 다만 지금 확인된 blackhole route는 Web을 시작한 뒤에도 `active`로 readback될 때까지 차단 조건이며, guest NAT 설정은 실기동 전까지 미검증이다. 별도 AWS-only 기동 점검은 실제 Failover와 구분하고, DNS/DR state를 변경하는 full Failover와 혼용하지 않는다.

## 2026-10-17 Web-only Canary 추가 안전 점검

아래 읽기 전용 결과가 이전 기준선보다 최신이다. 이 절의 차단 조건이 해결되기 전에는 이 문서 앞부분의 기동 명령을 실행하지 않는다.

- 현재 상태: Web `stopped`, EMR `stopped`, DB `running`; Web `AWS_RESOURCE_ID_REDACTED` / `t3.micro`, Web EIP `AWS_PUBLIC_IP_REDACTED`가 예상 ENI에 연결됨, `SourceDestCheck=false`. private `AWS_PUBLIC_IP_REDACTED/0` 및 `AWS_PUBLIC_IP_REDACTED/24`는 Web ENI 대상이지만 현재 `blackhole`; NAT 상태 스크립트는 `CURRENT_EGRESS_MODE=BLACKHOLE`, `NAT_INSTANCE_STATUS=PENDING_LIVE_TEST`, `NAT_BOOTSTRAP_STATUS=READY_TO_START_WEB`를 반환한다. 이는 시작 승인이나 최종 NAT READY가 아니다.
- 외부 트래픽: Web 보안그룹은 Cloudflare CIDR에서 TCP 80/443 인바운드를 허용한다. EIP가 붙은 채 Web이 부팅하면 Cloudflare edge에서 Web에 도달할 가능성이 있으므로 외부 트래픽 격리는 `BLOCKED`다. Cloudflare GET readback에서 `hospital-web.pp.ua`는 proxied CNAME `e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com`, `emr.hospital-web.pp.ua`는 proxied A `AWS_PUBLIC_IP_REDACTED`이다. 이는 현재 레코드가 Web EIP를 직접 가리키지 않음을 보여주지만, Tunnel ingress/origin 상세 설정은 확인되지 않아 AWS Web으로의 우회 전달이 없다고 증명하지 않는다. DNS를 유지하는 것만으로 격리된다고 판정하지 않는다.
- DB: SSM SSH를 통해 DB에서 읽기 전용 조회를 수행했다. 현재 `server_uuid=a7988d84-5be8-11f1-bb28-0a4b1b977fad`, `server_id=20`, `port=3306`, `read_only=1`, `super_read_only=1`. `persisted_variables`는 두 항목 모두 row가 없지만 `variables_info`는 둘 다 `GLOBAL` source와 `/etc/mysql/mysql.conf.d/z-hospital-dr-standby.cnf`를 반환했고, mysqld의 startup defaults는 두 설정 모두 `ON`(중복 정의도 모두 ON)이다. 이로써 현재 AWS DB의 런타임 및 시작 시 read-only 설정은 확인됐다. Web/EMR 애플리케이션 설정은 `AWS_PUBLIC_IP_REDACTED:3306`; VPC local 경로와 DB SG에서 Web/EMR SG 출발 TCP 3306이 허용된다. 따라서 앱은 DB에 도달할 네트워크 경로가 구성돼 있지만, 두 인스턴스가 stopped이므로 앱 인증/실제 연결은 미검증이다. DB read-only 상태에서 DML은 거부되어야 한다.
- 부팅 동작: Canonical Ansible은 Docker를 `enabled`, Web Nginx와 EMR Apache도 `enabled`로 설정하고 앱 컨테이너는 `--restart unless-stopped`로 만든다. 따라서 이전에 실행 중이던 컨테이너는 EC2 재부팅 후 자동 시작할 수 있다. 애플리케이션 코드에서 주기적 writer/scheduler는 발견되지 않았으나 실제 게스트의 timers/crontab은 stopped 상태라 `UNVERIFIED`다. WireGuard는 일반 `site.yml` 경로에 포함되지 않고 별도 opt-in playbook만 서비스를 시작/enable한다. 실제 Web의 현재 서비스 enable 상태는 아직 읽을 수 없다. 서비스가 없거나 자동 시작하지 않는다고 가정하지 않는다.
- SSM: Web instance profile의 역할에는 `AmazonSSMManagedInstanceCore`가 연결돼 있다. `ssm`/`ssmmessages` Interface Endpoint는 available 및 Private DNS enabled지만 endpoint SG `AWS_RESOURCE_ID_REDACTED`의 TCP 443 ingress는 DB SG만 허용한다. Web SG는 허용되지 않았다. 따라서 현재 private endpoint 경로의 Web SSM 접근은 차단된 구성이다. Web은 stopped라 SSM Online 상태도 아직 확인할 수 없다.
- NAT forwarding SG: 실제 Web SG에는 private subnet source의 forwarding ingress가 없다. Canonical Terraform은 `aws_web_nat_instance_enabled=true`일 때만 Web SG에 protocol `-1` ingress를 `AWS_PUBLIC_IP_REDACTED/24`, `AWS_PUBLIC_IP_REDACTED/24`, `AWS_PUBLIC_IP_REDACTED/24`로 추가한다. 현재 opt-in 규칙은 운영에 반영되지 않았다. Web NAT Ansible role은 AWS SG를 변경하지 않으므로, Web guest role만 적용해도 EMR/DB subnet의 forwarded packet은 현재 SG에서 허용되지 않으며 최종 NAT READY를 기대할 수 없다.
- DB 쓰기 차단: DB의 런타임과 시작 설정이 모두 read-only이므로 현재 DB 데이터 쓰기는 차단된 것으로 확인된다. 그러나 앱이 시작되면 DB에 읽기 요청을 할 수 있고 사용자 기능의 DML 경로도 존재한다. DB read-only는 외부 사용자 트래픽 격리의 대체가 아니다.

### 이전 Canary 변경안 (SUPERSEDED — 실행 금지)

> 아래의 기존 Web SG 직접 규칙 변경안과 수동 `start-instances` 절차는 2026-10-17 격리 검토에서 대체됐다. 기존 Web SG 규칙을 비우거나 egress를 편집하지 않는다. 아래 명령도 실행하지 말고, 문서 끝의 **별도 Canary SG 자동화**만 사용한다.

1. Web SG는 Web ENI 한 곳에만 부착된 것으로 확인했다. 이 SG의 **모든 ingress** (Cloudflare TCP 80/443과 On-Prem UDP 51820 포함)를 Canary 동안 비우고 기존 규칙 전체를 별도 보관한다. 이는 직접 Cloudflare edge뿐 아니라 게스트에서 자동 시작할 수 있는 WireGuard 진입도 막는다. 종료 시 Web stopped를 확인한 뒤 원본 규칙 전체와 정확히 대조해 복원한다.
2. Web SG의 egress는 Canary 첫 부팅 동안 SSM endpoint SG `AWS_RESOURCE_ID_REDACTED`로 TCP 443, AWS DB SG `AWS_RESOURCE_ID_REDACTED`로 TCP 3306만 허용하도록 제한한다. 이로써 SSM과 read-only DB Health만 허용하고, 게스트에서 시작될 수 있는 Cloudflare reverse tunnel/기타 public egress는 막는다. VPC DNS resolver는 AWS 제공 resolver 경로를 사용한다. 이 제한 중에는 ECR pull, apt 및 public egress 검사를 수행하지 않는다.
3. SSM endpoint SG에는 TCP 443 source `AWS_RESOURCE_ID_REDACTED` (Web SG) 허용을 추가해야 Web instance profile로 관리 세션을 열 수 있다. 범위는 해당 Web SG로 한정하고 DB SG 기존 규칙은 유지한다.
4. 제한된 egress 상태에서 SSM으로 Web identity, enabled/active services, Docker restart policy, timers/cron 존재 여부(명령 내용·환경값은 출력하지 않음), cloudflared/WireGuard 프로세스와 NAT 설정을 먼저 확인한다. 예상하지 못한 tunnel 또는 writer 작업이 있으면 egress를 열지 말고 Canary를 중단한다. 이상이 없을 때만 별도 승인을 받아 Web SG의 원래 public egress를 시험 구간 동안 복원해 Web의 단일 HTTPS egress probe를 한다. Web ingress는 계속 비운다.
5. Full NAT readiness를 시연할 별도 작업에서는 Canonical Terraform의 private-source all-protocol ingress 규칙을 검토·승인해 적용해야 한다. 출발지는 위 세 DR subnet CIDR로 한정하며 `AWS_PUBLIC_IP_REDACTED/0` ingress는 금지한다. 이 규칙은 이번 Web-only Canary에서 추가하지 않는다.
6. Web CNAME의 Tunnel ingress/origin 설정은 DNS GET만으로 확인할 수 없다. Tunnel origin이 Web EIP/private IP를 가리키지 않는지 권한 있는 읽기 전용 경로로 확인하거나, 해당 전달 경로를 별도 승인으로 차단해야 한다. 확인 전에는 `EXTERNAL_USER_ISOLATION=UNVERIFIED`로 두며, 보안그룹만으로 모든 Tunnel 경로가 격리된다고 단정하지 않는다.
7. 위 변경 승인 전까지 EC2 Start와 NAT role apply는 금지한다. DB는 변경하지 않는다. 시작 직전에도 DB identity/runtime read-only/startup source를 읽기 전용으로 재확인한다.

### 이전 승인 후 Web-only 명령 (SUPERSEDED — 실행 금지)

> 이 절의 수동 시작/중지 명령은 격리 SG가 적용되지 않은 상태에서 실행하면 안 된다. 현재 승인된 준비 도구가 격리 SG 적용, EC2 시작, SSM 점검, 중지 및 SG 원복을 한 실행 경로로 수행한다. 아래 명령은 참고 이력일 뿐 실행 절차가 아니다.

이 명령들은 준비용이다. 현재 조건에서는 실행하지 말고, 격리 변경의 별도 승인·readback 후에만 진행한다. 테스트 제한시간은 최대 30분이며 Web 외 다른 EC2는 변경하지 않는다.

```bash
set -euo pipefail
export AWS_REGION=ap-northeast-2
WEB_ID=AWS_RESOURCE_ID_REDACTED
aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$WEB_ID" \
  --query 'Reservations[0].Instances[0].{Id:InstanceId,State:State.Name,ENI:NetworkInterfaces[0].NetworkInterfaceId,EIP:NetworkInterfaces[0].Association.PublicIp}' --output table
aws ec2 start-instances --region "$AWS_REGION" --instance-ids "$WEB_ID" \
  --query 'StartingInstances[].{Id:InstanceId,Previous:PreviousState.Name,Current:CurrentState.Name}' --output table
aws ec2 wait instance-running --region "$AWS_REGION" --instance-ids "$WEB_ID"
aws ec2 wait instance-status-ok --region "$AWS_REGION" --instance-ids "$WEB_ID"
aws ssm describe-instance-information --region "$AWS_REGION" \
  --filters Key=InstanceIds,Values="$WEB_ID" \
  --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus,Agent:AgentVersion}' --output table
```

SSM이 `Online`이 아니면 바로 중단한다. SSH direct fallback, SG/route 수정, NAT role apply로 우회하지 않는다. SSM Online인 경우에만 기존 helper를 통해 Web identity, Docker/Nginx 상태, 컨테이너 metadata, 로컬 health (`/__hospital_dr/health`, 기대 HTTP 204)와 guest NAT 상태를 읽는다. 환자 API 및 업무 쓰기 요청은 호출하지 않는다. 시작 이후 route가 정확한 Web ENI 대상으로 `active`가 아니면 NAT apply나 EMR 시작 없이 중단한다.

SSM 세션에서 Web의 IMDSv2 identity도 실제 대상과 대조한다. 토큰은 원격 셸 메모리에서만 사용하고 출력하지 않는다:

초기 restricted-egress 상태에서 예상하지 못한 부팅 작업이 없는지 내용/환경값을 노출하지 않고 목록만 읽는다. cloudflared, WireGuard, app 관련 활성 서비스/timer 또는 cron job이 있으면 public egress를 열지 말고 중단한다:

~~~bash
dr_ssm_ssh dr-web 'set -eu
systemctl list-units --type=service --state=active --no-legend --no-pager \
  | awk "{print \$1}" | grep -Ei "cloudflared|wireguard|wg-quick|hospital-dr|pm2|docker|nginx" || true
systemctl list-unit-files --type=timer --state=enabled --no-pager --no-legend \
  | awk "{print \"ENABLED_TIMER=\" \$1}"
systemctl list-timers --all --no-legend --no-pager \
  | awk "{for (i=1;i<=NF;i++) if (\$i ~ /\\.timer$/) print \"SCHEDULED_TIMER=\" \$i}"
for user in root ubuntu; do
  count=$(crontab -l -u \"$user\" 2>/dev/null | awk \"!/^[[:space:]]*(#|$)/ {n++} END {print n+0}\")
  printf \"CRON_JOB_COUNT_%s=%s\\n\" \"$user\" \"$count\"
done
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  -maxdepth 1 -type f ! -name .placeholder -printf \"CRON_FILE=%f\\n\" 2>/dev/null || true
docker ps --format \"CONTAINER={{.Names}}|{{.State}}|{{.Status}}\"
if pgrep -x cloudflared >/dev/null; then echo CLOUDFLARED_PROCESS=PRESENT; else echo CLOUDFLARED_PROCESS=ABSENT; fi'
~~~

~~~bash
dr_ssm_ssh dr-web 'set -eu
token=$(curl --fail --silent --show-error --max-time 3 -X PUT \
  http://IP_REDACTED/latest/api/token \
  -H X-aws-ec2-metadata-token-ttl-seconds:60)
trap "unset token" EXIT
iid=$(curl --fail --silent --show-error --max-time 3 \
  -H "X-aws-ec2-metadata-token: $token" \
  http://AWS_PUBLIC_IP_REDACTED/latest/meta-data/instance-id)
ip=$(curl --fail --silent --show-error --max-time 3 \
  -H "X-aws-ec2-metadata-token: $token" \
  http://IP_REDACTED/latest/meta-data/local-ipv4)
printf "IMDS_INSTANCE_ID=%s\\nIMDS_PRIVATE_IP=%s\\n" "$iid" "$ip"
test "$iid" = AWS_RESOURCE_ID_REDACTED
test "$ip" = IP_REDACTED'
~~~

NAT role은 별도 승인 대상이다. 먼저 기존 check-mode를 사용한다:

```bash
ansible-playbook -i "$DR_ANSIBLE_DIR/inventory.ini" \
  automation/ansible/aws_web_nat_instance.yml --limit web_servers --check --diff \
  -e aws_web_nat_instance_enabled=true -e aws_web_nat_instance_action=apply
```

실제 apply는 이 Web-only Canary에 대한 별도 승인 후에만 위 “승인된 테스트 창” section의 기존 Apply 명령으로 수행한다. Role은 Web 게스트 NAT 서비스/sysctl/전용 iptables chain을 영구 변경하고 자동 rollback하지 않는다. Apply 후 guest verify와 route readback이 모두 통과하지 않으면 EMR을 시작하지 않는다. 이 Web-only Canary는 EMR egress가 확인되지 않으므로 `NAT_INSTANCE_STATUS=READY` 또는 최종 NAT READY를 판정할 수 없다.

처음 Web이 `stopped`였고 테스트에서만 시작했으며 route/NAT 변경을 하지 않았을 때, 테스트 종료는 Web 한 대만 stopped로 복구한다:

```bash
aws ec2 stop-instances --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED \
  --query 'StoppingInstances[].{Id:InstanceId,Previous:PreviousState.Name,Current:CurrentState.Name}' --output table
aws ec2 wait instance-stopped --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED
aws ec2 describe-instances --region "$AWS_REGION" --instance-ids AWS_RESOURCE_ID_REDACTED \
  --query 'Reservations[0].Instances[0].{Id:InstanceId,State:State.Name,ENI:NetworkInterfaces[0].NetworkInterfaceId,EIP:NetworkInterfaces[0].Association.PublicIp}' --output table
```

NAT role을 실제 Apply했거나 route 상태가 변경된 경우에는 이 단순 stop을 적용하기 전에 별도의 rollback 계획을 검토한다. 기존 route target을 중지하면 다시 blackhole이 된다. 현재 role의 remove는 apply 시점 baseline과 guest drift를 확인해 변경한 sysctl/controller/service/firewall만 원복하며, `iptables` package는 건드리지 않는다. baseline이 없거나 checksum/runtime가 달라졌으면 덮어쓰지 않고 BLOCKED로 남긴다. AWS route는 role이 수정하지 않으므로 별도 AWS snapshot/readback 절차가 필요하다. DB는 절대 stop하지 않는다.

Web egress probe는 원래 public egress를 별도 승인으로 복원하고 부팅 작업 검사에 이상이 없을 때만 수행한다. 이는 Web 자체가 EIP를 통해 외부로 나갈 수 있음을 확인할 뿐, EMR의 private-subnet forwarding/NAT를 증명하지 않는다. 결과는 승인된 변경 기록에 남기고 응답 본문은 저장하지 않는다:

~~~bash
egress_ip=$(dr_ssm_ssh dr-web 'curl --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com/')
test "$egress_ip" = IP_REDACTED
printf 'WEB_EGRESS_VIA_EIP=PASS\n'
printf 'WEB_NAT_BOOTSTRAP_CHECKED_AT_UTC=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
AWS_REGION=ap-northeast-2 operations/nat_instance/web_nat_instance_status.sh
~~~

### 비용 메모

Web은 `t3.micro` Linux다. 이번 Read-only 준비 시 AWS Price List API의 Seoul/Linux On-Demand 항목에서 컴퓨트 요금 `$0.013/시간`을 확인했다(30분 약 `$0.0065`; 계약·할인·Free Tier 제외). 공인 IPv4는 AWS VPC 가격표 기준 `$0.005/시간`이다. 기존 EIP는 인스턴스가 stopped일 때에도 이미 연결된 상태로 과금될 수 있으므로 이를 Canary의 추가 비용으로 계산하지 않는다. 단순 30분 귀속 추정은 컴퓨트 `$0.0065`와 기존 IPv4 사용료 약 `$0.0025`를 합해 `$0.009`이며, 실제 증분은 대체로 컴퓨트·전송량이고 기존 EBS/SSM endpoint 비용은 계속 발생한다. [AWS Price List 가격 조회 기준](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/finding-prices-in-service-price-list-files.html), [AWS VPC 공인 IPv4 가격](https://aws.amazon.com/vpc/pricing/). 테스트 종료 후 NAT/route/SG/EIP를 삭제하거나 해제하지 않는다.

## 2026-10-17 별도 Canary SG 자동화 — 현재 유일한 승인 후 절차

이 절차는 Web 한 대의 격리 기동만 수행하며 Failover/NAT 설정 적용이 아니다. 이 작업에서는 AWS 변경을 수행하지 않았다. 아래 `--run-canary`는 별도 운영 승인 후 MSP에서만 실행한다.

### 고정 격리 계약

- 새 임시 SG만 생성한다. 기존 Web SG `AWS_RESOURCE_ID_REDACTED` 및 그 규칙은 편집하지 않는다.
- 임시 SG 인바운드: **없음**.
- 임시 SG 아웃바운드: 실제 `ssm` 및 `ssmmessages` VPC Endpoint SG를 대상으로 하는 TCP 443만 허용한다. `ec2messages` Endpoint가 조회되면 해당 Endpoint SG도 포함한다. 생성 직후 AWS 기본 allow-all egress를 제거하고 readback한 뒤에만 Endpoint 443 규칙을 추가한다.
- 기존 Endpoint SG `AWS_RESOURCE_ID_REDACTED`에는 Canary SG 출발 TCP 443 규칙만 추가한다. 기존 DB SG 허용 규칙은 보존한다.
- Web ENI `AWS_RESOURCE_ID_REDACTED`의 연결 SG 목록을 기록한 후 Canary SG 하나로 **교체**한다. 기존 SG를 추가 연결하지 않는다. readback에서 기존 Web SG가 남아 있거나 다른 ENI가 바뀌면 중단한다.
- TCP 3306, 일반 인터넷, Cloudflare Tunnel egress, WireGuard egress는 임시 SG에 허용되지 않는다. 인바운드가 없으므로 EIP `AWS_PUBLIC_IP_REDACTED`로 직접 들어오는 사용자 트래픽도 SG에서 차단된다. Web 정지 상태에서 시작하므로 기존 연결 추적 상태도 재사용하지 않는다.
- Route/ENI/NACL, DB, DNS, Web/EMR 서비스 설정은 변경하지 않는다. NAT Ansible 역할은 적용하지 않는다.

### 현재 Read-only 상태

- Web은 고정 ID/VPC/Subnet/ENI/EIP와 일치하고 `stopped`; ENI에는 기존 Web SG 하나가 연결돼 있다.
- `ssm` (`vpce-04d79c4ec6d2a61e5`) 및 `ssmmessages` (`vpce-071a0a6fda4b8d0e8`)는 `available`, Private DNS 활성, Endpoint SG는 양쪽 모두 `AWS_RESOURCE_ID_REDACTED`다. 두 Endpoint ENI는 DB Subnet에 있고, Endpoint SG는 이 두 ENI에만 연결돼 있다.
- 현재 Endpoint SG TCP 443 ingress는 DB SG `AWS_RESOURCE_ID_REDACTED`만 허용한다. Canary SG를 허용하는 별도 규칙이 아직 없다. 승인 실행 시 도구가 임시 Canary SG만 추가한다.
- VPC DNS support/hostnames는 모두 켜져 있고 DHCP DNS는 `AmazonProvidedDNS`; Web과 Endpoint Subnet은 같은 VPC local route를 사용한다. 현재 연결된 NACL은 양방향 allow-all이다. Web role에는 `AmazonSSMManagedInstanceCore`가 연결돼 있다.
- AWS 보안그룹/NACL은 Route 53 VPC Resolver(`AmazonProvidedDNS`)로 향하는 DNS 질의를 차단할 수 없다. 따라서 이 격리의 “egress only”는 SG/NACL 데이터 경로 기준이며 DNS resolver 질의는 AWS 예외다. DNS 이름 기반 유출까지 차단해야 한다면 기존 DNS Firewall 정책을 별도 읽기 전용 확인해야 한다. 이번 도구는 이를 새로 만들거나 변경하지 않는다. [AWS SG DNS 동작](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- `ec2messages` Endpoint는 현재 없다. Web이 중지돼 있어 SSM Agent 버전을 모른다. AWS 문서에 따르면 Agent AWS_PUBLIC_IP_REDACTED 이상은 사용 가능한 경우 `ssmmessages`를 우선 사용하고, 2024년 이전 Region에서는 이전 Agent가 `ec2messages`를 사용할 수 있다. 이 Canary는 실제 `SSM Online`을 필수 조건으로 두며, 제한시간 안에 Online이 되지 않으면 Web을 중지하고 복구한다. 따라서 사전점검만으로 SSM 성공을 보장하지 않는다. [SSM 메시징 API/Agent 동작](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-setting-up-messageAPIs.html), [Systems Manager VPC Endpoint 요구사항](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-create-vpc.html)
- 현재 private route table `AWS_RESOURCE_ID_REDACTED`의 `AWS_PUBLIC_IP_REDACTED/0` 및 `AWS_PUBLIC_IP_REDACTED/24`는 Web ENI 대상 `blackhole`이다. 이 도구는 Web 시작 후 두 경로가 모두 정확한 Web ENI 대상 `active`가 아닐 경우 실패 처리하며 route를 고치지 않는다.

### 도구 및 실행

기본 실행은 오프라인 계약 검사이며 AWS를 조회하거나 변경하지 않는다. 실제 조회는 다음 read-only 명령으로 한다. 계정/리소스/SG/Endpoint/NACL/DNS/IAM 불일치가 있으면 mutating 모드로 진행하지 않는다.

```bash
cd /home/cloud/hospital-dr-codex
python3 operations/preflight/aws_web_canary_isolation.py --aws-read-only
```

**별도 Canary 변경 승인을 받은 뒤에만** 다음 순서로 실행한다. 먼저 private state 디렉터리를 준비하고 tmux 안에서 한 번만 실행한다. 실행기는 state snapshot을 0600으로 기록한 뒤 임시 SG를 준비하고, SG/ENI readback, Web 시작, EC2 상태 검사, SSM Online, IMDSv2 신원, 제한된 게스트 점검, 양쪽 NAT route를 확인한다. 성공·실패 모두 Web을 stopped로 되돌리고 원래 ENI SG 목록과 Endpoint SG ingress를 복구한 다음 Canary SG를 삭제한다.

```bash
cd /home/cloud/hospital-dr-codex
umask 077
STATE_DIR=/home/cloud/.local/state/hospital-dr-web-canary
mkdir -p -m 0700 "$STATE_DIR"
test "$(stat -c '%a' "$STATE_DIR")" = 700
STATE_FILE="$STATE_DIR/web-canary-$(date -u +%Y%m%dT%H%M%SZ).json"
export STATE_FILE
tmux new-session -s hospital-dr-web-canary
```

새 tmux 세션 안에서 실행:

```bash
cd /home/cloud/hospital-dr-codex
python3 operations/preflight/aws_web_canary_isolation.py \
  --run-canary --confirm-web-id AWS_RESOURCE_ID_REDACTED \
  --state-file "$STATE_FILE" \
  --max-minutes 30
```

툴은 `ACTIVE_RELEVANT_SERVICES`, enabled/scheduled timer 수, cron 항목 수, Docker 컨테이너 이름/상태, cloudflared/WireGuard 존재, MySQL 연결 수, `ip_forward`, NAT 사용자 체인 규칙 수만 출력한다. 환경변수, 프로세스 인자, 애플리케이션 로그, DB/환자 데이터는 출력하지 않는다. 이 Canary에서 서비스·timer·cron·tunnel이 발견돼도 중지/수정하지 않고 결과만 기록한다. Web SG egress가 Endpoint 외부로 열리지 않으므로 DB 연결과 인터넷/Tunnel/WireGuard 경로는 막힌 상태를 유지한다.

### 중단·복구

정상 실패도 자동으로 Web 중지와 원복을 시도한다. 프로세스가 끊겼거나 `cleanup`이 `RESTORED`가 아니면 같은 MSP 계정에서 아래 독립 복구 진입점을 실행한다. 원복 도구는 Web을 먼저 stopped로 readback한 뒤에만 원래 SG 연결을 복구하고, 도구가 추가한 Endpoint SG 규칙만 제거한다. 원본 Endpoint SG 규칙에 외부 drift가 있으면 이를 덮어쓰지 않고 BLOCKED로 남기며 Canary SG와 state 파일을 삭제하지 않는다.

```bash
cd /home/cloud/hospital-dr-codex
python3 operations/preflight/aws_web_canary_isolation.py \
  --restore --confirm-web-id AWS_RESOURCE_ID_REDACTED \
  --state-file "$STATE_FILE"
```

별도 터미널에서 복구할 때는 기존 Canary 프로세스가 종료됐거나 실패한 것을 확인한 뒤, 원래 실행 로그의 `state_file`에 출력된 **동일한 전체 경로**를 `--state-file`로 지정한다. 새 경로로 바꾸면 원래 ENI/Endpoint SG 백업을 찾지 못한다.

별도 터미널에서 사용하는 복구 명령 예시(아래 경로의 시간표시는 원 실행 로그의 정확한 `state_file` 값으로 바꾼다):

```bash
cd /home/cloud/hospital-dr-codex
STATE_FILE='/home/cloud/.local/state/hospital-dr-web-canary/web-canary-YYYYMMDDTHHMMSSZ.json'
python3 operations/preflight/aws_web_canary_isolation.py \
  --restore --confirm-web-id AWS_RESOURCE_ID_REDACTED \
  --state-file "$STATE_FILE"
```

실행 전후 복구 계약은 도구가 확인하며, state 파일은 복구 검증이 끝날 때까지 보존한다. SSM이 Online이 되지 않거나 Web start/status, guest identity/audit, route readback에서 하나라도 실패하면 다음 단계로 진행하지 않는다. 실패 코드에 상관없이 우선 위 `--restore` 실행 결과가 `RESTORED`인지 확인한다. Canary 최대 시간은 30분이며, 별도 모니터링 담당자는 실행 중 상태를 확인한다. 이 작업에는 Web NAT 설정 변경, EMR 시작, Web 공개 egress probe가 포함되지 않는다.

추가 비용은 테스트 중 Web EC2 실행 시간 및 전송량이다. 기존 Web EIP·EBS·SSM Interface Endpoint의 지속 비용은 테스트로 생성된 것이 아니며 계속 과금될 수 있다. Canary SG 자체에는 시간당 요금이 없다. Canary 종료 후 Web은 최초 `stopped` 상태, ENI의 원래 SG 목록, Endpoint SG의 기존 ingress 상태로 돌아와야 한다.

## 2026-10-17 Canary 재시도 절차 — 출력/경쟁 상태 보완

이 절차가 앞의 `tmux` 실행 예시를 대체한다. 이전 실행 state는 `phase=RESTORED`, `started_by_canary=true`, guest audit 및 NAT route 증거 없음이다. CloudTrail에서 `StartInstances` 성공과 Web의 `stopped → pending → running` 진행, 이후 `StopInstances` 요청을 확인했다. `DescribeInstanceStatus`가 반복됐지만 당시 응답 상태값은 남지 않았고, SSM `DescribeInstanceInformation`·`SendCommand` 기록은 없어 SSM 대기나 게스트 점검에 도달했다는 증거가 없다. 가장 좁혀진 중단 지점은 **EC2 instance/system status check 대기**다. 이전 `.log`는 0 byte이며, 기존 버전의 stdout 버퍼링 때문에 Ctrl+C 전 진행 내역이 저장되지 않았다. 기존 state/log는 보존하며 재사용하지 않는다.

수정 실행기는 모든 단계와 AWS API 호출의 시작·완료·제한시간·실패 reason code를 즉시 stdout/JSONL 로그에 flush하고 민감한 요청/응답 본문은 기록하지 않는다. 단계와 마지막 진행 이벤트는 state 파일에도 저장된다. AWS CLI 요청은 connect 5초, read 12초, 프로세스 20초 제한을 갖는다. EC2 시작은 최대 6분, status-check 대기는 전체 30분 예산으로 제한되고, SSM Online은 최대 10분 기다린 뒤 `SSM_OFFLINE`으로 종료·원복한다. 중간 취소는 exit 130으로 표시하되 자동 원복 결과를 먼저 기록한다.

일반 실행과 독립 복구는 같은 호스트 전역 `flock`을 사용한다. 활성 실행 중 `--restore`는 변경을 시작하지 않고 `CANARY_MUTATION_ALREADY_RUNNING`으로 거부된다. SIGINT/SIGTERM으로 실행기를 정리 종료한 뒤 별도 복구를 실행한다. AWS CLI 자식도 lock descriptor를 상속하므로 부모가 비정상 종료되어도 진행 중 API 호출이 끝날 때까지 경쟁 복구가 차단된다.

### tmux 없는 MSP에서 별도 세션 실행

별도 Canary 변경 승인을 받은 후에만, 이전 state 파일이 아닌 새 UTC 이름을 사용한다.

```bash
cd /home/cloud/hospital-dr-codex
umask 077
STATE_DIR=/home/cloud/.local/state/hospital-dr-web-canary
mkdir -p -m 0700 "$STATE_DIR"
test "$(stat -c '%a' "$STATE_DIR")" = 700
STATE_FILE="$STATE_DIR/web-canary-$(date -u +%Y%m%dT%H%M%SZ).json"
LOG_FILE="${STATE_FILE%.json}.log"
PID_FILE="${STATE_FILE%.json}.pid"
test ! -e "$STATE_FILE" && test ! -e "$LOG_FILE" && test ! -e "$PID_FILE"
nohup python3 operations/preflight/aws_web_canary_isolation.py \
  --run-canary --confirm-web-id AWS_RESOURCE_ID_REDACTED \
  --state-file "$STATE_FILE" --log-file "$LOG_FILE" --max-minutes 30 \
  </dev/null >/dev/null 2>&1 &
CANARY_PID=$!
printf '%s\n' "$CANARY_PID" > "$PID_FILE"
printf 'CANARY_PID=%s\nCANARY_LOG=%s\nCANARY_STATE=%s\n' "$CANARY_PID" "$LOG_FILE" "$STATE_FILE"
```

실행 직후 별도 세션에서 진행 상황을 확인한다:

```bash
tail -n 20 -F '/home/cloud/.local/state/hospital-dr-web-canary/<같은 UTC 이름>.log'
```

로그의 `PHASE`, `AWS_API_START/COMPLETE/FAILED`, `WAIT_PROGRESS`, `WAIT_TIMEOUT` 이벤트로 마지막 동작을 확인한다. API 실패 로그에는 AWS 오류 코드만 남으며 원문 stderr는 출력하지 않는다.

### 중단 및 긴급 복구

실행기를 정상 취소할 때는 PID 파일에 든 PID로 SIGINT를 보내고, 로그에서 `CLEANUP_COMPLETE` 또는 실패 reason을 기다린다. 실행기가 종료된 뒤에도 `cleanup`이 `RESTORED`가 아니면 동일 state/log 경로로 독립 복구를 수행한다. 실행 프로세스가 응답하지 않으면 SIGTERM을 보내고 API 호출 제한시간(최대 20초) 및 프로세스 종료를 확인한 다음 복구를 시작한다. 즉시 겹쳐서 `--restore`를 실행하지 않는다. lock이 해제되기 전 복구 명령은 변경하지 않고 차단된다.

```bash
cd /home/cloud/hospital-dr-codex
STATE_FILE='/home/cloud/.local/state/hospital-dr-web-canary/web-canary-<원 실행 UTC 이름>.json'
LOG_FILE="${STATE_FILE%.json}.log"
python3 operations/preflight/aws_web_canary_isolation.py \
  --restore --confirm-web-id AWS_RESOURCE_ID_REDACTED \
  --state-file "$STATE_FILE" --log-file "$LOG_FILE"
```

`AWS_WEB_CANARY_RESTORE`의 `phase=RESTORED`와 state의 같은 phase를 모두 확인한다. 원복 확인 전 state·log·lock 파일을 삭제하지 않는다. 기존 실행의 재현은 금지하며 다음 Canary 역시 별도 변경 승인을 받아야 한다.

## 2026-10-17 1차 Web Canary 판정 및 2차 NAT/EMR 준비 (최신 기준)

### 1차 Canary의 구조화된 최종 판정

검토 대상은 state `/home/cloud/.local/state/hospital-dr-web-canary/web-canary-20261017T060205Z.json`와 대응 JSONL log다. state는 `phase=RESTORED`, `started_by_canary=true`, 시작 전 Web `stopped`, 최종 `web_state=stopped`, route readback `active`를 기록한다.

- EC2 시작 및 시작 대기: 실행 흐름이 `START_WEB_EC2`, `WAIT_WEB_RUNNING`, `WAIT_EC2_STATUS_CHECKS` 각 완료 이벤트를 거쳐 다음 단계에 도달했다. 따라서 실행기가 요구하는 상태검사 poll predicate는 통과했다. 다만 개별 EC2/system status 필드 값은 state에 보존되지 않아 그 원시 응답값 자체를 사후 재검증할 수 없다.
- SSM: `WAIT_SSM_ONLINE` 완료 후 `PHASE=SSM_ONLINE`에 도달했다. `SendCommand`와 `GetCommandInvocation`이 수행됐으며, 구현은 invocation의 `Status=Success`가 아니면 guest audit를 PASS 처리하지 않는다. state에는 명령 원문/전체 응답은 없고 `SSM_GUEST_AUDIT_COMPLETE status=PASS`만 남아 있다.
- 게스트 신원/상태: sanitized audit의 `IMDS_INSTANCE_MATCH=PASS`와 `CANARY_GUEST_AUDIT=PASS` 조건을 통과했다. 기록상 Docker/Web 및 NAT 관련 unit/rules, `ip_forward=1`이 관측됐다. WireGuard unit은 active 목록에 있었으나 별도 runtime 검사 결과는 `ABSENT`라 서로 일치하지 않는다. Cloudflare tunnel process는 `ABSENT`, established MySQL 연결 수는 0으로 관측됐지만, 이 불일치는 2차 외부 egress 허용 전에 guest에서 다시 해소해야 한다.
- NAT route: `GUEST_AUDIT_COMPLETE status=PASS nat_route_state=active`. 이 판정은 route table `AWS_RESOURCE_ID_REDACTED`에서 `AWS_PUBLIC_IP_REDACTED/0` 및 `AWS_PUBLIC_IP_REDACTED/24` 두 route가 Web ENI `AWS_RESOURCE_ID_REDACTED`를 target으로 하고 AWS control plane에서 `State=active`였다는 뜻뿐이다. guest forwarding·iptables 동작 또는 EMR egress는 증명하지 않는다.
- 복구: `WEB_STOPPED`, `RESTORE_COMPLETE status=RESTORED`, `CLEANUP_COMPLETE status=RESTORED`; 이후 read-only AWS 조회에서 Web `stopped`, 원래 Web SG 연결 복구, Endpoint SG의 원래 ingress 복구, 임시 Canary SG 삭제가 확인됐다. 첫 Canary에서는 NAT Ansible role을 적용하지 않았고 EMR도 시작하지 않았다.

따라서 1차 결과는 **격리 기동·SSM read-only guest audit·AWS route readback·원복 성공**이다. NAT forwarding과 EMR 외부송신의 실검증 성공으로 확대 판정하지 않는다.

### 2차 Canary에서 허용할 격리 계약

아래 값은 마지막 읽기 전용 조회 기준이며 실행 직전에 다시 조회한다. 예상과 다르면 중단한다. 이번 단계에서는 AWS 변경을 하지 않았다.

| 대상 | Canary 정책 |
|---|---|
| Web `AWS_RESOURCE_ID_REDACTED` | 기존 SG 전체를 대체하는 임시 SG 하나만 연결. Ingress는 고정된 EMR 주소 `AWS_PUBLIC_IP_REDACTED/32`에서 TCP 443만(전달 probe) 허용. 초기 egress는 실제 SSM Endpoint SG TCP 443만 허용하며, Web·EMR guest audit 후에만 고정 probe IPv4 `/32` TCP 443을 추가한다. |
| EMR `AWS_RESOURCE_ID_REDACTED` | 기존 SG 전체를 대체하는 별도 임시 SG 하나만 연결. Ingress 없음. 초기 egress는 동일 SSM Endpoint SG TCP 443만 허용하며, Web·EMR guest audit 후에만 동일 probe IP `/32` TCP 443을 추가한다. DB TCP 3306, 일반 인터넷, WireGuard UDP, Cloudflare Tunnel 목적지는 허용하지 않음. |
| SSM Endpoint SG `AWS_RESOURCE_ID_REDACTED` | 기존 DB SG ingress를 보존하고, 임시 Web 및 EMR SG 각각의 TCP 443 source만 실행 중 추가 후 종료 시 추가한 두 규칙만 제거. Endpoint ENI 두 개 및 endpoint SG 연결 대상을 재확인. |
| Route/NACL/DB/DNS | 변경하지 않음. NACL은 최근 조회에서 양방향 allow 규칙이었음. 두 private route의 실제 target/state는 매번 readback. DB SG는 기존 상태를 보존하되 임시 ENI SG 교체와 임시 SG egress 때문에 앱의 TCP 3306 경로가 차단되는지 확인. |

임시 SG의 egress를 `AWS_PUBLIC_IP_REDACTED/0`으로 남겨서는 안 된다. 새 SG의 AWS 기본 allow-all egress는 제거한 뒤 위 규칙만 추가하고, readback으로 검증한 다음에만 ENI를 교체한다. ENI에서 원래 SG를 추가 SG로 남기는 방식은 규칙이 합쳐지므로 금지한다. Endpoint SG는 현재 SSM/ssmmessages endpoint ENI에만 연결된다는 점을 재확인한다.

제한사항: AWS VPC resolver 질의는 Security Group/NACL로 차단되지 않는다. 따라서 이 설계는 DNS 질의 자체의 정보유출을 막는 완전한 격리는 아니다. `checkip`는 공유된 공용 HTTPS endpoint이므로 `/32` allowlist가 임의의 앱 요청 위험을 0으로 만들지도 않는다. Web/EMR에서 앱 컨테이너가 자동 시작할 수 있으므로 DB는 read-only 확인 외에 임시 ENI SG에서 3306을 실제 차단해야 한다. 공개 인바운드는 두 임시 SG 모두에서 없지만, Cloudflare Tunnel ingress/origin 설정은 별도 권한 있는 확인 전까지 `UNVERIFIED`다. Web/EMR에서 WireGuard interface/process가 실제로 존재하거나 cloudflared가 실행 중이면 probe를 허용하지 않고 중단한다. EMR→Web subnet TCP 443 규칙은 NAT forwarding에 필요하며 같은 사설 subnet의 EMR이 Web의 local 443 listener에도 도달할 수 있다는 점을 승인자가 수용해야 한다.

### NAT role 적용 및 복원 계약

새 역할 변경은 기존 opt-in playbook과 `[web_servers]` SSM inventory를 사용한다. Web의 SSM/IMDSv2 identity가 instance `AWS_RESOURCE_ID_REDACTED`, ENI `AWS_RESOURCE_ID_REDACTED`, VPC/Subnet 및 private IP와 정확히 일치해야 한다. 현재 guest audit에 NAT service와 chain이 이미 관측됐으므로, 다음 실행은 **먼저 read-only 상태와 role의 `snapshot-firewall`이 baseline을 판정하는지 확인**한다. exact/absent가 아닌 chain drift는 자동 정리하지 않고 차단한다.

Apply는 iptables package를 설치하지 않고 이미 설치된 상태만 요구한다. baseline과 applied checksums는 Web에 root-only로 남는다. Restore는 baseline/backup의 root 소유·0600·SHA256, 현재 파일의 applied checksum, runtime `ip_forward`, package state 및 role-owned chain을 확인한다. drift가 있으면 덮어쓰지 않는다. 직접 Ansible apply/remove를 따로 실행하지 않고, 아래 transaction Runner가 SSM 관리 transport와 동일한 `[web_servers]` 역할 범위로 순서·상태·복구를 통합한다.

Restore 성공 후에만 Web을 stop하고 원래 ENI SG 목록 및 Endpoint SG ingress를 복원한다. Route는 원래 blackhole/active snapshot과 대조하며 이 절차는 route를 수정하지 않는다. Web/EMR stop→SG restore→Endpoint rule restore→temporary SG deletion 순서를 지킨다. `NAT_GUEST_STATUS=READY`는 게스트 forwarding 구성만 판정하며 EMR egress가 일치하기 전에는 전체 `NAT_INSTANCE_STATUS=READY`가 아니다.

### 2차 Canary 통합 Runner

`operations/demo/aws_nat_emr_canary.py`가 기존 Web Canary의 host-wide mutation lock, `AwsCli` 제한시간·로그·private state 구현, SSM SSH helper, NAT apply/remove playbook과 NAT status checker를 재사용한다. 기본 실행은 오프라인이며 AWS를 조회하지 않는다. `--aws-read-only`는 AWS 리소스 구성을 변경하지 않으며 계정/리소스/route/ENI/SG/SSM/DNS Firewall과 DB read-only 신원을 점검한다. 단, DB 검사에는 SSM Run Command로 SELECT만 실행하므로 AWS에 SSM command invocation/audit 기록이 생성된다. 이는 인프라 설정 변경은 아니지만 부작용 없는 API 조회만을 뜻하는 strict read-only와는 다르다.

SG/NACL로 VPC DNS Resolver 질의 자체를 차단할 수 없으므로 Run mode는 Route 53 Resolver DNS Firewall을 fail-closed walled garden으로 확인한다. 정확히 하나의 VPC association이 COMPLETE, FirewallFailOpen=DISABLED, SSM hostname과 `checkip.amazonaws.com`만 ALLOW, 나머지는 `*` BLOCK이며 ALLOW 우선순위가 앞서야 한다. 선택적 `ec2messages` endpoint가 실제로 있으면 그 hostname도 허용목록 계약에 포함한다. 이 정책을 읽기 검증할 수 없거나 맞지 않으면 실행은 시작되지 않는다. 본 작업에서는 실제 AWS 설정/상태를 변경하지 않았으며 DNS Firewall의 현재 운영값도 새로 확정하지 않았다.

#### 공유 VPC의 명시적 제한 egress 모드

`--dns-isolation-mode constrained-egress`는 제한 모드를 명시적으로 선택하고 결과·JSONL 감사 이벤트에 DNS 격리 상태를 남긴다. 이 선택은 DNS Firewall 검사를 우회하지 않는다. 해당 VPC에 검증 가능한 fail-closed Firewall association/policy가 없으면 `DNS_ISOLATION_NOT_GUARANTEED`로 BLOCKED이며 Canary state 생성이나 AWS 변경 단계에 진입하지 않는다. 읽기 전용 확인 명령은 다음과 같다:

```bash
python3 operations/demo/aws_nat_emr_canary.py \
  --aws-read-only --dns-isolation-mode constrained-egress
```

AmazonProvidedDNS 질의는 SG와 NACL의 차단 규칙을 우회한다. Firewall association이 없는 동안 DNS 이름 질의·DNS 기반 정보 유출을 이 Canary SG만으로 막거나 증명할 수 없다. 또한 pinned `checkip.amazonaws.com` IP의 TCP 443 허용은 그 목적지로 향하는 다른 애플리케이션 요청까지 프로토콜 수준에서 제한하지 않는다. 이를 충분히 통제할 독립 Resolver 정책/경로가 없으므로 현재 공유 VPC에서는 실기동 BLOCKED를 유지한다. 결과는 이를 `dns_filtering=NOT_GUARANTEED`, `unfiltered_dns_queries_possible=true`로 명시한다.

Canary SG 계약 자체는 Web/EMR을 기존 SG가 남지 않는 단일 임시 SG로 교체하고, SSM Endpoint SG TCP 443만 먼저 허용한다. Web·EMR 양쪽의 게스트 audit이 끝난 뒤에만 Web/EMR SG 각각에 검증된 probe IP `/32`의 TCP 443을 추가하고 정확히 readback한다. DB TCP 3306과 그 밖의 TCP/UDP/IPv6 송신은 허용하지 않는다. 이 제한은 DNS 질의를 막는다는 뜻이 아니며, 실행 전 preflight에서 SG 규칙은 `CONTRACT_ONLY_PENDING_EXCLUSIVE_SG_READBACK`으로 보고된다. AmazonProvidedDNS bypass, Firewall 미확인, 예상치 못한 서비스/tunnel/writer, SG/NACL/route 불일치 중 하나라도 남으면 진행하지 않는다.

운영 승인을 받더라도 DNS Firewall이 미검증인 현재 상태에서는 `--run-canary`를 실행하지 않는다. 승인 후에도 기존 Runner만 사용한다: strict 기본 모드에서 Read-only preflight PASS와 별도 변경 승인을 먼저 확보하고, 기존 `--run-canary`의 계정/VPC/인스턴스/ENI/DB/route/probe 확인을 모두 제공한다. `constrained-egress`를 명시한 mutation은 추가로 `--confirm-dns-isolation-mode CONSTRAINED_EGRESS_REVIEWED`를 요구하지만 이 확인값은 DNS 안전 검사를 우회하지 않는다. 실패·중단 시 기존 transaction cleanup, 또는 state의 정확한 `run_id`로 `--restore --confirm-run-id "$RUN_ID"`를 실행해 EMR 중지 → Web NAT baseline 복구 → Web 중지 → 기존 SG/Endpoint ingress 복원 순서로 되돌리고, 완료 전 새 실행은 금지한다.

임시 Web SG는 EMR `AWS_PUBLIC_IP_REDACTED/32`에서 TCP 443만 ingress 허용하고, EMR SG는 ingress가 없다. 두 SG egress는 처음에는 SSM endpoint SG TCP 443만 허용하며, Web·EMR guest audit 성공 후에만 실행 직전 확인한 probe IP `/32` TCP 443을 추가한다. 기존 SG를 추가로 남기지 않고 ENI의 SG 집합을 임시 SG 하나로 교체한다. endpoint SG에는 실행이 추가한 source SG 443 ingress만 일시 추가한다. DB 3306, 일반 인터넷, Cloudflare Tunnel/WireGuard는 허용하지 않는다. 자동 시작된 관련 컨테이너/Node/DB/tunnel 프로세스·서비스·timer/cron은 다음 단계 전 중단 사유다.

실제 승인된 maintenance window에서 먼저 다음 read-only 검사를 수행한다. AWS 계정과 권한은 사용자 운영 환경에서 제공되어야 하며, 명령은 credential 값을 출력하지 않는다.

```bash
cd /home/cloud/hospital-dr-codex
python3 operations/demo/aws_nat_emr_canary.py --aws-read-only
```

실행은 별도 AWS 변경 승인, 정확한 account/instance/ENI/route 확인, read-only preflight PASS 이후에만 허용된다. 작업 상태·log·PID는 `$HOME/.local/state/hospital-dr-nat-emr-canary` 아래 0700/0600으로 생성하고 기존 Web Canary와 동일한 mutation lock을 사용한다. 이 예시 명령을 실행한 적은 없다.

```bash
set -euo pipefail
umask 077
cd /home/cloud/hospital-dr-codex
CANARY_DIR="$HOME/.local/state/hospital-dr-nat-emr-canary"
mkdir -p "$CANARY_DIR"
chmod 700 "$CANARY_DIR"
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STATE_FILE="$CANARY_DIR/web-nat-emr-canary-$RUN_STAMP.json"
LOG_FILE="$CANARY_DIR/web-nat-emr-canary-$RUN_STAMP.jsonl"
PID_FILE="$CANARY_DIR/web-nat-emr-canary-$RUN_STAMP.pid"
CONSOLE_FILE="$CANARY_DIR/web-nat-emr-canary-$RUN_STAMP.console.log"
LAUNCH_PID_FILE="$CANARY_DIR/web-nat-emr-canary-$RUN_STAMP.launcher.pid"
test ! -e "$STATE_FILE" && test ! -e "$LOG_FILE" && test ! -e "$PID_FILE"
test ! -e "$CONSOLE_FILE" && test ! -e "$LAUNCH_PID_FILE"
umask 077
nohup python3 operations/demo/aws_nat_emr_canary.py \
  --run-canary --state-file "$STATE_FILE" --log-file "$LOG_FILE" --pid-file "$PID_FILE" \
  --max-minutes 30 \
  --confirm-account 009144422546 \
  --confirm-vpc-id AWS_RESOURCE_ID_REDACTED \
  --confirm-web-id AWS_RESOURCE_ID_REDACTED --confirm-web-eni AWS_RESOURCE_ID_REDACTED \
  --confirm-emr-id AWS_RESOURCE_ID_REDACTED --confirm-emr-eni AWS_RESOURCE_ID_REDACTED \
  --confirm-db-id AWS_RESOURCE_ID_REDACTED \
  --confirm-route-table-id AWS_RESOURCE_ID_REDACTED \
  --confirm-probe-host checkip.amazonaws.com \
  --confirm-isolated-canary-scope ISOLATED_WEB_NAT_EMR_CANARY_ONLY \
  </dev/null >"$CONSOLE_FILE" 2>&1 &
LAUNCH_PID=$!
printf '%s\n' "$LAUNCH_PID" > "$LAUNCH_PID_FILE"
printf 'CANARY_PID=%s\nCANARY_STATE=%s\nCANARY_JSONL=%s\nCANARY_CONSOLE=%s\n' \
  "$LAUNCH_PID" "$STATE_FILE" "$LOG_FILE" "$CONSOLE_FILE"
```

실행 중에는 별도 터미널에서 `tail -f "$LOG_FILE"` 또는 `tail -f "$CONSOLE_FILE"`로 확인한다. 중지는 먼저 내부 PID에 SIGINT를 보내 자동 정리를 기다린다: `kill -INT "$(sed -n 's/^pid=//p' "$PID_FILE")"`. 실행 종료 후 state의 `phase=RESTORED`와 `cleanup_complete=true`를 확인한다. 복구가 불완전하면 새 run을 시작하지 않는다.

실행은 Web/EMR이 원래 stopped, DB가 running 및 read-only ON/ON, 정확한 ENI/SG/route/Endpoint, SSM/IAM/NACL/DNS Firewall 조건을 각각 readback한 뒤에만 진행한다. 순서는 임시 SG 완전 교체→Web 시작·SSM/guest 점검→기존 NAT role apply 및 baseline hash 검증→route/guest NAT 검증→EMR 시작·SSM/guest audit→TLS 검증 egress probe→관측 IP가 Web EIP와 동일한지 확인→Canary NAT 계약이다. 운영 `NAT_INSTANCE_STATUS=READY`, route, DB, DNS, `DR_ACTIVE`, Failover 승인/요청은 수정하지 않는다.

### 권한 범위

사전조회에는 `sts:GetCallerIdentity`; EC2 `DescribeInstances`, `DescribeInstanceStatus`, `DescribeNetworkInterfaces`, `DescribeSecurityGroups`, `DescribeVpcEndpoints`, `DescribeVpcs`, `DescribeVpcAttribute`, `DescribeDhcpOptions`, `DescribeRouteTables`, `DescribeNetworkAcls`; `iam:GetInstanceProfile`/`ListAttachedRolePolicies`; Resolver Firewall `ListFirewallRuleGroupAssociations`, `ListFirewallConfigs`, `ListFirewallRules`, `ListFirewallDomains`; SSM `DescribeInstanceInformation` 권한이 필요하다. DB 상태를 직접 재확인하기 위해 `--aws-read-only`는 별도로 `ssm:SendCommand`와 `ssm:GetCommandInvocation`을 DB 인스턴스 및 `AWS-RunShellScript` 문서 범위에서 사용하고 SQL은 조회문만 보낸다. 이는 DB 변경은 아니지만 AWS API 관점에서는 Command invocation 감사 흔적을 만드는 행위다.

승인된 Canary에는 위 조회 권한 외에 임시 SG 전용 `ec2:CreateSecurityGroup`, `DeleteSecurityGroup`, `AuthorizeSecurityGroupIngress/Egress`, `RevokeSecurityGroupIngress/Egress`; 고정 Web/EMR ENI에만 `ec2:ModifyNetworkInterfaceAttribute`; 고정 Web/EMR 인스턴스에만 `ec2:StartInstances`/`StopInstances`; 그리고 해당 인스턴스·`AWS-StartSSHSession` 문서에 제한된 `ssm:StartSession`/`TerminateSession`이 필요하다. 실행기는 Route, IAM, DB 데이터, DNS, Trigger/Action을 변경하지 않으며 이에 대한 변경 권한을 요구하지 않는다. 운영 IAM 정책을 수정하지 말고 현재 역할에 위 최소 범위가 있는지 먼저 확인한다.

정상·오류·Ctrl+C/SIGTERM 처리의 자동 원복 순서는 **EMR 중지 → Web이 SSM Online인 동안 NAT role baseline restore/hash/readback → Web 중지 → Web/EMR 원래 SG 복원 → endpoint SG 추가 ingress만 제거 → 원래 상태/DB read-only/route readback → 임시 SG 제거**다. 중간 restore가 실패하면 남은 isolation을 유지하고 state를 보존한다. run 동안 단계별 AWS 호출과 SSM은 남은 30분 budget에 제한되고, cleanup budget을 별도 예약한다.

별도 세션에서 progress를 확인할 경우 JSONL 로그와 state만 읽는다. 실행 PID는 같은 디렉터리의 PID 파일 또는 호출한 셸의 `$!`를 사용한다. 정상 정리가 가능하도록 Ctrl+C 또는 SIGTERM을 우선 사용한다. process가 끝난 뒤 state의 `cleanup_complete`/`phase`가 `RESTORED`가 아니면 새 run을 시작하지 않는다.

```bash
# 이전 state/log를 삭제하거나 덮어쓰지 말고 해당 run id를 확인한다.
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$STATE_FILE"
RUN_ID="<위에서 확인한 정확한 run_id>"
python3 operations/demo/aws_nat_emr_canary.py \
  --restore --state-file "$STATE_FILE" --log-file "$LOG_FILE" --pid-file "$PID_FILE" \
  --confirm-run-id "$RUN_ID" \
  --confirm-account AWS_ACCOUNT_ID_REDACTED --confirm-vpc-id AWS_RESOURCE_ID_REDACTED \
  --confirm-web-id AWS_RESOURCE_ID_REDACTED --confirm-web-eni AWS_RESOURCE_ID_REDACTED \
  --confirm-emr-id AWS_RESOURCE_ID_REDACTED --confirm-emr-eni AWS_RESOURCE_ID_REDACTED \
  --confirm-db-id AWS_RESOURCE_ID_REDACTED \
  --confirm-route-table-id AWS_RESOURCE_ID_REDACTED
```

Ansible NAT role이 timeout/interrupt된 state는 별도 SSM read-only 확인 없이 복구 단계에서 재실행하지 않는다. 저장된 per-run `*.ssh_config`로 Web의 남은 NAT role process가 없는지 현장에서 확인하고, 정상 종료/readback 후에만 위 복구 명령에 `--confirm-nat-role-idle`을 추가한다. 확인 불가면 임시 SG 격리를 그대로 두고 현장 대응한다. SG/Route/NAT를 수동으로 임의 정리하지 않는다.

**현재 구현 판정: 코드 및 오프라인 transaction 검사 완료, 실기동은 미실행.** 실제 실행 전 BLOCKED 항목은 read-only preflight 결과(특히 DNS Firewall 허용목록/fail-open, 현 시점의 DB read-only, SSM Online·Endpoint 및 실제 probe IP), 두 instance의 stopped 상태, 그리고 운영 변경 승인을 확보하는 것이다. 이 독립 Canary는 Web 단독으로 최종 NAT readiness를 증명하지 않으며, Web/EMR을 정상 DR 애플리케이션으로 개방하거나 Production Failover를 실행하지 않는다.
