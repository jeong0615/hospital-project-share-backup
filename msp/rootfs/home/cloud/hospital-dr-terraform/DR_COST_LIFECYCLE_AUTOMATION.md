# Hospital DR Cost and Lifecycle Automation

## 1. Objective / 목표

Keep the reusable VPC foundation while eliminating avoidable hourly charges
when the DR environment is not being demonstrated or tested.

재사용 가능한 VPC 기반은 유지하되, DR 시연과 테스트를 하지 않을 때 발생하는
불필요한 시간당 과금을 자동으로 제거합니다.

The VPC, subnets, route tables, Internet Gateway, and security groups do not
have a start/stop state. They remain provisioned for fast recovery. Cost control
therefore targets EC2 runtime, NAT Gateway runtime, public IPv4, and detached
Elastic IP resources.

VPC, 서브넷, 라우팅 테이블, Internet Gateway, 보안 그룹에는 시작/중지 상태가
없습니다. 빠른 복구를 위해 유지하며 EC2 실행 시간, NAT Gateway 실행 시간,
공인 IPv4, 미연결 Elastic IP를 비용 제어 대상으로 관리합니다.

## 2. Operating Model / 운영 모델

### Local controller lifecycle

- Ubuntu controller boot: start the three existing DR EC2 instances.
- Wait for EC2 system and instance status checks.
- Detect the new Web public IP after EC2 start.
- Update Cloudflare and Ansible inventory automatically.
- Start and validate Web and EMR services.
- Keep NAT disabled during normal runtime.
- Ubuntu clean shutdown: switch DNS to the on-premises Cloudflare Tunnel, stop
  EC2, delete NAT, and release detached NAT EIPs.

### AWS-independent safety guard

The `hospital-dr-cost-guard` Lambda runs even if the Ubuntu controller is
powered off abruptly and cannot execute its shutdown hook.

- Every day at 19:00 KST: switch Cloudflare to the on-premises Tunnel, stop the
  three named Hospital DR EC2 instances, and delete the Hospital DR NAT Gateway.
- Every day at 19:20 KST: release detached `Hospital-DR-NAT-EIP` addresses after
  NAT deletion has completed.
- CloudWatch log retention: 7 days.

The Lambda and EventBridge schedule normally remain within their free usage
allowances. EC2, EBS, public IPv4, NAT processing, and network transfer are
still billed according to actual use and account credit eligibility.

## 3. Manual Commands / 수동 명령

```bash
cd /home/cloud/hospital-dr-terraform

# Start existing Web, Doc, and DB instances and switch DNS to DR
./dr_environment_control.sh start

# Stop EC2, switch DNS to on-premises, and remove temporary NAT/EIPs
./dr_environment_control.sh stop

# Show EC2, NAT, and NAT EIP status
./dr_environment_control.sh status

# Provision missing infrastructure, then remove NAT after provisioning
./dr_environment_control.sh provision
```

Full Doc/DB provisioning can require additional recovery variables:

```bash
ANSIBLE_LIMIT=all \
./dr_environment_control.sh provision
```

Set the database backup encryption key through
`/home/cloud/hospital-dr-secrets/dr.env` before running Doc/DB recovery
workflows.

Keep NAT after provisioning only when Native Replication or another private
outbound workflow is actively required:

```bash
KEEP_NAT_AFTER_PROVISION=true ./dr_environment_control.sh provision
```

Manual NAT-only control remains available:

```bash
./nat_gateway_control.sh enable
./nat_gateway_control.sh status
./nat_gateway_control.sh disable
```

## 4. Ubuntu Boot and Shutdown Installation / Ubuntu 부팅·종료 연동

Run once from an interactive Ubuntu terminal because `sudo` requires the local
administrator password:

```bash
cd /home/cloud/hospital-dr-terraform
sudo ./install_dr_environment_service.sh
sudo systemctl start hospital-dr-environment.service
```

Verification:

```bash
systemctl is-enabled hospital-dr-environment.service
systemctl status hospital-dr-environment.service --no-pager
journalctl -u hospital-dr-environment.service -n 100 --no-pager
```

Disable automatic controller linkage while retaining manual and AWS safety
controls:

```bash
sudo systemctl disable --now hospital-dr-environment.service
```

The previous NAT morning/evening timers must remain disabled because they can
recreate NAT independently of an active DR test:

```bash
systemctl is-enabled hospital-dr-nat-enable.timer
systemctl is-enabled hospital-dr-nat-disable.timer
```

Expected result: `disabled`.

## 5. AWS Safety Guard Operations / AWS 안전장치 운영

Inspect the schedules:

```bash
aws events list-rules \
  --region ap-northeast-2 \
  --name-prefix hospital-dr-daily \
  --query 'Rules[].{Name:Name,State:State,Schedule:ScheduleExpression}' \
  --output table
```

Test EIP cleanup without stopping EC2 using AWS CLI v1:

```bash
aws lambda invoke \
  --region ap-northeast-2 \
  --function-name hospital-dr-cost-guard \
  --payload '{"action":"cleanup"}' \
  /tmp/hospital-dr-cost-guard-response.json
```

Do not manually test `{"action":"shutdown"}` during a demonstration. It will
stop all three tagged DR instances immediately.

## 6. Database Network Rule / DB 네트워크 규칙

The DR DB instance uses private IP `AWS_PUBLIC_IP_REDACTED` and has no public IP. When
Native Replication connects from the private DR DB to the on-premises DB, the
on-premises firewall sees the NAT Gateway Elastic IP, not the Web public IP.

Current state: NAT is disabled, so there is no valid AWS replication source
public IP to whitelist.

After enabling NAT, retrieve the correct address:

```bash
cd /home/cloud/hospital-dr-terraform
./nat_gateway_control.sh enable

aws ec2 describe-nat-gateways \
  --region ap-northeast-2 \
  --filter "Name=tag:Name,Values=Hospital-DR-NAT-GW" "Name=state,Values=available" \
  --query 'NatGateways[0].NatGatewayAddresses[0].PublicIp' \
  --output text
```

Run this command on the on-premises DB server using the returned NAT IP:

```bash
sudo ufw allow from [NAT_GATEWAY_PUBLIC_IP] to any port 3306 proto tcp
sudo ufw status numbered
```

Because cost-first automation deletes the NAT EIP, the source IP can change on
the next enable. Production Native Replication should use a stable VPN/private
connection or deliberately retain one EIP and accept its hourly public IPv4
charge.

## 7. Cost State and Residual Charges / 비용 상태 및 잔여 과금

Stopped state removes these avoidable charges:

- EC2 instance runtime for Web, Doc, and DB.
- NAT Gateway hourly runtime and NAT data processing.
- Detached NAT Elastic IP hourly charges.
- Web public IPv4 runtime charge after the instance is stopped and the address
  is released by AWS.

These costs remain:

- EBS volumes attached to stopped instances.
- Existing snapshots and backup storage.
- Small CloudWatch log storage outside free allowances.
- Data transfer already consumed during tests.

Destroying EBS and all infrastructure would reduce storage cost further but
would also delete persistent DR server state. It is intentionally not part of
the automatic stop workflow.

## 8. Troubleshooting Records / 트러블슈팅 기록

### Terraform operation remained locked

Problem Symptom / 문제 현상:

`Another Terraform operation is already in progress` was returned even though
the Terraform command had ended.

Root Cause / 원인 분석:

An orphan `terraform-provider-aws` process inherited file descriptor 9 for
`/tmp/hospital-dr-terraform.lock` and kept the lock active.

Resolution / 해결 조치:

The orphan provider was terminated. `run_demo.sh` and
`nat_gateway_control.sh` now use `flock --close`, preventing provider children
from inheriting the lifecycle lock.

### Cloudflare 522 after EC2 restart

Problem Symptom / 문제 현상:

`hospital-web.pp.ua` returned Cloudflare Error 522 after manually starting EC2.

Root Cause / 원인 분석:

The Web public IP changed from `AWS_PUBLIC_IP_REDACTED` to `AWS_PUBLIC_IP_REDACTED`, while
Cloudflare still pointed to the old address. PM2 was also not registered for
automatic startup, producing an origin-side 502 after DNS correction.

Resolution / 해결 조치:

The new lifecycle start command discovers the current public IP and updates
Cloudflare automatically. The Web Ansible role now registers and enables
`pm2-ubuntu`; HTTPS health returned 200 after deployment.

### EMR 503 after Doc restart

Problem Symptom / 문제 현상:

`https://hospital-web.pp.ua/emr/` returned HTTP 503.

Root Cause / 원인 분석:

Apache was active and port 80 was reachable, but its reverse-proxy destination
`AWS_PUBLIC_IP_REDACTED:5000` was down because the EMR PM2 process did not start after EC2
reboot.

Resolution / 해결 조치:

The saved `hospital-emr` process was restored and the Doc Ansible role now
registers `pm2-ubuntu` with systemd. Internal Doc HTTP and external `/emr/`
both returned HTTP 200.

### Local systemd installation permission

Problem Symptom / 문제 현상:

The automatic installer returned `sudo: a password is required`.

Root Cause / 원인 분석:

Writing a unit into `/etc/systemd/system` requires the interactive Ubuntu
administrator password.

Resolution / 해결 조치:

The unit and installer are complete. Run `sudo
./install_dr_environment_service.sh` once from the Ubuntu terminal. AWS-side
daily protection is already active independently of this local installation.

## 9. Validation Results / 검증 결과

- Terraform validation: passed.
- Terraform apply: 10 safety resources created, no EC2/VPC replacement.
- AWS schedules: both `ENABLED`.
- NAT Gateway: absent.
- Detached Hospital NAT EIPs: zero.
- Manual environment `start`: passed.
- Web HTTPS: HTTP 200.
- EMR HTTPS: HTTP 200.
- Web PM2: enabled, active, application online.
- Doc PM2: enabled, active, application online.
