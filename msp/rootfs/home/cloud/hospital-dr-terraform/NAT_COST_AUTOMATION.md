# NAT Gateway Cost-Control Automation

## Architecture

The DR Web server has a public IP and uses the Internet Gateway directly. The
Doc and DB servers remain in private subnets. Their outbound Internet access is
provided only while the NAT Gateway and the private `AWS_PUBLIC_IP_REDACTED/0` route exist.

- Weekday enable schedule: 08:50 Asia/Seoul
- Daily safety-disable schedule: 18:30 Asia/Seoul
- Morning creation requires `.nat-schedule-enabled`.
- Evening deletion remains enabled even when morning creation is paused.
- A clean controller shutdown also runs NAT deletion before networking stops.
- `run_demo.sh` always enables NAT before Ansible provisioning.

## Operations

```bash
# Manual control
./nat_gateway_control.sh enable
./nat_gateway_control.sh status
./nat_gateway_control.sh disable

# Install timers once
sudo ./install_nat_schedule.sh

# Enable automatic morning creation during a test/demo period
./nat_schedule_enable.sh

# Stop automatic morning creation; keep the evening safety deletion
./nat_schedule_disable.sh

# Inspect schedules and execution logs
systemctl list-timers 'hospital-dr-nat-*'
journalctl -u hospital-dr-nat-enable.service
journalctl -u hospital-dr-nat-disable.service
tail -f /home/cloud/hospital-dr-terraform/nat_gateway.log
```

The systemd installation requires Ubuntu administrator privileges. The local
DR controller must be running at the scheduled time. Before shutting down the
controller forcibly, run `./nat_gateway_control.sh disable` and verify the
disabled status. A normal OS shutdown invokes the installed shutdown service.

systemd 설치에는 Ubuntu 관리자 권한이 필요합니다. 예약 시각에는 로컬 DR
컨트롤러가 실행 중이어야 합니다. 컨트롤러를 직접 종료하기 전에는
`./nat_gateway_control.sh disable`을 실행하고 비활성 상태를 확인하십시오.
정상적인 OS 종료에서는 설치된 shutdown 서비스가 삭제를 실행합니다.

## Troubleshooting Record

### Problem Symptom / 문제 현상

The NAT Gateway continued hourly billing while the DR environment was not being
tested. A console-only deletion was also unsafe because the next Terraform run
could recreate the resource without an explicit cost-control workflow.

DR 테스트를 하지 않는 시간에도 NAT Gateway 시간당 과금이 계속되었으며,
콘솔에서만 삭제하면 다음 Terraform 실행 시 리소스가 의도치 않게 재생성될
가능성이 있었습니다.

### Root Cause / 원인 분석

The Terraform configuration always declared one NAT Gateway, one Elastic IP,
and a private default route. Doc/DB provisioning also requires outbound access
for `apt`, NodeSource, and `npm`, so the NAT could not simply be removed from the
architecture.

Terraform이 NAT Gateway, Elastic IP, 프라이빗 기본 경로를 항상 생성하도록
선언하고 있었습니다. 또한 Doc/DB 프로비저닝은 `apt`, NodeSource, `npm` 외부
접속이 필요하므로 NAT를 아키텍처에서 완전히 제거할 수 없었습니다.

### Resolution / 해결 조치

Added `enable_nat_gateway` to manage the NAT Gateway, its Elastic IP, and the
private default route as one lifecycle unit. Added Terraform-based CLI control,
a shared execution lock, weekday creation, daily deletion, and a schedule guard.
The evening timer is persistent so a missed shutdown is retried after the
controller boots.

`enable_nat_gateway` 변수로 NAT Gateway, Elastic IP, 프라이빗 기본 경로를
하나의 수명주기로 관리했습니다. Terraform 기반 CLI 제어, 동시 실행 잠금,
평일 생성, 매일 삭제, 스케줄 보호 파일을 추가했습니다. 저녁 타이머는
Persistent로 설정하여 컨트롤러가 꺼져 삭제를 놓친 경우 다음 부팅 시 다시
실행합니다.

### Installation Permission Issue / 설치 권한 문제

The first timer installation attempt stopped because `sudo` required an
interactive password. No AWS resource was changed. The unit files and installer
were retained, and installation must be completed once from an interactive
terminal with `sudo ./install_nat_schedule.sh`.

최초 타이머 설치는 `sudo` 대화형 암호가 필요하여 중단됐으며 AWS 리소스는
변경되지 않았습니다. 유닛과 설치 스크립트는 정상 생성됐고, 대화형 터미널에서
한 번 `sudo ./install_nat_schedule.sh`을 실행해 설치를 완료해야 합니다.

## Validation Checklist

1. Run `terraform validate` and shell syntax checks.
2. Enable NAT and confirm `nat_gateway_id` plus the private default route.
3. From Doc/DB, verify package repository access.
4. Disable NAT and confirm the NAT Gateway, EIP, and private default route are absent.
5. Confirm Web-to-Doc-to-DB private traffic still works.
6. Confirm the evening timer deletes NAT after a manual daytime enable.

## Operational Notes

- Do not run NAT control while `run_demo.sh` is applying Terraform; both use the
  same lock file.
- NAT-disabled Doc/DB instances cannot reach package repositories or an
  on-premises DB through its public IP.
- Internal VPC traffic between Web, Doc, and DB does not require NAT.
- Enable the morning schedule only for active test/demo periods. Otherwise keep
  it paused and use manual enable immediately before testing.
