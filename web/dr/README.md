# AWS DR 배포 구조 템플릿

사용자 최종 컨텍스트: Web EIP `AWS_PUBLIC_IP_REDACTED`. 실제 AWS VM/AMI/security group/네트워크/DB 복제/EMR/origin TLS는 미수집입니다.

| 계층 | 준비물 |
|---|---|
| Web source | ../web/app 및 lock |
| Process | systemd unit을 새 DR 경로/User에 맞게 검토 |
| Proxy | Nginx / → loopback Node; /emr/ → 실제 DR EMR 주소 확인 필요 |
| Environment | 별도 Secret, DR DB 주소/포트/이름, SERVER_ROLE 식별값 |
| Public | hostname/TLS/Cloudflare Strict 조건 확인 |
| Data | DB 복구 및 failback 데이터 동기화 계획 별도 |

온프레미스 192.168.30.x에 AWS에서 접근 가능하다고 가정하지 않습니다. `environment.example`은 입력 자리이며 실제 AWS 값이 아닙니다. 배포/전환 명령은 실행하지 않았습니다. [복구](../docs/RECOVERY.md), [전환](../docs/FAILOVER_FAILBACK.md).
