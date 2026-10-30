# Network integration

최종 Web IP `IP_REDACTED/24`, Gateway `IP_REDACTED`. DB `IP_REDACTED:3306`, EMR `IP_REDACTED:5000`은 직접 읽은 앱 환경의 공개 접속 주소 및 Nginx와 일치합니다.

현재 추출 환경: enp0s3에 최종 Web IP, enp0s8 `IP_REDACTED/24` 및 default via `IP_REDACTED`; 사용자 설명상 Codex용 VirtualBox NAT입니다. `wg0 IP_REDACTED/24`와 `IP_REDACTED/24 dev wg0`도 관측되었습니다. 목적/최종 포함 여부는 사용자 확인 전 추측하지 않습니다. 이 정보는 `web/inventory/network-*.txt`의 temporary extraction environment 기록입니다. 실제 기본 Gateway를 임의 복원하지 않았습니다.

Netplan 원본은 root 읽기 권한이 없어 미수집입니다. 최종 주소 기반 예시만 별도로 제공하며 NIC 이름/renderer/DNS/추가 route를 확정하지 않습니다. NAT 설정을 최종 구성으로 적용하면 안 됩니다.

Cisco 세부는 [NETWORK_TOPOLOGY](../network/NETWORK_TOPOLOGY.md), 정책은 [ACL_POLICY](../network/ACL_POLICY.md). GNS3가 꺼져 있을 수 있으므로 backend 미도달은 환경상 미검증으로 분류합니다. 패킷/ACL 역방향 검증은 이번에 수행하지 않았습니다.
