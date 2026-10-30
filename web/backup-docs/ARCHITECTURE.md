# Architecture

출처: Web VM 직접 관측 + 사용자 제공 외부 최종 컨텍스트. 이 저장소는 HA/DR 시스템 전체의 실행 가능한 완전 백업이 아니라 Web 역할의 수집본입니다.

Browser → Cloudflare Edge TLS → cloudflared → Nginx `IP_REDACTED:80` → Express `IP_REDACTED:3000`.
Node → mysql2/promise → `IP_REDACTED:3306`. Nginx `/emr` → 301 `/emr/`, `/emr/` → `http://IP_REDACTED:5000/`.

Web VLAN20 `IP_REDACTED/24`, DB/EMR VLAN30 `IP_REDACTED/24`, Doc VLAN10 `IP_REDACTED/24`, Core/Uplink VLAN100 `IP_REDACTED/24`.
HSRP VIP: VLAN10 `.10.1`, VLAN20 `.20.1`, VLAN30 `.30.1` (모두 192.168 접두).

DNS Failover는 Tunnel CNAME에서 AWS EIP `AWS_PUBLIC_IP_REDACTED` A로 전환하며 Failback은 역순입니다. AWS Web/DB 복제 방식, RPO/RTO, AWS origin TLS, 실제 DR backend 주소는 확인되지 않았습니다. 세션은 기본 메모리 저장소이므로 노드 전환 시 로그인 세션 보존을 보장하지 않습니다.

Zabbix Agent의 Server/ServerActive는 `IP_REDACTED`, Hostname은 `web_sever`입니다. OS hostname `hospital-web-server-1`과 다른 것은 에이전트 등록 키 차이로 기록하며 임의로 수정하지 않습니다.

임시 추출 환경의 NAT와 목적 미확인 `wg0`는 최종 VLAN/라우팅 설계를 대체하지 않습니다.
