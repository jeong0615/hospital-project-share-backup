# Failover / Failback

최종 외부 컨텍스트에 따른 수동 운영 절차 템플릿입니다. 이번 작업에서 DNS/API/AWS를 변경하지 않았습니다.

Failover:
1. 실제 장애와 임시 GNS3 OFF/NAT 수집 상태를 구분합니다. DNS 기존 값과 장애 시각을 기록합니다.
2. AWS DR EIP AWS_PUBLIC_IP_REDACTED의 Web 프로세스/Nginx/DB·EMR 연결 및 Hostname 요청 처리, origin TLS를 검증합니다. 실제 AWS backend/HTTPS 설정은 아직 미수집입니다. Strict Rule 조건에 맞는 TLS 준비가 없으면 전환 성공을 가정하지 않습니다.
3. 운영자가 hospital-web.pp.ua의 Tunnel CNAME을 A IP_REDACTED으로 전환하고 Proxy 및 SSL Rule 상태를 확인합니다. TTL/전파 시간은 실제 설정을 기록합니다.
4. 외부 클라이언트에서 공용 HTTPS, 메인/로그인, `/health`, `/check/db`, `/emr/`을 확인합니다. Cloudflare 응답만으로 AWS origin 도달을 단정하지 않고 origin 로그 또는 신뢰할 수 있는 배포 식별값을 별도 확인합니다. 세션 재로그인을 고려합니다.
5. DB 데이터 일관성, 중앙 모니터링, 장애 전환 시각 및 소요시간을 기록하고 비식별 증빙을 추가합니다.

Failback:
1. 온프레미스의 IP/Gateway/ACL/DB·EMR/Tunnel 및 health를 먼저 검증합니다.
2. DR에서 발생한 쓰기의 동기화·복원 방향을 DB 담당자가 확정합니다. 자동 복제 구성을 가정하지 않습니다.
3. 운영자가 A를 CNAME `e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com`, Proxy=true로 복원합니다.
4. 여러 외부 위치의 HTTPS와 origin 식별/DB·EMR, 중앙 모니터링을 확인하고 실패 시 기록한 이전 DNS 상태로 되돌릴지 판단합니다.

실제 외부 전환 증빙, RTO/RPO, DR backend 설정은 MISSING_ITEMS입니다. 지금은 전환 테스트 통과를 선언하지 않습니다.
