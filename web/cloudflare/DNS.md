# 최종 DNS 컨텍스트

출처: 사용자 제공. 관리 콘솔/API 조회 증빙은 미수집.

| 상태 | Type | Name | Content | Proxy |
|---|---|---|---|---|
| 정상/Failback | CNAME | hospital-web.pp.ua | e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com | true |
| Failover | A | hospital-web.pp.ua | IP_REDACTED | 전환 시 운영자 확인; 기존 proxied 정책 유지 여부 검증 |

Zone SSL Full, hostname Rule hospital-web-strict는 Strict. 공용 TLS 종료는 Cloudflare Edge. proxied DNS의 공용 A/AAAA 응답만으로 원래 CNAME content나 Rule 설정을 증명할 수 없습니다.
