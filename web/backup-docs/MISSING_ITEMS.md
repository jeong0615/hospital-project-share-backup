# 수동 입력/추가 검증

Web 밖의 값은 추측하지 않습니다. 보호된 로컬 파일 미수집도 포함합니다. Secret/VM/IOS/DB dump는 Git에 넣지 않고 별도 보관 위치·복구 절차만 기록하세요.

- [ ] Cisco 2800 running-config 및 show 결과
- [ ] Cisco 2950 running-config 및 show 결과
- [ ] Cisco 3550 running-config 및 show 결과
- [ ] Cisco 3560 최종 running-config 및 show 결과
- [ ] show vlan brief / interfaces trunk / etherchannel summary / spanning-tree / standby brief / ip route / access-lists
- [ ] GNS3 Project, GNS L3 running-config, WEB-IN, SERVER-IN, Cloud Node 정보
- [ ] 전체 Physical Port Map
- [ ] 중앙 Zabbix에서 Web Agent 등록/최신 수집 외부 확인 자료
- [ ] DR Failover/Failback 실제 외부 검증 자료 및 AWS backend/origin TLS/복제/RPO/RTO
- [ ] 개인 Secret 원본 (Git 외부 보관만; 저장소에 추가 금지)
- [ ] 필요 시 VM OVA/VDI (Git 외부 대용량 백업)
- [ ] Cisco IOS 원본 (Git 외부 보관)
- [ ] DB 전체 schema 및 필요 시 dump (Git 외부 안전 보관)
- [ ] Netplan /etc/netplan/01-netcfg.yaml의 민감값 제거본: 읽기 권한 제한
- [ ] 권한 있는 nginx -T 전체 안전한 출력: sudo 비밀번호 요구
- [ ] wg0의 목적/최종 구성 포함 여부
- [ ] Cloudflare DNS Proxy/Zone SSL/Configuration Rule의 비밀값 없는 관리 증빙
- [ ] GNS3 ON 환경에서 DB/EMR/ACL 재검증 및 HTTPS 세션·쓰기 기능 검증
