# Monitoring

Web Server Zabbix Agent → Team Central Zabbix Server.

직접 확인: package zabbix-agent 1:5.0.17+dfsg-1, binary 5.0.17, service zabbix-agent active/running/enabled. `/etc/zabbix/zabbix_agentd.conf`: Server=IP_REDACTED, ServerActive=IP_REDACTED, Hostname=web_sever, Include=/etc/zabbix/zabbix_agentd.conf.d/*.conf. include 디렉터리에 수집 대상 conf는 없었습니다. TCP10050 IPv4/IPv6 listener 관측.

Unit은 `/lib/systemd/system/zabbix-agent.service`, 상세 실행 명령/User/EnvironmentFile은 복사 unit과 service-summary를 참고합니다. OS hostname과 Agent Hostname 차이는 중앙 등록값을 확인하기 전 수정하지 않습니다.

중앙 Zabbix 운영자는 팀 담당자입니다. 중앙 전체 config/dashboard/trigger/action/DB/Slack webhook/관리자 계정을 수집하거나 추측하지 않았습니다. Agent active 상태와 listen은 중앙 수집 성공의 증거가 아닙니다. 중앙 UI의 해당 Host availability/latest data 증빙은 수동 추가해야 합니다.

앱 `/check/zabbix`는 API 버전 확인 코드일 뿐 Agent 등록 상태를 확인하지 않습니다. 미마운트 routes/check.js의 관리자 로그인 코드도 현재 연동 구조로 설명하지 않습니다.
