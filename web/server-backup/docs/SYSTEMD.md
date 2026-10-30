# Application process manager 및 서비스

실제 프로세스 관리는 systemd. hospital-web/cloudflared/zabbix-agent/nginx 모두 active/running/enabled로 관측. 각 unit 원문은 configs/systemd, 실행 시점 속성은 inventory/service-summary.txt에 보관합니다. 서비스 상태 조회에 runtime log 본문은 저장하지 않았습니다.

hospital-web: User=root, WorkingDirectory=/home/vboxuser/hospital-web, EnvironmentFile=/home/vboxuser/hospital-web/.env, ExecStart=/usr/bin/node /home/vboxuser/hospital-web/app.js, Restart=always. `.env` 내용은 제외.
cloudflared: ExecStart=/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run, User/WorkingDirectory 미명시. config의 credential 참조만 placeholder.
Zabbix/Nginx: 배포판 unit을 수집. 실제 User, EnvironmentFile 구조는 해당 unit을 그대로 읽어 확인할 수 있습니다. 선택한 네 unit의 DropInPaths는 비어 있었습니다.

실행 시점 상태는 수집 시점 스냅샷입니다. Environment 값 전체나 프로세스 전체 command line, journal log는 수집하지 않았습니다. 복구는 새 서버에서만 적용하며 systemctl daemon-reload/enable/start는 이번에 실행하지 않았습니다.
