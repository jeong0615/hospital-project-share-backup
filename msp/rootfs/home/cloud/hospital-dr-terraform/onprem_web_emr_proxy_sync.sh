#!/bin/bash
set -euo pipefail

LOG_FILE="/home/cloud/hospital-dr-terraform/onprem_web_emr_proxy_sync.log"
ONPREM_WEB_SSH="${ONPREM_WEB_SSH:-vboxuser@IP_REDACTED}"
ONPREM_WEB_SSH_KEY="${ONPREM_WEB_SSH_KEY:-/home/cloud/.ssh/dr_key_v2}"
ONPREM_WEB_NODE_UPSTREAM="${ONPREM_WEB_NODE_UPSTREAM:-http://IP_REDACTED:3000}"
ONPREM_DOC_UPSTREAM="${ONPREM_DOC_UPSTREAM:-http://IP_REDACTED:5000}"
OFFICE_EGRESS_IP="${OFFICE_EGRESS_IP:-IP_REDACTED}"
EMR_HEALTH_CHECK_HEADER="${EMR_HEALTH_CHECK_HEADER:-dr-emr-check-2026}"
REMOTE_SITE_PATH="${REMOTE_SITE_PATH:-/etc/nginx/sites-available/hospital-web}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)

exec > >(tee -a "$LOG_FILE") 2>&1

TMP_CONF="$(mktemp /tmp/hospital-web.XXXXXX.conf)"
trap 'rm -f "$TMP_CONF"' EXIT

cat > "$TMP_CONF" <<EOF
map \$http_cf_connecting_ip \$hospital_emr_cf_allowed {
    default 0;
    ${OFFICE_EGRESS_IP} 1;
}

map \$http_x_hospital_dr_check \$hospital_emr_probe_allowed {
    default 0;
    "${EMR_HEALTH_CHECK_HEADER}" 1;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name hospital-web.pp.ua;

    set \$hospital_emr_access_allowed 0;
    if (\$hospital_emr_cf_allowed = 1) {
        set \$hospital_emr_access_allowed 1;
    }
    if (\$hospital_emr_probe_allowed = 1) {
        set \$hospital_emr_access_allowed 1;
    }

    location / {
        proxy_pass ${ONPREM_WEB_NODE_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location = /emr {
        return 301 /emr/;
    }

    location /emr/ {
        if (\$hospital_emr_access_allowed = 0) {
            return 403;
        }
        rewrite ^/emr/(.*)$ /\$1 break;
        proxy_pass ${ONPREM_DOC_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Prefix /emr;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name emr.hospital-web.pp.ua;

    set \$hospital_emr_access_allowed 0;
    if (\$hospital_emr_cf_allowed = 1) {
        set \$hospital_emr_access_allowed 1;
    }
    if (\$hospital_emr_probe_allowed = 1) {
        set \$hospital_emr_access_allowed 1;
    }

    location / {
        if (\$hospital_emr_access_allowed = 0) {
            return 403;
        }
        proxy_pass ${ONPREM_DOC_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

echo "=================================================="
echo "[$(date)] On-premises Web /emr proxy sync started."
echo "[$(date)] 온프레미스 Web /emr 프록시 동기화 시작."
echo "=================================================="
echo "[ONPREM WEB] Installing unified nginx proxy for root Web, /emr/, and emr subdomain."
echo "[온프레 Web] root Web, /emr/, emr 서브도메인 통합 nginx 프록시 설치."

scp -i "$ONPREM_WEB_SSH_KEY" "${SSH_OPTS[@]}" "$TMP_CONF" "${ONPREM_WEB_SSH}:/tmp/hospital-web.nginx.conf"
ssh -n -i "$ONPREM_WEB_SSH_KEY" "${SSH_OPTS[@]}" "$ONPREM_WEB_SSH" "sudo install -m 0644 /tmp/hospital-web.nginx.conf '${REMOTE_SITE_PATH}' && sudo ln -sfn '${REMOTE_SITE_PATH}' /etc/nginx/sites-enabled/hospital-web && sudo rm -f /etc/nginx/sites-enabled/default && sudo nginx -t && sudo systemctl reload nginx"

echo "[ONPREM WEB] Validating local root, /emr/, and emr subdomain proxy endpoints."
echo "[온프레 Web] 로컬 root, /emr/, emr 서브도메인 프록시 엔드포인트 검증."
ssh -n -i "$ONPREM_WEB_SSH_KEY" "${SSH_OPTS[@]}" "$ONPREM_WEB_SSH" "curl -fsS --connect-timeout 5 --max-time 15 http://IP_REDACTED/ >/dev/null && curl -fsS --connect-timeout 5 --max-time 15 -H 'X-Hospital-DR-Check: ${EMR_HEALTH_CHECK_HEADER}' http://IP_REDACTED/emr/ >/dev/null && curl -fsS --connect-timeout 5 --max-time 15 -H 'Host: emr.hospital-web.pp.ua' -H 'X-Hospital-DR-Check: ${EMR_HEALTH_CHECK_HEADER}' http://IP_REDACTED/ >/dev/null"

echo "[ONPREM WEB] On-premises Web /emr proxy sync completed."
echo "[온프레 Web] 온프레미스 Web /emr 프록시 동기화 완료."
echo "=================================================="
