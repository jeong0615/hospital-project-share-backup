#!/usr/bin/env bash
set -u

# This script is executed on an existing DR EC2 through SSM.  It deliberately
# does not open listeners, change security groups, or install a Docker socket
# mount.  It is safe to run repeatedly and reports component state without
# printing credentials, enrollment keys, or environment files.

ROLE="${AWS_DR_ROLE:-}"
HOSTNAME_VALUE="${AWS_DR_HOSTNAME:-}"
ZABBIX_ACTIVE_SERVER="${ZABBIX_ACTIVE_SERVER:-}"
WAZUH_MANAGER="${WAZUH_MANAGER:-}"
ZABBIX_EXTERNAL_PATH_ENABLED="${AWS_ZABBIX_EXTERNAL_PATH_ENABLED:-false}"
WAZUH_EXTERNAL_PATH_ENABLED="${AWS_WAZUH_EXTERNAL_PATH_ENABLED:-false}"
WAZUH_AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.8.0-1}"

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

if ! is_true "$ZABBIX_EXTERNAL_PATH_ENABLED" || ! is_true "$WAZUH_EXTERNAL_PATH_ENABLED"; then
  echo "RESULT status=DISABLED reason=MSP_BEHIND_UNCONTROLLED_UPSTREAM_NAT"
  echo "CONFIG_AVAILABLE=YES LIVE_PATH_ENABLED=NO"
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "RESULT status=FAIL reason=ROOT_REQUIRED"
  exit 2
fi

case "$ROLE" in
  web|emr|db) ;;
  *) echo "RESULT status=FAIL reason=INVALID_ROLE"; exit 2 ;;
esac

if [ -z "$HOSTNAME_VALUE" ] || [ -z "$ZABBIX_ACTIVE_SERVER" ] || [ -z "$WAZUH_MANAGER" ]; then
  echo "RESULT status=FAIL reason=REQUIRED_ENDPOINT_MISSING"
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
zabbix_status=NOT_ATTEMPTED
wazuh_status=NOT_ATTEMPTED
docker_status=NOT_APPLICABLE

if apt-get update -qq && apt-get install -y -qq ca-certificates curl gnupg zabbix-agent >/dev/null; then
  zabbix_status=PACKAGE_READY
else
  zabbix_status=PACKAGE_INSTALL_FAILED
fi

if [ "$zabbix_status" = PACKAGE_READY ]; then
  install -d -m 0755 /usr/local/sbin
  cat > /usr/local/sbin/hospital-dr-health-check <<'HEALTH'
#!/usr/bin/env bash
set -u
role="${AWS_DR_ROLE:-unknown}"
case "$role" in
  web)
    systemctl is-active --quiet nginx && docker inspect --format '{{.State.Health.Status}}' hospital-dr-web 2>/dev/null | grep -qx healthy
    ;;
  emr)
    systemctl is-active --quiet apache2 && docker inspect --format '{{.State.Health.Status}}' hospital-dr-emr 2>/dev/null | grep -qx healthy
    ;;
  db)
    systemctl is-active --quiet mysql && ss -ltnH 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:3306([[:space:]]|$)'
    ;;
  *) exit 1 ;;
esac
HEALTH
  chmod 0755 /usr/local/sbin/hospital-dr-health-check

  cat > /usr/local/sbin/hospital-dr-docker-health <<'DOCKER_HEALTH'
#!/usr/bin/env bash
set -u
role="${AWS_DR_ROLE:-unknown}"
case "$role" in
  web) name=hospital-dr-web ;;
  emr) name=hospital-dr-emr ;;
  *) exit 1 ;;
esac
docker inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null | grep -qx healthy
DOCKER_HEALTH
  chmod 0755 /usr/local/sbin/hospital-dr-docker-health

  cat > /usr/local/sbin/hospital-dr-docker-restarts <<'DOCKER_RESTARTS'
#!/usr/bin/env bash
set -u
role="${AWS_DR_ROLE:-unknown}"
case "$role" in
  web) name=hospital-dr-web ;;
  emr) name=hospital-dr-emr ;;
  *) exit 1 ;;
esac
docker inspect --format '{{.RestartCount}}' "$name" 2>/dev/null || echo 0
DOCKER_RESTARTS
  chmod 0755 /usr/local/sbin/hospital-dr-docker-restarts

  python3 - "$HOSTNAME_VALUE" "$ZABBIX_ACTIVE_SERVER" "$ROLE" <<'PY'
import re
import sys
from pathlib import Path

hostname, active_server, role = sys.argv[1:]
path = Path("/etc/zabbix/zabbix_agentd.conf")
text = path.read_text(encoding="utf-8") if path.exists() else ""
settings = {
    "Server": "IP_REDACTED",
    "ServerActive": active_server,
    "Hostname": hostname,
    "HostMetadata": "aws-dr-monitoring",
    "ListenIP": "IP_REDACTED",
    "RefreshActiveChecks": "60",
    "Timeout": "5",
}
for key, value in settings.items():
    pattern = re.compile(rf"(?m)^\s*#?\s*{re.escape(key)}\s*=.*$" )
    replacement = f"{key}={value}"
    if pattern.search(text):
        text = pattern.sub(replacement, text, count=1)
    else:
        text += f"\n{replacement}\n"
parameters = [
    "UserParameter=hospital.dr.health,/usr/local/sbin/hospital-dr-health-check",
]
if role in {"web", "emr"}:
    parameters += [
        "UserParameter=hospital.dr.docker.health,/usr/local/sbin/hospital-dr-docker-health",
        "UserParameter=hospital.dr.docker.restarts,/usr/local/sbin/hospital-dr-docker-restarts",
    ]
for parameter in parameters:
    if parameter not in text:
        text += f"\n{parameter}\n"
path.write_text(text, encoding="utf-8")
PY
  if systemctl enable --now zabbix-agent >/dev/null 2>&1; then
    zabbix_status=ACTIVE_CONFIGURED
  else
    zabbix_status=CONFIGURED_SERVICE_FAILED
  fi
fi

if apt-get install -y -qq lsb-release >/dev/null \
  && install -d -m 0755 /etc/apt/keyrings \
  && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
       | gpg --dearmor --yes -o /etc/apt/keyrings/wazuh.gpg \
  && printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
       > /etc/apt/sources.list.d/wazuh.list \
  && apt-get update -qq; then
  wazuh_candidate="$(apt-cache madison wazuh-agent | awk -v wanted="$WAZUH_AGENT_VERSION" '$3 == wanted {print $3; exit}')"
  if [ -n "$wazuh_candidate" ] && apt-get install -y -qq "wazuh-agent=$wazuh_candidate" >/dev/null; then
    wazuh_status=PACKAGE_READY
  else
    wazuh_status=PACKAGE_VERSION_UNAVAILABLE
  fi
else
  wazuh_status=REPOSITORY_UNAVAILABLE
fi

if [ "$wazuh_status" = PACKAGE_READY ]; then
  python3 - "$HOSTNAME_VALUE" "$WAZUH_MANAGER" "$ROLE" <<'PY'
import re
import sys
from pathlib import Path

hostname, manager, role = sys.argv[1:]
path = Path("/var/ossec/etc/ossec.conf")
text = path.read_text(encoding="utf-8") if path.exists() else "<ossec_config>\n</ossec_config>\n"
text = re.sub(
    r"\n?<!-- hospital-dr-aws-monitoring -->.*?<!-- /hospital-dr-aws-monitoring -->\n?",
    "\n",
    text,
    flags=re.DOTALL,
)
client = (
    "<!-- hospital-dr-aws-monitoring -->\n"
    "<client>\n"
    f"  <server><address>{manager}</address><port>1514</port><protocol>tcp</protocol></server>\n"
    "  <notify_time>10</notify_time>\n"
    "  <time-reconnect>60</time-reconnect>\n"
    "  <auto_restart>yes</auto_restart>\n"
    "</client>\n"
)
if re.search(r"<client\b", text):
    text = re.sub(r"<client\b.*?</client>", client.rstrip(), text, count=1, flags=re.DOTALL)
else:
    text = text.replace("</ossec_config>", client + "</ossec_config>", 1)

paths = ["/etc", "/etc/ssh"]
if role == "web":
    paths += ["/etc/nginx", "/etc/docker"]
elif role == "emr":
    paths += ["/etc/apache2", "/etc/docker"]
else:
    paths += ["/etc/mysql"]
match = re.search(r"(<syscheck\b[^>]*>)(.*?)(</syscheck>)", text, flags=re.DOTALL)
if match:
    body = match.group(2)
    additions = "".join(
        f"\n    <directories check_all=\"yes\">{item}</directories>"
        for item in paths
        if item not in body
    )
    text = text[:match.start(2)] + body + additions + text[match.end(2):]

localfiles = [
    "  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>",
]
if role in {"web", "emr"}:
    localfiles.append(
        "  <localfile><log_format>json</log_format><location>/var/log/hospital-dr/docker-events.json</location></localfile>"
    )
block = "\n".join(
    ["  <!-- hospital-dr-aws-monitoring-localfiles -->", *localfiles, "  <!-- /hospital-dr-aws-monitoring-localfiles -->"]
)
text = re.sub(
    r"\n?\s*<!-- hospital-dr-aws-monitoring-localfiles -->.*?<!-- /hospital-dr-aws-monitoring-localfiles -->\n?",
    "\n",
    text,
    flags=re.DOTALL,
)
text = text.replace("</ossec_config>", block + "\n</ossec_config>", 1)
path.write_text(text, encoding="utf-8")
PY

  if [ ! -s /var/ossec/etc/client.keys ] || ! grep -Fq "|${HOSTNAME_VALUE}|" /var/ossec/etc/client.keys; then
    systemctl stop wazuh-agent >/dev/null 2>&1 || true
    if timeout 25 /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -p 1515 -A "$HOSTNAME_VALUE" >/dev/null 2>&1; then
      wazuh_status=ENROLLED
    else
      wazuh_status=ENROLLMENT_BLOCKED
    fi
  else
    wazuh_status=ALREADY_ENROLLED
  fi
  if systemctl enable --now wazuh-agent >/dev/null 2>&1; then
    case "$wazuh_status" in
      ENROLLED|ALREADY_ENROLLED) wazuh_status=ACTIVE_CONFIGURED ;;
    esac
  else
    wazuh_status=CONFIGURED_SERVICE_FAILED
  fi
fi

if [ "$ROLE" = web ] || [ "$ROLE" = emr ]; then
  if command -v docker >/dev/null 2>&1; then
    install -d -m 0750 -o root -g root /var/log/hospital-dr
    touch /var/log/hospital-dr/docker-events.json
    chmod 0640 /var/log/hospital-dr/docker-events.json
    cat > /usr/local/sbin/hospital-dr-docker-events <<'EVENTS'
#!/usr/bin/env bash
set -u
exec /usr/bin/docker events \
  --filter container=hospital-dr-web \
  --filter container=hospital-dr-emr \
  --format '{{json .}}'
EVENTS
    chmod 0755 /usr/local/sbin/hospital-dr-docker-events
    cat > /etc/systemd/system/hospital-dr-docker-events.service <<'UNIT'
[Unit]
Description=Hospital DR Docker security event stream
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/hospital-dr-docker-events
Restart=always
RestartSec=5
StandardOutput=append:/var/log/hospital-dr/docker-events.json
StandardError=journal
User=root
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable --now hospital-dr-docker-events.service >/dev/null 2>&1; then
      docker_status=ACTIVE_CONFIGURED
    else
      docker_status=CONFIGURED_SERVICE_FAILED
    fi
  else
    docker_status=DOCKER_NOT_INSTALLED
  fi
fi

if [ "$zabbix_status" = ACTIVE_CONFIGURED ] || [ "$zabbix_status" = CONFIGURED_SERVICE_FAILED ]; then
  zabbix_result=PASS
else
  zabbix_result=BLOCKED
fi
if [ "$wazuh_status" = ACTIVE_CONFIGURED ]; then
  wazuh_result=PASS
elif [ "$wazuh_status" = ENROLLMENT_BLOCKED ] || [ "$wazuh_status" = REPOSITORY_UNAVAILABLE ]; then
  wazuh_result=BLOCKED_NETWORK
else
  wazuh_result=BLOCKED
fi
echo "RESULT role=$ROLE zabbix=$zabbix_result zabbix_detail=$zabbix_status wazuh=$wazuh_result wazuh_detail=$wazuh_status docker=$docker_status"
exit 0
