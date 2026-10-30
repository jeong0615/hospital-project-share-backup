#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Synchronize the selected MSP source paths into this msp/rootfs tree, capture
# non-secret host inventories, and report high-confidence secret patterns.
# This script intentionally never runs git add/commit/push.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ROOTFS="$SCRIPT_DIR/rootfs"
INVENTORY="$SCRIPT_DIR/inventory"
SOURCE_HOME="${MSP_BACKUP_SOURCE_HOME:-/home/cloud}"
SOURCE_ETC="${MSP_BACKUP_SOURCE_ETC:-/etc}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[ERROR] required command is missing: %s\n' "$1" >&2
    exit 1
  fi
}

require_command rsync
require_command rg
require_command perl

mkdir -p "$ROOTFS/home/cloud" "$ROOTFS/etc/systemd/system" "$INVENTORY"

COMMON_EXCLUDES=(
  '--include=**/.env.example'
  '--include=**/*.example.tfvars'
  '--include=**/*.tfvars.example'
  '--exclude=**/.git/'
  '--exclude=**/.aws/'
  '--exclude=**/.ssh/'
  '--exclude=**/.docker/'
  '--exclude=**/.terraform/'
  '--exclude=**/node_modules/'
  '--exclude=**/.npm/'
  '--exclude=**/.cache/'
  '--exclude=**/__pycache__/'
  '--exclude=**/venv/'
  '--exclude=**/.venv/'
  '--exclude=*.pyc'
  '--exclude=*.log'
  '--exclude=*.jsonl'
  '--exclude=*.pre-*'
  '--exclude=*.sqlite'
  '--exclude=*.sqlite3'
  '--exclude=*.db'
  '--exclude=*.db-*'
  '--exclude=*.env'
  '--exclude=**/.env'
  '--exclude=**/.env.*'
  '--exclude=*.pem'
  '--exclude=*.key'
  '--exclude=*.secret'
  '--exclude=*.csr'
  '--exclude=*.crt'
  '--exclude=*.sql'
  '--exclude=*.dump'
  '--exclude=*.enc'
  '--exclude=*.zip'
  '--exclude=*.tar'
  '--exclude=*.tar.gz'
  '--exclude=*.deb'
  '--exclude=*.tfstate'
  '--exclude=*.tfstate.*'
  '--exclude=*.tfvars'
  '--exclude=**/*.bak'
  '--exclude=**/*.bak-*'
  '--exclude=**/*.orig'
  '--exclude=**/*~'
  '--exclude=.bash_history'
  '--exclude=.wget-hsts'
  '--exclude=**/db_backups/'
  '--exclude=**/config-backups/'
  '--exclude=**/backup/'
  '--exclude=**/backups/'
  '--exclude=**/*backup*/'
  '--exclude=**/*legacy*/'
)

sync_tree() {
  local source_path="$1"
  local destination_path="$2"
  shift 2

  if [[ ! -d "$source_path" ]]; then
    printf '[SKIP] source directory is absent: %s\n' "$source_path"
    return 0
  fi

  mkdir -p "$destination_path"
  rsync -a --delete --delete-excluded "${COMMON_EXCLUDES[@]}" "$@" \
    "$source_path/" "$destination_path/"
  printf '[OK] synced %s\n' "$source_path"
}

sync_file() {
  local source_path="$1"
  local destination_path="$2"

  if [[ ! -f "$source_path" ]]; then
    printf '[SKIP] source file is absent: %s\n' "$source_path"
    return 0
  fi

  mkdir -p "$(dirname -- "$destination_path")"
  rsync -a "$source_path" "$destination_path"
  printf '[OK] copied %s\n' "$source_path"
}

# Canonical working source. hospital-dr-repo may contain uncommitted changes;
# those files are intentionally copied as-is without touching its .git state.
sync_tree "$SOURCE_HOME/hospital-dr-repo" \
  "$ROOTFS/home/cloud/hospital-dr-repo"

# Keep the current Codex documentation used by MSP operations. The duplicate
# checkout is selected by recovery-relevant subtrees only; its .git and local
# runtime state are never mirrored.
sync_tree "$SOURCE_HOME/hospital-dr-codex/docs" \
  "$ROOTFS/home/cloud/hospital-dr-codex/docs"

# These Codex subtrees are referenced by the running MSP systemd units and are
# required to reconstruct the current automation contract. Common filters
# remove local state, credentials, generated artifacts, and old backups.
sync_tree "$SOURCE_HOME/hospital-dr-codex/automation" \
  "$ROOTFS/home/cloud/hospital-dr-codex/automation" \
  '--exclude=**/firebase_backup.json'

sync_tree "$SOURCE_HOME/hospital-dr-codex/infra" \
  "$ROOTFS/home/cloud/hospital-dr-codex/infra" \
  '--exclude=**/wireguard-*/'

sync_tree "$SOURCE_HOME/hospital-dr-codex/operations" \
  "$ROOTFS/home/cloud/hospital-dr-codex/operations"

sync_tree "$SOURCE_HOME/hospital-dr-codex/monitoring" \
  "$ROOTFS/home/cloud/hospital-dr-codex/monitoring" \
  '--exclude=**/data/'

# Keep the repository-level security and ignore policy referenced by the
# copied CI workflow. The unrelated shell artifact at the checkout root is
# intentionally not selected.
sync_file "$SOURCE_HOME/hospital-dr-codex/.gitignore" \
  "$ROOTFS/home/cloud/hospital-dr-codex/.gitignore"
sync_file "$SOURCE_HOME/hospital-dr-codex/.gitleaks.toml" \
  "$ROOTFS/home/cloud/hospital-dr-codex/.gitleaks.toml"

# Keep Codex CI workflows without mirroring the duplicate checkout or its
# dependency/runtime directories.
sync_tree "$SOURCE_HOME/hospital-dr-codex/.github/workflows" \
  "$ROOTFS/home/cloud/hospital-dr-codex/.github/workflows"

# Keep Ansible orchestration and its active deployment payload paths. Some
# payload files overlap with hospital-dr-repo, but their Ansible path is part
# of the recoverable deployment contract; common filters remove secrets/data.
sync_tree "$SOURCE_HOME/hospital-dr-ansible" \
  "$ROOTFS/home/cloud/hospital-dr-ansible" \
  '--exclude=**/firebase_backup.json'

# Keep Terraform source/modules/policies/systemd templates, never providers,
# state, tfvars, or WireGuard key directories.
sync_tree "$SOURCE_HOME/hospital-dr-terraform" \
  "$ROOTFS/home/cloud/hospital-dr-terraform" \
  '--exclude=**/.nat-schedule-enabled' \
  '--exclude=**/wireguard-*/'

# Keep declarative Grafana provisioning and compose configuration, not its
# local database/data directory.
sync_tree "$SOURCE_HOME/grafana" \
  "$ROOTFS/home/cloud/grafana" \
  '--exclude=**/data/'

# The Zabbix runtime has live .env files and data volumes; the compose file is
# the non-secret reconstruction input needed here.
sync_file "$SOURCE_HOME/zabbix/docker-compose.yml" \
  "$ROOTFS/home/cloud/zabbix/docker-compose.yml"

# Wazuh deployment source is useful for reconstruction, but generated certs,
# password hashes, .env files and runtime data are intentionally omitted.
sync_tree "$SOURCE_HOME/wazuh-docker" \
  "$ROOTFS/home/cloud/wazuh-docker" \
  '--exclude=**/config/wazuh_indexer_ssl_certs/' \
  '--exclude=**/internal_users.yml' \
  '--exclude=**/certs/' \
  '--exclude=**/data/'

sanitize_wazuh_templates() {
  local wazuh_root="$ROOTFS/home/cloud/wazuh-docker"
  local compose
  local dashboard_config

  # The upstream example compose files contain default credentials. Replace
  # only the backup copies with explicit secret-store references; the source
  # checkout is never edited.
  for compose in \
    "$wazuh_root/single-node/docker-compose.yml" \
    "$wazuh_root/multi-node/docker-compose.yml"; do
    if [[ -f "$compose" ]]; then
      sed -E -i \
        -e 's/^([[:space:]]*-[[:space:]]*INDEXER_PASSWORD=).*/\1${WAZUH_INDEXER_PASSWORD:?set-in-secret-store}/' \
        -e 's/^([[:space:]]*-[[:space:]]*API_PASSWORD=).*/\1${WAZUH_API_PASSWORD:?set-in-secret-store}/' \
        -e 's/^([[:space:]]*-[[:space:]]*DASHBOARD_PASSWORD=).*/\1${WAZUH_DASHBOARD_PASSWORD:?set-in-secret-store}/' \
        "$compose"
    fi
  done

  for dashboard_config in \
    "$wazuh_root/single-node/config/wazuh_dashboard/wazuh.yml" \
    "$wazuh_root/multi-node/config/wazuh_dashboard/wazuh.yml"; do
    if [[ -f "$dashboard_config" ]]; then
      sed -E -i \
        's/^([[:space:]]*password:[[:space:]]*).*/\1"<SET_IN_SECRET_STORE>"/' \
        "$dashboard_config"
    fi
  done

  if [[ -f "$wazuh_root/README.md" ]]; then
    sed -E -i \
      -e 's/^([[:space:]]*API_PASSWORD=).*/\1<SET_IN_SECRET_STORE>/' \
      -e 's/^([[:space:]]*INDEXER_PASSWORD=).*/\1<SET_IN_SECRET_STORE>/' \
      -e 's/^([[:space:]]*DASHBOARD_PASSWORD=).*/\1<SET_IN_SECRET_STORE>/' \
      "$wazuh_root/README.md"
  fi
}

sanitize_wazuh_templates

sanitize_emr_templates() {
  local file

  # The MSP backup contains deployment copies of EMR source. Keep those
  # copies useful for recovery without carrying inline DB/test passwords.
  while IFS= read -r -d '' file; do
    sed -E -i \
      's/(password:[[:space:]]*process\.env\.DB_PASSWORD)[[:space:]]*\|\|[[:space:]]*[^,]+/\1/g' \
      "$file"
  done < <(find "$ROOTFS" -type f -path '*/emr/backend/db.js' -print0)

  while IFS= read -r -d '' file; do
    sed -E -i -e \
      's#^[[:space:]]*// 비밀번호가 .*#    // 환경변수 기반 테스트 계정일 때 임시 계정으로 로그인 처리#' \
      -e "s/(password[[:space:]]*===[[:space:]]*)('[^']*'|\"[^\"]*\")/\1process.env.EMR_TEST_ACCOUNT_PASSWORD/g" \
      -e "s/if \(testUsers\[login_id\] && password === process\.env\.EMR_TEST_ACCOUNT_PASSWORD\)/if (testUsers[login_id] \&\& process.env.EMR_TEST_ACCOUNT_PASSWORD \&\& password === process.env.EMR_TEST_ACCOUNT_PASSWORD)/" \
      "$file"
  done < <(find "$ROOTFS" -type f -path '*/emr/backend/auth.js' -print0)
}

sanitize_emr_templates

# The running ChatOps project is separate from the repository checkout. Keep
# source code only; SQLite/audit/venv state is runtime data.
sync_tree "$SOURCE_HOME/dr_project" \
  "$ROOTFS/home/cloud/dr_project" \
  '--exclude=**/audit/'

sync_tree "$SOURCE_HOME/scripts" \
  "$ROOTFS/home/cloud/scripts" \
  '--exclude=*.before-*'

# Only MSP-specific local units are copied from /etc. No /etc-wide mirror is
# attempted, and symlinks in *.wants are represented by enabled-services.txt.
SYSTEMD_UNITS=(
  hospital-dr-chatops-ngrok.service
  hospital-dr-chatops.service
  hospital-dr-environment.service
  hospital-dr-nat-disable.service
  hospital-dr-nat-disable.timer
  hospital-dr-nat-enable.service
  hospital-dr-nat-enable.timer
  hospital-dr-nat-shutdown.service
  hospital-dr-s3-upload.service
  hospital-dr-s3-upload.timer
  hospital-dr-zabbix-proxy.service
)
for unit in "${SYSTEMD_UNITS[@]}"; do
  sync_file "$SOURCE_ETC/systemd/system/$unit" \
    "$ROOTFS/etc/systemd/system/$unit"
done

capture_command() {
  local label="$1"
  local output_path="$2"
  shift 2

  {
    printf '# %s\n' "$label"
    if "$@"; then
      :
    else
      printf '# command unavailable or failed on this host\n'
    fi
  } > "$output_path" 2>/dev/null
}

capture_command 'dpkg --get-selections' \
  "$INVENTORY/packages.txt" dpkg --get-selections
capture_command 'apt-mark showmanual' \
  "$INVENTORY/manual-packages.txt" apt-mark showmanual
capture_command 'systemctl list-unit-files --state=enabled' \
  "$INVENTORY/enabled-services.txt" \
  systemctl list-unit-files --state=enabled --no-legend --no-pager
capture_command 'systemctl --type=service --state=running' \
  "$INVENTORY/running-services.txt" \
  systemctl --type=service --state=running --no-legend --no-pager
capture_command 'ss -lntu (listening sockets; process details omitted)' \
  "$INVENTORY/listening-sockets.txt" ss -lntu
capture_command 'docker ps -a (name, image, status only)' \
  "$INVENTORY/docker-containers.txt" \
  docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
capture_command 'docker images (repository, tag, id only)' \
  "$INVENTORY/docker-images.txt" \
  docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}'
capture_command 'docker network ls' \
  "$INVENTORY/docker-networks.txt" docker network ls
capture_command 'docker volume ls' \
  "$INVENTORY/docker-volumes.txt" docker volume ls

{
  printf '# Basic host information captured for reconstruction\n'
  if [[ -r /etc/os-release ]]; then
    awk -F= '/^(PRETTY_NAME|VERSION_ID)=/ {gsub(/^"|"$/, "", $2); print $1 "=" $2}' \
      /etc/os-release
  fi
  uname -a
} > "$INVENTORY/system-info.txt"

sanitize_sensitive_file() {
  local file="$1"
  local mode dir dir_mode status=0

  # The synchronized tree can preserve read-only source modes. Temporarily
  # make only the backup copy writable, then restore both file and directory
  # modes after redaction. The source checkout is never touched.
  mode="$(stat -c '%a' "$file")"
  dir="$(dirname -- "$file")"
  dir_mode="$(stat -c '%a' "$dir")"
  chmod u+w "$dir" "$file"

  if ! perl -0pi -e '
    # Remove complete private-key blocks before handling line-oriented values.
    s{-----BEGIN[[:space:]]+(?:[A-Z0-9]+[[:space:]]+)?PRIVATE KEY-----.*?-----END[[:space:]]+(?:[A-Z0-9]+[[:space:]]+)?PRIVATE KEY-----}{PRIVATE_KEY_REDACTED}gs;

    # Remove well-known bearer/token prefixes wherever they occur.
    s{\b(?:AKIA|ASIA)[0-9A-Z]{16}\b}{AWS_ACCESS_KEY_ID_REDACTED}g;
    s{\bxox[baprs]-[0-9A-Za-z-]{10,}\b}{SLACK_TOKEN_REDACTED}g;
    s{\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b}{GITHUB_TOKEN_REDACTED}g;
    s{\bgithub_pat_[A-Za-z0-9_]{20,}\b}{GITHUB_TOKEN_REDACTED}g;
    s{\bBearer[[:space:]]+[A-Za-z0-9._~+\/-=]{12,}\b}{Bearer TOKEN_REDACTED}gi;

    # Replace quoted and bare literal values assigned to sensitive names.
    # Environment/secret-store references and existing placeholders remain.
    s{
      (\b(?:AWS|CLOUDFLARE|CF|SLACK|GITHUB|DB|CHATOPS)?[_-]?(?:ACCESS[-_]KEY(?:[-_]ID)?|SECRET[-_]ACCESS[-_]KEY|SESSION[-_]TOKEN|API[-_]KEY|TOKEN|SECRET|PASSWORD|PASSWD|CLIENT[-_]SECRET|SIGNING[-_]SECRET|CREDENTIALS?|PRIVATE[-_]KEY)\b["\x27]?\s*[:=]\s*)
      (["\x27])
      (?!\s*(?:\$|<|>|var\.|lookup\(|reference\(|getenv|environ|process\.env|secret[_-]?store|placeholder|example|redact|set[_-]?in))
      [^"\x27\r\n]{8,}
      \2
    }{$1$2<SET_IN_SECRET_STORE>$2}igx;
    s{
      (\b(?:AWS|CLOUDFLARE|CF|SLACK|GITHUB|DB|CHATOPS)?[_-]?(?:ACCESS[-_]KEY(?:[-_]ID)?|SECRET[-_]ACCESS[-_]KEY|SESSION[-_]TOKEN|API[-_]KEY|TOKEN|SECRET|PASSWORD|PASSWD|CLIENT[-_]SECRET|SIGNING[-_]SECRET|CREDENTIALS?|PRIVATE[-_]KEY)\b["\x27]?\s*[:=]\s*)
      (?!["\x27]|\s*(?:\$|<|>|var\.|lookup\(|reference\(|getenv|environ|process\.env|secret[_-]?store|placeholder|example|redact|set[_-]?in|[A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[)|[A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]*\s*(?:,|\)|\}|\]|$)))
      [A-Za-z0-9][A-Za-z0-9!\@#%^&*+=:.:\/_?~\-]{11,}
    }{$1"<SET_IN_SECRET_STORE>"}igx;

    # Redact literal AWS S3 buckets and ARNs, but leave dynamic Terraform or
    # secret-store expressions intact.
    my @lines = split(/\n/, $_, -1);
    for my $line (@lines) {
      if ($line !~ /\$\{|\b(?:var|lookup|reference)\./i && $line !~ /[{}]/) {
        $line =~ s{\bs3://[A-Za-z0-9.!_-]{3,}}{s3://S3_BUCKET_REDACTED}gi;
        $line =~ s~\barn:aws:[A-Za-z0-9][A-Za-z0-9:/_.+\-*=,\@{}]*~AWS_ARN_REDACTED~g;
      }

      # Account IDs are not credentials, but are infrastructure identifiers
      # that should not be published as literal AWS deployment values.
      if ($line =~ /aws|amazonaws|account[ _-]*id|role[ _-]*arn|iam|caller[ _-]*identity|(?:i|ami|vpc|subnet|sg|eni|igw|nat|rtb|vol|eipalloc|eipassoc|snap)-[0-9a-f]{8,17}/i &&
          $line !~ /\$\{|\b(?:var|lookup|reference)\./i && $line !~ /[{}]/) {
        $line =~ s{(?<!\d)\d{12}(?!\d)}{AWS_ACCOUNT_ID_REDACTED}g;
      }

      # These identifiers are AWS-specific even when a nearby comment or
      # example omits the word AWS, so redact them unconditionally.
      $line =~ s{(?<![A-Za-z0-9])(?:i|ami|vpc|subnet|sg|eni|igw|nat|rtb|vol|eipalloc|eipassoc|snap)-[0-9a-f]{8,17}(?![A-Za-z0-9])}{AWS_RESOURCE_ID_REDACTED}gi;

      if ($line =~ /aws|amazonaws|ec2|vpc|subnet|security[ _-]*group|instance|elastic[ _-]*ip|public[ _-]*ip|endpoint|eip|nat|route[ _-]*table/i) {
        $line =~ s{(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)}{AWS_PUBLIC_IP_REDACTED}g;
      }
    }
    $_ = join("\n", @lines);
  ' "$file"; then
    status=$?
  fi

  chmod "$mode" "$file"
  chmod "$dir_mode" "$dir"
  return "$status"
}

sanitize_sensitive_tree() {
  local tree="$1"
  local file

  # Only invoke Perl for files that can contain a sensitive literal. This
  # keeps repeatable backups fast while the final scan still covers the full
  # tree.
  while IFS= read -r -d '' file; do
    sanitize_sensitive_file "$file"
  done < <(
    rg -l --null --hidden --text --pcre2 \
      '(?i)AKIA|ASIA|xox[baprs]-|github_pat_|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|Bearer[[:space:]]+|PRIVATE[[:space:]]+KEY|arn:aws:|s3://|(?:AWS|CLOUDFLARE|CF|SLACK|GITHUB|DB|CHATOPS)?[_-]?(?:ACCESS[-_]KEY|SECRET|TOKEN|PASSWORD|PASSWD|API[-_]KEY|CLIENT[-_]SECRET|SIGNING[-_]SECRET|CREDENTIALS?|PRIVATE[-_]KEY)|(?:aws|amazonaws|account[ _-]*id|role[ _-]*arn|caller[ _-]*identity)[^\r\n]{0,160}[0-9]{12}|(?:aws|amazonaws|public[ _-]*ip|elastic[ _-]*ip|eip|endpoint|ec2)[^\r\n]*(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])|(?:i|ami|vpc|subnet|sg|eni|igw|nat|rtb|vol|eipalloc|eipassoc|snap)-[0-9a-f]{8,17}' \
      "$tree" 2>/dev/null || true
  )
}

sanitize_sensitive_tree "$ROOTFS"

normalize_text_tree() {
  local tree="$1"
  local file

  while IFS= read -r -d '' file; do
    if grep -Iq . "$file" 2>/dev/null; then
      local mode dir dir_mode
      mode="$(stat -c '%a' "$file")"
      dir="$(dirname -- "$file")"
      dir_mode="$(stat -c '%a' "$dir")"
      chmod u+w "$dir"
      chmod u+w "$file"
      sed -i -e 's/\r$//' -e 's/[[:space:]]\+$//' -e 's/^[ ]*\t/\t/' "$file"
      perl -0777 -pi -e 's/\n+\z/\n/' "$file"
      chmod "$mode" "$file"
      chmod "$dir_mode" "$dir"
    fi
  done < <(find "$tree" -type f -print0)
}

normalize_text_tree "$ROOTFS"
normalize_text_tree "$INVENTORY"

scan_pattern() {
  local label="$1"
  local pattern="$2"
  local matches

  matches="$(rg -l --hidden --text --pcre2 "$pattern" "$ROOTFS" 2>/dev/null || true)"
  if [[ -z "$matches" ]]; then
    return 0
  fi

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    printf '[WARNING]\n%s\n%s\n' "${path#"$REPO_ROOT/"}" "$label"
  done <<< "$matches"
  return 1
}

CONFIG_GLOBS=(
  '--glob=*.env'
  '--glob=*.env.*'
  '--glob=*.ini'
  '--glob=*.yml'
  '--glob=*.yaml'
  '--glob=*.conf'
  '--glob=*.service'
  '--glob=*.tf'
  '--glob=*.tfvars'
  '--glob=*.sh'
  '--glob=*.json'
)

scan_config_pattern() {
  local label="$1"
  local pattern="$2"
  local matches

  matches="$(rg -l --hidden --text --pcre2 "${CONFIG_GLOBS[@]}" \
    "$pattern" "$ROOTFS" 2>/dev/null || true)"
  if [[ -z "$matches" ]]; then
    return 0
  fi

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    printf '[WARNING]\n%s\n%s\n' "${path#"$REPO_ROOT/"}" "$label"
  done <<< "$matches"
  return 1
}

scan_sensitive_literals() {
  local findings=0
  local path

  while IFS= read -r -d '' path; do
    if awk '
      BEGIN { found=0 }
      {
        line=tolower($0)
        if (line !~ /password|passwd|secret|credential|private[ _-]*key|signing[ _-]*secret/) next
        rhs=$0
        if (rhs !~ /[:=]/) next
        sub(/^[^:=]*[:=]/, "", rhs)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
        if (rhs ~ /^"[^"]{12,}"([[:space:]]*#.*)?$/ || rhs ~ /^\047[^\047]{12,}\047([[:space:]]*#.*)?$/) {
          rhs_lower=tolower(rhs)
          if (rhs_lower !~ /\$|\{|\}|getenv|environ|lookup|var[.]|process|config|reference|placeholder|example|set_in_secret_store/) {
            found=1
            exit
          }
        } else if (rhs ~ /^[A-Za-z0-9!@#%^&*+=:,_/-]{12,}([[:space:]]*#.*)?$/) {
          rhs_lower=tolower(rhs)
          if (rhs_lower !~ /password|passwd|secret|credential|token|key|env|var|lookup|reference/) {
            found=1
            exit
          }
        }
      }
      END { exit found ? 0 : 1 }
    ' "$path" >/dev/null 2>&1; then
      printf '[WARNING]\n%s\nSensitive literal assignment candidate\n' \
        "${path#"$REPO_ROOT/"}"
      findings=1
    fi
  done < <(
    find "$ROOTFS" -type f \( \
      -name '*.env' -o -name '*.env.*' -o -name '*.ini' -o \
      -name '*.yml' -o -name '*.yaml' -o -name '*.conf' -o \
      -name '*.service' -o -name '*.tf' -o -name '*.tfvars' -o \
      -name '*.sh' -o -name '*.json' \
    \) -print0
  )

  return "$findings"
}

secret_scan() {
  local findings=0

  scan_pattern 'AWS access key pattern detected' \
    '(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])' || findings=1
  scan_pattern 'AWS secret key assignment pattern detected' \
    "(?i)(aws_secret_access_key|aws_secret_key)\\s*[:=]\\s*[\"']?[A-Za-z0-9/+=]{30,}" || findings=1
  scan_pattern 'Slack token pattern detected' \
    '(?i)xox[baprs]-[0-9A-Za-z-]{10,}' || findings=1
  scan_pattern 'Private key header detected' \
    '-----BEGIN[[:space:]]+([A-Z0-9]+[[:space:]]+)?PRIVATE KEY-----' || findings=1
  scan_pattern 'AWS access-key assignment pattern detected' \
    "(?i)(aws_access_key_id|aws_access_key)[[:space:]]*[:=][[:space:]]*[\"']?[A-Z0-9]{16,}" || findings=1
  scan_pattern 'WireGuard private-key assignment pattern detected' \
    '(?i)^PrivateKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{40,}={0,2}[[:space:]]*$' || findings=1
  scan_pattern 'AWS account ID literal detected' \
    '(?im)^(?![^\r\n]*[{}])(?:[^\r\n]*(?:aws|amazonaws|account[ _-]*id|role[ _-]*arn|caller[ _-]*identity)[^\r\n]*)(?<![0-9])[0-9]{12}(?![0-9])' || findings=1
  scan_pattern 'AWS ARN literal detected' \
    '(?im)^(?![^\r\n]*(?:\$\{|\b(?:var|lookup|reference)\.|[{}]))[^\r\n]*\barn:aws:[A-Za-z0-9][A-Za-z0-9:/_.+*=,@{}-]{8,}' || findings=1
  scan_pattern 'AWS resource identifier detected' \
    '(?i)(?<![A-Za-z0-9])(?:i|ami|vpc|subnet|sg|eni|igw|nat|rtb|vol|eipalloc|eipassoc|snap)-[0-9a-f]{8,17}(?![A-Za-z0-9])' || findings=1
  scan_config_pattern 'Cloudflare token literal-assignment pattern detected' \
    "(?i)(cloudflare|cf)[_-]?(api|access)?[_-]?token\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{20,}" || findings=1
  scan_config_pattern 'Slack signing secret/token literal-assignment pattern detected' \
    "(?i)(slack|signing)[_-]?(token|secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9+/=_-]{12,}" || findings=1
  scan_sensitive_literals || findings=1

  if (( findings == 0 )); then
    printf '[OK] no high-confidence secret patterns detected; values were not printed\n'
  else
    printf '[WARNING] secret scan found review items; values were not printed\n'
  fi
}

printf '%s\n' '--- MSP backup synchronization ---'
printf 'source_home=%s\n' "$SOURCE_HOME"
printf 'destination=%s\n' "$ROOTFS"
printf '%s\n' '--- inventory capture ---'
printf '[OK] inventory written to %s\n' "$INVENTORY"
printf '%s\n' '--- secret scan ---'
secret_scan
printf '%s\n' 'backup_complete=true'
