#!/bin/bash
WEB_IP="IP_REDACTED"
DOC_IP="IP_REDACTED"
DB_IP="IP_REDACTED"

ssh -i ~/.ssh/dr_key_v2 ubuntu@IP_REDACTED <<EOF
cat <<EOT > ~/scripts/update_hosts.sh
#!/bin/bash
WEB_IP="IP_REDACTED"
DB_IP="IP_REDACTED"
DOC_IP="IP_REDACTED"

cat <<EOT2 > ~/hospital-dr-ansible/hosts
[web_servers]
web_server ansible_host=\$WEB_IP ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/dr_key

[doc_servers]
doc_server ansible_host=\$DOC_IP ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/dr_key

[db_servers]
db_server ansible_host=\$DB_IP ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/dr_key
EOT2
EOT
EOF
