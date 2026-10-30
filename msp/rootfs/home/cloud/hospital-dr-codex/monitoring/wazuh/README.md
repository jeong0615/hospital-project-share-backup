# Wazuh SIEM/EDR/XDR contract

The MSP runtime is the Wazuh 4.8 single-node deployment under
`/home/cloud/wazuh-docker`. The canonical repository owns the feature and
correlation contract in `feature-contract.yml`, the read-only pipeline checker,
and the ChatOps correlation implementation. Runtime credentials, TLS keys,
Wazuh volumes, and agent enrollment remain external inputs.

The current Manager configuration has JSON alert output, Indexer output,
Syscheck/FIM, Syscollector inventory, SCA, and vulnerability detection enabled.
The manager-to-indexer path is verified with `operations/security/wazuh_pipeline_check.py`.
Agent-side collection is only considered live when the required agents are
connected; a disconnected WireGuard path must remain `DISCONNECTED`, not a
synthetic PASS.

Wazuh vulnerability findings are stored in the real
`wazuh-states-vulnerabilities-*` state index. The read-only
`operations/security/wazuh_vulnerability_status.py` check separates a healthy
pipeline from current agent connectivity, and Grafana uses a dedicated
vulnerability-state datasource rather than querying `wazuh-alerts-*`.

The Grafana Indexer identity remains read-only. Its allowed index patterns are
specified in `grafana-readonly-role.json`; applying that role extends read
access only to the vulnerability state and the normalized project indices,
including `hospital-aws-cloud-events`. It does not grant write, cluster-admin,
or active-response permissions.

The AWS CloudTrail collector uses a separate external identity described by
`aws-cloudtrail-writer-role.json`. That role is limited to the single
`hospital-aws-cloud-events` index and only the index-read, index-create,
mapping, and document-write actions required by the collector. Its username
and password must live in the external
`/home/cloud/hospital-dr-secrets/aws-indexer-writer.env` file with mode 0600;
the file is never stored in Git.

`operations/security/devsecops_indexer_collector.py` stores completed,
secret-free GitHub Actions summaries in `hospital-devsecops-executions` and
normalized deterministic correlation incidents in
`hospital-security-incidents`, reusing the existing Indexer. The optional user
timer in `operations/security/systemd/` reads the existing external Wazuh
Indexer credential source and never sends Slack or performs active response.
The collector's runtime source must remain outside Git; its systemd unit uses
the existing operational compose credential source only to avoid introducing a
second plaintext secret file.

GitHub artifact cleanup is report-only by default. The
`artifact-retention-cleanup.yml` workflow can remove expired artifacts and only
superseded CI image/summary artifacts outside the protected recent-run window;
source and SARIF artifacts are not selected.

Security Slack is intentionally separate from ordinary infrastructure alert
Slack. Set `WAZUH_SECURITY_SLACK_ENABLED=true`, then provide
`WAZUH_SECURITY_SLACK_TOKEN` and `WAZUH_SECURITY_SLACK_CHANNEL` (or the
backward-compatible `SLACK_SECURITY_*` names) only in the external secret file
when the channel owner has provisioned them. `WAZUH_SECURITY_SLACK_DRY_RUN=true`
validates filtering and payload generation without sending. The ChatOps
endpoint sends only deterministic HIGH correlation incidents to that optional
client and never sends raw logs or secrets.

The correlation layer is not active response and cannot execute DR workflows.
It records a bounded, normalized state file and preserves the existing
two-person approval gate for any DR action.

The upstream Wazuh compose stack must be updated/restarted through its own
operational procedure to install a Manager integration script. This repository
does not silently mutate the external Wazuh volumes or rotate their credentials.

`operations/security/wazuh_chatops_integration.py` is the reviewed custom
integration helper. It accepts a Wazuh alert JSON file and posts it only to the
localhost ChatOps endpoint; it does not execute active response. Install it in
the external `wazuh_integrations` volume only after the Wazuh runtime owner
confirms the volume backup and restart procedure. Until that deployment is
done, `WAZUH_SECURITY_SLACK` remains `NOT_CONFIGURED` for live Manager-to-
ChatOps forwarding even though the Indexer/Grafana pipeline is healthy.

## AWS endpoint agents in the current MSP topology

The repository retains the AWS Zabbix Active Agent and Wazuh Agent bootstrap
for reuse in a future environment with a controlled inbound edge. The current
MSP is behind an uncontrolled upstream NAT and does not own a public inbound
IPv4 address. Therefore the external AWS Agent paths are disabled by design:

- `AWS_ZABBIX_EXTERNAL_PATH_ENABLED=false`
- `AWS_WAZUH_EXTERNAL_PATH_ENABLED=false`
- `CONFIG_AVAILABLE=YES`
- `LIVE_PATH_ENABLED=NO`
- `LIVE_PATH_REASON=MSP_BEHIND_UNCONTROLLED_UPSTREAM_NAT`

The bootstrap exits safely before requiring endpoint values when either flag is
disabled. No MSP TCP/10051, 1514, or 1515 port-forward is required in this
mode. AWS CloudTrail Event History collection remains the live AWS security
path and is independent of endpoint-agent enrollment.
