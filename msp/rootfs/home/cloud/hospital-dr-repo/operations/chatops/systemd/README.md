# ChatOps HTTPS callback preparation

These units keep ChatOps on `IP_REDACTED:5000` and run a separate
Cloudflare Tunnel connector. They do not contain a tunnel token or any
application Secret.

## MSP installation

Install `cloudflared` from the approved local package, then create the
credential file without putting its contents in Git:

```bash
sudo dpkg -i /path/to/cloudflared-linux-amd64.deb
sudo install -d -m 700 /etc/cloudflared
sudo install -o root -g root -m 600 /dev/null /etc/cloudflared/chatops-tunnel.token
sudoedit /etc/cloudflared/chatops-tunnel.token
```

The file must contain only the token from the ChatOps tunnel. Keep it
root-readable; systemd passes it to the `cloud` service through a private
credential path.

Install the units and start ChatOps first:

```bash
sudo install -m 644 hospital-dr-chatops.service /etc/systemd/system/
sudo install -m 644 hospital-dr-chatops-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hospital-dr-chatops.service
```

Start the tunnel only after Cloudflare has created the tunnel and the token
file is present:

```bash
sudo systemctl enable --now hospital-dr-chatops-tunnel.service
```

## Cloudflare configuration

Create a dedicated remotely managed tunnel named `hospital-dr-chatops`.
Create one Published application route:

```text
Hostname: chatops.hospital-web.pp.ua
Service:  http://IP_REDACTED:5000
```

Do not change `hospital-web.pp.ua`. Cloudflare should create the DNS route
for the dedicated subdomain. Do not expose port 5000 or create an inbound
firewall rule.

## Slack configuration

Set the Interactive Request URLs separately:

```text
Failover: https://chatops.hospital-web.pp.ua/slack/failover/action
Failback: https://chatops.hospital-web.pp.ua/slack/failback/action
```

The ChatOps process reads `/home/cloud/hospital-dr-secrets/dr.env` at startup.
The service unit provisions `/var/lib/hospital-dr` as its persistent state
directory and stores the approval database and cross-process pipeline lock
 there. `PrivateTmp=true` therefore cannot remove execution state. On startup,
expired `EXECUTING` leases are recorded as `FAILED`; they are never treated as
successful and a new execution requires a new two-person approval.
The staging deployment can use its own external Secret path through
`DR_SECRET_FILE`; do not copy `dr.env` into this repository.
