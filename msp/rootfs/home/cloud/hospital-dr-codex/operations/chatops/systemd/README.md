# ChatOps HTTPS callback preparation

These units keep ChatOps on `IP_REDACTED:5000` and run a separate
Cloudflare Tunnel connector. They do not contain a tunnel token or any
application Secret.

## MSP installation

The repository contains a fail-closed installer. It only installs the
existing `hospital-dr-chatops-tunnel.service`; it does not create a tunnel,
DNS record, Slack URL, or ngrok replacement. Start with a no-change audit:

```bash
cd /home/cloud/hospital-dr-codex
sudo bash operations/chatops/systemd/install_chatops_tunnel.sh --dry-run
```

Install `cloudflared` from an approved local package, then create the
connector credential file without putting its contents in Git:

```bash
sudo dpkg -i /path/to/cloudflared-linux-amd64.deb
sudo install -d -m 700 /etc/cloudflared
sudo install -o root -g root -m 600 /dev/null /etc/cloudflared/chatops-tunnel.token
sudoedit /etc/cloudflared/chatops-tunnel.token
```

The file must contain only the token from the ChatOps tunnel. Keep it
root-readable; systemd passes it to the `cloud` service through a private
credential path.

The fallback ngrok unit is dynamic by default and does not provide a stable
Slack callback URL. It records the agent URL in
`/var/lib/hospital-dr/ngrok_public_url` and logs a warning if a restart
changes it. Check the current URL and callback risk with:

```bash
python3 /home/cloud/dr_project/ngrok_url_check.py --check
```

Use a reserved/static ngrok domain only after confirming that the account has
one; do not put an authtoken or API key in this repository. The preferred
production callback remains the Cloudflare Tunnel URL documented below.

Install the production WSGI dependency before installing the unit:

```bash
sudo apt-get install -y --no-install-recommends python3-gunicorn
```

The service invokes the distro package as `/usr/bin/python3 -m gunicorn` with
one threaded worker, remains bound to `IP_REDACTED:5000`, and starts the
expiry/cleanup workers from `wsgi.py`.
Install the tunnel unit without starting it:

```bash
sudo bash operations/chatops/systemd/install_chatops_tunnel.sh --apply
```

Enable or start it only as an explicit operator action, after the existing
Cloudflare tunnel has the published hostname route below:

```bash
sudo bash operations/chatops/systemd/install_chatops_tunnel.sh --apply --enable --start
```

The installer requires `/etc/cloudflared/chatops-tunnel.token` to be a
non-empty `root:root` mode `0600` regular file. It never prints the token.
The token must be the connector token for the existing tunnel, not a
Cloudflare API token used for DNS/SSM automation.

Check the fixed endpoint without sending a Slack request:

```bash
bash operations/chatops/systemd/check_fixed_chatops_endpoint.sh
```

The check validates DNS and normal TLS. The Slack action routes are POST-only,
so a verified GET `405` is treated as endpoint reachability, not as a failure.

## Cloudflare configuration

Use the existing remotely managed tunnel named `hospital-dr-chatops`.
In Cloudflare Zero Trust, verify or restore one Published application route:

```text
Hostname: chatops.hospital-web.pp.ua
Service:  http://IP_REDACTED:5000
```

Do not change `hospital-web.pp.ua`. Cloudflare should create the DNS route
for the dedicated subdomain. Do not expose port 5000 or create an inbound
firewall rule.

If the existing tunnel is not visible with the available API token, use the
Cloudflare Dashboard to verify the tunnel and route rather than creating a
second tunnel. The route must be exactly:

```text
chatops.hospital-web.pp.ua -> http://IP_REDACTED:5000
```

The DNS record and tunnel route must be verified before changing any Slack App
Request URL. Keep the working ngrok URL until all three fixed routes pass the
read-only endpoint check.

## Slack configuration

Set the Interactive Request URLs separately:

```text
Failover: https://chatops.hospital-web.pp.ua/slack/failover/action
Failback: https://chatops.hospital-web.pp.ua/slack/failback/action
Emergency: https://chatops.hospital-web.pp.ua/slack/action
```

The Emergency App is a separate `ChatOps Emergency` Slack App.  Store its
`SLACK_EMERGENCY_BOT_TOKEN` and `SLACK_EMERGENCY_SIGNING_SECRET` in the
external `/home/cloud/hospital-dr-secrets/dr.env`; it never reuses the
Failover token.  The App needs `chat:write` and `pins:write`, and must be
invited to the private `긴급승인` channel.  Set
`SLACK_EMERGENCY_CHANNEL_ID` to that channel ID.  The ChatOps process reads
the external secret file at startup.
The service unit provisions `/var/lib/hospital-dr` as its persistent state
directory and stores the approval database and cross-process pipeline lock
 there. `PrivateTmp=true` therefore cannot remove execution state. On startup,
expired `EXECUTING` leases are recorded as `FAILED`; they are never treated as
successful and a new execution requires a new two-person approval.
The staging deployment can use its own external Secret path through
`DR_SECRET_FILE`; do not copy `dr.env` into this repository.
