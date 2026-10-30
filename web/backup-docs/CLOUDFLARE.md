# Cloudflare

직접 확인한 `/etc/cloudflared/config.yml`: tunnel `hospital-tunnel`; ingress `hospital-web.pp.ua` → `http://localhost:80`, `ssh.hospital-web.pp.ua` → `ssh://localhost:22`, catch-all `http_status:404`.

Credential 원본의 내용은 읽거나 복사하지 않았습니다. 설정에 나온 참조 경로는 `/home/vboxuser/.cloudflared/e6d3babc-8da8-45b4-85a3-a674302785fc.json`입니다. 백업 설정에서는 `<CREDENTIAL_FILE>`로 치환했습니다. UUID `e6d3babc-8da8-45b4-85a3-a674302785fc`는 사용자 기준 및 참조 파일명에서 확인한 공개 식별자입니다.

서비스는 `/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run`, active/enabled. PATH의 `/usr/local/bin/cloudflared`는 `/usr/bin/cloudflared` symlink이며 두 버전 조회는 2026.3.0입니다.

다음은 **사용자 제공 외부 최종 컨텍스트**이며 Cloudflare 관리 API로 검증하지 않았습니다: proxied CNAME, Zone SSL Full, Configuration Rule `hospital-web-strict` (Hostname equals hospital-web.pp.ua, SSL Strict), Edge TLS 종료. HTTP tunnel ingress를 임의로 HTTPS나 localhost:3000으로 바꾸지 않습니다. SSH ingress 존재만 확인했으며 Access 정책/SSH 인증은 검증하지 않았습니다.

DNS 및 전환 절차는 [DNS](../cloudflare/DNS.md), [FAILOVER_FAILBACK](FAILOVER_FAILBACK.md)를 참고하세요.
