# Deployment guide

This guide covers a small production deployment: one host receiving mail for one
or more domains, with outbound delivery either direct-to-MX or through a
smarthost.

## Production checklist

Before accepting real mail:

- Publish MX, A/AAAA, SPF, DKIM, and DMARC records.
- Set the reverse DNS (PTR) of the sending IP to the SMTP hostname.
- Replace the self-signed certificate with a trusted certificate.
- Bind SMTP to `:25` and submission to `:587` (and optionally implicit TLS to
  `:465`).
- Keep the filter listener and status server on loopback or a private network.
- Set a strong admin password and remove any `plain:` development users.
- Enable at least one spam control (DNSBL, rspamd, or greylisting) and monitor
  its decisions before enabling rejection.
- Configure backups for the queue, configuration, TLS keys, and DKIM keys.
- Provision every local mailbox in users.txt or explicitly configure recipient
  validation/aliases before accepting public MX traffic.
- Review Maildir mailbox/domain quota limits and provision adequate disk capacity.
- Use verified TLS for authenticated outbound SMTP relays (`required` or `implicit`).
- Enable external DSNs only if you have a trusted inbound sender policy;
  authenticated submission DSNs are enabled by default for new configurations.
- Confirm outbound port 25 is allowed by the hosting provider, or configure a
  smarthost.

## DNS

For `example.com` handled by `mail.example.com` at `203.0.113.10`:

```text
example.com.                        MX    10 mail.example.com.
mail.example.com.                   A     203.0.113.10
mail.example.com.                   AAAA  2001:db8::10
10.113.0.203.in-addr.arpa.          PTR   mail.example.com.
example.com.                        TXT   "v=spf1 mx -all"
default._domainkey.example.com.     TXT   "v=DKIM1; k=rsa; p=MIIBIjANBg..."
_dmarc.example.com.                 TXT   "v=DMARC1; p=none; rua=mailto:postmaster@example.com"
```

`gomta init` prints the exact DKIM and suggested SPF/DMARC values for every
configured domain. The DKIM record name is
`<selector>._domainkey.<domain>`.

Notes:

- `v=spf1 mx -all` says only the hosts listed in MX may send as the domain. If
  you send through a smarthost or application servers, include them instead.
- Start DMARC at `p=none`, collect reports for a few weeks, then move to
  `p=quarantine` and later `p=reject` once legitimate mail passes.
- PTR records are usually set in the hosting provider's control panel, not in
  your DNS zone.
- If the host has no IPv6 connectivity, publish only an A record.
- GoMTA does not implement MTA-STS or DANE. Those can be added at the DNS/edge
  layer if required.

## TLS

GoMTA reads `tls.cert_file` and `tls.key_file` at startup. The generated
self-signed certificate is appropriate for local testing only.

With Let's Encrypt and Certbot:

```sh
certbot certonly --standalone -d mail.example.com

# Point GoMTA at the live files:
tls:
  cert_file: /etc/letsencrypt/live/mail.example.com/fullchain.pem
  key_file: /etc/letsencrypt/live/mail.example.com/privkey.pem
  min_version: "1.2"
  auto_generate: false
```

Because certificates are loaded at startup, restart or reload GoMTA after
renewal. A systemd timer that runs `certbot renew` followed by
`systemctl restart gomta` is sufficient for a single host.

Use `tls: starttls` on ports 25/587 and `tls: implicit` if you expose port 465.
AUTH is not advertised without TLS.

## Ports and firewall

| Port | Listener | Exposure |
| --- | --- | --- |
| `25/tcp` | inbound MTA | Public |
| `587/tcp` | submission (STARTTLS) | Public, authenticated users only |
| `465/tcp` | submission (implicit TLS) | Optional |
| `10025/tcp` | filter | Loopback or private network only |
| `8080/tcp` | status | Loopback or private monitoring network |

Outbound:

- `25/tcp` to remote MX hosts for direct delivery.
- Your smarthost port (usually 587 or 465) if you relay outbound mail.
- `53/udp` and `53/tcp` to a recursive resolver for SPF, DKIM, DMARC, DNSBL, and
  MX lookups.

Many cloud providers block outbound port 25 by default. If yours does, use
`routing.outbound_options.smarthost` with an authenticated relay, or request the
block be removed.

## Directory layout

A typical single-host installation:

```text
/var/lib/gomta/
  gomta.yaml
  plugins.yaml
  domains.txt
  users.txt
  tls/
    cert.pem
    key.pem
  dkim/
    default.key
  data/
    queue/
      <id>.json
      <id>.eml
      failed/
    quarantine/
  mail/
    example.com/
      postmaster/
        new/
```

Own the directory by the service user, and keep `users.txt`, TLS keys, and DKIM
keys unreadable by other users:

```sh
chown -R gomta:gomta /var/lib/gomta
chmod 700 /var/lib/gomta /var/lib/gomta/data /var/lib/gomta/dkim /var/lib/gomta/tls
chmod 600 /var/lib/gomta/users.txt /var/lib/gomta/tls/key.pem /var/lib/gomta/dkim/*.key
```

## Running as a systemd service

`gomta` binds low ports only if it has permission. Either start it as root and
drop privileges is **not** supported, or grant the service user the bind
capability:

```ini
# /etc/systemd/system/gomta.service
[Unit]
Description=GoMTA SMTP server
Documentation=file:///opt/gomta/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gomta
Group=gomta
WorkingDirectory=/var/lib/gomta
ExecStart=/usr/local/bin/gomta serve -config /var/lib/gomta/gomta.yaml
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gomta
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now gomta
journalctl -u gomta -f
```

If you use unprivileged ports (2525/5587) during testing, remove the capability
lines.

## Docker

The image runs as a non-root user and keeps all state in `/var/lib/gomta`.

### Images

Published images live on Docker Hub as
[`ferchd/gomta`](https://hub.docker.com/r/ferchd/gomta):

```sh
docker pull ferchd/gomta:latest
```

Images are built for `linux/amd64` and `linux/arm64`. The CI workflow publishes:

| Tag | Source |
| --- | --- |
| `latest` | Latest push to `main` |
| `vX.Y.Z` | Git tag `vX.Y.Z` |
| `X.Y`, `X` | Git tag `vX.Y.Z` |
| `main` | Latest commit on `main` |
| `sha-<short>` | Every published commit |

For reproducible production deployments, pin a version tag or digest instead of
`latest`.

### First start

```sh
GOMTA_DOMAINS=example.com \
GOMTA_HOSTNAME=mail.example.com \
GOMTA_ADMIN_PASSWORD='change-this-password' \
docker compose up -d
```

Add `--build` to build the image from the local checkout instead of pulling the
published image. The Compose image name can be overridden with `GOMTA_IMAGE`.

On first start the entrypoint runs `gomta init` inside the volume, then starts
`gomta serve`. Later starts reuse the generated files. The generated password is
printed only if `GOMTA_ADMIN_PASSWORD` is omitted; set it explicitly and change
it before production.

Environment variables understood by the entrypoint:

| Variable | Description |
| --- | --- |
| `GOMTA_DOMAINS` | Comma-separated domains for the first-run `init`. Required when no config exists. |
| `GOMTA_HOSTNAME` | SMTP hostname. |
| `GOMTA_ADMIN_USER` | Admin login, default `postmaster@<first-domain>`. |
| `GOMTA_ADMIN_PASSWORD` | Admin password, minimum 8 characters. |
| `GOMTA_DKIM_SELECTOR` | DKIM selector, default `default`. |
| `GOMTA_DKIM_BITS` | RSA key size, default `2048`. |
| `GOMTA_CONFIG` | Config path, default `/var/lib/gomta/gomta.yaml`. |
| `GOMTA_STATUS_ADDR` | Override `status_addr` after initialization. |
| `GOMTA_PLUGINS_FILE` | Override `plugins_file`. |
| `GOMTA_DOMAINS_FILE` | Override `domains_file`. |
| `GOMTA_USERS_FILE` | Override `users_file`. |
| `GOMTA_HEALTHCHECK_URL` | URL used by the container health check. |

Passing a non-`serve` first argument runs the CLI directly:

```sh
docker run --rm -v gomta-data:/var/lib/gomta ferchd/gomta:latest check -config /var/lib/gomta/gomta.yaml
docker run --rm -v gomta-data:/var/lib/gomta ferchd/gomta:latest plugins
```

### Exposing the status endpoint

Compose maps host loopback `127.0.0.1:8080` to the container. The entrypoint sets
`status_addr: 0.0.0.0:8080` when `GOMTA_STATUS_ADDR` is provided so the port is
reachable from outside the container. Do not publish it to the public internet
without an authenticating proxy.

### Enabling Redis, rspamd, and ClamAV

Start the optional service:

```sh
docker compose --profile redis up -d
docker compose --profile rspamd up -d
docker compose --profile clamav up -d
```

Then update `plugins.yaml` in the volume:

```sh
docker compose cp gomta:/var/lib/gomta/plugins.yaml ./plugins.yaml
# edit the file, then:
docker compose cp ./plugins.yaml gomta:/var/lib/gomta/plugins.yaml
docker compose restart gomta
```

Use the Compose service names inside the container:

```yaml
# rate_limit / greylist
redis_url: redis://redis:6379/0

# rspamd
url: http://rspamd:11333

# clamav
address: clamav:3310
```

Enable the corresponding plugin by changing `enabled: false` to `enabled: true`
(or removing the field). Keep `skip_authenticated: true` for spam filters if
outbound submission traffic should not be scanned.

ClamAV needs time to download signatures on first start. Check its logs before
enabling `tempfail_on_error: true`; otherwise new mail may be deferred while the
database initializes.

### Volumes and permissions

Compose uses the named volume `gomta-data`. If you switch to a bind mount, make
sure the host directory is writable by UID/GID `10001`:

```sh
sudo mkdir -p /srv/gomta
sudo chown -R 10001:10001 /srv/gomta
```

### Ports 25 and 587

The generated Compose service maps `2525:2525` and `5587:5587` because those are
the generated listener ports. To use standard ports, edit the generated
`gomta.yaml` listener addresses to `:25` and `:587`, restart, and map
`25:25` / `587:587` in Compose.

### Publishing images

The [`Docker` workflow](.github/workflows/docker.yml) builds and pushes the
image. It runs on:

- pushes to `main` (publishes `latest`, `main`, and a `sha-<short>` tag);
- tags matching `v*` (publishes the version tags);
- pull requests (builds `linux/amd64` only and does not push);
- manual `workflow_dispatch`, which builds without pushing unless the `push`
  input is enabled.

To enable publishing, add two repository secrets under
**Settings → Secrets and variables → Actions**:

| Secret | Value |
| --- | --- |
| `DOCKERHUB_USERNAME` | Docker Hub account name, `ferchd` |
| `DOCKERHUB_TOKEN` | Docker Hub access token with read/write permission |

Create the token in Docker Hub under **Account settings → Personal access
tokens**. Do not use the account password. If `DOCKERHUB_USERNAME` is omitted,
the workflow falls back to `ferchd`; `DOCKERHUB_TOKEN` is always required for
pushes.

To release a version:

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The workflow then publishes `ferchd/gomta:0.1.0`, `0.1`, `0`, and the matching
`sha-<short>` tag. The image labels include the source revision and license.

## Backups

Back up:

- `gomta.yaml`, `plugins.yaml`, `domains.txt`, `users.txt`
- `tls/`
- `dkim/`
- `data/queue/` and `data/quarantine/`
- `mail/` if you use the Maildir backend as the final store

For a consistent queue backup, stop the service or snapshot the filesystem. The
queue is designed for crash recovery, but copying a live spool can capture an
envelope before its message file (or vice versa). Back up the DKIM private key
separately and restrict access; losing it breaks signing until you publish a new
selector.

## Monitoring

Use the status server for liveness and a quick view of queue depth:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/stats | jq .
```

`/healthz` and `/readyz` report that the HTTP status server is up. They do not
probe outbound connectivity, DNS, rspamd, or ClamAV. Use `/stats` and your
service logs for deeper checks.

`gomta status -config gomta.yaml` reads the configuration and spool from disk; it
does not query a running process. Use `/stats` for the live process.

Useful signals:

- `queue.queued` growing over time: outbound connectivity, DNS, or a downstream
  backend problem.
- `queue.failed` non-zero: permanent delivery failures; inspect
  `data/queue/failed/*.json`.
- `queue.quarantined` non-zero: a plugin quarantined mail; inspect
  `data/quarantine/`.
- Repeated `plugin error` logs: a filter is failing; decide whether it should be
  `fail_closed`.
- `authentication failed` spikes: credential stuffing or a broken client.

Logs are structured. Set `log.format: json` and collect stderr with journald,
Docker, or your normal agent.

## Security hardening

- Never expose the filter listener or status endpoint to the internet.
- Keep `relay_networks` limited to loopback or a controlled internal network.
- Do not enable `allow_insecure_auth` outside loopback development.
- Run as an unprivileged user with only `CAP_NET_BIND_SERVICE`.
- Keep TLS and DKIM keys at mode `0600`.
- Use bcrypt users; remove `plain:` entries.
- Start spam controls in annotate-only mode, inspect `Authentication-Results`
  and `X-Spam-*` headers, then enable rejection.
- Set `fail_closed: true` only for filters whose unavailability must stop mail
  (for example a mandatory antivirus scanner).
- Limit message size and recipient counts.
- Keep the host, Go toolchain used for builds, and container images patched.

## Troubleshooting

**`gomta check` fails with `TLS files not found`**

Run `gomta init`, provide a certificate, or set `tls.auto_generate: true`.

**`listen :25: permission denied`**

Grant `CAP_NET_BIND_SERVICE`, run on an unprivileged port, or use a socket
activator/reverse proxy. GoMTA does not drop privileges itself.

**`550 5.7.1 Relaying denied`**

The recipient domain is not in `domains.txt`, and the client is neither
authenticated nor in `relay_networks`. Authenticate on submission, add the client
network, or add the domain as local.

**Mail is accepted but never delivered**

Check `/stats` queue counts and `data/queue/*.json` for `last_error`. Direct
outbound delivery requires working MX DNS and outbound port 25. Try a smarthost
if the provider blocks port 25.

**SPF/DKIM/DMARC show unexpected results**

Inspect the `Authentication-Results` header. Confirm the receiving host can
resolve TXT records, that the DKIM selector in DNS matches `selector:`, and that
the `From` domain is in `sign_domains`. For DMARC, remember that alignment uses
the `From` header domain, not the envelope sender.

**Messages are quarantined**

Search logs for `message quarantined` and inspect
`data/quarantine/<id>.json` for the reason. The reason is also in the log line
from the plugin decision.

**Docker container restarts on first boot**

`GOMTA_DOMAINS` is required when the volume has no `gomta.yaml`. Check
`docker compose logs gomta`. If a bind mount is used, verify UID `10001` can
write to it.

**Certificate renewal did not take effect**

GoMTA loads certificates at startup. Restart the service after renewal.
