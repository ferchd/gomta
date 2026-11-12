# GoMTA

[![CI](https://github.com/ferchd/gomta/actions/workflows/ci.yml/badge.svg)](https://github.com/ferchd/gomta/actions/workflows/ci.yml)
[![Docker](https://github.com/ferchd/gomta/actions/workflows/docker.yml/badge.svg)](https://github.com/ferchd/gomta/actions/workflows/docker.yml)
[![Docker image](https://img.shields.io/docker/v/ferchd/gomta?label=docker%20hub)](https://hub.docker.com/r/ferchd/gomta)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/ferchd/gomta)](go.mod)

GoMTA is a small, modular SMTP server written in Go. It accepts mail for local
domains, relays and delivers outbound mail, and can run as an inbound MX, an
authenticated submission server, or a filtering MTA in front of another mail
system.

Configuration is deliberately boring: one YAML file for the server, one YAML
file for the plugin pipeline, and plain-text `domains.txt` / `users.txt` files
for policy.

## Highlights

- **Three listener modes** — `mta` for inbound MX traffic, `submission` for
  authenticated users, and `filter` for a filtering MTA in front of a mailbox
  server.
- **Async plugin hooks** — plugins for the same hook run concurrently, so a slow
  DNSBL, Redis, HTTP filter, or antivirus lookup does not serialize unrelated
  checks. Plugins that depend on other results can opt into an ordered phase.
- **Built-in mail security** — SPF, DKIM verification, DKIM signing, DMARC,
  DNSBLs, greylisting, rate limiting, rspamd, ClamAV, and an external-command
  filter.
- **Persistent queue** — JSON envelopes plus `.eml` payloads on disk, with
  configurable retry schedules, a failed queue, and a quarantine area.
- **Pluggable delivery** — direct-to-MX or smarthost SMTP, LMTP, Maildir, HTTP
  webhooks, external commands, and discard.
- **Operational basics** — STARTTLS and implicit TLS, AUTH PLAIN/LOGIN, health
  and readiness endpoints, JSON stats, structured logs, Docker images, and
  Compose profiles.
- **Single binary** — no runtime dependencies beyond the files you configure.

## Quick start

Install from source with Go 1.27.3 or newer:

```sh
go install github.com/ferchd/gomta/cmd/gomta@latest
```

Or clone the repository and build it locally:

```sh
git clone https://github.com/ferchd/gomta.git
cd gomta
go build -trimpath -o gomta ./cmd/gomta
```

Then initialize a local instance:

```sh
./gomta init -domain example.com -hostname mail.example.com
```

`init` creates `gomta.yaml`, `plugins.yaml`, `domains.txt`, `users.txt`, a
self-signed TLS certificate, an RSA DKIM key, and the spool/mail directories. It
prints the generated admin password once, along with the DNS records you should
publish.

On Windows the binary is `gomta.exe`; use `.\gomta.exe` in the commands below.
The Makefile targets assume a Unix-like shell.

Validate the installation:

```sh
./gomta check -config gomta.yaml
```

Start the server:

```sh
./gomta serve -config gomta.yaml
```

The generated listeners use unprivileged ports by default: MTA on `:2525`,
submission on `:5587`, and a loopback filter listener on `127.0.0.1:10025`.
Production deployments normally use `:25` and `:587`; see
[docs/deployment.md](docs/deployment.md).

Send a test message through the authenticated submission listener:

```sh
./gomta send -server 127.0.0.1:5587 \
  -from postmaster@example.com \
  -to postmaster@example.com \
  -user postmaster@example.com \
  -password 'PASSWORD-FROM-INIT' \
  -insecure
```

`-insecure` skips verification of the generated self-signed certificate. The
message is delivered by the configured local backend; with the defaults it
lands in:

```text
mail/example.com/postmaster/new/
```

## Docker

Published images are available on Docker Hub as
[`ferchd/gomta`](https://hub.docker.com/r/ferchd/gomta) for `linux/amd64` and
`linux/arm64`:

```sh
docker pull ferchd/gomta:latest
```

The quickest container start auto-initializes a volume on first boot:

```sh
docker run -d --name gomta \
  -p 2525:2525 -p 5587:5587 -p 127.0.0.1:8080:8080 \
  -e GOMTA_DOMAINS=example.com \
  -e GOMTA_HOSTNAME=mail.example.com \
  -e GOMTA_ADMIN_PASSWORD='change-this-password' \
  -v gomta-data:/var/lib/gomta \
  ferchd/gomta:latest
```

The same setup with Compose pulls the published image; add `--build` to build
from the local checkout instead:

```sh
GOMTA_DOMAINS=example.com \
GOMTA_HOSTNAME=mail.example.com \
GOMTA_ADMIN_PASSWORD='change-this-password' \
docker compose up -d
```

The image stores all configuration, keys, mail, and queue data in
`/var/lib/gomta`. Compose exposes SMTP on `2525`, submission on `5587`, and the
status endpoint on host loopback port `8080`.

Images are tagged `latest` for the newest `main` build, `vX.Y.Z` / `X.Y` / `X`
for releases, and `sha-<short>` for every published commit. Pin a version tag or
digest in production.

Optional service profiles are available:

```sh
docker compose --profile redis up -d
docker compose --profile rspamd up -d
docker compose --profile clamav up -d
```

Enabling the matching plugin still requires editing the generated
`plugins.yaml`; see [docs/deployment.md](docs/deployment.md#docker) for the
exact settings.

To use host ports 25 and 587, change the generated listener addresses or mount
your own configuration into the container.

Image publishing is automated by GitHub Actions. See
[Publishing images](docs/deployment.md#publishing-images) for the required
Docker Hub secrets and release steps.

## How a message flows

```text
SMTP client
    |
    v
listener (mta / submission / filter)
    |  connect hook
    |  helo hook
    |  MAIL  -> mail hooks   (SPF, rate limiting)
    |  RCPT  -> rcpt hooks   (greylisting, recipient policy)
    |  DATA  -> data hooks   (DKIM verify, DMARC, rspamd, ClamAV, exec)
    |  queue hook            (headers, DKIM signing)
    v
persistent spool  ->  retry workers
                          |
                          +--> local backend   (Maildir, LMTP, HTTP, exec…)
                          +--> filter backend  (LMTP/SMTP/HTTP downstream)
                          +--> outbound backend (direct MX or smarthost)
```

Plugins return an action: continue, accept, quarantine, discard, temporary
failure, or permanent rejection. The strongest decision wins, so one plugin
cannot accidentally override another plugin's rejection.

## Repository layout

```text
cmd/gomta/            CLI entry point
config/               YAML configuration, domains, and plugin loading
plugin/               Public plugin API, registry, and async runner
delivery/             Public delivery backend API and built-in backends
queue/                Persistent spool and retry engine
internal/smtpserver/  SMTP session handling
internal/plugins/     Built-in plugins
internal/app/         Service wiring and status server
internal/setup/       `gomta init` templates
docs/                 Configuration, plugin, and deployment documentation
examples/minimal/     A runnable minimal configuration
docker/               Container entrypoint
.github/              CI, Docker publishing, Dependabot, and issue templates
```

## Documentation

- [Configuration reference](docs/configuration.md) — every `gomta.yaml` field,
  listener modes, TLS, relay policy, queue settings, and policy files.
- [Plugins and delivery](docs/plugins.md) — hook semantics, every built-in
  plugin and backend, metadata keys, and how to write your own.
- [Deployment guide](docs/deployment.md) — DNS, TLS, production ports, systemd,
  Docker, backups, and troubleshooting.

## CLI overview

```text
gomta init          Create config, policy files, TLS certificate, and DKIM key
gomta serve         Run the SMTP server and delivery queue
gomta check         Validate configuration and print a summary
gomta status        Print a runtime snapshot without starting the server
gomta send          Send a test message through an SMTP listener
gomta dkim-keygen   Generate a DKIM private key and DNS TXT record
gomta plugins       List built-in plugins
gomta backends      List delivery backends
gomta version       Print version information
```

Run `gomta <command> -h` for command-specific flags.

## Requirements

- Go 1.27.3 or newer to build from source.
- No database is required. Redis is optional and only used for shared
  greylist/rate-limit state.
- A recursive DNS resolver is needed for SPF, DKIM, DMARC, DNSBL, and MX
  lookups.

## Development

```sh
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
go build -trimpath ./cmd/gomta
```

CI runs the same checks on every push and pull request, then validates
`examples/minimal/gomta.yaml`. The test suite covers the plugin runner, SPF
evaluator, DKIM key handling and signing/verification, DMARC alignment, rspamd
and ClamAV clients, setup, and an end-to-end STARTTLS + AUTH submission flow with
Maildir delivery.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, project
layout, and pull request expectations.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening an issue or pull request.

- [Report a bug](https://github.com/ferchd/gomta/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/ferchd/gomta/issues/new?template=feature_request.yml)
- [Open a pull request](https://github.com/ferchd/gomta/compare)

## Security

Do not report vulnerabilities in public issues. Use
[GitHub private vulnerability reporting](https://github.com/ferchd/gomta/security/advisories/new)
and follow [SECURITY.md](SECURITY.md) for scope and expectations.

## License

GoMTA is released under the [MIT License](LICENSE).

## Status

GoMTA is usable as a small mail server or filtering MTA, but it is not a
replacement for a full mail suite. It does not include a mailbox store, webmail,
a webmail interface or a configuration API. Failure DSNs are supported for
authenticated submission by default in newly generated configurations;
inbound DSNs require explicit opt-in to avoid backscatter. Back up the queue and
use a real mailbox backend (LMTP, Maildir, or HTTP) where durability matters.
