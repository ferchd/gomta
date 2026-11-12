# Changelog

All notable changes to GoMTA are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI for formatting, vetting, testing, and building.
- Multi-architecture Docker image publishing to `ferchd/gomta` on Docker Hub.
- Dependabot updates for Go modules, GitHub Actions, and Docker.
- Community files: license, contribution guide, code of conduct, security
  policy, issue forms, and pull request template.

### Changed

- The Go module path is now `github.com/ferchd/gomta`, matching the repository
  URL. Import paths in downstream code must be updated accordingly.
- `smtps://` delivery URLs now default to port `465`.

## [0.1.0] - 2026-11-11

### Added

- SMTP server with `mta`, `submission`, and `filter` listener modes.
- YAML configuration with strict unknown-field validation, plus `domains.txt`
  and `users.txt` policy files.
- STARTTLS and implicit TLS, AUTH PLAIN and AUTH LOGIN.
- Persistent on-disk queue with JSON envelopes, `.eml` payloads, retry
  schedules, a failed queue, and quarantine.
- Async plugin hooks with an ordered phase and deterministic action precedence.
- Built-in plugins: SPF, DKIM verification, DKIM signing, DMARC, DNSBL,
  greylisting, rate limiting, rspamd, ClamAV, header manipulation, HELO checks,
  and external commands.
- Delivery backends: direct-to-MX and smarthost SMTP, LMTP, Maildir, HTTP
  webhooks, external commands, and discard.
- CLI commands: `init`, `serve`, `check`, `status`, `send`, `dkim-keygen`,
  `plugins`, `backends`, and `version`.
- Health, readiness, and JSON statistics endpoints.
- Dockerfile, Compose file and profiles, and a first-run container entrypoint.
- Configuration reference, plugin guide, deployment guide, and a runnable
  minimal example.

[Unreleased]: https://github.com/ferchd/gomta/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ferchd/gomta/releases/tag/v0.1.0
