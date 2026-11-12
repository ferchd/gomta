# Security policy

## Supported versions

GoMTA is developed on the `main` branch. Security fixes are applied to `main`
and included in the next tagged release. Older releases are not maintained
separately.

| Version | Supported |
| --- | --- |
| `main` and latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a security problem.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/ferchd/gomta/security/advisories/new).
If that form is unavailable, contact the maintainer through
[GitHub](https://github.com/ferchd) and ask for a private channel.

Please include:

- A description of the issue and its impact.
- Affected version or commit.
- Steps to reproduce, including a minimal configuration where possible.
- Whether the issue requires authentication, a specific listener mode, or a
  particular plugin.
- Any suggested fix or mitigation.

Do not include real credentials, DKIM private keys, TLS private keys, or
message contents belonging to third parties.

## What to expect

- Acknowledgement within a reasonable time.
- An assessment of severity and affected versions.
- A coordinated disclosure timeline. Please allow time for a fix and release
  before publishing details.
- Credit in the release notes if you want it.

## Scope

In scope:

- SMTP session handling, AUTH, TLS setup, and listener separation.
- Header, address, and message parsing that could lead to injection, smuggling,
  or denial of service.
- Plugin and delivery backends, including command execution and HTTP clients.
- Queue handling, file permissions, and path traversal.
- Container image and entrypoint behavior.

Out of scope:

- Misconfiguration of DNS, TLS certificates, firewall rules, or host
  permissions.
- Vulnerabilities in optional third-party services (rspamd, ClamAV, Redis,
  reverse proxies) that are not caused by GoMTA's integration.
- Spam or phishing messages that are correctly delivered according to the
  configured policy.
- Reports that require an already-compromised host or root access.

## Operational hardening

GoMTA is an SMTP server and should be deployed with care:

- Run it as an unprivileged user. The container image uses UID/GID `10001`.
- Do not expose the filter listener or status endpoint to the public internet.
- Use STARTTLS or implicit TLS for submission and require authentication.
- Replace the generated self-signed certificate with a trusted certificate.
- Protect `gomta.yaml`, `users.txt`, DKIM keys, TLS keys, and the queue
  directory with appropriate filesystem permissions.
- Keep Go and the container base images updated. Dependabot is configured for
  Go modules, GitHub Actions, and Docker.
- Back up the queue before upgrading, and test configuration changes with
  `gomta check` first.

See [docs/deployment.md](docs/deployment.md) for deployment guidance.
