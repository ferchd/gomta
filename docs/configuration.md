# Configuration reference

GoMTA reads a single YAML file (usually `gomta.yaml`) plus three policy files:

```text
gomta.yaml       server configuration
plugins.yaml     plugin pipeline
domains.txt      domains accepted for local delivery
users.txt        submission credentials
```

All paths in `gomta.yaml` are resolved relative to the directory containing the
configuration file. `~` is **not** expanded by the configuration loader, but
plugin paths may use `~/` where documented.

The loader is strict: unknown YAML fields are rejected, so typos fail at
startup instead of being silently ignored. Run `gomta check -config gomta.yaml`
after every change.

## Environment variable expansion

`gomta.yaml` and `plugins.yaml` are passed through `os.ExpandEnv` before YAML
parsing. Both `${VAR}` and `$VAR` work:

```yaml
status_addr: "${GOMTA_STATUS_ADDR}"

plugins:
  - name: rspamd
    options:
      password: ${RSPAMD_PASSWORD}
```

Missing variables expand to an empty string. `domains.txt` and `users.txt` are
plain text and are **not** expanded.

## Top-level fields

| Field | Default | Description |
| --- | --- | --- |
| `hostname` | OS hostname | SMTP banner, EHLO name, Received header name, and default TLS/DKIM identity. |
| `data_dir` | `data` | Root for runtime data. The queue defaults to `<data_dir>/queue` and quarantine to `<data_dir>/quarantine`. |
| `domains_file` | `domains.txt` | Domains accepted for local delivery. |
| `users_file` | `users.txt` | Submission credentials. |
| `plugins_file` | `plugins.yaml` | Plugin pipeline configuration. |
| `status_addr` | `""` (disabled) | Address for `/healthz`, `/readyz`, and `/stats`. `gomta init` sets `127.0.0.1:8080`. |
| `relay_networks` | loopback | IPs/CIDRs allowed to relay without authenticating. |
| `log` | info/text | Structured logging. |
| `limits` | see below | Connection, message, and timeout limits. |
| `tls` | see below | Certificate and TLS policy. |
| `listeners` | `:25` + `:587` | SMTP endpoints. |
| `routing` | Maildir + SMTP | Delivery backend selection. |
| `queue` | see below | Persistent retry settings. |

Minimal configuration:

```yaml
hostname: mail.example.com
data_dir: data
domains_file: domains.txt
users_file: users.txt
plugins_file: plugins.yaml

listeners:
  - name: smtp
    address: ":25"
    mode: mta
    tls: starttls
  - name: submission
    address: ":587"
    mode: submission
    tls: starttls
    require_auth: true

routing:
  local_backend: maildir
  local_options:
    path: mail
  outbound_backend: smtp
  outbound_options:
    tls: opportunistic

status_addr: "127.0.0.1:8080"
```

## Logging

```yaml
log:
  level: info     # debug, info, warn, error
  format: text    # text or json
```

Logs are written to standard error. Use `format: json` when shipping logs to a
collector. `gomta serve -log-level debug` overrides the configured level
without changing the file.

## Limits

```yaml
limits:
  max_message_bytes: 26214400       # 25 MiB
  max_recipients: 100
  max_connections: 200
  max_connections_per_ip: 20
  max_line_length: 4096
  read_timeout: 5m
  write_timeout: 5m
  idle_timeout: 5m
  max_auth_failures: 5
  validate_local_recipients: false
```

| Field | Default | Description |
| --- | --- | --- |
| `max_message_bytes` | `26214400` | Maximum DATA size. Larger messages receive `552`. |
| `max_recipients` | `100` | Maximum RCPT commands per transaction. |
| `max_connections` | `200` | Global concurrent connection limit. |
| `max_connections_per_ip` | `20` | Per-client-IP connection limit. |
| `max_line_length` | `4096` | Maximum SMTP command line length. |
| `read_timeout` | `5m` | Read deadline. Also acts as the idle timeout between commands. |
| `write_timeout` | `5m` | Write deadline. |
| `idle_timeout` | `5m` | Accepted for forward compatibility; the current server uses `read_timeout` as its idle deadline. |
| `max_auth_failures` | `5` | Failed AUTH attempts before the session can no longer authenticate. |
| `validate_local_recipients` | `false` | When true and `users.txt` is non-empty, RCPT for a local domain is accepted only if the address exists in `users.txt`. Leave false when a downstream mailbox server owns the user list. |

`max_message_bytes` and `max_recipients` can be overridden per listener.

AUTH is only advertised over TLS. For development on a loopback address you can
set `allow_insecure_auth: true` on the listener to permit plaintext AUTH. The
`require_tls_for_auth` field exists in the schema but TLS is currently always
required unless that listener opt-in is present.

## TLS

```yaml
tls:
  cert_file: tls/cert.pem
  key_file: tls/key.pem
  min_version: "1.2"   # "1.2" or "1.3"
  auto_generate: false
```

If any listener uses `tls: starttls` or `tls: implicit`, the certificate and key
must exist. Set `auto_generate: true` to create a one-year self-signed ECDSA
certificate for `localhost`, the configured hostname, and loopback addresses.
`gomta init` generates a self-signed certificate and sets
`auto_generate: false`; replace it with a real certificate in production.

Certificate files are loaded at startup, so a failed renewal requires a process
restart (or a supervisor restart after renewal).

## Listeners

```yaml
listeners:
  - name: smtp
    address: ":25"
    mode: mta
    tls: starttls
    max_message_bytes: 26214400
    max_recipients: 100

  - name: submission
    address: ":587"
    mode: submission
    tls: starttls
    require_auth: true

  - name: filter
    address: "127.0.0.1:10025"
    mode: filter
    tls: none
```

| Field | Default | Description |
| --- | --- | --- |
| `name` | `listener-N` | Unique listener name used in logs and status output. |
| `address` | required | `host:port`. Use `:25`, `127.0.0.1:10025`, or `[::1]:2525`. |
| `mode` | `mta` | `mta`, `submission`, or `filter`. |
| `tls` | `starttls` | `starttls`, `implicit`, or `none`. |
| `require_auth` | forced for submission | Reject MAIL/RCPT until the client authenticates. |
| `allow_insecure_auth` | `false` | Permit AUTH without TLS. Only allowed on loopback addresses. |
| `max_message_bytes` | global limit | Per-listener DATA limit. |
| `max_recipients` | global limit | Per-listener recipient limit. |
| `banner` | unused | Accepted but not currently used by the SMTP backend. |

`implicit` means TLS from the first byte (typically port 465). `starttls` starts
in plaintext and upgrades on the client's request. `none` is intended for
loopback filter links.

### Listener modes

**`mta` — inbound mail exchanger**

- Accepts recipients in `domains.txt`.
- Relays to non-local domains only for authenticated users or clients in
  `relay_networks`.
- Runs the full inbound plugin pipeline.
- Use `:25` in production.

**`submission` — authenticated user submission**

- `require_auth` is forced to true.
- All MAIL/RCPT commands require AUTH.
- Accepts local and remote recipients.
- Useful for outbound mail from applications and users.
- Use `:587` (STARTTLS) or `:465` (implicit TLS) in production.

**`filter` — filtering MTA**

- Accepts only recipients in `domains.txt`; relaying is denied.
- Local recipients are delivered through `routing.filter_upstream` when it is
  configured, otherwise through the normal local backend.
- Usually listens on loopback with `tls: none` and receives mail from a front
  MTA such as Postfix.
- Non-local recipients are rejected with `550 5.7.1 Relaying denied`.

A single process can run any combination of listeners.

## Relay policy

```yaml
relay_networks:
  - 127.0.0.1/32
  - ::1/128
  - 10.0.0.0/8
```

Clients whose remote IP matches this list may relay to non-local domains without
authenticating on `mta` listeners. Submission listeners still require AUTH.
Keep this list as small as possible. An empty list is replaced with the loopback
defaults.

## Routing and delivery

```yaml
routing:
  local_backend: maildir
  local_options:
    path: mail

  outbound_backend: smtp
  outbound_options:
    tls: opportunistic
    timeout: 2m

  # Optional downstream for `filter` mode:
  filter_upstream: "lmtp://127.0.0.1:24"
  filter_options: {}
```

| Field | Default | Description |
| --- | --- | --- |
| `local_backend` | `maildir` | Backend for recipients in local domains. |
| `local_options` | `{path: mail}` for Maildir | Backend-specific options. |
| `outbound_backend` | `smtp` | Backend for non-local recipients. |
| `outbound_options` | `{}` | Backend-specific options. |
| `filter_upstream` | empty | URL for filter-mode local delivery. |
| `filter_options` | `{}` | Extra options merged into the filter backend. |

`filter_upstream` accepts:

```text
smtp://host:25
smtps://user:password@host:465
lmtp://127.0.0.1:24
http://127.0.0.1:8081/deliver
https://example.net/inbound
```

For `smtp` URLs a missing port defaults to 25, for `smtps` to 465, and for
`lmtp` to 24. HTTP(S) endpoints receive a JSON envelope with the message
base64-encoded. See [plugins.md](plugins.md#delivery-backends) for every backend
option.

The local backend also receives local mail on `mta` and `submission` listeners.
With the default Maildir backend, messages are stored under:

```text
<path>/<domain>/<local-part>/new/
```

## Queue

```yaml
queue:
  dir: data/queue
  workers: 4
  max_attempts: 6
  retry_schedule:
    - 1m
    - 5m
    - 15m
    - 1h
    - 6h
```

| Field | Default | Description |
| --- | --- | --- |
| `dir` | `<data_dir>/queue` | Spool directory. Created lazily. |
| `workers` | `4` | Concurrent delivery workers. |
| `max_attempts` | `6` | Attempts before a recipient is marked permanently failed. |
| `retry_schedule` | 1m, 5m, 15m, 1h, 6h | Delay between attempts. The last value is reused if attempts exceed the list. |

The spool contains one `<id>.json` envelope and one `<id>.eml` message per
queued item. When every recipient is delivered the files are removed. If a
recipient permanently fails after retries, the message is retained in
`<queue>/failed/` with its envelope. Messages quarantined by plugins are written
to `<data_dir>/quarantine/`.

A 4xx delivery result is retried. A 5xx result is permanent. No bounce/DSN is
generated automatically; monitor the failed directory or the stats endpoint.

## Status server

```yaml
status_addr: "127.0.0.1:8080"
```

Endpoints:

| Path | Response |
| --- | --- |
| `/healthz` | `200 ok` once the process is running. |
| `/readyz` | `200 ready` once the process is running. |
| `/stats` | JSON snapshot with hostname, uptime, listeners, domains, backend names, plugin entries, queue counts, user count, and plugin worker count. |

`gomta status -config gomta.yaml` prints the same snapshot without starting a
server. `gomta status -json=false` prints a short human-readable summary. Set
`status_addr: ""` to disable the HTTP server entirely.

## `domains.txt`

One domain per line. Blank lines and `#` comments are ignored. Domains are
lowercased and must be valid.

```text
# Domains accepted for local delivery.
example.com
example.org
```

Only these domains are treated as local. Everything else is outbound (or denied
on a filter listener).

## `users.txt`

One credential per line:

```text
user@example.com:$2a$12$...
```

- Bcrypt hashes are recommended. `gomta init` writes one.
- `plain:password` is accepted for development only.
- Usernames are case-insensitive.
- Short login names are accepted when they are unambiguous: `postmaster` is
  tried as `postmaster@<each-local-domain>`.
- The file is read at startup; restart after editing.

To create a bcrypt hash with common tools:

```sh
# Apache htpasswd
htpasswd -bnBC 12 "" 'your-password' | tr -d ':\n'

# Or let GoMTA generate a complete instance and copy its format:
gomta init -domain example.com -hostname mail.example.com
```

Passwords must be at least 8 characters when generated through GoMTA's helper;
the authentication path itself accepts any bcrypt hash.

## Validation rules

`gomta check` fails when:

- A required field is missing or a duration/integer cannot be parsed.
- An unknown YAML field is present.
- A listener uses an invalid mode or TLS value.
- Two listeners share a name or a non-`0` address.
- `allow_insecure_auth` is set on a non-loopback listener.
- A relay network is not a valid IP or CIDR.
- A TLS certificate is required but missing and `auto_generate` is false.
- A plugin or delivery backend name is unknown or its options are invalid.
- A local Maildir path cannot be created.

## See also

- [Plugins and delivery backends](plugins.md)
- [Deployment guide](deployment.md)
- [Minimal example](../examples/minimal/)
 
## Queue delivery guarantees and DSN

The spool persists each payload before its envelope. Delivery is **at-least-once**:
if the process crashes after the remote server accepts DATA but before the
recipient outcome is saved, the message may be retried and duplicated. Remote
receivers and webhook integrations should deduplicate using the GoMTA message ID.

`queue.max_age` (default `120h`) bounds retries by elapsed age, while
`queue.max_attempts` (default `100`) is an additional cap. A 4xx error
is retried until one of these conditions is reached; permanent 5xx results
fail immediately.

`queue.send_dsn` enables multipart delivery-status notifications for failed
authenticated submissions, using a null reverse-path to avoid loops.
`queue.dsn_inbound` defaults to `false` to avoid backscatter from forged
unauthenticated senders. Enabling inbound DSN requires a trusted sender policy.
Notifications use stable queue IDs, but SMTP delivery remains at-least-once.

## Resource limits

`limits.max_data_memory_bytes` (default 128 MiB) reserves a shared
budget before reading DATA into memory across all SMTP listeners. The value
must exceed `limits.max_message_bytes`. Plugins can perform additional
allocations, so the budget is not a total RSS cap. Connection limits also
apply globally across all configured listeners.

The Maildir backend accepts `max_mailbox_bytes` (default 512 MiB) and
`max_domain_bytes` (default 5 GiB). Quota checks are synchronized inside
one process, not across multiple instances writing to the same shared disk.
Use an external mailbox backend with central quotas in clustered deployments.

The rate-limit plugin accepts `scope: smart` (authenticated account or
per-IP for unauthenticated clients), `skip_authenticated: false` and
`fail_closed: true`. Shared rate limits across nodes require Redis.
SMTP AUTH also enforces per-IP failure windows across connections within
a single GoMTA process.

 
## Audit follow-up: identity, quotas and plugin memory

`authorized_senders` is a top-level map from authenticated mailbox to explicit
aliases that the account may use in SMTP `MAIL FROM` and the message `From`
header. No wildcard or implicit domain delegation is permitted:

```yaml
authorized_senders:
  alice@example.com:
    - billing@example.com
    - support@example.com
```

`validate_local_recipients: true` rejects unknown recipients **including when
users.txt is empty**. For a deliberate catch-all configuration, set this flag
to false and supply an appropriate storage policy.

Maildir quotas cache domain and mailbox bytes, reconciling on first delivery,
every five minutes, and when a limit would otherwise be exceeded. Writers
outside this GoMTA instance can temporarily make counters stale; shared
mailboxes require centralized quotas for strict enforcement.

The memory budget now also caps aggregate plugin DATA snapshot allocations.
It is separate from SMTP DATA reservations and does not claim to bound Go's
total RSS or allocations inside third-party plugins.

SMTP AUTH uses a per-process atomic in-flight and failed-attempt budget by
IP and presented username. All state expires after a fixed window and the
number of tracked identities is bounded. Multi-instance deployment requires
a shared counter store for cluster-wide enforcement.

Queue recipients are journaled before observational delivery hooks. Delivery
status notifications are tracked per failed recipient and can be reconstructed
from the persistent queue if a notification publication was interrupted.
The transport remains at-least-once, including DSNs.

 
## Spool reconciliation and retention

The queue checks for orphaned `.eml` files without a matching visible `.json`
envelope, and for stale interrupted `.tmp-*` files. `queue.orphan_grace`
(default `24h`) keeps recent incomplete publications untouched. Cleanup runs
at startup and hourly. It **never deletes visible queue entries**.

`queue.failed_retention` is opt-in: `0s` (the default) retains failed
messages and delivery-status markers indefinitely. Set a duration (at least
`24h`) only after establishing backups and operational retention policies.
Expired archive envelopes are removed before payloads. DSN markers are
preserved as long as the associated original envelope remains in the spool
or failed archive. One running GoMTA worker pool holds an exclusive OS lock
on its spool; a second process must fail startup instead of delivering the
same recipients concurrently. The lock is advisory and requires a filesystem
that implements the relevant OS locking semantics.

 
## Additional safeguards after the fourth audit

The `rate_limit` plugin's `scope: smart` now counts unauthenticated SMTP
traffic by **IP alone**. The unauthenticated sender is client-controlled; using
it as part of the limit key allowed a client to bypass the limit by rotating
`MAIL FROM`. Authenticated submissions remain grouped by authenticated user.

For the `exec` filtering plugin, `max_output_bytes` is a strictly enforced
capture limit (default 64 MiB). Process stdout terminates with an error when
it grows beyond this cap, even with `replace_body: false`. Stderr diagnostics
are retained up to 64 KiB. Oversized resulting message bodies are rejected by
the SMTP pipeline, including after message/header transformations. Plugins
running inside the Go process can still allocate memory before returning, so
runtime isolation of untrusted plugins requires a separate process.

The Maildir backend uses the local recipient identity in lowercase, matching
GoMTA's case-insensitive `users.txt` lookup. The original SMTP recipient is
still recorded in `Delivered-To` and `X-Original-To`. Domain quota
reservations are serialized briefly; disk I/O occurs outside the lock to
permit concurrent delivery to the same domain. Quota counters are per process
and periodically reconciled with the filesystem.

Readiness now requires a small durable file write, sync, close, delete, and
on POSIX systems a directory sync. It checks basic spool persistence, not
whether every future large message can be accepted.


## Fifth audit: mailbox identity, DSN and queue recovery

GoMTA deduplicates local SMTP recipients using the case-insensitive mailbox
identity of the configured users catalog; remote SMTP local parts preserve
their original spelling. Maildir delivery is idempotent for a stable queue
message ID and canonical mailbox address. Both new/ and cur/ are consulted,
so a retry after an uncertain directory sync does not create another copy
while the first copy remains present. This does **not** provide exactly-once
delivery with a remote SMTP server or across lost filesystem writes.

An authenticated sender authorized to use an explicit alias is recorded
persistently as `sender_authorized` in the envelope. This allows DSN to be
issued for delegated senders without enabling DSN backscatter for anonymous
inbound SMTP. Old queued envelopes remain compatible where AuthUser == From.

When a visible envelope has no payload, its metadata and diagnosis are
preserved under `queue.dir/corrupt/` and the active queue entry is removed
only after durable preservation and any applicable DSN publication.
Malformed envelope JSON is preserved byte-for-byte as `.envelope` for
administrative recovery. These records are **not** automatically deleted.

SMTP starts accepting connections only after the queue has acquired its
exclusive spool lock and is initially ready. The durable spool probe runs
every 30 seconds, not on every normal queue scan. Auxiliary `.tmp-*` files
under `failed/`, `corrupt/` and the quarantine directory are cleaned
after `queue.orphan_grace`.

SMTP DATA grows its memory reservations progressively as bytes arrive
instead of reserving the entire configured maximum for every small message.
This accounts for retained input buffers rather than every temporary
allocation by Go, TLS, content filters, or delivery workers.

 
## Sixth audit: integrity and memory ownership

Newly queued messages commit both `payload_size` and `payload_sha256` into
their durable JSON envelopes. The worker checks both before attempting
delivery; a mismatch is preserved with the raw payload in `queue/corrupt/`
for manual recovery. Legacy queue envelopes without a checksum continue
working, but cannot benefit from this integrity check. The scanner rejects
envelopes whose embedded IDs do not match the physical filename before
executing any delivery, DSN or archival action.

Plugin runners now pre-admit the entire maximum subprocess stdout/stderr
working set *together* with an input DATA snapshot, avoiding the circular
wait caused by nested memory acquisitions. A returned transformed body keeps
its memory lease until it is replaced or its SMTP DATA transaction ends.
A filter with `max_output_bytes` larger than the available execution budget
will not start; lower this option or increase the configured budget.

Stale Maildir `tmp/` files older than 24 hours are removed conservatively
during mailbox delivery and quota reconciliation. Recent temporary writes
are preserved. Mailbox lock entries are released when idle; retries can
still perform a linear lookup in `cur/` when searching for an already read
message.


## Seventh audit: publication and integrity protections

The spool publishes new payloads and envelopes **exclusively**. An existing
message ID, including an envelope whose payload is absent, is rejected instead
of silently overwritten. Initial publication uses a synced temporary file
linked into the destination name; the spool filesystem must support hard
links for this atomic no-clobber operation. Existing envelope state updates
still use atomic replacement.

The worker verifies the size and SHA-256 of modern payloads before delivery
**and archival**. Oversized or corrupted payloads are identified before
allocating an in-memory message, and the original on-disk payload is retained
under `queue/corrupt/` using a hard link. Legacy queue files without
checksums are still subject to the configured maximum message size. If the
filesystem cannot preserve corruption evidence safely, the active record is
not removed.

Authenticated messages revalidate the RFC5322 `From` identity after
content-transforming plugins, before later ordered signing plugins and again
before queue publication. Plugins cannot change their own authenticated
sender validation policy.

The `/stats` queue object now includes `corrupt` and
`oldest_corrupt_age` in addition to `quarantined`. The former counts
recovery diagnostics under `queue/corrupt/`; the latter counts content
quarantined by policy.
