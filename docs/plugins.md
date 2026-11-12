# Plugins and delivery backends

GoMTA has two extension points:

- **Plugins** observe or modify an SMTP transaction at a lifecycle hook.
- **Delivery backends** move an accepted message to its destination.

Both are ordinary Go packages with registries. Built-ins register themselves in
`init()`, so importing a package for its side effects is enough.

## Hook lifecycle

| Hook | When it runs | Typical use |
| --- | --- | --- |
| `connect` | When the SMTP session is created, after the client greeting and before MAIL. | DNS blocklists, connection policy. |
| `helo` | At session creation, immediately after `connect`. The HELO/EHLO name is available. | HELO validation. |
| `mail` | After `MAIL FROM`. | SPF, sender rate limits. |
| `rcpt` | For each accepted `RCPT TO`. `tx.Recipient` holds the current recipient. | Greylisting, recipient policy. |
| `data` | After the complete message has been read. | DKIM verification, DMARC, spam/virus scanning, content filters. |
| `queue` | After DATA decisions, just before the message is written to the spool. A `Received` header has already been added. | Header generation, DKIM signing. |
| `disconnect` | When the SMTP session closes. Decisions are logged but cannot change an already accepted message. | Audit and accounting. |
| `delivery` | Reserved for a future per-delivery hook. Not currently invoked. | — |

`connect` and `helo` both run when the session object is created. This happens
after the client sends EHLO/HELO, so both hooks can see `tx.Helo`. A client that
never greets never reaches MAIL/DATA.

### Transaction data

Plugins receive `*plugin.Tx`. Fields are read-only once the hook starts:

| Field | Meaning |
| --- | --- |
| `ID` | Queue ID. Assigned at DATA. |
| `RemoteIP`, `RemoteIPs`, `RemoteAddr` | Client address information. |
| `Helo` | HELO/EHLO argument. |
| `TLS`, `TLSVersion` | Whether the session is encrypted and the protocol version. |
| `AuthUser` | Authenticated user, or empty. |
| `MailFrom` | Normalized envelope sender. |
| `RcptTo` | Accepted recipients so far. |
| `Recipient` | Current recipient during the `rcpt` hook. |
| `Data` | Raw message bytes (data/queue hooks). |
| `Header` | Parsed header map (data/queue hooks). |
| `Size` | Current message size. |
| `Mode` | `mta`, `submission`, or `filter`. |
| `ServerName` | Configured hostname. |
| `Arrived` | When the transaction started. |

Use `tx.SetMeta`, `tx.Meta`, `tx.MetaString`, and `tx.MetaSnapshot` for state
shared between plugins and hooks. Metadata is copied into the queue envelope and
is available to later hooks.

Do not mutate `tx.Data` or `tx.Header` directly. Return body changes in
`Outcome.Body` and headers in `Outcome.Headers`; the runner applies them in a
deterministic order.

### Outcomes and decisions

```go
type Outcome struct {
    Action  plugin.Action
    Code    int
    Message string
    Headers []plugin.Header
    Body    []byte
    Meta    map[string]any
    Tags    []string
}
```

| Action | Effect |
| --- | --- |
| `ActionContinue` | No objection. |
| `ActionAccept` | Explicitly accept the transaction, but stronger decisions still win. |
| `ActionQuarantine` | Accept the SMTP transaction and store the message in `<data_dir>/quarantine/` without delivering it. |
| `ActionDiscard` | Accept the transaction and silently drop the message. |
| `ActionTempFail` | Return a 4xx and ask the client to retry. |
| `ActionReject` | Return a 5xx and permanently reject. |

Precedence is:

```text
continue < accept < quarantine < discard < tempfail < reject
```

The runner merges every plugin outcome; the strongest decision becomes the hook
decision. A rejection message is sanitized to one line before it is sent to the
client. `quarantine` and `discard` are acted on at the `data` and `queue` hooks;
at earlier hooks only reject/tempfail decisions affect the SMTP transaction.

Constructors:

```go
plugin.Reject(550, "5.7.1 blocked")
plugin.TempFail(451, "4.7.1 try again")
plugin.OK()
```

### Concurrency and ordering

Plugins attached to the same hook run **concurrently**. `plugins.yaml`'s
`workers` value limits how many run at once; the server never serializes a slow
DNS or HTTP lookup behind unrelated plugins.

Some plugins need results from other plugins or need to transform the body in
order. Implement the optional `plugin.Ordered` interface:

```go
func (p *Plugin) RunOrdered() bool { return true }
```

The runner then performs two phases:

1. All non-ordered plugins run concurrently. Their headers and metadata are
   merged before phase two.
2. Ordered plugins run one at a time in ascending `priority` order. Each sees
   the body and headers produced by earlier plugins.

Built-ins that are ordered: `headers`, `dkim_sign`, `dmarc`, and `exec`.
`headers` has priority 100 and `dkim_sign` priority 200 so the DKIM signature
covers generated headers.

If you write a body transformer, make it ordered. Two concurrent transformers
have no defined order; the later merge would overwrite the other result.

### Timeouts and failures

- `timeout` in `plugins.yaml` is the overall deadline for one hook invocation.
- A plugin can override it with its own `timeout` field.
- If a plugin returns an error, panics, or exceeds its timeout, the error is
  logged and the plugin is treated as `continue`.
- `fail_closed: true` changes that behavior: an individual plugin error becomes
  `451 4.7.1 Local policy check failed`.
- If the overall hook deadline expires, the result is `451 4.7.0 Policy check
  timed out` unless a plugin already produced a reject or tempfail.

Timeouts apply per hook invocation, not to the whole session or delivery.

## `plugins.yaml`

```yaml
workers: 8
timeout: 8s

plugins:
  - name: spf
    enabled: true
    priority: 10
    timeout: 3s
    fail_closed: false
    hooks: [mail]          # optional subset of the plugin's hooks
    options:
      reject_fail: false
      skip_authenticated: true
      skip_submission: true
```

| Field | Default | Description |
| --- | --- | --- |
| `workers` | `8` | Maximum concurrent non-ordered plugins per hook. |
| `timeout` | `8s` | Default per-plugin timeout. |
| `name` | required | Registered plugin name. |
| `enabled` | `true` | Set `false` to keep a configuration block without loading it. Disabled plugins are not constructed, so missing files/keys are not an error. |
| `priority` | `0` | Lower runs first. Controls ordered phase and deterministic result merging. |
| `timeout` | global timeout | Per-plugin override. |
| `fail_closed` | `false` | Turn plugin errors into a temporary failure. |
| `hooks` | all advertised | Restrict the plugin to a subset of its hooks. |
| `options` | `{}` | Plugin-specific free-form map. |

Unknown plugin names and invalid option values abort startup. `gomta check`
catches them before the server binds a port.

Plugin file paths resolve against the directory containing `gomta.yaml`
(`BuildContext.BaseDir`). `~/` is expanded for plugin paths.

## Built-in plugins

| Plugin | Hooks | Ordered | Purpose |
| --- | --- | --- | --- |
| `headers` | `queue` | yes | Add `Message-ID`, `Date`, `Authentication-Results`, and spam headers. |
| `helo` | `helo` | no | Validate the HELO/EHLO name. |
| `spf` | `mail` | no | Evaluate SPF and optionally reject failures. |
| `dnsbl` | `connect` | no | Check the client IP against DNS blocklists. |
| `rate_limit` | `mail` | no | Per-IP, per-user, or per-sender message limits. |
| `greylist` | `rcpt` | no | Classic greylisting with optional Redis state. |
| `rspamd` | `data` | no | Scan with an rspamd HTTP or Unix-socket endpoint. |
| `clamav` | `data` | no | Scan with clamd using INSTREAM. |
| `dkim_verify` | `data` | no | Verify DKIM signatures and record the result. |
| `dmarc` | `data` | yes | Evaluate DMARC using SPF/DKIM results and apply policy. |
| `dkim_sign` | `queue` | yes | Sign outgoing mail. |
| `exec` | `data` | yes | Run an external content filter. |

### `headers`

Adds headers at queue time, before DKIM signing.

```yaml
- name: headers
  priority: 100
  options:
    add_message_id: true
    add_date: true
    add_auth_results: true
    add_spam_headers: true
    spam_threshold: 5
```

- Only adds `Message-ID` or `Date` when the message lacks them.
- `Authentication-Results` is built from `spf.result`, `dkim.result`, and
  `dmarc.result`.
- Spam headers use rspamd metadata, SPF failures, and DNSBL hits. A score at or
  above `spam_threshold` adds `X-Spam-Flag: YES`.

### `helo`

```yaml
- name: helo
  priority: 5
  options:
    reject_invalid: true
    reject_localhost: false
    allow_ip_literals: true
    min_labels: 2
    skip_submission: true
```

Rejects malformed names, spaces, invalid IP literals, single-label names, and
optionally `localhost`. `skip_submission` defaults to true so authenticated
clients using a local hostname are not punished.

### `spf`

Evaluates the envelope sender (falling back to HELO) against SPF. Supports
`ip4`, `ip6`, `a`, `mx`, `include`, `redirect`, `exists`, `ptr`, macros,
`exp=`, and the RFC lookup/void limits.

```yaml
- name: spf
  priority: 10
  options:
    reject_fail: false       # reject on -all
    reject_softfail: false   # reject on ~all
    reject_none: false       # reject when no SPF record exists
    tempfail_on_error: false
    skip_authenticated: true
    skip_submission: true
    trusted_networks: [10.0.0.0/8]
```

Metadata: `spf.result` (`pass`, `fail`, `softfail`, `neutral`, `none`,
`temperror`, `permerror`, `trusted`), `spf.domain`, `spf.identity`,
`spf.explanation`.

### `dnsbl`

Queries one or more DNS blocklists using the reversed client IP. Private,
loopback, link-local, and explicitly allowlisted addresses are skipped.

```yaml
- name: dnsbl
  priority: 5
  options:
    zones: [zen.spamhaus.org, bl.spamcop.net]
    reject_listed: true
    skip_private: true
    skip_submission: true
    lookup_txt: true
    allowlist:
      - 192.0.2.10
      - 198.51.100.0/24
```

Downloading public blocklists does not grant Spamhaus data access; use a
resolver/service that is permitted to query the zone you choose.

Metadata: `dnsbl.listed`, `dnsbl.zones`, `dnsbl.reason`, `dnsbl.error`.

### `rate_limit`

Counts messages per key with a TTL. Uses an in-process store by default, or
Redis when `redis_url` is set.

```yaml
- name: rate_limit
  priority: 30
  options:
    scope: ip+sender        # ip, auth, sender, ip+sender
    limit: 200
    window: 1h
    action: tempfail        # tempfail or reject
    code: 0                 # 0 = 451/550 based on action
    skip_authenticated: true
    trusted_networks: [10.0.0.0/8]
    # redis_url: redis://127.0.0.1:6379/0
```

The limit is per window and keyed by the selected scope. Store errors fail open
(messages are allowed) and are logged. Metadata: `rate_limit.count`,
`rate_limit.limit`.

### `greylist`

Defers unknown `(client IP, sender, recipient)` triples for a delay, then lets
them pass for a longer TTL.

```yaml
- name: greylist
  priority: 40
  options:
    delay: 5m
    pass_ttl: 36h
    whitelist_authenticated: true
    whitelist_networks: [10.0.0.0/8]
    # redis_url: redis://127.0.0.1:6379/0
```

The hook runs on RCPT. The first attempt receives `450 4.7.1`; a retry after the
delay is accepted and the triple is remembered. Store errors fail open. Metadata:
`greylist.result` (`new`, `deferred`, `passed`).

### `rspamd`

Posts the raw message to rspamd's `/checkv2` endpoint.

```yaml
- name: rspamd
  priority: 50
  options:
    url: http://127.0.0.1:11333
    password: ${RSPAMD_PASSWORD}
    timeout: 20s
    reject_action: false
    reject_soft_reject: false
    enforce_greylist: false
    tempfail_on_error: false
    skip_authenticated: true
    trusted_networks: [10.0.0.0/8]
```

`url` may also be `unix:///run/rspamd/rspamd.sock`. By default, an rspamd
`reject` action only tags the message and adds spam headers; set
`reject_action: true` to return `550`. Metadata: `rspamd.score`,
`rspamd.action`, `rspamd.symbols`, `rspamd.messages`, `rspamd.error`.

### `clamav`

Scans with clamd over TCP or a Unix socket.

```yaml
- name: clamav
  priority: 60
  options:
    address: 127.0.0.1:3310       # or unix:///run/clamav/clamd.sock
    timeout: 30s
    on_virus: reject              # reject, tempfail, quarantine, tag
    tempfail_on_error: false
    skip_authenticated: false
```

Metadata: `clamav.result` (`clean`, `infected`, `error`), `clamav.virus`,
`clamav.error`.

### `dkim_verify`

Verifies every DKIM signature using DNS TXT records.

```yaml
- name: dkim_verify
  priority: 10
  options:
    max_verifications: 10
    reject_fail: false
    reject_unsigned: false
    reject_temperror: false
```

Metadata: `dkim.result` (`pass`, `fail`, `none`, `temperror`),
`dkim.signatures`, `dkim.valid`, `dkim.domain`, `dkim.identity`,
`dkim.domains` (comma-separated domains with a valid signature).

### `dmarc`

Runs after DKIM verification. Looks up the `_dmarc` record for the `From`
domain, falls back to the organizational domain, and checks relaxed or strict
alignment against SPF and DKIM results.

```yaml
- name: dmarc
  priority: 20
  options:
    enforce: none                  # none, quarantine, reject
    tempfail_on_error: false
    skip_authenticated: true
    skip_submission: true
    quarantine_as_reject: false
```

`enforce` is the maximum policy GoMTA will apply. With `none`, DMARC only
annotates. With `quarantine` or `reject`, the effective policy is the weaker of
the published policy and `enforce`. `pct` is honored deterministically per
queue ID, so retries make the same decision. A missing record sets
`dmarc.result=none` and does not reject.

Metadata: `dmarc.result`, `dmarc.domain`, `dmarc.record_domain`,
`dmarc.policy`, `dmarc.spf_aligned`, `dmarc.dkim_aligned`, `dmarc.error`.

### `dkim_sign`

Signs messages at queue time. Must run after `headers`, which is why the default
priorities are 100 and 200.

```yaml
- name: dkim_sign
  priority: 200
  options:
    selector: default
    key_file: dkim/default.key     # or `key:` with inline PEM
    sign_domains: [example.com]
    modes: [submission]            # mta, submission, filter
    headers: [From, To, Subject, Date, Message-ID, MIME-Version,
              Content-Type, Content-Transfer-Encoding]
    canonicalization: relaxed/relaxed
    expire: 0
    skip_signed: true
    required: false
```

- The signing domain is `domain:` if set, otherwise the `From` header domain.
- `sign_domains` limits signing to those domains.
- `modes` limits signing by listener mode.
- `skip_signed` avoids adding a second signature with the same domain and
  selector.
- `required: true` turns signing failures into a temporary failure instead of a
  logged error.
- RSA keys smaller than 1024 bits are rejected.

Generate a key and DNS record:

```sh
gomta dkim-keygen -domain example.com -selector default -out dkim/default.key
```

Metadata: `dkim.signed`, `dkim.domain`, `dkim.selector`.

### `exec`

Runs an external command with the raw message on stdin and an environment
describing the transaction.

```yaml
- name: exec
  priority: 70
  options:
    command: /usr/local/bin/filter
    args: ["--mode", "inbound"]
    timeout: 30s
    replace_body: true
    accept_codes: [0]
    tempfail_codes: [75]
    tempfail_on_error: true
    max_output_bytes: 67108864
    reject_message: Message rejected by content filter
    tempfail_message: Content filter temporarily unavailable, try again
    env:
      FILTER_MODE: inbound
```

- Exit `0` accepts and, when `replace_body` is true and stdout is non-empty,
  replaces the message with stdout.
- Codes in `tempfail_codes` return 451; other non-zero codes return 550.
- A missing executable or timeout follows `tempfail_on_error`.
- Environment variables include `GOMTA_HOOK`, `GOMTA_QUEUE_ID`, `GOMTA_FROM`,
  `GOMTA_RCPT`, `GOMTA_HELO`, `GOMTA_REMOTE_ADDR`, `GOMTA_REMOTE_IP`,
  `GOMTA_AUTH_USER`, `GOMTA_MODE`, `GOMTA_SERVER_NAME`, `GOMTA_TLS`, and
  `GOMTA_SIZE`.

Metadata: `exec.exit_code`, `exec.error`.

## Delivery backends

Delivery is selected by `routing.local_backend`, `routing.outbound_backend`, or
`routing.filter_upstream`. Every backend returns a per-recipient error; temporary
errors are retried, permanent errors are recorded.

| Backend | Use |
| --- | --- |
| `smtp` | Direct-to-MX or smarthost SMTP. |
| `lmtp` | Local delivery agent or downstream mailbox server. |
| `maildir` | Simple file-based mailbox store. |
| `http` | Webhook/API delivery. |
| `exec` | External delivery command. |
| `discard` | Accept and drop. |

### `smtp`

```yaml
routing:
  outbound_backend: smtp
  outbound_options:
    smarthost: smtp.example.net:587
    tls: required                 # opportunistic, required, none, implicit
    username: relay-user
    password: ${RELAY_PASSWORD}
    helo: mail.example.com
    timeout: 2m
    connect_timeout: 15s
    insecure_skip_verify: false
```

Without `smarthost`, the backend looks up MX records, sorts by preference, and
tries them in order. If a domain has no MX record it falls back to
`<domain>:25`. Recipients are grouped by domain. `opportunistic` probes for
STARTTLS and upgrades when available; `required` fails if STARTTLS is missing;
`implicit` assumes TLS from the first byte.

### `lmtp`

```yaml
routing:
  filter_upstream: "lmtp://127.0.0.1:24"
  filter_options:
    helo: mail.example.com
    timeout: 2m
    connect_timeout: 15s
```

`host` must include a port when configured through `local_options` or
`outbound_options`. The URL form supplies a default port of 24.

### `maildir`

```yaml
routing:
  local_backend: maildir
  local_options:
    path: mail
    hostname: mail.example.com
```

Messages are written with an atomic `tmp` → `new` rename under
`<path>/<domain>/<local-part>/new/`. `Delivered-To` and `X-Original-To` headers
are added. Invalid address components are sanitized.

### `http`

```yaml
routing:
  filter_upstream: "https://mail.example.net/inbound"
  filter_options:
    token: ${WEBHOOK_TOKEN}
    timeout: 30s
    headers:
      X-GoMTA: "1"
```

The backend POSTs JSON:

```json
{
  "id": "queue-id",
  "from": "sender@example.com",
  "to": ["rcpt@example.com"],
  "mode": "mta",
  "helo": "client.example.com",
  "remote_ip": "192.0.2.10",
  "meta": {"spf.result": "pass"},
  "message_base64": "..."
}
```

A 2xx response means success. A 4xx response is permanent; a 5xx response or
transport error is temporary. `token` is sent as a bearer token.

### `exec`

```yaml
routing:
  local_backend: exec
  local_options:
    command: /usr/local/bin/deliver
    args: ["--mailbox-root", "/var/mail"]
    timeout: 2m
```

The command receives the same JSON envelope as the HTTP backend on stdin,
base64-encoded message included. Exit `0` is success, `75` is temporary, and any
other non-zero exit is permanent. The command runs with the configuration
directory as its working directory.

### `discard`

```yaml
routing:
  outbound_backend: discard
```

Accepts every recipient and drops the message. Useful for testing and for
sinkhole routes.

## Writing a plugin

Plugins are normal Go packages. Register a factory in `init()`:

```go
package example

import (
    "context"
    "fmt"
    "strings"

    "github.com/ferchd/gomta/plugin"
)

func init() {
    plugin.Register("example", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
        return &Plugin{
            header: opts.String("header", "X-Example"),
        }, nil
    })
}

type Plugin struct {
    header string
}

func (p *Plugin) Name() string { return "example" }

func (p *Plugin) Hooks() []plugin.Hook {
    return []plugin.Hook{plugin.HookData}
}

func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
    if strings.Contains(strings.ToLower(string(tx.Data)), "forbidden") {
        return plugin.Reject(550, "5.7.1 message content rejected"), nil
    }
    return plugin.Outcome{
        Action:  plugin.ActionContinue,
        Headers: []plugin.Header{{Name: p.header, Value: "checked"}},
        Meta:    map[string]any{"example.checked": true},
    }, nil
}
```

To load it, add a blank import to `cmd/gomta/main.go` (or your fork's main
package):

```go
import (
    _ "github.com/ferchd/gomta/internal/plugins/all"
    _ "github.com/yourorg/gomta-example"
)
```

The stock `cmd/gomta` imports the built-ins for their side effects. The built-in
packages and the service wiring live under `internal/`, so an external `main`
cannot import them directly; build a fork of this repository, or add your plugin
under `internal/plugins/`, and keep the blank import in the in-repository main
package. Your plugin package itself may live in another module.

Guidelines:

- Honor `ctx` cancellation and return promptly.
- Treat `Tx` fields as read-only.
- Return errors for operational failures; configure `fail_closed` if the check
  must block mail when it fails.
- Use `plugin.Ordered` for body transforms or dependency-sensitive checks.
- Keep secrets in environment variables or files, not in logs.

## Writing a delivery backend

```go
package example

import (
    "context"
    "fmt"

    "github.com/ferchd/gomta/delivery"
    "github.com/ferchd/gomta/plugin"
)

func init() {
    delivery.Register("example", func(bc plugin.BuildContext, opts plugin.Options) (delivery.Backend, error) {
        return &Backend{path: opts.String("path", "")}, nil
    })
}

type Backend struct {
    path string
}

func (b *Backend) Name() string { return "example" }

func (b *Backend) Deliver(ctx context.Context, m *delivery.Message) map[string]error {
    out := make(map[string]error, len(m.To))
    for _, rcpt := range m.To {
        if b.path == "" {
            out[rcpt] = delivery.Perm(fmt.Errorf("path is required"))
            continue
        }
        out[rcpt] = deliverOne(ctx, b.path, rcpt, m.Data)
    }
    return out
}
```

Return `nil` for success, `delivery.Temp(err)` to retry, or `delivery.Perm(err)`
to fail permanently. `delivery.Message` contains the queue ID, envelope sender,
recipients, raw data, metadata, listener mode, HELO, and remote IP.

Blank-import the package in the in-repository main package exactly like a
plugin (the same `internal/` import restriction applies). Then reference it by
name:

```yaml
routing:
  local_backend: example
  local_options:
    path: /var/spool/example
```

## Inspecting what is loaded

```sh
gomta plugins
gomta backends
gomta check -config gomta.yaml
gomta status -config gomta.yaml -json=false
```

`gomta check` prints each hook and the plugin names attached to it, which is the
fastest way to confirm priorities and `hooks:` filters.
