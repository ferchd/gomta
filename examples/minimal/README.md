# Minimal example

This directory is a complete configuration that can be validated and run
without `gomta init`. It uses unprivileged ports and a self-signed certificate.

## Validate

```sh
go build -o gomta ./cmd/gomta
./gomta check -config examples/minimal/gomta.yaml
```

`check` creates `examples/minimal/tls/`, `data/`, and `mail/` because the config
enables TLS auto-generation and the Maildir backend. Those paths are ignored by
git.

## Run

```sh
./gomta serve -config examples/minimal/gomta.yaml
```

## Send a test message

The example user is `postmaster@example.com` with password `changeme`:

```sh
./gomta send -server 127.0.0.1:5587 \
  -from postmaster@example.com \
  -to postmaster@example.com \
  -user postmaster@example.com \
  -password changeme \
  -insecure
```

The message is written to:

```text
examples/minimal/mail/example.com/postmaster/new/
```

## Differences from `gomta init`

- No DKIM key or `dkim_sign` plugin; add one with
  `gomta dkim-keygen -domain example.com -selector default -out examples/minimal/dkim/default.key`.
- No generated admin password; the example hash is for `changeme`.
- TLS is self-signed and generated on demand.
- Ports are `2525` / `5587` instead of `25` / `587`.

For a production-shaped setup, run `gomta init` in an empty directory and use
that output instead.
