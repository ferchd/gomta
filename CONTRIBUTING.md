# Contributing to GoMTA

Thanks for taking the time to improve GoMTA. This document covers the
development workflow, expectations for changes, and how to report problems.

## Code of conduct

Everyone participating in this project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior according to
the process described there.

## Before you start

- Search [existing issues](https://github.com/ferchd/gomta/issues) and pull
  requests to avoid duplicate work.
- For large changes, open an issue first so the design can be discussed before
  you invest time in an implementation.
- Security problems must not be reported in public issues. Follow
  [SECURITY.md](SECURITY.md).

## Development environment

Requirements:

- Go 1.27.3 or newer (the version in `go.mod`).
- Git.
- Optional: Docker with Buildx for container changes, and WSL or a Unix-like
  shell if you want to use the `Makefile` targets.

Clone and build:

```sh
git clone https://github.com/ferchd/gomta.git
cd gomta
go build -trimpath -o gomta ./cmd/gomta
```

Create a throwaway instance and run it:

```sh
./gomta init -domain example.com -hostname mail.example.com
./gomta check -config gomta.yaml
./gomta serve -config gomta.yaml
```

`init` writes generated configuration, keys, queue data, and mail into the
working directory. These paths are ignored by Git; see `.gitignore`.

## Checks before opening a pull request

Run the same checks as CI:

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
go build -trimpath ./cmd/gomta
```

If you use `make`:

```sh
make fmt
make vet
make test
```

Guidelines:

- Keep the code formatted with `gofmt`.
- Add or update tests for behavior changes. Bug fixes should include a
  regression test when practical.
- Do not introduce a dependency unless it is clearly justified. GoMTA aims to
  stay close to the standard library and a small set of well-maintained
  modules.
- Update the documentation when you change configuration fields, plugin
  behavior, CLI output, or deployment steps. Relevant files live in `docs/`,
  `README.md`, and `examples/`.
- Keep commits focused. A change that fixes one problem is easier to review
  than a mixed refactor.
- Write commit messages in the imperative mood, for example
  `queue: retry temporary LMTP failures`.

## Project layout

| Path | Purpose |
| --- | --- |
| `cmd/gomta/` | CLI entry point and command wiring |
| `config/` | YAML configuration, policy files, and plugin configuration |
| `plugin/` | Public plugin API, registry, and async hook runner |
| `delivery/` | Public delivery backend API and built-in backends |
| `queue/` | Persistent spool and retry engine |
| `internal/smtpserver/` | SMTP session handling |
| `internal/plugins/` | Built-in plugin implementations |
| `internal/app/` | Service wiring and status server |
| `internal/setup/` | `gomta init` generated files |
| `docs/` | Configuration, plugin, and deployment documentation |

Public packages (`config`, `delivery`, `plugin`, `queue`) are intended for
external use. Changes to their exported APIs need a clear migration path and
documentation updates.

## Adding a plugin or delivery backend

1. Implement the interfaces in `plugin` or `delivery`.
2. Register a constructor and metadata so the type is available to the
   configuration loader.
3. Register the package in `internal/plugins/all` (plugins) or the delivery
   registry (backends).
4. Document the configuration keys, hook, defaults, and action behavior in
   `docs/plugins.md`.
5. Add unit tests, including failure and timeout paths.

## Reporting bugs

Open a [bug report](https://github.com/ferchd/gomta/issues/new?template=bug_report.yml)
and include:

- GoMTA version (`gomta version`) and how it was built.
- Operating system and architecture.
- A minimal configuration or the relevant listener/plugin section, with
  secrets removed.
- The exact command, observed behavior, and expected behavior.
- Relevant logs with passwords, tokens, DKIM keys, and message contents
  redacted.

## Feature requests

Open a [feature request](https://github.com/ferchd/gomta/issues/new?template=feature_request.yml).
Describe the problem first, then the proposed solution and alternatives. Not
every feature fits the project's scope: GoMTA is a small MTA, not a full mail
suite, and features that belong in an external service are usually better
implemented as plugins.

## Pull requests

- Fill in the pull request template.
- Link the issue the change addresses.
- Describe behavior changes and any migration steps.
- Confirm that tests and documentation were updated.

Maintainers may ask for changes, close stale pull requests, or decline changes
that do not fit the project's scope.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
