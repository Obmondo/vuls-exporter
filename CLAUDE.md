# Vuls Exporter - Claude Code Context

## Project Overview
Sidecar service that reads Vuls scan results and pushes them to the Obmondo API with client certificate authentication. Runs alongside the Vuls server in Kubernetes. Uses Linux inotify (`IN_CLOSE_WRITE`) via `golang.org/x/sys/unix` to detect new result files immediately, with a periodic ticker as fallback.

## Build & Test
```sh
make build      # static linux/amd64 binary → dist/
make test       # go test ./...
make vet        # go vet ./...
make lint       # golangci-lint run ./...
```

## Conventions
- Go 1.24, module name `github.com/Obmondo/vuls-exporter`
- Structured logging via `log/slog` (JSON handler to stderr)
- golangci-lint config in `.golangci.yaml` (version 2 format)
- No `Co-Authored-By` lines in commits

## Git commit style

- **Mandatory User Approval**: NEVER commit changes unless the user explicitly asks you to.
- **Signed Commits**: Always sign commits when requested (ensure GPG signing is enabled or use `-S`).
- **Pre-commit checks**: Before every commit, run `gofmt -w .` and `golangci-lint run ./...`. Both must be clean — no formatting diffs, no lint issues.
- Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

[optional body]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New user-facing feature |
| `fix` | Bug fix |
| `docs` | Documentation only (README, configuration.md, code comments) |
| `chore` | Maintenance that is not a feature or fix (deps, config, rename, gitignore) |
| `ci` | CI/CD workflow changes (.github/workflows/) |
| `refactor` | Code restructuring with no behaviour change |
| `test` | Adding or fixing tests only |
| `perf` | Performance improvement |
| `build` | Build system changes (Makefile, Dockerfile, .goreleaser.yaml) |
| `style` | Formatting / whitespace only, no logic change |

### Breaking changes

Append `!` after the type/scope for breaking changes:

```
chore!: rename module path
feat(api)!: remove deprecated endpoint
```

### Scope

Use the package or subsystem name — keep it short:

```
fix(config): ...
feat(exporter): ...
docs(readme): ...
ci(docker): ...
```

Omit scope when the change is repo-wide.

### Subject line rules

- Imperative mood, lowercase, no trailing period
- ≤ 72 characters
- Say *what* changed and *why*, not *how*

### Commit grouping

Commits should be logically atomic — one concern per commit. When a session touches multiple concerns, stage and commit them separately:

1. Code/logic fixes first (`fix`, `feat`, `refactor`)
2. Documentation second (`docs`)
3. Housekeeping last (`chore`, `ci`, `build`)
