# AGENTS.md — Guidance for LLM Coding Agents

This file tells AI coding agents how to work effectively in this repository.

## What this project is

VibeGuard is a local **MITM HTTPS proxy** (Go) that protects sensitive data when vibecoding: it redacts secrets/PII in requests to LLM APIs (replacing them with `__VG_<CATEGORY>_<hash12>__` placeholders), restores originals in responses, and provides an Admin UI (`/manager/`) with per-request audit.

**This repo is a personal fork** of [inkdust2021/VibeGuard](https://github.com/inkdust2021/VibeGuard) (Apache-2.0). Fork additions: Kimi Code support (`vibeguard kimi`, targets for `api.kimi.com`/`api.moonshot.*`) and the `integrations/kimi-code-vibeguard` precheck plugin. Keep fork-specific changes off upstream PRs; generic fixes may be cherry-picked upstream.

## Build, test, verify

```bash
go build ./... && go vet ./... && go test ./...
gofmt -l cmd internal   # files you touched must NOT appear
```

- Module deps may need a mirror in China: `GOPROXY=https://goproxy.cn,direct`.
- **Known pre-existing upstream issues** (do not "fix" unless asked, do not attribute to your change):
  - `go vet` fails on `internal/wsproxy/transform_conn.go:117` (`ReadFrom` signature).
  - `gofmt -l` lists `internal/admin/admin.go` and `internal/auditdb/*.go`.
- Most packages have no tests; only add tests to packages that already have them (e.g. `internal/proxy`, `internal/secretsources`, `internal/textsafe`, `internal/wsproxy`).
- Smoke test: `go build -o /tmp/vibeguard-dev ./cmd/vibeguard && /tmp/vibeguard-dev run env | grep -i proxy`, then `vibeguard-dev stop` to clean up the auto-started daemon.

## Architecture map

Request path (redact): `internal/proxy/proxy.go` (`handleHTTP` ~L426) → content-type/encoding gates → `internal/promptredact` (structured JSON fields) or `internal/redact` / `internal/pii_next/pipeline` (full-text fallback) → `internal/session` (placeholder↔original mapping, WAL) → upstream.

Response path (restore): `proxy.go` ~L693 → `internal/stream` (SSE, per-event, cross-chunk restorer) or `internal/restore` (whole-body/streamed) → client.

| Package | Role |
|---|---|
| `cmd/vibeguard` | CLI (cobra): start/stop/run/`<assistant>`/init/trust/test/version |
| `internal/proxy` | MITM core, CONNECT, intercept modes, audit emission, config hot reload |
| `internal/redact` / `internal/pii_next` | Legacy keyword engine / newer pipeline (rulelists with `:: luhn/china_id/uscc` checksum validators + NER + keywords) |
| `internal/promptredact` | Structured redaction of chat-API JSON bodies |
| `internal/ahocorasick` | Keyword matcher (byte-oriented AC automaton, sorted-array transitions + root direct table; callers match on `textsafe.FoldSegments` views, so keyword matching is case-insensitive and resistant to zero-width/NFKC evasion) |
| `internal/restore` / `internal/stream` | Placeholder restore (whole body / SSE streaming) |
| `internal/session` | Placeholder mapping store, TTL, AES-GCM-encrypted WAL |
| `internal/rulelists` | HTTPS subscription manager (optional `sha256_pin` / TOFU content pinning) |
| `internal/defaultrules` | Built-in `default.vgrules` |
| `internal/secretsources` | Import secrets from dotenv/lines files as keywords |
| `internal/admin` + `internal/auditdb` | Admin UI/API (bcrypt auth), in-memory + optional SQLite audit (build tag `vibeguard_full`) |
| `internal/cert` | CA generation/trust; keyword at-rest encryption key derives from CA key |
| `internal/wsproxy` | WebSocket redaction (beta, Codex) |
| `integrations/kimi-code-vibeguard` | Kimi Code precheck plugin (Node hook script, no Go) |

## Conventions

- Commits: Conventional Commits (`feat:`/`fix:`/`docs:`...), English, matching upstream history.
- Comments/docstrings in English in Go code; UI strings are bilingual via `uiText(lang, zh, en)` — update both languages.
- Config: global `~/.vibeguard/config.yaml`, project override `.vibeguard.yaml`, hot-reloaded via fsnotify; new config fields need defaults in `internal/config/config.go` **and** both init templates in `cmd/vibeguard/main.go` (zh + en).
- Never log or audit raw sensitive values on purpose; match previews use `previewValue` (first2…last2).

## How to add support for another coding CLI (assistant adapter)

1. `cmd/vibeguard/main.go`: `var fooCmd = newAssistantProxyCmd("foo", "Foo")` + `rootCmd.AddCommand(fooCmd)`.
2. If the CLI is Node/Bun-based it works out of the box (`HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` are injected); other runtimes need the CA in the system trust store (`vibeguard trust`) or extra env vars in `withExtraCAEnv`.
3. Add the provider's API host to default targets in `internal/config/config.go` **and** both init templates in `main.go` (relevant for `intercept_mode: targets`; the CLI's actual API host may differ from its brand domain — check its config).
4. Update the shell helper whitelist + hints in `install.sh`, hints in `install.ps1`, and both READMEs.

## Fork-specific notes

- Kimi Code CLI (`kimi`) is a bundled-Node single binary; it honors `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS`. Its API is `https://api.kimi.com/coding/v1`.
- Kimi Code hooks (`[[hooks]]` in `~/.kimi-code/config.toml` or plugin manifests) **cannot rewrite outbound messages** — only block (exit 2) or append context. `UserPromptSubmit` payload's `prompt` is a content-parts array (`[{type:"text",text:"..."}]`), not a string; `integrations/kimi-code-vibeguard/hooks/precheck.mjs` handles both shapes.
