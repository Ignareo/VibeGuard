# AGENTS.md — Guidance for LLM Coding Agents

This file tells AI coding agents how to work effectively in this repository.

## What this project is

VibeGuard is a local **MITM HTTPS proxy** (Go) that protects sensitive data when vibecoding: it redacts secrets/PII in requests to LLM APIs (replacing them with `__VG_<CATEGORY>_<hash12><checksum2>__` placeholders), restores originals in responses, and provides an Admin UI (`/manager/`) with per-request audit.

**This repo is a personal fork** of [inkdust2021/VibeGuard](https://github.com/inkdust2021/VibeGuard) (Apache-2.0). Fork additions: Kimi Code support (`vibeguard kimi`, targets for `api.kimi.com`/`api.moonshot.*`), the `integrations/kimi-code-vibeguard` precheck plugin, and the P1–P3 hardening/performance batch from [PLAN.md](PLAN.md) (all items done). Keep fork-specific changes off upstream PRs; generic fixes may be cherry-picked upstream.

## Build, test, verify

```bash
go build ./... && go build -tags vibeguard_full ./... && go vet ./... && go test ./...
gofmt -l cmd internal   # files you touched must NOT appear
```

- Module deps may need a mirror in China: `GOPROXY=https://goproxy.cn,direct`.
- **Known pre-existing upstream issues** (do not "fix" unless asked, do not attribute to your change):
  - `go vet` fails on `internal/wsproxy/transform_conn.go` (`ReadFrom` signature).
  - `gofmt -l` lists `internal/admin/admin.go` and `internal/auditdb/*.go`.
- Most packages have no tests; only add tests to packages that already have them (e.g. `internal/proxy`, `internal/secretsources`, `internal/textsafe`, `internal/wsproxy`, `internal/ahocorasick`, `internal/stream`).
- Smoke test: `go build -o /tmp/vibeguard-dev ./cmd/vibeguard && /tmp/vibeguard-dev run env | grep -i proxy`, then `vibeguard-dev stop` to clean up the auto-started daemon.
- Docs are Chinese-only: user docs in `README.md`, developer docs in `docs/TECHNICAL.md`, rule syntax in `docs/RULE_LISTS.md`. Update them when behavior changes.

## Architecture map

Request path (redact): `internal/proxy/proxy.go` (`OnRequest` handler) → content-type/encoding gates (`isTextContent` via mime parse; JSON sniffing when content-type missing, note `content_type_sniffed`; multipart per-part via `multipart.go`) → `internal/promptredact` (structured JSON fields, `invalid_json_policy` per-match fallback) or `internal/pii_next/pipeline` (rulelists + NER + keywords; legacy `internal/redact` for plain keyword flows) → `internal/session` (placeholder↔original mapping, encrypted WAL) → upstream.

Response path (restore): `proxy.go` `OnResponse` → `internal/stream` (SSE, per-event, cross-chunk restorer, delta streams isolated by key) or `internal/restore` (whole-body + `FindLeftovers` audit note) or `internal/wsproxy` (WebSocket frames).

| Package | Role |
|---|---|
| `cmd/vibeguard` | CLI (cobra): start/stop/run/`<assistant>`/init/trust/test/version; zh + en init templates |
| `internal/proxy` | MITM core, CONNECT, intercept modes, audit emission, config hot reload |
| `internal/promptredact` | Structured redaction of chat-API JSON bodies (no system-reminder exemption) |
| `internal/pii_next` / `internal/redact` | Newer pipeline / legacy keyword engine; both normalize via textsafe and rebuild in a single pass |
| `internal/textsafe` | Normalization folding (zero-width strip, NFKC, case fold) with folded→original span mapping |
| `internal/ahocorasick` | Keyword matcher: pure substring on caller-normalized text; sorted-array transitions + root lookup table |
| `internal/restore` / `internal/stream` | Placeholder restore: checksum-verified (`VerifyPlaceholderChecksum`), tail boundary in code (RE2 has no lookahead); `stream.MessageRestorer` for cross-message (WebSocket) restore |
| `internal/session` | Mapping store, TTL+LRU, AES-GCM WAL with batched fsync (`wal_sync_interval`) and compaction (`wal_compact_bytes`); `GetOrCreatePlaceholder` is atomic under one lock |
| `internal/rulelists` | `.vgrules` parsing (keyword/regex/`:: luhn\|china_id\|uscc` validators) + HTTPS subscriptions with `sha256_pin` (TOFU/fixed) |
| `internal/defaultrules` | Built-in `default.vgrules`; default subscription URL points at this fork (`Ignareo/VibeGuard`) |
| `internal/secretsources` | Import secrets from dotenv/lines files as keywords |
| `internal/admin` + `internal/auditdb` | Admin UI/API (bcrypt auth, login brute-force backoff, meta-audit of admin ops); in-memory + optional SQLite audit (build tag `vibeguard_full`); audit stores previews only unless `audit_db.persist_raw_values` |
| `internal/cert` | CA generation/trust; keyword at-rest encryption key derives from CA key |
| `internal/wsproxy` | WebSocket redaction (beta): inflates permessage-deflate (RSV1) text frames and forwards uncompressed, frame protocol validation, `SetOnError` hook → audit note `ws_frame_parse_error` |
| `integrations/kimi-code-vibeguard` | Kimi Code precheck plugin (Node hook script, no Go) |

## Conventions

- Commits: Conventional Commits (`feat:`/`fix:`/`docs:`...), English, matching upstream history.
- Comments/docstrings in English in Go code; UI strings are bilingual via `uiText(lang, zh, en)` — update both languages.
- Config: global `~/.vibeguard/config.yaml`, project override `.vibeguard.yaml`, hot-reloaded via fsnotify; new config fields need defaults in `internal/config/config.go` **and** both init templates in `cmd/vibeguard/main.go` (zh + en; the proxy/targets section uses literal tab indentation).
- Never log or audit raw sensitive values on purpose; match previews use `previewValue` (first2…last2).
- Placeholder format: `__VG_<CAT>_<hash14>__` where the last 2 hex chars are a checksum; legacy 12-hex placeholders must keep restoring (old WAL mappings).
- `textStreamRestorer.Feed` aliasing gotcha: `Restore` may return an alias of its input — copy before shifting the buffer tail.

## How to add support for another coding CLI (assistant adapter)

1. `cmd/vibeguard/main.go`: `var fooCmd = newAssistantProxyCmd("foo", "Foo")` + `rootCmd.AddCommand(fooCmd)`.
2. If the CLI is Node/Bun-based it works out of the box (`HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` are injected); other runtimes need the CA in the system trust store (`vibeguard trust`) or extra env vars in `withExtraCAEnv`.
3. Add the provider's API host to default targets in `internal/config/config.go` **and** both init templates in `main.go` (relevant for `intercept_mode: targets`; the CLI's actual API host may differ from its brand domain — check its config).
4. Update the shell helper whitelist + hints in `install.sh`, hints in `install.ps1`, and `README.md`.

## Fork-specific notes

- Kimi Code CLI (`kimi`) is a bundled-Node single binary; it honors `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS`. Its API is `https://api.kimi.com/coding/v1`.
- Kimi Code hooks (`[[hooks]]` in `~/.kimi-code/config.toml` or plugin manifests) **cannot rewrite outbound messages** — only block (exit 2) or append context. `UserPromptSubmit` payload's `prompt` is a content-parts array (`[{type:"text",text:"..."}]`), not a string; `integrations/kimi-code-vibeguard/hooks/precheck.mjs` handles both shapes.
- PLAN.md's P1–P3 items are all implemented; the "audit compliance" batch there is explicitly optional (on-demand only).
