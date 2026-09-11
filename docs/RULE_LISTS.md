# Rule List Directory

Community-curated list of `.vgrules` subscription URLs for VibeGuard.

To add your rule list, submit a PR editing the table below. Please include a brief description of what your rules cover.

## Rule syntax

```
# Comments start with #, //, ;, or !
keyword <CATEGORY> <TEXT...>       # substring match on normalized text (case-insensitive, zero-width stripped, NFKC)
regex   <CATEGORY> <RE2_PATTERN> [:: <VALIDATOR>]
                                   # Go RE2 regex; first capture group is redacted
```

An optional `:: <VALIDATOR>` suffix on a regex rule verifies the captured text's
checksum and discards failed matches (cuts false positives on numeric IDs):

- `:: luhn` — bank/credit card numbers (non-digits are stripped before the Luhn check)
- `:: china_id` — China national ID (GB 11643 checksum)
- `:: uscc` — Unified Social Credit Code (checksum)

Unknown validator names fail parsing with an error.

See [`rule_lists.sample.vgrules`](rule_lists.sample.vgrules) for a complete example.

## Available Rule Lists

<!-- Add your rule list below this line. Keep the table sorted alphabetically by name. -->

| Name | URL | Description |
|------|-----|-------------|
| Default Rules | `https://raw.githubusercontent.com/Ignareo/VibeGuard/refs/heads/main/internal/defaultrules/default.vgrules` | Built-in rules: email, phone, IP, UUID, SSN, IBAN, credit card (Luhn), bank card (Luhn), MAC, crypto addresses, API keys, China national ID (checksum), China passport, USCC (checksum), and more. |

## Subscription integrity (sha256_pin)

Remote subscriptions are fetched over HTTPS and validated by parsing, but HTTPS alone does
not stop a compromised rule source from pushing malicious rules. Add `sha256_pin` to a
`rule_lists` entry to pin the content hash:

```yaml
patterns:
  rule_lists:
    - name: my-rules
      url: https://example.com/rules.vgrules
      sha256_pin: tofu        # or a 64-char hex sha256 of the expected content
      enabled: true
```

- `tofu` — trust on first use: the first accepted content hash is recorded (in the
  subscription meta as `pinned_sha256`) and later mismatches are rejected.
- 64-char hex — the content sha256 must match exactly.

Rejected updates keep the existing local cache, set `last_error` in the subscription meta
(shown in the admin UI), and log a warning. To accept a legitimate upstream change, update
the pin to the new hash or clear `pinned_sha256` in the subscription meta file.
