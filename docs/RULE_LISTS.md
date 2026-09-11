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
| Default Rules | `https://raw.githubusercontent.com/inkdust2021/vgrules/refs/heads/main/default.vgrules` | Built-in rules: email, phone, IP, UUID, SSN, IBAN, credit card, MAC, crypto addresses, API keys, China national ID, and more. |
