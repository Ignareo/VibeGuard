package proxy

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/inkdust2021/vibeguard/internal/redact"
)

// reapplyMatchesPreservingJSON rebuilds a redacted body from the original body and the
// given matches, keeping only the replacements that preserve JSON validity.
//
// Whole-text redaction can corrupt JSON when a match spans structural characters (e.g. a
// keyword containing '"'). Reverting to the original body in that case would forward every
// detected secret in clear, so instead we retry at match granularity and drop only the
// offending matches.
//
// body must be valid JSON and matches must be non-overlapping (guaranteed by
// redact.Engine.RedactWithMatches). The greedy pass keeps the running output valid at
// every step, so the returned body is always valid JSON.
func reapplyMatchesPreservingJSON(body []byte, matches []redact.Match) (out []byte, applied, dropped []redact.Match) {
	sorted := make([]redact.Match, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End < sorted[j].End
	})

	out = body
	for _, m := range sorted {
		candidate := applyMatchesToBody(body, append(append([]redact.Match{}, applied...), m))
		if json.Valid(candidate) {
			applied = append(applied, m)
			out = candidate
		} else {
			dropped = append(dropped, m)
		}
	}
	return out, applied, dropped
}

// applyMatchesToBody replaces match ranges in body with their placeholders.
// matches must be sorted by Start ascending and non-overlapping.
func applyMatchesToBody(body []byte, matches []redact.Match) []byte {
	var buf bytes.Buffer
	buf.Grow(len(body))
	pos := 0
	for _, m := range matches {
		if m.Start < pos || m.End > len(body) || m.Start >= m.End {
			continue
		}
		buf.Write(body[pos:m.Start])
		buf.WriteString(m.Placeholder)
		pos = m.End
	}
	buf.Write(body[pos:])
	return buf.Bytes()
}

// matchCategories returns the sorted unique categories of the given matches (for logging/audit).
func matchCategories(matches []redact.Match) []string {
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m.Category]; ok {
			continue
		}
		seen[m.Category] = struct{}{}
		out = append(out, m.Category)
	}
	sort.Strings(out)
	return out
}
