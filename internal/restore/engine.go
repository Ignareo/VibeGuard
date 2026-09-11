package restore

import (
	"regexp"
	"sort"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/session"
)

// Engine handles placeholder restoration
type Engine struct {
	session *session.Manager
	prefix  string
	// regexFull matches placeholders that start with the full prefix (e.g. "__VG_"),
	// with an optional trailing "__" (some models/clients may drop it).
	regexFull *regexp.Regexp
	// regexBare matches placeholders that start with the prefix without leading underscores (e.g. "VG_"),
	// with an optional trailing "__". It uses a boundary to avoid matching inside full placeholders.
	regexBare *regexp.Regexp
	// regexBareAtStart is like regexBare but anchored at start, for streaming boundary detection.
	regexBareAtStart *regexp.Regexp
	barePrefix       string
	leading          string
}

// NewEngine creates a new restoration engine
func NewEngine(s *session.Manager, prefix string) *Engine {
	// Pattern: __VG_CATEGORY_HASH14__ or __VG_CATEGORY_HASH14_N__
	// The hash part is 12 hex chars (legacy, pre-checksum) or 14 (hash12 + 2-char checksum).
	//
	// Note: the "__" around placeholders may be treated as Markdown emphasis and dropped by some models/renderers.
	// Therefore we allow an optional trailing "__", and also support a "no leading underscores" variant (e.g. VG_TEXT_xxx).
	// Because RE2 has no lookahead, the trailing boundary (no word char after a "__"-less token)
	// is enforced in code — see placeholderTailOK.
	escapedPrefix := regexp.QuoteMeta(prefix)
	patternFull := escapedPrefix + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:[a-f0-9]{2})?(?:_\d+)?(?:__)?`

	leadingUnderscores := countLeadingUnderscores(prefix)
	leading := ""
	barePrefix := prefix
	if leadingUnderscores > 0 && leadingUnderscores <= len(prefix) {
		leading = prefix[:leadingUnderscores]
		barePrefix = prefix[leadingUnderscores:]
	}

	var reBare, reBareAtStart *regexp.Regexp
	if barePrefix != "" && barePrefix != prefix {
		escapedBare := regexp.QuoteMeta(barePrefix)
		// boundary: start or a non-underscore char, to avoid matching the "VG_" inside "__VG_".
		patternBare := `(?:^|[^_])(` + escapedBare + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:[a-f0-9]{2})?(?:_\d+)?(?:__)?` + `)`
		reBare = regexp.MustCompile(patternBare)
		reBareAtStart = regexp.MustCompile(`^` + escapedBare + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:[a-f0-9]{2})?(?:_\d+)?(?:__)?`)
	}

	return &Engine{
		session:          s,
		prefix:           prefix,
		regexFull:        regexp.MustCompile(patternFull),
		regexBare:        reBare,
		regexBareAtStart: reBareAtStart,
		barePrefix:       barePrefix,
		leading:          leading,
	}
}

// Restore replaces placeholders with original values
func (e *Engine) Restore(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	type repl struct {
		start int
		end   int
		orig  string
	}
	var repls []repl

	// 1) Full prefix placeholders (e.g. "__VG_...__" or "__VG_..." without trailing "__")
	full := e.regexFull.FindAllIndex(input, -1)
	for _, m := range full {
		start, end := m[0], m[1]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}
		if !placeholderTailOK(input, start, end) {
			continue
		}
		token := string(input[start:end])
		normalized := e.normalizeToken(token)
		original, ok := e.session.Lookup(normalized)
		if ok {
			repls = append(repls, repl{start: start, end: end, orig: original})
		}
	}

	// 2) Bare prefix placeholders (e.g. "VG_...__" or "VG_..." without leading/trailing "__")
	if e.regexBare != nil {
		locs := e.regexBare.FindAllSubmatchIndex(input, -1)
		for _, loc := range locs {
			// loc[0:2] is the whole match; loc[2:4] is the capturing group
			if len(loc) < 4 {
				continue
			}
			start, end := loc[2], loc[3]
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			if !placeholderTailOK(input, start, end) {
				continue
			}
			token := string(input[start:end])
			normalized := e.normalizeToken(token)
			original, ok := e.session.Lookup(normalized)
			if ok {
				repls = append(repls, repl{start: start, end: end, orig: original})
			}
		}
	}

	if len(repls) == 0 {
		return input
	}

	// Order by start asc; drop overlaps defensively.
	sort.Slice(repls, func(i, j int) bool {
		if repls[i].start != repls[j].start {
			return repls[i].start < repls[j].start
		}
		return repls[i].end < repls[j].end
	})

	out := make([]byte, 0, len(input))
	last := 0
	for _, r := range repls {
		if r.start < last {
			continue
		}
		out = append(out, input[last:r.start]...)
		out = append(out, []byte(r.orig)...)
		last = r.end
	}
	out = append(out, input[last:]...)
	return out
}

// RestoreString is a convenience method for string input
func (e *Engine) RestoreString(input string) string {
	return string(e.Restore([]byte(input)))
}

// Prefix returns the placeholder prefix (e.g. "__VG_").
func (e *Engine) Prefix() string {
	return e.prefix
}

// MatchAt checks whether input[start:] begins with a "complete placeholder"; if so, it returns the end position.
// This is used for streaming boundary detection to avoid emitting an incomplete prefix fragment that can no longer be restored.
func (e *Engine) MatchAt(input []byte, start int) (end int, ok bool) {
	if start < 0 || start >= len(input) {
		return 0, false
	}
	if loc := e.regexFull.FindIndex(input[start:]); loc != nil && loc[0] == 0 && loc[1] > 0 && start+loc[1] <= len(input) {
		if end := start + loc[1]; placeholderTailOK(input, start, end) {
			return end, true
		}
	}
	if e.regexBareAtStart != nil {
		if loc := e.regexBareAtStart.FindIndex(input[start:]); loc != nil && loc[0] == 0 && loc[1] > 0 && start+loc[1] <= len(input) {
			if end := start + loc[1]; placeholderTailOK(input, start, end) {
				return end, true
			}
		}
	}
	return 0, false
}

// FindLeftovers returns normalized, checksum-verified placeholder tokens that are still
// present after a Restore pass because their mapping was lost (TTL expiry / eviction /
// session clear). Lookalike text that merely matches the placeholder shape is ignored
// (the 2-hex checksum fails), so the result is suitable for audit flagging.
func (e *Engine) FindLeftovers(input []byte) []string {
	if len(input) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	collect := func(start, end int) {
		if start < 0 || end < 0 || start >= end || end > len(input) {
			return
		}
		if !placeholderTailOK(input, start, end) {
			return
		}
		normalized := e.normalizeToken(string(input[start:end]))
		if normalized == "" {
			return
		}
		if _, ok := e.session.Lookup(normalized); ok {
			return // restorable, not a leftover
		}
		if !e.session.VerifyPlaceholderChecksum(normalized) {
			return // lookalike text, not ours
		}
		if _, dup := seen[normalized]; !dup {
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
	}
	for _, m := range e.regexFull.FindAllIndex(input, -1) {
		collect(m[0], m[1])
	}
	if e.regexBare != nil {
		for _, loc := range e.regexBare.FindAllSubmatchIndex(input, -1) {
			if len(loc) >= 4 {
				collect(loc[2], loc[3])
			}
		}
	}
	return out
}

// placeholderTailOK enforces the trailing boundary that the RE2 pattern cannot express:
// a token without the closing "__" must not be followed by another word character
// (otherwise it is the prefix of a longer lookalike token, not one of our placeholders).
func placeholderTailOK(input []byte, start, end int) bool {
	if end >= len(input) {
		return true
	}
	if end-start >= 2 && input[end-1] == '_' && input[end-2] == '_' {
		return true // closed with "__"
	}
	return !isPlaceholderWordByte(input[end])
}

func isPlaceholderWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (e *Engine) normalizeToken(token string) string {
	p := strings.TrimSpace(token)
	if p == "" {
		return ""
	}
	// Ensure leading underscores (if the token starts from barePrefix).
	if !strings.HasPrefix(p, e.prefix) && e.barePrefix != "" && strings.HasPrefix(p, e.barePrefix) {
		p = e.leading + p
	}
	// Ensure trailing "__" (GeneratePlaceholder always appends it).
	if !strings.HasSuffix(p, "__") {
		p += "__"
	}
	return p
}

func countLeadingUnderscores(s string) int {
	n := 0
	for n < len(s) && s[n] == '_' {
		n++
	}
	return n
}
