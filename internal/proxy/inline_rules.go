package proxy

import (
	"fmt"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
	piirec "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
	"github.com/inkdust2021/vibeguard/internal/redact"
)

// inlineRulePriority ranks config patterns.regex/builtin above the default rule list (50)
// so explicit config wins on overlaps.
const inlineRulePriority = 60

// buildInlineRuleRecognizers wires the legacy config fields patterns.regex and
// patterns.builtin into the pipeline as inline rule lists, so configured rules actually
// take effect. Each rule is parsed independently: an invalid entry produces an error in
// the returned slice (logged by the caller) without discarding the valid rules.
func buildInlineRuleRecognizers(p config.PatternsConfig) (recs []piirec.Recognizer, errs []error) {
	add := func(cat, pattern, origin string) {
		rec, err := rulelist.Parse(strings.NewReader("regex "+cat+" "+pattern), rulelist.ParseOptions{
			Name:     origin,
			Priority: inlineRulePriority,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", origin, err))
			return
		}
		recs = append(recs, rec)
	}

	for _, rp := range p.Regex {
		pat := strings.TrimSpace(rp.Pattern)
		if pat == "" {
			continue
		}
		cat := config.SanitizeCategory(rp.Category)
		if cat == "" {
			cat = "REGEX"
		}
		add(cat, pat, "patterns.regex")
	}

	for _, name := range p.Builtin {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" {
			continue
		}
		pat, cat, ok := redact.BuiltinRule(n)
		if !ok {
			errs = append(errs, fmt.Errorf("patterns.builtin: unknown builtin rule %q", name))
			continue
		}
		add(cat, pat, "patterns.builtin:"+n)
	}

	return recs, errs
}
