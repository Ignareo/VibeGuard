package redact

import "fmt"

type builtinRule struct {
	pattern  string
	category string
}

var builtinRules = map[string]builtinRule{
	// Notes:
	// - Built-in rules improve out-of-the-box coverage so users don't need to write regexes to get started.
	// - When boundary characters must be preserved, use capture groups so the engine only replaces the first capture group (see engine.go).

	"email": {
		pattern:  `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
		category: "EMAIL",
	},
	"china_phone": {
		// Use a capture group to replace only the phone number, preserving non-digit boundary characters.
		pattern:  `(?:^|\D)(1[3-9]\d{9})(?:$|\D)`,
		category: "CHINA_PHONE",
	},
	"china_id": {
		// Use a capture group to replace only the ID number, preserving non-digit boundary characters.
		pattern:  `(?:^|\D)(\d{17}[\dXx])(?:$|\D)`,
		category: "CHINA_ID",
	},
	"uuid": {
		pattern:  `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`,
		category: "UUID",
	},
	"ipv4": {
		// Does not validate 0-255 ranges; the goal is "broad coverage with low configuration cost".
		pattern:  `(?:\d{1,3}\.){3}\d{1,3}`,
		category: "IPV4",
	},
	"mac": {
		pattern:  `(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}`,
		category: "MAC",
	},
}

// AddBuiltin adds a built-in rule to the engine (typically driven by config patterns.builtin).
func (e *Engine) AddBuiltin(name string) error {
	rule, ok := builtinRules[name]
	if !ok {
		return fmt.Errorf("unknown builtin rule: %s", name)
	}
	return e.AddRegex(rule.pattern, rule.category)
}

// BuiltinRule returns the pattern and category of a named built-in rule.
func BuiltinRule(name string) (pattern, category string, ok bool) {
	rule, ok := builtinRules[name]
	if !ok {
		return "", "", false
	}
	return rule.pattern, rule.category, true
}
