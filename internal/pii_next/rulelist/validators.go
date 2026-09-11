package rulelist

import (
	"fmt"
	"strings"
)

// Validator is a post-match check applied to the captured text of a regex rule.
// A match whose captured text fails the validator is discarded (treated as a
// false positive), which keeps rules like "18 digits" usable for IDs that
// carry a checksum digit.
type Validator func(text string) bool

// validators maps the `:: <name>` suffix of a regex rule to its check.
var validators = map[string]Validator{
	"luhn":     validateLuhn,
	"china_id": validateChinaID,
	"uscc":     validateUSCC,
}

func lookupValidator(name string) (Validator, error) {
	v, ok := validators[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, fmt.Errorf("未知校验器：%q（可用：luhn / china_id / uscc）", name)
	}
	return v, nil
}

// validateLuhn strips non-digits and applies the Luhn checksum (bank cards).
func validateLuhn(text string) bool {
	digits := make([]int, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// chinaIDWeights are the GB 11643-1999 weights for the first 17 digits.
var chinaIDWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// chinaIDCheckCodes maps sum%11 to the expected 18th character.
const chinaIDCheckCodes = "10X98765432"

// validateChinaID verifies the checksum of an 18-digit China national ID.
func validateChinaID(text string) bool {
	if len(text) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		c := text[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * chinaIDWeights[i]
	}
	last := text[17]
	if last == 'x' {
		last = 'X'
	}
	return last == chinaIDCheckCodes[sum%11]
}

// usccCharset is the 31-character alphabet of the Unified Social Credit Code
// (digits plus uppercase letters without I, O, S, Z, V).
const usccCharset = "0123456789ABCDEFGHJKLMNPQRTUWXY"

var usccWeights = [17]int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}

// validateUSCC verifies the checksum of an 18-character Unified Social Credit Code.
func validateUSCC(text string) bool {
	if len(text) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		v := strings.IndexByte(usccCharset, text[i])
		if v < 0 {
			return false
		}
		sum += v * usccWeights[i]
	}
	check := (31 - sum%31) % 31
	return text[17] == usccCharset[check]
}
