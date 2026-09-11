package rulelist

import (
	"bytes"
	"strings"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/defaultrules"
)

func TestDefaultRulesParse(t *testing.T) {
	rec, err := Parse(bytes.NewReader(defaultrules.DefaultRules), ParseOptions{Name: "default"})
	if err != nil {
		t.Fatalf("embedded default.vgrules must parse: %v", err)
	}
	if rec.RegexCount() == 0 {
		t.Fatalf("embedded default.vgrules has no regex rules")
	}
	// Checksum-verified rules must reject bad check digits.
	if hasMatchAt(rec, "id 110101199003077759 end", "110101199003077759") {
		t.Errorf("default rules: invalid China ID should be discarded")
	}
	if !hasMatchAt(rec, "id 110101199003077758 end", "110101199003077758") {
		t.Errorf("default rules: valid China ID not matched")
	}
}

func parseRules(t *testing.T, text string) *Recognizer {
	t.Helper()
	r, err := Parse(strings.NewReader(text), ParseOptions{Name: "test"})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return r
}

func hasMatchAt(rec *Recognizer, input, want string) bool {
	for _, m := range rec.Recognize([]byte(input)) {
		if input[m.Start:m.End] == want {
			return true
		}
	}
	return false
}

func TestRegexValidatorChinaID(t *testing.T) {
	rec := parseRules(t, "regex CHINA_ID (?:^|\\D)(\\d{17}[\\dXx])(?:$|\\D) :: china_id")

	if !hasMatchAt(rec, "身份证号 110101199003077758 谢谢", "110101199003077758") {
		t.Errorf("valid China ID not matched")
	}
	if hasMatchAt(rec, "身份证号 110101199003077759 谢谢", "110101199003077759") {
		t.Errorf("invalid China ID (bad checksum) should be discarded")
	}
	// 11010519491231002X is the classic valid example ending in X.
	if !hasMatchAt(rec, "尾号X 11010519491231002X 结束", "11010519491231002X") {
		t.Errorf("valid China ID ending in X not matched")
	}
}

func TestRegexValidatorLuhn(t *testing.T) {
	rec := parseRules(t, "regex BANK_CARD (?:^|\\D)(\\d{16,19})(?:$|\\D) :: luhn")

	if !hasMatchAt(rec, "卡号 4111111111111111 已绑定", "4111111111111111") {
		t.Errorf("Luhn-valid card not matched")
	}
	if hasMatchAt(rec, "卡号 4111111111111112 已绑定", "4111111111111112") {
		t.Errorf("Luhn-invalid card should be discarded")
	}
	// Grouped format: validator strips separators.
	rec2 := parseRules(t, "regex CREDIT_CARD (?:^|[^0-9])(\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4})(?:$|[^0-9]) :: luhn")
	if !hasMatchAt(rec2, "card 4111-1111-1111-1111 ok", "4111-1111-1111-1111") {
		t.Errorf("Luhn-valid grouped card not matched")
	}
	if hasMatchAt(rec2, "card 4111-1111-1111-1112 ok", "4111-1111-1111-1112") {
		t.Errorf("Luhn-invalid grouped card should be discarded")
	}
}

func TestRegexValidatorUSCC(t *testing.T) {
	rec := parseRules(t, "regex USCC (?:^|[^0-9A-Za-z])([0-9A-HJ-NPQRTUWXY]{18})(?:$|[^0-9A-Za-z]) :: uscc")

	if !hasMatchAt(rec, "统一社会信用代码 91110108MA01C8D52Q 备案", "91110108MA01C8D52Q") {
		t.Errorf("valid USCC not matched")
	}
	if hasMatchAt(rec, "统一社会信用代码 91110108MA01C8D52W 备案", "91110108MA01C8D52W") {
		t.Errorf("USCC with bad checksum should be discarded")
	}
}

func TestRegexUnknownValidatorFailsParse(t *testing.T) {
	_, err := Parse(strings.NewReader("regex FOO (\\d+) :: nope"), ParseOptions{Name: "test"})
	if err == nil {
		t.Fatalf("expected parse error for unknown validator")
	}
	if !strings.Contains(err.Error(), "未知校验器") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegexWithoutValidatorUnchanged(t *testing.T) {
	rec := parseRules(t, "regex NUM (?:^|\\D)(\\d{4})(?:$|\\D)")
	if !hasMatchAt(rec, "pin 1234 end", "1234") {
		t.Errorf("plain regex rule should still match")
	}
}
