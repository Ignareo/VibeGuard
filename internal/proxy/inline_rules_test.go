package proxy

import (
	"testing"

	"github.com/inkdust2021/vibeguard/internal/config"
)

func TestBuildInlineRuleRecognizers(t *testing.T) {
	t.Run("regex 规则生效", func(t *testing.T) {
		recs, errs := buildInlineRuleRecognizers(config.PatternsConfig{
			Regex: []config.RegexPattern{{Pattern: `(?:^|\D)(\d{6})(?:$|\D)`, Category: "PIN"}},
		})
		if len(errs) != 0 || len(recs) != 1 {
			t.Fatalf("recs=%d errs=%v", len(recs), errs)
		}
		matches := recs[0].Recognize([]byte("code 123456 ok"))
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if got := "code 123456 ok"[matches[0].Start:matches[0].End]; got != "123456" {
			t.Fatalf("unexpected match %q", got)
		}
		if matches[0].Category != "PIN" {
			t.Fatalf("unexpected category %q", matches[0].Category)
		}
	})

	t.Run("builtin 规则生效", func(t *testing.T) {
		recs, errs := buildInlineRuleRecognizers(config.PatternsConfig{
			Builtin: []string{"email"},
		})
		if len(errs) != 0 || len(recs) != 1 {
			t.Fatalf("recs=%d errs=%v", len(recs), errs)
		}
		matches := recs[0].Recognize([]byte("mail me at a@b.com please"))
		if len(matches) == 0 {
			t.Fatalf("builtin email rule did not match")
		}
		if matches[0].Category != "EMAIL" {
			t.Fatalf("unexpected category %q", matches[0].Category)
		}
	})

	t.Run("非法 regex 报错且不影响其他规则", func(t *testing.T) {
		recs, errs := buildInlineRuleRecognizers(config.PatternsConfig{
			Regex: []config.RegexPattern{
				{Pattern: `([a-z`, Category: "BAD"},
				{Pattern: `(ok)`, Category: "GOOD"},
			},
		})
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %v", errs)
		}
		if len(recs) != 1 {
			t.Fatalf("valid rule should survive, recs=%d", len(recs))
		}
	})

	t.Run("未知 builtin 报错", func(t *testing.T) {
		recs, errs := buildInlineRuleRecognizers(config.PatternsConfig{
			Builtin: []string{"nope"},
		})
		if len(errs) != 1 || len(recs) != 0 {
			t.Fatalf("recs=%d errs=%v", len(recs), errs)
		}
	})
}
