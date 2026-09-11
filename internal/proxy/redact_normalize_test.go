package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
	"github.com/inkdust2021/vibeguard/internal/pii_next/pipeline"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestRedactNormalizationEvasion(t *testing.T) {
	t.Run("零宽字符+大小写绕过-legacy引擎", func(t *testing.T) {
		eng := newKeywordRedactor(t, map[string]string{"password": "PASSWORD"})
		out, matches := eng.RedactWithMatches([]byte("my PaSs\u200bWoRd here"))
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if strings.Contains(string(out), "PaSs") {
			t.Fatalf("secret not redacted: %q", out)
		}
		if !strings.Contains(string(out), "__VG_PASSWORD_") {
			t.Fatalf("placeholder missing: %q", out)
		}
	})

	t.Run("全角数字手机号-regex", func(t *testing.T) {
		eng := newKeywordRedactor(t, nil)
		if err := eng.AddRegex(`(?:^|\D)(1[3-9]\d{9})(?:$|\D)`, "CHINA_PHONE"); err != nil {
			t.Fatal(err)
		}
		out, matches := eng.RedactWithMatches([]byte("电话：１３８００１３８０００ end"))
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d (%q)", len(matches), out)
		}
		if strings.Contains(string(out), "１３８") {
			t.Fatalf("full-width phone not redacted: %q", out)
		}
		if !strings.HasSuffix(string(out), " end") {
			t.Fatalf("surrounding text corrupted: %q", out)
		}
	})

	t.Run("pipeline关键词大小写+零宽", func(t *testing.T) {
		kw := keywords.New([]keywords.Keyword{{Text: "TopSecretToken", Category: "SECRET"}})
		p := pipeline.New(session.NewManager(time.Hour, 100), "__VG_", kw)
		out, matches := p.RedactWithMatches([]byte("leak top\u200csecrettoken ok"))
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if !strings.Contains(string(out), "__VG_SECRET_") || strings.Contains(string(out), "secrettoken") {
			t.Fatalf("pipeline did not redact evaded keyword: %q", out)
		}
	})

	t.Run("正常文本offsets不错位", func(t *testing.T) {
		eng := newKeywordRedactor(t, map[string]string{"secret": "SECRET"})
		out, matches := eng.RedactWithMatches([]byte("a secret b secret"))
		if len(matches) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(matches))
		}
		if strings.Contains(string(out), "secret") {
			t.Fatalf("not all occurrences redacted: %q", out)
		}
		// Placeholders must be registered for restore.
		for _, m := range matches {
			if m.Original != "secret" || m.Placeholder == "" {
				t.Fatalf("bad match: %+v", m)
			}
		}
	})
}
