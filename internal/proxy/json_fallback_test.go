package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func newKeywordRedactor(t *testing.T, keywords map[string]string) *redact.Engine {
	t.Helper()
	eng := redact.NewEngine(session.NewManager(time.Hour, 1000), "__VG_")
	for kw, cat := range keywords {
		eng.AddKeyword(kw, cat)
	}
	return eng
}

func TestReapplyMatchesPreservingJSON(t *testing.T) {
	t.Run("仅丢弃破坏 JSON 的匹配项", func(t *testing.T) {
		// "SECRET\"}" spans the closing quote of the JSON string, so replacing it
		// corrupts the document; "hunter2" is a safe in-string match.
		body := []byte(`{"model":"hunter2-x","messages":[{"role":"user","content":"the password is SECRET"}]}`)
		eng := newKeywordRedactor(t, map[string]string{
			`SECRET"}`: "SECRET",
			"hunter2":  "PASSWORD",
		})

		redacted, matches := eng.RedactWithMatches(body)
		if len(matches) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(matches))
		}
		if json.Valid(redacted) {
			t.Fatal("expected whole-text redaction to corrupt the JSON body")
		}

		out, applied, dropped := reapplyMatchesPreservingJSON(body, matches)
		if !json.Valid(out) {
			t.Fatalf("expected valid JSON after match-granular retry, got %q", out)
		}
		if len(applied) != 1 || len(dropped) != 1 {
			t.Fatalf("expected 1 applied / 1 dropped, got %d / %d", len(applied), len(dropped))
		}
		// The safe match must still be redacted (no full-body revert).
		if bytes.Contains(out, []byte("hunter2")) {
			t.Fatalf("safe match was not redacted: %q", out)
		}
		if !bytes.Contains(out, []byte(applied[0].Placeholder)) {
			t.Fatalf("placeholder missing from output: %q", out)
		}
		// The JSON-breaking match is dropped and stays in clear (audited via invalid_json_partial).
		if !bytes.Contains(out, []byte("SECRET")) {
			t.Fatalf("dropped match should remain in output: %q", out)
		}
	})

	t.Run("全部匹配安全时全部保留", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":"key is hunter2"}]}`)
		eng := newKeywordRedactor(t, map[string]string{"hunter2": "PASSWORD"})

		redacted, matches := eng.RedactWithMatches(body)
		if !json.Valid(redacted) {
			t.Fatal("expected whole-text redaction to keep JSON valid")
		}

		out, applied, dropped := reapplyMatchesPreservingJSON(body, matches)
		if len(dropped) != 0 {
			t.Fatalf("expected no dropped matches, got %d", len(dropped))
		}
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied match, got %d", len(applied))
		}
		if !bytes.Equal(out, redacted) {
			t.Fatalf("expected output identical to whole-text redaction, got %q want %q", out, redacted)
		}
	})

	t.Run("无匹配时原样返回", func(t *testing.T) {
		body := []byte(`{"messages":[]}`)
		out, applied, dropped := reapplyMatchesPreservingJSON(body, nil)
		if !bytes.Equal(out, body) {
			t.Fatalf("expected original body, got %q", out)
		}
		if len(applied) != 0 || len(dropped) != 0 {
			t.Fatalf("expected no applied/dropped matches, got %d/%d", len(applied), len(dropped))
		}
	})
}

func TestMatchCategories(t *testing.T) {
	matches := []redact.Match{
		{Category: "SECRET"},
		{Category: "PASSWORD"},
		{Category: "SECRET"},
	}
	got := matchCategories(matches)
	if strings.Join(got, ",") != "PASSWORD,SECRET" {
		t.Fatalf("unexpected categories: %v", got)
	}
	if got := matchCategories(nil); len(got) != 0 {
		t.Fatalf("expected empty categories, got %v", got)
	}
}
