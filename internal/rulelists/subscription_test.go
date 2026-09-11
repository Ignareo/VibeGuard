package rulelists

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/config"
)

const testRulesV1 = "keyword TEST alpha-secret\n"
const testRulesV2 = "keyword TEST beta-secret\n"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newRuleServer(t *testing.T, body *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, *body)
	}))
}

func syncOnce(t *testing.T, rl config.RuleListConfig) (bool, SubscriptionMeta, error) {
	t.Helper()
	return SyncSubscriptionIfDue(nil, rl, SyncSubscriptionOptions{Force: true})
}

func TestSubscriptionSHA256Pin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	body := testRulesV1
	srv := newRuleServer(t, &body)
	defer srv.Close()

	base := config.RuleListConfig{
		ID:        "pin-test",
		URL:       srv.URL,
		AllowHTTP: true,
		Enabled:   true,
	}

	// Correct pin: accepted.
	rl := base
	rl.SHA256Pin = sha256Hex(testRulesV1)
	updated, meta, err := syncOnce(t, rl)
	if err != nil || !updated {
		t.Fatalf("correct pin should be accepted: updated=%v err=%v", updated, err)
	}
	if meta.ContentSHA256 != sha256Hex(testRulesV1) {
		t.Fatalf("unexpected content hash: %q", meta.ContentSHA256)
	}

	// Tampered content: rejected, cache keeps the old content.
	body = testRulesV2
	updated, meta, err = syncOnce(t, rl)
	if err == nil || updated {
		t.Fatalf("tampered content should be rejected: updated=%v err=%v", updated, err)
	}
	if !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("expected mismatch error, got: %v", err)
	}
	if !strings.Contains(meta.LastError, "不匹配") {
		t.Fatalf("meta.LastError should record the rejection, got: %q", meta.LastError)
	}
	rulesPath, _ := SubscriptionRulesPath(rl)
	cached, err := os.ReadFile(rulesPath)
	if err != nil || string(cached) != testRulesV1 {
		t.Fatalf("cache must keep the original content, got %q err=%v", cached, err)
	}

	// Invalid pin format: rejected.
	rl.SHA256Pin = "not-a-hash"
	if _, _, err := syncOnce(t, rl); err == nil || !strings.Contains(err.Error(), "格式非法") {
		t.Fatalf("invalid pin format should fail, got: %v", err)
	}
}

func TestSubscriptionTOFUPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	body := testRulesV1
	srv := newRuleServer(t, &body)
	defer srv.Close()

	rl := config.RuleListConfig{
		ID:        "tofu-test",
		URL:       srv.URL,
		AllowHTTP: true,
		Enabled:   true,
		SHA256Pin: "tofu",
	}

	// First fetch: accepted and pinned.
	updated, meta, err := syncOnce(t, rl)
	if err != nil || !updated {
		t.Fatalf("first TOFU fetch should be accepted: updated=%v err=%v", updated, err)
	}
	if meta.PinnedSHA256 != sha256Hex(testRulesV1) {
		t.Fatalf("TOFU should pin the first content hash, got %q", meta.PinnedSHA256)
	}

	// Legit-looking but different content: rejected.
	body = testRulesV2
	updated, meta, err = syncOnce(t, rl)
	if err == nil || updated {
		t.Fatalf("changed content under TOFU should be rejected: updated=%v err=%v", updated, err)
	}
	if !strings.Contains(err.Error(), "TOFU") {
		t.Fatalf("expected TOFU mismatch error, got: %v", err)
	}
	rulesPath, _ := SubscriptionRulesPath(rl)
	cached, err := os.ReadFile(rulesPath)
	if err != nil || string(cached) != testRulesV1 {
		t.Fatalf("cache must keep the pinned content, got %q err=%v", cached, err)
	}
}

func TestSubscriptionNoPinStillWorks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	body := testRulesV1
	srv := newRuleServer(t, &body)
	defer srv.Close()

	rl := config.RuleListConfig{
		ID:        "nopin-test",
		URL:       srv.URL,
		AllowHTTP: true,
		Enabled:   true,
	}
	if updated, _, err := syncOnce(t, rl); err != nil || !updated {
		t.Fatalf("unpinned subscription should update: updated=%v err=%v", updated, err)
	}
	body = testRulesV2
	if updated, _, err := syncOnce(t, rl); err != nil || !updated {
		t.Fatalf("unpinned subscription should follow content changes: updated=%v err=%v", updated, err)
	}
}
