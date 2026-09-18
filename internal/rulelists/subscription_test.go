package rulelists

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestSubscriptionEmptyPinDefaultsToTOFU(t *testing.T) {
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

	// First fetch: accepted, and the content hash is recorded as a TOFU pin
	// (an empty sha256_pin defaults to trust-on-first-use).
	updated, meta, err := syncOnce(t, rl)
	if err != nil || !updated {
		t.Fatalf("first fetch should be accepted: updated=%v err=%v", updated, err)
	}
	if meta.PinnedSHA256 != sha256Hex(testRulesV1) {
		t.Fatalf("empty pin should record a TOFU pin, got %q", meta.PinnedSHA256)
	}
	if meta.ConsecutiveFailures != 0 {
		t.Fatalf("failures should be 0 after success, got %d", meta.ConsecutiveFailures)
	}

	// Content change: rejected like a pin mismatch; cache keeps the pinned content.
	body = testRulesV2
	updated, meta, err = syncOnce(t, rl)
	if err == nil || updated {
		t.Fatalf("changed content under default TOFU should be rejected: updated=%v err=%v", updated, err)
	}
	if !strings.Contains(err.Error(), "TOFU") {
		t.Fatalf("expected TOFU mismatch error, got: %v", err)
	}
	if meta.ConsecutiveFailures != 1 {
		t.Fatalf("failures should be 1 after a rejected update, got %d", meta.ConsecutiveFailures)
	}
	rulesPath, _ := SubscriptionRulesPath(rl)
	cached, err := os.ReadFile(rulesPath)
	if err != nil || string(cached) != testRulesV1 {
		t.Fatalf("cache must keep the pinned content, got %q err=%v", cached, err)
	}

	// The failure counter is persisted in the meta file (consumed by the admin UI).
	metaPath, _ := SubscriptionMetaPath(rl)
	persisted, ok, err := LoadSubscriptionMeta(metaPath)
	if err != nil || !ok {
		t.Fatalf("meta should be persisted: ok=%v err=%v", ok, err)
	}
	if persisted.ConsecutiveFailures != 1 {
		t.Fatalf("persisted failures should be 1, got %d", persisted.ConsecutiveFailures)
	}

	// Restoring the pinned content succeeds (no rewrite) and resets the counter.
	body = testRulesV1
	updated, meta, err = syncOnce(t, rl)
	if err != nil || updated {
		t.Fatalf("restored content should be accepted without rewrite: updated=%v err=%v", updated, err)
	}
	if meta.ConsecutiveFailures != 0 {
		t.Fatalf("failures should be reset on success, got %d", meta.ConsecutiveFailures)
	}
}

func TestSubscriptionOldMetaWithoutPinAdoptsTOFU(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, testRulesV1)
	}))
	defer srv.Close()

	rl := config.RuleListConfig{
		ID:        "oldmeta-test",
		URL:       srv.URL,
		AllowHTTP: true,
		Enabled:   true,
	}

	// Simulate a meta file written by an older version: fingerprint and ETag exist,
	// but no TOFU pin and no failure counter. The cache holds the accepted content.
	rulesPath, _ := SubscriptionRulesPath(rl)
	if err := writeFile0600(rulesPath, strings.NewReader(testRulesV1)); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	metaPath, _ := SubscriptionMetaPath(rl)
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	oldMeta := fmt.Sprintf(`{"url":%q,"etag":"\"v1\"","content_sha256":%q,"checked_at":100}`, srv.URL, sha256Hex(testRulesV1))
	if err := os.WriteFile(metaPath, []byte(oldMeta), 0o600); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	// 304 path: the cached bytes are validated; the missing TOFU pin is recorded on
	// first use instead of failing, so upgrades from older versions are seamless.
	_, meta, err := syncOnce(t, rl)
	if err != nil {
		t.Fatalf("old meta without pin must adopt TOFU without error: %v", err)
	}
	if meta.PinnedSHA256 != sha256Hex(testRulesV1) {
		t.Fatalf("TOFU pin should be recorded from cached content, got %q", meta.PinnedSHA256)
	}
	if meta.ConsecutiveFailures != 0 {
		t.Fatalf("failures should stay 0 on success, got %d", meta.ConsecutiveFailures)
	}
}

func TestSubscriptionConsecutiveFailures(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	body := testRulesV1
	srv := newRuleServer(t, &body)
	defer srv.Close()

	rl := config.RuleListConfig{
		ID:        "failcount-test",
		URL:       srv.URL,
		AllowHTTP: true,
		Enabled:   true,
		SHA256Pin: sha256Hex(testRulesV1),
	}

	// Success keeps the counter at 0.
	if _, meta, err := syncOnce(t, rl); err != nil || meta.ConsecutiveFailures != 0 {
		t.Fatalf("success should keep failures at 0: meta=%+v err=%v", meta, err)
	}

	// Consecutive rejected updates (fixed-pin mismatch) bump the counter.
	body = testRulesV2
	for want := 1; want <= 2; want++ {
		_, meta, err := syncOnce(t, rl)
		if err == nil {
			t.Fatalf("tampered content should be rejected (attempt %d)", want)
		}
		if meta.ConsecutiveFailures != want {
			t.Fatalf("failures should be %d, got %d", want, meta.ConsecutiveFailures)
		}
	}
	metaPath, _ := SubscriptionMetaPath(rl)
	persisted, ok, err := LoadSubscriptionMeta(metaPath)
	if err != nil || !ok {
		t.Fatalf("meta should be persisted: ok=%v err=%v", ok, err)
	}
	if persisted.ConsecutiveFailures != 2 {
		t.Fatalf("persisted failures should be 2, got %d", persisted.ConsecutiveFailures)
	}

	// A successful sync resets the counter.
	body = testRulesV1
	if _, meta, err := syncOnce(t, rl); err != nil || meta.ConsecutiveFailures != 0 {
		t.Fatalf("success should reset failures to 0: meta=%+v err=%v", meta, err)
	}

	// A transport failure (not only pin mismatches) also increments the counter.
	srv.Close()
	if _, meta, err := syncOnce(t, rl); err == nil || meta.ConsecutiveFailures != 1 {
		t.Fatalf("transport failure should increment failures to 1: meta=%+v err=%v", meta, err)
	}
}

func TestSubscriptionRedirectDowngradeRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Plain-HTTP target that a redirect would pull content from.
	body := testRulesV1
	target := newRuleServer(t, &body)
	defer target.Close()

	// HTTPS origin that redirects every request to the plain-HTTP target.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	// allow_http=false: the https->http redirect must be refused, not followed.
	rl := config.RuleListConfig{
		ID:        "redirect-test",
		URL:       origin.URL,
		AllowHTTP: false,
		Enabled:   true,
	}
	_, meta, err := SyncSubscriptionIfDue(nil, rl, SyncSubscriptionOptions{Force: true, Client: origin.Client()})
	if err == nil {
		t.Fatalf("https->http redirect must be rejected when allow_http=false")
	}
	if !strings.Contains(err.Error()+meta.LastError, "重定向") && !strings.Contains(err.Error()+meta.LastError, "http") {
		t.Fatalf("expected redirect rejection error, got: %v / %q", err, meta.LastError)
	}
}

func TestSubscriptionPinCheckedOn304(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	body := testRulesV1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	rl := config.RuleListConfig{
		ID:        "pin304-test",
		URL:       srv.URL,
		AllowHTTP: true,
		Enabled:   true,
	}

	// First fetch: caches content with ETag (no pin configured yet).
	if updated, _, err := syncOnce(t, rl); err != nil || !updated {
		t.Fatalf("initial fetch failed: updated=%v err=%v", updated, err)
	}

	// Now configure a pin that does NOT match the cached content; the 304 path
	// must validate the cached bytes against the pin instead of blindly accepting.
	rl.SHA256Pin = sha256Hex(testRulesV2)
	_, meta, err := syncOnce(t, rl)
	if err == nil {
		t.Fatalf("304 with mismatched pin must be rejected")
	}
	if !strings.Contains(meta.LastError, "不匹配") {
		t.Fatalf("meta.LastError should record the pin mismatch, got: %q", meta.LastError)
	}

	// A matching pin is accepted on the 304 path.
	rl.SHA256Pin = sha256Hex(testRulesV1)
	if _, _, err := syncOnce(t, rl); err != nil {
		t.Fatalf("304 with matching pin should be accepted, got: %v", err)
	}
}
