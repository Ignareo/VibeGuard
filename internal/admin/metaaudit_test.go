package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func newTestAdmin(t *testing.T) (*Admin, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	adm := New(config.NewManager(), session.NewManager(time.Hour, 10), nil, "", "")
	t.Cleanup(adm.Close)
	return adm, filepath.Join(dir, ".vibeguard", "admin-audit.log")
}

func readMetaAudit(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read meta-audit log: %v", err)
	}
	return string(data)
}

func TestLoginThrottleAndMetaAudit(t *testing.T) {
	adm, logPath := newTestAdmin(t)
	if err := adm.auth.Setup("correct-horse"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	post := func(pw string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/manager/api/auth/login", strings.NewReader(`{"password":"`+pw+`"}`))
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		adm.handleAuthLogin(rec, req)
		return rec
	}

	for i := 1; i <= loginMaxFailures; i++ {
		if rec := post("wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, rec.Code)
		}
	}
	// Locked out: even the correct password is rejected while the lockout is active.
	if rec := post("correct-horse"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 during lockout, got %d", rec.Code)
	}
	if rec := post("wrong"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 during lockout, got %d", rec.Code)
	}

	log := readMetaAudit(t, logPath)
	if got := strings.Count(log, "auth.login.failure"); got != loginMaxFailures {
		t.Fatalf("expected %d auth.login.failure entries, got %d:\n%s", loginMaxFailures, got, log)
	}
	if !strings.Contains(log, "auth.login.locked") {
		t.Fatalf("expected auth.login.locked entry:\n%s", log)
	}
	if !strings.Contains(log, "127.0.0.1") {
		t.Fatalf("expected remote address in meta-audit:\n%s", log)
	}

	// After the lockout expires, the correct password works again and is recorded.
	adm.loginMu.Lock()
	adm.loginLockedUntil = time.Now().Add(-time.Second)
	adm.loginMu.Unlock()
	if rec := post("correct-horse"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after lockout expiry, got %d", rec.Code)
	}
	if log := readMetaAudit(t, logPath); !strings.Contains(log, "auth.login.success") {
		t.Fatalf("expected auth.login.success entry:\n%s", log)
	}
}

func TestMetaAuditAdminOps(t *testing.T) {
	adm, logPath := newTestAdmin(t)

	rec := httptest.NewRecorder()
	adm.clearAudit(rec, httptest.NewRequest(http.MethodDelete, "/manager/api/audit", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clearAudit: expected 204, got %d", rec.Code)
	}

	privReq := httptest.NewRequest(http.MethodPost, "/manager/api/audit/privacy", strings.NewReader(`{"redact_log":false}`))
	rec2 := httptest.NewRecorder()
	adm.handleAuditPrivacy(rec2, privReq)
	if rec2.Code != http.StatusOK {
		t.Fatalf("handleAuditPrivacy: expected 200, got %d", rec2.Code)
	}

	log := readMetaAudit(t, logPath)
	if !strings.Contains(log, "audit.clear") {
		t.Fatalf("expected audit.clear entry:\n%s", log)
	}
	if !strings.Contains(log, "config.audit_privacy.update") {
		t.Fatalf("expected config.audit_privacy.update entry:\n%s", log)
	}
}

func TestMetaAuditLogFormat(t *testing.T) {
	dir := t.TempDir()
	m := &metaAuditLog{path: filepath.Join(dir, "admin-audit.log")}
	m.record("test.action", "count", 3, "ok", true)

	data, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"action":"test.action"`) || !strings.Contains(s, `"count":3`) || !strings.Contains(s, `"time":"`) {
		t.Fatalf("unexpected meta-audit line: %s", s)
	}
	fi, err := os.Stat(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %o", fi.Mode().Perm())
	}
}
