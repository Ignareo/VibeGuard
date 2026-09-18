package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/auditdb"
)

func TestCSRFProtectionOK(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		allowed bool
	}{
		{name: "get exempt", method: http.MethodGet, path: "/manager/api/stats", allowed: true},
		{name: "head exempt", method: http.MethodHead, path: "/manager/api/stats", allowed: true},
		{name: "options exempt", method: http.MethodOptions, path: "/manager/api/stats", allowed: true},
		{name: "post without header", method: http.MethodPost, path: "/manager/api/patterns", allowed: false},
		{name: "post with header", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1"}, allowed: true},
		{name: "post wrong header value", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "true"}, allowed: false},
		{name: "post matching origin", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Origin": "http://127.0.0.1:8080"}, allowed: true},
		{name: "post mismatched origin host", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Origin": "http://localhost:3000"}, allowed: false},
		{name: "post mismatched origin port", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Origin": "http://127.0.0.1:3000"}, allowed: false},
		{name: "post null origin", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Origin": "null"}, allowed: false},
		{name: "post same-origin fetch metadata", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Sec-Fetch-Site": "same-origin"}, allowed: true},
		{name: "post same-site fetch metadata", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Sec-Fetch-Site": "same-site"}, allowed: true},
		{name: "post none fetch metadata", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Sec-Fetch-Site": "none"}, allowed: true},
		{name: "post cross-site fetch metadata", method: http.MethodPost, path: "/manager/api/patterns", headers: map[string]string{"X-VG-Admin-Request": "1", "Sec-Fetch-Site": "cross-site"}, allowed: false},
		{name: "non-api path without header", method: http.MethodPost, path: "/manager/other", allowed: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://127.0.0.1:8080"+tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			if got := csrfProtectionOK(rec, req); got != tc.allowed {
				t.Fatalf("csrfProtectionOK = %v, want %v (status=%d)", got, tc.allowed, rec.Code)
			}
			if !tc.allowed && rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
		})
	}
}

func TestHandlerCSRFRunsBeforeAuth(t *testing.T) {
	a := &Admin{auth: NewAuthManager(filepath.Join(t.TempDir(), "admin_auth.json"))}

	// Without the header the request is rejected by CSRF protection (before auth).
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/manager/api/patterns", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "X-VG-Admin-Request") {
		t.Fatalf("missing header: got %d %q, want CSRF 403", rec.Code, rec.Body.String())
	}

	// With the header, CSRF passes and the auth layer answers (403 "setup required"
	// here because no admin password is configured yet).
	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/manager/api/patterns", strings.NewReader(`{}`))
	req.Header.Set("X-VG-Admin-Request", "1")
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "X-VG-Admin-Request") {
		t.Fatalf("header present but CSRF rejected: %q", rec.Body.String())
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 from auth layer", rec.Code)
	}
}

func TestAuthSetupLoopbackOnly(t *testing.T) {
	a := &Admin{auth: NewAuthManager(filepath.Join(t.TempDir(), "admin_auth.json"))}
	body := `{"password":"test-password-123"}`

	newSetupReq := func(remoteAddr, urlHost string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/manager/api/auth/setup", strings.NewReader(body))
		// net/http keeps the authority in req.Host; origin-form requests leave
		// req.URL.Host empty, absolute-URI (proxy-style) requests set it.
		req.Host = "127.0.0.1:8080"
		req.URL.Host = urlHost
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-VG-Admin-Request", "1")
		return req
	}

	// Non-loopback peer must be rejected before anything else.
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, newSetupReq("192.0.2.1:1234", ""))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "loopback") {
		t.Fatalf("non-loopback setup: got %d %q, want 403", rec.Code, rec.Body.String())
	}

	// Absolute-URI (proxy-style) request must be rejected even from loopback.
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, newSetupReq("127.0.0.1:1234", "127.0.0.1:8080"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("absolute-URI setup: got %d, want 403", rec.Code)
	}

	// Unparseable RemoteAddr is treated as non-loopback.
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, newSetupReq("not-a-hostport", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad remote addr setup: got %d, want 403", rec.Code)
	}

	// IPv6 loopback works too.
	rec = httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, newSetupReq("[::1]:1234", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ipv6 loopback setup: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// Direct loopback origin-form request succeeds.
	a2 := &Admin{auth: NewAuthManager(filepath.Join(t.TempDir(), "admin_auth.json"))}
	rec = httptest.NewRecorder()
	a2.Handler().ServeHTTP(rec, newSetupReq("127.0.0.1:1234", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback setup: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleTest(t *testing.T) {
	a := &Admin{}

	// Without a registered tester the endpoint is unavailable.
	req := httptest.NewRequest(http.MethodPost, "/manager/api/test", strings.NewReader(`{"text":"hello"}`))
	rec := httptest.NewRecorder()
	a.handleTest(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil tester: got %d, want 503", rec.Code)
	}

	a.SetRedactTester(func(text string) (string, []TestHit) {
		return "__VG_TEST__", []TestHit{{Category: "TEST", Source: "keywords", Placeholder: "__VG_TEST__", Preview: "he…lo", Length: 5}}
	})

	// Empty text is rejected.
	req = httptest.NewRequest(http.MethodPost, "/manager/api/test", strings.NewReader(`{"text":"  "}`))
	rec = httptest.NewRecorder()
	a.handleTest(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty text: got %d, want 400", rec.Code)
	}

	// Normal dry run returns redacted text and masked hits.
	req = httptest.NewRequest(http.MethodPost, "/manager/api/test", strings.NewReader(`{"text":"hello"}`))
	rec = httptest.NewRecorder()
	a.handleTest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run: got %d, want 200", rec.Code)
	}
	var resp struct {
		Redacted string    `json:"redacted"`
		Matches  []TestHit `json:"matches"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Redacted != "__VG_TEST__" || len(resp.Matches) != 1 || resp.Matches[0].Preview != "he…lo" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// Hits are capped at 50.
	a.SetRedactTester(func(text string) (string, []TestHit) {
		hits := make([]TestHit, 60)
		for i := range hits {
			hits[i] = TestHit{Category: "TEST", Placeholder: "__VG_T__", Preview: "ab…yz", Length: 5}
		}
		return text, hits
	})
	req = httptest.NewRequest(http.MethodPost, "/manager/api/test", strings.NewReader(`{"text":"hello"}`))
	rec = httptest.NewRecorder()
	a.handleTest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("capped dry run: got %d, want 200", rec.Code)
	}
	resp = struct {
		Redacted string    `json:"redacted"`
		Matches  []TestHit `json:"matches"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Matches) != 50 {
		t.Fatalf("hits not capped: got %d, want 50", len(resp.Matches))
	}
}

func TestSettersAndSourceRoundTrip(t *testing.T) {
	a := &Admin{}

	a.SetLocalRuleListErrors(map[string]string{"/tmp/a.vgrules": "boom", "/tmp/ok.vgrules": ""})
	if got := a.localRuleListErrors()["/tmp/a.vgrules"]; got != "boom" {
		t.Fatalf("local rule list error not stored: %q", got)
	}
	if got := a.nonLoopbackWarning(); got != "" {
		t.Fatalf("unexpected warning: %q", got)
	}
	a.SetNonLoopbackWarning("listening on 0.0.0.0")
	if got := a.nonLoopbackWarning(); got != "listening on 0.0.0.0" {
		t.Fatalf("warning not stored: %q", got)
	}
	a.SetNonLoopbackWarning("")
	if got := a.nonLoopbackWarning(); got != "" {
		t.Fatalf("warning not cleared: %q", got)
	}

	// Source survives the admin<->auditdb conversion.
	in := []AuditMatch{{Category: "API_KEY", Source: "rulelist:default", Placeholder: "__VG_API_KEY_x__", Value: "sk-live-secret", Length: 14}}
	db := adminToDBMatches(in, false)
	if db[0].Source != "rulelist:default" {
		t.Fatalf("Source lost in adminToDBMatches: %q", db[0].Source)
	}
	if db[0].Value == "sk-live-secret" {
		t.Fatalf("raw value persisted without consent")
	}
	out := dbToAdminEvent(auditdb.AuditEvent{Matches: db})
	if out.Matches[0].Source != "rulelist:default" {
		t.Fatalf("Source lost in dbToAdminEvent: %q", out.Matches[0].Source)
	}
}
