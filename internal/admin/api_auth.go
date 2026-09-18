package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const loginMaxFailures = 5

// isDirectLoopbackRequest reports whether r came in over a loopback TCP
// connection and used the origin-form request target (r.URL.Host == "", i.e.
// not an absolute-URI proxy-style request). An unparseable RemoteAddr is
// treated as non-loopback.
func isDirectLoopbackRequest(r *http.Request) bool {
	if r.URL.Host != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type AuthStatusResponse struct {
	Configured    bool   `json:"configured"`
	Authenticated bool   `json:"authenticated"`
	Broken        bool   `json:"broken"`
	BrokenError   string `json:"broken_error,omitempty"`
}

func (a *Admin) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	configured, authed, broken, brokenErr := a.auth.Status(r)
	resp := AuthStatusResponse{
		Configured:    configured,
		Authenticated: authed,
		Broken:        broken,
		BrokenError:   brokenErr,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The initial password setup grants full admin access, so it is only allowed
	// from a direct loopback connection using the origin-form request target.
	// This blocks a malicious page on the LAN from initializing/changing the admin
	// password when the proxy is bound to a non-loopback address, and blocks
	// absolute-URI (proxy-style) requests. Regular login is not restricted here
	// because it already has brute-force lockout.
	if !isDirectLoopbackRequest(r) {
		http.Error(w, "Forbidden: setup is only allowed from a direct loopback connection (仅允许本机直连初始化)", http.StatusForbidden)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	req.Password = strings.TrimSpace(req.Password)

	if err := a.auth.Setup(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.metaRecord(r, "auth.setup")

	// Create a session immediately after setup to avoid requiring a separate manual login.
	a.auth.mu.Lock()
	token, _, err := a.auth.CreateSessionLocked()
	a.auth.mu.Unlock()
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	setAdminSessionCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *Admin) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	req.Password = strings.TrimSpace(req.Password)

	// Brute-force protection: consecutive failures lock login attempts temporarily
	// (1 minute, doubling per extra failure, capped at ~16 minutes).
	a.loginMu.Lock()
	if until := a.loginLockedUntil; time.Now().Before(until) {
		a.loginMu.Unlock()
		a.metaRecord(r, "auth.login.locked", "retry_after_sec", int(time.Until(until).Seconds())+1)
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(until).Seconds())+1))
		http.Error(w, "Too many failed attempts; try again later", http.StatusTooManyRequests)
		return
	}
	a.loginMu.Unlock()

	if err := a.auth.Verify(req.Password); err != nil {
		a.loginMu.Lock()
		a.loginFailures++
		failures := a.loginFailures
		if failures >= loginMaxFailures {
			shift := failures - loginMaxFailures
			if shift > 4 {
				shift = 4
			}
			a.loginLockedUntil = time.Now().Add(time.Minute << shift)
		}
		locked := !a.loginLockedUntil.IsZero() && time.Now().Before(a.loginLockedUntil)
		a.loginMu.Unlock()
		a.metaRecord(r, "auth.login.failure", "failures", failures, "locked", locked)
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	a.loginMu.Lock()
	a.loginFailures = 0
	a.loginLockedUntil = time.Time{}
	a.loginMu.Unlock()
	a.metaRecord(r, "auth.login.success")

	a.auth.mu.Lock()
	token, _, err := a.auth.CreateSessionLocked()
	a.auth.mu.Unlock()
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	setAdminSessionCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *Admin) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	a.auth.DestroySession(r)
	clearAdminSessionCookie(w)
	a.metaRecord(r, "auth.logout")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
