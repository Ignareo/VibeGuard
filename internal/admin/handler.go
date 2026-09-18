package admin

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed static
var staticFS embed.FS

// Handler returns the HTTP handler for the admin UI
func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes (under /manager/api/)
	mux.HandleFunc("/manager/api/auth/status", a.handleAuthStatus)
	mux.HandleFunc("/manager/api/auth/setup", a.handleAuthSetup)
	mux.HandleFunc("/manager/api/auth/login", a.handleAuthLogin)
	mux.HandleFunc("/manager/api/auth/logout", a.handleAuthLogout)
	mux.HandleFunc("/manager/api/stats", a.handleStats)
	mux.HandleFunc("/manager/api/stats/stream", a.handleStatsStream)
	mux.HandleFunc("/manager/api/patterns", a.handlePatterns)
	mux.HandleFunc("/manager/api/patterns/", a.handlePatternsItem)
	mux.HandleFunc("/manager/api/rule_lists", a.handleRuleLists)
	mux.HandleFunc("/manager/api/rule_lists/upload", a.handleRuleListsUpload)
	mux.HandleFunc("/manager/api/rule_lists/subscribe", a.handleRuleListsSubscribe)
	mux.HandleFunc("/manager/api/rule_lists/", a.handleRuleListsItem)
	// NER: named entity recognition
	mux.HandleFunc("/manager/api/ner", a.handleNER)
	mux.HandleFunc("/manager/api/sessions", a.handleSessions)
	mux.HandleFunc("/manager/api/certificates", a.handleCertificates)
	mux.HandleFunc("/manager/api/certificates/trust", a.handleCertTrust)
	mux.HandleFunc("/manager/api/certificates/regenerate", a.handleCertRegenerate)
	mux.HandleFunc("/manager/api/audit", a.handleAudit)
	mux.HandleFunc("/manager/api/audit/privacy", a.handleAuditPrivacy)
	mux.HandleFunc("/manager/api/audit/persistence", a.handleAuditPersistence)
	mux.HandleFunc("/manager/api/audit/stream", a.handleAuditStream)
	mux.HandleFunc("/manager/api/logs", a.handleLogs)
	mux.HandleFunc("/manager/api/logs/stream", a.handleLogsStream)
	mux.HandleFunc("/manager/api/debug", a.handleDebug)
	mux.HandleFunc("/manager/api/debug/events", a.handleDebugEvents)
	mux.HandleFunc("/manager/api/debug/events/", a.handleDebugEventsItem)
	mux.HandleFunc("/manager/api/settings", a.handleSettings)
	mux.HandleFunc("/manager/api/test", a.handleTest)

	// Static files - serve from embedded FS
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		slog.Error("Failed to load static files", "error", err)
	}

	fileServer := http.FileServer(http.FS(staticContent))

	// Serve static files at /manager/*
	mux.Handle("/manager/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The admin UI is a local management tool; avoid browser caching issues where an old UI persists after updates.
		// Disable caching for all /manager/ resources.
		w.Header().Set("Cache-Control", "no-store")

		// SPA fallback - serve index.html for non-file routes
		path := strings.TrimPrefix(r.URL.Path, "/manager/")

		// If path is empty or looks like a route (no extension), serve index.html
		if path == "" || !strings.Contains(path, ".") {
			r.URL.Path = "/manager/"
			http.StripPrefix("/manager", http.FileServer(http.FS(staticContent))).ServeHTTP(w, r)
			return
		}

		// Serve static file
		http.StripPrefix("/manager", fileServer).ServeHTTP(w, r)
	}))

	// Add logging middleware
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// CSRF defense-in-depth runs before auth so it also protects the unauthenticated
		// endpoints (setup/login): see csrfProtectionOK for the threat model.
		if !csrfProtectionOK(w, r) {
			return
		}
		// Admin auth: all /manager/api/* endpoints require login by default (if no password is set yet, go through setup).
		if strings.HasPrefix(r.URL.Path, "/manager/api/") && !isManagerPublicAPI(r.URL.Path) {
			if a == nil || a.auth == nil {
				http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
				return
			}
			if ok := a.auth.Require(w, r); !ok {
				return
			}
		}

		mux.ServeHTTP(w, r)
		slog.Debug("Admin request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

// csrfProtectionOK enforces the CSRF policy for /manager/api/ write requests.
//
// Threat model: the session cookie is SameSite=Strict, but that does not stop a
// malicious page served from another port of the same site ("same-site" in the
// cookie sense, e.g. localhost:3000) from forging requests to the admin API on
// localhost:8080 — the browser attaches the cookie anyway. The admin SPA can
// attach a custom header to every API call; cross-site HTML forms cannot, and
// cross-origin JavaScript fails the CORS preflight because the admin API never
// sets CORS headers.
//
// Policy: any non-GET/HEAD/OPTIONS request under /manager/api/ must carry the
// custom header X-VG-Admin-Request: 1 (also enforced on the unauthenticated
// setup/login/logout endpoints), and requests that identify a cross-site origin
// are rejected.
func csrfProtectionOK(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/manager/api/") {
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get("X-VG-Admin-Request") != "1" {
		http.Error(w, "Forbidden: missing X-VG-Admin-Request header", http.StatusForbidden)
		return false
	}
	if !originAllowed(r) || !secFetchSiteAllowed(r) {
		http.Error(w, "Forbidden: cross-site request blocked", http.StatusForbidden)
		return false
	}
	return true
}

// originAllowed rejects requests whose Origin header identifies a different
// host (or port) than the request's Host header — i.e. a page on another
// origin/port trying to ride an ambient session cookie. Browsers always send
// Origin on cross-site POSTs; same-origin requests match by definition.
// A missing Origin header (non-browser clients) is allowed.
func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		// Unparseable or non-hierarchical origins (e.g. "null" from sandboxed
		// documents) cannot be tied to this host: reject.
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// secFetchSiteAllowed rejects obvious cross-site submissions when the browser
// sends the Sec-Fetch-Site metadata header (defense in depth on top of the
// custom-header check; older clients simply do not send it).
func secFetchSiteAllowed(r *http.Request) bool {
	v := r.Header.Get("Sec-Fetch-Site")
	if v == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "same-origin", "same-site", "none":
		return true
	default:
		return false
	}
}

func isManagerPublicAPI(path string) bool {
	switch path {
	case "/manager/api/settings",
		"/manager/api/auth/status",
		"/manager/api/auth/setup",
		"/manager/api/auth/login",
		"/manager/api/auth/logout":
		return true
	default:
		return false
	}
}
