package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/auditdb"
	"github.com/inkdust2021/vibeguard/internal/config"
)

type AuditResponse struct {
	RedactLog bool         `json:"redact_log"`
	MaxEvents int          `json:"max_events"`
	Events    []AuditEvent `json:"events"`
}

// handleAudit handles GET/DELETE /manager/api/audit
func (a *Admin) handleAudit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getAudit(w, r)
	case http.MethodDelete:
		a.clearAudit(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getAudit(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.audit == nil {
		http.Error(w, "Audit store not available", http.StatusInternalServerError)
		return
	}

	limit := clampInt(queryInt(r, "limit", 200), 1, 500)
	cfg := a.config.Get()

	events, err := a.listAuditEvents(limit)
	if err != nil {
		http.Error(w, "Failed to load audit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := AuditResponse{
		RedactLog: cfg.Log.RedactLog,
		MaxEvents: a.audit.max,
		Events:    events,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) clearAudit(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.audit == nil {
		http.Error(w, "Audit store not available", http.StatusInternalServerError)
		return
	}
	// If SQLite audit persistence is enabled, clear persisted data as well.
	if a.auditDB != nil {
		if err := a.auditDB.Clear(); err != nil {
			http.Error(w, "Failed to clear audit db: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	a.audit.Clear()
	a.metaRecord(r, "audit.clear")
	w.WriteHeader(http.StatusNoContent)
}

// handleAuditPrivacy handles POST /manager/api/audit/privacy
// Toggles "privacy mode" in the admin UI (whether to display originals in the audit panel).
func (a *Admin) handleAuditPrivacy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.config == nil {
		http.Error(w, "Config manager not available", http.StatusInternalServerError)
		return
	}

	var req struct {
		RedactLog *bool `json:"redact_log"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.RedactLog == nil {
		http.Error(w, "redact_log is required", http.StatusBadRequest)
		return
	}

	if err := a.updateConfig(r, "config.audit_privacy.update", func(c *config.Config) {
		c.Log.RedactLog = *req.RedactLog
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"redact_log": a.config.Get().Log.RedactLog,
	})
}

// handleAuditPersistence handles GET/POST /manager/api/audit/persistence
// Toggles "audit persistence" (SQLite). This is only available in the "full" build.
func (a *Admin) handleAuditPersistence(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.config == nil {
		http.Error(w, "Config manager not available", http.StatusInternalServerError)
		return
	}

	type resp struct {
		Available bool   `json:"available"`
		Enabled   bool   `json:"enabled"`
		Path      string `json:"path"`
		Retention string `json:"retention"`
	}

	if r.Method == http.MethodGet {
		cfg := a.config.Get()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp{
			Available: auditdb.Available,
			Enabled:   cfg.AuditDB.Enabled,
			Path:      cfg.AuditDB.Path,
			Retention: cfg.AuditDB.Retention,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled   *bool   `json:"enabled"`
		Retention *string `json:"retention,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "enabled is required", http.StatusBadRequest)
		return
	}

	if *req.Enabled && !auditdb.Available {
		http.Error(w, "AuditDB not available in this build", http.StatusNotImplemented)
		return
	}

	if err := a.updateConfig(r, "config.audit_persistence.update", func(c *config.Config) {
		c.AuditDB.Enabled = *req.Enabled
		if req.Retention != nil {
			c.AuditDB.Retention = strings.TrimSpace(*req.Retention)
		}
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cfg := a.config.Get()
	if cfg.AuditDB.Enabled && a.auditDB == nil {
		a.openAuditDB(cfg.AuditDB)
	} else if !cfg.AuditDB.Enabled && a.auditDB != nil {
		a.closeAuditDB()
	}

	// If enabling fails (e.g. permission issues), keep the config written but return current availability/enabled status.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp{
		Available: auditdb.Available,
		Enabled:   cfg.AuditDB.Enabled,
		Path:      cfg.AuditDB.Path,
		Retention: cfg.AuditDB.Retention,
	})
}

// handleAuditStream handles GET /manager/api/audit/stream?limit=200
func (a *Admin) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.audit == nil {
		http.Error(w, "Audit store not available", http.StatusInternalServerError)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	send := func(event string, v any) {
		data, _ := json.Marshal(v)
		_, _ = w.Write([]byte("event: " + event + "\n"))
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
		flusher.Flush()
	}

	limit := clampInt(queryInt(r, "limit", 200), 1, 500)
	cfg := a.config.Get()
	events, err := a.listAuditEvents(limit)
	if err != nil {
		http.Error(w, "Failed to load audit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	send("audit_init", AuditResponse{
		RedactLog: cfg.Log.RedactLog,
		MaxEvents: a.audit.max,
		Events:    events,
	})

	ch, cancel := a.audit.Subscribe(64)
	defer cancel()

	// Heartbeat: prevent intermediaries/browsers from closing long-lived connections.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			send("audit_event", ev)
		case <-ticker.C:
			// SSE comment line as heartbeat
			_, _ = w.Write([]byte(": ping " + strings.ReplaceAll(time.Now().Format(time.RFC3339), " ", "") + "\n\n"))
			flusher.Flush()
		}
	}
}

func (a *Admin) listAuditEvents(limit int) ([]AuditEvent, error) {
	if a == nil || a.audit == nil {
		return nil, nil
	}
	// If persistence is enabled, prefer reading from SQLite (history survives restarts).
	if a.auditDB != nil {
		evs, err := a.auditDB.List(limit)
		if err != nil {
			return nil, err
		}
		out := make([]AuditEvent, len(evs))
		for i := range evs {
			out[i] = dbToAdminEvent(evs[i])
		}
		return out, nil
	}
	return a.audit.List(limit), nil
}

func dbToAdminEvent(ev auditdb.AuditEvent) AuditEvent {
	out := AuditEvent{
		ID:                  ev.ID,
		Time:                ev.Time,
		Host:                ev.Host,
		Method:              ev.Method,
		Path:                ev.Path,
		ContentType:         ev.ContentType,
		ContentEncoding:     ev.ContentEncoding,
		Attempted:           ev.Attempted,
		RedactedCount:       ev.RedactedCount,
		Note:                ev.Note,
		ResponseStatus:      ev.ResponseStatus,
		ResponseContentType: ev.ResponseContentType,
		RestoreApplied:      ev.RestoreApplied,
		RestoredCount:       ev.RestoredCount,
	}
	if len(ev.Matches) > 0 {
		out.Matches = make([]AuditMatch, len(ev.Matches))
		for i := range ev.Matches {
			out.Matches[i] = AuditMatch{
				Category:    ev.Matches[i].Category,
				Placeholder: ev.Matches[i].Placeholder,
				Value:       ev.Matches[i].Value,
				IsPreview:   ev.Matches[i].IsPreview,
				Length:      ev.Matches[i].Length,
				Truncated:   ev.Matches[i].Truncated,
			}
		}
	}
	return out
}
