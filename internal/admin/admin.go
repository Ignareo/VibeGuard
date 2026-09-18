package admin

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inkdust2021/vibeguard/internal/auditdb"
	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	vlog "github.com/inkdust2021/vibeguard/internal/log"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// StatsCollector tracks request statistics
type StatsCollector struct {
	TotalRequests    atomic.Int64
	RedactedRequests atomic.Int64
	RestoredRequests atomic.Int64
	Errors           atomic.Int64
	// NERFailures counts silently skipped NER analyses (overloaded/request/status/decode).
	NERFailures atomic.Int64
}

// Admin handles the web UI HTTP endpoints
type Admin struct {
	config    *config.Manager
	session   *session.Manager
	ca        *cert.CA
	certPath  string
	keyPath   string
	stats     *StatsCollector
	started   atomic.Int64 // Unix timestamp
	audit     *AuditStore
	auditDB   *auditdb.Store
	stopPurge func()
	debug     *DebugStore
	auth      *AuthManager
	meta      *metaAuditLog

	// localRuleListErrs holds the most recent load error per configured local
	// rule list (key: strings.TrimSpace(rl.Path) of lists with an empty URL;
	// empty value means the last load succeeded). Written by the proxy after
	// each ReloadFromConfig, read by the rule-lists API.
	localRuleListErrs atomic.Value // map[string]string

	// nonLoopbackWarn is a server-composed warning shown as a banner in the
	// admin UI when the proxy listens on a non-loopback address ("" = none).
	nonLoopbackWarn atomic.Value // string

	// redactTester is the dry-run redaction callback backing POST /manager/api/test.
	redactTester atomic.Value // func(string) (string, []TestHit)

	// Login brute-force protection: consecutive failures trigger a temporary lockout.
	loginMu          sync.Mutex
	loginFailures    int
	loginLockedUntil time.Time
}

// New creates a new Admin handler
func New(cfg *config.Manager, sess *session.Manager, ca *cert.CA, certPath, keyPath string) *Admin {
	auth := NewAuthManager(defaultAuthFilePath())
	a := &Admin{
		config:   cfg,
		session:  sess,
		ca:       ca,
		certPath: certPath,
		keyPath:  keyPath,
		stats:    &StatsCollector{},
		audit:    NewAuditStore(200),
		debug:    NewDebugStore(50),
		auth:     auth,
		meta:     newMetaAuditLog(),
	}
	a.started.Store(0)

	// Audit persistence (SQLite) is disabled by default; it is only effective in the "full" build when enabled in config.
	c := cfg.Get()
	if c.AuditDB.Enabled {
		a.openAuditDB(c.AuditDB)
	}

	return a
}

// GetStats returns the stats collector for external incrementing
func (a *Admin) GetStats() *StatsCollector {
	return a.stats
}

// SetStartTime records when the proxy started
func (a *Admin) SetStartTime(unix int64) {
	a.started.Store(unix)
}

// SetLocalRuleListErrors records the most recent load error for each configured
// local rule list (key: strings.TrimSpace(rl.Path) of lists with an empty URL;
// an empty value means the last load succeeded). Called by the proxy after
// every ReloadFromConfig; consumed by the rule-lists API.
func (a *Admin) SetLocalRuleListErrors(m map[string]string) {
	if a == nil {
		return
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	a.localRuleListErrs.Store(cp)
}

func (a *Admin) localRuleListErrors() map[string]string {
	if a == nil {
		return nil
	}
	if v := a.localRuleListErrs.Load(); v != nil {
		if m, ok := v.(map[string]string); ok {
			return m
		}
	}
	return nil
}

// SetNonLoopbackWarning sets (or clears, with an empty msg) the warning shown
// as a banner in the admin UI when the proxy listens on a non-loopback address.
// Called by the proxy on startup and on hot reload.
func (a *Admin) SetNonLoopbackWarning(msg string) {
	if a == nil {
		return
	}
	a.nonLoopbackWarn.Store(msg)
}

func (a *Admin) nonLoopbackWarning() string {
	if a == nil {
		return ""
	}
	if v := a.nonLoopbackWarn.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// SetRedactTester registers the dry-run redaction callback used by
// POST /manager/api/test. The callback returns the redacted text and the hits
// (TestHit.Preview must already be masked; the raw value is never returned).
// Passing nil disables the endpoint (it then answers 503).
func (a *Admin) SetRedactTester(fn func(text string) (redacted string, hits []TestHit)) {
	if a == nil {
		return
	}
	a.redactTester.Store(fn)
}

func (a *Admin) getRedactTester() func(text string) (redacted string, hits []TestHit) {
	if a == nil {
		return nil
	}
	if v := a.redactTester.Load(); v != nil {
		if fn, ok := v.(func(text string) (redacted string, hits []TestHit)); ok {
			return fn
		}
	}
	return nil
}

// RecordAudit records one audit event about whether redaction rules were hit.
func (a *Admin) RecordAudit(ev AuditEvent) AuditEvent {
	if a == nil || a.audit == nil {
		return ev
	}
	saved := a.audit.Add(ev)

	// Optional: persist to disk (full build + enabled in config).
	if a.auditDB != nil {
		if _, err := a.auditDB.Add(adminToDBEvent(saved, a.persistRawAuditValues())); err != nil {
			slog.Warn("auditdb: write failed", "error", err)
		}
	}

	return saved
}

// UpdateAudit updates a previously recorded audit event (e.g. to fill response status fields).
func (a *Admin) UpdateAudit(id int64, fn func(*AuditEvent)) (AuditEvent, bool) {
	if a == nil || a.audit == nil {
		return AuditEvent{}, false
	}
	ev, ok := a.audit.Update(id, fn)
	if ok && a.auditDB != nil {
		_ = a.auditDB.Update(id, func(dbEv *auditdb.AuditEvent) {
			dbEv.ResponseStatus = ev.ResponseStatus
			dbEv.ResponseContentType = ev.ResponseContentType
			dbEv.RestoreApplied = ev.RestoreApplied
			dbEv.RestoredCount = ev.RestoredCount
			dbEv.Attempted = ev.Attempted
			dbEv.RedactedCount = ev.RedactedCount
			dbEv.Matches = append([]auditdb.AuditMatch(nil), adminToDBMatches(ev.Matches, a.persistRawAuditValues())...)
			dbEv.Note = ev.Note
		})
	}
	return ev, ok
}

// Debug returns the debug capture store (in-memory only; not persisted).
func (a *Admin) Debug() *DebugStore {
	if a == nil {
		return nil
	}
	return a.debug
}

// Close releases resources held by the admin component (currently only the audit DB).
func (a *Admin) Close() {
	if a == nil {
		return
	}
	a.closeAuditDB()
}

func (a *Admin) openAuditDB(cfg config.AuditDBConfig) {
	if a == nil {
		return
	}
	if a.auditDB != nil {
		return
	}
	if !auditdb.Available {
		slog.Warn("AuditDB enabled in config but not available in this build (lite); ignoring")
		return
	}

	path := vlog.ExpandPath(cfg.Path)
	db, err := auditdb.Open(path)
	if err != nil {
		slog.Error("Failed to open audit database", "path", path, "error", err)
		return
	}
	a.auditDB = db

	// Advance in-memory audit IDs to the persisted max ID to avoid conflicts after restarts/toggles.
	if a.audit != nil {
		if maxID, err := db.MaxID(); err == nil {
			a.audit.BumpNextID(maxID)
		}
	}

	retention := parseDuration(cfg.Retention, 7*24*time.Hour)
	a.stopPurge = db.StartPurgeLoop(retention, 1*time.Hour)
	slog.Info("Audit database enabled", "path", path, "retention", retention)
}

func (a *Admin) closeAuditDB() {
	if a.stopPurge != nil {
		a.stopPurge()
		a.stopPurge = nil
	}
	if a.auditDB != nil {
		_ = a.auditDB.Close()
		a.auditDB = nil
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	// Support "7d" style day durations.
	if len(s) > 1 && s[len(s)-1] == 'd' {
		if days, err := time.ParseDuration(s[:len(s)-1] + "h"); err == nil {
			return days * 24
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

// persistRawAuditValues reports whether raw matched values may be persisted to the audit
// DB. Default false: the DB only stores previews, even when the admin UI is allowed to
// display originals (log.redact_log=false).
func (a *Admin) persistRawAuditValues() bool {
	if a == nil || a.config == nil {
		return false
	}
	return a.config.Get().AuditDB.PersistRawValuesEnabled()
}

// updateConfig applies fn to the config and persists it, recording a meta-audit entry on
// success so rule/config changes stay traceable.
func (a *Admin) updateConfig(r *http.Request, action string, fn func(*config.Config)) error {
	err := a.config.Update(fn)
	if err == nil {
		a.metaRecord(r, action)
	}
	return err
}

func adminToDBEvent(ev AuditEvent, persistRaw bool) auditdb.AuditEvent {
	return auditdb.AuditEvent{
		ID:                  ev.ID,
		Time:                ev.Time,
		Host:                ev.Host,
		Method:              ev.Method,
		Path:                ev.Path,
		ContentType:         ev.ContentType,
		ContentEncoding:     ev.ContentEncoding,
		Attempted:           ev.Attempted,
		RedactedCount:       ev.RedactedCount,
		Matches:             append([]auditdb.AuditMatch(nil), adminToDBMatches(ev.Matches, persistRaw)...),
		Note:                ev.Note,
		ResponseStatus:      ev.ResponseStatus,
		ResponseContentType: ev.ResponseContentType,
		RestoreApplied:      ev.RestoreApplied,
		RestoredCount:       ev.RestoredCount,
	}
}

func adminToDBMatches(in []AuditMatch, persistRaw bool) []auditdb.AuditMatch {
	if len(in) == 0 {
		return nil
	}
	out := make([]auditdb.AuditMatch, len(in))
	for i := range in {
		value := in[i].Value
		isPreview := in[i].IsPreview
		if !persistRaw && !isPreview {
			// Never persist raw sensitive values by default; degrade to a preview.
			value = previewAuditValue(value)
			isPreview = true
		}
		out[i] = auditdb.AuditMatch{
			Category:    in[i].Category,
			Source:      in[i].Source,
			Placeholder: in[i].Placeholder,
			Value:       value,
			IsPreview:   isPreview,
			Length:      in[i].Length,
			Truncated:   in[i].Truncated,
		}
	}
	return out
}

// previewAuditValue masks a value for at-rest persistence (first2…last2), mirroring the
// UI preview format used in privacy mode.
func previewAuditValue(s string) string {
	r := []rune(s)
	n := len(r)
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	return string(r[:2]) + "…" + string(r[n-2:])
}
