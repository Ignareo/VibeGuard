package admin

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// metaAuditLog is an append-only JSONL log of sensitive admin operations (logins, audit
// clears, rule/config changes). It exists so admin actions stay traceable even when the
// traffic audit log is cleared, and it never records sensitive values (only action names,
// counts, categories, and the remote address).
type metaAuditLog struct {
	mu     sync.Mutex
	path   string
	failed bool // open failed once; warn only once
}

func newMetaAuditLog() *metaAuditLog {
	return &metaAuditLog{path: filepath.Join(config.GetConfigDir(), "admin-audit.log")}
}

// record appends one meta-audit entry. kv pairs must be plain strings/bools/ints.
func (m *metaAuditLog) record(action string, kv ...any) {
	if m == nil || strings.TrimSpace(m.path) == "" {
		return
	}

	entry := make(map[string]any, 2+len(kv)/2)
	entry["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	entry["action"] = action
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok || key == "" {
			continue
		}
		entry[key] = kv[i+1]
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		if !m.failed {
			m.failed = true
			slog.Warn("meta-audit log unavailable", "path", m.path, "error", err)
		}
		return
	}

	f, err := os.OpenFile(m.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		if !m.failed {
			m.failed = true
			slog.Warn("meta-audit log unavailable", "path", m.path, "error", err)
		}
		return
	}
	defer f.Close()
	_ = os.Chmod(m.path, 0600)
	if _, err := f.Write(append(line, '\n')); err != nil {
		slog.Warn("meta-audit write failed", "path", m.path, "error", err)
	}
}

// metaRecord records one meta-audit entry with the request's remote address.
func (a *Admin) metaRecord(r *http.Request, action string, kv ...any) {
	if a == nil || a.meta == nil {
		return
	}
	if r != nil {
		kv = append(kv, "remote", remoteAddr(r))
	}
	a.meta.record(action, kv...)
}

func remoteAddr(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
