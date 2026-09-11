//go:build vibeguard_full

package auditdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
	id                  INTEGER PRIMARY KEY,
	time                TEXT    NOT NULL,
	host                TEXT    NOT NULL DEFAULT '',
	method              TEXT    NOT NULL DEFAULT '',
	path                TEXT    NOT NULL DEFAULT '',
	content_type        TEXT    NOT NULL DEFAULT '',
	content_encoding    TEXT    NOT NULL DEFAULT '',
	attempted           INTEGER NOT NULL DEFAULT 0,
	redacted_count      INTEGER NOT NULL DEFAULT 0,
	matches             TEXT    NOT NULL DEFAULT '[]',
	note                TEXT    NOT NULL DEFAULT '',
	response_status     INTEGER NOT NULL DEFAULT 0,
	response_content_type TEXT NOT NULL DEFAULT '',
	restore_applied     INTEGER NOT NULL DEFAULT 0,
	restored_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(time);
`

// Store is a SQLite-backed audit event store.
// Note: this is only enabled in the "full" build (build tag: vibeguard_full).
type Store struct {
	mu sync.Mutex
	db *sql.DB

	path string
	// walChmod ensures the lazily created -wal/-shm sidecar files get tightened once.
	walChmod sync.Once

	insertStmt *sql.Stmt
	updateStmt *sql.Stmt
}

// Open opens or creates the SQLite audit database.
func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("auditdb: create dir: %w", err)
	}

	// modernc.org/sqlite only honors _pragma= query parameters; the classic
	// _journal_mode=/_busy_timeout= keys are silently ignored by the driver.
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("auditdb: open: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auditdb: schema: %w", err)
	}

	// Fail loudly if WAL mode did not stick (exotic filesystems may reject it):
	// busy_timeout without WAL gives much weaker concurrency than intended.
	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auditdb: read journal_mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		slog.Warn("SQLite audit DB is not in WAL journal mode", "path", path, "journal_mode", journalMode)
	}

	// The database file may contain previews of sensitive matches; never leave it
	// world/group-readable (the driver creates it with umask defaults, typically 0644).
	if err := chmodPrivateDBFiles(path); err != nil {
		_ = db.Close()
		return nil, err
	}

	ins, err := db.Prepare(`INSERT INTO audit_events
		(id, time, host, method, path, content_type, content_encoding,
		 attempted, redacted_count, matches, note,
		 response_status, response_content_type, restore_applied, restored_count)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auditdb: prepare insert: %w", err)
	}

	upd, err := db.Prepare(`UPDATE audit_events SET
		time=?, host=?, method=?, path=?, content_type=?, content_encoding=?,
		attempted=?, redacted_count=?, matches=?, note=?,
		response_status=?, response_content_type=?, restore_applied=?, restored_count=?
		WHERE id=?`)
	if err != nil {
		_ = ins.Close()
		_ = db.Close()
		return nil, fmt.Errorf("auditdb: prepare update: %w", err)
	}

	return &Store{db: db, path: path, insertStmt: ins, updateStmt: upd}, nil
}

// chmodPrivateDBFiles tightens permissions on the database and its journal sidecars
// (-wal/-shm in WAL mode, -journal in rollback modes).
func chmodPrivateDBFiles(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := os.Chmod(p, 0600); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("auditdb: chmod %s: %w", p, err)
		}
	}
	return nil
}

// MaxID returns the largest id in the table (used to avoid ID collisions after restart).
func (s *Store) MaxID() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var max int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM audit_events`).Scan(&max); err != nil {
		return 0, err
	}
	return max, nil
}

// Add persists one audit event. Requires ev.ID > 0 (assigned by the in-memory audit recorder).
func (s *Store) Add(ev AuditEvent) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.ID <= 0 {
		return ev, fmt.Errorf("auditdb: missing id")
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	} else {
		ev.Time = ev.Time.UTC()
	}

	matchesJSON, _ := json.Marshal(ev.Matches)
	_, err := s.insertStmt.Exec(
		ev.ID,
		ev.Time.Format(time.RFC3339Nano),
		ev.Host, ev.Method, ev.Path,
		ev.ContentType, ev.ContentEncoding,
		boolToInt(ev.Attempted), ev.RedactedCount, string(matchesJSON), ev.Note,
		ev.ResponseStatus, ev.ResponseContentType,
		boolToInt(ev.RestoreApplied), ev.RestoredCount,
	)
	if err != nil {
		return ev, fmt.Errorf("auditdb: insert: %w", err)
	}
	// The WAL/SHM sidecars are created lazily on the first write; tighten them once.
	s.walChmod.Do(func() {
		if err := chmodPrivateDBFiles(s.path); err != nil {
			slog.Warn("auditdb: failed to tighten sidecar file permissions", "error", err)
		}
	})
	return ev, nil
}

// Update reads an event by ID, mutates it, and writes it back.
func (s *Store) Update(id int64, fn func(*AuditEvent)) error {
	if id <= 0 || fn == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	row := s.db.QueryRow(`SELECT
		time, host, method, path, content_type, content_encoding,
		attempted, redacted_count, matches, note,
		response_status, response_content_type, restore_applied, restored_count
		FROM audit_events WHERE id=?`, id)

	var ev AuditEvent
	var timeStr, matchesStr string
	var attempted, restoreApplied int
	if err := row.Scan(
		&timeStr, &ev.Host, &ev.Method, &ev.Path,
		&ev.ContentType, &ev.ContentEncoding,
		&attempted, &ev.RedactedCount, &matchesStr, &ev.Note,
		&ev.ResponseStatus, &ev.ResponseContentType,
		&restoreApplied, &ev.RestoredCount,
	); err != nil {
		return fmt.Errorf("auditdb: select for update: %w", err)
	}

	ev.ID = id
	ev.Time, _ = time.Parse(time.RFC3339Nano, timeStr)
	ev.Attempted = attempted != 0
	ev.RestoreApplied = restoreApplied != 0
	_ = json.Unmarshal([]byte(matchesStr), &ev.Matches)

	fn(&ev)

	ev.Time = ev.Time.UTC()
	matchesJSON, _ := json.Marshal(ev.Matches)
	_, err := s.updateStmt.Exec(
		ev.Time.Format(time.RFC3339Nano),
		ev.Host, ev.Method, ev.Path,
		ev.ContentType, ev.ContentEncoding,
		boolToInt(ev.Attempted), ev.RedactedCount, string(matchesJSON), ev.Note,
		ev.ResponseStatus, ev.ResponseContentType,
		boolToInt(ev.RestoreApplied), ev.RestoredCount,
		id,
	)
	return err
}

// List returns the most recent limit events (time order: old -> new).
func (s *Store) List(limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 200
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT
		id, time, host, method, path, content_type, content_encoding,
		attempted, redacted_count, matches, note,
		response_status, response_content_type, restore_applied, restored_count
		FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var timeStr, matchesStr string
		var attempted, restoreApplied int
		if err := rows.Scan(
			&ev.ID, &timeStr, &ev.Host, &ev.Method, &ev.Path,
			&ev.ContentType, &ev.ContentEncoding,
			&attempted, &ev.RedactedCount, &matchesStr, &ev.Note,
			&ev.ResponseStatus, &ev.ResponseContentType,
			&restoreApplied, &ev.RestoredCount,
		); err != nil {
			return events, err
		}

		ev.Time, _ = time.Parse(time.RFC3339Nano, timeStr)
		ev.Attempted = attempted != 0
		ev.RestoreApplied = restoreApplied != 0
		_ = json.Unmarshal([]byte(matchesStr), &ev.Matches)
		events = append(events, ev)
	}

	// Reverse into old -> new order.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	return events, nil
}

// Purge deletes events older than retention.
func (s *Store) Purge(retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention).Format(time.RFC3339Nano)
	res, err := s.db.Exec(`DELETE FROM audit_events WHERE time < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Clear removes all events.
func (s *Store) Clear() error {
	_, err := s.db.Exec(`DELETE FROM audit_events`)
	return err
}

// Close closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.insertStmt.Close()
	_ = s.updateStmt.Close()
	return s.db.Close()
}

// StartPurgeLoop starts a periodic purge loop (background goroutine) and returns a stop function.
func (s *Store) StartPurgeLoop(retention time.Duration, interval time.Duration) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				n, err := s.Purge(retention)
				if err != nil {
					slog.Warn("auditdb: purge error", "error", err)
				} else if n > 0 {
					slog.Info("auditdb: purged old events", "count", n)
				}
			}
		}
	}()
	return func() { close(done) }
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
