package auditdb

import "time"

// AuditMatch matches the admin audit display fields (for easier JSON serialization and persistence).
type AuditMatch struct {
	Category string `json:"category"`
	// Source is a human-readable identifier of the rule that produced the hit
	// (e.g. rulelist:<list name>, keywords, ner-presidio, regex). Stored inside
	// the matches JSON blob, so no schema migration is needed.
	Source      string `json:"source,omitempty"`
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
	IsPreview   bool   `json:"is_preview"`
	Length      int    `json:"length"`
	Truncated   bool   `json:"truncated"`
}

// AuditEvent represents one proxy request's audit record (persisted to SQLite).
type AuditEvent struct {
	ID int64 `json:"id"`

	Time time.Time `json:"time"`

	Host            string `json:"host"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	ContentType     string `json:"content_type"`
	ContentEncoding string `json:"content_encoding,omitempty"`

	Attempted     bool         `json:"attempted"`
	RedactedCount int          `json:"redacted_count"`
	Matches       []AuditMatch `json:"matches"`
	Note          string       `json:"note,omitempty"`

	ResponseStatus      int    `json:"response_status,omitempty"`
	ResponseContentType string `json:"response_content_type,omitempty"`
	RestoreApplied      bool   `json:"restore_applied,omitempty"`
	RestoredCount       int    `json:"restored_count,omitempty"`
}
