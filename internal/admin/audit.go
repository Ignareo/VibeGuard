package admin

import (
	"sync"
	"time"
)

// AuditMatch represents a sensitive fragment hit in a request (for admin UI display).
type AuditMatch struct {
	Category string `json:"category"`
	// Source is a human-readable identifier of the rule that produced the hit
	// (e.g. rulelist:<list name>, keywords, ner-presidio, regex).
	Source      string `json:"source,omitempty"`
	Placeholder string `json:"placeholder"`
	// Value is the "display value": when privacy mode is enabled it is a preview (masked/truncated),
	// otherwise it is the original (still truncated).
	Value string `json:"value"`
	// IsPreview indicates whether Value is a preview (true in privacy mode).
	IsPreview bool `json:"is_preview"`
	// Length is the length of the original hit (before truncation), useful for validating expected matches.
	Length int `json:"length"`
	// Truncated indicates whether Value was truncated due to length.
	Truncated bool `json:"truncated"`
}

// AuditEvent represents an audit record for a proxy request (used to visualize whether redaction rules were hit).
type AuditEvent struct {
	ID int64 `json:"id"`
	// Time is the server time (RFC3339) for sorting and debugging.
	Time time.Time `json:"time"`

	Host        string `json:"host"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	// ContentEncoding is the request body's Content-Encoding (empty means uncompressed/unknown).
	ContentEncoding string `json:"content_encoding,omitempty"`

	// Attempted indicates whether this request entered the "redactable text body" scanning flow.
	Attempted bool `json:"attempted"`
	// RedactedCount is the number of replacements performed (matches may be truncated for display, but the count is accurate).
	RedactedCount int          `json:"redacted_count"`
	Matches       []AuditMatch `json:"matches"`

	// Note explains why scanning was skipped (e.g. no_body / not_text / too_large / read_error).
	Note string `json:"note,omitempty"`

	// ResponseStatus is the upstream response status code (0 if no response).
	ResponseStatus int `json:"response_status,omitempty"`
	// ResponseContentType is the upstream response Content-Type (empty means unknown/no response).
	ResponseContentType string `json:"response_content_type,omitempty"`
	// RestoreApplied indicates whether placeholder restore was attempted on the response side (text responses like JSON/SSE).
	RestoreApplied bool `json:"restore_applied,omitempty"`
	// RestoredCount is the number of placeholders restored in the response (rough count: matched placeholder tokens).
	RestoredCount int `json:"restored_count,omitempty"`
}

type AuditStore struct {
	mu     sync.RWMutex
	max    int
	nextID int64
	events []AuditEvent

	subNext int
	subs    map[int]chan AuditEvent
}

func NewAuditStore(max int) *AuditStore {
	if max <= 0 {
		max = 200
	}
	return &AuditStore{
		max:  max,
		subs: make(map[int]chan AuditEvent),
	}
}

func (s *AuditStore) Add(ev AuditEvent) AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	ev.ID = s.nextID
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}

	s.events = append(s.events, ev)
	if len(s.events) > s.max {
		// Drop the oldest records.
		s.events = append([]AuditEvent(nil), s.events[len(s.events)-s.max:]...)
	}

	for _, ch := range s.subs {
		select {
		case ch <- ev:
		default:
			// Slow clients: drop to avoid blocking the proxy goroutine.
		}
	}

	return ev
}

// BumpNextID raises nextID to at least min (never decreases).
// Used after enabling persistence so in-memory IDs continue from the persisted max ID, avoiding conflicts.
func (s *AuditStore) BumpNextID(min int64) {
	if s == nil {
		return
	}
	if min <= 0 {
		return
	}
	s.mu.Lock()
	if min > s.nextID {
		s.nextID = min
	}
	s.mu.Unlock()
}

// Update finds an event by ID and mutates it in-place.
// If updated, the updated event will be broadcast to subscribers (as an "audit_event" again),
// allowing the UI to merge by ID.
func (s *AuditStore) Update(id int64, fn func(*AuditEvent)) (AuditEvent, bool) {
	if id <= 0 || fn == nil {
		return AuditEvent{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.events {
		if s.events[i].ID != id {
			continue
		}
		fn(&s.events[i])
		updated := s.events[i]

		for _, ch := range s.subs {
			select {
			case ch <- updated:
			default:
			}
		}

		return updated, true
	}
	return AuditEvent{}, false
}

func (s *AuditStore) List(limit int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}
	if limit == 0 {
		return nil
	}
	out := make([]AuditEvent, limit)
	copy(out, s.events[len(s.events)-limit:])
	return out
}

func (s *AuditStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

func (s *AuditStore) Subscribe(buf int) (ch <-chan AuditEvent, cancel func()) {
	if buf <= 0 {
		buf = 32
	}
	c := make(chan AuditEvent, buf)

	s.mu.Lock()
	id := s.subNext
	s.subNext++
	s.subs[id] = c
	s.mu.Unlock()

	return c, func() {
		s.mu.Lock()
		if ch2, ok := s.subs[id]; ok {
			delete(s.subs, id)
			close(ch2)
		}
		s.mu.Unlock()
	}
}
