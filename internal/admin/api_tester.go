package admin

import (
	"encoding/json"
	"net/http"
	"strings"
)

// TestHit describes one redaction hit produced by the dry-run tester.
type TestHit struct {
	// Category is the placeholder category of the hit.
	Category string `json:"category"`
	// Source is a human-readable identifier of the rule that produced the hit.
	Source string `json:"source,omitempty"`
	// Placeholder is the placeholder token the value was replaced with.
	Placeholder string `json:"placeholder"`
	// Preview is the masked original value (first2…last2); the raw value is never returned.
	Preview string `json:"preview"`
	// Length is the length of the original value.
	Length int `json:"length"`
}

// testHitLimit caps the number of hits returned by POST /manager/api/test.
const testHitLimit = 50

// handleTest handles POST /manager/api/test — a dry-run redaction of user-provided
// text against the currently loaded rules. Nothing is persisted or sent upstream.
func (a *Admin) handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tester := a.getRedactTester()
	if tester == nil {
		http.Error(w, "Redaction test is not available", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		http.Error(w, "Missing text", http.StatusBadRequest)
		return
	}

	redacted, hits := tester(req.Text)
	if len(hits) > testHitLimit {
		hits = hits[:testHitLimit]
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"redacted": redacted,
		"matches":  hits,
	})
}
