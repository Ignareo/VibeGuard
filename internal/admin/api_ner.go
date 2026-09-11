package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/ner"
)

type NERSettings struct {
	Enabled     bool     `json:"enabled"`
	PresidioURL string   `json:"presidio_url"`
	Language    string   `json:"language"`
	Entities    []string `json:"entities"`
	MinScore    float64  `json:"min_score"`
}

type updateNERSettingsRequest struct {
	Enabled     *bool     `json:"enabled"`
	PresidioURL *string   `json:"presidio_url"`
	Language    *string   `json:"language"`
	Entities    *[]string `json:"entities"`
	MinScore    *float64  `json:"min_score"`
}

// handleNER handles GET/POST /manager/api/ner
func (a *Admin) handleNER(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getNERSettings(w, r)
	case http.MethodPost:
		a.updateNERSettings(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getNERSettings(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()
	entities := append([]string(nil), c.Patterns.NER.Entities...)
	if len(entities) == 0 {
		entities = ner.SafeEntityNames()
	}

	resp := NERSettings{
		Enabled:     c.Patterns.NER.Enabled,
		PresidioURL: strings.TrimSpace(c.Patterns.NER.PresidioURL),
		Language:    strings.TrimSpace(c.Patterns.NER.Language),
		Entities:    entities,
		MinScore:    c.Patterns.NER.MinScore,
	}
	if resp.Language == "" {
		resp.Language = "en"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) updateNERSettings(w http.ResponseWriter, r *http.Request) {
	var req updateNERSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil && req.PresidioURL == nil && req.Language == nil && req.Entities == nil && req.MinScore == nil {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	if req.PresidioURL != nil {
		// Allow empty here; if enabled, it must be set (validated below).
	}

	if req.Language != nil {
		lang := config.SanitizeNERLanguage(*req.Language)
		if lang == "" {
			http.Error(w, "Invalid language", http.StatusBadRequest)
			return
		}
	}

	if req.Entities != nil {
		// Allow empty array: means "fall back to the default entity set".
		for _, e := range *req.Entities {
			if config.SanitizeCategory(e) == "" {
				http.Error(w, "Invalid entities", http.StatusBadRequest)
				return
			}
		}
	}

	if req.MinScore != nil {
		if *req.MinScore < 0 || *req.MinScore > 1 {
			http.Error(w, "Invalid min_score", http.StatusBadRequest)
			return
		}
	}

	// When enabled, PresidioURL must be configured.
	{
		c := a.config.Get()
		enabled := c.Patterns.NER.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		urlVal := strings.TrimSpace(c.Patterns.NER.PresidioURL)
		if req.PresidioURL != nil {
			urlVal = strings.TrimSpace(*req.PresidioURL)
		}
		if enabled && urlVal == "" {
			http.Error(w, "presidio_url required when enabled", http.StatusBadRequest)
			return
		}
	}

	if err := a.updateConfig(r, "config.ner.update", func(c *config.Config) {
		if req.Enabled != nil {
			c.Patterns.NER.Enabled = *req.Enabled
		}
		if req.PresidioURL != nil {
			c.Patterns.NER.PresidioURL = strings.TrimSpace(*req.PresidioURL)
		}
		if req.Language != nil {
			lang := config.SanitizeNERLanguage(*req.Language)
			if lang != "" {
				c.Patterns.NER.Language = lang
			}
		}
		if req.Entities != nil {
			out := make([]string, 0, len(*req.Entities))
			for _, e := range *req.Entities {
				v := config.SanitizeCategory(e)
				if v == "" {
					continue
				}
				out = append(out, v)
			}
			c.Patterns.NER.Entities = out
		}
		if req.MinScore != nil {
			c.Patterns.NER.MinScore = *req.MinScore
		}
	}); err != nil {
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}

	a.getNERSettings(w, r)
}
