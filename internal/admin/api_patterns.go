package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// PatternsResponse represents the patterns API response
type PatternsResponse struct {
	Keywords    []config.KeywordPattern   `json:"keywords"`
	Exclude     []string                  `json:"exclude"`
	SecretFiles []config.SecretFileConfig `json:"secret_files"`
}

// handlePatterns handles GET/POST /manager/api/patterns
func (a *Admin) handlePatterns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getPatterns(w, r)
	case http.MethodPost:
		a.addPattern(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePatternsItem handles DELETE /manager/api/patterns/{type}/{index}
func (a *Admin) handlePatternsItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/manager/api/patterns/")
	parts := strings.Split(path, "/")

	if len(parts) != 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	patternType := parts[0]
	index, err := strconv.Atoi(parts[1])
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	if err := a.updateConfig(r, "config.patterns.delete", func(c *config.Config) {
		switch patternType {
		case "keywords":
			if index >= 0 && index < len(c.Patterns.Keywords) {
				c.Patterns.Keywords = append(c.Patterns.Keywords[:index], c.Patterns.Keywords[index+1:]...)
			}
		case "exclude":
			if index >= 0 && index < len(c.Patterns.Exclude) {
				c.Patterns.Exclude = append(c.Patterns.Exclude[:index], c.Patterns.Exclude[index+1:]...)
			}
		case "secret_files":
			if index >= 0 && index < len(c.Patterns.SecretFiles) {
				c.Patterns.SecretFiles = append(c.Patterns.SecretFiles[:index], c.Patterns.SecretFiles[index+1:]...)
			}
		}
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) getPatterns(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()

	keywords := make([]config.KeywordPattern, 0, len(c.Patterns.Keywords))
	for _, kw := range c.Patterns.Keywords {
		v := config.SanitizePatternValue(kw.Value)
		if v == "" {
			continue
		}
		cat := config.SanitizeCategory(kw.Category)
		if cat == "" {
			cat = "TEXT"
		}
		keywords = append(keywords, config.KeywordPattern{Value: v, Category: cat})
	}
	exclude := make([]string, 0, len(c.Patterns.Exclude))
	for _, ex := range c.Patterns.Exclude {
		v := config.SanitizePatternValue(ex)
		if v == "" {
			continue
		}
		exclude = append(exclude, v)
	}

	secretFiles := make([]config.SecretFileConfig, 0, len(c.Patterns.SecretFiles))
	for _, sf := range c.Patterns.SecretFiles {
		path := config.SanitizePatternValue(sf.Path)
		if path == "" {
			continue
		}
		format := strings.ToLower(strings.TrimSpace(sf.Format))
		if format == "" {
			format = "dotenv"
		}
		cat := config.SanitizeCategory(sf.Category)
		if cat == "" {
			if format == "lines" {
				cat = "SECRET_FILE"
			} else {
				cat = "DOTENV"
			}
		}
		minLen := sf.MinValueLen
		if minLen <= 0 {
			minLen = 8
		}
		if minLen > 1024 {
			minLen = 1024
		}
		enabled := true
		if sf.Enabled != nil {
			enabled = *sf.Enabled
		}
		secretFiles = append(secretFiles, config.SecretFileConfig{
			Path:        path,
			Format:      format,
			Category:    cat,
			MinValueLen: minLen,
			Enabled:     &enabled,
		})
	}

	resp := PatternsResponse{
		Keywords:    keywords,
		Exclude:     exclude,
		SecretFiles: secretFiles,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (a *Admin) addPattern(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type        string `json:"type"`
		Value       string `json:"value"`
		Category    string `json:"category"`
		Pattern     string `json:"pattern"`
		Path        string `json:"path"`
		Format      string `json:"format"`
		MinValueLen int    `json:"min_value_len"`
		Enabled     *bool  `json:"enabled"`
		Index       *int   `json:"index"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Basic validation: reject invalid rules before writing config to reduce "added successfully but not effective" confusion.
	switch req.Type {
	case "keyword":
		if config.SanitizePatternValue(req.Value) == "" {
			http.Error(w, "Keyword value is required", http.StatusBadRequest)
			return
		}
	case "secret_file":
		if config.SanitizePatternValue(req.Path) == "" {
			http.Error(w, "Secret file path is required", http.StatusBadRequest)
			return
		}
		f := strings.ToLower(strings.TrimSpace(req.Format))
		if f == "" {
			f = "dotenv"
		}
		if f != "dotenv" && f != "lines" {
			http.Error(w, "Invalid secret file format", http.StatusBadRequest)
			return
		}
	case "secret_file_update":
		if req.Index == nil || *req.Index < 0 {
			http.Error(w, "Index is required", http.StatusBadRequest)
			return
		}
		f := strings.ToLower(strings.TrimSpace(req.Format))
		if f != "" && f != "dotenv" && f != "lines" {
			http.Error(w, "Invalid secret file format", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Invalid pattern type", http.StatusBadRequest)
		return
	}

	if err := a.updateConfig(r, "config.patterns.add", func(c *config.Config) {
		switch req.Type {
		case "keyword":
			// Strip invisible characters to avoid "looks added but doesn't match" surprises.
			val := config.SanitizePatternValue(req.Value)
			if val == "" {
				return
			}
			cat := config.SanitizeCategory(req.Category)
			if cat == "" {
				cat = "TEXT"
			}
			c.Patterns.Keywords = append(c.Patterns.Keywords, config.KeywordPattern{
				Value:    val,
				Category: cat,
			})
		case "secret_file":
			path := config.SanitizePatternValue(req.Path)
			if path == "" {
				return
			}
			format := strings.ToLower(strings.TrimSpace(req.Format))
			if format == "" {
				format = "dotenv"
			}
			if format != "dotenv" && format != "lines" {
				return
			}
			cat := config.SanitizeCategory(req.Category)
			if cat == "" {
				if format == "lines" {
					cat = "SECRET_FILE"
				} else {
					cat = "DOTENV"
				}
			}
			minLen := req.MinValueLen
			if minLen <= 0 {
				minLen = 8
			}
			if minLen > 1024 {
				minLen = 1024
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			c.Patterns.SecretFiles = append(c.Patterns.SecretFiles, config.SecretFileConfig{
				Path:        path,
				Format:      format,
				Category:    cat,
				MinValueLen: minLen,
				Enabled:     &enabled,
			})
		case "secret_file_update":
			if req.Index == nil {
				return
			}
			i := *req.Index
			if i < 0 || i >= len(c.Patterns.SecretFiles) {
				return
			}
			prev := c.Patterns.SecretFiles[i]
			path := config.SanitizePatternValue(req.Path)
			if path == "" {
				path = config.SanitizePatternValue(prev.Path)
			}
			format := strings.ToLower(strings.TrimSpace(req.Format))
			if format == "" {
				format = strings.ToLower(strings.TrimSpace(prev.Format))
			}
			if format == "" {
				format = "dotenv"
			}
			if format != "dotenv" && format != "lines" {
				format = "dotenv"
			}
			cat := config.SanitizeCategory(req.Category)
			if cat == "" {
				cat = config.SanitizeCategory(prev.Category)
			}
			if cat == "" {
				if format == "lines" {
					cat = "SECRET_FILE"
				} else {
					cat = "DOTENV"
				}
			}
			minLen := req.MinValueLen
			if minLen <= 0 {
				minLen = prev.MinValueLen
			}
			if minLen <= 0 {
				minLen = 8
			}
			if minLen > 1024 {
				minLen = 1024
			}
			enabled := true
			if prev.Enabled != nil {
				enabled = *prev.Enabled
			}
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			c.Patterns.SecretFiles[i] = config.SecretFileConfig{
				Path:        path,
				Format:      format,
				Category:    cat,
				MinValueLen: minLen,
				Enabled:     &enabled,
			}
		}
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "created",
		"message": "Pattern added",
	})
}
