package ner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type presidioRecognizer struct {
	analyzeURL string
	client     *http.Client
	timeout    time.Duration
	sem        chan struct{}
	onFailure  func(kind string)

	language   string
	entities   []string
	allowed    map[string]struct{}
	minScore   float64
	priority   int
	sourceName string
}

type presidioAnalyzeRequest struct {
	Text           string   `json:"text"`
	Language       string   `json:"language,omitempty"`
	Entities       []string `json:"entities,omitempty"`
	ScoreThreshold *float64 `json:"score_threshold,omitempty"`
}

type presidioAnalyzeResponseItem struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	EntityType string  `json:"entity_type"`
	Score      float64 `json:"score"`
}

func newPresidioRecognizer(analyzeURL string, opts Options) *presidioRecognizer {
	entities, allowed := normalizeAndMapEntities(opts.Entities)
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}
	r := &presidioRecognizer{
		analyzeURL: analyzeURL,
		client:     client,
		timeout:    opts.Timeout,
		language:   opts.Language,
		entities:   entities,
		allowed:    allowed,
		minScore:   opts.MinScore,
		priority:   40, // Lower than the default rule-list priority (50) to avoid generic NER overriding explicit rules.
		sourceName: "ner-presidio",
		onFailure:  opts.OnFailure,
	}
	if opts.MaxConcurrency > 0 {
		r.sem = make(chan struct{}, opts.MaxConcurrency)
	}
	return r
}

func (r *presidioRecognizer) Name() string { return r.sourceName }

func (r *presidioRecognizer) fail(kind string) {
	if r != nil && r.onFailure != nil {
		r.onFailure(kind)
	}
}

func (r *presidioRecognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || len(input) == 0 {
		return nil
	}
	if !utf8.Valid(input) {
		return nil
	}

	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		default:
			// Concurrency limit reached: skip to avoid slowing down the proxy hot path.
			r.fail("overloaded")
			return nil
		}
	}

	lang := r.language
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang == "" || lang == "auto" {
		lang = "en"
	}

	req := presidioAnalyzeRequest{
		Text:     string(input),
		Language: lang,
		Entities: r.entities,
	}
	if r.minScore > 0 {
		v := r.minScore
		req.ScoreThreshold = &v
	}

	body, err := json.Marshal(&req)
	if err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.analyzeURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Do not reuse the proxy transport: NER is an optional external component and should not impact the main path.
	resp, err := r.client.Do(httpReq)
	if err != nil {
		r.fail("request")
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		r.fail("status")
		return nil
	}

	var items []presidioAnalyzeResponseItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		r.fail("decode")
		return nil
	}
	if len(items) == 0 {
		return nil
	}

	// Presidio start/end are usually "character indices" (Python string index), while we use UTF-8 byte offsets.
	// Build a runeIndex -> byteOffset mapping, and include a fallback branch in case Presidio returns byte offsets.
	runeStarts := buildRuneStartOffsets(string(input))
	runeCount := len(runeStarts) - 1

	out := make([]recognizer.Match, 0, len(items))
	for _, it := range items {
		if it.Start < 0 || it.End < 0 || it.Start >= it.End {
			continue
		}

		cat := config.SanitizeCategory(it.EntityType)
		if cat == "" {
			continue
		}
		cat = mapPresidioEntityToCategory(cat)
		if r.allowed != nil {
			if _, ok := r.allowed[cat]; !ok {
				continue
			}
		}

		var startByte, endByte int
		switch {
		case it.End <= runeCount:
			// rune offsets
			if it.Start > runeCount {
				continue
			}
			startByte = runeStarts[it.Start]
			endByte = runeStarts[it.End]
		case it.End <= len(input):
			// Fallback: if Presidio returns byte offsets, use them directly.
			startByte = it.Start
			endByte = it.End
		default:
			continue
		}

		if startByte < 0 || endByte < 0 || startByte >= endByte || endByte > len(input) {
			continue
		}

		out = append(out, recognizer.Match{
			Start:    startByte,
			End:      endByte,
			Category: cat,
			Priority: r.priority,
			Source:   r.Name(),
		})
	}
	return out
}

func buildRuneStartOffsets(s string) []int {
	// For empty strings, still return at least one element so runeCount = len(out)-1 is not negative.
	out := make([]int, 0, len(s)+1)
	for i := range s {
		out = append(out, i)
	}
	out = append(out, len(s))
	return out
}

func normalizeAndMapEntities(in []string) (entities []string, allowed map[string]struct{}) {
	list := in
	if len(list) == 0 {
		list = SafeEntityNames()
	}

	// allowed is used for a second filtering pass (especially to prevent Presidio from returning non-NER entities by default).
	allowed = make(map[string]struct{}, len(list)+2)

	seen := make(map[string]struct{}, len(list)+2)
	add := func(raw string) {
		raw = config.SanitizeCategory(raw)
		if raw == "" {
			return
		}
		raw = mapPresidioEntityToCategory(raw)
		allowed[raw] = struct{}{}

		// Request entities: map ORG compatibly for Presidio.
		reqEnt := raw
		if raw == "ORG" {
			reqEnt = "ORGANIZATION"
		}
		if _, ok := seen[reqEnt]; ok {
			return
		}
		seen[reqEnt] = struct{}{}
		entities = append(entities, reqEnt)
	}

	for _, e := range list {
		add(e)
	}
	if len(entities) == 0 {
		// Fallback: avoid empty entities causing Presidio to load a large default recognizer set (unpredictable FP/perf).
		for _, e := range SafeEntityNames() {
			add(e)
		}
	}
	return entities, allowed
}

func mapPresidioEntityToCategory(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "ORGANIZATION", "ORG":
		return "ORG"
	case "GPE", "LOC":
		return "LOCATION"
	default:
		return s
	}
}
