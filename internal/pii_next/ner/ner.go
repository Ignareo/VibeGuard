package ner

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

var (
	ErrMissingPresidioURL = errors.New("missing presidio_url")
	ErrInvalidPresidioURL = errors.New("invalid presidio_url")
)

type Options struct {
	// PresidioURL is the Presidio Analyzer service URL (e.g. http://127.0.0.1:5001).
	PresidioURL string
	// Language is passed to Presidio as the language parameter; "auto" is supported.
	Language string
	// Entities specifies enabled entity types (empty means use the implementation default set).
	Entities []string
	// MinScore is the confidence threshold (0~1; 0 means Presidio default).
	MinScore float64

	// Timeout is the per-request analysis timeout (0 means use the default).
	Timeout time.Duration
	// MaxConcurrency limits concurrency (<=0 means unlimited).
	MaxConcurrency int
	// HTTPClient allows injecting a custom client (testing or advanced use). If nil, a default client is used.
	HTTPClient *http.Client
	// OnFailure is invoked (best-effort, synchronously) when an NER analysis is silently skipped:
	// kind is one of "overloaded" (concurrency limit), "request" (HTTP call failed/timeout),
	// "status" (non-2xx response), "decode" (invalid response body). Nil disables the hook.
	OnFailure func(kind string)
}

// SafeEntityNames returns a default entity set with relatively low false positives.
func SafeEntityNames() []string {
	// Enable three common entity types by default. Finer control is available in the admin UI.
	return []string{"PERSON", "ORG", "LOCATION"}
}

func normalizeLanguage(s string) string {
	s = config.SanitizeNERLanguage(s)
	if s == "" {
		return "auto"
	}
	return s
}

func normalizePresidioAnalyzeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrMissingPresidioURL
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "", ErrInvalidPresidioURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ErrInvalidPresidioURL
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", ErrInvalidPresidioURL
	}
	u.Fragment = ""
	u.RawQuery = ""

	// Allow user input:
	// - http://host:5001
	// - http://host:5001/analyze
	// - http://host:5001/presidio (will append /analyze automatically)
	path := strings.TrimRight(strings.TrimSpace(u.Path), "/")
	if !strings.HasSuffix(path, "/analyze") {
		if path == "" {
			path = "/analyze"
		} else {
			path = path + "/analyze"
		}
	}
	u.Path = path

	return u.String(), nil
}

// New returns an NER Recognizer (the only engine: Presidio Analyzer over HTTP).
func New(opts Options) (recognizer.Recognizer, error) {
	analyzeURL, err := normalizePresidioAnalyzeURL(opts.PresidioURL)
	if err != nil {
		return nil, err
	}
	opts.Language = normalizeLanguage(opts.Language)
	if opts.Timeout <= 0 {
		opts.Timeout = 800 * time.Millisecond
	}
	return newPresidioRecognizer(analyzeURL, opts), nil
}
