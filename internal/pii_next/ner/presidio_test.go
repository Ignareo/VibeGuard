package ner

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPresidioOnFailure(t *testing.T) {
	t.Run("非 2xx 触发 status 失败回调", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		var failures atomic.Int64
		var lastKind atomic.Value
		rec, err := New(Options{
			PresidioURL: srv.URL,
			OnFailure: func(kind string) {
				failures.Add(1)
				lastKind.Store(kind)
			},
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		if matches := rec.Recognize([]byte("hello world")); matches != nil {
			t.Fatalf("expected nil matches on 500, got %v", matches)
		}
		if failures.Load() != 1 || lastKind.Load() != "status" {
			t.Fatalf("failures=%d kind=%v", failures.Load(), lastKind.Load())
		}
	})

	t.Run("服务不可达触发 request 失败回调", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close() // now unreachable

		var failures atomic.Int64
		rec, err := New(Options{
			PresidioURL: url,
			OnFailure:   func(kind string) { failures.Add(1) },
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		rec.Recognize([]byte("hello world"))
		if failures.Load() != 1 {
			t.Fatalf("failures=%d", failures.Load())
		}
	})

	t.Run("成功路径不触发失败回调", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"start":0,"end":5,"entity_type":"PERSON","score":0.9}]`))
		}))
		defer srv.Close()

		var failures atomic.Int64
		rec, err := New(Options{
			PresidioURL: srv.URL,
			OnFailure:   func(kind string) { failures.Add(1) },
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		matches := rec.Recognize([]byte("hello world"))
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if failures.Load() != 0 {
			t.Fatalf("unexpected failure callback: %d", failures.Load())
		}
	})

	t.Run("并发超限触发 overloaded 回调", func(t *testing.T) {
		started := make(chan struct{})
		block := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-block
		}))
		defer srv.Close()
		defer close(block)

		var failures atomic.Int64
		kinds := make(chan string, 4)
		rec, err := New(Options{
			PresidioURL:    srv.URL,
			MaxConcurrency: 1,
			OnFailure:      func(kind string) { failures.Add(1); kinds <- kind },
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		done := make(chan struct{})
		go func() { rec.Recognize([]byte("first request blocks")); close(done) }()
		<-started // first request now occupies the only slot

		// Second call must hit the concurrency limit.
		rec.Recognize([]byte("second request"))
		select {
		case kind := <-kinds:
			if kind != "overloaded" {
				t.Fatalf("kind=%q", kind)
			}
		default:
			t.Fatalf("expected overloaded failure callback")
		}
		<-done
	})
}
