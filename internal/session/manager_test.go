package session

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestGetOrCreatePlaceholderConcurrent(t *testing.T) {
	m := NewManager(time.Hour, 1000)
	defer m.Close()

	const goroutines = 32
	results := make([]string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = m.GetOrCreatePlaceholder("shared-secret", "SECRET", "__VG_")
		}(i)
	}
	wg.Wait()

	for i, ph := range results {
		if ph != results[0] {
			t.Fatalf("goroutine %d got %q, want %q", i, ph, results[0])
		}
	}
	if m.Size() != 1 {
		t.Fatalf("expected exactly 1 mapping, got %d", m.Size())
	}
	// Reverse lookup must resolve to the same placeholder.
	if ph, ok := m.LookupReverse("shared-secret"); !ok || ph != results[0] {
		t.Fatalf("LookupReverse = %q, %v; want %q", ph, ok, results[0])
	}
	// Forward lookup restores the original.
	if orig, ok := m.Lookup(results[0]); !ok || orig != "shared-secret" {
		t.Fatalf("Lookup = %q, %v", orig, ok)
	}
}

func TestPlaceholderChecksumAndCategory(t *testing.T) {
	m := NewManager(time.Hour, 1000)
	defer m.Close()

	ph := m.GetOrCreatePlaceholder("some-secret", "CHINA_PHONE", "__VG_")
	if !m.VerifyPlaceholderChecksum(ph) {
		t.Fatalf("generated placeholder should pass checksum verification: %q", ph)
	}
	if got := placeholderCategory(ph); got != "CHINA_PHONE" {
		t.Fatalf("category = %q, want CHINA_PHONE", got)
	}

	// Tamper with one hash character: verification must fail.
	i := len("__VG_CHINA_PHONE_")
	b := []byte(ph)
	if b[i] == 'a' {
		b[i] = 'b'
	} else {
		b[i] = 'a'
	}
	if m.VerifyPlaceholderChecksum(string(b)) {
		t.Fatalf("tampered placeholder should fail verification")
	}
	// Legacy 12-hex tokens cannot be verified.
	if m.VerifyPlaceholderChecksum("__VG_CHINA_PHONE_abcdef123456__") {
		t.Fatalf("legacy 12-hex token should not verify")
	}
	// Collision-suffixed variant verifies too.
	suffixed := ph[:len(ph)-2] + "_2__"
	if !m.VerifyPlaceholderChecksum(suffixed) {
		t.Fatalf("collision-suffixed placeholder should verify: %q", suffixed)
	}
}

func TestGetOrCreatePlaceholderDistinct(t *testing.T) {
	m := NewManager(time.Hour, 1000)
	defer m.Close()

	seen := make(map[string]string)
	for i := 0; i < 100; i++ {
		original := fmt.Sprintf("secret-%d", i)
		ph := m.GetOrCreatePlaceholder(original, "SECRET", "__VG_")
		if prev, ok := seen[ph]; ok && prev != original {
			t.Fatalf("placeholder %q reused for %q and %q", ph, prev, original)
		}
		seen[ph] = original
	}
	if m.Size() != 100 {
		t.Fatalf("expected 100 mappings, got %d", m.Size())
	}
}
