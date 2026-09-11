package ahocorasick

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

type hit struct {
	id         int
	start, end int
}

func collect(m *Matcher, input string) []hit {
	var out []hit
	m.EachMatch([]byte(input), func(id, start, end int) bool {
		out = append(out, hit{id, start, end})
		return true
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].start != out[j].start {
			return out[i].start < out[j].start
		}
		if out[i].end != out[j].end {
			return out[i].end < out[j].end
		}
		return out[i].id < out[j].id
	})
	return out
}

func TestMatcherClassicOverlaps(t *testing.T) {
	pats := []string{"he", "she", "his", "hers"}
	m := New(pats)
	got := collect(m, "ushers")
	// Expect: she@[1,4), he@[2,4), hers@[2,6)
	var wantSubs []string
	for _, h := range got {
		wantSubs = append(wantSubs, fmt.Sprintf("%s@%d", pats[h.id], h.start))
	}
	joined := strings.Join(wantSubs, ",")
	for _, want := range []string{"she@1", "he@2", "hers@2"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 hits, got %v", wantSubs)
	}
}

func TestMatcherUTF8AndEmpty(t *testing.T) {
	m := New([]string{"", "密码", "key"})
	got := collect(m, "这里有密码和key")
	found := map[string]bool{}
	for _, h := range got {
		found[string([]byte("这里有密码和key")[h.start:h.end])] = true
	}
	if !found["密码"] || !found["key"] || len(found) != 2 {
		t.Fatalf("unexpected hits: %v", found)
	}
	if m.PatternCount() != 3 {
		t.Fatalf("PatternCount = %d", m.PatternCount())
	}
}

func TestMatcherNonOverlappingPerPattern(t *testing.T) {
	m := New([]string{"aa"})
	var out []hit
	m.EachMatchNonOverlappingPerPattern([]byte("aaaa"), nil, func(id, start, end int) bool {
		out = append(out, hit{id, start, end})
		return true
	})
	// Leftmost-first, non-overlapping: [0,2) and [2,4).
	if len(out) != 2 || out[0].start != 0 || out[1].start != 2 {
		t.Fatalf("unexpected hits: %v", out)
	}
}

func TestMatcherNilAndEmpty(t *testing.T) {
	var nilM *Matcher
	nilM.EachMatch([]byte("x"), func(id, start, end int) bool {
		t.Fatalf("nil matcher must not emit hits")
		return true
	})
	if nilM.PatternCount() != 0 {
		t.Fatalf("nil PatternCount != 0")
	}
	empty := New(nil)
	empty.EachMatch([]byte("x"), func(id, start, end int) bool {
		t.Fatalf("empty matcher must not emit hits")
		return true
	})
}

func TestMatcherEarlyStop(t *testing.T) {
	m := New([]string{"a"})
	count := 0
	m.EachMatch([]byte("aaaa"), func(id, start, end int) bool {
		count++
		return false
	})
	if count != 1 {
		t.Fatalf("early stop failed, count=%d", count)
	}
}

func BenchmarkMatcherRootHeavy(b *testing.B) {
	pats := []string{"secret-token-1", "password-value", "api-key-12345", "密码"}
	m := New(pats)
	input := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 100))
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.EachMatch(input, func(id, start, end int) bool { return true })
	}
}
