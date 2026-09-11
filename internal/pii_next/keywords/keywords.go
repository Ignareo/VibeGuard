package keywords

import (
	"github.com/inkdust2021/vibeguard/internal/ahocorasick"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/textsafe"
)

// Keyword is an exact substring matching rule.
type Keyword struct {
	Text     string
	Category string
}

type Recognizer struct {
	keywords []Keyword
	priority int

	ac   *ahocorasick.Matcher
	cats []string // pattern id -> category
}

func New(keywords []Keyword) *Recognizer {
	kws := make([]Keyword, 0, len(keywords))
	pats := make([]string, 0, len(keywords))
	cats := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		if kw.Text == "" {
			continue
		}
		// Keywords match case-insensitively on a normalized view of the input
		// (zero-width stripped, NFKC, case folded); fold the patterns the same way.
		pat := textsafe.FoldString(kw.Text, true)
		if pat == "" {
			continue
		}
		kws = append(kws, kw)
		pats = append(pats, pat)
		cats = append(cats, kw.Category)
	}

	return &Recognizer{
		keywords: kws,
		priority: 100, // User-configured keywords should have the highest priority.
		ac:       ahocorasick.New(pats),
		cats:     cats,
	}
}

func (r *Recognizer) Name() string { return "keywords" }

func (r *Recognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || r.ac == nil || len(input) == 0 {
		return nil
	}

	// Rough estimate: each keyword hits ~0-1 times; preallocation reduces growth.
	out := make([]recognizer.Match, 0, min(len(r.cats), 32))

	for _, seg := range textsafe.FoldSegments(input, true) {
		if len(seg.Text) == 0 {
			continue
		}
		r.ac.EachMatchNonOverlappingPerPattern(seg.Text, nil, func(id, start, end int) bool {
			cat := ""
			if id >= 0 && id < len(r.cats) {
				cat = r.cats[id]
			}
			ms, me := seg.MapRange(start, end)
			out = append(out, recognizer.Match{
				Start:    ms,
				End:      me,
				Category: cat,
				Priority: r.priority,
				Source:   r.Name(),
			})
			return true
		})
	}

	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
