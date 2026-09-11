package textsafe

import (
	"sort"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// foldCaseFolder folds case for case-insensitive keyword matching.
var foldCaseFolder = cases.Fold()

// FoldedSegment is a normalized view of one redactable span of the input, with a mapping
// back to original byte offsets.
//
// Normalization applied to the segment text:
//   - zero-width / format characters (unicode.Cf) are removed, so inserting a U+200B into
//     a keyword no longer evades matching
//   - the remaining text is NFKC-normalized (full-width digits/letters become ASCII, ...)
//   - optionally case-folded (for case-insensitive keyword matching)
//
// Control characters and ANSI escape sequences remain hard boundaries (they split
// segments, exactly like RedactableSpans), so matches never span them.
type FoldedSegment struct {
	// Text is the normalized segment text; match against this.
	Text []byte

	// base is the original byte offset where this segment starts.
	base int
	// Mapping tables; nil when Text is identical to the original segment bytes (fast path:
	// offsets map 1:1 via base).
	runeOff  []int // byte offset in Text where folded rune i starts
	origFrom []int // original byte offset where the source rune of folded rune i starts
	origTo   []int // original byte offset where the source rune of folded rune i ends
}

// MapRange maps a folded byte range [start, end) in Text back to the original input byte
// range (absolute offsets). The original range always covers the full original runes that
// produced the matched folded runes (including any removed zero-width characters inside).
func (s FoldedSegment) MapRange(start, end int) (int, int) {
	if s.runeOff == nil {
		return s.base + start, s.base + end
	}
	if start < 0 {
		start = 0
	}
	if end > len(s.Text) {
		end = len(s.Text)
	}
	if start >= end {
		i := foldedRuneAt(s.runeOff, start)
		return s.origFrom[i], s.origFrom[i]
	}
	i := foldedRuneAt(s.runeOff, start)
	j := foldedRuneAt(s.runeOff, end-1)
	return s.origFrom[i], s.origTo[j]
}

// foldedRuneAt returns the index of the folded rune containing byte offset x
// (runeOff is sorted and runeOff[0] == 0).
func foldedRuneAt(runeOff []int, x int) int {
	i := sort.Search(len(runeOff), func(i int) bool { return runeOff[i] > x }) - 1
	if i < 0 {
		return 0
	}
	return i
}

// FoldSegments splits input at hard boundaries (control characters, ANSI escape sequences;
// the same boundaries as RedactableSpans minus zero-width/format characters) and returns
// each segment in normalized form for matching.
func FoldSegments(input []byte, caseFold bool) []FoldedSegment {
	if len(input) == 0 {
		return nil
	}

	var out []FoldedSegment
	segStart := -1
	flush := func(end int) {
		if segStart >= 0 && segStart < end {
			out = append(out, foldSegment(input, segStart, end, caseFold))
		}
		segStart = -1
	}

	for i := 0; i < len(input); {
		if n := hardBoundaryLen(input[i:]); n > 0 {
			flush(i)
			i += n
			continue
		}
		if segStart < 0 {
			segStart = i
		}
		_, size := utf8.DecodeRune(input[i:])
		if size <= 0 {
			size = 1
		}
		i += size
	}
	flush(len(input))

	return out
}

// FoldString normalizes a match pattern the same way FoldSegments normalizes text, so
// case-folded keyword matching compares like with like.
func FoldString(s string, caseFold bool) string {
	if s == "" {
		return ""
	}
	if !caseFold {
		if isASCII(s) {
			return s
		}
	} else if isLowerASCII(s) {
		return s
	}

	var buf []byte
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		buf = append(buf, foldRune(r, caseFold)...)
	}
	return string(buf)
}

// hardBoundaryLen mirrors protectedSeqLen but does NOT treat zero-width/format (Cf)
// characters as boundaries: they are dropped during folding so matches can span them.
func hardBoundaryLen(input []byte) int {
	if len(input) == 0 {
		return 0
	}

	if n := ansiEscapeSeqLen(input); n > 0 {
		return n
	}

	r, size := utf8.DecodeRune(input)
	if r == utf8.RuneError && size == 1 {
		if isASCIITextByte(input[0]) {
			return 0
		}
		return 1
	}

	switch r {
	case '\n', '\r', '\t':
		return 0
	}
	if r < 0x20 || r == 0x7f {
		return size
	}
	if unicode.Is(unicode.Cc, r) {
		return size
	}
	return 0
}

func foldSegment(input []byte, start, end int, caseFold bool) FoldedSegment {
	raw := input[start:end]

	// Fast path: pure-ASCII segments have no zero-width characters and are NFKC-stable;
	// with case folding, an ASCII segment without uppercase letters is identity, and one
	// with uppercase letters folds 1:1 (same length, same offsets).
	if isASCIIBytes(raw) {
		if !caseFold || !hasUpperASCII(raw) {
			return FoldedSegment{Text: raw, base: start}
		}
		folded := make([]byte, len(raw))
		for i, b := range raw {
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			folded[i] = b
		}
		return FoldedSegment{Text: folded, base: start}
	}

	var (
		buf      []byte
		runeOff  []int
		origFrom []int
		origTo   []int
	)
	identity := true
	for i := start; i < end; {
		r, size := utf8.DecodeRune(input[i:end])
		if r == utf8.RuneError && size == 1 {
			// Invalid byte: pass through unchanged so offsets stay meaningful.
			runeOff = append(runeOff, len(buf))
			buf = append(buf, input[i])
			origFrom = append(origFrom, i)
			origTo = append(origTo, i+1)
			i++
			continue
		}
		next := i + size

		if unicode.Is(unicode.Cf, r) {
			identity = false
			i = next
			continue
		}

		folded := foldRune(r, caseFold)
		if folded != string(input[i:next]) {
			identity = false
		}
		for _, fr := range folded {
			runeOff = append(runeOff, len(buf))
			buf = append(buf, string(fr)...)
			origFrom = append(origFrom, i)
			origTo = append(origTo, next)
		}
		i = next
	}

	if identity {
		return FoldedSegment{Text: raw, base: start}
	}
	return FoldedSegment{
		Text:     buf,
		base:     start,
		runeOff:  runeOff,
		origFrom: origFrom,
		origTo:   origTo,
	}
}

// foldRune returns the normalized form of a single rune: NFKC, then optional case fold.
// Per-rune normalization keeps the offset mapping exact; cross-rune composition is
// intentionally skipped (evasion resistance, not linguistics).
func foldRune(r rune, caseFold bool) string {
	if r < 0x80 {
		if caseFold && r >= 'A' && r <= 'Z' {
			return string(r + ('a' - 'A'))
		}
		return string(r)
	}
	s := norm.NFKC.String(string(r))
	if caseFold {
		s = foldCaseFolder.String(s)
	}
	return s
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isASCIIBytes(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func isLowerASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 || (s[i] >= 'A' && s[i] <= 'Z') {
			return false
		}
	}
	return true
}

func hasUpperASCII(b []byte) bool {
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}
