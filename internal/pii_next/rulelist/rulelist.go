package rulelist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/ahocorasick"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/textsafe"
)

type keywordRule struct {
	text string
	cat  string
}

// Recognizer loads and executes "rule list" matching.
//
// Rule format (parsed line-by-line; blank/comment lines are ignored):
// - keyword <CATEGORY> <TEXT...>
// - regex   <CATEGORY> <RE2_PATTERN...> [:: <VALIDATOR>]
//
// Comment lines start with #, //, ;, or ! (after trimming leading whitespace).
// CATEGORY is normalized to [A-Z0-9_]; TEXT strips invisible characters and trims whitespace.
// A regex rule may end with `:: <VALIDATOR>` (luhn / china_id / uscc); the validator
// runs on the captured text and failed matches are discarded.
type Recognizer struct {
	name     string
	priority int

	keywords   []keywordRule
	kwAC       *ahocorasick.Matcher
	kwCats     []string
	regex      []*regexp.Regexp
	regexCat   []string
	regexValid []Validator
}

func (r *Recognizer) Name() string {
	if r == nil {
		return "rulelist"
	}
	if strings.TrimSpace(r.name) == "" {
		return "rulelist"
	}
	return "rulelist:" + r.name
}

func (r *Recognizer) KeywordCount() int {
	if r == nil {
		return 0
	}
	return len(r.keywords)
}

func (r *Recognizer) RegexCount() int {
	if r == nil {
		return 0
	}
	return len(r.regex)
}

func (r *Recognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || len(input) == 0 {
		return nil
	}

	var out []recognizer.Match

	if r.kwAC != nil && len(r.kwCats) > 0 {
		// Rough estimate: each keyword hits ~0-1 times; preallocation reduces growth.
		out = make([]recognizer.Match, 0, min(len(r.kwCats), 64))
		// Keywords match case-insensitively on a normalized view (zero-width stripped,
		// NFKC, case folded); patterns were folded the same way at parse time.
		for _, seg := range textsafe.FoldSegments(input, true) {
			if len(seg.Text) == 0 {
				continue
			}
			r.kwAC.EachMatchNonOverlappingPerPattern(seg.Text, nil, func(id, start, end int) bool {
				cat := ""
				if id >= 0 && id < len(r.kwCats) {
					cat = r.kwCats[id]
				}
				if cat == "" {
					return true
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
	} else {
		out = nil
	}

	for i, re := range r.regex {
		if re == nil {
			continue
		}
		var valid Validator
		if i >= 0 && i < len(r.regexValid) {
			valid = r.regexValid[i]
		}
		locs := re.FindAllSubmatchIndex(input, -1)
		for _, loc := range locs {
			if len(loc) < 2 {
				continue
			}
			start, end := loc[0], loc[1]
			// If capture groups exist, prefer the first capture group's range (aligns with redact.Engine semantics).
			if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= 0 {
				start, end = loc[2], loc[3]
			}
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			if valid != nil && !valid(string(input[start:end])) {
				continue
			}
			cat := ""
			if i >= 0 && i < len(r.regexCat) {
				cat = r.regexCat[i]
			}
			if cat == "" {
				cat = "REGEX"
			}
			out = append(out, recognizer.Match{
				Start:    start,
				End:      end,
				Category: cat,
				Priority: r.priority,
				Source:   r.Name(),
			})
		}
	}

	return out
}

type ParseOptions struct {
	// Name is used in the recognizer name (for audit/debug).
	Name string
	// Higher Priority wins (used for overlap resolution with keywords/other rule lists).
	// Note: keyword matches default to priority 100; rule lists are recommended to be in the 10~90 range.
	Priority int
}

func Parse(r io.Reader, opts ParseOptions) (*Recognizer, error) {
	if r == nil {
		return nil, fmt.Errorf("规则列表读取器为空")
	}

	priority := opts.Priority
	if priority <= 0 {
		priority = 50
	}
	if priority > 99 {
		priority = 99
	}

	out := &Recognizer{
		name:     strings.TrimSpace(opts.Name),
		priority: priority,
	}

	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024) // Allow long regex lines.

	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if isCommentLine(s) {
			continue
		}

		kind, rest, ok := cutFirstField(s)
		if !ok {
			return nil, fmt.Errorf("规则列表第 %d 行：无效格式", lineNo)
		}
		kind = strings.ToLower(strings.TrimSpace(kind))
		rest = strings.TrimSpace(rest)

		switch kind {
		case "keyword", "k":
			catToken, value, ok := cutFirstField(rest)
			if !ok {
				return nil, fmt.Errorf("规则列表第 %d 行：keyword 缺少 CATEGORY/TEXT", lineNo)
			}
			cat := config.SanitizeCategory(catToken)
			if cat == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：keyword CATEGORY 非法：%q", lineNo, catToken)
			}
			text := config.SanitizePatternValue(value)
			if text == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：keyword TEXT 为空", lineNo)
			}
			out.keywords = append(out.keywords, keywordRule{text: text, cat: cat})

		case "regex", "r":
			catToken, pattern, ok := cutFirstField(rest)
			if !ok {
				return nil, fmt.Errorf("规则列表第 %d 行：regex 缺少 CATEGORY/PATTERN", lineNo)
			}
			cat := config.SanitizeCategory(catToken)
			if cat == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：regex CATEGORY 非法：%q", lineNo, catToken)
			}
			pat := strings.TrimSpace(pattern)
			if pat == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：regex PATTERN 为空", lineNo)
			}
			var valid Validator
			if idx := strings.LastIndex(pat, " :: "); idx >= 0 {
				name := strings.TrimSpace(pat[idx+4:])
				pat = strings.TrimSpace(pat[:idx])
				if pat == "" {
					return nil, fmt.Errorf("规则列表第 %d 行：regex PATTERN 为空", lineNo)
				}
				v, err := lookupValidator(name)
				if err != nil {
					return nil, fmt.Errorf("规则列表第 %d 行：%w", lineNo, err)
				}
				valid = v
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("规则列表第 %d 行：regex 编译失败：%w", lineNo, err)
			}
			out.regex = append(out.regex, re)
			out.regexCat = append(out.regexCat, cat)
			out.regexValid = append(out.regexValid, valid)

		default:
			return nil, fmt.Errorf("规则列表第 %d 行：未知规则类型：%q", lineNo, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if len(out.keywords) > 0 {
		pats := make([]string, 0, len(out.keywords))
		cats := make([]string, 0, len(out.keywords))
		for _, kw := range out.keywords {
			if kw.text == "" || kw.cat == "" {
				continue
			}
			// Fold keyword patterns the same way Recognize folds the input.
			pat := textsafe.FoldString(kw.text, true)
			if pat == "" {
				continue
			}
			pats = append(pats, pat)
			cats = append(cats, kw.cat)
		}
		out.kwAC = ahocorasick.New(pats)
		out.kwCats = cats
	}

	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ParseFile(path string, opts ParseOptions) (*Recognizer, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, fmt.Errorf("规则列表路径为空")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, opts)
}

func isCommentLine(s string) bool {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "#"):
		return true
	case strings.HasPrefix(s, ";"):
		return true
	case strings.HasPrefix(s, "!"):
		return true
	case strings.HasPrefix(s, "//"):
		return true
	default:
		return false
	}
}

func cutFirstField(s string) (first, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	i := strings.IndexFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
	if i == -1 {
		return s, "", true
	}
	return s[:i], strings.TrimSpace(s[i:]), true
}
