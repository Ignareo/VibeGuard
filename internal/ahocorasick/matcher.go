package ahocorasick

import "sort"

// Matcher is an Aho-Corasick automaton for multi-pattern matching over exact string patterns.
//
// Design goals:
// - lightweight: no third-party dependencies
// - byte-oriented: match on UTF-8 byte sequences (works for multilingual text)
// - reusable: read-only after build; safe for concurrent matching
//
// Notes:
//   - pattern order determines match IDs (0..n-1)
//   - this implementation does not perform case/Unicode normalization; callers should normalize patterns as needed
//   - transitions are stored as sorted arrays (binary search) instead of map[byte]int, and the
//     root state uses a 256-entry direct lookup table, since the matching loop spends most of
//     its time at the root on non-matching bytes
type Matcher struct {
	nodes []node
	root  [256]int32 // O(1) root transitions; -1 = no transition
	lens  []int      // pattern byte length by id
}

type node struct {
	keys []byte // sorted transition bytes
	vals []int  // parallel to keys
	fail int
	out  []int // pattern ids that end at this node (includes failure outputs)
}

func (n *node) next(b byte) (int, bool) {
	i := sort.Search(len(n.keys), func(i int) bool { return n.keys[i] >= b })
	if i < len(n.keys) && n.keys[i] == b {
		return n.vals[i], true
	}
	return 0, false
}

// buildNode is the mutable build-time representation (frozen into node afterwards).
type buildNode struct {
	next map[byte]int
	fail int
	out  []int
}

// New builds an automaton from patterns. Empty patterns are ignored.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	m.build(patterns)
	return m
}

func (m *Matcher) build(patterns []string) {
	m.nodes = nil
	m.lens = nil
	for i := range m.root {
		m.root[i] = -1
	}

	if len(patterns) == 0 {
		return
	}

	bnodes := []buildNode{{next: make(map[byte]int)}}
	m.lens = make([]int, len(patterns))

	// 1) build trie
	for id, pat := range patterns {
		if pat == "" {
			continue
		}
		m.lens[id] = len(pat)

		cur := 0
		for i := 0; i < len(pat); i++ {
			b := pat[i]
			nxt, ok := bnodes[cur].next[b]
			if !ok {
				nxt = len(bnodes)
				bnodes[cur].next[b] = nxt
				bnodes = append(bnodes, buildNode{next: make(map[byte]int)})
			}
			cur = nxt
		}
		bnodes[cur].out = append(bnodes[cur].out, id)
	}

	// 2) build failure links (BFS)
	q := make([]int, 0, len(bnodes))
	for _, child := range bnodes[0].next {
		bnodes[child].fail = 0
		q = append(q, child)
	}

	for head := 0; head < len(q); head++ {
		v := q[head]
		for b, u := range bnodes[v].next {
			q = append(q, u)

			f := bnodes[v].fail
			for f != 0 {
				if w, ok := bnodes[f].next[b]; ok {
					bnodes[u].fail = w
					goto linked
				}
				f = bnodes[f].fail
			}

			if w, ok := bnodes[0].next[b]; ok {
				bnodes[u].fail = w
			} else {
				bnodes[u].fail = 0
			}

		linked:
			// Output merge: include failure node outputs so matching does not need to walk the fail chain.
			if f := bnodes[u].fail; f != 0 && len(bnodes[f].out) > 0 {
				bnodes[u].out = append(bnodes[u].out, bnodes[f].out...)
			}
		}
	}

	// 3) freeze into sorted-array transitions + root lookup table
	m.nodes = make([]node, len(bnodes))
	for i := range bnodes {
		bn := &bnodes[i]
		keys := make([]byte, 0, len(bn.next))
		for b := range bn.next {
			keys = append(keys, b)
		}
		sort.Slice(keys, func(a, b int) bool { return keys[a] < keys[b] })
		vals := make([]int, len(keys))
		for j, b := range keys {
			vals[j] = bn.next[b]
		}
		m.nodes[i] = node{keys: keys, vals: vals, fail: bn.fail, out: bn.out}
	}
	for b, child := range bnodes[0].next {
		m.root[b] = int32(child)
	}
}

// PatternCount returns the number of patterns (ID range: 0..PatternCount-1).
func (m *Matcher) PatternCount() int {
	if m == nil {
		return 0
	}
	return len(m.lens)
}

// EachMatch matches over input and calls fn for each hit.
// Returning false from fn stops iteration early.
func (m *Matcher) EachMatch(input []byte, fn func(id, start, end int) bool) {
	if m == nil || len(m.nodes) == 0 || len(input) == 0 || fn == nil {
		return
	}

	state := 0
	for i := 0; i < len(input); i++ {
		b := input[i]

		// Transition; if missing, follow fail links back until root.
		for {
			if state == 0 {
				if n := m.root[b]; n >= 0 {
					state = int(n)
				}
				break
			}
			if nxt, ok := m.nodes[state].next(b); ok {
				state = nxt
				break
			}
			state = m.nodes[state].fail
		}

		if state == 0 || len(m.nodes[state].out) == 0 {
			continue
		}
		end := i + 1
		for _, id := range m.nodes[state].out {
			l := 0
			if id >= 0 && id < len(m.lens) {
				l = m.lens[id]
			}
			if l <= 0 || l > end {
				continue
			}
			start := end - l
			if start < 0 || start >= end {
				continue
			}
			if !fn(id, start, end) {
				return
			}
		}
	}
}

// EachMatchNonOverlappingPerPattern is like EachMatch, but guarantees that hits for the same pattern do not overlap.
//
// This preserves historical behavior: when scanning one keyword at a time via bytes.Index, hits are leftmost-first and non-overlapping.
//
// lastEndScratch avoids frequent allocations; if nil or too short, it is allocated internally.
func (m *Matcher) EachMatchNonOverlappingPerPattern(input []byte, lastEndScratch []int, fn func(id, start, end int) bool) {
	if m == nil || len(m.nodes) == 0 || len(input) == 0 || fn == nil {
		return
	}

	patN := len(m.lens)
	lastEnd := lastEndScratch
	if lastEnd == nil || len(lastEnd) < patN {
		lastEnd = make([]int, patN)
	} else {
		clear(lastEnd[:patN])
	}

	m.EachMatch(input, func(id, start, end int) bool {
		if id < 0 || id >= patN {
			return true
		}
		if start < lastEnd[id] {
			return true
		}
		lastEnd[id] = end
		return fn(id, start, end)
	})
}
