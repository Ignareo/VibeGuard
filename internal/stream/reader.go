package stream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/restore"
)

// SSERestoringReader wraps an io.ReadCloser and restores placeholders in SSE events.
//
// Key point: SSE streaming outputs from OpenAI-compatible APIs often deliver text as incremental "delta" fragments.
// Placeholders may be split across multiple SSE events, so "replace per event" can fail.
// This reader restores placeholders across delta events, while still keeping a whole-event fallback.
type SSERestoringReader struct {
	upstream io.ReadCloser
	restorer *restore.Engine
	buf      bytes.Buffer // accumulated bytes from upstream
	outBuf   bytes.Buffer // restored bytes ready for downstream
	readBuf  []byte       // reusable upstream read buffer

	// pending maps a stream key (chat choice index, Anthropic content block index, or
	// Responses output_index+content_index) to the most recent delta event of that stream.
	// On stream end, buffered placeholder tails are flushed into the pending event of the
	// matching stream.
	pending     map[string]*pendingDeltaEvent
	pendingKeys []string // insertion order, for deterministic flushing
	// restorers holds one cross-chunk text restorer per stream key, so interleaved outputs
	// (e.g. multiple chat.completions choices or Anthropic content blocks) never mix fragments.
	restorers map[string]*textStreamRestorer
}

// NewSSERestoringReader creates a new SSE restoring reader
func NewSSERestoringReader(upstream io.ReadCloser, restorer *restore.Engine) *SSERestoringReader {
	return &SSERestoringReader{
		upstream:  upstream,
		restorer:  restorer,
		readBuf:   make([]byte, 4096),
		pending:   make(map[string]*pendingDeltaEvent),
		restorers: make(map[string]*textStreamRestorer),
	}
}

// Read implements io.Reader
func (r *SSERestoringReader) Read(p []byte) (int, error) {
	for {
		// If we have restored bytes ready, return them
		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		// Read from upstream into internal buffer
		n, err := r.upstream.Read(r.readBuf)
		if n > 0 {
			r.buf.Write(r.readBuf[:n])
		}

		// Process complete SSE events (delimited by \n\n or \r\n\r\n)
		for {
			data := r.buf.Bytes()
			idx, sepLen := findSSEEventDelimiter(data)
			if idx == -1 {
				break // No complete event yet
			}

			// Extract complete event (including delimiter)
			event := r.buf.Next(idx + sepLen)
			r.handleEvent(event)
		}

		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		if err != nil {
			// On EOF/error, flush remaining buffered bytes
			r.flushAllPending(true)
			if r.buf.Len() > 0 {
				remaining := make([]byte, r.buf.Len())
				copy(remaining, r.buf.Bytes())
				r.buf.Reset()

				// Still do one fallback restore for remaining tail bytes at end of stream.
				restored := r.restorer.Restore(remaining)
				r.outBuf.Write(restored)
				if r.outBuf.Len() > 0 {
					return r.outBuf.Read(p)
				}
			}
			return 0, err
		}
	}
}

// Close implements io.Closer
func (r *SSERestoringReader) Close() error {
	return r.upstream.Close()
}

type pendingDeltaEvent struct {
	lineSep  []byte   // "\n" or "\r\n"
	eventSep []byte   // "\n\n" or "\r\n\r\n"
	before   [][]byte // non-data lines before the first data line
	after    [][]byte // non-data lines after data lines
	obj      map[string]any
	fields   []deltaField
}

func (e *pendingDeltaEvent) emit() []byte {
	if e == nil {
		return nil
	}
	b, _ := json.Marshal(e.obj)

	var out bytes.Buffer
	for _, ln := range e.before {
		if len(ln) == 0 {
			continue
		}
		out.Write(ln)
		out.Write(e.lineSep)
	}
	// data may span multiple lines; emit single-line JSON for easier downstream parsing.
	out.Write([]byte("data: "))
	out.Write(b)
	out.Write(e.lineSep)
	for _, ln := range e.after {
		if len(ln) == 0 {
			continue
		}
		out.Write(ln)
		out.Write(e.lineSep)
	}
	out.Write(e.eventSep)
	return out.Bytes()
}

type textStreamRestorer struct {
	eng *restore.Engine
	buf []byte
}

func newTextStreamRestorer(eng *restore.Engine) *textStreamRestorer {
	return &textStreamRestorer{eng: eng}
}

func (t *textStreamRestorer) Feed(fragment string) string {
	if fragment == "" {
		return ""
	}
	t.buf = append(t.buf, fragment...)

	cut := safeEmitCut(t.buf, t.eng)
	if cut <= 0 {
		return ""
	}

	out := t.eng.Restore(t.buf[:cut])
	// Keep the tail (placeholder prefix or incomplete placeholder) and wait for the next fragment.
	t.buf = append(t.buf[:0], t.buf[cut:]...)
	return string(out)
}

func (t *textStreamRestorer) Flush() string {
	if len(t.buf) == 0 {
		return ""
	}
	out := t.eng.Restore(t.buf)
	t.buf = t.buf[:0]
	return string(out)
}

func safeEmitCut(data []byte, eng *restore.Engine) int {
	if len(data) == 0 || eng == nil {
		return len(data)
	}
	prefixFullStr := eng.Prefix()
	if prefixFullStr == "" {
		return len(data)
	}
	prefixFull := []byte(prefixFullStr)
	prefixBareStr := strings.TrimLeft(prefixFullStr, "_")
	prefixBare := []byte(prefixBareStr)
	if len(prefixBare) == 0 {
		prefixBare = prefixFull
	}
	leadingUnderscores := len(prefixFullStr) - len(prefixBareStr)
	if leadingUnderscores < 0 {
		leadingUnderscores = 0
	}

	// 1) Handle "full prefix exists but the placeholder has not fully arrived yet":
	// keep bytes from the last prefix to the end.
	//
	// Important: placeholders may end with "__", and the prefix also starts with "_".
	// Naively keeping a suffix can misread the ending "__" as the start of the next prefix,
	// splitting a complete placeholder and breaking restoration.
	// Prefer detecting whether the last prefix already forms a complete placeholder at EOF; if so, we can emit all bytes.
	lastBare := bytes.LastIndex(data, prefixBare)
	if lastBare != -1 {
		start := lastBare
		// If the bare prefix is preceded by the prefix's leading underscores, rewind to the full prefix
		// to avoid splitting "__" across emissions.
		if leadingUnderscores > 0 && lastBare >= leadingUnderscores {
			all := true
			for i := lastBare - leadingUnderscores; i < lastBare; i++ {
				if data[i] != '_' {
					all = false
					break
				}
			}
			if all {
				start = lastBare - leadingUnderscores
			}
		}

		end, ok := eng.MatchAt(data, start)
		if ok {
			// Note: to handle cases where models drop the trailing "__", the engine allows the "__" suffix to be optional.
			// In streaming scenarios, however, "__" can be split into the next chunk; if we restore too early,
			// the later "__" will remain as plain text (appearing as extra "__" after the restored text).
			//
			// So if the matched placeholder is exactly at the buffer end and this chunk does not include "__",
			// keep it and wait for the next chunk.
			token := data[start:end]
			hasSuffix := bytes.HasSuffix(token, []byte("__"))
			const maxTail = 512

			if end == len(data) {
				if !hasSuffix && len(data)-start <= maxTail {
					return start
				}
				return len(data)
			}

			// end < len(data): there is more data. If the remainder contains only "_" (common when "__" is split),
			// keep it as well.
			if !hasSuffix && len(data)-start <= maxTail {
				rem := data[end:]
				if len(rem) > 0 && len(rem) <= 2 {
					onlyUnderscore := true
					for _, b := range rem {
						if b != '_' {
							onlyUnderscore = false
							break
						}
					}
					if onlyUnderscore {
						return start
					}
				}
			}

			// The trailing placeholder is complete (and there is more data): safe to emit all bytes.
			return len(data)
		}
		if !ok {
			// Max tail length: avoid infinite buffering when "__VG_" appears in normal text.
			const maxTail = 512
			if len(data)-start <= maxTail {
				return start
			}
		}
	}

	// 2) Handle "prefix split at the end": keep the longest suffix (at most len(prefix)-1).
	partial := suffixPrefixLen(data, prefixFull)
	if !bytes.Equal(prefixBare, prefixFull) {
		if p := suffixPrefixLen(data, prefixBare); p > partial {
			partial = p
		}
	}
	cut := len(data) - partial

	if cut < 0 {
		return 0
	}
	if cut > len(data) {
		return len(data)
	}
	return cut
}

func suffixPrefixLen(data, prefix []byte) int {
	if len(data) == 0 || len(prefix) <= 1 {
		return 0
	}
	max := len(prefix) - 1
	if max > len(data) {
		max = len(data)
	}
	for k := max; k > 0; k-- {
		if bytes.HasSuffix(data, prefix[:k]) {
			return k
		}
	}
	return 0
}

func findSSEEventDelimiter(data []byte) (idx int, sepLen int) {
	// Prefer CRLFCRLF if present earlier than LFLF
	idxCRLF := bytes.Index(data, []byte("\r\n\r\n"))
	idxLF := bytes.Index(data, []byte("\n\n"))

	switch {
	case idxCRLF != -1 && (idxLF == -1 || idxCRLF < idxLF):
		return idxCRLF, 4
	case idxLF != -1:
		return idxLF, 2
	default:
		return -1, 0
	}
}

// RestoringReader restores placeholders for arbitrary "continuous byte streams" (supports across chunk boundaries).
//
// Use cases:
//   - Upstream returns application/json but streams via chunked/long connections (non-standard SSE).
//     Reading all before restoring can cause long periods of no downstream output (appears "stuck").
//
// Note: this Reader does not attempt to understand JSON structure; it only does byte-level placeholder matching/restoring.
type RestoringReader struct {
	upstream  io.ReadCloser
	restorer  *restore.Engine
	readBuf   []byte
	outBuf    bytes.Buffer
	textState *textStreamRestorer
	flushed   bool
}

func NewRestoringReader(upstream io.ReadCloser, restorer *restore.Engine) *RestoringReader {
	return &RestoringReader{
		upstream:  upstream,
		restorer:  restorer,
		readBuf:   make([]byte, 4096),
		textState: newTextStreamRestorer(restorer),
	}
}

func (r *RestoringReader) Read(p []byte) (int, error) {
	for {
		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		n, err := r.upstream.Read(r.readBuf)
		if n > 0 {
			// Use the same "safe cut" strategy as SSE to avoid splitting placeholders across reads.
			if r.textState != nil {
				emitted := r.textState.Feed(string(r.readBuf[:n]))
				if emitted != "" {
					r.outBuf.WriteString(emitted)
				}
			} else {
				r.outBuf.Write(r.restorer.Restore(r.readBuf[:n]))
			}
		}

		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		if err != nil {
			// Flush tail (only once).
			if !r.flushed {
				r.flushed = true
				if r.textState != nil {
					if extra := r.textState.Flush(); extra != "" {
						r.outBuf.WriteString(extra)
					}
				}
			}
			if r.outBuf.Len() > 0 {
				return r.outBuf.Read(p)
			}
			return 0, err
		}
	}
}

func (r *RestoringReader) Close() error {
	return r.upstream.Close()
}

func (r *SSERestoringReader) restorerFor(key string) *textStreamRestorer {
	tr, ok := r.restorers[key]
	if !ok {
		tr = newTextStreamRestorer(r.restorer)
		r.restorers[key] = tr
	}
	return tr
}

// flushPendingEvent emits a pending delta event. When final, the buffered placeholder
// tails of the event's streams are restored and appended to their text fields first.
func (r *SSERestoringReader) flushPendingEvent(pe *pendingDeltaEvent, final bool) {
	if pe == nil {
		return
	}
	if final {
		for _, f := range pe.fields {
			if tr, ok := r.restorers[f.key]; ok {
				if extra := tr.Flush(); extra != "" {
					appendByPath(pe.obj, f.path, extra)
				}
			}
		}
	}
	r.outBuf.Write(pe.emit())
	// Drop every key pointing at this event (one event may carry several streams).
	kept := r.pendingKeys[:0]
	for _, k := range r.pendingKeys {
		if r.pending[k] == pe {
			delete(r.pending, k)
			continue
		}
		kept = append(kept, k)
	}
	r.pendingKeys = kept
}

func (r *SSERestoringReader) flushPendingKey(key string, final bool) {
	r.flushPendingEvent(r.pending[key], final)
}

func (r *SSERestoringReader) flushAllPending(final bool) {
	keys := append([]string(nil), r.pendingKeys...)
	for _, k := range keys {
		r.flushPendingKey(k, final)
	}
}

func (r *SSERestoringReader) handleEvent(event []byte) {
	if len(event) == 0 {
		return
	}

	parsed, ok := parseSSEEvent(event)
	if !ok {
		// If parsing fails, do a byte-level fallback restore.
		r.flushAllPending(true)
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// Terminal events like [DONE] / done / completed: flush pending deltas (with tails) first, then emit the terminal event.
	if parsed.isTerminal {
		r.flushAllPending(true)
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// Try parsing data as JSON to check whether this is a delta event.
	obj, fields, isDelta := parseDeltaJSON(parsed)
	if !isDelta {
		// Non-delta protocol event (e.g. Anthropic content_block_stop): flush pending
		// deltas with their restorer tails. Placeholders do not span protocol events in
		// practice, and restoring a block-final placeholder here is better than losing it.
		r.flushAllPending(true)
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// Delta event: emit the previous pending delta of each involved stream first
	// (per-stream FIFO is preserved; cross-stream reordering is harmless because
	// chat.completions / Anthropic / Responses deltas all carry their stream index).
	for _, f := range fields {
		r.flushPendingKey(f.key, false)
	}

	pe := &pendingDeltaEvent{
		lineSep:  parsed.lineSep,
		eventSep: parsed.eventSep,
		before:   parsed.before,
		after:    parsed.after,
		obj:      obj,
	}
	for _, f := range fields {
		text, ok := getByPath(obj, f.path)
		if !ok {
			continue
		}
		emitted := r.restorerFor(f.key).Feed(text)
		setByPath(obj, f.path, emitted)
		pe.fields = append(pe.fields, f)
	}
	if len(pe.fields) == 0 {
		// parseDeltaJSON should guarantee valid paths; if not, fall back to byte-level restore to avoid breaking downstream protocol.
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}
	for _, f := range pe.fields {
		if _, exists := r.pending[f.key]; !exists {
			r.pendingKeys = append(r.pendingKeys, f.key)
		}
		r.pending[f.key] = pe
	}
}

type parsedEvent struct {
	lineSep    []byte
	eventSep   []byte
	before     [][]byte
	after      [][]byte
	eventName  string
	data       []byte
	isTerminal bool
}

func parseSSEEvent(event []byte) (parsedEvent, bool) {
	var p parsedEvent
	if len(event) == 0 {
		return p, false
	}

	// Determine separator style
	p.eventSep = []byte("\n\n")
	p.lineSep = []byte("\n")
	if bytes.HasSuffix(event, []byte("\r\n\r\n")) {
		p.eventSep = []byte("\r\n\r\n")
		p.lineSep = []byte("\r\n")
	}

	body := event
	if len(event) >= len(p.eventSep) && bytes.HasSuffix(event, p.eventSep) {
		body = event[:len(event)-len(p.eventSep)]
	}

	lines := bytes.Split(body, []byte("\n"))
	seenData := false
	var dataLines [][]byte

	for _, raw := range lines {
		if len(raw) == 0 {
			continue
		}
		ln := bytes.TrimSuffix(raw, []byte("\r"))
		if len(ln) == 0 {
			continue
		}

		if bytes.HasPrefix(ln, []byte("event:")) {
			p.eventName = strings.TrimSpace(string(ln[len("event:"):]))
		}

		if bytes.HasPrefix(ln, []byte("data:")) {
			seenData = true
			d := ln[len("data:"):]
			if len(d) > 0 && d[0] == ' ' {
				d = d[1:]
			}
			dataLines = append(dataLines, d)
			continue
		}

		if !seenData {
			p.before = append(p.before, ln)
		} else {
			p.after = append(p.after, ln)
		}
	}

	p.data = bytes.Join(dataLines, []byte("\n"))
	dataTrim := bytes.TrimSpace(p.data)

	// Terminal detection: keep it permissive to avoid losing buffered tail.
	if bytes.Equal(dataTrim, []byte("[DONE]")) {
		p.isTerminal = true
		return p, true
	}
	lowerName := strings.ToLower(p.eventName)
	if strings.Contains(lowerName, "done") || strings.Contains(lowerName, "completed") || strings.Contains(lowerName, "complete") {
		p.isTerminal = true
		return p, true
	}

	return p, true
}

// navigatePath walks obj along path (string map keys and int array indices) and returns
// the value found there.
func navigatePath(obj map[string]any, path []any) (any, bool) {
	var cur any = obj
	for _, seg := range path {
		switch s := seg.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = m[s]
			if !ok {
				return nil, false
			}
		case int:
			arr, ok := cur.([]any)
			if !ok || s < 0 || s >= len(arr) {
				return nil, false
			}
			cur = arr[s]
		default:
			return nil, false
		}
	}
	return cur, true
}

func getByPath(obj map[string]any, path []any) (string, bool) {
	cur, ok := navigatePath(obj, path)
	if !ok {
		return "", false
	}
	s, ok := cur.(string)
	return s, ok
}

func setByPath(obj map[string]any, path []any, text string) bool {
	if obj == nil || len(path) == 0 {
		return false
	}
	parent, ok := navigatePath(obj, path[:len(path)-1])
	if !ok {
		return false
	}
	switch last := path[len(path)-1].(type) {
	case string:
		m, ok := parent.(map[string]any)
		if !ok {
			return false
		}
		m[last] = text
		return true
	case int:
		arr, ok := parent.([]any)
		if !ok || last < 0 || last >= len(arr) {
			return false
		}
		arr[last] = text
		return true
	}
	return false
}

func appendByPath(obj map[string]any, path []any, extra string) bool {
	if extra == "" {
		return true
	}
	cur, ok := getByPath(obj, path)
	if !ok {
		return false
	}
	return setByPath(obj, path, cur+extra)
}

// deltaField identifies a restorable text field inside an SSE delta JSON object: the
// stream key selects the cross-chunk restorer, the path locates the text inside the object.
type deltaField struct {
	key  string
	path []any
}

func parseDeltaJSON(p parsedEvent) (obj map[string]any, fields []deltaField, ok bool) {
	dataTrim := bytes.TrimSpace(p.data)
	if len(dataTrim) == 0 || dataTrim[0] != '{' {
		return nil, nil, false
	}

	if err := json.Unmarshal(dataTrim, &obj); err != nil {
		return nil, nil, false
	}

	// OpenAI chat.completions chunks: {"choices":[{"index":0,"delta":{"content":"..."}}]}.
	// They carry no "delta" marker in the event name or type, so detect them structurally.
	if choices, isArr := obj["choices"].([]any); isArr {
		for i, c := range choices {
			cm, isMap := c.(map[string]any)
			if !isMap {
				continue
			}
			d, isMap := cm["delta"].(map[string]any)
			if !isMap {
				continue
			}
			idx := i
			if v, isNum := cm["index"].(float64); isNum {
				idx = int(v)
			}
			if _, isStr := d["content"].(string); isStr {
				fields = append(fields, deltaField{
					key:  fmt.Sprintf("chat:%d:content", idx),
					path: []any{"choices", i, "delta", "content"},
				})
			}
			if tcs, isArr := d["tool_calls"].([]any); isArr {
				for j, tc := range tcs {
					tcm, isMap := tc.(map[string]any)
					if !isMap {
						continue
					}
					fn, isMap := tcm["function"].(map[string]any)
					if !isMap {
						continue
					}
					if _, isStr := fn["arguments"].(string); !isStr {
						continue
					}
					tcIdx := j
					if v, isNum := tcm["index"].(float64); isNum {
						tcIdx = int(v)
					}
					fields = append(fields, deltaField{
						key:  fmt.Sprintf("chat:%d:tool:%d", idx, tcIdx),
						path: []any{"choices", i, "delta", "tool_calls", j, "function", "arguments"},
					})
				}
			}
		}
		if len(fields) > 0 {
			return obj, fields, true
		}
	}

	// Delta detection for the remaining formats: prefer SSE event name, then fall back to JSON type.
	nameLower := strings.ToLower(p.eventName)
	typLower := ""
	if typ, isStr := obj["type"].(string); isStr {
		typLower = strings.ToLower(typ)
	}
	if !strings.Contains(nameLower, "delta") && !strings.Contains(typLower, "delta") {
		return nil, nil, false
	}

	// Responses API: {"type":"response.output_text.delta","delta":"...","output_index":0,"content_index":0}
	if _, isStr := obj["delta"].(string); isStr {
		key := "delta"
		if oi, isNum := obj["output_index"].(float64); isNum {
			ci := 0
			if v, isNum := obj["content_index"].(float64); isNum {
				ci = int(v)
			}
			key = fmt.Sprintf("resp:%d:%d", int(oi), ci)
		}
		return obj, []deltaField{{key: key, path: []any{"delta"}}}, true
	}

	// Anthropic content_block_delta: {"index":0,"delta":{"type":"text_delta","text":"..."}} or
	// {"index":1,"delta":{"type":"input_json_delta","partial_json":"..."}} (streamed tool input).
	if m, isMap := obj["delta"].(map[string]any); isMap {
		idx := 0
		if v, isNum := obj["index"].(float64); isNum {
			idx = int(v)
		}
		if _, isStr := m["text"].(string); isStr {
			fields = append(fields, deltaField{
				key:  fmt.Sprintf("anth:%d:text", idx),
				path: []any{"delta", "text"},
			})
		}
		if _, isStr := m["partial_json"].(string); isStr {
			fields = append(fields, deltaField{
				key:  fmt.Sprintf("anth:%d:json", idx),
				path: []any{"delta", "partial_json"},
			})
		}
		if len(fields) > 0 {
			return obj, fields, true
		}
	}

	// Unrecognized: do not write delta maps back as strings, or the protocol structure would be corrupted.
	return nil, nil, false
}
