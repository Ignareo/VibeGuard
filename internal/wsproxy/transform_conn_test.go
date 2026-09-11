package wsproxy

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestTransformConnWrite_RedactsMaskedTextFrame(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")

	clientSide, upstreamSide := io.Pipe()
	defer upstreamSide.Close()

	conn := NewTransformConn(pipeReadWriteCloser{Reader: bytes.NewReader(nil), Writer: upstreamSide, closer: io.NopCloser(bytes.NewReader(nil))}, eng, restore.NewEngine(sess, "__VG_"))

	raw, err := buildFrame(true, wsOpcodeText, true, []byte("hello Alice"))
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}

	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(clientSide)
		done <- buf
	}()

	if n, err := conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}
	_ = upstreamSide.Close()

	out := <-done
	frame, ok, err := parseFrame(out)
	if err != nil || !ok {
		t.Fatalf("parse output frame failed: ok=%v err=%v", ok, err)
	}
	if bytes.Contains(frame.payload, []byte("Alice")) {
		t.Fatalf("expected Alice to be redacted, got %q", frame.payload)
	}
	if !strings.Contains(string(frame.payload), "__VG_NAME_") {
		t.Fatalf("expected placeholder in payload, got %q", frame.payload)
	}
}

func TestTransformConnRead_RestoresTextFrame(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")
	redacted, _ := eng.RedactWithMatches([]byte("hello Alice"))

	serverFrame, err := buildFrame(true, wsOpcodeText, false, redacted)
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(serverFrame),
		Writer: io.Discard,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read failed: %v", err)
	}

	frame, ok, err := parseFrame(buf[:n])
	if err != nil || !ok {
		t.Fatalf("parse restored frame failed: ok=%v err=%v", ok, err)
	}
	if string(frame.payload) != "hello Alice" {
		t.Fatalf("expected restored payload, got %q", frame.payload)
	}
}

func TestTransformConnWrite_RedactsJSONPromptOnly(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")

	clientSide, upstreamSide := io.Pipe()
	defer upstreamSide.Close()

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(nil),
		Writer: upstreamSide,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	payload := []byte(`{"type":"response.create","metadata":{"note":"Alice"},"input":[{"role":"user","content":[{"type":"input_text","text":"hello Alice"}]}]}`)
	raw, err := buildFrame(true, wsOpcodeText, true, payload)
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}

	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(clientSide)
		done <- buf
	}()

	if n, err := conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}
	_ = upstreamSide.Close()

	out := <-done
	frame, ok, err := parseFrame(out)
	if err != nil || !ok {
		t.Fatalf("parse output frame failed: ok=%v err=%v", ok, err)
	}

	var body map[string]any
	if err := json.Unmarshal(frame.payload, &body); err != nil {
		t.Fatalf("unmarshal output payload: %v", err)
	}

	if got := body["type"]; got != "response.create" {
		t.Fatalf("expected type to stay unchanged, got %#v", got)
	}

	metadata, _ := body["metadata"].(map[string]any)
	if got := metadata["note"]; got != "Alice" {
		t.Fatalf("expected metadata.note to remain unchanged, got %#v", got)
	}

	input, _ := body["input"].([]any)
	msg, _ := input[0].(map[string]any)
	content, _ := msg["content"].([]any)
	part, _ := content[0].(map[string]any)
	text, _ := part["text"].(string)
	if !strings.Contains(text, "__VG_NAME_") {
		t.Fatalf("expected prompt text to contain placeholder, got %q", text)
	}
}

type pipeReadWriteCloser struct {
	io.Reader
	io.Writer
	closer io.Closer
}

func (p pipeReadWriteCloser) Close() error {
	if p.closer == nil {
		return nil
	}
	return p.closer.Close()
}

func compressMessage(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flate flush: %v", err)
	}
	_ = w.Close()
	out := buf.Bytes()
	if len(out) < 4 {
		t.Fatalf("compressed payload too short: %d", len(out))
	}
	// permessage-deflate strips the trailing 0x00 0x00 0xff 0xff sync marker.
	return out[:len(out)-4]
}

func buildRSV1Frame(t *testing.T, masked bool, payload []byte) []byte {
	t.Helper()
	raw, err := buildFrame(true, wsOpcodeText, masked, payload)
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}
	raw[0] |= 0x40 // RSV1
	return raw
}

func TestTransformConnWrite_InflatesAndRedactsCompressedTextFrame(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")

	clientSide, upstreamSide := io.Pipe()
	defer upstreamSide.Close()

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(nil),
		Writer: upstreamSide,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	raw := buildRSV1Frame(t, true, compressMessage(t, []byte("hello Alice")))

	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(clientSide)
		done <- buf
	}()

	if n, err := conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}
	_ = upstreamSide.Close()

	out := <-done
	frame, ok, err := parseFrame(out)
	if err != nil || !ok {
		t.Fatalf("parse output frame failed: ok=%v err=%v", ok, err)
	}
	if frame.rsv != 0 {
		t.Fatalf("expected forwarded frame to be uncompressed (rsv=%#x)", frame.rsv)
	}
	if bytes.Contains(frame.payload, []byte("Alice")) {
		t.Fatalf("expected Alice to be redacted, got %q", frame.payload)
	}
	if !strings.Contains(string(frame.payload), "__VG_NAME_") {
		t.Fatalf("expected placeholder in payload, got %q", frame.payload)
	}
}

func TestTransformConnRead_RestoresPlaceholderSplitAcrossMessages(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")
	redacted, _ := eng.RedactWithMatches([]byte("hello Alice"))
	if !bytes.Contains(redacted, []byte("__VG_NAME_")) {
		t.Fatalf("expected placeholder in redacted text, got %q", redacted)
	}

	// Split inside the placeholder so no single message contains it whole.
	idx := bytes.Index(redacted, []byte("__VG_NAME_")) + len("__VG_NAME_") + 2
	msg1 := redacted[:idx]
	msg2 := redacted[idx:]

	f1, err := buildFrame(true, wsOpcodeText, false, msg1)
	if err != nil {
		t.Fatalf("build frame 1: %v", err)
	}
	f2, err := buildFrame(true, wsOpcodeText, false, msg2)
	if err != nil {
		t.Fatalf("build frame 2: %v", err)
	}

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(append(f1, f2...)),
		Writer: io.Discard,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	var restored []byte
	for len(got) > 0 {
		frame, ok, err := parseFrame(got)
		if err != nil || !ok {
			t.Fatalf("parse restored frame failed: ok=%v err=%v", ok, err)
		}
		restored = append(restored, frame.payload...)
		got = got[frame.totalLen:]
	}
	if string(restored) != "hello Alice" {
		t.Fatalf("expected restored payload across messages, got %q", restored)
	}
}

func TestTransformConnWrite_MalformedFrameReportsErrorOnceAndPassesThrough(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")

	clientSide, upstreamSide := io.Pipe()
	defer upstreamSide.Close()

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(nil),
		Writer: upstreamSide,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	errCount := 0
	conn.SetOnError(func(error) { errCount++ })

	// RSV2 set without any negotiated extension: protocol error.
	bad, err := buildFrame(true, wsOpcodeText, true, []byte("hello Alice"))
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}
	bad[0] |= 0x20

	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(clientSide)
		done <- buf
	}()

	if n, err := conn.Write(bad); err != nil || n != len(bad) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}
	// After degradation the direction is pass-through; a second malformed
	// frame must not trigger the hook again.
	bad2, err := buildFrame(true, wsOpcodeText, true, []byte("still Alice"))
	if err != nil {
		t.Fatalf("build frame 2: %v", err)
	}
	bad2[0] |= 0x20
	if n, err := conn.Write(bad2); err != nil || n != len(bad2) {
		t.Fatalf("second write failed: n=%d err=%v", n, err)
	}
	_ = upstreamSide.Close()

	out := <-done
	if !bytes.Equal(out, append(bad, bad2...)) {
		t.Fatalf("expected raw frames to pass through unchanged")
	}
	if errCount != 1 {
		t.Fatalf("expected OnError to fire exactly once, got %d", errCount)
	}
}
