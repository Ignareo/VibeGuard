package proxy

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
)

func TestIsTextContent(t *testing.T) {
	cases := map[string]bool{
		"application/json":                   true,
		"application/vnd.api+json":           true, // +json suffix
		"application/json; charset=utf-8":    true,
		"application/x-ndjson":               true,
		"text/plain":                         true,
		"text/event-stream":                  true,
		"application/x-www-form-urlencoded":  true,
		"application/xml":                    true,
		"application/atom+xml":               true,
		"application/octet-stream":           false,
		"multipart/form-data; boundary=xxxx": false, // handled by its own path
		"image/png":                          false,
		"":                                   false,
	}
	for ct, want := range cases {
		if got := isTextContent(ct); got != want {
			t.Errorf("isTextContent(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestLooksLikeJSONBody(t *testing.T) {
	if !looksLikeJSONBody([]byte("  {\"a\":1}")) {
		t.Errorf("should detect JSON object")
	}
	if !looksLikeJSONBody([]byte("\r\n[1,2]")) {
		t.Errorf("should detect JSON array")
	}
	if looksLikeJSONBody([]byte("hello world")) {
		t.Errorf("plain text must not be detected as JSON")
	}
	if looksLikeJSONBody([]byte{0x00, 0x01}) {
		t.Errorf("binary must not be detected as JSON")
	}
}

func TestRedactMultipartBody(t *testing.T) {
	eng := newKeywordRedactor(t, map[string]string{"hunter2secret": "SECRET"})

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	boundary := w.Boundary()

	// 1) form field (no filename): redactable
	fw, _ := w.CreateFormField("prompt")
	_, _ = fw.Write([]byte("my password is hunter2secret ok"))
	// 2) text file part: redactable
	tw, _ := w.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="note"; filename="note.txt"`},
		"Content-Type":        {"text/plain"},
	})
	_, _ = tw.Write([]byte("remember hunter2secret"))
	// 3) binary file part: must stay untouched
	binPayload := []byte{'P', 'K', 0x00, 0x01}
	bw, _ := w.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="blob"; filename="x.bin"`},
		"Content-Type":        {"application/octet-stream"},
	})
	_, _ = bw.Write(binPayload)
	_ = w.Close()

	contentType := "multipart/form-data; boundary=" + boundary
	out, matches, err := redactMultipartBody(eng, buf.Bytes(), contentType)
	if err != nil {
		t.Fatalf("redactMultipartBody failed: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (field + text file), got %d", len(matches))
	}

	// The result must stay parseable with the same boundary.
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || mt != "multipart/form-data" {
		t.Fatalf("content type parse: %v", err)
	}
	mr := multipart.NewReader(bytes.NewReader(out), params["boundary"])
	seen := map[string]string{}
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(p)
		seen[p.FormName()] = string(data)
		p.Close()
	}
	if strings.Contains(seen["prompt"], "hunter2secret") || !strings.Contains(seen["prompt"], "__VG_SECRET_") {
		t.Errorf("form field not redacted: %q", seen["prompt"])
	}
	if strings.Contains(seen["note"], "hunter2secret") {
		t.Errorf("text file part not redacted: %q", seen["note"])
	}
	if seen["blob"] != string(binPayload) {
		t.Errorf("binary part corrupted: %q", seen["blob"])
	}
}
