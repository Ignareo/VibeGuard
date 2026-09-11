package proxy

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/redact"
)

// isMultipartFormData reports whether the content type is multipart/form-data.
func isMultipartFormData(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(mt), "multipart/form-data")
}

// looksLikeJSONBody sniffs whether a body prefix looks like JSON (for requests that
// omit Content-Type). Only '{'/'[' openings qualify; anything else is left untouched.
func looksLikeJSONBody(prefix []byte) bool {
	b := bytes.TrimLeft(prefix, "\r\n\t \xef\xbb\xbf")
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

// redactMultipartBody redacts the text parts of a multipart/form-data body, preserving
// the boundary and all part headers. Binary parts (a filename with a non-text
// Content-Type) are forwarded untouched. Form fields (no filename, no Content-Type)
// and text-typed parts are redacted; non-UTF-8 parts are left as-is.
func redactMultipartBody(eng redact.Redactor, body []byte, contentType string) ([]byte, []redact.Match, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, nil, err
	}
	boundary := strings.TrimSpace(params["boundary"])
	if boundary == "" {
		return nil, nil, errors.New("multipart boundary missing")
	}

	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var buf bytes.Buffer
	buf.Grow(len(body))
	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary); err != nil {
		return nil, nil, err
	}

	var matches []redact.Match
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(part)
		hdr := make(textproto.MIMEHeader, len(part.Header))
		for k, vv := range part.Header {
			hdr[k] = append([]string(nil), vv...)
		}
		isText := isRedactableMultipartPart(part)
		part.Close()
		if err != nil {
			return nil, nil, err
		}

		if isText && len(data) > 0 && utf8.Valid(data) {
			if out, ms := eng.RedactWithMatches(data); len(ms) > 0 {
				data = out
				matches = append(matches, ms...)
			}
		}

		pw, err := mw.CreatePart(hdr)
		if err != nil {
			return nil, nil, err
		}
		if _, err := pw.Write(data); err != nil {
			return nil, nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), matches, nil
}

// isRedactableMultipartPart reports whether a multipart part carries redactable text:
// form fields (no filename and no explicit Content-Type, per RFC 7578 defaulting to
// text/plain) and parts with a text-like Content-Type.
func isRedactableMultipartPart(p *multipart.Part) bool {
	ct := strings.TrimSpace(p.Header.Get("Content-Type"))
	if ct == "" {
		return p.FileName() == ""
	}
	return isTextContent(ct)
}
