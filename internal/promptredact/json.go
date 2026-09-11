package promptredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/redact"
)

// RedactJSONBody 只对 JSON 里的 prompt-like 字段做结构化脱敏，
// 避免误改模型、schema、metadata 等协议字段。
func RedactJSONBody(redactEng redact.Redactor, body []byte) (out []byte, matches []redact.Match, changed bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, false, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, false, fmt.Errorf("trailing JSON data")
	}

	redacted, matches, changed, err := redactJSONValuePromptOnly(redactEng, v)
	if err != nil {
		return nil, nil, false, err
	}
	if !changed {
		return body, nil, false, nil
	}

	out, err = json.Marshal(redacted)
	if err != nil {
		return nil, nil, false, err
	}
	return out, matches, true, nil
}

func redactPromptJSONStringValue(redactEng redact.Redactor, s string) (out any, matches []redact.Match, changed bool, err error) {
	redactedRaw, ms := redactEng.RedactWithMatches([]byte(s))
	if len(ms) == 0 {
		return s, nil, false, nil
	}

	b, err := json.Marshal(string(redactedRaw))
	if err != nil {
		return s, nil, false, err
	}

	raw := json.RawMessage(b)
	if !json.Valid(raw) {
		return s, nil, false, nil
	}

	return raw, ms, true, nil
}

func redactJSONValuePromptOnly(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONValuePromptOnly(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil

	case map[string]any:
		anyChanged := false
		var all []redact.Match
		for k, val := range vv {
			var (
				nv any
				ms []redact.Match
				ch bool
			)

			switch k {
			case "messages", "input", "contents":
				nv, ms, ch, err = redactJSONMessagesLike(redactEng, val)
			case "system", "instructions", "system_instruction", "systemInstruction":
				// System prompts: OpenAI Responses `instructions` (string), Anthropic
				// `system` (string or content blocks), Gemini `system_instruction` ({parts:[...]}).
				nv, ms, ch, err = redactJSONSystemLike(redactEng, val)
			default:
				nv, ms, ch, err = redactJSONValuePromptOnly(redactEng, val)
			}
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[k] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil

	default:
		return v, nil, false, nil
	}
}

func redactJSONStringLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	s, ok := v.(string)
	if !ok {
		return v, nil, false, nil
	}
	return redactPromptJSONStringValue(redactEng, s)
}

func redactJSONMessagesLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONMessageItem(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil
	case map[string]any:
		return redactJSONValuePromptOnly(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

// redactJSONSystemLike redacts system-prompt fields: plain strings, Anthropic-style
// content block arrays, and Gemini-style {parts:[...]} objects.
func redactJSONSystemLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		return redactJSONTextParts(redactEng, vv)
	case map[string]any:
		return redactJSONMessageItem(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

// redactJSONToolPayloadString redacts tool call payloads carried as strings
// (OpenAI tool_calls[].function.arguments, Responses function_call.output). The payload
// is usually a JSON-encoded string: prefer structured redaction of the parsed payload so
// escaped secrets are caught; fall back to plain-text redaction when it is not JSON.
func redactJSONToolPayloadString(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	s, ok := v.(string)
	if !ok {
		return v, nil, false, nil
	}

	var parsed any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if derr := dec.Decode(&parsed); derr == nil && dec.Decode(&struct{}{}) == io.EOF {
		nv, ms, ch, err := redactJSONDeepStrings(redactEng, parsed)
		if err != nil {
			return v, nil, false, err
		}
		if !ch {
			return s, nil, false, nil
		}
		b, err := json.Marshal(nv)
		if err != nil {
			return v, nil, false, err
		}
		return string(b), ms, true, nil
	}

	return redactPromptJSONStringValue(redactEng, s)
}

// redactJSONDeepStrings redacts every string leaf in v. Used for tool argument payloads
// (tool_use.input, functionCall.args, ...), which are free-form model/user-generated data
// rather than protocol fields. Map keys are left untouched.
func redactJSONDeepStrings(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONDeepStrings(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil
	case map[string]any:
		anyChanged := false
		var all []redact.Match
		for k, val := range vv {
			nv, ms, ch, err := redactJSONDeepStrings(redactEng, val)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[k] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil
	default:
		return v, nil, false, nil
	}
}

// redactJSONToolCalls redacts OpenAI-style tool_calls arrays: each item's
// function.arguments payload (tool/function names are left untouched so call pairing
// keeps working).
func redactJSONToolCalls(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	calls, ok := v.([]any)
	if !ok {
		return v, nil, false, nil
	}

	anyChanged := false
	var all []redact.Match
	for i := range calls {
		call, ok := calls[i].(map[string]any)
		if !ok {
			continue
		}
		fn, ok := call["function"].(map[string]any)
		if !ok {
			continue
		}
		args, ok := fn["arguments"]
		if !ok {
			continue
		}
		nv, ms, ch, err := redactJSONToolPayloadString(redactEng, args)
		if err != nil {
			return v, nil, false, err
		}
		if ch {
			fn["arguments"] = nv
			anyChanged = true
		}
		if len(ms) > 0 {
			all = append(all, ms...)
		}
	}
	return calls, all, anyChanged, nil
}

func redactJSONMessageItem(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case map[string]any:
		anyChanged := false
		var all []redact.Match

		if c, ok := vv["content"]; ok {
			nc, ms, ch, err := redactJSONMessageContent(redactEng, c)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["content"] = nc
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		if p, ok := vv["parts"]; ok {
			np, ms, ch, err := redactJSONTextParts(redactEng, p)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["parts"] = np
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		if t, ok := vv["text"]; ok {
			nt, ms, ch, err := redactJSONStringLike(redactEng, t)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["text"] = nt
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// OpenAI chat.completions tool calls on assistant messages.
		if tc, ok := vv["tool_calls"]; ok {
			nt, ms, ch, err := redactJSONToolCalls(redactEng, tc)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["tool_calls"] = nt
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// Responses API function_call items carry arguments directly on the item.
		if a, ok := vv["arguments"]; ok {
			na, ms, ch, err := redactJSONToolPayloadString(redactEng, a)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["arguments"] = na
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// Responses API function_call_output items carry the tool result as a string.
		if o, ok := vv["output"]; ok {
			no, ms, ch, err := redactJSONToolPayloadString(redactEng, o)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["output"] = no
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		return vv, all, anyChanged, nil
	default:
		return v, nil, false, nil
	}
}

func redactJSONMessageContent(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		return redactJSONTextParts(redactEng, vv)
	case map[string]any:
		return redactJSONTextPart(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

func redactJSONTextParts(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	parts, ok := v.([]any)
	if !ok {
		return v, nil, false, nil
	}

	anyChanged := false
	var all []redact.Match
	for i := range parts {
		nv, ms, ch, err := redactJSONTextPart(redactEng, parts[i])
		if err != nil {
			return v, nil, false, err
		}
		if ch {
			parts[i] = nv
			anyChanged = true
		}
		if len(ms) > 0 {
			all = append(all, ms...)
		}
	}
	return parts, all, anyChanged, nil
}

func redactJSONTextPart(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case map[string]any:
		anyChanged := false
		var all []redact.Match

		if t, ok := vv["text"]; ok {
			// Note: text parts starting with <system-reminder> are NOT exempt from
			// redaction. Claude Code / Kimi Code use them to inject file contents, which
			// is exactly where secrets end up; the upstream API treats the reminder as
			// plain text, so redacting it cannot break harness-side parsing.
			nt, ms, ch, err := redactJSONStringLike(redactEng, t)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["text"] = nt
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// Anthropic tool_use blocks: input is the free-form tool argument payload.
		if in, ok := vv["input"]; ok {
			nv, ms, ch, err := redactJSONDeepStrings(redactEng, in)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["input"] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// Anthropic tool_result blocks nest their result in a content field (string or blocks).
		if c, ok := vv["content"]; ok {
			nc, ms, ch, err := redactJSONMessageContent(redactEng, c)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["content"] = nc
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// Gemini functionCall / functionResponse parts: redact the args/response payloads
		// (names are left untouched so call pairing keeps working).
		for _, key := range []string{"functionCall", "functionResponse"} {
			fc, ok := vv[key].(map[string]any)
			if !ok {
				continue
			}
			sub := "args"
			if key == "functionResponse" {
				sub = "response"
			}
			payload, ok := fc[sub]
			if !ok {
				continue
			}
			nv, ms, ch, err := redactJSONDeepStrings(redactEng, payload)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				fc[sub] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		return vv, all, anyChanged, nil
	default:
		return v, nil, false, nil
	}
}
