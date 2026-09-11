package promptredact

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/session"
)

const testSecret = "sk-secret-12345"

func newTestEngine(t *testing.T) *redact.Engine {
	t.Helper()
	eng := redact.NewEngine(session.NewManager(time.Hour, 1000), "__VG_")
	eng.AddKeyword(testSecret, "API_KEY")
	return eng
}

func assertRedacted(t *testing.T, body string, out []byte, changed bool, matches []redact.Match) {
	t.Helper()
	if !changed {
		t.Fatalf("expected body to be redacted, got unchanged: %s", out)
	}
	if len(matches) == 0 {
		t.Fatal("expected matches to be reported")
	}
	if !json.Valid(out) {
		t.Fatalf("redacted body is not valid JSON: %s", out)
	}
	if strings.Contains(string(out), testSecret) {
		t.Fatalf("secret still present in redacted body: %s", out)
	}
	if !strings.Contains(string(out), "__VG_API_KEY_") {
		t.Fatalf("placeholder missing in redacted body: %s", out)
	}
}

func TestRedactJSONBodyOpenAIChatCompletions(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "The deploy key is ` + testSecret + `"},
			{"role": "assistant", "content": null, "tool_calls": [
				{"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"/etc/conf\",\"token\":\"` + testSecret + `\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_1", "content": "token=` + testSecret + `"}
		]
	}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
	// Tool names must survive so call pairing keeps working.
	if !strings.Contains(string(out), "read_file") {
		t.Fatalf("tool name was modified: %s", out)
	}
	// arguments must remain a JSON-encoded JSON object.
	var decoded struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	args := decoded.Messages[1].ToolCalls[0].Function.Arguments
	var argsObj map[string]any
	if err := json.Unmarshal([]byte(args), &argsObj); err != nil {
		t.Fatalf("arguments is no longer JSON: %q (%v)", args, err)
	}
	if !strings.Contains(argsObj["token"].(string), "__VG_API_KEY_") {
		t.Fatalf("arguments payload not redacted: %q", args)
	}
}

func TestRedactJSONBodyOpenAIResponses(t *testing.T) {
	body := `{
		"model": "gpt-4.1",
		"instructions": "Use key ` + testSecret + ` for lookups",
		"input": [
			{"type": "function_call", "call_id": "fc_1", "name": "query", "arguments": "{\"api_key\":\"` + testSecret + `\"}"},
			{"type": "function_call_output", "call_id": "fc_1", "output": "file contents: ` + testSecret + `"}
		]
	}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
	if !strings.Contains(string(out), `"name":"query"`) && !strings.Contains(string(out), `"name": "query"`) {
		t.Fatalf("function name was modified: %s", out)
	}
}

func TestRedactJSONBodyAnthropic(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-5",
		"system": [
			{"type": "text", "text": "You are helpful."},
			{"type": "text", "text": "Credential: ` + testSecret + `"}
		],
		"messages": [
			{"role": "assistant", "content": [
				{"type": "text", "text": "Let me check."},
				{"type": "tool_use", "id": "tu_1", "name": "bash", "input": {"command": "curl -H token=` + testSecret + `"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "tu_1", "content": [
					{"type": "text", "text": "output with ` + testSecret + `"}
				]}
			]}
		]
	}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
	if !strings.Contains(string(out), `"name":"bash"`) {
		t.Fatalf("tool name was modified: %s", out)
	}
}

func TestRedactJSONBodyAnthropicSystemString(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5","system":"key is ` + testSecret + `","messages":[{"role":"user","content":"hi"}]}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
}

func TestRedactJSONBodyGemini(t *testing.T) {
	body := `{
		"system_instruction": {"parts": [{"text": "Guard the key ` + testSecret + `"}]},
		"contents": [
			{"role": "model", "parts": [
				{"functionCall": {"name": "lookup", "args": {"api_key": "` + testSecret + `"}}}
			]},
			{"role": "user", "parts": [
				{"functionResponse": {"name": "lookup", "response": {"result": "leaked ` + testSecret + `"}}}
			]}
		]
	}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
	if !strings.Contains(string(out), `"name":"lookup"`) {
		t.Fatalf("function name was modified: %s", out)
	}
}

func TestRedactJSONBodySystemReminderNotExempt(t *testing.T) {
	// Claude Code / Kimi Code inject file contents via <system-reminder> text parts;
	// secrets inside them must be redacted like anywhere else.
	body := `{"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\nfile contents: ` + testSecret + `\n</system-reminder>"}]}]}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
}

func TestRedactJSONBodyNoSecrets(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed || len(matches) != 0 {
		t.Fatalf("expected no change, got changed=%v matches=%d", changed, len(matches))
	}
	if string(out) != body {
		t.Fatalf("body modified: %s", out)
	}
}

func TestRedactJSONBodyAnthropicThinkingBlock(t *testing.T) {
	body := `{"messages":[{"role":"assistant","content":[
		{"type":"thinking","thinking":"the key is ` + testSecret + `","signature":"abc123"},
		{"type":"text","text":"ok"}]}]}`
	out, _, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("expected thinking block to be redacted")
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if strings.Contains(string(out), testSecret) {
		t.Fatalf("secret still present: %s", out)
	}
	if !strings.Contains(string(out), `"signature":"abc123"`) {
		t.Fatalf("signature must be preserved: %s", out)
	}
}

func TestRedactJSONBodyLegacyFunctionCall(t *testing.T) {
	body := `{"messages":[{"role":"assistant","function_call":{"name":"deploy","arguments":"{\"token\":\"` + testSecret + `\"}"}}]}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
	if !strings.Contains(string(out), `"name":"deploy"`) {
		t.Fatalf("function name must be preserved: %s", out)
	}
}

func TestRedactJSONBodyReasoningSummary(t *testing.T) {
	body := `{"input":[
		{"type":"reasoning","summary":[{"type":"summary_text","text":"used key ` + testSecret + `"}]},
		{"type":"message","content":[{"type":"output_text","text":"done"}]}]}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
}

func TestRedactJSONBodyNonStringArguments(t *testing.T) {
	// Some clients send function_call arguments already parsed (object, not string).
	body := `{"input":[{"type":"function_call","name":"deploy","arguments":{"token":"` + testSecret + `"}}]}`
	out, matches, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRedacted(t, body, out, changed, matches)
	if !strings.Contains(string(out), `"name":"deploy"`) {
		t.Fatalf("function name must be preserved: %s", out)
	}
}

func TestRedactJSONBodyDocumentSource(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[
		{"type":"document","source":{"type":"text","media_type":"text/plain","data":"key: ` + testSecret + `"}},
		{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"` + testSecret + `"}}]}]}`
	out, _, changed, err := RedactJSONBody(newTestEngine(t), []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("expected text document source to be redacted")
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	content := decoded["messages"].([]any)[0].(map[string]any)["content"].([]any)
	textDoc := content[0].(map[string]any)["source"].(map[string]any)
	if strings.Contains(textDoc["data"].(string), testSecret) {
		t.Fatalf("text document source not redacted: %s", out)
	}
	// base64 sources must pass through untouched.
	b64Doc := content[1].(map[string]any)["source"].(map[string]any)
	if b64Doc["data"].(string) != testSecret {
		t.Fatalf("base64 document source must be preserved: %s", out)
	}
}
