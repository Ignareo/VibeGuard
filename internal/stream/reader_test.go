package stream

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// newRestoreFixture returns a restore engine plus a helper that registers a mapping and
// returns the placeholder for it.
func newRestoreFixture(t *testing.T) (*restore.Engine, func(original, category string) string) {
	t.Helper()
	sess := session.NewManager(time.Hour, 1000)
	eng := restore.NewEngine(sess, "__VG_")
	return eng, func(original, category string) string {
		ph := sess.GeneratePlaceholder(original, category, "__VG_")
		sess.Register(ph, original)
		return ph
	}
}

func readAllSSE(t *testing.T, eng *restore.Engine, stream string) string {
	t.Helper()
	r := NewSSERestoringReader(io.NopCloser(strings.NewReader(stream)), eng)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(out)
}

func TestSSEChatCompletionsSplitPlaceholder(t *testing.T) {
	eng, register := newRestoreFixture(t)
	ph := register("alice@example.com", "EMAIL")
	half := len(ph) / 2

	stream := "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Contact \"}}]}\n\n" +
		"data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":" + jsonQuote(ph[:half]) + "}}]}\n\n" +
		"data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":" + jsonQuote(ph[half:]+" for details") + "}}]}\n\n" +
		"data: [DONE]\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "alice@example.com") {
		t.Fatalf("placeholder was not restored across chunks:\n%s", out)
	}
	if strings.Contains(out, ph) {
		t.Fatalf("placeholder leaked into output:\n%s", out)
	}
	if !strings.Contains(out, " for details") {
		t.Fatalf("surrounding text was lost:\n%s", out)
	}
	if got := strings.Count(out, "data:"); got != 4 {
		t.Fatalf("expected 4 data events, got %d:\n%s", got, out)
	}
}

func TestSSEChatCompletionsInterleavedChoices(t *testing.T) {
	eng, register := newRestoreFixture(t)
	phA := register("secret-alpha-value", "SECRET")
	phB := register("secret-bravo-value", "SECRET")

	chunk := func(idx int, content string) string {
		return "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":" + strconv.Itoa(idx) + ",\"delta\":{\"content\":" + jsonQuote(content) + "}}]}\n\n"
	}

	stream := chunk(0, "A:"+phA[:10]) +
		chunk(1, "B:"+phB[:10]) +
		chunk(0, phA[10:]+"!") +
		chunk(1, phB[10:]+"?") +
		"data: [DONE]\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "secret-alpha-value") || !strings.Contains(out, "secret-bravo-value") {
		t.Fatalf("interleaved placeholders not restored:\n%s", out)
	}
	// No cross-talk: each restored value must sit in its own choice's stream.
	if strings.Contains(out, "secret-alpha-value?") || strings.Contains(out, "secret-bravo-value!") {
		t.Fatalf("streams mixed fragments:\n%s", out)
	}
}

func TestSSEChatCompletionsToolCallArguments(t *testing.T) {
	eng, register := newRestoreFixture(t)
	ph := register("sk-live-token-42", "API_KEY")

	stream := "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"deploy\",\"arguments\":\"{\\\"token\\\": \\\"" + ph[:12] + "\"}}]}}]}\n\n" +
		"data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"" + ph[12:] + "\\\"}\"}}]}}]}\n\n" +
		"data: [DONE]\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "sk-live-token-42") {
		t.Fatalf("tool_call arguments placeholder not restored:\n%s", out)
	}
}

func TestSSEAnthropicInputJSONDelta(t *testing.T) {
	eng, register := newRestoreFixture(t)
	ph := register("p@ssw0rd-secret", "PASSWORD")
	half := len(ph) / 2

	stream := "event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"pass\\\": \\\"" + ph[:half] + "\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"" + ph[half:] + "\\\"}\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "p@ssw0rd-secret") {
		t.Fatalf("input_json_delta placeholder not restored:\n%s", out)
	}
	if got := strings.Count(out, "data:"); got != 3 {
		t.Fatalf("expected 3 data events, got %d:\n%s", got, out)
	}
}

func TestSSEAnthropicBlockFinalPlaceholderWithoutSuffix(t *testing.T) {
	eng, register := newRestoreFixture(t)
	ph := register("bob@example.org", "EMAIL")
	// Model dropped the trailing "__": the restorer must hold it until the block ends,
	// then restore it when the non-delta stop event arrives.
	if !strings.HasSuffix(ph, "__") {
		t.Fatalf("unexpected placeholder format: %q", ph)
	}
	trimmed := strings.TrimSuffix(ph, "__")

	stream := "event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"mail \"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + trimmed + "\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "bob@example.org") {
		t.Fatalf("block-final placeholder without suffix was not restored:\n%s", out)
	}
}

func TestSSEAnthropicInterleavedBlocks(t *testing.T) {
	eng, register := newRestoreFixture(t)
	phA := register("first-secret", "SECRET")
	phB := register("second-secret", "SECRET")

	delta := func(idx int, text string) string {
		return "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":" + strconv.Itoa(idx) + ",\"delta\":{\"type\":\"text_delta\",\"text\":" + jsonQuote(text) + "}}\n\n"
	}

	stream := delta(0, "x"+phA[:10]) + delta(2, "y"+phB[:10]) + delta(0, phA[10:]) + delta(2, phB[10:]) +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "first-secret") || !strings.Contains(out, "second-secret") {
		t.Fatalf("interleaved block placeholders not restored:\n%s", out)
	}
}

func TestSSEResponsesOutputTextDelta(t *testing.T) {
	eng, register := newRestoreFixture(t)
	ph := register("carol@example.net", "EMAIL")
	half := len(ph) / 2

	stream := "event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"to " + ph[:half] + "\"}\n\n" +
		"event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"" + ph[half:] + " now\"}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\"}\n\n"

	out := readAllSSE(t, eng, stream)
	if !strings.Contains(out, "carol@example.net") {
		t.Fatalf("Responses delta placeholder not restored:\n%s", out)
	}
	if !strings.Contains(out, " now") {
		t.Fatalf("trailing text lost:\n%s", out)
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
