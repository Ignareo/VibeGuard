package stream

import "github.com/inkdust2021/vibeguard/internal/restore"

// MessageRestorer restores placeholders across message boundaries.
// Unlike Engine.Restore (single message), it keeps a small carry buffer
// so a placeholder split across two messages is still restored.
// Intended for frame/message-oriented transports such as WebSocket.
type MessageRestorer struct {
	r *textStreamRestorer
}

// NewMessageRestorer returns nil when eng is nil; Feed on a nil
// MessageRestorer passes bytes through unchanged.
func NewMessageRestorer(eng *restore.Engine) *MessageRestorer {
	if eng == nil {
		return nil
	}
	return &MessageRestorer{r: &textStreamRestorer{eng: eng}}
}

// Feed consumes one complete message and returns the restored bytes.
// A tail that may be the prefix of a split placeholder is held back
// and emitted by the next Feed or by Flush.
func (m *MessageRestorer) Feed(b []byte) []byte {
	if m == nil || m.r == nil {
		return b
	}
	return []byte(m.r.Feed(string(b)))
}

// Flush emits any buffered tail without further restoration.
func (m *MessageRestorer) Flush() []byte {
	if m == nil || m.r == nil {
		return nil
	}
	return []byte(m.r.Flush())
}
