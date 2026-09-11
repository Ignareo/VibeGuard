package wsproxy

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/promptredact"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/stream"
)

const (
	wsOpcodeContinuation = 0x0
	wsOpcodeText         = 0x1
	wsOpcodeBinary       = 0x2
	wsOpcodeClose        = 0x8
	wsOpcodePing         = 0x9
	wsOpcodePong         = 0xa
)

type readTransformFn func([]byte) []byte

// TransformConn 在 WebSocket 升级后的双向连接上做“上行脱敏、下行还原”。
// 控制帧、二进制帧和带未知 RSV 位的数据帧透传；带 RSV1（permessage-deflate）的
// 文本消息会缓存整消息后解压、脱敏/还原，再以未压缩帧转发（RFC 7692 允许逐消息
// 不压缩）。若对端启用了 context takeover，跨消息回引会导致解压失败，此时该方向
// 退化为透传并触发一次 OnError。
type TransformConn struct {
	conn io.ReadWriteCloser

	readState  *frameTransformer
	writeState *frameTransformer

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewTransformConn(conn io.ReadWriteCloser, redactor redact.Redactor, restorer *restore.Engine) *TransformConn {
	// Downstream messages may split a placeholder across frames/messages;
	// MessageRestorer carries the incomplete tail into the next message.
	msgRestorer := stream.NewMessageRestorer(restorer)
	return &TransformConn{
		conn: conn,
		readState: newFrameTransformer(false, func(payload []byte) []byte {
			if msgRestorer == nil {
				return append([]byte(nil), payload...)
			}
			return msgRestorer.Feed(payload)
		}),
		writeState: newFrameTransformer(true, func(payload []byte) []byte {
			if redactor == nil {
				return append([]byte(nil), payload...)
			}
			if json.Valid(payload) {
				out, _, changed, err := promptredact.RedactJSONBody(redactor, payload)
				if err == nil {
					if changed {
						return out
					}
					return append([]byte(nil), payload...)
				}
			}
			out, _ := redactor.RedactWithMatches(payload)
			return out
		}),
	}
}

func (c *TransformConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	return c.readState.ReadFrom(c.conn, p)
}

func (c *TransformConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.writeState.WriteTo(c.conn, p)
}

func (c *TransformConn) Close() error {
	return c.conn.Close()
}

// SetOnError registers a hook invoked once per direction when frame parsing
// or transform fails and that direction degrades to pass-through.
func (c *TransformConn) SetOnError(fn func(error)) {
	c.readState.onError = fn
	c.writeState.onError = fn
}

type frameTransformer struct {
	maskOutput bool
	transform  readTransformFn
	onError    func(error)

	inBuf  bytes.Buffer
	outBuf bytes.Buffer
	tmp    []byte

	msgMode     messageMode
	msgBuf      bytes.Buffer
	passthrough bool
	pendingErr  error
}

type messageMode int

const (
	messageModeNone messageMode = iota
	messageModeBufferText
	messageModeBufferCompressed
	messageModePassthroughText
	messageModePassthroughBinary
)

func newFrameTransformer(maskOutput bool, transform readTransformFn) *frameTransformer {
	return &frameTransformer{
		maskOutput: maskOutput,
		transform:  transform,
		tmp:        make([]byte, 4096),
	}
}

func (t *frameTransformer) ReadFrom(src io.Reader, p []byte) (int, error) {
	for {
		if t.outBuf.Len() > 0 {
			return t.outBuf.Read(p)
		}
		if t.passthrough {
			return src.Read(p)
		}
		if t.pendingErr != nil {
			err := t.pendingErr
			t.pendingErr = nil
			return 0, err
		}

		n, err := src.Read(t.tmp)
		if n > 0 {
			t.inBuf.Write(t.tmp[:n])
			if perr := t.processIncoming(); perr != nil {
				t.reportError(perr)
				t.outBuf.Write(t.inBuf.Bytes())
				t.inBuf.Reset()
				t.msgBuf.Reset()
				t.msgMode = messageModeNone
				t.passthrough = true
			}
		}

		if t.outBuf.Len() > 0 {
			if err != nil {
				t.pendingErr = err
			}
			return t.outBuf.Read(p)
		}
		if err != nil {
			return 0, err
		}
	}
}

func (t *frameTransformer) WriteTo(dst io.Writer, p []byte) (int, error) {
	if t.passthrough {
		n, err := dst.Write(p)
		if err != nil {
			return n, err
		}
		return len(p), nil
	}

	t.inBuf.Write(p)
	if err := t.processIncoming(); err != nil {
		t.reportError(err)
		t.passthrough = true
		raw := append([]byte(nil), t.inBuf.Bytes()...)
		t.inBuf.Reset()
		t.msgBuf.Reset()
		t.msgMode = messageModeNone
		if werr := writeAll(dst, raw); werr != nil {
			return len(p), werr
		}
		return len(p), nil
	}

	if t.outBuf.Len() > 0 {
		raw := append([]byte(nil), t.outBuf.Bytes()...)
		t.outBuf.Reset()
		if err := writeAll(dst, raw); err != nil {
			return len(p), err
		}
	}

	return len(p), nil
}

func (t *frameTransformer) reportError(err error) {
	if t.onError != nil {
		t.onError(err)
	}
}

// maxInflatedMessageBytes caps a decompressed permessage-deflate message to
// guard against zip bombs on the (TLS-authenticated but untrusted) upstream.
const maxInflatedMessageBytes = 32 << 20

// inflateMessage decompresses a permessage-deflate message payload: raw
// DEFLATE with the trailing 0x00 0x00 0xff 0xff sync marker stripped.
// Each message is decoded with a fresh reader, so a peer using context
// takeover (cross-message back-references) makes this fail and the
// connection degrades to pass-through.
func inflateMessage(payload []byte) ([]byte, error) {
	buf := make([]byte, 0, len(payload)+4)
	buf = append(buf, payload...)
	buf = append(buf, 0x00, 0x00, 0xff, 0xff)
	r := flate.NewReader(bytes.NewReader(buf))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxInflatedMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedMessageBytes {
		return nil, fmt.Errorf("inflated message exceeds %d bytes", maxInflatedMessageBytes)
	}
	return out, nil
}

func (t *frameTransformer) processIncoming() error {
	for {
		frame, ok, err := parseFrame(t.inBuf.Bytes())
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		t.inBuf.Next(frame.totalLen)

		out, err := t.handleFrame(frame)
		if err != nil {
			return err
		}
		if len(out) > 0 {
			t.outBuf.Write(out)
		}
	}
}

func (t *frameTransformer) handleFrame(frame wsFrame) ([]byte, error) {
	if frame.isControl() {
		return frame.raw, nil
	}

	switch frame.opcode {
	case wsOpcodeText:
		if frame.rsv == 0x40 {
			// permessage-deflate compressed text message (RSV1 on first frame only).
			if frame.fin {
				return t.transformCompressedMessage(frame.payload)
			}
			t.msgBuf.Reset()
			t.msgBuf.Write(frame.payload)
			t.msgMode = messageModeBufferCompressed
			return nil, nil
		}
		if frame.rsv != 0 {
			if !frame.fin {
				t.msgMode = messageModePassthroughText
			}
			return frame.raw, nil
		}
		if frame.fin {
			return t.transformTextMessage(frame.payload)
		}
		t.msgBuf.Reset()
		t.msgBuf.Write(frame.payload)
		t.msgMode = messageModeBufferText
		return nil, nil

	case wsOpcodeBinary:
		if !frame.fin {
			t.msgMode = messageModePassthroughBinary
		}
		return frame.raw, nil

	case wsOpcodeContinuation:
		switch t.msgMode {
		case messageModeBufferText:
			t.msgBuf.Write(frame.payload)
			if !frame.fin {
				return nil, nil
			}
			payload := append([]byte(nil), t.msgBuf.Bytes()...)
			t.msgBuf.Reset()
			t.msgMode = messageModeNone
			return t.transformTextMessage(payload)

		case messageModeBufferCompressed:
			t.msgBuf.Write(frame.payload)
			if !frame.fin {
				return nil, nil
			}
			payload := append([]byte(nil), t.msgBuf.Bytes()...)
			t.msgBuf.Reset()
			t.msgMode = messageModeNone
			return t.transformCompressedMessage(payload)

		case messageModePassthroughText, messageModePassthroughBinary:
			if frame.fin {
				t.msgMode = messageModeNone
			}
			return frame.raw, nil

		default:
			return frame.raw, nil
		}

	default:
		return frame.raw, nil
	}
}

func (t *frameTransformer) transformTextMessage(payload []byte) ([]byte, error) {
	if !utf8.Valid(payload) || t.transform == nil {
		return buildFrame(true, wsOpcodeText, t.maskOutput, payload)
	}
	return buildFrame(true, wsOpcodeText, t.maskOutput, t.transform(payload))
}

// transformCompressedMessage inflates a permessage-deflate text message,
// transforms it, and re-emits it as an uncompressed text frame (RFC 7692
// allows an endpoint to send any message uncompressed once the extension is
// negotiated).
func (t *frameTransformer) transformCompressedMessage(payload []byte) ([]byte, error) {
	plain, err := inflateMessage(payload)
	if err != nil {
		return nil, fmt.Errorf("inflate permessage-deflate frame: %w", err)
	}
	return t.transformTextMessage(plain)
}

type wsFrame struct {
	fin      bool
	rsv      byte
	opcode   byte
	masked   bool
	payload  []byte
	raw      []byte
	totalLen int
}

func (f wsFrame) isControl() bool {
	return f.opcode >= 0x8
}

func parseFrame(buf []byte) (wsFrame, bool, error) {
	var frame wsFrame
	if len(buf) < 2 {
		return frame, false, nil
	}

	b0 := buf[0]
	b1 := buf[1]
	frame.fin = b0&0x80 != 0
	frame.rsv = b0 & 0x70
	frame.opcode = b0 & 0x0f
	frame.masked = b1&0x80 != 0

	// Protocol validation (RFC 6455): without negotiated extensions only
	// RSV1 (permessage-deflate) may be set, and only on the first frame of
	// a data message; control frames must be final and <= 125 bytes.
	if frame.rsv&0x30 != 0 {
		return frame, false, fmt.Errorf("websocket frame has RSV2/RSV3 set (rsv=%#x)", frame.rsv)
	}
	if frame.rsv&0x40 != 0 && frame.opcode != wsOpcodeText && frame.opcode != wsOpcodeBinary {
		return frame, false, fmt.Errorf("websocket frame has RSV1 on opcode %#x", frame.opcode)
	}
	switch frame.opcode {
	case wsOpcodeContinuation, wsOpcodeText, wsOpcodeBinary:
	case wsOpcodeClose, wsOpcodePing, wsOpcodePong:
		if !frame.fin {
			return frame, false, fmt.Errorf("fragmented control frame (opcode %#x)", frame.opcode)
		}
		if b1&0x7f > 125 {
			return frame, false, fmt.Errorf("control frame (opcode %#x) payload too large", frame.opcode)
		}
	default:
		return frame, false, fmt.Errorf("unknown websocket opcode %#x", frame.opcode)
	}

	payloadLen := uint64(b1 & 0x7f)
	offset := 2
	switch payloadLen {
	case 126:
		if len(buf) < offset+2 {
			return frame, false, nil
		}
		payloadLen = uint64(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
	case 127:
		if len(buf) < offset+8 {
			return frame, false, nil
		}
		payloadLen = binary.BigEndian.Uint64(buf[offset : offset+8])
		offset += 8
	}

	maskKeyLen := 0
	if frame.masked {
		maskKeyLen = 4
	}
	total := offset + maskKeyLen
	if len(buf) < total {
		return frame, false, nil
	}
	if payloadLen > uint64(len(buf)-total) {
		return frame, false, nil
	}
	total += int(payloadLen)

	frame.totalLen = total
	frame.raw = append([]byte(nil), buf[:total]...)

	payloadOffset := offset
	var maskKey []byte
	if frame.masked {
		maskKey = frame.raw[offset : offset+4]
		payloadOffset += 4
	}
	payload := append([]byte(nil), frame.raw[payloadOffset:total]...)
	if frame.masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	frame.payload = payload

	return frame, true, nil
}

func buildFrame(fin bool, opcode byte, masked bool, payload []byte) ([]byte, error) {
	header := make([]byte, 0, 14)
	b0 := opcode & 0x0f
	if fin {
		b0 |= 0x80
	}
	header = append(header, b0)

	payloadLen := len(payload)
	b1 := byte(0)
	if masked {
		b1 |= 0x80
	}

	switch {
	case payloadLen < 126:
		header = append(header, b1|byte(payloadLen))
	case payloadLen <= 65535:
		header = append(header, b1|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(payloadLen))
		header = append(header, ext[:]...)
	default:
		header = append(header, b1|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(payloadLen))
		header = append(header, ext[:]...)
	}

	out := make([]byte, 0, len(header)+payloadLen+4)
	out = append(out, header...)

	if masked {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return nil, err
		}
		out = append(out, maskKey[:]...)
		for i, b := range payload {
			out = append(out, b^maskKey[i%4])
		}
		return out, nil
	}

	out = append(out, payload...)
	return out, nil
}

func writeAll(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
