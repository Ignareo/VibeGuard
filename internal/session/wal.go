package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WAL entry structure
type WALEntry struct {
	Placeholder string    `json:"placeholder"`
	Original    string    `json:"original"`
	Category    string    `json:"category"`
	CreatedAt   time.Time `json:"created_at"`
}

// WAL handles persistent storage of session mappings
type WAL struct {
	path string
	gcm  cipher.AEAD
	mu   sync.Mutex
	file *os.File

	// Async flush (batched fsync): when syncInterval > 0, Append writes without fsync and
	// a background flusher syncs every syncInterval; Append forces a sync once maxPending
	// unsynced entries accumulate. syncInterval <= 0 keeps the legacy sync-per-Append behavior.
	syncInterval time.Duration
	maxPending   int
	pending      int
	flushStop    chan struct{}
	flushDone    chan struct{}
}

// NewWAL creates a new WAL instance
func NewWAL(path string, key32 []byte) (*WAL, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("WAL encryption key must be 32 bytes, got %d", len(key32))
	}
	key := append([]byte(nil), key32...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	wal := &WAL{
		path: path,
		gcm:  gcm,
	}

	return wal, nil
}

// SetAsyncFlush enables batched fsync: entries are flushed by a background goroutine every
// interval, or eagerly once maxPending unsynced entries accumulate. interval <= 0 disables
// batching (every Append fsyncs). Must be called before the WAL is used concurrently.
func (w *WAL) SetAsyncFlush(interval time.Duration, maxPending int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncInterval = interval
	w.maxPending = maxPending
	if interval > 0 && w.flushStop == nil {
		w.flushStop = make(chan struct{})
		w.flushDone = make(chan struct{})
		go w.flushLoop()
	}
}

func (w *WAL) flushLoop() {
	ticker := time.NewTicker(w.syncInterval)
	defer func() {
		ticker.Stop()
		close(w.flushDone)
	}()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			_ = w.syncLocked()
			w.mu.Unlock()
		case <-w.flushStop:
			return
		}
	}
}

// syncLocked fsyncs when there are pending entries (caller must hold w.mu).
func (w *WAL) syncLocked() error {
	if w.pending == 0 || w.file == nil {
		return nil
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	w.pending = 0
	return nil
}

// Append adds a new entry to the WAL
func (w *WAL) Append(entry WALEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create WAL directory: %w", err)
	}

	// Open file if not already open
	if w.file == nil {
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open WAL file: %w", err)
		}
		w.file = f
	}

	// Serialize entry
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	// Encrypt
	encrypted, err := w.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt entry: %w", err)
	}

	// Write length prefix + encrypted data
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))

	if _, err := w.file.Write(append(lenBuf, encrypted...)); err != nil {
		return fmt.Errorf("failed to write entry: %w", err)
	}

	if w.syncInterval <= 0 {
		return w.file.Sync()
	}
	w.pending++
	if w.maxPending > 0 && w.pending >= w.maxPending {
		return w.syncLocked()
	}
	return nil
}

// Load reads all entries from the WAL
func (w *WAL) Load() ([]WALEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		_ = w.syncLocked()
		w.file.Close()
		w.file = nil
	}

	data, err := os.ReadFile(w.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read WAL: %w", err)
	}

	var entries []WALEntry
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		length := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(length) > len(data) {
			break
		}

		encrypted := data[offset : offset+int(length)]
		offset += int(length)

		decrypted, err := w.decrypt(encrypted)
		if err != nil {
			slog.Warn("Failed to decrypt WAL entry", "error", err)
			continue
		}

		var entry WALEntry
		if err := json.Unmarshal(decrypted, &entry); err != nil {
			slog.Warn("Failed to unmarshal WAL entry", "error", err)
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// Close flushes pending entries and closes the WAL file
func (w *WAL) Close() error {
	if w.flushStop != nil {
		close(w.flushStop)
		<-w.flushDone
		w.flushStop = nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	_ = w.syncLocked()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// Delete removes the WAL file
func (w *WAL) Delete() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	w.pending = 0

	return os.Remove(w.path)
}

// FileSize returns the current WAL file size in bytes (0 when the file does not exist).
func (w *WAL) FileSize() (int64, error) {
	st, err := os.Stat(w.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Compact rewrites the WAL with only the given (live) entries, bounding file growth.
// Concurrent Append calls block until the rewrite is done and then append to the new file.
func (w *WAL) Compact(entries []WALEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create WAL directory: %w", err)
	}

	tmp := w.path + ".compact"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open WAL compaction file: %w", err)
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}

	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			return fail(fmt.Errorf("failed to marshal entry: %w", err))
		}
		encrypted, err := w.encrypt(data)
		if err != nil {
			return fail(fmt.Errorf("failed to encrypt entry: %w", err))
		}
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
		if _, err := f.Write(append(lenBuf, encrypted...)); err != nil {
			return fail(fmt.Errorf("failed to write entry: %w", err))
		}
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("failed to sync compaction file: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to close compaction file: %w", err)
	}

	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	if err := os.Rename(tmp, w.path); err != nil {
		// Windows compatibility: remove the destination first, then rename.
		_ = os.Remove(w.path)
		if err2 := os.Rename(tmp, w.path); err2 != nil {
			return fmt.Errorf("failed to replace WAL: %w", err)
		}
	}
	_ = os.Chmod(w.path, 0600)
	w.pending = 0
	return nil
}

// encrypt encrypts data using AES-GCM
func (w *WAL) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, w.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := w.gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

// decrypt decrypts data using AES-GCM
func (w *WAL) decrypt(data []byte) ([]byte, error) {
	if len(data) < w.gcm.NonceSize() {
		return nil, fmt.Errorf("data too short")
	}

	nonce := data[:w.gcm.NonceSize()]
	ciphertext := data[w.gcm.NonceSize():]

	return w.gcm.Open(nil, nonce, ciphertext, nil)
}

// RestoreInto loads WAL entries into a session manager
func (w *WAL) RestoreInto(m *Manager) error {
	entries, err := w.Load()
	if err != nil {
		return err
	}

	for _, entry := range entries {
		// Check if entry is expired
		if time.Since(entry.CreatedAt) > m.ttl {
			continue
		}
		// Preserve CreatedAt from the WAL:
		// - otherwise a restart would reset createdAt to time.Now(), effectively extending TTL
		// - also avoid appending to the WAL during restore (even if the caller already called AttachWAL)
		m.register(entry.Placeholder, entry.Original, entry.CreatedAt, false)
	}

	slog.Info("Restored mappings from WAL", "count", len(entries))
	return nil
}
