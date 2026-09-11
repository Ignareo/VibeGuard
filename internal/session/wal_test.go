package session

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func newTestWAL(t *testing.T) *WAL {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	wal, err := NewWAL(filepath.Join(t.TempDir(), "test.wal"), key)
	if err != nil {
		t.Fatalf("NewWAL failed: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	return wal
}

func TestWALAppendLoadSyncMode(t *testing.T) {
	wal := newTestWAL(t) // default: fsync per append
	if err := wal.Append(WALEntry{Placeholder: "__VG_A_x__", Original: "secret-a", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := wal.Append(WALEntry{Placeholder: "__VG_B_y__", Original: "secret-b", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	entries, err := wal.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestWALAsyncFlush(t *testing.T) {
	wal := newTestWAL(t)
	wal.SetAsyncFlush(50*time.Millisecond, 100)

	if err := wal.Append(WALEntry{Placeholder: "__VG_A_x__", Original: "secret-a", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	// Background flusher syncs within the interval; Load must see the entry.
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := wal.Load()
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if len(entries) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry not visible after async flush window")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWALAsyncFlushMaxPending(t *testing.T) {
	wal := newTestWAL(t)
	wal.SetAsyncFlush(time.Hour, 3) // long interval: only maxPending triggers a sync

	for i := 0; i < 3; i++ {
		if err := wal.Append(WALEntry{
			Placeholder: fmt.Sprintf("__VG_A_%d__", i),
			Original:    fmt.Sprintf("secret-%d", i),
			CreatedAt:   time.Now(),
		}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}
	entries, err := wal.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after maxPending sync, got %d", len(entries))
	}
}

func TestWALCompact(t *testing.T) {
	wal := newTestWAL(t)
	var all []WALEntry
	for i := 0; i < 10; i++ {
		e := WALEntry{
			Placeholder: fmt.Sprintf("__VG_A_%d__", i),
			Original:    fmt.Sprintf("secret-%d", i),
			CreatedAt:   time.Now(),
		}
		all = append(all, e)
		if err := wal.Append(e); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}
	sizeBefore, err := wal.FileSize()
	if err != nil || sizeBefore == 0 {
		t.Fatalf("FileSize before compact: %d err=%v", sizeBefore, err)
	}

	live := all[:3]
	if err := wal.Compact(live); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}
	sizeAfter, _ := wal.FileSize()
	if sizeAfter >= sizeBefore {
		t.Fatalf("compaction did not shrink the WAL: before=%d after=%d", sizeBefore, sizeAfter)
	}

	entries, err := wal.Load()
	if err != nil {
		t.Fatalf("Load after compact failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after compaction, got %d", len(entries))
	}

	// Appends after compaction must go to the new file and remain readable.
	if err := wal.Append(WALEntry{Placeholder: "__VG_A_new__", Original: "secret-new", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("Append after compact failed: %v", err)
	}
	entries, err = wal.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
}
