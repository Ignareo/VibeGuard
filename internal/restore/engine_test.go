package restore

import (
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/session"
)

func newTestEngine(t *testing.T) (*Engine, *session.Manager) {
	t.Helper()
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)
	return NewEngine(sess, "__VG_"), sess
}

func TestRestoreChecksumPlaceholder(t *testing.T) {
	eng, sess := newTestEngine(t)
	ph := sess.GetOrCreatePlaceholder("my-secret-value", "SECRET", "__VG_")
	out := eng.RestoreString("token is " + ph + " ok")
	if !strings.Contains(out, "my-secret-value") {
		t.Fatalf("placeholder not restored: %q", out)
	}
}

func TestRestoreLegacy12HexPlaceholder(t *testing.T) {
	eng, sess := newTestEngine(t)
	// Old-format mapping (no checksum), e.g. restored from a pre-checksum WAL.
	sess.Register("__VG_TEXT_abcdef123456__", "old-secret")
	out := eng.RestoreString("say __VG_TEXT_abcdef123456__ now")
	if !strings.Contains(out, "old-secret") {
		t.Fatalf("legacy placeholder not restored: %q", out)
	}
}

func TestRestoreTrailingBoundary(t *testing.T) {
	eng, sess := newTestEngine(t)
	ph := sess.GetOrCreatePlaceholder("boundary-secret", "SECRET", "__VG_")
	// Token without closing "__" immediately followed by a word char is a longer
	// lookalike, not our placeholder: it must NOT be partially restored.
	stripped := strings.TrimSuffix(ph, "__")
	out := eng.RestoreString(stripped + "extra")
	if strings.Contains(out, "boundary-secret") {
		t.Fatalf("partial token should not be restored: %q", out)
	}
	// But the same token followed by punctuation is a model-dropped "__": restore it.
	out = eng.RestoreString(stripped + ".")
	if !strings.Contains(out, "boundary-secret") {
		t.Fatalf("token before punctuation should be restored: %q", out)
	}
}

func TestFindLeftovers(t *testing.T) {
	eng, sess := newTestEngine(t)
	ph := sess.GetOrCreatePlaceholder("lost-secret", "SECRET", "__VG_")
	sess.Clear() // mapping lost (expiry/eviction/clear)

	leftovers := eng.FindLeftovers([]byte("echo " + ph + " done"))
	if len(leftovers) != 1 {
		t.Fatalf("expected 1 verified leftover, got %v", leftovers)
	}

	// Lookalike with a bad checksum must not be reported.
	fake := ph[:len(ph)-4] + "00__"
	if eng.FindLeftovers([]byte("echo "+fake)) != nil {
		t.Fatalf("lookalike token should not be a leftover")
	}
	// Registered placeholder (restorable) must not be reported.
	ph2 := sess.GetOrCreatePlaceholder("live-secret", "SECRET", "__VG_")
	if eng.FindLeftovers([]byte("echo "+ph2)) != nil {
		t.Fatalf("restorable placeholder should not be a leftover")
	}
}
