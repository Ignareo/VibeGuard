package textsafe

import (
	"testing"
)

func TestFoldSegmentsZeroWidthJoin(t *testing.T) {
	// "pass" + U+200B + "word": the zero-width char must not split the matchable text.
	input := []byte("pass\u200bword")
	segs := FoldSegments(input, false)
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	if string(segs[0].Text) != "password" {
		t.Fatalf("expected folded text %q, got %q", "password", segs[0].Text)
	}
	// The whole folded range maps back to the full original range (including the ZWSP).
	gs, ge := segs[0].MapRange(0, len(segs[0].Text))
	if gs != 0 || ge != len(input) {
		t.Fatalf("MapRange(0,8) = (%d,%d), want (0,%d)", gs, ge, len(input))
	}
	// "word" starts at folded offset 4 -> original offset 4+3=7 (after the 3-byte ZWSP).
	gs, ge = segs[0].MapRange(4, 8)
	if gs != 7 || ge != 11 {
		t.Fatalf("MapRange(4,8) = (%d,%d), want (7,11)", gs, ge)
	}
}

func TestFoldSegmentsFullWidthDigits(t *testing.T) {
	input := []byte("tel:１３８００１３８０００")
	segs := FoldSegments(input, false)
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	want := "tel:13800138000"
	if string(segs[0].Text) != want {
		t.Fatalf("expected folded text %q, got %q", want, segs[0].Text)
	}
	// The phone number occupies folded [4,15) -> original full-width bytes.
	gs, ge := segs[0].MapRange(4, 15)
	if got := string(input[gs:ge]); got != "１３８００１３８０００" {
		t.Fatalf("mapped original = %q, want full-width digits", got)
	}
	// A single folded digit maps to exactly one full-width rune (3 bytes).
	gs, ge = segs[0].MapRange(4, 5)
	if gs != 4 || ge != 7 {
		t.Fatalf("MapRange(4,5) = (%d,%d), want (4,7)", gs, ge)
	}
}

func TestFoldSegmentsCaseFold(t *testing.T) {
	segs := FoldSegments([]byte("PaSsWoRd"), true)
	if len(segs) != 1 || string(segs[0].Text) != "password" {
		t.Fatalf("expected [password], got %v", segs)
	}
	// ASCII case fold is length-preserving, offsets stay 1:1.
	gs, ge := segs[0].MapRange(2, 5)
	if gs != 2 || ge != 5 {
		t.Fatalf("MapRange(2,5) = (%d,%d), want (2,5)", gs, ge)
	}

	// Without case folding the text is untouched.
	segs = FoldSegments([]byte("PaSsWoRd"), false)
	if string(segs[0].Text) != "PaSsWoRd" {
		t.Fatalf("expected unchanged text, got %q", segs[0].Text)
	}

	// Case-fold expansion: ß -> ss; the expanded range maps back to the single rune.
	segs = FoldSegments([]byte("aßb"), true)
	if string(segs[0].Text) != "assb" {
		t.Fatalf("expected %q, got %q", "assb", segs[0].Text)
	}
	gs, ge = segs[0].MapRange(1, 3)
	if gs != 1 || ge != 3 {
		t.Fatalf("MapRange(1,3) = (%d,%d), want (1,3)", gs, ge)
	}
}

func TestFoldSegmentsHardBoundaries(t *testing.T) {
	// Control characters and ANSI sequences still split segments.
	input := []byte("foo\x07bar\x1b[31mbaz")
	segs := FoldSegments(input, false)
	if len(segs) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(segs))
	}
	if string(segs[0].Text) != "foo" || string(segs[1].Text) != "bar" || string(segs[2].Text) != "baz" {
		t.Fatalf("unexpected segments: %q %q %q", segs[0].Text, segs[1].Text, segs[2].Text)
	}
	// Segment bases point into the original input.
	gs, ge := segs[1].MapRange(0, 3)
	if string(input[gs:ge]) != "bar" {
		t.Fatalf("segment 1 maps to %q, want %q", input[gs:ge], "bar")
	}
	gs, ge = segs[2].MapRange(0, 3)
	if string(input[gs:ge]) != "baz" {
		t.Fatalf("segment 2 maps to %q, want %q", input[gs:ge], "baz")
	}
}

func TestFoldSegmentsIdentityFastPath(t *testing.T) {
	input := []byte("plain ascii text")
	segs := FoldSegments(input, false)
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	if &segs[0].Text[0] != &input[0] {
		t.Fatal("expected identity fast path to share the input bytes")
	}
}

func TestFoldString(t *testing.T) {
	if got := FoldString("MySecret", true); got != "mysecret" {
		t.Fatalf("FoldString case fold = %q, want %q", got, "mysecret")
	}
	if got := FoldString("ＴＯＫＥＮ", true); got != "token" {
		t.Fatalf("FoldString full-width = %q, want %q", got, "token")
	}
	if got := FoldString("ab\u200bcd", true); got != "abcd" {
		t.Fatalf("FoldString zero-width = %q, want %q", got, "abcd")
	}
	if got := FoldString("KeepCase", false); got != "KeepCase" {
		t.Fatalf("FoldString no-fold = %q, want %q", got, "KeepCase")
	}
}
