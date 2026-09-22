package engine

// Chunked detection is the one place where a payload is not analysed as a
// single string: above chunkLimit the text is cut into slices and every
// detector runs per slice. That makes the cut a seam, and a seam is where
// entities disappear — "паспорт 4509 123456" split into "паспорт 4509 " and
// "123456" matches nothing on either side. The tests here pin the two
// properties that make the seam invisible: an entity the cut runs through is
// still found (chunkOverlap), and an entity that both neighbours can see is
// masked once, not twice (the merged detect.Resolve).

import (
	"context"
	"strings"
	"testing"
)

// chunkFillerUnit is deliberately dull prose with no personal data of any
// kind. It ends with a space so units concatenate into real words, and the
// tests assert that a payload made only of it produces no spans at all — a
// filler that detected as anything would make every count below meaningless.
const chunkFillerUnit = "обычный текст без персональных данных "

// fillTo returns exactly n bytes of PD-free filler ending with a space, so the
// caller can place an entity at a byte offset it chose. splitPoints cuts after
// a space, which is precisely what makes the offset controllable.
func fillTo(n int) string {
	if n <= 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(n)
	for sb.Len()+len(chunkFillerUnit) <= n-1 {
		sb.WriteString(chunkFillerUnit)
	}
	// The remainder is padded with a single latin run rather than half a
	// Cyrillic word: a truncated multi-byte letter would be invalid UTF-8 and
	// the detectors would be tested on a string no client can send.
	for sb.Len() < n-1 {
		sb.WriteByte('x')
	}
	sb.WriteByte(' ')
	return sb.String()
}

// spaceFree returns n bytes that splitPoints cannot cut at: no space, no
// newline. It is how a test forces the cut to land where it wants it.
func spaceFree(n int) string { return strings.Repeat("y", n) }

// chunkEntities are the values the tests push across the seam. All three carry
// an internal space, which is what makes them splittable at all: splitPoints
// cuts after a space, so an entity without one (an e-mail, an INN) can only be
// cut by the rune-boundary fallback and is not at risk here.
var chunkEntities = []string{
	"паспорт 4509 123456",
	"карта 4276 1600 1234 5678",
	"телефон +7 916 123-45-67",
}

// maskedForm returns what the engine makes of entity on its own. The expected
// mask is taken from the engine rather than written down here, so that a
// detector retuning its span (or the shipped strategy changing) does not turn
// this file into a second, stale copy of the mask format — the format itself is
// pinned by the mask package's own tests.
func maskedForm(t *testing.T, e *Engine, entity string) string {
	t.Helper()
	res, err := e.Mask(context.Background(), "", "probe", entity)
	if err != nil {
		t.Fatalf("Mask(%q): %v", entity, err)
	}
	if res.Output == entity {
		t.Fatalf("%q is not detected even on its own: the chunk-seam test would prove nothing", entity)
	}
	return res.Output
}

// TestChunkFillerIsClean is the premise of every other test in this file.
func TestChunkFillerIsClean(t *testing.T) {
	e, _ := newEngine(t)
	txt := fillTo(3 * chunkLimit / 2)
	res := mustProcess(t, e, "filler", txt)
	if res.Output != txt {
		t.Fatalf("the filler is not PD-free: %d span(s) %v", res.Spans, res.Types)
	}
}

// TestChunkBoundaryEntity is the regression test for the seam.
//
// For each entity it walks the placement one byte at a time through the region
// around the cut, keeps the placements where the cut really does fall inside
// the entity, and requires the entity to be masked in every one of them. Before
// chunkOverlap existed these were exactly the placements that came back
// untouched.
func TestChunkBoundaryEntity(t *testing.T) {
	e, _ := newEngine(t)

	for _, entity := range chunkEntities {
		entity := entity
		t.Run(entity, func(t *testing.T) {
			want := maskedForm(t, e, entity)
			var cuts []int // cut offsets inside the entity that were exercised

			// The entity is placed so that it straddles the end of the first
			// 64 KiB window, and the text after it is space-free up to that
			// window end, so the last space splitPoints can find is one of the
			// entity's own.
			for start := chunkLimit - len(entity); start < chunkLimit; start++ {
				txt := fillTo(start) + entity + "." + spaceFree(chunkLimit) + " " + fillTo(chunkLimit/2)
				cut := firstInnerCut(txt, start, start+len(entity))
				if cut < 0 {
					continue // this placement is not cut through; nothing to prove
				}
				cuts = append(cuts, cut-start)

				res := mustProcess(t, e, "boundary", txt)
				if strings.Contains(res.Output, entity) {
					t.Errorf("cut at +%d inside the entity: %q came back unmasked", cut-start, entity)
				}
				if n := strings.Count(res.Output, want); n != 1 {
					t.Errorf("cut at +%d inside the entity: masked form %q appears %d times, want 1",
						cut-start, want, n)
				}
			}

			if len(cuts) < 2 {
				t.Fatalf("only %v cut positions landed inside the entity; the test is not covering the seam", cuts)
			}
			t.Logf("cut offsets exercised inside %q: %v", entity, cuts)
		})
	}
}

// TestChunkOverlapNoDoubleMask covers the risk the overlap itself introduces:
// an entity that sits in the overlap window is reported by two chunks, so the
// merged set holds the same span twice. It must reach the mask once.
//
// The check is byte-exact rather than "is it masked": masking the same span
// twice would either stack stars over stars or drop the second replacement
// somewhere inside mask.Apply, and both show up as a masked form that does not
// appear exactly once, or as a text whose length no longer matches the
// single-span result.
func TestChunkOverlapNoDoubleMask(t *testing.T) {
	e, _ := newEngine(t)

	for _, entity := range chunkEntities {
		entity := entity
		t.Run(entity, func(t *testing.T) {
			want := maskedForm(t, e, entity)

			// Place the entity so it ENDS shortly before the cut and starts
			// well inside the overlap window: the previous chunk sees it in
			// full, and so does the next one, which begins chunkOverlap bytes
			// earlier.
			start := chunkLimit - 300
			end := start + len(entity)
			txt := fillTo(start) + entity + "." + spaceFree(chunkLimit-64-end-1) + " " + spaceFree(4096) + fillTo(chunkLimit/2)

			cut := firstCutIn(txt, end, chunkLimit)
			if cut < 0 || cut-chunkOverlap > start {
				t.Fatalf("placement is wrong: entity [%d,%d), cut %d, overlap starts at %d",
					start, end, cut, cut-chunkOverlap)
			}

			res := mustProcess(t, e, "overlap", txt)
			if n := strings.Count(res.Output, want); n != 1 {
				t.Fatalf("entity inside the overlap window: masked form %q appears %d times, want exactly 1",
					want, n)
			}
			if strings.Contains(res.Output, entity) {
				t.Fatalf("entity inside the overlap window came back unmasked")
			}
			// One span, masked once: the output differs from the input by
			// exactly the length that one replacement changes.
			if got, want := len(res.Output)-len(txt), len(maskedForm(t, e, entity))-len(entity); got != want {
				t.Fatalf("length delta = %d, want %d: the span was masked more than once", got, want)
			}

			// And the mapping still restores byte for byte.
			back := mustProcess(t, e, "overlap", res.Output)
			if back.Output != txt {
				t.Fatal("reverse step did not restore the text byte for byte")
			}
		})
	}
}

// TestSmallPayloadIsNotChunked pins the cheap path: everything up to chunkLimit
// must go through detection in one piece, so the overwhelming majority of
// requests pay one length comparison and nothing else for the seam machinery.
func TestSmallPayloadIsNotChunked(t *testing.T) {
	txt := fillTo(chunkLimit)
	if got := splitPoints(txt, chunkLimit); len(got) != 2 {
		t.Fatalf("splitPoints on a payload of exactly chunkLimit produced %d cuts, want the whole text", len(got)-1)
	}
	// One byte more is two chunks, and the second one starts early.
	txt += "x"
	cuts := splitPoints(txt, chunkLimit)
	if len(cuts) != 3 {
		t.Fatalf("cuts = %v, want one interior cut", cuts)
	}
	// The overlap is chunkOverlap bytes, minus at most the few that rune
	// alignment gives back.
	if got, want := chunkStart(txt, cuts[1]), cuts[1]-chunkOverlap; got > want || want-got > 3 {
		t.Fatalf("chunkStart = %d, want %d (or a rune boundary just before it)", got, want)
	}
}

// TestChunkStartAlignsToRune keeps the overlap from beginning in the middle of
// a Cyrillic letter, which would hand the detectors invalid UTF-8 and lose the
// very entity the overlap exists to save.
func TestChunkStartAlignsToRune(t *testing.T) {
	// "я" is two bytes; a cut whose overlap lands on the second one must move
	// back to the first.
	s := strings.Repeat("я", chunkOverlap) + strings.Repeat("a", chunkOverlap)
	for cut := chunkOverlap; cut < len(s); cut++ {
		got := chunkStart(s, cut)
		if got < 0 || got > cut {
			t.Fatalf("chunkStart(%d) = %d", cut, got)
		}
		if s[got]&0xC0 == 0x80 {
			t.Fatalf("chunkStart(%d) = %d lands on a continuation byte", cut, got)
		}
		if cut-got > chunkOverlap+1 {
			t.Fatalf("chunkStart(%d) = %d backed up %d bytes, more than one rune", cut, got, cut-got)
		}
	}
}

// firstInnerCut returns the first interior cut strictly inside [from,to), or -1.
func firstInnerCut(s string, from, to int) int {
	for _, c := range splitPoints(s, chunkLimit) {
		if c > from && c < to {
			return c
		}
	}
	return -1
}

// firstCutIn returns the first interior cut in [from,to), or -1.
func firstCutIn(s string, from, to int) int {
	for _, c := range splitPoints(s, chunkLimit) {
		if c >= from && c < to && c != 0 && c != len(s) {
			return c
		}
	}
	return -1
}
