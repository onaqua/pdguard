// Package detect holds the detector contract, the shared per-request analysis
// context and the overlap resolver. Individual detectors live in sibling files
// and are registered from init().
package detect

import (
	"context"
	"sort"
	"sync"

	"pdguard/internal/pd"
	"pdguard/internal/pd/text"
)

// Context carries everything a detector needs about one request. It is built
// once per call and reused by every detector, so the expensive work
// (lowercasing, tokenizing) happens exactly once.
type Context struct {
	// Text is the original payload. Offsets in every Span refer to it.
	Text string
	// Lower is Text lowercased with byte offsets preserved 1:1, and with the
	// non-breaking and narrow space characters normalised to ASCII spaces (see
	// normalizeSpaces). Detectors search this copy; Text stays untouched so
	// everything outside a span is masked byte for byte.
	Lower string
	// Tokens is the single-pass tokenization of Text.
	Tokens []text.Token

	// Enabled reports whether a PD type should be looked for at all. Detectors
	// must consult it before doing expensive work.
	Enabled func(pd.Type) bool

	// CaseBlind reports whether the payload carries no capitalisation signal:
	// lowercasing changed nothing. It is computed from the original text, not
	// from Lower, because Lower also normalises spaces.
	CaseBlind bool

	// wordIdx maps a byte offset to the index of the token starting there.
	wordIdx map[int]int
}

// NewContext builds the analysis context for a payload.
func NewContext(payload string, enabled func(pd.Type) bool) *Context {
	if enabled == nil {
		enabled = func(pd.Type) bool { return true }
	}
	lower := text.SafeLower(payload)
	toks := text.Tokenize(payload)
	idx := make(map[int]int, len(toks))
	for i, t := range toks {
		idx[t.Start] = i
	}
	return &Context{
		Text:      payload,
		Lower:     normalizeSpaces(lower),
		Tokens:    toks,
		Enabled:   enabled,
		CaseBlind: lower == payload,
		wordIdx:   idx,
	}
}

// normalizeSpaces returns a copy of s in which the space characters that
// Word, Outlook and browsers insert are replaced by the same number of ASCII
// spaces: U+00A0 (2 bytes) becomes two spaces, and the narrow spaces U+202F,
// U+2007, U+2009, U+2002 and U+2003 (3 bytes each) become three. The byte
// length is preserved, so a byte offset found in the result is valid in s.
// Tabs are left alone: they are already a whitespace character.
func normalizeSpaces(s string) string {
	b := []byte(s)
	if !hasNormalizableSpace(b) {
		return s
	}
	for i := 0; i < len(b); i++ {
		if isNBSP(b, i) {
			b[i], b[i+1] = ' ', ' '
			i++
			continue
		}
		if isNarrowAt(b, i) {
			b[i], b[i+1], b[i+2] = ' ', ' ', ' '
			i += 2
			continue
		}
	}
	return string(b)
}

// hasNormalizableSpace reports whether s contains a space character that
// normalizeSpaces would rewrite.
func hasNormalizableSpace(s []byte) bool {
	for i := 0; i < len(s); i++ {
		if isNBSP(s, i) || isNarrowAt(s, i) {
			return true
		}
	}
	return false
}

// isNBSP reports whether the bytes at i spell U+00A0 (a non-breaking space).
func isNBSP(s []byte, i int) bool {
	return i+1 < len(s) && s[i] == 0xC2 && s[i+1] == 0xA0
}

// isNarrowAt reports whether the bytes at i spell one of the narrow space
// characters this package normalises.
func isNarrowAt(s []byte, i int) bool {
	return i+2 < len(s) && s[i] == 0xE2 && isNarrowSpace(s[i+1], s[i+2])
}

// isNarrowSpace reports whether the two bytes after the 0xE2 lead byte spell
// one of the narrow space characters this package normalises.
func isNarrowSpace(a, b byte) bool {
	if a != 0x80 {
		return false
	}
	switch b {
	case 0xAF, 0x87, 0x89, 0x82, 0x83: // U+202F, U+2007, U+2009, U+2002, U+2003
		return true
	}
	return false
}

// TokenAt returns the index of the token starting at byte offset off, or -1.
func (c *Context) TokenAt(off int) int {
	if i, ok := c.wordIdx[off]; ok {
		return i
	}
	return -1
}

// Slice returns the original text of a span.
func (c *Context) Slice(start, end int) string { return c.Text[start:end] }

// Detector finds occurrences of one or more PD types in a Context.
// Implementations MUST be stateless and safe for concurrent use: a single
// instance serves every request.
type Detector interface {
	// Name identifies the detector in logs and Span.Src.
	Name() string
	// Types lists the PD types this detector can emit.
	Types() []pd.Type
	// Detect returns spans with byte offsets into ctx.Text. Returning
	// overlapping or unsorted spans is fine — Resolve sorts it out.
	Detect(ctx *Context) []pd.Span
}

var (
	regMu     sync.RWMutex
	registry  []Detector
	regByName = map[string]Detector{}
)

// Register adds a detector to the global registry. Call from init().
// Registering the same name twice panics: it means two files claimed one slot.
func Register(d Detector) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := regByName[d.Name()]; dup {
		panic("detect: duplicate detector name " + d.Name())
	}
	regByName[d.Name()] = d
	registry = append(registry, d)
}

// Detectors returns every registered detector.
func Detectors() []Detector {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Detector, len(registry))
	copy(out, registry)
	return out
}

// Run executes every registered detector and returns the resolved,
// non-overlapping, position-ordered set of spans.
func Run(ctx *Context) []pd.Span {
	spans, _ := RunCtx(context.Background(), ctx)
	return spans
}

// RunCtx is Run with a cancellation point between detectors.
//
// The HTTP layer bounds a request with a context deadline and its own comment
// says "a context deadline lets the engine stop early" — but nothing below the
// engine ever looked at it, so the deadline only changed the error that was
// returned AFTER all the work had been done. A pathological payload therefore
// held a core for as long as it liked while the client had already given up and
// retried, which is how a slow request turns into an avalanche.
//
// Between detectors is the right granularity: each detector is now linear in
// the payload, so the window between two checks is bounded by one pass over one
// chunk. The partial result is returned together with the error so a caller that
// prefers a partial mask to no mask at all has the choice.
func RunCtx(cancel context.Context, ctx *Context) ([]pd.Span, error) {
	regMu.RLock()
	ds := registry
	regMu.RUnlock()

	var all []pd.Span
	for _, d := range ds {
		if err := cancel.Err(); err != nil {
			return Resolve(all), err
		}
		if spans := d.Detect(ctx); len(spans) > 0 {
			all = append(all, spans...)
		}
	}
	return Resolve(all), cancel.Err()
}

// Resolve removes overlaps from a raw detection set.
//
// The rule, in order: a longer span beats a shorter one, then a higher type
// priority wins, then higher confidence. Length comes first because the
// expensive mistake is splitting one real identifier (a 16-digit card) into
// fragments that each get a different mask.
func Resolve(spans []pd.Span) []pd.Span {
	if len(spans) < 2 {
		return spans
	}
	sort.SliceStable(spans, func(i, j int) bool {
		return resolveLess(spans[i], spans[j])
	})
	kept := resolveFilter(spans)
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

// resolveLess orders two spans by the resolution rule: longer first, then
// higher type priority, then higher confidence, then earlier position.
func resolveLess(a, b pd.Span) bool {
	if a.Len() != b.Len() {
		return a.Len() > b.Len()
	}
	if pa, pb := a.Type.Priority(), b.Type.Priority(); pa != pb {
		return pa > pb
	}
	if a.Conf != b.Conf {
		return a.Conf > b.Conf
	}
	return a.Start < b.Start
}

// resolveFilter drops spans that overlap an already kept one, keeping the
// first claimant of each byte.
func resolveFilter(spans []pd.Span) []pd.Span {
	kept := make([]pd.Span, 0, len(spans))
	if len(spans) < resolveOccupancyMin {
		return resolvePairwise(spans, kept)
	}
	occ := newOccupancy(spans)
	for _, s := range spans {
		if occ.free(s.Start, s.End) {
			occ.take(s.Start, s.End)
			kept = append(kept, s)
		}
	}
	return kept
}

// resolvePairwise drops overlapping spans by comparing each candidate against
// everything kept so far.
func resolvePairwise(spans, kept []pd.Span) []pd.Span {
	for _, s := range spans {
		clash := false
		for _, k := range kept {
			if s.Overlaps(k) {
				clash = true
				break
			}
		}
		if !clash {
			kept = append(kept, s)
		}
	}
	return kept
}

// resolveOccupancyMin is where the bitmap starts paying for itself. Below it
// the pairwise loop wins outright: it allocates nothing, and a few hundred
// integer comparisons cost less than sizing a bitmap over the payload.
const resolveOccupancyMin = 48

// occupancy marks which bytes of the payload a kept span already claims.
//
// The pairwise loop it replaces compared every candidate against everything
// kept so far. Detectors mostly produce disjoint spans, so almost every
// candidate is kept and the loop is n²/2 comparisons: on a PD-dense 256 KiB
// chunk — a client list, a batch of forms — that is 8000 spans and ~70 ms
// spent purely on overlap resolution, more than every detector combined, per
// chunk, against a 16 ms per-request CPU budget. Early exit is impossible there
// because the candidates are ordered by LENGTH, not by position.
//
// A bitmap makes the same decision in time proportional to the bytes the spans
// cover instead of to the square of their number, and the ordering that decides
// who wins is untouched: the caller still feeds spans in priority order and the
// first claimant of a byte keeps it.
type occupancy struct {
	bits []uint64
	n    int // number of addressable byte positions
}

func newOccupancy(spans []pd.Span) *occupancy {
	max := 0
	for _, s := range spans {
		if s.End > max {
			max = s.End
		}
	}
	return &occupancy{bits: make([]uint64, max/64+1), n: max}
}

// free reports whether every byte of [start,end) is still unclaimed.
func (o *occupancy) free(start, end int) bool {
	if start < 0 {
		start = 0
	}
	if end > o.n {
		end = o.n
	}
	for i := start; i < end; i++ {
		if o.bits[i>>6]&(1<<uint(i&63)) != 0 {
			return false
		}
	}
	return true
}

// take claims [start,end).
func (o *occupancy) take(start, end int) {
	if start < 0 {
		start = 0
	}
	if end > o.n {
		end = o.n
	}
	for i := start; i < end; i++ {
		o.bits[i>>6] |= 1 << uint(i&63)
	}
}
