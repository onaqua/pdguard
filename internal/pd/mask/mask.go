// Package mask turns detected spans into a masked payload and can restore the
// original from the recorded replacements. Masking strategies are pluggable so
// the output shape can be retuned from configuration without touching code.
package mask

import (
	"sort"
	"strings"
	"sync"

	"pdguard/internal/pd"
)

// Strategy renders the replacement text for one detected value.
// Implementations MUST be deterministic: the same input always yields the same
// mask, otherwise a retried request would return a different answer.
type Strategy interface {
	// Name is the identifier used in configuration files.
	Name() string
	// Mask renders the replacement for original, which is the exact substring
	// the detector matched. t is provided so one strategy can serve several
	// types with small variations.
	Mask(original string, t pd.Type) string
}

var (
	stratMu sync.RWMutex
	strats  = map[string]Strategy{}
)

// RegisterStrategy publishes a strategy under its name. Call from init().
func RegisterStrategy(s Strategy) {
	stratMu.Lock()
	defer stratMu.Unlock()
	if _, dup := strats[s.Name()]; dup {
		panic("mask: duplicate strategy name " + s.Name())
	}
	strats[s.Name()] = s
}

// Lookup returns a strategy by name, or nil when it is unknown.
func Lookup(name string) Strategy {
	stratMu.RLock()
	defer stratMu.RUnlock()
	return strats[name]
}

// StrategyNames lists every registered strategy, for /admin/config discovery.
func StrategyNames() []string {
	stratMu.RLock()
	defer stratMu.RUnlock()
	out := make([]string, 0, len(strats))
	for n := range strats {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Replacement records one substitution so it can be undone exactly.
type Replacement struct {
	Type      pd.Type `json:"type"`
	OrigStart int     `json:"orig_start"` // byte offsets into the original text
	OrigEnd   int     `json:"orig_end"`
	MaskStart int     `json:"mask_start"` // byte offsets into the masked text
	MaskEnd   int     `json:"mask_end"`
	Original  string  `json:"-"` // never serialised: this is the protected value
	Masked    string  `json:"masked"`
}

// Result is the outcome of masking one payload.
type Result struct {
	Masked       string
	Replacements []Replacement
	// Types lists the distinct PD categories found, in first-seen order. Safe
	// to log: it names categories, never values.
	Types []pd.Type
}

// Apply rewrites src, replacing every span with the mask produced by the
// strategy pick returns for that span's type. Spans must be non-overlapping;
// Apply sorts them by position and skips any residual overlap defensively.
// A nil strategy from pick leaves that span untouched.
func Apply(src string, spans []pd.Span, pick func(pd.Type) Strategy) Result {
	if len(spans) == 0 {
		return Result{Masked: src}
	}

	ordered := make([]pd.Span, len(spans))
	copy(ordered, spans)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Start < ordered[j].Start })

	var sb strings.Builder
	sb.Grow(len(src) + len(ordered)*8)

	reps := make([]Replacement, 0, len(ordered))
	seen := make(map[pd.Type]bool, len(ordered))
	types := make([]pd.Type, 0, 8)
	cursor := 0

	for _, s := range ordered {
		if s.Start < cursor || s.Start < 0 || s.End > len(src) || s.Start >= s.End {
			continue // overlapping or out-of-range: drop rather than corrupt the text
		}

		st := pick(s.Type)
		if st == nil {
			continue
		}

		original := src[s.Start:s.End]
		masked := st.Mask(original, s.Type)

		sb.WriteString(src[cursor:s.Start])
		maskStart := sb.Len()
		sb.WriteString(masked)
		maskEnd := sb.Len()
		cursor = s.End

		reps = append(reps, Replacement{
			Type:      s.Type,
			OrigStart: s.Start,
			OrigEnd:   s.End,
			MaskStart: maskStart,
			MaskEnd:   maskEnd,
			Original:  original,
			Masked:    masked,
		})

		if !seen[s.Type] {
			seen[s.Type] = true
			types = append(types, s.Type)
		}
	}

	sb.WriteString(src[cursor:])
	return Result{Masked: sb.String(), Replacements: reps, Types: types}
}

// Restore rebuilds the original text from a masked payload and the
// replacements recorded when it was produced. It is used as a fallback when
// the stored original is unavailable; the primary demasking path returns the
// stored original verbatim, which is exact by construction.
func Restore(masked string, reps []Replacement) string {
	if len(reps) == 0 {
		return masked
	}

	ordered := make([]Replacement, len(reps))
	copy(ordered, reps)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].MaskStart < ordered[j].MaskStart })

	var sb strings.Builder
	sb.Grow(len(masked) + 32)

	cursor := 0
	for _, r := range ordered {
		if r.MaskStart < cursor || r.MaskEnd > len(masked) || r.MaskStart >= r.MaskEnd {
			continue
		}
		sb.WriteString(masked[cursor:r.MaskStart])
		sb.WriteString(r.Original)
		cursor = r.MaskEnd
	}
	sb.WriteString(masked[cursor:])
	return sb.String()
}

// Label returns the bracketed Russian label for a type, e.g. "[ТЕЛЕФОН]".
// Unknown types get the generic "[ПД]" so a new category can never surface a
// raw value just because its label was forgotten.
func Label(t pd.Type) string {
	if l, ok := typeLabels[t]; ok {
		return l
	}
	return "[ПД]"
}
