package detect

import (
	"regexp"
	"strings"
	"sync/atomic"

	"pdguard/internal/pd"
	"pdguard/internal/pd/text"
)

// CustomType is one user-defined personal-data type, described entirely in
// configuration. The engine compiles the pattern and lower-cases the anchors
// before publishing a snapshot through SetCustomTypes.
type CustomType struct {
	// Name is the wire identifier of the type.
	Name string
	// Pattern is the compiled regular expression matched against the payload.
	Pattern *regexp.Regexp
	// Anchors are lower-cased cue words that must stand within AnchorWindow
	// bytes to the left of a match for it to be accepted.
	Anchors []string
	// AnchorWindow is how far left of a match an anchor word is accepted.
	AnchorWindow int
	// Strategy is the mask strategy name applied to this type.
	Strategy string
	// Label is the bracketed label used when Strategy is "label".
	Label string
	// MinConfidence is the confidence floor.
	MinConfidence float64
}

// customTypes is the atomic snapshot of the current user-defined types. The
// engine publishes it on load and on every configuration apply, so the detector
// always sees the latest set without any lock on the request path.
var customTypes atomic.Pointer[[]CustomType]

// SetCustomTypes publishes the current set of user-defined types. The engine
// calls it on load and on every configuration apply.
func SetCustomTypes(types []CustomType) {
	cp := append([]CustomType(nil), types...)
	customTypes.Store(&cp)
}

// customSnapshot returns the current user-defined types, or nil when none are
// configured.
func customSnapshot() []CustomType {
	p := customTypes.Load()
	if p == nil {
		return nil
	}
	return *p
}

// customDetector finds user-defined personal-data types. It is stateless: the
// per-request set of types comes from the atomic snapshot.
type customDetector struct{}

// Name identifies the detector in logs and in Span.Src.
func (customDetector) Name() string { return "custom" }

// Types is dynamic — the set is configuration-driven — so it reports nothing.
func (customDetector) Types() []pd.Type { return nil }

// Detect matches every configured custom pattern and applies the anchor rule.
// A custom type is the lowest-priority detection: when its span overlaps a
// built-in detector's span, Resolve keeps the built-in one because a built-in
// type always outranks the default priority of a custom type.
func (customDetector) Detect(ctx *Context) []pd.Span {
	types := customSnapshot()
	if len(types) == 0 {
		return nil
	}
	var out []pd.Span
	for _, ct := range types {
		if !ctx.Enabled(pd.Type(ct.Name)) {
			continue
		}
		for _, loc := range ct.Pattern.FindAllStringIndex(ctx.Text, -1) {
			start, end := loc[0], loc[1]
			if len(ct.Anchors) > 0 && !customAnchorWithin(ctx.Lower, start, ct.Anchors, ct.AnchorWindow) {
				continue
			}
			out = append(out, pd.Span{
				Start: start, End: end,
				Type: pd.Type(ct.Name), Conf: 0.9, Src: "custom",
			})
		}
	}
	return out
}

func init() { Register(customDetector{}) }

// customAnchorWithin reports whether any anchor word stands within window bytes
// to the left of offset before, matched case-insensitively at word boundaries.
func customAnchorWithin(lower string, before int, anchors []string, window int) bool {
	from := before - window
	if from < 0 {
		from = 0
	}
	win := lower[from:before]
	for _, a := range anchors {
		for off := 0; off < len(win); {
			i := strings.Index(win[off:], a)
			if i < 0 {
				break
			}
			abs := from + off + i
			end := abs + len(a)
			if text.IsBoundary(lower, abs) && text.IsBoundary(lower, end) {
				return true
			}
			off += i + 1
		}
	}
	return false
}
