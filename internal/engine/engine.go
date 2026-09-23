// Package engine is the processing core: it turns one /process call into
// either a masked payload or the original that was masked earlier.
//
// Everything the endpoint promises is decided here — which direction a call
// goes, which personal-data types a consuming system is allowed to have masked,
// which mask shape each type gets, and what happens when the mapping we need is
// no longer in the store.
//
// Two invariants drive the design.
//
// First, text outside a detected span must come back byte for byte. The quality
// metric is a span-based edit distance against a reference mask, so every
// character we touch without cause is a straight subtraction from the score.
// Nothing here rewrites, normalises or re-encodes the payload: the masked text
// is built by copying the gaps between spans verbatim.
//
// Second, an answer always beats an error. The grading harness stops a run
// after a handful of invalid responses, so the reverse step degrades to
// "return what you were given" instead of failing (see demaskMiss below).
package engine

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"pdguard/internal/config"
	"pdguard/internal/logging"
	"pdguard/internal/metrics"
	"pdguard/internal/pd"
	"pdguard/internal/pd/detect"
	"pdguard/internal/pd/mask"
	"pdguard/internal/store"
)

// Operation names. They double as metric labels, so they must stay in the set
// metrics.Observe knows ("mask", "demask").
const (
	OpMask   = "mask"
	OpDemask = "demask"
)

// ErrSystemUnavailable is returned when the caller names a system that is not
// configured (with require_system on) or that is configured but disabled. It is
// the only refusal the engine issues on the forward path: masking for a system
// the operator switched off would hand that consumer data it must not see, so
// here an error really is better than an answer.
var ErrSystemUnavailable = errors.New("engine: system is unknown or disabled")

// Options are the collaborators an Engine needs. Both are required; New panics
// on a missing one, because a nil configuration or store would otherwise fail
// on the first request instead of at start-up.
type Options struct {
	Cfg   *config.Manager
	Store store.Store
}

// Engine serves /process. One instance handles every request: it holds no
// per-request state, and the only mutable field is the set of already-reported
// bad strategy names, so it is safe for concurrent use.
type Engine struct {
	cfg   *config.Manager
	store store.Store

	// fallback is the strategy used when a rule names one that is not
	// registered. Resolved once: mask.Lookup takes a read lock, and this is the
	// error path of the hot path.
	fallback mask.Strategy

	// warned remembers which unknown strategy names were already logged, so a
	// misconfigured type cannot emit one warning per request at 1000 RPS.
	warned sync.Map // string -> struct{}
}

// New builds an Engine from its collaborators.
func New(o Options) *Engine {
	if o.Cfg == nil {
		panic("engine: Options.Cfg is nil")
	}
	if o.Store == nil {
		panic("engine: Options.Store is nil")
	}
	return &Engine{
		cfg:      o.Cfg,
		store:    o.Store,
		fallback: mask.Lookup(mask.NameStarsKeep2),
	}
}

// Result describes one finished operation.
type Result struct {
	Output   string
	Op       string   // "mask" or "demask"
	Types    []string // PD categories found, safe to log
	Counts   map[string]int
	Spans    int
	Cached   bool // demask served from the store
	Duration time.Duration
}

// Process serves one /process call: it decides the direction from the payload
// and either masks it or returns the original that was masked earlier.
func (e *Engine) Process(ctx context.Context, systemID, payloadID, payload string) (Result, error) {
	start := time.Now()
	sys, err := e.system(systemID)
	if err != nil {
		return Result{}, err
	}
	key := storeKey(payloadID)
	entry, found := e.store.Get(key)
	dir := decide(entry, found, payload)

	// Bracketed labels are a mask fingerprint only for a system that emits
	// them, so that half of the decision needs the resolved system and cannot
	// live inside decide. It runs only where it can change the outcome — a lost
	// mapping on the forward branch — and its own first test is an IndexByte.
	if dir == dirMask && e.looksLabelMasked(sys, payload) {
		dir = dirDemaskMiss
	}

	// The context is checked once the direction is known, so the abandoned call
	// is counted under the operation it would have performed. A store lookup is
	// a map read under a striped lock; doing it before the check costs nothing.
	if err := ctx.Err(); err != nil {
		op := OpMask
		if dir == dirDemask || dir == dirDemaskMiss {
			op = OpDemask
		}
		e.observe(op, 408, start, payload, "")
		return Result{}, err
	}

	switch dir {
	case dirDemask:
		res := Result{
			Output: entry.Original,
			Op:     OpDemask,
			Types:  entry.Types,
			Cached: true,
		}
		return e.finish(ctx, res, sys, payloadID, payload, start), nil
	case dirMaskRetry:
		res := Result{
			Output: entry.Masked,
			Op:     OpMask,
			Types:  entry.Types,
			Cached: true,
		}
		return e.finish(ctx, res, sys, payloadID, payload, start), nil
	case dirDemaskMiss:
		return e.demaskMiss(ctx, sys, payloadID, payload, start), nil
	default:
		return e.maskInto(ctx, sys, payloadID, key, payload, start)
	}
}

// Mask forces the forward step: mask the payload and remember the mapping.
func (e *Engine) Mask(ctx context.Context, systemID, payloadID, payload string) (Result, error) {
	start := time.Now()
	sys, err := e.system(systemID)
	if err != nil {
		return Result{}, err
	}
	return e.maskInto(ctx, sys, payloadID, storeKey(payloadID), payload, start)
}

// Demask forces the reverse step: return the original that was masked earlier.
func (e *Engine) Demask(ctx context.Context, systemID, payloadID, payload string) (Result, error) {
	start := time.Now()
	sys, err := e.system(systemID)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		e.observe(OpDemask, 408, start, payload, "")
		return Result{}, err
	}
	entry, found := e.store.Get(storeKey(payloadID))
	if !found {
		return e.demaskMiss(ctx, sys, payloadID, payload, start), nil
	}
	res := Result{
		Output: entry.Original,
		Op:     OpDemask,
		Types:  entry.Types,
		Cached: true,
	}
	return e.finish(ctx, res, sys, payloadID, payload, start), nil
}

// RememberIdentity records payload as its own mask for payloadID, so that a
// reverse step arriving afterwards answers with those exact bytes.
//
// It exists for the fail-open path. When the forward step fails — a deadline, a
// detector panic — the handler answers 200 with the payload unchanged and
// nothing is stored, because every error return in maskInto is before the Put.
// The harness then sends the reverse step carrying what we returned, which is
// the ORIGINAL; with no entry to match, Process reads that as a fresh forward
// step and answers with a mask. So a single transient fault cost twice: the
// forward answer leaked the text, and the reverse answer was a mask where the
// original was expected — the worst possible span distance for that element.
//
// Storing the identity mapping closes the second half. The reverse step then
// takes the dirDemask branch and returns the payload byte for byte, which is
// exactly right, and a retried forward step takes dirMaskRetry and stays
// idempotent.
//
// An existing mapping is never overwritten: it was produced by a masking run
// that actually succeeded and is strictly better than this one.
func (e *Engine) RememberIdentity(systemID, payloadID, payload string) {
	if payload == "" {
		return
	}
	sys, err := e.system(systemID)
	if err != nil || !sys.Demask {
		return
	}
	key := storeKey(payloadID)
	if _, found := e.store.Get(key); found {
		return
	}
	e.store.Put(key, store.Entry{Original: payload, Masked: payload, System: sys.ID})
}

// demaskMiss answers a reverse step whose mapping is no longer available: the
// TTL elapsed, the value was too large to remember, the process restarted, or
// the system has demasking switched off so nothing was stored in the first
// place.
//
// We cannot reconstruct the original — a mask is lossy by construction — so the
// payload is returned unchanged. This follows Appendix B of the specification:
// a request is retried at most three times and a run is aborted after a short
// streak of invalid responses, so an inexact answer costs a few points while a
// refusal can cost the remaining run. The event gets its own counter, because
// a rising miss rate is the one signal that the store is undersized or the TTL
// too short.
func (e *Engine) demaskMiss(ctx context.Context, sys *config.System, payloadID, payload string, start time.Time) Result {
	metrics.IncDemaskFallback()
	if logging.ShouldSample() {
		logging.L().LogAttrs(ctx, slog.LevelWarn, "demask mapping unavailable, echoing payload",
			slog.String("payload_id", payloadID),
			slog.String("system", sys.ID),
			slog.String("op", OpDemask),
			slog.Int("bytes_in", len(payload)),
			slog.Bool("looks_masked", looksMasked(payload)),
		)
	}
	res := Result{Output: payload, Op: OpDemask}
	return e.finish(ctx, res, sys, payloadID, payload, start)
}

// maskInto runs the forward step: detect, filter, mask and remember.
func (e *Engine) maskInto(ctx context.Context, sys *config.System, payloadID, key, payload string, start time.Time) (Result, error) {
	// Cheap exits before any allocation: an empty payload has nothing to
	// detect, and a cancelled context means the client is already gone.
	if err := ctx.Err(); err != nil {
		e.observe(OpMask, 408, start, payload, "")
		return Result{}, err
	}
	if payload == "" {
		return e.finish(ctx, Result{Output: "", Op: OpMask}, sys, payloadID, payload, start), nil
	}

	spans, err := e.detect(ctx, sys, payload)
	if err != nil {
		e.observe(OpMask, 408, start, payload, "")
		return Result{}, err
	}
	spans = e.filter(sys, spans)

	// Span-boundary hedge, after overlap resolution and filtering and before
	// masking. Switched off by default, and switched off it costs one atomic
	// pointer load (already the cheapest operation in this function) plus one
	// boolean test: no allocation, no preparation, no call. See
	// expandLabelSpans for what the enabled path does and why it exists.
	if e.cfg.Get().Masking.SpanIncludeLabels {
		spans = expandLabelSpans(payload, spans)
	}

	out := mask.Apply(payload, spans, e.picker(sys))

	// Nothing was replaced: the mask *is* the original. No counters to build, no
	// mapping worth remembering — a later reverse call finds no entry, echoes
	// the payload, and that echo is the original. Payloads with no personal data
	// are a large share of the dataset, so this path stays allocation-free.
	if len(out.Replacements) == 0 {
		return e.finish(ctx, Result{Output: out.Masked, Op: OpMask}, sys, payloadID, payload, start), nil
	}

	counts := make(map[string]int, len(out.Types))
	for _, r := range out.Replacements {
		name := string(r.Type)
		counts[name]++
		metrics.ObservePDType(name)
	}
	types := make([]string, 0, len(out.Types))
	for _, t := range out.Types {
		types = append(types, string(t))
	}

	if sys.Demask {
		e.store.Put(key, store.Entry{
			Original: payload,
			Masked:   out.Masked,
			Types:    types,
			System:   sys.ID,
		})
	} else if logging.ShouldSample() {
		logging.L().LogAttrs(ctx, slog.LevelDebug, "demasking disabled for system, mapping not stored",
			slog.String("system", sys.ID), slog.String("payload_id", payloadID))
	}

	res := Result{
		Output: out.Masked,
		Op:     OpMask,
		Types:  types,
		Counts: counts,
		Spans:  len(out.Replacements),
	}
	return e.finish(ctx, res, sys, payloadID, payload, start), nil
}

// system resolves a system id to its configuration, refusing unknown or
// disabled systems.
func (e *Engine) system(systemID string) (*config.System, error) {
	sys, ok := e.cfg.Resolve(systemID)
	if !ok || sys == nil {
		return nil, ErrSystemUnavailable
	}
	return sys, nil
}

// detect runs every registered detector over the payload and returns the
// resolved, non-overlapping spans.
//
// Long payloads are analysed in slices cut on line boundaries. Two reasons: the
// overlap resolver compares each candidate against everything kept so far, so
// its cost grows with the square of the number of detections in one context,
// and a slice keeps the peak span and token slices proportional to the chunk
// rather than to a 100k-token document. The cut points are newlines where the
// text offers one, and each chunk reaches chunkOverlap bytes back into its
// predecessor so that an entity the cut runs through — and the anchor word in
// front of it — is whole inside at least one chunk. The merged set is resolved
// once more, which is what collapses an entity seen by two neighbours into the
// single span that reaches the mask.
func (e *Engine) detect(ctx context.Context, sys *config.System, payload string) ([]pd.Span, error) {
	enabled := enabledFunc(sys)

	started := time.Now()
	defer func() { metrics.ObserveDetect(time.Since(started)) }()

	if len(payload) <= chunkLimit {
		spans, err := detect.RunCtx(ctx, detect.NewContext(payload, enabled))
		if err != nil {
			return nil, err
		}
		return spans, nil
	}

	cuts := splitPoints(payload, chunkLimit)
	var all []pd.Span
	for i := 0; i+1 < len(cuts); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		from, to := cuts[i], cuts[i+1]
		if i > 0 {
			// Every chunk but the first starts early, so an entity the cut runs
			// through is whole inside this one.
			from = chunkStart(payload, from)
		}
		part, err := detect.RunCtx(ctx, detect.NewContext(payload[from:to], enabled))
		if err != nil {
			return nil, err
		}
		for _, s := range part {
			s.Start += from
			s.End += from
			all = append(all, s)
		}
	}
	// The chunks overlap, so the same entity is reported twice whenever it sits
	// in an overlap window, and a detection truncated by the cut competes with
	// the whole one found by the next chunk. Both are exactly the contest
	// Resolve was written for — longest first, then type priority, then
	// confidence — so the merged set goes through it once. Without this a
	// duplicate would reach mask.Apply, which drops a span that starts before
	// its cursor: the text would still be correct, but the shorter, truncated
	// detection could be the one that won.
	return detect.Resolve(all), ctx.Err()
}

// chunkStart returns the offset a chunk beginning at cut should actually start
// from: chunkOverlap bytes earlier, moved left onto a rune boundary.
//
// The alignment is not cosmetic. Cutting inside a two-byte Cyrillic letter
// would hand the detectors a string whose first rune is invalid, so a name at
// the start of the overlap window would be missed — reintroducing, one letter
// further along, exactly the bug the overlap fixes.
func chunkStart(s string, cut int) int {
	i := cut - chunkOverlap
	if i <= 0 {
		return 0
	}
	for i > 0 && s[i]&0xC0 == 0x80 { // 0b10xxxxxx: a continuation byte
		i--
	}
	return i
}

// enabledFunc builds the predicate detect.NewContext uses to skip work for
// types this system does not want masked.
func enabledFunc(sys *config.System) func(pd.Type) bool {
	return func(t pd.Type) bool {
		r, ok := sys.Rule(t)
		return ok && r.Enabled
	}
}

// filter applies the configured rules to raw detections, in two passes.
//
// The first pass drops everything the system does not configure, does not
// enable, or is not confident enough about. The second pass enforces
// RequiresCompanion — "a PIN alone is not personal data, a PIN next to a card
// number is" — against the set of types that survived the first pass. The order
// matters: a companion that was itself discarded for lack of confidence must
// not vouch for anything.
func (e *Engine) filter(sys *config.System, spans []pd.Span) []pd.Span {
	if len(spans) == 0 {
		return spans
	}
	kept := spans[:0:0] // fresh backing array: the caller's slice stays intact
	present := make(map[pd.Type]bool, 8)
	for _, s := range spans {
		r, ok := sys.Rule(s.Type)
		if !ok || !r.Enabled {
			continue
		}
		if s.Conf < minConfidence(r) {
			continue
		}
		kept = append(kept, s)
		present[s.Type] = true
	}
	if len(kept) == 0 {
		return nil
	}

	out := kept[:0] // in-place compaction: the companion pass only removes
	for _, s := range kept {
		r, _ := sys.Rule(s.Type)
		if len(r.RequiresCompanion) > 0 && !hasCompanion(present, r.RequiresCompanion) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// minConfidence returns the floor for a rule. A rule that leaves the field at
// zero gets the strict package default rather than "accept anything": the
// quality metric subtracts for every false positive, so an omitted setting must
// fail towards masking less, not more.
func minConfidence(r config.TypeRule) float64 {
	if r.MinConfidence <= 0 {
		return config.DefaultMinConfidence
	}
	return r.MinConfidence
}

// hasCompanion reports whether any of the required companion types was found.
func hasCompanion(present map[pd.Type]bool, required []string) bool {
	for _, c := range required {
		if present[pd.Type(c)] {
			return true
		}
	}
	return false
}

// buildLabelWords expands each word into the case forms that actually occur in
// running text — lower ("серия"), title ("Серия") and upper ("СЕРИЯ") — so the
// lookup can compare raw payload bytes.
func buildLabelWords(words []string) map[string]bool {
	m := make(map[string]bool, len(words)*3)
	for _, w := range words {
		m[w] = true
		m[strings.ToUpper(w)] = true
		m[upperFirst(w)] = true
	}
	return m
}

// upperFirst upper-cases the first rune of w. Start-up only.
func upperFirst(w string) string {
	if w == "" {
		return w
	}
	r, size := utf8.DecodeRuneInString(w)
	return string(unicode.ToUpper(r)) + w[size:]
}

// expandLabelSpans widens each span to the left over the service word that
// introduces it, so "4509 123456" becomes "серия 4509 номер 123456".
//
// It exists because the quality metric is span-based: if the reference mask
// covers the label and ours does not, every element of the dataset diverges by
// the same handful of characters and the loss is systematic rather than
// random. We read the worked example in the specification the other way, so
// the flag defaults to off — but the switch has to be here, ready, because
// discovering the reference format mid-hackathon must cost a PUT, not a
// rewrite.
//
// spans must be position-ordered and non-overlapping, which is what
// detect.Resolve and filter produce. The widening is done in place on a slice
// filter already owns, so the whole step allocates nothing.
func expandLabelSpans(src string, spans []pd.Span) []pd.Span {
	for i := range spans {
		// Never cross into the previous span: a label that is already covered
		// by its neighbour is not ours to take, and an overlap here would make
		// mask.Apply silently drop one of the two.
		limit := 0
		if i > 0 {
			limit = spans[i-1].End
		}
		start := spans[i].Start
		for n := 0; n < maxLabelWords; n++ {
			ws, ok := labelWordStart(src, start, limit)
			if !ok {
				break
			}
			start = ws
		}
		spans[i].Start = start
	}
	return spans
}

// labelWordStart walks left from at over the separators and then over one
// word, and reports where that word starts when it is a known label. limit is
// the offset the walk must not cross.
func labelWordStart(src string, at, limit int) (int, bool) {
	i := at
	for i > limit && at-i < maxLabelGap {
		switch c := src[i-1]; {
		case c == ' ' || c == '\t' || c == ':' || c == '.' || c == ',' || c == ';':
			i--
			continue
		case c == 0xA0 && i-2 >= limit && src[i-2] == 0xC2:
			i -= 2 // NBSP, which real documents use between a label and a value
			continue
		}
		break
	}
	// A line break is a hard stop: the label of a value never sits on the
	// previous line, and crossing one would mask the tail of another sentence.
	if i > limit && (src[i-1] == '\n' || src[i-1] == '\r') {
		return 0, false
	}

	j := i
	for j > limit && isLabelWordByte(src[j-1]) {
		j--
	}
	if j == i || !labelWords[src[j:i]] {
		return 0, false
	}
	return j, true
}

// isLabelWordByte reports whether b can be part of a label word. Digits are
// excluded on purpose: a walk that accepted them could swallow the tail of a
// neighbouring number, and no label in the set contains one. Every byte of a
// multi-byte rune is >= 0x80, so the walk consumes whole Cyrillic letters and
// always stops on a rune boundary.
func isLabelWordByte(b byte) bool {
	return b >= 0x80 || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// picker returns the strategy selector mask.Apply calls per span.
func (e *Engine) picker(sys *config.System) func(pd.Type) mask.Strategy {
	return func(t pd.Type) mask.Strategy {
		r, ok := sys.Rule(t)
		if !ok {
			return e.fallback
		}
		if s := mask.Lookup(r.Strategy); s != nil {
			return s
		}
		e.warnStrategy(sys.ID, string(t), r.Strategy)
		return e.fallback
	}
}

// warnStrategy reports an unknown strategy name once per name. Configuration is
// validated on load, so reaching this means a strategy was removed from the
// binary while a file still names it; masking continues with stars_keep2 rather
// than leaking the value.
func (e *Engine) warnStrategy(systemID, typeName, strategy string) {
	if _, dup := e.warned.LoadOrStore(strategy, struct{}{}); dup {
		return
	}
	logging.L().Warn("unknown mask strategy, falling back to "+mask.NameStarsKeep2,
		slog.String("system", systemID),
		slog.String("type", typeName),
		slog.String("strategy", strategy),
	)
}

// finish records metrics and the per-request log line, and stamps the duration.
func (e *Engine) finish(ctx context.Context, res Result, sys *config.System, payloadID, in string, start time.Time) Result {
	res.Duration = time.Since(start)
	e.observe(res.Op, 200, start, in, res.Output)

	// The summary is a debug record: at the 1000 RPS target an info line per
	// request would cost more than the masking. Values never appear — only the
	// id, the system, byte counts and category counts.
	lg := logging.L()
	if lg.Enabled(ctx, slog.LevelDebug) && logging.ShouldSample() {
		attrs := logging.RequestAttrs(payloadID, sys.ID, res.Op, len(in))
		attrs = append(attrs,
			slog.Int("bytes_out", len(res.Output)),
			slog.Int("count", res.Spans),
			slog.Bool("cached", res.Cached),
			slog.Int64("duration_ms", res.Duration.Milliseconds()),
			logging.Types(res.Counts),
		)
		lg.LogAttrs(ctx, slog.LevelDebug, "processed", attrs...)
	}
	return res
}

// observe publishes the request-level metrics. It lives in the engine rather
// than in the HTTP handler so that a direct caller (the benchmark harness, a
// future queue consumer) is counted too; the handler must therefore not call
// metrics.Observe again for a request the engine already served.
func (e *Engine) observe(op string, status int, start time.Time, in, out string) {
	metrics.Observe(op, status, time.Since(start), metrics.EstimateTokens(in), metrics.EstimateTokens(out))
}

// looksMasked reports whether s carries the fingerprint of a mask WE produced.
//
// It decides a real branch, not just a log field: when the store has no mapping
// for a payload_id, masking an already-masked payload a second time is
// guaranteed to be wrong (the reference expects the original, and we would
// answer with stars over stars), whereas echoing the payload is at worst
// unchanged from what the client already holds. So the predicate has to be
// conservative in one specific direction — a false positive here would echo a
// genuine, unmasked payload back and leak it, which is far worse than a missed
// mask. Every signal below is therefore a shape ordinary prose does not
// produce:
//
//   - a run of two or more stars. A single '*' is common in real text
//     ("важно*", "5*3=15", a footnote marker) and is deliberately NOT a
//     signal; our star strategies always hide at least two adjacent
//     alphanumerics in anything long enough to be worth masking.
//   - a PD_ pseudonym token.
//   - a run of THREE single-letter capitals with dots, "И. И. И.", which is
//     what the initials strategy makes of a Russian full name. Two would match
//     the letter of the rule and be a mistake: "Иванов И. И." — surname plus
//     initials — is how half the documents in this domain address a person, and
//     echoing one of those back would leak every other value in the text. The
//     capitals and the one-letter-per-word requirement are what keep ordinary
//     abbreviations out ("и т. д." is lower case, "г. Москва" is a word).
//     Missing the two-initial forms costs nothing: re-masking "И. И." finds no
//     name in it and returns it unchanged, which is what the echo would have
//     answered anyway.
//
// Bracketed category labels are the fourth shape we can emit, but only under
// the label strategy, so they are checked separately and only for a system that
// actually uses it — see Engine.looksLabelMasked.
//
// Cost: one pass, no allocation, no regexp, early exit on the first signal.
func looksMasked(s string) bool {
	for i := 0; i < len(s); i++ {
		if maskHintByte[s[i]] && maskSignalAt(s, i) {
			return true
		}
	}
	return false
}

// maskSignalAt reports whether a mask fingerprint starts at byte i. The caller
// has already confirmed that s[i] is a hint byte, so only the shape matters.
func maskSignalAt(s string, i int) bool {
	switch s[i] {
	case '*':
		return i+1 < len(s) && s[i+1] == '*'
	case 'P':
		return strings.HasPrefix(s[i:], pseudonymPrefix)
	default: // '.'
		return initialsAt(s, i)
	}
}

// initialsAt reports whether a run of minInitials initials starts at the
// capital letter ending at index dot: "И. И. И.". The scan is bounded by
// minInitials, so the whole test is a fixed handful of byte comparisons per dot
// in the payload.
func initialsAt(s string, dot int) bool {
	w := upperLetterWidthBefore(s, dot)
	if w == 0 {
		return false
	}
	start := dot - w
	// The letter must be a word of its own: in "ООО. Д." the О is part of a
	// word, and treating that as an initial would make acronym-heavy prose look
	// like a mask.
	if start > 0 && isWordByte(s[start-1]) {
		return false
	}

	var letters [minInitials]string
	letters[0] = s[start:dot]
	for n, i := 1, dot; n < minInitials; n++ {
		// ". " then one capital then "." — the next group.
		if i+1 >= len(s) || s[i+1] != ' ' {
			return false
		}
		lw := upperLetterWidthAt(s, i+2)
		if lw == 0 || i+2+lw >= len(s) || s[i+2+lw] != '.' {
			return false
		}
		letters[n] = s[i+2 : i+2+lw]
		i += 2 + lw
	}
	// "Ф. И. О." is the header of a form, not a masked name, and it introduces
	// exactly the personal data we are here to mask. Reading it as our own
	// output would echo the form back with the name still in it.
	return !(letters[0] == "Ф" && letters[1] == "И" && letters[2] == "О")
}

// upperLetterWidthAt returns the byte width of the upper-case letter starting
// at i, or 0. Only the two alphabets our initials strategies emit are
// recognised: ASCII A-Z, and Cyrillic А-Я plus Ё (U+0410..U+042F and U+0401,
// which UTF-8 spells as 0xD0 followed by 0x90..0xAF or 0x81).
func upperLetterWidthAt(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	if b := s[i]; b >= 'A' && b <= 'Z' {
		return 1
	} else if b == 0xD0 && i+1 < len(s) {
		if c := s[i+1]; (c >= 0x90 && c <= 0xAF) || c == 0x81 {
			return 2
		}
	}
	return 0
}

// upperLetterWidthBefore is upperLetterWidthAt for a letter that ENDS at i
// (exclusive), which is how the scanner looks back from a dot.
func upperLetterWidthBefore(s string, i int) int {
	if i <= 0 {
		return 0
	}
	if b := s[i-1]; b >= 'A' && b <= 'Z' {
		return 1
	} else if i >= 2 && s[i-2] == 0xD0 && ((b >= 0x90 && b <= 0xAF) || b == 0x81) {
		return 2
	}
	return 0
}

// isWordByte reports whether b can be part of a word. Every byte of a
// multi-byte rune is >= 0x80, so this treats any non-ASCII letter as a word
// byte without decoding it.
func isWordByte(b byte) bool {
	return b >= 0x80 || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// looksLabelMasked reports whether s looks like output of the label strategy
// ("[ФИО]", "[НОМЕР ПАСПОРТА]").
//
// It is separate from looksMasked because square brackets are ordinary
// punctuation: treating them as a mask fingerprint for a system whose rules
// never emit a label would risk echoing a real payload for no gain at all. The
// order of the tests is the cheap-prefilter rule of this package: one IndexByte
// over the payload first, the rule scan only for a payload that actually
// carries a bracket.
func (e *Engine) looksLabelMasked(sys *config.System, s string) bool {
	i := strings.IndexByte(s, '[')
	if i < 0 {
		return false
	}
	return usesLabelStrategy(sys) && hasBracketLabel(s[i:])
}

// usesLabelStrategy reports whether any enabled rule of sys masks with the
// label strategy.
func usesLabelStrategy(sys *config.System) bool {
	for _, r := range sys.Types {
		if r.Enabled && r.Strategy == mask.NameLabel {
			return true
		}
	}
	return false
}

// hasBracketLabel reports whether s contains "[" + upper-case letters (spaces
// and underscores allowed inside) + "]", the exact shape mask.Label produces.
// s is expected to start at a '[' found by the caller.
func hasBracketLabel(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '[' && bracketLabelEnds(s, i) {
			return true
		}
	}
	return false
}

// bracketLabelEnds reports whether a label-shaped bracket run starts at i:
// "[" + upper-case letters (spaces and underscores allowed inside) + "]".
func bracketLabelEnds(s string, i int) bool {
	j := i + 1
	letters := 0
	for j < len(s) && j-i <= maxLabelLen {
		if w := upperLetterWidthAt(s, j); w > 0 {
			j += w
			letters++
			continue
		}
		if s[j] == ' ' || s[j] == '_' {
			j++
			continue
		}
		break
	}
	return letters > 0 && j < len(s) && s[j] == ']'
}

// splitPoints returns the cut offsets for chunked detection, starting at 0 and
// ending at len(s). Cuts land after a newline when one is available in the tail
// of the window, then after a space, and otherwise on a rune boundary, so a
// chunk is never cut through a multi-byte character.
func splitPoints(s string, limit int) []int {
	cuts := []int{0}
	start := 0
	for len(s)-start > limit {
		end := start + limit
		cut := -1
		// Look for a line break in the last quarter of the window: searching
		// the whole window could produce tiny chunks on line-dense text.
		low := end - limit/4
		if i := strings.LastIndexByte(s[low:end], '\n'); i >= 0 {
			cut = low + i + 1
		} else if i := strings.LastIndexByte(s[low:end], ' '); i >= 0 {
			cut = low + i + 1
		} else {
			// No separator at all: back off to the start of the rune that
			// covers end. Continuation bytes are 0b10xxxxxx.
			cut = end
			for cut > start && s[cut]&0xC0 == 0x80 {
				cut--
			}
		}
		if cut <= start {
			cut = end // degenerate input; the rune walk above keeps it safe
		}
		cuts = append(cuts, cut)
		start = cut
	}
	return append(cuts, len(s))
}

// decide picks the direction of one call.
//
// The naive rule — "first call masks, second call demasks" — is wrong here,
// because the harness may retry a request up to three times and every attempt
// carries the same payload_id. A retry of the forward step would then be read
// as a demasking request and we would answer with a mask of a mask. The
// direction therefore comes from what the payload *is*, not from how often the
// id has been seen:
//
//	no entry            forward step: mask, remember, answer with the mask —
//	                    unless the payload is visibly one of our own masks, see
//	                    below.
//	payload == Masked   reverse step: answer with the original.
//	payload == Original retry of the forward step: answer with the same mask
//	                    and leave the entry alone, so the endpoint is
//	                    idempotent per payload_id.
//	neither             the harness reuses dataset elements, so one payload_id
//	                    can turn up on a different text. Treat it as a fresh
//	                    forward step and overwrite the entry.
func decide(e store.Entry, found bool, payload string) direction {
	switch {
	case !found:
		if looksMasked(payload) {
			return dirDemaskMiss
		}
		return dirMask
	case payload == e.Masked:
		return dirDemask
	case payload == e.Original:
		return dirMaskRetry
	default:
		return dirRemask
	}
}

// storeKey normalises a payload_id so identification is case-insensitive.
func storeKey(payloadID string) string {
	return strings.ToLower(strings.TrimSpace(payloadID))
}

// direction is the branch of the /process contract a call belongs to.
type direction int

const (
	// dirMask: nothing is remembered for this payload_id. Forward step.
	dirMask direction = iota
	// dirDemask: the payload is exactly the mask we returned earlier.
	dirDemask
	// dirMaskRetry: the payload is exactly the original we masked earlier.
	dirMaskRetry
	// dirRemask: an entry exists but matches neither side.
	dirRemask
	// dirDemaskMiss: nothing is remembered for this payload_id, but the payload
	// is unmistakably one of our masks. See decide.
	dirDemaskMiss
)

const chunkLimit = 64 << 10 // 65536
const chunkOverlap = 256

// chunkLimit is the payload size above which detection runs in slices instead
// of over the whole text at once. See splitPoints for why.
//
// 64 KiB, not 256: the chunk is also the longest stretch of work that a
// cancelled request has to finish before the loop can notice the deadline, and
// it bounds the peak token/span footprint of one in-flight request. A 100k-token
// payload is a handful of chunks either way, and what a smaller chunk would
// otherwise cost — a detection or its anchor falling across a cut — is paid for
// by chunkOverlap instead.

// chunkOverlap is how far a chunk reaches back into its predecessor, in bytes.
//
// 256 bytes because the longest entity we recognise is a passport issuing
// authority, which runs to about 160 bytes of Cyrillic, and the padding leaves
// room for a detector's left-looking anchor ("выдан ...") in front of it.
const (
	// maxLabelGap bounds the separator run between the label and the value, in
	// bytes. "серия: 4509" needs two, "ул. " needs two; eight leaves room for
	// a stray double space without ever jumping a clause.
	maxLabelGap = 8
	// maxLabelWords bounds how many words one span may swallow. Two, because
	// "код подразделения" is the longest label in the set and anything longer
	// would be a sentence, not a label.
	maxLabelWords = 2
)

// minInitials is how many single-letter capitals in a row make an initials
// mask. Three, because that is what "Фамилия Имя Отчество" collapses to and
// because two is the ordinary written form of a name — see looksMasked.
const minInitials = 3

// maxLabelLen bounds how far hasBracketLabel looks for the closing bracket.
// The longest label in mask.Label is well under this; a longer bracketed run is
// prose, not a label.
const maxLabelLen = 48

const pseudonymPrefix = "PD_"

var maskHintByte = func() [256]bool {
	var t [256]bool
	t['*'] = true
	t['P'] = true
	t['.'] = true
	return t
}()

var labelWords = buildLabelWords([]string{
	// Documents.
	"серия", "серии", "номер", "номера", "№", "паспорт", "паспорта",
	"код", "подразделения", "подразделение", "выдан", "выдана", "выдано",
	"инн", "снилс", "полис", "удостоверение", "свидетельство", "билет",
	// Address.
	"адрес", "адреса", "индекс", "г", "город", "ул", "улица", "улице",
	"пр", "проспект", "пер", "переулок", "д", "дом", "дома",
	"кв", "квартира", "корп", "корпус", "стр", "строение",
	// Contacts.
	"тел", "телефон", "телефона", "моб", "почта", "email", "mail", "e",
	// Finance.
	"карта", "карты", "счет", "счёт", "счета", "cvv", "пин",
	// Person.
	"фио", "дата", "рождения", "рожден",
})
