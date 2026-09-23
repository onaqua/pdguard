package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/metrics"
	"pdguard/internal/pd"
	"pdguard/internal/store"
)

const (
	engOpFmt      = "op = %q, want %q"
	engProcessFmt = "Process: %v"
	engMaskFmt    = "Mask: %v"
)

// Payloads used across the tests. They were chosen against the real detectors
// (see the confidences quoted in the comments) so a test failure points at the
// engine, not at a detector that happens to disagree about a sample.
const (
	// One name, one card and one phone; every type well above the default floor.
	pdPayload = "Клиент Иванов Иван Иванович, карта 4276 1600 1234 5678, телефон +7 916 123-45-67."
	// A second, different text for the "payload_id reused" branch.
	pdPayloadAlt = "Почта клиента: ivan.petrov@example.com"
	// Contains no client data at all: a branch address and opening hours. The
	// specification names exactly this as a false positive to avoid.
	cleanPayload = "Отделение банка на улице Ленина работает с 9 до 18."
	// CARD_NUMBER alone, detected at conf 0.85 (anchored, not Luhn-valid).
	cardPayload = "Оплата картой 4276 1600 1234 5678 прошла успешно."
	// PIN alone, detected at conf 0.93; masked by default, dropped only when
	// the requires_companion rule is enabled.
	pinOnlyPayload = "ПИН-код 1234 менять раз в год."
	pinCardPayload = "Карта 4276 1600 1234 5678, ПИН-код 1234."
)

// newEngine builds an engine on the shipped defaults with an isolated store.
// The sweeper is disabled (negative interval) so no background goroutine can
// expire an entry while a test is comparing counters.
func newEngine(t *testing.T) (*Engine, store.Store) {
	t.Helper()
	return newEngineWith(t, nil)
}

// newEngineWith applies edit to the default configuration before starting.
func newEngineWith(t *testing.T, edit func(*config.Config)) (*Engine, store.Store) {
	t.Helper()
	mgr, err := config.Load("") // empty path: built-in defaults, nothing persisted
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if edit != nil {
		c := mgr.Get().Clone()
		edit(c)
		if err := mgr.Apply(c); err != nil {
			t.Fatalf("config.Apply: %v", err)
		}
	}
	st := store.New(store.Config{
		Shards:        8,
		TTL:           time.Minute,
		MaxEntries:    1024,
		MaxValueBytes: 1 << 20,
		SweepInterval: -1,
	})
	t.Cleanup(st.Close)
	return New(Options{Cfg: mgr, Store: st}), st
}

// setRule rewrites one type rule of the default system.
func setRule(c *config.Config, t pd.Type, edit func(*config.TypeRule)) {
	sys := c.Systems["default"]
	r := sys.Types[string(t)]
	edit(&r)
	sys.Types[string(t)] = r
}

func mustProcess(t *testing.T, e *Engine, id, payload string) Result {
	t.Helper()
	res, err := e.Process(context.Background(), "", id, payload)
	if err != nil {
		t.Fatalf("Process(%q): unexpected error: %v", id, err)
	}
	return res
}

// ---------------------------------------------------------------------------
// The five branches of the direction decision. Each one gets its own test,
// because picking the wrong branch is the single most expensive bug available
// in this service: it turns a valid answer into a mask of a mask.
// ---------------------------------------------------------------------------

// Branch 1: no entry for the id -> forward step.
func TestDirectionFirstCallMasks(t *testing.T) {
	e, st := newEngine(t)

	res := mustProcess(t, e, "p1", pdPayload)
	if res.Op != OpMask {
		t.Fatalf(engOpFmt, res.Op, OpMask)
	}
	if res.Cached {
		t.Error("first call reported Cached")
	}
	if res.Output == pdPayload {
		t.Fatal("payload with personal data came back unchanged")
	}
	if res.Spans == 0 || len(res.Types) == 0 {
		t.Fatalf("no spans reported: %+v", res)
	}
	entry, ok := st.Get("p1")
	if !ok {
		t.Fatal("mapping was not stored")
	}
	if entry.Original != pdPayload || entry.Masked != res.Output {
		t.Error("stored mapping does not match what was returned")
	}
}

// Branch 2: the payload is the mask we returned -> reverse step.
func TestDirectionSecondCallDemasks(t *testing.T) {
	e, _ := newEngine(t)

	masked := mustProcess(t, e, "p2", pdPayload)
	back := mustProcess(t, e, "p2", masked.Output)

	if back.Op != OpDemask {
		t.Fatalf(engOpFmt, back.Op, OpDemask)
	}
	if !back.Cached {
		t.Error("demasking from the store did not report Cached")
	}
	if back.Output != pdPayload {
		t.Errorf("demasked output differs from the original:\n got %q\nwant %q", back.Output, pdPayload)
	}
}

// Branch 3: the payload is the original we already masked -> retry of the
// forward step. The answer must be identical and the entry untouched.
func TestDirectionRetryIsIdempotent(t *testing.T) {
	e, st := newEngine(t)

	first := mustProcess(t, e, "p3", pdPayload)
	puts := st.Stats().Puts

	for attempt := 2; attempt <= 3; attempt++ { // the harness retries up to 3 times
		again := mustProcess(t, e, "p3", pdPayload)
		if again.Output != first.Output {
			t.Fatalf("attempt %d returned a different mask:\n got %q\nwant %q", attempt, again.Output, first.Output)
		}
		if again.Op != OpMask {
			t.Errorf("attempt %d: op = %q, want %q", attempt, again.Op, OpMask)
		}
		if !again.Cached {
			t.Errorf("attempt %d: retry was not served from the store", attempt)
		}
	}
	if got := st.Stats().Puts; got != puts {
		t.Errorf("retries rewrote the mapping: puts %d -> %d", puts, got)
	}
	// And the reverse step still works after the retries.
	back := mustProcess(t, e, "p3", first.Output)
	if back.Output != pdPayload {
		t.Errorf("demask after retries returned %q", back.Output)
	}
}

// Branch 4: the id is reused for a different element -> mask again, overwrite.
func TestDirectionReusedIDRemasks(t *testing.T) {
	e, st := newEngine(t)

	first := mustProcess(t, e, "p4", pdPayload)
	second := mustProcess(t, e, "p4", pdPayloadAlt)

	if second.Op != OpMask {
		t.Fatalf(engOpFmt, second.Op, OpMask)
	}
	if second.Cached {
		t.Error("a fresh masking reported Cached")
	}
	if second.Output == first.Output {
		t.Fatal("the second element produced the first element's mask")
	}
	entry, ok := st.Get("p4")
	if !ok {
		t.Fatal("mapping disappeared")
	}
	if entry.Original != pdPayloadAlt {
		t.Error("the entry was not overwritten with the new element")
	}
	// The reverse step now answers for the new element.
	back := mustProcess(t, e, "p4", second.Output)
	if back.Output != pdPayloadAlt {
		t.Errorf("demask returned %q, want %q", back.Output, pdPayloadAlt)
	}
}

// Branch 5: a reverse step whose mapping is gone. We must answer, not fail.
func TestDirectionDemaskMissEchoesPayload(t *testing.T) {
	e, _ := newEngine(t)

	before := metrics.DemaskFallbacks()
	masked := "Клиент Ив** Ив** Ив**, карта 42** **** **** **78."

	res, err := e.Demask(context.Background(), "", "never-seen", masked)
	if err != nil {
		t.Fatalf("Demask must never fail on a missing mapping: %v", err)
	}
	if res.Output != masked {
		t.Errorf("output = %q, want the payload unchanged", res.Output)
	}
	if res.Cached {
		t.Error("an echoed answer reported Cached")
	}
	if got := metrics.DemaskFallbacks() - before; got != 1 {
		t.Errorf("fallback counter moved by %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// The "mask only in company" rule is an opt-in: when requires_companion is set
// for a type, a lone value is not masked, but a value next to its companion is.
func TestRequiresCompanion(t *testing.T) {
	e, _ := newEngineWith(t, func(c *config.Config) {
		setRule(c, pd.TypePIN, func(r *config.TypeRule) {
			r.RequiresCompanion = []string{string(pd.TypeCardNumber)}
		})
	})

	alone := mustProcess(t, e, "c1", pinOnlyPayload)
	if alone.Output != pinOnlyPayload {
		t.Errorf("a lone PIN was masked:\n got %q\nwant %q", alone.Output, pinOnlyPayload)
	}
	if n, ok := alone.Counts[string(pd.TypePIN)]; ok {
		t.Errorf("a lone PIN was counted %d times", n)
	}

	together := mustProcess(t, e, "c2", pinCardPayload)
	if n := together.Counts[string(pd.TypePIN)]; n != 1 {
		t.Fatalf("PIN next to a card was masked %d times, want 1: %q", n, together.Output)
	}
	if strings.Contains(together.Output, "1234,") || strings.HasSuffix(together.Output, "1234.") {
		t.Errorf("the PIN digits survived masking: %q", together.Output)
	}
}

// A companion that is itself dropped for lack of confidence must not vouch for
// anything: the confidence filter has to run first.
func TestCompanionMustSurviveConfidenceFirst(t *testing.T) {
	e, _ := newEngineWith(t, func(c *config.Config) {
		// The card in pinCardPayload is detected at 0.85; this floor drops it.
		setRule(c, pd.TypeCardNumber, func(r *config.TypeRule) { r.MinConfidence = 0.95 })
		// The companion rule is opt-in; enable it to exercise the ordering.
		setRule(c, pd.TypePIN, func(r *config.TypeRule) {
			r.RequiresCompanion = []string{string(pd.TypeCardNumber)}
		})
	})

	res := mustProcess(t, e, "c3", pinCardPayload)
	if _, ok := res.Counts[string(pd.TypePIN)]; ok {
		t.Errorf("the PIN was masked although its companion had been filtered out: %q", res.Output)
	}
	if res.Output != pinCardPayload {
		t.Errorf("output changed although every detection was filtered:\n got %q\nwant %q", res.Output, pinCardPayload)
	}
}

func TestMinConfidenceFloor(t *testing.T) {
	// The card is detected at 0.85: it passes the default 0.7 floor.
	e, _ := newEngine(t)
	masked := mustProcess(t, e, "m1", cardPayload)
	if masked.Output == cardPayload {
		t.Fatalf("card was not masked at the default floor: %q", masked.Output)
	}

	// Raised above the detector's confidence, the same card must survive intact.
	strict, _ := newEngineWith(t, func(c *config.Config) {
		setRule(c, pd.TypeCardNumber, func(r *config.TypeRule) { r.MinConfidence = 0.9 })
	})
	kept := mustProcess(t, strict, "m2", cardPayload)
	if kept.Output != cardPayload {
		t.Errorf("a detection below the floor was masked:\n got %q\nwant %q", kept.Output, cardPayload)
	}
	if kept.Spans != 0 {
		t.Errorf("spans = %d, want 0", kept.Spans)
	}
}

func TestDisabledTypeIsNotMasked(t *testing.T) {
	e, _ := newEngineWith(t, func(c *config.Config) {
		setRule(c, pd.TypeCardNumber, func(r *config.TypeRule) { r.Enabled = false })
	})
	res := mustProcess(t, e, "d1", cardPayload)
	if res.Output != cardPayload {
		t.Errorf("a disabled type was masked:\n got %q\nwant %q", res.Output, cardPayload)
	}
}

// With demasking switched off for a system, nothing is remembered, so the
// reverse step degrades to an echo instead of handing back the original.
func TestDemaskDisabledSystemStoresNothing(t *testing.T) {
	e, st := newEngine(t) // "analytics" ships with demask: false

	res, err := e.Process(context.Background(), "analytics", "a1", pdPayload)
	if err != nil {
		t.Fatalf(engProcessFmt, err)
	}
	if res.Output == pdPayload {
		t.Fatal("masking did nothing")
	}
	if _, ok := st.Get("a1"); ok {
		t.Error("a mapping was stored for a system that may not demask")
	}
	back, err := e.Process(context.Background(), "analytics", "a1", res.Output)
	if err != nil {
		t.Fatalf("reverse Process: %v", err)
	}
	// No mapping, so the masked text goes through the forward path again. What
	// matters is that the original is not revealed and the call still answers.
	if strings.Contains(back.Output, "Иванов Иван Иванович") {
		t.Error("the original leaked to a system that may not demask")
	}
}

func TestUnknownSystemIsRefusedOnlyWhenRequired(t *testing.T) {
	// Default configuration: an unknown id falls back to the default system.
	e, _ := newEngine(t)
	if _, err := e.Process(context.Background(), "no-such-system", "u1", cleanPayload); err != nil {
		t.Fatalf("unknown system must fall back to the default: %v", err)
	}

	strict, _ := newEngineWith(t, func(c *config.Config) { c.RequireSystem = true })
	if _, err := strict.Process(context.Background(), "no-such-system", "u2", cleanPayload); err != ErrSystemUnavailable {
		t.Fatalf("err = %v, want ErrSystemUnavailable", err)
	}
}

// ---------------------------------------------------------------------------
// Payload handling
// ---------------------------------------------------------------------------

// The quality metric is an edit distance against a reference mask, so text
// outside personal data must come back byte for byte. This is the single most
// important assertion in the package.
func TestTextWithoutPDIsByteIdentical(t *testing.T) {
	e, st := newEngine(t)

	for _, in := range []string{
		cleanPayload,
		"Поэт Александр Пушкин — классик русской литературы.",
		"Договор № 12 от прошлого года, сумма 15000 рублей.",
		"Just a plain English sentence, nothing personal here.",
		"Строка с эмодзи 🙂 и табом\tи переводом строки\n",
	} {
		res := mustProcess(t, e, "bb-"+in[:4], in)
		if res.Output != in {
			t.Errorf("payload without personal data was altered:\n got %q\nwant %q", res.Output, in)
		}
		if res.Spans != 0 {
			t.Errorf("%q: spans = %d, want 0", in, res.Spans)
		}
	}
	if st.Len() != 0 {
		t.Errorf("no-op maskings were stored: %d entries", st.Len())
	}
}

func TestEmptyPayload(t *testing.T) {
	e, st := newEngine(t)

	res, err := e.Process(context.Background(), "", "e1", "")
	if err != nil {
		t.Fatalf("empty payload must not fail: %v", err)
	}
	if res.Output != "" {
		t.Errorf("output = %q, want empty", res.Output)
	}
	if res.Op != OpMask || res.Spans != 0 {
		t.Errorf("unexpected result %+v", res)
	}
	if st.Len() != 0 {
		t.Error("an empty payload was remembered")
	}
	// A second call must behave the same way: nothing was stored, so this is
	// another forward step and it must still answer.
	if again, err := e.Process(context.Background(), "", "e1", ""); err != nil || again.Output != "" {
		t.Errorf("second call: %q, %v", again.Output, err)
	}
}

func TestCanceledContext(t *testing.T) {
	e, _ := newEngine(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := e.Process(ctx, "", "x1", pdPayload); err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// A deadline that has already passed must be reported too.
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	if _, err := e.Process(dctx, "", "x2", pdPayload); err != context.DeadlineExceeded {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}

	// The reverse step is abandoned as well, even though it would be served
	// from the store: the caller is gone either way.
	masked := mustProcess(t, e, "x3", pdPayload)
	if _, err := e.Process(ctx, "", "x3", masked.Output); err != context.Canceled {
		t.Fatalf("reverse Process: err = %v, want context.Canceled", err)
	}
	if _, err := e.Demask(ctx, "", "x3", masked.Output); err != context.Canceled {
		t.Fatalf("Demask: err = %v, want context.Canceled", err)
	}
}

// payload_id identification is case-insensitive, so a retry that re-cases the
// id still finds its mapping.
func TestPayloadIDIsCaseInsensitive(t *testing.T) {
	e, _ := newEngine(t)

	masked := mustProcess(t, e, "Req-42", pdPayload)
	back := mustProcess(t, e, "  rEq-42 ", masked.Output)
	if back.Output != pdPayload {
		t.Errorf("re-cased id did not find the mapping: got %q", back.Output)
	}
}

// Long payloads are analysed in chunks; the round trip must stay exact and the
// text between detections untouched.
func TestLongPayloadRoundTrip(t *testing.T) {
	e, _ := newEngine(t)

	var sb strings.Builder
	filler := "Обычный текст без персональных данных в этой строке.\n"
	for sb.Len() < chunkLimit+64<<10 {
		sb.WriteString(filler)
		if sb.Len()%7919 < len(filler) { // sprinkle some personal data around
			sb.WriteString(pdPayload)
			sb.WriteString("\n")
		}
	}
	long := sb.String()
	if len(long) <= chunkLimit {
		t.Fatalf("test payload is only %d bytes", len(long))
	}

	masked := mustProcess(t, e, "long", long)
	if masked.Spans == 0 {
		t.Fatal("no personal data found in the long payload")
	}
	if strings.Contains(masked.Output, "Иванов Иван Иванович") {
		t.Error("a name survived masking in the chunked path")
	}
	if strings.Count(masked.Output, filler) != strings.Count(long, filler) {
		t.Error("filler text was altered by chunked masking")
	}
	back := mustProcess(t, e, "long", masked.Output)
	if back.Output != long {
		t.Error("the long payload did not survive the round trip")
	}
}

func TestSplitPointsCoverInputOnRuneBoundaries(t *testing.T) {
	src := strings.Repeat("абвгд ежзий\n", 5000) // multi-byte, with separators
	for _, limit := range []int{64, 1000, 4096} {
		checkSplitPoints(t, src, limit)
	}
}

// checkSplitPoints verifies that splitPoints for one limit covers the whole
// input, never lands inside a rune, and reassembles the original text.
func checkSplitPoints(t *testing.T, src string, limit int) {
	t.Helper()
	cuts := splitPoints(src, limit)
	if cuts[0] != 0 || cuts[len(cuts)-1] != len(src) {
		t.Fatalf("limit %d: cuts do not span the input: %v..%v", limit, cuts[0], cuts[len(cuts)-1])
	}
	var joined strings.Builder
	for i := 0; i+1 < len(cuts); i++ {
		from, to := cuts[i], cuts[i+1]
		if to <= from {
			t.Fatalf("limit %d: non-increasing cut %d..%d", limit, from, to)
		}
		if src[from]&0xC0 == 0x80 {
			t.Fatalf("limit %d: cut at %d lands inside a rune", limit, from)
		}
		joined.WriteString(src[from:to])
	}
	if joined.String() != src {
		t.Fatalf("limit %d: chunks do not reassemble the input", limit)
	}
}

// Mask and Demask force a direction; Process derives it. They must agree.
func TestExplicitDirectionsMatchProcess(t *testing.T) {
	e, _ := newEngine(t)

	viaProcess := mustProcess(t, e, "x", pdPayload)
	viaMask, err := e.Mask(context.Background(), "", "y", pdPayload)
	if err != nil {
		t.Fatalf(engMaskFmt, err)
	}
	if viaMask.Output != viaProcess.Output {
		t.Errorf("Mask and Process disagree:\n %q\n %q", viaMask.Output, viaProcess.Output)
	}
	back, err := e.Demask(context.Background(), "", "y", viaMask.Output)
	if err != nil {
		t.Fatalf("Demask: %v", err)
	}
	if back.Output != pdPayload {
		t.Errorf("Demask returned %q", back.Output)
	}
	if back.Op != OpDemask || !back.Cached {
		t.Errorf("unexpected demask result %+v", back)
	}
}

// Masking is deterministic: the same text always produces the same mask, which
// is what makes a retry served without the store still consistent.
func TestMaskingIsDeterministic(t *testing.T) {
	e, _ := newEngine(t)
	other, _ := newEngine(t)

	a, err := e.Mask(context.Background(), "", "k1", pdPayload)
	if err != nil {
		t.Fatalf(engMaskFmt, err)
	}
	b, err := other.Mask(context.Background(), "", "k2", pdPayload)
	if err != nil {
		t.Fatalf(engMaskFmt, err)
	}
	if a.Output != b.Output {
		t.Errorf("two engines produced different masks:\n %q\n %q", a.Output, b.Output)
	}
}

func TestConcurrentProcessIsSafe(t *testing.T) {
	e, _ := newEngine(t)

	const workers = 16
	done := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			res, err := e.Process(context.Background(), "", "shared", pdPayload)
			if err != nil {
				done <- "error: " + err.Error()
				return
			}
			done <- res.Output
		}()
	}
	first := <-done
	for i := 1; i < workers; i++ {
		if got := <-done; got != first {
			t.Fatalf("concurrent masking disagreed:\n %q\n %q", got, first)
		}
	}
	if strings.HasPrefix(first, "error: ") {
		t.Fatal(first)
	}
}

// TestBirthDateAfterNameSurvivesTheFloor covers a branch that was dead for
// roughly two dates in five.
//
// "A date straight after a full name is a birth date" is scored at one fixed
// confidence, and a date whose day and month are both 12 or less costs an
// ambiguity penalty on top. The confidence was set exactly at the configured
// floor, so every such date fell below it and was never masked — while the same
// sentence with a day above 12 was. The engine is the right place to test it:
// the floor lives in the configuration, not in the detector.
func TestBirthDateAfterNameSurvivesTheFloor(t *testing.T) {
	eng, _ := newEngine(t)
	for _, in := range []string{
		"Иванов Иван Иванович 25.05.1990",
		"Иванов Иван Иванович 12.05.1990",
		"Иванов Иван Иванович, 01.02.1985, паспорт 4509 123456",
		"Петров Пётр Петрович 03.03.1975 проживает в Москве",
	} {
		res, err := eng.Mask(context.Background(), "", "id", in)
		if err != nil {
			t.Fatalf("Mask(%q): %v", in, err)
		}
		if !hasType(res.Types, string(pd.TypeBirthDate)) {
			t.Errorf("%q: BIRTH_DATE not detected, types = %v", in, res.Types)
		}
	}
}

func hasType(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// TestMaskPropagatesCancellation checks the engine end of the deadline the
// HTTP layer attaches. The cancellation point inside detection itself is
// covered by detect.TestRunCtxStopsOnCancellation.
func TestMaskPropagatesCancellation(t *testing.T) {
	eng, _ := newEngine(t)
	// Long enough that detection cannot possibly finish between the cancel and
	// the first check.
	payload := strings.Repeat(pdPayload+"\n", 4000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := eng.Mask(ctx, "", "id", payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("Mask on a cancelled context: err = %v, want context.Canceled", err)
	}
}

// TestRememberIdentityMakesFailOpenReversible covers the second half of the
// fail-open trade-off. Answering 200 with the untouched payload was deliberate;
// what was not deliberate is that the reverse step then found no mapping, read
// the original as fresh input and answered with a MASK — the furthest possible
// answer from the expected original.
func TestRememberIdentityMakesFailOpenReversible(t *testing.T) {
	eng, _ := newEngine(t)
	const id = "failed-forward-step"

	// The forward step failed, so the handler echoed the payload and recorded
	// the identity mapping.
	eng.RememberIdentity("", id, pdPayload)

	res, err := eng.Process(context.Background(), "", id, pdPayload)
	if err != nil {
		t.Fatalf(engProcessFmt, err)
	}
	if res.Output != pdPayload {
		t.Fatalf("reverse step returned %q, want the payload byte for byte", res.Output)
	}

	// A mapping that a successful masking run already produced outranks this
	// one and must not be replaced.
	eng2, _ := newEngine(t)
	masked, err := eng2.Mask(context.Background(), "", id, pdPayload)
	if err != nil {
		t.Fatalf(engMaskFmt, err)
	}
	eng2.RememberIdentity("", id, pdPayload)
	back, err := eng2.Process(context.Background(), "", id, masked.Output)
	if err != nil {
		t.Fatalf(engProcessFmt, err)
	}
	if back.Output != pdPayload {
		t.Fatalf("demask returned %q, want the original", back.Output)
	}
}
