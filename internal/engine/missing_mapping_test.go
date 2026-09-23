package engine

// The reverse step is the deterministic half of the score: either we still
// hold the original or the element is lost. The tests here cover what happens
// when the mapping is NOT there — which used to be "mask the mask", the one
// answer that is guaranteed wrong — and, just as importantly, that ordinary
// text is never mistaken for a mask on the way in.

import (
	"context"
	"strings"
	"testing"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/pd"
	"pdguard/internal/pd/mask"
	"pdguard/internal/store"
)

const mmConfigLoadFmt = "config.Load: %v"

// newEngineDefaultStore builds an engine on a store with the SHIPPED limits,
// which is the point of the oversize test: the bug was a default that could
// not hold what the server accepts.
func newEngineDefaultStore(t *testing.T) (*Engine, store.Store) {
	t.Helper()
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf(mmConfigLoadFmt, err)
	}
	st := store.New(store.Config{SweepInterval: -1})
	t.Cleanup(st.Close)
	return New(Options{Cfg: mgr, Store: st}), st
}

// bigPayload returns n bytes or so of realistic text carrying personal data,
// so the masking path really runs rather than short-circuiting on "nothing
// detected".
func bigPayload(n int) string {
	unit := "Клиент Иванов Иван Иванович, карта 4276 1600 1234 5678, телефон +7 916 123-45-67. " +
		"Обычный текст без персональных данных, чтобы объём был похож на настоящий документ. "
	var sb strings.Builder
	sb.Grow(n + len(unit))
	for sb.Len() < n {
		sb.WriteString(unit)
	}
	return sb.String()
}

// TestDemaskOversizedPayload is the regression test for the defect that made
// demasking fail silently above the store's per-value limit: Put dropped the
// record, the reverse step found nothing, and the engine masked the mask. A
// 3 MiB payload is inside what the server accepts, so it must round-trip.
func TestDemaskOversizedPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-megabyte payload")
	}
	e, st := newEngineDefaultStore(t)

	original := bigPayload(3 << 20)
	masked := mustProcess(t, e, "big", original)
	if masked.Op != OpMask {
		t.Fatalf("op = %q, want %q", masked.Op, OpMask)
	}
	if masked.Output == original {
		t.Fatal("a 3 MiB payload full of personal data came back unchanged")
	}
	if got := st.Stats().Skipped; got != 0 {
		t.Fatalf("store refused %d put(s): the mapping for a payload we accepted was dropped", got)
	}

	back := mustProcess(t, e, "big", masked.Output)
	if back.Op != OpDemask {
		t.Fatalf("reverse op = %q, want %q", back.Op, OpDemask)
	}
	if back.Output != original {
		t.Fatalf("reverse step is not byte-exact: %d bytes in, %d bytes out",
			len(original), len(back.Output))
	}
}

// TestStoreRemembersEverythingTheServerAccepts states the invariant the defect
// violated, in the two places that have to agree on it.
func TestStoreRemembersEverythingTheServerAccepts(t *testing.T) {
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf(mmConfigLoadFmt, err)
	}
	c := mgr.Get()
	// A JSON body escaping Cyrillic as \uXXXX is about three times the size of
	// the UTF-8 text inside it, so the decoded payload cannot exceed a third of
	// the body limit — that is the margin the store has to cover.
	if want := c.Server.MaxBodyBytes / 3; int64(c.Store.MaxValueBytes) < want {
		t.Fatalf("store.max_value_bytes = %d cannot hold the largest accepted body (%d) once decoded: want >= %d",
			c.Store.MaxValueBytes, c.Server.MaxBodyBytes, want)
	}
	if def := store.DefaultConfig(); def.MaxValueBytes < c.Store.MaxValueBytes {
		t.Fatalf("store package default MaxValueBytes = %d is below the configured %d",
			def.MaxValueBytes, c.Store.MaxValueBytes)
	}
}

// TestDemaskMissEchoesMaskedText covers the branch itself: the mapping is gone
// (expired, evicted, a restart) and the payload is our own mask. The answer
// must be that mask, unchanged — not a mask of a mask.
func TestDemaskMissEchoesMaskedText(t *testing.T) {
	e, st := newEngine(t)

	masked := mustProcess(t, e, "gone", pdPayload)
	if masked.Spans == 0 {
		t.Fatal("the sample payload was not masked at all")
	}
	st.Delete("gone")

	back := mustProcess(t, e, "gone", masked.Output)
	if back.Op != OpDemask {
		t.Fatalf("op = %q, want %q: a lost mapping must not turn into a forward step", back.Op, OpDemask)
	}
	if back.Output != masked.Output {
		t.Fatalf("the mask was rewritten instead of echoed:\n in: %q\nout: %q", masked.Output, back.Output)
	}
	if back.Spans != 0 {
		t.Fatalf("Spans = %d: the echo path must not mask anything", back.Spans)
	}
	// Nothing was remembered either: storing the mask as its own original would
	// make a later retry answer with a mask where the original was expected.
	if _, ok := st.Get("gone"); ok {
		t.Fatal("the echo path stored a mapping from a mask to itself")
	}
}

// TestDemaskMissEchoesOversizedMask is the two defects meeting: a payload too
// large for the store still has to survive the reverse step, because the
// echo is the backstop for whatever the raised limits do not cover.
func TestDemaskMissEchoesOversizedMask(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-megabyte payload")
	}
	// A store that refuses everything interesting, which is what the shipped
	// configuration used to do to a 2.5 MiB text.
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf(mmConfigLoadFmt, err)
	}
	st := store.New(store.Config{MaxValueBytes: 1 << 10, SweepInterval: -1})
	t.Cleanup(st.Close)
	e := New(Options{Cfg: mgr, Store: st})

	original := bigPayload(1 << 20)
	masked := mustProcess(t, e, "toobig", original)
	if _, ok := st.Get("toobig"); ok {
		t.Fatal("the store was supposed to refuse this payload; the test proves nothing")
	}

	back := mustProcess(t, e, "toobig", masked.Output)
	if back.Op != OpDemask || back.Output != masked.Output {
		t.Fatalf("op = %q, echoed = %v: an unrememberable mask must come back unchanged, not re-masked",
			back.Op, back.Output == masked.Output)
	}
}

// TestLooksMaskedNegatives is the guard on the other side of the branch. Stars,
// dots and capitals occur in ordinary writing, and a payload wrongly read as a
// mask would be echoed back UNMASKED — a leak, and the most expensive possible
// answer on the forward step. Every string here must still be masked normally.
func TestLooksMaskedNegatives(t *testing.T) {
	plain := []string{
		"важно*",
		"5*3=15",
		"*примечание к договору",
		"ставка 5.5*2 процента",
		"и т. д., и т. п.",
		"г. Москва, ул. Вавилова",
		"ООО «Ромашка», ИНН см. договор",
		"Сноска* поясняет условия",
		// The two forms that make the "three initials" rule necessary: both are
		// ordinary Russian document writing and both carry personal data that
		// an echo would leak.
		"Директор Иванов И. И. утвердил порядок",
		"Ф. И. О.: Иванов Иван Иванович",
	}
	for _, s := range plain {
		if looksMasked(s) {
			t.Errorf("looksMasked(%q) = true: ordinary text would be echoed instead of masked", s)
		}
	}

	masked := []string{
		"45** ****56",
		"телефон +7 9** ***-**-67",
		"PD_FIO_a1b2c3",
		"Клиент И. И. И., счёт открыт",
		"A. B. C. — три инициала латиницей",
	}
	for _, s := range masked {
		if !looksMasked(s) {
			t.Errorf("looksMasked(%q) = false: our own mask would be masked a second time", s)
		}
	}
}

// TestPlainTextWithStarsIsStillMasked runs the negatives through the whole
// engine rather than through the predicate alone: the branch, not the helper,
// is what can leak.
func TestPlainTextWithStarsIsStillMasked(t *testing.T) {
	e, _ := newEngine(t)

	cases := []string{
		"важно* Иванов Иван Иванович, телефон +7 916 123-45-67",
		"5*3=15, карта 4276 1600 1234 5678",
		"*примечание: почта ivan.petrov@example.com",
		"и т. д. — клиент Петров Пётр Петрович",
	}
	for i, in := range cases {
		res := mustProcess(t, e, "plain-"+string(rune('a'+i)), in)
		if res.Op != OpMask {
			t.Errorf("%q: op = %q, want %q", in, res.Op, OpMask)
		}
		if res.Output == in {
			t.Errorf("%q came back unchanged: it was mistaken for a mask", in)
		}
	}
}

// TestLabelMaskIsRecognisedOnlyWhereLabelsAreUsed pins the config-gated half of
// the decision. Square brackets are ordinary punctuation, so they may only
// count as a mask fingerprint for a system that actually emits labels.
func TestLabelMaskIsRecognisedOnlyWhereLabelsAreUsed(t *testing.T) {
	const labelled = "Клиент [ФИО], телефон [ТЕЛЕФОН]."

	// Default configuration: no rule uses the label strategy, so this is just
	// text and the forward step must run.
	e, _ := newEngine(t)
	if e.looksLabelMasked(mustSystem(t, e, "default"), labelled) {
		t.Error("bracketed text counted as a mask for a system that never emits labels")
	}

	// A system whose FIO rule masks with labels: now the same text is our own
	// output and a lost mapping must echo it.
	le, st := newEngineWith(t, func(c *config.Config) {
		setRule(c, pd.TypeFIO, func(r *config.TypeRule) { r.Strategy = mask.NameLabel })
		setRule(c, pd.TypePhone, func(r *config.TypeRule) { r.Strategy = mask.NameLabel })
	})
	if !le.looksLabelMasked(mustSystem(t, le, "default"), labelled) {
		t.Fatal("a label-masking system did not recognise its own output")
	}
	res := mustProcess(t, le, "lbl", labelled)
	if res.Op != OpDemask || res.Output != labelled {
		t.Fatalf("op = %q, output changed = %v: a label mask with no mapping must be echoed",
			res.Op, res.Output != labelled)
	}
	if _, ok := st.Get("lbl"); ok {
		t.Error("the echo path stored a mapping")
	}
}

func mustSystem(t *testing.T, e *Engine, id string) *config.System {
	t.Helper()
	sys, err := e.system(id)
	if err != nil {
		t.Fatalf("system(%q): %v", id, err)
	}
	return sys
}

// TestDemaskMissIsCountedNotErrored keeps the degradation observable: the
// answer is a 200 either way, so the counter is the only place a shrinking
// store shows up.
func TestDemaskMissIsCountedNotErrored(t *testing.T) {
	e, st := newEngine(t)
	masked := mustProcess(t, e, "count", pdPayload)
	st.Delete("count")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := e.Process(ctx, "", "count", masked.Output); err != nil {
		t.Fatalf("a lost mapping must not be an error: %v", err)
	}
}

// BenchmarkLooksMasked measures what the branch costs on the forward path: the
// predicate runs over every payload that has no mapping yet, which is every
// first request of a pair, so it has to be a scan and nothing more.
func BenchmarkLooksMasked(b *testing.B) {
	txt := bigPayload(1000) // about the size the latency budget is quoted at
	b.ReportAllocs()
	b.SetBytes(int64(len(txt)))
	for i := 0; i < b.N; i++ {
		if looksMasked(txt) {
			b.Fatal("the benchmark payload must not look masked")
		}
	}
}
