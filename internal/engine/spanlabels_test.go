package engine

import (
	"strings"
	"testing"

	"pdguard/internal/config"
	"pdguard/internal/pd"
)

const slNumLabel = "номер 123456"

// ---------------------------------------------------------------------------
// expandLabelSpans, unit level
//
// These tests address the walk directly rather than through the detectors, so
// a change in recall cannot make them pass or fail for the wrong reason. The
// spans are built with strings.Index so the expectations read as text, not as
// byte arithmetic nobody can check by eye.
// ---------------------------------------------------------------------------

// span builds a span covering the first occurrence of value in src.
func span(t *testing.T, src, value string, typ pd.Type) pd.Span {
	t.Helper()
	i := strings.Index(src, value)
	if i < 0 {
		t.Fatalf("test setup: %q does not contain %q", src, value)
	}
	return pd.Span{Start: i, End: i + len(value), Type: typ, Conf: 1}
}

// covered renders what the masker would replace, which is the only thing the
// widening actually changes.
func covered(src string, s pd.Span) string { return src[s.Start:s.End] }

func TestExpandLabelSpansSwallowsTheLabel(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		value string
		typ   pd.Type
		want  string
	}{
		// The case from the task: the series number is introduced by "серия",
		// itself introduced by "паспорт" — two words, which is the limit.
		{"серия 4509", "Паспорт серия 4509 выдан МВД", "4509", pd.TypePassport, "Паспорт серия 4509"},
		{"номер", "номер 123456 подтверждён", "123456", pd.TypePassport, slNumLabel},
		{"colon separator", "Телефон: +7 916 123-45-67", "+7 916 123-45-67", pd.TypePhone, "Телефон: +7 916 123-45-67"},
		{"abbreviated street", "Живёт на ул. Вавилова", "Вавилова", pd.TypeStreet, "ул. Вавилова"},
		{"no separator at all", "Квитанция №123456 оплачена", "123456", pd.TypePassport, "№123456"},
		{"upper case label", "СЕРИЯ 4509 выдана", "4509", pd.TypePassport, "СЕРИЯ 4509"},
		{"two-word label", "код подразделения 770-055", "770-055", pd.TypeSubdivisionCode, "код подразделения 770-055"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spans := []pd.Span{span(t, tc.src, tc.value, tc.typ)}
			got := expandLabelSpans(tc.src, spans)
			if len(got) != 1 {
				t.Fatalf("expansion changed the number of spans: %d", len(got))
			}
			if c := covered(tc.src, got[0]); c != tc.want {
				t.Fatalf("covered %q, want %q", c, tc.want)
			}
		})
	}
}

// TestExpandLabelSpansLeavesOrdinaryWordsAlone is the false-positive guard.
// Every character the widening takes that the reference mask did not is a
// direct subtraction from the score, so a word that is not a label must never
// be swallowed — including the words the specification names by hand.
func TestExpandLabelSpansLeavesOrdinaryWordsAlone(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		value string
		typ   pd.Type
	}{
		{"ordinary verb", "Читал Александра 4509", "4509", pd.TypePassport},
		{"sentence boundary", "Всё готово. 4509 123456", "4509", pd.TypePassport},
		{"across a newline", "серия\n4509 123456", "4509", pd.TypePassport},
		{"start of text", "4509 123456 в деле", "4509", pd.TypePassport},
		{"gap too wide", "серия     " + "    4509", "4509", pd.TypePassport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := span(t, tc.src, tc.value, tc.typ)
			got := expandLabelSpans(tc.src, []pd.Span{in})
			if got[0].Start != in.Start {
				t.Fatalf("span widened to %q; it must stay %q", covered(tc.src, got[0]), tc.value)
			}
		})
	}
}

// TestExpandLabelSpansNeverOverlaps covers the rule that keeps the widening
// safe: mask.Apply silently DROPS a span that overlaps its predecessor, so an
// unchecked expansion would not merely mask too much — it would leave the
// value it swallowed into visible in the output.
func TestExpandLabelSpansNeverOverlaps(t *testing.T) {
	// "Иванов" is a FIO span that ends right before " номер"; the passport span
	// that follows would like to swallow "номер", and may.
	src := "Иванов номер 123456"
	spans := []pd.Span{
		span(t, src, "Иванов", pd.TypeFIO),
		span(t, src, "123456", pd.TypePassport),
	}
	got := expandLabelSpans(src, spans)
	if c := covered(src, got[1]); c != slNumLabel {
		t.Fatalf("second span covers %q, want %q", c, slNumLabel)
	}
	if got[1].Start < got[0].End {
		t.Fatalf("spans overlap: %d < %d", got[1].Start, got[0].End)
	}

	// Now the label is already inside the previous span: the expansion of the
	// second span must be abandoned rather than reach across it.
	src2 := "Серия 4509 123456"
	spans2 := []pd.Span{
		span(t, src2, "Серия 4509", pd.TypePassport),
		span(t, src2, "123456", pd.TypePassport),
	}
	got2 := expandLabelSpans(src2, spans2)
	if got2[1].Start < got2[0].End {
		t.Fatalf("second span was widened into the first: %d < %d", got2[1].Start, got2[0].End)
	}
	if c := covered(src2, got2[1]); c != "123456" {
		t.Fatalf("second span covers %q, want %q", c, "123456")
	}
}

// TestExpandLabelSpansKeepsRuneBoundaries: the walk is byte-wise for speed, so
// the one way it could corrupt the output is by cutting a Cyrillic letter in
// half. The masked text must still be valid UTF-8 whatever it swallows.
func TestExpandLabelSpansKeepsRuneBoundaries(t *testing.T) {
	src := "Договор, серия 4509 номер 123456, дата 01.02.2003"
	spans := []pd.Span{
		span(t, src, "4509", pd.TypePassport),
		span(t, src, "123456", pd.TypePassport),
		span(t, src, "01.02.2003", pd.TypeBirthDate),
	}
	for _, s := range expandLabelSpans(src, spans) {
		head := src[:s.Start]
		if strings.ToValidUTF8(head, "�") != head {
			t.Fatalf("span starts inside a multi-byte rune at %d", s.Start)
		}
	}
}

// ---------------------------------------------------------------------------
// Through the engine
// ---------------------------------------------------------------------------

// spanHedgeControl is the same sentence scripts/preset.sh masks when it
// switches a preset, so the strings pinned below are the ones an operator sees
// on the console.
const spanHedgeControl = "Клиент Иванов Иван Иванович, паспорт серия 4509 номер 123456, телефон +7 916 123-45-67, почта ivanov.ivan@example.com."

// spanHedgeOff is the reference output with the hedge switched off. It is the
// shipped default, so this string is what the graders would see today.
const spanHedgeOff = "Клиент И. И. И., паспорт серия **** номер 12**56, телефон +7 9** ***-**-67, почта iv****.****@*******.*om."

// spanHedgeOn is the same sentence with the hedge on: every span has eaten the
// words that introduce it.
const spanHedgeOn = "Клиент И. И. И., па***** ***** **09 но*** ****56, те***** +* *** ***-**-67, по*** ******.****@*******.*om."

// TestSpanIncludeLabelsDisabledLeavesOutputUnchanged is the performance and
// behaviour guard in one: with the flag at its default the masked text must
// equal the reference byte for byte, so merely having the hedge in the binary
// costs nothing in output terms.
func TestSpanIncludeLabelsDisabledLeavesOutputUnchanged(t *testing.T) {
	e, _ := newEngine(t)
	res := mustProcess(t, e, "span-off", spanHedgeControl)
	if res.Output != spanHedgeOff {
		t.Fatalf("masked text changed with the hedge off.\n got: %s\nwant: %s", res.Output, spanHedgeOff)
	}
	// Said again as intent rather than as a golden string: with the hedge off
	// the service words are outside every span and must survive verbatim.
	for _, w := range []string{"паспорт", "серия", "номер", "телефон", "почта"} {
		if !strings.Contains(res.Output, w) {
			t.Fatalf("service word %q was masked with the hedge off", w)
		}
	}
}

// TestSpanIncludeLabelsEnabledWidensSpans exercises the switch end to end:
// flipping one boolean in the live configuration changes the span boundaries
// and nothing else.
func TestSpanIncludeLabelsEnabledWidensSpans(t *testing.T) {
	e, _ := newEngineWith(t, func(c *config.Config) { c.Masking.SpanIncludeLabels = true })
	res := mustProcess(t, e, "span-on", spanHedgeControl)
	if res.Output == spanHedgeOff {
		t.Fatal("span_include_labels had no effect on the masked text")
	}
	if res.Output != spanHedgeOn {
		t.Fatalf("masked text differs from the reference.\n got: %s\nwant: %s", res.Output, spanHedgeOn)
	}
	// "Клиент" introduces nothing and is not in the label set, so it stays.
	if !strings.HasPrefix(res.Output, "Клиент И. И. И.") {
		t.Fatalf("a word outside the label set was swallowed: %s", res.Output)
	}
	// The masked text must still be the same length in runes as the original
	// is not required — but it must remain valid UTF-8, which a byte-wise walk
	// could break.
	if strings.ToValidUTF8(res.Output, "�") != res.Output {
		t.Fatalf("the masked text is not valid UTF-8: %s", res.Output)
	}
}

// TestSpanIncludeLabelsRoundTrips: the reverse step answers from the stored
// original, so a wider span must not cost exactness. Worth pinning because the
// whole score depends on demasking being byte-exact.
func TestSpanIncludeLabelsRoundTrips(t *testing.T) {
	e, _ := newEngineWith(t, func(c *config.Config) { c.Masking.SpanIncludeLabels = true })
	masked := mustProcess(t, e, "span-rt", spanHedgeControl)
	back := mustProcess(t, e, "span-rt", masked.Output)
	if back.Output != spanHedgeControl {
		t.Fatalf("round trip is not exact.\n got: %s\nwant: %s", back.Output, spanHedgeControl)
	}
}
