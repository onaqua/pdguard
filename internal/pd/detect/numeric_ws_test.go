package detect

import (
	"testing"

	"pdguard/internal/pd"
	"pdguard/internal/pd/mask"
)

// nb is a non-breaking space. After normalisation it arrives as two regular
// spaces, so every NBSP sample below doubles as a double-space sample.
const nb = "\u00a0"

// wsCard is a Luhn-valid card number split into four groups.
const wsCard = "4276" + nb + "3801" + nb + "2345" + nb + "6789"

// wsAccount is a 20-digit bank account split into five groups.
const wsAccount = "4081 7810 0999 1000 4312"

// wsPhone is a mobile number split into four groups.
const wsPhone = "+7" + nb + "916" + nb + "123" + nb + "45" + nb + "67"

// wsSNILS is an eleven-digit SNILS split into three groups.
const wsSNILS = "112" + nb + "233" + nb + "445" + nb + "95"

// wsPassport is a passport number split into two groups.
const wsPassport = "45" + nb + "09" + nb + "123456"

// wsCardDouble is the same card with two regular spaces between groups.
const wsCardDouble = "4276  3801  2345  6789"

// wsCardMixed is the same card with a single space before the last group.
const wsCardMixed = "4276 3801 23456789"

// wsAccountNBSP is the account with NBSP separators.
const wsAccountNBSP = "40817" + nb + "810" + nb + "0" + nb + "9991" + nb + "0004312"

// wsPassportDash is a passport with a dash between the first two groups.
const wsPassportDash = "45-09 123456"

// wsCardFrame is the prose that introduces a card number in the positive cases.
const wsCardFrame = "Клиент Иванов Иван Иванович, карта "

// wantWS is the observable part of a detected span: the exact substring and
// its type. Offsets are checked indirectly through the substring.
type wantWS struct {
	text string
	typ  pd.Type
}

// checkWS runs the full detector set and asserts that some span covers the
// whole value with the expected type. The frame may carry other personal data
// (an FIO), so the value is searched for rather than required to be the only
// span.
func checkWS(t *testing.T, payload string, w wantWS) {
	t.Helper()
	ctx := NewContext(payload, nil)
	spans := Run(ctx)
	for _, s := range spans {
		if s.Type != w.typ {
			continue
		}
		if got := ctx.Slice(s.Start, s.End); got == w.text {
			return
		}
	}
	t.Errorf("payload %q: no %s span covering %q in %+v", payload, w.typ, w.text, spans)
}

// checkWSNone asserts that the payload yields no spans at all.
func checkWSNone(t *testing.T, payload string) {
	t.Helper()
	ctx := NewContext(payload, nil)
	if spans := Run(ctx); len(spans) != 0 {
		t.Fatalf("payload %q: got %d spans, want none (%+v)", payload, len(spans), spans)
	}
}

// TestNumericWSFound covers values whose groups are separated by NBSP, double
// spaces or a dash, framed by ordinary prose.
func TestNumericWSFound(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    wantWS
	}{
		{"card nbsp", wsCardFrame + wsCard + ".", wantWS{wsCard, pd.TypeCardNumber}},
		{"card double space", wsCardFrame + wsCardDouble + ".", wantWS{wsCardDouble, pd.TypeCardNumber}},
		{"card mixed", wsCardFrame + wsCardMixed + ".", wantWS{wsCardMixed, pd.TypeCardNumber}},
		{"phone nbsp", "Проверь: тел. " + wsPhone, wantWS{wsPhone, pd.TypePhone}},
		{"snils nbsp", "СНИЛС: " + wsSNILS + "; других данных нет.", wantWS{wsSNILS, pd.TypeSNILS}},
		{"account nbsp", "Переведи на английский: счёт " + wsAccountNBSP + ".", wantWS{wsAccountNBSP, pd.TypeBankAccount}},
		{"account spaces", "Переведи на английский: счёт " + wsAccount + ".", wantWS{wsAccount, pd.TypeBankAccount}},
		{"passport nbsp", "Клиент Иванов Иван Иванович, паспорт " + wsPassport + ".", wantWS{wsPassport, pd.TypePassport}},
		{"passport dash", "Клиент Иванов Иван Иванович, паспорт " + wsPassportDash + ".", wantWS{wsPassportDash, pd.TypePassport}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkWS(t, c.payload, c.want)
		})
	}
}

// TestNumericWSNegative asserts that spaced digit runs that are not personal
// data stay untouched.
func TestNumericWSNegative(t *testing.T) {
	cases := []string{
		"в 2023  году 15  раз",
		"суммы 1500  2300  4100",
		"код 12  34",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			checkWSNone(t, c)
		})
	}
}

// TestNumericWSMaskRoundTrip masks a card with NBSP separators and restores it.
// Everything outside the span — including the trailing ", спасибо" — must come
// back byte for byte.
func TestNumericWSMaskRoundTrip(t *testing.T) {
	payload := "карта " + wsCard + ", спасибо"
	ctx := NewContext(payload, nil)
	spans := Run(ctx)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1 (%+v)", len(spans), spans)
	}
	s := spans[0]
	if got := ctx.Slice(s.Start, s.End); got != wsCard {
		t.Fatalf("span covers %q, want %q", got, wsCard)
	}

	pick := func(pd.Type) mask.Strategy { return mask.Lookup(mask.NameStarsKeep2) }
	res := mask.Apply(payload, spans, pick)

	// The masked text must keep the frame and the trailing clause verbatim.
	prefix, suffix := "карта ", ", спасибо"
	if len(res.Masked) < len(prefix)+len(suffix) {
		t.Fatalf("masked text too short: %q", res.Masked)
	}
	if res.Masked[:len(prefix)] != prefix {
		t.Errorf("masked prefix %q, want %q", res.Masked[:len(prefix)], prefix)
	}
	if res.Masked[len(res.Masked)-len(suffix):] != suffix {
		t.Errorf("masked suffix %q, want %q", res.Masked[len(res.Masked)-len(suffix):], suffix)
	}

	back := mask.Restore(res.Masked, res.Replacements)
	if back != payload {
		t.Errorf("restored text differs:\n got %q\nwant %q", back, payload)
	}
}
