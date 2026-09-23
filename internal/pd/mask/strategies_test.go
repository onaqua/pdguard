package mask

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"pdguard/internal/pd"
)

// strategy fetches a registered strategy or fails: a typo in a name constant
// must break the tests, not silently disable masking at runtime.
func strategy(t *testing.T, name string) Strategy {
	t.Helper()
	s := Lookup(name)
	if s == nil {
		t.Fatalf("strategy %q is not registered", name)
	}
	return s
}

func TestAllStrategiesRegistered(t *testing.T) {
	want := []string{
		NameStarsKeep2, NameStarsAll, NameInitials, NameInitialsLatin,
		NameLabel, NameToken, NameSynthetic, NameKeepDomain, NameNone,
	}
	for _, n := range want {
		s := strategy(t, n)
		if s.Name() != n {
			t.Errorf("Lookup(%q).Name() = %q", n, s.Name())
		}
	}
}

// TestStarsKeep2PassportReference pins the single reference sample given in the
// statement of work. The score is an edit distance against the reference mask,
// so this exact byte sequence is what the grader compares against.
func TestStarsKeep2PassportReference(t *testing.T) {
	got := strategy(t, NameStarsKeep2).Mask("4509 123456", pd.TypePassport)
	if got != "45** ****56" {
		t.Fatalf("Mask(%q) = %q, want %q", "4509 123456", got, "45** ****56")
	}
}

func TestStarsKeep2(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"passport reference", "4509 123456", "45** ****56"},
		{"card with spaces", "4276 3800 1234 5678", "42** **** **** **78"},
		{"phone", "+7 (912) 345-67-89", "+7 (9**) ***-**-89"},
		{"inn", "770708389427", "77********27"},
		{"cyrillic word", "Иванов", "Ив**ов"},
		{"exactly four alnum", "1234", "****"},
		{"three alnum", "abc", "***"},
		{"five alnum", "12345", "12*45"},
		{"punctuation only", "---", "---"},
		{"empty", "", ""},
		{"separators kept", "AB-12-CD", "AB-**-CD"},
	}
	s := strategy(t, NameStarsKeep2)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.Mask(c.in, pd.TypePassport); got != c.want {
				t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestStarsKeep2KeepsRuneLength guards the property the whole scoring model
// rests on: the mask must line up with the source character for character.
func TestStarsKeep2KeepsRuneLength(t *testing.T) {
	s := strategy(t, NameStarsKeep2)
	for _, in := range []string{
		"1234567890", "4509 123456", "+7 912 345 67 89", "770708389427",
		"Иванов Иван", "ivanov@mail.ru",
	} {
		got := s.Mask(in, pd.TypePassport)
		if utf8.RuneCountInString(got) != utf8.RuneCountInString(in) {
			t.Errorf("Mask(%q) = %q: rune count %d, want %d",
				in, got, utf8.RuneCountInString(got), utf8.RuneCountInString(in))
		}
	}
}

func TestStarsAll(t *testing.T) {
	cases := []struct{ in, want string }{
		{"123", "***"},
		{"4509", "****"},
		{"12-34", "**-**"},
		{"Код", "***"},
		{"", ""},
	}
	s := strategy(t, NameStarsAll)
	for _, c := range cases {
		if got := s.Mask(c.in, pd.TypeCVV); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestInitialsReference pins the second reference sample from the statement of
// work: a full name collapses to spaced initials.
func TestInitialsReference(t *testing.T) {
	got := strategy(t, NameInitials).Mask("Иванов Иван Иванович", pd.TypeFIO)
	if got != "И. И. И." {
		t.Fatalf("Mask(%q) = %q, want %q", "Иванов Иван Иванович", got, "И. И. И.")
	}
}

func TestInitials(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"full name", "Иванов Иван Иванович", "И. И. И."},
		{"already abbreviated", "Иванов И.И.", "И. И. И."},
		{"abbreviated spaced", "Иванов И. И.", "И. И. И."},
		{"surname and name", "Петрова Анна", "П. А."},
		{"double surname", "Петров-Водкин", "П.-В."},
		{"double surname with name", "Петров-Водкин Кузьма", "П.-В. К."},
		{"lower case input", "иванов иван", "И. И."},
		{"single word", "Сидоров", "С."},
		{"extra spaces", "  Иванов   Иван  ", "И. И."},
		{"digits only falls back", "1234567", "12***67"},
	}
	s := strategy(t, NameInitials)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.Mask(c.in, pd.TypeFIO); got != c.want {
				t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestInitialsLatin(t *testing.T) {
	cases := []struct{ in, want string }{
		{"IVAN IVANOV", "I. I."},
		{"Ivan Ivanov", "I. I."},
		{"JOHN R SMITH", "J. R. S."},
		{"MARY-JANE WATSON", "M.-J. W."},
	}
	s := strategy(t, NameInitialsLatin)
	for _, c := range cases {
		if got := s.Mask(c.in, pd.TypeCardHolder); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLabel(t *testing.T) {
	cases := []struct {
		typ  pd.Type
		want string
	}{
		{pd.TypeFIO, "[ФИО]"},
		{pd.TypePhone, "[ТЕЛЕФОН]"},
		{pd.TypeCardNumber, "[КАРТА]"},
		{pd.TypeEmail, "[ПОЧТА]"},
		{pd.Type("NOT_A_TYPE"), "[ПД]"},
	}
	s := strategy(t, NameLabel)
	for _, c := range cases {
		if got := s.Mask("любое значение", c.typ); got != c.want {
			t.Errorf("Mask(_, %q) = %q, want %q", c.typ, got, c.want)
		}
	}
}

// TestLabelCoversEveryType makes adding a pd.Type without a label a test
// failure: an unlabelled category would be masked as the vague "[ПД]".
func TestLabelCoversEveryType(t *testing.T) {
	for _, typ := range pd.AllTypes {
		if Label(typ) == "[ПД]" {
			t.Errorf("type %q has no Russian label", typ)
		}
	}
}

func TestTokenFormat(t *testing.T) {
	s := strategy(t, NameToken)
	got := s.Mask("Иванов Иван Иванович", pd.TypeFIO)
	if !strings.HasPrefix(got, "PD_FIO_") {
		t.Fatalf("Mask = %q, want prefix PD_FIO_", got)
	}
	tail := strings.TrimPrefix(got, "PD_FIO_")
	if len(tail) != 6 {
		t.Fatalf("tail %q has %d chars, want 6", tail, len(tail))
	}
	for _, r := range tail {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("tail %q is not lower-case hex", tail)
		}
	}
}

// TestTokenDeterministic is the property a retried request depends on: the
// endpoint must be idempotent per payload_id, so the same value must always
// produce the same token.
func TestTokenDeterministic(t *testing.T) {
	s := strategy(t, NameToken)
	const v = "+7 912 345-67-89"
	a := s.Mask(v, pd.TypePhone)
	b := s.Mask(v, pd.TypePhone)
	if a != b {
		t.Fatalf("token not deterministic: %q vs %q", a, b)
	}
	if other := s.Mask("+7 912 345-67-88", pd.TypePhone); other == a {
		t.Errorf("different values produced the same token %q", a)
	}
}

// TestSyntheticDeterministic covers the same idempotence requirement for the
// synthetic strategy, which must never reach for math/rand.
func TestSyntheticDeterministic(t *testing.T) {
	s := strategy(t, NameSynthetic)
	cases := []struct {
		typ pd.Type
		in  string
	}{
		{pd.TypeFIO, "Иванов Иван Иванович"},
		{pd.TypeCardNumber, "4276 3800 1234 5678"},
		{pd.TypePhone, "+7 (912) 345-67-89"},
		{pd.TypeEmail, "ivanov@mail.ru"},
		{pd.TypeBirthDate, "12.03.1985"},
		{pd.TypePassport, "4509 123456"},
	}
	for _, c := range cases {
		a := s.Mask(c.in, c.typ)
		b := s.Mask(c.in, c.typ)
		if a != b {
			t.Errorf("synthetic(%q) not deterministic: %q vs %q", c.in, a, b)
		}
	}
}

// TestSyntheticKeepsShape checks the promise that makes synthetic masking
// useful: the replacement must look like the same kind of value, so the model
// keeps understanding the prompt.
func TestSyntheticKeepsShape(t *testing.T) {
	s := strategy(t, NameSynthetic)

	t.Run("card passes luhn and keeps format", func(t *testing.T) {
		assertSyntheticCard(t, s)
	})

	t.Run("phone keeps separators", func(t *testing.T) {
		assertSyntheticPhone(t, s)
	})

	t.Run("email keeps domain", func(t *testing.T) {
		assertSyntheticEmail(t, s)
	})

	t.Run("date stays a valid date", func(t *testing.T) {
		assertSyntheticDate(t, s)
	})

	t.Run("name keeps word count and case", func(t *testing.T) {
		assertSyntheticName(t, s)
	})

	t.Run("generic keeps length and digits", func(t *testing.T) {
		assertSyntheticGeneric(t, s)
	})
}

// assertSyntheticCard checks that a synthetic card passes Luhn and keeps its
// format and brand digit.
func assertSyntheticCard(t *testing.T, s Strategy) {
	t.Helper()
	const in = "4276 3800 1234 5678"
	got := s.Mask(in, pd.TypeCardNumber)
	if got == in {
		t.Fatalf("card was not replaced")
	}
	assertSameSkeleton(t, in, got)
	d := digitsOf(got)
	if len(d) != 16 {
		t.Fatalf("got %d digits, want 16", len(d))
	}
	if d[0] != 4 {
		t.Errorf("brand digit changed: got %d, want 4", d[0])
	}
	if want := luhnCheckDigit(d[:len(d)-1]); d[len(d)-1] != want {
		t.Errorf("luhn check digit %d, want %d", d[len(d)-1], want)
	}
}

// assertSyntheticPhone checks that a synthetic phone keeps its separators and
// leading digits.
func assertSyntheticPhone(t *testing.T, s Strategy) {
	t.Helper()
	const in = "+7 (912) 345-67-89"
	got := s.Mask(in, pd.TypePhone)
	assertSameSkeleton(t, in, got)
	d := digitsOf(got)
	if len(d) != 11 || d[0] != 7 || d[1] != 9 {
		t.Errorf("got %q: want 11 digits starting with 7,9", got)
	}
}

// assertSyntheticEmail checks that a synthetic email keeps its domain and draws
// its local part from the synthetic pool.
func assertSyntheticEmail(t *testing.T, s Strategy) {
	t.Helper()
	got := s.Mask("ivanov@mail.ru", pd.TypeEmail)
	if !strings.HasSuffix(got, "@mail.ru") {
		t.Errorf("got %q, want the domain preserved", got)
	}
	local := strings.TrimSuffix(got, "@mail.ru")
	found := false
	for _, l := range synEmailLocals {
		if l == local {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("local part %q is not one of the synthetic pool", local)
	}
}

// assertSyntheticDate checks that a synthetic date stays a valid calendar date.
func assertSyntheticDate(t *testing.T, s Strategy) {
	t.Helper()
	const in = "12.03.1985"
	got := s.Mask(in, pd.TypeBirthDate)
	assertSameSkeleton(t, in, got)
	g := digitGroups(got)
	if len(g) != 3 {
		t.Fatalf("got %q: want three digit groups", got)
	}
	if g[0].val < 1 || g[0].val > 28 {
		t.Errorf("day %d out of range in %q", g[0].val, got)
	}
	if g[1].val < 1 || g[1].val > 12 {
		t.Errorf("month %d out of range in %q", g[1].val, got)
	}
	if g[2].val < 1900 || g[2].val > 2100 {
		t.Errorf("year %d out of range in %q", g[2].val, got)
	}
}

// assertSyntheticName checks that a synthetic name keeps its word count and
// letter case.
func assertSyntheticName(t *testing.T, s Strategy) {
	t.Helper()
	got := s.Mask("ИВАНОВ ИВАН ИВАНОВИЧ", pd.TypeFIO)
	if n := len(strings.Fields(got)); n != 3 {
		t.Errorf("got %q: want three words", got)
	}
	for _, r := range got {
		if unicode.IsLower(r) {
			t.Errorf("got %q: upper-case input must stay upper case", got)
			break
		}
	}
}

// assertSyntheticGeneric checks that a generic synthetic value keeps its length
// and digit skeleton.
func assertSyntheticGeneric(t *testing.T, s Strategy) {
	t.Helper()
	const in = "4509 123456"
	got := s.Mask(in, pd.TypePassport)
	assertSameSkeleton(t, in, got)
	if got == in {
		t.Errorf("passport was not replaced")
	}
}

// assertSameSkeleton verifies that every non-alphanumeric rune kept its exact
// position and that letters stayed letters and digits stayed digits.
func assertSameSkeleton(t *testing.T, in, got string) {
	t.Helper()
	a, b := []rune(in), []rune(got)
	if len(a) != len(b) {
		t.Fatalf("length changed: %q -> %q", in, got)
	}
	for i := range a {
		switch {
		case unicode.IsDigit(a[i]):
			if !unicode.IsDigit(b[i]) {
				t.Fatalf("digit at %d became %q in %q", i, string(b[i]), got)
			}
		case unicode.IsLetter(a[i]):
			if !unicode.IsLetter(b[i]) {
				t.Fatalf("letter at %d became %q in %q", i, string(b[i]), got)
			}
		default:
			if a[i] != b[i] {
				t.Fatalf("separator at %d changed %q -> %q in %q", i, string(a[i]), string(b[i]), got)
			}
		}
	}
}

func TestKeepDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ivanov@mail.ru", "iv****@mail.ru"},
		{"a.petrov@example.com", "a.p*****@example.com"},
		{"ab@mail.ru", "**@mail.ru"},
		{"no-at-sign", "no-**-**gn"}, // falls back to stars_keep2
	}
	s := strategy(t, NameKeepDomain)
	for _, c := range cases {
		if got := s.Mask(c.in, pd.TypeEmail); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNone(t *testing.T) {
	s := strategy(t, NameNone)
	for _, in := range []string{"", "Иванов", "4509 123456"} {
		if got := s.Mask(in, pd.TypeFIO); got != in {
			t.Errorf("Mask(%q) = %q, want it unchanged", in, got)
		}
	}
}

// TestApplyWithStrategies wires the strategies through mask.Apply to prove the
// bytes outside the detected spans survive untouched — every byte we alter
// outside a span is a direct penalty in the scoring metric.
func TestApplyWithStrategies(t *testing.T) {
	const src = "Клиент Иванов Иван Иванович, паспорт 4509 123456, спасибо."
	spans := []pd.Span{
		{Start: strings.Index(src, "Иванов"), End: strings.Index(src, "Иванов") + len("Иванов Иван Иванович"), Type: pd.TypeFIO},
		{Start: strings.Index(src, "4509"), End: strings.Index(src, "4509") + len("4509 123456"), Type: pd.TypePassport},
	}
	res := Apply(src, spans, func(typ pd.Type) Strategy {
		if typ == pd.TypeFIO {
			return Lookup(NameInitials)
		}
		return Lookup(NameStarsKeep2)
	})
	const want = "Клиент И. И. И., паспорт 45** ****56, спасибо."
	if res.Masked != want {
		t.Fatalf("masked = %q, want %q", res.Masked, want)
	}
	if got := Restore(res.Masked, res.Replacements); got != src {
		t.Fatalf("restore = %q, want %q", got, src)
	}
}
