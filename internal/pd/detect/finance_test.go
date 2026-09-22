package detect

import (
	"sort"
	"strings"
	"testing"
	"time"

	"pdguard/internal/pd"
)

// wantFin is the observable part of a span: the exact substring it covers, its
// type, its confidence and the sub-shape hint. Offsets are checked indirectly
// through the substring, which is what actually matters for masking.
type wantFin struct {
	text string
	typ  pd.Type
	conf float64
	hint string
}

// runFinance exercises the finance detector alone, so a sibling detector
// registered later cannot change this file's expectations.
func runFinance(t *testing.T, payload string) []pd.Span {
	t.Helper()
	ctx := NewContext(payload, nil)
	spans := financeDetector{}.Detect(ctx)
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	return spans
}

func checkFinance(t *testing.T, payload string, want []wantFin) {
	t.Helper()
	ctx := NewContext(payload, nil)
	got := runFinance(t, payload)
	if len(got) != len(want) {
		t.Fatalf("payload %q: got %d spans, want %d (%+v)", payload, len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Start < 0 || g.End > len(ctx.Text) || g.Start >= g.End {
			t.Fatalf("payload %q: span %d has bad range %d..%d", payload, i, g.Start, g.End)
		}
		if s := ctx.Slice(g.Start, g.End); s != w.text {
			t.Errorf("payload %q: span %d covers %q, want %q", payload, i, s, w.text)
		}
		if g.Type != w.typ {
			t.Errorf("payload %q: span %d type %s, want %s", payload, i, g.Type, w.typ)
		}
		if g.Conf != w.conf {
			t.Errorf("payload %q: span %d conf %v, want %v", payload, i, g.Conf, w.conf)
		}
		if g.Hint != w.hint {
			t.Errorf("payload %q: span %d hint %q, want %q", payload, i, g.Hint, w.hint)
		}
		if g.Src != "finance" {
			t.Errorf("payload %q: span %d src %q, want %q", payload, i, g.Src, "finance")
		}
	}
}

func TestFinanceCardPositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "grouped visa test number passes luhn without a cue word",
			payload: "Оплата картой 4111 1111 1111 1111 прошла.",
			want:    []wantFin{{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"}},
		},
		{
			name:    "solid mastercard test number",
			payload: "Карта 5500005555555559 заблокирована.",
			want:    []wantFin{{"5500005555555559", pd.TypeCardNumber, finConfLuhn, "mastercard"}},
		},
		{
			name:    "hyphen separated groups",
			payload: "Списание с 4111-1111-1111-1111 отменено.",
			want:    []wantFin{{"4111-1111-1111-1111", pd.TypeCardNumber, finConfLuhn, "visa"}},
		},
		{
			name:    "amex is fifteen digits in 4-6-5 groups",
			payload: "Оплата картой 3782 822463 10005 принята.",
			want:    []wantFin{{"3782 822463 10005", pd.TypeCardNumber, finConfLuhn, "amex"}},
		},
		{
			name:    "mir range is recognised by its issuer digits",
			payload: "Выпущена карта 2200 0000 0000 0004.",
			want:    []wantFin{{"2200 0000 0000 0004", pd.TypeCardNumber, finConfLuhn, "mir"}},
		},
		{
			name:    "discover test number",
			payload: "Card 6011 1111 1111 1117 declined.",
			want:    []wantFin{{"6011 1111 1111 1117", pd.TypeCardNumber, finConfLuhn, "discover"}},
		},
		{
			name:    "broken checksum is still a card next to an explicit cue",
			payload: "Номер карты 4111 1111 1111 1112 введён неверно.",
			want:    []wantFin{{"4111 1111 1111 1112", pd.TypeCardNumber, finConfCardAnchor, "visa"}},
		},
		{
			name:    "uppercase cue word is matched case-insensitively",
			payload: "НОМЕР КАРТЫ 4111 1111 1111 1112",
			want:    []wantFin{{"4111 1111 1111 1112", pd.TypeCardNumber, finConfCardAnchor, "visa"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

func TestFinanceINNPositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "organisation inn with cue and valid control digit",
			payload: "ИНН 7707083893 указан в договоре.",
			want:    []wantFin{{"7707083893", pd.TypeINN, finConfINNChecked, "organization"}},
		},
		{
			name:    "individual inn with cue",
			payload: "ИНН 770708389324 подтверждён.",
			want:    []wantFin{{"770708389324", pd.TypeINN, finConfINNChecked, "personal"}},
		},
		{
			name:    "individual inn stands on its two control digits alone",
			payload: "Реквизит 770708389324 обновлён.",
			want:    []wantFin{{"770708389324", pd.TypeINN, finConfINN12, "personal"}},
		},
		{
			name:    "broken control digit is still masked next to the cue",
			payload: "ИНН 7707083894 в заявке.",
			want:    []wantFin{{"7707083894", pd.TypeINN, finConfINNAnchor, "organization"}},
		},
		{
			name:    "spelled out cue word",
			payload: "Идентификационный номер налогоплательщика 7707083893.",
			want:    []wantFin{{"7707083893", pd.TypeINN, finConfINNChecked, "organization"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

func TestFinanceAccountPositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "twenty solid digits next to the cue",
			payload: "Расчётный счёт 40702810900000012345 в банке.",
			want:    []wantFin{{"40702810900000012345", pd.TypeBankAccount, finConfAccount, "account"}},
		},
		{
			name:    "twenty digits written in groups of four",
			payload: "Счет 4070 2810 9000 0001 2345 открыт.",
			want:    []wantFin{{"4070 2810 9000 0001 2345", pd.TypeBankAccount, finConfAccount, "account"}},
		},
		{
			name:    "abbreviated cue",
			payload: "р/с 40702810900000012345",
			want:    []wantFin{{"40702810900000012345", pd.TypeBankAccount, finConfAccount, "account"}},
		},
		{
			name:    "iban stands on its mod-97 checksum",
			payload: "IBAN GB82 WEST 1234 5698 7654 32 действует.",
			want:    []wantFin{{"GB82 WEST 1234 5698 7654 32", pd.TypeBankAccount, finConfIBAN, "iban"}},
		},
		{
			name:    "solid iban",
			payload: "Перевод на DE89370400440532013000 отправлен.",
			want:    []wantFin{{"DE89370400440532013000", pd.TypeBankAccount, finConfIBAN, "iban"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

func TestFinanceSecretsPositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "cvv with the classic cue",
			payload: "CVV 123 не сообщайте никому.",
			want:    []wantFin{{"123", pd.TypeCVV, finConfSecret, "cvv"}},
		},
		{
			name:    "four digit security code",
			payload: "Код безопасности карты: 4567",
			want:    []wantFin{{"4567", pd.TypeCVV, finConfSecret, "cvv"}},
		},
		{
			name:    "pin code",
			payload: "ПИН-код 1234 менять раз в год.",
			want:    []wantFin{{"1234", pd.TypePIN, finConfSecret, "pin"}},
		},
		{
			name:    "six digit pin",
			payload: "pin 123456 задан клиентом",
			want:    []wantFin{{"123456", pd.TypePIN, finConfSecret, "pin"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

func TestFinanceCombinations(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "card and its cvv",
			payload: "Карта 4111 1111 1111 1111, CVV 123.",
			want: []wantFin{
				{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"},
				{"123", pd.TypeCVV, finConfSecret, "cvv"},
			},
		},
		{
			name:    "card and inn in one sentence",
			payload: "Карта 4111 1111 1111 1111, ИНН 770708389324.",
			want: []wantFin{
				{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"},
				{"770708389324", pd.TypeINN, finConfINNChecked, "personal"},
			},
		},
		{
			name:    "a cue vouches for the number next to it, not for the one after",
			payload: "CVV 123, сумма 456 рублей.",
			want:    []wantFin{{"123", pd.TypeCVV, finConfSecret, "cvv"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

func TestFinanceNegative(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "product code of sixteen digits fails luhn and has no cue",
			payload: "Артикул 1234567890123456 в каталоге.",
		},
		{
			name:    "grouped sixteen digits without a cue stay untouched",
			payload: "Заказ 1234 5678 9012 3456 оформлен.",
		},
		{
			name:    "three digits without a cvv cue",
			payload: "Всего 123 штуки на складе.",
		},
		{
			name:    "four digits without a pin cue",
			payload: "Договор подписан в 2024 году.",
		},
		{
			name:    "six digits without a pin cue",
			payload: "Код подтверждения 123456 отправлен.",
		},
		{
			name:    "phone number is not a financial identifier",
			payload: "Телефон +7 916 123-45-67 для связи.",
		},
		{
			name:    "amount with thousands separators",
			payload: "Сумма 1 234 567 890 123 рублей перечислена.",
		},
		{
			name:    "ten digit inn checksum without a cue is too cheap to trust",
			payload: "Номер заказа 7707083893 уточните у оператора.",
		},
		{
			name:    "twenty digits without an account cue",
			payload: "Значение 40702810900000012345 записано в журнал.",
		},
		{
			name:    "filler digits never form a card even with a cue",
			payload: "Карта 0000 0000 0000 0000 в тестовых данных.",
		},
		{
			name:    "digits glued to a word are an identifier of something else",
			payload: "Идентификатор id4111111111111111 в системе.",
		},
		{
			name:    "sixteen digits inside a longer run",
			payload: "Пакет 41111111111111119876 обработан.",
		},
		{
			name:    "cue-like substring inside an unrelated word",
			payload: "Картина 4111 1111 1111 1112 висит в офисе.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFinance(t, tc.payload); len(got) != 0 {
				t.Fatalf("payload %q: expected no spans, got %+v", tc.payload, got)
			}
		})
	}
}

func TestFinanceRespectsEnabled(t *testing.T) {
	payload := "Карта 4111 1111 1111 1111, CVV 123, ИНН 770708389324."
	ctx := NewContext(payload, func(t pd.Type) bool { return t == pd.TypeCVV })
	got := financeDetector{}.Detect(ctx)
	if len(got) != 1 {
		t.Fatalf("expected only the CVV span, got %+v", got)
	}
	if got[0].Type != pd.TypeCVV {
		t.Fatalf("got type %s, want %s", got[0].Type, pd.TypeCVV)
	}
}

func TestFinanceLuhn(t *testing.T) {
	cases := []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},
		{"5500005555555559", true},
		{"378282246310005", true},
		{"6011111111111117", true},
		{"2200000000000004", true},
		{"4111111111111112", false},
		{"1234567890123456", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := finLuhn(tc.digits); got != tc.want {
			t.Errorf("finLuhn(%d digits) = %v, want %v", len(tc.digits), got, tc.want)
		}
	}
}

func TestFinanceINNChecksum(t *testing.T) {
	cases := []struct {
		digits string
		want   bool
	}{
		{"7707083893", true},
		{"7707083894", false},
		{"770708389324", true},
		{"770708389325", false},
		{"770708389314", false}, // first control digit broken
		{"12345678901", false},  // eleven digits is not an INN at all
		{"", false},
	}
	for _, tc := range cases {
		if got := finINNChecksum(tc.digits); got != tc.want {
			t.Errorf("finINNChecksum(%d digits) = %v, want %v", len(tc.digits), got, tc.want)
		}
	}
}

func TestFinanceIBANChecksum(t *testing.T) {
	cases := []struct {
		compact string
		want    bool
	}{
		{"gb82west12345698765432", true},
		{"de89370400440532013000", true},
		{"gb82west12345698765433", false},
		{"id4111111111111111", false},
		{"ab12", false},
	}
	for _, tc := range cases {
		if got := finIBANChecksum(tc.compact); got != tc.want {
			t.Errorf("finIBANChecksum(len %d) = %v, want %v", len(tc.compact), got, tc.want)
		}
	}
}

func TestFinanceCardScheme(t *testing.T) {
	cases := []struct {
		head string
		want string
	}{
		{"4111", "visa"},
		{"5500", "mastercard"},
		{"2200", "mir"},
		{"2204", "mir"},
		{"2221", "mastercard"},
		{"3782", "amex"},
		{"6011", "discover"},
		{"9999", "card"},
		{"", "card"},
	}
	for _, tc := range cases {
		if got := finCardScheme([]byte(tc.head)); got != tc.want {
			t.Errorf("finCardScheme(%q) = %q, want %q", tc.head, got, tc.want)
		}
	}
}

func TestFinanceDetectorIdentity(t *testing.T) {
	d := financeDetector{}
	if d.Name() != "finance" {
		t.Fatalf("Name() = %q, want %q", d.Name(), "finance")
	}
	if len(d.Types()) != 5 {
		t.Fatalf("Types() returned %d entries, want 5", len(d.Types()))
	}
}

// TestFinanceCardGrouping covers every way a sixteen-digit number gets typed.
// The grouping test is what separates a card from a thousands-separated
// amount, so each shape it must accept is pinned here.
func TestFinanceCardGrouping(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "dots between groups of four",
			payload: "Оплата картой 4111.1111.1111.1111 прошла.",
			want:    []wantFin{{"4111.1111.1111.1111", pd.TypeCardNumber, finConfLuhn, "visa"}},
		},
		{
			name:    "dots and no cue word at all",
			payload: "Списание 5500.0055.5555.5559 подтверждено.",
			want:    []wantFin{{"5500.0055.5555.5559", pd.TypeCardNumber, finConfLuhn, "mastercard"}},
		},
		{
			name:    "eight plus eight next to a cue word",
			payload: "Карта 41111111 11111111, списание",
			want:    []wantFin{{"41111111 11111111", pd.TypeCardNumber, finConfLuhn, "visa"}},
		},
		{
			name:    "thirteen digit legacy visa",
			payload: "Оплата картой 4222222222222 принята.",
			want:    []wantFin{{"4222222222222", pd.TypeCardNumber, finConfLuhn, "visa"}},
		},
		{
			name:    "nineteen digit card in groups of four",
			payload: "Карта 6759 6498 2643 8453 128 действует.",
			want:    []wantFin{{"6759 6498 2643 8453 128", pd.TypeCardNumber, finConfLuhn, "discover"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

// TestFinanceMaskedCardIsLeftAlone pins the decision documented at scanCard: a
// number that arrives already masked is passed through untouched.
//
// The asterisks split the run into two short chains, neither of which is
// card-shaped, so nothing fires. That is the right answer twice over — the
// reference mask of an already-masked value is the value itself, so masking the
// two surviving groups would be pure edit distance against us, and the hidden
// digits cannot be restored on the reverse step either. A real card in the same
// sentence must still be found, so the rule is a limitation of the input rather
// than of the detector.
func TestFinanceMaskedCardIsLeftAlone(t *testing.T) {
	for _, payload := range []string{
		"Карта 4276 **** **** 6789 списание 100 рублей.",
		"Карта 427638******5678 заблокирована.",
		"Привязана карта **** **** **** 1111.",
	} {
		t.Run(payload, func(t *testing.T) {
			if got := runFinance(t, payload); len(got) != 0 {
				t.Fatalf("payload %q: expected no spans, got %+v", payload, got)
			}
		})
	}
	checkFinance(t, "Карта 4276 **** **** 6789 заменена на 4111 1111 1111 1111.",
		[]wantFin{{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"}})
}

// TestFinanceExpiryIsNotMasked pins the other half of the card block. The spec
// does not list the expiry date among the categories, so "09/28" comes back
// byte for byte — and, more importantly, standing next to the card it must not
// disturb the card's own span.
func TestFinanceExpiryIsNotMasked(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{"alone", "Срок действия 09/28.", nil},
		{"english cue", "exp 09/28", nil},
		{"before the card", "Срок действия 09/28, карта 4111 1111 1111 1111.",
			[]wantFin{{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"}}},
		{"after the card", "Карта 4111 1111 1111 1111 до 09/28.",
			[]wantFin{{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"}}},
		{"glued to the card", "Карта 4111 1111 1111 1111 09/28 CVC",
			[]wantFin{{"4111 1111 1111 1111", pd.TypeCardNumber, finConfLuhn, "visa"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

// TestFinanceINNShapes covers the INN typed with separators and introduced by
// an oblique case of its cue phrase. "ИНН" itself does not decline, so it is
// the spelled-out phrase around it that has to be listed.
func TestFinanceINNShapes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "ten digits in groups of four",
			payload: "ИНН 7707 0838 93 указан в договоре.",
			want:    []wantFin{{"7707 0838 93", pd.TypeINN, finConfINNChecked, "organization"}},
		},
		{
			name:    "twelve digits in groups of four",
			payload: "ИНН 7707 0838 9324 подтверждён.",
			want:    []wantFin{{"7707 0838 9324", pd.TypeINN, finConfINNChecked, "personal"}},
		},
		{
			name:    "grouped digits that fail the control digit are still cued",
			payload: "ИНН 7707 0838 94 в заявке.",
			want:    []wantFin{{"7707 0838 94", pd.TypeINN, finConfINNAnchor, "organization"}},
		},
		{
			name:    "oblique case of the spelled out cue",
			payload: "Запрос по налоговому номеру 7707083893 отправлен.",
			want:    []wantFin{{"7707083893", pd.TypeINN, finConfINNChecked, "organization"}},
		},
		{
			name:    "preposition before the cue",
			payload: "Сведения об ИНН 7707083893 получены.",
			want:    []wantFin{{"7707083893", pd.TypeINN, finConfINNChecked, "organization"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

// TestFinanceAccountShapes covers the account and IBAN spellings a statement
// actually uses: five-digit blocks, dots, and an IBAN printed in groups.
func TestFinanceAccountShapes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{
			name:    "groups of five",
			payload: "Счет 40702 81090 00000 12345 открыт.",
			want:    []wantFin{{"40702 81090 00000 12345", pd.TypeBankAccount, finConfAccount, "account"}},
		},
		{
			name:    "mixed block sizes",
			payload: "счёт 4070 28109 0000 0012 345 в рублях",
			want:    []wantFin{{"4070 28109 0000 0012 345", pd.TypeBankAccount, finConfAccount, "account"}},
		},
		{
			name:    "dots between blocks",
			payload: "Счет 4070.2810.9000.0001.2345 открыт.",
			want:    []wantFin{{"4070.2810.9000.0001.2345", pd.TypeBankAccount, finConfAccount, "account"}},
		},
		{
			name:    "iban in groups of four",
			payload: "IBAN GB82 WEST 1234 5698 7654 32 действует.",
			want:    []wantFin{{"GB82 WEST 1234 5698 7654 32", pd.TypeBankAccount, finConfIBAN, "iban"}},
		},
		{
			name:    "german iban in groups of four",
			payload: "Реквизиты: DE89 3704 0044 0532 0130 00",
			want:    []wantFin{{"DE89 3704 0044 0532 0130 00", pd.TypeBankAccount, finConfIBAN, "iban"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

// TestFinanceSecretsObliqueCues covers the case forms of the CVV and PIN cue
// phrases. The digits carry no evidence whatsoever, so an unlisted case form is
// a straight miss — and, in the other direction, a cue is required without
// exception, which the negative table below is there to prove.
func TestFinanceSecretsObliqueCues(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantFin
	}{
		{"nominative", "Код проверки 123 не сообщайте.",
			[]wantFin{{"123", pd.TypeCVV, finConfSecret, "cvv"}}},
		{"genitive", "Введите значение проверочного кода 456.",
			[]wantFin{{"456", pd.TypeCVV, finConfSecret, "cvv"}}},
		{"protective code genitive", "Значение защитного кода 789 указано на карте.",
			[]wantFin{{"789", pd.TypeCVV, finConfSecret, "cvv"}}},
		{"security code dative", "Обратитесь к коду безопасности 321 на обороте.",
			[]wantFin{{"321", pd.TypeCVV, finConfSecret, "cvv"}}},
		{"three digit phrase", "Трёхзначный код 147 с обратной стороны.",
			[]wantFin{{"147", pd.TypeCVV, finConfSecret, "cvv"}}},
		{"code on the back", "Код на обороте 258 никому не называйте.",
			[]wantFin{{"258", pd.TypeCVV, finConfSecret, "cvv"}}},
		{"pin genitive", "Смена пин-кода 1234 выполнена.",
			[]wantFin{{"1234", pd.TypePIN, finConfSecret, "pin"}}},
		{"pin spelled apart", "ПИН код 4321 придёт отдельно.",
			[]wantFin{{"4321", pd.TypePIN, finConfSecret, "pin"}}},
		{"secret code", "Секретный код 9876 задан клиентом.",
			[]wantFin{{"9876", pd.TypePIN, finConfSecret, "pin"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkFinance(t, tc.payload, tc.want) })
	}
}

// TestFinanceSecretsAlwaysNeedACue is the rule that may never be relaxed: three
// or four digits are the most common shape in any text, and masking them
// without an explicit cue would damage prices, counts, years and room numbers
// on every second payload.
func TestFinanceSecretsAlwaysNeedACue(t *testing.T) {
	for _, payload := range []string{
		"Карта 4111 1111 1111 1111, срок 09/28, 123 рубля комиссия.",
		"В отделении 123 работает 4 окна.",
		"Код подтверждения 123456 отправлен.",
		"Квартира 123, подъезд 4.",
		"Товар 123 шт. по цене 4567 рублей.",
		"Проверка связи 123.",
	} {
		t.Run(payload, func(t *testing.T) {
			for _, s := range runFinance(t, payload) {
				if s.Type == pd.TypeCVV || s.Type == pd.TypePIN {
					t.Fatalf("payload %q: %s masked without a cue word", payload, s.Type)
				}
			}
		})
	}
}

// TestFinanceBankOwnNumbersAreNotClientData covers the identifiers of the bank
// rather than of its client. A BIK identifies a credit organisation and is
// published in a state register; the spec does not list it and masking it would
// be edit distance spent on public data, so nine digits next to "БИК" stay put.
func TestFinanceBankOwnNumbersAreNotClientData(t *testing.T) {
	for _, payload := range []string{
		"БИК 044525225 банка получателя.",
		"Банк получателя: БИК 044525974, к/с 30101810145250000974",
		"КПП 770701001 организации.",
		"ОКПО 12345678 указан в справке.",
	} {
		t.Run(payload, func(t *testing.T) {
			for _, s := range runFinance(t, payload) {
				if s.Hint != "account" && s.Hint != "iban" {
					t.Fatalf("payload %q: an identifier of the bank was masked as %s (%s)",
						payload, s.Type, s.Hint)
				}
			}
		})
	}
}

// TestFinanceProbesCoverAnchors keeps the whole-payload pre-filter honest.
//
// The pre-filter is an optimisation and must never change a decision: if a cue
// word can occur, some probe of its group has to occur too. Adding an anchor
// without extending its probe list would silently disable it on every payload
// that does not happen to contain another cue of the same group, which is a
// detector that quietly stops working rather than a test that fails.
func TestFinanceProbesCoverAnchors(t *testing.T) {
	groups := []struct {
		name    string
		anchors []finAnchor
		probes  []string
	}{
		{"card", finCardAnchors, finCardProbes},
		{"inn", finINNAnchors, finINNProbes},
		{"account", finAccountAnchors, finAccountProbes},
		{"cvv", finCVVAnchors, finCVVProbes},
		{"pin", finPINAnchors, finPINProbes},
	}
	for _, g := range groups {
		for _, a := range g.anchors {
			if !finContainsAny(a.s, g.probes) {
				t.Errorf("%s: anchor %q is matched by no probe in %v", g.name, a.s, g.probes)
			}
		}
	}
}

// TestFinanceIBANScanIsLinear pins the complexity of the IBAN frame. The
// candidate is consumed whether or not it is accepted; restarting one byte
// later would re-scan the same body from every fourth position of a long
// "ab12ab12…" run, which is quadratic and is exactly what a hostile payload
// would send.
func TestFinanceIBANScanIsLinear(t *testing.T) {
	payload := strings.Repeat("ab12", 8000) // 32 KB, one alphanumeric run
	start := time.Now()
	spans := financeDetector{}.Detect(NewContext(payload, nil))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("detect on %d bytes took %v: the IBAN scan is quadratic", len(payload), d)
	}
	if len(spans) != 0 {
		t.Fatalf("a repeated alphanumeric run produced %d spans", len(spans))
	}
}
