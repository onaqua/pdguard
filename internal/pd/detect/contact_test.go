package detect

import (
	"sort"
	"strings"
	"testing"
	"time"

	"pdguard/internal/pd"
)

// wantContact is the observable part of a span: the exact substring it covers,
// its type and its confidence. Offsets are checked indirectly through the
// substring, which is what actually matters for masking.
type wantContact struct {
	text string
	typ  pd.Type
	conf float64
}

// runContact exercises the contact detector alone, so a sibling detector
// registered later cannot change this file's expectations.
func runContact(t *testing.T, payload string) []pd.Span {
	t.Helper()
	ctx := NewContext(payload, nil)
	spans := contactDetector{}.Detect(ctx)
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	return spans
}

func checkContact(t *testing.T, payload string, want []wantContact) {
	t.Helper()
	ctx := NewContext(payload, nil)
	got := runContact(t, payload)
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
		if g.Src != "contact" {
			t.Errorf("payload %q: span %d src %q, want %q", payload, i, g.Src, "contact")
		}
	}
}

func TestContactEmailPositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantContact
	}{
		{
			name:    "plain address",
			payload: "Мой адрес ivan.petrov@mail.ru для связи.",
			want:    []wantContact{{"ivan.petrov@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "sentence dot is not part of the address",
			payload: "Пишите на ivan@mail.ru.",
			want:    []wantContact{{"ivan@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "uppercase is matched, original case is reported",
			payload: "Контакт: IVAN.PETROV@MAIL.RU",
			want:    []wantContact{{"IVAN.PETROV@MAIL.RU", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "plus tag and hyphen in the local part",
			payload: "дубль на i-petrov+bank@sub.example.co.uk, спасибо",
			want:    []wantContact{{"i-petrov+bank@sub.example.co.uk", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "cyrillic domain",
			payload: "почта: ivanov@почта.рф",
			want:    []wantContact{{"ivanov@почта.рф", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "leading dot stays outside the address",
			payload: "письмо.ivan@mail.ru",
			want:    []wantContact{{"ivan@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "two addresses in one line",
			payload: "a1@mail.ru, b2@yandex.ru",
			want: []wantContact{
				{"a1@mail.ru", pd.TypeEmail, contactConfEmail},
				{"b2@yandex.ru", pd.TypeEmail, contactConfEmail},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkContact(t, c.payload, c.want) })
	}
}

func TestContactPhonePositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantContact
	}{
		{
			name:    "plus seven spaced",
			payload: "Телефон +7 916 123-45-67 рабочий.",
			want:    []wantContact{{"+7 916 123-45-67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "plus seven with parentheses",
			payload: "тел. +7(916)123-45-67",
			want:    []wantContact{{"+7(916)123-45-67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "city code",
			payload: "Звоните: +7 495 123-45-67",
			want:    []wantContact{{"+7 495 123-45-67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "eight spaced groups",
			payload: "мобильный 8 916 123 45 67",
			want:    []wantContact{{"8 916 123 45 67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "eight solid",
			payload: "номер 89161234567 основной",
			want:    []wantContact{{"89161234567", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "eight hyphenated",
			payload: "8-916-123-45-67",
			want:    []wantContact{{"8-916-123-45-67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "seven without plus",
			payload: "сотовый 7 916 1234567",
			want:    []wantContact{{"7 916 1234567", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "area code in parentheses",
			payload: "Звоните (916) 123-45-67 в будни.",
			want:    []wantContact{{"(916) 123-45-67", pd.TypePhone, contactConfPhoneOther}},
		},
		{
			name:    "local ten digits with separators",
			payload: "контактный 916-123-45-67",
			want:    []wantContact{{"916-123-45-67", pd.TypePhone, contactConfPhoneOther}},
		},
		{
			name:    "international number",
			payload: "whatsapp +1 202 555 0143",
			want:    []wantContact{{"+1 202 555 0143", pd.TypePhone, contactConfPhoneOther}},
		},
		{
			name:    "ten solid digits next to a cue word",
			payload: "Контактный телефон 9161234567",
			want:    []wantContact{{"9161234567", pd.TypePhone, contactConfPhoneOther}},
		},
		{
			name:    "email and phone in one payload",
			payload: "ivan@mail.ru, тел +7 916 123-45-67",
			want: []wantContact{
				{"ivan@mail.ru", pd.TypeEmail, contactConfEmail},
				{"+7 916 123-45-67", pd.TypePhone, contactConfPhonePlus7},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkContact(t, c.payload, c.want) })
	}
}

// TestContactNegative pins the cases where staying byte-identical is worth more
// than a detection: service mailboxes, published bank and emergency numbers,
// fragments of longer identifiers, and text that merely looks contact-shaped.
func TestContactNegative(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"toll free eight hundred", "Звоните 8 800 555 35 35 круглосуточно."},
		{"toll free with plus seven", "+7 800 555 35 35"},
		{"emergency short number", "Единый номер 112, звоните с мобильного."},
		{"bank short number", "Телефон банка 900 для смс."},
		{"card number grouped", "Карта 4276 3800 1234 5678 выпущена в 2020."},
		{"card number solid", "Номер карты 4276380012345678"},
		{"account number", "Счёт 40817810099910004312 в рублях."},
		{"support mailbox", "Пишите на support@alfabank.ru"},
		{"info mailbox", "info@example.com — общий ящик."},
		{"noreply mailbox", "noreply@bank.example"},
		{"corporate domain personal local", "Письмо от a.sidorov@alfabank.ru получено."},
		{"domain without at sign", "Сайт mail.ru открывается медленно."},
		{"dog is an animal", "Собака сидела у подъезда и лаяла."},
		{"email spelled in words is not supported", "ivanov собака mail точка ru"},
		{"bare ten digits without a cue word", "Заказ 9161234567 оформлен."},
		{"year and short numbers", "В 2019 году было 15 отделений."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkContact(t, c.payload, nil) })
	}
}

// TestContactSpansAreWellFormed guards the invariant the masking engine relies
// on: offsets point into ctx.Text and spans never overlap each other.
func TestContactSpansAreWellFormed(t *testing.T) {
	payload := "Иван, ivan@mail.ru, тел +7 916 123-45-67 и 8 800 555 35 35."
	spans := runContact(t, payload)
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2: %+v", len(spans), spans)
	}
	for i := 1; i < len(spans); i++ {
		if spans[i-1].End > spans[i].Start {
			t.Fatalf("spans overlap: %+v", spans)
		}
	}
}

// TestContactRespectsEnabled checks the detector honours the per-type switch,
// so an operator can turn a category off without redeploying.
func TestContactRespectsEnabled(t *testing.T) {
	payload := "ivan@mail.ru +7 916 123-45-67"
	ctx := NewContext(payload, func(t pd.Type) bool { return t == pd.TypePhone })
	spans := contactDetector{}.Detect(ctx)
	if len(spans) != 1 || spans[0].Type != pd.TypePhone {
		t.Fatalf("got %+v, want a single PHONE span", spans)
	}
}

// TestContactPhoneSeparatorStyles covers the spellings the detector used to
// miss because the patterns only knew about spaces and hyphens. Dots are how a
// number gets typed on a phone keypad and pasted out of a spreadsheet, and a
// ten-digit number is routinely written without the country code at all.
func TestContactPhoneSeparatorStyles(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantContact
	}{
		{
			name:    "dots between every group",
			payload: "Звоните 8.916.123.45.67 в любое время.",
			want:    []wantContact{{"8.916.123.45.67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "dots with the plus prefix",
			payload: "+7.916.123.45.67",
			want:    []wantContact{{"+7.916.123.45.67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "ten digits grouped three-three-four next to a cue",
			payload: "тел 916 123 4567",
			want:    []wantContact{{"916 123 4567", pd.TypePhone, contactConfPhoneOther}},
		},
		{
			name:    "ten digits grouped three-seven next to a cue",
			payload: "мобильный 916 1234567",
			want:    []wantContact{{"916 1234567", pd.TypePhone, contactConfPhoneOther}},
		},
		{
			name:    "eight with a spaced parenthesised area code",
			payload: "8 (916) 123-45-67",
			want:    []wantContact{{"8 (916) 123-45-67", pd.TypePhone, contactConfPhonePlus7}},
		},
		{
			name:    "twelve digit international number",
			payload: "+49 30 901820 34",
			want:    []wantContact{{"+49 30 901820 34", pd.TypePhone, contactConfPhoneOther}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkContact(t, c.payload, c.want) })
	}
}

// TestContactPhoneWithExtension pins a deliberate limitation.
//
// The number itself is found in every spelling of an extension, which is what
// matters: the extension is reported as ordinary text and left byte-identical.
// Swallowing "доб. 123" into the span would be worse than leaving it, because
// the default mask stars out alphanumerics — the word "доб" would come back as
// "до*", damage to text that is not personal data at all — and masking the
// three digits on their own changes nothing, since a three-character span keeps
// its first two and last two characters and so survives the mask untouched.
func TestContactPhoneWithExtension(t *testing.T) {
	cases := []struct{ payload, want string }{
		{"Телефон +7 495 123-45-67 доб. 123", "+7 495 123-45-67"},
		{"Тел. 8 (495) 123-45-67 доб 4501", "8 (495) 123-45-67"},
		{"телефон +7 495 123-45-67, добавочный 12", "+7 495 123-45-67"},
		{"call +7 495 123-45-67 ext. 7", "+7 495 123-45-67"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			checkContact(t, c.payload, []wantContact{{c.want, pd.TypePhone, contactConfPhonePlus7}})
		})
	}
}

// TestContactPhoneLists covers several numbers in one line. Each has to be a
// span of its own: a comma and a slash separate two numbers, they never join
// two halves of one.
func TestContactPhoneLists(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantContact
	}{
		{
			name:    "comma separated",
			payload: "Телефоны: +7 916 123-45-67, +7 916 765-43-21",
			want: []wantContact{
				{"+7 916 123-45-67", pd.TypePhone, contactConfPhonePlus7},
				{"+7 916 765-43-21", pd.TypePhone, contactConfPhonePlus7},
			},
		},
		{
			name:    "slash separated",
			payload: "Тел: 8-916-123-45-67 / 8-495-111-22-33",
			want: []wantContact{
				{"8-916-123-45-67", pd.TypePhone, contactConfPhonePlus7},
				{"8-495-111-22-33", pd.TypePhone, contactConfPhonePlus7},
			},
		},
		{
			name:    "a card and a phone in two sentences",
			payload: "Оплата картой 4276380012345678. Телефон 8 916 123 45 67.",
			want:    []wantContact{{"8 916 123 45 67", pd.TypePhone, contactConfPhonePlus7}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkContact(t, c.payload, c.want) })
	}
}

// TestContactEmailShapes covers the address spellings that carry punctuation
// around them. Every one of these used to be either missed outright (the
// underscore was not in the local-part character set, so the scan started in
// the middle of the address and the boundary check then threw it away) or at
// risk of swallowing the punctuation that follows it.
func TestContactEmailShapes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantContact
	}{
		{
			name:    "underscore in the local part",
			payload: "почта ivan_petrov@mail.ru",
			want:    []wantContact{{"ivan_petrov@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "angle brackets",
			payload: "Пишите на <ivan@mail.ru>, ответим завтра.",
			want:    []wantContact{{"ivan@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "double quotes",
			payload: "адрес \"ivan.petrov@mail.ru\" указан в анкете",
			want:    []wantContact{{"ivan.petrov@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "closing parenthesis",
			payload: "(контакт: ivan@mail.ru)",
			want:    []wantContact{{"ivan@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "trailing comma",
			payload: "ivan@mail.ru, Иван Петров",
			want:    []wantContact{{"ivan@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "plus addressing on a deep subdomain",
			payload: "дубль на ivan+bank@mx.corp.example.co.uk;",
			want:    []wantContact{{"ivan+bank@mx.corp.example.co.uk", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "mailto prefix stays outside the address",
			payload: "mailto:ivan.petrov@mail.ru",
			want:    []wantContact{{"ivan.petrov@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
		{
			name:    "digits only local part",
			payload: "счёт выслан на 12345@mail.ru",
			want:    []wantContact{{"12345@mail.ru", pd.TypeEmail, contactConfEmail}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkContact(t, c.payload, c.want) })
	}
}

// TestContactNegativeShapes is the other half of the two features above. Dots
// between digit groups are how an IP address and a version string are written
// too, and those must survive byte for byte; a dotted run is therefore only
// trusted when the Russian country prefix confirms it.
func TestContactNegativeShapes(t *testing.T) {
	for _, payload := range []string{
		"IP сервера 192.168.10.10 недоступен.",
		"Адрес шлюза 10.120.45.67 изменён.",
		"версия 10.2.13.45.67 сборки",
		"Артикул 916.123.45.67 в каталоге.",
		"Служебный ящик noreply@alfabank.ru не принимает писем.",
		"Домен @mail.ru без локальной части.",
		"Ник @ivan_petrov в мессенджере.",
		"Счёт 4070.2810.9000.0001.2345 закрыт.",
		"Оплата картой 4111.1111.1111.1111 прошла.",
	} {
		t.Run(payload, func(t *testing.T) { checkContact(t, payload, nil) })
	}
}

// TestContactScanIsLinear pins the complexity class of the hand-written
// scanner. Every rejected run is skipped whole rather than retried one byte
// later, which is what keeps a numeric table from costing quadratic time.
func TestContactScanIsLinear(t *testing.T) {
	payload := strings.Repeat("1234 ", 4000) + strings.Repeat("ab12", 4000)
	start := time.Now()
	spans := contactDetector{}.Detect(NewContext(payload, nil))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("detect on %d bytes took %v: the scan is super-linear", len(payload), d)
	}
	if len(spans) != 0 {
		t.Fatalf("a run of repeated groups produced %d spans", len(spans))
	}
}
