package detect

import (
	"sort"
	"testing"

	"pdguard/internal/pd"
)

const (
	dtDriver9902 = "9902 123456"
	dtSnils      = "112-233-445 95"
	dtAB1234567  = "АБ 1234567"
	dt77AA123456 = "77 АА 123456"
)

// wantDoc is the observable part of a span: the exact substring it covers, its
// type and its confidence. Offsets are checked indirectly through the
// substring, which is what actually matters for masking.
type wantDoc struct {
	text string
	typ  pd.Type
	conf float64
}

// runDocs exercises the docs detector alone, so a sibling detector registered
// later cannot change this file's expectations.
func runDocs(t *testing.T, payload string) []pd.Span {
	t.Helper()
	ctx := NewContext(payload, nil)
	spans := docsDetector{}.Detect(ctx)
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	return spans
}

func checkDocs(t *testing.T, payload string, want []wantDoc) {
	t.Helper()
	ctx := NewContext(payload, nil)
	got := runDocs(t, payload)
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
		if g.Src != "docs" {
			t.Errorf("payload %q: span %d src %q, want %q", payload, i, g.Src, "docs")
		}
	}
}

func TestDocsPositive(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantDoc
	}{
		{
			name:    "driver license grouped",
			payload: "Водительское удостоверение 9902 123456 выдано в 2019 году.",
			want:    []wantDoc{{dtDriver9902, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "driver license split series",
			payload: "в/у 99 02 123456",
			want:    []wantDoc{{"99 02 123456", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "driver license solid digits",
			payload: "Водительские права 9902123456.",
			want:    []wantDoc{{"9902123456", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "driver license uppercase anchor",
			payload: "ВОДИТЕЛЬСКОЕ УДОСТОВЕРЕНИЕ 9902 123456",
			want:    []wantDoc{{dtDriver9902, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "driver license old cyrillic series",
			payload: "Водительское удостоверение АБ 123456",
			want:    []wantDoc{{"АБ 123456", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "snils grouped with valid checksum",
			payload: "СНИЛС 112-233-445 95 подтверждён.",
			want:    []wantDoc{{dtSnils, pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "snils fully hyphenated",
			payload: "Страховое свидетельство 112-233-445-95",
			want:    []wantDoc{{"112-233-445-95", pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "snils solid without anchor is accepted on checksum",
			payload: "Реквизит 11223344595 принят.",
			want:    []wantDoc{{"11223344595", pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "snils with broken checksum but explicit anchor",
			payload: "Страховой номер 112-233-445 96",
			want:    []wantDoc{{"112-233-445 96", pd.TypeSNILS, docConfAnchored}},
		},
		{
			name:    "snils starting with 8 needs the anchor",
			payload: "СНИЛС 80000000072",
			want:    []wantDoc{{"80000000072", pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "foreign passport",
			payload: "Загранпаспорт 75 1234567 действителен.",
			want:    []wantDoc{{"75 1234567", pd.TypeForeignPassport, docConfAnchored}},
		},
		{
			name:    "foreign passport inflected anchor and solid number",
			payload: "Данные заграничного паспорта 751234567",
			want:    []wantDoc{{"751234567", pd.TypeForeignPassport, docConfAnchored}},
		},
		{
			name:    "birth certificate with anchor",
			payload: "Свидетельство о рождении II-МЮ 123456 выдано ЗАГС.",
			want:    []wantDoc{{"II-МЮ 123456", pd.TypeBirthCertificate, docConfAnchored}},
		},
		{
			name:    "birth certificate shape alone",
			payload: "Реквизиты: IV-АБ 654321",
			want:    []wantDoc{{"IV-АБ 654321", pd.TypeBirthCertificate, docConfWeak}},
		},
		{
			name:    "military id",
			payload: "Военный билет АБ 1234567",
			want:    []wantDoc{{dtAB1234567, pd.TypeMilitaryID, docConfAnchored}},
		},
		{
			name:    "military id with number sign",
			payload: "Воен. билет АБ № 1234567",
			want:    []wantDoc{{"АБ № 1234567", pd.TypeMilitaryID, docConfAnchored}},
		},
		{
			name:    "residence permit",
			payload: "Вид на жительство 123456789 оформлен.",
			want:    []wantDoc{{"123456789", pd.TypeResidencePermit, docConfAnchored}},
		},
		{
			name:    "temporary residence permit abbreviation",
			payload: "РВП 1234567",
			want:    []wantDoc{{"1234567", pd.TypeResidencePermit, docConfAnchored}},
		},
		{
			name:    "oms policy solid",
			payload: "Полис ОМС 1234567890123456",
			want:    []wantDoc{{"1234567890123456", pd.TypeOMS, docConfAnchored}},
		},
		{
			name:    "oms policy grouped",
			payload: "Медицинский полис 1234 5678 9012 3456",
			want:    []wantDoc{{"1234 5678 9012 3456", pd.TypeOMS, docConfAnchored}},
		},
		{
			name:    "driver license inflected anchor",
			payload: "Реквизиты водительского удостоверения 9902 123456",
			want:    []wantDoc{{dtDriver9902, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "driver license genitive noun anchor",
			payload: "Удостоверения водителя 9902 123456 нет в деле",
			want:    []wantDoc{{dtDriver9902, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			// Pre-2011 licences print the region code in front of the Cyrillic
			// series; the short rule must not also claim the tail of it.
			name:    "driver license region and cyrillic series",
			payload: "Водительское удостоверение 77 АА 123456",
			want:    []wantDoc{{dt77AA123456, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "driver license abbreviated anchor",
			payload: "Вод. удостоверение 77 АА 123456",
			want:    []wantDoc{{dt77AA123456, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			name:    "snils grouped with spaces only",
			payload: "СНИЛС 112 233 445 95 подтверждён.",
			want:    []wantDoc{{"112 233 445 95", pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "snils after a colon",
			payload: "СНИЛС: 112-233-445-95",
			want:    []wantDoc{{"112-233-445-95", pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "pension certificate is the same number",
			payload: "Пенсионное свидетельство 112-233-445 95",
			want:    []wantDoc{{dtSnils, pd.TypeSNILS, docConfChecksum}},
		},
		{
			name:    "foreign passport with a numero sign",
			payload: "Загранпаспорт № 751234567",
			want:    []wantDoc{{"751234567", pd.TypeForeignPassport, docConfAnchored}},
		},
		{
			name:    "oms policy of the old pattern",
			payload: "Полис ОМС АБ 1234567",
			want:    []wantDoc{{dtAB1234567, pd.TypeOMS, docConfAnchored}},
		},
		{
			name:    "oms policy with a six digit number",
			payload: "Медицинский полис ВС 123456",
			want:    []wantDoc{{"ВС 123456", pd.TypeOMS, docConfAnchored}},
		},
		{
			name:    "oms policy named in full",
			payload: "Полис обязательного медицинского страхования 1234 5678 9012 3456",
			want:    []wantDoc{{"1234 5678 9012 3456", pd.TypeOMS, docConfAnchored}},
		},
		{
			name:    "two documents in one sentence",
			payload: "СНИЛС 112-233-445 95, военный билет АБ 1234567.",
			want: []wantDoc{
				{dtSnils, pd.TypeSNILS, docConfChecksum},
				{dtAB1234567, pd.TypeMilitaryID, docConfAnchored},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkDocs(t, tc.payload, tc.want) })
	}
}

func TestDocsNegative(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "eleven digits with broken checksum and no anchor",
			payload: "Заказ 12345678901 обработан вчера.",
		},
		{
			name:    "phone-shaped run with valid checksum and no anchor",
			payload: "Перезвоните на 80000000072 после обеда.",
		},
		{
			name:    "repeated digits never form a snils",
			payload: "Заполнитель 00000000000 в шаблоне.",
		},
		{
			name:    "sixteen digits without an oms anchor stay for the card detector",
			payload: "Карта 1234 5678 9012 3456 заблокирована.",
		},
		{
			name:    "roman numerals in ordinary prose",
			payload: "Глава II описана в разделе III-IV подробно.",
		},
		{
			name:    "ten digits without a driver licence anchor",
			payload: "Отделение банка обработало 9902 123456 обращений.",
		},
		{
			name:    "nine digits without a residence permit anchor",
			payload: "Инвентарный номер 123456789 в описи.",
		},
		{
			name:    "two-plus-seven digits without a foreign passport anchor",
			payload: "Партия 75 1234567 отгружена.",
		},
		{
			name:    "cyrillic series and seven digits without a military anchor",
			payload: "Партия АБ 1234567 принята складом.",
		},
		{
			name:    "anchor-like substring inside an unrelated word",
			payload: "Омский завод отгрузил 1234567890123456 единиц.",
		},
		{
			name:    "vuz is not a driver licence cue",
			payload: "Вуз принял 9902 123456 заявлений.",
		},
		{
			name:    "snils digits embedded in a longer run",
			payload: "Идентификатор 1122334459512345 обновлён.",
		},

		// Antipodes of the shapes added above.
		{
			// The INN belongs to the finance detector; twelve digits next to
			// its own cue word must not be read as any document here.
			name:    "inn is not an identity document",
			payload: "ИНН 771234567890 указан в договоре.",
		},
		{
			name:    "oms cue with an unrelated amount",
			payload: "Полис ОМС оформлен, оплачено 123456 рублей.",
		},
		{
			name:    "cyrillic pair and digits without an oms cue",
			payload: "Отгружено ВС 123456 единиц.",
		},
		{
			name:    "region series without a driver licence cue",
			payload: "Партия 77 АА 123456 принята складом.",
		},
		{
			name:    "pension mention with an unrelated amount",
			payload: "Пенсионное свидетельство оформлено, начислено 12345678901 копеек.",
		},
		{
			name:    "foreign passport cue in another clause",
			payload: "Загранпаспорт получен. Заказ 751234567 отгружен.",
		},
		{
			name:    "nine digits after a driver licence cue in another sentence",
			payload: "Водительское удостоверение восстановлено. Счёт 9902 123456 оплачен.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runDocs(t, tc.payload); len(got) != 0 {
				t.Fatalf("payload %q: expected no spans, got %+v", tc.payload, got)
			}
		})
	}
}

func TestDocsRespectsEnabled(t *testing.T) {
	payload := "Водительское удостоверение 9902 123456"
	ctx := NewContext(payload, func(t pd.Type) bool { return t != pd.TypeDriverLicense })
	if got := (docsDetector{}).Detect(ctx); len(got) != 0 {
		t.Fatalf("disabled type still reported: %+v", got)
	}
}

func TestDocsSNILSChecksum(t *testing.T) {
	cases := []struct {
		digits string
		want   bool
	}{
		{"11223344595", true},
		{"11223344596", false},
		{"12345678901", false},
		{"00000000000", true}, // arithmetically valid; rejected by the filler rule
		{"1122334459", false}, // too short
	}
	for _, tc := range cases {
		if got := docSNILSChecksum(tc.digits); got != tc.want {
			t.Errorf("docSNILSChecksum(%q) = %v, want %v", tc.digits, got, tc.want)
		}
	}
}

func TestDocsRomanValue(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"i", 1}, {"ii", 2}, {"iv", 4}, {"ix", 9}, {"xxx", 30}, {"xl", 40},
		{"ab", 0}, {"", 0},
	}
	for _, tc := range cases {
		if got := docRomanValue(tc.in); got != tc.want {
			t.Errorf("docRomanValue(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestDocsDetectorIdentity(t *testing.T) {
	d := docsDetector{}
	if d.Name() != "docs" {
		t.Fatalf("Name() = %q, want %q", d.Name(), "docs")
	}
	if len(d.Types()) != 7 {
		t.Fatalf("Types() returned %d entries, want 7", len(d.Types()))
	}
}

// TestDocsDriverLicenseSeparatingWords covers the layouts a printed form uses
// for a licence: the series and the number introduced by their own label words,
// exactly as §4.2 of the specification describes for a passport. The label
// itself is never masked — it is not personal data, and the quality metric
// charges for every byte we touch without cause — so a spelled-out label splits
// the value into the two digit groups it really is.
func TestDocsDriverLicenseSeparatingWords(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantDoc
	}{
		{
			"series label and numero sign",
			"Водительское удостоверение серия 77 12 № 345678 категории B.",
			[]wantDoc{{"77 12 № 345678", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			"solid series with numero sign",
			"Водительское удостоверение 7712 № 345678.",
			[]wantDoc{{"7712 № 345678", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			"latin numero sign",
			"Водительское удостоверение 77 12 N 345678.",
			[]wantDoc{
				{"77 12", pd.TypeDriverLicense, docConfAnchored},
				{"345678", pd.TypeDriverLicense, docConfAnchored},
			},
		},
		{
			"spelled out labels",
			"Водительское удостоверение серия 7712 номер 345678.",
			[]wantDoc{
				{"7712", pd.TypeDriverLicense, docConfAnchored},
				{"345678", pd.TypeDriverLicense, docConfAnchored},
			},
		},
		{
			"spelled out labels with pairs",
			"Удостоверение водителя серия 77 12 номер 345678.",
			[]wantDoc{
				{"77 12", pd.TypeDriverLicense, docConfAnchored},
				{"345678", pd.TypeDriverLicense, docConfAnchored},
			},
		},
		{
			"abbreviated cue",
			"В/у 77 12 № 345678 действительно до 2030 года.",
			[]wantDoc{{"77 12 № 345678", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			"bare groups still match",
			"Водительское удостоверение 77 12 345678.",
			[]wantDoc{{"77 12 345678", pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			// The two-letter Cyrillic series of the pre-2011 layout stands
			// between digits exactly as a label does, and must stay INSIDE the
			// span: it is part of the document number, not a caption.
			"old region series is not a label",
			"Водительское удостоверение 77 АА 123456 старого образца.",
			[]wantDoc{{dt77AA123456, pd.TypeDriverLicense, docConfAnchored}},
		},
		{
			"foreign passport takes the same labels",
			"Загранпаспорт серия 75 номер 1234567 оформлен.",
			[]wantDoc{
				{"75", pd.TypeForeignPassport, docConfAnchored},
				{"1234567", pd.TypeForeignPassport, docConfAnchored},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkDocs(t, tc.payload, tc.want) })
	}
}

// TestDocsDriverLicenseLabelsStayNegative keeps the widened shape from turning
// any labelled number into a licence: the cue word is still mandatory, and the
// clause tests still apply.
func TestDocsDriverLicenseLabelsStayNegative(t *testing.T) {
	for _, payload := range []string{
		"Серия 77 12 № 345678 накладной оформлена.",
		"Договор серия 77 12 номер 345678 подписан.",
		"Водительские права были утеряны, дело 55 66 778899 закрыто.",
		"Водительское удостоверение утеряно. Заказ 77 12 345678 отменён.",
	} {
		for _, s := range runDocs(t, payload) {
			if s.Type == pd.TypeDriverLicense {
				t.Errorf("payload %q: unexpected driver licence span %q", payload, payload[s.Start:s.End])
			}
		}
	}
}
