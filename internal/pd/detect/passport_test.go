package detect

import (
	"sort"
	"testing"

	"pdguard/internal/pd"
)

// passportSpans runs ONLY the passport detector, deliberately bypassing Run:
// sibling detectors live in other files of this package and their findings
// would make these assertions depend on unrelated code. Spans come back in
// document order so a table can spell out the expected substrings verbatim.
func passportSpans(t *testing.T, in string) []pd.Span {
	t.Helper()
	d := passportDetector{}
	spans := d.Detect(NewContext(in, nil))
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	return spans
}

// passportTexts returns the exact source substrings covered by spans of one
// type. Comparing substrings rather than offsets is what proves the mask will
// leave every other byte of the payload untouched.
func passportTexts(t *testing.T, in string, typ pd.Type) []string {
	t.Helper()
	var got []string
	for _, s := range passportSpans(t, in) {
		if s.Type == typ {
			got = append(got, in[s.Start:s.End])
		}
	}
	return got
}

func passportEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPassportSeriesAndNumber(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"joined with space", "паспорт 4509 123456", []string{"4509 123456"}},
		{"contiguous", "паспорт 4509123456", []string{"4509123456"}},
		{"series written as two pairs", "паспорт: 45 09 123456", []string{"45 09 123456"}},
		{"numero sign between groups", "паспорт 45 09 № 123456", []string{"45 09 № 123456"}},
		{"labelled series and number", "серия 4509 номер 123456", []string{"4509", "123456"}},
		{"labelled pairs and number", "серия 45 09 номер 123456", []string{"45 09", "123456"}},
		{"passport rf with numero", "паспорт РФ 4509 № 123456", []string{"4509 № 123456"}},
		{"hyphen separator", "паспорт 4509-123456", []string{"4509-123456"}},
		{"abbreviated labels", "с. 4509 н. 123456", []string{"4509", "123456"}},
		{"uppercase anchor", "ПАСПОРТ 4509 123456", []string{"4509 123456"}},
		{"identity document phrase", "документ, удостоверяющий личность: 4509 123456", []string{"4509 123456"}},
		{"inside a sentence", "Клиент предъявил паспорт 4509 123456 и ушёл", []string{"4509 123456"}},

		// Field order. A form may print either half first, and the two vouch
		// for each other in both directions.
		{"number before series", "номер 123456 серия 4509", []string{"123456", "4509"}},
		{"latin numero label", "серия 4509 N 123456", []string{"4509", "123456"}},
		{"latin no label", "серия 4509 No 123456", []string{"4509", "123456"}},
		{"hash joins the groups", "серия 4509 # 123456", []string{"4509 # 123456"}},

		// Table and form layouts: the label is followed by a colon and any
		// amount of horizontal whitespace.
		{"colons and double space", "Серия: 4509  Номер: 123456", []string{"4509", "123456"}},
		{"tab aligned columns", "Серия:\t4509\tНомер:\t123456", []string{"4509", "123456"}},

		// The number itself printed in groups, the way it is stamped on the
		// document rather than typed into a field.
		{"number split into pairs", "паспорт 4509 12 34 56", []string{"4509 12 34 56"}},
		{"everything in pairs", "паспорт 45 09 12 34 56", []string{"45 09 12 34 56"}},
		{"number split into triples", "паспорт 4509 123 456", []string{"4509 123 456"}},

		// Case forms and abbreviations of the anchor word.
		{"genitive anchor", "Реквизиты паспорта 4509 123456", []string{"4509 123456"}},
		{"instrumental anchor", "удостоверяется паспортом 4509 123456", []string{"4509 123456"}},
		{"abbreviated anchor", "пасп. 4509 123456", []string{"4509 123456"}},
		{"bare abbreviated anchor", "пасп 4509 123456", []string{"4509 123456"}},
		{"slash abbreviation", "п/п 4509 123456", []string{"4509 123456"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passportTexts(t, tc.in, pd.TypePassport)
			if !passportEqual(got, tc.want) {
				t.Fatalf("passport spans = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPassportLabelsStayOutsideSpan pins the rule that drives the whole design:
// "серия" and "номер" are not personal data, so a word between the two digit
// groups must produce two spans instead of one span swallowing that word.
func TestPassportLabelsStayOutsideSpan(t *testing.T) {
	const in = "серия 4509 номер 123456"
	spans := passportSpans(t, in)
	if len(spans) != 2 {
		t.Fatalf("want 2 spans, got %d: %+v", len(spans), spans)
	}
	for _, s := range spans {
		if s.Type != pd.TypePassport {
			t.Fatalf("unexpected type %s", s.Type)
		}
		if s.Src != detectorPassport {
			t.Fatalf("Src = %q, want %q", s.Src, detectorPassport)
		}
		if s.Conf != ppConfPassport {
			t.Fatalf("Conf = %v, want %v", s.Conf, ppConfPassport)
		}
	}
	if got := in[spans[0].Start:spans[0].End]; got != "4509" {
		t.Fatalf("first span = %q, want %q", got, "4509")
	}
	if got := in[spans[1].Start:spans[1].End]; got != "123456" {
		t.Fatalf("second span = %q, want %q", got, "123456")
	}
	// The bytes between the two spans must be the untouched label.
	if got := in[spans[0].End:spans[1].Start]; got != " номер " {
		t.Fatalf("gap between spans = %q, want %q", got, " номер ")
	}
}

func TestPassportSubdivisionCode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"dashed", "код подразделения 770-001", []string{"770-001"}},
		{"six digits", "код подразделения 770001", []string{"770001"}},
		{"slash abbreviation", "к/п 770-001", []string{"770-001"}},
		{"short abbreviation", "кп 770-001", []string{"770-001"}},
		{"bare word", "подразделение 770-001", []string{"770-001"}},
		{"space instead of a hyphen", "код подразделения 770 001", []string{"770 001"}},
		{"abbreviated label", "код подр. 770001", []string{"770001"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passportTexts(t, tc.in, pd.TypeSubdivisionCode)
			if !passportEqual(got, tc.want) {
				t.Fatalf("subdivision spans = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPassportIssuerAuthority(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			"ovd stops at comma",
			"Паспорт выдан ОВД Тверского района города Москвы, дата выдачи 01.01.2010",
			[]string{"ОВД Тверского района города Москвы"},
		},
		{
			"abbreviated city keeps its dot",
			"выдан ГУ МВД России по г. Москве",
			[]string{"ГУ МВД России по г. Москве"},
		},
		{
			"kem vydan with colon",
			"кем выдан: УФМС России по Московской области в Басманном районе",
			[]string{"УФМС России по Московской области в Басманном районе"},
		},
		{
			"gor abbreviation",
			"выдан ТП УФМС России по гор. Москве по району Арбат",
			[]string{"ТП УФМС России по гор. Москве по району Арбат"},
		},
		{
			"trailing period is trimmed",
			"Выдан Отделом УФМС России по г. Санкт-Петербургу.",
			[]string{"Отделом УФМС России по г. Санкт-Петербургу"},
		},
		{
			"stops before the subdivision code",
			"выдан ОВД Басманного района код подразделения 770-001",
			[]string{"ОВД Басманного района"},
		},
		{
			// The issue date is the most common thing to stand between the
			// anchor and the authority, and the walk stops on a bare number:
			// without ppSkipIssueDate the whole clause was lost.
			"issue date between the anchor and the authority",
			"паспорт 4509 123456, выдан 20.06.2015 ГУ МВД России по г. Москве",
			[]string{"ГУ МВД России по г. Москве"},
		},
		{
			"textual issue date between the anchor and the authority",
			"выдан 20 июня 2015 года ОВД Басманного района",
			[]string{"ОВД Басманного района"},
		},
		{
			// The issuer lexicon holds the glue of an authority name, but glue
			// alone is not an authority: masking the preposition of "выдано в
			// 2019 году" is a pure loss on the metric.
			"a preposition is not an authority",
			"Водительское удостоверение 9902 123456 выдано в 2019 году.",
			nil,
		},
		{
			"a lone institution word names nobody",
			"Свидетельство о рождении II-МЮ 123456 выдано ЗАГС.",
			nil,
		},
		{
			"migration office abbreviation",
			"выдан ОУФМС России по Тульской области",
			[]string{"ОУФМС России по Тульской области"},
		},
		{
			"territorial point with a city abbreviation",
			"выдан ТП в г. Щёкино УФМС России",
			[]string{"ТП в г. Щёкино УФМС России"},
		},
		{
			"migration point of a district office",
			"выдан МП ОМВД России по Тульскому району",
			[]string{"МП ОМВД России по Тульскому району"},
		},
		{
			// Quotation marks belong to the name of the division. The star
			// strategy leaves non-alphanumerics in place, so carrying them
			// inside the span costs the metric nothing and keeps the name whole.
			"quoted division name",
			"выдан ОВД «Центральный» города Твери",
			[]string{"ОВД «Центральный» города Твери"},
		},
		{
			"registry office naming a city",
			"выдано ЗАГС города Москвы",
			[]string{"ЗАГС города Москвы"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passportTexts(t, tc.in, pd.TypePassportIssuer)
			if !passportEqual(got, tc.want) {
				t.Fatalf("issuer spans = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPassportBirthPlace(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"city abbreviation", "место рождения: г. Москва", []string{"г. Москва"}},
		{"full word city", "Уроженец города Казани", []string{"города Казани"}},
		{"village with region", "родился в с. Ивановка Тульской области", []string{"с. Ивановка Тульской области"}},
		{"hamlet", "место рождения дер. Малые Вязёмы", []string{"дер. Малые Вязёмы"}},
		{"female form", "уроженка г. Твери", []string{"г. Твери"}},
		{"stops at comma", "место рождения г. Тула, паспорт 4509 123456", []string{"г. Тула"}},
		{
			"city followed by its region",
			"место рождения: г. Тула Тульской области",
			[]string{"г. Тула Тульской области"},
		},
		{
			// The comma is carried only because a region word follows it; the
			// trailing period is trimmed off the span the same way it always is.
			"comma before the region is part of the place",
			"место рождения: с. Ивановка, Тульская обл.",
			[]string{"с. Ивановка, Тульская обл"},
		},
		{
			"comma before the next field still stops the span",
			"место рождения г. Тула, гражданство РФ",
			[]string{"г. Тула"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passportTexts(t, tc.in, pd.TypeBirthPlace)
			if !passportEqual(got, tc.want) {
				t.Fatalf("birth place spans = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPassportCitizenship(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"abbreviation", "гражданство РФ", []string{"РФ"}},
		{"two words", "гражданин Российской Федерации", []string{"Российской Федерации"}},
		{"republic", "Гражданка Республики Беларусь", []string{"Республики Беларусь"}},
		{"genitive country", "гражданство: Казахстана", []string{"Казахстана"}},
		{"stops at comma", "гражданство России, паспорт 4509 123456", []string{"России"}},
		{"adjective before the label", "российское гражданство подтверждено", []string{"российское"}},
		{"adjective in the genitive", "подтверждение российского гражданства", []string{"российского"}},
		{"citizen of a country", "гражданин России обратился в банк", []string{"России"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passportTexts(t, tc.in, pd.TypeCitizenship)
			if !passportEqual(got, tc.want) {
				t.Fatalf("citizenship spans = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPassportCombined checks that neighbouring fields of one passport block do
// not bleed into each other: each span must cover its own value and nothing of
// the label or the next field.
func TestPassportCombined(t *testing.T) {
	const in = "Паспорт гражданина РФ 4509 123456, выдан ОВД города Тулы, " +
		"код подразделения 710-002, место рождения: г. Тула"

	want := map[pd.Type][]string{
		pd.TypePassport:        {"4509 123456"},
		pd.TypeCitizenship:     {"РФ"},
		pd.TypePassportIssuer:  {"ОВД города Тулы"},
		pd.TypeSubdivisionCode: {"710-002"},
		pd.TypeBirthPlace:      {"г. Тула"},
	}
	for typ, exp := range want {
		if got := passportTexts(t, in, typ); !passportEqual(got, exp) {
			t.Errorf("%s spans = %q, want %q", typ, got, exp)
		}
	}
}

// TestPassportNegatives is the table that protects the metric: every entry is a
// text where masking anything at all is a pure loss. A bare ten-digit run, a
// phone number, a sum, an inventory number and the figurative "паспорт
// проекта" must all come back empty.
func TestPassportNegatives(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"ten digits without anchor", "1234567890"},
		{"phone number", "Телефон: 8 (915) 123-45-67"},
		{"money amount", "Сумма перевода составила 4509123456 рублей"},
		{"inventory number", "Инвентарный номер 123456 присвоен станку"},
		{"serial number", "Серийный номер 1234567890 нанесён на корпус"},
		{"figurative passport", "Паспорт проекта 4509 123456 утверждён комитетом"},
		{"famous poet", "Александр Пушкин — великий русский поэт"},
		{"bank account", "Счёт 40817810099910004312 открыт в отделении банка"},
		{"credit issued, no authority", "Кредит выдан на сумму 100000 рублей"},
		{"citizen without a country", "Гражданин обратился в отделение банка"},
		{"born in a year", "Родился в 1985 году в семье военного"},
		{"code without the word subdivision", "Код 770-001 присвоен участку"},
		{"long digit run", "Идентификатор операции 45091234567890"},
		{"inventory number near a passport mention", "Паспорт клиента получен, инвентарный номер 123456"},

		// The antipode of every recall case added above. Each one is a shape
		// the widened rules now reach, standing in a context that makes it
		// something other than a passport.
		{"row number column header", "№ п/п 4509 123456 в реестре"},
		{"row numbers in a table", "№ п/п 1 2 3"},
		{"a longer run of pairs is not a passport", "Паспорт получен, показатели 45 09 12 34 56 78 90"},
		{"latin n inside an english word", "Report in 123456 lines"},
		{"hash without a series is a ticket", "Задача # 123456 закрыта"},
		{"latin numero without a series", "Ticket No 123456 resolved"},
		{"double citizenship names no country", "Двойное гражданство не заявлено"},
		{"citizenship without a value", "Клиент получил гражданство в 2020 году"},
		{"phone typed in pairs", "Телефон 8 916 123 45 67"},
		{"case number after a passport mention", "Клиент позвонил, номер 123456 дела закрыт"},
		{"bank branch address is not a birth place", "Отделение банка: г. Москва, ул. Тверская, 7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, s := range passportSpans(t, tc.in) {
				t.Errorf("unexpected %s span %q", s.Type, tc.in[s.Start:s.End])
			}
		})
	}
}

// TestPassportRespectsEnabled verifies the per-type switch the service uses to
// turn categories off from configuration without a redeploy.
func TestPassportRespectsEnabled(t *testing.T) {
	const in = "паспорт 4509 123456, гражданство РФ"
	ctx := NewContext(in, func(typ pd.Type) bool { return typ != pd.TypePassport })
	for _, s := range (passportDetector{}).Detect(ctx) {
		if s.Type == pd.TypePassport {
			t.Fatalf("disabled type was still detected: %q", in[s.Start:s.End])
		}
	}
}

// TestPassportDeterministic guards the idempotency requirement: a retried
// request must produce byte-identical output, so detection may not depend on
// map iteration order or any other run-to-run variation.
func TestPassportDeterministic(t *testing.T) {
	const in = "Паспорт гражданина РФ 4509 123456, выдан ОВД города Тулы, место рождения: г. Тула"
	first := passportSpans(t, in)
	if len(first) == 0 {
		t.Fatal("expected at least one span")
	}
	for i := 0; i < 5; i++ {
		again := passportSpans(t, in)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d spans, first run %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d span %d = %+v, want %+v", i, j, again[j], first[j])
			}
		}
	}
}

// TestPassportYieldsToOtherDocuments is the regression that an independent
// reviewer's corpus exposed: "Водительское удостоверение серия 77 12 № 345678"
// fits the passport shape exactly, the passport span was emitted first, and
// Resolve — which sees only offsets and confidences — dropped the correct
// DRIVER_LICENSE span in its favour. The evidence that separates the two lives
// to the LEFT of the digits, so the detector has to weigh it at the moment of
// emission.
func TestPassportYieldsToOtherDocuments(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"driver licence with series label and numero", "Водительское удостоверение серия 77 12 № 345678 категории B."},
		{"driver licence joined groups", "Водительское удостоверение 77 12 345678 категории B."},
		{"driver licence solid series", "Водительское удостоверение 7712 345678."},
		{"driver licence latin numero", "Водительское удостоверение 77 12 N 345678."},
		{"driver licence split labels", "Водительское удостоверение серия 7712 номер 345678."},
		{"driver licence genitive cue", "Удостоверение водителя серия 77 12 № 345678."},
		{"driver licence abbreviation", "В/у серия 77 12 № 345678."},
		{"driver licence english cue", "Driver license серия 77 12 № 345678."},
		{"foreign passport", "Загранпаспорт серия 75 номер 1234567 оформлен."},
		{"snils", "СНИЛС серия 112 номер 233445."},
		{"oms policy", "Полис ОМС серия 1234 номер 567890."},
		{"military id", "Военный билет серия 4509 номер 123456."},
		{"residence permit", "Вид на жительство серия 4509 номер 123456."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := passportTexts(t, tc.in, pd.TypePassport); len(got) != 0 {
				t.Fatalf("passport must stand aside for another document, got %q", got)
			}
		})
	}
}

// TestPassportKeepsItsOwnFormsNextToOtherDocuments proves the veto above is
// conditional. A record that lists several documents still yields its passport:
// the marker of the other document is inside the window, but so is the word
// "паспорт", and the specific evidence wins over the generic "серия".
func TestPassportKeepsItsOwnFormsNextToOtherDocuments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"joined", "паспорт 4509 123456", []string{"4509 123456"}},
		{"contiguous", "паспорт 4509123456", []string{"4509123456"}},
		{"separating words", "паспорт серия 4509 номер 123456", []string{"4509", "123456"}},
		{"separating words no anchor", "серия 4509 номер 123456", []string{"4509", "123456"}},
		{"pairs", "паспорт: 45 09 123456", []string{"45 09 123456"}},
		{"after snils", "СНИЛС 112-233-445 95, паспорт 4509 123456.", []string{"4509 123456"}},
		{"after driver licence", "Водительское удостоверение 9902 123456, паспорт 4509 123456.", []string{"4509 123456"}},
		{"after oms", "Полис ОМС оформлен, паспорт серия 4509 номер 123456.", []string{"4509", "123456"}},
		{"licence mention in a previous sentence", "Водительские права утеряны. Паспорт 4509 123456 предъявлен.", []string{"4509 123456"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passportTexts(t, tc.in, pd.TypePassport)
			if !passportEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPassportOtherDocMarkersStayNegative keeps the veto from becoming a way to
// mask numbers: with no passport anchor at all, ten bare digits are still not
// personal data to this detector.
func TestPassportOtherDocMarkersStayNegative(t *testing.T) {
	for _, in := range []string{
		"Водительское удостоверение 4509123456 предъявлено.",
		"Клиент назвал 4509 123456 в разговоре.",
		"Инвентарный номер 123456 списан.",
	} {
		if got := passportTexts(t, in, pd.TypePassport); len(got) != 0 {
			t.Fatalf("payload %q: expected no passport spans, got %q", in, got)
		}
	}
}
