package detect

import (
	"testing"

	"pdguard/internal/pd"
)

// wantAddr is one expected span: the category plus the EXACT substring the
// detector must cover. Comparing the substring rather than raw offsets is what
// proves the marker stayed outside the span — "ул." and "д." must survive the
// masking byte for byte, otherwise the Levenshtein score suffers.
type wantAddr struct {
	typ  pd.Type
	text string
}

func runAddr(t *testing.T, payload string) []pd.Span {
	t.Helper()
	ctx := NewContext(payload, nil)
	return addressDetector{}.Detect(ctx)
}

func checkAddr(t *testing.T, payload string, want []wantAddr) {
	t.Helper()
	got := runAddr(t, payload)
	if len(got) != len(want) {
		t.Fatalf("payload %q: got %d spans, want %d\n%s", payload, len(got), len(want), dumpAddr(payload, got))
	}
	for i, w := range want {
		g := got[i]
		if g.Type != w.typ || payload[g.Start:g.End] != w.text {
			t.Errorf("payload %q: span %d = (%s, %q), want (%s, %q)",
				payload, i, g.Type, payload[g.Start:g.End], w.typ, w.text)
		}
		if g.Src != "address" {
			t.Errorf("payload %q: span %d has Src %q, want \"address\"", payload, i, g.Src)
		}
		if g.Conf < 0.7 {
			t.Errorf("payload %q: span %d has Conf %v, below the 0.7 floor", payload, i, g.Conf)
		}
	}
}

func dumpAddr(payload string, spans []pd.Span) string {
	out := ""
	for _, s := range spans {
		out += "  " + string(s.Type) + " " + s.Hint + " " + payload[s.Start:s.End] + "\n"
	}
	if out == "" {
		out = "  <no spans>\n"
	}
	return out
}

func TestAddressComponents(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantAddr
	}{
		{
			name:    "full address behind an anchor",
			payload: "Клиент проживает по адресу: г. Москва, ул. Ленина, д. 5, кв. 12",
			want: []wantAddr{
				{pd.TypeCity, "Москва"},
				{pd.TypeStreet, "Ленина"},
				{pd.TypeHouse, "5"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "postal code, hyphenated city, multi-word street, letter in house",
			payload: "Индекс 101000, г. Санкт-Петербург, наб. реки Фонтанки, д. 12А",
			want: []wantAddr{
				{pd.TypePostalCode, "101000"},
				{pd.TypeCity, "Санкт-Петербург"},
				{pd.TypeStreet, "реки Фонтанки"},
				{pd.TypeHouse, "12А"},
			},
		},
		{
			name:    "street type on the right of the name",
			payload: "Доставить по адресу: Ленинский проспект, д. 32",
			want: []wantAddr{
				{pd.TypeStreet, "Ленинский"},
				{pd.TypeHouse, "32"},
			},
		},
		{
			name:    "corpus is a separate span of the same type",
			payload: "Адрес: ул. Мира, д. 5 корп. 2",
			want: []wantAddr{
				{pd.TypeStreet, "Мира"},
				{pd.TypeHouse, "5"},
				{pd.TypeHouse, "2"},
			},
		},
		{
			name:    "country inside an address context",
			payload: "Адрес: Россия, г. Казань, ул. Баумана, д. 3",
			want: []wantAddr{
				{pd.TypeCountry, "Россия"},
				{pd.TypeCity, "Казань"},
				{pd.TypeStreet, "Баумана"},
				{pd.TypeHouse, "3"},
			},
		},
		{
			name:    "office counts as an apartment",
			payload: "Адрес доставки: ул. Профсоюзная, д. 10, офис 501",
			want: []wantAddr{
				{pd.TypeStreet, "Профсоюзная"},
				{pd.TypeHouse, "10"},
				{pd.TypeApartment, "501"},
			},
		},
		{
			// A street named after a public figure IS masked once it is part of
			// a real address: two neighbouring components are the evidence.
			name:    "street named after a poet, with neighbours",
			payload: "г. Химки, улица Пушкина, д. 4",
			want: []wantAddr{
				{pd.TypeCity, "Химки"},
				{pd.TypeStreet, "Пушкина"},
				{pd.TypeHouse, "4"},
			},
		},
		{
			name:    "village marker",
			payload: "Зарегистрирован: дер. Гадюкино, д. 7",
			want: []wantAddr{
				{pd.TypeCity, "Гадюкино"},
				{pd.TypeHouse, "7"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkAddr(t, c.payload, c.want) })
	}
}

func TestAddressNegative(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			// Specification requirement: the address of a bank branch is not
			// the client's personal data and must stay untouched.
			name:    "bank branch address",
			payload: "Адрес отделения банка: г. Москва, ул. Тверская, д. 7",
		},
		{
			name:    "bank branch, other wording",
			payload: "Ближайший банкомат: г. Тула, ул. Советская, д. 1",
		},
		{
			// A lone toponym may be a plain mention, not somebody's address.
			name:    "single street with no other component and no anchor",
			payload: "Памятник Пушкину стоит на улице Пушкина.",
		},
		{
			name:    "six digits that are a sum of money",
			payload: "Сумма перевода 450000 рублей зачислена на счёт.",
		},
		{
			name:    "дом is a building only in front of a number",
			payload: "Рядом строится дом культуры и новая школа.",
		},
		{
			name:    "квартира-студия is a term, not an address",
			payload: "Клиенту предложена квартира-студия в новом доме.",
		},
		{
			name:    "a year is not a city",
			payload: "В 2020 г. Иванов открыл вклад.",
		},
		{
			name:    "a country on its own is not an address",
			payload: "Товары поставляются в Казахстан и обратно.",
		},
		{
			name:    "square metres are not a flat number",
			payload: "Площадь помещения 45 кв. м, потолки высокие.",
		},
		{
			name:    "a famous person is not personal data",
			payload: "Александр Пушкин — русский поэт.",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runAddr(t, c.payload); len(got) != 0 {
				t.Errorf("payload %q: expected no spans, got:\n%s", c.payload, dumpAddr(c.payload, got))
			}
		})
	}
}

// TestAddressPersonalAnchorBeatsBranchWord covers the tie-break inside the
// bank-place rule: once the text has moved on from the branch to the client,
// the client's own address must be masked again.
func TestAddressPersonalAnchorBeatsBranchWord(t *testing.T) {
	payload := "Клиент был в отделении, проживает по адресу: г. Омск, ул. Мира, д. 2"
	checkAddr(t, payload, []wantAddr{
		{pd.TypeCity, "Омск"},
		{pd.TypeStreet, "Мира"},
		{pd.TypeHouse, "2"},
	})
}

func TestAddressFallbackWholeString(t *testing.T) {
	// Nothing here decomposes into components, so the anchored run is emitted
	// as one ADDRESS span — the only case where that is allowed.
	checkAddr(t, "Адрес: Тверская 12", []wantAddr{{pd.TypeAddress, "Тверская 12"}})
}

func TestAddressFallbackSkipsNonAddresses(t *testing.T) {
	cases := []string{
		"Адрес: ivan2@example.com",       // an e-mail is not a postal address
		"Адрес: https://example.com/a1",  // neither is a URL
		"Адрес отделения: Тверская 12",   // bank premises again
		"По этому адресу никто не живёт", // no number at all
	}
	for _, payload := range cases {
		if got := runAddr(t, payload); len(got) != 0 {
			t.Errorf("payload %q: expected no spans, got:\n%s", payload, dumpAddr(payload, got))
		}
	}
}

func TestAddressConfidence(t *testing.T) {
	anchored := runAddr(t, "Проживает по адресу: г. Тверь, ул. Мира, д. 3")
	for _, s := range anchored {
		if s.Conf != 0.95 {
			t.Errorf("anchored span %s has Conf %v, want 0.95", s.Type, s.Conf)
		}
	}
	// No anchor word, but three components standing together.
	neighbours := runAddr(t, "г. Тверь, ул. Мира, д. 3")
	if len(neighbours) != 3 {
		t.Fatalf("expected 3 spans without an anchor, got:\n%s", dumpAddr("г. Тверь, ул. Мира, д. 3", neighbours))
	}
	for _, s := range neighbours {
		if s.Conf != 0.8 {
			t.Errorf("neighbour-only span %s has Conf %v, want 0.8", s.Type, s.Conf)
		}
	}
}

func TestAddressRespectsEnabled(t *testing.T) {
	payload := "Клиент проживает по адресу: г. Москва, ул. Ленина, д. 5, кв. 12"
	ctx := NewContext(payload, func(t pd.Type) bool { return t == pd.TypeStreet })
	got := addressDetector{}.Detect(ctx)
	if len(got) != 1 || got[0].Type != pd.TypeStreet || payload[got[0].Start:got[0].End] != "Ленина" {
		t.Fatalf("expected only the STREET span, got:\n%s", dumpAddr(payload, got))
	}
}

func TestAddressDetectorIdentity(t *testing.T) {
	d := addressDetector{}
	if d.Name() != "address" {
		t.Errorf("Name() = %q, want \"address\"", d.Name())
	}
	want := map[pd.Type]bool{
		pd.TypeAddress: true, pd.TypeCountry: true, pd.TypePostalCode: true,
		pd.TypeCity: true, pd.TypeStreet: true, pd.TypeHouse: true, pd.TypeApartment: true,
	}
	if len(d.Types()) != len(want) {
		t.Fatalf("Types() = %v", d.Types())
	}
	for _, tp := range d.Types() {
		if !want[tp] {
			t.Errorf("Types() contains unexpected %s", tp)
		}
	}
}

// TestAddressCaseInsensitive guards the specification's requirement that
// identification is case-insensitive: an all-caps address must produce the
// same components as the normal one.
func TestAddressCaseInsensitive(t *testing.T) {
	checkAddr(t, "АДРЕС: Г. КАЗАНЬ, УЛ. БАУМАНА, Д. 3", []wantAddr{
		{pd.TypeCity, "КАЗАНЬ"},
		{pd.TypeStreet, "БАУМАНА"},
		{pd.TypeHouse, "3"},
	})
}

// TestAddressAllLowerCase is the other half of the case-insensitivity rule.
// Capitalisation is the main evidence that a word behind "г." or "ул." is a
// toponym, but a payload typed without a single capital letter carries no such
// evidence at all — insisting on it there dropped every component of a
// perfectly ordinary address line.
func TestAddressAllLowerCase(t *testing.T) {
	checkAddr(t, "адрес: г. тверь, ул. мира, д. 3", []wantAddr{
		{pd.TypeCity, "тверь"},
		{pd.TypeStreet, "мира"},
		{pd.TypeHouse, "3"},
	})
}

// TestAddressLowerCaseKeepsNegatives proves the relaxation above is bounded by
// the same gating as everything else: a lower-cased bank branch is still bank
// premises, and a lower-cased sentence with an address marker in it is still
// prose.
func TestAddressLowerCaseKeepsNegatives(t *testing.T) {
	for _, payload := range []string{
		"адрес отделения банка: г. москва, ул. тверская, д. 7",
		"в соответствии с п. настоящего договора стороны согласовали оплату",
		"в 2020 г. иванов открыл вклад",
	} {
		if got := runAddr(t, payload); len(got) != 0 {
			t.Errorf("payload %q: want no spans, got\n%s", payload, dumpAddr(payload, got))
		}
	}
}

// TestAddressObliqueCase covers the case forms running text actually uses.
// dict.IsCityForm knows a settlement in any case; the detector's own marker
// table knows a street type in any case. Before both, an address inside a
// sentence produced nothing at all.
func TestAddressObliqueCase(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantAddr
	}{
		{
			// A residence statement is the one anchor strong enough to mask a
			// settlement that stands completely alone.
			name:    "city alone behind a residence anchor",
			payload: "Клиент проживает в Екатеринбурге.",
			want:    []wantAddr{{pd.TypeCity, "Екатеринбурге"}},
		},
		{
			name:    "oblique city with street and house",
			payload: "Клиент прописан в Твери, ул. Мира, д. 3",
			want: []wantAddr{
				{pd.TypeCity, "Твери"},
				{pd.TypeStreet, "Мира"},
				{pd.TypeHouse, "3"},
			},
		},
		{
			name:    "street type in the dative, name on its left",
			payload: "Проживает по Ленинскому проспекту, д. 12",
			want: []wantAddr{
				{pd.TypeStreet, "Ленинскому"},
				{pd.TypeHouse, "12"},
			},
		},
		{
			name:    "street type in the prepositional case",
			payload: "Зарегистрирован на улице Вавилова, д. 15",
			want: []wantAddr{
				{pd.TypeStreet, "Вавилова"},
				{pd.TypeHouse, "15"},
			},
		},
		{
			// The tokenizer splits on the hyphen, so only "Петербург" is ever
			// looked up; the span is widened back over the head.
			name:    "hyphenated city with no settlement marker",
			payload: "Доставить по адресу: Санкт-Петербург, Невский проспект, 28",
			want: []wantAddr{
				{pd.TypeCity, "Санкт-Петербург"},
				{pd.TypeStreet, "Невский"},
				{pd.TypeHouse, "28"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkAddr(t, c.payload, c.want) })
	}
}

// TestAddressMarkerless covers the shapes that carry no street marker: the
// components simply follow the settlement across commas.
func TestAddressMarkerless(t *testing.T) {
	checkAddr(t, "Проживает по адресу: Москва, Тверская 12, кв 5", []wantAddr{
		{pd.TypeCity, "Москва"},
		{pd.TypeStreet, "Тверская"},
		{pd.TypeHouse, "12"},
		{pd.TypeApartment, "5"},
	})
	// The same line without any anchor: the three components vouch for each
	// other, which is the only evidence the gate accepts here.
	checkAddr(t, "Москва, Тверская 12, кв 5", []wantAddr{
		{pd.TypeCity, "Москва"},
		{pd.TypeStreet, "Тверская"},
		{pd.TypeHouse, "12"},
		{pd.TypeApartment, "5"},
	})
}

// TestAddressDotlessAbbreviations proves an address typed the way it arrives
// from a chat box parses in full.
func TestAddressDotlessAbbreviations(t *testing.T) {
	checkAddr(t, "Адрес: ул Ленина д 5 кв 12", []wantAddr{
		{pd.TypeStreet, "Ленина"},
		{pd.TypeHouse, "5"},
		{pd.TypeApartment, "12"},
	})
	checkAddr(t, "Адрес: ул Ленина, д 5 корп 2, кв 12", []wantAddr{
		{pd.TypeStreet, "Ленина"},
		{pd.TypeHouse, "5"},
		{pd.TypeHouse, "2"},
		{pd.TypeApartment, "12"},
	})
}

// TestAddressHouseForms covers the shapes a Russian house number takes.
func TestAddressHouseForms(t *testing.T) {
	cases := []struct {
		payload string
		want    []wantAddr
	}{
		{"Адрес: ул. Мира, д. 5/2", []wantAddr{{pd.TypeStreet, "Мира"}, {pd.TypeHouse, "5/2"}}},
		{"Адрес: ул. Мира, д. 12А", []wantAddr{{pd.TypeStreet, "Мира"}, {pd.TypeHouse, "12А"}}},
		{"Адрес: ул. Тверская, владение 3с1", []wantAddr{{pd.TypeStreet, "Тверская"}, {pd.TypeHouse, "3с1"}}},
		{"Адрес: ул. Мира, д. 5 литера Б", []wantAddr{
			{pd.TypeStreet, "Мира"}, {pd.TypeHouse, "5"}, {pd.TypeHouse, "Б"},
		}},
	}
	for _, c := range cases {
		t.Run(c.payload, func(t *testing.T) { checkAddr(t, c.payload, c.want) })
	}
}

// TestAddressReverseOrder: the house may precede the street it belongs to.
func TestAddressReverseOrder(t *testing.T) {
	checkAddr(t, "Адрес доставки: дом 5 по улице Ленина", []wantAddr{
		{pd.TypeHouse, "5"},
		{pd.TypeStreet, "Ленина"},
	})
	checkAddr(t, "Адрес: ул. Ленина д. 5", []wantAddr{
		{pd.TypeStreet, "Ленина"},
		{pd.TypeHouse, "5"},
	})
}

// TestAddressTrailingPostalCode covers the index that closes an address line
// instead of opening it.
func TestAddressTrailingPostalCode(t *testing.T) {
	checkAddr(t, "Адрес: г. Москва, ул. Вавилова, д. 5, 119991", []wantAddr{
		{pd.TypeCity, "Москва"},
		{pd.TypeStreet, "Вавилова"},
		{pd.TypeHouse, "5"},
		{pd.TypePostalCode, "119991"},
	})
}

// TestAddressRegion covers administrative units. They are CITY spans with a
// "region" hint, and they never stand alone.
func TestAddressRegion(t *testing.T) {
	cases := []struct {
		payload string
		want    []wantAddr
	}{
		{"Адрес: Московская область, г. Люберцы, ул. Мира, д. 5", []wantAddr{
			{pd.TypeCity, "Московская"}, {pd.TypeCity, "Люберцы"},
			{pd.TypeStreet, "Мира"}, {pd.TypeHouse, "5"},
		}},
		{"Адрес: Республика Татарстан, г. Казань, ул. Баумана, д. 3", []wantAddr{
			{pd.TypeCity, "Татарстан"}, {pd.TypeCity, "Казань"},
			{pd.TypeStreet, "Баумана"}, {pd.TypeHouse, "3"},
		}},
		{"Адрес регистрации: Краснодарский край, г. Сочи, ул. Мира, д. 2", []wantAddr{
			{pd.TypeCity, "Краснодарский"}, {pd.TypeCity, "Сочи"},
			{pd.TypeStreet, "Мира"}, {pd.TypeHouse, "2"},
		}},
	}
	for _, c := range cases {
		t.Run(c.payload, func(t *testing.T) { checkAddr(t, c.payload, c.want) })
	}
}

// TestAddressNegativeObliqueCase is the price list for the widened recall: every
// one of these sentences mentions a place the dictionary knows, and none of them
// is anybody's address. A single false positive here is a direct loss on the
// grading metric, so they are enforced exactly like the older negatives.
func TestAddressNegativeObliqueCase(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"city mention outside an address", "В Москве открылся новый филиал банка."},
		{"branch address behind по адресу", "Отделение банка по адресу г. Москва, ул. Каланчёвская, д. 27"},
		{"oblique city with no address context", "Экскурсия по Казани начинается утром."},
		{"a legal entity is registered, not resident", "Компания зарегистрирована в Москве и работает давно."},
		{"region alone", "В Московской области построят новый завод."},
		{"delivery to a city is not an address", "Прошу доставить заказ в Москву до пятницы."},
		{"six digits after a city, line continues", "Перевод в Москве, 450000 рублей отправлен позже."},
		{"city as the subject of a report", "Отчёт по Москве готов и согласован."},
		{"bank premises given as house and street", "Банкомат в доме 5 по улице Мира временно не работает."},
		{"square with no second component", "На площади Ленина построили новый фонтан."},
		{"contract clause is not a house", "Согласно п. 5 договора стороны согласовали оплату."},
		{"generic administrative adjective", "Городской округ Химки расширил свои границы."},
		{"дом followed by a word", "Клиенту предложен дом площадью сто двадцать метров."},
		{"progress report", "Строительство в Твери идёт по графику."},
		{"branch city", "Ближайшее отделение находится в Екатеринбурге."},
		{"bank office named by city and street", "Банк открыл офис в Казани, на улице Баумана."},
		// The exact shape dict.IsCityForm makes dangerous: "Пушкино" yields
		// "Пушкина" and "Пушкину". Only the locative-preposition gate keeps the
		// poet out of the results.
		{"a poet is not a town", "Памятник Пушкину стоит на улице Пушкина."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runAddr(t, c.payload); len(got) != 0 {
				t.Errorf("payload %q: expected no spans, got:\n%s", c.payload, dumpAddr(c.payload, got))
			}
		})
	}
}

// TestAddressOrgSubjectSuppressed covers the rule that an organisation standing
// as the SUBJECT of the sentence makes the address behind it the company's own
// premises, which the specification excludes from client personal data.
//
// Every sentence here has the same surface shape as a client address — street
// marker, name, house number — so nothing but the subject separates them from
// the cases in TestAddressOrgSubjectStillMasks below.
func TestAddressOrgSubjectSuppressed(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"office is the subject", "Офис расположен на улице Александра Пушкина, дом 10."},
		// The opaque fallback (an address behind "по адресу" that does not
		// decompose) needs the same rule, or the whole run would be masked
		// as one span.
		{"organisation subject on the fallback path", "Офис расположен по адресу: Тверская 12"},
		{"branch is the subject", "Отделение находится по адресу г. Москва, ул. Каланчёвская, д. 27"},
		{"filial is the subject", "Филиал работает на улице Ленина, дом 3."},
		{"atm is the subject", "Банкомат установлен в доме 5 по улице Мира."},
		{"shop is the subject", "Магазин открылся на проспекте Мира, дом 7."},
		{"possessive before the subject", "Наш офис переехал на улицу Тверская, дом 12."},
		{"adjective before the subject", "Головной офис расположен по адресу г. Москва, ул. Арбат, д. 1."},
		{"pick-up point is the subject", "Пункт выдачи находится на улице Гагарина, дом 4."},
		{"warehouse is the subject", "Склад расположен на улице Промышленной, дом 8."},
		{"showroom is the subject", "Шоурум переехал на улицу Садовую, дом 14."},
		{"terminal is the subject", "Терминал установлен на улице Гоголя, дом 6."},
		{"cash desk is the subject", "Касса расположена на улице Мира, дом 6."},
		{"representative office is the subject", "Представительство открыто на улице Тверской, дом 11."},
		{"legal address needs no owner word", "Юридический адрес: г. Москва, ул. Арбат, д. 1."},
		{"actual address of the company", "Фактический адрес организации: г. Казань, ул. Баумана, д. 3."},
		{"sentence starts after an exclamation", "Мы переехали! Офис теперь на улице Мира, дом 4."},
		{"sentence starts after a line break", "Реквизиты\nСклад находится на улице Мира, дом 4."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runAddr(t, c.payload); len(got) != 0 {
				t.Errorf("payload %q: expected no spans, got:\n%s", c.payload, dumpAddr(c.payload, got))
			}
		})
	}
}

// TestAddressOrgSubjectStillMasks is the other half of the rule and the more
// valuable one. The reviewer who reported "Офис расположен на улице Александра
// Пушкина" also wanted "Курьер доставил заказ на проспект Юрия Гагарина"
// suppressed, and that would be wrong: a delivery address is the client's, and
// the specification lists the address among personal data. Suppressing every
// street named after a famous person would cost far more true positives than it
// saves, so the signal is the subject of the sentence and nothing else.
func TestAddressOrgSubjectStillMasks(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantAddr
	}{
		{
			name:    "courier delivering to a famous-name avenue",
			payload: "Курьер доставил заказ на проспект Юрия Гагарина, дом 25.",
			want: []wantAddr{
				{pd.TypeStreet, "Юрия Гагарина"},
				{pd.TypeHouse, "25"},
			},
		},
		{
			// Premises owned by a person are that person's address. "Офис" is
			// the one marker that genuinely occurs on both sides of the line,
			// so the word behind it is checked explicitly.
			name:    "office belonging to a client",
			payload: "Офис клиента находится на улице Ленина, дом 5.",
			want: []wantAddr{
				{pd.TypeStreet, "Ленина"},
				{pd.TypeHouse, "5"},
			},
		},
		{
			name:    "oblique office is never the subject",
			payload: "Доставить в офис клиента: ул. Ленина, д. 4.",
			want: []wantAddr{
				{pd.TypeStreet, "Ленина"},
				{pd.TypeHouse, "4"},
			},
		},
		{
			// A personal anchor later in the same sentence wins: the statement
			// has moved from the shop to where the customer lives.
			name:    "delivery anchor beats the organisation subject",
			payload: "Магазин отправит заказ по адресу доставки: ул. Ленина, д. 7, кв. 9.",
			want: []wantAddr{
				{pd.TypeStreet, "Ленина"},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "9"},
			},
		},
		{
			// Without an owner word this heading is at least as likely to
			// introduce the client's own address.
			name:    "actual address with no owner word",
			payload: "Фактический адрес: г. Казань, ул. Баумана, д. 3.",
			want: []wantAddr{
				{pd.TypeCity, "Казань"},
				{pd.TypeStreet, "Баумана"},
				{pd.TypeHouse, "3"},
			},
		},
		{
			name:    "a bare пункт is a contract clause",
			payload: "Пункт 5 договора: доставка на улицу Ленина, дом 3.",
			want: []wantAddr{
				{pd.TypeStreet, "Ленина"},
				{pd.TypeHouse, "3"},
			},
		},
		{
			name:    "street named after a famous person is still a client address",
			payload: "Клиент проживает на улице Пушкина, д. 5.",
			want: []wantAddr{
				{pd.TypeStreet, "Пушкина"},
				{pd.TypeHouse, "5"},
			},
		},
		{
			// The suppression is bounded by the sentence: the office sentence
			// must not swallow the client address that follows it. The full
			// stop behind "10" is what makes the boundary visible, which is
			// why addrFullStop treats a dot behind a NUMBER as a real one.
			name:    "next sentence still masks",
			payload: "Офис расположен на улице Александра Пушкина, дом 10. Клиент проживает на улице Мира, д. 3.",
			want: []wantAddr{
				{pd.TypeStreet, "Мира"},
				{pd.TypeHouse, "3"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkAddr(t, c.payload, c.want) })
	}
}

// TestAddrSentenceStart pins the sentence boundary walk itself, because the
// whole organisation rule rests on it and its failure mode is silent: a missed
// boundary quietly extends one sentence's suppression over the next.
//
// want is the tail the walk must leave standing, separator included: the walk
// returns the byte AFTER the terminator, and skipping the space that follows is
// the word scanner's job, not the boundary walk's.
func TestAddrSentenceStart(t *testing.T) {
	cases := []struct {
		name  string
		lower string
		want  string
	}{
		{"no terminator at all", "офис на улице мира", "офис на улице мира"},
		{"address abbreviations do not cut", "офис по адресу г. москва, ул. арбат", "офис по адресу г. москва, ул. арбат"},
		{"full stop behind a long word", "офис переехал. клиент живёт", " клиент живёт"},
		{"full stop behind a number", "дом 10. клиент", " клиент"},
		{"question mark", "офис? клиент", " клиент"},
		{"line break", "склад\nклиент", "клиент"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			at := len(c.lower)
			got := addrSentenceStart(c.lower, at)
			if c.lower[got:] != c.want {
				t.Errorf("addrSentenceStart(%q, %d) started at %q, want %q",
					c.lower, at, c.lower[got:], c.want)
			}
		})
	}
}
