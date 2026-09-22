package detect

import (
	"testing"

	"pdguard/internal/pd"
	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/text"
)

// fioSpansIn runs only the name detector, so a failure here can never be
// blamed on a sibling detector's spans.
func fioSpansIn(t *testing.T, in string) []pd.Span {
	t.Helper()
	return fioDetector{}.Detect(NewContext(in, nil))
}

// fioOnly filters the result down to one PD type.
func fioOnly(spans []pd.Span, typ pd.Type) []pd.Span {
	out := make([]pd.Span, 0, len(spans))
	for _, s := range spans {
		if s.Type == typ {
			out = append(out, s)
		}
	}
	return out
}

// fioRequireNamesDict skips a test that cannot work until the name lists are
// populated. The dictionary files ship as placeholders in the skeleton, and a
// red test there would hide real regressions in the morphological rules, which
// are covered separately and need no dictionary at all.
func fioRequireNamesDict(t *testing.T) {
	t.Helper()
	if !dict.IsFirstName("иван") || !dict.IsSurname("иванов") {
		t.Skip("name dictionaries are not populated yet")
	}
}

// assertOneSpan checks that exactly one span of typ was found and that it
// covers want byte-for-byte.
func fioAssertOneSpan(t *testing.T, in string, typ pd.Type, want, wantHint string) {
	t.Helper()
	spans := fioOnly(fioSpansIn(t, in), typ)
	if len(spans) != 1 {
		t.Fatalf("%q: got %d spans of %s, want 1: %v", in, len(spans), typ, fioDump(in, spans))
	}
	got := in[spans[0].Start:spans[0].End]
	if got != want {
		t.Errorf("%q: span text = %q, want %q", in, got, want)
	}
	if wantHint != "" && spans[0].Hint != wantHint {
		t.Errorf("%q: hint = %q, want %q", in, spans[0].Hint, wantHint)
	}
	if spans[0].Src != "fio" {
		t.Errorf("%q: src = %q, want %q", in, spans[0].Src, "fio")
	}
	if spans[0].Conf <= 0 || spans[0].Conf > 1 {
		t.Errorf("%q: conf = %v, want (0,1]", in, spans[0].Conf)
	}
}

func fioDump(in string, spans []pd.Span) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, in[s.Start:s.End])
	}
	return out
}

// TestFIOMorphologyPositive covers the shapes that are recognised from
// morphology alone, so they hold whatever the dictionaries contain.
func TestFIOMorphologyPositive(t *testing.T) {
	cases := []struct {
		in, want, hint string
	}{
		{"Иванов Иван Иванович обратился в банк", "Иванов Иван Иванович", "full"},
		{"Клиент Иван Иванович Иванов", "Иван Иванович Иванов", "full"},
		{"Позвонил Иван Иванович", "Иван Иванович", "name_patronymic"},
		{"Счёт открыт на имя Иванова Ивана Ивановича", "Иванова Ивана Ивановича", "full"},
		{"Заявление подал Иванов И.И.", "Иванов И.И.", "surname_initials"},
		{"Заявление подал Иванов И. И.", "Иванов И. И.", "surname_initials"},
		{"Перевод от Петрова П.П. получен", "Петрова П.П.", "surname_initials"},
		{"Подпись: И.И. Иванов", "И.И. Иванов", "surname_initials"},
		{"Подпись: И. И. Иванов", "И. И. Иванов", "surname_initials"},
		{"Клиент Петров-Водкин закрыл вклад", "Петров-Водкин", "surname"},
		{"Доверенность на Мамина-Сибиряка оформлена", "Мамина-Сибиряка", "surname"},
		// The dative hides the "-ин" the morphology looks for: only the
		// hyphenated-compound rule in fioIsSurname recovers this one.
		{"Доверенность выдана Мамину-Сибиряку на получение вклада.", "Мамину-Сибиряку", "surname"},
		{"Клиент Салтыкову-Щедрину открыл счёт", "Салтыкову-Щедрину", "surname"},
		{"клиент Иванов позвонил", "Иванов", "surname"},
		{"Получатель Сидоров подтвердил перевод", "Сидоров", "surname"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, c.hint)
	}
}

// TestFIODictionaryPositive covers the two-component shapes that need the
// given-name list: without a patronymic there is nothing else to lean on.
func TestFIODictionaryPositive(t *testing.T) {
	fioRequireNamesDict(t)
	cases := []struct {
		in, want, hint string
	}{
		{"Клиент Иванов Иван подтвердил заявку", "Иванов Иван", "surname_name"},
		{"Клиент Иван Иванов подтвердил заявку", "Иван Иванов", "surname_name"},
		{"Перевод для Иванова Ивана", "Иванова Ивана", "surname_name"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, c.hint)
	}
}

// fioAssertSpans checks the exact list of FIO spans, in position order. Unlike
// fioAssertOneSpan it is used where the interesting part of the answer is what
// the detector did NOT extend over.
func fioAssertSpans(t *testing.T, in string, want ...string) {
	t.Helper()
	got := fioDump(in, fioOnly(fioSpansIn(t, in), pd.TypeFIO))
	if len(got) != len(want) {
		t.Errorf("%q: spans = %v, want %v", in, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%q: span %d = %q, want %q", in, i, got[i], want[i])
		}
	}
}

// TestFIOMorphPair covers the pair rule that does not need the given-name
// list. "Фамилия Имя" is the commonest shape in a banking form and the list
// can never cover the long tail of CIS given names, so a capitalised second
// word next to a personal-data anchor is accepted on morphology alone.
func TestFIOMorphPair(t *testing.T) {
	fioRequireNamesDict(t)
	cases := []struct{ in, want string }{
		{"Клиент Мирзоев Хуршед подтвердил заявку", "Мирзоев Хуршед"},
		{"Заявитель Иванов Хуршед", "Иванов Хуршед"},
		{"Перевод для Петрова Жаннет", "Петрова Жаннет"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "surname_name")
	}
}

// TestFIOMorphPairNegative is the anti-pod of TestFIOMorphPair: every input
// here has a surname followed by something that is NOT a given name, and the
// detector must stop at the surname instead of swallowing the next word.
func TestFIOMorphPairNegative(t *testing.T) {
	fioRequireNamesDict(t)
	// A lower-case word after the surname is the sentence continuing.
	fioAssertSpans(t, "Клиент Иванов подтвердил заявку", "Иванов")
	// Toponyms, countries and organisations stay outside the span.
	fioAssertSpans(t, "Перевод от Иванова Москва получен", "Иванова")
	fioAssertSpans(t, "Клиент Иванов Россия", "Иванов")
	// An organisation marker next to the candidate still vetoes the whole
	// region: "Иванов Холдинг" is a counterparty, not a client.
	fioAssertSpans(t, "Клиент Иванов Холдинг")
	// Without an anchor there is no pair and no lone surname either.
	fioAssertSpans(t, "Отчёт от аудиторов Москвы направлен вовремя")
	fioAssertSpans(t, "Скидка для постоянных клиентов действует")
	fioAssertSpans(t, "Договор Иванов Хуршед")
}

// TestFIOToponymSurname pins both directions of the town/surname ambiguity.
// "Киров" is a regional centre and a perfectly ordinary surname, and which one
// is meant is decided by the word standing immediately in front.
func TestFIOToponymSurname(t *testing.T) {
	fioRequireNamesDict(t)
	// A personal-data anchor directly in front makes it a person.
	fioAssertSpans(t, "Клиент Киров подтвердил заявку", "Киров")
	fioAssertSpans(t, "Счёт оформлен на имя Кирова", "Кирова")
	fioAssertSpans(t, "Заявитель: Киров", "Киров")
	// Everything else leaves the town alone.
	fioAssertSpans(t, "Город Киров находится на Вятке")
	fioAssertSpans(t, "Отделение банка в городе Киров")
	fioAssertSpans(t, "Клиент проживает в городе Киров постоянно")
	fioAssertSpans(t, "Перевод в Киров отправлен")
}

// TestFIOAmbiguousInitial covers the letters that are both an initial and an
// abbreviation. The specification's own example is on the negative side.
func TestFIOAmbiguousInitial(t *testing.T) {
	fioRequireNamesDict(t)
	fioAssertSpans(t, "Г. Иванов обратился в банк", "Г. Иванов")
	fioAssertSpans(t, "Д. Петров направил заявление", "Д. Петров")
	// A town, not a person — the lower-case letter is the giveaway.
	fioAssertSpans(t, "г. Пушкин")
	fioAssertSpans(t, "г. Иванове расположено отделение")
	// Even upper-cased, an address context and a place name both veto it.
	fioAssertSpans(t, "Доставка в Г. Иванове")
	fioAssertSpans(t, "Г. Пушкин известен каждому")
	// The following word has to be a surname the dictionary knows.
	fioAssertSpans(t, "Г. Заявление принято")
}

// TestFIOSeparators covers a name broken up by table layout: a wide column gap
// or a single line break must not take it apart, while a blank line — which
// separates records — must still stop the match.
func TestFIOSeparators(t *testing.T) {
	fioRequireNamesDict(t)
	fioAssertSpans(t, "Иванов\nИван\nИванович", "Иванов\nИван\nИванович")
	fioAssertSpans(t, "Иванов   Иван   Иванович", "Иванов   Иван   Иванович")
	fioAssertSpans(t, "Фамилия   Имя   Отчество\nИванов   Иван   Иванович",
		"Иванов   Иван   Иванович")
	fioAssertSpans(t, "Клиент      Иванов", "Иванов")
	fioAssertSpans(t, "Иванов\nИ.И.", "Иванов\nИ.И.")
	// A blank line is a wall: the surname of one record must not be spliced
	// onto the given name of the next.
	fioAssertSpans(t, "Иванов\n\nИван Иванович", "Иван Иванович")
	fioAssertSpans(t, "Петров\n\nСидоров\n\nИванов")
}

// TestFIOBrackets checks that quotes, brackets and a leading colon do not
// leak into the span — every stray byte inside a mask is a direct loss on the
// span-distance metric.
func TestFIOBrackets(t *testing.T) {
	fioRequireNamesDict(t)
	fioAssertSpans(t, "Клиент «Иванов Иван Иванович» заключил договор", "Иванов Иван Иванович")
	fioAssertSpans(t, "(Иванов Иван Иванович)", "Иванов Иван Иванович")
	fioAssertSpans(t, "ФИО: Иванов Иван Иванович", "Иванов Иван Иванович")
	fioAssertSpans(t, `Подписал "Иванов И.И." лично`, "Иванов И.И.")
	fioAssertSpans(t, "Клиент [Иванов Иван Иванович] подтвердил", "Иванов Иван Иванович")
}

// TestFIOCaseInsensitive pins the specification requirement that recognition
// must not depend on letter case.
func TestFIOCaseInsensitive(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ИВАНОВ ИВАН ИВАНОВИЧ", "ИВАНОВ ИВАН ИВАНОВИЧ"},
		{"иванов иван иванович", "иванов иван иванович"},
		{"Иванов Иван Иванович", "Иванов Иван Иванович"},
		{"клиент иванов", "иванов"},
		{"КЛИЕНТ ИВАНОВ", "ИВАНОВ"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "")
	}
}

// TestFIONegative is the important half of the suite: every hit here would be
// a false positive, and the quality metric charges us for each one.
func TestFIONegative(t *testing.T) {
	cases := []string{
		// Public figures — the case named by the specification.
		"Мы читали поэта Александра Пушкина в школе",
		"Стихи Пушкина знает каждый",
		"поэт Иванов Иван Иванович написал это в романе",
		"памятник Иванову Ивану Ивановичу стоит в парке",
		// Toponyms.
		"Город Пушкин находится рядом с Петербургом",
		"улица Пушкина, дом 5",
		"Библиотека имени Пушкина закрыта",
		"Отделение банка на улице Иванова",
		// Organisations.
		"ООО Иванов и партнёры",
		"Клиент ООО Иванов Иван Иванович",
		"Договор с ОАО Петров",
		// Dotted abbreviations that look like initials.
		"т.е. Иванов",
		"г. Пушкин",
		// An ordinary noun in front of a given name. The morphology used to
		// trim the plural "-и" off "стихи" and then read the remaining "стих"
		// as the indeclinable "-их" surname shape (Черных, Долгих), which made
		// "стихи Александра" a masked name. Trimming a case ending is only
		// allowed before a DICTIONARY lookup, never before a morphological one.
		"Стихи Александра Пушкина изучают в школе",
		"Мы читаем стихи Александра Пушкина в школе",
		// A surname-shaped word with no anchor at all.
		"Иванов",
		"Отчёт сдан вовремя",
		"Платёж прошёл успешно",
	}
	for _, in := range cases {
		if spans := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(spans) != 0 {
			t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, spans))
		}
	}
}

// TestFIOFamousPersonVeto exercises the public-figure list directly; it can
// only run once that list is filled in.
func TestFIOFamousPersonVeto(t *testing.T) {
	if !dict.IsFamousPerson("пушкин") {
		t.Skip("famous-people dictionary is not populated yet")
	}
	cases := []string{
		"Мы читали Александра Пушкина в оригинале",
		"Сочинения Александра Пушкина",
		"Александр Сергеевич Пушкин родился в Москве",
	}
	for _, in := range cases {
		if spans := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(spans) != 0 {
			t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, spans))
		}
	}
}

// TestFIOAnchorBeatsFamousList pins a deliberate trade-off. dict derives its
// single-word famous set from every part of every listed name, so it contains
// ordinary client surnames such as "петров" and "попов". Next to a personal-data
// anchor the reading is a client, not a public figure, and masking it is the
// right answer — otherwise every client who shares a surname with a celebrity
// would leak.
func TestFIOAnchorBeatsFamousList(t *testing.T) {
	if !dict.IsFamousPerson("пушкин") {
		t.Skip("famous-people dictionary is not populated yet")
	}
	fioAssertOneSpan(t, "Счёт оформлен на имя Пушкина", pd.TypeFIO, "Пушкина", "surname")
}

// TestFIOStopWordComponent checks that a stop word never becomes a given name,
// using whichever stop word the dictionary actually knows.
func TestFIOStopWordComponent(t *testing.T) {
	var stop string
	for _, w := range []string{"сегодня", "банк", "документов", "магазин", "машина", "только"} {
		if dict.IsStopWord(w) {
			stop = w
			break
		}
	}
	if stop == "" {
		t.Skip("stop-word dictionary is not populated yet")
	}
	in := stop + " Иванович"
	if spans := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(spans) != 0 {
		t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, spans))
	}
}

// TestFIODisabledType makes sure the detector honours the per-type switch, so
// a deployment can turn a category off without touching code.
func TestFIODisabledType(t *testing.T) {
	ctx := NewContext("Иванов Иван Иванович", func(pd.Type) bool { return false })
	if spans := (fioDetector{}).Detect(ctx); len(spans) != 0 {
		t.Errorf("expected no spans when every type is disabled, got %d", len(spans))
	}
}

// TestFIOSpanOffsets guards the invariant the masking engine depends on:
// offsets are byte offsets into the original text, which multi-byte Cyrillic
// makes easy to get wrong.
func TestFIOSpanOffsets(t *testing.T) {
	const in = "Отправитель: Иванов Иван Иванович, сумма 100"
	spans := fioOnly(fioSpansIn(t, in), pd.TypeFIO)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Start < 0 || s.End > len(in) || s.Start >= s.End {
		t.Fatalf("bad span %+v for input of %d bytes", s, len(in))
	}
	if got := in[s.Start:s.End]; got != "Иванов Иван Иванович" {
		t.Errorf("span text = %q", got)
	}
}

// ------------------------------------------------------------- card holder

func TestCardHolderPositive(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Держатель карты: IVAN IVANOV", "IVAN IVANOV"},
		{"Имя на карте IVAN I IVANOV", "IVAN I IVANOV"},
		{"IVAN IVANOV 4509 1234 5678 9012", "IVAN IVANOV"},
		{"cardholder PETR PETROV", "PETR PETROV"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeCardHolder, c.want, "holder")
	}
}

func TestCardHolderNegative(t *testing.T) {
	cases := []string{
		// No card context at all.
		"IVAN IVANOV",
		"PLEASE CHECK THIS",
		// Company and brand capitals next to a card must stay untouched.
		"Карта ALFA BANK LTD",
		"Оплата картой VISA CLASSIC 4509 1234 5678 9012",
		"Перевод в ACME INC по карте 4509 1234 5678 9012",
		// A single word is not a holder name.
		"Держатель карты: IVANOV",
	}
	for _, in := range cases {
		if spans := fioOnly(fioSpansIn(t, in), pd.TypeCardHolder); len(spans) != 0 {
			t.Errorf("%q: expected no CARD_HOLDER spans, got %v", in, fioDump(in, spans))
		}
	}
}

// TestFIORegistered proves the detector reached the global registry, which is
// what the pipeline actually iterates.
func TestFIORegistered(t *testing.T) {
	for _, d := range Detectors() {
		if d.Name() == "fio" {
			types := d.Types()
			if len(types) != 2 || types[0] != pd.TypeFIO || types[1] != pd.TypeCardHolder {
				t.Fatalf("fio detector reports types %v", types)
			}
			return
		}
	}
	t.Fatal("fio detector is not registered")
}

// ----------------------------------------------- strong client anchors (4.1)

// TestFIOStrongAnchorsAreAnchors pins the invariant fioStrongAnchor's godoc
// states: every strong anchor is also an ordinary one. The lone-surname rule
// asks fioHasAnchor before anything else, so a strong anchor that was missing
// from fioAnchor would be a strong anchor that never fires.
func TestFIOStrongAnchorsAreAnchors(t *testing.T) {
	for w := range fioStrongAnchor {
		if _, ok := fioAnchor[w]; !ok {
			t.Errorf("strong anchor %q is missing from fioAnchor", w)
		}
	}
}

// TestFIOWeakAnchorsAreNotStrong keeps the two lists apart where it matters.
// "от" and "для" license a bare surname, but they say nothing about who the
// person is — "письмо от Пушкина" is as likely to be about the poet — so they
// must never lift the public-figure veto.
func TestFIOWeakAnchorsAreNotStrong(t *testing.T) {
	for _, w := range []string{"от", "для", "у", "с", "менеджер", "директор", "кассир"} {
		if _, ok := fioStrongAnchor[w]; ok {
			t.Errorf("%q must not be a strong client anchor", w)
		}
	}
}

// TestFIOStrongClientAnchorLeft exercises the override's own predicate, where
// the weak/strong distinction and the adjacency rule can be pinned without a
// dictionary. The candidate is always the last word of the input.
func TestFIOStrongClientAnchorLeft(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Strong: an unambiguous role word written directly in front.
		{"Заемщик Салтыков", true},
		{"Заёмщика Иванова", true},
		{"Клиентка Петрова", true},
		{"Поручитель Сидоров", true},
		{"Вкладчику Иванову", true},
		{"Заявитель: Иванов", true},
		{"ФИО: Иванов", true},
		// Strong, multi-word.
		{"Счет оформлен на Иванова", true},
		{"Паспорт на имя Иванова", true},
		{"Доверенность на Иванова", true},
		{"Ф.И.О. Иванов", true},
		// Weak: licenses a bare surname elsewhere, never lifts the veto.
		{"Письмо от Иванова", false},
		{"Скидка для Иванова", false},
		{"Менеджер Иванов", false},
		{"Директор Иванов", false},
		// Adjacency: an anchor further left does not count.
		{"Клиент упомянул Иванова", false},
		{"Клиент подписал документы Иванова", false},
		{"Иванов", false},
	}
	for _, c := range cases {
		ctx := NewContext(c.in, nil)
		last := len(ctx.Tokens) - 1
		for last >= 0 && ctx.Tokens[last].Kind != text.KindWord {
			last--
		}
		if last < 0 {
			t.Fatalf("%q: no word token", c.in)
		}
		got := fioStrongClientAnchorLeft(ctx, last, ctx.Tokens[last].Start)
		if got != c.want {
			t.Errorf("fioStrongClientAnchorLeft(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestFIOStrongAnchorBeatsFamousVeto covers the class of input the veto used to
// swallow whole: a CLIENT whose surname belongs to a public figure. The bank
// has customers called Пушкин, Толстой, Гагарин and Салтыков-Щедрин, and their
// data is personal data like anyone else's; a role word written directly in
// front of the name is what proves the reading.
func TestFIOStrongAnchorBeatsFamousVeto(t *testing.T) {
	if !dict.IsFamousPerson("пушкин") {
		t.Skip("famous-people dictionary is not populated yet")
	}
	cases := []struct{ in, want string }{
		// The hyphenated double surname the review corpus reported missing.
		{"Заемщик Салтыков-Щедрин Михаил Евграфович подтвердил свои данные.",
			"Салтыков-Щедрин Михаил Евграфович"},
		{"Заявитель: Салтыков-Щедрин Михаил Евграфович",
			"Салтыков-Щедрин Михаил Евграфович"},
		// One case of the anchor per shape of anchor.
		{"Заёмщик Лермонтов Михаил Юрьевич внес платеж.", "Лермонтов Михаил Юрьевич"},
		{"Поручитель Гагарин Юрий Алексеевич подписал договор.", "Гагарин Юрий Алексеевич"},
		{"Вкладчик Пушкин Александр Сергеевич закрыл вклад.", "Пушкин Александр Сергеевич"},
		{"Гражданка Ахматова Анна Андреевна обратилась в банк.", "Ахматова Анна Андреевна"},
		// Multi-word anchors, matched as a suffix of the text in front.
		{"Счет оформлен на Пушкина Александра Сергеевича.", "Пушкина Александра Сергеевича"},
		{"Паспорт на имя Лермонтова Михаила Юрьевича.", "Лермонтова Михаила Юрьевича"},
		{"ФИО: Гагарин Юрий Алексеевич", "Гагарин Юрий Алексеевич"},
		// The tokenizer splits "Ф.И.О." into single letters, so the phrase list
		// has to carry the dotted form itself.
		{"Ф.И.О. Пушкин Александр Сергеевич", "Пушкин Александр Сергеевич"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "")
	}
}

// TestFIOFamousVetoHoldsWithoutStrongAnchor is the half that pays for the half
// above. All five inputs are taken verbatim from the review corpus and from the
// specification's own negative examples: a public figure mentioned as a public
// figure must survive byte for byte, because the quality metric is a span
// distance against a reference mask and every masked byte here is a pure loss.
func TestFIOFamousVetoHoldsWithoutStrongAnchor(t *testing.T) {
	if !dict.IsFamousPerson("пушкин") {
		t.Skip("famous-people dictionary is not populated yet")
	}
	cases := []string{
		"В школьную программу входит стихотворение Александра Пушкина.",
		"Памятник Пушкину А.С. установлен на площади в 1880 году.",
		"Роман Льва Николаевича Толстого Война и мир известен во всем мире.",
		"Юрий Алексеевич Гагарин совершил первый в истории полет в космос в 1961 году.",
		"Библиотека имени А. С. Пушкина открыта для читателей ежедневно.",
		// A bank-side job title must not reach the override: it describes our
		// employee's role, not the named person's relationship to us.
		"Менеджер Пушкин Александр Сергеевич",
		"Директор Гагарин Юрий Алексеевич подписал",
		// The anchor has to be IMMEDIATE: one four words away is not adjacency.
		"Клиент упомянул стихотворение Александра Пушкина.",
	}
	for _, in := range cases {
		if spans := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(spans) != 0 {
			t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, spans))
		}
	}
}

// TestFIOLowerSurnameAfterStrongAnchor covers specification 4.1 inside an
// ordinary mixed-case text. The payload here has capitals elsewhere, so
// fioCaseBlind stays false and the lone-surname rule's capital-letter test used
// to reject the name outright.
func TestFIOLowerSurnameAfterStrongAnchor(t *testing.T) {
	fioRequireNamesDict(t)
	fioAssertOneSpan(t, "Клиент иванов пришел в офис", pd.TypeFIO, "иванов", "surname")
	fioAssertOneSpan(t, "Заемщик петров подтвердил перевод", pd.TypeFIO, "петров", "surname")
	fioAssertOneSpan(t, "Счет оформлен на иванова", pd.TypeFIO, "иванова", "surname")
}

// TestFIOLowerSurnameNeedsStrongAnchor is the other direction. Without a strong
// anchor the capital letter stays mandatory, because two of the ordinary
// anchors are "от" and "для" and dict.LooksLikeSurname accepts the genitive
// plural of a large part of ordinary Russian vocabulary.
func TestFIOLowerSurnameNeedsStrongAnchor(t *testing.T) {
	fioRequireNamesDict(t)
	cases := []string{
		// Weak anchors keep the capital-letter requirement.
		"Письмо от иванова получено",
		"Скидка для иванова действует",
		// A strong anchor is still not enough for a word the dictionary does
		// not know as a surname: without a capital there is nothing else left
		// to tell a name from an ordinary "-ов" plural.
		"Отправитель документов не указан.",
		"Владелец активов не установлен.",
		"Заемщик подтвердил получение средств и документов.",
	}
	for _, in := range cases {
		if spans := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(spans) != 0 {
			t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, spans))
		}
	}
}
