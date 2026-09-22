package detect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"pdguard/internal/pd"
)

// This file pins the review findings that were fixed. Every case here failed
// before the fix and is a false positive or a miss the quality metric charges
// for directly, so each one is worth a named test rather than a line in a
// table somewhere.

// regressNoSpans asserts that a payload comes back with nothing masked at all.
func regressNoSpans(t *testing.T, payload string, d Detector) {
	t.Helper()
	if got := d.Detect(NewContext(payload, nil)); len(got) != 0 {
		t.Errorf("%q: expected no spans, got %v", payload, dumpAddr(payload, got))
	}
}

// regressTypes returns the source substrings the detector covered with typ.
func regressTypes(t *testing.T, payload string, d Detector, typ pd.Type) []string {
	t.Helper()
	var out []string
	for _, s := range d.Detect(NewContext(payload, nil)) {
		if s.Type == typ && s.Conf >= 0.7 {
			out = append(out, payload[s.Start:s.End])
		}
	}
	return out
}

// TestBankBranchAddressBothWordOrders covers the specification's explicit
// negative example. The address of a branch is not client data — and it is not
// client data in either word order. Only "Адрес отделения ..." used to be
// recognised; "Отделение ... по адресу ..." was masked, because the generic
// word "адрес" stood closer to the toponym than the branch marker did.
func TestBankBranchAddressBothWordOrders(t *testing.T) {
	for _, in := range []string{
		"Отделение банка расположено по адресу г. Москва, ул. Тверская, д. 7",
		"Банкомат по адресу г. Тула, ул. Советская, д. 1",
		"Наш филиал находится по адресу: г. Омск, ул. Мира, д. 2",
		"Адрес отделения банка: г. Москва, ул. Тверская, д. 7",
		"Ближайший банкомат: г. Тула, ул. Советская, д. 1",
	} {
		regressNoSpans(t, in, addressDetector{})
	}
	// The client's own address in the same phrasing must still be masked, or
	// the fix would have traded one defect for a worse one.
	if got := regressTypes(t, "Проживает по адресу: г. Москва, ул. Тверская, д. 7",
		addressDetector{}, pd.TypeCity); len(got) != 1 || got[0] != "Москва" {
		t.Errorf("client address no longer detected: %v", got)
	}
}

// TestAddressWithoutDots covers an address typed the way a person types it into
// a chat box. Demanding the dot after "ул"/"кв" bought no precision — neither is
// an ordinary Russian word — and cost the whole address.
func TestAddressWithoutDots(t *testing.T) {
	for _, in := range []string{
		"г Москва ул Ленина д 5 кв 10",
		"г Москва, ул Ленина, д 5, кв 10",
	} {
		city := regressTypes(t, in, addressDetector{}, pd.TypeCity)
		street := regressTypes(t, in, addressDetector{}, pd.TypeStreet)
		flat := regressTypes(t, in, addressDetector{}, pd.TypeApartment)
		if len(city) != 1 || len(street) != 1 || len(flat) != 1 {
			t.Errorf("%q: city=%v street=%v apartment=%v, want one of each", in, city, street, flat)
		}
	}
}

// TestAddressBareHouseNumber covers "<улица>, <номер>", the shortest and most
// common way an address is written in Russia. Without the "д." marker the house
// number was invisible, and in the two-component case the street went with it:
// a street with no anchor and no neighbour is dropped by the gate.
func TestAddressBareHouseNumber(t *testing.T) {
	cases := []struct {
		in    string
		house string
	}{
		{"ул. Ленина, 5", "5"},
		{"г. Москва, ул. Ленина, 5", "5"},
		{"г. Москва, ул. Ленина, 5, кв. 10", "5"},
		{"адрес регистрации: Санкт-Петербург, Невский проспект, 28, кв. 15", "28"},
	}
	for _, tc := range cases {
		got := regressTypes(t, tc.in, addressDetector{}, pd.TypeHouse)
		if len(got) != 1 || got[0] != tc.house {
			t.Errorf("%q: HOUSE = %v, want [%q]", tc.in, got, tc.house)
		}
	}
	// A year after a street name is not a house number: four digits are out of
	// range on purpose, and this is the case the guard exists for.
	if got := regressTypes(t, "ул. Победы, 1941 год", addressDetector{}, pd.TypeHouse); len(got) != 0 {
		t.Errorf("a year was read as a house number: %v", got)
	}
}

// TestFamousPersonAnyWordOrder covers the Pushkin case the specification names.
// The dictionary stores "имя отчество фамилия"; a document just as readily
// writes "фамилия имя отчество", and that spelling was masked.
func TestFamousPersonAnyWordOrder(t *testing.T) {
	for _, in := range []string{
		"Пушкин Александр Сергеевич — великий поэт.",
		"Пушкина Александра Сергеевича знает каждый школьник.",
		"Достоевский Фёдор Михайлович жил в Петербурге.",
		"Толстой Лев Николаевич написал «Войну и мир».",
		"Лев Николаевич Толстой написал «Войну и мир».",
		"Александр Сергеевич Пушкин",
		"Александр Пушкин",
	} {
		if got := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(got) != 0 {
			t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, got))
		}
	}
}

// TestCommonSurnamesAreNotVetoed is the other half of the public-figure rule.
// The single-word famous set used to be derived from every part of every listed
// name, so it held "петров", "попов" and "павлов" — among the most frequent
// client surnames in the country — and those clients were silently never masked.
func TestCommonSurnamesAreNotVetoed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Петров П.П.", "Петров П.П."},
		{"П.П. Петров", "П.П. Петров"},
		{"Иван Петров", "Иван Петров"},
		{"Петров Иван", "Петров Иван"},
		{"Попов А.А.", "Попов А.А."},
		{"Павлов Иван", "Павлов Иван"},
		{"Жуков Ж.Ж.", "Жуков Ж.Ж."},
	}
	for _, tc := range cases {
		got := fioOnly(fioSpansIn(t, tc.in), pd.TypeFIO)
		if len(got) != 1 || tc.in[got[0].Start:got[0].End] != tc.want {
			t.Errorf("%q: got %v, want one span %q", tc.in, fioDump(tc.in, got), tc.want)
		}
	}
}

// TestLoneSurnameNeedsACapital covers the most expensive false positive in the
// whole detector. "от" and "для" are two of the commonest words in Russian, and
// the surname morphology test accepts the genitive plural of ordinary nouns, so
// a plain sentence lost a ten-letter word to a three-byte set of initials.
func TestLoneSurnameNeedsACapital(t *testing.T) {
	for _, in := range []string{
		"Скидка для постоянных клиентов",
		"Уважаемые клиенты! Специальные условия для вкладчиков и держателей карт действуют до конца месяца.",
		"Отчет от аудиторов получен",
		"Требование от кредиторов направлено",
		"Информация от поставщиков услуг",
		"Заявка от заемщиков рассмотрена",
		"Акции для владельцев карт",
		"Оплата для подрядчиков выполнена",
		"Условия для депозитов физических лиц",
		"Выписка для судебных приставов",
		"В отделении на Тверской обслуживание для пенсионеров ведется без очереди",
	} {
		if got := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(got) != 0 {
			t.Errorf("%q: expected no FIO spans, got %v", in, fioDump(in, got))
		}
	}
	// A real surname after the same anchor still is one.
	in := "Выписка от Смирновой за март"
	if got := fioOnly(fioSpansIn(t, in), pd.TypeFIO); len(got) != 1 {
		t.Errorf("%q: got %v, want one FIO span", in, fioDump(in, got))
	}
}

// TestBirthPlaceOfAPublicFigure covers the specification's Pushkin sentence one
// span to the right of where it was being checked. The FIO detector's veto kept
// the name, and the birthplace detector masked the city anyway.
func TestBirthPlaceOfAPublicFigure(t *testing.T) {
	for _, in := range []string{
		"Поэт Александр Пушкин родился в Москве.",
		"Пушкин родился в Москве в 1799 году.",
		"Александр Сергеевич Пушкин родился в Москве 6 июня 1799 года.",
	} {
		if got := regressTypes(t, in, passportDetector{}, pd.TypeBirthPlace); len(got) != 0 {
			t.Errorf("%q: BIRTH_PLACE = %v, want none", in, got)
		}
	}
	// A client's birthplace is still personal data.
	in := "Клиент Иванов Иван родился в Москве."
	if got := regressTypes(t, in, passportDetector{}, pd.TypeBirthPlace); len(got) != 1 {
		t.Errorf("%q: BIRTH_PLACE = %v, want [Москве]", in, got)
	}
}

// TestPassportNumberNeedsMoreThanANumeroSign covers a stable loss on every
// document that mentions a passport and also carries a claim or receipt number
// — which in a banking corpus is most of them.
func TestPassportNumberNeedsMoreThanANumeroSign(t *testing.T) {
	for _, in := range []string{
		"Паспорт готов. Заявка № 452301 принята",
		"Паспорт оформлен, квитанция № 123456",
		"Паспортный стол: обращение № 778899",
		"паспорт клиента проверен, тикет № 445566 закрыт",
		"Оплата по счету, паспорт предъявлен, чек № 100200",
	} {
		if got := regressTypes(t, in, passportDetector{}, pd.TypePassport); len(got) != 0 {
			t.Errorf("%q: PASSPORT = %v, want none", in, got)
		}
	}
	// A numero sign between a series and a number is still one passport value.
	in := "паспорт 4509 № 123456"
	if got := regressTypes(t, in, passportDetector{}, pd.TypePassport); len(got) != 1 {
		t.Errorf("%q: PASSPORT = %v, want one span", in, got)
	}
}

// TestDriverLicenceIgnoresTheWordRights covers ten-digit order, case and
// organisation numbers, which the "права" cue used to claim whenever the word
// meant "rights" — which in a banking or legal text is nearly always.
func TestDriverLicenceIgnoresTheWordRights(t *testing.T) {
	for _, in := range []string{
		"Права потребителя защищены, заказ 1234567890 оформлен",
		"Права требования 4012345678 переданы",
		"Водительские права были утеряны, дело 5566778899 закрыто",
	} {
		if got := regressTypes(t, in, docsDetector{}, pd.TypeDriverLicense); len(got) != 0 {
			t.Errorf("%q: DRIVER_LICENSE = %v, want none", in, got)
		}
	}
	in := "Водительские права 9902123456."
	if got := regressTypes(t, in, docsDetector{}, pd.TypeDriverLicense); len(got) != 1 {
		t.Errorf("%q: DRIVER_LICENSE = %v, want one span", in, got)
	}
}

// TestMilitaryIDNeedsARealSeries covers the two-letter prefix the pattern has
// to include in its own match: any preposition satisfies it, so one mention of
// anything "военный" turned a seven-digit amount into a document number.
func TestMilitaryIDNeedsARealSeries(t *testing.T) {
	for _, in := range []string{
		"Военная ипотека: перечислено по 1234567 рублей",
		"Военный билет сдан, приказ ав 1234567 подписан",
	} {
		if got := regressTypes(t, in, docsDetector{}, pd.TypeMilitaryID); len(got) != 0 {
			t.Errorf("%q: MILITARY_ID = %v, want none", in, got)
		}
	}
	in := "Военный билет АБ 1234567"
	if got := regressTypes(t, in, docsDetector{}, pd.TypeMilitaryID); len(got) != 1 {
		t.Errorf("%q: MILITARY_ID = %v, want one span", in, got)
	}
}

// TestResidencePermitNeedsMoreThanACue covers the rule with no shape at all:
// seven to nine digits, with the cue word carrying the entire burden of proof.
func TestResidencePermitNeedsMoreThanACue(t *testing.T) {
	for _, in := range []string{
		"Вид на жительство оформлен, оплачено 1500000 рублей",
		"ВНЖ получен. Дело № 12345678 рассмотрено.",
		"Вид на жительство продлён, сумма 9999999 руб",
	} {
		if got := regressTypes(t, in, docsDetector{}, pd.TypeResidencePermit); len(got) != 0 {
			t.Errorf("%q: RESIDENCE_PERMIT = %v, want none", in, got)
		}
	}
	in := "Вид на жительство 123456789 оформлен."
	if got := regressTypes(t, in, docsDetector{}, pd.TypeResidencePermit); len(got) != 1 {
		t.Errorf("%q: RESIDENCE_PERMIT = %v, want one span", in, got)
	}
}

// TestLuhnAloneIsNotACard covers the second card pass, which waived the
// grouping test — the very test that, by its own documentation, separates a
// card from a thousands-separated amount — while keeping the top confidence. A
// random digit run passes Luhn one time in ten.
func TestLuhnAloneIsNotACard(t *testing.T) {
	for _, in := range []string{
		"Итого 1 234 567 897 776 рублей",
		"Оборот 123 456 789 012 776 руб",
		"Начислено 1 234 567 897 776 условных единиц за период",
	} {
		if got := regressTypes(t, in, financeDetector{}, pd.TypeCardNumber); len(got) != 0 {
			t.Errorf("%q: CARD_NUMBER = %v, want none", in, got)
		}
	}
	// A properly grouped, Luhn-valid card still needs no cue word at all.
	in := "Оплата 4111 1111 1111 1111 прошла"
	if got := regressTypes(t, in, financeDetector{}, pd.TypeCardNumber); len(got) != 1 {
		t.Errorf("%q: CARD_NUMBER = %v, want one span", in, got)
	}
	// Odd grouping is still accepted when the text says "карта".
	in = "Карта 41111111 11111111, списание"
	if got := regressTypes(t, in, financeDetector{}, pd.TypeCardNumber); len(got) != 1 {
		t.Errorf("%q: CARD_NUMBER = %v, want one span", in, got)
	}
}

// TestFinanceScanIsLinear pins the complexity class, not a stopwatch reading.
//
// scanCard used to walk from the last group of a digit chain back to the
// current one, three times, recounting every window's digits from scratch — and
// a chain is any run of digit groups separated by single spaces, so a numeric
// table or a column of phone numbers produced one enormous chain. 20 KB of that
// cost seven seconds of CPU and found nothing. The bound below is two orders of
// magnitude above the fixed version and still an order below the broken one, so
// it cannot fail for being run on a slow machine.
func TestFinanceScanIsLinear(t *testing.T) {
	payload := strings.Repeat("1234 ", 4000) // 20 KB, one chain, 4000 groups
	start := time.Now()
	spans := financeDetector{}.Detect(NewContext(payload, nil))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("detect on %d bytes took %v: the scan is super-linear again", len(payload), d)
	}
	if len(spans) != 0 {
		t.Fatalf("a run of repeated groups produced %d spans", len(spans))
	}
}

// TestResolveIsLinear pins the overlap resolver's complexity. The pairwise loop
// it replaced compared every candidate against everything already kept, which
// on a PD-dense chunk cost more than every detector put together.
func TestResolveIsLinear(t *testing.T) {
	const n = 20000
	spans := make([]pd.Span, 0, n)
	for i := 0; i < n; i++ {
		spans = append(spans, pd.Span{Start: i * 10, End: i*10 + 8, Type: pd.TypeFIO, Conf: 0.9})
	}
	start := time.Now()
	kept := Resolve(spans)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Resolve of %d disjoint spans took %v: it is quadratic again", n, d)
	}
	if len(kept) != n {
		t.Fatalf("Resolve kept %d of %d disjoint spans", len(kept), n)
	}
}

// TestResolveKeepsThePriorityOrder guards the behaviour the occupancy bitmap
// must not change: length first, then type priority, then confidence.
func TestResolveKeepsThePriorityOrder(t *testing.T) {
	// Enough spans to take the bitmap path, all of them overlapping the same
	// bytes, so exactly one must survive and it must be the longest.
	spans := make([]pd.Span, 0, resolveOccupancyMin+1)
	for i := 0; i < resolveOccupancyMin; i++ {
		spans = append(spans, pd.Span{Start: 10, End: 14, Type: pd.TypeCVV, Conf: 0.9})
	}
	spans = append(spans, pd.Span{Start: 8, End: 24, Type: pd.TypeCardNumber, Conf: 0.8})

	kept := Resolve(spans)
	if len(kept) != 1 || kept[0].Type != pd.TypeCardNumber {
		t.Fatalf("Resolve kept %+v, want the single longest span", kept)
	}
}

// TestAddressNeighbourScanIsLinear pins the complexity of the component gate.
// It used to scan every candidate in the payload for every candidate, and an
// address-dense text is exactly the profile of this track's dataset.
func TestAddressNeighbourScanIsLinear(t *testing.T) {
	payload := strings.Repeat("Адрес: г. Москва, ул. Ленина, д. 5, кв. 12. ", 2000)
	start := time.Now()
	spans := addressDetector{}.Detect(NewContext(payload, nil))
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("detect on %d bytes took %v: the neighbour scan is quadratic again", len(payload), d)
	}
	if len(spans) == 0 {
		t.Fatal("the address-dense payload produced no spans at all")
	}
}

// TestRunCtxStopsOnCancellation pins the cancellation point the HTTP layer's
// deadline depends on.
//
// detect.Run had no way to observe a cancelled request, so the engine could
// only notice the deadline AFTER detection had finished: the timeout changed
// the returned error and nothing else, and a slow payload kept a core busy long
// past the point where the client had given up and retried.
func TestRunCtxStopsOnCancellation(t *testing.T) {
	const payload = "Клиент Иванов Иван Иванович, карта 4111 1111 1111 1111"
	ctx := NewContext(payload, nil)
	if len(Run(ctx)) == 0 {
		t.Fatal("the sample payload produced no spans; the test proves nothing")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	spans, err := RunCtx(cancelled, ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunCtx err = %v, want context.Canceled", err)
	}
	if len(spans) != 0 {
		t.Fatalf("RunCtx ran %d detectors' worth of work after cancellation", len(spans))
	}
}
