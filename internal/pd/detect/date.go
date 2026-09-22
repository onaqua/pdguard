// This file recognises calendar dates and decides whether a date is a birth
// date or a passport issue date.
//
// The scoring metric is a span-based edit distance against a reference mask,
// so every byte we touch outside real personal data is a direct loss. Three
// consequences shape the whole detector:
//
//  1. A date is emitted only when it survives a real calendar check AND its
//     year is plausible (1900..today). A future or impossible date is far more
//     likely to be a version number, an invoice id or an IP address.
//  2. The span covers the date itself and nothing else. The trailing "года" /
//     "г." of "12 мая 1990 года" is deliberately left OUT: those words are not
//     personal data, the reference mask almost certainly keeps them verbatim,
//     and including them would cost us edit distance on every textual date.
//  3. A date with no anchor at all is NOT assumed to be a birth date unless it
//     is old enough to be one. "Заявление подано 01.09.2024" is the shape that
//     dominates a banking corpus, and reading it as a date of birth was the
//     single largest source of false positives this detector could produce.
//
// SHAPE MATCHING RUNS ON TOKENS, NOT ON REGEXPS.
//
// Every shape below used to be a package-level regexp scanned over the whole
// payload. That cost ~145 µs per 4 KiB request and allocated a fresh submatch
// slice per candidate, and it was pure duplication: Context already tokenizes
// the payload once for every detector, and a numeric date is exactly the token
// sequence NUMBER SEP NUMBER SEP NUMBER. Walking the token slice answers the
// same question with integer comparisons, reuses a cache-hot array, allocates
// nothing, and gets the boundary checks for free — a token is by construction a
// maximal run, so "1112.05.19901" can no longer offer a 4-digit prefix as a
// year. The remaining lookups (month, ordinal) are the dictionary hash lookups
// they always were.
//
// Package-level regexes: there are none, on purpose. Adding one back would
// reintroduce both the scan and the per-candidate allocation.
//
// DATES WRITTEN AS TEXT.
//
// Clause 4.2 of the specification asks for "a date written as text rather than
// as numbers", and that is more than a month word: "двенадцатое мая тысяча
// девятьсот девяностого года" spells out every component. The year parser
// (dateWordYear) is an accumulator over tokens, so it inherits the same
// properties as the rest of the file — it compares slices of ctx.Lower against
// tables expanded at package initialisation and allocates nothing — and it is
// fronted by a single substring probe (dateWordYearGate), evaluated at most
// once per request and only once a textual date shape has actually been found.
// Its recall is bought entirely with an anchor: see dateWordYearAllowed.
package detect

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"pdguard/internal/pd"
	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/text"
)

// Tuning constants. They are named rather than inlined because the trade-off
// between recall and false positives is the single most important knob here.
const (
	dateAnchorWindow = 60 // bytes of left context scanned for a type anchor
	// dateRightWindow must be wide enough to hold the LONGEST right-hand
	// anchor, not just the shortest: "года рождения" is 25 bytes in UTF-8, and
	// a window that cannot fit it silently demoted every "12.05.1990 года
	// рождения" to the weaker "date after a name" reading.
	dateRightWindow = 48
	// dateRightSkip is how many bytes of separator may stand between the date
	// and its right-hand anchor. Zero is allowed on purpose: scanned documents
	// write "12.05.1990г.р." with nothing in between.
	dateRightSkip = 2
	// dateNegativeWindow is wider than the right window because a suppressing
	// word is often separated from the date by a number of its own:
	// "договор 12/2024 от 01.03.2024".
	dateNegativeWindow = 40
	dateMinYear        = 1900
	// dateAdultGap: a date sitting right after a full name counts as a birth
	// date only if the person would be at least this old today. The same gap
	// separates a plausible birth year from a business date — see classify.
	dateAdultGap = 14
	// dateCompactLen is the digit count of a separator-less date, "12051990".
	dateCompactLen = 8
	// dateSepPad is how many bytes of horizontal whitespace may pad EACH side
	// of an explicit separator. Forms filled by hand and cells pasted out of a
	// spreadsheet write "15  /  07  /  1988", and a separator that had to be a
	// single token lost every one of them.
	//
	// Three is the deliberate ceiling. The danger of this rule is that it turns
	// unrelated numbers standing near a punctuation mark into a date, and the
	// wider the padding the more of the line it can reach across; three bytes
	// is enough for the column alignment people actually type and too narrow to
	// jump a tab stop. The companion restriction lives in dateSepAt: padding is
	// allowed only around an EXPLICIT separator, never around whitespace used
	// as one, so "15  07  1988" — a table row far more often than a date —
	// stays unmatched.
	dateSepPad = 3
	// dateWordYearMaxWords bounds the spelled-out year parser. The longest
	// real form, "тысяча девятьсот девяносто первого", is four words; the fifth
	// slot exists only so the parser stops on its own instead of walking a
	// sentence.
	dateWordYearMaxWords = 5
	// dateLinkWindow bounds the anchor propagation pass: an unanchored date
	// borrows a neighbour's type only when it sits within this many bytes of
	// it, which in practice means the same clause or the same enumeration.
	dateLinkWindow = 96
	// dateMaxSpans caps the propagation pass, which is quadratic in the number
	// of dates found. A payload with more dates than this is a table or a log,
	// not a form, and propagation has nothing to offer there anyway.
	dateMaxSpans = 64

	dateConfAnchored      = 0.95 // explicit "дата рождения" / "выдан"
	dateConfRightAnchored = 0.90 // trailing "г.р."
	// dateConfStrongFloor is the lowest confidence a date carrying an EXPLICIT
	// anchor of its own can have: the right-hand anchor with the ambiguity
	// penalty already applied. It separates "typed by evidence" from "typed by
	// heuristic", which is exactly the line the propagation pass needs.
	dateConfStrongFloor = 0.85
	// dateConfPropagated is a date typed by a sibling's anchor. It must clear
	// the 0.7 floor even after the ambiguity penalty, and it must stay below
	// every anchored value so that a propagated date never outranks a real one
	// inside Resolve.
	dateConfPropagated = 0.80
	// dateConfAfterName is the heuristic "a date follows a full name". It must
	// clear the configured floor (0.7) WITH the ambiguity penalty already
	// subtracted. At 0.70 it did not: every date whose day and month are both
	// 12 or less — about two dates in five, and every first-of-the-month — fell
	// to 0.65 and was dropped, so the branch worked for days 13..31 only.
	// "Иванов Иван Иванович 25.05.1990" was masked and "Иванов Иван Иванович
	// 12.05.1990" was not, which is not a rule anybody wrote on purpose.
	dateConfAfterName = 0.78
	// dateConfBare is a date with no evidence at all. It sits below the 0.7
	// floor on purpose, so such a span is never masked on its own; it exists
	// only as a candidate for the propagation pass.
	dateConfBare         = 0.60
	dateAmbiguityPenalty = 0.05 // both day and month <= 12: order is a guess
	// dateConfEps absorbs binary floating point error when a confidence is
	// compared against a band: 0.95-0.05 is not exactly 0.90.
	dateConfEps = 1e-9
	// dateLabelWindow — дальнобойность ЯВНОЙ МЕТКИ ПОЛЯ ("дата рождения",
	// "дата выдачи"). Шире dateAnchorWindow, потому что бланк печатает между
	// меткой и значением целое родительное словосочетание: "Дата выдачи паспорта
	// представителя клиента: 10.03.15" — 61 байт уточнений. Дальнобойность
	// покупается не шириной, а чистотой промежутка: см. dateCleanRun.
	dateLabelWindow = 96
	// dateConfNoYear — дата, у которой года нет вовсе ("15 января", "15 03").
	// Явный якорь для неё обязателен, поэтому она уверенно выше порога 0.7; но
	// она ниже dateConfAnchored, чтобы полная дата всегда выигрывала у частичной
	// внутри Resolve, и ровно на уровне dateConfRightAnchored, чтобы не заводить
	// новую полосу уверенности и не ломать TestDateConfidenceBandsAreDisjoint.
	dateConfNoYear = 0.90
)

// dateWordYearMarker is the cheap prefilter that keeps the spelled-out year
// parser off the hot path.
const dateWordYearMarker = "тысяч"

// dateCurrentYear is the plausibility horizon for every date in the service.
//
// It is sampled ONCE, at package initialisation, rather than per request: the
// value is needed by every candidate on a 1000 RPS hot path and it changes at
// most once a year. A process that lives across New Year's Eve keeps the old
// horizon until it is restarted, which can only make the detector more
// conservative (last year's dates stay valid, this year's stay suppressed), so
// the staleness is safe in the direction that matters.
var dateCurrentYear = time.Now().Year()

// dateAnchor is the classification produced by the left-context scan.
type dateAnchor uint8

const (
	anchorNone dateAnchor = iota
	anchorBirth
	anchorIssue
)

// Anchor vocabularies. Every phrase is matched on word boundaries, which is
// what makes the dangerous two-letter abbreviations ("др", "гр") usable: they
// cannot fire inside "другой" or "график".
var (
	dateBirthAnchors = []string{
		"дата рождения", "дату рождения", "даты рождения", "дата рожд",
		"год рождения", "года рождения", "рождения", "рожден", "рождён",
		"родился", "родилась", "родившийся", "родившаяся",
		"д.р.", "д. р.", "др", "г.р.", "г. р.", "гр", "род.", "рожд.",
		"date of birth", "birth date", "birthday", "dob", "born",
	}
	dateIssueAnchors = []string{
		"дата выдачи", "дату выдачи", "даты выдачи", "выдачи", "выдача",
		"выдан", "выдана", "выдано", "выданный", "выданного",
		"issued", "date of issue", "issue date",
	}
	// dateRightBirthAnchors are the suffixes that turn a plain date into a
	// birth date: "12.05.1990 г.р.", "12.05.1990 (дата рождения)". The longer
	// spellings come first so that a prefix test reports the most specific one.
	dateRightBirthAnchors = []string{
		"дата рождения", "дату рождения", "даты рождения",
		"года рождения", "год рождения", "рождения", "г.р.", "г. р.", "г.р",
	}
	// dateNegativeAnchors mark a number that only looks like a date. The
	// specification names amounts, contract numbers, versions and IPs
	// explicitly; suppressing them is cheaper than masking them wrongly.
	//
	// The second group is the one that protects the propagation pass. A
	// document that carries a real date of birth almost always carries a
	// business date in the same sentence — "Дата рождения 12.05.1990,
	// заявление подано 01.09.2005" — and without these words the propagation
	// would happily type the second one as a date of birth too.
	dateNegativeAnchors = []string{
		"версия", "версии", "версию", "version", "сборка", "build",
		"договор", "договора", "договору", "контракт", "контракта",
		"счёт", "счет", "счёта", "счета", "накладная", "накладной",
		"заказ", "заказа", "order", "invoice", "артикул",
		"телефон", "тел", "сумма", "суммы", "сумму", "руб", "рублей",
		"инн", "кпп", "бик", "ip", "платеж", "платёж", "ставка", "скидка",

		"заявление", "заявления", "заявлению", "заявка", "заявки", "заявку",
		"подано", "подана", "подан", "принято", "принята", "принят",
		"оформлен", "оформлена", "оформлено", "рассмотрено", "рассмотрена",
		"регистрации", "регистрация", "зарегистрирован", "зарегистрирована",
		"срок", "сроком", "период", "периода", "стаж", "стажа",
		"действует", "действителен", "действительна", "действия",
		"открыт", "открыта", "закрыт", "закрыта", "закрытия", "открытия",
		"операция", "операции", "транзакция", "списание", "зачисление",
		"обращение", "обращения", "запрос", "запроса", "поручение",
		"квитанция", "квитанции", "чек", "отчет", "отчёт", "отчета", "отчёта",
		"начислено", "начислен", "уплачено", "оплачено", "погашения",
	}
	// dateRightNegatives fire when the "date" is immediately followed by a
	// unit, which means it was a number all along.
	dateRightNegatives = []string{"%", "руб", "₽", "$", "коп", "usd", "eur"}
	// dateBirthLabels / dateIssueLabels — ЗАМКНУТЫЙ список явных меток поля.
	// Сюда не попадают короткие и многозначные якоря ("др", "гр", "выдачи",
	// "рождения"): их дальнобойность стоила бы ровно той точности, ради которой
	// dateAnchorWindow держали узким. "выдачи" отдельно исключено из-за
	// addr2-008 "Пункт выдачи находится на улице Гагарина, дом 4."
	//
	// ГОЛЫЕ ГЛАГОЛЫ "выдан"/"выдана"/"выдано" в дальнобойный список ТОЖЕ НЕ
	// ВХОДЯТ (см. риск R-2). Они остаются в dateIssueAnchors и сохраняют свои
	// 60 байт, потому что в реальном тексте они относятся не к дате, а к
	// предмету ("Справка выдана для предъявления по месту требования от
	// 01.09.2024", "Доверенность выдана Ивановым Иваном Ивановичем, паспорт
	// серия 12 05 номер 123456"). Ни один заявленный позитив из раздела 4 от
	// их дальнобойности не зависит: единственный кейс с "выдан"
	// ("Паспорт выдан 15 03, …") имеет метку в 1 байте от значения и
	// закрывается обычным leftAnchor.
	//
	// Инвариант списка: каждая метка — ДВУСЛОВНОЕ сочетание "дата/дату/даты/
	// дате/год/года" + "рождения/выдачи". ОДНОСЛОВНЫХ элементов тут быть не
	// должно; добавление любого — отдельное решение с разбором негативов.
	dateBirthLabels = []string{
		"дата рождения", "дату рождения", "даты рождения", "дате рождения",
		"дата рожд", "год рождения", "года рождения",
	}
	dateIssueLabels = []string{
		"дата выдачи", "дату выдачи", "даты выдачи", "дате выдачи",
	}
	// dateIdentifierLeft / dateIdentifierRight — слова, которые превращают
	// пару из двух чисел <= 12 в половину чужого идентификатора: серию
	// документа или номер дома с дробью (риски R-3 и R-4). См.
	// dateDayMonthInIdentifier.
	dateIdentifierLeft = []string{
		"серия", "серии", "сер",
		"дом", "д", "корпус", "корп", "стр", "строение",
		"кв", "квартира", "офис", "оф", "владение", "влд", "лит", "литера",
	}
	dateIdentifierRight = []string{"№", "номер", "no"}
)

// dateDetector finds birth dates and passport issue dates.
//
// It is stateless: a single value serves every concurrent request, and all
// per-request data travels in the Context.
type dateDetector struct{}

func init() { Register(dateDetector{}) }

// Name implements Detector.
func (dateDetector) Name() string { return "date" }

// Types implements Detector.
func (dateDetector) Types() []pd.Type {
	return []pd.Type{pd.TypeBirthDate, pd.TypePassportIssueDate}
}

// Detect implements Detector. The four scans are independent; overlaps between
// them (a numeric date that also ends in "1990 г.р.") are settled by Resolve,
// which keeps the longer span.
func (d dateDetector) Detect(ctx *Context) []pd.Span {
	if !ctx.Enabled(pd.TypeBirthDate) && !ctx.Enabled(pd.TypePassportIssueDate) {
		return nil
	}
	var gate int8
	if !strings.ContainsAny(ctx.Text, "0123456789") && !dateWordYearGate(ctx.Lower, &gate) {
		return nil
	}
	now := dateCurrentYear
	var out []pd.Span
	out = d.numeric(ctx, out, now)
	out = d.textual(ctx, out, now, &gate)
	out = d.numDayMonth(ctx, out)
	out = d.tokenScan(ctx, out, now, &gate)
	out = d.birthYear(ctx, out, now)
	if len(out) == 0 {
		return nil
	}
	datePropagate(ctx, out)
	return Resolve(out)
}

// dateAppend defers the first allocation until a date is actually found. The
// overwhelming majority of payloads contain none, and an empty slice allocated
// per request is pure waste at 1000 RPS.
func dateAppend(out []pd.Span, sp pd.Span) []pd.Span {
	if out == nil {
		out = make([]pd.Span, 0, 4)
	}
	return append(out, sp)
}

// numeric handles 12.05.1990, 12/05/1990, 12-05-1990, 12 05 1990, 12.05.90,
// 1990-05-12 (ISO), 1990.12.05 and 1990.25.12 in one pass over the tokens.
//
// The separators are matched through dateSepAt rather than as single tokens,
// which is what admits "15  /  07  /  1988": a form filled by hand pads its
// separators, and the three parts are still one date.
func (d dateDetector) numeric(ctx *Context, out []pd.Span, now int) []pd.Span {
	s := ctx.Lower
	toks := ctx.Tokens
	for i := 0; i+4 < len(toks); i++ {
		g1 := toks[i]
		if g1.Kind != text.KindNumber || (g1.Len() > 2 && g1.Len() != 4) {
			continue
		}
		sepA, j, ok := dateSepAt(s, toks, i+1)
		if !ok {
			continue
		}
		g2 := toks[j]
		if g2.Kind != text.KindNumber || g2.Len() > 2 {
			continue
		}
		sepB, k, ok := dateSepAt(s, toks, j+1)
		if !ok || sepB != sepA {
			continue
		}
		yEnd, ok := dateYearEnd(s, toks[k])
		if !ok {
			continue
		}
		if dateChained(s, toks, i, k, sepA) {
			continue
		}
		day, mon, year, hint, amb, ok := dateOrder(
			s[g1.Start:g1.End],
			s[g2.Start:g2.End],
			s[toks[k].Start:yEnd],
			sepA, now,
		)
		if !ok || !validCalendar(day, mon, year) {
			continue
		}
		sp, ok := d.classify(ctx, g1.Start, yEnd, year, now, hint, amb)
		if !ok {
			continue
		}
		out = dateAppend(out, sp)
		i = k
	}
	return out
}

// numDayMonth находит "15 03" и "15/03" — день и месяц, у которых года нет.
// Форма сама по себе не несёт никаких признаков даты (это два числа), поэтому
// ЯВНЫЙ якорь обязателен и проверяется ПЕРВЫМ, как в compact.
func (d dateDetector) numDayMonth(ctx *Context, out []pd.Span) []pd.Span {
	s := ctx.Lower
	toks := ctx.Tokens
	for i := 0; i+2 < len(toks); i++ {
		g1 := toks[i]
		if g1.Kind != text.KindNumber || g1.Len() > 2 {
			continue
		}
		sep, j, ok := dateSepAt(s, toks, i+1)
		if !ok {
			continue
		}
		g2 := toks[j]
		if g2.Kind != text.KindNumber || g2.Len() > 2 {
			continue
		}
		if !dateDayMonthIsolated(s, toks, i, j, sep) {
			continue
		}
		n1, e1 := strconv.Atoi(s[g1.Start:g1.End])
		n2, e2 := strconv.Atoi(s[g2.Start:g2.End])
		if e1 != nil || e2 != nil {
			continue
		}
		var day, mon int
		switch {
		case n1 > 12 && n2 <= 12:
			day, mon = n1, n2
		case n2 > 12 && n1 <= 12:
			day, mon = n2, n1
		case n1 <= 12 && n2 <= 12:
			day, mon = n1, n2
		default:
			continue
		}
		if day < 1 || day > maxDaysInMonth(mon) {
			continue
		}
		if dateDayMonthInIdentifier(ctx, g1.Start, g2.End) {
			continue
		}
		sp, ok := d.classifyNoYear(ctx, g1.Start, g2.End, "dm")
		if !ok {
			continue
		}
		out = dateAppend(out, sp)
		i = j
	}
	return out
}

// dateDayMonthIsolated — несущая проверка правила numDayMonth. Без неё
// "Дата рождения 29.02.1990" (негатив date-ext-035: 1990 не високосный)
// вернулся бы как совершенно валидная пара "29.02", а золотой позитив
// "дата рождения 1990-05-12" предложил бы вторую дату "05-12".
//
// ТРИ УТОЧНЕНИЯ, без которых проверка дырявая (риск R-5):
//
//  1. Соседняя группа — это не только text.KindNumber. Токенизатор склеивает
//     год с приклеенной "г" в ОДИН токен text.KindAlnum ("1990г" в
//     "12.05.1990г.р."), и ровно ради этого написан dateYearEnd. Проверка на
//     Kind == KindNumber такую группу не видит. Блокирующей считается любая
//     соседняя группа, у которой dateDigitPrefix(s, t) > 0.
//  2. Просмотр через паддинг обязателен С ОБЕИХ сторон и для ЛЮБОГО sep,
//     включая ' '. Иначе "Дата рождения 15 07  1988" (пара через один
//     пробел, год через два) даст span "15 07" и оставит "1988" снаружи.
//  3. Для sep == ' ' блокирующей считается соседняя числовая группа через
//     ЛЮБОЙ из четырёх разделителей, а не только через пробел: "15 07.1988"
//     — это одна запись, а не пара плюс год.
func dateDayMonthIsolated(s string, toks []text.Token, first, last int, sep byte) bool {
	if p := datePadBack(s, toks, first-1); p >= 0 {
		if dateDigitPrefix(s, toks[p]) > 0 {
			return false
		}
		if dateSepBlocks(s, toks, p, sep) {
			if q := datePadBack(s, toks, p-1); q >= 0 && dateDigitPrefix(s, toks[q]) > 0 {
				return false
			}
		}
	}
	if n := datePadFwd(s, toks, last+1); n >= 0 {
		if dateDigitPrefix(s, toks[n]) > 0 {
			return false
		}
		if dateSepBlocks(s, toks, n, sep) {
			if m := datePadFwd(s, toks, n+1); m >= 0 && dateDigitPrefix(s, toks[m]) > 0 {
				return false
			}
		}
	}
	return true
}

// dateSepBlocks reports whether the token at index i is a separator that
// continues the numeric record: the same separator as sep, or any of the four
// separators when sep is a space.
func dateSepBlocks(s string, toks []text.Token, i int, sep byte) bool {
	if !datePunctSep(s, toks[i]) {
		return false
	}
	if sep == ' ' {
		return true
	}
	return s[toks[i].Start] == sep
}

// dateDayMonthInIdentifier отсекает два класса, в которых пара из двух
// чисел <= 12 — не дата, а половина чужого идентификатора. Проверяется
// узким окном (16 байт влево, 12 байт вправо), по границам слова.
//
// СЕРИЯ ДОКУМЕНТА (риск R-3). Серия российского паспорта печатается ровно
// как пара двузначных групп: "45 09", "77 12", "12 05". Блокирует: слово
// "серия"/"серии"/"сер" слева; "№", "номер", "no" справа; числовая группа
// из 6 цифр справа через любой разделитель или пробел.
//
// АДРЕС (риск R-4). "дом 4/2", "д. 12/1", "корпус 1/2", "кв. 5/2" — это
// штатная русская запись дома с дробью. Блокирует слева: "дом", "д",
// "корпус", "корп", "стр", "строение", "кв", "квартира", "офис", "оф",
// "владение", "влд", "лит", "литера".
func dateDayMonthInIdentifier(ctx *Context, start, end int) bool {
	s := ctx.Lower
	from := start - 16
	if from < 0 {
		from = 0
	}
	for _, w := range dateIdentifierLeft {
		if lastAnchor(s, from, start, w) >= 0 {
			return true
		}
	}
	to := end + 12
	if to > len(s) {
		to = len(s)
	}
	right := s[end:to]
	for _, w := range dateIdentifierRight {
		if strings.HasPrefix(right, w) && text.IsBoundary(s, end+len(w)) {
			return true
		}
	}
	for _, t := range ctx.Tokens {
		if t.Start >= end && t.End <= to && t.Kind == text.KindNumber && t.Len() == 6 {
			return true
		}
	}
	return false
}

// classifyNoYear типизирует дату без года. Явный якорь обязателен: без года
// не остаётся ни проверки правдоподобия, ни возрастного теста, то есть ни
// одного запасного свидетельства. Никаких heuristic-веток (nameBefore,
// dateConfBare, propagate) здесь нет и быть не должно — такой span либо
// привязан к явной метке, либо не существует.
//
// hasNegativeContext здесь вызывается БЕЗУСЛОВНО, а не в default-ветке, как
// в classify, и это ключевое отличие двух функций (риск R-6). Пара из двух
// чисел <= 12 собственного свидетельства не имеет ВООБЩЕ: "1.2", "10.05",
// "12/05", "15 07", "09/28" — это версия, сумма, номер договора, строка
// таблицы и срок действия карты. Поэтому для формы без года слово
// "версия"/"сумма"/"договор"/"срок" отменяет якорь, а не наоборот, и правая
// проверка единиц (dateRightNegatives) работает здесь точно так же.
func (d dateDetector) classifyNoYear(ctx *Context, start, end int, hint string) (pd.Span, bool) {
	var typ pd.Type
	switch dateAnchorAt(ctx.Lower, start) {
	case anchorBirth:
		typ = pd.TypeBirthDate
	case anchorIssue:
		typ = pd.TypePassportIssueDate
	default:
		return pd.Span{}, false
	}
	if hasNegativeContext(ctx.Lower, start, end) {
		return pd.Span{}, false
	}
	if !ctx.Enabled(typ) {
		return pd.Span{}, false
	}
	return pd.Span{Start: start, End: end, Type: typ,
		Conf: dateConfNoYear, Src: "date", Hint: hint}, true
}

// textual handles "12 мая 1990" and its abbreviated and oblique-case forms
// ("12 янв. 90", "12 январём 1990"). The month word is validated against the
// dictionary, which carries every case form, so an arbitrary word here costs
// one hash lookup and nothing else. The trailing "года"/"г." is intentionally
// not part of the match — see the file comment.
func (d dateDetector) textual(ctx *Context, out []pd.Span, now int, gate *int8) []pd.Span {
	s := ctx.Lower
	toks := ctx.Tokens
	for i := 0; i+2 < len(toks); i++ {
		g1 := toks[i]
		if g1.Kind != text.KindNumber || g1.Len() > 2 {
			continue
		}
		sepA, j, ok := dateWordSepAt(s, toks, i+1)
		if !ok {
			continue
		}
		w := toks[j]
		if w.Kind != text.KindWord || w.Len() < 3 || w.Len() > 20 {
			continue
		}
		mon, ok := 0, false
		if w.Len() >= 6 { // настоящий месяц: минимум "янв" = 6 байт
			mon, ok = monthNumber(s[w.Start:w.End])
		}
		if !ok {
			if !dateMonthPlaceholder[s[w.Start:w.End]] {
				continue
			}
			mon = 0 // месяц неизвестен: заглушка формы
		}
		day, err := strconv.Atoi(s[g1.Start:g1.End])
		if err != nil {
			continue
		}
		// Год необязателен. Разбор жадный: сначала пробуем полную форму, и
		// только если она не сложилась, откатываемся к форме без года.
		end, year, hint := w.End, 0, "text" // форма без года
		last := j                           // индекс токена месяца, не ноль
		k := j + 1                          // разделитель после месяца
		if k < len(toks) && dateIsDot(s, toks[k]) {
			k++ // сокращение месяца: "12 янв. 1990"
		}
		if sepB, k2, ok := dateWordSepAt(s, toks, k); ok && sepB == sepA {
			if y, yEnd, lastTok, word, ok := dateTailYear(ctx, k2, now, gate); ok {
				if word && !dateWordYearAllowed(ctx, g1.Start, yEnd) {
					continue
				}
				end, year, last = yEnd, y, lastTok
			}
		}
		if !dateValidDayMonth(day, mon, year, now) {
			continue
		}
		var sp pd.Span
		if year != 0 {
			sp, ok = d.classify(ctx, g1.Start, end, year, now, hint, false)
		} else {
			sp, ok = d.classifyNoYear(ctx, g1.Start, end, "dm")
		}
		if !ok {
			continue
		}
		out = dateAppend(out, sp)
		i = last
	}
	return out
}

// dateValidDayMonth validates a day/month pair, with or without a year. When
// the year is known the full calendar check applies; without a year February
// gets 29 days (maxDaysInMonth). A placeholder month (mon == 0) only bounds the
// day by 31 and, when a year is present, checks the year's plausibility.
func dateValidDayMonth(day, mon, year, now int) bool {
	if day < 1 {
		return false
	}
	if mon == 0 {
		if day > 31 {
			return false
		}
		return year == 0 || (year >= dateMinYear && year <= now)
	}
	if mon < 1 || mon > 12 {
		return false
	}
	if year != 0 {
		return validCalendar(day, mon, year)
	}
	return day <= maxDaysInMonth(mon)
}

// tokenScan carries the two shapes that are driven by whole tokens rather than
// by a separator pattern, so that they share a single walk over ctx.Tokens:
//
//   - "двенадцатое мая 1990": the day is a dictionary word, not a shape, so
//     composing a pattern out of the ordinal list would be both slower and
//     harder to extend.
//   - "12051990": a date with no separators at all. It is indistinguishable
//     from an account, contract or order number, so it is only ever read as a
//     date when an explicit anchor stands to its left.
func (d dateDetector) tokenScan(ctx *Context, out []pd.Span, now int, gate *int8) []pd.Span {
	toks := ctx.Tokens
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Kind == text.KindNumber && t.Len() == dateCompactLen {
			if sp, ok := d.compact(ctx, t, now); ok {
				out = dateAppend(out, sp)
			}
			continue
		}
		if t.Kind != text.KindWord {
			continue
		}
		day, after, ok := ordinalAt(ctx, i)
		if !ok {
			continue
		}
		j := skipSpace(toks, after)
		if j < 0 || toks[j].Kind != text.KindWord {
			continue
		}
		mon, ok := monthNumber(ctx.Lower[toks[j].Start:toks[j].End])
		if !ok {
			continue
		}
		k := skipSpace(toks, j+1)
		if k < 0 {
			continue
		}
		year, yEnd, last, word, ok := dateTailYear(ctx, k, now, gate)
		if !ok || !validCalendar(day, mon, year) {
			continue
		}
		if word && !dateWordYearAllowed(ctx, toks[i].Start, yEnd) {
			continue
		}
		sp, ok := d.classify(ctx, toks[i].Start, yEnd, year, now, "words", false)
		if !ok {
			continue
		}
		out = dateAppend(out, sp)
		i = last
	}
	return out
}

// compact reads a separator-less eight-digit date. Both readings are tried,
// day-first before year-first, and the calendar check settles which one is
// real: "12051990" can only be 12.05.1990 and "19900512" can only be ISO.
//
// The left anchor is mandatory and is checked BEFORE any parsing, because
// without it this shape has no distinguishing feature whatsoever — every
// eight-digit account number in the corpus would qualify.
func (d dateDetector) compact(ctx *Context, t text.Token, now int) (pd.Span, bool) {
	if leftAnchor(ctx.Lower, t.Start) == anchorNone {
		return pd.Span{}, false
	}
	g := ctx.Lower[t.Start:t.End]
	if day, mon, year, _, amb, ok := dateOrder(g[0:2], g[2:4], g[4:8], '.', now); ok && validCalendar(day, mon, year) {
		return d.classify(ctx, t.Start, t.End, year, now, "compact", amb)
	}
	if day, mon, year, _, amb, ok := dateOrder(g[0:4], g[4:6], g[6:8], '-', now); ok && validCalendar(day, mon, year) {
		return d.classify(ctx, t.Start, t.End, year, now, "compact", amb)
	}
	return pd.Span{}, false
}

// birthYear covers the single construction in which a bare year is personal
// data: "1990 года рождения", "1990 г.р.", "1990г.р.". The span is the year
// alone; "года рождения" stays untouched.
func (d dateDetector) birthYear(ctx *Context, out []pd.Span, now int) []pd.Span {
	if !ctx.Enabled(pd.TypeBirthDate) {
		return out
	}
	s := ctx.Lower
	toks := ctx.Tokens
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		var yEnd int
		glued := false
		switch t.Kind {
		case text.KindNumber:
			if t.Len() != 4 {
				continue
			}
			yEnd = t.End
		case text.KindAlnum:
			n := dateDigitPrefix(s, t)
			if n != 4 || s[t.Start+n:t.End] != "г" {
				continue
			}
			yEnd, glued = t.Start+n, true
		default:
			continue
		}
		if !dateBirthYearTail(s, toks, i+1, glued) {
			continue
		}
		year, err := strconv.Atoi(s[t.Start:yEnd])
		if err != nil || year < dateMinYear || year > now {
			continue
		}
		out = dateAppend(out, pd.Span{
			Start: t.Start, End: yEnd,
			Type: pd.TypeBirthDate,
			Conf: dateConfRightAnchored,
			Src:  "date",
			Hint: "text",
		})
	}
	return out
}

// classify turns a validated date range into a Span, choosing between the two
// PD types from context. It returns ok=false whenever the safest action is to
// leave the text alone.
func (d dateDetector) classify(ctx *Context, start, end, year, now int, hint string, ambiguous bool) (pd.Span, bool) {
	if year < dateMinYear || year > now {
		return pd.Span{}, false
	}
	var typ pd.Type
	var conf float64
	switch dateAnchorAt(ctx.Lower, start) {
	case anchorBirth:
		typ, conf = pd.TypeBirthDate, dateConfAnchored
	case anchorIssue:
		typ, conf = pd.TypePassportIssueDate, dateConfAnchored
	default:
		switch {
		case hasRightBirthAnchor(ctx.Lower, end):
			typ, conf = pd.TypeBirthDate, dateConfRightAnchored
		case year <= now-dateAdultGap && nameBefore(ctx, start):
			typ, conf = pd.TypeBirthDate, dateConfAfterName
		case year > now-dateAdultGap:
			// The default used to be "an unanchored date is a date of birth",
			// and it was this detector's biggest false-positive source: a
			// banking corpus is full of "Заявление подано 01.09.2024, срок
			// рассмотрения до 15.10.2024", where neither date is personal data
			// and both were being masked. Nobody in a form is fourteen days —
			// or fourteen years — old, so a recent date with no evidence
			// whatsoever behind it is dropped outright rather than kept as a
			// weak candidate that the propagation pass might later promote.
			return pd.Span{}, false
		case hasNegativeContext(ctx.Lower, start, end):
			return pd.Span{}, false
		default:
			typ, conf = pd.TypeBirthDate, dateConfBare
		}
	}
	if ambiguous {
		conf -= dateAmbiguityPenalty
	}
	if !ctx.Enabled(typ) {
		return pd.Span{}, false
	}
	return pd.Span{Start: start, End: end, Type: typ, Conf: conf, Src: "date", Hint: hint}, true
}

// datePropagate is the second pass that closes the gap this detector was
// reported for. On
//
//	"Дата рождения 12.05.1990, второй вариант 1990.12.05, третий 12 мая 1990 года"
//
// only the first two dates were masked: the anchor "дата рождения" is found by
// a fixed-width scan of the left context, and by the third date it is out of
// reach. Widening that window is the wrong fix — it would let an anchor reach
// across a sentence boundary into unrelated numbers — so instead, once at least
// one date in the payload has been typed by an explicit anchor, the dates that
// found no evidence of their own borrow that type at a reduced confidence.
//
// It is a pass over the CANDIDATES, not over the text: no rescanning, no
// regexps, no allocations, and it is skipped entirely unless the payload
// actually contains both an anchored and an unanchored date.
//
// Four guards carry the precision burden, because the obvious one does not.
// The task description suggested restricting propagation to dates "of the same
// format", but the three dates in the reported example are three different
// formats — dmy, ISO-ish ymd and a textual month — so a format test would fail
// the very case it is meant to fix. Locality does the work instead:
//
//  1. Only a BIRTH date propagates. An issue date has no age-based
//     plausibility test to fall back on, so borrowing it cannot be made safe.
//  2. The donor must be the NEAREST anchored date. A bare date sitting next to
//     "паспорт выдан ..." does not reach past it to a birth date further away.
//  3. The two must be at most dateLinkWindow bytes apart with no sentence
//     boundary in between — same clause or same enumeration, nothing wider.
//  4. The candidate must already have survived classify, which means it is old
//     enough to be a birth date and carries no negative context. That is what
//     keeps "Дата рождения 12.05.1990, заявление подано 01.09.2005" honest.
func datePropagate(ctx *Context, spans []pd.Span) {
	if len(spans) < 2 || len(spans) > dateMaxSpans {
		return
	}
	donor, taker := false, false
	for _, s := range spans {
		switch {
		case s.Conf >= dateConfStrongFloor-dateConfEps:
			donor = true
		case s.Conf <= dateConfBare+dateConfEps:
			taker = true
		}
	}
	if !donor || !taker {
		return
	}
	for i := range spans {
		if spans[i].Conf > dateConfBare+dateConfEps {
			continue
		}
		best, bestGap := -1, dateLinkWindow+1
		for j := range spans {
			if spans[j].Conf < dateConfStrongFloor-dateConfEps {
				continue
			}
			if spans[j].Hint == "dm" {
				continue // частичная дата донором не бывает: у неё нет года,
				// а вместе с ним нет и возрастного теста, которым
				// datePropagate оправдывает заимствование типа
			}
			if gap := dateGap(spans[i], spans[j]); gap < bestGap {
				best, bestGap = j, gap
			}
		}
		if best < 0 || spans[best].Type != pd.TypeBirthDate {
			continue
		}
		from, to := dateGapRange(spans[i], spans[best])
		if dateSentenceBreak(ctx, from, to) {
			continue
		}
		conf := dateConfPropagated
		if spans[i].Conf < dateConfBare-dateConfEps {
			conf -= dateAmbiguityPenalty
		}
		spans[i].Type = pd.TypeBirthDate
		spans[i].Conf = conf
	}
}

// dateGap returns the number of bytes between two spans, 0 when they touch or
// overlap.
func dateGap(a, b pd.Span) int {
	if a.End <= b.Start {
		return b.Start - a.End
	}
	if b.End <= a.Start {
		return a.Start - b.End
	}
	return 0
}

// dateGapRange returns the byte range that lies strictly between two spans.
func dateGapRange(a, b pd.Span) (int, int) {
	if a.End <= b.Start {
		return a.End, b.Start
	}
	if b.End <= a.Start {
		return b.End, a.Start
	}
	return 0, 0
}

// dateSentenceBreak reports whether [from,to) crosses a sentence boundary.
//
// The dot is the hard case, because a date is full of them: "12.05.1990." ends
// with a dot that belongs to the number as easily as to the sentence. The test
// used here is the one a reader applies — a dot, then whitespace, then a
// capital letter — and it deliberately errs towards reporting a break, since a
// missed propagation costs recall while a wrong one costs precision, and
// precision is what the metric charges for.
func dateSentenceBreak(ctx *Context, from, to int) bool {
	s := ctx.Lower
	if from < 0 || to > len(s) {
		return true
	}
	for i := from; i < to; i++ {
		switch s[i] {
		case '\n', '\r', '!', '?':
			return true
		case '.':
			j := i + 1
			if j >= len(s) || (s[j] != ' ' && s[j] != '\t') {
				continue
			}
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			if j < len(s) && text.IsUpperFirst(ctx.Text[j:]) {
				return true
			}
		}
	}
	return false
}

// leftAnchor reports the nearest typing anchor to the left of the date. The
// nearest one wins so that "дата рождения 01.01.1980, паспорт выдан
// 02.02.2010" types both dates correctly.
func leftAnchor(lower string, start int) dateAnchor {
	from := start - dateAnchorWindow
	if from < 0 {
		from = 0
	}
	best, kind := -1, anchorNone
	for _, a := range dateBirthAnchors {
		if i := lastAnchor(lower, from, start, a); i > best {
			best, kind = i, anchorBirth
		}
	}
	for _, a := range dateIssueAnchors {
		if i := lastAnchor(lower, from, start, a); i > best {
			best, kind = i, anchorIssue
		}
	}
	return kind
}

// dateCleanRun сообщает, что lower[from:to) не содержит ни одной цифры, ни
// одного разрыва предложения и ни одного разрыва предикации. Это и есть та
// проверка, которая делает широкое окно безопасным: метка не имеет права
// перепрыгнуть через более близкое число ("Дата рождения 12.05.1990,
// заявление подано 01.09.2005" — между меткой и второй датой стоят цифры
// первой), не имеет права дотянуться из предыдущего предложения и не имеет
// права дотянуться из соседней предикации внутри того же предложения.
//
// Отвергается run, в котором встретился хотя бы один байт из:
//
//	цифра 0..9                — между меткой и значением есть другое число
//	'.' ';' '!' '?' '\n' '\r' — конец предложения (точка отвергается
//	                            безусловно, а не эвристикой dateSentenceBreak:
//	                            "гр. Иванова" между меткой и значением —
//	                            повод отказаться, а не повод угадывать)
//	',' '(' ')'               — разрыв предикации, см. ниже
//	'—' '–', а также '-' В ОКРУЖЕНИИ ПРОБЕЛОВ — тире как разрыв предикации.
//	                            Дефис ВНУТРИ слова ("финансово-кредитной")
//	                            разрывом не считается и run не портит.
//
// Двоеточие ':' — единственный знак препинания, который РАЗРЕШЁН.
//
// Запятая и тире — несущая часть проверки, а не косметика (риск R-1).
// Дальнобойность метки законна ровно в одном синтаксическом случае: когда
// между меткой и значением стоит ИМЕННАЯ ГРУППА в родительном падеже,
// которую печатает бланк ("Дата выдачи паспорта представителя клиента:
// 10.03.15"). Такая группа не содержит ни запятой, ни тире. Запятая же
// означает новую предикацию — и именно в ней живёт тот самый крупнейший
// источник ложных срабатываний, который зафиксирован в шапке date.go
// (пункт 3, строки 16–18):
//
//	"Дата рождения не указана, заявление подано 01.09.2024"
//	                         ^^^ запятая — граница; справа бизнес-дата
//
// Двоеточие потому и разрешено, что им бланк заканчивает саму метку: все
// семь позитивов класса D имеют перед значением ровно ": ".
//
// Союз в промежутке ("и", "а", "но", "или", "либо") проверяется тем же
// правилом, что и метка, — по границам слова: именная группа бланка союзов
// не содержит.
func dateCleanRun(lower string, from, to int) bool {
	if from < 0 || to > len(lower) || from >= to {
		return false
	}
	for i := from; i < to; i++ {
		switch c := lower[i]; {
		case c >= '0' && c <= '9':
			return false
		case c == '.' || c == ';' || c == '!' || c == '?' || c == '\n' || c == '\r':
			return false
		case c == ',' || c == '(' || c == ')':
			return false
		case c == 0xE2 && i+2 < to && lower[i+1] == 0x80 && (lower[i+2] == 0x94 || lower[i+2] == 0x93):
			// '—' (U+2014) и '–' (U+2013) — тире как разрыв предикации.
			return false
		case c == '-':
			// Дефис внутри слова ("финансово-кредитной") разрывом не
			// считается; тире в окружении пробелов — разрыв предикации.
			if i > from && i+1 < to && lower[i-1] == ' ' && lower[i+1] == ' ' {
				return false
			}
		}
	}
	return true
}

// dateLabelAnchor — дальнобойный напарник leftAnchor, ограниченный явными
// метками поля и чистым промежутком. Побеждает ближайшая метка, как и в
// leftAnchor.
func dateLabelAnchor(lower string, start int) dateAnchor {
	from := start - dateLabelWindow
	if from < 0 {
		from = 0
	}
	best, bestEnd, kind := -1, -1, anchorNone
	for _, a := range dateBirthLabels {
		if i := lastAnchor(lower, from, start, a); i > best {
			best, bestEnd, kind = i, i+len(a), anchorBirth
		}
	}
	for _, a := range dateIssueLabels {
		if i := lastAnchor(lower, from, start, a); i > best {
			best, bestEnd, kind = i, i+len(a), anchorIssue
		}
	}
	if best < 0 || !dateCleanRun(lower, bestEnd, start) {
		return anchorNone
	}
	return kind
}

// dateAnchorAt — то, что теперь спрашивают classify и новые правила:
// сначала обычный leftAnchor, и только если он молчит — dateLabelAnchor.
// Порядок важен: ближний якорь должен по-прежнему побеждать дальний.
func dateAnchorAt(lower string, start int) dateAnchor {
	if a := leftAnchor(lower, start); a != anchorNone {
		return a
	}
	return dateLabelAnchor(lower, start)
}

// lastAnchor returns the largest offset in [from,to) at which phrase occurs on
// word boundaries, or -1.
func lastAnchor(lower string, from, to int, phrase string) int {
	best := -1
	for off := from; off+len(phrase) <= to; {
		i := strings.Index(lower[off:to], phrase)
		if i < 0 {
			break
		}
		i += off
		if text.IsBoundary(lower, i) && text.IsBoundary(lower, i+len(phrase)) {
			best = i
		}
		off = i + 1
	}
	return best
}

// hasRightBirthAnchor spots a "г.р."-style suffix directly after the date.
//
// The anchor must start within dateRightSkip bytes of the date's end, which is
// what keeps the match local: a "рождения" ten words later is about something
// else. Zero separator bytes are allowed on purpose — scanned documents write
// "12.05.1990г.р." glued together, and requiring a word boundary there used to
// lose the whole date.
func hasRightBirthAnchor(lower string, end int) bool {
	to := end + dateRightWindow
	if to > len(lower) {
		to = len(lower)
	}
	tail := lower[end:to]
	skip := 0
	for skip < len(tail) && skip < dateRightSkip &&
		(tail[skip] == ' ' || tail[skip] == '\t' || tail[skip] == ',' || tail[skip] == '(') {
		skip++
	}
	tail = tail[skip:]
	for _, a := range dateRightBirthAnchors {
		if strings.HasPrefix(tail, a) && text.IsBoundary(lower, end+skip+len(a)) {
			return true
		}
	}
	return false
}

// hasNegativeContext suppresses numbers that merely look like dates. It runs
// only when no positive anchor was found, so an explicit "выдан" always wins
// over a stray "договор" earlier in the sentence.
func hasNegativeContext(lower string, start, end int) bool {
	from := start - dateNegativeWindow
	if from < 0 {
		from = 0
	}
	for _, n := range dateNegativeAnchors {
		if lastAnchor(lower, from, start, n) >= 0 {
			return true
		}
	}
	if head := strings.TrimRight(lower[from:start], " \t"); head != "" {
		switch head[len(head)-1] {
		case '$', '%':
			return true
		}
		if strings.HasSuffix(head, "№") || strings.HasSuffix(head, "₽") {
			return true
		}
	}
	to := end + 8
	if to > len(lower) {
		to = len(lower)
	}
	tail := strings.TrimLeft(lower[end:to], " \t")
	for _, n := range dateRightNegatives {
		if strings.HasPrefix(tail, n) {
			return true
		}
	}
	return false
}

// nameBefore reports whether the tokens just before off look like a Russian
// full name. It deliberately only inspects a handful of tokens: this is a
// weak signal used to raise a date from "unclassified" to "birth date", not a
// name detector.
func nameBefore(ctx *Context, off int) bool {
	i := sort.Search(len(ctx.Tokens), func(k int) bool { return ctx.Tokens[k].End > off }) - 1
	words := 0
	for ; i >= 0 && words < 3; i-- {
		t := ctx.Tokens[i]
		if t.End > off {
			continue
		}
		switch t.Kind {
		case text.KindSpace:
			continue
		case text.KindWord:
			words++
			w := ctx.Lower[t.Start:t.End]
			if !text.IsCyrillicWord(w) || !text.IsUpperFirst(ctx.Text[t.Start:t.End]) {
				return false
			}
			if dict.IsPatronymic(w) || dict.IsSurname(w) || dict.IsFirstName(w) || dict.LooksLikeSurname(w) {
				return true
			}
		case text.KindPunct:
			continue
		default:
			return false
		}
	}
	return false
}

// datePunctSep reports whether a token is one of the three explicit date
// separators.
func datePunctSep(s string, t text.Token) bool {
	if t.Kind != text.KindPunct || t.Len() != 1 {
		return false
	}
	c := s[t.Start]
	return c == '.' || c == '/' || c == '-'
}

// dateSepAt matches the separator that stands between two groups of a numeric
// date, starting at token j. It returns the separator character and the index
// of the first token after it.
//
// Two shapes are accepted, and the asymmetry between them is the whole point
// of this function:
//
//   - An EXPLICIT separator — '.', '/' or '-' — may be padded with up to
//     dateSepPad bytes of horizontal whitespace on each side. "15  /  07  /
//     1988" is a date somebody typed into a form, and the padding carries no
//     information at all.
//   - Whitespace used AS the separator stays exactly as strict as it was: one
//     single space, nothing else. Relaxing this side is what would start
//     masking spreadsheet columns — "15  07  1988" pasted out of three cells
//     has the same token shape as a date and none of its meaning — so the
//     separator-less spelling keeps needing either a single space (and then
//     still has to survive classify) or a left anchor via compact.
//
// A newline never pads a separator: dateInlineSpace rejects it, which is what
// stops the last number of one table row from joining the first of the next.
func dateSepAt(s string, toks []text.Token, j int) (sep byte, next int, ok bool) {
	if j < len(toks) && toks[j].Kind == text.KindSpace {
		if !dateInlineSpace(s, toks[j]) || toks[j].Len() > dateSepPad {
			return 0, 0, false
		}
		if toks[j].Len() == 1 && s[toks[j].Start] == ' ' {
			if j+1 >= len(toks) {
				return 0, 0, false
			}
			if !datePunctSep(s, toks[j+1]) {
				return ' ', j + 1, true
			}
		}
		j++
	}
	if j >= len(toks) || !datePunctSep(s, toks[j]) {
		return 0, 0, false
	}
	sep = s[toks[j].Start]
	j++
	if j < len(toks) && toks[j].Kind == text.KindSpace {
		if !dateInlineSpace(s, toks[j]) || toks[j].Len() > dateSepPad {
			return 0, 0, false
		}
		j++
	}
	if j >= len(toks) {
		return 0, 0, false
	}
	return sep, j, true
}

// dateWordSepAt — разделитель между числовым днём и словом месяца (и между
// месяцем и годом). Принимаются РОВНО две записи: один горизонтальный пробел
// (sep = ' ') или один дефис (sep = '-'). Точка и слэш сюда не допущены
// намеренно: точка уже занята сокращением месяца ("12 янв. 1990"), а слэш со
// словесным месяцем не встречается. Вызывающий обязан требовать ОДИН И ТОТ ЖЕ
// разделитель с обеих сторон месяца, так что "15-янв 1990" датой не станет.
func dateWordSepAt(s string, toks []text.Token, j int) (sep byte, next int, ok bool) {
	if j >= len(toks) {
		return 0, 0, false
	}
	t := toks[j]
	switch t.Kind {
	case text.KindSpace:
		if t.Len() != 1 || s[t.Start] != ' ' {
			return 0, 0, false
		}
		return ' ', j + 1, true
	case text.KindPunct:
		if t.Len() != 1 || s[t.Start] != '-' {
			return 0, 0, false
		}
		return '-', j + 1, true
	}
	return 0, 0, false
}

// dateIsDot reports whether a token is a lone '.', the optional dot of an
// abbreviated month ("12 янв. 1990").
func dateIsDot(s string, t text.Token) bool {
	return t.Kind == text.KindPunct && t.Len() == 1 && s[t.Start] == '.'
}

// dateInlineSpace reports whether a token is horizontal whitespace. A newline
// is excluded deliberately: the three parts of a date do not straddle a line
// break, and accepting one would join a table cell to the one below it.
func dateInlineSpace(s string, t text.Token) bool {
	if t.Kind != text.KindSpace || t.Len() == 0 || t.Len() > 4 {
		return false
	}
	for i := t.Start; i < t.End; i++ {
		if s[i] != ' ' && s[i] != '\t' {
			return false
		}
	}
	return true
}

// dateDigitPrefix counts the leading ASCII digits of a token.
func dateDigitPrefix(s string, t text.Token) int {
	n := 0
	for i := t.Start; i < t.End && s[i] >= '0' && s[i] <= '9'; i++ {
		n++
	}
	return n
}

// dateYearEnd reports where the year digits of a trailing group end.
//
// A four- or two-digit number is the ordinary case. The alphanumeric case
// exists because "12.05.1990г.р." tokenizes the year and the "г" as ONE token:
// the digits are still a clean year, and refusing the whole date over a glued
// abbreviation loses a shape that scanned documents produce constantly.
func dateYearEnd(s string, t text.Token) (int, bool) {
	switch t.Kind {
	case text.KindNumber:
		if t.Len() == 4 || t.Len() == 2 {
			return t.End, true
		}
	case text.KindAlnum:
		n := dateDigitPrefix(s, t)
		if (n == 4 || n == 2) && s[t.Start+n:t.End] == "г" {
			return t.Start + n, true
		}
	}
	return 0, false
}

// dateChained rejects a match that is one link of a longer punctuated number —
// an IP address or a version string. first is the index of the leading group,
// last the index of the token the year ends in.
//
// Both ends look through one run of padding whitespace, for the same reason
// dateSepAt does: once "1 . 2 . 3 . 4" can be read as a date, the guard that
// recognises it as a chain has to be able to see the padded links too.
//
// Both ends also require a NUMBER beyond the separator, not just the separator
// itself. A chain is "число sep число sep число sep число"; a separator with a
// word on the far side of it is a sentence, and the difference is not academic
// — "род. 12.05.1990" puts an abbreviation's full stop exactly where a chain's
// separator would, and a test that stopped at the dot threw the date away.
func dateChained(s string, toks []text.Token, first, last int, sep byte) bool {
	if sep != '.' && sep != '/' && sep != '-' {
		return false
	}
	if p := datePadBack(s, toks, first-1); p >= 0 && datePunctSep(s, toks[p]) && s[toks[p].Start] == sep {
		if q := datePadBack(s, toks, p-1); q >= 0 && toks[q].Kind == text.KindNumber {
			return true
		}
	}
	if n := datePadFwd(s, toks, last+1); n >= 0 && datePunctSep(s, toks[n]) && s[toks[n].Start] == sep {
		if m := datePadFwd(s, toks, n+1); m >= 0 && toks[m].Kind == text.KindNumber {
			return true
		}
	}
	return false
}

// datePadBack steps back over one run of horizontal whitespace, returning -1
// when there is no token left to inspect.
func datePadBack(s string, toks []text.Token, i int) int {
	if i >= 0 && toks[i].Kind == text.KindSpace {
		if !dateInlineSpace(s, toks[i]) || toks[i].Len() > dateSepPad {
			return -1
		}
		i--
	}
	if i < 0 {
		return -1
	}
	return i
}

// datePadFwd is datePadBack in the other direction.
func datePadFwd(s string, toks []text.Token, i int) int {
	if i < len(toks) && toks[i].Kind == text.KindSpace {
		if !dateInlineSpace(s, toks[i]) || toks[i].Len() > dateSepPad {
			return -1
		}
		i++
	}
	if i >= len(toks) {
		return -1
	}
	return i
}

// dateSkipInline advances past one optional horizontal-whitespace token. A
// newline is reported as "no more tokens", which ends the match.
func dateSkipInline(s string, toks []text.Token, i int) int {
	if i < len(toks) && toks[i].Kind == text.KindSpace {
		if !dateInlineSpace(s, toks[i]) {
			return len(toks)
		}
		i++
	}
	return i
}

// dateBirthYearTail reports whether the tokens from i spell one of the two
// suffixes that make a bare year personal data: "года рождения" or "г.р.".
// glued is true when the "г" was already fused into the year token by the
// tokenizer ("1990г.р."), so it must not be looked for again.
func dateBirthYearTail(s string, toks []text.Token, i int, glued bool) bool {
	if !glued {
		i = dateSkipInline(s, toks, i)
		if i >= len(toks) || toks[i].Kind != text.KindWord {
			return false
		}
		w := s[toks[i].Start:toks[i].End]
		if isYearWord(w) {
			i = dateSkipInline(s, toks, i+1)
			if i >= len(toks) || toks[i].Kind != text.KindWord {
				return false
			}
			return strings.HasPrefix(s[toks[i].Start:toks[i].End], "рожд")
		}
		if w != "г" {
			return false
		}
		i++
	}
	if i >= len(toks) || !dateIsDot(s, toks[i]) {
		return false
	}
	i = dateSkipInline(s, toks, i+1)
	if i >= len(toks) || toks[i].Kind != text.KindWord {
		return false
	}
	return s[toks[i].Start:toks[i].End] == "р"
}

// isYearWord lists the case forms of "год" that precede "рождения". The set is
// closed on purpose: a prefix test would accept "годовщина".
func isYearWord(w string) bool {
	switch w {
	case "год", "года", "году", "годе", "годом":
		return true
	}
	return false
}

// dateOrder decides which of the three numeric groups is the day, the month
// and the year.
//
// The rules, in order: a four-digit group is the year; of the two remaining
// groups the one above 12 must be the day. When both are <= 12 the order is
// genuinely undecidable, so we fall back to the local convention (day-month
// for a year-last date, ISO for a year-first one) and report ambiguous=true so
// the caller can lower its confidence.
//
// sep is the character that joined the groups. It matters in exactly one case:
// "1990-05-12" is ISO 8601, where the order is fixed by the standard rather
// than guessed, so that shape must not pay the ambiguity penalty.
func dateOrder(g1, g2, g3 string, sep byte, now int) (day, month, year int, hint string, ambiguous, ok bool) {
	n1, e1 := strconv.Atoi(g1)
	n2, e2 := strconv.Atoi(g2)
	n3, e3 := strconv.Atoi(g3)
	if e1 != nil || e2 != nil || e3 != nil {
		return 0, 0, 0, "", false, false
	}
	switch {
	case len(g1) == 4:
		year = n1
	case len(g1) <= 2 && n1 > 31 && len(g3) <= 2:
		year = expandYear(n1, now)
	case len(g3) == 4 || len(g3) == 2:
		year, ok = yearFromGroup(g3, now)
		if !ok {
			return 0, 0, 0, "", false, false
		}
		switch {
		case n1 > 12 && n2 <= 12:
			return n1, n2, year, "dmy", false, true
		case n2 > 12 && n1 <= 12:
			return n2, n1, year, "mdy", false, true
		case n1 <= 12 && n2 <= 12:
			return n1, n2, year, "dmy", true, true
		}
		return 0, 0, 0, "", false, false
	default:
		return 0, 0, 0, "", false, false
	}
	switch {
	case n2 > 12 && n3 <= 12:
		return n2, n3, year, "ydm", false, true
	case n3 > 12 && n2 <= 12:
		return n3, n2, year, "ymd", false, true
	case n2 <= 12 && n3 <= 12:
		return n3, n2, year, "ymd", sep != '-', true
	}
	return 0, 0, 0, "", false, false
}

// yearFromGroup normalises a 2- or 4-digit year group.
func yearFromGroup(g string, now int) (int, bool) {
	n, err := strconv.Atoi(g)
	if err != nil {
		return 0, false
	}
	switch len(g) {
	case 4:
		return n, true
	case 2:
		return expandYear(n, now), true
	}
	return 0, false
}

// expandYear resolves a two-digit year against the current century: anything
// not yet reached this century belongs to the previous one, which is the only
// reading that makes sense for a birth or issue date.
func expandYear(yy, now int) int {
	if yy <= now%100 {
		return now/100*100 + yy
	}
	return now/100*100 - 100 + yy
}

// validCalendar is a real calendar check, leap years included: "31.02.1990"
// and "29.02.1900" are not dates and must never be masked.
func validCalendar(day, month, year int) bool {
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	return day <= daysInMonth(month, year)
}

func daysInMonth(month, year int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapYear(year) {
			return 29
		}
		return 28
	}
	return 0
}

// maxDaysInMonth — daysInMonth для НЕИЗВЕСТНОГО года: февралю достаётся 29.
// Именно это отличие спасает date-ext-034 "Дата рождения 31.02.1990":
// 31 > 29, пара "31.02" невалидна и без года.
func maxDaysInMonth(month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		return 29
	}
	return 0
}

// isLeapYear implements the full Gregorian rule; the century exceptions matter
// because 1900 is inside our plausible range.
func isLeapYear(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

// skipSpace returns the first non-whitespace token at or after from, or -1.
func skipSpace(toks []text.Token, from int) int {
	for i := from; i < len(toks); i++ {
		if toks[i].Kind != text.KindSpace {
			return i
		}
	}
	return -1
}

// ordinalAt reads a spelled-out day starting at token i, handling the
// two-word forms ("двадцать первое"). It returns the value and the index of
// the first token after it.
func ordinalAt(ctx *Context, i int) (value, after int, ok bool) {
	toks := ctx.Tokens
	w := ctx.Lower[toks[i].Start:toks[i].End]
	if tens, isTens := dateOrdinalTens[w]; isTens {
		if j := skipSpace(toks, i+1); j >= 0 && toks[j].Kind == text.KindWord {
			if n, found := ordinalNumber(ctx.Lower[toks[j].Start:toks[j].End]); found && n <= 9 {
				return tens + n, j + 1, true
			}
		}
	}
	if n, found := ordinalNumber(w); found {
		return n, i + 1, true
	}
	return 0, 0, false
}

// ordinalNumber resolves a spelled-out ordinal. The dictionary is consulted
// first so the data files stay the place to extend coverage; the built-in
// table is a guaranteed floor, because the detector's correctness must not
// depend on a data file being populated.
func ordinalNumber(w string) (int, bool) {
	if n, ok := dict.Ordinal(w); ok && n >= 1 && n <= 31 {
		return n, true
	}
	n, ok := dateOrdinalFallback[w]
	return n, ok
}

// monthNumber resolves a month word in any case form, dictionary first.
func monthNumber(w string) (int, bool) {
	if n, ok := dict.Month(w); ok && n >= 1 && n <= 12 {
		return n, true
	}
	n, ok := dateMonthFallback[w]
	return n, ok
}

// dateTailYear reads the year that closes a date whose month is a word, at
// token j. It is the single place the two spellings of a year meet:
//
//   - the ordinary numeric group, two or four digits, possibly glued to a
//     trailing "г" (dateYearEnd);
//   - the year written out in Russian words, "тысяча девятьсот девяностого".
//
// It returns the value, the byte offset the date ends at, the index of the
// last token consumed, and whether the year was the spelled-out kind — the
// caller needs that last flag because a spelled-out year is only ever read as
// a date behind an explicit anchor (dateWordYearAllowed).
func dateTailYear(ctx *Context, j, now int, gate *int8) (year, end, last int, word, ok bool) {
	toks := ctx.Tokens
	if j < 0 || j >= len(toks) {
		return 0, 0, 0, false, false
	}
	if yEnd, isNum := dateYearEnd(ctx.Lower, toks[j]); isNum {
		y, valid := yearFromGroup(ctx.Lower[toks[j].Start:yEnd], now)
		if !valid {
			return 0, 0, 0, false, false
		}
		return y, yEnd, j, false, true
	}
	y, lastTok, spelled := dateWordYear(ctx, j, gate)
	if !spelled {
		return 0, 0, 0, false, false
	}
	return y, toks[lastTok].End, lastTok, true, true
}

// dateWordYear reads a year written out in Russian words starting at token i
// and returns its value together with the index of its last token.
//
// Russian builds a year regularly — a thousands component, an optional
// hundreds one, an optional tens one, and a FINAL component in the ordinal:
// "тысяча девятьсот девяностого", "тысяча девятьсот восемьдесят восьмого",
// "две тысячи двадцать первого". So the parse is an accumulator over tokens
// rather than a table of whole years: sum the cardinal components, and let the
// first ordinal close the number.
//
// Nothing here builds a string. The words are compared as slices of ctx.Lower
// against tables expanded once at package initialisation, so the parser keeps
// this detector at its zero allocations per call.
//
// The ordinal is what makes the parse safe as well as short: "тысяча девятьсот
// девяносто" on its own is not a year, it is the start of one, and refusing it
// costs nothing while accepting it would let any half-phrase through.
func dateWordYear(ctx *Context, i int, gate *int8) (year, last int, ok bool) {
	if !dateWordYearGate(ctx.Lower, gate) {
		return 0, 0, false
	}
	toks, s := ctx.Tokens, ctx.Lower
	sum, pending, words := 0, 0, 0
	scaled := false
	for words < dateWordYearMaxWords {
		if i >= len(toks) || toks[i].Kind != text.KindWord {
			return 0, 0, false
		}
		w := s[toks[i].Start:toks[i].End]
		words++
		if scale, isScale := dateYearScale[w]; isScale {
			if pending == 0 {
				pending = 1
			}
			sum += pending * scale
			pending, scaled = 0, true
		} else if v, isCard := dateYearCardinal[w]; isCard {
			pending += v
		} else if v, isOrd := dateYearOrdinal(w); isOrd {
			if v >= 1000 {
				scaled = true
			}
			if !scaled {
				return 0, 0, false
			}
			return sum + pending + v, i, true
		} else {
			return 0, 0, false
		}
		i++
		if i < len(toks) && toks[i].Kind == text.KindSpace {
			if !dateInlineSpace(s, toks[i]) {
				return 0, 0, false
			}
			i++
		}
	}
	return 0, 0, false
}

// dateWordYearGate evaluates that prefilter at most once per request.
//
// The probe scans the whole payload, so it must not run per candidate; but it
// must also not run unconditionally, because the overwhelming majority of
// payloads never reach a textual date shape at all and would pay for a scan
// that could not have found anything. Threading the tri-state through (0
// unknown, 1 open, -1 closed) gets both: the scan happens on the first textual
// date shape in the payload and never again.
func dateWordYearGate(lower string, state *int8) bool {
	if *state == 0 {
		if strings.Contains(lower, dateWordYearMarker) {
			*state = 1
		} else {
			*state = -1
		}
	}
	return *state > 0
}

// dateWordYearAllowed gates a spelled-out year on an explicit date anchor.
//
// A numeric date carries its own evidence: three groups joined by separators
// are a shape ordinary prose does not produce by accident, so the detector can
// afford to weigh it on context alone. A year in words has no such shape. "В
// тысяча девятьсот сорок первом началась война" is a sentence about history,
// "родился он в тысяча девятьсот девяностом" is personal data, and the only
// thing that tells them apart is the anchor. So this spelling is read as a
// date ONLY beside an explicit "дата рождения" / "выдан", never on the weaker
// name or plausible-age heuristics that classify would otherwise apply.
func dateWordYearAllowed(ctx *Context, start, end int) bool {
	return leftAnchor(ctx.Lower, start) != anchorNone || hasRightBirthAnchor(ctx.Lower, end)
}

// dateYearOrdinal resolves the final, ordinal component of a spelled-out year.
//
// The dictionary is consulted first so data/ordinals.txt stays the place to
// extend coverage. Unlike ordinalNumber there is no 1..31 clamp: a year's last
// component is routinely a ten ("девяностого") or a thousand
// ("двухтысячного"), and the clamp exists only to keep day-of-month parsing
// honest.
func dateYearOrdinal(w string) (int, bool) {
	if n, ok := dict.Ordinal(w); ok {
		return n, true
	}
	n, ok := dateYearOrdinalFallback[w]
	return n, ok
}

// dateMonthPlaceholder — заглушки, которые бланк печатает в слоте месяца,
// когда поле не заполнено: "15 Mмм 1990" (латинская M + кириллические мм).
// День и год при такой заглушке — настоящие ПД, поэтому значение маскируется.
//
// Двухбуквенные формы ("мм", "mm") в список НЕ входят намеренно: "15 мм" —
// это миллиметры, и такое правило начало бы маскировать размеры. Трёхбуквенная
// заглушка единицей измерения не бывает.
var dateMonthPlaceholder = map[string]bool{
	"mмм": true, "ммм": true, "mmm": true,
}

// dateMonthFallback lists the nominative, genitive, prepositional, dative and
// instrumental forms plus the common abbreviations — the shapes that actually
// occur in scanned documents. It mirrors data/months.txt so that a missing or
// truncated data file cannot silently cost the detector its month coverage.
var dateMonthFallback = map[string]int{
	"январь": 1, "января": 1, "январе": 1, "январю": 1, "январём": 1, "январем": 1, "янв": 1,
	"февраль": 2, "февраля": 2, "феврале": 2, "февралю": 2, "февралём": 2, "февралем": 2, "фев": 2, "февр": 2,
	"март": 3, "марта": 3, "марте": 3, "марту": 3, "мартом": 3, "мар": 3, "мрт": 3,
	"апрель": 4, "апреля": 4, "апреле": 4, "апрелю": 4, "апрелем": 4, "апр": 4,
	"май": 5, "мая": 5, "мае": 5, "маю": 5, "маем": 5,
	"июнь": 6, "июня": 6, "июне": 6, "июню": 6, "июнем": 6, "июн": 6,
	"июль": 7, "июля": 7, "июле": 7, "июлю": 7, "июлем": 7, "июл": 7,
	"август": 8, "августа": 8, "августе": 8, "августу": 8, "августом": 8, "авг": 8,
	"сентябрь": 9, "сентября": 9, "сентябре": 9, "сентябрю": 9, "сентябрём": 9, "сентябрем": 9, "сен": 9, "сент": 9,
	"октябрь": 10, "октября": 10, "октябре": 10, "октябрю": 10, "октябрём": 10, "октябрем": 10, "окт": 10,
	"ноябрь": 11, "ноября": 11, "ноябре": 11, "ноябрю": 11, "ноябрём": 11, "ноябрем": 11, "ноя": 11, "нояб": 11,
	"декабрь": 12, "декабря": 12, "декабре": 12, "декабрю": 12, "декабрём": 12, "декабрем": 12, "дек": 12,
}

// dateOrdinalFallback holds the neuter nominative and genitive forms, the two
// that appear in dates ("двенадцатое мая", "двенадцатого мая").
var dateOrdinalFallback = map[string]int{
	"первое": 1, "первого": 1,
	"второе": 2, "второго": 2,
	"третье": 3, "третьего": 3,
	"четвёртое": 4, "четвертое": 4, "четвёртого": 4, "четвертого": 4,
	"пятое": 5, "пятого": 5,
	"шестое": 6, "шестого": 6,
	"седьмое": 7, "седьмого": 7,
	"восьмое": 8, "восьмого": 8,
	"девятое": 9, "девятого": 9,
	"десятое": 10, "десятого": 10,
	"одиннадцатое": 11, "одиннадцатого": 11,
	"двенадцатое": 12, "двенадцатого": 12,
	"тринадцатое": 13, "тринадцатого": 13,
	"четырнадцатое": 14, "четырнадцатого": 14,
	"пятнадцатое": 15, "пятнадцатого": 15,
	"шестнадцатое": 16, "шестнадцатого": 16,
	"семнадцатое": 17, "семнадцатого": 17,
	"восемнадцатое": 18, "восемнадцатого": 18,
	"девятнадцатое": 19, "девятнадцатого": 19,
	"двадцатое": 20, "двадцатого": 20,
	"тридцатое": 30, "тридцатого": 30,
}

// dateOrdinalTens prefixes the compound days 21..29 and 31.
var dateOrdinalTens = map[string]int{"двадцать": 20, "тридцать": 30}

// dateYearScale holds the thousands unit of a spelled-out year in the case
// forms a year actually uses: "тысяча девятьсот", "две тысячи", "двух тысяч".
var dateYearScale = map[string]int{
	"тысяча": 1000, "тысячи": 1000, "тысячу": 1000, "тысяч": 1000,
}

// dateYearCardinal holds the NON-final components of a spelled-out year.
//
// Completeness matters here for a reason that is not obvious: the list is
// consulted before dateYearOrdinal, and dict.Ordinal carries the small
// cardinals too ("три" -> 3). A cardinal missing from this table would
// therefore be mistaken for the closing ordinal and silently end the number
// early — "две тысячи три" would read as the year 2003 instead of being
// rejected as the unfinished phrase it is.
var dateYearCardinal = map[string]int{
	"один": 1, "одна": 1, "одно": 1, "одну": 1,
	"два": 2, "две": 2, "двух": 2,
	"три": 3, "трёх": 3, "трех": 3,
	"четыре": 4, "пять": 5, "шесть": 6, "семь": 7, "восемь": 8, "девять": 9,
	"десять": 10, "одиннадцать": 11, "двенадцать": 12, "тринадцать": 13,
	"четырнадцать": 14, "пятнадцать": 15, "шестнадцать": 16, "семнадцать": 17,
	"восемнадцать": 18, "девятнадцать": 19,
	"двадцать": 20, "тридцать": 30, "сорок": 40, "пятьдесят": 50,
	"шестьдесят": 60, "семьдесят": 70, "восемьдесят": 80, "девяносто": 90,
	"сто": 100, "двести": 200, "триста": 300, "четыреста": 400, "пятьсот": 500,
	"шестьсот": 600, "семьсот": 700, "восемьсот": 800, "девятьсот": 900,
}

// dateYearOrdinalFallback completes dict.Ordinal for the closing component of
// a year. It holds two groups the day-of-month dictionary deliberately lacks:
//
//   - the tens and thousands ordinals (40th..90th, 1000th, 2000th). These are
//     mirrored in data/ordinals.txt for the same reason dateMonthFallback
//     mirrors months.txt — a truncated data file must not silently cost the
//     detector a whole spelling — and they are safely above 31, so they cannot
//     leak into day parsing, which clamps to 1..31.
//   - the PREPOSITIONAL forms ("в тысяча девятьсот девяностом году"). These
//     are kept out of ordinals.txt on purpose: "первом" is a plausible year
//     component and an implausible day of month, and adding it to the shared
//     file would let "в первом мая 1990" parse as a date.
var dateYearOrdinalFallback = map[string]int{
	"сороковой": 40, "сорокового": 40, "сороковом": 40, "сороковое": 40,
	"пятидесятый": 50, "пятидесятого": 50, "пятидесятом": 50, "пятидесятое": 50,
	"шестидесятый": 60, "шестидесятого": 60, "шестидесятом": 60, "шестидесятое": 60,
	"семидесятый": 70, "семидесятого": 70, "семидесятом": 70, "семидесятое": 70,
	"восьмидесятый": 80, "восьмидесятого": 80, "восьмидесятом": 80, "восьмидесятое": 80,
	"девяностый": 90, "девяностого": 90, "девяностом": 90, "девяностое": 90,
	"тысячный": 1000, "тысячного": 1000, "тысячном": 1000,
	"двухтысячный": 2000, "двухтысячного": 2000, "двухтысячном": 2000,

	"первом": 1, "втором": 2, "третьем": 3,
	"четвёртом": 4, "четвертом": 4, "пятом": 5, "шестом": 6, "седьмом": 7,
	"восьмом": 8, "девятом": 9, "десятом": 10,
	"одиннадцатом": 11, "двенадцатом": 12, "тринадцатом": 13,
	"четырнадцатом": 14, "пятнадцатом": 15, "шестнадцатом": 16,
	"семнадцатом": 17, "восемнадцатом": 18, "девятнадцатом": 19,
	"двадцатом": 20, "тридцатом": 30,
}
