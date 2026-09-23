package detect

import (
	"math"
	"testing"

	"pdguard/internal/pd"
)

// dateSpans runs only the date detector, so a failure here cannot be caused by
// a sibling detector registered in another file.
func dateSpans(t *testing.T, payload string) []pd.Span {
	t.Helper()
	return dateDetector{}.Detect(NewContext(payload, nil))
}

func TestDateDetectorName(t *testing.T) {
	d := dateDetector{}
	if d.Name() != "date" {
		t.Fatalf("Name() = %q, want %q", d.Name(), "date")
	}
	if len(d.Types()) != 2 {
		t.Fatalf("Types() = %v, want the two date types", d.Types())
	}
}

// datePositiveCase is one positive date-detection case.
type datePositiveCase struct {
	name string
	in   string
	want string // exact substring the span must cover
	typ  pd.Type
	hint string
	conf float64
}

func TestDateDetectPositive(t *testing.T) {
	cases := []datePositiveCase{
		{name: "dotted dmy", in: "Дата рождения: 12.05.1990", want: "12.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.90},
		{name: "slashed dmy", in: "дата рождения 12/05/1990", want: "12/05/1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.90},
		{name: "dashed dmy with abbreviated anchor", in: "Д.Р. 12-05-1990", want: "12-05-1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.90},
		{name: "space separated", in: "дата рождения 12 05 1990", want: "12 05 1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.90},
		{name: "two digit year", in: "дата рождения 12.05.90", want: "12.05.90",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.90},
		{name: "unambiguous dmy", in: "Дата рождения 25.05.1990", want: "25.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.95},
		{name: "mdy resolved by day above 12", in: "дата рождения 05/25/1990", want: "05/25/1990",
			typ: pd.TypeBirthDate, hint: "mdy", conf: 0.95},
		{name: "ymd", in: "дата рождения 1990.12.05", want: "1990.12.05",
			typ: pd.TypeBirthDate, hint: "ymd", conf: 0.90},
		{name: "ydm resolved by day above 12", in: "дата рождения 1990.25.12", want: "1990.25.12",
			typ: pd.TypeBirthDate, hint: "ydm", conf: 0.95},
		{name: "leap day is a real date", in: "Дата рождения 29.02.2000", want: "29.02.2000",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.95},

		// The right-hand anchor is the only evidence here, and it is the
		// longest one in the list: a window too short to hold it silently
		// demoted this shape below the configured confidence floor.
		{name: "trailing goda rozhdeniya", in: "Анкета: Иванов Иван Иванович, 12.05.1990 года рождения", want: "12.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.85},

		{name: "issue date", in: "Паспорт выдан 20.06.2015", want: "20.06.2015",
			typ: pd.TypePassportIssueDate, hint: "dmy", conf: 0.95},
		{name: "issue date long anchor", in: "Дата выдачи 20.06.2015", want: "20.06.2015",
			typ: pd.TypePassportIssueDate, hint: "dmy", conf: 0.95},
		{name: "issue date english anchor", in: "Passport issued 20.06.2015", want: "20.06.2015",
			typ: pd.TypePassportIssueDate, hint: "dmy", conf: 0.95},

		// The trailing "года" / "г." is NOT part of the span: it is ordinary
		// text and must survive byte for byte.
		{name: "textual month keeps the goda tail outside", in: "Родился 12 мая 1990 года", want: "12 мая 1990",
			typ: pd.TypeBirthDate, hint: "text", conf: 0.95},
		{name: "textual month abbreviated tail", in: "родилась 12 мая 1990 г.", want: "12 мая 1990",
			typ: pd.TypeBirthDate, hint: "text", conf: 0.95},
		{name: "textual month genitive with issue anchor", in: "паспорт выдан 12 января 2015 года", want: "12 января 2015",
			typ: pd.TypePassportIssueDate, hint: "text", conf: 0.95},
		{name: "textual month two digit year", in: "дата рождения 12 мая 90", want: "12 мая 90",
			typ: pd.TypeBirthDate, hint: "text", conf: 0.95},

		{name: "spelled out day", in: "Дата рождения: двенадцатое мая 1990 года", want: "двенадцатое мая 1990",
			typ: pd.TypeBirthDate, hint: "words", conf: 0.95},
		{name: "spelled out compound day", in: "Дата рождения: двадцать первое мая 1990 года", want: "двадцать первое мая 1990",
			typ: pd.TypeBirthDate, hint: "words", conf: 0.95},

		// Clause 4.2 of the specification asks for dates written as text and
		// not as numbers, and that includes the YEAR. The span still stops
		// before the trailing "года": those four letters are ordinary text.
		{name: "spelled out year", in: "Дата рождения клиента: двенадцатое мая тысяча девятьсот девяностого года.",
			want: "двенадцатое мая тысяча девятьсот девяностого",
			typ:  pd.TypeBirthDate, hint: "words", conf: 0.95},
		{name: "spelled out year with a numeric day", in: "Дата рождения: 12 мая тысяча девятьсот девяностого года",
			want: "12 мая тысяча девятьсот девяностого",
			typ:  pd.TypeBirthDate, hint: "text", conf: 0.95},
		{name: "spelled out issue date", in: "Дата выдачи паспорта: двадцатое июня две тысячи пятнадцатого года",
			want: "двадцатое июня две тысячи пятнадцатого",
			typ:  pd.TypePassportIssueDate, hint: "words", conf: 0.95},

		// Separators padded with whitespace, as a form filled in by hand
		// writes them. The padding is inside the span because it is inside
		// the date.
		{name: "padded slashes", in: "Дата рождения: 15  /  07  /  1988 года.", want: "15  /  07  /  1988",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.95},
		{name: "padded dashes", in: "Паспорт выдан 20 - 06 - 2015 отделением", want: "20 - 06 - 2015",
			typ: pd.TypePassportIssueDate, hint: "dmy", conf: 0.95},

		{name: "bare year with rozhdeniya", in: "1990 года рождения", want: "1990",
			typ: pd.TypeBirthDate, hint: "text", conf: 0.90},
		{name: "bare year with gr", in: "Клиент 1990 г.р.", want: "1990",
			typ: pd.TypeBirthDate, hint: "text", conf: 0.90},
		{name: "full date wins over the bare year inside it", in: "12.05.1990 г.р.", want: "12.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.85},

		// 0.78 - 0.05 ambiguity penalty. The penalty must not push this branch
		// below the 0.7 floor the configuration applies, or the whole "date
		// straight after a name" reading would only ever work for days 13..31.
		{name: "date right after a full name", in: "Иванов Иван Иванович 12.05.1990", want: "12.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.73},
		{name: "bare plausible date defaults to birth date", in: "12.05.1990", want: "12.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.55},

		{name: "case insensitive anchor", in: "ДАТА РОЖДЕНИЯ 25.05.1990", want: "25.05.1990",
			typ: pd.TypeBirthDate, hint: "dmy", conf: 0.95},
		{name: "case insensitive month", in: "Родился 12 МАЯ 1990", want: "12 МАЯ 1990",
			typ: pd.TypeBirthDate, hint: "text", conf: 0.95},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertDatePositive(t, tc)
		})
	}
}

// assertDatePositive checks that one positive date case produces exactly the
// expected span.
func assertDatePositive(t *testing.T, tc datePositiveCase) {
	t.Helper()
	got := dateSpans(t, tc.in)
	if len(got) != 1 {
		t.Fatalf("got %d spans %v, want exactly 1", len(got), dump(tc.in, got))
	}
	s := got[0]
	if have := tc.in[s.Start:s.End]; have != tc.want {
		t.Errorf("span covers %q, want %q", have, tc.want)
	}
	if s.Type != tc.typ {
		t.Errorf("type = %s, want %s", s.Type, tc.typ)
	}
	if s.Hint != tc.hint {
		t.Errorf("hint = %q, want %q", s.Hint, tc.hint)
	}
	if s.Src != "date" {
		t.Errorf("src = %q, want %q", s.Src, "date")
	}
	if math.Abs(s.Conf-tc.conf) > 1e-9 {
		t.Errorf("conf = %v, want %v", s.Conf, tc.conf)
	}
}

// TestDateDetectNegative is the important half of the suite: the metric is a
// normalised edit distance against a reference mask, so every span emitted
// over text that is not personal data is a direct loss.
func TestDateDetectNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"time of day", "Время 12:05"},
		{"time with seconds", "Начало 12:05:30"},
		{"semantic version", "Версия 1.2.3"},
		{"version that looks like a date", "Версия 1.2.30"},
		{"ip address", "Сервер 192.168.1.10"},
		{"private ip address", "ip 10.0.0.1"},
		{"contract number", "Договор 12-05-1990"},
		{"order number", "Заказ 01.02.1999"},
		{"phone number blocks", "Телефон 8 800 555 35 35"},
		{"grouped amount", "Сумма 1 000 000"},
		{"amount with currency", "Оплата 100 000 рублей"},
		{"percentage glued to the number", "Скидка 12.05.1990%"},
		{"impossible day in february", "Дата рождения 31.02.1990"},
		{"february 29 in a common year", "Дата рождения 29.02.1990"},
		{"february 29 in a non-leap century", "Дата рождения 29.02.1900"},
		{"day and month both above 12", "Дата рождения 32.13.1990"},
		{"month above 12 in ymd", "Дата рождения 1990.13.32"},
		{"date in the future", "Срок до 12.05.2090"},
		{"year before 1900", "12.05.1890"},
		{"bare year is not personal data", "Отчёт за 2024"},
		{"bare year with no construction", "В 1990 началась история"},
		{"digits inside a longer run", "Идентификатор 1112.05.19901"},
		{"word that is not a month", "12 рублей 1990"},

		// A year in words is only ever a date next to an anchor. Without one
		// these are sentences, and the metric charges for every byte of them.
		{"spelled out year in prose", "В тысяча девятьсот сорок первом началась война"},
		{"spelled out date with no anchor", "Двенадцатое мая тысяча девятьсот девяностого года стало важной датой"},
		{"spelled out founding date is not a birth date", "Компания основана двенадцатого мая тысяча девятьсот девяностого года"},
		{"spelled year without its closing ordinal", "Дата рождения: двенадцатое мая тысяча девятьсот года"},
		{"spelled year without its thousand", "Дата рождения: двенадцатое мая девяностого года"},

		// Padding is allowed around an EXPLICIT separator only, and only up to
		// dateSepPad bytes of it. These are the shapes that would start being
		// masked if either half of that rule were dropped.
		{"numbers in a row are not a date", "Сумма 15 07 1988 рублей"},
		{"table columns separated by padding alone", "Колонки отчёта:\n15  07  1988\n16  08  1989"},
		{"padding wider than the limit", "Дата рождения: 15    /    07    /    1988"},
		{"a separator may not be padded across a line break", "Дата рождения 15 /\n07 / 1988"},
		{"padded version string", "Версия 1 . 2 . 3"},
		{"padded separators do not override a negative anchor", "Счёт 15  /  07  /  1988 закрыт"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dateSpans(t, tc.in); len(got) != 0 {
				t.Fatalf("got %d spans %v, want none", len(got), dump(tc.in, got))
			}
		})
	}
}

func TestDateDetectTwoDatesTypedIndependently(t *testing.T) {
	const in = "Дата рождения 01.01.1980, паспорт выдан 02.02.2010"
	got := dateSpans(t, in)
	if len(got) != 2 {
		t.Fatalf("got %d spans %v, want 2", len(got), dump(in, got))
	}
	if in[got[0].Start:got[0].End] != "01.01.1980" || got[0].Type != pd.TypeBirthDate {
		t.Errorf("first span = %q/%s, want 01.01.1980/BIRTH_DATE", in[got[0].Start:got[0].End], got[0].Type)
	}
	if in[got[1].Start:got[1].End] != "02.02.2010" || got[1].Type != pd.TypePassportIssueDate {
		t.Errorf("second span = %q/%s, want 02.02.2010/PASSPORT_ISSUE_DATE", in[got[1].Start:got[1].End], got[1].Type)
	}
}

func TestDateDetectRespectsDisabledTypes(t *testing.T) {
	const in = "Дата рождения 25.05.1990, паспорт выдан 20.06.2015"
	only := func(want pd.Type) func(pd.Type) bool {
		return func(t pd.Type) bool { return t == want }
	}

	got := dateDetector{}.Detect(NewContext(in, only(pd.TypePassportIssueDate)))
	if len(got) != 1 || got[0].Type != pd.TypePassportIssueDate {
		t.Fatalf("issue-only run produced %v, want a single issue date", dump(in, got))
	}
	got = dateDetector{}.Detect(NewContext(in, only(pd.TypeBirthDate)))
	if len(got) != 1 || got[0].Type != pd.TypeBirthDate {
		t.Fatalf("birth-only run produced %v, want a single birth date", dump(in, got))
	}
	got = dateDetector{}.Detect(NewContext(in, func(pd.Type) bool { return false }))
	if len(got) != 0 {
		t.Fatalf("all-disabled run produced %v, want none", dump(in, got))
	}
}

// TestDateSpansStayInsideText guards the invariant every downstream layer
// relies on: offsets are byte offsets into ctx.Text, and Cyrillic is 2 bytes
// per letter, so an off-by-one here would corrupt the output.
func TestDateSpansStayInsideText(t *testing.T) {
	const in = "Клиент Пётр родился двенадцатое мая 1990 года в Москве"
	got := dateSpans(t, in)
	if len(got) != 1 {
		t.Fatalf("got %d spans %v, want 1", len(got), dump(in, got))
	}
	s := got[0]
	if s.Start < 0 || s.End > len(in) || s.Start >= s.End {
		t.Fatalf("span %+v out of range for %d bytes", s, len(in))
	}
	if in[s.Start:s.End] != "двенадцатое мая 1990" {
		t.Fatalf("span covers %q, want %q", in[s.Start:s.End], "двенадцатое мая 1990")
	}
}

func TestDateOrder(t *testing.T) {
	const now = 2026
	cases := []struct {
		g1, g2, g3       string
		sep              byte
		day, month, year int
		hint             string
		ambiguous, ok    bool
	}{
		{"12", "05", "1990", '.', 12, 5, 1990, "dmy", true, true},
		{"25", "05", "1990", '.', 25, 5, 1990, "dmy", false, true},
		{"05", "25", "1990", '/', 25, 5, 1990, "mdy", false, true},
		{"1990", "12", "05", '.', 5, 12, 1990, "ymd", true, true},
		{"1990", "25", "12", '.', 25, 12, 1990, "ydm", false, true},
		{"12", "05", "90", '.', 12, 5, 1990, "dmy", true, true},
		{"12", "05", "05", '.', 12, 5, 2005, "dmy", true, true},
		{"90", "05", "12", '.', 12, 5, 1990, "ymd", true, true},
		{"32", "13", "1990", '.', 0, 0, 0, "", false, false},
		// ISO 8601 fixes the order by standard, so the dash-separated
		// year-first shape must not pay the ambiguity penalty.
		{"1990", "05", "12", '-', 12, 5, 1990, "ymd", false, true},
	}
	for _, tc := range cases {
		day, month, year, hint, amb, ok := dateOrder(tc.g1, tc.g2, tc.g3, tc.sep, now)
		if ok != tc.ok {
			t.Fatalf("dateOrder(%q,%q,%q) ok = %v, want %v", tc.g1, tc.g2, tc.g3, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if day != tc.day || month != tc.month || year != tc.year || hint != tc.hint || amb != tc.ambiguous {
			t.Errorf("dateOrder(%q,%q,%q) = %d/%d/%d %q amb=%v, want %d/%d/%d %q amb=%v",
				tc.g1, tc.g2, tc.g3, day, month, year, hint, amb,
				tc.day, tc.month, tc.year, tc.hint, tc.ambiguous)
		}
	}
}

func TestValidCalendar(t *testing.T) {
	cases := []struct {
		day, month, year int
		want             bool
	}{
		{31, 1, 1990, true},
		{31, 4, 1990, false},
		{30, 4, 1990, true},
		{29, 2, 2000, true},  // divisible by 400
		{29, 2, 1900, false}, // divisible by 100 but not 400
		{29, 2, 1996, true},
		{28, 2, 1990, true},
		{29, 2, 1990, false},
		{0, 1, 1990, false},
		{1, 0, 1990, false},
		{1, 13, 1990, false},
	}
	for _, tc := range cases {
		if got := validCalendar(tc.day, tc.month, tc.year); got != tc.want {
			t.Errorf("validCalendar(%d,%d,%d) = %v, want %v", tc.day, tc.month, tc.year, got, tc.want)
		}
	}
}

func TestExpandYear(t *testing.T) {
	const now = 2026
	cases := map[int]int{90: 1990, 26: 2026, 27: 1927, 5: 2005, 0: 2000}
	for yy, want := range cases {
		if got := expandYear(yy, now); got != want {
			t.Errorf("expandYear(%d, %d) = %d, want %d", yy, now, got, want)
		}
	}
}

// dump renders spans as the text they cover, so a failure message shows what
// was matched instead of raw offsets.
func dump(in string, spans []pd.Span) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, string(s.Type)+":"+in[s.Start:s.End])
	}
	return out
}

// TestDateConfidenceBandsAreDisjoint pins the invariant the propagation pass
// reads confidences for. Three bands must stay separated: an explicitly
// anchored date (donor), a heuristically typed one (neither donor nor taker)
// and an unanchored one (taker). Editing one constant without the others would
// silently turn the pass into something else.
func TestDateConfidenceBandsAreDisjoint(t *testing.T) {
	if dateConfStrongFloor > dateConfRightAnchored-dateAmbiguityPenalty+dateConfEps {
		t.Errorf("a right-anchored ambiguous date (%v) no longer reaches the donor floor %v",
			dateConfRightAnchored-dateAmbiguityPenalty, dateConfStrongFloor)
	}
	if dateConfAfterName >= dateConfStrongFloor {
		t.Errorf("a name-heuristic date (%v) must not act as a propagation donor (floor %v)",
			dateConfAfterName, dateConfStrongFloor)
	}
	if dateConfAfterName-dateAmbiguityPenalty <= dateConfBare {
		t.Errorf("a name-heuristic date (%v) must not be mistaken for a bare one (%v)",
			dateConfAfterName-dateAmbiguityPenalty, dateConfBare)
	}
	if dateConfPropagated-dateAmbiguityPenalty < 0.7 {
		t.Errorf("a propagated ambiguous date (%v) falls below the configured floor",
			dateConfPropagated-dateAmbiguityPenalty)
	}
	if dateConfPropagated >= dateConfStrongFloor {
		t.Errorf("a propagated date (%v) must never outrank an anchored one (%v)",
			dateConfPropagated, dateConfStrongFloor)
	}
}

// dateCovered returns the substrings covered with at least the configured
// confidence floor, i.e. what the service would actually mask.
func dateCovered(t *testing.T, in string) []string {
	t.Helper()
	var out []string
	for _, s := range dateSpans(t, in) {
		if s.Conf >= 0.7 {
			out = append(out, in[s.Start:s.End])
		}
	}
	return out
}

func dateEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestDateAnchorPropagation covers the gap this detector was reported for: the
// left-context scan is a fixed-width window, so in an enumeration the anchor
// only reaches the first date or two.
func TestDateAnchorPropagation(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "three spellings behind one anchor",
			in:   "Дата рождения 12.05.1990, второй вариант 1990.12.05, третий 12 мая 1990 года",
			want: []string{"12.05.1990", "1990.12.05", "12 мая 1990"},
		},
		{
			name: "enumeration of birth dates",
			in:   "Даты рождения детей: 12.05.2001, 03.07.2003, 21.11.2005",
			want: []string{"12.05.2001", "03.07.2003", "21.11.2005"},
		},
		{
			name: "range keeps both ends",
			in:   "Дата рождения указана в диапазоне с 12.05.1990 по 20.06.1990",
			want: []string{"12.05.1990", "20.06.1990"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dateCovered(t, tc.in); !dateEqual(got, tc.want) {
				t.Errorf("masked %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDatePropagationStaysLocal is the precision half of the propagation pass.
// A document that carries a real date of birth almost always carries a
// business date in the same paragraph, and those must not be dragged in.
func TestDatePropagationStaysLocal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "business date in the same sentence is not a birth date",
			in:   "Дата рождения 12.05.1990, заявление подано 01.09.2005",
			want: []string{"12.05.1990"},
		},
		{
			name: "a sentence boundary stops propagation",
			in:   "Дата рождения 12.05.1990. Полис оформлен на срок, указанный ниже 01.02.2005",
			want: []string{"12.05.1990"},
		},
		{
			name: "a date too far away is not borrowed",
			in: "Дата рождения 12.05.1990, далее следует пространное описание обстоятельств " +
				"дела и перечень приложенных документов, а затем 01.02.2005",
			want: []string{"12.05.1990"},
		},
		{
			// The bare date sits outside the reach of "выдан" but inside the
			// propagation window, so only guard 1 keeps it clean: an issue
			// date has no age test to fall back on and never lends its type.
			name: "an issue date does not propagate",
			in:   "Паспорт выдан 20.06.2010 в отделении полиции, прежний 01.02.2005",
			want: []string{"20.06.2010"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dateCovered(t, tc.in); !dateEqual(got, tc.want) {
				t.Errorf("masked %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDateBusinessDatesAreNotBirthDates covers the rule the detector's author
// flagged as the biggest risk: "an unanchored date is a date of birth" is
// wrong for every recent date in a banking corpus.
func TestDateBusinessDatesAreNotBirthDates(t *testing.T) {
	for _, in := range []string{
		"Заявление подано 01.09.2024, срок рассмотрения до 15.10.2024",
		"Отчётный период закрыт 31.12.2025",
		"Платёж проведён 05.03.2026",
		"Встреча назначена на 10.10.2025",
	} {
		if got := dateSpans(t, in); len(got) != 0 {
			t.Errorf("%q: got %v, want no spans at all", in, dump(in, got))
		}
	}
}

// TestDateExtraForms covers the spellings the first version of the detector
// could not see.
func TestDateExtraForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"abbreviated rod", "род. 12.05.1990", []string{"12.05.1990"}},
		{"abbreviated dr", "д.р. 12.05.1990", []string{"12.05.1990"}},
		{"glued gr", "Клиент 12.05.1990г.р.", []string{"12.05.1990"}},
		{"glued bare year", "Клиент 1990г.р.", []string{"1990"}},
		{"two digit year with gr", "12.05.90 г.р.", []string{"12.05.90"}},
		{"bare year gr", "Клиент 1990 г.р.", []string{"1990"}},
		{"slashes", "дата рождения 12/05/1990", []string{"12/05/1990"}},
		{"compact with anchor", "дата рождения 12051990", []string{"12051990"}},
		{"compact iso with anchor", "дата рождения 19900512", []string{"19900512"}},
		{"no leading zeros", "дата рождения 1.5.1990", []string{"1.5.1990"}},
		{"leading zeros", "дата рождения 01.05.1990", []string{"01.05.1990"}},
		{"iso", "дата рождения 1990-05-12", []string{"1990-05-12"}},
		{"month in instrumental case", "родился 12 январём 1990 года", []string{"12 январём 1990"}},
		{"month in dative case", "родился 12 январю 1990 года", []string{"12 январю 1990"}},
		{"abbreviated month with dot", "родился 12 янв. 1990 года", []string{"12 янв. 1990"}},
		// Both ends of a range are dates: the left-context window reaches the
		// second one directly, without any need for propagation.
		{"issue date range", "паспорт выдан 20.06.2015, продлён 21.07.2015",
			[]string{"20.06.2015", "21.07.2015"}},
		{"birth date range", "дата рождения от 12.05.1990 до 20.06.1990",
			[]string{"12.05.1990", "20.06.1990"}},
		{"parenthesised right anchor", "Анкета 12.05.1990 (дата рождения)",
			[]string{"12.05.1990"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dateCovered(t, tc.in); !dateEqual(got, tc.want) {
				t.Errorf("%q: masked %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDateCompactNeedsAnAnchor is the other half of the separator-less shape:
// eight digits with nothing to type them are an account number.
func TestDateCompactNeedsAnAnchor(t *testing.T) {
	for _, in := range []string{
		"Номер 12051990",
		"12051990",
		"Счёт 40817810",
		"дата рождения 99999999",
		"дата рождения 12345678",
	} {
		if got := dateCovered(t, in); len(got) != 0 {
			t.Errorf("%q: masked %v, want nothing", in, got)
		}
	}
}

// TestDateISOIsNotAmbiguous pins the one place the separator changes the
// reading: "1990-05-12" is ISO 8601 and its order is fixed by the standard.
func TestDateISOIsNotAmbiguous(t *testing.T) {
	got := dateSpans(t, "дата рождения 1990-05-12")
	if len(got) != 1 {
		t.Fatalf("got %d spans, want 1", len(got))
	}
	if math.Abs(got[0].Conf-dateConfAnchored) > 1e-9 {
		t.Errorf("conf = %v, want %v (no ambiguity penalty for ISO)", got[0].Conf, dateConfAnchored)
	}
}

// TestDateWordYear unit-tests the spelled-out year parser on its own, away
// from the anchor and calendar rules that gate it inside the detector.
//
// Russian builds a year regularly, so the parser is an accumulator rather than
// a table of years; these cases pin the component shapes it has to add up
// ("тысяча" alone, "две тысячи" multiplied, a hundreds word, a tens word) and
// the places it must refuse.
func TestDateWordYear(t *testing.T) {
	ok := []struct {
		in   string
		want int
	}{
		{"тысяча девятьсот девяностого", 1990},
		{"тысяча девятьсот восемьдесят восьмого", 1988},
		{"тысяча девятьсот сорок первого", 1941},
		{"тысяча девятьсот двадцатого", 1920},
		{"тысяча девятьсот девяностом", 1990}, // prepositional: "в ... году"
		{"две тысячи первого", 2001},
		{"две тысячи двадцать первого", 2021},
		{"две тысячи пятнадцатого", 2015},
		{"двухтысячного", 2000},
	}
	for _, tc := range ok {
		t.Run(tc.in, func(t *testing.T) {
			assertWordYearOK(t, tc)
		})
	}

	bad := []struct {
		name string
		in   string
		at   int
	}{
		{"no closing ordinal", "тысяча девятьсот девяносто года", 0},
		{"incomplete thousand", "тысяча девятьсот года", 0},
		{"an ordinal with no thousand behind it", "тысяча девятьсот девяностого", 4},
		{"a line break ends the number", "тысяча девятьсот\nдевяностого", 0},
		{"ordinary words", "тысяча рублей наличными", 0},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			assertWordYearBad(t, tc)
		})
	}
}

// assertWordYearOK checks that a spelled-out year parses to the expected value
// and ends on its own last word.
func assertWordYearOK(t *testing.T, tc struct {
	in   string
	want int
}) {
	t.Helper()
	ctx := NewContext(tc.in, nil)
	var gate int8
	got, last, found := dateWordYear(ctx, 0, &gate)
	if !found {
		t.Fatalf("dateWordYear(%q) found nothing", tc.in)
	}
	if got != tc.want {
		t.Errorf("dateWordYear(%q) = %d, want %d", tc.in, got, tc.want)
	}
	// The year must end on its own last word, so the caller can put
	// the span boundary there and leave a trailing "года" outside it.
	if end := ctx.Tokens[last].End; end != len(tc.in) {
		t.Errorf("year ends at %d, want %d (trailing %q)", end, len(tc.in), tc.in[end:])
	}
}

// assertWordYearBad checks that a spelled-out year is refused.
func assertWordYearBad(t *testing.T, tc struct {
	name string
	in   string
	at   int
}) {
	t.Helper()
	ctx := NewContext(tc.in, nil)
	var gate int8
	if y, _, found := dateWordYear(ctx, tc.at, &gate); found {
		t.Errorf("dateWordYear(%q, %d) = %d, want no match", tc.in, tc.at, y)
	}
}

// TestDateWordYearGate pins the prefilter that keeps the parser off the hot
// path: one substring probe per request, and the tri-state must be cached
// rather than recomputed.
func TestDateWordYearGate(t *testing.T) {
	var open, shut int8
	if !dateWordYearGate("родился двенадцатого мая тысяча девятьсот девяностого", &open) {
		t.Error("gate closed on a payload that contains the marker")
	}
	if open != 1 {
		t.Errorf("gate state = %d, want 1 (cached open)", open)
	}
	if dateWordYearGate("дата рождения 12.05.1990", &shut) {
		t.Error("gate opened on a payload with no spelled year")
	}
	if shut != -1 {
		t.Errorf("gate state = %d, want -1 (cached closed)", shut)
	}
	// "двухтысячного" is the contracted spelling; one probe has to cover it
	// too, which is why the marker is the stem and not a whole word.
	var contracted int8
	if !dateWordYearGate("первое января двухтысячного года", &contracted) {
		t.Error("gate closed on the contracted dvuhtysyachnogo spelling")
	}
}

// TestDateWordYearForms covers the spelled-out year end to end, including the
// forms that must stay untouched.
func TestDateWordYearForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"compound day and dve tysyachi year", "Дата рождения: двадцать первое мая две тысячи первого года",
			[]string{"двадцать первое мая две тысячи первого"}},
		{"dvuhtysyachnogo", "Дата рождения: первое января двухтысячного года",
			[]string{"первое января двухтысячного"}},
		{"four component year", "Клиент родился двенадцатого мая тысяча девятьсот восемьдесят восьмого года",
			[]string{"двенадцатого мая тысяча девятьсот восемьдесят восьмого"}},
		{"compound day and compound year", "Дата рождения: тридцать первое декабря тысяча девятьсот девяносто девятого года",
			[]string{"тридцать первое декабря тысяча девятьсот девяносто девятого"}},
		{"issue anchor", "Дата выдачи паспорта: двадцатое июня две тысячи пятнадцатого года",
			[]string{"двадцатое июня две тысячи пятнадцатого"}},

		{"no anchor, no mask", "Компания основана двенадцатого мая тысяча девятьсот девяностого года", nil},
		{"history stays verbatim", "В тысяча девятьсот девяносто первом году распался Советский Союз", nil},
		{"a bare spelled year is not a date", "Клиент родился в тысяча девятьсот девяностом году", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dateCovered(t, tc.in); !dateEqual(got, tc.want) {
				t.Errorf("%q: masked %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDateSeparatorPadding is the other reported gap: a form filled in by hand
// pads its separators, and a separator that had to be a single token lost
// every such date.
//
// The negative half is the load-bearing one. Padding is admitted around an
// explicit '.', '/' or '-' and nowhere else, because whitespace on its own is
// what separates spreadsheet columns.
func TestDateSeparatorPadding(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"padded slashes", "Дата рождения: 15  /  07  /  1988 года.", []string{"15  /  07  /  1988"}},
		{"padded dots", "Дата рождения 12 . 05 . 1990", []string{"12 . 05 . 1990"}},
		{"padded dashes", "Паспорт выдан 20 - 06 - 2015", []string{"20 - 06 - 2015"}},
		{"uneven padding", "Дата рождения 12 -  05 - 1990", []string{"12 -  05 - 1990"}},
		{"tabs pad a separator too", "Дата рождения 15\t/\t07\t/\t1988", []string{"15\t/\t07\t/\t1988"}},
		{"padding with a right anchor", "Анкета: 15  /  07  /  1988 г.р.", []string{"15  /  07  /  1988"}},

		{"four spaces are past the limit", "Дата рождения: 15    /    07    /    1988", nil},
		{"whitespace alone never pads", "Дата рождения 15  07  1988", nil},
		{"a line break is not padding", "Дата рождения 15 /\n07 / 1988", nil},
		{"columns of a table", "Колонки отчёта:\n15  07  1988\n16  08  1989", nil},
		{"an amount is not a date", "Сумма 15 07 1988 рублей", nil},
		{"a negative anchor still wins", "Счёт 15  /  07  /  1988 закрыт", nil},
		{"a padded version string is still a version", "Версия 1 . 2 . 3", nil},
		{"a recent business date stays verbatim", "Отчёт сформирован 05 . 03 . 2026 автоматически", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dateCovered(t, tc.in); !dateEqual(got, tc.want) {
				t.Errorf("%q: masked %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDateChainedLooksPastAnAbbreviation guards the regression the padded
// separator rule introduced and the fix that closed it: once dateChained can
// look through whitespace, the full stop of "род." sits exactly where a chain
// link's separator would, and a test that stopped at the dot threw away every
// date behind an abbreviated anchor.
func TestDateChainedLooksPastAnAbbreviation(t *testing.T) {
	for _, in := range []string{"род. 12.05.1990", "д.р. 12.05.1990", "рожд. 12.05.1990"} {
		if got := dateCovered(t, in); !dateEqual(got, []string{"12.05.1990"}) {
			t.Errorf("%q: masked %v, want [12.05.1990]", in, got)
		}
	}
	// The chain test itself must still fire on the shapes it exists for.
	for _, in := range []string{"Сервер 192.168.1.10", "ip 10.0.0.1", "Идентификатор 1112.05.19901"} {
		if got := dateSpans(t, in); len(got) != 0 {
			t.Errorf("%q: got %v, want no spans", in, dump(in, got))
		}
	}
}
