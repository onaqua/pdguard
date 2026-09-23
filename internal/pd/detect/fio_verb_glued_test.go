package detect

import (
	"strings"
	"testing"

	"pdguard/internal/pd"
)

// TestFIOVerbGluedValue covers a leading imperative verb stripped from a value
// run at the start of a sentence, initials glued to a surname, and the latin
// «Имя Фамилия» order without a card anchor.
func TestFIOVerbGluedValue(t *testing.T) {
	cases := []struct {
		in   string
		typ  pd.Type
		want string
	}{
		{"Отправь Анне Залуцкой уведомление.", pd.TypeFIO, "Анне Залуцкой"},
		{"Звонил Перешеин, просил перезвонить.", pd.TypeFIO, "Перешеин"},
		{"Позвони Перешеину Илье завтра.", pd.TypeFIO, "Перешеину Илье"},
		{"Клиент И.С.Перешеин открыл счёт.", pd.TypeFIO, "И.С.Перешеин"},
		{"Составь письмо И.С.Перешеину о задолженности.", pd.TypeFIO, "И.С.Перешеину"},
		{"Нет данных от А.П.Залуцкой.", pd.TypeFIO, "А.П.Залуцкой"},
		{"Клиент И.С.Иванов открыл счёт.", pd.TypeFIO, "И.С.Иванов"},
		{"Письмо Ilya Pereshein о задолженности.", pd.TypeCardHolder, "Ilya Pereshein"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, c.typ, c.want, "")
	}
}

// TestFIOVerbGluedNegative pins the cases that must stay untouched.
func TestFIOVerbGluedNegative(t *testing.T) {
	cases := []struct {
		in  string
		typ pd.Type
	}{
		{"Visa Classic card", pd.TypeCardHolder},
		{"Hello World", pd.TypeCardHolder},
		{"Отправь отчёт в Сбербанк.", pd.TypeFIO},
	}
	for _, c := range cases {
		if spans := fioOnly(fioSpansIn(t, c.in), c.typ); len(spans) != 0 {
			t.Errorf("%q: expected no %s spans, got %v", c.in, c.typ, fioDump(c.in, spans))
		}
	}
}

// TestFIOVerbGluedPartial pins the cases where the leading verb is stripped but
// the rest of the name is still found.
func TestFIOVerbGluedPartial(t *testing.T) {
	fioAssertOneSpan(t, "Пишу Анне Петровне.", pd.TypeFIO, "Анне Петровне", "")
	for _, s := range fioOnly(fioSpansIn(t, "Т.е. Иванов прав."), pd.TypeFIO) {
		if got := "Т.е. Иванов прав."[s.Start:s.End]; strings.Contains(got, "Т.е.") {
			t.Errorf("Т.е. Иванов прав.: span %q must not contain the abbreviation", got)
		}
	}
}
