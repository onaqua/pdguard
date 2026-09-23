package detect

import (
	"testing"

	"pdguard/internal/pd"
)

// TestFIOPairObliqueNoPatr covers «Фамилия Имя» and «Имя Фамилия» without a
// patronymic, where the surname is an oblique form not in the dictionary.
func TestFIOPairObliqueNoPatr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Составь письмо Перешеину Илье о задолженности.", "Перешеину Илье"},
		{"Составь письмо Илье Перешеину о задолженности.", "Илье Перешеину"},
		{"Письмо от Перешеиной Анны.", "Перешеиной Анны"},
		{"Договор подписан Мордвинцевым Игорем.", "Мордвинцевым Игорем"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "surname_name")
	}
}

// TestFIOLoneObliqueAnchor covers a lone oblique surname after a strong client
// anchor.
func TestFIOLoneObliqueAnchor(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Позвони клиенту Перешеину завтра.", "Перешеину"},
		{"Составь ответ клиентке Мордвинцевой.", "Мордвинцевой"},
		{"Мы говорили о клиенте Перешеине вчера.", "Перешеине"},
		{"Пригласи клиентку Залуцкую на встречу.", "Залуцкую"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "surname")
	}
}

// TestFIOStrongAnchorForms covers the added strong-anchor forms.
func TestFIOStrongAnchorForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Напиши г-ну Перешеину о долге.", "Перешеину"},
		{"Напиши г-же Залуцкой о долге.", "Залуцкой"},
		{"Направьте господину Иванову ответ.", "Иванову"},
		{"Напиши г-же Ивановой о долге.", "Ивановой"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "surname")
	}
}

// TestFIOYoForms covers the «ё»→«е» folding in the name dictionaries.
func TestFIOYoForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Встреча с Ивановым Ильёй перенесена.", "Ивановым Ильёй"},
		{"Встреча с Ильёй Ивановым перенесена.", "Ильёй Ивановым"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "surname_name")
	}
}

// TestFIOPairAnchorNegative pins that the span never swallows the anchor or a
// preceding word.
func TestFIOPairAnchorNegative(t *testing.T) {
	fioAssertSpans(t, "Москве Анне позвонили.")
	fioAssertSpans(t, "Спасибо Илье за помощь.")
	fioAssertSpans(t, "Позвони клиенту завтра.")
	fioAssertSpans(t, "Напиши г-ну директору.")
}
