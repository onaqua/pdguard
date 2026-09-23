package detect

import (
	"strings"
	"testing"

	"pdguard/internal/pd"
)

// TestFIOHoldoutPositive pins the delayed-sample cases: fluent-vowel given
// names, two initials next to a short consonant surname, a name plus a
// consonant surname without a patronymic, prepositional-case role anchors,
// leading imperatives on «-и», and a lowercase surname in mixed-case text.
func TestFIOHoldoutPositive(t *testing.T) {
	fioRequireNamesDict(t)
	cases := []struct{ in, want string }{
		// 1. Fluent vowel: Лев -> Льва/Льву/Львом.
		{"Жалоба от Льва Иванова.", "Льва Иванова"},
		{"Письмо Льву Иванову.", "Льву Иванову"},
		{"Встреча с Львом Ивановым.", "Львом Ивановым"},
		// 2. Two initials + short consonant surname.
		{"Сегодня звонил Л. А. Ткач по поводу кредита.", "Л. А. Ткач"},
		{"Заёмщик Л.А. Ткач подал заявку.", "Л.А. Ткач"},
		{"Сегодня звонил Ткач Л. А. по поводу кредита.", "Ткач Л. А."},
		{"Заёмщик Ткач Л.А. подал заявку.", "Ткач Л.А."},
		// 3. Name + consonant surname without a patronymic.
		{"Сегодня звонил Лев Ткач по поводу кредита.", "Лев Ткач"},
		{"Сегодня звонил Ткач Лев по поводу кредита.", "Ткач Лев"},
		{"Жалоба от Льва Коваля зарегистрирована.", "Льва Коваля"},
		// 4. Prepositional-case role anchors.
		{"Напиши о заёмщике Лихачёве отчёт.", "Лихачёве"},
		{"Напиши о заёмщике Капустине отчёт.", "Капустине"},
		// 5. Leading imperative on «-и».
		{"Попроси Капустина Льва перезвонить.", "Капустина Льва"},
		{"Попроси Льва Капустина перезвонить.", "Льва Капустина"},
		// 6. Lowercase surname in mixed-case text.
		{"Расскажи о Тимофее Степановиче коротко.", "Тимофее Степановиче"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "")
	}
}

// TestFIOHoldoutNegative pins the delayed-sample negatives: a verb must not be
// masked, a stop/org word must not be read as a surname, and a stop-word-only
// sentence stays untouched.
func TestFIOHoldoutNegative(t *testing.T) {
	fioRequireNamesDict(t)
	// «прыгнул» is a verb, not a name.
	fioAssertSpans(t, "Лев прыгнул на антилопу.")
	// «банк» is a stop/org word, so «Иван Банк» must not be a name pair.
	for _, in := range []string{"Звонил Иван Банк."} {
		for _, s := range fioOnly(fioSpansIn(t, in), pd.TypeFIO) {
			if got := in[s.Start:s.End]; got == "Иван Банк" {
				t.Errorf("%q: masked %q, want no «Иван Банк»", in, got)
			}
		}
	}
	// A stop-word-only sentence has no name at all.
	fioAssertSpans(t, "Верни деньги до пятницы.")
}

// TestFIOHoldoutRegression pins the R11 regression: a leading imperative or
// preposition before two initials must not be read as a surname, the initials
// belong to the surname that follows them, and a consonant word in an
// all-caps/all-lowercase payload is not a surname.
func TestFIOHoldoutRegression(t *testing.T) {
	fioRequireNamesDict(t)
	cases := []struct{ in, want string }{
		{"Позвони И. С. Перешеину завтра.", "И. С. Перешеину"},
		{"Пригласи И. С. Перешеина на встречу.", "И. С. Перешеина"},
		{"Отправь И. С. Перешеину уведомление.", "И. С. Перешеину"},
		{"Уведоми Т. С. Лихачёву об овердрафте.", "Т. С. Лихачёву"},
		{"Попроси Т. С. Лихачёва перезвонить.", "Т. С. Лихачёва"},
		{"Запиши Т.С. Лихачёва на приём.", "Т.С. Лихачёва"},
		{"НЕТ ДАННЫХ ОТ И. С. ПЕРЕШЕИНА ЗА МАРТ.", "И. С. ПЕРЕШЕИНА"},
		{"нет данных от и. с. перешеина за март.", "и. с. перешеина"},
		{"пригласи и. с. перешеина на встречу.", "и. с. перешеина"},
		{"ДОГОВОР ПОДПИСАН ИЛЬЁЙ СЕРГЕЕВИЧЕМ ПЕРЕШЕИНЫМ ВЧЕРА.", "ИЛЬЁЙ СЕРГЕЕВИЧЕМ ПЕРЕШЕИНЫМ"},
		{"договор подписан ильёй сергеевичем перешеиным вчера.", "ильёй сергеевичем перешеиным"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "")
	}
}

// TestFIOHoldoutRegressionNegative pins the R11 regression on the negative
// side: a field label after two initials must not be swallowed into the name.
func TestFIOHoldoutRegressionNegative(t *testing.T) {
	fioRequireNamesDict(t)
	in := "Плательщик: И. И. Назначение: оплата по договору аренды."
	for _, s := range fioOnly(fioSpansIn(t, in), pd.TypeFIO) {
		if got := in[s.Start:s.End]; strings.Contains(got, "Назначение") {
			t.Errorf("%q: span %q contains «Назначение»", in, got)
		}
	}
}
