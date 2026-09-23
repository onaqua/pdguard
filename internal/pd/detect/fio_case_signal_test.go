package detect

import "testing"

const (
	caseSignalLihachev = "Лихачёве Т. С."
	caseSignalTkachLA  = "Ткача Л. А."
)

// TestFIOCaseSignalInitials pins the initials rules against the case signal:
// the word after the initials is a surname only when the text carries case and
// the word is capitalised, so «открыл», «ПОДАЛ» and «коротко» never steal the
// initials from the real surname in front of them.
func TestFIOCaseSignalInitials(t *testing.T) {
	fioAssertSpans(t, "Расскажи о Лихачёве Т. С. коротко.", caseSignalLihachev)
	fioAssertSpans(t, "клиент перешеин и. с. открыл счёт.", "перешеин и. с.")
	fioAssertSpans(t, "НЕТ ДАННЫХ ОТ ПЕРЕШЕИНА И. С. ЗА МАРТ.", "ПЕРЕШЕИНА И. С.")
	fioAssertSpans(t, "ЗАЁМЩИК ЛИХАЧЁВ Т. С. ПОДАЛ ЗАЯВКУ.", "ЛИХАЧЁВ Т. С.")
	fioAssertSpans(t, "Позвони И. С. Перешеину завтра.", "И. С. Перешеину")
	fioAssertSpans(t, "Сегодня звонил Л. А. Ткач по поводу кредита.", "Л. А. Ткач")
}

// TestFIOCaseSignalLooseBefore covers a capitalised word in front of two
// initials that no surname check confirms («Ткача»): it is taken only before
// exactly two initials and never at the start of a sentence.
func TestFIOCaseSignalLooseBefore(t *testing.T) {
	fioAssertSpans(t, "Жалоба от Ткача Л. А. зарегистрирована.", caseSignalTkachLA)
	fioAssertSpans(t, "Жалоба от Ткача Л.А. зарегистрирована.", "Ткача Л.А.")
	fioAssertSpans(t, "Уведоми Т. С. Лихачёву об овердрафте.", "Т. С. Лихачёву")
}

// TestFIOCaseSignalConsonantForms covers surnames on a consonant in oblique
// cases next to a dictionary given name and after a strong anchor.
func TestFIOCaseSignalConsonantForms(t *testing.T) {
	fioAssertSpans(t, "Жалоба от Ткача Льва зарегистрирована.", "Ткача Льва")
	fioAssertSpans(t, "Жалоба от Льва Ткача зарегистрирована.", "Льва Ткача")
	fioAssertSpans(t, "Заёмщик Ткач подал заявку.", "Ткач")
	fioAssertSpans(t, "Расскажи о Ткаче Льве коротко.", "Ткаче Льве")
}

// TestFIOCaseSignalLowercaseEnding: in a mixed-case text a lower-case word is
// not a surname just because of its ending.
func TestFIOCaseSignalLowercaseEnding(t *testing.T) {
	fioAssertSpans(t, "Расскажи о Тимофее Степановиче коротко.", "Тимофее Степановиче")
	fioAssertSpans(t, "Плательщик: И. И. Назначение: оплата по договору аренды.")
}
