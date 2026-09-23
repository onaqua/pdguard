package detect

import "testing"

const (
	r13Ksenia = "Ксении Андреевне Зубаревой"
	r13Li     = "Ли Руслан Тимурович"
)

// TestFIOFirstPluralVerbStart: a sentence-initial first-person plural verb
// («Благодарим») is not an adjective surname and must not take the name away.
func TestFIOFirstPluralVerbStart(t *testing.T) {
	fioAssertSpans(t, "Благодарим Олега Борисовича Щербакова за обращение.", "Олега Борисовича Щербакова")
	fioAssertSpans(t, "Благодарим Олега Щербакова за обращение.", "Олега Щербакова")
	fioAssertSpans(t, "Благодарим Ксению Андреевну Цой за обращение.", "Ксению Андреевну Цой")
}

// TestFIOFemIndeclinable: a woman's surname on a consonant does not decline,
// but only a capitalised word in the middle of a cased sentence qualifies.
func TestFIOFemIndeclinable(t *testing.T) {
	fioAssertSpans(t, "Сделай выжимку из обращения Мельник Ксении Андреевны на одну строку.", "Мельник Ксении Андреевны")
	fioAssertSpans(t, "Сгенерируй СМС Ксении Андреевне Зубаревой о списании.", r13Ksenia)
	fioAssertSpans(t, "нет данных от анны петровны перешеиной за март.", "анны петровны перешеиной")
	fioAssertSpans(t, "ДОГОВОР ПОДПИСАН АННОЙ ПЕТРОВНОЙ ПЕРЕШЕИНОЙ ВЧЕРА.", "АННОЙ ПЕТРОВНОЙ ПЕРЕШЕИНОЙ")
}

// TestFIOShortSurnames covers two- and three-letter surnames, including «Ли»,
// which the stop list also holds as a particle.
func TestFIOShortSurnames(t *testing.T) {
	fioAssertSpans(t, "Клиентка сказала: я Ли Руслан Тимурович.", r13Li)
	fioAssertSpans(t, "Клиентка сказала: я Руслан Тимурович Ли.", "Руслан Тимурович Ли")
	fioAssertSpans(t, "Сделай выжимку из обращения Ли Руслана Тимуровича на одну строку.", "Ли Руслана Тимуровича")
	fioAssertSpans(t, "Клиентка сказала: я Ли Руслан.", "Ли Руслан")
	fioAssertSpans(t, "Клиентка сказала: я Ли Р. Т.", "Ли Р. Т.")
	fioAssertSpans(t, "Заявление г-жи Цой принято.", "Цой")
	fioAssertSpans(t, "Сделай выжимку из обращения Олега\nБорисовича\nЛи на одну строку.", "Олега\nБорисовича\nЛи")
}

// TestFIOFeminineRoleAnchors: feminine role words introduce a lone surname.
func TestFIOFeminineRoleAnchors(t *testing.T) {
	fioAssertSpans(t, "Нет подписи заявительницы Зубаревой.", "Зубаревой")
	fioAssertSpans(t, "Нет подписи заявительницы Мельник.", "Мельник")
	fioAssertSpans(t, "Справка о заявительнице Цой готова.", "Цой")
}

// TestFIOInitialsKeptByConfirmedSurname: the ending of an ALL-CAPS «КОРОТКО»
// must not take the initials away from a confirmed surname before them.
func TestFIOInitialsKeptByConfirmedSurname(t *testing.T) {
	fioAssertSpans(t, "РАССКАЖИ О ЛИХАЧЁВЕ Т. С. КОРОТКО.", "ЛИХАЧЁВЕ Т. С.")
	fioAssertSpans(t, "Позвони И. С. Перешеину завтра.", "И. С. Перешеину")
}
