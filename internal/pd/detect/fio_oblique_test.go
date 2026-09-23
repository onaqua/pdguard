package detect

import (
	"fmt"
	"testing"

	"pdguard/internal/pd"
)

const (
	fiooFrameNom = "Клиент %s открыл счёт."
	fiooFrameGen = "Нет данных от %s за март."
	fiooFrameDat = "Составь письмо %s о задолженности."
	fiooFrameAcc = "Пригласи %s на встречу."
	fiooFrameIns = "Договор подписан %s вчера."
	fiooFramePre = "Мы говорили о %s вчера."

	fiooMascNom = "Илья Сергеевич"
	fiooMascGen = "Ильи Сергеевича"
	fiooMascDat = "Илье Сергеевичу"
	fiooMascAcc = "Илью Сергеевича"
	fiooMascIns = "Ильёй Сергеевичем"
	fiooMascPre = "Илье Сергеевиче"

	fiooFemNom = "Анна Петровна"
	fiooFemGen = "Анны Петровны"
	fiooFemDat = "Анне Петровне"
	fiooFemAcc = "Анну Петровну"
	fiooFemIns = "Анной Петровной"
	fiooFemPre = "Анне Петровне"

	fiooPerNom = "Перешеин"
	fiooPerGen = "Перешеина"
	fiooPerDat = "Перешеину"
	fiooPerIns = "Перешеиным"
	fiooPerPre = "Перешеине"

	fiooZalNom = "Залуцкий"
	fiooZalGen = "Залуцкого"
	fiooZalDat = "Залуцкому"
	fiooZalIns = "Залуцким"
	fiooZalPre = "Залуцком"

	fiooMorNom = "Мордвинцев"
	fiooMorGen = "Мордвинцева"
	fiooMorDat = "Мордвинцеву"
	fiooMorIns = "Мордвинцевым"
	fiooMorPre = "Мордвинцеве"

	fiooKraNom = "Кравчук"
	fiooKraGen = "Кравчука"
	fiooKraDat = "Кравчуку"
	fiooKraIns = "Кравчуком"
	fiooKraPre = "Кравчуке"

	fiooPerFNom = "Перешеина"
	fiooPerFGen = "Перешеиной"
	fiooPerFAcc = "Перешеину"

	fiooZalFNom = "Залуцкая"
	fiooZalFGen = "Залуцкой"
	fiooZalFAcc = "Залуцкую"

	fiooMorFNom = "Мордвинцева"
	fiooMorFGen = "Мордвинцевой"
	fiooMorFAcc = "Мордвинцеву"
)

// fiooFull joins a surname form and a given-name part into a full name.
func fiooFull(surname, given string) string { return surname + " " + given }

// fiooAssert checks that the frame with the name filled in yields exactly one
// FIO span covering the whole name.
func fiooAssert(t *testing.T, frame, name string) {
	t.Helper()
	fioAssertOneSpan(t, fmt.Sprintf(frame, name), pd.TypeFIO, name, "full")
}

// TestFIOObliqueSurname covers surnames that are not in the dictionary and are
// recognised in oblique cases from the neighbouring patronymic. Both word
// orders and all six cases are exercised for masculine and feminine surnames.
func TestFIOObliqueSurname(t *testing.T) {
	cases := []struct{ frame, name string }{
		// Перешеин, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooPerNom, fiooMascNom)},
		{fiooFrameGen, fiooFull(fiooPerGen, fiooMascGen)},
		{fiooFrameDat, fiooFull(fiooPerDat, fiooMascDat)},
		{fiooFrameAcc, fiooFull(fiooPerGen, fiooMascAcc)},
		{fiooFrameIns, fiooFull(fiooPerIns, fiooMascIns)},
		{fiooFramePre, fiooFull(fiooPerPre, fiooMascPre)},
		// Перешеин, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooMascNom, fiooPerNom)},
		{fiooFrameGen, fiooFull(fiooMascGen, fiooPerGen)},
		{fiooFrameDat, fiooFull(fiooMascDat, fiooPerDat)},
		{fiooFrameAcc, fiooFull(fiooMascAcc, fiooPerGen)},
		{fiooFrameIns, fiooFull(fiooMascIns, fiooPerIns)},
		{fiooFramePre, fiooFull(fiooMascPre, fiooPerPre)},
		// Залуцкий, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooZalNom, fiooMascNom)},
		{fiooFrameGen, fiooFull(fiooZalGen, fiooMascGen)},
		{fiooFrameDat, fiooFull(fiooZalDat, fiooMascDat)},
		{fiooFrameAcc, fiooFull(fiooZalGen, fiooMascAcc)},
		{fiooFrameIns, fiooFull(fiooZalIns, fiooMascIns)},
		{fiooFramePre, fiooFull(fiooZalPre, fiooMascPre)},
		// Залуцкий, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooMascNom, fiooZalNom)},
		{fiooFrameGen, fiooFull(fiooMascGen, fiooZalGen)},
		{fiooFrameDat, fiooFull(fiooMascDat, fiooZalDat)},
		{fiooFrameAcc, fiooFull(fiooMascAcc, fiooZalGen)},
		{fiooFrameIns, fiooFull(fiooMascIns, fiooZalIns)},
		{fiooFramePre, fiooFull(fiooMascPre, fiooZalPre)},
		// Мордвинцев, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooMorNom, fiooMascNom)},
		{fiooFrameGen, fiooFull(fiooMorGen, fiooMascGen)},
		{fiooFrameDat, fiooFull(fiooMorDat, fiooMascDat)},
		{fiooFrameAcc, fiooFull(fiooMorGen, fiooMascAcc)},
		{fiooFrameIns, fiooFull(fiooMorIns, fiooMascIns)},
		{fiooFramePre, fiooFull(fiooMorPre, fiooMascPre)},
		// Мордвинцев, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooMascNom, fiooMorNom)},
		{fiooFrameGen, fiooFull(fiooMascGen, fiooMorGen)},
		{fiooFrameDat, fiooFull(fiooMascDat, fiooMorDat)},
		{fiooFrameAcc, fiooFull(fiooMascAcc, fiooMorGen)},
		{fiooFrameIns, fiooFull(fiooMascIns, fiooMorIns)},
		{fiooFramePre, fiooFull(fiooMascPre, fiooMorPre)},
		// Кравчук, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooKraNom, fiooMascNom)},
		{fiooFrameGen, fiooFull(fiooKraGen, fiooMascGen)},
		{fiooFrameDat, fiooFull(fiooKraDat, fiooMascDat)},
		{fiooFrameAcc, fiooFull(fiooKraGen, fiooMascAcc)},
		{fiooFrameIns, fiooFull(fiooKraIns, fiooMascIns)},
		{fiooFramePre, fiooFull(fiooKraPre, fiooMascPre)},
		// Кравчук, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooMascNom, fiooKraNom)},
		{fiooFrameGen, fiooFull(fiooMascGen, fiooKraGen)},
		{fiooFrameDat, fiooFull(fiooMascDat, fiooKraDat)},
		{fiooFrameAcc, fiooFull(fiooMascAcc, fiooKraGen)},
		{fiooFrameIns, fiooFull(fiooMascIns, fiooKraIns)},
		{fiooFramePre, fiooFull(fiooMascPre, fiooKraPre)},
		// Перешеина, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooPerFNom, fiooFemNom)},
		{fiooFrameGen, fiooFull(fiooPerFGen, fiooFemGen)},
		{fiooFrameDat, fiooFull(fiooPerFGen, fiooFemDat)},
		{fiooFrameAcc, fiooFull(fiooPerFAcc, fiooFemAcc)},
		{fiooFrameIns, fiooFull(fiooPerFGen, fiooFemIns)},
		{fiooFramePre, fiooFull(fiooPerFGen, fiooFemPre)},
		// Перешеина, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooFemNom, fiooPerFNom)},
		{fiooFrameGen, fiooFull(fiooFemGen, fiooPerFGen)},
		{fiooFrameDat, fiooFull(fiooFemDat, fiooPerFGen)},
		{fiooFrameAcc, fiooFull(fiooFemAcc, fiooPerFAcc)},
		{fiooFrameIns, fiooFull(fiooFemIns, fiooPerFGen)},
		{fiooFramePre, fiooFull(fiooFemPre, fiooPerFGen)},
		// Залуцкая, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooZalFNom, fiooFemNom)},
		{fiooFrameGen, fiooFull(fiooZalFGen, fiooFemGen)},
		{fiooFrameDat, fiooFull(fiooZalFGen, fiooFemDat)},
		{fiooFrameAcc, fiooFull(fiooZalFAcc, fiooFemAcc)},
		{fiooFrameIns, fiooFull(fiooZalFGen, fiooFemIns)},
		{fiooFramePre, fiooFull(fiooZalFGen, fiooFemPre)},
		// Залуцкая, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooFemNom, fiooZalFNom)},
		{fiooFrameGen, fiooFull(fiooFemGen, fiooZalFGen)},
		{fiooFrameDat, fiooFull(fiooFemDat, fiooZalFGen)},
		{fiooFrameAcc, fiooFull(fiooFemAcc, fiooZalFAcc)},
		{fiooFrameIns, fiooFull(fiooFemIns, fiooZalFGen)},
		{fiooFramePre, fiooFull(fiooFemPre, fiooZalFGen)},
		// Мордвинцева, Фамилия Имя Отчество.
		{fiooFrameNom, fiooFull(fiooMorFNom, fiooFemNom)},
		{fiooFrameGen, fiooFull(fiooMorFGen, fiooFemGen)},
		{fiooFrameDat, fiooFull(fiooMorFGen, fiooFemDat)},
		{fiooFrameAcc, fiooFull(fiooMorFAcc, fiooFemAcc)},
		{fiooFrameIns, fiooFull(fiooMorFGen, fiooFemIns)},
		{fiooFramePre, fiooFull(fiooMorFGen, fiooFemPre)},
		// Мордвинцева, Имя Отчество Фамилия.
		{fiooFrameNom, fiooFull(fiooFemNom, fiooMorFNom)},
		{fiooFrameGen, fiooFull(fiooFemGen, fiooMorFGen)},
		{fiooFrameDat, fiooFull(fiooFemDat, fiooMorFGen)},
		{fiooFrameAcc, fiooFull(fiooFemAcc, fiooMorFAcc)},
		{fiooFrameIns, fiooFull(fiooFemIns, fiooMorFGen)},
		{fiooFramePre, fiooFull(fiooFemPre, fiooMorFGen)},
	}
	for _, c := range cases {
		fiooAssert(t, c.frame, c.name)
	}
}

// TestFIOObliqueUserExample pins the exact case reported from the stand: the
// dative surname leaked because it was not in the dictionary.
func TestFIOObliqueUserExample(t *testing.T) {
	fioAssertOneSpan(t,
		"Составь письмо Перешеину Илье Сергеевичу о том что его задолженность по карте составила 300 рублей.",
		pd.TypeFIO, fiooFull(fiooPerDat, fiooMascDat), "full")
}

// TestFIOObliqueInitials covers oblique surnames next to initials, where the
// initials are strong evidence on their own.
func TestFIOObliqueInitials(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Составь письмо И. С. Перешеину о долге.", "И. С. Перешеину"},
		{"Составь письмо Перешеину И. С. о долге.", "Перешеину И. С."},
		{"Договор подписан Перешеиным И. С.", "Перешеиным И. С."},
		{"Составь письмо Залуцкому И. С.", "Залуцкому И. С."},
		{"Составь письмо Перешеиной А. П.", "Перешеиной А. П."},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, "surname_initials")
	}
}

// TestFIOObliqueNegative pins that an address or job title in front of a name
// never becomes part of the span: the span starts at the given name.
func TestFIOObliqueNegative(t *testing.T) {
	fioAssertSpans(t, "Господину Илье Сергеевичу привет.", fiooMascDat)
	fioAssertSpans(t, "Гражданину Илье Сергеевичу отказано.", fiooMascDat)
	fioAssertSpans(t, "Директору Илье Сергеевичу направлено письмо.", fiooMascDat)
	fioAssertSpans(t, "Скажу Илье Сергеевичу.", fiooMascDat)
	fioAssertSpans(t, "Спасибо Илье Сергеевичу за помощь.", fiooMascDat)
	fioAssertSpans(t, "Клиенту Анне Петровне одобрено.", fiooFemDat)
}
