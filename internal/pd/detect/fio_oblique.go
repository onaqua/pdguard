package detect

import (
	"strings"

	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/text"
)

// fioCase is a bitmask of Russian grammatical cases. The oblique-surname rule
// derives the case and gender of a surname from the neighbouring patronymic,
// which is the most reliable witness, and then checks the surname form against
// the endings of that case.
type fioCase uint8

const (
	fioCaseNom fioCase = 1 << iota
	fioCaseGen
	fioCaseDat
	fioCaseAcc
	fioCaseIns
	fioCasePre
)

// fioCaseAll is every case; used by the initials rules, which accept an oblique
// surname in any case and either gender.
const fioCaseAll = fioCaseNom | fioCaseGen | fioCaseDat | fioCaseAcc | fioCaseIns | fioCasePre

// fioCaseOfPatronymic derives the case set and gender (0 = masculine,
// 1 = feminine) from a patronymic's ending. The patronymic is the most reliable
// witness for the case and gender of the whole name, so the surname is checked
// against exactly these cases.
func fioCaseOfPatronymic(lower string) (fioCase, int) {
	switch {
	case strings.HasSuffix(lower, "ичом"):
		return fioCaseIns, 0
	case strings.HasSuffix(lower, "ичем"):
		return fioCaseIns, 0
	case strings.HasSuffix(lower, "ича"):
		return fioCaseGen | fioCaseAcc, 0
	case strings.HasSuffix(lower, "ичу"):
		return fioCaseDat, 0
	case strings.HasSuffix(lower, "иче"):
		return fioCasePre, 0
	case strings.HasSuffix(lower, "ич"):
		return fioCaseNom, 0
	case strings.HasSuffix(lower, "ной"):
		return fioCaseIns, 1
	case strings.HasSuffix(lower, "на"):
		return fioCaseNom, 1
	case strings.HasSuffix(lower, "ны"):
		return fioCaseGen, 1
	case strings.HasSuffix(lower, "не"):
		return fioCaseDat | fioCasePre, 1
	case strings.HasSuffix(lower, "ну"):
		return fioCaseAcc, 1
	}
	return 0, 0
}

// fioObliqueSurname reports whether w is a form of a surname in one of the
// cases cs, for the given gender fem. The word is not in the dictionary, so the
// nominative candidate is recovered by stripping the case ending and attaching
// the nominative one, then checked against the dictionary and the surname
// morphology.
func fioObliqueSurname(w string, cs fioCase, fem int) bool {
	if fem == 0 {
		return fioObliqueMasculine(w, cs)
	}
	return fioObliqueFeminine(w, cs)
}

// fioObliqueEnding is one case-ending → nominative-ending pair for the
// oblique-surname rule.
type fioObliqueEnding struct {
	cases fioCase
	suf   string
	nom   string
}

// fioObliqueMascEndings covers masculine surnames: consonant-ending surnames
// (-ов/-ев/-ёв/-ин/-ын and the consonant suffixes) and adjective-ending
// surnames (-ский/-цкий/-ой/-ый/-ий).
var fioObliqueMascEndings = []fioObliqueEnding{
	{fioCaseGen | fioCaseAcc, "а", ""},
	{fioCaseDat, "у", ""},
	{fioCaseIns, "ым", ""},
	{fioCaseIns, "ом", ""},
	{fioCaseIns, "ем", ""},
	{fioCasePre, "е", ""},
	{fioCaseGen | fioCaseAcc, "ого", "ий"},
	{fioCaseDat, "ому", "ий"},
	{fioCaseIns, "им", "ий"},
	{fioCasePre, "ом", "ий"},
}

// fioObliqueFemEndings covers feminine surnames: -ова/-ева/-ина/-ына and
// -ская/-цкая.
var fioObliqueFemEndings = []fioObliqueEnding{
	{fioCaseGen | fioCaseDat | fioCaseIns | fioCasePre, "ой", "а"},
	{fioCaseAcc, "у", "а"},
	{fioCaseGen | fioCaseDat | fioCaseIns | fioCasePre, "ой", "ая"},
	{fioCaseAcc, "ую", "ая"},
}

// fioObliqueMasculine checks the masculine surname endings.
func fioObliqueMasculine(w string, cs fioCase) bool {
	return fioObliqueEndings(w, cs, fioObliqueMascEndings)
}

// fioObliqueFeminine checks the feminine surname endings.
func fioObliqueFeminine(w string, cs fioCase) bool {
	return fioObliqueEndings(w, cs, fioObliqueFemEndings)
}

// fioObliqueEndings tries every ending pair whose case is in cs.
func fioObliqueEndings(w string, cs fioCase, endings []fioObliqueEnding) bool {
	for _, e := range endings {
		if cs&e.cases != 0 && fioObliqueTry(w, e.suf, e.nom) {
			return true
		}
	}
	return false
}

// fioObliqueTry strips the case ending suf from w, attaches the nominative
// ending nomSuf, and checks the recovered candidate. The stem (w without the
// case ending) must be at least three runes long.
func fioObliqueTry(w, suf, nomSuf string) bool {
	if !strings.HasSuffix(w, suf) {
		return false
	}
	stem := w[:len(w)-len(suf)]
	if fioRunes(stem) < 3 {
		return false
	}
	return fioObliqueCandidateOK(stem + nomSuf)
}

// fioObliqueCandidateOK reports whether the recovered nominative form is a
// surname: known to the dictionary or matching the surname morphology, and not
// a stop word, citizenship, city, country or one of the short list of
// addresses and job titles.
func fioObliqueCandidateOK(nom string) bool {
	if dict.IsStopWord(nom) || dict.IsCitizenship(nom) || dict.IsCity(nom) || dict.IsCountry(nom) {
		return false
	}
	if _, bad := fioObliqueBad[nom]; bad {
		return false
	}
	return dict.IsSurname(nom) || dict.LooksLikeSurname(nom)
}

// fioObliqueBad — обращения и должности, которые морфология фамилии могла бы
// вывести из косвенной формы («господину» → «господин»). Большинство уже
// стоп-слова или гражданства; этот короткий список страхует остальные.
var fioObliqueBad = fioSet([]string{
	"господин", "господина", "гражданин", "товарищ", "сударь", "мужчина", "мужчин", "коллег", "коллега",
})

// fioPatrNeighbourBad — обращения и служебные слова, которые не могут быть
// фамилией рядом с отчеством, даже если по форме похожи на неё.
var fioPatrNeighbourBad = fioSet([]string{
	"уважаемый", "уважаемая", "уважаемые", "дорогой", "дорогая", "дорогие",
	"господин", "господину", "госпожа", "гражданин", "гражданину", "гражданка",
	"товарищ", "коллега", "коллеги", "директору",
	"клиент", "клиентка", "клиенту", "клиентке", "заёмщик", "заемщик",
	"спасибо", "здравствуйте", "привет", "добрый", "доброе", "добрая",
	"скажу", "пригласи",
})

// fioPatrNeighbourSurname reports whether c, sitting next to a patronymic, is
// accepted as a surname even though its ending does not look like a surname.
// The patronymic is strong evidence, so a capitalised (or case-blind) word that
// is not a stop word, place name, address or verb-like form is taken as the
// surname, provided it agrees in case with the patronymic.
func fioPatrNeighbourSurname(ctx *Context, c fioComp, cs fioCase, fem int) bool {
	if !fioCaseBlind(ctx) && !text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	if fioRunes(c.lower) < 2 || !fioCyrillicWord(c.lower) {
		return false
	}
	if dict.IsStopWord(c.lower) || c.cls&(fioClsFirst|fioClsPatr) != 0 {
		return false
	}
	if dict.IsCity(c.lower) || dict.IsCityForm(c.lower) || dict.IsCountry(c.lower) || dict.IsCitizenship(c.lower) {
		return false
	}
	if _, bad := fioPatrNeighbourBad[c.lower]; bad {
		return false
	}
	if fioPatrNeighbourVerbLike(ctx, c) {
		return false
	}
	return fioAgreesWithCase(c.lower, cs, fem)
}

// fioPatrNeighbourVerbLike reports whether c, not a dictionary surname, looks
// like a verb form and so must not be taken as a surname next to a patronymic.
// Both the oblique-verb endings and the bare imperative «ь» (excluding surnames
// on «-арь»/«-ярь») are rejected.
func fioPatrNeighbourVerbLike(ctx *Context, c fioComp) bool {
	if c.cls&fioClsSurname != 0 || fioObliqueAnyCase(ctx, c) {
		return false
	}
	if fioVerbLike(c.lower) {
		return true
	}
	return fioRunes(c.lower) >= 4 && fioNameForms(c.lower) == 0 && fioImperativeLikeNotAry(c.lower)
}

// fioAgreesWithCase reports whether the word w, taken as a surname, agrees in
// case with the case set cs and gender fem derived from the neighbouring
// patronymic. The nominative accepts any word; indeclinable endings and
// feminine surnames on a consonant or «ь» are accepted in any case; otherwise
// the ending must match one of the endings of the derived case.
func fioAgreesWithCase(w string, cs fioCase, fem int) bool {
	if cs&fioCaseNom != 0 {
		return true
	}
	for _, suf := range []string{"ко", "енко", "их", "ых", "дзе", "швили", "ян", "аго", "яго"} {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	last := []rune(w)[len([]rune(w))-1]
	if last == 'ь' || last < 'а' || last > 'я' {
		if fem == 1 {
			return true
		}
	}
	if fem == 0 {
		switch {
		case cs&(fioCaseGen|fioCaseAcc) != 0:
			return fioEndsAny(w, "а", "я", "ого", "его")
		case cs&fioCaseDat != 0:
			return fioEndsAny(w, "у", "ю", "ому", "ему")
		case cs&fioCaseIns != 0:
			return fioEndsAny(w, "ом", "ем", "ём", "ым", "им")
		case cs&fioCasePre != 0:
			return fioEndsAny(w, "е", "ом", "ем")
		}
		return false
	}
	switch {
	case cs&fioCaseAcc != 0:
		return fioEndsAny(w, "у", "ю", "ую")
	default:
		return fioEndsAny(w, "ой", "ей")
	}
}

// fioEndsAny reports whether w ends with any of the given suffixes.
func fioEndsAny(w string, sufs ...string) bool {
	for _, s := range sufs {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}

// fioVerbLike reports whether w ends like a verb form. Surnames that are
// already recognised as oblique or dictionary surnames are exempt, so forms
// like «Перешеина» or «Ковалёв» are not cut off.
func fioVerbLike(w string) bool {
	for _, suf := range []string{"ть", "те", "ите", "йте", "ешь", "ишь", "ет", "ит", "ют", "ят", "ла", "ли", "ло", "л"} {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	return false
}

// fioImperativeLike reports whether w ends like an imperative verb form. It is
// used only to strip a leading verb from a value run at the start of a
// sentence («Отправь Анне Залуцкой», «Позвони Перешеину Илье»). The bare
// endings «ь» and «й» are unambiguous imperatives; the «и»-based endings
// («ни», «ри», «ди», ...) are only accepted when the word is not a dictionary
// name, so «Никита» and «Дмитрий» are never mistaken for verbs.
func fioImperativeLike(w string) bool {
	for _, suf := range []string{"ь", "й", "те", "йте", "ите"} {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	if fioNameForms(w) == 0 {
		for _, suf := range []string{"ни", "ри", "ди", "жи", "ши", "чи", "сти", "пиши"} {
			if strings.HasSuffix(w, suf) {
				return true
			}
		}
		if fioImperativeIEnding(w) {
			return true
		}
	}
	return false
}

// fioImperativeIEnding reports whether w ends in one of the «и»-based
// imperative endings. It is only accepted for words of at least five runes
// that are not dictionary names and not surnames on «-швили», so «Попроси»,
// «Верни» and «Позвони» are stripped while «Никита», «Дмитрий» and
// «Джанашвили» are never mistaken for verbs.
func fioImperativeIEnding(w string) bool {
	if fioRunes(w) < 5 || strings.HasSuffix(w, "швили") {
		return false
	}
	for _, suf := range []string{"си", "зи", "ни", "ри", "ди", "ти", "ви", "ми", "жи", "ши", "чи"} {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	return false
}

// fioImperativeLikeNotAry reports whether w ends in the bare imperative «ь»,
// excluding surnames on «-арь»/«-ярь» (Бондарь, Пономарь, Косарь), whose «ь»
// ending is not an imperative. The «й» ending is deliberately not treated as an
// imperative here, since it is common in surnames («Задорожный»).
func fioImperativeLikeNotAry(w string) bool {
	if strings.HasSuffix(w, "арь") || strings.HasSuffix(w, "ярь") {
		return false
	}
	return strings.HasSuffix(w, "ь")
}

// fioObliqueComponent reports whether c is a capitalised oblique surname in the
// case and gender derived from the neighbouring patronymic.
func fioObliqueComponent(ctx *Context, c fioComp, cs fioCase, fem int) bool {
	if !fioCaseBlind(ctx) && !text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	return fioObliqueSurname(c.lower, cs, fem)
}

// fioObliqueAnyCase reports whether c is a capitalised oblique surname in any
// case and either gender. Used by the initials rules, where the initials are
// strong evidence on their own.
func fioObliqueAnyCase(ctx *Context, c fioComp) bool {
	if !fioCaseBlind(ctx) && !text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	return fioObliqueSurname(c.lower, fioCaseAll, 0) || fioObliqueSurname(c.lower, fioCaseAll, 1)
}

// fioSurnameOrOblique reports whether c is a dictionary surname or a
// capitalised oblique surname in any case. Used by the surname-then-initials
// branch.
func fioSurnameOrOblique(ctx *Context, c fioComp) bool {
	return c.cls&fioClsSurname != 0 || fioObliqueAnyCase(ctx, c) || fioShapeSurnameExtComp(ctx, c)
}

// fioInitialsPreposition — предлоги, которые не могут быть фамилией перед
// инициалами, даже если по форме похожи на неё. Сравнение идёт по нижнему
// регистру, поэтому заглавные формы в тексте ВЕРХНИМ регистром покрыты.
var fioInitialsPreposition = fioSet([]string{
	"от", "для", "у", "с", "к", "о", "об", "по", "при", "на", "в", "за", "до",
})

// fioSurnameBeforeInitials reports whether c can be a surname standing BEFORE
// two initials («Ткач Л.А.»). Unlike the word after the initials, the word
// before them is held to the strict surname checks: a dictionary/oblique
// surname, an extended surname shape, or a consonant surname next to a given
// name. A verb, imperative, stop word or preposition is never accepted, so
// «Позвони И. С.» is not read as a surname followed by initials.
func fioSurnameBeforeInitials(ctx *Context, c fioComp) bool {
	return fioSurnameClassOK(ctx, c) || fioObliqueAnyCase(ctx, c) ||
		fioShapeSurnameExtComp(ctx, c) || fioShapeSurnameConsonant(ctx, c)
}

// fioLooseBeforeInitials reports whether c, a word the surname checks do not
// confirm, may still be the surname in front of TWO initials («Ткача Л. А.»).
// Only the capital letter vouches for it, so it must be a capitalised word in a
// text that carries case, not the first word of a sentence (where «Позвони» is
// capitalised anyway), and not a verb, imperative, stop word or preposition.
// fioTrySurnameInitials additionally demands exactly two initials after it.
func fioLooseBeforeInitials(ctx *Context, c fioComp) bool {
	if !fioInitialsSurname(ctx, c) || fioValueAtSentenceStart(ctx, c.tok) {
		return false
	}
	if fioVerbLike(c.lower) || fioImperativeLike(c.lower) {
		return false
	}
	_, prep := fioInitialsPreposition[c.lower]
	return !prep
}

// fioInitialsSurnameReject reports whether c, standing after two initials, must
// not be taken as a surname: it ends in a common noun suffix («Назначение»,
// «Сумма») or is immediately followed by a field-label colon.
func fioInitialsSurnameReject(ctx *Context, c fioComp) bool {
	for _, suf := range []string{"ние", "тие", "ство", "ция", "сть"} {
		if strings.HasSuffix(c.lower, suf) {
			return true
		}
	}
	j := c.lastTok + 1
	for j < len(ctx.Tokens) && ctx.Tokens[j].Kind == text.KindSpace {
		j++
	}
	if j < len(ctx.Tokens) && ctx.Tokens[j].Kind == text.KindPunct &&
		ctx.Text[ctx.Tokens[j].Start:ctx.Tokens[j].End] == ":" {
		return true
	}
	return false
}

// fioSurnameAfterInitials reports whether c can be a surname standing AFTER two
// initials («И. О. Ткач»). Two initials are strong evidence on their own, so a
// capitalised Cyrillic word that is not a stop word, city or country is taken
// as the surname even when the dictionary and morphology both miss it.
func fioSurnameAfterInitials(ctx *Context, c fioComp) bool {
	if fioInitialsSurnameReject(ctx, c) {
		return false
	}
	if fioSurnameClassOK(ctx, c) || fioObliqueAnyCase(ctx, c) || fioShapeSurnameExtComp(ctx, c) {
		return true
	}
	return fioInitialsSurname(ctx, c)
}

// fioCommonAdj — основы частых прилагательных, которые по форме похожи на
// фамилии-прилагательные, но в сильных контекстах не должны приниматься за
// фамилию («Клиент Новый», «Анна Главная»).
var fioCommonAdj = fioSet([]string{
	"нов", "стар", "больш", "мал", "добр", "хорош", "плох", "главн", "основн",
	"нуж", "важн", "перв", "втор", "трет", "последн", "следующ", "русск",
	"московск", "российск", "банковск", "личн", "государствен",
	"уважаем", "дорог",
})

// fioShapeAdjEndings — окончания фамилий-прилагательных в любом падеже.
var fioShapeAdjEndings = []string{"ый", "ий", "ой", "ая", "ого", "ому", "ым", "им", "ом", "ую"}

// fioShapeAryEndings — окончания фамилий на «-арь»/«-ярь» в любом падеже.
var fioShapeAryEndings = []string{"арь", "ярь", "аря", "арю", "арем", "аре", "ярю", "ярем"}

// fioShapeSurnameExt reports whether w is an "extended surname shape": a word
// that is not a dictionary name, stop word or place name but ends like an
// adjective surname or a surname on «-арь»/«-ярь». It is used only in strong
// contexts (a dictionary given name, initials, or a strong client anchor),
// where the surrounding evidence outweighs the missing dictionary entry.
func fioShapeSurnameExt(w string) bool {
	if fioRunes(w) < 5 {
		return false
	}
	if dict.IsStopWord(w) || dict.IsCity(w) || dict.IsCountry(w) || dict.IsCitizenship(w) {
		return false
	}
	if dict.IsFirstName(w) {
		return false
	}
	return fioShapeAdjSurname(w) || fioShapeArySurname(w)
}

// fioShapeSurnameExtComp reports whether c is a capitalised (or case-blind)
// word that passes fioShapeSurnameExt. Used at the strong-context call sites.
func fioShapeSurnameExtComp(ctx *Context, c fioComp) bool {
	if !fioCaseBlind(ctx) && !text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	return fioShapeSurnameExt(c.lower)
}

// fioInitialsSurname reports whether c can be a surname standing next to TWO
// initials. The initials are strong evidence on their own, so a capitalised
// Cyrillic word of at least two runes that is not a stop word, city or country
// is taken as the surname even when the dictionary and morphology both miss it
// («Л.А. Ткач», «Ткач Л.А.»).
func fioInitialsSurname(ctx *Context, c fioComp) bool {
	// The capital letter is the whole evidence here. A text written entirely in
	// lower or upper case carries none, and «открыл», «ПОДАЛ» or «за» after the
	// initials would otherwise be swallowed as a surname.
	if fioNoCaseSignal(ctx) || !text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	if fioRunes(c.lower) < 2 || !fioCyrillicWord(c.lower) {
		return false
	}
	if dict.IsStopWord(c.lower) || dict.IsCity(c.lower) || dict.IsCountry(c.lower) {
		return false
	}
	return true
}

// fioShapeSurnameConsonant reports whether c is a capitalised (or case-blind)
// word of at least four runes that ends in a consonant or «ь» and is not a stop
// word, place name, citizenship, organisation word, verb or imperative, and is
// not the first word of a sentence. Next to a dictionary given name it is taken
// as a surname («Лев Ткач», «Ткач Лев»).
func fioShapeSurnameConsonant(ctx *Context, c fioComp) bool {
	// The capital letter is the only evidence that a consonant word is a
	// surname. In a payload written entirely in upper or lower case there is no
	// such signal, so «ПОДПИСАН»/«подписан» must not be read as a surname.
	if fioNoCaseSignal(ctx) || !text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	if fioRunes(c.lower) < 4 {
		return false
	}
	if dict.IsStopWord(c.lower) || dict.IsCity(c.lower) || dict.IsCountry(c.lower) ||
		dict.IsCitizenship(c.lower) || dict.IsOrgWord(c.lower) {
		return false
	}
	if fioVerbLike(c.lower) || fioImperativeLike(c.lower) {
		return false
	}
	if fioValueAtSentenceStart(ctx, c.tok) {
		return false
	}
	if fioNameForms(c.lower)&(dict.NameFirst|dict.NamePatronymic) != 0 {
		return false
	}
	return fioConsonantSurnameForm(c.lower)
}

// fioConsonantSurnameForm reports whether w ends like a surname on a consonant
// in any case: the bare form («Ткач», «Коваль») or that form plus a one-letter
// case ending («Ткача», «Ткачу», «Ткаче», «Коваля», «Ковалю»). The instrumental
// «Ткачом»/«Ковалем» already ends in a consonant. The stem must keep at least
// three runes, so short words («Лес» → «Леса») are not cut down to nothing.
func fioConsonantSurnameForm(w string) bool {
	r := []rune(w)
	last := r[len(r)-1]
	if last == 'ь' || fioIsConsonantRune(last) {
		return true
	}
	switch last {
	case 'а', 'у', 'е', 'я', 'ю':
		return len(r) >= 4 && fioIsConsonantRune(r[len(r)-2])
	}
	return false
}

// fioIsConsonantRune reports whether r is a lower-case Cyrillic consonant.
func fioIsConsonantRune(r rune) bool {
	switch r {
	case 'а', 'е', 'ё', 'и', 'о', 'у', 'ы', 'э', 'ю', 'я', 'ь', 'ъ', 'й':
		return false
	}
	return r >= 'а' && r <= 'я'
}

// fioShapeAdjSurname reports whether w ends like an adjective surname whose
// stem ends in a consonant and is not a common adjective.
func fioShapeAdjSurname(w string) bool {
	for _, suf := range fioShapeAdjEndings {
		if !strings.HasSuffix(w, suf) {
			continue
		}
		stem := w[:len(w)-len(suf)]
		if !fioEndsConsonant(stem) {
			continue
		}
		if _, common := fioCommonAdj[stem]; common {
			return false
		}
		return true
	}
	return false
}

// fioShapeArySurname reports whether w ends like a surname on «-арь»/«-ярь».
func fioShapeArySurname(w string) bool {
	for _, suf := range fioShapeAryEndings {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	return false
}

// fioEndsConsonant reports whether s ends in a Cyrillic consonant.
func fioEndsConsonant(s string) bool {
	r := []rune(s)
	if len(r) == 0 {
		return false
	}
	last := r[len(r)-1]
	switch last {
	case 'а', 'е', 'ё', 'и', 'о', 'у', 'ы', 'э', 'ю', 'я', 'ь', 'ъ', 'й':
		return false
	}
	return last >= 'а' && last <= 'я'
}

// fioTryObliqueFull tries the three-component shapes where the surname is an
// oblique form not recognised by the dictionary: «X Имя Отчество» and
// «Имя Отчество X». The case and gender come from the neighbouring patronymic.
func fioTryObliqueFull(ctx *Context, cls []fioClass, c1, c2, c3 fioComp) (fioMatch, bool) {
	if c3.cls&fioClsPatr != 0 && c1.cls&fioClsSurname == 0 && fioLoose(cls, c2) {
		if cs, fem := fioCaseOfPatronymic(c3.lower); fioObliqueComponent(ctx, c1, cs, fem) || fioPatrNeighbourSurname(ctx, c1, cs, fem) {
			return fioMatch{start: c1.start, end: c3.end, lastTok: c3.lastTok,
				conf: fioConfFull, hint: "full", surname: c1.lower}, true
		}
	}
	if c2.cls&fioClsPatr != 0 && c3.cls&fioClsSurname == 0 && fioLoose(cls, c1) {
		if cs, fem := fioCaseOfPatronymic(c2.lower); fioObliqueComponent(ctx, c3, cs, fem) || fioPatrNeighbourSurname(ctx, c3, cs, fem) {
			return fioMatch{start: c1.start, end: c3.end, lastTok: c3.lastTok,
				conf: fioConfFull, hint: "full", surname: c3.lower}, true
		}
	}
	return fioMatch{}, false
}
