package detect

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"pdguard/internal/pd"
	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/text"
)

// fioDetector recognises Russian person names (pd.TypeFIO) and Latin
// card-holder names (pd.TypeCardHolder).
//
// The detector is intentionally asymmetric: multi-component names are matched
// on morphology alone, while a single word is only ever masked when a context
// anchor ("клиент", "на имя", "от") makes the reading unambiguous. A lone
// surname is the cheapest false positive on the span-distance metric — the
// initials strategy folds a ten-letter word into three bytes — so it is held
// to the strictest standard of all.
//
// The type carries no state, so the single registered instance is safe for
// concurrent use.
type fioDetector struct{}

// Name identifies the detector in logs and in Span.Src.
func (fioDetector) Name() string { return "fio" }

// Types lists what this detector can emit.
func (fioDetector) Types() []pd.Type { return []pd.Type{pd.TypeFIO, pd.TypeCardHolder} }

// Detect scans the payload for person names. Spans never overlap each other:
// after a hit the scan resumes past the last consumed token.
func (fioDetector) Detect(ctx *Context) []pd.Span {
	var out []pd.Span
	if ctx.Enabled == nil || ctx.Enabled(pd.TypeFIO) {
		out = fioScanRussian(ctx, out, fioCaseBlind(ctx))
	}
	if ctx.Enabled == nil || ctx.Enabled(pd.TypeCardHolder) {
		out = fioScanHolders(ctx, out)
	}
	if ctx.Enabled == nil || ctx.Enabled(pd.TypeFIO) || ctx.Enabled(pd.TypeCardHolder) {
		out = fioScanValues(ctx, out)
	}
	return out
}

// FamousMentionLeft reports whether a public figure is named in the same
// sentence, to the left of byte offset off. Существует потому, что вето
// публичных персон раньше жило целиком внутри FIO-детектора, из-за чего
// «Пушкин родился в Москве» возвращался с целым именем и замаскированным
// городом — собственный негативный пример ТЗ, сломанный в другом месте.
// Детекторы, чей якорь синтаксически привязан к человеку («родился в»,
// «уроженец»), обязаны спросить эту функцию перед выдачей спана. Просмотр
// останавливается на первом конце предложения, чтобы знаменитость из
// предыдущего предложения не прикрыла данные реального клиента.
func FamousMentionLeft(ctx *Context, off int) bool {
	i := sort.Search(len(ctx.Tokens), func(k int) bool { return ctx.Tokens[k].Start >= off }) - 1
	for ; i >= 0; i-- {
		t := ctx.Tokens[i]
		if t.End > off {
			continue
		}
		if off-t.Start > fioFamousMentionWindow {
			return false
		}
		if stop, result := fioFamousMentionToken(ctx, i, off); stop {
			return result
		}
	}
	return false
}

// fioFamousMentionToken applies the public-figure veto to a single token to the
// left of off. It returns (stop, result): when stop is true the scan must halt
// immediately with the given result.
func fioFamousMentionToken(ctx *Context, i, off int) (stop, result bool) {
	t := ctx.Tokens[i]
	switch t.Kind {
	case text.KindWord:
		if dict.IsFamousSurnameForm(ctx.Lower[t.Start:t.End]) {
			return true, true
		}
	case text.KindSpace:
		if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
			return true, false
		}
	case text.KindPunct:
		if strings.ContainsAny(t.In(ctx.Text), "!?;") {
			return true, false
		}
		if t.In(ctx.Text) == "." && !fioAbbrevDot(ctx, i) {
			return true, false
		}
	}
	return false, false
}

func init() {
	Register(fioDetector{})
	// Индекс словоформ имён, который читает этот детектор, разворачивается
	// при первом обращении и занимает около десяти миллисекунд. Оставленный
	// сам по себе, он приходится на первый пришедший запрос и виден как
	// всплеск задержки; построение в фоне на старте тратит это время, пока
	// никто не ждёт. Запрос, пришедший тем временем, просто блокируется на
	// том же sync.Once, как и заблокировался бы.
	go dict.WarmNames()
}

// Окна и зазоры измеряются в байтах и намеренно малы — метрика качества есть
// расстояние между спанами и эталонной маской, поэтому каждое ложное
// срабатывание стоит напрямую. Широкое окно контекста позволило бы якорю,
// стоящему за несколько предложений, санкционировать голую фамилию.
const (
	fioAnchorWindow = 40 // how far left an anchor word may sit, in bytes
	fioAnchorWords  = 4  // ... and how many words back
	fioNegWindow    = 56 // negative markers get a slightly wider reach
	fioNegWords     = 3
	fioHolderWindow = 120 // card-holder evidence may sit further away
	fioMaxGap       = 3   // max byte length of the whitespace between components
	fioMaxWideGap   = 24  // ... and of a table column or a single line break
	fioStrongWindow = 48
)

// fioStrongWindow: самая длинная фраза в fioStrongPhraseAnchor —
// "зарегистрирована на", 36 байт UTF-8; 48 оставляет место ровно для
// пробельного прогона перед именем и ни для чего больше — в этом и смысл:
// сильный якорь засчитывается, только если написан непосредственно перед
// именем.

// Полное трёхчастное имя практически однозначно; пара всё ещё требует
// подтверждения обеих половин; одиночная фамилия держится целиком на якоре
// и потому первой проигрывает разрешение пересечений.
const (
	fioConfFull        = 0.98
	fioConfInitials2   = 0.95
	fioConfInitials1   = 0.90
	fioConfInitialsAmb = 0.85
	fioConfPair        = 0.90
	fioConfPairLoose   = 0.80
	fioConfLone        = 0.75
	fioConfHolder      = 0.85
	fioConfHolderDic   = 0.95
)

// Конверты значения. Порог config-а для FIO и CARD_HOLDER — 0.70, поэтому
// самое слабое правило здесь стоит выше него, но ниже любой словарной формы,
// которую выдают ветви A–E.
const (
	fioConfStandalone = 0.93 // весь payload — одно значение
	fioConfLabel      = 0.88 // значение поля после «метка:»
	fioConfAnchored   = 0.82 // значение сразу за сильным ролевым якорем
	fioConfValueWeak  = 0.74 // тот же конверт, но свидетельство только регистр
)

// fioValueMaxAtoms — сколько атомов может содержать одно значение. Три:
// фамилия, имя, отчество, и ни одной части больше; четвёртое слово — это уже
// проза, а не поле формы.
const fioValueMaxAtoms = 3

// fioValueMaxBytes — предел длины значения. 96 байт = 48 кириллических букв:
// всё ещё меньше любого предложения корпуса, но с запасом для
// «Жан-Батист О'Коннор Д'Артаньянович» (63 байта).
const fioValueMaxBytes = 96

// fioValueSeps — разделители внутри составного атома. Дефис уже склеивает
// fioReadComponent; слэш и апостроф добавлены ТОЛЬКО здесь, чтобы не менять
// поведение ветвей A–E на всём остальном корпусе.
const fioValueSeps = "-/'\u2019"

// fioSpaceCutset в исходном коде выглядит так (последний символ —
// неразрывный пробел U+00A0, которым полны вставленные из форм данные).
// Побайтно этот литерал равен 0x20 0x09 0x0D 0x0A 0xC2 0xA0. Невидимый
// последний символ критичен: без него суффиксный тест сильных якорей
// ломается на данных, вставленных из форм.
const fioSpaceCutset = " \t\r\n\u00a0"

// fioFamousMentionWindow: 200 байт — примерно полтора предложения кириллицы,
// что покрывает «Александр Сергеевич Пушкин родился в ...», но не позволяет
// знаменитости, названной двумя предложениями раньше, за что-либо ручаться.
const fioFamousMentionWindow = 200

// fioClsAnySurname matches both ways a word can be read as a surname. The
// toponym reading is deliberately NOT part of fioClsSurname: only the rules
// that demand a personal-data anchor directly in front may use it.
const fioClsAnySurname = fioClsSurname | fioClsToponymSurname

// fioMatch is a pattern hit that still has to pass the negative rules.
type fioMatch struct {
	start, end int
	lastTok    int
	conf       float64
	hint       string
	// surname is the lowercased surname component, used by the public-figure
	// veto. Empty when the pattern has no surname (name + patronymic).
	surname string
	// standalone marks a value envelope (R1) whose whole payload is one name.
	// It lets the public-figure veto be lifted only when the surname is a
	// dictionary surname, so «Салтыков-Щедрин» masks but «Пушкин» does not.
	standalone bool
}

// fioComp is one name component: a word, possibly a hyphenated compound such
// as "Петров-Водкин", which the tokenizer hands us as word '-' word.
type fioComp struct {
	start, end int
	tok        int // index of the first token, i.e. the cache slot
	lastTok    int
	lower      string
	cls        fioClass
}

// fioClass is the cached verdict for the component starting at a token. Each
// question is a done/answer bit pair so that the expensive ones can be left
// unanswered until a rule actually asks.
type fioClass uint16

const (
	fioClsDone fioClass = 1 << iota
	fioClsFirst
	fioClsPatr
	fioClsSurname
	fioClsStop
	fioClsLooseDone
	fioClsLoose
	fioClsCyrDone
	fioClsCyr
	fioClsToponymSurname
)

// fioCaseBlind reports whether the payload carries no capitalisation signal at
// all. Чат-сообщение или отсканированная форма, набранные целиком в нижнем
// регистре, не предлагают заглавной буквы, по которой можно судить об
// одиночной фамилии; настаивать на ней там значило бы потерять каждое имя в
// тексте, и единственным свидетельством остаётся якорь — ровно то, чего
// ветка E и так требует. Решается один раз на запрос, и сравнение строк
// останавливается на первой заглавной букве, так что обычный смешанный текст
// платит несколько байт.
func fioCaseBlind(ctx *Context) bool { return ctx.CaseBlind }

func fioScanRussian(ctx *Context, out []pd.Span, caseBlind bool) []pd.Span {
	toks := ctx.Tokens
	cls := make([]fioClass, len(toks))
	for i := 0; i < len(toks); i++ {
		if toks[i].Kind != text.KindWord {
			continue
		}
		m, ok := fioTryMatch(ctx, cls, i, caseBlind)
		if !ok {
			continue
		}
		if fioVetoed(ctx, i, m) {
			i = m.lastTok
			continue
		}
		out = append(out, pd.Span{
			Start: m.start,
			End:   m.end,
			Type:  pd.TypeFIO,
			Conf:  m.conf,
			Src:   "fio",
			Hint:  m.hint,
		})
		i = m.lastTok
	}
	return out
}

// fioTryMatch tries every name shape at token i, longest first, so that
// "Иванов Иван Иванович" is never reported as the shorter "Иванов Иван".
func fioTryMatch(ctx *Context, cls []fioClass, i int, caseBlind bool) (fioMatch, bool) {
	// Ветвь A. Инициалы перед фамилией: «И.И. Иванов», «И. И. Иванов».
	if m, ok := fioTryInitialsBefore(ctx, cls, i); ok {
		return m, true
	}

	c1, ok := fioReadComponent(ctx, cls, i)
	if !ok || (c1.cls&fioClsStop != 0 && !fioStopSurnameComp(ctx, c1)) {
		return fioMatch{}, false
	}

	c2, c3, c2ok, c3ok := fioReadComponents(ctx, cls, c1)

	// Ветвь B. Три компонента.
	if c3ok {
		if m, ok := fioTryThreeComponents(ctx, cls, c1, c2, c3); ok {
			return m, true
		}
	}

	// Ветвь C. Фамилия, за которой идут инициалы: «Иванов И.И.».
	if m, ok := fioTryBranchC(ctx, cls, c1); ok {
		return m, true
	}

	// Ветвь D. Два компонента.
	if c2ok {
		if m, ok := fioTryTwoComponents(ctx, cls, i, c1, c2, caseBlind); ok {
			return m, true
		}
	}

	// Ветвь E. Одиночная фамилия.
	if m, ok := fioTryLoneSurname(ctx, i, c1, caseBlind); ok {
		return m, true
	}
	return fioMatch{}, false
}

// fioReadComponents reads the second and third name components after c1.
func fioReadComponents(ctx *Context, cls []fioClass, c1 fioComp) (c2, c3 fioComp, c2ok, c3ok bool) {
	if j, sp := fioNextWordTok(ctx, c1.lastTok); sp {
		c2, c2ok = fioReadComponent(ctx, cls, j)
	}
	if c2ok && c2.cls&fioClsStop != 0 && !fioStopSurnameComp(ctx, c2) {
		c2ok = false
	}
	if c2ok {
		if j, sp := fioNextWordTok(ctx, c2.lastTok); sp {
			c3, c3ok = fioReadComponent(ctx, cls, j)
		}
		if c3ok && c3.cls&fioClsStop != 0 && !fioStopSurnameComp(ctx, c3) {
			c3ok = false
		}
	}
	return c2, c3, c2ok, c3ok
}

// fioTryInitialsBefore tries the initials-before-surname shape (branch A).
func fioTryInitialsBefore(ctx *Context, cls []fioClass, i int) (fioMatch, bool) {
	n, iniLast, _, amb := fioReadInitials(ctx, i)
	if n == 0 && !amb {
		return fioMatch{}, false
	}
	j, ok := fioInitialsAfterTok(ctx, iniLast)
	if !ok {
		return fioMatch{}, false
	}
	c, ok := fioReadComponent(ctx, cls, j)
	if !ok {
		return fioMatch{}, false
	}
	if !fioSurnameClassOK(ctx, c) && !fioObliqueAnyCase(ctx, c) && !fioShapeSurnameExtComp(ctx, c) {
		// Two initials are strong evidence on their own: a short surname on a
		// consonant («Ткач») that the dictionary and morphology both miss is
		// still a surname when two initials stand in front of it.
		if n != 2 || fioInitialsSurnameReject(ctx, c) || !fioInitialsSurname(ctx, c) {
			return fioMatch{}, false
		}
	}
	if !amb {
		conf := fioConfInitials1
		if n == 2 {
			conf = fioConfInitials2
		}
		return fioMatch{
			start: ctx.Tokens[i].Start, end: c.end, lastTok: c.lastTok,
			conf: conf, hint: "surname_initials", surname: c.lower,
		}, true
	}
	if fioAmbiguousInitialOK(ctx, i, c) {
		return fioMatch{
			start: ctx.Tokens[i].Start, end: c.end, lastTok: c.lastTok,
			conf: fioConfInitialsAmb, hint: "surname_initials", surname: c.lower,
		}, true
	}
	return fioMatch{}, false
}

// fioInitialsAfterTok returns the token index of the word following the
// initials, handling the case where the surname is glued to the last initial
// («И.С.Перешеин» — после точки второго инициала сразу, без пробела, идёт
// слово с заглавной).
func fioInitialsAfterTok(ctx *Context, iniLast int) (int, bool) {
	if j, ok := fioNextWordTok(ctx, iniLast); ok {
		return j, true
	}
	if iniLast+1 < len(ctx.Tokens) && ctx.Tokens[iniLast+1].Kind == text.KindWord &&
		ctx.Tokens[iniLast+1].Start == ctx.Tokens[iniLast].End &&
		text.IsUpperFirst(ctx.Text[ctx.Tokens[iniLast+1].Start:ctx.Tokens[iniLast+1].End]) {
		return iniLast + 1, true
	}
	return 0, false
}

// fioTryThreeComponents tries the three-component shape (branch B).
func fioTryThreeComponents(ctx *Context, cls []fioClass, c1, c2, c3 fioComp) (fioMatch, bool) {
	if c3.cls&fioClsPatr != 0 && c1.cls&fioClsSurname != 0 && fioSurnameCompOK(ctx, c1) && fioLoose(cls, c2) {
		return fioMatch{start: c1.start, end: c3.end, lastTok: c3.lastTok,
			conf: fioConfFull, hint: "full", surname: c1.lower}, true
	}
	if c2.cls&fioClsPatr != 0 && c3.cls&fioClsSurname != 0 && fioSurnameCompOK(ctx, c3) && fioLoose(cls, c1) {
		return fioMatch{start: c1.start, end: c3.end, lastTok: c3.lastTok,
			conf: fioConfFull, hint: "full", surname: c3.lower}, true
	}
	// «Имя Фамилия Отчество»: имя открывает тройку, фамилия стоит в середине,
	// отчество замыкает. Два существующих правила покрывают «Фамилия Имя
	// Отчество» и «Имя Отчество Фамилия», но не этот порядок, из-за чего
	// отчество оставалось открытым.
	if c1.cls&fioClsFirst != 0 && c2.cls&fioClsSurname != 0 && fioSurnameCompOK(ctx, c2) && c3.cls&fioClsPatr != 0 {
		return fioMatch{start: c1.start, end: c3.end, lastTok: c3.lastTok,
			conf: fioConfFull, hint: "full", surname: c2.lower}, true
	}
	// «X Имя Отчество» и «Имя Отчество X» с косвенной формой фамилии.
	if m, ok := fioTryObliqueFull(ctx, cls, c1, c2, c3); ok {
		return m, true
	}
	return fioMatch{}, false
}

// fioSurnameCompOK reports whether a surname component is acceptable given the
// case context. In a mixed-case text a surname without a capital letter is only
// accepted when the dictionary knows it as a surname; the morphological ending
// alone is not enough, so «коротко» after «Тимофее Степановиче» is not read as
// a surname.
func fioSurnameCompOK(ctx *Context, c fioComp) bool {
	if fioCaseBlind(ctx) || text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return true
	}
	return fioNameForms(c.lower)&dict.NameSurname != 0
}

// fioSurnameClassOK reports whether c carries the surname class AND the case
// context allows it: an ending such as «-ко» makes «коротко» look like a
// surname, but in a mixed-case text a surname guessed from its ending needs a
// capital letter.
func fioSurnameClassOK(ctx *Context, c fioComp) bool {
	return c.cls&fioClsSurname != 0 && fioSurnameCompOK(ctx, c)
}

// fioPairSurname reports whether c, standing next to a dictionary given name,
// is a surname the dictionary does not know: an oblique form, an adjective or
// «-арь» surname, a surname on a consonant, or a short one such as «Ли», «Цой».
func fioPairSurname(ctx *Context, c fioComp) bool {
	return fioObliqueAnyCase(ctx, c) || fioShapeSurnameExtComp(ctx, c) ||
		fioShapeSurnameConsonant(ctx, c) || fioShortSurnameComp(ctx, c)
}

// fioShortAnchoredSurname reports whether a dictionary surname shorter than
// four runes («Цой», «Ким») may stand alone: only right after a strong client
// anchor («г-жи Цой», «клиенту Ким») and only when written as a surname.
func fioShortAnchoredSurname(ctx *Context, i int, c fioComp) bool {
	return fioShortSurnameComp(ctx, c) && fioStrongClientAnchorLeft(ctx, i, c.start)
}

// fioTryBranchC tries branch C for c1. A word that only its capital letter
// vouches for as a surname («Ткача Л. А.») is accepted only in front of two
// initials.
func fioTryBranchC(ctx *Context, cls []fioClass, c1 fioComp) (fioMatch, bool) {
	strict := fioSurnameBeforeInitials(ctx, c1)
	if !strict && !fioLooseBeforeInitials(ctx, c1) {
		return fioMatch{}, false
	}
	return fioTrySurnameInitials(ctx, cls, c1, strict)
}

// fioTrySurnameInitials tries the surname-then-initials shape (branch C).
func fioTrySurnameInitials(ctx *Context, cls []fioClass, c1 fioComp, strict bool) (fioMatch, bool) {
	n, last, end := fioReadInitialsAfter(ctx, c1.lastTok)
	if n == 0 || (!strict && n != 2) {
		return fioMatch{}, false
	}
	// If the word right after the initials is itself a valid surname, the
	// initials belong to it (branch A), not to the word before them — unless
	// the word before is a confirmed surname and the one after is not a
	// dictionary surname: in «РАССКАЖИ О ЛИХАЧЁВЕ Т. С. КОРОТКО» the ending of
	// «КОРОТКО» must not take the initials away from «ЛИХАЧЁВЕ».
	if j, ok := fioInitialsAfterTok(ctx, last); ok {
		if c, ok := fioReadComponent(ctx, cls, j); ok && fioSurnameAfterInitials(ctx, c) &&
			(!strict || fioNameForms(c.lower)&dict.NameSurname != 0) {
			return fioMatch{}, false
		}
	}
	conf := fioConfInitials1
	if n == 2 {
		conf = fioConfInitials2
	}
	return fioMatch{start: c1.start, end: end, lastTok: last,
		conf: conf, hint: "surname_initials", surname: c1.lower}, true
}

// fioTryTwoComponents tries the two-component shape (branch D).
func fioTryTwoComponents(ctx *Context, cls []fioClass, i int, c1, c2 fioComp, caseBlind bool) (fioMatch, bool) {
	if c2.cls&fioClsPatr != 0 && fioLoose(cls, c1) {
		return fioMatch{start: c1.start, end: c2.end, lastTok: c2.lastTok,
			conf: fioConfPair, hint: "name_patronymic"}, true
	}
	if c1.cls&fioClsFirst != 0 && fioSurnameClassOK(ctx, c2) {
		return fioMatch{start: c1.start, end: c2.end, lastTok: c2.lastTok,
			conf: fioConfPair, hint: "surname_name", surname: c2.lower}, true
	}
	if fioSurnameClassOK(ctx, c1) && c2.cls&fioClsFirst != 0 {
		return fioMatch{start: c1.start, end: c2.end, lastTok: c2.lastTok,
			conf: fioConfPair, hint: "surname_name", surname: c1.lower}, true
	}
	if fioMorphPair(ctx, cls, i, c1, c2, caseBlind) {
		return fioMatch{start: c1.start, end: c2.end, lastTok: c2.lastTok,
			conf: fioConfPairLoose, hint: "surname_name", surname: c1.lower}, true
	}
	// «Фамилия Имя» и «Имя Фамилия» без отчества, где фамилия — косвенная
	// форма, которой нет в словаре. Имя обязательно словарное (fioClsFirst).
	if c1.cls&fioClsFirst != 0 && fioPairSurname(ctx, c2) {
		return fioMatch{start: c1.start, end: c2.end, lastTok: c2.lastTok,
			conf: fioConfPair, hint: "surname_name", surname: c2.lower}, true
	}
	if fioPairSurname(ctx, c1) && c2.cls&fioClsFirst != 0 {
		return fioMatch{start: c1.start, end: c2.end, lastTok: c2.lastTok,
			conf: fioConfPair, hint: "surname_name", surname: c1.lower}, true
	}
	return fioMatch{}, false
}

// fioTryLoneSurname tries the lone-surname shape (branch E).
func fioTryLoneSurname(ctx *Context, i int, c1 fioComp, caseBlind bool) (fioMatch, bool) {
	if c1.cls&fioClsAnySurname == 0 {
		// Косвенная фамилия, которой нет в словаре: принимается только рядом
		// с сильным клиентским якорем, который вводит субъекта данных.
		if !fioPairSurname(ctx, c1) || !fioStrongClientAnchorLeft(ctx, i, c1.start) {
			return fioMatch{}, false
		}
	} else if (fioRunes(c1.lower) < 4 && !fioShortAnchoredSurname(ctx, i, c1)) ||
		!fioLoneSurnameCaseOK(ctx, i, c1, caseBlind) ||
		fioToponymVetoed(ctx, i, c1.lower) ||
		!fioHasAnchor(ctx, i, c1.start) {
		return fioMatch{}, false
	}
	return fioMatch{start: c1.start, end: c1.end, lastTok: c1.lastTok,
		conf: fioConfLone, hint: "surname", surname: c1.lower}, true
}

// fioLoneSurnameCaseOK: строчный путь заменяет утраченное свидетельство двумя
// более строгими требованиями, а не ослабляет одно: сильный клиентский якорь
// стоит непосредственно перед словом, так что "от" и "для" этот путь вообще
// не открывают; слово — фамилия, которую знает СЛОВАРЬ, а не просто похожая
// по форме. Порядок конъюнктов: сначала словарь — он отвечает «нет» на любое
// обычное слово ценой одного хеша, тогда как якорный тест обходит токены и
// левое окно.
func fioLoneSurnameCaseOK(ctx *Context, tokIdx int, c fioComp, caseBlind bool) bool {
	if caseBlind || text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return true
	}
	return fioNameForms(c.lower)&dict.NameSurname != 0 &&
		fioStrongClientAnchorLeft(ctx, tokIdx, c.start)
}

// fioMorphPair — «Фамилия Имя», где имени нет в словаре. Три независимые
// гарантии требуются одновременно, а уверенность (fioConfPairLoose = 0.80)
// остаётся ниже любой словарной формы: второе слово с заглавной (несущее
// свидетельство, требуется безусловно), второе слово проходит «слабый» тест
// на имя, и рядом стоит якорь персональных данных.
func fioMorphPair(ctx *Context, cls []fioClass, tokIdx int, c1, c2 fioComp, caseBlind bool) bool {
	if caseBlind || c1.cls&fioClsAnySurname == 0 || fioRunes(c1.lower) < 4 {
		return false
	}
	if !text.IsUpperFirst(ctx.Text[c1.start:c1.end]) || !text.IsUpperFirst(ctx.Text[c2.start:c2.end]) {
		return false
	}
	if fioRunes(c2.lower) < 3 || dict.IsCityForm(c2.lower) ||
		dict.IsCountry(c2.lower) || dict.IsCitizenship(c2.lower) {
		return false
	}
	if !fioLoose(cls, c2) || fioToponymVetoed(ctx, tokIdx, c1.lower) {
		return false
	}
	return fioHasAnchor(ctx, tokIdx, c1.start)
}

// fioToponymVetoed: вето не абсолютно. «Киров», «Гагарин» и «Орёл» —
// одновременно города и совершенно обычные фамилии, и клиент, чья фамилия
// совпала с названием города, — ровно тот человек, чьи данные не должны
// утечь. Два прочтения разделяет смежность: якорь персональных данных,
// написанный непосредственно перед словом, вводит человека, тогда как адрес
// пишет там что-то другое и вето сохраняет.
func fioToponymVetoed(ctx *Context, tokIdx int, lower string) bool {
	if !dict.IsCity(lower) && !dict.IsCountry(lower) && !dict.IsCitizenship(lower) {
		return false
	}
	return !fioImmediateAnchor(ctx, tokIdx)
}

func fioImmediateAnchor(ctx *Context, tokIdx int) bool {
	w, ok := fioWordBefore(ctx, tokIdx)
	if !ok {
		return false
	}
	_, isAnchor := fioAnchor[w]
	return isAnchor
}

// fioAmbiguousInitialOK: «г. Пушкин» — город, «Г. Иванов» — человек, и
// различаются они лишь деталями, поэтому все три теста обязаны пройти вместе:
// буква написана ЗАГЛАВНОЙ, следующее слово — фамилия, известная СЛОВАРЮ, и
// не название места ни в какой падежной форме, и непосредственно слева нет
// ничего, что помещает фразу в адрес.
func fioAmbiguousInitialOK(ctx *Context, tokIdx int, c fioComp) bool {
	t := ctx.Tokens[tokIdx]
	if !text.IsUpperFirst(ctx.Text[t.Start:t.End]) {
		return false
	}
	if fioNameForms(c.lower)&dict.NameSurname == 0 {
		return false
	}
	if dict.IsCity(c.lower) || dict.IsCityForm(c.lower) || dict.IsFamousSurnameForm(c.lower) {
		return false
	}
	if w, ok := fioWordBefore(ctx, tokIdx); ok {
		if _, bad := fioGeoLeft[w]; bad {
			return false
		}
		if dict.IsStreetType(w) {
			return false
		}
	}
	return true
}

// fioClassify: три роли имени приходят из ОДНОГО словарного поиска. Ветвь
// fioClsToponymSurname — город, чьё имя одновременно обычная фамилия
// («Киров», «Клин», «Орёл»). dict.LooksLikeSurname отказывает им наотрез, что
// правильно для морфологии самой по себе и неправильно как окончательный
// ответ: клиент, разделивший имя с городом, не маскировался вовсе. Прочтение
// разрешает fioToponymVetoed, требующий якоря непосредственно перед словом,
// поэтому бит держится отдельно от fioClsSurname и на него смотрят только
// якорные правила.
func fioClassify(cls []fioClass, i int, lower string) fioClass {
	if c := cls[i]; c&fioClsDone != 0 {
		return c
	}
	c := fioClsDone
	if dict.IsStopWord(lower) {
		c |= fioClsStop
	}
	forms := fioNameForms(lower)
	if forms&dict.NameFirst != 0 {
		c |= fioClsFirst
	}
	if forms&dict.NamePatronymic != 0 {
		c |= fioClsPatr
	}
	switch {
	case forms&dict.NameSurname != 0,
		fioAnyPart(lower, fioLooksLikeSurname),
		strings.IndexByte(lower, '-') >= 0 && fioAnyPart(lower, fioInflectedStrongSurname):
		c |= fioClsSurname
	case c&fioClsStop == 0 && dict.SurnameShape(lower) && dict.IsCity(lower) &&
		!dict.IsFirstName(lower):
		c |= fioClsToponymSurname
	}
	cls[i] |= c
	return c
}

// fioLooksLikeSurname — это dict.LooksLikeSurname со своей дешёвой половиной
// впереди: три словарных поиска, которые делает та функция, стоят дороже
// теста окончания, решающего ответ почти для любого слова. Пара возвращает
// ровно то, что LooksLikeSurname возвращает сама по себе.
func fioLooksLikeSurname(w string) bool {
	return dict.SurnameShape(w) && dict.LooksLikeSurname(w)
}

func fioIsCyrillic(ctx *Context, cls []fioClass, i int) bool {
	v := cls[i]
	if v&fioClsCyrDone == 0 {
		v |= fioClsCyrDone
		t := ctx.Tokens[i]
		if fioCyrillicWord(ctx.Text[t.Start:t.End]) {
			v |= fioClsCyr
		}
		cls[i] = v
	}
	return v&fioClsCyr != 0
}

// fioCyrillicWord: ведущие байты 0xD0 и 0xD1 кодируют U+0400..U+047F —
// кириллические буквы и ничего больше, поэтому обычный случай не декодирует
// ни одной руны. Латинская ASCII-буква решает вопрос так же быстро в другую
// сторону. Всё остальное передаётся общему тесту text.IsCyrillicWord, так что
// вердикт идентичен.
func fioCyrillicWord(s string) bool {
	seen := false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case (c == 0xD0 || c == 0xD1) && i+1 < len(s):
			seen = true
			i += 2
		case c < utf8.RuneSelf:
			if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' {
				return false
			}
			i++
		default:
			return text.IsCyrillicWord(s)
		}
	}
	return seen
}

// fioNameForms: вопрос распространяется на каждую половину дефисного
// составного ровно так, как это делает fioAnyPart. Без аллокаций: половины —
// подстроки. Словарные формы хранятся через «е», поэтому слово с «ё»
// дополнительно проверяется и в форме с «е».
func fioNameForms(w string) dict.NameForm {
	f := fioNameFormsBase(w)
	if strings.ContainsRune(w, 'ё') {
		f |= fioNameFormsBase(strings.ReplaceAll(w, "ё", "е"))
	}
	return f
}

func fioNameFormsBase(w string) dict.NameForm {
	f := dict.NameForms(w)
	if strings.IndexByte(w, '-') < 0 {
		return f
	}
	rest := w
	for {
		k := strings.IndexByte(rest, '-')
		if k < 0 {
			if rest != w {
				f |= dict.NameForms(rest)
			}
			return f
		}
		f |= dict.NameForms(rest[:k])
		rest = rest[k+1:]
	}
}

// fioLoose: кэшируется отдельно от остальной классификации и вычисляется,
// только когда правило действительно спрашивает, потому что fioIsGivenLoose
// стоит дюжину словарных поисков, а судят по нему лишь слово, стоящее рядом с
// подтверждённым отчеством — или рядом с фамилией и якорем.
func fioLoose(cls []fioClass, c fioComp) bool {
	if c.cls&fioClsFirst != 0 {
		return true
	}
	v := cls[c.tok]
	if v&fioClsLooseDone == 0 {
		v |= fioClsLooseDone
		if fioIsGivenLoose(c.lower) {
			v |= fioClsLoose
		}
		cls[c.tok] = v
	}
	return v&fioClsLoose != 0
}

// fioReadComponent: условия склейки дефисного составного (все обязательны):
// дефис — отдельный токен KindPunct строго "-", приклеенный к предыдущему
// слову и к следующему, следующее — кириллическое слово длиной ≥ 2 рун. Класс
// кэшируется в слоте cls[i] (индекс первого токена) и вычисляется по lower
// всего составного.
func fioReadComponent(ctx *Context, cls []fioClass, i int) (fioComp, bool) {
	toks := ctx.Tokens
	if i >= len(toks) || toks[i].Kind != text.KindWord {
		return fioComp{}, false
	}
	t := toks[i]
	if !fioIsCyrillic(ctx, cls, i) {
		return fioComp{}, false
	}
	c := fioComp{start: t.Start, end: t.End, tok: i, lastTok: i}
	if i+2 < len(toks) {
		sep, nxt := toks[i+1], toks[i+2]
		if sep.Kind == text.KindPunct && sep.Start == t.End && ctx.Text[sep.Start:sep.End] == "-" &&
			nxt.Kind == text.KindWord && nxt.Start == sep.End &&
			fioIsCyrillic(ctx, cls, i+2) &&
			fioRunes(ctx.Text[nxt.Start:nxt.End]) >= 2 {
			c.end = nxt.End
			c.lastTok = i + 2
		}
	}
	c.lower = ctx.Lower[c.start:c.end]
	c.cls = fioClassify(cls, i, c.lower)
	return c, true
}

func fioNextWordTok(ctx *Context, lastTok int) (int, bool) {
	toks := ctx.Tokens
	if lastTok+2 >= len(toks) {
		return 0, false
	}
	if !fioIsNameGap(ctx, toks[lastTok+1]) {
		return 0, false
	}
	if toks[lastTok+2].Kind != text.KindWord {
		return 0, false
	}
	return lastTok + 2, true
}

// fioIsNameGap: запятая или тире заканчивают имя, а не продолжают его. Кроме
// обычного одиночного пробела принимается широкий прогон табличной колонки и
// один перевод строки. ПУСТАЯ строка остаётся стеной: два перевода строки
// разделяют записи, и пересечение такой границы приклеило бы фамилию одного
// человека к имени следующего. Байтовая граница fioMaxWideGap = 24 делает то
// же для прогона пробелов настолько широкого, что это может быть только
// вёрстка страницы.
func fioIsNameGap(ctx *Context, t text.Token) bool {
	if t.Kind != text.KindSpace || t.Len() > fioMaxWideGap {
		return false
	}
	if t.Len() == 1 {
		return true // the overwhelmingly common case: one plain space
	}
	return strings.Count(ctx.Text[t.Start:t.End], "\n") <= 1
}

// fioReadInitials: точка — часть имени, поэтому end — это dot.End. Между
// инициалами допускается пробельный прогон длиной ≤ fioMaxGap (3 байта).
// Русский полон точечных сокращений той же формы, что инициалы. «т.е. Иванов»
// не должно превращаться в замаскированное имя, поэтому пара-сокращение
// отвергается наотрез, а одиночная неоднозначная буква возвращается как
// таковая: count = 0, но lastTok/end заполнены и ambiguous = true.
func fioReadInitials(ctx *Context, i int) (count, lastTok, end int, ambiguous bool) {
	toks := ctx.Tokens
	if !fioStartsInitialRun(ctx, i) {
		return 0, 0, 0, false
	}
	var letters [2]string
	j := i
	for count < 2 {
		nj, ok := fioReadInitialOne(ctx, toks, j, &letters, count)
		if !ok {
			break
		}
		count++
		lastTok, end = nj-1, toks[nj-1].End
		j = nj
		if j < len(toks) && toks[j].Kind == text.KindSpace && toks[j].Len() <= fioMaxGap {
			j++
		}
	}
	switch count {
	case 1:
		if _, bad := fioAmbiguousInitial[letters[0]]; bad {
			return 0, lastTok, end, true
		}
	case 2:
		if _, bad := fioAbbrevPair[letters[0]+"."+letters[1]]; bad {
			return 0, 0, 0, false
		}
	}
	return count, lastTok, end, false
}

// fioReadInitialOne reads a single initial (one letter followed by a dot) at
// token j. On success it stores the lowercased letter in letters[count] and
// returns the index just past the dot; otherwise it returns j unchanged.
func fioReadInitialOne(ctx *Context, toks []text.Token, j int, letters *[2]string, count int) (int, bool) {
	if j+1 >= len(toks) {
		return j, false
	}
	w := toks[j]
	if w.Kind != text.KindWord {
		return j, false
	}
	s := ctx.Text[w.Start:w.End]
	if !fioOneRune(s) || !fioCyrillicWord(s) {
		return j, false
	}
	dot := toks[j+1]
	if dot.Kind != text.KindPunct || dot.Start != w.End || ctx.Text[dot.Start:dot.End] != "." {
		return j, false
	}
	letters[count] = ctx.Lower[w.Start:w.End]
	return j + 2, true
}

// fioStartsInitialRun: без этого отвергнутое сокращение «т.е.» было бы заново
// прочитано со второй буквы и «е. Иванов» замаскировалось бы как имя.
func fioStartsInitialRun(ctx *Context, i int) bool {
	toks := ctx.Tokens
	j := i - 1
	if j >= 0 && toks[j].Kind == text.KindSpace && toks[j].Len() <= fioMaxGap {
		j--
	}
	if j < 1 {
		return true
	}
	dot, prev := toks[j], toks[j-1]
	if dot.Kind != text.KindPunct || ctx.Text[dot.Start:dot.End] != "." {
		return true
	}
	return !(prev.Kind == text.KindWord && prev.End == dot.Start &&
		fioRunes(ctx.Text[prev.Start:prev.End]) == 1)
}

// fioReadInitialsAfter: неоднозначная одиночная буква здесь никогда не
// принимается (четвёртый результат отбрасывается, а count для неё равен 0):
// после фамилии она гораздо чаще единица измерения или сокращение. Зазор
// перед инициалами проверяется через fioIsNameGap.
func fioReadInitialsAfter(ctx *Context, lastTok int) (count, last, end int) {
	toks := ctx.Tokens
	if lastTok+2 >= len(toks) || !fioIsNameGap(ctx, toks[lastTok+1]) {
		return 0, 0, 0
	}
	n, l, e, _ := fioReadInitials(ctx, lastTok+2)
	return n, l, e
}

// fioInflectedStrongSurname — единственный морфологический путь, который всё
// ещё срезает окончания на пути запроса, потому что перечислить его заранее
// нельзя: он применяется только к дефисным составным, которых обычная проза
// не порождает.
func fioInflectedStrongSurname(p string) bool {
	for _, suf := range fioInflections {
		if !strings.HasSuffix(p, suf) {
			continue
		}
		stem := p[:len(p)-len(suf)]
		if fioRunes(stem) < 4 || dict.IsStopWord(stem) || dict.IsCity(stem) {
			continue
		}
		for _, strong := range fioStrongSurnameSuffixes {
			if strings.HasSuffix(stem, strong) {
				return true
			}
		}
	}
	return false
}

// fioStrongSurnameSuffixes — строгое подмножество того, что принимает
// dict.LooksLikeSurname. Несклоняемые "-ых"/"-их" и короткие "-ко"/"-ук"/"-ян"
// исключены именно потому, что срезание падежного окончания с обычного слова
// попадает на них случайно ("стихи" → "стих"), тогда как основы на
// "-ов"/"-ев"/"-ин"/"-ский" из обычной лексики так недостижимы.
var fioStrongSurnameSuffixes = []string{
	"ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "ская", "цкая",
}

// fioInflections: порядок значим (длинные раньше коротких). Срезание идёт по
// байтам: UTF-8 самосинхронизируется, поэтому совпадение суффикса не может
// разрубить руну пополам. Таблица зеркалит nameCaseEndings в
// internal/pd/dict/names.go, который порождает те же формы с другого конца;
// две таблицы обязаны держаться в согласии.
var fioInflections = []string{
	"ами", "ой", "ом", "ем", "ым", "ей", "ах", "ам", "ья",
	"а", "у", "е", "ы", "и", "ю", "я",
}

// fioIsGivenLoose: требовать здесь словарь значило бы потерять каждое
// неперечисленное имя, тогда как отчество держит точность: перечисленные
// исключения — это слова, которые ещё могли бы проскользнуть. Словарное
// попадание учитывается в fioClassify, поэтому здесь судятся только слова,
// которых словарь не знает.
func fioIsGivenLoose(w string) bool {
	if fioRunes(w) < 2 {
		return false
	}
	if dict.IsStopWord(w) || dict.IsCity(w) || dict.IsCountry(w) || dict.IsCitizenship(w) ||
		dict.IsOrgWord(w) || dict.IsIssuerWord(w) || dict.IsStreetType(w) {
		return false
	}
	if _, isMonth := dict.Month(w); isMonth {
		return false
	}
	if _, isAnchor := fioAnchor[w]; isAnchor {
		return false
	}
	if _, isNeg := fioNegContext[w]; isNeg {
		return false
	}
	if _, isOrg := fioLegalForm[w]; isOrg {
		return false
	}
	for _, suf := range fioAdjectiveEndings {
		if strings.HasSuffix(w, suf) {
			return false
		}
	}
	return true
}

// fioAdjectiveEndings: окончания, общие с настоящими именами ("-ий" как в
// Дмитрий, "-ей" как в Сергей), намеренно отсутствуют: их исключение отвергло
// бы целый класс подлинных личных имён, которых словарь может не содержать.
var fioAdjectiveEndings = []string{"ый", "ое", "ые", "ых", "ого", "ому", "ыми", "ую", "ою"}

// fioAnyPart применяет fn к целому слову и, для дефисного составного, к
// каждой половине; без аллокаций — половины являются подстроками.
func fioAnyPart(w string, fn func(string) bool) bool {
	if fn(w) {
		return true
	}
	rest := w
	for {
		k := strings.IndexByte(rest, '-')
		if k < 0 {
			return rest != w && fn(rest)
		}
		if fn(rest[:k]) {
			return true
		}
		rest = rest[k+1:]
	}
}

func fioRunes(s string) int { return utf8.RuneCountInString(s) }

// fioOneRune спрашивают о каждом слове payload (инициал — однобуквенное
// слово), и ограничение длины отвечает за все, кроме самых коротких, поскольку
// ни одна руна не шире четырёх байт (utf8.UTFMax).
func fioOneRune(s string) bool {
	if len(s) == 0 || len(s) > utf8.UTFMax {
		return false
	}
	_, n := utf8.DecodeRuneInString(s)
	return n == len(s)
}

// fioHasAnchor: ограничения — не более fioAnchorWords = 4 слов назад и не
// дальше fioAnchorWindow = 40 байт (по start - t.Start). Многословные якоря
// дешевле проверять на сыром окне, чем пересобирать из токенов, — и они ищутся
// как подстрока (strings.Contains), в отличие от сильных якорей.
func fioHasAnchor(ctx *Context, tokIdx, start int) bool {
	words := 0
	for j := tokIdx - 1; j >= 0 && words < fioAnchorWords; j-- {
		t := ctx.Tokens[j]
		if start-t.Start > fioAnchorWindow {
			break
		}
		if t.Kind != text.KindWord {
			continue
		}
		words++
		if _, ok := fioAnchor[ctx.Lower[t.Start:t.End]]; ok {
			return true
		}
	}
	win := fioLeftWindow(ctx, start, fioAnchorWindow)
	for _, p := range fioPhraseAnchor {
		if strings.Contains(win, p) {
			return true
		}
	}
	return false
}

// fioVetoed: негативные правила выполняются после сопоставления, а не во
// время него, потому что они говорят об области вокруг имени, а не о самом
// имени. Вето публичной персоны — единственное, которое может перебить
// сильный клиентский якорь. Литературное и географическое вето остаётся
// абсолютным. Переопределение спрашивается ПОСЛЕДНИМ и только если вето
// знаменитости реально сработало.
func fioVetoed(ctx *Context, tokIdx int, m fioMatch) bool {
	if fioNegContextBefore(ctx, tokIdx, m.start) || fioOrgAdjacent(ctx, tokIdx, m.lastTok) {
		return true
	}
	if !fioFamous(ctx, tokIdx, m) {
		return false
	}
	return !(m.standalone && fioValueSurnameKnown(m) ||
		fioStrongClientAnchorLeft(ctx, tokIdx, m.start))
}

// fioValueSurnameKnown: хотя бы одна дефисная часть фамильного компонента
// значения есть в СЛОВАРЕ фамилий. Ровно этим «Салтыков-Щедрин» отличается
// от «Пушкин».
func fioValueSurnameKnown(m fioMatch) bool {
	return fioAnyPart(m.surname, func(p string) bool {
		return fioNameForms(p)&dict.NameSurname != 0
	})
}

// fioStrongClientAnchorLeft: сильный якорь — слово, которое может вводить
// только СУБЪЕКТА персональных данных: «клиент», «заёмщик», «поручитель»,
// «на имя», «ФИО». ТЗ требует, чтобы публичная фигура, упомянутая как
// публичная фигура, была оставлена в покое, и детектор реализует это вето по
// словарю известных имён. Но у банка есть клиенты по фамилии Толстой, Пушкин,
// Гагарин и Салтыков-Щедрин, и их данные — персональные данные ровно как у
// всех. Разводит два прочтения смежность: культурное упоминание ставит перед
// именем произведение, заглавие или место; банковский документ ставит там
// РОЛЬ человека. Слабые якоря исключены намеренно: «от», «для», «у» и «с»
// ничего не говорят о том, кто этот человек.
func fioStrongClientAnchorLeft(ctx *Context, tokIdx, start int) bool {
	if w, ok := fioWordBefore(ctx, tokIdx); ok {
		if _, yes := fioStrongAnchor[w]; yes {
			return true
		}
	}
	win := strings.TrimRight(fioLeftWindow(ctx, start, fioStrongWindow), fioSpaceCutset)
	for _, p := range fioStrongPhraseAnchor {
		if strings.HasSuffix(win, p) {
			return true
		}
	}
	return false
}

// fioNegContextBefore: окно шире якорного: fioNegWindow = 56 байт,
// fioNegWords = 3 слова.
func fioNegContextBefore(ctx *Context, tokIdx, start int) bool {
	words := 0
	for j := tokIdx - 1; j >= 0 && words < fioNegWords; j-- {
		t := ctx.Tokens[j]
		if start-t.Start > fioNegWindow {
			break
		}
		if t.Kind != text.KindWord {
			continue
		}
		words++
		if _, ok := fioNegContext[ctx.Lower[t.Start:t.End]]; ok {
			return true
		}
	}
	return false
}

// fioOrgAdjacent блокирует название компании, собранное из фамилии: «ООО
// Иванов и партнёры» — контрагент, а не клиент. Проверяются обе стороны
// совпадения.
func fioOrgAdjacent(ctx *Context, firstTok, lastTok int) bool {
	if w, ok := fioWordBefore(ctx, firstTok); ok && fioIsOrgMarker(w) {
		return true
	}
	if w, ok := fioWordAfter(ctx, lastTok); ok && fioIsOrgMarker(w) {
		return true
	}
	return false
}

func fioIsOrgMarker(w string) bool {
	if dict.IsOrgWord(w) {
		return true
	}
	_, ok := fioLegalForm[w]
	return ok
}

// fioWordBefore/fioWordAfter: ровно три токена просматриваются в каждую
// сторону; между якорем и именем допускаются только пробелы и пунктуация.
// KindNumber/KindAlnum прерывают поиск.
func fioWordBefore(ctx *Context, tokIdx int) (string, bool) {
	for j := tokIdx - 1; j >= 0 && j >= tokIdx-3; j-- {
		t := ctx.Tokens[j]
		if t.Kind == text.KindWord {
			return ctx.Lower[t.Start:t.End], true
		}
		if t.Kind != text.KindSpace && t.Kind != text.KindPunct {
			return "", false
		}
	}
	return "", false
}

func fioWordAfter(ctx *Context, tokIdx int) (string, bool) {
	for j := tokIdx + 1; j < len(ctx.Tokens) && j <= tokIdx+3; j++ {
		t := ctx.Tokens[j]
		if t.Kind == text.KindWord {
			return ctx.Lower[t.Start:t.End], true
		}
		if t.Kind != text.KindSpace && t.Kind != text.KindPunct {
			return "", false
		}
	}
	return "", false
}

// fioLeftWindow: начало левого окна может попасть внутрь руны; это может
// только заставить тест Contains промахнуться, но никогда — сработать
// ошибочно, потому что иглы поиска — корректный UTF-8.
func fioLeftWindow(ctx *Context, off, n int) string {
	lo := off - n
	if lo < 0 {
		lo = 0
	}
	if off > len(ctx.Lower) {
		off = len(ctx.Lower)
	}
	return ctx.Lower[lo:off]
}

func fioRightWindow(ctx *Context, off, n int) string {
	hi := off + n
	if hi > len(ctx.Lower) {
		hi = len(ctx.Lower)
	}
	if off < 0 {
		off = 0
	}
	return ctx.Lower[off:hi]
}

// fioFamous: три теста, от самого специфичного к самому слабому. Буквальная
// фраза — и только для МНОГОСЛОВНОЙ. Та же фраза как МНОЖЕСТВО СЛОВ, потому
// что словарь хранит «имя отчество фамилия», а русский с той же лёгкостью
// пишет публичную фигуру как «фамилия имя отчество». Только фамилия — последний
// и условный: рядом с якорем персональных данных прочтение — клиент,
// разделивший фамилию со знаменитостью, и маскировать правильно.
func fioFamous(ctx *Context, tokIdx int, m fioMatch) bool {
	phrase := ctx.Lower[m.start:m.end]
	if strings.IndexByte(phrase, ' ') >= 0 && dict.IsFamousPerson(phrase) {
		return true
	}
	if fioFamousSet(ctx, m) {
		return true
	}
	if m.surname == "" {
		return false
	}
	if !fioAnyPart(m.surname, dict.IsFamousSurnameForm) {
		return false
	}
	// Фамилия, известная СЛОВАРЮ фамилий, — это скорее реальный клиент, чем
	// знаменитость: «Гарсия» (с «ия») морфологически выводится из «Гарсиа»
	// (с «иа»), но является обычной испанской фамилией. Полное имя
	// знаменитости всё равно ловится первыми двумя проверками, а фамилии
	// знаменитостей, совпадающие с обычными («Крылов»), в famousSurnameForms
	// не попадают вовсе.
	if fioValueSurnameKnown(m) {
		return false
	}
	return !fioHasAnchor(ctx, tokIdx, m.start)
}

// fioFamousSet: расширение окна дёшево, потому что fioFamousWords бросает
// работу на первом слове, которого список известных никогда не видел, — а это
// обычный случай.
func fioFamousSet(ctx *Context, m fioMatch) bool {
	if fioFamousWords(ctx.Lower[m.start:m.end]) {
		return true
	}
	if s, ok := fioWordStartBefore(ctx, m.start); ok && fioFamousWords(ctx.Lower[s:m.end]) {
		return true
	}
	if e, ok := fioWordEndAfter(ctx, m.lastTok); ok && fioFamousWords(ctx.Lower[m.start:e]) {
		return true
	}
	return false
}

// fioFamousWords: здесь ничего не аллоцируется — слова являются подстроками
// payload, массив, в который они пишутся, не убегает (buf — массив на стеке
// размера dict.FamousSetMaxWords == 4), а dict.FamousNameSet хеширует этот
// массив напрямую.
func fioFamousWords(phrase string) bool {
	var buf [dict.FamousSetMaxWords]string
	n, ok := fioSplitWords(phrase, buf[:])
	if !ok {
		return false
	}
	for k := 0; k < n; k++ {
		stem, ok := fioFamousStem(buf[k])
		if !ok {
			return false
		}
		buf[k] = stem
	}
	return dict.FamousNameSet(buf[:n])
}

// fioSplitWords — это strings.Fields без аллокации среза, возвращающий false,
// когда слов больше, чем помещается в buf.
func fioSplitWords(phrase string, buf []string) (int, bool) {
	n, start := 0, -1
	for i, r := range phrase {
		if unicode.IsSpace(r) {
			var ok bool
			if n, ok = fioSplitFlush(buf, n, phrase, start, i); !ok {
				return 0, false
			}
			start = -1
			continue
		}
		if start < 0 {
			start = i
		}
	}
	var ok bool
	if n, ok = fioSplitFlush(buf, n, phrase, start, len(phrase)); !ok {
		return 0, false
	}
	return n, true
}

// fioSplitFlush appends the pending word phrase[start:end] to buf, returning
// the new count and whether it fit. A negative start means no pending word.
func fioSplitFlush(buf []string, n int, phrase string, start, end int) (int, bool) {
	if start < 0 {
		return n, true
	}
	return fioSplitAddWord(buf, n, phrase, start, end)
}

// fioSplitAddWord appends phrase[start:end] to buf, reporting overflow.
func fioSplitAddWord(buf []string, n int, phrase string, start, end int) (int, bool) {
	if n == len(buf) {
		return 0, false
	}
	buf[n] = phrase[start:end]
	return n + 1, true
}

// fioFamousStem: набор обрезаемых символов — дословно ".,;:!?()«»\"".
func fioFamousStem(w string) (string, bool) {
	w = strings.Trim(w, ".,;:!?()«»\"")
	if w == "" {
		return "", false
	}
	return dict.FamousWordForm(w)
}

// fioWordStartBefore: ctx.TokenAt возвращает -1 для смещения, на котором токен
// не начинается; проверка i < 2 покрывает и этот случай, и начало текста.
func fioWordStartBefore(ctx *Context, off int) (int, bool) {
	i := ctx.TokenAt(off)
	if i < 2 {
		return 0, false
	}
	sp, w := ctx.Tokens[i-1], ctx.Tokens[i-2]
	if !fioIsNameGap(ctx, sp) || w.Kind != text.KindWord {
		return 0, false
	}
	return w.Start, true
}

func fioWordEndAfter(ctx *Context, lastTok int) (int, bool) {
	j, ok := fioNextWordTok(ctx, lastTok)
	if !ok {
		return 0, false
	}
	return ctx.Tokens[j].End, true
}

// fioAbbrevDot: точка завершает предложение, если только это не точка
// сокращения, т. е. приклеенная к короткому слову ("г.", "им."): условие —
// слово непосредственно слева (w.End == dot.Start) длиной ≤ 3 рун.
func fioAbbrevDot(ctx *Context, i int) bool {
	if i == 0 {
		return false
	}
	w := ctx.Tokens[i-1]
	return w.Kind == text.KindWord && w.End == ctx.Tokens[i].Start && fioRunes(w.In(ctx.Text)) <= 3
}

// fioCardDigitsRe matches a card-number-shaped digit group. Compiled once:
// compiling inside Detect would dominate the per-request cost at 1000 RPS.
var fioCardDigitsRe = regexp.MustCompile(`(?:\d{4}[ \-]?){3}\d{2,4}|\d{13,19}`)

// fioScanHolders: имя держателя — два или три латинских слова в капитале,
// минимум два «полных» слова, одиночная заглавная буква не может начать имя,
// средний инициал может нести точку, между словами допускается пробельный
// прогон ≤ fioMaxGap, «шумное» слово убивает кандидата целиком,
// организационный маркер рядом отменяет кандидата, якорь карты обязателен.
func fioScanHolders(ctx *Context, out []pd.Span) []pd.Span {
	toks := ctx.Tokens
	for i := 0; i < len(toks); i++ {
		if toks[i].Kind != text.KindWord || !fioStartsUpperLatin(ctx, toks[i]) {
			continue
		}
		start, end, last, parts, full, named, blocked := fioHolderRun(ctx, i)
		if blocked || parts < 2 || full < 2 {
			i = last
			continue
		}
		if fioOrgAdjacent(ctx, i, last) || !fioHolderAnchor(ctx, start, end) {
			i = last
			continue
		}
		conf := fioConfHolder
		if named {
			conf = fioConfHolderDic
		}
		out = append(out, pd.Span{
			Start: start, End: end, Type: pd.TypeCardHolder,
			Conf: conf, Src: "fio", Hint: "holder",
		})
		i = last
	}
	return out
}

// fioHolderRun reads a run of up to three Latin capitalised words starting at
// token i, returning the consumed span and the flags that decide acceptance.
func fioHolderRun(ctx *Context, i int) (start, end, last, parts, full int, named, blocked bool) {
	toks := ctx.Tokens
	start = toks[i].Start
	st := fioHolderState{end: toks[i].End, last: i}
	j := i
	for st.parts < 3 {
		nj, ok := fioHolderWord(ctx, toks, j, &st)
		if !ok {
			break
		}
		j = nj
	}
	return start, st.end, st.last, st.parts, st.full, st.named, st.blocked
}

// fioHolderState accumulates the state of a holder-name run.
type fioHolderState struct {
	end, last, parts, full int
	named, blocked         bool
}

// fioHolderWord reads one Latin capitalised word at token j into st. It
// returns the next token index and whether the run may continue.
func fioHolderWord(ctx *Context, toks []text.Token, j int, st *fioHolderState) (int, bool) {
	t := toks[j]
	if t.Kind != text.KindWord {
		return j, false
	}
	w := ctx.Text[t.Start:t.End]
	if !fioIsUpperLatin(w) {
		return j, false
	}
	lw := ctx.Lower[t.Start:t.End]
	if fioIsLatinNoise(lw) {
		st.blocked = true
		return j, false
	}
	n := fioRunes(w)
	if n == 1 && st.parts == 0 {
		return j, false // a stray capital letter is not the start of a name
	}
	if n > 1 {
		st.full++
	}
	if dict.IsLatinName(lw) {
		st.named = true
	}
	st.parts++
	st.end, st.last = t.End, j
	j = st.last + 1
	// A middle initial may carry a dot: "IVAN I. IVANOV".
	if n == 1 && j < len(toks) && toks[j].Kind == text.KindPunct &&
		toks[j].Start == t.End && ctx.Text[toks[j].Start:toks[j].End] == "." {
		st.end, st.last = toks[j].End, j
		j++
	}
	if j < len(toks) && toks[j].Kind == text.KindSpace && toks[j].Len() <= fioMaxGap {
		return j + 1, true
	}
	return j, false
}

// fioHolderAnchor: окно — fioHolderWindow = 120 байт в каждую сторону; сначала
// словарь-подстроки, затем (дороже) регулярное выражение.
func fioHolderAnchor(ctx *Context, start, end int) bool {
	left := fioLeftWindow(ctx, start, fioHolderWindow)
	right := fioRightWindow(ctx, end, fioHolderWindow)
	for _, a := range fioHolderAnchorWords {
		if strings.Contains(left, a) || strings.Contains(right, a) {
			return true
		}
	}
	return fioCardDigitsRe.MatchString(left) || fioCardDigitsRe.MatchString(right)
}

// fioStartsUpperLatin — предфильтр перед холдер-сканом: имя держателя пишется
// латинскими заглавными, поэтому токен, чей первый байт уже не ASCII или
// строчная буква, не может его начать — а это каждое слово русского payload.
func fioStartsUpperLatin(ctx *Context, t text.Token) bool {
	b := ctx.Text[t.Start]
	return b < utf8.RuneSelf && !('a' <= b && b <= 'z')
}

func fioIsUpperLatin(s string) bool {
	seen := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			if !unicode.Is(unicode.Latin, r) || !unicode.IsUpper(r) {
				return false
			}
			seen = true
		case unicode.IsDigit(r):
			return false
		}
	}
	return seen
}

func fioIsLatinNoise(lw string) bool {
	if dict.IsOrgWord(lw) {
		return true
	}
	_, ok := fioLatinNoise[lw]
	return ok
}

func fioSet(words []string) map[string]struct{} {
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}

// fioStrongAnchor: слова, называющие СУБЪЕКТА персональных данных и ничего
// иного. Каждая запись отвечает на вопрос «кем этот человек приходится
// банку?» — потому вето публичных персон им и уступает. Должности, описывающие
// сторону банка («менеджер», «кассир», «директор»), отсутствуют намеренно.
// Инвариант: fioStrongAnchor — строгое подмножество fioAnchor.
var fioStrongAnchor = fioSet([]string{
	"клиент", "клиента", "клиенту", "клиентом", "клиентка", "клиентки", "клиентке",
	"клиенте", "клиентку", "клиенткой",
	"заемщик", "заёмщик", "заемщика", "заёмщика", "заемщику", "заёмщику",
	"заемщиком", "заёмщиком", "заемщице", "заёмщице",
	"заемщике", "заёмщике", "заемщица", "заёмщица", "заемщицы", "заёмщицы",
	"созаемщик", "созаёмщик", "созаемщика", "созаёмщика",
	"заявитель", "заявителя", "заявителю", "заявителем", "заявительница",
	"заявителе",
	"плательщик", "плательщика", "плательщику", "плательщиком", "плательщике",
	"получатель", "получателя", "получателю", "получателем", "получателе",
	"отправитель", "отправителя", "отправителю", "отправителем", "отправителе",
	"владелец", "владельца", "владельцу", "владельцем", "владельце",
	"держатель", "держателя", "держателю", "держателем", "держательнице",
	"держателе", "держательница", "держательницы", "держательницу",
	"господин", "господина", "господину", "госпожа", "госпоже", "госпожи", "госпожу",
	"вкладчик", "вкладчика", "вкладчику", "вкладчиком", "вкладчике",
	"поручитель", "поручителя", "поручителю", "поручителем", "поручителе",
	"наследник", "наследника", "наследнику", "наследница", "наследницы",
	"наследнике",
	"гражданин", "гражданина", "гражданину", "гражданка", "гражданки", "гражданке",
	"гражданине",
	"пациент", "пациента", "пациенту", "пациентка", "пациенте",
	"абонент", "абонента", "абоненту", "абоненте",
	"сотрудник", "сотрудника", "сотруднику", "сотрудником", "сотруднике",
	"фио", "принадлежит",
	// Женские формы ролей во всех падежах: «заявительницы Зубаревой», «клиентке Цой».
	"заявительницы", "заявительнице", "заявительницу", "заявительницей",
	"получательница", "получательницы", "получательнице", "получательницу", "получательницей",
	"отправительница", "отправительницы", "отправительнице", "отправительницу", "отправительницей",
	"владелица", "владелицы", "владелице", "владелицу", "владелицей",
	"вкладчица", "вкладчицы", "вкладчице", "вкладчицу", "вкладчицей",
	"поручительница", "поручительницы", "поручительнице", "поручительницу", "поручительницей",
	"плательщица", "плательщицы", "плательщице", "плательщицу", "плательщицей",
	"наследнице", "наследницу", "наследницей",
	"пациентки", "пациентке", "пациентку", "пациенткой",
	"абонентка", "абонентки", "абонентке", "абонентку", "абоненткой",
	"сотрудница", "сотрудницы", "сотруднице", "сотрудницу", "сотрудницей",
})

// fioStrongPhraseAnchor: сильные якоря длиннее одного токена, сопоставляются
// как суффикс текста непосредственно слева от имени. «на имя» покрывает более
// длинные формы, перечисленные в ТЗ, потому что все они им заканчиваются.
// Точечная "ф.и.о." выписана явно, потому что токенизатор разбивает её на
// одиночные буквы и однословный поиск увидел бы только финальное "о".
var fioStrongPhraseAnchor = []string{
	"на имя", "ф.и.о.", "ф. и. о.", "ф.и.о", "ф. и. о",
	"доверенность на", "оформлен на", "оформлена на", "оформлено на",
	"зарегистрирован на", "зарегистрирована на", "выдан на", "выдана на",
	"г-н", "г-на", "г-ну", "г-жа", "г-жи", "г-же", "г-жу",
}

// fioAnchor: обычные якоря, достаточные для голой фамилии.
var fioAnchor = fioSet([]string{
	"клиент", "клиента", "клиенту", "клиентом", "клиентка", "клиентки", "клиентке",
	"клиенте", "клиентку", "клиенткой",
	"заявитель", "заявителя", "заявителю", "заявителем", "заявительница", "заявителе",
	"плательщик", "плательщика", "плательщику", "плательщиком", "плательщике",
	"получатель", "получателя", "получателю", "получателем", "получателе",
	"отправитель", "отправителя", "отправителю", "отправителем", "отправителе",
	"владелец", "владельца", "владельцу", "владельцем", "владельце",
	"держатель", "держателя", "держателю", "держателем", "держательнице",
	"держателе", "держательница", "держательницы", "держательницу",
	"сотрудник", "сотрудника", "сотруднику", "сотрудником", "сотруднике",
	"менеджер", "менеджера", "менеджеру",
	"директор", "директора", "директору", "директором",
	"руководитель", "руководителя", "начальник", "начальника",
	"бухгалтер", "бухгалтера", "кассир", "кассира",
	"подпись", "подписал", "подписала", "подписан", "подписано",
	"гражданин", "гражданина", "гражданину", "гражданка", "гражданки", "гражданке", "гражданине",
	"фио", "имя", "фамилия", "фамилию", "фамилии",
	"от", "для",
	"представитель", "представителя", "представителю",
	"доверенность", "доверенности", "доверенное",
	"выдан", "выдана", "выдано", "выданный",
	"принадлежит", "оформлен", "оформлена", "оформлено",
	"зарегистрирован", "зарегистрирована",
	"пациент", "пациента", "пациенту", "пациентка", "пациенте",
	"абонент", "абонента", "абоненту", "абоненте",
	"пользователь", "пользователя", "пользователю",
	"контрагент", "контрагента",
	"поручитель", "поручителя", "поручителю", "поручителем", "поручителе",
	"созаёмщик", "созаемщик", "созаёмщика", "созаемщика",
	"заёмщик", "заемщик", "заёмщика", "заемщика",
	"заёмщику", "заемщику", "заёмщиком", "заемщиком",
	"заемщице", "заёмщице", "заемщике", "заёмщике",
	"заемщица", "заёмщица", "заемщицы", "заёмщицы",
	"вкладчик", "вкладчика", "вкладчику", "вкладчиком", "вкладчике",
	"наследник", "наследника", "наследнику", "наследница", "наследницы", "наследнике",
	"супруг", "супруга", "супруге", "супругу", "супруги",
	"господин", "господина", "господину", "госпожа", "госпоже", "госпожи", "госпожу",
	// Женские формы ролей во всех падежах: «заявительницы Зубаревой», «клиентке Цой».
	"заявительницы", "заявительнице", "заявительницу", "заявительницей",
	"получательница", "получательницы", "получательнице", "получательницу", "получательницей",
	"отправительница", "отправительницы", "отправительнице", "отправительницу", "отправительницей",
	"владелица", "владелицы", "владелице", "владелицу", "владелицей",
	"вкладчица", "вкладчицы", "вкладчице", "вкладчицу", "вкладчицей",
	"поручительница", "поручительницы", "поручительнице", "поручительницу", "поручительницей",
	"плательщица", "плательщицы", "плательщице", "плательщицу", "плательщицей",
	"наследнице", "наследницу", "наследницей",
	"пациентки", "пациентке", "пациентку", "пациенткой",
	"абонентка", "абонентки", "абонентке", "абонентку", "абоненткой",
	"сотрудница", "сотрудницы", "сотруднице", "сотрудницу", "сотрудницей",
})

// fioPhraseAnchor: ищется как подстрока левого окна в fioHasAnchor (в отличие
// от суффиксного сопоставления сильных фраз).
var fioPhraseAnchor = []string{
	"на имя", "ф.и.о", "ф. и. о", "фио:", "доверенность на",
	"оформлен на", "оформлена на", "зарегистрирован на", "выдан на",
	"г-н", "г-на", "г-ну", "г-жа", "г-жи", "г-же", "г-жу",
}

// fioNegContext: литературные и географические маркеры, описывающие само
// упоминание и перевешивающие любую должность, случайно оказавшуюся перед ним.
var fioNegContext = fioSet([]string{
	"поэт", "поэта", "поэту", "поэтом", "поэзия", "поэзии",
	"писатель", "писателя", "писателю", "писателем",
	"композитор", "композитора", "композитору",
	"художник", "художника", "художнику",
	"учёный", "ученый", "учёного", "ученого",
	"академик", "академика", "профессор", "профессора",
	"режиссёр", "режиссер", "режиссёра", "режиссера",
	"актёр", "актер", "актёра", "актера", "актриса", "актрисы",
	"певец", "певца", "певица", "музыкант", "музыканта",
	"персонаж", "персонажа", "герой", "героя", "героем",
	"роман", "романа", "романе", "повесть", "повести",
	"стихи", "стихов", "стихотворение", "стихотворения", "сказка", "сказки",
	"произведение", "произведения", "произведений", "творчество", "творчества",
	"цитата", "цитаты", "цитирует", "сочинение", "сочинения",
	"является", "являются", "являлся", "являлась",
	"улица", "улицы", "улице", "улицу", "ул",
	"площадь", "площади", "проспект", "проспекта", "переулок", "переулка",
	"набережная", "набережной", "бульвар", "бульвара", "шоссе",
	"музей", "музея", "театр", "театра", "библиотека", "библиотеки",
	"памятник", "памятника", "имени", "им",
	"институт", "института", "университет", "университета",
	"школа", "школы", "гимназия", "лицей",
	"станция", "станции", "метро", "парк", "парка",
	"премия", "премии", "фонд", "фонда",
	"царь", "царя", "император", "императора", "князь", "князя",
	"генерал", "генерала", "философ", "философа",
	"математик", "математика", "физик", "физика", "космонавт", "космонавта",
})

// fioLegalForm: небольшой встроенный запасной список организационных
// маркеров: полный список принадлежит словарю, но эти несколько аббревиатур
// достаточно часты рядом с «фамильными» названиями компаний, чтобы детектор
// держал собственную копию, а не зависел от покрытия словаря.
var fioLegalForm = fioSet([]string{
	"ооо", "оао", "зао", "пао", "ао", "ип", "нко", "тоо", "гуп", "муп",
	"фгуп", "фгбу", "чоп", "нао", "пко",
	"компания", "компании", "фирма", "фирмы", "организация", "организации",
	"предприятие", "холдинг", "корпорация", "агентство", "бюро",
	"завод", "фабрика", "магазин", "салон",
})

// fioAmbiguousInitial: односимвольные строки в нижнем регистре; сравнение идёт
// по ctx.Lower, а заглавность проверяется отдельно по ctx.Text.
var fioAmbiguousInitial = fioSet([]string{
	"г", "д", "к", "с", "р", "т", "п", "в", "м", "н", "о", "л", "у", "ч",
})

// fioGeoLeft: слова, помещающие следующее сокращение в адрес, а не в имя, так
// что «в г. Иванове» сохраняет город, а «Г. Иванов» становится человеком.
// Спрашивается только слово, стоящее НЕПОСРЕДСТВЕННО перед; более широкое окно
// поймало бы «в» из несвязанной клаузы.
var fioGeoLeft = fioSet([]string{
	"в", "во", "из", "под", "над", "за", "до", "около", "близ", "по",
	"город", "города", "городе", "городу", "гор", "г", "пос", "посёлок", "поселок",
	"область", "области", "обл", "район", "района", "районе",
	"край", "края", "округ", "округа", "республика", "республики", "республике",
	"адрес", "адреса", "адресу", "адресом", "индекс", "индекса",
	"проживает", "проживающий", "проживающая", "прописан", "прописана",
	"отделение", "отделения", "отделении", "филиал", "филиала", "офис", "офиса",
	"находится", "расположен", "расположено", "доставка", "доставку", "доставки",
	"переехал", "переезд", "родился", "родилась", "уроженец", "уроженка",
})

// fioAbbrevPair: точечные пары, выглядящие ровно как два инициала, но
// являющиеся обычными русскими сокращениями. Ключ строится как
// letters[0] + "." + letters[1], поэтому записи без завершающей точки.
var fioAbbrevPair = fioSet([]string{
	"т.е", "т.к", "т.д", "т.п", "т.н", "и.о", "н.э", "г.р", "с.г", "д.р",
	"г.о", "м.о",
})

// fioHolderAnchorWords: строчные подстроки, помещающие латинское имя в контекст
// карты. Используются основы, чтобы не перечислять падежные окончания.
var fioHolderAnchorWords = []string{
	"держател", "владелец карт", "владельца карт",
	"holder", "cardholder", "card holder", "card number",
	"на карте", "имя на карте", "имя держателя",
	"карта", "карты", "карте", "картой", "card",
}

// fioLatinNoise: «шумные» латинские слова, которые не просто останавливают
// набор — они убивают кандидата целиком.
var fioLatinNoise = fioSet([]string{
	"ltd", "inc", "llc", "plc", "pjsc", "ojsc", "jsc", "corp", "co", "gmbh",
	"sa", "ag", "nv", "bv", "oy", "as", "kft", "limited", "company", "group",
	"holding", "trust", "fund", "capital", "invest", "investments",
	"bank", "banking", "alfa", "alpha", "sber", "sberbank", "tinkoff", "vtb",
	"gazprombank", "raiffeisen", "otkritie", "psb", "mkb", "rosbank",
	"visa", "mastercard", "maestro", "mir", "amex", "american", "express",
	"unionpay", "jcb", "discover", "paypal", "apple", "google", "samsung",
	"card", "cards", "holder", "name", "valid", "thru", "from", "until",
	"expires", "expiry", "debit", "credit", "classic", "gold", "platinum",
	"world", "black", "premium", "business", "corporate", "standard",
	"account", "number", "code", "security", "cvv", "cvc", "pin", "atm", "pos",
	"payment", "transaction", "transfer", "merchant", "terminal", "total",
	"usd", "eur", "rub", "rur", "approved", "declined", "success", "error",
	"the", "and", "for", "swift", "iban", "bic",
})

// fioNoCaseSignal сообщает, что регистр в payload не несёт информации: текст
// целиком строчный ЛИБО целиком заглавный. Второе так же важно, как первое:
// в «КЛИЕНТ ИВАН ЗАПРОСИЛ ПЕРЕВЫПУСК КАРТЫ» заглавная буква стоит у каждого
// слова, и принимать её за свидетельство — значит съесть два обычных слова
// вместе с именем.
func fioNoCaseSignal(ctx *Context) bool {
	if ctx.CaseBlind {
		return true
	}
	for _, r := range ctx.Text {
		if unicode.IsLetter(r) && !unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// fioValueRun — прочитанный прогон атомов значения.
type fioValueRun struct {
	start, end int
	lastTok    int
	atoms      int    // всего атомов, 1..fioValueMaxAtoms
	full       int    // из них полных слов (не инициалов)
	dictSeen   bool   // хотя бы один атом подтверждён словарём или морфологией
	latinOnly  bool   // все атомы латинские -> CARD_HOLDER, иначе FIO
	surname    string // последний полный атом, для вето знаменитости
	firstLower string // первый полный атом, для латинского CARD_HOLDER
	latinName  bool   // порядок «Имя Фамилия»: первый атом — словарное латинское имя
}

// fioReadValueComp — fioReadComponent с расширенным набором разделителей
// (fioValueSeps) и с цепочкой из нескольких разделителей. Отдельная функция,
// а не параметр существующей, именно чтобы ветви A–E остались нетронутыми.
func fioReadValueComp(ctx *Context, cls []fioClass, i int) (fioComp, bool) {
	toks := ctx.Tokens
	if i >= len(toks) || toks[i].Kind != text.KindWord {
		return fioComp{}, false
	}
	t := toks[i]
	c := fioComp{start: t.Start, end: t.End, tok: i, lastTok: i}
	j := i
	for j+2 < len(toks) {
		sep, nxt := toks[j+1], toks[j+2]
		if sep.Kind != text.KindPunct || sep.Start != c.end ||
			!strings.Contains(fioValueSeps, ctx.Text[sep.Start:sep.End]) {
			break
		}
		if nxt.Kind != text.KindWord || nxt.Start != sep.End {
			break
		}
		c.end = nxt.End
		c.lastTok = j + 2
		j += 2
	}
	c.lower = ctx.Lower[c.start:c.end]
	c.cls = fioClassify(cls, i, c.lower)
	return c, true
}

// fioValueParts разбивает атом по fioValueSeps на части.
func fioValueParts(w string) []string {
	return strings.FieldsFunc(w, func(r rune) bool {
		return strings.ContainsRune(fioValueSeps, r)
	})
}

// fioValueBadWord: слово, которое не может быть частью имени — стоп-слово,
// топоним, страна, гражданство, организация, эмитент, тип улицы, месяц,
// правовая форма или негативный контекст.
func fioValueBadWord(w string) bool {
	if dict.IsStopWord(w) || dict.IsCity(w) || dict.IsCityForm(w) ||
		dict.IsCountry(w) || dict.IsCitizenship(w) || dict.IsOrgWord(w) ||
		dict.IsIssuerWord(w) || dict.IsStreetType(w) {
		return true
	}
	if _, isMonth := dict.Month(w); isMonth {
		return true
	}
	if _, isLegal := fioLegalForm[w]; isLegal {
		return true
	}
	if _, isNeg := fioNegContext[w]; isNeg {
		return true
	}
	return false
}

// fioValueAdjective: слово с прилагательным окончанием не может быть именем.
func fioValueAdjective(w string) bool {
	for _, suf := range fioAdjectiveEndings {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	return false
}

// fioValueAtomOK судит один ПОЛНЫЙ атом значения (инициалы судятся отдельно).
// Возвращает (принят, подтверждён словарём).
func fioValueAtomOK(ctx *Context, cls []fioClass, c fioComp, noCase bool) (bool, bool) {
	if !fioIsCyrillic(ctx, cls, c.tok) && !text.IsLatinWord(c.lower) {
		return false, false
	}
	if fioRunes(c.lower) < 2 {
		return false, false
	}
	parts := fioValueParts(c.lower)
	if fioValuePartsBad(parts) || fioValueBadWord(c.lower) {
		return false, false
	}
	if fioValueDictSeen(parts, c.lower) {
		return true, true
	}
	if !noCase && text.IsUpperFirst(ctx.Text[c.start:c.end]) && !fioValueAdjective(c.lower) {
		return true, false
	}
	return false, false
}

// fioValuePartsBad reports whether any part of the atom is a word that cannot
// be part of a name.
func fioValuePartsBad(parts []string) bool {
	for _, p := range parts {
		if fioRunes(p) >= 2 && fioValueBadWord(p) {
			return true
		}
	}
	return false
}

// fioValueDictSeen reports whether the atom or any of its parts is confirmed
// by the dictionary or morphology.
func fioValueDictSeen(parts []string, lower string) bool {
	for _, p := range parts {
		if fioNameForms(p) != 0 || fioLooksLikeSurname(p) || dict.IsLatinName(p) {
			return true
		}
	}
	return fioNameForms(lower) != 0 || fioLooksLikeSurname(lower) || dict.IsLatinName(lower)
}

// fioReadValueRun читает прогон атомов, начиная с токена tok.
func fioReadValueRun(ctx *Context, cls []fioClass, tok int, noCase bool) (fioValueRun, bool) {
	var run fioValueRun
	run.start = ctx.Tokens[tok].Start
	run.lastTok = tok
	run.latinOnly = true
	first := true
	prevInitial := ""
	for run.atoms < fioValueMaxAtoms {
		t := ctx.Tokens[run.lastTok]
		if t.Kind != text.KindWord {
			break
		}
		if consumed, ok, letter := fioReadValueInitial(ctx, &run, first, prevInitial); consumed {
			if !ok {
				break
			}
			prevInitial = letter
			first = false
			continue
		}
		if !fioReadValueCompAtom(ctx, cls, &run, noCase) {
			break
		}
		prevInitial = ""
		first = false
	}
	if run.atoms == 0 {
		return fioValueRun{}, false
	}
	return run, true
}

// fioReadValueInitial attempts to consume a single initial (letter + dot) at
// run.lastTok. It returns (consumed, ok, letter): consumed reports whether the
// token was an initial at all; ok reports whether the run may continue; letter
// is the lowercased initial when consumed.
func fioReadValueInitial(ctx *Context, run *fioValueRun, first bool, prevInitial string) (consumed, ok bool, letter string) {
	t := ctx.Tokens[run.lastTok]
	s := ctx.Text[t.Start:t.End]
	if !fioOneRune(s) || run.lastTok+1 >= len(ctx.Tokens) {
		return false, true, ""
	}
	dot := ctx.Tokens[run.lastTok+1]
	if dot.Kind != text.KindPunct || dot.Start != t.End || ctx.Text[dot.Start:dot.End] != "." {
		return false, true, ""
	}
	// Строчный инициал в начале значения («и. иван петрович») принимается,
	// если буква не неоднозначна («г.», «д.» — это сокращения, а не инициалы).
	// Одиночное «и.» само по себе всё равно не пройдёт fioValueRunAccepted,
	// потому что требует минимум двух атомов или словарного подтверждения.
	letter = ctx.Lower[t.Start:t.End]
	if fioAmbiguousInitialAtStart(first, s, letter) {
		return true, false, ""
	}
	if prevInitial != "" {
		if _, bad := fioAbbrevPair[prevInitial+"."+letter]; bad {
			return true, false, ""
		}
	}
	run.atoms++
	run.end = dot.End
	run.lastTok = run.lastTok + 1
	if !text.IsLatinWord(s) {
		run.latinOnly = false
	}
	if run.lastTok+2 < len(ctx.Tokens) && fioIsNameGap(ctx, ctx.Tokens[run.lastTok+1]) {
		run.lastTok += 2
		return true, true, letter
	}
	return true, false, ""
}

// fioAmbiguousInitialAtStart reports whether a lowercase initial at the very
// start of a value run is an ambiguous abbreviation («г.», «д.») rather than a
// real initial. Uppercase initials and non-ambiguous lowercase letters («и.»)
// are accepted.
func fioAmbiguousInitialAtStart(first bool, s, letter string) bool {
	if !first || text.IsUpperFirst(s) {
		return false
	}
	_, amb := fioAmbiguousInitial[letter]
	return amb
}

// fioReadValueCompAtom reads one full component atom into run. It returns
// false when the atom cannot be consumed and the run must stop.
func fioReadValueCompAtom(ctx *Context, cls []fioClass, run *fioValueRun, noCase bool) bool {
	c, ok := fioReadValueComp(ctx, cls, run.lastTok)
	if !ok {
		return false
	}
	accepted, dictSeen := fioValueAtomOK(ctx, cls, c, noCase)
	if !accepted || fioValueLowerTail(ctx, c, *run, noCase) {
		return false
	}
	run.atoms++
	run.full++
	if dictSeen {
		run.dictSeen = true
	}
	if !text.IsLatinWord(c.lower) {
		run.latinOnly = false
	}
	if run.full == 1 {
		run.firstLower = c.lower
	}
	run.surname = c.lower
	run.end = c.end
	run.lastTok = c.lastTok
	if run.lastTok+2 < len(ctx.Tokens) && fioIsNameGap(ctx, ctx.Tokens[run.lastTok+1]) {
		run.lastTok += 2
		return true
	}
	return false
}

// fioValueLowerTail reports whether c must not continue a value run that has
// already started: in a cased text, a lower-case word after the first atom is
// accepted only when the dictionary knows it as a name. Its ending alone
// («готова» looks like a surname on «-ова») does not carry it into
// «заявительнице Цой готова».
func fioValueLowerTail(ctx *Context, c fioComp, run fioValueRun, noCase bool) bool {
	if noCase || run.atoms == 0 || text.IsUpperFirst(ctx.Text[c.start:c.end]) {
		return false
	}
	return fioNameForms(c.lower) == 0
}

// fioValueTerminated проверяет правую границу прогона для конвертов R1 и R2.
// После последнего атома допускаются только пробелы, а затем ровно одно из:
// конец payload, запятая, или точка конца предложения.
func fioValueTerminated(ctx *Context, run fioValueRun) bool {
	i := run.lastTok + 1
	for i < len(ctx.Tokens) && ctx.Tokens[i].Kind == text.KindSpace {
		i++
	}
	if i >= len(ctx.Tokens) {
		return true
	}
	t := ctx.Tokens[i]
	if t.Kind != text.KindPunct {
		return false
	}
	s := ctx.Text[t.Start:t.End]
	if s == "," {
		return true
	}
	if s == "." {
		return fioValueDotTerminated(ctx, i)
	}
	return false
}

// fioValueDotTerminated reports whether a sentence-ending dot at token i
// terminates the value run.
func fioValueDotTerminated(ctx *Context, i int) bool {
	if i > 0 && ctx.Tokens[i-1].Kind == text.KindPunct &&
		ctx.Text[ctx.Tokens[i-1].Start:ctx.Tokens[i-1].End] == "." {
		return true
	}
	if !fioAbbrevDot(ctx, i) {
		if i+1 >= len(ctx.Tokens) || ctx.Tokens[i+1].Kind == text.KindSpace {
			return true
		}
	}
	return false
}

// fioStandaloneBounds возвращает границы payload без окружающих пробелов,
// ok = false, если в payload есть перевод строки или он длиннее
// fioValueMaxBytes.
func fioStandaloneBounds(ctx *Context) (lo, hi int, ok bool) {
	s := ctx.Text
	trimmed := strings.Trim(s, fioSpaceCutset)
	if trimmed == "" {
		return 0, 0, false
	}
	lo = len(s) - len(strings.TrimLeft(s, fioSpaceCutset))
	hi = lo + len(trimmed)
	if strings.ContainsAny(trimmed, "\n\r") {
		return 0, 0, false
	}
	if len(trimmed) > fioValueMaxBytes {
		return 0, 0, false
	}
	return lo, hi, true
}

// fioValueRunAccepted — условие приёма прогона (§2.4-бис) для конверта R1.
// Слабый прогон (только регистровое свидетельство) обязан иметь atoms >= 2,
// иначе одиночное заглавное обычное слово («Версия», «Заказ») маскируется.
func fioValueRunAccepted(run fioValueRun) bool {
	return fioValueRunAcceptedFor(run, false)
}

// fioValueRunAcceptedFor — условие приёма прогона (§2.4-бис), разведённое по
// конвертам. allowSingleInitial разрешает одиночный инициал (atoms == 1,
// full == 0) — это делает значением метка поля, а не сам инициал, поэтому
// только конверт R2 его принимает. Во всех конвертах слабый прогон (только
// регистровое свидетельство) обязан иметь atoms >= 2.
func fioValueRunAcceptedFor(run fioValueRun, allowSingleInitial bool) bool {
	if run.dictSeen {
		return true
	}
	if run.atoms >= 2 {
		return true
	}
	return allowSingleInitial && run.atoms == 1 && run.full == 0
}

// fioValueLatinSurname: латинское значение принимается как CARD_HOLDER только
// если первый полный атом читается как фамилия — апострофным составным
// («O'Brien») или латинским фамильным окончанием («PETROV», «Sidorova»). Это
// отделяет имя держателя карты от транслитерированного русского имени
// «IVAN IVANOV», которое без карточного контекста маскировать нельзя.
func fioValueLatinSurname(run fioValueRun) bool {
	if run.firstLower == "" {
		return false
	}
	if strings.IndexByte(run.firstLower, '\'') >= 0 {
		return true
	}
	for _, suf := range fioLatinSurnameSuffixes {
		if strings.HasSuffix(run.firstLower, suf) {
			return true
		}
	}
	return false
}

// fioLatinSurnameSuffixes — окончания транслитерированных фамилий, по которым
// латинское слово читается как фамилия, а не как имя. Намеренно узкий список:
// он должен отличать «PETROV»/«Sidorova» от «IVAN»/«PETR»/«ANNA»/«JOHN».
var fioLatinSurnameSuffixes = []string{
	"ov", "ova", "ev", "eva", "in", "ina", "enko", "uk", "yuk", "ich",
	"sky", "skaya", "ski", "ska", "yan",
}

// fioValueLabelStart проверяет, что двоеточие в токене i открывает поле, а не
// адрес или время. Три структурных барьера (§2.6, §3А.4): токен слева от ':'
// (игнорируя пробелы) обязан быть словом — иначе время открывает поле
// («с 09:00 до 20:00»); за ':' обязан идти пробел или конец payload — иначе
// «https://» открывает поле; слово слева не должно быть географическим,
// издательским или негативным маркером.
func fioValueLabelStart(ctx *Context, i int) bool {
	j := i - 1
	for j >= 0 && ctx.Tokens[j].Kind == text.KindSpace {
		j--
	}
	if j < 0 || ctx.Tokens[j].Kind != text.KindWord {
		return false
	}
	if i+1 < len(ctx.Tokens) && ctx.Tokens[i+1].Kind != text.KindSpace {
		return false
	}
	w := ctx.Lower[ctx.Tokens[j].Start:ctx.Tokens[j].End]
	if _, bad := fioGeoLeft[w]; bad {
		return false
	}
	if dict.IsStreetType(w) || dict.IsIssuerWord(w) {
		return false
	}
	if _, bad := fioNegContext[w]; bad {
		return false
	}
	return true
}

// fioIsCapitalInitial: однобуквенное слово с приклеенной точкой, написанное
// ЗАГЛАВНОЙ. Отличает значение от топонимической аббревиатуры («г.», «с.»,
// «д.» пишутся строчными) и служит условием пропуска одного стоп-слова в R3.
func fioIsCapitalInitial(ctx *Context, i int) bool {
	t := ctx.Tokens[i]
	if t.Kind != text.KindWord || !fioOneRune(ctx.Text[t.Start:t.End]) {
		return false
	}
	if !text.IsUpperFirst(ctx.Text[t.Start:t.End]) {
		return false
	}
	if i+1 >= len(ctx.Tokens) {
		return false
	}
	dot := ctx.Tokens[i+1]
	return dot.Kind == text.KindPunct && dot.Start == t.End &&
		ctx.Text[dot.Start:dot.End] == "."
}

// fioValueOverlaps: спан нового конверта не должен пересекаться с уже
// выданными спанами; Resolve всё равно снимет пересечения, но ранний отказ
// дешевле и не даёт слабому правилу укоротить сильное. Когда allowExtend
// истинно, разрешён спан, который СТРОГО длиннее существующего и полностью
// его покрывает: это более полное чтение того же имени (например,
// «иван петрович и.» поверх «иван петрович»), и Resolve оставит более длинный
// спан. Равный спан — это чистое дублирование, его отвергаем всегда.
func fioValueOverlaps(out []pd.Span, start, end int, allowExtend bool) bool {
	for _, s := range out {
		if start < s.End && s.Start < end &&
			!(allowExtend && s.Start >= start && s.End <= end && (s.Start > start || s.End < end)) {
			return true
		}
	}
	return false
}

// fioEmitValue собирает спан из прогона значения. confStrong — уверенность
// конверта при словарном свидетельстве; без него (только регистр) — слабая
// fioConfValueWeak. Латинский прогон обязан читаться как фамилия, иначе это
// транслитерированное имя без карточного контекста.
func fioEmitValue(out []pd.Span, run fioValueRun, confStrong float64) []pd.Span {
	conf := confStrong
	if !run.dictSeen {
		conf = fioConfValueWeak
	}
	typ := pd.TypeFIO
	hint := "value"
	if run.latinOnly {
		// Одиночное латинское слово — не имя держателя карты: «Держатель
		// карты: IVANOV» остаётся нетронутым. Имя держателя — минимум два
		// атома, и первый из них обязан читаться как фамилия (или быть
		// словарным латинским именем в порядке «Имя Фамилия»).
		if run.atoms < 2 || (!fioValueLatinSurname(run) && !run.latinName) {
			return out
		}
		typ = pd.TypeCardHolder
		hint = "holder_value"
	}
	return append(out, pd.Span{
		Start: run.start, End: run.end, Type: typ, Conf: conf, Src: "fio", Hint: hint,
	})
}

// fioValueLastTok возвращает индекс токена последнего атома прогона. run.lastTok
// указывает на следующий кандидат-токен (после пробельного зазора), а не на
// последний атом, поэтому для fioOrgAdjacent нужен токен, заканчивающийся на
// run.end.
func fioValueLastTok(ctx *Context, run fioValueRun) int {
	for i := len(ctx.Tokens) - 1; i >= 0; i-- {
		if ctx.Tokens[i].End == run.end {
			return i
		}
	}
	return run.lastTok
}

// fioScanValues — третий проход детектора, рядом с fioScanRussian и
// fioScanHolders. Реализует три конверта значения: R1 (весь payload — одно
// значение), R2 (значение сразу после «метка:»), R3 (значение сразу за
// сильным ролевым якорем).
func fioScanValues(ctx *Context, out []pd.Span) []pd.Span {
	cls := make([]fioClass, len(ctx.Tokens))
	noCase := fioNoCaseSignal(ctx)

	// R1 — fioValueStandalone. Весь payload (после обрезки пробелов и не более
	// одной завершающей точки) есть один прогон атомов значения.
	out = fioValueStandalone(ctx, cls, noCase, out)

	// R2 — fioValueLabel. Значение стоит сразу после ':', прошедшего
	// fioValueLabelStart, и заканчивается концом payload, запятой или точкой
	// конца предложения.
	out = fioValueLabel(ctx, cls, noCase, out)

	// R3 — fioValueAnchored. Значение стоит сразу за сильным ролевым якорем
	// (fioStrongAnchor) или за фразой из fioStrongPhraseAnchor, без двоеточия.
	out = fioValueAnchored(ctx, cls, noCase, out)

	// R4 — fioScanLatinValues. Латинское имя держателя внутри предложения,
	// без карточного якоря: «Sidorova Anna подтвердила операцию по карте».
	out = fioScanLatinValues(ctx, cls, noCase, out)

	return out
}

// fioValueStandalone scans the whole payload as a single value (envelope R1).
func fioValueStandalone(ctx *Context, cls []fioClass, noCase bool, out []pd.Span) []pd.Span {
	lo, _, ok := fioStandaloneBounds(ctx)
	if !ok {
		return out
	}
	tokIdx := ctx.TokenAt(lo)
	if tokIdx < 0 || ctx.Tokens[tokIdx].Kind != text.KindWord {
		return out
	}
	// Ведущий глагол в начале предложения («Отправь Анне Залуцкой»,
	// «Позвони Перешеину Илье») не является частью значения: прогон начинается
	// со следующего слова.
	if fioValueLeadingVerb(ctx, cls, tokIdx) {
		if j, ok := fioNextWordTok(ctx, tokIdx); ok {
			tokIdx = j
		}
	}
	run, ok := fioReadValueRun(ctx, cls, tokIdx, noCase)
	if !ok || run.start != ctx.Tokens[tokIdx].Start || !fioValueTerminated(ctx, run) ||
		!fioValueRunAccepted(run) {
		return out
	}
	m := fioMatch{
		start:      run.start,
		end:        run.end,
		lastTok:    run.lastTok,
		surname:    run.surname,
		standalone: true,
	}
	if fioVetoed(ctx, tokIdx, m) || fioValueOverlaps(out, run.start, run.end, noCase) {
		return out
	}
	return fioEmitValue(out, run, fioConfStandalone)
}

// fioValueLeadingVerb reports whether the word at token tok is a leading
// imperative verb that opens a value run at the start of a sentence. The word
// must not be a dictionary name/patronymic and must read as a verb or an
// imperative form.
func fioValueLeadingVerb(ctx *Context, cls []fioClass, tok int) bool {
	t := ctx.Tokens[tok]
	if t.Kind != text.KindWord || !fioValueAtSentenceStart(ctx, tok) {
		return false
	}
	w := ctx.Lower[t.Start:t.End]
	if fioNameForms(w) != 0 {
		return false
	}
	if fioRunes(w) < 4 {
		return false
	}
	return fioVerbLike(w) || fioImperativeLike(w)
}

// fioValueAtSentenceStart reports whether token tok stands at the start of a
// sentence: at the very beginning of the text or right after a sentence-ending
// punctuation mark or a newline.
func fioValueAtSentenceStart(ctx *Context, tok int) bool {
	j := tok - 1
	for j >= 0 && ctx.Tokens[j].Kind == text.KindSpace {
		j--
	}
	if j < 0 {
		return true
	}
	prev := ctx.Tokens[j]
	if prev.Kind == text.KindPunct {
		s := ctx.Text[prev.Start:prev.End]
		if s == "." || s == "!" || s == "?" {
			return true
		}
	}
	return strings.Contains(ctx.Text[prev.End:ctx.Tokens[tok].Start], "\n")
}

// fioValueLabel scans values that follow a field label (envelope R2).
func fioValueLabel(ctx *Context, cls []fioClass, noCase bool, out []pd.Span) []pd.Span {
	for i := 0; i < len(ctx.Tokens); i++ {
		if !fioIsColon(ctx, i) {
			continue
		}
		if !fioValueLabelStart(ctx, i) {
			continue
		}
		run, startTok, ok := fioValueLabelRun(ctx, cls, i, noCase)
		if !ok {
			continue
		}
		if out, ok = fioEmitValueChecked(ctx, out, run, startTok, fioConfLabel); !ok {
			continue
		}
	}
	return out
}

// fioIsColon reports whether token i is a colon.
func fioIsColon(ctx *Context, i int) bool {
	t := ctx.Tokens[i]
	return t.Kind == text.KindPunct && ctx.Text[t.Start:t.End] == ":"
}

// fioValueLabelRun reads the value run that follows a field label at token i.
// It returns the run and the token index where the value starts.
func fioValueLabelRun(ctx *Context, cls []fioClass, i int, noCase bool) (fioValueRun, int, bool) {
	startTok := i + 1
	if startTok >= len(ctx.Tokens) || ctx.Tokens[startTok].Kind != text.KindSpace {
		return fioValueRun{}, 0, false
	}
	startTok++
	if startTok >= len(ctx.Tokens) || ctx.Tokens[startTok].Kind != text.KindWord {
		return fioValueRun{}, 0, false
	}
	run, ok := fioReadValueRun(ctx, cls, startTok, noCase)
	if !ok || !fioValueTerminated(ctx, run) || !fioValueRunAcceptedFor(run, true) {
		return fioValueRun{}, 0, false
	}
	return run, startTok, true
}

// fioEmitValueChecked emits a value span after the veto and overlap checks.
// It returns the updated out and whether the span was emitted.
func fioEmitValueChecked(ctx *Context, out []pd.Span, run fioValueRun, startTok int, conf float64) ([]pd.Span, bool) {
	m := fioMatch{
		start:   run.start,
		end:     run.end,
		lastTok: fioValueLastTok(ctx, run),
		surname: run.surname,
	}
	if fioVetoed(ctx, startTok, m) || fioValueOverlaps(out, run.start, run.end, true) {
		return out, false
	}
	return fioEmitValue(out, run, conf), true
}

// fioValueAnchored scans values that follow a strong role anchor (envelope R3).
func fioValueAnchored(ctx *Context, cls []fioClass, noCase bool, out []pd.Span) []pd.Span {
	for i := 0; i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.Kind != text.KindWord {
			continue
		}
		if !fioValueAnchoredAt(ctx, i) {
			continue
		}
		run, startTok, ok := fioValueAnchoredRun(ctx, cls, i, noCase)
		if !ok {
			continue
		}
		if out, ok = fioEmitValueChecked(ctx, out, run, startTok, fioConfAnchored); !ok {
			continue
		}
	}
	return out
}

// fioValueAnchoredRun reads the value run that follows a strong anchor at
// token i. It returns the run and the token index where the value starts.
func fioValueAnchoredRun(ctx *Context, cls []fioClass, i int, noCase bool) (fioValueRun, int, bool) {
	startTok := i + 1
	if startTok < len(ctx.Tokens) && ctx.Tokens[startTok].Kind == text.KindSpace {
		startTok++
	}
	if startTok >= len(ctx.Tokens) || ctx.Tokens[startTok].Kind != text.KindWord {
		return fioValueRun{}, 0, false
	}
	// Пропуск ровно одного стоп-слова между якорем и значением — только
	// если следующий за ним атом — заглавный инициал.
	startTok = fioValueSkipStopWord(ctx, startTok)
	run, ok := fioReadValueRun(ctx, cls, startTok, noCase)
	if !ok || !fioValueRunAcceptedFor(run, false) {
		return fioValueRun{}, 0, false
	}
	return run, startTok, true
}

// fioValueAnchoredAt reports whether token i is a strong role anchor or the
// end of a strong phrase anchor.
func fioValueAnchoredAt(ctx *Context, i int) bool {
	t := ctx.Tokens[i]
	if _, yes := fioStrongAnchor[ctx.Lower[t.Start:t.End]]; yes {
		return true
	}
	win := strings.TrimRight(fioLeftWindow(ctx, t.Start, fioStrongWindow), fioSpaceCutset)
	for _, p := range fioStrongPhraseAnchor {
		if strings.HasSuffix(win, p) {
			return true
		}
	}
	return false
}

// fioValueSkipStopWord skips exactly one stop word between the anchor and the
// value, but only when the following atom is a capital initial.
func fioValueSkipStopWord(ctx *Context, startTok int) int {
	if !dict.IsStopWord(ctx.Lower[ctx.Tokens[startTok].Start:ctx.Tokens[startTok].End]) {
		return startTok
	}
	next := startTok + 1
	if next < len(ctx.Tokens) && ctx.Tokens[next].Kind == text.KindSpace {
		next++
	}
	if next < len(ctx.Tokens) && fioIsCapitalInitial(ctx, next) {
		return next
	}
	return startTok
}

// fioScanLatinValues — конверт R4: латинское имя держателя карты внутри
// предложения, без карточного якоря. «Sidorova Anna подтвердила операцию по
// карте» и «имя «SMIRNOVA ANNA»» — это имя держателя, а не транслитерация
// русского имени: первый атом обязан читаться как латинская фамилия
// (окончание -ov/-ova/...), иначе это «Ivan Petrov», который без карточного
// контекста маскировать нельзя. Прогон читается тем же fioReadValueRun, что и
// конверты R1–R3, поэтому латинская фамилия + имя собираются в один спан.
func fioScanLatinValues(ctx *Context, cls []fioClass, noCase bool, out []pd.Span) []pd.Span {
	for i := 0; i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.Kind != text.KindWord || !text.IsLatinWord(ctx.Lower[t.Start:t.End]) {
			continue
		}
		run, ok := fioReadValueRun(ctx, cls, i, noCase)
		if !ok || !run.latinOnly || run.atoms < 2 {
			continue
		}
		run, ok = fioValueLatinOK(ctx, run)
		if !ok {
			continue
		}
		m := fioMatch{
			start:   run.start,
			end:     run.end,
			lastTok: fioValueLastTok(ctx, run),
			surname: run.surname,
		}
		if fioVetoed(ctx, i, m) || fioValueOverlaps(out, run.start, run.end, true) {
			continue
		}
		out = fioEmitValue(out, run, fioConfHolder)
		i = run.lastTok
	}
	return out
}

// fioValueLatinOK reports whether a latin value run is a surname or follows the
// «Имя Фамилия» order, marking the run as a latin name when the latter.
func fioValueLatinOK(ctx *Context, run fioValueRun) (fioValueRun, bool) {
	if fioValueLatinSurname(run) {
		return run, true
	}
	if !fioValueLatinNameFirst(ctx, run) {
		return run, false
	}
	run.latinName = true
	return run, true
}

// fioValueLatinNameFirst reports whether a latin run follows the «Имя Фамилия»
// order: the first atom is a dictionary latin first name and the last atom is a
// capitalised latin word of at least three letters that is not latin noise.
// This lets «Ilya Pereshein» be masked as a card holder even though the first
// word is a given name rather than a surname.
func fioValueLatinNameFirst(ctx *Context, run fioValueRun) bool {
	if !dict.IsLatinName(run.firstLower) {
		return false
	}
	last := fioValueLastTok(ctx, run)
	if last < 0 || last >= len(ctx.Tokens) {
		return false
	}
	t := ctx.Tokens[last]
	s := ctx.Text[t.Start:t.End]
	if !text.IsLatinWord(ctx.Lower[t.Start:t.End]) || fioRunes(s) < 3 ||
		!text.IsUpperFirst(s) || fioIsUpperLatin(s) {
		return false
	}
	if _, noise := fioLatinNoise[ctx.Lower[t.Start:t.End]]; noise {
		return false
	}
	return true
}
