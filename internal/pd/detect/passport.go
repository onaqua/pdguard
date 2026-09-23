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

// detectorPassport is the identifier reported in Span.Src and in logs.
const detectorPassport = "passport"

// passportDetector covers the identity block of an RF internal passport.
// The type is empty and therefore trivially safe for concurrent use.
type passportDetector struct{}

// Name implements Detector.
func (passportDetector) Name() string { return detectorPassport }

// Types implements Detector. A fresh slice is returned so a caller cannot
// mutate the detector's view of itself.
func (passportDetector) Types() []pd.Type {
	return []pd.Type{
		pd.TypePassport,
		pd.TypeSubdivisionCode,
		pd.TypePassportIssuer,
		pd.TypeBirthPlace,
		pd.TypeCitizenship,
	}
}

// Detect implements Detector. Spans of different categories may overlap;
// Resolve picks the winner.
func (d passportDetector) Detect(ctx *Context) []pd.Span {
	if len(ctx.Text) == 0 {
		return nil
	}
	out := make([]pd.Span, 0, 8)
	out = d.numbers(ctx, out)
	out = d.subdivision(ctx, out)
	out = d.issuer(ctx, out)
	out = d.birthPlace(ctx, out)
	out = d.citizenship(ctx, out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func init() {
	// Failing loudly at load beats truncating a stem table at scan time: a
	// silently dropped stem would look like a detector that simply stopped
	// recognising one spelling of a field.
	for _, t := range [][]ppStem{
		ppAnchorStems, ppSeriesStems, ppNumberStems,
		ppIssuerStems, ppBirthStems, ppCitizenshipStems,
	} {
		if len(t) > ppMaxStems {
			panic("detect: passport stem table exceeds ppMaxStems")
		}
	}
	Register(passportDetector{})
}

// ppStem is one literal prefix of a vocabulary entry together with the check
// that verifies whatever follows it. tail receives the offset just past lit and
// returns the end of the whole word; ok=false rejects the occurrence.
type ppStem struct {
	lit  string
	tail func(s string, i int) (int, bool)
	// bare marks a label that is a symbol rather than a spelled-out word. A
	// bare label is far weaker evidence and is handled separately by the caller.
	bare bool
}

// ppSpan is one accepted vocabulary hit: the byte range of the whole word.
type ppSpan struct{ start, end int }

// ppLabel is one "label + digit group" hit, e.g. "серия 45 09".
type ppLabel struct {
	labelStart int
	digStart   int
	digEnd     int
	// bare marks a symbol label ("№", "#", "N") rather than a spelled-out word.
	bare bool
}

// ppDigitLayout is one grouping of the digits of a value: the group sizes, in
// order, separated by whitespace.
type ppDigitLayout struct {
	groups []uint8
	// flexLast lets the separator before the LAST group be empty or one of the
	// printer's marks, so "4509123456", "4509 123456", "4509-123456" and
	// "4509 № 123456" are all the same value written four ways.
	flexLast bool
	// strictTail refuses a match that is itself only a slice of a longer run of
	// groups.
	strictTail bool
}

// ppOtherDocMarker is a literal that names an identity document which is NOT
// the RF internal passport. exact demands a token boundary at BOTH ends.
type ppOtherDocMarker struct {
	lit   string
	exact bool
}

const (
	ppConfPassport    = 0.98
	ppConfSubdivision = 0.95
	ppConfIssuer      = 0.85
	ppConfBirthPlace  = 0.80
	ppConfCitizenship = 0.90

	ppConfBareValue   = 0.90 // значение без якоря: форма — единственное свидетельство
	ppConfIssuerBare  = 0.80 // орган назван, но клаузы «кем выдан» нет
	ppBareAsideBytes  = 80   // максимальная длина скобочной ремарки в хвосте payload
	ppSubdivFillerMax = 2    // слов между меткой «код подразделения» и кодом
	ppIssuerLeftBytes = 60   // сколько байт влево можно добрать к названию органа
	ppCorroborateGap  = 24   // байт между двумя взаимно подтверждающими группами

	ppAnchorWindow    = 60 // bytes an anchor may sit ahead of the digits
	ppPairWindow      = 40 // bytes between a "серия" group and its "номер" group
	ppIssuerMaxBytes  = 160
	ppIssuerMinWords  = 2
	ppBirthMaxBytes   = 100
	ppCitizenMaxBytes = 60
	ppCitizenMaxWords = 3
)

// ppWord* are the authority and region vocabulary words that recur across the
// tables below. Hoisting them into constants keeps the duplicated literals out
// of the source (go:S1192) without changing the values.
const (
	ppWordOtdel         = "отдел"
	ppWordOtdelom       = "отделом"
	ppWordOtdela        = "отдела"
	ppWordOtdeleniem    = "отделением"
	ppWordOtdelenie     = "отделение"
	ppWordOtdeleniya    = "отделения"
	ppWordUpravleniem   = "управлением"
	ppWordUpravleniya   = "управления"
	ppWordUpravlenie    = "управление"
	ppWordMigratsionnoy = "миграционной"
	ppWordVizovoy       = "визовой"
	ppWordVydachi       = "выдачи"
	ppWordRespublika    = "республика"
	ppWordRespubliki    = "республики"
)

// ppMaxStems bounds the cursor array ppFindStems keeps on the stack. Making it
// a compile-time constant is what keeps that scan free of allocations; it must
// stay >= the longest stem table below.
const ppMaxStems = 12

// ppOtherDocWindow is how far left of a digit group a marker naming a DIFFERENT
// document may stand and still claim it. It is deliberately the same 80 bytes
// as docAnchorWindow in docs.go.
const ppOtherDocWindow = 80

var (
	// ppSubdivisionRe requires the label: a bare "770-001" is indistinguishable
	// from a part number, a score or a page range. The three digit layouts are
	// the three ways the code is printed — hyphenated, spaced and solid. A short
	// filler of up to two words is allowed only after the spelled-out label.
	ppSubdivisionRe = regexp.MustCompile(
		`(?:код[ \t]+подразделени[яе]|подразделени[еяю])` +
			`[ \t]*(?:[№#:][ \t]*)?((?:[а-яё]{2,12}[ \t]+){0,2})` +
			`(\d{3}[ \t]*-[ \t]*\d{3}|\d{3}[ \t]+\d{3}|\d{6})`)

	// ppSubdivisionShortRe is the abbreviated label, which takes no filler: a
	// "кп" followed by a word is a different thing ("КПП 770701001").
	ppSubdivisionShortRe = regexp.MustCompile(
		`(?:код[ \t]+подр\.|подр\.|к/п|кп)` +
			`[ \t]*(?:[№#:][ \t]*)?(\d{3}[ \t]*-[ \t]*\d{3}|\d{3}[ \t]+\d{3}|\d{6})`)

	// ppBareSubdivisionRe is the code written as a payload of its own. Only the
	// hyphenated spelling: a bare "450 000" is an amount, "450-000" is not.
	ppBareSubdivisionRe = regexp.MustCompile(`^\d{3}[ \t]*[-–—][ \t]*\d{3}$`)

	// ppLeadDateRe matches an issue date written between the anchor and the
	// authority: "паспорт 4509 123456, выдан 20.06.2015 ГУ МВД России".
	ppLeadDateRe = regexp.MustCompile(
		`^(?:\d{1,2}[./\- ]\d{1,2}[./\- ]\d{2,4}|\d{1,2}[ \t]+[а-яё]{3,12}\.?[ \t]+\d{4})` +
			`(?:[ \t]+(?:года?|г\.))?[ \t,;]*`)
)

func ppFindStems(s string, stems []ppStem, fn func(stem, start, end int)) {
	n := len(stems) // init() has already proved every table fits
	var next [ppMaxStems]int
	for i := 0; i < n; i++ {
		next[i] = strings.Index(s, stems[i].lit)
	}
	for {
		best := ppBestStem(next, n)
		if best < 0 {
			return
		}
		pos := next[best]
		st := &stems[best]
		if end, ok := st.tail(s, pos+len(st.lit)); ok {
			fn(best, pos, end)
		}
		next[best] = ppNextStemPos(s, pos, st.lit)
	}
}

// ppBestStem returns the index of the stem whose next occurrence is earliest,
// or -1 when no stem has a pending occurrence.
func ppBestStem(next [ppMaxStems]int, n int) int {
	best := -1
	for i := 0; i < n; i++ {
		if next[i] >= 0 && (best < 0 || next[i] < next[best]) {
			best = i
		}
	}
	return best
}

// ppNextStemPos returns the offset of the next occurrence of lit after pos, or
// -1 when there is none.
func ppNextStemPos(s string, pos int, lit string) int {
	if j := strings.Index(s[pos+1:], lit); j >= 0 {
		return pos + 1 + j
	}
	return -1
}

func ppIsLowerCyr(r rune) bool { return (r >= 'а' && r <= 'я') || r == 'ё' }

// ppSkipLowerCyr advances past a run of lowercase Cyrillic letters — the manual
// equivalent of the "[а-яё]*" suffix the old patterns used for inflection.
func ppSkipLowerCyr(s string, i int) int {
	for i < len(s) {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if !ppIsLowerCyr(r) {
			break
		}
		i += sz
	}
	return i
}

// ppSkipHorizSpace advances past spaces and tabs only. A line break is never
// crossed: these vocabularies bind a label to a value on one line, and a
// heading followed by unrelated text on the next line is not that.
func ppSkipHorizSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// ppSkipTrailingSpace walks back over spaces and tabs ending at i.
func ppSkipTrailingSpace(s string, i int) int {
	for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		i--
	}
	return i
}

// ppTailPlain accepts the literal as it stands; the caller still checks that
// both of its edges sit on token boundaries.
func ppTailPlain(_ string, i int) (int, bool) { return i, true }

// ppPayloadValue returns the byte range of the payload's self-contained value:
// the whole text minus outer whitespace, minus ONE trailing parenthesised aside
// and minus the sentence punctuation after it. ok=false when nothing is left.
func ppPayloadValue(s string) (start, end int, ok bool) {
	start, end = 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end = ppSkipTrailingSpace(s, end)
	if end > start && s[end-1] == ')' {
		end = ppStripTrailingAside(s, start, end)
	}
	end = ppStripTrailingPunct(s, start, end)
	return start, end, start < end
}

// ppStripTrailingAside removes ONE trailing parenthesised aside and the
// whitespace before it, provided the aside is short enough to be a remark.
func ppStripTrailingAside(s string, start, end int) int {
	open := -1
	for i := end - 1; i >= start; i-- {
		if s[i] == '(' {
			open = i
			break
		}
	}
	if open >= start && end-1-open <= ppBareAsideBytes {
		end = ppSkipTrailingSpace(s, open)
	}
	return end
}

// ppStripTrailingPunct removes the sentence punctuation and whitespace at the
// end of the payload.
func ppStripTrailingPunct(s string, start, end int) int {
	for end > start {
		c := s[end-1]
		if c == '.' || c == ',' || c == ';' || c == ':' || c == '!' || c == '?' ||
			c == ' ' || c == '\t' {
			end--
			continue
		}
		break
	}
	return end
}

func ppDigitsExact(s string, i, n int) int {
	if i+n > len(s) {
		return -1
	}
	for k := 0; k < n; k++ {
		if s[i+k] < '0' || s[i+k] > '9' {
			return -1
		}
	}
	return i + n
}

// ppHasDigit is a cheap guard that skips the numeric patterns entirely on texts
// without a single digit.
func ppHasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func ppOnBoundaries(s string, start, end int) bool {
	return text.IsBoundary(s, start) && text.IsBoundary(s, end)
}

func ppOverlaps(spans []pd.Span, s, e int) bool {
	for _, sp := range spans {
		if s < sp.End && sp.Start < e {
			return true
		}
	}
	return false
}

// ppSkipLeadSep advances past the whitespace and punctuation that separate an
// anchor from its value ("кем выдан: ..."). It never crosses a line break.
func ppSkipLeadSep(s string, i int) int {
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '\n' || r == '\r' {
			return i
		}
		if unicode.IsSpace(r) || strings.ContainsRune(":—–-№\"«»", r) {
			i += size
			continue
		}
		return i
	}
	return i
}

func ppTokenFrom(ctx *Context, off int) int {
	return sort.Search(len(ctx.Tokens), func(i int) bool { return ctx.Tokens[i].Start >= off })
}

// ppRoleGenitive are the genitive-case subjects that may stand between a
// citizenship or birthplace anchor and its colon: "Гражданство поручителя: ...".
var ppRoleGenitive = map[string]struct{}{
	"поручителя": {}, "бенефициара": {}, "клиента": {}, "заемщика": {},
	"заёмщика": {}, "созаемщика": {}, "созаёмщика": {}, "вкладчика": {},
	"держателя": {}, "владельца": {}, "наследника": {},
}

// ppNextWordToken returns the index of the next KindWord token at or after i+1,
// or -1 when there is none.
func ppNextWordToken(ctx *Context, i int) int {
	for i++; i < len(ctx.Tokens); i++ {
		if ctx.Tokens[i].Kind == text.KindWord {
			return i
		}
	}
	return -1
}

// ppLeadSepRole returns the offset just past the colon that follows the anchor
// ending at from, allowing between one and four role words — a genitive subject
// and/or a "по ..." clarification — to stand between the anchor and the colon.
// It returns -1 when the words between the anchor and the colon are not a valid
// role phrase, when there is no colon, or when the phrase is longer than four
// words. The plain "anchor: value" form is deliberately left to ppSkipLeadSep.
func ppLeadSepRole(ctx *Context, from int) int {
	i := ppTokenFrom(ctx, from)
	words := 0
	for i < len(ctx.Tokens) {
		t := ctx.Tokens[i]
		switch t.Kind {
		case text.KindSpace:
			i++
		case text.KindPunct:
			if end, ok := ppRoleColon(ctx, t, words); ok {
				return end
			}
			i++
		case text.KindWord:
			i = ppRoleWordAdvance(ctx, i, &words)
			if i < 0 {
				return -1
			}
		default:
			return -1
		}
	}
	return -1
}

// ppRoleColon returns the offset just past a colon that closes a role phrase of
// between one and four words, or ok=false when the token is not such a colon.
func ppRoleColon(ctx *Context, t text.Token, words int) (int, bool) {
	if t.In(ctx.Text) != ":" {
		return 0, false
	}
	if words >= 1 && words <= 4 {
		return t.End, true
	}
	return 0, false
}

// ppRoleWordAdvance consumes one role word at token index i, updating the word
// count, and returns the next token index, or -1 when the phrase is invalid.
func ppRoleWordAdvance(ctx *Context, i int, words *int) int {
	next, nw := ppRoleWord(ctx, i)
	if next < 0 {
		return -1
	}
	*words += nw
	if *words > 4 {
		return -1
	}
	return next
}

// ppRoleWord advances past one role word at token index i, returning the next
// token index and the number of words consumed, or -1 when the word is not a
// valid role phrase element.
func ppRoleWord(ctx *Context, i int) (next, words int) {
	t := ctx.Tokens[i]
	w := t.In(ctx.Lower)
	if _, ok := ppRoleGenitive[w]; ok {
		return i + 1, 1
	}
	if w == "доверенного" {
		j := ppNextWordToken(ctx, i)
		if j < 0 || ctx.Tokens[j].In(ctx.Lower) != "лица" {
			return -1, 0
		}
		return j + 1, 2
	}
	if w == "по" {
		return ppRoleByPhrase(ctx, i)
	}
	return -1, 0
}

// ppRoleByPhrase advances past a "по ..." clarification at token index i.
func ppRoleByPhrase(ctx *Context, i int) (int, int) {
	j := ppNextWordToken(ctx, i)
	if j < 0 {
		return -1, 0
	}
	nw := ctx.Tokens[j].In(ctx.Lower)
	switch nw {
	case "договору":
		k := ppNextWordToken(ctx, j)
		if k >= 0 && ctx.Tokens[k].In(ctx.Lower) == "страхования" {
			return k + 1, 3
		}
		return j + 1, 2
	case "кредиту", "вкладу":
		return j + 1, 2
	default:
		return -1, 0
	}
}

// ppQuoteBefore reports whether the token immediately before pos is an opening
// quote («, " or ').
func ppQuoteBefore(ctx *Context, pos int) bool {
	for i := ppTokenFrom(ctx, pos) - 1; i >= 0; i-- {
		t := ctx.Tokens[i]
		if t.Kind == text.KindSpace {
			continue
		}
		if t.Kind == text.KindPunct {
			q := t.In(ctx.Text)
			return q == "«" || q == "\"" || q == "'"
		}
		return false
	}
	return false
}

// ppQuotedLabelLeadSep handles the form "в поле «Гражданство» указано: <value>"
// (or "в графе ..."). The anchor is the label inside the quotes; after it come
// the closing quote, the verb "указано"/"указан"/"указана"/"значится" and a
// colon. It returns the offset just past the colon, or -1 when the pattern does
// not hold.
func ppQuotedLabelLeadSep(ctx *Context, start, end int) int {
	if !ppQuoteBefore(ctx, start) {
		return -1
	}
	i := ppNextNonSpace(ctx, ppTokenFrom(ctx, end))
	if i < 0 || ctx.Tokens[i].Kind != text.KindPunct {
		return -1
	}
	q := ctx.Tokens[i].In(ctx.Text)
	if q != "»" && q != "\"" && q != "'" {
		return -1
	}
	i = ppNextNonSpace(ctx, i+1)
	if i < 0 || ctx.Tokens[i].Kind != text.KindWord {
		return -1
	}
	w := ctx.Tokens[i].In(ctx.Lower)
	if w != "указано" && w != "указан" && w != "указана" && w != "значится" {
		return -1
	}
	i = ppNextNonSpace(ctx, i+1)
	if i < 0 || ctx.Tokens[i].Kind != text.KindPunct || ctx.Tokens[i].In(ctx.Text) != ":" {
		return -1
	}
	return ctx.Tokens[i].End
}

// ppNextNonSpace returns the index of the next non-space token at or after i,
// or -1 when there is none.
func ppNextNonSpace(ctx *Context, i int) int {
	for i < len(ctx.Tokens) && ctx.Tokens[i].Kind == text.KindSpace {
		i++
	}
	if i >= len(ctx.Tokens) {
		return -1
	}
	return i
}

// ppWordAfter returns the lower-cased word that follows off, or "" when the
// next non-space token is not a word.
func ppWordAfter(ctx *Context, off int) string {
	for i := ppTokenFrom(ctx, off); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.Kind == text.KindSpace {
			continue
		}
		if t.Kind == text.KindWord {
			return t.In(ctx.Lower)
		}
		return ""
	}
	return ""
}

// ppWordBefore returns the lower-cased word that precedes off, or "".
func ppWordBefore(ctx *Context, off int) string {
	for i := ppTokenFrom(ctx, off) - 1; i >= 0; i-- {
		t := ctx.Tokens[i]
		if t.Kind == text.KindSpace {
			continue
		}
		if t.Kind == text.KindWord {
			return t.In(ctx.Lower)
		}
		return ""
	}
	return ""
}

var ppAnchorStems = []ppStem{
	{lit: "пасп", tail: ppTailPassport},
	{lit: "сери", tail: ppTailSeriesNoun},
	{lit: "passport", tail: ppTailPassportLatin},
	{lit: "удостоверени", tail: ppTailIdentityCard},
	{lit: "документ", tail: ppTailIdentityDoc},
	{lit: "п/п", tail: ppTailShortPassport},
}

// ppTailPassport accepts "паспорт" in any case form, the abbreviation "пасп."
// and the bare stem. "паспарту" is rejected.
func ppTailPassport(s string, i int) (int, bool) {
	if strings.HasPrefix(s[i:], "орт") {
		return ppSkipLowerCyr(s, i+len("орт")), true
	}
	if i < len(s) && s[i] == '.' {
		return i + 1, true
	}
	return i, text.IsBoundary(s, i)
}

// ppTailSeriesNoun accepts "серия" and "серии" — and deliberately nothing
// longer, because a suffix wildcard here would also match "серийный".
func ppTailSeriesNoun(s string, i int) (int, bool) {
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r != 'я' && r != 'и' {
		return 0, false
	}
	return i + sz, true
}

func ppTailPassportLatin(s string, i int) (int, bool) {
	if i < len(s) && s[i] == 's' {
		i++
	}
	return i, true
}

// ppTailIdentityCard completes "удостоверение личности". The noun alone is not
// an anchor: it also heads a driving licence, which is another detector's.
func ppTailIdentityCard(s string, i int) (int, bool) {
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r != 'е' && r != 'я' {
		return 0, false
	}
	j := ppSkipHorizSpace(s, i+sz)
	if j == i+sz || !strings.HasPrefix(s[j:], "личности") {
		return 0, false
	}
	return j + len("личности"), true
}

// ppTailIdentityDoc completes "документ, удостоверяющий личность".
func ppTailIdentityDoc(s string, i int) (int, bool) {
	i = ppSkipLowerCyr(s, i)
	if i < len(s) && s[i] == ',' {
		i++
	}
	j := ppSkipHorizSpace(s, i)
	if j == i || !strings.HasPrefix(s[j:], "удостоверяющи") {
		return 0, false
	}
	j += len("удостоверяющи")
	r, sz := utf8.DecodeRuneInString(s[j:])
	if r != 'й' && r != 'е' {
		return 0, false
	}
	k := ppSkipHorizSpace(s, j+sz)
	if k == j+sz || !strings.HasPrefix(s[k:], "личность") {
		return 0, false
	}
	return k + len("личность"), true
}

// ppTailShortPassport accepts "п/п" as the abbreviation of "паспорт", but not
// where it is the "№ п/п" of a numbered table column.
func ppTailShortPassport(s string, i int) (int, bool) {
	j := ppSkipTrailingSpace(s, i-len("п/п"))
	if j > 0 && (strings.HasSuffix(s[:j], "№") || strings.HasSuffix(s[:j], "#") ||
		strings.HasSuffix(s[:j], "номер") || strings.HasSuffix(s[:j], "номера")) {
		return 0, false
	}
	return i, text.IsBoundary(s, i)
}

func ppAnchors(ctx *Context) []ppSpan {
	var out []ppSpan
	lastEnd := -1
	ppFindStems(ctx.Lower, ppAnchorStems, func(_, start, end int) {
		if end <= lastEnd || !ppOnBoundaries(ctx.Text, start, end) {
			return
		}
		if _, meta := ppMetaphorWords[ppWordAfter(ctx, end)]; meta {
			return
		}
		out = append(out, ppSpan{start: start, end: end})
		lastEnd = end
	})
	return out
}

var (
	ppSeriesStems = []ppStem{
		{lit: "сер", tail: ppTailSeriesLabel},
		{lit: "с.", tail: ppTailPlain},
	}

	ppNumberStems = []ppStem{
		{lit: "номер", tail: ppTailNumberWord},
		{lit: "ном", tail: ppTailDot},
		{lit: "н.", tail: ppTailPlain},
		{lit: "№", tail: ppTailPlain, bare: true},
		{lit: "#", tail: ppTailPlain, bare: true},
		{lit: "n", tail: ppTailLatinNumero, bare: true},
	}
)

// ppTailSeriesLabel accepts "серия", "серии", "сер." and a bare "сер", and
// rejects "серийный".
func ppTailSeriesLabel(s string, i int) (int, bool) {
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r == 'и' || r == 'я' {
		return ppTailSeriesVowel(s, i+sz, r)
	}
	if i < len(s) && s[i] == '.' {
		return i + 1, true
	}
	return i, text.IsBoundary(s, i)
}

// ppTailSeriesVowel completes the vowel-ending forms of "серия": "серии",
// "серия", "серии" and "серие" (as in "серией"), rejecting "серийный".
func ppTailSeriesVowel(s string, j int, r rune) (int, bool) {
	if text.IsBoundary(s, j) {
		return j, true
	}
	r2, sz2 := utf8.DecodeRuneInString(s[j:])
	if r == 'и' && (r2 == 'я' || r2 == 'и' || r2 == 'ю') && text.IsBoundary(s, j+sz2) {
		return j + sz2, true
	}
	if r == 'и' && r2 == 'е' {
		k := j + sz2
		r3, sz3 := utf8.DecodeRuneInString(s[k:])
		if r3 == 'й' && text.IsBoundary(s, k+sz3) {
			return k + sz3, true
		}
	}
	return 0, false
}

// ppTailNumberWord accepts "номер" and its case forms up to two letters long —
// номера, номеру, номером, номере. The cap keeps "номерной знак" out.
func ppTailNumberWord(s string, i int) (int, bool) {
	for k := 0; k < 2; k++ {
		if text.IsBoundary(s, i) {
			return i, true
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		if !ppIsLowerCyr(r) {
			return i, true
		}
		i += sz
	}
	if text.IsBoundary(s, i) {
		return i, true
	}
	return 0, false
}

// ppTailDot requires the period that makes an abbreviation ("ном.").
func ppTailDot(s string, i int) (int, bool) {
	if i < len(s) && s[i] == '.' {
		return i + 1, true
	}
	return 0, false
}

// ppTailLatinNumero accepts the Latin forms — "N", "No", "N." and "No.".
func ppTailLatinNumero(s string, i int) (int, bool) {
	if i < len(s) && s[i] == 'o' {
		i++
	}
	if i < len(s) && s[i] == '.' {
		i++
	}
	return i, true
}

// ppIsNumberMark reports the punctuation that may stand between a series and a
// number without breaking them into two values.
func ppIsNumberMark(r rune) bool {
	switch r {
	case '-', '–', '—', '/', '№', '#':
		return true
	}
	return false
}

// Ordered most specific first: the first layout that matches at a position
// wins, so "4509 12 34 56" is never truncated to "4509 12".
var ppJoinedLayouts = []ppDigitLayout{
	{groups: []uint8{2, 2, 2, 2, 2}, strictTail: true},
	{groups: []uint8{4, 2, 2, 2}, strictTail: true},
	{groups: []uint8{4, 3, 3}, strictTail: true},
	{groups: []uint8{2, 2, 6}, flexLast: true},
	{groups: []uint8{4, 6}, flexLast: true},
}

var (
	ppSeriesLayouts = []ppDigitLayout{
		{groups: []uint8{2, 2}},
		{groups: []uint8{4}},
	}
	ppNumberLayouts = []ppDigitLayout{
		{groups: []uint8{2, 2, 2}, strictTail: true},
		{groups: []uint8{3, 3}, strictTail: true},
		{groups: []uint8{6}},
	}
)

// ppMatchLayout matches one layout at i and returns the end offset, or -1.
func ppMatchLayout(s string, i int, l *ppDigitLayout) int {
	for g := 0; g < len(l.groups); g++ {
		if g > 0 {
			j := ppLayoutSeparator(s, i, g == len(l.groups)-1 && l.flexLast)
			if j < 0 {
				return -1
			}
			i = j
		}
		e := ppDigitsExact(s, i, int(l.groups[g]))
		if e < 0 {
			return -1
		}
		i = e
	}
	return i
}

// ppLayoutSeparator returns the offset just past the separator before a group,
// or -1 when the separator is missing. flexLast allows the separator before the
// last group to be empty or a single number mark.
func ppLayoutSeparator(s string, i int, flexLast bool) int {
	j := ppSkipHorizSpace(s, i)
	if flexLast {
		if j < len(s) {
			if r, sz := utf8.DecodeRuneInString(s[j:]); ppIsNumberMark(r) {
				j = ppSkipHorizSpace(s, j+sz)
			}
		}
		return j
	}
	if j == i {
		return -1
	}
	return j
}

// ppBareGroupings are the whole-payload shapes of a passport series+number.
// Unlike ppJoinedLayouts they demand a NON-EMPTY separator between every pair
// of groups: the grouping is the only evidence there is, so "1234567890" — the
// existing golden negative — must not match.
var ppBareGroupings = [][]uint8{{4, 6}, {2, 2, 6}}

// ppMatchBare matches groups at i requiring a non-empty separator between every
// pair: a run of spaces/tabs, or one ppIsNumberMark rune optionally padded.
func ppMatchBare(s string, i int, groups []uint8) int {
	for g := 0; g < len(groups); g++ {
		if g > 0 {
			j := ppBareSeparator(s, i)
			if j < 0 {
				return -1
			}
			i = j
		}
		e := ppDigitsExact(s, i, int(groups[g]))
		if e < 0 {
			return -1
		}
		i = e
	}
	return i
}

// ppBareSeparator returns the offset just past a NON-EMPTY separator before a
// group: a run of spaces/tabs, or one number mark optionally padded. It returns
// -1 when there is no separator at all.
func ppBareSeparator(s string, i int) int {
	j := ppSkipHorizSpace(s, i)
	if j == i {
		if j < len(s) {
			if r, sz := utf8.DecodeRuneInString(s[j:]); ppIsNumberMark(r) {
				return ppSkipHorizSpace(s, j+sz)
			}
		}
		return -1
	}
	if j < len(s) {
		if r, sz := utf8.DecodeRuneInString(s[j:]); ppIsNumberMark(r) {
			j = ppSkipHorizSpace(s, j+sz)
		}
	}
	return j
}

// ppGroupAdjacent reports a whitespace-separated digit group directly before
// start or directly after end.
func ppGroupAdjacent(s string, start, end int) bool {
	if j := ppSkipHorizSpace(s, end); j > end && j < len(s) && s[j] >= '0' && s[j] <= '9' {
		return true
	}
	j := ppSkipTrailingSpace(s, start)
	return j < start && j > 0 && s[j-1] >= '0' && s[j-1] <= '9'
}

func (d passportDetector) numbers(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypePassport) {
		return out
	}
	anchors := ppAnchors(ctx)
	base := len(out)

	out = d.joined(ctx, anchors, out, base)

	series := ppLabels(ctx, ppSeriesStems, ppSeriesLayouts, out[base:], false)
	numbers := ppLabels(ctx, ppNumberStems, ppNumberLayouts, out[base:], true)

	out = ppSeriesSpans(ctx, anchors, series, numbers, out)
	out = ppNumberSpans(ctx, anchors, series, numbers, out)
	out = ppBareSeriesNumber(ctx, out, base)
	return d.corroborated(ctx, anchors, out, base)
}

// ppSeriesSpans emits a passport span for each series label that is paired with
// a number or stands near a passport anchor.
func ppSeriesSpans(ctx *Context, anchors []ppSpan, series, numbers []ppLabel, out []pd.Span) []pd.Span {
	for _, s := range series {
		if ppOtherDocumentLeft(ctx, anchors, s.digStart) {
			continue
		}
		if ppPairedAfter(numbers, s.digEnd) || ppPairedNumberBefore(numbers, s.labelStart) ||
			ppAnchorNear(anchors, s.labelStart, ppAnchorWindow) {
			out = append(out, pd.Span{
				Start: s.digStart, End: s.digEnd, Type: pd.TypePassport,
				Conf: ppConfPassport, Src: detectorPassport, Hint: "series",
			})
		}
	}
	return out
}

// ppNumberSpans emits a passport span for each number label that is paired with
// a series or stands near a passport anchor. A bare number label needs a pair.
func ppNumberSpans(ctx *Context, anchors []ppSpan, series, numbers []ppLabel, out []pd.Span) []pd.Span {
	for _, n := range numbers {
		if ppOtherDocumentLeft(ctx, anchors, n.digStart) {
			continue
		}
		paired := ppPairedBefore(series, n.labelStart) || ppPairedSeriesAfter(series, n.digEnd)
		if n.bare && !paired {
			continue
		}
		if paired || ppAnchorNear(anchors, n.labelStart, ppAnchorWindow) {
			out = append(out, pd.Span{
				Start: n.digStart, End: n.digEnd, Type: pd.TypePassport,
				Conf: ppConfPassport, Src: detectorPassport, Hint: "number",
			})
		}
	}
	return out
}

// ppBareSeriesNumber claims a whole-payload series+number written without any
// label, provided no earlier span already covers it.
func ppBareSeriesNumber(ctx *Context, out []pd.Span, base int) []pd.Span {
	s, e, ok := ppPayloadValue(ctx.Text)
	if !ok || ppOverlaps(out[base:], s, e) {
		return out
	}
	for _, g := range ppBareGroupings {
		if ppMatchBare(ctx.Text, s, g) == e {
			return append(out, pd.Span{
				Start: s, End: e, Type: pd.TypePassport,
				Conf: ppConfBareValue, Src: detectorPassport, Hint: "bare_series_number",
			})
		}
	}
	return out
}

func ppPairedAfter(numbers []ppLabel, seriesEnd int) bool {
	for _, n := range numbers {
		if n.labelStart >= seriesEnd && n.labelStart-seriesEnd <= ppPairWindow {
			return true
		}
	}
	return false
}

func ppPairedBefore(series []ppLabel, numberLabel int) bool {
	for _, s := range series {
		if s.digEnd <= numberLabel && numberLabel-s.digEnd <= ppPairWindow {
			return true
		}
	}
	return false
}

func ppPairedNumberBefore(numbers []ppLabel, seriesLabel int) bool {
	for _, n := range numbers {
		if n.digEnd <= seriesLabel && seriesLabel-n.digEnd <= ppPairWindow {
			return true
		}
	}
	return false
}

func ppPairedSeriesAfter(series []ppLabel, numberEnd int) bool {
	for _, s := range series {
		if s.labelStart >= numberEnd && s.labelStart-numberEnd <= ppPairWindow {
			return true
		}
	}
	return false
}

// ppCorroborated claims two series+number groups that stand side by side with
// nothing but a conjunction between them. One such group inside prose is an
// order number (golden doc2-neg-03); two of them joined only by "и" is a list.
func (d passportDetector) corroborated(ctx *Context, anchors []ppSpan, out []pd.Span, base int) []pd.Span {
	groups := ppBareGroups(ctx)
	for i := 1; i < len(groups); i++ {
		prev, cur := groups[i-1], groups[i]
		if !ppCorroboratePair(ctx, anchors, out, base, prev, cur) {
			continue
		}
		out = append(out, pd.Span{
			Start: prev.start, End: prev.end, Type: pd.TypePassport,
			Conf: ppConfBareValue, Src: detectorPassport, Hint: "corroborated",
		})
		out = append(out, pd.Span{
			Start: cur.start, End: cur.end, Type: pd.TypePassport,
			Conf: ppConfBareValue, Src: detectorPassport, Hint: "corroborated",
		})
	}
	return out
}

// ppBareGroups returns every bare series+number group in the payload, in order.
func ppBareGroups(ctx *Context) []ppSpan {
	lower := ctx.Lower
	var groups []ppSpan
	for i := 0; i < len(lower); i++ {
		if lower[i] < '0' || lower[i] > '9' || !text.IsBoundary(ctx.Text, i) {
			continue
		}
		for _, g := range ppBareGroupings {
			e := ppMatchBare(lower, i, g)
			if e < 0 || !text.IsBoundary(ctx.Text, e) {
				continue
			}
			groups = append(groups, ppSpan{start: i, end: e})
			i = e - 1
			break
		}
	}
	return groups
}

// ppCorroboratePair reports whether two adjacent bare groups stand close enough
// and are not claimed by another span or a different document.
func ppCorroboratePair(ctx *Context, anchors []ppSpan, out []pd.Span, base int, prev, cur ppSpan) bool {
	if cur.start-prev.end > ppCorroborateGap {
		return false
	}
	if !ppCorroborateGapOK(ctx, prev.end, cur.start) {
		return false
	}
	if ppCorroborateNoise(ctx, prev.start) || ppCorroborateNoise(ctx, cur.start) {
		return false
	}
	if ppOtherDocumentLeft(ctx, anchors, prev.start) || ppOtherDocumentLeft(ctx, anchors, cur.start) {
		return false
	}
	if ppOverlaps(out[base:], prev.start, prev.end) || ppOverlaps(out[base:], cur.start, cur.end) {
		return false
	}
	return true
}

// ppCorroborateGapOK reports whether the bytes between two groups are only
// spaces, commas, semicolons and at most one conjunction "и"/"and".
func ppCorroborateGapOK(ctx *Context, from, to int) bool {
	conj := 0
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens) && ctx.Tokens[i].Start < to; i++ {
		if !ppCorroborateGapToken(ctx, ctx.Tokens[i], &conj) {
			return false
		}
	}
	return true
}

// ppCorroborateGapToken reports whether one token is acceptable inside the gap
// between two corroborating groups.
func ppCorroborateGapToken(ctx *Context, t text.Token, conj *int) bool {
	switch t.Kind {
	case text.KindSpace:
		return true
	case text.KindPunct:
		switch t.In(ctx.Text) {
		case ",", ";":
			return true
		default:
			return false
		}
	case text.KindWord:
		w := t.In(ctx.Lower)
		if w != "и" && w != "and" {
			return false
		}
		*conj++
		return *conj <= 1
	default:
		return false
	}
}

// ppCorroborateNoise reports whether the word left of a group is a noise or
// metaphor word that makes the group an order/article rather than a passport.
func ppCorroborateNoise(ctx *Context, groupStart int) bool {
	w := ppWordBefore(ctx, groupStart)
	if _, noise := ppNumberNoiseWords[w]; noise {
		return true
	}
	_, meta := ppMetaphorWords[w]
	return meta
}

// ppAnchorNear reports whether an anchor ends no more than window bytes before
// pos. Anchors come out in ascending order, so only the closest one can qualify.
func ppAnchorNear(anchors []ppSpan, pos, window int) bool {
	i := sort.Search(len(anchors), func(k int) bool { return anchors[k].end > pos })
	if i == 0 {
		return false
	}
	return pos-anchors[i-1].end <= window
}

// ppNamedAnchorNear walks back over the WHOLE window instead of stopping at the
// closest anchor, because a generic "серия" standing between the word "паспорт"
// and the digits must not hide it.
func ppNamedAnchorNear(lower string, anchors []ppSpan, pos, window int) bool {
	i := sort.Search(len(anchors), func(k int) bool { return anchors[k].end > pos })
	for i--; i >= 0; i-- {
		if pos-anchors[i].end > window {
			return false
		}
		if ppAnchorNamesDocument(lower, anchors[i]) {
			return true
		}
	}
	return false
}

// ppAnchorNamesDocument reports whether an anchor actually says "passport".
func ppAnchorNamesDocument(lower string, a ppSpan) bool {
	return !strings.HasPrefix(lower[a.start:a.end], "сери")
}

func (d passportDetector) joined(ctx *Context, anchors []ppSpan, out []pd.Span, base int) []pd.Span {
	lower := ctx.Lower
	high := 0
	for _, a := range anchors {
		from, to := ppAnchorWindowBounds(a, high, len(lower))
		for p := from; p < to; p++ {
			if !ppIsDigitBoundary(lower, ctx.Text, p) {
				continue
			}
			if e := ppJoinedMatch(ctx, anchors, out, base, lower, p); e > p {
				out = append(out, pd.Span{
					Start: p, End: e, Type: pd.TypePassport,
					Conf: ppConfPassport, Src: detectorPassport, Hint: "series_number",
				})
				p = e - 1
			}
		}
		if to > high {
			high = to
		}
	}
	return out
}

// ppAnchorWindowBounds returns the [from,to) byte window an anchor may scan for
// a joined series+number, clamped to the already-scanned high watermark.
func ppAnchorWindowBounds(a ppSpan, high, length int) (int, int) {
	from, to := a.end, a.end+ppAnchorWindow+1
	if from < high {
		from = high
	}
	if to > length {
		to = length
	}
	return from, to
}

// ppIsDigitBoundary reports whether byte p is a digit on a token boundary.
func ppIsDigitBoundary(lower, s string, p int) bool {
	return lower[p] >= '0' && lower[p] <= '9' && text.IsBoundary(s, p)
}

// ppJoinedMatch tries every joined layout at p and returns the end offset of
// the first that fits, or -1 when none does.
func ppJoinedMatch(ctx *Context, anchors []ppSpan, out []pd.Span, base int, lower string, p int) int {
	for li := range ppJoinedLayouts {
		l := &ppJoinedLayouts[li]
		e := ppMatchLayout(lower, p, l)
		if e < 0 || !text.IsBoundary(ctx.Text, e) {
			continue
		}
		if l.strictTail && ppGroupAdjacent(lower, p, e) {
			break
		}
		if ppOverlaps(out[base:], p, e) || !ppAnchorNear(anchors, p, ppAnchorWindow) {
			break
		}
		if ppOtherDocumentLeft(ctx, anchors, p) {
			break
		}
		return e
	}
	return -1
}

func ppLabels(ctx *Context, stems []ppStem, layouts []ppDigitLayout, taken []pd.Span, checkNoise bool) []ppLabel {
	var out []ppLabel
	ppFindStems(ctx.Lower, stems, func(si, start, end int) {
		if !text.IsBoundary(ctx.Text, start) {
			return
		}
		ds, de := ppLabelValue(ctx.Lower, end, layouts)
		if ds < 0 || !ppOnBoundaries(ctx.Text, ds, de) || ppOverlaps(taken, ds, de) {
			return
		}
		if checkNoise {
			if _, noise := ppNumberNoiseWords[ppWordBefore(ctx, start)]; noise {
				return
			}
		}
		out = append(out, ppLabel{
			labelStart: start, digStart: ds, digEnd: de, bare: stems[si].bare,
		})
	})
	return out
}

// ppLabelValue tolerates horizontal whitespace and one separator mark between
// the label and the digits: "Серия: 4509" and "Серия № 4509".
func ppLabelValue(s string, labelEnd int, layouts []ppDigitLayout) (int, int) {
	i := ppSkipHorizSpace(s, labelEnd)
	if i < len(s) {
		if r, sz := utf8.DecodeRuneInString(s[i:]); r == ':' || ppIsNumberMark(r) {
			i = ppSkipHorizSpace(s, i+sz)
		}
	}
	for li := range layouts {
		l := &layouts[li]
		if e := ppMatchLayout(s, i, l); e > 0 {
			if l.strictTail && ppGroupAdjacent(s, i, e) {
				continue
			}
			return i, e
		}
	}
	return -1, -1
}

var ppMetaphorWords = map[string]struct{}{
	"проект": {}, "проекта": {}, "проекту": {}, "проектом": {},
	"сделка": {}, "сделки": {}, "сделку": {},
	"объект": {}, "объекта": {}, "объекту": {},
	"изделие": {}, "изделия": {}, "товар": {}, "товара": {},
	"качества": {}, "безопасности": {}, "здоровья": {},
	"продукт": {}, "продукта": {}, "процесс": {}, "процесса": {},
	"услуги": {}, "оборудования": {}, "станка": {}, "отходов": {},
	"здания": {}, "дома": {}, "квартиры": {}, "маршрута": {}, "вакансии": {},
}

var ppNumberNoiseWords = map[string]struct{}{
	"инвентарный": {}, "инвентарного": {}, "серийный": {}, "серийного": {},
	"регистрационный": {}, "учетный": {}, "учётный": {}, "заводской": {},
	"лицевой": {}, "порядковый": {}, "кадастровый": {}, "табельный": {},
	"договор": {}, "договора": {}, "заказ": {}, "заказа": {},
	"счет": {}, "счёт": {}, "счета": {}, "счёта": {},
	"телефон": {}, "телефона": {}, "контактный": {}, "мобильный": {},
	"государственный": {}, "гос": {}, "складской": {}, "партии": {},
	"заявка": {}, "заявки": {}, "заявке": {}, "заявку": {},
	"обращение": {}, "обращения": {}, "обращению": {},
	"квитанция": {}, "квитанции": {}, "квитанцию": {},
	"чек": {}, "чека": {}, "чеку": {},
	"тикет": {}, "тикета": {}, "талон": {}, "талона": {},
	"претензия": {}, "претензии": {}, "накладная": {}, "накладной": {},
	"операция": {}, "операции": {}, "перевод": {}, "перевода": {},
	"платеж": {}, "платёж": {}, "платежа": {}, "платежное": {},
	"полис": {}, "полиса": {}, "рейс": {}, "рейса": {}, "кабинет": {},
	"позиция": {}, "позиции": {}, "позиций": {},
	"артикул": {}, "артикула": {}, "артикулы": {}, "артикулов": {},
	"партия": {}, "партий": {},
}

func (d passportDetector) subdivision(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypeSubdivisionCode) || !ppHasDigit(ctx.Lower) {
		return out
	}
	base := len(out)
	if strings.Contains(ctx.Lower, "подр") || strings.Contains(ctx.Lower, "к/п") ||
		strings.Contains(ctx.Lower, "кп") {
		out = ppLabelledSubdivision(ctx, out)
	}
	out = ppBareSubdivision(ctx, out, base)
	return ppSubdivisionNearAuthority(ctx, out, base)
}

// ppLabelledSubdivision runs the two labelled subdivision patterns. The
// spelled-out label allows a short filler of up to two words; the abbreviated
// label takes none. The filler is rejected if any of its words is a metaphor.
func ppLabelledSubdivision(ctx *Context, out []pd.Span) []pd.Span {
	for _, m := range ppSubdivisionRe.FindAllStringSubmatchIndex(ctx.Lower, -1) {
		ds, de := m[4], m[5]
		if ds < 0 || !text.IsBoundary(ctx.Text, m[0]) || !ppOnBoundaries(ctx.Text, ds, de) {
			continue
		}
		if ppFillerMetaphor(ctx.Lower, m[2], m[3]) {
			continue
		}
		out = append(out, pd.Span{
			Start: ds, End: de, Type: pd.TypeSubdivisionCode,
			Conf: ppConfSubdivision, Src: detectorPassport, Hint: "subdivision",
		})
	}
	for _, m := range ppSubdivisionShortRe.FindAllStringSubmatchIndex(ctx.Lower, -1) {
		ds, de := m[2], m[3]
		if ds < 0 || !text.IsBoundary(ctx.Text, m[0]) || !ppOnBoundaries(ctx.Text, ds, de) {
			continue
		}
		out = append(out, pd.Span{
			Start: ds, End: de, Type: pd.TypeSubdivisionCode,
			Conf: ppConfSubdivision, Src: detectorPassport, Hint: "subdivision",
		})
	}
	return out
}

// ppFillerMetaphor reports whether the filler between the label and the code
// contains a metaphor word that makes the code a project/object number.
func ppFillerMetaphor(lower string, from, to int) bool {
	if from < 0 || to < 0 {
		return false
	}
	for _, w := range strings.Fields(lower[from:to]) {
		if _, meta := ppMetaphorWords[w]; meta {
			return true
		}
	}
	return false
}

// ppBareSubdivision claims a NNN-NNN code written as the whole payload.
func ppBareSubdivision(ctx *Context, out []pd.Span, base int) []pd.Span {
	s, e, ok := ppPayloadValue(ctx.Text)
	if !ok || ppOverlaps(out[base:], s, e) {
		return out
	}
	if !ppBareSubdivisionRe.MatchString(ctx.Lower[s:e]) {
		return out
	}
	return append(out, pd.Span{
		Start: s, End: e, Type: pd.TypeSubdivisionCode,
		Conf: ppConfBareValue, Src: detectorPassport, Hint: "bare_subdivision",
	})
}

// ppSubdivisionNearAuthority claims a NNN-NNN group standing behind an
// authority name — "ОВД №45, 770-045". The authority is the label.
//
// It runs AFTER the labelled pass and skips any group that pass already
// claimed. Without that guard it double-claims the code in the ordinary
// "выдан ОВД …, код подразделения NNN-NNN" block, where BOTH the label and
// the authority stand in range.
func ppSubdivisionNearAuthority(ctx *Context, out []pd.Span, base int) []pd.Span {
	lower := ctx.Lower
	for i := 0; i < len(lower); i++ {
		if lower[i] < '0' || lower[i] > '9' || !text.IsBoundary(ctx.Text, i) {
			continue
		}
		e := ppMatchSubdivisionGroup(lower, i)
		if e < 0 || !text.IsBoundary(ctx.Text, e) {
			continue
		}
		if ppOverlaps(out[base:], i, e) {
			continue
		}
		if !ppAuthorityLeft(ctx, i) {
			continue
		}
		if ppCorroborateNoise(ctx, i) {
			continue
		}
		out = append(out, pd.Span{
			Start: i, End: e, Type: pd.TypeSubdivisionCode,
			Conf: ppConfBareValue, Src: detectorPassport, Hint: "subdivision_authority",
		})
	}
	return out
}

// ppMatchSubdivisionGroup matches a NNN-NNN group at i, returning its end.
func ppMatchSubdivisionGroup(s string, i int) int {
	if i+3 > len(s) {
		return -1
	}
	for k := 0; k < 3; k++ {
		if s[i+k] < '0' || s[i+k] > '9' {
			return -1
		}
	}
	j := ppSkipHorizSpace(s, i+3)
	if j >= len(s) || s[j] != '-' {
		return -1
	}
	j = ppSkipHorizSpace(s, j+1)
	if j+3 > len(s) {
		return -1
	}
	for k := 0; k < 3; k++ {
		if s[j+k] < '0' || s[j+k] > '9' {
			return -1
		}
	}
	return j + 3
}

// ppAuthorityLeft reports whether a strong authority token or an authority
// head+qualifier phrase stands within ppAnchorWindow bytes to the left of pos.
func ppAuthorityLeft(ctx *Context, pos int) bool {
	for i := ppTokenFrom(ctx, pos) - 1; i >= 0; i-- {
		t := ctx.Tokens[i]
		if t.Kind == text.KindSpace {
			continue
		}
		if t.End > pos {
			continue
		}
		if pos-t.End > ppAnchorWindow {
			return false
		}
		if t.Kind != text.KindWord {
			continue
		}
		if ppAuthorityWord(ctx, t) {
			return true
		}
	}
	return false
}

// ppAuthorityWord reports whether a word token names a passport-issuing body,
// either outright or as a head followed by a qualifying word.
func ppAuthorityWord(ctx *Context, t text.Token) bool {
	w := t.In(ctx.Lower)
	if ppIsStrongAuthority(w) {
		return true
	}
	if _, head := ppAuthorityHeads[w]; head {
		if _, ok := ppAuthorityQualifiers[ppWordAfter(ctx, t.End)]; ok {
			return true
		}
	}
	return false
}

// ppStrongAuthority holds the tokens that name a passport-issuing body and
// nothing else: membership alone is the evidence. None of the 187 golden
// negatives contains one. "загс", "мфц", "гибдд", "гаи", "мрэо", "рэо" are
// deliberately absent — the first two are pinned as non-evidence by
// TestPassportIssuerAuthority/"a lone institution word names nobody", the rest
// name a different document.
var ppStrongAuthority = map[string]struct{}{
	"овд": {}, "ровд": {}, "рувд": {}, "увд": {}, "гувд": {}, "мвд": {},
	"омвд": {}, "умвд": {}, "гумвд": {}, "увмд": {}, "увмвд": {},
	"уфмс": {}, "фмс": {}, "оуфмс": {}, "туфмс": {},
	"овм": {}, "оувм": {}, "увм": {}, "гувм": {}, "мро": {}, "пвс": {}, "овир": {},
	"ovd": {}, "uvd": {}, "ufms": {}, "mvd": {}, "omvd": {},
}

// ppAuthorityHeads / ppAuthorityQualifiers spell out the bodies that have no
// abbreviation. A head ALONE is never enough: "Отделение банка" is six of the
// golden negatives, and none of them carries a qualifier.
var ppAuthorityHeads = map[string]struct{}{
	ppWordOtdel: {}, ppWordOtdela: {}, ppWordOtdelom: {}, "отделе": {},
	ppWordOtdelenie: {}, ppWordOtdeleniya: {}, ppWordOtdeleniem: {}, "отделении": {},
	ppWordUpravlenie: {}, ppWordUpravleniya: {}, ppWordUpravleniem: {}, "управлении": {},
	"служба": {}, "службы": {}, "службой": {},
}

var ppAuthorityQualifiers = map[string]struct{}{
	"полиции": {}, "милиции": {}, "внутренних": {}, ppWordMigratsionnoy: {},
	"миграционная": {}, "миграции": {}, ppWordVizovoy: {}, "визовая": {},
	"уфмс": {}, "фмс": {}, "мвд": {}, "увд": {},
}

// ppIssuerPrefixWords may be pulled into the span to the LEFT of the token that
// triggered it: "Паспортно-визовая служба УВД Московского района". Verbs of
// issuing are deliberately absent — "выдан" is a label, not part of the name.
var ppIssuerPrefixWords = map[string]struct{}{
	ppWordOtdel: {}, ppWordOtdela: {}, ppWordOtdelom: {}, ppWordOtdelenie: {}, ppWordOtdeleniya: {},
	ppWordOtdeleniem: {}, ppWordUpravlenie: {}, ppWordUpravleniya: {}, ppWordUpravleniem: {},
	"служба": {}, "службы": {}, "службой": {},
	"паспортно": {}, "паспортный": {}, "паспортным": {}, "визовая": {}, ppWordVizovoy: {},
	ppWordMigratsionnoy: {}, "миграционная": {}, "территориальный": {}, "территориальное": {},
	"главное": {}, "главного": {}, "межрайонный": {}, "межрайонное": {},
	"районный": {}, "районное": {}, "городской": {}, "городское": {},
	"областное": {}, "краевое": {}, "пункт": {}, "пункта": {},
	"мп": {}, "тп": {}, "гу": {}, "ту": {}, "мо": {}, "мро": {},
}

// ppIsStrongAuthority reports whether w names a passport-issuing body outright.
func ppIsStrongAuthority(w string) bool {
	_, ok := ppStrongAuthority[w]
	return ok
}

var ppIssuerStems = []ppStem{
	{lit: "выдан", tail: ppTailIssued},
	{lit: "выдавши", tail: ppTailIssuingBody},
	{lit: "орган", tail: ppTailIssuingOrgan},
}

// ppTailIssued accepts "выдан", "выдана", "выдано" and "выданы".
func ppTailIssued(s string, i int) (int, bool) {
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r == 'а' || r == 'о' || r == 'ы' {
		i += sz
	}
	return i, true
}

// ppTailIssuingBody completes "выдавший орган" / "выдавшим органом".
func ppTailIssuingBody(s string, i int) (int, bool) {
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r != 'й' && r != 'м' {
		return 0, false
	}
	j := ppSkipHorizSpace(s, i+sz)
	if j == i+sz || !strings.HasPrefix(s[j:], "орган") {
		return 0, false
	}
	j += len("орган")
	if strings.HasPrefix(s[j:], "ом") {
		j += len("ом")
	}
	return j, true
}

// ppTailIssuingOrgan completes "орган выдачи".
func ppTailIssuingOrgan(s string, i int) (int, bool) {
	j := ppSkipHorizSpace(s, i)
	if j == i || !strings.HasPrefix(s[j:], ppWordVydachi) {
		return 0, false
	}
	return j + len(ppWordVydachi), true
}

func (d passportDetector) issuer(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypePassportIssuer) {
		return out
	}
	base := len(out)
	ppFindStems(ctx.Lower, ppIssuerStems, func(_, start, end int) {
		if !ppOnBoundaries(ctx.Text, start, end) {
			return
		}
		s, e, ok := ppIssuerSpan(ctx, ppSkipIssueDate(ctx, ppSkipLeadSep(ctx.Text, end)))
		if !ok {
			return
		}
		out = append(out, pd.Span{
			Start: s, End: e, Type: pd.TypePassportIssuer,
			Conf: ppConfIssuer, Src: detectorPassport, Hint: "issuer",
		})
	})
	return d.unanchoredIssuer(ctx, out, base)
}

// ppSkipIssueDate steps over an issue date that stands between the issuing
// anchor and the authority name. Only the leading run is consumed: the date
// itself stays outside the issuer span.
func ppSkipIssueDate(ctx *Context, from int) int {
	if from >= len(ctx.Lower) {
		return from
	}
	loc := ppLeadDateRe.FindStringIndex(ctx.Lower[from:])
	if loc == nil || loc[1] == 0 {
		return from
	}
	return from + loc[1]
}

// ppIssuerExtendLeft grows the span left over the words that spell out the kind
// of body. It stops at anything else, so "выдан ОВД" never swallows the label.
//
// One punctuation token is allowed INSIDE the run and only there: a hyphen that
// joins two prefix words, as in "Паспортно-визовая". Both of its neighbours must
// themselves be ppIssuerPrefixWords, so the hyphen can never end up on the edge
// of the span and "(ранее — УВД «Тушинское»)" still starts at "УВД".
func ppIssuerExtendLeft(ctx *Context, start int) int {
	limit := start - ppIssuerLeftBytes
	if limit < 0 {
		limit = 0
	}
	for i := ppTokenFrom(ctx, start) - 1; i >= 0; i-- {
		t := ctx.Tokens[i]
		if t.Start < limit {
			break
		}
		if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
			break
		}
		ns, stop := ppIssuerExtendToken(ctx, t, start)
		if stop {
			return start
		}
		start = ns
	}
	return start
}

// ppIssuerExtendToken advances the span start over one prefix token. stop=true
// means the token is not a valid prefix and the walk must end at the current
// start.
func ppIssuerExtendToken(ctx *Context, t text.Token, start int) (int, bool) {
	switch t.Kind {
	case text.KindSpace:
		return start, false
	case text.KindWord:
		if _, ok := ppIssuerPrefixWords[t.In(ctx.Lower)]; !ok {
			return start, true
		}
		return t.Start, false
	case text.KindPunct:
		if t.In(ctx.Text) != "-" {
			return start, true
		}
		prev := ppWordBefore(ctx, t.Start)
		next := ppWordAfter(ctx, t.End)
		if _, ok := ppIssuerPrefixWords[prev]; !ok {
			return start, true
		}
		if _, ok := ppIssuerPrefixWords[next]; !ok {
			return start, true
		}
		return t.Start, false
	default:
		return start, true
	}
}

// unanchoredIssuer emits an issuer span for a payload that names the authority
// without the "кем выдан" clause. It runs AFTER the anchored pass and skips any
// candidate the anchored pass already covers, so no span is ever emitted twice.
func (d passportDetector) unanchoredIssuer(ctx *Context, out []pd.Span, base int) []pd.Span {
	lower := ctx.Lower
	hasClause := strings.Contains(lower, "выдан") || strings.Contains(lower, "выдавш") ||
		strings.Contains(lower, "орган выдачи") || strings.Contains(lower, "кем")
	anchors := ppAnchors(ctx)
	for i := 0; i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.Kind != text.KindWord {
			continue
		}
		if !ppIssuerTrigger(ctx, t) {
			continue
		}
		s, e, ok := ppIssuerSpanMin(ctx, t.Start, 1)
		if !ok {
			continue
		}
		s = ppIssuerExtendLeft(ctx, s)
		if ppIssuerStoppedOnPredicate(ctx, s, e) && !hasClause && len(anchors) == 0 {
			continue
		}
		if ppOverlaps(out[base:], s, e) {
			continue
		}
		out = append(out, pd.Span{
			Start: s, End: e, Type: pd.TypePassportIssuer,
			Conf: ppConfIssuerBare, Src: detectorPassport, Hint: "issuer_bare",
		})
	}
	return out
}

// ppIssuerTrigger reports whether a word token names a passport-issuing body
// and can therefore start an unanchored issuer span.
func ppIssuerTrigger(ctx *Context, t text.Token) bool {
	lw := t.In(ctx.Lower)
	if ppIsStrongAuthority(lw) {
		return true
	}
	if _, head := ppAuthorityHeads[lw]; head {
		if _, ok := ppAuthorityQualifiers[ppWordAfter(ctx, t.End)]; ok {
			return true
		}
	}
	return false
}

// ppIssuerStoppedOnPredicate reports whether the span walk stopped on a
// predicate verb, i.e. the authority is the subject of a sentence rather than a
// field value.
func ppIssuerStoppedOnPredicate(ctx *Context, s, e int) bool {
	for i := ppTokenFrom(ctx, e); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.Kind == text.KindSpace {
			continue
		}
		if t.Kind != text.KindWord {
			return false
		}
		_, pred := ppIssuerPredicateWords[t.In(ctx.Lower)]
		return pred
	}
	return false
}

func ppIssuerSpan(ctx *Context, from int) (int, int, bool) {
	return ppIssuerSpanMin(ctx, from, ppIssuerMinWords)
}

// ppIssuerSpanMin is ppIssuerSpan with the word floor spelled out: the
// unanchored pass needs only one word, because the word itself is the evidence.
// ppIssuerWalkState carries the mutable state of the issuer span walk.
type ppIssuerWalkState struct {
	end           int
	lastWord      string
	afterNumSign  bool
	hasIssuerWord bool
	words         int
}

func ppIssuerSpanMin(ctx *Context, from, minWords int) (int, int, bool) {
	limit := from + ppIssuerMaxBytes
	st := ppIssuerWalkState{end: from}
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.End > limit {
			break
		}
		if !ppIssuerWalkToken(ctx, t, &st) {
			break
		}
	}
	if !st.hasIssuerWord || st.words < minWords {
		return 0, 0, false
	}
	s, e, ok := text.TrimSpanEdges(ctx.Text, from, st.end)
	if !ok {
		return 0, 0, false
	}
	return s, ppRestoreClosingQuote(ctx.Text, s, e, st.end), true
}

// ppIssuerWalkToken advances the issuer span walk over one token, returning
// false when the walk must stop at the current end.
func ppIssuerWalkToken(ctx *Context, t text.Token, st *ppIssuerWalkState) bool {
	ok := true
	switch t.Kind {
	case text.KindSpace:
		if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
			return false
		}
	case text.KindWord, text.KindAlnum:
		ok = ppIssuerWalkWord(ctx, t, st)
	case text.KindNumber:
		// A bare number is a date or a code, i.e. the next field — unless it
		// is the department number written as "№ 5".
		if !st.afterNumSign {
			return false
		}
		st.end = t.End
	case text.KindPunct:
		ok = ppIssuerWalkPunct(ctx, t, st)
	}
	if !ok {
		return false
	}
	if t.Kind != text.KindSpace {
		st.afterNumSign = t.Kind == text.KindPunct && t.In(ctx.Text) == "№"
	}
	return true
}

// ppIssuerWalkWord advances the walk over a word or alphanumeric token.
func ppIssuerWalkWord(ctx *Context, t text.Token, st *ppIssuerWalkState) bool {
	w := t.In(ctx.Lower)
	if _, stop := ppIssuerStopWords[w]; stop {
		return false
	}
	if _, pred := ppIssuerPredicateWords[w]; pred {
		return false
	}
	if ppIsAuthorityWord(w) {
		st.hasIssuerWord = true
	}
	st.lastWord = w
	st.words++
	st.end = t.End
	return true
}

// ppIssuerWalkPunct advances the walk over a punctuation token.
func ppIssuerWalkPunct(ctx *Context, t text.Token, st *ppIssuerWalkState) bool {
	switch t.In(ctx.Text) {
	case ".":
		if ppEndsSentence(st.lastWord) {
			return false
		}
		st.end = t.End
	case "-", "–", "—", "/", "№", "\"", "«", "»":
		st.end = t.End
	default:
		return false
	}
	return true
}

// ppRestoreClosingQuote re-attaches a single trailing closing quote or
// guillemet that TrimSpanEdges stripped, provided the span still contains its
// matching opener. Quotation marks belong to the name of the division, so
// "OVD \"Central\"" keeps its closing quote.
func ppRestoreClosingQuote(s string, start, end, rawEnd int) int {
	if rawEnd <= end {
		return end
	}
	// The trimmed tail must be exactly one closing quote/guillemet.
	r, sz := utf8.DecodeRuneInString(s[end:])
	if end+sz != rawEnd {
		return end
	}
	var open rune
	switch r {
	case '"':
		open = '"'
	case '»':
		open = '«'
	default:
		return end
	}
	for i := start; i < end; i++ {
		rr, _ := utf8.DecodeRuneInString(s[i:])
		if rr == open {
			return rawEnd
		}
	}
	return end
}

// ppEndsSentence decides whether a period closes the issuer name.
func ppEndsSentence(prevWord string) bool {
	if prevWord == "" || utf8.RuneCountInString(prevWord) < 4 {
		return false
	}
	_, abbrev := ppIssuerAbbrevs[prevWord]
	return !abbrev
}

func ppIsIssuerWord(w string) bool {
	if dict.IsIssuerWord(w) {
		return true
	}
	_, ok := ppIssuerWords[w]
	return ok
}

// ppIsAuthorityWord is the EVIDENCE test, as opposed to ppIsIssuerWord, which
// only says a word may appear inside an authority name.
func ppIsAuthorityWord(w string) bool {
	if _, glue := ppIssuerGlue[w]; glue {
		return false
	}
	if ppIsStrongAuthority(w) {
		return true
	}
	return ppIsIssuerWord(w)
}

var ppIssuerWords = map[string]struct{}{
	"овд": {}, "ровд": {}, "рувд": {}, "увд": {}, "гувд": {}, "мвд": {},
	"омвд": {}, "умвд": {}, "гумвд": {}, "увмд": {}, "уфмс": {}, "фмс": {},
	"оуфмс": {}, "овм": {}, "оувм": {}, "увм": {}, "мро": {}, "мп": {},
	"гу": {}, "ту": {}, "тп": {}, "мфц": {},
	"мрэо": {}, "рэо": {}, "пвс": {}, "овир": {}, "гибдд": {},
	"загс": {}, "загса": {}, "загсом": {},
	ppWordOtdel: {}, ppWordOtdela: {}, ppWordOtdelom: {}, ppWordOtdelenie: {}, ppWordOtdeleniem: {},
	ppWordOtdeleniya: {}, "отделении": {}, "отделу": {},
	ppWordUpravlenie: {}, ppWordUpravleniem: {}, ppWordUpravleniya: {}, "управлении": {},
	ppWordMigratsionnoy: {}, "миграционного": {}, "миграции": {},
	"полиции": {}, "милиции": {}, "паспортный": {}, "паспортным": {},
	"паспортно": {}, ppWordVizovoy: {}, "консульство": {}, "консульством": {},
	"посольство": {}, "посольством": {},
}

var ppIssuerStopWords = map[string]struct{}{
	"дата": {}, "даты": {}, "дате": {}, ppWordVydachi: {}, "код": {}, "кода": {},
	"подразделения": {}, "зарегистрирован": {}, "зарегистрирована": {},
	"проживает": {}, "проживающий": {}, "проживающая": {}, "адрес": {},
	"паспорт": {}, "паспорта": {}, "серия": {}, "номер": {}, "снилс": {},
	"инн": {}, "телефон": {}, "место": {}, "рождения": {}, "гражданство": {},
}

var ppIssuerAbbrevs = map[string]struct{}{
	"г": {}, "гор": {}, "обл": {}, "окр": {}, "респ": {}, "край": {},
	"р-н": {}, "рн": {}, "пос": {}, "им": {}, "тер": {}, "мкр": {},
	"ул": {}, "пер": {}, "с": {}, "д": {}, "п": {}, "мо": {}, "спб": {},
}

var ppIssuerGlue = map[string]struct{}{
	"в": {}, "по": {}, "г": {}, "гор": {}, "им": {}, "имени": {}, "на": {},
	"города": {}, "городе": {}, "район": {}, "района": {}, "районе": {},
	"округ": {}, "округа": {}, "область": {}, "области": {},
	"край": {}, "края": {}, ppWordRespublika: {}, ppWordRespubliki: {},
	"выдан": {}, "выдана": {}, "выдано": {}, "выдал": {}, "выдала": {},
	"выдали": {}, "выдавший": {}, "выдавшим": {}, ppWordVydachi: {}, "кем": {},
	"дата": {}, "код": {}, "подразделения": {},
	"зарегистрирован": {}, "зарегистрирована": {}, "регистрации": {},
}

// ppIssuerPredicateWords are the finite verbs that turn an authority name from a
// FIELD VALUE into the subject of a sentence: "МВД России сообщило о задержании"
// names a ministry, not the bearer of a passport. ppIssuerSpanMin breaks on them
// the same way it breaks on ppIssuerStopWords, so the verb never lands inside a
// span; unanchoredIssuer then drops the candidate outright unless the payload
// also carries an issuing clause or a passport anchor.
//
// The issuing verbs are in this table too, and that is deliberate: without them
// "УФМС России по Московской области выдало паспорт гражданину" masks the verb
// "выдало" as part of the authority name. They are in ppIssuerGlue, which only
// stops them from being EVIDENCE — the walk still ate them.
var ppIssuerPredicateWords = map[string]struct{}{
	"выдал": {}, "выдала": {}, "выдало": {}, "выдали": {},
	"выдан": {}, "выдана": {}, "выдано": {}, "выданы": {},
	"сообщил": {}, "сообщило": {}, "сообщила": {}, "сообщает": {}, "сообщают": {},
	"заявил": {}, "заявило": {}, "заявила": {}, "заявляет": {},
	"проводит": {}, "провело": {}, "провёл": {}, "провел": {},
	"расследует": {}, "возбудил": {}, "возбудило": {}, "задержал": {}, "задержало": {},
	"опубликовал": {}, "опубликовало": {}, "напомнил": {}, "напомнило": {},
	"предупредил": {}, "предупредило": {}, "разыскивает": {}, "рекомендует": {},
	"требует": {}, "утвердил": {}, "утвердило": {}, "принял": {}, "приняло": {},
	"отказал": {}, "отказало": {}, "начал": {}, "начало": {},
}

var ppBirthStems = []ppStem{
	{lit: "мест", tail: ppTailPlaceOfBirthRu},
	{lit: "place", tail: ppTailPlaceOfBirthEn},
	{lit: "родил", tail: ppTailBornIn},
	{lit: "урожен", tail: ppTailNative},
	{lit: "м.", tail: ppTailMR},
	{lit: "мр", tail: ppTailPlain},
}

// ppTailPlaceOfBirthRu completes "место рождения" in any of its spellings,
// including the abbreviated "мест. рожд.".
func ppTailPlaceOfBirthRu(s string, i int) (int, bool) {
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r != 'о' && r != 'а' {
		return 0, false
	}
	j := ppSkipHorizSpace(s, i+sz)
	if j == i+sz || !strings.HasPrefix(s[j:], "рожд") {
		return 0, false
	}
	j = ppSkipLowerCyr(s, j+len("рожд"))
	if j < len(s) && s[j] == '.' {
		j++
	}
	return j, true
}

func ppTailPlaceOfBirthEn(s string, i int) (int, bool) {
	j := ppSkipHorizSpace(s, i)
	if j == i || !strings.HasPrefix(s[j:], "of") {
		return 0, false
	}
	k := ppSkipHorizSpace(s, j+2)
	if k == j+2 || !strings.HasPrefix(s[k:], "birth") {
		return 0, false
	}
	return k + len("birth"), true
}

// ppTailBornIn completes "родился в" / "родилась в".
func ppTailBornIn(s string, i int) (int, bool) {
	switch {
	case strings.HasPrefix(s[i:], "ся"):
		i += len("ся")
	case strings.HasPrefix(s[i:], "ась"):
		i += len("ась")
	default:
		return 0, false
	}
	j := ppSkipHorizSpace(s, i)
	if j == i || !strings.HasPrefix(s[j:], "в") {
		return 0, false
	}
	return j + len("в"), true
}

// ppTailNative completes "уроженец", "уроженка" and "уроженцы".
func ppTailNative(s string, i int) (int, bool) {
	if strings.HasPrefix(s[i:], "ец") {
		return i + len("ец"), true
	}
	r, sz := utf8.DecodeRuneInString(s[i:])
	if r != 'к' && r != 'ц' {
		return 0, false
	}
	return ppSkipLowerCyr(s, i+sz), true
}

// ppTailMR completes the form-field abbreviation "м. р.".
func ppTailMR(s string, i int) (int, bool) {
	j := ppSkipHorizSpace(s, i)
	if !strings.HasPrefix(s[j:], "р.") {
		return 0, false
	}
	return j + len("р."), true
}

func (d passportDetector) birthPlace(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypeBirthPlace) {
		return out
	}
	ppFindStems(ctx.Lower, ppBirthStems, func(_, start, end int) {
		if !ppOnBoundaries(ctx.Text, start, end) || FamousMentionLeft(ctx, start) {
			return
		}
		// Quoted-label form: «Место рождения» указано: <value>.
		if q := ppQuotedLabelLeadSep(ctx, start, end); q >= 0 && ppBirthPlaceEmit(ctx, &out, q) {
			return
		}
		// Role-colon form: Место рождения поручителя: <value>.
		if r := ppLeadSepRole(ctx, end); r >= 0 && ppBirthPlaceEmit(ctx, &out, r) {
			return
		}
		ppBirthPlaceEmit(ctx, &out, ppSkipLeadSep(ctx.Text, end))
	})
	return out
}

// ppBirthPlaceEmit appends a birth-place span starting at from, returning
// whether a span was emitted.
func ppBirthPlaceEmit(ctx *Context, out *[]pd.Span, from int) bool {
	s, e, ok := ppBirthPlaceSpan(ctx, from)
	if !ok {
		return false
	}
	*out = append(*out, pd.Span{
		Start: s, End: e, Type: pd.TypeBirthPlace,
		Conf: ppConfBirthPlace, Src: detectorPassport, Hint: "birth_place",
	})
	return true
}

// ppBirthWalkState carries the mutable state of the birth-place span walk.
type ppBirthWalkState struct {
	end     int
	tent    int
	first   bool
	pending bool
}

func ppBirthPlaceSpan(ctx *Context, from int) (int, int, bool) {
	limit := from + ppBirthMaxBytes
	st := ppBirthWalkState{end: from, tent: from, first: true}
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.End > limit {
			break
		}
		if !ppBirthWalkToken(ctx, t, &st) {
			break
		}
	}
	if st.first {
		return 0, 0, false
	}
	return text.TrimSpanEdges(ctx.Text, from, st.end)
}

// ppBirthWalkToken advances the birth-place span walk over one token, returning
// false when the walk must stop at the current end.
func ppBirthWalkToken(ctx *Context, t text.Token, st *ppBirthWalkState) bool {
	switch t.Kind {
	case text.KindSpace:
		if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
			return false
		}
	case text.KindWord:
		return ppBirthWalkWord(ctx, t, st)
	case text.KindPunct:
		return ppBirthWalkPunct(ctx, t, st)
	default:
		return false
	}
	return true
}

// ppBirthWalkWord advances the walk over a word token.
func ppBirthWalkWord(ctx *Context, t text.Token, st *ppBirthWalkState) bool {
	lw := t.In(ctx.Lower)
	_, locality := ppLocalityTypes[lw]
	_, region := ppRegionWords[lw]
	capitalised := text.IsUpperFirst(t.In(ctx.Text)) && !dict.IsStopWord(lw)
	switch {
	case locality || dict.IsStreetType(lw):
	case capitalised || dict.IsCity(lw):
	case !st.first && region:
	default:
		return false
	}
	st.first = false
	st.tent = t.End
	switch {
	case !st.pending:
		st.end = st.tent
	case region:
		st.end, st.pending = st.tent, false
	}
	return true
}

// ppBirthWalkPunct advances the walk over a punctuation token.
func ppBirthWalkPunct(ctx *Context, t text.Token, st *ppBirthWalkState) bool {
	switch t.In(ctx.Text) {
	case ".", "-", "–":
		st.tent = t.End
		if !st.pending {
			st.end = st.tent
		}
	case ",":
		if st.pending || st.first {
			return false
		}
		st.pending, st.tent = true, t.End
	default:
		return false
	}
	return true
}

var ppLocalityTypes = map[string]struct{}{
	"г": {}, "гор": {}, "город": {}, "города": {}, "городе": {},
	"с": {}, "село": {}, "села": {}, "селе": {}, "сел": {},
	"д": {}, "дер": {}, "деревня": {}, "деревне": {}, "деревни": {},
	"п": {}, "пос": {}, "поселок": {}, "посёлок": {}, "поселке": {}, "посёлке": {},
	"пгт": {}, "рп": {}, "ст": {}, "станица": {}, "станице": {}, "ст-ца": {},
	"х": {}, "хутор": {}, "хуторе": {}, "аул": {}, "ауле": {},
	"нп": {}, "мкр": {}, "жд": {},
}

var ppRegionWords = map[string]struct{}{
	"область": {}, "области": {}, "обл": {}, "край": {}, "края": {}, "крае": {},
	"район": {}, "района": {}, "районе": {}, "р-н": {}, "рн": {},
	ppWordRespublika: {}, ppWordRespubliki: {}, "республике": {}, "респ": {},
	"округ": {}, "округа": {}, "округе": {}, "ао": {}, "губернии": {},
	"уезд": {}, "уезда": {}, "ссср": {}, "рсфср": {}, "рф": {}, "россии": {},
	"федерации": {}, "россия": {}, "казахстан": {}, "казахстана": {},
	"автономный": {}, "автономная": {}, "автономного": {}, "автономной": {},
	"автономном": {}, "автономном округе": {}, "обл.": {},
}

var ppCitizenshipStems = []ppStem{
	{lit: "граждан", tail: ppTailCitizen},
	{lit: "подданств", tail: ppTailCyrSuffix},
	{lit: "citizenship", tail: ppTailPlain},
	{lit: "nationality", tail: ppTailPlain},
}

// ppTailCitizen accepts "гражданство", "гражданин" and "гражданка" with any
// case ending, and rejects "граждане".
func ppTailCitizen(s string, i int) (int, bool) {
	switch {
	case strings.HasPrefix(s[i:], "ств"):
		i += len("ств")
	case strings.HasPrefix(s[i:], "ин"):
		i += len("ин")
	case strings.HasPrefix(s[i:], "к"):
		i += len("к")
	default:
		return 0, false
	}
	return ppSkipLowerCyr(s, i), true
}

func ppTailCyrSuffix(s string, i int) (int, bool) { return ppSkipLowerCyr(s, i), true }

func (d passportDetector) citizenship(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypeCitizenship) {
		return out
	}
	ppFindStems(ctx.Lower, ppCitizenshipStems, func(_, start, end int) {
		if !ppOnBoundaries(ctx.Text, start, end) {
			return
		}
		// Quoted-label form: «Гражданство» указано: <value>.
		if q := ppQuotedLabelLeadSep(ctx, start, end); q >= 0 && ppCitizenshipEmit(ctx, &out, q, "citizenship") {
			return
		}
		// Role-colon form: Гражданство поручителя: <value>.
		if r := ppLeadSepRole(ctx, end); r >= 0 && ppCitizenshipEmit(ctx, &out, r, "citizenship") {
			return
		}
		if ppCitizenshipEmit(ctx, &out, ppSkipLeadSep(ctx.Text, end), "citizenship") {
			return
		}
		if s, e, ok := ppCitizenshipAdjLeft(ctx, start); ok {
			out = append(out, pd.Span{
				Start: s, End: e, Type: pd.TypeCitizenship,
				Conf: ppConfCitizenship, Src: detectorPassport, Hint: "citizenship_adj",
			})
		}
	})
	return out
}

// ppCitizenshipEmit appends a citizenship span starting at from, returning
// whether a span was emitted.
func ppCitizenshipEmit(ctx *Context, out *[]pd.Span, from int, hint string) bool {
	s, e, ok := ppCitizenshipSpan(ctx, from)
	if !ok {
		return false
	}
	*out = append(*out, pd.Span{
		Start: s, End: e, Type: pd.TypeCitizenship,
		Conf: ppConfCitizenship, Src: detectorPassport, Hint: hint,
	})
	return true
}

func ppCitizenshipAdjLeft(ctx *Context, off int) (int, int, bool) {
	for i := ppTokenFrom(ctx, off) - 1; i >= 0; i-- {
		t := ctx.Tokens[i]
		if t.Kind == text.KindSpace {
			continue
		}
		if t.Kind != text.KindWord {
			return 0, 0, false
		}
		if _, ok := ppCitizenshipAdjectives[t.In(ctx.Lower)]; !ok {
			return 0, 0, false
		}
		return t.Start, t.End, true
	}
	return 0, 0, false
}

func ppCitizenshipSpan(ctx *Context, from int) (int, int, bool) {
	limit := from + ppCitizenMaxBytes
	end := from
	words := 0
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.End > limit || words >= ppCitizenMaxWords {
			break
		}
		if !ppCitizenshipWalkToken(ctx, t, &end, &words) {
			break
		}
	}
	if words == 0 {
		return 0, 0, false
	}
	return text.TrimSpanEdges(ctx.Text, from, end)
}

// ppCitizenshipWalkToken advances the citizenship span walk over one token,
// returning false when the walk must stop at the current end.
func ppCitizenshipWalkToken(ctx *Context, t text.Token, end *int, words *int) bool {
	switch t.Kind {
	case text.KindSpace:
		if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
			return false
		}
	case text.KindWord:
		lw := t.In(ctx.Lower)
		_, value := ppCitizenshipValues[lw]
		_, tail := ppCitizenshipTails[lw]
		if *words == 0 {
			if !value && !dict.IsCitizenship(lw) && !dict.IsCountry(lw) {
				return false
			}
		} else if !value && !tail && !dict.IsCountry(lw) && !text.IsUpperFirst(t.In(ctx.Text)) {
			return false
		}
		(*words)++
		*end = t.End
	case text.KindPunct:
		if t.In(ctx.Text) != "-" {
			return false
		}
		*end = t.End
	default:
		return false
	}
	return true
}

var ppCitizenshipValues = map[string]struct{}{
	"рф": {}, "россия": {}, "россии": {}, "российское": {}, "российской": {},
	"российская": {}, "российскую": {}, "российского": {}, "ссср": {}, "рб": {},
	"рк": {}, "беларусь": {}, "беларуси": {}, "белоруссия": {}, "белоруссии": {},
	"казахстан": {}, "казахстана": {}, "украина": {}, "украины": {},
	"армения": {}, "армении": {}, "узбекистан": {}, "узбекистана": {},
	"киргизия": {}, "киргизии": {}, "кыргызстан": {}, "кыргызстана": {},
	"таджикистан": {}, "таджикистана": {}, "азербайджан": {}, "азербайджана": {},
	"молдова": {}, "молдовы": {}, "грузия": {}, "грузии": {}, "туркменистан": {},
	"туркменистана": {}, ppWordRespublika: {}, ppWordRespubliki: {}, "сша": {},
	"германия": {}, "германии": {}, "израиль": {}, "израиля": {}, "китай": {},
	"китая": {}, "russia": {}, "russian": {}, "usa": {}, "belarus": {},
	"kazakhstan": {}, "ukraine": {},
}

var ppCitizenshipTails = map[string]struct{}{
	"федерация": {}, "федерации": {}, "федерацию": {}, ppWordRespublika: {},
	ppWordRespubliki: {}, "беларусь": {}, "беларуси": {}, "союз": {}, "союза": {},
	"federation": {},
}

var ppCitizenshipAdjectives = map[string]struct{}{
	"российское": {}, "российского": {}, "российским": {}, "российскому": {},
	"российский": {}, "российская": {}, "российской": {}, "российскую": {},
	"украинское": {}, "украинского": {}, "украинским": {}, "украинский": {},
	"белорусское": {}, "белорусского": {}, "белорусским": {}, "белорусский": {},
	"казахстанское": {}, "казахстанского": {}, "казахское": {},
	"армянское": {}, "армянского": {}, "узбекское": {}, "узбекского": {},
	"киргизское": {}, "кыргызское": {}, "таджикское": {}, "таджикского": {},
	"азербайджанское": {}, "молдавское": {}, "грузинское": {},
	"немецкое": {}, "американское": {}, "израильское": {}, "китайское": {},
	"турецкое": {}, "французское": {}, "британское": {}, "польское": {},
}

var ppOtherDocMarkers = []ppOtherDocMarker{
	// Driving licence.
	{lit: "водительск"},
	{lit: "удостоверение водителя"}, {lit: "удостоверения водителя"},
	{lit: "удостоверению водителя"}, {lit: "удостоверением водителя"},
	{lit: "удостоверении водителя"},
	{lit: "вод. удостоверен"}, {lit: "вод.удостоверен"},
	{lit: "driver license"}, {lit: "driver's license"},
	{lit: "driving licence"}, {lit: "driving license"},
	{lit: "в/у", exact: true}, {lit: "ву", exact: true},
	// Foreign passport.
	{lit: "загран"},
	{lit: "international passport"}, {lit: "foreign passport"},
	// SNILS and the pension certificate.
	{lit: "снилс"}, {lit: "страховое свидетельство"},
	{lit: "страхового свидетельства"}, {lit: "пенсионное свидетельство"},
	// Compulsory medical insurance policy.
	{lit: "омс", exact: true},
	{lit: "медицинский полис"}, {lit: "медицинского полиса"},
	{lit: "медицинским полисом"}, {lit: "медицинского страхования"},
	// Military ID.
	{lit: "военный билет"}, {lit: "военного билета"},
	{lit: "военному билету"}, {lit: "военном билете"},
	{lit: "военник"}, {lit: "воен. билет"}, {lit: "воен.билет"},
	// Residence permit.
	{lit: "на жительств"}, {lit: "внж", exact: true}, {lit: "рвп", exact: true},
}

func ppOtherDocumentLeft(ctx *Context, anchors []ppSpan, pos int) bool {
	if ppNamedAnchorNear(ctx.Lower, anchors, pos, ppOtherDocWindow) {
		return false
	}
	from := pos - ppOtherDocWindow
	if from < 0 {
		from = 0
	}
	win := ctx.Lower[from:pos]
	for i := range ppOtherDocMarkers {
		m := &ppOtherDocMarkers[i]
		for off := 0; off+len(m.lit) <= len(win); {
			j := strings.Index(win[off:], m.lit)
			if j < 0 {
				break
			}
			abs := from + off + j
			if text.IsBoundary(ctx.Lower, abs) &&
				(!m.exact || text.IsBoundary(ctx.Lower, abs+len(m.lit))) {
				return true
			}
			off += j + 1
		}
	}
	return false
}
