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

	ppAnchorWindow    = 60 // bytes an anchor may sit ahead of the digits
	ppPairWindow      = 40 // bytes between a "серия" group and its "номер" group
	ppIssuerMaxBytes  = 160
	ppIssuerMinWords  = 2
	ppBirthMaxBytes   = 100
	ppCitizenMaxBytes = 60
	ppCitizenMaxWords = 3
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
	// the three ways the code is printed — hyphenated, spaced and solid.
	ppSubdivisionRe = regexp.MustCompile(
		`(?:код[ \t]+подразделени[яе]|код[ \t]+подр\.|подразделени[еяю]|подр\.|к/п|кп)` +
			`[ \t]*(?:[№#:][ \t]*)?(\d{3}[ \t]*-[ \t]*\d{3}|\d{3}[ \t]+\d{3}|\d{6})`)

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
		best := -1
		for i := 0; i < n; i++ {
			if next[i] >= 0 && (best < 0 || next[i] < next[best]) {
				best = i
			}
		}
		if best < 0 {
			return
		}
		pos := next[best]
		st := &stems[best]
		if end, ok := st.tail(s, pos+len(st.lit)); ok {
			fn(best, pos, end)
		}
		if j := strings.Index(s[pos+1:], st.lit); j >= 0 {
			next[best] = pos + 1 + j
		} else {
			next[best] = -1
		}
	}
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
		j := i + sz
		if text.IsBoundary(s, j) {
			return j, true
		}
		r2, sz2 := utf8.DecodeRuneInString(s[j:])
		if r == 'и' && (r2 == 'я' || r2 == 'и') && text.IsBoundary(s, j+sz2) {
			return j + sz2, true
		}
		return 0, false
	}
	if i < len(s) && s[i] == '.' {
		return i + 1, true
	}
	return i, text.IsBoundary(s, i)
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
			j := ppSkipHorizSpace(s, i)
			if g == len(l.groups)-1 && l.flexLast {
				if j < len(s) {
					if r, sz := utf8.DecodeRuneInString(s[j:]); ppIsNumberMark(r) {
						j = ppSkipHorizSpace(s, j+sz)
					}
				}
			} else if j == i {
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
		from, to := a.end, a.end+ppAnchorWindow+1
		if from < high {
			from = high
		}
		if to > len(lower) {
			to = len(lower)
		}
		for p := from; p < to; p++ {
			if lower[p] < '0' || lower[p] > '9' || !text.IsBoundary(ctx.Text, p) {
				continue
			}
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
				out = append(out, pd.Span{
					Start: p, End: e, Type: pd.TypePassport,
					Conf: ppConfPassport, Src: detectorPassport, Hint: "series_number",
				})
				if e > p {
					p = e - 1
				}
				break
			}
		}
		if to > high {
			high = to
		}
	}
	return out
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
		if s[i] == '#' || s[i] == ':' {
			i = ppSkipHorizSpace(s, i+1)
		} else if strings.HasPrefix(s[i:], "№") {
			i = ppSkipHorizSpace(s, i+len("№"))
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
}

func (d passportDetector) subdivision(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypeSubdivisionCode) || !ppHasDigit(ctx.Lower) {
		return out
	}
	if !strings.Contains(ctx.Lower, "подр") && !strings.Contains(ctx.Lower, "к/п") &&
		!strings.Contains(ctx.Lower, "кп") {
		return out
	}
	for _, m := range ppSubdivisionRe.FindAllStringSubmatchIndex(ctx.Lower, -1) {
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
	if j == i || !strings.HasPrefix(s[j:], "выдачи") {
		return 0, false
	}
	return j + len("выдачи"), true
}

func (d passportDetector) issuer(ctx *Context, out []pd.Span) []pd.Span {
	if !ctx.Enabled(pd.TypePassportIssuer) {
		return out
	}
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
	return out
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

func ppIssuerSpan(ctx *Context, from int) (int, int, bool) {
	limit := from + ppIssuerMaxBytes
	end := from
	lastWord := ""
	afterNumSign := false
	hasIssuerWord := false
	words := 0

loop:
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.End > limit {
			break
		}
		switch t.Kind {
		case text.KindSpace:
			if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
				break loop
			}
		case text.KindWord, text.KindAlnum:
			w := t.In(ctx.Lower)
			if _, stop := ppIssuerStopWords[w]; stop {
				break loop
			}
			if ppIsAuthorityWord(w) {
				hasIssuerWord = true
			}
			lastWord = w
			words++
			end = t.End
		case text.KindNumber:
			// A bare number is a date or a code, i.e. the next field — unless it
			// is the department number written as "№ 5".
			if !afterNumSign {
				break loop
			}
			end = t.End
		case text.KindPunct:
			switch t.In(ctx.Text) {
			case ".":
				if ppEndsSentence(lastWord) {
					break loop
				}
				end = t.End
			case "-", "–", "—", "/", "№", "\"", "«", "»":
				end = t.End
			default:
				break loop
			}
		}
		if t.Kind != text.KindSpace {
			afterNumSign = t.Kind == text.KindPunct && t.In(ctx.Text) == "№"
		}
	}
	if !hasIssuerWord || words < ppIssuerMinWords {
		return 0, 0, false
	}
	return text.TrimSpanEdges(ctx.Text, from, end)
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
	return ppIsIssuerWord(w)
}

var ppIssuerWords = map[string]struct{}{
	"овд": {}, "ровд": {}, "рувд": {}, "увд": {}, "гувд": {}, "мвд": {},
	"омвд": {}, "умвд": {}, "гумвд": {}, "увмд": {}, "уфмс": {}, "фмс": {},
	"оуфмс": {}, "овм": {}, "оувм": {}, "увм": {}, "мро": {}, "мп": {},
	"гу": {}, "ту": {}, "тп": {}, "мфц": {},
	"мрэо": {}, "рэо": {}, "пвс": {}, "овир": {}, "гибдд": {},
	"загс": {}, "загса": {}, "загсом": {},
	"отдел": {}, "отдела": {}, "отделом": {}, "отделение": {}, "отделением": {},
	"отделения": {}, "отделении": {}, "отделу": {},
	"управление": {}, "управлением": {}, "управления": {}, "управлении": {},
	"миграционной": {}, "миграционного": {}, "миграции": {},
	"полиции": {}, "милиции": {}, "паспортный": {}, "паспортным": {},
	"паспортно": {}, "визовой": {}, "консульство": {}, "консульством": {},
	"посольство": {}, "посольством": {},
}

var ppIssuerStopWords = map[string]struct{}{
	"дата": {}, "даты": {}, "дате": {}, "выдачи": {}, "код": {}, "кода": {},
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
	"край": {}, "края": {}, "республика": {}, "республики": {},
	"выдан": {}, "выдана": {}, "выдано": {}, "выдал": {}, "выдала": {},
	"выдали": {}, "выдавший": {}, "выдавшим": {}, "выдачи": {}, "кем": {},
	"дата": {}, "код": {}, "подразделения": {},
	"зарегистрирован": {}, "зарегистрирована": {}, "регистрации": {},
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
		if !ppOnBoundaries(ctx.Text, start, end) {
			return
		}
		if FamousMentionLeft(ctx, start) {
			return
		}
		s, e, ok := ppBirthPlaceSpan(ctx, ppSkipLeadSep(ctx.Text, end))
		if !ok {
			return
		}
		out = append(out, pd.Span{
			Start: s, End: e, Type: pd.TypeBirthPlace,
			Conf: ppConfBirthPlace, Src: detectorPassport, Hint: "birth_place",
		})
	})
	return out
}

func ppBirthPlaceSpan(ctx *Context, from int) (int, int, bool) {
	limit := from + ppBirthMaxBytes
	end, tent := from, from
	first := true
	pending := false

loop:
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.End > limit {
			break
		}
		switch t.Kind {
		case text.KindSpace:
			if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
				break loop
			}
		case text.KindWord:
			lw := t.In(ctx.Lower)
			_, locality := ppLocalityTypes[lw]
			_, region := ppRegionWords[lw]
			capitalised := text.IsUpperFirst(t.In(ctx.Text)) && !dict.IsStopWord(lw)
			switch {
			case locality || dict.IsStreetType(lw):
			case capitalised || dict.IsCity(lw):
			case !first && region:
			default:
				break loop
			}
			first = false
			tent = t.End
			switch {
			case !pending:
				end = tent
			case region:
				end, pending = tent, false
			}
		case text.KindPunct:
			switch t.In(ctx.Text) {
			case ".", "-", "–":
				tent = t.End
				if !pending {
					end = tent
				}
			case ",":
				if pending || first {
					break loop
				}
				pending, tent = true, t.End
			default:
				break loop
			}
		default:
			break loop
		}
	}
	if first {
		return 0, 0, false
	}
	return text.TrimSpanEdges(ctx.Text, from, end)
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
	"республика": {}, "республики": {}, "республике": {}, "респ": {},
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
		if s, e, ok := ppCitizenshipSpan(ctx, ppSkipLeadSep(ctx.Text, end)); ok {
			out = append(out, pd.Span{
				Start: s, End: e, Type: pd.TypeCitizenship,
				Conf: ppConfCitizenship, Src: detectorPassport, Hint: "citizenship",
			})
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

loop:
	for i := ppTokenFrom(ctx, from); i < len(ctx.Tokens); i++ {
		t := ctx.Tokens[i]
		if t.End > limit || words >= ppCitizenMaxWords {
			break
		}
		switch t.Kind {
		case text.KindSpace:
			if strings.ContainsAny(t.In(ctx.Text), "\n\r") {
				break loop
			}
		case text.KindWord:
			lw := t.In(ctx.Lower)
			_, value := ppCitizenshipValues[lw]
			_, tail := ppCitizenshipTails[lw]
			if words == 0 {
				if !value && !dict.IsCitizenship(lw) && !dict.IsCountry(lw) {
					break loop
				}
			} else if !value && !tail && !dict.IsCountry(lw) && !text.IsUpperFirst(t.In(ctx.Text)) {
				break loop
			}
			words++
			end = t.End
		case text.KindPunct:
			if t.In(ctx.Text) != "-" {
				break loop
			}
			end = t.End
		default:
			break loop
		}
	}
	if words == 0 {
		return 0, 0, false
	}
	return text.TrimSpanEdges(ctx.Text, from, end)
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
	"туркменистана": {}, "республика": {}, "республики": {}, "сша": {},
	"германия": {}, "германии": {}, "израиль": {}, "израиля": {}, "китай": {},
	"китая": {}, "russia": {}, "russian": {}, "usa": {}, "belarus": {},
	"kazakhstan": {}, "ukraine": {},
}

var ppCitizenshipTails = map[string]struct{}{
	"федерация": {}, "федерации": {}, "федерацию": {}, "республика": {},
	"республики": {}, "беларусь": {}, "беларуси": {}, "союз": {}, "союза": {},
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
