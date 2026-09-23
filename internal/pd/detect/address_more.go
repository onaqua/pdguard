package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"pdguard/internal/pd"
	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/text"
)

// addrIsBankPlace reports whether a candidate is the bank's own premises and
// must not be masked as a client address.
func addrIsBankPlace(ctx *Context, c addrCandidate, k *addrSentCache) bool {
	if c.name != "" {
		if dict.IsBankPlace(c.name) {
			return true
		}
		for _, part := range strings.Fields(c.name) {
			if dict.IsBankPlace(part) {
				return true
			}
		}
	}
	bank := addrLastPhrase(ctx.Lower, c.span.Start-addrBankWindow, c.span.Start, addrBankWords)
	if bank >= 0 {
		personal := addrLastPhrase(ctx.Lower, c.span.Start-addrBankWindow, c.span.Start, addrPersonalAnchors)
		return personal <= bank
	}
	return k.suppresses(ctx.Lower, c.span.Start)
}

func (k *addrSentCache) suppresses(lower string, at int) bool {
	if k.at < 0 || at < k.at || addrSentenceEnds(lower, k.at, at) {
		k.start = addrSentenceStart(lower, at)
		k.head = addrOrgHeading(lower, k.start, at)
	}
	k.at = at
	return k.head >= 0 && addrLastPhrase(lower, k.head, at, addrPersonalAnchors) < 0
}

func addrOrgSubject(lower string, sentStart, at int) bool {
	tail := addrOrgHeading(lower, sentStart, at)
	return tail >= 0 && addrLastPhrase(lower, tail, at, addrPersonalAnchors) < 0
}

func addrOrgHeading(lower string, sentStart, at int) int {
	p := sentStart
	for skipped := 0; skipped <= addrOrgMaxModifiers; skipped++ {
		ws, we := addrNextWord(lower, p, at)
		if ws < 0 {
			return -1
		}
		if _, ok := addrOrgSubjectModifiers[lower[ws:we]]; ok {
			p = we
			continue
		}
		return addrOrgHead(lower, ws, we, at)
	}
	return -1
}

func addrOrgHead(lower string, ws, we, at int) int {
	head := lower[ws:we]
	ns, ne := addrNextWord(lower, we, at)
	next := ""
	if ns >= 0 {
		next = lower[ns:ne]
	}
	return addrOrgHeadKind(head, next, lower, ne, at, we)
}

// addrOrgHeadKind resolves the head noun of an organisation heading by its
// kind, delegating each case to a small helper.
func addrOrgHeadKind(head, next, lower string, ne, at, we int) int {
	switch head {
	case "пункт", "пункты":
		return addrOrgHeadPunkt(next, ne)
	case "точка", "точки":
		return addrOrgHeadTochka(next, ne)
	case "юридический":
		return addrOrgHeadLegal(next, ne)
	case "фактический", "почтовый":
		return addrOrgHeadActual(next, lower, ne, at)
	default:
		return addrOrgHeadNoun(head, next, we)
	}
}

// addrOrgHeadPunkt accepts a "пункт" heading when the next word names what the
// point serves.
func addrOrgHeadPunkt(next string, ne int) int {
	if next == "выдачи" || next == "обслуживания" ||
		next == "приёма" || next == "приема" || next == "продаж" {
		return ne
	}
	return -1
}

// addrOrgHeadTochka accepts a "точка" heading when the next word names what the
// point sells or serves.
func addrOrgHeadTochka(next string, ne int) int {
	if next == "обслуживания" || next == "продаж" {
		return ne
	}
	return -1
}

// addrOrgHeadLegal accepts a "юридический адрес" heading; a legal address is an
// organisation's by definition, so no owner is needed.
func addrOrgHeadLegal(next string, ne int) int {
	if next == "адрес" {
		return ne
	}
	return -1
}

// addrOrgHeadActual accepts a "фактический"/"почтовый адрес" heading only when
// an organisation owner follows it.
func addrOrgHeadActual(next, lower string, ne, at int) int {
	if next != "адрес" {
		return -1
	}
	if ts, te := addrNextWord(lower, ne, at); ts >= 0 {
		if _, ok := addrOrgOwners[lower[ts:te]]; ok {
			return te
		}
	}
	return -1
}

// addrOrgHeadNoun accepts a plain subject noun heading, rejecting a person's
// workplace.
func addrOrgHeadNoun(head, next string, we int) int {
	if _, ok := addrOrgSubjectNouns[head]; !ok {
		return -1
	}
	if _, person := addrOrgSubjectPersons[next]; person {
		return -1 // "офис клиента" — a person's workplace, still personal
	}
	return we
}

func addrSentenceStart(lower string, at int) int {
	from := at - addrSentenceWindow
	if from < 0 {
		from = 0
	}
	for i := at - 1; i >= from; i-- {
		switch lower[i] {
		case '\n', '\r', '!', '?':
			return i + 1
		case '.':
			if addrFullStop(lower, from, i) {
				return i + 1
			}
		}
	}
	return from
}

func addrSentenceEnds(lower string, from, to int) bool {
	for i := from; i < to; i++ {
		switch lower[i] {
		case '\n', '\r', '!', '?':
			return true
		case '.':
			if addrFullStop(lower, 0, i) {
				return true
			}
		}
	}
	return false
}

func addrFullStop(lower string, from, i int) bool {
	start, _ := text.ExpandWord(lower, i, i)
	if start < from {
		start = from
	}
	w := lower[start:i]
	if w == "" {
		return true
	}
	for _, r := range w {
		if unicode.IsLetter(r) {
			return utf8.RuneCountInString(w) > addrOrgAbbrevRunes
		}
	}
	return true // digits only before the dot: "дом 10." is a real full stop
}

func addrNextWord(lower string, p, to int) (int, int) {
	for p < to {
		r, sz := utf8.DecodeRuneInString(lower[p:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			break
		}
		p += sz
	}
	if p >= to {
		return -1, -1
	}
	start := p
	for p < to {
		r, sz := utf8.DecodeRuneInString(lower[p:])
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			break
		}
		p += sz
	}
	return start, p
}

func addrHasNeighbour(all []addrCandidate, idx int) bool {
	c := all[idx]
	const reach = addrNeighbourGap + addrNeighbourSlack
	for j := idx - 1; j >= 0 && c.span.Start-all[j].span.Start <= reach; j-- {
		if addrIsNeighbour(all[j], c) {
			return true
		}
	}
	for j := idx + 1; j < len(all) && all[j].span.Start-c.span.Start <= reach; j++ {
		if addrIsNeighbour(all[j], c) {
			return true
		}
	}
	return false
}

func addrIsNeighbour(o, c addrCandidate) bool {
	if o.span.Type == c.span.Type && !addrRegionPair(o, c) {
		return false
	}
	gap := o.span.Start - c.span.End
	if gap < 0 {
		gap = c.span.Start - o.span.End
	}
	return gap >= 0 && gap <= addrNeighbourGap
}

func addrRegionPair(o, c addrCandidate) bool {
	return o.span.Type == pd.TypeCity &&
		(o.span.Hint == addrHintRegion) != (c.span.Hint == addrHintRegion)
}

func addrBareCity(ctx *Context, i int, caseBlind bool) (addrCandidate, bool) {
	t := ctx.Tokens[i]
	if !caseBlind && !addrStartsUpper(ctx.Text[t.Start:t.End]) {
		return addrCandidate{}, false
	}
	w := ctx.Lower[t.Start:t.End]
	if !dict.IsCityForm(w) {
		return addrCandidate{}, false
	}
	start := t.Start
	switch {
	case dict.IsCity(w):
	case addrPrecededByLocative(ctx, i):
	default:
		h := addrHyphenHead(ctx, i)
		if h < 0 {
			return addrCandidate{}, false
		}
		start = ctx.Tokens[h].Start
	}
	return addrCandidate{
		span:           pd.Span{Start: start, End: t.End, Type: pd.TypeCity, Src: "address", Hint: "city"},
		needsNeighbour: true,
		residenceOK:    true,
		name:           w,
	}, true
}

func addrStartsUpper(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	if c < utf8.RuneSelf {
		return 'A' <= c && c <= 'Z'
	}
	if len(s) > 1 {
		switch c {
		case 0xD0:
			// U+0400..U+042F — Ѐ..Џ and А..Я, uppercase throughout.
			// U+0430..U+043F (D0 B0..BF) is а..о, lower case.
			return s[1] >= 0x80 && s[1] <= 0xAF
		case 0xD1:
			// U+0440..U+045F — р..я and ѐ..џ, lower case throughout. Beyond
			// that lie the archaic letters, which the table below settles.
			if s[1] <= 0x9F {
				return false
			}
		}
	}
	return text.IsUpperFirst(s)
}

func addrHyphenHead(ctx *Context, i int) int {
	toks := ctx.Tokens
	if i < 2 || !addrPunctByte(ctx, toks[i-1], '-') || toks[i-2].Kind != text.KindWord {
		return -1
	}
	h := i - 2
	for h >= 2 && addrPunctByte(ctx, toks[h-1], '-') && toks[h-2].Kind == text.KindWord {
		h -= 2
	}
	return h
}

func addrIsRegionAdjective(ctx *Context, t text.Token, caseBlind bool) bool {
	if !caseBlind && !addrStartsUpper(ctx.Text[t.Start:t.End]) {
		return false
	}
	w := ctx.Lower[t.Start:t.End]
	if _, generic := addrGenericAdmin[w]; generic {
		return false
	}
	if _, marker := addrMarkers[w]; marker {
		return false
	}
	for _, suf := range addrRegionAdjSuffixes {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	return false
}

func addrPrecededByLocative(ctx *Context, i int) bool {
	p := addrPrevNonSpace(ctx.Tokens, i-1)
	if p < 0 || ctx.Tokens[p].Kind != text.KindWord {
		return false
	}
	_, ok := addrLocativePreps[ctx.Lower[ctx.Tokens[p].Start:ctx.Tokens[p].End]]
	return ok
}

func addrCommaChain(ctx *Context, after int, caseBlind bool) (street, house addrCandidate, next int, ok bool) {
	toks := ctx.Tokens
	k := addrSkipSpace(toks, after)
	if k < 0 || !addrPunctByte(ctx, toks[k], ',') {
		return street, house, after, false
	}
	s, e, n, found := addrScanName(ctx, k+1, true, caseBlind)
	if !found {
		return street, house, after, false
	}
	name := ctx.Lower[s:e]
	if dict.IsCityForm(name) || addrIsCountryWord(name) {
		return street, house, after, false
	}

	k = addrSkipSpace(toks, n)
	if k < 0 {
		return street, house, after, false
	}
	if addrPunctByte(ctx, toks[k], ',') {
		k = addrSkipSpace(toks, k+1)
		if k < 0 {
			return street, house, after, false
		}
	}
	h := toks[k]
	if h.Kind != text.KindNumber && h.Kind != text.KindAlnum {
		return street, house, after, false
	}
	if !addrIsDigit(ctx.Text[h.Start]) || h.Len() > addrMaxValueLen ||
		text.CountDigits(ctx.Text[h.Start:h.End]) > addrBareHouseMaxDigits {
		return street, house, after, false
	}
	street = addrCandidate{
		span: pd.Span{Start: s, End: e, Type: pd.TypeStreet, Src: "address", Hint: "street"},
		name: name,
	}
	house = addrCandidate{
		span: pd.Span{Start: h.Start, End: h.End, Type: pd.TypeHouse, Src: "address", Hint: "house"},
	}
	return street, house, k + 1, true
}

// addrNamedSpec describes the candidate a named-address scan should build.
type addrNamedSpec struct {
	typ            pd.Type
	hint           string
	needsNeighbour bool
	allowOrdinal   bool
}

func addrNamedCandidate(ctx *Context, idx, after int, caseBlind bool, spec addrNamedSpec) (addrCandidate, int, bool) {

	if s, e, next, ok := addrScanName(ctx, after, spec.allowOrdinal, caseBlind); ok {
		return addrCandidate{
			span:           pd.Span{Start: s, End: e, Type: spec.typ, Src: "address", Hint: spec.hint},
			needsNeighbour: spec.needsNeighbour,
			name:           ctx.Lower[s:e],
		}, next, true
	}

	toks := ctx.Tokens
	p := addrPrevNonSpace(toks, idx-1)
	if p < 0 || toks[p].Kind != text.KindWord {
		return addrCandidate{}, idx, false
	}
	if !addrIsNameWord(ctx, toks[p], caseBlind) &&
		!(spec.hint == addrHintRegion && addrIsRegionAdjective(ctx, toks[p], caseBlind)) {
		return addrCandidate{}, idx, false
	}
	start, end := toks[p].Start, toks[p].End
	for p-2 >= 0 && addrPunctByte(ctx, toks[p-1], '-') && toks[p-2].Kind == text.KindWord {
		start = toks[p-2].Start
		p -= 2
	}
	w := ctx.Lower[start:end]
	if dict.IsCityForm(w) || addrPrecededByCity(ctx, p) {
		return addrCandidate{}, idx, false // that word is the city, not the street
	}
	return addrCandidate{
		span:           pd.Span{Start: start, End: end, Type: spec.typ, Src: "address", Hint: spec.hint},
		needsNeighbour: spec.needsNeighbour,
		name:           w,
	}, after, true
}

func addrCountryCandidate(ctx *Context, i int) (addrCandidate, int, bool) {
	toks := ctx.Tokens
	t := toks[i]
	w := ctx.Lower[t.Start:t.End]

	if w == "российская" || w == "россииская" {
		if n := addrSkipSpace(toks, i+1); n >= 0 && toks[n].Kind == text.KindWord &&
			strings.HasPrefix(ctx.Lower[toks[n].Start:toks[n].End], "федераци") {
			return addrCandidate{
				span:           pd.Span{Start: t.Start, End: toks[n].End, Type: pd.TypeCountry, Src: "address", Hint: "country"},
				needsNeighbour: true,
				name:           ctx.Lower[t.Start:toks[n].End],
			}, n + 1, true
		}
	}
	if !addrIsCountryWord(w) {
		return addrCandidate{}, i, false
	}
	return addrCandidate{
		span:           pd.Span{Start: t.Start, End: t.End, Type: pd.TypeCountry, Src: "address", Hint: "country"},
		needsNeighbour: true,
		name:           w,
	}, i + 1, true
}

func addrIsCountryWord(w string) bool {
	if dict.IsCountry(w) {
		return true
	}
	_, ok := addrCountries[w]
	return ok
}

func addrPostalCandidate(ctx *Context, i int) (addrCandidate, bool) {
	t := ctx.Tokens[i]
	if t.Len() != 6 {
		return addrCandidate{}, false
	}
	anchored := addrLastPhrase(ctx.Lower, t.Start-40, t.Start, addrPostalWords) >= 0
	if !anchored && !addrPostalStructural(ctx, i) && !addrPostalTrailing(ctx, i) {
		return addrCandidate{}, false
	}
	return addrCandidate{
		span: pd.Span{Start: t.Start, End: t.End, Type: pd.TypePostalCode, Src: "address", Hint: "postal_code"},
	}, true
}

func addrPostalStructural(ctx *Context, i int) bool {
	toks := ctx.Tokens
	n := i + 1
	if n >= len(toks) || !addrPunctByte(ctx, toks[n], ',') {
		return false
	}
	limit := toks[i].End + 40
	for j := n + 1; j < len(toks) && toks[j].Start < limit; j++ {
		if toks[j].Kind != text.KindWord {
			continue
		}
		w := ctx.Lower[toks[j].Start:toks[j].End]
		if _, ok := addrMarkers[w]; ok {
			return true
		}
		if dict.IsStreetType(w) || dict.IsCityForm(w) {
			return true
		}
	}
	return false
}

func addrPostalTrailing(ctx *Context, i int) bool {
	toks := ctx.Tokens
	if !addrEndsLine(ctx, i) {
		return false
	}
	k := addrPrevNonSpace(toks, i-1)
	if k < 0 || !addrPunctByte(ctx, toks[k], ',') {
		return false
	}
	k = addrPrevNonSpace(toks, k-1)
	if k < 0 {
		return false
	}
	switch toks[k].Kind {
	case text.KindWord:
		if dict.IsCityForm(ctx.Lower[toks[k].Start:toks[k].End]) {
			return true
		}
	case text.KindNumber, text.KindAlnum:
		// "..., д. 5, 119991" — decided by the marker scan below.
	default:
		return false
	}
	return addrMarkerNear(ctx, k, addrPostalNearby)
}

func addrEndsLine(ctx *Context, i int) bool {
	toks := ctx.Tokens
	n := i + 1
	if n >= len(toks) {
		return true
	}
	if toks[n].Kind == text.KindPunct && toks[n].Len() == 1 {
		switch ctx.Text[toks[n].Start] {
		case '.', ';', ')':
			n++
		}
	}
	if n >= len(toks) {
		return true
	}
	return toks[n].Kind == text.KindSpace &&
		strings.ContainsAny(ctx.Text[toks[n].Start:toks[n].End], "\n\r")
}

func addrMarkerNear(ctx *Context, k, limit int) bool {
	toks := ctx.Tokens
	floor := toks[k].Start - limit
	for j := k; j >= 0 && toks[j].End > floor; j-- {
		if toks[j].Kind != text.KindWord {
			continue
		}
		w := ctx.Lower[toks[j].Start:toks[j].End]
		if _, ok := addrMarkers[w]; ok {
			return true
		}
		if dict.IsStreetType(w) || dict.IsCityForm(w) {
			return true
		}
	}
	return false
}

func addrBareHouse(ctx *Context, i, lastStreetEnd int) (addrCandidate, bool) {
	t := ctx.Tokens[i]
	if lastStreetEnd < 0 || t.Start-lastStreetEnd > addrBareHouseGap {
		return addrCandidate{}, false
	}
	if !addrIsDigit(ctx.Text[t.Start]) ||
		text.CountDigits(ctx.Text[t.Start:t.End]) > addrBareHouseMaxDigits ||
		t.Len() > addrMaxValueLen {
		return addrCandidate{}, false
	}
	// Exactly one comma, optionally followed by one space, may stand between.
	if strings.TrimSpace(ctx.Text[lastStreetEnd:t.Start]) != "," {
		return addrCandidate{}, false
	}
	return addrCandidate{
		span: pd.Span{Start: t.Start, End: t.End, Type: pd.TypeHouse, Src: "address", Hint: "house"},
	}, true
}

func addrMarkerAt(ctx *Context, i int) (addrMarker, int, bool) {
	toks := ctx.Tokens
	t := toks[i]
	if t.Kind != text.KindWord {
		return addrMarker{}, i, false
	}
	w := ctx.Lower[t.Start:t.End]

	if i+2 < len(toks) && addrPunctByte(ctx, toks[i+1], '-') && toks[i+2].Kind == text.KindWord {
		joined := w + "-" + ctx.Lower[toks[i+2].Start:toks[i+2].End]
		if m, ok := addrMarkers[joined]; ok {
			return m, addrSkipDot(ctx, i+3), true
		}
	}

	m, ok := addrMarkers[w]
	if !ok {
		if dict.IsStreetType(w) {
			m, ok = addrMarker{addrMkStreet, false}, true
		} else {
			return addrMarker{}, i, false
		}
	}
	next := i + 1
	hasDot := next < len(toks) && addrPunctByte(ctx, toks[next], '.')
	if m.needDot && !hasDot {
		return addrMarker{}, i, false
	}
	if hasDot {
		next++
	}
	return m, next, true
}

func addrSkipDot(ctx *Context, i int) int {
	if i < len(ctx.Tokens) && addrPunctByte(ctx, ctx.Tokens[i], '.') {
		return i + 1
	}
	return i
}

func addrIsYearMarker(ctx *Context, i int) bool {
	p := addrPrevNonSpace(ctx.Tokens, i-1)
	return p >= 0 && ctx.Tokens[p].Kind == text.KindNumber
}

func addrScanName(ctx *Context, i int, allowOrdinal, caseBlind bool) (start, end, next int, ok bool) {
	toks := ctx.Tokens
	k := addrSkipSpace(toks, i)
	if k < 0 {
		return 0, 0, i, false
	}
	start, end = -1, -1

	if allowOrdinal && toks[k].Kind == text.KindNumber {
		var nk int
		start, end, nk, ok = addrScanOrdinal(ctx, k, caseBlind)
		if !ok {
			return 0, 0, i, false
		}
		k = nk
	}

	start, end, k, ok = addrScanNameWords(ctx, k, start, end, caseBlind)
	if !ok {
		return 0, 0, i, false
	}
	return start, end, k, true
}

// addrScanOrdinal reads an ordinal prefix ("5-я") of a street name and the name
// word that must follow it.
func addrScanOrdinal(ctx *Context, k int, caseBlind bool) (start, end, next int, ok bool) {
	toks := ctx.Tokens
	start, end = toks[k].Start, toks[k].End
	k++
	if k+1 < len(toks) && addrPunctByte(ctx, toks[k], '-') &&
		toks[k+1].Kind == text.KindWord && toks[k+1].Len() <= 4 {
		end = toks[k+1].End
		k += 2
	}
	n := addrSkipSpace(toks, k)
	// A bare number after a street marker is a house number, not a name.
	if n < 0 || toks[n].Kind != text.KindWord || !addrIsNameWord(ctx, toks[n], caseBlind) {
		return 0, 0, k, false
	}
	return start, end, n, true
}

// addrScanNameWords walks the consecutive words of a toponym, extending across
// hyphens and single spaces.
func addrScanNameWords(ctx *Context, k, start, end int, caseBlind bool) (int, int, int, bool) {
	toks := ctx.Tokens
	for words := 0; k < len(toks) && words < addrMaxNameWords; words++ {
		t := toks[k]
		if t.Kind != text.KindWord || !addrIsNameWord(ctx, t, caseBlind) {
			break
		}
		if start < 0 {
			start = t.Start
		}
		end = t.End
		k++
		k = addrExtendHyphen(ctx, k, &end)
		// Continue only across exactly one space: any punctuation ends the name.
		if addrCanContinueName(ctx, k, caseBlind) {
			k++
			continue
		}
		break
	}
	return start, end, k, start >= 0 && end >= 0
}

// addrExtendHyphen folds a hyphenated tail ("Ленина-Кузнецова") into the name.
func addrExtendHyphen(ctx *Context, k int, end *int) int {
	toks := ctx.Tokens
	for k+1 < len(toks) && addrPunctByte(ctx, toks[k], '-') && toks[k+1].Kind == text.KindWord {
		*end = toks[k+1].End
		k += 2
	}
	return k
}

// addrCanContinueName reports whether the name may continue across exactly one
// space into another name word.
func addrCanContinueName(ctx *Context, k int, caseBlind bool) bool {
	toks := ctx.Tokens
	return k+1 < len(toks) && toks[k].Kind == text.KindSpace &&
		toks[k+1].Kind == text.KindWord && addrIsNameWord(ctx, toks[k+1], caseBlind)
}

func addrIsNameWord(ctx *Context, t text.Token, caseBlind bool) bool {
	if t.Kind != text.KindWord {
		return false
	}
	w := ctx.Lower[t.Start:t.End]
	if utf8.RuneCountInString(w) < 2 {
		return false
	}
	if _, isMarker := addrMarkers[w]; isMarker {
		return false
	}
	if dict.IsStreetType(w) || dict.IsStopWord(w) {
		return false
	}
	if _, conn := addrNameConnectors[w]; conn {
		return true
	}
	return caseBlind || addrStartsUpper(ctx.Text[t.Start:t.End])
}

// addrScanValue reads a house or flat number. Demanding a leading DIGIT is what
// keeps "дом культуры" and "квартира-студия" out of the results: both are
// followed by a word, not a number.
//
// letter admits the one exception, "д. 5 литера Б": a single UPPERCASE letter.
// The case requirement is not relaxed for a case-blind payload the way toponym
// scanning relaxes it, because the words that would then qualify are exactly
// the single-letter prepositions — "стр. в договоре" must not yield a building
// named "в", and in a lower-cased payload nothing else tells the two apart.
func addrScanValue(ctx *Context, i int, letter bool) (start, end, next int, ok bool) {
	toks := ctx.Tokens
	k := addrSkipSpace(toks, i)
	if k < 0 {
		return 0, 0, i, false
	}
	t := toks[k]
	if letter && t.Kind == text.KindWord && t.Len() <= 2 &&
		utf8.RuneCountInString(ctx.Text[t.Start:t.End]) == 1 &&
		addrStartsUpper(ctx.Text[t.Start:t.End]) {
		return t.Start, t.End, k + 1, true
	}
	if t.Kind != text.KindNumber && t.Kind != text.KindAlnum {
		return 0, 0, i, false
	}
	if !addrIsDigit(ctx.Text[t.Start]) || t.Len() > addrMaxValueLen {
		return 0, 0, i, false
	}
	start, end = t.Start, t.End
	k++
	// "д. 5/1"
	for k+1 < len(toks) && addrPunctByte(ctx, toks[k], '/') &&
		(toks[k+1].Kind == text.KindNumber || toks[k+1].Kind == text.KindAlnum) &&
		addrIsDigit(ctx.Text[toks[k+1].Start]) && toks[k+1].Len() <= addrMaxValueLen {
		end = toks[k+1].End
		k += 2
	}
	return start, end, k, true
}

func (d addressDetector) fallback(ctx *Context, raw []addrCandidate) (pd.Span, bool) {
	if !ctx.Enabled(pd.TypeAddress) {
		return pd.Span{}, false
	}
	const anchor = "адрес"
	for off := 0; off+len(anchor) <= len(ctx.Lower); {
		j := strings.Index(ctx.Lower[off:], anchor)
		if j < 0 {
			return pd.Span{}, false
		}
		j += off
		off = j + len(anchor)
		if !text.IsBoundary(ctx.Lower, j) {
			continue
		}
		_, wordEnd := text.ExpandWord(ctx.Lower, j, off)
		form := ctx.Lower[j:wordEnd]

		p := addrSkipSpaces(ctx.Lower, wordEnd)
		if addrColonOrDash(ctx.Lower, p) {
			p++
		} else if form != "адресу" {
			continue // "адрес" without a colon is a sentence, not a value
		}
		if s, ok := addrFallbackRun(ctx, p, raw); ok {
			return s, true
		}
	}
	return pd.Span{}, false
}

// addrSkipSpaces advances p past any run of spaces and tabs.
func addrSkipSpaces(s string, p int) int {
	for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
		p++
	}
	return p
}

// addrColonOrDash reports whether a colon or a dash stands at p.
func addrColonOrDash(s string, p int) bool {
	return p < len(s) && (s[p] == ':' || s[p] == '-')
}

func addrFallbackRun(ctx *Context, p int, raw []addrCandidate) (pd.Span, bool) {
	p = addrSkipSpaces(ctx.Text, p)
	end := addrCutRun(ctx.Text, p)
	start, end, ok := text.TrimSpanEdges(ctx.Text, p, end)
	if !ok || end-start < 10 {
		return pd.Span{}, false
	}
	run := ctx.Text[start:end]
	// An address always carries a number; an e-mail or a URL never qualifies.
	if text.CountDigits(run) == 0 || strings.Contains(run, "@") || strings.Contains(ctx.Lower[start:end], "http") {
		return pd.Span{}, false
	}
	if len(strings.Fields(run)) < 2 {
		return pd.Span{}, false
	}
	if addrOverlapsRaw(raw, start, end) {
		return pd.Span{}, false // decomposed (or deliberately dropped) already
	}
	if addrLastPhrase(ctx.Lower, start-addrBankWindow, start, addrBankWords) >= 0 {
		return pd.Span{}, false
	}
	if addrOrgSubject(ctx.Lower, addrSentenceStart(ctx.Lower, start), start) {
		return pd.Span{}, false
	}
	return pd.Span{
		Start: start, End: end, Type: pd.TypeAddress,
		Conf: 0.9, Src: "address", Hint: "full",
	}, true
}

// addrOverlapsRaw reports whether [start,end) overlaps any already-decomposed
// candidate.
func addrOverlapsRaw(raw []addrCandidate, start, end int) bool {
	for _, c := range raw {
		if c.span.Start < end && start < c.span.End {
			return true
		}
	}
	return false
}

func addrCutRun(s string, p int) int {
	limit := p + addrMaxRun
	if limit > len(s) {
		limit = len(s)
	}
	for i := p; i < limit; i++ {
		switch s[i] {
		case '\n', '\r', ';':
			return i
		case '.':
			if i+2 < len(s) && s[i+1] == ' ' && addrIsUpperAt(s, i+2) && !addrShortWordBefore(s, p, i) {
				return i
			}
		}
	}
	return limit
}

func addrShortWordBefore(s string, from, dot int) bool {
	start, _ := text.ExpandWord(s, dot, dot)
	if start < from {
		start = from
	}
	return utf8.RuneCountInString(s[start:dot]) <= 4
}

func addrIsUpperAt(s string, i int) bool {
	return text.IsUpperFirst(s[i:])
}

func addrLastPhrase(lower string, from, to int, phrases []string) int {
	if from < 0 {
		from = 0
	}
	if to > len(lower) {
		to = len(lower)
	}
	if from >= to {
		return -1
	}
	win := lower[from:to]
	best := -1
	for _, p := range phrases {
		for at := 0; ; {
			i := strings.Index(win[at:], p)
			if i < 0 {
				break
			}
			i += at
			abs := from + i
			if abs > best && text.IsBoundary(lower, abs) {
				best = abs
			}
			at = i + 1
		}
	}
	return best
}

func addrPrecededByCity(ctx *Context, p int) bool {
	toks := ctx.Tokens
	k := addrPrevNonSpace(toks, p-1)
	if k >= 0 && addrPunctByte(ctx, toks[k], '.') {
		k = addrPrevNonSpace(toks, k-1)
	}
	if k < 0 || toks[k].Kind != text.KindWord {
		return false
	}
	m, ok := addrMarkers[ctx.Lower[toks[k].Start:toks[k].End]]
	return ok && m.kind == addrMkCity
}

func addrSkipSpace(toks []text.Token, i int) int {
	for i >= 0 && i < len(toks) && toks[i].Kind == text.KindSpace {
		i++
	}
	if i < 0 || i >= len(toks) {
		return -1
	}
	return i
}

func addrPrevNonSpace(toks []text.Token, i int) int {
	for i >= 0 && i < len(toks) && toks[i].Kind == text.KindSpace {
		i--
	}
	if i < 0 || i >= len(toks) {
		return -1
	}
	return i
}

func addrPunctByte(ctx *Context, t text.Token, b byte) bool {
	return t.Kind == text.KindPunct && t.Len() == 1 && ctx.Text[t.Start] == b
}

func addrIsDigit(b byte) bool { return b >= '0' && b <= '9' }
