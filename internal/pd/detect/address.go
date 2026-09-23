// Address detection.
//
// WHY COMPONENTS AND NOT ONE SPAN OVER THE WHOLE ADDRESS.
// Quality is scored as a span-based Levenshtein distance against a reference
// mask, so every byte we rewrite outside real personal data is a direct
// penalty. A Russian address is glue plus values: "г.", "ул.", "д.", "кв.",
// commas and spaces are service words, not personal data, and the reference
// mask keeps them. Emitting one span over "г. Москва, ул. Ленина, д. 5" would
// therefore corrupt the glue and cost us distance on every such address.
// Hence this detector returns SEPARATE spans for city, street, house, flat,
// postal code and country, always excluding the marker itself.
// pd.TypeAddress is used only as a fallback: an address that follows an
// explicit anchor as one opaque run we could not decompose.
//
// The second rule that shapes everything here: a miss costs less than a false
// positive. A component is emitted only with an explicit address anchor
// nearby, or when a second component of a different kind sits next to it.
//
// No regexp is used at all — the whole scan is a single allocation-free walk
// over ctx.Tokens, which matters on 100k-token payloads at 1000 RPS.
package detect

import (
	"sort"

	"pdguard/internal/pd"
	"pdguard/internal/pd/text"
)

// addrMarkerKind classifies an address keyword.
type addrMarkerKind uint8

const (
	addrMkStreet addrMarkerKind = iota + 1
	addrMkCity
	addrMkRegion // область/край/республика/район: an administrative unit of the address
	addrMkHouse
	addrMkCorpus // корпус/строение: a second HOUSE span, only valid after a house
	addrMkApartment
)

// addrMarker describes one address keyword. needDot marks short abbreviations
// that collide with an ordinary Russian word and are therefore only safe with
// the dot: "с." is a village while "с" is a preposition, "к." is a building
// while "к" is a preposition, "пл." is a square while "пл" ends "пл." forms.
//
// It is NOT set on abbreviations that are not words in their own right — "ул",
// "кв", "просп", "наб", "мкр", "корп", "влад", "пом". Demanding the dot there
// bought no precision at all (none of them can appear as an ordinary word) and
// cost the whole address whenever someone typed "ул Ленина д 5 кв 10" without
// dots, which is how addresses arrive from a chat box or a hand-filled form.
type addrMarker struct {
	kind    addrMarkerKind
	needDot bool
}

// addrCandidate is one component of an address found by scan.
type addrCandidate struct {
	span pd.Span
	// needsNeighbour marks components that are meaningless on their own (a
	// country name, a bare city name): an anchor is not enough for them, a
	// second address component must be present.
	needsNeighbour bool
	// residenceOK lets a needsNeighbour component be saved by an explicit
	// statement that a person LIVES there. Only settlement names carry it: a
	// country or a region is still too coarse to be somebody's address on its
	// own, while "проживает в Екатеринбурге" is a complete one.
	residenceOK bool
	// name is the lowercased toponym, used for the bank-place lookup.
	name string
}

// addressDetector finds addresses and their components. It is stateless.
type addressDetector struct{}

// addrSentCache memoises the sentence start and organisation heading for the
// current request. It lives on the caller's stack — zero allocations.
type addrSentCache struct {
	at    int // offset the cached sentence was validated for; -1 when empty
	start int // first byte of that sentence
	head  int // offset past its organisation heading; -1 when it has none
}

const (
	// addrAnchorWindow is how far left of a component an address anchor may sit.
	// It is generous because Cyrillic costs two bytes per character: 120 bytes
	// is only about 60 characters, i.e. one address line.
	addrAnchorWindow = 120
	// addrBankWindow is wider than addrAnchorWindow on purpose: failing to mask a bank
	// branch address costs nothing, masking it costs metric points.
	addrBankWindow = 200
	// addrSentenceWindow bounds the backward walk that looks for the start of
	// the current sentence. A sentence longer than this is simply cut at the
	// window: the cap can only HIDE an organisation marker, never invent one,
	// so the worst case is the behaviour we had before the sentence rule.
	addrSentenceWindow = 400
	// addrOrgMaxModifiers caps how many adjectives may stand between the start
	// of the sentence and its head noun ("наш головной офис"). Past that the
	// sentence is about something else and the noun is no longer its subject.
	addrOrgMaxModifiers = 3
	// addrOrgAbbrevRunes is the longest LETTER word that a dot may abbreviate.
	// Every address abbreviation is within it: "г.", "ул.", "д.", "кв.",
	// "корп.", "стр.", "лит.".
	addrOrgAbbrevRunes = 4
	// addrNeighbourGap is the maximum distance between two components of one
	// address; beyond it they are unrelated mentions.
	addrNeighbourGap = 60
	// addrNeighbourSlack is the longest a component itself can be — three
	// Cyrillic words plus hyphens. addrHasNeighbour walks a slice ordered by
	// span START, so it needs this much headroom before it may stop.
	addrNeighbourSlack = 96
	// addrCorpusGap bounds "д. 5 корп. 2": a bare "стр. 3" far from any house is a
	// page reference, not a building.
	addrCorpusGap = 40
	// addrMaxNameWords caps a toponym so a runaway scan cannot swallow a sentence.
	addrMaxNameWords = 3
	// addrMaxValueLen bounds a house/flat number in bytes; longer digit runs are
	// account numbers, not buildings.
	addrMaxValueLen = 8
	// addrBareHouseMaxDigits bounds the markerless "<улица>, 5" house number.
	// Three digits cover every real Russian house number and, crucially, exclude
	// a four-digit year: "ул. Победы, 1941 год" must stay byte-identical, and a
	// year after a street name is a far more common sentence than a house above
	// 999. A trailing letter ("5а") arrives as one KindAlnum token and is fine.
	addrBareHouseMaxDigits = 3
	// addrBareHouseGap is how far past the street name the bare number may sit.
	// It only has to span ", ".
	addrBareHouseGap = 3
	// addrPostalNearby is how far left of a trailing index an address marker may
	// sit. One component — ", д. 5," or ", ул. Ленина," — is all it has to span.
	addrPostalNearby = 40
	// addrMaxRun bounds the opaque-address fallback.
	addrMaxRun = 220
)

// addrHintRegion marks the CITY spans that are really an administrative unit.
// The type catalogue has no separate region category, so the hint is what tells
// the two apart — for the neighbour rule and for logs.
const addrHintRegion = "region"

// addrMarkers is the closed set of Russian address keywords. It is deliberately
// kept in code rather than in dict/: these are grammar-like function words of
// the address format, not open-ended lexical data, and the detector must work
// even before the dictionaries are populated. dict.IsStreetType is consulted
// in addition to this table, never instead of it.
// Oblique case forms are listed explicitly rather than derived, for the same
// reason dict/inflect.go expands city names at start-up: a table lookup costs
// one hash, building a stem on every token costs an allocation. Running text
// writes "на улице Вавилова", "по Ленинскому проспекту", "к дому 5" far more
// often than the nominative, and every form missing here is a lost address.
var addrMarkers = map[string]addrMarker{
	// street types
	"улица": {addrMkStreet, false}, "улице": {addrMkStreet, false},
	"улицы": {addrMkStreet, false}, "улицу": {addrMkStreet, false},
	"улицей": {addrMkStreet, false}, "улицам": {addrMkStreet, false},
	"ул":          {addrMkStreet, false},
	"проспект":    {addrMkStreet, false},
	"проспекте":   {addrMkStreet, false},
	"проспекта":   {addrMkStreet, false},
	"проспекту":   {addrMkStreet, false},
	"проспектом":  {addrMkStreet, false},
	"просп":       {addrMkStreet, false},
	"пр-т":        {addrMkStreet, false},
	"пр-кт":       {addrMkStreet, false},
	"переулок":    {addrMkStreet, false},
	"переулке":    {addrMkStreet, false},
	"переулка":    {addrMkStreet, false},
	"переулку":    {addrMkStreet, false},
	"пер":         {addrMkStreet, true},
	"бульвар":     {addrMkStreet, false},
	"бульваре":    {addrMkStreet, false},
	"бульвара":    {addrMkStreet, false},
	"бульвару":    {addrMkStreet, false},
	"б-р":         {addrMkStreet, false},
	"шоссе":       {addrMkStreet, false},
	"ш":           {addrMkStreet, true},
	"набережная":  {addrMkStreet, false},
	"набережной":  {addrMkStreet, false},
	"набережную":  {addrMkStreet, false},
	"наб":         {addrMkStreet, false},
	"площадь":     {addrMkStreet, false},
	"площади":     {addrMkStreet, false},
	"пл":          {addrMkStreet, true},
	"проезд":      {addrMkStreet, false},
	"проезде":     {addrMkStreet, false},
	"проезду":     {addrMkStreet, false},
	"тупик":       {addrMkStreet, false},
	"туп":         {addrMkStreet, true},
	"аллея":       {addrMkStreet, false},
	"аллее":       {addrMkStreet, false},
	"тракт":       {addrMkStreet, false},
	"тракте":      {addrMkStreet, false},
	"микрорайон":  {addrMkStreet, false},
	"микрорайоне": {addrMkStreet, false},
	"мкр":         {addrMkStreet, false},
	"мкрн":        {addrMkStreet, false},
	"территория":  {addrMkStreet, false},
	"снт":         {addrMkStreet, false},

	// settlement types
	"г": {addrMkCity, false}, "гор": {addrMkCity, true}, "город": {addrMkCity, false},
	"городе": {addrMkCity, false}, "городу": {addrMkCity, false}, "пгт": {addrMkCity, false},
	"с": {addrMkCity, true}, "село": {addrMkCity, false}, "селе": {addrMkCity, false},
	"дер": {addrMkCity, true}, "деревня": {addrMkCity, false}, "деревне": {addrMkCity, false},
	"пос": {addrMkCity, true}, "посёлок": {addrMkCity, false}, "поселок": {addrMkCity, false},
	"посёлке": {addrMkCity, false}, "поселке": {addrMkCity, false},
	"ст-ца": {addrMkCity, false}, "станица": {addrMkCity, false},
	"станице": {addrMkCity, false},
	"х":       {addrMkCity, true}, "хутор": {addrMkCity, false}, "рп": {addrMkCity, false},

	// administrative units. They were previously reached only through
	// dict.IsStreetType, which typed a region as a STREET; worse, that path does
	// not demand a second component, while "в Московской области открыт офис" is
	// ordinary prose. addrMkRegion fixes both: a proper CITY-class span, and
	// needsNeighbour so a region alone is never an address.
	"область": {addrMkRegion, false}, "обл": {addrMkRegion, false},
	"области": {addrMkRegion, false}, "областью": {addrMkRegion, false},
	"край": {addrMkRegion, false}, "края": {addrMkRegion, false},
	"крае": {addrMkRegion, false}, "краю": {addrMkRegion, false},
	"республика": {addrMkRegion, false}, "республике": {addrMkRegion, false},
	"республики": {addrMkRegion, false}, "респ": {addrMkRegion, false},
	"район": {addrMkRegion, false}, "районе": {addrMkRegion, false},
	"района": {addrMkRegion, false}, "р-н": {addrMkRegion, false},
	"округ": {addrMkRegion, false}, "округе": {addrMkRegion, false},

	// house and its parts. "д" carries no dot requirement: unlike "с"/"к"/"пл"
	// it is not a Russian word, and addrScanValue already insists on a digit
	// right behind it, so "д 5" cannot fire on prose while "ул Ленина д 5 кв 10"
	// — how an address arrives from a chat box — now parses in full.
	"д": {addrMkHouse, false}, "дом": {addrMkHouse, false}, "дома": {addrMkHouse, false},
	"дому": {addrMkHouse, false}, "доме": {addrMkHouse, false},
	"влад": {addrMkHouse, false}, "вл": {addrMkHouse, false},
	"владение": {addrMkHouse, false}, "владении": {addrMkHouse, false},
	"домовладение": {addrMkHouse, false},
	"к":            {addrMkCorpus, true}, "корп": {addrMkCorpus, false},
	"корпус": {addrMkCorpus, false}, "корпусе": {addrMkCorpus, false},
	"стр": {addrMkCorpus, true}, "строение": {addrMkCorpus, false},
	"строении": {addrMkCorpus, false},
	"лит":      {addrMkCorpus, true}, "литера": {addrMkCorpus, false},
	"литер": {addrMkCorpus, false},

	// flat and its synonyms
	"кв": {addrMkApartment, false}, "квартира": {addrMkApartment, false},
	"квартире": {addrMkApartment, false}, "квартиру": {addrMkApartment, false},
	"кв-ра": {addrMkApartment, false},
	"офис":  {addrMkApartment, false}, "офисе": {addrMkApartment, false},
	"оф": {addrMkApartment, true}, "апартаменты": {addrMkApartment, false},
	"апарт": {addrMkApartment, true}, "помещение": {addrMkApartment, false},
	"пом": {addrMkApartment, false},
}

var addrLocativePreps = map[string]struct{}{
	"в": {}, "во": {}, "из": {}, "на": {}, "по": {}, "до": {}, "от": {},
	"к": {}, "ко": {}, "под": {}, "подо": {}, "над": {}, "за": {}, "при": {},
	"близ": {}, "около": {}, "вблизи": {},
}

// Address anchor phrases shared by the residence, anchor and personal lists.
// They are kept as constants so the same literal is not duplicated across the
// three slices below.
const (
	addrPhraseProzhivaet   = "проживает"
	addrPhraseProzhivayush = "проживающ"
	addrPhrasePropisan     = "прописан"
	addrPhraseMesto        = "место жительства"
	addrPhraseMesta        = "места жительства"
	addrPhraseMestu        = "месту жительства"
)

var addrResidenceAnchors = []string{
	addrPhraseProzhivaet, "проживаю", addrPhraseProzhivayush, addrPhrasePropisan,
	addrPhraseMesto, addrPhraseMesta, addrPhraseMestu,
}

var addrNameConnectors = map[string]struct{}{
	"реки": {}, "реке": {}, "имени": {}, "им": {},
	"маршала": {}, "генерала": {}, "академика": {}, "адмирала": {},
	"космонавта": {}, "лётчика": {}, "летчика": {}, "профессора": {},
	"братьев": {}, "героев": {}, "партизана": {}, "писателя": {},
	"поэта": {}, "доктора": {}, "капитана": {}, "майора": {},
	"полковника": {}, "инженера": {}, "художника": {}, "композитора": {},
}

var addrAnchors = []string{
	"адрес", addrPhraseProzhivaet, addrPhraseProzhivayush, addrPhrasePropisan, "зарегистрирован",
	"регистраци", addrPhraseMesto, addrPhraseMesta, addrPhraseMestu,
	"доставка", "доставки", "доставить по", "куда", "address", "индекс",
}

// The bare word "адрес" is deliberately absent. "Отделение банка расположено по
// адресу г. Москва, ул. Тверская, д. 7" is the most natural way to write a
// branch address, and there "адресу" stands closer to the toponym than
// "отделение" does — so treating it as personal evidence made the branch
// address win the comparison and get masked, which is exactly the negative
// example the specification calls out.
var addrPersonalAnchors = []string{
	addrPhraseProzhivaet, addrPhraseProzhivayush, addrPhrasePropisan, "зарегистрирован",
	"регистраци", addrPhraseMesto, addrPhraseMesta, addrPhraseMestu,
	"доставка", "доставки", "доставить по", "куда",
}

var addrBankWords = []string{
	"отделен", "филиал", "банкомат", "допофис", "доп. офис", "доп.офис",
	"дополнительный офис", "офис банка", "офисе банка", "головной офис",
	"головном офисе", "операционн", "касса банка", "представительств",
	"офис в", "офис на", "офис по", "офиса в", "офиса на", "офиса по",
	"офисе в", "офисе на", "офисе по", "офисы в", "офисов в",
}

var addrOrgSubjectNouns = map[string]struct{}{
	"офис": {}, "офисы": {}, "допофис": {}, "допофисы": {},
	"отделение": {}, "отделения": {}, "филиал": {}, "филиалы": {},
	"банкомат": {}, "банкоматы": {}, "терминал": {}, "терминалы": {},
	"касса": {}, "кассы": {}, "магазин": {}, "магазины": {},
	"склад": {}, "склады": {}, "пвз": {}, "шоурум": {}, "шоурумы": {},
	"салон": {}, "салоны": {}, "представительство": {}, "представительства": {},
}

var addrOrgSubjectModifiers = map[string]struct{}{
	"наш": {}, "наша": {}, "наше": {}, "наши": {},
	"ваш": {}, "ваша": {}, "ваше": {}, "ваши": {},
	"новый": {}, "новая": {}, "новое": {}, "новые": {},
	"ближайший": {}, "ближайшая": {}, "ближайшее": {}, "ближайшие": {},
	"головной": {}, "головное": {}, "главный": {}, "главное": {},
	"центральный": {}, "центральная": {}, "центральное": {},
	"дополнительный": {}, "операционный": {}, "операционная": {},
	"основной": {}, "корпоративный": {}, "банковский": {},
	"премиум": {}, "премиальный": {}, "флагманский": {},
	"единственный": {}, "первый": {}, "второй": {}, "третий": {},
	"этот": {}, "эта": {}, "данный": {}, "указанный": {}, "местный": {},
}

var addrOrgSubjectPersons = map[string]struct{}{
	"клиента": {}, "клиентки": {}, "клиентов": {}, "заказчика": {},
	"покупателя": {}, "получателя": {}, "сотрудника": {}, "сотрудницы": {},
	"работника": {}, "абонента": {}, "пользователя": {}, "владельца": {},
	"арендатора": {},
}

var addrOrgOwners = map[string]struct{}{
	"организации": {}, "компании": {}, "фирмы": {}, "предприятия": {},
	"юрлица": {}, "банка": {}, "общества": {}, "офиса": {},
}

var addrPostalWords = []string{"индекс", "zip", "postal", "postcode", "почтовый"}

var addrCountries = map[string]struct{}{
	"россия": {}, "россии": {}, "рф": {}, "казахстан": {}, "беларусь": {},
	"белоруссия": {}, "украина": {}, "армения": {}, "узбекистан": {},
	"киргизия": {}, "кыргызстан": {}, "таджикистан": {}, "азербайджан": {},
	"грузия": {}, "молдова": {}, "туркменистан": {},
}

var addrRegionAdjSuffixes = []string{"ская", "ский", "ской", "скую", "цкая", "цкий", "цкой"}

var addrGenericAdmin = map[string]struct{}{
	"городской": {}, "городская": {}, "сельский": {}, "сельская": {},
	"муниципальный": {}, "муниципальная": {}, "федеральный": {},
	"автономный": {}, "автономная": {}, "административный": {},
}

// Name implements Detector.
func (addressDetector) Name() string { return "address" }

// Types implements Detector.
func (addressDetector) Types() []pd.Type {
	return []pd.Type{
		pd.TypeAddress, pd.TypeCountry, pd.TypePostalCode,
		pd.TypeCity, pd.TypeStreet, pd.TypeHouse, pd.TypeApartment,
	}
}

// Detect implements Detector.
func (d addressDetector) Detect(ctx *Context) []pd.Span {
	if len(ctx.Text) == 0 || !d.anyEnabled(ctx) {
		return nil
	}

	raw := d.scan(ctx, addrCaseBlind(ctx))

	kept := make([]addrCandidate, 0, len(raw))
	sent := addrSentCache{at: -1}
	for _, c := range raw {
		if addrIsBankPlace(ctx, c, &sent) {
			continue
		}
		kept = append(kept, c)
	}

	sort.SliceStable(kept, func(i, j int) bool { return kept[i].span.Start < kept[j].span.Start })

	out := make([]pd.Span, 0, len(kept)+1)
	for idx := range kept {
		if s, ok := addrEmitCandidate(ctx, kept, idx); ok {
			out = append(out, s)
		}
	}

	if s, ok := d.fallback(ctx, raw); ok {
		out = append(out, s)
	}
	return Resolve(out)
}

// addrEmitCandidate decides whether one kept candidate becomes a span and with
// what confidence, applying the anchor, neighbour and residence rules.
func addrEmitCandidate(ctx *Context, kept []addrCandidate, idx int) (pd.Span, bool) {
	c := kept[idx]
	if !ctx.Enabled(c.span.Type) {
		return pd.Span{}, false
	}
	anchored := addrLastPhrase(ctx.Lower, c.span.Start-addrAnchorWindow, c.span.Start, addrAnchors) >= 0
	neighbour := false
	if c.needsNeighbour || !anchored {
		neighbour = addrHasNeighbour(kept, idx)
	}
	if s, ok := addrResidenceSpan(ctx, c, neighbour); ok {
		return s, true
	}
	switch {
	case c.needsNeighbour && !neighbour:
		return pd.Span{}, false // a lone country or a bare city name is just a word
	case anchored:
		c.span.Conf = 0.95
	case neighbour:
		c.span.Conf = 0.8
	default:
		return pd.Span{}, false // below 0.7 nothing is emitted at all
	}
	return c.span, true
}

// addrResidenceSpan emits a needsNeighbour component when the text explicitly
// says a person lives there, at the residence confidence.
func addrResidenceSpan(ctx *Context, c addrCandidate, neighbour bool) (pd.Span, bool) {
	if !c.needsNeighbour || neighbour || !c.residenceOK {
		return pd.Span{}, false
	}
	if addrLastPhrase(ctx.Lower, c.span.Start-addrAnchorWindow, c.span.Start, addrResidenceAnchors) < 0 {
		return pd.Span{}, false
	}
	c.span.Conf = 0.9
	return c.span, true
}

func (d addressDetector) anyEnabled(ctx *Context) bool {
	for _, t := range d.Types() {
		if ctx.Enabled(t) {
			return true
		}
	}
	return false
}

func addrCaseBlind(ctx *Context) bool { return ctx.Text == ctx.Lower }

// addrScanState carries the running house and street ends that the scan loop
// threads through its per-token helpers.
type addrScanState struct {
	lastHouseEnd  int
	lastStreetEnd int
}

func (d addressDetector) scan(ctx *Context, caseBlind bool) []addrCandidate {
	toks := ctx.Tokens
	out := make([]addrCandidate, 0, 8)
	st := addrScanState{lastHouseEnd: -1, lastStreetEnd: -1}

	for i := 0; i < len(toks); i++ {
		if cands, ni, ok := addrScanToken(ctx, i, caseBlind, &st); ok {
			out = append(out, cands...)
			i = ni
		}
	}
	return out
}

// addrScanToken dispatches one token to the handler for its kind: a number, a
// non-word, a bare word, or an address marker.
func addrScanToken(ctx *Context, i int, caseBlind bool, st *addrScanState) ([]addrCandidate, int, bool) {
	t := ctx.Tokens[i]
	if t.Kind == text.KindNumber || t.Kind == text.KindAlnum {
		return addrScanNumber(ctx, i, st)
	}
	if t.Kind != text.KindWord {
		return nil, i, false
	}
	m, after, ok := addrMarkerAt(ctx, i)
	if !ok {
		return addrScanWord(ctx, i, caseBlind, st)
	}
	return addrScanMarker(ctx, i, after, m, caseBlind, st)
}

// addrScanNumber handles a digit or alphanumeric token: a postal code, then a
// bare house number. It never advances the cursor past the token itself.
func addrScanNumber(ctx *Context, i int, st *addrScanState) ([]addrCandidate, int, bool) {
	t := ctx.Tokens[i]
	if t.Kind == text.KindNumber {
		if c, ok := addrPostalCandidate(ctx, i); ok {
			return []addrCandidate{c}, i, true
		}
	}
	if c, ok := addrBareHouse(ctx, i, st.lastStreetEnd); ok {
		st.lastHouseEnd = c.span.End
		return []addrCandidate{c}, i, true
	}
	return nil, i, false
}

// addrScanWord handles a word token that is not an address marker: a country, a
// bare city, and the comma chain that may follow it.
func addrScanWord(ctx *Context, i int, caseBlind bool, st *addrScanState) ([]addrCandidate, int, bool) {
	t := ctx.Tokens[i]
	if !caseBlind && !addrStartsUpper(ctx.Text[t.Start:t.End]) {
		return nil, i, false
	}
	if c, next, ok := addrCountryCandidate(ctx, i); ok {
		return []addrCandidate{c}, next - 1, true
	}
	c, ok := addrBareCity(ctx, i, caseBlind)
	if !ok {
		return nil, i, false
	}
	cands := []addrCandidate{c}
	ni := i
	if st2, hs, next, ok := addrCommaChain(ctx, i+1, caseBlind); ok {
		cands = append(cands, st2, hs)
		st.lastStreetEnd, st.lastHouseEnd = st2.span.End, hs.span.End
		ni = next - 1
	}
	return cands, ni, true
}

// addrScanMarker dispatches an address marker to the helper for its kind.
func addrScanMarker(ctx *Context, i, after int, m addrMarker, caseBlind bool, st *addrScanState) ([]addrCandidate, int, bool) {
	switch m.kind {
	case addrMkStreet:
		return addrScanStreet(ctx, i, after, caseBlind, st)
	case addrMkRegion:
		return addrScanRegion(ctx, i, after, caseBlind)
	case addrMkCity:
		return addrScanCity(ctx, i, after, caseBlind, st)
	case addrMkHouse:
		return addrScanHouse(ctx, i, after, st)
	case addrMkCorpus:
		return addrScanCorpus(ctx, i, after, st)
	case addrMkApartment:
		return addrScanApartment(ctx, i, after)
	}
	return nil, i, false
}

// addrScanStreet reads a street name after a street marker and widens the
// street end to cover any trailing token the name scan consumed.
func addrScanStreet(ctx *Context, i, after int, caseBlind bool, st *addrScanState) ([]addrCandidate, int, bool) {
	c, next, ok := addrNamedCandidate(ctx, i, after, caseBlind, addrNamedSpec{
		typ: pd.TypeStreet, hint: "street", allowOrdinal: true,
	})
	if !ok {
		return nil, i, false
	}
	st.lastStreetEnd = c.span.End
	if next > 0 && ctx.Tokens[next-1].End > st.lastStreetEnd {
		st.lastStreetEnd = ctx.Tokens[next-1].End
	}
	return []addrCandidate{c}, next - 1, true
}

// addrScanRegion reads an administrative unit after a region marker.
func addrScanRegion(ctx *Context, i, after int, caseBlind bool) ([]addrCandidate, int, bool) {
	c, next, ok := addrNamedCandidate(ctx, i, after, caseBlind, addrNamedSpec{
		typ: pd.TypeCity, hint: addrHintRegion, needsNeighbour: true,
	})
	if !ok {
		return nil, i, false
	}
	return []addrCandidate{c}, next - 1, true
}

// addrScanCity reads a settlement name after a city marker, then the comma
// chain that may follow it.
func addrScanCity(ctx *Context, i, after int, caseBlind bool, st *addrScanState) ([]addrCandidate, int, bool) {
	if addrIsYearMarker(ctx, i) {
		return nil, i, false // "в 2020 г. Иванов" is a year, not a city
	}
	s, e, next, ok := addrScanName(ctx, after, false, caseBlind)
	if !ok {
		return nil, i, false
	}
	cands := []addrCandidate{{
		span: pd.Span{Start: s, End: e, Type: pd.TypeCity, Src: "address", Hint: "city"},
		name: ctx.Lower[s:e],
	}}
	ni := next - 1
	if st2, hs, n2, ok := addrCommaChain(ctx, next, caseBlind); ok {
		cands = append(cands, st2, hs)
		st.lastStreetEnd, st.lastHouseEnd = st2.span.End, hs.span.End
		ni = n2 - 1
	}
	return cands, ni, true
}

// addrScanHouse reads a house number after a house marker.
func addrScanHouse(ctx *Context, i, after int, st *addrScanState) ([]addrCandidate, int, bool) {
	s, e, next, ok := addrScanValue(ctx, after, false)
	if !ok {
		return nil, i, false
	}
	st.lastHouseEnd = e
	return []addrCandidate{{
		span: pd.Span{Start: s, End: e, Type: pd.TypeHouse, Src: "address", Hint: "house"},
	}}, next - 1, true
}

// addrScanCorpus reads a corpus number, but only when a house stands nearby.
func addrScanCorpus(ctx *Context, i, after int, st *addrScanState) ([]addrCandidate, int, bool) {
	if st.lastHouseEnd < 0 || ctx.Tokens[i].Start-st.lastHouseEnd > addrCorpusGap {
		return nil, i, false
	}
	s, e, next, ok := addrScanValue(ctx, after, true)
	if !ok {
		return nil, i, false
	}
	st.lastHouseEnd = e
	return []addrCandidate{{
		span: pd.Span{Start: s, End: e, Type: pd.TypeHouse, Src: "address", Hint: "corpus"},
	}}, next - 1, true
}

// addrScanApartment reads a flat number after an apartment marker.
func addrScanApartment(ctx *Context, i, after int) ([]addrCandidate, int, bool) {
	s, e, next, ok := addrScanValue(ctx, after, false)
	if !ok {
		return nil, i, false
	}
	return []addrCandidate{{
		span: pd.Span{Start: s, End: e, Type: pd.TypeApartment, Src: "address", Hint: "apartment"},
	}}, next - 1, true
}

func init() { Register(addressDetector{}) }
