// This file covers the identity documents other than the RF internal passport:
// driver licence (mandatory in the spec) plus the bonus set — SNILS, foreign
// passport, birth certificate, military ID, residence permit and the OMS
// policy.
//
// Every shape here is a bare run of digits, which in free Russian text is also
// what an order number, an invoice line or a phone looks like. A false positive
// costs the span-based Levenshtein metric directly, so the rule throughout is:
// emit only when the surrounding text names the document, or when an arithmetic
// checksum proves the number is what it claims to be.
//
// Cost discipline. Detect runs on every request, and a regexp sweep over the
// payload is three orders of magnitude more expensive than a substring scan
// (measured on a 4 KiB payload: 27-88 µs per rule against 91 ns for one
// strings.Contains). So no rule is allowed to sweep the payload until two
// questions have been answered from a single cheap pass:
//
//  1. Could the payload contain the DIGITS this shape needs at all?
//     docProfile answers that arithmetically, in one byte loop for all rules.
//  2. Where could a match legally start? A rule that demands a cue word can
//     only match inside a short window after one, so only those windows are
//     swept — see docForEachWindow.
//
// Neither test can change a verdict: both are necessary conditions of the
// regexp matching AND of the evidence tests passing, so a candidate that the
// old full sweep would have accepted is still reached.
package detect

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"pdguard/internal/pd"
	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/text"
)

// Confidence levels used by this detector. They are coarse on purpose: the
// resolver only needs a stable ordering, not a calibrated probability.
const (
	docConfChecksum = 0.98 // arithmetic proof (SNILS control number)
	docConfAnchored = 0.92 // an explicit cue word stands next to the number
	docConfWeak     = 0.80 // the shape alone is distinctive enough
)

// docAnchorWindow is how far left of a candidate we look for a cue word, in
// bytes. Roughly one clause: far enough to survive "водительское удостоверение
// серия и номер 9902 123456", short enough that an unrelated earlier sentence
// cannot vouch for a number.
const docAnchorWindow = 80

// docShapeMaxBytes bounds the longest string any shape in this file can match
// (the birth certificate, "III-МЮ № 123456", is the longest at 21 bytes). It is
// the slack added to a scan window so that a match starting just inside the
// window is never cut in half by the window's own edge.
const docShapeMaxBytes = 32

// docMaxAnchors is the size of the fixed cursor array used by the window scan.
// Keeping it a compile-time constant is what makes that scan allocation-free;
// it must stay >= the longest cue list below.
const docMaxAnchors = 16

// docKeyBytes is how much of a cue word the window scan actually searches for.
//
// A short needle is matched by the vectorised path of strings.Index and costs
// about 90 ns over a 4 KiB payload; a 25-byte one falls back to Rabin-Karp and
// costs fifteen times as much, which on a nine-cue rule set was the single
// largest item in this detector's budget. Searching for a PREFIX is safe
// because it can only ever yield a superset of the real cue positions, and
// docAnchorLeft re-validates every candidate against the full cue anyway.
const docKeyBytes = 8

// docAnchor is a cue word searched to the left of a candidate number.
//
// Matching is prefix-based by default so Russian inflection is covered without
// listing every case form ("загранпаспорт" also matches "загранпаспорта").
// Short cues set exact, because a prefix match on two or three letters would
// fire inside unrelated words — "ву" in "вуз", "омс" in "омский".
type docAnchor struct {
	s     string
	exact bool
}

var (
	docAnchorsDriverLicense = []docAnchor{
		{s: "водительск"}, // водительское удостоверение / водительские права
		// The genitive construction "удостоверение водителя" inflects on the
		// FIRST word, which a single stem cannot cover, so its case forms are
		// listed. The bare noun "водителя" is deliberately not a cue: it stands
		// in "стаж водителя" and "вина водителя" just as often, and the licence
		// shape is any ten digits.
		{s: "удостоверение водителя"}, {s: "удостоверения водителя"},
		{s: "удостоверению водителя"}, {s: "удостоверением водителя"},
		{s: "удостоверении водителя"},
		{s: "вод. удостоверен"}, {s: "вод.удостоверен"},
		// The bare word "права" is NOT an anchor. In a banking or legal text it
		// means "rights" far more often than "driving licence" — "права
		// потребителя", "права требования", "права сторон" — and the licence
		// pattern matches any ten consecutive digits, which is also the shape of
		// every order number, case number and organisation INN. "водительск"
		// above already covers "водительские права", which is the only phrasing
		// that actually introduces the document.
		{s: "driver license"}, {s: "driver's license"},
		{s: "driving licence"}, {s: "driving license"},
		{s: "в/у", exact: true}, {s: "ву", exact: true},
	}
	docAnchorsSNILS = []docAnchor{
		{s: "снилс"},
		{s: "страхов"},  // страховой номер / страховое свидетельство
		{s: "пенсионн"}, // пенсионное свидетельство / пенсионное удостоверение
	}
	docAnchorsForeignPassport = []docAnchor{
		{s: "загран"}, // загранпаспорт / заграничный паспорт
		{s: "international passport"}, {s: "foreign passport"},
	}
	docAnchorsBirthCertificate = []docAnchor{
		{s: "о рожден"}, // свидетельство / св-во о рождении
	}
	// The cue names the DOCUMENT, not the adjective. A bare "военн" stem also
	// begins "военная ипотека", "военная пенсия" and "военнослужащий", and the
	// military-ID shape is "two letters and seven digits" — which any seven-digit
	// sum preceded by a two-letter preposition satisfies.
	docAnchorsMilitaryID = []docAnchor{
		{s: "военный билет"}, {s: "военного билета"},
		{s: "военному билету"}, {s: "военном билете"},
		{s: "военник"}, {s: "воен. билет"}, {s: "воен.билет"},
		{s: "военн. билет"},
		{s: "удостоверение личности военнослужащего"},
	}
	docAnchorsResidencePermit = []docAnchor{
		{s: "на жительств"},      // вид на жительство
		{s: "временное прожива"}, // разрешение на временное проживание
		{s: "временного прожива"},
		{s: "внж", exact: true}, {s: "рвп", exact: true},
	}
	docAnchorsOMS = []docAnchor{
		{s: "медицинский полис"}, {s: "медицинского полиса"},
		{s: "медицинским полисом"}, {s: "медицинского страхования"},
		{s: "полис обязательного медицинского страхования"},
		{s: "омс", exact: true},
	}
)

var (
	// 2+2 series and 6 digits of number, written solid or in groups.
	//
	// The optional label between the two halves is what the spec's own §4.2
	// wording for a passport asks of every document: a form prints "серия 77 12
	// № 345678" or "серия 7712 номер 345678" as readily as it prints the bare
	// groups, and the number sign may be typed Cyrillic (№), ASCII (#) or Latin
	// ("N", "No"). Without it the shape stopped at "77 12" and the licence went
	// to the passport detector, whose pattern is the same four-plus-six digits.
	// The alternatives are ordered longest first: Go's regexp is leftmost-FIRST,
	// so "номера" has to be offered before "номер" to be seen at all.
	reDocDriverLicense = regexp.MustCompile(
		`[0-9]{2}[ \t]{0,32}[0-9]{2}[ \t]{0,32}(?:(?:номера|номером|номер|№|#|no|n)\.?[ \t]{0,32})?[0-9]{6}`)
	// Pre-2011 licences carry a two-letter Cyrillic series.
	reDocDriverLicenseOld = regexp.MustCompile(`[а-яё]{2} ?(?:№ ?)?[0-9]{6}`)
	// The other pre-2011 layout puts the region code first: "77 АА 123456".
	reDocDriverLicenseRegion = regexp.MustCompile(`[0-9]{2} ?[а-яё]{2} ?(?:№ ?)?[0-9]{6}`)
	// 11 digits, optionally grouped 3-3-3-2.
	reDocSNILS = regexp.MustCompile(`[0-9]{3}[- ]?[0-9]{3}[- ]?[0-9]{3}[- ]?[0-9]{2}`)
	// 2 digits of series, 7 of number — nine digits in total, solid or split.
	// It takes the same optional label between the halves as the licence above,
	// and for the same reason: a form writes "загранпаспорт серия 75 номер
	// 1234567" as often as it writes the bare groups.
	reDocForeignPassport = regexp.MustCompile(
		`[0-9]{2}[ \t]{0,32}(?:(?:номера|номером|номер|№|#|no|n)\.?[ \t]{0,32})?[0-9]{7}`)
	// Roman series, Cyrillic sub-series, 6 digits: "II-МЮ 123456".
	reDocBirthCertificate = regexp.MustCompile(`[ivxlc]{1,5}-[а-яё]{2} ?(?:№ ?)?[0-9]{6}`)
	// Two Cyrillic letters and 7 digits: "АБ 1234567".
	reDocMilitaryID = regexp.MustCompile(`[а-яё]{2} ?(?:№ ?)?[0-9]{7}`)
	// Residence permits have no single legal format; a 7-9 digit group next to
	// the cue word is the only reliable shape.
	reDocPermitNumber = regexp.MustCompile(`[0-9]{7,9}`)
	// 16 digits, solid or in four groups — the same shape as a bank card, which
	// is exactly why the cue word is mandatory here.
	reDocOMS = regexp.MustCompile(`[0-9]{16}|[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4}`)
	// Policies issued before the single 16-digit number carry a Cyrillic series
	// and six or seven digits, exactly like a military ID — which is why this
	// shape may never fire without its own cue word.
	reDocOMSSeries = regexp.MustCompile(`[а-яё]{2} ?(?:№ ?)?[0-9]{6,7}`)
)

// docRule binds one textual shape to one PD type and to the evidence required
// before the match may be reported.
type docRule struct {
	typ  pd.Type
	re   *regexp.Regexp
	hint string
	// anchors are the cue words accepted for this rule.
	anchors []docAnchor
	// mustAnchor lets Detect skip the whole regexp scan when the payload does
	// not contain any cue word at all — the common case on long texts — and,
	// when one is present, confine the scan to the windows a match could start
	// in rather than sweeping the payload.
	mustAnchor bool
	// minRun is the shortest run of CONSECUTIVE digits any match must contain,
	// and minGroup the most digits one separated group must hold. Both are
	// read off the shape above and are necessary conditions of a match, so a
	// payload that fails them provably cannot produce one.
	minRun   int
	minGroup int
	// needRomanDash gates the birth-certificate shape on the single byte pattern
	// no other rule shares: a hyphen directly after a Roman numeral letter.
	needRomanDash bool
	// verify is an optional extra test, run after the cue word was found and
	// before score. It exists for the shapes whose regexp carries no structure
	// of its own: for those the cue word alone is not evidence, because a cue
	// anywhere in the clause would otherwise vouch for any digit run.
	// anchorEnd is where the accepted cue word ends, or -1 when there was none.
	verify func(ctx *Context, anchorEnd, start, end int) bool
	// score decides whether a candidate really is personal data and how sure we
	// are. Returning ok=false drops it silently: on this metric a miss is
	// cheaper than masking text that should have stayed byte-identical.
	score func(matched string, anchored bool) (float64, bool)

	// keys and maxLit are derived from anchors once at package load; see
	// docScanKeys. They are read-only afterwards, so the rule set stays safe
	// to share across concurrent requests.
	keys   []string
	maxLit int
}

// docHintSeriesNumber is the hint shared by every rule whose shape is a series
// followed by a number. It is a constant so the literal is not duplicated.
const docHintSeriesNumber = "series+number"

// docRules is the whole rule set, evaluated in order. Rules are pure data and
// the functions they hold are stateless, so the slice is safe to share across
// concurrent requests.
var docRules = []docRule{
	{
		typ: pd.TypeSNILS, re: reDocSNILS, hint: "snils",
		anchors: docAnchorsSNILS, score: docScoreSNILS,
		minRun: 2, minGroup: 11,
	},
	{
		typ: pd.TypeDriverLicense, re: reDocDriverLicense, hint: docHintSeriesNumber,
		anchors: docAnchorsDriverLicense, mustAnchor: true,
		// minGroup is 6, not 10: a label between the series and the number ends
		// the digit group, so "77 12 № 345678" offers no group longer than the
		// six digits of the number itself. The pre-filter must stay a NECESSARY
		// condition of a match or it would silently veto one.
		minRun: 6, minGroup: 6,
		verify: docNumberContextOK, score: docScoreAnchored,
	},
	{
		typ: pd.TypeDriverLicense, re: reDocDriverLicenseRegion, hint: "region-series",
		anchors: docAnchorsDriverLicense, mustAnchor: true,
		minRun: 6, minGroup: 6,
		verify: docBoth(docNumberContextOK, docCyrillicSeriesOK), score: docScoreAnchored,
	},
	{
		typ: pd.TypeDriverLicense, re: reDocDriverLicenseOld, hint: "old-series",
		anchors: docAnchorsDriverLicense, mustAnchor: true,
		minRun: 6, minGroup: 6,
		verify: docAll(docNumberContextOK, docCyrillicSeriesOK, docNoDigitsBefore),
		score:  docScoreAnchored,
	},
	{
		typ: pd.TypeForeignPassport, re: reDocForeignPassport, hint: docHintSeriesNumber,
		anchors: docAnchorsForeignPassport, mustAnchor: true,
		// minGroup drops to 7 for the same reason it does for the licence: a
		// label standing between the series and the number ends the digit group.
		minRun: 7, minGroup: 7,
		verify: docNumberContextOK, score: docScoreAnchored,
	},
	{
		typ: pd.TypeBirthCertificate, re: reDocBirthCertificate, hint: docHintSeriesNumber,
		anchors: docAnchorsBirthCertificate, score: docScoreBirthCertificate,
		minRun: 6, minGroup: 6, needRomanDash: true,
	},
	{
		typ: pd.TypeMilitaryID, re: reDocMilitaryID, hint: docHintSeriesNumber,
		anchors: docAnchorsMilitaryID, mustAnchor: true,
		minRun: 7, minGroup: 7,
		verify: docCyrillicSeriesOK, score: docScoreAnchored,
	},
	{
		typ: pd.TypeResidencePermit, re: reDocPermitNumber, hint: "number",
		anchors: docAnchorsResidencePermit, mustAnchor: true,
		minRun: 7, minGroup: 7,
		verify: docPermitNumberOK, score: docScoreAnchored,
	},
	{
		typ: pd.TypeOMS, re: reDocOMS, hint: "policy",
		anchors: docAnchorsOMS, mustAnchor: true,
		minRun: 4, minGroup: 16,
		score: docScoreAnchored,
	},
	{
		typ: pd.TypeOMS, re: reDocOMSSeries, hint: "old-series",
		anchors: docAnchorsOMS, mustAnchor: true,
		minRun: 6, minGroup: 6,
		verify: docAll(docNumberContextOK, docCyrillicSeriesOK, docNoDigitsBefore),
		score:  docScoreAnchored,
	},
}

func init() {
	// Derive the scan keys once, at start-up, rather than on every request —
	// the same discipline the city inflection index follows.
	for i := range docRules {
		docRules[i].keys, docRules[i].maxLit = docScanKeys(docRules[i].anchors)
		// Failing loudly here beats truncating the cursor array at scan time:
		// a silently dropped cue would look like a detector that simply stopped
		// finding one spelling of a document.
		if len(docRules[i].keys) > docMaxAnchors {
			panic("detect: docs rule " + string(docRules[i].typ) + " needs more than docMaxAnchors scan keys")
		}
	}
	Register(docsDetector{})
}

// docsDetector finds identity documents other than the RF internal passport.
// It holds no state, as the Detector contract requires.
type docsDetector struct{}

// Name identifies the detector in logs and in Span.Src.
func (docsDetector) Name() string { return "docs" }

// docsTypes is returned by Types; a package-level slice avoids allocating on
// every call from the config and metrics layers.
var docsTypes = []pd.Type{
	pd.TypeDriverLicense, pd.TypeSNILS, pd.TypeForeignPassport,
	pd.TypeBirthCertificate, pd.TypeMilitaryID, pd.TypeResidencePermit,
	pd.TypeOMS,
}

// Types lists the PD categories this detector can emit.
func (docsDetector) Types() []pd.Type { return docsTypes }

// Detect walks every rule over the lowercased payload. Offsets come straight
// from ctx.Lower, which has the same byte length as ctx.Text, so no remapping
// is needed.
func (docsDetector) Detect(ctx *Context) []pd.Span {
	var out []pd.Span
	lower := ctx.Lower
	if len(lower) == 0 {
		return nil
	}
	prof := docScanProfile(lower)

	for i := range docRules {
		r := &docRules[i]
		if !ctx.Enabled(r.typ) || !r.possible(prof) {
			continue
		}

		accept := func(start, end int) bool {
			return docAccept(ctx, r, lower, &out, start, end)
		}

		if r.mustAnchor {
			// A cue word is required, so a match can only begin in the window
			// docAnchorLeft looks back over. Sweeping those windows instead of
			// the payload is what makes a rule cost nothing on a long text that
			// mentions the document once.
			docForEachWindow(lower, r.keys, r.maxLit, func(from, to int) {
				docScanRange(lower, r.re, from, to, accept)
			})
			continue
		}
		docScanRange(lower, r.re, 0, len(lower), accept)
	}
	return out
}

// docAccept validates one candidate against the rule's evidence and appends the
// resulting span (or the two halves of a split value) to out.
func docAccept(ctx *Context, r *docRule, lower string, out *[]pd.Span, start, end int) bool {
	if !text.IsBoundary(lower, start) || !text.IsBoundary(lower, end) {
		return false
	}
	anchorEnd, anchored := docAnchorLeft(lower, start, r.anchors)
	if r.mustAnchor && !anchored {
		return false
	}
	if r.verify != nil && !r.verify(ctx, anchorEnd, start, end) {
		return false
	}
	conf, ok := r.score(lower[start:end], anchored)
	if !ok {
		return false
	}
	// A label word caught between the two halves of the value is not
	// personal data and must survive byte for byte: the quality metric
	// is a span-Levenshtein distance to a reference mask, and starring
	// out the letters of "номер" is the same kind of loss as missing a
	// digit. The value is therefore reported as the two digit groups it
	// really is — the same split the passport detector makes for
	// "серия 4509 номер 123456".
	if ls, le, split := docInnerLabel(lower, start, end); split {
		a, b, okA := text.TrimSpanEdges(lower, start, ls)
		c, d, okB := text.TrimSpanEdges(lower, le, end)
		if okA && okB {
			*out = append(*out,
				pd.Span{Start: a, End: b, Type: r.typ, Conf: conf, Src: "docs", Hint: r.hint},
				pd.Span{Start: c, End: d, Type: r.typ, Conf: conf, Src: "docs", Hint: r.hint})
			return true
		}
	}
	*out = append(*out, pd.Span{
		Start: start, End: end,
		Type: r.typ, Conf: conf, Src: "docs", Hint: r.hint,
	})
	return true
}

// docScanKeys reduces a cue list to the shortest set of prefixes that still
// finds every occurrence, and reports the longest cue in the list — the reach a
// window has to allow for past the prefix that opened it.
func docScanKeys(anchors []docAnchor) ([]string, int) {
	maxLit := 0
	raw := make([]string, 0, len(anchors))
	for _, a := range anchors {
		if len(a.s) > maxLit {
			maxLit = len(a.s)
		}
		raw = append(raw, docRunePrefix(a.s, docKeyBytes))
	}
	keys := make([]string, 0, len(raw))
	for i, k := range raw {
		if !docKeyCovered(raw, i, k) {
			keys = append(keys, k)
		}
	}
	return keys, maxLit
}

// docKeyCovered reports whether the key at i is already found by an earlier or
// shorter key, in which case it must not survive on its own.
func docKeyCovered(raw []string, i int, k string) bool {
	for j, other := range raw {
		if j == i {
			continue
		}
		// A shorter prefix already finds everything this one would; on a
		// tie the earlier entry wins, so exactly one survives.
		if len(other) < len(k) && strings.HasPrefix(k, other) {
			return true
		}
		if other == k && j < i {
			return true
		}
	}
	return false
}

// docRunePrefix truncates s to at most n bytes without splitting a rune.
func docRunePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// docProfile is what one byte pass over the payload can tell every rule about
// whether its shape is even possible here.
type docProfile struct {
	// maxRun is the longest run of consecutive ASCII digits.
	maxRun int
	// maxGroup is the most digits inside one group, where a group survives a
	// single space or hyphen standing between two digits — exactly the
	// separators the shapes in this file allow.
	maxGroup int
	// romanDash records a hyphen directly preceded by a Roman numeral letter,
	// the one cheap signature of a birth certificate series.
	romanDash bool
}

// docScanProfile builds the profile in a single pass. It is deliberately a
// byte loop over ASCII: every separator and digit a shape here can contain is
// one byte wide, and multi-byte Cyrillic simply falls into the default arm.
func docScanProfile(s string) docProfile {
	var p docProfile
	run, group := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			run, group = docProfileDigit(&p, run, group)
		case c == ' ' || c == '-':
			run, group = docProfileSep(s, i, &p, run, group)
		default:
			run, group = 0, 0
		}
	}
	return p
}

// docProfileDigit folds one digit into the running run and group, widening the
// profile maxima when they grow.
func docProfileDigit(p *docProfile, run, group int) (int, int) {
	run++
	group++
	if run > p.maxRun {
		p.maxRun = run
	}
	if group > p.maxGroup {
		p.maxGroup = group
	}
	return run, group
}

// docProfileSep handles a space or dash separator: it may mark a Roman-dash
// birth certificate and may let the digit group survive.
func docProfileSep(s string, i int, p *docProfile, run, group int) (int, int) {
	if c := s[i]; c == '-' && i > 0 && docIsRomanByte(s[i-1]) {
		p.romanDash = true
	}
	run = 0
	// The group survives only a separator that actually stands BETWEEN
	// two digits; anything else ends it.
	if !(i > 0 && docIsDigitByte(s[i-1]) && i+1 < len(s) && docIsDigitByte(s[i+1])) {
		group = 0
	}
	return run, group
}

func docIsDigitByte(c byte) bool { return c >= '0' && c <= '9' }

// docIsRomanByte reports the lowercase Roman numeral letters the birth
// certificate series is built from.
func docIsRomanByte(c byte) bool {
	switch c {
	case 'i', 'v', 'x', 'l', 'c':
		return true
	}
	return false
}

// possible reports whether the payload could contain a match for this rule.
func (r *docRule) possible(p docProfile) bool {
	if p.maxRun < r.minRun || p.maxGroup < r.minGroup {
		return false
	}
	return !r.needRomanDash || p.romanDash
}

// docScanRange reports every match of re that STARTS inside [from,to). A
// rejected candidate restarts the search one byte later instead of skipping
// past it: otherwise a bogus match (say, a 10-digit prefix of a 16-digit run)
// would hide a real document that starts inside it.
//
// The slice handed to the regexp reaches docShapeMaxBytes past to, so a match
// that starts just inside the range is never truncated by the range's own edge.
func docScanRange(s string, re *regexp.Regexp, from, to int, accept func(start, end int) bool) {
	if from < 0 {
		from = 0
	}
	if to > len(s) {
		to = len(s)
	}
	limit := to + docShapeMaxBytes
	if limit > len(s) {
		limit = len(s)
	}
	for pos := from; pos < to; {
		loc := re.FindStringIndex(s[pos:limit])
		if loc == nil {
			return
		}
		start, end := pos+loc[0], pos+loc[1]
		if start >= to {
			return
		}
		if accept(start, end) {
			pos = end
		} else {
			pos = start + 1
		}
	}
}

// docInnerLabels are the words a shape in this file may swallow while joining a
// series to a number. The set is closed on purpose: the two-letter Cyrillic
// SERIES of a military ID or of a pre-2011 licence also stands between digits
// ("77 АА 123456") and is part of the value, so anything not listed here is
// kept inside the span. Entries are lowercase, as ctx.Lower is.
var docInnerLabels = map[string]struct{}{
	"номер": {}, "номера": {}, "номером": {}, "n": {}, "no": {},
}

// docInnerLabel returns the byte range of a label word standing inside the
// match [start,end), and whether one was found. Only the FIRST letter run is
// considered: a shape here never carries two of them, and a leading run is a
// series rather than a label, which the closed vocabulary rejects anyway.
//
// The scan reads ctx.Lower directly and compares sub-slices against a map, so
// it allocates nothing — this detector's zero-allocation budget is a hard
// constraint.
func docInnerLabel(s string, start, end int) (int, int, bool) {
	for i := start; i < end; {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if !unicode.IsLetter(r) {
			i += sz
			continue
		}
		j := i + sz
		for j < end {
			r2, sz2 := utf8.DecodeRuneInString(s[j:])
			if !unicode.IsLetter(r2) {
				break
			}
			j += sz2
		}
		_, ok := docInnerLabels[s[i:j]]
		return i, j, ok
	}
	return 0, 0, false
}

// docForEachWindow invokes fn over the byte ranges in which a match for a rule
// with these cues may START. Windows are emitted in ascending order and never
// overlap: a high-water mark clips each one to the bytes not yet offered, so
// the total work stays linear in the payload even when the cue word repeats
// every few bytes.
//
// Clipping is safe because acceptance does not depend on WHICH window a
// candidate was found in — docAnchorLeft re-examines every cue near it — so a
// candidate dropped from a later window was already offered by an earlier one.
func docForEachWindow(s string, keys []string, maxLit int, fn func(from, to int)) {
	n := len(keys) // init() has already proved this fits
	var next [docMaxAnchors]int
	for i := 0; i < n; i++ {
		next[i] = strings.Index(s, keys[i])
	}
	high := 0
	for {
		best := docNextBest(next, n)
		if best < 0 {
			return
		}
		pos, lit := next[best], keys[best]
		from, to := docWindowBounds(pos, maxLit, len(s), high)
		if from < to {
			fn(from, to)
			high = to
		}
		if j := strings.Index(s[pos+1:], lit); j >= 0 {
			next[best] = pos + 1 + j
		} else {
			next[best] = -1
		}
	}
}

// docNextBest returns the index of the earliest next occurrence among the scan
// keys, or -1 when none remains.
func docNextBest(next [docMaxAnchors]int, n int) int {
	best := -1
	for i := 0; i < n; i++ {
		if next[i] >= 0 && (best < 0 || next[i] < next[best]) {
			best = i
		}
	}
	return best
}

// docWindowBounds clips the scan window for one key occurrence to the bytes not
// yet offered and to the payload length.
func docWindowBounds(pos, maxLit, sLen, high int) (int, int) {
	from, to := pos, pos+maxLit+docAnchorWindow+1
	if from < high {
		from = high
	}
	if to > sLen {
		to = sLen
	}
	return from, to
}

// docAnchorLeft returns where the NEAREST cue word ends within docAnchorWindow
// bytes to the left of before, or -1 when there is none. The window is sliced
// from the lowered text, but the boundary checks run against the full string so
// a cue cut in half by the window edge can never be accepted.
//
// The end offset is returned, not just a yes/no, because a rule whose shape
// carries no structure needs to inspect what stands BETWEEN the cue and the
// digits before believing them.
func docAnchorLeft(s string, before int, anchors []docAnchor) (int, bool) {
	from := before - docAnchorWindow
	if from < 0 {
		from = 0
	}
	win := s[from:before]
	best := -1
	for _, a := range anchors {
		best = docAnchorScan(s, win, from, a, best)
	}
	return best, best >= 0
}

// docAnchorScan finds every occurrence of one cue inside the window and keeps
// the nearest accepted end offset.
func docAnchorScan(s, win string, from int, a docAnchor, best int) int {
	for off := 0; off < len(win); {
		i := strings.Index(win[off:], a.s)
		if i < 0 {
			break
		}
		abs := from + off + i
		if text.IsBoundary(s, abs) && (!a.exact || text.IsBoundary(s, abs+len(a.s))) {
			if end := abs + len(a.s); end > best {
				best = end
			}
		}
		off += i + 1
	}
	return best
}

// docScoreAnchored is the score function for shapes that are meaningless
// without a cue word: Detect has already verified the anchor is there.
func docScoreAnchored(string, bool) (float64, bool) { return docConfAnchored, true }

// docScoreSNILS trusts the control number over the surrounding words: a correct
// checksum is a 1-in-101 coincidence, which is stronger evidence than any cue.
//
// The checksum runs on text.DigitsOnly, so every spelling of the same number —
// solid, hyphenated, space-grouped or mixed — is reduced to the same eleven
// digits and scores identically.
func docScoreSNILS(matched string, anchored bool) (float64, bool) {
	d := text.DigitsOnly(matched)
	if len(d) != 11 || docAllSameDigit(d) {
		return 0, false
	}
	if docSNILSChecksum(d) {
		// An unpunctuated 11-digit run starting with 7 or 8 is far more often a
		// Russian phone number than a SNILS that happens to validate. Without a
		// cue word, leave it to the phone detector rather than mislabel it.
		if !anchored && len(matched) == 11 && (d[0] == '7' || d[0] == '8') {
			return 0, false
		}
		return docConfChecksum, true
	}
	if anchored {
		// The text says "СНИЛС": mask it even though the checksum fails — a
		// typo in a real number is still personal data.
		return docConfAnchored, true
	}
	return 0, false
}

// docScoreBirthCertificate accepts the shape without a cue word, because a
// Roman numeral glued to a Cyrillic pair and six digits does not occur in
// ordinary prose. It still validates the Roman part so that stray Latin letters
// before a hyphen cannot pass.
func docScoreBirthCertificate(matched string, anchored bool) (float64, bool) {
	roman, _, ok := strings.Cut(matched, "-")
	if !ok {
		return 0, false
	}
	if v := docRomanValue(roman); v < 1 || v > 99 {
		return 0, false
	}
	if anchored {
		return docConfAnchored, true
	}
	return docConfWeak, true
}

// docSNILSChecksum validates the two control digits: the first nine digits are
// weighted 9..1, the sum is taken modulo 101, and 100 or 101 collapse to 00.
func docSNILSChecksum(d string) bool {
	if len(d) != 11 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (9 - i)
	}
	ctrl := sum % 101
	if ctrl >= 100 {
		ctrl = 0
	}
	return ctrl == int(d[9]-'0')*10+int(d[10]-'0')
}

// docAllSameDigit reports a run like "00000000000", which passes the SNILS
// checksum arithmetically but is always filler data, never a real number.
func docAllSameDigit(d string) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return len(d) > 0
}

// docRomanValue parses a lowercase Roman numeral, returning 0 when s is not
// one. Only the ASCII letters the regexp already allows are handled.
func docRomanValue(s string) int {
	total, prev := 0, 0
	for i := len(s) - 1; i >= 0; i-- {
		var v int
		switch s[i] {
		case 'i':
			v = 1
		case 'v':
			v = 5
		case 'x':
			v = 10
		case 'l':
			v = 50
		case 'c':
			v = 100
		default:
			return 0
		}
		if v < prev {
			total -= v
		} else {
			total += v
			prev = v
		}
	}
	return total
}

// docPrepositions are the two-letter Cyrillic words that a "series + digits"
// pattern happily reads as a document series. Go's RE2 has no look-behind, so
// the letters are part of the match and end up inside the span; rejecting them
// here is what keeps "перечислено по 1234567 рублей" byte-identical.
var docPrepositions = map[string]struct{}{
	"по": {}, "за": {}, "от": {}, "на": {}, "до": {}, "из": {}, "ко": {},
	"во": {}, "со": {}, "об": {}, "не": {}, "ни": {}, "но": {}, "то": {},
	"та": {}, "те": {}, "же": {}, "ли": {}, "бы": {}, "уж": {}, "да": {},
	"их": {}, "им": {}, "ей": {}, "её": {}, "ее": {}, "он": {}, "мы": {},
	"вы": {}, "ты": {}, "ох": {}, "ах": {}, "ну": {},
}

// docCyrillicSeriesOK validates the two-letter Cyrillic series of a military ID,
// an old OMS policy or a pre-2011 driving licence.
//
// Two tests, both cheap. The letters must not be an ordinary Russian word — a
// preposition is what "перечислено ПО 1234567 рублей" offers the pattern — and
// they must be written in capitals, which is how a document series is always
// printed and how an inline preposition never is. A payload typed without any
// capitals at all is exempt from the second test for the same reason
// addrCaseBlind exists: there the case carries no information either way.
//
// The letters are looked up wherever they stand inside the match, because the
// region layout of an old licence ("77 АА 123456") puts two digits in front of
// them.
func docCyrillicSeriesOK(ctx *Context, _, start, end int) bool {
	at, ok := docCyrillicPairAt(ctx.Lower, start, end)
	if !ok {
		return false
	}
	series, _ := docLeadingRunes(ctx.Lower, at, end, 2)
	if _, bad := docPrepositions[series]; bad {
		return false
	}
	if dict.IsStopWord(series) {
		return false
	}
	if ctx.Text == ctx.Lower {
		return true // no capitalisation anywhere: the test proves nothing
	}
	raw, _ := docLeadingRunes(ctx.Text, at, end, 2)
	return raw != "" && raw == strings.ToUpper(raw)
}

// docCyrillicPairAt returns the offset of the first pair of adjacent Cyrillic
// letters inside [start,end).
func docCyrillicPairAt(s string, start, end int) (int, bool) {
	for i := start; i < end; {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if unicode.Is(unicode.Cyrillic, r) {
			if _, ok := docLeadingRunes(s, i, end, 2); ok {
				return i, true
			}
			return 0, false
		}
		i += sz
	}
	return 0, false
}

// docLeadingRunes returns the first n runes of s[start:end] when they are all
// Cyrillic letters.
func docLeadingRunes(s string, start, end, n int) (string, bool) {
	i := start
	for k := 0; k < n; k++ {
		if i >= end {
			return "", false
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		if !unicode.Is(unicode.Cyrillic, r) {
			return "", false
		}
		i += sz
	}
	return s[start:i], true
}

// docNumberUnits follow a number that was an amount or a count all along.
var docNumberUnits = []string{"руб", "₽", "%", "шт", "коп", "тыс", "млн", "usd", "eur"}

// docNumberNoiseWords name the OTHER numbered things that stand next to an
// identity document in a real text.
var docNumberNoiseWords = map[string]struct{}{
	"дело": {}, "дела": {}, "делу": {}, "заказ": {}, "заказа": {},
	"договор": {}, "договора": {}, "счет": {}, "счёт": {}, "счета": {},
	"сумма": {}, "суммы": {}, "сумму": {}, "оплачено": {}, "оплата": {},
	"телефон": {}, "телефона": {}, "заявка": {}, "заявки": {},
	"квитанция": {}, "квитанции": {}, "чек": {}, "чека": {},
	"платеж": {}, "платёж": {}, "инн": {}, "кпп": {}, "бик": {},
	"накладная": {}, "накладной": {}, "приказ": {}, "приказа": {},
	"тикет": {}, "обращение": {}, "обращения": {}, "талон": {},
}

// docNumberContextOK is the evidence a cue word cannot supply on its own: the
// cue and the number must belong to the same clause, the number must not be
// introduced by a word naming a different kind of number, and it must not be
// followed by a unit of measurement.
//
// Without it one legitimate mention of a document licensed any digit run in the
// next eighty bytes: "Водительские права были утеряны, дело 5566778899 закрыто"
// masked the case number.
func docNumberContextOK(ctx *Context, anchorEnd, start, end int) bool {
	if anchorEnd < 0 || anchorEnd > start {
		return false
	}
	if strings.ContainsAny(ctx.Lower[anchorEnd:start], ".\n\r;!?") {
		return false
	}
	if _, noise := docNumberNoiseWords[docWordBefore(ctx, start)]; noise {
		return false
	}
	tail := strings.TrimLeft(ctx.Lower[end:], " \t")
	for _, u := range docNumberUnits {
		if strings.HasPrefix(tail, u) {
			return false
		}
	}
	return true
}

// docPermitNumberOK is the extra evidence a residence-permit number needs.
//
// reDocPermitNumber is seven to nine digits and nothing else — no series, no
// separator, no checksum — so the cue word carries the entire burden of proof,
// and a cue anywhere in the 80-byte window vouched for any number at all: "Вид
// на жительство оформлен, оплачено 1500000 рублей" masked the amount. Three
// tests narrow it to numbers that can plausibly be the permit: the cue and the
// number must be in the same clause, the number must not be introduced by a
// word naming something else, and it must not be followed by a unit.
func docPermitNumberOK(ctx *Context, anchorEnd, start, end int) bool {
	if anchorEnd < 0 || anchorEnd > start {
		return false
	}
	if strings.ContainsAny(ctx.Lower[anchorEnd:start], ".\n\r;!?") {
		return false
	}
	return docNumberContextOK(ctx, anchorEnd, start, end)
}

// docNoDigitsBefore rejects a Cyrillic-series match that is only the tail of a
// longer layout: in "77 АБ 123456" the region rule above already claims the
// whole string, and letting the short rule match "АБ 123456" as well would
// emit two overlapping spans for one document.
func docNoDigitsBefore(ctx *Context, _, start, _ int) bool {
	i := start
	if i > 0 && ctx.Lower[i-1] == ' ' {
		i--
	}
	return i == 0 || !docIsDigitByte(ctx.Lower[i-1])
}

// docWordBefore returns the lowercased word standing left of off, skipping the
// punctuation ("№", ":", "#") that may introduce a number.
func docWordBefore(ctx *Context, off int) string {
	for i := ppTokenFrom(ctx, off) - 1; i >= 0; i-- {
		t := ctx.Tokens[i]
		switch t.Kind {
		case text.KindSpace, text.KindPunct:
			continue
		case text.KindWord:
			return t.In(ctx.Lower)
		default:
			return ""
		}
	}
	return ""
}

// docBoth chains two verifiers; both must accept.
func docBoth(a, b func(*Context, int, int, int) bool) func(*Context, int, int, int) bool {
	return func(ctx *Context, anchorEnd, start, end int) bool {
		return a(ctx, anchorEnd, start, end) && b(ctx, anchorEnd, start, end)
	}
}

// docAll chains any number of verifiers; every one of them must accept. The
// slice is built once at package load, so the chain costs one loop per
// candidate and nothing per request.
func docAll(fs ...func(*Context, int, int, int) bool) func(*Context, int, int, int) bool {
	return func(ctx *Context, anchorEnd, start, end int) bool {
		for _, f := range fs {
			if !f(ctx, anchorEnd, start, end) {
				return false
			}
		}
		return true
	}
}
