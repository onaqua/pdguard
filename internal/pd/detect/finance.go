package detect

import (
	"strings"

	"pdguard/internal/pd"
	"pdguard/internal/pd/text"
)

// financeDetector finds card numbers, INNs, bank accounts, CVVs and PINs.
// It holds no state, as the Detector contract requires: every per-request value
// lives in a finScan created on the stack.
type financeDetector struct{}

// Name identifies the detector in logs and in Span.Src.
func (financeDetector) Name() string { return "finance" }

// Types lists the PD categories this detector can emit.
func (financeDetector) Types() []pd.Type { return financeTypes }

// Detect walks the payload once, collecting digit chains and testing each
// against every enabled rule. Offsets come straight from ctx.Lower, which has
// the same byte length as ctx.Text, so no remapping is needed.
func (financeDetector) Detect(ctx *Context) []pd.Span {
	s := finScan{lower: ctx.Lower}
	s.card = ctx.Enabled(pd.TypeCardNumber)
	s.inn = ctx.Enabled(pd.TypeINN)
	s.account = ctx.Enabled(pd.TypeBankAccount)
	s.cvv = ctx.Enabled(pd.TypeCVV)
	s.pin = ctx.Enabled(pd.TypePIN)
	if !s.card && !s.inn && !s.account && !s.cvv && !s.pin {
		return nil
	}
	if s.account {
		s.scanIBAN()
	}
	lower := s.lower
	for i := 0; i < len(lower); {
		if !finIsDigit(lower[i]) {
			i++
			continue
		}
		cs, ce := i, finChainEnd(lower, i)
		i = ce
		if !text.IsBoundary(lower, cs) || !text.IsBoundary(lower, ce) {
			continue
		}
		if s.insideIBAN(cs, ce) {
			continue
		}
		s.chain(cs, ce)
	}
	return s.out
}

func init() { Register(financeDetector{}) }

// financeTypes is returned by Types; a package-level slice avoids allocating on
// every call from the config and metrics layers.
var financeTypes = []pd.Type{
	pd.TypeCardNumber, pd.TypeINN, pd.TypeBankAccount, pd.TypeCVV, pd.TypePIN,
}

// finAnchor is a cue word searched to the left of a candidate.
type finAnchor struct {
	s     string
	exact bool
}

// finGroup is one uninterrupted run of digits inside a chain. Its length equals
// its digit count, which is what every length rule below is written against.
type finGroup struct{ start, end int }

// finCue memoises one whole-payload pre-filter answer.
type finCue struct{ known, has bool }

// finScan is the working state of a single Detect call.
type finScan struct {
	lower string

	// Per-type switches from ctx.Enabled.
	card, inn, account, cvv, pin bool
	// Whether the payload contains any cue word for the type at all, resolved
	// lazily.
	cardCue, innCue, accountCue, cvvCue, pinCue finCue

	groups []finGroup // groups of the chain being examined
	used   [][2]int   // byte ranges already claimed inside that chain

	ibans  [][2]int // IBAN spans, in position order
	ibanAt int      // cursor into ibans while walking chains

	out []pd.Span
}

const (
	// finConfLuhn is for a card whose checksum verifies. A random digit run
	// passes Luhn about one time in ten, so the checksum on its own proves
	// nothing: it is the COMBINATION of card grouping and a valid checksum that
	// makes a 13-19 digit run a card with near certainty, and only that
	// combination needs no cue word. A Luhn-valid run with odd grouping earns
	// the same score, but only when the text also names a card — see
	// cardWindow.
	finConfLuhn = 0.99
	// finConfCardAnchor is for a card shape that fails Luhn but is introduced
	// by an explicit cue word. A mistyped card number is still personal data.
	finConfCardAnchor = 0.85

	finConfINNChecked = 0.98 // control digits verify and a cue word is present
	finConfINN12      = 0.90 // control digits verify, 12 digits, no cue word
	finConfINNAnchor  = 0.85 // cue word present, control digits do not verify

	finConfIBAN    = 0.97 // mod-97 checksum verifies
	finConfAccount = 0.95 // 20 digits (or an IBAN shape) next to a cue word

	// finConfSecret covers CVV and PIN. Both are unremarkable short digit runs;
	// all of the evidence comes from the cue word, so both score the same.
	finConfSecret = 0.93
)

// finAnchorWindow is how far left of a candidate a cue word is accepted, in
// bytes. Roughly one clause — long enough for "номер платёжной карты клиента:",
// short enough that a previous sentence cannot vouch for a number. Cyrillic
// costs two bytes per letter, which is why the figure looks generous.
const finAnchorWindow = 72

// finShortAnchorWindow is the tighter window used for CVV and PIN. Three or
// four digits are the most common shape in any text, so their cue word has to
// be practically adjacent — just enough for "код безопасности карты:", which is
// 44 bytes of Cyrillic on its own.
const finShortAnchorWindow = 56

// finCardMinDigits / finCardMaxDigits bound a payment card number (ISO/IEC
// 7812: 13 digits for the shortest legacy Visa, 19 for the longest Maestro).
const (
	finCardMinDigits = 13
	finCardMaxDigits = 19
)

// finAccountDigits is the length of a Russian bank account number. It is fixed
// by the Bank of Russia chart of accounts, so there is no range to allow for.
const finAccountDigits = 20

// finINNMaxDigits is the longest INN, and therefore the size of the stack
// buffer the control digits are checked in.
const finINNMaxDigits = 12

// finSpanCap is the capacity the result slice is born with: financial
// identifiers arrive in small clusters (a payment order, a card block), so one
// allocation of eight covers a realistic payload where growing from nil takes
// four.
const finSpanCap = 8

// INN control-digit weights, straight from the Federal Tax Service algorithm.
// A 10-digit (organisation) INN carries one control digit, a 12-digit
// (individual) INN carries two, computed over the 10- and 11-digit prefixes.
var (
	finINNWeights10 = [9]int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	finINNWeights11 = [10]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	finINNWeights12 = [11]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
)

var (
	finCardAnchors = []finAnchor{
		{s: "карта", exact: true}, {s: "карты", exact: true},
		{s: "карте", exact: true}, {s: "карту", exact: true},
		{s: "картой", exact: true}, {s: "карт", exact: true},
		{s: "карточка", exact: true}, {s: "карточки", exact: true},
		{s: "карточке", exact: true}, {s: "карточку", exact: true},
		{s: "card"}, // card, cardholder, card number
		{s: "pan", exact: true}, {s: "visa", exact: true},
		{s: "mastercard", exact: true}, {s: "maestro", exact: true},
		{s: "мир", exact: true}, {s: "виза", exact: true},
	}

	// The legal spelling of the cue is "идентификационный номер
	// налогоплательщика", but the phrase is 82 bytes long — wider than the
	// anchor window on its own. Its last word carries all of the meaning and
	// fits, so that is what is listed.
	//
	// "ИНН" itself does not decline, so the oblique cases of the phrase around
	// it are what have to be spelled out: "по ИНН", "об ИНН" need nothing, but
	// "налогового номера" and "ИНН'а" style spellings do.
	finINNAnchors = []finAnchor{
		{s: "инн", exact: true},
		{s: "налогоплательщик"},
		{s: "налоговый номер"}, {s: "налогового номера"},
		{s: "налоговому номеру"}, {s: "налоговым номером"},
		{s: "tax id"}, {s: "taxid", exact: true},
	}

	finAccountAnchors = []finAnchor{
		{s: "счет", exact: true}, {s: "счёт", exact: true},
		{s: "счета", exact: true}, {s: "счёта", exact: true},
		{s: "счету", exact: true}, {s: "счёту", exact: true},
		{s: "счете", exact: true}, {s: "счёте", exact: true},
		{s: "счетом", exact: true}, {s: "счётом", exact: true},
		{s: "р/с", exact: true}, {s: "к/с", exact: true},
		{s: "расчетн"}, {s: "расчётн"}, {s: "лицевой"}, {s: "лицевого"},
		{s: "account"}, {s: "iban", exact: true},
	}

	// CVV cue words, including the oblique cases of every Russian phrasing:
	// the digits carry no evidence at all, so the cue is the whole of the
	// proof and a case form we fail to list is a miss.
	finCVVAnchors = []finAnchor{
		{s: "cvv", exact: true}, {s: "cvc", exact: true},
		{s: "cvv2", exact: true}, {s: "cvc2", exact: true},
		{s: "cid", exact: true},
		{s: "код проверки"}, {s: "проверочный код"}, {s: "проверочного кода"},
		{s: "проверочный"}, {s: "защитный код"}, {s: "защитного кода"},
		{s: "код безопасности"}, {s: "кода безопасности"},
		{s: "коду безопасности"}, {s: "кодом безопасности"},
		{s: "три цифры на обороте"}, {s: "трёх цифр на обороте"},
		{s: "трех цифр на обороте"},
		{s: "трехзначный код"}, {s: "трёхзначный код"},
		{s: "трехзначного кода"}, {s: "трёхзначного кода"},
		{s: "код на обороте"}, {s: "кода на обороте"},
		{s: "security code"}, {s: "card verification"},
	}

	finPINAnchors = []finAnchor{
		{s: "пин", exact: true}, {s: "pin", exact: true},
		{s: "пинкод"}, {s: "pincode"}, {s: "pin code"}, {s: "pin-code"},
		{s: "код карты"}, {s: "кода карты"},
		{s: "секретный код"}, {s: "секретного кода"},
	}
)

// Probe lists for the whole-payload pre-filter.
//
// The pre-filter answers one question — can a cue word occur in this payload at
// all — and the per-candidate search answers the precise one. It therefore does
// not need the cue words themselves, only a substring that every cue of the
// group contains: "карт" stands for ten declensions of "карта" and both of
// "карточка", "сч" stands for every case of "счёт" and for "расчётный".
// Sixty-one whole-payload searches become twenty-eight, and the lists are kept
// honest by TestFinanceProbesCoverAnchors, which fails if an anchor is added
// that no probe of its group matches.
var (
	finCardProbes    = []string{"карт", "card", "pan", "visa", "mastercard", "maestro", "мир", "виза"}
	finINNProbes     = []string{"инн", "налог", "tax"}
	finAccountProbes = []string{"сч", "лицев", "account", "iban", "р/с", "к/с"}
	finCVVProbes     = []string{
		"cvv", "cvc", "cid", "провер", "защитн", "безопасн",
		"цифр", "оборот", "значн", "security", "verification",
	}
	finPINProbes = []string{"пин", "pin", "код карт", "кода карт", "секретн"}
)

// finChainEnd returns the end of the digit chain starting at i.
func finChainEnd(s string, i int) int {
	j := i
	for {
		for j < len(s) && finIsDigit(s[j]) {
			j++
		}
		if j+1 < len(s) && finIsChainSep(s[j]) && finIsDigit(s[j+1]) {
			j++
			continue
		}
		return j
	}
}

func finIsChainSep(c byte) bool { return c == ' ' || c == '-' || c == '.' }

// chain splits the chain into groups and runs the rules.
func (s *finScan) chain(cs, ce int) {
	s.groups = s.groups[:0]
	g := cs
	for i := cs; i < ce; i++ {
		if !finIsDigit(s.lower[i]) {
			s.groups = append(s.groups, finGroup{g, i})
			g = i + 1
		}
	}
	s.groups = append(s.groups, finGroup{g, ce})
	s.used = s.used[:0]
	if s.card {
		s.scanCard()
	}
	if s.account {
		s.scanAccount()
	}
	if s.inn {
		s.scanINN()
	}
	if s.cvv || s.pin {
		s.scanSecrets()
	}
}

// cue lazily resolves the whole-payload pre-filter.
func (s *finScan) cue(c *finCue, probes []string) bool {
	if !c.known {
		c.has, c.known = finContainsAny(s.lower, probes), true
	}
	return c.has
}

// scanCard walks the groups left to right, taking card windows.
func (s *finScan) scanCard() {
	for i := 0; i < len(s.groups); {
		j, conf, ok := s.cardWindow(i)
		if !ok {
			i++
			continue
		}
		s.emit(s.groups[i].start, s.groups[j].end,
			pd.TypeCardNumber, conf, s.scheme(i, j))
		i = j + 1
	}
}

// cardWindow runs the three passes in order.
func (s *finScan) cardWindow(i int) (int, float64, bool) {
	lo, hi, ok := s.cardBounds(i)
	if !ok {
		return 0, 0, false
	}
	// Pass 1: arithmetic + card grouping (no cue word needed).
	for j := hi; j >= lo; j-- {
		if s.allSame(i, j) || s.usedOverlap(s.groups[i].start, s.groups[j].end) {
			continue
		}
		if s.grouped(i, j) && s.luhn(i, j) {
			return j, finConfLuhn, true
		}
	}
	// Gates for passes 2 and 3: everything below needs a cue word.
	if !finIssuerDigit(s.lower[s.groups[i].start]) ||
		!s.cue(&s.cardCue, finCardProbes) ||
		!finCueLeft(s.lower, s.groups[i].start, finCardAnchors, finAnchorWindow) {
		return 0, 0, false
	}
	// Pass 2: Luhn at any grouping (cue already present).
	for j := hi; j >= lo; j-- {
		if s.allSame(i, j) || s.usedOverlap(s.groups[i].start, s.groups[j].end) {
			continue
		}
		if s.luhn(i, j) {
			return j, finConfLuhn, true
		}
	}
	// Pass 3: card grouping without Luhn.
	for j := hi; j >= lo; j-- {
		if s.allSame(i, j) || s.usedOverlap(s.groups[i].start, s.groups[j].end) {
			continue
		}
		if s.grouped(i, j) {
			return j, finConfCardAnchor, true
		}
	}
	return 0, 0, false
}

// cardBounds finds the contiguous range of valid card windows from group i.
func (s *finScan) cardBounds(i int) (lo, hi int, ok bool) {
	lo, hi = -1, -1
	n := 0
	for j := i; j < len(s.groups); j++ {
		n += s.groups[j].end - s.groups[j].start
		if n > finCardMaxDigits {
			break
		}
		if n >= finCardMinDigits {
			if lo < 0 {
				lo = j
			}
			hi = j
		}
	}
	return lo, hi, lo >= 0
}

// grouped reports whether groups i..j form a card shape.
func (s *finScan) grouped(i, j int) bool {
	if i == j {
		return true
	}
	if j-i == 2 {
		a, b, c := s.groups[i].end-s.groups[i].start,
			s.groups[i+1].end-s.groups[i+1].start,
			s.groups[j].end-s.groups[j].start
		if a == 4 && b == 6 && c == 5 {
			return true
		}
	}
	for k := i; k < j; k++ {
		if s.groups[k].end-s.groups[k].start != 4 {
			return false
		}
	}
	n := s.groups[j].end - s.groups[j].start
	return n >= 1 && n <= 4
}

// scanAccount finds 20-digit runs next to a cue word.
func (s *finScan) scanAccount() {
	for i := 0; i < len(s.groups); {
		hit, n := -1, 0
		for j := i; j < len(s.groups); j++ {
			n += s.groups[j].end - s.groups[j].start
			if n > finAccountDigits {
				break
			}
			if n != finAccountDigits {
				continue
			}
			if s.usedOverlap(s.groups[i].start, s.groups[j].end) {
				continue
			}
			if s.cue(&s.accountCue, finAccountProbes) &&
				finCueLeft(s.lower, s.groups[i].start, finAccountAnchors, finAnchorWindow) {
				hit = j
				break
			}
		}
		if hit < 0 {
			i++
			continue
		}
		s.emit(s.groups[i].start, s.groups[hit].end, pd.TypeBankAccount, finConfAccount, "account")
		i = hit + 1
	}
}

// scanINN finds single-group INNs, then delegates to scanINNGrouped.
func (s *finScan) scanINN() {
	for k := 0; k < len(s.groups); k++ {
		g := s.groups[k]
		n := g.end - g.start
		if n != 10 && n != 12 {
			continue
		}
		if s.usedOverlap(g.start, g.end) {
			continue
		}
		d := s.lower[g.start:g.end]
		if finAllSame(d) {
			continue
		}
		cued := s.innCued(g.start)
		valid := finINNChecksum(d)
		var conf float64
		switch {
		case valid && cued:
			conf = finConfINNChecked
		case valid && n == 12:
			conf = finConfINN12
		case cued:
			conf = finConfINNAnchor
		default:
			continue
		}
		hint := "organization"
		if n == 12 {
			hint = "personal"
		}
		s.emit(g.start, g.end, pd.TypeINN, conf, hint)
	}
	s.scanINNGrouped()
}

// scanINNGrouped finds INNs split across groups, next to a cue word.
func (s *finScan) scanINNGrouped() {
	if len(s.groups) < 2 || !s.cue(&s.innCue, finINNProbes) {
		return
	}
	for i := 0; i < len(s.groups); {
		hit, conf, n := -1, 0.0, 0
		for j := i; j < len(s.groups); j++ {
			n += s.groups[j].end - s.groups[j].start
			if n > finINNMaxDigits {
				break
			}
			if j == i || (n != 10 && n != finINNMaxDigits) {
				continue
			}
			if s.allSame(i, j) || s.usedOverlap(s.groups[i].start, s.groups[j].end) {
				continue
			}
			if !finCueLeft(s.lower, s.groups[i].start, finINNAnchors, finAnchorWindow) {
				continue
			}
			hit, conf = j, finConfINNAnchor
			if s.innChecksum(i, j) {
				conf = finConfINNChecked
			}
			break
		}
		if hit < 0 {
			i++
			continue
		}
		hint := "organization"
		if n == finINNMaxDigits {
			hint = "personal"
		}
		s.emit(s.groups[i].start, s.groups[hit].end, pd.TypeINN, conf, hint)
		i = hit + 1
	}
}

// innCued reports whether a cue word vouches for the INN at offset off.
func (s *finScan) innCued(off int) bool {
	return s.cue(&s.innCue, finINNProbes) &&
		finCueLeft(s.lower, off, finINNAnchors, finAnchorWindow)
}

// scanSecrets finds CVV and PIN codes next to their cue words.
func (s *finScan) scanSecrets() {
	for k := 0; k < len(s.groups); k++ {
		g := s.groups[k]
		n := g.end - g.start
		if n < 3 || n > 6 {
			continue
		}
		if s.usedOverlap(g.start, g.end) {
			continue
		}
		if s.cvv && n <= 4 && s.cue(&s.cvvCue, finCVVProbes) &&
			finCueLeft(s.lower, g.start, finCVVAnchors, finShortAnchorWindow) {
			s.emit(g.start, g.end, pd.TypeCVV, finConfSecret, "cvv")
			continue
		}
		if s.pin && n >= 4 && s.cue(&s.pinCue, finPINProbes) &&
			finCueLeft(s.lower, g.start, finPINAnchors, finShortAnchorWindow) {
			s.emit(g.start, g.end, pd.TypePIN, finConfSecret, "pin")
		}
	}
}

// scanIBAN finds IBAN candidates by direct four-character comparison.
func (s *finScan) scanIBAN() {
	lower := s.lower
	for i := 0; i+3 < len(lower); i++ {
		if !finIsASCIILetter(lower[i]) || !finIsASCIILetter(lower[i+1]) ||
			!finIsDigit(lower[i+2]) || !finIsDigit(lower[i+3]) {
			continue
		}
		if !text.IsBoundary(lower, i) {
			continue
		}
		end := finIBANEnd(lower, i+4)
		s.takeIBAN(i, end)
		i = end - 1
	}
}

// takeIBAN validates and records one IBAN candidate.
func (s *finScan) takeIBAN(start, end int) {
	lower := s.lower
	if !text.IsBoundary(lower, end) {
		return
	}
	if n := finAlnumLen(lower[start:end]); n < 15 || n > 34 {
		return
	}
	conf := 0.0
	switch {
	case finIBANChecksum(lower[start:end]):
		conf = finConfIBAN
	case s.cue(&s.accountCue, finAccountProbes) &&
		finCueLeft(lower, start, finAccountAnchors, finAnchorWindow):
		conf = finConfAccount
	default:
		return
	}
	s.append(pd.Span{
		Start: start, End: end,
		Type: pd.TypeBankAccount, Conf: conf, Src: "finance", Hint: "iban",
	})
	s.ibans = append(s.ibans, [2]int{start, end})
}

// finIBANEnd returns the end of the alphanumeric IBAN run starting at i.
func finIBANEnd(s string, i int) int {
	j := i
	for j < len(s) && finIsAlnum(s[j]) {
		j++
	}
	for j+1 < len(s) && s[j] == ' ' && finIsAlnum(s[j+1]) {
		k := j + 1
		for k < len(s) && finIsAlnum(s[k]) {
			k++
		}
		if k-(j+1) > 4 {
			break
		}
		j = k
	}
	return j
}

// insideIBAN reports whether the chain [cs,ce) lies inside a recorded IBAN.
func (s *finScan) insideIBAN(cs, ce int) bool {
	for s.ibanAt < len(s.ibans) && s.ibans[s.ibanAt][1] <= cs {
		s.ibanAt++
	}
	return s.ibanAt < len(s.ibans) && s.ibans[s.ibanAt][0] < ce
}

// append adds a span to the result, allocating the slice on first use.
func (s *finScan) append(sp pd.Span) {
	if s.out == nil {
		s.out = make([]pd.Span, 0, finSpanCap)
	}
	s.out = append(s.out, sp)
}

// emit appends a span and claims its bytes in the current chain.
func (s *finScan) emit(start, end int, t pd.Type, conf float64, hint string) {
	s.append(pd.Span{
		Start: start, End: end, Type: t, Conf: conf, Src: "finance", Hint: hint,
	})
	s.used = append(s.used, [2]int{start, end})
}

// usedOverlap reports whether [start,end) overlaps any claimed range.
func (s *finScan) usedOverlap(start, end int) bool {
	for _, u := range s.used {
		if start < u[1] && u[0] < end {
			return true
		}
	}
	return false
}

// scheme returns the payment scheme hint for groups i..j.
func (s *finScan) scheme(i, j int) string {
	var head [4]byte
	n := 0
	for k := i; k <= j && n < len(head); k++ {
		g := s.groups[k]
		for p := g.start; p < g.end && n < len(head); p++ {
			head[n] = s.lower[p]
			n++
		}
	}
	return finCardScheme(head[:n])
}

// finCardScheme maps the leading digits of a card to its payment scheme.
func finCardScheme(head []byte) string {
	if len(head) == 0 {
		return "card"
	}
	switch head[0] {
	case '4':
		return "visa"
	case '5':
		return "mastercard"
	case '2':
		// 2200-2204 is the МИР range; the rest of the 2-series was handed to
		// Mastercard when it outgrew the 5-series.
		if len(head) >= 4 && head[1] == '2' && head[2] == '0' && head[3] <= '4' {
			return "mir"
		}
		return "mastercard"
	case '3':
		return "amex"
	case '6':
		return "discover"
	}
	return "card"
}

// allSame reports whether every digit in groups i..j is identical.
func (s *finScan) allSame(i, j int) bool {
	first := s.lower[s.groups[i].start]
	for k := i; k <= j; k++ {
		g := s.groups[k]
		for p := g.start; p < g.end; p++ {
			if s.lower[p] != first {
				return false
			}
		}
	}
	return true
}

// finAllSame reports whether every byte of s is the same digit.
func finAllSame(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return len(s) > 0
}

// luhn checks the Luhn checksum of groups i..j.
func (s *finScan) luhn(i, j int) bool {
	sum, alt := 0, false
	for k := j; k >= i; k-- {
		g := s.groups[k]
		sum, alt = finLuhnFold(s.lower[g.start:g.end], sum, alt)
	}
	return sum%10 == 0
}

// finLuhnFold folds one digit group into the running Luhn sum.
func finLuhnFold(d string, sum int, alt bool) (int, bool) {
	for i := len(d) - 1; i >= 0; i-- {
		v := int(d[i] - '0')
		if alt {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		alt = !alt
	}
	return sum, alt
}

// finLuhn reports whether d passes the Luhn checksum.
func finLuhn(d string) bool {
	if len(d) == 0 {
		return false
	}
	sum, _ := finLuhnFold(d, 0, false)
	return sum%10 == 0
}

// finINNChecksum reports whether d has valid INN control digits.
func finINNChecksum(d string) bool {
	if len(d) > finINNMaxDigits {
		return false
	}
	var buf [finINNMaxDigits]byte
	copy(buf[:], d)
	return finINNChecksumBytes(buf[:len(d)])
}

// finINNChecksumBytes reports whether d has valid INN control digits.
func finINNChecksumBytes(d []byte) bool {
	switch len(d) {
	case 10:
		return finINNControl(d, finINNWeights10[:]) == int(d[9]-'0')
	case 12:
		return finINNControl(d, finINNWeights11[:]) == int(d[10]-'0') &&
			finINNControl(d, finINNWeights12[:]) == int(d[11]-'0')
	}
	return false
}

// finINNControl computes the INN control digit over d with weights w.
func finINNControl(d []byte, w []int) int {
	sum := 0
	for i, k := range w {
		sum += int(d[i]-'0') * k
	}
	return sum % 11 % 10
}

// innChecksum checks the INN control digits of groups i..j.
func (s *finScan) innChecksum(i, j int) bool {
	var buf [finINNMaxDigits]byte
	n := 0
	for k := i; k <= j && n < len(buf); k++ {
		g := s.groups[k]
		for p := g.start; p < g.end && n < len(buf); p++ {
			buf[n] = s.lower[p]
			n++
		}
	}
	return finINNChecksumBytes(buf[:n])
}

// finIBANChecksum reports whether s passes the mod-97 IBAN checksum.
func finIBANChecksum(s string) bool {
	if finAlnumLen(s) < 5 {
		return false
	}
	rem, skip := 0, 4
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' {
			continue
		}
		if skip > 0 {
			skip--
			continue
		}
		if !finIBANFold(&rem, c) {
			return false
		}
	}
	if skip > 0 {
		return false // fewer than five characters: not an IBAN at all
	}
	for i, left := 0, 4; i < len(s) && left > 0; i++ {
		c := s[i]
		if c == ' ' {
			continue
		}
		left--
		if !finIBANFold(&rem, c) {
			return false
		}
	}
	return rem == 1
}

// finIBANFold folds one character into the running mod-97 remainder.
func finIBANFold(rem *int, c byte) bool {
	switch {
	case finIsDigit(c):
		*rem = *rem*10 + int(c-'0')
	case c >= 'a' && c <= 'z':
		*rem = *rem*100 + int(c-'a') + 10
	default:
		return false
	}
	*rem %= 97
	return true
}

// finAlnumLen counts the non-space characters of s.
func finAlnumLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			n++
		}
	}
	return n
}

// finContainsAny reports whether s contains any of the probes.
func finContainsAny(s string, probes []string) bool {
	for _, p := range probes {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// finCueLeft searches for a cue word to the left of offset before.
func finCueLeft(s string, before int, anchors []finAnchor, window int) bool {
	from := before - window
	if from < 0 {
		from = 0
	}
	win := s[from:before]
	for _, a := range anchors {
		for off := 0; off < len(win); {
			i := strings.Index(win[off:], a.s)
			if i < 0 {
				break
			}
			abs := from + off + i
			end := abs + len(a.s)
			if text.IsBoundary(s, abs) && (!a.exact || text.IsBoundary(s, end)) &&
				!finHasDigit(s[end:before]) {
				return true
			}
			off += i + 1
		}
	}
	return false
}

// finHasDigit reports whether s contains any ASCII digit.
func finHasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if finIsDigit(s[i]) {
			return true
		}
	}
	return false
}

// finIssuerDigit reports whether c is a payment-card major industry digit.
func finIssuerDigit(c byte) bool { return c >= '2' && c <= '6' }

// finIsDigit reports whether c is an ASCII digit.
func finIsDigit(c byte) bool { return c >= '0' && c <= '9' }

// finIsASCIILetter reports whether c is a lowercase ASCII letter.
func finIsASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' }

// finIsAlnum reports whether c is an ASCII digit or lowercase letter.
func finIsAlnum(c byte) bool { return finIsDigit(c) || finIsASCIILetter(c) }
