// This file covers the two contact identifiers of the spec: e-mail addresses
// and telephone numbers.
//
// Both shapes are syntactically self-evident, which makes them the safest
// detections in the whole service — but both also have a well-known impersonal
// tail that must stay byte-identical, because the metric is a span-based edit
// distance and every false positive is a direct loss:
//
//   - the bank's own mailboxes (info@, support@, anything on a corporate
//     domain) are the bank speaking, not a client's contact;
//   - the contact-centre and the emergency services (8 800 …, 112, 900) are
//     published numbers, not personal data.
//
// Those two exclusion lists live right here, next to the patterns they guard,
// so that a reviewer can check them without hunting through the config.
//
// Neither shape is found with a regexp any more. Both are anchored on a byte
// that a regexp engine has to look for anyway — '@' for an address, a digit or
// a '+' for a number — and Go's regexp cannot use that anchor unless the whole
// pattern starts with one literal string. Measured on the 4 KiB sparse profile
// the five telephone patterns cost 115 µs per call between them; the scanner
// below does the same work by walking each candidate outwards from its anchor
// byte, which is linear, allocation-free and roughly ten times faster. The
// shapes recognised are documented at contactClassify, one case per rule, so
// the loss of the patterns' declarativeness is paid back in comments.
package detect

import (
	"strings"

	"pdguard/internal/pd"
	"pdguard/internal/pd/text"
)

// Confidence levels emitted by this detector. The e-mail shape is
// unmistakable; a number carrying the Russian country prefix is nearly as
// good; every other telephone shape is a bare run of digits with separators
// and gets the weak score.
const (
	contactConfEmail      = 0.98
	contactConfPhonePlus7 = 0.95 // +7 / 8 / 7 country prefix present
	contactConfPhoneOther = 0.80
)

// contactAnchorWindow is how far left of a candidate a cue word is accepted,
// in bytes. One short clause: enough for "контактный телефон для связи:
// 9161234567", short enough that an earlier sentence cannot vouch for a number.
const contactAnchorWindow = 48

// contactPhoneAnchors are cue words that let a shape too plain to stand on its
// own (ten digits in an unusual grouping, or written with dots) be reported.
// Stored as stems so Russian inflection is covered without listing every case
// form; matching is prefix-based and requires a word boundary on the left.
//
// The abbreviation "тел" is listed with each punctuation mark that can follow
// it rather than as a bare stem, because the stem also opens "телевизор",
// "телеканал" and "телега" — and a stem that vouches for ten bare digits has to
// be worth its word. Bare "номер" is deliberately absent for the same reason:
// "номер заказа 9161234567" is an order, and that phrase is far more common in
// a banking text than a telephone introduced by "номер" alone.
var contactPhoneAnchors = []string{
	"телефон", "тел.", "тел:", "тел ", "тел,", "телеграм",
	"моб", "сотов", "контактн",
	"звонит", "позвон", "перезвон", "дозвон",
	"номер телефона", "whatsapp", "ватсап", "вотсап", "viber", "вайбер",
	"phone", "mobile", "cell", "telegram",
}

var contactEmailLocalStop = map[string]bool{
	"info": true, "support": true, "help": true, "helpdesk": true,
	"noreply": true, "no-reply": true, "donotreply": true, "do-not-reply": true,
	"press": true, "hr": true, "pr": true, "ir": true, "office": true,
	"contact": true, "contacts": true, "feedback": true, "sales": true,
	"admin": true, "webmaster": true, "abuse": true, "security": true,
	"mailbox": true, "service": true, "reception": true,
}

var contactEmailDomainStop = []string{
	"alfabank.ru", "alfabank.com", "alfa-bank.ru", "alfabank.by", "alfabank.kz",
	"alfadirect.ru", "alfastrah.ru",
	"sberbank.ru", "vtb.ru", "gazprombank.ru", "tinkoff.ru", "raiffeisen.ru",
	"cbr.ru", "gosuslugi.ru", "nalog.ru", "nalog.gov.ru", "gov.ru",
}

var contactPhoneShortStop = map[string]bool{
	"112": true, "101": true, "102": true, "103": true, "104": true,
	"911": true, "900": true, "1000": true, "0890": true, "0900": true,
	"8800": true, "8900": true,
}

// contactPhoneFreePrefixes are the national prefixes of toll-free and service
// ranges. "8 800 …" is always the organisation speaking, never a client.
var contactPhoneFreePrefixes = []string{"800", "804"}

// contactPhoneMaxDigits caps the digits of a telephone run. A number tops out
// at fifteen digits (ITU E.164) including the country code; a longer
// uninterrupted run means the candidate is a card, an account, an IBAN or an
// invoice line, and must be left alone so the higher-priority detector can
// claim the whole of it.
const contactPhoneMaxDigits = 15

// contactRunStart marks the bytes that may open a telephone run. A table
// lookup keeps the outer scan to one load and one branch per byte, which is
// what makes a full pass over the payload cost less than a single regexp.
var contactRunStart [256]bool

func init() {
	for c := '0'; c <= '9'; c++ {
		contactRunStart[c] = true
	}
	contactRunStart['+'] = true
	contactRunStart['('] = true
}

// contactSpanCap is the capacity the result slice is born with. Contacts come
// in small groups (a signature block, a contact card), so one allocation of
// eight covers almost every real payload; growing from nil would take four.
const contactSpanCap = 8

func contactIsDigit(c byte) bool { return c >= '0' && c <= '9' }

func contactIsASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' }

func contactIsAlnumASCII(c byte) bool { return contactIsDigit(c) || contactIsASCIILetter(c) }

// contactIsLocalByte reports the characters admitted in an e-mail local part.
// The underscore is there because "ivan_petrov@mail.ru" is an ordinary address
// and, without it, the scan stopped at the underscore and the boundary check
// then threw the whole address away.
func contactIsLocalByte(c byte) bool {
	return contactIsAlnumASCII(c) || c == '.' || c == '_' || c == '+' || c == '-'
}

// contactIsPhoneSep reports the characters that may stand between two digit
// groups of a telephone number. A comma and a slash are deliberately absent:
// they are how two numbers are listed next to each other.
func contactIsPhoneSep(c byte) bool {
	return c == ' ' || c == '-' || c == '.' || c == '(' || c == ')'
}

// contactCyrillicLen returns 2 when s[i:] starts with a two-byte Cyrillic
// letter and 0 otherwise. Used for the .рф zone; decoding the rune and asking
// the unicode tables would cost more than the two comparisons, and the letters
// that matter all live in one contiguous block.
func contactCyrillicLen(s string, i int) int {
	if i+1 >= len(s) {
		return 0
	}
	switch s[i] {
	case 0xD0: // А-Я, а-п, Ё
		if (s[i+1] >= 0x90 && s[i+1] <= 0xBF) || s[i+1] == 0x81 {
			return 2
		}
	case 0xD1: // р-я, ё
		if (s[i+1] >= 0x80 && s[i+1] <= 0x8F) || s[i+1] == 0x91 {
			return 2
		}
	}
	return 0
}

// contactDetector finds e-mail addresses and telephone numbers. It holds no
// state, as the Detector contract requires.
type contactDetector struct{}

func init() { Register(contactDetector{}) }

// Name identifies the detector in logs and in Span.Src.
func (contactDetector) Name() string { return "contact" }

// contactTypes is returned by Types; a package-level slice avoids allocating on
// every call from the config and metrics layers.
var contactTypes = []pd.Type{pd.TypeEmail, pd.TypePhone}

// Types lists the PD categories this detector can emit.
func (contactDetector) Types() []pd.Type { return contactTypes }

// Detect scans the lowercased payload. Offsets come straight from ctx.Lower,
// which has the same byte length as ctx.Text, so no remapping is needed.
func (contactDetector) Detect(ctx *Context) []pd.Span {
	var out []pd.Span
	lower := ctx.Lower

	if ctx.Enabled(pd.TypeEmail) {
		out = contactScanEmails(lower, out)
	}
	if ctx.Enabled(pd.TypePhone) {
		out = contactScanPhones(lower, out)
	}
	return out
}

func contactScanEmails(s string, out []pd.Span) []pd.Span {
	for i := 0; i < len(s); {
		k := strings.IndexByte(s[i:], '@')
		if k < 0 {
			return out
		}
		at := i + k
		start, end, ok := contactEmailAround(s, at)
		if !ok {
			i = at + 1
			continue
		}
		if out == nil {
			out = make([]pd.Span, 0, contactSpanCap)
		}
		out = append(out, pd.Span{
			Start: start, End: end,
			Type: pd.TypeEmail, Conf: contactConfEmail,
			Src: "contact", Hint: "email",
		})
		i = end
	}
	return out
}

// contactEmailAround grows the address around the '@' at position at.
//
// The local part is deliberately ASCII-only (letters, digits, dot, underscore,
// hyphen, plus) and must begin with an alphanumeric, so "письмо.ivan@mail.ru"
// reports only the address and the sentence keeps its full stop. Plus
// addressing is part of the local part, quotes and angle brackets are not in
// the character set at all and therefore fall outside the span on their own.
func contactEmailAround(s string, at int) (int, int, bool) {
	start := at
	for start > 0 && contactIsLocalByte(s[start-1]) {
		start--
	}
	// A local part may not open with '.', '-', '+' or '_'; dropping the run of
	// them is what separates the address from the word glued in front of it.
	for start < at && !contactIsAlnumASCII(s[start]) {
		start++
	}
	if start == at || !text.IsBoundary(s, start) {
		return 0, 0, false
	}

	end := at + 1
	for end < len(s) {
		c := s[end]
		if contactIsAlnumASCII(c) || c == '-' || c == '.' {
			end++
			continue
		}
		if n := contactCyrillicLen(s, end); n > 0 {
			end += n
			continue
		}
		break
	}
	// A trailing dot or hyphen belongs to the sentence, not to the domain:
	// "пишите на ivan@mail.ru." and "<ivan@mail.ru>" both end here.
	for end > at+1 && (s[end-1] == '.' || s[end-1] == '-') {
		end--
	}
	if !contactDomainOK(s[at+1:end]) || !text.IsBoundary(s, end) {
		return 0, 0, false
	}
	if contactEmailExcluded(s[start:at], s[at+1:end]) {
		return 0, 0, false
	}
	return start, end, true
}

// contactDomainOK validates the domain half: every label non-empty, and a
// top-level label of at least two letters. The .рф zone is why Cyrillic
// letters count; a digit or a hyphen in the last label means the run is a
// version string or an identifier rather than a host name.
func contactDomainOK(d string) bool {
	dot := strings.LastIndexByte(d, '.')
	if dot <= 0 || dot == len(d)-1 {
		return false
	}
	prev := -1
	for i := 0; i <= len(d); i++ {
		if i == len(d) || d[i] == '.' {
			if i-prev-1 == 0 {
				return false
			}
			prev = i
		}
	}
	tld, n := d[dot+1:], 0
	for i := 0; i < len(tld); {
		if contactIsASCIILetter(tld[i]) {
			i++
			n++
			continue
		}
		m := contactCyrillicLen(tld, i)
		if m == 0 {
			return false
		}
		i += m
		n++
	}
	return n >= 2
}

// contactEmailExcluded reports whether an address is institutional rather than
// personal. The local part is compared without its "+tag" suffix, because
// support+ticket123@ is still the support desk.
func contactEmailExcluded(local, domain string) bool {
	if plus := strings.IndexByte(local, '+'); plus > 0 {
		local = local[:plus]
	}
	if contactEmailLocalStop[local] {
		return true
	}
	for _, d := range contactEmailDomainStop {
		if domain == d || (len(domain) > len(d) &&
			strings.HasSuffix(domain, d) && domain[len(domain)-len(d)-1] == '.') {
			return true
		}
	}
	return false
}

// contactRun is one maximal telephone-shaped run: digits joined by separators,
// ending at the last digit. Everything a rule needs to judge the shape is
// collected in the single pass that finds it, so no rule re-reads the bytes.
type contactRun struct {
	start      int    // first byte of the run: a digit, a '+' or a '('
	end        int    // one past the last digit
	firstDigit int    // first digit of the run
	digits     int    // how many digits it holds
	groups     [4]int // sizes of the first four digit groups
	nGroups    int    // how many groups there are in total
	hasDot     bool   // at least one group separator was a dot
}

func contactScanPhones(s string, out []pd.Span) []pd.Span {
	emails := len(out) // spans collected so far are addresses
	for i := 0; i < len(s); {
		if !contactRunStart[s[i]] {
			i++
			continue
		}
		r, ok := contactRunAt(s, i)
		if !ok {
			i++
			continue
		}
		i = r.end
		contactDropExportSuffix(s, &r)
		start, conf, hint, needAnchor, ok := contactClassify(s, r)
		if !ok {
			continue
		}
		if !contactBoundsOK(s, r) || contactOverlaps(out[:emails], start, r.end) {
			continue
		}
		var buf [contactPhoneMaxDigits + 1]byte
		n := 0
		for p := r.firstDigit; p < r.end; p++ {
			if contactIsDigit(s[p]) {
				buf[n] = s[p]
				n++
			}
		}
		if contactPhoneExcluded(buf[:n]) {
			continue
		}
		if needAnchor && !contactHasAnchorLeft(s, start) {
			continue
		}
		if out == nil {
			out = make([]pd.Span, 0, contactSpanCap)
		}
		out = append(out, pd.Span{
			Start: start, End: r.end,
			Type: pd.TypePhone, Conf: conf,
			Src: "contact", Hint: hint,
		})
	}
	return out
}

// contactRunAt collects the telephone-shaped run beginning at i. It reports
// ok=false when the run holds no digit at all, which is the only way a '+' or
// a '(' can open one and lead nowhere.
func contactRunAt(s string, i int) (contactRun, bool) {
	r := contactRun{start: i, firstDigit: -1}
	j := i
	if s[j] == '+' {
		j++
	}
	for j < len(s) {
		if contactIsDigit(s[j]) {
			g := j
			for j < len(s) && contactIsDigit(s[j]) {
				j++
			}
			if r.firstDigit < 0 {
				r.firstDigit = g
			}
			if r.nGroups < len(r.groups) {
				r.groups[r.nGroups] = j - g
			}
			r.nGroups++
			r.digits += j - g
			r.end = j
			continue
		}
		next, dot, ok := contactSepRun(s, j)
		if !ok {
			break
		}
		r.hasDot = r.hasDot || dot
		j = next
	}
	return r, r.firstDigit >= 0
}

// contactSepRun consumes the separators at i and returns where the next digit
// begins. At most two separators may stand between two groups, which is what
// admits ") " in "(916) 123-45-67" while refusing the line break between two
// unrelated numbers.
//
// A dot is a separator only when it sits directly between two digits. A full
// stop followed by a space ends a sentence, and treating it as a separator
// would splice the next sentence's number onto this one — the joined run would
// then be too long for any rule and BOTH numbers would be lost.
func contactSepRun(s string, i int) (int, bool, bool) {
	j, dot := i, false
	for j < len(s) && j-i < 2 && contactIsPhoneSep(s[j]) {
		if s[j] == '.' {
			dot = true
		}
		j++
	}
	if j == i || j >= len(s) || !contactIsDigit(s[j]) {
		return i, false, false
	}
	if dot && j-i != 1 {
		return i, false, false
	}
	return j, dot, true
}

// contactDropExportSuffix removes a trailing ".0" from a telephone run when it
// sits at the very end of the value. Spreadsheet exports leave a float artifact
// on numbers, and a phone followed by ".0" must still be seen as the phone. The
// suffix is dropped only when nothing but a boundary follows it, so a sum like
// "4276.16" or a version like "1.2.30" is never touched.
func contactDropExportSuffix(s string, r *contactRun) {
	if r.end < 2 || s[r.end-1] != '0' || s[r.end-2] != '.' {
		return
	}
	if r.end < len(s) {
		switch s[r.end] {
		case ' ', ',', '.':
		default:
			return
		}
	}
	r.end -= 2
	r.digits--
	r.nGroups--
	if r.nGroups < len(r.groups) {
		r.groups[r.nGroups] = 0
	}
	r.hasDot = false
	for p := r.start; p < r.end; p++ {
		if s[p] == '.' {
			r.hasDot = true
			break
		}
	}
}

// contactClassify decides which telephone shape a run is, if any. The cases
// are ordered by how much they prove, and each one is a rule in its own right:
//
//	ru         eleven digits opening with the Russian country prefix, in any
//	           separator style: +7 916 123-45-67, 8(916)1234567, 8.916.123.45.67
//	area-code  a parenthesised area code and nine to eleven digits
//	intl       a leading '+' and a plausible E.164 length
//	local      ten digits grouped 3-3-2-2, the national way of writing a number
//	bare       ten digits in any other grouping — needs a cue word
//
// A run written with dots is only trusted when the country prefix confirms it:
// "192.168.10.10" is grouped exactly like a local number, and an IP address in
// a log line must come back byte for byte.
func contactClassify(s string, r contactRun) (start int, conf float64, hint string, needAnchor, ok bool) {
	first := s[r.firstDigit]
	switch {
	case r.digits == 11 && (first == '7' || first == '8'):
		conf, hint = contactConfPhonePlus7, "ru"
	case s[r.start] == '(' && r.digits >= 9 && r.digits <= 11:
		conf, hint = contactConfPhoneOther, "area-code"
	case s[r.start] == '+' && r.digits >= 8 && r.digits <= contactPhoneMaxDigits:
		conf, hint = contactConfPhoneOther, "intl"
	case r.digits == 10 && r.nGroups == 4 && r.groups == [4]int{3, 3, 2, 2}:
		conf, hint = contactConfPhoneOther, "local"
	case r.digits == 10:
		conf, hint, needAnchor = contactConfPhoneOther, "bare", true
	default:
		return 0, 0, "", false, false
	}
	if r.hasDot && hint != "ru" {
		needAnchor = true
	}
	// The '+' and the parenthesised area code are part of how the number is
	// written; a stray '(' in front of any other shape is not.
	start = r.firstDigit
	if c := s[r.start]; c == '+' || (c == '(' && hint == "area-code") {
		start = r.start
	}
	return start, conf, hint, needAnchor, true
}

// contactBoundsOK reports whether the run stands on its own rather than inside
// a longer token: "id4111111111111111" is an identifier, and a number glued to
// a word never is a telephone.
func contactBoundsOK(s string, r contactRun) bool {
	if contactIsDigit(s[r.start]) {
		if !text.IsBoundary(s, r.start) {
			return false
		}
	} else if r.start > 0 && contactIsDigit(s[r.start-1]) {
		return false
	}
	return text.IsBoundary(s, r.end)
}

// contactOverlaps reports whether [start,end) touches an already accepted span.
// The list is tiny in practice (contacts are sparse), so a linear scan beats a
// map or an interval tree here.
func contactOverlaps(spans []pd.Span, start, end int) bool {
	for _, s := range spans {
		if start < s.End && s.Start < end {
			return true
		}
	}
	return false
}

// contactPhoneExcluded reports whether a number is a published service line.
// The national significant number is compared, so both "8 800 …" and
// "+7 800 …" are recognised as the same toll-free range. The digits arrive in
// a stack buffer and the map is indexed through string(b), which the compiler
// turns into a lookup with no copy, so nothing here allocates.
func contactPhoneExcluded(digits []byte) bool {
	if contactPhoneShortStop[string(digits)] {
		return true
	}
	nat := digits
	if len(nat) == 11 && (nat[0] == '7' || nat[0] == '8') {
		nat = nat[1:]
	}
	if contactPhoneShortStop[string(nat)] {
		return true
	}
	for _, p := range contactPhoneFreePrefixes {
		if contactHasPrefix(nat, p) {
			return true
		}
	}
	return false
}

// contactHasPrefix is bytes.HasPrefix without the import — and without the
// conversion an inline string(b) comparison would cost.
func contactHasPrefix(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if b[i] != p[i] {
			return false
		}
	}
	return true
}

// contactHasAnchorLeft reports whether a cue word starts within
// contactAnchorWindow bytes to the left of before. The window is sliced from
// the lowered text, but the boundary check runs against the full string so a
// cue cut in half by the window edge can never be accepted.
func contactHasAnchorLeft(s string, before int) bool {
	from := before - contactAnchorWindow
	if from < 0 {
		from = 0
	}
	win := s[from:before]
	for _, a := range contactPhoneAnchors {
		for off := 0; off < len(win); {
			i := strings.Index(win[off:], a)
			if i < 0 {
				break
			}
			if abs := from + off + i; text.IsBoundary(s, abs) {
				return true
			}
			off += i + 1
		}
	}
	return false
}
