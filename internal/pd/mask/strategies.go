package mask

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode"

	"pdguard/internal/pd"
)

// Strategy names, as written in configuration files. They are exported so the
// config layer can reference them without repeating string literals that would
// silently rot if a strategy is ever renamed.
const (
	// NameStarsKeep2 is the default for almost every type: it keeps the first
	// and last two alphanumerics and stars the rest.
	NameStarsKeep2 = "stars_keep2"
	// NameStarsAll hides every alphanumeric; used for secrets short enough that
	// even two visible characters would leak a meaningful fraction (CVV, PIN).
	NameStarsAll = "stars_all"
	// NameInitials renders a Cyrillic full name as initials, e.g. "И. И. И.".
	NameInitials = "initials"
	// NameInitialsLatin is NameInitials for Latin script (card holder line).
	NameInitialsLatin = "initials_latin"
	// NameLabel replaces the value with a bracketed Russian category label.
	NameLabel = "label"
	// NameToken replaces the value with a deterministic pseudonym token.
	NameToken = "token"
	// NameSynthetic replaces the value with a plausible fake of the same shape.
	NameSynthetic = "synthetic"
	// NameKeepDomain masks only the local part of an e-mail address.
	NameKeepDomain = "keep_domain"
	// NameNone leaves the value untouched; it disables masking for a type
	// without having to disable its detector.
	NameNone = "none"
)

func init() {
	RegisterStrategy(starsKeep2Strategy{})
	RegisterStrategy(starsAllStrategy{})
	RegisterStrategy(initialsStrategy{})
	RegisterStrategy(initialsLatinStrategy{})
	RegisterStrategy(labelStrategy{})
	RegisterStrategy(tokenStrategy{})
	RegisterStrategy(syntheticStrategy{})
	RegisterStrategy(keepDomainStrategy{})
	RegisterStrategy(noneStrategy{})
}

// isAlnum decides which runes the star strategies are allowed to hide.
// Separators (spaces, dots, hyphens, "@", "+", brackets) are deliberately NOT
// alphanumeric: the scoring metric is a span-based edit distance against a
// reference mask, so keeping punctuation in place costs nothing and keeps the
// masked text aligned with the reference character for character.
func isAlnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// countAlnum counts maskable runes without allocating.
func countAlnum(s string) int {
	n := 0
	for _, r := range s {
		if isAlnum(r) {
			n++
		}
	}
	return n
}

// starsMask replaces alphanumerics with '*', keeping head leading and tail
// trailing ones. Everything else is copied verbatim, so the output has exactly
// the same rune count as the input. Cyrillic is handled by iterating runes:
// a Cyrillic letter is two bytes and a byte loop would corrupt it.
func starsMask(s string, head, tail int) string {
	n := countAlnum(s)
	if n == 0 {
		return s
	}
	if head+tail >= n {
		// Nothing would be hidden — mask everything instead. Leaking a short
		// value in full is worse than over-masking a four-character one.
		head, tail = 0, 0
	}
	var sb strings.Builder
	sb.Grow(len(s)) // output is never longer: a 2-byte letter becomes a 1-byte '*'
	idx := 0
	for _, r := range s {
		if !isAlnum(r) {
			sb.WriteRune(r)
			continue
		}
		if idx < head || idx >= n-tail {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('*')
		}
		idx++
	}
	return sb.String()
}

type starsKeep2Strategy struct{}

func (starsKeep2Strategy) Name() string { return NameStarsKeep2 }

// Mask keeps the first two and last two alphanumerics. The format is pinned by
// the only reference sample in the statement of work: "4509 123456" must become
// "45** ****56", which this rule reproduces byte for byte.
func (starsKeep2Strategy) Mask(original string, _ pd.Type) string {
	return starsMask(original, 2, 2)
}

type starsAllStrategy struct{}

func (starsAllStrategy) Name() string { return NameStarsAll }

// Mask hides every alphanumeric. Used for CVV and PIN, where three or four
// digits carry so little entropy that revealing any of them is a real leak.
func (starsAllStrategy) Mask(original string, _ pd.Type) string {
	return starsMask(original, 0, 0)
}

// initialsOf reduces every word of s to "X." separated by a space, keeping a
// hyphen between the halves of a double surname ("Петров-Водкин" -> "П.-В.").
// isWordRune decides which script counts as a word character, so the Latin
// variant does not emit initials for stray Cyrillic and vice versa.
//
// The scan is single pass over runes and treats a dot as an ordinary
// separator, which is what makes an already abbreviated input ("Иванов И.И.")
// normalise to the same canonical "И. И. И." as the spelled-out form. That
// idempotence matters because detection may see either spelling.
func initialsOf(s string, isWordRune func(rune) bool) string {
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	inWord, first := false, true
	sep := byte(' ')
	for _, r := range s {
		switch {
		case isWordRune(r):
			if inWord {
				continue
			}
			writeInitial(&sb, first, sep, r)
			first, inWord = false, true
		case r == '-' || r == '–' || r == '‑':
			inWord, sep = false, '-'
		case r == '/':
			inWord, sep = false, '/'
		default:
			inWord, sep = false, ' '
		}
	}
	if first {
		return ""
	}
	return sb.String()
}

// writeInitial appends one initial: the separator before it, then the
// upper-cased letter and a dot. sep is the byte written between initials: a
// space, a hyphen (double surname) or a slash (alternative surname).
func writeInitial(sb *strings.Builder, first bool, sep byte, r rune) {
	if !first {
		sb.WriteByte(sep)
	}
	// Uppercase unconditionally: the reference masks spell initials in
	// capitals even when the source was typed in lower case.
	sb.WriteRune(unicode.ToUpper(r))
	sb.WriteByte('.')
}

func isAnyLetter(r rune) bool { return unicode.IsLetter(r) }

func isLatinLetter(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
}

type initialsStrategy struct{}

func (initialsStrategy) Name() string { return NameInitials }

// Mask renders "Иванов Иван Иванович" as "И. И. И.", the shape given as an
// example in the statement of work. A value with no letters at all (a detector
// misfire) falls back to stars_keep2 rather than returning it unmasked.
func (initialsStrategy) Mask(original string, _ pd.Type) string {
	if out := initialsOf(original, isAnyLetter); out != "" {
		return out
	}
	return starsMask(original, 2, 2)
}

type initialsLatinStrategy struct{}

func (initialsLatinStrategy) Name() string { return NameInitialsLatin }

// Mask is the Latin-script counterpart used for the card holder line:
// "IVAN IVANOV" becomes "I. I.".
func (initialsLatinStrategy) Mask(original string, _ pd.Type) string {
	if out := initialsOf(original, isLatinLetter); out != "" {
		return out
	}
	return starsMask(original, 2, 2)
}

// typeLabels maps every catalogue type to its Russian label. The map is built
// once at package init and never written afterwards, so concurrent reads from
// the request path need no lock.
var typeLabels = map[pd.Type]string{
	pd.TypeFIO:               "[ФИО]",
	pd.TypeBirthDate:         "[ДАТА РОЖДЕНИЯ]",
	pd.TypeBirthPlace:        "[МЕСТО РОЖДЕНИЯ]",
	pd.TypePassport:          "[ПАСПОРТ]",
	pd.TypePassportIssueDate: "[ДАТА ВЫДАЧИ]",
	pd.TypePassportIssuer:    "[КЕМ ВЫДАН]",
	pd.TypeSubdivisionCode:   "[КОД ПОДРАЗДЕЛЕНИЯ]",
	pd.TypeCitizenship:       "[ГРАЖДАНСТВО]",
	pd.TypeDriverLicense:     "[ВОДИТЕЛЬСКОЕ УДОСТОВЕРЕНИЕ]",
	pd.TypeAddress:           "[АДРЕС]",
	pd.TypeCountry:           "[СТРАНА]",
	pd.TypePostalCode:        "[ИНДЕКС]",
	pd.TypeCity:              "[ГОРОД]",
	pd.TypeStreet:            "[УЛИЦА]",
	pd.TypeHouse:             "[ДОМ]",
	pd.TypeApartment:         "[КВАРТИРА]",
	pd.TypeEmail:             "[ПОЧТА]",
	pd.TypePhone:             "[ТЕЛЕФОН]",
	pd.TypeINN:               "[ИНН]",
	pd.TypeCardNumber:        "[КАРТА]",
	pd.TypeCardHolder:        "[ДЕРЖАТЕЛЬ КАРТЫ]",
	pd.TypeCVV:               "[CVV]",
	pd.TypePIN:               "[ПИН]",
	pd.TypeSNILS:             "[СНИЛС]",
	pd.TypeForeignPassport:   "[ЗАГРАНПАСПОРТ]",
	pd.TypeBirthCertificate:  "[СВИДЕТЕЛЬСТВО О РОЖДЕНИИ]",
	pd.TypeMilitaryID:        "[ВОЕННЫЙ БИЛЕТ]",
	pd.TypeResidencePermit:   "[ВИД НА ЖИТЕЛЬСТВО]",
	pd.TypeOMS:               "[ПОЛИС ОМС]",
	pd.TypeBankAccount:       "[СЧЁТ]",
}

type labelStrategy struct{}

func (labelStrategy) Name() string { return NameLabel }

// Mask replaces the value with its category label. It destroys the original
// length, so it is offered as an option rather than used by default: the
// scoring metric rewards masks that stay aligned with the source text.
func (labelStrategy) Mask(_ string, t pd.Type) string { return Label(t) }

// tokenSalt keeps tokens from being reversible by dictionary attack on short
// values (a phone number has only ~10^10 candidates). It is a build-time
// constant so the same value always yields the same token across replicas —
// a retry of the same request must return a byte-identical answer.
const tokenSalt = "pdguard.v1.token"

// tokenHexLen is the number of hex characters appended to a token. Three bytes
// of digest give six characters, enough to keep distinct values apart inside
// one payload while staying short enough not to distort the text.
const tokenHexLen = 6

type tokenStrategy struct{}

func (tokenStrategy) Name() string { return NameToken }

// Mask renders a pseudonym such as "PD_FIO_a1b2c3". The same value always maps
// to the same token, so an LLM can still tell two mentions of the same person
// apart from two different people — this is the tokenisation bonus item of the
// statement of work.
func (tokenStrategy) Mask(original string, t pd.Type) string {
	sum := sha256.Sum256([]byte(tokenSalt + "\x00" + original))
	tail := hex.EncodeToString(sum[:tokenHexLen/2])
	slug := string(t)
	if slug == "" {
		slug = "PD"
	}
	var sb strings.Builder
	sb.Grow(len(slug) + tokenHexLen + 4)
	sb.WriteString("PD_")
	sb.WriteString(slug)
	sb.WriteByte('_')
	sb.WriteString(tail)
	return sb.String()
}

// syntheticSalt separates the synthetic stream from the token stream so the
// two features cannot be correlated against each other.
const syntheticSalt = "pdguard.v1.synthetic"

// stream is a deterministic byte source derived from the SHA-256 digest of the
// masked value. math/rand is deliberately not used: a retried request must
// produce the identical replacement, and a global RNG would also be a shared
// mutable state on a 1000 RPS path. Each stream is created per call and never
// escapes it, so the type is safe to use concurrently.
type stream struct {
	buf [sha256.Size]byte
	pos int
}

// newStream seeds the byte source from the salt and the given parts.
func newStream(parts ...string) *stream {
	h := sha256.New()
	h.Write([]byte(syntheticSalt))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	s := &stream{}
	h.Sum(s.buf[:0])
	return s
}

// next returns the next pseudo-random byte, re-hashing when the digest is
// exhausted so long values never run out of entropy.
func (s *stream) next() byte {
	if s.pos == len(s.buf) {
		s.buf = sha256.Sum256(s.buf[:])
		s.pos = 0
	}
	b := s.buf[s.pos]
	s.pos++
	return b
}

// pick returns a deterministic index in [0,n).
func (s *stream) pick(n int) int {
	if n <= 0 {
		return 0
	}
	return int(s.next()) % n
}

// digit returns a deterministic ASCII digit.
func (s *stream) digit() byte { return '0' + s.next()%10 }

// Name pools for synthetic full names. They are intentionally short and
// unremarkable: the point is to keep the sentence readable for the LLM, not to
// simulate the Russian census.
var (
	synSurnamesM = []string{"Соколов", "Петров", "Смирнов", "Кузнецов", "Попов", "Новиков", "Морозов", "Волков"}
	synFirstM    = []string{"Андрей", "Дмитрий", "Сергей", "Михаил", "Никита", "Егор", "Павел", "Роман"}
	synPatrM     = []string{"Андреевич", "Дмитриевич", "Сергеевич", "Михайлович", "Никитич", "Егорович", "Павлович", "Романович"}

	synSurnamesF = []string{"Соколова", "Петрова", "Смирнова", "Кузнецова", "Попова", "Новикова", "Морозова", "Волкова"}
	synFirstF    = []string{"Анна", "Мария", "Елена", "Ольга", "Ирина", "Татьяна", "Наталья", "Дарья"}
	synPatrF     = []string{"Андреевна", "Дмитриевна", "Сергеевна", "Михайловна", "Никитична", "Егоровна", "Павловна", "Романовна"}

	synLatinFirst    = []string{"Ivan", "Petr", "Andrey", "Sergey", "Mikhail", "Aleksey", "Dmitriy", "Nikolay"}
	synLatinSurnames = []string{"Ivanov", "Petrov", "Sokolov", "Smirnov", "Kuznetsov", "Popov", "Novikov", "Morozov"}

	synCities = []string{"Самара", "Казань", "Воронеж", "Пермь", "Тюмень", "Саратов", "Курск", "Тверь"}

	synEmailLocals = []string{"ivanov", "petrov.a", "sokolov", "smirnova", "kuznetsov1", "popov.s", "novikov", "morozov.d"}
)

// Alphabets for the generic shape-preserving fallback. Vowels and consonants
// are alternated so the result is pronounceable rather than an unreadable
// consonant cluster, which keeps the text natural for the model.
var (
	cyrVowels = []rune("аеиоуыэюя")
	cyrCons   = []rune("бвгдклмнпрстфх")
	latVowels = []rune("aeiou")
	latCons   = []rune("bdfgklmnprstv")
)

type caseStyle uint8

const (
	caseMixed caseStyle = iota // 0
	caseUpper                  // 1
	caseLower                  // 2
)

// detectCase reports how the original was capitalised so the synthetic value
// can imitate it: "IVAN IVANOV" must not come back as "Ivan Ivanov".
func detectCase(s string) caseStyle {
	hasUpper, hasLower := false, false
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		}
	}
	switch {
	case hasUpper && !hasLower:
		return caseUpper
	case hasLower && !hasUpper:
		return caseLower
	default:
		return caseMixed
	}
}

func applyCase(s string, c caseStyle) string {
	switch c {
	case caseUpper:
		return strings.ToUpper(s)
	case caseLower:
		return strings.ToLower(s)
	default:
		return s
	}
}

// wordCount counts maximal letter runs, which is how many name parts the
// synthetic value has to produce to keep the same shape.
func wordCount(s string) int {
	n, in := 0, false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if !in {
				n++
				in = true
			}
		} else {
			in = false
		}
	}
	return n
}

func hasCyrillic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

// looksFemale is a cheap suffix heuristic. Getting the gender wrong only makes
// the fake slightly less natural, so a full morphological analyser would be
// overkill here.
func looksFemale(s string) bool {
	lower := strings.ToLower(s)
	for _, w := range strings.FieldsFunc(lower, func(r rune) bool { return !unicode.IsLetter(r) }) {
		if strings.HasSuffix(w, "вна") || strings.HasSuffix(w, "ова") ||
			strings.HasSuffix(w, "ева") || strings.HasSuffix(w, "ина") {
			return true
		}
	}
	return false
}

// syntheticName builds a fake full name with the same number of parts and the
// same capitalisation as the original.
func syntheticName(original string, h *stream) string {
	n := wordCount(original)
	if n == 0 {
		return genericShape(original, h)
	}
	var parts []string
	if hasCyrillic(original) {
		sur, first, patr := synSurnamesM, synFirstM, synPatrM
		if looksFemale(original) {
			sur, first, patr = synSurnamesF, synFirstF, synPatrF
		}
		switch {
		case n >= 3:
			parts = []string{sur[h.pick(len(sur))], first[h.pick(len(first))], patr[h.pick(len(patr))]}
		case n == 2:
			parts = []string{sur[h.pick(len(sur))], first[h.pick(len(first))]}
		default:
			parts = []string{sur[h.pick(len(sur))]}
		}
	} else {
		// Latin order follows the card holder line: given name then surname.
		switch {
		case n >= 2:
			parts = []string{synLatinFirst[h.pick(len(synLatinFirst))], synLatinSurnames[h.pick(len(synLatinSurnames))]}
		default:
			parts = []string{synLatinSurnames[h.pick(len(synLatinSurnames))]}
		}
	}
	return applyCase(strings.Join(parts, " "), detectCase(original))
}

// luhnCheckDigit returns the digit that makes payload+check pass the Luhn test.
// Card numbers are validated by consumers (and by our own detector), so a fake
// that fails the checksum would be spotted as garbage.
func luhnCheckDigit(payload []byte) byte {
	sum, double := 0, true
	for i := len(payload) - 1; i >= 0; i-- {
		d := int(payload[i])
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return byte((10 - sum%10) % 10)
}

// digitsOf collects the decimal digits of s as values 0..9.
func digitsOf(s string) []byte {
	out := make([]byte, 0, 24)
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			out = append(out, c-'0')
		}
	}
	return out
}

// writeDigits copies s, substituting the i-th decimal digit with digits[i].
// Every non-digit rune keeps its exact position, which is what preserves the
// formatting of the original (spaces, dashes, plus sign, brackets).
func writeDigits(s string, digits []byte) string {
	var sb strings.Builder
	sb.Grow(len(s))
	k := 0
	for _, r := range s {
		if r >= '0' && r <= '9' && k < len(digits) {
			sb.WriteByte('0' + digits[k])
			k++
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// syntheticCard keeps the leading digit (so a Visa stays a Visa) and the
// separators, randomises the middle and recomputes the Luhn check digit.
func syntheticCard(original string, h *stream) string {
	d := digitsOf(original)
	if len(d) < 4 {
		return genericShape(original, h)
	}
	out := make([]byte, len(d))
	out[0] = d[0]
	for i := 1; i < len(out)-1; i++ {
		out[i] = h.next() % 10
	}
	out[len(out)-1] = luhnCheckDigit(out[:len(out)-1])
	return writeDigits(original, out)
}

// syntheticPhone keeps the country prefix and the mobile "9" so the result is
// still recognisable as a Russian mobile number of the same format.
func syntheticPhone(original string, h *stream) string {
	d := digitsOf(original)
	if len(d) == 0 {
		return genericShape(original, h)
	}
	out := make([]byte, len(d))
	copy(out, d)
	start := 0
	if d[0] == 7 || d[0] == 8 {
		start = 1
	}
	if len(d)-start >= 10 {
		out[start] = 9
		start++
	}
	for i := start; i < len(out); i++ {
		out[i] = h.next() % 10
	}
	return writeDigits(original, out)
}

// syntheticEmail swaps the local part for a plausible one and keeps the domain:
// the domain is a property of the mail provider, not of the person, and the
// model often needs it (corporate vs. personal address).
func syntheticEmail(original string, h *stream) string {
	at := strings.LastIndexByte(original, '@')
	if at <= 0 {
		return genericShape(original, h)
	}
	local := synEmailLocals[h.pick(len(synEmailLocals))]
	return applyCase(local, detectCase(original[:at])) + original[at:]
}

// digitGroup is one run of consecutive digits inside a date.
type digitGroup struct {
	start, end int
	val        int
}

func digitGroups(s string) []digitGroup {
	var out []digitGroup
	i := 0
	for i < len(s) {
		if s[i] < '0' || s[i] > '9' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		v, _ := strconv.Atoi(s[i:j])
		out = append(out, digitGroup{start: i, end: j, val: v})
		i = j
	}
	return out
}

// shiftYear moves a year a few years back, staying inside a plausible and
// four-digit-wide range so the rendered group keeps its width.
func shiftYear(y int, h *stream) int {
	v := y - (1 + h.pick(6))
	if v < 1900 || v > 2100 {
		v = 1970 + h.pick(40)
	}
	return v
}

// syntheticDate rebuilds a date keeping the separators, the field order and the
// width of every group, and guarantees the result is a real calendar date:
// days stay in 1..28 and months in 1..12, so February never gets a 30th.
func syntheticDate(original string, h *stream) string {
	g := digitGroups(original)
	if len(g) == 0 {
		return original
	}
	vals := make([]int, len(g))
	switch {
	case len(g) == 3 && g[2].end-g[2].start == 4: // dd.mm.yyyy
		vals[0] = 1 + h.pick(28)
		vals[1] = 1 + h.pick(12)
		vals[2] = shiftYear(g[2].val, h)
	case len(g) == 3 && g[0].end-g[0].start == 4: // yyyy-mm-dd
		vals[0] = shiftYear(g[0].val, h)
		vals[1] = 1 + h.pick(12)
		vals[2] = 1 + h.pick(28)
	default:
		// Unknown layout (e.g. "12 января 1990"): a 4-digit group is a year,
		// anything shorter is capped at 12 so it is valid as day or month.
		for i, grp := range g {
			if grp.end-grp.start >= 4 {
				vals[i] = shiftYear(grp.val, h)
			} else {
				vals[i] = 1 + h.pick(12)
			}
		}
	}
	var sb strings.Builder
	sb.Grow(len(original))
	cursor := 0
	for i, grp := range g {
		sb.WriteString(original[cursor:grp.start])
		sb.WriteString(padNum(vals[i], grp.end-grp.start))
		cursor = grp.end
	}
	sb.WriteString(original[cursor:])
	return sb.String()
}

// padNum renders v zero-padded to width, truncating from the left if it would
// not fit — the width of every group must survive so the mask stays aligned.
func padNum(v, width int) string {
	s := strconv.Itoa(v)
	if len(s) > width {
		return s[len(s)-width:]
	}
	if len(s) == width {
		return s
	}
	var sb strings.Builder
	sb.Grow(width)
	for i := len(s); i < width; i++ {
		sb.WriteByte('0')
	}
	sb.WriteString(s)
	return sb.String()
}

// genericShape is the fallback for identifiers with no special structure
// (passport, INN, SNILS, street names...). It replaces every digit with a
// digit and every letter with a letter of the same script and case, leaving
// punctuation alone, so the value keeps its exact length and silhouette.
func genericShape(original string, h *stream) string {
	var sb strings.Builder
	sb.Grow(len(original))
	prevVowel := false
	for _, r := range original {
		switch {
		case r >= '0' && r <= '9':
			sb.WriteByte(h.digit())
		case unicode.IsLetter(r):
			cyr := unicode.Is(unicode.Cyrillic, r)
			var pool []rune
			switch {
			case cyr && prevVowel:
				pool = cyrCons
			case cyr:
				pool = cyrVowels
			case prevVowel:
				pool = latCons
			default:
				pool = latVowels
			}
			n := pool[h.pick(len(pool))]
			if unicode.IsUpper(r) {
				n = unicode.ToUpper(n)
			}
			sb.WriteRune(n)
			prevVowel = !prevVowel
		default:
			sb.WriteRune(r)
			prevVowel = false
		}
	}
	return sb.String()
}

type syntheticStrategy struct{}

func (syntheticStrategy) Name() string { return NameSynthetic }

// Mask returns a fake value of the same type and the same shape — a different
// full name, a different card number that still passes Luhn, a different but
// valid date. This is the "synthetic replacement" bonus item: unlike stars, it
// leaves the prompt semantically intact, so the model can still reason about
// "the client" without ever seeing the real person.
func (syntheticStrategy) Mask(original string, t pd.Type) string {
	if original == "" {
		return original
	}
	h := newStream(string(t), original)
	switch t {
	case pd.TypeFIO, pd.TypeCardHolder:
		return syntheticName(original, h)
	case pd.TypeCardNumber:
		return syntheticCard(original, h)
	case pd.TypePhone:
		return syntheticPhone(original, h)
	case pd.TypeEmail:
		return syntheticEmail(original, h)
	case pd.TypeBirthDate, pd.TypePassportIssueDate:
		return syntheticDate(original, h)
	case pd.TypeCity, pd.TypeBirthPlace:
		city := synCities[h.pick(len(synCities))]
		return applyCase(city, detectCase(original))
	default:
		return genericShape(original, h)
	}
}

type keepDomainStrategy struct{}

func (keepDomainStrategy) Name() string { return NameKeepDomain }

// Mask hides the local part of an address and keeps the domain:
// "ivanov@mail.ru" becomes "iv****@mail.ru". Only the first two characters
// survive here (unlike stars_keep2): the tail of a local part is usually the
// surname ending or a birth year and is the most identifying piece of it.
// A value with no "@" is not an address after all, so it falls back to the
// default strategy rather than being emitted unmasked.
func (keepDomainStrategy) Mask(original string, _ pd.Type) string {
	at := strings.LastIndexByte(original, '@')
	if at <= 0 {
		return starsMask(original, 2, 2)
	}
	return starsMask(original[:at], 2, 0) + original[at:]
}

type noneStrategy struct{}

func (noneStrategy) Name() string { return NameNone }

// Mask returns the value unchanged. It exists so a type can be detected,
// counted and reported in metrics while staying visible to the model — useful
// when a category turns out to be a false-positive source and has to be
// neutralised in production without a redeploy.
func (noneStrategy) Mask(original string, _ pd.Type) string { return original }
