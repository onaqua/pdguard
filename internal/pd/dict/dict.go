// Package dict holds the lexical knowledge the detectors rely on: Russian
// given names and patronymic shapes, toponyms, issuing-authority vocabulary,
// and — just as important — the negative lists that keep the service from
// masking things that are not personal data.
//
// Data lives in data/*.txt (one entry per line, '#' starts a comment) and is
// embedded into the binary, so the service has no runtime file dependencies.
package dict

import (
	"embed"
	"sort"
	"strings"
	"sync"

	"pdguard/internal/pd/text"
)

//go:embed data/*.txt
var files embed.FS

type set = map[string]struct{}

func lines(name string) []string {
	raw, err := files.ReadFile(name)
	if err != nil {
		return nil
	}
	out := make([]string, 0, 256)
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(strings.TrimSuffix(ln, "\r"))
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, text.SafeLower(ln))
	}
	return out
}

func readSet(name string) set {
	s := make(set, 256)
	for _, line := range lines(name) {
		s[line] = struct{}{}
	}
	return s
}

// readIndexed reads "value<TAB>number" (or "value number") pairs, e.g. month
// names to their ordinal position.
func readIndexed(name string) map[string]int {
	m := make(map[string]int, 64)
	for _, line := range lines(name) {
		key, num, ok := splitIndexed(line)
		if !ok {
			continue
		}
		if n := parseIndexedNum(num); n > 0 {
			m[strings.TrimSpace(key)] = n
		}
	}
	return m
}

// splitIndexed splits a "value<TAB>number" (or "value number") line.
func splitIndexed(line string) (key, num string, ok bool) {
	key, num, ok = strings.Cut(line, "\t")
	if ok {
		return key, num, true
	}
	return strings.Cut(line, " ")
}

// parseIndexedNum parses a decimal number, returning -1 for a non-numeric one.
func parseIndexedNum(num string) int {
	n := 0
	for _, c := range strings.TrimSpace(num) {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

var (
	once sync.Once

	firstNames   set
	surnames     set
	patronymics  set
	latinNames   set
	cities       set
	streetTypes  set
	countries    set
	citizenships set
	issuerWords  set
	months       map[string]int
	ordinals     map[string]int
	famous       set
	famousLast   set
	famousWords  set
	famousSets   set
	stopWords    set
	bankPlaces   set
	orgWords     set
)

func load() {
	once.Do(func() {
		firstNames = readSet("data/first_names.txt")
		surnames = readSet("data/surnames.txt")
		patronymics = readSet("data/patronymics.txt")
		latinNames = readSet("data/latin_names.txt")
		cities = readSet("data/cities.txt")
		streetTypes = readSet("data/street_types.txt")
		countries = readSet("data/countries.txt")
		citizenships = readSet("data/citizenships.txt")
		issuerWords = readSet("data/issuer_words.txt")
		famous = readSet("data/famous_people.txt")
		stopWords = readSet("data/stop_words.txt")
		bankPlaces = readSet("data/bank_places.txt")
		orgWords = readSet("data/org_words.txt")
		months = readIndexed("data/months.txt")
		ordinals = readIndexed("data/ordinals.txt")

		buildFamousIndexes()
		buildCityForms()
	})
}

// buildFamousIndexes fills the famous-word and famous-surname sets from the
// famous-people list.
func buildFamousIndexes() {
	famousLast = make(set, len(famous))
	famousWords = make(set, len(famous)*3)
	famousSets = make(set, len(famous))
	for full := range famous {
		parts := strings.Fields(full)
		for _, part := range parts {
			famousWords[part] = struct{}{}
			if isFamousSurnameWord(part) {
				famousLast[part] = struct{}{}
			}
		}
		famousSets[sortedKey(parts)] = struct{}{}
	}
}

// isFamousSurnameWord reports whether a word of a famous name is long enough
// and not an ordinary given name, surname or patronymic, so it can identify a
// public figure on its own.
func isFamousSurnameWord(part string) bool {
	if len([]rune(part)) < 4 {
		return false
	}
	if _, ok := surnames[part]; ok {
		return false
	}
	if _, ok := firstNames[part]; ok {
		return false
	}
	if _, ok := patronymics[part]; ok {
		return false
	}
	return true
}

// sortedKey joins words in sorted order so that two spellings of one name that
// differ only in word order produce the same key.
func sortedKey(words []string) string {
	cp := make([]string, len(words))
	copy(cp, words)
	sort.Strings(cp)
	return strings.Join(cp, " ")
}

// ---- lookups. All take an ALREADY-LOWERCASED word. ----

func IsFirstName(w string) bool   { load(); _, ok := firstNames[w]; return ok }
func IsSurname(w string) bool     { load(); _, ok := surnames[w]; return ok }
func IsLatinName(w string) bool   { load(); _, ok := latinNames[w]; return ok }
func IsCity(w string) bool        { load(); _, ok := cities[w]; return ok }
func IsStreetType(w string) bool  { load(); _, ok := streetTypes[w]; return ok }
func IsCountry(w string) bool     { load(); _, ok := countries[w]; return ok }
func IsCitizenship(w string) bool { load(); _, ok := citizenships[w]; return ok }
func IsIssuerWord(w string) bool  { load(); _, ok := issuerWords[w]; return ok }
func IsStopWord(w string) bool    { load(); _, ok := stopWords[w]; return ok }
func IsOrgWord(w string) bool     { load(); _, ok := orgWords[w]; return ok }

// IsBankPlace reports whether a toponym belongs to the bank's own premises,
// which must not be masked as a client address.
func IsBankPlace(w string) bool { load(); _, ok := bankPlaces[w]; return ok }

// Month returns the 1-based month number for a Russian month name in any
// common case form ("января", "январь", "янв").
func Month(w string) (int, bool) { load(); n, ok := months[w]; return n, ok }

// Ordinal returns the number written as a Russian word ("двенадцатое" -> 12).
func Ordinal(w string) (int, bool) { load(); n, ok := ordinals[w]; return n, ok }

// IsPatronymic recognises a patronymic either from the explicit list or from
// its morphology, which is highly regular in Russian.
func IsPatronymic(w string) bool {
	load()
	if _, ok := patronymics[w]; ok {
		return true
	}
	for _, suf := range patronymicSuffixes {
		if strings.HasSuffix(w, suf) && len([]rune(w)) >= len([]rune(suf))+3 {
			return true
		}
	}
	return false
}

var patronymicSuffixes = []string{
	"ович", "евич", "ьевич", "иевич", "инич", "овна", "евна", "ьевна",
	"иевна", "ична", "инична", "оглы", "кызы", "угли",
}

// IsFamousPerson reports whether a full name (space-separated, lowercased)
// names a public figure whose mention is not personal data — the Pushkin case
// called out in the specification.
func IsFamousPerson(fullLower string) bool {
	load()
	if _, ok := famous[fullLower]; ok {
		return true
	}
	// A single surname from the famous list also counts.
	if !strings.ContainsRune(fullLower, ' ') {
		_, ok := famousLast[fullLower]
		return ok
	}
	return false
}

// IsFamousWord reports whether w is one word of some public figure's name.
// A detector uses it to normalise an inflected word ("пушкина" -> "пушкин")
// before handing a whole phrase to IsFamousNameSet; on its own the answer is
// far too weak to veto anything, because it includes ordinary given names.
func IsFamousWord(w string) bool { load(); _, ok := famousWords[w]; return ok }

// IsFamousNameSet reports whether words are exactly the words of one entry in
// the famous-people list, in any order.
//
// Order-insensitivity is the point: the list stores "имя отчество фамилия",
// while Russian documents and headlines just as often write "фамилия имя
// отчество". Matching the literal phrase missed every reversed mention, so
// "Пушкин Александр Сергеевич" was masked as a client — the exact false
// positive the specification names. The caller is responsible for lowercasing
// and for trimming case endings; this only compares word sets.
func IsFamousNameSet(words []string) bool {
	if len(words) < 2 {
		return false // a lone surname is IsFamousPerson's business, not this
	}
	load()
	_, ok := famousSets[sortedKey(words)]
	return ok
}

// LooksLikeSurname applies Russian surname morphology for names that are not
// in the list. Used only as a weak signal, always combined with context.
func LooksLikeSurname(w string) bool {
	if len([]rune(w)) < 4 {
		return false
	}
	if IsStopWord(w) || IsFirstName(w) || IsCity(w) {
		return false
	}
	for _, suf := range surnameSuffixes {
		if strings.HasSuffix(w, suf) {
			return true
		}
	}
	return false
}

var surnameSuffixes = []string{
	"ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "ская", "цкая",
	"ова", "ева", "ёва", "ина", "ына", "ко", "ук", "юк", "швили", "дзе",
	"ян", "енко", "чук", "ых", "их",
}

// Stats reports dictionary sizes; used by /admin/config for observability.
func Stats() map[string]int {
	load()
	return map[string]int{
		"city_forms":   len(cityForms),
		"first_names":  len(firstNames),
		"surnames":     len(surnames),
		"patronymics":  len(patronymics),
		"latin_names":  len(latinNames),
		"cities":       len(cities),
		"street_types": len(streetTypes),
		"countries":    len(countries),
		"citizenships": len(citizenships),
		"issuer_words": len(issuerWords),
		"famous":       len(famous),
		"stop_words":   len(stopWords),
		"bank_places":  len(bankPlaces),
		"org_words":    len(orgWords),
		"months":       len(months),
		"ordinals":     len(ordinals),
	}
}
