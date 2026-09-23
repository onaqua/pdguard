package dict

import (
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// WHY IT EXISTS. The FIO detector used to recover a case ending the other way
// round: on every word of the payload it trimmed each of sixteen endings in
// turn and asked the dictionary about the stem and about four "restored"
// variants of it ("Андре" + "й"). Every one of those variants is a string
// concatenation, i.e. a heap allocation, and the per-detector benchmark
// charged fio 1252 allocations and 25 KB per 4 KiB payload — an order of
// magnitude worse than any other detector.
//
// The set of forms is finite and fully known before the first request, so it
// is expanded ONCE here and the hot path does one map lookup instead of ~50
// lookups and ~10 allocations. This is the same trade that inflect.go makes
// for city names: memory is the cheap resource in this service, per-request
// CPU is not.
//
// The expansion is the exact inverse of the trimming it replaces, so recall is
// unchanged by construction: a word w was accepted iff w, or w minus one case
// ending, or that stem plus one restored tail, is a dictionary entry — which is
// exactly the set {d} ∪ {d+e} ∪ {d-tail+e} generated below.

// NameForm is a bitmask of the roles one written word form can play in a
// Russian personal name. A single form often has several: "иванова" is both a
// surname and an oblique form of one.
type NameForm uint8

// The roles a name form can carry.
const (
	NameFirst      NameForm = 1 << iota // a given name ("Ивану")
	NameSurname                         // a surname ("Иванову")
	NamePatronymic                      // a patronymic ("Ивановичу")
)

// nameMinStemRunes is the shortest stem the detector is willing to trim down
// to. Below it a case ending eats the word itself and any three-letter
// fragment would match something.
const nameMinStemRunes = 3

// fluentVowelStems maps given names with a fluent vowel onto their oblique
// stem. The regular case-ending expansion would produce "лева"/"павела",
// which are not the real oblique forms: "лев" drops the "е" in "льва",
// "льву", "львом", "льве", and "павел" drops it in "павла", "павлу",
// "павлом", "павле". The stem is declined with the same endings as the
// nominative, so the oblique forms come out right.
var fluentVowelStems = map[string]string{
	"лев":   "льв",
	"павел": "павл",
}

var (
	nameCaseEndings = []string{
		"ами", "ой", "ом", "ем", "ым", "ей", "ах", "ам", "ья",
		"а", "у", "е", "ы", "и", "ю", "я",
	}
	nameRestoreTails = []string{"й", "ь", "я", "а"}

	// Patronymics take a narrower set: trimming a final "я" the way a given
	// name allows turns ordinary adjectives into patronymic stems.
	patronymicCaseEndings = []string{"ой", "ом", "ем", "ым", "а", "у", "е", "ы", "и"}
	patronymicRestoreTail = []string{"а"}
)

var (
	// nameForms maps every generated form to the roles it can play.
	nameForms map[string]NameForm

	// famousWordForms maps an inflected word of a public figure's name onto
	// the nominative form the famous list stores ("пушкина" -> "пушкин").
	famousWordForms map[string]string

	// famousSurnameForms holds the inflected forms of the surnames that alone
	// identify a public figure.
	famousSurnameForms set

	// famousSetsN is famousSets keyed by a fixed-size array instead of a
	// joined string, so a lookup builds nothing.
	famousSetsN map[[FamousSetMaxWords]string]struct{}

	// patShapes and patRestoreShapes carry patronymicSuffixes ready for a
	// length-checked suffix test; see patronymicShape.
	patShapes        []patShape
	patRestoreShapes []patShape

	// surnameShapeByLast buckets surnameSuffixes by their final byte, so a
	// word whose last byte no surname ending uses is rejected without a single
	// string comparison. See SurnameShape.
	surnameShapeByLast [256][]string
)

// patShape is one patronymic suffix together with the shortest word it may
// terminate. dict.IsPatronymic demands three runes of stem in front of the
// suffix; precomputing the total spares a RuneCount per candidate.
type patShape struct {
	suf      string
	minRunes int
}

// namesOnce guards the expansion. It is separate from dict's own load() so
// that this file can be added without touching dict.go; loadNames runs load()
// first because every table below is derived from the raw lists.
var namesOnce sync.Once

// loadNames makes the indexes in this file available.
func loadNames() {
	load()
	namesOnce.Do(buildNameForms)
}

func buildNameForms() {
	m := make(map[string]NameForm, (len(firstNames)+len(surnames))*34+len(patronymics)*20)
	addNameForms(m, firstNames, NameFirst, nameCaseEndings, nameRestoreTails)
	addNameForms(m, surnames, NameSurname, nameCaseEndings, nameRestoreTails)
	addNameForms(m, patronymics, NamePatronymic, patronymicCaseEndings, patronymicRestoreTail)
	nameForms = m

	buildPatronymicShapes()
	buildSurnameShapes()
	buildFamousForms()
}

// addNameForms indexes every written form of every entry of src under bit.
func addNameForms(m map[string]NameForm, src set, bit NameForm, endings, restores []string) {
	for w := range src {
		m[w] |= bit
		if utf8.RuneCountInString(w) >= nameMinStemRunes {
			for _, e := range endings {
				m[w+e] |= bit
			}
		}
		addRestoredForms(m, w, bit, endings, restores)
		if stem, ok := fluentVowelStems[w]; ok {
			for _, e := range endings {
				m[stem+e] |= bit
			}
		}
	}
}

// addRestoredForms indexes the oblique forms reached by dropping a nominative
// tail ("Андрей" -> "Андрея") and appending each case ending.
func addRestoredForms(m map[string]NameForm, w string, bit NameForm, endings, restores []string) {
	for _, tail := range restores {
		if !strings.HasSuffix(w, tail) {
			continue
		}
		stem := w[:len(w)-len(tail)]
		if utf8.RuneCountInString(stem) < nameMinStemRunes {
			continue
		}
		for _, e := range endings {
			m[stem+e] |= bit
		}
	}
}

// buildSurnameShapes buckets the surname endings by their last byte.
func buildSurnameShapes() {
	for _, suf := range surnameSuffixes {
		b := suf[len(suf)-1]
		surnameShapeByLast[b] = append(surnameShapeByLast[b], suf)
	}
}

// SurnameShape is the morphological half of LooksLikeSurname: w is long enough
// and carries a Russian surname ending, with no dictionary lookup at all.
//
// It exists to stand in front of LooksLikeSurname on the request path. That
// function asks the stop-word, given-name and city lists before it looks at
// the ending, which means three string hashes for every word of the payload,
// while the ending alone settles the answer for the overwhelming majority of
// them. The two together return exactly what LooksLikeSurname returns alone.
func SurnameShape(w string) bool {
	loadNames()
	if len(w) < 4 {
		return false
	}
	for _, suf := range surnameShapeByLast[w[len(w)-1]] {
		if strings.HasSuffix(w, suf) {
			return utf8.RuneCountInString(w) >= 4
		}
	}
	return false
}

func buildPatronymicShapes() {
	patShapes = make([]patShape, 0, len(patronymicSuffixes))
	patRestoreShapes = make([]patShape, 0, len(patronymicSuffixes))
	for _, suf := range patronymicSuffixes {
		n := utf8.RuneCountInString(suf)
		patShapes = append(patShapes, patShape{suf: suf, minRunes: n + 3})
		// The feminine forms are reached through the restored "-а": a stem
		// "ивановн" stands for "ивановна". Dropping the "а" from the suffix
		// lets the same test run against the stem with no concatenation, and
		// the length bound shifts by exactly one rune in both directions.
		if strings.HasSuffix(suf, "а") {
			cut := suf[:len(suf)-len("а")]
			patRestoreShapes = append(patRestoreShapes, patShape{suf: cut, minRunes: n + 2})
		}
	}
}

func patronymicShapeForm(w string) bool {
	if !hasPatronymicMarker(w) {
		return false
	}
	if patronymicShape(w, patShapes) {
		return true
	}
	for _, e := range patronymicCaseEndings {
		if !strings.HasSuffix(w, e) {
			continue
		}
		stem := w[:len(w)-len(e)]
		if utf8.RuneCountInString(stem) < nameMinStemRunes {
			continue
		}
		if patronymicShape(stem, patShapes) || patronymicShape(stem, patRestoreShapes) {
			return true
		}
	}
	return false
}

// hasPatronymicMarker is the cheap prefilter in front of patronymicShapeForm.
// "ич" covers -ович/-евич/-ьевич/-иевич/-инич, "вн" the -овна family, "чн"
// -ична/-инична, and "гл"/"зы" the Turkic -оглы/-угли/-кызы.
func hasPatronymicMarker(w string) bool {
	return strings.Contains(w, "ич") || strings.Contains(w, "вн") ||
		strings.Contains(w, "чн") || strings.Contains(w, "гл") ||
		strings.Contains(w, "зы")
}

func patronymicShape(w string, shapes []patShape) bool {
	for _, s := range shapes {
		if strings.HasSuffix(w, s.suf) && utf8.RuneCountInString(w) >= s.minRunes {
			return true
		}
	}
	return false
}

// buildFamousForms expands the public-figure vocabulary the FIO detector
// normalises against, and rebuilds the full-name set under an array key.
//
// Insertion runs in three passes over a sorted word list so the canonical form
// chosen for an ambiguous inflection is deterministic across processes: the
// word as written wins over any stem derived from another word.
func buildFamousForms() {
	words := sortedFamousWords()
	buildFamousWordForms(words)
	buildFamousSurnameForms()
	buildFamousSetsN()
}

// sortedFamousWords returns the famous vocabulary as a sorted slice, so the
// canonical form chosen for an ambiguous inflection is deterministic.
func sortedFamousWords() []string {
	words := make([]string, 0, len(famousWords))
	for w := range famousWords {
		words = append(words, w)
	}
	sort.Strings(words)
	return words
}

// buildFamousWordForms maps every inflected word of the famous vocabulary onto
// its nominative form ("пушкина" -> "пушкин").
func buildFamousWordForms(words []string) {
	famousWordForms = make(map[string]string, len(words)*20)
	for _, w := range words {
		famousWordForms[w] = w
	}
	for _, w := range words {
		if utf8.RuneCountInString(w) < nameMinStemRunes {
			continue
		}
		for _, e := range nameCaseEndings {
			addIfAbsent(famousWordForms, w+e, w)
		}
	}
	for _, w := range words {
		addRestoredWordForms(famousWordForms, w)
	}
}

// addRestoredWordForms maps the oblique forms of w reached by dropping a
// nominative tail ("Андрей" -> "Андрея") onto w.
func addRestoredWordForms(m map[string]string, w string) {
	for _, tail := range nameRestoreTails {
		if !strings.HasSuffix(w, tail) {
			continue
		}
		stem := w[:len(w)-len(tail)]
		if utf8.RuneCountInString(stem) < nameMinStemRunes {
			continue
		}
		for _, e := range nameCaseEndings {
			addIfAbsent(m, stem+e, w)
		}
	}
}

// buildFamousSurnameForms indexes the inflected forms of the surnames that
// alone identify a public figure.
func buildFamousSurnameForms() {
	famousSurnameForms = make(set, len(famousLast)*34)
	src := make(set, len(famousLast)+len(famous))
	for w := range famousLast {
		src[w] = struct{}{}
	}
	// A one-word entry in the famous list is answered by IsFamousPerson
	// directly, so its forms belong here too.
	for w := range famous {
		if !strings.ContainsRune(w, ' ') {
			src[w] = struct{}{}
		}
	}
	for w := range src {
		famousSurnameForms[w] = struct{}{}
		if utf8.RuneCountInString(w) >= nameMinStemRunes {
			for _, e := range nameCaseEndings {
				famousSurnameForms[w+e] = struct{}{}
			}
		}
		addRestoredSurnameForms(w)
	}
}

// addRestoredSurnameForms indexes the oblique forms of a famous surname word
// reached by dropping a nominative tail.
func addRestoredSurnameForms(w string) {
	for _, tail := range nameRestoreTails {
		if !strings.HasSuffix(w, tail) {
			continue
		}
		stem := w[:len(w)-len(tail)]
		if utf8.RuneCountInString(stem) < nameMinStemRunes {
			continue
		}
		for _, e := range nameCaseEndings {
			famousSurnameForms[stem+e] = struct{}{}
		}
	}
}

// buildFamousSetsN rebuilds the full-name set under an array key.
func buildFamousSetsN() {
	famousSetsN = make(map[[FamousSetMaxWords]string]struct{}, len(famous))
	for full := range famous {
		parts := strings.Fields(full)
		if len(parts) < 2 || len(parts) > FamousSetMaxWords {
			continue
		}
		var key [FamousSetMaxWords]string
		copy(key[:], parts)
		sort.Strings(key[:len(parts)])
		famousSetsN[key] = struct{}{}
	}
}

func addIfAbsent(m map[string]string, key, val string) {
	if _, ok := m[key]; !ok {
		m[key] = val
	}
}

// ---- lookups. All take an ALREADY-LOWERCASED word. ----

// NameForms reports every personal-name role the written form w can play,
// oblique cases included. One hash lookup plus, for words that could be
// patronymics, a cheap suffix test; it allocates nothing.
//
// Prefer it over three separate calls: the bitmask is what the FIO detector
// caches per token, and folding the three questions into one lookup removes
// two string hashes per word of the payload.
func NameForms(w string) NameForm {
	loadNames()
	f := nameForms[w]
	if f&NamePatronymic == 0 && patronymicShapeForm(w) {
		f |= NamePatronymic
	}
	return f
}

// IsFirstNameForm reports whether w is a given name in any common case form.
func IsFirstNameForm(w string) bool { return NameForms(w)&NameFirst != 0 }

// IsSurnameForm reports whether w is a DICTIONARY surname in any common case
// form. It says nothing about surname morphology — LooksLikeSurname owns that
// question, and the two are deliberately kept apart: a dictionary hit is
// trustworthy on its own, a morphological one never is.
func IsSurnameForm(w string) bool { return NameForms(w)&NameSurname != 0 }

// IsPatronymicForm reports whether w is a patronymic in any common case form,
// from the list or from the productive "-ович/-евна" morphology.
func IsPatronymicForm(w string) bool { return NameForms(w)&NamePatronymic != 0 }

// FamousWordForm maps an inflected word onto the nominative form the
// famous-people list stores ("пушкина" -> "пушкин"), reporting false when no
// case form of the word appears in a public figure's name at all.
//
// On its own the answer proves nothing — the list's words include ordinary
// given names — it only normalises a phrase before FamousNameSet judges it.
func FamousWordForm(w string) (string, bool) {
	loadNames()
	s, ok := famousWordForms[w]
	return s, ok
}

// IsFamousSurnameForm reports whether w, in any common case form, is a surname
// that identifies a public figure on its own ("пушкина" -> Пушкин).
func IsFamousSurnameForm(w string) bool {
	loadNames()
	_, ok := famousSurnameForms[w]
	return ok
}

// FamousSetMaxWords is the longest public figure's name the array-keyed set
// can hold. Every entry in the list is a two- or three-part name.
const FamousSetMaxWords = 4

// FamousNameSet reports whether words are exactly the words of one entry in
// the famous-people list, in any order.
//
// It is IsFamousNameSet without the joined key, so it can run on the request
// path: the words are copied into a fixed-size array, which Go hashes directly.
// The caller passes already-lowercased words normalised by FamousWordForm, and
// MAY pass them in any order — the array is sorted here.
func FamousNameSet(words []string) bool {
	if len(words) < 2 || len(words) > FamousSetMaxWords {
		return false
	}
	loadNames()
	var key [FamousSetMaxWords]string
	copy(key[:], words)
	sort.Strings(key[:len(words)])
	_, ok := famousSetsN[key]
	return ok
}

// WarmNames builds the indexes in this file ahead of time.
//
// Expanding them takes about ten milliseconds, which is nothing against the
// life of the process but is a visible spike on whichever request happens to
// arrive first. Callers that know when the quiet moment is — a server during
// start-up — should spend it there instead.
func WarmNames() { loadNames() }

// NameStats reports the size of the indexes in this file, for /admin/config.
func NameStats() map[string]int {
	loadNames()
	return map[string]int{
		"name_forms":           len(nameForms),
		"famous_word_forms":    len(famousWordForms),
		"famous_surname_forms": len(famousSurnameForms),
	}
}
