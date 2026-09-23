package dict

import "strings"

var cityForms set

func buildCityForms() {
	cityForms = make(set, len(cities)*5)
	for c := range cities {
		cityForms[c] = struct{}{}
		for _, f := range toponymForms(c) {
			if isCityFormCandidate(f, c) {
				cityForms[f] = struct{}{}
			}
		}
	}
}

// isCityFormCandidate reports whether f is a usable oblique form of city c:
// non-empty, different from the nominative, and not colliding with a surname,
// given name or stop word.
func isCityFormCandidate(f, c string) bool {
	if f == "" || f == c {
		return false
	}
	if _, bad := surnames[f]; bad {
		return false
	}
	if _, bad := firstNames[f]; bad {
		return false
	}
	if _, bad := stopWords[f]; bad {
		return false
	}
	return true
}

func splitLastComponent(name string) (head, tail string) {
	i := strings.LastIndexAny(name, " -")
	if i < 0 {
		return "", name
	}
	return name[:i+1], name[i+1:]
}

func toponymForms(name string) []string {
	head, tail := splitLastComponent(name)

	r := []rune(tail)
	if len(r) < 3 {
		return nil
	}
	stem := string(r[:len(r)-1])
	var endings []string

	switch r[len(r)-1] {
	case 'а':
		// Москва -> Москве, Москвы, Москву, Москвой
		endings = []string{"е", "ы", "у", "ой", "ою"}
	case 'я':
		// Анапа-like soft stems: Гвинея -> Гвинеи, Гвинее, Гвинею
		endings = []string{"и", "е", "ю", "ей"}
	case 'ь':
		// Казань -> Казани, Тверь -> Твери, Пермь -> Перми
		endings = []string{"и", "ью", "ей"}
	case 'о':
		// Иваново -> Иванове, Кемерово -> Кемерова. Formally declinable and
		// still common in written banking text, unlike in speech.
		endings = []string{"е", "а", "у", "ом"}
	case 'й':
		// Нижний -> Нижнем; the adjectival component of a compound name.
		endings = []string{"ем", "его", "ему", "им"}
		stem = string(r[:len(r)-2]) // drop the "ий"/"ый" pair
		if len(r) < 4 {
			return nil
		}
	case 'е', 'и', 'у', 'ю', 'ы', 'э':
		return nil // Сочи, Баку, Тбилиси: indeclinable
	default:
		// Consonant stem: Екатеринбург -> Екатеринбурге, Омск -> Омска
		stem = tail
		endings = []string{"е", "а", "у", "ом"}
	}

	out := make([]string, 0, len(endings)+1)
	for _, e := range endings {
		out = append(out, head+stem+e)
		if head != "" {
			out = append(out, stem+e)
		}
	}
	if head != "" {
		out = append(out, tail)
	}
	return out
}

// IsCityForm reports whether w — already lowercased — names a city in the
// nominative or in any common oblique case. Prefer it over IsCity anywhere the
// word comes from running text rather than from a structured address field.
func IsCityForm(w string) bool {
	load()
	_, ok := cityForms[w]
	return ok
}
