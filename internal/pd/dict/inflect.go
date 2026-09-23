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
		for _, f := range hyphenCityForms(c) {
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

	tailForms := singleWordForms(tail)
	if tailForms == nil {
		return nil
	}

	// A multi-word toponym ("нижний новгород") inflects BOTH words: the head
	// is an agreeing adjective ("нижнего новгорода", "нижнем новгороде") and
	// the tail a noun. The cross product covers every case combination the
	// running text can write. A head that is not an adjective ("сергиев посад")
	// stays fixed, which is the behaviour the single-word path already had.
	headForms := adjectiveForms(head)
	out := make([]string, 0, len(tailForms)*6+1)
	if headForms == nil {
		for _, tf := range tailForms {
			out = append(out, head+tf)
		}
	} else {
		for _, hf := range headForms {
			for _, tf := range tailForms {
				out = append(out, hf+" "+tf)
			}
		}
	}
	if head != "" {
		out = append(out, tailForms...)
		out = append(out, tail)
	}
	return out
}

// singleWordForms returns the oblique forms of a single-word toponym tail
// ("москва" -> "москве", "москвы", "москву", "москвой"), or nil when the word
// is indeclinable or too short to decline.
func singleWordForms(tail string) []string {
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

	out := make([]string, 0, len(endings))
	for _, e := range endings {
		out = append(out, stem+e)
	}
	return out
}

// hyphenCityForms returns the oblique forms of a hyphenated city ("ростов-на-дону").
// The first part declines as a noun; the tail is either a fixed "на-<river>"
// ("-на-Дону", "-на-Амуре") or an agreeing adjective ("-Камчатский",
// "-Уральский") that declines with it. The cross product covers every case the
// running text can write.
func hyphenCityForms(name string) []string {
	parts := strings.Split(name, "-")
	if len(parts) < 2 {
		return nil
	}
	headForms := singleWordForms(parts[0])
	if headForms == nil {
		return nil
	}
	rest := strings.Join(parts[1:], "-")
	var restForms []string
	if strings.HasPrefix(rest, "на-") {
		restForms = []string{rest}
	} else {
		restForms = hyphenAdjForms(rest)
		if restForms == nil {
			restForms = []string{rest}
		}
	}
	out := make([]string, 0, len(headForms)*len(restForms))
	for _, hf := range headForms {
		for _, rf := range restForms {
			out = append(out, hf+"-"+rf)
		}
	}
	return out
}

// hyphenAdjForms returns the inflected forms of an adjectival tail of a
// hyphenated city ("камчатский" -> "камчатского", "камчатскому",
// "камчатским", "камчатском"). It mirrors adjectiveForms but spells the
// genitive of a hard-stem adjective ("ский"/"цкий") with "ого" rather than the
// "его" a soft stem ("нижний") takes.
func hyphenAdjForms(tail string) []string {
	r := []rune(tail)
	n := len(r)
	if n < 3 {
		return nil
	}
	base := string(r[:n-2])
	switch {
	case strings.HasSuffix(tail, "ский"), strings.HasSuffix(tail, "цкий"):
		// камчатский -> камчатского, камчатскому, камчатским, камчатском
		return []string{tail, base + "ого", base + "ому", base + "им", base + "ом"}
	case strings.HasSuffix(tail, "ий"):
		// нижний -> нижнего, нижнему, нижним, нижнем
		return []string{tail, base + "его", base + "ему", base + "им", base + "ем"}
	case strings.HasSuffix(tail, "ый"), strings.HasSuffix(tail, "ой"):
		// старый -> старого, старому, старым, старом
		return []string{tail, base + "ого", base + "ому", base + "ым", base + "ом"}
	case strings.HasSuffix(tail, "ая"):
		// старая -> старой, старую
		return []string{tail, base + "ой", base + "ую"}
	case strings.HasSuffix(tail, "яя"):
		// верхняя -> верхней, верхнюю
		return []string{tail, base + "ей", base + "юю"}
	case strings.HasSuffix(tail, "ое"), strings.HasSuffix(tail, "ее"):
		// сибирское -> сибирского, сибирскому, сибирским, сибирском
		return []string{tail, base + "ого", base + "ому", base + "им", base + "ом"}
	default:
		return nil
	}
}

// adjectiveForms returns the inflected forms of an adjectival head of a
// multi-word toponym, or nil when the head is not an adjective. The head is
// passed with its trailing separator ("нижний "); the returned forms carry no
// separator so the caller can join them with a space.
func adjectiveForms(head string) []string {
	h := strings.TrimSpace(head)
	if h == "" {
		return nil
	}
	r := []rune(h)
	n := len(r)
	if n < 3 {
		return nil
	}
	base := string(r[:n-2])
	switch {
	case strings.HasSuffix(h, "ий"):
		// нижний -> нижнего, нижнему, нижним, нижнем
		return []string{h, base + "его", base + "ему", base + "им", base + "ем"}
	case strings.HasSuffix(h, "ый"), strings.HasSuffix(h, "ой"):
		// старый -> старого, старому, старым, старом
		return []string{h, base + "ого", base + "ому", base + "ым", base + "ом"}
	case strings.HasSuffix(h, "ая"):
		// старая -> старой, старую
		return []string{h, base + "ой", base + "ую"}
	case strings.HasSuffix(h, "яя"):
		// верхняя -> верхней, верхнюю
		return []string{h, base + "ей", base + "юю"}
	case strings.HasSuffix(h, "ие"):
		// великие -> великих, великим, великими
		return []string{h, base + "их", base + "им", base + "ими"}
	case strings.HasSuffix(h, "ые"):
		// набережные -> набережных, набережным, набережными
		return []string{h, base + "ых", base + "ым", base + "ыми"}
	default:
		return nil
	}
}

// IsCityForm reports whether w — already lowercased — names a city in the
// nominative or in any common oblique case. Prefer it over IsCity anywhere the
// word comes from running text rather than from a structured address field.
func IsCityForm(w string) bool {
	load()
	_, ok := cityForms[w]
	return ok
}
