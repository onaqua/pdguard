// Package text provides byte-offset-preserving primitives shared by all
// detectors: a length-stable lowercase, a single-pass tokenizer and small
// classification helpers. Every function here is allocation-conscious because
// it sits on the hot path of a 1000 RPS service.
package text

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// TokenKind classifies a token produced by Tokenize.
type TokenKind uint8

const (
	KindSpace  TokenKind = iota
	KindWord             // letters (Cyrillic or Latin), possibly with internal apostrophe/hyphen
	KindNumber           // digits only
	KindAlnum            // mixed letters+digits, e.g. "AB1234"
	KindPunct
)

// Token is a half-open byte range over the source string.
type Token struct {
	Start int
	End   int
	Kind  TokenKind
}

// Len returns the token's length in bytes.
func (t Token) Len() int { return t.End - t.Start }

// In returns the token's text from the source it was produced from.
func (t Token) In(s string) string { return s[t.Start:t.End] }

// SafeLower lowercases s while guaranteeing the result has exactly the same
// byte length, so an offset found in the lowered string is valid in the
// original. Runes whose lowercase form has a different UTF-8 width (a handful
// of Turkish/Greek/special cases) are left untouched — correctness of offsets
// matters more than lowering an exotic character.
func SafeLower(s string) string {
	ascii, hasUpper := scanASCII(s)
	if ascii {
		if !hasUpper {
			return s
		}
		return lowerASCII(s)
	}
	return lowerUnicode(s)
}

// scanASCII reports whether s is pure ASCII and whether it contains an
// uppercase letter.
func scanASCII(s string) (ascii, hasUpper bool) {
	ascii = true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			return false, false
		}
		if 'A' <= c && c <= 'Z' {
			hasUpper = true
		}
	}
	return ascii, hasUpper
}

// lowerASCII lower-cases a pure-ASCII string in place.
func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// lowerUnicode lower-cases s rune by rune, keeping the byte length stable.
func lowerUnicode(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		lr := unicode.ToLower(r)
		if utf8.RuneLen(lr) != utf8.RuneLen(r) { // keep offsets stable
			lr = r
		}
		sb.WriteRune(lr)
	}
	out := sb.String()
	if len(out) != len(s) { // defensive: never hand back shifted offsets
		return s
	}
	return out
}

// Tokenize splits s into tokens in a single pass. Adjacent runes of the same
// class are merged; a word that contains digits is reported as KindAlnum.
func Tokenize(s string) []Token {
	toks := make([]Token, 0, len(s)/4+8)
	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		start := i
		switch {
		case unicode.IsSpace(r):
			i = skipSpaceRun(s, i+size)
			toks = append(toks, Token{start, i, KindSpace})
		case isWordRune(r):
			var kind TokenKind
			i, kind = scanWordRun(s, i+size, r)
			toks = append(toks, Token{start, i, kind})
		default:
			i += size
			toks = append(toks, Token{start, i, KindPunct})
		}
	}
	return toks
}

// skipSpaceRun returns the offset just past the run of spaces starting at i.
func skipSpaceRun(s string, i int) int {
	for i < len(s) {
		r2, sz := utf8.DecodeRuneInString(s[i:])
		if !unicode.IsSpace(r2) {
			break
		}
		i += sz
	}
	return i
}

// scanWordRun returns the offset just past the word starting at i and its kind.
func scanWordRun(s string, i int, first rune) (int, TokenKind) {
	hasLetter, hasDigit := unicode.IsLetter(first), unicode.IsDigit(first)
	for i < len(s) {
		r2, sz := utf8.DecodeRuneInString(s[i:])
		if !isWordRune(r2) {
			break
		}
		if unicode.IsLetter(r2) {
			hasLetter = true
		}
		if unicode.IsDigit(r2) {
			hasDigit = true
		}
		i += sz
	}
	kind := KindWord
	switch {
	case hasLetter && hasDigit:
		kind = KindAlnum
	case hasDigit:
		kind = KindNumber
	}
	return i, kind
}

// IsCyrillicWord reports whether every letter in s is Cyrillic and s has at
// least one letter. Used to separate Russian names from Latin card holders.
func IsCyrillicWord(s string) bool {
	seen := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if !unicode.Is(unicode.Cyrillic, r) {
				return false
			}
			seen = true
		}
	}
	return seen
}

// IsLatinWord reports whether every letter in s is Latin and s has at least one.
func IsLatinWord(s string) bool {
	seen := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if !unicode.Is(unicode.Latin, r) {
				return false
			}
			seen = true
		}
	}
	return seen
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// IsUpperFirst reports whether the first rune of s is an uppercase letter.
func IsUpperFirst(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsUpper(r)
}

// DigitsOnly returns the digits of s, dropping every other byte. Used for
// checksum validation (Luhn, INN, SNILS) where separators are irrelevant.
func DigitsOnly(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b = append(b, s[i])
		}
	}
	return string(b)
}

// CountDigits returns how many ASCII digits s contains.
func CountDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

// IsBoundary reports whether the byte offset i in s sits on a token boundary,
// i.e. the neighbouring rune is not a letter or digit. Detectors use it to
// avoid matching inside a longer identifier.
func IsBoundary(s string, i int) bool {
	if i <= 0 || i >= len(s) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	rPrev, _ := utf8.DecodeLastRuneInString(s[:i])
	return !(isWordRune(r) && isWordRune(rPrev))
}

// ExpandWord grows [start,end) outwards to cover the full word it sits inside.
func ExpandWord(s string, start, end int) (int, int) {
	for start > 0 {
		r, sz := utf8.DecodeLastRuneInString(s[:start])
		if !isWordRune(r) {
			break
		}
		start -= sz
	}
	for end < len(s) {
		r, sz := utf8.DecodeRuneInString(s[end:])
		if !isWordRune(r) {
			break
		}
		end += sz
	}
	return start, end
}

// TrimSpanEdges shrinks [start,end) so it does not begin or end with a space
// or punctuation character. Returns ok=false when nothing is left.
func TrimSpanEdges(s string, start, end int) (int, int, bool) {
	for start < end {
		r, sz := utf8.DecodeRuneInString(s[start:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			break
		}
		start += sz
	}
	for end > start {
		r, sz := utf8.DecodeLastRuneInString(s[:end])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			break
		}
		end -= sz
	}
	return start, end, start < end
}
