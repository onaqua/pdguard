// Package logging provides the process logger and, more importantly, the
// guarantee that protected data never reaches a log record.
//
// The specification asks for detailed logging at every stage of the request
// and for the list of detected PD categories per request, while at the same
// time asking the reviewer to check that "the protected source data does not
// end up in logs and technical metrics". Those two requirements pull in
// opposite directions, so this package resolves them with one rule: a log
// record may carry categories, counts, lengths and fingerprints, never values.
//
// The rule is enforced mechanically rather than by convention. Every handler
// built here is wrapped in a scrubbing handler that inspects each attribute:
// keys on an explicit safe list pass through untouched, everything else is
// sanitised and — when it still has the shape of personal data — replaced by a
// length plus a salted fingerprint. A programmer who logs the payload by
// mistake therefore leaks nothing, which is exactly the failure mode the
// specification is looking for.
//
// L() is on the hot path (at least one record per request at a target of
// 1000 RPS), so the logger lives in an atomic.Pointer: readers take a
// lock-free snapshot and the rare Setup call swaps a fully built replacement.
package logging

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// FreeTextLimit is the longest free-form string that a non-whitelisted
// attribute may keep verbatim. Anything longer is assumed to be a payload
// fragment and is reduced to a length plus a fingerprint: a long unknown
// string has no debugging value that is worth the risk of leaking a document.
const FreeTextLimit = 64

// redactedSuffix is the closing marker every scrub replacement shares, so the
// operator can recognise a redacted value at a glance.
const redactedSuffix = " redacted]"

var safeKeys = map[string]bool{
	"payload_id":  true,
	"system":      true,
	"op":          true,
	"status":      true,
	"types":       true,
	"duration_ms": true,
	"bytes_in":    true,
	"bytes_out":   true,
	"count":       true,
	"detector":    true,
	"strategy":    true,
	"stage":       true,
	"error_kind":  true,
	"len":         true,
	"fp":          true,
	"redacted":    true,

	// Start-up and diagnostic keys. Their values come from the process
	// environment, never from a payload: a listen address is dotted digits
	// that trip the digit-run rule, a dictionary-size map and a goroutine
	// stack are both longer than FreeTextLimit, and all three were being
	// redacted into uselessness — a panic you cannot read the stack of is a
	// panic you cannot fix. Note what is NOT here: "path" and "panic" stay
	// scrubbed, because a URL and a panic value can both carry caller input.
	"addr":   true,
	"config": true,
	"dict":   true,
	"stack":  true,
}

// Patterns are compiled once at package level: Scrub runs inside the request
// path and compiling a regexp per call would dominate its cost.
//
// Order matters. Mail addresses are matched first because their local part
// often contains a long digit run that the digit rule would otherwise eat,
// producing a half-redacted address instead of a clean marker.
var (
	reEmail  = regexp.MustCompile(`[\p{L}0-9._%+\-]+@[\p{L}0-9.\-]+\.[\p{L}]{2,}`)
	rePhone  = regexp.MustCompile(`(?:\+7|\b8)[\s\-()]*\d[\d\s\-()]{7,}\d`)
	reGroups = regexp.MustCompile(`\b\d{3,4}(?:[ \-]\d{2,4}){1,}\b`)
	reDigits = regexp.MustCompile(`\d{6,}`)
	// Two or more adjacent capitalised words are the ФИО shape. Digits alone
	// would never catch "Иванов Иван Иванович", and a name is the single most
	// identifying value in the whole payload, so it gets its own rule.
	reNameRun = regexp.MustCompile(`\p{Lu}\p{L}+(?:[ .\x{00A0}]+\p{Lu}\p{L}+)+`)
)

var current atomic.Pointer[slog.Logger]

var salt = newSalt()

var (
	sampleEvery atomic.Int64
	sampleCount atomic.Uint64
)

func newSalt() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the platform has no usable entropy
		// source; continuing would silently weaken the fingerprint, so
		// refuse to start instead.
		panic("logging: cannot read random salt: " + err.Error())
	}
	return b
}

func init() {
	// A usable logger must exist before Setup runs, otherwise early start-up
	// failures would be logged through an unscrubbed default handler.
	Setup("info", "text")
}

// Setup configures the process-wide logger. format is "json" or "text";
// level is "debug", "info", "warn" or "error". Unknown values fall back to
// "text" and "info" rather than failing: losing a log line format is never a
// reason to refuse to start.
func Setup(level, format string) {
	SetupWriter(level, format, os.Stderr)
}

// SetupWriter configures the process-wide logger to write to w instead of
// stderr. It is a test hook: the engine and httpapi tests want to assert on
// the bytes the logger would have written without touching the real one.
func SetupWriter(level, format string, w io.Writer) {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	l := slog.New(&scrubHandler{inner: h})
	current.Store(l)
	slog.SetDefault(l)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// L returns the process logger. Never nil.
func L() *slog.Logger {
	if l := current.Load(); l != nil {
		return l
	}
	// Only reachable if a caller raced with package initialisation; build a
	// throwaway rather than returning nil to a caller that cannot check.
	return slog.New(&scrubHandler{inner: slog.NewTextHandler(os.Stderr, nil)})
}

// SetSampling makes high-volume debug records emit only every n-th time.
// n <= 1 disables sampling. Sampling is opt-in per call site through
// ShouldSample, so mandatory records (errors, per-request summaries) are never
// affected by it.
func SetSampling(n int) {
	if n < 1 {
		n = 1
	}
	sampleEvery.Store(int64(n))
}

// ShouldSample reports whether the calling site should emit its high-volume
// record this time. It is lock-free so that a debug log in a per-token loop
// costs one atomic increment when sampling is on.
func ShouldSample() bool {
	n := sampleEvery.Load()
	if n <= 1 {
		return true
	}
	return sampleCount.Add(1)%uint64(n) == 0
}

// Safe returns an attribute describing a protected value WITHOUT revealing
// it: only its length in runes and a short salted fingerprint. Length is
// counted in runes, not bytes, because Cyrillic text would otherwise report
// doubled sizes and mislead whoever reads the log.
func Safe(key, value string) slog.Attr {
	return slog.Group(key,
		slog.Int("len", utf8.RuneCountInString(value)),
		slog.String("fp", Fingerprint(value)),
	)
}

// Fingerprint returns a short, salted, non-reversible identifier for a
// protected value, stable within one process run. Use it to correlate log
// lines about the same value without ever printing it.
func Fingerprint(value string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(value))
	var sum [sha256.Size]byte
	return hex.EncodeToString(h.Sum(sum[:0])[:4])
}

// Types renders detected PD categories with per-category counts. Category
// names are safe to log; values are not, and never appear here. Categories are
// sorted so that two identical requests produce byte-identical records, which
// makes log diffing and golden tests possible.
func Types(counts map[string]int) slog.Attr {
	if len(counts) == 0 {
		return slog.String("types", "")
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := make([]any, 0, len(keys))
	for _, k := range keys {
		attrs = append(attrs, slog.Int(k, counts[k]))
	}
	return slog.Group("types", attrs...)
}

// RequestAttrs bundles the standard per-request fields. Returning a slice
// rather than a *slog.Logger lets the caller append stage-specific attributes
// without allocating a child logger per request.
func RequestAttrs(payloadID, system, op string, bytesIn int) []slog.Attr {
	return []slog.Attr{
		slog.String("payload_id", payloadID),
		slog.String("system", system),
		slog.String("op", op),
		slog.Int("bytes_in", bytesIn),
	}
}

// Scrub removes anything that looks like personal data from a free-form
// string before it reaches a log record. Used as a last line of defence on
// error messages coming from the standard library, which happily quote the
// offending input ("invalid character ... in \"79161234567\"").
//
// The replacement keeps the type and the length of what was removed, because
// those two facts are what an operator actually needs when debugging a parse
// failure, and neither of them identifies a person.
func Scrub(s string) string {
	if s == "" {
		return s
	}
	out := s
	if strings.ContainsRune(out, '@') {
		out = reEmail.ReplaceAllString(out, "[email redacted]")
	}
	out = rePhone.ReplaceAllStringFunc(out, func(m string) string {
		return "[phone:" + strconv.Itoa(countDigits(m)) + redactedSuffix
	})
	// Grouped digits go before the plain run: a card is written as four
	// groups of four, and "4276 3801 2345 6789" contains no run of six.
	out = reGroups.ReplaceAllStringFunc(out, func(m string) string {
		return "[digits:" + strconv.Itoa(countDigits(m)) + redactedSuffix
	})
	out = reDigits.ReplaceAllStringFunc(out, func(m string) string {
		return "[digits:" + strconv.Itoa(len(m)) + redactedSuffix
	})
	out = reNameRun.ReplaceAllString(out, "[name redacted]")
	return out
}

func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

// redactValue is the policy applied to every attribute whose key is not on the
// safe list. Scrub alone is not enough here: it knows nothing about names, and
// "Иванов Иван Иванович" is exactly the kind of value that must never appear.
// So a scrubbed value that still carries the shape of personal data — adjacent
// capitalised words, a group of four or more digits, or simply an unexpectedly
// long string — is dropped entirely in favour of a length and a fingerprint.
func redactValue(s string) string {
	if s == "" {
		return s
	}
	out := Scrub(s)
	if looksSensitive(out) {
		return "[redacted len=" + strconv.Itoa(utf8.RuneCountInString(s)) +
			" fp=" + Fingerprint(s) + "]"
	}
	return out
}

// looksSensitive reports whether a string still has the shape of personal data
// after scrubbing. It is deliberately trigger-happy: this is the logging path,
// where over-redacting costs a little debuggability and under-redacting costs
// a compliance failure. (The detection path, where false positives cost
// quality points, uses the pd packages instead — never this function.)
func looksSensitive(s string) bool {
	if utf8.RuneCountInString(s) > FreeTextLimit {
		return true
	}
	digits := 0
	capRun := 0  // consecutive capitalised words, the ФИО shape
	letters := 0 // letters in the current word
	upper := false
	inWord := false
	for _, r := range s {
		if sensitiveRune(r, &digits, &capRun, &letters, &upper, &inWord) {
			return true
		}
	}
	flushWord(&capRun, &inWord, &upper, &letters)
	return capRun >= 2
}

// sensitiveRune advances the state machine by one rune and reports whether the
// string has become sensitive.
func sensitiveRune(r rune, digits, capRun *int, letters *int, upper, inWord *bool) bool {
	switch {
	case unicode.IsDigit(r):
		flushWord(capRun, inWord, upper, letters)
		*digits++
		if *digits >= 4 {
			return true
		}
		*capRun = 0
	case unicode.IsLetter(r):
		*digits = 0
		if !*inWord {
			*inWord = true
			*upper = unicode.IsUpper(r)
		}
		*letters++
	default:
		flushWord(capRun, inWord, upper, letters)
		*digits = 0
		// A separator other than a single space or dot breaks the
		// name shape: "Иванов, Петров" is a list, not a full name.
		if r != ' ' && r != '.' && r != '\u00A0' {
			*capRun = 0
		}
	}
	return *capRun >= 2
}

// flushWord folds the current word into the capitalised-word run counter.
func flushWord(capRun *int, inWord *bool, upper *bool, letters *int) {
	if !*inWord {
		return
	}
	if *upper && *letters >= 2 {
		*capRun++
	} else {
		*capRun = 0
	}
	*inWord, *upper, *letters = false, false, 0
}

// scrubHandler wraps any slog.Handler and applies the whitelist policy to
// every attribute, including those attached earlier through With. It is the
// reason a leak cannot happen by accident: the policy lives in one place that
// every record must pass through, instead of at each of the dozens of call
// sites that build a log line.
type scrubHandler struct {
	inner slog.Handler
}

// Enabled delegates: level filtering is the wrapped handler's business.
func (h *scrubHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// Handle rebuilds the record with sanitised attributes. The message itself is
// scrubbed too, because fmt-formatted messages are the other common way an
// input string sneaks into a log line.
func (h *scrubHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, Scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

// WithAttrs sanitises the pre-bound attributes once, at binding time, so the
// cost is paid per logger rather than per record.
func (h *scrubHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	cp := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		cp[i] = scrubAttr(a)
	}
	return &scrubHandler{inner: h.inner.WithAttrs(cp)}
}

// WithGroup only forwards: grouping changes nesting, not safety.
func (h *scrubHandler) WithGroup(name string) slog.Handler {
	return &scrubHandler{inner: h.inner.WithGroup(name)}
}

// scrubAttr applies the policy to one attribute. Groups are walked so that a
// payload nested three levels deep is caught as well as a top-level one.
func scrubAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve() // a LogValuer may produce a string out of nowhere
	if v.Kind() == slog.KindGroup {
		if safeKeys[a.Key] {
			return slog.Attr{Key: a.Key, Value: v}
		}
		src := v.Group()
		cp := make([]slog.Attr, len(src))
		for i, g := range src {
			cp[i] = scrubAttr(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(cp...)}
	}
	if safeKeys[a.Key] {
		return slog.Attr{Key: a.Key, Value: v}
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redactValue(v.String()))
	case slog.KindAny:
		// errors and Stringers render as text downstream, so they have to
		// be inspected as text here. Numbers, times and bools cannot carry
		// a name or a document number and are left alone.
		s := fmt.Sprint(v.Any())
		if red := redactValue(s); red != s {
			return slog.String(a.Key, red)
		}
		return slog.Attr{Key: a.Key, Value: v}
	default:
		return slog.Attr{Key: a.Key, Value: v}
	}
}
