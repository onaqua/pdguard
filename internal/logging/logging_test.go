package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// newTestLogger builds a logger with the same scrubbing wrapper that Setup
// installs, but writing into a buffer so a test can assert on the bytes that
// would have gone to stderr.
func newTestLogger(buf *bytes.Buffer) *slog.Logger { return newTestLogger2(buf) }

// newTestLogger2 is the same for any writer, so that the concurrency test can
// serialise writes through its own lock.
func newTestLogger2(w io.Writer) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// Drop the timestamp so that two records built from the same input
		// compare byte for byte.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return slog.New(&scrubHandler{inner: h})
}

// secrets is the set of values that must never be reconstructible from a log
// record, whatever a careless call site does with them. Every case in this
// file is checked against all of them.
var secrets = []string{
	"Иванов Иван Иванович",
	"4509 123456",
	"4276 3801 2345 6789",
	"+7 916 123-45-67",
	"ivanov.ivan@example.com",
	"770708-1234",
	"123456789012",
}

// reNoise strips the two fields that legitimately contain arbitrary hex and
// digits — the record timestamp and our own fingerprints — so that the
// fragment checks below cannot false-positive on them.
var reNoise = regexp.MustCompile(`"time":"[^"]*"|fp=[0-9a-f]+|"fp":"[0-9a-f]+"`)

func assertNoSecrets(t *testing.T, out string) {
	t.Helper()
	out = reNoise.ReplaceAllString(out, "")
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("log output leaked a protected value %q\noutput: %s", s, out)
		}
	}
	// Fragments matter as much as whole values: a partially scrubbed card
	// number is still a card number.
	for _, frag := range []string{"Иванович", "Иванов", "3801", "1234567", "@example.com"} {
		if strings.Contains(out, frag) {
			t.Fatalf("log output leaked fragment %q\noutput: %s", frag, out)
		}
	}
}

// TestUnsafeKeyNeverLeaks is the core compliance test: someone logs the whole
// payload under an arbitrary key, and nothing recognisable comes out.
func TestUnsafeKeyNeverLeaks(t *testing.T) {
	payload := "Клиент Иванов Иван Иванович, паспорт 4509 123456, " +
		"карта 4276 3801 2345 6789, телефон +7 916 123-45-67, " +
		"почта ivanov.ivan@example.com"

	var buf bytes.Buffer
	l := newTestLogger(&buf)
	l.Info("processing", "payload", payload)
	l.Info("processing", "text", "Иванов Иван Иванович")
	l.Info("processing", "raw", "4276 3801 2345 6789")
	l.Error("parse failed", "err", "invalid input \"+7 916 123-45-67\"")
	l.Info("nested", slog.Group("ctx", slog.String("body", payload)))
	l.With("payload", payload).Info("bound")
	l.WithGroup("g").Info("grouped", "payload", payload)
	l.Info("in message: " + payload)

	assertNoSecrets(t, buf.String())
	if !strings.Contains(buf.String(), "redacted") {
		t.Fatalf("expected redaction markers in output: %s", buf.String())
	}
}

// TestSafeKeysSurvive guards the other half of the contract: the whitelist
// must keep the operational fields readable, or the logs become useless.
func TestSafeKeysSurvive(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	attrs := RequestAttrs("req-42-ABC", "alfa-chat", "mask", 1024)
	l.LogAttrs(context.Background(), slog.LevelInfo, "request",
		append(attrs, Types(map[string]int{"FIO": 2, "PHONE": 1}))...)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	if rec["payload_id"] != "req-42-ABC" {
		t.Fatalf("payload_id was mangled: %v", rec["payload_id"])
	}
	if rec["system"] != "alfa-chat" || rec["op"] != "mask" {
		t.Fatalf("safe fields were mangled: %v", rec)
	}
	if rec["bytes_in"] != float64(1024) {
		t.Fatalf("bytes_in was mangled: %v", rec["bytes_in"])
	}
	types, ok := rec["types"].(map[string]any)
	if !ok {
		t.Fatalf("types is not a group: %v", rec["types"])
	}
	if types["FIO"] != float64(2) || types["PHONE"] != float64(1) {
		t.Fatalf("type counts were mangled: %v", types)
	}
}

// TestTypesIsDeterministic: identical inputs must produce identical records so
// that logs can be diffed between runs.
func TestTypesIsDeterministic(t *testing.T) {
	counts := map[string]int{"PHONE": 1, "FIO": 2, "EMAIL": 3}
	var first string
	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		newTestLogger(&buf).LogAttrs(context.Background(), slog.LevelInfo, "m", Types(counts))
		got := buf.String()
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("Types output is not stable:\n%s\n%s", first, got)
		}
	}
	var buf bytes.Buffer
	newTestLogger(&buf).LogAttrs(context.Background(), slog.LevelInfo, "m", Types(nil))
	if strings.Contains(buf.String(), "null") {
		t.Fatalf("empty Types should render as an empty value: %s", buf.String())
	}
}

func TestSafeHidesValueButKeepsLength(t *testing.T) {
	const value = "Иванов Иван Иванович"

	var buf bytes.Buffer
	newTestLogger(&buf).LogAttrs(context.Background(), slog.LevelInfo, "m", Safe("fio", value))
	out := buf.String()
	assertNoSecrets(t, out)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, out)
	}
	g, ok := rec["fio"].(map[string]any)
	if !ok {
		t.Fatalf("Safe did not produce a group: %v", rec["fio"])
	}
	// 20 runes, not 37 bytes: Cyrillic must be counted in runes.
	if g["len"] != float64(20) {
		t.Fatalf("Safe reported len=%v, want 20", g["len"])
	}
	fp, _ := g["fp"].(string)
	if fp != Fingerprint(value) {
		t.Fatalf("Safe reported fp=%q, want %q", fp, Fingerprint(value))
	}
	if len(fp) != 8 {
		t.Fatalf("fingerprint length is %d, want 8", len(fp))
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("+7 916 123-45-67")
	if a != Fingerprint("+7 916 123-45-67") {
		t.Fatal("Fingerprint is not deterministic within one process")
	}
	if a == Fingerprint("+7 916 123-45-68") {
		t.Fatal("Fingerprint collided on values differing by one digit")
	}
	if strings.Contains(a, "916") {
		t.Fatalf("fingerprint echoes the input: %q", a)
	}
	seen := map[string]string{}
	for _, s := range secrets {
		fp := Fingerprint(s)
		if prev, dup := seen[fp]; dup {
			t.Fatalf("fingerprint collision between %q and %q", prev, s)
		}
		seen[fp] = s
	}
	// The salt is per-run, so a fingerprint must not equal the unsalted
	// digest that an attacker could precompute.
	if Fingerprint("") == "e3b0c442" {
		t.Fatal("Fingerprint is unsalted")
	}
}

func TestScrub(t *testing.T) {
	cases := []struct {
		in       string
		mustNot  []string
		mustHave string
	}{
		{"телефон +7 916 123-45-67 клиента", []string{"916", "123-45-67"}, "redacted"},
		{"звоните 8 (916) 123-45-67", []string{"916"}, "redacted"},
		{"почта ivanov.ivan@example.com уже занята", []string{"ivanov", "example.com"}, "[email redacted]"},
		{"паспорт 4509 123456", []string{"123456"}, "[digits:6 redacted]"},
		{"счёт 40817810099910004312", []string{"40817810099910004312"}, "redacted"},
		{"СНИЛС 112-233-445 95", []string{"112-233"}, "[digits:11 redacted]"}, // grouped digits count too
		{"обычный текст без ПД", []string{}, "обычный текст без ПД"},
		{"дом 12, кв. 5", []string{}, "дом 12, кв. 5"},
	}
	for _, c := range cases {
		got := Scrub(c.in)
		for _, bad := range c.mustNot {
			if strings.Contains(got, bad) {
				t.Errorf("Scrub(%q) = %q, still contains %q", c.in, got, bad)
			}
		}
		if !strings.Contains(got, c.mustHave) {
			t.Errorf("Scrub(%q) = %q, want it to contain %q", c.in, got, c.mustHave)
		}
	}
	if Scrub("") != "" {
		t.Error("Scrub(\"\") must stay empty")
	}
}

func TestLooksSensitive(t *testing.T) {
	sensitive := []string{
		"Иванов Иван Иванович",
		"Ivan Ivanov",
		"карта 4276",
		strings.Repeat("a", FreeTextLimit+1),
	}
	for _, s := range sensitive {
		if !looksSensitive(s) {
			t.Errorf("looksSensitive(%q) = false, want true", s)
		}
	}
	benign := []string{
		"ok",
		"timeout waiting for store",
		"дом 12",
		"strategy stars_keep2 applied",
	}
	for _, s := range benign {
		if looksSensitive(s) {
			t.Errorf("looksSensitive(%q) = true, want false", s)
		}
	}
}

func TestSetupAndL(t *testing.T) {
	if L() == nil {
		t.Fatal("L() returned nil before Setup")
	}
	for _, format := range []string{"json", "text", "weird"} {
		for _, level := range []string{"debug", "info", "warn", "error", "nonsense"} {
			Setup(level, format)
			if L() == nil {
				t.Fatalf("L() nil after Setup(%q, %q)", level, format)
			}
		}
	}
	Setup("debug", "json")
	if !L().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug level was not applied")
	}
	Setup("error", "json")
	if L().Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("error level did not suppress info")
	}
	Setup("info", "text") // restore a sane default for the rest of the suite
}

func TestSampling(t *testing.T) {
	SetSampling(1)
	for i := 0; i < 5; i++ {
		if !ShouldSample() {
			t.Fatal("sampling of 1 must let everything through")
		}
	}
	SetSampling(0) // invalid values must not disable logging entirely
	if !ShouldSample() {
		t.Fatal("SetSampling(0) must behave like 1")
	}
	SetSampling(4)
	hits := 0
	for i := 0; i < 400; i++ {
		if ShouldSample() {
			hits++
		}
	}
	if hits != 100 {
		t.Fatalf("sampling every 4th of 400 gave %d hits, want 100", hits)
	}
	SetSampling(1)
}

// TestConcurrentLoggingIsRaceFree exercises the atomic logger swap, the
// sampling counter and the scrubbing handler from many goroutines at once;
// run with -race this is the proof that no shared mutable state was missed.
func TestConcurrentLoggingIsRaceFree(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	l := newTestLogger2(&lockedWriter{mu: &mu, buf: &buf})

	SetSampling(3)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if ShouldSample() {
					l.Info("work", "payload", secrets[j%len(secrets)],
						"payload_id", "id", "count", j)
				}
				_ = Fingerprint(secrets[j%len(secrets)])
				_ = L()
			}
		}(i)
	}
	// Concurrently reconfigure the process logger: Setup races with L().
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			Setup("info", "json")
		}
	}()
	wg.Wait()
	SetSampling(1)
	Setup("info", "text")

	mu.Lock()
	defer mu.Unlock()
	assertNoSecrets(t, buf.String())
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func BenchmarkFingerprint(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Fingerprint("Иванов Иван Иванович")
	}
}

func BenchmarkScrubClean(b *testing.B) {
	const s = "mask applied, strategy stars_keep2"
	for i := 0; i < b.N; i++ {
		_ = Scrub(s)
	}
}
