package metrics

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// scrape renders the registry and returns it as a string.
func scrape(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	WritePrometheus(&buf)
	return buf.String()
}

// seriesValue finds the exact series line "name{labels} value" and returns its
// value. Exact-prefix matching keeps _bucket from matching _bucket_count-style
// mistakes.
func seriesValue(t *testing.T, out, series string) float64 {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		sp := strings.LastIndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		if line[:sp] != series {
			continue
		}
		v, err := strconv.ParseFloat(line[sp+1:], 64)
		if err != nil {
			t.Fatalf("series %q has unparsable value %q: %v", series, line[sp+1:], err)
		}
		return v
	}
	t.Fatalf("series %q not found in:\n%s", series, out)
	return 0
}

func hasSeries(out, series string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if sp := strings.LastIndexByte(line, ' '); sp > 0 && line[:sp] == series {
			return true
		}
	}
	return false
}

func TestWritePrometheusHasAllRequiredSeries(t *testing.T) {
	Reset()
	Observe("mask", 200, 12*time.Millisecond, 100, 90)
	ObserveDetect(3 * time.Millisecond)
	ObservePDType("FIO")
	IncRejected("inflight_limit")
	SetStoreStats(7, 8, 9, 10, 11, 12, 13)

	out := scrape(t)

	// Every metric named by the specification must be present.
	for _, name := range []string{
		"pdguard_requests_total",
		"pdguard_request_duration_seconds_bucket",
		"pdguard_request_duration_seconds_sum",
		"pdguard_request_duration_seconds_count",
		"pdguard_detect_duration_seconds_bucket",
		"pdguard_detect_duration_seconds_sum",
		"pdguard_detect_duration_seconds_count",
		"pdguard_tokens_in_total",
		"pdguard_tokens_out_total",
		"pdguard_rps",
		"pdguard_tps",
		"pdguard_pd_detected_total",
		"pdguard_inflight",
		"pdguard_rejected_total",
		"pdguard_store_entries",
		"pdguard_build_info",
	} {
		if !strings.Contains(out, name+"{") && !strings.Contains(out, "\n"+name+" ") &&
			!strings.HasPrefix(out, name+" ") {
			t.Errorf("missing metric %s in exposition:\n%s", name, out)
		}
		if !strings.Contains(out, "# TYPE "+strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")+" ") {
			t.Errorf("missing TYPE line for %s", name)
		}
	}
}

func TestExpositionIsWellFormed(t *testing.T) {
	Reset()
	Observe("demask", 429, time.Millisecond, 1, 1)

	for _, line := range strings.Split(strings.TrimRight(scrape(t), "\n"), "\n") {
		checkExpositionLine(t, line)
	}
}

// checkExpositionLine validates a single line of the Prometheus exposition.
func checkExpositionLine(t *testing.T, line string) {
	t.Helper()
	if line == "" {
		t.Fatal("blank line in exposition")
	}
	if strings.HasPrefix(line, "#") {
		if !strings.HasPrefix(line, "# HELP ") && !strings.HasPrefix(line, "# TYPE ") {
			t.Errorf("unexpected comment line %q", line)
		}
		return
	}
	sp := strings.LastIndexByte(line, ' ')
	if sp < 0 {
		t.Errorf("sample line without value: %q", line)
		return
	}
	if _, err := strconv.ParseFloat(line[sp+1:], 64); err != nil {
		t.Errorf("sample line %q: value not a float: %v", line, err)
	}
	if strings.Count(line[:sp], "{") != strings.Count(line[:sp], "}") {
		t.Errorf("unbalanced braces in %q", line)
	}
}

func TestCountersGrow(t *testing.T) {
	Reset()
	for i := 0; i < 3; i++ {
		Observe("mask", 200, 5*time.Millisecond, 10, 20)
	}
	Observe("demask", 500, 5*time.Millisecond, 0, 0)

	out := scrape(t)
	if got := seriesValue(t, out, `pdguard_requests_total{op="mask",status="200"}`); got != 3 {
		t.Errorf("mask/200 = %v, want 3", got)
	}
	if got := seriesValue(t, out, `pdguard_requests_total{op="demask",status="500"}`); got != 1 {
		t.Errorf("demask/500 = %v, want 1", got)
	}
	if got := seriesValue(t, out, "pdguard_tokens_in_total"); got != 30 {
		t.Errorf("tokens_in = %v, want 30", got)
	}
	if got := seriesValue(t, out, "pdguard_tokens_out_total"); got != 60 {
		t.Errorf("tokens_out = %v, want 60", got)
	}

	Reset()
	out = scrape(t)
	if got := seriesValue(t, out, `pdguard_requests_total{op="mask",status="200"}`); got != 0 {
		t.Errorf("after Reset mask/200 = %v, want 0", got)
	}
	if got := seriesValue(t, out, "pdguard_tokens_in_total"); got != 0 {
		t.Errorf("after Reset tokens_in = %v, want 0", got)
	}
}

func TestInflightAndStoreGauges(t *testing.T) {
	Reset()
	IncInflight()
	IncInflight()
	DecInflight()
	SetStoreStats(5, 6, 7, 8, 9, 10, 11)

	out := scrape(t)
	if got := seriesValue(t, out, "pdguard_inflight"); got != 1 {
		t.Errorf("inflight = %v, want 1", got)
	}
	for _, tc := range []struct {
		series string
		want   float64
	}{
		{"pdguard_store_entries", 5},
		{"pdguard_store_puts_total", 6},
		{"pdguard_store_hits_total", 7},
		{"pdguard_store_misses_total", 8},
		{"pdguard_store_expired_total", 9},
		{"pdguard_store_evicted_total", 10},
		{"pdguard_store_skipped_total", 11},
	} {
		if got := seriesValue(t, out, tc.series); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.series, got, tc.want)
		}
	}
}

func TestHistogramBucketing(t *testing.T) {
	Reset()
	// 3ms lands in the 0.005 bucket, 300ms in the 0.5 bucket, 30s in +Inf.
	Observe("mask", 200, 3*time.Millisecond, 0, 0)
	Observe("mask", 200, 300*time.Millisecond, 0, 0)
	Observe("mask", 200, 30*time.Second, 0, 0)

	out := scrape(t)
	base := `pdguard_request_duration_seconds_bucket{op="mask",le=`
	type wantBucket struct {
		le  string
		cum float64
	}
	for _, w := range []wantBucket{
		{"0.002", 0}, // nothing below 2ms
		{"0.005", 1}, // the 3ms sample
		{"0.25", 1},
		{"0.5", 2},  // + the 300ms sample
		{"10", 2},   // 30s is above the last finite bound
		{"+Inf", 3}, // everything
	} {
		series := base + `"` + w.le + `"}`
		if got := seriesValue(t, out, series); got != w.cum {
			t.Errorf("%s = %v, want %v", series, got, w.cum)
		}
	}
	if got := seriesValue(t, out, `pdguard_request_duration_seconds_count{op="mask"}`); got != 3 {
		t.Errorf("histogram count = %v, want 3", got)
	}
	sum := seriesValue(t, out, `pdguard_request_duration_seconds_sum{op="mask"}`)
	if want := 0.003 + 0.3 + 30.0; sum < want-1e-6 || sum > want+1e-6 {
		t.Errorf("histogram sum = %v, want %v", sum, want)
	}

	// Buckets are cumulative, hence monotonically non-decreasing.
	prev := -1.0
	for _, b := range latencyBounds {
		v := seriesValue(t, out, base+`"`+strconv.FormatFloat(b, 'g', -1, 64)+`"}`)
		if v < prev {
			t.Fatalf("buckets not cumulative at le=%v: %v after %v", b, v, prev)
		}
		prev = v
	}
}

func TestDetectHistogramSeparate(t *testing.T) {
	Reset()
	ObserveDetect(20 * time.Millisecond)
	ObserveDetect(20 * time.Millisecond)

	out := scrape(t)
	if got := seriesValue(t, out, "pdguard_detect_duration_seconds_count"); got != 2 {
		t.Errorf("detect count = %v, want 2", got)
	}
	if got := seriesValue(t, out, `pdguard_detect_duration_seconds_bucket{le="0.025"}`); got != 2 {
		t.Errorf("detect 25ms bucket = %v, want 2", got)
	}
	if got := seriesValue(t, out, `pdguard_detect_duration_seconds_bucket{le="0.01"}`); got != 0 {
		t.Errorf("detect 10ms bucket = %v, want 0", got)
	}
}

func TestLabelCardinalityIsBounded(t *testing.T) {
	Reset()
	// Values that a buggy or hostile caller might invent must never mint new
	// series; they all have to collapse into the "other" bucket.
	Observe("weird-op", 200, time.Millisecond, 0, 0)
	Observe("mask", 599, time.Millisecond, 0, 0)
	ObservePDType("NOT_A_REAL_TYPE")
	ObservePDType("ALSO_FAKE")
	IncRejected("made-up-reason")

	out := scrape(t)
	if got := seriesValue(t, out, `pdguard_requests_total{op="other",status="200"}`); got != 1 {
		t.Errorf("unknown op not folded into other: %v", got)
	}
	if got := seriesValue(t, out, `pdguard_requests_total{op="mask",status="other"}`); got != 1 {
		t.Errorf("unknown status not folded into other: %v", got)
	}
	if got := seriesValue(t, out, `pdguard_pd_detected_total{type="other"}`); got != 2 {
		t.Errorf("unknown pd types not folded into other: %v", got)
	}
	if got := seriesValue(t, out, `pdguard_rejected_total{reason="other"}`); got != 1 {
		t.Errorf("unknown reason not folded into other: %v", got)
	}
	for _, bad := range []string{
		`pdguard_requests_total{op="weird-op",status="200"}`,
		`pdguard_pd_detected_total{type="NOT_A_REAL_TYPE"}`,
		`pdguard_rejected_total{reason="made-up-reason"}`,
	} {
		if hasSeries(out, bad) {
			t.Errorf("unexpected series minted: %s", bad)
		}
	}

	// The number of series is fixed regardless of how many odd labels arrive.
	before := strings.Count(out, "\n")
	for i := 0; i < 50; i++ {
		Observe("op"+strconv.Itoa(i), 900+i, time.Millisecond, 0, 0)
		ObservePDType("T" + strconv.Itoa(i))
		IncRejected("r" + strconv.Itoa(i))
	}
	if after := strings.Count(scrape(t), "\n"); after != before {
		t.Errorf("series count grew from %d to %d lines", before, after)
	}
}

func TestKnownPDTypesAreExposed(t *testing.T) {
	Reset()
	ObservePDType("FIO")
	ObservePDType("FIO")
	ObservePDType("CARD_NUMBER")

	out := scrape(t)
	if got := seriesValue(t, out, `pdguard_pd_detected_total{type="FIO"}`); got != 2 {
		t.Errorf("FIO = %v, want 2", got)
	}
	if got := seriesValue(t, out, `pdguard_pd_detected_total{type="CARD_NUMBER"}`); got != 1 {
		t.Errorf("CARD_NUMBER = %v, want 1", got)
	}
}

func TestRateWindow(t *testing.T) {
	var r ringWindow
	const now = 1_700_000_000

	for i := 0; i < 10; i++ {
		r.add(now, 1)
	}
	if got := r.rate(now); got != 1.0 { // 10 events / 10s window
		t.Errorf("rate = %v, want 1", got)
	}
	// A second in the past still counts while it is inside the window.
	r.add(now-3, 10)
	if got := r.rate(now); got != 2.0 {
		t.Errorf("rate with older bucket = %v, want 2", got)
	}
	// A bucket that has rolled out of the window is ignored.
	if got := r.rate(now + 20); got != 0 {
		t.Errorf("stale buckets counted: rate = %v, want 0", got)
	}
	// Reusing a slot a full minute later resets it instead of accumulating.
	r.add(now+rateBuckets, 1)
	if got := r.rate(now + rateBuckets); got != 0.1 {
		t.Errorf("slot not reset on wrap: rate = %v, want 0.1", got)
	}
}

func TestRPSAndTPSMove(t *testing.T) {
	Reset()
	for i := 0; i < 20; i++ {
		Observe("mask", 200, time.Millisecond, 30, 30)
	}
	if got := RPS(); got <= 0 {
		t.Errorf("RPS = %v, want > 0", got)
	}
	if got := TPS(); got <= 0 {
		t.Errorf("TPS = %v, want > 0", got)
	}
	out := scrape(t)
	if got := seriesValue(t, out, "pdguard_rps"); got <= 0 {
		t.Errorf("pdguard_rps = %v, want > 0", got)
	}
	if got := seriesValue(t, out, "pdguard_tps"); got <= 0 {
		t.Errorf("pdguard_tps = %v, want > 0", got)
	}

	Reset()
	if got := RPS(); got != 0 {
		t.Errorf("RPS after Reset = %v, want 0", got)
	}
}

func TestEstimateTokens(t *testing.T) {
	if got := EstimateTokens(""); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
	if got := EstimateTokens("a"); got != 1 {
		t.Errorf("single rune = %d, want 1 (never zero for non-empty input)", got)
	}
	// 12 Latin chars / 4 = 3.
	if got := EstimateTokens("abcdefghijkl"); got != 3 {
		t.Errorf("latin = %d, want 3", got)
	}
	// 12 Cyrillic letters / 3 = 4; the point of the test is that multi-byte
	// runes are counted as runes, not as bytes (which would give 8).
	if got := EstimateTokens("абвгдеёжзийк"); got != 4 {
		t.Errorf("cyrillic = %d, want 4", got)
	}
	// Mixed text: 12 cyrillic + 12 latin.
	if got := EstimateTokens("абвгдеёжзийк" + "abcdefghijkl"); got != 7 {
		t.Errorf("mixed = %d, want 7", got)
	}
	// Invalid UTF-8 must terminate and not panic.
	if got := EstimateTokens("\xff\xfe\xfd\xfc"); got != 1 {
		t.Errorf("invalid utf8 = %d, want 1", got)
	}
	if got := EstimateTokens(strings.Repeat("ё", 3000)); got != 1000 {
		t.Errorf("long cyrillic = %d, want 1000", got)
	}
}

func TestSnapshot(t *testing.T) {
	Reset()
	Observe("mask", 200, 40*time.Millisecond, 100, 80)
	Observe("demask", 200, 40*time.Millisecond, 10, 10)
	ObservePDType("EMAIL")
	IncRejected("rate_limit")
	IncInflight()
	SetStoreStats(1, 2, 3, 4, 5, 6, 7)

	s := Snapshot()
	if got := s["requests_total"].(int64); got != 2 {
		t.Errorf("requests_total = %v, want 2", got)
	}
	if got := s["tokens_in"].(int64); got != 110 {
		t.Errorf("tokens_in = %v, want 110", got)
	}
	if got := s["inflight"].(int64); got != 1 {
		t.Errorf("inflight = %v, want 1", got)
	}
	byOp := s["by_op"].(map[string]any)
	mask := byOp["mask"].(map[string]any)
	if got := mask["requests"].(int64); got != 1 {
		t.Errorf("by_op.mask.requests = %v, want 1", got)
	}
	if got := mask["p95"].(float64); got != 0.05 {
		t.Errorf("by_op.mask.p95 = %v, want 0.05", got)
	}
	if got := s["pd_detected"].(map[string]int64)["EMAIL"]; got != 1 {
		t.Errorf("pd_detected.EMAIL = %v, want 1", got)
	}
	if got := s["rejected"].(map[string]int64)["rate_limit"]; got != 1 {
		t.Errorf("rejected.rate_limit = %v, want 1", got)
	}
	if got := s["store"].(map[string]int64)["entries"]; got != 1 {
		t.Errorf("store.entries = %v, want 1", got)
	}
	if s["version"].(string) == "" || s["go_version"].(string) == "" {
		t.Error("build info missing from snapshot")
	}
}

func TestEscapeLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{"a\nb", `a\nb`},
	} {
		if got := escapeLabel(tc.in); got != tc.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestConcurrent is the -race guard: every exported recorder is hammered from
// many goroutines while the registry is scraped, which is exactly what happens
// when Prometheus polls a server under load.
func TestConcurrent(t *testing.T) {
	Reset()

	const workers, iters = 16, 200
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go concurrentWorker(w, iters, &wg)
	}

	var readers sync.WaitGroup
	readers.Add(2)
	done := make(chan struct{})
	go concurrentScraper(done, &readers)
	go concurrentSnapper(done, &readers)

	wg.Wait()
	close(done)
	readers.Wait()

	out := scrape(t)
	if got := seriesValue(t, out, `pdguard_requests_total{op="mask",status="200"}`); got != workers*iters {
		t.Errorf("requests = %v, want %d", got, workers*iters)
	}
	if got := seriesValue(t, out, `pdguard_pd_detected_total{type="FIO"}`); got != workers*iters {
		t.Errorf("pd FIO = %v, want %d", got, workers*iters)
	}
	if got := seriesValue(t, out, "pdguard_inflight"); got != 0 {
		t.Errorf("inflight = %v, want 0", got)
	}
}

// concurrentWorker hammers every exported recorder from one goroutine.
func concurrentWorker(w, iters int, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < iters; i++ {
		IncInflight()
		Observe("mask", 200, time.Duration(i)*time.Microsecond, 5, 5)
		ObservePDType("FIO")
		ObserveDetect(time.Duration(i) * time.Microsecond)
		IncRejected("rate_limit")
		SetStoreStats(int64(i), 1, 2, 3, 4, 5, 6)
		DecInflight()
	}
}

// concurrentScraper renders the registry until done is closed.
func concurrentScraper(done <-chan struct{}, readers *sync.WaitGroup) {
	defer readers.Done()
	for {
		select {
		case <-done:
			return
		default:
			var buf bytes.Buffer
			WritePrometheus(&buf)
		}
	}
}

// concurrentSnapper takes snapshots until done is closed.
func concurrentSnapper(done <-chan struct{}, readers *sync.WaitGroup) {
	defer readers.Done()
	for {
		select {
		case <-done:
			return
		default:
			_ = Snapshot()
		}
	}
}
