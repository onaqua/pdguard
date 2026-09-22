// Package metrics is the lock-free instrumentation layer of the proxy.
//
// Three constraints shaped this file.
//
// First, zero external dependencies: there is no prometheus/client_golang, so
// the registry is a handful of hand-rolled atomics and WritePrometheus renders
// the text exposition format directly. The format is small and stable, and
// Grafana scrapes it happily.
//
// Second, the hot path runs at a target of 1000 RPS and must add no contention:
// every recording function is a couple of atomic adds on preallocated cells. No
// mutex is taken anywhere, and no string is allocated while serving a request —
// label values are interned in maps built once at init time.
//
// Third, and most important for a personal-data service: nothing here may ever
// touch a payload. Only shapes are recorded — the category name of a detection,
// its count, byte-free token estimates and durations. There is no API that
// accepts a detected value, so a careless caller cannot leak one through a
// metric label.
package metrics

import (
	"bufio"
	"io"
	"runtime"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"pdguard/internal/pd"
)

// Version is the build version reported by pdguard_build_info. It is a var so
// that release builds can stamp it with -ldflags "-X pdguard/internal/metrics.Version=v1.2.3".
var Version = "dev"

const labelOther = "other"

// Known operation labels. Anything else becomes "other".
var opNames = []string{"mask", "demask", labelOther}

// Known HTTP status codes. The service answers with a small, fixed set; any
// other code is folded into "other" rather than minted as a new series.
var statusCodes = []int{
	200, 400, 401, 403, 404, 405, 408, 413, 415, 422, 429,
	500, 502, 503, 504,
}

// Known shed reasons for IncRejected.
var rejectReasons = []string{
	"inflight_limit", "queue_timeout", "rate_limit", "body_too_large",
	"shutting_down", labelOther,
}

// latencyBounds are the histogram upper bounds in seconds. They are clustered
// below one second because the specification caps a single /process call at
// 1s: the interesting question is "how close to the budget are we", not "how
// slow can it get". The implicit +Inf bucket is appended by the renderer.
var latencyBounds = []float64{
	0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10,
}

// Label cardinality is bounded on purpose.
//
// Prometheus keeps one time series per distinct label combination, and every
// series costs memory in the process and in the scraper forever. A metric label
// fed from request data (an op name from a URL, an error string from a
// dependency) is therefore an unbounded-growth bug waiting to happen — the
// classic "cardinality explosion". Every label value below is resolved through
// a fixed map built at init; anything not in the map collapses to "other".

// histogram is a fixed-bucket cumulative histogram.
//
// counts has one cell per bound plus one for +Inf, and sumNanos accumulates the
// observed durations in nanoseconds. Nanoseconds (an integer) are used instead
// of float seconds so the running sum is a plain atomic.Int64: Go has no atomic
// float, and a CAS loop on float bits would be slower and racier than needed.
type histogram struct {
	counts    []atomic.Int64
	sumNanos  atomic.Int64
	obsCount  atomic.Int64
	boundsRef []float64
}

func newHistogram(bounds []float64) *histogram {
	return &histogram{
		counts:    make([]atomic.Int64, len(bounds)+1),
		boundsRef: bounds,
	}
}

// observe files one duration. The bucket search is linear over 13 bounds, which
// beats binary search at this size and keeps the code obvious.
func (h *histogram) observe(d time.Duration) {
	ns := d.Nanoseconds()
	if ns < 0 {
		ns = 0
	}
	sec := float64(ns) / float64(time.Second)
	idx := len(h.boundsRef) // +Inf bucket unless a bound matches
	for i, b := range h.boundsRef {
		if sec <= b {
			idx = i
			break
		}
	}
	h.counts[idx].Add(1)
	h.sumNanos.Add(ns)
	h.obsCount.Add(1)
}

func (h *histogram) reset() {
	for i := range h.counts {
		h.counts[i].Store(0)
	}
	h.sumNanos.Store(0)
	h.obsCount.Store(0)
}

// quantile returns the upper bound of the bucket that contains the requested
// quantile. It is an approximation by construction — that is what a bucketed
// histogram can offer — and it is good enough for the /stats screen shown on
// the demo; Grafana computes exact-ish quantiles from the raw buckets.
func (h *histogram) quantile(q float64) float64 {
	total := h.obsCount.Load()
	if total == 0 {
		return 0
	}
	want := int64(float64(total) * q)
	if want < 1 {
		want = 1
	}
	var cum int64
	for i := range h.counts {
		cum += h.counts[i].Load()
		if cum >= want {
			if i < len(h.boundsRef) {
				return h.boundsRef[i]
			}
			return h.boundsRef[len(h.boundsRef)-1]
		}
	}
	return h.boundsRef[len(h.boundsRef)-1]
}

// Sliding-window rate estimation.
//
// rateBuckets one-second slots form a ring indexed by unix-second modulo the
// ring size, so no allocation, no list and no clock thread are needed. Each
// slot carries the unix second it belongs to; when a writer lands on a slot
// whose stamp is stale it claims the slot with a CAS and zeroes the counter,
// which is how a bucket "expires" without anybody sweeping it. A reader sums
// the rateWindow most recent slots and skips any slot whose stamp does not
// match the second it expects, so slots left over from a previous minute are
// ignored instead of being counted as fresh traffic.
//
// The only race is a writer that adds to a slot microseconds before another
// writer zeroes it on a second boundary; at most one second of samples can be
// lost that way, which is irrelevant for a rate gauge and buys a completely
// lock-free hot path.
const (
	rateBuckets = 60 // ring size: one full minute of history
	rateWindow  = 10 // seconds averaged for the reported rate
)

type ringWindow struct {
	stamps [rateBuckets]atomic.Int64
	counts [rateBuckets]atomic.Int64
}

func (r *ringWindow) add(now int64, v int64) {
	i := int(now % rateBuckets)
	if prev := r.stamps[i].Load(); prev != now && r.stamps[i].CompareAndSwap(prev, now) {
		r.counts[i].Store(0)
	}
	r.counts[i].Add(v)
}

// rate averages the last rateWindow seconds, current (partial) second included
// so that a freshly started load test shows movement immediately.
func (r *ringWindow) rate(now int64) float64 {
	var sum int64
	for j := int64(0); j < rateWindow; j++ {
		sec := now - j
		i := int(((sec % rateBuckets) + rateBuckets) % rateBuckets)
		if r.stamps[i].Load() == sec {
			sum += r.counts[i].Load()
		}
	}
	return float64(sum) / float64(rateWindow)
}

func (r *ringWindow) reset() {
	for i := 0; i < rateBuckets; i++ {
		r.stamps[i].Store(0)
		r.counts[i].Store(0)
	}
}

// registry holds every cell. All maps are built once in init and never written
// again, so concurrent reads need no synchronisation.
var (
	requestsTotal map[string]map[string]*atomic.Int64 // op -> status -> count
	durationByOp  map[string]*histogram               // op -> latency histogram
	detectHist    = newHistogram(latencyBounds)

	tokensInTotal  atomic.Int64
	tokensOutTotal atomic.Int64

	pdDetected map[string]*atomic.Int64 // pd type name -> count
	pdOrder    []string                 // stable render order

	rejectedTotal map[string]*atomic.Int64

	inflight atomic.Int64

	storeEntries atomic.Int64
	storePuts    atomic.Int64
	storeHits    atomic.Int64
	storeMisses  atomic.Int64
	storeExpired atomic.Int64
	storeEvicted atomic.Int64
	storeSkipped atomic.Int64

	reqWindow   ringWindow
	tokenWindow ringWindow

	statusLabels map[int]string // interned "200", "429", ... to avoid itoa on the hot path
)

func init() {
	requestsTotal = make(map[string]map[string]*atomic.Int64, len(opNames))
	durationByOp = make(map[string]*histogram, len(opNames))
	statusLabels = make(map[int]string, len(statusCodes))
	for _, code := range statusCodes {
		statusLabels[code] = strconv.Itoa(code)
	}
	for _, op := range opNames {
		byStatus := make(map[string]*atomic.Int64, len(statusCodes)+1)
		for _, code := range statusCodes {
			byStatus[statusLabels[code]] = new(atomic.Int64)
		}
		byStatus[labelOther] = new(atomic.Int64)
		requestsTotal[op] = byStatus
		durationByOp[op] = newHistogram(latencyBounds)
	}

	// The PD categories come from the shared catalogue so the metric label set
	// can never drift away from the types detectors actually emit.
	pdDetected = make(map[string]*atomic.Int64, len(pd.AllTypes)+1)
	pdOrder = make([]string, 0, len(pd.AllTypes)+1)
	for _, t := range pd.AllTypes {
		pdDetected[string(t)] = new(atomic.Int64)
		pdOrder = append(pdOrder, string(t))
	}
	pdDetected[labelOther] = new(atomic.Int64)
	pdOrder = append(pdOrder, labelOther)

	rejectedTotal = make(map[string]*atomic.Int64, len(rejectReasons))
	for _, r := range rejectReasons {
		rejectedTotal[r] = new(atomic.Int64)
	}
}

func normalizeOp(op string) string {
	if _, ok := requestsTotal[op]; ok {
		return op
	}
	return labelOther
}

func normalizeStatus(status int) string {
	if s, ok := statusLabels[status]; ok {
		return s
	}
	return labelOther
}

// Observe records one finished /process call: op is "mask" or "demask", status
// is the HTTP status code that was written, d is the wall time of the handler
// and tokensIn/tokensOut are the estimated token counts of the request and the
// response.
func Observe(op string, status int, d time.Duration, tokensIn, tokensOut int) {
	o := normalizeOp(op)
	requestsTotal[o][normalizeStatus(status)].Add(1)
	durationByOp[o].observe(d)

	now := time.Now().Unix()
	reqWindow.add(now, 1)

	total := int64(0)
	if tokensIn > 0 {
		tokensInTotal.Add(int64(tokensIn))
		total += int64(tokensIn)
	}
	if tokensOut > 0 {
		tokensOutTotal.Add(int64(tokensOut))
		total += int64(tokensOut)
	}
	if total > 0 {
		tokenWindow.add(now, total)
	}
}

// ObservePDType counts one detected personal-data category. Only the category
// name is recorded — never the value, and never its position in the text.
func ObservePDType(t string) {
	if c, ok := pdDetected[t]; ok {
		c.Add(1)
		return
	}
	pdDetected[labelOther].Add(1)
}

// ObserveDetect records the time spent inside detection alone, so a slow
// regexp can be told apart from a slow store or a slow client.
func ObserveDetect(d time.Duration) { detectHist.observe(d) }

// IncInflight marks the start of a request being served.
func IncInflight() { inflight.Add(1) }

// DecInflight marks the end of a request being served.
func DecInflight() { inflight.Add(-1) }

// IncRejected counts one request shed before it was served (429). The reason
// is folded to "other" when it is not one of the known load-shedding causes.
func IncRejected(reason string) {
	if c, ok := rejectedTotal[reason]; ok {
		c.Add(1)
		return
	}
	rejectedTotal[labelOther].Add(1)
}

// SetStoreStats publishes the mapping-store gauges. The store owns these
// numbers; metrics only mirrors the latest snapshot it is given.
func SetStoreStats(entries, puts, hits, misses, expired, evicted, skipped int64) {
	storeEntries.Store(entries)
	storePuts.Store(puts)
	storeHits.Store(hits)
	storeMisses.Store(misses)
	storeExpired.Store(expired)
	storeEvicted.Store(evicted)
	storeSkipped.Store(skipped)
}

// EstimateTokens is a cheap proxy for an LLM tokenizer: real BPE would cost far
// more than the masking itself, and the TPS metric only needs a stable unit of
// "text volume". Cyrillic text averages roughly three characters per token and
// Latin/ASCII roughly four, so runes of each script are counted in one pass and
// divided accordingly. Non-empty input never estimates to zero.
func EstimateTokens(s string) int {
	var cyr, other int
	for i := 0; i < len(s); {
		b := s[i]
		if b < 0x80 { // ASCII fast path: no decoding needed
			other++
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= 0x0400 && r <= 0x04FF { // Cyrillic block
			cyr++
		} else {
			other++
		}
		i += size
	}
	n := cyr/3 + other/4
	if n == 0 && cyr+other > 0 {
		return 1
	}
	return n
}

// RPS returns the request rate averaged over the sliding window.
func RPS() float64 { return reqWindow.rate(time.Now().Unix()) }

// TPS returns the token rate (in plus out) averaged over the sliding window.
func TPS() float64 { return tokenWindow.rate(time.Now().Unix()) }

// Reset clears every counter. Test-only: it is not safe to call while requests
// are in flight, because it resets cells other goroutines are adding to.
func Reset() {
	for _, op := range opNames {
		for _, c := range requestsTotal[op] {
			c.Store(0)
		}
		durationByOp[op].reset()
	}
	detectHist.reset()
	tokensInTotal.Store(0)
	tokensOutTotal.Store(0)
	for _, c := range pdDetected {
		c.Store(0)
	}
	for _, c := range rejectedTotal {
		c.Store(0)
	}
	inflight.Store(0)
	demaskFallbacks.Store(0)
	SetStoreStats(0, 0, 0, 0, 0, 0, 0)
	reqWindow.reset()
	tokenWindow.reset()
}

// escapeLabel escapes a label value per the exposition format: backslash,
// double quote and newline. Values here are interned constants, so this is
// belt-and-braces against a future label source.
func escapeLabel(v string) string {
	needs := false
	for i := 0; i < len(v); i++ {
		if c := v[i]; c == '\\' || c == '"' || c == '\n' {
			needs = true
			break
		}
	}
	if !needs {
		return v
	}
	out := make([]byte, 0, len(v)+4)
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

func writeHelp(w *bufio.Writer, name, help, typ string) {
	w.WriteString("# HELP ")
	w.WriteString(name)
	w.WriteByte(' ')
	w.WriteString(help)
	w.WriteString("\n# TYPE ")
	w.WriteString(name)
	w.WriteByte(' ')
	w.WriteString(typ)
	w.WriteByte('\n')
}

func writeInt(w *bufio.Writer, name, labels string, v int64) {
	w.WriteString(name)
	w.WriteString(labels)
	w.WriteByte(' ')
	w.WriteString(strconv.FormatInt(v, 10))
	w.WriteByte('\n')
}

func writeFloat(w *bufio.Writer, name, labels string, v float64) {
	w.WriteString(name)
	w.WriteString(labels)
	w.WriteByte(' ')
	w.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	w.WriteByte('\n')
}

func joinLabels(a, b string) string {
	if a == "" {
		return "{" + b + "}"
	}
	return "{" + a + "," + b + "}"
}

// writeHistogram renders the three series a Prometheus histogram is made of:
// cumulative _bucket series carrying the le label, then _sum and _count.
// extra carries any additional labels ("op=..."), already formatted without
// braces, or is empty.
func writeHistogram(w *bufio.Writer, name, extra string, h *histogram) {
	var cum int64
	for i, b := range h.boundsRef {
		cum += h.counts[i].Load()
		writeInt(w, name+"_bucket", joinLabels(extra, `le="`+strconv.FormatFloat(b, 'g', -1, 64)+`"`), cum)
	}
	cum += h.counts[len(h.boundsRef)].Load()
	writeInt(w, name+"_bucket", joinLabels(extra, `le="+Inf"`), cum)

	sum := float64(h.sumNanos.Load()) / float64(time.Second)
	labels := ""
	if extra != "" {
		labels = "{" + extra + "}"
	}
	writeFloat(w, name+"_sum", labels, sum)
	writeInt(w, name+"_count", labels, h.obsCount.Load())
}

// WritePrometheus renders the whole registry in the Prometheus text exposition
// format. Output order is deterministic so that diffing two scrapes by hand
// during the demo is possible.
func WritePrometheus(w io.Writer) {
	bw := bufio.NewWriterSize(w, 16<<10)
	defer bw.Flush()

	writeHelp(bw, "pdguard_requests_total", "Total /process calls by operation and HTTP status.", "counter")
	for _, op := range opNames {
		keys := make([]string, 0, len(requestsTotal[op]))
		for s := range requestsTotal[op] {
			keys = append(keys, s)
		}
		sort.Strings(keys)
		for _, s := range keys {
			writeInt(bw, "pdguard_requests_total",
				`{op="`+escapeLabel(op)+`",status="`+escapeLabel(s)+`"}`,
				requestsTotal[op][s].Load())
		}
	}

	writeHelp(bw, "pdguard_request_duration_seconds", "End-to-end handler latency by operation.", "histogram")
	for _, op := range opNames {
		writeHistogram(bw, "pdguard_request_duration_seconds", `op="`+escapeLabel(op)+`"`, durationByOp[op])
	}

	writeHelp(bw, "pdguard_detect_duration_seconds", "Time spent inside personal-data detection.", "histogram")
	writeHistogram(bw, "pdguard_detect_duration_seconds", "", detectHist)

	writeHelp(bw, "pdguard_tokens_in_total", "Estimated tokens received.", "counter")
	writeInt(bw, "pdguard_tokens_in_total", "", tokensInTotal.Load())

	writeHelp(bw, "pdguard_tokens_out_total", "Estimated tokens returned.", "counter")
	writeInt(bw, "pdguard_tokens_out_total", "", tokensOutTotal.Load())

	now := time.Now().Unix()

	writeHelp(bw, "pdguard_rps", "Requests per second over the sliding window.", "gauge")
	writeFloat(bw, "pdguard_rps", "", reqWindow.rate(now))

	writeHelp(bw, "pdguard_tps", "Tokens per second (in+out) over the sliding window.", "gauge")
	writeFloat(bw, "pdguard_tps", "", tokenWindow.rate(now))

	writeHelp(bw, "pdguard_pd_detected_total", "Detected personal-data items by category. Values are never recorded.", "counter")
	for _, t := range pdOrder {
		writeInt(bw, "pdguard_pd_detected_total", `{type="`+escapeLabel(t)+`"}`, pdDetected[t].Load())
	}

	writeHelp(bw, "pdguard_inflight", "Requests currently being served.", "gauge")
	writeInt(bw, "pdguard_inflight", "", inflight.Load())

	writeHelp(bw, "pdguard_rejected_total", "Requests shed with 429 by reason.", "counter")
	for _, r := range rejectReasons {
		writeInt(bw, "pdguard_rejected_total", `{reason="`+escapeLabel(r)+`"}`, rejectedTotal[r].Load())
	}

	writeHelp(bw, "pdguard_demask_fallback_total", "Reverse requests answered with the payload unchanged because the mapping was gone.", "counter")
	writeInt(bw, "pdguard_demask_fallback_total", "", demaskFallbacks.Load())

	writeHelp(bw, "pdguard_store_entries", "Mappings currently held by the store.", "gauge")
	writeInt(bw, "pdguard_store_entries", "", storeEntries.Load())
	writeHelp(bw, "pdguard_store_puts_total", "Mappings stored.", "counter")
	writeInt(bw, "pdguard_store_puts_total", "", storePuts.Load())
	writeHelp(bw, "pdguard_store_hits_total", "Demask lookups served.", "counter")
	writeInt(bw, "pdguard_store_hits_total", "", storeHits.Load())
	writeHelp(bw, "pdguard_store_misses_total", "Demask lookups with no mapping.", "counter")
	writeInt(bw, "pdguard_store_misses_total", "", storeMisses.Load())
	writeHelp(bw, "pdguard_store_expired_total", "Mappings dropped by TTL.", "counter")
	writeInt(bw, "pdguard_store_expired_total", "", storeExpired.Load())
	writeHelp(bw, "pdguard_store_evicted_total", "Mappings dropped under memory pressure.", "counter")
	writeInt(bw, "pdguard_store_evicted_total", "", storeEvicted.Load())
	writeHelp(bw, "pdguard_store_skipped_total", "Mappings not stored (duplicate payload_id or oversized).", "counter")
	writeInt(bw, "pdguard_store_skipped_total", "", storeSkipped.Load())

	writeHelp(bw, "pdguard_build_info", "Build metadata; always 1.", "gauge")
	writeInt(bw, "pdguard_build_info",
		`{version="`+escapeLabel(Version)+`",go_version="`+escapeLabel(runtime.Version())+`"}`, 1)
}

// Snapshot returns a JSON-friendly view for the human-facing /stats endpoint.
// It is intentionally a different shape from the Prometheus output: operators
// want a handful of headline numbers, not 80 series.
func Snapshot() map[string]any {
	now := time.Now().Unix()

	byOp := make(map[string]any, len(opNames))
	var totalReq int64
	for _, op := range opNames {
		var sum int64
		statuses := make(map[string]int64, 4)
		for s, c := range requestsTotal[op] {
			if v := c.Load(); v != 0 {
				statuses[s] = v
				sum += v
			}
		}
		totalReq += sum
		h := durationByOp[op]
		byOp[op] = map[string]any{
			"requests": sum,
			"statuses": statuses,
			"p50":      h.quantile(0.50),
			"p95":      h.quantile(0.95),
			"p99":      h.quantile(0.99),
		}
	}

	pd := make(map[string]int64)
	for t, c := range pdDetected {
		if v := c.Load(); v != 0 {
			pd[t] = v
		}
	}
	rej := make(map[string]int64)
	for r, c := range rejectedTotal {
		if v := c.Load(); v != 0 {
			rej[r] = v
		}
	}

	return map[string]any{
		"version":         Version,
		"go_version":      runtime.Version(),
		"requests_total":  totalReq,
		"by_op":           byOp,
		"rps":             reqWindow.rate(now),
		"tps":             tokenWindow.rate(now),
		"tokens_in":       tokensInTotal.Load(),
		"tokens_out":      tokensOutTotal.Load(),
		"inflight":        inflight.Load(),
		"rejected":        rej,
		"pd_detected":     pd,
		"demask_fallback": demaskFallbacks.Load(),
		"detect_p95":      detectHist.quantile(0.95),
		"store": map[string]int64{
			"entries": storeEntries.Load(),
			"puts":    storePuts.Load(),
			"hits":    storeHits.Load(),
			"misses":  storeMisses.Load(),
			"expired": storeExpired.Load(),
			"evicted": storeEvicted.Load(),
			"skipped": storeSkipped.Load(),
		},
	}
}
