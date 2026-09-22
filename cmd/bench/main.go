// Command bench is a load tool that reproduces what the AlfaSonar grading
// harness does to us, so we can see our score before the official run.
//
// It speaks the real protocol over real HTTP: for each dataset element it sends
// a forward request under a fresh payload_id, then a reverse request under the
// same id with the mask it got back, and counts the element successful only if
// the reverse step returned the original bytes exactly. Both halves are paced
// by one target RPS, retried the way the harness retries (up to 2 retries, 3
// attempts total, honouring Retry-After), and the run aborts the way the
// harness aborts it — after 5 consecutive invalid responses (a 429 is not
// invalid and does not reset the streak; a successful response resets it). The
// per-request timeout is 10 seconds.
//
// Three things it deliberately does not do:
//
//  1. It does not score our mask against a reference: we have no reference
//     masks, so any "quality" number here would be invented. Instead it reports
//     the two facts we can actually measure — the share of PD cases where
//     something was masked, and the share of negative cases that came back
//     untouched. The second number lands on the jury metric, because every
//     byte changed without cause is a direct deduction from it.
//
//  2. It does not reuse a payload_id within a run. Reuse would make the forward
//     step idempotent by accident (the engine would answer from the store) and
//     hide exactly the work we are trying to measure.
//
//  3. It does not assume a warmed process. The -warmup flag runs the same
//     traffic with discarded measurements, so the percentiles are not set by
//     the first few hundred allocations and the first cache fills.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// options are the validated command-line settings. The fields mirror the flags
// so that validation can normalise them in one place.
type options struct {
	url         string
	rps         int
	duration    time.Duration
	concurrency int
	timeout     time.Duration
	urlNote     string
}

// validate normalises the endpoint and rejects settings that cannot produce a
// meaningful run. It keeps the pre-existing absolute-URL rule in force: a
// scheme-less argument must not silently become something the HTTP client
// would accept.
func (o *options) validate() error {
	norm, note, err := normalizeEndpoint(o.url)
	if err != nil {
		return err
	}
	o.url = norm
	o.urlNote = note
	if o.rps <= 0 {
		return fmt.Errorf("rps must be positive")
	}
	if o.duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if o.concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive")
	}
	if o.timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	return nil
}

// normalizeEndpoint turns a -url argument into the /process endpoint. The case
// that motivated it is "origin only": a run against http://localhost:8080 used
// to 404 five times in a row and abort under the streak rule, which looks in
// the report exactly like a service that fell over. Normalisation may add a
// missing path; it may never invent a host.
func normalizeEndpoint(in string) (string, string, error) {
	u, err := url.Parse(in)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("endpoint must include a host: %q", in)
	}
	note := ""
	switch u.Path {
	case "", "/":
		u.Path = "/process"
		note = "endpoint normalised to " + u.String()
	case "/process":
		// Already the endpoint; nothing to say.
	case "/process/":
		u.Path = "/process"
		note = "endpoint normalised to " + u.String()
	default:
		// Some other path is left alone, but the operator should know the
		// tool is not talking to /process.
		note = "endpoint path is not /process; using " + u.String() + " as-is"
	}
	return u.String(), note, nil
}

// datasetElement is one item of the corpus. HasPD marks the positive cases
// (the payload carries personal data) so the report can separate the two facts
// it actually measures.
type datasetElement struct {
	Payload string
	HasPD   bool
}

// datasetRecord is the on-disk shape of one corpus item. The corpus is JSONL:
// one self-contained JSON object per line, no surrounding brackets and no
// commas between records. HasPD is derived from expect_types: a non-empty list
// marks a positive case, an empty list a negative one.
type datasetRecord struct {
	ID          string   `json:"id"`
	Text        string   `json:"text"`
	ExpectTypes []string `json:"expect_types"`
	Note        string   `json:"note"`
}

// loadDataset reads the corpus from a JSONL file: one self-contained JSON
// object per line, no surrounding brackets and no commas between records.
// Blank lines are skipped. A line that does not parse, an element without a
// non-empty text, or a file that yields no elements at all is an error reported
// with the file path and, where applicable, the offending line number.
func loadDataset(path string) ([]datasetElement, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read dataset: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var elements []datasetElement
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec datasetRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("parse dataset %s line %d: %w", path, line, err)
		}
		if rec.Text == "" {
			return nil, fmt.Errorf("dataset %s line %d: element %q has empty text", path, line, rec.ID)
		}
		elements = append(elements, datasetElement{
			Payload: rec.Text,
			HasPD:   len(rec.ExpectTypes) > 0,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read dataset %s: %w", path, err)
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("dataset %s is empty", path)
	}
	return elements, nil
}

// processRequest and processResponse are the body of the /process contract.
type processRequest struct {
	Payload   string `json:"payload"`
	PayloadID string `json:"payload_id"`
}

type processResponse struct {
	Result string `json:"result"`
}

// parseResult decodes a /process response body and reports whether it carried a
// usable result field.
func parseResult(body []byte) (string, bool) {
	var resp processResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", false
	}
	return resp.Result, true
}

// runState is the shared abort machinery. The streak counts consecutive invalid
// responses across all workers; a 429 neither advances nor resets it, and a
// successful response resets it.
type runState struct {
	invalidStreak atomic.Int32
	aborted       atomic.Bool
}

// bumpInvalid advances the invalid streak and reports whether it crossed the
// abort threshold.
func (s *runState) bumpInvalid() bool {
	if s.invalidStreak.Add(1) >= 5 {
		s.aborted.Store(true)
		return true
	}
	return false
}

// limiter paces requests at a target rate with a burst equal to the
// concurrency. It is a token bucket: a refill goroutine drops one token every
// 1/rate seconds into a buffered channel, and each request consumes one.
type limiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newLimiter(rate float64, burst int) *limiter {
	l := &limiter{
		tokens: make(chan struct{}, burst),
		stop:   make(chan struct{}),
	}
	for i := 0; i < burst; i++ {
		l.tokens <- struct{}{}
	}
	if rate <= 0 {
		return l
	}
	interval := time.Duration(float64(time.Second) / rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
}

func (l *limiter) close() {
	close(l.stop)
}

// wait blocks until a token is available or the run context ends. It reports
// false when the run is over, so the caller can stop without counting.
func (l *limiter) wait(ctx context.Context) bool {
	select {
	case <-l.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

// metrics collects the numbers the report prints. Every method takes discard so
// the warmup phase can run the same traffic without polluting the measurements.
type metrics struct {
	mu                   sync.Mutex
	latencies            []time.Duration
	statusCounts         map[int]int
	totalRequests        int
	totalRoundTrips      int
	successfulRoundTrips int
	pdCases              int
	pdMasked             int
	negativeCases        int
	negativeUntouched    int
}

func (m *metrics) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies = m.latencies[:0]
	m.statusCounts = make(map[int]int)
	m.totalRequests = 0
	m.totalRoundTrips = 0
	m.successfulRoundTrips = 0
	m.pdCases = 0
	m.pdMasked = 0
	m.negativeCases = 0
	m.negativeUntouched = 0
}

func (m *metrics) recordStatus(discard bool, code int) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCounts[code]++
	m.totalRequests++
}

func (m *metrics) addLatency(discard bool, d time.Duration) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies = append(m.latencies, d)
}

func (m *metrics) incRoundTrip(discard bool, success bool) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalRoundTrips++
	if success {
		m.successfulRoundTrips++
	}
}

func (m *metrics) incPD(discard bool) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pdCases++
}

func (m *metrics) incPDMasked(discard bool) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pdMasked++
}

func (m *metrics) incNegative(discard bool) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.negativeCases++
}

func (m *metrics) incNegativeUntouched(discard bool) {
	if discard {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.negativeUntouched++
}

// percentiles returns p50, p90, p95, p99 and the maximum round-trip latency.
func (m *metrics) percentiles() (p50, p90, p95, p99, max time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.latencies) == 0 {
		return 0, 0, 0, 0, 0
	}
	lats := make([]time.Duration, len(m.latencies))
	copy(lats, m.latencies)
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p := func(q float64) time.Duration {
		idx := int(q * float64(len(lats)))
		if idx >= len(lats) {
			idx = len(lats) - 1
		}
		return lats[idx]
	}
	return p(0.50), p(0.90), p(0.95), p(0.99), lats[len(lats)-1]
}

// bench is one run of the tool: the endpoint, the client, the corpus and the
// shared state.
type bench struct {
	opts        options
	url         string
	client      *http.Client
	elements    []datasetElement
	lim         *limiter
	state       runState
	m           metrics
	runDuration time.Duration
}

func newBench(o options, elements []datasetElement) *bench {
	return &bench{
		opts:     o,
		url:      o.url,
		client:   &http.Client{Timeout: o.timeout},
		elements: elements,
		m:        metrics{statusCounts: make(map[int]int)},
	}
}

var idCounter atomic.Uint64

// newID produces a fresh payload_id per element. Reusing an id within a run
// would make the forward step idempotent by accident and hide the work we are
// trying to measure, so every element gets a unique one.
func (b *bench) newID() string {
	return fmt.Sprintf("bench-%d-%d", time.Now().UnixNano(), idCounter.Add(1))
}

// run drives the corpus for a duration. When discard is true (the warmup
// phase) the same traffic is sent but no measurement is kept.
func (b *bench) run(d time.Duration, discard bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	b.state.aborted.Store(false)
	b.state.invalidStreak.Store(0)
	if !discard {
		b.m.reset()
		b.runDuration = d
	}
	b.lim = newLimiter(float64(b.opts.rps), b.opts.concurrency)
	defer b.lim.close()
	var wg sync.WaitGroup
	for i := 0; i < b.opts.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.worker(ctx, discard)
		}()
	}
	wg.Wait()
}

// worker pulls elements round-robin until the run ends or the run aborts. Each
// worker starts at a random offset so a short run still samples the whole
// corpus instead of only the head of the file; otherwise elements at the tail
// (for example the negative cases) would never be reached.
func (b *bench) worker(ctx context.Context, discard bool) {
	i := rand.Intn(len(b.elements))
	for {
		if b.state.aborted.Load() {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		el := b.elements[i%len(b.elements)]
		i++
		b.roundTrip(ctx, el, discard)
	}
}

// roundTrip performs the forward and reverse steps for one element and records
// the outcome. An element is counted as a round-trip only when both steps
// completed; an element left unfinished because the run ended is neither a
// success nor a failure and is not counted at all.
func (b *bench) roundTrip(ctx context.Context, el datasetElement, discard bool) {
	id := b.newID()

	_, mask, fOK, fEnded := b.doRequest(ctx, el.Payload, id, discard)
	if !fOK {
		if !fEnded && !b.state.aborted.Load() {
			b.m.incRoundTrip(discard, false)
		}
		return
	}

	// The two facts we can actually measure (see the package comment): whether
	// a PD case had anything masked, and whether a negative case came back
	// untouched.
	if el.HasPD {
		b.m.incPD(discard)
		if mask != el.Payload {
			b.m.incPDMasked(discard)
		}
	} else {
		b.m.incNegative(discard)
		if mask == el.Payload {
			b.m.incNegativeUntouched(discard)
		}
	}

	_, original, rOK, rEnded := b.doRequest(ctx, mask, id, discard)
	if !rOK {
		if !rEnded && !b.state.aborted.Load() {
			b.m.incRoundTrip(discard, false)
		}
		return
	}

	success := original == el.Payload
	b.m.incRoundTrip(discard, success)
}

// doRequest sends one logical request with the harness's retry policy: up to 2
// retries (3 attempts total), honouring Retry-After on a 429. It returns the
// final status, the parsed result, whether a valid 200 was obtained, and
// whether the run ended (context done) before the request could complete.
func (b *bench) doRequest(ctx context.Context, payload, id string, discard bool) (int, string, bool, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		status, body, retryAfter := b.post(ctx, payload, id, discard)
		switch {
		case status == -1:
			// The run ended (context done); stop without counting.
			return 0, "", false, true
		case status == http.StatusTooManyRequests:
			// A 429 is not an invalid response: it neither advances the
			// streak nor resets it. Honour Retry-After and try again.
			if retryAfter > 0 {
				time.Sleep(retryAfter)
			} else {
				time.Sleep(time.Second)
			}
			continue
		case status == http.StatusOK:
			if result, ok := parseResult(body); ok {
				// A successful response resets the invalid streak.
				b.state.invalidStreak.Store(0)
				return status, result, true, false
			}
			// A 200 with an unparseable body is invalid.
			if b.state.bumpInvalid() {
				return status, "", false, false
			}
			continue
		default:
			// Any other status (or a network error, status 0) is invalid.
			if b.state.bumpInvalid() {
				return status, "", false, false
			}
			continue
		}
	}
	return 0, "", false, false
}

// post sends one HTTP request, paced by the limiter. It returns the status, the
// body and the Retry-After hint, or status -1 when the run ended before a token
// was available. The latency of the single HTTP request is measured from just
// before the request is sent to just after the response is read; the pacing
// wait, the warmup sleep and the time between the two requests of a pair are
// not part of it.
func (b *bench) post(ctx context.Context, payload, id string, discard bool) (int, []byte, time.Duration) {
	if !b.lim.wait(ctx) {
		return -1, nil, 0
	}
	body, _ := json.Marshal(processRequest{Payload: payload, PayloadID: id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, 0
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, nil, 0
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	b.m.addLatency(discard, time.Since(start))
	retryAfter := time.Duration(0)
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			retryAfter = time.Duration(secs) * time.Second
		}
	}
	b.m.recordStatus(discard, resp.StatusCode)
	return resp.StatusCode, data, retryAfter
}

// report prints the numbers the specification's section 5 asks for: latency
// percentiles, RPS, the share of successful round-trips and the status
// distribution, plus the two facts the tool can actually measure.
func (b *bench) report() {
	m := &b.m
	m.mu.Lock()
	totalRT := m.totalRoundTrips
	okRT := m.successfulRoundTrips
	pdCases := m.pdCases
	pdMasked := m.pdMasked
	negCases := m.negativeCases
	negUntouched := m.negativeUntouched
	totalReq := m.totalRequests
	statuses := make(map[int]int, len(m.statusCounts))
	for k, v := range m.statusCounts {
		statuses[k] = v
	}
	m.mu.Unlock()

	p50, p90, p95, p99, max := m.percentiles()

	fmt.Println("=== pdguard bench report ===")
	fmt.Println("Latency (round-trip):")
	fmt.Printf("  p50: %s\n", p50)
	fmt.Printf("  p90: %s\n", p90)
	fmt.Printf("  p95: %s\n", p95)
	fmt.Printf("  p99: %s\n", p99)
	fmt.Printf("  max: %s\n", max)

	rps := 0.0
	if b.runDuration > 0 {
		rps = float64(totalReq) / b.runDuration.Seconds()
	}
	fmt.Printf("RPS: %.1f\n", rps)

	if totalRT > 0 {
		fmt.Printf("Successful round-trips: %.2f%% (%d/%d)\n",
			100*float64(okRT)/float64(totalRT), okRT, totalRT)
	} else {
		fmt.Println("Successful round-trips: n/a (0 round-trips)")
	}

	fmt.Println("Status distribution:")
	codes := make([]int, 0, len(statuses))
	for c := range statuses {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		fmt.Printf("  %d: %d\n", c, statuses[c])
	}

	if pdCases > 0 {
		fmt.Printf("PD cases masked: %.2f%% (%d/%d)\n",
			100*float64(pdMasked)/float64(pdCases), pdMasked, pdCases)
	} else {
		fmt.Println("PD cases masked: n/a (no PD cases)")
	}
	if negCases > 0 {
		fmt.Printf("Negative cases untouched: %.2f%% (%d/%d)\n",
			100*float64(negUntouched)/float64(negCases), negUntouched, negCases)
	} else {
		fmt.Println("Negative cases untouched: n/a (no negative cases)")
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		urlFlag      = flag.String("url", "http://localhost:8080", "base URL of the pdguard service")
		rpsFlag      = flag.Int("rps", 1000, "target requests per second")
		durationFlag = flag.Duration("duration", 30*time.Second, "run duration")
		concFlag     = flag.Int("concurrency", 64, "number of concurrent workers")
		timeoutFlag  = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		warmupFlag   = flag.Duration("warmup", 0, "warmup duration with discarded measurements")
		datasetFlag  = flag.String("dataset", "", "path to the dataset JSON file")
	)
	flag.Parse()

	o := options{
		url:         *urlFlag,
		rps:         *rpsFlag,
		duration:    *durationFlag,
		concurrency: *concFlag,
		timeout:     *timeoutFlag,
	}
	if err := o.validate(); err != nil {
		return err
	}
	if o.urlNote != "" {
		fmt.Fprintln(os.Stderr, "note:", o.urlNote)
	}

	elements, err := loadDataset(*datasetFlag)
	if err != nil {
		return err
	}
	if len(elements) == 0 {
		return fmt.Errorf("dataset is empty")
	}

	b := newBench(o, elements)
	if *warmupFlag > 0 {
		b.run(*warmupFlag, true)
	}
	b.run(o.duration, false)
	b.report()
	return nil
}
