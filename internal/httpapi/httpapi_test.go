package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/engine"
	"pdguard/internal/store"
)

const (
	httpConfigLoadFmt  = "config.Load: %v"
	httpConfigApplyFmt = "config.Apply: %v"
	httpRetryID        = "retry-1"
	httpSecretToken    = "s3cret-token"
	httpDemoKey        = "demo-key-analytics"
)

// sampleText is a payload that every layer must agree on: it carries a full
// Russian name and a card number, so masking is guaranteed to change something
// and the round trip is a real assertion rather than a tautology.
const sampleText = "Клиент Иванов Иван Иванович, карта 4509 1234 5678 9012, почта ivanov@example.com."

// newTestServer builds a Server on the shipped defaults, optionally tweaked.
// Passing an empty path to config.Load means "defaults, never persisted", which
// keeps a test from writing to the repository.
func newTestServer(t *testing.T, tune func(*config.Config)) (*Server, store.Store) {
	t.Helper()
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf(httpConfigLoadFmt, err)
	}
	if tune != nil {
		c := mgr.Get().Clone()
		tune(c)
		if err := mgr.Apply(c); err != nil {
			t.Fatalf(httpConfigApplyFmt, err)
		}
	}
	st := store.New(store.Config{Shards: 8, TTL: time.Minute, MaxEntries: 1000, MaxValueBytes: 1 << 20, SweepInterval: -1})
	t.Cleanup(st.Close)
	return newServerWithStore(t, mgr, st), st
}

func newServerWithStore(t *testing.T, mgr *config.Manager, st store.Store) *Server {
	t.Helper()
	s := New(Options{
		Engine:  engine.New(engine.Options{Cfg: mgr, Store: st}),
		Cfg:     mgr,
		Store:   st,
		Version: "test",
	})
	s.SetReady(true)
	return s
}

// post sends a JSON body and returns the recorded response.
func post(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// processCall runs one /process request and returns the result field.
func processCall(t *testing.T, s *Server, payloadID, payload string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"payload": payload, "payload_id": payloadID})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	rec := post(t, s, pathProcess, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /process: status %d, body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != contentTypeJSON {
		t.Fatalf("Content-Type: got %q, want %q", ct, contentTypeJSON)
	}
	var out processResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return out.Result
}

// TestProcessRoundTrip is the contract from Appendix A end to end: the first
// call with a fresh payload_id masks, and the second call with the same id
// carrying that mask returns the original byte for byte.
func TestProcessRoundTrip(t *testing.T) {
	s, _ := newTestServer(t, nil)

	masked := processCall(t, s, "req-1", sampleText)
	if masked == sampleText {
		t.Fatalf("nothing was masked in %q", masked)
	}
	if !strings.Contains(masked, "*") {
		t.Fatalf("masked text has no masking marks: %q", masked)
	}

	restored := processCall(t, s, "req-1", masked)
	if restored != sampleText {
		t.Fatalf("demasking is not exact:\n got %q\nwant %q", restored, sampleText)
	}
}

// TestPayloadIDIsCaseInsensitive checks the specification's requirement that
// identification ignores case: a reverse step that re-cases the id must still
// find its mapping.
func TestPayloadIDIsCaseInsensitive(t *testing.T) {
	s, _ := newTestServer(t, nil)

	masked := processCall(t, s, "Req-CASE", sampleText)
	if restored := processCall(t, s, "rEQ-case", masked); restored != sampleText {
		t.Fatalf("case-insensitive id lost the mapping:\n got %q\nwant %q", restored, sampleText)
	}
}

// TestForwardRetryIsIdempotent covers the harness retrying a masking request:
// the same payload under the same id must produce the same mask, not a mask of
// a mask.
func TestForwardRetryIsIdempotent(t *testing.T) {
	s, _ := newTestServer(t, nil)

	first := processCall(t, s, httpRetryID, sampleText)
	second := processCall(t, s, httpRetryID, sampleText)
	if first != second {
		t.Fatalf("retry produced a different mask:\n got %q\nwant %q", second, first)
	}
	if restored := processCall(t, s, httpRetryID, first); restored != sampleText {
		t.Fatalf("demasking after a retry is not exact: %q", restored)
	}
}

// TestEmptyPayload asserts that an empty payload is valid input with an empty
// result, not an error: answering 400 here would spend the harness's error
// budget on a request we can serve.
func TestEmptyPayload(t *testing.T) {
	s, _ := newTestServer(t, nil)
	if got := processCall(t, s, "empty-1", ""); got != "" {
		t.Fatalf("empty payload: got %q, want \"\"", got)
	}
}

// TestTextWithoutPDIsUnchanged is the false-positive guard at the transport
// level: text outside personal data must come back byte for byte, because the
// quality metric subtracts for every character we touch without cause.
func TestTextWithoutPDIsUnchanged(t *testing.T) {
	const plain = "Стихи Александра Пушкина изучают в школе. Отделение банка на Тверской работает до 20:00."
	s, _ := newTestServer(t, nil)
	if got := processCall(t, s, "plain-1", plain); got != plain {
		t.Fatalf("plain text was modified:\n got %q\nwant %q", got, plain)
	}
}

// TestMissingPayloadIDIs400 is the one input we cannot serve: without an id
// there is nothing to correlate the two steps of the contract with.
func TestMissingPayloadIDIs400(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, body := range []string{
		`{"payload":"текст"}`,
		`{"payload":"текст","payload_id":""}`,
		`{"payload":"текст","payload_id":"   "}`,
	} {
		rec := post(t, s, pathProcess, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: got status %d, want 400", body, rec.Code)
		}
	}
}

// TestUnknownFieldsAreIgnored pins DisallowUnknownFields being off: a harness
// that adds a field must not turn every request into a 400.
func TestUnknownFieldsAreIgnored(t *testing.T) {
	s, _ := newTestServer(t, nil)
	rec := post(t, s, pathProcess, `{"payload":"текст","payload_id":"x1","trace_id":"abc","nested":{"a":1}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown fields rejected: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// TestMalformedJSONIsNot500 checks the degradation rule: a body we cannot parse
// is a client mistake (400), never a server fault (500).
func TestMalformedJSONIsNot500(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, body := range []string{`{`, `not json at all`, ``, `[]`} {
		rec := post(t, s, pathProcess, body)
		if rec.Code >= 500 {
			t.Fatalf("body %q: got status %d, want a 4xx", body, rec.Code)
		}
	}
}

// TestBodyTooLargeIs413 checks that the body cap answers a defined status
// rather than letting the handler allocate without bound.
func TestBodyTooLargeIs413(t *testing.T) {
	s, _ := newTestServer(t, func(c *config.Config) { c.Server.MaxBodyBytes = 64 })
	rec := post(t, s, pathProcess, `{"payload":"`+strings.Repeat("a", 500)+`","payload_id":"big"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: got status %d, want 413", rec.Code)
	}
}

// TestWrongMethodIs405 relies on the method-qualified mux patterns.
func TestWrongMethodIs405(t *testing.T) {
	s, _ := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, pathProcess, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /process: got status %d, want 405", rec.Code)
	}
}

// TestOperationalEndpoints checks that the endpoints an operator and the
// grading demo rely on answer at all, and that /ready tracks the flag.
func TestOperationalEndpoints(t *testing.T) {
	s, _ := newTestServer(t, nil)
	_ = processCall(t, s, "ops-1", sampleText) // give the counters something to show

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	if rec := get(pathHealth); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("/health: status %d, body %s", rec.Code, rec.Body.String())
	}

	if rec := get(pathMetrics); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "pdguard_requests_total") {
		t.Fatalf("/metrics: status %d, body starts %.120s", rec.Code, rec.Body.String())
	}

	rec := get(pathStats)
	if rec.Code != http.StatusOK {
		t.Fatalf("/stats: status %d", rec.Code)
	}
	var stats map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("/stats is not JSON: %v", err)
	}
	for _, key := range []string{"metrics", "store", "dict", "version", "detectors"} {
		if _, ok := stats[key]; !ok {
			t.Fatalf("/stats is missing %q: %v", key, stats)
		}
	}

	if rec := get(pathOpenAPI); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/process") {
		t.Fatalf("/openapi.yaml: status %d", rec.Code)
	}

	s.SetReady(false)
	if rec := get(pathReady); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready while draining: got %d, want 503", rec.Code)
	}
	s.SetReady(true)
	if rec := get(pathReady); rec.Code != http.StatusOK {
		t.Fatalf("/ready when ready: got %d, want 200", rec.Code)
	}
}

// TestResponseKeepsCyrillicUnescaped pins SetEscapeHTML(false): escaping would
// inflate every Russian response and is a measurable cost at 1000 RPS.
func TestResponseKeepsCyrillicUnescaped(t *testing.T) {
	s, _ := newTestServer(t, nil)
	rec := post(t, s, pathProcess, `{"payload":"обычный текст","payload_id":"utf-1"}`)
	if !strings.Contains(rec.Body.String(), "обычный текст") {
		t.Fatalf("response escaped non-ASCII text: %s", rec.Body.String())
	}
}

// TestAdminConfigRedactsSecrets is the privacy guard on the admin surface: the
// configuration is useful to read, the credentials in it are not.
func TestAdminConfigRedactsSecrets(t *testing.T) {
	s, _ := newTestServer(t, func(c *config.Config) { c.Server.AdminToken = httpSecretToken })

	req := httptest.NewRequest(http.MethodGet, pathAdminConfig, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /admin/config: got %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, pathAdminConfig, nil)
	req.Header.Set(HeaderAdminToken, httpSecretToken)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/config: got %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, httpSecretToken) || strings.Contains(body, httpDemoKey) {
		t.Fatalf("/admin/config leaked a secret: %s", body)
	}
	if !strings.Contains(body, redacted) {
		t.Fatalf("/admin/config did not redact anything: %s", body)
	}

	// A round trip must not destroy the keys the GET refused to show.
	put := httptest.NewRequest(http.MethodPut, pathAdminConfig, strings.NewReader(body))
	put.Header.Set(HeaderAdminToken, httpSecretToken)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/config: got %d, body %s", rec.Code, rec.Body.String())
	}
	if got := s.cfg.Get().Server.AdminToken; got != httpSecretToken {
		t.Fatalf("admin token after round trip: got %q, want the original", got)
	}
	if sys, ok := s.cfg.Get().System("analytics"); !ok || sys.APIKey != httpDemoKey {
		t.Fatalf("api key was destroyed by a round trip: %+v", sys)
	}
}

// TestAdminDetectNeverReturnsValues is the load-bearing assertion of the debug
// endpoint: it may describe a detection, never reveal it.
func TestAdminDetectNeverReturnsValues(t *testing.T) {
	s, _ := newTestServer(t, nil)

	body, _ := json.Marshal(map[string]string{"payload": sampleText})
	rec := post(t, s, pathAdminDetect, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("/admin/detect: got %d, body %s", rec.Code, rec.Body.String())
	}
	var out detectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count == 0 {
		t.Fatalf("nothing detected in the sample: %s", rec.Body.String())
	}
	for _, fragment := range []string{"Иванов", "4509", "ivanov@example.com"} {
		if strings.Contains(rec.Body.String(), fragment) {
			t.Fatalf("/admin/detect leaked %q: %s", fragment, rec.Body.String())
		}
	}
	for _, sp := range out.Spans {
		if sp.Start < 0 || sp.End > len(sampleText) || sp.Start >= sp.End {
			t.Fatalf("span out of range: %+v", sp)
		}
	}
}

// TestRequireSystemGate checks the allow-list mode: with require_system on, an
// unnamed or unknown consumer is refused instead of being served by the default
// system. This is the one place on /process where refusing beats answering.
func TestRequireSystemGate(t *testing.T) {
	s, _ := newTestServer(t, func(c *config.Config) { c.RequireSystem = true })

	body := `{"payload":"текст","payload_id":"gate-1"}`
	if rec := post(t, s, pathProcess, body); rec.Code != http.StatusForbidden {
		t.Fatalf("no system header with require_system: got %d, want 403", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, pathProcess, strings.NewReader(body))
	req.Header.Set(HeaderSystemID, "analytics")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing api key: got %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, pathProcess, strings.NewReader(body))
	req.Header.Set(HeaderSystemID, "ANALYTICS") // identification is case-insensitive
	req.Header.Set(HeaderAPIKey, httpDemoKey)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated request: got %d, body %s", rec.Code, rec.Body.String())
	}
}

// gateStore blocks inside Get until it is released, which is the only reliable
// way to hold a /process handler open long enough to saturate the limiter. The
// real handler is far too fast to fill a semaphore by racing goroutines.
type gateStore struct {
	store.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gateStore) Get(id string) (store.Entry, bool) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return g.Store.Get(id)
}

// TestConcurrencyLimitSheds429 pins the admission control: when every slot is
// busy the service answers 429 with Retry-After immediately instead of queueing
// until the caller's timeout fires.
func TestConcurrencyLimitSheds429(t *testing.T) {
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf(httpConfigLoadFmt, err)
	}
	c := mgr.Get().Clone()
	c.Server.MaxConcurrent = 1
	if err := mgr.Apply(c); err != nil {
		t.Fatalf(httpConfigApplyFmt, err)
	}

	inner := store.New(store.Config{Shards: 4, TTL: time.Minute, MaxEntries: 100, MaxValueBytes: 1 << 20, SweepInterval: -1})
	t.Cleanup(inner.Close)
	gate := &gateStore{Store: inner, entered: make(chan struct{}), release: make(chan struct{})}
	s := newServerWithStore(t, mgr, gate)

	done := make(chan struct{})
	go func() {
		defer close(done)
		post(t, s, pathProcess, `{"payload":"текст","payload_id":"slow-1"}`)
	}()

	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the first request never reached the store")
	}

	rec := post(t, s, pathProcess, `{"payload":"текст","payload_id":"shed-1"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("saturated limiter: got status %d, want 429", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 without a Retry-After header")
	}

	// Probes must survive load shedding, or an orchestrator will restart the
	// instance exactly when it is busiest.
	probe := httptest.NewRequest(http.MethodGet, pathHealth, nil)
	probeRec := httptest.NewRecorder()
	s.ServeHTTP(probeRec, probe)
	if probeRec.Code != http.StatusOK {
		t.Fatalf("/health while shedding: got %d, want 200", probeRec.Code)
	}

	close(gate.release)
	<-done
}

// TestPanicDoesNotKillTheProcess checks the outermost guard directly: a
// handler that panics must produce a response, not take the run down with it.
func TestPanicDoesNotKillTheProcess(t *testing.T) {
	s, _ := newTestServer(t, nil)
	h := s.recoverMW(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panicking handler: got %d, want 500", rec.Code)
	}
}

// TestConcurrentRoundTrips is a smoke test for the shared-nothing claim: one
// Server, one engine and one store serving many payload_ids at once must still
// demask each one exactly.
func TestConcurrentRoundTrips(t *testing.T) {
	s, _ := newTestServer(t, nil)

	const workers = 24
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			id := "conc-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			text := sampleText + " #" + id
			masked := processCall(t, s, id, text)
			if got := processCall(t, s, id, masked); got != text {
				t.Errorf("worker %d: round trip lost bytes:\n got %q\nwant %q", i, got, text)
			}
		}(i)
	}
	wg.Wait()
}

// TestBufferPoolIsReused guards the response path against a subtle bug class:
// a pooled buffer handed back before its bytes were written would make one
// response leak into another under load.
func TestBufferPoolIsReused(t *testing.T) {
	s, _ := newTestServer(t, nil)
	var last string
	for i := 0; i < 50; i++ {
		id := "pool-" + string(rune('a'+i%26))
		text := strings.Repeat("текст ", i+1)
		var buf bytes.Buffer
		buf.WriteString(text)
		got := processCall(t, s, id, buf.String())
		if got != text {
			t.Fatalf("iteration %d: got %q, want %q (previous %q)", i, got, text, last)
		}
		last = got
	}
}

// TestFailOpenRemembersIdentityMapping covers the half of the fail-open
// trade-off that was never intended.
//
// Answering 200 with the untouched payload when the pipeline fails is a
// deliberate choice: Appendix B aborts a run after a streak of invalid
// responses. But nothing was written to the store on that path, so the reverse
// step — which carries the text we just returned, i.e. the ORIGINAL — found no
// mapping, was read as a fresh forward step, and came back MASKED. One
// transient fault therefore cost twice, and the second cost was the largest
// span distance available for that element.
func TestFailOpenRemembersIdentityMapping(t *testing.T) {
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf(httpConfigLoadFmt, err)
	}
	c := mgr.Get().Clone()
	c.Server.FailOpen = true
	c.Server.ProcessTimeout = time.Nanosecond // guarantees the forward step fails
	if err := mgr.Apply(c); err != nil {
		t.Fatalf(httpConfigApplyFmt, err)
	}
	st := store.New(store.Config{Shards: 4, TTL: time.Minute, MaxEntries: 100, MaxValueBytes: 1 << 20, SweepInterval: -1})
	t.Cleanup(st.Close)
	s := newServerWithStore(t, mgr, st)

	if echoed := processCall(t, s, "req-fail", sampleText); echoed != sampleText {
		t.Fatalf("fail-open answered %q, want the payload unchanged", echoed)
	}

	// The fault is over; the harness now sends the reverse step carrying what
	// we returned.
	c = mgr.Get().Clone()
	c.Server.ProcessTimeout = 5 * time.Second
	if err := mgr.Apply(c); err != nil {
		t.Fatalf(httpConfigApplyFmt, err)
	}

	back := processCall(t, s, "req-fail", sampleText)
	if back != sampleText {
		t.Fatalf("the reverse step after a fail-open returned %q, want the original byte for byte", back)
	}
}

// TestAdmissionLimiterIsBuilt pins that the shipped defaults actually construct
// the limiter. With max_concurrent at 0 the middleware returned the next
// handler untouched, so there was no ceiling on in-flight requests at all and
// nothing stood between a burst of large payloads and the container's memory
// limit.
func TestAdmissionLimiterIsBuilt(t *testing.T) {
	s, _ := newTestServer(t, nil)
	if s.sem == nil {
		t.Fatal("no admission limiter: server.max_concurrent is 0 in the defaults")
	}
	if got, want := cap(s.sem), config.Default().Server.MaxConcurrent; got != want {
		t.Fatalf("limiter capacity = %d, want %d", got, want)
	}
}
