package httpapi

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"pdguard/internal/config"
)

// fakeClock is a controllable time source for the LLM rate limiter.
type fakeClock struct {
	t time.Time
}

func (f *fakeClock) now() time.Time { return f.t }

func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

// TestChatLLMRateLimit caps the LLM chain at two calls per minute: the first
// two requests succeed, the third is refused with 429 and a Retry-After header,
// and after the clock advances past the refill interval a request succeeds
// again.
func TestChatLLMRateLimit(t *testing.T) {
	s, _ := newChatServer(t, func(c *config.Config) {
		c.LLM.RequestsPerMinute = 2
	}, echoRespond)
	clock := &fakeClock{t: time.Now()}
	s.llmLimit.now = clock.now

	for i := 0; i < 2; i++ {
		rec := chatCall(t, s, chatBody())
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200, body %s", i+1, rec.Code, rec.Body.String())
		}
	}

	rec := chatCall(t, s, chatBody())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status %d, want 429, body %s", rec.Code, rec.Body.String())
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 response must carry a Retry-After header")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a whole number >= 1", ra)
	}

	// With a limit of 2/min the refill rate is 2/60 per second, so after 30
	// seconds at least one token has accrued and the next call succeeds.
	clock.advance(31 * time.Second)
	rec = chatCall(t, s, chatBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("request after refill: status %d, want 200, body %s", rec.Code, rec.Body.String())
	}
}

// TestChatLLMRateLimitZeroDisables checks that a zero limit means "no limit":
// five consecutive requests all succeed.
func TestChatLLMRateLimitZeroDisables(t *testing.T) {
	s, _ := newChatServer(t, func(c *config.Config) {
		c.LLM.RequestsPerMinute = 0
	}, echoRespond)

	for i := 0; i < 5; i++ {
		rec := chatCall(t, s, chatBody())
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200, body %s", i+1, rec.Code, rec.Body.String())
		}
	}
}
