package httpapi

import (
	"sync"
	"time"
)

// llmLimiter is a thread-safe token bucket that caps the number of LLM calls
// the whole process may make per minute. The capacity and refill rate come from
// the live configuration, so an operator can change the limit on the fly via
// /admin/config without restarting the service.
//
// The bucket is refilled lazily: instead of a background ticker, each call
// computes how many tokens have accrued since the last refill from the elapsed
// wall time. This keeps the limiter lock-free between requests and lets tests
// drive it with a fake clock.
type llmLimiter struct {
	mu sync.Mutex

	// now returns the current time. It is a field so tests can substitute a
	// fake clock and advance it deterministically.
	now func() time.Time

	capacity float64
	tokens   float64
	last     time.Time
}

// newLLMLimiter builds a limiter with the given per-minute capacity. A
// non-positive capacity means "no limit": every call is allowed.
func newLLMLimiter(perMinute int) *llmLimiter {
	return &llmLimiter{
		now:      time.Now,
		capacity: float64(perMinute),
		tokens:   float64(perMinute),
		last:     time.Now(),
	}
}

// setCapacity adjusts the bucket to a new per-minute capacity. The current
// token reserve is trimmed to the new capacity so a lowered limit takes effect
// immediately rather than letting a large backlog drain slowly.
func (l *llmLimiter) setCapacity(perMinute int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked()
	l.capacity = float64(perMinute)
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
}

// allow consumes one token and reports whether the call may proceed. When the
// bucket is empty it returns the number of whole seconds until the next token
// is available (at least 1), so the caller can set Retry-After.
func (l *llmLimiter) allow() (ok bool, retryAfter int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.capacity <= 0 {
		return true, 0
	}
	l.refillLocked()
	if l.tokens >= 1 {
		l.tokens--
		return true, 0
	}
	// The bucket is empty. The next token arrives after 1/rate seconds, where
	// rate is capacity/60 per second; round up to a whole second, at least 1.
	rate := l.capacity / 60
	secs := int(1/rate + 0.999)
	if secs < 1 {
		secs = 1
	}
	return false, secs
}

// refillLocked adds the tokens accrued since the last refill. Callers must hold
// l.mu.
func (l *llmLimiter) refillLocked() {
	now := l.now()
	elapsed := now.Sub(l.last).Seconds()
	if elapsed <= 0 {
		return
	}
	l.last = now
	if l.capacity <= 0 {
		return
	}
	l.tokens += elapsed * (l.capacity / 60)
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
}
