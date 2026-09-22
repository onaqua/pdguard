package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"pdguard/internal/logging"
	"pdguard/internal/metrics"
)

// chain wraps h in the given middlewares so that mw[0] sees the request first
// and the response last. Writing the composition here instead of nesting the
// calls by hand keeps the order in one readable list (see Server.build).
func chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// ---------------------------------------------------------------------------
// The pipeline, outermost first. The order is not arbitrary:
//
//  1. recover   — must see every panic, including one raised inside another
//     layer, so nothing may sit above it. A single panic taking the
//     process down would end a load-testing run, which costs far more
//     than one bad response.
//  2. metrics   — counts and times everything that got past the panic guard,
//     including the 429s produced below it. Placing it under the
//     limiter would hide exactly the numbers you need when the
//     service is shedding.
//  3. limit     — sheds before any work is done. The specification allows 429
//     under load and honours Retry-After, and answering 429 in
//     microseconds is much better than queueing until the client's
//     10-second timeout fires.
//  4. timeout   — bounds the handler once it is admitted. Under the limiter,
//     so a request that never started does not burn its budget
//     waiting for a slot.
//  5. bodyLimit — caps the body before any handler reads it.
//  6. log       — innermost, so it reports the status the handler actually
//     produced, and so the hot path skips it cheaply when the level
//     or the sampler says no. It never logs a payload.
//
// ---------------------------------------------------------------------------

func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &respWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// The panic value can embed request data, so only the recovered
			// value's own text and the stack are logged — never the body.
			logging.L().LogAttrs(r.Context(), slog.LevelError, "panic in handler",
				slog.String("path", r.URL.Path),
				slog.Any("panic", rec),
				slog.String("stack", string(debug.Stack())),
			)
			if !rw.wroteHeader {
				rw.Header().Set("Content-Type", contentTypeJSON)
				rw.WriteHeader(http.StatusInternalServerError)
				_, _ = rw.Write([]byte(`{"error":"internal error"}` + "\n"))
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

func (s *Server) metricsMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		metrics.IncInflight()
		defer metrics.DecInflight()

		next.ServeHTTP(w, r)

		rw, ok := w.(*respWriter)
		if !ok || rw.engineServed {
			return
		}
		metrics.Observe(rw.op, rw.status, time.Since(start), 0, 0)
	})
}

func (s *Server) limitMW(next http.Handler) http.Handler {
	if s.sem == nil {
		return next
	}
	retryAfter := strconv.Itoa(int(retryAfterHint.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Probes are never shed: an orchestrator that reads a load-shedding
		// 429 as "unhealthy" would take the instance out of rotation exactly
		// when it is working hardest.
		if r.URL.Path == pathHealth || r.URL.Path == pathReady {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			metrics.IncRejected("inflight_limit")
			h := w.Header()
			h.Set("Content-Type", contentTypeJSON)
			h.Set("Retry-After", retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"busy","retry_after":` + retryAfter + "}\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) timeoutMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := s.cfg.Get().Server.ProcessTimeout
		if d <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// http.TimeoutHandler is deliberately not used: it buffers the whole response
// in memory before writing it, which for a 100k-token payload doubles the peak
// footprint of every request, and it writes its own 503 that would break the
// /process contract. A context deadline lets the engine stop early and lets the
// handler decide what to answer.

func (s *Server) bodyLimitMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := s.cfg.Get().Server.MaxBodyBytes; n > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)

		lg := logging.L()
		if !lg.Enabled(r.Context(), slog.LevelDebug) || !logging.ShouldSample() {
			return
		}
		status := 0
		var written int64
		if rw, ok := w.(*respWriter); ok {
			status, written = rw.status, rw.written
		}
		lg.LogAttrs(r.Context(), slog.LevelDebug, "http",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int64("bytes_in", r.ContentLength),
			slog.Int64("bytes_out", written),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
	})
}

// respWriter records what the handler answered so the layers above it can log
// and count without a second source of truth.
//
// It is installed by the recover layer rather than by the metrics layer,
// because the panic guard is the outermost thing in the pipeline and has to
// know whether a status line already went out before it writes its own 500.
type respWriter struct {
	http.ResponseWriter
	status      int
	written     int64
	wroteHeader bool

	// engineServed marks a request the engine already reported to the metrics
	// package. engine.observe publishes the op/status/latency series itself so
	// that non-HTTP callers are counted too, so the metrics layer must not
	// publish a second sample for the same request.
	engineServed bool
	// op is the operation label for requests the metrics layer does count.
	op string
}

func (w *respWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *respWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush keeps streaming responses working through the wrapper; /metrics writes
// a large body and benefits from not being buffered by an intermediary.
func (w *respWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *respWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// markEngineServed tells the metrics layer that the engine already published
// this request's counters. A handler that did not reach the engine leaves the
// flag alone and gets counted by the layer instead.
func markEngineServed(w http.ResponseWriter, op string) {
	if rw, ok := w.(*respWriter); ok {
		rw.engineServed = true
		rw.op = op
	}
}
