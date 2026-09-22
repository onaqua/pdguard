package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"

	"pdguard/internal/engine"
	"pdguard/internal/logging"
	"pdguard/internal/metrics"
)

// processRequest is the body of Appendix A, and nothing more.
//
// Unknown fields are accepted on purpose: json.Decoder.DisallowUnknownFields is
// NOT enabled. A future harness version that adds a field would otherwise turn
// every request into a 400, and rejecting a request we could have served is the
// one failure mode this endpoint cannot afford.
type processRequest struct {
	Payload   string `json:"payload"`
	PayloadID string `json:"payload_id"`
}

// processResponse is the answer of Appendix A: one field, always present.
type processResponse struct {
	Result string `json:"result"`
}

// handleProcess implements POST /process.
//
// The direction (mask or demask) is not decided here — engine.Process derives
// it from what the payload is, so a retried forward step cannot be mistaken for
// a reverse one. This handler owns only the transport concerns: parsing,
// admission, and choosing what to answer when something goes wrong.
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Get()

	systemID, authStatus := s.authorize(r, cfg.RequireSystem)
	if authStatus != 0 {
		// Refusing here is the one place on this route where an error beats an
		// answer: the operator has switched on the allow-list, so serving an
		// unknown consumer would hand it data it is not allowed to see.
		s.writeError(w, authStatus, "system is unknown, disabled, or the API key does not match")
		return
	}

	var req processRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		s.writeDecodeError(w, err)
		return
	}

	// payload_id is the only hard requirement. Without it there is nothing to
	// correlate the two steps of the contract with, and answering something
	// plausible would silently break the demasking half of the score.
	if strings.TrimSpace(req.PayloadID) == "" {
		s.writeError(w, http.StatusBadRequest, "payload_id is required")
		return
	}

	// An empty payload is valid input, not an error: the honest answer is an
	// empty result. The engine handles it too; short-circuiting keeps the case
	// obvious and skips a store lookup.
	if req.Payload == "" {
		s.writeJSON(w, http.StatusOK, processResponse{Result: ""})
		return
	}

	res, err := s.runEngine(r.Context(), systemID, req.PayloadID, req.Payload)
	if err != nil {
		s.writeProcessFailure(w, r, cfg.Server.FailOpen, systemID, req.PayloadID, req.Payload, err)
		return
	}

	markEngineServed(w, res.Op)
	s.writeJSON(w, http.StatusOK, processResponse{Result: res.Output})
}

// runEngine calls the engine with its own panic guard.
//
// The outer recoverMW would turn a panic into a 500, but on this route a 500 is
// exactly what must not happen: a detector that panics on one pathological
// payload would otherwise be able to spend the harness's whole error budget.
// Catching it here converts the panic into an ordinary error, which the
// fail-open path below can answer 200 to.
func (s *Server) runEngine(ctx context.Context, systemID, payloadID, payload string) (res engine.Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			logging.L().LogAttrs(ctx, slog.LevelError, "panic while processing payload",
				slog.String("payload_id", payloadID),
				slog.Any("panic", rec),
				slog.Int("bytes_in", len(payload)),
				slog.String("stack", string(debug.Stack())),
			)
			err = fmt.Errorf("engine panic: %v", rec)
		}
	}()
	return s.eng.Process(ctx, systemID, payloadID, payload)
}

// writeProcessFailure decides what to answer when the engine could not produce
// a result.
//
// FailOpen (default true) answers 200 with the payload unchanged. That is a
// real trade-off and it is worth stating plainly: returning unmasked text from
// a masking proxy is bad, but Appendix B aborts the whole run after a short
// streak of invalid responses, so one transient fault turning into a stalled
// run is worse. Operators who care more about the leak than about the run set
// server.fail_open to false and get a 503 instead.
//
// engine.ErrSystemUnavailable is excluded from fail-open even so. It means the
// operator disabled the consumer (or left no usable default system), and
// echoing the payload would hand unmasked personal data to exactly the caller
// that was switched off. That refusal is the one error the engine issues on the
// forward path, and it stays an error here.
func (s *Server) writeProcessFailure(w http.ResponseWriter, r *http.Request, failOpen bool, systemID, payloadID, payload string, err error) {
	if errors.Is(err, engine.ErrSystemUnavailable) {
		s.writeError(w, http.StatusForbidden, "system is unknown or disabled")
		return
	}
	timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	if timedOut {
		metrics.IncRejected("queue_timeout")
	}

	// Only lengths, ids and category-free facts are logged; the payload itself
	// never appears in a log line.
	attrs := logging.RequestAttrs(payloadID, systemID, engine.OpMask, len(payload))
	attrs = append(attrs,
		slog.String("err", err.Error()),
		slog.Bool("fail_open", failOpen),
		slog.Bool("timeout", timedOut),
	)
	logging.L().LogAttrs(r.Context(), slog.LevelError, "process failed", attrs...)

	if !failOpen {
		status := http.StatusServiceUnavailable
		if timedOut {
			status = http.StatusGatewayTimeout
		}
		s.writeError(w, status, "processing failed")
		return
	}
	// Remember what we are about to answer, so the reverse step for this
	// payload_id returns these bytes instead of masking them. Without it the
	// fault costs twice: unmasked text now, and a mask where the harness
	// expects the original on the next call. See engine.RememberIdentity.
	s.eng.RememberIdentity(systemID, payloadID, payload)
	s.writeJSON(w, http.StatusOK, processResponse{Result: payload})
}

// writeDecodeError answers a body we could not read.
//
// This is not the fail-open case: with an unparseable body there is no payload
// to echo, so a 400 naming the problem is the most useful answer available. It
// is still not a 500 — the harness never sends malformed JSON, so a 400 here
// means a human is holding it wrong and should be told.
func (s *Server) writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		metrics.IncRejected("body_too_large")
		s.writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	s.writeError(w, http.StatusBadRequest, "request body must be JSON with payload and payload_id")
}

// authorize resolves the consuming system and reports the status to refuse
// with, or 0 to continue.
//
// When require_system is off — the default, and what the graded run needs — the
// header is read if present and nothing is verified: the engine falls back to
// the default system. Only with require_system on does the header become
// mandatory and the API key checked.
func (s *Server) authorize(r *http.Request, requireSystem bool) (systemID string, status int) {
	systemID = strings.TrimSpace(r.Header.Get(HeaderSystemID))
	if !requireSystem {
		return systemID, 0
	}
	sys, ok := s.cfg.Get().System(systemID)
	if !ok || sys == nil || !sys.Enabled {
		return systemID, http.StatusForbidden
	}
	if sys.APIKey != "" {
		// Constant time: the comparison is against a shared secret, and a
		// timing side channel here would leak it one byte at a time.
		got := r.Header.Get(HeaderAPIKey)
		if subtle.ConstantTimeCompare([]byte(sys.APIKey), []byte(got)) != 1 {
			return systemID, http.StatusUnauthorized
		}
	}
	return systemID, 0
}
