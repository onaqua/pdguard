package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/llm"
	"pdguard/internal/logging"
	"pdguard/internal/metrics"
	"pdguard/internal/pd/mask"
)

// chatRequest is the OpenAI-compatible request body. Unknown fields are
// accepted, matching the /process convention: a client that adds a field must
// not be turned away.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []llm.Message `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	// PDGuard is populated only when the caller asks for it with
	// X-PDGuard-Debug: 1. It carries the masked messages and the raw answer,
	// which are safe to show to the caller but must never reach a log.
	PDGuard *pdguardDebug `json:"pdguard,omitempty"`
}

type pdguardDebug struct {
	MaskedMessages []llm.Message `json:"masked_messages"`
	LLMAnswer      string        `json:"llm_answer"`
	PDTypes        []string      `json:"pd_types"`
	TimingsMS      timings       `json:"timings_ms"`
}

type timings struct {
	Mask    int64 `json:"mask"`
	LLM     int64 `json:"llm"`
	Restore int64 `json:"restore"`
}

// handleChat implements POST /v1/chat/completions: it masks the incoming
// messages, guards against a leak, calls the LLM with the masked text and
// restores the answer before returning it to the caller.
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if d := chatTimeout(s.cfg.Get()); d > 0 {
		// The chat route is allowed to outlive the server's write timeout:
		// the LLM call plus masking can exceed it, and cutting the response
		// off mid-stream would turn a good answer into a 502.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Now().Add(d))
		_ = rc.SetReadDeadline(time.Now().Add(d))
	}
	systemID, authStatus := s.authorizeChat(r)
	if authStatus != 0 {
		s.writeError(w, authStatus, "system is unknown, disabled, or the API key does not match")
		return
	}
	sys, ok := s.cfg.Resolve(systemID)
	if !ok || sys == nil {
		s.writeError(w, http.StatusForbidden, "system is unknown or disabled")
		return
	}
	if s.llm == nil {
		s.writeError(w, http.StatusServiceUnavailable, "llm upstream is not configured")
		return
	}
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeDecodeError(w, err)
		return
	}
	if len(req.Messages) == 0 {
		s.writeError(w, http.StatusBadRequest, "messages is required")
		return
	}
	debug := r.Header.Get("X-PDGuard-Debug") == "1"

	if status, msg := s.checkLLMRate(w); status != http.StatusOK {
		s.logChat(sys, time.Now(), status, nil)
		s.writeError(w, status, msg)
		return
	}

	start := time.Now()
	content, answer, masked, counts, tm, status, errMsg := s.runChat(r, sys, req.Messages)
	if status != http.StatusOK {
		s.logChat(sys, start, status, counts)
		s.writeError(w, status, errMsg)
		return
	}
	s.logChat(sys, start, status, counts)

	resp := chatResponse{
		ID:      newChatID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []chatChoice{{
			Index:        0,
			Message:      chatMessage{Role: "assistant", Content: content},
			FinishReason: "stop",
		}},
	}
	if debug {
		resp.PDGuard = &pdguardDebug{
			MaskedMessages: masked,
			LLMAnswer:      answer,
			PDTypes:        distinctTypes(counts),
			TimingsMS:      tm,
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// checkLLMRate enforces the per-minute LLM call limit. It reads the live
// configuration, re-syncs the token bucket to the configured capacity and, when
// the bucket is empty, answers 429 with a Retry-After header and records the
// rejection under the "llm_rate" reason. It returns http.StatusOK when the call
// may proceed.
func (s *Server) checkLLMRate(w http.ResponseWriter) (int, string) {
	s.llmLimit.setCapacity(s.cfg.Get().LLM.RequestsPerMinute)
	ok, retryAfter := s.llmLimit.allow()
	if ok {
		return http.StatusOK, ""
	}
	metrics.IncRejected("llm_rate")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	return http.StatusTooManyRequests, "llm rate limit exceeded, retry later"
}

// runChat runs the masking pipeline: mask, leak guard, LLM call, restore. It
// returns the final content, the raw LLM answer, the masked messages, the PD
// counts, the stage timings, and the status plus message to answer with on
// failure.
func (s *Server) runChat(r *http.Request, sys *config.System, messages []llm.Message) (content, answer string, masked []llm.Message, counts map[string]int, tm timings, status int, errMsg string) {
	maskStart := time.Now()
	masked, reps, err := s.eng.MaskMessages(r.Context(), sys, messages)
	if err != nil {
		return "", "", nil, nil, timings{}, http.StatusServiceUnavailable, "masking failed"
	}
	maskDur := time.Since(maskStart)

	if s.eng.LeakGuard(r.Context(), sys, masked, reps) {
		return "", "", masked, nil, timings{}, http.StatusUnprocessableEntity, "leak guard: unmasked personal data"
	}

	llmStart := time.Now()
	answer, err = s.llm.Complete(r.Context(), masked)
	if err != nil {
		return "", "", masked, nil, timings{}, http.StatusBadGateway, "llm upstream error"
	}
	llmDur := time.Since(llmStart)

	restoreStart := time.Now()
	content = answer
	if sys.Demask {
		content = mask.RestoreText(answer, flatten(reps))
	}
	restoreDur := time.Since(restoreStart)

	return content, answer, masked, countTypes(reps), timings{
		Mask:    maskDur.Milliseconds(),
		LLM:     llmDur.Milliseconds(),
		Restore: restoreDur.Milliseconds(),
	}, http.StatusOK, ""
}

// authorizeChat resolves the consuming system for the chat route. A Bearer
// token selects the system whose api_key matches it (how OpenAI clients
// authenticate); otherwise the /process-style X-System-Id / X-API-Key headers
// are used. An unknown Bearer key with require_system on is refused with 401.
func (s *Server) authorizeChat(r *http.Request) (string, int) {
	cfg := s.cfg.Get()
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		key := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if key != "" {
			if sys := matchBearerKey(cfg, key); sys != nil {
				return sys.ID, 0
			}
			if cfg.RequireSystem {
				return "", http.StatusUnauthorized
			}
		}
	}
	return s.authorize(r, cfg.RequireSystem)
}

// matchBearerKey returns the enabled system whose api_key equals key, or nil.
func matchBearerKey(cfg *config.Config, key string) *config.System {
	for _, sys := range cfg.Systems {
		if sys != nil && sys.Enabled && sys.APIKey != "" &&
			subtle.ConstantTimeCompare([]byte(sys.APIKey), []byte(key)) == 1 {
			return sys
		}
	}
	return nil
}

// countTypes tallies personal-data occurrences by category across every
// message's replacements.
func countTypes(reps [][]mask.Replacement) map[string]int {
	counts := make(map[string]int)
	for _, rs := range reps {
		for _, r := range rs {
			counts[string(r.Type)]++
		}
	}
	return counts
}

// flatten concatenates the per-message replacement slices into one.
func flatten(reps [][]mask.Replacement) []mask.Replacement {
	total := 0
	for _, rs := range reps {
		total += len(rs)
	}
	out := make([]mask.Replacement, 0, total)
	for _, rs := range reps {
		out = append(out, rs...)
	}
	return out
}

// distinctTypes returns the sorted list of PD categories present in counts.
func distinctTypes(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for t := range counts {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// logChat records one chat request. Only the system, status, duration and PD
// category counts are logged; message texts and the API key never appear.
func (s *Server) logChat(sys *config.System, start time.Time, status int, counts map[string]int) {
	attrs := []any{
		slog.String("system", sys.ID),
		slog.Int("status", status),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
	}
	if len(counts) > 0 {
		attrs = append(attrs, logging.Types(counts))
	}
	logging.L().Info("llm chat", attrs...)
}

// newChatID returns a unique completion id.
func newChatID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	}
	return "chatcmpl-" + hex.EncodeToString(b)
}
