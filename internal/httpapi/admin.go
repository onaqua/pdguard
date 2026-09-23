package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"pdguard/internal/config"
	"pdguard/internal/logging"
	"pdguard/internal/pd"
	"pdguard/internal/pd/detect"
)

// redacted replaces every secret in an outgoing configuration. It is also
// recognised on the way back in: a PUT that carries it for a system keeps that
// system's existing key, so the obvious GET-edit-PUT loop cannot destroy a
// secret it was never shown.
const redacted = "***"

// detectRequest is the debug endpoint's input.
type detectRequest struct {
	Payload string `json:"payload"`
}

// detectHit describes one detection. There is deliberately no field for the
// matched text, and none may ever be added: this endpoint is meant to be safe
// to call on real data during a demo, and a response that carried the values
// would put personal data into whatever captured the HTTP exchange — a browser
// history, a proxy log, a screen recording. Offsets and lengths are enough to
// explain a detection; the caller already holds the text and can slice it
// itself if it genuinely needs to.
type detectHit struct {
	Type  string  `json:"type"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Len   int     `json:"len"`
	Conf  float64 `json:"conf"`
	Src   string  `json:"src"`
	Hint  string  `json:"hint,omitempty"`
}

// detectResponse is the debug report.
type detectResponse struct {
	Bytes  int            `json:"bytes"`
	Count  int            `json:"count"`
	Types  map[string]int `json:"types"`
	Spans  []detectHit    `json:"spans"`
	System string         `json:"system"`
}

// adminAuth reports whether the caller may touch /admin/*.
//
// The token comes from the environment first (main passes PDGUARD_ADMIN_TOKEN)
// and from the configuration second, because a deployment should be able to set
// it without putting it in the file that /admin/config prints. An empty token
// leaves the routes open, which is what a laptop demo wants and what a
// deployment must not do — the start-up log says so out loud.
func (s *Server) adminAuth(w http.ResponseWriter, r *http.Request) bool {
	want := s.adminToken
	if want == "" {
		want = s.cfg.Get().Server.AdminToken
	}
	if want == "" {
		return true
	}
	got := r.Header.Get(HeaderAdminToken)
	if got == "" {
		// Accept the bearer form too: curl users and most API clients reach for
		// Authorization before a custom header.
		if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
			got = strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
		}
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		s.writeError(w, http.StatusUnauthorized, "admin token is missing or wrong")
		return false
	}
	return true
}

// handleAdminConfigGet returns the running configuration with every secret
// replaced by redacted. The endpoint exists so an operator can see what the
// process actually believes, which is not always what the file on disk says
// after a PUT on a read-only filesystem.
func (s *Server) handleAdminConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	safe := redactSecrets(s.cfg.Get().Clone())
	body, err := config.Marshal(safe)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "cannot render configuration")
		return
	}
	// config.Marshal already produces the canonical on-disk shape, so the body
	// is written as-is rather than re-encoded through writeJSON: what you read
	// here is exactly what a PUT would accept back.
	h := w.Header()
	h.Set("Content-Type", contentTypeJSON)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// redactSecrets blanks every credential in a configuration snapshot. It mutates
// the clone it is given, never the live snapshot.
func redactSecrets(c *config.Config) *config.Config {
	if c == nil {
		return nil
	}
	if c.Server.AdminToken != "" {
		c.Server.AdminToken = redacted
	}
	for _, sys := range c.Systems {
		if sys != nil && sys.APIKey != "" {
			sys.APIKey = redacted
		}
	}
	return c
}

// handleAdminConfigPut replaces the running configuration.
//
// Validation, the atomic swap and the persist are all config.Manager.Apply's
// job; this handler only parses, restores the secrets the GET hid, and reports
// the outcome. A rejected configuration leaves the running one untouched, so a
// bad PUT can never take the service down mid-run.
func (s *Server) handleAdminConfigPut(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeDecodeError(w, err)
		return
	}
	next, err := config.Unmarshal(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	restoreSecrets(next, s.cfg.Get())
	if err := s.cfg.Apply(next); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The live config now drives the timeout, the body cap and the fail-open
	// switch on the next request. The concurrency semaphore is the exception:
	// its capacity is fixed at start-up (see Server.sem), so a changed
	// max_concurrent needs a restart, and saying so beats a silent no-op.
	logging.L().Info("configuration applied via /admin/config",
		"systems", len(next.Systems),
		"require_system", next.RequireSystem,
		"fail_open", next.Server.FailOpen,
	)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":                 "applied",
		"persisted":              s.cfg.Path() != "",
		"max_concurrent_applies": false,
	})
}

// restoreSecrets copies credentials the client could not have known back from
// the running configuration, so a round-tripped GET does not wipe them.
func restoreSecrets(next, cur *config.Config) {
	if next == nil || cur == nil {
		return
	}
	if next.Server.AdminToken == redacted {
		next.Server.AdminToken = cur.Server.AdminToken
	}
	for id, sys := range next.Systems {
		if sys == nil || sys.APIKey != redacted {
			continue
		}
		if old, ok := cur.System(id); ok && old != nil {
			sys.APIKey = old.APIKey
		} else {
			sys.APIKey = ""
		}
	}
}

func (s *Server) handleAdminDetect(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	var req detectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeDecodeError(w, err)
		return
	}
	sys := s.resolveDetectSystem(r)
	out := buildDetectResponse(req.Payload, sys)
	s.writeJSON(w, http.StatusOK, out)
}

// resolveDetectSystem picks the system the debug endpoint should judge against.
func (s *Server) resolveDetectSystem(r *http.Request) *config.System {
	cfg := s.cfg.Get()
	sysID := strings.TrimSpace(r.Header.Get(HeaderSystemID))
	sys, ok := cfg.System(sysID)
	if !ok || sys == nil {
		sys, _ = cfg.System(cfg.DefaultSystem)
	}
	return sys
}

// buildDetectResponse runs detection and filters the spans by the system's
// rules, mirroring what the engine would mask.
func buildDetectResponse(payload string, sys *config.System) detectResponse {
	enabled := func(t pd.Type) bool {
		if sys == nil {
			return true
		}
		rule, ok := sys.Rule(t)
		return ok && rule.Enabled
	}
	spans := detect.Run(detect.NewContext(payload, enabled))
	out := detectResponse{
		Bytes: len(payload),
		Types: make(map[string]int, 8),
		Spans: make([]detectHit, 0, len(spans)),
	}
	if sys != nil {
		out.System = sys.ID
	}
	for _, sp := range spans {
		if !spanAllowed(sys, sp) {
			continue
		}
		name := string(sp.Type)
		out.Types[name]++
		out.Spans = append(out.Spans, detectHit{
			Type: name, Start: sp.Start, End: sp.End, Len: sp.Len(),
			Conf: sp.Conf, Src: sp.Src, Hint: sp.Hint,
		})
	}
	out.Count = len(out.Spans)
	return out
}

// spanAllowed reports whether a detection passes the system's enabled and
// confidence rules.
func spanAllowed(sys *config.System, sp pd.Span) bool {
	if sys == nil {
		return true
	}
	rule, ok := sys.Rule(sp.Type)
	if !ok || !rule.Enabled {
		return false
	}
	floor := rule.MinConfidence
	if floor <= 0 {
		floor = config.DefaultMinConfidence
	}
	return sp.Conf >= floor
}
