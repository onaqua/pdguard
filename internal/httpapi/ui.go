package httpapi

import (
	_ "embed"
	"net/http"
	"strconv"
)

const (
	contentTypeHTML = "text/html; charset=utf-8"

	// demoCSP pins the page to this origin. default-src 'none' denies every
	// fetch the page does not explicitly need; 'unsafe-inline' is required
	// because the whole point is that the script and the style live in the
	// document, and no 'self' or host source is granted for scripts, so the
	// page cannot pull code from anywhere at all. connect-src 'self' leaves
	// exactly one capability: calling this service's own endpoints.
	demoCSP = "default-src 'none'; " +
		"script-src 'unsafe-inline'; " +
		"style-src 'unsafe-inline'; " +
		"img-src data:; " +
		"connect-src 'self'; " +
		"base-uri 'none'; " +
		"form-action 'none'; " +
		"frame-ancestors 'none'"

	// demoCacheControl forbids serving the page from cache without asking.
	// A cached copy is the classic way to lose ten minutes on stage: the
	// binary is rebuilt, the judge reloads, and the browser hands back the
	// previous page. The document is one same-origin fetch of well under a
	// megabyte and is requested once per demo, so freshness is worth far more
	// here than the saved round trip.
	demoCacheControl = "no-cache"
)

// handleUI serves the demo console on / and /demo.
//
// The root route is registered as the anchored pattern "GET /{$}", not as
// "GET /": the unanchored form is ServeMux's catch-all and would claim every
// path nobody else registered, so a mistyped /admin route would render a web
// page and GET /process would stop reporting 405. Anchoring keeps the rest of
// the routing table exactly as it was.
//
// The handler does no work at start-up, owns no goroutine and touches neither
// the engine nor the store, so POST /process is unaffected whether or not
// anyone ever opens the page.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if len(demoPage) == 0 {
		s.writeError(w, http.StatusNotFound, "the demo console is not bundled in this build")
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentTypeHTML)
	h.Set("Content-Length", strconv.Itoa(len(demoPage)))
	h.Set("Content-Security-Policy", demoCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", demoCacheControl)
	w.WriteHeader(http.StatusOK)
	// net/http drops the body for a HEAD request on its own, so the GET
	// pattern covering HEAD needs no special case here.
	_, _ = w.Write(demoPage)
}
