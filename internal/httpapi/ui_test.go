package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const uiDoctype = "<!doctype html"

// getUI performs a GET against the server and returns the recorded response.
func getUI(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// TestDemoPageIsServed pins the thing the demo actually depends on: the bare
// host shows the product. A judge who types localhost:8080 and gets a 404 sees
// a broken service, whatever the benchmark says.
func TestDemoPageIsServed(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, path := range []string{pathUI, pathDemo} {
		rec := getUI(t, s, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != contentTypeHTML {
			t.Fatalf("GET %s: Content-Type %q, want %q", path, ct, contentTypeHTML)
		}
		body := rec.Body.String()
		if !strings.HasPrefix(strings.TrimSpace(body), uiDoctype) {
			t.Fatalf("GET %s: body does not start with a doctype: %.60s", path, body)
		}
		if n, _ := strconv.Atoi(rec.Header().Get("Content-Length")); n != len(body) {
			t.Fatalf("GET %s: Content-Length %s does not match %d bytes", path, rec.Header().Get("Content-Length"), len(body))
		}
	}
}

// TestDemoPageHasNoExternalReferences is the offline guarantee. The demo room
// may have no network, and the page must never reach for a CDN, a font service
// or an image host. Checking the bytes is cheap and catches the one mistake
// that is invisible on a developer laptop with working WiFi.
func TestDemoPageHasNoExternalReferences(t *testing.T) {
	body := string(demoPage)
	for _, bad := range []string{"http://", "https://", "//cdn", "//fonts", "@import"} {
		if strings.Contains(body, bad) {
			t.Fatalf("the demo page references something external (%q); everything must be inline", bad)
		}
	}
	// The page also must not persist what a judge types.
	for _, bad := range []string{"localStorage", "sessionStorage", "document.cookie", "indexedDB"} {
		if strings.Contains(body, bad) {
			t.Fatalf("the demo page uses %s; entered personal data must not be persisted", bad)
		}
	}
}

// TestDemoPageCarriesLockdownHeaders checks the policy that keeps a page full
// of somebody's real personal data from talking to anywhere but this origin.
func TestDemoPageCarriesLockdownHeaders(t *testing.T) {
	s, _ := newTestServer(t, nil)
	rec := getUI(t, s, pathUI)

	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("Content-Security-Policy %q is missing %q", csp, want)
		}
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestCatchAllRouteDoesNotSwallowAPIRoutes is the regression this change is
// most likely to cause: "GET /" matches every unclaimed path in a Go 1.22 mux,
// so a careless registration would answer HTML where the harness expects JSON.
// Every route the specification and the operators depend on is checked here.
func TestCatchAllRouteDoesNotSwallowAPIRoutes(t *testing.T) {
	s, _ := newTestServer(t, nil)

	// The graded contract first: POST /process must still work and still
	// answer JSON, not a web page.
	rec := post(t, s, pathProcess, `{"payload":"Иванов Иван Иванович","payload_id":"ui-route-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /process after adding the UI: status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != contentTypeJSON {
		t.Fatalf("POST /process: Content-Type %q, want %q", ct, contentTypeJSON)
	}
	if strings.Contains(rec.Body.String(), "Иванов Иван Иванович") {
		t.Fatalf("POST /process returned the payload unmasked: %s", rec.Body.String())
	}

	for _, path := range []string{pathHealth, pathReady, pathMetrics, pathStats, pathAdminConfig, pathOpenAPI} {
		r := getUI(t, s, path)
		if r.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, r.Code)
		}
		if strings.Contains(r.Body.String(), uiDoctype) {
			t.Fatalf("GET %s served the demo page instead of its own response", path)
		}
	}

	// POST /admin/detect is what the page draws its highlights from; the
	// catch-all is GET-only and must not shadow it.
	if r := post(t, s, pathAdminDetect, `{"payload":"карта 4509 1234 5678 9012"}`); r.Code != http.StatusOK {
		t.Fatalf("POST /admin/detect: status %d, want 200", r.Code)
	}

	// GET /process is still a 405 from the mux, not a page.
	if r := getUI(t, s, pathProcess); r.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /process: status %d, want 405", r.Code)
	}
}

// TestUnknownPathIsStillNotFound pins the reason the root route is anchored
// with {$}. An unanchored "GET /" would make every one of these paths render
// the demo page, so a typo in an admin route would look like success.
func TestUnknownPathIsStillNotFound(t *testing.T) {
	s, _ := newTestServer(t, nil)
	for _, path := range []string{"/admin/typo", "/nope", "/process/extra", "/demo/extra"} {
		rec := getUI(t, s, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), uiDoctype) {
			t.Fatalf("GET %s served the demo page instead of a 404", path)
		}
	}
}
