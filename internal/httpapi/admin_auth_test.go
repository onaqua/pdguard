package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pdguard/internal/config"
)

// adminAuthToken is the shared secret used to exercise the /admin/* gate.
const adminAuthToken = "admin-auth-secret"

// TestAdminConfigRequiresTokenWhenSet pins the security boundary: once an admin
// token is configured, GET and PUT /admin/config must refuse callers that do
// not present it, and accept those that do.
func TestAdminConfigRequiresTokenWhenSet(t *testing.T) {
	s, _ := newTestServer(t, func(c *config.Config) { c.Server.AdminToken = adminAuthToken })

	// A valid configuration body for the PUT: the GET with the token returns
	// exactly what a PUT would accept back.
	get := httptest.NewRequest(http.MethodGet, pathAdminConfig, nil)
	get.Header.Set(HeaderAdminToken, adminAuthToken)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/config with token: got %d, want 200", rec.Code)
	}
	validBody := rec.Body.String()

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(method, pathAdminConfig, strings.NewReader(validBody))
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s /admin/config without token: got %d, want 401", method, rec.Code)
		}

		req = httptest.NewRequest(method, pathAdminConfig, strings.NewReader(validBody))
		req.Header.Set(HeaderAdminToken, adminAuthToken)
		rec = httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s /admin/config with token: got %d, want 200", method, rec.Code)
		}
	}
}

// TestAdminDetectIsOpenWithoutToken guards the demo path: the console calls
// /admin/detect with no token, so the endpoint must stay reachable even when an
// admin token is configured. It only reads, so opening it leaks no write path.
func TestAdminDetectIsOpenWithoutToken(t *testing.T) {
	s, _ := newTestServer(t, func(c *config.Config) { c.Server.AdminToken = adminAuthToken })

	body := `{"payload":"Клиент Иванов Иван Иванович, паспорт 4509 123456"}`
	req := httptest.NewRequest(http.MethodPost, pathAdminDetect, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/detect without token: got %d, want 200", rec.Code)
	}
}
