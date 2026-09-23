package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/store"
)

// TestAdminConfigPutNotPersisted pins the read-only-filesystem contract: a PUT
// that validates and applies in memory but cannot write the file must answer
// 200 with persisted=false, and the new configuration must actually be live.
func TestAdminConfigPutNotPersisted(t *testing.T) {
	// Load a valid configuration from a real file, then replace the directory
	// with a regular file so the later persist fails on every platform without
	// depending on file permissions, which are unreliable on Windows hosts:
	// os.MkdirAll cannot turn a file into a directory.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	seed, err := config.Marshal(config.Default())
	if err != nil {
		t.Fatalf("config.Marshal: %v", err)
	}
	if err := os.WriteFile(path, seed, 0o644); err != nil {
		t.Fatalf("write seed config: %v", err)
	}
	mgr, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove config dir: %v", err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	st := store.New(store.Config{Shards: 8, TTL: time.Minute, MaxEntries: 1000, MaxValueBytes: 1 << 20, SweepInterval: -1})
	t.Cleanup(st.Close)
	s := newServerWithStore(t, mgr, st)

	// Build a valid configuration that flips require_system, so the GET after
	// the PUT can prove the change took effect.
	next := mgr.Get().Clone()
	next.RequireSystem = true
	body, err := config.Marshal(next)
	if err != nil {
		t.Fatalf("config.Marshal: %v", err)
	}

	put := httptest.NewRequest(http.MethodPut, pathAdminConfig, strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/config on read-only path: got %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status    string `json:"status"`
		Persisted bool   `json:"persisted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if out.Status != "applied" {
		t.Fatalf("status: got %q, want %q", out.Status, "applied")
	}
	if out.Persisted {
		t.Fatalf("persisted: got true, want false on a read-only path")
	}

	// The change must be live even though the file write failed.
	if got := s.cfg.Get().RequireSystem; !got {
		t.Fatalf("require_system after PUT: got %v, want true", got)
	}
	get := httptest.NewRequest(http.MethodGet, pathAdminConfig, nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/config: got %d, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"require_system": true`) {
		t.Fatalf("GET /admin/config does not show the applied change: %s", rec.Body.String())
	}
}

// TestAdminConfigPutInvalidRejected pins that a configuration failing validation
// is refused with 400 and leaves the running configuration untouched.
func TestAdminConfigPutInvalidRejected(t *testing.T) {
	s, _ := newTestServer(t, nil)

	// require_system=true with no default_system among the systems is invalid.
	bad := `{"server":{"addr":":8080"},"default_system":"missing","require_system":true,"systems":[]}`
	put := httptest.NewRequest(http.MethodPut, pathAdminConfig, strings.NewReader(bad))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, put)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid /admin/config: got %d, want 400, body %s", rec.Code, rec.Body.String())
	}
}
