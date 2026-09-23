package engine

import (
	"bytes"
	"strings"
	"testing"

	"pdguard/internal/config"
	"pdguard/internal/logging"
)

// reqLogPayload carries a full name and a passport number, so a successful
// mask is guaranteed to detect FIO and PASSPORT.
const reqLogPayload = "Клиент Иванов Иван Иванович, паспорт 4509 123456"

// captureLogs points the process logger at a buffer for the duration of fn and
// returns everything it wrote. The logger is restored afterwards so the rest of
// the suite keeps writing to stderr.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	logging.SetupWriter("debug", "json", &buf)
	t.Cleanup(func() { logging.Setup("info", "json") })
	fn()
	return buf.String()
}

// TestRequestLogListsTypesWithoutValues is the jury requirement: the per-request
// summary names the detected PD categories and their counts, and never the
// values themselves.
func TestRequestLogListsTypesWithoutValues(t *testing.T) {
	e, _ := newEngine(t)
	out := captureLogs(t, func() {
		mustProcess(t, e, "req-log-1", reqLogPayload)
	})

	if !strings.Contains(out, `"request"`) {
		t.Fatalf("no per-request summary in log output:\n%s", out)
	}
	for _, typ := range []string{"FIO", "PASSPORT"} {
		if !strings.Contains(out, typ) {
			t.Fatalf("request summary is missing type %s:\n%s", typ, out)
		}
	}
	for _, frag := range []string{"Иванов", "4509 123456"} {
		if strings.Contains(out, frag) {
			t.Fatalf("request summary leaked %q:\n%s", frag, out)
		}
	}
}

// TestRequestLogDisabledSuppressesSummary checks the log.requests switch: with
// it off, no per-request summary is written even though the request succeeds.
func TestRequestLogDisabledSuppressesSummary(t *testing.T) {
	e, _ := newEngineWith(t, func(c *config.Config) { c.Log.Requests = false })
	out := captureLogs(t, func() {
		mustProcess(t, e, "req-log-2", reqLogPayload)
	})

	if strings.Contains(out, `"request"`) {
		t.Fatalf("request summary written despite log.requests=false:\n%s", out)
	}
}
