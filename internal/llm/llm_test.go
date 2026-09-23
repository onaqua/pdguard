package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// capturedRequest records what the fake upstream received.
type capturedRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// completeErrFmt is the shared failure message for a failed Complete call.
const completeErrFmt = "Complete: %v"

// newTestClient spins up an httptest server that records the request body and
// answers with the given handler, then returns the client and a way to read
// what was sent.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *capturedRequest, *string) {
	t.Helper()
	var got capturedRequest
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New(Options{BaseURL: srv.URL, Model: "m1", Timeout: time.Second, Stream: true, APIKey: "k1"})
	return c, &got, &auth
}

func TestCompleteStreamingSSE(t *testing.T) {
	c, got, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Привет\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" мир\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	msg := []Message{{Role: "user", Content: "текст"}}
	out, err := c.Complete(context.Background(), msg)
	if err != nil {
		t.Fatalf(completeErrFmt, err)
	}
	if out != "Привет мир" {
		t.Fatalf("answer = %q, want %q", out, "Привет мир")
	}
	if !got.Stream {
		t.Fatal("stream flag was not sent")
	}
	if got.Model != "m1" {
		t.Fatalf("model = %q, want m1", got.Model)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "текст" {
		t.Fatalf("messages = %+v", got.Messages)
	}
}

func TestCompleteNonStreaming(t *testing.T) {
	c, got, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ответ"}}]}`))
	})
	c.stream = false
	out, err := c.Complete(context.Background(), []Message{{Role: "user", Content: "x"}})
	if err != nil {
		t.Fatalf(completeErrFmt, err)
	}
	if out != "ответ" {
		t.Fatalf("answer = %q, want %q", out, "ответ")
	}
	if got.Stream {
		t.Fatal("stream flag should be false")
	}
}

func TestCompleteHTTPError(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	_, err := c.Complete(context.Background(), []Message{{Role: "user", Content: "x"}})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should carry the status code: %v", err)
	}
	if strings.Contains(err.Error(), "boom") {
		t.Fatalf("error must not echo the upstream body: %v", err)
	}
}

func TestCompleteDemoMode(t *testing.T) {
	c := New(Options{BaseURL: "", Model: "m", Timeout: time.Second, Stream: true})
	out, err := c.Complete(context.Background(), []Message{{Role: "user", Content: "PD_FIO_abc123"}})
	if err != nil {
		t.Fatalf(completeErrFmt, err)
	}
	if !strings.Contains(out, "PD_FIO_abc123") {
		t.Fatalf("demo answer should quote the last user message: %q", out)
	}
}

func TestCompleteSendsBearerToken(t *testing.T) {
	c, _, auth := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	})
	c.stream = false
	if _, err := c.Complete(context.Background(), []Message{{Role: "user", Content: "x"}}); err != nil {
		t.Fatalf(completeErrFmt, err)
	}
	if *auth != "Bearer k1" {
		t.Fatalf("Authorization = %q, want %q", *auth, "Bearer k1")
	}
}
