package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/engine"
	"pdguard/internal/llm"
	"pdguard/internal/store"
)

// chatSample is the payload the chat tests agree on: it carries a full name, a
// passport and a phone, so masking is guaranteed to change something.
const chatSample = "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел. +7 916 123-45-67"

const (
	chatContentTypeHeader = "Content-Type"
	chatContentTypeJSON   = "application/json"
	chatStatusBodyFmt     = "status %d, body %s"
	chatDecodeRespFmt     = "decode response: %v"
	chatLeakedName        = "Иванов"
)

// chatBody renders the OpenAI-style request for chatSample.
func chatBody() string {
	b, _ := json.Marshal(map[string]any{
		"messages": []map[string]string{{"role": "user", "content": chatSample}},
	})
	return string(b)
}

// echoRespond answers with the masked content it received, so RestoreText has
// tokens to turn back into the originals.
func echoRespond(w http.ResponseWriter, req *chatRequest) {
	content := ""
	if len(req.Messages) > 0 {
		content = req.Messages[0].Content
	}
	body, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": content}}},
	})
	w.Header().Set(chatContentTypeHeader, chatContentTypeJSON)
	_, _ = w.Write(body)
}

// errorRespond answers with a 500, as a failing upstream would.
func errorRespond(w http.ResponseWriter, req *chatRequest) {
	http.Error(w, "boom", http.StatusInternalServerError)
}

// slowRespond waits delay before answering, to exercise the chat timeout path.
func slowRespond(delay time.Duration) func(w http.ResponseWriter, req *chatRequest) {
	return func(w http.ResponseWriter, req *chatRequest) {
		time.Sleep(delay)
		echoRespond(w, req)
	}
}

// newChatServer builds a Server whose LLM client points at a fake upstream
// that records the request body and answers with respond.
func newChatServer(t *testing.T, tune func(*config.Config), respond func(w http.ResponseWriter, req *chatRequest)) (*Server, *chatRequest) {
	t.Helper()
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if tune != nil {
		c := mgr.Get().Clone()
		tune(c)
		if err := mgr.Apply(c); err != nil {
			t.Fatalf("config.Apply: %v", err)
		}
	}
	st := store.New(store.Config{Shards: 8, TTL: time.Minute, MaxEntries: 1000, MaxValueBytes: 1 << 20, SweepInterval: -1})
	t.Cleanup(st.Close)

	var recorded chatRequest
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&recorded)
		respond(w, &recorded)
	}))
	t.Cleanup(fake.Close)

	llmClient := llm.New(llm.Options{BaseURL: fake.URL, Model: "m", Timeout: time.Second, Stream: false})
	s := New(Options{
		Engine:  engine.New(engine.Options{Cfg: mgr, Store: st}),
		Cfg:     mgr,
		Store:   st,
		Version: "test",
		LLM:     llmClient,
	})
	s.SetReady(true)
	return s, &recorded
}

// chatCall posts a chat request and returns the recorded response.
func chatCall(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, s, pathChat, body)
}

func TestChatMasksBeforeLLM(t *testing.T) {
	s, recorded := newChatServer(t, nil, echoRespond)
	rec := chatCall(t, s, chatBody())
	if rec.Code != http.StatusOK {
		t.Fatalf(chatStatusBodyFmt, rec.Code, rec.Body.String())
	}
	if len(recorded.Messages) == 0 {
		t.Fatal("the LLM received no messages")
	}
	sent := recorded.Messages[0].Content
	for _, frag := range []string{chatLeakedName, "4509 123456", "916 123-45-67"} {
		if strings.Contains(sent, frag) {
			t.Fatalf("the LLM request leaked %q: %s", frag, sent)
		}
	}
	if !strings.Contains(sent, "PD_") {
		t.Fatalf("the LLM request has no mask tokens: %s", sent)
	}
}

func TestChatRestoresAnswer(t *testing.T) {
	s, _ := newChatServer(t, nil, echoRespond)
	rec := chatCall(t, s, chatBody())
	if rec.Code != http.StatusOK {
		t.Fatalf(chatStatusBodyFmt, rec.Code, rec.Body.String())
	}
	var out chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf(chatDecodeRespFmt, err)
	}
	if len(out.Choices) == 0 {
		t.Fatal("no choices in the response")
	}
	if got := out.Choices[0].Message.Content; got != chatSample {
		t.Fatalf("restored content:\n got %q\nwant %q", got, chatSample)
	}
}

func TestChatDemaskFalseReturnsTokens(t *testing.T) {
	s, _ := newChatServer(t, nil, echoRespond)
	req := httptest.NewRequest(http.MethodPost, pathChat, strings.NewReader(chatBody()))
	req.Header.Set(chatContentTypeHeader, chatContentTypeJSON)
	req.Header.Set(HeaderSystemID, "analytics")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf(chatStatusBodyFmt, rec.Code, rec.Body.String())
	}
	var out chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf(chatDecodeRespFmt, err)
	}
	content := out.Choices[0].Message.Content
	if !strings.Contains(content, "PD_") {
		t.Fatalf("demask=false must return tokens, got: %s", content)
	}
	if strings.Contains(content, chatLeakedName) {
		t.Fatalf("demask=false leaked the original: %s", content)
	}
}

func TestChatLLMErrorIs502(t *testing.T) {
	s, recorded := newChatServer(t, nil, errorRespond)
	rec := chatCall(t, s, chatBody())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502, body %s", rec.Code, rec.Body.String())
	}
	if len(recorded.Messages) > 0 {
		sent := recorded.Messages[0].Content
		for _, frag := range []string{chatLeakedName, "4509 123456", "916 123-45-67"} {
			if strings.Contains(sent, frag) {
				t.Fatalf("the LLM request leaked %q: %s", frag, sent)
			}
		}
	}
}

func TestChatSurvivesSlowLLM(t *testing.T) {
	// The chat route must not be cut off by the /process timeout: the LLM
	// answers after 300ms while process_timeout_ms is 50, so a request that
	// used the process budget would be cancelled and answered 502.
	s, _ := newChatServer(t, func(c *config.Config) {
		c.Server.ProcessTimeout = 50 * time.Millisecond
	}, slowRespond(300*time.Millisecond))
	rec := chatCall(t, s, chatBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf(chatDecodeRespFmt, err)
	}
	if len(out.Choices) == 0 {
		t.Fatal("no choices in the response")
	}
	if got := out.Choices[0].Message.Content; got != chatSample {
		t.Fatalf("restored content:\n got %q\nwant %q", got, chatSample)
	}
}

func TestChatDebugField(t *testing.T) {
	s, _ := newChatServer(t, nil, echoRespond)

	req := httptest.NewRequest(http.MethodPost, pathChat, strings.NewReader(chatBody()))
	req.Header.Set(chatContentTypeHeader, chatContentTypeJSON)
	req.Header.Set("X-PDGuard-Debug", "1")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf(chatStatusBodyFmt, rec.Code, rec.Body.String())
	}
	var withDebug chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &withDebug); err != nil {
		t.Fatalf(chatDecodeRespFmt, err)
	}
	if withDebug.PDGuard == nil {
		t.Fatal("X-PDGuard-Debug: 1 must add the pdguard field")
	}
	if len(withDebug.PDGuard.MaskedMessages) == 0 {
		t.Fatal("pdguard.masked_messages is empty")
	}

	rec = chatCall(t, s, chatBody())
	var withoutDebug chatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &withoutDebug); err != nil {
		t.Fatalf(chatDecodeRespFmt, err)
	}
	if withoutDebug.PDGuard != nil {
		t.Fatal("without X-PDGuard-Debug the pdguard field must be absent")
	}
}
