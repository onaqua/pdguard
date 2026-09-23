// Package llm is a minimal OpenAI-compatible chat client used by the LLM
// masking chain. It speaks only the subset of the protocol the chain needs:
// one POST to /chat/completions with a model, a message list and a stream
// flag, and a plain-text answer read back either from a JSON body or from an
// SSE stream.
//
// The client is deliberately small and dependency-free. It never logs the
// request body or the API key, and an upstream HTTP error is reported as a
// status code without echoing the request that caused it.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Message is one chat turn. Role is "system", "user" or "assistant".
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Options configure a Client. All fields except APIKey come from the llm
// configuration block; APIKey is read from the environment by the caller so it
// never lives in a file.
type Options struct {
	BaseURL string
	Model   string
	Timeout time.Duration
	Stream  bool
	CAFile  string
	APIKey  string
}

// Client is an OpenAI-compatible chat client. It is safe for concurrent use:
// it holds no per-request state.
type Client struct {
	baseURL string
	model   string
	stream  bool
	apiKey  string
	http    *http.Client
}

// New builds a Client from its options. A nil or zero timeout falls back to a
// minute, so a misconfigured deployment cannot hang forever.
func New(o Options) *Client {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if o.CAFile != "" {
		if pool, err := systemPoolWith(o.CAFile); err == nil {
			tr.TLSClientConfig.RootCAs = pool
		}
	}
	return &Client{
		baseURL: strings.TrimRight(o.BaseURL, "/"),
		model:   o.Model,
		stream:  o.Stream,
		apiKey:  o.APIKey,
		http:    &http.Client{Timeout: timeout, Transport: tr},
	}
}

// systemPoolWith returns the system certificate pool with the extra PEM bundle
// at path appended. On any failure it returns the system pool alone, so a bad
// CA file degrades to the default trust store rather than breaking the client.
func systemPoolWith(path string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("llm: no certificates parsed from CA file")
	}
	return pool, nil
}

// chatRequest is the wire body sent to the upstream.
type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// chatResponse is the non-streaming answer.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// streamChunk is one SSE data payload of a streaming answer.
type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

// Complete sends the messages to the upstream and returns the assistant's
// answer as plain text. When the client was built with an empty base URL it
// answers with the built-in demo model instead of touching the network.
func (c *Client) Complete(ctx context.Context, messages []Message) (string, error) {
	if c.baseURL == "" {
		return demoAnswer(messages), nil
	}
	body, err := json.Marshal(chatRequest{Model: c.model, Messages: messages, Stream: c.stream})
	if err != nil {
		return "", fmt.Errorf("llm: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: upstream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The request body is deliberately not included: it may carry masked
		// text, and the error must never echo it.
		return "", fmt.Errorf("llm: upstream status %d", resp.StatusCode)
	}
	if c.stream {
		return readStream(resp.Body)
	}
	return readJSON(resp.Body)
}

// readJSON parses a non-streaming response body.
func readJSON(r io.Reader) (string, error) {
	var out chatResponse
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return "", fmt.Errorf("llm: decode response: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("llm: empty choices in response")
	}
	return out.Choices[0].Message.Content, nil
}

// readStream parses an SSE body: lines prefixed with "data: " carry a JSON
// chunk whose choices[0].delta.content is appended to the answer, and the
// stream ends at "data: [DONE]".
func readStream(r io.Reader) (string, error) {
	var sb strings.Builder
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}
		var chunk streamChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			return "", fmt.Errorf("llm: decode stream chunk: %w", err)
		}
		if len(chunk.Choices) > 0 {
			sb.WriteString(chunk.Choices[0].Delta.Content)
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("llm: read stream: %w", err)
	}
	return sb.String(), nil
}

// demoAnswer renders the offline demo model's reply. It quotes the content of
// the last user message verbatim so the chain visibly shows that the model
// received only masks.
func demoAnswer(messages []Message) string {
	content := ""
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			content = messages[i].Content
			break
		}
	}
	return "Демо-модель (LLM не подключена). Получен запрос: «" + content + "»."
}
