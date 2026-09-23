package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"pdguard/internal/config"
)

// TestChatCustomTypeMasksInLLMChain verifies that a custom personal-data type
// configured without touching the code is detected and masked in the LLM chain
// exactly like the built-in types: the request body the stub LLM receives must
// carry neither the custom contract number nor the built-in passport number.
func TestChatCustomTypeMasksInLLMChain(t *testing.T) {
	s, recorded := newChatServer(t, func(c *config.Config) {
		c.CustomTypes = append(c.CustomTypes, config.CustomType{
			Name:     "CONTRACT_NUMBER",
			Pattern:  `\d{2}-\d{6}`,
			Anchors:  []string{"договор"},
			Strategy: config.StrategyStarsAll,
		})
	}, echoRespond)

	body := `{"messages":[{"role":"user","content":"Договор 12-345678 и паспорт 4509 123456"}]}`
	rec := chatCall(t, s, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(recorded.Messages) == 0 {
		t.Fatal("the LLM received no messages")
	}
	sent := recorded.Messages[0].Content
	for _, frag := range []string{"12-345678", "4509 123456"} {
		if strings.Contains(sent, frag) {
			t.Fatalf("the LLM request leaked %q: %s", frag, sent)
		}
	}
}
