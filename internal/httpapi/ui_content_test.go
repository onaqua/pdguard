package httpapi

import (
	"strings"
	"testing"
)

// TestDemoPageContentPinsTheChatFlow checks that the demo console still carries
// the three labelled steps of the chat flow and the product name. These strings
// are what a judge reads on stage, so a refactor that renames them silently
// would break the demo even though every HTTP test stays green.
func TestDemoPageContentPinsTheChatFlow(t *testing.T) {
	body := string(demoPage)
	for _, want := range []string{
		"Что отправлено в ИИ",
		"Что ответил ИИ",
		"Что получил пользователь",
		"pdguard",
		"Маскирование и демаскирование",
		"/process",
		"TextEncoder",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the demo page is missing %q", want)
		}
	}
}
