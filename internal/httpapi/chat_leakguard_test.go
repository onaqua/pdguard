package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// leakGuardSamples are realistic chat prompts that carry personal data but
// must not trip the leak guard: every value is masked before the LLM call, so
// the guard must not see a surviving unmasked span and refuse with 422.
var leakGuardSamples = []string{
	"Составь короткое вежливое письмо клиенту Иванову Ивану Ивановичу: паспорт 4509 123456 проверен, карта 4276 3801 2345 6789 перевыпущена, позвоним по номеру +7 916 123-45-67.",
	"Клиент Смирнов Алексей Викторович, дата рождения 12.03.1985, место рождения г. Казань. Паспорт 45 11 234567, выдан Отделом УФМС России по г. Москве 12.01.2011, код подразделения 770-045. Адрес регистрации: г. Москва, ул. Арбат, д. 10, кв. 5. ИНН 771234567859, e-mail a.smirnov85@example.ru, CVV-код 321, PIN-код 1234. Подготовь краткую справку.",
	"Кто такой Александр Пушкин? Ответь одним предложением.",
	"Переведи на английский: Держатель карты IVAN IVANOV, счёт 40817810099910004312.",
}

// leakGuardFragments are the raw personal-data values that must never reach
// the LLM upstream for any of the samples above.
var leakGuardFragments = []string{
	"4509 123456",
	"4276 3801 2345 6789",
	"771234567859",
	"a.smirnov85@example.ru",
	"40817810099910004312",
}

func TestChatLeakGuardNoFalsePositive(t *testing.T) {
	for i, sample := range leakGuardSamples {
		body, _ := json.Marshal(map[string]any{
			"messages": []map[string]string{{"role": "user", "content": sample}},
		})
		s, recorded := newChatServer(t, nil, echoRespond)
		rec := chatCall(t, s, string(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("sample %d: status %d, want 200, body %s", i, rec.Code, rec.Body.String())
		}
		if len(recorded.Messages) == 0 {
			t.Fatalf("sample %d: the LLM received no messages", i)
		}
		sent := recorded.Messages[0].Content
		for _, frag := range leakGuardFragments {
			if strings.Contains(sent, frag) {
				t.Fatalf("sample %d: the LLM request leaked %q: %s", i, frag, sent)
			}
		}
	}
}
