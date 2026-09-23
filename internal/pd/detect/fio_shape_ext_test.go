package detect

import (
	"testing"

	"pdguard/internal/pd"
)

// TestFIOShapeExtPositive covers surnames that are not in the dictionary and do
// not look like surnames by ending, but are accepted in strong contexts (a
// dictionary given name, initials, or a strong client anchor): adjective
// surnames like «Задорожный» and surnames on «-арь» like «Бондарь».
func TestFIOShapeExtPositive(t *testing.T) {
	cases := []struct{ in, want, hint string }{
		{"Клиент Дмитрий Задорожный открыл счёт.", "Дмитрий Задорожный", "surname_name"},
		{"Клиент Задорожный Дмитрий открыл счёт.", "Задорожный Дмитрий", "surname_name"},
		{"Ольга Задорожная просит закрыть карту.", "Ольга Задорожная", "surname_name"},
		{"Встреча с Задорожным Никитой перенесена.", "Задорожным Никитой", "surname_name"},
		{"Илья Бондарь просит закрыть карту.", "Илья Бондарь", "surname_name"},
		{"Бондарь Илья просит закрыть карту.", "Бондарь Илья", "surname_name"},
		{"Клиент Д. Ю. Задорожный открыл счёт.", "Д. Ю. Задорожный", "surname_initials"},
		{"И. С. Бондарь просит закрыть карту.", "И. С. Бондарь", "surname_initials"},
		{"Клиент Задорожный Д. Ю. открыл счёт.", "Задорожный Д. Ю.", "surname_initials"},
		{"Клиент Бондарь открыл счёт.", "Бондарь", "surname"},
		{"Клиентка Задорожная открыла счёт.", "Задорожная", "surname"},
		{"Клиент Бондарь И.С. открыл счёт.", "Бондарь И.С.", "surname_initials"},
		{"Клиент Перешеин И.С. открыл счёт.", "Перешеин И.С.", "surname_initials"},
	}
	for _, c := range cases {
		fioAssertOneSpan(t, c.in, pd.TypeFIO, c.want, c.hint)
	}
}

// TestFIOShapeExtNegative pins that common adjectives are never taken for
// surnames even in strong contexts, and that a bare adjective without a strong
// context is not masked at all.
func TestFIOShapeExtNegative(t *testing.T) {
	fioAssertSpans(t, "Клиент Новый открыл счёт.")
	fioAssertSpans(t, "Анна Главная в списке.")
	fioAssertSpans(t, "Нижний ящик пуст.")
	fioAssertSpans(t, "Встреча с Новым годом.")
}
