package detect

import (
	"testing"

	"pdguard/internal/pd"
)

// TestAddressHyphenCity covers hyphenated compound city names whose first part
// declines while the tail stays fixed ("Ростов-на-Дону") or declines as an
// adjective ("Петропавловск-Камчатский"). The whole hyphenated chain must be
// masked as one CITY span, never just its head.
func TestAddressHyphenCity(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantAddr
	}{
		{
			name:    "rostov nominative",
			payload: "Клиент проживает: Ростов-на-Дону, улица Тверская, дом 7, квартира 12.",
			want: []wantAddr{
				{pd.TypeCity, "Ростов-на-Дону"},
				{pd.TypeStreet, "Тверская"},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "rostov genitive",
			payload: "Письмо клиенту из Ростова-на-Дону, адрес: ул. Тверская, д. 7, кв. 12.",
			want: []wantAddr{
				{pd.TypeCity, "Ростова-на-Дону"},
				{pd.TypeStreet, "Тверская"},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "rostov prepositional",
			payload: "Составь ответ клиенту, который живёт в Ростове-на-Дону на Тверской улице, дом 7, квартира 12.",
			want: []wantAddr{
				{pd.TypeCity, "Ростове-на-Дону"},
				{pd.TypeStreet, "Тверской"},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "komsomolsk",
			payload: "Доставка в Комсомольск-на-Амуре, ул. Ленина, д. 5.",
			want: []wantAddr{
				{pd.TypeCity, "Комсомольск-на-Амуре"},
				{pd.TypeStreet, "Ленина"},
				{pd.TypeHouse, "5"},
			},
		},
		{
			name:    "petropavlovsk nominative",
			payload: "Адрес: Петропавловск-Камчатский, ул. Мира, д. 3.",
			want: []wantAddr{
				{pd.TypeCity, "Петропавловск-Камчатский"},
				{pd.TypeStreet, "Мира"},
				{pd.TypeHouse, "3"},
			},
		},
		{
			name:    "petropavlovsk prepositional",
			payload: "Клиент живёт в Петропавловске-Камчатском на улице Мира, дом 3.",
			want: []wantAddr{
				{pd.TypeCity, "Петропавловске-Камчатском"},
				{pd.TypeStreet, "Мира"},
				{pd.TypeHouse, "3"},
			},
		},
		{
			name:    "kamensk",
			payload: "Проживает в Каменске-Уральском, ул. Победы, д. 9.",
			want: []wantAddr{
				{pd.TypeCity, "Каменске-Уральском"},
				{pd.TypeStreet, "Победы"},
				{pd.TypeHouse, "9"},
			},
		},
		{
			name:    "saint petersburg",
			payload: "Доставить по адресу: Санкт-Петербург, Невский проспект, 28.",
			want: []wantAddr{
				{pd.TypeCity, "Санкт-Петербург"},
				{pd.TypeStreet, "Невский"},
				{pd.TypeHouse, "28"},
			},
		},
		{
			name:    "ulan ude",
			payload: "Клиент из Улан-Удэ, ул. Смолина, д. 4.",
			want: []wantAddr{
				{pd.TypeCity, "Улан-Удэ"},
				{pd.TypeStreet, "Смолина"},
				{pd.TypeHouse, "4"},
			},
		},
		{
			name:    "yoshkar ola nominative",
			payload: "Адрес: Йошкар-Ола, ул. Комсомольская, д. 2.",
			want: []wantAddr{
				{pd.TypeCity, "Йошкар-Ола"},
				{pd.TypeStreet, "Комсомольская"},
				{pd.TypeHouse, "2"},
			},
		},
		{
			name:    "yoshkar ola genitive",
			payload: "Клиент из Йошкар-Олы, ул. Пушкина, д. 6.",
			want: []wantAddr{
				{pd.TypeCity, "Йошкар-Олы"},
				{pd.TypeStreet, "Пушкина"},
				{pd.TypeHouse, "6"},
			},
		},
		{
			name:    "yoshkar ola prepositional",
			payload: "Живёт в Йошкар-Оле на улице Пушкина, дом 6.",
			want: []wantAddr{
				{pd.TypeCity, "Йошкар-Оле"},
				{pd.TypeStreet, "Пушкина"},
				{pd.TypeHouse, "6"},
			},
		},
		{
			name:    "not a hyphenated city",
			payload: "Работа по схеме точка-на-точке.",
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkAddr(t, tc.payload, tc.want)
		})
	}
}
