package detect

import (
	"testing"

	"pdguard/internal/pd"
)

const (
	addrtNizhnyNovgorodPrep = "Нижнем Новгороде"
	addrtMalayaBronnaya     = "Малая Бронная"
	addrtMaloyBronnoy       = "Малой Бронной"
	addrtNizhnegoNovgoroda  = "Нижнего Новгорода"
)

// TestAddressMultiWordCity covers the markerless multi-word city in every case
// form: the head adjective and the head noun must both be inflected and both be
// covered by the CITY span.
func TestAddressMultiWordCity(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    []wantAddr
	}{
		{
			name:    "nominative city with street and house",
			payload: "Клиент проживает: Нижний Новгород, улица Малая Бронная, дом 7, квартира 12.",
			want: []wantAddr{
				{pd.TypeCity, "Нижний Новгород"},
				{pd.TypeStreet, addrtMalayaBronnaya},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "genitive city behind из",
			payload: "Письмо клиенту из Нижнего Новгорода, адрес: ул. Малая Бронная, д. 7, кв. 12.",
			want: []wantAddr{
				{pd.TypeCity, addrtNizhnegoNovgoroda},
				{pd.TypeStreet, addrtMalayaBronnaya},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "prepositional city behind в городе",
			payload: "Клиент проживает в городе Нижнем Новгороде на улице Тверской в доме 7, квартира 12.",
			want: []wantAddr{
				{pd.TypeCity, addrtNizhnyNovgorodPrep},
				{pd.TypeStreet, "Тверской"},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "prepositional city with adjective street before marker",
			payload: "Составь ответ клиенту, который живёт в Нижнем Новгороде на Малой Бронной улице, дом 7, квартира 12.",
			want: []wantAddr{
				{pd.TypeCity, addrtNizhnyNovgorodPrep},
				{pd.TypeStreet, addrtMaloyBronnoy},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "city behind г. marker",
			payload: "Проживает в г. Нижнем Новгороде, на ул. Малой Бронной, д. 7, кв. 12.",
			want: []wantAddr{
				{pd.TypeCity, addrtNizhnyNovgorodPrep},
				{pd.TypeStreet, addrtMaloyBronnoy},
				{pd.TypeHouse, "7"},
				{pd.TypeApartment, "12"},
			},
		},
		{
			name:    "genitive city behind г. marker",
			payload: "Уроженец г. Нижнего Новгорода",
			want:    []wantAddr{{pd.TypeCity, addrtNizhnegoNovgoroda}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkAddr(t, c.payload, c.want) })
	}
}

// TestAddressRunOnHouseFlat covers the space-free "дом-квартира" written right
// after a street: both digits must be closed by a span.
func TestAddressRunOnHouseFlat(t *testing.T) {
	checkAddr(t, "Отправь письмо по адресу 125009, Москва, ул. Тверская, 7-12.", []wantAddr{
		{pd.TypePostalCode, "125009"},
		{pd.TypeCity, "Москва"},
		{pd.TypeStreet, "Тверская"},
		{pd.TypeHouse, "7"},
		{pd.TypeApartment, "12"},
	})
}

// TestAddressMultiWordNegatives pins the false-positive price of the widened
// recall: none of these sentences is anybody's address.
func TestAddressMultiWordNegatives(t *testing.T) {
	for _, payload := range []string{
		"Нижний ящик стола пуст.",
		"В 7-12 классах занятия отменены.",
		"Малой кровью не обойтись.",
		"Великий пост начался.",
	} {
		if got := runAddr(t, payload); len(got) != 0 {
			t.Errorf(addrtNoSpansFmt, payload, dumpAddr(payload, got))
		}
	}
}
