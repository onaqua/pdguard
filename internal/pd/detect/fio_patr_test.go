package detect

import (
	"testing"
)

const fioPatrIlyaSergeevich = "Илья Сергеевич"

// fioPatrSpan is one expected span: the substring and its byte range.
type fioPatrSpan struct {
	sub string
	off int
}

// fioPatrCheck asserts that the detector returns exactly the expected spans.
func fioPatrCheck(t *testing.T, in string, want []fioPatrSpan) {
	t.Helper()
	got := fioSpansIn(t, in)
	if len(got) != len(want) {
		t.Fatalf("%q: got %d spans, want %d: %v", in, len(got), len(want), got)
	}
	for i, w := range want {
		s := got[i]
		if s.Start != w.off || s.End != w.off+len(w.sub) || in[s.Start:s.End] != w.sub {
			t.Errorf("%q: span %d = [%d:%d] %q, want [%d:%d] %q",
				in, i, s.Start, s.End, in[s.Start:s.End], w.off, w.off+len(w.sub), w.sub)
		}
	}
}

func TestFioPatrNeighbourSurname(t *testing.T) {
	cases := []struct {
		in   string
		want []fioPatrSpan
	}{
		{"Клиент Задорожный Дмитрий Юрьевич открыл счёт.",
			[]fioPatrSpan{{"Задорожный Дмитрий Юрьевич", 13}}},
		{"Нет данных от Задорожного Дмитрия Юрьевича за март.",
			[]fioPatrSpan{{"Задорожного Дмитрия Юрьевича", 25}}},
		{"Составь письмо Задорожной Анне Петровне.",
			[]fioPatrSpan{{"Задорожной Анне Петровне", 28}}},
		{"Бондарь Мария Ивановна просит закрыть карту.",
			[]fioPatrSpan{{"Бондарь Мария Ивановна", 0}}},
		{"Держатель карты — Мария Ивановна Бондарь.",
			[]fioPatrSpan{{"Мария Ивановна Бондарь", 34}}},
		{"Договор подписан Кравчуком Петром Кузьмичом вчера.",
			[]fioPatrSpan{{"Кравчуком Петром Кузьмичом", 32}}},
		{"составь письмо перешеину илье сергеевичу о долге",
			[]fioPatrSpan{{"перешеину илье сергеевичу", 28}}},
		{"Отправь Анне Петровне уведомление.",
			[]fioPatrSpan{{"Анне Петровне", 15}}},
		{"Поздравь Анну Петровну с днём рождения.",
			[]fioPatrSpan{{"Анну Петровну", 17}}},
		{"Отправь Анне Петровне Перешеиной уведомление.",
			[]fioPatrSpan{{"Анне Петровне Перешеиной", 15}}},
	}
	for _, c := range cases {
		fioPatrCheck(t, c.in, c.want)
	}
}

func TestFioPatrNeighbourSurnameNegatives(t *testing.T) {
	cases := []struct {
		in   string
		want []fioPatrSpan
	}{
		{"Уважаемая Мария Ивановна, ваша заявка одобрена.",
			[]fioPatrSpan{{"Мария Ивановна", 19}}},
		{"Дорогой Илья Сергеевич!",
			[]fioPatrSpan{{fioPatrIlyaSergeevich, 15}}},
		{"Спасибо, Илья Сергеевич.",
			[]fioPatrSpan{{fioPatrIlyaSergeevich, 16}}},
		{"Пишите Илье Сергеевичу.",
			[]fioPatrSpan{{"Илье Сергеевичу", 13}}},
		{"Москва Илья Сергеевич",
			[]fioPatrSpan{{fioPatrIlyaSergeevich, 13}}},
		{"Творчество Александра Сергеевича Пушкина изучают в школе.",
			nil},
		{"Памятник Петру Ильичу открыт.",
			nil},
	}
	for _, c := range cases {
		fioPatrCheck(t, c.in, c.want)
	}
}
