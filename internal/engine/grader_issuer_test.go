package engine

import (
	"context"
	"testing"
)

// TestGraderIssuerCases pins the masking of passport issue dates and issuing
// authorities end to end through the engine. The cases cover the two fixes:
// the wide verb window that lets "выдан" reach a date across a long authority
// name, and the literal "\\n" line break inside an authority name.
func TestGraderIssuerCases(t *testing.T) {
	e, _ := newEngine(t)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "issue date across long authority",
			in:   "паспорт 50 09 876543, выдан Отделом УФМС России по Московской области по г. Балашиха 25.06.2015, код подразделения 500-123",
			want: "паспорт 50 ** ****43, выдан От***** **** ****** ** ********** ******* ** *. ******ха 25.**.**15, код подразделения 50*-*23",
		},
		{
			name: "issue date across short authority",
			in:   "Паспорт 45 11 234567, выдан Отделом УФМС России по г. Москве 12.01.2011, код подразделения 770-045.",
			want: "Паспорт 45 ** ****67, выдан От***** **** ****** ** *. ****ве 12.**.**11, код подразделения 77*-*45.",
		},
		{
			name: "contract date stays",
			in:   "Кредитный договор №102 от 05.06.2023. Паспорт заёмщика: серия 4509, номер 123456.",
			want: "Кредитный договор №102 от 05.06.2023. Паспорт заёмщика: серия ****, номер 12**56.",
		},
		{
			name: "unanchored dates stay",
			in:   "Повторная проверка назначена на 12.03.1985, повторный визит — на 25.06.2015.",
			want: "Повторная проверка назначена на 12.03.1985, повторный визит — на 25.06.2015.",
		},
		{
			name: "second date after comma stays",
			in:   "Паспорт выдан 20.06.2010 в отделении полиции, прежний 01.02.2005.",
			want: "Паспорт выдан 20.**.**10 в о******** *****ии, прежний 01.02.2005.",
		},
		{
			name: "multiline authority with literal backslash n",
			in:   "УФМС,\\nг. Москва (многострочное значение)",
			want: "УФ**,\\**. ****ва (многострочное значение)",
		},
		{
			name: "quoted authority",
			in:   "ОВД «Южное» г. Москвы",
			want: "ОВ* «*****» *. ****вы",
		},
		{
			name: "two authorities in one sentence",
			in:   "Первый паспорт был выдан УФМС города Казани, повторный — ОВД «Савёловский» г. Москвы.",
			want: "Первый паспорт был выдан УФ** ****** ****ни, повторный — ОВ* «***********» *. ****вы.",
		},
		{
			name: "latin authority with escaped quotes",
			in:   "OVD \\\"Central\\\" (латинские символы)",
			want: "OV* \\\"*****al\\\" (латинские символы)",
		},
		{
			name: "passport with issue date and authority",
			in:   "Гражданин Иванов И. И. предъявил паспорт серия 4509 номер 123456, выданный УМВД России по г. Москве 12.03.2015.",
			want: "Гражданин И. И. И. предъявил паспорт серия **** номер 12**56, выданный УМ** ****** ** *. ****ве 12.**.**15.",
		},
		{
			name: "authority with department number",
			in:   "Данный документ был оформлен Отделом полиции № 5 УМВД России по г. Краснодару в установленном порядке.",
			want: "Данный документ был оформлен От***** ******* № * **** ****** ** *. ********ру в установленном порядке.",
		},
		{
			name: "authority repeated in one sentence",
			in:   "Орган выдачи УФМС России по Республике Татарстан совпадает с указанным в анкете: УФМС России по Республике Татарстан.",
			want: "Орган выдачи УФ** ****** ** ********** *******ан совпадает с указанным в анкете: УФ** ****** ** ********** *******ан.",
		},
		{
			name: "lowercase authority",
			in:   "Паспорт выдан овд «северный» города москвы в прошлом году.",
			want: "Паспорт выдан ов* «********» ****** ****вы в прошлом году.",
		},
		{
			name: "authority with mixed quotes",
			in:   "УФМС «России» по \\\"Тверской обл.\\\" (разные виды кавычек)",
			want: "УФ** «******» ** \\\"******** *бл.\\\" (разные виды кавычек)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := e.Mask(context.Background(), "", "grader", c.in)
			if err != nil {
				t.Fatalf("Mask: %v", err)
			}
			if res.Output != c.want {
				t.Errorf("Mask mismatch\n  in:   %q\n  got:  %q\n  want: %q", c.in, res.Output, c.want)
			}
		})
	}
}
