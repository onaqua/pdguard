package detect

import "testing"

func TestZZProbe(t *testing.T) {
	for _, in := range []string{
		"Дата рождения клиента: двенадцатое мая тысяча девятьсот девяностого года.",
		"Дата рождения: 15  /  07  /  1988 года.",
		"Дата рождения 12 . 05 . 1990",
		"Анкета: 15  /  07  /  1988 г.р.",
		"Дата рождения: 12 мая тысяча девятьсот девяностого года",
	} {
		for _, s := range dateSpans(t, in) {
			t.Logf("%q -> %q %s hint=%q conf=%v", in, in[s.Start:s.End], s.Type, s.Hint, s.Conf)
		}
	}
}
