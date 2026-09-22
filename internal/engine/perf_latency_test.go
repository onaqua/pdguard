package engine

import (
	"context"
	"strings"
	"testing"
	"time"
)

func bigText(n int) string {
	unit := "Клиент Иванов Иван Иванович, дата рождения 12.03.1985, паспорт 4509 123456 выдан ОУФМС России по г. Москве, " +
		"проживает по адресу г. Москва, ул. Тверская, д. 12, кв. 5, телефон +7 (916) 123-45-67, почта ivanov.ivan@mail.ru, " +
		"СНИЛС 112-233-445 95, ИНН 771234567890, карта 4276 1600 1234 5678. Стихи Александра Пушкина он любит с детства. "
	var sb strings.Builder
	for sb.Len() < n {
		sb.WriteString(unit)
		sb.WriteString("\n")
	}
	return sb.String()
}

func TestLatencyBudget(t *testing.T) {
	e := newEng(t)
	for _, size := range []int{1 << 10, 64 << 10, 350 << 10, 700 << 10} {
		txt := bigText(size)
		st := time.Now()
		r, err := e.Process(context.Background(), "", "perf", txt)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("in=%d bytes -> %v (spans=%d)", len(txt), time.Since(st), r.Spans)
	}
}
