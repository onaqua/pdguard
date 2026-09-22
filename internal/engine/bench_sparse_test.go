package engine

import (
	"context"
	"strings"
	"testing"
)

// sparse: ordinary Russian prose with one PD-bearing sentence per ~10.
func sparseText(n int) string {
	prose := "Банк рассматривает заявку в течение трёх рабочих дней и уведомляет о решении. " +
		"Условия обслуживания описаны в тарифах, размещённых на официальном сайте. " +
		"При досрочном погашении проценты пересчитываются по фактическому сроку пользования. " +
		"Отделение работает по будням с девяти до девятнадцати часов без перерыва. " +
		"Стихи Александра Пушкина изучают в школе. "
	pdline := "Заявитель Иванов Иван Иванович, телефон +7 (916) 123-45-67, паспорт 4509 123456. "
	var sb strings.Builder
	i := 0
	for sb.Len() < n {
		sb.WriteString(prose)
		if i%2 == 0 {
			sb.WriteString(pdline)
		}
		sb.WriteString("\n")
		i++
	}
	return sb.String()
}

func BenchmarkSparseText(b *testing.B) {
	for _, size := range []int{1024, 4096, 16384} {
		txt := sparseText(size)
		b.Run(strings.Repeat("", 0)+itoaSmall(len(txt)), func(b *testing.B) {
			m, _ := loadDefault()
			e := newEngB(m)
			b.ReportAllocs()
			b.SetBytes(int64(len(txt)))
			for i := 0; i < b.N; i++ {
				_, _ = e.Mask(context.Background(), "", "k", txt)
			}
		})
	}
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
