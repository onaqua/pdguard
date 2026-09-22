package engine

import (
	"context"
	"strconv"
	"testing"
)

func BenchmarkPayloadSizes(b *testing.B) {
	for _, size := range []int{512, 2048, 8192, 32768} {
		txt := bigText(size)
		b.Run(strconv.Itoa(len(txt)), func(b *testing.B) {
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
