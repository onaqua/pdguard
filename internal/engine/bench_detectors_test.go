package engine

import (
	"testing"

	"pdguard/internal/pd"
	"pdguard/internal/pd/detect"
)

func BenchmarkPerDetector(b *testing.B) {
	txt := sparseText(4096)
	en := func(pd.Type) bool { return true }
	ctx := detect.NewContext(txt, en)
	for _, d := range detect.Detectors() {
		d := d
		b.Run(d.Name(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = d.Detect(ctx)
			}
		})
	}
	b.Run("_NewContext", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = detect.NewContext(txt, en)
		}
	})
}
