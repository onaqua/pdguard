package engine

import (
	"testing"
	"time"

	"pdguard/internal/pd"
	"pdguard/internal/pd/detect"
)

func TestResolveScaling(t *testing.T) {
	en := func(pd.Type) bool { return true }
	for _, size := range []int{32 << 10, 64 << 10, 128 << 10, 250 << 10} {
		txt := bigText(size)
		ctx := detect.NewContext(txt, en)
		st := time.Now()
		sp := detect.Run(ctx)
		t.Logf("single-chunk %6d bytes: Run=%v spans=%d", len(txt), time.Since(st), len(sp))
	}
	// isolate Resolve: feed it the raw (unresolved) candidate set
	txt := bigText(250 << 10)
	ctx := detect.NewContext(txt, en)
	var raw []pd.Span
	for _, d := range detect.Detectors() {
		raw = append(raw, d.Detect(ctx)...)
	}
	st := time.Now()
	out := detect.Resolve(raw)
	t.Logf("Resolve alone: raw=%d kept=%d in %v", len(raw), len(out), time.Since(st))
}
