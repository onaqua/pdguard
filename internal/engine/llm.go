package engine

import (
	"context"

	"pdguard/internal/config"
	"pdguard/internal/llm"
	"pdguard/internal/pd"
	"pdguard/internal/pd/mask"
)

// MaskMessages masks personal data in a set of chat messages before they are
// sent to the LLM. Detection and filtering follow the system's rules (enabled
// types, confidence floors, requires_companion) exactly as /process does, but
// every type is masked with the LLM-configured strategy rather than the
// per-type one, so the model sees a uniform token stream.
//
// Unlike /process, no mapping is stored: the chain restores the answer with
// mask.RestoreText, which needs only the replacements, not the store.
func (e *Engine) MaskMessages(ctx context.Context, sys *config.System, messages []llm.Message) ([]llm.Message, [][]mask.Replacement, error) {
	e.syncCustom()
	cfg := e.cfg.Get()
	strategy := mask.Lookup(cfg.LLM.Strategy)
	if strategy == nil {
		strategy = e.fallback
	}
	pick := func(pd.Type) mask.Strategy { return strategy }

	out := make([]llm.Message, len(messages))
	reps := make([][]mask.Replacement, len(messages))
	for i, m := range messages {
		spans, err := e.detect(ctx, sys, m.Content)
		if err != nil {
			return nil, nil, err
		}
		spans = e.filter(sys, cfg, spans)
		res := mask.Apply(m.Content, spans, pick)
		out[i] = llm.Message{Role: m.Role, Content: res.Masked}
		reps[i] = res.Replacements
	}
	return out, reps, nil
}

// LeakGuard reports whether any masked message still carries a detected
// personal-data span that is not covered by one of our masks. It is the last
// line of defence before the LLM is called: a span that survived masking means
// the model would see unmasked personal data, so the caller must refuse.
func (e *Engine) LeakGuard(ctx context.Context, sys *config.System, masked []llm.Message, reps [][]mask.Replacement) bool {
	cfg := e.cfg.Get()
	for i, m := range masked {
		spans, err := e.detect(ctx, sys, m.Content)
		if err != nil {
			return true
		}
		spans = e.filter(sys, cfg, spans)
		for _, sp := range spans {
			if !coveredByMasks(sp, reps[i]) {
				return true
			}
		}
	}
	return false
}

// coveredByMasks reports whether a span overlaps at least one replacement's
// masked range. The replacements carry byte offsets into the masked text, so
// the check is a simple interval intersection.
func coveredByMasks(sp pd.Span, reps []mask.Replacement) bool {
	for _, r := range reps {
		if sp.Start < r.MaskEnd && r.MaskStart < sp.End {
			return true
		}
	}
	return false
}
