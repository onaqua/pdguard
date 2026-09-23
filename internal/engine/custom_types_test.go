package engine

import (
	"testing"

	"pdguard/internal/config"
)

// contractPattern is the regexp of the CONTRACT_NUMBER custom type used across
// these tests.
const contractPattern = `\d{2}-\d{6}`

// contractAnchors is the anchor word that must precede a contract number.
const contractAnchors = "договор"

// contractPayload is a sentence carrying a contract number next to its anchor.
const contractPayload = "Договор 12-345678 подписан"

// contractMasked is the expected mask of contractPayload under stars_keep2.
const contractMasked = "Договор 12-****78 подписан"

// addContractType appends the CONTRACT_NUMBER custom type to a configuration.
func addContractType(c *config.Config) {
	c.CustomTypes = append(c.CustomTypes, config.CustomType{
		Name:     "CONTRACT_NUMBER",
		Pattern:  contractPattern,
		Anchors:  []string{contractAnchors},
		Strategy: config.StrategyStarsKeep2,
	})
}

// TestCustomTypeMasksWithAnchor checks that a custom type masks a value only
// when its anchor word stands nearby.
func TestCustomTypeMasksWithAnchor(t *testing.T) {
	e, _ := newEngineWith(t, addContractType)

	res := mustProcess(t, e, "custom-anchor", contractPayload)
	if res.Output != contractMasked {
		t.Fatalf("masked = %q, want %q", res.Output, contractMasked)
	}

	noAnchor := "Артикул 12-345678"
	res = mustProcess(t, e, "custom-no-anchor", noAnchor)
	if res.Output != noAnchor {
		t.Fatalf("no-anchor output = %q, want unchanged %q", res.Output, noAnchor)
	}
}

// TestCustomTypeEnabledByApply checks that applying a new configuration through
// Manager.Apply enables a custom type without restarting the engine.
func TestCustomTypeEnabledByApply(t *testing.T) {
	e, _ := newEngineWith(t, nil)

	before := mustProcess(t, e, "custom-before", contractPayload)
	if before.Output != contractPayload {
		t.Fatalf("before apply output = %q, want unchanged %q", before.Output, contractPayload)
	}

	c := e.cfg.Get().Clone()
	addContractType(c)
	if err := e.cfg.Apply(c); err != nil {
		t.Fatalf("config.Apply: %v", err)
	}

	after := mustProcess(t, e, "custom-after", contractPayload)
	if after.Output != contractMasked {
		t.Fatalf("after apply output = %q, want %q", after.Output, contractMasked)
	}
}

// TestCustomFamousPeopleVeto checks that a dictionary addition vetoes masking a
// public figure, while the same name is masked without the addition (the FIO
// detector renders it as "И. И. написал роман.").
func TestCustomFamousPeopleVeto(t *testing.T) {
	famous := "Иван Иванов написал роман."

	e, _ := newEngineWith(t, func(c *config.Config) {
		c.Dictionaries.FamousPeople = []string{"иван иванов"}
	})
	res := mustProcess(t, e, "famous-veto", famous)
	if res.Output != famous {
		t.Fatalf("with addition output = %q, want unchanged %q", res.Output, famous)
	}

	e2, _ := newEngineWith(t, nil)
	res = mustProcess(t, e2, "famous-plain", famous)
	if res.Output == famous {
		t.Fatalf("without addition output = %q, want it masked", res.Output)
	}
}

// TestCustomTypeValidationErrors checks that an invalid pattern and a name that
// collides with a built-in type are rejected by validation.
func TestCustomTypeValidationErrors(t *testing.T) {
	mgr, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	badPattern := mgr.Get().Clone()
	badPattern.CustomTypes = []config.CustomType{{
		Name: "BAD_PATTERN", Pattern: "[", Strategy: config.StrategyStarsKeep2,
	}}
	if err := mgr.Apply(badPattern); err == nil {
		t.Fatal("invalid pattern: Apply succeeded, want error")
	}

	badName := mgr.Get().Clone()
	badName.CustomTypes = []config.CustomType{{
		Name: "FIO", Pattern: contractPattern, Strategy: config.StrategyStarsKeep2,
	}}
	if err := mgr.Apply(badName); err == nil {
		t.Fatal("built-in name: Apply succeeded, want error")
	}
}
