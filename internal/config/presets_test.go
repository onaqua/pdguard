package config

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"pdguard/internal/pd"
	"pdguard/internal/pd/mask"
)

// The masking presets in configs/presets are full, drop-in configurations that
// differ from the shipped default in ONE respect: the shape of the mask. The
// quality metric compares our output against a reference mask nobody has shown
// us, so the format is a bet, and scripts/preset.sh exists to change that bet
// on a running service in seconds. These tests are what makes that switch safe
// to reach for: a preset that does not validate is not a documentation bug, it
// is a lever that snaps off at the moment somebody pulls it.
//
// The files are generated from the recipes below rather than maintained by
// hand, and the test is their generator:
//
//	bash scripts/go.sh test ./internal/config/ -run TestPresetFiles -update
//
// Run that after adding a PD type or a strategy; without it, a new type would
// be missing from every preset and silently unmasked the moment one is applied.

// updatePresets rewrites the preset files instead of comparing against them.
var updatePresets = flag.Bool("update", false, "rewrite configs/presets/*.json from the recipes in this file")

// presetDir is where the shipped presets live, relative to this package.
const presetDir = "../../configs/presets"

// preset is one shipped configuration: a name, why it exists, and the edits
// that turn the default configuration into it.
type preset struct {
	name string
	why  string
	edit func(*Config)
}

// presets is the catalogue. Every entry changes the mask FORMAT only — never
// which systems exist, which types are detected, or how confident a detector
// has to be — so switching formats can never become a policy change by
// accident. TestPresetsDifferOnlyInMaskingFormat holds that line.
var presets = []preset{
	{
		name: "stars-keep2",
		why:  "the shipped default: first two and last two alphanumerics survive",
	},
	{
		name: "stars-all",
		why:  "hypothesis: the reference hides every character but keeps the length",
		edit: everyType(mask.NameStarsAll),
	},
	{
		name: "labels",
		why:  "hypothesis: the reference replaces values with [ФИО], [ПАСПОРТ], ...",
		edit: everyType(mask.NameLabel),
	},
	{
		name: "tokens",
		why:  "deterministic pseudonyms (PD_FIO_a1b2c3) — the tokenisation bonus",
		edit: everyType(mask.NameToken),
	},
	{
		name: "synthetic",
		why:  "plausible fakes of the same shape — the synthetic-replacement bonus",
		edit: everyType(mask.NameSynthetic),
	},
	{
		name: "keep-domain",
		why:  "stars-keep2, but an e-mail keeps its domain: iv****@mail.ru",
		edit: oneType(pd.TypeEmail, mask.NameKeepDomain),
	},
	{
		name: "span-with-labels",
		why:  "stars-keep2 with spans widened over the introducing word (серия 4509)",
		edit: func(c *Config) { c.Masking.SpanIncludeLabels = true },
	},
}

// everyType rewrites the strategy of every type of every system.
func everyType(strategy string) func(*Config) {
	return func(c *Config) {
		for _, sys := range c.Systems {
			for name, r := range sys.Types {
				r.Strategy = strategy
				sys.Types[name] = r
			}
		}
	}
}

// oneType rewrites the strategy of a single type across every system.
func oneType(t pd.Type, strategy string) func(*Config) {
	return func(c *Config) {
		for _, sys := range c.Systems {
			r := sys.Types[string(t)]
			r.Strategy = strategy
			sys.Types[string(t)] = r
		}
	}
}

// build renders one preset's bytes.
func (p preset) build(t *testing.T) []byte {
	t.Helper()
	c := Default()
	if p.edit != nil {
		p.edit(c)
	}
	b, err := Marshal(c)
	if err != nil {
		t.Fatalf("preset %s: marshal: %v", p.name, err)
	}
	return b
}

func (p preset) path() string { return filepath.Join(presetDir, p.name+".json") }

// TestPresetFiles pins the files against their recipes, and regenerates them
// under -update.
//
// The byte-for-byte comparison is not pedantry: scripts/preset.sh reads these
// files line by line — there is no jq on a borrowed laptop at 3am — which is
// exact only while they carry the canonical shape config.Marshal writes. A
// hand edit that reflows the JSON would leave the script silently reading an
// empty signature and reporting "custom" for a preset it just applied.
func TestPresetFiles(t *testing.T) {
	for _, p := range presets {
		p := p
		t.Run(p.name, func(t *testing.T) {
			want := p.build(t)
			if *updatePresets {
				if err := os.MkdirAll(presetDir, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", presetDir, err)
				}
				if err := os.WriteFile(p.path(), want, 0o644); err != nil {
					t.Fatalf("write %s: %v", p.path(), err)
				}
				t.Logf("wrote %s (%d bytes)", p.path(), len(want))
				return
			}
			got, err := os.ReadFile(p.path())
			if err != nil {
				t.Fatalf("%v — regenerate with: go test ./internal/config/ -run TestPresetFiles -update", err)
			}
			if string(got) != string(want) {
				t.Fatalf("configs/presets/%s.json is stale or hand-edited; regenerate with: "+
					"go test ./internal/config/ -run TestPresetFiles -update", p.name)
			}
		})
	}
}

// TestPresetsLoadAndValidate is the gate scripts/preset.sh depends on: every
// preset must be a COMPLETE configuration, not a fragment, so it can be applied
// whole through PUT /admin/config and can equally serve as PDGUARD_CONFIG.
func TestPresetsLoadAndValidate(t *testing.T) {
	for _, p := range presets {
		p := p
		t.Run(p.name, func(t *testing.T) {
			// Load normalises and validates exactly as start-up does.
			m, err := Load(p.path())
			if err != nil {
				t.Fatalf("preset %s does not load: %v", p.name, err)
			}
			c := m.Get()
			sys, ok := c.System(c.DefaultSystem)
			if !ok || sys == nil {
				t.Fatalf("preset %s has no default system %q", p.name, c.DefaultSystem)
			}
			for _, typ := range pd.AllTypes {
				r, ok := sys.Rule(typ)
				if !ok {
					t.Fatalf("preset %s: type %s is missing; regenerate the presets", p.name, typ)
				}
				if !r.Enabled {
					continue
				}
				if mask.Lookup(r.Strategy) == nil {
					t.Fatalf("preset %s: type %s names unregistered strategy %q", p.name, typ, r.Strategy)
				}
			}
		})
	}
}

// TestPresetsDifferOnlyInMaskingFormat states the promise the presets make.
// Applying one is meant to be a reversible experiment about output shape; if a
// preset could also flip require_system or drop a type, reaching for one in the
// middle of a graded run would be a gamble rather than a measurement.
func TestPresetsDifferOnlyInMaskingFormat(t *testing.T) {
	base := mustLoadPreset(t, presets[0])
	for _, p := range presets[1:] {
		p := p
		t.Run(p.name, func(t *testing.T) {
			c := mustLoadPreset(t, p)
			if c.Server != base.Server || c.Store != base.Store || c.Log != base.Log {
				t.Fatal("preset changes server/store/log settings; it must change masking only")
			}
			if c.DefaultSystem != base.DefaultSystem || c.RequireSystem != base.RequireSystem {
				t.Fatal("preset changes system resolution; it must change masking only")
			}
			if got, want := systemIDs(c), systemIDs(base); !equalStrings(got, want) {
				t.Fatalf("systems = %v, want %v", got, want)
			}
			for id, sys := range c.Systems {
				bsys := base.Systems[id]
				if sys.Enabled != bsys.Enabled || sys.Demask != bsys.Demask || sys.APIKey != bsys.APIKey {
					t.Fatalf("system %q: access settings differ from the default preset", id)
				}
				for typeName, r := range sys.Types {
					b, ok := bsys.Types[typeName]
					if !ok {
						t.Fatalf("system %q: type %s is not in the default preset", id, typeName)
					}
					if r.Enabled != b.Enabled || r.MinConfidence != b.MinConfidence {
						t.Fatalf("system %q type %s: detection settings differ from the default preset", id, typeName)
					}
				}
			}
		})
	}
}

// TestSpanIncludeLabelsIsOptedInByExactlyOnePreset guards the hedge: widening a
// span over its label is a bet on the reference format, so it must be off
// everywhere except in the preset whose whole purpose is to turn it on.
func TestSpanIncludeLabelsIsOptedInByExactlyOnePreset(t *testing.T) {
	for _, p := range presets {
		c := mustLoadPreset(t, p)
		want := p.name == "span-with-labels"
		if got := c.Masking.SpanIncludeLabels; got != want {
			t.Fatalf("preset %s: span_include_labels = %v, want %v", p.name, got, want)
		}
	}
	if Default().Masking.SpanIncludeLabels {
		t.Fatal("span_include_labels must default to false: the narrow span is the lower-variance bet")
	}
}

// TestShippedConfigIsTheDefaultPreset keeps configs/config.json and the default
// preset in step, so "which format is the service running" has one answer
// whether the reader looks at the file or at the preset it names.
func TestShippedConfigIsTheDefaultPreset(t *testing.T) {
	shipped, err := os.ReadFile("../../configs/config.json")
	if err != nil {
		t.Skipf("no shipped configuration to compare: %v", err)
	}
	want, err := os.ReadFile(presets[0].path())
	if err != nil {
		t.Fatalf("read default preset: %v", err)
	}
	if string(shipped) != string(want) {
		t.Fatalf("configs/config.json is not the %s preset; run: bash scripts/preset.sh apply %s --file",
			presets[0].name, presets[0].name)
	}
}

func mustLoadPreset(t *testing.T, p preset) *Config {
	t.Helper()
	m, err := Load(p.path())
	if err != nil {
		t.Fatalf("load preset %s: %v", p.name, err)
	}
	return m.Get()
}

func systemIDs(c *Config) []string {
	out := make([]string, 0, len(c.Systems))
	for id := range c.Systems {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
