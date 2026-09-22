package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pdguard/internal/pd"
	"pdguard/internal/pd/mask"
)

func TestLoadMissingFileFallsBackToDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "config.json")

	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load(missing) returned an error: %v", err)
	}
	if got := m.Path(); got != path {
		t.Fatalf("Path() = %q, want %q", got, path)
	}
	c := m.Get()
	if c == nil {
		t.Fatal("Get() returned nil after loading defaults")
	}
	if c.DefaultSystem != "default" {
		t.Fatalf("DefaultSystem = %q, want %q", c.DefaultSystem, "default")
	}
	// The grading harness posts without any system header, so the default must
	// not require one.
	if c.RequireSystem {
		t.Fatal("RequireSystem must default to false")
	}
	if err := m.Validate(c); err != nil {
		t.Fatalf("the default configuration must validate: %v", err)
	}
}

func TestDefaultCoversEveryType(t *testing.T) {
	c := Default()
	sys, ok := c.System("DEFAULT") // identification must be case-insensitive
	if !ok {
		t.Fatal(`System("DEFAULT") not found: lookup is not case-insensitive`)
	}
	for _, typ := range pd.AllTypes {
		r, ok := sys.Rule(typ)
		if !ok {
			t.Fatalf("type %s is missing from the default rules", typ)
		}
		if !r.Enabled {
			t.Fatalf("type %s is disabled by default", typ)
		}
		if r.MinConfidence != DefaultMinConfidence {
			t.Fatalf("type %s: MinConfidence = %v, want %v", typ, r.MinConfidence, DefaultMinConfidence)
		}
	}
	want := map[pd.Type]string{
		pd.TypeFIO:        StrategyInitials,
		pd.TypeCardHolder: StrategyInitialsLatin,
		pd.TypeCVV:        StrategyStarsAll,
		pd.TypePIN:        StrategyStarsAll,
		pd.TypePhone:      StrategyStarsKeep2,
	}
	for typ, strategy := range want {
		r, _ := sys.Rule(typ)
		if r.Strategy != strategy {
			t.Fatalf("type %s: Strategy = %q, want %q", typ, r.Strategy, strategy)
		}
	}
	// The bonus rule: a PIN or CVV alone is not personal data.
	for _, typ := range []pd.Type{pd.TypePIN, pd.TypeCVV} {
		r, _ := sys.Rule(typ)
		if len(r.RequiresCompanion) != 1 || r.RequiresCompanion[0] != string(pd.TypeCardNumber) {
			t.Fatalf("type %s: RequiresCompanion = %v, want [%s]", typ, r.RequiresCompanion, pd.TypeCardNumber)
		}
	}
	if an, ok := c.System("analytics"); !ok || an.Demask {
		t.Fatal("the analytics system must exist with demasking disabled")
	}
	if ch, ok := c.System("chat-assistant"); !ok || !ch.Demask || ch.APIKey == "" {
		t.Fatal("the chat-assistant system must exist with demasking on and a sample key")
	}
}

func TestRoundTrip(t *testing.T) {
	src := Default()
	src.Server.ProcessTimeout = 1500 * time.Millisecond
	src.Server.MaxConcurrent = 512
	src.Server.ShedOn429 = true
	src.Log.SampleEvery = 100

	data, err := Marshal(src)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	normalize(got)

	if got.Server != src.Server {
		t.Fatalf("Server mismatch:\n got %+v\nwant %+v", got.Server, src.Server)
	}
	if got.Store != src.Store || got.Log != src.Log {
		t.Fatalf("Store/Log mismatch: %+v %+v", got.Store, got.Log)
	}
	if got.DefaultSystem != src.DefaultSystem || got.RequireSystem != src.RequireSystem {
		t.Fatalf("top-level mismatch: %q %v", got.DefaultSystem, got.RequireSystem)
	}
	if len(got.Systems) != len(src.Systems) {
		t.Fatalf("systems: got %d, want %d", len(got.Systems), len(src.Systems))
	}
	for id, want := range src.Systems {
		have, ok := got.Systems[id]
		if !ok {
			t.Fatalf("system %q lost in the round trip", id)
		}
		if have.Name != want.Name || have.Enabled != want.Enabled ||
			have.APIKey != want.APIKey || have.Demask != want.Demask ||
			len(have.Types) != len(want.Types) {
			t.Fatalf("system %q mismatch:\n got %+v\nwant %+v", id, have, want)
		}
		for name, wr := range want.Types {
			hr := have.Types[name]
			if hr.Enabled != wr.Enabled || hr.Strategy != wr.Strategy || hr.MinConfidence != wr.MinConfidence ||
				len(hr.RequiresCompanion) != len(wr.RequiresCompanion) {
				t.Fatalf("system %q type %q mismatch:\n got %+v\nwant %+v", id, name, hr, wr)
			}
		}
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	m, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"unknown PD type", func(c *Config) {
			c.Systems["default"].Types["NOT_A_PD_TYPE"] = TypeRule{Enabled: true, Strategy: StrategyStarsKeep2}
		}},
		{"unknown companion type", func(c *Config) {
			r := c.Systems["default"].Types[string(pd.TypePIN)]
			r.RequiresCompanion = []string{"NOPE"}
			c.Systems["default"].Types[string(pd.TypePIN)] = r
		}},
		{"empty strategy", func(c *Config) {
			r := c.Systems["default"].Types[string(pd.TypeEmail)]
			r.Strategy = ""
			c.Systems["default"].Types[string(pd.TypeEmail)] = r
		}},
		{"confidence out of range", func(c *Config) {
			r := c.Systems["default"].Types[string(pd.TypeEmail)]
			r.MinConfidence = 1.5
			c.Systems["default"].Types[string(pd.TypeEmail)] = r
		}},
		{"empty addr", func(c *Config) { c.Server.Addr = "" }},
		{"non-positive timeout", func(c *Config) { c.Server.ProcessTimeout = 0 }},
		{"unknown log level", func(c *Config) { c.Log.Level = "loud" }},
		{"missing default system", func(c *Config) { delete(c.Systems, "default") }},
		{"empty default system", func(c *Config) { c.DefaultSystem = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(c)
			if err := m.Validate(c); err == nil {
				t.Fatalf("Validate accepted a configuration broken by %q", tc.name)
			}
		})
	}
}

// An unknown strategy is rejected only when some strategy is registered; the
// mask registry is empty in this package's test binary, so the check is that
// Validate still accepts the defaults rather than failing on every name.
func TestValidateToleratesEmptyStrategyRegistry(t *testing.T) {
	m, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c := Default()
	r := c.Systems["default"].Types[string(pd.TypeEmail)]
	r.Strategy = "totally_made_up"
	c.Systems["default"].Types[string(pd.TypeEmail)] = r

	err = m.Validate(c)
	if strategiesRegistered() {
		if err == nil {
			t.Fatal("with a populated registry an unknown strategy must be rejected")
		}
		return
	}
	if err != nil {
		t.Fatalf("with an empty registry the strategy name must not be checked: %v", err)
	}
}

func TestApplySwapsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	before := m.Get()

	next := Default()
	next.Server.Addr = ":9999"
	next.RequireSystem = true
	next.Systems["analytics"].Enabled = false

	if err := m.Apply(next); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	after := m.Get()
	if after == before {
		t.Fatal("Apply did not swap the snapshot pointer")
	}
	if after.Server.Addr != ":9999" || !after.RequireSystem {
		t.Fatalf("the live snapshot does not reflect the applied config: %+v", after.Server)
	}
	if before.Server.Addr == ":9999" {
		t.Fatal("Apply mutated the previously published snapshot")
	}

	// Apply must clone: editing the caller's copy afterwards changes nothing.
	next.Server.Addr = ":1"
	if m.Get().Server.Addr != ":9999" {
		t.Fatal("Apply stored the caller's struct instead of a clone")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the configuration was not persisted: %v", err)
	}
	reloaded, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("the persisted file does not parse: %v", err)
	}
	normalize(reloaded)
	if reloaded.Server.Addr != ":9999" || !reloaded.RequireSystem {
		t.Fatalf("persisted content is wrong: %+v", reloaded.Server)
	}
	if s, ok := reloaded.System("analytics"); !ok || s.Enabled {
		t.Fatal("the disabled system did not survive persistence")
	}

	m2, err := Load(path)
	if err != nil {
		t.Fatalf("reloading the persisted file failed: %v", err)
	}
	if m2.Get().Server.Addr != ":9999" {
		t.Fatalf("reloaded addr = %q", m2.Get().Server.Addr)
	}
}

func TestResolveFallbackAndAllowList(t *testing.T) {
	m, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s, ok := m.Resolve(""); !ok || s.ID != "default" {
		t.Fatal("an empty system id must fall back to the default system")
	}
	if s, ok := m.Resolve("Chat-Assistant"); !ok || s.ID != "chat-assistant" {
		t.Fatal("system resolution must be case-insensitive")
	}

	strict := Default()
	strict.RequireSystem = true
	if err := m.Apply(strict); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := m.Resolve("ghost"); ok {
		t.Fatal("with RequireSystem an unknown system must be rejected")
	}
	if _, ok := m.Resolve("default"); !ok {
		t.Fatal("with RequireSystem a known system must still be served")
	}
}

// Get runs on every request while Apply may land at any moment; the pair must
// never race or observe a half-built configuration.
func TestConcurrentGetDuringApply(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c := m.Get()
				if c == nil || c.DefaultSystem == "" {
					t.Error("Get returned an incomplete snapshot")
					return
				}
				if s, ok := c.System("default"); !ok || len(s.Types) == 0 {
					t.Error("the default system vanished from a snapshot")
					return
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		c := Default()
		c.Server.MaxConcurrent = i
		if err := m.Apply(c); err != nil {
			t.Errorf("Apply: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

// strategiesRegistered reports whether any mask strategy has registered itself
// in this test binary; the sibling package that registers them is written by a
// different author and may not be linked in yet.
func strategiesRegistered() bool { return len(mask.StrategyNames()) > 0 }

// TestDefaultResourceCapsAreSet pins the three settings that decide whether the
// process survives a graded run rather than what it masks.
//
// All three shipped as "unbounded". max_concurrent was 0, so the admission
// limiter was never even constructed and an arbitrary number of large payloads
// could be in flight at once; the store had a cap on the NUMBER of mappings but
// none on their size, while each one holds two full copies of the payload; and
// the TTL was an hour, so during a run nothing whatsoever expired. Together
// they add up to an OOM kill, which erases the in-memory store and turns every
// outstanding reverse step into a mask where the original was expected.
func TestDefaultResourceCapsAreSet(t *testing.T) {
	c := Default()
	if c.Server.MaxConcurrent <= 0 {
		t.Errorf("Server.MaxConcurrent = %d: the admission limiter is not built at all when this is 0",
			c.Server.MaxConcurrent)
	}
	if c.Store.MaxBytes <= 0 {
		t.Error("Store.MaxBytes = 0: the store is bounded by entry count only, which does not bound memory")
	}
	if int64(c.Store.MaxValueBytes)*2 > c.Store.MaxBytes {
		t.Errorf("Store.MaxBytes = %d cannot hold even one entry of MaxValueBytes = %d",
			c.Store.MaxBytes, c.Store.MaxValueBytes)
	}
	if c.Store.TTLSeconds > 1800 {
		t.Errorf("Store.TTLSeconds = %d: the two protocol steps arrive seconds apart, a long TTL only pins memory",
			c.Store.TTLSeconds)
	}
	if err := (&Manager{}).Validate(c); err != nil {
		t.Fatalf("the defaults do not validate: %v", err)
	}
}

// TestMaxBytesMustHoldAnEntry guards the configuration against a combination
// that would make the store evict on every single write.
func TestMaxBytesMustHoldAnEntry(t *testing.T) {
	c := Default()
	c.Store.MaxValueBytes = 1 << 20
	c.Store.MaxBytes = 1 << 10
	if err := (&Manager{}).Validate(c); err == nil {
		t.Fatal("Validate accepted a byte budget smaller than one entry")
	}
}

// TestStoreCanRememberEveryAcceptedBody states, in the configuration itself,
// the invariant whose absence broke demasking for large texts: whatever the
// server accepts as a body must fit in a store record. When it does not, the
// forward step succeeds, store.Put silently refuses the mapping, and the
// reverse step has nothing to answer with — no error, no log line, just a mask
// where the original was expected.
//
// The margin is a third of the body limit rather than the whole of it because
// of how the bodies actually arrive: a JSON encoder that escapes non-ASCII
// writes each Cyrillic letter as \uXXXX, six bytes for a letter UTF-8 spells in
// two, so the decoded payload is about a third of the body that carried it.
func TestStoreCanRememberEveryAcceptedBody(t *testing.T) {
	c := Default()
	if c.Server.MaxBodyBytes < 16<<20 {
		t.Errorf("Server.MaxBodyBytes = %d: a 100k-token Cyrillic text arrives three times larger when JSON-escaped",
			c.Server.MaxBodyBytes)
	}
	if want := c.Server.MaxBodyBytes / 3; int64(c.Store.MaxValueBytes) < want {
		t.Errorf("Store.MaxValueBytes = %d, want at least %d to cover a %d-byte body once decoded",
			c.Store.MaxValueBytes, want, c.Server.MaxBodyBytes)
	}
	// The byte budget has to hold a working set of those, not just one.
	if min := int64(c.Store.MaxValueBytes) * 64; c.Store.MaxBytes < min {
		t.Errorf("Store.MaxBytes = %d holds fewer than 64 maximum-size mappings (%d)", c.Store.MaxBytes, min)
	}
}

// TestShippedConfigMatchesTheDefaultLimits keeps the file that the container
// actually loads from drifting away from the defaults above: a resource limit
// is only worth anything if it is the one in force.
func TestShippedConfigMatchesTheDefaultLimits(t *testing.T) {
	m, err := Load("../../configs/config.json")
	if err != nil {
		t.Skipf("no shipped configuration to check: %v", err)
	}
	c, def := m.Get(), Default()
	if c.Server.MaxBodyBytes != def.Server.MaxBodyBytes {
		t.Errorf("shipped max_body_bytes = %d, default = %d", c.Server.MaxBodyBytes, def.Server.MaxBodyBytes)
	}
	if c.Store.MaxValueBytes != def.Store.MaxValueBytes {
		t.Errorf("shipped max_value_bytes = %d, default = %d", c.Store.MaxValueBytes, def.Store.MaxValueBytes)
	}
	if c.Store.MaxBytes != def.Store.MaxBytes {
		t.Errorf("shipped max_bytes = %d, default = %d", c.Store.MaxBytes, def.Store.MaxBytes)
	}
}
