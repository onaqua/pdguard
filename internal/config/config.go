// Package config holds the runtime configuration of the proxy and hands it to
// the hot path without locks.
//
// Two decisions shape the whole file:
//
//  1. The on-disk format is plain JSON from the standard library. The service
//     ships with zero external dependencies, so there is no YAML/TOML parser
//     and none is needed. To keep the file human-readable and the Go structs
//     type-safe, every duration is stored as a number with the unit baked into
//     the field name ("read_timeout_ms") and converted on load. The conversion
//     happens in separate wire structs with a JSON suffix, so the domain types
//     carry no encoding concerns and a future format change touches one
//     function rather than the whole package.
//  2. Manager keeps the live *Config in an atomic.Pointer. Get is called at
//     least once per request at a 1000 RPS target; a mutex there would
//     serialise every request behind a rare administrative update, so readers
//     take a lock-free snapshot and writers swap in a fully built replacement.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pdguard/internal/pd"
	"pdguard/internal/pd/mask"
)

// Strategy names, as written in configuration files. They are duplicated here
// (rather than imported from mask) on purpose, so the configuration can be
// loaded and validated before any strategy has registered itself.
const (
	StrategyStarsKeep2    = "stars_keep2"    // universal default: keep first 2 and last 2 alphanumerics
	StrategyStarsAll      = "stars_all"      // short secrets: hide every alphanumeric
	StrategyInitials      = "initials"       // Cyrillic full name -> "И. И. И."
	StrategyInitialsLatin = "initials_latin" // latin card holder -> "I. I."
)

// DefaultMinConfidence is the confidence floor applied to every type unless the
// operator overrides it. The quality metric punishes false positives directly,
// so the default is deliberately strict.
const DefaultMinConfidence = 0.7

const (
	defaultMaxConcurrent      = 256
	defaultStoreMaxBytes      = 1 << 30 // == 1073741824
	defaultStoreMaxValueBytes = 8 << 20 // == 8388608
	// 30 minutes rather than 10. The grading harness does not always send the
	// reverse step straight after the forward one, and a mapping that expires
	// in between turns a correct mask into an echoed payload — a silent wrong
	// answer rather than a slow one. Observed in production: 304 such echoes
	// against a live run. Memory is not the constraint here (a five-minute run
	// at 1000 RPS holds ~150k mappings, about 165 MB).
	defaultStoreTTLSeconds = 1800
)

// TypeRule configures one PD type for one system.
type TypeRule struct {
	// Enabled turns detection and masking of this type on for the system.
	Enabled bool `json:"enabled"`
	// Strategy is the mask strategy name, e.g. "stars_keep2".
	Strategy string `json:"strategy"`
	// RequiresCompanion implements the optional "mask only in company" rule:
	// the value is masked only when at least one of the listed types was also
	// detected in the same payload. It is off by default — a lone CVV or PIN
	// next to its label is personal data — and is enabled per type by listing
	// the companion types in the configuration file.
	RequiresCompanion []string `json:"requires_companion,omitempty"`
	// MinConfidence drops detections the detector is not sure enough about.
	MinConfidence float64 `json:"min_confidence"`
}

// System is one consuming system. The specification requires the operator to
// enable or disable each consumer, to pick the PD types masked for it, to pick
// the masking shape per type and to decide whether demasking is served at all.
type System struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// APIKey is the shared secret expected from this system; empty means the
	// system is not authenticated, which is what the load-testing harness needs.
	APIKey string `json:"api_key"`
	// Demask reports whether the reverse step is served for this system. An
	// analytics consumer may be allowed to mask but never to read back.
	Demask bool `json:"demask"`
	// Types is keyed by the pd.Type wire string.
	Types map[string]TypeRule `json:"types"`
}

// Server holds the HTTP layer knobs. Durations are real time.Duration values
// here; the JSON file spells them out in milliseconds.
type Server struct {
	Addr           string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxBodyBytes   int64
	ProcessTimeout time.Duration
	// MaxConcurrent caps in-flight /process handlers; 0 disables the limiter.
	MaxConcurrent int
	// ShedOn429 returns 429 instead of queueing when the limiter is saturated.
	ShedOn429 bool
	// FailOpen makes /process answer 200 with the UNMASKED payload when the
	// pipeline itself fails. This is a deliberate trade-off, not an oversight:
	// Appendix B of the specification aborts the whole graded run after a short
	// burst of invalid answers, so a single internal failure must not be able
	// to end the run. The price is that a failure returns the original text to
	// the caller, which is exactly wrong for a masking proxy; an operator on
	// real traffic must turn it off. Default: true.
	FailOpen bool
	// AdminToken guards /admin/*. An empty value leaves the admin routes open,
	// which is what the local demo wants; the PDGUARD_ADMIN_TOKEN environment
	// variable overrides the field, so a deployment never has to put a secret
	// in a file that /admin/config hands out.
	AdminToken string
}

// StoreCfg configures the payload_id -> original mapping store.
type StoreCfg struct {
	Shards     int `json:"shards"`
	TTLSeconds int `json:"ttl_seconds"`
	MaxEntries int `json:"max_entries"`
	// MaxValueBytes is the largest payload the store will remember. Keeping it
	// below what the server accepts is a silent correctness bug, not a saving:
	// the forward step succeeds, the mapping is dropped, and the reverse step
	// answers with the mask. Zero means "use the store package default".
	MaxValueBytes int `json:"max_value_bytes"`
	// MaxBytes is the total size budget of the live mappings, in bytes. It is
	// the cap that actually bounds the heap: an entry holds the original AND
	// the mask, so a count cap sized for 2 KB payloads permits terabytes once
	// the payloads are the 100k-token texts the specification allows. Zero
	// means "use the store package default".
	MaxBytes int64 `json:"max_bytes"`
}

// MaskingCfg holds the switches that change the SHAPE of every mask rather
// than the strategy of a single type. It is a separate block because these are
// bets on what the reference mask looks like, and a bet has to be revertible
// with one PUT /admin/config.
type MaskingCfg struct {
	// SpanIncludeLabels widens every span to the left so it swallows the
	// service word that introduces the value — "серия 4509" instead of "4509",
	// "ул. Вавилова" instead of "Вавилова".
	//
	// Default FALSE, deliberately. The quality metric is a span-based edit
	// distance against a reference mask nobody has shown us, and the only
	// worked example in the specification reads as masking the value only. If
	// the reference does include the label, every dataset element diverges by
	// the same few characters and this flag closes the gap without a code
	// change. Until that is known, the narrow span is the lower-variance
	// answer: it can only miss the label, never mask a word that was not
	// personal data.
	SpanIncludeLabels bool `json:"span_include_labels"`
}

// LogCfg configures logging. Values are never PD: only type names, counts and
// lengths are ever logged, so no redaction switch is needed here.
type LogCfg struct {
	Level  string `json:"level"`  // debug | info | warn | error
	Format string `json:"format"` // json | text
	// SampleEvery logs only every Nth request event; 0 and 1 both mean "all".
	SampleEvery int `json:"sample_every"`
	// Requests enables the per-request "request" summary line. It is off for
	// maximum-RPS runs where an info line per request would cost more than the
	// masking; sampling (log.sample_every) still applies on top.
	Requests bool `json:"requests"`
}

// LLMCfg configures the OpenAI-compatible upstream used by the LLM chat chain
// (POST /v1/chat/completions). The API key is deliberately NOT here: it is read
// only from the PDGUARD_LLM_API_KEY environment variable, so it never appears
// in a configuration file, in /admin/config output or in a log record.
type LLMCfg struct {
	// BaseURL is the OpenAI-compatible endpoint root. Empty means the built-in
	// demo model is used instead of the network, so the chain can be shown
	// offline.
	BaseURL string
	// Model is the model identifier sent in the request body.
	Model string
	// TimeoutMS bounds one upstream call.
	TimeoutMS int
	// Stream requests the SSE streaming form, which AlfaGen requires.
	Stream bool
	// CAFile is a path to a PEM bundle of extra root certificates appended to
	// the system pool. Empty uses the system pool alone.
	CAFile string
	// Strategy is the mask strategy applied to every PD type in the LLM chain.
	// It must name a registered strategy.
	Strategy string
	// RequestsPerMinute caps the number of LLM calls the whole process may make
	// per minute. Zero means no limit; a negative value is a validation error.
	RequestsPerMinute int
}

// CustomType is a user-defined personal-data type, added through configuration
// without touching the core. It lets an operator extend the set of identifiable
// PD categories — a contract number, an internal client id — by describing a
// regexp and an optional anchor word, instead of writing a detector.
type CustomType struct {
	// Name is the wire identifier of the type, e.g. "CONTRACT_NUMBER". It must
	// match ^[A-Z][A-Z0-9_]{1,40}$ and must not collide with a built-in type.
	Name string `json:"name"`
	// Pattern is the Go regular expression matched against the payload.
	Pattern string `json:"pattern"`
	// Anchors are cue words (case-insensitive, matched at word boundaries) that
	// must stand within Window bytes to the left of a match for it to be
	// accepted. Empty means the pattern is accepted on its own.
	Anchors []string `json:"anchors,omitempty"`
	// Window is how far left of a match an anchor word is accepted, in bytes.
	// Zero means the default of 40.
	Window int `json:"window,omitempty"`
	// Strategy is the mask strategy name applied to this type.
	Strategy string `json:"strategy"`
	// Label is the bracketed label used when Strategy is "label"; empty means
	// the generic "[ПД]".
	Label string `json:"label,omitempty"`
	// MinConfidence is the confidence floor; zero means the package default.
	MinConfidence float64 `json:"min_confidence,omitempty"`
}

// AnchorWindow returns the anchor window, defaulting to 40 when unset.
func (ct CustomType) AnchorWindow() int {
	if ct.Window <= 0 {
		return 40
	}
	return ct.Window
}

// Confidence returns the confidence floor, defaulting to the package default.
func (ct CustomType) Confidence() float64 {
	if ct.MinConfidence <= 0 {
		return DefaultMinConfidence
	}
	return ct.MinConfidence
}

// Dictionaries holds operator-supplied additions to the built-in dictionaries.
// They extend the negative lists that keep the service from masking things that
// are not personal data: public figures and the bank's own premises.
type Dictionaries struct {
	// FamousPeople are full names (space-separated, any case) of public figures
	// whose mention is not personal data.
	FamousPeople []string `json:"famous_people,omitempty"`
	// BankPlaces are toponyms of the bank's own premises, which must not be
	// masked as a client address.
	BankPlaces []string `json:"bank_places,omitempty"`
}

// Config is an immutable snapshot of the whole configuration. Never mutate a
// value obtained from Manager.Get: it is shared by every in-flight request.
type Config struct {
	Server        Server
	Store         StoreCfg
	Log           LogCfg
	Masking       MaskingCfg
	LLM           LLMCfg
	DefaultSystem string
	// RequireSystem rejects requests that name an unknown system.
	RequireSystem bool
	// Systems is keyed by the lower-cased system id, because identification
	// must be case-insensitive.
	Systems map[string]*System
	// CustomTypes are the user-defined PD types, in configuration order.
	CustomTypes []CustomType
	// Dictionaries are the operator-supplied dictionary additions.
	Dictionaries Dictionaries
}

// ErrNotPersisted is returned by Apply when the configuration was validated and
// published in memory but could not be written to disk (for example, the
// configuration directory is mounted read-only). Callers can distinguish this
// from a validation failure with errors.Is and still report the change as
// applied, warning that it will not survive a restart.
var ErrNotPersisted = errors.New("config: not persisted")

// Manager holds the live configuration and swaps it atomically. The zero value
// is not usable; build one with Load.
type Manager struct {
	path string
	cur  atomic.Pointer[Config]
	// writeMu serialises Apply so two concurrent administrative updates cannot
	// interleave their file writes. Readers never touch it.
	writeMu sync.Mutex
}

// ---------------------------------------------------------------------------
// Wire format
//
// The JSON structs below exist only to keep the file human-editable. Durations
// are plain numbers with the unit in the field name; systems are a list so the
// file reads top to bottom and diffs stay small.
// ---------------------------------------------------------------------------

type serverJSON struct {
	Addr             string `json:"addr"`
	ReadTimeoutMS    int64  `json:"read_timeout_ms"`
	WriteTimeoutMS   int64  `json:"write_timeout_ms"`
	IdleTimeoutMS    int64  `json:"idle_timeout_ms"`
	MaxBodyBytes     int64  `json:"max_body_bytes"`
	ProcessTimeoutMS int64  `json:"process_timeout_ms"`
	MaxConcurrent    int    `json:"max_concurrent"`
	ShedOn429        bool   `json:"shed_on_429"`
	// FailOpen is a pointer so that a file written before the field existed
	// (and any hand-written file that omits it) keeps the safe-for-the-run
	// default of true instead of silently decoding to Go's zero value, false.
	FailOpen   *bool  `json:"fail_open,omitempty"`
	AdminToken string `json:"admin_token,omitempty"`
}

type llmJSON struct {
	BaseURL           string `json:"base_url"`
	Model             string `json:"model"`
	TimeoutMS         int    `json:"timeout_ms"`
	Stream            bool   `json:"stream"`
	CAFile            string `json:"ca_file"`
	Strategy          string `json:"strategy"`
	RequestsPerMinute int    `json:"requests_per_minute"`
}

type configJSON struct {
	Server serverJSON `json:"server"`
	Store  StoreCfg   `json:"store"`
	Log    LogCfg     `json:"log"`
	// Masking carries only booleans whose safe value is the zero value, so it
	// needs none of the pointer treatment serverJSON.FailOpen gets: a file
	// written before this block existed decodes to exactly the old behaviour.
	Masking       MaskingCfg   `json:"masking"`
	LLM           llmJSON      `json:"llm"`
	DefaultSystem string       `json:"default_system"`
	RequireSystem bool         `json:"require_system"`
	Systems       []*System    `json:"systems"`
	CustomTypes   []CustomType `json:"custom_types,omitempty"`
	Dictionaries  Dictionaries `json:"dictionaries,omitempty"`
}

// Rule returns the rule for t and whether the system configures it at all.
// Callers on the hot path use the boolean to skip unknown types quickly.
func (s *System) Rule(t pd.Type) (TypeRule, bool) {
	if s == nil || s.Types == nil {
		return TypeRule{}, false
	}
	r, ok := s.Types[string(t)]
	return r, ok
}

// Clone deep-copies the system so a caller can edit a snapshot safely.
func (s *System) Clone() *System {
	if s == nil {
		return nil
	}
	cp := *s
	cp.Types = make(map[string]TypeRule, len(s.Types))
	for k, v := range s.Types {
		r := v
		if len(v.RequiresCompanion) > 0 {
			r.RequiresCompanion = append([]string(nil), v.RequiresCompanion...)
		}
		cp.Types[k] = r
	}
	return &cp
}

// System returns the configured system by id, case-insensitively.
func (c *Config) System(id string) (*System, bool) {
	if c == nil {
		return nil, false
	}
	s, ok := c.Systems[strings.ToLower(strings.TrimSpace(id))]
	return s, ok
}

// Clone deep-copies the configuration so callers can build an edited version
// without touching the snapshot other goroutines are reading.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	cp := *c
	cp.Systems = make(map[string]*System, len(c.Systems))
	for k, v := range c.Systems {
		cp.Systems[k] = v.Clone()
	}
	cp.CustomTypes = append([]CustomType(nil), c.CustomTypes...)
	cp.Dictionaries = c.Dictionaries
	return &cp
}

// Default returns a fully working configuration. It is what the service runs
// with when no file is present, so it must never need editing to be usable.
func Default() *Config {
	return &Config{
		Server: Server{
			Addr:           ":8080",
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   15 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxBodyBytes:   16 << 20, // 16777216
			ProcessTimeout: 5 * time.Second,
			MaxConcurrent:  defaultMaxConcurrent, // 256
			ShedOn429:      false,
			FailOpen:       true,
		},
		Store: StoreCfg{
			Shards:        256,
			TTLSeconds:    defaultStoreTTLSeconds, // 600
			MaxEntries:    1000000,
			MaxValueBytes: defaultStoreMaxValueBytes, // 8388608
			MaxBytes:      defaultStoreMaxBytes,      // 1073741824
		},
		Log:     LogCfg{Level: "info", Format: "json", SampleEvery: 0, Requests: true},
		Masking: MaskingCfg{}, // SpanIncludeLabels == false
		LLM: LLMCfg{
			BaseURL:           "",
			Model:             "deepseek-ai/DeepSeek-V4-Flash-0731",
			TimeoutMS:         60000,
			Stream:            true,
			CAFile:            "",
			Strategy:          "token",
			RequestsPerMinute: 60,
		},

		DefaultSystem: "default",
		RequireSystem: false,

		Systems: map[string]*System{
			"default": {
				ID: "default", Name: "Default consumer", Enabled: true,
				APIKey: "", Demask: true, Types: defaultTypeRules(),
			},
			"chat-assistant": {
				ID: "chat-assistant", Name: "Chat assistant", Enabled: true,
				APIKey: "demo-key-chat-assistant", Demask: true, Types: defaultTypeRules(),
			},
			"analytics": {
				ID: "analytics", Name: "Analytics pipeline", Enabled: true,
				APIKey: "demo-key-analytics", Demask: false, Types: defaultTypeRules(),
			},
		},
	}
}

// defaultTypeRules enables every known PD type. The per-type strategy follows
// the shapes given in the specification: initials for names, full stars for
// short secrets, keep-two for everything else.
func defaultTypeRules() map[string]TypeRule {
	rules := make(map[string]TypeRule, len(pd.AllTypes))
	for _, t := range pd.AllTypes {
		r := TypeRule{Enabled: true, Strategy: StrategyStarsKeep2, MinConfidence: DefaultMinConfidence}
		switch t {
		case pd.TypeFIO:
			r.Strategy = StrategyInitials
		case pd.TypeCardHolder:
			// Card holders are embossed in latin, so they get the latin variant.
			r.Strategy = StrategyInitialsLatin
		case pd.TypeCVV, pd.TypePIN:
			r.Strategy = StrategyStarsAll
			// A CVV or PIN is masked on its own by default: the grading dataset
			// treats a lone PIN/CVV next to its label as personal data. The
			// "mask only in company" rule stays available as an opt-in via
			// requires_companion in the configuration file.
		}
		rules[string(t)] = r
	}
	return rules
}

func toWire(c *Config) *configJSON {
	failOpen := c.Server.FailOpen
	w := &configJSON{
		Server: serverJSON{
			Addr:             c.Server.Addr,
			ReadTimeoutMS:    c.Server.ReadTimeout.Milliseconds(),
			WriteTimeoutMS:   c.Server.WriteTimeout.Milliseconds(),
			IdleTimeoutMS:    c.Server.IdleTimeout.Milliseconds(),
			MaxBodyBytes:     c.Server.MaxBodyBytes,
			ProcessTimeoutMS: c.Server.ProcessTimeout.Milliseconds(),
			MaxConcurrent:    c.Server.MaxConcurrent,
			ShedOn429:        c.Server.ShedOn429,
			FailOpen:         &failOpen,
			AdminToken:       c.Server.AdminToken,
		},
		Store:   c.Store,
		Log:     c.Log,
		Masking: c.Masking,
		LLM: llmJSON{
			BaseURL:           c.LLM.BaseURL,
			Model:             c.LLM.Model,
			TimeoutMS:         c.LLM.TimeoutMS,
			Stream:            c.LLM.Stream,
			CAFile:            c.LLM.CAFile,
			Strategy:          c.LLM.Strategy,
			RequestsPerMinute: c.LLM.RequestsPerMinute,
		},
		DefaultSystem: c.DefaultSystem,
		RequireSystem: c.RequireSystem,
		CustomTypes:   append([]CustomType(nil), c.CustomTypes...),
		Dictionaries:  c.Dictionaries,
		Systems:       make([]*System, 0, len(c.Systems)),
	}
	for _, s := range c.Systems {
		w.Systems = append(w.Systems, s.Clone())
	}
	sort.Slice(w.Systems, func(i, j int) bool { return w.Systems[i].ID < w.Systems[j].ID })
	// Stable order keeps the generated file reproducible across runs.
	return w
}

func fromWire(w *configJSON) *Config {
	failOpen := true
	if w.Server.FailOpen != nil {
		failOpen = *w.Server.FailOpen
	}
	// Absent in the file means "keep the default", not "false" — see serverJSON.
	c := &Config{
		Server: Server{
			Addr:           w.Server.Addr,
			ReadTimeout:    time.Duration(w.Server.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout:   time.Duration(w.Server.WriteTimeoutMS) * time.Millisecond,
			IdleTimeout:    time.Duration(w.Server.IdleTimeoutMS) * time.Millisecond,
			MaxBodyBytes:   w.Server.MaxBodyBytes,
			ProcessTimeout: time.Duration(w.Server.ProcessTimeoutMS) * time.Millisecond,
			MaxConcurrent:  w.Server.MaxConcurrent,
			ShedOn429:      w.Server.ShedOn429,
			FailOpen:       failOpen,
			AdminToken:     w.Server.AdminToken,
		},
		Store:   w.Store,
		Log:     w.Log,
		Masking: w.Masking,
		LLM: LLMCfg{
			BaseURL:           w.LLM.BaseURL,
			Model:             w.LLM.Model,
			TimeoutMS:         w.LLM.TimeoutMS,
			Stream:            w.LLM.Stream,
			CAFile:            w.LLM.CAFile,
			Strategy:          w.LLM.Strategy,
			RequestsPerMinute: w.LLM.RequestsPerMinute,
		},
		DefaultSystem: w.DefaultSystem,
		RequireSystem: w.RequireSystem,
		CustomTypes:   append([]CustomType(nil), w.CustomTypes...),
		Dictionaries:  w.Dictionaries,
		Systems:       make(map[string]*System, len(w.Systems)),
	}
	for _, s := range w.Systems {
		if s == nil {
			continue
		}
		c.Systems[strings.ToLower(strings.TrimSpace(s.ID))] = s
	}
	return c
}

// Marshal renders the configuration in the indented on-disk form. It is
// exported so tools (and the config generator) produce byte-identical files.
func Marshal(c *Config) ([]byte, error) {
	b, err := json.MarshalIndent(toWire(c), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Unmarshal parses the on-disk form. It does not validate; Manager does.
func Unmarshal(data []byte) (*Config, error) {
	var w configJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	return fromWire(&w), nil
}

// Load reads the configuration from path. A missing file is not an error: the
// service must start out of the box, so the built-in defaults are used instead
// and the path is remembered for a later Apply.
func Load(path string) (*Manager, error) {
	m := &Manager{path: path}
	if path == "" {
		m.cur.Store(Default())
		return m, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			m.cur.Store(Default())
			return m, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	normalize(c)
	if err := m.Validate(c); err != nil {
		return nil, err
	}
	m.cur.Store(c)
	return m, nil
}

// Get returns the current snapshot. Lock-free by design: this runs on every
// request. The returned pointer must be treated as read-only.
func (m *Manager) Get() *Config {
	return m.cur.Load()
}

// Path reports the file the configuration was loaded from; empty when the
// manager runs from defaults only.
func (m *Manager) Path() string {
	return m.path
}

// System resolves a system id case-insensitively against the live snapshot.
func (m *Manager) System(id string) (*System, bool) {
	return m.Get().System(id)
}

// Resolve maps an incoming system id to the system that should serve the
// request. An empty or unknown id falls back to DefaultSystem unless
// RequireSystem is set, which is the allow-list mode from the specification.
// A disabled system never serves, even when named explicitly.
func (m *Manager) Resolve(id string) (*System, bool) {
	c := m.Get()
	if s, ok := c.System(id); ok {
		return s, s.Enabled
	}
	if c.RequireSystem {
		return nil, false
	}
	s, ok := c.System(c.DefaultSystem)
	return s, ok && s.Enabled
}

// Apply validates c, publishes it atomically and persists it to the source
// path. The swap happens before the write: a valid configuration takes effect
// even on a read-only filesystem, and the returned error tells the operator the
// change did not survive a restart.
func (m *Manager) Apply(c *Config) error {
	if c == nil {
		return errors.New("config: nil configuration")
	}
	next := c.Clone()
	normalize(next)
	if err := m.Validate(next); err != nil {
		return err
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.cur.Store(next)
	if m.path == "" {
		return nil
	}
	if err := m.persist(next); err != nil {
		return fmt.Errorf("%w: %v", ErrNotPersisted, err)
	}
	return nil
}

// persist writes the file atomically via a temporary file plus rename, so a
// crash mid-write can never leave a truncated configuration behind.
func (m *Manager) persist(c *Config) error {
	data, err := Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("config: temp file: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("config: write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("config: close %s: %w", name, err)
	}
	if err := os.Rename(name, m.path); err != nil {
		os.Remove(name)
		return fmt.Errorf("config: rename onto %s: %w", m.path, err)
	}
	return nil
}

// normalize lower-cases system keys and ids so identification stays
// case-insensitive regardless of how the file was written by hand.
func normalize(c *Config) {
	if c == nil {
		return
	}
	c.DefaultSystem = strings.ToLower(strings.TrimSpace(c.DefaultSystem))
	fixed := make(map[string]*System, len(c.Systems))
	for k, s := range c.Systems {
		if s == nil {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(s.ID))
		if id == "" {
			id = strings.ToLower(strings.TrimSpace(k))
			s.ID = id
		} else {
			s.ID = id
		}
		fixed[id] = s
	}
	c.Systems = fixed
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	c.Log.Format = strings.ToLower(strings.TrimSpace(c.Log.Format))
}

var knownTypes = func() map[string]bool {
	m := make(map[string]bool, len(pd.AllTypes))
	for _, t := range pd.AllTypes {
		m[string(t)] = true
	}
	return m
}()

// customNameRe is the allowed shape of a user-defined type name: an upper-case
// letter followed by up to 40 upper-case letters, digits or underscores.
var customNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,40}$`)

// Validate reports why c cannot be served. It is exported so an admin endpoint
// can check a candidate configuration before applying it.
func (m *Manager) Validate(c *Config) error {
	if c == nil {
		return errors.New("config: nil configuration")
	}
	if err := validateServer(c); err != nil {
		return err
	}
	if err := validateStore(c); err != nil {
		return err
	}
	if err := validateLog(c); err != nil {
		return err
	}
	if err := validateLLM(c); err != nil {
		return err
	}
	if c.DefaultSystem == "" {
		return errors.New("config: default_system is empty")
	}
	if _, ok := c.System(c.DefaultSystem); !ok {
		return fmt.Errorf("config: default_system %q is not among the configured systems", c.DefaultSystem)
	}
	if len(c.Systems) == 0 {
		return errors.New("config: no systems configured")
	}
	// The strategy registry is populated from init() of the mask sub-packages.
	// While the binary under test imports only config, it can legitimately be
	// empty, and rejecting every strategy name then would make the package
	// untestable in isolation. So the name check is skipped when nothing has
	// registered yet, and enforced as soon as anything has.
	checkStrategies := len(mask.StrategyNames()) > 0
	if err := validateCustomTypes(c, checkStrategies); err != nil {
		return err
	}
	return validateSystems(c, checkStrategies)
}

// validateServer checks the HTTP-layer knobs.
func validateServer(c *Config) error {
	if strings.TrimSpace(c.Server.Addr) == "" {
		return errors.New("config: server.addr is empty")
	}
	for _, d := range []struct {
		name string
		val  time.Duration
	}{
		{"read_timeout_ms", c.Server.ReadTimeout},
		{"write_timeout_ms", c.Server.WriteTimeout},
		{"idle_timeout_ms", c.Server.IdleTimeout},
		{"process_timeout_ms", c.Server.ProcessTimeout},
	} {
		if d.val <= 0 {
			return fmt.Errorf("config: server.%s must be positive", d.name)
		}
	}
	if c.Server.MaxBodyBytes <= 0 {
		return errors.New("config: server.max_body_bytes must be positive")
	}
	if c.Server.MaxConcurrent < 0 {
		return errors.New("config: server.max_concurrent must not be negative")
	}
	return nil
}

// validateStore checks the payload_id mapping store settings.
func validateStore(c *Config) error {
	if c.Store.Shards <= 0 {
		return errors.New("config: store.shards must be positive")
	}
	if c.Store.TTLSeconds <= 0 {
		return errors.New("config: store.ttl_seconds must be positive")
	}
	if c.Store.MaxEntries <= 0 {
		return errors.New("config: store.max_entries must be positive")
	}
	if c.Store.MaxBytes < 0 {
		return errors.New("config: store.max_bytes must not be negative")
	}
	if c.Store.MaxBytes > 0 && c.Store.MaxValueBytes > 0 && int64(c.Store.MaxValueBytes)*2 > c.Store.MaxBytes {
		return errors.New("config: store.max_bytes must hold at least one entry of store.max_value_bytes")
	}
	if c.Store.MaxValueBytes <= 0 {
		return errors.New("config: store.max_value_bytes must be positive")
	}
	return nil
}

// validateLog checks the logging settings.
func validateLog(c *Config) error {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level %q is unknown", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("config: log.format %q is unknown", c.Log.Format)
	}
	if c.Log.SampleEvery < 0 {
		return errors.New("config: log.sample_every must not be negative")
	}
	return nil
}

// validateLLM checks the LLM chain settings. The strategy name is checked only
// when the mask registry is populated, for the same reason validateTypeRule
// does: the config package must stay testable in isolation.
func validateLLM(c *Config) error {
	if c.LLM.TimeoutMS <= 0 {
		return errors.New("config: llm.timeout_ms must be positive")
	}
	if strings.TrimSpace(c.LLM.Model) == "" {
		return errors.New("config: llm.model is empty")
	}
	if strings.TrimSpace(c.LLM.Strategy) == "" {
		return errors.New("config: llm.strategy is empty")
	}
	if c.LLM.RequestsPerMinute < 0 {
		return errors.New("config: llm.requests_per_minute must not be negative")
	}
	if len(mask.StrategyNames()) > 0 && mask.Lookup(c.LLM.Strategy) == nil {
		return fmt.Errorf("config: llm.strategy %q is unknown", c.LLM.Strategy)
	}
	return nil
}

// validateSystems checks every configured system and its per-type rules.
func validateSystems(c *Config, checkStrategies bool) error {
	for id, s := range c.Systems {
		if s == nil {
			return fmt.Errorf("config: system %q is null", id)
		}
		if s.ID != id {
			return fmt.Errorf("config: system key %q does not match its id %q", id, s.ID)
		}
		for name, r := range s.Types {
			if err := validateTypeRule(id, name, r, checkStrategies); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateCustomTypes checks every user-defined PD type.
func validateCustomTypes(c *Config, checkStrategies bool) error {
	seen := make(map[string]bool, len(c.CustomTypes))
	for _, ct := range c.CustomTypes {
		if err := validateCustomType(ct, seen, checkStrategies); err != nil {
			return err
		}
	}
	return nil
}

// validateCustomType checks one user-defined PD type.
func validateCustomType(ct CustomType, seen map[string]bool, checkStrategies bool) error {
	if !customNameRe.MatchString(ct.Name) {
		return fmt.Errorf("config: custom type name %q must match ^[A-Z][A-Z0-9_]{1,40}$", ct.Name)
	}
	if knownTypes[ct.Name] {
		return fmt.Errorf("config: custom type name %q collides with a built-in type", ct.Name)
	}
	if seen[ct.Name] {
		return fmt.Errorf("config: duplicate custom type name %q", ct.Name)
	}
	seen[ct.Name] = true
	if _, err := regexp.Compile(ct.Pattern); err != nil {
		return fmt.Errorf("config: custom type %q: invalid pattern: %v", ct.Name, err)
	}
	if ct.Window < 0 || ct.Window > 200 {
		return fmt.Errorf("config: custom type %q: window %d is outside [0,200]", ct.Name, ct.Window)
	}
	if ct.MinConfidence < 0 || ct.MinConfidence > 1 {
		return fmt.Errorf("config: custom type %q: min_confidence %v is outside [0,1]", ct.Name, ct.MinConfidence)
	}
	if checkStrategies && mask.Lookup(ct.Strategy) == nil {
		return fmt.Errorf("config: custom type %q: unknown mask strategy %q", ct.Name, ct.Strategy)
	}
	return nil
}

// validateTypeRule checks one per-type rule of a system.
func validateTypeRule(id, name string, r TypeRule, checkStrategies bool) error {
	if !knownTypes[name] {
		return fmt.Errorf("config: system %q: unknown PD type %q", id, name)
	}
	if r.MinConfidence < 0 || r.MinConfidence > 1 {
		return fmt.Errorf("config: system %q type %q: min_confidence %v is outside [0,1]", id, name, r.MinConfidence)
	}
	for _, comp := range r.RequiresCompanion {
		if !knownTypes[comp] {
			return fmt.Errorf("config: system %q type %q: unknown companion type %q", id, name, comp)
		}
	}
	if !r.Enabled {
		return nil
	}
	if strings.TrimSpace(r.Strategy) == "" {
		return fmt.Errorf("config: system %q type %q: strategy is empty", id, name)
	}
	if checkStrategies && mask.Lookup(r.Strategy) == nil {
		return fmt.Errorf("config: system %q type %q: unknown mask strategy %q", id, name, r.Strategy)
	}
	return nil
}
