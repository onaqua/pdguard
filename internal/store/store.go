// Package store remembers what we did to a payload so the demasking request
// that follows can answer with the byte-exact original.
//
// The grading protocol sends two requests carrying the same payload_id: the
// first masks, the second demasks. Half the score is the demasking half, and
// unlike detection it is fully deterministic — either we still hold the
// original or we lose those points outright. Everything here is therefore
// tuned for survivability under load rather than for cleverness: no eviction
// that can fire earlier than it must, no shared lock that can stall, no path
// that can panic and take the process down between the two requests.
//
// SECURITY: Entry.Original (and Entry.Masked) are the protected values. They
// live in memory only, are never written to a log, a metric or an error
// string, and never leave this package except through Get. Only Entry.Types —
// category identifiers such as "FIO" — may be logged.
package store

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is what we remember about one masking operation.
//
// The store treats an Entry as immutable once handed to Put: the slices are
// kept by reference rather than copied, because Replacements can be large and
// this is the hot path. Callers must not mutate a slice they have passed to
// Put or received from Get.
type Entry struct {
	// Original is the exact payload we were asked to mask. Returning it
	// verbatim is what makes demasking lossless. Protected data — never log.
	Original string
	// Masked is the payload we answered with. The handler compares an incoming
	// payload against it to tell a demasking request from a retried masking
	// request. Protected data — never log.
	Masked string
	// Types lists the PD categories found, as pd.Type strings. This is the only
	// field that is safe to log or export as a metric label.
	Types []string
	// System names the masking profile/config used, so a retry answers with the
	// same shape even if the running config was reloaded in between.
	System string
	// Replacements is an opaque blob reserved for the positional restore path
	// (encoded mask.Replacement records). The store never interprets it; it may
	// be nil when the caller relies on Original alone.
	Replacements []byte
}

// Config tunes the in-memory store. A zero value is valid: New fills every
// field from DefaultConfig. A negative SweepInterval disables the background
// sweeper, which is useful in tests that assert exact counters.
type Config struct {
	Shards     int           // number of independent lock stripes; default 256
	TTL        time.Duration // entry lifetime; default 30 minutes
	MaxEntries int           // global soft cap on the entry COUNT; default 2_000_000
	// MaxValueBytes refuses to remember a payload larger than this; default
	// 8 MiB.
	//
	// The number is not a tuning knob, it is a correctness constraint: it must
	// be at least as large as the biggest body the HTTP layer is willing to
	// accept. A refused Put is silent, so a payload above this limit is masked,
	// answered, and then NOT found on the reverse step — and a reverse step that
	// finds nothing cannot reconstruct the original, because a mask is lossy.
	// Demasking simply did not work for those payloads, with no error anywhere
	// to say so. Anything we accept as a body, we must be able to remember.
	MaxValueBytes int
	// MaxBytes is the global soft cap on the total SIZE of the live entries,
	// len(Original)+len(Masked) summed; default 1 GiB.
	//
	// It exists because MaxEntries alone cannot bound memory. An entry holds two
	// full copies of the payload, and the specification allows payloads of 100k
	// tokens — a few hundred kilobytes each. With a count cap of 200k and no
	// byte budget at all the configuration permitted terabytes: the process died
	// of OOM, took the whole in-memory store with it, and every reverse step
	// still owed an original then answered with the mask instead. A byte budget
	// is the only cap that tracks what actually fills the heap.
	//
	// The budget is sized against the deployment, not guessed: the container is
	// given 2 GiB (docker-compose.yml) and the process sets GOMEMLIMIT to 80% of
	// that from the cgroup, which leaves a gigabyte for the mappings and the
	// rest for the in-flight requests and the collector's headroom.
	MaxBytes      int64
	SweepInterval time.Duration // background expiry sweep; default 30 seconds
}

// Stats is a snapshot of the store counters. Every field counts events, never
// content, so the whole struct is safe to log and to export as metrics.
type Stats struct {
	Entries int64 // live entries, including expired ones not yet swept
	Puts    int64 // successful Put calls
	Hits    int64 // Get calls that returned a live entry
	Misses  int64 // Get calls that found nothing or found an expired entry
	Expired int64 // entries dropped because their TTL ran out
	Evicted int64 // live entries dropped to honour MaxEntries or MaxBytes
	Skipped int64 // Put calls refused (empty id or oversized payload)
	Bytes   int64 // sum of len(Original)+len(Masked) over the live entries
}

// Store is the contract the HTTP layer depends on. A second implementation
// (for example a Redis-backed one for multi-instance deployments) can be
// dropped in without touching the handler.
type Store interface {
	// Put remembers e under id, replacing any previous entry and restarting the
	// TTL. A refused Put is silent by design: the caller learns about it from
	// the following Get returning false and falls back to the positional
	// restore path.
	Put(id string, e Entry)
	// Get returns the entry for id. The second result is false when the id is
	// unknown or its TTL has elapsed; callers must treat both the same way.
	Get(id string) (Entry, bool)
	// Delete forgets id. It is a no-op when id is unknown.
	Delete(id string)
	// Len is the approximate number of live entries.
	Len() int
	// Stats returns a counter snapshot.
	Stats() Stats
	// Close stops the background sweeper. The store stays readable and
	// writable afterwards, so an in-flight request can never fail because of a
	// shutdown race.
	Close()
}

// DefaultConfig returns the tuned defaults described in Config.
func DefaultConfig() Config {
	return Config{
		Shards:        defaultShards,
		TTL:           defaultTTL,
		MaxEntries:    defaultMaxEntries,
		MaxValueBytes: defaultMaxValueBytes,
		MaxBytes:      defaultMaxBytes,
		SweepInterval: defaultSweepInterval,
	}
}

// Defaults chosen for the hackathon profile: 1000 RPS, payloads up to 100k
// tokens, two requests per payload_id a few seconds apart.
const (
	defaultShards     = 256
	defaultTTL        = 30 * time.Minute
	defaultMaxEntries = 2_000_000
	// 8 MiB. The HTTP layer accepts a 16 MiB body, and a Cyrillic payload that
	// arrives JSON-escaped (\uXXXX, six bytes per two-byte letter) shrinks about
	// threefold when decoded, so 16 MiB of body is at most ~5.5 MiB of text.
	// Eight covers that with margin, and the engine's masked-payload echo (see
	// engine.looksMasked) catches whatever still does not fit.
	defaultMaxValueBytes = 8 << 20
	defaultMaxBytes      = 1 << 30 // 1 GiB; see Config.MaxBytes for the arithmetic
	defaultSweepInterval = 30 * time.Second

	maxShards = 4096

	// evictSample is how many random keys Put looks at when it has to make room
	// immediately. Sampling is the trick Redis uses for its approximated LRU:
	// it costs O(1) with no bookkeeping on the hot path, and with 8 samples the
	// victim is old enough in practice. An exact LRU would need an intrusive
	// list updated under the write lock on every Get, which would turn reads
	// into writes and cost far more than the precision is worth here.
	evictSample = 8

	// evictBurst caps how many records one Put may reclaim. A byte budget can
	// be exceeded by a single large payload, so one freed slot is not always
	// enough; letting Put drain a whole shard, however, would move the cost of
	// a burst onto whichever request happens to arrive during it. Eight is the
	// compromise: enough to absorb a big entry, small enough to stay O(1) on
	// the request path, and the sweeper reclaims whatever is left over.
	evictBurst = 8

	// shrinkFloor/shrinkRatio decide when a shard's map is rebuilt. Go never
	// returns bucket memory after deletes, so a traffic spike would otherwise
	// pin the peak footprint for the life of the process.
	shrinkFloor = 1024
	shrinkRatio = 4
)

// FNV-1a constants, identical to hash/fnv's 32-bit variant. The algorithm is
// inlined rather than taken from hash/fnv because fnv.New32a returns an
// interface value that escapes to the heap on every call; on a 1000 RPS path
// an allocation per lookup is not worth the import.
const (
	fnvOffset32 = 2166136261
	fnvPrime32  = 16777619
)

// record is an entry plus its deadline. Because the TTL is uniform, ordering
// records by expires is the same as ordering them by insertion time, so FIFO
// eviction comes for free without a second timestamp field.
type record struct {
	entry   Entry
	expires int64 // time.Now().UnixNano() + TTL
	size    int64 // this record's cost against MaxBytes; see entrySize
}

// shard is one lock stripe. At 1000 RPS a single global mutex would serialise
// every request; 256 stripes make contention negligible.
type shard struct {
	mu   sync.RWMutex
	m    map[string]record
	high int // largest len(m) seen since the last rebuild, for shrinking

	// Deliberate over-padding: the hot fields above occupy well under one
	// cache line, and this pushes the next shard's mutex onto a different line
	// so two cores writing to neighbouring shards do not ping-pong it.
	_ [64]byte
}

type memStore struct {
	shards []shard
	mask   uint32 // len(shards)-1; len is always a power of two

	ttl           int64 // nanoseconds
	maxEntries    int64
	maxValueBytes int
	maxBytes      int64
	sweepInterval time.Duration
	shardsPerTick int

	entries atomic.Int64
	bytes   atomic.Int64
	puts    atomic.Int64
	hits    atomic.Int64
	misses  atomic.Int64
	expired atomic.Int64
	evicted atomic.Int64
	skipped atomic.Int64

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// New builds the sharded in-memory store and starts its sweeper.
func New(cfg Config) Store {
	def := DefaultConfig()
	if cfg.Shards <= 0 {
		cfg.Shards = def.Shards
	}
	if cfg.TTL <= 0 {
		cfg.TTL = def.TTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = def.MaxEntries
	}
	if cfg.MaxValueBytes <= 0 {
		cfg.MaxValueBytes = def.MaxValueBytes
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = def.MaxBytes
	}
	if cfg.SweepInterval == 0 {
		cfg.SweepInterval = def.SweepInterval
	}

	n := roundUpPow2(cfg.Shards)
	s := &memStore{
		shards:        make([]shard, n),
		mask:          uint32(n - 1),
		ttl:           int64(cfg.TTL),
		maxEntries:    int64(cfg.MaxEntries),
		maxValueBytes: cfg.MaxValueBytes,
		maxBytes:      cfg.MaxBytes,
		sweepInterval: cfg.SweepInterval,
		shardsPerTick: shardsPerTick(n, cfg.TTL, cfg.SweepInterval),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	for i := range s.shards {
		s.shards[i].m = make(map[string]record)
	}
	if cfg.SweepInterval > 0 {
		go s.sweepLoop()
	} else {
		close(s.done) // nothing to wait for; Close stays non-blocking
	}
	return s
}

// roundUpPow2 clamps the shard count to a power of two in [1,maxShards] so the
// shard index is a mask-and instead of a division.
func roundUpPow2(n int) int {
	if n < 1 {
		n = 1
	}
	if n > maxShards {
		n = maxShards
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// shardsPerTick spreads a full sweep cycle over one TTL: sweeping a single
// shard per tick (256 shards, 30s ticks) would take over two hours, so expired
// payloads would outlive their TTL by a wide margin and hold memory. Sweeping
// the whole table on one tick instead would produce a latency sawtooth, which
// the 1s budget cannot afford.
func shardsPerTick(shards int, ttl, interval time.Duration) int {
	if interval <= 0 || ttl <= 0 {
		return 1
	}
	ticks := int64(ttl / interval)
	if ticks < 1 {
		ticks = 1
	}
	per := (int64(shards) + ticks - 1) / ticks
	if per < 1 {
		per = 1
	}
	if per > int64(shards) {
		per = int64(shards)
	}
	return int(per)
}

func (s *memStore) shardOf(id string) *shard {
	h := uint32(fnvOffset32)
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= fnvPrime32
	}
	return &s.shards[h&s.mask]
}

// Put stores e under id.
//
// Two cases are refused and counted as Skipped. An empty id, because every
// empty id would collide and demasking would then return another request's
// text — returning nothing is bad, returning someone else's payload is worse.
// And a payload above MaxValueBytes, as the last line of defence against a
// single pathological body pinning the heap; the global byte budget is what
// bounds ordinary traffic.
//
// A refusal is invisible to the caller until the following Get returns false,
// which is precisely why MaxValueBytes must stay above the accepted body size:
// the reverse step then has nothing to answer with. Skipped is the counter to
// watch — a non-zero value means some payload_id lost its mapping the moment it
// was created.
func (s *memStore) Put(id string, e Entry) {
	if id == "" || len(e.Original) > s.maxValueBytes || len(e.Masked) > s.maxValueBytes {
		s.skipped.Add(1)
		return
	}
	now := time.Now().UnixNano()
	rec := record{entry: e, expires: now + s.ttl, size: entrySize(e)}

	sh := s.shardOf(id)
	sh.mu.Lock()
	if old, exists := sh.m[id]; exists {
		s.bytes.Add(-old.size)
	} else {
		// Over a soft cap: free space first so the table cannot grow past it
		// even when the sweeper is stopped or lagging behind a burst.
		for i := 0; i < evictBurst && s.overCap(); i++ {
			if !s.evictSampled(sh, now) {
				break // this shard has nothing left to give
			}
		}
		s.entries.Add(1)
	}
	s.bytes.Add(rec.size)
	sh.m[id] = rec
	if len(sh.m) > sh.high {
		sh.high = len(sh.m)
	}
	sh.mu.Unlock()

	s.puts.Add(1)
}

// entrySize is what one record costs against MaxBytes: both protected strings.
// Types and Replacements are not counted — they are bounded by the category
// list and are noise next to two copies of the payload.
func entrySize(e Entry) int64 { return int64(len(e.Original)) + int64(len(e.Masked)) }

// overCap reports whether the store is above either soft cap.
func (s *memStore) overCap() bool {
	return s.entries.Load() >= s.maxEntries || s.bytes.Load() >= s.maxBytes
}

// evictSampled frees one slot in sh and reports whether it managed to. The
// caller must hold sh.mu for writing. Map iteration order in Go is randomised,
// which gives us the random sample for free. An expired record found along the
// way is preferred: dropping it costs nobody anything.
func (s *memStore) evictSampled(sh *shard, now int64) bool {
	var (
		victim    string
		victimExp int64 = math.MaxInt64
		victimSz  int64
		seen      int
	)
	for k, r := range sh.m {
		if r.expires <= now {
			delete(sh.m, k)
			// The reason counter always moves before the live count, so an
			// observer that sees Len() drop knows Stats() already explains why.
			s.expired.Add(1)
			s.entries.Add(-1)
			s.bytes.Add(-r.size)
			return true
		}
		if r.expires < victimExp {
			victimExp, victim, victimSz = r.expires, k, r.size
		}
		seen++
		if seen >= evictSample {
			break
		}
	}
	if seen == 0 {
		return false // this shard is empty; the sweeper will drain the busy ones
	}
	// victim can never be "": Put refuses empty ids, so "" is a safe sentinel.
	delete(sh.m, victim)
	s.evicted.Add(1)
	s.entries.Add(-1)
	s.bytes.Add(-victimSz)
	return true
}

// Get returns the entry for id when it is still live.
func (s *memStore) Get(id string) (Entry, bool) {
	sh := s.shardOf(id)

	sh.mu.RLock()
	rec, ok := sh.m[id]
	sh.mu.RUnlock()

	if !ok {
		s.misses.Add(1)
		return Entry{}, false
	}
	if now := time.Now().UnixNano(); rec.expires <= now {
		// Lazy expiry: reads take the read lock, so the delete needs a second
		// pass under the write lock. It happens only on the rare expired hit,
		// and the re-check there keeps the counters exact under concurrency.
		s.dropExpired(sh, id, now)
		s.misses.Add(1)
		return Entry{}, false
	}
	s.hits.Add(1)
	return rec.entry, true
}

func (s *memStore) dropExpired(sh *shard, id string, now int64) {
	sh.mu.Lock()
	if rec, ok := sh.m[id]; ok && rec.expires <= now {
		delete(sh.m, id)
		s.expired.Add(1)
		s.entries.Add(-1)
		s.bytes.Add(-rec.size)
	}
	sh.mu.Unlock()
}

// Delete forgets id.
func (s *memStore) Delete(id string) {
	sh := s.shardOf(id)
	sh.mu.Lock()
	if rec, ok := sh.m[id]; ok {
		delete(sh.m, id)
		s.entries.Add(-1)
		s.bytes.Add(-rec.size)
	}
	sh.mu.Unlock()
}

// Len reports the number of stored entries. It is approximate in exactly one
// direction: entries whose TTL has elapsed but which no Get or sweep has
// touched yet are still counted.
func (s *memStore) Len() int { return int(s.entries.Load()) }

// Stats returns a snapshot of the counters. The fields are read one by one, so
// a snapshot taken under concurrent traffic is internally consistent only to
// within a few in-flight operations — fine for logging, not a ledger.
func (s *memStore) Stats() Stats {
	return Stats{
		Entries: s.entries.Load(),
		Puts:    s.puts.Load(),
		Hits:    s.hits.Load(),
		Misses:  s.misses.Load(),
		Expired: s.expired.Load(),
		Evicted: s.evicted.Load(),
		Skipped: s.skipped.Load(),
		Bytes:   s.bytes.Load(),
	}
}

// Close stops the sweeper. It is idempotent and safe to call concurrently with
// traffic: reads and writes keep working afterwards, only the background
// reclamation stops.
func (s *memStore) Close() {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done // make shutdown observable, so tests and -race see a clean exit
	})
}

func (s *memStore) sweepLoop() {
	defer close(s.done)
	t := time.NewTicker(s.sweepInterval)
	defer t.Stop()

	next := 0
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			n := s.shardsPerTick
			if s.overCap() {
				n *= 4 // over the cap: reclaim faster, latency comes second
			}
			for i := 0; i < n && i < len(s.shards); i++ {
				s.sweepShard(&s.shards[next])
				next = (next + 1) & int(s.mask)
			}
		}
	}
}

// sweepShard drops the expired records of one shard and, while the store is
// over its soft cap, also drops that shard's share of the oldest live ones.
func (s *memStore) sweepShard(sh *shard) {
	now := time.Now().UnixNano()

	sh.mu.Lock()
	defer sh.mu.Unlock()

	for k, r := range sh.m {
		if r.expires <= now {
			delete(sh.m, k)
			s.expired.Add(1)
			s.entries.Add(-1)
			s.bytes.Add(-r.size)
		}
	}

	if need := s.shardEvictQuota(len(sh.m)); need > 0 {
		s.evictOldest(sh, need)
	}

	// Rebuild a map that has shrunk far below its peak: Go keeps the buckets of
	// deleted keys forever, so without this a single burst would pin memory.
	if sh.high > shrinkFloor && len(sh.m)*shrinkRatio < sh.high {
		fresh := make(map[string]record, len(sh.m))
		for k, r := range sh.m {
			fresh[k] = r
		}
		sh.m = fresh
		sh.high = len(fresh)
	}
}

// evictOldest removes the n oldest records of sh. The caller must hold sh.mu
// for writing. Sorting a shard costs O(k log k) over roughly MaxEntries/Shards
// keys and only ever runs while the store is over its cap, so it stays off the
// request path.
func (s *memStore) evictOldest(sh *shard, n int) {
	type victim struct {
		key     string
		expires int64
		size    int64
	}
	cand := make([]victim, 0, len(sh.m))
	for k, r := range sh.m {
		cand = append(cand, victim{k, r.expires, r.size})
	}
	sort.Slice(cand, func(i, j int) bool { return cand[i].expires < cand[j].expires })
	for i := 0; i < n && i < len(cand); i++ {
		delete(sh.m, cand[i].key)
		s.evicted.Add(1)
		s.entries.Add(-1)
		s.bytes.Add(-cand[i].size)
	}
}

// shardEvictQuota is this shard's share of the overshoot, in records.
//
// Two caps are honoured at once. The entry cap converts directly into a record
// count; the byte cap is converted with the store's own mean record size, which
// is the only estimate available without walking every shard. Both are shares
// of the whole store spread over all shards, so one sweep cycle brings the
// store back under the cap without any shard over-reclaiming on its own.
func (s *memStore) shardEvictQuota(shardLen int) int {
	if shardLen == 0 {
		return 0
	}
	need := int64(0)
	if over := s.entries.Load() - s.maxEntries; over > 0 {
		need = over
	}
	entries := s.entries.Load()
	if overBytes := s.bytes.Load() - s.maxBytes; overBytes > 0 && entries > 0 {
		mean := s.bytes.Load() / entries
		if mean < 1 {
			mean = 1
		}
		if byCount := overBytes / mean; byCount > need {
			need = byCount
		}
	}
	if need <= 0 {
		return 0
	}
	per := int(need)/len(s.shards) + 1
	if per > shardLen {
		per = shardLen
	}
	return per
}
