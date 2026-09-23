package store

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// testStore builds a store with the sweeper disabled (negative SweepInterval)
// so counter assertions are not racing a background goroutine.
func testStore(t *testing.T, cfg Config) Store {
	t.Helper()
	if cfg.SweepInterval == 0 {
		cfg.SweepInterval = -1
	}
	s := New(cfg)
	t.Cleanup(s.Close)
	return s
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	c := DefaultConfig()
	if c.Shards <= 0 || c.TTL <= 0 || c.MaxEntries <= 0 || c.MaxValueBytes <= 0 || c.SweepInterval <= 0 {
		t.Fatalf("default config has a non-positive field: %+v", c)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 4})

	want := Entry{
		Original:     "Иванов Иван Иванович, карта 4509 123456",
		Masked:       "И. И. И., карта 45** ****56",
		Types:        []string{"FIO", "CARD_NUMBER"},
		System:       "default",
		Replacements: []byte{1, 2, 3},
	}
	s.Put("req-1", want)

	got, ok := s.Get("req-1")
	if !ok {
		t.Fatal("Get after Put: not found")
	}
	if got.Original != want.Original || got.Masked != want.Masked || got.System != want.System {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
	if len(got.Types) != 2 || got.Types[0] != "FIO" || got.Types[1] != "CARD_NUMBER" {
		t.Fatalf("types not preserved: %v", got.Types)
	}
	if string(got.Replacements) != string(want.Replacements) {
		t.Fatalf("replacements not preserved: %v", got.Replacements)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
}

func TestGetUnknownID(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 2})

	if _, ok := s.Get("nope"); ok {
		t.Fatal("Get on empty store returned ok")
	}
	if st := s.Stats(); st.Misses != 1 || st.Hits != 0 {
		t.Fatalf("stats after miss: %+v", st)
	}
}

// Identifiers are compared byte for byte: two ids differing only in case are
// two different entries. Folding them would risk answering a demask with
// another request's text.
func TestIDIsCaseSensitive(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 8})

	s.Put("Req-A", Entry{Original: "upper"})
	if _, ok := s.Get("req-a"); ok {
		t.Fatal("lowercased id must not match")
	}
}

func TestPutOverwritesSameID(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 4})

	s.Put("id", Entry{Original: "first", Masked: "f****"})
	s.Put("id", Entry{Original: "second", Masked: "s*****"})

	got, ok := s.Get("id")
	if !ok || got.Original != "second" {
		t.Fatalf("overwrite failed: %+v ok=%v", got, ok)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d after overwrite, want 1", s.Len())
	}
	if st := s.Stats(); st.Puts != 2 {
		t.Fatalf("Puts = %d, want 2", st.Puts)
	}
}

func TestTTLExpiry(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 2, TTL: 20 * time.Millisecond})

	s.Put("short", Entry{Original: "secret"})
	if _, ok := s.Get("short"); !ok {
		t.Fatal("entry must be live immediately after Put")
	}

	time.Sleep(60 * time.Millisecond)

	if _, ok := s.Get("short"); ok {
		t.Fatal("entry must be gone after its TTL")
	}
	st := s.Stats()
	if st.Expired != 1 {
		t.Fatalf("Expired = %d, want 1", st.Expired)
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d after lazy expiry, want 0", s.Len())
	}
	// A repeated Get on the same dead id must not inflate Expired again.
	s.Get("short")
	if st := s.Stats(); st.Expired != 1 {
		t.Fatalf("Expired = %d after second Get, want 1", st.Expired)
	}
}

func TestSweeperReclaimsExpired(t *testing.T) {
	t.Parallel()
	// Sweeper enabled on purpose: nothing calls Get here, so only the
	// background goroutine can reclaim these entries.
	s := New(Config{Shards: 8, TTL: 10 * time.Millisecond, SweepInterval: 2 * time.Millisecond})
	defer s.Close()

	for i := 0; i < 50; i++ {
		s.Put(fmt.Sprintf("k%d", i), Entry{Original: "x"})
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Len() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := s.Len(); n != 0 {
		t.Fatalf("sweeper left %d entries behind", n)
	}
	if st := s.Stats(); st.Expired != 50 {
		t.Fatalf("Expired = %d, want 50", st.Expired)
	}
}

func TestSkipOversizedPayload(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 2, MaxValueBytes: 32})

	big := strings.Repeat("a", 64)
	s.Put("big", Entry{Original: big, Masked: "aa**"})

	if _, ok := s.Get("big"); ok {
		t.Fatal("oversized payload must not be stored")
	}
	st := s.Stats()
	if st.Skipped != 1 || st.Puts != 0 {
		t.Fatalf("stats after skip: %+v", st)
	}

	// The masked side is capped too: it is roughly as large as the original.
	s.Put("big2", Entry{Original: "ok", Masked: big})
	if _, ok := s.Get("big2"); ok {
		t.Fatal("oversized mask must not be stored")
	}
	if st := s.Stats(); st.Skipped != 2 {
		t.Fatalf("Skipped = %d, want 2", st.Skipped)
	}

	// A payload exactly at the limit is fine.
	s.Put("edge", Entry{Original: strings.Repeat("b", 32)})
	if _, ok := s.Get("edge"); !ok {
		t.Fatal("payload of exactly MaxValueBytes must be stored")
	}
}

func TestSkipEmptyID(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 2})

	s.Put("", Entry{Original: "secret"})
	if _, ok := s.Get(""); ok {
		t.Fatal("empty id must never be stored")
	}
	if st := s.Stats(); st.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", st.Skipped)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 4})

	s.Put("id", Entry{Original: "v"})
	s.Delete("id")
	if _, ok := s.Get("id"); ok {
		t.Fatal("deleted entry still readable")
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d after delete, want 0", s.Len())
	}
	s.Delete("id")     // idempotent
	s.Delete("absent") // no-op
	if s.Len() != 0 {
		t.Fatalf("Len = %d after redundant deletes, want 0", s.Len())
	}
}

func TestMaxEntriesSoftCap(t *testing.T) {
	t.Parallel()
	const softCap = 100
	s := testStore(t, Config{Shards: 4, MaxEntries: softCap})

	for i := 0; i < 1000; i++ {
		s.Put(fmt.Sprintf("id-%d", i), Entry{Original: "v"})
	}

	if n := s.Len(); n > softCap {
		t.Fatalf("Len = %d, must not exceed the cap %d", n, softCap)
	}
	st := s.Stats()
	if st.Evicted == 0 {
		t.Fatal("nothing was evicted despite exceeding MaxEntries")
	}
	if st.Puts != 1000 {
		t.Fatalf("Puts = %d, want 1000", st.Puts)
	}
	// The most recent write must survive: it is the one a demask will ask for.
	if _, ok := s.Get("id-999"); !ok {
		t.Fatal("the newest entry was evicted")
	}
}

func TestStatsCounters(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 4, MaxValueBytes: 8})

	s.Put("a", Entry{Original: "1"})
	s.Put("b", Entry{Original: "2"})
	s.Put("toolong", Entry{Original: "123456789"}) // skipped
	s.Get("a")                                     // hit
	s.Get("a")                                     // hit
	s.Get("zzz")                                   // miss
	s.Delete("b")

	// Bytes is 1: "a" holds a one-byte Original and no Masked, and "b" was
	// deleted, which must give its byte back.
	want := Stats{Entries: 1, Puts: 2, Hits: 2, Misses: 1, Expired: 0, Evicted: 0, Skipped: 1, Bytes: 1}
	if got := s.Stats(); got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

func TestConcurrentPutGet(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 64, MaxEntries: 1 << 20})

	const (
		workers = 16
		perWork = 500
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			concurrentPutGetWorker(t, s, w, perWork)
		}(w)
	}
	wg.Wait()

	if n := s.Len(); n != workers*perWork {
		t.Fatalf("Len = %d, want %d", n, workers*perWork)
	}
	// Every entry must still be readable after the storm: this is the exact
	// property the demasking half of the score depends on.
	assertAllEntriesReadable(t, s, workers, perWork)
}

// concurrentPutGetWorker writes and immediately reads back one worker's share
// of entries.
func concurrentPutGetWorker(t *testing.T, s Store, w, perWork int) {
	t.Helper()
	for i := 0; i < perWork; i++ {
		id := fmt.Sprintf("w%d-%d", w, i)
		orig := fmt.Sprintf("payload %d %d", w, i)
		s.Put(id, Entry{Original: orig, Masked: "pa*****", Types: []string{"FIO"}})
		got, ok := s.Get(id)
		if !ok {
			t.Errorf("%s: lost right after Put", id)
			return
		}
		if got.Original != orig {
			t.Errorf("%s: got %q want %q", id, got.Original, orig)
			return
		}
	}
}

// assertAllEntriesReadable checks that every entry written by the concurrent
// storm is still present and intact.
func assertAllEntriesReadable(t *testing.T, s Store, workers, perWork int) {
	t.Helper()
	for w := 0; w < workers; w++ {
		for i := 0; i < perWork; i++ {
			id := fmt.Sprintf("w%d-%d", w, i)
			got, ok := s.Get(id)
			if !ok || got.Original != fmt.Sprintf("payload %d %d", w, i) {
				t.Fatalf("%s: missing or corrupted after concurrent load", id)
			}
		}
	}
}

// Concurrent readers and writers on the SAME id, plus deletes, to shake out
// lock-upgrade mistakes in the lazy-expiry path under -race.
func TestConcurrentSameID(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 8, TTL: 5 * time.Millisecond})

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				s.Put("hot", Entry{Original: "v", Types: []string{"PHONE"}})
				s.Get("hot")
				if i%97 == 0 {
					s.Delete("hot")
				}
			}
		}()
	}
	wg.Wait()

	if n := s.Len(); n < 0 || n > 1 {
		t.Fatalf("Len = %d, want 0 or 1 for a single id", n)
	}
}

func TestUsableAfterClose(t *testing.T) {
	t.Parallel()
	s := New(Config{Shards: 4, SweepInterval: 5 * time.Millisecond})

	s.Put("before", Entry{Original: "kept"})
	s.Close()
	s.Close() // idempotent

	if got, ok := s.Get("before"); !ok || got.Original != "kept" {
		t.Fatal("entry stored before Close must stay readable")
	}
	// Close only stops reclamation; an in-flight request must never fail.
	s.Put("after", Entry{Original: "still works"})
	if got, ok := s.Get("after"); !ok || got.Original != "still works" {
		t.Fatal("Put after Close must still work")
	}
	s.Delete("after")
	if s.Len() != 1 {
		t.Fatalf("Len = %d after Close, want 1", s.Len())
	}
	if st := s.Stats(); st.Puts != 2 {
		t.Fatalf("Puts = %d after Close, want 2", st.Puts)
	}
}

func TestRoundUpPow2(t *testing.T) {
	t.Parallel()
	cases := map[int]int{-5: 1, 0: 1, 1: 1, 3: 4, 100: 128, 256: 256, 1 << 20: maxShards}
	for in, want := range cases {
		if got := roundUpPow2(in); got != want {
			t.Errorf("roundUpPow2(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestShardsPerTick(t *testing.T) {
	t.Parallel()
	// 30m TTL / 30s interval = 60 ticks, 256 shards -> 5 shards per tick.
	if got := shardsPerTick(256, 30*time.Minute, 30*time.Second); got != 5 {
		t.Errorf("shardsPerTick(256,30m,30s) = %d, want 5", got)
	}
	// An interval longer than the TTL still sweeps every shard each tick.
	if got := shardsPerTick(16, time.Second, 10*time.Second); got != 16 {
		t.Errorf("shardsPerTick(16,1s,10s) = %d, want 16", got)
	}
	if got := shardsPerTick(8, 0, 0); got != 1 {
		t.Errorf("shardsPerTick with zero durations = %d, want 1", got)
	}
}

// Shard distribution must be even, otherwise the stripes do not buy anything.
func TestShardDistribution(t *testing.T) {
	t.Parallel()
	s := New(Config{Shards: 16, SweepInterval: -1}).(*memStore)
	defer s.Close()

	counts := make(map[*shard]int)
	for i := 0; i < 16000; i++ {
		counts[s.shardOf(fmt.Sprintf("payload-id-%d", i))]++
	}
	if len(counts) != 16 {
		t.Fatalf("only %d of 16 shards used", len(counts))
	}
	for sh, n := range counts {
		if n < 500 || n > 2000 {
			t.Errorf("shard %p got %d of 16000 keys: distribution is skewed", sh, n)
		}
	}
}

func BenchmarkStorePutGet(b *testing.B) {
	s := New(Config{Shards: 256, MaxEntries: 1 << 22})
	defer s.Close()

	e := Entry{
		Original: "Иванов Иван Иванович, паспорт 4509 123456, +7 916 123-45-67",
		Masked:   "И. И. И., паспорт 45** ****56, +7 9** ***-**-67",
		Types:    []string{"FIO", "PASSPORT", "PHONE"},
		System:   "default",
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		var buf [32]byte
		for pb.Next() {
			id := string(appendID(buf[:0], i))
			s.Put(id, e)
			if _, ok := s.Get(id); !ok {
				b.Fatal("entry lost right after Put")
			}
			i++
		}
	})
}

// appendID formats a benchmark id without pulling fmt into the measured loop.
func appendID(dst []byte, n int) []byte {
	dst = append(dst, "bench-"...)
	if n == 0 {
		return append(dst, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(dst, tmp[i:]...)
}

// TestMaxBytesCapsMemory is the regression test for the defect that made the
// store unbounded in memory: MaxEntries counts records, and a record holds two
// full copies of the payload, so a configuration sized for small payloads went
// to OOM on large ones long before the count cap was anywhere near.
func TestMaxBytesCapsMemory(t *testing.T) {
	t.Parallel()
	const value = 4096
	// Room for about eight entries by size; the count cap is far out of reach,
	// so only the byte budget can stop the growth.
	s := testStore(t, Config{
		Shards: 4, MaxEntries: 1_000_000, MaxValueBytes: 1 << 20, MaxBytes: 8 * value,
	})

	big := strings.Repeat("x", value)
	for i := 0; i < 500; i++ {
		s.Put(fmt.Sprintf("id-%d", i), Entry{Original: big})
	}

	st := s.Stats()
	// The admission burst is bounded, so the store is allowed to overshoot by a
	// little; what it must not do is grow with the number of writes.
	if st.Bytes > 4*int64(8*value) {
		t.Fatalf("Bytes = %d, want the byte budget %d to hold", st.Bytes, 8*value)
	}
	if st.Evicted == 0 {
		t.Fatal("nothing was evicted despite exceeding MaxBytes")
	}
	if st.Entries >= 500 {
		t.Fatalf("Entries = %d: the byte budget did not bound the store", st.Entries)
	}
	// The newest mapping is the one a demasking request will ask for.
	if _, ok := s.Get("id-499"); !ok {
		t.Fatal("the newest entry was evicted")
	}
}

// TestBytesAccounting pins the bookkeeping: every path that removes a record
// must give its bytes back, or the budget drifts upwards until the store
// evicts everything.
func TestBytesAccounting(t *testing.T) {
	t.Parallel()
	s := testStore(t, Config{Shards: 2})

	s.Put("a", Entry{Original: "12345", Masked: "*****"})
	if got := s.Stats().Bytes; got != 10 {
		t.Fatalf("Bytes after put = %d, want 10", got)
	}
	// Overwriting must replace the cost, not add to it.
	s.Put("a", Entry{Original: "123", Masked: "***"})
	if got := s.Stats().Bytes; got != 6 {
		t.Fatalf("Bytes after overwrite = %d, want 6", got)
	}
	s.Delete("a")
	if got := s.Stats().Bytes; got != 0 {
		t.Fatalf("Bytes after delete = %d, want 0", got)
	}
}

// TestDefaultsRememberLargePayloads is the regression test for the defect that
// made demasking fail on big texts. The per-value limit is not a tuning knob:
// a Put refused here is a mapping that never existed, and the reverse step
// then answers with the mask instead of the original — silently, with only the
// Skipped counter to show for it. The defaults must therefore hold anything
// the HTTP layer is willing to accept (a 16 MiB body, at most ~5.5 MiB of text
// once JSON escaping is undone), and the byte budget must hold several of them.
func TestDefaultsRememberLargePayloads(t *testing.T) {
	t.Parallel()
	c := DefaultConfig()
	if c.MaxValueBytes < 8<<20 {
		t.Fatalf("MaxValueBytes = %d, want at least 8 MiB: the store cannot remember what the server accepts",
			c.MaxValueBytes)
	}
	if c.MaxBytes < 1<<30 {
		t.Fatalf("MaxBytes = %d, want at least 1 GiB", c.MaxBytes)
	}
	if int64(c.MaxValueBytes)*2 > c.MaxBytes {
		t.Fatalf("MaxBytes = %d cannot hold one entry of MaxValueBytes = %d", c.MaxBytes, c.MaxValueBytes)
	}

	// And the defaults really do accept such a value, rather than merely
	// claiming to: this is the exact shape of the 3 MiB payload that used to
	// come back as a mask on the reverse step.
	s := testStore(t, Config{Shards: 4})
	big := strings.Repeat("Клиент Иванов Иван Иванович. ", (3<<20)/29)
	s.Put("big", Entry{Original: big, Masked: big})
	got, ok := s.Get("big")
	if !ok {
		t.Fatalf("a %d-byte payload was refused by the default configuration", len(big))
	}
	if got.Original != big {
		t.Fatal("the stored original is not byte-identical")
	}
	if st := s.Stats(); st.Skipped != 0 {
		t.Fatalf("Skipped = %d, want 0", st.Skipped)
	}
}
