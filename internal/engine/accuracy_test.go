package engine

// This file is the quality gate. engine_test.go proves the contract branches
// are wired correctly on a handful of hand-picked payloads; this test asks a
// different question — how much of Appendix B do we actually catch, and how
// much untouched text do we damage while catching it.
//
// It runs the whole pipeline (detect -> resolve -> filter -> mask -> store ->
// demask) over testdata/golden.jsonl, the corpus that mirrors every category
// the specification lists. Detector coverage moves as detectors are tuned, so
// an individual miss is reported and not fatal; the three properties that
// cannot regress without costing the run are enforced. See the thresholds
// below for which is which.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// goldenPath is resolved from the package directory, which is where `go test`
// runs. The corpus lives at the repository root because cmd/bench feeds on the
// same file and must not reach into an internal package's testdata.
// goldenGlob matches every corpus shard. Cases are split across several
// files so that contributors extending different detectors never collide
// on one shared file; ids stay unique across the whole set.
const goldenGlob = "../../testdata/golden*.jsonl"

// Thresholds.
//
// minRecall is a floor, not a target. Recall is the share of expected
// (case, type) pairs the engine actually reported, micro-averaged, so one
// missed category inside a long complex sentence costs as much as a whole
// missed single-category case. Detectors are deliberately conservative — the
// jury's span-based Levenshtein metric charges for every byte we touch without
// cause — so some of the corpus is expected to be missed, and the gate is set
// where a real regression (a detector broken, a dictionary lost, a rule
// disabled in the default config) shows up but ordinary tuning does not.
//
// minNegativeClean and minExactRestore are 1.0 on purpose and are enforced per
// case rather than as an average: a single damaged negative case is a false
// positive the metric charges for directly, and a single inexact restore is a
// failed element in the graded run.
const (
	minRecall        = 0.85
	minNegativeClean = 1.0
	minExactRestore  = 1.0
)

// goldenCase is one line of testdata/golden.jsonl.
//
// ExpectTypes lists the pd.Type values the engine must report for the case. An
// empty list marks a negative case: the text contains no client personal data
// and must come back byte for byte.
type goldenCase struct {
	ID          string   `json:"id"`
	Text        string   `json:"text"`
	ExpectTypes []string `json:"expect_types"`
	Note        string   `json:"note"`
}

// loadGolden reads the corpus. Blank lines are skipped so the file can be kept
// readable in sections; anything else that fails to parse is a fatal error,
// because a silently dropped case would quietly lower the denominator of every
// ratio this test reports.
func loadGolden(t *testing.T) []goldenCase {
	t.Helper()
	paths, err := filepath.Glob(goldenGlob)
	if err != nil || len(paths) == 0 {
		t.Fatalf("no golden corpus matched %s: %v", goldenGlob, err)
	}
	sort.Strings(paths)

	var out []goldenCase
	seen := make(map[string]bool)
	for _, goldenPath := range paths {
		out = append(out, loadGoldenFile(t, goldenPath, seen)...)
	}
	return out
}

// loadGoldenFile reads one corpus shard, rejecting ids already used by an
// earlier shard.
func loadGoldenFile(t *testing.T, goldenPath string, seen map[string]bool) []goldenCase {
	t.Helper()
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("open golden dataset: %v", err)
	}
	defer f.Close()

	var out []goldenCase
	sc := bufio.NewScanner(f)
	// Complex-sentence cases run to several paragraphs; the default 64 KiB
	// token limit is enough today but the corpus is meant to grow.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var c goldenCase
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("%s:%d: %v", goldenPath, line, err)
		}
		if c.ID == "" {
			t.Fatalf("%s:%d: case has no id", goldenPath, line)
		}
		// Ids double as payload_id values, and the store folds them to lower
		// case: two cases differing only in case would share one mapping and
		// turn a real restore failure into a passing test.
		key := strings.ToLower(c.ID)
		if seen[key] {
			t.Fatalf("%s:%d: duplicate id %q", goldenPath, line, c.ID)
		}
		seen[key] = true
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read golden dataset: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no cases", goldenPath)
	}
	return out
}

// TestAccuracyGolden measures the engine against the whole corpus.
func TestAccuracyGolden(t *testing.T) {
	cases := loadGolden(t)
	e, _ := newEngine(t)
	ctx := context.Background()

	st := &goldenStats{
		missedByType: map[string]int{},
		extraByType:  map[string]int{},
	}
	for _, c := range cases {
		scoreGoldenCase(t, e, ctx, c, st)
	}

	recall := ratio(st.foundPairs, st.expectedPairs)
	negClean := ratio(st.negativeClean, st.negatives)
	restore := ratio(st.exactRestore, len(cases))

	t.Log("=== golden corpus summary ===")
	t.Logf("cases            %d (%d positive, %d negative)", len(cases), st.positives, st.negatives)
	t.Logf("recall           %.3f  (%d/%d expected type occurrences)", recall, st.foundPairs, st.expectedPairs)
	t.Logf("negatives clean  %.3f  (%d/%d untouched)", negClean, st.negativeClean, st.negatives)
	t.Logf("exact restore    %.3f  (%d/%d byte identical)", restore, st.exactRestore, len(cases))
	logCounts(t, "missed by type", st.missedByType)
	logCounts(t, "extra by type ", st.extraByType)
	for _, m := range st.missedCases {
		t.Logf("miss  %s", m)
	}

	if recall < minRecall {
		t.Errorf("recall %.3f is below the floor %.2f: a detector, a dictionary or a default config rule has regressed",
			recall, minRecall)
	}
	if negClean < minNegativeClean {
		t.Errorf("negative cases clean %.3f, want %.2f", negClean, minNegativeClean)
	}
	if restore < minExactRestore {
		t.Errorf("exact restore %.3f, want %.2f", restore, minExactRestore)
	}
}

// goldenStats accumulates the counters TestAccuracyGolden reports.
type goldenStats struct {
	expectedPairs int // (case, expected type) pairs over the whole corpus
	foundPairs    int // how many of them the engine reported
	positives     int
	negatives     int
	negativeClean int
	exactRestore  int

	missedByType map[string]int
	extraByType  map[string]int
	missedCases  []string
}

// scoreGoldenCase runs one corpus case through the engine and folds its result
// into the running totals.
func scoreGoldenCase(t *testing.T, e *Engine, ctx context.Context, c goldenCase, st *goldenStats) {
	t.Helper()
	// Forward step. The payload_id is the case id, so the reverse step
	// below exercises exactly the mapping the graded harness would use.
	fwd, err := e.Process(ctx, "", c.ID, c.Text)
	if err != nil {
		t.Errorf("%s: forward step failed: %v", c.ID, err)
		return
	}

	// Reverse step: feed back the mask we just produced.
	rev, err := e.Process(ctx, "", c.ID, fwd.Output)
	if err != nil {
		t.Errorf("%s: reverse step failed: %v", c.ID, err)
		return
	}

	// Property 3 — demasking is byte exact. Fatal: an inexact restore is a
	// failed element in the graded run, and it means the store round trip
	// or the direction decision is broken, not that a detector is shy.
	if rev.Output == c.Text {
		st.exactRestore++
	} else {
		t.Errorf("%s: demasking is not byte exact\n  want %q\n  got  %q", c.ID, c.Text, rev.Output)
	}

	got := make(map[string]bool, len(fwd.Types))
	for _, ty := range fwd.Types {
		got[ty] = true
	}

	if len(c.ExpectTypes) == 0 {
		// Property 2 — a negative case must leave the text alone. Fatal for
		// the same reason: the metric charges for every byte we change
		// without cause, and the specification names these exact shapes
		// (a poet's name, a branch address) as things we must not touch.
		st.negatives++
		if fwd.Output == c.Text && len(fwd.Types) == 0 {
			st.negativeClean++
		} else {
			t.Errorf("%s (%s): false positive on a negative case\n  text  %q\n  mask  %q\n  types %v",
				c.ID, c.Note, c.Text, fwd.Output, fwd.Types)
		}
		return
	}

	scoreGoldenPositive(t, c, fwd.Types, got, st)
}

// scoreGoldenPositive folds a positive case's recall and extra-type counts into
// the running totals.
func scoreGoldenPositive(t *testing.T, c goldenCase, types []string, got map[string]bool, st *goldenStats) {
	t.Helper()
	// Property 1 — recall. Reported, not enforced per case: detectors are
	// tuned towards missing a doubtful span rather than masking clean text,
	// so individual misses are information for whoever tunes them next.
	st.positives++
	missing := make([]string, 0, len(c.ExpectTypes))
	for _, want := range c.ExpectTypes {
		st.expectedPairs++
		if got[want] {
			st.foundPairs++
			continue
		}
		missing = append(missing, want)
		st.missedByType[want]++
	}
	if len(missing) > 0 {
		st.missedCases = append(st.missedCases,
			fmt.Sprintf("%s: missing %v (%s)", c.ID, missing, c.Note))
	}

	// Types found beyond what the case declares are counted but never
	// failed: the corpus lists the categories a case is *about*, and a
	// long sentence legitimately carries more. They are still worth
	// printing — a type that shows up everywhere is usually a detector
	// that has become too eager.
	for _, ty := range types {
		want := false
		for _, exp := range c.ExpectTypes {
			if exp == ty {
				want = true
				break
			}
		}
		if !want {
			st.extraByType[ty]++
		}
	}
}

// TestGoldenPayloadIDCaseInsensitive checks the identification rule from the
// specification on real corpus texts: the reverse step may arrive with the
// payload_id in a different case and must still find its mapping. It is a
// separate test because a failure here is a contract bug, not a quality number.
func TestGoldenPayloadIDCaseInsensitive(t *testing.T) {
	cases := loadGolden(t)
	e, _ := newEngine(t)
	ctx := context.Background()

	checked := 0
	for _, c := range cases {
		if len(c.ExpectTypes) == 0 {
			continue // nothing is stored for a case that masks nothing
		}
		fwd, err := e.Process(ctx, "", c.ID, c.Text)
		if err != nil {
			t.Fatalf("%s: forward step failed: %v", c.ID, err)
		}
		if fwd.Output == c.Text {
			continue // detectors found nothing, so there is no mapping to find
		}
		rev, err := e.Process(ctx, "", strings.ToUpper(c.ID), fwd.Output)
		if err != nil {
			t.Fatalf("%s: reverse step failed: %v", c.ID, err)
		}
		if rev.Output != c.Text {
			t.Fatalf("%s: upper-cased payload_id lost the mapping\n  want %q\n  got  %q",
				c.ID, c.Text, rev.Output)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no case produced a mask; the corpus or the detectors are broken")
	}
	t.Logf("case-insensitive payload_id verified on %d cases", checked)
}

// ratio guards the empty denominator so a corpus without negatives reports 1.0
// instead of NaN, which would compare false against every threshold.
func ratio(n, total int) float64 {
	if total == 0 {
		return 1
	}
	return float64(n) / float64(total)
}

// logCounts prints a map ordered by count, so the worst offender is first.
func logCounts(t *testing.T, label string, m map[string]int) {
	t.Helper()
	if len(m) == 0 {
		t.Logf("%s  none", label)
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%d", k, m[k])
	}
	t.Logf("%s  %s", label, b.String())
}
