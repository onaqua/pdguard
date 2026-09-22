package metrics

import "sync/atomic"

// demaskFallbacks counts reverse requests we answered with the payload
// unchanged because the mapping was no longer available (TTL elapsed, entry too
// large to remember, process restarted, or demasking disabled for the system).
//
// It gets its own series rather than folding into store_misses because the two
// answer different questions: a store miss is a lookup that found nothing,
// while this counts the times that miss was visible to a client as a degraded
// answer. It is the single number that says "raise the TTL or the store cap".
var demaskFallbacks atomic.Int64

// IncDemaskFallback records one reverse request served with the payload echoed
// back unchanged.
func IncDemaskFallback() { demaskFallbacks.Add(1) }

// DemaskFallbacks returns the current count. Exported for tests and for the
// /stats endpoint.
func DemaskFallbacks() int64 { return demaskFallbacks.Load() }
