package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// cacheKey uniquely identifies a DNS query.
type cacheKey struct {
	name  string // normalized lowercase qname with trailing dot
	qtype uint16
}

// cacheEntry holds a cached DNS response.
type cacheEntry struct {
	resp    *dns.Msg
	expires time.Time
}

// dnsCache is a concurrent-safe, TTL-based DNS response cache. It stores
// responses keyed by (qname, qtype) and evicts expired entries lazily on
// access plus a periodic background sweep.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[cacheKey]cacheEntry
	maxTTL  time.Duration

	// Stats (atomically updated, read without lock).
	hits   atomic.Uint64
	misses atomic.Uint64
	evicts atomic.Uint64

	stop chan struct{}
}

// newDNSCache creates a cache with the given max TTL and starts a background
// eviction goroutine that runs every minute.
func newDNSCache(maxTTL time.Duration) *dnsCache {
	c := &dnsCache{
		entries: make(map[cacheKey]cacheEntry),
		maxTTL:  maxTTL,
		stop:    make(chan struct{}),
	}
	go c.evictLoop()
	return c
}

// get returns a cached response if present and not expired, otherwise nil.
func (c *dnsCache) get(name string, qtype uint16) *dns.Msg {
	key := cacheKey{name: dns.CanonicalName(name), qtype: qtype}

	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil
	}
	if time.Now().After(e.expires) {
		// Lazy eviction with double-check to avoid TOCTOU race.
		c.mu.Lock()
		if e2, ok := c.entries[key]; ok && time.Now().After(e2.expires) {
			delete(c.entries, key)
			c.evicts.Add(1)
		}
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	c.hits.Add(1)
	resp := e.resp.Copy()
	return resp
}

// put stores a DNS response in the cache, capping TTL to maxTTL.
func (c *dnsCache) put(name string, qtype uint16, resp *dns.Msg) {
	if c.maxTTL <= 0 {
		return
	}
	// Never cache SERVFAIL or truncated responses.
	if resp.Rcode == dns.RcodeServerFailure || resp.Truncated {
		return
	}
	// Use the minimum TTL from the answer/auth/add sections, capped to maxTTL.
	ttl := c.minTTL(resp)
	if ttl <= 0 {
		return
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	key := cacheKey{name: dns.CanonicalName(name), qtype: qtype}
	c.mu.Lock()
	c.entries[key] = cacheEntry{
		resp:    resp.Copy(),
		expires: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

// stats returns current hit/miss/evict counters and entry count.
func (c *dnsCache) stats() (hits, misses, evicts, size uint64) {
	c.mu.RLock()
	size = uint64(len(c.entries))
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), c.evicts.Load(), size
}

// minTTL returns the smallest TTL across all answer, authority, and extra
// records. Returns 0 if there are no records.
func (c *dnsCache) minTTL(resp *dns.Msg) time.Duration {
	var minTTL time.Duration
	for _, rr := range append(resp.Answer, append(resp.Ns, resp.Extra...)...) {
		if t := rr.Header().Ttl; t > 0 {
			d := time.Duration(t) * time.Second
			if minTTL == 0 || d < minTTL {
				minTTL = d
			}
		}
	}
	return minTTL
}

// evictLoop runs every minute and removes expired entries.
func (c *dnsCache) evictLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.evict()
		case <-c.stop:
			return
		}
	}
}

func (c *dnsCache) evict() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
			c.evicts.Add(1)
		}
	}
}

// stop terminates the background eviction goroutine.
func (c *dnsCache) Close() {
	close(c.stop)
}
