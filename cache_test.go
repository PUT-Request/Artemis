package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCacheHit(t *testing.T) {
	c := newDNSCache(5 * time.Second)
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("google.com.", dns.TypeA)
	resp.Answer = []dns.RR{
		aRecord("google.com.", net.ParseIP("142.251.222.14")),
	}

	// Miss on empty cache
	if got := c.get("google.com.", dns.TypeA); got != nil {
		t.Fatal("expected miss on empty cache")
	}

	// Store
	c.put("google.com.", dns.TypeA, resp)

	// Hit
	got := c.get("google.com.", dns.TypeA)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}

	// Stats
	hits, misses, _, size := c.stats()
	if hits != 1 || misses != 1 || size != 1 {
		t.Fatalf("stats: hits=%d misses=%d size=%d", hits, misses, size)
	}
}

func TestDNSCacheMissDifferentType(t *testing.T) {
	c := newDNSCache(5 * time.Second)
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("google.com.", dns.TypeA)
	resp.Answer = []dns.RR{
		aRecord("google.com.", net.ParseIP("142.251.222.14")),
	}
	c.put("google.com.", dns.TypeA, resp)

	// AAAA query should miss
	if got := c.get("google.com.", dns.TypeAAAA); got != nil {
		t.Fatal("expected miss for different qtype")
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	c := newDNSCache(1 * time.Millisecond) // very short TTL
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{
		aRecord("example.com.", net.ParseIP("93.184.216.34")),
	}
	c.put("example.com.", dns.TypeA, resp)

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	if got := c.get("example.com.", dns.TypeA); got != nil {
		t.Fatal("expected miss after expiry")
	}
}

func TestDNSCacheNoCacheServFail(t *testing.T) {
	c := newDNSCache(5 * time.Second)
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetRcode(new(dns.Msg), dns.RcodeServerFailure)

	c.put("bad.com.", dns.TypeA, resp)

	if got := c.get("bad.com.", dns.TypeA); got != nil {
		t.Fatal("SERVFAIL should not be cached")
	}
}

func TestDNSCacheNoCacheTruncated(t *testing.T) {
	c := newDNSCache(5 * time.Second)
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("big.com.", dns.TypeA)
	resp.Truncated = true

	c.put("big.com.", dns.TypeA, resp)

	if got := c.get("big.com.", dns.TypeA); got != nil {
		t.Fatal("truncated response should not be cached")
	}
}

func TestDNSCacheCopyIsolation(t *testing.T) {
	c := newDNSCache(5 * time.Second)
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("test.com.", dns.TypeA)
	resp.Answer = []dns.RR{
		aRecord("test.com.", net.ParseIP("1.2.3.4")),
	}
	c.put("test.com.", dns.TypeA, resp)

	got := c.get("test.com.", dns.TypeA)
	got.Answer[0].(*dns.A).A = net.ParseIP("9.9.9.9") // mutate cached copy

	// Original should be unaffected
	got2 := c.get("test.com.", dns.TypeA)
	if got2.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Fatal("cache returned mutated entry — copy isolation broken")
	}
}

func TestDNSCacheDisabled(t *testing.T) {
	c := newDNSCache(0) // disabled
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("no.com.", dns.TypeA)
	resp.Answer = []dns.RR{
		aRecord("no.com.", net.ParseIP("1.2.3.4")),
	}
	c.put("no.com.", dns.TypeA, resp)

	if got := c.get("no.com.", dns.TypeA); got != nil {
		t.Fatal("cache disabled should not store")
	}
}
