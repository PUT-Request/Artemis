package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnssecValidator validates DNSSEC signatures on responses from upstreams.
type dnssecValidator struct {
	enabled bool
	cache   map[string]*dnssecCacheEntry
	mu      sync.RWMutex
}

type dnssecCacheEntry struct {
	key    *dns.DNSKEY
	expiry time.Time
}

func newDNSSECValidator(enabled bool) *dnssecValidator {
	return &dnssecValidator{
		enabled: enabled,
		cache:   make(map[string]*dnssecCacheEntry),
	}
}

// Validate checks DNSSEC signatures on a response.
// Returns true if valid, disabled, or domain is unsigned.
func (v *dnssecValidator) Validate(resp *dns.Msg, upstreams []string) bool {
	if !v.enabled || resp == nil {
		return true
	}

	// Build RRSIG map: TypeCovered -> []RRSIG
	rrsigMap := map[uint16][]*dns.RRSIG{}
	for _, rr := range resp.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigMap[rrsig.TypeCovered] = append(rrsigMap[rrsig.TypeCovered], rrsig)
		}
	}
	for _, rr := range resp.Ns {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigMap[rrsig.TypeCovered] = append(rrsigMap[rrsig.TypeCovered], rrsig)
		}
	}

	// No RRSIGs = unsigned domain (acceptable)
	if len(rrsigMap) == 0 {
		return true
	}

	// Group answer records by type (skip RRSIG)
	rrsets := map[uint16][]dns.RR{}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		rrsets[rr.Header().Rrtype] = append(rrsets[rr.Header().Rrtype], rr)
	}

	// Validate each RRset against its RRSIG
	for rrType, rrs := range rrsets {
		rrsigList, ok := rrsigMap[rrType]
		if !ok {
			continue // no RRSIG for this type, skip
		}

		// Try each RRSIG until one verifies
		verified := false
		for _, rrsig := range rrsigList {
			if !rrsig.ValidityPeriod(time.Now()) {
				log.Printf("dnssec: signature expired for %s (type %d)", rrs[0].Header().Name, rrType)
				continue
			}

			// Fetch DNSKEY matching this RRSIG's SignerName + KeyTag
			dnskey := v.fetchDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm, upstreams)
			if dnskey == nil {
				log.Printf("dnssec: no DNSKEY for signer=%s keytag=%d", rrsig.SignerName, rrsig.KeyTag)
				continue
			}

			// Verify
			if err := rrsig.Verify(dnskey, rrs); err != nil {
				log.Printf("dnssec: verify failed for %s signer=%s: %v", rrs[0].Header().Name, rrsig.SignerName, err)
				continue
			}

			verified = true
			break
		}

		if !verified {
			log.Printf("dnssec: no valid RRSIG for %s (type %d)", rrs[0].Header().Name, rrType)
			return false
		}
	}

	return true
}

// fetchDNSKEY gets a DNSKEY matching signerName, keyTag, and algorithm.
func (v *dnssecValidator) fetchDNSKEY(signerName string, keyTag uint16, algorithm uint8, upstreams []string) *dns.DNSKEY {
	cacheKey := fmt.Sprintf("%s:%d:%d", signerName, keyTag, algorithm)

	// Check cache
	v.mu.RLock()
	if entry, ok := v.cache[cacheKey]; ok && time.Now().Before(entry.expiry) {
		v.mu.RUnlock()
		return entry.key
	}
	v.mu.RUnlock()

	// Fetch from upstreams
	for _, up := range upstreams {
		m := new(dns.Msg)
		m.SetQuestion(signerName, dns.TypeDNSKEY)
		m.SetEdns0(4096, true)

		c := &dns.Client{Timeout: 5 * time.Second}
		r, _, err := c.Exchange(m, up)
		if err != nil || r == nil {
			continue
		}

		// Find DNSKEY matching keyTag AND algorithm
		for _, rr := range r.Answer {
			if key, ok := rr.(*dns.DNSKEY); ok {
				if key.KeyTag() == keyTag && key.Algorithm == algorithm {
					v.mu.Lock()
					v.cache[cacheKey] = &dnssecCacheEntry{
						key:    key,
						expiry: time.Now().Add(1 * time.Hour),
					}
					v.mu.Unlock()
					return key
				}
			}
		}

		// Check Ns section (DNSKEY often appears there)
		for _, rr := range r.Ns {
			if key, ok := rr.(*dns.DNSKEY); ok {
				if key.KeyTag() == keyTag && key.Algorithm == algorithm {
					v.mu.Lock()
					v.cache[cacheKey] = &dnssecCacheEntry{
						key:    key,
						expiry: time.Now().Add(1 * time.Hour),
					}
					v.mu.Unlock()
					return key
				}
			}
		}
	}

	return nil
}

// Debug prints DNSSEC validation details for troubleshooting.
func (v *dnssecValidator) Debug(resp *dns.Msg, upstreams []string) {
	if resp == nil {
		return
	}
	
	rrsigs := 0
	for _, rr := range resp.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigs++
			log.Printf("dnssec-debug: RRSIG type=%d signer=%s keytag=%d algo=%d labels=%d origttl=%d exp=%d inc=%d",
				rrsig.TypeCovered, rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm,
				rrsig.Labels, rrsig.OrigTtl, rrsig.Expiration, rrsig.Inception)
		}
	}
	if rrsigs == 0 {
		log.Printf("dnssec-debug: no RRSIGs in response for %s", resp.Question[0].Name)
	}
}
