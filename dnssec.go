package main

import (
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnssecValidator validates DNSSEC signatures on responses from upstreams.
type dnssecValidator struct {
	enabled bool
	cache   map[string]*dns.DNSKEY
	mu      sync.RWMutex
}

// newDNSSECValidator creates a new DNSSEC validator.
func newDNSSECValidator(enabled bool) *dnssecValidator {
	return &dnssecValidator{
		enabled: enabled,
		cache:   make(map[string]*dns.DNSKEY),
	}
}

// Validate checks if a response has valid DNSSEC signatures.
// Returns true if valid, if DNSSEC is disabled, or if the domain is unsigned.
func (v *dnssecValidator) Validate(resp *dns.Msg) bool {
	if !v.enabled || resp == nil {
		return true
	}

	// No RRSIG = unsigned domain, which is acceptable
	rrsig := v.extractRRSIG(resp)
	if rrsig == nil {
		return true
	}

	// Get DNSKEY from response or fetch it
	dnskey := v.extractDNSKEY(resp)
	if dnskey == nil {
		dnskey = v.fetchDNSKEY(rrsig.SignerName)
		if dnskey == nil {
			log.Printf("dnssec: could not get DNSKEY for %s", rrsig.SignerName)
			return false
		}
	}

	// Check signature validity period
	if !rrsig.ValidityPeriod(time.Now()) {
		log.Printf("dnssec: signature expired for %s", resp.Question[0].Name)
		return false
	}

	// Verify signature on answer records
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		if err := rrsig.Verify(dnskey, []dns.RR{rr}); err != nil {
			log.Printf("dnssec: validation failed for %s: %v", rr.Header().Name, err)
			return false
		}
	}

	return true
}

// extractRRSIG finds the first RRSIG record in the response.
func (v *dnssecValidator) extractRRSIG(resp *dns.Msg) *dns.RRSIG {
	for _, rr := range resp.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			return rrsig
		}
	}
	for _, rr := range resp.Ns {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			return rrsig
		}
	}
	return nil
}

// extractDNSKEY finds the first DNSKEY record in the response.
func (v *dnssecValidator) extractDNSKEY(resp *dns.Msg) *dns.DNSKEY {
	for _, rr := range resp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			return key
		}
	}
	for _, rr := range resp.Ns {
		if key, ok := rr.(*dns.DNSKEY); ok {
			return key
		}
	}
	return nil
}

// fetchDNSKEY retrieves the DNSKEY for a signer name from upstream.
func (v *dnssecValidator) fetchDNSKEY(signerName string) *dns.DNSKEY {
	// Check cache
	v.mu.RLock()
	if key, ok := v.cache[signerName]; ok {
		v.mu.RUnlock()
		return key
	}
	v.mu.RUnlock()

	// Query for DNSKEY
	m := new(dns.Msg)
	m.SetQuestion(signerName, dns.TypeDNSKEY)
	m.SetEdns0(4096, true) // DO bit

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 5 * time.Second

	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil || r == nil {
		// Try TCP
		c.Net = "tcp"
		r, _, err = c.Exchange(m, "1.1.1.1:53")
		if err != nil || r == nil {
			return nil
		}
	}

	// Extract DNSKEY from response
	for _, rr := range r.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			// Cache it
			v.mu.Lock()
			v.cache[signerName] = key
			v.mu.Unlock()
			return key
		}
	}

	return nil
}
