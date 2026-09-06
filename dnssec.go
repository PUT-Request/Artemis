package main

import (
	"log"

	"github.com/miekg/dns"
)

// dnssecValidator handles DNSSEC DO bit forwarding.
// We trust upstreams (AdGuard, Mullvad) to validate DNSSEC.
// This validator only ensures the DO bit is properly forwarded.
type dnssecValidator struct {
	enabled bool
}

// newDNSSECValidator creates a new DNSSEC validator.
func newDNSSECValidator(enabled bool) *dnssecValidator {
	return &dnssecValidator{
		enabled: enabled,
	}
}

// SetDOBit sets the DNSSEC OK bit on a query if DNSSEC is enabled.
// This tells upstreams to return DNSSEC data (RRSIG, DNSKEY).
func (v *dnssecValidator) SetDOBit(r *dns.Msg) {
	if !v.enabled {
		return
	}
	// Set DO bit with 4096 byte payload
	r.SetEdns0(4096, true)
}

// Validate checks if the response is valid.
// Since we trust upstreams, we just pass through their responses.
// If upstream returns SERVFAIL (DNSSEC failure), we pass it through.
func (v *dnssecValidator) Validate(resp *dns.Msg) bool {
	if !v.enabled || resp == nil {
		return true
	}
	
	// Log DNSSEC status for debugging
	if resp.Rcode == dns.RcodeServerFailure {
		log.Printf("dnssec: upstream returned SERVFAIL (possible DNSSEC failure)")
	}
	
	// Always return true - we trust the upstream's validation
	return true
}

// HasRRSIG checks if a response contains RRSIG records.
func (v *dnssecValidator) HasRRSIG(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}
	return false
}
