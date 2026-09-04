package main

import (
	"net"
	"strings"
	"sync"
)

// LiveConfig is the hot-reloadable, DB-backed runtime config. All readers
// (DNS handler, redirect dispatcher, web UI) go through the runtime's RWMutex
// so edits apply with no restart.
type LiveConfig struct {
	Upstreams      []string
	SpecialEnabled bool
	ShortEnabled   bool
	Redirects      []RedirectConfig
	Domains        []DomainConfig
	AutoSites      []AutoSiteConfig
}

// DomainConfig maps a custom domain (exact or wildcard) to a fixed IP.
type DomainConfig struct {
	Domain string
	IP     string
}

// AutoSiteConfig is a ".auto" mirror group: <Name>.auto redirects to the
// first working URL in Sites (in priority order).
type AutoSiteConfig struct {
	Name    string
	Sites   []string
	Enabled bool
}

// runtime owns the live snapshot consulted by the DNS handler and redirect
// dispatcher, plus the in-process restart logic in main.
type runtime struct {
	mu   sync.RWMutex
	live *LiveConfig
}

// snapshot returns a deep copy so callers can't mutate shared state.
func (rt *runtime) snapshot() *LiveConfig {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	cp := &LiveConfig{
		Upstreams:      append([]string(nil), rt.live.Upstreams...),
		SpecialEnabled: rt.live.SpecialEnabled,
		ShortEnabled:   rt.live.ShortEnabled,
		Domains:        append([]DomainConfig(nil), rt.live.Domains...),
	}
	cp.Redirects = make([]RedirectConfig, len(rt.live.Redirects))
	copy(cp.Redirects, rt.live.Redirects)
	cp.AutoSites = make([]AutoSiteConfig, len(rt.live.AutoSites))
	copy(cp.AutoSites, rt.live.AutoSites)
	return cp
}

func (rt *runtime) reload(s *Store) error {
	lc, err := s.loadLive()
	if err != nil {
		return err
	}
	rt.mu.Lock()
	rt.live = lc
	rt.mu.Unlock()
	return nil
}

func (rt *runtime) Upstreams() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return append([]string(nil), rt.live.Upstreams...)
}

func (rt *runtime) SpecialEnabled() bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.live.SpecialEnabled
}

func (rt *runtime) ShortEnabled() bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.live.ShortEnabled
}

// redirectFor returns a copy of the redirect whose domain matches name, or nil.
func (rt *runtime) redirectFor(name string) *RedirectConfig {
	norm := strings.ToLower(strings.TrimSuffix(name, "."))
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for i := range rt.live.Redirects {
		rc := rt.live.Redirects[i]
		if norm == rc.Domain || strings.HasSuffix(norm, "."+rc.Domain) {
			c := rc
			return &c
		}
	}
	return nil
}

// isRedirectTLD reports whether the TLD portion of name belongs to a registered
// redirect domain space. E.g. if "fy" is a redirect, then "novel.fy" has
// redirect TLD "fy" and should NOT be fed to the base32 short-code decoder.
func (rt *runtime) isRedirectTLD(name string) bool {
	norm := strings.ToLower(strings.TrimSuffix(name, "."))
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, rc := range rt.live.Redirects {
		if norm == rc.Domain || strings.HasSuffix(norm, "."+rc.Domain) {
			return true
		}
	}
	return false
}

func (rt *runtime) Redirects() []RedirectConfig {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]RedirectConfig, len(rt.live.Redirects))
	copy(out, rt.live.Redirects)
	return out
}

func (rt *runtime) Domains() []DomainConfig {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]DomainConfig, len(rt.live.Domains))
	copy(out, rt.live.Domains)
	return out
}

func (rt *runtime) AutoSites() []AutoSiteConfig {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]AutoSiteConfig, len(rt.live.AutoSites))
	for i, s := range rt.live.AutoSites {
		out[i] = s
		out[i].Sites = append([]string(nil), s.Sites...)
	}
	return out
}

// autoSite returns a copy of the registered ".auto" group for name, or nil.
func (rt *runtime) autoSite(name string) *AutoSiteConfig {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for i := range rt.live.AutoSites {
		s := rt.live.AutoSites[i]
		if strings.EqualFold(s.Name, name) {
			c := s
			c.Sites = append([]string(nil), s.Sites...)
			return &c
		}
	}
	return nil
}

// domainIP finds the IP for a query name among custom domains. Supports
// exact matches and a leading "*." wildcard; exact matches take precedence
// over wildcards. Returns nil if no match.
func (rt *runtime) domainIP(name string) net.IP {
	norm := strings.ToLower(strings.TrimSuffix(name, "."))

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// pass 1: exact match wins
	for _, d := range rt.live.Domains {
		dn := strings.ToLower(d.Domain)
		if dn == norm {
			if ip := net.ParseIP(d.IP); ip != nil {
				return ip
			}
		}
	}
	// pass 2: wildcard match
	for _, d := range rt.live.Domains {
		dn := strings.ToLower(d.Domain)
		if !strings.HasPrefix(dn, "*.") {
			continue
		}
		base := strings.TrimPrefix(dn, "*.")
		if strings.HasSuffix(norm, "."+base) {
			if ip := net.ParseIP(d.IP); ip != nil {
				return ip
			}
		}
	}
	return nil
}
