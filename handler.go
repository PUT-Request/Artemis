package main

import (
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type handler struct {
	cfg   *Config
	rt    *runtime
	store *Store
	udp   *dns.Client
	tcp   *dns.Client
	acl   []*net.IPNet
	rl    *rateLimiter
	cache *dnsCache
}

func newHandler(cfg *Config, rt *runtime, store *Store) *handler {
	timeout := cfg.Server.Timeout.Std()
	h := &handler{
		cfg:   cfg,
		rt:    rt,
		store: store,
		udp:   &dns.Client{Net: "udp", Timeout: timeout},
		tcp:   &dns.Client{Net: "tcp", Timeout: timeout},
		rl:    newRateLimiter(cfg.Server.RateLimit),
	}
	if cfg.Server.DNSCacheTTL.Std() > 0 {
		h.cache = newDNSCache(cfg.Server.DNSCacheTTL.Std())
	}
	for _, cidr := range cfg.Server.ACL {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			h.acl = append(h.acl, n)
		} else {
			log.Printf("invalid acl cidr %q ignored", cidr)
		}
	}
	return h
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := clientIPOf(w.RemoteAddr())
	if !h.allowed(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}
	m := h.resolveMsg(r, clientIP)
	// Truncate to the client's advertised payload size on UDP (never on TCP).
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		m.Truncate(udpMaxSize(r))
	}
	if err := w.WriteMsg(m); err != nil {
		log.Printf("write to %s failed: %v", w.RemoteAddr(), err)
	}
}

// resolveMsg runs the shared resolution + logging logic for a raw DNS message.
// Used by both the socket servers and the DoH handler.
func (h *handler) resolveMsg(r *dns.Msg, clientIP string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true

	if len(r.Question) == 0 {
		m.Rcode = dns.RcodeServerFailure
		return m
	}
	if len(r.Question) > 1 {
		// We only resolve a single question; reject multi-question packets.
		m.Rcode = dns.RcodeFormatError
		return m
	}

	q := r.Question[0]
	var resp *dns.Msg

	if p := ipFromPhoneQuery(q.Name); h.rt.SpecialEnabled() && p.valid {
		resp = h.specialAnswer(r, q, p.ip)
	} else if rc := h.rt.redirectFor(q.Name); h.cfg.HTTP.Enabled && rc != nil {
		resp = h.redirectAnswer(r, q)
	} else if h.cfg.HTTP.Enabled && isShortName(q.Name, h.cfg.HTTP.ShortTLD) && h.rt.ShortEnabled() && !h.rt.isRedirectTLD(q.Name) {
		resp = h.autoAnswer(r, q)
	} else if h.cfg.HTTP.Enabled && isAutoName(q.Name) {
		resp = h.autoAnswer(r, q)
	} else if ip := h.rt.domainIP(q.Name); ip != nil {
		resp = h.domainAnswer(r, q, ip)
	} else {
		resp = h.forward(q, r)
	}

	m.Answer = append(m.Answer, resp.Answer...)
	m.Ns = append(m.Ns, resp.Ns...)
	m.Extra = append(m.Extra, resp.Extra...)
	m.Rcode = resp.Rcode
	m.Truncated = m.Truncated || resp.Truncated

	if h.store != nil {
		h.store.LogIP(clientIP)
	}
	return m
}

// udpMaxSize returns the largest UDP response size the client accepts:
// its EDNS0 advertised payload size, else 512, capped at 4096.
func udpMaxSize(r *dns.Msg) int {
	size := 512
	if opt := r.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > size {
			size = s
		}
	}
	if size > 4096 {
		size = 4096
	}
	return size
}

// specialAnswer returns the embedded IP for a phone-style query,
// e.g. "+1-192-168-199-1" -> 192.168.199.1. Only A queries get an answer.
func (h *handler) specialAnswer(r *dns.Msg, q dns.Question, ip net.IP) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Rcode = dns.RcodeNameError
	if q.Qtype != dns.TypeA {
		return m
	}
	m.Rcode = dns.RcodeSuccess
	m.Answer = []dns.RR{aRecord(q.Name, ip)}
	return m
}

// redirectAnswer resolves a *.domain query to the configured answer IP.
func (h *handler) redirectAnswer(r *dns.Msg, q dns.Question) *dns.Msg {
	return h.domainAnswer(r, q, net.ParseIP(h.cfg.HTTP.AnswerIP))
}

// domainAnswer returns the configured IP for a custom-domain query.
func (h *handler) domainAnswer(r *dns.Msg, q dns.Question, ip net.IP) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Rcode = dns.RcodeNameError
	if q.Qtype != dns.TypeA {
		return m
	}
	m.Rcode = dns.RcodeSuccess
	m.Answer = []dns.RR{aRecord(q.Name, ip)}
	return m
}

// autoAnswer resolves any name under the reserved ".auto" TLD to the
// configured answer IP so the visitor lands on our redirect server.
func (h *handler) autoAnswer(r *dns.Msg, q dns.Question) *dns.Msg {
	return h.domainAnswer(r, q, net.ParseIP(h.cfg.HTTP.AnswerIP))
}

// isAutoName reports whether name is the apex "auto" or under ".auto".
func isAutoName(name string) bool {
	norm := strings.ToLower(strings.TrimSuffix(name, "."))
	return norm == "auto" || strings.HasSuffix(norm, ".auto")
}

// isShortName reports whether name is the apex or under the short-code TLD,
// e.g. "32" or "*.32".
func isShortName(name, tld string) bool {
	if tld == "" {
		return false
	}
	norm := strings.ToLower(strings.TrimSuffix(name, "."))
	tld = strings.ToLower(tld)
	return norm == tld || strings.HasSuffix(norm, "."+tld)
}

func aRecord(name string, ip net.IP) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   ip.To4(),
	}
}

// forward relays the query to the first upstream that answers, retrying over
// TCP if the UDP response is truncated. Responses are cached when a cache is
// configured.
func (h *handler) forward(q dns.Question, r *dns.Msg) *dns.Msg {
	// Check cache first.
	if h.cache != nil {
		if cached := h.cache.get(q.Name, q.Qtype); cached != nil {
			cached.Id = r.Id // match the caller's transaction ID
			return cached
		}
	}

	var resp *dns.Msg
	for _, up := range h.rt.Upstreams() {
		resp, _, err := h.udp.Exchange(r, up)
		if err == nil && !resp.Truncated {
			break
		}
		if err == nil && resp.Truncated {
			if tcpResp, _, terr := h.tcp.Exchange(r, up); terr == nil {
				resp = tcpResp
				break
			}
			// TCP also failed — return the truncated UDP response.
			break
		}
		log.Printf("upstream %s failed: %v", up, err)
		resp = nil
	}

	if resp == nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}

	// Store in cache.
	if h.cache != nil {
		h.cache.put(q.Name, q.Qtype, resp)
	}
	return resp
}

// redirectLabel extracts the query parameter label from a redirect query,
// e.g. "privacy.fmhy." -> "privacy"; apex "fmhy." -> "".
func redirectLabel(name, domain string) string {
	norm := strings.ToLower(strings.TrimSuffix(name, "."))
	if norm == domain {
		return ""
	}
	suffix := "." + domain
	if !strings.HasSuffix(norm, suffix) {
		return ""
	}
	label := strings.TrimSuffix(norm, suffix)
	if label != "" {
		return strings.Split(label, ".")[0]
	}
	return ""
}

// redirectTarget builds the redirect URL, e.g. "https://fmhy.net/?q=privacy".
// The label is URL-escaped so attacker-controlled DNS labels can't inject
// extra query parameters or fragments.
func redirectTarget(rc *RedirectConfig, label string) string {
	target := strings.TrimRight(rc.Target, "/")
	if label != "" && rc.QueryParam != "" {
		return target + "?" + url.QueryEscape(rc.QueryParam) + "=" + url.QueryEscape(label)
	}
	return target
}

type phoneIP struct {
	ip    net.IP
	valid bool
}

// ipFromPhoneQuery detects names like "+1-192-168-199-1" or "192-168-199-1".
// Any leading phone-number prefix ("+<cc>") is allowed; the last 4
// dash-separated segments must be valid octets.
func ipFromPhoneQuery(name string) phoneIP {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return phoneIP{}
	}
	parts := strings.Split(name, "-")
	if len(parts) < 4 {
		return phoneIP{}
	}

	oct := parts[len(parts)-4:]
	var b [4]byte
	for i, p := range oct {
		// ParseUint rejects a leading sign, so "+1" can't sneak in as an octet.
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return phoneIP{}
		}
		b[i] = byte(n)
	}

	prefix := parts[:len(parts)-4]
	if len(prefix) > 0 {
		joined := strings.Join(prefix, "-")
		if !strings.HasPrefix(joined, "+") {
			return phoneIP{}
		}
		digits := strings.TrimPrefix(joined, "+")
		if digits == "" || !allDigits(digits) {
			return phoneIP{}
		}
	}

	return phoneIP{ip: net.IPv4(b[0], b[1], b[2], b[3]).To4(), valid: true}
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func clientIPOf(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
