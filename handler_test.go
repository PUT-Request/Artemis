package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

func TestIPFromPhoneQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"no trailing dot", "192-168-199-1", "192.168.199.1", true},
		{"trailing dot", "192-168-199-1.", "192.168.199.1", true},
		{"plus country code", "+1-192-168-199-1.", "192.168.199.1", true},
		{"longer country code", "+44-10-0-0-1.", "10.0.0.1", true},
		{"zero octet", "0-0-0-0.", "0.0.0.0", true},
		{"too few parts", "1-2-3.", "", false},
		{"octet too large", "+1-999-168-199-1.", "", false},
		{"non numeric", "192-168-abc-1.", "", false},
		{"prefix without plus", "1-192-168-199-1.", "", false},
		{"empty", ".", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipFromPhoneQuery(tt.in)
			if got.valid != tt.ok {
				t.Fatalf("valid = %v, want %v", got.valid, tt.ok)
			}
			if !got.valid {
				return
			}
			if got.ip.String() != tt.want {
				t.Fatalf("ip = %s, want %s", got.ip.String(), tt.want)
			}
		})
	}
}

func TestRedirectLabel(t *testing.T) {
	tests := []struct {
		name, qname, domain, want string
	}{
		{"single label", "privacy.fmhy.", "fmhy", "privacy"},
		{"case insensitive", "PRIVACY.FMHY.", "fmhy", "privacy"},
		{"nested picks leftmost", "a.b.fmhy.", "fmhy", "a"},
		{"apex", "fmhy.", "fmhy", ""},
		{"no match", "example.com.", "fmhy", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redirectLabel(tt.qname, tt.domain); got != tt.want {
				t.Fatalf("redirectLabel(%q, %q) = %q, want %q", tt.qname, tt.domain, got, tt.want)
			}
		})
	}
}

func TestRedirectTarget(t *testing.T) {
	rc := &RedirectConfig{Domain: "fmhy", Target: "https://fmhy.net", QueryParam: "q"}

	if got := redirectTarget(rc, "privacy"); got != "https://fmhy.net?q=privacy" {
		t.Fatalf("with label = %q, want %q", got, "https://fmhy.net?q=privacy")
	}
	if got := redirectTarget(rc, ""); got != "https://fmhy.net" {
		t.Fatalf("apex = %q, want %q", got, "https://fmhy.net")
	}
}

func newTestRuntime() *runtime {
	return &runtime{live: &LiveConfig{
		Upstreams:      []string{"1.1.1.1:53"},
		SpecialEnabled: true,
		Redirects: []RedirectConfig{
			{Domain: "fmhy", Target: "https://fmhy.net", QueryParam: "q"},
		},
		Domains: []DomainConfig{
			{Domain: "router.lan", IP: "192.168.1.1"},
			{Domain: "*.lan", IP: "10.0.0.9"},
		},
	}}
}

func TestRuntimeRedirectFor(t *testing.T) {
	rt := newTestRuntime()
	cases := []struct {
		qname string
		match bool
	}{
		{"fmhy.", true},
		{"privacy.fmhy.", true},
		{"PRIVACY.fmhy.", true},
		{"example.com.", false},
		{"notfmhy.", false},
		{"privacy.fmhy.evil.", false},
	}

	for _, c := range cases {
		if rc := rt.redirectFor(c.qname); (rc != nil) != c.match {
			t.Fatalf("redirectFor(%q) match = %v, want %v", c.qname, rc != nil, c.match)
		}
	}
}

func TestDynamicDomainIP(t *testing.T) {
	rt := newTestRuntime()
	cases := []struct {
		qname string
		want  string
		ok    bool
	}{
		{"router.lan.", "192.168.1.1", true},
		{"other.lan.", "10.0.0.9", true}, // wildcard
		{"a.b.lan.", "10.0.0.9", true},   // nested wildcard
		{"example.com.", "", false},
		{"lan.", "", false},
	}

	for _, c := range cases {
		ip := rt.domainIP(c.qname)
		if (ip != nil) != c.ok {
			t.Fatalf("domainIP(%q) ok = %v, want %v", c.qname, ip != nil, c.ok)
		}
		if ip != nil && ip.String() != c.want {
			t.Fatalf("domainIP(%q) = %s, want %s", c.qname, ip.String(), c.want)
		}
	}
}

func TestDynamicDomainExactBeatsWildcard(t *testing.T) {
	rt := &runtime{live: &LiveConfig{
		Domains: []DomainConfig{
			{Domain: "*.lan", IP: "10.0.0.9"},
			{Domain: "router.lan", IP: "192.168.1.1"},
		},
	}}
	// even though the wildcard sorts/stores first, exact match must win
	if ip := rt.domainIP("router.lan."); ip == nil || ip.String() != "192.168.1.1" {
		t.Fatalf("exact should win: got %v", ip)
	}
	if ip := rt.domainIP("laptop.lan."); ip == nil || ip.String() != "10.0.0.9" {
		t.Fatalf("wildcard should match: got %v", ip)
	}
}

func TestIsAutoName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"annas-archive.auto.", true},
		{"auto.", true},
		{"a.b.auto.", true},
		{"annas-archive.AUTO.", true},
		{"example.com.", false},
		{"auto.example.", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isAutoName(c.in); got != c.want {
			t.Fatalf("isAutoName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAutoGroupName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"annas-archive.auto", "annas-archive"},
		{"annas-archive.auto:80", "annas-archive"},
		{"annas-archive.AUTO", "annas-archive"},
		{"a.b.auto", "a.b"},
		{"auto", ""},
		{"auto:80", ""},
		{"example.com", ""},
	}
	for _, c := range cases {
		if got := autoGroupName(c.in); got != c.want {
			t.Fatalf("autoGroupName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAutoPickerFailover(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()

	rt := newTestRuntime()
	a := &app{cfg: cfg, rt: rt, store: nil}
	srv := newAutoServer(a)

	// fake checker: first mirror down, second up
	group := &AutoSiteConfig{
		Name:    "annas-archive",
		Sites:   []string{"https://mirror1.example/", "https://mirror2.example/"},
		Enabled: true,
	}
	srv.check = func(url string) bool { return url == "https://mirror2.example" }

	if got := srv.pick(group); got != "https://mirror2.example/" {
		t.Fatalf("pick = %q, want mirror2 (first is down)", got)
	}

	// all down -> first mirror as fallback (clear cache first)
	srv.check = func(string) bool { return false }
	srv.cache = map[string]autoCacheEntry{}
	if got := srv.pick(group); got != "https://mirror1.example/" {
		t.Fatalf("all-down pick = %q, want mirror1 fallback", got)
	}
}

func TestAutoRuntimeLookup(t *testing.T) {
	rt := &runtime{live: &LiveConfig{
		AutoSites: []AutoSiteConfig{
			{Name: "annas-archive", Sites: []string{"https://a.example"}, Enabled: true},
		},
	}}
	g := rt.autoSite("annas-archive")
	if g == nil || g.Name != "annas-archive" {
		t.Fatal("autoSite should find group")
	}
	if g := rt.autoSite("unknown"); g != nil {
		t.Fatal("autoSite unknown should be nil")
	}
}

func TestRuntimeSnapshotIsolate(t *testing.T) {
	rt := newTestRuntime()
	snap := rt.snapshot()
	snap.Upstreams[0] = "changed"
	if rt.live.Upstreams[0] != "1.1.1.1:53" {
		t.Fatal("snapshot should not mutate live config")
	}
}

func TestRedirectAnswer(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	cfg.HTTP.AnswerIP = "10.1.2.3"
	rt := newTestRuntime()
	h := newHandler(cfg, rt, nil)
	q := dns.Question{Name: "privacy.fmhy.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := new(dns.Msg)
	req.Question = []dns.Question{q}
	resp := h.redirectAnswer(req, q)

	if resp.Rcode != 0 || len(resp.Answer) != 1 {
		t.Fatalf("rcode = %d, answers = %d", resp.Rcode, len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.IPv4(10, 1, 2, 3)) {
		t.Fatalf("answer ip = %s, want 10.1.2.3", a.A.String())
	}
}

// TestHTTPFrontRouting verifies the merged dispatcher: redirect domains 302,
// .auto hosts go to the auto picker, everything else 404s.
func TestHTTPFrontRouting(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	rt := &runtime{live: &LiveConfig{
		Redirects: []RedirectConfig{
			{Domain: "fmhy", Target: "https://fmhy.net", QueryParam: "q"},
		},
		AutoSites: []AutoSiteConfig{
			{Name: "annas-archive", Sites: []string{"https://a.example"}, Enabled: true},
		},
	}}
	a := &app{cfg: cfg, rt: rt, store: nil}
	front := &httpFront{handler: newHandler(cfg, rt, nil), auto: newAutoServer(a)}
	front.auto.check = func(string) bool { return true }

	srv := httptest.NewServer(front)
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// redirect domain -> 302 to target
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Host = "privacy.fmhy"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://fmhy.net?q=privacy" {
		t.Fatalf("redirect got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// .auto host -> 302 to working mirror
	req2, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req2.Host = "annas-archive.auto"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("auto: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound || resp2.Header.Get("Location") != "https://a.example" {
		t.Fatalf("auto got %d %q", resp2.StatusCode, resp2.Header.Get("Location"))
	}

	// unknown -> 404
	req3, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req3.Host = "example.com"
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("unknown: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown got %d, want 404", resp3.StatusCode)
	}
}
