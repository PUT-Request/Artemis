package main

import (
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestShortDecodeRoundtrip(t *testing.T) {
	enc := func(u string) string {
		// base32 no padding, then lowercased to mimic browser behavior
		return strings.ToLower(base32NoPad(u))
	}
	cases := []struct{ host, want string }{
		{"nb2hi4dthixs6ztnnb4s43tfoqxt64j5obzgs5tbmn4q.ba", "https://fmhy.net/?q=privacy"},
		{enc("https://annas-archive.se/") + ".ba", "https://annas-archive.se/"},
		{enc("example.com") + ".ba", "https://example.com"}, // no scheme -> prepend https
	}
	for _, c := range cases {
		got, err := shortDecode(c.host, "ba")
		if err != nil {
			t.Fatalf("shortDecode(%q): %v", c.host, err)
		}
		if got != c.want {
			t.Fatalf("shortDecode(%q) = %q, want %q", c.host, got, c.want)
		}
	}
	// multi-label join: one long base32 string split across DNS labels
	e := enc("https://example.com/some/very/long/path")
	split := e[:40] + "." + e[40:]
	if got, err := shortDecode(split+".ba", "ba"); err != nil || got != "https://example.com/some/very/long/path" {
		t.Fatalf("multi-label = %q err=%v", got, err)
	}
	// invalid labels -> error
	for _, bad := range []string{"!!!.ba", "a.ba", "foo.ba"} {
		if _, err := shortDecode(bad, "ba"); err == nil {
			t.Fatalf("shortDecode(%q) should fail", bad)
		}
	}
	// wrong tld
	if _, err := shortDecode("nb2hi4dthixs6ztnnb4s43tfoqxt64j5obzgs5tbmn4q.ba", "go"); err == nil {
		t.Fatal("wrong tld should fail")
	}
}

func base32NoPad(u string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(u))
}

// TestShortFrontRouting verifies the HTTP front 302s .ba short codes when
// enabled and 404s them when disabled.
func TestShortFrontRouting(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	rt := &runtime{live: &LiveConfig{
		ShortEnabled: true,
		Redirects:    []RedirectConfig{{Domain: "fmhy", Target: "https://fmhy.net", QueryParam: "q"}},
		AutoSites:    []AutoSiteConfig{{Name: "annas-archive", Sites: []string{"https://a.example"}, Enabled: true}},
	}}
	a := &app{cfg: cfg, rt: rt, store: nil}
	front := &httpFront{handler: newHandler(cfg, rt, nil), auto: newAutoServer(a)}
	front.auto.check = func(string) bool { return true }

	srv := httptest.NewServer(front)
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	enc := strings.ToLower(base32NoPad("https://fmhy.net/?q=privacy"))
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Host = enc + ".ba"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("short: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://fmhy.net/?q=privacy" {
		t.Fatalf("short got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// disabled -> 404
	rt.mu.Lock()
	rt.live.ShortEnabled = false
	rt.mu.Unlock()
	req2, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req2.Host = enc + ".ba"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("short disabled: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled got %d, want 404", resp2.StatusCode)
	}
}

func TestIsShortName(t *testing.T) {
	cases := []struct {
		name, tld string
		want      bool
	}{
		{"foo.32.", "32", true},
		{"32.", "32", true},
		{"foo.32.", "32", true},
		{"foo.32.", "go", false},
		{"foo.go.", "go", true},
		{"foo.32.", "", false},
		{"", "32", false},
	}
	for _, c := range cases {
		if got := isShortName(c.name, c.tld); got != c.want {
			t.Fatalf("isShortName(%q,%q) = %v, want %v", c.name, c.tld, got, c.want)
		}
	}
}

func TestResolveMsgShortDNS(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	rt := &runtime{live: &LiveConfig{ShortEnabled: true}}
	h := newHandler(cfg, rt, nil)
	q := dns.Question{Name: "nb2hi4dthixs6ztnnb4s43tfoqxt64j5obzgs5tbmn4q.ba.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := new(dns.Msg)
	req.Question = []dns.Question{q}
	m := h.resolveMsg(req, "127.0.0.1")
	if m.Rcode != 0 || len(m.Answer) != 1 {
		t.Fatalf("rcode=%d answers=%d", m.Rcode, len(m.Answer))
	}
	a := m.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Fatalf("answer = %s", a.A.String())
	}
}

// Regression: resolveMsg must evaluate redirectFor/domainIP exactly once so a
// concurrent config reload can't produce a nil deref (TOCTOU panic).
func TestResolveMsgSingleEval(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	rt := newTestRuntime()
	h := newHandler(cfg, rt, nil)

	// refresh the runtime mid-flight from a goroutine to stress the race
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			lc := rt.snapshot() // read under RLock
			rt.mu.Lock()
			rt.live = lc // write under Lock (no nesting)
			rt.mu.Unlock()
		}
		close(done)
	}()

	q := dns.Question{Name: "privacy.fmhy.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := new(dns.Msg)
	req.Question = []dns.Question{q}
	for i := 0; i < 2000; i++ {
		m := h.resolveMsg(req, "127.0.0.1")
		if m.Rcode != 0 || len(m.Answer) != 1 {
			t.Fatalf("iter %d: rcode=%d answers=%d", i, m.Rcode, len(m.Answer))
		}
	}
	<-done
}

func TestResolveMsgMultiQuestionRejected(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	rt := newTestRuntime()
	h := newHandler(cfg, rt, nil)

	req := new(dns.Msg)
	req.Question = []dns.Question{
		{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	m := h.resolveMsg(req, "127.0.0.1")
	if m.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %d, want FORMERR", m.Rcode)
	}
}

func TestValidateRedirectURL(t *testing.T) {
	good := []string{"https://annas-archive.pk/", "http://192.168.1.50:8080", "https://localhost/mirror", "http://127.0.0.1:9101", "http://[::1]:8080"}
	for _, u := range good {
		if err := validateRedirectURL(u); err != nil {
			t.Fatalf("expected %q valid, got %v", u, err)
		}
	}
	bad := []string{
		"https://example.com/\r\nX-Injected: yes", // CRLF / header injection
		"javascript:alert(1)",
		"ftp://example.com/",
		"https://169.254.169.254/", // cloud metadata
		"http://0.0.0.0/",
		"",
	}
	for _, u := range bad {
		if err := validateRedirectURL(u); err == nil {
			t.Fatalf("expected %q rejected", u)
		}
	}
}

func TestAuthOKNoLengthLeak(t *testing.T) {
	if authOK("abc", "a") {
		t.Fatal("mismatch should not pass")
	}
	if !authOK("secret", "secret") {
		t.Fatal("match should pass")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request within a second should be denied")
	}
	if !rl.allow("5.6.7.8") {
		t.Fatal("different IP should be allowed")
	}
	// unlimited
	ul := newRateLimiter(0)
	if !ul.allow("1.2.3.4") {
		t.Fatal("limit 0 means unlimited")
	}
}

func TestAllowedACL(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	cfg.Server.ACL = []string{"192.168.1.0/24", "127.0.0.1/8"}
	rt := newTestRuntime()
	h := newHandler(cfg, rt, nil)

	if !h.allowed("127.0.0.1") || !h.allowed("192.168.1.20") {
		t.Fatal("allowed IPs rejected")
	}
	if h.allowed("8.8.8.8") {
		t.Fatal("non-ACL IP allowed")
	}
}

func TestServerHTTPHeaders(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	a := &app{cfg: cfg}
	w := newWebServer(a)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w.render(rec, req, "dashboard", map[string]any{})

	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("CSP missing frame-ancestors")
	}
}

func TestDeriveLabel(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/privacy", "privacy"},
		{"/tools/ai-checker", "ai-checker.tools"},
		{"/a/b/c", "c.b.a"},
		{"/", ""},
		{"/tools/AI-Checker", "ai-checker.tools"}, // lowercased
		{"/tools/ai checker", "aichecker.tools"},  // space dropped from segment
	}
	for _, c := range cases {
		if got := deriveLabel(c.path); got != c.want {
			t.Errorf("deriveLabel(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestUpsertRedirectRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upsert.db")
	st, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()
	rc := RedirectConfig{Domain: "privacy.fy", Target: "https://fmhy.net/privacy"}
	if err := st.UpsertRedirect("eli32", rc); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// upsert again -> updates target in place, stays one row
	rc.Target = "https://fmhy.net/privacy-tools"
	if err := st.UpsertRedirect("eli32", rc); err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	reds, err := st.listRedirects()
	if err != nil {
		t.Fatalf("listRedirects: %v", err)
	}
	n := 0
	for _, r := range reds {
		if r.Domain == "privacy.fy" {
			n++
			if r.Target != "https://fmhy.net/privacy-tools" {
				t.Fatalf("target = %q", r.Target)
			}
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 privacy.fy row, got %d", n)
	}
}

func TestRedirectsSortedBySpecificity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sort.db")
	st, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()
	for _, d := range []string{"ai.tools.fy", "tools.fy", "fy"} {
		if err := st.UpsertRedirect("eli32", RedirectConfig{Domain: d, Target: "https://example.com"}); err != nil {
			t.Fatalf("upsert %s: %v", d, err)
		}
	}
	reds, err := st.listRedirects()
	if err != nil {
		t.Fatalf("listRedirects: %v", err)
	}
	// most specific first
	if len(reds) != 3 || reds[0].Domain != "ai.tools.fy" || reds[2].Domain != "fy" {
		t.Fatalf("not sorted by specificity: %+v", reds)
	}
}
