package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// webServer is the management UI. It authenticates with HTTP Basic auth
// against config.webui and serves Bootstrap-rendered pages from templates/.
type webServer struct {
	app       *app
	server    *http.Server
	tmpl      *template.Template
	csrfMu    sync.Mutex
	csrfToken string
	limiter   *authLimiter
}

func newWebServer(a *app) *webServer {
	w := &webServer{app: a, limiter: &authLimiter{fails: map[string]*failState{}}}
	funcs := template.FuncMap{
		"add":       func(a, b int) int { return a + b },
		"hasPrefix": func(s, prefix string) bool { return strings.HasPrefix(s, prefix) },
	}
	w.tmpl = template.Must(template.New("").Funcs(funcs).ParseGlob("templates/*.html"))
	w.refreshCSRF()

	mux := http.NewServeMux()
	mux.HandleFunc("/", w.route)
	w.server = newHTTPServer(w.basicAuth(mux))
	w.server.Addr = a.cfg.WebUI.Listen
	return w
}

func (w *webServer) refreshCSRF() {
	b := make([]byte, 16)
	rand.Read(b)
	w.csrfMu.Lock()
	w.csrfToken = hex.EncodeToString(b)
	w.csrfMu.Unlock()
}

func (w *webServer) csrf() string {
	w.csrfMu.Lock()
	defer w.csrfMu.Unlock()
	return w.csrfToken
}

// applyDynamic reloads the live config from the DB. The new snapshot is only
// swapped in on success, so a DB error keeps the previous config serving.
func (w *webServer) applyDynamic() error {
	return w.app.rt.reload(w.app.store)
}

func (w *webServer) Serve() {
	if err := w.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("web server: %v", err)
	}
}

// ---------------- auth ----------------

type failState struct {
	count int
	since time.Time
}

// authLimiter throttles failed Basic-auth attempts per source IP.
type authLimiter struct {
	mu    sync.Mutex
	fails map[string]*failState
}

func (l *authLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	fs, ok := l.fails[ip]
	if !ok {
		return true
	}
	if time.Since(fs.since) > 10*time.Second {
		delete(l.fails, ip)
		return true
	}
	return fs.count < 5
}

func (l *authLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fs, ok := l.fails[ip]
	if !ok || time.Since(fs.since) > 10*time.Second {
		l.fails[ip] = &failState{count: 1, since: time.Now()}
		return
	}
	fs.count++
}

func (l *authLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// authOK compares credentials via fixed-length hashes so constant-time compare
// doesn't leak the password length.
func authOK(got, want string) bool {
	gh := sha256.Sum256([]byte(got))
	wh := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gh[:], wh[:]) == 1
}

func (w *webServer) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !w.limiter.allow(ip) {
			time.Sleep(time.Duration(400+200*w.limiterFailCount(ip)) * time.Millisecond)
			rw.Header().Set("WWW-Authenticate", `Basic realm="Artemis"`)
			http.Error(rw, "too many attempts", http.StatusTooManyRequests)
			return
		}
		u, p, ok := r.BasicAuth()
		userOK := authOK(u, w.app.cfg.WebUI.Username)
		passOK := authOK(p, w.app.cfg.WebUI.Password)
		if !ok || !userOK || !passOK {
			w.limiter.fail(ip)
			rw.Header().Set("WWW-Authenticate", `Basic realm="Artemis"`)
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.limiter.success(ip)
		next.ServeHTTP(rw, r)
	})
}

func (w *webServer) limiterFailCount(ip string) int {
	w.limiter.mu.Lock()
	defer w.limiter.mu.Unlock()
	if fs, ok := w.limiter.fails[ip]; ok {
		if fs.count > 5 {
			return 5
		}
		return fs.count
	}
	return 0
}

// ---------------- routing / rendering ----------------

func (w *webServer) route(rw http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/dashboard":
		w.pageDashboard(rw, r)
	case "/upstreams":
		w.handleUpstreams(rw, r)
	case "/special":
		w.handleSpecial(rw, r)
	case "/redirects":
		w.handleRedirects(rw, r)
	case "/domains":
		w.handleDomains(rw, r)
	case "/auto":
		w.handleAuto(rw, r)
	case "/restart":
		w.handleRestart(rw, r)
	case "/changes":
		w.pageChanges(rw, r)
	default:
		http.NotFound(rw, r)
	}
}

func (w *webServer) render(rw http.ResponseWriter, r *http.Request, name string, data any) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "+
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
			"font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; frame-ancestors 'none'")
	tmplData := map[string]any{
		"Data":   data,
		"Active": name,
		"CSRF":   w.csrf(),
		"User":   w.app.cfg.WebUI.Username,
		"Err":    r.URL.Query().Get("err"),
	}
	if err := w.tmpl.ExecuteTemplate(rw, name+".html", tmplData); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// consumeCSRF validates the posted token and rotates it on success so a
// captured token can't be replayed.
func (w *webServer) consumeCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		log.Printf("consumeCSRF: parse form: %v", err)
	}
	got := r.FormValue("csrf")
	want := w.csrf()
	ok := subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
	if ok {
		w.refreshCSRF()
	}
	return ok
}

// redirectErr redirects back, appending an error message when present.
func (w *webServer) redirectErr(rw http.ResponseWriter, r *http.Request, path string, err error) {
	if err == nil {
		http.Redirect(rw, r, path, http.StatusFound)
		return
	}
	http.Redirect(rw, r, path+"?err="+url.QueryEscape(err.Error()), http.StatusFound)
}

// ---------------- dashboard ----------------

func (w *webServer) pageDashboard(rw http.ResponseWriter, r *http.Request) {
	cfg := map[string]int{
		"Upstreams": len(w.app.rt.Upstreams()),
		"Redirects": len(w.app.rt.Redirects()),
		"Domains":   len(w.app.rt.Domains()),
		"AutoSites": len(w.app.rt.AutoSites()),
	}
	changes := w.app.store.recentChanges(8)

	var cacheHits, cacheMisses, cacheEvicts, cacheSize uint64
	if w.app.handler.cache != nil {
		cacheHits, cacheMisses, cacheEvicts, cacheSize = w.app.handler.cache.stats()
	}
	w.render(rw, r, "dashboard", map[string]any{
		"Cfg":        cfg,
		"Changes":    changes,
		"DNS":        w.app.cfg.Server.Listen,
		"DoH":        w.app.cfg.DoH.Listen,
		"HTTP":       w.app.cfg.HTTP.Listen,
		"WebUI":      w.app.cfg.WebUI.Listen,
		"CacheHits":  cacheHits,
		"CacheMiss":  cacheMisses,
		"CacheEvict": cacheEvicts,
		"CacheSize":  cacheSize,
		"CacheTTL":   w.app.cfg.Server.DNSCacheTTL.Std().Seconds(),
	})
}

// ---------------- upstreams ----------------

func (w *webServer) handleUpstreams(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !w.consumeCSRF(r) {
			http.Error(rw, "bad csrf", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		server := strings.TrimSpace(r.FormValue("server"))
		user := w.app.cfg.WebUI.Username
		var err error
		switch {
		case action == "add" && server != "":
			if !validUpstream(server) {
				err = fmt.Errorf("invalid upstream %q: expected host:port with a numeric port", server)
			} else {
				err = w.app.store.AddUpstream(user, server)
			}
		case action == "remove" && server != "":
			err = w.app.store.RemoveUpstream(user, server)
		}
		if err == nil {
			err = w.applyDynamic()
		}
		w.redirectErr(rw, r, "/upstreams", err)
		return
	}
	upstreams, err := w.app.store.listUpstreams()
	if err != nil {
		upstreams = w.app.rt.Upstreams()
	}
	w.render(rw, r, "upstreams", map[string]any{"Upstreams": upstreams})
}

func validUpstream(s string) bool {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

// ---------------- special ----------------

func (w *webServer) handleSpecial(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !w.consumeCSRF(r) {
			http.Error(rw, "bad csrf", http.StatusBadRequest)
			return
		}
		user := w.app.cfg.WebUI.Username
		var err error
		if err = w.app.store.SetSetting(user, "special.enabled", strconv.FormatBool(r.FormValue("phone_enabled") == "on")); err == nil {
			err = w.app.store.SetSetting(user, "short.enabled", strconv.FormatBool(r.FormValue("short_enabled") == "on"))
		}
		if err == nil {
			err = w.applyDynamic()
		}
		w.redirectErr(rw, r, "/special", err)
		return
	}
	w.render(rw, r, "special", map[string]any{
		"PhoneEnabled": w.app.rt.SpecialEnabled(),
		"ShortEnabled": w.app.rt.ShortEnabled(),
		"ShortTLD":     w.app.cfg.HTTP.ShortTLD,
	})
}

// ---------------- redirects ----------------

func (w *webServer) handleRedirects(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !w.consumeCSRF(r) {
			http.Error(rw, "bad csrf", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		if action == "import-sitemap" {
			w.handleSitemapImport(rw, r)
			return
		}
		oldDomain := tidyDomain(r.FormValue("old_domain"))
		rc := parseRedirectForm(r)
		user := w.app.cfg.WebUI.Username

		var err error
		switch action {
		case "add":
			err = requireRedirect(rc)
			if err == nil {
				err = w.app.store.AddRedirect(user, rc)
			}
		case "update":
			err = requireRedirect(rc)
			if err == nil && oldDomain == "" {
				err = fmt.Errorf("missing original domain")
			}
			if err == nil {
				err = w.app.store.UpdateRedirect(user, oldDomain, rc)
			}
		case "delete":
			if oldDomain == "" {
				err = fmt.Errorf("missing domain")
			} else {
				err = w.app.store.DeleteRedirect(user, oldDomain)
			}
		}
		if err == nil {
			err = w.applyDynamic()
		}
		w.redirectErr(rw, r, "/redirects", err)
		return
	}
	redirects := w.app.rt.Redirects()
	var imported, manual []RedirectConfig
	for _, rc := range redirects {
		if rc.QueryParam == "" {
			imported = append(imported, rc)
		} else {
			manual = append(manual, rc)
		}
	}
	w.render(rw, r, "redirects", map[string]any{
		"Imported": imported,
		"Manual":   manual,
		"Listen":   w.app.cfg.HTTP.Listen,
		"AnswerIP": w.app.cfg.HTTP.AnswerIP,
		"ShortTLD": w.app.cfg.HTTP.ShortTLD,
	})
}

// handleSitemapImport fetches a sitemap XML for a base URL and upserts one
// redirect per <loc>, mapping each URL to a short <label>.<tld> domain via
// path segments (deepest segment = leftmost label, e.g. /tools/ai -> ai.tools).
func (w *webServer) handleSitemapImport(rw http.ResponseWriter, r *http.Request) {
	base := strings.TrimSpace(r.FormValue("sitemap_url"))
	tld := strings.TrimSpace(r.FormValue("sitemap_tld"))
	if base == "" || tld == "" {
		w.redirectErr(rw, r, "/redirects", fmt.Errorf("sitemap URL and TLD are required"))
		return
	}
	sitemapURL := strings.TrimRight(base, "/") + "/sitemap.xml"
	resp, err := http.Get(sitemapURL)
	if err != nil {
		w.redirectErr(rw, r, "/redirects", fmt.Errorf("fetch sitemap: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.redirectErr(rw, r, "/redirects", fmt.Errorf("fetch sitemap: HTTP %d", resp.StatusCode))
		return
	}
	var ss struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&ss); err != nil {
		w.redirectErr(rw, r, "/redirects", fmt.Errorf("parse sitemap: %v", err))
		return
	}

	inserted := 0
	user := w.app.cfg.WebUI.Username
	for _, u := range ss.URLs {
		loc := strings.TrimSpace(u.Loc)
		if loc == "" {
			continue
		}
		if err := validateRedirectURL(loc); err != nil {
			continue
		}
		p, err := url.Parse(loc)
		if err != nil || p.Path == "" {
			continue
		}
		label := deriveLabel(p.Path)
		if label == "" {
			continue
		}
		domain := label + "." + tld
		rc := RedirectConfig{Domain: domain, Target: loc, QueryParam: ""}
		if err := w.app.store.UpsertRedirect(user, rc); err == nil {
			inserted++
		}
	}
	if err := w.applyDynamic(); err != nil {
		log.Printf("sitemap import applied-dynamic warning: %v", err)
	}
	w.redirectErr(rw, r, "/redirects", fmt.Errorf("%d redirects imported for .%s", inserted, tld))
}

// deriveLabel turns a URL path into a short subdomain, reversing the path
// segments so the deepest segment becomes the leftmost label.
// e.g. /tools/ai-checker -> "ai-checker.tools"
func deriveLabel(path string) string {
	segs := strings.FieldsFunc(strings.Trim(path, "/"), func(r rune) bool { return r == '/' })
	for i, j := 0, len(segs)-1; i < j; i, j = i+1, j-1 {
		segs[i], segs[j] = segs[j], segs[i]
	}
	cleaned := make([]string, 0, len(segs))
	for _, s := range segs {
		s = strings.ToLower(s)
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				b.WriteRune(r)
			}
		}
		term := b.String()
		if term == "" || term == "-" || len(term) > 63 {
			continue
		}
		cleaned = append(cleaned, term)
	}
	if len(cleaned) == 0 {
		return ""
	}
	return strings.Join(cleaned, ".")
}

// requireRedirect validates the fields a redirect needs before persisting.
func requireRedirect(rc RedirectConfig) error {
	if rc.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if rc.Target == "" {
		return fmt.Errorf("target is required")
	}
	if err := validateRedirectURL(rc.Target); err != nil {
		return fmt.Errorf("invalid target: %v", err)
	}
	return nil
}

func parseRedirectForm(r *http.Request) RedirectConfig {
	return RedirectConfig{
		Domain:     tidyDomain(r.FormValue("domain")),
		Target:     strings.TrimSpace(r.FormValue("target")),
		QueryParam: strings.TrimSpace(r.FormValue("query_param")),
	}
}

// ---------------- custom domains ----------------

func (w *webServer) handleDomains(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !w.consumeCSRF(r) {
			http.Error(rw, "bad csrf", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		oldDomain := tidyDomain(r.FormValue("old_domain"))
		d := DomainConfig{
			Domain: tidyDomain(r.FormValue("domain")),
			IP:     strings.TrimSpace(r.FormValue("ip")),
		}
		user := w.app.cfg.WebUI.Username

		var err error
		switch action {
		case "add":
			err = requireDomain(d)
			if err == nil {
				err = w.app.store.AddDomain(user, d)
			}
		case "update":
			err = requireDomain(d)
			if err == nil && oldDomain == "" {
				err = fmt.Errorf("missing original domain")
			}
			if err == nil {
				err = w.app.store.UpdateDomain(user, oldDomain, d)
			}
		case "delete":
			if oldDomain == "" {
				err = fmt.Errorf("missing domain")
			} else {
				err = w.app.store.DeleteDomain(user, oldDomain)
			}
		}
		if err == nil {
			err = w.applyDynamic()
		}
		w.redirectErr(rw, r, "/domains", err)
		return
	}
	domains := w.app.rt.Domains()
	w.render(rw, r, "domains", map[string]any{"Domains": domains})
}

func requireDomain(d DomainConfig) error {
	if d.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if net.ParseIP(d.IP) == nil {
		return fmt.Errorf("invalid IP %q", d.IP)
	}
	return nil
}

// ---------------- auto sites ----------------

func (w *webServer) handleAuto(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !w.consumeCSRF(r) {
			http.Error(rw, "bad csrf", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		name := strings.TrimSpace(r.FormValue("name"))
		site := strings.TrimSpace(r.FormValue("site"))
		user := w.app.cfg.WebUI.Username

		var err error
		switch action {
		case "add":
			if name == "" {
				err = fmt.Errorf("name is required")
			} else if err = validateRedirectURL(site); err != nil {
				err = fmt.Errorf("invalid mirror: %v", err)
			} else {
				err = w.app.store.AddAutoSite(user, AutoSiteConfig{Name: tidyDomain(name), Sites: []string{site}, Enabled: true})
			}
		case "delete":
			if name == "" {
				err = fmt.Errorf("name is required")
			} else {
				err = w.app.store.DeleteAutoSite(user, tidyDomain(name))
			}
		case "add-mirror":
			if name == "" || site == "" {
				err = fmt.Errorf("name and site are required")
			} else if err = validateRedirectURL(site); err != nil {
				err = fmt.Errorf("invalid mirror: %v", err)
			} else {
				err = w.app.store.AddAutoMirror(user, tidyDomain(name), site)
			}
		case "remove-mirror":
			if name == "" || site == "" {
				err = fmt.Errorf("name and site are required")
			} else {
				err = w.app.store.RemoveAutoMirror(user, tidyDomain(name), site)
			}
		}
		if err == sql.ErrNoRows {
			err = fmt.Errorf("group not found")
		}
		if err == nil {
			err = w.applyDynamic()
		}
		w.redirectErr(rw, r, "/auto", err)
		return
	}
	autoSites := w.app.rt.AutoSites()
	w.render(rw, r, "auto", map[string]any{"AutoSites": autoSites})
}

// ---------------- restart ----------------

func (w *webServer) handleRestart(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(rw, r, "/", http.StatusFound)
		return
	}
	if !w.consumeCSRF(r) {
		http.Error(rw, "bad csrf", http.StatusBadRequest)
		return
	}
	if err := w.app.restart(); err != nil {
		log.Printf("webui restart failed: %v", err)
		http.Error(rw, "restart failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, r, "/", http.StatusFound)
}

// ---------------- audit trail ----------------

func (w *webServer) pageChanges(rw http.ResponseWriter, r *http.Request) {
	changes := w.app.store.recentChanges(200)
	w.render(rw, r, "changes", map[string]any{"Changes": changes})
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
