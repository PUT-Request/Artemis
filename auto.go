package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// autoServer handles the ".auto" TLD on its HTTP listener. For Host
// "<name>.auto" it picks the first working mirror for the registered group
// <name> and replies with a 302. Health results are cached per group and
// refreshed in the background (stale-while-revalidate), so one slow mirror
// group never stalls the whole endpoint.
type autoServer struct {
	app   *app
	check func(url string) bool
	mu    sync.Mutex // guards cache + locks
	cache map[string]autoCacheEntry
	locks map[string]*sync.Mutex
}

type autoCacheEntry struct {
	url       string
	checkedAt time.Time
}

func newAutoServer(a *app) *autoServer {
	cfg := a.cfg.HTTP
	return &autoServer{
		app:   a,
		check: func(url string) bool { return mirrorUp(url, cfg.CheckTimeout.Std()) },
		cache: map[string]autoCacheEntry{},
		locks: map[string]*sync.Mutex{},
	}
}

func (a *autoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := autoGroupName(r.Host)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	group := a.app.rt.autoSite(name)
	if group == nil || !group.Enabled || len(group.Sites) == 0 {
		http.NotFound(w, r)
		return
	}

	location := a.pick(group)
	if a.app.store != nil {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		a.app.store.LogIP(clientIP)
	}
	http.Redirect(w, r, location, http.StatusFound)
}

// pick returns the mirror to redirect to, revalidating in the background once
// the cache TTL expires so requests never wait on network health checks.
func (a *autoServer) pick(group *AutoSiteConfig) string {
	ttl := a.app.cfg.HTTP.CacheTTL.Std()

	a.mu.Lock()
	e, ok := a.cache[group.Name]
	a.mu.Unlock()

	if ok && time.Since(e.checkedAt) < ttl {
		return e.url
	}
	if ok {
		// stale but usable: serve it now, refresh in the background
		go a.refresh(group)
		return e.url
	}
	return a.refresh(group)
}

// refresh runs the health checks for a group under a per-group lock so
// concurrent requests to the same group don't stampede, while requests to
// other groups proceed independently.
func (a *autoServer) refresh(group *AutoSiteConfig) string {
	lock := a.groupLock(group.Name)
	lock.Lock()
	defer lock.Unlock()

	// Another goroutine may have refreshed while we waited.
	a.mu.Lock()
	e, ok := a.cache[group.Name]
	a.mu.Unlock()
	if ok && time.Since(e.checkedAt) < a.app.cfg.HTTP.CacheTTL.Std() {
		return e.url
	}

	picked := ""
	for _, site := range group.Sites {
		if a.check(strings.TrimRight(site, "/")) {
			picked = site
			break
		}
	}
	if picked == "" {
		// none reachable: best-effort fall back to the first mirror
		picked = group.Sites[0]
	}

	a.mu.Lock()
	a.cache[group.Name] = autoCacheEntry{url: picked, checkedAt: time.Now()}
	a.mu.Unlock()
	return picked
}

func (a *autoServer) groupLock(name string) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.locks[name]; ok {
		return l
	}
	l := &sync.Mutex{}
	a.locks[name] = l
	return l
}

// autoGroupName extracts the ".auto" label from a Host header, e.g.
// "annas-archive.auto:80" -> "annas-archive". Returns "" if not a .auto host.
func autoGroupName(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if host == "auto" {
		return ""
	}
	if strings.HasSuffix(host, ".auto") {
		return strings.TrimSuffix(host, ".auto")
	}
	return ""
}

// mirrorUp reports whether url responds to a HEAD (fallback GET) with a
// 2xx/3xx status within timeout.
func mirrorUp(url string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	// HEAD unsupported / blocked: try GET, but never follow redirects for the check
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	greq, gerr := http.NewRequest(http.MethodGet, url, nil)
	if gerr != nil {
		return false
	}
	gresp, gerr := client.Do(greq)
	if gerr != nil {
		return false
	}
	gresp.Body.Close()
	return gresp.StatusCode >= 200 && gresp.StatusCode < 400
}
