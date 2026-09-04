package main

import (
	"context"
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// base32DecodeNoPad decodes an unpadded, case-insensitive base32 string (the
// form that survives browser hostname lowercasing).
func base32DecodeNoPad(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
}

// httpFront is the single HTTP server that serves both URL redirect domains
// (Host matches a configured redirect -> 302) and the ".auto" TLD (Host under
// .auto -> 302 to a working mirror). Everything dispatches on the Host header,
// so it slots behind a reverse proxy (nginx/caddy) unchanged.
type httpFront struct {
	handler *handler
	auto    *autoServer
}

func (f *httpFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	ip := httpClientIP(r)
	log.Printf("http front: %s %s host=%s remote=%s", r.Method, r.URL.Path, host, ip)

	// Per-IP rate limit + ACL (shared with the DNS side). The front is now an
	// open redirector for .ba short codes, so it needs a throttle.
	if !f.handler.allowed(ip) {
		log.Printf("http front: rate limited %s", ip)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Redirect domains take priority: check before short-TLD so that
	// e.g. novel.fy hits a redirect (not found → 404) rather than being
	// fed to the base32 short-code decoder which would decode it as garbage.
	if rc := f.handler.rt.redirectFor(host); rc != nil {
		label := redirectLabel(host, rc.Domain)
		location := redirectTarget(rc, label)
		if f.handler.store != nil {
			f.handler.store.LogIP(ip)
		}
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	tld := f.handler.cfg.HTTP.ShortTLD
	if tld != "" && f.handler.rt.ShortEnabled() && isShortName(host, tld) && !f.handler.rt.isRedirectTLD(host) {
		if target, err := shortDecode(host, tld); err == nil {
			if f.handler.store != nil {
				f.handler.store.LogIP(ip)
			}
			http.Redirect(w, r, target, http.StatusFound)
		} else {
			http.NotFound(w, r)
		}
		return
	}

	if autoGroupName(host) != "" {
		f.auto.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

// httpClientIP returns the real client IP, trusting X-Forwarded-For only when
// the direct peer is loopback (e.g. a local reverse proxy).
func httpClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	return host
}

// shortDecode turns "<base32-of-url>.32" into the decoded URL: it joins every
// label before the short TLD, base32-decodes (case-insensitive, no padding),
// prepends https:// when the result has no scheme, and validates it.
func shortDecode(host, tld string) (string, error) {
	norm := normalizeHost(host)
	prefix := strings.TrimSuffix(norm, "."+tld)
	if prefix == norm || prefix == "" {
		return "", fmt.Errorf("not a short-code name")
	}
	joined := strings.ReplaceAll(prefix, ".", "")
	raw, err := base32DecodeNoPad(joined)
	if err != nil {
		return "", fmt.Errorf("base32 decode: %w", err)
	}
	target := string(raw)
	// Reject decoded content with non-printable/non-ASCII characters (garbage
	// from base32-decoding ordinary words like "novel").
	for _, r := range target {
		if r < 0x20 || r > 0x7E {
			return "", fmt.Errorf("decoded content contains non-printable character")
		}
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	if err := validateRedirectURL(target); err != nil {
		return "", err
	}
	return target, nil
}

// normalizeHost lowercases a Host header, drops any port and trailing dot.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

// startHTTPFront binds the single redirect + .auto HTTP listener.
func (a *app) startHTTPFront() (*http.Server, error) {
	mux := http.NewServeMux()
	front := &httpFront{handler: a.handler, auto: newAutoServer(a)}
	mux.Handle("/", front)

	ln, err := net.Listen("tcp", a.cfg.HTTP.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen http %s: %w", a.cfg.HTTP.Listen, err)
	}
	srv := newHTTPServer(mux)
	go func() {
		log.Printf("HTTP front listening on %s (redirects + .auto)", a.cfg.HTTP.Listen)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("http front: %v", err)
		}
	}()
	return srv, nil
}

// stopHTTPServers gracefully drains in-flight requests (2s budget each).
func stopHTTPServers(servers []*http.Server) {
	for _, s := range servers {
		if s == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.Shutdown(ctx)
		cancel()
	}
}
