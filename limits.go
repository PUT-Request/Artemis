package main

import (
	"net"
	"sync"
	"time"
)

// rateLimiter is a simple per-second, per-IP token counter used to blunt
// spoofed-source DNS floods and open-resolver abuse.
type rateLimiter struct {
	limit     int
	mu        sync.Mutex
	counts    map[string]*ipCount
	lastClean time.Time
}

type ipCount struct {
	start time.Time
	count int
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{limit: limit, counts: map[string]*ipCount{}, lastClean: time.Now()}
}

func (l *rateLimiter) allow(ip string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Periodic cleanup bounds the map even under spoofed-source floods.
	if now.Sub(l.lastClean) > time.Minute {
		for k, v := range l.counts {
			if now.Sub(v.start) > time.Minute {
				delete(l.counts, k)
			}
		}
		l.lastClean = now
	}

	c, ok := l.counts[ip]
	if !ok || now.Sub(c.start) >= time.Second {
		if len(l.counts) > 100_000 {
			// Aggressively clean up expired entries before rejecting.
			for k, v := range l.counts {
				if now.Sub(v.start) > 2*time.Minute {
					delete(l.counts, k)
				}
			}
			// If still over cap after cleanup, reject (extreme flood scenario).
			if len(l.counts) > 100_000 {
				return false
			}
		}
		l.counts[ip] = &ipCount{start: now, count: 1}
		return true
	}
	c.count++
	return c.count <= l.limit
}

// allowed gates a query source by the optional ACL allow-list and the per-IP
// rate limit. Empty ACL means allow all.
func (h *handler) allowed(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if len(h.acl) > 0 {
		if ip == nil {
			return false
		}
		ok := false
		for _, n := range h.acl {
			if n.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return h.rl.allow(clientIP)
}
