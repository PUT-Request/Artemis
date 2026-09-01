package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateRedirectURL rejects redirect targets and auto-mirror URLs that could
// cause header injection (control characters / CRLF) or SSRF to cloud-metadata
// style link-local addresses. Allows http/https, loopback and private LAN IPs
// (mirrors on the local network are a supported use case).
func validateRedirectURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is empty")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("url contains control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("url has no host")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && blockedIP(ip) {
		return fmt.Errorf("host %q is not allowed", host)
	}
	return nil
}

// blockedIP reports whether an IP literal host is off-limits for health checks:
// link-local (incl. cloud metadata 169.254.169.254), unspecified, multicast,
// reserved. Loopback and RFC1918 private ranges are allowed for LAN mirrors.
func blockedIP(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 240.0.0.0/4 reserved
		if ip4[0] >= 240 {
			return true
		}
		// 169.254.0.0/16 is already covered by IsLinkLocalUnicast
	}
	return false
}

// normalizePortHost extracts a validateable host from "host:port" strings.
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}
