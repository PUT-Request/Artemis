package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

// dohServer serves DNS-over-HTTPS (RFC 8484) over plain HTTP — no TLS — for
// local/LAN use. Supports GET /dns-query?dns=<base64url> and POST with a raw
// DNS message body. Resolves through the shared handler.
type dohServer struct {
	app  *app
	path string
}

func (d *dohServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != d.path {
		http.NotFound(w, r)
		return
	}

	clientIP := hostOfRemote(r.RemoteAddr)
	if !d.app.handler.allowed(clientIP) {
		http.Error(w, "refused", http.StatusForbidden)
		return
	}

	var query []byte
	switch r.Method {
	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" || len(b64) > 64<<10 {
			http.Error(w, "missing or oversized dns parameter", http.StatusBadRequest)
			return
		}
		q, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "bad dns encoding", http.StatusBadRequest)
			return
		}
		query = q
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		query = body
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(query) == 0 || len(query) > 65535 {
		http.Error(w, "bad dns message size", http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}

	resp := d.app.handler.resolveMsg(req, clientIP)

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(packed)
}

func hostOfRemote(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
