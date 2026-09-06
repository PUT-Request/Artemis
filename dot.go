package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// dotServer serves DNS-over-TLS (RFC 7858) — encrypted DNS on port 853.
// It wraps the shared handler and reuses the same ACL/rate-limit logic.
type dotServer struct {
	app    *app
	server *dns.Server
}

// startDOT creates and starts a DNS-over-TLS listener.
// The server reuses the shared handler for all DNS resolution.
func (a *app) startDOT() (*dns.Server, error) {
	if a.cfg.DoT.CertFile == "" || a.cfg.DoT.KeyFile == "" {
		return nil, fmt.Errorf("dot: cert_file and key_file are required")
	}

	cert, err := tls.LoadX509KeyPair(a.cfg.DoT.CertFile, a.cfg.DoT.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("dot: load TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	ln, err := tls.Listen("tcp", a.cfg.DoT.Listen, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dot: listen %s: %w", a.cfg.DoT.Listen, err)
	}

	s := &dns.Server{
		Listener: ln,
		Handler:  a.handler,
	}

	go func() {
		log.Printf("DoT listening on %s (TLS)", a.cfg.DoT.Listen)
		if err := s.ActivateAndServe(); err != nil {
			log.Printf("dot server: %v", err)
			select {
			case a.errCh <- fmt.Errorf("dot %s: %w", a.cfg.DoT.Listen, err):
			default:
			}
		}
	}()

	return s, nil
}

// stopDOT gracefully shuts down the DoT server.
func (a *app) stopDOT(s *dns.Server) {
	if s != nil {
		s.Shutdown()
	}
}
