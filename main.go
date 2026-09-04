package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type app struct {
	cfg          *Config
	cfgPath      string
	store        *Store
	rt           *runtime
	handler      *handler
	webUI        *webServer
	mu           sync.Mutex
	dnsServers   []*dns.Server
	httpServers  []*http.Server
	shuttingDown atomic.Bool
	errCh        chan error
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	store, err := openStore(cfg.Database.Path)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()

	if cfg.Database.RetentionDays > 0 {
		go func() {
			for range time.Tick(24 * time.Hour) {
				store.Prune(cfg.Database.RetentionDays)
			}
		}()
	}

	a := &app{cfg: cfg, cfgPath: *cfgPath, store: store, errCh: make(chan error, 4)}
	if lc, err := store.loadLive(); err != nil {
		log.Fatalf("load live config: %v", err)
	} else {
		a.rt = &runtime{live: lc}
	}
	a.handler = newHandler(cfg, a.rt, store)

	if cfg.WebUI.Enabled {
		a.webUI = newWebServer(a)
	}

	if err := a.start(); err != nil {
		log.Fatalf("start: %v", err)
	}

	log.Printf("Artemis DNS listening on %s (udp+tcp)", cfg.Server.Listen)
	if cfg.WebUI.Enabled {
		go a.webUI.Serve()
		log.Printf("Web UI listening on %s", cfg.WebUI.Listen)
	}
	// Surface fatal server errors (e.g. listener died).
	go func() {
		for err := range a.errCh {
			log.Fatalf("listener error: %v", err)
		}
	}()
	if isNonLoopback(cfg.Server.Listen) {
		log.Printf("WARNING: DNS bound to a non-loopback address — an open resolver unless server.acl is set")
	}
	if cfg.WebUI.Enabled && isNonLoopback(cfg.WebUI.Listen) {
		log.Printf("WARNING: Web UI bound to a non-loopback address over plaintext HTTP — credentials are sent unencrypted")
	}

	// In-process restart via SIGHUP (same as the Web UI Restart button).
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		for range ch {
			if a.shuttingDown.Load() {
				return
			}
			log.Printf("SIGHUP received, restarting listeners")
			if err := a.restart(); err != nil {
				log.Printf("restart failed: %v", err)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		a.shuttingDown.Store(true)
		log.Printf("received %v, shutting down", s)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		a.stop(ctx)
	}
}

func (a *app) start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	dnsS, httpS, err := a.bindAll()
	if err != nil {
		return err
	}
	a.dnsServers, a.httpServers = dnsS, httpS
	return nil
}

// bindAll synchronously binds every listener into fresh slices. On error it
// closes whatever it already bound and returns the error, leaving the caller's
// existing slices untouched.
func (a *app) bindAll() ([]*dns.Server, []*http.Server, error) {
	var dnsS []*dns.Server
	var httpS []*http.Server
	cleanup := func() {
		for _, s := range dnsS {
			s.Shutdown()
		}
		stopHTTPServers(httpS)
	}

	udp, err := a.bindUDP(a.cfg.Server.Listen, a.handler)
	if err != nil {
		return nil, nil, err
	}
	dnsS = append(dnsS, udp)

	tcp, err := a.bindTCP(a.cfg.Server.Listen, a.handler)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	dnsS = append(dnsS, tcp)

	if a.cfg.HTTP.Enabled {
		front, err := a.startHTTPFront()
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		httpS = append(httpS, front)
	}

	if a.cfg.DoH.Enabled {
		doh, err := a.startDOH()
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		httpS = append(httpS, doh)
	}
	return dnsS, httpS, nil
}

// bindUDP binds a UDP DNS listener synchronously so bind errors surface
// immediately instead of being masked by a timer.
func (a *app) bindUDP(addr string, h dns.Handler) (*dns.Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind udp %s: %w", addr, err)
	}
	s := &dns.Server{PacketConn: pc, Handler: h}
	go func() {
		if err := s.ActivateAndServe(); err != nil {
			log.Printf("dns udp %s: %v", addr, err)
			select {
			case a.errCh <- fmt.Errorf("dns udp %s: %w", addr, err):
			default:
			}
		}
	}()
	return s, nil
}

// bindTCP binds a TCP DNS listener synchronously.
func (a *app) bindTCP(addr string, h dns.Handler) (*dns.Server, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind tcp %s: %w", addr, err)
	}
	s := &dns.Server{Listener: l, Handler: h}
	go func() {
		if err := s.ActivateAndServe(); err != nil {
			log.Printf("dns tcp %s: %v", addr, err)
			select {
			case a.errCh <- fmt.Errorf("dns tcp %s: %w", addr, err):
			default:
			}
		}
	}()
	return s, nil
}

func (a *app) startDOH() (*http.Server, error) {
	mux := http.NewServeMux()
	doh := &dohServer{app: a, path: a.cfg.DoH.Path}
	mux.Handle(a.cfg.DoH.Path, doh)

	ln, err := net.Listen("tcp", a.cfg.DoH.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen doh %s: %w", a.cfg.DoH.Listen, err)
	}
	srv := newHTTPServer(mux)
	go func() {
		log.Printf("DoH listening on %s (%s)", a.cfg.DoH.Listen, a.cfg.DoH.Path)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("doh server: %v", err)
		}
	}()
	return srv, nil
}

// newHTTPServer applies sane timeouts so slowloris / slow-body clients can't
// hold connections forever.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func isNonLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && !ip.IsLoopback()
}

// restart stops the old listeners, reloads config.yaml + the live DB config,
// and rebinds. If a bind fails, the already-bound listeners are torn down and
// the error is returned — nothing is leaked, so a later restart can recover.
func (a *app) restart() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if cfg, err := loadConfig(a.cfgPath); err != nil {
		log.Printf("reload config.yaml failed (keeping old): %v", err)
	} else {
		a.cfg = cfg
	}
	if err := a.rt.reload(a.store); err != nil {
		log.Printf("reload live config failed (keeping old): %v", err)
	}

	// Tear down old listeners.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range a.dnsServers {
		s.ShutdownContext(ctx)
	}
	a.dnsServers = nil
	stopHTTPServers(a.httpServers)
	a.httpServers = nil
	if a.webUI != nil {
		a.webUI.server.Shutdown(ctx)
		a.webUI = nil
	}

	dnsS, httpS, err := a.bindAll()
	if err != nil {
		return err
	}
	a.dnsServers, a.httpServers = dnsS, httpS

	if a.cfg.WebUI.Enabled {
		a.webUI = newWebServer(a)
		go a.webUI.Serve()
		log.Printf("Web UI listening on %s", a.cfg.WebUI.Listen)
	}

	a.store.RecordChange("system", "restart", "")
	log.Printf("restart complete")
	return nil
}

func (a *app) stop(ctx context.Context) {
	// Snapshot the servers, then release the lock before graceful shutdown so
	// an in-flight WebUI restart request can complete instead of deadlocking.
	a.mu.Lock()
	dnsS := a.dnsServers
	httpS := a.httpServers
	a.dnsServers = nil
	a.httpServers = nil
	webUI := a.webUI
	a.mu.Unlock()

	for _, s := range dnsS {
		s.ShutdownContext(ctx)
	}
	stopHTTPServers(httpS)
	if webUI != nil {
		webUI.server.Shutdown(ctx)
	}
}
