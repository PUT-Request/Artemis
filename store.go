package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const requestLogMax = 100_000 // cap on distinct IP rows

// Store is the SQLite source of truth for both the dynamic config and the
// per-IP request counters. Single writer (SetMaxOpenConns(1)) keeps SQLite
// simple; log writes funnel through one goroutine so resolution never spawns
// unbounded DB goroutines.
type Store struct {
	db     *sql.DB
	logCh  chan string
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func openStore(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	schema := `
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_log (
    client_ip TEXT PRIMARY KEY,
    count     INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS upstreams (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    server   TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS redirects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    target      TEXT NOT NULL,
    query_param TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS domains (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL UNIQUE,
    ip           TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auto_sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    sites       TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config_changes (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL DEFAULT (datetime('now')),
    user   TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	// One-time migration: drop the legacy per-query logging table (kept the
	// qnames we no longer store). Guarded by schema_version so it never runs
	// again or destroys a fresh schema.
	var ver string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='schema_version'`).Scan(&ver); err != nil && err != sql.ErrNoRows {
		db.Close()
		return nil, err
	}
	if ver == "" {
		if _, err := db.Exec(`DROP TABLE IF EXISTS queries;`); err != nil {
			db.Close()
			return nil, err
		}
		if _, err := db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('schema_version','2')`); err != nil {
			db.Close()
			return nil, err
		}
	}

	// v3: redirect ports/IP moved to the global config.http block, so drop the
	// now-unused per-redirect columns (only if they exist).
	if ver == "" || ver == "2" {
		cols := map[string]bool{}
		if rows, err := db.Query(`PRAGMA table_info(redirects)`); err == nil {
			for rows.Next() {
				var cid, name, typ string
				var notnull, pk int
				var dflt sql.NullString
				rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk)
				cols[name] = true
			}
			rows.Close()
		}
		for _, col := range []string{"answer_ip", "http_port"} {
			if cols[col] {
				if _, err := db.Exec(`ALTER TABLE redirects DROP COLUMN ` + col); err != nil {
					log.Printf("drop redirects.%s: %v", col, err)
				}
			}
		}
		if _, err := db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('schema_version','3')`); err != nil {
			db.Close()
			return nil, err
		}
	}

	// The DB holds config and an audit trail — keep it private.
	if err := os.Chmod(path, 0o600); err != nil {
		log.Printf("chmod %s: %v", path, err)
	}

	s := &Store{db: db, logCh: make(chan string, 1024), stopCh: make(chan struct{})}
	if err := s.seedDefaults(); err != nil {
		db.Close()
		return nil, err
	}
	s.wg.Add(1)
	go s.logWriter()
	return s, nil
}

// seedDefaults populates first-run values once, tracked by a "seeded" marker
// so deleting all upstreams later does not resurrect the defaults on restart.
// Toggle defaults are ensured on every start (idempotent) so upgrades to newer
// builds pick up newly added settings on existing databases.
func (s *Store) seedDefaults() error {
	for _, kv := range [][2]string{
		{"special.enabled", "true"},
		{"short.enabled", "true"},
	} {
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, kv[0], kv[1]); err != nil {
			return err
		}
	}
	if v, _ := s.getSetting("seeded"); v == "1" {
		return nil
	}
	defaults := []string{"94.140.14.14:53", "1.1.1.1:53", "8.8.8.8:53"}
	for i, u := range defaults {
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO upstreams (server, position) VALUES (?, ?)`, u, i); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('seeded','1')`)
	return err
}

// ---------------- audit ---------------

func (s *Store) RecordChange(user, action, detail string) {
	if _, err := s.db.Exec(`INSERT INTO config_changes (user, action, detail) VALUES (?, ?, ?)`, user, action, detail); err != nil {
		log.Printf("record change: %v", err)
	}
}

// ---------------- per-IP request counter ----------------

// LogIP enqueues a request from clientIP. Never blocks: on a full buffer the
// event is dropped rather than stalling resolution.
func (s *Store) LogIP(clientIP string) {
	if s == nil || clientIP == "" {
		return
	}
	select {
	case s.logCh <- clientIP:
	default:
	}
}

// logWriter batches increments and flushes to SQLite periodically.
func (s *Store) logWriter() {
	defer s.wg.Done()
	counts := map[string]int{}
	flush := func() {
		for ip, n := range counts {
			if _, err := s.db.Exec(
				`INSERT INTO request_log (client_ip, count) VALUES (?, ?)
				 ON CONFLICT(client_ip) DO UPDATE SET count = count + ?, last_seen = datetime('now')`,
				ip, n, n,
			); err != nil {
				log.Printf("log write failed: %v", err)
			}
		}
		counts = map[string]int{}
		s.capRequestLog()
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case ip := <-s.logCh:
			counts[ip]++
		case <-ticker.C:
			flush()
		case <-s.stopCh:
			for {
				select {
				case ip := <-s.logCh:
					counts[ip]++
				default:
					flush()
					return
				}
			}
		}
	}
}

// capRequestLog bounds the table so spoofed UDP sources can't grow it forever.
func (s *Store) capRequestLog() {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM request_log`).Scan(&n); err != nil || n <= requestLogMax {
		return
	}
	excess := n - requestLogMax
	if _, err := s.db.Exec(
		`DELETE FROM request_log WHERE client_ip IN (
			SELECT client_ip FROM request_log ORDER BY count ASC, last_seen ASC LIMIT ?)`, excess,
	); err != nil {
		log.Printf("cap request log: %v", err)
	}
}

// Prune deletes request-log rows not seen in retentionDays (0 disables).
func (s *Store) Prune(retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UTC().Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec(`DELETE FROM request_log WHERE last_seen < ?`, cutoff); err != nil {
		log.Printf("prune failed: %v", err)
	}
}

func (s *Store) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return s.db.Close()
}

// ---------------- live config load ---------------

// loadLive rebuilds a LiveConfig from the DB. Any DB error aborts the load so
// callers keep serving the previous snapshot instead of an empty one.
func (s *Store) loadLive() (*LiveConfig, error) {
	ups, err := s.listUpstreams()
	if err != nil {
		return nil, err
	}
	special, err := s.getSetting("special.enabled")
	if err != nil {
		return nil, err
	}
	short, err := s.getSetting("short.enabled")
	if err != nil {
		return nil, err
	}
	reds, err := s.listRedirects()
	if err != nil {
		return nil, err
	}
	doms, err := s.listDomains()
	if err != nil {
		return nil, err
	}
	autos, err := s.listAutoSites()
	if err != nil {
		return nil, err
	}
	return &LiveConfig{
		Upstreams:      ups,
		SpecialEnabled: special == "true",
		ShortEnabled:   short == "true",
		Redirects:      reds,
		Domains:        doms,
		AutoSites:      autos,
	}, nil
}

// ---------------- upstreams ---------------

func (s *Store) listUpstreams() ([]string, error) {
	rows, err := s.db.Query(`SELECT server FROM upstreams ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) AddUpstream(user, server string) error {
	var max int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(position),-1) FROM upstreams`).Scan(&max); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO upstreams (server, position) VALUES (?, ?)`, server, max+1); err != nil {
		return err
	}
	s.RecordChange(user, "upstream-add", server)
	return nil
}

func (s *Store) RemoveUpstream(user, server string) error {
	res, err := s.db.Exec(`DELETE FROM upstreams WHERE server = ?`, server)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "upstream-remove", server)
	}
	return nil
}

// ---------------- settings ---------------

func (s *Store) getSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s *Store) SetSetting(user, key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err == nil {
		s.RecordChange(user, "setting-set", key+"="+value)
	}
	return err
}

// ---------------- redirects ---------------

func (s *Store) listRedirects() ([]RedirectConfig, error) {
	rows, err := s.db.Query(`SELECT domain, target, query_param FROM redirects`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RedirectConfig
	for rows.Next() {
		var rc RedirectConfig
		if err := rows.Scan(&rc.Domain, &rc.Target, &rc.QueryParam); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	// Most specific (longest) domains first so exact-match rows like
	// "ai.tools.fy" win over parent "tools.fy" or "fy" in redirectFor().
	sort.Slice(out, func(i, j int) bool {
		return len(out[i].Domain) > len(out[j].Domain)
	})
	return out, rows.Err()
}

func (s *Store) AddRedirect(user string, rc RedirectConfig) error {
	if _, err := s.db.Exec(
		`INSERT INTO redirects (domain, target, query_param) VALUES (?, ?, ?)`,
		rc.Domain, rc.Target, rc.QueryParam,
	); err != nil {
		return err
	}
	if b, jerr := json.Marshal(rc); jerr == nil {
		s.RecordChange(user, "redirect-add", string(b))
	}
	return nil
}

// UpsertRedirect inserts or replaces a redirect row by its unique domain.
func (s *Store) UpsertRedirect(user string, rc RedirectConfig) error {
	if _, err := s.db.Exec(
		`INSERT INTO redirects (domain, target, query_param, updated_at) VALUES (?, ?, ?, datetime('now'))
		 ON CONFLICT(domain) DO UPDATE SET target=excluded.target, query_param=excluded.query_param, updated_at=datetime('now')`,
		rc.Domain, rc.Target, rc.QueryParam,
	); err != nil {
		return err
	}
	if b, jerr := json.Marshal(rc); jerr == nil {
		s.RecordChange(user, "redirect-upsert", string(b))
	}
	return nil
}

func (s *Store) UpdateRedirect(user string, oldDomain string, rc RedirectConfig) error {
	res, err := s.db.Exec(
		`UPDATE redirects SET domain=?, target=?, query_param=?, updated_at=datetime('now')
		 WHERE domain=?`,
		rc.Domain, rc.Target, rc.QueryParam, oldDomain,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "redirect-update", oldDomain+" -> "+rc.Domain)
	}
	return nil
}

func (s *Store) DeleteRedirect(user, domain string) error {
	res, err := s.db.Exec(`DELETE FROM redirects WHERE domain = ?`, domain)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "redirect-delete", domain)
	}
	return nil
}

// ---------------- custom domains ---------------

func (s *Store) listDomains() ([]DomainConfig, error) {
	rows, err := s.db.Query(`SELECT domain, ip FROM domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainConfig
	for rows.Next() {
		var d DomainConfig
		if err := rows.Scan(&d.Domain, &d.IP); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) AddDomain(user string, d DomainConfig) error {
	if _, err := s.db.Exec(`INSERT INTO domains (domain, ip) VALUES (?, ?)`, d.Domain, d.IP); err != nil {
		return err
	}
	if b, jerr := json.Marshal(d); jerr == nil {
		s.RecordChange(user, "domain-add", string(b))
	}
	return nil
}

func (s *Store) UpdateDomain(user string, oldDomain string, d DomainConfig) error {
	res, err := s.db.Exec(
		`UPDATE domains SET domain=?, ip=?, updated_at=datetime('now') WHERE domain=?`,
		d.Domain, d.IP, oldDomain,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "domain-update", oldDomain+" -> "+d.Domain)
	}
	return nil
}

func (s *Store) DeleteDomain(user, domain string) error {
	res, err := s.db.Exec(`DELETE FROM domains WHERE domain = ?`, domain)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "domain-delete", domain)
	}
	return nil
}

// ---------------- auto sites ----------------

func (s *Store) listAutoSites() ([]AutoSiteConfig, error) {
	rows, err := s.db.Query(`SELECT name, sites, enabled FROM auto_sites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AutoSiteConfig
	for rows.Next() {
		var name, sitesJSON string
		var enabled int
		if err := rows.Scan(&name, &sitesJSON, &enabled); err != nil {
			return nil, err
		}
		var sites []string
		if err := json.Unmarshal([]byte(sitesJSON), &sites); err != nil {
			sites = nil
		}
		out = append(out, AutoSiteConfig{Name: name, Sites: sites, Enabled: enabled == 1})
	}
	return out, rows.Err()
}

func (s *Store) AddAutoSite(user string, a AutoSiteConfig) error {
	b, err := json.Marshal(a.Sites)
	if err != nil {
		return err
	}
	enabled := 0
	if a.Enabled {
		enabled = 1
	}
	if _, err := s.db.Exec(
		`INSERT INTO auto_sites (name, sites, enabled) VALUES (?, ?, ?)`,
		a.Name, string(b), enabled,
	); err != nil {
		return err
	}
	s.RecordChange(user, "auto-add", a.Name+" "+string(b))
	return nil
}

func (s *Store) DeleteAutoSite(user, name string) error {
	res, err := s.db.Exec(`DELETE FROM auto_sites WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "auto-delete", name)
	}
	return nil
}

// autoSiteSites returns the mirror list for a group name.
func (s *Store) autoSiteSites(name string) ([]string, error) {
	var raw string
	err := s.db.QueryRow(`SELECT sites FROM auto_sites WHERE name = ?`, name).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sites []string
	if err := json.Unmarshal([]byte(raw), &sites); err != nil {
		return nil, err
	}
	return sites, nil
}

func (s *Store) setAutoSiteSites(user, name string, sites []string) error {
	b, err := json.Marshal(sites)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE auto_sites SET sites = ?, updated_at = datetime('now') WHERE name = ?`,
		string(b), name,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.RecordChange(user, "auto-update", name+" "+string(b))
	}
	return nil
}

// AddAutoMirror appends a mirror to a group's list if not already present.
// Read-modify-write is done in a transaction so concurrent edits can't lose a
// mirror.
func (s *Store) AddAutoMirror(user, name, site string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRow(`SELECT sites FROM auto_sites WHERE name = ?`, name).Scan(&raw)
	if err == sql.ErrNoRows {
		return sql.ErrNoRows
	}
	if err != nil {
		return err
	}
	var sites []string
	if err := json.Unmarshal([]byte(raw), &sites); err != nil {
		return err
	}
	for _, x := range sites {
		if x == site {
			return tx.Commit() // duplicate: treat as success, no change
		}
	}
	sites = append(sites, site)
	b, err := json.Marshal(sites)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE auto_sites SET sites = ?, updated_at = datetime('now') WHERE name = ?`, string(b), name); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.RecordChange(user, "auto-update", name+" "+string(b))
	return nil
}

// RemoveAutoMirror removes a mirror from a group's list (transactional).
func (s *Store) RemoveAutoMirror(user, name, site string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRow(`SELECT sites FROM auto_sites WHERE name = ?`, name).Scan(&raw)
	if err == sql.ErrNoRows {
		return sql.ErrNoRows
	}
	if err != nil {
		return err
	}
	var sites []string
	if err := json.Unmarshal([]byte(raw), &sites); err != nil {
		return err
	}
	keep := sites[:0]
	for _, x := range sites {
		if x != site {
			keep = append(keep, x)
		}
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE auto_sites SET sites = ?, updated_at = datetime('now') WHERE name = ?`, string(b), name); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.RecordChange(user, "auto-update", name+" "+string(b))
	return nil
}

// ---------------- audit trail ---------------

func (s *Store) recentChanges(limit int) []configChangeRow {
	rows, err := s.db.Query(`SELECT id, ts, user, action, detail FROM config_changes ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []configChangeRow
	for rows.Next() {
		var r configChangeRow
		if err := rows.Scan(&r.ID, &r.TS, &r.User, &r.Action, &r.Detail); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

type configChangeRow struct {
	ID     int64
	TS     string
	User   string
	Action string
	Detail string
}

// tidyDomain normalizes a domain input (lowercase, no trailing dot).
func tidyDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}
