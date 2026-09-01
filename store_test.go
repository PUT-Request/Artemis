package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreCRUDAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer s.Close()
	defer os.Remove(path)

	// live config loads with seeded defaults
	lc, err := s.loadLive()
	if err != nil {
		t.Fatalf("loadLive: %v", err)
	}
	if len(lc.Upstreams) == 0 {
		t.Fatal("expected seeded upstreams")
	}
	if !lc.SpecialEnabled {
		t.Fatal("expected special.enabled default true")
	}

	// upstream CRUD + audit
	if err := s.AddUpstream("tester", "9.9.9.9:53"); err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}
	ups, err := s.listUpstreams()
	if err != nil {
		t.Fatalf("listUpstreams: %v", err)
	}
	if len(ups) != 4 {
		t.Fatalf("upstreams = %d, want 4", len(ups))
	}
	if err := s.RemoveUpstream("tester", "9.9.9.9:53"); err != nil {
		t.Fatalf("RemoveUpstream: %v", err)
	}

	// redirect CRUD
	rc := RedirectConfig{Domain: "fmhy", Target: "https://fmhy.net", QueryParam: "q"}
	if err := s.AddRedirect("tester", rc); err != nil {
		t.Fatalf("AddRedirect: %v", err)
	}
	reds, err := s.listRedirects()
	if err != nil {
		t.Fatalf("listRedirects: %v", err)
	}
	if len(reds) != 1 || reds[0].Domain != "fmhy" {
		t.Fatalf("redirects = %+v", reds)
	}
	if err := s.UpdateRedirect("tester", "fmhy", RedirectConfig{Domain: "fmhy2", Target: "https://t.net"}); err != nil {
		t.Fatalf("UpdateRedirect: %v", err)
	}
	if err := s.DeleteRedirect("tester", "fmhy2"); err != nil {
		t.Fatalf("DeleteRedirect: %v", err)
	}

	// domain CRUD
	if err := s.AddDomain("tester", DomainConfig{Domain: "router.lan", IP: "192.168.1.1"}); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	doms, err := s.listDomains()
	if err != nil {
		t.Fatalf("listDomains: %v", err)
	}
	if len(doms) != 1 || doms[0].IP != "192.168.1.1" {
		t.Fatalf("domains = %+v", doms)
	}

	// setting
	if err := s.SetSetting("tester", "special.enabled", "false"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	lc2, err := s.loadLive()
	if err != nil {
		t.Fatalf("loadLive: %v", err)
	}
	if lc2.SpecialEnabled {
		t.Fatal("special.enabled should be false")
	}

	// auto site CRUD + mirror add/remove
	if err := s.AddAutoSite("tester", AutoSiteConfig{
		Name: "annas-archive", Sites: []string{"https://annas-archive.pk"}, Enabled: true,
	}); err != nil {
		t.Fatalf("AddAutoSite: %v", err)
	}
	if err := s.AddAutoMirror("tester", "annas-archive", "https://annas-archive.gl"); err != nil {
		t.Fatalf("AddAutoMirror: %v", err)
	}
	if err := s.AddAutoMirror("tester", "annas-archive", "https://annas-archive.pk"); err != nil {
		t.Fatalf("AddAutoMirror dup: %v", err) // duplicate should be ignored
	}
	lc3, err := s.loadLive()
	if err != nil {
		t.Fatalf("loadLive: %v", err)
	}
	if len(lc3.AutoSites) != 1 {
		t.Fatalf("auto sites = %d, want 1", len(lc3.AutoSites))
	}
	if got := lc3.AutoSites[0].Sites; len(got) != 2 || got[1] != "https://annas-archive.gl" {
		t.Fatalf("sites = %v", got)
	}
	if err := s.RemoveAutoMirror("tester", "annas-archive", "https://annas-archive.pk"); err != nil {
		t.Fatalf("RemoveAutoMirror: %v", err)
	}
	sites, err := s.autoSiteSites("annas-archive")
	if err != nil {
		t.Fatalf("autoSiteSites: %v", err)
	}
	if len(sites) != 1 || sites[0] != "https://annas-archive.gl" {
		t.Fatalf("after remove sites = %v", sites)
	}
	if err := s.DeleteAutoSite("tester", "annas-archive"); err != nil {
		t.Fatalf("DeleteAutoSite: %v", err)
	}
	autos, err := s.listAutoSites()
	if err != nil {
		t.Fatalf("listAutoSites: %v", err)
	}
	if len(autos) != 0 {
		t.Fatalf("auto sites after delete = %d, want 0", len(autos))
	}

	// audit trail recorded
	changes := s.recentChanges(100)
	if len(changes) == 0 {
		t.Fatal("expected audit entries")
	}

	// per-IP request counter (async writer, so poll until flushed)
	s.LogIP("127.0.0.1")
	s.LogIP("127.0.0.1")
	s.LogIP("10.0.0.5")
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n1, n2 int
		s.db.QueryRow(`SELECT count FROM request_log WHERE client_ip='127.0.0.1'`).Scan(&n1)
		s.db.QueryRow(`SELECT count FROM request_log WHERE client_ip='10.0.0.5'`).Scan(&n2)
		if n1 == 2 && n2 == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("request_log not flushed: 127.0.0.1=%d (want 2), 10.0.0.5=%d (want 1)", n1, n2)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSeedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seed.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	// delete all upstreams, reopen: defaults must NOT resurrect
	for _, u := range []string{"94.140.14.14:53", "1.1.1.1:53", "8.8.8.8:53"} {
		if err := s.RemoveUpstream("tester", u); err != nil {
			t.Fatalf("RemoveUpstream: %v", err)
		}
	}
	s.Close()

	s2, err := openStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	ups, _ := s2.listUpstreams()
	if len(ups) != 0 {
		t.Fatalf("defaults resurrected after reopen: %v", ups)
	}
}

// TestSchemaMigrationV3 simulates a pre-v3 DB (redirects still has the
// answer_ip/http_port columns) and checks openStore drops them.
func TestSchemaMigrationV3(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate.db")

	db, err := openRawSQLite(path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key,value) VALUES ('schema_version','2')`); err != nil {
		t.Fatalf("version: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE redirects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		target TEXT NOT NULL,
		query_param TEXT NOT NULL DEFAULT '',
		answer_ip TEXT NOT NULL DEFAULT '127.0.0.1',
		http_port INTEGER NOT NULL DEFAULT 8080,
		updated_at TEXT NOT NULL DEFAULT (datetime('now'))
	);`); err != nil {
		t.Fatalf("redirects: %v", err)
	}
	db.Close()

	s, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer s.Close()

	var hasAnswerIP, hasHTTPPort int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('redirects') WHERE name='answer_ip'`).Scan(&hasAnswerIP); err != nil {
		t.Fatalf("pragma answer_ip: %v", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('redirects') WHERE name='http_port'`).Scan(&hasHTTPPort); err != nil {
		t.Fatalf("pragma http_port: %v", err)
	}
	if hasAnswerIP != 0 || hasHTTPPort != 0 {
		t.Fatalf("columns not dropped: answer_ip=%d http_port=%d", hasAnswerIP, hasHTTPPort)
	}
	var ver string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("version: %v", err)
	}
	if ver != "3" {
		t.Fatalf("schema_version = %q, want 3", ver)
	}
}

func TestUpgradeAddsNewToggles(t *testing.T) {
	// Simulate a DB seeded by an older build: seeded=1, no short.enabled.
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := openRawSQLite(path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
		`INSERT INTO settings (key,value) VALUES ('seeded','1')`,
		`INSERT INTO settings (key,value) VALUES ('special.enabled','true')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	db.Close()

	s, err := openStore(path)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer s.Close()
	if v, _ := s.getSetting("short.enabled"); v != "true" {
		t.Fatalf("short.enabled = %q, want true (upgrade must add new toggles)", v)
	}
	if v, _ := s.getSetting("special.enabled"); v != "true" {
		t.Fatalf("special.enabled = %q", v)
	}
	lc, err := s.loadLive()
	if err != nil {
		t.Fatalf("loadLive: %v", err)
	}
	if !lc.ShortEnabled {
		t.Fatal("ShortEnabled should be true after upgrade")
	}
}

// openRawSQLite opens a SQLite file with no migrations/seeding.
func openRawSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
