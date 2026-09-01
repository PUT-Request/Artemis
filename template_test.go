package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAutoTemplateNameFields guards against the add-mirror/remove-mirror forms
// posting an empty group name (which made them silently no-op).
func TestAutoTemplateNameFields(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	a := &app{cfg: cfg}
	w := newWebServer(a)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auto", nil)
	w.render(rec, req, "auto", map[string]any{
		"AutoSites": []AutoSiteConfig{
			{Name: "annas-archive", Sites: []string{"https://a.pk", "https://b.pk"}, Enabled: true},
		},
	})

	body := rec.Body.String()
	for _, want := range []string{
		`name="name" value="annas-archive"`,  // add-mirror form
		`name="name" value="annas-archive">`, // remove-mirror + delete forms
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("template missing %q", want)
		}
	}
	if strings.Contains(body, `name="name" value=""`) {
		t.Fatal("template renders an empty group name field")
	}
}
