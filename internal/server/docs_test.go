package server

import (
	"slices"
	"strings"
	"testing"
)

// internalRoutes serve the web UI and are deliberately left out of the public
// reference: they need a browser session, which third parties don't have.
var internalRoutes = []string{
	"GET /",
	"GET /docs",
	"GET /api/me",
	"POST /api/login",
	"POST /api/logout",
	"POST /api/enroll/info",
	"POST /api/enroll",
	"POST /api/monitors",
	"PUT /api/monitors/{id}",
	"DELETE /api/monitors/{id}",
	"POST /api/incidents/{id}/notes",
	"GET /api/keys",
	"POST /api/keys",
	"POST /api/keys/{id}/rotate",
	"DELETE /api/keys/{id}",
	"GET /api/users",
	"POST /api/users",
	"PUT /api/users/{id}",
	"DELETE /api/users/{id}",
	"GET /api/db",
	"PUT /api/db/retention",
	"POST /api/db/trim",
	"POST /api/db/vacuum",
}

// TestSpecMatchesRoutes fails when a route is added without either
// documenting it in openapi.json or listing it as internal, and when the
// spec documents a route that no longer exists.
func TestSpecMatchesRoutes(t *testing.T) {
	s := New(nil, nil, 1)
	s.Handler()
	sp, err := parseSpec(specJSON)
	if err != nil {
		t.Fatal(err)
	}
	var documented []string
	for _, p := range sp.Paths {
		for _, m := range p.Val {
			documented = append(documented, strings.ToUpper(m.Key)+" "+p.Key)
		}
	}
	for _, r := range s.routes {
		in, out := slices.Contains(documented, r), slices.Contains(internalRoutes, r)
		switch {
		case in && out:
			t.Errorf("%s is documented but also listed as internal", r)
		case !in && !out:
			t.Errorf("%s is neither documented in openapi.json nor listed in internalRoutes", r)
		}
	}
	for _, d := range append(documented, internalRoutes...) {
		if !slices.Contains(s.routes, d) {
			t.Errorf("%s is documented or listed but not registered", d)
		}
	}
}

func TestDocsPage(t *testing.T) {
	sp, err := parseSpec(specJSON)
	if err != nil {
		t.Fatal(err)
	}
	page, err := renderDocs(sp)
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if strings.Contains(html, "<script") {
		t.Error("the docs page must not need JavaScript")
	}
	for _, p := range sp.Paths {
		for _, m := range p.Val {
			if !strings.Contains(html, `id="`+m.Val.OperationID+`"`) {
				t.Errorf("%s %s has no section", m.Key, p.Key)
			}
		}
	}
	for _, e := range sp.Components.Schemas {
		if !strings.Contains(html, `id="model-`+e.Key+`"`) {
			t.Errorf("model %s has no section", e.Key)
		}
	}
	// Every in-page link lands somewhere.
	for _, part := range strings.Split(html, `href="#`)[1:] {
		id := part[:strings.IndexByte(part, '"')]
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("link to #%s has no target", id)
		}
	}
}

func TestMarkdown(t *testing.T) {
	for in, want := range map[string]string{
		"a <b> & `<c>`":              "<p>a &lt;b&gt; &amp; <code>&lt;c&gt;</code></p>\n",
		"**x** [y](https://e.com)":   `<p><strong>x</strong> <a href="https://e.com">y</a></p>` + "\n",
		"[bad](javascript:alert(1))": "<p>[bad](javascript:alert(1))</p>\n",
		"- one\n- `two`":             "<ul><li>one</li><li><code>two</code></li></ul>\n",
	} {
		if got := string(markdown(in)); got != want {
			t.Errorf("markdown(%q) = %q, want %q", in, got, want)
		}
	}
}
