package server_test

// End-to-end tests: a real server, checker and SQLite database, driven over
// HTTP the way the UI drives it, probing a local target whose status we flip.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ELT-Global/blip/internal/monitor"
	"github.com/ELT-Global/blip/internal/server"
	"github.com/ELT-Global/blip/internal/store"
	"github.com/ELT-Global/blip/internal/totp"
)

type env struct {
	t      *testing.T
	url    string
	db     *store.DB
	dbPath string
	target string
	status atomic.Int32           // what the target responds with
	body   atomic.Pointer[string] // and its JSON body, if set
	hits   atomic.Int64           // requests the target has received
}

// respond sets the target's status and JSON body.
func (e *env) respond(status int, body string) {
	e.body.Store(&body)
	e.status.Store(int32(status))
}

func setup(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blip.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, dbPath: path}
	e.status.Store(200)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		body := e.body.Load()
		if body != nil {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(int(e.status.Load()))
		if body != nil {
			io.WriteString(w, *body)
		}
	}))
	e.target = target.URL

	ctx, cancel := context.WithCancel(context.Background())
	runner := monitor.New(db)
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()
	srv := httptest.NewServer(server.New(db, runner, 1).Handler())
	e.url = srv.URL
	t.Cleanup(func() {
		srv.Close()
		cancel()
		<-done
		target.Close()
		db.Close()
	})
	return e
}

type client struct {
	e    *env
	http *http.Client
}

func (e *env) anon() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar}}
}

// root creates an enrolled root account and returns a client signed in as it.
func (e *env) root(email string) *client {
	e.t.Helper()
	secret := totp.NewSecret()
	if err := e.db.UpsertRoot(context.Background(), email, secret, 0); err != nil {
		e.t.Fatal(err)
	}
	c := e.anon()
	c.mustDo("POST", "/api/login", map[string]string{"email": email, "code": totp.Code(secret, totp.Step(time.Now()))}, 200, nil)
	return c
}

// do sends a JSON request and decodes the JSON reply into out (if non-nil).
func (c *client) do(method, path string, body any, out any) int {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.url+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", c.e.url) // as browsers send on every POST
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			c.e.t.Fatalf("%s %s: decode %q: %v", method, path, data, err)
		}
	}
	return res.StatusCode
}

func (c *client) mustDo(method, path string, body any, want int, out any) {
	c.e.t.Helper()
	if got := c.do(method, path, body, out); got != want {
		c.e.t.Fatalf("%s %s = %d, want %d", method, path, got, want)
	}
}

func eventually(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type user struct {
	ID      int64
	Email   string
	Role    string
	Pending bool
	Invite  string
}

type bucket struct{ T, N, Up, Ms int64 }

type monitorView struct {
	ID       int64
	Name     string
	Method   string
	URL      string
	Interval int
	Public   bool
	Last     *struct{ T, Ms, Code int64 }
	Days     []bucket
}

type incident struct {
	ID    int64
	Start int64
	Ended *int64
	Code  int
	Cause string
	Notes []struct {
		Author string
		T      int64
		Body   string
	}
}

type dbStats struct {
	File   int64
	Tables []struct {
		Name string
		Rows int64
	}
	Oldest    int64
	Retention struct {
		RawDays  int `json:"raw_days"`
		HourDays int `json:"hour_days"`
	}
}

func (s dbStats) rows(table string) int64 {
	for _, t := range s.Tables {
		if t.Name == table {
			return t.Rows
		}
	}
	return -1
}

func hash(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func TestLogin(t *testing.T) {
	e := setup(t)
	secret := totp.NewSecret()
	if err := e.db.UpsertRoot(context.Background(), "admin@example.com", secret, 0); err != nil {
		t.Fatal(err)
	}
	c := e.anon()
	var me *user
	c.mustDo("GET", "/api/me", nil, 200, &me)
	if me != nil {
		t.Fatalf("signed out /api/me = %+v, want null", me)
	}

	code := totp.Code(secret, totp.Step(time.Now()))
	wrong := fmt.Sprintf("%06d", (atoi(code)+1)%1_000_000)
	c.mustDo("POST", "/api/login", map[string]string{"email": "admin@example.com", "code": wrong}, 401, nil)
	c.mustDo("POST", "/api/login", map[string]string{"email": "nobody@example.com", "code": code}, 401, nil)
	c.mustDo("POST", "/api/login", map[string]string{"email": "ADMIN@example.com", "code": code}, 200, nil)
	c.mustDo("GET", "/api/me", nil, 200, &me)
	if me == nil || me.Email != "admin@example.com" || me.Role != "root" {
		t.Fatalf("/api/me = %+v, want the root user", me)
	}

	// A code works once: replaying it from another client fails.
	e.anon().mustDo("POST", "/api/login", map[string]string{"email": "admin@example.com", "code": code}, 401, nil)

	// Logout must end the session on the server, not just drop the cookie.
	u, _ := url.Parse(e.url)
	stolen := c.http.Jar.Cookies(u)
	c.mustDo("POST", "/api/logout", nil, 204, nil)
	thief := e.anon()
	thief.http.Jar.SetCookies(u, stolen)
	thief.mustDo("GET", "/api/me", nil, 200, &me)
	if me != nil {
		t.Fatalf("logged-out session still resolves to %+v", me)
	}
	thief.mustDo("GET", "/api/users", nil, 401, nil)
}

func TestSessionExpiry(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var me user
	root.mustDo("GET", "/api/me", nil, 200, &me)

	tok := "expired-session-token"
	if err := e.db.CreateSession(context.Background(), hash(tok), me.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	c := e.anon()
	u, _ := url.Parse(e.url)
	c.http.Jar.SetCookies(u, []*http.Cookie{{Name: "blip_session", Value: tok}})
	var got *user
	c.mustDo("GET", "/api/me", nil, 200, &got)
	if got != nil {
		t.Fatalf("expired session resolves to %+v", got)
	}
	c.mustDo("GET", "/api/users", nil, 401, nil)

	// Trim sweeps the expired session but keeps the live one.
	root.mustDo("POST", "/api/db/trim", nil, 200, nil)
	var st dbStats
	root.mustDo("GET", "/api/db", nil, 200, &st)
	if n := st.rows("sessions"); n != 1 {
		t.Errorf("sessions after trim = %d, want 1", n)
	}
}

// Bootstrapping an existing email resets it and revokes its sessions.
func TestBootstrapResetRevokesSessions(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	if err := e.db.UpsertRoot(context.Background(), "root@example.com", totp.NewSecret(), 0); err != nil {
		t.Fatal(err)
	}
	root.mustDo("GET", "/api/users", nil, 401, nil)
}

func TestLoginRateLimit(t *testing.T) {
	e := setup(t)
	secret := totp.NewSecret()
	e.db.UpsertRoot(context.Background(), "admin@example.com", secret, 0)
	c := e.anon()
	// Malformed emails are rejected before the limiter, costing nothing.
	for range 15 {
		c.mustDo("POST", "/api/login", map[string]string{"email": strings.Repeat("x", 300) + "@example.com", "code": "000000"}, 401, nil)
		c.mustDo("POST", "/api/login", map[string]string{"email": "not an email", "code": "000000"}, 401, nil)
	}
	for range 10 {
		c.mustDo("POST", "/api/login", map[string]string{"email": "admin@example.com", "code": "000000"}, 401, nil)
	}
	// Even the right code is refused once the limit is hit, and so is
	// another account from the same address.
	code := totp.Code(secret, totp.Step(time.Now()))
	c.mustDo("POST", "/api/login", map[string]string{"email": "admin@example.com", "code": code}, 429, nil)
	c.mustDo("POST", "/api/login", map[string]string{"email": "other@example.com", "code": code}, 429, nil)

	// The email stays locked from other addresses (as a proxy reports them),
	// while those addresses can still try other accounts.
	from := func(ip, email string) int {
		req, _ := http.NewRequest("POST", e.url+"/api/login", strings.NewReader(`{"email":"`+email+`","code":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if got := from("203.0.113.7", "admin@example.com"); got != 429 {
		t.Errorf("locked email from a new address = %d, want 429", got)
	}
	if got := from("203.0.113.8", "someone@example.com"); got != 401 {
		t.Errorf("other email from a new address = %d, want 401", got)
	}

	// A blocked address can't spend attempts against another account.
	for range 12 {
		c.mustDo("POST", "/api/login", map[string]string{"email": "victim@example.com", "code": "000000"}, 429, nil)
	}
	if got := from("203.0.113.9", "victim@example.com"); got != 401 {
		t.Errorf("victim from a fresh address = %d, want 401 (not locked by refused attempts)", got)
	}
}

func TestEnrollRateLimit(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var u user
	root.mustDo("POST", "/api/users", map[string]string{"email": "new@example.com", "role": "read"}, 201, &u)
	token := strings.TrimPrefix(u.Invite, "/panel/enroll#")
	c := e.anon()
	for range 10 {
		c.mustDo("POST", "/api/enroll", map[string]string{"token": token, "code": "000000"}, 401, nil)
	}
	c.mustDo("POST", "/api/enroll", map[string]string{"token": token, "code": "000000"}, 429, nil)
}

// enrollUser invites email with role and completes enrollment as that user.
func enrollUser(t *testing.T, root *client, email, role string) *client {
	t.Helper()
	var u user
	root.mustDo("POST", "/api/users", map[string]string{"email": email, "role": role}, 201, &u)
	if !u.Pending || !strings.HasPrefix(u.Invite, "/panel/enroll#") {
		t.Fatalf("invite = %+v", u)
	}
	token := strings.TrimPrefix(u.Invite, "/panel/enroll#")
	c := root.e.anon()
	var info struct{ Email, Secret, URI, QR string }
	c.mustDo("POST", "/api/enroll/info", map[string]string{"token": token}, 200, &info)
	if info.Email != email || !strings.HasPrefix(info.QR, "<svg") || !strings.Contains(info.URI, "secret="+info.Secret) {
		t.Fatalf("enrollment info = %+v", info)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(info.Secret)
	if err != nil {
		t.Fatal(err)
	}
	c.mustDo("POST", "/api/enroll", map[string]string{"token": token, "code": "123"}, 401, nil)
	c.mustDo("POST", "/api/enroll", map[string]string{"token": token, "code": totp.Code(secret, totp.Step(time.Now()))}, 200, nil)
	var me user
	c.mustDo("GET", "/api/me", nil, 200, &me)
	if me.Email != email || me.Role != role || me.Pending {
		t.Fatalf("enrolled user = %+v", me)
	}
	// The invite is single-use.
	c.mustDo("POST", "/api/enroll/info", map[string]string{"token": token}, 404, nil)
	return c
}

func TestInviteExpiry(t *testing.T) {
	e := setup(t)
	secret := totp.NewSecret()
	_, err := e.db.InviteUser(context.Background(), "late@example.com", store.RoleRead, secret, hash("old-invite"), time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	c := e.anon()
	c.mustDo("POST", "/api/enroll/info", map[string]string{"token": "old-invite"}, 404, nil)
	c.mustDo("POST", "/api/enroll", map[string]string{"token": "old-invite", "code": totp.Code(secret, totp.Step(time.Now()))}, 404, nil)
	c.mustDo("POST", "/api/enroll/info", map[string]string{"token": "bogus"}, 404, nil)
}

func TestUsersAndPermissions(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	reader := enrollUser(t, root, "reader@example.com", "read")
	writer := enrollUser(t, root, "writer@example.com", "write")

	root.mustDo("POST", "/api/users", map[string]string{"email": "reader@example.com", "role": "read"}, 409, nil)
	root.mustDo("POST", "/api/users", map[string]string{"email": "not-an-email", "role": "read"}, 400, nil)
	root.mustDo("POST", "/api/users", map[string]string{"email": "x@example.com", "role": "admin"}, 400, nil)

	var priv monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "Private", "url": e.target, "interval": 3600, "public": false}, 201, &priv)
	var list []monitorView
	reader.mustDo("GET", "/api/monitors", nil, 200, &list)
	if len(list) != 1 || list[0].URL == "" {
		t.Errorf("reader sees %+v, want the private monitor with its target", list)
	}

	// Every gated route, by the role it needs.
	mon := map[string]any{"name": "API", "url": e.target, "interval": 60, "public": true}
	mp := fmt.Sprintf("/api/monitors/%d", priv.ID)
	routes := []struct {
		method, path string
		body         any
		role         string
	}{
		{"POST", "/api/monitors", mon, "write"},
		{"PUT", mp, mon, "write"},
		{"DELETE", "/api/monitors/999999", nil, "write"},
		{"POST", "/api/incidents/999999/notes", map[string]string{"body": "x"}, "write"},
		{"GET", "/api/users", nil, "root"},
		{"POST", "/api/users", map[string]string{"email": "y@example.com", "role": "bogus"}, "root"},
		{"PUT", "/api/users/999999", map[string]string{"role": "read"}, "root"},
		{"DELETE", "/api/users/999999", nil, "root"},
		{"GET", "/api/db", nil, "root"},
		{"PUT", "/api/db/retention", map[string]int{"raw_days": 30, "hour_days": 400}, "root"},
		{"POST", "/api/db/trim", nil, "root"},
		{"POST", "/api/db/vacuum", nil, "root"},
	}
	anon := e.anon()
	for _, r := range routes {
		if got := anon.do(r.method, r.path, r.body, nil); got != 401 {
			t.Errorf("anonymous %s %s = %d, want 401", r.method, r.path, got)
		}
		if got := reader.do(r.method, r.path, r.body, nil); got != 403 {
			t.Errorf("reader %s %s = %d, want 403", r.method, r.path, got)
		}
		if got := writer.do(r.method, r.path, r.body, nil); (r.role == "root") != (got == 403) {
			t.Errorf("writer %s %s = %d, want 403 only for root routes", r.method, r.path, got)
		}
	}

	var us []user
	root.mustDo("GET", "/api/users", nil, 200, &us)
	ids := map[string]int64{}
	for _, u := range us {
		ids[u.Email] = u.ID
	}
	if len(ids) != 3 {
		t.Fatalf("users = %+v, want 3", us)
	}

	// Promote the reader; their existing session picks up the new role.
	root.mustDo("PUT", fmt.Sprintf("/api/users/%d", ids["reader@example.com"]), map[string]string{"role": "write"}, 204, nil)
	reader.mustDo("PUT", mp, mon, 200, nil)

	// A pending root invite doesn't count: the last enrolled root stays.
	root.mustDo("POST", "/api/users", map[string]string{"email": "pending-root@example.com", "role": "root"}, 201, nil)
	rootPath := fmt.Sprintf("/api/users/%d", ids["root@example.com"])
	root.mustDo("PUT", rootPath, map[string]string{"role": "read"}, 409, nil)
	root.mustDo("DELETE", rootPath, nil, 409, nil)

	// Removing a user ends their sessions.
	root.mustDo("DELETE", fmt.Sprintf("/api/users/%d", ids["writer@example.com"]), nil, 204, nil)
	writer.mustDo("POST", "/api/monitors", mon, 401, nil)
	root.mustDo("DELETE", fmt.Sprintf("/api/users/%d", ids["writer@example.com"]), nil, 404, nil)
}

func TestVisibility(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var pub, priv monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "Public", "url": e.target, "interval": 60, "public": true}, 201, &pub)
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "Private", "url": e.target + "/secret", "interval": 60, "public": false}, 201, &priv)

	anon := e.anon()
	var list []monitorView
	anon.mustDo("GET", "/api/monitors", nil, 200, &list)
	if len(list) != 1 || list[0].ID != pub.ID {
		t.Fatalf("anonymous list = %+v, want only the public monitor", list)
	}
	if list[0].URL != "" || list[0].Method != "" {
		t.Errorf("anonymous view leaks target: %+v", list[0])
	}
	for _, p := range []string{"", "/checks", "/hours", "/incidents"} {
		anon.mustDo("GET", fmt.Sprintf("/api/monitors/%d%s", priv.ID, p), nil, 404, nil)
	}

	root.mustDo("GET", "/api/monitors", nil, 200, &list)
	if len(list) != 2 {
		t.Fatalf("signed-in list has %d monitors, want 2", len(list))
	}
	var got monitorView
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d", priv.ID), nil, 200, &got)
	if got.URL != e.target+"/secret" || got.Method != "GET" {
		t.Errorf("signed-in view = %+v, want target shown", got)
	}
}

func TestMonitorValidation(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	for _, body := range []map[string]any{
		{"name": "", "url": e.target, "interval": 60},
		{"name": "x", "url": "ftp://example.com", "interval": 60},
		{"name": "x", "url": "/relative", "interval": 60},
		{"name": "x", "url": e.target, "interval": 0},
		{"name": "x", "url": e.target, "interval": 90000},
		{"name": "x", "url": e.target, "interval": 60, "method": "BREW"},
		{"name": "x", "url": e.target, "interval": 60, "extra": true},
	} {
		if got := root.do("POST", "/api/monitors", body, nil); got != 400 {
			t.Errorf("POST /api/monitors %v = %d, want 400", body, got)
		}
	}
	root.mustDo("PUT", "/api/monitors/999", map[string]any{"name": "x", "url": e.target, "interval": 60}, 404, nil)
}

func TestEditRestartsChecks(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var m monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "url": e.target, "interval": 3600, "public": true}, 201, &m)
	path := fmt.Sprintf("/api/monitors/%d", m.ID)
	eventually(t, "the first check", func() bool {
		var v monitorView
		root.mustDo("GET", path, nil, 200, &v)
		return v.Last != nil
	})

	// The next scheduled check is an hour away, so only a restart can see this.
	e.status.Store(503)
	root.mustDo("PUT", path, map[string]any{"name": "Renamed", "url": e.target + "/v2", "interval": 3600, "public": false}, 200, nil)
	var v monitorView
	eventually(t, "a check of the edited monitor", func() bool {
		root.mustDo("GET", path, nil, 200, &v)
		return v.Last != nil && v.Last.Code == 503
	})
	if v.Name != "Renamed" || v.URL != e.target+"/v2" || v.Public {
		t.Errorf("after edit = %+v", v)
	}
	e.anon().mustDo("GET", path, nil, 404, nil) // now private
}

func TestCheckIncidentFlow(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	writer := enrollUser(t, root, "writer@example.com", "write")
	var m monitorView
	writer.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "method": "head", "url": e.target, "interval": 1, "public": true}, 201, &m)
	if m.Method != "HEAD" {
		t.Errorf("method = %q, want normalized HEAD", m.Method)
	}
	path := fmt.Sprintf("/api/monitors/%d", m.ID)
	anon := e.anon()
	countChecks := func(code int64) (n int) {
		var cs []struct{ Code int64 }
		anon.mustDo("GET", path+"/checks", nil, 200, &cs)
		for _, c := range cs {
			if c.Code == code {
				n++
			}
		}
		return n
	}
	incidents := func(c *client) (incs []incident) {
		c.mustDo("GET", path+"/incidents", nil, 200, &incs)
		return incs
	}

	eventually(t, "a successful check", func() bool { return countChecks(200) > 0 })

	// A sustained outage is one incident, not one per failed check.
	e.status.Store(503)
	eventually(t, "three failed checks", func() bool { return countChecks(503) >= 3 })
	incs := incidents(anon)
	if len(incs) != 1 || incs[0].Ended != nil || incs[0].Code != 503 || !strings.Contains(incs[0].Cause, "503") {
		t.Fatalf("incidents = %+v, want one ongoing 503", incs)
	}

	notePath := fmt.Sprintf("/api/incidents/%d/notes", incs[0].ID)
	anon.mustDo("POST", notePath, map[string]string{"body": "hi"}, 401, nil)
	writer.mustDo("POST", notePath, map[string]string{"body": "  "}, 400, nil)
	writer.mustDo("POST", "/api/incidents/9999/notes", map[string]string{"body": "x"}, 404, nil)
	writer.mustDo("POST", notePath, map[string]string{"body": "Looking into it"}, 201, nil)

	e.status.Store(200)
	eventually(t, "the incident to resolve", func() bool {
		incs = incidents(anon)
		return len(incs) == 1 && incs[0].Ended != nil
	})
	// Note authors are emails: visible to users, hidden from the public.
	if n := incs[0].Notes; len(n) != 1 || n[0].Body != "Looking into it" || n[0].Author != "" || n[0].T == 0 {
		t.Errorf("public notes = %+v, want the note without its author", n)
	}
	if n := incidents(root)[0].Notes; len(n) != 1 || n[0].Author != "writer@example.com" {
		t.Errorf("signed-in notes = %+v, want the writer as author", n)
	}

	// A second outage opens a second incident, listed first.
	e.status.Store(500)
	eventually(t, "a second incident", func() bool { return len(incidents(anon)) == 2 })
	incs = incidents(anon)
	if incs[0].Code != 500 || incs[0].Ended != nil || incs[1].Ended == nil || incs[0].Start < incs[1].Start {
		t.Errorf("incidents = %+v, want the ongoing 500 first, then the resolved one", incs)
	}

	// Deleting the monitor stops its checks and removes all its history.
	writer.mustDo("DELETE", path, nil, 204, nil)
	anon.mustDo("GET", path, nil, 404, nil)
	hits := e.hits.Load()
	time.Sleep(2500 * time.Millisecond)
	if extra := e.hits.Load() - hits; extra > 1 { // one probe may have been in flight
		t.Errorf("target got %d requests after delete", extra)
	}
	var st dbStats
	root.mustDo("GET", "/api/db", nil, 200, &st)
	for _, table := range []string{"checks", "hours", "incidents", "notes", "monitors"} {
		if n := st.rows(table); n != 0 {
			t.Errorf("%s rows after delete = %d, want 0", table, n)
		}
	}
}

// Rollups must match the raw checks exactly, including duplicate results
// and day boundaries in the viewer's timezone.
func TestRollups(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var m monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "url": e.target, "interval": 3600, "public": true}, 201, &m)

	day := (time.Now().Unix()/86400 - 10) * 86400 // a UTC midnight ten days ago
	batch := []store.Check{
		{MonitorID: m.ID, T: day + 3600, Ms: 100, Code: 200},
		{MonitorID: m.ID, T: day + 3660, Ms: 30, Code: 500},
		{MonitorID: m.ID, T: day + 3720, Ms: 300, Code: 200},
		{MonitorID: m.ID, T: day + 23*3600, Ms: 50, Code: 200},
	}
	for range 2 { // replaying a batch must not count checks or open incidents twice
		if err := e.db.Record(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
	}
	var incs []incident
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/incidents", m.ID), nil, 200, &incs)
	if len(incs) != 1 || incs[0].Start != day+3660 || incs[0].Ended == nil || *incs[0].Ended != day+3720 {
		t.Fatalf("incidents = %+v, want the one 500 from %d to %d", incs, day+3660, day+3720)
	}

	var hours []bucket
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/hours?from=%d&to=%d", m.ID, day, day+86400), nil, 200, &hours)
	want := []bucket{{day + 3600, 3, 2, 200}, {day + 23*3600, 1, 1, 50}}
	if fmt.Sprint(hours) != fmt.Sprint(want) {
		t.Errorf("hours = %v, want %v", hours, want)
	}

	days := func(tz int) map[int64]bucket {
		var v monitorView
		root.mustDo("GET", fmt.Sprintf("/api/monitors/%d?days=30&tz=%d", m.ID, tz), nil, 200, &v)
		out := map[int64]bucket{}
		for _, b := range v.Days {
			out[b.T] = b
		}
		return out
	}
	if got := days(0)[day]; got != (bucket{day, 4, 3, 150}) {
		t.Errorf("UTC day = %+v, want 4 checks, 3 up, 150ms mean", got)
	}
	// At UTC+1 the 23:00 UTC check falls on the next local day.
	d := days(3600)
	if got := d[day-3600]; got != (bucket{day - 3600, 3, 2, 200}) {
		t.Errorf("UTC+1 day = %+v, want 3 checks", got)
	}
	if got := d[day+86400-3600]; got.N != 1 {
		t.Errorf("UTC+1 next day = %+v, want 1 check", got)
	}

	// A late result for a deleted monitor must not sink the rest of its batch,
	// and a same-second result with a new status still changes state (here,
	// opens an incident) without being counted twice.
	late := []store.Check{
		{MonitorID: m.ID + 1000, T: day + 7200, Ms: 1, Code: 200},
		{MonitorID: m.ID, T: day + 3600, Ms: 5, Code: 503, Err: "503 Service Unavailable"},
	}
	if err := e.db.Record(context.Background(), late); err != nil {
		t.Fatal(err)
	}
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/hours?from=%d&to=%d", m.ID, day, day+86400), nil, 200, &hours)
	if fmt.Sprint(hours) != fmt.Sprint(want) {
		t.Errorf("hours after same-second result = %v, want unchanged %v", hours, want)
	}
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/incidents", m.ID), nil, 200, &incs)
	if len(incs) != 2 || incs[0].Start != day+3660 || incs[1].Start != day+3600 {
		t.Errorf("incidents = %+v, want the 500 plus one opened by the same-second 503", incs)
	}
}

func TestRetention(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var m monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "url": e.target, "interval": 3600, "public": true}, 201, &m)
	eventually(t, "the first check", func() bool {
		var v monitorView
		root.mustDo("GET", fmt.Sprintf("/api/monitors/%d", m.ID), nil, 200, &v)
		return v.Last != nil
	})

	// Seed two days of hourly checks sixty days ago, including a resolved outage.
	now := time.Now().Unix()
	old := now - 60*86400
	var batch []store.Check
	for t := old; t < old+48*3600; t += 3600 {
		code := 200
		if t == old+3600 {
			code = 503
		}
		batch = append(batch, store.Check{MonitorID: m.ID, T: t, Ms: 50, Code: code})
	}
	if err := e.db.Record(context.Background(), batch); err != nil {
		t.Fatal(err)
	}

	var st dbStats
	root.mustDo("GET", "/api/db", nil, 200, &st)
	if st.File == 0 || st.Oldest != old || st.Retention.RawDays != 30 || st.Retention.HourDays != 400 {
		t.Fatalf("stats = %+v, want defaults 30/400 and the seeded oldest check", st)
	}

	// Zero keeps data forever.
	type trimmed struct{ Checks, Hours, Incidents int64 }
	var res trimmed
	root.mustDo("PUT", "/api/db/retention", map[string]int{"raw_days": -1, "hour_days": 0}, 400, nil)
	root.mustDo("PUT", "/api/db/retention", map[string]int{"raw_days": 0, "hour_days": 0}, 200, nil)
	root.mustDo("POST", "/api/db/trim", nil, 200, &res)
	if res != (trimmed{}) {
		t.Errorf("trim with retention off = %+v, want nothing removed", res)
	}

	root.mustDo("PUT", "/api/db/retention", map[string]int{"raw_days": 30, "hour_days": 90}, 200, nil)
	root.mustDo("POST", "/api/db/trim", nil, 200, &res)
	if res != (trimmed{Checks: 48}) {
		t.Errorf("trim = %+v, want 48 raw checks removed and rollups kept", res)
	}

	// The old range is now quantized: no raw checks, but hourly history remains.
	q := fmt.Sprintf("?from=%d&to=%d", old, old+48*3600)
	var checks, hours []map[string]any
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/checks%s", m.ID, q), nil, 200, &checks)
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/hours%s", m.ID, q), nil, 200, &hours)
	if len(checks) != 0 || len(hours) != 48 {
		t.Errorf("after trim: %d checks, %d hours; want 0 and 48", len(checks), len(hours))
	}

	// Cutting rollups to 30 days also drops the old resolved incident, while
	// an ongoing one survives.
	e.status.Store(503)
	root.mustDo("PUT", fmt.Sprintf("/api/monitors/%d", m.ID), map[string]any{"name": "API", "url": e.target, "interval": 3600, "public": true}, 200, nil)
	var incs []incident
	eventually(t, "an ongoing incident", func() bool {
		root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/incidents", m.ID), nil, 200, &incs)
		return len(incs) == 2 && incs[0].Ended == nil
	})
	root.mustDo("PUT", "/api/db/retention", map[string]int{"raw_days": 30, "hour_days": 30}, 200, nil)
	root.mustDo("POST", "/api/db/trim", nil, 200, &res)
	if res != (trimmed{Hours: 48, Incidents: 1}) {
		t.Errorf("second trim = %+v, want 48 hours and 1 incident removed", res)
	}
	root.mustDo("GET", fmt.Sprintf("/api/monitors/%d/incidents", m.ID), nil, 200, &incs)
	if len(incs) != 1 || incs[0].Ended != nil {
		t.Errorf("incidents after trim = %+v, want only the ongoing one", incs)
	}
	root.mustDo("POST", "/api/db/vacuum", nil, 204, nil)
}

func TestOriginCheck(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	post := func(origin string) int {
		req, _ := http.NewRequest("POST", e.url+"/api/monitors", strings.NewReader(`{"name":"x","url":"http://a.b","interval":60}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		res, err := root.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if got := post("https://evil.example"); got != 403 {
		t.Errorf("cross-origin POST = %d, want 403", got)
	}
	var list []monitorView
	root.mustDo("GET", "/api/monitors", nil, 200, &list)
	if len(list) != 0 {
		t.Errorf("rejected POST still created %d monitors", len(list))
	}
	if got := post(e.url); got != 201 {
		t.Errorf("same-origin POST = %d, want 201", got)
	}
}

// Incident causes are public, so transport errors must not echo the target.
func TestIncidentCauseHidesTarget(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here now, so connections are refused
	var m monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "Gone", "url": "http://" + addr + "/private-path", "interval": 60, "public": true}, 201, &m)

	var incs []incident
	eventually(t, "an incident", func() bool {
		e.anon().mustDo("GET", fmt.Sprintf("/api/monitors/%d/incidents", m.ID), nil, 200, &incs)
		return len(incs) == 1
	})
	if incs[0].Code != store.CodeRefused {
		t.Errorf("code = %d, want CodeRefused", incs[0].Code)
	}
	if c := incs[0].Cause; c == "" || strings.Contains(c, addr) || strings.Contains(c, "private-path") {
		t.Errorf("cause %q is empty or reveals the target", c)
	}
}

// get fetches url with optional header pairs. RoundTrip, unlike Client.Do,
// leaves gzip bodies as sent.
func get(t *testing.T, url string, header ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, body
}

func TestStaticAssets(t *testing.T) {
	e := setup(t)
	for path, want := range map[string]string{
		"/":                     "text/html",
		"/m/42":                 "text/html",
		"/panel":                "text/html",
		"/panel/settings":       "text/html",
		"/status.js":            "text/javascript",
		"/sw.js":                "text/javascript",
		"/manifest.webmanifest": "application/manifest+json",
		"/icon-512.png":         "image/png",
	} {
		res, _ := get(t, e.url+path)
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), want) {
			t.Errorf("GET %s = %d %s, want 200 %s", path, res.StatusCode, res.Header.Get("Content-Type"), want)
		}
	}
	res, _ := get(t, e.url+"/")
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("security headers = %v", res.Header)
	}

	if res, _ := get(t, e.url+"/nope.js"); res.StatusCode != 404 {
		t.Errorf("GET /nope.js = %d, want 404", res.StatusCode)
	}
	if res, body := get(t, e.url+"/api/nope"); res.StatusCode != 404 || !strings.Contains(string(body), `"error"`) {
		t.Errorf("GET /api/nope = %d %s, want a JSON 404", res.StatusCode, body)
	}

	// Compressed only when accepted, decompressing to the same bytes, and
	// revalidated with the ETag.
	plainRes, plain := get(t, e.url+"/app.css")
	if plainRes.Header.Get("Content-Encoding") != "" {
		t.Errorf("app.css compressed for a client that didn't ask")
	}
	res, gz := get(t, e.url+"/app.css", "Accept-Encoding", "gzip")
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("app.css headers = %v, want gzip", res.Header)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	if unzipped, _ := io.ReadAll(zr); !bytes.Equal(unzipped, plain) || len(gz) >= len(plain) {
		t.Errorf("gzip body (%d bytes) doesn't decompress to the %d-byte original", len(gz), len(plain))
	}
	if res, _ := get(t, e.url+"/app.css", "If-None-Match", res.Header.Get("ETag")); res.StatusCode != 304 {
		t.Errorf("revalidation = %d, want 304", res.StatusCode)
	}
}

func atoi(s string) (n int) {
	fmt.Sscan(s, &n)
	return n
}

// A health body that reports failure turns a 200 into an outage, degraded
// checks are counted but stay up, and public callers see only the status.
func TestHealthBody(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var m monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "url": e.target, "interval": 1, "public": true}, 201, &m)
	path := fmt.Sprintf("/api/monitors/%d", m.ID)
	anon := e.anon()
	type report struct {
		Status, Format, Version, Instance string
		Started                           int64
		Components                        []struct{ Name, Status string }
	}
	var mv struct {
		Health *struct{ Mode string }
		Report *report
		Days   []struct{ Warn int }
	}
	get := func(c *client) {
		mv.Report, mv.Health = nil, nil
		c.mustDo("GET", path, nil, 200, &mv)
	}

	e.respond(200, `{"status":"UP","components":{"db":{"status":"UP"},"redis":{"status":"UP"}}}`)
	eventually(t, "a passing report", func() bool { get(root); return mv.Report != nil && mv.Report.Status == "pass" })
	if mv.Report.Format != "Spring Boot Actuator" || len(mv.Report.Components) != 2 || mv.Health == nil || mv.Health.Mode != "auto" {
		t.Errorf("report = %+v, health = %+v", mv.Report, mv.Health)
	}

	// Down in the body, 200 on the wire: an incident naming the component.
	e.respond(200, `{"status":"DOWN","components":{"db":{"status":"DOWN"},"redis":{"status":"UP"}}}`)
	var incs []incident
	eventually(t, "an incident", func() bool { anon.mustDo("GET", path+"/incidents", nil, 200, &incs); return len(incs) > 0 })
	if incs[0].Code != store.CodeUnhealthy || incs[0].Cause != "Health check failed: db" {
		t.Errorf("incident = %+v", incs[0])
	}

	// Degraded resolves the incident but is counted.
	e.respond(200, `{"status":"Degraded","entries":{"db":{"status":"Degraded"}},"totalDuration":"00:00:00.01"}`)
	eventually(t, "the incident to resolve", func() bool {
		anon.mustDo("GET", path+"/incidents", nil, 200, &incs)
		return incs[0].Ended != nil
	})
	eventually(t, "a degraded check in the rollup", func() bool { get(root); return len(mv.Days) > 0 && mv.Days[len(mv.Days)-1].Warn > 0 })

	// The public sees the status but not versions, instances or components.
	e.respond(200, `{"status":"ok","version":"1.0","hostname":"web-1","uptime_seconds":100,"checks":{"db":"ok"}}`)
	eventually(t, "a version", func() bool { get(root); return mv.Report.Version == "1.0" && mv.Report.Started > 0 })
	if mv.Report.Instance != "web-1" {
		t.Errorf("report = %+v", mv.Report)
	}
	get(anon)
	if mv.Report == nil || mv.Report.Status != "pass" || mv.Report.Version != "" || mv.Report.Instance != "" ||
		mv.Report.Format != "" || mv.Report.Components != nil || mv.Health != nil {
		t.Errorf("public report = %+v, health = %+v", mv.Report, mv.Health)
	}

	// A deploy is an event; anonymous callers get only its time and kind.
	e.respond(200, `{"status":"ok","version":"1.1","hostname":"web-1","uptime_seconds":100}`)
	type event struct {
		T                        int64
		Kind, Instance, From, To string
	}
	var evs []event
	eventually(t, "a deploy", func() bool {
		root.mustDo("GET", path+"/events", nil, 200, &evs)
		return slices.ContainsFunc(evs, func(e event) bool { return e.Kind == "deploy" })
	})
	i := slices.IndexFunc(evs, func(e event) bool { return e.Kind == "deploy" })
	if evs[i].From != "1.0" || evs[i].To != "1.1" {
		t.Errorf("deploy = %+v", evs[i])
	}
	evs = nil
	anon.mustDo("GET", path+"/events", nil, 200, &evs)
	for _, ev := range evs {
		if ev.From != "" || ev.To != "" || ev.Instance != "" {
			t.Errorf("public event = %+v", ev)
		}
	}

	// A body that stops being readable (a proxy's error page, say) leaves the
	// last report in place, older than the latest check, so it can be shown
	// as stale.
	var last struct {
		Last   struct{ T int64 }
		Report struct {
			T       int64
			Version string
		}
	}
	e.body.Store(ptr("<html>Bad gateway</html>"))
	eventually(t, "a check without a readable body", func() bool {
		root.mustDo("GET", path, nil, 200, &last)
		return last.Last.T > last.Report.T
	})
	if last.Report.Version != "1.1" {
		t.Errorf("stale report = %+v, want the last readable one", last.Report)
	}

	// Pointing the version at another field changes what is read, so the
	// old report is hidden and tracking starts over instead of logging the
	// new field's value as a deploy.
	root.mustDo("PUT", path, map[string]any{"name": "API", "url": e.target, "interval": 1, "public": true,
		"health": map[string]string{"mode": "auto", "version": "build"}}, 200, nil)
	get(root)
	if mv.Report != nil {
		t.Errorf("report after changing settings = %+v, want none until the next read", mv.Report)
	}
	e.respond(200, `{"status":"ok","version":"1.1","build":"b-77"}`)
	eventually(t, "a report with the new field", func() bool { get(root); return mv.Report != nil && mv.Report.Version == "b-77" })
	time.Sleep(2500 * time.Millisecond)
	evs = nil
	root.mustDo("GET", path+"/events", nil, 200, &evs)
	if n := len(slices.DeleteFunc(evs, func(e event) bool { return e.Kind != "deploy" })); n != 1 {
		t.Errorf("deploys after changing the version field = %d, want still 1", n)
	}

	// Turning it off ignores the body, so a failing one no longer counts, and
	// the old report is no longer shown.
	root.mustDo("PUT", path, map[string]any{"name": "API", "url": e.target, "interval": 1, "public": true, "health": map[string]string{"mode": "off"}}, 200, nil)
	e.respond(200, `{"status":"down"}`)
	time.Sleep(2500 * time.Millisecond)
	var cs []struct {
		Code   int
		Health string
	}
	anon.mustDo("GET", path+"/checks?from="+fmt.Sprint(time.Now().Unix()-1), nil, 200, &cs)
	for _, c := range cs {
		if c.Code != 200 || c.Health != "" {
			t.Errorf("check with health off = %+v", c)
		}
	}
	if get(root); mv.Report != nil {
		t.Errorf("report with health off = %+v", mv.Report)
	}
	root.mustDo("PUT", path, map[string]any{"name": "API", "url": e.target, "interval": 1, "health": map[string]string{"mode": "sometimes"}}, 400, nil)
}

func ptr(s string) *string { return &s }
