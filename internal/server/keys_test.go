package server_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type apiKey struct {
	ID          int64
	Name        string
	Prefix      string
	Owner       string
	AllMonitors bool `json:"all_monitors"`
	Monitors    []int64
	TTLDays     int `json:"ttl_days"`
	Expires     *int64
	Created     int64
	LastUsed    *int64 `json:"last_used"`
	Key         string
}

var keyFormat = regexp.MustCompile(`^blip_[0-9a-hjkmnp-tv-z]{8}_[0-9a-hjkmnp-tv-z]{24}$`)

// bearer sends a request with an API key and no cookies.
func (e *env) bearer(key, path string, out any) (int, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.url+path, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if out != nil && res.StatusCode == 200 {
		if err := json.Unmarshal(data, out); err != nil {
			e.t.Fatalf("GET %s: decode %q: %v", path, data, err)
		}
	}
	return res.StatusCode, res.Header
}

func (e *env) mustBearer(key, path string, want int, out any) {
	e.t.Helper()
	if got, _ := e.bearer(key, path, out); got != want {
		e.t.Fatalf("GET %s with key = %d, want %d", path, got, want)
	}
}

func names(ms []monitorView) (out []string) {
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func TestAPIKeys(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var pub, priv monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "Public", "url": e.target, "interval": 3600, "public": true}, 201, &pub)
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "Private", "url": e.target + "/internal", "interval": 3600, "public": false}, 201, &priv)

	var all apiKey
	root.mustDo("POST", "/api/keys", map[string]any{"name": "Grafana", "ttl_days": 30, "all_monitors": true}, 201, &all)
	if !keyFormat.MatchString(all.Key) || !strings.HasPrefix(all.Key, all.Prefix+"_") {
		t.Fatalf("key %q (prefix %q) is not blip_<id>_<secret>", all.Key, all.Prefix)
	}
	if all.Expires == nil || *all.Expires-all.Created < 30*86400-5 || all.LastUsed != nil || all.Owner != "root@example.com" {
		t.Errorf("new key = %+v, want a 30-day expiry, no use yet and root as owner", all)
	}

	// An all-monitors key sees private monitors and their targets.
	var list []monitorView
	e.mustBearer(all.Key, "/api/monitors", 200, &list)
	if got := names(list); !slices.Equal(got, []string{"Private", "Public"}) {
		t.Fatalf("all-monitors key sees %v", got)
	}
	if list[0].URL == "" {
		t.Error("key doesn't see the monitor's URL")
	}
	e.mustBearer(all.Key, fmt.Sprintf("/api/monitors/%d/checks", priv.ID), 200, nil)
	// Keys are case-insensitive, since Crockford base32 is.
	e.mustBearer(strings.ToUpper(all.Key), "/api/monitors", 200, nil)

	// The secret is never listed again; use shows up as last_used.
	var keys []apiKey
	root.mustDo("GET", "/api/keys", nil, 200, &keys)
	if len(keys) != 1 || keys[0].Key != "" || keys[0].LastUsed == nil || keys[0].Prefix != all.Prefix {
		t.Fatalf("listed keys = %+v, want one used key without its secret", keys)
	}

	// A scoped key sees only its monitors; others look missing.
	var scoped apiKey
	root.mustDo("POST", "/api/keys", map[string]any{"name": "Vendor", "ttl_days": 0, "monitors": []int64{pub.ID, pub.ID}}, 201, &scoped)
	if scoped.Expires != nil || scoped.AllMonitors || !slices.Equal(scoped.Monitors, []int64{pub.ID}) {
		t.Errorf("scoped key = %+v, want no expiry and only the public monitor", scoped)
	}
	e.mustBearer(scoped.Key, "/api/monitors", 200, &list)
	if got := names(list); !slices.Equal(got, []string{"Public"}) || list[0].URL == "" {
		t.Errorf("scoped key sees %+v", list)
	}
	for _, p := range []string{"", "/checks", "/hours", "/incidents"} {
		e.mustBearer(scoped.Key, fmt.Sprintf("/api/monitors/%d%s", priv.ID, p), 404, nil)
	}

	// Bad keys are refused outright, never served as anonymous.
	for _, bad := range []string{"nope", "blip_00000000_000000000000000000000000", all.Key[:len(all.Key)-1]} {
		code, h := e.bearer(bad, "/api/monitors", nil)
		if code != 401 || !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("key %q = %d %q, want 401 with a Bearer challenge", bad, code, h.Get("WWW-Authenticate"))
		}
	}
	req, _ := http.NewRequest("GET", e.url+"/api/monitors", nil)
	req.Header.Set("Authorization", "Basic "+all.Key)
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 401 {
		t.Errorf("non-bearer scheme = %d, want 401", res.StatusCode)
	}

	// Keys are read-only and can't reach the panel's endpoints.
	for _, p := range []string{"/api/keys", "/api/users", "/api/db"} {
		e.mustBearer(all.Key, p, 401, nil)
	}
	req, _ = http.NewRequest("POST", e.url+"/api/monitors", strings.NewReader(`{"name":"x","url":"http://a.b","interval":60}`))
	req.Header.Set("Authorization", "Bearer "+all.Key)
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 401 {
		t.Errorf("POST with a key = %d, want 401", res.StatusCode)
	}

	// Rotation swaps the secret and prefix and resets last_used.
	var rot apiKey
	root.mustDo("POST", fmt.Sprintf("/api/keys/%d/rotate", all.ID), nil, 200, &rot)
	if rot.ID != all.ID || rot.Key == all.Key || rot.Prefix == all.Prefix || rot.LastUsed != nil || !keyFormat.MatchString(rot.Key) {
		t.Errorf("rotated = %+v, want the same key with a new secret", rot)
	}
	e.mustBearer(all.Key, "/api/monitors", 401, nil)
	e.mustBearer(rot.Key, "/api/monitors", 200, nil)

	// Expired keys are refused.
	raw, err := sql.Open("sqlite", "file:"+e.dbPath+"?_pragma=busy_timeout(5000)") // wait out the checker's writes
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("UPDATE api_keys SET exp=1 WHERE id=?", rot.ID); err != nil {
		t.Fatal(err)
	}
	e.mustBearer(rot.Key, "/api/monitors", 401, nil)
	// Rotating an expired key renews it.
	root.mustDo("POST", fmt.Sprintf("/api/keys/%d/rotate", all.ID), nil, 200, &rot)
	e.mustBearer(rot.Key, "/api/monitors", 200, nil)

	// Revocation.
	root.mustDo("DELETE", fmt.Sprintf("/api/keys/%d", all.ID), nil, 204, nil)
	e.mustBearer(rot.Key, "/api/monitors", 401, nil)
	root.mustDo("DELETE", fmt.Sprintf("/api/keys/%d", all.ID), nil, 404, nil)

	// Deleting a monitor drops it from scoped keys.
	root.mustDo("DELETE", fmt.Sprintf("/api/monitors/%d", pub.ID), nil, 204, nil)
	root.mustDo("GET", "/api/keys", nil, 200, &keys)
	if len(keys) != 1 || len(keys[0].Monitors) != 0 {
		t.Errorf("keys after monitor delete = %+v", keys)
	}
	e.mustBearer(scoped.Key, "/api/monitors", 200, &list)
	if len(list) != 0 {
		t.Errorf("key whose monitors are gone sees %v", names(list))
	}
}

func TestAPIKeyValidation(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	var m monitorView
	root.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "url": e.target, "interval": 3600}, 201, &m)
	for _, body := range []map[string]any{
		{"name": "", "all_monitors": true},
		{"name": strings.Repeat("x", 101), "all_monitors": true},
		{"name": "x", "ttl_days": -1, "all_monitors": true},
		{"name": "x", "ttl_days": 3651, "all_monitors": true},
		{"name": "x"},
		{"name": "x", "monitors": []int64{}},
		{"name": "x", "all_monitors": true, "monitors": []int64{m.ID}},
		{"name": "x", "monitors": []int64{m.ID, 99999}},
		{"name": "x", "all_monitors": true, "secret": "mine"},
	} {
		if got := root.do("POST", "/api/keys", body, nil); got != 400 {
			t.Errorf("POST /api/keys %v = %d, want 400", body, got)
		}
	}
	e.anon().mustDo("POST", "/api/keys", map[string]any{"name": "x", "all_monitors": true}, 401, nil)
}

// Users manage their own keys; root manages everyone's. Keys go with their owner.
func TestAPIKeyOwnership(t *testing.T) {
	e := setup(t)
	root := e.root("root@example.com")
	reader := enrollUser(t, root, "reader@example.com", "read")

	var rk, mine apiKey
	root.mustDo("POST", "/api/keys", map[string]any{"name": "Root's", "all_monitors": true}, 201, &rk)
	reader.mustDo("POST", "/api/keys", map[string]any{"name": "Reader's", "ttl_days": 7, "all_monitors": true}, 201, &mine)

	var keys []apiKey
	reader.mustDo("GET", "/api/keys", nil, 200, &keys)
	if len(keys) != 1 || keys[0].ID != mine.ID {
		t.Errorf("reader lists %+v, want only their own key", keys)
	}
	reader.mustDo("POST", fmt.Sprintf("/api/keys/%d/rotate", rk.ID), nil, 404, nil)
	reader.mustDo("DELETE", fmt.Sprintf("/api/keys/%d", rk.ID), nil, 404, nil)

	root.mustDo("GET", "/api/keys", nil, 200, &keys)
	if len(keys) != 2 || keys[0].Owner != "reader@example.com" {
		t.Errorf("root lists %+v, want both keys, newest first", keys)
	}

	var users []user
	root.mustDo("GET", "/api/users", nil, 200, &users)
	for _, u := range users {
		if u.Email == "reader@example.com" {
			root.mustDo("DELETE", fmt.Sprintf("/api/users/%d", u.ID), nil, 204, nil)
		}
	}
	e.mustBearer(mine.Key, "/api/monitors", 401, nil)
	root.mustDo("GET", "/api/keys", nil, 200, &keys)
	if len(keys) != 1 {
		t.Errorf("keys after deleting their owner = %+v", keys)
	}
}

// TestSpecConformance calls every documented endpoint with an API key and
// checks the live response against openapi.json, so the reference can't
// drift from what the server sends.
func TestSpecConformance(t *testing.T) {
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}

	e := setup(t)
	root := e.root("root@example.com")
	writer := enrollUser(t, root, "writer@example.com", "write")
	var m monitorView
	writer.mustDo("POST", "/api/monitors", map[string]any{"name": "API", "url": e.target, "interval": 1, "public": false}, 201, &m)
	var k apiKey
	root.mustDo("POST", "/api/keys", map[string]any{"name": "Spec", "all_monitors": true}, 201, &k)

	// A health body and a deploy, so the report and event schemas have data.
	path := fmt.Sprintf("/api/monitors/%d", m.ID)
	healthBody := func(v string) string {
		return `{"status":"pass","version":"` + v + `","hostname":"web-1","started_at":"2026-01-02T03:04:05Z",` +
			`"message":"fine","checks":{"db":{"status":"warn","output":"slow"}}}`
	}
	e.respond(200, healthBody("1.0"))
	var evs []any
	eventually(t, "a report", func() bool {
		var mv struct{ Report *struct{ Version string } }
		root.mustDo("GET", path, nil, 200, &mv)
		return mv.Report != nil && mv.Report.Version == "1.0"
	})
	e.respond(200, healthBody("2.0"))
	eventually(t, "a deploy event", func() bool { root.mustDo("GET", path+"/events", nil, 200, &evs); return len(evs) > 0 })

	// An incident with a note, so every schema has data to check.
	e.status.Store(503)
	var incs []incident
	eventually(t, "an incident", func() bool { root.mustDo("GET", path+"/incidents", nil, 200, &incs); return len(incs) > 0 })
	writer.mustDo("POST", fmt.Sprintf("/api/incidents/%d/notes", incs[0].ID), map[string]string{"body": "on it"}, 201, nil)
	e.status.Store(200)
	eventually(t, "the incident to resolve", func() bool {
		root.mustDo("GET", path+"/incidents", nil, 200, &incs)
		return incs[0].Ended != nil
	})

	resolve := func(node map[string]any) map[string]any {
		for {
			ref, ok := node["$ref"].(string)
			if !ok {
				return node
			}
			cur := any(spec)
			for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
				cur = cur.(map[string]any)[part]
			}
			node = cur.(map[string]any)
		}
	}
	var check func(at string, s map[string]any, v any)
	check = func(at string, s map[string]any, v any) {
		s = resolve(s)
		if alts, ok := s["oneOf"].([]any); ok {
			for _, a := range alts {
				if matches(resolve(a.(map[string]any)), v) {
					check(at, a.(map[string]any), v)
					return
				}
			}
			t.Errorf("%s: %v matches no oneOf branch", at, v)
			return
		}
		if !matches(s, v) {
			t.Errorf("%s: %v doesn't match type %v", at, v, s["type"])
			return
		}
		switch v := v.(type) {
		case map[string]any:
			props, _ := s["properties"].(map[string]any)
			for _, r := range s["required"].([]any) {
				if _, ok := v[r.(string)]; !ok {
					t.Errorf("%s: missing required %q", at, r)
				}
			}
			for name, val := range v {
				ps, ok := props[name]
				if !ok {
					t.Errorf("%s: undocumented field %q", at, name)
					continue
				}
				check(at+"."+name, ps.(map[string]any), val)
			}
		case []any:
			if len(v) == 0 {
				t.Errorf("%s: empty array, so its items went unchecked", at)
			}
			for i, item := range v {
				check(fmt.Sprintf("%s[%d]", at, i), s["items"].(map[string]any), item)
			}
		}
	}

	for _, p := range []string{"", "/hours", "/checks", "/incidents", "/events"} {
		docPath := "/api/monitors/{id}" + p
		var body any
		e.mustBearer(k.Key, path+p, 200, &body)
		check(docPath, responseSchema(spec, docPath), body)
	}
	var body any
	e.mustBearer(k.Key, "/api/monitors", 200, &body)
	check("/api/monitors", responseSchema(spec, "/api/monitors"), body)
	// Signed-in sessions see note authors, which the schema also allows.
	root.mustDo("GET", path+"/incidents", nil, 200, &body)
	check("/api/monitors/{id}/incidents (session)", responseSchema(spec, "/api/monitors/{id}/incidents"), body)
}

func responseSchema(spec map[string]any, path string) map[string]any {
	op := spec["paths"].(map[string]any)[path].(map[string]any)["get"].(map[string]any)
	ok := op["responses"].(map[string]any)["200"].(map[string]any)
	return ok["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
}

// matches checks v against s's own type and enum (not its children).
func matches(s map[string]any, v any) bool {
	var ts []string
	switch t := s["type"].(type) {
	case string:
		ts = []string{t}
	case []any:
		for _, x := range t {
			ts = append(ts, x.(string))
		}
	}
	if enum, ok := s["enum"].([]any); ok && !slices.Contains(enum, v) {
		return false
	}
	for _, t := range ts {
		switch v := v.(type) {
		case nil:
			if t == "null" {
				return true
			}
		case bool:
			if t == "boolean" {
				return true
			}
		case float64:
			if t == "number" || t == "integer" && v == float64(int64(v)) {
				return true
			}
		case string:
			if t == "string" {
				return true
			}
		case []any:
			if t == "array" {
				return true
			}
		case map[string]any:
			if t == "object" {
				return true
			}
		}
	}
	return len(ts) == 0
}
