package health

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestParseFormats(t *testing.T) {
	recent := time.Now().Add(-time.Hour).UTC()
	for _, tc := range []struct {
		name, ctype, body string
		want              Report
	}{
		{
			name:  "IETF draft",
			ctype: "application/health+json",
			body: `{"status":"warn","version":"1","releaseId":"1.2.2","serviceId":"api","output":"slow db",
				"checks":{"cassandra:responseTime":[{"componentType":"datastore","observedValue":250,"status":"warn","output":"250ms"}],
				"uptime":[{"componentType":"system","observedValue":1209600.245,"observedUnit":"s","status":"pass"}]}}`,
			want: Report{Format: "IETF health+json", Status: Warn, Version: "1.2.2", Message: "slow db", HasUptime: true,
				Uptime: 1209600.245, UptimeUnit: 1, Components: []Component{{"cassandra:responseTime", Warn, "250ms"}}},
		},
		{
			name: "Spring Boot Actuator",
			body: `{"status":"DOWN","components":{"db":{"status":"DOWN","details":{"error":"timeout"}},"diskSpace":{"status":"UP"},"ping":{"status":"UP"}}}`,
			want: Report{Format: "Spring Boot Actuator", Status: Fail,
				Components: []Component{{"db", Fail, ""}, {"diskSpace", Pass, ""}, {"ping", Pass, ""}}},
		},
		{
			name: "Spring Boot 2.0 details",
			body: `{"status":"OUT_OF_SERVICE","details":{"redis":{"status":"OUT_OF_SERVICE"}}}`,
			want: Report{Format: "Spring Boot Actuator", Status: Fail, Components: []Component{{"redis", Fail, ""}}},
		},
		{
			name: "MicroProfile Health",
			body: `{"status":"UP","checks":[{"name":"database","status":"UP","data":{}},{"name":"queue","status":"UP"}]}`,
			want: Report{Format: "MicroProfile Health", Status: Pass, Components: []Component{{"database", Pass, ""}, {"queue", Pass, ""}}},
		},
		{
			name: "ASP.NET Core",
			body: `{"status":"Degraded","totalDuration":"00:00:00.0140","entries":{"sql":{"data":{},"description":"Slow","duration":"00:00:00.01","status":"Degraded"}}}`,
			want: Report{Format: "ASP.NET Core", Status: Warn, Components: []Component{{"sql", Warn, "Slow"}}},
		},
		{
			name: "Statuspage",
			body: `{"page":{"id":"x"},"status":{"indicator":"minor","description":"Partial System Outage"},
				"components":[{"name":"API","status":"operational"},{"name":"Webhooks","status":"partial_outage"}]}`,
			want: Report{Format: "Statuspage", Status: Warn, Message: "Partial System Outage",
				Components: []Component{{"API", Pass, ""}, {"Webhooks", Warn, ""}}},
		},
		{
			name: "Elasticsearch",
			body: `{"cluster_name":"logs","status":"yellow","number_of_nodes":3}`,
			want: Report{Format: "Elasticsearch", Status: Warn},
		},
		{
			name: "generic JSON",
			body: `{"status":"ok","version":"v2.4.1","commit":"9f2c1e7a3b4d5c6e","hostname":"web-3","uptime_ms":3600000,
				"dependencies":{"postgres":"ok","redis":{"healthy":false,"error":"connection refused"}}}`,
			want: Report{Format: "JSON", Status: Pass, Version: "v2.4.1", Commit: "9f2c1e7", Instance: "web-3",
				HasUptime: true, Uptime: 3600000, UptimeUnit: 1000,
				Components: []Component{{"postgres", Pass, ""}, {"redis", Fail, "connection refused"}}},
		},
		{
			name: "nested build info and start time",
			body: `{"healthy":true,"build":{"version":"3.1.0"},"git":{"commit":{"id":"abcdef1234567890"}},"started_at":"` + recent.Format(time.RFC3339) + `"}`,
			want: Report{Format: "JSON", Status: Pass, Version: "3.1.0", Commit: "abcdef1", Started: recent.Unix()},
		},
		{
			name: "draft-like status with object checks",
			body: `{"status":"pass","checks":{"db":{"status":"warn","output":"slow"}}}`,
			want: Report{Format: "JSON", Status: Pass, Components: []Component{{"db", Warn, "slow"}}},
		},
		{
			name: "status from components only",
			body: `{"checks":{"db":"up","cache":"degraded"}}`,
			want: Report{Format: "JSON", Status: Warn, Components: []Component{{"cache", Warn, ""}, {"db", Pass, ""}}},
		},
		{
			name: "duration string uptime",
			body: `{"ok":true,"uptime":"72h3m0.5s"}`,
			want: Report{Format: "JSON", Status: Pass, HasUptime: true, Uptime: 72*3600 + 180.5, UptimeUnit: 1},
		},
		{
			name: "unit-less integer uptime",
			body: `{"status":"pass","uptime":12345}`,
			want: Report{Format: "JSON", Status: Pass, HasUptime: true, Uptime: 12345},
		},
		{
			name: "fractional uptime is seconds",
			body: `{"uptime":12.5}`,
			want: Report{Format: "JSON", HasUptime: true, Uptime: 12.5, UptimeUnit: 1},
		},
		{
			name: "maintenance",
			body: `{"status":"maintenance","message":"Upgrading database"}`,
			want: Report{Format: "JSON", Status: Maintenance, Message: "Upgrading database"},
		},
		{name: "plain text", body: "Degraded", want: Report{Format: "Text", Status: Warn}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Parse(tc.ctype, []byte(tc.body), Config{})
			if !ok {
				t.Fatal("not recognised")
			}
			if !equal(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func equal(a, b Report) bool { return reflect.DeepEqual(a, b) }

func TestParseIgnores(t *testing.T) {
	for _, body := range []string{
		"", "<html><body>OK</body></html>", "not json at all, a longer sentence here", `[1,2,3]`,
		`{"name":"widget","count":3}`, `{"status":"draft"}`, `{broken`,
	} {
		if r, ok := Parse("application/json", []byte(body), Config{}); ok {
			t.Errorf("Parse(%q) = %+v, want nothing", body, r)
		}
	}
	if _, ok := Parse("", []byte(`{"status":"down"}`), Config{Mode: "off"}); ok {
		t.Error("mode off still parsed")
	}
}

func TestCustomPaths(t *testing.T) {
	body := `{"status":"ok","meta":{"state":"RED","rel":"7.0"},"nodes":[{"name":"n1","boot":1700000000}]}`
	got, _ := Parse("", []byte(body), Config{Status: "meta.state", Version: "$.meta.rel", Started: "nodes[0].boot", Instance: "nodes.0.name"})
	want := Report{Format: "JSON + custom fields", Status: Fail, Version: "7.0", Started: 1700000000, Instance: "n1"}
	if !equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	// A configured path that matches nothing replaces detection rather than
	// falling back to it.
	got, _ = Parse("", []byte(`{"status":"down"}`), Config{Status: "missing"})
	if got.Status != Unknown {
		t.Errorf("status = %v, want unknown", got.Status)
	}
}

func TestDuration(t *testing.T) {
	for in, want := range map[string]float64{
		"PT1H30M": 5400, "P2DT3S": 172803, "1.02:03:04": 93784, "02:03:04.5": 7384.5,
		"3 days, 4:05:06": 273906, "3d4h": 273600, "2d": 172800, "1h2m3s": 3723, "5 days 2 hours": 439200,
	} {
		if got, ok := duration(in); !ok || got != want {
			t.Errorf("duration(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
}

func TestTimestamp(t *testing.T) {
	base := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	for _, v := range []any{base.Format(time.RFC3339), base.UTC().Format("2006-01-02 15:04:05")} {
		if got := timestamp(v); got != base.Unix() {
			t.Errorf("timestamp(%v) = %d, want %d", v, got, base.Unix())
		}
	}
	for _, mult := range []int64{1, 1e3, 1e6, 1e9} {
		n := base.Unix() * mult
		if got := timestamp(jsonNum(n)); got != base.Unix() {
			t.Errorf("timestamp(%d) = %d", n, got)
		}
	}
	if timestamp(jsonNum(12345)) != 0 || timestamp(jsonNum(time.Now().Add(72*time.Hour).Unix())) != 0 {
		t.Error("implausible times accepted")
	}
}

func TestTrackerDeploysAndRestarts(t *testing.T) {
	tr := NewTracker(nil)
	t0 := time.Unix(1_800_000_000, 0)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * 30 * time.Second) }
	obs := func(i int, r Report) []Event {
		_, ev, _ := tr.Observe(at(i), 50*time.Millisecond, r)
		return ev
	}
	start := t0.Unix() - 86400
	if ev := obs(0, Report{Version: "1.0", Started: start}); ev != nil {
		t.Fatalf("baseline produced events: %v", ev)
	}
	// Mid-rollout flapping between versions is not a deploy...
	obs(1, Report{Version: "1.1", Started: start})
	if ev := obs(2, Report{Version: "1.0", Started: start}); ev != nil {
		t.Fatalf("flap produced events: %v", ev)
	}
	// ...two in a row is.
	obs(3, Report{Version: "1.1", Started: start})
	ev := obs(4, Report{Version: "1.1", Started: at(4).Unix() - 5})
	want := []Event{
		{T: at(3).Unix(), Kind: "deploy", From: "1.0", To: "1.1"},
		{T: at(4).Unix() - 5, Kind: "restart"},
	}
	if !slices.Equal(ev, want) {
		t.Fatalf("events = %v, want %v", ev, want)
	}

	// Saved state survives a blip restart without re-reporting anything.
	_, _, saved := tr.Observe(at(5), 0, Report{Version: "1.1", Started: at(4).Unix() - 5})
	tr = NewTracker(saved)
	if ev := obs(6, Report{Version: "1.1", Started: at(4).Unix() - 5}); ev != nil {
		t.Fatalf("resumed tracker produced events: %v", ev)
	}
}

func TestTrackerLoadBalancer(t *testing.T) {
	tr := NewTracker(nil)
	t0 := time.Unix(1_800_000_000, 0)
	a, b := t0.Unix()-7200, t0.Unix()-3600
	// Two long-running instances without IDs, alternating: no restarts.
	for i := range 6 {
		started := a
		if i%2 == 1 {
			started = b
		}
		up := float64(t0.Unix() + int64(i*30) - started)
		if _, ev, _ := tr.Observe(t0.Add(time.Duration(i)*30*time.Second), 0, Report{HasUptime: true, Uptime: up, UptimeUnit: 1}); ev != nil {
			t.Fatalf("check %d: %v", i, ev)
		}
	}
	// A named instance appearing after the baseline is a start; the same
	// name with a later start time is a restart.
	later := t0.Add(10 * time.Minute)
	tr.Observe(later, 0, Report{Instance: "pod-a", Started: a})
	_, ev, _ := tr.Observe(later.Add(30*time.Second), 0, Report{Instance: "pod-b", Started: later.Unix() + 10})
	if len(ev) != 1 || ev[0].Kind != "start" || ev[0].Instance != "pod-b" {
		t.Fatalf("new instance: %v", ev)
	}
	_, ev, _ = tr.Observe(later.Add(60*time.Second), 0, Report{Instance: "pod-a", Started: later.Unix() + 50})
	if len(ev) != 1 || ev[0].Kind != "restart" || ev[0].Instance != "pod-a" {
		t.Fatalf("restarted instance: %v", ev)
	}
}

func TestTrackerLearnsUptimeUnit(t *testing.T) {
	tr := NewTracker(nil)
	t0 := time.Unix(1_800_000_000, 0)
	ms := 5_000_000.0 // milliseconds, but the field is just "uptime"
	if s, _, _ := tr.Observe(t0, 0, Report{HasUptime: true, Uptime: ms}); s != 0 {
		t.Fatalf("start known before the unit: %d", s)
	}
	s, _, _ := tr.Observe(t0.Add(30*time.Second), 0, Report{HasUptime: true, Uptime: ms + 30_000})
	if want := t0.Unix() - 5000; s != want {
		t.Fatalf("started = %d, want %d", s, want)
	}
}

func jsonNum(n int64) any { return json.Number(strconv.FormatInt(n, 10)) }

// Payloads change shape between checks: fields come and go, and a deploy can
// change the uptime's unit. None of that alone is a deploy or a restart.
func TestTrackerChangingPayload(t *testing.T) {
	tr := NewTracker(nil)
	t0 := time.Unix(1_800_000_000, 0)
	start := t0.Unix() - 86400
	i := 0
	obs := func(r Report) (int64, []Event) {
		i++
		s, ev, _ := tr.Observe(t0.Add(time.Duration(i)*30*time.Second), 0, r)
		return s, ev
	}
	upAt := func() float64 { return float64(t0.Unix() + int64(i+1)*30 - start) }
	steps := []Report{
		{Version: "1.0", Instance: "web-1", Started: start}, // baseline
		{},               // a body with nothing we track
		{Started: start}, // the version and instance vanish
		{Version: "1.0"}, // the version returns unchanged
		{Version: "1.0", Commit: ""},
		{Instance: "web-1", Started: start},
		{Version: "1.0", HasUptime: true, Uptime: upAt(), UptimeUnit: 1}, // start time now from uptime
	}
	for n, r := range steps {
		if r.HasUptime {
			r.Uptime = upAt()
		}
		if _, ev := obs(r); ev != nil {
			t.Fatalf("step %d (%+v): unexpected events %v", n, r, ev)
		}
	}

	// A unit-less uptime the tracker learned as seconds suddenly arrives in
	// nanoseconds: the implausible start is dropped, not logged as a restart.
	tr = NewTracker(nil)
	i = 0
	for range 3 {
		if _, ev := obs(Report{HasUptime: true, Uptime: upAt()}); ev != nil {
			t.Fatalf("seconds: %v", ev)
		}
	}
	s, ev := obs(Report{HasUptime: true, Uptime: upAt() * 1e9})
	if s != 0 || ev != nil {
		t.Fatalf("after the unit changed: started %d, events %v", s, ev)
	}
	// Once the unit is relearned the start time is right again, and the same
	// process is recognised.
	s, ev = obs(Report{HasUptime: true, Uptime: upAt() * 1e9})
	if s != start || ev != nil {
		t.Fatalf("relearned: started %d (want %d), events %v", s, start, ev)
	}
}
