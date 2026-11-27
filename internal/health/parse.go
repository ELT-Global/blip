package health

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxComponents = 50
	maxName       = 100
	maxText       = 300
)

// words maps status words, normalised to lower snake case, to a Status.
var words = map[string]Status{}

func init() {
	for s, list := range map[Status]string{
		Pass: "ok okay pass passed passing up healthy green success successful good online available running " +
			"operational alive ready serving true fine normal",
		Warn: "warn warning warnings degraded degraded_performance yellow partial partial_outage minor impaired " +
			"unstable slow at_risk",
		Fail: "fail failed failing failure down unhealthy red error err critical crit unavailable offline " +
			"out_of_service major_outage major dead false not_ready not_serving ko bad outage",
		Maintenance: "maintenance under_maintenance in_maintenance maint draining",
	} {
		for _, w := range strings.Fields(list) {
			words[w] = s
		}
	}
}

func word(s string) Status {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "_", "-", "_").Replace(s)
	return words[s]
}

// Parse reads a health body. ok is false when the body says nothing about
// health that blip understands, so callers can tell "no information" from a
// report. contentType is the response's Content-Type header.
func Parse(contentType string, body []byte, cfg Config) (r Report, ok bool) {
	b := bytes.TrimSpace(body)
	if len(b) == 0 || cfg.Off() {
		return r, false
	}
	if b[0] != '{' {
		return parseText(b)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root map[string]any
	if dec.Decode(&root) != nil {
		return r, false
	}
	detect(&r, contentType, root)
	generic(&r, root)
	custom(&r, root, cfg)
	if r.Status == Unknown {
		for _, c := range r.Components {
			r.Status = worse(r.Status, c.Status)
		}
	}
	ok = r.Status != Unknown || r.Version != "" || r.Commit != "" || r.Started != 0 || r.HasUptime ||
		r.Instance != "" || len(r.Components) > 0
	return r, ok
}

// parseText understands a body that is a single status word, such as the
// "Healthy" or "Degraded" that ASP.NET Core writes by default.
func parseText(b []byte) (Report, bool) {
	if len(b) > 40 || bytes.ContainsAny(b, "<\n") {
		return Report{}, false
	}
	s := word(string(b))
	return Report{Format: "Text", Status: s}, s != Unknown
}

// detect recognises well-known formats and reads what is specific to them.
func detect(r *Report, contentType string, root map[string]any) {
	status, _ := root["status"].(string)
	checksMap, _ := root["checks"].(map[string]any)
	checksList, _ := root["checks"].([]any)
	switch {
	case strings.Contains(contentType, "health+json") ||
		(slices.Contains([]string{"pass", "warn", "fail"}, status) && (isListMap(checksMap) || root["releaseId"] != nil || root["serviceId"] != nil)):
		r.Format = "IETF health+json"
		r.Status = word(status)
		// version is the API's major version; releaseId names the release.
		r.Version = str(root["releaseId"])
		if r.Version == "" {
			r.Version = str(root["version"])
		}
		r.Message = text(root["output"])
		for _, k := range sortedKeys(checksMap) {
			list, _ := checksMap[k].([]any)
			c := Component{Name: clip(k, maxName)}
			for _, e := range list {
				o, _ := e.(map[string]any)
				if o == nil {
					continue
				}
				if k == "uptime" || strings.HasSuffix(k, ":uptime") {
					if v, ok := num(o["observedValue"]); ok {
						r.HasUptime, r.Uptime, r.UptimeUnit = true, v, unitPerSecond(str(o["observedUnit"]))
					}
					c.Name = ""
					break
				}
				c.Status = worse(c.Status, word(str(o["status"])))
				if c.Output == "" {
					c.Output = text(o["output"])
				}
			}
			if c.Name != "" && c.Status != Unknown {
				addComponent(r, c)
			}
		}
	case isUpper(status) && (isObjMap(root["components"]) || isObjMap(root["details"])):
		r.Format = "Spring Boot Actuator"
		r.Status = word(status)
		comps := root["components"]
		if comps == nil {
			comps = root["details"] // Spring Boot 1.x and 2.0
		}
		objComponents(r, comps.(map[string]any))
	case isUpper(status) && checksList != nil:
		r.Format = "MicroProfile Health"
		r.Status = word(status)
		listComponents(r, checksList)
	case slices.Contains([]string{"Healthy", "Degraded", "Unhealthy"}, status) && (root["entries"] != nil || root["totalDuration"] != nil):
		r.Format = "ASP.NET Core"
		r.Status = word(status)
		if m, ok := root["entries"].(map[string]any); ok {
			objComponents(r, m)
		}
	case isStatuspage(root):
		r.Format = "Statuspage"
		st := root["status"].(map[string]any)
		ind := str(st["indicator"])
		if ind == "none" {
			r.Status = Pass
		} else {
			r.Status = word(ind)
		}
		r.Message = text(st["description"])
	case root["cluster_name"] != nil && slices.Contains([]string{"green", "yellow", "red"}, status):
		r.Format = "Elasticsearch"
		r.Status = word(status)
	default:
		r.Format = "JSON"
	}
}

func isStatuspage(root map[string]any) bool {
	st, ok := root["status"].(map[string]any)
	return ok && st["indicator"] != nil
}

// isUpper matches the upper-case statuses Spring and MicroProfile use.
func isUpper(s string) bool {
	return s == "UNKNOWN" || (s != "" && s == strings.ToUpper(s) && word(s) != Unknown)
}

// isListMap matches the draft's checks: every value is a list.
func isListMap(m map[string]any) bool {
	for _, x := range m {
		if _, ok := x.([]any); !ok {
			return false
		}
	}
	return len(m) > 0
}

func isObjMap(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return false
	}
	for _, x := range m {
		if o, ok := x.(map[string]any); !ok || o["status"] == nil {
			return false
		}
	}
	return true
}

// Field names that commonly carry each fact, in order of preference. scopes
// are nested objects searched after the top level.
var (
	statusKeys  = []string{"status", "state", "health", "health_status", "healthStatus", "overall_status", "overallStatus", "overall", "healthy", "ok", "up", "alive", "success", "ready"}
	componentKs = []string{"checks", "components", "dependencies", "services", "entries", "details", "subsystems", "resources", "indicators"}
	versionKeys = []string{"version", "app_version", "appVersion", "service_version", "serviceVersion", "build_version", "buildVersion", "releaseId", "release_id", "release", "tag"}
	commitKeys  = []string{"commit", "commit_sha", "commitSha", "commit_id", "commitId", "commit_hash", "commitHash", "sha", "git_sha", "gitSha", "git_commit", "gitCommit", "git_hash", "gitHash", "revision", "rev", "vcs_revision", "vcsRevision"}
	startKeys   = []string{"started_at", "startedAt", "start_time", "startTime", "started", "startup_time", "startupTime", "start_at", "boot_time", "bootTime", "booted_at", "bootedAt", "launched_at", "launchedAt", "up_since", "upSince", "running_since", "runningSince", "process_start_time", "processStartTime"}
	instKeys    = []string{"instance", "instance_id", "instanceId", "instance_name", "instanceName", "hostname", "host", "host_name", "hostName", "node", "node_id", "nodeId", "node_name", "nodeName", "pod", "pod_name", "podName", "server_id", "serverId", "server_name", "serverName", "machine", "machine_id", "machineId", "container", "container_id", "containerId", "replica", "replica_id", "dyno", "task_id", "taskId", "worker_id", "workerId"}
	msgKeys     = []string{"message", "msg", "output", "reason", "error", "detail"}
	infoScopes  = []string{"build", "app", "application", "info", "service", "server", "meta", "metadata", "release", "runtime", "process", "system", "git", "vcs", "data", "stats", "env", "kubernetes", "k8s"}
	// instance scopes are objects that describe the instance itself, so their
	// plain name or id field identifies it.
	instScopes = []string{"instance", "host", "node", "pod", "machine", "container"}
)

// uptimeKeys pairs uptime fields with their units per second; 0 is unknown.
var uptimeKeys = []struct {
	key  string
	unit float64
}{
	{"uptime", 0}, {"uptime_s", 1}, {"uptime_sec", 1}, {"uptime_secs", 1}, {"uptime_seconds", 1}, {"uptimeSec", 1},
	{"uptimeSecs", 1}, {"uptimeSeconds", 1}, {"uptimeInSeconds", 1}, {"uptime_in_seconds", 1},
	{"uptime_ms", 1e3}, {"uptimeMs", 1e3}, {"uptime_millis", 1e3}, {"uptimeMillis", 1e3}, {"uptimeInMillis", 1e3},
	{"uptime_milliseconds", 1e3}, {"uptimeMilliseconds", 1e3}, {"uptime_us", 1e6}, {"uptime_micros", 1e6},
	{"uptime_ns", 1e9}, {"uptimeNanos", 1e9}, {"uptime_nanoseconds", 1e9},
}

// generic fills in whatever detect left empty from familiar field names.
func generic(r *Report, root map[string]any) {
	if r.Status == Unknown && r.Format == "JSON" {
		for _, k := range statusKeys {
			if s := statusOf(root[k]); s != Unknown {
				r.Status = s
				break
			}
		}
	}
	if len(r.Components) == 0 {
		for _, k := range componentKs {
			switch v := root[k].(type) {
			case map[string]any:
				objComponents(r, v)
			case []any:
				listComponents(r, v)
			}
			if len(r.Components) > 0 {
				break
			}
		}
	}
	if r.Version == "" {
		r.Version = find(root, versionKeys, infoScopes)
	}
	if r.Commit == "" {
		r.Commit = shortCommit(findCommit(root))
	}
	if r.Started == 0 {
		for _, sc := range scopes(root, infoScopes) {
			for _, k := range startKeys {
				if t := timestamp(sc[k]); t != 0 {
					r.Started = t
					break
				}
			}
			if r.Started != 0 {
				break
			}
		}
	}
	if !r.HasUptime && r.Started == 0 {
	up:
		for _, sc := range scopes(root, infoScopes) {
			for _, u := range uptimeKeys {
				if v, unit, ok := uptime(sc[u.key], u.unit); ok {
					r.HasUptime, r.Uptime, r.UptimeUnit = true, v, unit
					break up
				}
			}
		}
	}
	if r.Instance == "" {
		r.Instance = find(root, instKeys, infoScopes)
	}
	if r.Instance == "" {
		for _, k := range instScopes {
			if m, ok := root[k].(map[string]any); ok {
				if r.Instance = find(m, []string{"hostname", "name", "id"}, nil); r.Instance != "" {
					break
				}
			}
		}
	}
	if r.Message == "" && r.Format == "JSON" {
		for _, k := range msgKeys {
			if r.Message = text(root[k]); r.Message != "" {
				break
			}
		}
	}
}

// custom applies a monitor's own field paths. A configured path replaces
// automatic detection for that field even when it finds nothing, since it
// was set because detection got it wrong.
func custom(r *Report, root map[string]any, cfg Config) {
	if cfg.Status != "" {
		r.Status = statusOf(lookup(root, cfg.Status))
	}
	if cfg.Version != "" {
		r.Version, r.Commit = str(lookup(root, cfg.Version)), ""
	}
	if cfg.Started != "" {
		r.Started = timestamp(lookup(root, cfg.Started))
		r.HasUptime = false
	}
	if cfg.Uptime != "" {
		r.Uptime, r.UptimeUnit, r.HasUptime = uptime(lookup(root, cfg.Uptime), 0)
		if r.HasUptime {
			r.Started = 0
		}
	}
	if cfg.Instance != "" {
		r.Instance = str(lookup(root, cfg.Instance))
	}
	if cfg.Status != "" || cfg.Version != "" || cfg.Started != "" || cfg.Uptime != "" || cfg.Instance != "" {
		r.Format += " + custom fields"
	}
}

// lookup follows a dotted path such as "a.b.0.c" or "a.b[0].c".
func lookup(v any, path string) any {
	path = strings.NewReplacer("[", ".", "]", "").Replace(strings.TrimPrefix(path, "$"))
	for _, p := range strings.Split(path, ".") {
		if p == "" {
			continue
		}
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(x) {
				return nil
			}
			v = x[i]
		default:
			return nil
		}
	}
	return v
}

// statusOf reads a status from a string, a boolean, or an object holding one.
func statusOf(v any) Status {
	switch x := v.(type) {
	case string:
		return word(x)
	case bool:
		if x {
			return Pass
		}
		return Fail
	case map[string]any:
		if ind, ok := x["indicator"].(string); ok && ind == "none" {
			return Pass
		}
		for _, k := range []string{"status", "indicator", "state", "health", "healthy", "ok", "up"} {
			if _, nested := x[k].(map[string]any); nested {
				continue // one level is enough; deeper objects are details
			}
			if s := statusOf(x[k]); s != Unknown {
				return s
			}
		}
	}
	return Unknown
}

// objComponents reads {"name": status-or-object, ...}.
func objComponents(r *Report, m map[string]any) {
	for _, k := range sortedKeys(m) {
		c := Component{Name: clip(k, maxName), Status: statusOf(m[k])}
		if c.Status == Unknown {
			continue
		}
		if o, ok := m[k].(map[string]any); ok {
			c.Output = componentOutput(o)
		}
		addComponent(r, c)
	}
}

// listComponents reads [{"name": ..., "status": ...}, ...].
func listComponents(r *Report, list []any) {
	for _, e := range list {
		o, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name := find(o, []string{"name", "id", "component", "componentId", "service", "key", "title"}, nil)
		c := Component{Name: clip(name, maxName), Status: statusOf(o)}
		if name == "" || c.Status == Unknown {
			continue
		}
		c.Output = componentOutput(o)
		addComponent(r, c)
	}
}

func componentOutput(o map[string]any) string {
	for _, k := range []string{"output", "message", "error", "description", "reason"} {
		if s := text(o[k]); s != "" {
			return s
		}
	}
	return ""
}

func addComponent(r *Report, c Component) {
	if len(r.Components) < maxComponents {
		r.Components = append(r.Components, c)
	}
}

// scopes returns root followed by its nested info objects.
func scopes(root map[string]any, names []string) []map[string]any {
	out := []map[string]any{root}
	for _, n := range names {
		if m, ok := root[n].(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// find returns the first short scalar under one of keys, at the top level
// first and then inside each scope object.
func find(root map[string]any, keys, scopeNames []string) string {
	for _, sc := range scopes(root, scopeNames) {
		for _, k := range keys {
			if s := str(sc[k]); s != "" {
				return s
			}
		}
	}
	return ""
}

// findCommit also accepts Spring's {"git": {"commit": {"id": "..."}}}.
func findCommit(root map[string]any) string {
	if s := find(root, commitKeys, infoScopes); s != "" {
		return s
	}
	for _, sc := range scopes(root, infoScopes) {
		if c, ok := sc["commit"].(map[string]any); ok {
			if s := str(c["id"]); s != "" {
				return s
			}
		}
	}
	return ""
}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]{12,64}$`)

func shortCommit(s string) string {
	if hexRe.MatchString(s) {
		return strings.ToLower(s[:7])
	}
	return s
}

// str returns a short single-line string or number, or "".
func str(v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = strings.TrimSpace(x)
	case json.Number:
		s = x.String()
	default:
		return ""
	}
	if s == "" || len(s) > maxName || strings.ContainsAny(s, "\r\n") || !utf8.ValidString(s) {
		return ""
	}
	return s
}

// text returns a message string, clipped, or "".
func text(v any) string {
	switch x := v.(type) {
	case string:
		return clip(strings.TrimSpace(x), maxText)
	case []any: // the IETF draft's notes and some outputs are lists of strings
		var parts []string
		for _, e := range x {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return clip(strings.Join(parts, "; "), maxText)
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func num(v any) (float64, bool) {
	var f float64
	var err error
	switch x := v.(type) {
	case json.Number:
		f, err = x.Float64()
	case string:
		f, err = strconv.ParseFloat(strings.TrimSpace(x), 64)
	default:
		return 0, false
	}
	return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0
}

// minTime and maxAhead bound plausible start times.
const (
	minTime  = 946684800 // 2000-01-01
	maxAhead = 86400
)

var timeLayouts = []string{
	time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05 -0700 MST", time.RFC1123, time.RFC1123Z, time.UnixDate,
}

// timestamp reads a time as a string or a Unix number in s, ms, µs or ns,
// returning Unix seconds, or 0 when it isn't a plausible start time.
func timestamp(v any) int64 {
	var t int64
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		for _, l := range timeLayouts {
			if p, err := time.Parse(l, s); err == nil {
				t = p.Unix()
				break
			}
		}
	}
	if t == 0 {
		f, ok := num(v)
		if !ok {
			return 0
		}
		for f >= 1e11 { // milliseconds, microseconds or nanoseconds
			f /= 1000
		}
		t = int64(f)
	}
	if t < minTime || t > time.Now().Unix()+maxAhead {
		return 0
	}
	return t
}

// uptime reads an uptime value. Numbers keep the given unit (0 if unknown,
// except that a fractional value is taken to be seconds); duration strings
// are converted to seconds.
func uptime(v any, unit float64) (float64, float64, bool) {
	if f, ok := num(v); ok {
		if unit == 0 && f != math.Trunc(f) {
			unit = 1
		}
		return f, unit, true
	}
	s, ok := v.(string)
	if !ok {
		return 0, 0, false
	}
	if secs, ok := duration(strings.TrimSpace(s)); ok {
		return secs, 1, true
	}
	return 0, 0, false
}

var (
	isoDur    = regexp.MustCompile(`^P(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)
	clockDur  = regexp.MustCompile(`^(?:(\d+)[.:])?(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)$`)                       // .NET "1.02:03:04.5"
	pyDur     = regexp.MustCompile(`^(\d+) days?, (\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)$`)                        // Python "3 days, 4:05:06"
	daysGoDur = regexp.MustCompile(`^(\d+)d(.*)$`)                                                              // "3d4h5m"
	wordsDur  = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*(days?|hours?|hrs?|minutes?|mins?|seconds?|secs?)\b`) // "3 days 4 hours"
)

// duration parses the common ways of writing an uptime, in seconds.
func duration(s string) (float64, bool) {
	f := func(x string) float64 { v, _ := strconv.ParseFloat(x, 64); return v }
	if m := isoDur.FindStringSubmatch(s); m != nil && s != "P" && s != "PT" {
		return f(m[1])*86400 + f(m[2])*3600 + f(m[3])*60 + f(m[4]), true
	}
	if m := clockDur.FindStringSubmatch(s); m != nil {
		return f(m[1])*86400 + f(m[2])*3600 + f(m[3])*60 + f(m[4]), true
	}
	if m := pyDur.FindStringSubmatch(s); m != nil {
		return f(m[1])*86400 + f(m[2])*3600 + f(m[3])*60 + f(m[4]), true
	}
	days := 0.0
	rest := s
	if m := daysGoDur.FindStringSubmatch(s); m != nil {
		days, rest = f(m[1]), m[2]
	}
	if rest == "" && days > 0 {
		return days * 86400, true
	}
	if d, err := time.ParseDuration(rest); err == nil && d >= 0 {
		return days*86400 + d.Seconds(), true
	}
	if ms := wordsDur.FindAllStringSubmatch(s, -1); ms != nil {
		total := 0.0
		for _, m := range ms {
			mult := map[byte]float64{'d': 86400, 'h': 3600, 'm': 60, 's': 1}[strings.ToLower(m[2])[0]]
			total += f(m[1]) * mult
		}
		return total, true
	}
	return 0, false
}

// unitPerSecond converts an IETF observedUnit to units per second.
func unitPerSecond(u string) float64 {
	switch strings.ToLower(u) {
	case "ms", "millis", "milliseconds":
		return 1e3
	case "us", "µs", "micros", "microseconds":
		return 1e6
	case "ns", "nanos", "nanoseconds":
		return 1e9
	case "m", "min", "mins", "minutes":
		return 1.0 / 60
	case "h", "hr", "hours":
		return 1.0 / 3600
	case "d", "day", "days":
		return 1.0 / 86400
	}
	return 1 // the draft's examples use "s"
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
