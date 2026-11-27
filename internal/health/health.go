// Package health reads the body of a health endpoint: overall status,
// component checks, version, start time or uptime, and instance identity.
//
// Parse recognises the common formats on its own (the IETF health+json
// draft, Spring Boot Actuator, MicroProfile Health, ASP.NET Core
// HealthChecks, Elasticsearch-style colours, Atlassian Statuspage, plain
// JSON with familiar field names, and one-word text bodies). Config lets a
// monitor point at its own fields instead.
//
// Tracker turns successive reports into deploy and restart events.
package health

import (
	"encoding/json"
	"errors"
	"strings"
)

// Status is the health a body reports. The zero value means it said nothing
// we understood.
type Status int8

const (
	Unknown Status = iota
	Pass
	Warn
	Fail
	Maintenance
)

var statusNames = [...]string{"", "pass", "warn", "fail", "maintenance"}

func (s Status) String() string {
	if s < 0 || int(s) >= len(statusNames) {
		return ""
	}
	return statusNames[s]
}

func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Status) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	for i, n := range statusNames {
		if n == v {
			*s = Status(i)
			return nil
		}
	}
	return errors.New("unknown health status " + v)
}

// severity orders statuses for picking the worst of several.
func (s Status) severity() int {
	return [...]int{0, 1, 3, 4, 2}[s]
}

// worse returns the more severe of a and b.
func worse(a, b Status) Status {
	if b.severity() > a.severity() {
		return b
	}
	return a
}

// Component is one dependency a health body reports on, such as a database.
type Component struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Output string `json:"output,omitempty"`
}

// Report is what one health body said. Started is a Unix time taken from an
// absolute field; Uptime is the raw uptime value, in UptimeUnit units per
// second (0 when the unit is unknown and must be learned from later checks).
type Report struct {
	Format     string
	Status     Status
	Version    string
	Commit     string
	Instance   string
	Message    string
	Started    int64
	HasUptime  bool
	Uptime     float64
	UptimeUnit float64
	Components []Component
}

// Label is how a report's release is shown: the version, the short commit,
// or both.
func (r Report) Label() string {
	switch {
	case r.Version != "" && r.Commit != "" && !strings.Contains(r.Version, r.Commit):
		return r.Version + " (" + r.Commit + ")"
	case r.Version != "":
		return r.Version
	}
	return r.Commit
}

// Failing names the components that are failing, or failing and degraded
// when none fail outright.
func (r Report) Failing() []string {
	var fail, warn []string
	for _, c := range r.Components {
		switch c.Status {
		case Fail:
			fail = append(fail, c.Name)
		case Warn:
			warn = append(warn, c.Name)
		}
	}
	if len(fail) > 0 {
		return fail
	}
	return warn
}

// Config is a monitor's health settings. Mode "off" ignores bodies; the
// paths override automatic detection for one field each, as dotted paths
// such as "app.build.version" or "checks.0.status".
type Config struct {
	Mode     string `json:"mode"`
	Status   string `json:"status,omitempty"`
	Version  string `json:"version,omitempty"`
	Started  string `json:"started,omitempty"`
	Uptime   string `json:"uptime,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// Off reports whether bodies should be ignored.
func (c Config) Off() bool { return c.Mode == "off" }

// Validate normalises c and checks it, returning a message for the user.
func (c *Config) Validate() string {
	if c.Mode == "" {
		c.Mode = "auto"
	}
	if c.Mode != "auto" && c.Mode != "off" {
		return `health.mode must be "auto" or "off"`
	}
	for _, p := range []*string{&c.Status, &c.Version, &c.Started, &c.Uptime, &c.Instance} {
		*p = strings.TrimPrefix(strings.TrimSpace(*p), "$.")
		if len(*p) > 200 {
			return "health field paths must be at most 200 characters"
		}
	}
	return ""
}
