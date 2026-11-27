package health

import (
	"encoding/json"
	"math"
	"slices"
	"sync"
	"time"
)

// Event is a change noticed between health reports: "deploy" when the
// version changes, "restart" when a known process starts again, and "start"
// when a new instance appears.
type Event struct {
	T        int64  `json:"t"`
	Kind     string `json:"kind"`
	Instance string `json:"instance,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
}

const (
	maxLines = 16
	lineTTL  = 24 * 3600 // forget processes unseen for a day
)

// Tracker follows one monitor's reports. It is safe for concurrent use, so
// a monitor's probe loop can be replaced while the old one finishes.
type Tracker struct {
	mu sync.Mutex
	s  state
}

// state is persisted between runs so a blip restart doesn't report every
// monitor as freshly deployed and restarted.
type state struct {
	LastT   int64  `json:"last,omitempty"` // previous observation; 0 before the first
	Version string `json:"v,omitempty"`    // confirmed release label
	Cand    string `json:"cv,omitempty"`   // a new label seen once, awaiting confirmation
	CandT   int64  `json:"ct,omitempty"`
	Lines   []line `json:"lines,omitempty"` // known processes

	// Learning the unit of a bare "uptime" number from consecutive checks.
	Unit   float64 `json:"unit,omitempty"` // units per second
	PrevUp float64 `json:"pu,omitempty"`
	PrevT  float64 `json:"pt,omitempty"`
}

// line is a process: an instance ID when the body names one, otherwise just
// a start time, so several instances behind a load balancer can be told apart.
type line struct {
	Key     string `json:"k,omitempty"`
	Started int64  `json:"s"`
	Seen    int64  `json:"seen"`
}

// NewTracker resumes from state saved by an earlier Observe, or starts fresh.
func NewTracker(saved []byte) *Tracker {
	t := &Tracker{}
	if len(saved) > 0 {
		json.Unmarshal(saved, &t.s) // a damaged state just starts over
	}
	return t
}

// Observe records a report taken at `at` with the given response latency.
// It returns the process start time it derived (0 if unknown), any events,
// and the state to persist.
func (t *Tracker) Observe(at time.Time, latency time.Duration, r Report) (started int64, events []Event, saved []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := &t.s
	now := at.Unix()
	first := s.LastT == 0

	// Versions: a new label must be seen twice in a row, so a load balancer
	// alternating between old and new instances mid-rollout doesn't log a
	// deploy on every check.
	if label := r.Label(); label != "" {
		switch {
		case s.Version == "":
			s.Version = label
		case label == s.Version:
			s.Cand = ""
		case label == s.Cand:
			events = append(events, Event{T: s.CandT, Kind: "deploy", From: s.Version, To: label})
			s.Version, s.Cand = label, ""
		default:
			s.Cand, s.CandT = label, now
		}
	}

	// Start time: given outright, or worked out from uptime.
	tol := 2.0
	if r.Started != 0 {
		started = r.Started
	} else if r.HasUptime {
		unit := r.UptimeUnit
		if unit == 0 {
			unit = t.learn(at, r.Uptime)
		}
		if unit > 0 {
			started = int64(math.Round(float64(at.UnixMilli())/1000 - r.Uptime/unit))
			// The server measured uptime somewhere within the request, and
			// coarse units round it.
			tol = 3 + 2*latency.Seconds() + max(1, 1/unit)
		}
	}
	// A start before 2000 or in the future means the uptime's unit is wrong,
	// as when a service switches from seconds to milliseconds; drop it, and
	// relearn the unit from the next checks rather than log a restart.
	if started != 0 && (started < minTime || float64(started) > float64(now)+tol) {
		started = 0
		if r.UptimeUnit == 0 {
			s.Unit = 0
		}
	}
	if started != 0 {
		events = append(events, t.place(r.Instance, started, now, tol, first)...)
	}
	s.LastT = now
	saved, _ = json.Marshal(s)
	if first {
		events = nil // the first report is the baseline
	}
	return started, events, saved
}

// learn infers the unit of a bare uptime number from how fast it grows
// against the wall clock, returning 0 until it knows.
func (t *Tracker) learn(at time.Time, up float64) float64 {
	s := &t.s
	nowF := float64(at.UnixMilli()) / 1000
	if s.PrevT > 0 && up > s.PrevUp && nowF-s.PrevT >= 1 {
		ratio := (up - s.PrevUp) / (nowF - s.PrevT)
		for _, u := range []float64{1, 1e3, 1e6, 1e9} {
			if r := ratio / u; r > 0.6 && r < 1.6 {
				s.Unit = u
				break
			}
		}
	}
	s.PrevUp, s.PrevT = up, nowF
	return s.Unit
}

// place matches a start time to a known process. A process seen for the
// first time is only news if it started since the previous check; otherwise
// it is an old instance the load balancer hadn't sent us to before.
func (t *Tracker) place(key string, started, now int64, tol float64, first bool) []Event {
	s := &t.s
	near := func(a, b int64) bool { return math.Abs(float64(a-b)) <= tol }
	var events []Event
	i := slices.IndexFunc(s.Lines, func(l line) bool {
		if key != "" {
			return l.Key == key
		}
		return l.Key == "" && near(l.Started, started)
	})
	switch {
	case i >= 0 && key != "" && float64(started) > float64(s.Lines[i].Started)+tol:
		events = append(events, Event{T: started, Kind: "restart", Instance: key})
		s.Lines[i].Started = started
	case i >= 0 && key != "" && !near(started, s.Lines[i].Started):
		s.Lines[i].Started = started // the clock moved back; follow it quietly
	case i < 0:
		if !first && float64(started) > float64(s.LastT)-tol {
			kind := "restart"
			if key != "" && len(s.Lines) > 0 {
				kind = "start" // a new instance ID: a replacement or a scale-up
			}
			events = append(events, Event{T: started, Kind: kind, Instance: key})
		}
		s.Lines = append(s.Lines, line{Key: key, Started: started})
		i = len(s.Lines) - 1
	}
	s.Lines[i].Seen = now

	// Forget processes that have gone quiet, keeping the most recently seen.
	s.Lines = slices.DeleteFunc(s.Lines, func(l line) bool { return now-l.Seen > lineTTL })
	if len(s.Lines) > maxLines {
		slices.SortFunc(s.Lines, func(a, b line) int { return int(b.Seen - a.Seen) })
		s.Lines = s.Lines[:maxLines]
	}
	return events
}
