package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ELT-Global/blip/internal/store"
)

// monitorView is a monitor as the UI sees it. Target details are hidden from
// anonymous visitors so a public status page doesn't leak internal URLs.
type monitorView struct {
	ID       int64          `json:"id"`
	Name     string         `json:"name"`
	Method   string         `json:"method,omitempty"`
	URL      string         `json:"url,omitempty"`
	Interval int            `json:"interval"`
	Public   bool           `json:"public"`
	Last     *store.Check   `json:"last"`
	Days     []store.Bucket `json:"days"`
}

func (s *Server) view(r *http.Request, m store.Monitor, signedIn bool, days int) (monitorView, error) {
	v := monitorView{ID: m.ID, Name: m.Name, Interval: m.Interval, Public: m.Public}
	if signedIn {
		v.Method, v.URL = m.Method, m.URL
	}
	if c, ok := s.runner.Latest(m.ID); ok {
		v.Last = &c
	}
	// Start at local midnight so the oldest day is whole.
	tz := tzOffset(r)
	today := (time.Now().Unix() + int64(tz)) / 86400
	from := (today-int64(days)+1)*86400 - int64(tz)
	var err error
	v.Days, err = s.db.Days(r.Context(), m.ID, from, tz)
	return v, err
}

// tzOffset is the client's UTC offset in seconds, used to align day buckets
// with local midnight.
func tzOffset(r *http.Request) int {
	tz := queryInt(r, "tz", 0)
	return int(max(-14*3600, min(14*3600, tz)))
}

func (s *Server) listMonitors(w http.ResponseWriter, r *http.Request) {
	signedIn := s.user(r) != nil
	ms, err := s.db.Monitors(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	days := int(max(1, min(90, queryInt(r, "days", 30))))
	out := []monitorView{}
	for _, m := range ms {
		if !m.Public && !signedIn {
			continue
		}
		v, err := s.view(r, m, signedIn, days)
		if err != nil {
			failErr(w, err)
			return
		}
		out = append(out, v)
	}
	reply(r, w, http.StatusOK, out)
}

// visible loads a monitor if the requester may see it.
func (s *Server) visible(w http.ResponseWriter, r *http.Request) (store.Monitor, bool, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return store.Monitor{}, false, false
	}
	m, err := s.db.Monitor(r.Context(), id)
	signedIn := s.user(r) != nil
	if err == nil && !m.Public && !signedIn {
		err = store.ErrNotFound
	}
	if err != nil {
		failErr(w, err)
		return m, false, false
	}
	return m, signedIn, true
}

func (s *Server) getMonitor(w http.ResponseWriter, r *http.Request) {
	m, signedIn, ok := s.visible(w, r)
	if !ok {
		return
	}
	days := int(max(1, min(400, queryInt(r, "days", 90))))
	v, err := s.view(r, m, signedIn, days)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, v)
}

// timeRange reads from/to (unix seconds), defaulting to the last day and
// capping the span at maxSpan.
func timeRange(r *http.Request, maxSpan time.Duration) (int64, int64) {
	now := time.Now().Unix()
	to := queryInt(r, "to", now+1)
	from := queryInt(r, "from", to-86400)
	return max(from, to-int64(maxSpan.Seconds())), to
}

func (s *Server) monitorHours(w http.ResponseWriter, r *http.Request) {
	m, _, ok := s.visible(w, r)
	if !ok {
		return
	}
	from, to := timeRange(r, 31*24*time.Hour)
	hs, err := s.db.Hours(r.Context(), m.ID, from, to)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, hs)
}

const maxChecks = 20_000

func (s *Server) monitorChecks(w http.ResponseWriter, r *http.Request) {
	m, _, ok := s.visible(w, r)
	if !ok {
		return
	}
	from, to := timeRange(r, 7*24*time.Hour)
	cs, err := s.db.Checks(r.Context(), m.ID, from, to, maxChecks)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, cs)
}

func (s *Server) monitorIncidents(w http.ResponseWriter, r *http.Request) {
	m, signedIn, ok := s.visible(w, r)
	if !ok {
		return
	}
	is, err := s.db.Incidents(r.Context(), m.ID, int(max(1, min(200, queryInt(r, "limit", 50)))))
	if err != nil {
		failErr(w, err)
		return
	}
	if !signedIn { // authors are email addresses; keep them off public pages
		for i := range is {
			for j := range is[i].Notes {
				is[i].Notes[j].Author = ""
			}
		}
	}
	reply(r, w, http.StatusOK, is)
}

var methods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}

func (s *Server) readMonitor(w http.ResponseWriter, r *http.Request) (store.Monitor, bool) {
	var m store.Monitor
	if !decode(w, r, &m) {
		return m, false
	}
	m.Name = strings.TrimSpace(m.Name)
	m.Method = strings.ToUpper(m.Method)
	if m.Method == "" {
		m.Method = "GET"
	}
	u, err := url.Parse(m.URL)
	var msg string
	switch {
	case m.Name == "" || utf8.RuneCountInString(m.Name) > 100:
		msg = "name must be 1-100 characters"
	case !methods[m.Method]:
		msg = "unsupported method"
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(m.URL) > 2048:
		msg = "url must be an absolute http(s) URL"
	case m.Interval < s.minInterval || m.Interval > 86400:
		msg = "interval must be between " + strconv.Itoa(s.minInterval) + " and 86400 seconds"
	default:
		return m, true
	}
	fail(w, http.StatusBadRequest, msg)
	return m, false
}

func (s *Server) createMonitor(w http.ResponseWriter, r *http.Request) {
	in, ok := s.readMonitor(w, r)
	if !ok {
		return
	}
	m, err := s.db.CreateMonitor(r.Context(), in)
	if err != nil {
		failErr(w, err)
		return
	}
	s.runner.Set(m.ID)
	reply(r, w, http.StatusCreated, m)
}

func (s *Server) updateMonitor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	m, ok := s.readMonitor(w, r)
	if !ok {
		return
	}
	m.ID = id
	if err := s.db.UpdateMonitor(r.Context(), m); err != nil {
		failErr(w, err)
		return
	}
	s.runner.Set(m.ID)
	reply(r, w, http.StatusOK, m)
}

func (s *Server) deleteMonitor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	// Delete first: the runner refuses to (re)start monitors missing from the
	// database, so a concurrent edit can't resurrect this one's probe.
	if err := s.db.DeleteMonitor(r.Context(), id); err != nil {
		failErr(w, err)
		return
	}
	s.runner.Remove(id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addNote(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct{ Body string }
	if !decode(w, r, &in) {
		return
	}
	body := strings.TrimSpace(in.Body)
	if body == "" || utf8.RuneCountInString(body) > 4000 {
		fail(w, http.StatusBadRequest, "note must be 1-4000 characters")
		return
	}
	n, err := s.db.AddNote(r.Context(), id, current(r).Email, body)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusCreated, n)
}

func (s *Server) dbStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.db.Stats(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, st)
}

func (s *Server) setRetention(w http.ResponseWriter, r *http.Request) {
	var in store.Retention
	if !decode(w, r, &in) {
		return
	}
	if in.RawDays < 0 || in.HourDays < 0 || in.RawDays > 36500 || in.HourDays > 36500 {
		fail(w, http.StatusBadRequest, "days must be between 0 (keep forever) and 36500")
		return
	}
	if err := s.db.SetRetention(r.Context(), in); err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, in)
}

func (s *Server) trim(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.Trim(r.Context(), time.Now())
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, res)
}

func (s *Server) vacuum(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Vacuum(r.Context()); err != nil {
		failErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
