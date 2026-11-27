package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/ELT-Global/blip/internal/health"
)

// Codes stored in place of an HTTP status when a request fails outright.
const (
	CodeError   = 0
	CodeTimeout = -1
	CodeDNS     = -2
	CodeRefused = -3
	CodeTLS     = -4
	// CodeUnhealthy is a response with a 2xx or 3xx status whose body
	// reported that the service is failing.
	CodeUnhealthy = -5
)

// Up reports whether a stored code counts as the monitor being up.
func Up(code int) bool { return code >= 200 && code < 400 }

// Check is one probe result. Health is the status the response body
// reported, if any. Err is only used as an incident's cause, and Report,
// Source, State and Events carry the health details stored alongside the check.
type Check struct {
	MonitorID int64         `json:"-"`
	T         int64         `json:"t"`
	Ms        int           `json:"ms"`
	Code      int           `json:"code"`
	Health    health.Status `json:"health,omitempty"`
	Err       string        `json:"-"`

	Report *Report        `json:"-"`
	Source string         `json:"-"` // see Monitor.Source
	State  []byte         `json:"-"`
	Events []health.Event `json:"-"`
}

// Degraded reports whether a check was up but its body reported a warning.
func (c Check) Degraded() bool { return Up(c.Code) && c.Health == health.Warn }

// Bucket aggregates checks over an hour or a day. Ms is the mean latency of
// successful checks; Warn counts the up checks that reported degraded.
type Bucket struct {
	T    int64 `json:"t"`
	N    int   `json:"n"`
	Up   int   `json:"up"`
	Warn int   `json:"warn"`
	Ms   int   `json:"ms"`
}

// Record stores a batch of checks in one transaction, updates the hourly
// rollups, opens or resolves incidents on state changes, and saves health
// reports and events.
func (db *DB) Record(ctx context.Context, checks []Check) error {
	return db.tx(ctx, func(tx *sql.Tx) error {
		exists, err := tx.Prepare("SELECT 1 FROM monitors WHERE id=?")
		if err != nil {
			return err
		}
		ins, err := tx.Prepare("INSERT OR IGNORE INTO checks(monitor_id, t, ms, code, health) VALUES(?, ?, ?, ?, ?)")
		if err != nil {
			return err
		}
		stored, err := tx.Prepare("SELECT code FROM checks WHERE monitor_id=? AND t=?")
		if err != nil {
			return err
		}
		hour, err := tx.Prepare(`
			INSERT INTO hours(monitor_id, h, n, up, warn, ms_sum, ms_max) VALUES(?, ?, 1, ?, ?, ?, ?)
			ON CONFLICT(monitor_id, h) DO UPDATE SET n=n+1, up=up+excluded.up, warn=warn+excluded.warn,
				ms_sum=ms_sum+excluded.ms_sum, ms_max=max(ms_max, excluded.ms_max)`)
		if err != nil {
			return err
		}
		open, err := tx.Prepare(`
			INSERT INTO incidents(monitor_id, start, code, cause) SELECT ?1, ?2, ?3, ?4
			WHERE NOT EXISTS (SELECT 1 FROM incidents WHERE monitor_id=?1 AND ended IS NULL)`)
		if err != nil {
			return err
		}
		resolve, err := tx.Prepare("UPDATE incidents SET ended=? WHERE monitor_id=? AND ended IS NULL")
		if err != nil {
			return err
		}
		report, err := tx.Prepare(`
			INSERT INTO reports(monitor_id, t, source, body, state) VALUES(?, ?, ?, ?, ?)
			ON CONFLICT(monitor_id) DO UPDATE SET t=excluded.t, source=excluded.source, body=excluded.body, state=excluded.state
			WHERE excluded.t >= reports.t`)
		if err != nil {
			return err
		}
		event, err := tx.Prepare("INSERT OR IGNORE INTO events(monitor_id, t, kind, instance, from_v, to_v) VALUES(?, ?, ?, ?, ?, ?)")
		if err != nil {
			return err
		}
		for _, c := range checks {
			// Results can outlive their monitor briefly after a delete.
			var one int
			if err := exists.QueryRow(c.MonitorID).Scan(&one); errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return err
			}
			if c.Report != nil {
				body, _ := json.Marshal(c.Report)
				if _, err := report.Exec(c.MonitorID, c.T, c.Source, string(body), c.State); err != nil {
					return err
				}
			}
			for _, e := range c.Events {
				if _, err := event.Exec(c.MonitorID, e.T, e.Kind, e.Instance, e.From, e.To); err != nil {
					return err
				}
			}
			up, ms, warn := 0, 0, 0
			if Up(c.Code) {
				up, ms = 1, c.Ms
			}
			if c.Degraded() {
				warn = 1
			}
			// A restarted probe can land in the same second as the previous
			// check. Keep the stored one so the rollup counts each check once;
			// apply the newer result's state change only if it differs, so
			// replaying a batch changes nothing.
			res, err := ins.Exec(c.MonitorID, c.T, c.Ms, c.Code, c.Health)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 1 {
				if _, err := hour.Exec(c.MonitorID, c.T/3600, up, warn, ms, ms); err != nil {
					return err
				}
			} else {
				var code int
				if err := stored.QueryRow(c.MonitorID, c.T).Scan(&code); err != nil {
					return err
				}
				if Up(code) == (up == 1) {
					continue
				}
			}
			if up == 1 {
				_, err = resolve.Exec(c.T, c.MonitorID)
			} else {
				_, err = open.Exec(c.MonitorID, c.T, c.Code, c.Err)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// LastCheck returns the most recent check of a monitor.
func (db *DB) LastCheck(ctx context.Context, id int64) (Check, error) {
	c := Check{MonitorID: id}
	err := db.sql.QueryRowContext(ctx,
		"SELECT t, ms, code, health FROM checks WHERE monitor_id=? ORDER BY t DESC LIMIT 1", id).Scan(&c.T, &c.Ms, &c.Code, &c.Health)
	return c, one(err)
}

// Checks returns raw checks with from <= t < to, oldest first, capped at limit.
func (db *DB) Checks(ctx context.Context, id, from, to int64, limit int) ([]Check, error) {
	rows, err := db.sql.QueryContext(ctx,
		"SELECT t, ms, code, health FROM checks WHERE monitor_id=? AND t>=? AND t<? ORDER BY t LIMIT ?", id, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cs := []Check{}
	for rows.Next() {
		var c Check
		if err := rows.Scan(&c.T, &c.Ms, &c.Code, &c.Health); err != nil {
			return nil, err
		}
		cs = append(cs, c)
	}
	return cs, rows.Err()
}

// Hours returns hourly buckets with from <= start < to (unix seconds).
func (db *DB) Hours(ctx context.Context, id, from, to int64) ([]Bucket, error) {
	return db.buckets(ctx, `
		SELECT h*3600, n, up, warn, CASE up WHEN 0 THEN 0 ELSE ms_sum/up END
		FROM hours WHERE monitor_id=? AND h>=? AND h<? ORDER BY h`, id, from/3600, (to+3599)/3600)
}

// Days returns daily buckets starting at from, where days begin at local
// midnight for a timezone offset of tz seconds east of UTC.
func (db *DB) Days(ctx context.Context, id, from int64, tz int) ([]Bucket, error) {
	return db.buckets(ctx, `
		SELECT d*86400-?1, sum(n), sum(up), sum(warn), CASE sum(up) WHEN 0 THEN 0 ELSE sum(ms_sum)/sum(up) END
		FROM (SELECT (h*3600+?1)/86400 AS d, n, up, warn, ms_sum FROM hours WHERE monitor_id=?2 AND h>=?3)
		GROUP BY d ORDER BY d`, tz, id, (from+3599)/3600)
}

func (db *DB) buckets(ctx context.Context, q string, args ...any) ([]Bucket, error) {
	rows, err := db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bs := []Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.T, &b.N, &b.Up, &b.Warn, &b.Ms); err != nil {
			return nil, err
		}
		bs = append(bs, b)
	}
	return bs, rows.Err()
}
