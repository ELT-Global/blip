package store

import (
	"context"
	"encoding/json"

	"github.com/ELT-Global/blip/internal/health"
)

// Report is the latest health a monitor's response body reported. Started is
// when the process started, Unix seconds, worked out from a start time or an
// uptime; 0 if unknown.
type Report struct {
	T          int64              `json:"t"`
	Format     string             `json:"format,omitempty"`
	Status     health.Status      `json:"status"`
	Version    string             `json:"version,omitempty"`
	Instance   string             `json:"instance,omitempty"`
	Started    int64              `json:"started,omitempty"`
	Message    string             `json:"message,omitempty"`
	Components []health.Component `json:"components,omitempty"`
}

// LastReport returns a monitor's latest health report, the source it was
// read from (see Monitor.Source) and the tracker state saved with it, or
// ErrNotFound if it has none.
func (db *DB) LastReport(ctx context.Context, id int64) (Report, string, []byte, error) {
	var r Report
	var body, source string
	var state []byte
	err := db.sql.QueryRowContext(ctx, "SELECT body, source, state FROM reports WHERE monitor_id=?", id).Scan(&body, &source, &state)
	if err != nil {
		return r, "", nil, one(err)
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return r, "", nil, err
	}
	return r, source, state, nil
}

// Events returns a monitor's deploy and restart events with from <= t < to,
// newest first, capped at limit.
func (db *DB) Events(ctx context.Context, id, from, to int64, limit int) ([]health.Event, error) {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT t, kind, instance, from_v, to_v FROM events
		WHERE monitor_id=? AND t>=? AND t<? ORDER BY t DESC LIMIT ?`, id, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []health.Event{}
	for rows.Next() {
		var e health.Event
		if err := rows.Scan(&e.T, &e.Kind, &e.Instance, &e.From, &e.To); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
