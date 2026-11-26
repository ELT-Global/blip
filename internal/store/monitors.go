package store

import (
	"context"
	"time"
)

// Monitor is an HTTP endpoint checked every Interval seconds.
type Monitor struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Interval int    `json:"interval"`
	Public   bool   `json:"public"`
}

const monitorCols = "id, name, method, url, interval, public"

func scanMonitor(s interface{ Scan(...any) error }) (Monitor, error) {
	var m Monitor
	err := s.Scan(&m.ID, &m.Name, &m.Method, &m.URL, &m.Interval, &m.Public)
	return m, err
}

// CreateMonitor stores m and returns it with its new ID.
func (db *DB) CreateMonitor(ctx context.Context, m Monitor) (Monitor, error) {
	row := db.sql.QueryRowContext(ctx, `
		INSERT INTO monitors(name, method, url, interval, public, created) VALUES(?, ?, ?, ?, ?, ?)
		RETURNING `+monitorCols,
		m.Name, m.Method, m.URL, m.Interval, m.Public, time.Now().Unix())
	return scanMonitor(row)
}

// UpdateMonitor replaces the settings of the monitor with m.ID.
func (db *DB) UpdateMonitor(ctx context.Context, m Monitor) error {
	return affected(db.sql.ExecContext(ctx,
		"UPDATE monitors SET name=?, method=?, url=?, interval=?, public=? WHERE id=?",
		m.Name, m.Method, m.URL, m.Interval, m.Public, m.ID))
}

// DeleteMonitor removes a monitor and, via cascades, all of its history.
func (db *DB) DeleteMonitor(ctx context.Context, id int64) error {
	return affected(db.sql.ExecContext(ctx, "DELETE FROM monitors WHERE id=?", id))
}

// Monitor returns one monitor, or ErrNotFound.
func (db *DB) Monitor(ctx context.Context, id int64) (Monitor, error) {
	m, err := scanMonitor(db.sql.QueryRowContext(ctx, "SELECT "+monitorCols+" FROM monitors WHERE id=?", id))
	return m, one(err)
}

// Monitors returns all monitors, ordered by name.
func (db *DB) Monitors(ctx context.Context) ([]Monitor, error) {
	rows, err := db.sql.QueryContext(ctx, "SELECT "+monitorCols+" FROM monitors ORDER BY name, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ms []Monitor
	for rows.Next() {
		m, err := scanMonitor(rows)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	return ms, rows.Err()
}
