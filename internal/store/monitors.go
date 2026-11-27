package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ELT-Global/blip/internal/health"
)

// Monitor is an HTTP endpoint checked every Interval seconds. Health says
// how its response bodies are read.
type Monitor struct {
	ID       int64         `json:"id"`
	Name     string        `json:"name"`
	Method   string        `json:"method"`
	URL      string        `json:"url"`
	Interval int           `json:"interval"`
	Public   bool          `json:"public"`
	Health   health.Config `json:"health"`
}

const monitorCols = "id, name, method, url, interval, public, health"

func scanMonitor(s interface{ Scan(...any) error }) (Monitor, error) {
	var m Monitor
	var cfg string
	err := s.Scan(&m.ID, &m.Name, &m.Method, &m.URL, &m.Interval, &m.Public, &cfg)
	if cfg != "" {
		json.Unmarshal([]byte(cfg), &m.Health)
	}
	if m.Health.Mode == "" {
		m.Health.Mode = "auto"
	}
	return m, err
}

// Source identifies what a monitor's health reports are read from: its
// method, URL and health settings. When any of them changes, earlier reports
// describe something else, so they are no longer shown and tracking starts
// over (a new version path would otherwise look like a deploy).
func (m Monitor) Source() string {
	return m.Method + " " + m.URL + " " + configJSON(m.Health)
}

func configJSON(c health.Config) string {
	b, _ := json.Marshal(c)
	return string(b)
}

// CreateMonitor stores m and returns it with its new ID.
func (db *DB) CreateMonitor(ctx context.Context, m Monitor) (Monitor, error) {
	row := db.sql.QueryRowContext(ctx, `
		INSERT INTO monitors(name, method, url, interval, public, health, created) VALUES(?, ?, ?, ?, ?, ?, ?)
		RETURNING `+monitorCols,
		m.Name, m.Method, m.URL, m.Interval, m.Public, configJSON(m.Health), time.Now().Unix())
	return scanMonitor(row)
}

// UpdateMonitor replaces the settings of the monitor with m.ID.
func (db *DB) UpdateMonitor(ctx context.Context, m Monitor) error {
	return affected(db.sql.ExecContext(ctx,
		"UPDATE monitors SET name=?, method=?, url=?, interval=?, public=?, health=? WHERE id=?",
		m.Name, m.Method, m.URL, m.Interval, m.Public, configJSON(m.Health), m.ID))
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
