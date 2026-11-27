package store

import (
	"context"
	"database/sql"
	"os"
	"time"
)

// Retention controls how long data is kept, in days. Zero keeps data forever.
// Raw checks older than RawDays survive only as hourly rollups.
type Retention struct {
	RawDays  int `json:"raw_days"`
	HourDays int `json:"hour_days"`
}

// DefaultRetention applies until a root user changes it in Settings.
var DefaultRetention = Retention{RawDays: 30, HourDays: 400}

// Retention returns the current policy, falling back to DefaultRetention.
func (db *DB) Retention(ctx context.Context) (Retention, error) {
	r := DefaultRetention
	rows, err := db.sql.QueryContext(ctx, "SELECT k, v FROM settings WHERE k IN ('raw_days', 'hour_days')")
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v int
		if err := rows.Scan(&k, &v); err != nil {
			return r, err
		}
		if k == "raw_days" {
			r.RawDays = v
		} else {
			r.HourDays = v
		}
	}
	return r, rows.Err()
}

// SetRetention stores a new policy; Trim applies it.
func (db *DB) SetRetention(ctx context.Context, r Retention) error {
	_, err := db.sql.ExecContext(ctx,
		"INSERT OR REPLACE INTO settings(k, v) VALUES('raw_days', ?), ('hour_days', ?)", r.RawDays, r.HourDays)
	return err
}

// TableStat describes one table's footprint.
type TableStat struct {
	Name  string `json:"name"`
	Rows  int64  `json:"rows"`
	Bytes int64  `json:"bytes"`
}

// Stats describes the database file for the Settings page.
type Stats struct {
	Path     string      `json:"path"`
	File     int64       `json:"file"` // main database file
	WAL      int64       `json:"wal"`  // write-ahead log
	Free     int64       `json:"free"` // reusable pages inside the file
	Tables   []TableStat `json:"tables"`
	Oldest   int64       `json:"oldest"` // oldest raw check, 0 if none
	Retained Retention   `json:"retention"`
}

var dataTables = []string{"checks", "hours", "incidents", "notes", "monitors", "users", "sessions", "api_keys"}

// Stats reports database size and per-table row counts and bytes.
func (db *DB) Stats(ctx context.Context) (Stats, error) {
	s := Stats{Path: db.path}
	if fi, err := os.Stat(db.path); err == nil {
		s.File = fi.Size()
	}
	if fi, err := os.Stat(db.path + "-wal"); err == nil {
		s.WAL = fi.Size()
	}
	var pageSize, free int64
	if err := db.sql.QueryRowContext(ctx, "SELECT page_size, freelist_count FROM pragma_page_size, pragma_freelist_count").Scan(&pageSize, &free); err != nil {
		return s, err
	}
	s.Free = pageSize * free

	// dbstat attributes index pages to the index name; fold them into their table.
	bytes := map[string]int64{}
	rows, err := db.sql.QueryContext(ctx, `SELECT coalesce(m.tbl_name, d.name), sum(d.pgsize)
		FROM dbstat d LEFT JOIN sqlite_schema m ON m.name = d.name GROUP BY 1`)
	if err == nil {
		for rows.Next() {
			var name string
			var b int64
			if rows.Scan(&name, &b) == nil {
				bytes[name] = b
			}
		}
		rows.Close()
	}
	for _, t := range dataTables {
		ts := TableStat{Name: t, Bytes: bytes[t]}
		if err := db.sql.QueryRowContext(ctx, "SELECT count(*) FROM "+t).Scan(&ts.Rows); err != nil {
			return s, err
		}
		s.Tables = append(s.Tables, ts)
	}
	var oldest sql.NullInt64
	if err := db.sql.QueryRowContext(ctx, "SELECT min(t) FROM checks").Scan(&oldest); err != nil {
		return s, err
	}
	s.Oldest = oldest.Int64
	s.Retained, err = db.Retention(ctx)
	return s, err
}

// TrimResult counts rows removed by Trim.
type TrimResult struct {
	Checks    int64 `json:"checks"`
	Hours     int64 `json:"hours"`
	Incidents int64 `json:"incidents"`
}

// Trim applies the retention policy as of now, then returns freed pages to
// the filesystem and truncates the WAL.
func (db *DB) Trim(ctx context.Context, now time.Time) (TrimResult, error) {
	var res TrimResult
	r, err := db.Retention(ctx)
	if err != nil {
		return res, err
	}
	err = db.tx(ctx, func(tx *sql.Tx) error {
		ids, err := monitorIDs(tx)
		if err != nil {
			return err
		}
		// Per-monitor deletes walk the (monitor_id, t) key as a range instead
		// of scanning the whole table.
		del := func(cut int64, q string, n *int64) error {
			if cut <= 0 {
				return nil
			}
			for _, id := range ids {
				out, err := tx.Exec(q, id, cut)
				if err != nil {
					return err
				}
				c, _ := out.RowsAffected()
				*n += c
			}
			return nil
		}
		if err := del(cutoff(now, r.RawDays), "DELETE FROM checks WHERE monitor_id=? AND t<?", &res.Checks); err != nil {
			return err
		}
		hourCut := cutoff(now, r.HourDays)
		if err := del(hourCut/3600, "DELETE FROM hours WHERE monitor_id=? AND h<?", &res.Hours); err != nil {
			return err
		}
		if err := del(hourCut, "DELETE FROM incidents WHERE monitor_id=? AND ended<?", &res.Incidents); err != nil {
			return err
		}
		_, err = tx.Exec("DELETE FROM sessions WHERE exp<?", now.Unix())
		return err
	})
	if err != nil {
		return res, err
	}
	if _, err := db.sql.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
		return res, err
	}
	_, err = db.sql.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return res, err
}

func cutoff(now time.Time, days int) int64 {
	if days <= 0 {
		return 0
	}
	return now.Add(-time.Duration(days) * 24 * time.Hour).Unix()
}

func monitorIDs(tx *sql.Tx) ([]int64, error) {
	rows, err := tx.Query("SELECT id FROM monitors")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Vacuum rebuilds the database file to its minimal size.
func (db *DB) Vacuum(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, "VACUUM"); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}
