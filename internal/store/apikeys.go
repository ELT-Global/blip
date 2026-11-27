package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"
)

// APIKey is a read-only credential for the monitor API. The secret itself is
// never stored: callers keep its hash and the public Prefix.
type APIKey struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Prefix      string  `json:"prefix"`
	Owner       string  `json:"owner"` // the owning user's email
	AllMonitors bool    `json:"all_monitors"`
	Monitors    []int64 `json:"monitors"` // when AllMonitors is false
	TTLDays     int     `json:"ttl_days"` // 0: never expires
	Expires     *int64  `json:"expires"`
	Created     int64   `json:"created"`
	LastUsed    *int64  `json:"last_used"`

	UserID int64 `json:"-"`
}

// Expired reports whether the key's lifetime has run out at now.
func (k APIKey) Expired(now time.Time) bool { return k.Expires != nil && *k.Expires <= now.Unix() }

// Allows reports whether the key may read monitor id.
func (k APIKey) Allows(id int64) bool { return k.AllMonitors || slices.Contains(k.Monitors, id) }

// ErrUnknownMonitor is returned when a key is scoped to a monitor that doesn't exist.
var ErrUnknownMonitor = errors.New("unknown monitor")

const keyCols = "k.id, k.name, k.prefix, u.email, k.all_monitors, k.ttl_days, k.exp, k.created, k.last_used, k.user_id"
const keyFrom = " FROM api_keys k JOIN users u ON u.id = k.user_id"

func scanKey(s interface{ Scan(...any) error }) (APIKey, error) {
	var k APIKey
	err := s.Scan(&k.ID, &k.Name, &k.Prefix, &k.Owner, &k.AllMonitors, &k.TTLDays, &k.Expires, &k.Created, &k.LastUsed, &k.UserID)
	k.Monitors = []int64{}
	return k, err
}

func expiry(now time.Time, ttlDays int) *int64 {
	if ttlDays == 0 {
		return nil
	}
	exp := now.Add(time.Duration(ttlDays) * 24 * time.Hour).Unix()
	return &exp
}

// CreateKey stores k (Name, AllMonitors, Monitors, TTLDays and UserID are
// read; Monitors must be free of duplicates) under prefix and secret hash,
// returning it as stored.
func (db *DB) CreateKey(ctx context.Context, k APIKey, prefix string, hash []byte) (APIKey, error) {
	now := time.Now()
	var id int64
	err := db.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRow(`INSERT INTO api_keys(user_id, name, prefix, hash, all_monitors, ttl_days, exp, created)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			k.UserID, k.Name, prefix, hash, k.AllMonitors, k.TTLDays, expiry(now, k.TTLDays), now.Unix()).Scan(&id)
		if err != nil || k.AllMonitors {
			return err
		}
		ins, err := tx.Prepare("INSERT OR IGNORE INTO api_key_monitors(key_id, monitor_id) SELECT ?1, id FROM monitors WHERE id=?2")
		if err != nil {
			return err
		}
		for _, m := range k.Monitors {
			res, err := ins.Exec(id, m)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 { // Monitors must hold no duplicates
				return ErrUnknownMonitor
			}
		}
		return nil
	})
	if err != nil {
		return APIKey{}, err
	}
	return db.key(ctx, "k.id = ?", id)
}

func (db *DB) key(ctx context.Context, where string, args ...any) (APIKey, error) {
	k, err := scanKey(db.sql.QueryRowContext(ctx, "SELECT "+keyCols+keyFrom+" WHERE "+where, args...))
	if err != nil {
		return k, one(err)
	}
	if !k.AllMonitors {
		k.Monitors, err = db.keyMonitors(ctx, k.ID)
	}
	return k, err
}

func (db *DB) keyMonitors(ctx context.Context, id int64) ([]int64, error) {
	rows, err := db.sql.QueryContext(ctx, "SELECT monitor_id FROM api_key_monitors WHERE key_id=? ORDER BY monitor_id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ms := []int64{}
	for rows.Next() {
		var m int64
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	return ms, rows.Err()
}

// KeyByHash resolves a presented secret's hash to its key, expired or not.
func (db *DB) KeyByHash(ctx context.Context, hash []byte) (APIKey, error) {
	return db.key(ctx, "k.hash = ?", hash)
}

// Keys lists the keys owned by userID, or every key when userID is 0,
// newest first.
func (db *DB) Keys(ctx context.Context, userID int64) ([]APIKey, error) {
	rows, err := db.sql.QueryContext(ctx, "SELECT "+keyCols+keyFrom+" WHERE ?1 = 0 OR k.user_id = ?1 ORDER BY k.created DESC, k.id DESC", userID)
	if err != nil {
		return nil, err
	}
	out := []APIKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if !out[i].AllMonitors {
			if out[i].Monitors, err = db.keyMonitors(ctx, out[i].ID); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// RotateKey replaces a key's secret and restarts its lifetime; the old secret
// stops working at once. userID limits it to that owner's keys (0: any key).
func (db *DB) RotateKey(ctx context.Context, id, userID int64, prefix string, hash []byte) (APIKey, error) {
	now := time.Now()
	err := db.tx(ctx, func(tx *sql.Tx) error {
		var ttl int
		err := tx.QueryRow("SELECT ttl_days FROM api_keys WHERE id=?1 AND (?2 = 0 OR user_id = ?2)", id, userID).Scan(&ttl)
		if err != nil {
			return one(err)
		}
		_, err = tx.Exec("UPDATE api_keys SET prefix=?, hash=?, exp=?, last_used=NULL WHERE id=?",
			prefix, hash, expiry(now, ttl), id)
		return err
	})
	if err != nil {
		return APIKey{}, err
	}
	return db.key(ctx, "k.id = ?", id)
}

// DeleteKey revokes a key. userID limits it to that owner's keys (0: any key).
func (db *DB) DeleteKey(ctx context.Context, id, userID int64) error {
	return affected(db.sql.ExecContext(ctx, "DELETE FROM api_keys WHERE id=?1 AND (?2 = 0 OR user_id = ?2)", id, userID))
}

// TouchKey records that a key was just used.
func (db *DB) TouchKey(ctx context.Context, id int64, t time.Time) error {
	_, err := db.sql.ExecContext(ctx, "UPDATE api_keys SET last_used=? WHERE id=?", t.Unix(), id)
	return err
}
