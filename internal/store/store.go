// Package store persists blip's state in a single SQLite file.
//
// Check results are the bulk of the data, so they live in compact
// WITHOUT ROWID tables keyed by (monitor, time) and are rolled up into
// hourly aggregates as they are written. Raw checks can then be trimmed
// while day and hour history stays available from the rollups.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("not found")

// DB wraps the SQLite handle. All methods are safe for concurrent use.
type DB struct {
	sql  *sql.DB
	path string
}

const schema = `
CREATE TABLE users(
	id         INTEGER PRIMARY KEY,
	email      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	role       INTEGER NOT NULL,
	secret     BLOB NOT NULL,
	last_step  INTEGER NOT NULL DEFAULT 0,
	invite     BLOB,
	invite_exp INTEGER,
	created    INTEGER NOT NULL
);
CREATE TABLE sessions(
	token   BLOB PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
	exp     INTEGER NOT NULL
) WITHOUT ROWID;
-- AUTOINCREMENT: a deleted monitor's id is never reused, so late results
-- and old /m/{id} links can't land on a different monitor.
CREATE TABLE monitors(
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	name     TEXT NOT NULL,
	method   TEXT NOT NULL,
	url      TEXT NOT NULL,
	interval INTEGER NOT NULL,
	public   INTEGER NOT NULL,
	created  INTEGER NOT NULL
);
CREATE TABLE checks(
	monitor_id INTEGER NOT NULL REFERENCES monitors ON DELETE CASCADE,
	t          INTEGER NOT NULL,
	ms         INTEGER NOT NULL,
	code       INTEGER NOT NULL,
	PRIMARY KEY(monitor_id, t)
) WITHOUT ROWID;
CREATE TABLE hours(
	monitor_id INTEGER NOT NULL REFERENCES monitors ON DELETE CASCADE,
	h          INTEGER NOT NULL,
	n          INTEGER NOT NULL,
	up         INTEGER NOT NULL,
	ms_sum     INTEGER NOT NULL,
	ms_max     INTEGER NOT NULL,
	PRIMARY KEY(monitor_id, h)
) WITHOUT ROWID;
CREATE TABLE incidents(
	id         INTEGER PRIMARY KEY,
	monitor_id INTEGER NOT NULL REFERENCES monitors ON DELETE CASCADE,
	start      INTEGER NOT NULL,
	ended      INTEGER,
	code       INTEGER NOT NULL,
	cause      TEXT NOT NULL
);
CREATE INDEX incidents_monitor ON incidents(monitor_id, start);
CREATE INDEX incidents_open ON incidents(monitor_id) WHERE ended IS NULL;
CREATE TABLE notes(
	id          INTEGER PRIMARY KEY,
	incident_id INTEGER NOT NULL REFERENCES incidents ON DELETE CASCADE,
	author      TEXT NOT NULL,
	t           INTEGER NOT NULL,
	body        TEXT NOT NULL
);
CREATE INDEX notes_incident ON notes(incident_id);
CREATE TABLE settings(
	k TEXT PRIMARY KEY,
	v INTEGER NOT NULL
) WITHOUT ROWID;
`

// Open opens (creating if needed) the database at path and applies the schema.
func Open(path string) (*DB, error) {
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)&_txlock=immediate"
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db := &DB{sql: sdb, path: path}
	if err := db.migrate(); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return db, nil
}

// migrations[i] takes the schema from user_version i to i+1. Append only.
var migrations = []string{schema, `
-- API keys are read-only credentials owned by a user. Only a hash of the
-- secret is kept; prefix is the public part shown in lists and logs.
CREATE TABLE api_keys(
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id      INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
	name         TEXT NOT NULL,
	prefix       TEXT NOT NULL UNIQUE,
	hash         BLOB NOT NULL UNIQUE,
	all_monitors INTEGER NOT NULL,
	ttl_days     INTEGER NOT NULL, -- 0: never expires
	exp          INTEGER,
	created      INTEGER NOT NULL,
	last_used    INTEGER
);
CREATE INDEX api_keys_user ON api_keys(user_id);
CREATE TABLE api_key_monitors(
	key_id     INTEGER NOT NULL REFERENCES api_keys ON DELETE CASCADE,
	monitor_id INTEGER NOT NULL REFERENCES monitors ON DELETE CASCADE,
	PRIMARY KEY(key_id, monitor_id)
) WITHOUT ROWID;
CREATE INDEX api_key_monitors_monitor ON api_key_monitors(monitor_id);
`}

func (db *DB) migrate() error {
	var v int
	if err := db.sql.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v == 0 {
		// auto_vacuum must be chosen before the first table exists; INCREMENTAL
		// lets Trim hand freed pages back to the filesystem cheaply.
		if _, err := db.sql.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			return err
		}
	}
	for ; v < len(migrations); v++ {
		tx, err := db.sql.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (db *DB) Close() error { return db.sql.Close() }

func (db *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func one(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
