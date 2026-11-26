package store

import (
	"context"
	"database/sql"
	"time"
)

// Incident is a period during which a monitor was down. Ended is nil while ongoing.
type Incident struct {
	ID    int64  `json:"id"`
	Start int64  `json:"start"`
	Ended *int64 `json:"ended"`
	Code  int    `json:"code"`
	Cause string `json:"cause"`
	Notes []Note `json:"notes"`
}

// Note is a comment a user added to an incident. Author is their email.
type Note struct {
	ID     int64  `json:"id"`
	Author string `json:"author"`
	T      int64  `json:"t"`
	Body   string `json:"body"`
}

// Incidents returns a monitor's most recent incidents with their notes, newest first.
func (db *DB) Incidents(ctx context.Context, monitorID int64, limit int) ([]Incident, error) {
	// One plain read: a transaction here would be BEGIN IMMEDIATE and queue
	// behind the check writer.
	rows, err := db.sql.QueryContext(ctx, `
		SELECT i.id, i.start, i.ended, i.code, i.cause, n.id, n.author, n.t, n.body
		FROM (SELECT * FROM incidents WHERE monitor_id=? ORDER BY start DESC LIMIT ?) i
		LEFT JOIN notes n ON n.incident_id = i.id
		ORDER BY i.start DESC, i.id DESC, n.t, n.id`, monitorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		var in Incident
		var nid, nt sql.NullInt64
		var author, body sql.NullString
		if err := rows.Scan(&in.ID, &in.Start, &in.Ended, &in.Code, &in.Cause, &nid, &author, &nt, &body); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].ID != in.ID {
			in.Notes = []Note{}
			out = append(out, in)
		}
		if nid.Valid {
			last := &out[len(out)-1]
			last.Notes = append(last.Notes, Note{ID: nid.Int64, Author: author.String, T: nt.Int64, Body: body.String})
		}
	}
	return out, rows.Err()
}

// AddNote attaches a note to an incident, or returns ErrNotFound if it is gone.
func (db *DB) AddNote(ctx context.Context, incidentID int64, author, body string) (Note, error) {
	n := Note{Author: author, T: time.Now().Unix(), Body: body}
	err := db.sql.QueryRowContext(ctx, `INSERT INTO notes(incident_id, author, t, body)
		SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM incidents WHERE id=?1) RETURNING id`,
		incidentID, author, n.T, body).Scan(&n.ID)
	return n, one(err)
}
