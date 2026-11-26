package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role is a user's permission level. Each role includes the ones below it.
type Role int

const (
	RoleRead  Role = 1 // see private monitors
	RoleWrite Role = 2 // manage monitors, add incident notes
	RoleRoot  Role = 3 // manage users and the database
)

var roleNames = [...]string{RoleRead: "read", RoleWrite: "write", RoleRoot: "root"}

func (r Role) String() string {
	if r < RoleRead || r > RoleRoot {
		return "invalid"
	}
	return roleNames[r]
}

func (r Role) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Role) UnmarshalText(b []byte) error {
	for i, n := range roleNames {
		if n != "" && n == string(b) {
			*r = Role(i)
			return nil
		}
	}
	return fmt.Errorf("invalid role %q", b)
}

// User is an account. Secret is the raw TOTP key.
type User struct {
	ID      int64  `json:"id"`
	Email   string `json:"email"`
	Role    Role   `json:"role"`
	Pending bool   `json:"pending"` // invited but not yet enrolled
	Created int64  `json:"created"`

	Secret   []byte `json:"-"`
	LastStep int64  `json:"-"`
}

const userCols = "id, email, role, invite IS NOT NULL, created, secret, last_step"

func scanUser(s interface{ Scan(...any) error }) (User, error) {
	var u User
	err := s.Scan(&u.ID, &u.Email, &u.Role, &u.Pending, &u.Created, &u.Secret, &u.LastStep)
	return u, err
}

// UpsertRoot creates email as an active root user, or resets an existing
// user to root with a new secret. step is the TOTP step already used to
// confirm the secret, so that code cannot be replayed to sign in. Existing
// sessions are revoked, since a reset is how a compromised account recovers.
func (db *DB) UpsertRoot(ctx context.Context, email string, secret []byte, step int64) error {
	return db.tx(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRow(`
			INSERT INTO users(email, role, secret, last_step, created) VALUES(?, ?, ?, ?, ?)
			ON CONFLICT(email) DO UPDATE SET role=excluded.role, secret=excluded.secret,
				last_step=excluded.last_step, invite=NULL, invite_exp=NULL
			RETURNING id`,
			email, RoleRoot, secret, step, time.Now().Unix()).Scan(&id)
		if err != nil {
			return err
		}
		_, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", id)
		return err
	})
}

// InviteUser creates a pending user who must enroll with the invite token
// (stored as a hash) before it expires.
func (db *DB) InviteUser(ctx context.Context, email string, role Role, secret, inviteHash []byte, exp time.Time) (User, error) {
	row := db.sql.QueryRowContext(ctx, `
		INSERT INTO users(email, role, secret, invite, invite_exp, created) VALUES(?, ?, ?, ?, ?, ?)
		RETURNING `+userCols,
		email, role, secret, inviteHash, exp.Unix(), time.Now().Unix())
	u, err := scanUser(row)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		err = ErrExists
	}
	return u, err
}

// ErrExists is returned when inviting an email that already has an account.
var ErrExists = errors.New("user already exists")

// UserByInvite returns the pending user holding an unexpired invite.
func (db *DB) UserByInvite(ctx context.Context, inviteHash []byte) (User, error) {
	row := db.sql.QueryRowContext(ctx,
		"SELECT "+userCols+" FROM users WHERE invite = ? AND invite_exp > ?", inviteHash, time.Now().Unix())
	u, err := scanUser(row)
	return u, one(err)
}

// ActivateUser completes enrollment, recording the TOTP step used to confirm it.
func (db *DB) ActivateUser(ctx context.Context, id, step int64) error {
	return affected(db.sql.ExecContext(ctx,
		"UPDATE users SET invite=NULL, invite_exp=NULL, last_step=? WHERE id=? AND invite IS NOT NULL", step, id))
}

// UserByEmail returns an enrolled user.
func (db *DB) UserByEmail(ctx context.Context, email string) (User, error) {
	row := db.sql.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE email = ? AND invite IS NULL", email)
	u, err := scanUser(row)
	return u, one(err)
}

// UseStep records a TOTP step as consumed. It fails if the step is not newer
// than the last one used, which blocks code replay.
func (db *DB) UseStep(ctx context.Context, id, step int64) error {
	return affected(db.sql.ExecContext(ctx, "UPDATE users SET last_step=? WHERE id=? AND last_step < ?", step, id, step))
}

// Users returns all users, including pending invites, ordered by email.
func (db *DB) Users(ctx context.Context) ([]User, error) {
	rows, err := db.sql.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY email")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var us []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		us = append(us, u)
	}
	return us, rows.Err()
}

// SetRole changes a user's role. Demoting the last root is refused.
func (db *DB) SetRole(ctx context.Context, id int64, role Role) error {
	return db.tx(ctx, func(tx *sql.Tx) error {
		if role != RoleRoot {
			if err := keepRoot(tx, id); err != nil {
				return err
			}
		}
		return affected(tx.Exec("UPDATE users SET role=? WHERE id=?", role, id))
	})
}

// DeleteUser removes a user and their sessions. Deleting the last root is refused.
func (db *DB) DeleteUser(ctx context.Context, id int64) error {
	return db.tx(ctx, func(tx *sql.Tx) error {
		if err := keepRoot(tx, id); err != nil {
			return err
		}
		return affected(tx.Exec("DELETE FROM users WHERE id=?", id))
	})
}

// ErrLastRoot prevents locking everyone out of user management.
var ErrLastRoot = errors.New("cannot remove the last root user")

func keepRoot(tx *sql.Tx, id int64) error {
	var others int
	err := tx.QueryRow("SELECT count(*) FROM users WHERE role=? AND invite IS NULL AND id<>?", RoleRoot, id).Scan(&others)
	if err != nil {
		return err
	}
	if others == 0 {
		return ErrLastRoot
	}
	return nil
}

// CreateSession stores a session token hash for a user.
func (db *DB) CreateSession(ctx context.Context, tokenHash []byte, userID int64, exp time.Time) error {
	_, err := db.sql.ExecContext(ctx, "INSERT INTO sessions(token, user_id, exp) VALUES(?, ?, ?)", tokenHash, userID, exp.Unix())
	return err
}

// SessionUser resolves an unexpired session to its user.
func (db *DB) SessionUser(ctx context.Context, tokenHash []byte) (User, error) {
	row := db.sql.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.role, u.invite IS NOT NULL, u.created, u.secret, u.last_step
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = ? AND s.exp > ?`, tokenHash, time.Now().Unix())
	u, err := scanUser(row)
	return u, one(err)
}

// DeleteSession ends a session.
func (db *DB) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM sessions WHERE token = ?", tokenHash)
	return err
}
