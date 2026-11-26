package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/ELT-Global/blip/internal/qr"
	"github.com/ELT-Global/blip/internal/store"
	"github.com/ELT-Global/blip/internal/totp"
)

const (
	cookieName = "blip_session"
	sessionTTL = 30 * 24 * time.Hour
	inviteTTL  = 7 * 24 * time.Hour
	issuer     = "blip"
)

// newToken returns a random URL-safe token and the hash stored in its place.
func newToken() (string, []byte) {
	b := make([]byte, 32)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	return tok, hashToken(tok)
}

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// user returns the signed-in user, or nil.
func (s *Server) user(r *http.Request) *store.User {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	u, err := s.db.SessionUser(r.Context(), hashToken(c.Value))
	if err != nil {
		return nil
	}
	return &u
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	reply(r, w, http.StatusOK, s.user(r)) // null when signed out
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Code string }
	if !decode(w, r, &in) {
		return
	}
	email := strings.TrimSpace(in.Email)
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email || len(email) > 254 {
		fail(w, http.StatusUnauthorized, "invalid email or code")
		return
	}
	// Limiting per email as well as per IP caps guessing even from many
	// addresses, at the cost of letting an attacker briefly lock an account.
	// The IP key goes first so an address already over its limit can't
	// spend attempts against any email.
	keys := []string{"ip:" + clientIP(r), "email:" + strings.ToLower(email)}
	if !s.limiter.attempt(keys...) {
		fail(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	u, err := s.db.UserByEmail(r.Context(), email)
	if err == nil {
		if step, ok := totp.Verify(u.Secret, strings.TrimSpace(in.Code), time.Now()); ok {
			err = s.db.UseStep(r.Context(), u.ID, step) // fails on replay
		} else {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		fail(w, http.StatusUnauthorized, "invalid email or code")
		return
	}
	s.limiter.reset(keys...)
	if err := s.startSession(w, r, u.ID); err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, u)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	tok, hash := newToken()
	exp := time.Now().Add(sessionTTL)
	if err := s.db.CreateSession(r.Context(), hash, userID, exp); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r),
	})
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.db.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isHTTPS(r)})
	w.WriteHeader(http.StatusNoContent)
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// clientIP prefers the address the nearest proxy saw (the last
// X-Forwarded-For entry), since deployments sit behind one.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(xff[strings.LastIndexByte(xff, ',')+1:])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type enrollment struct {
	Email  string `json:"email"`
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"` // SVG markup
}

func newEnrollment(email string, secret []byte) enrollment {
	e := enrollment{Email: email, Secret: totp.Encode(secret), URI: totp.URI(issuer, email, secret)}
	if c, err := qr.Encode([]byte(e.URI)); err == nil {
		e.QR = c.SVG()
	}
	return e
}

// Invite tokens travel in request bodies, never URLs, so they stay out of
// proxy access logs.

func (s *Server) enrollInfo(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token string }
	if !decode(w, r, &in) {
		return
	}
	u, err := s.db.UserByInvite(r.Context(), hashToken(in.Token))
	if err != nil {
		fail(w, http.StatusNotFound, "invite is invalid or has expired")
		return
	}
	reply(r, w, http.StatusOK, newEnrollment(u.Email, u.Secret))
}

// enroll confirms the user scanned their secret, activates the account and
// signs them in.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token, Code string }
	if !decode(w, r, &in) {
		return
	}
	// Look the invite up before limiting: unknown 256-bit tokens can't be
	// guessed, and limiting them would let junk requests fill the limiter.
	hash := hashToken(in.Token)
	u, err := s.db.UserByInvite(r.Context(), hash)
	if err != nil {
		fail(w, http.StatusNotFound, "invite is invalid or has expired")
		return
	}
	if !s.limiter.attempt("invite:" + string(hash)) {
		fail(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	step, ok := totp.Verify(u.Secret, strings.TrimSpace(in.Code), time.Now())
	if !ok {
		fail(w, http.StatusUnauthorized, "code does not match, check your authenticator's clock")
		return
	}
	if err := s.db.ActivateUser(r.Context(), u.ID, step); err != nil {
		failErr(w, err)
		return
	}
	if err := s.startSession(w, r, u.ID); err != nil {
		failErr(w, err)
		return
	}
	u.Pending = false
	reply(r, w, http.StatusOK, u)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.db.Users(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, us)
}

func (s *Server) inviteUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string
		Role  store.Role
	}
	if !decode(w, r, &in) {
		return
	}
	addr, err := mail.ParseAddress(in.Email)
	if err != nil || addr.Address != strings.TrimSpace(in.Email) {
		fail(w, http.StatusBadRequest, "invalid email")
		return
	}
	if in.Role < store.RoleRead || in.Role > store.RoleRoot {
		fail(w, http.StatusBadRequest, "role must be read, write or root")
		return
	}
	tok, hash := newToken()
	u, err := s.db.InviteUser(r.Context(), addr.Address, in.Role, totp.NewSecret(), hash, time.Now().Add(inviteTTL))
	if err != nil {
		failErr(w, err)
		return
	}
	// The token travels in the fragment so it never reaches server logs.
	reply(r, w, http.StatusCreated, struct {
		store.User
		Invite string `json:"invite"`
	}{u, "/panel/enroll#" + tok})
}

func (s *Server) setRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct{ Role store.Role }
	if !decode(w, r, &in) {
		return
	}
	if in.Role < store.RoleRead || in.Role > store.RoleRoot {
		fail(w, http.StatusBadRequest, "role must be read, write or root")
		return
	}
	if err := s.db.SetRole(r.Context(), id, in.Role); err != nil {
		failErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteUser(r.Context(), id); err != nil {
		failErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// limiter caps attempts per key in a fixed window. Counting happens before
// the attempt is checked, so parallel requests cannot slip past the cap.
type limiter struct {
	mu        sync.Mutex
	maxKeys   int // bounds memory; see attempt
	max       int
	window    time.Duration
	now       func() time.Time
	hits      map[string]*hit
	lastSweep time.Time
}

type hit struct {
	n     int
	reset time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, maxKeys: 100_000, window: window, now: time.Now, hits: map[string]*hit{}}
}

// attempt counts an attempt against each key in order and reports whether
// all are within the limit. It stops at the first key over its limit, so
// later keys aren't charged for refused requests. Once maxKeys live keys
// exist, new keys are refused until some expire: failing closed beats
// running out of memory.
func (l *limiter) attempt(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > l.maxKeys/2 && now.Sub(l.lastSweep) > time.Minute {
		l.lastSweep = now
		for k, h := range l.hits {
			if now.After(h.reset) {
				delete(l.hits, k)
			}
		}
	}
	for _, k := range keys {
		h, found := l.hits[k]
		if !found || now.After(h.reset) {
			if !found && len(l.hits) >= l.maxKeys {
				return false
			}
			h = &hit{reset: now.Add(l.window)}
			l.hits[k] = h
		}
		if h.n++; h.n > l.max {
			return false
		}
	}
	return true
}

// reset forgets the keys' attempts, after a success.
func (l *limiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.hits, k)
	}
}
