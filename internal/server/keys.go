package server

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ELT-Global/blip/internal/store"
)

// API keys look like blip_k7m2q9xd_3f8hw2c9tqzv6n1mbxr4e5ka: a fixed prefix,
// an 8-character public id that identifies the key in lists, and a 24-character
// secret (120 bits). Both use Crockford's lowercase base32, which has no
// ambiguous characters (no i, l, o or u), so keys survive being read aloud or
// retyped. Only the SHA-256 of the whole key is stored.
const (
	keyPrefix = "blip_"
	keyIDLen  = 8
	keyLen    = len(keyPrefix) + keyIDLen + 1 + 24
	// keyTouch is how stale last_used may get, so busy keys don't write on
	// every request.
	keyTouch = time.Minute
)

var crockford = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// newAPIKey returns a fresh key, its public prefix and the hash to store.
func newAPIKey() (key, prefix string, hash []byte) {
	b := make([]byte, 5+15)
	rand.Read(b)
	prefix = keyPrefix + crockford.EncodeToString(b[:5])
	key = prefix + "_" + crockford.EncodeToString(b[5:])
	return key, prefix, hashToken(key)
}

// viewer is who is reading the monitor API: an API key, a signed-in user, or
// (both nil) an anonymous visitor.
type viewer struct {
	user *store.User
	key  *store.APIKey
}

// sees reports whether the viewer may read m. Keys see exactly their scope;
// users see everything; visitors see public monitors.
func (v viewer) sees(m store.Monitor) bool {
	switch {
	case v.key != nil:
		return v.key.Allows(m.ID)
	case v.user != nil:
		return true
	}
	return m.Public
}

// trusted viewers see monitor targets. Note authors (email addresses) stay
// limited to signed-in users, since keys are handed to third parties.
func (v viewer) trusted() bool { return v.user != nil || v.key != nil }

// viewer identifies the requester. A request that sends an Authorization
// header is judged on that key alone: a bad key is refused, never downgraded
// to anonymous access, so integrations fail loudly.
func (s *Server) viewer(w http.ResponseWriter, r *http.Request) (viewer, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return viewer{user: s.user(r)}, true
	}
	refuse := func(msg string) (viewer, bool) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="blip"`)
		fail(w, http.StatusUnauthorized, msg)
		return viewer{}, false
	}
	scheme, tok, _ := strings.Cut(auth, " ")
	tok = strings.ToLower(strings.TrimSpace(tok))
	if !strings.EqualFold(scheme, "Bearer") || len(tok) != keyLen || !strings.HasPrefix(tok, keyPrefix) {
		return refuse("invalid API key")
	}
	k, err := s.db.KeyByHash(r.Context(), hashToken(tok))
	if errors.Is(err, store.ErrNotFound) {
		return refuse("invalid API key")
	}
	if err != nil {
		failErr(w, err)
		return viewer{}, false
	}
	now := time.Now()
	if k.Expired(now) {
		return refuse("API key has expired")
	}
	if k.LastUsed == nil || now.Unix()-*k.LastUsed >= int64(keyTouch.Seconds()) {
		if err := s.db.TouchKey(r.Context(), k.ID, now); err != nil {
			slog.Error("touch api key", "err", err)
		}
	}
	return viewer{key: &k}, true
}

// keyOwner limits key management to the caller's own keys; root manages all.
func keyOwner(r *http.Request) int64 {
	if u := current(r); u.Role < store.RoleRoot {
		return u.ID
	}
	return 0
}

// newKey is an API key as returned once, at creation or rotation.
type newKey struct {
	store.APIKey
	Key string `json:"key"`
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.db.Keys(r.Context(), keyOwner(r))
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, ks)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string  `json:"name"`
		TTLDays     int     `json:"ttl_days"`
		AllMonitors bool    `json:"all_monitors"`
		Monitors    []int64 `json:"monitors"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	slices.Sort(in.Monitors)
	in.Monitors = slices.Compact(in.Monitors)
	var msg string
	switch {
	case in.Name == "" || utf8.RuneCountInString(in.Name) > 100:
		msg = "name must be 1-100 characters"
	case in.TTLDays < 0 || in.TTLDays > 3650:
		msg = "ttl_days must be between 0 (never expires) and 3650"
	case in.AllMonitors && len(in.Monitors) > 0:
		msg = "choose all_monitors or a list of monitors, not both"
	case !in.AllMonitors && len(in.Monitors) == 0:
		msg = "choose at least one monitor, or all_monitors"
	case len(in.Monitors) > 1000:
		msg = "a key can list at most 1000 monitors"
	}
	if msg != "" {
		fail(w, http.StatusBadRequest, msg)
		return
	}
	key, prefix, hash := newAPIKey()
	k, err := s.db.CreateKey(r.Context(), store.APIKey{
		Name: in.Name, TTLDays: in.TTLDays, AllMonitors: in.AllMonitors, Monitors: in.Monitors, UserID: current(r).ID,
	}, prefix, hash)
	if errors.Is(err, store.ErrUnknownMonitor) {
		fail(w, http.StatusBadRequest, "one of the monitors does not exist")
		return
	}
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusCreated, newKey{k, key})
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	key, prefix, hash := newAPIKey()
	k, err := s.db.RotateKey(r.Context(), id, keyOwner(r), prefix, hash)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(r, w, http.StatusOK, newKey{k, key})
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteKey(r.Context(), id, keyOwner(r)); err != nil {
		failErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
