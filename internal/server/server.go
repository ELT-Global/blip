// Package server exposes blip's JSON API and serves the embedded web UI.
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ELT-Global/blip/internal/monitor"
	"github.com/ELT-Global/blip/internal/store"
)

// Server holds the dependencies shared by all handlers.
type Server struct {
	db          *store.DB
	runner      *monitor.Runner
	minInterval int
	limiter     *limiter
	static      map[string]*asset
	spec, docs  *asset
	routes      []string // registered patterns, for the spec drift test
}

// New builds a server. minInterval is the shortest check frequency, in
// seconds, that monitors may use.
func New(db *store.DB, runner *monitor.Runner, minInterval int) *Server {
	s := &Server{db: db, runner: runner, minInterval: minInterval, limiter: newLimiter(10, 15*time.Minute), static: loadAssets()}
	s.spec, s.docs = loadDocs()
	return s
}

// Handler returns the HTTP handler for the API and the embedded UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes = nil
	h := func(pattern string, fn http.HandlerFunc) {
		s.routes = append(s.routes, pattern)
		mux.HandleFunc(pattern, fn)
	}

	h("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	h("GET /api/me", s.me)
	h("POST /api/login", s.login)
	h("POST /api/logout", s.logout)
	h("POST /api/enroll/info", s.enrollInfo)
	h("POST /api/enroll", s.enroll)

	h("GET /api/monitors", s.listMonitors)
	h("GET /api/monitors/{id}", s.getMonitor)
	h("GET /api/monitors/{id}/hours", s.monitorHours)
	h("GET /api/monitors/{id}/checks", s.monitorChecks)
	h("GET /api/monitors/{id}/incidents", s.monitorIncidents)
	h("POST /api/monitors", s.need(store.RoleWrite, s.createMonitor))
	h("PUT /api/monitors/{id}", s.need(store.RoleWrite, s.updateMonitor))
	h("DELETE /api/monitors/{id}", s.need(store.RoleWrite, s.deleteMonitor))
	h("POST /api/incidents/{id}/notes", s.need(store.RoleWrite, s.addNote))

	h("GET /api/keys", s.need(store.RoleRead, s.listKeys))
	h("POST /api/keys", s.need(store.RoleRead, s.createKey))
	h("POST /api/keys/{id}/rotate", s.need(store.RoleRead, s.rotateKey))
	h("DELETE /api/keys/{id}", s.need(store.RoleRead, s.deleteKey))

	h("GET /api/openapi.json", s.serveSpec)
	h("GET /docs", s.serveDocs)

	h("GET /api/users", s.need(store.RoleRoot, s.listUsers))
	h("POST /api/users", s.need(store.RoleRoot, s.inviteUser))
	h("PUT /api/users/{id}", s.need(store.RoleRoot, s.setRole))
	h("DELETE /api/users/{id}", s.need(store.RoleRoot, s.deleteUser))

	h("GET /api/db", s.need(store.RoleRoot, s.dbStats))
	h("PUT /api/db/retention", s.need(store.RoleRoot, s.setRetention))
	h("POST /api/db/trim", s.need(store.RoleRoot, s.trim))
	h("POST /api/db/vacuum", s.need(store.RoleRoot, s.vacuum))

	h("GET /", s.serveStatic)

	return secure(mux)
}

// secure sets defensive headers and rejects cross-origin writes. Session
// cookies are SameSite=Lax, and requiring a matching Origin on mutations
// closes the remaining CSRF gap.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					fail(w, http.StatusForbidden, "cross-origin request")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

// need wraps a handler so it only runs for a signed-in user with at least role.
func (s *Server) need(role store.Role, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.user(r)
		switch {
		case u == nil:
			fail(w, http.StatusUnauthorized, "sign in required")
		case u.Role < role:
			fail(w, http.StatusForbidden, "requires "+role.String()+" permission")
		default:
			fn(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
		}
	}
}

func current(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxKey{}).(*store.User)
	return u
}

type apiError struct {
	Error string `json:"error"`
}

func fail(w http.ResponseWriter, code int, msg string) { reply(nil, w, code, apiError{msg}) }

// failErr maps store errors to HTTP statuses and logs anything unexpected.
func failErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrExists):
		fail(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrLastRoot):
		fail(w, http.StatusConflict, err.Error())
	default:
		slog.Error("request failed", "err", err)
		fail(w, http.StatusInternalServerError, "internal error")
	}
}

var gzPool = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}

// reply writes v as JSON, gzipped when the client accepts it and it is
// large enough to benefit.
func reply(r *http.Request, w http.ResponseWriter, code int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		slog.Error("encode response", "err", err)
		code = http.StatusInternalServerError
		buf.Reset()
		buf.WriteString(`{"error":"internal error"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	if r != nil && buf.Len() > 1024 && acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		h.Add("Vary", "Accept-Encoding")
		w.WriteHeader(code)
		gz := gzPool.Get().(*gzip.Writer)
		gz.Reset(w)
		gz.Write(buf.Bytes())
		gz.Close()
		gzPool.Put(gz)
		return
	}
	w.WriteHeader(code)
	w.Write(buf.Bytes())
}

func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

// decode reads a small JSON body into v, rejecting unknown fields.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusNotFound, "not found")
		return 0, false
	}
	return id, true
}

// queryInt reads an integer query parameter, falling back to def.
func queryInt(r *http.Request, name string, def int64) int64 {
	if v, err := strconv.ParseInt(r.URL.Query().Get(name), 10, 64); err == nil {
		return v
	}
	return def
}
