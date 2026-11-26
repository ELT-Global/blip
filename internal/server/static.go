package server

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/ELT-Global/blip/web"
)

// asset is an embedded file prepared once at startup: hashed for ETags and,
// for text, pre-compressed so requests cost a map lookup and a write.
type asset struct {
	body, gz []byte
	ctype    string
	etag     string
}

// types is fixed rather than taken from package mime, whose answers depend on
// the host OS (Windows registries often map .js to text/plain).
var types = map[string]string{
	".html":        "text/html; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".webmanifest": "application/manifest+json",
}

func loadAssets() map[string]*asset {
	out := map[string]*asset{}
	fs.WalkDir(web.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".go") {
			return err
		}
		body, err := fs.ReadFile(web.FS, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		// Weak: the gzip and identity bodies share it.
		a := &asset{body: body, etag: `W/"` + base64.RawURLEncoding.EncodeToString(sum[:12]) + `"`}
		a.ctype = cmp.Or(types[path.Ext(p)], "application/octet-stream")
		if a.ctype != "image/png" {
			var buf bytes.Buffer
			gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			gz.Write(body)
			gz.Close()
			if buf.Len() < len(body) {
				a.gz = buf.Bytes()
			}
		}
		out["/"+p] = a
		return nil
	})
	return out
}

// serveStatic serves embedded files, mapping app routes to their page.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/api/"):
		fail(w, http.StatusNotFound, "not found")
		return
	case p == "/" || strings.HasPrefix(p, "/m/"):
		p = "/index.html"
	case p == "/panel" || strings.HasPrefix(p, "/panel/"):
		p = "/panel.html"
	}
	a, ok := s.static[p]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.ctype)
	h.Set("ETag", a.etag)
	h.Set("Vary", "Accept-Encoding")
	// Revalidate on every load: a 304 is cheap, and deploys show up at once.
	h.Set("Cache-Control", "no-cache")
	if p == "/sw.js" {
		h.Set("Service-Worker-Allowed", "/")
	}
	if r.Header.Get("If-None-Match") == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.body
	if a.gz != nil && acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	w.Write(body)
}
