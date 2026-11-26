package main

import (
	"context"
	"encoding/base32"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ELT-Global/blip/internal/store"
	"github.com/ELT-Global/blip/internal/totp"
)

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

var promptRe = regexp.MustCompile(`(Admin email|6-digit code): $`)

// runBootstrap drives the interactive bootstrap, answering each prompt with
// answer(prompt, output so far). A stalled run fails instead of hanging.
func runBootstrap(t *testing.T, db *store.DB, answer func(prompt, out string) string) (string, error) {
	t.Helper()
	inR, inW := io.Pipe()
	defer inR.Close() // unblocks any pending answer if bootstrap returns early
	var out syncBuf
	errc := make(chan error, 1)
	go func() { errc <- bootstrap(context.Background(), db, inR, &out) }()
	answered := 0
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-errc:
			return out.String(), err
		case <-deadline:
			t.Fatalf("bootstrap stalled; output so far:\n%s", out.String())
		case <-time.After(5 * time.Millisecond):
		}
		s := out.String()
		if m := promptRe.FindStringSubmatch(s); m != nil && strings.Count(s, ": ") > answered {
			answered = strings.Count(s, ": ")
			line := answer(m[1], s)
			go io.WriteString(inW, line+"\n")
		}
	}
}

var keyRe = regexp.MustCompile(`manually: ([A-Z2-7]+)`)

func TestBootstrap(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "blip.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var step int64
	emails, codes := 0, 0
	out, err := runBootstrap(t, db, func(prompt, out string) string {
		switch prompt {
		case "Admin email":
			if emails++; emails == 1 {
				return "not an email"
			}
			return "admin@example.com"
		default:
			if codes++; codes == 1 {
				return "000000" // wrong first, to exercise the retry
			}
			key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(keyRe.FindStringSubmatch(out)[1])
			step = totp.Step(time.Now())
			return totp.Code(key, step)
		}
	})
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}
	if !strings.Contains(out, "doesn't look like an email") || !strings.Contains(out, "█") || !strings.Contains(out, "ready") {
		t.Errorf("output lacks the email retry, QR code or confirmation:\n%s", out)
	}
	u, err := db.UserByEmail(context.Background(), "admin@example.com")
	if err != nil || u.Role != store.RoleRoot {
		t.Fatalf("user = %+v, %v; want root", u, err)
	}
	// The confirmation code is consumed, so it can't be replayed to sign in.
	if u.LastStep != step {
		t.Errorf("last used step = %d, want the confirmation's %d", u.LastStep, step)
	}
}

func TestBootstrapGivesUpWithoutSaving(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "blip.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = runBootstrap(t, db, func(prompt, _ string) string {
		if prompt == "Admin email" {
			return "admin@example.com"
		}
		return "000000"
	})
	if err == nil {
		t.Fatal("bootstrap succeeded with wrong codes")
	}
	if _, err := db.UserByEmail(context.Background(), "admin@example.com"); err != store.ErrNotFound {
		t.Errorf("user lookup err = %v, want ErrNotFound", err)
	}
}
