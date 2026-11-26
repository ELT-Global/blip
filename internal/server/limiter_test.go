package server

import (
	"testing"
	"time"
)

func newTestLimiter(max int) (*limiter, *time.Time) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(max, time.Minute)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestLimiterWindow(t *testing.T) {
	l, now := newTestLimiter(2)
	if !l.attempt("a", "b") || !l.attempt("a") {
		t.Fatal("attempts within the limit were refused")
	}
	if l.attempt("a") {
		t.Error("third attempt on a was allowed")
	}
	if !l.attempt("b") {
		t.Error("b was blocked by a's attempts")
	}

	*now = now.Add(time.Minute + time.Second)
	if !l.attempt("a") {
		t.Error("a still blocked after the window")
	}

	l.attempt("a")
	l.reset("a")
	if !l.attempt("a") || !l.attempt("a") {
		t.Error("reset didn't clear a's count")
	}
}

// A refused key stops the check, so keys after it (an email after its
// blocked IP) aren't charged.
func TestLimiterStopsAtRefusedKey(t *testing.T) {
	l, _ := newTestLimiter(1)
	l.attempt("ip")
	if l.attempt("ip", "email") {
		t.Fatal("over-limit ip was allowed")
	}
	if !l.attempt("email") {
		t.Error("email was charged by a request its ip had already refused")
	}
}

// When full of live keys the limiter refuses new keys, keeps serving known
// ones, and frees space once entries expire.
func TestLimiterCap(t *testing.T) {
	l, now := newTestLimiter(5)
	l.maxKeys = 4
	for _, k := range []string{"a", "b", "c", "d"} {
		l.attempt(k)
	}
	if l.attempt("e") {
		t.Error("a new key was accepted past the cap")
	}
	if !l.attempt("a") {
		t.Error("a known key was refused at the cap")
	}
	*now = now.Add(2 * time.Minute)
	if !l.attempt("e") {
		t.Error("expired keys weren't swept to make room")
	}
	if len(l.hits) != 1 {
		t.Errorf("limiter holds %d keys after the sweep, want 1", len(l.hits))
	}
}
