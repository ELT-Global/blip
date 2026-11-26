package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ELT-Global/blip/internal/store"
)

// Set probes the stored monitor at once, and never restarts one that has
// been deleted (as when an edit races a delete).
func TestSetFollowsDatabase(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "blip.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()

	// An hourly interval: Run's first probe is randomly delayed, so only Set probes now.
	m, err := db.CreateMonitor(context.Background(), store.Monitor{Name: "x", Method: "GET", URL: target.URL, Interval: 3600})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := New(db)
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// Set is a no-op until Run has started, so retry until it takes effect.
	for deadline := time.Now().Add(5 * time.Second); hits.Load() == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Set never probed the monitor")
		}
		r.Set(m.ID)
	}
	time.Sleep(100 * time.Millisecond) // let any in-flight probe land
	before := hits.Load()

	if err := db.DeleteMonitor(context.Background(), m.ID); err != nil {
		t.Fatal(err)
	}
	r.Set(m.ID)
	time.Sleep(300 * time.Millisecond)
	if n := hits.Load(); n != before {
		t.Errorf("deleted monitor was probed again (%d hits, was %d)", n, before)
	}
}
