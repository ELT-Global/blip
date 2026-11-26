// Package monitor schedules HTTP checks and records their results.
//
// Each monitor runs in its own goroutine on a timer. Results flow through a
// single channel to one writer goroutine that batches them into SQLite
// transactions, so probes never contend on the database.
package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/ELT-Global/blip/internal/store"
)

const (
	maxTimeout = 30 * time.Second
	maxBody    = 64 << 10 // read at most this much so latency covers the response
	maxBatch   = 512
)

// Runner owns the probe goroutines and the latest result of every monitor.
type Runner struct {
	db      *store.DB
	client  *http.Client
	results chan store.Check

	mu     sync.Mutex
	jobs   map[int64]context.CancelFunc
	latest map[int64]store.Check
	ctx    context.Context
	wg     sync.WaitGroup
}

// New returns a runner that records to db. Call Run to start it.
func New(db *store.DB) *Runner {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 2
	t.ResponseHeaderTimeout = maxTimeout
	return &Runner{
		db: db,
		client: &http.Client{
			Transport: t,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		results: make(chan store.Check, maxBatch),
		jobs:    map[int64]context.CancelFunc{},
		latest:  map[int64]store.Check{},
	}
}

// Run starts all stored monitors and blocks until ctx is cancelled and every
// pending result is written.
func (r *Runner) Run(ctx context.Context) error {
	// Hold the lock across loading so a concurrent Set can't slip between
	// the query and r.ctx becoming available.
	r.mu.Lock()
	ms, err := r.db.Monitors(ctx)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	r.ctx = ctx
	for _, m := range ms {
		if c, err := r.db.LastCheck(ctx, m.ID); err == nil {
			r.latest[m.ID] = c
		}
		// Spread first probes over the interval so a restart doesn't burst.
		r.startLocked(m, rand.N(time.Duration(m.Interval)*time.Second))
	}
	r.mu.Unlock()

	done := make(chan struct{})
	go func() { r.write(); close(done) }()
	<-ctx.Done()
	// Set checks ctx and calls wg.Add under r.mu; passing through the lock
	// once means no Add can follow the Wait below.
	r.mu.Lock()
	r.mu.Unlock()
	r.wg.Wait()
	close(r.results)
	<-done
	return nil
}

// Set starts or restarts a monitor, probing it immediately. It runs the
// stored row rather than a caller's copy, so concurrent edits settle on the
// latest one and a deleted monitor is never restarted.
func (r *Runner) Set(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil || r.ctx.Err() != nil {
		return
	}
	if m, err := r.db.Monitor(r.ctx, id); err == nil {
		r.startLocked(m, 0)
	}
}

// Remove stops a monitor and forgets its latest result.
func (r *Runner) Remove(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancel, ok := r.jobs[id]; ok {
		cancel()
		delete(r.jobs, id)
	}
	delete(r.latest, id)
}

// Latest returns the most recent result for a monitor.
func (r *Runner) Latest(id int64) (store.Check, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.latest[id]
	return c, ok
}

func (r *Runner) startLocked(m store.Monitor, delay time.Duration) {
	if cancel, ok := r.jobs[m.ID]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(r.ctx)
	r.jobs[m.ID] = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.loop(ctx, m, delay)
	}()
}

func (r *Runner) loop(ctx context.Context, m store.Monitor, delay time.Duration) {
	every := time.Duration(m.Interval) * time.Second
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		c := r.probe(ctx, m, min(every, maxTimeout))
		if ctx.Err() != nil {
			return // stopped mid-probe; the result is meaningless
		}
		r.results <- c
		timer.Reset(every)
	}
}

func (r *Runner) probe(ctx context.Context, m store.Monitor, timeout time.Duration) store.Check {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	c := store.Check{MonitorID: m.ID, T: start.Unix()}
	req, err := http.NewRequestWithContext(ctx, m.Method, m.URL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "blip/1")
		var resp *http.Response
		if resp, err = r.client.Do(req); err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
			resp.Body.Close()
			c.Code = resp.StatusCode
			if !store.Up(c.Code) {
				c.Err = resp.Status
			}
		}
	}
	c.Ms = int(time.Since(start).Milliseconds())
	if err != nil {
		c.Code = classify(err)
		c.Err = cause(c.Code, err)
	}
	return c
}

// cause describes a failure without the target URL or host, since incident
// causes are shown on public status pages.
func cause(code int, err error) string {
	switch code {
	case store.CodeTimeout:
		return "Timed out"
	case store.CodeDNS:
		return "DNS lookup failed"
	case store.CodeRefused:
		return "Connection refused"
	case store.CodeTLS:
		return "TLS certificate error"
	}
	for {
		next := errors.Unwrap(err)
		if next == nil {
			break
		}
		err = next
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// wsaeconnrefused is Windows' "connection refused", which syscall.ECONNREFUSED
// does not match there.
const wsaeconnrefused = 10061

// classify maps transport errors to the compact codes stored with checks.
func classify(err error) int {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, http.ErrHandlerTimeout), isTimeout(err):
		return store.CodeTimeout
	case errors.As(err, &dns):
		return store.CodeDNS
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.Errno(wsaeconnrefused)):
		return store.CodeRefused
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &invalid):
		return store.CodeTLS
	}
	return store.CodeError
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// write drains results in batches: it blocks for one, then takes whatever
// else is already queued, so latency stays low and bursts share a commit.
func (r *Runner) write() {
	batch := make([]store.Check, 0, maxBatch)
	for c := range r.results {
		batch = append(batch[:0], c)
	drain:
		for len(batch) < maxBatch {
			select {
			case c, ok := <-r.results:
				if !ok {
					break drain
				}
				batch = append(batch, c)
			default:
				break drain
			}
		}
		// Use a fresh context: shutdown must not drop the final batch.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := r.db.Record(ctx, batch)
		cancel()
		if err != nil {
			slog.Error("record checks", "n", len(batch), "err", err)
			continue
		}
		r.mu.Lock()
		for _, c := range batch {
			if _, ok := r.jobs[c.MonitorID]; ok {
				r.latest[c.MonitorID] = c
			}
		}
		r.mu.Unlock()
	}
}
