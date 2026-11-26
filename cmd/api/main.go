// Command api runs blip: the HTTP server, the checker and the admin tools.
//
//	api [serve]       run the server on $PORT (default 8080)
//	api bootstrap     create or reset a root account interactively
//	api health        exit 0 if the local server answers, for container health checks
//
// The database lives at $BLIP_DB (default ./blip.db).
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ELT-Global/blip/internal/monitor"
	"github.com/ELT-Global/blip/internal/qr"
	"github.com/ELT-Global/blip/internal/server"
	"github.com/ELT-Global/blip/internal/store"
	"github.com/ELT-Global/blip/internal/totp"
)

const minInterval = 10 // seconds

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "bootstrap":
		err = withDB(func(db *store.DB) error {
			return bootstrap(context.Background(), db, os.Stdin, os.Stdout)
		})
	case "health":
		err = health()
	default:
		err = fmt.Errorf("unknown command %q (want serve, bootstrap or health)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func withDB(fn func(*store.DB) error) error {
	db, err := store.Open(env("BLIP_DB", "blip.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return withDB(func(db *store.DB) error {
		runner := monitor.New(db)
		errc := make(chan error, 2) // the checker failing to start, or the listener failing
		var bg sync.WaitGroup
		bg.Go(func() {
			if err := runner.Run(ctx); err != nil {
				errc <- fmt.Errorf("checker: %w", err)
			}
		})
		bg.Go(func() { maintain(ctx, db) })

		srv := &http.Server{
			Addr:              ":" + env("PORT", "8080"),
			Handler:           server.New(db, runner, minInterval).Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		go func() { errc <- srv.ListenAndServe() }()
		slog.Info("blip listening", "addr", srv.Addr, "db", env("BLIP_DB", "blip.db"))

		var err error
		select {
		case err = <-errc:
			srv.Close()
		case <-ctx.Done():
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = srv.Shutdown(shut) // waits for in-flight requests
			cancel()
		}
		// Stop the checker and trimmer and let them finish before the DB closes.
		stop()
		bg.Wait()
		return err
	})
}

// maintain applies the retention policy hourly.
func maintain(ctx context.Context, db *store.DB) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if res, err := db.Trim(ctx, time.Now()); err != nil {
			slog.Error("trim", "err", err)
		} else if res != (store.TrimResult{}) {
			slog.Info("trimmed", "checks", res.Checks, "hours", res.Hours, "incidents", res.Incidents)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func health() error {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + env("PORT", "8080") + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

// bootstrap asks for an email, shows a fresh TOTP secret and saves the
// account as root once the user proves their authenticator has it. Running
// it for an existing email resets that account's secret.
func bootstrap(ctx context.Context, db *store.DB, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	ask := func(prompt string) (string, error) {
		fmt.Fprint(out, prompt)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", err
			}
			return "", io.ErrUnexpectedEOF
		}
		return strings.TrimSpace(sc.Text()), nil
	}

	var email string
	for {
		v, err := ask("Admin email: ")
		if err != nil {
			return err
		}
		if a, err := mail.ParseAddress(v); err == nil && a.Address == v {
			email = v
			break
		}
		fmt.Fprintln(out, "That doesn't look like an email address.")
	}

	secret := totp.NewSecret()
	uri := totp.URI("blip", email, secret)
	fmt.Fprintln(out, "\nScan this with your authenticator app:")
	if c, err := qr.Encode([]byte(uri)); err == nil {
		fmt.Fprint(out, c.Terminal())
	}
	fmt.Fprintf(out, "\nOr enter the key manually: %s\n\n", totp.Encode(secret))

	for range 3 {
		code, err := ask("6-digit code: ")
		if err != nil {
			return err
		}
		if step, ok := totp.Verify(secret, code, time.Now()); ok {
			if err := db.UpsertRoot(ctx, email, secret, step); err != nil {
				return err
			}
			fmt.Fprintf(out, "Root account %s is ready. Sign in at /panel.\n", email)
			return nil
		}
		fmt.Fprintln(out, "Code doesn't match; check the time on your device.")
	}
	return errors.New("too many wrong codes, nothing was saved")
}
