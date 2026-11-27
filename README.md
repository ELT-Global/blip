# blip

A small, fast uptime monitor: one Go binary, one SQLite file, and a
plain HTML/CSS/JS status page and admin panel (installable as a PWA).

- `/` shows monitors with 30-day uptime. Visitors see public monitors;
  signed-in users also see private ones and their target URLs.
- `/m/{id}` shows 90 days of daily blocks. Click a day to see its hours, and
  an hour to see every check, with a latency chart for the same range.
  Incidents open and close automatically; users with write access can add notes.
- Health bodies are read automatically: the IETF `health+json` draft, Spring
  Boot Actuator, MicroProfile Health, ASP.NET Core, Statuspage, Elasticsearch,
  one-word text bodies and plain JSON with familiar fields. A body saying
  `fail` marks the check down even on a 200, `warn` marks it degraded, and
  component checks, version, instance and uptime are shown to signed-in users.
  Version changes and restarts are logged as events and marked on the latency
  chart. Each monitor can point at its own fields or turn this off.
- `/panel` is the admin panel: sign in with email and an authenticator code (TOTP).
  - **Monitors**: method, URL, frequency (10s to 24h) and public/private visibility.
  - **API**: create read-only API keys, scoped to all monitors or a chosen
    few, that expire after 7 days to a year or never. The list shows when each
    key was last used; keys can be rotated or revoked at any time.
  - **Users**: invite users as Read, Write or Root. Invites are one-time setup
    links that expire after 7 days.
  - **Settings**: database size per table, retention, Trim and Vacuum.

## API

`/docs` is the API reference: a static HTML page rendered at startup from
the embedded OpenAPI 3.1 document, which is served at `/api/openapi.json`
for Postman, Insomnia or client generators. The API is read-only:

```sh
curl "$BLIP_URL/api/monitors" -H "Authorization: Bearer blip_k7m2q9xd_3f8hw2c9tqzv6n1mbxr4e5ka"
```

Without a key, requests see public monitors only. Keys are shown once; blip
stores a SHA-256 hash and the public `blip_xxxxxxxx` prefix. Tests check that
every route is either documented or deliberately internal, and that live
responses match the documented schemas.

## Deploy on Coolify

Create a resource from this repository with either build pack:

- **Docker Compose** (recommended): uses `docker-compose.yaml`, which keeps
  `/data` in a named volume and routes your domain to port 8080. Nothing is
  published on the host.
- **Dockerfile**: the image declares `EXPOSE 8080`; make sure the port
  (*Ports Exposes*) is `8080` and add a persistent storage mount at `/data`.

The container only listens on 8080 inside Coolify's network; no host port is
bound in either setup.

Then open the container's terminal in Coolify and create the first account:

```sh
api bootstrap
```

It asks for an email, shows a QR code for your authenticator app, and saves
the account once you enter a valid code. Running it again for the same email
resets that account's authenticator, which is the recovery path.

## Configuration

| Variable  | Default   | Purpose                  |
|-----------|-----------|--------------------------|
| `PORT`    | `8080`    | HTTP listen port         |
| `BLIP_DB` | `blip.db` | SQLite file (`/data/blip.db` in the image) |

Run blip behind a TLS-terminating proxy (Coolify does this) and don't expose
its port directly: session cookies are marked `Secure` when the proxy sends
`X-Forwarded-Proto: https`, and sign-in rate limits key on the client address
the proxy appends to `X-Forwarded-For`. Each address, each email and each
invite gets 10 attempts per 15-minute window, so 10 wrong codes lock that
account's sign-in until the window ends.

## Storage

Checks are stored as `(monitor, time, latency, status)` in a `WITHOUT ROWID`
table, roughly 20 bytes each on disk, and every check is also added to an hourly
rollup. By default raw checks are kept for 30 days and rollups for 400, so
history older than 30 days is quantized to hourly resolution. Resolved
incidents are deleted along with the rollups for their time. Trimming runs
hourly; adjust the limits under **Settings**.

## Development

```sh
go test ./...
go run ./cmd/api            # http://localhost:8080
go run ./cmd/api bootstrap
go generate ./web           # re-render the PNG icons from the glyph in genicons.go
```

The only dependency is `modernc.org/sqlite`, a pure-Go SQLite, so builds need
no C toolchain (`CGO_ENABLED=0`).
