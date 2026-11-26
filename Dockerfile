FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && mkdir -p /out/data

# BusyBox (1.5 MB) rather than scratch, so Coolify's terminal has a shell
# to run `api bootstrap` from. It also provides a writable /tmp for SQLite.
FROM busybox:1.37.0-musl
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build --chown=65534:65534 /out/data /data
USER 65534:65534
ENV BLIP_DB=/data/blip.db
VOLUME /data
# Declares the listening port so Coolify's proxy can route to it; nothing is
# published on the host.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["api", "health"]
ENTRYPOINT ["api"]
CMD ["serve"]
