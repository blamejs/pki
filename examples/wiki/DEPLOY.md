# Deploying the pkijs.com docs site

The documentation site is a **stateless, zero-dependency** container: every
page is generated at boot from the toolkit's `lib/` `@module` / `@primitive`
comment blocks. There is no database, no admin login, no writable state —
a restart or a fresh image always reflects the current source. That makes
deployment simple and the runtime hardened (nonroot, all capabilities
dropped, no persistent data to protect).

The container listens on **port 3009** (`WIKI_PORT`).

## Run it locally

```sh
cd examples/wiki
docker compose up --build
# → http://localhost:3009
```

`docker compose` builds from the repo root (the site needs the toolkit
`lib/` to generate its pages) and serves on 3009. Health: `GET /healthz`
returns `{"status":"ok"}`.

## Production (TLS on pkijs.com)

The production overlay pulls the published GHCR image and puts Caddy in
front for automatic Let's Encrypt TLS:

```sh
cd examples/wiki
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Point `pkijs.com` and `www.pkijs.com` A/AAAA records at the host, open
`80`/`443` inbound, and Caddy issues certificates on first boot. Caddy
forwards to the wiki container on the internal network — the wiki port is
never exposed on the host. See `Caddyfile` for the reverse-proxy config.

## Environment variables

| Variable        | Default              | Purpose                                  |
|-----------------|----------------------|------------------------------------------|
| `WIKI_PORT`     | `3009`               | HTTP listen port                         |
| `WIKI_BIND`     | `0.0.0.0`            | Bind address                             |
| `WIKI_SITE_URL` | `https://pkijs.com`  | Canonical public URL used in page markup |

No secrets are ever baked into the image.

## Published image

`ghcr.io/blamejs/pki-wiki` — multi-arch (`linux/amd64`, `linux/arm64`),
built, Trivy-scanned, and cosign-signed on every `v*` tag by
`.github/workflows/release-container.yml`. The base image is a
digest-pinned Chainguard (Wolfi) node image, resolved to a fresh digest at
build time so the scanned image is the published image.

## Updating

The site tracks the source: a new toolkit release republishes the image
with the current API surface. To refresh a running production deployment,
`docker compose pull && docker compose up -d`.
