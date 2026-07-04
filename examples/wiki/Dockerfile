# syntax=docker/dockerfile:1.7
#
# Chainguard (Wolfi) image for the pkijs.com documentation site.
#
# Build context = repo ROOT, not examples/wiki/: the site generates every
# page at boot from the toolkit's own `lib/*.js` @module / @primitive
# comment blocks (see examples/wiki/lib/page-generator + site.config's
# LIB_DIR → ../../lib), so the Dockerfile copies both `lib/` and
# `examples/wiki/`. Compose in this directory sets `context: ../..`.
#
# The site is stateless and zero-dependency — no database, no npm install,
# no build step. Pages are a pure function of the source, so the runtime
# image just carries the source and serves it. That keeps the image tiny
# and the attack surface minimal.
#
# Base image is digest-pinned (tag@sha256) for reproducible local builds
# and supply-chain provenance. release-container.yml resolves the rolling
# `:latest` tag to a FRESH digest at build time and passes it via the
# BASE_RUNTIME build-arg (so the scanned image == the published one and
# always carries current CVE patches); a plain local `docker build` uses
# the pinned default below. Dependabot's docker updater bumps the pin.
ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@sha256:5280e63c3d2c81366056926b79f27f70e4adbd3a03a5b45c53503eac2b722b3f

FROM ${BASE_RUNTIME} AS runtime

# Chainguard's :latest already runs as `nonroot` (UID 65532); Trivy's
# static Dockerfile checker (DS-0002) flags any image without an explicit
# USER line regardless of the base default, so restate it.
USER 65532:65532

# Non-secret defaults baked into the image. WIKI_PORT MUST agree with
# EXPOSE / HEALTHCHECK below and with release-container.yml's smoke `-p`
# and /healthz curl — the codebase-patterns wiki-port detector gates that.
ENV NODE_ENV=production \
    WIKI_PORT=3009 \
    WIKI_BIND=0.0.0.0 \
    WIKI_SITE_URL=https://pkijs.com

WORKDIR /app
# The toolkit source the page generator parses, then the site itself.
COPY --chown=65532:65532 lib ./lib
COPY --chown=65532:65532 examples/wiki ./examples/wiki

WORKDIR /app/examples/wiki
EXPOSE 3009
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.WIKI_PORT || 3009) + '/healthz').then(function(r){process.exit(r.ok?0:1)}).catch(function(){process.exit(1)})"]

# The Chainguard node image's ENTRYPOINT is ["/usr/bin/node"], so CMD is
# just the script path.
CMD ["server.js"]
