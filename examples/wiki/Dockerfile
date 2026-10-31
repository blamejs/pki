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
ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@sha256:6cb70d6b2a324e491263949ea9f58938ed19031ef478e0bdb0b1810f96f8b400

FROM ${BASE_RUNTIME} AS runtime

# Chainguard's :latest already runs as `nonroot` (UID 65532); Trivy's
# static Dockerfile checker (DS-0002) flags any image without an explicit
# USER line regardless of the base default, so restate it.
USER 65532:65532

# The lowest patched Node release on each supported major line. The build
# stops when the base image's Node is older than the entry for its major, or
# when its major has no entry. scripts/check-engine-floor.js requires the
# entry for the engines.node major to equal engines.node.
ARG NODE_FLOORS=24.22.1,26.12.1
RUN ["node", "-e", "var v=process.versions.node;var f=(process.env.NODE_FLOORS||'').split(',').filter(function(s){return s.split('.')[0]===v.split('.')[0]})[0];function n(s){var p=s.split('.').map(Number);return p[0]*1e8+p[1]*1e4+p[2]}var m=!f?'NODE_FLOORS states no patched release for Node '+v.split('.')[0]:n(v)<n(f)?'Node '+v+' is older than '+f+', the patched release for its line':'';if(m){console.error(m+'. Update BASE_RUNTIME or NODE_FLOORS in examples/wiki/Dockerfile.');process.exit(1)}console.log('Node '+v+' meets floor '+f)"]

# Non-secret defaults baked into the image. WIKI_PORT MUST agree with
# EXPOSE / HEALTHCHECK below and with release-container.yml's smoke `-p`
# and /healthz curl — the codebase-patterns wiki-port detector gates that.
ENV NODE_ENV=production \
    WIKI_PORT=3009 \
    WIKI_BIND=0.0.0.0 \
    WIKI_SITE_URL=https://pkijs.com

WORKDIR /app
# The toolkit source the page generator parses, then the site itself. README.md
# sits at the repo root (resolved as LIB_DIR/../README.md) and backs the
# generated Overview page, so it must land at /app/README.md alongside lib/.
COPY --chown=65532:65532 lib ./lib
COPY --chown=65532:65532 README.md ./README.md
COPY --chown=65532:65532 examples/wiki ./examples/wiki

WORKDIR /app/examples/wiki
EXPOSE 3009
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.WIKI_PORT || 3009) + '/healthz').then(function(r){process.exit(r.ok?0:1)}).catch(function(){process.exit(1)})"]

# The Chainguard node image's ENTRYPOINT is ["/usr/bin/node"], so CMD is
# just the script path.
CMD ["server.js"]
