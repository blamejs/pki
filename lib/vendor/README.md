# Vendored dependencies

`@blamejs/pki` ships with **zero npm runtime dependencies**, and it currently
vendors **nothing** — this directory holds only the manifest.

## Native-first crypto

The toolkit's cryptography runs entirely on Node's built-in `node:crypto`. The
engine floor (Node `>=24.18`) links OpenSSL 3.5, which provides:

- the full classical set — RSA (PKCS#1 v1.5, PSS, OAEP), ECDSA, EdDSA
  (Ed25519/Ed448), ECDH (incl. X25519/X448), AES (GCM/CBC/CTR/KW), HMAC, HKDF,
  PBKDF2, and the SHA-1/2/3 family; and
- the FIPS post-quantum set — **ML-KEM** (FIPS 203), **ML-DSA** (FIPS 204), and
  **SLH-DSA** (FIPS 205).

A platform built-in ships **zero bytes**, has **nothing to hash-pin or keep
current**, and is **OpenSSL/NSS-interoperable by construction** — which is what
the toolkit's interoperability gate needs. So there is no reason to vendor a
crypto library when the runtime already provides the primitive.

## When something IS vendored

A package is added here **only** when a specific operation is confirmed missing
from the engine floor (for example, a pure-JS fallback for a post-quantum
operation whose JS binding is absent on a supported Node version, or a
cross-check reference used only in tests). When that happens:

- `MANIFEST.json` records the package's version, SPDX license, upstream author,
  source URL, exported surface, bundler invocation, CPE, and pinned SHA-256, so
  any tampering is detectable and `scripts/check-vendor-currency.js` can gate
  version drift.
- The top-level `NOTICE` gains the component's attribution.
- The reason and the re-open condition are recorded alongside the entry — a
  vendored dependency is a deliberate, justified exception to native-first, not
  a default.

Bundles, when present, are produced with
`esbuild --format=cjs --minify --platform=node` against the pinned upstream
version; refreshing one recomputes its SHA-256 and updates the bytes and the
matching `hashes.server` entry in the same change.
