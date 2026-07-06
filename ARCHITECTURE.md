# @blamejs/pki architecture

A contributor's guide to where things live and why the layers are ordered the way they are. This doc is the orientation map; the contributor disciplines are in [CONTRIBUTING.md](CONTRIBUTING.md) and the capability roadmap is in [ROADMAP.md](ROADMAP.md).

## Top-level layout

```
pki/
├── index.js          # Single npm export — `var pki = require("@blamejs/pki")`
├── lib/              # Toolkit source (the SHIPPED code)
│   ├── constants.js        # C.TIME / C.BYTES / LIMITS / version — bounds and scale helpers
│   ├── framework-error.js  # PkiError base + defineClass + per-domain error classes
│   ├── asn1-der.js         # Strict DER/BER codec: decode / encode / build.* / read.* / TAGS
│   ├── oid.js              # OID registry: name / byName / register / toArcs / toDER / …
│   ├── webcrypto.js        # W3C SubtleCrypto engine over node:crypto — PQC-first, classical-capable
│   ├── x509.js             # X.509 certificate model: parse / pemDecode / pemEncode
│   └── vendor/             # MANIFEST.json only — crypto is node:crypto; nothing vendored (see vendor/README.md)
├── examples/wiki/    # Source-driven docs site (lives at pkijs.com)
├── test/             # Layered tests (smoke runner walks every layer)
│   ├── layer-0-primitives/ # Pure-function primitives — codec, registry, model, errors
│   ├── fixtures/           # Real certificates + known-answer OID/DER vectors
│   └── helpers/            # Shared check / waitUntil / vectors + interop drivers
├── scripts/          # Release orchestrator, api-snapshot, comment-block validator, vendor tooling
├── bin/              # CLI entry shim
└── *.md              # README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, ARCHITECTURE, ROADMAP
```

## Single export, named namespaces

Consumers use one `require()`:

```js
var pki = require("@blamejs/pki");

var cert = pki.x509.parse(pem);              // parse an X.509 certificate
var der  = pki.asn1.build.oid("2.5.4.3");    // build canonical DER
var name = pki.oid.name("2.5.4.3");          // OID → "commonName"
```

Every namespace hangs off `pki.X`. `index.js` is the canonical export list; a new namespace registers there. The current surface is `pki.version`, `pki.C` (a.k.a. `pki.constants`), `pki.errors`, `pki.asn1`, `pki.oid`, `pki.webcrypto` (a ready `Crypto` instance carrying the `Crypto` / `SubtleCrypto` / `CryptoKey` / `WebCryptoError` classes), and `pki.x509`. Future namespaces — `pki.cms`, `pki.ocsp`, `pki.crl`, `pki.csr`, `pki.tsp`, `pki.pkcs12`, and the path-validation engine — join in the same shape as they land (see [ROADMAP.md](ROADMAP.md)).

## The layered design

The toolkit is a stack of dependency-ordered layers. Each layer depends only on the ones beneath it, and the smoke runner exercises them bottom-up so a primitive is proven before its consumers run.

### 1. Codec — `lib/asn1-der.js`

The load-bearing layer. A purpose-built ASN.1 DER/BER encoder/decoder that everything above it rides on. Its contract:

- **Strict on decode.** It rejects every non-DER shape — indefinite-length encodings, non-minimal integer and length encodings, trailing bytes after a value, constructed strings where primitive is required — and enforces a hard depth and size cap **before** it walks a byte, so malformed or deeply nested input is refused in bounded time instead of exhausting the stack. BER is accepted only where a specific standard permits it.
- **Canonical on encode.** The low-level `encode` and the `build.*` helpers produce canonical DER — there is exactly one valid encoding per value.
- **One definition, both directions.** A single structure definition drives encode and decode so EXPLICIT/IMPLICIT context-tag handling cannot diverge between the two. There is no separate hand-rolled decoder and encoder for the same structure to fall out of sync.

The codec exposes low-level `read.*` / `build.*` helpers plus the `TAGS` table and OID-content codecs, so higher layers describe structures declaratively rather than nudging bytes.

### 2. OID registry — `lib/oid.js`

A data-driven registry, not a switch. Object identifiers resolve by name in both directions (`name` / `byName`), convert between arc arrays and DER content (`toArcs` / `fromArcs` / `toDER` / `fromDER`), and new identifiers are registered as data (`register`). Every algorithm, attribute, and extension the toolkit understands is a registry entry keyed by OID — the mechanism that keeps algorithm handling data-driven all the way up the stack. Adding a post-quantum signature algorithm is a registry row plus a signer, never a special case in a parser.

### 3. Structures — `lib/x509.js` and the structure modules to come

The certificate and message models. `lib/x509.js` today parses X.509 v3 certificates and handles PEM in both directions (`parse` / `pemDecode` / `pemEncode`), modeling the full standard extension set and distinguished names as ordered RDN collections so multi-valued RDNs encode correctly. Each structure module maps to a named RFC and is built by describing the structure to the codec once — parse, build, sign, and verify all derive from that single description. The roadmap adds CRL, CSR, CMS, OCSP, timestamping, and the PKCS key/credential stores as sibling modules in this layer, each following the same one-structure-both-directions discipline.

### 4. Crypto engine — `lib/webcrypto.js`

Cryptographic operations run through a zero-dependency W3C WebCrypto engine (`Crypto` / `SubtleCrypto` / `CryptoKey`) built on Node's native `node:crypto`. It is PQC-first without being PQC-only: post-quantum ML-DSA-44/65/87 and SLH-DSA signatures sit in the same algorithm dispatch as the full classical set — RSA (PKCS#1-v1.5 / PSS / OAEP), ECDSA, ECDH, Ed25519/Ed448, AES-GCM/CBC/CTR/KW, HMAC, HKDF, PBKDF2, and the SHA family including legacy SHA-1 — and ML-KEM-512/768/1024 key generation with SPKI/PKCS#8 encoding is available today, with KEM encapsulation/decapsulation on the roadmap. Because the runtime already provides every primitive (classical, and FIPS 203/204/205 PQC via the OpenSSL 3.5 the Node floor ships), the toolkit vendors no crypto — a platform built-in ships zero bytes and is OpenSSL/NSS-interoperable by construction (see `lib/vendor/README.md`). Higher structure modules (CMS sign/verify, certificate signing, path validation) compose this engine and select a signer/verifier by the algorithm identifier carried in the structure via the OID registry (layer 2), never a hardcoded assumption. The post-quantum and hybrid KEM transport paths join this layer as they land on the roadmap.

## Cross-cutting concerns

### Errors — `lib/framework-error.js`

`PkiError` is the base for every typed failure, built through `defineClass` so each domain (codec, OID, PEM, certificate, …) gets its own class with a stable `domain/reason` code. Untrusted-input parsing throws a typed `PkiError` — malformed input is a permanent verdict with a name, not a thrown string or a falsy return. This is the toolkit's dominant validation tier. The toolkit's validation policy has three tiers: config-time entry points throw on bad input, malformed untrusted bytes throw a typed `PkiError`, and hot-path observability sinks drop-silent.

### Bounds — `lib/constants.js`

`C.TIME.*` / `C.BYTES.*` are functional scale helpers (`C.TIME.minutes(n)`, `C.BYTES.mib(n)`), and `LIMITS` holds the codec's depth/size caps and the toolkit version. Bounds live here as data so the fail-closed caps are one auditable place, not scattered magic numbers.

## Design principles

These are the decisions the layout encodes. They're the reason the toolkit reimplements the standards surface rather than wrapping an existing parser.

1. **Own the codec.** Correctness, denial-of-service resistance, and canonical encoding are in-tree decisions, not inherited from an external parser. The depth/size caps and the strict-decode rejections are ours to guarantee.
2. **Registry, not switch.** Algorithms, attributes, and extensions resolve through the OID-keyed registry. New capability — including post-quantum — is a data entry, not a branch added to a parser.
3. **Fail closed.** Every decode of untrusted bytes and every verify path either produces a real, validated result or throws a typed error. No path substitutes zero, a default, or partial output for a verdict.
4. **One structure, both directions.** A single definition drives encode and decode so the two can't diverge on context-tag handling.
5. **Post-quantum-first.** ML-DSA and SLH-DSA signatures are first-class alongside the classical set, and ML-KEM key generation ships today with KEM encapsulation on the roadmap. There is no classical-only default where a post-quantum or hybrid option exists.
6. **Standards are the contract.** Every structure maps to a named RFC; the `build.*` helpers emit canonical DER, so each value has exactly one valid encoding; interoperability with an independent implementation (OpenSSL / NSS, and for PKCS#12 also Windows CAPI / macOS Keychain) is an acceptance gate, not an aspiration.

## Where to read first

If you're new to the codebase, read in this order:

1. `index.js` — the single export surface.
2. `lib/asn1-der.js` — the codec; everything above it depends on its strictness guarantees.
3. `lib/oid.js` — the registry that keeps algorithm handling data-driven.
4. `lib/x509.js` — a representative structure module (parse + PEM, built on the codec).
5. `lib/framework-error.js` — the typed-error shape every failure uses.
6. `test/layer-0-primitives/asn1-der.test.js` — the canonical test shape (`run()` + `CHECKS <n>` + shared helpers).

This is enough orientation to start contributing without spelunking every module.
