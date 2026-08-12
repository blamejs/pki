# @blamejs/pki architecture

A contributor's guide to where things live and why the layers are ordered the
way they are. This is the orientation map. The contributor disciplines are in
[CONTRIBUTING.md](CONTRIBUTING.md) and the capability roadmap is in
[ROADMAP.md](ROADMAP.md).

## Top-level layout

```
pki/
├── index.js          # Single npm export — `var pki = require("@blamejs/pki")`
├── lib/              # Toolkit source (the shipped code)
│   ├── constants.js        # C.TIME / C.BYTES / LIMITS / version — bounds and scale helpers
│   ├── framework-error.js  # PkiError base + defineClass + per-domain error classes
│   ├── asn1-der.js         # Strict DER/BER codec: decode / encode / build.* / read.* / TAGS
│   ├── cbor-det.js         # Strict deterministic CBOR codec (RFC 8949)
│   ├── oid.js              # OID registry: name / byName / register / toArcs / toDER / …
│   ├── webcrypto.js        # W3C SubtleCrypto engine over node:crypto
│   ├── schema-*.js         # The schema engine, the shared PKIX sub-schemas, per-format parsers
│   ├── guard-*.js          # One fail-closed choke point per CVE class
│   ├── validator-*.js      # Shared structural validators (signatures, COSE, TPM, TLS, …)
│   └── vendor/             # MANIFEST.json only — crypto is node:crypto (see vendor/README.md)
├── examples/wiki/    # Source-driven docs site (lives at pkijs.com)
├── test/             # Layered tests (smoke runner walks every layer)
│   ├── layer-0-primitives/ # Pure-function primitives — codec, registry, schemas, guards
│   ├── integration/        # Containerized OpenSSL interoperability drivers
│   ├── fixtures/           # Real certificates + known-answer OID/DER vectors
│   └── helpers/            # Shared check / waitUntil / vectors
├── fuzz/             # Coverage-guided harnesses + seed corpora, one per parse path
├── scripts/          # Release orchestrator, api-snapshot, comment-block validator, vendor tooling
├── bin/              # CLI entry shim
└── *.md              # README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, ARCHITECTURE, ROADMAP
```

## Single export, named namespaces

Consumers use one `require()`:

```js
var pki = require("@blamejs/pki");

var cert = pki.schema.x509.parse(pem);       // parse an X.509 certificate
var der  = pki.asn1.build.oid("2.5.4.3");    // build canonical DER
var name = pki.oid.name("2.5.4.3");          // OID → "commonName"
```

Every namespace hangs off `pki.X`, and `index.js` is the canonical export list,
so a new namespace registers there.

Decoding and everything else are deliberately separate namespaces.
`pki.schema.<format>` is the pure decoder for a format's bytes;
`pki.<format>` is the working surface over it. So `pki.schema.x509.parse`
decodes a certificate and `pki.x509.sign` issues one. Reaching for
`pki.x509.parse` is the common first mistake; it does not exist.

`pki.<format>` is not write-only, though. It holds whatever verb needs more than
a decode, which for several formats includes the primary read path:
`pki.pkcs12.open` verifies the MAC and decrypts the bags that
`pki.schema.pkcs12.parse` only surfaces structurally, and `pki.crl.verify`,
`pki.cmp.verify`, `pki.cmc.verify`, `pki.ocsp.verify`, and `pki.cms.verify` all
check signatures the schema layer deliberately does not. The rule is that
`pki.schema.*` never performs cryptography and never confers trust; anything
that does lives one level up.

## The layered design

The toolkit is a stack of dependency-ordered layers. Each layer depends only on
the ones beneath it, and the smoke runner exercises them bottom-up so a
primitive is proven before its consumers run.

### 1. Codec — `lib/asn1-der.js`, `lib/cbor-det.js`

The load-bearing layer, and everything above it rides on the contract:

- **Strict on decode.** It rejects every non-DER shape — indefinite-length
  encodings, non-minimal integer and length encodings, trailing bytes after a
  value, constructed strings where primitive is required — and enforces a hard
  depth and size cap before it walks a byte, so malformed or deeply nested input
  is refused in bounded time instead of exhausting the stack. BER is accepted
  only where a specific standard permits it.
- **Canonical on encode.** The low-level `encode` and the `build.*` helpers
  produce canonical DER, so there is exactly one valid encoding per value.
- **One definition, both directions.** A single structure definition drives
  encode and decode, so EXPLICIT/IMPLICIT context-tag handling cannot diverge.
  There is no separate hand-rolled decoder and encoder for the same structure to
  fall out of sync.

`lib/cbor-det.js` applies the same posture to RFC 8949 deterministic CBOR, which
is what the C509 certificate and WebAuthn surfaces decode.

The codec exposes low-level `read.*` and `build.*` helpers plus the `TAGS` table
and OID-content codecs, so higher layers describe structures declaratively
rather than nudging bytes.

### 2. OID registry — `lib/oid.js`

A data-driven registry rather than a switch. Object identifiers resolve by name
in both directions (`name` and `byName`), convert between arc arrays and DER
content (`toArcs` / `fromArcs` / `toDER` / `fromDER`), and new identifiers
register as data (`register`). Every algorithm, attribute, and extension the
toolkit understands is a registry entry keyed by OID, which is the mechanism
that keeps algorithm handling data-driven all the way up the stack. Adding a
post-quantum signature algorithm is a registry row plus a signer, never a
special case in a parser.

### 3. Schema engine and format parsers — `lib/schema-*.js`

`lib/schema-engine.js` is a declarative ASN.1 structure-schema engine: `walk`,
`encode`, and the combinators (`seq`, `field`, `optional`, `choice`, `setOf`,
`explicit`, and the typed leaves). A format parser declares its structure as
data and hands it to the engine; it never advances a child cursor, re-checks a
tag, or re-rolls PEM handling by hand. Each structural rule — bounds-checked
positional reads, optional and context-tagged field ordering, SET-OF ascending
order and uniqueness, arity, fail-closed typed errors — is written once, so no
new format can reintroduce the bug class it prevents.

`lib/schema-pkix.js` holds the sub-schemas every format reuses:
`algorithmIdentifier`, `name`, `attribute`, `spki`, `extension`, the bounded
version reader, and the single coerce-decode-walk parse entry every format's
`parse` is bound to. Input coercion, the PEM size cap, and the DER-decode
wrapping live here once, so a format cannot diverge on a guard.

The per-format modules — `schema-x509`, `schema-crl`, `schema-csr`,
`schema-pkcs8`, `schema-cms`, `schema-ocsp`, `schema-tsp`, `schema-attrcert`,
`schema-crmf`, `schema-pkcs12`, `schema-cmp`, `schema-cmc`, `schema-csrattrs`,
`schema-smime`, `schema-c509` — each compose the engine plus those sub-schemas.
Most expose `parse` plus the PEM codecs, but the surface follows the format
rather than a template: `schema-ocsp` splits into `parseRequest` and
`parseResponse`, `schema-cmc` adds `parsePkiData` and `parsePkiResponse` and has
no PEM codec, `schema-csrattrs` is `parse` alone, `schema-c509` pairs `parse`
with `encode`, and `schema-smime` is a set of attribute decoders with no `parse`
at all. Check the namespace before assuming a verb.

`lib/schema-all.js` is the orchestrator: `pki.schema.parse` inspects a decoded
root and routes to the first sibling whose `matches` detector accepts. Order in
the `FORMATS` table is load-bearing where two detectors overlap — a 2-child CMP
`PKIMessage` whose body is `ir [0]` also satisfies the shallow OCSP-request
probe, and a `[0]`-subject v1 attribute certificate also satisfies
`x509.matches` — so `cmp` sits ahead of `ocsp-request` and `attrcert` ahead of
`x509`. Insert a new format ahead of any more permissive detector, and read the
ordering notes in that file before moving an entry.

Byte ranges an external verifier hashes — `tbsBytes`, a CMS `eContent` or
`signedAttrsBytes`, a CMP `headerBytes` — are surfaced raw, never re-serialized.

### 4. Crypto engine — `lib/webcrypto.js`

Cryptographic operations run through a zero-dependency W3C WebCrypto engine
(`Crypto`, `SubtleCrypto`, `CryptoKey`) built on Node's native `node:crypto`. It
is post-quantum-first without being post-quantum-only: ML-DSA-44/65/87 and
SLH-DSA signatures sit in the same algorithm dispatch as the full classical set
— RSA (PKCS#1 v1.5, PSS, OAEP), ECDSA, ECDH, Ed25519/Ed448, AES-GCM/CBC/CTR/KW,
HMAC, HKDF, PBKDF2, and the SHA family including legacy SHA-1 — and
ML-KEM-512/768/1024 key generation with SPKI and PKCS#8 encoding, plus
`encapsulateBits` and `decapsulateBits`, which are what the CMS
`KEMRecipientInfo` arm rides on. The runtime
already provides every primitive, classical and the FIPS 203/204/205
post-quantum sets via the OpenSSL 3.5 the Node floor ships, so the toolkit
vendors no crypto: a platform built-in ships zero bytes and is OpenSSL- and
NSS-interoperable by construction (see `lib/vendor/README.md`). Higher modules —
CMS sign and verify, certificate signing, path validation — compose this engine
and select a signer or verifier by the algorithm identifier carried in the
structure, resolved through the OID registry rather than a hardcoded assumption.

## Cross-cutting concerns

### Guards — `lib/guard-*.js`

Where the schema engine defines a structural rule once, the guard family defines
a fail-closed defense once. Each `guard-<shape>.js` is the single choke point
for one vulnerability class: `guard-bytes` (detached-buffer re-view),
`guard-limits` (resource caps), `guard-crypto` (constant-time compare),
`guard-text` (cap before copy), `guard-range` (bounded integer narrowing),
`guard-name` (control-byte reject and canonical DN comparison), `guard-secret`
(secret zeroization), and their siblings, with `guard-all.js` as the
orchestrator. Guards are internal, never exposed on `pki.*`, and each takes the
caller's own typed error class and code so every boundary keeps its
`domain/reason`. A guard is worth creating at one consumer: its value is
preventing the class in the next one.

### Validators — `lib/validator-*.js`

The shared structural validators the format modules call into: signature
conformance (`validator-sig`), COSE keys, TPM structures, Android
`KeyDescription`, attribute certificates, and TLS structures, behind
`validator-all.js`.

### Errors — `lib/framework-error.js`

`PkiError` is the base for every typed failure, built through `defineClass` so
each domain gets its own class with a stable `domain/reason` code. Parsing
untrusted input throws a typed `PkiError`: malformed input is a permanent
verdict with a name rather than a thrown string or a falsy return. Validation
has three tiers — config-time entry points throw on bad input, malformed
untrusted bytes throw a typed `PkiError`, and hot-path observability sinks drop
silently by design.

### Bounds — `lib/constants.js`

`C.TIME.*` and `C.BYTES.*` are functional scale helpers (`C.TIME.minutes(n)`,
`C.BYTES.mib(n)`), and `LIMITS` holds the codec's depth and size caps and the
toolkit version. Bounds live here as data, so the fail-closed caps are one
auditable place rather than scattered magic numbers.

## Design principles

These are the decisions the layout encodes, and the reason the toolkit
reimplements the standards surface rather than wrapping an existing parser.

1. **Own the codec.** Correctness, denial-of-service resistance, and canonical
   encoding are in-tree decisions rather than inherited from an external parser.
   The depth and size caps and the strict-decode rejections are ours to
   guarantee.
2. **Registry, not switch.** Algorithms, attributes, and extensions resolve
   through the OID-keyed registry. New capability, post-quantum included, is a
   data entry rather than a branch added to a parser.
3. **Fail closed.** Every decode of untrusted bytes and every verify path either
   produces a real, validated result or throws a typed error. No path
   substitutes zero, a default, or partial output for a verdict.
4. **One structure, both directions.** A single definition drives encode and
   decode, so the two cannot diverge on context-tag handling.
5. **Post-quantum-first.** ML-DSA and SLH-DSA signatures are first-class
   alongside the classical set, and ML-KEM key generation, encapsulation, and
   decapsulation carry the CMS KEM recipient arm. No default is classical-only
   where a post-quantum or hybrid option exists.
6. **Standards are the contract.** Every structure maps to a named RFC, the
   `build.*` helpers emit canonical DER so each value has exactly one valid
   encoding, and interoperability with an independent implementation is an
   acceptance gate. That gate runs against OpenSSL today. NSS, Windows CAPI, and
   macOS Keychain cross-checks are on the roadmap and are not yet wired.

## Where to read first

If you are new to the codebase, read in this order:

1. `index.js` — the single export surface.
2. `lib/asn1-der.js` — the codec; everything above it depends on its strictness
   guarantees.
3. `lib/oid.js` — the registry that keeps algorithm handling data-driven.
4. `lib/schema-engine.js` then `lib/schema-x509.js` — the engine and a
   representative format parser built on it.
5. `lib/framework-error.js` — the typed-error shape every failure uses.
6. `test/layer-0-primitives/asn1-der.test.js` — the canonical test shape
   (`run()`, `CHECKS <n>`, shared helpers).

That is enough orientation to start contributing without spelunking every
module.
