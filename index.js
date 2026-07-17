// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @blamejs/pki -- public API entry point.
 *
 * A pure-JavaScript PKI toolkit that owns its stack. Zero npm runtime
 * dependencies; strict, fail-closed parsing; post-quantum-first crypto.
 *
 * Public surface lives on the exported object below. Notable groupings:
 *
 *   Core:          C / constants (scale helpers + version), errors
 *                  (PkiError taxonomy), asn1 (strict DER codec), oid
 *                  (OID <-> name registry), webcrypto (W3C SubtleCrypto
 *                  engine over node:crypto -- PQC-first, classical-capable,
 *                  ML-DSA / ML-KEM / SLH-DSA alongside the classical set)
 *   Schema:        schema (the structure-schema engine + the registered
 *                  format parsers -- X.509, CRL, CSR, PKCS#8, PKCS#12, CMS,
 *                  OCSP, timestamps, CRMF, CMP, attribute certificates --
 *                  with detect-and-route schema.parse; schema.all() lists
 *                  the registered set)
 *   Validation:    path (RFC 5280 certification-path validation), ct
 *                  (RFC 6962 Certificate Transparency SCT decoding)
 *
 * ROADMAP.md tracks what remains ahead of the shipped surface.
 *
 * See LICENSE (Apache-2.0) and NOTICE for vendored attribution.
 */

var constants = require("./lib/constants");
var errors    = require("./lib/framework-error");
var asn1      = require("./lib/asn1-der");
var cbor      = require("./lib/cbor-det");
var oid       = require("./lib/oid");
var webcrypto = require("./lib/webcrypto");
var schema    = require("./lib/schema-all");
var path      = require("./lib/path-validate");
var ct        = require("./lib/ct");
var cms       = require("./lib/cms-verify");
var smime     = require("./lib/smime");
var tsp       = require("./lib/tsp-sign");
var ocsp      = require("./lib/ocsp");
var x509      = require("./lib/x509-sign");
var csr       = require("./lib/csr-sign");
var attrcert  = require("./lib/attrcert-sign");
var merkle    = require("./lib/merkle");
var shbs      = require("./lib/shbs");
var hpke      = require("./lib/hpke");
var sigstore  = require("./lib/sigstore");
var est        = require("./lib/est");
var jose       = require("./lib/jose");
var acme       = require("./lib/acme");
var trust      = require("./lib/trust");
var inspect    = require("./lib/inspect");
var lint       = require("./lib/lint");
var webauthn   = require("./lib/webauthn");

module.exports = {
  version:   constants.version,
  // `C` is the terse call-site alias; `constants` the discoverable name.
  C:         constants,
  constants: constants,
  errors:    errors,
  // `asn1` is the strict DER codec (decode/encode/build/read/TAGS).
  asn1:      asn1,
  // `cbor` is the strict, fail-closed RFC 8949 deterministic CBOR codec
  // (decode + read.* leaf readers), sibling to `asn1`. It rejects every
  // non-deterministic shape -- indefinite length, a non-minimal argument,
  // unsorted / duplicate map keys, a non-shortest float, trailing bytes --
  // before it walks a byte, and surfaces zero-copy bytes / content views.
  cbor:      cbor,
  oid:       oid,
  // `schema` is the family: the L2 structure-schema engine (schema.engine) and
  // the per-format parsers (schema.x509, ...) with detect-and-route schema.parse.
  schema:    schema,
  // `path` is RFC 5280 sec. 6 certification-path validation -- pki.path.validate
  // runs the sec. 6.1 state machine over an already-parsed path + a trust anchor.
  path:      path,
  // `ct` is RFC 6962 Certificate Transparency -- pki.ct.parseSctList decodes the
  // SCT-list extension a certificate / OCSP response carries; the signature is
  // surfaced raw for external verification (pki.ct.reconstructSignedData).
  ct:        ct,
  cms:       cms,
  smime:     smime,
  tsp:       tsp,
  ocsp:      ocsp,
  // `x509` is the certificate-issuance producing side -- pki.x509.sign builds and
  // signs an X.509 certificate (RFC 5280 sec. 4), self-signed or CA-signed, over any
  // signature algorithm the registry resolves (RSA/ECDSA/EdDSA/ML-DSA/SLH-DSA/composite).
  // Parsing lives at pki.schema.x509.parse.
  x509:      x509,
  // `csr` is the PKCS#10 certification-request producing side -- pki.csr.sign builds and
  // signs a CertificationRequest (RFC 2986), self-signed by the subject key for proof of
  // possession, with requested extensions in a PKCS#9 extensionRequest attribute. Parsing
  // lives at pki.schema.csr.parse.
  csr:       csr,
  // `attrcert` is the RFC 5755 attribute-certificate producing side -- pki.attrcert.sign
  // builds and signs an AttributeCertificate binding a Holder to privilege attributes as an
  // Attribute Authority (never self-signed). Parsing lives at pki.schema.attrcert.parse.
  attrcert:  attrcert,
  // `merkle` is the RFC 6962 / RFC 9162 Merkle-tree proof-verification core --
  // pki.merkle.leafHash / nodeHash / emptyRootHash build the domain-separated
  // (0x00 leaf / 0x01 node) SHA-256 tree hashes; pki.merkle.verifyInclusion and
  // verifyConsistency fold an audit / consistency proof and constant-time-
  // compare to a checkpoint root. Pure sync hashing, fail-closed, transport-free.
  merkle:    merkle,
  // `shbs` verifies stateful hash-based signatures -- HSS/LMS (RFC 8554),
  // carried by RFC 9802 (X.509) and RFC 9708 (CMS), profiled by NIST SP 800-208.
  // VERIFY ONLY by design: stateful signing requires atomic one-time-key index
  // state that belongs in an HSM, so this module never mints a signature.
  shbs:      shbs,
  // `hpke` is RFC 9180 Hybrid Public Key Encryption -- the KEM + HKDF key
  // schedule + AEAD context construction behind TLS ECH / MLS / OHTTP. Pure
  // composition over node:crypto; the classical DHKEM suites, all four modes.
  hpke:      hpke,
  // `sigstore` verifies a Sigstore bundle (the npm --provenance artifact): a
  // keyless Fulcio signature over a DSSE-wrapped in-toto SLSA attestation with a
  // Rekor inclusion proof -- offline, zero-dep, against caller-pinned trust.
  sigstore:  sigstore,
  // `est` is RFC 7030 / 8951 / 9908 Enrollment over Secure Transport -- the
  // transport-agnostic client codecs (base64 transfer, multipart splitter),
  // certs-only + serverkeygen validators over CMS, the enroll-attribute builders,
  // and the HTTP response classifier. No socket; fail-closed.
  est:       est,
  // `jose` is the RFC 7515 Flattened JWS + RFC 7638 JWK-thumbprint layer: a strict
  // base64url codec, a bounded duplicate-key-rejecting JSON reader, profiled
  // sign/verify (ACME-outer / EAB-inner / keyChange-inner), and an alg registry
  // (ES/RS/PS/EdDSA/ML-DSA). It is the crypto envelope pki.acme composes.
  jose:      jose,
  // `acme` is the RFC 8555 / 8737 / 8738 / 9773 ACME message layer over pki.jose:
  // resource-object validators, the three state machines, request builders,
  // http-01 / dns-01 / tls-alpn-01 challenge math, and the ARI certID. A message
  // layer, not an HTTP client -- transport is the operator's to inject.
  acme:      acme,
  // `trust` is Mozilla/NSS certdata.txt + CCADB CSV root-store ingestion --
  // pki.trust.parseCertdata / parseCcadbCsv produce constraint-carrying trust
  // anchors (per-purpose trust bits + per-purpose distrust-after dates the bare
  // root list omits); pki.trust.anchor hands one to pki.path.validate. Offline:
  // the operator supplies the text; no fetch.
  trust:     trust,
  // `inspect` is human-readable inspection -- pki.inspect.certificate(pem|der|parsed)
  // renders an OpenSSL-familiar `x509 -text`-style report from the strict parser +
  // OID registry, naming extension/algorithm OIDs OpenSSL shows only as raw bytes.
  // Pure, no OpenSSL dependency; best-effort (a bad extension falls back to hex).
  inspect:   inspect,
  lint:      lint,
  // `webauthn` verifies a W3C WebAuthn / passkey attestation -- pki.webauthn.verify
  // checks the attestation-statement signature + each format's structural bindings
  // (packed / tpm / android-key / apple / fido-u2f / none) and surfaces the x5c chain
  // for the caller to anchor to a pinned root via pki.path.validate; it does not
  // itself chain to a trust anchor. parseAttestationObject structurally decodes the
  // attestation object + authenticatorData + COSE key over the strict pki.cbor codec.
  // A verifier, not a ceremony client; fail-closed.
  webauthn:  webauthn,
  // A ready W3C Crypto instance (globalThis.crypto shape) with the classes for
  // constructing more attached under the same namespace (pki.webcrypto.CryptoKey,
  // .SubtleCrypto, .Crypto, .WebCryptoError). PQC-first, classical-capable, zero-dep.
  webcrypto: _webcryptoNamespace(),
};

function _webcryptoNamespace() {
  var wc = webcrypto.webcrypto;                 // the ready Crypto instance
  wc.Crypto = webcrypto.Crypto;
  wc.SubtleCrypto = webcrypto.SubtleCrypto;
  wc.CryptoKey = webcrypto.CryptoKey;
  wc.WebCryptoError = webcrypto.WebCryptoError;
  return wc;
}
