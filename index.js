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
var oid       = require("./lib/oid");
var webcrypto = require("./lib/webcrypto");
var schema    = require("./lib/schema-all");
var path      = require("./lib/path-validate");
var ct        = require("./lib/ct");
var est        = require("./lib/est");
var jose       = require("./lib/jose");
var acme       = require("./lib/acme");

module.exports = {
  version:   constants.version,
  // `C` is the terse call-site alias; `constants` the discoverable name.
  C:         constants,
  constants: constants,
  errors:    errors,
  // `asn1` is the strict DER codec (decode/encode/build/read/TAGS).
  asn1:      asn1,
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
