// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @blamejs/pki — public API entry point.
 *
 * A pure-JavaScript PKI toolkit that owns its stack. Zero npm runtime
 * dependencies; strict, fail-closed parsing; post-quantum-first crypto.
 *
 * Public surface lives on the exported object below. Notable groupings:
 *
 *   Core:          C / constants (scale helpers + version), errors
 *                  (PkiError taxonomy), asn1 (strict DER codec), oid
 *                  (OID ↔ name registry), webcrypto (W3C SubtleCrypto
 *                  engine over node:crypto — PQC-first, classical-capable)
 *   Schema:        schema (the structure-schema engine + per-format parsers:
 *                  schema.engine, schema.x509, schema.parse detect-and-route)
 *
 * The surface grows per ROADMAP.md — CMS, OCSP, CRL, CSR, PKCS#8/#12,
 * timestamping, path validation, and the post-quantum algorithm set are
 * targeted additions that ride the same core.
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
  // the per-format parsers (schema.x509, …) with detect-and-route schema.parse.
  schema:    schema,
  // `path` is RFC 5280 §6 certification-path validation — pki.path.validate
  // runs the §6.1 state machine over an already-parsed path + a trust anchor.
  path:      path,
  // `ct` is RFC 6962 Certificate Transparency — pki.ct.parseSctList decodes the
  // SCT-list extension a certificate / OCSP response carries; the signature is
  // surfaced raw for external verification (pki.ct.reconstructSignedData).
  ct:        ct,
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
