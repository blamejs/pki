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
 *   Certificates:  x509 (parse DER / PEM certificates)
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
var asn1Schema = require("./lib/asn1-schema");
var oid       = require("./lib/oid");
var webcrypto = require("./lib/webcrypto");
var x509      = require("./lib/x509");

module.exports = {
  version:   constants.version,
  // `C` is the terse call-site alias; `constants` the discoverable name.
  C:         constants,
  constants: constants,
  errors:    errors,
  // `asn1.schema` (L2) is the declarative structure-schema engine, exposed on
  // the asn1 namespace alongside the codec (decode/encode/build/read/TAGS).
  asn1:      Object.assign({}, asn1, { schema: asn1Schema }),
  oid:       oid,
  x509:      x509,
  // A ready W3C Crypto instance (globalThis.crypto shape) + the classes
  // for constructing more. PQC-first, classical-capable, zero-dep.
  webcrypto: webcrypto.webcrypto,
  WebCrypto: {
    Crypto:         webcrypto.Crypto,
    SubtleCrypto:   webcrypto.SubtleCrypto,
    CryptoKey:      webcrypto.CryptoKey,
    WebCryptoError: webcrypto.WebCryptoError,
  },
};
