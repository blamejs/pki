// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema
 * @nav        Schema
 * @title      Schema
 * @order      10
 * @featured   true
 * @slug       schema
 *
 * @intro
 *   The schema family: a declarative ASN.1 structure-schema engine and the
 *   per-format parsers built on it. Every format (X.509 certificates, CRLs,
 *   and — as they land — CMS / CSR / PKCS#8) is a member that COMPOSES the
 *   shared engine and the shared PKIX sub-schemas (AlgorithmIdentifier, Name,
 *   Extension), so a structural rule — bounds-checked positional reads,
 *   optional / tagged field ordering, SET-OF uniqueness, fail-closed typed
 *   errors — is defined once in the engine and no format can reintroduce the
 *   class of bug it prevents.
 *
 *   `parse` is the orchestrator: hand it DER (or PEM) and it detects which
 *   format the bytes encode and routes to that member's parser. Each member is
 *   also reachable directly (`pki.schema.x509.parse`, `pki.schema.crl.parse`),
 *   and `all()` enumerates the registered formats.
 *
 * @card
 *   One declarative schema engine; every PKI format (X.509, CRL, …) is a
 *   member composed on it. Detect-and-parse DER, or call a format directly.
 */

var asn1 = require("./asn1-der");
var engine = require("./schema-engine");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");
var frameworkError = require("./framework-error");

var SchemaError = frameworkError.SchemaError;

// REGISTRY — each format is declarative data: a name, a `detect(root)` that
// recognizes the decoded DER root as this format's outer structure, and the
// member's own `parse`. Adding a format is a table entry, not new dispatch
// logic. Order matters: the most specific detector wins, so a new member is
// inserted ahead of any more-permissive one.
var FORMATS = [
  {
    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
    // signatureValue } — the same outer shape as a certificate, distinguished
    // by its tbsCertList (a bare Time at the certificate's Validity position).
    // Checked first because its detector is the specific one.
    name: "crl",
    module: crl,
    detect: crl.matches,
    parse: function (input) { return crl.parse(input); },
  },
  {
    name: "x509",
    module: x509,
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm
    // SEQUENCE, signatureValue BIT STRING }. The fallback after the CRL
    // detector: a three-element SEQUENCE whose first element is a SEQUENCE.
    detect: function (root) {
      return root && root.tagClass === "universal" && root.tagNumber === asn1.TAGS.SEQUENCE &&
        root.children && root.children.length === 3 &&
        root.children[0].tagNumber === asn1.TAGS.SEQUENCE;
    },
    parse: function (input) { return x509.parse(input); },
  },
];

/**
 * @primitive  pki.schema.all
 * @signature  pki.schema.all() -> string[]
 * @since      0.1.7
 * @status     experimental
 * @spec       RFC 5280
 * @related    pki.schema.parse
 *
 * The names of every registered format, in detection order.
 *
 * @example
 *   pki.schema.all();  // → ["x509"]
 */
function all() { return FORMATS.map(function (f) { return f.name; }); }

/**
 * @primitive  pki.schema.parse
 * @signature  pki.schema.parse(input) -> parsed
 * @since      0.1.7
 * @status     experimental
 * @spec       RFC 5280
 * @related    pki.schema.x509, pki.schema.all
 *
 * Detect which PKI format `input` (a DER `Buffer` or a PEM string) encodes and
 * route to that format's parser, returning the same structured object the
 * format's own `parse` returns. Throws `SchemaError("schema/unknown-format")` when
 * the bytes match no registered format; the underlying decode / structural
 * errors of the matched format propagate unchanged.
 *
 * @example
 *   var parsed = pki.schema.parse(der);  // cert → the pki.schema.x509 shape
 */
function parse(input) {
  var der = _coerceDer(input);
  var root;
  try { root = asn1.decode(der); }
  catch (e) { throw new SchemaError("schema/bad-der", "input did not decode as DER: " + ((e && e.message) || String(e)), e); }
  // Route the COERCED DER (not the original input): a PEM string/Buffer has
  // already been unwrapped here, so the matched format parses DER directly and
  // never re-treats the armor as DER.
  for (var i = 0; i < FORMATS.length; i++) {
    if (FORMATS[i].detect(root)) return FORMATS[i].parse(der);
  }
  throw new SchemaError("schema/unknown-format", "input does not match any registered PKI format (" + all().join(", ") + ")");
}

// Detection needs DER bytes. Accept a DER Buffer as-is; unwrap a PEM string OR a
// PEM Buffer (a `.pem` file read with fs.readFileSync is ASCII armor, not DER,
// and must be decoded before routing — the format parsers accept PEM buffers,
// so the detect-and-route entry point must too).
function _coerceDer(input) {
  if (typeof input === "string") return x509.pemDecode(input);
  if (Buffer.isBuffer(input)) return _looksLikePem(input) ? x509.pemDecode(input) : input;
  throw new SchemaError("schema/bad-input", "parse expects a DER Buffer or a PEM string");
}

// A PEM block opens with "-----BEGIN"; DER opens with a tag byte (0x30 for the
// SEQUENCE these formats start with). Sniff only the head.
function _looksLikePem(buf) {
  return buf.length >= 11 && buf.slice(0, 64).toString("latin1").indexOf("-----BEGIN") !== -1;
}

module.exports = {
  engine: engine,
  x509: x509,
  crl: crl,
  all: all,
  parse: parse,
};
