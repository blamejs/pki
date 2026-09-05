// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema
 * @nav        Schema
 * @title      Schema
 * @fullname   Format detection: parse DER without knowing the format first
 * @order      10
 * @featured   true
 * @slug       schema
 *
 * @intro
 *   The schema family: a declarative ASN.1 structure-schema engine and the
 *   per-format parsers built on it. Every format, from X.509 certificates
 *   and CRLs through CMS, OCSP, timestamps, and PKCS#12 stores (`all()`
 *   enumerates the registered set), is a member that composes the
 *   shared engine and the shared PKIX sub-schemas (AlgorithmIdentifier, Name,
 *   Extension), so a structural rule (bounds-checked positional reads,
 *   optional / tagged field ordering, SET-OF uniqueness, fail-closed typed
 *   errors) is defined once in the engine and no format can reintroduce the
 *   class of bug it prevents.
 *
 *   `parse` is the orchestrator: hand it DER (or PEM) and it detects which
 *   format the bytes encode and routes to that member's parser. Each member is
 *   also reachable directly (`pki.schema.x509.parse`, `pki.schema.crl.parse`),
 *   and `all()` enumerates the registered formats.
 *
 * @card
 *   One declarative schema engine; every PKI format (X.509, CRL, ...) is a
 *   member composed on it. Detect-and-parse DER, or call a format directly.
 */

var engine = require("./schema-engine");
var pkix = require("./schema-pkix");
var x509 = require("./schema-x509");
var c509 = require("./schema-c509");
var crl = require("./schema-crl");
var csr = require("./schema-csr");
var pkcs8 = require("./schema-pkcs8");
var pkcs12 = require("./schema-pkcs12");
var cms = require("./schema-cms");
var ocsp = require("./schema-ocsp");
var tsp = require("./schema-tsp");
var crmf = require("./schema-crmf");
var cmp = require("./schema-cmp");
var csrattrs = require("./schema-csrattrs");
var attrcert = require("./schema-attrcert");
var smime = require("./schema-smime");
var cmc = require("./schema-cmc");
var frameworkError = require("./framework-error");

var SchemaError = frameworkError.SchemaError;
var PemError = frameworkError.PemError;

var ENTRY = Object.assign(Object.create(null), { pemLabel: null, PemError: PemError, ErrorClass: SchemaError, prefix: "schema", what: "input", ber: true });

var FORMATS = [
  {
    name: "cms",
    module: cms,
    detect: cms.matches,
    parse: function (input) { return cms.parse(input); },
  },
  {
    name: "tsp",
    module: tsp,
    detect: tsp.matches,
    parse: function (input) { return tsp.parse(input); },
  },
  {
    name: "crmf",
    module: crmf,
    detect: crmf.matches,
    parse: function (input) { return crmf.parse(input); },
  },
  {
    name: "cmp",
    module: cmp,
    detect: cmp.matches,
    parse: function (input) { return cmp.parse(input); },
  },
  {
    name: "csrattrs",
    module: csrattrs,
    detect: csrattrs.matches,
    parse: function (input) { return csrattrs.parse(input); },
  },
  {
    name: "ocsp-request",
    module: ocsp,
    detect: ocsp.matchesRequest,
    parse: function (input) { return ocsp.parseRequest(input); },
  },
  {
    name: "ocsp-response",
    module: ocsp,
    detect: ocsp.matchesResponse,
    parse: function (input) { return ocsp.parseResponse(input); },
  },
  {
    name: "pkcs12",
    module: pkcs12,
    detect: pkcs12.matches,
    parse: function (input) { return pkcs12.parse(input); },
  },
  {
    name: "pkcs8",
    module: pkcs8,
    detect: pkcs8.matches,
    parse: function (input) { return pkcs8.parse(input); },
  },
  {
    name: "csr",
    module: csr,
    detect: csr.matches,
    parse: function (input) { return csr.parse(input); },
  },
  {
    name: "attrcert",
    module: attrcert,
    detect: attrcert.matches,
    parse: function (input) { return attrcert.parse(input); },
  },
  {
    name: "attrcert-v1",
    module: attrcert,
    detect: attrcert.matchesV1,
    parse: function (input) { return attrcert.parseV1(input); },
  },
  {
    name: "crl",
    module: crl,
    detect: crl.matches,
    parse: function (input) { return crl.parse(input); },
  },
  {
    name: "x509",
    module: x509,
    detect: x509.matches,
    parse: function (input) { return x509.parse(input); },
  },
];

/**
 * @primitive  pki.schema.all
 * @signature  pki.schema.all() -> string[]
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 5280
 * @related    pki.schema.parse
 *
 * The names of every registered format, in detection order.
 *
 * @example
 *   pki.schema.all();  // -> ["cms", "tsp", "crmf", "cmp", "csrattrs", "ocsp-request", "ocsp-response", "pkcs12", "pkcs8", "csr", "attrcert", "attrcert-v1", "crl", "x509"]
 */
function all() { return FORMATS.map(function (f) { return f.name; }); }

/**
 * @primitive  pki.schema.parse
 * @signature  pki.schema.parse(input) -> parsed
 * @since      0.1.7
 * @status     stable
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
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var parsed = pki.schema.parse(der);  // cert -> the pki.schema.x509 shape
 */
function parse(input) {
  var der = pkix.coerceToDer(input, ENTRY);
  var root = pkix.decodeRoot(der, ENTRY);
  for (var i = 0; i < FORMATS.length; i++) {
    if (FORMATS[i].detect(root)) return FORMATS[i].parse(der);
  }
  throw new SchemaError("schema/unknown-format", "input does not match any registered PKI format (" + all().join(", ") + ")");
}

/**
 * @primitive  pki.schema.detectFormat
 * @signature  pki.schema.detectFormat(input) -> string | null
 * @since       0.3.8
 * @status      stable
 * @spec        RFC 5280
 * @related     pki.schema.parse, pki.schema.all
 *
 * Detect which registered PKI format `input` (a DER `Buffer` or PEM string)
 * encodes and return its name, one of `pki.schema.all()`, without parsing it,
 * or `null` when the decoded bytes match no registered format. This is the
 * detection half of `pki.schema.parse`, running the same authoritative `FORMATS`
 * ordering, exposed for a caller (e.g. `pki.inspect.any`) that needs the format
 * name instead of the parsed result. Input that does not decode as DER throws the
 * same coercion / decode error `parse` throws.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   pki.schema.detectFormat(der);  // "x509" | "crl" | "csr" | "cms" | ... | null
 */
function detectFormat(input) {
  var der = pkix.coerceToDer(input, ENTRY);
  var root = pkix.decodeRoot(der, ENTRY);
  for (var i = 0; i < FORMATS.length; i++) {
    if (FORMATS[i].detect(root)) return FORMATS[i].name;
  }
  return null;
}

module.exports = {
  engine: engine,
  x509: { parse: x509.parse, pemDecode: x509.pemDecode, pemEncode: x509.pemEncode },
  c509: { parse: c509.parse, encode: c509.encode },
  crl:  { parse: crl.parse,  pemDecode: crl.pemDecode, pemEncode: crl.pemEncode },
  csr:  { parse: csr.parse,  pemDecode: csr.pemDecode, pemEncode: csr.pemEncode },
  pkcs8: { parse: pkcs8.parse, parseEncrypted: pkcs8.parseEncrypted, pemDecode: pkcs8.pemDecode, pemEncode: pkcs8.pemEncode },
  pkcs12: { parse: pkcs12.parse, pemDecode: pkcs12.pemDecode, pemEncode: pkcs12.pemEncode },
  cms:  { parse: cms.parse, pemDecode: cms.pemDecode, pemEncode: cms.pemEncode },
  ocsp: { parseRequest: ocsp.parseRequest, parseResponse: ocsp.parseResponse, pemDecode: ocsp.pemDecode, pemEncode: ocsp.pemEncode },
  tsp: { parse: tsp.parse, parseResponse: tsp.parseResponse, parseRequest: tsp.parseRequest, parseTstInfo: tsp.parseTstInfo, parseToken: tsp.parseToken, pemDecode: tsp.pemDecode, pemEncode: tsp.pemEncode },
  crmf: { parse: crmf.parse, pemDecode: crmf.pemDecode, pemEncode: crmf.pemEncode },
  cmp: { parse: cmp.parse, pemDecode: cmp.pemDecode, pemEncode: cmp.pemEncode },
  csrattrs: { parse: csrattrs.parse },
  attrcert: { parse: attrcert.parse, pemDecode: attrcert.pemDecode, pemEncode: attrcert.pemEncode },
  smime: { parseSigningCertificate: smime.parseSigningCertificate, parseSigningCertificateV2: smime.parseSigningCertificateV2, parseSmimeCapabilities: smime.parseSmimeCapabilities, decodeAttribute: smime.decodeAttribute },
  cmc: { parse: cmc.parse, parsePkiData: cmc.parsePkiData, parsePkiResponse: cmc.parsePkiResponse },
  all: all,
  parse: parse,
  detectFormat: detectFormat,
};
