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
var pkcs1 = require("./schema-pkcs1");
var sec1 = require("./schema-sec1");
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
    parse: function (input, caps) { return cms.parse(input, caps); },
  },
  {
    name: "tsp",
    module: tsp,
    detect: tsp.matches,
    parse: function (input, caps) { return tsp.parse(input, caps); },
  },
  {
    name: "crmf",
    module: crmf,
    detect: crmf.matches,
    parse: function (input, caps) { return crmf.parse(input, caps); },
  },
  {
    name: "cmp",
    module: cmp,
    detect: cmp.matches,
    parse: function (input, caps) { return cmp.parse(input, caps); },
  },
  {
    name: "csrattrs",
    module: csrattrs,
    detect: csrattrs.matches,
    parse: function (input, caps) { return csrattrs.parse(input, caps); },
  },
  {
    name: "ocsp-request",
    module: ocsp,
    detect: ocsp.matchesRequest,
    parse: function (input, caps) { return ocsp.parseRequest(input, caps); },
  },
  {
    name: "ocsp-response",
    module: ocsp,
    detect: ocsp.matchesResponse,
    parse: function (input, caps) { return ocsp.parseResponse(input, caps); },
  },
  {
    name: "pkcs12",
    module: pkcs12,
    detect: pkcs12.matches,
    parse: function (input, caps) { return pkcs12.parse(input, caps); },
  },
  {
    name: "pkcs8",
    module: pkcs8,
    detect: pkcs8.matches,
    parse: function (input, caps) { return pkcs8.parse(input, caps); },
  },
  {
    name: "csr",
    module: csr,
    detect: csr.matches,
    parse: function (input, caps) { return csr.parse(input, caps); },
  },
  {
    name: "attrcert",
    module: attrcert,
    detect: attrcert.matches,
    parse: function (input, caps) { return attrcert.parse(input, caps); },
  },
  {
    name: "attrcert-v1",
    module: attrcert,
    detect: attrcert.matchesV1,
    parse: function (input, caps) { return attrcert.parseV1(input, caps); },
  },
  {
    name: "crl",
    module: crl,
    detect: crl.matches,
    parse: function (input, caps) { return crl.parse(input, caps); },
  },
  {
    name: "x509",
    module: x509,
    detect: x509.matches,
    parse: function (input, caps) { return x509.parse(input, caps); },
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
 * @signature  pki.schema.parse(input, caps?) -> parsed
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
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. They bound the detection decode
 *     and the decode of whichever format matches, and a parse that exceeds one is refused
 *     with the `/too-large` code of that format.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var parsed = pki.schema.parse(der);  // cert -> the pki.schema.x509 shape
 */
function parse(input, callerOpts) {
  /** @internal The caps are validated once here and the snapshot is what the chosen format
   *  receives, so the detection decode and the format's own decode are held to the same
   *  figures a caller named, read once. */
  var caps = pkix.parseCaps(callerOpts, ENTRY);
  var der = pkix.coerceToDer(input, ENTRY);
  var root = pkix.decodeRoot(der, ENTRY, caps);
  for (var i = 0; i < FORMATS.length; i++) {
    if (FORMATS[i].detect(root)) return FORMATS[i].parse(der, caps);
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

/** @internal What a bundle row's bytes are, given the label the file put on them. An
 * `EncryptedPrivateKeyInfo` is `SEQUENCE { AlgorithmIdentifier, OCTET STRING }`, which a PKCS#1
 * `DigestInfo` also is, so structure alone cannot classify it and `detectFormat` deliberately
 * does not. In a bundle the label is evidence the bare bytes do not carry, and RFC 7468 sec. 11
 * gives the encrypted structure a label of its own, so the label is what makes the question
 * answerable here and nowhere else. */
var LABEL_ONLY_FORMATS = [
  { label: "ENCRYPTED PRIVATE KEY", name: "pkcs8-encrypted", detect: pkcs8.matchesEncrypted },
  { label: "RSA PRIVATE KEY", name: "pkcs1", detect: pkcs1.matches },
  { label: "RSA PUBLIC KEY", name: "pkcs1-public", detect: pkcs1.matchesPublic },
  { label: "EC PRIVATE KEY", name: "sec1", detect: sec1.matches },
];

function detectFormatForLabel(input, label) {
  var der = pkix.coerceToDer(input, ENTRY);
  var root = pkix.decodeRoot(der, ENTRY);
  for (var j = 0; j < LABEL_ONLY_FORMATS.length; j++) {
    if (LABEL_ONLY_FORMATS[j].label === label) {
      return LABEL_ONLY_FORMATS[j].detect(root) ? LABEL_ONLY_FORMATS[j].name : null;
    }
  }
  for (var i = 0; i < FORMATS.length; i++) {
    if (FORMATS[i].detect(root)) return FORMATS[i].name;
  }
  return null;
}

/**
 * @primitive  pki.schema.pem.decodeBundle
 * @signature  pki.schema.pem.decodeBundle(text, opts) -> [{ index, offset, label, der }]
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.detectFormat, pki.schema.pem.encodeBundle
 *
 * Read every object in a PEM file: a `fullchain.pem` of a leaf and its intermediates, a
 * `ca-certificates.crt` of hundreds of anchors, a file holding a key beside its certificate.
 * Each row carries the label that named the object, the DER it decoded to, its position in
 * the file and the offset into the text its boundary started at, so a fault in a file of hundreds
 * names the one object it is about. `offset` counts into the text this verb read: a
 * `BufferSource` is read as latin1, so one character is one byte and the offset is the byte
 * offset into the file, while a string a caller decoded itself is counted in that string's own
 * characters.
 *
 * Explanatory text before, between and after the blocks is text, which is what a bundle
 * written by a real tool carries. A label the toolkit has no parser for is a row like any
 * other: the label is data, not a filter.
 *
 * This is the verb for a file of several objects. Every other door reads one: a parse door,
 * a `pemDecode`, and a verb taking a certificate or a message as PEM each refuse a file
 * holding more than one with `pem/multiple-blocks`, naming how many it holds.
 *
 * Fail-closed on the file rather than on the object: a boundary opened and never closed, a
 * block closed under a different label, a body carrying RFC 1421 encryption headers, a body
 * outside the base64 alphabet, more objects than `opts.maxBlocks`, and objects decoding to
 * more than `opts.maxDecodedBytes` are each refused with their own `pem/*` code. Either cap
 * may be tightened by a caller and neither may be raised above the toolkit's own.
 *
 * @opts
 *   route            check each label's claim against the structure its bytes carry, and add
 *                    `format` to every row (`null` when the label names no parser). A label
 *                    whose claim the bytes do not support is `pem/label-structure-mismatch`.
 *   maxBlocks        how many objects the file may hold. Default `C.LIMITS.PEM_MAX_BLOCKS`.
 *   maxDecodedBytes  how many bytes those objects may decode to in total, across the file
 *                    rather than per object. Default `C.LIMITS.PEM_MAX_DECODED_BYTES`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var cert = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var text = "Some Root CA\n============\n" + pki.schema.x509.pemEncode(cert, "CERTIFICATE");
 *   var rows = pki.schema.pem.decodeBundle(text);
 *   rows.length;           // 1, the two prose lines being text
 *   rows[0].label;         // "CERTIFICATE"
 *   rows[0].offset;        // 26, where its boundary starts
 *   pki.schema.x509.parse(rows[0].der);
 */

/**
 * @primitive  pki.schema.pem.encodeBundle
 * @signature  pki.schema.pem.encodeBundle(objects) -> string
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.pem.decodeBundle
 *
 * Write an ordered list of `{ label, der }` objects to one PEM text, each block wrapped at 64
 * characters and closed under the label it was opened with. What `decodeBundle` reads back is
 * the list that went in, and writing that list again produces the same text.
 *
 * A label is held to the uppercase form this toolkit writes, so a label carrying a boundary
 * cannot put a block into the file that the caller never named. The reader is wider than the
 * writer: it takes every label RFC 7468 sec. 3 admits, including lowercase and the empty one.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var cert = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var text = pki.schema.pem.encodeBundle([{ label: "CERTIFICATE", der: cert }, { label: "CERTIFICATE", der: cert }]);
 *   pki.schema.pem.decodeBundle(text).length;   // 2
 */

/** @internal What a block's bytes are, for the label-versus-structure comparison. Bytes the
 * detector cannot place are not a fault here: the label may name something this toolkit has no
 * parser for, and the reader answers that with a row rather than a refusal. */
function _detectOrNull(der, label) {
  try { return detectFormatForLabel(der, label); } catch (_e) { /* allow:swallow-unverified unreadable bytes are "no structure", which the caller is told */ return null; }
}

module.exports = {
  engine: engine,
  x509: { parse: x509.parse, pemDecode: x509.pemDecode, pemEncode: x509.pemEncode,
    decodeExtensions: x509.decodeExtensions, decodeExtension: x509.decodeExtension },
  c509: { parse: c509.parse, encode: c509.encode },
  crl:  { parse: crl.parse,  pemDecode: crl.pemDecode, pemEncode: crl.pemEncode,
    decodeExtensions: crl.decodeExtensions, decodeExtension: crl.decodeExtension },
  csr:  { parse: csr.parse,  pemDecode: csr.pemDecode, pemEncode: csr.pemEncode,
    decodeExtensions: csr.decodeExtensions, decodeExtension: csr.decodeExtension },
  pkcs8: { parse: pkcs8.parse, parseEncrypted: pkcs8.parseEncrypted, pemDecode: pkcs8.pemDecode, pemEncode: pkcs8.pemEncode },
  pkcs1: {
    parse: pkcs1.parse, parsePublic: pkcs1.parsePublic,
    encode: pkcs1.encode, encodePublic: pkcs1.encodePublic,
    pemDecode: pkcs1.pemDecode, pemEncode: pkcs1.pemEncode,
    pemDecodePublic: pkcs1.pemDecodePublic, pemEncodePublic: pkcs1.pemEncodePublic,
  },
  sec1: { parse: sec1.parse, encode: sec1.encode, pemDecode: sec1.pemDecode, pemEncode: sec1.pemEncode },
  pkcs12: { parse: pkcs12.parse, pemDecode: pkcs12.pemDecode, pemEncode: pkcs12.pemEncode },
  cms:  { parse: cms.parse, pemDecode: cms.pemDecode, pemEncode: cms.pemEncode },
  ocsp: { parseRequest: ocsp.parseRequest, parseResponse: ocsp.parseResponse, pemDecode: ocsp.pemDecode, pemEncode: ocsp.pemEncode },
  tsp: { parse: tsp.parse, parseResponse: tsp.parseResponse, parseRequest: tsp.parseRequest, parseTstInfo: tsp.parseTstInfo, parseToken: tsp.parseToken, pemDecode: tsp.pemDecode, pemEncode: tsp.pemEncode },
  crmf: { parse: crmf.parse, pemDecode: crmf.pemDecode, pemEncode: crmf.pemEncode,
    decodeExtensions: crmf.decodeExtensions, decodeExtension: crmf.decodeExtension },
  cmp: { parse: cmp.parse, pemDecode: cmp.pemDecode, pemEncode: cmp.pemEncode },
  csrattrs: { parse: csrattrs.parse },
  attrcert: { parse: attrcert.parse, pemDecode: attrcert.pemDecode, pemEncode: attrcert.pemEncode,
    decodeExtensions: attrcert.decodeExtensions, decodeExtension: attrcert.decodeExtension },
  smime: { parseSigningCertificate: smime.parseSigningCertificate, parseSigningCertificateV2: smime.parseSigningCertificateV2, parseSmimeCapabilities: smime.parseSmimeCapabilities, decodeAttribute: smime.decodeAttribute },
  cmc: { parse: cmc.parse, parsePkiData: cmc.parsePkiData, parsePkiResponse: cmc.parsePkiResponse },
  pem: {
    decodeBundle: function (text, opts) { return pkix.pemDecodeBundle(text, opts, PemError, _detectOrNull); },
    encodeBundle: function (objects) { return pkix.pemEncodeBundle(objects, PemError); },
  },
  all: all,
  parse: parse,
  detectFormat: detectFormat,
};
