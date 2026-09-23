// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.x509
 * @nav        Schema
 * @title      X.509
 * @fullname   X.509 certificates: parse, sign and inspect
 * @order      100
 * @featured   true
 * @slug       x509
 *
 * @intro
 *   X.509 certificate handling per RFC 5280. The seed surface is
 *   `parse`, which turns a DER or PEM certificate into a structured,
 *   fully-decoded object: version, serial, signature algorithm, issuer
 *   and subject distinguished names, validity window (as real `Date`s),
 *   subject public-key info, and the extension list. The parser composes
 *   the strict DER codec and the OID registry, so every field is
 *   validated on the way in and every algorithm / attribute / extension
 *   is named where the registry knows it.
 *
 *   The raw `tbsCertificate` bytes are returned alongside the parsed
 *   fields. A signature-verification layer hashes exactly the bytes that
 *   were signed, with no re-encoding step whose round-trip fidelity it
 *   would have to trust.
 *
 * @card
 *   Parse DER / PEM X.509 certificates into structured, validated fields
 *   with named algorithms, extensions, and real-`Date` validity windows.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");
var intrinsic = require("./guard-intrinsic");

var CertificateError = frameworkError.CertificateError;
var PemError = frameworkError.PemError;


/**
 * @primitive  pki.schema.x509.pemDecode
 * @signature  pki.schema.x509.pemDecode(text, label?) -> Buffer
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.x509.pemEncode
 *
 * Extract the DER bytes from a PEM block (default label `CERTIFICATE`, the
 * RFC 7468 sec. 5 armor, the canonical-label default every sibling format
 * applies). Pass a `label` to enforce a different block type, or an explicit
 * `null` to accept a block of any type. The text holds one object: a file of
 * several is refused with `pem/multiple-blocks` and read with
 * `pki.schema.pem.decodeBundle`. Throws `PemError` on a missing / mismatched
 * envelope or a non-base64 body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pemText = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) }, { pem: true });
 *   var der = pki.schema.x509.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label === null ? null : (label || "CERTIFICATE"), PemError); }

/**
 * @primitive  pki.schema.x509.pemEncode
 * @signature  pki.schema.x509.pemEncode(der, label) -> string
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.x509.pemDecode
 *
 * Wrap DER bytes in a PEM envelope with 64-column base64 lines.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var pem = pki.schema.x509.pemEncode(der, "CERTIFICATE");
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label, PemError); }


var NS = pkix.makeNS("x509", CertificateError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);

var VALIDITY = schema.seq([
  schema.field("notBefore", pkix.time(NS)),
  schema.field("notAfter", pkix.time(NS)),
], {
  assert: "sequence", arity: { exact: 2 }, code: "x509/bad-validity", what: "Validity",
  build: function (m) { return { notBefore: m.fields.notBefore.value, notAfter: m.fields.notAfter.value }; },
});

var SPKI = pkix.spki(NS);

var EXTENSIONS = pkix.extensions(NS);

var CERTIFICATE_VERSION = pkix.versionReader(NS, { "1": 2, "2": 3 });

var CERTIFICATE_TBS = schema.seq([
  schema.optional("version", CERTIFICATE_VERSION, { tag: 0, explicit: true, emptyCode: "x509/bad-version", default: 1 }),
  schema.field("serialNumber", schema.integerLeaf()),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("issuer", NAME),
  schema.field("validity", VALIDITY),
  schema.field("subject", NAME),
  schema.field("subjectPublicKeyInfo", SPKI),
  schema.trailing([
    { tag: 1, name: "issuerUniqueID", schema: schema.implicitBitString(1) },
    { tag: 2, name: "subjectUniqueID", schema: schema.implicitBitString(2) },
    { tag: 3, name: "extensions", schema: EXTENSIONS, explicit: true, emptyCode: "x509/bad-extensions" },
  ], { minTag: 1, maxTag: 3, unexpectedCode: "x509/bad-tbs", orderCode: "x509/bad-tbs" }),
], { assert: "sequence", code: "x509/bad-tbs", what: "tbsCertificate" });

var CERTIFICATE = pkix.signedEnvelope(NS, CERTIFICATE_TBS, {
  code: "x509/not-a-certificate", what: "Certificate",
  build: function (e, ctx) {
    var tbs = e.tbsMatch;

    if (!intrinsic.bufferEquals(e.outerSignatureAlgorithmBytes, tbs.fields.signature.node.bytes)) {
      throw ctx.E("x509/bad-signature-algorithm", "signatureAlgorithm must match tbsCertificate.signature (RFC 5280 sec. 4.1.1.2)");
    }

    var version = tbs.fields.version.value;
    var issuer = tbs.fields.issuer.value.result;
    if (!issuer.rdns.length) {
      throw ctx.E("x509/bad-issuer", "issuer must be a non-empty distinguished name");
    }

    var extField = tbs.fields.extensions;
    var hasExtensions = !!(extField && extField.present);
    if (hasExtensions && version !== 3) {
      throw ctx.E("x509/bad-version", "extensions are only permitted in a v3 certificate");
    }

    if ((tbs.fields.issuerUniqueID.present || tbs.fields.subjectUniqueID.present) && version < 2) {
      throw ctx.E("x509/bad-version", "issuerUniqueID/subjectUniqueID require a v2 or v3 certificate (RFC 5280 sec. 4.1.2.8)");
    }

    var serialNode = tbs.fields.serialNumber.node;
    return {
      version:               version,
      serialNumber:          tbs.fields.serialNumber.value,
      serialNumberHex:       intrinsic.bufToString(serialNode.content, "hex"),
      signatureAlgorithm:    e.signatureAlgorithm,
      tbsSignatureAlgorithm: tbs.fields.signature.value.result,
      issuer:                issuer,
      subject:               tbs.fields.subject.value.result,
      validity:              tbs.fields.validity.value.result,
      subjectPublicKeyInfo:  tbs.fields.subjectPublicKeyInfo.value.result,
      issuerUniqueID:        tbs.fields.issuerUniqueID.present ? tbs.fields.issuerUniqueID.value : null,
      subjectUniqueID:       tbs.fields.subjectUniqueID.present ? tbs.fields.subjectUniqueID.value : null,
      extensions:            hasExtensions ? extField.value.result : [],
      tbsBytes:              e.tbsBytes,
      signatureValue:        e.signatureValue,
    };
  },
});


/**
 * @primitive  pki.schema.x509.parse
 * @signature  pki.schema.x509.parse(input, caps?) -> certificate
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 5280, X.509
 * @defends    malformed-certificate-parse (CWE-20)
 * @related    pki.asn1.decode, pki.oid.name
 *
 * Parse a DER `Buffer` or a PEM string/Buffer into a structured
 * certificate: `{ version, serialNumber, serialNumberHex,
 * signatureAlgorithm, issuer, subject, validity, subjectPublicKeyInfo,
 * issuerUniqueID, subjectUniqueID, extensions, tbsBytes, signatureValue }`.
 * Distinguished names come back both as a rendered `dn` string and as
 * structured `rdns`; the validity window is real `Date`s; the two unique
 * identifiers are `{ unusedBits, bytes }` or null (RFC 5280 sec. 4.1.2.8);
 * `tbsBytes` is the exact signed byte range for a downstream verifier.
 *
 * Throws `CertificateError` when the bytes are not a well-formed
 * certificate and `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pemString = await pki.x509.sign({ subject: [{ commonName: "example.com" }, { organizationName: "Example" }],
 *     subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) }, { pem: true });
 *   var cert = pki.schema.x509.parse(pemString);
 *   cert.subject.dn;                 // "CN=example.com, O=Example"
 *   cert.validity.notAfter;          // Date
 *   cert.signatureAlgorithm.name;    // "Ed25519" (the algorithm the issuer signed with)
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. A parse that exceeds one is
 *     refused with the `/too-large` code of this format.
 */
var parse = pkix.makeRecordingParser({ pemLabel: "CERTIFICATE", PemError: PemError, ErrorClass: CertificateError, prefix: "x509", what: "certificate", topSchema: CERTIFICATE, ns: NS }, "certificate");

function matches(root) {
  var TAGS = asn1.TAGS;
  var tbs = pkix.signedEnvelopeTbs(root);
  if (!tbs) return false;
  var kids = tbs.children;
  var i = schema.isContext(kids[0], 0) ? 1 : 0;
  var validity = kids[i + 3];
  return schema.isUniversal(validity, TAGS.SEQUENCE) &&
    !!validity.children && validity.children.length === 2 &&
    intrinsic.every(validity.children, function (t) {
      return schema.isUniversalOneOf(t, [TAGS.UTC_TIME, TAGS.GENERALIZED_TIME]);
    });
}

/** @internal The certificate scope, as the shared door reads it: RFC 5280 sec. 4.2's extension
 *  table and the criticality that profile fixes. One scope, so the single-extension verb takes no
 *  `opts.scope`. */
var CERT_SCOPES = intrinsic.assign(intrinsic.create(null), {
  certificate: {
    decoders: function (ctx) { return pkix.certExtensionDecoders(ctx).byOid; },
    criticality: pkix.certFixedCriticality(oid),
  },
});
var DOOR = pkix.extensionDoor({
  ns: NS, ErrorClass: CertificateError, key: "x509", kind: "certificate", what: "the certificate",
  parse: parse, scopes: CERT_SCOPES, defaultScope: "certificate",
  segments: function (cert) { return [{ list: cert.extensions || [], scope: "certificate" }]; },
});

/**
 * @primitive  pki.schema.x509.decodeExtensions
 * @signature  pki.schema.x509.decodeExtensions(certOrBytes, opts?) -> rows
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 5280 sec. 4.2
 * @related    pki.schema.x509.parse, pki.lint.certificate, pki.inspect.certificate
 *
 * Read a certificate's extensions as decoded records. `parse` hands back each extension's raw
 * `extnValue` octets, because what an extension means is a question the reader asks rather than
 * one the parse answers; this is the verb that asks it. The argument is the object `parse`
 * returned or the bytes `parse` takes, and a parse result is read rather than re-derived.
 *
 * Each row is `{ oid, name, critical, value, scope, index, state, decoded, code, profile }`, with
 * every field always present. `state` is the discriminator: `"decoded"` when the value read as the
 * structure its identifier names, `"unrecognized"` when this toolkit registers no decoder for that
 * OID, and `"undecodable"` when it does and the value did not read. Read `state` rather than
 * testing `decoded`, because a valid `ocspNoCheck` decodes to `null`.
 *
 * `value` carries the raw octets in every arm, byte-identical to the certificate's, for a caller
 * recomputing a hash or comparing an encoding. `code` is the typed error code in the undecodable
 * arm and `null` elsewhere. `profile` reports the criticality the RFC fixes for that OID, as
 * `{ criticalExpected, citation, deviates, violations }`, and is `null` for an extension whose
 * criticality the issuer chooses.
 *
 * Nothing here is a verdict. An unrecognized critical extension is reported rather than refused,
 * whatever `opts.strict` says, because RFC 5280 sec. 4.2's rule about one is the caller's to
 * apply and refusing it would make a certificate carrying a private critical extension
 * unreadable. The two facts that rule needs, `critical` and `state`, are on the row.
 *
 * @opts
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value. It does not turn an unrecognized OID into a throw.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call. Each may only
 *     tighten the built-in ceiling, and each bounds the decoding this call performs.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: false }, subjectAltName: [{ dNSName: "leaf.example" }] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var rows = pki.schema.x509.decodeExtensions(certDer);
 *   rows.filter(function (r) { return r.critical && r.state !== "decoded"; }).length;  // -> 0
 *   // The filter above is the RFC 5280 sec. 4.2 rule: a relying party rejects a certificate whose
 *   // critical extensions it cannot read.
 */
var decodeExtensions = DOOR.decodeExtensions;

/**
 * @primitive  pki.schema.x509.decodeExtension
 * @signature  pki.schema.x509.decodeExtension(ext, opts?) -> row
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 5280 sec. 4.2
 * @related    pki.schema.x509.decodeExtensions
 *
 * Read one certificate extension record as a decoded row. The argument is one element of a
 * `pki.schema.x509.parse` result's `extensions`, as `{ oid, name, critical, value }`, and the row
 * is the one `decodeExtensions` would have produced for it, with `index` 0.
 *
 * @opts
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call. Each may only
 *     tighten the built-in ceiling.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: false } } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var parsed = pki.schema.x509.parse(certDer);
 *   pki.schema.x509.decodeExtension(parsed.extensions[0]).state;  // -> "decoded"
 */
var decodeExtension = DOOR.decodeExtension;

module.exports = {
  parse:     parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches:   matches,
  decodeExtensions: decodeExtensions,
  decodeExtension:  decodeExtension,
};
