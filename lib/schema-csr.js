// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.csr
 * @nav        Schema
 * @title      CSR
 * @order      130
 * @slug       csr
 *
 * @intro
 *   PKCS#10 certification request handling per RFC 2986. `parse` turns a DER or
 *   PEM CSR into a structured object: version, subject distinguished name,
 *   subject public-key info, the requested attributes (each with its raw values),
 *   and the signature over the CertificationRequestInfo. It composes the same
 *   schema engine and shared PKIX sub-schemas (AlgorithmIdentifier, Name,
 *   SubjectPublicKeyInfo) the certificate parser uses, so the request inherits the
 *   identical fail-closed structural rules, and the raw
 *   `certificationRequestInfoBytes` are returned for signature checking.
 *
 *   A CSR is self-signed only in the sense that the requester proves possession of
 *   the private key; unlike a certificate or CRL there is no inner signature
 *   algorithm to agree with, the subject MAY be empty, and the attribute set has
 *   no uniqueness constraint: the parser deliberately omits those three
 *   certificate/CRL guards.
 *
 * @card
 *   Parse DER / PEM PKCS#10 CSRs into structured, validated fields: subject DN,
 *   public key, requested attributes, signature, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");

var CsrError = frameworkError.CsrError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("csr", CsrError, oid);

var NAME = pkix.name(NS);
var SPKI = pkix.spki(NS);

var CSR_VERSION = pkix.versionReader(NS, { "0": 1 });

var ATTRIBUTE = pkix.attribute(NS);

var EXTENSIONS = pkix.extensions(NS);
var DIRECTORY_STRING_TAGS = [
  asn1.TAGS.UTF8_STRING, asn1.TAGS.PRINTABLE_STRING, asn1.TAGS.TELETEX_STRING,
  asn1.TAGS.UNIVERSAL_STRING, asn1.TAGS.BMP_STRING,
];
var RECOGNIZED_ATTRIBUTE_VALUE = intrinsic.create(null);
RECOGNIZED_ATTRIBUTE_VALUE[oid.byName("extensionRequest")] = function (node, ctx) {
  try { return { extensions: schema.walk(EXTENSIONS, node, ctx).result }; }
  catch (e) {
    throw ctx.E("csr/bad-attribute-value",
      "extensionRequest value must be a well-formed Extensions SEQUENCE (RFC 2985 sec. 5.4.2): " + ((e && e.message) || intrinsic.String(e)), e);
  }
};
RECOGNIZED_ATTRIBUTE_VALUE[oid.byName("challengePassword")] = function (node, ctx) {
  if (node.tagClass !== "universal" || intrinsic.indexOf(DIRECTORY_STRING_TAGS, node.tagNumber) === -1) {
    throw ctx.E("csr/bad-attribute-value", "challengePassword must be a DirectoryString (RFC 2985 sec. 5.4.1)");
  }
  var s;
  try { s = asn1.read.string(node); }
  catch (e) { throw ctx.E("csr/bad-attribute-value", "challengePassword must be a well-formed DirectoryString (RFC 2985 sec. 5.4.1)", e); }
  if (s.length < 1 || s.length > 255) {
    throw ctx.E("csr/bad-attribute-value", "challengePassword must be 1..255 characters (RFC 2985 sec. 5.4.1)");
  }
};

var CERTIFICATION_REQUEST_INFO = schema.seq([
  schema.field("version", CSR_VERSION),
  schema.field("subject", NAME),
  schema.field("subjectPKInfo", SPKI),
  schema.field("attributes", schema.implicitSetOf(0, ATTRIBUTE, { min: 0, code: "csr/bad-attributes", what: "attributes" })),
], {
  assert: "sequence", code: "csr/bad-cri", what: "certificationRequestInfo",
  build: function (m, ctx) {
    var attributes = intrinsic.map(m.fields.attributes.value.items, function (it) {
      var a = it.value.result;
      var checkValue = RECOGNIZED_ATTRIBUTE_VALUE[a.type];
      if (checkValue) {
        var valueItems = it.value.fields.values.value.items;
        if (valueItems.length !== 1) {
          throw ctx.E("csr/bad-attribute-value", (a.name || a.type) + " is a SINGLE VALUE attribute (RFC 2985 sec. 5.4)");
        }
        var enriched = checkValue(valueItems[0].node, ctx);
        if (enriched) { intrinsic.forEach(intrinsic.keys(enriched), function (k) { a[k] = enriched[k]; }); }
      }
      return a;
    });
    return {
      version: m.fields.version.value,
      subject: m.fields.subject.value.result,
      subjectPublicKeyInfo: m.fields.subjectPKInfo.value.result,
      attributes: attributes,
    };
  },
});

var CERTIFICATION_REQUEST = pkix.signedEnvelope(NS, CERTIFICATION_REQUEST_INFO, {
  code: "csr/not-a-certification-request", what: "CertificationRequest",
  build: function (e) {
    var cri = e.tbsMatch.result;
    return {
      version: cri.version,
      subject: cri.subject,
      subjectPublicKeyInfo: cri.subjectPublicKeyInfo,
      attributes: cri.attributes,
      certificationRequestInfoBytes: e.tbsBytes,
      tbsBytes: e.tbsBytes,
      signatureAlgorithm: e.signatureAlgorithm,
      signatureValue: e.signatureValue,
    };
  },
});

/**
 * @primitive  pki.schema.csr.parse
 * @signature  pki.schema.csr.parse(input, caps?) -> csr
 * @since      0.1.8
 * @status     stable
 * @spec       RFC 2986
 * @related    pki.schema.x509.parse, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM (`CERTIFICATE REQUEST`) string into a structured
 * PKCS#10 request: `{ version, subject, subjectPublicKeyInfo, attributes,
 * certificationRequestInfoBytes, tbsBytes, signatureAlgorithm, signatureValue }`.
 * Every field is validated on the way in; a malformed CertificationRequest /
 * CertificationRequestInfo throws a typed `CsrError` (`csr/*`) and a leaf-level
 * codec fault surfaces as `asn1/*`. Attribute values are returned as raw DER
 * buffers so an unrecognized attribute type never fails the parse; the
 * `extensionRequest` attribute additionally carries its requested extensions
 * decoded on `.extensions` (the `{ oid, name, critical, value }` shape a
 * certificate's extensions use).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.csr.sign(
 *     { subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *       extensionRequest: { subjectAltName: [{ dNSName: "req.example" }] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var csr = pki.schema.csr.parse(der);
 *   csr.subject.dn;             // -> "CN=req.example"
 *   csr.attributes[0].type;     // -> "1.2.840.113549.1.9.14"
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. A parse that exceeds one is
 *     refused with the `/too-large` code of this format.
 */
var parse = pkix.makeRecordingParser({ pemLabel: "CERTIFICATE REQUEST", PemError: PemError, ErrorClass: CsrError, prefix: "csr", what: "certification request", topSchema: CERTIFICATION_REQUEST, ns: NS }, "csr");

/**
 * @primitive  pki.schema.csr.pemDecode
 * @signature  pki.schema.csr.pemDecode(text, label?) -> Buffer
 * @since      0.1.8
 * @status     stable
 * @spec       RFC 7468, RFC 2986
 * @related    pki.schema.csr.parse
 *
 * Extract the DER bytes from a PEM CSR block (default label `CERTIFICATE
 * REQUEST`). Throws `PemError` on a missing / mismatched envelope or a non-base64
 * body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pemText = await pki.csr.sign({ subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey) },
 *     { key: await pki.key.export(pair.privateKey) }, { pem: true });
 *   var der = pki.schema.csr.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "CERTIFICATE REQUEST", PemError); }

/**
 * @primitive  pki.schema.csr.pemEncode
 * @signature  pki.schema.csr.pemEncode(der, label?) -> string
 * @since      0.1.8
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.csr.pemDecode
 *
 * Wrap DER bytes in a PEM CSR envelope (default label `CERTIFICATE REQUEST`).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.csr.sign({ subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey) },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var pem = pki.schema.csr.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "CERTIFICATE REQUEST", PemError); }

function matches(root) {
  var TAGS = asn1.TAGS;
  var cri = pkix.signedEnvelopeTbs(root);
  if (!cri) return false;
  var k = cri.children;
  if (k.length !== 4) return false;
  return schema.isUniversal(k[0], TAGS.INTEGER) &&
    schema.isUniversal(k[1], TAGS.SEQUENCE) &&
    schema.isUniversal(k[2], TAGS.SEQUENCE) &&
    schema.isContext(k[3], 0);
}

/** @internal A request asks for certificate extensions, so the certificate table reads them. What
 *  the scope changes is the verdict a caller draws: RFC 2985 sec. 5.4.2 makes criticality part of
 *  the REQUEST, and which requested extensions to honor, critical or not, is the CA's decision. The
 *  criticality profile is reported all the same, because a CA honoring a request against it would
 *  issue a non-conforming certificate. */
var CSR_SCOPES = intrinsic.assign(intrinsic.create(null), {
  "csr-requested": {
    decoders: function (ctx) { return pkix.certExtensionDecoders(ctx).byOid; },
    criticality: pkix.certFixedCriticality(oid),
  },
});
var OID_EXTENSION_REQUEST = oid.byName("extensionRequest");

function _err(code, message, cause) { return new CsrError(code, message, cause); }

var DOOR = pkix.extensionDoor({
  ns: NS, ErrorClass: CsrError, key: "csr", kind: "csr", what: "the certification request",
  parse: parse, scopes: CSR_SCOPES, defaultScope: "csr-requested", groups: true,
  segments: function (csr, read) {
    var attrs = csr.attributes || [];
    var out = [];
    for (var i = 0; i < attrs.length; i++) {
      if (attrs[i].type !== OID_EXTENSION_REQUEST) continue;
      intrinsic.push(out, { list: attrs[i].extensions || [], scope: "csr-requested", containerIndex: i });
    }
    if (!read.groups && out.length > 1) {
      throw _err("csr/ambiguous-extension-request", "this request carries " + out.length +
        " extensionRequest attributes, and which of them a CA should honor is not stated anywhere; " +
        "pass { groups: true } to read each one separately");
    }
    return out;
  },
  group: function (rows, segments) {
    var out = [], byIndex = intrinsic.create(null);
    for (var s = 0; s < segments.length; s++) {
      var g = { attributeIndex: segments[s].containerIndex, extensions: [] };
      byIndex[segments[s].containerIndex] = g;
      intrinsic.push(out, g);
    }
    for (var r = 0; r < rows.length; r++) intrinsic.push(byIndex[rows[r].containerIndex].extensions, rows[r]);
    return out;
  },
});

/**
 * @primitive  pki.schema.csr.decodeExtensions
 * @signature  pki.schema.csr.decodeExtensions(csrOrBytes, opts?) -> rows
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 2985 sec. 5.4.2, RFC 5280 sec. 4.2
 * @related    pki.schema.csr.parse, pki.schema.x509.decodeExtensions
 *
 * Read the extensions a certification request asks for, as decoded records. This is the verb a CA
 * calls to see what a request wants before deciding what to issue. The argument is the object
 * `parse` returned or the bytes `parse` takes.
 *
 * The rows come from the request's one `extensionRequest` attribute. A request carrying more than
 * one is refused with `csr/ambiguous-extension-request`, because nothing says which of them a CA
 * should honor; pass `groups: true` to read each attribute separately instead.
 *
 * Each row is `{ oid, name, critical, value, scope, index, containerIndex, state, decoded, code,
 * profile }`, with `scope` `"csr-requested"` and `containerIndex` the position of the attribute the
 * row came from. Criticality here is part of the request, not a verdict: RFC 2985 sec. 5.4.2 leaves
 * which requested extensions to honor to the CA, and `profile` reports what RFC 5280 would fix for
 * the certificate that request would produce.
 *
 * @opts
 *   - `groups` (boolean) -- return `[{ attributeIndex, extensions }]`, one entry per
 *     `extensionRequest` attribute, instead of one flat table. This is how a non-conforming request
 *     carrying several is read.
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value. It does not turn an unrecognized OID into a throw.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var csrDer = await pki.csr.sign({ subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     extensionRequest: { subjectAltName: [{ dNSName: "req.example" }] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var rows = pki.schema.csr.decodeExtensions(csrDer);
 *   rows.filter(function (r) { return r.name === "subjectAltName"; })[0].state;  // -> "decoded"
 */
var decodeExtensions = DOOR.decodeExtensions;

/**
 * @primitive  pki.schema.csr.decodeExtension
 * @signature  pki.schema.csr.decodeExtension(ext, opts?) -> row
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 2985 sec. 5.4.2
 * @related    pki.schema.csr.decodeExtensions
 *
 * Read one requested extension record as a decoded row, at scope `"csr-requested"`. The argument is
 * one element of an `extensionRequest` attribute's `extensions`, as `{ oid, name, critical, value }`.
 *
 * @opts
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var csrDer = await pki.csr.sign({ subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     extensionRequest: { subjectAltName: [{ dNSName: "req.example" }] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var csr = pki.schema.csr.parse(csrDer);
 *   pki.schema.csr.decodeExtension(csr.attributes[0].extensions[0]).state;  // -> "decoded"
 */
var decodeExtension = DOOR.decodeExtension;

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  decodeExtensions: decodeExtensions,
  decodeExtension: decodeExtension,
  certificationRequestSchema: CERTIFICATION_REQUEST,
};
