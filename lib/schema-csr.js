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
var RECOGNIZED_ATTRIBUTE_VALUE = Object.create(null);
RECOGNIZED_ATTRIBUTE_VALUE[oid.byName("extensionRequest")] = function (node, ctx) {
  try { return { extensions: schema.walk(EXTENSIONS, node, ctx).result }; }
  catch (e) {
    throw ctx.E("csr/bad-attribute-value",
      "extensionRequest value must be a well-formed Extensions SEQUENCE (RFC 2985 sec. 5.4.2): " + ((e && e.message) || String(e)), e);
  }
};
RECOGNIZED_ATTRIBUTE_VALUE[oid.byName("challengePassword")] = function (node, ctx) {
  if (node.tagClass !== "universal" || DIRECTORY_STRING_TAGS.indexOf(node.tagNumber) === -1) {
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
    var attributes = m.fields.attributes.value.items.map(function (it) {
      var a = it.value.result;
      var checkValue = RECOGNIZED_ATTRIBUTE_VALUE[a.type];
      if (checkValue) {
        var valueItems = it.value.fields.values.value.items;
        if (valueItems.length !== 1) {
          throw ctx.E("csr/bad-attribute-value", (a.name || a.type) + " is a SINGLE VALUE attribute (RFC 2985 sec. 5.4)");
        }
        var enriched = checkValue(valueItems[0].node, ctx);
        if (enriched) { Object.keys(enriched).forEach(function (k) { a[k] = enriched[k]; }); }
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
 * @signature  pki.schema.csr.parse(input) -> csr
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

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  certificationRequestSchema: CERTIFICATION_REQUEST,
};
