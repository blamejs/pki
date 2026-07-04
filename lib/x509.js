// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.x509
 * @nav        Certificates
 * @title      X.509
 * @order      100
 * @featured   true
 * @slug       x509
 *
 * @intro
 *   X.509 certificate handling per RFC 5280. The seed surface is
 *   `parse` — turn a DER or PEM certificate into a structured,
 *   fully-decoded object: version, serial, signature algorithm, issuer
 *   and subject distinguished names, validity window (as real `Date`s),
 *   subject public-key info, and the extension list. The parser composes
 *   the strict DER codec and the OID registry, so every field is
 *   validated on the way in and every algorithm / attribute / extension
 *   is named where the registry knows it.
 *
 *   The raw `tbsCertificate` bytes are returned alongside the parsed
 *   fields so a signature-verification layer can hash exactly the bytes
 *   that were signed rather than re-encoding and hoping for round-trip
 *   fidelity.
 *
 * @card
 *   Parse DER / PEM X.509 certificates into structured, validated fields
 *   with named algorithms, extensions, and real-`Date` validity windows.
 */

var constants = require("./constants");
var asn1 = require("./asn1-der");
var schema = require("./asn1-schema");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CertificateError = frameworkError.CertificateError;
var PemError = frameworkError.PemError;

// Distinguished-name attribute short labels (RFC 4514 §3 + common use).
var DN_SHORT = {
  commonName:             "CN",
  countryName:            "C",
  localityName:           "L",
  stateOrProvinceName:    "ST",
  streetAddress:          "STREET",
  organizationName:       "O",
  organizationalUnitName: "OU",
  domainComponent:        "DC",
  surname:                "SN",
  givenName:              "GN",
  serialNumber:           "SERIALNUMBER",
  emailAddress:           "emailAddress",
};

// ---- PEM -------------------------------------------------------------

var PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

/**
 * @primitive  pki.x509.pemDecode
 * @signature  pki.x509.pemDecode(text, label?) -> Buffer
 * @since      0.1.0
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.x509.pemEncode
 *
 * Extract the DER bytes from a PEM block. With `label` given (e.g.
 * `"CERTIFICATE"`) the block type must match; without it, the first block
 * is taken. Throws `PemError` on a missing / mismatched envelope or a
 * non-base64 body.
 *
 * @example
 *   var der = pki.x509.pemDecode(pemText, "CERTIFICATE");
 */
function pemDecode(text, label) {
  if (Buffer.isBuffer(text)) text = text.toString("latin1");
  if (typeof text !== "string") throw new PemError("pem/bad-input", "pemDecode expects a string or Buffer");
  if (text.length > constants.LIMITS.PEM_MAX_BYTES) throw new PemError("pem/too-large", "PEM input exceeds size cap");
  var m = PEM_RE.exec(text);
  if (!m) throw new PemError("pem/no-block", "no PEM block found");
  if (label && m[1] !== label) throw new PemError("pem/label-mismatch", "expected " + JSON.stringify(label) + " block, got " + JSON.stringify(m[1]));
  var b64 = m[2].replace(/[\r\n\t ]+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new PemError("pem/bad-base64", "PEM body is not valid base64");
  return Buffer.from(b64, "base64");
}

/**
 * @primitive  pki.x509.pemEncode
 * @signature  pki.x509.pemEncode(der, label) -> string
 * @since      0.1.0
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.x509.pemDecode
 *
 * Wrap DER bytes in a PEM envelope with 64-column base64 lines.
 *
 * @example
 *   var pem = pki.x509.pemEncode(der, "CERTIFICATE");
 */
function pemEncode(der, label) {
  if (typeof label !== "string" || label.length === 0) throw new PemError("pem/bad-label", "pemEncode requires a label");
  var buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  var b64 = buf.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
}

// ---- helpers ---------------------------------------------------------

// The x509 error namespace the schema engine walks under: prefix names the
// error family and E constructs the typed CertificateError. The shared PKIX
// sub-schemas below are ns-parameterized FACTORIES so crl.js / cms.js can later
// reuse them while emitting their own crl/*, cms/* codes (hoist to a shared
// lib/pkix-schema.js when that second consumer lands).
var NS = { prefix: "x509", E: function (code, message) { return new CertificateError(code, message); }, oid: oid };

// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
function algorithmIdentifier(ns) {
  return schema.seq([
    schema.field("algorithm", schema.oidLeaf()),
    schema.optional("parameters", schema.any(), { whenAny: true }),
  ], {
    assert: "sequence", arity: { min: 1 }, code: ns.prefix + "/bad-algorithm-identifier", what: "AlgorithmIdentifier",
    build: function (m, ctx) {
      var dotted = m.fields.algorithm.value;
      return { oid: dotted, name: ctx.oid.name(dotted) || null, parameters: m.fields.parameters.present ? m.fields.parameters.node.bytes : null };
    },
  });
}
var ALGORITHM_IDENTIFIER = algorithmIdentifier(NS);

function _algId(node) { return schema.walk(ALGORITHM_IDENTIFIER, node, NS).result; }

// attrValueToString(ns): the AttributeValue decode-leaf. A malformed KNOWN
// string type (invalid UTF-8, a non-IA5 byte, a PrintableString character
// outside its set, ...) surfaces as an asn1/bad-* content error and must fail
// the certificate closed — do NOT hex-encode it away, or the decoder's strict
// string validation is silently bypassed on the DN path. A value that is simply
// not a decodable primitive string is NOT malformed and stays representable: an
// ANY-typed non-string tag (asn1/expected-string) or a constructed universal
// type such as a SEQUENCE (asn1/expected-primitive) renders per RFC 4514 §2.4 as
// "#" plus the hex of its FULL DER encoding (node.bytes), round-tripping intact.
function attrValueToString(ns) {
  return schema.decode(function (node) {
    try { return asn1.read.string(node); }
    catch (e) {
      if (!e || (e.code !== "asn1/expected-string" && e.code !== "asn1/expected-primitive")) {
        throw ns.E(ns.prefix + "/bad-atv", "malformed string in attribute value: " + ((e && e.message) || String(e)));
      }
      return "#" + node.bytes.toString("hex");
    }
  });
}

function _escapeDnValue(v) {
  return v.replace(/([,+"\\<>;])/g, "\\$1");
}

// Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName; RDN ::= SET OF
// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }. The atv asserts
// bare-constructed (min 2) — matching the historical guard that never checked
// the SEQUENCE tag — and repeated RDN attribute types stay legal (no uniqueness).
function attributeTypeAndValue(ns) {
  return schema.seq([
    schema.field("type", schema.oidLeaf()),
    schema.field("value", attrValueToString(ns)),
  ], {
    assert: "constructed", arity: { min: 2 }, code: ns.prefix + "/bad-atv", what: "AttributeTypeAndValue",
    build: function (m, ctx) {
      var typeOid = m.fields.type.value;
      return { type: typeOid, name: ctx.oid.name(typeOid) || null, value: m.fields.value.value };
    },
  });
}
function relativeDistinguishedName(ns) {
  return schema.setOf(attributeTypeAndValue(ns), { assert: "set", code: ns.prefix + "/bad-rdn", what: "RelativeDistinguishedName" });
}
function name(ns) {
  return schema.seqOf(relativeDistinguishedName(ns), {
    assert: "sequence", code: ns.prefix + "/bad-name", what: "Name",
    build: function (m) {
      var rdns = [], parts = [];
      m.items.forEach(function (rdnItem) {
        var atvs = [], atvParts = [];
        rdnItem.value.items.forEach(function (atvItem) {
          var a = atvItem.value.result; // atvItem.value = the atv seq-match; .value = its build result
          atvs.push(a);
          var label = (a.name && DN_SHORT[a.name]) || a.name || a.type;
          atvParts.push(label + "=" + _escapeDnValue(a.value));
        });
        rdns.push(atvs);
        parts.push(atvParts.join("+"));
      });
      return { rdns: rdns, dn: parts.join(", ") };
    },
  });
}
var NAME = name(NS);

function _parseName(node) { return schema.walk(NAME, node, NS).result; }

// Validity ::= SEQUENCE { notBefore Time, notAfter Time }. The historical guard
// checked only children.length===2 (not the SEQUENCE tag) -> assert "constructed".
var VALIDITY = schema.seq([
  schema.field("notBefore", schema.time(NS)),
  schema.field("notAfter", schema.time(NS)),
], {
  assert: "constructed", arity: { exact: 2 }, code: "x509/bad-validity", what: "Validity",
  build: function (m) { return { notBefore: m.fields.notBefore.value, notAfter: m.fields.notAfter.value }; },
});

// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
var SPKI = schema.seq([
  schema.field("algorithm", ALGORITHM_IDENTIFIER),
  schema.field("subjectPublicKey", schema.bitString()),
], {
  assert: "constructed", arity: { exact: 2 }, code: "x509/bad-spki", what: "SubjectPublicKeyInfo",
  build: function (m) {
    return {
      algorithm: m.fields.algorithm.value.result, // algorithm field = ALGORITHM_IDENTIFIER seq-match; .value = its build
      publicKey: { unusedBits: m.fields.subjectPublicKey.value.unusedBits, bytes: m.fields.subjectPublicKey.value.bytes },
      bytes: m.node.bytes,
    };
  },
});

// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
// extnValue OCTET STRING }. `critical` is a universal BOOLEAN present-by-count
// (not context-tagged), so the per-extension decode handles the 2-vs-3-child
// shape directly; the seqOf centralizes the SEQUENCE / SIZE(1..MAX) assertion
// and the RFC 5280 §4.2 per-OID uniqueness.
function extension(ns) {
  return schema.decode(function (ext) {
    if (!ext.children || ext.children.length < 2) {
      throw ns.E(ns.prefix + "/bad-extension", "Extension must be a SEQUENCE");
    }
    var extnID = asn1.read.oid(ext.children[0]);
    var critical = false, valueNode;
    if (ext.children.length === 3) { critical = asn1.read.boolean(ext.children[1]); valueNode = ext.children[2]; }
    else { valueNode = ext.children[1]; }
    return { oid: extnID, name: ns.oid.name(extnID) || null, critical: critical, value: asn1.read.octetString(valueNode) };
  });
}
function extensions(ns) {
  return schema.seqOf(extension(ns), {
    assert: "sequence", min: 1, code: ns.prefix + "/bad-extensions", what: "Extensions",
    unique: function (item) { return item.value.oid; }, dupCode: ns.prefix + "/duplicate-extension",
    build: function (m) { return m.items.map(function (it) { return it.value; }); },
  });
}
var EXTENSIONS = extensions(NS);

function _parseExtensions(seqNode) { return schema.walk(EXTENSIONS, seqNode, NS).result; }

// Version ::= INTEGER { v1(0), v2(1), v3(2) }, [0] EXPLICIT DEFAULT v1. Read as a
// BigInt so an out-of-range value can't coerce to a float; reject an explicitly-
// encoded v1 (DER forbids encoding the DEFAULT).
function readVersion(ns) {
  return schema.decode(function (n) {
    var v = asn1.read.integer(n);
    if (v === 0n) throw ns.E(ns.prefix + "/bad-version", "DER forbids explicitly encoding the default version v1");
    if (v === 1n) return 2;
    if (v === 2n) return 3;
    throw ns.E(ns.prefix + "/bad-version", "unsupported certificate version " + v.toString());
  });
}

// TBSCertificate ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, serialNumber
// INTEGER, signature AlgorithmIdentifier, issuer Name, validity Validity,
// subject Name, subjectPublicKeyInfo SubjectPublicKeyInfo, issuerUniqueID [1]
// IMPLICIT OPTIONAL, subjectUniqueID [2] IMPLICIT OPTIONAL, extensions [3]
// EXPLICIT OPTIONAL }. The trailing fields are at-most-once, in increasing tag
// order (the engine enforces it); only extensions are surfaced.
var CERTIFICATE_TBS = schema.seq([
  schema.optional("version", readVersion(NS), { tag: 0, explicit: true, emptyCode: "x509/bad-version", default: 1 }),
  schema.field("serialNumber", schema.integerLeaf()),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("issuer", NAME),
  schema.field("validity", VALIDITY),
  schema.field("subject", NAME),
  schema.field("subjectPublicKeyInfo", SPKI),
  schema.trailing([
    { tag: 1, name: "issuerUniqueID", schema: schema.any() },
    { tag: 2, name: "subjectUniqueID", schema: schema.any() },
    { tag: 3, name: "extensions", schema: EXTENSIONS, explicit: true, emptyCode: "x509/bad-extensions" },
  ], { minTag: 1, maxTag: 3, unexpectedCode: "x509/bad-tbs", orderCode: "x509/bad-tbs" }),
], { assert: "constructed", code: "x509/bad-tbs", what: "tbsCertificate" });

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue
// BIT STRING }. The build runs the RFC 5280 cross-field checks (§4.1.1.2 sig-alg
// agreement, §4.1.2.4 non-empty issuer, §4.1.2.9 extensions-only-in-v3) after the
// structural walk, then assembles the public parse result. Raw-byte accessors
// (serialNumberHex, tbsBytes, sig-alg agreement) read off the match-tree nodes.
var CERTIFICATE = schema.seq([
  schema.field("tbsCertificate", CERTIFICATE_TBS),
  schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("signatureValue", schema.bitString()),
], {
  assert: "sequence", arity: { exact: 3 }, code: "x509/not-a-certificate", what: "Certificate",
  build: function (m, ctx) {
    var tbs = m.fields.tbsCertificate.value; // CERTIFICATE_TBS seq-match (no build)

    // RFC 5280 §4.1.1.2 — outer signatureAlgorithm MUST equal tbsCertificate.signature.
    if (!m.fields.signatureAlgorithm.node.bytes.equals(tbs.fields.signature.node.bytes)) {
      throw ctx.E("x509/bad-signature-algorithm", "signatureAlgorithm must match tbsCertificate.signature (RFC 5280 §4.1.1.2)");
    }

    var version = tbs.fields.version.value; // 1 (default) | 2 | 3
    var issuer = tbs.fields.issuer.value.result;
    // RFC 5280 §4.1.2.4 — issuer MUST be non-empty (an empty subject is permitted, §4.1.2.6).
    if (!issuer.rdns.length) {
      throw ctx.E("x509/bad-issuer", "issuer must be a non-empty distinguished name");
    }

    var extField = tbs.fields.extensions;
    var hasExtensions = !!(extField && extField.present);
    // RFC 5280 §4.1.2.9 — extensions appear only in a v3 certificate.
    if (hasExtensions && version !== 3) {
      throw ctx.E("x509/bad-version", "extensions are only permitted in a v3 certificate");
    }

    var serialNode = tbs.fields.serialNumber.node;
    var sigBits = m.fields.signatureValue.value; // { unusedBits, bytes }
    return {
      version:               version,
      serialNumber:          tbs.fields.serialNumber.value,
      serialNumberHex:       serialNode.content.toString("hex"),
      signatureAlgorithm:    m.fields.signatureAlgorithm.value.result,
      tbsSignatureAlgorithm: tbs.fields.signature.value.result,
      issuer:                issuer,
      subject:               tbs.fields.subject.value.result,
      validity:              tbs.fields.validity.value.result,
      subjectPublicKeyInfo:  tbs.fields.subjectPublicKeyInfo.value.result,
      extensions:            hasExtensions ? extField.value.result : [],
      tbsBytes:              tbs.node.bytes,
      signatureValue:        { unusedBits: sigBits.unusedBits, bytes: sigBits.bytes },
    };
  },
});

// ---- parse -----------------------------------------------------------

/**
 * @primitive  pki.x509.parse
 * @signature  pki.x509.parse(input) -> certificate
 * @since      0.1.0
 * @status     stable
 * @spec       RFC 5280, X.509
 * @defends    malformed-certificate-parse (CWE-20)
 * @related    pki.asn1.decode, pki.oid.name
 *
 * Parse a DER `Buffer` or a PEM string/Buffer into a structured
 * certificate: `{ version, serialNumber, serialNumberHex,
 * signatureAlgorithm, issuer, subject, validity, subjectPublicKeyInfo,
 * extensions, tbsBytes, signatureValue }`. Distinguished names come back
 * both as a rendered `dn` string and as structured `rdns`; the validity
 * window is real `Date`s; `tbsBytes` is the exact signed byte range for a
 * downstream verifier.
 *
 * Throws `CertificateError` when the bytes are not a well-formed
 * certificate and `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var cert = pki.x509.parse(pemString);
 *   cert.subject.dn;                 // "CN=example.com, O=Example"
 *   cert.validity.notAfter;          // Date
 *   cert.signatureAlgorithm.name;    // "sha256WithRSAEncryption"
 */
function parse(input) {
  var der;
  if (typeof input === "string" || (Buffer.isBuffer(input) && input.length >= 5 && input.toString("latin1", 0, 5) === "-----")) {
    der = pemDecode(input, "CERTIFICATE");
  } else if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    der = Buffer.isBuffer(input) ? input : Buffer.from(input);
  } else {
    throw new CertificateError("x509/bad-input", "parse expects a DER Buffer or a PEM string");
  }

  var root;
  try {
    root = asn1.decode(der);
  } catch (e) {
    throw new CertificateError("x509/bad-der", "certificate DER did not decode: " + e.message, e);
  }
  return schema.walk(CERTIFICATE, root, NS).result;
}

module.exports = {
  parse:     parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
};
