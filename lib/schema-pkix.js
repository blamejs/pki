// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal — no operator-facing namespace. The documented surface is the
// parsers that compose these factories (pki.schema.x509, pki.schema.crl, …).
//
// Shared PKIX structure-schema factories (RFC 5280). Each is a namespace-
// parameterized FACTORY: given an error namespace `ns` ({ prefix, E, oid }) it
// returns an asn1-schema that walks the corresponding ASN.1 structure and emits
// the caller's own <prefix>/* error codes. x509.js, crl.js, and future CMS/CSR
// parsers compose these so AlgorithmIdentifier / Name / Extension are defined
// once, not re-derived per format. This module is internal infrastructure — the
// operator-facing surface is the parsers that consume it.

var asn1 = require("./asn1-der");
var constants = require("./constants");
var schema = require("./schema-engine");

var PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

// ---- shared parse-entry ----------------------------------------------
// Input handling, PEM unwrapping (with the size cap), DER-decode wrapping, and
// the walk are defined ONCE here so no format can diverge on a guard. Each
// format supplies only its labels, error class, code prefix, and top schema.

// pemDecode(text, label, PemError): `label` (when truthy) is enforced, else the
// first block is taken. Applies the LIMITS.PEM_MAX_BYTES cap before scanning.
function pemDecode(text, label, PemError) {
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

function pemEncode(der, label, PemError) {
  if (typeof label !== "string" || label.length === 0) throw new PemError("pem/bad-label", "pemEncode requires a label");
  var buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  var b64 = buf.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
}

// Coerce parse input to DER bytes. A PEM string OR a PEM Buffer (a .pem file
// read with fs.readFileSync) is unwrapped with opts.pemLabel; a DER Buffer or
// Uint8Array is taken as bytes. opts: { pemLabel, PemError, ErrorClass, prefix }.
function coerceToDer(input, opts) {
  if (typeof input === "string") return pemDecode(input, opts.pemLabel, opts.PemError);
  if (input instanceof Uint8Array && !Buffer.isBuffer(input)) input = Buffer.from(input);
  if (Buffer.isBuffer(input)) {
    return _isPemArmor(input) ? pemDecode(input, opts.pemLabel, opts.PemError) : input;
  }
  throw new opts.ErrorClass(opts.prefix + "/bad-input", "parse expects a DER Buffer or a PEM string");
}

// Does a Buffer carry PEM armor (a .pem read with fs.readFileSync) rather than
// raw DER? It does iff "-----BEGIN" appears and everything before it is TEXT
// (UTF-8 BOM / whitespace / RFC 7468 explanatory preamble). DER is binary — its
// leading tag+length bytes are non-printable — so a non-SEQUENCE DER (a bare
// SET / INTEGER) is NOT misrouted here; it decodes and fails closed structurally.
function _isPemArmor(buf) {
  var head = buf.slice(0, 4096).toString("latin1");
  var idx = head.indexOf("-----BEGIN");
  if (idx === -1) return false;
  for (var i = 0; i < idx; i++) {
    var c = buf[i];
    var textByte = (c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d ||
      c === 0xef || c === 0xbb || c === 0xbf; // printable ASCII, tab/newlines, UTF-8 BOM
    if (!textByte) return false;
  }
  return true;
}

// Decode the DER root, wrapping a codec fault in the caller's <prefix>/bad-der.
function decodeRoot(der, opts) {
  try { return asn1.decode(der); }
  catch (e) { throw new opts.ErrorClass(opts.prefix + "/bad-der", (opts.what || "input") + " DER did not decode: " + ((e && e.message) || String(e)), e); }
}

// The shared parse entry: coerce -> decode -> walk the top schema. A format's
// parse() is one call to this; the guard-parity bug class (a new format not
// mirroring an existing format's input handling) is structurally impossible.
function runParse(input, opts) {
  return schema.walk(opts.topSchema, decodeRoot(coerceToDer(input, opts), opts), opts.ns).result;
}

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

// attrValueToString(ns): the AttributeValue decode-leaf. A malformed KNOWN
// string type (invalid UTF-8, a non-IA5 byte, a PrintableString character
// outside its set, ...) surfaces as an asn1/bad-* content error and must fail
// closed — do NOT hex-encode it away, or the decoder's strict string validation
// is silently bypassed on the DN path. A value that is simply not a decodable
// primitive string is NOT malformed and stays representable: an ANY-typed
// non-string tag (asn1/expected-string) or a constructed universal type such as
// a SEQUENCE (asn1/expected-primitive) renders per RFC 4514 §2.4 as "#" plus the
// hex of its FULL DER encoding (node.bytes), round-tripping intact.
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
  // RelativeDistinguishedName ::= SET SIZE (1..MAX) — an empty SET {} is malformed.
  return schema.setOf(attributeTypeAndValue(ns), { assert: "set", min: 1, code: ns.prefix + "/bad-rdn", what: "RelativeDistinguishedName" });
}
function name(ns) {
  return schema.seqOf(relativeDistinguishedName(ns), {
    assert: "sequence", code: ns.prefix + "/bad-name", what: "Name",
    build: function (m) {
      var rdns = [], parts = [];
      m.items.forEach(function (rdnItem) {
        var atvs = [], atvParts = [];
        rdnItem.value.items.forEach(function (atvItem) {
          var a = atvItem.value.result; // atvItem.value = the atv seq-match; .result = its build result
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

// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
// extnValue OCTET STRING }. `critical` is a universal BOOLEAN present-by-count
// (not context-tagged), so the per-extension decode handles the 2-vs-3-child
// shape directly; the seqOf centralizes the SEQUENCE / SIZE(1..MAX) assertion
// and the RFC 5280 §4.2 per-OID uniqueness.
function extension(ns) {
  return schema.decode(function (ext) {
    // Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue } — a
    // UNIVERSAL SEQUENCE of exactly 2 (critical omitted) or 3 children. A
    // context-tagged item (e.g. [5]{OID, OCTET STRING}) or a wrong child count
    // is malformed; assert the tag, don't just count children (fail closed).
    if (!ext.children || ext.tagClass !== "universal" || ext.tagNumber !== asn1.TAGS.SEQUENCE ||
        ext.children.length < 2 || ext.children.length > 3) {
      throw ns.E(ns.prefix + "/bad-extension", "Extension must be a SEQUENCE of {extnID, critical?, extnValue}");
    }
    var extnID = asn1.read.oid(ext.children[0]);
    var critical = false, valueNode;
    if (ext.children.length === 3) {
      critical = asn1.read.boolean(ext.children[1]);
      // critical is BOOLEAN DEFAULT FALSE — DER omits the field when false, so an
      // explicitly-encoded FALSE is a non-canonical form; reject it fail-closed.
      if (critical === false) throw ns.E(ns.prefix + "/bad-extension", "an explicit critical FALSE must be omitted (BOOLEAN DEFAULT FALSE)");
      valueNode = ext.children[2];
    } else {
      valueNode = ext.children[1];
    }
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

// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
// subjectPublicKey BIT STRING } (RFC 5280 §4.1.2.7, RFC 2986 §4.1). Asserted as a
// universal SEQUENCE — a context-tagged or SET-tagged constructed node carrying
// two well-formed children is NOT a SubjectPublicKeyInfo. Shared by the
// certificate and CSR parsers.
function spki(ns) {
  return schema.seq([
    schema.field("algorithm", algorithmIdentifier(ns)),
    schema.field("subjectPublicKey", schema.bitString()),
  ], {
    assert: "sequence", arity: { exact: 2 }, code: ns.prefix + "/bad-spki", what: "SubjectPublicKeyInfo",
    build: function (m) {
      return {
        algorithm: m.fields.algorithm.value.result,
        publicKey: { unusedBits: m.fields.subjectPublicKey.value.unusedBits, bytes: m.fields.subjectPublicKey.value.bytes },
        bytes: m.node.bytes,
      };
    },
  });
}

// Certificate, CertificateList, and CertificationRequest share one outer shape:
// SEQUENCE { toBeSigned SEQUENCE, signatureAlgorithm, signatureValue }. This
// returns the first element (the to-be-signed info) when `root` is that
// SEQUENCE-of-exactly-3 whose first child is itself a constructed universal
// SEQUENCE, or null otherwise. Every format's `matches` detector shares this
// preamble, so the signed-envelope shape is recognized in one place and the three
// detectors cannot drift on it (the CRL detector historically omitted the
// tbs-is-universal check this recovers).
function signedEnvelopeTbs(root) {
  if (!root || root.tagClass !== "universal" || root.tagNumber !== asn1.TAGS.SEQUENCE) return null;
  if (!root.children || root.children.length !== 3) return null;
  var tbs = root.children[0];
  if (!tbs.children || tbs.tagClass !== "universal" || tbs.tagNumber !== asn1.TAGS.SEQUENCE) return null;
  return tbs;
}

// Every format's `parse` is the shared runParse bound to that format's identity
// (PEM label, error class, error-code prefix, top-level schema). This returns the
// bound parser so a format declares its configuration once and never re-writes the
// coerce -> decode -> walk wrapper. `opts`: { pemLabel, PemError, ErrorClass,
// prefix, what, topSchema, ns }.
function makeParser(opts) {
  return function (input) { return runParse(input, opts); };
}

// The X.509 SIGNED{ToBeSigned} macro (RFC 5280 §4.1.1.3): the outer
// SEQUENCE { toBeSigned, signatureAlgorithm AlgorithmIdentifier,
// signatureValue BIT STRING } shared by Certificate, CertificateList and
// CertificationRequest. `tbsSchema` parses the first element; the SEQUENCE-of-3
// shape, the arity, the signature extraction and the raw tbs / outer-signature
// bytes (for the cert/CRL outer==inner agreement check) are owned here once, and
// each format's `opts.build(envelope, ctx)` shapes its own object from the
// envelope. A CSR's build simply omits the agreement check — its CRI has no inner
// signature AlgorithmIdentifier — so the omission is structural, not a copy that
// forgot a guard.
function signedEnvelope(ns, tbsSchema, opts) {
  return schema.seq([
    schema.field("toBeSigned", tbsSchema),
    schema.field("signatureAlgorithm", algorithmIdentifier(ns)),
    schema.field("signatureValue", schema.bitString()),
  ], {
    assert: "sequence", arity: { exact: 3 }, code: opts.code, what: opts.what,
    build: function (m, ctx) {
      var tbsMatch = m.fields.toBeSigned.value;
      var sigBits = m.fields.signatureValue.value;
      return opts.build({
        tbsMatch: tbsMatch,                                    // raw seq-match: .fields.* / .result / .node
        tbsBytes: tbsMatch.node.bytes,                         // the exact signed region
        outerSignatureAlgorithmBytes: m.fields.signatureAlgorithm.node.bytes,
        signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
        signatureValue: { unusedBits: sigBits.unusedBits, bytes: sigBits.bytes },
      }, ctx);
    },
  });
}

module.exports = {
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  coerceToDer: coerceToDer,
  decodeRoot: decodeRoot,
  runParse: runParse,
  DN_SHORT: DN_SHORT,
  algorithmIdentifier: algorithmIdentifier,
  spki: spki,
  makeParser: makeParser,
  signedEnvelopeTbs: signedEnvelopeTbs,
  signedEnvelope: signedEnvelope,
  attrValueToString: attrValueToString,
  attributeTypeAndValue: attributeTypeAndValue,
  relativeDistinguishedName: relativeDistinguishedName,
  name: name,
  extension: extension,
  extensions: extensions,
};

