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
var schema = require("./schema-engine");

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
    // Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue } —
    // exactly 2 (critical omitted) or 3 children. Fewer, or a 4th+ element, is
    // malformed; do NOT silently ignore trailing children (fail closed).
    if (!ext.children || ext.children.length < 2 || ext.children.length > 3) {
      throw ns.E(ns.prefix + "/bad-extension", "Extension must be a SEQUENCE of {extnID, critical?, extnValue}");
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

module.exports = {
  DN_SHORT: DN_SHORT,
  algorithmIdentifier: algorithmIdentifier,
  attrValueToString: attrValueToString,
  attributeTypeAndValue: attributeTypeAndValue,
  relativeDistinguishedName: relativeDistinguishedName,
  name: name,
  extension: extension,
  extensions: extensions,
};

