// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.smime
 * @nav        Schema
 * @title      S/MIME (ESS)
 * @order      180
 * @slug       smime
 *
 * @intro
 *   S/MIME Enhanced Security Services signed-attribute values per RFC 5035 (ESS)
 *   and RFC 8551 (S/MIME 4.0). These are the DER-decoded VALUES of CMS signed
 *   attributes — they ride inside a `SignerInfo.signedAttrs`, so this is a
 *   companion decoder a CMS consumer invokes by attribute OID, NOT a top-level
 *   format the schema orchestrator auto-routes.
 *
 *   `parseSigningCertificate` / `parseSigningCertificateV2` decode the ESS
 *   signing-certificate attributes that bind a signature to the exact certificate
 *   that made it: each surfaces its list of `ESSCertID`(v2) — the certificate hash
 *   (raw), the hash algorithm (decoded for v2, or the implied SHA-1 for v1), and
 *   the optional `issuerSerial` (issuer `GeneralNames` validated + surfaced raw,
 *   serial as a BigInt + hex) — plus the optional certificate policies.
 *   `parseSmimeCapabilities` decodes the ordered `SMIMECapabilities` list (each a
 *   capability OID + raw parameters). `decodeAttribute` takes a CMS-shaped
 *   `{ type, values }` attribute, enforces the single-`AttributeValue` rule
 *   (RFC 8551 §2.5.2), routes on the attribute OID, and recognize-and-defers an
 *   unknown attribute type with its raw values intact.
 *
 *   Structure is decoded; verification is the consumer's — the parser surfaces
 *   `certHash` + `hashAlgorithm` + `issuerSerial` so a verifier recomputes the
 *   certificate hash (compose `webcrypto`) and matches the issuer/serial against
 *   the actual signing certificate; it never recomputes a hash or trusts a cert.
 *   Whether an attribute is correctly placed in `signedAttrs` (vs `unsignedAttrs`)
 *   is the CMS consumer's knowledge. DER-only, fail-closed.
 *
 * @card
 *   Decode RFC 5035 ESS SigningCertificate / SigningCertificateV2 and RFC 8551
 *   SMIMECapabilities signed-attribute values — cert-hash binding, validated
 *   issuer GeneralNames, ordered capability list, OID-dispatched, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var SmimeError = frameworkError.SmimeError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("smime", SmimeError, oid);
var TAGS = asn1.TAGS;

var ALGID = pkix.algorithmIdentifier(NS);

// Registry constants — never a dotted literal in a format module.
var OID_SHA1 = oid.byName("sha1");
var OID_SHA256 = oid.byName("sha256");
var OID_SIGNING_CERTIFICATE = oid.byName("signingCertificate");
var OID_SIGNING_CERTIFICATE_V2 = oid.byName("signingCertificateV2");
var OID_SMIME_CAPABILITIES = oid.byName("smimeCapabilities");

// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }
// (RFC 5035 App A). A bare universal SEQUENCE of exactly two fields — distinct
// from the RFC 5755 attribute-certificate IssuerSerial (three fields, reached
// IMPLICIT-tagged), so declared per-format. `issuer` composes the shared
// GeneralNames factory (every CHOICE arm validated + surfaced raw, SIZE 1..MAX).
var ISSUER_SERIAL = schema.seq([
  schema.field("issuer", pkix.generalNames(NS, { code: "smime/bad-general-names" })),
  schema.field("serialNumber", schema.integerLeaf()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "smime/bad-issuer-serial", what: "IssuerSerial",
  build: function (m) {
    return {
      issuer: m.fields.issuer.value.result,
      serialNumber: m.fields.serialNumber.value,
      serialNumberHex: m.fields.serialNumber.node.content.toString("hex"),
    };
  },
});

// PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId,
//   policyQualifiers SEQUENCE OF PolicyQualifierInfo OPTIONAL } (RFC 5280 §4.2.1.4).
// Decode the policy OID (+ registry name); surface policyQualifiers raw.
var POLICY_INFORMATION = schema.seq([
  schema.field("policyIdentifier", schema.oidLeaf()),
  schema.optional("policyQualifiers", schema.any(), { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "smime/bad-policy-information", what: "PolicyInformation",
  build: function (m, ctx) {
    var qualifiers = null;
    if (m.fields.policyQualifiers.present) {
      // The qualifier body stays raw (per the ESS scope), but the RFC 5280
      // §4.2.1.4 structure is validated fail-closed by the shared assertion — the
      // same PolicyInformation shape the certificatePolicies decoder enforces.
      var q = m.fields.policyQualifiers.node;
      pkix.assertPolicyQualifiers(q, function (msg, cause) { throw ctx.E("smime/bad-policy-information", msg, cause); });
      qualifiers = q.bytes;
    }
    return {
      policyIdentifier: m.fields.policyIdentifier.value,
      name: ctx.oid.name(m.fields.policyIdentifier.value) || null,
      policyQualifiers: qualifiers,
    };
  },
});
// policies SEQUENCE OF PolicyInformation OPTIONAL — order-preserving; the ASN.1
// module carries no SIZE bound, so an explicitly present but empty list is legal.
var POLICIES = schema.seqOf(POLICY_INFORMATION, {
  assert: "sequence", min: 0, code: "smime/bad-policies", what: "policies",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// ESSCertID ::= SEQUENCE { certHash Hash, issuerSerial IssuerSerial OPTIONAL }
// (RFC 5035 §5.4.2). Hash ::= OCTET STRING — for v1 it is the SHA-1 hash of the
// whole certificate with NO algorithm field, so the hash algorithm is SYNTHESIZED
// as the implied SHA-1 to make v1 shape-compatible with v2 for a verifier.
var ESS_CERT_ID = schema.seq([
  schema.field("certHash", schema.octetString()),
  schema.optional("issuerSerial", ISSUER_SERIAL, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "smime/bad-ess-cert-id", what: "ESSCertID",
  build: function (m) {
    return {
      certHash: m.fields.certHash.value,
      hashAlgorithm: { oid: OID_SHA1, name: "sha1", parameters: null, implied: true },
      issuerSerial: m.fields.issuerSerial.present ? m.fields.issuerSerial.value.result : null,
    };
  },
});

// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT
//   {algorithm id-sha256}, certHash Hash, issuerSerial IssuerSerial OPTIONAL }
// (RFC 5035 §5.4.1 / §4). The mandatory certHash OCTET STRING pivots between the
// two optional SEQUENCEs, so a leading SEQUENCE is hashAlgorithm and a leading
// OCTET STRING means hashAlgorithm defaulted.
var ESS_CERT_ID_V2 = schema.seq([
  schema.optional("hashAlgorithm", ALGID, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.field("certHash", schema.octetString()),
  schema.optional("issuerSerial", ISSUER_SERIAL, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "smime/bad-ess-cert-id-v2", what: "ESSCertIDv2",
  build: function (m, ctx) {
    var hashAlgorithm;
    if (m.fields.hashAlgorithm.present) {
      var alg = m.fields.hashAlgorithm.value.result;
      // X.690 §11.5: a DEFAULT value MUST be omitted in DER. The default is
      // {algorithm id-sha256, parameters ABSENT}; an explicit encoding byte-equal
      // to it is a non-canonical DEFAULT and is rejected fail-closed (the
      // structured-value analogue of the primitive-DEFAULT rejection the toolkit
      // already enforces). A present hashAlgorithm carrying a redundant NULL
      // parameters is NOT byte-equal to the params-absent default and decodes.
      if (alg.oid === OID_SHA256 && alg.parameters === null) {
        throw ctx.E("smime/non-canonical-default",
          "ESSCertIDv2 hashAlgorithm equal to the DEFAULT {algorithm id-sha256} MUST be omitted (X.690 §11.5)");
      }
      hashAlgorithm = { oid: alg.oid, name: alg.name, parameters: alg.parameters, defaulted: false };
    } else {
      hashAlgorithm = { oid: OID_SHA256, name: "sha256", parameters: null, defaulted: true };
    }
    return {
      certHash: m.fields.certHash.value,
      hashAlgorithm: hashAlgorithm,
      issuerSerial: m.fields.issuerSerial.present ? m.fields.issuerSerial.value.result : null,
    };
  },
});

// SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID,
//   policies SEQUENCE OF PolicyInformation OPTIONAL } (RFC 5035 §5.4.2). certs is
// order-preserving — RFC 5035 §3 makes the FIRST element the signing certificate
// — and non-empty (an empty certs cannot name a signing cert).
function signingCertificateSchema(essCertId, code, what) {
  return schema.seq([
    schema.field("certs", schema.seqOf(essCertId, { assert: "sequence", min: 1, code: "smime/bad-certs", what: "certs" })),
    schema.optional("policies", POLICIES, { whenUniversal: [TAGS.SEQUENCE] }),
  ], {
    assert: "sequence", code: code, what: what,
    build: function (m) {
      return {
        certs: m.fields.certs.value.items.map(function (it) { return it.value.result; }),
        policies: m.fields.policies.present ? m.fields.policies.value.result : null,
      };
    },
  });
}
var SIGNING_CERTIFICATE = signingCertificateSchema(ESS_CERT_ID, "smime/bad-signing-certificate", "SigningCertificate");
var SIGNING_CERTIFICATE_V2 = signingCertificateSchema(ESS_CERT_ID_V2, "smime/bad-signing-certificate-v2", "SigningCertificateV2");

// SMIMECapability ::= SEQUENCE { capabilityID OBJECT IDENTIFIER,
//   parameters ANY DEFINED BY capabilityID OPTIONAL } (RFC 8551 §2.5.2). Distinct
// domain from AlgorithmIdentifier though isomorphic — surfaced as capabilityID +
// raw parameters (the ANY-DEFINED-BY interpretation is a negotiation concern).
var SMIME_CAPABILITY = schema.seq([
  schema.field("capabilityID", schema.oidLeaf()),
  schema.optional("parameters", schema.any(), { whenAny: true }),
], {
  assert: "sequence", code: "smime/bad-capability", what: "SMIMECapability",
  build: function (m, ctx) {
    return {
      capabilityID: m.fields.capabilityID.value,
      name: ctx.oid.name(m.fields.capabilityID.value) || null,
      parameters: m.fields.parameters.present ? m.fields.parameters.node.bytes : null,
    };
  },
});
// SMIMECapabilities ::= SEQUENCE OF SMIMECapability — ordered by preference
// (RFC 8551 §2.5.2), never sorted; an empty list is legal.
var SMIME_CAPABILITIES = schema.seqOf(SMIME_CAPABILITY, {
  assert: "sequence", min: 0, code: "smime/bad-capabilities", what: "SMIMECapabilities",
  build: function (m) { return { capabilities: m.items.map(function (it) { return it.value.result; }) }; },
});

/**
 * @primitive  pki.schema.smime.parseSigningCertificate
 * @signature  pki.schema.smime.parseSigningCertificate(der) -> { certs, policies }
 * @since      0.1.22
 * @status     experimental
 * @spec       RFC 5035, RFC 2634
 * @related    pki.schema.smime.parseSigningCertificateV2, pki.schema.smime.decodeAttribute
 *
 * Decode an ESS v1 `SigningCertificate` attribute value (RFC 5035 §5.4.2) — the
 * raw `AttributeValue` a CMS consumer plucks off `SignerInfo.signedAttrs`. Returns
 * `{ certs, policies }`: each `certs` entry is `{ certHash, hashAlgorithm,
 * issuerSerial }` in wire order (the first is the signing certificate), where
 * `hashAlgorithm` is the implied SHA-1 (v1 carries no algorithm field) and
 * `issuerSerial` (or `null`) surfaces the issuer `GeneralNames` + serial. Throws a
 * typed `smime/*` (or leaf `asn1/*`) error on malformed input.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var essCertId = b.sequence([b.octetString(Buffer.alloc(20, 1))]);   // SHA-1 hash, no issuerSerial
 *   var av = b.sequence([b.sequence([essCertId])]);                     // SigningCertificate { certs }
 *   var sc = pki.schema.smime.parseSigningCertificate(av);
 *   sc.certs[0].hashAlgorithm.name;    // "sha1" (implied)
 */
var parseSigningCertificate = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: SmimeError, prefix: "smime", what: "SigningCertificate", topSchema: SIGNING_CERTIFICATE, ns: NS });

/**
 * @primitive  pki.schema.smime.parseSigningCertificateV2
 * @signature  pki.schema.smime.parseSigningCertificateV2(der) -> { certs, policies }
 * @since      0.1.22
 * @status     experimental
 * @spec       RFC 5035, RFC 5816
 * @related    pki.schema.smime.parseSigningCertificate, pki.schema.smime.decodeAttribute
 *
 * Decode an ESS v2 `SigningCertificateV2` attribute value (RFC 5035 §5.4.1).
 * Identical shape to v1 but each `certs` entry carries a real `hashAlgorithm`:
 * decoded when present, or the RFC 5035 §4 default `id-sha256` (with
 * `defaulted: true`) when omitted. An explicit `hashAlgorithm` byte-equal to that
 * default is a non-canonical DER encoding and is rejected `smime/non-canonical-default`
 * (X.690 §11.5). Throws a typed `smime/*` error on malformed input.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var essCertId = b.sequence([b.octetString(Buffer.alloc(32, 2))]);   // hashAlgorithm defaulted
 *   var av = b.sequence([b.sequence([essCertId])]);
 *   var sc = pki.schema.smime.parseSigningCertificateV2(av);
 *   sc.certs[0].hashAlgorithm.defaulted;   // true (SHA-256 default)
 */
var parseSigningCertificateV2 = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: SmimeError, prefix: "smime", what: "SigningCertificateV2", topSchema: SIGNING_CERTIFICATE_V2, ns: NS });

/**
 * @primitive  pki.schema.smime.parseSmimeCapabilities
 * @signature  pki.schema.smime.parseSmimeCapabilities(der) -> { capabilities }
 * @since      0.1.22
 * @status     experimental
 * @spec       RFC 8551
 * @related    pki.schema.smime.decodeAttribute
 *
 * Decode an `SMIMECapabilities` attribute value (RFC 8551 §2.5.2) into
 * `{ capabilities }` — an ORDERED list (preference order, never sorted), each
 * `{ capabilityID, name, parameters }` with `parameters` the raw
 * `ANY DEFINED BY capabilityID` bytes (or `null`). Throws a typed `smime/*` error
 * on malformed input.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var cap = b.sequence([b.oid(pki.oid.byName("aes256-CBC"))]);
 *   var caps = pki.schema.smime.parseSmimeCapabilities(b.sequence([cap]));
 *   caps.capabilities[0].name;    // "aes256-CBC"
 */
var parseSmimeCapabilities = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: SmimeError, prefix: "smime", what: "SMIMECapabilities", topSchema: SMIME_CAPABILITIES, ns: NS });

/**
 * @primitive  pki.schema.smime.decodeAttribute
 * @signature  pki.schema.smime.decodeAttribute(attr) -> { kind, ... }
 * @since      0.1.22
 * @status     experimental
 * @spec       RFC 8551, RFC 5035
 * @related    pki.schema.smime.parseSigningCertificate, pki.schema.cms.parse
 *
 * OID-dispatch convenience over the three value decoders for a CMS-shaped
 * `{ type, values }` attribute (the shape `cms.parse` surfaces on
 * `signerInfos[i].signedAttrs`). Enforces the single-`AttributeValue` rule
 * (RFC 8551 §2.5.2 / §2.5) — a `values` length other than 1 is rejected
 * `smime/multi-valued-attribute` — then routes on `attr.type`:
 * `signingCertificate` / `signingCertificateV2` / `smimeCapabilities` decode to
 * `{ kind, ...result }`; any other type is recognize-and-deferred
 * `smime/unsupported-attribute` (its `type`, registry `name`, and raw `values`
 * carried on the error so a caller keeps the bytes).
 *
 * @example
 *   var b = pki.asn1.build;
 *   var essCertId = b.sequence([b.octetString(Buffer.alloc(32, 2))]);   // ESSCertIDv2, hashAlgorithm defaulted
 *   var av = b.sequence([b.sequence([essCertId])]);                     // SigningCertificateV2 { certs: [ ESSCertIDv2 ] }
 *   var got = pki.schema.smime.decodeAttribute({ type: pki.oid.byName("signingCertificateV2"), values: [av] });
 *   got.kind;    // "signingCertificateV2"
 */
function decodeAttribute(attr) {
  if (!attr || typeof attr !== "object" || typeof attr.type !== "string" || !Array.isArray(attr.values)) {
    throw new SmimeError("smime/bad-input", "decodeAttribute expects a CMS attribute { type, values }");
  }
  // Route on the attribute OID FIRST. The single-AttributeValue MUST (RFC 8551
  // §2.5.2) is specific to the ESS / SMIMECapabilities attributes, so it is
  // enforced only inside the known-type branch; an unknown / custom attribute
  // recognize-and-defers with its raw values intact regardless of value count
  // (its own cardinality rules are not this decoder's to enforce).
  if (attr.type === OID_SIGNING_CERTIFICATE || attr.type === OID_SIGNING_CERTIFICATE_V2 || attr.type === OID_SMIME_CAPABILITIES) {
    if (attr.values.length !== 1) {
      throw new SmimeError("smime/multi-valued-attribute",
        "an ESS / SMIMECapabilities attribute MUST carry exactly one AttributeValue, got " + attr.values.length + " (RFC 8551 §2.5.2)");
    }
    var value = attr.values[0];
    if (attr.type === OID_SIGNING_CERTIFICATE) { var v1 = parseSigningCertificate(value); return { kind: "signingCertificate", certs: v1.certs, policies: v1.policies }; }
    if (attr.type === OID_SIGNING_CERTIFICATE_V2) { var v2 = parseSigningCertificateV2(value); return { kind: "signingCertificateV2", certs: v2.certs, policies: v2.policies }; }
    return { kind: "smimeCapabilities", capabilities: parseSmimeCapabilities(value).capabilities };
  }
  var e = new SmimeError("smime/unsupported-attribute", "unsupported S/MIME attribute type " + attr.type + (oid.name(attr.type) ? " (" + oid.name(attr.type) + ")" : ""));
  e.type = attr.type;
  e.name = oid.name(attr.type) || null;
  e.values = attr.values;
  throw e;
}

module.exports = {
  parseSigningCertificate: parseSigningCertificate,
  parseSigningCertificateV2: parseSigningCertificateV2,
  parseSmimeCapabilities: parseSmimeCapabilities,
  decodeAttribute: decodeAttribute,
};
