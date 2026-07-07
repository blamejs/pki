// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.crmf
 * @nav        Schema
 * @title      CRMF
 * @order      180
 * @slug       crmf
 *
 * @intro
 *   Certificate Request Message Format handling per RFC 4211. `parse` decodes a
 *   `CertReqMessages` — the request body CMP and EST enrollment carry — into an
 *   array of messages, each with its `CertRequest` (certReqId, a `CertTemplate`
 *   of the requested certificate fields, and any registration controls), an
 *   optional proof-of-possession, and optional registration info.
 *
 *   RFC 4211 Appendix B is an IMPLICIT TAGS module, so the whole `CertTemplate`
 *   body is one ascending run of IMPLICIT context tags `[0]`..`[9]`, every field
 *   OPTIONAL. Two fields break IMPLICIT because their base type is a CHOICE and
 *   X.680 forces EXPLICIT: `issuer [3]` / `subject [5]` are `Name`, dual-accepted
 *   here (the standards-compliant EXPLICIT encoding and the dominant IMPLICIT one
 *   real tooling emits); and the `OptionalValidity` times are EXPLICIT. version,
 *   when supplied, MUST be 2 (RFC 4211 §5); certReqId is an unbounded signed
 *   INTEGER (the RFC 9483 `-1` sentinel is legal). The `CertRequest` byte range
 *   the proof-of-possession signature covers, and each `poposkInput`, are surfaced
 *   RAW for a downstream verifier; registration controls / info values and the
 *   keyEncipherment / keyAgreement POP arms are surfaced RAW rather than recursed.
 *   DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM RFC 4211 CertReqMessages into requested-certificate templates,
 *   proof-of-possession, and registration controls — dual-accepted names, raw
 *   verifier inputs, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CrmfError = frameworkError.CrmfError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("crmf", CrmfError, oid);

var TAGS = asn1.TAGS;

// ---- dual-accept Name (issuer [3] / subject [5]) ---------------------
// RFC 4211 Appendix B is IMPLICIT TAGS, but Name is a CHOICE so X.680 §31.2.7
// forces EXPLICIT tagging — the standards-compliant wire is a context [tag]
// EXPLICIT wrapper around a universal RDNSequence. The dominant tooling
// (pyasn1-modules, BouncyCastle) instead encodes IMPLICIT (the [tag] REPLACES the
// RDNSequence 0x30, so the children ARE the RDN SETs). Both occur in real CMP /
// EST, so accept either, disambiguated by the first inner element's tag: a
// universal SET leads the IMPLICIT form; a single universal SEQUENCE is the
// EXPLICIT wrapper. Anything else fails closed.
function crmfName(tag) {
  var NAME = pkix.name(NS);                          // EXPLICIT arm walks a universal RDNSequence
  var INAME = pkix.name(NS, { implicitTag: tag });   // IMPLICIT arm: [tag] children ARE the RDN SETs
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "context" || n.tagNumber !== tag || !n.children) {
      throw ctx.E("crmf/bad-name", "issuer/subject [" + tag + "] must be a Name (RFC 4211 §5)");
    }
    if (n.children.length === 0) return schema.walk(INAME, n, ctx).result; // IMPLICIT empty RDNSequence
    var c0 = n.children[0];
    if (c0.tagClass === "universal" && c0.tagNumber === TAGS.SET) {
      return schema.walk(INAME, n, ctx).result;                            // IMPLICIT: children ARE RDN SETs
    }
    if (n.children.length === 1 && c0.tagClass === "universal" && c0.tagNumber === TAGS.SEQUENCE) {
      return schema.walk(NAME, c0, ctx).result;                            // EXPLICIT: [tag] wraps RDNSequence
    }
    throw ctx.E("crmf/bad-name", "issuer/subject [" + tag + "] Name must be an IMPLICIT RDNSequence (SET-led) or an EXPLICIT-wrapped RDNSequence");
  });
}

// ---- OptionalValidity (§5) -------------------------------------------
// validity [4] IMPLICIT SEQUENCE { notBefore [0] Time OPTIONAL, notAfter [1] Time
// OPTIONAL }. Time is a CHOICE of UTCTime / GeneralizedTime, so [0]/[1] are
// EXPLICIT (an IMPLICIT tag would erase the UTCTime-vs-GeneralizedTime
// discriminator). RFC 4211 §5 requires at least one of the two to be present.
var OPTIONAL_VALIDITY = schema.seq([
  schema.trailing([
    { tag: 0, name: "notBefore", schema: schema.time(NS), explicit: true, emptyCode: "crmf/bad-validity" },
    { tag: 1, name: "notAfter", schema: schema.time(NS), explicit: true, emptyCode: "crmf/bad-validity" },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "crmf/bad-validity", orderCode: "crmf/bad-validity" }),
], {
  assert: "implicit", implicitTag: 4, code: "crmf/bad-validity", what: "OptionalValidity",
  build: function (m, ctx) {
    var f = m.fields;
    if (!f.notBefore.present && !f.notAfter.present) {
      throw ctx.E("crmf/bad-validity", "OptionalValidity must contain notBefore or notAfter (RFC 4211 §5)");
    }
    return { notBefore: f.notBefore.present ? f.notBefore.value : null, notAfter: f.notAfter.present ? f.notAfter.value : null };
  },
});

// ---- ProofOfPossession (§4) ------------------------------------------
// raVerified [0] NULL — the RA has already verified POP out of band.
var POPO_RAVERIFIED = schema.decode(function (n, ctx) {
  try { asn1.read.nullImplicit(n, 0); }
  catch (e) { throw ctx.E("crmf/bad-popo", "raVerified [0] must be an IMPLICIT NULL", e); }
  return { type: "raVerified" };
});

// POPOSigningKey ::= SEQUENCE { poposkInput [0] POPOSigningKeyInput OPTIONAL,
// algorithmIdentifier AlgorithmIdentifier, signature BIT STRING } — IMPLICIT [1].
// poposkInput is surfaced RAW (deferred): the signed region and the authInfo /
// PKMACValue semantics are POP-verifier concerns (§4.1).
var POPO_SIGNING_KEY = schema.seq([
  schema.optional("poposkInput", schema.any(), { tag: 0 }),
  schema.field("algorithmIdentifier", pkix.algorithmIdentifier(NS)),
  schema.field("signature", schema.bitString()),
], {
  assert: "implicit", implicitTag: 1, code: "crmf/bad-popo", what: "POPOSigningKey",
  build: function (m) {
    return {
      type: "signature",
      poposkInput: m.fields.poposkInput.present ? m.fields.poposkInput.node.bytes : null,
      algorithmIdentifier: m.fields.algorithmIdentifier.value.result,
      signature: { unusedBits: m.fields.signature.value.unusedBits, bytes: m.fields.signature.value.bytes },
    };
  },
});

// keyEncipherment [2] / keyAgreement [3] POPOPrivKey — a 5-arm CHOICE (incl.
// encryptedKey [4] EnvelopedData). Surfaced RAW; structural decode is deferred to
// the CMP/EST verify layer (§4).
function popoPrivKey(type) {
  return schema.decode(function (n) { return { type: type, bytes: n.bytes }; });
}

// ProofOfPossession ::= CHOICE { raVerified [0] NULL, signature [1] POPOSigningKey,
// keyEncipherment [2] POPOPrivKey, keyAgreement [3] POPOPrivKey }. Each arm yields
// the final object so the CertReqMsg build reads one uniform popo shape.
var PROOF_OF_POSSESSION = schema.choice([
  { when: { tagClass: "context", tagNumber: 0 }, schema: POPO_RAVERIFIED },
  { when: { tagClass: "context", tagNumber: 1 }, schema: schema.decode(function (n, ctx) { return schema.walk(POPO_SIGNING_KEY, n, ctx).result; }) },
  { when: { tagClass: "context", tagNumber: 2 }, schema: popoPrivKey("keyEncipherment") },
  { when: { tagClass: "context", tagNumber: 3 }, schema: popoPrivKey("keyAgreement") },
], { code: "crmf/bad-popo" });

// ---- Controls / regInfo (§5, §6, §7) ---------------------------------
// AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY DEFINED BY
// type }. The list is decoded; each value stays RAW (the per-OID value semantics
// are deferred). Shared shape for both controls and regInfo.
var CONTROL = schema.seq([
  schema.field("type", schema.oidLeaf()),
  schema.field("value", schema.any()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "crmf/bad-control", what: "AttributeTypeAndValue",
  build: function (m, ctx) {
    var t = m.fields.type.value;
    return { type: t, name: ctx.oid.name(t) || null, value: m.fields.value.node.bytes };
  },
});
function mapControls(m) { return m.items.map(function (it) { return it.value.result; }); }
// Controls ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue (§5).
var CONTROLS = schema.seqOf(CONTROL, { assert: "sequence", min: 1, code: "crmf/bad-controls", what: "Controls", build: mapControls });
// regInfo ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue (§7).
var REG_INFO = schema.seqOf(CONTROL, { assert: "sequence", min: 1, code: "crmf/bad-reg-info", what: "regInfo", build: mapControls });

// ---- CertTemplate (§5) — the IMPLICIT-TAGS core ----------------------
// CertTemplate ::= SEQUENCE { version [0], serialNumber [1], signingAlg [2],
// issuer [3] Name, validity [4] OptionalValidity, subject [5] Name, publicKey [6]
// SubjectPublicKeyInfo, issuerUID [7], subjectUID [8], extensions [9] } — every
// field IMPLICIT and OPTIONAL, so the whole body is one ascending [0..9] trailing
// run. issuer/subject Name and the [4] validity times are the CHOICE exceptions.
var CERT_TEMPLATE = schema.seq([
  schema.trailing([
    { tag: 0, name: "version", schema: schema.implicitInteger(0) },
    { tag: 1, name: "serialNumber", schema: schema.implicitInteger(1) },
    { tag: 2, name: "signingAlg", schema: pkix.algorithmIdentifier(NS, { implicitTag: 2 }) },
    { tag: 3, name: "issuer", schema: crmfName(3) },
    { tag: 4, name: "validity", schema: OPTIONAL_VALIDITY },
    { tag: 5, name: "subject", schema: crmfName(5) },
    { tag: 6, name: "publicKey", schema: pkix.spki(NS, { implicitTag: 6 }) },
    { tag: 7, name: "issuerUID", schema: schema.implicitBitString(7) },
    { tag: 8, name: "subjectUID", schema: schema.implicitBitString(8) },
    { tag: 9, name: "extensions", schema: pkix.extensions(NS, { implicitTag: 9 }) },
  ], { minTag: 0, maxTag: 9, unexpectedCode: "crmf/bad-cert-template", orderCode: "crmf/bad-cert-template" }),
], {
  assert: "sequence", code: "crmf/bad-cert-template", what: "CertTemplate",
  build: function (m, ctx) {
    var f = m.fields;
    // RFC 4211 §5 — serialNumber, signingAlg, issuerUID, and subjectUID MUST be
    // omitted from a CertTemplate: serialNumber and signingAlg are assigned by the
    // CA, and the UID pair is deprecated. A requester must not dictate a
    // CA-assigned value (a requester-chosen serialNumber is a real hazard), so a
    // template that sets any of them is rejected fail-closed, not surfaced as
    // acceptable. They stay in the field map (parsed, then rejected) so the
    // diagnostic names the offending field rather than a bare tag number.
    var caAssigned = ["serialNumber", "signingAlg", "issuerUID", "subjectUID"];
    for (var i = 0; i < caAssigned.length; i++) {
      if (f[caAssigned[i]].present) {
        throw ctx.E("crmf/bad-cert-template", "CertTemplate " + caAssigned[i] + " MUST be omitted — it is CA-assigned or deprecated (RFC 4211 §5)");
      }
    }
    // version MUST be 2 (v3) when supplied; SHOULD be omitted (RFC 4211 §5).
    if (f.version.present && f.version.value !== 2n) {
      throw ctx.E("crmf/bad-version", "CertTemplate version MUST be 2 (v3) if supplied (RFC 4211 §5)");
    }
    return {
      version:    f.version.present ? f.version.value : null,
      issuer:     f.issuer.present ? f.issuer.value : null,
      validity:   f.validity.present ? f.validity.value.result : null,
      subject:    f.subject.present ? f.subject.value : null,
      publicKey:  f.publicKey.present ? f.publicKey.value.result : null,
      extensions: f.extensions.present ? f.extensions.value.result : null,
    };
  },
});

// ---- CertRequest / CertReqMsg / CertReqMessages (§3, §5) --------------
// CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate CertTemplate,
// controls Controls OPTIONAL }. certReqId is a SIGNED INTEGER with no value
// constraint — a negative value (the RFC 9483 -1 sentinel) is legal.
var CERT_REQUEST = schema.seq([
  schema.field("certReqId", schema.integerLeaf()),
  schema.field("certTemplate", CERT_TEMPLATE),
  schema.optional("controls", CONTROLS, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "crmf/bad-cert-request", what: "CertRequest",
  build: function (m) {
    return {
      certReqId:     m.fields.certReqId.value,
      certReqIdHex:  m.fields.certReqId.node.content.toString("hex"),
      certTemplate:  m.fields.certTemplate.value.result,
      controls:      m.fields.controls.present ? m.fields.controls.value.result : null,
      certReqBytes:  m.node.bytes,   // the exact CertRequest TLV the POP signature covers (§4.1)
    };
  },
});

// CertReqMsg ::= SEQUENCE { certReq CertRequest, popo ProofOfPossession OPTIONAL,
// regInfo SEQUENCE OF AttributeTypeAndValue OPTIONAL }. popo is a CHOICE of context
// [0]..[3]; regInfo is a bare universal SEQUENCE, so the two OPTIONAL positions are
// disambiguated by tag class.
var CERT_REQ_MSG = schema.seq([
  schema.field("certReq", CERT_REQUEST),
  schema.optional("popo", PROOF_OF_POSSESSION, { tags: [0, 1, 2, 3] }),
  schema.optional("regInfo", REG_INFO, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "crmf/bad-cert-req-msg", what: "CertReqMsg",
  build: function (m, ctx) {
    var certReq = m.fields.certReq.value.result;
    var popo = m.fields.popo.present ? m.fields.popo.value : null;
    // RFC 4211 §4.1 — for a signature POP, poposkInput's presence is fixed by the
    // CertTemplate: it MUST be omitted when the template carries BOTH subject and
    // publicKey (the signature is then over the DER of the CertRequest), and MUST
    // be present otherwise. Enforcing this at parse stops a verifier being led to
    // hash poposkInput bytes bound to one identity/key while the request asks for
    // a certificate over a different template.
    if (popo && popo.type === "signature") {
      var complete = certReq.certTemplate.subject !== null && certReq.certTemplate.publicKey !== null;
      if (complete && popo.poposkInput !== null) {
        throw ctx.E("crmf/bad-popo", "poposkInput MUST be omitted when the CertTemplate contains both subject and publicKey (RFC 4211 §4.1)");
      }
      if (!complete && popo.poposkInput === null) {
        throw ctx.E("crmf/bad-popo", "poposkInput MUST be present when the CertTemplate lacks subject or publicKey (RFC 4211 §4.1)");
      }
    }
    return {
      certReq: certReq,
      popo:    popo,
      regInfo: m.fields.regInfo.present ? m.fields.regInfo.value.result : null,
    };
  },
});

// CertReqMessages ::= SEQUENCE SIZE(1..MAX) OF CertReqMsg (§3) — an empty sequence
// is malformed.
var CERT_REQ_MESSAGES = schema.seqOf(CERT_REQ_MSG, {
  assert: "sequence", min: 1, code: "crmf/bad-cert-req-messages", what: "CertReqMessages",
  build: function (m) { return { messages: m.items.map(function (it) { return it.value.result; }) }; },
});

// ---- parse -----------------------------------------------------------

/**
 * @primitive  pki.schema.crmf.parse
 * @signature  pki.schema.crmf.parse(input) -> certReqMessages
 * @since      0.1.17
 * @status     experimental
 * @spec       RFC 4211
 * @related    pki.schema.parse, pki.schema.csr.parse
 *
 * Parse a DER `Buffer` or a PEM string/Buffer into a structured `CertReqMessages`:
 * `{ messages: [ { certReq, popo, regInfo } ] }`. Each `certReq` is
 * `{ certReqId, certReqIdHex, certTemplate, controls, certReqBytes }`, and
 * `certTemplate` carries the requestable certificate fields (`version`, `issuer`,
 * `validity`, `subject`, `publicKey`, `extensions` — each `null` when absent). The
 * CA-assigned / deprecated fields RFC 4211 §5 requires a request to omit
 * (`serialNumber`, `signingAlg`, `issuerUID`, `subjectUID`) are rejected, not
 * surfaced. `popo` is
 * `null`, `{ type: "raVerified" }`, `{ type: "signature", poposkInput,
 * algorithmIdentifier, signature }`, or `{ type: "keyEncipherment" |
 * "keyAgreement", bytes }`. `certReqBytes` is the exact `CertRequest` byte range a
 * proof-of-possession verifier hashes.
 *
 * Throws `CrmfError` when the bytes are not a well-formed `CertReqMessages`, and
 * `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var m = pki.schema.crmf.parse(der);
 *   m.messages[0].certReq.certTemplate.subject.dn;   // "CN=req.example"
 */
var parse = pkix.makeParser({
  pemLabel: null, PemError: PemError, ErrorClass: CrmfError, prefix: "crmf",
  what: "certificate request message", topSchema: CERT_REQ_MESSAGES, ns: NS,
});

/**
 * @primitive  pki.schema.crmf.pemDecode
 * @signature  pki.schema.crmf.pemDecode(text, label?) -> Buffer
 * @since      0.1.17
 * @status     experimental
 * @spec       RFC 7468, RFC 4211
 * @related    pki.schema.crmf.parse
 *
 * Extract the DER bytes from a PEM block (RFC 4211 registers no RFC 7468 label, so
 * the first block is taken unless `label` is given — CRMF rides inside CMP / EST as
 * DER in practice). Throws `PemError` on a missing envelope or a non-base64 body.
 *
 * @example
 *   var der = pki.schema.crmf.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || null, PemError); }

// matches(root): a CertReqMessages is a universal SEQUENCE whose first CertReqMsg
// is a SEQUENCE whose first CertRequest is a SEQUENCE leading with a universal
// INTEGER (certReqId) then a universal SEQUENCE (certTemplate). This 3-level probe
// is disjoint from every registered root PROVIDED crmf is checked before
// ocsp-request: an OCSPRequest's tbsRequest never leads with the INTEGER-then-
// SEQUENCE pair (its children[0] is a context [0] version or a requestList).
function matches(root) {
  if (!root || root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE || !root.children || root.children.length < 1) return false;
  var msg = root.children[0];
  if (!msg.children || msg.tagClass !== "universal" || msg.tagNumber !== TAGS.SEQUENCE || msg.children.length < 1) return false;
  var certReq = msg.children[0];
  if (!certReq.children || certReq.tagClass !== "universal" || certReq.tagNumber !== TAGS.SEQUENCE || certReq.children.length < 2) return false;
  var id = certReq.children[0], tpl = certReq.children[1];
  return id.tagClass === "universal" && id.tagNumber === TAGS.INTEGER &&
    tpl.tagClass === "universal" && tpl.tagNumber === TAGS.SEQUENCE && !!tpl.children;
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  matches: matches,
};
