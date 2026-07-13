// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.crmf (RFC 4211 CertReqMessages parser).
 * Spec-first conformance vectors: a valid CertReqMessages parses to the
 * documented shape; every malformed CertReqMsg / CertRequest / CertTemplate is
 * rejected fail-closed with a typed crmf/* (or leaf-level asn1/*) error. The
 * module is IMPLICIT TAGS (RFC 4211 Appendix B), so the CertTemplate body is one
 * ascending [0..9] run of IMPLICIT context tags — issuer [3] / subject [5] Name
 * break IMPLICIT (a CHOICE, dual-accepted here) and the OptionalValidity times
 * are EXPLICIT. certReqId is an unbounded signed INTEGER (accepts the RFC 9483
 * -1 sentinel); version [0] MUST be 2 when supplied (RFC 4211 §5).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
// The matches detector is internal dispatch infrastructure (not on the curated
// pki.schema.crmf surface), so reach it via the module directly.
var crmfMod = require("../../lib/schema-crmf");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.crmf.parse(der); }); }
function parse(der) { return pki.schema.crmf.parse(der); }

// ---- OIDs used in fixtures -------------------------------------------
var SHA256_RSA = "1.2.840.113549.1.1.11";   // sha256WithRSAEncryption (signingAlg)
var RSA_ENC = "1.2.840.113549.1.1.1";       // rsaEncryption (SPKI algorithm)
var OLD_CERT_ID = "1.3.6.1.5.5.7.5.1.5";    // id-regCtrl-oldCertID
var UTF8_PAIRS = "1.3.6.1.5.5.7.5.2.1";     // id-regInfo-utf8Pairs
var BASIC_CONSTRAINTS = "2.5.29.19";

// ---- primitive fixture builders --------------------------------------
function algId(o) { return b.sequence([b.oid(o)]); }
// RDNSequence ::= SEQUENCE OF RDN — a bare universal SEQUENCE (the EXPLICIT arm).
function rdnSeq(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
// The RDN SETs alone (the IMPLICIT arm's children — the [tag] replaces the 0x30).
function rdnSets(cn) { return [b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]; }

// implicitInt(tag, n): [tag] IMPLICIT INTEGER — a context-primitive carrying the
// INTEGER content octets (the [tag] replaces the universal 0x02).
function implicitInt(tag, n) { return b.contextPrimitive(tag, pki.asn1.decode(b.integer(n)).content); }
// implicitBits(tag, body, unused): [tag] IMPLICIT BIT STRING (context-primitive).
function implicitBits(tag, body, unused) { return b.contextPrimitive(tag, Buffer.concat([Buffer.from([unused || 0]), body])); }
// implicitName(tag, cn): IMPLICIT Name — [tag] constructed whose children ARE the RDN SETs.
function implicitName(tag, cn) { return b.contextConstructed(tag, Buffer.concat(rdnSets(cn))); }
// explicitName(tag, cn): EXPLICIT Name — [tag] wraps a universal SEQUENCE (RDNSequence).
function explicitName(tag, cn) { return b.explicit(tag, rdnSeq(cn)); }
// implicitAlg(tag, o): [tag] IMPLICIT AlgorithmIdentifier { algorithm }.
function implicitAlg(tag, o) { return b.contextConstructed(tag, b.oid(o)); }
// implicitSpki(tag, algOid, keyBits): [tag] IMPLICIT SubjectPublicKeyInfo { alg, BIT STRING }.
function spkiContent(algOid, keyBits) { return Buffer.concat([algId(algOid), b.bitString(keyBits || Buffer.from([0x04, 0x05, 0x06]), 0)]); }
function implicitSpki(tag, algOid, keyBits) { return b.contextConstructed(tag, spkiContent(algOid, keyBits)); }
// optValidity(nb, na): validity [4] IMPLICIT OptionalValidity { notBefore [0] EXPLICIT
// Time, notAfter [1] EXPLICIT Time } — the [0]/[1] wrap a universal GeneralizedTime.
function optValidity(nb, na) {
  var kids = [];
  if (nb) kids.push(b.explicit(0, b.generalizedTime(new Date(nb))));
  if (na) kids.push(b.explicit(1, b.generalizedTime(new Date(na))));
  return b.contextConstructed(4, Buffer.concat(kids));
}
function extn(oidStr, valueBytes, critical) {
  var children = [b.oid(oidStr)];
  if (critical !== undefined) children.push(b.boolean(critical));
  children.push(b.octetString(valueBytes));
  return b.sequence(children);
}

// certTemplate(o): assemble a CertTemplate (all fields OPTIONAL, ascending tags).
function certTemplate(o) {
  o = o || {};
  if (o.rawKids) return b.sequence(o.rawKids);
  var k = [];
  if (o.versionNode) k.push(o.versionNode);
  else if (o.version !== undefined) k.push(implicitInt(0, o.version));
  if (o.serialNumber !== undefined) k.push(implicitInt(1, o.serialNumber));
  if (o.signingAlg) k.push(implicitAlg(2, o.signingAlg));
  if (o.issuerNode) k.push(o.issuerNode);
  else if (o.issuer) k.push(implicitName(3, o.issuer));
  if (o.validityNode) k.push(o.validityNode);
  else if (o.validity) k.push(optValidity(o.validity.nb, o.validity.na));
  if (o.subjectNode) k.push(o.subjectNode);
  else if (o.subject) k.push(implicitName(5, o.subject));
  if (o.publicKey) k.push(implicitSpki(6, o.publicKey.alg, o.publicKey.keyBits));
  if (o.issuerUID) k.push(implicitBits(7, o.issuerUID, 0));
  if (o.subjectUID) k.push(implicitBits(8, o.subjectUID, 0));
  if (o.extensions) k.push(b.contextConstructed(9, Buffer.concat(o.extensions)));
  return b.sequence(k);
}
function templateDefault() { return certTemplate({ subject: "req.example", publicKey: { alg: RSA_ENC } }); }

// control(typeOid, valueNode): CRMF AttributeTypeAndValue ::= SEQUENCE { type, value }.
function control(typeOid, valueNode) { return b.sequence([b.oid(typeOid), valueNode]); }

// certRequest(o): CertRequest ::= SEQUENCE { certReqId, certTemplate, controls? }.
function certRequest(o) {
  o = o || {};
  if (o.rawKids) return b.sequence(o.rawKids);
  var k = [b.integer(o.id === undefined ? 0 : o.id), o.templateNode || templateDefault()];
  if (o.controls) k.push(b.sequence(o.controls));
  return b.sequence(k);
}

// POP arms.
function popoRaVerified() { return b.contextPrimitive(0, Buffer.alloc(0)); }        // raVerified [0] NULL
function popoSignature(o) {
  o = o || {};
  var kids = [];
  if (o.poposkInput) kids.push(o.poposkInput);                                     // a pre-built poposkInput [0] node
  kids.push(algId(o.alg || SHA256_RSA));
  kids.push(b.bitString(o.sig || Buffer.from([0xaa, 0xbb]), o.sigUnused || 0));
  return b.contextConstructed(1, Buffer.concat(kids));                             // signature [1] POPOSigningKey
}
// poposkInput(o): a valid POPOSigningKeyInput [0] — authInfo (publicKeyMAC PKMACValue)
// + publicKey SPKI. Overridable to build malformed variants.
function poposkInput(o) {
  o = o || {};
  var authInfo = o.authInfo || b.sequence([algId(SHA256_RSA), b.bitString(Buffer.from([0xaa]), 0)]);        // PKMACValue
  var publicKey = o.publicKey || b.sequence([algId(RSA_ENC), b.bitString(Buffer.from([0x04, 0x05, 0x06]), 0)]); // SPKI
  var fields = o.fields || [authInfo, publicKey];
  return b.contextConstructed(0, Buffer.concat(fields));
}
// keyEncipherment [2] POPOPrivKey — EXPLICIT wrapper (POPOPrivKey is a CHOICE)
// around one inner alternative; default thisMessage [0] BIT STRING.
function popoKeyEnc(inner) { return b.contextConstructed(2, inner || b.contextPrimitive(0, Buffer.from([0x00, 0xab]))); }
// The fields of a minimal valid v0 EnvelopedData (version, recipientInfos {ktri v0},
// encryptedContentInfo) — the content of an IMPLICIT encryptedKey [4]. The content
// type defaults to id-ct-encKeyWithID (RFC 4211 §4.2); override to test the reject.
function envDataFields(ct, detached, emptyCt) {
  var rid = b.sequence([rdnSeq("CA"), b.integer(1)]);
  var ktri = b.sequence([b.integer(0), rid, algId(RSA_ENC), b.octetString(Buffer.from([0xde, 0xad]))]);
  var eciFields = [b.oid(ct || "1.2.840.113549.1.9.16.1.21"), algId("2.16.840.1.101.3.4.1.2")];
  if (!detached) eciFields.push(b.contextPrimitive(0, emptyCt ? Buffer.alloc(0) : Buffer.from([0xde, 0xad, 0xbe, 0xef])));  // encryptedContent [0]
  return Buffer.concat([b.integer(0), b.set([ktri]), b.sequence(eciFields)]);
}

// certReqMsg(o): CertReqMsg ::= SEQUENCE { certReq, popo?, regInfo? }.
function certReqMsg(o) {
  o = o || {};
  if (o.rawKids) return b.sequence(o.rawKids);
  var k = [o.certReqNode || certRequest(o.certReq || {})];
  if (o.popo) k.push(o.popo);
  if (o.regInfo) k.push(b.sequence(o.regInfo));
  return b.sequence(k);
}
// certReqMessages(list): CertReqMessages ::= SEQUENCE SIZE(1..MAX) OF CertReqMsg.
function certReqMessages(list) { return b.sequence(list); }
function one(o) { return certReqMessages([certReqMsg(o || {})]); }

// ---- ACCEPT ----------------------------------------------------------
function testAcceptMinimal() {
  var der = one({});
  var m = parse(der);
  check("minimal: one message", m.messages.length === 1);
  var msg = m.messages[0];
  check("minimal: certReqId 0n", msg.certReq.certReqId === 0n);
  check("minimal: certReqIdHex", msg.certReq.certReqIdHex === "00");
  check("minimal: subject dn", msg.certReq.certTemplate.subject.dn === "CN=req.example");
  check("minimal: publicKey algorithm", msg.certReq.certTemplate.publicKey.algorithm.oid === RSA_ENC);
  check("minimal: publicKey raw bits", Buffer.isBuffer(msg.certReq.certTemplate.publicKey.publicKey.bytes));
  // publicKey [6] is IMPLICIT on the wire, but .bytes is the importable SPKI
  // SEQUENCE DER (0x30), not the [6] TLV — matching the x509/csr contract.
  (function () { var pkb = msg.certReq.certTemplate.publicKey.bytes; check("minimal: publicKey.bytes is importable SPKI SEQUENCE", pkb[0] === 0x30 && pki.asn1.decode(pkb).tagNumber === 16 && pki.asn1.decode(pkb).children.length === 2); })();
  check("minimal: version absent -> null", msg.certReq.certTemplate.version === null);
  check("minimal: popo null", msg.popo === null);
  check("minimal: regInfo null", msg.regInfo === null);
  check("minimal: controls null", msg.certReq.controls === null);
  // RAW EXACTNESS: certReqBytes equals the CertRequest TLV on the wire.
  var cr = certRequest({});
  var m2 = parse(certReqMessages([certReqMsg({ certReqNode: cr })]));
  check("minimal: certReqBytes equals the CertRequest TLV", m2.messages[0].certReq.certReqBytes.equals(cr));
}

function testAcceptFullTemplate() {
  // Every field a conforming request MAY set (RFC 4211 §5): version 2, issuer,
  // validity, subject, publicKey, and extensions (one critical, one with critical
  // omitted — the DEFAULT FALSE path).
  var tpl = certTemplate({
    version: 2, issuer: "Issuing CA",
    validity: { nb: "2026-01-01T00:00:00Z", na: "2027-01-01T00:00:00Z" },
    subject: "end.entity", publicKey: { alg: RSA_ENC },
    extensions: [extn(BASIC_CONSTRAINTS, b.sequence([b.boolean(true)]), true), extn("2.5.29.15", b.bitString(Buffer.from([0x05, 0xa0]), 5))],
  });
  var t = parse(one({ certReq: { templateNode: tpl } })).messages[0].certReq.certTemplate;
  check("full: version 2n", t.version === 2n);
  check("full: issuer dn", t.issuer.dn === "CN=Issuing CA");
  check("full: validity Dates", t.validity.notBefore instanceof Date && t.validity.notAfter instanceof Date);
  check("full: subject dn", t.subject.dn === "CN=end.entity");
  check("full: publicKey algorithm", t.publicKey.algorithm.oid === RSA_ENC);
  check("full: extensions named", t.extensions.length === 2 && t.extensions[0].name === "basicConstraints" && t.extensions[0].critical === true);
  check("full: extension with critical omitted (DEFAULT FALSE)", t.extensions[1].name === "keyUsage" && t.extensions[1].critical === false);
}

function testAcceptEmptyTemplate() {
  var t = parse(one({ certReq: { templateNode: b.sequence([]) } })).messages[0].certReq.certTemplate;
  check("empty template: all requestable fields null", t.version === null && t.issuer === null &&
    t.validity === null && t.subject === null && t.publicKey === null && t.extensions === null);
  // The CA-assigned fields are surfaced (null in a valid request); the rule that
  // a request must OMIT them is enforced in CertRequest, not by dropping them —
  // the shared CertTemplate structure carries them for the revocation consumer.
  check("empty template: CA-assigned fields surfaced null", t.serialNumber === null && t.signingAlg === null && t.issuerUID === null && t.subjectUID === null);
}

function testAcceptExplicitName() {
  // issuer [3] EXPLICIT reading (the standards-compliant CHOICE encoding, OQ1).
  var t = parse(one({ certReq: { templateNode: certTemplate({ issuerNode: explicitName(3, "Explicit CA"), subject: "s", publicKey: { alg: RSA_ENC } }) } })).messages[0].certReq.certTemplate;
  check("explicit name: issuer dn rendered", t.issuer.dn === "CN=Explicit CA");
}

function testAcceptPop() {
  check("popo raVerified", parse(one({ popo: popoRaVerified() })).messages[0].popo.type === "raVerified");
  var sig = parse(one({ popo: popoSignature({}) })).messages[0].popo;
  check("popo signature: type + fields", sig.type === "signature" && sig.algorithmIdentifier.oid === SHA256_RSA && Buffer.isBuffer(sig.signature.bytes) && sig.poposkInput === null);
  // poposkInput is only permitted when the template is incomplete (§4.1) — a
  // subject-only template.
  var sigIn = parse(certReqMessages([certReqMsg({ certReq: { templateNode: certTemplate({ subject: "s" }) }, popo: popoSignature({ poposkInput: poposkInput() }) })])).messages[0].popo;
  // poposkInput surfaces the raw wire [0] TLV AND the SEQUENCE-tagged signed region
  // (RFC 4211 §4.1) — the two differ only in the identifier octet.
  check("poposkInput.bytes is the wire [0] TLV", sigIn.poposkInput.bytes[0] === 0xa0);
  check("poposkInput.signedBytes is the SEQUENCE DER the signature covers", sigIn.poposkInput.signedBytes[0] === 0x30 &&
    sigIn.poposkInput.signedBytes.slice(1).equals(sigIn.poposkInput.bytes.slice(1)));
  var ke = parse(one({ popo: popoKeyEnc() })).messages[0].popo;
  check("popo keyEncipherment: method + raw bytes", ke.type === "keyEncipherment" && ke.method === "thisMessage" && Buffer.isBuffer(ke.bytes));
}

function testAcceptRegInfoControls() {
  var m = parse(one({ certReq: { controls: [control(OLD_CERT_ID, b.octetString(Buffer.from([0x01])))] }, regInfo: [control(UTF8_PAIRS, b.utf8("k?v"))] }));
  check("controls[0] named oldCertID + raw value", m.messages[0].certReq.controls[0].name === "oldCertID" && Buffer.isBuffer(m.messages[0].certReq.controls[0].value));
  check("regInfo[0] named utf8Pairs + raw value", m.messages[0].regInfo[0].name === "utf8Pairs" && Buffer.isBuffer(m.messages[0].regInfo[0].value));
  // id-regInfo-certReq (§7.2) resolves to the RFC name, not a local alias.
  check("id-regInfo-certReq resolves to the RFC name", pki.oid.name("1.3.6.1.5.5.7.5.2.2") === "certReq" && pki.oid.byName("certReq") === "1.3.6.1.5.5.7.5.2.2");
}

function testAcceptMultiMessage() {
  var m = parse(certReqMessages([certReqMsg({ certReq: { id: 0 } }), certReqMsg({ certReq: { id: 1 } }), certReqMsg({ certReq: { id: 2 } })]));
  check("three messages, order preserved", m.messages.length === 3 && m.messages[0].certReq.certReqId === 0n && m.messages[2].certReq.certReqId === 2n);
}

function testAcceptCertReqIdSentinel() {
  var m = parse(one({ certReq: { id: -1 } }));
  check("certReqId -1 accepted (RFC 9483 sentinel)", m.messages[0].certReq.certReqId === -1n && m.messages[0].certReq.certReqIdHex === "ff");
}

// ---- REJECT — envelope / DER -----------------------------------------
function testRejectEnvelope() {
  check("empty CertReqMessages", parseCode(certReqMessages([])) === "crmf/bad-cert-req-messages");
  var good = one({});
  check("trailing garbage", parseCode(Buffer.concat([good, Buffer.from([0x00])])) === "crmf/bad-der");
  check("indefinite-length outer", parseCode(Buffer.concat([Buffer.from([0x30, 0x80]), good.slice(2), Buffer.from([0x00, 0x00])])) === "crmf/bad-der");
  var idSeq = parseCode(one({ certReq: { rawKids: [b.sequence([]), templateDefault()] } }));
  check("certReqId a SEQUENCE not INTEGER", idSeq.indexOf("asn1/") === 0 || idSeq === "crmf/bad-cert-request");
  check("CertReqMsg unexpected 4th child", parseCode(certReqMessages([certReqMsg({ rawKids: [certRequest({}), popoRaVerified(), b.sequence([control(UTF8_PAIRS, b.utf8("x"))]), b.integer(9)] })])) === "crmf/bad-cert-req-msg");
}

// ---- REJECT — CertTemplate IMPLICIT-tag traps ------------------------
function testRejectTemplateTraps() {
  check("version [0] as universal INTEGER", parseCode(one({ certReq: { templateNode: certTemplate({ versionNode: b.integer(2), subject: "s", publicKey: { alg: RSA_ENC } }) } })) === "crmf/bad-cert-template");
  check("version [0] constructed", parseCode(one({ certReq: { templateNode: certTemplate({ versionNode: b.contextConstructed(0, b.integer(2)) }) } })).indexOf("asn1/") === 0);
  check("signingAlg [2] primitive not constructed", parseCode(one({ certReq: { templateNode: certTemplate({ rawKids: [b.contextPrimitive(2, Buffer.from([0x06, 0x01, 0x2a]))] }) } })) === "crmf/bad-algorithm-identifier");
  check("template fields out of order ([5] before [3])", parseCode(one({ certReq: { templateNode: certTemplate({ rawKids: [implicitName(5, "s"), implicitName(3, "i")] }) } })) === "crmf/bad-cert-template");
  check("template duplicate tag (two [6])", parseCode(one({ certReq: { templateNode: certTemplate({ rawKids: [implicitSpki(6, RSA_ENC), implicitSpki(6, RSA_ENC)] }) } })) === "crmf/bad-cert-template");
  check("template unexpected [10]", parseCode(one({ certReq: { templateNode: certTemplate({ rawKids: [b.contextConstructed(10, Buffer.alloc(0))] }) } })) === "crmf/bad-cert-template");
  check("serialNumber [1] non-minimal INTEGER", parseCode(one({ certReq: { templateNode: certTemplate({ rawKids: [b.contextPrimitive(1, Buffer.from([0x00, 0x02]))] }) } })) === "asn1/non-minimal-integer");
}

// ---- REJECT — CA-assigned / deprecated CertTemplate fields (§5) -------
function testRejectCaAssignedFields() {
  // RFC 4211 §5 — serialNumber / signingAlg (CA-assigned) and issuerUID /
  // subjectUID (deprecated) MUST be omitted from a CertTemplate.
  function tpl(extra) { var o = { subject: "s", publicKey: { alg: RSA_ENC } }; Object.keys(extra).forEach(function (k) { o[k] = extra[k]; }); return certTemplate(o); }
  check("serialNumber present rejected", parseCode(one({ certReq: { templateNode: tpl({ serialNumber: 7 }) } })) === "crmf/bad-cert-template");
  check("signingAlg present rejected", parseCode(one({ certReq: { templateNode: tpl({ signingAlg: SHA256_RSA }) } })) === "crmf/bad-cert-template");
  check("issuerUID present rejected", parseCode(one({ certReq: { templateNode: tpl({ issuerUID: Buffer.from([0xde]) }) } })) === "crmf/bad-cert-template");
  check("subjectUID present rejected", parseCode(one({ certReq: { templateNode: tpl({ subjectUID: Buffer.from([0xad]) }) } })) === "crmf/bad-cert-template");
}

// ---- REJECT — poposkInput <-> template presence (§4.1) ---------------
function testRejectPoposkInput() {
  var complete = certTemplate({ subject: "s", publicKey: { alg: RSA_ENC } });
  var subjectOnly = certTemplate({ subject: "s" });
  function msg(tplNode, popo) { return certReqMessages([certReqMsg({ certReq: { templateNode: tplNode }, popo: popo })]); }
  check("poposkInput present + complete template rejected", parseCode(msg(complete, popoSignature({ poposkInput: poposkInput() }))) === "crmf/bad-popo");
  check("poposkInput absent + incomplete template rejected", parseCode(msg(subjectOnly, popoSignature({}))) === "crmf/bad-popo");
  check("complete template + no poposkInput accepted", parseCode(msg(complete, popoSignature({}))) === "NO-THROW");
  check("incomplete template + poposkInput accepted", parseCode(msg(subjectOnly, popoSignature({ poposkInput: poposkInput() }))) === "NO-THROW");
  // poposkInput [0] must be constructed (POPOSigningKeyInput is a SEQUENCE).
  var primInput = b.contextConstructed(1, Buffer.concat([b.contextPrimitive(0, Buffer.from([0x01])), algId(SHA256_RSA), b.bitString(Buffer.from([0xaa]), 0)]));
  check("poposkInput [0] primitive rejected", parseCode(msg(subjectOnly, primInput)) === "crmf/bad-popo");
  // POPOSigningKeyInput is fully validated: empty / arity / malformed-field all fail closed.
  check("poposkInput empty [0] rejected", parseCode(msg(subjectOnly, popoSignature({ poposkInput: b.contextConstructed(0, Buffer.alloc(0)) }))) === "crmf/bad-popo");
  check("poposkInput missing publicKey (arity 1) rejected", parseCode(msg(subjectOnly, popoSignature({ poposkInput: poposkInput({ fields: [b.sequence([algId(SHA256_RSA), b.bitString(Buffer.from([0xaa]), 0)])] }) }))) === "crmf/bad-popo");
  check("poposkInput bad publicKey (not SPKI) rejected", parseCode(msg(subjectOnly, popoSignature({ poposkInput: poposkInput({ publicKey: b.integer(1) }) }))) === "crmf/bad-spki");
  // authInfo sender [0] EXPLICIT GeneralName is accepted.
  check("poposkInput authInfo sender [0] GeneralName accepted", parseCode(msg(subjectOnly, popoSignature({ poposkInput: poposkInput({ authInfo: b.explicit(0, b.contextPrimitive(2, Buffer.from("dns.example", "latin1"))) }) }))) === "NO-THROW");
  // A POP signature / PKMACValue MAC is octet-string algorithm output handed to
  // an external verifier -- a non-octet-aligned BIT STRING is malformed
  // (RFC 4211 sec. 4.1, RFC 9481).
  check("POP signature with unused bits rejected", parseCode(msg(complete, popoSignature({ sig: Buffer.from([0xa0]), sigUnused: 4 }))) === "crmf/bad-popo");
  check("poposkInput PKMACValue with unused bits rejected", parseCode(msg(subjectOnly, popoSignature({ poposkInput: poposkInput({ authInfo: b.sequence([algId(SHA256_RSA), b.bitString(Buffer.from([0xa0]), 4)]) }) }))) === "crmf/bad-popo");
}

// ---- POPOPrivKey methods + §4.2/§4.3 validation ----------------------
function testPopoPrivKeyMethods() {
  var complete = certTemplate({ subject: "s", publicKey: { alg: RSA_ENC } });
  var subjectOnly = certTemplate({ subject: "s" });
  function m2(tplNode, popo) { return certReqMessages([certReqMsg({ certReq: { templateNode: tplNode }, popo: popo })]); }
  function keyEnc(inner) { return b.contextConstructed(2, inner); }
  function keyAgree(inner) { return b.contextConstructed(3, inner); }
  // subsequentMessage [1] SubsequentMessage ::= INTEGER { encrCert(0), challengeResp(1) }.
  check("subsequentMessage encrCert(0) accepted + method surfaced", parse(one({ popo: keyEnc(implicitInt(1, 0)) })).messages[0].popo.method === "subsequentMessage");
  check("subsequentMessage challengeResp(1) accepted", parseCode(one({ popo: keyEnc(implicitInt(1, 1)) })) === "NO-THROW");
  check("subsequentMessage out-of-range value rejected", parseCode(one({ popo: keyEnc(implicitInt(1, 5)) })) === "crmf/bad-popo");
  // agreeMAC [3] IMPLICIT PKMACValue (the [3] replaces the PKMACValue SEQUENCE tag).
  function agreeMac() { return b.contextConstructed(3, Buffer.concat([algId(SHA256_RSA), b.bitString(Buffer.from([0xaa]), 0)])); }
  // agreeMAC [3] / dhMAC [2] MAC the certReq, which MUST contain subject + publicKey.
  check("agreeMAC [3] + complete template accepted", parse(m2(complete, keyAgree(agreeMac()))).messages[0].popo.method === "agreeMAC");
  check("agreeMAC [3] + incomplete template rejected", parseCode(m2(subjectOnly, keyAgree(agreeMac()))) === "crmf/bad-popo");
  check("dhMAC [2] + incomplete template rejected", parseCode(m2(subjectOnly, keyAgree(b.contextPrimitive(2, Buffer.from([0x00, 0xaa]))))) === "crmf/bad-popo");
  // Each alternative's PAYLOAD is decoded, not just form-checked.
  check("agreeMAC [3] non-PKMACValue payload rejected", parseCode(m2(complete, keyAgree(b.contextConstructed(3, b.integer(1))))) === "crmf/bad-popo");
  // The PKMACValue MAC is octet-string output -- unused BIT STRING bits are malformed.
  check("agreeMAC [3] PKMACValue with unused bits rejected", parseCode(m2(complete, keyAgree(b.contextConstructed(3, Buffer.concat([algId(SHA256_RSA), b.bitString(Buffer.from([0xa0]), 4)]))))) === "crmf/bad-popo");
  check("dhMAC [2] malformed BIT STRING rejected", parseCode(m2(complete, keyAgree(b.contextPrimitive(2, Buffer.from([0x08]))))) === "crmf/bad-popo");
  check("thisMessage [0] malformed BIT STRING rejected", parseCode(one({ popo: keyEnc(b.contextPrimitive(0, Buffer.from([0x08]))) })) === "crmf/bad-popo");
  // encryptedKey [4] EnvelopedData is structurally validated, not deferred raw.
  check("encryptedKey [4] valid EnvelopedData accepted + method surfaced", parse(one({ popo: keyEnc(b.contextConstructed(4, envDataFields())) })).messages[0].popo.method === "encryptedKey");
  // A ZERO-LENGTH attached ciphertext is as meaningless a POP as a detached one
  // (no key material to verify or archive) -- same reject, same code.
  check("encryptedKey [4] zero-length ciphertext rejected", parseCode(one({ popo: keyEnc(b.contextConstructed(4, envDataFields(null, false, true))) })) === "crmf/bad-popo");
  check("encryptedKey [4] malformed EnvelopedData rejected", parseCode(one({ popo: keyEnc(b.contextConstructed(4, b.integer(9))) })) === "crmf/bad-popo");
  // RFC 4211 §4.2 — the enveloped content type MUST be id-ct-encKeyWithID.
  check("encryptedKey [4] wrong content type (id-data) rejected", parseCode(one({ popo: keyEnc(b.contextConstructed(4, envDataFields("1.2.840.113549.1.7.1"))) })) === "crmf/bad-popo");
  // The encrypted key material MUST be present (a detached EnvelopedData is rejected).
  check("encryptedKey [4] detached (no encryptedContent) rejected", parseCode(one({ popo: keyEnc(b.contextConstructed(4, envDataFields(null, true))) })) === "crmf/bad-popo");
  // The MAC arms are key-agreement only — rejected under keyEncipherment [2].
  check("keyEncipherment [2] + dhMAC inner rejected", parseCode(one({ popo: keyEnc(b.contextPrimitive(2, Buffer.from([0x00, 0xaa]))) })) === "crmf/bad-popo");
  check("keyEncipherment [2] + agreeMAC inner rejected", parseCode(one({ popo: keyEnc(agreeMac()) })) === "crmf/bad-popo");
}

// ---- REJECT — poposkInput publicKey must match the template (§4.1) ----
function testRejectPoposkInputKeyMismatch() {
  // template with publicKey but no subject -> poposkInput required, and its publicKey
  // MUST equal the template publicKey (RFC 4211 §4.1).
  var RSA_KEY = Buffer.from([0x04, 0x05, 0x06]);
  var OTHER_KEY = Buffer.from([0x07, 0x08, 0x09]);
  function tpl(keyBits) { return certTemplate({ publicKey: { alg: RSA_ENC, keyBits: keyBits } }); }  // no subject
  function pin(keyBits) { return poposkInput({ publicKey: b.sequence([algId(RSA_ENC), b.bitString(keyBits, 0)]) }); }
  function msg(tplNode, pk) { return certReqMessages([certReqMsg({ certReq: { templateNode: tplNode }, popo: popoSignature({ poposkInput: pk }) })]); }
  check("poposkInput publicKey matches template -> accepted", parseCode(msg(tpl(RSA_KEY), pin(RSA_KEY))) === "NO-THROW");
  check("poposkInput publicKey differs from template -> rejected", parseCode(msg(tpl(RSA_KEY), pin(OTHER_KEY))) === "crmf/bad-popo");
}

// ---- REJECT — version value (RFC 4211 §5: MUST be 2 if supplied) ------
function testRejectVersionValue() {
  check("version 0 rejected", parseCode(one({ certReq: { templateNode: certTemplate({ version: 0, subject: "s", publicKey: { alg: RSA_ENC } }) } })) === "crmf/bad-version");
  check("version 1 rejected", parseCode(one({ certReq: { templateNode: certTemplate({ version: 1, subject: "s", publicKey: { alg: RSA_ENC } }) } })) === "crmf/bad-version");
  check("version 3 rejected", parseCode(one({ certReq: { templateNode: certTemplate({ version: 3, subject: "s", publicKey: { alg: RSA_ENC } }) } })) === "crmf/bad-version");
  check("version 2 accepted", parseCode(one({ certReq: { templateNode: certTemplate({ version: 2, subject: "s", publicKey: { alg: RSA_ENC } }) } })) === "NO-THROW");
}

// ---- REJECT — Name / Validity / POP ----------------------------------
function testRejectNameValidityPop() {
  check("issuer [3] neither IMPLICIT nor EXPLICIT Name", parseCode(one({ certReq: { templateNode: certTemplate({ issuerNode: b.contextPrimitive(3, Buffer.from([1])) }) } })) === "crmf/bad-name");
  check("notBefore [0] IMPLICIT not EXPLICIT", parseCode(one({ certReq: { templateNode: certTemplate({ validityNode: b.contextConstructed(4, b.contextPrimitive(0, Buffer.from("20260101000000Z", "latin1"))) }) } })) === "crmf/bad-validity");
  check("validity [4] present but EMPTY (§5 at-least-one)", parseCode(one({ certReq: { templateNode: certTemplate({ validityNode: b.contextConstructed(4, Buffer.alloc(0)) }) } })) === "crmf/bad-validity");
  // A context [4] is neither a ProofOfPossession arm ([0..3]) nor the universal-
  // SEQUENCE regInfo, so it is rejected as an unexpected CertReqMsg element.
  check("stray context [4] after certReq", parseCode(one({ rawKids: [certRequest({}), b.contextConstructed(4, Buffer.alloc(0))] })) === "crmf/bad-cert-req-msg");
  check("popo raVerified constructed/non-empty", parseCode(one({ popo: b.contextConstructed(0, Buffer.alloc(0)) })) === "crmf/bad-popo");
  // POPOPrivKey ([2]/[3]) is EXPLICIT (a CHOICE): a primitive [2], or a [2]
  // wrapping a non-context / out-of-range inner, is not a valid POP shell.
  check("keyEncipherment [2] primitive (not EXPLICIT-constructed)", parseCode(one({ popo: b.contextPrimitive(2, Buffer.from([0x01])) })) === "crmf/bad-popo");
  check("keyEncipherment [2] wrapping a universal SEQUENCE", parseCode(one({ popo: b.contextConstructed(2, b.sequence([b.integer(1)])) })) === "crmf/bad-popo");
  check("keyEncipherment [2] wrapping an out-of-range [5]", parseCode(one({ popo: b.contextConstructed(2, b.contextPrimitive(5, Buffer.from([0x01]))) })) === "crmf/bad-popo");
  // Per-arm form: [3] agreeMAC / [4] encryptedKey are constructed; [0]/[1]/[2] primitive.
  check("keyEncipherment [2] wrapping [3] as primitive (wrong form)", parseCode(one({ popo: b.contextConstructed(2, b.contextPrimitive(3, Buffer.from([0x01]))) })) === "crmf/bad-popo");
  check("keyEncipherment [2] wrapping [0] as constructed (wrong form)", parseCode(one({ popo: b.contextConstructed(2, b.contextConstructed(0, b.sequence([]))) })) === "crmf/bad-popo");
}

// ---- REJECT — popo / regInfo position + SIZE -------------------------
function testRejectPositionSize() {
  // A regInfo (universal SEQUENCE) present with NO popo, first control malformed:
  // proves the popo tags:[0..3] recognizer did NOT mis-consume the SEQUENCE as popo.
  check("regInfo with malformed control (no popo)", parseCode(one({ regInfo: [b.sequence([b.integer(1)])] })) === "crmf/bad-control");
  check("regInfo empty SEQUENCE", parseCode(certReqMessages([certReqMsg({ rawKids: [certRequest({}), b.sequence([])] })])) === "crmf/bad-reg-info");
  check("controls empty SEQUENCE", parseCode(one({ certReq: { rawKids: [b.integer(0), templateDefault(), b.sequence([])] } })) === "crmf/bad-controls");
}

// ---- DISPATCH + coercion ---------------------------------------------
function testDispatch() {
  var der = one({});
  var routed = pki.schema.parse(der);
  check("orchestrator routes CRMF to crmf", Array.isArray(routed.messages) && routed.messages.length === 1);
  check("all() includes crmf between tsp and ocsp-request", (function () {
    var a = pki.schema.all();
    return a.indexOf("crmf") !== -1 && a.indexOf("crmf") > a.indexOf("tsp") && a.indexOf("crmf") < a.indexOf("ocsp-request");
  })());
  // A 2-message CRMF routes to crmf regardless of the ocsp-request overlap.
  check("2-message CRMF routes to crmf", Array.isArray(pki.schema.parse(certReqMessages([certReqMsg({}), certReqMsg({})])).messages));
  // detector predicate
  check("crmf.matches on a CRMF true", crmfMod.matches(pki.asn1.decode(der)) === true);
}

function testInputCoercion() {
  var der = one({});
  check("parse(Buffer) ok", parse(der).messages.length === 1);
  check("parse(Uint8Array) ok", parse(new Uint8Array(der)).messages.length === 1);
  check("parse(42) bad-input", parseCode(42) === "crmf/bad-input");
  // The PEM path: RFC 4211 registers no RFC 7468 label (pemLabel null), so the
  // FIRST block of any label is taken — as a string and as a Buffer — and a bad
  // envelope fails with the pem/* verdict.
  var pem = "-----BEGIN CERT REQUEST MESSAGES-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CERT REQUEST MESSAGES-----\n";
  check("parse(PEM string) ok (label-agnostic)", parse(pem).messages.length === 1);
  check("parse(PEM Buffer) ok", parse(Buffer.from(pem, "latin1")).messages.length === 1);
  check("pemDecode round-trips", pki.schema.crmf.pemDecode(pem).equals(der));
  check("pemEncode with an explicit label round-trips",
    pki.schema.crmf.pemDecode(pki.schema.crmf.pemEncode(der, "CERT REQUEST MESSAGES"), "CERT REQUEST MESSAGES").equals(der));
  check("pemEncode without a label fails closed",
    code(function () { pki.schema.crmf.pemEncode(der); }) === "pem/bad-label");
  check("missing envelope -> pem/no-block", parseCode("not a pem block") === "pem/no-block");
  check("bad base64 body -> pem/bad-base64", parseCode("-----BEGIN X-----\n@@@@\n-----END X-----\n") === "pem/bad-base64");
  // multi-defect fail-closed: never NO-THROW.
  var multi = one({ certReq: { templateNode: certTemplate({ version: 0, rawKids: [implicitInt(0, 0), implicitName(5, "s"), implicitName(3, "i")] }) } });
  var mc = parseCode(multi);
  check("multi-defect rejected (typed)", mc !== "NO-THROW" && (mc.indexOf("crmf/") === 0 || mc.indexOf("asn1/") === 0));
}

// ---- schema.encode round-trip (proves crmf's IMPLICIT/EXPLICIT tag handling) ----
function testEncodeRoundTrip() {
  var S = pki.schema.engine;
  function rdn(cn) { return { rdns: [[{ type: "2.5.4.3", value: cn }]] }; }
  var value = [{ certReq: { certReqId: 0n, certTemplate: {
    version: 2n, issuer: rdn("Issuing CA"),
    validity: { notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") },
    subject: rdn("end.entity"),
    publicKey: { algorithm: { algorithm: RSA_ENC }, subjectPublicKey: { unusedBits: 0, bytes: Buffer.from([0x04, 0x05, 0x06]) } },
  } } }];
  // One schema definition drives both directions: encode -> decode -> parse recovers
  // the value, so the IMPLICIT/EXPLICIT tags cannot diverge between the two.
  var t = parse(S.encode(crmfMod.certReqMessagesSchema, value)).messages[0].certReq.certTemplate;
  check("encode round-trip: version [0] IMPLICIT INTEGER", t.version === 2n);
  check("encode round-trip: issuer [3] IMPLICIT Name", t.issuer.dn === "CN=Issuing CA");
  check("encode round-trip: subject [5] IMPLICIT Name", t.subject.dn === "CN=end.entity");
  check("encode round-trip: validity [4] EXPLICIT times", t.validity.notBefore.toISOString() === "2026-01-01T00:00:00.000Z" && t.validity.notAfter instanceof Date);
  check("encode round-trip: publicKey [6] IMPLICIT SPKI is importable (0x30)", t.publicKey.algorithm.oid === RSA_ENC && t.publicKey.bytes[0] === 0x30);
  check("encode round-trip: encoded bytes route as crmf", crmfMod.matches(pki.asn1.decode(S.encode(crmfMod.certReqMessagesSchema, value))));
}

// The NS-bound walkers a composing envelope (CMP) delegates to: walking an
// already-decoded interior node yields the same result parse would, and a
// malformed interior throws the crmf-owned class/code — never the composer's.
function testWalkers() {
  var msgs = b.sequence([b.sequence([b.sequence([b.integer(0n), b.sequence([b.explicit(5, rdnSeq("walker.example"))])])])]);
  var walked = crmfMod.walkCertReqMessages(pki.asn1.decode(msgs));
  check("walkCertReqMessages decodes a bare CertReqMessages", walked.messages[0].certReq.certTemplate.subject.dn === "CN=walker.example");
  check("walkCertReqMessages rejects with a crmf/* code", code(function () {
    crmfMod.walkCertReqMessages(pki.asn1.decode(b.sequence([])));
  }) === "crmf/bad-cert-req-messages");
  var tpl = crmfMod.walkCertTemplate(pki.asn1.decode(b.sequence([b.explicit(5, rdnSeq("tpl.example"))])));
  check("walkCertTemplate decodes a bare CertTemplate", tpl.subject.dn === "CN=tpl.example");
  // The bare template surfaces serialNumber/issuer — the CA-assigned omission
  // rule is REQUEST-context and lives in CertRequest, not the structure, so a
  // revocation consumer (CMP RevDetails) reads serialNumber off this walker.
  var revTpl = crmfMod.walkCertTemplate(pki.asn1.decode(b.sequence([implicitInt(1, 5)])));
  check("walkCertTemplate surfaces serialNumber (no request-omission rule)", revTpl.serialNumber === 5n);
  check("walkCertTemplate still enforces the structural version==2 rule", code(function () {
    crmfMod.walkCertTemplate(pki.asn1.decode(b.sequence([implicitInt(0, 5)])));
  }) === "crmf/bad-version");
}

// ---- branch coverage: Name/validity/POP/control edge arms -----------
function testBranchCoverage() {
  // Empty IMPLICIT issuer [3]: a [tag]-constructed node with ZERO children is a
  // valid empty RDNSequence (an empty DN), taken by the length===0 arm — distinct
  // from the SET-led IMPLICIT and single-SEQUENCE EXPLICIT arms.
  var emptyIssuer = certTemplate({ issuerNode: b.contextConstructed(3, Buffer.alloc(0)), subject: "s", publicKey: { alg: RSA_ENC } });
  var iss = parse(one({ certReq: { templateNode: emptyIssuer } })).messages[0].certReq.certTemplate.issuer;
  check("empty IMPLICIT issuer [3] -> empty RDNSequence (dn '')", iss !== null && iss.dn === "" && iss.rdns.length === 0);

  // issuer [3] constructed but the first inner element is neither a universal SET
  // (IMPLICIT arm) nor a single universal SEQUENCE (EXPLICIT arm): fails closed.
  check("issuer [3] wrapping a universal INTEGER child rejected", parseCode(one({ certReq: { templateNode: certTemplate({ issuerNode: b.contextConstructed(3, b.integer(1)) }) } })) === "crmf/bad-name");
  check("issuer [3] wrapping two universal SEQUENCE children rejected", parseCode(one({ certReq: { templateNode: certTemplate({ issuerNode: b.contextConstructed(3, Buffer.concat([rdnSeq("a"), rdnSeq("b")])) }) } })) === "crmf/bad-name");

  // OptionalValidity with exactly one of the two times present (§5 requires >=1):
  // the absent side surfaces null (each ternary's false arm).
  var nbOnly = parse(one({ certReq: { templateNode: certTemplate({ validity: { nb: "2026-01-01T00:00:00Z" }, subject: "s", publicKey: { alg: RSA_ENC } }) } })).messages[0].certReq.certTemplate.validity;
  check("validity notBefore-only -> notAfter null", nbOnly.notBefore instanceof Date && nbOnly.notAfter === null);
  var naOnly = parse(one({ certReq: { templateNode: certTemplate({ validity: { na: "2027-01-01T00:00:00Z" }, subject: "s", publicKey: { alg: RSA_ENC } }) } })).messages[0].certReq.certTemplate.validity;
  check("validity notAfter-only -> notBefore null", naOnly.notBefore === null && naOnly.notAfter instanceof Date);

  // subsequentMessage [1] whose content is not a well-formed INTEGER (non-minimal
  // encoding) is rejected by the integer read, not the {0,1} range check.
  check("subsequentMessage [1] non-minimal INTEGER content rejected", parseCode(one({ popo: popoKeyEnc(b.contextPrimitive(1, Buffer.from([0x00, 0x00]))) })) === "crmf/bad-popo");

  // A control / regInfo AttributeTypeAndValue with an UNREGISTERED type OID
  // surfaces name === null (the oid-registry lookup returns undefined).
  var unk = parse(one({ certReq: { controls: [control("1.2.3.4.5.6.7", b.octetString(Buffer.from([0x01])))] } })).messages[0].certReq.controls[0];
  check("control with an unknown OID -> name null, raw value surfaced", unk.name === null && unk.type === "1.2.3.4.5.6.7" && Buffer.isBuffer(unk.value));
}

// ---- runner ----------------------------------------------------------
testAcceptMinimal();
testWalkers();
testAcceptFullTemplate();
testAcceptEmptyTemplate();
testAcceptExplicitName();
testAcceptPop();
testAcceptRegInfoControls();
testAcceptMultiMessage();
testAcceptCertReqIdSentinel();
testRejectEnvelope();
testRejectTemplateTraps();
testRejectCaAssignedFields();
testRejectPoposkInput();
testPopoPrivKeyMethods();
testRejectPoposkInputKeyMismatch();
testRejectVersionValue();
testRejectNameValidityPop();
testRejectPositionSize();
testDispatch();
testEncodeRoundTrip();
testInputCoercion();
testBranchCoverage();

if (require.main === module) console.log("CHECKS " + helpers.getChecks());
module.exports = {};
