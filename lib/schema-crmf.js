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
 *   `CertReqMessages`, the request body CMP and EST enrollment carry, into an
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
 *   when supplied, MUST be 2 (RFC 4211 sec. 5); certReqId is an unbounded signed
 *   INTEGER (the RFC 9483 `-1` sentinel is legal). The `CertRequest` byte range
 *   the proof-of-possession signature covers, and each `poposkInput`, are surfaced
 *   raw for a downstream verifier; registration controls / info values and the
 *   keyEncipherment / keyAgreement POP arms are surfaced raw and never recursed.
 *   DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM RFC 4211 CertReqMessages into requested-certificate templates,
 *   proof-of-possession, and registration controls: dual-accepted names, raw
 *   verifier inputs, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var cms = require("./schema-cms");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");

var CrmfError = frameworkError.CrmfError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("crmf", CrmfError, oid);

var TAGS = asn1.TAGS;

function crmfName(tag) {
  var NAME = pkix.name(NS);
  var INAME = pkix.name(NS, { implicitTag: tag });
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "context" || n.tagNumber !== tag || !n.children) {
      throw ctx.E("crmf/bad-name", "issuer/subject [" + tag + "] must be a Name (RFC 4211 sec. 5)");
    }
    if (n.children.length === 0) return schema.walk(INAME, n, ctx).result;
    var c0 = n.children[0];
    if (c0.tagClass === "universal" && c0.tagNumber === TAGS.SET) {
      return schema.walk(INAME, n, ctx).result;
    }
    if (n.children.length === 1 && c0.tagClass === "universal" && c0.tagNumber === TAGS.SEQUENCE) {
      return schema.walk(NAME, c0, ctx).result;
    }
    throw ctx.E("crmf/bad-name", "issuer/subject [" + tag + "] Name must be an IMPLICIT RDNSequence (SET-led) or an EXPLICIT-wrapped RDNSequence");
  }, function (value) {
    return schema.encode(INAME, value.rdns, NS);
  });
}

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
      throw ctx.E("crmf/bad-validity", "OptionalValidity must contain notBefore or notAfter (RFC 4211 sec. 5)");
    }
    return { notBefore: f.notBefore.present ? f.notBefore.value : null, notAfter: f.notAfter.present ? f.notAfter.value : null };
  },
});

var POPO_RAVERIFIED = schema.decode(function (n, ctx) {
  try { asn1.read.nullImplicit(n, 0); }
  catch (e) { throw ctx.E("crmf/bad-popo", "raVerified [0] must be an IMPLICIT NULL", e); }
  return { type: "raVerified" };
});


var PKMAC_VALUE = schema.seq([
  schema.field("algId", pkix.algorithmIdentifier(NS)),
  schema.field("value", schema.bitString()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "crmf/bad-popo", what: "PKMACValue",
  build: function (m, ctx) {
    var macBitString = m.fields.value.value;
    if (macBitString.unusedBits !== 0) {
      throw ctx.E("crmf/bad-popo", "a PKMACValue MAC BIT STRING must be octet-aligned (0 unused bits)");
    }
    return { algId: m.fields.algId.value.result, value: { unusedBits: macBitString.unusedBits, bytes: macBitString.bytes } };
  },
});

var POPOSK_AUTH_INFO = schema.choice([
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.explicit(0, pkix.generalName(NS, { code: "crmf/bad-popo" }), { code: "crmf/bad-popo" }) },
  { when: { tagClass: "universal", tagNumber: TAGS.SEQUENCE }, schema: PKMAC_VALUE },
], { code: "crmf/bad-popo" });

var POPOSK_INPUT = schema.seq([
  schema.field("authInfo", POPOSK_AUTH_INFO),
  schema.field("publicKey", pkix.spki(NS)),
], { assert: "implicit", implicitTag: 0, arity: { exact: 2 }, code: "crmf/bad-popo", what: "POPOSigningKeyInput" });

var POPO_SIGNING_KEY = schema.seq([
  schema.optional("poposkInput", schema.decode(function (n, ctx) {
    var m = schema.walk(POPOSK_INPUT, n, ctx);
    return { node: n, publicKey: m.fields.publicKey.value.result.bytes };
  }), { tag: 0 }),
  schema.field("algorithmIdentifier", pkix.algorithmIdentifier(NS)),
  schema.field("signature", schema.bitString()),
], {
  assert: "implicit", implicitTag: 1, code: "crmf/bad-popo", what: "POPOSigningKey",
  build: function (m, ctx) {
    var pin = m.fields.poposkInput;
    var sig = m.fields.signature.value;
    if (sig.unusedBits !== 0) {
      throw ctx.E("crmf/bad-popo", "a POPOSigningKey signature BIT STRING must be octet-aligned (0 unused bits)");
    }
    return {
      type: "signature",
      poposkInput: pin.present ? { bytes: pin.node.bytes, signedBytes: asn1.sequenceTlv(pin.node), publicKey: pin.value.publicKey } : null,
      algorithmIdentifier: m.fields.algorithmIdentifier.value.result,
      signature: { unusedBits: sig.unusedBits, bytes: sig.bytes },
    };
  },
});

var POPOPRIVKEY_METHODS = intrinsic.assign(intrinsic.create(null), { 0: "thisMessage", 1: "subsequentMessage", 2: "dhMAC", 3: "agreeMAC", 4: "encryptedKey" });
function popoPrivKey(type) {
  return schema.decode(function (n, ctx) {
    if (!n.children || n.children.length !== 1) {
      throw ctx.E("crmf/bad-popo", type + " [" + n.tagNumber + "] POPOPrivKey must be an EXPLICIT wrapper around one alternative (RFC 4211 sec. 4)");
    }
    var inner = n.children[0];
    if (inner.tagClass !== "context" || inner.tagNumber < 0 || inner.tagNumber > 4) {
      throw ctx.E("crmf/bad-popo", type + " POPOPrivKey alternative must be a context [0]..[4] CHOICE element (RFC 4211 sec. 4)");
    }
    if (type === "keyEncipherment" && (inner.tagNumber === 2 || inner.tagNumber === 3)) {
      throw ctx.E("crmf/bad-popo", "keyEncipherment POP cannot use the MAC alternative " + POPOPRIVKEY_METHODS[inner.tagNumber] + " (RFC 4211 sec. 4.2)");
    }
    var mustBeConstructed = inner.tagNumber === 3 || inner.tagNumber === 4;
    if (mustBeConstructed !== !!inner.children) {
      throw ctx.E("crmf/bad-popo", type + " POPOPrivKey [" + inner.tagNumber + "] has the wrong primitive/constructed form (RFC 4211 sec. 4)");
    }
    if (inner.tagNumber === 0 || inner.tagNumber === 2) {
      try { asn1.read.bitStringImplicit(inner, inner.tagNumber); }
      catch (e) { throw ctx.E("crmf/bad-popo", POPOPRIVKEY_METHODS[inner.tagNumber] + " [" + inner.tagNumber + "] must be a BIT STRING (RFC 4211 sec. 4.2)", e); }
    }
    if (inner.tagNumber === 1) {
      var v;
      try { v = asn1.read.integerImplicit(inner, 1); }
      catch (e) { throw ctx.E("crmf/bad-popo", "subsequentMessage must be an INTEGER", e); }
      if (v !== 0n && v !== 1n) {
        throw ctx.E("crmf/bad-popo", "SubsequentMessage must be encrCert(0) or challengeResp(1) (RFC 4211 sec. 4.2)");
      }
    }
    if (inner.tagNumber === 3) {
      try { schema.embeddedDer(PKMAC_VALUE, asn1.sequenceTlv(inner), schema.withResources(NS, ctx), { code: "crmf/bad-popo", what: "agreeMAC [3] PKMACValue" }); }
      catch (e) { throw ctx.E("crmf/bad-popo", "agreeMAC [3] must be a PKMACValue SEQUENCE { algId, BIT STRING } (RFC 4211 sec. 4.2)", e); }
    }
    if (inner.tagNumber === 4) {
      var env;
      try { env = cms.walkEnvelopedData(pkix.decodeNested(asn1.sequenceTlv(inner), ctx, "an encryptedKey [4] EnvelopedData"), ctx); }
      catch (e) { throw ctx.E("crmf/bad-popo", "encryptedKey [4] must be a well-formed EnvelopedData (RFC 4211 sec. 4.2, RFC 5652 sec. 6.1)", e); }
      if (env.encryptedContentInfo.contentType !== oid.byName("encKeyWithID")) {
        throw ctx.E("crmf/bad-popo", "encryptedKey [4] EnvelopedData content type MUST be id-ct-encKeyWithID (RFC 4211 sec. 4.2)");
      }
      cms.assertAttachedCiphertext(env.encryptedContentInfo, ctx.E, "crmf/bad-popo", "encryptedKey [4] EnvelopedData");
    }
    return { type: type, method: POPOPRIVKEY_METHODS[inner.tagNumber], bytes: n.bytes };
  });
}

var PROOF_OF_POSSESSION = schema.choice([
  { when: { tagClass: "context", tagNumber: 0 }, schema: POPO_RAVERIFIED },
  { when: { tagClass: "context", tagNumber: 1 }, schema: schema.decode(function (n, ctx) { return schema.walk(POPO_SIGNING_KEY, n, ctx).result; }) },
  { when: { tagClass: "context", tagNumber: 2 }, schema: popoPrivKey("keyEncipherment") },
  { when: { tagClass: "context", tagNumber: 3 }, schema: popoPrivKey("keyAgreement") },
], { code: "crmf/bad-popo" });

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
function mapControls(m) { return intrinsic.map(m.items, function (it) { return it.value.result; }); }
var CONTROLS = schema.seqOf(CONTROL, { assert: "sequence", min: 1, code: "crmf/bad-controls", what: "Controls", build: mapControls });
var REG_INFO = schema.seqOf(CONTROL, { assert: "sequence", min: 1, code: "crmf/bad-reg-info", what: "regInfo", build: mapControls });

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
    if (f.version.present && f.version.value !== 2n &&
        !(ctx.allowV1Version && f.version.value === 0n)) {
      throw ctx.E("crmf/bad-version", "CertTemplate version MUST be 2 (v3) if supplied (RFC 4211 sec. 5)");
    }
    return {
      version:     f.version.present ? f.version.value : null,
      serialNumber: f.serialNumber.present ? f.serialNumber.value : null,
      signingAlg:  f.signingAlg.present ? f.signingAlg.value.result : null,
      issuer:      f.issuer.present ? f.issuer.value : null,
      validity:    f.validity.present ? f.validity.value.result : null,
      subject:     f.subject.present ? f.subject.value : null,
      publicKey:   f.publicKey.present ? f.publicKey.value.result : null,
      issuerUID:   f.issuerUID.present ? f.issuerUID.value : null,
      subjectUID:  f.subjectUID.present ? f.subjectUID.value : null,
      extensions:  f.extensions.present ? f.extensions.value.result : null,
    };
  },
});

var CERT_REQUEST = schema.seq([
  schema.field("certReqId", schema.integerLeaf()),
  schema.field("certTemplate", CERT_TEMPLATE),
  schema.optional("controls", CONTROLS, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "crmf/bad-cert-request", what: "CertRequest",
  build: function (m, ctx) {
    var tpl = m.fields.certTemplate.value.result;
    var caAssigned = ctx.allowSigningAlg
      ? ["serialNumber", "issuerUID", "subjectUID"]
      : ["serialNumber", "signingAlg", "issuerUID", "subjectUID"];
    for (var i = 0; i < caAssigned.length; i++) {
      if (tpl[caAssigned[i]] !== null) {
        throw ctx.E("crmf/bad-cert-template", "CertTemplate " + caAssigned[i] + " MUST be omitted -- it is CA-assigned or deprecated (RFC 4211 sec. 5)");
      }
    }
    return {
      certReqId:     m.fields.certReqId.value,
      certReqIdHex:  intrinsic.bufToString(m.fields.certReqId.node.content, "hex"),
      certTemplate:  tpl,
      controls:      m.fields.controls.present ? m.fields.controls.value.result : null,
      certReqBytes:  m.node.bytes,
    };
  },
});

var CERT_REQ_MSG = schema.seq([
  schema.field("certReq", CERT_REQUEST),
  schema.optional("popo", PROOF_OF_POSSESSION, { tags: [0, 1, 2, 3] }),
  schema.optional("regInfo", REG_INFO, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "crmf/bad-cert-req-msg", what: "CertReqMsg",
  build: function (m, ctx) {
    var certReq = m.fields.certReq.value.result;
    var popo = m.fields.popo.present ? m.fields.popo.value : null;
    var complete = certReq.certTemplate.subject !== null && certReq.certTemplate.publicKey !== null;
    if (popo && popo.type === "signature") {
      if (complete && popo.poposkInput !== null) {
        throw ctx.E("crmf/bad-popo", "poposkInput MUST be omitted when the CertTemplate contains both subject and publicKey (RFC 4211 sec. 4.1)");
      }
      if (!complete && popo.poposkInput === null) {
        throw ctx.E("crmf/bad-popo", "poposkInput MUST be present when the CertTemplate lacks subject or publicKey (RFC 4211 sec. 4.1)");
      }
      if (popo.poposkInput !== null && certReq.certTemplate.publicKey !== null &&
          !intrinsic.bufferEquals(popo.poposkInput.publicKey, certReq.certTemplate.publicKey.bytes)) {
        throw ctx.E("crmf/bad-popo", "POPOSigningKeyInput publicKey MUST equal the CertTemplate publicKey (RFC 4211 sec. 4.1)");
      }
    }
    if (popo && (popo.type === "keyEncipherment" || popo.type === "keyAgreement") &&
        (popo.method === "dhMAC" || popo.method === "agreeMAC") && !complete) {
      throw ctx.E("crmf/bad-popo", "a MAC-based key-agreement/encipherment POP (dhMAC/agreeMAC) requires the CertTemplate to contain both subject and publicKey (RFC 4211 sec. 4.2/sec. 4.3)");
    }
    return {
      certReq: certReq,
      popo:    popo,
      regInfo: m.fields.regInfo.present ? m.fields.regInfo.value.result : null,
    };
  },
});

var CERT_REQ_MESSAGES = schema.seqOf(CERT_REQ_MSG, {
  assert: "sequence", min: 1, code: "crmf/bad-cert-req-messages", what: "CertReqMessages",
  build: function (m) { return { messages: intrinsic.map(m.items, function (it) { return it.value.result; }) }; },
});


/**
 * @primitive  pki.schema.crmf.parse
 * @signature  pki.schema.crmf.parse(input, caps?) -> certReqMessages
 * @since      0.1.17
 * @status     stable
 * @spec       RFC 4211
 * @related    pki.schema.parse, pki.schema.csr.parse
 *
 * Parse a DER `Buffer` or a PEM string/Buffer into a structured `CertReqMessages`:
 * `{ messages: [ { certReq, popo, regInfo } ] }`. Each `certReq` is
 * `{ certReqId, certReqIdHex, certTemplate, controls, certReqBytes }`, and
 * `certTemplate` carries the requestable certificate fields (`version`, `issuer`,
 * `validity`, `subject`, `publicKey`, `extensions`, each `null` when absent). The
 * CA-assigned / deprecated fields RFC 4211 sec. 5 requires a request to omit
 * (`serialNumber`, `signingAlg`, `issuerUID`, `subjectUID`) are rejected, not
 * surfaced. `popo` is
 * `null`, `{ type: "raVerified" }`, `{ type: "signature", poposkInput,
 * algorithmIdentifier, signature }`, or `{ type: "keyEncipherment" |
 * "keyAgreement", method, bytes }` (where `method` is the POPOPrivKey alternative:
 * `thisMessage` / `subsequentMessage` / `dhMAC` / `agreeMAC` / `encryptedKey`, each
 * structurally validated, the `encryptedKey` EnvelopedData included). When present, `poposkInput` is
 * `{ bytes, signedBytes, publicKey }`, where `bytes` is the raw wire `[0]` TLV,
 * `signedBytes` is the `POPOSigningKeyInput` re-tagged to the `SEQUENCE` DER the
 * signature actually covers, and `publicKey` is the canonical
 * `SubjectPublicKeyInfo` DER the RFC 4211 sec. 4.1 template-match check compares
 * against the `CertTemplate` publicKey (a POP verifier imports it directly).
 * `certReqBytes` is the exact `CertRequest` byte range a proof-of-possession
 * verifier hashes when `poposkInput` is absent.
 *
 * Throws `CrmfError` when the bytes are not a well-formed `CertReqMessages`, and
 * `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "req.example", publicKey: await pki.key.export(pair.publicKey) } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var m = pki.schema.crmf.parse(der);
 *   m.messages[0].certReq.certTemplate.subject.dn;   // "CN=req.example"
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. A parse that exceeds one is
 *     refused with the `/too-large` code of this format.
 */
var parse = pkix.makeRecordingParser({
  pemLabel: null, PemError: PemError, ErrorClass: CrmfError, prefix: "crmf",
  what: "certificate request message", topSchema: CERT_REQ_MESSAGES, ns: NS,
}, "crmf");

/**
 * @primitive  pki.schema.crmf.pemDecode
 * @signature  pki.schema.crmf.pemDecode(text, label?) -> Buffer
 * @since      0.1.17
 * @status     stable
 * @spec       RFC 7468, RFC 4211
 * @related    pki.schema.crmf.parse
 *
 * Extract the DER bytes from a PEM block (RFC 4211 registers no RFC 7468 label, so
 * a block of any label is accepted unless `label` is given; CRMF rides inside CMP /
 * EST as DER in practice). The text holds one object: a file of several is refused
 * with `pem/multiple-blocks` and read with `pki.schema.pem.decodeBundle`. Throws
 * `PemError` on a missing envelope or a non-base64 body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var msg = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "req.example", publicKey: await pki.key.export(pair.publicKey) } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var pemText = pki.schema.crmf.pemEncode(msg, "CERT REQUEST MESSAGES");
 *   var der = pki.schema.crmf.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || null, PemError); }

/**
 * @primitive  pki.schema.crmf.pemEncode
 * @signature  pki.schema.crmf.pemEncode(der, label) -> string
 * @since      0.1.23
 * @status     stable
 * @spec       RFC 7468, RFC 4211
 * @related    pki.schema.crmf.pemDecode
 *
 * Wrap DER bytes in a PEM envelope. RFC 4211 registers no RFC 7468 label, so
 * `label` is REQUIRED: the operator names the envelope explicitly (mirroring
 * `pemDecode`, which accepts any label). Omitting it throws `pem/bad-label`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "req.example", publicKey: await pki.key.export(pair.publicKey) } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var pem = pki.schema.crmf.pemEncode(der, "CERT REQUEST MESSAGES");
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label, PemError); }

function matches(root) {
  var k = pkix.rootSequenceChildren(root, 1);
  if (!k) return false;
  var msg = k[0];
  if (!(msg.children && schema.isUniversal(msg, TAGS.SEQUENCE) && msg.children.length >= 1)) return false;
  var certReq = msg.children[0];
  if (!(certReq.children && schema.isUniversal(certReq, TAGS.SEQUENCE) && certReq.children.length >= 2)) return false;
  var id = certReq.children[0], tpl = certReq.children[1];
  return schema.isUniversal(id, TAGS.INTEGER) &&
    schema.isUniversal(tpl, TAGS.SEQUENCE) && !!tpl.children;
}

/** @internal `outer` is the walk context of the parse that reached these messages, when another
 *  format carries them. Only its caps and budget cross over: the messages are still read in this
 *  namespace, so a fault in one keeps the CRMF error class and code. */
function walkCertReqMessages(node, opts, outer) {
  var ctx = schema.withResources(NS, outer);
  if (opts && (opts.allowSigningAlg || opts.allowV1Version)) {
    ctx = intrinsic.assign({}, ctx);
    if (opts.allowSigningAlg) ctx.allowSigningAlg = true;
    if (opts.allowV1Version) ctx.allowV1Version = true;
  }
  return schema.walk(CERT_REQ_MESSAGES, node, ctx).result;
}
function walkCertTemplate(node, outer) {
  return schema.walk(CERT_TEMPLATE, node, schema.withResources(NS, outer)).result;
}

/** @internal A CertTemplate asks for certificate extensions, so the certificate table reads them.
 *  As with a PKCS#10 request, criticality is part of what is asked for and RFC 4211 sec. 5 leaves
 *  the decision to the CA; the criticality RFC 5280 fixes is reported all the same. */
var CRMF_SCOPES = intrinsic.assign(intrinsic.create(null), {
  "crmf-template": {
    decoders: function (ctx) { return pkix.certExtensionDecoders(ctx).byOid; },
    criticality: pkix.certFixedCriticality(oid),
  },
});

var DOOR = pkix.extensionDoor({
  ns: NS, ErrorClass: CrmfError, key: "crmf", kind: "crmf", what: "the certificate request messages",
  parse: parse, scopes: CRMF_SCOPES, defaultScope: "crmf-template",
  segments: function (parsed) {
    var messages = parsed.messages || [];
    var out = [];
    for (var i = 0; i < messages.length; i++) {
      var template = messages[i].certReq && messages[i].certReq.certTemplate;
      intrinsic.push(out, { list: (template && template.extensions) || [], scope: "crmf-template", containerIndex: i });
    }
    return out;
  },
});

/**
 * @primitive  pki.schema.crmf.decodeExtensions
 * @signature  pki.schema.crmf.decodeExtensions(messagesOrBytes, opts?) -> rows
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 4211 sec. 5, RFC 5280 sec. 4.2
 * @related    pki.schema.crmf.parse, pki.schema.csr.decodeExtensions
 *
 * Read the extensions the certificate templates in a `CertReqMessages` ask for, as decoded records.
 * The argument is the object `parse` returned or the bytes `parse` takes, and the rows of every
 * message are returned in one array, each naming the message it came from in `containerIndex`.
 *
 * Each row is `{ oid, name, critical, value, scope, index, containerIndex, state, decoded, code,
 * profile }`, with `scope` `"crmf-template"`. Criticality here is part of the request: RFC 4211
 * sec. 5 leaves which requested extensions to honor to the CA, and `profile` reports what RFC 5280
 * would fix for the certificate the request would produce.
 *
 * @opts
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value. It does not turn an unrecognized OID into a throw.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "req.example", publicKey: await pki.key.export(pair.publicKey),
 *       extensions: { subjectAltName: [{ dNSName: "req.example" }] } } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var rows = pki.schema.crmf.decodeExtensions(der);
 *   rows[0].scope + " " + rows[0].name;  // -> "crmf-template subjectAltName"
 */
var decodeExtensions = DOOR.decodeExtensions;

/**
 * @primitive  pki.schema.crmf.decodeExtension
 * @signature  pki.schema.crmf.decodeExtension(ext, opts?) -> row
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 4211 sec. 5
 * @related    pki.schema.crmf.decodeExtensions
 *
 * Read one requested extension record as a decoded row, at scope `"crmf-template"`. The argument is
 * one element of a `certTemplate`'s `extensions`, as `{ oid, name, critical, value }`.
 *
 * @opts
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "req.example", publicKey: await pki.key.export(pair.publicKey),
 *       extensions: { subjectAltName: [{ dNSName: "req.example" }] } } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var msgs = pki.schema.crmf.parse(der);
 *   pki.schema.crmf.decodeExtension(msgs.messages[0].certReq.certTemplate.extensions[0]).name;  // -> "subjectAltName"
 */
var decodeExtension = DOOR.decodeExtension;

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  decodeExtensions: decodeExtensions,
  decodeExtension: decodeExtension,
  walkCertReqMessages: walkCertReqMessages,
  walkCertTemplate: walkCertTemplate,
  certReqMessagesSchema: CERT_REQ_MESSAGES,
};
