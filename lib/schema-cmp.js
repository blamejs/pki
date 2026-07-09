// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.cmp
 * @nav        Schema
 * @title      CMP
 * @order      200
 * @slug       cmp
 *
 * @intro
 *   Certificate Management Protocol handling per RFC 9810 (which obsoletes
 *   RFC 4210 and RFC 9480). `parse` decodes a `PKIMessage` — the protected
 *   transport envelope CMP enrollment, revocation, confirmation, and support
 *   exchanges ride — into its header (version, sender / recipient
 *   GeneralNames including the NULL-DN anonymous form, nonces, transaction
 *   id, free text, general info), its body, its protection bits, and its
 *   extra certificates.
 *
 *   The body is a 27-arm tagged CHOICE: certificate-request arms (`ir`,
 *   `cr`, `kur`, `krr`, `ccr`) are RFC 4211 CertReqMessages decoded by the
 *   CRMF parser; response, revocation, confirmation, error, general-message,
 *   and polling arms decode structurally (an encrypted certificate's
 *   EnvelopedData decodes via the CMS parser); every other defined arm is
 *   recognized and surfaced raw — `nested` messages are never auto-recursed.
 *   Protection is surfaced, not verified: the exact `headerBytes` and
 *   `bodyBytes` wire slices are exposed so an external verifier reconstructs
 *   the virtual ProtectedPart `SEQUENCE { header, body }` and checks the MAC
 *   or signature itself. DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM RFC 9810 CMP PKIMessages — header, 27-arm body (requests
 *   via CRMF, encrypted certs via CMS, the rest structural or raw),
 *   protection inputs surfaced byte-exact for external verification,
 *   fail-closed.
 */

var asn1 = require("./asn1-der.js");
var oid = require("./oid.js");
var schema = require("./schema-engine.js");
var pkix = require("./schema-pkix.js");
var cms = require("./schema-cms.js");
var crmf = require("./schema-crmf.js");
var frameworkError = require("./framework-error.js");

var CmpError = frameworkError.CmpError;
var PemError = frameworkError.PemError;
var NS = pkix.makeNS("cmp", CmpError, oid);
var TAGS = asn1.TAGS;

var OID_IMPLICIT_CONFIRM = oid.byName("implicitConfirm");
var OID_CONFIRM_WAIT_TIME = oid.byName("confirmWaitTime");
var OID_CERT_PROFILE = oid.byName("certProfile");

// ---- leaves -----------------------------------------------------------

// CMP times are GeneralizedTime only (RFC 9810 §5.1.1).
var GENERALIZED_TIME = schema.decode(function (n, ctx) {
  if (n.tagClass !== "universal" || n.tagNumber !== TAGS.GENERALIZED_TIME) {
    throw ctx.E("cmp/bad-time", "CMP times must be GeneralizedTime (RFC 9810 §5.1.1)");
  }
  return asn1.read.time(n);
});

// A PKIFreeText element MUST be a UTF8String (§5.1.1).
var UTF8_TEXT = schema.decode(function (n, ctx) {
  if (n.tagClass !== "universal" || n.tagNumber !== TAGS.UTF8_STRING) {
    throw ctx.E("cmp/bad-freetext", "PKIFreeText elements must be UTF8String (RFC 9810 §5.1.1)");
  }
  return asn1.read.string(n);
});

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String.
var PKI_FREE_TEXT = schema.seqOf(UTF8_TEXT, {
  min: 1, code: "cmp/bad-freetext", what: "PKIFreeText",
  build: function (m) { return m.items.map(function (it) { return it.value; }); },
});

// PKIStatus ::= INTEGER {0..6} (§5.2.3) — a value whitelist, surfaced named.
var PKI_STATUS_NAMES = ["accepted", "grantedWithMods", "rejection", "waiting",
  "revocationWarning", "revocationNotification", "keyUpdateWarning"];
var PKI_STATUS = schema.decode(function (n, ctx) {
  var v = asn1.read.integer(n);
  if (v < 0n || v > 6n) throw ctx.E("cmp/bad-status", "undefined PKIStatus " + v.toString() + " (RFC 9810 §5.2.3)");
  var code = Number(v);
  return { code: code, name: PKI_STATUS_NAMES[code] };
});

// PKIFailureInfo ::= BIT STRING named bits 0..26 (§5.2.3). X.690 §11.2.2:
// a named-bit BIT STRING drops trailing zero bits, so the final carried bit
// must be 1. Bits past 26 are extensible and surface as numeric indexes.
var FAIL_INFO_NAMES = ["badAlg", "badMessageCheck", "badRequest", "badTime", "badCertId",
  "badDataFormat", "wrongAuthority", "incorrectData", "missingTimeStamp", "badPOP",
  "certRevoked", "certConfirmed", "wrongIntegrity", "badRecipientNonce", "timeNotAvailable",
  "unacceptedPolicy", "unacceptedExtension", "addInfoNotAvailable", "badSenderNonce",
  "badCertTemplate", "signerNotTrusted", "transactionIdInUse", "unsupportedVersion",
  "notAuthorized", "systemUnavail", "systemFailure", "duplicateCertReq"];
var PKI_FAILURE_INFO = schema.decode(function (n, ctx) {
  var bs = asn1.read.bitString(n);
  var total = bs.bytes.length * 8 - bs.unusedBits;
  schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (m) { throw ctx.E("cmp/bad-fail-info", m); });
  var bits = [];
  for (var i = 0; i < total; i++) {
    if ((bs.bytes[i >> 3] >> (7 - (i % 8))) & 1) bits.push(i < FAIL_INFO_NAMES.length ? FAIL_INFO_NAMES[i] : i);
  }
  return { bits: bits, raw: bs };
});

// PollRep checkAfter is a delay in seconds — negative poisons scheduling, and
// the value surfaces as an exact number or not at all.
var CHECK_AFTER = schema.decode(function (n, ctx) {
  var v = asn1.read.integer(n);
  if (v < 0n || v > 2147483647n) throw ctx.E("cmp/bad-poll-rep", "checkAfter must be a non-negative delay in seconds (RFC 9810 §5.3.22)");
  return Number(v);
});

// A raw certificate / CRL / publication-info element — surfaced byte-exact for
// downstream parsing, but structurally a universal SEQUENCE: a CMPCertificate
// is a Certificate, and CertificateList / PKIPublicationInfo are SEQUENCEs, so
// a primitive (an INTEGER) or wrong-tag element is not a valid structure and
// rejects rather than handing arbitrary bytes to certificate processing. The
// `code` names the containing structure (a shared leaf cannot know its context).
function rawSequence(code) {
  return schema.decode(function (n, ctx) {
    // A Certificate, CertificateList, and PKIPublicationInfo are each a
    // NON-EMPTY universal SEQUENCE — an empty SEQUENCE (0x30 0x00) has the
    // right tag but is none of them, so require at least one child rather than
    // surface a degenerate structure as certificate/CRL bytes.
    if (!(n.tagClass === "universal" && n.tagNumber === TAGS.SEQUENCE && n.children && n.children.length >= 1)) {
      throw ctx.E(code, "expected a non-empty universal SEQUENCE (Certificate / CertificateList / PKIPublicationInfo)");
    }
    return n.bytes;
  });
}

var GENERAL_NAME = pkix.generalName(NS, { decodeValue: true });
var ALG_ID = pkix.algorithmIdentifier(NS);
var EXTENSIONS = pkix.extensions(NS);

// ---- header ------------------------------------------------------------

// InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }
// (§5.1.1, §5.3.19). Recognized id-it types with a fixed value syntax are
// validated (the CMS signed-attr value-syntax posture); all others surface
// raw with the registry name resolving.
var INFO_TYPE_AND_VALUE = schema.seq([
  schema.field("infoType", schema.oidLeaf()),
  schema.optional("infoValue", schema.any(), { whenAny: true }),
], {
  assert: "sequence", code: "cmp/bad-info-type-and-value", what: "InfoTypeAndValue",
  build: function (m, ctx) {
    var t = m.fields.infoType.value;
    var valueNode = m.fields.infoValue.present ? m.fields.infoValue.value : null;
    if (valueNode !== null) {
      // A recognized id-it value is validated by CONTENT, not just tag: run the
      // strict typed reader so a well-tagged but malformed payload (a non-empty
      // NULL, a GeneralizedTime carrying garbage, an invalid-UTF-8 string)
      // rejects rather than being surfaced as valid CMP.
      if (t === OID_IMPLICIT_CONFIRM) {
        if (!(valueNode.tagClass === "universal" && valueNode.tagNumber === TAGS.NULL)) {
          throw ctx.E("cmp/bad-info-value", "an implicitConfirm value must be NULL (RFC 9810 §5.1.1.1)");
        }
        try { asn1.read.nullValue(valueNode); }
        catch (e) { throw ctx.E("cmp/bad-info-value", "an implicitConfirm value must be an empty NULL (RFC 9810 §5.1.1.1)", e); }
      }
      if (t === OID_CONFIRM_WAIT_TIME) {
        if (!(valueNode.tagClass === "universal" && valueNode.tagNumber === TAGS.GENERALIZED_TIME)) {
          throw ctx.E("cmp/bad-info-value", "a confirmWaitTime value must be a GeneralizedTime (RFC 9810 §5.1.1.2)");
        }
        try { asn1.read.time(valueNode); }
        catch (e) { throw ctx.E("cmp/bad-info-value", "a confirmWaitTime GeneralizedTime is malformed (RFC 9810 §5.1.1.2)", e); }
      }
      if (t === OID_CERT_PROFILE) {
        if (!(valueNode.tagClass === "universal" && valueNode.tagNumber === TAGS.SEQUENCE &&
              valueNode.children && valueNode.children.length >= 1)) {
          throw ctx.E("cmp/bad-info-value", "a certProfile value must be a non-empty SEQUENCE OF UTF8String (RFC 9810 §5.1.1.4)");
        }
        for (var i = 0; i < valueNode.children.length; i++) {
          var el = valueNode.children[i];
          if (!(el.tagClass === "universal" && el.tagNumber === TAGS.UTF8_STRING)) {
            throw ctx.E("cmp/bad-info-value", "a certProfile element must be a UTF8String (RFC 9810 §5.1.1.4)");
          }
          try { asn1.read.string(el); }
          catch (e) { throw ctx.E("cmp/bad-info-value", "a certProfile element must be a valid UTF8String (RFC 9810 §5.1.1.4)", e); }
        }
      }
    }
    return { type: t, name: ctx.oid.name(t) || null, value: valueNode === null ? null : valueNode.bytes };
  },
});

var GENERAL_INFO = schema.seqOf(INFO_TYPE_AND_VALUE, {
  min: 1, code: "cmp/bad-general-info", what: "generalInfo",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// PKIHeader ::= SEQUENCE { pvno, sender, recipient, then EXPLICIT [0]..[8]
// optionals, ascending, at-most-once } (§5.1.1).
var PKI_HEADER = schema.seq([
  schema.field("pvno", pkix.versionReader(NS, { "1": 1, "2": 2, "3": 3 })),
  schema.field("sender", GENERAL_NAME),
  schema.field("recipient", GENERAL_NAME),
  schema.trailing([
    { tag: 0, name: "messageTime", schema: GENERALIZED_TIME, explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 1, name: "protectionAlg", schema: ALG_ID, explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 2, name: "senderKID", schema: schema.octetString(), explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 3, name: "recipKID", schema: schema.octetString(), explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 4, name: "transactionID", schema: schema.octetString(), explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 5, name: "senderNonce", schema: schema.octetString(), explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 6, name: "recipNonce", schema: schema.octetString(), explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 7, name: "freeText", schema: PKI_FREE_TEXT, explicit: true, emptyCode: "cmp/bad-header" },
    { tag: 8, name: "generalInfo", schema: GENERAL_INFO, explicit: true, emptyCode: "cmp/bad-header" },
  ], { minTag: 0, maxTag: 8, unexpectedCode: "cmp/bad-header", orderCode: "cmp/bad-header" }),
], {
  assert: "sequence", code: "cmp/bad-header", what: "PKIHeader",
  build: function (m) {
    var f = m.fields;
    return {
      pvno: f.pvno.value,
      sender: f.sender.value,
      recipient: f.recipient.value,
      messageTime: f.messageTime.present ? f.messageTime.value : null,
      protectionAlg: f.protectionAlg.present ? f.protectionAlg.value.result : null,
      senderKID: f.senderKID.present ? f.senderKID.value : null,
      recipKID: f.recipKID.present ? f.recipKID.value : null,
      transactionID: f.transactionID.present ? f.transactionID.value : null,
      senderNonce: f.senderNonce.present ? f.senderNonce.value : null,
      recipNonce: f.recipNonce.present ? f.recipNonce.value : null,
      freeText: f.freeText.present ? f.freeText.value.result : null,
      generalInfo: f.generalInfo.present ? f.generalInfo.value.result : null,
    };
  },
});

// ---- decoded body arms ---------------------------------------------------

// PKIStatusInfo ::= SEQUENCE { status, statusString OPTIONAL, failInfo OPTIONAL } (§5.2.3).
var PKI_STATUS_INFO = schema.seq([
  schema.field("status", PKI_STATUS),
  schema.optional("statusString", PKI_FREE_TEXT, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.optional("failInfo", PKI_FAILURE_INFO, { whenUniversal: [TAGS.BIT_STRING] }),
], {
  assert: "sequence", code: "cmp/bad-status-info", what: "PKIStatusInfo",
  build: function (m) {
    return {
      status: m.fields.status.value,
      statusString: m.fields.statusString.present ? m.fields.statusString.value.result : null,
      failInfo: m.fields.failInfo.present ? m.fields.failInfo.value : null,
    };
  },
});

// ErrorMsgContent ::= SEQUENCE { pKIStatusInfo, errorCode INTEGER OPTIONAL,
// errorDetails PKIFreeText OPTIONAL } (§5.3.21).
var ERROR_MSG_CONTENT = schema.seq([
  schema.field("pKIStatusInfo", PKI_STATUS_INFO),
  schema.optional("errorCode", schema.integerLeaf(), { whenUniversal: [TAGS.INTEGER] }),
  schema.optional("errorDetails", PKI_FREE_TEXT, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "cmp/bad-error", what: "ErrorMsgContent",
  build: function (m) {
    return {
      pKIStatusInfo: m.fields.pKIStatusInfo.value.result,
      errorCode: m.fields.errorCode.present ? m.fields.errorCode.value : null,
      errorDetails: m.fields.errorDetails.present ? m.fields.errorDetails.value.result : null,
    };
  },
});

// CertStatus ::= SEQUENCE { certHash, certReqId, statusInfo OPTIONAL,
// hashAlg [0] OPTIONAL } (§5.3.18). certReqId accepts the -1 sentinel.
var CERT_STATUS = schema.seq([
  schema.field("certHash", schema.octetString()),
  schema.field("certReqId", schema.integerLeaf()),
  schema.optional("statusInfo", PKI_STATUS_INFO, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.trailing([
    { tag: 0, name: "hashAlg", schema: ALG_ID, explicit: true, emptyCode: "cmp/bad-cert-status" },
  ], { minTag: 0, maxTag: 0, unexpectedCode: "cmp/bad-cert-status", orderCode: "cmp/bad-cert-status" }),
], {
  assert: "sequence", code: "cmp/bad-cert-status", what: "CertStatus",
  build: function (m) {
    return {
      certHash: m.fields.certHash.value,
      certReqId: m.fields.certReqId.value,
      statusInfo: m.fields.statusInfo.present ? m.fields.statusInfo.value.result : null,
      hashAlg: m.fields.hashAlg.present ? m.fields.hashAlg.value.result : null,
    };
  },
});

// CertConfirmContent ::= SEQUENCE OF CertStatus — an EMPTY sequence is legal
// (reject-all, §5.3.18), so no SIZE floor.
var CERT_CONFIRM_CONTENT = schema.seqOf(CERT_STATUS, {
  code: "cmp/bad-cert-status", what: "CertConfirmContent",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// GenMsgContent / GenRepContent ::= SEQUENCE OF InfoTypeAndValue — no SIZE
// bound, empty legal (§5.3.19/.20).
var GEN_MSG_CONTENT = schema.seqOf(INFO_TYPE_AND_VALUE, {
  code: "cmp/bad-info-type-and-value", what: "GenMsgContent",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// RevDetails ::= SEQUENCE { certDetails CertTemplate, crlEntryDetails
// Extensions OPTIONAL } (§5.3.9) — the CertTemplate interior (an IMPLICIT
// TAGS module) is owned by the CRMF parser and walked NS-bound there.
var CERT_TEMPLATE_LEAF = schema.decode(function (n) { return crmf.walkCertTemplate(n); });
var REV_DETAILS = schema.seq([
  schema.field("certDetails", CERT_TEMPLATE_LEAF),
  schema.optional("crlEntryDetails", EXTENSIONS, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "cmp/bad-rev-req", what: "RevDetails",
  build: function (m) {
    return {
      certDetails: m.fields.certDetails.value,
      crlEntryDetails: m.fields.crlEntryDetails.present ? m.fields.crlEntryDetails.value.result : null,
    };
  },
});
var REV_REQ_CONTENT = schema.seqOf(REV_DETAILS, {
  code: "cmp/bad-rev-req", what: "RevReqContent",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// CertId ::= SEQUENCE { issuer GeneralName, serialNumber INTEGER } (RFC 4211).
var CERT_ID = schema.seq([
  schema.field("issuer", GENERAL_NAME),
  schema.field("serialNumber", schema.integerLeaf()),
], {
  assert: "sequence", code: "cmp/bad-rev-rep", what: "CertId",
  build: function (m) {
    return { issuer: m.fields.issuer.value, serialNumber: m.fields.serialNumber.value };
  },
});

// RevRepContent ::= SEQUENCE { status SIZE(1..MAX), revCerts [0] OPTIONAL,
// crls [1] OPTIONAL } (§5.3.10).
var REV_REP_CONTENT = schema.seq([
  schema.field("status", schema.seqOf(PKI_STATUS_INFO, {
    min: 1, code: "cmp/bad-rev-rep", what: "RevRep status",
    build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
  })),
  schema.trailing([
    { tag: 0, name: "revCerts", schema: schema.seqOf(CERT_ID, {
      min: 1, code: "cmp/bad-rev-rep", what: "revCerts",
      build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
    }), explicit: true, emptyCode: "cmp/bad-rev-rep" },
    { tag: 1, name: "crls", schema: schema.seqOf(rawSequence("cmp/bad-rev-rep"), {
      min: 1, code: "cmp/bad-rev-rep", what: "crls",
      build: function (m) { return m.items.map(function (it) { return it.value; }); },
    }), explicit: true, emptyCode: "cmp/bad-rev-rep" },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "cmp/bad-rev-rep", orderCode: "cmp/bad-rev-rep" }),
], {
  assert: "sequence", code: "cmp/bad-rev-rep", what: "RevRepContent",
  build: function (m) {
    return {
      status: m.fields.status.value.result,
      revCerts: m.fields.revCerts.present ? m.fields.revCerts.value.result : null,
      crls: m.fields.crls.present ? m.fields.crls.value.result : null,
    };
  },
});

// EncryptedKey ::= CHOICE { encryptedValue EncryptedValue (deprecated),
// envelopedData [0] EnvelopedData } (§5.2.2). EncryptedKey is imported from
// the RFC 4211 CRMF module, which is IMPLICIT TAGS, so `envelopedData [0]` is
// an IMPLICIT context tag REPLACING the EnvelopedData SEQUENCE tag — the [0]
// node's children ARE the EnvelopedData fields, no inner wrapper. Retag it to
// the universal SEQUENCE the CMS walker expects, exactly as the sibling CRMF
// `encryptedKey [4] EnvelopedData` POP arm does (schema-crmf.js). The
// deprecated encryptedValue arm surfaces RAW — never field-walked, so nothing
// dereferences its optional interior (absent algorithm parameters crash
// consumers that walk it blindly).
var ENCRYPTED_KEY = schema.choice([
  { when: { tagClass: "universal", tagNumber: TAGS.SEQUENCE },
    schema: schema.decode(function (n) { return { encryptedValue: n.bytes }; }) },
  { when: { tagClass: "context", tagNumber: 0 },
    schema: schema.decode(function (n, ctx) {
      var env;
      try { env = cms.walkEnvelopedData(asn1.decode(asn1.sequenceTlv(n))); }
      catch (e) {
        if (e instanceof frameworkError.CmsError) throw e;
        throw ctx.E("cmp/bad-cert-response", "envelopedData [0] must be an IMPLICIT EnvelopedData (RFC 9810 §5.2.2)", e);
      }
      // RFC 9810 §5.2.2 — a CMP EncryptedKey EnvelopedData is addressed to
      // exactly one recipient (the end entity for a delivered cert / key). CMS
      // permits RecipientInfos SET SIZE 1..MAX, so the single-recipient bound is
      // CMP's: more than one recipient is a malformed EncryptedKey.
      if (env.recipientInfos.length !== 1) {
        throw ctx.E("cmp/bad-cert-response", "an EncryptedKey EnvelopedData must contain exactly one RecipientInfo (RFC 9810 §5.2.2)");
      }
      // The ciphertext IS the encrypted certificate / private key here, so an
      // EnvelopedData with no ciphertext to decrypt — absent (detached, CMS
      // permits it) OR present-but-empty — must reject (RFC 9810 §5.2.2/§5.3.4;
      // the same rule the CRMF encryptedKey POP arm enforces).
      var ct = env.encryptedContentInfo.encryptedContent;
      if (ct === null || ct.length === 0) {
        throw ctx.E("cmp/bad-cert-response", "an EncryptedKey envelopedData must carry non-empty attached ciphertext — its encryptedContent is the certificate/key payload (RFC 9810 §5.2.2)");
      }
      return { envelopedData: env };
    }) },
], { code: "cmp/bad-cert-response", what: "EncryptedKey" });

// CertOrEncCert ::= CHOICE { certificate [0], encryptedCert [1] } (§5.3.4).
var CERT_OR_ENC_CERT = schema.choice([
  { when: { tagClass: "context", tagNumber: 0 },
    schema: schema.explicit(0, schema.decode(function (n, ctx) {
      if (!(n.tagClass === "universal" && n.tagNumber === TAGS.SEQUENCE && n.children && n.children.length >= 1)) {
        throw ctx.E("cmp/bad-cert-response", "a certificate [0] must be a CMPCertificate (a non-empty universal SEQUENCE)");
      }
      return { certificate: n.bytes };
    }), { code: "cmp/bad-cert-response" }) },
  { when: { tagClass: "context", tagNumber: 1 },
    schema: schema.explicit(1, ENCRYPTED_KEY, { code: "cmp/bad-cert-response" }) },
], { code: "cmp/bad-cert-response", what: "CertOrEncCert" });

// CertifiedKeyPair ::= SEQUENCE { certOrEncCert, privateKey [0] OPTIONAL,
// publicationInfo [1] OPTIONAL } (§5.3.4).
var CERTIFIED_KEY_PAIR = schema.seq([
  schema.field("certOrEncCert", CERT_OR_ENC_CERT),
  schema.trailing([
    { tag: 0, name: "privateKey", schema: ENCRYPTED_KEY, explicit: true, emptyCode: "cmp/bad-cert-response" },
    { tag: 1, name: "publicationInfo", schema: rawSequence("cmp/bad-cert-response"), explicit: true, emptyCode: "cmp/bad-cert-response" },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "cmp/bad-cert-response", orderCode: "cmp/bad-cert-response" }),
], {
  assert: "sequence", code: "cmp/bad-cert-response", what: "CertifiedKeyPair",
  build: function (m) {
    var out = m.fields.certOrEncCert.value.certificate !== undefined
      ? { certificate: m.fields.certOrEncCert.value.certificate }
      : { encryptedCert: m.fields.certOrEncCert.value };
    out.privateKey = m.fields.privateKey.present ? m.fields.privateKey.value : null;
    out.publicationInfo = m.fields.publicationInfo.present ? m.fields.publicationInfo.value : null;
    return out;
  },
});

// CertResponse ::= SEQUENCE { certReqId INTEGER (the -1 sentinel is legal),
// status PKIStatusInfo, certifiedKeyPair OPTIONAL, rspInfo OPTIONAL } (§5.3.4).
var CERT_RESPONSE = schema.seq([
  schema.field("certReqId", schema.integerLeaf()),
  schema.field("status", PKI_STATUS_INFO),
  schema.optional("certifiedKeyPair", CERTIFIED_KEY_PAIR, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.optional("rspInfo", schema.octetString(), { whenUniversal: [TAGS.OCTET_STRING] }),
], {
  assert: "sequence", code: "cmp/bad-cert-response", what: "CertResponse",
  build: function (m, ctx) {
    var status = m.fields.status.value.result;
    var certifiedKeyPair = m.fields.certifiedKeyPair.present ? m.fields.certifiedKeyPair.value.result : null;
    // RFC 9810 §5.3.4 — only one of the failInfo (in PKIStatusInfo) and
    // certifiedKeyPair fields can be present in a CertResponse: a rejection
    // carries no certificate. Accepting both lets a caller keying off
    // certifiedKeyPair process a certificate from a failed response.
    if (status.failInfo !== null && certifiedKeyPair !== null) {
      throw ctx.E("cmp/bad-cert-response",
        "a CertResponse must not carry both failInfo and certifiedKeyPair (RFC 9810 §5.3.4)");
    }
    // A certifiedKeyPair is present ONLY when the status grants the certificate:
    // accepted (0) or grantedWithMods (1). Any other status — rejection, waiting,
    // the revocation / keyUpdate warnings — denies or defers the request, so a
    // certificate under it is a malformed response even when no explicit failInfo
    // bit is set (a rejection is commonly signalled by status alone). Keying the
    // rule off failInfo presence alone would let a bare-rejection status ship a
    // certificate (RFC 9810 §5.3.4).
    if (certifiedKeyPair !== null && status.status.code !== 0 && status.status.code !== 1) {
      throw ctx.E("cmp/bad-cert-response",
        "a CertResponse certifiedKeyPair is allowed only under a granting status (accepted or grantedWithMods) (RFC 9810 §5.3.4)");
    }
    return {
      certReqId: m.fields.certReqId.value,
      status: status,
      certifiedKeyPair: certifiedKeyPair,
      rspInfo: m.fields.rspInfo.present ? m.fields.rspInfo.value : null,
    };
  },
});

// CertRepMessage ::= SEQUENCE { caPubs [1] OPTIONAL, response SEQUENCE OF
// CertResponse } (§5.3.4) — the optional precedes the required field (the
// x509-version shape). caPubs surface raw: the parser confers NO trust.
var CERT_REP_MESSAGE = schema.seq([
  schema.optional("caPubs", schema.seqOf(rawSequence("cmp/bad-cert-rep"), {
    min: 1, code: "cmp/bad-cert-rep", what: "caPubs",
    build: function (m) { return m.items.map(function (it) { return it.value; }); },
  }), { tag: 1, explicit: true, emptyCode: "cmp/bad-cert-rep" }),
  schema.field("response", schema.seqOf(CERT_RESPONSE, {
    code: "cmp/bad-cert-rep", what: "response",
    build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
  })),
], {
  assert: "sequence", code: "cmp/bad-cert-rep", what: "CertRepMessage",
  build: function (m) {
    return {
      caPubs: m.fields.caPubs.present ? m.fields.caPubs.value.result : null,
      response: m.fields.response.value.result,
    };
  },
});

// PollReqContent / PollRepContent (§5.3.22) — certReqId may be -1.
var POLL_REQ_ENTRY = schema.seq([
  schema.field("certReqId", schema.integerLeaf()),
], {
  assert: "sequence", code: "cmp/bad-poll-req", what: "PollReq entry",
  build: function (m) { return { certReqId: m.fields.certReqId.value }; },
});
var POLL_REQ_CONTENT = schema.seqOf(POLL_REQ_ENTRY, {
  code: "cmp/bad-poll-req", what: "PollReqContent",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});
var POLL_REP_ENTRY = schema.seq([
  schema.field("certReqId", schema.integerLeaf()),
  schema.field("checkAfter", CHECK_AFTER),
  schema.optional("reason", PKI_FREE_TEXT, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "cmp/bad-poll-rep", what: "PollRep entry",
  build: function (m) {
    return {
      certReqId: m.fields.certReqId.value,
      checkAfter: m.fields.checkAfter.value,
      reason: m.fields.reason.present ? m.fields.reason.value.result : null,
    };
  },
});
var POLL_REP_CONTENT = schema.seqOf(POLL_REP_ENTRY, {
  code: "cmp/bad-poll-rep", what: "PollRepContent",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// ---- the 27-arm body dispatch ----------------------------------------------

// Tag -> arm name, verbatim from the PKIXCMP-2023 module (§5.1.2). Every
// defined arm is at minimum recognized; a subset decodes structurally.
var BODY_ARMS = ["ir", "ip", "cr", "cp", "p10cr", "popdecc", "popdecr", "kur", "kup",
  "krr", "krp", "rr", "rp", "ccr", "ccp", "ckuann", "cann", "rann", "crlann",
  "pkiconf", "nested", "genm", "genp", "error", "certConf", "pollReq", "pollRep"];
// Arms carrying RFC 4211 CertReqMessages — walked by the CRMF parser.
var CRMF_ARMS = { 0: true, 2: true, 7: true, 9: true, 13: true };
// Arms with a structural schema here.
var DECODED_ARMS = {
  1: CERT_REP_MESSAGE, 3: CERT_REP_MESSAGE, 8: CERT_REP_MESSAGE, 14: CERT_REP_MESSAGE,
  11: REV_REQ_CONTENT, 12: REV_REP_CONTENT,
  21: GEN_MSG_CONTENT, 22: GEN_MSG_CONTENT,
  23: ERROR_MSG_CONTENT, 24: CERT_CONFIRM_CONTENT,
  25: POLL_REQ_CONTENT, 26: POLL_REP_CONTENT,
};

// The open-CHOICE dispatch: tag -> arm name; walk where a schema exists;
// surface every other defined arm raw as { arm, tag, bytes } — `decoded` is
// ABSENT (not null) on raw arms, so its presence discriminates decoded-empty
// (pkiconf decodes to null) from recognized-undecoded. `nested` [20] is never
// auto-recursed: a self-nesting tower amplifies per-level walk products, so
// the operator re-feeds its bytes to parse explicitly.
var BODY = schema.decode(function (n, ctx) {
  if (n.tagClass !== "context" || !n.children) {
    throw ctx.E("cmp/bad-body", "PKIBody must be a constructed context-tagged CHOICE arm (RFC 9810 §5.1.2)");
  }
  if (n.tagNumber < 0 || n.tagNumber > 26) {
    throw ctx.E("cmp/bad-body", "PKIBody tag [" + n.tagNumber + "] is not a defined arm (RFC 9810 §5.1.2)");
  }
  if (n.children.length !== 1) {
    throw ctx.E("cmp/bad-body", "a PKIBody arm wraps exactly one value (X.690 §8.14)");
  }
  var inner = n.children[0];
  var out = { arm: BODY_ARMS[n.tagNumber], tag: n.tagNumber, bytes: inner.bytes };
  if (CRMF_ARMS[n.tagNumber]) {
    out.decoded = crmf.walkCertReqMessages(inner);
  } else if (DECODED_ARMS[n.tagNumber]) {
    var match = schema.walk(DECODED_ARMS[n.tagNumber], inner, ctx);
    out.decoded = match.result;
  } else if (n.tagNumber === 19) {
    // PKIConfirmContent ::= NULL (§5.3.16).
    if (!(inner.tagClass === "universal" && inner.tagNumber === TAGS.NULL)) {
      throw ctx.E("cmp/bad-pkiconf", "PKIConfirmContent must be NULL (RFC 9810 §5.3.16)");
    }
    // A NULL is well-formed only with empty content (X.690 §8.8.2); the tag check
    // alone would surface a non-empty NULL as a valid confirmation.
    try { asn1.read.nullValue(inner); }
    catch (e) { throw ctx.E("cmp/bad-pkiconf", "PKIConfirmContent must be an empty NULL (RFC 9810 §5.3.16)", e); }
    out.decoded = null;
  }
  return out;
});

// ---- the message envelope -----------------------------------------------------

// PKIProtection ::= BIT STRING — raw bits for the external verifier.
var PROTECTION = schema.decode(function (n, ctx) {
  var bs;
  try { bs = asn1.read.bitString(n); }
  catch (e) { throw ctx.E("cmp/bad-protection", "PKIProtection must be a BIT STRING (RFC 9810 §5.1.3)", e); }
  return { unusedBits: bs.unusedBits, bytes: bs.bytes };
});

// PKIMessage ::= SEQUENCE { header, body, protection [0] OPTIONAL,
// extraCerts [1] OPTIONAL } (§5.1). The build runs the two cross-checks that
// span structures: protection presence <=> protectionAlg presence (§5.1.1,
// both directions), and a certConf hashAlg requires pvno cmp2021(3)
// (§5.3.18). headerBytes / bodyBytes are the exact wire slices protection is
// computed over (as DER-SEQUENCE(headerBytes || bodyBytes)) — surfaced raw,
// never re-encoded.
var PKI_MESSAGE = schema.seq([
  schema.field("header", PKI_HEADER),
  schema.field("body", BODY),
  schema.trailing([
    { tag: 0, name: "protection", schema: PROTECTION, explicit: true, emptyCode: "cmp/bad-protection" },
    { tag: 1, name: "extraCerts", schema: schema.seqOf(rawSequence("cmp/bad-extra-certs"), {
      min: 1, code: "cmp/bad-extra-certs", what: "extraCerts",
      build: function (m) { return m.items.map(function (it) { return it.value; }); },
    }), explicit: true, emptyCode: "cmp/bad-extra-certs" },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "cmp/not-a-pki-message", orderCode: "cmp/not-a-pki-message" }),
], {
  assert: "sequence", code: "cmp/not-a-pki-message", what: "PKIMessage",
  build: function (m, ctx) {
    var header = m.fields.header.value.result;
    var body = m.fields.body.value;
    var protection = m.fields.protection.present ? m.fields.protection.value : null;
    var extraCerts = m.fields.extraCerts.present ? m.fields.extraCerts.value.result : null;
    if ((protection !== null) !== (header.protectionAlg !== null)) {
      throw ctx.E("cmp/protection-alg-mismatch",
        "protection bits and the header protectionAlg must be present together or absent together (RFC 9810 §5.1.1)");
    }
    if (body.arm === "certConf") {
      for (var i = 0; i < body.decoded.length; i++) {
        if (body.decoded[i].hashAlg !== null && header.pvno !== 3) {
          throw ctx.E("cmp/bad-cert-status", "a certConf hashAlg requires CMP version cmp2021(3) (RFC 9810 §5.3.18)");
        }
      }
    }
    // RFC 9810 §5.2.2 / §7 — EnvelopedData is cmp2021(3) syntax: a response
    // carrying it (an encryptedCert or a privateKey in the envelopedData form)
    // under pvno < 3 is a version mismatch, the same version gate the certConf
    // hashAlg rule applies. The deprecated EncryptedValue form is the pre-2021
    // encoding and stays legal at pvno 2. Only the CertRepMessage arms
    // (ip/cp/kup/ccp) carry a `response` array with a certifiedKeyPair.
    if (body.decoded && body.decoded.response) {
      for (var r = 0; r < body.decoded.response.length; r++) {
        var ckp = body.decoded.response[r].certifiedKeyPair;
        if (!ckp) continue;
        var usesEnveloped =
          (ckp.encryptedCert && ckp.encryptedCert.envelopedData !== undefined) ||
          (ckp.privateKey && ckp.privateKey.envelopedData !== undefined);
        if (usesEnveloped && header.pvno !== 3) {
          throw ctx.E("cmp/bad-version", "a response carrying EnvelopedData (encryptedCert or privateKey) requires CMP version cmp2021(3) (RFC 9810 §5.2.2, §7)");
        }
      }
    }
    // RFC 9810 §5.3.12 — a cross-certification response (ccp) reuses the
    // CertRepMessage syntax "with the restriction that no encrypted private key
    // can be sent": cross-certification certifies an existing CA's public key,
    // so there is no key generation and CertifiedKeyPair.privateKey has no
    // meaning. Reject a ccp that carries one rather than surface the key
    // material; the field stays legal in the enrollment responses (ip/cp/kup).
    if (body.arm === "ccp" && body.decoded && body.decoded.response) {
      for (var c = 0; c < body.decoded.response.length; c++) {
        var ckpCcp = body.decoded.response[c].certifiedKeyPair;
        if (ckpCcp && ckpCcp.privateKey !== null) {
          throw ctx.E("cmp/bad-cert-response", "a cross-certification response (ccp) must not carry an encrypted private key (RFC 9810 §5.3.12)");
        }
      }
    }
    return {
      header: header,
      headerBytes: m.fields.header.value.node.bytes,
      body: body,
      bodyBytes: m.fields.body.node.bytes,
      protection: protection,
      extraCerts: extraCerts,
    };
  },
});

/**
 * @primitive  pki.schema.cmp.parse
 * @signature  pki.schema.cmp.parse(input) -> pkiMessage
 * @since      0.1.19
 * @status     experimental
 * @spec       RFC 9810, RFC 9483, RFC 9481
 * @related    pki.schema.parse, pki.schema.crmf.parse, pki.schema.cms.parse
 *
 * Parse a DER `Buffer` or a PEM string into a structured PKIMessage:
 * `{ header, headerBytes, body, bodyBytes, protection, extraCerts }`.
 * `header` carries `pvno` (1..3), `sender` / `recipient` (validated
 * GeneralNames — the anonymous NULL-DN form included), and the optional
 * `messageTime`, `protectionAlg`, `senderKID` / `recipKID`,
 * `transactionID`, `senderNonce` / `recipNonce`, `freeText`, and
 * `generalInfo` (recognized id-it types value-checked: implicitConfirm is
 * NULL, confirmWaitTime a GeneralizedTime, certProfile a sequence of
 * UTF8Strings). `body` is `{ arm, tag, bytes, decoded? }`: request arms
 * (`ir` / `cr` / `kur` / `krr` / `ccr`) decode via the CRMF parser;
 * `ip` / `cp` / `kup` / `ccp` decode to `{ caPubs, response }` (an encrypted
 * certificate's EnvelopedData decodes via the CMS parser; the deprecated
 * EncryptedValue arm and `caPubs` surface raw — the parser confers no
 * trust); `rr` / `rp`, `genm` / `genp`, `error`, `certConf` (an empty
 * confirmation is the legal reject-all), and `pollReq` / `pollRep` decode
 * structurally; `pkiconf` decodes to `null`; every other defined arm —
 * `p10cr` (feed `body.bytes` to `pki.schema.csr.parse`), the
 * challenge-response and announcement arms, and `nested` (never
 * auto-recursed) — surfaces raw with `decoded` absent. `certReqId` values
 * are BigInt and accept the protocol's -1 sentinel.
 *
 * Protection is surfaced, not verified: `protection` carries the raw BIT
 * STRING, and the MAC or signature is computed over the DER of the virtual
 * `ProtectedPart ::= SEQUENCE { header, body }` — reconstruct it as a DER
 * SEQUENCE wrapping exactly `headerBytes || bodyBytes`. `extraCerts` are
 * raw DER certificates and are NOT covered by protection.
 *
 * Throws `CmpError` when the bytes are not a well-formed PKIMessage, and
 * `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var m = pki.schema.cmp.parse(der);
 *   m.body.arm;             // "ir", "ip", "error", ...
 *   m.header.transactionID; // raw Buffer or null
 */
var parse = pkix.makeParser({
  pemLabel: "CMP", PemError: PemError, ErrorClass: CmpError,
  prefix: "cmp", what: "PKIMessage", topSchema: PKI_MESSAGE, ns: NS,
});

/**
 * @primitive  pki.schema.cmp.pemDecode
 * @signature  pki.schema.cmp.pemDecode(text, label?) -> Buffer
 * @since      0.1.19
 * @status     experimental
 * @spec       RFC 7468, RFC 9810
 * @related    pki.schema.cmp.parse
 *
 * Extract the DER bytes from a PEM block (default label `CMP`). CMP is
 * wire-DER over HTTP (RFC 9811) — the PEM path is a convenience for
 * messages that transit text channels.
 *
 * @example
 *   var der = pki.schema.cmp.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "CMP", PemError); }

/**
 * @primitive  pki.schema.cmp.pemEncode
 * @signature  pki.schema.cmp.pemEncode(der, label?) -> string
 * @since      0.1.19
 * @status     experimental
 * @spec       RFC 7468
 * @related    pki.schema.cmp.pemDecode
 *
 * Wrap DER bytes in a PEM envelope (default label `CMP`).
 *
 * @example
 *   var pem = pki.schema.cmp.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "CMP", PemError); }

// A PKIMessage root is a SEQUENCE of 2-4 whose first child (PKIHeader) is a
// SEQUENCE of >= 3 leading with a bare INTEGER (pvno) and whose second child
// (PKIBody) is context-class constructed [0..26]. The one overlap in the
// registry is one-directional: a 2-child PKIMessage with body ir [0] also
// satisfies the shallow ocsp-request probe, so this detector registers AHEAD
// of ocsp-request — while every real OCSPRequest fails here (its tbsRequest
// never leads with a bare INTEGER).
function matches(root) {
  var k = pkix.rootSequenceChildren(root, 2, 4);
  if (!k) return false;
  var header = k[0];
  if (!(schema.isUniversal(header, TAGS.SEQUENCE) && header.children && header.children.length >= 3)) return false;
  var pvno = header.children[0];
  if (!schema.isUniversal(pvno, TAGS.INTEGER)) return false;
  var body = k[1];
  return schema.isContextInRange(body, 0, 26) && !!body.children;
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
};
