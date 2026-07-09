// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.cmp (RFC 9810 PKIMessage parser).
 * Spec-first conformance vectors: a valid PKIMessage parses to the documented
 * shape; every malformed header / body arm / cross-field fault is rejected
 * fail-closed with a typed cmp/* (or leaf asn1/*, or delegated crmf/*) code.
 * A PKIMessage is a protected transport envelope around a 27-arm body CHOICE
 * ([0]..[26]); the request arms are RFC 4211 CertReqMessages delegated to the
 * crmf walkers, EncryptedKey's envelopedData arm to the CMS walker. Protection
 * is computed over the virtual ProtectedPart SEQUENCE { header, body }, so the
 * exact wire slices surface as headerBytes / bodyBytes for the external verify
 * layer — never re-encoded. DER-only, fail-closed.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
// The matches detector is internal dispatch infrastructure (not on the curated
// pki.schema.cmp surface), so reach it via the module directly.
var cmpMod = require("../../lib/schema-cmp");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.cmp.parse(der); }); }
function parse(der) { return pki.schema.cmp.parse(der); }

// ---- OIDs used in fixtures -------------------------------------------
var SHA256 = "2.16.840.1.101.3.4.2.1";
var PBMAC1 = "1.2.840.113549.1.5.14";
var AES256_CBC = "2.16.840.1.101.3.4.1.42";
var RSA_ENC = "1.2.840.113549.1.1.1";
var ID_DATA = "1.2.840.113549.1.7.1";
var IT_IMPLICIT_CONFIRM = "1.3.6.1.5.5.7.4.13";
var IT_CONFIRM_WAIT = "1.3.6.1.5.5.7.4.14";
var IT_CA_CERTS = "1.3.6.1.5.5.7.4.17";
var IT_CERT_PROFILE = "1.3.6.1.5.5.7.4.21";
var REASON_CODE = "2.5.29.21";

// ---- primitive fixture builders --------------------------------------
function algId(o) { return b.sequence([b.oid(o)]); }
function rdn(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
// GeneralName directoryName [4] — EXPLICIT (Name is a CHOICE).
function genName4(cn) { return b.contextConstructed(4, rdn(cn)); }
function nullDn() { return b.contextConstructed(4, b.sequence([])); }
function freeText(strings) { return b.sequence(strings.map(function (s) { return b.utf8(s); })); }
// A canonical named-bits PKIFailureInfo BIT STRING for a set of bit indexes.
function failBits(bits) {
  var maxBit = Math.max.apply(null, bits);
  var bytes = Buffer.alloc((maxBit >> 3) + 1);
  bits.forEach(function (i) { bytes[i >> 3] |= 0x80 >> (i % 8); });
  return b.bitString(bytes, 7 - (maxBit % 8));
}
function pkiStatusInfo(o) {
  o = o || {};
  var kids = [b.integer(o.status !== undefined ? o.status : 2)];
  if (o.strings) kids.push(freeText(o.strings));
  if (o.failBitsRaw) kids.push(o.failBitsRaw);
  else if (o.failBits) kids.push(failBits(o.failBits));
  return b.sequence(kids);
}
function itv(oidStr, valueDer) {
  var kids = [b.oid(oidStr)];
  if (valueDer) kids.push(valueDer);
  return b.sequence(kids);
}
function pkiHeader(o) {
  o = o || {};
  if (o.rawKids) return b.sequence(o.rawKids);
  var kids = [
    b.integer(o.pvno !== undefined ? o.pvno : 2),
    o.sender || nullDn(),
    o.recipient || genName4("CA"),
  ];
  if (o.messageTime) kids.push(b.explicit(0, o.messageTime));
  if (o.protectionAlg) kids.push(b.explicit(1, o.protectionAlg));
  if (o.senderKID) kids.push(b.explicit(2, b.octetString(o.senderKID)));
  if (o.recipKID) kids.push(b.explicit(3, b.octetString(o.recipKID)));
  if (o.transactionID) kids.push(b.explicit(4, b.octetString(o.transactionID)));
  if (o.senderNonce) kids.push(b.explicit(5, b.octetString(o.senderNonce)));
  if (o.recipNonce) kids.push(b.explicit(6, b.octetString(o.recipNonce)));
  if (o.freeText) kids.push(b.explicit(7, freeText(o.freeText)));
  if (o.generalInfo) kids.push(b.explicit(8, b.sequence(o.generalInfo)));
  if (o.extraRaw) kids.push(o.extraRaw);
  return b.sequence(kids);
}
function body(tag, inner) { return b.explicit(tag, inner); }
function pkiMessage(o) {
  o = o || {};
  var kids = [o.header || pkiHeader(), o.body];
  if (o.protection) kids.push(b.explicit(0, o.protection));
  if (o.extraCerts) kids.push(b.explicit(1, b.sequence(o.extraCerts)));
  if (o.extraRaw) kids.push(o.extraRaw);
  return b.sequence(kids);
}
var ERROR_BODY = body(23, b.sequence([pkiStatusInfo({ status: 2 })]));
function minimalMessage(o) {
  o = o || {};
  return pkiMessage({ header: o.header || pkiHeader(o.headerOpts || {}), body: o.body || ERROR_BODY, protection: o.protection, extraCerts: o.extraCerts, extraRaw: o.extraRaw });
}
// A minimal one-message CertReqMessages (crmf) with certReqId 0.
var CERT_REQ_MESSAGES = b.sequence([b.sequence([b.sequence([b.integer(0), b.sequence([b.explicit(5, rdn("req.example"))])])])]);
// A raw stand-in "certificate" (surfaced raw — never parsed here).
var RAW_CERT = b.sequence([b.oid("2.5.4.3"), b.utf8("not-a-real-cert")]);
var RAW_CRL = b.sequence([b.oid("2.5.4.3"), b.utf8("not-a-real-crl")]);
// A minimal EnvelopedData (one ktri recipient) for the encryptedCert arm — kept
// as its field array so both the universal SEQUENCE form and the IMPLICIT [0]
// context-constructed form (EncryptedKey.envelopedData [0], imported from the
// RFC 4211 IMPLICIT-TAGS module, replaces the SEQUENCE tag with [0]) are built
// from the same fields.
var ENVELOPED_FIELDS = [
  b.integer(0),
  b.set([b.sequence([
    b.integer(0),
    b.sequence([rdn("CA"), b.integer(9)]),
    algId(RSA_ENC),
    b.octetString(Buffer.alloc(32, 6)),
  ])]),
  b.sequence([b.oid(ID_DATA), b.sequence([b.oid(AES256_CBC), b.octetString(Buffer.alloc(16, 4))]),
              b.contextPrimitive(0, Buffer.alloc(48, 5))]),
];
var ENVELOPED = b.sequence(ENVELOPED_FIELDS);
function implicitEnveloped() { return b.contextConstructed(0, Buffer.concat(ENVELOPED_FIELDS)); }
function certStatus(o) {
  o = o || {};
  var kids = [b.octetString(o.certHash || Buffer.alloc(32, 1)), b.integer(o.certReqId !== undefined ? o.certReqId : 0)];
  if (o.statusInfo) kids.push(o.statusInfo);
  if (o.hashAlg) kids.push(b.explicit(0, o.hashAlg));
  if (o.omitCertReqId) kids = [b.octetString(o.certHash || Buffer.alloc(32, 1))];
  return b.sequence(kids);
}
function certResponse(o) {
  o = o || {};
  var kids = [b.integer(o.certReqId !== undefined ? o.certReqId : 0)];
  if (o.omitStatus !== true) kids.push(o.status || pkiStatusInfo({ status: 0 }));
  if (o.certifiedKeyPair) kids.push(o.certifiedKeyPair);
  if (o.rspInfo) kids.push(b.octetString(o.rspInfo));
  return b.sequence(kids);
}
function certRepMessage(o) {
  o = o || {};
  var kids = [];
  if (o.caPubs) kids.push(b.explicit(1, b.sequence(o.caPubs)));
  kids.push(b.sequence(o.responses || []));
  return b.sequence(kids);
}
function revDetails(o) {
  o = o || {};
  var tpl = o.certDetails || b.sequence([implicitInt(1, 7), b.contextConstructed(3, Buffer.concat([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("I")])])]))]);
  var kids = [tpl];
  if (o.crlEntryDetails) kids.push(o.crlEntryDetails);
  return b.sequence(kids);
}
function implicitInt(tag, n) { return b.contextPrimitive(tag, pki.asn1.decode(b.integer(n)).content); }
function reasonCodeExts() {
  return b.sequence([b.sequence([b.oid(REASON_CODE), b.octetString(b.enumerated(1))])]);
}

// ---- ACCEPT: envelope + header ----------------------------------------
function testAcceptMinimalError() {
  var header = pkiHeader({});
  var der = pkiMessage({ header: header, body: ERROR_BODY });
  check("minimal error message parses", parseCode(der) === "NO-THROW");
  var m = parse(der);
  check("pvno surfaced", m.header.pvno === 2);
  check("NULL-DN sender accepted (directoryName [4], empty DN)", m.header.sender.tagNumber === 4);
  check("arm/tag surfaced", m.body.arm === "error" && m.body.tag === 23);
  check("decoded error status named", m.body.decoded.pKIStatusInfo.status.name === "rejection");
  check("headerBytes is the exact wire slice", m.headerBytes.equals(header));
  check("bodyBytes is the exact wire slice", m.bodyBytes.equals(ERROR_BODY));
  check("protection null when absent", m.protection === null && m.extraCerts === null);
}

function testAcceptFullHeader() {
  var header = pkiHeader({
    pvno: 3,
    sender: genName4("EE"),
    messageTime: b.generalizedTime(new Date("2026-07-08T00:00:00Z")),
    protectionAlg: algId(PBMAC1),
    senderKID: Buffer.alloc(8, 1),
    transactionID: Buffer.alloc(16, 2),
    senderNonce: Buffer.alloc(16, 3),
    recipNonce: Buffer.alloc(16, 4),
    freeText: ["hello", "world"],
    generalInfo: [itv(IT_IMPLICIT_CONFIRM, b.nullValue())],
  });
  var der = pkiMessage({ header: header, body: ERROR_BODY, protection: b.bitString(Buffer.alloc(32, 9), 0) });
  var m = parse(der);
  check("full header: pvno 3", m.header.pvno === 3);
  check("full header: messageTime is a Date", m.header.messageTime instanceof Date);
  check("full header: protectionAlg resolves", m.header.protectionAlg.name === "pbmac1");
  check("full header: senderKID raw", m.header.senderKID.equals(Buffer.alloc(8, 1)));
  check("full header: transactionID raw", m.header.transactionID.equals(Buffer.alloc(16, 2)));
  check("full header: nonces raw", m.header.senderNonce.length === 16 && m.header.recipNonce.length === 16);
  check("full header: freeText strings", JSON.stringify(m.header.freeText) === JSON.stringify(["hello", "world"]));
  check("full header: generalInfo implicitConfirm resolves", m.header.generalInfo[0].name === "implicitConfirm");
  check("protection pair accepted (alg + bits)", m.protection.bytes.length === 32 && m.header.protectionAlg.oid === PBMAC1);

  // pvno 1 is inside the accept range (the verify layer narrows it, not parse).
  check("pvno 1 accepted", parse(minimalMessage({ headerOpts: { pvno: 1 } })).header.pvno === 1);

  // recipKID [3] is surfaced raw alongside senderKID [2].
  var kidHeader = pkiHeader({ senderKID: Buffer.alloc(8, 1), recipKID: Buffer.alloc(8, 2) });
  var km = parse(pkiMessage({ header: kidHeader, body: ERROR_BODY }));
  check("recipKID surfaced raw", km.header.recipKID.equals(Buffer.alloc(8, 2)) && km.header.senderKID.equals(Buffer.alloc(8, 1)));

  // certProfile id-it value: a non-empty SEQUENCE OF UTF8String is accepted and
  // surfaced raw (§5.1.1.4).
  var certProfile = b.sequence([b.utf8("profile-a"), b.utf8("profile-b")]);
  var cpAccept = parse(pkiMessage({ header: pkiHeader({ generalInfo: [itv(IT_CERT_PROFILE, certProfile)] }), body: ERROR_BODY }));
  check("certProfile SEQ OF UTF8String accepted", cpAccept.header.generalInfo[0].name === "certProfile" && Buffer.isBuffer(cpAccept.header.generalInfo[0].value));

  // errorCode / errorDetails surface their decoded values.
  var errFull = parse(minimalMessage({ body: body(23, b.sequence([pkiStatusInfo({ status: 2, strings: ["denied"] }), b.integer(42), freeText(["see log"])])) }));
  check("error statusString / errorCode / errorDetails decoded",
        errFull.body.decoded.pKIStatusInfo.statusString[0] === "denied" &&
        errFull.body.decoded.errorCode === 42n &&
        errFull.body.decoded.errorDetails[0] === "see log");

  // confirmWaitTime with a valid GeneralizedTime value is accepted (the reject
  // side is a UTCTime; this proves the accept side is not over-rejecting).
  var cwt = parse(pkiMessage({ header: pkiHeader({ generalInfo: [itv(IT_CONFIRM_WAIT, b.generalizedTime(new Date("2026-07-09T00:00:00Z")))] }), body: ERROR_BODY }));
  check("confirmWaitTime GeneralizedTime accepted", cwt.header.generalInfo[0].name === "confirmWaitTime");

  // A NULL-DN recipient (not just sender) is accepted — anonymity is legal on
  // either endpoint (§5.1.1).
  var nullRecip = parse(pkiMessage({ header: pkiHeader({ sender: genName4("EE"), recipient: nullDn() }), body: ERROR_BODY }));
  check("NULL-DN recipient accepted", nullRecip.header.recipient.tagNumber === 4);
}

// ---- ACCEPT: request arms via the crmf walker ---------------------------
function testAcceptRequestArms() {
  var m = parse(minimalMessage({ body: body(0, CERT_REQ_MESSAGES) }));
  check("ir decodes via crmf", m.body.arm === "ir" && m.body.decoded.messages[0].certReq.certReqId === 0n);
  check("ir bodyBytes equals the [n] TLV", m.bodyBytes.equals(body(0, CERT_REQ_MESSAGES)));
  [[2, "cr"], [7, "kur"], [9, "krr"], [13, "ccr"]].forEach(function (t) {
    var mm = parse(minimalMessage({ body: body(t[0], CERT_REQ_MESSAGES) }));
    check(t[1] + " shares the CertReqMessages walker", mm.body.arm === t[1] && mm.body.decoded.messages.length === 1);
  });
}

// ---- ACCEPT: CertRepMessage arms ----------------------------------------
function testAcceptCertRep() {
  var ckp = b.sequence([b.explicit(0, RAW_CERT)]);
  var ip = certRepMessage({ caPubs: [RAW_CERT], responses: [certResponse({ certifiedKeyPair: ckp })] });
  var m = parse(minimalMessage({ body: body(1, ip) }));
  check("ip decodes", m.body.arm === "ip");
  check("caPubs raw", m.body.decoded.caPubs.length === 1 && m.body.decoded.caPubs[0].equals(RAW_CERT));
  check("response status accepted", m.body.decoded.response[0].status.status.name === "accepted");
  check("certOrEncCert certificate raw", m.body.decoded.response[0].certifiedKeyPair.certificate.equals(RAW_CERT));

  var cpNeg = certRepMessage({ responses: [certResponse({ certReqId: -1 })] });
  m = parse(minimalMessage({ body: body(3, cpNeg) }));
  check("cp certReqId -1 accepted (p10cr sentinel)", m.body.decoded.response[0].certReqId === -1n);

  // certOrEncCert.encryptedCert [1] is EXPLICIT (CMP module) wrapping an
  // EncryptedKey whose envelopedData [0] is IMPLICIT (CRMF module) — the
  // encoding real CMP responders (OpenSSL/BouncyCastle/EJBCA) emit.
  var encCkp = b.sequence([b.explicit(1, implicitEnveloped())]);
  var cpEnc = certRepMessage({ responses: [certResponse({ certifiedKeyPair: encCkp })] });
  m = parse(minimalMessage({ body: body(3, cpEnc) }));
  check("encryptedCert IMPLICIT envelopedData [0] walks via cms",
        m.body.decoded.response[0].certifiedKeyPair.encryptedCert.envelopedData.recipientInfos.length === 1);
  // The non-conformant EXPLICIT-wrapping form (an inner SEQUENCE inside [0]) is
  // NOT a valid IMPLICIT EnvelopedData and must reject, not silently accept.
  var explicitCkp = b.sequence([b.explicit(1, b.contextConstructed(0, ENVELOPED))]);
  check("EXPLICIT-wrapped envelopedData [0] rejected (not the IMPLICIT form)",
        /^(cmp|cms)\//.test(parseCode(minimalMessage({ body: body(3, certRepMessage({ responses: [certResponse({ certifiedKeyPair: explicitCkp })] })) }))));

  // The deprecated encryptedValue arm surfaces RAW — including the shape whose
  // inner symmAlg has an OID and ABSENT parameters (a consumer that walked it
  // would dereference the absent params; raw surfacing cannot crash).
  var encValue = b.sequence([b.contextConstructed(1, Buffer.concat([algId(AES256_CBC)])), b.bitString(Buffer.alloc(8, 3), 0)]);
  var cpVal = certRepMessage({ responses: [certResponse({ certifiedKeyPair: b.sequence([b.explicit(1, encValue)]) })] });
  m = parse(minimalMessage({ body: body(3, cpVal) }));
  check("deprecated encryptedValue arm surfaces raw, no crash",
        Buffer.isBuffer(m.body.decoded.response[0].certifiedKeyPair.encryptedCert.encryptedValue));

  [[8, "kup"], [14, "ccp"]].forEach(function (t) {
    var rep = certRepMessage({ responses: [certResponse({})] });
    var mm = parse(minimalMessage({ body: body(t[0], rep) }));
    check(t[1] + " shares the CertRepMessage schema", mm.body.arm === t[1] && mm.body.decoded.response.length === 1);
  });

  // The optional CertifiedKeyPair trailing fields + CertResponse.rspInfo.
  var fullCkp = b.sequence([
    b.explicit(0, RAW_CERT),
    b.explicit(0, implicitEnveloped()),   // privateKey [0] EncryptedKey (IMPLICIT envelopedData [0])
    b.explicit(1, b.sequence([b.oid("1.3.6.1.5.5.7.5.1.2")])),   // publicationInfo [1] raw
  ]);
  var fullResp = certRepMessage({ responses: [certResponse({ certifiedKeyPair: fullCkp, rspInfo: Buffer.alloc(6, 0xdd) })] });
  m = parse(minimalMessage({ body: body(1, fullResp) }));
  var ckpOut = m.body.decoded.response[0].certifiedKeyPair;
  check("CertifiedKeyPair privateKey [0] surfaced", ckpOut.privateKey && ckpOut.privateKey.envelopedData.recipientInfos.length === 1);
  check("CertifiedKeyPair publicationInfo [1] surfaced raw", Buffer.isBuffer(ckpOut.publicationInfo));
  check("CertResponse rspInfo surfaced raw", m.body.decoded.response[0].rspInfo.equals(Buffer.alloc(6, 0xdd)));
}

// ---- ACCEPT: revocation arms ---------------------------------------------
function testAcceptRevocation() {
  var rr = b.sequence([revDetails({ crlEntryDetails: reasonCodeExts() })]);
  var m = parse(minimalMessage({ body: body(11, rr) }));
  check("rr decodes", m.body.arm === "rr");
  check("rr certDetails walked by crmf (serialNumber)", m.body.decoded[0].certDetails.serialNumber === 7n);
  check("rr crlEntryDetails decoded", m.body.decoded[0].crlEntryDetails[0].name === "reasonCode");

  var certId = b.sequence([genName4("CA"), b.integer(9)]);
  var rp = b.sequence([
    b.sequence([pkiStatusInfo({ status: 0 })]),
    b.explicit(0, b.sequence([certId])),
    b.explicit(1, b.sequence([RAW_CRL])),
  ]);
  m = parse(minimalMessage({ body: body(12, rp) }));
  check("rp status decoded", m.body.decoded.status[0].status.name === "accepted");
  check("rp revCerts CertId decoded", m.body.decoded.revCerts[0].serialNumber === 9n);
  check("rp crls raw", m.body.decoded.crls[0].equals(RAW_CRL));
}

// ---- ACCEPT: certConf / pkiconf / genm / poll ------------------------------
function testAcceptConfirmAndSupport() {
  var two = b.sequence([
    certStatus({ statusInfo: pkiStatusInfo({ status: 0 }) }),
    certStatus({ hashAlg: algId(SHA256) }),
  ]);
  var m = parse(minimalMessage({ headerOpts: { pvno: 3 }, body: body(24, two) }));
  check("certConf two entries decode", m.body.decoded.length === 2 && m.body.decoded[1].hashAlg.name === "sha256");

  m = parse(minimalMessage({ body: body(24, b.sequence([])) }));
  check("EMPTY certConf legal (reject-all)", m.body.arm === "certConf" && m.body.decoded.length === 0);

  m = parse(minimalMessage({ body: body(24, b.sequence([certStatus({ certReqId: -1 })])) }));
  check("certConf certReqId -1 accepted", m.body.decoded[0].certReqId === -1n);

  m = parse(minimalMessage({ body: body(19, b.nullValue()) }));
  check("pkiconf decodes to null", m.body.arm === "pkiconf" && m.body.decoded === null);

  var genm = b.sequence([itv(IT_CA_CERTS, b.sequence([RAW_CERT])), itv(IT_CERT_PROFILE)]);
  m = parse(minimalMessage({ body: body(21, genm) }));
  check("genm InfoTypeAndValue decodes", m.body.decoded[0].name === "caCerts" && Buffer.isBuffer(m.body.decoded[0].value));
  check("genm bare infoValue is null", m.body.decoded[1].value === null);
  m = parse(minimalMessage({ body: body(22, b.sequence([])) }));
  check("EMPTY genp legal", m.body.decoded.length === 0);

  m = parse(minimalMessage({ body: body(25, b.sequence([b.sequence([b.integer(-1)])])) }));
  check("pollReq certReqId -1 accepted", m.body.decoded[0].certReqId === -1n);
  m = parse(minimalMessage({ body: body(26, b.sequence([b.sequence([b.integer(0), b.integer(5), freeText(["soon"])])])) }));
  check("pollRep checkAfter surfaced", m.body.decoded[0].checkAfter === 5 && m.body.decoded[0].reason[0] === "soon");
}

// ---- ACCEPT: raw arms + extraCerts + protection exactness -------------------
function testAcceptRawArmsAndProtection() {
  [[4, "p10cr"], [5, "popdecc"], [10, "krp"], [15, "ckuann"], [16, "cann"], [20, "nested"]].forEach(function (t) {
    var m = parse(minimalMessage({ body: body(t[0], b.sequence([b.integer(1)])) }));
    check(t[1] + " surfaces {arm, tag, bytes} raw", m.body.arm === t[1] && m.body.tag === t[0] &&
          Buffer.isBuffer(m.body.bytes) && !("decoded" in m.body));
  });

  var m = parse(minimalMessage({ extraCerts: [RAW_CERT, RAW_CRL] }));
  check("extraCerts raw", m.extraCerts.length === 2 && m.extraCerts[0].equals(RAW_CERT));

  var header = pkiHeader({ protectionAlg: algId(PBMAC1) });
  var bodyDer = ERROR_BODY;
  var der = pkiMessage({ header: header, body: bodyDer, protection: b.bitString(Buffer.alloc(20, 7), 0) });
  var mm = parse(der);
  check("protection raw bits surfaced", mm.protection.bytes.equals(Buffer.alloc(20, 7)) && mm.protection.unusedBits === 0);
  // The documented ProtectedPart reconstruction: DER-SEQUENCE(headerBytes || bodyBytes).
  var protectedPart = b.sequence([mm.headerBytes, mm.bodyBytes]);
  check("ProtectedPart reconstruction matches an independent build",
        protectedPart.equals(b.sequence([header, bodyDer])));

  var names = parse(minimalMessage({ body: body(23, b.sequence([pkiStatusInfo({ status: 2, failBits: [1, 9] })])) }));
  check("failInfo names decoded", JSON.stringify(names.body.decoded.pKIStatusInfo.failInfo.bits) === JSON.stringify(["badMessageCheck", "badPOP"]));
  var last = parse(minimalMessage({ body: body(23, b.sequence([pkiStatusInfo({ status: 2, failBits: [26] })])) }));
  check("failInfo bit 26 round-trips", last.body.decoded.pKIStatusInfo.failInfo.bits[0] === "duplicateCertReq");
}

// ---- REJECT: envelope / header ------------------------------------------------
function testRejectHeader() {
  check("pvno 0 rejected", parseCode(minimalMessage({ headerOpts: { pvno: 0 } })) === "cmp/bad-version");
  check("pvno 4 rejected", parseCode(minimalMessage({ headerOpts: { pvno: 4 } })) === "cmp/bad-version");
  var enumHeader = pkiHeader({ rawKids: [b.enumerated(2), nullDn(), genName4("CA")] });
  check("pvno as ENUMERATED rejected at the leaf", /^asn1\//.test(parseCode(pkiMessage({ header: enumHeader, body: ERROR_BODY }))));
  var twoField = pkiHeader({ rawKids: [b.integer(2), nullDn()] });
  check("missing recipient rejected", /^(cmp|asn1)\//.test(parseCode(pkiMessage({ header: twoField, body: ERROR_BODY }))));
  var repeated = pkiHeader({ rawKids: [b.integer(2), nullDn(), genName4("CA"),
    b.explicit(5, b.octetString(Buffer.alloc(4, 1))), b.explicit(5, b.octetString(Buffer.alloc(4, 2)))] });
  check("repeated senderNonce [5] rejected", parseCode(pkiMessage({ header: repeated, body: ERROR_BODY })) === "cmp/bad-header");
  var stray = pkiHeader({ rawKids: [b.integer(2), nullDn(), genName4("CA"), b.explicit(9, b.nullValue())] });
  check("stray [9] header field rejected", parseCode(pkiMessage({ header: stray, body: ERROR_BODY })) === "cmp/bad-header");
  var outOfOrder = pkiHeader({ rawKids: [b.integer(2), nullDn(), genName4("CA"),
    b.explicit(5, b.octetString(Buffer.alloc(4, 1))), b.explicit(4, b.octetString(Buffer.alloc(4, 2)))] });
  check("out-of-order [5]-before-[4] rejected", parseCode(pkiMessage({ header: outOfOrder, body: ERROR_BODY })) === "cmp/bad-header");
  check("messageTime as UTCTime rejected", parseCode(minimalMessage({
    headerOpts: { messageTime: b.utcTime(new Date("2026-07-08T00:00:00Z")) } })) === "cmp/bad-time");
  check("freeText with a PrintableString element rejected", parseCode(pkiMessage({
    header: pkiHeader({ rawKids: [b.integer(2), nullDn(), genName4("CA"), b.explicit(7, b.sequence([b.printable("x")]))] }),
    body: ERROR_BODY })) === "cmp/bad-freetext");
  check("EMPTY freeText rejected", parseCode(pkiMessage({
    header: pkiHeader({ rawKids: [b.integer(2), nullDn(), genName4("CA"), b.explicit(7, b.sequence([]))] }),
    body: ERROR_BODY })) === "cmp/bad-freetext");
  check("EMPTY generalInfo rejected", parseCode(pkiMessage({
    header: pkiHeader({ generalInfo: [] }), body: ERROR_BODY })) === "cmp/bad-general-info");
  check("implicitConfirm with a non-NULL value rejected", parseCode(pkiMessage({
    header: pkiHeader({ generalInfo: [itv(IT_IMPLICIT_CONFIRM, b.integer(1))] }), body: ERROR_BODY })) === "cmp/bad-info-value");
  check("confirmWaitTime with a UTCTime value rejected", parseCode(pkiMessage({
    header: pkiHeader({ generalInfo: [itv(IT_CONFIRM_WAIT, b.utcTime(new Date("2026-07-08T00:00:00Z")))] }), body: ERROR_BODY })) === "cmp/bad-info-value");
  check("certProfile with an empty SEQUENCE rejected", parseCode(pkiMessage({
    header: pkiHeader({ generalInfo: [itv(IT_CERT_PROFILE, b.sequence([]))] }), body: ERROR_BODY })) === "cmp/bad-info-value");
  check("certProfile with a PrintableString element rejected", parseCode(pkiMessage({
    header: pkiHeader({ generalInfo: [itv(IT_CERT_PROFILE, b.sequence([b.printable("x")]))] }), body: ERROR_BODY })) === "cmp/bad-info-value");
  check("sender with an out-of-range GeneralName tag rejected", /^(cmp|asn1)\//.test(parseCode(pkiMessage({
    header: pkiHeader({ rawKids: [b.integer(2), b.contextConstructed(9, b.sequence([])), genName4("CA")] }), body: ERROR_BODY }))));
}

function testRejectEnvelope() {
  check("protection without protectionAlg rejected",
        parseCode(minimalMessage({ protection: b.bitString(Buffer.alloc(8, 1), 0) })) === "cmp/protection-alg-mismatch");
  check("protectionAlg without protection rejected",
        parseCode(minimalMessage({ headerOpts: { protectionAlg: algId(PBMAC1) } })) === "cmp/protection-alg-mismatch");
  var twoInner = Buffer.concat([Buffer.from([0xa0, 0x08]), b.bitString(Buffer.from([1]), 0), b.bitString(Buffer.from([2]), 0)]);
  check("protection wrapper with two inner TLVs rejected", /^cmp\//.test(parseCode(pkiMessage({
    header: pkiHeader({ protectionAlg: algId(PBMAC1) }), body: ERROR_BODY, extraRaw: twoInner }))));
  check("EMPTY extraCerts rejected", parseCode(minimalMessage({ extraCerts: [] })) === "cmp/bad-extra-certs");
  var valid = minimalMessage({});
  check("trailing garbage rejected", parseCode(Buffer.concat([valid, Buffer.from([0x00])])) === "cmp/bad-der");
  var indef = Buffer.concat([Buffer.from([0x30, 0x80]), pkiHeader({}), ERROR_BODY, Buffer.from([0x00, 0x00])]);
  check("indefinite-length root rejected (DER-only, no ber opt)", parseCode(indef) === "cmp/bad-der");
  var five = pkiMessage({ extraRaw: Buffer.concat([b.explicit(0, b.bitString(Buffer.from([1]), 0)), b.explicit(1, b.sequence([RAW_CERT])), b.integer(1)]), body: ERROR_BODY, header: pkiHeader({ protectionAlg: algId(PBMAC1) }) });
  check("a 5th root child rejected", /^cmp\//.test(parseCode(five)));
}

// ---- REJECT: body arms -----------------------------------------------------------
function testRejectBody() {
  check("body tag [27] rejected", parseCode(minimalMessage({ body: b.explicit(27, b.nullValue()) })) === "cmp/bad-body");
  var primitiveBody = pkiMessage({ header: pkiHeader({}), body: b.contextPrimitive(23, Buffer.from([0x05, 0x00])) });
  check("primitive body form rejected", parseCode(primitiveBody) === "cmp/bad-body");
  var twoTlv = Buffer.concat([Buffer.from([0xb7, 0x04]), b.nullValue(), b.nullValue()]);
  check("body wrapper with two inner TLVs rejected", parseCode(pkiMessage({ header: pkiHeader({}), body: twoTlv })) === "cmp/bad-body");

  check("PKIStatus 7 rejected", parseCode(minimalMessage({ body: body(23, b.sequence([pkiStatusInfo({ status: 7 })])) })) === "cmp/bad-status");
  check("error with a stray 4th element rejected", parseCode(minimalMessage({
    body: body(23, b.sequence([pkiStatusInfo({ status: 2 }), b.integer(1), freeText(["d"]), b.nullValue()])) })) === "cmp/bad-error");
  check("failInfo with a trailing zero bit rejected", parseCode(minimalMessage({
    body: body(23, b.sequence([pkiStatusInfo({ status: 2, failBitsRaw: b.bitString(Buffer.from([0x40]), 4) })])) })) === "cmp/bad-fail-info");

  check("CertStatus missing certReqId rejected", parseCode(minimalMessage({
    body: body(24, b.sequence([certStatus({ omitCertReqId: true })])) })) === "cmp/bad-cert-status");
  check("hashAlg + pvno 2 rejected (cross-structure rule)", parseCode(minimalMessage({
    headerOpts: { pvno: 2 }, body: body(24, b.sequence([certStatus({ hashAlg: algId(SHA256) })])) })) === "cmp/bad-cert-status");

  check("EMPTY caPubs rejected", parseCode(minimalMessage({
    body: body(1, b.sequence([b.explicit(1, b.sequence([])), b.sequence([])])) })) === "cmp/bad-cert-rep");
  check("CertResponse missing status rejected", parseCode(minimalMessage({
    body: body(1, certRepMessage({ responses: [certResponse({ omitStatus: true })] })) })) === "cmp/bad-cert-response");
  check("certOrEncCert tag [2] rejected (closed CHOICE)", parseCode(minimalMessage({
    body: body(1, certRepMessage({ responses: [certResponse({ certifiedKeyPair: b.sequence([b.explicit(2, RAW_CERT)]) })] })) })) === "cmp/bad-cert-response");
  // RFC 9810 §5.3.4 — only ONE of failInfo (in PKIStatusInfo) and
  // certifiedKeyPair can be present: a rejection carrying a certificate is a
  // malformed response a caller keying off certifiedKeyPair must not process.
  var failWithCert = certRepMessage({ responses: [certResponse({
    status: pkiStatusInfo({ status: 2, failBits: [2] }),
    certifiedKeyPair: b.sequence([b.explicit(0, RAW_CERT)]),
  })] });
  check("CertResponse with both failInfo and certifiedKeyPair rejected",
        parseCode(minimalMessage({ body: body(1, failWithCert) })) === "cmp/bad-cert-response");
  // The two legal single-arm shapes still parse: a rejection without a cert,
  // and a success with a cert.
  check("CertResponse rejection without a cert accepted", parseCode(minimalMessage({
    body: body(1, certRepMessage({ responses: [certResponse({ status: pkiStatusInfo({ status: 2, failBits: [2] }) })] })) })) === "NO-THROW");
  check("CertResponse success with a cert accepted", parseCode(minimalMessage({
    body: body(1, certRepMessage({ responses: [certResponse({ certifiedKeyPair: b.sequence([b.explicit(0, RAW_CERT)]) })] })) })) === "NO-THROW");

  check("EMPTY rp status rejected", parseCode(minimalMessage({
    body: body(12, b.sequence([b.sequence([])])) })) === "cmp/bad-rev-rep");
  check("EMPTY revCerts rejected", parseCode(minimalMessage({
    body: body(12, b.sequence([b.sequence([pkiStatusInfo({ status: 0 })]), b.explicit(0, b.sequence([]))])) })) === "cmp/bad-rev-rep");
  check("rr certDetails wrong shape rejects with a crmf/* code (NS-bound walker)", /^crmf\//.test(parseCode(minimalMessage({
    body: body(11, b.sequence([b.sequence([b.integer(5)])])) }))));
  check("ir with structurally-invalid CertReqMessages rejects typed crmf/*", /^crmf\//.test(parseCode(minimalMessage({
    body: body(0, b.sequence([])) }))));

  check("negative checkAfter rejected", parseCode(minimalMessage({
    body: body(26, b.sequence([b.sequence([b.integer(0), b.integer(-5)])])) })) === "cmp/bad-poll-rep");
  check("pkiconf wrapping an INTEGER rejected", parseCode(minimalMessage({ body: body(19, b.integer(1)) })) === "cmp/bad-pkiconf");
}

// ---- dispatch / coercion / misc ------------------------------------------------------
function testDispatchAndCoercion() {
  var der = minimalMessage({});
  var routed = pki.schema.parse(der);
  check("schema.parse routes a PKIMessage to cmp", routed.body && routed.body.arm === "error");
  check("all() lists cmp between crmf and ocsp-request", JSON.stringify(pki.schema.all()) ===
        JSON.stringify(["cms", "tsp", "crmf", "cmp", "ocsp-request", "ocsp-response", "pkcs12", "pkcs8", "csr", "attrcert", "attrcert-v1", "crl", "x509"]));

  // The one order-dependent pair: a 2-child PKIMessage with body ir[0]
  // satisfies the shallow ocsp-request probe, so cmp must sit ahead of it.
  var irMsg = pkiMessage({ header: pkiHeader({}), body: body(0, CERT_REQ_MESSAGES) });
  var routedIr = pki.schema.parse(irMsg);
  check("a 2-child ir PKIMessage routes to cmp, not ocsp-request", routedIr.body && routedIr.body.arm === "ir");
  var ocspReq = b.sequence([b.sequence([b.sequence([b.sequence([
    b.sequence([algId(SHA256), b.octetString(Buffer.from([1])), b.octetString(Buffer.from([2])), b.integer(5)])])])])]);
  check("a real OCSPRequest still routes to ocsp-request (cmp.matches false)", cmpMod.matches(pki.asn1.decode(ocspReq)) === false);
  var ocspRouted = pki.schema.parse(ocspReq);
  check("OCSPRequest routing intact", Array.isArray(ocspRouted.requestList));

  check("Uint8Array input parses", parseCode(new Uint8Array(der)) === "NO-THROW");
  var pem = pki.schema.cmp.pemEncode(der);
  check("pemEncode emits the CMP label", pem.indexOf("-----BEGIN CMP-----") === 0);
  check("PEM input parses", parseCode(pem) === "NO-THROW");
  check("pemDecode round-trips", pki.schema.cmp.pemDecode(pem).equals(der));
  check("number input rejected", parseCode(42) === "cmp/bad-input");

  var evil = pkiMessage({ header: pkiHeader({ pvno: 0 }), body: b.explicit(27, b.integer(1)) });
  check("multi-defect fail-closed", /^(cmp|asn1)\//.test(parseCode(evil)));

  check("id-it implicitConfirm OID pinned", pki.oid.name("1.3.6.1.5.5.7.4.13") === "implicitConfirm");
  check("id-it kemCiphertextInfo OID pinned", pki.oid.name("1.3.6.1.5.5.7.4.24") === "kemCiphertextInfo");
  check("passwordBasedMac OID round-trips", pki.oid.name(pki.oid.byName("passwordBasedMac")) === "passwordBasedMac");
  check("dhBasedMac OID pinned", pki.oid.name("1.2.840.113533.7.66.30") === "dhBasedMac");
}

// ---- runner ----------------------------------------------------------
testAcceptMinimalError();
testAcceptFullHeader();
testAcceptRequestArms();
testAcceptCertRep();
testAcceptRevocation();
testAcceptConfirmAndSupport();
testAcceptRawArmsAndProtection();
testRejectHeader();
testRejectEnvelope();
testRejectBody();
testDispatchAndCoercion();

if (require.main === module) console.log("CHECKS " + helpers.getChecks());
module.exports = {};
