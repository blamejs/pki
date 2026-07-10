// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.cms (CMS SignedData parser, RFC 5652 + the §3 ContentInfo
 * envelope). Spec-first conformance vectors, RED-first: every valid CMS parses to
 * the documented shape; every malformed structure is rejected fail-closed with a
 * typed cms/* (or leaf-level asn1/*) error. The parser is an OID-dispatch
 * envelope — ContentInfo reads contentType and structurally decodes only
 * id-signedData, recognizing-and-deferring the other PKCS#7 content types with a
 * precise cms/unsupported-content-type. eContent / signature / signedAttrs bytes
 * are surfaced RAW for external verification.
 *
 * RED baseline: pki.schema.cms.parse is undefined until the parser lands, so every
 * vector throws — the suite drives the build to GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

// ---- OIDs ------------------------------------------------------------
var ID_SIGNED_DATA    = "1.2.840.113549.1.7.2";
var ID_DATA           = "1.2.840.113549.1.7.1";
var ID_ENVELOPED_DATA = "1.2.840.113549.1.7.3";
var ID_SIGNED_ENV     = "1.2.840.113549.1.7.4";
var ID_DIGESTED_DATA  = "1.2.840.113549.1.7.5";
var ID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";
var ID_CT_AUTHDATA    = "1.2.840.113549.1.9.16.1.2";
var ID_CT_TSTINFO     = "1.2.840.113549.1.9.16.1.4"; // a non-id-data eContentType
var CT_ATTR           = "1.2.840.113549.1.9.3";      // id-contentType
var MD_ATTR           = "1.2.840.113549.1.9.4";      // id-messageDigest
var ST_ATTR           = "1.2.840.113549.1.9.5";      // id-signingTime (non-mandatory)
var SHA256            = "2.16.840.1.101.3.4.2.1";
var CN                = "2.5.4.3";

// ---- fixture builders (compose pki.asn1.build) -----------------------
function algId(o) { return b.sequence([b.oid(o)]); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid(CN), b.utf8(cn)])])]); }

// [tag] IMPLICIT SET OF: the context tag replaces the universal SET tag; the
// content is the member TLVs concatenated. DER wants ascending order — sort for
// accept vectors, pass sort:false to build an out-of-order reject vector.
function implicitSetOf(tag, members, opts) {
  var arr = members.slice();
  if (!opts || opts.sort !== false) arr.sort(Buffer.compare);
  return b.contextConstructed(tag, arr.length ? Buffer.concat(arr) : Buffer.alloc(0));
}

// EncapsulatedContentInfo { eContentType, eContent [0] EXPLICIT OCTET STRING OPT }
function encap(typeOid, eContent) {
  var c = [b.oid(typeOid)];
  if (eContent !== null && eContent !== undefined) c.push(b.explicit(0, b.octetString(eContent)));
  return b.sequence(c);
}

// IssuerAndSerialNumber { issuer Name, serialNumber INTEGER }
function iasn(cn, serial) { return b.sequence([name(cn), b.integer(BigInt(serial))]); }
// subjectKeyIdentifier [0] IMPLICIT OCTET STRING (context primitive)
function skid(bytes) { return b.contextPrimitive(0, Buffer.from(bytes)); }

function attribute(typeOid, values) { return b.sequence([b.oid(typeOid), b.set(values)]); }
function contentTypeAttr(oid) { return attribute(CT_ATTR, [b.oid(oid)]); }
function messageDigestAttr(bytes) { return attribute(MD_ATTR, [b.octetString(Buffer.from(bytes))]); }

// SignerInfo { version, sid, digestAlgorithm, signedAttrs [0]?, signatureAlgorithm, signature, unsignedAttrs [1]? }
function signerInfo(o) {
  o = o || {};
  var c = [];
  c.push(o.version !== undefined ? o.version : b.integer(1n));
  c.push(o.sid || iasn("Signer", 7));
  c.push(o.digestAlg || algId(SHA256));
  if (o.signedAttrs) c.push(implicitSetOf(0, o.signedAttrs, { sort: o.signedAttrsSort !== false }));
  c.push(o.sigAlg || algId(SHA256));
  c.push(o.signature || b.octetString(Buffer.from([0xDE, 0xAD, 0xBE, 0xEF])));
  if (o.unsignedAttrs) c.push(implicitSetOf(1, o.unsignedAttrs));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}

// SignedData { version, digestAlgorithms SET, encapContentInfo, certs [0]?, crls [1]?, signerInfos SET }
function signedData(o) {
  o = o || {};
  var c = [];
  c.push(o.version !== undefined ? o.version : b.integer(1n));
  c.push(o.digestAlgs || b.set([]));
  c.push(o.encap || encap(ID_DATA, null));
  if (o.certs) c.push(implicitSetOf(0, o.certs, { sort: o.certsSort !== false }));
  if (o.crls) c.push(implicitSetOf(1, o.crls));
  c.push(o.signers || b.set([]));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}

// ContentInfo { contentType OID, content [0] EXPLICIT }
function contentInfo(typeOid, contentNode) { return b.sequence([b.oid(typeOid), b.explicit(0, contentNode)]); }
function cms(o) { return contentInfo(ID_SIGNED_DATA, signedData(o)); }

// SET (0x31) built in the GIVEN order (no DER sort) — for order-reject vectors.
function rawSet(members) {
  var body = Buffer.concat(members);
  var n = body.length, hdr;
  if (n < 0x80) hdr = Buffer.from([0x31, n]);
  else if (n < 0x100) hdr = Buffer.from([0x31, 0x81, n]);
  else hdr = Buffer.from([0x31, 0x82, (n >> 8) & 0xff, n & 0xff]);
  return Buffer.concat([hdr, body]);
}

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.cms.parse(der); }); }
function parse(der) { return pki.schema.cms.parse(der); }

// ---- ACCEPT vectors --------------------------------------------------
function testAccept() {
  // 2. minimal detached certs-only: v1, empty digestAlgs, encap {id-data, no eContent},
  //    one raw cert in certificates [0], empty signerInfos.
  var certEl = b.sequence([b.oid("1.2.3"), b.integer(1n)]); // a cert-shaped raw element
  var m = parse(cms({ certs: [certEl] }));
  check("certs-only: version 1", m.version === 1);
  check("certs-only: empty digestAlgorithms", Array.isArray(m.digestAlgorithms) && m.digestAlgorithms.length === 0);
  check("certs-only: detached (eContent null)", m.encapContentInfo.eContent === null);
  check("certs-only: one raw certificate", Array.isArray(m.certificates) && m.certificates.length === 1);
  check("certs-only: empty signerInfos", Array.isArray(m.signerInfos) && m.signerInfos.length === 0);

  // 3. attached, one SignerInfo w/ issuerAndSerialNumber, no signedAttrs.
  var eContent = Buffer.from("hello cms", "utf8");
  var a = parse(cms({ encap: encap(ID_DATA, eContent), signers: b.set([signerInfo({})]) }));
  check("attached: raw eContent surfaced", Buffer.isBuffer(a.encapContentInfo.eContent) && a.encapContentInfo.eContent.equals(eContent));
  check("attached: signerInfo sid issuer DN", /Signer/.test(a.signerInfos[0].sid.issuer.dn));
  check("attached: signerInfo serialNumberHex", typeof a.signerInfos[0].sid.serialNumberHex === "string");
  check("attached: no signedAttrs", a.signerInfos[0].signedAttrs === null);
  check("attached: raw signature bytes", Buffer.isBuffer(a.signerInfos[0].signature) && a.signerInfos[0].signature.length === 4);

  // 4. SignerInfo w/ subjectKeyIdentifier [0] -> version 3 (SignedData v3 too, §5.1).
  var s3 = parse(cms({ version: b.integer(3n), signers: b.set([signerInfo({ version: b.integer(3n), sid: skid([1, 2, 3, 4]) })]) }));
  check("skid signer: version 3", s3.signerInfos[0].version === 3);
  check("skid signer: raw key id", Buffer.isBuffer(s3.signerInfos[0].sid.subjectKeyIdentifier));

  // 5. signedAttrs present (content-type + message-digest) -> raw bytes surfaced (leading 0xA0).
  var withAttrs = parse(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([0, 1, 2, 3])] })]) }));
  check("signedAttrs: decoded list length 2", withAttrs.signerInfos[0].signedAttrs.length === 2);
  check("signedAttrs: raw [0] on-wire bytes preserved", withAttrs.signerInfos[0].signedAttrsBytes[0] === 0xA0);

  // 7. detached with signerInfos present.
  var det = parse(cms({ encap: encap(ID_DATA, null), signers: b.set([signerInfo({})]) }));
  check("detached with signers: eContent null", det.encapContentInfo.eContent === null);
}

// ---- ENVELOPE reject vectors -----------------------------------------
function testEnvelope() {
  check("8. top-level SET not SEQUENCE", parseCode(b.set([b.oid(ID_SIGNED_DATA)])) === "cms/not-a-content-info");
  check("9a. envelope 1 child", parseCode(b.sequence([b.oid(ID_SIGNED_DATA)])) === "cms/not-a-content-info");
  check("9b. envelope 3 children", parseCode(b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, signedData({})), b.integer(0n)])) === "cms/not-a-content-info");
  // contentType is a required OID leaf; an INTEGER there is a type confusion the
  // codec catches — a leaf fault surfaces as asn1/* (the documented contract).
  check("10. contentType not an OID -> leaf asn1 fault", parseCode(b.sequence([b.integer(2n), b.explicit(0, signedData({}))])) === "asn1/unexpected-tag");
  check("11. content not [0] EXPLICIT (universal SET)", parseCode(b.sequence([b.oid(ID_SIGNED_DATA), b.set([])])) === "cms/not-a-content-info");
  check("12. content [0] PRIMITIVE not constructed", parseCode(b.sequence([b.oid(ID_SIGNED_DATA), b.contextPrimitive(0, Buffer.from([0]))])) === "cms/not-a-content-info");
}

// ---- CONTENT-TYPE dispatch -------------------------------------------
function testContentType() {
  // id-envelopedData / id-encryptedData are now structurally decoded (promoted out of
  // the deferred set) — a malformed body fails with a structural cms/* code, not unsupported.
  check("13. id-envelopedData now decoded (structural error, not unsupported)", parseCode(contentInfo(ID_ENVELOPED_DATA, b.sequence([b.integer(0n)]))) === "cms/bad-enveloped-data");
  check("14a. id-encryptedData now decoded (structural error, not unsupported)", parseCode(contentInfo(ID_ENCRYPTED_DATA, b.sequence([b.integer(0n)]))) === "cms/bad-encrypted-data");
  check("14b. id-digestedData -> unsupported", parseCode(contentInfo(ID_DIGESTED_DATA, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
  check("14c. id-signedAndEnvelopedData -> unsupported", parseCode(contentInfo(ID_SIGNED_ENV, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
  check("14d. id-ct-authData now decoded (structural error, not unsupported)", parseCode(contentInfo(ID_CT_AUTHDATA, b.sequence([b.integer(0n)]))) === "cms/bad-auth-data");
  check("15. unknown OID -> unknown-content-type", parseCode(contentInfo("1.2.3.4.5", b.sequence([b.integer(0n)]))) === "cms/unknown-content-type");
}

// ---- VERSION + sid rules ---------------------------------------------
function testVersion() {
  check("16. SignedData version 2 (not in {1,3,4,5})", parseCode(cms({ version: b.integer(2n) })) === "cms/bad-version");
  check("17. sid=iasn but SignerInfo version 3", parseCode(cms({ signers: b.set([signerInfo({ version: b.integer(3n), sid: iasn("S", 1) })]) })) === "cms/bad-signer-version");
  check("18. sid=skid but SignerInfo version 1", parseCode(cms({ signers: b.set([signerInfo({ version: b.integer(1n), sid: skid([9, 9]) })]) })) === "cms/bad-signer-version");
  check("27. sid neither arm (an INTEGER)", parseCode(cms({ signers: b.set([signerInfo({ sid: b.integer(5n) })]) })) === "cms/bad-signer-identifier");
}

// ---- SET-OF ordering + strict DER ------------------------------------
function testSetOrder() {
  // 19. digestAlgorithms members in DESCENDING DER order -> reject.
  var a1 = algId(SHA256);          // 2.16.840...
  var a2 = algId("1.2.840.113549.1.1.11"); // sha256WithRSA — different bytes
  var lo = Buffer.compare(a1, a2) < 0 ? a1 : a2;
  var hi = Buffer.compare(a1, a2) < 0 ? a2 : a1;
  var descSet = rawSet([hi, lo]); // wrong order
  check("19. digestAlgorithms descending order rejected", parseCode(cms({ digestAlgs: descSet })) !== "NO-THROW");

  // 23. indefinite-length outer SEQUENCE (0x30 0x80 ... 0x00 0x00).
  check("23. indefinite length rejected", parseCode(Buffer.from([0x30, 0x80, 0x00, 0x00])) !== "NO-THROW");

  // 24. valid CMS + one trailing byte.
  var good = cms({ certs: [b.sequence([b.oid("1.2.3"), b.integer(1n)])] });
  check("24. trailing byte rejected", parseCode(Buffer.concat([good, Buffer.from([0x00])])) !== "NO-THROW");
}

// ---- DISPATCH (orchestrator) -----------------------------------------
function testDispatch() {
  var built = cms({ encap: encap(ID_DATA, Buffer.from("x")), signers: b.set([signerInfo({})]) });
  var m = pki.schema.parse(built);
  check("33. complete SignedData routes to cms member", m && m.signerInfos && m.encapContentInfo && m.validity === undefined);
  check("33b. all() lists cms", pki.schema.all().indexOf("cms") !== -1);
  // 36. input coercion via the shared parse-entry.
  check("36. non-buffer input -> cms/bad-input", parseCode(42) === "cms/bad-input");
}

// ---- SIGNED-ATTRS content (§11) + raw exactness + more rejects ------
function testCompleteness() {
  // 6. a non-id-data eContentType is surfaced raw; it forces SignedData v3 (§5.1)
  //    and requires signedAttrs on each signer (§5.3).
  var m6 = parse(cms({ version: b.integer(3n), encap: encap(ID_CT_TSTINFO, Buffer.from("tst")),
    signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_CT_TSTINFO), messageDigestAttr([1])] })]) }));
  check("6. non-id-data eContentType surfaced", m6.encapContentInfo.eContentType === ID_CT_TSTINFO);
  check("6b. non-id-data forces SignedData v3", m6.version === 3);

  // 6c. non-id-data eContentType but a signer WITHOUT signedAttrs -> reject (§5.3).
  check("6c. non-id-data without signedAttrs rejected",
    parseCode(cms({ version: b.integer(3n), encap: encap(ID_CT_TSTINFO, Buffer.from("t")), signers: b.set([signerInfo({})]) })) === "cms/missing-signed-attrs");

  // 5b/5c. signedAttrs present but missing a mandatory attribute -> reject (§11).
  check("5b. signedAttrs missing content-type rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [messageDigestAttr([1])] })]) })) === "cms/missing-content-type");
  check("5c. signedAttrs missing message-digest rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA)] })]) })) === "cms/missing-message-digest");

  // 16b. SignedData version inconsistent with contents (v1 but a v3 signer) -> reject (§5.1).
  check("16b. SignedData version vs contents rejected",
    parseCode(cms({ version: b.integer(1n), signers: b.set([signerInfo({ version: b.integer(3n), sid: skid([1]) })]) })) === "cms/bad-version");

  // 20. signerInfos out of ascending DER order -> reject.
  var siA = signerInfo({ sid: iasn("Alice", 1) }), siB = signerInfo({ sid: iasn("Bob", 2) });
  var sHi = Buffer.compare(siA, siB) < 0 ? siB : siA, sLo = Buffer.compare(siA, siB) < 0 ? siA : siB;
  check("20. signerInfos descending order rejected", parseCode(cms({ signers: rawSet([sHi, sLo]) })) !== "NO-THROW");

  // 21. signedAttrs [0] members not DER-sorted -> reject (§5.4 DER-of-signedAttrs).
  var ctA = contentTypeAttr(ID_DATA), mdA = messageDigestAttr([1, 2, 3]);
  var aHi = Buffer.compare(ctA, mdA) < 0 ? mdA : ctA, aLo = Buffer.compare(ctA, mdA) < 0 ? ctA : mdA;
  check("21. signedAttrs not DER-sorted rejected", parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [aHi, aLo], signedAttrsSort: false })]) })) !== "NO-THROW");

  // 22. constructed (BER) OCTET STRING as eContent -> reject (primitive-only).
  var constructedOS = Buffer.from([0x24, 0x03, 0x04, 0x01, 0x41]);
  check("22. constructed eContent rejected", parseCode(cms({ encap: b.sequence([b.oid(ID_DATA), b.explicit(0, constructedOS)]) })) !== "NO-THROW");

  // 25. duplicate content-type signed attribute -> reject.
  check("25. duplicate content-type attr rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), contentTypeAttr(ID_CT_TSTINFO), messageDigestAttr([1])] })]) })) === "cms/duplicate-content-type");

  // 26. content-type attribute multi-valued -> reject.
  check("26. content-type multi-valued rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [attribute(CT_ATTR, [b.oid(ID_DATA), b.oid(ID_CT_TSTINFO)]), messageDigestAttr([1])] })]) })) === "cms/bad-content-type-attr");

  // 26b. content-type value is not an OBJECT IDENTIFIER (§11.1 syntax) -> reject.
  check("26b. content-type value not an OID rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [attribute(CT_ATTR, [b.integer(5n)]), messageDigestAttr([1])] })]) })) === "cms/bad-content-type-attr");

  // 26c. message-digest value is not an OCTET STRING (§11.2 syntax) -> reject.
  check("26c. message-digest value not an OCTET STRING rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), attribute(MD_ATTR, [b.oid(ID_DATA)])] })]) })) === "cms/bad-message-digest-attr");

  // 26d. content-type value is OID-TAGGED but its payload is malformed (a
  //      truncated base-128 subidentifier: 0x06 0x01 0x80) — the tag passes, the
  //      OID content does not; must reject at parse, not verify (§11.1).
  check("26d. content-type malformed OID payload rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [attribute(CT_ATTR, [Buffer.from([0x06, 0x01, 0x80])]), messageDigestAttr([1])] })]) })) === "cms/bad-content-type-attr");

  // 25b. two instances of the SAME non-mandatory attribute type (signingTime,
  //      each a valid single Time) -> reject; §5.3 forbids any repeated
  //      signed-attribute type.
  check("25b. duplicate signed-attribute type rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]), attribute(ST_ATTR, [b.utcTime(new Date("2026-01-02T03:04:05Z"))]), attribute(ST_ATTR, [b.utcTime(new Date("2026-01-02T03:04:06Z"))])] })]) })) === "cms/duplicate-signed-attr");

  // 25c. content-type signed-attr value is syntactically valid but differs from
  //      the eContentType (id-data content carrying an id-ct-TSTInfo content-type
  //      attribute) -> reject; §5.3 requires the two OIDs to match.
  check("25c. content-type attr != eContentType rejected",
    parseCode(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_CT_TSTINFO), messageDigestAttr([1])] })]) })) === "cms/content-type-mismatch");

  // 28. malformed IssuerAndSerialNumber (issuer not a Name) -> reject.
  check("28. malformed IssuerAndSerial rejected",
    parseCode(cms({ signers: b.set([signerInfo({ sid: b.sequence([b.integer(9n), b.integer(1n)]) })]) })) !== "NO-THROW");

  // 29. SignerInfo missing the required signatureAlgorithm -> reject.
  check("29. SignerInfo missing signatureAlgorithm rejected",
    parseCode(cms({ signers: b.set([signerInfo({ children: [b.integer(1n), iasn("S", 1), algId(SHA256), b.octetString(Buffer.from([1, 2]))] })]) })) !== "NO-THROW");

  // 30. certificates [0] present but PRIMITIVE (IMPLICIT SET must be constructed) -> reject.
  var sd30 = b.sequence([b.integer(1n), b.set([]), encap(ID_DATA, null), b.contextPrimitive(0, Buffer.from([1, 2, 3])), b.set([])]);
  check("30. certificates [0] primitive rejected", parseCode(contentInfo(ID_SIGNED_DATA, sd30)) !== "NO-THROW");

  // 31. eContent surfaced byte-for-byte (not a re-encode).
  var payload = Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]);
  check("31. eContent bytes exact", parse(cms({ encap: encap(ID_DATA, payload), signers: b.set([signerInfo({})]) })).encapContentInfo.eContent.equals(payload));

  // 32. signedAttrsBytes raw [0] TLV + signature bytes exact.
  var sig = Buffer.from([0x11, 0x22, 0x33]);
  var m32 = parse(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([9])], signature: b.octetString(sig) })]) }));
  check("32. signedAttrsBytes is the raw [0] TLV", m32.signerInfos[0].signedAttrsBytes[0] === 0xA0);
  check("32b. signature bytes exact", m32.signerInfos[0].signature.equals(sig));

  // 35. a PKCS#8 key (INTEGER-first) routes to pkcs8, never misclassified as cms.
  var pk8 = b.sequence([b.integer(0n), algId("1.3.101.112"), b.octetString(Buffer.from([1, 2, 3, 4]))]);
  var routed = pki.schema.parse(pk8);
  check("35. pkcs8 routes to pkcs8, not cms", routed.privateKey !== undefined && routed.signerInfos === undefined);

  // 37. multiple defects -> a typed reject, never NO-THROW / raw TypeError.
  var c37 = parseCode(cms({ version: b.integer(2n), signers: b.set([signerInfo({ version: b.integer(3n), sid: iasn("X", 1) })]) }));
  check("37. multi-defect fail-closed (typed reject)", c37 !== "NO-THROW" && c37.indexOf("RAW:") !== 0);
}

// ---- EnvelopedData / EncryptedData (RFC 5652 §6/§8, RFC 5753) ---------
var ID_AES256_CBC = "2.16.840.1.101.3.4.1.42";
var ID_AES256_WRAP = "2.16.840.1.101.3.4.1.45";
var RSA_OID = "1.2.840.113549.1.1.1";
var ID_ECDH = "1.3.132.1.11.1";
var KEM_ORI_OID = "1.2.840.113549.1.9.16.13.3";
var CT = Buffer.from([0x11, 0x22, 0x33, 0x44]);
var EKEY = Buffer.from([0xAA, 0xBB, 0xCC]);
var UKM = Buffer.from([0x5A, 0x5B]);

// EncryptedContentInfo { contentType, contentEncryptionAlgorithm, encryptedContent [0] IMPLICIT OPT }
function eci(ctType, algOid, ciphertext) {
  var c = [b.oid(ctType), algId(algOid)];
  if (ciphertext !== null && ciphertext !== undefined) c.push(b.contextPrimitive(0, ciphertext));
  return b.sequence(c);
}
// KeyTransRecipientInfo (the untagged SEQUENCE arm)
function ktri(o) {
  o = o || {};
  if (o.children) return b.sequence(o.children);
  return b.sequence([
    o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n),
    o.rid || iasn("Recipient", 9),
    o.keyAlg || algId(RSA_OID),
    o.ekey || b.octetString(EKEY),
  ]);
}
// OriginatorPublicKey [1] IMPLICIT { algorithm, publicKey BIT STRING }
function originatorPublicKey(algOid, pub) { return b.contextConstructed(1, Buffer.concat([algId(algOid), b.bitString(Buffer.from(pub), 0)])); }
// rKeyId [0] IMPLICIT RecipientKeyIdentifier { subjectKeyIdentifier OCTET STRING, date? }
function recipKeyId(o) {
  o = o || {};
  var c = [b.octetString(Buffer.from(o.skid || [0x01, 0x02]))];
  if (o.date) c.push(b.generalizedTime(new Date(o.date)));
  if (o.other) c.push(o.other);
  return b.contextConstructed(0, Buffer.concat(c));
}
// OtherKeyAttribute ::= SEQUENCE { keyAttrId OID, keyAttr ANY OPTIONAL } (RFC 5652 §10.2.7)
function otherKeyAttr() { return b.sequence([b.oid("1.2.3.4.5"), b.utf8("attr")]); }
function recipEncKey(o) { o = o || {}; return b.sequence([o.rid || recipKeyId({}), o.ekey || b.octetString(EKEY)]); }
// KeyAgreeRecipientInfo [1] IMPLICIT
function kari(o) {
  o = o || {};
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(3n)];
  c.push(b.explicit(0, o.originator || originatorPublicKey(ID_ECDH, [0x04, 0x01, 0x02]))); // originator [0] EXPLICIT
  if (o.ukm !== undefined && o.ukm !== null) c.push(b.explicit(1, b.octetString(o.ukm)));   // ukm [1] EXPLICIT
  c.push(o.keyAlg || algId(ID_ECDH));
  c.push(b.sequence(o.reks || [recipEncKey({})]));  // recipientEncryptedKeys SEQUENCE OF
  return b.contextConstructed(1, Buffer.concat(c));
}
// KEKRecipientInfo [2] IMPLICIT
function kekri(o) {
  o = o || {};
  var kekid = [b.octetString(Buffer.from(o.keyId || [0x0A, 0x0B]))];
  if (o.date) kekid.push(b.generalizedTime(new Date(o.date)));
  if (o.other) kekid.push(o.other);
  return b.contextConstructed(2, Buffer.concat([
    o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(4n),
    b.sequence(kekid), o.keyAlg || algId(ID_AES256_WRAP), o.ekey || b.octetString(EKEY),
  ]));
}
// PasswordRecipientInfo [3] IMPLICIT
function pwri(o) {
  o = o || {};
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n)];
  if (o.kdf) c.push(b.contextConstructed(0, b.oid(o.kdf)));  // keyDerivationAlgorithm [0] IMPLICIT AlgId
  c.push(o.keyAlg || algId(ID_AES256_WRAP));
  c.push(o.ekey || b.octetString(EKEY));
  return b.contextConstructed(3, Buffer.concat(c));
}
// OtherRecipientInfo [4] IMPLICIT { oriType, oriValue }
function ori(o) { o = o || {}; return b.contextConstructed(4, Buffer.concat([b.oid(o.oriType || KEM_ORI_OID), o.oriValue || b.sequence([b.integer(1n)])])); }
// OriginatorInfo [0] IMPLICIT { certs [0]?, crls [1]? }
function originatorInfo(o) {
  o = o || {};
  var c = [];
  if (o.certs) c.push(implicitSetOf(0, o.certs));
  if (o.crls) c.push(implicitSetOf(1, o.crls));
  return b.contextConstructed(0, Buffer.concat(c));
}
// EnvelopedData { version, originatorInfo [0]?, recipientInfos SET, eci, unprotectedAttrs [1]? }
function envelopedData(o) {
  o = o || {};
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n)];
  if (o.originatorInfo) c.push(o.originatorInfo);
  c.push(o.recipsRaw || b.set(o.recips || [ktri({})]));
  c.push(o.eci || eci(ID_DATA, ID_AES256_CBC, CT));
  if (o.unprotectedAttrs) c.push(implicitSetOf(1, o.unprotectedAttrs));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}
function encryptedData(o) {
  o = o || {};
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n)];
  c.push(o.eci || eci(ID_DATA, ID_AES256_CBC, CT));
  if (o.unprotectedAttrs) c.push(implicitSetOf(1, o.unprotectedAttrs));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}
function envCI(o) { return contentInfo(ID_ENVELOPED_DATA, envelopedData(o)); }
function encCI(o) { return contentInfo(ID_ENCRYPTED_DATA, encryptedData(o)); }

function testEncryptedData() {
  var m = parse(encCI({ version: 0 }));
  check("EncryptedData minimal v0", m.version === 0 && m.recipientInfos === undefined);
  check("EncryptedData eci contentType", m.encryptedContentInfo.contentType === ID_DATA);
  check("EncryptedData encryptedContent raw exact", m.encryptedContentInfo.encryptedContent.equals(CT));
  check("EncryptedData contentEncryptionAlgorithm", m.encryptedContentInfo.contentEncryptionAlgorithm.oid === ID_AES256_CBC);
  check("EncryptedData detached (null ct)", parse(encCI({ version: 0, eci: eci(ID_DATA, ID_AES256_CBC, null) })).encryptedContentInfo.encryptedContent === null);
  // a NEUTRAL attribute type — the §11 types are misplaced in unprotectedAttrs.
  var mu = parse(encCI({ version: 2, unprotectedAttrs: [attribute(NEUTRAL_ATTR, [b.utf8("x")])] }));
  check("EncryptedData v2 with unprotectedAttrs", mu.version === 2 && mu.unprotectedAttrs.length === 1);
  // version cross-field
  check("EncryptedData v0 WITH unprotectedAttrs rejected", parseCode(encCI({ version: 0, unprotectedAttrs: [attribute(NEUTRAL_ATTR, [b.utf8("x")])] })) === "cms/bad-version");
  check("EncryptedData v2 WITHOUT unprotectedAttrs rejected", parseCode(encCI({ version: 2 })) === "cms/bad-version");
  check("EncryptedData unprotectedAttrs empty SET rejected", parseCode(encCI({ version: 2, children: [b.integer(2n), eci(ID_DATA, ID_AES256_CBC, CT), b.contextConstructed(1, Buffer.alloc(0))] })) === "cms/bad-unprotected-attrs");
}

function testEnvelopedKtri() {
  var m = parse(envCI({ version: 0, recips: [ktri({ version: 0 })] }));
  check("EnvelopedData ktri IAS v0", m.version === 0 && m.recipientInfos.length === 1 && m.recipientInfos[0].type === "ktri");
  check("EnvelopedData ktri rid issuer dn", !!m.recipientInfos[0].rid.issuer.dn);
  check("EnvelopedData ktri encryptedKey raw exact", m.recipientInfos[0].encryptedKey.equals(EKEY));
  // RFC 5652 §6.2.1 — the key-encryption algorithm the encryptedKey must be
  // unwrapped with is part of the recipient surface (rsaEncryption vs RSA-OAEP
  // is invisible without it).
  check("EnvelopedData ktri keyEncryptionAlgorithm surfaced", m.recipientInfos[0].keyEncryptionAlgorithm.oid === RSA_OID);
  var ms = parse(envCI({ version: 2, recips: [ktri({ version: 2, rid: skid([0x33, 0x44]) })] }));
  check("EnvelopedData ktri skid -> ktri v2 + envelope v2", ms.version === 2 && ms.recipientInfos[0].rid.subjectKeyIdentifier.equals(Buffer.from([0x33, 0x44])));
  check("EnvelopedData detached content with recipients", parse(envCI({ version: 0, eci: eci(ID_DATA, ID_AES256_CBC, null) })).encryptedContentInfo.encryptedContent === null);
  // ktri version cross-field
  check("ktri IAS but version 2 rejected", parseCode(envCI({ version: 2, recips: [ktri({ version: 2, rid: iasn("R", 9) })] })) === "cms/bad-recipient-version");
  check("ktri skid but version 0 rejected", parseCode(envCI({ version: 0, recips: [ktri({ version: 0, rid: skid([0x33]) })] })) === "cms/bad-recipient-version");
}

function testEnvelopedOtherArms() {
  var mk = parse(envCI({ version: 2, recips: [kari({ version: 3, ukm: UKM })] }));
  check("EnvelopedData kari v3, envelope v2", mk.version === 2 && mk.recipientInfos[0].type === "kari" && mk.recipientInfos[0].version === 3);
  check("EnvelopedData kari ukm raw exact", mk.recipientInfos[0].ukm.equals(UKM));
  check("EnvelopedData kari recipientEncryptedKeys", mk.recipientInfos[0].recipientEncryptedKeys.length === 1);
  check("EnvelopedData kari ukm absent -> null", parse(envCI({ version: 2, recips: [kari({ version: 3, originator: iasn("Orig", 3) })] })).recipientInfos[0].ukm === null);
  // RFC 5652 §6.2.2 / §10.2.7 — an rKeyId's OtherKeyAttribute is recipient-matching
  // data; surfaced raw when present, null when absent.
  var mko = parse(envCI({ version: 2, recips: [kari({ version: 3, reks: [recipEncKey({ rid: recipKeyId({ other: otherKeyAttr() }) })] })] }));
  check("EnvelopedData kari rKeyId other surfaced raw", mko.recipientInfos[0].recipientEncryptedKeys[0].rid.other.equals(otherKeyAttr()));
  check("EnvelopedData kari rKeyId other absent -> null", mk.recipientInfos[0].recipientEncryptedKeys[0].rid.other === null);
  var mkek = parse(envCI({ version: 2, recips: [kekri({ version: 4, date: "2026-01-01T00:00:00Z" })] }));
  check("EnvelopedData kekri v4, envelope v2", mkek.version === 2 && mkek.recipientInfos[0].type === "kekri");
  // Same rule for a KEKIdentifier's OtherKeyAttribute (§6.2.3 / §10.2.7).
  var mkeko = parse(envCI({ version: 2, recips: [kekri({ version: 4, other: otherKeyAttr() })] }));
  check("EnvelopedData kekri kekid other surfaced raw", mkeko.recipientInfos[0].kekid.other.equals(otherKeyAttr()));
  check("EnvelopedData kekri kekid other absent -> null", mkek.recipientInfos[0].kekid.other === null);
  var mp = parse(envCI({ version: 3, recips: [pwri({ version: 0, kdf: "1.2.840.113549.1.5.12" })] }));
  check("EnvelopedData pwri -> envelope v3", mp.version === 3 && mp.recipientInfos[0].type === "pwri" && mp.recipientInfos[0].keyDerivationAlgorithm.oid === "1.2.840.113549.1.5.12");
  check("EnvelopedData pwri kdf omitted -> null", parse(envCI({ version: 3, recips: [pwri({ version: 0 })] })).recipientInfos[0].keyDerivationAlgorithm === null);
  // an UNRECOGNIZED oriType — a recognized id-ori-kem value is content-validated
  // (see testKemRecipientInfo), so the opaque-surface vector uses a foreign arc.
  var mo = parse(envCI({ version: 3, recips: [ori({ oriType: "1.3.99.1" })] }));
  check("EnvelopedData ori -> envelope v3", mo.version === 3 && mo.recipientInfos[0].type === "ori" && Buffer.isBuffer(mo.recipientInfos[0].oriValue));
  // originatorInfo present forces the version up from 0 to 2 (an extendedCertificate [0]
  // element is neither the v2AttrCert [2] nor the other [3] that would force v3/v4).
  var moi = parse(envCI({ version: 2, originatorInfo: originatorInfo({ certs: [b.contextConstructed(0, name("EmbeddedCert"))] }), recips: [ktri({ version: 0 })] }));
  check("EnvelopedData originatorInfo certs surfaced", moi.originatorInfo.certs.length === 1);
  var mix = parse(envCI({ version: 2, recips: [ktri({ version: 0 }), kari({ version: 3 })] }));
  check("EnvelopedData mixed ktri+kari SET, envelope v2", mix.recipientInfos.length === 2);
}

function testEnvelopedVersionAndStructure() {
  check("Enveloped v0 but kari present rejected", parseCode(envCI({ version: 0, recips: [kari({ version: 3 })] })) === "cms/bad-version");
  check("Enveloped v2 but pwri present rejected", parseCode(envCI({ version: 2, recips: [pwri({ version: 0 })] })) === "cms/bad-version");
  check("kari version 2 (not 3) rejected", parseCode(envCI({ version: 2, recips: [kari({ version: 2 })] })) === "cms/bad-version");
  check("kekri version 3 (not 4) rejected", parseCode(envCI({ version: 2, recips: [kekri({ version: 3 })] })) === "cms/bad-version");
  check("recipientInfos empty SET rejected", parseCode(envCI({ version: 0, recipsRaw: b.set([]) })) === "cms/bad-recipient-infos");
  check("RecipientInfo unknown tag [5] rejected", parseCode(envCI({ version: 0, recipsRaw: b.set([b.contextConstructed(5, Buffer.alloc(0))]) })) === "cms/bad-recipient-info");
  check("RecipientInfo primitive [1] rejected", parseCode(envCI({ version: 0, recipsRaw: b.set([b.contextPrimitive(1, Buffer.from([1]))]) })) === "cms/bad-kari");
  check("ktri missing keyEncryptionAlgorithm rejected", parseCode(envCI({ version: 0, recips: [ktri({ children: [b.integer(0n), iasn("R", 9), b.octetString(EKEY)] })] })).indexOf("cms/") === 0);
  // encryptedContent is [0] IMPLICIT (primitive) — a constructed [0] (BER streamed) is
  // rejected at the codec, proving the implicitOctetString primitive assert (not the
  // EXPLICIT ENCAP_CONTENT_INFO shape, which would double-strip the ciphertext).
  check("encryptedContent constructed [0] rejected", parseCode(encCI({ version: 0, eci: b.sequence([b.oid(ID_DATA), algId(ID_AES256_CBC), b.contextConstructed(0, b.octetString(CT))]) })).indexOf("asn1/") === 0);
  // RAW EXACTNESS: the [0] IMPLICIT content octets ARE the ciphertext, not an inner TLV.
  var raw = parse(encCI({ version: 0, eci: eci(ID_DATA, ID_AES256_CBC, CT) }));
  check("encryptedContent decodes the [0] IMPLICIT content directly (raw exact)", raw.encryptedContentInfo.encryptedContent.equals(CT));

  // empty SET rejects on the three min:1 sites the shared primitive alone doesn't pin.
  check("OriginatorInfo empty certs [0] SET rejected", parseCode(envCI({ version: 2, originatorInfo: originatorInfo({ certs: [] }), recips: [ktri({ version: 0 })] })) === "cms/bad-originator-certs");
  check("OriginatorInfo empty crls [1] SET rejected", parseCode(envCI({ version: 2, originatorInfo: originatorInfo({ crls: [] }), recips: [ktri({ version: 0 })] })) === "cms/bad-originator-crls");
  check("EnvelopedData empty unprotectedAttrs [1] SET rejected", parseCode(envCI({ version: 2, recips: [ktri({ version: 0 })], unprotectedAttrs: [] })) === "cms/bad-unprotected-attrs");

  // the v4 (cert other[3] / crl other[1]) and v3 (v2AttrCert[2]) version branches.
  var otherCert = b.contextConstructed(3, b.sequence([b.integer(1n)]));
  var otherCrl = b.contextConstructed(1, b.sequence([b.integer(1n)]));
  var v2AttrCert = b.contextConstructed(2, b.sequence([b.integer(1n)]));
  check("originatorInfo cert other[3] -> envelope v4", parse(envCI({ version: 4, originatorInfo: originatorInfo({ certs: [otherCert] }), recips: [ktri({ version: 0 })] })).version === 4);
  check("cert other[3] but stated version 2 rejected", parseCode(envCI({ version: 2, originatorInfo: originatorInfo({ certs: [otherCert] }), recips: [ktri({ version: 0 })] })) === "cms/bad-version");
  check("originatorInfo crl other[1] -> envelope v4", parse(envCI({ version: 4, originatorInfo: originatorInfo({ crls: [otherCrl] }), recips: [ktri({ version: 0 })] })).version === 4);
  check("originatorInfo cert v2AttrCert[2] -> envelope v3", parse(envCI({ version: 3, originatorInfo: originatorInfo({ certs: [v2AttrCert] }), recips: [ktri({ version: 0 })] })).version === 3);
}

function testEnvelopedDispatch() {
  var routed = pki.schema.parse(envCI({ version: 0 }));
  check("orchestrator routes EnvelopedData to cms", !!routed.recipientInfos && !!routed.encryptedContentInfo && routed.signerInfos === undefined);
  var routedEnc = pki.schema.parse(encCI({ version: 0 }));
  check("orchestrator routes EncryptedData to cms", routedEnc.recipientInfos === undefined && !!routedEnc.encryptedContentInfo);
  check("authEnvelopedData now decoded (structural error, not unsupported)", parseCode(contentInfo("1.2.840.113549.1.9.16.1.23", b.sequence([b.integer(0n)]))) === "cms/bad-auth-enveloped-data");
  check("EnvelopedData + trailing byte rejected", parseCode(Buffer.concat([envCI({ version: 0 }), Buffer.from([0x00])])) === "cms/bad-der");
}

// ---- AuthenticatedData / AuthEnvelopedData / KEMRecipientInfo ---------
// (RFC 5652 §9, RFC 5083, RFC 9629, RFC 9936, RFC 5084, RFC 8619)
var ID_CT_AUTHENV = "1.2.840.113549.1.9.16.1.23";
var HMAC_SHA256   = "1.2.840.113549.2.9";
var ML_KEM_768    = "2.16.840.1.101.3.4.4.2";
var HKDF_SHA256   = "1.2.840.113549.1.9.16.3.28";
var ID_AES256_GCM = "2.16.840.1.101.3.4.1.46";
var ID_AES256_CCM = "2.16.840.1.101.3.4.1.47";
var CS_ATTR       = "1.2.840.113549.1.9.6";  // id-countersignature
var NEUTRAL_ATTR  = "1.3.99.7.7";            // no §11 placement rule
var MAC12 = Buffer.alloc(12, 0x4D);
var KEMCT_768 = Buffer.alloc(1088, 0x2A);    // ML-KEM-768 ciphertext size (FIPS 203)

// AlgorithmIdentifier WITH a parameters node.
function algIdP(o, params) { return b.sequence([b.oid(o), params]); }
// GCMParameters / CCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 }
function aeadParams(nonceLen, icv) {
  var c = [b.octetString(Buffer.alloc(nonceLen, 0x11))];
  if (icv !== undefined) c.push(b.integer(BigInt(icv)));
  return b.sequence(c);
}
function eciP(ctType, algNode, ciphertext) {
  var c = [b.oid(ctType), algNode];
  if (ciphertext !== null && ciphertext !== undefined) c.push(b.contextPrimitive(0, ciphertext));
  return b.sequence(c);
}
// KEMRecipientInfo ::= SEQUENCE { version(0), rid, kem, kemct OCTET STRING, kdf,
//   kekLength INTEGER (1..65535), ukm [0] EXPLICIT OPT, wrap, encryptedKey } (RFC 9629 §3)
function kemri(o) {
  o = o || {};
  if (o.children) return b.sequence(o.children);
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n)];
  c.push(o.rid || iasn("KemRecipient", 7));
  c.push(o.kem || algId(ML_KEM_768));
  c.push(o.kemct || b.octetString(KEMCT_768));
  c.push(o.kdf || algId(HKDF_SHA256));
  c.push(o.kekLength || b.integer(32n));
  if (o.ukm) c.push(b.explicit(0, b.octetString(o.ukm)));
  if (o.ukmWrongTag) c.push(b.explicit(1, b.octetString(o.ukmWrongTag)));
  c.push(o.wrap || algId(ID_AES256_WRAP));
  c.push(o.ekey || b.octetString(EKEY));
  return b.sequence(c);
}
function oriKem(o) { return ori({ oriValue: kemri(o) }); }
// AuthenticatedData ::= SEQUENCE { version, originatorInfo [0]?, recipientInfos SET,
//   macAlgorithm, digestAlgorithm [1]?, encapContentInfo, authAttrs [2]?, mac, unauthAttrs [3]? }
function authData(o) {
  o = o || {};
  if (o.children) return b.sequence(o.children);
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n)];
  if (o.originatorInfo) c.push(o.originatorInfo);
  c.push(o.recipsRaw || b.set(o.recips || [ktri({})]));
  c.push(o.macAlg || algId(HMAC_SHA256));
  if (o.digestAlg) c.push(b.contextConstructed(1, b.oid(o.digestAlg)));
  c.push(o.encap || encap(ID_DATA, Buffer.from("auth me")));
  if (o.authAttrs) c.push(implicitSetOf(2, o.authAttrs, { sort: o.authAttrsSort !== false }));
  if (o.authAttrsRaw) c.push(o.authAttrsRaw);
  c.push(o.mac || b.octetString(MAC12));
  if (o.unauthAttrs) c.push(implicitSetOf(3, o.unauthAttrs));
  return b.sequence(c);
}
function adCI(o) { return contentInfo(ID_CT_AUTHDATA, authData(o)); }
// AuthEnvelopedData ::= SEQUENCE { version(0), originatorInfo [0]?, recipientInfos SET,
//   authEncryptedContentInfo, authAttrs [1]?, mac, unauthAttrs [2]? } (RFC 5083 §2.1)
function authEnv(o) {
  o = o || {};
  if (o.children) return b.sequence(o.children);
  var c = [o.version !== undefined ? b.integer(BigInt(o.version)) : b.integer(0n)];
  if (o.originatorInfo) c.push(o.originatorInfo);
  c.push(o.recipsRaw || b.set(o.recips || [ktri({})]));
  c.push(o.eci || eciP(ID_DATA, algIdP(ID_AES256_GCM, aeadParams(12)), CT));
  if (o.authAttrs) c.push(implicitSetOf(1, o.authAttrs, { sort: o.authAttrsSort !== false }));
  c.push(o.mac || b.octetString(MAC12));
  if (o.unauthAttrs) c.push(implicitSetOf(2, o.unauthAttrs));
  return b.sequence(c);
}
function aeCI(o) { return contentInfo(ID_CT_AUTHENV, authEnv(o)); }

// ---- SignedData version branches driven by cert/crl element tags (§5.1) ----
function testSignedDataCertCrlVersions() {
  var v1AttrCert = b.contextConstructed(1, b.sequence([b.integer(1n)]));
  var v2AttrCert = b.contextConstructed(2, b.sequence([b.integer(1n)]));
  var otherCert = b.contextConstructed(3, b.sequence([b.integer(1n)]));
  var otherCrl = b.contextConstructed(1, b.sequence([b.integer(1n)]));
  var crl = b.sequence([b.sequence([b.integer(0n)]), algId(SHA256), b.bitString(Buffer.from([1]), 0)]);
  check("SignedData v1AttrCert [1] -> v3", parse(cms({ version: b.integer(3n), certs: [v1AttrCert] })).version === 3);
  check("SignedData v2AttrCert [2] -> v4", parse(cms({ version: b.integer(4n), certs: [v2AttrCert] })).version === 4);
  check("SignedData other cert [3] -> v5", parse(cms({ version: b.integer(5n), certs: [otherCert] })).version === 5);
  check("SignedData other crl [1] -> v5", parse(cms({ version: b.integer(5n), crls: [otherCrl] })).version === 5);
  check("SignedData v1AttrCert stated v1 rejected", parseCode(cms({ version: b.integer(1n), certs: [v1AttrCert] })) === "cms/bad-version");
  check("SignedData other crl stated v1 rejected", parseCode(cms({ version: b.integer(1n), crls: [otherCrl] })) === "cms/bad-version");
  // a CertificateList (universal SEQUENCE) in crls stays v1 and is surfaced raw.
  var mc = parse(cms({ version: b.integer(1n), crls: [crl] }));
  check("SignedData crls CertificateList surfaced raw", mc.crls.length === 1 && mc.crls[0].bytes.equals(crl));
  // two signers in ascending DER order parse green (multi-signer accept).
  var siA = signerInfo({ sid: iasn("Alice", 1) }), siB = signerInfo({ sid: iasn("Bob", 2) });
  var pair = [siA, siB].sort(Buffer.compare);
  check("SignedData two sorted signers accepted", parse(cms({ signers: b.set(pair) })).signerInfos.length === 2);
  // mixed sid arms in one SET: an issuerAndSerialNumber (v1) signer beside a
  // subjectKeyIdentifier (v3) signer; the v3 signer forces SignedData v3
  // (sec. 5.1), so the same pair under a stated v1 rejects.
  var msV1 = signerInfo({ sid: iasn("Alice", 1) });
  var msV3 = signerInfo({ version: b.integer(3n), sid: skid([1, 2, 3, 4]) });
  var msPair = [msV1, msV3].sort(Buffer.compare);
  var msOk = parse(cms({ version: b.integer(3n), signers: b.set(msPair) }));
  check("SignedData mixed iasn+skid signers accepted", msOk.signerInfos.length === 2 &&
    msOk.signerInfos.filter(function (s) { return s.version === 3; }).length === 1);
  check("SignedData mixed signers stated v1 rejected", parseCode(cms({ version: b.integer(1n), signers: b.set(msPair) })) === "cms/bad-version");
}

// ---- CertificateChoices / RevocationInfoChoice are CLOSED tag sets ----
function testCertCrlChoiceClosure() {
  var seqEl = b.sequence([b.integer(1n)]);
  check("certs INTEGER element rejected", parseCode(cms({ certs: [b.integer(7n)] })) === "cms/bad-certificates");
  check("certs context [7] element rejected", parseCode(cms({ certs: [b.contextConstructed(7, seqEl)] })) === "cms/bad-certificates");
  check("certs [3] PRIMITIVE element rejected", parseCode(cms({ certs: [b.contextPrimitive(3, Buffer.from([1]))] })) === "cms/bad-certificates");
  check("crls [0] element rejected", parseCode(cms({ version: b.integer(1n), crls: [b.contextConstructed(0, seqEl)] })) === "cms/bad-crls");
  check("crls [2] element rejected", parseCode(cms({ version: b.integer(1n), crls: [b.contextConstructed(2, seqEl)] })) === "cms/bad-crls");
  check("crls PRIMITIVE [1] element rejected", parseCode(cms({ version: b.integer(1n), crls: [b.contextPrimitive(1, Buffer.from([1]))] })) === "cms/bad-crls");
  // the same closed sets bind OriginatorInfo's buckets (§6.1 uses the same CHOICEs).
  check("OriginatorInfo certs INTEGER rejected", parseCode(envCI({ version: 2, originatorInfo: originatorInfo({ certs: [b.integer(7n)] }), recips: [ktri({ version: 0 })] })) === "cms/bad-originator-certs");
  check("OriginatorInfo crls [0] rejected", parseCode(envCI({ version: 2, originatorInfo: originatorInfo({ crls: [b.contextConstructed(0, seqEl)] }), recips: [ktri({ version: 0 })] })) === "cms/bad-originator-crls");
}

// ---- signedAttrs MUST be DER even when the envelope is BER (§5.3) ----
// Drives the module-level walkSignedData the PKCS#12 public-key-integrity path
// consumes (schema-pkcs12 walks a ber-decoded AuthenticatedSafe through it).
function testDerAttrsUnderBer() {
  var cmsLib = require("../../lib/schema-cms.js");
  var ctA = contentTypeAttr(ID_DATA), mdA = messageDigestAttr([1]);
  var sorted = [ctA, mdA].sort(Buffer.compare);
  // [0] with an INDEFINITE length (A0 80 ... 00 00).
  var indefOuter = Buffer.concat([Buffer.from([0xA0, 0x80]), Buffer.concat(sorted), Buffer.from([0x00, 0x00])]);
  var si1 = b.sequence([b.integer(1n), iasn("S", 1), algId(SHA256), indefOuter, algId(SHA256), b.octetString(Buffer.from([1]))]);
  var sd1 = signedData({ signers: b.set([si1]) });
  var n1 = pki.asn1.decode(sd1, { ber: true });
  check("ber walkSignedData: indefinite [0] signedAttrs rejected",
    code(function () { cmsLib.walkSignedData(n1); }) === "cms/bad-signed-attrs");
  // definite [0] whose INNER attribute TLV is indefinite.
  var indefAttr = Buffer.concat([Buffer.from([0x30, 0x80]), b.oid(CT_ATTR), b.set([b.oid(ID_DATA)]), Buffer.from([0x00, 0x00])]);
  var si2 = b.sequence([b.integer(1n), iasn("S", 1), algId(SHA256),
    b.contextConstructed(0, Buffer.concat([mdA, indefAttr])), algId(SHA256), b.octetString(Buffer.from([1]))]);
  var n2 = pki.asn1.decode(signedData({ signers: b.set([si2]) }), { ber: true });
  check("ber walkSignedData: indefinite INNER attribute rejected",
    code(function () { cmsLib.walkSignedData(n2); }) === "cms/bad-signed-attrs");
  // a fully-DER signedAttrs through the same ber path stays green.
  var si3 = signerInfo({ signedAttrs: [ctA, mdA] });
  var n3 = pki.asn1.decode(signedData({ signers: b.set([si3]) }), { ber: true });
  var ok3 = cmsLib.walkSignedData(n3);
  check("ber walkSignedData: DER signedAttrs accepted", ok3.signerInfos[0].signedAttrs.length === 2);
}

// ---- §11 attribute placement + signing-time syntax + countersignature ----
function testAttrPlacementRules() {
  var st = attribute(ST_ATTR, [b.utcTime(new Date("2026-01-02T03:04:05Z"))]);
  var neutral = attribute(NEUTRAL_ATTR, [b.integer(1n)]);
  // placement rejects: each §11 type outside its allowed set(s).
  check("countersignature in signedAttrs rejected", parseCode(cms({ signers: b.set([signerInfo({
    signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]), attribute(CS_ATTR, [b.sequence([b.integer(1n)])])] })]) })) === "cms/misplaced-attr");
  check("signing-time in unsignedAttrs rejected", parseCode(cms({ signers: b.set([signerInfo({ unsignedAttrs: [st] })]) })) === "cms/misplaced-attr");
  check("content-type in EnvelopedData unprotectedAttrs rejected",
    parseCode(envCI({ version: 2, recips: [ktri({ version: 0 })], unprotectedAttrs: [contentTypeAttr(ID_DATA)] })) === "cms/misplaced-attr");
  check("message-digest in EncryptedData unprotectedAttrs rejected",
    parseCode(encCI({ version: 2, unprotectedAttrs: [messageDigestAttr([1])] })) === "cms/misplaced-attr");
  // signing-time value rules (§11.3): single-valued, Time syntax.
  check("signing-time 2-valued rejected", parseCode(cms({ signers: b.set([signerInfo({
    signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]),
      attribute(ST_ATTR, [b.utcTime(new Date("2026-01-02T03:04:05Z")), b.utcTime(new Date("2026-01-02T03:04:06Z"))])] })]) })) === "cms/bad-signing-time-attr");
  check("signing-time non-Time value rejected", parseCode(cms({ signers: b.set([signerInfo({
    signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]), attribute(ST_ATTR, [b.integer(5n)])] })]) })) === "cms/bad-signing-time-attr");
  var mOk = parse(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]), st] })]) }));
  check("signing-time valid UTCTime accepted", mOk.signerInfos[0].signedAttrs.length === 3);
  var g51 = attribute(ST_ATTR, [b.generalizedTime(new Date("2051-06-07T08:09:10Z"))]);
  var mG = parse(cms({ signers: b.set([signerInfo({ signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]), g51] })]) }));
  check("signing-time post-2049 GeneralizedTime accepted", mG.signerInfos[0].signedAttrs.length === 3);
  // unsignedAttrs surface (a neutral type) + empty-SET rejects.
  var mU = parse(cms({ signers: b.set([signerInfo({ unsignedAttrs: [neutral] })]) }));
  check("unsignedAttrs surfaced", mU.signerInfos[0].unsignedAttrs.length === 1 && mU.signerInfos[0].unsignedAttrs[0].type === NEUTRAL_ATTR);
  check("empty signedAttrs [0] SET rejected", parseCode(cms({ signers: b.set([b.sequence([b.integer(1n), iasn("S", 1), algId(SHA256),
    b.contextConstructed(0, Buffer.alloc(0)), algId(SHA256), b.octetString(Buffer.from([1]))])]) })) === "cms/bad-signed-attrs");
  check("empty unsignedAttrs [1] SET rejected", parseCode(cms({ signers: b.set([b.sequence([b.integer(1n), iasn("S", 1), algId(SHA256),
    algId(SHA256), b.octetString(Buffer.from([1])), b.contextConstructed(1, Buffer.alloc(0))])]) })) === "cms/bad-unsigned-attrs");
}

// ---- countersignature values are SignerInfos with §11.4 binding rules ----
function testCountersignatureValues() {
  // a countersignature's signedAttrs carry message-digest but MUST NOT carry content-type.
  function csValue(o) {
    o = o || {};
    return b.sequence([b.integer(1n), iasn("Countersigner", 3), algId(SHA256),
      implicitSetOf(0, o.signedAttrs || [messageDigestAttr([7])]),
      algId(SHA256), b.octetString(Buffer.from([9, 9]))]);
  }
  var mOk = parse(cms({ signers: b.set([signerInfo({ unsignedAttrs: [attribute(CS_ATTR, [csValue()])] })]) }));
  check("countersignature in unsignedAttrs accepted", mOk.signerInfos[0].unsignedAttrs[0].type === CS_ATTR);
  check("countersignature w/ content-type attr rejected", parseCode(cms({ signers: b.set([signerInfo({
    unsignedAttrs: [attribute(CS_ATTR, [csValue({ signedAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([7])] })])] })]) })) === "cms/misplaced-attr");
  check("countersignature w/o message-digest rejected", parseCode(cms({ signers: b.set([signerInfo({
    unsignedAttrs: [attribute(CS_ATTR, [csValue({ signedAttrs: [attribute(NEUTRAL_ATTR, [b.integer(1n)])] })])] })]) })) === "cms/missing-message-digest");
  var garbage = parseCode(cms({ signers: b.set([signerInfo({ unsignedAttrs: [attribute(CS_ATTR, [b.integer(5n)])] })]) }));
  check("countersignature garbage value rejected (typed)", garbage !== "NO-THROW" && garbage.indexOf("RAW:") !== 0);
  // §11.4 explicitly permits multiple countersignature instances in unsignedAttrs.
  var two = [attribute(CS_ATTR, [csValue()]), attribute(CS_ATTR, [csValue({ signedAttrs: [messageDigestAttr([8])] })])];
  var mTwo = parse(cms({ signers: b.set([signerInfo({ unsignedAttrs: two })]) }));
  check("two countersignature instances accepted", mTwo.signerInfos[0].unsignedAttrs.length === 2);
}

// ---- KEMRecipientInfo (RFC 9629 via ori [4], ML-KEM RFC 9936) ----------
function testKemRecipientInfo() {
  var m = parse(envCI({ version: 3, recips: [oriKem({})] }));
  var r = m.recipientInfos[0];
  check("kemri: envelope v3 + ori surface", m.version === 3 && r.type === "ori" && r.oriType === KEM_ORI_OID);
  check("kemri: version 0", r.kemri.version === 0);
  check("kemri: rid issuerAndSerialNumber", r.kemri.ridType === "issuerAndSerialNumber" && !!r.kemri.rid.issuer.dn);
  check("kemri: kem algorithm surfaced", r.kemri.kem.oid === ML_KEM_768);
  check("kemri: kemct raw exact", r.kemri.kemct.equals(KEMCT_768));
  check("kemri: kdf surfaced", r.kemri.kdf.oid === HKDF_SHA256);
  check("kemri: kekLength 32", r.kemri.kekLength === 32);
  check("kemri: ukm absent -> null", r.kemri.ukm === null);
  check("kemri: wrap surfaced", r.kemri.wrap.oid === ID_AES256_WRAP);
  check("kemri: encryptedKey raw exact", r.kemri.encryptedKey.equals(EKEY));
  var mS = parse(envCI({ version: 3, recips: [oriKem({ rid: skid([0x77]), ukm: UKM })] }));
  check("kemri: skid rid + ukm [0] EXPLICIT", mS.recipientInfos[0].kemri.ridType === "subjectKeyIdentifier" && mS.recipientInfos[0].kemri.ukm.equals(UKM));
  // an unrecognized oriType stays raw-opaque (the ORI extension point).
  var mU = parse(envCI({ version: 3, recips: [ori({ oriType: "1.3.99.1" })] }));
  check("unknown oriType stays raw", Buffer.isBuffer(mU.recipientInfos[0].oriValue) && mU.recipientInfos[0].kemri === null);
  // an unrecognized kem/wrap pair carries no ML-KEM/AES-wrap value rules.
  var mF = parse(envCI({ version: 3, recips: [oriKem({ kem: algIdP(ID_ECDH, b.octetString(Buffer.from([1]))), kemct: b.octetString(Buffer.from([1, 2])), wrap: algId("1.3.99.2"), kekLength: b.integer(7n) })] }));
  check("kemri: unrecognized kem accepted raw", mF.recipientInfos[0].kemri.kem.oid === ID_ECDH && mF.recipientInfos[0].kemri.kekLength === 7);
  // rejects.
  check("kemri: version 1 rejected", parseCode(envCI({ version: 3, recips: [oriKem({ version: 1 })] })) === "cms/bad-version");
  check("kemri: kekLength 0 rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kekLength: b.integer(0n) })] })) === "cms/bad-kek-length");
  check("kemri: kekLength 65536 rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kekLength: b.integer(65536n) })] })) === "cms/bad-kek-length");
  check("kemri: kekLength 16 vs aes256-wrap rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kekLength: b.integer(16n) })] })) === "cms/kek-length-mismatch");
  check("kemri: ML-KEM-768 short kemct rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kemct: b.octetString(Buffer.alloc(1087, 0x2A)) })] })) === "cms/bad-kem-ciphertext");
  check("kemri: ML-KEM params present rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kem: algIdP(ML_KEM_768, Buffer.from([0x05, 0x00])) })] })) === "cms/bad-algorithm-parameters");
  check("kemri: HKDF params present rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kdf: algIdP(HKDF_SHA256, Buffer.from([0x05, 0x00])) })] })) === "cms/bad-algorithm-parameters");
  var wrongTag = parseCode(envCI({ version: 3, recips: [oriKem({ ukmWrongTag: UKM })] }));
  check("kemri: ukm at [1] rejected", wrongTag !== "NO-THROW" && wrongTag.indexOf("cms/") === 0);
  check("kemri: truncated (no encryptedKey) rejected", parseCode(envCI({ version: 3, recips: [oriKem({ children: [b.integer(0n), iasn("K", 7), algId(ML_KEM_768), b.octetString(KEMCT_768), algId(HKDF_SHA256), b.integer(32n), algId(ID_AES256_WRAP)] })] })) === "cms/bad-kem-recipient-info");
  // the recognized id-ori-kem type is validated by CONTENT — a value that is not
  // a KEMRecipientInfo rejects with a typed cms/* code, never accepted on tag.
  var garbageOri = parseCode(envCI({ version: 3, recips: [ori({})] }));
  check("kemri: recognized ori garbage value rejected", garbageOri.indexOf("cms/") === 0);
  check("kemri: kekLength not INTEGER rejected", parseCode(envCI({ version: 3, recips: [oriKem({ kekLength: b.octetString(Buffer.from([32])) })] })) === "asn1/unexpected-tag");
}

// ---- AuthenticatedData (RFC 5652 §9) -----------------------------------
function testAuthenticatedData() {
  var m = parse(adCI({}));
  check("authData: minimal v0", m.version === 0 && m.recipientInfos.length === 1);
  check("authData: macAlgorithm surfaced", m.macAlgorithm.oid === HMAC_SHA256);
  check("authData: mac raw exact", m.mac.equals(MAC12));
  check("authData: no digestAlgorithm -> null", m.digestAlgorithm === null && m.authAttrs === null && m.authAttrsBytes === null);
  check("authData: eContent surfaced", m.encapContentInfo.eContent.equals(Buffer.from("auth me")));
  var full = parse(adCI({ digestAlg: SHA256,
    authAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1])],
    unauthAttrs: [attribute(NEUTRAL_ATTR, [b.integer(1n)])] }));
  check("authData: digestAlgorithm surfaced", full.digestAlgorithm.oid === SHA256);
  check("authData: authAttrs decoded", full.authAttrs.length === 2);
  check("authData: authAttrsBytes raw [2] TLV", full.authAttrsBytes[0] === 0xA2);
  check("authData: unauthAttrs decoded", full.unauthAttrs.length === 1);
  // version rule (§9.1): originatorInfo tags only; recipient kinds do NOT bump.
  var v2AttrCert = b.contextConstructed(2, b.sequence([b.integer(1n)]));
  var otherCert = b.contextConstructed(3, b.sequence([b.integer(1n)]));
  var otherCrl = b.contextConstructed(1, b.sequence([b.integer(1n)]));
  check("authData: v2AttrCert -> v1", parse(adCI({ version: 1, originatorInfo: originatorInfo({ certs: [v2AttrCert] }) })).version === 1);
  check("authData: other cert [3] -> v3", parse(adCI({ version: 3, originatorInfo: originatorInfo({ certs: [otherCert] }) })).version === 3);
  check("authData: other crl [1] -> v3", parse(adCI({ version: 3, originatorInfo: originatorInfo({ crls: [otherCrl] }) })).version === 3);
  check("authData: pwri recipient does NOT bump version", parse(adCI({ version: 0, recips: [pwri({ version: 0 })] })).version === 0);
  check("authData: kemri ori recipient does NOT bump version", parse(adCI({ version: 0, recips: [oriKem({})] })).version === 0);
  check("authData: version 2 rejected", parseCode(adCI({ version: 2 })) === "cms/bad-version");
  check("authData: v3 stated without originatorInfo rejected", parseCode(adCI({ version: 3 })) === "cms/bad-version");
  check("authData: v0 stated with v2AttrCert rejected", parseCode(adCI({ version: 0, originatorInfo: originatorInfo({ certs: [v2AttrCert] }) })) === "cms/bad-version");
  // §9.1 biconditional + non-id-data rules.
  check("authData: digestAlgorithm without authAttrs rejected", parseCode(adCI({ digestAlg: SHA256 })) === "cms/missing-auth-attrs");
  check("authData: authAttrs without digestAlgorithm rejected", parseCode(adCI({ authAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1])] })) === "cms/missing-digest-algorithm");
  check("authData: non-id-data without authAttrs rejected", parseCode(adCI({ encap: encap(ID_CT_TSTINFO, Buffer.from("t")) })) === "cms/missing-auth-attrs");
  var nid = parse(adCI({ version: 0, digestAlg: SHA256, encap: encap(ID_CT_TSTINFO, Buffer.from("t")),
    authAttrs: [contentTypeAttr(ID_CT_TSTINFO), messageDigestAttr([1])] }));
  check("authData: non-id-data with authAttrs accepted", nid.encapContentInfo.eContentType === ID_CT_TSTINFO);
  // authAttrs carry the §11.1/§11.2 binding rules.
  check("authData: authAttrs missing content-type rejected", parseCode(adCI({ digestAlg: SHA256, authAttrs: [messageDigestAttr([1])] })) === "cms/missing-content-type");
  check("authData: authAttrs missing message-digest rejected", parseCode(adCI({ digestAlg: SHA256, authAttrs: [contentTypeAttr(ID_DATA)] })) === "cms/missing-message-digest");
  check("authData: authAttrs content-type mismatch rejected", parseCode(adCI({ digestAlg: SHA256, authAttrs: [contentTypeAttr(ID_CT_TSTINFO), messageDigestAttr([1])] })) === "cms/content-type-mismatch");
  check("authData: duplicate attr type rejected", parseCode(adCI({ digestAlg: SHA256,
    authAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1]), attribute(NEUTRAL_ATTR, [b.integer(1n)]), attribute(NEUTRAL_ATTR, [b.integer(2n)])] })) === "cms/duplicate-signed-attr");
  check("authData: message-digest in unauthAttrs rejected", parseCode(adCI({ unauthAttrs: [messageDigestAttr([1])] })) === "cms/misplaced-attr");
  // structural rejects.
  check("authData: empty authAttrs [2] rejected", parseCode(adCI({ authAttrsRaw: b.contextConstructed(2, Buffer.alloc(0)) })) === "cms/bad-auth-attrs");
  check("authData: empty unauthAttrs [3] rejected", parseCode(adCI({ children: [b.integer(0n), b.set([ktri({})]), algId(HMAC_SHA256), encap(ID_DATA, Buffer.from("x")), b.octetString(MAC12), b.contextConstructed(3, Buffer.alloc(0))] })) === "cms/bad-unauth-attrs");
  check("authData: empty recipientInfos rejected", parseCode(adCI({ recipsRaw: b.set([]) })) === "cms/bad-recipient-infos");
  check("authData: mac not OCTET STRING rejected", parseCode(adCI({ mac: b.integer(5n) })) === "asn1/unexpected-tag");
  var misordered = parseCode(adCI({ digestAlg: SHA256, authAttrs: [contentTypeAttr(ID_DATA), messageDigestAttr([1])].sort(Buffer.compare).reverse(), authAttrsSort: false }));
  check("authData: authAttrs not DER-sorted rejected", misordered !== "NO-THROW");
  check("authData: trailing byte rejected", parseCode(Buffer.concat([adCI({}), Buffer.from([0x00])])) === "cms/bad-der");
  // orchestrator routing.
  var routed = pki.schema.parse(adCI({}));
  check("orchestrator routes AuthenticatedData to cms", !!routed.macAlgorithm && !!routed.mac && routed.signerInfos === undefined);
}

// ---- AuthEnvelopedData (RFC 5083 + RFC 5084 AEAD parameters) -----------
function testAuthEnvelopedData() {
  var m = parse(aeCI({}));
  check("authEnv: minimal v0", m.version === 0 && m.recipientInfos.length === 1);
  check("authEnv: encryptedContentInfo surfaced", m.encryptedContentInfo.contentType === ID_DATA && m.encryptedContentInfo.encryptedContent.equals(CT));
  check("authEnv: mac raw exact", m.mac.equals(MAC12));
  check("authEnv: GCM aead surfaced", m.aead.kind === "gcm" && m.aead.nonce.length === 12 && m.aead.icvLen === 12);
  check("authEnv: authAttrs absent -> null", m.authAttrs === null && m.authAttrsBytes === null);
  // authAttrs here carry NO content-binding presence rules (§11.1/§11.2 bind
  // signed-data and authenticated-data) — a lone neutral attribute is legal.
  var wa = parse(aeCI({ authAttrs: [attribute(NEUTRAL_ATTR, [b.integer(1n)])], unauthAttrs: [attribute("1.3.99.8.8", [b.integer(2n)])] }));
  check("authEnv: authAttrs decoded (no presence rules)", wa.authAttrs.length === 1);
  check("authEnv: authAttrsBytes raw [1] TLV", wa.authAttrsBytes[0] === 0xA1);
  check("authEnv: unauthAttrs decoded", wa.unauthAttrs.length === 1);
  // GCM explicit ICVlen 16 + matching 16-byte mac.
  var g16 = parse(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_GCM, aeadParams(12, 16)), CT), mac: b.octetString(Buffer.alloc(16, 0x4D)) }));
  check("authEnv: GCM ICVlen 16 accepted", g16.aead.icvLen === 16 && g16.mac.length === 16);
  // CCM accept (nonce 7..13, ICVlen from the CCM set).
  var ccm = parse(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_CCM, aeadParams(13, 8)), CT), mac: b.octetString(Buffer.alloc(8, 0x4D)) }));
  check("authEnv: CCM accepted", ccm.aead.kind === "ccm" && ccm.aead.icvLen === 8);
  // an unrecognized content-encryption algorithm surfaces raw, no AEAD rules.
  var unk = parse(aeCI({ eci: eciP(ID_DATA, algIdP("1.3.99.3", b.octetString(Buffer.from([1]))), CT) }));
  check("authEnv: unrecognized alg raw (aead null)", unk.aead === null);
  // originatorInfo never changes the version (RFC 5083 fixes it at 0).
  var otherCert = b.contextConstructed(3, b.sequence([b.integer(1n)]));
  check("authEnv: originatorInfo other cert stays v0", parse(aeCI({ originatorInfo: originatorInfo({ certs: [otherCert] }) })).version === 0);
  // rejects.
  check("authEnv: version 1 rejected", parseCode(aeCI({ version: 1 })) === "cms/bad-version");
  check("authEnv: non-id-data without authAttrs rejected", parseCode(aeCI({ eci: eciP(ID_CT_TSTINFO, algIdP(ID_AES256_GCM, aeadParams(12)), CT) })) === "cms/missing-auth-attrs");
  var nidOk = parse(aeCI({ eci: eciP(ID_CT_TSTINFO, algIdP(ID_AES256_GCM, aeadParams(12)), CT), authAttrs: [contentTypeAttr(ID_CT_TSTINFO)] }));
  check("authEnv: non-id-data with authAttrs accepted", nidOk.encryptedContentInfo.contentType === ID_CT_TSTINFO);
  check("authEnv: authAttrs content-type mismatch rejected", parseCode(aeCI({ authAttrs: [contentTypeAttr(ID_CT_TSTINFO)] })) === "cms/content-type-mismatch");
  check("authEnv: duplicate attr type rejected", parseCode(aeCI({ authAttrs: [attribute(NEUTRAL_ATTR, [b.integer(1n)]), attribute(NEUTRAL_ATTR, [b.integer(2n)])] })) === "cms/duplicate-attr");
  check("authEnv: GCM params absent rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algId(ID_AES256_GCM), CT) })) === "cms/bad-aead-params");
  check("authEnv: GCM ICVlen 8 rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_GCM, aeadParams(12, 8)), CT) })) === "cms/bad-aead-params");
  check("authEnv: GCM encoded DEFAULT ICVlen 12 rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_GCM, aeadParams(12, 12)), CT) })) === "cms/non-canonical-default");
  check("authEnv: mac length != ICVlen rejected", parseCode(aeCI({ mac: b.octetString(Buffer.alloc(16, 0x4D)) })) === "cms/mac-length-mismatch");
  check("authEnv: CCM nonce 14 rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_CCM, aeadParams(14, 8)), CT), mac: b.octetString(Buffer.alloc(8)) })) === "cms/bad-aead-params");
  check("authEnv: CCM nonce 6 rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_CCM, aeadParams(6, 8)), CT), mac: b.octetString(Buffer.alloc(8)) })) === "cms/bad-aead-params");
  check("authEnv: CCM ICVlen 7 rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_CCM, aeadParams(13, 7)), CT), mac: b.octetString(Buffer.alloc(7)) })) === "cms/bad-aead-params");
  check("authEnv: GCM nonce not OCTET STRING rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_GCM, b.sequence([b.integer(1n)])), CT) })) === "cms/bad-aead-params");
  check("authEnv: GCM params 3 children rejected", parseCode(aeCI({ eci: eciP(ID_DATA, algIdP(ID_AES256_GCM, b.sequence([b.octetString(Buffer.alloc(12)), b.integer(13n), b.integer(13n)])), CT) })) === "cms/bad-aead-params");
  check("authEnv: empty authAttrs [1] rejected", parseCode(aeCI({ children: [b.integer(0n), b.set([ktri({})]), eciP(ID_DATA, algIdP(ID_AES256_GCM, aeadParams(12)), CT), b.contextConstructed(1, Buffer.alloc(0)), b.octetString(MAC12)] })) === "cms/bad-auth-attrs");
  check("authEnv: empty unauthAttrs [2] rejected", parseCode(aeCI({ children: [b.integer(0n), b.set([ktri({})]), eciP(ID_DATA, algIdP(ID_AES256_GCM, aeadParams(12)), CT), b.octetString(MAC12), b.contextConstructed(2, Buffer.alloc(0))] })) === "cms/bad-unauth-attrs");
  check("authEnv: empty recipientInfos rejected", parseCode(aeCI({ recipsRaw: b.set([]) })) === "cms/bad-recipient-infos");
  // orchestrator routing.
  var routed = pki.schema.parse(aeCI({}));
  check("orchestrator routes AuthEnvelopedData to cms", !!routed.mac && !!routed.encryptedContentInfo && routed.macAlgorithm === undefined);
}

// ---- the dispatched ContentInfo type rides every parse result ----------
function testContentTypeDiscriminator() {
  check("SignedData result carries contentTypeName", parse(cms({})).contentTypeName === "signedData");
  check("EnvelopedData result carries contentTypeName", parse(envCI({ version: 0 })).contentTypeName === "envelopedData");
  check("EncryptedData result carries contentTypeName", parse(encCI({ version: 0 })).contentTypeName === "encryptedData");
  check("AuthenticatedData result carries contentTypeName", parse(adCI({})).contentTypeName === "authData");
  check("AuthEnvelopedData result carries contentTypeName", parse(aeCI({})).contentTypeName === "authEnvelopedData");
  check("contentType is the dotted OID", parse(cms({})).contentType === ID_SIGNED_DATA);
}

function run() {
  testAccept();
  testEnvelope();
  testContentType();
  testVersion();
  testSetOrder();
  testDispatch();
  testCompleteness();
  testEncryptedData();
  testEnvelopedKtri();
  testEnvelopedOtherArms();
  testEnvelopedVersionAndStructure();
  testEnvelopedDispatch();
  testSignedDataCertCrlVersions();
  testCertCrlChoiceClosure();
  testDerAttrsUnderBer();
  testAttrPlacementRules();
  testCountersignatureValues();
  testKemRecipientInfo();
  testAuthenticatedData();
  testAuthEnvelopedData();
  testContentTypeDiscriminator();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
