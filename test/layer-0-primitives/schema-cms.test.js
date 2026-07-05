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
  check("13. id-envelopedData -> unsupported", parseCode(contentInfo(ID_ENVELOPED_DATA, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
  check("14a. id-encryptedData -> unsupported", parseCode(contentInfo(ID_ENCRYPTED_DATA, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
  check("14b. id-digestedData -> unsupported", parseCode(contentInfo(ID_DIGESTED_DATA, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
  check("14c. id-signedAndEnvelopedData -> unsupported", parseCode(contentInfo(ID_SIGNED_ENV, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
  check("14d. id-ct-authData -> unsupported", parseCode(contentInfo(ID_CT_AUTHDATA, b.sequence([b.integer(0n)]))) === "cms/unsupported-content-type");
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

function run() {
  testAccept();
  testEnvelope();
  testContentType();
  testVersion();
  testSetOrder();
  testDispatch();
  testCompleteness();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
