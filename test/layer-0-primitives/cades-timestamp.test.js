// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * CAdES signature timestamp: `id-aa-signatureTimeStampToken` attached and verified.
 *
 * The attribute is `{ 1 2 840 113549 1 9 16 2 14 }` with value type `TimeStampToken` (RFC 5126
 * clause 6.1.1; ETSI EN 319 122-1 clause 5.3 and Annex D), it is unsigned, and its imprint is
 * "the hash value of the signature field (without the ASN.1 tag and length) within SignerInfo for
 * which the signature-time-stamp attribute is created" (EN 319 122-1 clause 5.3). RFC 5652
 * clause 11.4 states the same octet rule for the sibling countersignature: "the contents octets of
 * the signature OCTET STRING in a SignerInfo value of the signed-data ... neither the tag nor length
 * octets are included".
 *
 * Plurality is the opposite of countersignature. EN 319 122-1 clause 5.3: "The signature-time-stamp
 * attribute shall contain exactly one component of AttributeValue type", while RFC 5126
 * clause 6.1.1 has "Several instances of this attribute may occur with an electronic signature, from
 * different TSAs". So n timestamps are n `Attribute` members each carrying a one-element SET, where
 * RFC 5652 clause 11.4 puts n countersignatures in one attribute with n values.
 *
 * Every vector drives a shipped `pki.*` verb and every hostile case is built as an ENCODING.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("node:crypto");
var b = pki.asn1.build;

var CONTENT = Buffer.from("the CAdES content being signed", "utf8");
var GENTIME = new Date("2027-06-01T00:00:00Z");
var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2030-01-01T00:00:00Z");

async function codeOf(p) {
  try { await p; return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; }
}

// A signer and a TSA, each with the certificate its role needs.
async function makeSigner(cn, exts) {
  var kp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var spki = await pki.key.export(kp.publicKey);
  var key = await pki.key.export(kp.privateKey);
  var cert = await pki.x509.sign({ subject: cn, subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: exts || { keyUsage: ["digitalSignature"] } }, { key: key });
  return { cert: cert, key: key, spki: spki };
}
function makeTsaExts() {
  return { extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true,
    keyUsage: ["digitalSignature"] };
}

// A TimeStampToken over `imprintBytes`, minted raw so a shape `pki.tsp.sign` refuses can still be
// judged by the verifier.
async function mintToken(tsa, imprintBytes, o) {
  o = o || {};
  var alg = o.alg || "sha256";
  var h = o.hashedMessage || crypto.createHash(alg).update(imprintBytes).digest();
  var fields = [b.integer(1n), b.oid(o.policy || "1.2.3.4.1"),
    b.sequence([b.sequence([b.oid(pki.oid.byName(alg))]), b.octetString(h)]),
    b.integer(BigInt(o.serialNumber == null ? 7 : o.serialNumber)),
    b.generalizedTime(o.genTime || GENTIME)];
  if (o.genTimeRaw) fields[4] = o.genTimeRaw;
  if (o.extensions) fields.push(b.contextConstructed(1, Buffer.concat(o.extensions)));
  var attrs = [];
  if (o.ess !== null) {
    attrs.push({ type: "signingCertificateV2",
      values: [o.ess || pki.schema.smime.buildSigningCertificateV2(tsa.cert)] });
  }
  var signers = o.signers || { cert: tsa.cert, key: tsa.key };
  return await pki.cms.sign(b.sequence(fields), signers,
    { eContentType: o.eContentType === undefined ? "tSTInfo" : o.eContentType,
      detached: o.detached === true, additionalSignedAttributes: attrs });
}

// The signature octets of one SignerInfo, read through the shipped parser rather than by hand.
function signatureOctetsOf(cmsDer, idx) {
  return pki.schema.cms.parse(cmsDer).signerInfos[idx || 0].signature;
}

async function run() {
  var signer = await makeSigner("CAdES Signer");
  var tsa = await makeSigner("TSA One", makeTsaExts());
  var tsa2 = await makeSigner("TSA Two", makeTsaExts());
  var base = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key });

  // ---- the imprint verb: what an operator sends a third-party TSA ----------------------------
  // CT-2: the imprint is the hash of the signature contents octets, computed here independently.
  var imprint = await pki.cms.timestampImprint(base);
  var sigOctets = signatureOctetsOf(base);
  check("CT-2 the imprint names the digest asked for", imprint.hashAlgorithm === "sha256");
  check("CT-2 the imprint is the hash of SignerInfo.signature's contents octets",
    imprint.hashedMessage.equals(crypto.createHash("sha256").update(sigOctets).digest()));
  check("CT-2 and it names the signer it was taken for", imprint.signerIndex === 0);
  var imprint384 = await pki.cms.timestampImprint(base, { digestAlgorithm: "sha384" });
  check("CT-2b another digest is taken on request",
    imprint384.hashAlgorithm === "sha384" &&
    imprint384.hashedMessage.equals(crypto.createHash("sha384").update(sigOctets).digest()));
  check("CT-2c a digest outside the registry is refused",
    (await codeOf(pki.cms.timestampImprint(base, { digestAlgorithm: "nope" }))) === "cms/bad-input");
  // The MD5 refusal must be the clause's own, not the generic "this build does not carry that
  // digest" the algorithm table would answer with, so the message is what distinguishes them.
  var md5Err = null;
  try { await pki.cms.timestampImprint(base, { digestAlgorithm: "md5" }); }
  catch (e) { md5Err = e; }
  check("CT-2d MD5 is refused by the clause that forbids it (ETSI EN 319 122-1 clause 6.2.1)",
    md5Err !== null && md5Err.code === "cms/bad-input" && md5Err.message.indexOf("MD5") === 0);
  check("CT-45 an out-of-range signerIndex is refused by the imprint verb",
    (await codeOf(pki.cms.timestampImprint(base, { signerIndex: 3 }))) === "cms/bad-input");
  // CT-58: both verbs read wire bytes, so the input a documented contract names is DER or PEM. A
  // parsed object is refused rather than half-read, and this pins the contract the docstring states.
  check("CT-58 the imprint verb takes DER or PEM, and a parsed object is refused",
    (await codeOf(pki.cms.timestampImprint(pki.schema.cms.parse(base)))) === "cms/bad-input" &&
    (await pki.cms.timestampImprint(pki.schema.cms.pemEncode(base))).signerIndex === 0);

  // ---- the attach verb ------------------------------------------------------------------------
  var token = await mintToken(tsa, sigOctets);
  var attached = await pki.cms.attachTimestamp(base, token);

  // CT-44: the verb refuses a token whose imprint covers other bytes, so it cannot produce a
  // message it would itself refuse.
  var wrongToken = await mintToken(tsa, Buffer.from("other bytes", "utf8"));
  check("CT-44 a token whose imprint covers other bytes is refused by the attach verb",
    (await codeOf(pki.cms.attachTimestamp(base, wrongToken))) === "cms/timestamp-imprint-mismatch");
  check("CT-45 an out-of-range signerIndex is refused by the attach verb",
    (await codeOf(pki.cms.attachTimestamp(base, token, { signerIndex: 2 }))) === "cms/bad-input");

  // CT-3 / CT-4: what the splice preserves, byte for byte.
  var before = pki.schema.cms.parse(base);
  var after = pki.schema.cms.parse(attached);
  check("CT-4 signedAttrsBytes is identical before and after the attach",
    before.signerInfos[0].signedAttrsBytes.equals(after.signerInfos[0].signedAttrsBytes));
  check("CT-3 the signature octets are identical",
    before.signerInfos[0].signature.equals(after.signerInfos[0].signature));
  check("CT-3 the encapsulated content and its type are identical",
    before.encapContentInfo.eContentType === after.encapContentInfo.eContentType &&
    before.encapContentInfo.eContent.equals(after.encapContentInfo.eContent));
  check("CT-3 each embedded certificate is identical",
    before.certificates.length === after.certificates.length &&
    before.certificates.every(function (c, i) { return c.bytes.equals(after.certificates[i].bytes); }));
  check("CT-8 the rebuilt unsignedAttrs re-parses, so its SET OF is in DER order",
    after.signerInfos[0].unsignedAttrs.length === 1 &&
    after.signerInfos[0].unsignedAttrs[0].name === "timeStampToken");

  // ---- the verify row ------------------------------------------------------------------------
  // CT-1: the signer is still valid and the timestamp row verifies.
  var v = await pki.cms.verify(attached, { certs: [signer.cert], content: CONTENT });
  check("CT-1 the signer row is still valid after the attach", v.signers[0].ok === true);
  check("CT-1 the timestamp row verifies",
    Array.isArray(v.signers[0].signatureTimeStamps) &&
    v.signers[0].signatureTimeStamps.length === 1 &&
    v.signers[0].signatureTimeStamps[0].valid === true);
  check("CT-1 and it surfaces the generation time from the verified eContent",
    v.signers[0].signatureTimeStamps[0].genTime instanceof Date &&
    v.signers[0].signatureTimeStamps[0].genTime.toISOString() === GENTIME.toISOString());

  // CT-9 / CT-10: `trusted` is a second question from `valid`, answered definitely either way.
  check("CT-9 with no anchor the row reports valid and untrusted",
    v.signers[0].signatureTimeStamps[0].trusted === false);
  var vAnchored = await pki.cms.verify(attached, { certs: [signer.cert], content: CONTENT,
    timestampTrustAnchors: [tsa.cert] });
  check("CT-10 with the TSA anchor passed the row reports trusted",
    vAnchored.signers[0].signatureTimeStamps[0].valid === true &&
    vAnchored.signers[0].signatureTimeStamps[0].trusted === true);

  // CT-5: two instances of the attribute, from two TSAs, as two rows.
  var token2 = await mintToken(tsa2, sigOctets, { genTime: new Date("2027-07-01T00:00:00Z"), serialNumber: 9 });
  var twice = await pki.cms.attachTimestamp(attached, token2);
  var vTwice = await pki.cms.verify(twice, { certs: [signer.cert], content: CONTENT });
  check("CT-5 two timestamps from two authorities verify as two rows",
    vTwice.signers[0].signatureTimeStamps.length === 2 &&
    vTwice.signers[0].signatureTimeStamps.every(function (r) { return r.valid === true; }));
  check("CT-5 each row carries its own generation time",
    vTwice.signers[0].signatureTimeStamps[0].genTime.toISOString() !== vTwice.signers[0].signatureTimeStamps[1].genTime.toISOString());
  // CT-46 PIN: the plurality is repeated ATTRIBUTE members, not one attribute with two values.
  var attrs = pki.schema.cms.parse(twice).signerInfos[0].unsignedAttrs
    .filter(function (a) { return a.name === "timeStampToken"; });
  check("CT-46 PIN two timestamps are two attribute instances, each with one value (EN 319 122-1 " +
    "clause 5.3), not one attribute with two values as RFC 5652 clause 11.4 has for countersignature",
  attrs.length === 2 && attrs.every(function (a) { return a.values.length === 1; }));

  // CT-24: one attribute carrying two values is refused on the read side.
  var twoValue = b.sequence([b.oid(pki.oid.byName("timeStampToken")), b.set([token, token])]);
  var handBuilt = await spliceRawUnsignedAttr(base, twoValue);
  var vTwoValue = await pki.cms.verify(handBuilt, { certs: [signer.cert], content: CONTENT });
  check("CT-24 one attribute carrying two AttributeValues is refused (EN 319 122-1 clause 5.3)",
    vTwoValue.signers[0].signatureTimeStamps[0].valid === false &&
    vTwoValue.signers[0].signatureTimeStamps[0].code === "cms/timestamp-multi-valued");

  // CT-16: an unreadable timestamp does not take the signer row down.
  var junk = b.sequence([b.oid(pki.oid.byName("timeStampToken")), b.set([b.octetString(Buffer.from("not a token"))])]);
  var vJunk = await pki.cms.verify(await spliceRawUnsignedAttr(base, junk),
    { certs: [signer.cert], content: CONTENT });
  check("CT-16 an unreadable timestamp leaves the signer's own verdict standing",
    vJunk.signers[0].ok === true && vJunk.signers[0].signatureTimeStamps[0].valid === false);
  check("CT-16 and the failure is a row verdict rather than a throw",
    typeof vJunk.signers[0].signatureTimeStamps[0].code === "string");

  // CT-17: a token over different bytes, spliced past the attach verb's own check.
  var vWrong = await pki.cms.verify(
    await spliceRawUnsignedAttr(base, b.sequence([b.oid(pki.oid.byName("timeStampToken")), b.set([wrongToken])])),
    { certs: [signer.cert], content: CONTENT });
  check("CT-17 a token whose imprint covers other bytes is a row verdict, not a throw",
    vWrong.signers[0].ok === true && vWrong.signers[0].signatureTimeStamps[0].valid === false &&
    vWrong.signers[0].signatureTimeStamps[0].code === "cms/timestamp-imprint-mismatch");

  // CT-43: the archive timestamp OID is NOT read as a signature timestamp. EN 319 122-1
  // clause 5.5.3 contains "The archive-time-stamp-v3 attribute shall be identified by the
  // id-aa-signatureTimeStampToken OID" and then defines id-aa-ets-archiveTimestampV3 as
  // { itu-t(0) identified-organization(4) etsi(0) electronic-signature-standard(1733)
  // attributes(2) 4 }. The ASN.1 is followed, not the prose: 1.2.840.113549.1.9.16.2.14 is the
  // signature timestamp and 0.4.0.1733.2.4 is the archive timestamp, and a dispatcher following the
  // sentence would hash the wrong octets for every B-T signature.
  var archive = b.sequence([b.oid("0.4.0.1733.2.4"), b.set([token])]);
  var vArchive = await pki.cms.verify(await spliceRawUnsignedAttr(base, archive),
    { certs: [signer.cert], content: CONTENT });
  check("CT-43 an archive-timestamp attribute is not read as a signature timestamp",
    vArchive.signers[0].ok === true &&
    (!vArchive.signers[0].signatureTimeStamps || vArchive.signers[0].signatureTimeStamps.length === 0));

  // CT-25: the attribute in signedAttrs is not read as a signature timestamp. Toolkit decision: RFC
  // 5652 clause 11.4 has the explicit prohibition for countersignature and neither CAdES document
  // states one here, so this is a posture rather than a cited rule.
  var signedPlacement = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "timeStampToken", values: [token] }] });
  var vSigned = await pki.cms.verify(signedPlacement, { certs: [signer.cert], content: CONTENT });
  check("CT-25 a timestamp attribute among the SIGNED attributes is not read as one",
    vSigned.signers[0].ok === true &&
    (!vSigned.signers[0].signatureTimeStamps || vSigned.signers[0].signatureTimeStamps.length === 0));

  // ---- gate G-5, the two time-coherence rules -------------------------------------------------
  // CT-40: a genTime before the signature's own claimed signing time is a contradiction inside one
  // signature. signing-time is the signer's assertion and not evidence of the real time, but it sits
  // under the signature, so the two disagreeing is a fault to report.
  var late = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key,
  }, { signingTime: new Date("2027-09-01T00:00:00Z") });
  var lateSig = signatureOctetsOf(late);
  var earlyToken = await mintToken(tsa, lateSig, { genTime: new Date("2027-06-01T00:00:00Z") });
  var vEarly = await pki.cms.verify(await pki.cms.attachTimestamp(late, earlyToken),
    { certs: [signer.cert], content: CONTENT });
  check("CT-40 a genTime preceding the signed signing-time is refused",
    vEarly.signers[0].signatureTimeStamps[0].valid === false &&
    vEarly.signers[0].signatureTimeStamps[0].code === "cms/timestamp-before-signing-time");
  var okToken = await mintToken(tsa, lateSig, { genTime: new Date("2027-09-02T00:00:00Z") });
  var vOk = await pki.cms.verify(await pki.cms.attachTimestamp(late, okToken),
    { certs: [signer.cert], content: CONTENT });
  check("CT-40 CONTROL a genTime after the signing-time verifies",
    vOk.signers[0].signatureTimeStamps[0].valid === true);

  // CT-41: EN 319 122-1 clause 6.3 requirement m, whose expiry half is checkable from the signer
  // certificate alone: "the tokens ... shall be created before the signing certificate has been
  // revoked or has expired".
  var shortLived = await makeSignerWithWindow("Short Lived", NB, new Date("2027-03-01T00:00:00Z"));
  var slBase = await pki.cms.sign(CONTENT, { cert: shortLived.cert, key: shortLived.key });
  var afterExpiry = await mintToken(tsa, signatureOctetsOf(slBase), { genTime: new Date("2027-06-01T00:00:00Z") });
  var vExpired = await pki.cms.verify(await pki.cms.attachTimestamp(slBase, afterExpiry),
    { certs: [shortLived.cert], content: CONTENT, time: new Date("2027-02-01T00:00:00Z") });
  check("CT-41 a genTime after the signer certificate's notAfter is refused",
    vExpired.signers[0].signatureTimeStamps[0].valid === false &&
    vExpired.signers[0].signatureTimeStamps[0].code === "cms/timestamp-after-signer-expiry");
  var beforeExpiry = await mintToken(tsa, signatureOctetsOf(slBase), { genTime: new Date("2027-02-01T00:00:00Z") });
  var vInWindow = await pki.cms.verify(await pki.cms.attachTimestamp(slBase, beforeExpiry),
    { certs: [shortLived.cert], content: CONTENT, time: new Date("2027-02-01T00:00:00Z") });
  check("CT-41 CONTROL a genTime inside the certificate's window verifies",
    vInWindow.signers[0].signatureTimeStamps[0].valid === true);

  // ---- where the attribute lands on a message with more than one SignerInfo -------------------
  // CT-6: the attach names one signer, and the others keep the bytes they had.
  var signer2 = await makeSigner("Second Signer");
  var twoSigners = await pki.cms.sign(CONTENT, [{ cert: signer.cert, key: signer.key },
    { cert: signer2.cert, key: signer2.key }]);
  var sig1 = signatureOctetsOf(twoSigners, 1);
  var tokenFor1 = await mintToken(tsa, sig1);
  var attached1 = await pki.cms.attachTimestamp(twoSigners, tokenFor1, { signerIndex: 1 });
  // signerInfos is a SET OF, so the attach re-sorts it: giving one member an attribute changes its
  // encoding and with it its DER position. Each signer is therefore found by its signature value,
  // which is what identifies it, rather than by the index it held in the input.
  var parsed1 = pki.schema.cms.parse(attached1);
  function byIndexSignature(parsedCms, want) {
    return parsedCms.signerInfos.filter(function (s) { return s.signature.equals(want); })[0];
  }
  var sig0 = signatureOctetsOf(twoSigners, 0);
  var stampedSi = byIndexSignature(parsed1, sig1);
  var untouchedSi = byIndexSignature(parsed1, sig0);
  check("CT-6 the named signer carries the attribute and the other carries none",
    stampedSi !== undefined && untouchedSi !== undefined &&
    stampedSi.unsignedAttrs.length === 1 &&
    (untouchedSi.unsignedAttrs === null || untouchedSi.unsignedAttrs.length === 0));
  var vTwo = await pki.cms.verify(attached1, { certs: [signer.cert, signer2.cert], content: CONTENT });
  var rowStamped = vTwo.signers.filter(function (s) { return s.signatureTimeStamps.length === 1; });
  check("CT-6 both signatures still verify and only the named signer has a timestamp row",
    vTwo.signers.length === 2 && vTwo.signers.every(function (s) { return s.ok === true; }) &&
    rowStamped.length === 1 && rowStamped[0].signatureTimeStamps[0].valid === true);
  // Which certificate index 1 belongs to is the DER sort's answer, not the order the signers were
  // passed in: `pki.cms.sign` sorts the SET OF too. The expected certificate is therefore resolved
  // from the message, through the signer identifier the attach verb targeted.
  var targetSid = pki.schema.cms.parse(twoSigners).signerInfos[1].sid;
  var candidates = [signer.cert, signer2.cert];
  var serials = candidates.map(function (c) { return pki.schema.x509.parse(c).serialNumber; });
  check("CT-6 PREMISE the two signer certificates carry different serial numbers",
    serials[0] !== serials[1]);
  var expectedCert = candidates.filter(function (c) {
    return pki.schema.x509.parse(c).serialNumber === targetSid.serialNumber;
  })[0];
  check("CT-6 the row belongs to the signer whose signature the token covers",
    expectedCert !== undefined && rowStamped[0].cert.equals(expectedCert));

  // CT-7: an unsignedAttrs that already carries a countersignature gains a second MEMBER, and the
  // rebuilt SET OF re-parses, which is what proves its DER ordering.
  var countersigned = await pki.cms.countersign(base, { cert: signer2.cert, key: signer2.key });
  var csAttached = await pki.cms.attachTimestamp(countersigned, token);
  var vCs = await pki.cms.verify(csAttached, { certs: [signer.cert, signer2.cert], content: CONTENT });
  check("CT-7 the countersignature still verifies beside the timestamp",
    vCs.signers[0].countersignatures.length === 1 && vCs.signers[0].countersignatures[0].ok === true &&
    vCs.signers[0].signatureTimeStamps.length === 1 &&
    vCs.signers[0].signatureTimeStamps[0].valid === true);
  check("CT-7 both unsigned attributes are present after the splice",
    pki.schema.cms.parse(csAttached).signerInfos[0].unsignedAttrs.length === 2);

  // ---- what the row reports about the authority -----------------------------------------------
  // CT-11: a revocation checker reaches the TSA chain and the row says what it established. The
  // four states `pki.path.validate` answers with are carried, not a boolean, so "checked, good"
  // stays distinguishable from "never consulted".
  var goodChecker = { check: function () { return Promise.resolve({ status: "good" }); } };
  var vRev = await pki.cms.verify(attached, { certs: [signer.cert], content: CONTENT,
    timestampTrustAnchors: [tsa.cert], timestampRevocationChecker: goodChecker });
  check("CT-11 a timestampRevocationChecker reaches the row and it reports what was established",
    vRev.signers[0].signatureTimeStamps[0].valid === true &&
    vRev.signers[0].signatureTimeStamps[0].trusted === true &&
    vRev.signers[0].signatureTimeStamps[0].revocationChecked === "determined");
  check("CT-11 CONTROL without a checker the same row reports that nothing was consulted",
    vAnchored.signers[0].signatureTimeStamps[0].revocationChecked === false);

  // CT-12: the signer's chain is validated at the instant the caller names, which for a timestamped
  // signature is the token's genTime. An expired signer certificate is still trusted as of a time
  // inside its window, and untrusted as of now.
  var pastWindow = new Date("2026-02-01T00:00:00Z");
  var expiredSigner = await makeSignerWithWindow("Expired Signer", new Date("2026-01-01T00:00:00Z"),
    new Date("2026-03-01T00:00:00Z"));
  var expBase = await pki.cms.sign(CONTENT, { cert: expiredSigner.cert, key: expiredSigner.key });
  var expStamped = await pki.cms.attachTimestamp(expBase,
    await mintToken(tsa, signatureOctetsOf(expBase), { genTime: pastWindow }));
  var vAtGenTime = await pki.cms.verify(expStamped,
    { certs: [expiredSigner.cert], content: CONTENT, trustAnchors: [expiredSigner.cert],
      time: pastWindow });
  check("CT-12 the signer chain validated at the token's genTime is trusted",
    vAtGenTime.signers[0].ok === true && vAtGenTime.trusted === true);
  var vAtNow = await pki.cms.verify(expStamped,
    { certs: [expiredSigner.cert], content: CONTENT, trustAnchors: [expiredSigner.cert] });
  check("CT-12 and the same message is untrusted against the current clock, the certificate having " +
    "expired", vAtNow.signers[0].ok === true && vAtNow.trusted === false);

  // CT-13: the binding this suite mints is the v2 form under SHA-256, which is what EN 319 122-1
  // clause 6.3 requirement i requires of a signature that does not digest with SHA-1.
  var tokenSi = pki.schema.cms.parse(token).signerInfos[0];
  var essAttr = tokenSi.signedAttrs.filter(function (a) { return a.name === "signingCertificateV2"; })[0];
  var essVal = pki.schema.smime.parseSigningCertificateV2(essAttr.values[0]);
  check("CT-13 the token is bound by an ESSCertIDv2 under SHA-256",
    essVal.certs.length === 1 && essVal.certs[0].hashAlgorithm.name === "sha256" &&
    essVal.certs[0].certHash.equals(crypto.createHash("sha256").update(tsa.cert).digest()));

  // ---- a token the TSP layer refuses is a ROW verdict, never a throw out of cms.verify ---------
  // Each class here is already pinned per-code at the TSP layer; what this table pins is the CAdES
  // routing: the signer keeps its own verdict and the failure lands on the row, with the code the
  // token layer answered.
  var badTokens = [
    ["CT-18 an imprint whose length is not the digest's output length",
      { hashedMessage: Buffer.alloc(16, 9) }, "tsp/imprint-length"],
    ["CT-19 a SHA-1 imprint, refused by default", { alg: "sha1" }, "tsp/weak-digest"],
    ["CT-22 an MD5 imprint (ETSI EN 319 122-1 clause 6.2.1)", { alg: "md5" }, "tsp/unsupported-algorithm"],
    ["CT-26 a token whose SignedData carries two signers",
      { signers: [{ cert: tsa.cert, key: tsa.key }, { cert: tsa2.cert, key: tsa2.key }] }, "tsp/multi-signer"],
    ["CT-27 a detached token carrying no eContent", { detached: true }, "tsp/detached-token"],
    ["CT-28 an eContentType that is not id-ct-TSTInfo", { eContentType: "data" }, "tsp/wrong-econtent-type"],
    ["CT-29 no ESS signing-certificate attribute", { ess: null }, "tsp/missing-signing-certificate"],
    ["CT-30 an ESS certHash naming a different certificate",
      { ess: pki.schema.smime.buildSigningCertificateV2(Buffer.alloc(32, 3)) }, "tsp/cert-binding-mismatch"],
    ["CT-37 an unknown CRITICAL TSTInfo extension",
      { extensions: [b.sequence([b.oid("1.2.3.4.999"), b.boolean(true), b.octetString(Buffer.alloc(1))])] },
      "tsp/unknown-critical-extension"],
  ];
  for (var bt = 0; bt < badTokens.length; bt++) {
    var spec = badTokens[bt];
    var badToken = await mintToken(tsa, sigOctets, spec[1]);
    var vBad = await pki.cms.verify(await spliceRawUnsignedAttr(base,
      b.sequence([b.oid(pki.oid.byName("timeStampToken")), b.set([badToken])])),
    { certs: [signer.cert], content: CONTENT });
    check(spec[0] + " is a row verdict (" + spec[2] + "), and the signer keeps its own",
      vBad.signers[0].ok === true && vBad.signers[0].signatureTimeStamps.length === 1 &&
      vBad.signers[0].signatureTimeStamps[0].valid === false &&
      vBad.signers[0].signatureTimeStamps[0].code === spec[2]);
  }
  // CT-20: the one opt-in that admits a weak imprint admits it on this route too, and the attach
  // verb holds the same posture as the verifier: without the opt-in it refuses rather than writing
  // an attribute whose row would then be refused.
  var weakToken = await mintToken(tsa, sigOctets, { alg: "sha1" });
  check("CT-20 the attach verb refuses a weak-imprint token by default",
    (await codeOf(pki.cms.attachTimestamp(base, weakToken))) === "cms/weak-timestamp-imprint");
  var vWeakAllowed = await pki.cms.verify(await pki.cms.attachTimestamp(base, weakToken,
    { allowWeakDigests: true }), { certs: [signer.cert], content: CONTENT, allowWeakDigests: true });
  check("CT-20 allowWeakDigests admits the same SHA-1 imprint, which is the archived-token path",
    vWeakAllowed.signers[0].signatureTimeStamps[0].valid === true);
  // CT-37 CONTROL: an unknown NON-critical TSTInfo extension is accepted, so the refusal above is
  // the criticality and not the unknown OID.
  var vPlainExt = await pki.cms.verify(await pki.cms.attachTimestamp(base,
    await mintToken(tsa, sigOctets,
      { extensions: [b.sequence([b.oid("1.2.3.4.999"), b.octetString(Buffer.alloc(1))])] })),
  { certs: [signer.cert], content: CONTENT });
  check("CT-37 CONTROL an unknown NON-critical TSTInfo extension is accepted",
    vPlainExt.signers[0].signatureTimeStamps[0].valid === true);
  // CT-32: a token signed under a certificate that is not a TSA certificate (RFC 3161 sec. 2.3).
  var vNotTsa = await pki.cms.verify(
    await pki.cms.attachTimestamp(base, await mintToken(signer, sigOctets)),
    { certs: [signer.cert], content: CONTENT });
  check("CT-32 a token under a certificate with no timeStamping EKU is a row verdict (tsp/bad-eku)",
    vNotTsa.signers[0].ok === true &&
    vNotTsa.signers[0].signatureTimeStamps[0].valid === false &&
    vNotTsa.signers[0].signatureTimeStamps[0].code === "tsp/bad-eku");

  // ---- the CAdES baseline requirements the verb decides ---------------------------------------
  // CT-47 / CT-48: a sound signature is not by itself a CAdES signature, and the report names which
  // requirements it answered for.
  check("CT-48 a signature with no signing-certificate attribute is reported non-conformant " +
    "(ETSI EN 319 122-1 clauses 5.2.2.2 and 5.2.2.3)",
  v.signers[0].cadesBaseline.conformant === false &&
    v.signers[0].cadesBaseline.signingCertificateAttribute === null &&
    v.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-no-signing-certificate"; }));
  var bb = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificateV2",
      values: [pki.schema.smime.buildSigningCertificateV2(signer.cert)] }] });
  var vBb = await pki.cms.verify(bb, { certs: [signer.cert], content: CONTENT });
  check("CT-48 the v2 form under SHA-256 is conformant (requirement i)",
    vBb.signers[0].cadesBaseline.conformant === true &&
    vBb.signers[0].cadesBaseline.signingCertificateAttribute === "v2" &&
    vBb.signers[0].cadesBaseline.findings.length === 0);
  check("CT-48 the report names the requirements it answered for, so conformant is read against " +
    "that list rather than as a full clause 6.3 audit",
  vBb.signers[0].cadesBaseline.requirementsChecked.length === 3);
  var v1Ess = b.sequence([b.sequence([b.sequence([b.octetString(crypto.createHash("sha1").update(signer.cert).digest())])])]);
  var vV1 = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificate", values: [v1Ess] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-48 the v1 form under a SHA-256 signature is non-conformant (requirement i)",
    vV1.signers[0].cadesBaseline.signingCertificateAttribute === "v1" &&
    vV1.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-signing-certificate-v1"; }));
  var vCt = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2",
      values: [pki.schema.smime.buildSigningCertificateV2(signer.cert)] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-47 a content-type other than id-data is reported non-conformant (clause 6.3 " +
    "requirement f)",
  vCt.signers[0].ok === true && vCt.signers[0].cadesBaseline.conformant === false &&
    vCt.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-content-type"; }));

  // CT-49: the requirement is that the signing certificate IS protected, so the attribute's presence
  // is not the answer: an identifier naming other bytes protects nothing, and reporting it as met
  // would make the verdict say the opposite of what holds.
  var strayEss = pki.schema.smime.buildSigningCertificateV2(Buffer.alloc(40, 0x5A));
  var vStray = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificateV2", values: [strayEss] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-49 a signing-certificate-v2 identifier hashing other bytes is reported non-conformant",
    vStray.signers[0].ok === true && vStray.signers[0].cadesBaseline.conformant === false &&
    vStray.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-signing-certificate-mismatch"; }));
  var strayV1 = b.sequence([b.sequence([b.sequence([b.octetString(crypto.createHash("sha1").update(Buffer.alloc(40, 0x5A)).digest())])])]);
  var vStrayV1 = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificate", values: [strayV1] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-49 and the v1 form is held to its binding the same way",
    vStrayV1.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-signing-certificate-mismatch"; }));
  var v1Bound = b.sequence([b.sequence([b.sequence([b.octetString(crypto.createHash("sha1").update(signer.cert).digest())])])]);
  var vV1Bound = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificate", values: [v1Bound] }] }),
  { certs: [signer.cert], content: CONTENT });
  // A v1 identifier is SHA-1 by definition (RFC 2634), so a correctly-bound one draws the
  // requirement-i row and the weak-binding row, which is the posture `pki.tsp.verify` already holds
  // a v1-bound token to, and NOT the mismatch row.
  var v1Codes = vV1Bound.signers[0].cadesBaseline.findings.map(function (f) { return f.code; });
  check("CT-49 CONTROL a v1 identifier that does bind is not reported as a mismatch",
    v1Codes.indexOf("cms/cades-signing-certificate-mismatch") === -1 &&
    v1Codes.indexOf("cms/cades-signing-certificate-v1") !== -1 &&
    v1Codes.indexOf("cms/cades-weak-certificate-binding") !== -1);
  var junkEss = b.sequence([b.oid(pki.oid.byName("sha256"))]);
  var vJunkEss = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificateV2", values: [junkEss] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-49 an attribute value that does not decode is reported rather than passed over",
    vJunkEss.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-signing-certificate-unreadable"; }));
  var certless = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { certificates: false, additionalSignedAttributes: [{ type: "signingCertificateV2",
      values: [pki.schema.smime.buildSigningCertificateV2(signer.cert)] }] });
  var vNoCert = await pki.cms.verify(certless, { content: CONTENT });
  check("CT-49 with no certificate matched the binding is undecidable and is reported, not assumed",
    vNoCert.signers[0].cadesBaseline.conformant === false &&
    vNoCert.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-signing-certificate-unverifiable"; }));
  // An identifier states the certificate twice, by hash and by issuer and serial, and RFC 5035
  // clause 5 makes the second a MUST where it is present. A hash that agrees beside an issuer and
  // serial naming another certificate is a contradiction rather than a match, and it is the same
  // claim `pki.tsp.verify` holds a token's own binding to.
  var dirName = b.explicit(4, b.sequence([b.set([b.sequence([b.oid(pki.oid.byName("commonName")),
    b.utf8("Not The Issuer")])])]));
  var wrongIssuerSerial = b.sequence([b.sequence([b.sequence([
    b.octetString(crypto.createHash("sha256").update(signer.cert).digest()),
    b.sequence([b.sequence([dirName]), b.integer(99n)])])])]);
  var vWrongIs = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificateV2", values: [wrongIssuerSerial] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-49 an identifier whose hash agrees but whose issuer and serial name another certificate " +
    "is reported (RFC 5035 clause 5)",
  vWrongIs.signers[0].cadesBaseline.conformant === false &&
    vWrongIs.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-signing-certificate-mismatch"; }));
  var weakBound = b.sequence([b.sequence([b.sequence([b.sequence([b.oid(pki.oid.byName("sha1")), b.nullValue()]),
    b.octetString(crypto.createHash("sha1").update(signer.cert).digest())])])]);
  var vWeakBound = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key },
    { additionalSignedAttributes: [{ type: "signingCertificateV2", values: [weakBound] }] }),
  { certs: [signer.cert], content: CONTENT });
  check("CT-49 a binding digest the rest of the toolkit refuses is reported here too",
    vWeakBound.signers[0].cadesBaseline.findings.some(function (f) { return f.code === "cms/cades-weak-certificate-binding"; }));

  // CT-50: the imprint verb will not produce a request for a token its own attach verb refuses by
  // default. There is no archived case on the producing side: the token does not exist yet.
  check("CT-50 a weak digest is refused by the imprint verb",
    (await codeOf(pki.cms.timestampImprint(base, { digestAlgorithm: "sha1" }))) === "cms/bad-input");

  // ---- the rest of each new verb's reachable refusals and forms ------------------------------
  // CT-51: the out-of-range message counts the signers the message actually carries, so the plural
  // arm is the one a multi-signer message reaches.
  var rangeErr = null;
  try { await pki.cms.timestampImprint(twoSigners, { signerIndex: 7 }); }
  catch (e) { rangeErr = e; }
  check("CT-51 the out-of-range refusal names how many signers the message carries",
    rangeErr !== null && rangeErr.code === "cms/bad-input" && rangeErr.message.indexOf("2 signers") !== -1);

  // CT-52: a token whose imprint names a digest no registry entry maps is refused by the attach
  // verb rather than hashed under a guessed algorithm.
  var oddDigestToken = await (async function () {
    var h = crypto.createHash("sha256").update(sigOctets).digest();
    var fields = [b.integer(1n), b.oid("1.2.3.4.1"),
      b.sequence([b.sequence([b.oid("1.2.3.4.5.6.7")]), b.octetString(h)]),
      b.integer(7n), b.generalizedTime(GENTIME)];
    return await pki.cms.sign(b.sequence(fields), { cert: tsa.cert, key: tsa.key },
      { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2",
        values: [pki.schema.smime.buildSigningCertificateV2(tsa.cert)] }] });
  })();
  check("CT-52 a token whose imprint digest is not in the registry is refused by the attach verb",
    (await codeOf(pki.cms.attachTimestamp(base, oddDigestToken))) === "cms/bad-input");

  // CT-53: the PEM form of the attach verb returns a CMS block the parser reads back.
  var pemOut = await pki.cms.attachTimestamp(base, token, { pem: true });
  check("CT-53 pem: true returns a CMS block carrying the same attribute",
    typeof pemOut === "string" && pemOut.indexOf("-----BEGIN CMS-----") === 0 &&
    pki.schema.cms.parse(pki.schema.cms.pemDecode(pemOut)).signerInfos[0].unsignedAttrs[0].name === "timeStampToken");

  // CT-54: a signer that signed the content directly carries no signed attributes at all, so there
  // is no claimed signing time to order the token against, and the row is judged on the rest.
  var attrless = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key }, { signedAttributes: false });
  var attrlessStamped = await pki.cms.attachTimestamp(attrless,
    await mintToken(tsa, signatureOctetsOf(attrless)));
  var vAttrless = await pki.cms.verify(attrlessStamped, { certs: [signer.cert], content: CONTENT });
  check("CT-54 a timestamp on a signer with no signed attributes verifies",
    vAttrless.signers[0].ok === true && vAttrless.signers[0].signatureTimeStamps[0].valid === true);
  check("CT-54 and that signature is reported non-conformant, a CAdES signature needing both the " +
    "content-type and the signing-certificate attribute",
  vAttrless.signers[0].cadesBaseline.conformant === false &&
    vAttrless.signers[0].cadesBaseline.findings.length === 2);

  // CT-56: what the imprint verb produces, the verifier must be able to read. The admitted set is
  // the verifier's own imprint set, so a digest this build will not verify a timestamp under is not
  // one it will take an imprint under either, whatever the general digest table carries.
  check("CT-56 a digest the timestamp verifier does not read is refused by the imprint verb",
    (await codeOf(pki.cms.timestampImprint(base, { digestAlgorithm: "sha3-256" }))) === "cms/bad-input");
  var sha3Token = await mintToken(tsa, sigOctets, { alg: "sha3-256" });
  check("CT-56 and the attach verb refuses a token whose imprint uses one",
    (await codeOf(pki.cms.attachTimestamp(base, sha3Token))) === "cms/bad-input");

  // CT-57: the expiry bound is decided on the instant the token NAMES, not on the millisecond a
  // Date can hold. RFC 3161 clause 2.4.2 lets genTime carry a fraction finer than that, so a token
  // issued one microsecond after the certificate expired is after it.
  var expShort = await makeSignerWithWindow("Boundary Signer", NB, new Date("2027-06-01T00:00:00Z"));
  var boundaryBase = await pki.cms.sign(CONTENT, { cert: expShort.cert, key: expShort.key });
  var subMs = Buffer.concat([Buffer.from([0x18, 22]), Buffer.from("20270601000000.000001Z", "ascii")]);
  var vSubMs = await pki.cms.verify(await pki.cms.attachTimestamp(boundaryBase,
    await mintToken(tsa, signatureOctetsOf(boundaryBase), { genTimeRaw: subMs })),
  { certs: [expShort.cert], content: CONTENT, time: new Date("2027-01-01T00:00:00Z") });
  check("CT-57 a genTime a fraction of a millisecond past the signer's notAfter is refused",
    vSubMs.signers[0].signatureTimeStamps[0].valid === false &&
    vSubMs.signers[0].signatureTimeStamps[0].code === "cms/timestamp-after-signer-expiry");
  var vOnTheBoundary = await pki.cms.verify(await pki.cms.attachTimestamp(boundaryBase,
    await mintToken(tsa, signatureOctetsOf(boundaryBase), { genTime: new Date("2027-06-01T00:00:00Z") })),
  { certs: [expShort.cert], content: CONTENT, time: new Date("2027-01-01T00:00:00Z") });
  check("CT-57 CONTROL a genTime ON the notAfter instant is not after it",
    vOnTheBoundary.signers[0].signatureTimeStamps[0].valid === true);

  // CT-55 CONTROL: the ordering rule reads the signing-time attribute without a guard around the
  // read, because the parser holds that value to a Time first. This pins the guarantee it leans on:
  // a message carrying an unreadable signing-time is refused at parse, so no row is ever judged
  // against a value nobody could decode.
  var brokenTime = replaceSignedAttr(base, "signingTime",
    b.sequence([b.oid(pki.oid.byName("signingTime")), b.set([b.octetString(Buffer.from("not a time"))])]));
  check("CT-55 CONTROL an unreadable signing-time is refused at parse (RFC 5652 sec. 11.3), which " +
    "is why the ordering rule can read it directly",
  (await codeOf(pki.cms.verify(brokenTime, { certs: [signer.cert], content: CONTENT }))) === "cms/bad-signing-time-attr");

  console.log("CHECKS " + helpers.getChecks());
}

// A signer whose certificate window is chosen, for the expiry rule.
async function makeSignerWithWindow(cn, nb, na) {
  var kp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var spki = await pki.key.export(kp.publicKey);
  var key = await pki.key.export(kp.privateKey);
  var cert = await pki.x509.sign({ subject: cn, subjectPublicKey: spki, notBefore: nb, notAfter: na,
    extensions: { keyUsage: ["digitalSignature"] } }, { key: key });
  return { cert: cert, key: key };
}

// Replace one signed attribute of the first SignerInfo with a hand-built one of the same type. The
// signature covers signedAttrs, so this breaks it on purpose: it is how a reader is driven with a
// value no signer would produce, and the signer verdict is expected to be false alongside it.
function replaceSignedAttr(cmsDer, typeName, attrDer) {
  var node = pki.asn1.decode(cmsDer);
  var signedData = node.children[1].children[0];
  var siSet = signedData.children[signedData.children.length - 1];
  var si = siSet.children[0];
  var wantOid = pki.oid.byName(typeName);
  var kids = si.children.map(function (k) {
    if (k.tagClass !== "context" || k.tagNumber !== 0) return k.bytes;
    var members = k.children.filter(function (m) {
      return pki.asn1.read.oid(m.children[0]) !== wantOid;
    }).map(function (m) { return m.bytes; });
    members.push(attrDer);
    var set = Buffer.from(b.set(members));
    set[0] = 0xA0;                 // [0] IMPLICIT SET OF Attribute
    return set;
  });
  var newSi = b.sequence(kids);
  var sdKids = signedData.children.map(function (k, i) {
    return i === signedData.children.length - 1 ? b.set([newSi]) : k.bytes;
  });
  return b.sequence([node.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
}

// Splice a hand-built Attribute into the first SignerInfo's unsignedAttrs, past the attach verb's
// own checks, so the READ side can be driven with a shape the writer refuses.
async function spliceRawUnsignedAttr(cmsDer, attrDer) {
  var node = pki.asn1.decode(cmsDer);
  var signedData = node.children[1].children[0];
  var siSet = signedData.children[signedData.children.length - 1];
  var si = siSet.children[0];
  var kids = si.children.map(function (k) { return k.bytes; });
  var setOf = b.set([attrDer]);
  var wire = Buffer.from(setOf); wire[0] = 0xA1;
  kids.push(wire);
  var newSi = b.sequence(kids);
  var sdKids = signedData.children.map(function (k, i) {
    return i === signedData.children.length - 1 ? b.set([newSi]) : k.bytes;
  });
  return b.sequence([node.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); });
}
