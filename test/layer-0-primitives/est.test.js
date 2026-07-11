// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.est (RFC 7030 / 8951 / 9908 EST protocol codecs + validators).
 * Transport-agnostic: every codec, validator, and builder is exercised without a
 * socket. RED-first: pki.est is undefined until the module lands, so every vector
 * throws -- the suite drives it GREEN. Fail-closed with typed est/* codes; the
 * certs-only + serverkeygen validators constrain the shipped cms.parse output.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = require("../helpers/vectors");
var b = pki.asn1.build;

var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_ENVELOPED_DATA = "1.2.840.113549.1.7.3";
var ID_DATA        = "1.2.840.113549.1.7.1";
var RSA_OID        = "1.2.840.113549.1.1.1";
var AES256_CBC     = "2.16.840.1.101.3.4.1.42";
var AES256_WRAP    = "2.16.840.1.101.3.4.1.45";
var ECDSA_SHA256   = "1.2.840.10045.4.3.2";
var SAN_OID        = "2.5.29.17";
var EXTREQ_OID     = "1.2.840.113549.1.9.14";
var DECRYPT_KEY_ID = "1.2.840.113549.1.9.16.2.37";
var CHALLENGE_PW   = "1.2.840.113549.1.9.7";

var KEM_ORI_OID = "1.2.840.113549.1.9.16.13.3";  // id-ori-kem (RFC 9629)
function algId(o) { return b.sequence([b.oid(o)]); }
// A KEM-recipient EnvelopedData ContentInfo (KEMRecipientInfo under the ori [4]
// arm, RFC 9629) with a subjectKeyIdentifier recipient. Uses unregistered kem /
// kdf / wrap OIDs so no algorithm-specific length rule fires.
function kemEnvelopedKeyCI(skid) {
  var kemri = b.sequence([
    b.integer(0n),                                     // version
    b.contextPrimitive(0, Buffer.from(skid)),          // rid = subjectKeyIdentifier [0]
    algId("1.3.6.1.4.1.99999.1"),                      // kem (unregistered)
    b.octetString(Buffer.from([1, 2, 3, 4])),          // kemct
    algId("1.3.6.1.4.1.99999.2"),                      // kdf (unregistered)
    b.integer(32n),                                    // kekLength
    algId("1.3.6.1.4.1.99999.3"),                      // wrap (unregistered)
    b.octetString(Buffer.from([0xAA, 0xBB])),          // encryptedKey
  ]);
  var ori = b.contextConstructed(4, Buffer.concat([b.oid(KEM_ORI_OID), kemri]));  // [4] { oriType, oriValue }
  var eci = b.sequence([b.oid(ID_SIGNED_DATA), algId(AES256_CBC), b.contextPrimitive(0, Buffer.from([0x11, 0x22]))]);
  var env = b.sequence([b.integer(3n), b.set([ori]), eci]);   // ori recipient -> EnvelopedData version 3
  return b.sequence([b.oid(ID_ENVELOPED_DATA), b.explicit(0, env)]);
}
// A minimal, structurally valid CMS EnvelopedData ContentInfo (one KTRI, opaque
// ciphertext) -- the server-generated encrypted-key shape (RFC 7030 sec. 4.4.2):
// the encapsulated content type is id-signedData (the SignedData holding the key).
// o.skid: a Buffer -> a subjectKeyIdentifier recipient (ktri v2, envelope v2);
// otherwise an issuerAndSerialNumber recipient (ktri v0, envelope v0).
// o.innerType overrides the encapsulated content type for the reject vector.
function envelopedKeyCI(o) {
  o = o || {};
  var iasn = b.sequence([b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("R")])])]), b.integer(9n)]);
  var rid = o.skid ? b.contextPrimitive(0, Buffer.from(o.skid)) : iasn;
  var ktri = b.sequence([b.integer(o.skid ? 2n : 0n), rid, algId(RSA_OID), b.octetString(Buffer.from([0xAA, 0xBB]))]);
  var eciChildren = [b.oid(o.innerType || ID_SIGNED_DATA), algId(AES256_CBC)];
  if (!o.detached) eciChildren.push(b.contextPrimitive(0, Buffer.from([0x11, 0x22])));   // encryptedContent [0] (omitted = detached)
  var eci = b.sequence(eciChildren);
  var env = b.sequence([b.integer(o.skid ? 2n : 0n), b.set([ktri]), eci]);
  return b.sequence([b.oid(ID_ENVELOPED_DATA), b.explicit(0, env)]);
}
// A structurally valid PKCS#10 CSR reusing REAL_CERT's raw subject + SPKI, with
// an optional extensionRequest SubjectAltName (o.san = raw GeneralNames DER). The
// signature is a placeholder BIT STRING (csr.parse is structural, not verifying).
function extReqAttr(sanVal, critical) {
  var extChildren = [b.oid(SAN_OID)];
  if (critical) extChildren.push(b.boolean(true));                                  // critical BOOLEAN (DEFAULT FALSE)
  extChildren.push(b.octetString(sanVal));
  var exts = b.sequence([b.sequence(extChildren)]);                                 // Extensions ::= SEQ OF Extension
  return b.sequence([b.oid(EXTREQ_OID), b.set([exts])]);                            // extensionRequest Attribute
}
function reenrollCsr(o) {
  o = o || {};
  var tbs = pki.asn1.decode(REAL_CERT).children[0];
  var subjectDer = o.subjectDer || tbs.children[5].bytes;
  var spkiDer = tbs.children[6].bytes;
  var sans = o.sans || (o.san !== undefined ? [o.san] : []);
  var attrList = sans.map(function (sv) { return extReqAttr(sv, o.criticalSan); });
  // [0] IMPLICIT SET OF Attribute: DER-sort when more than one is present.
  var attrs = attrList.length ? Buffer.concat(attrList.slice().sort(Buffer.compare)) : Buffer.alloc(0);
  var cri = b.sequence([b.integer(0n), subjectDer, spkiDer, b.contextConstructed(0, attrs)]);
  return b.sequence([cri, algId(ECDSA_SHA256), b.bitString(Buffer.from([1, 2, 3]), 0)]);
}

// A real EC certificate (universal-SEQUENCE plain-certificate CertificateChoices).
var REAL_CERT = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);

// Build a certs-only CMS Simple PKI Response (RFC 5272 sec. 4.1): SignedData with
// no eContent, EMPTY signerInfos, certificates in the certificates [0] field.
function certsOnly(certs, o) {
  o = o || {};
  var sd = [b.integer(BigInt(o.version === undefined ? 1 : o.version)), b.set(o.digestAlgs || []), b.sequence([b.oid(o.eContentType || ID_DATA)])];
  if (o.eContent) sd[2] = b.sequence([b.oid(o.eContentType || ID_DATA), b.explicit(0, b.octetString(o.eContent))]);
  if (certs) sd.push(b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))));
  if (o.crls) sd.push(b.contextConstructed(1, Buffer.concat(o.crls.slice().sort(Buffer.compare))));
  sd.push(b.set(o.signers || []));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}
// A minimal SignerInfo (issuerAndSerialNumber, no signedAttrs) for the not-certs-only vector.
function signerInfo() {
  var name = b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("S")])])]);
  return b.sequence([b.integer(1n), b.sequence([name, b.integer(1n)]), b.sequence([b.oid("2.16.840.1.101.3.4.2.1")]), b.sequence([b.oid("1.2.840.10045.4.3.2")]), b.octetString(Buffer.from([1, 2]))]);
}

// A minimal, structurally valid X.509 CRL (CertificateList): v1, no revoked list,
// the inner + outer signature algorithms agreeing (crl.parse checks that).
function validCrl() {
  var tbs = b.sequence([
    b.sequence([b.oid(ECDSA_SHA256)]),                                           // signature AlgId
    b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("Test CA")])])]),    // issuer
    b.utcTime(new Date("2026-01-01T00:00:00Z")),                                 // thisUpdate
  ]);
  return b.sequence([tbs, b.sequence([b.oid(ECDSA_SHA256)]), b.bitString(Buffer.from([0x00]), 0)]);
}

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

// ---- transfer codec (RFC 8951 sec. 3/3.1) ----------------------------
function testTransferCodec() {
  var der = certsOnly([REAL_CERT]);
  var b64 = der.toString("base64");
  // 30. CRLF-wrapped base64 decodes (receivers tolerate CR/LF/space/tab).
  var wrapped = b64.replace(/(.{16})/g, "$1\r\n");
  check("30. CRLF-wrapped base64 decodes", pki.est.transferDecode(wrapped).equals(der));
  // 31. bare single-line base64 decodes.
  check("31. bare base64 decodes", pki.est.transferDecode(b64).equals(der));
  // 31b. transferEncode round-trips (DER -> base64 -> DER).
  check("31b. transferEncode round-trip", pki.est.transferDecode(pki.est.transferEncode(der)).equals(der));
  // 32. a hostile non-alphabet byte -> est/bad-base64 fail-closed.
  check("32. hostile byte rejected", code(function () { pki.est.transferDecode(b64.slice(0, 8) + "*" + b64.slice(9)); }) === "est/bad-base64");
  // 32b. a detached-backed Buffer reads as zero-length: the text guard must fail
  // closed typed here (matching the byte boundaries), not decode as empty.
  check("32b. detached-backed Buffer rejected", code(function () {
    var ab = new ArrayBuffer(8); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.est.transferDecode(b);
  }) === "est/bad-input");
  // 32b. a non-canonical / truncated body (length 1 mod 4, e.g. "A") -> est/bad-base64,
  //      not a silently truncated decode.
  check("32b. truncated base64 rejected", code(function () { pki.est.transferDecode("A"); }) === "est/bad-base64");
  check("32c. unpadded base64 rejected", code(function () { pki.est.transferDecode("QQ"); }) === "est/bad-base64");
  // 33. an oversize body -> est/too-large BEFORE decode.
  check("33. oversize body rejected", code(function () { pki.est.transferDecode("A".repeat(pki.C.LIMITS.DER_MAX_BYTES * 2)); }) === "est/too-large");
  // 33b. a CRLF-wrapped body whose DECODED DER is exactly at the limit is accepted:
  //      the pre-decode ceiling allows normal line-wrapping whitespace (the wrapped
  //      form exceeds a base64-length-only cap even though the DER is within bounds).
  var atLimit = Buffer.alloc(pki.C.LIMITS.DER_MAX_BYTES, 0);
  var wrappedLimit = atLimit.toString("base64").replace(/(.{64})/g, "$1\r\n");
  check("33b. CRLF-wrapped near-limit body accepted", pki.est.transferDecode(wrappedLimit).length === atLimit.length);
}

// ---- certs-only validators (RFC 7030 sec. 4.1.3 / 4.2.3) -------------
function testCertsOnly() {
  // 34. a 3-cert certs-only response parses; certs surfaced raw, as-received.
  var three = pki.est.parseCertsOnly(certsOnly([REAL_CERT, REAL_CERT, REAL_CERT]));
  check("34. 3-cert certs-only parses", three.certificates.length === 3 && Buffer.isBuffer(three.certificates[0]));
  // 36. certs-only with NO certificates -> est/no-certificates.
  check("36. zero certificates rejected", code(function () { pki.est.parseCertsOnly(certsOnly(null)); }) === "est/no-certificates");
  // 37. a valid CRL present in crls is accepted and surfaced (RFC 5272 MAY).
  var withCrl = pki.est.parseCertsOnly(certsOnly([REAL_CERT], { crls: [validCrl()] }));
  check("37. crl surfaced", Array.isArray(withCrl.crls) && withCrl.crls.length === 1);
  // 37b. a [1] otherRevInfo RevocationInfoChoice is not a CRL -> est/bad-crl
  //      (an otherRevInfo forces SignedData version 5, RFC 5652 sec. 5.1).
  var otherRevInfo = b.contextConstructed(1, b.sequence([b.oid("1.3.6.1.5.5.7.16.2"), b.sequence([])]));
  check("37b. otherRevInfo choice rejected", code(function () { pki.est.parseCertsOnly(certsOnly([REAL_CERT], { crls: [otherRevInfo], version: 5 })); }) === "est/bad-crl");
  // 37c. a universal SEQUENCE that is not a CertificateList -> est/bad-crl.
  check("37c. non-CRL SEQUENCE rejected", code(function () { pki.est.parseCertsOnly(certsOnly([REAL_CERT], { crls: [b.sequence([b.integer(1n)])] })); }) === "est/bad-crl");
  // 38. a SignerInfo present -> est/not-certs-only (P2).
  check("38. signerInfo present rejected", code(function () { pki.est.parseCertsOnly(certsOnly([REAL_CERT], { signers: [signerInfo()] })); }) === "est/not-certs-only");
  // 39. eContent present -> est/not-certs-only.
  check("39. eContent present rejected", code(function () { pki.est.parseCertsOnly(certsOnly([REAL_CERT], { eContent: Buffer.from("x") })); }) === "est/not-certs-only");
  // 40. eContentType not id-data -> rejected.
  check("40. eContentType not id-data rejected", code(function () { pki.est.parseCertsOnly(certsOnly([REAL_CERT], { eContentType: ID_SIGNED_DATA, version: 3 })); }) === "est/not-certs-only");
  // 41. a [2] v2AttrCert CertificateChoices element -> est/bad-certificate-choice.
  var attrCertEl = b.contextConstructed(2, b.sequence([b.integer(1n)]));
  check("41. attrcert choice rejected", code(function () { pki.est.parseCertsOnly(certsOnly([attrCertEl], { version: 4 })); }) === "est/bad-certificate-choice");
  // 41b. a universal SEQUENCE that is not a valid X.509 Certificate -> est/bad-certificate
  //      (the tag check alone would let a malformed SEQUENCE through).
  check("41b. non-certificate SEQUENCE rejected", code(function () { pki.est.parseCertsOnly(certsOnly([b.sequence([b.integer(1n)])])); }) === "est/bad-certificate");
  // 42. findIssuedCert matches the issued cert by public key (SPKI bytes).
  var spki = pki.schema.x509.parse(REAL_CERT).subjectPublicKeyInfo;
  var found = pki.est.findIssuedCert([REAL_CERT], spki);
  check("42. findIssuedCert matches by public key", Buffer.isBuffer(found) && found.equals(REAL_CERT));
  check("42b. findIssuedCert null on no match", pki.est.findIssuedCert([REAL_CERT], { bytes: Buffer.from([0x30, 0x00]) }) === null);
}

// ---- serverkeygen (RFC 7030 sec. 4.4) -------------------------------
function testServerKeygen() {
  var pkcs8 = b.sequence([b.integer(0n), b.sequence([b.oid("1.3.101.112")]), b.octetString(Buffer.alloc(34, 7))]);
  var certPart = certsOnly([REAL_CERT]);
  function multipart(parts, boundary) {
    boundary = boundary || "estBoundary";
    var body = parts.map(function (p) { return "--" + boundary + "\r\nContent-Type: " + p.ct + "\r\n\r\n" + p.body; }).join("\r\n");
    return body + "\r\n--" + boundary + "--\r\n";
  }
  var ct = 'multipart/mixed; boundary="estBoundary"';
  // 43. pkcs8 part + certs-only part -> PrivateKeyInfo + cert list.
  var body43 = multipart([{ ct: "application/pkcs8", body: pkcs8.toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  var r43 = pki.est.parseServerKeygenResponse(body43, ct, {});
  check("43. two-part pkcs8 + certs", !!r43.privateKey && Array.isArray(r43.certificates) && r43.certificates.length === 1);
  // 45. missing terminal boundary -> est/bad-multipart.
  var noTerm = '--estBoundary\r\nContent-Type: application/pkcs8\r\n\r\n' + pkcs8.toString("base64") + "\r\n";
  check("45. missing terminator rejected", code(function () { pki.est.parseServerKeygenResponse(noTerm, ct, {}); }) === "est/bad-multipart");
  // 46. three parts -> rejected fail-closed.
  var body46 = multipart([{ ct: "application/pkcs8", body: "AA==" }, { ct: "application/pkcs8", body: "AA==" }, { ct: "text/plain", body: "x" }]);
  check("46. three parts rejected", code(function () { pki.est.parseServerKeygenResponse(body46, ct, {}); }) === "est/bad-multipart");
  // 46b. a look-alike key media type (application/pkcs8evil) is not a valid part -> est/bad-multipart.
  var body46b = multipart([{ ct: "application/pkcs8evil", body: pkcs8.toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  check("46b. look-alike key media type rejected", code(function () { pki.est.parseServerKeygenResponse(body46b, ct, {}); }) === "est/bad-multipart");
  // 46c. a stray smime-type=server-generated-key on the wrong media type is not a key part.
  var body46c = multipart([{ ct: "text/plain; smime-type=server-generated-key", body: "AA==" }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  check("46c. smime-type on wrong media type rejected", code(function () { pki.est.parseServerKeygenResponse(body46c, ct, {}); }) === "est/bad-multipart");
  // 46e. a smime-type-like substring inside another quoted parameter is NOT the
  //      smime-type parameter -> the part is not dispatched as the encrypted key.
  var body46e = multipart([{ ct: 'application/pkcs7-mime; name="; smime-type=server-generated-key"', body: "AA==" }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  check("46e. quoted smime-type substring not a key part", code(function () { pki.est.parseServerKeygenResponse(body46e, ct, { requestedEncryption: true }); }) === "est/bad-multipart");
  // 46f. the certificate part must be smime-type=certs-only too (RFC 7030 sec. 4.4.2);
  //      a bare application/pkcs7-mime cert part is rejected.
  var body46f = multipart([{ ct: "application/pkcs8", body: pkcs8.toString("base64") }, { ct: "application/pkcs7-mime", body: certPart.toString("base64") }]);
  check("46f. cert part missing certs-only rejected", code(function () { pki.est.parseServerKeygenResponse(body46f, ct, {}); }) === "est/bad-multipart");
  // 46d. a "--boundaryX" line is NOT an RFC 2046 delimiter -> it stays part body,
  //      not a split point (a raw-substring split would treat it as a boundary).
  var trick = "--bnd\r\nContent-Type: text/plain\r\n\r\nhello\r\n--bndX still body\r\nmore\r\n--bnd--\r\n";
  var tparts = pki.est.splitMultipartMixed(trick, 'multipart/mixed; boundary="bnd"');
  check("46d. non-delimiter --boundaryX stays body", tparts.length === 1 && /--bndX still body/.test(tparts[0].body));
  // 47. whitespace before the semicolon is tolerated (erratum 5779 rejected).
  var r47 = pki.est.parseServerKeygenResponse(body43, 'multipart/mixed ; boundary="estBoundary"', {});
  check("47. whitespace before ; tolerated", !!r47.privateKey);
  // 49. a cleartext pkcs8 part when encryption was requested -> est/expected-encrypted-key.
  check("49. cleartext key when encryption requested", code(function () { pki.est.parseServerKeygenResponse(body43, ct, { requestedEncryption: true }); }) === "est/expected-encrypted-key");
  // 48. an encrypted key part carrying a real EnvelopedData -> encryptedKey surfaced.
  var encPart = "application/pkcs7-mime; smime-type=server-generated-key";
  var body48 = multipart([{ ct: encPart, body: envelopedKeyCI().toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  var r48 = pki.est.parseServerKeygenResponse(body48, ct, { requestedEncryption: true });
  check("48. encrypted key part -> EnvelopedData surfaced", !!r48.encryptedKey && r48.encryptedKey.contentTypeName === "envelopedData" && r48.certificates.length === 1);
  // 48b. an encrypted-labeled key part that is a SignedData (not EnvelopedData) -> est/bad-key-part.
  var body48b = multipart([{ ct: encPart, body: certsOnly([REAL_CERT]).toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  check("48b. non-EnvelopedData encrypted key rejected", code(function () { pki.est.parseServerKeygenResponse(body48b, ct, { requestedEncryption: true }); }) === "est/bad-key-part");
  // 48b2. an EnvelopedData that encapsulates id-data (not id-signedData) -> est/bad-key-part.
  var body48b2 = multipart([{ ct: encPart, body: envelopedKeyCI({ innerType: ID_DATA }).toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  check("48b2. non-SignedData encapsulated content rejected", code(function () { pki.est.parseServerKeygenResponse(body48b2, ct, { requestedEncryption: true }); }) === "est/bad-key-part");
  // 48b3. a detached EnvelopedData (no encryptedContent) has no ciphertext -> est/bad-key-part.
  var body48b3 = multipart([{ ct: encPart, body: envelopedKeyCI({ detached: true }).toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  check("48b3. detached EnvelopedData key rejected", code(function () { pki.est.parseServerKeygenResponse(body48b3, ct, { requestedEncryption: true }); }) === "est/bad-key-part");
  // 48c. the recipient key id matches the advertised decryptKeyID -> accepted.
  var kid = Buffer.from([0x33, 0x44]);
  var bodySkid = multipart([{ ct: encPart, body: envelopedKeyCI({ skid: kid }).toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  var r48c = pki.est.parseServerKeygenResponse(bodySkid, ct, { requestedEncryption: true, expectedRecipientKeyId: kid });
  check("48c. matching recipient key id accepted", !!r48c.encryptedKey);
  // 48d. a DIFFERENT recipient key id than advertised -> est/recipient-mismatch fail-closed.
  check("48d. recipient key id mismatch rejected", code(function () { pki.est.parseServerKeygenResponse(bodySkid, ct, { requestedEncryption: true, expectedRecipientKeyId: Buffer.from([0x99, 0x99]) }); }) === "est/recipient-mismatch");
  // 48e. a KEM-recipient (RFC 9629) key id is collected too -> a matching one is accepted.
  var bodyKem = multipart([{ ct: encPart, body: kemEnvelopedKeyCI(kid).toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  var r48e = pki.est.parseServerKeygenResponse(bodyKem, ct, { requestedEncryption: true, expectedRecipientKeyId: kid });
  check("48e. KEM recipient key id matched", !!r48e.encryptedKey);
  // 48f-g. an issuerAndSerialNumber recipient (the server mapped the advertised
  //        identifier to a cert) is matched by opts.expectedRecipientIssuerSerial.
  var recipIssuer = b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("R")])])]);
  var bodyIas = multipart([{ ct: encPart, body: envelopedKeyCI().toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: certPart.toString("base64") }]);
  var r48f = pki.est.parseServerKeygenResponse(bodyIas, ct, { requestedEncryption: true, expectedRecipientIssuerSerial: { issuer: recipIssuer, serialNumber: 9n } });
  check("48f. issuerAndSerial recipient matched", !!r48f.encryptedKey);
  check("48g. issuerAndSerial mismatch rejected", code(function () { pki.est.parseServerKeygenResponse(bodyIas, ct, { requestedEncryption: true, expectedRecipientIssuerSerial: { issuer: recipIssuer, serialNumber: 42n } }); }) === "est/recipient-mismatch");
}

// ---- builders -------------------------------------------------------
function testBuilders() {
  // 50. a 12-byte channel binding -> challengePassword = its base64; parse-back shows the attr.
  var attr = pki.est.challengePasswordFromTlsUnique(Buffer.alloc(12, 0x5a));
  check("50. challengePassword attr from tls-unique", Buffer.isBuffer(attr) && pki.asn1.decode(attr).children[0] && pki.asn1.read.oid(pki.asn1.decode(attr).children[0]) === CHALLENGE_PW);
  // 50b. a > 190-byte binding (base64 > 255) -> est/tls-unique-too-long.
  check("50b. over-long tls-unique rejected", code(function () { pki.est.challengePasswordFromTlsUnique(Buffer.alloc(200, 1)); }) === "est/tls-unique-too-long");
  // 51. decrypt-key attributes encode to attributes carrying the right OID.
  var dk = pki.est.decryptKeyIdentifierAttr(Buffer.from([1, 2, 3]));
  check("51. decryptKeyIdentifier attr", pki.asn1.read.oid(pki.asn1.decode(dk).children[0]) === DECRYPT_KEY_ID);
  var caps = pki.est.smimeCapabilitiesAttr([{ capabilityID: AES256_WRAP }]);
  check("51b. smimeCapabilities attr", pki.asn1.read.oid(pki.asn1.decode(caps).children[0]) === "1.2.840.113549.1.9.15");
  // 52. csrattrs -> plan: template priority (a CsrAttrs with template + legacy uses template only).
  var tplAttr = b.sequence([b.oid("1.2.840.113549.1.9.16.2.61"), b.set([b.sequence([b.integer(0n), b.contextConstructed(1, Buffer.alloc(0))])])]);
  var legacy = b.sequence([b.oid(RSA_OID), b.set([b.integer(2048n)])]);
  var csrattrsParsed = pki.schema.csrattrs.parse(b.sequence([tplAttr, legacy]));
  var plan = pki.est.buildEnrollAttributes(csrattrsParsed);
  check("52. template priority: plan derived from template only", plan.fromTemplate === true);
  // 53. challengePassword OID in the response -> channelBindingRequired, no password invented.
  var plan53 = pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(b.sequence([b.oid(CHALLENGE_PW)])));
  check("53. challengePassword -> channelBindingRequired flag", plan53.channelBindingRequired === true);
  // 53b. an empty rsaEncryption key-type hint ("any size") is carried into the plan.
  var planAny = pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(b.sequence([b.sequence([b.oid(RSA_OID), b.set([])])])));
  check("53b. empty key-type hint -> keyType any", !!planAny.keyType && planAny.keyType.type === "rsaEncryption" && planAny.keyType.keySize === null);
  // 53c. two key-type attributes (rsaEncryption + ecPublicKey) -> ambiguous, fail closed
  //      (RFC 9908 sec. 3.2 non-template form: exactly one key-type attribute).
  var twoKt = b.sequence([b.sequence([b.oid(RSA_OID), b.set([])]), b.sequence([b.oid("1.2.840.10045.2.1"), b.set([])])]);
  check("53c. two key-type attributes rejected", code(function () { pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(twoKt)); }) === "est/ambiguous-key-type");
  // 53d. a registered-but-unmodeled bare OID (ecdsaWithSHA384 signature-scheme
  //      instruction, RFC 8951) is surfaced on unhandled, never silently dropped.
  var sigPlan = pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(b.sequence([b.oid("1.2.840.10045.4.3.3")])));
  check("53d. registered unmodeled OID surfaced", sigPlan.unhandled.length === 1 && sigPlan.unhandled[0].oid === "1.2.840.10045.4.3.3" && sigPlan.unhandled[0].name === "ecdsaWithSHA384");
  // 53e. a non-RSA/EC key type (Ed25519) is modeled as keyType, not unhandled.
  var planEd = pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(b.sequence([b.sequence([b.oid("1.3.101.112"), b.set([])])])));
  check("53e. Ed25519 key-type modeled", !!planEd.keyType && planEd.keyType.type === "Ed25519" && planEd.unhandled.length === 0);
  // 53f. rsaEncryption + Ed25519 are two key types -> ambiguous, fail closed.
  var twoKt2 = b.sequence([b.sequence([b.oid(RSA_OID), b.set([])]), b.sequence([b.oid("1.3.101.112"), b.set([])])]);
  check("53f. mixed RSA + Ed25519 key types rejected", code(function () { pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(twoKt2)); }) === "est/ambiguous-key-type");
  // 53g. an undecoded key type's raw values (RFC 9908 key-type parameters) are
  //      surfaced on keyType.values, never silently dropped.
  var planEdParam = pki.est.buildEnrollAttributes(pki.schema.csrattrs.parse(b.sequence([b.sequence([b.oid("1.3.101.112"), b.set([b.integer(1n)])])])));
  check("53g. non-RSA key-type params preserved", planEdParam.keyType.type === "Ed25519" && Array.isArray(planEdParam.keyType.values) && planEdParam.keyType.values.length === 1);
  // 54. reenrollGuard: the new CSR carries the old cert's subject bytes; a mutated subject rejects.
  check("54. reenrollGuard surfaces the old subject for reuse", pki.est.reenrollGuard(REAL_CERT).subjectDn === pki.schema.x509.parse(REAL_CERT).subject.dn);
  var OLD_SAN = pki.schema.x509.parse(REAL_CERT).extensions.filter(function (e) { return e.oid === SAN_OID; })[0].value;
  // 54b. a re-enroll CSR reusing subject + the identical SAN passes.
  check("54b. matching subject + SAN accepted", pki.est.reenrollGuard(REAL_CERT, reenrollCsr({ san: OLD_SAN })).subjectDn === pki.schema.x509.parse(REAL_CERT).subject.dn);
  // 54c. the old cert has a SAN but the CSR omits it -> est/reenroll-san-mismatch (RFC 7030 sec. 4.2.2 MUST).
  check("54c. omitted SAN rejected", code(function () { pki.est.reenrollGuard(REAL_CERT, reenrollCsr({})); }) === "est/reenroll-san-mismatch");
  // 54d. the CSR requests a DIFFERENT SAN -> est/reenroll-san-mismatch.
  var otherSan = b.sequence([b.contextPrimitive(2, Buffer.from("other.example", "latin1"))]);
  check("54d. changed SAN rejected", code(function () { pki.est.reenrollGuard(REAL_CERT, reenrollCsr({ san: otherSan })); }) === "est/reenroll-san-mismatch");
  // 54d2. the same SAN names but the critical flag flipped -> est/reenroll-san-mismatch
  //       ("identical" covers criticality, not just the GeneralNames bytes).
  check("54d2. flipped SAN criticality rejected", code(function () { pki.est.reenrollGuard(REAL_CERT, reenrollCsr({ san: OLD_SAN, criticalSan: true })); }) === "est/reenroll-san-mismatch");
  // 54e. a mutated subject still rejects (subject guard precedes the SAN guard).
  var otherSubject = b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("other")])])]);
  check("54e. mutated subject rejected", code(function () { pki.est.reenrollGuard(REAL_CERT, reenrollCsr({ subjectDer: otherSubject, san: OLD_SAN })); }) === "est/reenroll-subject-mismatch");
  // 54f. two extensionRequest attributes -> ambiguous, fail closed (a later one
  //      could request a different SAN than the DER-first one).
  check("54f. duplicate extensionRequest rejected", code(function () { pki.est.reenrollGuard(REAL_CERT, reenrollCsr({ sans: [OLD_SAN, b.sequence([b.contextPrimitive(2, Buffer.from("x.example", "latin1"))])] })); }) === "est/reenroll-ambiguous-request");
  // 54g. the SAME rendered DN re-encoded with a different ASN.1 string type is
  //      NOT byte-identical -> rejected (RFC 7030 sec. 4.2.2 compares DER, not DN).
  function atv(o, enc, val) { return b.set([b.sequence([b.oid(o), enc(val)])]); }
  var sameDnDiffDer = b.sequence([atv("2.5.4.6", b.printable, "US"), atv("2.5.4.8", b.utf8, "California"), atv("2.5.4.10", b.utf8, "blamejs pki"), atv("2.5.4.11", b.utf8, "Test"), atv("2.5.4.3", b.printable, "pkijs.com")]);
  check("54g. same DN string encoding differs -> byte-mismatch rejected",
    pki.schema.csr.parse(reenrollCsr({ subjectDer: sameDnDiffDer, san: OLD_SAN })).subject.dn === pki.schema.x509.parse(REAL_CERT).subject.dn &&
    code(function () { pki.est.reenrollGuard(REAL_CERT, reenrollCsr({ subjectDer: sameDnDiffDer, san: OLD_SAN })); }) === "est/reenroll-subject-mismatch");
  // 55. path builder (T2).
  check("55. path cacerts", pki.est.paths("https://ca.example").cacerts === "https://ca.example/.well-known/est/cacerts");
  check("55b. labeled path", pki.est.paths("https://ca.example", { label: "label1" }).simpleenroll === "https://ca.example/.well-known/est/label1/simpleenroll");
  check("55c. label == op name rejected", code(function () { pki.est.paths("https://ca.example", { label: "cacerts" }); }) === "est/bad-label");
  check("55d. label with slash rejected", code(function () { pki.est.paths("https://ca.example", { label: "a/b" }); }) === "est/bad-label");
  // 55e-g. dot-segment + reserved-character labels retarget the URL -> rejected.
  check("55e. dot-segment label rejected", code(function () { pki.est.paths("https://ca.example", { label: ".." }); }) === "est/bad-label");
  check("55f. query-char label rejected", code(function () { pki.est.paths("https://ca.example", { label: "a?b" }); }) === "est/bad-label");
  check("55g. fragment-char label rejected", code(function () { pki.est.paths("https://ca.example", { label: "a#b" }); }) === "est/bad-label");
}

// ---- HTTP classification (RFC 7030 sec. 4.2.3 / RFC 8951 sec. 3.3/3.4) ----
function testClassify() {
  // 56. 200 with the wrong content-type -> est/bad-content-type.
  check("56. 200 wrong content-type", code(function () { pki.est.classifyResponse(200, { "content-type": "text/html" }, Buffer.alloc(0), { op: "cacerts" }); }) === "est/bad-content-type");
  // 56b. a look-alike type that only PREFIXES the required token -> rejected (exact token).
  check("56b. content-type prefix look-alike rejected", code(function () { pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mimeevil" }, Buffer.alloc(0), { op: "cacerts" }); }) === "est/bad-content-type");
  // 56c. the exact token, bare or with parameters -> ok.
  check("56c. exact content-type with params ok", pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime; smime-type=certs-only" }, Buffer.alloc(0), { op: "cacerts" }).status === "ok");
  check("56d. exact content-type bare ok", pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime" }, Buffer.alloc(0), { op: "cacerts" }).status === "ok");
  // 56e-g. simpleenroll requires smime-type=certs-only (RFC 7030 sec. 4.2.3): a
  //        different S/MIME message type or a missing smime-type is not a success.
  check("56e. enroll wrong smime-type rejected", code(function () { pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime; smime-type=CMC-response" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-content-type");
  check("56f. enroll certs-only ok", pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime; smime-type=certs-only" }, Buffer.alloc(0), { op: "simpleenroll" }).status === "ok");
  check("56g. enroll missing smime-type rejected", code(function () { pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-content-type");
  // 57. 202 with Retry-After surfaced (seconds); missing Retry-After -> est/missing-retry-after.
  var r202 = pki.est.classifyResponse(202, { "retry-after": "120" }, Buffer.alloc(0), { op: "simpleenroll" });
  check("57. 202 retry-after surfaced bounded", r202.status === "retry" && r202.retryAfterSeconds === 120);
  check("57b. 202 missing retry-after", code(function () { pki.est.classifyResponse(202, {}, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/missing-retry-after");
  // 57c. an HTTP-date Retry-After -> retryAfterDate (epoch ms); with opts.now -> bounded seconds.
  var when = Date.parse("Wed, 01 Jan 2020 00:00:00 GMT");
  var r57c = pki.est.classifyResponse(202, { "retry-after": "Wed, 01 Jan 2020 00:00:00 GMT" }, Buffer.alloc(0), { op: "simpleenroll", now: when - 120000 });
  check("57c. HTTP-date retry-after -> date + bounded seconds", r57c.retryAfterDate === when && r57c.retryAfterSeconds === 120);
  var r57d = pki.est.classifyResponse(202, { "retry-after": "Wed, 01 Jan 2020 00:00:00 GMT" }, Buffer.alloc(0), { op: "simpleenroll" });
  check("57d. HTTP-date retry-after without now -> date, seconds null", r57d.retryAfterDate === when && r57d.retryAfterSeconds === null);
  // 57e. an uninterpretable Retry-After -> est/bad-retry-after (no delay-less retry verdict).
  check("57e. garbage retry-after rejected", code(function () { pki.est.classifyResponse(202, { "retry-after": "soon" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-retry-after");
  // 57e2. a non-HTTP-date string Date.parse would accept (ISO "2026-07-10") is NOT a
  //       valid Retry-After header value -> est/bad-retry-after.
  check("57e2. ISO-form retry-after rejected", code(function () { pki.est.classifyResponse(202, { "retry-after": "2026-07-10" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-retry-after");
  // 57e3. a syntactically-shaped but impossible calendar date (Feb 31) that V8 would
  //       normalize to March -> est/bad-retry-after, not an accepted retry date.
  check("57e3. impossible calendar date rejected", code(function () { pki.est.classifyResponse(202, { "retry-after": "Wed, 31 Feb 2020 00:00:00 GMT" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-retry-after");
  // 57i. the obsolete asctime form carries no GMT token -> it MUST be parsed as
  //      UTC (Date.UTC), not local time, so retryAfterDate is timezone-independent.
  var ascWhen = Date.UTC(1994, 10, 6, 8, 49, 37);
  check("57i. asctime retry-after parsed as UTC", pki.est.classifyResponse(202, { "retry-after": "Sun Nov  6 08:49:37 1994" }, Buffer.alloc(0), { op: "simpleenroll" }).retryAfterDate === ascWhen);
  // 57f-g. an overflowing / nonsensical delay-seconds -> est/bad-retry-after, never an unsafe number.
  check("57f. overflow retry-after rejected", code(function () { pki.est.classifyResponse(202, { "retry-after": "99999999999999999999" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-retry-after");
  check("57g. over-cap retry-after rejected", code(function () { pki.est.classifyResponse(202, { "retry-after": "40000000" }, Buffer.alloc(0), { op: "simpleenroll" }); }) === "est/bad-retry-after");
  // 57h. an HTTP-date more than a year ahead (with opts.now) exceeds the same cap.
  var farDate = "Wed, 01 Jan 2020 00:00:00 GMT";
  check("57h. far-future HTTP-date rejected", code(function () { pki.est.classifyResponse(202, { "retry-after": farDate }, Buffer.alloc(0), { op: "simpleenroll", now: Date.parse(farDate) - 63072000000 }); }) === "est/bad-retry-after");
  // 58. 204/404 on csrattrs -> "none available" verdict; 204 on cacerts -> error.
  check("58. 204 csrattrs -> none-available", pki.est.classifyResponse(204, {}, Buffer.alloc(0), { op: "csrattrs" }).status === "none-available");
  check("58b. 404 csrattrs -> none-available", pki.est.classifyResponse(404, {}, Buffer.alloc(0), { op: "csrattrs" }).status === "none-available");
  check("58c. 204 cacerts -> error", code(function () { pki.est.classifyResponse(204, {}, Buffer.alloc(0), { op: "cacerts" }); }).indexOf("est/") === 0);
  // 59. a 4xx text/plain body surfaced capped as the diagnostic on the typed error.
  var c59 = code(function () { pki.est.classifyResponse(400, { "content-type": "text/plain" }, Buffer.from("bad request details"), { op: "simpleenroll" }); });
  check("59. 4xx typed http-error", c59 === "est/http-error");
  // 60. fullcmc is a real path (paths() emits it) but its CMC response is deferred
  //     -> a precise est/fullcmc-not-supported, never a silently-accepted 200.
  check("60. fullcmc classification rejected", code(function () { pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime" }, Buffer.alloc(0), { op: "fullcmc" }); }) === "est/fullcmc-not-supported");
  // 60b. an unrecognized operation name -> est/unsupported-operation (not a pass).
  check("60b. unrecognized op rejected", code(function () { pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime" }, Buffer.alloc(0), { op: "bogus" }); }) === "est/unsupported-operation");
}

function run() {
  testTransferCodec();
  testCertsOnly();
  testServerKeygen();
  testBuilders();
  testClassify();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
