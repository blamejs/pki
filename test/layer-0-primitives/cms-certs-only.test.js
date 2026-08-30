// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.certsOnly / pki.cms.parseCertsOnly / pki.cms.isCertsOnly and
 * pki.smime.buildCertsOnly (RFC 8551 sec. 3.8 certificate-management message / RFC 5652 sec. 5.1
 * degenerate SignedData). A certs-only message carries certificates and/or CRLs and nothing else:
 * an id-data encapContentInfo with the eContent ABSENT, an EMPTY signerInfos, an EMPTY
 * digestAlgorithms. The builder emits it, the reader recovers the raw cert/CRL DER (permitting a
 * CRL-only message, the RFC 8551 vs RFC 5272 fault line), and the recognizer classifies it
 * structurally. Malformed input fails closed with a typed cms/* error.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var vectors = require("../helpers/vectors");
var signing = require("../helpers/signing");
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }

var ID_DATA = O("data");
var ID_SIGNED_DATA = O("signedData");
var ECDSA_SHA256 = "1.2.840.10045.4.3.2";

// Two structurally different real X.509 certificates (RSA + EC): a "certs" claim tested with >= 2 members.
var CERT_A = signing.makeSigner("rsa").cert;
var CERT_B = signing.makeSigner("ec-p256").cert;
var CERT_EC = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);

// A minimal, structurally valid X.509 CRL (CertificateList): v1, no revoked list, the inner + outer
// signature algorithms agreeing (crl.parse checks that).
function validCrl(cn) {
  var tbs = b.sequence([
    b.sequence([b.oid(ECDSA_SHA256)]),
    b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn || "Test CA")])])]),
    b.utcTime(new Date("2026-01-01T00:00:00Z")),
  ]);
  return b.sequence([tbs, b.sequence([b.oid(ECDSA_SHA256)]), b.bitString(Buffer.from([0x00]), 0)]);
}

// A hand-built certs-only SignedData ContentInfo (the adversarial-input builder, independent of our
// producer): reused for the reader reject vectors.
function handCertsOnly(certs, o) {
  o = o || {};
  var sd = [b.integer(BigInt(o.version === undefined ? 1 : o.version)), b.set(o.digestAlgs || []), b.sequence([b.oid(o.eContentType || ID_DATA)])];
  if (o.eContent) sd[2] = b.sequence([b.oid(o.eContentType || ID_DATA), b.explicit(0, b.octetString(o.eContent))]);
  if (certs) sd.push(b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))));
  if (o.crls) sd.push(b.contextConstructed(1, Buffer.concat(o.crls.slice().sort(Buffer.compare))));
  sd.push(b.set(o.signers || []));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}
function handSignerInfo() {
  var name = b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("S")])])]);
  return b.sequence([b.integer(1n), b.sequence([name, b.integer(1n)]), b.sequence([b.oid("2.16.840.1.101.3.4.2.1")]), b.sequence([b.oid("1.2.840.10045.4.3.2")]), b.octetString(Buffer.from([1, 2]))]);
}

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
async function acode(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

async function run() {
  // ==== Accept / round-trip ====

  // 1. two certs -> a degenerate SignedData; parse sees signerInfos empty + both certs; the reader
  //    returns both byte-identical.
  var out1 = pki.cms.certsOnly([CERT_A, CERT_B]);
  var p1 = pki.schema.cms.parse(out1);
  check("1. certsOnly([A,B]) is a signedData, version 1, zero signerInfos, two certs",
    p1.contentTypeName === "signedData" && p1.version === 1 && p1.signerInfos.length === 0 && p1.certificates.length === 2);
  var r1 = pki.cms.parseCertsOnly(out1);
  var got1 = r1.certificates.slice().sort(Buffer.compare);
  var want1 = [CERT_A, CERT_B].slice().sort(Buffer.compare);
  check("1a. reader returns both certs byte-identical",
    r1.certificates.length === 2 && Buffer.compare(got1[0], want1[0]) === 0 && Buffer.compare(got1[1], want1[1]) === 0 && r1.crls.length === 0);

  // 2. single cert + a CRL round-trips with one cert and one CRL.
  var crlA = validCrl();
  var out2 = pki.cms.certsOnly(CERT_A, { crls: [crlA] });
  var r2 = pki.cms.parseCertsOnly(out2);
  check("2. cert + CRL round-trips (one cert, one CRL, both byte-identical)",
    r2.certificates.length === 1 && Buffer.compare(r2.certificates[0], CERT_A) === 0 &&
    r2.crls.length === 1 && Buffer.compare(r2.crls[0], crlA) === 0);

  // 3. CRL-only: no certs, one CRL -> a valid message (the RFC 8551 vs RFC 5272 fault line).
  var out3 = pki.cms.certsOnly([], { crls: [crlA] });
  var r3 = pki.cms.parseCertsOnly(out3);
  check("3. CRL-only message is valid; reader returns { certificates: [], crls: [crlA] }",
    r3.certificates.length === 0 && r3.crls.length === 1 && Buffer.compare(r3.crls[0], crlA) === 0);

  // 4. PEM output round-trips through the reader.
  var pem4 = pki.cms.certsOnly([CERT_A], { pem: true });
  check("4. certsOnly(..,{pem:true}) is a PEM string", typeof pem4 === "string" && pem4.indexOf("-----BEGIN") >= 0);
  var r4 = pki.cms.parseCertsOnly(pem4);
  check("4a. the PEM reader recovers the cert byte-identical",
    r4.certificates.length === 1 && Buffer.compare(r4.certificates[0], CERT_A) === 0);

  // 5. the S/MIME frame carries the certs-only body.
  var mime5 = pki.smime.buildCertsOnly([CERT_A]);
  var mimeStr = mime5.toString("latin1");
  check("5. buildCertsOnly emits application/pkcs7-mime; smime-type=certs-only; name=smime.p7c",
    /Content-Type: application\/pkcs7-mime; smime-type=certs-only; name=smime\.p7c/.test(mimeStr));
  check("5a. the frame declares base64 + attachment filename=smime.p7c",
    /Content-Transfer-Encoding: base64/.test(mimeStr) && /Content-Disposition: attachment; filename=smime\.p7c/.test(mimeStr));
  var bodyB64 = mimeStr.split("\r\n\r\n")[1].replace(/[\r\n]/g, "");
  var bodyDer = Buffer.from(bodyB64, "base64");
  check("5b. the base64 body decodes to the same DER as pki.cms.certsOnly([A])",
    Buffer.compare(bodyDer, pki.cms.certsOnly([CERT_A])) === 0);

  // ==== Adversarial ====

  // 6. all-empty (no certs, no CRLs) is refused.
  check("6. certsOnly([]) with no crls -> cms/bad-input", code(function () { pki.cms.certsOnly([]); }) === "cms/bad-input");
  check("6a. certsOnly() with nothing -> cms/bad-input", code(function () { pki.cms.certsOnly(); }) === "cms/bad-input");

  // 7. a non-certificate SEQUENCE is refused, never embedded.
  check("7. certsOnly([notACert]) -> cms/bad-input", code(function () { pki.cms.certsOnly([b.sequence([b.integer(1n)])]); }) === "cms/bad-input");

  // 8. a non-CRL passed as a CRL is refused.
  check("8. certsOnly(A,{crls:[notACrl]}) -> cms/bad-input", code(function () { pki.cms.certsOnly(CERT_A, { crls: [b.sequence([b.integer(1n)])] }); }) === "cms/bad-input");

  // 9. a tagged CertificateChoices alternative (an attribute cert [2]) is not a plain certificate.
  var attrCertEl = b.contextConstructed(2, b.sequence([b.integer(1n)]).slice(2));   // raw [2] tagged, non-universal
  check("9. a tagged CertificateChoices alternative -> refused", code(function () { pki.cms.certsOnly([attrCertEl]); }) === "cms/bad-input");

  // 10. a sparse / holey / nullish certs array is a typed error, driven fast.
  var sparse = []; sparse[3] = CERT_A;   // holes at 0..2
  check("10. sparse certs array -> cms/bad-input", code(function () { pki.cms.certsOnly(sparse); }) === "cms/bad-input");
  check("10a. [null] certs array -> cms/bad-input", code(function () { pki.cms.certsOnly([null]); }) === "cms/bad-input");

  // 11. a mutating caller array: the emitted message reflects the door snapshot, not the late value.
  var mutate = [CERT_A];
  var swapped = false;
  Object.defineProperty(mutate, 0, { configurable: true, enumerable: true, get: function () { if (swapped) return CERT_B; swapped = true; return CERT_A; } });
  var out11 = pki.cms.certsOnly(mutate);
  var r11 = pki.cms.parseCertsOnly(out11);
  check("11. a mutating certs array is snapshotted at the door (emits the read value, one cert)",
    r11.certificates.length === 1 && Buffer.compare(r11.certificates[0], CERT_A) === 0);

  // ==== Dispatch / recognizer ====

  // 12. isCertsOnly: true for a certs-only message, false for a signed message and an EnvelopedData.
  check("12. isCertsOnly(certsOnly([A])) === true", pki.cms.isCertsOnly(pki.cms.certsOnly([CERT_A])) === true);
  var rsaSigner = signing.makeSigner("rsa");
  var signed = await pki.cms.sign(Buffer.from("hi"), [{ cert: rsaSigner.cert, key: rsaSigner.key }]);
  check("12a. isCertsOnly(a one-signer SignedData) === false", pki.cms.isCertsOnly(signed) === false);
  var rec = signing.makeRecipient("rsa");
  var env = await pki.cms.encrypt(Buffer.from("secret"), [{ cert: rec.cert }]);
  check("12b. isCertsOnly(an EnvelopedData) === false", pki.cms.isCertsOnly(env) === false);

  // 13. the reader refuses a non-degenerate SignedData.
  check("13. parseCertsOnly(a SignedData with eContent) -> cms/not-certs-only",
    code(function () { pki.cms.parseCertsOnly(handCertsOnly([CERT_EC], { eContent: Buffer.from("x") })); }) === "cms/not-certs-only");
  check("13a. parseCertsOnly(a one-signer SignedData) -> cms/not-certs-only",
    code(function () { pki.cms.parseCertsOnly(handCertsOnly([CERT_EC], { signers: [handSignerInfo()] })); }) === "cms/not-certs-only");

  // ==== Strict-DER / raw-exactness ====

  // 14. digestAlgorithms and signerInfos are each exactly the empty SET (31 00), and the
  //     encapContentInfo has NO [0] eContent child.
  var node = pki.asn1.decode(pki.cms.certsOnly([CERT_A]));
  var sd = node.children[1].children[0];                 // content [0] EXPLICIT -> SignedData SEQUENCE
  var digestAlgs = sd.children[1];                        // digestAlgorithms SET
  var encap = sd.children[2];                             // encapContentInfo SEQUENCE
  var signerInfos = sd.children[sd.children.length - 1];  // signerInfos SET (last field)
  check("14. digestAlgorithms is the empty SET 31 00", Buffer.compare(digestAlgs.bytes, Buffer.from([0x31, 0x00])) === 0);
  check("14a. signerInfos is the empty SET 31 00", Buffer.compare(signerInfos.bytes, Buffer.from([0x31, 0x00])) === 0);
  check("14b. encapContentInfo has no eContent child (one child: eContentType)", encap.children.length === 1);

  // 15. two certs supplied out of DER order come back SET-OF sorted (X.690 sec. 11.6).
  var lo = Buffer.compare(CERT_A, CERT_B) < 0 ? CERT_A : CERT_B;
  var hi = lo === CERT_A ? CERT_B : CERT_A;
  var out15 = pki.cms.certsOnly([hi, lo]);               // supplied high-then-low
  var r15 = pki.cms.parseCertsOnly(out15);
  check("15. certificates [0] members are ascending DER order regardless of input order",
    Buffer.compare(r15.certificates[0], lo) === 0 && Buffer.compare(r15.certificates[1], hi) === 0);

  // 16. determinism + re-parse identity: the same input emits identical bytes and re-parses.
  check("16. certsOnly is deterministic (same input -> identical bytes)",
    Buffer.compare(pki.cms.certsOnly([CERT_A, CERT_B]), pki.cms.certsOnly([CERT_A, CERT_B])) === 0);
  check("16a. the emitted message re-parses through the strict CMS parser",
    pki.schema.cms.parse(pki.cms.certsOnly([CERT_A])).signerInfos.length === 0);

  // ==== Options door ====
  check("17. an unknown option is refused", code(function () { pki.cms.certsOnly([CERT_A], { bogus: 1 }); }) === "cms/bad-input");

  // ==== Input-form coverage (PEM string, byte-source PEM, PKCS7 armor, wrong types) ====
  function pem(label, der) { return "-----BEGIN " + label + "-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END " + label + "-----\n"; }

  // 18. a PEM-string certificate input round-trips through the builder.
  var out18 = pki.cms.certsOnly([pem("CERTIFICATE", CERT_A)]);
  check("18. a PEM-string certificate is accepted", Buffer.compare(pki.cms.parseCertsOnly(out18).certificates[0], CERT_A) === 0);
  // 19. a non-Buffer, non-string certificate entry is refused.
  check("19. a numeric certificate entry -> cms/bad-input", code(function () { pki.cms.certsOnly([123]); }) === "cms/bad-input");
  // 20. a PEM-string CRL input round-trips (CRL-only, the CRL through the string path).
  var out20 = pki.cms.certsOnly([], { crls: [pem("X509 CRL", crlA)] });
  check("20. a PEM-string CRL is accepted", Buffer.compare(pki.cms.parseCertsOnly(out20).crls[0], crlA) === 0);
  // 21. a certificate DER whose first byte is not 0x30, and is not PEM either, is refused.
  check("21. non-DER non-PEM certificate bytes -> cms/bad-input", code(function () { pki.cms.certsOnly([Buffer.from([0x01, 0x02, 0x03])]); }) === "cms/bad-input");
  // 21a. a byte source that carries PEM text (first byte not 0x30) is decoded through the PEM fallback.
  var out21a = pki.cms.certsOnly([Buffer.from(pem("CERTIFICATE", CERT_A), "latin1")]);
  check("21a. a Buffer of PEM certificate text is accepted", Buffer.compare(pki.cms.parseCertsOnly(out21a).certificates[0], CERT_A) === 0);
  // 21b. a string that is not a PEM block is refused.
  check("21b. a non-PEM string certificate -> cms/bad-input", code(function () { pki.cms.certsOnly(["not a pem block"]); }) === "cms/bad-input");

  // 22. the reader refuses a valid-DER structure that is not a CMS message.
  check("22. parseCertsOnly(a bare certificate DER) -> cms/bad-response", code(function () { pki.cms.parseCertsOnly(CERT_A); }) === "cms/bad-response");
  // 23. the reader accepts the message as PEM bytes (a byte source whose first byte is not 0x30).
  var pemBytes = Buffer.from(pki.cms.certsOnly([CERT_A], { pem: true }), "latin1");
  check("23. parseCertsOnly of a byte source carrying PEM text round-trips",
    Buffer.compare(pki.cms.parseCertsOnly(pemBytes).certificates[0], CERT_A) === 0);
  // 24. a PKCS7-armored PEM (the .p7c label) is read through the second armor.
  var p7cPem = pem("PKCS7", pki.cms.certsOnly([CERT_A]));
  check("24. parseCertsOnly of a PKCS7-armored PEM round-trips",
    Buffer.compare(pki.cms.parseCertsOnly(p7cPem).certificates[0], CERT_A) === 0);
  // 25. bytes that are neither DER nor any PEM block are refused.
  check("25. parseCertsOnly of non-DER non-PEM bytes -> cms/bad-input", code(function () { pki.cms.parseCertsOnly(Buffer.from([0x01, 0x02])); }) === "cms/bad-input");
  // 26. a non-Buffer, non-string reader input is refused.
  check("26. parseCertsOnly(a number) -> cms/bad-input", code(function () { pki.cms.parseCertsOnly(123); }) === "cms/bad-input");
  // 27. an all-empty degenerate SignedData (no certificates, no CRLs) conveys nothing and is refused.
  check("27. parseCertsOnly of an all-empty certs-only message -> cms/no-certificates",
    code(function () { pki.cms.parseCertsOnly(handCertsOnly(null)); }) === "cms/no-certificates");
  // 28. isCertsOnly reports false for a degenerate-looking but non-signedData input, and throws on garbage.
  check("28. isCertsOnly of non-DER non-PEM bytes throws cms/bad-input", code(function () { pki.cms.isCertsOnly(Buffer.from([0x01, 0x02])); }) === "cms/bad-input");

  // ==== maxCerts is a resource bound: the bound itself is validated (a bad cap cannot defeat it) ====
  var twoCertBag = pki.cms.certsOnly([CERT_A, CERT_B]);
  // 29. a positive integer cap is applied.
  check("29. maxCerts: 1 returns one certificate from a two-cert bundle", pki.cms.parseCertsOnly(twoCertBag, { maxCerts: 1 }).certificates.length === 1);
  // 30. a negative cap is refused, not sliced to all-but-the-last.
  check("30. maxCerts: -1 -> cms/bad-input", code(function () { pki.cms.parseCertsOnly(twoCertBag, { maxCerts: -1 }); }) === "cms/bad-input");
  // 31. NaN is refused, not read as "no cap".
  check("31. maxCerts: NaN -> cms/bad-input", code(function () { pki.cms.parseCertsOnly(twoCertBag, { maxCerts: NaN }); }) === "cms/bad-input");
  // 32. a fractional cap is refused.
  check("32. maxCerts: 1.5 -> cms/bad-input", code(function () { pki.cms.parseCertsOnly(twoCertBag, { maxCerts: 1.5 }); }) === "cms/bad-input");
  // 33. a non-numeric cap is refused.
  check("33. maxCerts: \"1\" -> cms/bad-input", code(function () { pki.cms.parseCertsOnly(twoCertBag, { maxCerts: "1" }); }) === "cms/bad-input");
  // 34. an absent cap leaves the count uncapped (both certs returned).
  check("34. omitted maxCerts leaves the bundle uncapped", pki.cms.parseCertsOnly(twoCertBag).certificates.length === 2);

  // ==== digestAlgorithms is not required to be empty: RFC 5652 sec. 5.1 permits a non-empty set even
  //      with no signer, so a valid EST/AIA bundle carrying one is still read + recognized (interop) ====
  var SHA256_ALG = b.sequence([b.oid("2.16.840.1.101.3.4.2.1")]);
  var nonEmptyDigests = handCertsOnly([CERT_EC], { digestAlgs: [SHA256_ALG] });
  // 35. the reader accepts a certs-only whose digestAlgorithms set is non-empty, returning the cert.
  check("35. parseCertsOnly(non-empty digestAlgorithms) accepts and returns the cert",
    Buffer.compare(pki.cms.parseCertsOnly(nonEmptyDigests).certificates[0], CERT_EC) === 0);
  // 36. the recognizer still classifies it as certs-only (a non-canonical but valid bundle).
  check("36. isCertsOnly(non-empty digestAlgorithms) === true", pki.cms.isCertsOnly(nonEmptyDigests) === true);

  // ==== maxCerts caps the COMBINED number of certificates and CRLs (not each collection separately) ====
  var mixBag = pki.cms.certsOnly([CERT_A, CERT_B], { crls: [validCrl("CA-X"), validCrl("CA-Y")] });   // 2 certs + 2 CRLs
  // 37. with a cap of 3, certificates are counted first and CRLs draw the remainder: 2 certs + 1 CRL.
  var r37 = pki.cms.parseCertsOnly(mixBag, { maxCerts: 3 });
  check("37. maxCerts: 3 over a 2-cert 2-CRL bundle returns 2 certs + 1 CRL (combined cap holds)",
    r37.certificates.length === 2 && r37.crls.length === 1);
  // 38. with a cap of 2, the certificates exhaust the budget and no CRL is returned.
  var r38 = pki.cms.parseCertsOnly(mixBag, { maxCerts: 2 });
  check("38. maxCerts: 2 leaves no budget for CRLs (2 certs, 0 CRLs)",
    r38.certificates.length === 2 && r38.crls.length === 0);

  // ==== isCertsOnly is a predicate: false for any other well-formed CMS, throws only on non-CMS bytes ====
  // 39. a well-formed CMS ContentInfo of an unsupported type (bare id-data) is not certs-only -> false.
  var dataCI = b.sequence([b.oid(ID_DATA), b.explicit(0, b.octetString(Buffer.from("hello")))]);
  check("39. isCertsOnly(a bare id-data ContentInfo) === false (not an exception)", pki.cms.isCertsOnly(dataCI) === false);
  // 40. bytes that decode but are not a ContentInfo at all still throw (only unsupported-type is translated).
  check("40. isCertsOnly(a non-ContentInfo SEQUENCE) throws cms/not-a-content-info",
    code(function () { pki.cms.isCertsOnly(b.sequence([b.integer(1n)])); }) === "cms/not-a-content-info");

  void acode;
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
