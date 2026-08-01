// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.est.serverkeygen (RFC 7030 sec. 4.4) + pki.est.csrattrs (sec. 4.5, RFC 9908) network
// verbs, driven through the SHIPPED consumer path over the injectable fakeTransport (no socket). Every
// reject with a pre-transport gate asserts t.calls.length === 0; every accept injects { transport } only.
// The multipart / enveloped-key / certs-only fixtures mirror the codec-level est.test.js verbatim.

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = require("../helpers/vectors");
var fakeTransport = require("../helpers/fake-transport").fakeTransport;
var b = pki.asn1.build;

var BASE = "https://ca.example";
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_ENVELOPED_DATA = "1.2.840.113549.1.7.3";
var ID_DATA = "1.2.840.113549.1.7.1";
var RSA_OID = "1.2.840.113549.1.1.1";
var AES256_CBC = "2.16.840.1.101.3.4.1.42";
var ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var CHALLENGE_PW = "1.2.840.113549.1.9.7";
var TEMPLATE_OID = "1.2.840.113549.1.9.16.2.61";
var SK_CT = 'multipart/mixed; boundary="estBoundary"';
var ENC_PART = "application/pkcs7-mime; smime-type=server-generated-key";
var KID = Buffer.from([0x33, 0x44]);
var REAL_CERT = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);

function algId(o) { return b.sequence([b.oid(o)]); }
function ct(type) { return { "content-type": type }; }
async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// A minimal CMS EnvelopedData ContentInfo (server-generated encrypted key). o.skid -> a subjectKeyIdentifier
// recipient; o.innerType overrides the encapsulated content type; verbatim from est.test.js.
function envelopedKeyCI(o) {
  o = o || {};
  var iasn = b.sequence([b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("R")])])]), b.integer(9n)]);
  var rid = o.skid ? b.contextPrimitive(0, Buffer.from(o.skid)) : iasn;
  var ktri = b.sequence([b.integer(o.skid ? 2n : 0n), rid, algId(RSA_OID), b.octetString(Buffer.from([0xAA, 0xBB]))]);
  var eciChildren = [b.oid(o.innerType || ID_SIGNED_DATA), algId(AES256_CBC)];
  eciChildren.push(b.contextPrimitive(0, Buffer.from([0x11, 0x22])));
  var env = b.sequence([b.integer(o.skid ? 2n : 0n), b.set([ktri]), b.sequence(eciChildren)]);
  return b.sequence([b.oid(ID_ENVELOPED_DATA), b.explicit(0, env)]);
}
// A certs-only SignedData ContentInfo (the certificate part), verbatim from est.test.js.
function certsOnly(certs) {
  var sd = [b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)]), b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))), b.set([])];
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}
// A multipart/mixed body (boundary "estBoundary").
function multipart(parts) {
  var body = parts.map(function (p) { return "--estBoundary\r\nContent-Type: " + p.ct + "\r\n\r\n" + p.body; }).join("\r\n");
  return body + "\r\n--estBoundary--\r\n";
}
// A structurally valid PKCS#10 CSR reusing REAL_CERT's raw subject + SPKI, with caller attributes (built
// nodes) and an optional replacement SPKI. csr.parse is structural (no signature verification).
function csrWith(attrNodes, altSpki) {
  var tbs = pki.asn1.decode(REAL_CERT).children[0];
  var attrs = (attrNodes && attrNodes.length) ? Buffer.concat(attrNodes.slice().sort(Buffer.compare)) : Buffer.alloc(0);
  var cri = b.sequence([b.integer(0n), tbs.children[5].bytes, altSpki || tbs.children[6].bytes, b.contextConstructed(0, attrs)]);
  return b.sequence([cri, algId(ECDSA_SHA256), b.bitString(Buffer.from([1, 2, 3]), 0)]);
}
var pkcs8 = b.sequence([b.integer(0n), b.sequence([b.oid("1.3.101.112")]), b.octetString(Buffer.alloc(34, 7))]);
var CERT_PART = certsOnly([REAL_CERT]);
var CSR_PLAIN = csrWith([]);
var CSR_KEK = csrWith([pki.est.decryptKeyIdentifierAttr(KID)]);
// 200 serverkeygen reply: a key part + the certs-only part. o.raw overrides the whole body; o.tls forwards a cipher.
function skReply(keyCt, keyBody, o) {
  o = o || {};
  var body = o.raw != null ? o.raw : multipart([{ ct: keyCt, body: keyBody }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: CERT_PART.toString("base64") }]);
  return { status: 200, headers: ct(SK_CT), body: body, tls: o.tls };
}
function csrattrsOK(der) { return { status: 200, headers: ct("application/csrattrs"), body: pki.est.transferEncode(der) }; }

async function run() {
  // ===== serverkeygen -- accept =====
  var t1 = fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64")));
  var r1 = await pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: t1 });
  check("SK-1. cleartext key + request shape", !!r1.privateKey && r1.certificates.length === 1 && !r1.encryptedKey &&
    t1.calls.length === 1 && t1.calls[0].method === "POST" && /\/serverkeygen$/.test(t1.calls[0].url) &&
    t1.calls[0].headers["content-type"] === "application/pkcs10" && t1.calls[0].headers.accept === "multipart/mixed" &&
    t1.calls[0].body === pki.est.transferEncode(CSR_PLAIN));
  var r2 = await pki.est.serverkeygen(BASE, CSR_KEK, { transport: fakeTransport(skReply(ENC_PART, envelopedKeyCI({ skid: KID }).toString("base64"))) });
  check("SK-2. encrypted key, encryption auto-derived from the CSR's DecryptKeyIdentifier", !!r2.encryptedKey && r2.encryptedKey.contentTypeName === "envelopedData" && r2.certificates.length === 1 && !r2.privateKey);
  var r3 = await pki.est.serverkeygen(BASE, CSR_KEK, { transport: fakeTransport(skReply(ENC_PART, envelopedKeyCI().toString("base64"))), expectedRecipientIssuerSerial: { issuer: b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("R")])])]), serialNumber: 9n } });
  check("SK-3. issuer+serial recipient resolves via a caller hint", !!r3.encryptedKey);
  var r4 = await pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport({ status: 202, headers: { "retry-after": "60" }, body: "" }) });
  check("SK-4. a 202 is surfaced, never slept", r4.retry === true && r4.retryAfterSeconds === 60);
  var r5 = await pki.est.serverkeygen(BASE, csrWith([], b.sequence([b.sequence([b.oid("1.3.101.112")]), b.bitString(Buffer.alloc(32, 9), 0)])), { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"))) });
  check("SK-5. a CA-generated cert whose key differs from the CSR key still resolves (no leaf pick)", !!r5.privateKey && r5.certificates.length === 1);

  // ===== serverkeygen -- reject =====
  var t6 = fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64")));
  check("SK-6. CSR advertised a KEK but the key part is cleartext -> downgrade refused", (await codeOf(pki.est.serverkeygen(BASE, CSR_KEK, { transport: t6 }))) === "est/expected-encrypted-key" && t6.calls.length === 1);
  check("SK-7. encrypted to a different recipient than the CSR advertised", (await codeOf(pki.est.serverkeygen(BASE, CSR_KEK, { transport: fakeTransport(skReply(ENC_PART, envelopedKeyCI({ skid: Buffer.from([0x99, 0x99]) }).toString("base64"))) }))) === "est/recipient-mismatch");
  check("SK-8. a three-part body", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport(skReply(null, null, { raw: multipart([{ ct: "application/pkcs8", body: "AA==" }, { ct: "application/pkcs8", body: "AA==" }, { ct: "text/plain", body: "x" }]) })) }))) === "est/bad-multipart");
  check("SK-9. a 200 non-multipart content-type", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport({ status: 200, headers: ct("application/pkcs7-mime"), body: "AA==" }) }))) === "est/bad-content-type");
  check("SK-10. a 200 empty body", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport({ status: 200, headers: ct(SK_CT), body: "" }) }))) === "est/empty-body");
  check("SK-11. the encrypted key encapsulates id-data (not SignedData)", (await codeOf(pki.est.serverkeygen(BASE, CSR_KEK, { transport: fakeTransport(skReply(ENC_PART, envelopedKeyCI({ innerType: ID_DATA, skid: KID }).toString("base64"))) }))) === "est/bad-key-part");
  var t12 = fakeTransport(skReply(ENC_PART, envelopedKeyCI({ skid: KID }).toString("base64")));
  check("SK-12. opts contradicts the CSR (pre-transport)", (await codeOf(pki.est.serverkeygen(BASE, CSR_KEK, { transport: t12, requestedEncryption: false }))) === "est/bad-input" && t12.calls.length === 0);
  check("SK-13a. a NULL cipher on the serverkeygen channel", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"), { tls: { cipher: { name: "ECDHE-RSA-NULL-SHA", standardName: "TLS_ECDHE_RSA_WITH_NULL_SHA" } } })) }))) === "est/weak-cipher");
  check("SK-13b. an EXPORT cipher", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"), { tls: { cipher: { name: "EXP-RC4-MD5" } } })) }))) === "est/weak-cipher");
  check("SK-13c. an anonymous cipher", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"), { tls: { cipher: { standardName: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" } } })) }))) === "est/weak-cipher");
  var r13d = await pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"), { tls: { cipher: { name: "ECDHE-RSA-AES128-GCM-SHA256" } } })) });
  check("SK-13d. a strong cipher is accepted", !!r13d.privateKey);
  var t14a = fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64")));
  check("SK-14a. an http base URL is refused pre-transport", (await codeOf(pki.est.serverkeygen("http://ca.example", CSR_PLAIN, { transport: t14a }))) === "est/insecure-url" && t14a.calls.length === 0);
  check("SK-14b. no trust anchor without a transport", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, {}))) === "est/no-trust-anchors");
  check("SK-15a. a 500 http error", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport({ status: 500, headers: {}, body: "boom" }) }))) === "est/http-error");
  var t15b = fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64")));
  check("SK-15b. a non-CSR input is rejected pre-transport", (await codeOf(pki.est.serverkeygen(BASE, 123, { transport: t15b }))) === "est/bad-input" && t15b.calls.length === 0);
  var r15c = await pki.est.serverkeygen(BASE, pki.schema.csr.pemEncode(CSR_PLAIN), { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"))) });
  check("SK-15c. a PEM CSR is accepted", !!r15c.privateKey);
  // SK-16: a recipient pin on a CSR with NO key-encryption attribute implies encryption the CSR never requested;
  // without the gate a compromised CA could deliver the key to a recipient IT controls (or cleartext) while the
  // caller believes its pin was enforced. Refused pre-transport.
  var t16a = fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64")));
  check("SK-16a. expectedRecipientKeyId on a no-KEK CSR is refused pre-transport (fail-open closed)", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: t16a, expectedRecipientKeyId: KID }))) === "est/bad-input" && t16a.calls.length === 0);
  var t16b = fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64")));
  check("SK-16b. expectedRecipientIssuerSerial on a no-KEK CSR is refused pre-transport", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: t16b, expectedRecipientIssuerSerial: { issuer: b.sequence([]), serialNumber: 9n } }))) === "est/bad-input" && t16b.calls.length === 0);
  // SK-17: a bad expectedRecipientIssuerSerial.serialNumber is a typed est/bad-input, never a raw BigInt error.
  check("SK-17a. a non-integer expectedRecipientIssuerSerial.serialNumber is a typed est/bad-input (verb)", (await codeOf(pki.est.serverkeygen(BASE, CSR_KEK, { transport: fakeTransport(skReply(ENC_PART, envelopedKeyCI().toString("base64"))), expectedRecipientIssuerSerial: { issuer: b.sequence([]), serialNumber: "not-a-number" } }))) === "est/bad-input");
  check("SK-17b. parseServerKeygenResponse rejects a bad serialNumber typed (not a raw BigInt error)", (await codeOf(Promise.resolve().then(function () { return pki.est.parseServerKeygenResponse(multipart([{ ct: ENC_PART, body: envelopedKeyCI().toString("base64") }, { ct: "application/pkcs7-mime; smime-type=certs-only", body: CERT_PART.toString("base64") }]), SK_CT, { expectedRecipientIssuerSerial: { issuer: b.sequence([]), serialNumber: {} } }); }))) === "est/bad-input");
  // SK-18: a bogus opts.auth.scheme is caught at config time, even when the server would answer 200.
  check("SK-18. a bogus opts.auth.scheme is rejected at construction (not deferred to a 401)", (await codeOf(pki.est.serverkeygen(BASE, CSR_PLAIN, { transport: fakeTransport(skReply("application/pkcs8", pkcs8.toString("base64"))), auth: { scheme: "bogus" } }))) === "est/bad-input");

  // ===== csrattrs -- accept =====
  var tc1 = fakeTransport(csrattrsOK(b.sequence([b.oid(CHALLENGE_PW)])));
  var rc1 = await pki.est.csrattrs(BASE, { transport: tc1 });
  check("CA-1. happy parse + plan", rc1.available === true && rc1.attrs.items.length === 1 && rc1.plan.channelBindingRequired === true &&
    tc1.calls.length === 1 && tc1.calls[0].method === "GET" && /\/csrattrs$/.test(tc1.calls[0].url) && tc1.calls[0].headers.accept === "application/csrattrs");
  var rc2 = await pki.est.csrattrs(BASE, { transport: fakeTransport(csrattrsOK(b.sequence([]))) });
  check("CA-2. a valid EMPTY CsrAttrs (30 00) parses (not est/empty-body)", rc2.available === true && rc2.attrs.items.length === 0);
  var tc3 = fakeTransport({ status: 204, headers: {}, body: "" });
  var rc3 = await pki.est.csrattrs(BASE, { transport: tc3 });
  check("CA-3. a 204 is none-available", rc3.available === false && rc3.attrs === null && tc3.calls.length === 1);
  var rc4 = await pki.est.csrattrs(BASE, { transport: fakeTransport({ status: 404, headers: {}, body: "" }) });
  check("CA-4. a 404 is none-available", rc4.available === false && rc4.attrs === null);
  var rc5 = await pki.est.csrattrs(BASE, { transport: fakeTransport(csrattrsOK(b.sequence([b.oid(CHALLENGE_PW), b.oid("1.3.6.1.4.1.99999.7")]))) });
  check("CA-5. an unknown OID is surfaced on unhandled, not dropped", rc5.available === true && rc5.attrs.items.length === 2 && rc5.plan.unhandled.some(function (u) { return u.oid === "1.3.6.1.4.1.99999.7"; }));
  var tplAttr = b.sequence([b.oid(TEMPLATE_OID), b.set([b.sequence([b.integer(0n), b.contextConstructed(1, Buffer.alloc(0))])])]);
  var rc6 = await pki.est.csrattrs(BASE, { transport: fakeTransport(csrattrsOK(b.sequence([tplAttr, b.sequence([b.oid(RSA_OID), b.set([b.integer(2048n)])])]))) });
  check("CA-6. a template attribute drives the plan from the template", rc6.plan.fromTemplate === true);
  var tc7 = fakeTransport([{ status: 401, headers: { "www-authenticate": 'Basic realm="est"' }, body: "" }, csrattrsOK(b.sequence([b.oid(CHALLENGE_PW)]))]);
  var rc7 = await pki.est.csrattrs(BASE, { transport: tc7, username: "u", password: "p" });
  check("CA-7. a 401 is tolerated (auth path live)", rc7.available === true && tc7.calls.length === 2 && /^Basic /.test(tc7.calls[1].headers.authorization));

  // ===== csrattrs -- reject =====
  var tc8 = fakeTransport({ status: 200, headers: ct("application/csrattrs"), body: "" });
  check("CA-8. an empty HTTP body (distinct from 30 00)", (await codeOf(pki.est.csrattrs(BASE, { transport: tc8 }))) === "est/empty-body" && tc8.calls.length === 1);
  check("CA-9. a 202 is nonconforming for a policy GET", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport({ status: 202, headers: { "retry-after": "60" }, body: "" }) }))) === "est/http-error");
  check("CA-10. a 400 is an http error", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport({ status: 400, headers: {}, body: "bad" }) }))) === "est/http-error");
  check("CA-11. a wrong content-type", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport({ status: 200, headers: ct("text/plain"), body: "MAA=" }) }))) === "est/bad-content-type");
  check("CA-12. a non-base64 body", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport({ status: 200, headers: ct("application/csrattrs"), body: "!!!!" }) }))) === "est/bad-base64");
  check("CA-13. a malformed CsrAttrs propagates", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport(csrattrsOK(b.integer(1n))) }))) === "csrattrs/not-csrattrs");
  check("CA-14. an RFC 9908 violation (two templates) propagates", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport(csrattrsOK(b.sequence([tplAttr, tplAttr]))) }))) === "csrattrs/duplicate-template");
  check("CA-15. a non-standard 2xx", (await codeOf(pki.est.csrattrs(BASE, { transport: fakeTransport({ status: 201, headers: ct("application/csrattrs"), body: "MAA=" }) }))) === "est/http-error");
  var tc16a = fakeTransport(csrattrsOK(b.sequence([])));
  check("CA-16a. an http base URL is refused pre-transport", (await codeOf(pki.est.csrattrs("http://ca.example", { transport: tc16a }))) === "est/insecure-url" && tc16a.calls.length === 0);
  check("CA-16b. no trust anchor without a transport", (await codeOf(pki.est.csrattrs(BASE, {}))) === "est/no-trust-anchors");
  var tc16c = fakeTransport({ status: 401, headers: { "www-authenticate": 'Basic realm="est"' }, body: "" });
  check("CA-16c. a 401 with no credentials fails closed, no authorization sent", (await codeOf(pki.est.csrattrs(BASE, { transport: tc16c }))) === "est/auth-required" && tc16c.calls.every(function (c) { return !(c.headers && c.headers.authorization); }));

  console.log("CHECKS " + helpers.getChecks());
}

if (require.main === module) { run().catch(function (e) { console.error(e); process.exit(1); }); }
module.exports = { run: run };
