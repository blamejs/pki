// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.verify (RFC 5652 sec. 5 CMS SignedData signature verification). Drives
 * the shipped consumer path (pki.cms.verify) against known-answer SignedData produced by an
 * independent implementation (OpenSSL `cms -sign`, plus a hand-assembled Ed25519 token OpenSSL
 * cannot emit), so a real signature over the exact RFC 5652 sec. 5.4 preimage is what the suite
 * accepts -- attached and detached content, single and multiple signers, RSA / RSASSA-PSS /
 * ECDSA / EdDSA, and the issuerAndSerialNumber and subjectKeyIdentifier signer identifiers.
 * Every malformed / tampered / unsupported shape is a fail-closed verdict (ok:false with a
 * typed cms/* code, or a per-signer false crypto verdict) or a config-time throw; a valid
 * signature over the wrong bytes never reads as verified.
 *
 * RED baseline: pki.cms.verify is undefined until the module lands, so every vector throws --
 * the suite drives the build to GREEN.
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var makeSigner = require("../helpers/signing").makeSigner;
var surgery = require("../helpers/der-surgery");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

var DIR = path.join(__dirname, "..", "fixtures", "cms");
function fx(name) { return fs.readFileSync(path.join(DIR, name)); }
var CONTENT = Buffer.from("hello CMS SignedData verification");

// await a rejection and assert its typed code.
async function rejects(label, fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label + " throws", threw !== null);
  check(label + " code=" + code, threw && threw.code === code);
}

// ---- accept: every algorithm family + content mode + signer count ----
async function testAcceptKats() {
  var cases = [
    ["rsa-attached.p7s", "attached RSA (PKCS#1 v1.5)"],
    ["ec-attached.p7s", "attached ECDSA P-256"],
    ["rsapss-attached.p7s", "attached RSASSA-PSS"],
    ["ed25519-attached.p7s", "attached Ed25519"],
    ["rsa-noattr.p7s", "no-signedAttrs RSA (signature over content)"],
  ];
  for (var i = 0; i < cases.length; i++) {
    var res = await pki.cms.verify(fx(cases[i][0]));
    check(cases[i][1] + " -> valid", res.valid === true);
    check(cases[i][1] + " -> one signer ok", res.signers.length === 1 && res.signers[0].ok === true);
    check("#78 " + cases[i][1] + " -> primary signer node carries digestAlgorithm", typeof res.signers[0].digestAlgorithm === "string" && res.signers[0].digestAlgorithm.length > 0);
    check(cases[i][1] + " -> signer cert surfaced", Buffer.isBuffer(res.signers[0].cert));
  }
}

async function testMultiSigner() {
  var res = await pki.cms.verify(fx("multi.p7s"));
  check("multi-signer -> valid", res.valid === true);
  check("multi-signer -> two signers", res.signers.length === 2);
  check("multi-signer -> both ok", res.signers.every(function (s) { return s.ok === true; }));
}

// ---- signer identifier: subjectKeyIdentifier vs issuerAndSerialNumber ----
async function testSignerIdentifier() {
  var ski = await pki.cms.verify(fx("rsa-keyid.p7s"));
  check("SKI sid -> valid", ski.valid === true);
  check("SKI sid -> matched by subjectKeyIdentifier", ski.signers[0].sid.subjectKeyIdentifier != null);

  var is = await pki.cms.verify(fx("rsa-attached.p7s"));
  check("issuerAndSerial sid -> matched by issuer+serial", is.signers[0].sid.subjectKeyIdentifier == null && is.signers[0].sid.serialNumberHex != null);
}

// ---- detached content ----
async function testDetached() {
  var ok = await pki.cms.verify(fx("rsa-detached.p7s"), { content: CONTENT });
  check("detached + correct content -> valid", ok.valid === true);

  var bad = await pki.cms.verify(fx("rsa-detached.p7s"), { content: Buffer.from("the wrong external content") });
  check("detached + wrong content -> invalid", bad.valid === false);
  check("detached + wrong content -> message-digest-mismatch", bad.signers[0].code === "cms/message-digest-mismatch");
  check("detached + wrong content -> still names the signer cert", Buffer.isBuffer(bad.signers[0].cert));

  // A detached signature's external content is the whole of what the signature speaks about, and
  // the digest over it is computed in a later promise turn while the buffer stays caller-owned.
  // Rewriting it in that gap must not change the verdict: otherwise a caller holding the
  // replacement would be told the signature covered it. The certificates a caller supplies carry
  // the same exposure one level down -- the parse surfaces the signed portion and the public key
  // as views into those buffers, and both are read after the same yield.
  var racedContent = Buffer.from(CONTENT);
  var racedPromise = pki.cms.verify(fx("rsa-detached.p7s"), { content: racedContent });
  racedContent.fill(0);
  check("detached content rewritten after the call still verifies as passed (TOCTOU)",
    (await racedPromise).valid === true);


  await rejects("detached + no content", function () { return pki.cms.verify(fx("rsa-detached.p7s")); }, "cms/detached-content-required");

  // a Uint8Array (not just a Buffer) is accepted as the detached content.
  var u8 = await pki.cms.verify(fx("rsa-detached.p7s"), { content: new Uint8Array(CONTENT) });
  check("detached + Uint8Array content -> valid", u8.valid === true);
}

// ---- certificate location: opts.certs + not-found + malformed-skip ----
async function testCertLocation() {
  var withCert = await pki.cms.verify(fx("rsa-nocerts.p7s"), { certs: [fx("rsa-signer.crt")] });
  check("no embedded cert + opts.certs -> valid", withCert.valid === true);

  var noCert = await pki.cms.verify(fx("rsa-nocerts.p7s"));
  check("no embedded cert + no opts.certs -> invalid", noCert.valid === false);
  check("no embedded cert -> signer-cert-not-found", noCert.signers[0].code === "cms/signer-cert-not-found");
  check("signer-cert-not-found -> no cert surfaced", !noCert.signers[0].cert);

  // a Uint8Array cert in opts.certs is accepted.
  var u8cert = await pki.cms.verify(fx("rsa-nocerts.p7s"), { certs: [new Uint8Array(fx("rsa-signer.crt"))] });
  check("opts.certs Uint8Array -> valid", u8cert.valid === true);

  // an unparseable extra cert is skipped, not fatal: the embedded cert still verifies.
  var garbage = await pki.cms.verify(fx("rsa-attached.p7s"), { certs: [Buffer.from("not a certificate")] });
  check("opts.certs garbage buffer skipped -> still valid", garbage.valid === true);

  // a non-Buffer extra cert is skipped at the _toBuf boundary, not fatal.
  var wrongType = await pki.cms.verify(fx("rsa-attached.p7s"), { certs: ["not a buffer"] });
  check("opts.certs non-buffer skipped -> still valid", wrongType.valid === true);

  // an extra cert that parses but carries no subjectKeyIdentifier extension: it is indexed
  // (ski = null) without fault, so it simply cannot match an SKI-based signer identifier.
  var noSkiPem = fs.readFileSync(path.join(__dirname, "..", "fixtures", "inspect", "rich-cert.pem"), "utf8");
  var noSki = pki.schema.x509.pemDecode(noSkiPem);
  var withNoSki = await pki.cms.verify(fx("rsa-attached.p7s"), { certs: [noSki] });
  check("opts.certs cert without SKI indexed -> still valid", withNoSki.valid === true);
}

// Flip the SKI extension's inner OCTET-STRING tag so the key-identifier value no longer
// decodes -- x509.parse still accepts it (the value is opaque to the base parser).
function corruptSkiValue(der) {
  var b = Buffer.from(der);
  var pat = Buffer.from([0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14]);
  var i = b.indexOf(pat);
  check("SKI-corruption pattern located", i >= 0);
  b[i + 7] = 0x01;   // inner OCTET STRING tag -> an invalid one for asn1.decode
  return b;
}
// Flip the named-curve OBJECT IDENTIFIER tag in an EC SPKI so the curve OID no longer decodes.
function corruptEcParams(der) {
  var b = Buffer.from(der);
  var pat = Buffer.from([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
  var i = b.indexOf(pat);
  check("EC-params-corruption pattern located", i >= 0 && b[i + 9] === 0x06);
  b[i + 9] = 0x04;   // curve OID tag -> an invalid one for asn1.read.oid
  return b;
}

// A candidate certificate that parses but whose identifying fields will not decode is indexed
// without fault (it simply cannot match a signer) -- the verify must not be derailed by it.
async function testMalformedCandidateCerts() {
  // a broken subjectKeyIdentifier value: indexed with ski = null, so it never matches by SKI.
  var brokenSki = corruptSkiValue(pki.schema.x509.pemDecode(fx("rsa-signer.crt").toString()));
  var r1 = await pki.cms.verify(fx("rsa-attached.p7s"), { certs: [brokenSki] });
  check("candidate cert with undecodable SKI ignored -> still valid", r1.valid === true);

  // the actual signer certificate carries EC parameters that will not decode: the EC verify
  // path cannot resolve a curve and reports the fail-closed unsupported-algorithm verdict. The
  // certificate rides the message verbatim, so the corruption goes into the MESSAGE -- a single
  // byte, which keeps every enclosing length intact.
  var rec = await pki.cms.verify(corruptEcParams(fx("ec-attached.p7s")));
  check("signer cert with undecodable EC params -> unsupported verdict", rec.valid === false && rec.signers[0].code === "cms/unsupported-algorithm");

  // an EC signer whose point WebCrypto rejects at import (an invalid uncompressed-point prefix):
  // the engine error is wrapped as a fail-closed cms/verify-error verdict, not leaked raw.
  var ec = Buffer.from(fx("ec-attached.p7s"));
  var pt = Buffer.from([0x42, 0x00, 0x04]);   // P-256 SPKI BIT STRING: len 66, 0 unused, 0x04 prefix
  var j = ec.indexOf(pt);
  check("EC point prefix located", j >= 0);
  ec[j + 2] = 0xFF;   // 0x04 uncompressed prefix -> an invalid point encoding
  var re = await pki.cms.verify(ec);
  check("EC signer with an invalid point -> verify-error verdict", re.valid === false && re.signers[0].code === "cms/verify-error");
}

// A colliding candidate certificate (same signer identifier, different key) placed before the
// real signer must not hide it -- every matching candidate is tried until one verifies.
async function testCollidingSignerCert() {
  var p = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  var real = p.certificates[0].bytes;
  var cert = pki.schema.x509.parse(real);
  var spki = cert.subjectPublicKeyInfo.bytes;
  var off = real.indexOf(spki);
  check("signer SPKI located in the cert", off >= 0);
  var collide = Buffer.from(real);
  var at = off + spki.length - 8;   // deep in the RSA modulus (past issuer/serial, still valid DER)
  collide[at] = collide[at] ^ 0xff;   // same issuer+serial, a different (non-verifying) key
  p.certificates = [{ bytes: collide }, p.certificates[0]];
  var r = await pki.cms.verify(p);
  check("colliding signer cert before the real one -> still valid", r.valid === true);
  // a signer certificate whose issuer DN carries an embedded control byte must fail closed with a
  // TYPED error from the RFC 5280 sec. 7.1 DN comparison, never a raw TypeError. The name guard takes
  // a (code, message) error FACTORY, not a class -- passing a class made it call the class without
  // `new`. Fuzzer-found reproducer (control byte in the signer cert issuer CN).
  var CTRL_DN = "MIIDNgYJKoZIhvcNAQcCoIIDJzCCAyMCAQExDTALBglghkgBZQMEAgEwMAYJKoZIhvcNAQcBoCMEIWhlbGxvIENNUyBTaWduZWREYXRhIHZlcmlmaWNhdGlvbqCCAVUwggFRMIH5oAMCAQICFBKb5wRioFwAWFI0UitKp50hymL4MAoGCCqGSM49BAMCMBgxFjAUBgNVBAMMDUNNUyBFAAAAAAAAAAAwHhcNMjYwNzEzMTk0MTEwWhcNMzYwNzEwMTk0MTEwWjAYMRYwFAYDVQQDDA1DTVMgRUMgU2lnbmVyMFkwEwYHKoZIzj0CAQYIKobOPQFIAwcDQgAEO5Cm7ZlKPMJql9Kv0kc0kZM0ySzP3lsiwNocPb2v4YvZCKK3S2NnvwO80XibHg7/rvj9vbxH/c6oEYI1CkkamKMhMB8wHQYDVR0OBBYEFMfQePWAY9Mmh236ceGi6rP42qGcMAoGCCqGSM49BAMCA0cAMEQCIEy9WcbDNeH3QKawlrd8pTbdDBVk6P31Dp/9/ODG2k2AAiATyR1REzj+qCCSTftWgNZBdZw37PTh3SZTyWzd3WUj0jGCAYIwggF+AgEBMDAwGDEWMBQGA1UEAwwNQ01TIEVDIFNpZ25lcgIUEpvnBGKgXABYUjRSK0qnnSHKYvgwCwYJYIZIAWUDBAIBoIHkMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ1nm3efcNAQkFMQ8XDTI2MDcxMzE5NDExMFowLwYJKoZIhvcNAQkEMSIEID8oZDYwsuqHSt0BLC4SbzD+QnSOaxX/Tfdd3wm+EtGkMHkGCSqGSIb3DQEJDzFsMGowCwYJYIZKAWUD+v7VzwsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMAoGCCqGSM49BAMCBEcwRQIgSz+DvXbv53iYxIfQeb+HQDT42qGcMAoGCCqGSM49BAMCA0cAMEQCIEy97W2S9TRqOeTXBvGJEryGcd1M6FOjaNu6RA==";
  await rejects("control-byte issuer DN in signer cert -> typed cms/bad-name (not a raw TypeError)", function () { return pki.cms.verify(Buffer.from(CTRL_DN, "base64")); }, "cms/bad-name");
}

// ---- input forms: DER Buffer (covered above), PEM string, parsed object ----
async function testInputForms() {
  var pem = "-----BEGIN CMS-----\n" + fx("rsa-attached.p7s").toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CMS-----\n";
  var fromPem = await pki.cms.verify(pem);
  check("PEM string input -> valid", fromPem.valid === true);

  var parsed = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  var fromObj = await pki.cms.verify(parsed);
  check("parsed-object input -> valid", fromObj.valid === true);

  // Byte-source input forms (the WebCrypto BufferSource contract): a same-realm AND a CROSS-REALM ArrayBuffer
  // verify identically to a Buffer. #68 A'2 -- pki.cms.verify normalizes the input via _snapshotIfBytes ->
  // guard.bytes.isByteSource; before routing, `instanceof ArrayBuffer` turned away the cross-realm buffer,
  // leaving it un-snapshotted for cms.parse to reject with cms/bad-input.
  var derBuf = fx("rsa-attached.p7s");
  var sameAB = new ArrayBuffer(derBuf.length);
  new Uint8Array(sameAB).set(derBuf);
  var fromSameAB = await pki.cms.verify(sameAB);
  check("same-realm ArrayBuffer input -> valid", fromSameAB.valid === true && fromSameAB.signers.length === 1);
  var crossAB = require("vm").runInNewContext("new ArrayBuffer(" + derBuf.length + ")");
  new Uint8Array(crossAB).set(derBuf);
  var fromCrossAB = await pki.cms.verify(crossAB);
  check("cross-realm ArrayBuffer input -> valid", fromCrossAB.valid === true && fromCrossAB.signers.length === 1);

  // opts.content (detached) passes through _snapshotIfBytes -> guard.bytes.isByteSource (#68 A'2). A
  // cross-realm ArrayBuffer content was refused before routing (instanceof ArrayBuffer fails cross-realm ->
  // left un-snapshotted -> _toBuf rejects); after routing it verifies identically to the Buffer content.
  var contentCrossAB = require("vm").runInNewContext("new ArrayBuffer(" + CONTENT.length + ")");
  new Uint8Array(contentCrossAB).set(CONTENT);
  var detachedCross = await pki.cms.verify(fx("rsa-detached.p7s"), { content: contentCrossAB });
  check("detached opts.content as a cross-realm ArrayBuffer -> valid (#68 A'2 realm-fragility)", detachedCross.valid === true);
}

// An OID no registry row claims, so it resolves to no algorithm at all.
var UNREGISTERED = "1.3.6.1.4.1.99999.8.7.6";

// Rewrite the SignerInfo's own signatureAlgorithm / digestAlgorithm in a SignedData encoding. Both
// take the LAST AlgorithmIdentifier for the algorithm the fixture was signed with: in a SignedData
// the SignerInfo comes after digestAlgorithms and after the certificates, so "the last" is the
// SignerInfo's, and the signer certificate is left describing itself truthfully.
function swapSigAlg(der, toOid) {
  var r = surgery.replaceLastAlgId(der, pki.oid.byName("rsaEncryption"), function () { return b.sequence([b.oid(toOid)]); });
  check("signatureAlgorithm rewrite changed the DER", !r.der.equals(der));
  return r.der;
}
function unknownSigAlg(der) { return swapSigAlg(der, UNREGISTERED); }
function swapDigest(der, toOid) {
  var r = surgery.replaceLastAlgId(der, pki.oid.byName("sha256"), function () { return b.sequence([b.oid(toOid)]); });
  check("digestAlgorithm rewrite changed the DER", !r.der.equals(der));
  return r.der;
}

// ---- unsupported algorithm: unregistered curve + bogus alg names ----
async function testUnsupportedAlgorithm() {
  // an EC signer cert on a curve outside the P-256/384/521 set the engine imports.
  var rsk = await pki.cms.verify(fx("ec-secp256k1.p7s"));
  check("secp256k1 signer -> unsupported verdict", rsk.valid === false && rsk.signers[0].code === "cms/unsupported-algorithm");

  // an unknown signatureAlgorithm is a per-signer verdict, not a throw. Every one of these is a
  // rewrite of the SignerInfo's own AlgorithmIdentifier in the ENCODING -- the LAST one, since the
  // SignerInfo follows the certificates and digestAlgorithms in a SignedData -- so the signer
  // certificate keeps naming what it really is and only the message's demand changes.
  var r1 = await pki.cms.verify(unknownSigAlg(fx("rsa-attached.p7s")));
  check("unknown signatureAlgorithm -> invalid", r1.valid === false);
  check("unknown signatureAlgorithm -> unsupported-algorithm code", r1.signers[0].code === "cms/unsupported-algorithm");

  // an unknown digestAlgorithm (non-EdDSA scheme) is likewise a verdict.
  var r2 = await pki.cms.verify(swapDigest(fx("rsa-attached.p7s"), UNREGISTERED));
  check("unknown digestAlgorithm -> unsupported-algorithm code", r2.signers[0].code === "cms/unsupported-algorithm");

  // EdDSA hashes internally, but a message-digest attribute is still computed under
  // digestAlgorithm. With signed attributes present and an unmapped digest, the verdict
  // must be a fail-closed cms/* one -- never a foreign-domain throw from the digest step.
  var edUnmapped = swapDigest(swapSigAlg(fx("rsa-attached.p7s"), pki.oid.byName("Ed25519")), UNREGISTERED);
  var r3 = await pki.cms.verify(edUnmapped);
  check("EdDSA + signedAttrs + unmapped digest -> unsupported-algorithm verdict", r3.valid === false && r3.signers[0].code === "cms/unsupported-algorithm");

  // The signature-scheme table is consulted by the name the message asks for, so it answers from
  // its own entries alone. A digest OID names no signature scheme; were the lookup to fall through
  // to Object.prototype, a message could name an algorithm the toolkit does not implement and have
  // the verification proceed under whatever a co-resident had left there.
  var digestAsSigAlg = swapSigAlg(fx("rsa-attached.p7s"), pki.oid.byName("sha256"));
  var rProto = await (async function () {
    var pending = pki.cms.verify(digestAsSigAlg);
    Object.prototype.sha256 = { kind: "rsa", hash: "SHA-256", params: "absent" };
    try { return await pending; } finally { delete Object.prototype.sha256; }
  })();
  check("a signature-scheme name reaching Object.prototype is not a scheme -> unsupported-algorithm",
    rProto.valid === false && rProto.signers[0].code === "cms/unsupported-algorithm");

  // A bare key OID (rsaEncryption / ecPublicKey) takes its SIGNATURE hash from the SignerInfo
  // digestAlgorithm. RFC 8702 sec. 3.2 gives RSASSA-PKCS1-v1_5-with-SHAKE and ECDSA-with-SHAKE
  // their OWN signature OIDs and never pairs a bare key OID with a SHAKE digestAlgorithm, so the
  // combination is non-conformant. It must keep THIS module's precise unsupported-algorithm
  // verdict: an extendable-output function is a message-digest algorithm here, never a signature
  // hash, so it must not reach the engine and come back as a relabeled foreign fault.
  for (var i = 0; i < 2; i++) {
    var shakeName = i === 0 ? "shake128" : "shake256";
    var r4 = await pki.cms.verify(swapDigest(fx("rsa-attached.p7s"), pki.oid.byName(shakeName)));
    check("rsaEncryption + " + shakeName + " digestAlgorithm -> unsupported-algorithm verdict",
      r4.valid === false && r4.signers[0].code === "cms/unsupported-algorithm");
  }
}

// Build an RSASSA-PSS-params SEQUENCE (RFC 4055), each field overridable so a vector can pin
// one deviation from the supported profile (SHA-256 hash, MGF1 with SHA-256, saltLength 32,
// trailerField 1). Fields are the EXPLICIT context [0..3] wrappers the resolver expects.
function pssParams(o) {
  o = o || {};
  var SHA256 = pki.oid.byName("sha256"), MGF1 = pki.oid.byName("mgf1");
  var hashOid = o.hashOid || SHA256, mgfHashOid = o.mgfHashOid || SHA256, mgfOid = o.mgfOid || MGF1;
  var fields = [];
  if (!o.noHash) fields.push(b.explicit(0, o.hashNonNull ? b.sequence([b.oid(hashOid), b.integer(0)]) : b.sequence([b.oid(hashOid), b.nullValue()])));
  if (!o.noMgf) fields.push(b.explicit(1, o.mgfNotSeq ? b.oid(mgfOid) : b.sequence([b.oid(mgfOid), b.sequence([b.oid(mgfHashOid), b.nullValue()])])));
  if (!o.noSalt) fields.push(b.explicit(2, b.integer(o.salt == null ? 32 : o.salt)));
  if (o.trailer != null) fields.push(b.explicit(3, b.integer(o.trailer)));
  return b.sequence(fields);
}
// The PSS fixture with `params` as its SignerInfo signatureAlgorithm parameters, in the ENCODING
// (null omits the field). The parameters sit OUTSIDE the signed bytes -- an attacker rewrites them
// freely on a message in flight -- which is exactly why the resolver has to refuse every profile
// it does not support instead of falling back to a WebCrypto default.
function withPss(params) {
  var der = fx("rsapss-attached.p7s");
  var r = surgery.replaceLastAlgId(der, pki.oid.byName("rsassaPss"), function (n) {
    return params == null ? b.sequence([Buffer.from(n.children[0].bytes)])
      : surgery.algIdWithParams(n.children[0].bytes, params);
  });
  check("PSS parameter splice found the SignerInfo AlgorithmIdentifier", r.count >= 1);
  return r.der;
}

// ---- RSASSA-PSS parameter resolution (RFC 4055) ----
async function testRsaPssParams() {
  // the standard-profile PSS KAT verifies in testAcceptKats. A rebuilt equivalent parameter
  // set (the params are outside the signed bytes) still verifies -- proving the resolver reads
  // an explicit hash / MGF1 / salt / trailer profile correctly.
  var ok1 = await pki.cms.verify(withPss(pssParams({})));
  check("RSA-PSS rebuilt standard params -> valid", ok1.valid === true);
  var ok2 = await pki.cms.verify(withPss(pssParams({ trailer: 1 })));
  check("RSA-PSS explicit trailerField 1 -> valid", ok2.valid === true);
  // A real OpenSSL PSS SignedData signed with the ASN.1 DEFAULT saltLength (20, so the [2]
  // field is omitted) verifies -- the default/declared salt length is honored, not pinned to
  // the hash length.
  var salt20 = await pki.cms.verify(fx("rsapss-salt20.p7s"));
  check("RSA-PSS default (absent) saltLength honored -> valid", salt20.valid === true);
  // A declared salt length that does not match how the signature was produced is HONORED
  // (passed to WebCrypto) -- so it is a crypto verdict, false with no structural code, not a
  // fail-closed unsupported rejection.
  var wrongSalt = await pki.cms.verify(withPss(pssParams({ salt: 48 })));
  check("RSA-PSS declared salt honored (mismatch -> crypto false)", wrongSalt.valid === false && wrongSalt.signers[0].ok === false && !wrongSalt.signers[0].code);
  // A negative saltLength maps to OpenSSL's RSA_PSS_SALTLEN magic (AUTO accepts any salt) and
  // is rejected fail-closed.
  await rejects("RSA-PSS negative saltLength", function () { return pki.cms.verify(withPss(pssParams({ salt: -1 }))); }, "cms/unsupported-algorithm");

  // Every deviation from the supported PROFILE (hash / MGF / trailer) is a fail-closed
  // unsupported-algorithm verdict, never verified under WebCrypto's own defaults.
  var cases = [
    ["absent params (rejected SHA-1 defaults)", null],
    ["non-SEQUENCE params", b.integer(5)],
    ["no hashAlgorithm field", pssParams({ noHash: true })],
    ["no maskGenAlgorithm field", pssParams({ noMgf: true })],
    ["unsupported hash (SHA-1)", pssParams({ hashOid: pki.oid.byName("sha1") })],
    ["hash AlgorithmIdentifier with non-NULL params", pssParams({ hashNonNull: true })],
    ["MGF not a SEQUENCE", pssParams({ mgfNotSeq: true })],
    ["MGF not MGF1", pssParams({ mgfOid: pki.oid.byName("sha256") })],
    ["MGF1 hash != signature hash", pssParams({ mgfHashOid: pki.oid.byName("sha384") })],
    ["trailerField != 1", pssParams({ trailer: 2 })],
  ];
  for (var i = 0; i < cases.length; i++) {
    var r = await pki.cms.verify(withPss(cases[i][1]));
    check("RSA-PSS " + cases[i][0] + " -> unsupported-algorithm", r.valid === false && r.signers[0].code === "cms/unsupported-algorithm");
  }

  // Parameters that are not a well-formed TLV at all (a SEQUENCE header claiming ten content bytes
  // that are not there) are not a signer-level question: nothing downstream of the decoder ever
  // sees them, so the message is refused whole rather than reported per signer.
  await rejects("RSA-PSS parameters that are not well-formed DER",
    function () { return pki.cms.verify(withPss(Buffer.from([0x30, 0x0a]))); }, "cms/bad-der");

  // Structural malformations of the RSASSA-PSS-params (crafted DER the resolver must reject
  // field-by-field), each a fail-closed unsupported-algorithm verdict.
  var SHA256 = pki.oid.byName("sha256"), MGF1 = pki.oid.byName("mgf1");
  var goodHash = b.sequence([b.oid(SHA256), b.nullValue()]);
  var goodMgf = b.sequence([b.oid(MGF1), b.sequence([b.oid(SHA256), b.nullValue()])]);
  var goodSaltF = b.explicit(2, b.integer(32));
  var nonEmptyNull = Buffer.from([0x05, 0x01, 0x00]);   // a NULL TLV with non-empty content
  var structural = [
    ["hashAlgorithm inner not a SEQUENCE", b.sequence([b.explicit(0, b.oid(SHA256)), b.explicit(1, goodMgf), goodSaltF])],
    ["hashAlgorithm OID slot not an OID", b.sequence([b.explicit(0, b.sequence([b.integer(0), b.nullValue()])), b.explicit(1, goodMgf), goodSaltF])],
    ["hashAlgorithm NULL params non-empty", b.sequence([b.explicit(0, b.sequence([b.oid(SHA256), nonEmptyNull])), b.explicit(1, goodMgf), goodSaltF])],
    ["saltLength slot not an INTEGER", b.sequence([b.explicit(0, goodHash), b.explicit(1, goodMgf), b.explicit(2, b.oid(SHA256))])],
    ["MGF OID slot not an OID", b.sequence([b.explicit(0, goodHash), b.explicit(1, b.sequence([b.integer(0), b.sequence([b.oid(SHA256), b.nullValue()])])), goodSaltF])],
    ["a field tag beyond [3]", b.sequence([b.explicit(0, goodHash), b.explicit(1, goodMgf), goodSaltF, b.explicit(4, b.integer(0))])],
    ["fields out of order", b.sequence([b.explicit(1, goodMgf), b.explicit(0, goodHash)])],
    ["a non-context field", b.sequence([b.integer(0)])],
    ["a field with two children", b.sequence([b.contextConstructed(0, Buffer.concat([goodHash, goodHash])), b.explicit(1, goodMgf), goodSaltF])],
  ];
  for (var j = 0; j < structural.length; j++) {
    var rs = await pki.cms.verify(withPss(structural[j][1]));
    check("RSA-PSS " + structural[j][0] + " -> unsupported-algorithm", rs.valid === false && rs.signers[0].code === "cms/unsupported-algorithm");
  }
}

// ---- signatureAlgorithm parameters shape (RFC 5754): NULL for RSA, absent for ECDSA/EdDSA ----
async function testAlgParams() {
  // The fixture with `params` on its SignerInfo signatureAlgorithm, in the ENCODING (null omits
  // the field). The signature algorithm each fixture was signed with names the AlgorithmIdentifier
  // to rewrite, and the LAST one is the SignerInfo's own.
  function withParams(fixture, algName, params) {
    var der = fx(fixture);
    var r = surgery.replaceLastAlgId(der, pki.oid.byName(algName), function (n) {
      return params == null ? b.sequence([Buffer.from(n.children[0].bytes)])
        : surgery.algIdWithParams(n.children[0].bytes, params);
    });
    check(algName + " AlgorithmIdentifier located in " + fixture, r.count >= 1);
    check(algName + " parameter splice changed the DER", !r.der.equals(der));
    return r.der;
  }
  var un = "cms/unsupported-algorithm";
  // RSA PKCS#1 v1.5: parameters MUST be a DER NULL -- absent or non-NULL fails closed.
  var r1 = await pki.cms.verify(withParams("rsa-attached.p7s", "rsaEncryption", null));
  check("rsaEncryption with absent params -> unsupported", r1.valid === false && r1.signers[0].code === un);
  var r1b = await pki.cms.verify(withParams("rsa-attached.p7s", "rsaEncryption", b.integer(0)));
  check("rsaEncryption with non-NULL params -> unsupported", r1b.valid === false && r1b.signers[0].code === un);
  // ECDSA: parameters MUST be absent -- a present (even NULL) parameter fails closed.
  var r2 = await pki.cms.verify(withParams("ec-attached.p7s", "ecdsaWithSHA256", b.nullValue()));
  check("ecdsaWithSHA256 with present params -> unsupported", r2.valid === false && r2.signers[0].code === un);
  // EdDSA: parameters MUST be absent (RFC 8419 sec. 3). This one the DECODER enforces, so the
  // message is refused whole rather than reported per signer -- the strictest of the three, and
  // the reason its code differs from its siblings above.
  await rejects("Ed25519 with present params", function () {
    return pki.cms.verify(withParams("ed25519-attached.p7s", "Ed25519", b.nullValue()));
  }, "cms/bad-algorithm-parameters");

  // digestAlgorithm parameters (RFC 5754 sec. 2): absent and NULL both accepted (the KATs use
  // both); a present non-NULL is malformed and fails closed.
  var dDer = fx("rsa-attached.p7s");
  var dPatched = surgery.replaceLastAlgId(dDer, pki.oid.byName("sha256"),
    function (n) { return surgery.algIdWithParams(n.children[0].bytes, b.integer(0)); });
  check("digestAlgorithm parameter splice changed the DER", !dPatched.der.equals(dDer));
  var rd = await pki.cms.verify(dPatched.der);
  check("digestAlgorithm with non-NULL params -> unsupported", rd.valid === false && rd.signers[0].code === un);
}

// Flip one byte of `value` where it sits in `der`. A one-byte edit leaves every TLV length intact,
// so the message stays well-formed and the only thing that changed is what it says.
function flipOneByteOf(der, value, label) {
  var out = Buffer.from(der);
  var at = out.indexOf(Buffer.from(value));
  check(label + " located in the encoding", at >= 0);
  out[at] = out[at] ^ 0xff;
  return out;
}

// ---- tampered: a valid structure over the wrong bytes never reads verified ----
async function testTampered() {
  // flip a signature byte (signedAttrs case): messageDigest still matches, crypto verdict false.
  // The element is found by its value in the message and flipped there, so what verify is handed
  // is a tampered ENCODING -- one byte, so every length stays intact.
  var d1 = flipOneByteOf(fx("rsa-attached.p7s"), pki.schema.cms.parse(fx("rsa-attached.p7s")).signerInfos[0].signature, "the signature");
  var r1 = await pki.cms.verify(d1);
  check("tampered signature -> invalid", r1.valid === false);
  check("tampered signature -> ok:false with no structural code", r1.signers[0].ok === false && !r1.signers[0].code);

  // flip a content byte (no-signedAttrs case): signature is over the content directly.
  var d2 = flipOneByteOf(fx("rsa-noattr.p7s"), pki.schema.cms.parse(fx("rsa-noattr.p7s")).encapContentInfo.eContent, "the eContent");
  var r2 = await pki.cms.verify(d2);
  check("tampered content (no-attrs) -> invalid", r2.valid === false && r2.signers[0].ok === false);
}

function oidMessageDigest() { return pki.oid.byName("messageDigest"); }
function oidContentType() { return pki.oid.byName("contentType"); }

// The checks decode the SignedAttributes from signedAttrsBytes (the verified preimage), so a
// malformed-attribute vector is crafted as those bytes, not as the parsed si.signedAttrs.
// id-data is rsa-attached's eContentType; a matching content-type lets the message-digest
// checks be reached.
var DATA_OID = "1.2.840.113549.1.7.1";
function _attr(typeOid, values) { return b.sequence([b.oid(typeOid), b.set(values)]); }
function _ctAttr(o) { return _attr(oidContentType(), [b.oid(o || DATA_OID)]); }
function _mdAttr() { return _attr(oidMessageDigest(), [b.octetString(Buffer.alloc(32))]); }
function _withSignedAttrs(attrs) {
  var der = fx("rsa-attached.p7s");
  var setOf = Buffer.from(b.set(attrs));
  setOf[0] = 0xA0;   // the on-wire [0] IMPLICIT tag verify re-tags back to a SET OF
  // Replace the real signedAttrs element, named by its own bytes, so the crafted attributes are
  // what the message carries -- and the enclosing lengths are rebuilt around the new size.
  var orig = pki.schema.cms.parse(der).signerInfos[0].signedAttrsBytes;
  var r = surgery.replaceTlv(der, orig, setOf);
  check("the signedAttrs element replaced exactly once", r.count === 1);
  return r.der;
}

// ---- malformed signed attributes (crafted into the signed bytes) ----
async function testBadSignedAttrs() {
  // Attributes malformed in the STRUCTURE are refused by the shared Attribute sub-schema as the
  // message is decoded, each naming the field that is wrong. They never reach the signature step,
  // so they are typed refusals rather than per-signer verdicts.
  // the SET OF carries something that is not an Attribute SEQUENCE.
  await rejects("a signed Attribute that is not a SEQUENCE", function () { return pki.cms.verify(_withSignedAttrs([b.integer(5)])); }, "cms/bad-attribute");
  // an Attribute whose type slot is not an OBJECT IDENTIFIER: the OID leaf reader refuses the tag,
  // in the codec's own domain -- pki.asn1 is a public namespace and its reader is what the CMS
  // schema composes here, so the code names the layer that actually refused.
  await rejects("a signed Attribute type not an OID", function () { return pki.cms.verify(_withSignedAttrs([b.sequence([b.integer(5), b.set([b.oid(DATA_OID)])])])); }, "asn1/unexpected-tag");
  // an Attribute whose values field is not a SET OF.
  await rejects("a signed Attribute values not a SET", function () { return pki.cms.verify(_withSignedAttrs([b.sequence([b.oid(oidContentType()), b.oid(DATA_OID)])])); }, "cms/bad-attribute-values");

  // a valid content-type but no message-digest attribute at all.
  await rejects("signedAttrs without message-digest", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr()])); }, "cms/missing-message-digest");
  // a message-digest attribute carrying more than one value.
  await rejects("message-digest with two values", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr(), _attr(oidMessageDigest(), [b.octetString(Buffer.alloc(32)), b.octetString(Buffer.alloc(32))])])); }, "cms/bad-message-digest-attr");
  // a message-digest attribute whose value is not an OCTET STRING.
  await rejects("message-digest value not an OCTET STRING", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr(), _attr(oidMessageDigest(), [b.integer(5)])])); }, "cms/bad-message-digest-attr");
}

// ---- content-type signed attribute (RFC 5652 sec. 5.3) ----
async function testContentType() {
  // a content-type attribute whose OID does not equal the eContentType. The coherence rule is a
  // decoding rule here, so it is a typed refusal of the message rather than a per-signer verdict.
  await rejects("content-type != eContentType", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr("1.2.840.113549.1.7.2"), _mdAttr()])); }, "cms/content-type-mismatch");

  // no content-type attribute at all.
  await rejects("signedAttrs without content-type", function () { return pki.cms.verify(_withSignedAttrs([_mdAttr()])); }, "cms/missing-content-type");
  // a content-type attribute whose value is not an OBJECT IDENTIFIER.
  await rejects("content-type value not an OBJECT IDENTIFIER", function () { return pki.cms.verify(_withSignedAttrs([_attr(oidContentType(), [b.integer(5)]), _mdAttr()])); }, "cms/bad-content-type-attr");
  // a content-type attribute carrying more than one value.
  await rejects("content-type with two values", function () { return pki.cms.verify(_withSignedAttrs([_attr(oidContentType(), [b.oid(DATA_OID), b.oid(DATA_OID)]), _mdAttr()])); }, "cms/bad-content-type-attr");
}

// ---- a parse result is re-derived from the bytes it was parsed from, so writing to one changes
// nothing about the verdict it produces ----
async function testSignedAttrsBinding() {
  var crypto = require("node:crypto");
  // Assign to the parsed messageDigest attribute so it matches attacker-chosen content, leaving
  // signedAttrsBytes (the bytes the signature actually covers) alone. Passing a parse result back
  // is supported, so this has to be defeated rather than merely unsupported: verify re-derives the
  // whole structure from the bytes the parser recorded, and the assignment is simply not there.
  var p = pki.schema.cms.parse(fx("rsa-detached.p7s"));
  var attacker = Buffer.from("attacker-chosen content that was never signed");
  var mdOid = oidMessageDigest();
  var forged = crypto.createHash("sha256").update(attacker).digest();
  p.signerInfos[0].signedAttrs.forEach(function (a) { if (a.type === mdOid) a.values[0] = b.octetString(forged); });
  var r = await pki.cms.verify(p, { content: attacker });
  check("an assigned messageDigest cannot forge a valid verdict", r.valid === false);

  // The same for a content-type assignment: the verdict is the one the BYTES earn -- here still
  // valid, because nothing about the message actually changed.
  var p2 = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  p2.signerInfos[0].signedAttrs.forEach(function (a) { if (a.type === oidContentType()) a.values[0] = b.oid("1.2.840.113549.1.7.2"); });
  var r2 = await pki.cms.verify(p2);
  check("an assigned content-type does not change the verdict", r2.valid === true);

  // And the same message presented as a REBUILT object -- every field copied out of a genuine
  // parse result into a fresh object -- is refused outright rather than believed, because nothing
  // ties those fields to any one message. This is the substitution the re-derivation exists for:
  // keep a real signer's signature and signed attributes, put other content beside them, and each
  // field is individually well-formed while together they describe a message nobody signed.
  var real = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  var rebuilt = {
    version: real.version, digestAlgorithms: real.digestAlgorithms, certificates: real.certificates,
    crls: real.crls, encapContentInfo: real.encapContentInfo, signerInfos: real.signerInfos,
  };
  await rejects("a rebuilt SignedData object", function () { return pki.cms.verify(rebuilt); }, "cms/bad-input");

  // The specific forgery it closes: null out signedAttrsBytes and hand the signature's own
  // preimage back as the content under any eContentType. With no signed attributes the signature
  // is checked over the content directly -- which IS that preimage -- and neither the content-type
  // nor the message-digest check runs, so every part of the check passes.
  var si = real.signerInfos[0];
  var preimage = Buffer.from(si.signedAttrsBytes);
  preimage[0] = 0x31;   // [0] IMPLICIT -> the universal SET OF the signature covers
  var swapped = {
    version: real.version, digestAlgorithms: real.digestAlgorithms, certificates: real.certificates,
    encapContentInfo: { eContentType: "1.2.3.4.5.6.7.8", eContent: preimage },
    signerInfos: [{
      version: si.version, sid: si.sid, digestAlgorithm: si.digestAlgorithm,
      signatureAlgorithm: si.signatureAlgorithm, signedAttrs: undefined, signedAttrsBytes: null,
      signature: si.signature, unsignedAttrs: si.unsignedAttrs,
    }],
  };
  await rejects("a SignerInfo re-presented over its own signed-attribute preimage",
    function () { return pki.cms.verify(swapped); }, "cms/bad-input");

  // A structure missing the fields the verb reads is named as the wrong thing, never dereferenced.
  await rejects("an object with an empty signerInfos and nothing else",
    function () { return pki.cms.verify({ signerInfos: [] }); }, "cms/bad-input");
  await rejects("an object whose SignerInfo is empty",
    function () { return pki.cms.verify({ signerInfos: [{}], encapContentInfo: { eContent: Buffer.alloc(0) } }); }, "cms/bad-input");
}

// ---- the signed-attribute stripping forgery, built as BYTES ------------------
//
// A CMS signature does not commit to WHETHER signed attributes were present, so a signature made
// over a SignedAttributes block can be re-presented as one made over content: drop the signedAttrs
// field and set the encapsulated content to the DER of those same attributes. RFC 5652 sec. 5.4
// then says the signature is over the content itself, which is exactly what it covers -- and with
// no attributes there is no message-digest or content-type attribute left to disagree. This is
// draft-vangeest-lamps-cms-euf-cma-signeddata Attack Type 1, and it needs no object manipulation:
// the whole thing is expressible in DER, which is what an attacker actually controls.
//
// The re-derivation vectors above stop a caller-ASSEMBLED object. They do not touch this, and the
// standards fix is a protocol change (signing with a context string) no verifier can apply alone.
// What a verifier CAN do is refuse the shape: the content of every such forgery is the encoded
// SignedAttributes of a real message, which sec. 5.3 requires to carry both a content-type and a
// message-digest attribute. That is a necessary condition of the attack and a shape ordinary
// content does not have.
function _asSignedAttrsSetOf(signedAttrsBytes) {
  var preimage = Buffer.from(signedAttrsBytes);
  preimage[0] = 0x31;   // the on-wire [0] IMPLICIT -> the universal SET OF the signature covers
  return preimage;
}
// Rebuild a SignedData in DER carrying `si` with NO signedAttrs over `content`, signature verbatim.
// A null `content` builds the DETACHED form (no eContent), for a caller supplying it via opts.content.
function _stripAttrsForgery(parsed, content, eContentType) {
  var si = parsed.signerInfos[0];
  function algId(a) { return a.parameters ? b.sequence([b.oid(a.oid), b.raw(a.parameters)]) : b.sequence([b.oid(a.oid)]); }
  var forgedSi = b.sequence([
    b.integer(BigInt(si.version)),
    b.sequence([b.raw(si.sid.issuer.bytes), b.integer(BigInt("0x" + si.sid.serialNumberHex))]),
    algId(si.digestAlgorithm), algId(si.signatureAlgorithm),
    b.octetString(Buffer.from(si.signature)),
  ]);
  var signedData = b.sequence([
    b.integer(1n),
    b.set([algId(si.digestAlgorithm)]),
    content == null ? b.sequence([b.oid(eContentType)]) : b.sequence([b.oid(eContentType), b.explicit(0, b.octetString(content))]),
    b.contextConstructed(0, Buffer.concat(parsed.certificates.map(function (c) { return Buffer.from(c.bytes); }))),
    b.set([b.raw(forgedSi)]),
  ]);
  return b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, b.raw(signedData))]);
}

async function testSignedAttrsStripping() {
  var s = makeSigner("ec-p256");
  var genuine = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  var p = pki.schema.cms.parse(genuine);
  var signerCert = Buffer.from(p.certificates[0].bytes);
  check("the genuine message verifies", (await pki.cms.verify(genuine)).valid === true);

  var forged = _stripAttrsForgery(p, _asSignedAttrsSetOf(p.signerInfos[0].signedAttrsBytes), "1.2.840.113549.1.7.1");
  var r = await pki.cms.verify(forged, { certs: [signerCert] });
  check("a stripped-attributes forgery does not read as valid", r.valid === false);
  check("...and says why, rather than failing as a bad signature it is not",
    r.signers[0].code === "cms/ambiguous-content");

  // The signature really is genuine over those bytes -- the refusal is the SHAPE, not a crypto
  // failure, which is what makes this worth a distinct code an operator can act on.
  check("the reused signature is genuinely valid over the substituted content",
    r.signers[0].ok === false && r.signers[0].code !== "cms/bad-signature");

  // The rule must not cost a legitimate no-attributes message, which is the whole risk of the fix.
  var noAttrs = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key }, { signedAttributes: false });
  check("a legitimate no-signed-attributes message still verifies",
    (await pki.cms.verify(noAttrs)).valid === true);
  check("...and the OpenSSL-produced no-attrs fixture still verifies",
    (await pki.cms.verify(fx("rsa-noattr.p7s"))).valid === true);

  // Content that is merely attribute-SHAPED but lacks the two attributes sec. 5.3 makes mandatory
  // is not the forgery and must not be refused -- the detector is a necessary condition, not a
  // guess at anything SET-OF-shaped.
  var nearMiss = b.set([b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])])]);
  var nm = await pki.cms.sign(nearMiss, { cert: s.cert, key: s.key }, { signedAttributes: false });
  check("a SET OF attributes WITHOUT a message-digest is not the forgery shape",
    (await pki.cms.verify(nm)).valid === true);

  // The detector reads the two mandatory attributes down to their VALUES. RFC 5652 sec. 11.1 makes
  // content-type a single OBJECT IDENTIFIER and sec. 11.2 makes message-digest a single OCTET
  // STRING, so a set carrying those OIDs over an empty or wrongly-typed value cannot be the
  // preimage of any real signature -- refusing it would cost a caller whose content merely
  // resembles the shape. The condition has to stay NECESSARY to the attack.
  var wrongValues = [
    ["empty value sets", b.set([
      b.sequence([b.oid(oidContentType()), b.set([])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([])]),
    ])],
    ["a content-type value that is not an OID", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.integer(5n)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
    ])],
    ["a message-digest value that is not an OCTET STRING", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.integer(5n)])]),
    ])],
    ["two content-type values", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID), b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
    ])],
    // Right tag, unreadable body: an OBJECT IDENTIFIER with no content cannot be the preimage of
    // anything, because the real SignedAttributes parser reads that value and would have refused
    // it. Cardinality and tag alone are not the condition -- the value has to READ.
    ["an empty content-type OID body", b.set([
      b.sequence([b.oid(oidContentType()), b.set([Buffer.from([0x06, 0x00])])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
    ])],
    // RFC 5652 sec. 5.3 forbids repeating an attribute type, so a set that does could never have
    // been signed as a SignedAttributes -- the real parser refuses it.
    ["a repeated attribute type", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
    ])],
    // Every attribute is bounded 1..ATTRIBUTE_MAX_VALUES by the shared Attribute schema, not just
    // the two mandatory ones -- so an unrelated attribute with an empty value set also puts the set
    // outside what could ever have been signed.
    ["an unrelated attribute with an empty value set", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
      b.sequence([b.oid("1.2.3.4.5.6"), b.set([])]),
    ])],
    // sec. 11 also says WHERE each attribute may appear, and id-countersignature is forbidden in
    // signedAttrs (sec. 11.4). The real parser refuses that set as signedAttrs, so it cannot be the
    // preimage any signature covered -- and matching it would refuse ordinary content that merely
    // carried the attribute encoding. The placement rows are part of the condition, not a separate
    // concern from the value rules beside them.
    ["a countersignature attribute, forbidden in signedAttrs", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
      b.sequence([b.oid(pki.oid.byName("countersignature")), b.set([b.sequence([b.integer(1n)])])]),
    ])],
    // sec. 11.3 constrains signing-time the same way when it is present.
    ["an unreadable signing-time", b.set([
      b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
      b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
      b.sequence([b.oid(pki.oid.byName("signingTime")), b.set([b.integer(5n)])]),
    ])],
  ];
  for (var wv of wrongValues) {
    var signedWv = await pki.cms.sign(wv[1], { cert: s.cert, key: s.key }, { signedAttributes: false });
    check("attribute-shaped content with " + wv[0] + " is not refused",
      (await pki.cms.verify(signedWv)).valid === true);
  }

  // The condition is what a CONFORMING SignedAttributes can be, not what this decoder accepts. Its
  // per-attribute value cap is a resource limit this implementation chose; RFC 5652 gives an
  // AttributeValue set SIZE (1..MAX). A signer elsewhere can produce a block above that cap, and
  // the stripped message presents those bytes as opaque content where no cap applies -- so reading
  // the local limit as part of the shape would miss exactly the preimage the attack reuses.
  var manyValues = [];
  for (var mv = 0; mv < pki.C.LIMITS.ATTRIBUTE_MAX_VALUES + 44; mv++) manyValues.push(b.integer(BigInt(mv)));
  var bigAttrBlock = b.set([
    b.sequence([b.oid(oidContentType()), b.set([b.oid(DATA_OID)])]),
    b.sequence([b.oid(oidMessageDigest()), b.set([b.octetString(Buffer.alloc(32))])]),
    b.sequence([b.oid("1.2.3.4.5.6"), b.set(manyValues)]),
  ].sort(Buffer.compare));
  await rejects("a conforming attribute set larger than this decoder's own cap",
    function () { return pki.cms.sign(bigAttrBlock, { cert: s.cert, key: s.key }, { signedAttributes: false }); },
    "cms/ambiguous-content");

  // The preimage is also refused when it arrives DETACHED, via opts.content rather than eContent --
  // the check has to sit wherever the no-attributes preimage is chosen, not only on the attached
  // path. (Applied per SignerInfo by placement: it is inside the per-signer preimage computation,
  // so a message mixing an attributes-present signer with a stripped one is judged signer by
  // signer. testMultiSigner covers that ordinary multi-signer messages are unaffected.)
  var detachedForged = _stripAttrsForgery(p, null, DATA_OID);
  var rd = await pki.cms.verify(detachedForged, { certs: [signerCert], content: _asSignedAttrsSetOf(p.signerInfos[0].signedAttrsBytes) });
  check("the forgery is refused when the preimage arrives as detached content too",
    rd.valid === false && rd.signers[0].code === "cms/ambiguous-content");

  // The other direction (Attack Type 2): a signer must not be induced to sign attribute-shaped
  // content WITHOUT attributes, because that signature can then be promoted into an
  // attributes-present message. The refusal belongs at the signer too, not only at the verifier.
  var attrShaped = _asSignedAttrsSetOf(p.signerInfos[0].signedAttrsBytes);
  await rejects("signing attribute-shaped content with signedAttributes:false",
    function () { return pki.cms.sign(attrShaped, { cert: s.cert, key: s.key }, { signedAttributes: false }); },
    "cms/ambiguous-content");
  check("...but the same content signed WITH attributes is fine (it is unambiguous)",
    (await pki.cms.verify(await pki.cms.sign(attrShaped, { cert: s.cert, key: s.key }))).valid === true);

  // The refusal is decided on a SNAPSHOT, so a caller who still owns the options object cannot
  // arrange for the check and the signing to see different values. Flipping signedAttributes from
  // true to false the instant the call returns would otherwise skip the guard while the signer went
  // on to sign the attribute-shaped content directly -- minting exactly the signature the stripping
  // attack needs. Same for the content buffer: the bytes inspected must be the bytes signed.
  var racedOpts = { signedAttributes: true };
  var raced = pki.cms.sign(attrShaped, { cert: s.cert, key: s.key }, racedOpts);
  racedOpts.signedAttributes = false;                    // after the call, before it resolves
  var racedOut = await raced;
  check("flipping signedAttributes after the call cannot skip the refusal",
    pki.schema.cms.parse(racedOut).signerInfos[0].signedAttrsBytes != null);

  var mutableContent = Buffer.from(CONTENT);
  var racedContent = pki.cms.sign(mutableContent, { cert: s.cert, key: s.key }, { signedAttributes: false });
  mutableContent.fill(0x41);                             // rewrite the caller's buffer mid-flight
  var contentOut = await racedContent;
  check("the bytes signed are the bytes checked, not the caller's buffer as it later became",
    (await pki.cms.verify(contentOut, { content: CONTENT })).valid === true);

  // The verdict has to let an operator apply a stricter policy of their own, which needs both the
  // content type and whether attributes were present -- neither was reachable without a second parse.
  var vGen = await pki.cms.verify(genuine);
  var vNo = await pki.cms.verify(noAttrs);
  check("the verdict names the content type", vGen.eContentType === DATA_OID);
  check("the verdict says whether each signer's attributes were present",
    vGen.signers[0].signedAttributesPresent === true && vNo.signers[0].signedAttributesPresent === false);
}

// ---- EdDSA signer keys must be validated on-curve and full-order before verify ----
// Zero the `len` bytes that follow `pattern` in `der` -- an SPKI public-key point, replaced in
// place with the all-zeroes low-order point. Fixed width, so the encoding stays well-formed.
function zeroPointAfter(der, pattern, len, label) {
  var out = Buffer.from(der);
  var i = out.indexOf(pattern);
  check(label + " SPKI point located in the signer cert", i >= 0);
  out.fill(0x00, i + pattern.length, i + pattern.length + len);
  return out;
}

async function testEdPointValidation() {
  // node/OpenSSL imports a low-order (e.g. all-zeroes) Ed25519 SPKI without complaint and such
  // a key can verify a forged signature; the point MUST be rejected before verify.
  // The certificate rides the message verbatim, so the point is zeroed where it sits IN the
  // message -- a fixed-width fill, so every enclosing length still holds.
  var pat = Buffer.from([0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]);   // Ed25519 OID tail + BIT STRING(33) + 0 unused bits
  var red = await pki.cms.verify(zeroPointAfter(fx("ed25519-attached.p7s"), pat, 32, "Ed25519"));
  check("Ed25519 low-order signer point rejected before verify", red.valid === false && red.signers[0].code === "cms/bad-signature");

  // the one-shot sameKeyOid guard: an Ed448 signatureAlgorithm over an Ed25519 signer key is an
  // algorithm mismatch (the key and signature share one OID, RFC 8410), rejected before import.
  // Only the SignerInfo's AlgorithmIdentifier is rewritten, so the certificate still says Ed25519
  // and the two genuinely disagree.
  var mism = surgery.replaceLastAlgId(fx("ed25519-attached.p7s"), pki.oid.byName("Ed25519"),
    function () { return b.sequence([b.oid(pki.oid.byName("Ed448"))]); });
  check("Ed448 signatureAlgorithm swap changed the DER", !mism.der.equals(fx("ed25519-attached.p7s")));
  var rMism = await pki.cms.verify(mism.der);
  check("Ed448 sig-alg over an Ed25519 signer key -> algorithm mismatch", rMism.valid === false && rMism.signers[0].code === "cms/unsupported-algorithm");

  // the Ed448 curve selector in the point validator: a genuine Ed448 signer whose public-key point
  // is zeroed (a low-order point) is rejected before verify, exactly as the Ed25519 case above.
  var signed448 = await pki.cms.sign(CONTENT, makeSigner("ed448"));
  var pat448 = Buffer.from([0x2B, 0x65, 0x71, 0x03, 0x3A, 0x00]);   // Ed448 OID tail + BIT STRING(58) + 0 unused bits
  var r448 = await pki.cms.verify(zeroPointAfter(signed448, pat448, 57, "Ed448"));
  check("Ed448 low-order signer point rejected before verify", r448.valid === false && r448.signers[0].code === "cms/bad-signature");
}

// ---- config-time misuse throws typed cms/bad-input ----
async function testBadInput() {
  await rejects("options a string", function () { return pki.cms.verify(fx("rsa-attached.p7s"), "nope"); }, "cms/bad-input");
  await rejects("options a Buffer", function () { return pki.cms.verify(fx("rsa-attached.p7s"), Buffer.from([1])); }, "cms/bad-input");
  await rejects("detached content wrong type", function () { return pki.cms.verify(fx("rsa-detached.p7s"), { content: 12345 }); }, "cms/bad-input");
}

// An id-countersignature value that is not a well-formed SignerInfo refuses the WHOLE message
// rather than being surfaced as one failed countersignature among the verdicts.
//
// That is the choice, and it is the fail-closed one: the decoder validates every countersignature
// value by CONTENT rather than trusting the attribute type, so a message carrying one is malformed
// and there is no sound reading of the rest of it to report. Surfacing it per-countersignature
// would mean handing back a verdict assembled from a structure the decoder had already found to be
// wrong. The rule is pinned here through the shipped verbs because it is a property of the message,
// not of the countersignature walk: schema-cms.test.js covers the BER-envelope path separately.
async function testMalformedCountersignatureValue() {
  var s = makeSigner("ec-p256");
  // The baseline first: a real countersignature verifies and is reported, so a refusal below is the
  // malformed VALUE being caught rather than the countersignature path failing generally.
  var signed = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  var countersigned = await pki.cms.countersign(signed, { cert: s.cert, key: s.key });
  var baseline = await pki.cms.verify(countersigned, { certs: [s.cert] });
  check("a real countersignature verifies and is reported",
    baseline.valid === true && (baseline.signers[0].countersignatures || []).length === 1 &&
    baseline.signers[0].countersignatures[0].ok === true);
  // A countersignature that verified carries no code, so a reader can tell a failure row from a
  // successful one by the field's presence.
  check("a countersignature row that verified carries no code field",
    Object.keys(baseline.signers[0].countersignatures[0]).join(",") ===
      "ok,sid,cert,digestAlgorithm,unsignedAttrs,countersignatures");

  var notSignerInfos = [
    ["an INTEGER", b.integer(5n)],
    ["an empty SEQUENCE", b.sequence([])],
    ["a SEQUENCE whose version is not a CMS one", b.sequence([b.integer(99n)])],
    ["an OCTET STRING of noise", b.octetString(Buffer.from([1, 2, 3, 4]))],
  ];
  function verifying(message) { return function () { return pki.cms.verify(message, { certs: [s.cert] }); }; }
  for (var i = 0; i < notSignerInfos.length; i++) {
    var msg = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key },
      { unsignedAttributes: [{ type: "countersignature", values: [notSignerInfos[i][1]] }] });
    await rejects("a countersignature value that is " + notSignerInfos[i][0] + " refuses the message",
      verifying(msg), i === 2 ? "cms/bad-version" : "cms/bad-signer-info");
  }
}

// Rewrite the SignerInfo's OWN digestAlgorithm / signatureAlgorithm in a SignedData encoding. The
// algorithm currently there names which AlgorithmIdentifier to find, and the LAST one is the
// SignerInfo's: the SignerInfo follows both digestAlgorithms and the certificates.
function signerAlgId(der, which, build) {
  var cur = pki.schema.cms.parse(der).signerInfos[0][which].oid;
  var r = surgery.replaceLastAlgId(der, cur, build);
  check("the SignerInfo " + which + " located", r.count >= 1);
  check("the SignerInfo " + which + " rewrite changed the DER", !r.der.equals(der));
  return r.der;
}
function swapSignerDigest(der, toOidName) {
  return signerAlgId(der, "digestAlgorithm", function () { return b.sequence([b.oid(pki.oid.byName(toOidName))]); });
}
function signerDigestParams(der, params) {
  return signerAlgId(der, "digestAlgorithm", function (n) { return surgery.algIdWithParams(n.children[0].bytes, params); });
}
function swapSignerSigAlg(der, toOidName) {
  return signerAlgId(der, "signatureAlgorithm", function () { return b.sequence([b.oid(pki.oid.byName(toOidName))]); });
}
function signerSigAlgParams(der, params) {
  return signerAlgId(der, "signatureAlgorithm", function (n) { return surgery.algIdWithParams(n.children[0].bytes, params); });
}
// Overwrite `oldValue` with `newValue` where it sits in `der`. Equal lengths only, so the encoding
// is untouched apart from the value itself.
function overwriteValue(der, oldValue, newValue, label) {
  check(label + " replacement is the same length", oldValue.length === newValue.length);
  var out = Buffer.from(der);
  var at = out.indexOf(Buffer.from(oldValue));
  check(label + " located in the encoding", at >= 0);
  Buffer.from(newValue).copy(out, at);
  return out;
}

// ---- ML-DSA (RFC 9882) verify-side rejects ----
async function testMlDsaVerify() {
  // a valid ML-DSA-65 SignedData verifies (the full sign round-trip is covered in cms-sign.test.js).
  check("ML-DSA-65 SignedData verifies", (await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")))).valid === true);
  // a SignedData with NO embedded certificates: the signer certificate is supplied out-of-band via
  // opts.certs (drives the `parsed.certificates || []` no-embed path).
  var noEmbed = await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { certificates: false });
  var outOfBandCert = Buffer.from(pki.schema.cms.parse(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"))).certificates[0].bytes);
  check("ML-DSA-65 no embedded cert -> signer-cert-not-found without opts.certs",
    (await pki.cms.verify(noEmbed)).signers[0].code === "cms/signer-cert-not-found");
  // an out-of-band candidate supplied as a raw DER Buffer via opts.certs (the raw-value arm of the
  // candidate loader) -- the certificate that goes with THIS message, so it verifies.
  var reSigned = await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { certificates: false });
  check("ML-DSA-65 raw-Buffer opts.certs candidate -> a verdict, not a throw",
    typeof (await pki.cms.verify(reSigned, { certs: [outOfBandCert] })).valid === "boolean");
  // R3 -- signatureAlgorithm / signer-key parameter-set disagreement (the sameKeyOid guard).
  var m3 = swapSignerSigAlg(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")), "id-ml-dsa-87");
  check("R3 sig-alg id-ml-dsa-87 over an id-ml-dsa-65 key -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(m3)));
  // R1 -- signatureAlgorithm parameters present where absent is required. The decoder enforces
  // this one, so the message is refused whole rather than reported per signer.
  var m1 = signerSigAlgParams(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")), b.nullValue());
  await rejects("R1 ML-DSA signatureAlgorithm parameters present", function () { return pki.cms.verify(m1); }, "cms/bad-algorithm-parameters");
  // R2 -- digestAlgorithm parameters present and non-NULL.
  var m2 = signerDigestParams(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")), b.octetString(Buffer.from([0x00])));
  check("R2 ML-DSA digestAlgorithm non-NULL parameters -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(m2)));
  // R14 -- a SHA-2 ML-DSA digestAlgorithm (id-sha512) carrying a DER NULL parameter is ACCEPTED:
  // RFC 9882 says signers omit it, but RFC 5754 requires a verifier to accept SHA-2 with absent OR NULL.
  var m14 = signerDigestParams(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")), b.nullValue());
  check("R14 ML-DSA sha512 digestAlgorithm DER NULL parameter -> accepted (RFC 5754)", (await pki.cms.verify(m14)).valid === true);
  // R14b -- a SHAKE256 ML-DSA digestAlgorithm with a present parameter (even DER NULL) is REJECTED:
  // RFC 8702 sec. 3.1 requires the SHAKE parameters absent, with no NULL exception.
  var m14b = signerDigestParams(await pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-44"), { digestAlgorithm: "shake256" })), b.nullValue());
  check("R14b ML-DSA shake256 digestAlgorithm NULL parameter -> unsupported (RFC 8702)", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(m14b)));
  // R8 -- an unwired message digest (SHA3-512) with signed attributes present.
  var m8 = swapSignerDigest(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")), "sha3-512");
  check("R8 ML-DSA unsupported message digest -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(m8)));
  // R12 (verify side) -- a below-strength message digest for the parameter set (SHA-256 / ML-DSA-87).
  var m12 = swapSignerDigest(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-87")), "sha256");
  check("R12 SHA-256 under ML-DSA-87 (below strength) -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(m12)));
  // R7 -- empty-context binding (RFC 9882 sec. 3.2): an ML-DSA signature computed under a NON-EMPTY
  // context does not verify under CMS, which signs and verifies with the empty context. Re-sign the
  // exact preimage with a context and swap it in -> the verdict is invalid (a code-less false, no throw).
  var s7 = makeSigner("ml-dsa-65");
  var der7 = await pki.cms.sign(CONTENT, s7);
  var p7 = pki.schema.cms.parse(der7);
  var preimage7 = Buffer.from(p7.signerInfos[0].signedAttrsBytes); preimage7[0] = 0x31;   // [0] IMPLICIT -> universal SET OF
  var ctxSig = require("node:crypto").sign(null, preimage7, { key: s7.keyObject, context: Buffer.from("ctx") });
  var swapped7 = overwriteValue(der7, p7.signerInfos[0].signature, ctxSig, "the ML-DSA signature");
  check("R7 non-empty-context ML-DSA signature -> invalid under empty-context verify", (await pki.cms.verify(swapped7)).valid === false);
  // M9 -- with NO signed attributes the digestAlgorithm has no meaning and is ignored on verify:
  // neither an unsupported digest NAME nor a present (non-NULL) PARAMETER may reject the signature.
  var noattr = swapSignerDigest(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { signedAttributes: false }), "sha3-512");
  check("M9 no-signed-attrs verify ignores digestAlgorithm name", (await pki.cms.verify(noattr, { content: CONTENT })).valid === true);
  // opts.content that DIFFERS from an attached SignedData's own eContent is a substitution trap -> reject.
  await rejects("opts.content differing from an attached SignedData's eContent -> cms/content-conflict", function () { return pki.cms.verify(noattr, { content: Buffer.from("a different content the signature never covered") }); }, "cms/content-conflict");
  // R15 -- a present, non-NULL digestAlgorithm parameter is likewise ignored without signed attributes.
  var m15 = signerDigestParams(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { signedAttributes: false }), b.octetString(Buffer.from([0x00])));
  check("R15 no-attrs ML-DSA ignores a present digestAlgorithm parameter", (await pki.cms.verify(m15, { content: CONTENT })).valid === true);
}

// The result must describe the bytes the signature was checked against. verify()
// parses synchronously and verifies in a later promise turn, so a caller's buffer
// rewritten in that gap must not be able to yield a valid result over content the
// signature never covered -- the accidental form of this is a pooled read buffer
// recycled across concurrent verifies, not an attacker.
async function testParseVerifyReadSameBytes() {
  var der = await pki.cms.sign(Buffer.from("the bytes that were actually signed"), makeSigner("ec-p256"));

  var raced = Buffer.from(der);
  var out = null, err = null;
  var p = pki.cms.verify(raced);
  raced.fill(0x41);                       // rewritten on the very next line
  try { out = await p; } catch (e) { err = e; }

  // Without the private copy the overwrite lands on the very bytes the signature
  // covers, so this comes back invalid or throws. Passing means parse and verify
  // both read memory the caller can no longer reach.
  check("TOCTOU. a buffer rewritten between parse and verify does not affect the verdict",
    err === null && out.valid === true && out.signers.length === 1);

  // ...for EVERY byte form the parser accepts, not just the two most common. A
  // BufferSource reaches the decoder, so an ArrayBuffer or a DataView left aliased
  // would reopen the window for exactly the inputs that came in by the wider door.
  var ab = new ArrayBuffer(der.length);
  new Uint8Array(ab).set(der);
  var viewOut = null, viewErr = null;
  var vp = pki.cms.verify(new DataView(ab));
  new Uint8Array(ab).fill(0x41);
  try { viewOut = await vp; } catch (e) { viewErr = e; }
  check("TOCTOU. a DataView's backing buffer rewritten after the call is equally ineffective",
    viewErr === null && viewOut.valid === true);
}

// ---- the trust seam: `valid` is signature soundness, `trusted` is chaining to a caller anchor ----
// A SignedData carries its own certificates, so verifying a signature against them establishes that
// the message is internally consistent -- nothing more. Anyone can mint a certificate, sign a message
// with it, and embed it. Without a way to name the roots a caller accepts, `valid: true` was the only
// answer this verb could give, and it reads as the stronger claim.
async function testTrustSeam() {
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2036-01-01T00:00:00Z");
  var crypto = require("crypto");

  async function mintCa(name) {
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    var key = kp.privateKey.export({ format: "der", type: "pkcs8" });
    var der = await pki.x509.sign({
      subject: [{ commonName: name }], subjectPublicKey: kp.publicKey.export({ format: "der", type: "spki" }),
      serialNumber: 1, notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
    }, { key: key });
    return { der: der, key: key };
  }
  async function mintLeafUnder(ca, name, serial) {
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    var der = await pki.x509.sign({
      subject: [{ commonName: name }], subjectPublicKey: kp.publicKey.export({ format: "der", type: "spki" }),
      serialNumber: serial, notBefore: NB, notAfter: NA,
      extensions: { keyUsage: ["digitalSignature"], subjectKeyIdentifier: true, authorityKeyIdentifier: true },
    }, { key: ca.key, cert: ca.der });
    return { cert: der, key: kp.privateKey.export({ format: "der", type: "pkcs8" }) };
  }

  var ourCa = await mintCa("cms-trust-ca.example");
  var otherCa = await mintCa("cms-other-ca.example");
  var leaf = await mintLeafUnder(ourCa, "cms-signer.example", 10);
  var signed = await pki.cms.sign(CONTENT, { cert: leaf.cert, key: leaf.key });
  var AT = { time: new Date("2026-06-01T00:00:00Z") };

  // The signature is sound either way -- that claim does not depend on anchoring, and callers
  // reading `valid` today must keep getting the same answer.
  var noAnchors = await pki.cms.verify(signed, AT);
  check("trust: with no anchors the signature still verifies", noAnchors.valid === true);
  check("trust: ...and the verdict says the signer was not anchored, rather than staying silent",
    noAnchors.trusted === false);

  var anchored = await pki.cms.verify(signed, Object.assign({ trustAnchors: [ourCa.der] }, AT));
  check("trust: a signer chaining to a supplied anchor is reported trusted",
    anchored.valid === true && anchored.trusted === true);

  // The discriminating case: the same message, same sound signature, anchors that do NOT issue it.
  // Without this the vector would pass on a `trusted` that merely echoed `valid`.
  var wrongAnchor = await pki.cms.verify(signed, Object.assign({ trustAnchors: [otherCa.der] }, AT));
  check("trust: a signer that does not chain to the supplied anchors is NOT trusted",
    wrongAnchor.trusted === false);
  check("trust: ...while its signature is still reported sound, which is a different claim",
    wrongAnchor.valid === true);

  // `trusted` is created with the verdict, on the message and on every signer row. An assignment
  // would consult the prototype chain, so a setter installed while the verification was pending
  // could swallow the write and leave its getter reporting a signer that was never anchored to
  // anything as trusted.
  var pollutedTrust = await (async function () {
    var pending = pki.cms.verify(signed, AT);   // no anchors: nothing here can be trusted
    Object.defineProperty(Object.prototype, "trusted",
      { configurable: true, get: function () { return true; }, set: function () {} });
    try {
      var r = await pending;
      return Object.prototype.hasOwnProperty.call(r, "trusted") && r.trusted === false &&
        Object.prototype.hasOwnProperty.call(r.signers[0], "trusted") && r.signers[0].trusted === false;
    } finally { delete Object.prototype.trusted; }
  })();
  check("trust: a polluted Object.prototype.trusted cannot report an unanchored signer as trusted",
    pollutedTrust);

  // A signer row settles through a promise of its own, and resolving one reads `then` off the
  // value. The row ends that lookup on itself, so an accessor installed while the signature check
  // is pending cannot rewrite the ok the message verdict is derived from.
  var badSig = Buffer.from(signed);
  badSig[badSig.length - 20] ^= 0x01;
  var pollutedRow = await (async function () {
    var pending = pki.cms.verify(badSig, AT);
    Object.defineProperty(Object.prototype, "then", { configurable: true,
      get: function () { try { this.ok = true; } catch (_e) { /* frozen */ } return undefined; } });
    try { return await pending; } finally { delete Object.prototype.then; }
  })();
  check("trust: an inherited then accessor cannot turn a failed signer row into a valid message",
    pollutedRow.valid === false && pollutedRow.signers[0].ok === false);

  // The trust verdict is a decision about the message, so it must not be reachable through the
  // prototype: `every` replaced after load answers true without consulting a single signer, and a
  // message no supplied anchor covers reports trusted:true.
  var realEvery = Array.prototype.every;
  Array.prototype.every = function () { return true; };
  var wrongAnchorSwapped;
  try { wrongAnchorSwapped = await pki.cms.verify(signed, Object.assign({ trustAnchors: [otherCa.der] }, AT)); }
  finally { Array.prototype.every = realEvery; }
  check("trust: ...and stays untrusted with Array.prototype.every replaced after load",
    wrongAnchorSwapped.trusted === false);
  // Signature soundness is the sibling verdict in the same function and answers the same way: a
  // message whose signature does not verify must not report valid:true because `every` was replaced.
  var forged = Buffer.from(signed);
  forged[forged.length - 1] ^= 0xff;   // corrupt the last signature byte
  var realEvery2 = Array.prototype.every;
  Array.prototype.every = function () { return true; };
  var forgedSwapped;
  try { forgedSwapped = await pki.cms.verify(forged, AT); }
  finally { Array.prototype.every = realEvery2; }
  check("trust: a corrupted signature stays invalid with Array.prototype.every replaced after load",
    forgedSwapped.valid === false);

  // A self-signed certificate the attacker minted and embedded: exactly what `valid: true` alone
  // could not distinguish from a real signer.
  var rogue = makeSigner("ec-p256");
  var rogueSigned = await pki.cms.sign(CONTENT, { cert: rogue.cert, key: rogue.key });
  var rogueV = await pki.cms.verify(rogueSigned, Object.assign({ trustAnchors: [ourCa.der] }, AT));
  check("trust: an attacker-minted self-signed signer verifies but is not trusted",
    rogueV.valid === true && rogueV.trusted === false);

  // The option that made the gap silent: a misspelling pinned nothing and said nothing.
  await rejects("trust: an unknown option is refused rather than swallowed",
    function () { return pki.cms.verify(signed, { trustAnchor: [ourCa.der] }); }, "cms/bad-input");

  // A caller's MISTAKE is not a verdict about the message. Anchors that cannot be read are a
  // configuration fault and must throw, because absorbing them into `trusted: false` would report
  // "this signer is not trusted" about a check that never ran -- the same conflation between an
  // answer and an absent answer that this whole seam exists to remove.
  var anchorFault = await (async function () {
    try { await pki.cms.verify(signed, Object.assign({ trustAnchors: [Buffer.from([1, 2, 3])] }, AT)); return "NO-THROW"; }
    catch (e) { return e && e.code; }
  })();
  check("trust: unusable anchors throw as a config fault rather than reading as untrusted",
    anchorFault !== "NO-THROW" && /bad-input|bad-anchor/.test(String(anchorFault)));
  // ...and that check does not depend on the MESSAGE being good. A SignedData whose signer cannot
  // be verified never reaches a chain walk, so validating the anchors only there would accept a
  // caller's mistake in silence for exactly the messages most likely to be hostile.
  var tamperedSig = Buffer.from(signed);
  tamperedSig[tamperedSig.length - 1] ^= 0xff;
  var faultOnBadMessage = await (async function () {
    try { await pki.cms.verify(tamperedSig, Object.assign({ trustAnchors: [Buffer.from([1, 2, 3])] }, AT)); return "NO-THROW"; }
    catch (e) { return e && e.code; }
  })();
  check("trust: unusable anchors are refused even when no signer verifies",
    faultOnBadMessage !== "NO-THROW" && /bad-input|bad-anchor/.test(String(faultOnBadMessage)));
  // The validation instant is held to the same rule as the anchors, and for the same reason:
  // whether a caller's configuration is usable must not depend on whether the message was good.
  await rejects("trust: an unusable validation time is refused",
    function () { return pki.cms.verify(signed, { trustAnchors: [ourCa.der], time: new Date("nope") }); },
    "cms/bad-input");
  await rejects("trust: ...and refused even when no signer verifies",
    function () { return pki.cms.verify(tamperedSig, { trustAnchors: [ourCa.der], time: new Date("nope") }); },
    "cms/bad-input");
  // A value that inherits from Date.prototype and holds no instant answers `instanceof Date`, so
  // a check keyed on that admits it and the `getTime()` behind it throws a raw TypeError out of
  // a verb whose refusals are all its own typed code.
  await rejects("trust: a validation time that inherits from Date and holds no instant",
    function () { return pki.cms.verify(signed, { trustAnchors: [ourCa.der], time: Object.create(Date.prototype) }); },
    "cms/bad-input");
  // The key-purpose options are held to the same rule as the anchors and the instant. Every part
  // of the trust configuration is judged in one place, before any signer is looked at, so a
  // caller's mistake never depends on whether the message happened to be good.
  var badPurposeCodes = await Promise.all([
    { requiredEku: [] }, { requiredEku: ["notARegisteredPurposeName"] }, { checkPurpose: "" },
    { checkPurpose: "notARegisteredPurposeName" },
  ].map(function (bad) {
    return (async function () {
      try { await pki.cms.verify(signed, Object.assign({ trustAnchors: [ourCa.der] }, bad, AT)); return "NO-THROW"; }
      catch (e) { return e && e.code; }
    })();
  }));
  check("trust: a malformed key-purpose option is refused",
    badPurposeCodes.every(function (c) { return c !== "NO-THROW" && /bad-input/.test(String(c)); }));
  var badPurposeOnBadMessage = await (async function () {
    try { await pki.cms.verify(tamperedSig, Object.assign({ trustAnchors: [ourCa.der], requiredEku: [] }, AT)); return "NO-THROW"; }
    catch (e) { return e && e.code; }
  })();
  check("trust: ...and refused even when no signer verifies",
    badPurposeOnBadMessage !== "NO-THROW" && /bad-input/.test(String(badPurposeOnBadMessage)));
  // The anchor's CONSTRAINT metadata is preflighted too, not just its name/key/algorithm. An
  // Invalid Date here is the NaN-Date fail-open: `notBefore > it` is NaN-false, silently dropping
  // the distrust restriction, so it must be refused rather than reaching a comparison.
  var badMetaAnchor = Object.assign(caAnchor({ serverAuth: true, emailProtection: true, codeSigning: false }),
    { distrustAfter: { emailProtection: new Date("not-a-date") } });
  var badMetaCodes = await Promise.all([signed, tamperedSig].map(function (msg) {
    return (async function () {
      try { await pki.cms.verify(msg, Object.assign({ trustAnchors: [badMetaAnchor], checkPurpose: "emailProtection" }, AT)); return "NO-THROW"; }
      catch (e) { return e && e.code; }
    })();
  }));
  check("trust: an anchor's malformed constraint metadata is refused, message good or not",
    badMetaCodes.every(function (c) { return c !== "NO-THROW" && /bad-input/.test(String(c)); }));
  // The same, with the purpose given in its DOTTED form. The resolver normalizes that to the
  // registered name, which is the key an anchor's per-purpose metadata is stored under -- so the
  // preflight has to read the normalized value, or it inspects `distrustAfter["1.3.6..."]` while
  // the walk reads `distrustAfter.emailProtection` and the two disagree about the same anchor.
  var dottedEmail = pki.oid.byName("emailProtection");
  var dottedCodes = await Promise.all([signed, tamperedSig].map(function (msg) {
    return (async function () {
      try { await pki.cms.verify(msg, Object.assign({ trustAnchors: [badMetaAnchor], checkPurpose: dottedEmail }, AT)); return "NO-THROW"; }
      catch (e) { return e && e.code; }
    })();
  }));
  check("trust: ...and equally when the purpose is named by its dotted OID",
    dottedCodes.every(function (c) { return c !== "NO-THROW" && /bad-input/.test(String(c)); }));
  await rejects("trust: an empty anchor list is refused rather than silently anchoring nothing",
    function () { return pki.cms.verify(signed, Object.assign({ trustAnchors: [] }, AT)); }, "cms/bad-input");

  // The chain is walked a promise turn after the call, and the anchors stay caller-owned across it.
  // Re-pointing the array, rewriting an anchor's bytes, or moving the instant would have the chain
  // judged against a configuration that was never asked for, while the verdict reports the one that
  // was. Mutate all three the way a pooled buffer would and the answer must not move.
  var raceAnchor = Buffer.from(ourCa.der);
  var raceArray = [raceAnchor];
  var raceTime = new Date(AT.time.getTime());
  var racePromise = pki.cms.verify(signed, { trustAnchors: raceArray, time: raceTime });
  raceArray[0] = otherCa.der;              // swap the slot
  raceArray.push(otherCa.der);             // and grow the array
  raceAnchor.fill(0);                      // and destroy the bytes it pointed at
  raceTime.setFullYear(1990);              // and move the instant out of validity
  check("trust: anchors mutated after the call still decide against what was passed (TOCTOU)",
    (await racePromise).trusted === true);

  // The anchor TUPLE form is caller-owned in the same way: `{ name, publicKey, algorithm }` is an
  // ordinary object whose key bytes can be rewritten as readily as a DER buffer's. Copying only the
  // DER spelling would close the window for one form of an anchor and leave it open for the other.
  var caParsed = pki.schema.x509.parse(ourCa.der);
  // The shape path-validate's own toAnchor produces from a certificate: publicKey is the whole
  // SPKI DER, and the algorithm parameters and subject DER ride along.
  var tuple = { name: caParsed.subject, algorithm: caParsed.subjectPublicKeyInfo.algorithm.oid,
    parameters: caParsed.subjectPublicKeyInfo.algorithm.parameters,
    subjectDer: caParsed.subject.bytes,
    publicKey: Buffer.from(caParsed.subjectPublicKeyInfo.bytes) };
  var tuplePromise = pki.cms.verify(signed, { trustAnchors: [tuple], time: AT.time });
  tuple.publicKey.fill(0);                 // destroy the key bytes the anchor comparison reads
  tuple.name = { rdns: [] };               // and replace the name it matches on
  check("trust: an anchor TUPLE mutated after the call still decides against what was passed",
    (await tuplePromise).trusted === true);
  // ...and the guarantee is absolute rather than shallow: an anchor too deep to copy is refused,
  // not copied down to some level and shared below it. A partial snapshot is worse than none,
  // because the promise reads as though it held everywhere.
  var deep = { name: { rdns: [] }, algorithm: "1.2.840.10045.2.1", publicKey: Buffer.alloc(4) };
  var cursor = deep;
  for (var d = 0; d < 12; d++) { cursor.nested = {}; cursor = cursor.nested; }
  await rejects("trust: an anchor nested deeper than it can be copied is refused, not part-copied",
    function () { return pki.cms.verify(signed, Object.assign({ trustAnchors: [deep] }, AT)); }, "cms/bad-input");

  // A subjectKeyIdentifier names a KEY, and several certificates can hold it: a self-signed one
  // embedded in the message beside a CA-issued one the caller supplies. Trust is decided from the
  // certificate the SignerInfo actually selected -- the one the verdict reports as `cert` -- and
  // never from a same-key sibling, which carries its own validity window, key usage and policy
  // set. Letting a sibling answer would report an expired or wrong-purpose signer certificate as
  // trusted because a different certificate for that key happened to chain.
  var twinKp = require("crypto").generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var twinSpki = twinKp.publicKey.export({ format: "der", type: "spki" });
  var twinKey = twinKp.privateKey.export({ format: "der", type: "pkcs8" });
  var twinSelfSigned = await pki.x509.sign({
    subject: [{ commonName: "twin-selfsigned.example" }], subjectPublicKey: twinSpki,
    serialNumber: 20, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectKeyIdentifier: true },
  }, { key: twinKey });
  var twinIssued = await pki.x509.sign({
    subject: [{ commonName: "twin-issued.example" }], subjectPublicKey: twinSpki,
    serialNumber: 21, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectKeyIdentifier: true, authorityKeyIdentifier: true },
  }, { key: ourCa.key, cert: ourCa.der });
  // Signed with the self-signed cert embedded and identified by SKI, so the embedded one matches first.
  var twinSigned = await pki.cms.sign(CONTENT, { cert: twinSelfSigned, key: twinKey, sid: "subjectKeyIdentifier" });
  var twinRes = await pki.cms.verify(twinSigned,
    Object.assign({ trustAnchors: [ourCa.der], certs: [twinIssued] }, AT));
  check("trust: a same-key sibling does not lend its trust to the certificate the message presented",
    twinRes.valid === true && twinRes.trusted === false);
  check("trust: ...and the verdict names the certificate the decision was made about",
    Buffer.isBuffer(twinRes.signers[0].cert) && twinRes.signers[0].cert.equals(twinSelfSigned));
  // The ANCHOR's own trust metadata is a separate question from the leaf's EKU, and pki.path reads
  // it only when a purpose is named. A root distributed with NSS trust bits can be marked
  // untrusted for email while remaining a good TLS root, so requiring the leaf's EKU without
  // naming the purpose checks one end of the chain and not the other -- and a root explicitly
  // distrusted for the purpose being asked about would still answer "trusted".
  function caAnchor(purposes) {
    var c = pki.schema.x509.parse(ourCa.der);
    return { name: c.subject, algorithm: c.subjectPublicKeyInfo.algorithm.oid,
      parameters: c.subjectPublicKeyInfo.algorithm.parameters, subjectDer: c.subject.bytes,
      publicKey: Buffer.from(c.subjectPublicKeyInfo.bytes), purposes: purposes };
  }
  var distrustedForEmail = caAnchor({ serverAuth: true, emailProtection: false, codeSigning: false });
  check("trust: an anchor distrusted for the named purpose does not confer trust",
    (await pki.cms.verify(signed, Object.assign({ trustAnchors: [distrustedForEmail],
      checkPurpose: "emailProtection" }, AT))).trusted === false);
  check("trust: ...and the same anchor trusted for that purpose does",
    (await pki.cms.verify(signed, Object.assign({ trustAnchors: [caAnchor({ serverAuth: true, emailProtection: true, codeSigning: false })],
      checkPurpose: "emailProtection" }, AT))).trusted === true);
  // distrustAfter carries DATES, and the snapshot must not flatten them. A Date has no enumerable
  // own properties, so a field-by-field copy yields `{}` -- the policy would survive as an empty
  // object and be rejected as an invalid date, disabling the constraint it encodes. Both sides are
  // asserted: a leaf issued before the cut-off stays trusted, one issued after does not.
  var emailOk = { serverAuth: true, emailProtection: true, codeSigning: false };
  var cutoff = new Date("2026-03-01T00:00:00Z");
  var withCutoff = Object.assign(caAnchor(emailOk), { distrustAfter: { emailProtection: cutoff } });
  check("trust: an anchor's distrustAfter dates survive the snapshot (leaf before the cut-off)",
    (await pki.cms.verify(signed, Object.assign({ trustAnchors: [withCutoff],
      checkPurpose: "emailProtection" }, AT))).trusted === true);
  var lateLeaf = await mintLeafUnder(ourCa, "late-signer.example", 40);
  var lateSigned = await pki.cms.sign(CONTENT, { cert: lateLeaf.cert, key: lateLeaf.key });
  var earlyCutoff = Object.assign(caAnchor(emailOk), { distrustAfter: { emailProtection: new Date("2025-01-01T00:00:00Z") } });
  check("trust: ...and a leaf issued after the cut-off is not trusted through that anchor",
    (await pki.cms.verify(lateSigned, Object.assign({ trustAnchors: [earlyCutoff],
      checkPurpose: "emailProtection" }, AT))).trusted === false);

  // A certificate that chains is not automatically a certificate permitted to have signed. When
  // keyUsage is present it says what the key may do, and RFC 5280 sec. 4.2.1.3 makes that binding:
  // a leaf asserting keyEncipherment alone must not verify a signature, however well it chains.
  // Path validation checks the CA's keyCertSign, not the target's signing usage, so the format
  // that KNOWS a signature was made asks the question.
  var noSignKp = require("crypto").generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var noSignKey = noSignKp.privateKey.export({ format: "der", type: "pkcs8" });
  var noSignCert = await pki.x509.sign({
    subject: [{ commonName: "no-signing-usage.example" }],
    subjectPublicKey: noSignKp.publicKey.export({ format: "der", type: "spki" }),
    serialNumber: 30, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["keyEncipherment"], subjectKeyIdentifier: true, authorityKeyIdentifier: true },
  }, { key: ourCa.key, cert: ourCa.der });
  var noSignSigned = await pki.cms.sign(CONTENT, { cert: noSignCert, key: noSignKey });
  var noSignRes = await pki.cms.verify(noSignSigned, Object.assign({ trustAnchors: [ourCa.der] }, AT));
  check("trust: a signer whose keyUsage forbids signing is not trusted, however well it chains",
    noSignRes.trusted === false);
  check("trust: ...while the signature itself is still reported as sound, which is a different claim",
    noSignRes.valid === true);

  // Presenting the CA-issued certificate itself is what makes it trusted -- the decision follows
  // the certificate, not the key.
  var twinDirect = await pki.cms.sign(CONTENT, { cert: twinIssued, key: twinKey, sid: "subjectKeyIdentifier" });
  check("trust: the same key IS trusted when the message presents the certificate that chains",
    (await pki.cms.verify(twinDirect, Object.assign({ trustAnchors: [ourCa.der] }, AT))).trusted === true);
}

// ENGINE-GAP-1/2 for pki.scep (and any signed-attribute consumer): cms.verify surfaces each signer's
// AUTHENTICATED attributes and the attached eContent, bound to the verified signature -- so a protocol's
// transaction state is read from what the signature covered, never a separate untrusted re-parse.
async function testSignedAttrsAndEContentSurface() {
  var s = makeSigner("ec-p256");
  var scepish = "1.3.6.1.5.5.7.24.1";   // an arbitrary OID standing in for a protocol's own signed attribute
  var p7 = await pki.cms.sign(CONTENT, s, { additionalSignedAttributes: [{ type: scepish, values: [b.octetString(Buffer.from("txn"))] }] });
  var v = await pki.cms.verify(p7);
  check("EG1. verify surfaces the authenticated attributes under the verified signer",
    v.valid === true && Array.isArray(v.signers[0].signedAttributes));
  var types = v.signers[0].signedAttributes.map(function (a) { return a.type; });
  check("EG1. the custom signed attribute is surfaced by OID (bound to the signer)", types.indexOf(scepish) >= 0);
  check("EG1. the standard authenticated attributes are surfaced (contentType + messageDigest)",
    types.indexOf(pki.oid.byName("contentType")) >= 0 && types.indexOf(pki.oid.byName("messageDigest")) >= 0);
  check("EG2. verify surfaces the attached eContent, equal to the signed content",
    Buffer.isBuffer(v.eContent) && v.eContent.equals(CONTENT));
  var det = await pki.cms.sign(CONTENT, s, { detached: true });
  check("EG2. a detached SignedData surfaces eContent:null", (await pki.cms.verify(det, { content: CONTENT })).eContent === null);
}

async function run() {
  await testTrustSeam();
  await testParseVerifyReadSameBytes();
  await testAcceptKats();
  await testMultiSigner();
  await testSignerIdentifier();
  await testDetached();
  await testCertLocation();
  await testMalformedCandidateCerts();
  await testCollidingSignerCert();
  await testInputForms();
  await testUnsupportedAlgorithm();
  await testRsaPssParams();
  await testAlgParams();
  await testTampered();
  await testBadSignedAttrs();
  await testContentType();
  await testSignedAttrsBinding();
  await testSignedAttrsAndEContentSurface();
  await testSignedAttrsStripping();
  await testEdPointValidation();
  await testMlDsaVerify();
  await testBadInput();
  await testMalformedCountersignatureValue();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
