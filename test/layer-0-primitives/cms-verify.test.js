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
  // path cannot resolve a curve and reports the fail-closed unsupported-algorithm verdict.
  var parsed = pki.schema.cms.parse(fx("ec-attached.p7s"));
  parsed.certificates[0].bytes = corruptEcParams(parsed.certificates[0].bytes);
  await rejects("signer cert with undecodable EC params", function () { return pki.cms.verify(parsed); }, "cms/unsupported-algorithm");
}

// ---- input forms: DER Buffer (covered above), PEM string, parsed object ----
async function testInputForms() {
  var pem = "-----BEGIN CMS-----\n" + fx("rsa-attached.p7s").toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CMS-----\n";
  var fromPem = await pki.cms.verify(pem);
  check("PEM string input -> valid", fromPem.valid === true);

  var parsed = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  var fromObj = await pki.cms.verify(parsed);
  check("parsed-object input -> valid", fromObj.valid === true);
}

// ---- unsupported algorithm: unregistered curve + bogus alg names ----
async function testUnsupportedAlgorithm() {
  // an EC signer cert on a curve outside the P-256/384/521 set the engine imports.
  await rejects("secp256k1 signer", function () { return pki.cms.verify(fx("ec-secp256k1.p7s")); }, "cms/unsupported-algorithm");

  // an unknown signatureAlgorithm is a per-signer verdict, not a throw.
  var p1 = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  p1.signerInfos[0].signatureAlgorithm.name = "not-a-real-alg";
  var r1 = await pki.cms.verify(p1);
  check("unknown signatureAlgorithm -> invalid", r1.valid === false);
  check("unknown signatureAlgorithm -> unsupported-algorithm code", r1.signers[0].code === "cms/unsupported-algorithm");

  // an unknown digestAlgorithm (non-EdDSA scheme) is likewise a verdict.
  var p2 = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  p2.signerInfos[0].digestAlgorithm.name = "not-a-real-digest";
  var r2 = await pki.cms.verify(p2);
  check("unknown digestAlgorithm -> unsupported-algorithm code", r2.signers[0].code === "cms/unsupported-algorithm");

  // EdDSA hashes internally, but a message-digest attribute is still computed under
  // digestAlgorithm. With signed attributes present and an unmapped digest, the verdict
  // must be a fail-closed cms/* one -- never a foreign-domain throw from the digest step.
  var p3 = pki.schema.cms.parse(fx("rsa-attached.p7s"));   // rsa-attached carries signedAttrs
  p3.signerInfos[0].signatureAlgorithm.name = "Ed25519";
  p3.signerInfos[0].digestAlgorithm.name = "not-a-real-digest";
  var r3 = await pki.cms.verify(p3);
  check("EdDSA + signedAttrs + unmapped digest -> unsupported-algorithm verdict", r3.valid === false && r3.signers[0].code === "cms/unsupported-algorithm");
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
function withPss(params) {
  var p = pki.schema.cms.parse(fx("rsapss-attached.p7s"));
  p.signerInfos[0].signatureAlgorithm.parameters = params;
  return p;
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

  // Every deviation from the supported profile is a fail-closed unsupported-algorithm verdict,
  // never verified under WebCrypto's own defaults.
  var cases = [
    ["absent params (rejected SHA-1 defaults)", null],
    ["non-SEQUENCE params", b.integer(5)],
    ["undecodable params", Buffer.from([0x30, 0x0a])],
    ["no hashAlgorithm field", pssParams({ noHash: true })],
    ["no maskGenAlgorithm field", pssParams({ noMgf: true })],
    ["no saltLength field", pssParams({ noSalt: true })],
    ["unsupported hash (SHA-1)", pssParams({ hashOid: pki.oid.byName("sha1") })],
    ["hash AlgorithmIdentifier with non-NULL params", pssParams({ hashNonNull: true })],
    ["saltLength != hash length", pssParams({ salt: 48 })],
    ["MGF not a SEQUENCE", pssParams({ mgfNotSeq: true })],
    ["MGF not MGF1", pssParams({ mgfOid: pki.oid.byName("sha256") })],
    ["MGF1 hash != signature hash", pssParams({ mgfHashOid: pki.oid.byName("sha384") })],
    ["trailerField != 1", pssParams({ trailer: 2 })],
  ];
  for (var i = 0; i < cases.length; i++) {
    var r = await pki.cms.verify(withPss(cases[i][1]));
    check("RSA-PSS " + cases[i][0] + " -> unsupported-algorithm", r.valid === false && r.signers[0].code === "cms/unsupported-algorithm");
  }

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
  function withParams(fixture, params) {
    var p = pki.schema.cms.parse(fx(fixture));
    p.signerInfos[0].signatureAlgorithm.parameters = params;
    return p;
  }
  var un = "cms/unsupported-algorithm";
  // RSA PKCS#1 v1.5: parameters MUST be a DER NULL -- absent or non-NULL fails closed.
  var r1 = await pki.cms.verify(withParams("rsa-attached.p7s", null));
  check("rsaEncryption with absent params -> unsupported", r1.valid === false && r1.signers[0].code === un);
  var r1b = await pki.cms.verify(withParams("rsa-attached.p7s", b.integer(0)));
  check("rsaEncryption with non-NULL params -> unsupported", r1b.valid === false && r1b.signers[0].code === un);
  // ECDSA: parameters MUST be absent -- a present (even NULL) parameter fails closed.
  var r2 = await pki.cms.verify(withParams("ec-attached.p7s", b.nullValue()));
  check("ecdsaWithSHA256 with present params -> unsupported", r2.valid === false && r2.signers[0].code === un);
  // EdDSA: parameters MUST be absent.
  var r3 = await pki.cms.verify(withParams("ed25519-attached.p7s", b.nullValue()));
  check("Ed25519 with present params -> unsupported", r3.valid === false && r3.signers[0].code === un);

  // digestAlgorithm parameters (RFC 5754 sec. 2): absent and NULL both accepted (the KATs use
  // both); a present non-NULL is malformed and fails closed.
  var d = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  d.signerInfos[0].digestAlgorithm.parameters = b.integer(0);
  var rd = await pki.cms.verify(d);
  check("digestAlgorithm with non-NULL params -> unsupported", rd.valid === false && rd.signers[0].code === un);
}

// ---- tampered: a valid structure over the wrong bytes never reads verified ----
async function testTampered() {
  // flip a signature byte (signedAttrs case): messageDigest still matches, crypto verdict false.
  var p1 = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  var sig = Buffer.from(p1.signerInfos[0].signature);
  sig[0] = sig[0] ^ 0xff;
  p1.signerInfos[0].signature = sig;
  var r1 = await pki.cms.verify(p1);
  check("tampered signature -> invalid", r1.valid === false);
  check("tampered signature -> ok:false with no structural code", r1.signers[0].ok === false && !r1.signers[0].code);

  // flip a content byte (no-signedAttrs case): signature is over the content directly.
  var p2 = pki.schema.cms.parse(fx("rsa-noattr.p7s"));
  var c = Buffer.from(p2.encapContentInfo.eContent);
  c[0] = c[0] ^ 0xff;
  p2.encapContentInfo.eContent = c;
  var r2 = await pki.cms.verify(p2);
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
  var setOf = Buffer.from(b.set(attrs));
  setOf[0] = 0xA0;   // the on-wire [0] IMPLICIT tag verify re-tags back to a SET OF
  var p = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  p.signerInfos[0].signedAttrsBytes = setOf;
  return p;
}

// ---- malformed signed attributes (crafted into the signed bytes) ----
async function testBadSignedAttrs() {
  // the SET OF carries something that is not an Attribute SEQUENCE.
  await rejects("a signed Attribute that is not a SEQUENCE", function () { return pki.cms.verify(_withSignedAttrs([b.integer(5)])); }, "cms/bad-signed-attrs");
  // an Attribute whose type slot is not an OBJECT IDENTIFIER.
  await rejects("a signed Attribute type not an OID", function () { return pki.cms.verify(_withSignedAttrs([b.sequence([b.integer(5), b.set([b.oid(DATA_OID)])])])); }, "cms/bad-signed-attrs");
  // an Attribute whose values field is not a SET OF.
  await rejects("a signed Attribute values not a SET", function () { return pki.cms.verify(_withSignedAttrs([b.sequence([b.oid(oidContentType()), b.oid(DATA_OID)])])); }, "cms/bad-signed-attrs");

  // a valid content-type but no message-digest attribute at all.
  await rejects("signedAttrs without message-digest", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr()])); }, "cms/bad-signed-attrs");
  // a message-digest attribute carrying more than one value.
  await rejects("message-digest with two values", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr(), _attr(oidMessageDigest(), [b.octetString(Buffer.alloc(32)), b.octetString(Buffer.alloc(32))])])); }, "cms/bad-signed-attrs");
  // a message-digest attribute whose value is not an OCTET STRING.
  await rejects("message-digest value not an OCTET STRING", function () { return pki.cms.verify(_withSignedAttrs([_ctAttr(), _attr(oidMessageDigest(), [b.integer(5)])])); }, "cms/bad-signed-attrs");
}

// ---- content-type signed attribute (RFC 5652 sec. 5.3) ----
async function testContentType() {
  // a content-type attribute whose OID does not equal the eContentType -> a verdict, not a throw.
  var r1 = await pki.cms.verify(_withSignedAttrs([_ctAttr("1.2.840.113549.1.7.2"), _mdAttr()]));
  check("content-type != eContentType -> invalid", r1.valid === false);
  check("content-type mismatch -> content-type-mismatch code", r1.signers[0].code === "cms/content-type-mismatch");

  // no content-type attribute at all.
  await rejects("signedAttrs without content-type", function () { return pki.cms.verify(_withSignedAttrs([_mdAttr()])); }, "cms/bad-signed-attrs");
  // a content-type attribute whose value is not an OBJECT IDENTIFIER.
  await rejects("content-type value not an OBJECT IDENTIFIER", function () { return pki.cms.verify(_withSignedAttrs([_attr(oidContentType(), [b.integer(5)]), _mdAttr()])); }, "cms/bad-signed-attrs");
  // a content-type attribute carrying more than one value.
  await rejects("content-type with two values", function () { return pki.cms.verify(_withSignedAttrs([_attr(oidContentType(), [b.oid(DATA_OID), b.oid(DATA_OID)]), _mdAttr()])); }, "cms/bad-signed-attrs");
}

// ---- the checked attributes must be the signed attributes (no parsed-object desync) ----
async function testSignedAttrsBinding() {
  var crypto = require("node:crypto");
  // Forgery attempt on the documented parsed-object path: mutate the parsed messageDigest
  // attribute to match attacker-chosen content while leaving signedAttrsBytes (the bytes the
  // signature actually covers) intact. Deriving the checked attributes from the signed bytes
  // -- not the mutable parsed si.signedAttrs -- must defeat this.
  var p = pki.schema.cms.parse(fx("rsa-detached.p7s"));
  var attacker = Buffer.from("attacker-chosen content that was never signed");
  var mdOid = oidMessageDigest();
  var forged = crypto.createHash("sha256").update(attacker).digest();
  p.signerInfos[0].signedAttrs.forEach(function (a) { if (a.type === mdOid) a.values[0] = b.octetString(forged); });
  var r = await pki.cms.verify(p, { content: attacker });
  check("mutated parsed messageDigest cannot forge a valid verdict", r.valid === false);

  // Likewise a mutated parsed content-type attribute must not change the verdict.
  var p2 = pki.schema.cms.parse(fx("rsa-attached.p7s"));
  p2.signerInfos[0].signedAttrs.forEach(function (a) { if (a.type === oidContentType()) a.values[0] = b.oid("1.2.840.113549.1.7.2"); });
  var r2 = await pki.cms.verify(p2);
  check("mutated parsed content-type does not change the verdict", r2.valid === true);
}

// ---- EdDSA signer keys must be validated on-curve and full-order before verify ----
async function testEdPointValidation() {
  // node/OpenSSL imports a low-order (e.g. all-zeroes) Ed25519 SPKI without complaint and such
  // a key can verify a forged signature; the point MUST be rejected before verify.
  var p = pki.schema.cms.parse(fx("ed25519-attached.p7s"));
  var cert = Buffer.from(p.certificates[0].bytes);
  var pat = Buffer.from([0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]);   // Ed25519 OID tail + BIT STRING(33) + 0 unused bits
  var i = cert.indexOf(pat);
  check("Ed25519 SPKI point located in the signer cert", i >= 0);
  cert.fill(0x00, i + pat.length, i + pat.length + 32);   // all-zeroes: a low-order point on the curve
  p.certificates[0].bytes = cert;
  await rejects("Ed25519 low-order signer point rejected before verify", function () { return pki.cms.verify(p); }, "cms/bad-signature");

  // the Ed448 curve selector: relabel the signer as Ed448 -- the Ed25519-sized point is not a
  // valid Ed448 point, so it is rejected before verify.
  var p448 = pki.schema.cms.parse(fx("ed25519-attached.p7s"));
  p448.signerInfos[0].signatureAlgorithm.name = "Ed448";
  await rejects("Ed448-labelled signer with a non-Ed448 point", function () { return pki.cms.verify(p448); }, "cms/bad-signature");
}

// ---- config-time misuse throws typed cms/bad-input ----
async function testBadInput() {
  await rejects("options a string", function () { return pki.cms.verify(fx("rsa-attached.p7s"), "nope"); }, "cms/bad-input");
  await rejects("options a Buffer", function () { return pki.cms.verify(fx("rsa-attached.p7s"), Buffer.from([1])); }, "cms/bad-input");
  await rejects("detached content wrong type", function () { return pki.cms.verify(fx("rsa-detached.p7s"), { content: 12345 }); }, "cms/bad-input");
}

async function run() {
  await testAcceptKats();
  await testMultiSigner();
  await testSignerIdentifier();
  await testDetached();
  await testCertLocation();
  await testMalformedCandidateCerts();
  await testInputForms();
  await testUnsupportedAlgorithm();
  await testRsaPssParams();
  await testAlgParams();
  await testTampered();
  await testBadSignedAttrs();
  await testContentType();
  await testSignedAttrsBinding();
  await testEdPointValidation();
  await testBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
