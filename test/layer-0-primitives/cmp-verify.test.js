// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.cmp.verify -- incoming CMP PKIMessage protection verification (the
// verify-inverse of pki.cmp.build). Every vector drives the shipped consumer pki.cmp.verify(message, opts)
// and asserts the resolved { valid, trusted, protectionType, protectionAlg, code } verdict OR the thrown
// err.code. The honest oracle is self-round-trip against pki.cmp.build (both flavors): a built message
// verifies; ANY flipped ProtectedPart byte / wrong secret / wrong key / absent protection / declared-vs-actual
// alg mismatch fails closed. The #1 fragile area is that verify recomputes over the EXACT ProtectedPart bytes
// build signed -- SEQUENCE { header, body } reconstructed from the parser-surfaced RAW headerBytes/bodyBytes,
// NEVER a re-serialization (a re-encode is both a false reject and a bypass). RFC 9810 sec. 5.1.3.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;
var b = asn1.build;
var nodeCrypto = require("node:crypto");
var constants = require("../../lib/constants");

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}
function parse(der) { return pki.schema.cmp.parse(der); }
function reconProtectedPart(m) { return b.sequence([b.raw(m.headerBytes), b.raw(m.bodyBytes)]); }

// ---- DER surgery helpers (build a tampered / unprotected / alg-substituted PKIMessage) ----
function msgKids(der) { return asn1.decode(der).children; }            // [header, body, protection[0]?, extraCerts[1]?]
// Rebuild a PKIMessage from raw child TLV buffers (header, body, and any present protection/extraCerts).
function rebuild(kids) { return b.sequence(kids.map(function (k) { return b.raw(k); })); }

// Strip a message to an unprotected one: drop the header protectionAlg [1] AND the protection [0] +
// extraCerts [1] envelope children, leaving SEQUENCE { header', body } (parser-legal: both absent).
function makeUnprotected(der) {
  var kids = msgKids(der);
  var hk = asn1.decode(kids[0].bytes).children.filter(function (c) { return !(c.tagClass === "context" && c.tagNumber === 1); });
  var newHeader = b.sequence(hk.map(function (c) { return b.raw(c.bytes); }));
  return b.sequence([b.raw(newHeader), b.raw(kids[1].bytes)]);
}

// Substitute the header protectionAlg [1] for a different AlgorithmIdentifier, keeping the ORIGINAL
// protection bits + body -- the declared-vs-actual-alg mismatch (verify uses the wire declaration).
function substituteAlg(der, newAlgDer) {
  var kids = msgKids(der);
  var newHeader = b.sequence(asn1.decode(kids[0].bytes).children.map(function (c) {
    if (c.tagClass === "context" && c.tagNumber === 1) return b.explicit(1, b.raw(newAlgDer));
    return b.raw(c.bytes);
  }));
  var parts = [newHeader];
  for (var i = 1; i < kids.length; i++) parts.push(kids[i].bytes);
  return rebuild(parts);
}

// Drop the extraCerts [1] envelope child so a signature message carries no embedded signer cert.
function stripExtraCerts(der) {
  var k = msgKids(der);
  return rebuild([k[0].bytes, k[1].bytes, k[2].bytes]);
}

// Hand-build a PBMAC1 protectionAlg = SEQUENCE { OID(pbmac1), PBMAC1-params { PBKDF2 algId, HMAC algId } }
// with knobs for the param edges: keyLen omitted, an hmacWithSHA1 prf/mac, a huge iterationCount.
function pbmac1AlgId(o) {
  // Emit each HMAC AlgorithmIdentifier with ABSENT parameters: hmacWithSHA1 with NULL is the non-canonical
  // encoded-DEFAULT (rejected at decode as bad-mac-data), so absent params let hmacWithSHA1 decode and reach
  // the M17 unsupported-PRF check; hmacWithSHA256's PRF/HMAC resolve off the OID name, not the params.
  var pbkdf2Kids = [b.octetString(o.salt), b.integer(BigInt(o.iter))];
  if (o.keyLen != null) pbkdf2Kids.push(b.integer(BigInt(o.keyLen)));
  pbkdf2Kids.push(b.sequence([b.oid(pki.oid.byName(o.prf))]));                             // prf algId (absent params)
  var pbkdf2 = b.sequence([b.oid(pki.oid.byName("pbkdf2")), b.sequence(pbkdf2Kids)]);
  var hmac = b.sequence([b.oid(pki.oid.byName(o.mac))]);                                   // messageAuthScheme (absent params)
  return b.sequence([b.oid(pki.oid.byName("pbmac1")), b.sequence([pbkdf2, hmac])]);
}

async function run() {
  var s = makeSigner("ec-p256");
  var HDR = { sender: { directoryName: [{ commonName: "Test Signer" }] }, recipient: { directoryName: "CN=CA" }, transactionID: Buffer.alloc(16, 7), senderNonce: Buffer.alloc(16, 5) };
  var SIG = { key: s.key, cert: s.cert };
  var IRBODY = { ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: s.spki } } };
  function hdr(over) { return Object.assign({}, HDR, over || {}); }
  async function buildSig(over, body) { return pki.cmp.build({ header: hdr(over), body: body || IRBODY }, SIG); }
  async function buildMac(secret, macOver, over, body) {
    var mac = Object.assign({ secret: secret, salt: Buffer.alloc(16, 9), iterationCount: 2048 }, macOver || {});
    return pki.cmp.build({ header: hdr(over), body: body || IRBODY }, { mac: mac });
  }

  // ===== 1. accept-signature (every algorithm arm) -- the single-algorithm coverage axis =====
  var arms = ["rsa", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ml-dsa-65", "slh-dsa-sha2-128f"];
  for (var ai = 0; ai < arms.length; ai++) {
    var sa = makeSigner(arms[ai]);
    var der = await pki.cmp.build({ header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: sa.spki }, sa.key) } }, { key: sa.key, cert: sa.cert });
    var v = await pki.cmp.verify(der, { signerCert: sa.cert });
    check("1." + ai + " " + arms[ai] + " signature protection verifies (valid, type=signature, trusted=false no anchors)",
      v.valid === true && v.protectionType === "signature" && v.trusted === false && !!v.protectionAlg.name);
  }
  var comp = makeCompositeSigner ? makeCompositeSigner("id-MLDSA65-Ed25519-SHA512") : null;
  if (comp) {
    var cder = await pki.cmp.build({ header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: comp.spki }, comp.key) } }, { key: comp.key, cert: comp.cert });
    var cv = await pki.cmp.verify(cder, { signerCert: comp.cert });
    check("1.comp a composite protectionAlg verifies (both components required)", cv.valid === true && cv.protectionType === "signature");
  }

  // ===== 2. accept-mac (PBMAC1) =====
  var macDer = await buildMac("hunter2");
  var mv = await pki.cmp.verify(macDer, { sharedSecret: "hunter2" });
  check("2. PBMAC1 verifies: valid, type=mac, trusted (secret matched), protectionAlg.name=pbmac1",
    mv.valid === true && mv.protectionType === "mac" && mv.trusted === true && mv.protectionAlg.name === "pbmac1");

  // ===== 3. GREEN oracle cross-check: an independent PBKDF2+HMAC over the reconstructed ProtectedPart =====
  var mm = parse(macDer);
  var derivedKey = nodeCrypto.pbkdf2Sync(Buffer.from("hunter2", "utf8"), Buffer.alloc(16, 9), 2048, 32, "sha256");
  var oracleMac = nodeCrypto.createHmac("sha256", derivedKey).update(reconProtectedPart(mm)).digest();
  check("3. verify hashes the identical ProtectedPart bytes: independent PBKDF2+HMAC == the emitted MAC", oracleMac.equals(mm.protection.bytes));

  // ===== 4. reject-wrong-secret (constant-time compare) =====
  var ws = await pki.cmp.verify(macDer, { sharedSecret: "wrong" });
  check("4. a wrong PBMAC1 secret -> { valid:false, cmp/protection-failed }", ws.valid === false && ws.code === "cmp/protection-failed");

  // ===== 5. reject-flipped-byte (THE byte-exactness vector): header + body region twins, sig + mac =====
  // Splice a DIFFERENT header (different transactionID) onto the original body+protection: the protection
  // covered the ORIGINAL header, so verify recomputes over the swapped header and fails.
  var a = await buildSig({ transactionID: Buffer.alloc(16, 7) });
  var bH = await buildSig({ transactionID: Buffer.alloc(16, 8) });
  var ak = msgKids(a), bk = msgKids(bH);
  var tamperHeader = rebuild([bk[0].bytes, ak[1].bytes, ak[2].bytes, ak[3].bytes]);
  var th = await pki.cmp.verify(tamperHeader, { signerCert: s.cert });
  check("5a. a swapped header (protection covers the original) -> cmp/protection-failed", th.valid === false && th.code === "cmp/protection-failed");
  var aBody = await buildSig({}, IRBODY);
  var bBody = await buildSig({}, { ir: { certTemplate: { subject: [{ commonName: "OTHER" }], publicKey: s.spki } } });
  var abk = msgKids(aBody), bbk = msgKids(bBody);
  var tamperBody = rebuild([abk[0].bytes, bbk[1].bytes, abk[2].bytes, abk[3].bytes]);
  var tb = await pki.cmp.verify(tamperBody, { signerCert: s.cert });
  check("5b. a swapped body (protection covers the original) -> cmp/protection-failed", tb.valid === false && tb.code === "cmp/protection-failed");
  var am = await buildMac("hunter2", {}, { transactionID: Buffer.alloc(16, 7) });
  var bm = await buildMac("hunter2", {}, { transactionID: Buffer.alloc(16, 8) });
  var amk = msgKids(am), bmk = msgKids(bm);
  var tamperMac = rebuild([bmk[0].bytes, amk[1].bytes, amk[2].bytes]);
  var tm = await pki.cmp.verify(tamperMac, { sharedSecret: "hunter2" });
  check("5c. a swapped-header PBMAC1 message -> cmp/protection-failed", tm.valid === false && tm.code === "cmp/protection-failed");

  // ===== 6. reject-absent-protection (a naive valid-check is never fooled by an unprotected message) =====
  var unprot = makeUnprotected(await buildSig());
  var up = await pki.cmp.verify(unprot, { signerCert: s.cert });
  check("6. an unprotected PKIMessage -> { valid:false, cmp/no-protection }", up.valid === false && up.code === "cmp/no-protection");

  // ===== 7. reject-declared-vs-actual-alg-mismatch (the wire declaration drives the scheme, not the cert) =====
  // Keep the original ECDSA-P256 bits but declare a DIFFERENT signature alg in the header protectionAlg.
  var wrongAlg = substituteAlg(await buildSig(), b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA512"))]));
  var wa = await pki.cmp.verify(wrongAlg, { signerCert: s.cert });
  check("7. a declared protectionAlg != the alg that produced the bits -> cmp/protection-failed", wa.valid === false && wa.code === "cmp/protection-failed");

  // ===== 8. reject-wrong-signer-key / unresolvable signer =====
  var other = makeSigner("ec-p256");
  var wk = await pki.cmp.verify(await buildSig(), { signerCert: other.cert });
  check("8a. presenting the wrong signer cert -> cmp/protection-failed", wk.valid === false && wk.code === "cmp/protection-failed");
  // A signed message whose extraCerts do NOT contain the signer, with no opts.signerCert -> unresolvable.
  var noSigner = stripExtraCerts(await buildSig());
  var r8b = await pki.cmp.verify(noSigner, {});
  check("8b. no signerCert and no resolvable extraCerts -> cmp/signer-cert-not-found", r8b.valid === false && r8b.code === "cmp/signer-cert-not-found");
  // RFC 9483 sec. 3.1: the authenticated sender field MUST match the signer cert subject -- a cert the anchor
  // trusts must not be usable to sign under another party's sender name. Signature valid, sender != subject.
  var spoof = makeSigner("ec-p256", { cn: "attacker" });   // signer cert subject commonName "attacker"
  var spoofDer = await pki.cmp.build({ header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: spoof.spki }, spoof.key) } }, { key: spoof.key, cert: spoof.cert });
  var vspoof = await pki.cmp.verify(spoofDer, { signerCert: spoof.cert });
  check("8c. sender != signer cert subject -> { valid:false, cmp/sender-mismatch } (RFC 9483 sec. 3.1)", vspoof.valid === false && vspoof.code === "cmp/sender-mismatch");

  // ===== 9. out-of-path signer trust (the FULL path.validate composition) =====
  var NB = new Date("2020-01-01T00:00:00Z"), NA = new Date("2040-01-01T00:00:00Z"), T = new Date("2030-06-01T00:00:00Z");
  var caKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var caKey = caKp.privateKey.export({ format: "der", type: "pkcs8" });
  var caSpki = caKp.publicKey.export({ format: "der", type: "spki" });
  var caCert = await pki.x509.sign({ subject: "CN=Test CMP CA", subjectPublicKey: caSpki, serialNumber: 1, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: caKey });
  var signerKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var signerKey = signerKp.privateKey.export({ format: "der", type: "pkcs8" });
  var signerSpki = signerKp.publicKey.export({ format: "der", type: "spki" });
  var signerCert = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: signerSpki, serialNumber: 2, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: caKey, cert: caCert });
  // A p10cr body avoids the CRMF proof-of-possession key<->protection-key coupling (the ir POP key would
  // default to the protection key), so the chain build's requested key can differ from the default signer.
  async function p10Body(spki, key) { return { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: spki }, key) }; }
  var chainDer = await pki.cmp.build({ header: HDR, body: await p10Body(signerSpki, signerKey) }, { key: signerKey, cert: signerCert });
  var t9a = await pki.cmp.verify(chainDer, { signerCert: signerCert });
  check("9a. crypto-only (no trustAnchors): valid, trusted=false, signer surfaced", t9a.valid === true && t9a.trusted === false && !!t9a.signer && !!t9a.signer.cert);
  var t9b = await pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [caCert], time: T });
  check("9b. with the issuing CA as trustAnchor: valid, trusted=true", t9b.valid === true && t9b.trusted === true);
  var t9c = await pki.cmp.verify(await buildSig(), { signerCert: s.cert, trustAnchors: [caCert], time: T });
  check("9c. a signer NOT chaining to the anchor -> { valid:true, trusted:false, cmp/untrusted-signer }", t9c.trusted === false && t9c.code === "cmp/untrusted-signer");
  var noKuKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var noKuKey = noKuKp.privateKey.export({ format: "der", type: "pkcs8" });
  var noKuSpki = noKuKp.publicKey.export({ format: "der", type: "spki" });
  var noKuCert = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: noKuSpki, serialNumber: 3, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["keyEncipherment"], authorityKeyIdentifier: true } }, { key: caKey, cert: caCert });
  var noKuDer = await pki.cmp.build({ header: HDR, body: await p10Body(noKuSpki, noKuKey) }, { key: noKuKey, cert: noKuCert });
  var t9d = await pki.cmp.verify(noKuDer, { signerCert: noKuCert, trustAnchors: [caCert], time: T });
  check("9d. a signer cert whose keyUsage omits digitalSignature -> cmp/untrusted-signer", t9d.trusted === false && t9d.code === "cmp/untrusted-signer");
  // A signer cert with a NON-MINIMAL KeyUsage NamedBitList (03 02 00 80 -- digitalSignature set but 0 unused
  // bits where the minimal form is 03 02 07 80) is not trusted end to end: the sec. 3.2 keyUsage gate reads it
  // through the shared strict decoder (X.690 sec. 11.2.2 minimal rule) AND full path validation rejects the
  // malformed extension. x509.sign only emits the minimal form, so patch the TBS to the non-minimal encoding
  // and re-sign with the CA key so the certificate signature stays valid.
  var kuOkDer = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: signerSpki, serialNumber: 51, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: caKey, cert: caCert });
  var kuKids = asn1.decode(kuOkDer).children;   // [tbs, sigAlg, signature]
  var kuTbs = Buffer.from(kuKids[0].bytes);
  var kuOidPos = kuTbs.indexOf(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0f]));   // keyUsage 2.5.29.15
  var kuBitPos = kuTbs.indexOf(Buffer.from([0x03, 0x02, 0x07, 0x80]), kuOidPos);
  kuTbs[kuBitPos + 2] = 0x00;   // 03 02 07 80 -> 03 02 00 80 : a non-minimal NamedBitList
  var kuSig = nodeCrypto.sign("sha256", kuTbs, { key: caKp.privateKey, dsaEncoding: "der" });
  var malKuCert = asn1.build.sequence([asn1.build.raw(kuTbs), asn1.build.raw(kuKids[1].bytes), asn1.build.bitString(kuSig, 0)]);
  var malKuMsg = await pki.cmp.build({ header: HDR, body: await p10Body(signerSpki, signerKey) }, { key: signerKey, cert: signerCert });
  var t9d2 = await pki.cmp.verify(malKuMsg, { signerCert: malKuCert, trustAnchors: [caCert], time: T });
  check("9d2. a signer cert with a non-minimal KeyUsage encoding -> cmp/untrusted-signer (not authorized to sign)", t9d2.trusted === false && t9d2.code === "cmp/untrusted-signer");
  // An EXPLICIT opts.signerCert is resolved WITHOUT the senderKID SKI gate (the senderKID only narrows a
  // candidate search): a valid message from a signer certificate that omits an SKI, carrying an arbitrary
  // header senderKID, still resolves to its exact opts.signerCert and verifies (the signature is the gate).
  var noSkiKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var noSkiKey = noSkiKp.privateKey.export({ format: "der", type: "pkcs8" });
  var noSkiSpki = noSkiKp.publicKey.export({ format: "der", type: "spki" });
  var noSkiCert = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: noSkiSpki, serialNumber: 52, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { key: caKey, cert: caCert });
  var kidMsg = await pki.cmp.build({ header: hdr({ senderKID: Buffer.alloc(20, 0xab) }), body: await p10Body(noSkiSpki, noSkiKey) }, { key: noSkiKey, cert: noSkiCert });
  check("9d3. an explicit opts.signerCert with no SKI resolves despite a header senderKID -> valid", (await pki.cmp.verify(kidMsg, { signerCert: noSkiCert })).valid === true);
  // A signer cert EXPIRED at the current time whose message backdates messageTime into the cert's old
  // validity window MUST NOT be trusted: the path is validated at a TRUSTED current time, not the sender's
  // self-asserted messageTime (an expired-cert holder could otherwise backdate to stay trusted).
  var expKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var expKey = expKp.privateKey.export({ format: "der", type: "pkcs8" });
  var expSpki = expKp.publicKey.export({ format: "der", type: "spki" });
  var expCert = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: expSpki, serialNumber: 9, notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: caKey, cert: caCert });
  var expDer = await pki.cmp.build({ header: Object.assign({ messageTime: new Date("2020-06-01T00:00:00Z") }, HDR), body: await p10Body(expSpki, expKey) }, { key: expKey, cert: expCert });
  var texp = await pki.cmp.verify(expDer, { signerCert: expCert, trustAnchors: [caCert] });   // NO opts.time
  check("9e. a now-expired signer backdated via messageTime is NOT trusted (path validated at a trusted now)", texp.valid === true && texp.trusted === false && texp.code === "cmp/untrusted-signer");
  check("9f. an explicit opts.time enables historical verification of the then-valid signer", (await pki.cmp.verify(expDer, { signerCert: expCert, trustAnchors: [caCert], time: new Date("2020-06-01T00:00:00Z") })).trusted === true);
  // A config-tier fault in the trust/validation options is a DEPLOYMENT error -> throw cmp/bad-input, never
  // mask it as a routine cmp/untrusted-signer (a genuine no-path result stays an untrusted verdict, per 9c).
  check("9g. an empty trustAnchors array -> throws cmp/bad-input (config error, not untrusted-signer)", await codeOf(pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [] })) === "cmp/bad-input");
  check("9h. a non-Date opts.time -> throws cmp/bad-input", await codeOf(pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [caCert], time: "not-a-date" })) === "cmp/bad-input");
  check("9i. a malformed trust anchor -> throws cmp/bad-input", await codeOf(pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [Buffer.from([1, 2, 3])] })) === "cmp/bad-input");
  check("9j. a falsy PRESENT opts.time (0) is not silently defaulted -> throws cmp/bad-input", await codeOf(pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [caCert], time: 0 })) === "cmp/bad-input");
  // extraCerts are unsigned: a flood of certs (here 40 distinct junk certs + duplicates) must not degrade an
  // otherwise-valid signer to untrusted -- dedup + a hard count cap keep the pool bounded so the real signer
  // still chains. Splice a hostile extraCerts SEQUENCE onto the valid signed message.
  var floodEntries = [];
  for (var fj = 0; fj < 40; fj++) floodEntries.push(asn1.build.raw(makeSigner("ec-p256").cert));
  for (var fk = 0; fk < 5; fk++) floodEntries.push(asn1.build.raw(signerCert));   // duplicates of the real signer
  var ck = msgKids(chainDer);   // [header, body, protection[0], extraCerts[1]]
  var floodDer = rebuild([ck[0].bytes, ck[1].bytes, ck[2].bytes, asn1.build.explicit(1, asn1.build.sequence(floodEntries))]);
  check("9k. a flood of unsigned extraCerts does not degrade a valid signer (dedup + bound)", (await pki.cmp.verify(floodDer, { signerCert: signerCert, trustAnchors: [caCert], time: T })).trusted === true);
  // a non-certificate DER SEQUENCE in unsigned extraCerts is DROPPED before path building -- it must not reach
  // path.build and turn a valid verification into a path/bad-input exception.
  var junkExtra = asn1.build.explicit(1, asn1.build.sequence([asn1.build.raw(signerCert), asn1.build.raw(asn1.build.sequence([asn1.build.integer(1n)]))]));
  var junkDer = rebuild([ck[0].bytes, ck[1].bytes, ck[2].bytes, junkExtra]);
  check("9l. a non-certificate entry in unsigned extraCerts is dropped, not raised as an exception", (await pki.cmp.verify(junkDer, { signerCert: signerCert, trustAnchors: [caCert], time: T })).trusted === true);
  // A tight candidate pool (only one slot left under the ceiling) must spend it on the USEFUL embedded issuer,
  // not the redundant signer leaf (already the path target): signer -> intermediate -> root, with [signer,
  // intermediate] in extraCerts and the caller pool filled to leave exactly one slot, still chains to trusted.
  var intKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var intKey = intKp.privateKey.export({ format: "der", type: "pkcs8" });
  var intSpki = intKp.publicKey.export({ format: "der", type: "spki" });
  var intCert = await pki.x509.sign({ subject: [{ commonName: "Intermediate CA" }], subjectPublicKey: intSpki, serialNumber: 40, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], authorityKeyIdentifier: true } }, { key: caKey, cert: caCert });
  var leafKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var leafKey = leafKp.privateKey.export({ format: "der", type: "pkcs8" });
  var leafSpki = leafKp.publicKey.export({ format: "der", type: "spki" });
  var leafCert = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: leafSpki, serialNumber: 41, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: intKey, cert: intCert });
  var leafMsg = await pki.cmp.build({ header: HDR, body: await p10Body(leafSpki, leafKey) }, { key: leafKey, cert: leafCert });
  var lk = msgKids(leafMsg);
  var tightMsg = rebuild([lk[0].bytes, lk[1].bytes, lk[2].bytes, asn1.build.explicit(1, asn1.build.sequence([asn1.build.raw(leafCert), asn1.build.raw(intCert)]))]);
  var junkFill = makeSigner("ec-p256").cert, fillPool = [];
  for (var pj = 0; pj < constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - 1; pj++) fillPool.push(junkFill);
  check("9l2. a tight candidate pool spends its last slot on the embedded issuer, not the redundant signer leaf", (await pki.cmp.verify(tightMsg, { signerCert: leafCert, trustAnchors: [caCert], intermediates: fillPool, time: T })).trusted === true);
  // The dedup keys on the canonical cert identity, so an extraCert duplicating a caller intermediate supplied as
  // a PARSED certificate object (path.build accepts parsed candidates) is dropped too -- the last slot goes to
  // the useful embedded issuer, not the parsed-object duplicate.
  var junkParsed = pki.schema.x509.parse(junkFill);
  var dupPool = [];
  for (var pk = 0; pk < constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - 1; pk++) dupPool.push(junkParsed);
  var dupMsg = rebuild([lk[0].bytes, lk[1].bytes, lk[2].bytes, asn1.build.explicit(1, asn1.build.sequence([asn1.build.raw(leafCert), asn1.build.raw(junkFill), asn1.build.raw(intCert)]))]);
  check("9l2b. an extraCert duplicating a PARSED-object intermediate is deduped -> the last slot holds the issuer", (await pki.cmp.verify(dupMsg, { signerCert: leafCert, trustAnchors: [caCert], intermediates: dupPool, time: T })).trusted === true);
  // The trusted verdict surfaces the VALIDATED chain as independent DER-buffer copies (never slices pinning the
  // response): an intermediate delivered in extraCerts (DER) appears in signer.chain; one supplied ONLY as a parsed
  // pool object (no retained DER to copy) is omitted, though the signer path still validates through it.
  var chainDerV = await pki.cmp.verify(tightMsg, { signerCert: leafCert, trustAnchors: [caCert], intermediates: [], time: T });
  check("9l2c. verdict.signer.chain surfaces the validated path as DER-buffer copies (signer + the extraCerts intermediate)", chainDerV.trusted === true && Array.isArray(chainDerV.signer.chain) && chainDerV.signer.chain.length === 2 && chainDerV.signer.chain.every(function (c) { return Buffer.isBuffer(c); }));
  var bareLeafMsg = rebuild([lk[0].bytes, lk[1].bytes, lk[2].bytes, asn1.build.explicit(1, asn1.build.sequence([asn1.build.raw(leafCert)]))]);   // extraCerts = [leaf] only; the issuer comes from a PARSED pool object
  var parsedIntV = await pki.cmp.verify(bareLeafMsg, { signerCert: leafCert, trustAnchors: [caCert], intermediates: [pki.schema.x509.parse(intCert)], time: T });
  check("9l2d. a validated-path intermediate supplied only as a parsed pool object (no DER to copy) is omitted from verdict.signer.chain -> the signer alone, still trusted", parsedIntV.trusted === true && Array.isArray(parsedIntV.signer.chain) && parsedIntV.signer.chain.length === 1 && Buffer.isBuffer(parsedIntV.signer.chain[0]) && parsedIntV.signer.chain[0].equals(leafCert));
  // A raw Buffer input is snapshotted: parse copies the input, so mutating the caller's buffer AFTER verify
  // cannot change the returned authenticated fields -- they bind to the verified snapshot, not the live buffer.
  var rawBuf = Buffer.from(await buildSig());
  var snapV = await pki.cmp.verify(rawBuf, { signerCert: s.cert });
  var tidBefore = Buffer.from(snapV.transactionID);
  rawBuf.fill(0x00);
  check("9l3. a raw Buffer input is snapshotted -- mutating it after verify does not alter the verdict transactionID", snapV.valid === true && snapV.transactionID.equals(tidBefore));
  // opts.signerCert is snapshotted too: mutating the caller's signerCert buffer after verify does not change
  // the surfaced verdict.signer.cert / .spki -- they bind to the verified copy, not the caller's live buffer.
  var scBuf = Buffer.from(s.cert);
  var scV = await pki.cmp.verify(await buildSig(), { signerCert: scBuf });
  var certBefore = Buffer.from(scV.signer.cert), spkiBefore = Buffer.from(scV.signer.spki);
  scBuf.fill(0x00);
  check("9l4. opts.signerCert is snapshotted -- mutating it after verify does not alter verdict.signer.cert / .spki", scV.valid === true && scV.signer.cert.equals(certBefore) && scV.signer.spki.equals(spkiBefore));
  // A signer with a POPULATED subject and a non-critical SAN whose OUTER tag is malformed (a SET wrapping a
  // valid [2] dNSName) must NOT bind the header sender to that unvalidated name: path validation does not
  // decode a non-critical unused SAN, so verify must reject the structure through the shared generalNames
  // schema (RFC 5280 sec. 4.2.1.6 SEQUENCE OF GeneralName) and fail closed to sender-mismatch.
  function patchSanToSet(der) {
    der = Buffer.from(der);
    var sanOid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]);   // subjectAltName 2.5.29.17
    var p = der.indexOf(sanOid);
    if (p < 0) throw new Error("SAN OID not found");
    p += sanOid.length;
    if (der[p] === 0x01) p += 3;                                // skip a critical BOOLEAN (01 01 FF) if present
    if (der[p] !== 0x04) throw new Error("expected extnValue OCTET STRING");
    var contentStart = der[p + 1] < 0x80 ? p + 2 : p + 2 + (der[p + 1] & 0x7f);
    if (der[contentStart] !== 0x30) throw new Error("expected a SEQUENCE at the SAN content");
    der[contentStart] = 0x31;                                  // SEQUENCE (30) -> SET (31): a malformed SAN outer tag
    return der;
  }
  var malKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var malKey = malKp.privateKey.export({ format: "der", type: "pkcs8" });
  var malSpki = malKp.publicKey.export({ format: "der", type: "spki" });
  var malCertOk = await pki.x509.sign({ subject: [{ commonName: "Populated Subject" }], subjectPublicKey: malSpki, serialNumber: 50, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "malformed.example" }] } }, { key: caKey, cert: caCert });
  var malCert = patchSanToSet(malCertOk);
  var malMsg = await pki.cmp.build({ header: hdr({ sender: { dNSName: "malformed.example" } }), body: await p10Body(malSpki, malKey) }, { key: malKey, cert: malCertOk });
  check("9l5. a populated-subject signer with a malformed (SET) SAN does not bind the sender to the wrapped dNSName", (await pki.cmp.verify(malMsg, { signerCert: malCert })).code === "cmp/sender-mismatch");
  // An EMPTY-subject protection certificate binds the sender to a subjectAltName entry (RFC 5280 sec. 7.1),
  // not the (empty) subject DN -- a matching SAN sender verifies, a non-matching one is a sender-mismatch.
  var eeKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var eeKey = eeKp.privateKey.export({ format: "der", type: "pkcs8" });
  var eeSpki = eeKp.publicKey.export({ format: "der", type: "spki" });
  var eeCert = await pki.x509.sign({ subject: [], subjectPublicKey: eeSpki, serialNumber: 20, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "ee.example" }] } }, { key: caKey, cert: caCert });
  async function eeMsg(dns) { return pki.cmp.build({ header: hdr({ sender: { dNSName: dns } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: eeSpki }, eeKey) } }, { key: eeKey, cert: eeCert }); }
  check("9m. an empty-subject cert: a sender matching a subjectAltName entry verifies", (await pki.cmp.verify(await eeMsg("ee.example"), { signerCert: eeCert })).valid === true);
  check("9n. an empty-subject cert: a sender NOT in the subjectAltName -> cmp/sender-mismatch", (await pki.cmp.verify(await eeMsg("evil.example"), { signerCert: eeCert })).code === "cmp/sender-mismatch");
  check("9o. an empty-subject cert: a case-different dNSName sender still matches the SAN (RFC 5280 sec. 4.2.1.6)", (await pki.cmp.verify(await eeMsg("EE.EXAMPLE"), { signerCert: eeCert })).valid === true);
  // A MALFORMED dNSName (an empty label) is compared byte-exact, not case-folded, so a byte-distinct identity
  // differing only in case does not bind (RFC 5280 sec. 4.2.1.6 / RFC 1034 preferred name syntax).
  var badDnsCert = await pki.x509.sign({ subject: [], subjectPublicKey: eeSpki, serialNumber: 47, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "Victim..COM" }] } }, { key: caKey, cert: caCert });
  async function badDnsMsg(dns) { return pki.cmp.build({ header: hdr({ sender: { dNSName: dns } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: eeSpki }, eeKey) } }, { key: eeKey, cert: badDnsCert }); }
  check("9o2. a malformed dNSName (empty label) is compared byte-exact -> a case difference does not bind", (await pki.cmp.verify(await badDnsMsg("victim..com"), { signerCert: badDnsCert })).code === "cmp/sender-mismatch");
  // the path-builder pool ceiling (1000): unsigned extraCerts must not push a caller pool already at the
  // ceiling over it and turn a valid verification into an exception.
  var fullPool = new Array(1000).fill(signerCert);
  check("9p. extraCerts do not push a ceiling-full caller intermediates pool over the path-builder limit", (await pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [caCert], intermediates: fullPool, time: T })).trusted === true);
  // a cert with BOTH a populated subject and a SAN: the sender may identify the signer via EITHER (the SAN is
  // checked even when the subject is non-empty), so a SAN-named sender is not rejected.
  var sanKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var sanKey = sanKp.privateKey.export({ format: "der", type: "pkcs8" });
  var sanSpki = sanKp.publicKey.export({ format: "der", type: "spki" });
  var sanCert = await pki.x509.sign({ subject: [{ commonName: "Test Signer" }], subjectPublicKey: sanSpki, serialNumber: 30, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "alt.example" }] } }, { key: sanKey });
  var sanSenderMsg = await pki.cmp.build({ header: hdr({ sender: { dNSName: "alt.example" } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: sanSpki }, sanKey) } }, { key: sanKey, cert: sanCert });
  check("9q. a populated-subject cert: a sender matching the SAN verifies (subject DN OR SAN)", (await pki.cmp.verify(sanSenderMsg, { signerCert: sanCert })).valid === true);
  // non-dNSName SAN types are compared per RFC 5280 sec. 7, not by raw DER: rfc822Name domain case-insensitive,
  // directoryName under the canonical DN comparison.
  var mailKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var mailKey = mailKp.privateKey.export({ format: "der", type: "pkcs8" });
  var mailSpki = mailKp.publicKey.export({ format: "der", type: "spki" });
  var mailCert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 31, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "user@Example.com" }] } }, { key: caKey, cert: caCert });
  async function mailMsg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mailCert }); }
  check("9r. rfc822Name SAN: a case-different domain sender still matches (RFC 5280 sec. 7.5)", (await pki.cmp.verify(await mailMsg("user@example.com"), { signerCert: mailCert })).valid === true);
  check("9s. rfc822Name SAN: a different local-part does NOT match -> cmp/sender-mismatch", (await pki.cmp.verify(await mailMsg("other@example.com"), { signerCert: mailCert })).code === "cmp/sender-mismatch");
  // An rfc822Name with more than one "@" is a malformed mailbox (RFC 5321 addr-spec) -> exact comparison, so a
  // domain-case difference in such an address does not fold into a false match.
  var mail2Cert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 43, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "a@b@EXAMPLE.com" }] } }, { key: caKey, cert: caCert });
  async function mail2Msg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mail2Cert }); }
  check("9s2. an rfc822Name with multiple at-signs is malformed -> a domain-case difference does not bind", (await pki.cmp.verify(await mail2Msg("a@b@example.com"), { signerCert: mail2Cert })).code === "cmp/sender-mismatch");
  // A VALID quoted local-part may itself contain "@" (RFC 5321) -- the mailbox separator is the "@" after the
  // closing quote, so a quoted address still binds with the domain compared case-insensitively.
  var mail3Cert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 44, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "\"a@b\"@EXAMPLE.com" }] } }, { key: caKey, cert: caCert });
  async function mail3Msg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mail3Cert }); }
  check("9s3. a quoted rfc822Name local-part carrying '@' still binds (domain case-insensitive)", (await pki.cmp.verify(await mail3Msg("\"a@b\"@example.com"), { signerCert: mail3Cert })).valid === true);
  // A quoted local-part correctly holds the FIRST "@", but the DOMAIN must still be valid: an extra "@" in the
  // domain ("a"@b@X) is malformed -> exact comparison, so the malformed suffix is not case-folded into a match.
  var mail4Cert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 46, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "\"a\"@b@EXAMPLE.com" }] } }, { key: caKey, cert: caCert });
  async function mail4Msg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mail4Cert }); }
  check("9s4. a quoted rfc822Name whose domain carries an extra '@' is malformed -> a case difference does not bind", (await pki.cmp.verify(await mail4Msg("\"a\"@b@example.com"), { signerCert: mail4Cert })).code === "cmp/sender-mismatch");
  // An rfc822Name whose DOMAIN is not a valid FQDN (an empty label like "Victim..COM") is compared byte-exact,
  // not case-folded, so it cannot bind a byte-distinct identity.
  var mail5Cert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 49, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "user@Victim..COM" }] } }, { key: caKey, cert: caCert });
  async function mail5Msg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mail5Cert }); }
  check("9s5. an rfc822Name with a malformed domain is compared byte-exact -> a case difference does not bind", (await pki.cmp.verify(await mail5Msg("user@victim..com"), { signerCert: mail5Cert })).code === "cmp/sender-mismatch");
  // An unquoted local-part with an empty atom ("a..b") is malformed -> byte-exact comparison.
  var mail6Cert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 50, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "a..b@EXAMPLE.com" }] } }, { key: caKey, cert: caCert });
  async function mail6Msg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mail6Cert }); }
  check("9s6. an rfc822Name with a malformed local-part (empty atom) is compared byte-exact -> a case difference does not bind", (await pki.cmp.verify(await mail6Msg("a..b@example.com"), { signerCert: mail6Cert })).code === "cmp/sender-mismatch");
  // A local-part with a non-atext character (a space) is malformed (RFC 5321 sec. 4.1.2) -> byte-exact comparison.
  var mail7Cert = await pki.x509.sign({ subject: [], subjectPublicKey: mailSpki, serialNumber: 53, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ rfc822Name: "user name@EXAMPLE.com" }] } }, { key: caKey, cert: caCert });
  async function mail7Msg(addr) { return pki.cmp.build({ header: hdr({ sender: { rfc822Name: addr } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: mailSpki }, mailKey) } }, { key: mailKey, cert: mail7Cert }); }
  check("9s7. an rfc822Name local-part with a non-atext character (space) is compared byte-exact -> a case difference does not bind", (await pki.cmp.verify(await mail7Msg("user name@example.com"), { signerCert: mail7Cert })).code === "cmp/sender-mismatch");
  var dnKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var dnKey = dnKp.privateKey.export({ format: "der", type: "pkcs8" });
  var dnSpki = dnKp.publicKey.export({ format: "der", type: "spki" });
  var dnCert = await pki.x509.sign({ subject: [], subjectPublicKey: dnSpki, serialNumber: 32, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ directoryName: [{ commonName: "Alt Name" }] }] } }, { key: caKey, cert: caCert });
  var dnMsg = await pki.cmp.build({ header: hdr({ sender: { directoryName: [{ commonName: "Alt Name" }] } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: dnSpki }, dnKey) } }, { key: dnKey, cert: dnCert });
  check("9t. directoryName SAN: a sender matching the SAN DN verifies (canonical DN comparison)", (await pki.cmp.verify(dnMsg, { signerCert: dnCert })).valid === true);
  // uniformResourceIdentifier SAN: the scheme and host are case-insensitive (RFC 5280 sec. 4.2.1.6 / RFC 3986
  // sec. 6.2.2.1); the path and every other component stay byte-exact (fail-closed).
  var uriKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var uriKey = uriKp.privateKey.export({ format: "der", type: "pkcs8" });
  var uriSpki = uriKp.publicKey.export({ format: "der", type: "spki" });
  var uriCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 33, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://EE.Example.com/enroll" }] } }, { key: caKey, cert: caCert });
  async function uriMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: uriCert }); }
  check("9u. uniformResourceIdentifier SAN: a case-different scheme+host sender still matches", (await pki.cmp.verify(await uriMsg("HTTPS://ee.example.COM/enroll"), { signerCert: uriCert })).valid === true);
  check("9v. uniformResourceIdentifier SAN: a case-different PATH does NOT match (path is case-sensitive) -> cmp/sender-mismatch", (await pki.cmp.verify(await uriMsg("https://ee.example.com/ENROLL"), { signerCert: uriCert })).code === "cmp/sender-mismatch");
  check("9w. uniformResourceIdentifier SAN: a different host does NOT match -> cmp/sender-mismatch", (await pki.cmp.verify(await uriMsg("https://evil.example.com/enroll"), { signerCert: uriCert })).code === "cmp/sender-mismatch");
  // A no-authority URI (no "//"): the scheme is still case-insensitive, the scheme-specific-part byte-exact.
  var urnCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 34, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "urn:example:Enroll" }] } }, { key: caKey, cert: caCert });
  async function urnMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: urnCert }); }
  // An authority-free URI (a URN, no host) is host-less, so it is compared byte-exact (RFC 5280 sec. 4.2.1.6):
  // a case-different scheme does NOT fold into a match, but a byte-identical value still binds.
  check("9x. an authority-free URI: a case-different scheme does NOT bind -> cmp/sender-mismatch", (await pki.cmp.verify(await urnMsg("URN:example:Enroll"), { signerCert: urnCert })).code === "cmp/sender-mismatch");
  check("9x2. an authority-free URI: a byte-identical value still binds", (await pki.cmp.verify(await urnMsg("urn:example:Enroll"), { signerCert: urnCert })).valid === true);
  // A value that is not a well-formed absolute URI (no scheme) falls back to an exact byte comparison (fail-closed
  // -- an input we cannot confidently parse is never normalized into a false identity match).
  var relCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 35, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "relative/Path" }] } }, { key: caKey, cert: caCert });
  async function relMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: relCert }); }
  check("9y. a scheme-less URI value: an exact byte match still binds", (await pki.cmp.verify(await relMsg("relative/Path"), { signerCert: relCert })).valid === true);
  check("9y2. a scheme-less URI value: a case difference does NOT match (no normalization) -> cmp/sender-mismatch", (await pki.cmp.verify(await relMsg("relative/path"), { signerCert: relCert })).code === "cmp/sender-mismatch");
  // A URI carrying userinfo + no path: the host is case-insensitive, but userinfo stays case-sensitive (it is not
  // part of the host), so a userinfo-case difference is a mismatch -- the normalizer never over-folds identity.
  var uiCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 36, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://User@Host.example" }] } }, { key: caKey, cert: caCert });
  async function uiMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: uiCert }); }
  check("9z. a URI with userinfo + no path: a case-different host still matches (host case-insensitive)", (await pki.cmp.verify(await uiMsg("https://User@host.EXAMPLE"), { signerCert: uiCert })).valid === true);
  check("9z2. a URI with userinfo: a case-different userinfo does NOT match (userinfo case-sensitive) -> cmp/sender-mismatch", (await pki.cmp.verify(await uiMsg("https://user@host.example"), { signerCert: uiCert })).code === "cmp/sender-mismatch");
  // The port is NOT part of the host: only the host case-folds; the port stays byte-exact, so a malformed
  // non-numeric port (":ADMIN" vs ":admin") is a mismatch, while a numeric port + case-different host matches.
  var portCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 37, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://host.example:ADMIN/p" }] } }, { key: caKey, cert: caCert });
  async function portMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: portCert }); }
  check("9z3. a case-different non-numeric port does NOT match (port byte-exact) -> cmp/sender-mismatch", (await pki.cmp.verify(await portMsg("https://host.example:admin/p"), { signerCert: portCert })).code === "cmp/sender-mismatch");
  var numPortCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 38, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://Host.Example:8443/p" }] } }, { key: caKey, cert: caCert });
  async function numPortMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: numPortCert }); }
  check("9z4. a case-different host with the same numeric port matches (host folded, port equal)", (await pki.cmp.verify(await numPortMsg("https://host.example:8443/p"), { signerCert: numPortCert })).valid === true);
  // An IPv6-literal host case-folds (hex is case-insensitive) with the port after the "]" kept exact.
  var v6Cert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 39, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://[2001:DB8::1]:443/p" }] } }, { key: caKey, cert: caCert });
  async function v6Msg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: v6Cert }); }
  check("9z5. an IPv6-literal host case-folds with an exact port", (await pki.cmp.verify(await v6Msg("https://[2001:db8::1]:443/p"), { signerCert: v6Cert })).valid === true);
  // An unterminated IPv6 literal is malformed -> exact-DER fallback (no normalization), so a case difference
  // in the malformed authority is a mismatch rather than a folded false match.
  var v6BadCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 40, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://[2001:DB8/p" }] } }, { key: caKey, cert: caCert });
  async function v6BadMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: v6BadCert }); }
  check("9z6. an unterminated IPv6 literal falls back to exact comparison (a case difference does not match)", (await pki.cmp.verify(await v6BadMsg("https://[2001:db8/p"), { signerCert: v6BadCert })).code === "cmp/sender-mismatch");
  // A malformed authority (non-numeric port) is NOT normalized at all -> exact comparison, so a host-case
  // difference alongside the SAME malformed port is still a mismatch (the host is never folded for an
  // authority the normalizer cannot validate).
  var malPortCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 41, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://EXAMPLE.com:ADMIN/p" }] } }, { key: caKey, cert: caCert });
  async function malPortMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: malPortCert }); }
  check("9z7. a malformed authority (non-numeric port) is not normalized -> a host-case difference does not bind", (await pki.cmp.verify(await malPortMsg("https://example.com:ADMIN/p"), { signerCert: malPortCert })).code === "cmp/sender-mismatch");
  // An authority with more than one "@" is malformed (a raw "@" is forbidden in userinfo) -> exact comparison,
  // so a host-case difference in such an authority does not fold into a false match.
  var atCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 42, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://a@b@EXAMPLE.com/p" }] } }, { key: caKey, cert: caCert });
  async function atMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: atCert }); }
  check("9z8. an authority with multiple at-signs is not normalized -> a host-case difference does not bind", (await pki.cmp.verify(await atMsg("https://a@b@example.com/p"), { signerCert: atCert })).code === "cmp/sender-mismatch");
  // A hostless authority ("scheme:///path", empty host) is malformed (RFC 5280 sec. 4.2.1.6 requires an FQDN/IP
  // host) -> exact comparison, so the scheme is not case-folded into a false match.
  var noHostCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 45, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "HTTPS:///p" }] } }, { key: caKey, cert: caCert });
  async function noHostMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: noHostCert }); }
  check("9z8b. a hostless URI authority is not normalized -> a scheme-case difference does not bind", (await pki.cmp.verify(await noHostMsg("https:///p"), { signerCert: noHostCert })).code === "cmp/sender-mismatch");
  // A URI authority whose host is not a valid FQDN/IP (an empty label like "Victim..COM") is compared byte-exact,
  // not case-folded, so it cannot bind a byte-distinct identity (RFC 5280 sec. 4.2.1.6 / RFC 1034).
  var badHostCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 48, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://Victim..COM/p" }] } }, { key: caKey, cert: caCert });
  async function badHostMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: badHostCert }); }
  check("9z8c. a URI SAN with a malformed host is compared byte-exact -> a case difference does not bind", (await pki.cmp.verify(await badHostMsg("https://victim..com/p"), { signerCert: badHostCert })).code === "cmp/sender-mismatch");
  // A URI with a malformed component OUTSIDE the authority (a bad percent-escape "%zz" in the path) is not a
  // well-formed RFC 3986 URI, so it is compared byte-exact rather than case-folding the host into a match.
  var badPctCert = await pki.x509.sign({ subject: [], subjectPublicKey: uriSpki, serialNumber: 51, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uniformResourceIdentifier: "https://EXAMPLE.com/%zz" }] } }, { key: caKey, cert: caCert });
  async function badPctMsg(u) { return pki.cmp.build({ header: hdr({ sender: { uniformResourceIdentifier: u } }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: uriSpki }, uriKey) } }, { key: uriKey, cert: badPctCert }); }
  check("9z8d. a URI SAN with an invalid percent-escape is compared byte-exact -> a host-case difference does not bind", (await pki.cmp.verify(await badPctMsg("https://example.com/%zz"), { signerCert: badPctCert })).code === "cmp/sender-mismatch");
  // opts defaults ONLY for null / undefined -- a falsy non-object (false / 0 / "") is a bad config, not a
  // default, so it raises cmp/bad-input like any other non-object rather than being silently coerced to {}.
  check("9z9a. opts=false -> cmp/bad-input (not silently defaulted)", await codeOf(pki.cmp.verify(chainDer, false)) === "cmp/bad-input");
  check("9z9b. opts=0 -> cmp/bad-input", await codeOf(pki.cmp.verify(chainDer, 0)) === "cmp/bad-input");
  check("9z9c. opts=empty-string -> cmp/bad-input", await codeOf(pki.cmp.verify(chainDer, "")) === "cmp/bad-input");
  check("9z9d. omitted opts (undefined) still defaults to {} -> valid", (await pki.cmp.verify(chainDer)).valid === true);
  check("9z9e. opts=null still defaults to {} -> valid", (await pki.cmp.verify(chainDer, null)).valid === true);

  // ===== 10. reject-unknown/legacy/KEM alg (never a silent accept) =====
  var pbmOid = substituteAlg(await buildSig(), b.sequence([b.oid(pki.oid.byName("passwordBasedMac"))]));
  check("10a. a legacy id-PasswordBasedMac protectionAlg -> cmp/unsupported-algorithm", (await pki.cmp.verify(pbmOid, { sharedSecret: "x" })).code === "cmp/unsupported-algorithm");
  var dhOid = substituteAlg(await buildSig(), b.sequence([b.oid(pki.oid.byName("dhBasedMac"))]));
  check("10b. a legacy id-DHBasedMac protectionAlg -> cmp/unsupported-algorithm", (await pki.cmp.verify(dhOid, { sharedSecret: "x" })).code === "cmp/unsupported-algorithm");

  // ===== 11. reject PBMAC1 keyLength-omitted / SHA-1 PRF (params surgery on a real MAC message) =====
  var SALT = Buffer.alloc(16, 9);
  var noKeyLen = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 2048, keyLen: null, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("11a. PBMAC1 PBKDF2-params omitting keyLength -> fail-closed (RFC 9579 sec. 5)", (await pki.cmp.verify(noKeyLen, { sharedSecret: "hunter2" })).valid === false);
  var sha1Prf = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 2048, keyLen: 32, prf: "hmacWithSHA1", mac: "hmacWithSHA256" }));
  check("11b. a PBMAC1 hmacWithSHA1 PRF -> cmp/unsupported-algorithm (RFC 9481 sec. 7 / RFC 9579 sec. 7)", (await pki.cmp.verify(sha1Prf, { sharedSecret: "hunter2" })).code === "cmp/unsupported-algorithm");
  var sha1Mac = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 2048, keyLen: 32, prf: "hmacWithSHA256", mac: "hmacWithSHA1" }));
  check("11c. a PBMAC1 hmacWithSHA1 messageAuthScheme -> cmp/unsupported-algorithm", (await pki.cmp.verify(sha1Mac, { sharedSecret: "hunter2" })).code === "cmp/unsupported-algorithm");
  var shortKey = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 2048, keyLen: 16, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("11d. a PBMAC1 keyLength below the RFC 9579 sec. 9 floor (< 20) -> throws cmp/bad-input", await codeOf(pki.cmp.verify(shortKey, { sharedSecret: "hunter2" })) === "cmp/bad-input");
  var longKey = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 2048, keyLen: 4096, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("11e. a PBMAC1 keyLength over the ceiling -> throws cmp/bad-input", await codeOf(pki.cmp.verify(longKey, { sharedSecret: "hunter2" })) === "cmp/bad-input");
  // A messageAuthScheme / prf HMAC AlgorithmIdentifier with MALFORMED parameters (an INTEGER instead of the
  // RFC 8018 App. B.1 NULL/absent) is rejected as cmp/bad-mac-data, not silently discarded before OID dispatch.
  function pbmac1AlgIdParams(macParams, prfParams) {
    var prfAlg = prfParams ? b.sequence([b.oid(pki.oid.byName("hmacWithSHA256")), prfParams]) : b.sequence([b.oid(pki.oid.byName("hmacWithSHA256"))]);
    var pbkdf2 = b.sequence([b.oid(pki.oid.byName("pbkdf2")), b.sequence([b.octetString(SALT), b.integer(2048n), b.integer(32n), prfAlg])]);
    var hmac = macParams ? b.sequence([b.oid(pki.oid.byName("hmacWithSHA256")), macParams]) : b.sequence([b.oid(pki.oid.byName("hmacWithSHA256"))]);
    return b.sequence([b.oid(pki.oid.byName("pbmac1")), b.sequence([pbkdf2, hmac])]);
  }
  var badMacScheme = substituteAlg(macDer, pbmac1AlgIdParams(b.integer(5n), null));
  check("11f. a PBMAC1 messageAuthScheme with non-NULL parameters -> cmp/bad-mac-data (not silently discarded)", (await pki.cmp.verify(badMacScheme, { sharedSecret: "hunter2" })).code === "cmp/bad-mac-data");
  var badPrfScheme = substituteAlg(macDer, pbmac1AlgIdParams(null, b.integer(5n)));
  check("11g. a PBMAC1 PBKDF2 prf with non-NULL parameters -> cmp/bad-mac-data", (await pki.cmp.verify(badPrfScheme, { sharedSecret: "hunter2" })).code === "cmp/bad-mac-data");

  // ===== 12. work-factor caps: a hostile iterationCount/keyLength combination rejects BEFORE derivation =====
  var hugeIter = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 100000000, keyLen: 32, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("12a. a PBMAC1 iterationCount over the cap -> cmp/bad-input before any derivation", await codeOf(pki.cmp.verify(hugeIter, { sharedSecret: "hunter2" })) === "cmp/bad-input");
  // A count below the RFC 8018 sec. 4.2 floor (1000) is refused symmetrically with pki.cmp.build, so a peer cannot
  // downgrade the work factor to run cheap offline guesses against a password-like shared secret.
  var lowIter = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 1, keyLen: 32, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("12b. a PBMAC1 iterationCount below the floor (< 1000) -> cmp/bad-input", await codeOf(pki.cmp.verify(lowIter, { sharedSecret: "hunter2" })) === "cmp/bad-input");
  // The COMBINED work is bounded: an at-cap iterationCount with a 1024-octet keyLength derives 32 SHA-256 blocks,
  // so the total HMAC work is 32x the per-block ceiling -- rejected before any derivation (no multi-second burn).
  var comboWork = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 10000000, keyLen: 1024, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("12c. an at-cap iterationCount x a maximal keyLength (32 derived blocks) -> cmp/bad-input", await codeOf(pki.cmp.verify(comboWork, { sharedSecret: "hunter2" })) === "cmp/bad-input");
  // A legitimate multi-block derived key (keyLength 64 = 2 SHA-256 blocks) at a normal count stays well under the
  // combined ceiling and verifies end to end -- the cap bounds hostile work without rejecting a real 2-block key.
  var twoBlock = await buildMac("hunter2", { keyLength: 64 });
  check("12d. a genuine 2-block keyLength (64) at a normal iterationCount -> valid", (await pki.cmp.verify(twoBlock, { sharedSecret: "hunter2" })).valid === true);
  // An empty / short PBMAC1 salt is refused BEFORE derivation (RFC 8018 sec. 4.1 64-bit floor): an under-length
  // salt loses precomputation resistance, so the work-factor gate rejects it rather than MAC-verify a weak message.
  var emptySalt = substituteAlg(macDer, pbmac1AlgId({ salt: Buffer.alloc(0), iter: 2048, keyLen: 32, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("12e. a PBMAC1 empty salt -> cmp/bad-input", await codeOf(pki.cmp.verify(emptySalt, { sharedSecret: "hunter2" })) === "cmp/bad-input");
  var shortSalt = substituteAlg(macDer, pbmac1AlgId({ salt: Buffer.alloc(4, 9), iter: 2048, keyLen: 32, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("12f. a PBMAC1 salt below the 8-octet floor -> cmp/bad-input", await codeOf(pki.cmp.verify(shortSalt, { sharedSecret: "hunter2" })) === "cmp/bad-input");

  // ===== 13. header echo opt-ins =====
  var echoDer = await buildSig({ transactionID: Buffer.alloc(16, 0x33), recipNonce: undefined });
  var tid = Buffer.alloc(16, 0x33);
  check("13a. matching transactionID opt-in -> valid", (await pki.cmp.verify(echoDer, { signerCert: s.cert, transactionID: tid })).valid === true);
  // A failed opt-in echo is a REJECTION verdict (valid:false) on the SIGNATURE path too, not just the MAC path.
  var t13b = await pki.cmp.verify(echoDer, { signerCert: s.cert, transactionID: Buffer.alloc(16, 0x44) });
  check("13b. wrong transactionID opt-in -> { valid:false, cmp/transaction-id-mismatch }", t13b.valid === false && t13b.code === "cmp/transaction-id-mismatch");
  var rnDer = await buildSig({ recipNonce: Buffer.alloc(16, 0x55) });
  var t13c = await pki.cmp.verify(rnDer, { signerCert: s.cert, expectRecipNonce: Buffer.alloc(16, 0x66) });
  check("13c. wrong expectRecipNonce -> { valid:false, cmp/bad-recip-nonce }", t13c.valid === false && t13c.code === "cmp/bad-recip-nonce");
  check("13d. matching expectRecipNonce -> valid", (await pki.cmp.verify(rnDer, { signerCert: s.cert, expectRecipNonce: Buffer.alloc(16, 0x55) })).valid === true);

  // ===== 14. input coercion (DER / PEM / parsed object) + display-field desync =====
  var derMsg = await buildSig();
  var pemMsg = await pki.cmp.build({ header: HDR, body: IRBODY }, Object.assign({ pem: true }, SIG));
  check("14a. a raw DER Buffer verifies", (await pki.cmp.verify(derMsg, { signerCert: s.cert })).valid === true);
  check("14b. a PEM CMP string verifies", (await pki.cmp.verify(pemMsg, { signerCert: s.cert })).valid === true);
  var parsedObj = parse(derMsg);
  check("14c. an already-parsed object verifies", (await pki.cmp.verify(parsedObj, { signerCert: s.cert })).valid === true);
  // A parsed object's decoded fields are UNTRUSTED: mutating header.transactionID must neither reach the
  // verdict nor bypass the opt-in echo check (verify re-derives every field from the authenticated slices).
  parsedObj.header.transactionID = Buffer.alloc(16, 0xee);
  var desyncV = await pki.cmp.verify(parsedObj, { signerCert: s.cert });
  check("14d. a mutated decoded field is discarded -- the verdict echoes the AUTHENTICATED transactionID (0x07, not 0xee)",
    desyncV.valid === true && Buffer.isBuffer(desyncV.transactionID) && !desyncV.transactionID.equals(Buffer.alloc(16, 0xee)) && desyncV.transactionID.equals(Buffer.alloc(16, 7)));
  check("14e. a mutated transactionID cannot bypass the opt-in echo check (the authenticated value is checked)",
    (await pki.cmp.verify(parsedObj, { signerCert: s.cert, transactionID: Buffer.alloc(16, 0xee) })).code === "cmp/transaction-id-mismatch");
  // A parsed object with a MALFORMED raw slice (a null protection.bytes) makes reassembly throw -- it must
  // surface the documented typed cmp/bad-input, not a raw asn1/* error leaking through the coercion boundary.
  var badSlice = parse(derMsg);
  badSlice.protection = { bytes: null, unusedBits: 0 };
  check("14f. a parsed object with a malformed raw slice -> typed cmp/bad-input (not a raw asn1 error)", await codeOf(pki.cmp.verify(badSlice, { signerCert: s.cert })) === "cmp/bad-input");
  // A non-buffer opt-in echo value (e.g. a string from JSON config) is a config error -> cmp/bad-input, never a
  // routine transaction/nonce mismatch verdict that would misreport the typing mistake as a peer auth failure.
  check("14g. a non-buffer opts.transactionID (string) -> cmp/bad-input, not a mismatch verdict", await codeOf(pki.cmp.verify(derMsg, { signerCert: s.cert, transactionID: "not-a-buffer" })) === "cmp/bad-input");
  check("14h. a non-buffer opts.expectRecipNonce (string) -> cmp/bad-input", await codeOf(pki.cmp.verify(derMsg, { signerCert: s.cert, expectRecipNonce: "not-a-buffer" })) === "cmp/bad-input");

  // ===== 15. config throws (tier-1: throw, not a verdict) =====
  check("15a. malformed DER -> throws a typed cmp/*", /^cmp\//.test(await codeOf(pki.cmp.verify(Buffer.from([0x30, 0x00]), {}))));
  check("15b. a MAC message with no sharedSecret -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, {})) === "cmp/bad-input");
  check("15c. a signature message WITH a sharedSecret (flavor mismatch) -> throws cmp/bad-input", await codeOf(pki.cmp.verify(derMsg, { signerCert: s.cert, sharedSecret: "x" })) === "cmp/bad-input");
  check("15d. a MAC message WITH signerCert/trustAnchors (flavor mismatch) -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "hunter2", signerCert: s.cert })) === "cmp/bad-input");
  check("15e. an unknown opts key -> throws cmp/bad-input", await codeOf(pki.cmp.verify(derMsg, { signerCert: s.cert, bogus: 1 })) === "cmp/bad-input");
  // an empty PBMAC1 secret has no entropy -> a peer could forge a matching MAC; require a non-empty secret.
  check("15f. an empty-string sharedSecret on a MAC message -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "" })) === "cmp/bad-input");
  check("15g. a zero-length Buffer sharedSecret -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: Buffer.alloc(0) })) === "cmp/bad-input");

  // ===== 16. direction-agnostic acceptance (a RESPONSE arm verifies exactly like a request) =====
  var errDer = await pki.cmp.build({ header: HDR, body: { error: { pKIStatusInfo: { status: 2 } } } }, SIG);
  check("16. a RESPONSE (error) message verifies like a request (flavor + signer, not role)", (await pki.cmp.verify(errDer, { signerCert: s.cert })).valid === true);

  // ===== 17. signer resolution: senderKID SKI binding (M14), extraCerts[0] (M11 RFC 9483 sec. 3.3), PEM =====
  var skiSigner = makeSigner("ec-p256", { ski: true });
  var ski = nodeCrypto.createHash("sha1").update(skiSigner.spki).digest();
  var skidDer = await pki.cmp.build({ header: hdr({ senderKID: ski }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: skiSigner.spki }, skiSigner.key) } }, { key: skiSigner.key, cert: skiSigner.cert });
  check("17a. a senderKID matching the signer cert SKI resolves + verifies", (await pki.cmp.verify(skidDer, { signerCert: skiSigner.cert })).valid === true);
  check("17b. an explicit signerCert that did NOT sign the message resolves (senderKID not a resolution gate) but its signature fails -> cmp/protection-failed", (await pki.cmp.verify(skidDer, { signerCert: s.cert })).code === "cmp/protection-failed");
  check("17c. no signerCert resolves the signer from extraCerts[0]", (await pki.cmp.verify(await buildSig(), {})).valid === true);
  var pemCert = "-----BEGIN CERTIFICATE-----\n" + s.cert.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----";
  check("17d. a PEM signerCert is accepted", (await pki.cmp.verify(await buildSig(), { signerCert: pemCert })).valid === true);
  check("17e. a non-buffer/non-string signerCert -> throws cmp/bad-input", await codeOf(pki.cmp.verify(await buildSig(), { signerCert: 42 })) === "cmp/bad-input");
  check("17f. no signerCert + a senderKID resolves the signer from extraCerts by SKI match", (await pki.cmp.verify(skidDer, {})).valid === true);

  // ===== 18. PBMAC1 protectionAlg with no parameters + a Buffer sharedSecret =====
  var noParams = substituteAlg(macDer, b.sequence([b.oid(pki.oid.byName("pbmac1"))]));
  check("18a. a PBMAC1 protectionAlg carrying no PBMAC1-params -> fail closed", (await pki.cmp.verify(noParams, { sharedSecret: "hunter2" })).valid === false);
  check("18b. a Buffer sharedSecret verifies", (await pki.cmp.verify(macDer, { sharedSecret: Buffer.from("hunter2", "utf8") })).valid === true);
  check("18c. maxIterations below the message iterationCount -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "hunter2", maxIterations: 1 })) === "cmp/bad-input");
  check("18d. a non-integer maxIterations -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "hunter2", maxIterations: 1.5 })) === "cmp/bad-input");

  // ===== 19. header opt-in echoes with matching values keep valid on the MAC path too =====
  var macEcho = await buildMac("hunter2", {}, { transactionID: Buffer.alloc(16, 0x21) });
  check("19a. a matching transactionID on a MAC message stays valid", (await pki.cmp.verify(macEcho, { sharedSecret: "hunter2", transactionID: Buffer.alloc(16, 0x21) })).valid === true);
  check("19b. a wrong transactionID on a MAC message -> cmp/transaction-id-mismatch", (await pki.cmp.verify(macEcho, { sharedSecret: "hunter2", transactionID: Buffer.alloc(16, 0x99) })).code === "cmp/transaction-id-mismatch");

  // ===== 20. verdict + coercion + trust-input edge branches =====
  check("20a. opts=null is treated as the default (empty) opts", (await pki.cmp.verify(await buildSig(), null)).valid === true);
  check("20b. opts as a Buffer -> throws cmp/bad-input", await codeOf(pki.cmp.verify(await buildSig(), Buffer.from("x"))) === "cmp/bad-input");
  check("20b2. opts as a string -> throws cmp/bad-input", await codeOf(pki.cmp.verify(await buildSig(), "x")) === "cmp/bad-input");
  var minHdr = { sender: { directoryName: [{ commonName: "Test Signer" }] }, recipient: { directoryName: "CN=CA" } };
  var minV = await pki.cmp.verify(await pki.cmp.build({ header: minHdr, body: IRBODY }, SIG), { signerCert: s.cert });
  check("20c. a message with no transactionID/senderNonce -> verdict echoes null for the absent fields", minV.valid === true && minV.transactionID === null && minV.senderNonce === null && minV.recipNonce === null);
  // trustAnchors as a SINGLE root cert (not an array); no opts.time -> the signer path is validated at the
  // trusted current time (the signer cert's 2020..2040 window covers it), exercising the single-cert coercion.
  var mtChain = await pki.cmp.build({ header: Object.assign({ messageTime: T }, HDR), body: await p10Body(signerSpki, signerKey) }, { key: signerKey, cert: signerCert });
  check("20d. trustAnchors as a single cert (not an array) validates at a trusted now -> trusted", (await pki.cmp.verify(mtChain, { signerCert: signerCert, trustAnchors: caCert })).trusted === true);
  check("20e. a trust verify with the message extraCerts stripped still validates (signer issued directly by the anchor)", (await pki.cmp.verify(stripExtraCerts(mtChain), { signerCert: signerCert, trustAnchors: [caCert], intermediates: [], time: T })).trusted === true);

  // ===== 21. additional fail-closed edge branches =====
  check("21a. maxIterations = Infinity -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "hunter2", maxIterations: Infinity })) === "cmp/bad-input");
  check("21b. maxIterations = 0 -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "hunter2", maxIterations: 0 })) === "cmp/bad-input");
  check("21c. a malformed PEM signerCert -> throws cmp/bad-input", await codeOf(pki.cmp.verify(await buildSig(), { signerCert: "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----" })) === "cmp/bad-input");
  check("21d. a valid-DER-but-not-a-certificate signerCert (corrupt required config) -> throws cmp/bad-input, not a routine not-found verdict", await codeOf(pki.cmp.verify(await buildSig(), { signerCert: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]) })) === "cmp/bad-input");
  var noTidDer = await pki.cmp.build({ header: { sender: { directoryName: [{ commonName: "Test Signer" }] }, recipient: { directoryName: "CN=CA" } }, body: IRBODY }, SIG);
  check("21e. an opt-in transactionID against a message that carries none -> cmp/transaction-id-mismatch", (await pki.cmp.verify(noTidDer, { signerCert: s.cert, transactionID: Buffer.alloc(16, 1) })).code === "cmp/transaction-id-mismatch");

  // ===== 23. every caller-owned option is fixed at the call =====
  // Verification suspends this verb -- PBMAC1 derivation on one path, the signature engine on the
  // other -- and an option read after it resumes answers for whatever the caller last wrote. RED
  // without the fix: each of these returned valid === true for a message the option did not match.
  var raceDer = await buildSig({ transactionID: Buffer.alloc(16, 7) });
  check("23a. baseline: a transactionID the message does not carry is refused",
    (await pki.cmp.verify(raceDer, { signerCert: s.cert, transactionID: Buffer.alloc(16, 9) })).valid === false);
  check("23b. baseline: the matching transactionID passes",
    (await pki.cmp.verify(raceDer, { signerCert: s.cert, transactionID: Buffer.alloc(16, 7) })).valid === true);

  // The buffer itself is overwritten, so the caller never touches the property.
  var raceBuf = Buffer.alloc(16, 9);
  var racePending = pki.cmp.verify(raceDer, { signerCert: s.cert, transactionID: raceBuf });
  raceBuf.fill(7);
  check("23c. overwriting the transactionID buffer mid-call does not change the verdict",
    (await racePending).valid === false);

  // The property is replaced on the caller's own options object.
  var raceOpts = { signerCert: s.cert, transactionID: Buffer.alloc(16, 9) };
  var racePending2 = pki.cmp.verify(raceDer, raceOpts);
  raceOpts.transactionID = Buffer.alloc(16, 7);
  check("23d. replacing opts.transactionID mid-call does not change the verdict",
    (await racePending2).valid === false);

  // The MAC path suspends inside PBMAC1 derivation, so it has the same window.
  var raceMac = await buildMac("hunter2", {}, { transactionID: Buffer.alloc(16, 7) });
  var macOpts = { sharedSecret: "hunter2", transactionID: Buffer.alloc(16, 9) };
  var racePending3 = pki.cmp.verify(raceMac, macOpts);
  macOpts.transactionID = Buffer.alloc(16, 7);
  check("23e. the MAC path fixes the transactionID at the call too",
    (await racePending3).valid === false);

  // expectRecipNonce is the sibling echo value and takes the same route.
  var raceNonce = Buffer.alloc(16, 3);
  var racePending4 = pki.cmp.verify(raceDer, { signerCert: s.cert, expectRecipNonce: raceNonce });
  raceNonce.fill(0);
  var rn = await racePending4;
  check("23f. overwriting expectRecipNonce mid-call does not change the verdict", rn.valid === false);

  // A Date is re-made at the same instant, so setTime on the caller's own object cannot move the
  // instant the chain is validated at. The call starts OUTSIDE the signer's validity, where the
  // chain fails, and is mutated to an instant inside it -- the direction that would gain trust.
  var raceChain = await pki.cmp.build({ header: Object.assign({ messageTime: T }, HDR), body: await p10Body(signerSpki, signerKey) }, { key: signerKey, cert: signerCert });
  var OUTSIDE = new Date("2099-01-01T00:00:00Z");
  check("23g. baseline: an instant past the signer's validity leaves it untrusted",
    (await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [caCert], time: new Date(OUTSIDE.getTime()) })).trusted === false);
  var raceDate = new Date(OUTSIDE.getTime());
  var racePending5 = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [caCert], time: raceDate });
  raceDate.setTime(T.getTime());
  check("23h. calling setTime on the caller's Date mid-call does not gain trust",
    (await racePending5).trusted === false);

  // Appending to the anchor array after the call does not widen the set the chain was built against.
  // The array starts with an unrelated anchor, so the call is well-formed and the chain simply fails.
  var raceAnchors = [s.cert];
  check("23i. baseline: an unrelated anchor leaves the signer untrusted",
    (await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [s.cert], time: T })).trusted === false);
  check("23j. baseline: the real anchor makes it trusted",
    (await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [caCert], time: T })).trusted === true);
  var racePending6 = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: raceAnchors, time: T });
  raceAnchors.push(caCert);
  check("23k. appending to opts.trustAnchors mid-call does not make the signer trusted",
    (await racePending6).trusted === false);

  // A PARSED anchor is passed through by reference on purpose -- guard.parsed records provenance
  // against the object's identity, so a copy would stop being recognized as parser output. What
  // makes that safe is the far end: path validation re-derives a parsed certificate from the bytes
  // it recorded, so a field edited on the caller's object never reaches the decision.
  var parsedAnchor = pki.schema.x509.parse(caCert);
  var racePending7 = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [parsedAnchor], time: T });
  parsedAnchor.subject = { dn: "CN=Not The CA", rdns: [] };
  parsedAnchor.tbsBytes = Buffer.alloc(4);
  check("23l. a parsed anchor still anchors the chain after its fields are edited mid-call",
    (await racePending7).trusted === true);

  // An options bag whose fields are ACCESSORS is refused outright, by the toolkit's own options
  // door. That single rule is what closes the whole caller-getter class rather than one member of
  // it: an accessor is caller code running inside the call before the verb has done anything, and
  // from there it can rewrite the very predicates and constructors the verb is about to use --
  // Buffer.from, Array.isArray, util.types.isUint8Array, Promise.prototype.then. Hardening each of
  // those in turn is a list with no end; refusing the accessor removes the window they all need.
  // The accessor is never even read, so it cannot act before being refused.
  var accessorRead = false;
  var accessorBag = {
    signerCert: signerCert, trustAnchors: [caCert],
    get time() { accessorRead = true; return new Date(T.getTime()); },
  };
  check("23m. an accessor-backed options bag is refused",
    (await codeOf(pki.cmp.verify(raceChain, accessorBag))) === "cmp/bad-input");
  check("23n. and the accessor was never invoked", accessorRead === false);
  check("23n2. the refusal names the field and what to pass instead", await (async function () {
    try { await pki.cmp.verify(raceChain, accessorBag); return false; }
    catch (e) { return /"time"/.test(e.message) && /plain values/.test(e.message); }
  })());

  // The rule holds one level down. An accessor under an INDEX of a certificate list is caller code
  // exactly as an accessor under a name is, and a list is where it pays: an element can answer as
  // one certificate to a check and as another to the read, or simply run and rewrite a predicate
  // the reduction has not reached yet. RED without the element check: the getter ran.
  var elementRead = false;
  var accessorList = [];
  Object.defineProperty(accessorList, "0", {
    enumerable: true, configurable: true,
    get: function () { elementRead = true; return caCert; },
  });
  check("23n3. an accessor-backed certificate-list element is refused",
    (await codeOf(pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: accessorList, time: T }))) === "cmp/bad-input");
  check("23n4. and that element was never read", elementRead === false);

  // The anchor list is copied without calling back into the caller's array. `map` is the caller's
  // property, so an array that answers it with itself would leave the copy aliasing the original,
  // and appending mid-call would widen the set the chain is built against.
  // The entries are PARSED certificates, which every later step passes through unchanged, so a
  // hostile `map` cannot also break the byte conversion and fail the chain for an unrelated reason.
  //
  // Honest status of this one: it PINS the behavior, it does not prove the loop is what produces
  // it. Swapping the loop back to `v.map(_fixByteish)` leaves this passing -- the appended anchor
  // does not reach the anchor set even when the container aliases, so the exposure the reviewer
  // described is not reachable through this route. The loop is kept because dispatching a copy
  // through a method the caller owns is the wrong shape regardless of whether today's downstream
  // happens to absorb it, and this vector holds the outcome still while that stays true.
  var parsedOther = pki.schema.x509.parse(s.cert), parsedCa = pki.schema.x509.parse(caCert);
  var hostile = [parsedOther];
  hostile.map = function () { return this; };
  check("23o. the hostile list is a real array", Array.isArray(hostile));
  check("23p. and its map answers with itself", hostile.map(function () { return 1; }) === hostile);
  check("23q. baseline: the parsed CA alone does anchor the chain",
    (await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [parsedCa], time: T })).trusted === true);
  var racePending8 = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: hostile, time: T });
  hostile.push(parsedCa);
  check("23r. appending to an array whose map returns itself does not widen the anchor set",
    (await racePending8).trusted === false);

  // A getter for a LATER field reaching back to mutate the buffer an EARLIER field handed over is
  // the same class, and it dies at the same door: the bag is refused before any field is read. The
  // ordering discipline in the reducer (copy each field as it is read) is kept behind that door
  // anyway, because a rule that holds only while another rule holds is not a rule.
  var smuggler = Buffer.alloc(16, 9);
  var reach = {
    signerCert: s.cert,
    transactionID: smuggler,
    get revocationChecker() { smuggler.fill(7); return undefined; },
  };
  check("23s. a bag whose later field reaches back through a getter is refused",
    (await codeOf(pki.cmp.verify(raceDer, reach))) === "cmp/bad-input");
  check("23s2. and the earlier field's bytes were never touched",
    smuggler.every(function (b) { return b === 9; }));

  // An array's length is independent of what it holds. Only the elements that exist are copied, so
  // a sparse list carrying one anchor at index 100000000 collapses to that one anchor instead of
  // becoming a dense hundred-million-entry allocation inside verify. No ceiling is imposed: a trust
  // store is the caller's own configuration, and path.build limits the untrusted candidate pool
  // rather than the number of anchors, so capping this would refuse a large store that verifies.
  var sparse = [];
  sparse[100000000] = caCert;
  var sparseStart = Date.now();
  var sparseErr = null;
  try { await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: sparse, time: T }); }
  catch (e) { sparseErr = e; }
  check("23t. a sparse anchor list is refused, naming what is wrong with it",
    sparseErr !== null && sparseErr.code === "cmp/bad-input" && /dense array/.test(sparseErr.message));
  // The refusal is reached by counting the properties the object has, never by walking its length,
  // so it returns immediately. Wall-clock is the only observable that separates the two, and the
  // bound is far above any real machine rather than a measured figure.
  check("23u. and refused without walking a hundred million positions",
    (Date.now() - sparseStart) < 30000);

  // An element defined non-enumerable is still an element, and every ordinary array operation
  // consumes it, so the copy must not quietly drop the anchor and report the signer untrusted.
  var hidden = [];
  Object.defineProperty(hidden, "0", { value: caCert, enumerable: false, writable: true, configurable: true });
  check("23v. a non-enumerable element is still an anchor",
    (await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: hidden, time: T })).trusted === true);

  // 2^32-1 is the one uint32 the language does not treat as an array index, so a property named
  // "4294967295" is a name the caller hung on the array, never a certificate to feed the builder.
  var named = [caCert];
  named["4294967295"] = "not a certificate";
  check("23w. a property named 4294967295 is not read as a certificate",
    (await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: named, time: T })).trusted === true);

  // An anchor supplied at an INHERITED index is one an ordinary array operation would consume, so
  // silently skipping it would drop a trust anchor and turn a trusted verification into an untrusted
  // one. The list is refused instead, loudly, rather than emulated: the caller is told their list is
  // not dense and normalizes it themselves.
  var proto = []; proto[0] = caCert;
  var inherited = [];
  inherited.length = 1;                        // a hole at index 0 ...
  Object.setPrototypeOf(inherited, proto);     // ... that the prototype answers for
  check("23x. the fixture is a real array whose index 0 is inherited",
    Array.isArray(inherited) && (0 in inherited) &&
    !Object.prototype.hasOwnProperty.call(inherited, "0") && inherited[0] === caCert);
  var inhErr = null;
  try { await pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: inherited, time: T }); }
  catch (e) { inhErr = e; }
  check("23x2. an anchor reachable only through the prototype is refused, never silently dropped",
    inhErr !== null && inhErr.code === "cmp/bad-input" && /dense array/.test(inhErr.message));

  // Array.prototype.map is a replaceable global, and the anchor list becomes path-builder input
  // AFTER verification suspends. A caller who swaps it during that window must not end up trusted.
  //
  // What this vector establishes, precisely: the swap is live and is reached, and the verdict is
  // still untrusted. It does NOT isolate cmp-verify's explicit loops as the cause -- a global map
  // replacement also corrupts path building's own internals, so the refusal cannot be attributed to
  // one change. The loops in _certList and the pool assembly are kept on principle, because a trust
  // decision should not dispatch through a replaceable global at all, and they are honestly recorded
  // here as unproven by this vector rather than credited with a result they may not produce.
  var realMap = Array.prototype.map;
  var swapped = false;
  var pendingSwap = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [s.cert], time: T });
  Array.prototype.map = function () { swapped = true; return [caCert]; };
  var swapVerdict;
  try { swapVerdict = await pendingSwap; } finally { Array.prototype.map = realMap; }
  check("23y. replacing Array.prototype.map mid-call does not decide the anchor set",
    swapVerdict.trusted === false);
  // The replacement really was live and really was reached during the window -- without this the
  // vector above would pass on a call that simply never touched it. What the fix changes is that
  // nothing on the ANCHOR path dispatches through it: cmp-verify builds its lists with explicit
  // loops, so the swap cannot answer the question "which certificates are trusted". Code deeper in
  // path building still calls it, which is why this asserts the swap fired rather than claiming the
  // whole call is free of it.
  check("23z. the replacement was installed and reached while the call was pending", swapped === true);

  // An Array.prototype index SETTER is the sharper form of the same idea: a fresh array has no own
  // slot at 0, so `out[0] = cert` is a [[Set]] that walks the prototype chain and lands in caller
  // code at the moment the anchor list is being built. Appending with a captured defineProperty
  // creates the own slot outright and consults no setter. RED without it: the setter fired.
  var setterFired = false;
  var pendingSetter = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [s.cert], time: T });
  Object.defineProperty(Array.prototype, "0", {
    configurable: true, set: function () { setterFired = true; }, get: function () { return caCert; },
  });
  var setterVerdict;
  try { setterVerdict = await pendingSetter; } finally { delete Array.prototype[0]; }
  // As with the map swap: the setter IS reached, by array building deeper in path validation, so
  // this cannot assert that nothing invoked it. What it does assert is the property that matters --
  // a setter installed during the window does not turn an unrelated anchor into a trusted signer.
  // cmp-verify's own lists are built with a captured defineProperty and consult no setter; proving
  // that in isolation would need path validation to be hardened the same way, which is its own cut.
  check("23aa. the setter was installed and reached while the call was pending", setterFired === true);
  check("23ab. and the unrelated anchor still leaves the signer untrusted", setterVerdict.trusted === false);

  // A byte option is copied through guard.bytes.snapshot, this toolkit's door for caller bytes, so a
  // source the door refuses stays refused. A SharedArrayBuffer-backed view is the case: another
  // thread can rewrite it at any moment, and a bare Buffer.from would have laundered it into an
  // ordinary Buffer that every later check accepts without the door's rules ever having run.
  var shared = new Uint8Array(new SharedArrayBuffer(16));
  shared.fill(7);
  check("23ac. the fixture really is SharedArrayBuffer-backed",
    shared.buffer instanceof SharedArrayBuffer);
  check("23ad. a shared-memory transactionID is refused rather than copied",
    (await codeOf(pki.cmp.verify(raceDer, { signerCert: s.cert, transactionID: shared }))) === "cmp/bad-input");
  var sharedSecretView = new Uint8Array(new SharedArrayBuffer(8));
  sharedSecretView.fill(1);
  check("23ae. and so is a shared-memory sharedSecret",
    (await codeOf(pki.cmp.verify(raceMac, { sharedSecret: sharedSecretView }))) === "cmp/bad-input");

  // The copy of a byte shared secret is this module's, and it holds the plaintext. pbes2.pbmac1
  // clears only the MAC key it derives, so the copy has to be wiped on the way out. Observed by
  // holding the caller's buffer: it must be untouched (it is theirs), while nothing of the secret
  // may survive in a copy the module made. The copy is not reachable from here, so what this pins
  // is the pair of properties the wipe must not break -- the caller's own bytes are never clobbered,
  // and the verdict is still correct -- alongside the guard-secret contract tested in its own file.
  var callerSecret = Buffer.from("hunter2", "utf8");
  var secretVerdict = await pki.cmp.verify(raceMac, { sharedSecret: callerSecret });
  check("23af. a byte shared secret still verifies", secretVerdict.valid === true);
  check("23ag. and the caller's own buffer is left intact",
    callerSecret.toString("utf8") === "hunter2");

  // global.Date is replaceable, and a replacement asked for a fresh instant could hand back the
  // caller's own object -- leaving the "copy" of opts.time as the Date they can still mutate. The
  // constructor is captured at module load. RED without that: the swapped Date was used.
  var realDate = global.Date;
  var dateUsed = false;
  var liveDate = new realDate(OUTSIDE.getTime());
  var pendingDate = pki.cmp.verify(raceChain, { signerCert: signerCert, trustAnchors: [caCert], time: liveDate });
  function SwappedDate() { dateUsed = true; return liveDate; }
  SwappedDate.now = realDate.now;
  global.Date = SwappedDate;
  var dateVerdict;
  try { dateVerdict = await pendingDate; } finally { global.Date = realDate; }
  liveDate.setTime(T.getTime());
  // As with the map swap and the index setter: the replacement is reached, by code deeper in path
  // validation that asks for the current time. cmp-verify's own copy is taken with the constructor
  // captured at module load and happens synchronously at the call, before this swap is even
  // installed -- so what this asserts is that the window was live, and 23ai asserts the outcome.
  check("23ah. the replaced constructor was installed and reached while the call was pending",
    dateUsed === true);
  check("23ai. and mutating the caller's Date afterwards still leaves the signer untrusted",
    dateVerdict.trusted === false);

  // The secret's copy is made before the later options are reduced, so a fault in one of THOSE is
  // the path on which the copy would be left unowned. Reducing collects each copy as it is made,
  // and the wipe runs over what was collected rather than over a result that never existed. The
  // copy is not reachable from here; what is observable is that the call still refuses cleanly and
  // the caller's own secret is untouched, which is what the collect-then-wipe must not break.
  var faultSecret = Buffer.from("hunter2", "utf8");
  var sparseAfterSecret = [];
  sparseAfterSecret[100000000] = caCert;
  var faultCode = await codeOf(pki.cmp.verify(raceMac, {
    sharedSecret: faultSecret, trustAnchors: sparseAfterSecret,
  }));
  check("23aj. a fault after the secret is copied still refuses cleanly", faultCode === "cmp/bad-input");
  check("23ak. and the caller's own secret is left intact",
    faultSecret.toString("utf8") === "hunter2");

  // The sharpest form of the accessor class: a getter that installs a replacement for a global the
  // verb itself is about to use. Promise.prototype.finally is the example -- a verb cleaning up with
  // `.finally(...)` would dispatch into the replacement and hand back whatever it returned, so a
  // rejected verification could be reported as passing. Two things stop it, and the order matters:
  // the bag is refused before the getter runs at all, and the cleanup is language-level try/finally,
  // which looks nothing up even if something did get installed.
  var realFinally = Promise.prototype.finally;
  var finallyReached = false;
  var swapOnGetter = {
    signerCert: s.cert,
    get transactionID() {
      Promise.prototype.finally = function () {
        finallyReached = true;
        return Promise.resolve({ valid: true, trusted: true, forged: true });
      };
      return Buffer.alloc(16, 9);   // does NOT match the message
    },
  };
  var swapCode;
  try { swapCode = await codeOf(pki.cmp.verify(raceDer, swapOnGetter)); }
  finally { Promise.prototype.finally = realFinally; }
  check("23al. the bag carrying that getter is refused before it can install anything",
    swapCode === "cmp/bad-input");
  check("23am. and the replacement was never installed", finallyReached === false);

  // The echo-value type check is a configuration error the caller must be shown, never a routine
  // mismatch verdict that blames the peer. It is written out as two named checks rather than a loop,
  // because the reduction has already run the caller's getters and one of those could have replaced
  // Array.prototype.forEach with a no-op -- switching the check off rather than failing it.
  //
  // Honest status: this pins the CONTRACT, not the hardening. A vector that actually installs a
  // no-op forEach cannot isolate it, because forEach is used throughout the certificate parsing this
  // path also runs, so the call dies there first and the refusal cannot be attributed to this check.
  // The written-out form is kept on principle, the same principle as the loops above: a check that a
  // caller can switch off is not a check.
  check("23an. a string transactionID is a configuration error, not a mismatch verdict",
    (await codeOf(pki.cmp.verify(raceDer, { signerCert: s.cert, transactionID: "not-a-buffer" }))) === "cmp/bad-input");
  check("23ao. and so is a string expectRecipNonce",
    (await codeOf(pki.cmp.verify(raceDer, { signerCert: s.cert, expectRecipNonce: "not-a-buffer" }))) === "cmp/bad-input");

  // Whether a byte option is COPIED, and whether that copy is entered in the wipe list, must not be
  // decided by a predicate the caller can rewrite. Buffer.isBuffer is a writable property and
  // `instanceof Uint8Array` consults Uint8Array[Symbol.hasInstance]. Answering false for the
  // caller's own secret skipped the copy and put their live buffer where the copy belongs -- which
  // the wipe then destroys, memory the toolkit does not own. Two independent things stop it: the
  // accessor that would install the lie is refused at the door, and the tests ask
  // util.types.isUint8Array, which is a fact about the value rather than a claim about its
  // prototype. The second still holds for a caller who rewrites the globals without an accessor.
  var realHasInstance = Object.getOwnPropertyDescriptor(Uint8Array, Symbol.hasInstance);
  var realIsBuffer = Buffer.isBuffer;
  var callerOwned = Buffer.from("hunter2", "utf8");
  var lieOnce = true;
  try {
    // No accessor here: the globals are rewritten directly, which is the form the door cannot see.
    Buffer.isBuffer = function () { return false; };
    Object.defineProperty(Uint8Array, Symbol.hasInstance, {
      configurable: true, value: function () { if (lieOnce) { lieOnce = false; return false; } return true; },
    });
    await pki.cmp.verify(raceMac, { sharedSecret: callerOwned });
  } catch (_e) { /* the verdict is not what this vector is about */ }
  finally {
    Buffer.isBuffer = realIsBuffer;
    if (realHasInstance) Object.defineProperty(Uint8Array, Symbol.hasInstance, realHasInstance);
    else delete Uint8Array[Symbol.hasInstance];
  }
  check("23ap. a lying kind test cannot make the verb wipe the caller's own secret",
    callerOwned.toString("utf8") === "hunter2");

  // A STRING secret is converted to bytes once, at the door, and that copy is recorded in the same
  // wipe list as the byte form -- so it is cleared on every path out rather than left behind by the
  // MAC path, which is where the conversion used to happen with nothing owning the result. The
  // string itself is immutable and cannot be cleared, which is why bytes remain the form to pass
  // when the secret must not outlive the call.
  //
  // The copy is deliberately NOT observable from a test: the conversion uses a Buffer.from captured
  // at module load, so a spy installed afterwards never sees it -- which is the property 23au/23av
  // below actually pin. What is observable here is that the string form works and that the wipe list
  // it feeds is the same one 23af/23ag exercise for bytes; guard-secret's own tests pin the wipe.
  check("23aq. a string secret still verifies",
    (await pki.cmp.verify(raceMac, { sharedSecret: "hunter2" })).valid === true);
  check("23ar. and an empty string is still refused as a secret",
    (await codeOf(pki.cmp.verify(raceMac, { sharedSecret: "" }))) === "cmp/bad-input");

  // The authentication bypass this pair exists for, and the two independent things that stop it.
  //
  // The accessor on sharedSecret -- the first thing the reduction reads -- could install a
  // Buffer.from replacement, receive the plaintext secret as its argument, and have its RETURN
  // become the PBMAC1 key: a message authenticated under a secret the caller never held then
  // verified. The options door refuses the accessor outright, and the conversion uses a Buffer.from
  // captured at module load, so the swap has nothing to reach even from outside an accessor.
  var macUnderOther = await pki.cmp.build({ header: hdr({ transactionID: Buffer.alloc(16, 7) }), body: IRBODY },
    { mac: { secret: "attacker-key", salt: Buffer.alloc(16, 9), iterationCount: 2048 } });
  check("23at. baseline: the wrong secret does not verify",
    (await pki.cmp.verify(macUnderOther, { sharedSecret: "hunter2" })).valid === false);

  var realFrom = Buffer.from;
  var stolen = null;
  function poison() {
    Buffer.from = function (a, enc) {
      if (typeof a === "string" && enc === "utf8") {
        stolen = a; Buffer.from = realFrom;
        return realFrom("attacker-key", "utf8");
      }
      return realFrom.apply(Buffer, arguments);
    };
  }

  // (a) through an accessor -- refused before the accessor runs.
  var poisoning = {};
  Object.defineProperty(poisoning, "sharedSecret", {
    enumerable: true, configurable: true,
    get: function () { poison(); return "hunter2"; },
  });
  var viaAccessor;
  try { viaAccessor = await codeOf(pki.cmp.verify(macUnderOther, poisoning)); }
  finally { Buffer.from = realFrom; }
  check("23au. an accessor that would substitute the PBMAC1 key is refused at the door",
    viaAccessor === "cmp/bad-input");

  // (b) without one -- the global is rewritten directly, which no door can see, and the captured
  // constructor is what holds. This is the half that survives if the door is ever relaxed.
  var poisonVerdict;
  try { poison(); poisonVerdict = await pki.cmp.verify(macUnderOther, { sharedSecret: "hunter2" }); }
  catch (_e) { poisonVerdict = { valid: false }; }
  finally { Buffer.from = realFrom; }
  check("23au2. and a direct Buffer.from swap cannot substitute it either",
    poisonVerdict.valid === false);
  check("23av. and cannot capture the caller's plaintext secret through it", stolen === null);

  // ===== 22. PBMAC1 dispatches on the immutable OID, not the mutable registry display name (LAST: mutates oid) =====
  var oidMsg = await buildMac("hunter2");
  pki.oid.register(pki.oid.byName("hmacWithSHA256"), "renamed-hmac-256");   // a documented display-name override
  check("22. renaming hmacWithSHA256 in the registry does not break PBMAC1 verify (OID dispatch)", (await pki.cmp.verify(oidMsg, { sharedSecret: "hunter2" })).valid === true);

  console.log("CHECKS " + helpers.getChecks());
}

run().then(function () { }, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
