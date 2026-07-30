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
  // the path-builder pool ceiling (1000): unsigned extraCerts must not push a caller pool already at the
  // ceiling over it and turn a valid verification into an exception.
  var fullPool = new Array(1000).fill(signerCert);
  check("9p. extraCerts do not push a ceiling-full caller intermediates pool over the path-builder limit", (await pki.cmp.verify(chainDer, { signerCert: signerCert, trustAnchors: [caCert], intermediates: fullPool, time: T })).trusted === true);

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

  // ===== 12. work-factor caps: a huge iterationCount rejects BEFORE derivation (no multi-second burn) =====
  var hugeIter = substituteAlg(macDer, pbmac1AlgId({ salt: SALT, iter: 100000000, keyLen: 32, prf: "hmacWithSHA256", mac: "hmacWithSHA256" }));
  check("12. a PBMAC1 iterationCount over the cap -> cmp/bad-input before any derivation", await codeOf(pki.cmp.verify(hugeIter, { sharedSecret: "hunter2" })) === "cmp/bad-input");

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

  // ===== 15. config throws (tier-1: throw, not a verdict) =====
  check("15a. malformed DER -> throws a typed cmp/*", /^cmp\//.test(await codeOf(pki.cmp.verify(Buffer.from([0x30, 0x00]), {}))));
  check("15b. a MAC message with no sharedSecret -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, {})) === "cmp/bad-input");
  check("15c. a signature message WITH a sharedSecret (flavor mismatch) -> throws cmp/bad-input", await codeOf(pki.cmp.verify(derMsg, { signerCert: s.cert, sharedSecret: "x" })) === "cmp/bad-input");
  check("15d. a MAC message WITH signerCert/trustAnchors (flavor mismatch) -> throws cmp/bad-input", await codeOf(pki.cmp.verify(macDer, { sharedSecret: "hunter2", signerCert: s.cert })) === "cmp/bad-input");
  check("15e. an unknown opts key -> throws cmp/bad-input", await codeOf(pki.cmp.verify(derMsg, { signerCert: s.cert, bogus: 1 })) === "cmp/bad-input");

  // ===== 16. direction-agnostic acceptance (a RESPONSE arm verifies exactly like a request) =====
  var errDer = await pki.cmp.build({ header: HDR, body: { error: { pKIStatusInfo: { status: 2 } } } }, SIG);
  check("16. a RESPONSE (error) message verifies like a request (flavor + signer, not role)", (await pki.cmp.verify(errDer, { signerCert: s.cert })).valid === true);

  // ===== 17. signer resolution: senderKID SKI binding (M14), extraCerts[0] (M11 RFC 9483 sec. 3.3), PEM =====
  var skiSigner = makeSigner("ec-p256", { ski: true });
  var ski = nodeCrypto.createHash("sha1").update(skiSigner.spki).digest();
  var skidDer = await pki.cmp.build({ header: hdr({ senderKID: ski }), body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: skiSigner.spki }, skiSigner.key) } }, { key: skiSigner.key, cert: skiSigner.cert });
  check("17a. a senderKID matching the signer cert SKI resolves + verifies", (await pki.cmp.verify(skidDer, { signerCert: skiSigner.cert })).valid === true);
  check("17b. a senderKID NOT binding to the presented cert -> cmp/signer-cert-not-found", (await pki.cmp.verify(skidDer, { signerCert: s.cert })).code === "cmp/signer-cert-not-found");
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
  check("21d. a valid-DER-but-not-a-certificate signerCert -> cmp/signer-cert-not-found", (await pki.cmp.verify(await buildSig(), { signerCert: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]) })).code === "cmp/signer-cert-not-found");
  var noTidDer = await pki.cmp.build({ header: { sender: { directoryName: [{ commonName: "Test Signer" }] }, recipient: { directoryName: "CN=CA" } }, body: IRBODY }, SIG);
  check("21e. an opt-in transactionID against a message that carries none -> cmp/transaction-id-mismatch", (await pki.cmp.verify(noTidDer, { signerCert: s.cert, transactionID: Buffer.alloc(16, 1) })).code === "cmp/transaction-id-mismatch");

  console.log("CHECKS " + helpers.getChecks());
}

run().then(function () { }, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
