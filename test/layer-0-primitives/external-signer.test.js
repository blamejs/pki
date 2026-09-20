// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the signer form every signing verb takes beside a private key:
 * `{ algorithm, publicKey, sign(bytes) }`. The private half never reaches the
 * toolkit, which is the point: a key in an HSM, a cloud KMS, a PKCS#11 token or a
 * PIV slot can sign what this toolkit builds.
 *
 * The vectors drive the shipped verbs. What they pin is the contract around the
 * callback: it is handed the bytes WebCrypto would be handed and returns the bytes
 * WebCrypto would return, its declared algorithm is held to the certificate's key,
 * its declared public key is held to the key the signature will be verified
 * against, and what it returns is read once and copied before use.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var subtle = pki.webcrypto.subtle;

function code(p) {
  return Promise.resolve(p).then(function () { return "NO-THROW"; }, function (e) { return (e && e.code) || e.name; });
}

var NOT_BEFORE = new Date("2026-01-01T00:00:00Z");
var NOT_AFTER = new Date("2036-01-01T00:00:00Z");

// A signer that delegates to WebCrypto, so the callback's contract is exactly the
// one the toolkit documents. `calls` records what it was handed and whether it ran.
function delegatingSigner(pair, spki, alg, signAlg) {
  var self = {
    calls: 0,
    lastBytes: null,
    algorithm: alg,
    publicKey: spki,
    sign: function (bytes) {
      self.calls += 1;
      self.lastBytes = Buffer.from(bytes);
      return subtle.sign(signAlg, pair.privateKey, bytes);
    },
  };
  return self;
}

async function ed25519Signer() {
  var pair = await pki.key.generate("Ed25519");
  var spki = await pki.key.export(pair.publicKey);
  return { pair: pair, spki: spki, signer: delegatingSigner(pair, spki, { name: "Ed25519" }, { name: "Ed25519" }) };
}

async function p256Signer() {
  var pair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var spki = await pki.key.export(pair.publicKey);
  var alg = { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } };
  return { pair: pair, spki: spki, signer: delegatingSigner(pair, spki, alg, { name: "ECDSA", hash: "SHA-256" }) };
}

// The serial is pinned so two signings of the same spec differ only in the signature,
// which is what makes the deterministic-signature control meaningful.
function rootSpec(spki, cn) {
  return {
    subject: cn || "CN=External Signer Root",
    subjectPublicKey: spki,
    serialNumber: 20260920n,
    notBefore: NOT_BEFORE,
    notAfter: NOT_AFTER,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  };
}

// ---- the form signs, and what it signs verifies ---------------------------
async function testSignerSignsACertificate() {
  var e = await ed25519Signer();
  var der = await pki.x509.sign(rootSpec(e.spki), { key: e.signer });
  check("a signer object signs a certificate", Buffer.isBuffer(der));
  check("and the signer was the one asked for the signature", e.signer.calls === 1);
  var parsed = pki.schema.x509.parse(der);
  check("the certificate names the signer's algorithm",
    parsed.signatureAlgorithm.name === "Ed25519");
  check("and it is self-consistent: the tbs the signer saw is the tbs the certificate carries",
    e.signer.lastBytes.equals(parsed.tbsBytes));

  // CONTROL: the same spec signed by the private key directly is byte-identical,
  // Ed25519 being deterministic. The seam adds a caller, not a different signature.
  var direct = await pki.x509.sign(rootSpec(e.spki), { key: e.pair.privateKey });
  check("CONTROL: the same certificate signed with the CryptoKey is byte-identical",
    direct.equals(der));
}

// ---- the declared algorithm is held to the certificate's key --------------
async function testDeclaredAlgorithmIsChecked() {
  var e = await ed25519Signer();
  var wrong = {
    algorithm: { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
    publicKey: e.spki,
    calls: 0,
    sign: function (bytes) { wrong.calls += 1; return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes); },
  };
  check("a signer whose algorithm does not match the certificate's key is refused",
    await code(pki.x509.sign(rootSpec(e.spki), { key: wrong })) === "x509/bad-input");
  check("and it is refused before the signer is asked to sign", wrong.calls === 0);
}

// ---- the declared public key is held to the key that will verify ----------
async function testDeclaredPublicKeyIsChecked() {
  var e = await ed25519Signer();
  var other = await ed25519Signer();
  var mismatched = {
    algorithm: { name: "Ed25519" },
    publicKey: other.spki,
    calls: 0,
    sign: function (bytes) { mismatched.calls += 1; return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes); },
  };
  check("a signer that declares a different public key than the certificate names is refused",
    await code(pki.x509.sign(rootSpec(e.spki), { key: mismatched })) === "x509/bad-input");
  check("and it is refused before the signer is asked to sign", mismatched.calls === 0);
}

// ---- what the callback returns ------------------------------------------
async function testReturnedSignatureIsHeldToTheContract() {
  var p = await p256Signer();
  // An ECDSA signer that returns the DER SEQUENCE an HSM usually returns, where the
  // contract asks for the fixed-width r||s WebCrypto returns.
  var derSigner = {
    algorithm: { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
    publicKey: p.spki,
    sign: async function (bytes) {
      var raw = Buffer.from(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, p.pair.privateKey, bytes));
      return pki.asn1.build.sequence([
        pki.asn1.build.integer(BigInt("0x" + raw.subarray(0, 32).toString("hex"))),
        pki.asn1.build.integer(BigInt("0x" + raw.subarray(32).toString("hex"))),
      ]);
    },
  };
  check("an ECDSA signer that returns a DER signature is refused",
    await code(pki.x509.sign(rootSpec(p.spki), { key: derSigner })) === "x509/bad-input");

  var e = await ed25519Signer();
  var short = { algorithm: { name: "Ed25519" }, publicKey: e.spki, sign: function () { return Buffer.alloc(8); } };
  check("a signature of the wrong length is refused",
    await code(pki.x509.sign(rootSpec(e.spki), { key: short })) === "x509/bad-input");

  var notBytes = { algorithm: { name: "Ed25519" }, publicKey: e.spki, sign: function () { return "a signature"; } };
  check("a signer that returns something other than bytes is refused",
    await code(pki.x509.sign(rootSpec(e.spki), { key: notBytes })) === "x509/bad-input");

  var throws = { algorithm: { name: "Ed25519" }, publicKey: e.spki, sign: function () { throw new RangeError("the token is locked"); } };
  check("a signer that throws is reported as this domain's input refusal",
    await code(pki.x509.sign(rootSpec(e.spki), { key: throws })) === "x509/bad-input");

  var rejects = { algorithm: { name: "Ed25519" }, publicKey: e.spki, sign: function () { return Promise.reject(new RangeError("the token is locked")); } };
  check("a signer whose promise rejects is reported the same way",
    await code(pki.x509.sign(rootSpec(e.spki), { key: rejects })) === "x509/bad-input");
}

// ---- the caller's object is read once ------------------------------------
async function testCallerObjectIsReadOnce() {
  var e = await ed25519Signer();

  // A signature the signer keeps a handle on and mutates after returning it.
  var mutable = Buffer.alloc(64);
  var mutating = {
    algorithm: { name: "Ed25519" },
    publicKey: e.spki,
    sign: async function (bytes) {
      var raw = Buffer.from(await subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes));
      raw.copy(mutable);
      return mutable;
    },
  };
  var der = await pki.x509.sign(rootSpec(e.spki), { key: mutating });
  mutable.fill(0);
  check("a signature mutated after the signer returned it does not change the certificate",
    pki.schema.x509.parse(der).signatureValue.bytes.some(function (byte) { return byte !== 0; }));

  // An algorithm that answers correctly once and then lies.
  var reads = 0;
  var shifting = {
    publicKey: e.spki,
    get algorithm() {
      reads += 1;
      return reads === 1 ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256" };
    },
    sign: function (bytes) { return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes); },
  };
  var verdict = await code(pki.x509.sign(rootSpec(e.spki), { key: shifting }));
  check("an algorithm that answers differently on a second read cannot split the check from the use (" + verdict + ")",
    verdict === "NO-THROW" || verdict === "x509/bad-input");
  check("and the door read it exactly once (" + reads + ")", reads === 1);

  // The bytes handed to the callback are a copy. A callback that rewrites them rewrites its own
  // copy, so the artifact still carries, and is verified against, what the verb built.
  var rewriting = {
    algorithm: { name: "Ed25519" },
    publicKey: e.spki,
    sign: function (bytes) {
      var at = Buffer.from(bytes).indexOf("good.example");
      if (at !== -1) Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).write("evil.example", at);
      return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes);
    },
  };
  var csr = await code(pki.csr.sign({ subject: "CN=good.example", subjectPublicKey: e.spki }, { key: rewriting }));
  if (csr === "NO-THROW") {
    var built = await pki.csr.sign({ subject: "CN=good.example", subjectPublicKey: e.spki }, { key: rewriting });
    check("a callback that rewrites the bytes it was handed does not rewrite the artifact",
      pki.schema.csr.parse(built).subject.dn.indexOf("good.example") !== -1);
  } else {
    check("a callback that rewrites the bytes it was handed does not rewrite the artifact (" + csr + ")",
      csr === "csr/bad-input");
  }

  // The copy the callback is handed is an allocation of its own: reaching its backing buffer does
  // not reach the bytes the artifact is built from, which a pooled copy would.
  var reachable = null;
  var probing = {
    algorithm: { name: "Ed25519" },
    publicKey: e.spki,
    sign: function (bytes) {
      reachable = Buffer.from(bytes.buffer).length;
      return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes);
    },
  };
  await pki.csr.sign({ subject: "CN=good.example", subjectPublicKey: e.spki }, { key: probing });
  check("the copy handed to the callback has a backing buffer of its own (" + reachable + ")",
    reachable !== null && reachable <= 4096);

  // Plain configuration read off `this` answers. A client or a counter is held in the callback's
  // closure, because the verb snapshots its options and the signer object arrives as a copy.
  var closureCalls = 0;
  var withState = {
    algorithm: { name: "Ed25519" },
    publicKey: e.spki,
    keyId: "kms://key/1",
    sign: function (bytes) {
      if (this.keyId !== "kms://key/1") throw new Error("configuration on the signer did not answer");
      closureCalls += 1;
      return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes);
    },
  };
  check("a signer reads its own configuration off the object it declared",
    await code(pki.x509.sign(rootSpec(e.spki), { key: withState })) === "NO-THROW");
  check("and state the callback keeps in its closure reaches the caller", closureCalls === 1);

  // An ECDSA key names only its curve, so the digest a signer declares is checked on its own.
  var pWrongHash = await p256Signer();
  var wrongHash = {
    algorithm: { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-512" } },
    publicKey: pWrongHash.spki,
    calls: 0,
    sign: function (bytes) { wrongHash.calls += 1; return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pWrongHash.pair.privateKey, bytes); },
  };
  check("a signer that declares a digest the scheme does not sign under is refused",
    await code(pki.x509.sign(rootSpec(pWrongHash.spki), { key: wrongHash })) === "x509/bad-input");
  check("and it is refused before the signer is asked to sign", wrongHash.calls === 0);

  // A nested field of the declared algorithm is read once too: the hash a scheme checks is the
  // hash that signs, and a getter cannot make those two different answers.
  var p = await p256Signer();
  var hashReads = 0;
  var alg = {
    name: "ECDSA",
    namedCurve: "P-256",
    get hash() { hashReads += 1; return hashReads === 1 ? { name: "SHA-256" } : { name: "SHA-512" }; },
  };
  var nested = {
    algorithm: alg,
    publicKey: p.spki,
    sign: function (bytes) { return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, p.pair.privateKey, bytes); },
  };
  var nestedVerdict = await code(pki.x509.sign(rootSpec(p.spki), { key: nested }));
  check("a nested algorithm field that answers differently on a second read cannot split the check from the use (" + nestedVerdict + ")",
    nestedVerdict === "NO-THROW" || nestedVerdict === "x509/bad-input");
  check("and the door read the nested field at most once (" + hashReads + ")", hashReads <= 1);

  // One level deeper: the name inside the declared hash is a caller field too.
  var nameReads = 0;
  var pDeep = await p256Signer();
  var deep = {
    algorithm: {
      name: "ECDSA", namedCurve: "P-256",
      hash: { get name() { nameReads += 1; return nameReads === 1 ? "SHA-256" : "SHA-512"; } },
    },
    publicKey: pDeep.spki,
    sign: function (bytes) { return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pDeep.pair.privateKey, bytes); },
  };
  var deepVerdict = await code(pki.x509.sign(rootSpec(pDeep.spki), { key: deep }));
  check("a hash name that answers differently on a second read cannot split the check from the use (" + deepVerdict + ")",
    deepVerdict === "NO-THROW" || deepVerdict === "x509/bad-input");
  check("and the door read the hash name at most once (" + nameReads + ")", nameReads <= 1);

  var signReads = 0;
  var shiftingSign = {
    algorithm: { name: "Ed25519" },
    publicKey: e.spki,
    get sign() {
      signReads += 1;
      if (signReads === 1) return function (bytes) { return subtle.sign({ name: "Ed25519" }, e.pair.privateKey, bytes); };
      return function () { return Buffer.alloc(64); };
    },
  };
  await code(pki.x509.sign(rootSpec(e.spki), { key: shiftingSign }));
  check("and the sign callback is read exactly once (" + signReads + ")", signReads === 1);
}

// ---- the shapes the form does not cover ----------------------------------
async function testFormsTheSeamRefuses() {
  var e = await ed25519Signer();
  var noPublicKey = { algorithm: { name: "Ed25519" }, sign: function () { return Buffer.alloc(64); } };
  check("a signer with no publicKey is refused",
    await code(pki.x509.sign(rootSpec(e.spki), { key: noPublicKey })) === "x509/bad-input");
  var noAlgorithm = { publicKey: e.spki, sign: function () { return Buffer.alloc(64); } };
  check("a signer with no algorithm is refused",
    await code(pki.x509.sign(rootSpec(e.spki), { key: noAlgorithm })) === "x509/bad-input");

  // The certificate-free CMS form names its key by SPKI rather than by certificate, so it names
  // the key a signer's publicKey is held to just as a certificate does.
  check("a signer signs the certificate-free CMS form, which names its key by SPKI",
    await code(pki.cms.sign(Buffer.from("content"), {
      spki: e.spki, keyIdentifier: Buffer.from([1, 2, 3, 4]), key: e.signer,
    })) === "NO-THROW");
}

// ---- every verb that takes a key takes the form ---------------------------
async function testEverySigningVerbTakesTheForm() {
  var e = await ed25519Signer();
  var caCert = await pki.x509.sign(rootSpec(e.spki), { key: e.pair.privateKey });

  var leafPair = await pki.key.generate("Ed25519");
  var leafSpki = await pki.key.export(leafPair.publicKey);

  // Each verb has to ASK the signer, not merely accept the object: a verb that quietly took a
  // different path would otherwise pass by not throwing.
  var refused = [], silent = [];
  async function drive(name, run) {
    var before = e.signer.calls;
    try { await run(); } catch (err) { refused.push(name + ": " + ((err && err.code) || (err && err.message))); return; }
    if (e.signer.calls === before) silent.push(name);
  }

  await drive("x509.sign", async function () {
    await pki.x509.sign({
      subject: "CN=Leaf", subjectPublicKey: leafSpki, notBefore: NOT_BEFORE, notAfter: NOT_AFTER,
    }, { key: e.signer, cert: caCert });
  });
  await drive("crl.sign", async function () {
    await pki.crl.sign({ thisUpdate: NOT_BEFORE, nextUpdate: NOT_AFTER, revoked: [] }, { key: e.signer, cert: caCert });
  });
  await drive("csr.sign", async function () {
    await pki.csr.sign({ subject: "CN=Requester", subjectPublicKey: e.spki }, { key: e.signer });
  });
  await drive("cms.sign", async function () {
    await pki.cms.sign(Buffer.from("content"), { key: e.signer, cert: caCert });
  });
  await drive("ocsp.sign", async function () {
    await pki.ocsp.sign({
      responses: [{ cert: caCert, issuer: caCert, status: "good", thisUpdate: NOT_BEFORE }],
    }, { key: e.signer, cert: caCert });
  });
  await drive("cmp.build", async function () {
    var csrDer = await pki.csr.sign({ subject: "client", subjectPublicKey: leafSpki }, { key: leafPair.privateKey });
    await pki.cmp.build({
      header: { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" } },
      body: { p10cr: csrDer },
    }, { key: e.signer, cert: caCert });
  });
  await drive("crmf.build", async function () {
    await pki.crmf.build({ certReqId: 0, certTemplate: { subject: "device-42", publicKey: e.spki } }, { key: e.signer });
  });
  await drive("ocsp.buildRequest", async function () {
    await pki.ocsp.buildRequest({ cert: caCert, issuer: caCert }, { signer: { key: e.signer, cert: caCert } });
  });
  await drive("attrcert.sign", async function () {
    await pki.attrcert.sign({
      holder: { entityName: { directoryName: "CN=Alice" } },
      notBeforeTime: NOT_BEFORE, notAfterTime: NOT_AFTER,
      attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } },
    }, { cert: caCert, key: e.signer });
  });
  // RFC 3161 sec. 2.3 requires the TSA certificate to assert the timeStamping EKU and nothing else,
  // so the timestamp runs under a certificate minted for the same key rather than the CA's own.
  var tsaCert = await pki.x509.sign({
    subject: "CN=External Signer TSA", subjectPublicKey: e.spki, serialNumber: 20260921n,
    notBefore: NOT_BEFORE, notAfter: NOT_AFTER,
    extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true },
  }, { key: e.pair.privateKey, cert: caCert });
  await drive("tsp.sign", async function () {
    var imprint = { hashAlgorithm: "sha256", hashedMessage: Buffer.from(await subtle.digest("SHA-256", Buffer.from("hello"))) };
    await pki.tsp.sign(imprint, { cert: tsaCert, key: e.signer }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
  });

  check("every signing verb drives the signer form (" + refused.join("; ") + ")", refused.length === 0);
  check("and each of them asked the signer for the signature (" + silent.join("; ") + ")", silent.length === 0);
}

// ---- a signature that does not verify is refused, on every verb -----------
async function testABadSignatureIsRefusedEverywhere() {
  var e = await ed25519Signer();
  var caCert = await pki.x509.sign(rootSpec(e.spki), { key: e.pair.privateKey });
  var other = await pki.key.generate("Ed25519");

  // Well-formed, correct length, produced by a different key: only a self-check
  // against the declared public key catches it.
  var wrongKey = {
    algorithm: { name: "Ed25519" },
    publicKey: e.spki,
    sign: function (bytes) { return subtle.sign({ name: "Ed25519" }, other.privateKey, bytes); },
  };

  var accepted = [];
  async function mustRefuse(name, run) {
    var verdict = await code(run());
    if (verdict === "NO-THROW") accepted.push(name);
  }
  await mustRefuse("x509.sign", function () {
    return pki.x509.sign({ subject: "CN=Leaf", subjectPublicKey: e.spki, notBefore: NOT_BEFORE, notAfter: NOT_AFTER },
      { key: wrongKey, cert: caCert });
  });
  await mustRefuse("crl.sign", function () {
    return pki.crl.sign({ thisUpdate: NOT_BEFORE, nextUpdate: NOT_AFTER, revoked: [] }, { key: wrongKey, cert: caCert });
  });
  await mustRefuse("csr.sign", function () {
    return pki.csr.sign({ subject: "CN=Requester", subjectPublicKey: e.spki }, { key: wrongKey });
  });
  await mustRefuse("cms.sign", function () {
    return pki.cms.sign(Buffer.from("content"), { key: wrongKey, cert: caCert });
  });
  await mustRefuse("ocsp.sign", function () {
    return pki.ocsp.sign({ responses: [{ cert: caCert, issuer: caCert, status: "good", thisUpdate: NOT_BEFORE }] },
      { key: wrongKey, cert: caCert });
  });
  check("a signature that does not verify is refused by every signing verb (" + accepted.join("; ") + ")",
    accepted.length === 0);
}

async function run() {
  await testSignerSignsACertificate();
  await testDeclaredAlgorithmIsChecked();
  await testDeclaredPublicKeyIsChecked();
  await testReturnedSignatureIsHeldToTheContract();
  await testCallerObjectIsReadOnce();
  await testFormsTheSeamRefuses();
  await testEverySigningVerbTakesTheForm();
  await testABadSignatureIsRefusedEverywhere();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
