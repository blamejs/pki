// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the operations a signature verdict rests on are taken once, when the package loads, so a
 * replacement installed afterwards reaches none of them.
 *
 * Each of these is an ordinary writable property of a module object or a prototype, read at the moment
 * of the call before this gate existed. A replacement of any one of them decides a verdict the caller
 * asked a cryptographic question to get: the verifier itself, the signer, the key the verifier is
 * handed, the SubtleCrypto method the certificate path calls, and the constant-time comparison a MAC
 * rests on. Every vector drives a shipped verb, installs the replacement while the call is in flight
 * with a control proving it is live, and asserts the toolkit answers from the operations it captured.
 *
 * This states the rule once for the whole set, rather than in the suite of whichever module happens to
 * notice a particular one.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = require("../helpers/signing").makeSigner;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");
var AT = new Date("2027-01-01T00:00:00Z");

// Replace a property on `host` for the duration of `fn`, restoring it however `fn` ends.
async function withReplaced(host, name, value, fn) {
  var real = host[name], hadOwn = Object.prototype.hasOwnProperty.call(host, name);
  var desc = hadOwn ? Object.getOwnPropertyDescriptor(host, name) : null;
  Object.defineProperty(host, name, { value: value, writable: true, configurable: true });
  try { return await fn(); }
  finally {
    if (desc) Object.defineProperty(host, name, desc);
    else { try { delete host[name]; } catch (_de) { host[name] = real; } }
  }
}

// ---- the native verifier ----
async function testNativeVerifierIsCaptured() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "captured.example", subjectPublicKey: s.spki }, { key: s.key });
  var tampered = Buffer.from(der);
  tampered[tampered.length - 1] ^= 0x01;
  // CONTROL: the altered request is refused with nothing replaced, which is the verdict to preserve.
  var clean = await pki.csr.verify(tampered);
  check("CONTROL the altered request is refused", clean.valid === false);
  var live, verdict;
  await withReplaced(crypto, "verify", function () { return true; }, async function () {
    live = crypto.verify(null, Buffer.from("x"), s.spki, Buffer.alloc(64)) === true;
    verdict = await pki.csr.verify(tampered);
  });
  check("a replaced crypto.verify is live during the probe", live === true);
  check("and it cannot make a tampered request verify (" + (verdict && verdict.valid) + ")",
    !!verdict && verdict.valid === false);
}

// ---- the native signer ----
async function testNativeSignerIsCaptured() {
  var s = makeSigner("ed25519");
  var live, der = null, thrown = null;
  await withReplaced(crypto, "sign", function () { return Buffer.alloc(64, 0x7a); }, async function () {
    live = crypto.sign(null, Buffer.from("x"), s.keyObject)[0] === 0x7a;
    try { der = await pki.csr.sign({ subject: "captured.example", subjectPublicKey: s.spki }, { key: s.key }); }
    catch (e) { thrown = (e && e.code) || e.name; }
  });
  check("a replaced crypto.sign is live during the probe", live === true);
  var v = der === null ? null : await pki.csr.verify(der);
  check("and it cannot decide the signature a request carries (" + (thrown || "signed") + ")",
    thrown === null && v !== null && v.valid === true);
}

// ---- the key the verifier is handed ----
async function testKeyImportIsCaptured() {
  var a = makeSigner("ec-p256"), b = makeSigner("ec-p256");
  // CONTROL: the two keys really are different, which is what the probe must preserve.
  check("CONTROL two independently generated P-256 keys have different public halves",
    Buffer.compare(Buffer.from(a.spki), Buffer.from(b.spki)) !== 0);
  var live, derived;
  await withReplaced(crypto, "createPublicKey", function () { return a.keyObject; }, async function () {
    live = crypto.createPublicKey({ key: b.spki, format: "der", type: "spki" }) === a.keyObject;
    derived = await pki.key.publicFromPrivate(b.key);
  });
  check("a replaced crypto.createPublicKey is live during the probe", live === true);
  check("and it cannot substitute the public key derived from a private one",
    Buffer.isBuffer(derived) && Buffer.compare(derived, Buffer.from(b.spki)) === 0);
}

// ---- the SubtleCrypto methods a certification path calls ----
async function buildPath() {
  var rootKey = makeSigner("ed25519");
  var rootDer = await pki.x509.sign({
    serialNumber: 1n, subject: "Captured Root", subjectPublicKey: rootKey.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: rootKey.key });
  var leafKey = makeSigner("ed25519");
  var leaf = await pki.x509.sign({
    serialNumber: 42n, subject: "leaf.captured.example", subjectPublicKey: leafKey.spki, notBefore: NB, notAfter: NA,
  }, { key: rootKey.key, cert: rootDer });
  return { anchor: pki.path.anchorFromCert(rootDer), leaf: leaf, leafKey: leafKey, rootKey: rootKey };
}

async function testSubtleVerifyIsCaptured() {
  var p = await buildPath();
  /* A leaf whose signature bytes are altered. The path refuses it, and must go on refusing it while a
     replaced SubtleCrypto `verify` answers true for everything. */
  var tampered = Buffer.from(p.leaf);
  tampered[tampered.length - 1] ^= 0x01;
  check("CONTROL the altered leaf is refused with the signature verdict",
    (await pki.path.validate([tampered], { time: AT, trustAnchors: p.anchor })).valid === false);
  var proto = Object.getPrototypeOf(pki.webcrypto.subtle);
  var live, underReplaced;
  await withReplaced(proto, "verify", async function () { return true; }, async function () {
    live = (await pki.webcrypto.subtle.verify({ name: "Ed25519" }, null, Buffer.alloc(0), Buffer.alloc(0))) === true;
    underReplaced = await pki.path.validate([tampered], { time: AT, trustAnchors: p.anchor });
  });
  check("a replaced SubtleCrypto verify is live during the probe", live === true);
  check("and it cannot make an altered certificate validate (" + (underReplaced && underReplaced.valid) + ")",
    !!underReplaced && underReplaced.valid === false);
}

async function testSubtleSignIsCaptured() {
  var s = makeSigner("ed25519");
  var proto = Object.getPrototypeOf(pki.webcrypto.subtle);
  var live, der = null, thrown = null;
  await withReplaced(proto, "sign", async function () { return new Uint8Array(64).buffer; }, async function () {
    var got = await pki.webcrypto.subtle.sign({ name: "Ed25519" }, null, Buffer.alloc(0));
    live = new Uint8Array(got).every(function (b) { return b === 0; });
    try { der = await pki.csr.sign({ subject: "subtlesign.example", subjectPublicKey: s.spki }, { key: s.key }); }
    catch (e) { thrown = (e && e.code) || e.name; }
  });
  check("a replaced SubtleCrypto sign is live during the probe", live === true);
  var v = der === null ? null : await pki.csr.verify(der);
  check("and it cannot decide the signature a signed structure carries (" + (thrown || "signed") + ")",
    thrown === null && v !== null && v.valid === true);
}

// ---- the key-material export ----
/* A verifier checks against the key it is handed, and a key IDENTITY is a digest over the key's
   exported material, so the export decides both. Reached off the key's own prototype it is
   replaceable: one returning a fixed value gave two distinct authorized TUF keys the same material
   identifier, which took a two-key threshold down to one signature. */
async function testKeyExportIsCaptured() {
  var s = makeSigner("ec-p256");
  var real = pki.key;   // keep the namespace reachable while the prototype is replaced
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var proto = Object.getPrototypeOf(pair.publicKey);
  var fixed = Buffer.alloc(16, 0x7a);
  var live, derived;
  await withReplaced(proto, "export", function () { return fixed; }, async function () {
    live = pair.publicKey.export({ format: "der", type: "spki" }) === fixed;
    derived = await real.publicFromPrivate(s.key);
  });
  check("a replaced key export is live during the probe", live === true);
  check("and it cannot decide the public key derived from a private one",
    Buffer.isBuffer(derived) && Buffer.compare(derived, Buffer.from(s.spki)) === 0);
}

/* The same question one layer up: the exporter that reads a CryptoKey's material. The key-pair probe
   imports and signs with what it returns, so a replacement exporting a different private key makes a
   mismatched pair report as corresponding. */
async function testCryptoKeyExporterIsCaptured() {
  var kp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var spki = await pki.key.export(kp.publicKey);
  var other = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var otherPkcs8 = await pki.key.export(other.privateKey);
  var webcryptoModule = require("../../lib/webcrypto");
  var live, derived;
  await withReplaced(webcryptoModule, "exportAnyKey", async function () { return Buffer.from(otherPkcs8); },
    async function () {
      live = Buffer.compare(Buffer.from(await webcryptoModule.exportAnyKey(kp.privateKey, function (c, m) { return new Error(c + m); }, "x")),
        Buffer.from(otherPkcs8)) === 0;
      derived = await pki.key.publicFromPrivate(kp.privateKey);
    });
  check("a replaced CryptoKey exporter is live during the probe", live === true);
  check("and it cannot substitute the private key a public half is derived from",
    Buffer.isBuffer(derived) && Buffer.compare(derived, Buffer.from(spki)) === 0);
}

// ---- the digest a key identifier is ----
/* A transparency-log key identifier is a digest over the key's name, a separator, an algorithm byte
   and the key. It is what matches a signature line to a caller's key, so a replaced hash `update`
   changed those four bytes and a note the key really did sign reported `verified: false`. */
async function testKeyIdentifierDigestIsCaptured() {
  var kp = await pki.key.generate("Ed25519");
  var spki = await pki.key.export(kp.publicKey);
  var raw = pki.asn1.read.bitString(pki.asn1.decode(spki).children[1]).bytes;
  var name = "captured.example/log";
  var realId = pki.tlog.keyId(name, raw);
  var text = name + "\n5\n" + Buffer.alloc(32, 0x11).toString("base64") + "\n";
  var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, Buffer.from(text, "utf8")));
  var note = text + "\n" + String.fromCharCode(0x2014) + " " + name + " " +
    Buffer.concat([realId, sig]).toString("base64") + "\n";
  var hashProto = Object.getPrototypeOf(crypto.createHash("sha256"));
  var live, underReplaced, verdict;
  await withReplaced(hashProto, "update", function () { return this; }, async function () {
    live = crypto.createHash("sha256").update(Buffer.from("abc")).digest()
      .equals(crypto.createHash("sha256").update(Buffer.from("def")).digest());
    underReplaced = pki.tlog.keyId(name, raw);
    verdict = await pki.tlog.verifyNote(note, [{ name: name, publicKey: raw }]);
  });
  check("a replaced hash update is live during the probe, so a chained digest covers nothing",
    live === true);
  check("and it cannot change the key identifier a signature line is matched on",
    Buffer.compare(underReplaced, realId) === 0);
  check("so a note the key signed still verifies (" + (verdict && verdict.verified) + ")",
    !!verdict && verdict.verified === true && verdict.signers.length === 1);
}

// ---- the accessors a view's extent is read through ----
/* A WebCrypto verb returns an ArrayBuffer, so the signature it produced is converted from a view on
   the way out. `buffer`, `byteOffset` and `byteLength` are getters on the TypedArray prototype, so a
   replacement of any of them decides which bytes the conversion copies: measured, it turned a valid
   64-byte Ed25519 signature into 64 zero bytes. The conversion reads them through accessors captured
   at load. */
async function testViewExtentAccessorsAreCaptured() {
  var kp = await pki.key.generate("Ed25519");
  var msg = Buffer.from("bytes the caller asked to sign", "utf8");
  var proto = Object.getPrototypeOf(Uint8Array.prototype);
  var realBuffer = Object.getOwnPropertyDescriptor(proto, "buffer");
  var realOffset = Object.getOwnPropertyDescriptor(proto, "byteOffset");
  var naiveWrong, produced;
  try {
    Object.defineProperty(proto, "buffer", { configurable: true, get: function () { return new ArrayBuffer(4096); } });
    Object.defineProperty(proto, "byteOffset", { configurable: true, get: function () { return 0; } });
    // CONTROL, inside the window: the ordinary spelling of the conversion now copies other bytes.
    var marked = Buffer.alloc(8, 0x5a);
    var naive = new Uint8Array(ArrayBuffer.prototype.slice.call(marked.buffer, marked.byteOffset, marked.byteOffset + 8));
    naiveWrong = naive.every(function (b) { return b === 0; });
    produced = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, msg));
  } finally {
    Object.defineProperty(proto, "buffer", realBuffer);
    Object.defineProperty(proto, "byteOffset", realOffset);
  }
  check("CONTROL the replaced view accessors are live, so the ordinary conversion copies other bytes",
    naiveWrong === true);
  check("and they cannot change the signature bytes a WebCrypto verb returns",
    produced.length === 64 &&
    (await pki.webcrypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, produced, msg)) === true);
}

// ---- the promise constructor a verdict is handed back through ----
/* `Promise.resolve` builds its promise from the receiver it is called on, so reading the global
   binding at the call hands that construction to whatever the binding holds. A descriptor failure
   answering `false` through a constructor that answers true is not a refusal. The constructor is
   captured at load; `Promise.prototype.then` is a different matter, and `await` calls it. */
async function testPromiseConstructorIsCaptured() {
  var p = await buildPath();
  var tampered = Buffer.from(p.leaf);
  tampered[tampered.length - 1] ^= 0x01;
  check("CONTROL the altered leaf is refused with nothing replaced",
    (await pki.path.validate([tampered], { time: AT, trustAnchors: p.anchor })).valid === false);
  var realPromise = globalThis.Promise;
  var hostile = class extends realPromise {
    static resolve(v) { void v; return realPromise.resolve(true); }
    static reject(e) { void e; return realPromise.resolve(true); }
  };
  var live, underReplaced, threw = null;
  try {
    globalThis.Promise = hostile;
    live = (await Promise.resolve(false)) === true;
    underReplaced = await pki.path.validate([tampered], { time: AT, trustAnchors: p.anchor });
  } catch (e) { threw = (e && e.code) || String(e); } finally { globalThis.Promise = realPromise; }
  check("a replaced global Promise is live during the probe, answering true for resolve(false)",
    live === true);
  check("and it cannot turn an altered certificate into a valid path (" +
    (threw || (underReplaced && underReplaced.valid)) + ")",
  threw === null && !!underReplaced && underReplaced.valid === false);
}

// ---- the promise a signing verb awaits its own self-check through ----
/* Every signing verb checks its own output before it emits it, and awaits that check through a
   promise. `Promise.resolve` builds from the RECEIVER it is called on, so reading the global binding
   at the call hands the construction to whatever that binding holds: a constructor whose `resolve`
   settles without awaiting its argument runs the continuation before the check has finished, and the
   verb emits what it was about to refuse. On the composite arm the check genuinely returns a promise,
   from `assertSignatureVerifies` in lib/pki-build.js, so a dropped rejection is the whole verdict.

   The instrument COUNTS reads of the global rather than forcing a self-check to fail, because a verb
   whose check passes emits the same bytes either way: what separates a captured construction from a
   live one is whether the global was read at all. Replacing the binding does not disturb `async` or
   `await`, which take the realm's intrinsic rather than this property, so a count of zero means the
   verb built every promise from the constructor it captured. */
async function testSigningVerbsBuildThroughTheCapturedPromise() {
  var ca = makeSigner("ec-p256");
  var caCert = await pki.x509.sign({
    subject: "Captured CA", subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: ca.key });
  var ee = makeSigner("ec-p256");
  var csrDer = await pki.csr.sign({ subject: "captured.example", subjectPublicKey: ee.spki }, { key: ee.key });

  var realPromise = globalThis.Promise;
  function countingFor(counter) {
    function Counting(executor) { return new realPromise(executor); }
    Counting.prototype = realPromise.prototype;
    Counting.resolve = function (v) { counter.n += 1; return realPromise.resolve(v); };
    Counting.reject = function (e) { counter.n += 1; return realPromise.reject(e); };
    // Every static counts. Counting only `resolve` and `reject` left the aggregators invisible: a verb
    // that reached the global for `all` reported zero, which is how the composite-verdict and
    // proof-of-possession aggregators stayed live under a passing instrument.
    Counting.all = function (a) { counter.n += 1; return realPromise.all(a); };
    Counting.allSettled = function (a) { counter.n += 1; return realPromise.allSettled(a); };
    Counting.race = function (a) { counter.n += 1; return realPromise.race(a); };
    Counting.any = function (a) { counter.n += 1; return realPromise.any(a); };
    return Counting;
  }

  // CONTROL: the counter really counts, so a zero below is the verb and not a dead instrument.
  // Both shapes are controlled: a resolve-only control cannot tell a silent aggregator from a clean one.
  var ctl = { n: 0 };
  try { globalThis.Promise = countingFor(ctl); await Promise.resolve(1); }
  finally { globalThis.Promise = realPromise; }
  check("CONTROL the read counter registers an explicit Promise.resolve", ctl.n === 1);

  var ctlAll = { n: 0 };
  try { globalThis.Promise = countingFor(ctlAll); await Promise.all([1, 2]); }
  finally { globalThis.Promise = realPromise; }
  check("CONTROL the read counter registers an explicit Promise.all", ctlAll.n === 1);

  var verbs = [
    ["pki.x509.sign", function () {
      return pki.x509.sign({ subject: "leaf.example", subjectPublicKey: ee.spki, notBefore: NB, notAfter: NA,
        extensions: { keyUsage: ["digitalSignature"] } }, { cert: caCert, key: ca.key });
    }],
    ["pki.csr.sign", function () {
      return pki.csr.sign({ subject: "captured.example", subjectPublicKey: ee.spki }, { key: ee.key });
    }],
    ["pki.csr.verify", function () { return pki.csr.verify(csrDer); }],
    ["pki.crl.sign", function () {
      return pki.crl.sign({ thisUpdate: AT, nextUpdate: NA, crlNumber: 1n,
        revoked: [{ serialNumber: 7n, revocationDate: AT }] }, { cert: caCert, key: ca.key });
    }],
  ];

  var live = [];
  for (var i = 0; i < verbs.length; i++) {
    var counter = { n: 0 }, failed = null;
    try {
      globalThis.Promise = countingFor(counter);
      await verbs[i][1]();
    } catch (e) { failed = (e && e.code) || String(e && e.message).slice(0, 60); }
    finally { globalThis.Promise = realPromise; }
    if (failed !== null) live.push(verbs[i][0] + " threw " + failed);
    else if (counter.n !== 0) live.push(verbs[i][0] + " read the global " + counter.n + " time(s)");
  }
  check("every signing verb builds its self-check promise from the captured constructor (" +
    (live.length ? live.join("; ") : "none read it") + ")", live.length === 0);
}

// ---- the aggregator that assembles a verdict out of component results ----
/* A verdict assembled with `Promise.all` is worth only what the constructor awaiting the components is
   worth. Read off the live global, a replacement that resolves a fabricated array never runs the
   component verifications and its own values become the verdict: `pki.crmf.verifyPop` reports an
   unverified proof of possession as verified, and the composite arm reports `ok` for a signature whose
   ML-DSA and traditional halves were never checked. A counter alone does not show this, so the
   substitute here fabricates a marked result and the assertion looks for the marker in the verdict. */
async function testVerdictAggregatorsBuildThroughTheCapturedPromise() {
  var s = makeSigner("ec-p256");
  var req = await pki.crmf.build({
    certReqId: 1n,
    certTemplate: { subject: "aggregate.example", publicKey: s.spki },
  }, { key: s.key });

  var realPromise = globalThis.Promise;
  function fabricating() {
    function Fabricating(executor) { return new realPromise(executor); }
    Fabricating.prototype = realPromise.prototype;
    Fabricating.resolve = function (v) { return realPromise.resolve(v); };
    Fabricating.reject = function (e) { return realPromise.reject(e); };
    Fabricating.all = function () {
      return realPromise.resolve([{ verified: true, ok: true, method: "FABRICATED" }]);
    };
    Fabricating.allSettled = function () {
      return realPromise.resolve([{ status: "fulfilled", value: { verified: true, method: "FABRICATED" } }]);
    };
    Fabricating.race = function (a) { return realPromise.race(a); };
    Fabricating.any = function (a) { return realPromise.any(a); };
    return Fabricating;
  }

  // CONTROL: the substitute really does replace the result a caller reading the global receives.
  var ctl;
  try {
    globalThis.Promise = fabricating();
    ctl = await Promise.all([realPromise.resolve({ verified: false, method: "real" })]);
  } finally { globalThis.Promise = realPromise; }
  check("CONTROL the fabricating substitute replaces an explicit Promise.all result",
    !!ctl && !!ctl[0] && ctl[0].method === "FABRICATED");

  var verdict = null, failed = null;
  try {
    globalThis.Promise = fabricating();
    verdict = await pki.crmf.verifyPop(req);
  } catch (e) { failed = (e && e.code) || String((e && e.message) || e).slice(0, 70); }
  finally { globalThis.Promise = realPromise; }

  var first = (verdict && verdict.messages && verdict.messages[0]) || null;
  var fabricated = !!first && first.method === "FABRICATED";
  check("pki.crmf.verifyPop assembles its verdict through the captured constructor, so no fabricated " +
    "component result reaches it (" +
    (failed !== null ? "threw " + failed : fabricated ? "FABRICATED reached the verdict"
      : "method=" + (first && first.method)) + ")",
    failed === null && !fabricated);
}

// ---- the captured promise statics themselves ----
/* The six promise statics are captured as a set, because a member with no captured form is a member
   that stays live: the detector holds every one of them to zero in lib/, so a call site that needs one
   has to have it. This pins each capture to the operation it was bound to at load, under a global whose
   own statics throw, so a capture that secretly re-read the binding fails rather than silently
   degrading. */
async function testCapturedPromiseStaticsSurviveAReplacedGlobal() {
  var intrinsic = require("../../lib/guard-intrinsic");
  var realPromise = globalThis.Promise;

  function hostile() {
    function Hostile(executor) { return new realPromise(executor); }
    Hostile.prototype = realPromise.prototype;
    ["resolve", "reject", "all", "allSettled", "race", "any"].forEach(function (k) {
      Hostile[k] = function () { throw new Error("hostile " + k + " reached"); };
    });
    return Hostile;
  }

  // CONTROL: the hostile global really does break a caller that reads the binding at the call.
  var controlThrew = false;
  try {
    globalThis.Promise = hostile();
    try { Promise.resolve(1); } catch (e) { controlThrew = /hostile resolve/.test(String(e.message)); }
  } finally { globalThis.Promise = realPromise; }
  check("CONTROL a hostile global breaks a call-time read of Promise.resolve", controlThrew);

  var P = intrinsic.Promise;
  var ops = [
    ["promiseResolve", function (f) { return f(P, 7); }, function (v) { return v === 7; }],
    ["promiseAll", function (f) { return f(P, [1, 2]); }, function (v) { return v[0] === 1 && v[1] === 2; }],
    ["promiseAllSettled", function (f) { return f(P, [realPromise.resolve(1)]); },
      function (v) { return v[0].status === "fulfilled" && v[0].value === 1; }],
    ["promiseRace", function (f) { return f(P, [realPromise.resolve("first")]); },
      function (v) { return v === "first"; }],
    ["promiseAny", function (f) { return f(P, [realPromise.resolve("one")]); },
      function (v) { return v === "one"; }],
    ["promiseTry", function (f) { return f(P, function () { return "ran"; }); },
      function (v) { return v === "ran"; }],
    ["promiseWithResolvers", function (f) {
      var d = f(P);
      d.resolve("settled");
      return d.promise;
    }, function (v) { return v === "settled"; }],
  ];

  var broken = [];
  for (var i = 0; i < ops.length; i++) {
    var name = ops[i][0], fn = intrinsic.uncurry(intrinsic[name]), got, failed = null;
    try {
      globalThis.Promise = hostile();
      got = await ops[i][1](fn);
    } catch (e) { failed = String((e && e.message) || e).slice(0, 60); }
    finally { globalThis.Promise = realPromise; }
    if (failed !== null) broken.push(name + " threw " + failed);
    else if (!ops[i][2](got)) broken.push(name + " returned " + JSON.stringify(got));
  }
  check("every captured promise static answers from its load-time binding (" +
    (broken.length ? broken.join("; ") : "all " + ops.length) + ")", broken.length === 0);

  // `reject` is the refusal carrier, so it is asserted to still REJECT rather than to resolve.
  var rejected = null;
  try {
    globalThis.Promise = hostile();
    var rj = intrinsic.uncurry(intrinsic.promiseReject);
    await rj(P, new Error("refused")).then(
      function () { rejected = false; }, function (e) { rejected = /refused/.test(String(e.message)); });
  } catch (e) { rejected = "threw " + String(e && e.message).slice(0, 50); }
  finally { globalThis.Promise = realPromise; }
  check("the captured promiseReject still rejects under a hostile global (" + rejected + ")",
    rejected === true);
}

// ---- the digest a TUF key identifier is ----
/* A TUF role names its signers by key identifier, and the identifier is a digest over the key object.
   Reached off the live hash prototype, a replacement decided that binding: a different Ed25519 key
   filed under an authorized key's identifier was accepted, and metadata it signed reported
   `verified: true` where the check otherwise throws `tuf/bad-key`. */
async function testTufKeyIdentifierIsCaptured() {
  var kp = await pki.key.generate("Ed25519");
  var raw = Buffer.from(await pki.webcrypto.subtle.exportKey("raw", kp.publicKey));
  var key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: raw.toString("hex") } };
  var realId = pki.tuf.keyId(key);
  var other = await pki.key.generate("Ed25519");
  var otherRaw = Buffer.from(await pki.webcrypto.subtle.exportKey("raw", other.publicKey));
  var otherKey = { keytype: "ed25519", scheme: "ed25519", keyval: { public: otherRaw.toString("hex") } };
  // CONTROL: the two keys have different identifiers with nothing replaced.
  check("CONTROL two Ed25519 keys carry different TUF identifiers",
    realId !== pki.tuf.keyId(otherKey) && realId.length === 64);
  var hashProto = Object.getPrototypeOf(crypto.createHash("sha256"));
  var live, underReplaced, underReplacedOther;
  await withReplaced(hashProto, "update", function () { return this; }, async function () {
    live = crypto.createHash("sha256").update(Buffer.from("abc")).digest()
      .equals(crypto.createHash("sha256").update(Buffer.from("def")).digest());
    underReplaced = pki.tuf.keyId(key);
    underReplacedOther = pki.tuf.keyId(otherKey);
  });
  check("a replaced hash update is live during the TUF probe", live === true);
  check("and it cannot change the identifier a key is filed under",
    underReplaced === realId && underReplacedOther !== realId);
  // The consumer arm, where the identifier binding decides a verdict, lives beside the metadata
  // fixtures in tuf.test.js (M9a).
}

// ---- the constant-time comparison ----
async function testConstantTimeComparisonIsCaptured() {
  var s = makeSigner("ed25519");
  var pfx = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "right" });
  check("CONTROL the wrong password is refused",
    (await pki.pkcs12.verifyMac(pfx, "wrong")).valid === false);
  var live, underReplaced;
  await withReplaced(crypto, "timingSafeEqual", function () { return true; }, async function () {
    live = crypto.timingSafeEqual(Buffer.from("ab"), Buffer.from("cd")) === true;
    underReplaced = await pki.pkcs12.verifyMac(pfx, "wrong");
  });
  check("a replaced crypto.timingSafeEqual is live during the probe", live === true);
  check("and it cannot turn a wrong password into a matching MAC (" +
    (underReplaced && underReplaced.valid) + ")", !!underReplaced && underReplaced.valid === false);
}

async function run() {
  await testNativeVerifierIsCaptured();
  await testNativeSignerIsCaptured();
  await testKeyImportIsCaptured();
  await testSubtleVerifyIsCaptured();
  await testSubtleSignIsCaptured();
  await testKeyExportIsCaptured();
  await testCryptoKeyExporterIsCaptured();
  await testKeyIdentifierDigestIsCaptured();
  await testViewExtentAccessorsAreCaptured();
  await testPromiseConstructorIsCaptured();
  await testSigningVerbsBuildThroughTheCapturedPromise();
  await testVerdictAggregatorsBuildThroughTheCapturedPromise();
  await testCapturedPromiseStaticsSurviveAReplacedGlobal();
  await testTufKeyIdentifierIsCaptured();
  await testConstantTimeComparisonIsCaptured();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack) || e); process.exit(1); }
  );
}
