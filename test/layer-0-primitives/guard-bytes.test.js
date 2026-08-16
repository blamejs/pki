// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-bytes: the detached-byte-input door, and the SHIPPED verbs that must
 * route through it.
 *
 * Transferring an ArrayBuffer away (structuredClone with `transfer`, a worker hand-off,
 * a stream that adopts the buffer) leaves every view of it reading ZERO-LENGTH instead of
 * throwing. A boundary that accepts the caller's bytes and hands the object straight on
 * therefore operates on NOTHING and succeeds: a CMS signature over no content, a key
 * identifier of no bytes, a MAC key derived from no password. The result is a
 * well-formed, verifiable artifact that covers none of what the caller passed.
 *
 * So the first half of this file pins the guard's own contract, and the second half
 * drives the shipped consumer verbs -- pki.cms.*, pki.x509.sign, pki.crl.sign,
 * pki.ocsp.buildRequest, pki.pkcs12.build -- with a detached input and asserts a typed
 * refusal in the calling module's own domain. The guard contract alone would not show
 * that those verbs still CALL it.
 *
 * The two halves of the second set are not equally strong, and the difference is worth
 * knowing when reading a failure. Neutering the guard leaves some of these vectors green:
 * an empty certificate does not parse and an empty private key does not import, so those
 * doors were already closed and what these vectors add is that the refusal keeps the
 * module's OWN typed code instead of whatever the downstream failure happened to raise.
 * The vectors that go red without the guard are the ones that were open: content handed
 * to cms.sign / cms.compress and the PKCS#12 password, where an empty read produced a
 * signed, verifiable, correctly-encoded artifact covering nothing.
 */

var guardBytes = require("../../lib/guard-bytes");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var detachedBuffer = helpers.detachedBuffer;
var detachedUint8 = helpers.detachedUint8;

// withCause: the guard threads the raw detach failure as the cause, so a class without it
// would turn the typed reject into a bare TypeError from the error path itself.
var TestError = errors.defineClass("TestError", { withCause: true });
function factoryE(code, message, cause) { return new TestError(code, message, cause); }

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e && e.code; } }
// A verb documented `-> Promise<...>` must REJECT, never throw: a synchronous throw goes straight
// past the caller's `.catch` and nothing in the shape of the call warns them. So this calls the
// verb OUTSIDE any try, proving the call itself returns a promise, and only then awaits it. A
// plain `try { await fn() }` cannot tell the two apart, which is how the copy added for the
// time-of-check window silently became a synchronous throw at every producing verb.
async function rejectsWith(label, fn, code) {
  var p, threw = null;
  try { p = fn(); } catch (err) { threw = err; }
  check(label + " returns a promise rather than throwing", threw === null && !!p && typeof p.then === "function");
  if (threw) { check(label + " -> " + code, threw.code === code); return; }
  var e = null;
  try { await p; } catch (err) { e = err; }
  check(label + " is refused", e !== null);
  check(label + " -> " + code, e && e.code === code);
}

// ---- the guard's own contract ----------------------------------------------

function testViewContract() {
  var live = Buffer.from([1, 2, 3]);
  var v = guardBytes.view(live, TestError, "t/bad", "input");
  check("view returns the same bytes", Buffer.compare(v, live) === 0);
  // A view, not a copy: writing through it reaches the caller's memory, which is what makes
  // it safe to call before a size ceiling has been applied (nothing is materialized).
  v[0] = 0x9;
  check("view aliases the caller's memory", live[0] === 0x9);

  check("view refuses a detached Buffer", codeOf(function () {
    guardBytes.view(detachedBuffer(4), TestError, "t/bad", "input");
  }) === "t/bad");
  check("view refuses a detached Uint8Array", codeOf(function () {
    guardBytes.view(detachedUint8(4), TestError, "t/bad", "input");
  }) === "t/bad");
  check("view refuses a non-byte input", codeOf(function () {
    guardBytes.view("0011", TestError, "t/bad", "input");
  }) === "t/bad");

  // snapshot is the same door plus a private copy -- the parse-then-verify TOCTOU defence.
  var src = Buffer.from([7, 7, 7]);
  var snap = guardBytes.snapshot(src, TestError, "t/bad", "input");
  src[0] = 0x1;
  check("snapshot does NOT alias the caller's memory", snap[0] === 7);
  check("snapshot refuses a detached Buffer", codeOf(function () {
    guardBytes.snapshot(detachedBuffer(4), TestError, "t/bad", "input");
  }) === "t/bad");

  // source / snapshotSource take the wider W3C BufferSource contract.
  var ab = new ArrayBuffer(3);
  check("source accepts a raw ArrayBuffer", guardBytes.source(ab, TestError, "t/bad", "input").length === 3);
  check("source refuses a detached ArrayBuffer", codeOf(function () {
    var gone = new ArrayBuffer(3);
    structuredClone(gone, { transfer: [gone] });
    guardBytes.source(gone, TestError, "t/bad", "input");
  }) === "t/bad");
  check("snapshotSource refuses a detached view", codeOf(function () {
    guardBytes.snapshotSource(detachedUint8(4), TestError, "t/bad", "input");
  }) === "t/bad");
}

// snapshotDeep copies a whole caller-supplied spec. Where that spec holds a SECRET, the copy is a
// second plaintext credential, and a module whose rule is "a caller's Buffer is borrowed, leave it
// alone" will not clear it. `collect` is how the copies stay accountable: the caller of the guard
// gets every buffer it made and clears them itself.
async function testDeepSnapshotContract() {
  var src = { pw: Buffer.from("secret"), nested: { der: Buffer.from([1, 2, 3]) }, n: 7n, s: "x" };
  var made = [];
  var copy = guardBytes.snapshotDeep(src, TestError, "t/bad", "spec", { collect: made });
  check("snapshotDeep copies every byte leaf", made.length === 2);
  check("snapshotDeep copies are not the originals", made.indexOf(src.pw) === -1);
  check("snapshotDeep preserves the values", Buffer.compare(copy.pw, Buffer.from("secret")) === 0);
  check("snapshotDeep preserves a bigint by value", copy.n === 7n);
  src.pw.fill(0x41);
  check("the copy does not follow the caller's later write", Buffer.compare(copy.pw, Buffer.from("secret")) === 0);

  var dates = guardBytes.snapshotDeep({ d: new Date(5) }, TestError, "t/bad", "spec");
  check("snapshotDeep copies a Date by value", dates.d.getTime() === 5);

  // The KIND of a byte value survives the copy. Each verb's field validators decide which byte
  // forms that field takes -- most accept only Buffer / Uint8Array -- so a copy that normalized
  // everything to Buffer would widen every one of those doors at once, silently accepting a
  // DataView or a Uint16Array reinterpreted through the platform's element layout.
  var kinds = guardBytes.snapshotDeep({
    buf: Buffer.from([1, 2]), u8: new Uint8Array([3, 4]), u16: new Uint16Array([5, 6]),
    dv: new DataView(new ArrayBuffer(4)), ab: new ArrayBuffer(4),
  }, TestError, "t/bad", "spec");
  check("a Buffer copies as a Buffer", Buffer.isBuffer(kinds.buf));
  check("a Uint8Array copies as a Uint8Array, not a Buffer",
    kinds.u8 instanceof Uint8Array && !Buffer.isBuffer(kinds.u8));
  check("a Uint16Array copies as a Uint16Array with its values",
    kinds.u16 instanceof Uint16Array && kinds.u16[0] === 5 && kinds.u16[1] === 6);
  check("a DataView copies as a DataView", kinds.dv instanceof DataView);
  check("an ArrayBuffer copies as an ArrayBuffer", kinds.ab instanceof ArrayBuffer);

  // The clone is the object every later check reads, so its SHAPE has to survive too. A
  // null-prototype dictionary must not come back inheriting from Object.prototype, and a key
  // literally named `__proto__` must stay an own property rather than re-pointing the clone --
  // otherwise an unknown-option check walks a different object than the verb goes on to read.
  var bare = Object.create(null);
  bare.a = 1;
  var bareCopy = guardBytes.snapshotDeep(bare, TestError, "t/bad", "spec");
  check("a null-prototype object keeps its null prototype", Object.getPrototypeOf(bareCopy) === null);
  check("a null-prototype object keeps its fields", bareCopy.a === 1);

  var protoKey = JSON.parse("{\"__proto__\": {\"polluted\": true}, \"real\": 1}");
  var protoCopy = guardBytes.snapshotDeep(protoKey, TestError, "t/bad", "spec");
  check("a literal __proto__ key stays an own property",
    Object.prototype.hasOwnProperty.call(protoCopy, "__proto__"));
  check("a literal __proto__ key does not re-point the clone",
    Object.getPrototypeOf(protoCopy) === Object.prototype);
  check("the clone's own keys match the source's", Object.keys(protoCopy).sort().join(",") === "__proto__,real");

  // What separates a HANDLE from a data bag is not the prototype. A caller's own class used as an
  // options object is data, and passing it through on the strength of its prototype left the whole
  // window open for it: pki.cms.sign takes any non-Buffer object as options, so an instance whose
  // signedAttributes flipped after the call still reached the signing turn. It is copied, with its
  // prototype kept so its methods still resolve.
  function Bag() { this.v = 1; }
  Bag.prototype.describe = function () { return "bag " + this.v; };
  var bag = new Bag();
  var bagCopy = guardBytes.snapshotDeep({ h: bag }, TestError, "t/bad", "spec").h;
  check("a class instance carrying data is copied, not aliased", bagCopy !== bag);
  check("the copy keeps its prototype and its methods", bagCopy instanceof Bag && bagCopy.describe() === "bag 1");
  bag.v = 99;
  check("the copy does not follow a later write to the instance", bagCopy.v === 1);

  // An INHERITED field is data the verb reads too -- `opts.signedAttributes` resolves through the
  // prototype chain. Copying own keys and keeping the caller's prototype would leave it live, so
  // the inherited value is copied as an own property, shadowing it.
  var base = { signedAttributes: true };
  var inheriting = Object.create(base);
  var inheritedCopy = guardBytes.snapshotDeep(inheriting, TestError, "t/bad", "spec");
  check("an inherited field is copied as an own property",
    Object.prototype.hasOwnProperty.call(inheritedCopy, "signedAttributes"));
  base.signedAttributes = false;
  check("the copy does not follow a later write to the prototype", inheritedCopy.signedAttributes === true);

  // And a NON-ENUMERABLE one. `opts.signedAttributes` resolves the same either way, so the set that
  // has to be copied is the set a name lookup can reach -- not the set `for...in` reports. Each
  // narrower rule in turn left the caller's object reachable behind a copy that looked complete.
  var hiddenProto = Object.defineProperty({}, "signedAttributes", { value: true, writable: true });
  var hiddenCopy = guardBytes.snapshotDeep(Object.create(hiddenProto), TestError, "t/bad", "spec");
  hiddenProto.signedAttributes = false;
  check("a non-enumerable inherited field is copied too", hiddenCopy.signedAttributes === true);
  check("and copying it does not make it enumerable",
    Object.keys(hiddenCopy).indexOf("signedAttributes") === -1);

  // Reading a caller's property runs a caller's accessor. One that throws is a bad input like any
  // other, and comes out with this boundary's code rather than as itself.
  var trap = {};
  Object.defineProperty(trap, "boom", { enumerable: true, get: function () { throw new RangeError("no"); } });
  check("a throwing accessor becomes the boundary's typed fault",
    codeOf(function () { guardBytes.snapshotDeep(trap, TestError, "t/bad", "spec"); }) === "t/bad");

  // isCryptoKeyLike is structural by design, so it can recognize another implementation's key --
  // and structural means an options bag can wear the shape. A key is a key AND nothing else; a bag
  // carrying its own fields alongside is data, and passing it through would leave those fields the
  // caller's to rewrite.
  var keyShapedBag = { signedAttributes: true, type: "private", extractable: true,
    algorithm: { name: "bogus" }, usages: [] };
  var bagOut = guardBytes.snapshotDeep({ o: keyShapedBag }, TestError, "t/bad", "spec").o;
  check("a CryptoKey-shaped options bag is copied, not passed through", bagOut !== keyShapedBag);
  check("and keeps its values", bagOut.signedAttributes === true && bagOut.type === "private");

  // An array can carry named properties, and `opts.pem` reads the same whatever the type is.
  var arrOpts = [1, 2];
  arrOpts.pem = true;
  var arrCopy = guardBytes.snapshotDeep(arrOpts, TestError, "t/bad", "spec");
  check("an array copies its elements", Array.isArray(arrCopy) && arrCopy.length === 2 && arrCopy[1] === 2);
  check("an array copies its named properties too", arrCopy.pem === true);

  // A key handle is passed through: its meaning is not in its own properties, and a copy of one
  // cannot sign. This engine's own CryptoKey carries its key handle as an own property, so a rule
  // like "no own keys means a handle" would have copied it into a shell -- the toolkit's own
  // isCryptoKeyLike is what answers this, the same predicate key.js and jose.js ask.
  var ck = await require("node:crypto").webcrypto.subtle.importKey(
    "pkcs8", signing.makeSigner("ec-p256").key, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  check("a CryptoKey passes through by reference",
    guardBytes.snapshotDeep({ k: ck }, TestError, "t/bad", "spec").k === ck);
  // The same for the things whose state is not in their properties either.
  var live = { m: new Map([["a", 1]]), s: new Set([1]), re: /x/, err: new Error("e") };
  var liveCopy = guardBytes.snapshotDeep(live, TestError, "t/bad", "spec");
  check("a Map / Set / RegExp / Error passes through by reference",
    liveCopy.m === live.m && liveCopy.s === live.s && liveCopy.re === live.re && liveCopy.err === live.err);

  check("snapshotDeep refuses a detached leaf", codeOf(function () {
    guardBytes.snapshotDeep({ b: detachedBuffer(4) }, TestError, "t/bad", "spec");
  }) === "t/bad");
  check("snapshotDeep bounds a cyclic structure", codeOf(function () {
    var cyc = {}; cyc.self = cyc;
    guardBytes.snapshotDeep(cyc, TestError, "t/bad", "spec");
  }) === "t/bad");

  // fixArguments is the whole rule in one call: copy every argument, hand back the copies, and
  // give the caller a release that clears everything it copied. Both halves matter -- the copy
  // closes the window, the release stops the copy of a secret from outliving the call.
  var pw = Buffer.from("hunter2");
  var fixed = guardBytes.fixArguments(TestError, "t/bad", [
    [{ mac: { secret: pw } }, "opts"], [Buffer.from("content"), "content"],
  ]);
  var seenSecret = fixed.values[0].mac.secret;
  check("fixArguments copies a secret nested below the top level", seenSecret !== pw);
  check("fixArguments preserves its value", Buffer.compare(seenSecret, Buffer.from("hunter2")) === 0);
  pw.fill(0x41);
  check("the copy does not follow the caller's write", Buffer.compare(seenSecret, Buffer.from("hunter2")) === 0);
  fixed.release();
  check("release clears the copy it made", seenSecret.every(function (byte) { return byte === 0; }));
  check("release leaves the caller's own buffer alone", Buffer.compare(pw, Buffer.alloc(7, 0x41)) === 0);

  // The copying can fail PARTWAY -- a detached leaf in a later argument, a getter that throws --
  // and by then earlier arguments have already been copied. `fixArguments` clears those before it
  // rethrows, because it returns no handle on that path and nothing else could reach them.
  //
  // What is checkable from outside is the shape of that path: the fault comes out typed and
  // unchanged, and the caller's own buffers are left alone. The copies themselves are internal and
  // unreachable by construction, which is the point -- the same `release` closure the success path
  // uses is what runs, and the vector above pins that release clears what `collect` holds. A
  // vector claiming to observe the wipe here would be asserting on something it cannot see.
  var earlySecret = Buffer.from("first-secret");
  var threw = null;
  try {
    guardBytes.fixArguments(TestError, "t/bad", [
      [{ pw: earlySecret }, "first"], [{ bad: detachedBuffer(4) }, "second"],
    ]);
  } catch (e) { threw = e; }
  check("a fault partway through copying comes out typed", threw !== null && threw.code === "t/bad");
  check("the caller's own buffer is untouched by that path",
    Buffer.compare(earlySecret, Buffer.from("first-secret")) === 0);
}

// The guard family threads a caller's typed error under two conventions -- a CLASS
// (`new E(code, msg)`) and a FACTORY (`E(code, msg)`, no `new`). guard-bytes accepts either,
// so a boundary holding only one of the two can still reach the guard instead of hand-rolling
// the re-view. Passing a factory as if it were a class would throw a raw TypeError from the
// error path itself, which is how a fail-closed check turns into an untyped crash.
function testEitherErrorConvention() {
  check("a factory E yields the typed error, not a TypeError", codeOf(function () {
    guardBytes.view(detachedBuffer(2), factoryE, "t/factory", "input");
  }) === "t/factory");
  var thrown = null;
  try { guardBytes.view("nope", factoryE, "t/factory", "input"); } catch (e) { thrown = e; }
  check("a factory E yields the caller's error class", thrown instanceof TestError);
  check("a class E still yields the caller's error class",
    codeOf(function () { guardBytes.view("nope", TestError, "t/class", "input"); }) === "t/class");
}

// ---- the shipped verbs -----------------------------------------------------

async function testCmsDoors() {
  var s = signing.makeSigner("ec-p256");
  var CONTENT = Buffer.from("the content the caller believes is being signed");

  await rejectsWith("cms.sign over a detached Buffer",
    function () { return pki.cms.sign(detachedBuffer(CONTENT), { cert: s.cert, key: s.key }); },
    "cms/bad-input");
  await rejectsWith("cms.sign over a detached Uint8Array",
    function () { return pki.cms.sign(detachedUint8(CONTENT), { cert: s.cert, key: s.key }); },
    "cms/bad-input");

  // The byte forms this verb does NOT document stay refused. Copying the arguments at entry must
  // not widen that: a Uint16Array or a DataView reaching the encoder would carry whatever bytes the
  // platform's element layout produced, under a signature that says nothing about which layout.
  await rejectsWith("cms.sign over a Uint16Array",
    function () { return pki.cms.sign(new Uint16Array([1, 2, 3]), { cert: s.cert, key: s.key }); },
    "cms/bad-input");
  await rejectsWith("cms.sign over a DataView",
    function () { return pki.cms.sign(new DataView(new ArrayBuffer(8)), { cert: s.cert, key: s.key }); },
    "cms/bad-input");
  await rejectsWith("cms.sign over a raw ArrayBuffer",
    function () { return pki.cms.sign(new ArrayBuffer(8), { cert: s.cert, key: s.key }); },
    "cms/bad-input");
  check("cms.sign still accepts the byte forms it documents",
    Buffer.isBuffer(await pki.cms.sign(new Uint8Array([1, 2, 3]), { cert: s.cert, key: s.key })));
  await rejectsWith("cms.sign with a detached signer certificate",
    function () { return pki.cms.sign(CONTENT, { cert: detachedBuffer(s.cert), key: s.key }); },
    "cms/bad-input");
  await rejectsWith("cms.sign with a detached private key",
    function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: detachedBuffer(s.key) }); },
    "cms/bad-input");

  // Detached content on the DETACHED-signature path too: the preimage arrives through
  // opts.content there, a different door from the eContent one above.
  var detachedSig = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key, detached: true });
  await rejectsWith("cms.verify with detached opts.content",
    function () { return pki.cms.verify(detachedSig, { certs: [s.cert], content: detachedBuffer(CONTENT) }); },
    "cms/bad-input");
  await rejectsWith("cms.verify over a detached message",
    function () { return pki.cms.verify(detachedBuffer(32), { certs: [s.cert] }); },
    "cms/bad-input");

  await rejectsWith("cms.countersign over a detached message",
    function () { return pki.cms.countersign(detachedBuffer(64), { cert: s.cert, key: s.key }); },
    "cms/bad-input");

  await rejectsWith("cms.compress over detached content",
    function () { return pki.cms.compress(detachedBuffer(CONTENT)); }, "cms/bad-input");
  await rejectsWith("cms.decompress over a detached message",
    function () { return pki.cms.decompress(detachedBuffer(32)); }, "cms/bad-input");
  await rejectsWith("cms.encrypt over detached content",
    function () { return pki.cms.encrypt(detachedBuffer(CONTENT), [{ cert: s.cert }]); },
    "cms/bad-input");
  await rejectsWith("cms.encrypt to a detached recipient certificate",
    function () { return pki.cms.encrypt(CONTENT, [{ cert: detachedBuffer(s.cert) }]); },
    "cms/bad-input");
  await rejectsWith("cms.authenticate over detached content",
    function () {
      return pki.cms.authenticate(detachedBuffer(CONTENT),
        { key: Buffer.alloc(32, 1), kekId: Buffer.alloc(4) });
    }, "cms/bad-input");
  await rejectsWith("cms.decrypt over a detached message",
    function () { return pki.cms.decrypt(detachedBuffer(32), { key: s.key, cert: s.cert }); },
    "cms/bad-input");
}

async function testIssuanceDoors() {
  var s = signing.makeSigner("ec-p256");
  var SPEC = {
    subject: "detached-input", serialNumber: 1n,
    notBefore: new Date(0), notAfter: new Date(1e12), subjectPublicKey: s.spki,
  };
  // The spec must ISSUE when nothing is detached -- otherwise every refusal below could be the
  // spec being wrong rather than the input being detached, which is how a vector passes for a
  // reason it does not name.
  check("the issuance spec is valid as written", Buffer.isBuffer(await pki.x509.sign(SPEC, { key: s.key })));

  await rejectsWith("x509.sign with a detached subjectKeyIdentifier",
    function () {
      return pki.x509.sign(Object.assign({}, SPEC, {
        extensions: { subjectKeyIdentifier: detachedBuffer(20) },
      }), { key: s.key });
    }, "x509/bad-input");
  await rejectsWith("x509.sign with a detached authorityKeyIdentifier",
    function () {
      return pki.x509.sign(Object.assign({}, SPEC, {
        extensions: { authorityKeyIdentifier: detachedBuffer(20) },
      }), { key: s.key });
    }, "x509/bad-input");
  await rejectsWith("x509.sign with a detached signing key",
    function () { return pki.x509.sign(SPEC, { key: detachedBuffer(s.key) }); }, "x509/bad-input");

  // A structure nested past the copy's depth cap is the other way the copy itself can fail. It
  // must arrive as a rejection too, not as a throw from a call the caller wrapped in .catch.
  var deep = {};
  var cursor = deep;
  for (var d = 0; d < 200; d++) { cursor.next = {}; cursor = cursor.next; }
  await rejectsWith("x509.sign with a spec nested past the copy's depth cap",
    function () { return pki.x509.sign(Object.assign({}, SPEC, { extensions: deep }), { key: s.key }); },
    "x509/bad-input");

  await rejectsWith("crl.sign with a detached authorityKeyIdentifier",
    function () {
      return pki.crl.sign({
        thisUpdate: new Date(0), nextUpdate: new Date(1e12), revoked: [],
        extensions: { authorityKeyIdentifier: detachedBuffer(20) },
      }, { name: "Detached CRL Issuer", publicKey: s.spki, key: s.key });
    }, "crl/bad-input");
}

async function testOcspAndPkcs12Doors() {
  var s = signing.makeSigner("ec-p256");

  await rejectsWith("ocsp.buildRequest over a detached target certificate",
    function () { return pki.ocsp.buildRequest({ cert: detachedBuffer(s.cert), issuer: s.cert }); },
    "ocsp/bad-input");
  await rejectsWith("ocsp.buildRequest over a detached issuer certificate",
    function () { return pki.ocsp.buildRequest({ cert: s.cert, issuer: detachedBuffer(s.cert) }); },
    "ocsp/bad-input");

  // The password is the input whose empty read is worst: PKCS#12 would derive a MAC key and an
  // encryption key from the EMPTY password and emit a file that opens with no password at all.
  await rejectsWith("pkcs12.build with a detached password",
    function () {
      return pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] },
        { password: detachedBuffer(8) });
    }, "pkcs12/bad-input");
  await rejectsWith("pkcs12.build with a detached per-bag encryption password",
    function () {
      return pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key,
        encrypt: { password: detachedBuffer(8) } }] }] }, { password: "1234" });
    }, "pkcs12/bad-input");

  // Copying the password to close the mid-derivation window must not leave the caller's own
  // credential cleared, and must not change which password opens the store. The copy this module
  // made is cleared inside the verb; the caller's is theirs.
  var callerPw = Buffer.from("s3cr3t-p4ss");
  var store = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] },
    { password: callerPw });
  check("pkcs12.build leaves the caller's password buffer intact",
    Buffer.compare(callerPw, Buffer.from("s3cr3t-p4ss")) === 0);
  check("the store opens with the password that was passed",
    (await pki.pkcs12.verifyMac(store, Buffer.from("s3cr3t-p4ss"))) === true);
  check("the store does not open with a different password",
    (await pki.pkcs12.verifyMac(store, Buffer.from("wrong-pass"))) === false);

  // A secret nested BELOW the top level of an options object is the case a one-level copy misses:
  // `opts.mac.secret` is read by the PBMAC1 derivation after the first turn, so a shallow copy
  // leaves the MAC keyed to whatever the caller wrote afterwards rather than what they passed.
  var csrDer = await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: s.spki }, s.key);
  var message = {
    header: { sender: { directoryName: [{ commonName: "c" }] }, recipient: { directoryName: [{ commonName: "srv" }] } },
    body: { p10cr: csrDer },
  };
  // An options object with a prototype of its own is still a caller's data. pki.cms.sign accepts
  // any non-Buffer object there, so leaving that shape aliased reopened the whole window for it:
  // signedAttributes flipped from true to false after the call would skip the attribute-shaped-
  // content refusal and sign the content directly.
  var attrShaped = pki.asn1.build.set([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("contentType")),
      pki.asn1.build.set([pki.asn1.build.oid("1.2.840.113549.1.7.1")])]),
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("messageDigest")),
      pki.asn1.build.set([pki.asn1.build.octetString(Buffer.alloc(32))])]),
  ].sort(Buffer.compare));
  function SignOpts() { this.signedAttributes = true; }
  var protoOpts = new SignOpts();
  var signingWithProtoOpts = pki.cms.sign(attrShaped, { cert: s.cert, key: s.key }, protoOpts);
  protoOpts.signedAttributes = false;
  var protoSigned = pki.schema.cms.parse(await signingWithProtoOpts);
  check("cms.sign honours a custom-prototype options object as it was at entry",
    !!protoSigned.signerInfos[0].signedAttrsBytes);
  await rejectsWith("cms.sign over attribute-shaped content with signedAttributes false",
    function () { return pki.cms.sign(attrShaped, { cert: s.cert, key: s.key }, { signedAttributes: false }); },
    "cms/ambiguous-content");

  // The same through an INHERITED option. `opts.signedAttributes` resolves up the prototype chain,
  // so a copy that kept the caller's prototype would still be reading the caller's object.
  var optsProto = { signedAttributes: true };
  var inheritedOpts = Object.create(optsProto);
  var signingWithInherited = pki.cms.sign(attrShaped, { cert: s.cert, key: s.key }, inheritedOpts);
  optsProto.signedAttributes = false;
  var inheritedSigned = pki.schema.cms.parse(await signingWithInherited);
  check("cms.sign honours an inherited option as it was at entry",
    !!inheritedSigned.signerInfos[0].signedAttrsBytes);

  var macOpts = { mac: { secret: Buffer.from("hunter2"), salt: Buffer.alloc(16, 9), iterationCount: 2048 } };
  check("the PBMAC1 premise holds without any mutation",
    (await pki.cmp.verify(await pki.cmp.build(message, macOpts), { sharedSecret: Buffer.from("hunter2") })).valid === true);

  var liveSecret = Buffer.from("hunter2");
  var building = pki.cmp.build(message,
    { mac: { secret: liveSecret, salt: Buffer.alloc(16, 9), iterationCount: 2048 } });
  liveSecret.fill(0);
  var macDer = await building;
  check("cmp.build MACs under the nested secret as it was at entry",
    (await pki.cmp.verify(macDer, { sharedSecret: Buffer.from("hunter2") })).valid === true);
  check("cmp.build did not adopt the secret written after the call",
    (await pki.cmp.verify(macDer, { sharedSecret: Buffer.alloc(7) })).valid === false);
}

// A door that re-VIEWS instead of copying leaves the caller's memory live under the value it
// just checked, so mutating it after the call changes what the verb goes on to use. That is the
// same time-of-check/time-of-use window a detached buffer opens, reached from the other side,
// and it is the one a mechanical "route this through the guard" edit reintroduces: `view` and
// `snapshot` differ by exactly this and nothing else at the call site.
async function testCallerCannotRewriteAfterEntry() {
  var s = signing.makeSigner("ec-p256");

  // cms.sign: the content is signed a promise turn after it is inspected.
  var live = Buffer.from("the bytes the caller passed to cms.sign");
  var signing1 = pki.cms.sign(live, { cert: s.cert, key: s.key });
  live.fill(0x41);                                   // rewritten while the signature is in flight
  var der = await signing1;
  var parsed = pki.schema.cms.parse(der);
  check("cms.sign signs the content as it was at entry, not as rewritten",
    Buffer.compare(Buffer.from(parsed.encapContentInfo.eContent),
      Buffer.from("the bytes the caller passed to cms.sign")) === 0);
  var verdict = await pki.cms.verify(der, { certs: [s.cert] });
  check("the signature over that content still verifies", verdict.valid === true);

  // x509.sign: a key identifier is encoded into the certificate after the same kind of gap.
  var keyId = Buffer.alloc(20, 0xab);
  var issuing = pki.x509.sign({
    subject: "rewrite-after-entry", serialNumber: 2n,
    notBefore: new Date(0), notAfter: new Date(1e12), subjectPublicKey: s.spki,
    extensions: { subjectKeyIdentifier: keyId },
  }, { key: s.key });
  keyId.fill(0xcd);
  var cert = pki.schema.x509.parse(await issuing);
  var ski = (cert.extensions || []).filter(function (e) { return e.name === "subjectKeyIdentifier"; })[0];
  check("x509.sign embeds the key id as it was at entry",
    !!ski && Buffer.compare(pki.asn1.read.octetString(pki.asn1.decode(ski.value)),
      Buffer.alloc(20, 0xab)) === 0);

  // The OPTIONS object is a caller-owned argument too, and its fields are read at the very END of
  // the verb -- `opts.pem` decides the returned encoding after the signature comes back. Fixing the
  // spec and leaving opts mutable closes the half of the window that is easiest to see.
  var certOpts = { pem: false };
  var pending = pki.x509.sign({
    subject: "opts-after-entry", serialNumber: 3n,
    notBefore: new Date(0), notAfter: new Date(1e12), subjectPublicKey: s.spki,
  }, { key: s.key }, certOpts);
  certOpts.pem = true;
  check("x509.sign returns the encoding opts asked for at entry", Buffer.isBuffer(await pending));

  var crlOpts = { pem: false };
  var pendingCrl = pki.crl.sign({ thisUpdate: new Date(0), nextUpdate: new Date(1e12), revoked: [] },
    { name: "opts-after-entry CRL", publicKey: s.spki, key: s.key }, crlOpts);
  crlOpts.pem = true;
  check("crl.sign returns the encoding opts asked for at entry", Buffer.isBuffer(await pendingCrl));

  // Re-pointing the signer object's key after the call must not change who signed. The signer is
  // copied one level, so the field cannot be swapped even though the key material stays borrowed.
  var other = signing.makeSigner("ec-p256", { cn: "someone-else", serial: 0x77 });
  var issuer = { key: s.key };
  var pendingIssuer = pki.x509.sign({
    subject: "issuer-after-entry", serialNumber: 4n,
    notBefore: new Date(0), notAfter: new Date(1e12), subjectPublicKey: s.spki,
  }, issuer);
  issuer.key = other.key;
  var issuedDer = await pendingIssuer;
  // The certificate is self-signed and carries s.spki, so validating it against ITSELF as the
  // anchor checks the signature with the key it names. It holds only if the entry key made that
  // signature; a signature by the key swapped in afterwards would not verify under s.spki.
  function selfValid(der) {
    var c = pki.schema.x509.parse(der);
    return pki.path.validate([c], {
      time: new Date(1000),
      trustAnchor: { name: c.subject, publicKey: c.subjectPublicKeyInfo.bytes, algorithm: c.subjectPublicKeyInfo.algorithm },
    }).then(function (r) { return r.valid; }, function () { return false; });
  }
  check("the self-validation premise holds for an unswapped certificate",
    (await selfValid(await pki.x509.sign({
      subject: "issuer-baseline", serialNumber: 5n, notBefore: new Date(0), notAfter: new Date(1e12),
      subjectPublicKey: s.spki,
    }, { key: s.key }))) === true);
  check("x509.sign signs with the key the signer named at entry", (await selfValid(issuedDer)) === true);
}

async function run() {
  testViewContract();
  await testDeepSnapshotContract();
  testEitherErrorConvention();
  await testCmsDoors();
  await testIssuanceDoors();
  await testOcspAndPkcs12Doors();
  await testCallerCannotRewriteAfterEntry();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
