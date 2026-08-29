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
var identifier = require("../../lib/guard-identifier");
var vm = require("vm");
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
function errorOf(fn) { try { fn(); return { code: "NO-THROW" }; } catch (e) { return e; } }
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
  // A value built over Uint8Array.prototype inherits the whole interface and holds no bytes. The
  // refusal held before the door read the slot, because the read it would have reached is wrapped
  // and comes back as this code; pinning it keeps that true however the door is written.
  check("view refuses a value that inherits from Uint8Array and holds no bytes", codeOf(function () {
    guardBytes.view(Object.create(Uint8Array.prototype), TestError, "t/bad", "input");
  }) === "t/bad");
  // The same question read the other way round is where a prototype test gives a wrong answer a
  // wrapped read cannot rescue: a real Uint8Array built in another realm holds bytes and inherits
  // from that realm, and the caller was told the bytes they passed were not bytes.
  var foreignBytes = vm.runInNewContext("new Uint8Array([1, 2, 3])");
  check("view accepts a Uint8Array from another realm and reads its bytes",
    guardBytes.view(foreignBytes, TestError, "t/bad", "input").equals(Buffer.from([1, 2, 3])));
  // Where a view's bytes are is asked of the language, never of the view. `buffer`, `byteOffset`
  // and `byteLength` are accessors on the shared typed-array prototype, so a caller's subclass can
  // answer all three. One that lied substituted the memory: an array holding AA AA AA AA whose
  // `buffer` returned another store had these doors hand back that other store's bytes, so the
  // bytes a verb went on to hash or sign were not the bytes in the array it was given.
  var decoyStore = new Uint8Array([0x11, 0x22, 0x33, 0x44]).buffer;
  var LyingBuffer = class extends Uint8Array { get buffer() { return decoyStore; } };
  var LyingBounds = class extends Uint8Array {
    get byteOffset() { return 99; }
    get byteLength() { return 1; }
  };
  var ThrowingBuffer = class extends Uint8Array {
    get buffer() { throw new RangeError("planted"); }
  };
  var own = Buffer.from([0xAA, 0xAA, 0xAA, 0xAA]);
  [["view", guardBytes.view], ["source", guardBytes.source], ["snapshot", guardBytes.snapshot]
  ].forEach(function (door) {
    check(door[0] + " reads a lying `buffer` override's own bytes",
      door[1](new LyingBuffer([0xAA, 0xAA, 0xAA, 0xAA]), TestError, "t/bad", "input").equals(own));
    check(door[0] + " reads a lying bounds override's own bytes",
      door[1](new LyingBounds([0xAA, 0xAA, 0xAA, 0xAA]), TestError, "t/bad", "input").equals(own));
    check(door[0] + " reads past a `buffer` override that throws",
      door[1](new ThrowingBuffer([0xAA, 0xAA, 0xAA, 0xAA]), TestError, "t/bad", "input").equals(own));
  });
  // A view over shared memory is still refused, and an override cannot make ordinary memory read
  // as shared: the store is taken from the slot, so the check answers about the real one.
  check("a view over shared memory is refused", codeOf(function () {
    guardBytes.view(new Uint8Array(new SharedArrayBuffer(4)), TestError, "t/bad", "input");
  }) === "t/bad");
  var ClaimsShared = class extends Uint8Array {
    get buffer() { return new SharedArrayBuffer(4); }
  };
  check("while an override claiming shared memory does not make private memory shared",
    guardBytes.view(new ClaimsShared([0xAA, 0xAA, 0xAA, 0xAA]), TestError, "t/bad", "input").equals(own));
  // The copy keeps a view's kind by reading the value's slot, never `v.constructor` or
  // `v.BYTES_PER_ELEMENT`. Both are ordinary properties a subclass answers: one that threw took
  // the copy out through the caller's own exception, and one that lied built the copy with a
  // different element width and a different kind than the value being copied.
  var HostileCtor = class extends Uint8Array {};
  Object.defineProperty(HostileCtor.prototype, "constructor",
                        { value: function () { throw new RangeError("planted"); }, configurable: true });
  var ctorCopy = guardBytes.snapshotDeep({ b: new HostileCtor([1, 2]) }, TestError, "t/bad", "arg").b;
  check("a copy keeps the kind past a `constructor` that throws",
        ctorCopy instanceof Uint8Array && Array.from(ctorCopy).join(",") === "1,2");
  var HostileWidth = class extends Uint16Array { get BYTES_PER_ELEMENT() { return 1; } };
  var widthCopy = guardBytes.snapshotDeep({ b: new HostileWidth([0x1234, 0x5678]) },
                                          TestError, "t/bad", "arg").b;
  check("and past a `BYTES_PER_ELEMENT` that lies",
        widthCopy instanceof Uint16Array && Array.from(widthCopy).join(",") === "4660,22136");
  // ...while EVERY concrete typed-array kind this runtime has still copies to its own kind and
  // elements. Enumerated from the runtime rather than listed, because a list is complete the day
  // it is written and short afterwards: `Float16Array` landed on Node 24, a list drafted before it
  // refused the kind outright, and a test carrying the same stale list would not have said so.
  var concreteKinds = Object.keys(require("util").types)
    .filter(function (name) { return /^is[A-Za-z0-9]+Array$/.test(name); })
    .map(function (name) { return globalThis[name.slice(2)]; })
    .filter(function (C) { return typeof C === "function" && C.BYTES_PER_ELEMENT > 0; });
  check("the runtime offers a plausible number of typed-array kinds", concreteKinds.length >= 9);
  // The predicates are held as functions taken at load, not looked up by name on every call.
  // `util.types` is an ordinary object, so a name lookup would hand the kind decision -- and the
  // constructor the copy is built from -- to anyone who replaces a predicate on it later.
  var nodeTypes = require("util").types;
  var trueIsUint8 = nodeTypes.isUint8Array;
  var claimsNothing = function () { return false; };
  var kindUnderMutation;
  nodeTypes.isUint8Array = claimsNothing;
  try {
    kindUnderMutation = guardBytes.snapshotDeep({ b: new Uint8Array([1, 2]) },
                                                TestError, "t/bad", "arg").b;
  } finally {
    nodeTypes.isUint8Array = trueIsUint8;
  }
  check("a predicate replaced on util.types after load does not change the copy's kind",
        kindUnderMutation instanceof Uint8Array &&
        Array.from(kindUnderMutation).join(",") === "1,2");
  check("and util.types is left as it was found", nodeTypes.isUint8Array === trueIsUint8);
  concreteKinds.forEach(function (C) {
    var big = /^Big/.test(C.name);
    var src = big ? new C([1n, 2n]) : new C([1, 2]);
    var copy = guardBytes.snapshotDeep({ b: src }, TestError, "t/bad", "arg").b;
    check("a " + C.name + " copies to its own kind and elements",
          Object.getPrototypeOf(copy) === Object.getPrototypeOf(src) &&
          Array.from(copy).join(",") === Array.from(src).join(","));
  });
  // An array index can carry an accessor the same as a named field can. At the argument itself
  // that is refused before it is read, on the same reasoning as a named accessor field: a value
  // that can answer differently between the check and the use is not one the check covered, and
  // refusing it means the caller's code never runs at all.
  var hostileElement = [];
  var elementFault = new RangeError("planted");
  Object.defineProperty(hostileElement, "0",
                        { enumerable: true, get: function () { throw elementFault; } });
  hostileElement.length = 1;
  var elementErr = errorOf(function () {
    guardBytes.snapshotDeep(hostileElement, TestError, "t/bad", "arg");
  });
  check("an array element supplied through an accessor is refused at the argument",
        elementErr.code === "t/bad" && elementErr !== elementFault);
  check("and it is refused without the getter having been run", elementErr.cause === undefined);
  // Below the argument an accessor is read, matching the rule for names: a platform object nested
  // in a spec carries its own, and refusing those turns an ordinary signer into a bad input. A
  // getter that throws there is still typed with this boundary's code rather than escaping as
  // itself, and the caller's own fault is carried as the cause.
  var nestedErr = errorOf(function () {
    guardBytes.snapshotDeep({ list: hostileElement }, TestError, "t/bad", "arg");
  });
  check("a nested array element whose getter throws is refused with this boundary's code",
        nestedErr.code === "t/bad" && nestedErr !== elementFault);
  check("and the caller's own fault is carried as the cause", nestedErr.cause === elementFault);
  // ...while an ordinary array still copies its elements and keeps its holes.
  var sparse = [1, 2, 3];
  sparse[10] = 9;
  var sparseCopy = guardBytes.snapshotDeep(sparse, TestError, "t/bad", "arg");
  check("an ordinary array copies its elements and keeps its holes",
        sparseCopy.length === 11 && sparseCopy[0] === 1 && sparseCopy[10] === 9 &&
        !(3 in sparseCopy));
  // A collection is walked with the intrinsic `forEach`, called against it. `forEach` is an
  // ordinary method a caller can shadow on any instance: one that threw took the copy out through
  // their own exception, and one yielding different entries filled the copy with something other
  // than the collection holds.
  var hostileMap = new Map([["a", 1]]);
  hostileMap.forEach = function () { throw new RangeError("planted"); };
  var mapCopy = guardBytes.snapshotDeep(hostileMap, TestError, "t/bad", "arg");
  check("a Map with its own `forEach` still copies the entries it holds",
        mapCopy.size === 1 && mapCopy.get("a") === 1);
  var hostileSet = new Set([1, 2]);
  hostileSet.forEach = function () { throw new RangeError("planted"); };
  check("as does a Set", guardBytes.snapshotDeep(hostileSet, TestError, "t/bad", "arg").size === 2);
  // The refusal below names the kind from what the value IS. `v.constructor.name` is two property
  // reads a caller answers, and a getter under either took the refusal out through their exception
  // in place of the typed error whose whole job is to say why the value was refused.
  var hostileName = new Error("opaque");
  hostileName.extra = 1;
  Object.defineProperty(hostileName, "constructor",
                        { get: function () { throw new RangeError("planted"); }, configurable: true });
  check("an opaque value whose `constructor` throws is refused with the caller's own code",
        codeOf(function () {
          guardBytes.snapshotDeep(hostileName, TestError, "t/bad", "arg");
        }) === "t/bad");
  // A Date in a copied argument keeps the instant it holds. `getTime` is an ordinary method a
  // subclass answers, so reading it off the value put a different instant in the copy.
  var LyingClock = class extends Date { getTime() { return 0; } };
  check("a copied Date holds the instant the original holds",
        guardBytes.snapshotDeep({ when: new LyingClock(1700000000000) },
                                TestError, "t/bad", "arg").when.valueOf() === 1700000000000);
  // A DataView carries its own accessors rather than the typed-array ones, so both pairs have to
  // be reached; taking only one leaves the other kind read off the value again.
  var dvBytes = new Uint8Array([1, 2, 3, 4]);
  check("source reads a DataView through its own intrinsic accessors",
    guardBytes.source(new DataView(dvBytes.buffer), TestError, "t/bad", "input")
      .equals(Buffer.from([1, 2, 3, 4])));
  // The four forms the toolkit calls bytes, and nothing else. Every door that has to decide
  // whether an argument is bytes asks this, so no door can answer a narrower list than the one
  // that finally reads them.
  check("isByteSource accepts each of the four byte forms",
    guardBytes.isByteSource(Buffer.alloc(1)) && guardBytes.isByteSource(new Uint8Array(1)) &&
    guardBytes.isByteSource(new DataView(new ArrayBuffer(1))) && guardBytes.isByteSource(new ArrayBuffer(1)));
  check("and a real ArrayBuffer from another realm",
    guardBytes.isByteSource(vm.runInNewContext("new ArrayBuffer(4)")) === true);
  check("while a value that only inherits from ArrayBuffer is not one",
    guardBytes.isByteSource(Object.create(ArrayBuffer.prototype)) === false);
  check("and neither is a plain object or a nullish value",
    guardBytes.isByteSource({}) === false && guardBytes.isByteSource(null) === false &&
    guardBytes.isByteSource(undefined) === false);
  // isAsyncIterable is the sibling classifier: a byte STREAM, not a byte source. The two are
  // mutually exclusive -- a verb accepting a streamed content asks this, and a byte source is
  // never diverted to the streaming path.
  var asyncGen = (async function* () { yield Buffer.from([1]); })();
  var asyncIterableObj = {};
  asyncIterableObj[Symbol.asyncIterator] = function () { return { next: function () { return Promise.resolve({ done: true }); } }; };
  check("isAsyncIterable accepts an async generator and a bare Symbol.asyncIterator object",
    guardBytes.isAsyncIterable(asyncGen) === true && guardBytes.isAsyncIterable(asyncIterableObj) === true);
  // A callable that carries a Symbol.asyncIterator method is a valid async iterable `for await`
  // consumes, so it is accepted despite being a function rather than a plain object.
  var callableAsyncIterable = function () {};
  callableAsyncIterable[Symbol.asyncIterator] = async function* () { yield Buffer.from([1]); };
  check("isAsyncIterable accepts a callable that implements the async-iteration protocol",
    guardBytes.isAsyncIterable(callableAsyncIterable) === true);
  check("isAsyncIterable rejects a plain function with no Symbol.asyncIterator",
    guardBytes.isAsyncIterable(function () {}) === false);
  // A byte source is bytes, never a stream, even when a caller has attached a Symbol.asyncIterator:
  // the byte-source classification wins, so a door offering both forms never diverts real bytes.
  var bufWithAsync = Buffer.from([1, 2, 3]);
  bufWithAsync[Symbol.asyncIterator] = async function* () { yield Buffer.from([9]); };
  check("isAsyncIterable treats a byte source with an attached Symbol.asyncIterator as bytes, not a stream",
    guardBytes.isByteSource(bufWithAsync) === true && guardBytes.isAsyncIterable(bufWithAsync) === false);
  check("isAsyncIterable rejects each byte source (never diverts bytes to streaming)",
    guardBytes.isAsyncIterable(Buffer.alloc(1)) === false && guardBytes.isAsyncIterable(new Uint8Array(1)) === false &&
    guardBytes.isAsyncIterable(new DataView(new ArrayBuffer(1))) === false && guardBytes.isAsyncIterable(new ArrayBuffer(1)) === false);
  check("isAsyncIterable rejects a plain object, a sync iterable, and nullish values",
    guardBytes.isAsyncIterable({}) === false && guardBytes.isAsyncIterable([1, 2]) === false &&
    guardBytes.isAsyncIterable(null) === false && guardBytes.isAsyncIterable(undefined) === false);
  // Shared memory holds bytes and cannot hold this module's promise about them, since another
  // thread can rewrite it after the checks have read it. Copying it into a private ArrayBuffer
  // would keep the bytes and change the kind, so it is refused at every door instead, including
  // a view whose backing store is shared while the view itself is an ordinary Uint8Array.
  var shared = new SharedArrayBuffer(4);
  var sharedView = new Uint8Array(shared);
  check("shared memory is not a byte source", guardBytes.isByteSource(shared) === false);
  check("view refuses shared memory", codeOf(function () {
    guardBytes.view(shared, TestError, "t/bad", "input");
  }) === "t/bad");
  check("and a view whose backing store is shared", codeOf(function () {
    guardBytes.view(sharedView, TestError, "t/bad", "input");
  }) === "t/bad");
  check("source refuses shared memory", codeOf(function () {
    guardBytes.source(shared, TestError, "t/bad", "input");
  }) === "t/bad");
  check("snapshotDeep refuses it nested in a spec", codeOf(function () {
    guardBytes.snapshotDeep({ b: shared }, TestError, "t/bad", "spec");
  }) === "t/bad");
  check("and nested as a view over it", codeOf(function () {
    guardBytes.snapshotDeep({ b: sharedView }, TestError, "t/bad", "spec");
  }) === "t/bad");
  check("while an ordinary ArrayBuffer still copies to its own kind",
    guardBytes.snapshotDeep(new ArrayBuffer(4), TestError, "t/bad", "spec") instanceof ArrayBuffer);

  // snapshot is the same door plus a private copy -- the parse-then-verify TOCTOU defense.
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
  // A Date carries named properties like anything else, and a verb reads an option by name
  // whatever the argument's type. Returning the instant alone leaves the copy holding nothing
  // the caller added while the original still answers, and the checks read the copy.
  var stamped = new Date(7);
  stamped.pem = true;
  var stampedCopy = guardBytes.snapshotDeep(stamped, TestError, "t/bad", "spec");
  check("a Date keeps its instant through the copy",
        stampedCopy instanceof Date && stampedCopy.getTime() === 7);
  check("and carries a name the caller added to it", stampedCopy.pem === true);

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
  // signedAttributes flipped after the call still reached the signing turn. It is copied -- as a
  // plain object, because the class is the caller's too. Keeping it left the copy dispatching into
  // their code, and a class can be rewritten after the call has begun, so a copy taken to stop the
  // argument changing under the verb changed with it.
  function Bag() { this.v = 1; }
  Bag.prototype.describe = function () { return "bag " + this.v; };
  var bag = new Bag();
  var bagCopy = guardBytes.snapshotDeep({ h: bag }, TestError, "t/bad", "spec").h;
  check("a class instance carrying data is copied, not aliased", bagCopy !== bag);
  check("the copy is a plain object carrying the data, not an instance of the caller's class",
    !(bagCopy instanceof Bag) && Object.getPrototypeOf(bagCopy) === Object.prototype &&
    bagCopy.v === 1 && bagCopy.describe === undefined);
  bag.v = 99;
  check("the copy does not follow a later write to the instance", bagCopy.v === 1);
  Bag.prototype.describe = function () { throw new RangeError("planted"); };
  check("nor a later rewrite of the class it came from", bagCopy.describe === undefined);
  // A dictionary with no prototype keeps having none. Gaining `Object.prototype` would make the
  // copy inherit whatever a runtime has planted there -- names the original never answered.
  var dict = Object.create(null);
  dict.pem = true;
  var dictCopy = guardBytes.snapshotDeep({ h: dict }, TestError, "t/bad", "spec").h;
  check("a null-prototype dictionary copies to one with no prototype either",
    Object.getPrototypeOf(dictCopy) === null && dictCopy.pem === true);

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
  // Including the read this module makes on its own behalf, when it asks whether the value is a
  // pending result. That question is still a property read of the caller's object.
  function Trapped() {}
  Object.defineProperty(Trapped.prototype, "then", { get: function () { throw new RangeError("no"); } });
  check("a throwing `then` accessor is typed too", codeOf(function () {
    guardBytes.snapshotDeep({ t: new Trapped() }, TestError, "t/bad", "spec");
  }) === "t/bad");

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
  // An index is what the language calls one. `String(Number(k)) === k` also matches "-1", "1.5",
  // "NaN", "Infinity" and "4294967295" (one past the last index), each an ordinary named property
  // on an array: dropping them here loses a field the caller set, and guard-identifier passes
  // over the same names, so the option reaches neither the check nor the verb.
  var oddNames = [];
  ["-1", "1.5", "NaN", "Infinity", "4294967295", "01"].forEach(function (k) { oddNames[k] = "x"; });
  var oddCopy = guardBytes.snapshotDeep(oddNames, TestError, "t/bad", "spec");
  check("a named property that merely looks numeric survives the copy",
    ["-1", "1.5", "NaN", "Infinity", "4294967295", "01"].every(function (k) { return oddCopy[k] === "x"; }));
  var realIdx = [7, 8];
  check("while real indices stay elements rather than named properties",
    Array.isArray(guardBytes.snapshotDeep(realIdx, TestError, "t/bad", "spec")) &&
    guardBytes.snapshotDeep(realIdx, TestError, "t/bad", "spec")[1] === 8);
  // A sparse array costs what it holds. `[].length = 4e9` is one statement, and a copy that
  // counted from zero to `length` would do four billion iterations for an array holding one
  // element, inside a guard whose job includes bounding a caller's argument.
  var sparse = [];
  sparse[5] = "x";
  sparse.length = 4000000000;
  var startedAt = Date.now();
  var sparseCopy = guardBytes.snapshotDeep(sparse, TestError, "t/bad", "spec");
  check("a sparse array is copied by the indices it holds, not by its length",
    sparseCopy[5] === "x" && sparseCopy.length === 4000000000 &&
    Object.keys(sparseCopy).length === 1 && (Date.now() - startedAt) < 2000);
  // A hole is not an element, and the copy has to measure the same either way.
  var holed = [1, 2, 3];
  delete holed[1];   // a hole, written without the sparse-literal syntax eslint refuses
  var holedCopy = guardBytes.snapshotDeep(holed, TestError, "t/bad", "spec");
  check("holes survive the copy and the length is preserved",
    holedCopy.length === 3 && !(1 in holedCopy) && holedCopy[2] === 3);

  // A key handle is passed through: its meaning is not in its own properties, and a copy of one
  // cannot sign. This engine's own CryptoKey carries its key handle as an own property, so a rule
  // like "no own keys means a handle" would have copied it into a shell -- the toolkit's own
  // isCryptoKeyLike is what answers this, the same predicate key.js and jose.js ask.
  var ck = await require("node:crypto").webcrypto.subtle.importKey(
    "pkcs8", signing.makeSigner("ec-p256").key, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  check("a CryptoKey passes through by reference",
    guardBytes.snapshotDeep({ k: ck }, TestError, "t/bad", "spec").k === ck);
  // The walk reports Symbol keys, so both directions of that need pinning on a real key.
  //
  // First direction: a platform key carries no enumerable own symbol, so it still passes through.
  // If a runtime ever caches its algorithm or usages under one, this fails at the upgrade rather
  // than an operator finding their keys refused. Read the surface first, since a lazy cache would
  // land exactly there.
  void ck.type; void ck.extractable; void ck.algorithm; void ck.usages;
  var ckSymbols = Object.getOwnPropertySymbols(ck).filter(function (s) {
    var d = Object.getOwnPropertyDescriptor(ck, s);
    return d && d.enumerable;
  });
  check("a platform CryptoKey carries no enumerable own symbol", ckSymbols.length === 0);
  check("so it still passes through after its surface has been read",
    guardBytes.snapshotDeep({ k: ck }, TestError, "t/bad", "spec").k === ck);
  // Second direction: a handle is passed through by REFERENCE, so a field the caller hangs on one
  // stays theirs to change after every check has read it. That is the window the refusal closes.
  //
  // A symbol key is outside it, and deliberately. Every verb reads its options by name, so nothing
  // under a symbol reaches one and refusing a key for carrying one protects nothing; what it costs
  // is a documented input, since another WebCrypto implementation may keep its internals under a
  // symbol. The options door still reports one, which is the case that matters: a caller who wrote
  // a symbol onto a bag they passed as options meant it as an option and no verb will read it.
  var marked = await require("node:crypto").webcrypto.subtle.importKey(
    "pkcs8", signing.makeSigner("ec-p256").key, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  marked[Symbol("pem")] = true;
  check("a CryptoKey carrying a symbol field still reaches the verb, since no verb reads one",
    guardBytes.snapshotDeep({ k: marked }, TestError, "t/bad", "spec").k === marked);
  var namedOnKey = await require("node:crypto").webcrypto.subtle.importKey(
    "pkcs8", signing.makeSigner("ec-p256").key, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  namedOnKey.detached = false;
  var namedErr;
  try { guardBytes.snapshotDeep({ k: namedOnKey }, TestError, "t/bad", "spec"); namedErr = { code: "NO-THROW" }; }
  catch (e) { namedErr = e; }
  check("while a name a verb could read is still refused on the same handle",
    namedErr.code === "t/bad");
  // The options door is the one that answers for a symbol, and it is untouched.
  var symBag = {};
  symBag[Symbol("pem")] = true;
  var bagErr;
  try {
    identifier.assertKnownKeys(symBag, { cert: 1 }, function (c, m) { var e = new Error(m); e.code = c; return e; },
      "t/bad", "unknown option ");
    bagErr = { code: "NO-THROW" };
  } catch (e) { bagErr = e; }
  check("an options bag carrying a symbol is still refused at the options door",
    bagErr.code === "t/bad");

  // Third direction, and the one enumerability hid: a field written with defineProperty is not
  // enumerable, and skipping those judged the property by how it was written rather than by who
  // wrote it. `Object.defineProperty` belongs to a caller as much as to a platform, so a handle
  // passed through by reference could carry an option that no check ever saw and that stayed
  // theirs to flip afterwards. Every kind that passes through gets the same reading.
  var foreign = vm.runInNewContext("/x/g");
  check("a foreign RegExp with nothing of its own still passes through",
    guardBytes.snapshotDeep({ k: foreign }, TestError, "t/bad", "spec").k === foreign);
  var concealed = vm.runInNewContext("/x/g");
  Object.defineProperty(concealed, "detached",
    { value: false, enumerable: false, configurable: true, writable: true });
  check("the fixture's field answers a read while reporting as non-enumerable",
    concealed.detached === false && Object.keys(concealed).indexOf("detached") === -1);
  var concealedErr;
  try { guardBytes.snapshotDeep(concealed, TestError, "t/bad", "opts"); concealedErr = { code: "NO-THROW" }; }
  catch (e) { concealedErr = e; }
  check("the same object carrying a non-enumerable caller field is refused",
    concealedErr.code === "t/bad");
  // The shipped consumer: cms.sign reads `detached` off its options bag, so the field above is a
  // real option and the message it decides the shape of is a real artifact.
  var s2 = signing.makeSigner("ec-p256");
  var signErr;
  try {
    await pki.cms.sign(Buffer.from("content"), { cert: s2.cert, key: s2.key }, concealed);
    signErr = { code: "NO-THROW" };
  } catch (e) { signErr = e; }
  check("cms.sign refuses an options bag hiding an option behind non-enumerability",
    signErr.code === "cms/bad-input");

  // What a value passed on by reference may carry is decided by whether the property can still
  // move, which is a fact about the property. A key handle carries implementation state written
  // with neither `writable` nor `configurable`, so nothing the checks read about it can change
  // afterwards and the key reaches the verb as itself -- at the argument, where `pki.csr.sign`
  // takes a key as its second argument, as much as nested in a spec.
  var frozenField = vm.runInNewContext("/x/g");
  Object.defineProperty(frozenField, "detached",
    { value: false, enumerable: false, configurable: false, writable: false });
  check("a settled field cannot answer differently later, so it rides along",
    guardBytes.snapshotDeep(frozenField, TestError, "t/bad", "opts") === frozenField);
  // Settled has to reach what the field POINTS AT. A binding nobody can move, holding a Date
  // anybody can move, is an option that changes after the checks read it: cms.sign signed one
  // signing time while the operator read another off the same object afterwards.
  var frozenToDate = vm.runInNewContext("/x/g");
  Object.defineProperty(frozenToDate, "signingTime",
    { value: new Date("2030-01-01T00:00:00Z"), enumerable: true, configurable: false, writable: false });
  var pointedErr;
  try { guardBytes.snapshotDeep(frozenToDate, TestError, "t/bad", "opts"); pointedErr = { code: "NO-THROW" }; }
  catch (e) { pointedErr = e; }
  check("a settled binding onto a value that can still move is refused",
    pointedErr.code === "t/bad" && pointedErr.message.indexOf("signingTime") !== -1);
  // A Proxy behind a settled binding answers through a handler, so asking it anything is the harm:
  // reading its prototype runs a trap, and a trap that throws would leave this module carrying the
  // caller's own error out of a question it asked on its own behalf.
  var hostileTrap = new Proxy({}, { getPrototypeOf: function () { throw new RangeError("trap"); } });
  var frozenToProxy = vm.runInNewContext("/x/g");
  Object.defineProperty(frozenToProxy, "note",
    { value: hostileTrap, enumerable: true, configurable: false, writable: false });
  var trapErr;
  try { guardBytes.snapshotDeep(frozenToProxy, TestError, "t/bad", "opts"); trapErr = { code: "NO-THROW" }; }
  catch (e) { trapErr = e; }
  check("a settled binding onto a Proxy is refused with this boundary's code",
    trapErr.code === "t/bad" && !(trapErr instanceof RangeError));
  // Settled where it sits. A frozen property reached through the prototype is settled only while
  // nothing can be put in front of it, and an extensible receiver takes an own property of the
  // same name at any time -- after which the read answers with that one instead.
  var frozenAbove = Object.create(RegExp.prototype);
  Object.defineProperty(frozenAbove, "detached",
    { value: false, writable: false, configurable: false, enumerable: true });
  var shadowable = vm.runInNewContext("/x/g");
  Object.setPrototypeOf(shadowable, frozenAbove);
  var shadowErr;
  try { guardBytes.snapshotDeep(shadowable, TestError, "t/bad", "opts"); shadowErr = { code: "NO-THROW" }; }
  catch (e) { shadowErr = e; }
  check("an inherited settled field on an extensible value is refused, since it can be shadowed",
    shadowErr.code === "t/bad");
  var unshadowable = vm.runInNewContext("/x/g");
  Object.setPrototypeOf(unshadowable, frozenAbove);
  Object.preventExtensions(unshadowable);
  check("while the same field on a value nothing can be added to rides along",
    guardBytes.snapshotDeep(unshadowable, TestError, "t/bad", "opts") === unshadowable);
  ["writable", "configurable"].forEach(function (which) {
    var movable = vm.runInNewContext("/x/g");
    var desc = { value: false, enumerable: false, configurable: false, writable: false };
    desc[which] = true;
    Object.defineProperty(movable, "detached", desc);
    var err;
    try { guardBytes.snapshotDeep(movable, TestError, "t/bad", "opts"); err = { code: "NO-THROW" }; }
    catch (e) { err = e; }
    check("a field that is " + which + " can still move, so it is refused", err.code === "t/bad");
  });

  // A copied Date answers every Date question the way a Date holding that instant answers. An own
  // method shadows the language's, and normalizing the prototype does not reach an own property,
  // so the shadow is left behind while the caller's data comes across.
  var shadowed = new Date("2030-01-01T00:00:00Z");
  shadowed.getUTCFullYear = function () { throw new Error("caller code ran"); };
  shadowed.note = "kept";
  var shadowCopy = guardBytes.snapshotDeep({ signingTime: shadowed }, TestError, "t/bad", "opts").signingTime;
  check("the copy answers a Date method with the language's, not the caller's",
    shadowCopy.getUTCFullYear() === 2030);
  check("while the caller's data still comes across", shadowCopy.note === "kept");
  // The VALUE decides, not the name. A plain value under a method's name is a field, and dropping
  // it would take a caller's typo out of reach of the unknown-option check -- the silence this
  // release exists to end.
  var plainUnderMethodName = new Date("2030-01-01T00:00:00Z");
  plainUnderMethodName.getTime = "unused";
  var plainCopy = guardBytes.snapshotDeep({ signingTime: plainUnderMethodName },
    TestError, "t/bad", "opts").signingTime;
  check("a plain value under a Date method's name is carried across as the field it is",
    plainCopy.getTime === "unused");
  var s3 = signing.makeSigner("ec-p256");
  var signedWithShadow = await pki.cms.sign(Buffer.from("content"), { cert: s3.cert, key: s3.key },
    { signingTime: shadowed });
  check("so cms.sign encodes the signing time instead of running the override",
    Buffer.isBuffer(signedWithShadow) && signedWithShadow.length > 0);
  var typoErr;
  try {
    await pki.cms.sign(Buffer.from("content"), { cert: s3.cert, key: s3.key },
      { signingTime: new Date("2030-01-01T00:00:00Z"), getTime: "unused" });
    typoErr = { code: "NO-THROW" };
  } catch (e) { typoErr = e; }
  check("and an option named after a Date method still reaches the unknown-option check",
    typoErr.code === "cms/bad-input");

  // Across algorithms, because what this engine keeps behind a key varies by one: a signing key
  // holds a KeyObject, an HMAC key holds the raw bytes. Both are the engine's own state on its own
  // key object, so both reach the verb as themselves.
  var subtle = require("../../lib/webcrypto.js").webcrypto.subtle;
  var ecPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  check("an ECDSA private key reaches the verb as itself",
    guardBytes.snapshotDeep(ecPair.privateKey, TestError, "t/bad", "key") === ecPair.privateKey);
  var hmacKey = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
  hmacKey = hmacKey.key || hmacKey;
  check("and so does an HMAC key, whose handle holds bytes rather than a key object",
    guardBytes.snapshotDeep(hmacKey, TestError, "t/bad", "key") === hmacKey);

  // A node:crypto KeyObject is a key input `pki.hpke` documents, and its material lives behind an
  // internal slot: a copy of one holds the shape of a key and none of the key, so the copy could
  // not export, sign or derive. It reaches the verb as itself, at the argument and below it.
  var nodeKeys = require("node:crypto").generateKeyPairSync("x25519");
  [["private", nodeKeys.privateKey], ["public", nodeKeys.publicKey]].forEach(function (row) {
    var got = guardBytes.snapshotDeep(row[1], TestError, "t/bad", "key");
    check("a node KeyObject (" + row[0] + ") reaches the verb as itself", got === row[1]);
    var nested = guardBytes.snapshotDeep({ key: row[1] }, TestError, "t/bad", "spec").key;
    check("and the same one nested in a spec does too", nested === row[1]);
    check("so it can still be exported, which a copy of it could not",
      typeof nested.export === "function" && Buffer.isBuffer(nested.export({ format: "der", type: row[0] === "private" ? "pkcs8" : "spki" })));
  });
  // The slot is what answers, so a lookalike wearing only the prototype is not one. Asking whether
  // it is key-shaped reads `type`, whose getter raises a raw TypeError on a value with no key
  // behind it; that fault is this boundary's to type, not the caller's to receive as somebody
  // else's error.
  var keyLookalike = Object.create(require("node:crypto").KeyObject.prototype);
  keyLookalike.password = "hunter2";
  var lookalikeErr;
  try { guardBytes.snapshotDeep({ k: keyLookalike }, TestError, "t/bad", "spec"); lookalikeErr = { code: "NO-THROW" }; }
  catch (e) { lookalikeErr = e; }
  check("a KeyObject lookalike is refused with this boundary's code, not a raw TypeError",
    lookalikeErr.code === "t/bad" && !(lookalikeErr instanceof TypeError));
  check("and the caller's own fault is carried as the cause",
    lookalikeErr.cause instanceof TypeError);

  // The surfaces are tables of names, so a name has to be IN one rather than answered by one.
  // Built as ordinary objects they answered `surface.toString` with the function every object
  // inherits, which read as though every kind published `toString`, `constructor`, `valueOf`,
  // `hasOwnProperty` and `__proto__` -- five names a caller can write on an object that is then
  // handed on by reference.
  ["toString", "constructor", "valueOf", "hasOwnProperty", "__proto__"].forEach(function (name) {
    var carrier = vm.runInNewContext("/x/g");
    Object.defineProperty(carrier, name, { value: 1, enumerable: false, configurable: true, writable: true });
    var err;
    try { guardBytes.snapshotDeep(carrier, TestError, "t/bad", "opts"); err = { code: "NO-THROW" }; }
    catch (e) { err = e; }
    check("a name inherited by the surface table is not on the surface: " + name,
      err.code === "t/bad" && err.message.indexOf(name) !== -1);
  });

  // A symbol key is treated exactly as a string one is, which is the point: the walk reports both,
  // so neither is a way to smuggle a field past a check or to behave differently under a copy. A
  // method a class declares under a symbol is a method like any other, so the copy no longer
  // carries it -- the copy is a plain object, and nothing the caller wrote runs through it.
  var METHOD = Symbol("describe");
  function SymBag() { this.pem = true; }
  SymBag.prototype[METHOD] = function () { return 42; };
  var symCopy = guardBytes.snapshotDeep(new SymBag(), TestError, "t/bad", "spec");
  check("a class method declared under a symbol is left behind with the class",
        symCopy.pem === true && symCopy[METHOD] === undefined &&
        Object.getPrototypeOf(symCopy) === Object.prototype);
  function ThrowSym() {}
  Object.defineProperty(ThrowSym.prototype, Symbol("boom"), {
    get: function () { throw new Error("ran"); }, enumerable: false, configurable: true
  });
  function ThrowStr() {}
  Object.defineProperty(ThrowStr.prototype, "boom", {
    get: function () { throw new Error("ran"); }, enumerable: false, configurable: true
  });
  var symGet = codeOf(function () { guardBytes.snapshotDeep(new ThrowSym(), TestError, "t/bad", "spec"); });
  var strGet = codeOf(function () { guardBytes.snapshotDeep(new ThrowStr(), TestError, "t/bad", "spec"); });
  check("an accessor that throws is the caller's typed error under either key kind",
        symGet === "t/bad" && strGet === "t/bad");
  // A Map or a Set holds data the caller can still change, so it is copied like anything else --
  // entries and any named properties alongside them. A RegExp or an Error carries no caller data
  // that a verb reads, so there is nothing to fix and it stays as it is.
  var live = { m: new Map([["a", 1]]), s: new Set([1]), re: /x/, err: new Error("e") };
  live.m.pem = true;
  var liveCopy = guardBytes.snapshotDeep(live, TestError, "t/bad", "spec");
  check("a Map is copied, entries and all",
    liveCopy.m !== live.m && liveCopy.m.get("a") === 1 && liveCopy.m.pem === true);
  check("a Set is copied", liveCopy.s !== live.s && liveCopy.s.has(1));
  live.m.set("a", 99);
  live.m.pem = false;
  check("the Map copy does not follow later writes",
    liveCopy.m.get("a") === 1 && liveCopy.m.pem === true);
  check("a RegExp / Error stays as it is", liveCopy.re === live.re && liveCopy.err === live.err);

  // A kind whose state cannot be read has no safe handling once it also carries the caller's own
  // fields: it cannot be copied, and passing it through would leave those fields changeable after
  // they were checked. That is refused rather than half-handled, which is what stops this from
  // being one more shape to discover later. Carrying nothing of its own, it still passes through.
  var bareWeak = new WeakMap();
  check("an empty WeakMap passes through",
    guardBytes.snapshotDeep({ w: bareWeak }, TestError, "t/bad", "spec").w === bareWeak);
  var loadedWeak = new WeakMap();
  loadedWeak.signedAttributes = true;
  check("a WeakMap carrying caller fields is refused", codeOf(function () {
    guardBytes.snapshotDeep({ w: loadedWeak }, TestError, "t/bad", "spec");
  }) === "t/bad");

  // The same for every other kind whose state cannot be read. Each of these was reachable as an
  // options bag with a field glued on, which is why the rule is the kind's own surface and nothing
  // more rather than a list of kinds to trust.
  var kindsCarryingFields = [
    ["an Error", function () { var e = new Error("o"); e.signedAttributes = true; return e; }],
    ["a RegExp", function () { var r = /x/; r.signedAttributes = true; return r; }],
    ["a promise", function () { var p = Promise.resolve(1); p.signedAttributes = true; return p; }],
  ];
  function refusesKind(make) {
    return codeOf(function () {
      guardBytes.snapshotDeep({ v: make() }, TestError, "t/bad", "spec");
    });
  }
  kindsCarryingFields.forEach(function (kind) {
    check(kind[0] + " carrying caller fields is refused", refusesKind(kind[1]) === "t/bad");
  });
  var cleanErr = new Error("boom");
  check("an Error carrying only its own kind's fields passes through",
    guardBytes.snapshotDeep({ e: cleanErr }, TestError, "t/bad", "spec").e === cleanErr);
  var callableField = new Error("boom");
  callableField.signedAttributes = function () {};
  check("a callable extra field is no exemption", codeOf(function () {
    guardBytes.snapshotDeep({ e: callableField }, TestError, "t/bad", "spec");
  }) === "t/bad");

  // A parse result keeps its identity, because the doors that decide integrity re-derive it from
  // the bytes the record names and ignore what the object says. That covers it as a PARSE RESULT.
  // A caller who adds an option to one has added a field no door re-derives, so it stops being
  // only a parse result and is copied like the data it now also is. Deleting a field is a
  // different case and changes nothing: re-derivation does not consult the object for it.
  var certBytes = signing.makeSigner("ec-p256").cert;
  var parsedCert = pki.schema.x509.parse(certBytes);
  check("a parse result keeps its identity",
    guardBytes.snapshotDeep({ c: parsedCert }, TestError, "t/bad", "spec").c === parsedCert);
  var pruned = pki.schema.x509.parse(certBytes);
  delete pruned.extensions;
  check("a pruned parse result still keeps its identity",
    guardBytes.snapshotDeep({ c: pruned }, TestError, "t/bad", "spec").c === pruned);
  var withOption = pki.schema.x509.parse(certBytes);
  withOption.signedAttributes = true;
  check("a parse result with an option added to it is copied",
    guardBytes.snapshotDeep({ c: withOption }, TestError, "t/bad", "spec").c !== withOption);
  var hiddenOption = pki.schema.x509.parse(certBytes);
  Object.defineProperty(hiddenOption, "pem", { value: true, writable: true, enumerable: false });
  check("including one added where Object.keys cannot see it",
    guardBytes.snapshotDeep({ c: hiddenOption }, TestError, "t/bad", "spec").c !== hiddenOption);

  // The copy is a plain one of its kind, and never carries the caller's prototype back.
  //
  // The prototype is part of the argument, so restoring it left the copy dispatching into the
  // caller's code: a `map` on an array subclass, a `getUTCFullYear` on a Date subclass, reached by
  // the verb through what was supposed to be a private snapshot. One that threw surfaced the
  // caller's own exception from inside a verb, and the prototype could be rewritten AFTER the call
  // had begun, so the value the checks read and the value the verb ran against were the same
  // object only until the caller changed its class.
  //
  // Restoring it was for the names: copying and checking are one rule read from two sides, and a
  // copy the check reads differently splits them. That is measured below rather than assumed --
  // the names match without it, because a method the class defines is not a name this walk
  // reports and so is not copied onto the copy as one.
  function ArrayBag() {}
  ArrayBag.prototype = Object.create(Array.prototype);
  ArrayBag.prototype.constructor = ArrayBag;
  ArrayBag.prototype.describe = function () { return "bag"; };
  var arrayBag = Object.setPrototypeOf([], ArrayBag.prototype);
  arrayBag.pem = true;
  var arrayCopy = guardBytes.snapshotDeep({ o: arrayBag }, TestError, "t/bad", "spec").o;
  check("a collection subclass copies to a plain one of its kind",
    Array.isArray(arrayCopy) && Object.getPrototypeOf(arrayCopy) === Array.prototype &&
    arrayCopy.describe === undefined);
  check("and the copy still reports the same option names as the original",
    identifier.readableNames(arrayCopy, TestError, "t/bad", "o").join(",") ===
    identifier.readableNames(arrayBag, TestError, "t/bad", "o").join(",") &&
    identifier.readableNames(arrayCopy, TestError, "t/bad", "o").join(",") === "pem");
  function MapBag() {}
  MapBag.prototype = Object.create(Map.prototype);
  MapBag.prototype.constructor = MapBag;
  MapBag.prototype.describe = function () { return "bag"; };
  var mapBag = Object.setPrototypeOf(new Map(), MapBag.prototype);
  mapBag.set("k", 1);
  mapBag.pem = true;
  var mapCopy = guardBytes.snapshotDeep({ o: mapBag }, TestError, "t/bad", "spec").o;
  check("a Map subclass copies to a plain Map, keeping its entries",
    Object.getPrototypeOf(mapCopy) === Map.prototype && mapCopy.get("k") === 1 &&
    mapCopy.describe === undefined);
  check("and reports the same option names as the original",
    identifier.readableNames(mapCopy, TestError, "t/bad", "o").join(",") === "pem");
  // The methods a verb goes on to call are the language's, whatever class the caller passed. An
  // override that throws is unreachable through the copy, and so is one installed after the call
  // began -- the copy's class was decided when it was made, and it is not the caller's.
  var TrapArray = class extends Array { map() { throw new RangeError("planted"); } };
  var trapList = new TrapArray();
  trapList.push({ ref: 1 });
  var listCopy = guardBytes.snapshotDeep({ signers: trapList }, TestError, "t/bad", "spec").signers;
  check("an array subclass whose `map` throws is copied to one a verb can walk",
    listCopy.map(function (x) { return x.ref; }).join(",") === "1");
  var TrapDate = class extends Date { getUTCFullYear() { throw new RangeError("planted"); } };
  var dateCopy = guardBytes.snapshotDeep({ signingTime: new TrapDate(0) },
                                         TestError, "t/bad", "spec").signingTime;
  check("a Date subclass whose method throws is copied to one a verb can read",
    dateCopy.getUTCFullYear() === 1970 && dateCopy.valueOf() === 0);
  // ...and rewriting the caller's class after the call cannot reach the copy either.
  TrapArray.prototype.map = function () { throw new RangeError("planted later"); };
  check("a prototype rewritten after the copy was taken does not reach it",
    listCopy.map(function (x) { return x.ref; }).join(",") === "1");

  check("snapshotDeep refuses a detached leaf", codeOf(function () {
    guardBytes.snapshotDeep({ b: detachedBuffer(4) }, TestError, "t/bad", "spec");
  }) === "t/bad");
  check("snapshotDeep bounds a cyclic structure", codeOf(function () {
    var cyc = {}; cyc.self = cyc;
    guardBytes.snapshotDeep(cyc, TestError, "t/bad", "spec");
  }) === "t/bad");
  // A cycle in the prototype chain. The vector above covers a cycle in the values. A Proxy whose
  // `getPrototypeOf` trap returns the proxy makes one, and the engine permits it while the target
  // stays extensible. Every question this module asks about a kind is an `instanceof`, which
  // walks that chain, so without a test for the shape the copy exhausts the stack and a raw
  // RangeError escapes a guard whose contract is a typed error.
  var protoCycTarget = { a: 1 };
  var protoCyc = new Proxy(protoCycTarget, { getPrototypeOf: function () { return protoCyc; } });
  check("the fixture really is a prototype cycle", Object.getPrototypeOf(protoCyc) === protoCyc);
  var protoCycErr;
  try { guardBytes.snapshotDeep(protoCyc, TestError, "t/bad", "spec"); protoCycErr = new Error("NO-THROW"); }
  catch (e) { protoCycErr = e; }
  check("snapshotDeep refuses a cyclic prototype chain with the caller's typed code",
        protoCycErr.code === "t/bad" && protoCycErr instanceof TestError);
  // The Proxy rule reaches it first, and that is the whole story: `Object.setPrototypeOf` refuses
  // to build a cycle out of ordinary objects ("Cyclic __proto__ value"), so a Proxy is the only
  // way to have one and refusing every Proxy already covers it. The cycle test in _deep stays as
  // a second line under the first, and is unreachable while the first one holds.
  check("and the refusal names a shape rather than reporting a stack overflow",
        /Proxy|prototype chain is a cycle/.test(protoCycErr.message));
  // A Proxy takes its copied names from `ownKeys` and answers reads from `get`, and the two need
  // not agree. Copying one whose ownKeys is empty yields an object holding nothing while the
  // original still answers `password`, so the field the caller supplied is gone with no fault
  // raised. Copying it is not copying it, so it is refused.
  var liar = new Proxy({}, {
    ownKeys: function () { return []; },
    get: function (_, k) { return k === "password" ? "pw" : undefined; },
  });
  check("the fixture reports no keys while answering a read",
        Object.getOwnPropertyNames(liar).length === 0 && liar.password === "pw");
  var liarErr;
  try { guardBytes.snapshotDeep(liar, TestError, "t/bad", "spec"); liarErr = new Error("NO-THROW"); }
  catch (e) { liarErr = e; }
  check("snapshotDeep refuses a Proxy with the caller's typed code",
        liarErr.code === "t/bad" && liarErr instanceof TestError);
  check("and the refusal names the shape", /Proxy/.test(liarErr.message));
  var nestedErr;
  try { guardBytes.snapshotDeep({ inner: liar }, TestError, "t/bad", "spec"); nestedErr = { code: "NO-THROW" }; }
  catch (e) { nestedErr = e; }
  check("a Proxy nested inside a spec is refused on the same rule", nestedErr.code === "t/bad");
  // A plain object inheriting from one. The copy reads names from the whole chain, so the liar
  // decides what is taken while the original still answers through its get trap.
  var viaProto = Object.create(liar);
  var viaErr;
  try { guardBytes.snapshotDeep(viaProto, TestError, "t/bad", "spec"); viaErr = { code: "NO-THROW" }; }
  catch (e) { viaErr = e; }
  check("an object inheriting from a Proxy is refused", viaErr.code === "t/bad");
  // A `getPrototypeOf` trap runs the caller's code, so any walk of the chain does too. Reading
  // the chain before deciding the value is a Proxy lets a throwing trap escape as its own raw
  // Error from a guard whose contract is a typed one, which is why the Proxy test runs first.
  var boom = new Proxy({}, { getPrototypeOf: function () { throw new Error("trap"); } });
  var boomErr;
  try { guardBytes.snapshotDeep(boom, TestError, "t/bad", "spec"); boomErr = new Error("NO-THROW"); }
  catch (e) { boomErr = e; }
  check("a Proxy whose getPrototypeOf trap throws still refuses with the caller's typed code",
        boomErr.code === "t/bad" && boomErr instanceof TestError);
  var boomProtoErr;
  try { guardBytes.snapshotDeep(Object.create(boom), TestError, "t/bad", "spec"); boomProtoErr = { code: "NO-THROW" }; }
  catch (e) { boomProtoErr = e; }
  check("and so does an object inheriting from one", boomProtoErr.code === "t/bad");

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

  // Every BufferSource form is accepted as content and signed OVER ITS BYTE VIEW (#68 -- the byte doors route
  // through guard.bytes.isByteSource, the WebCrypto BufferSource contract). A Uint16Array / DataView /
  // ArrayBuffer carries the platform's element-layout bytes; passing a BufferSource is opting into exactly
  // those bytes, and the signature is over them. (Detachment / TOCTOU is still refused, below and elsewhere.)
  check("cms.sign over a Uint16Array is accepted (its byte view is signed)",
    Buffer.isBuffer(await pki.cms.sign(new Uint16Array([1, 2, 3]), { cert: s.cert, key: s.key })));
  check("cms.sign over a DataView is accepted",
    Buffer.isBuffer(await pki.cms.sign(new DataView(new ArrayBuffer(8)), { cert: s.cert, key: s.key })));
  check("cms.sign over a raw ArrayBuffer is accepted",
    Buffer.isBuffer(await pki.cms.sign(new ArrayBuffer(8), { cert: s.cert, key: s.key })));
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
  check("cms.sign honors a custom-prototype options object as it was at entry",
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
  check("cms.sign honors an inherited option as it was at entry",
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
// An array reads its elements through its prototype chain wherever it has a hole, so the
// set a consumer sees is not the set `Reflect.ownKeys` reports. A copy built from the own
// keys alone hands the verb a shorter list than the caller passed, and the verb then acts
// on a signer, an anchor or a policy that was never dropped by anyone.
async function testInheritedArrayElementsSurviveTheCopy() {
  var s = signing.makeSigner("ec-p256");

  var signers = [];
  signers.length = 1;                              // one slot, and the slot is a hole
  Object.setPrototypeOf(signers, Object.assign(Object.create(Array.prototype), {
    0: { cert: s.cert, key: s.key }
  }));
  check("the fixture reads as a one-signer list to an ordinary consumer",
    signers.length === 1 && signers[0] !== undefined && Reflect.ownKeys(signers).indexOf("0") === -1);

  var der = await pki.cms.sign(Buffer.from("content"), signers);
  var parsed = pki.schema.cms.parse(der);
  check("cms.sign signs with the signer the array resolves, not the hole its own keys report",
    parsed.signerInfos.length === 1);
  var verdict = await pki.cms.verify(der, { certs: [s.cert] });
  check("and the message it produced verifies", verdict.valid === true);

  // The other direction: an inherited index at or past `length` is not something a
  // length-bounded read reaches, so carrying it across would lengthen the copy.
  var two = [{ cert: s.cert, key: s.key }];
  Object.setPrototypeOf(two, Object.assign(Object.create(Array.prototype), { 1: "past the end" }));
  var der2 = await pki.cms.sign(Buffer.from("content"), two);
  check("an inherited index past length does not lengthen the copy",
    pki.schema.cms.parse(der2).signerInfos.length === 1);
}

// A Date is accepted by its internal slot, which admits a subclass from any realm, and a
// subclass answers `getTime` with whatever it likes. Every verb whose arguments this module
// copies is reached only by the copy, so the copy is where that has to stop: it reads the
// instant intrinsically and hands on a plain Date holding it. What the verb compares is then
// the instant the caller's Date holds rather than the one it reports, and no later read
// inside the verb can reopen the gap.
async function testCallerDateCannotAnswerTheInstant() {
  var LyingDate = class extends Date { getTime() { return 0; } };
  var lying = new LyingDate("2030-01-01T00:00:00Z");
  check("the fixture holds one instant and reports another",
    lying.getTime() === 0 && Date.prototype.getTime.call(lying) !== 0);

  var copied = guardBytes.snapshotDeep({ notBefore: lying }, TestError, "t/bad", "spec").notBefore;
  check("the copy holds the instant the original holds, not the one it reported",
    Date.prototype.getTime.call(copied) === Date.parse("2030-01-01T00:00:00Z"));
  check("and it answers with that instant, since the subclass was left behind",
    copied.getTime() === Date.parse("2030-01-01T00:00:00Z"));

  // The shipped verb behind that copy: an inverted validity is refused on the instants the
  // Dates hold. Reported as zero, notBefore would have sorted before notAfter and issued.
  var s = signing.makeSigner("ec-p256");
  var threw = null;
  try {
    await pki.x509.sign({
      subject: "lying-date", serialNumber: 3n, subjectPublicKey: s.spki,
      notBefore: lying, notAfter: new Date("2020-01-01T00:00:00Z"),
    }, { key: s.key });
  } catch (e) { threw = e; }
  check("x509.sign refuses the inverted validity the held instants describe",
    threw !== null && threw.code === "x509/bad-input");
}

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
  await testInheritedArrayElementsSurviveTheCopy();
  await testCallerDateCannotAnswerTheInstant();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
