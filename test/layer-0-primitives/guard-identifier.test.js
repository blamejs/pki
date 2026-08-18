// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-identifier (@internal): fail-closed canonicalization of the
 * structured-identifier strings the toolkit compares and encodes.
 * Oracle: X.660 -- a canonical dotted-decimal OID has two or more arcs, no
 * leading-zero component, the root arc 0..2, and the second arc 0..39 under roots
 * 0 and 1. The string-OID contract is the shared primitive pki.oid name/arc
 * resolution, pki.asn1 build.oid, and pki.path.validate EKU / policy key checking
 * compose -- exercised end-to-end there; these pin its contract directly.
 */

var identifier = require("../../lib/guard-identifier");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;
var spawnSync = require("child_process").spawnSync;
var path = require("path");
var vm = require("vm");
var INDEX = path.resolve(__dirname, "../../index.js");

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
// The thrown error itself, so a vector can assert the REASON (the operator-facing message,
// the error type) and not only the code -- a code-only assertion passes against a check that
// happens to reject for some other reason entirely.
function errOf(fn) { try { fn(); return { code: "NO-THROW", message: "NO-THROW" }; } catch (e) { return e; } }

function testAcceptsCanonical() {
  check("a plain OID is returned unchanged", identifier.assertCanonicalOid("1.2.840.113549", E, "x/bad", "oid") === "1.2.840.113549");
  check("a two-arc OID is accepted", identifier.assertCanonicalOid("2.5", E, "x/bad", "oid") === "2.5");
  check("a zero arc is canonical (no leading zero)", identifier.assertCanonicalOid("2.5.29.0", E, "x/bad", "oid") === "2.5.29.0");
  check("root 2 lifts the second-arc bound", identifier.assertCanonicalOid("2.999.1", E, "x/bad", "oid", "x/bounds") === "2.999.1");
  // A UUID-based arc exceeds 2^53 -- it must survive as a BigInt without precision loss.
  check("a huge arc beyond 2^53 is accepted", identifier.assertCanonicalOid("2.25.329800735698586629295641978511506172918", E, "x/bad", "oid") === "2.25.329800735698586629295641978511506172918");
}

function testSyntaxRejects() {
  check("a leading-zero arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("2.05.29.15", E, "x/bad", "oid"); }) === "x/bad");
  check("a single arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("2", E, "x/bad", "oid"); }) === "x/bad");
  check("a non-string throws the syntax code", codeOf(function () { identifier.assertCanonicalOid(1.2, E, "x/bad", "oid"); }) === "x/bad");
  check("a trailing dot throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("1.2.", E, "x/bad", "oid"); }) === "x/bad");
  check("a non-numeric arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("1.2.x", E, "x/bad", "oid"); }) === "x/bad");
}

function testBoundsRejects() {
  // The X.660 arc bounds throw the SEPARATE boundsCode when one is supplied.
  check("root arc above 2 throws the bounds code", codeOf(function () { identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid", "x/bounds"); }) === "x/bounds");
  check("second arc 40 under root 1 throws the bounds code", codeOf(function () { identifier.assertCanonicalOid("1.40.1", E, "x/bad", "oid", "x/bounds"); }) === "x/bounds");
  // With no boundsCode, an out-of-range arc falls back to the syntax code.
  check("bounds fault falls back to the syntax code by default", codeOf(function () { identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid"); }) === "x/bad");
}

function testBoundsWaived() {
  // boundsCode === null waives the arc-bound check (a LOOKUP key): a well-formed
  // but non-encodable OID passes syntax so the caller can treat it as a miss.
  check("boundsCode null accepts an out-of-bounds well-formed OID", identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid", null) === "9.9.9");
  // Syntax is still enforced even when bounds are waived.
  check("boundsCode null still rejects a leading-zero arc", codeOf(function () { identifier.assertCanonicalOid("2.05.1", E, "x/bad", "oid", null); }) === "x/bad");
}

// assertKnownKeys -- every own key of a caller-supplied options object must be one the
// caller recognizes. Oracle: the failure this prevents is fail-OPEN. A misspelled option
// key is silently absent, so the default applies and a caller who asked for a stricter
// check quietly gets the looser behavior with no error anywhere. The consumers compose
// this at their config-time boundary (x509.sign extensions, csr.sign spec, crl.sign
// issuingDistributionPoint, cmp.build opts, webauthn opts.tpmPolicy); these pin the
// contract directly, including the two ways a hand-rolled walk gets it wrong.
function testKnownKeys() {
  var KNOWN = { alpha: 1, beta: 1 };
  check("every known key is accepted", identifier.assertKnownKeys({ alpha: 1, beta: 2 }, KNOWN, E, "x/bad", "unknown ") === undefined);
  check("an empty object is accepted", identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown ") === undefined);
  var err = errOf(function () { identifier.assertKnownKeys({ alpha: 1, gamma: 3 }, KNOWN, E, "x/bad", "unknown option "); });
  check("an unknown key throws the caller's code", err.code === "x/bad");
  check("the message is the caller's wording plus the quoted key", err.message === 'unknown option "gamma"');

  // A table consulted with a truthiness test rather than hasOwnProperty accepts every
  // inherited Object member as a recognized key -- "constructor" resolves to a function,
  // which is truthy, so a caller passing { constructor: ... } sails through a hand-rolled
  // walk. The guard reads own properties only, so an inherited name is still unknown.
  check("an inherited Object member is not a known key", errOf(function () {
    identifier.assertKnownKeys({ constructor: 1 }, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
  check("toString is not a known key", errOf(function () {
    identifier.assertKnownKeys({ toString: 1 }, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");

  // An options object built by JSON.parse can carry an OWN "__proto__" key. Object.keys
  // enumerates it (unlike a `for..in` walk over a literal, where it is the prototype
  // slot), so it must be inspected and rejected rather than skipped.
  var fromJson = JSON.parse('{"__proto__": {"alpha": 1}}');
  check("an own __proto__ key from JSON is rejected", errOf(function () {
    identifier.assertKnownKeys(fromJson, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");

  // The message may be a builder, for the callers that name the key mid-sentence and
  // follow it with the hint saying what to pass instead.
  var built = errOf(function () {
    identifier.assertKnownKeys({ gamma: 1 }, KNOWN, E, "x/bad", function (k) {
      return "unknown extension " + JSON.stringify(k) + "; pass a pre-encoded DER via the array form";
    });
  });
  check("a function message builds the whole sentence", built.message === 'unknown extension "gamma"; pass a pre-encoded DER via the array form');

  // The guard rejects through a (code, message) FACTORY, never `new` on a class -- a
  // caller holding a class adapts at the call site so the guard keeps one convention.
  var adapted = errOf(function () {
    identifier.assertKnownKeys({ gamma: 1 }, KNOWN, function (c, m) { return new TestError(c, m); }, "x/adapted", "unknown ");
  });
  check("a class adapted to a factory still throws the typed error", adapted.code === "x/adapted" && adapted instanceof TestError);

  // What counts as a method, which is the one thing the property walk skips. The distinction has
  // to hold on both sides of guard.bytes.snapshotDeep. That copy carries every readable name onto
  // the copy and keeps the prototype, so the same method is inherited before it and own after it.
  function Bag() { this.alpha = 1; }
  Bag.prototype.describe = function () { return "bag"; };
  check("an instance whose class defines a method is accepted",
        identifier.assertKnownKeys(new Bag(), KNOWN, E, "x/bad", "unknown ") === undefined);
  // The same instance after a snapshot: `describe` and `constructor` are now own properties.
  var copied = Object.create(Bag.prototype);
  copied.alpha = 1;
  copied.describe = Bag.prototype.describe;
  copied.constructor = Bag;
  check("a snapshot copy carrying its methods as own properties is accepted",
        identifier.assertKnownKeys(copied, KNOWN, E, "x/bad", "unknown ") === undefined);
  // A function value is not a free pass. It is a method only where the chain above supplies the
  // same function under that name. An unrelated function under an unknown name is still unknown.
  check("an own function under an unknown name is still reported", errOf(function () {
    identifier.assertKnownKeys({ gamma: function () {} }, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
  // An own property shadowing a method with another function is a value the caller supplied.
  var shadow = Object.create(Bag.prototype);
  shadow.describe = function () { return "mine"; };
  check("an own property shadowing a method with another function is reported",
        errOf(function () { identifier.assertKnownKeys(shadow, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");
  // An accessor is never a method. A getter exists to answer with a value, which is what an
  // option is, including one whose value happens to be a function.
  var accessor = {};
  Object.defineProperty(accessor, "gamma", { get: function () { return function () {}; }, enumerable: false });
  check("an inherited-style accessor is reported however its value reads",
        errOf(function () { identifier.assertKnownKeys(accessor, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");

  // A name added to Object.prototype after this module loaded reaches an empty object. `{}.gamma`
  // answers while the object itself holds nothing. The built-ins are skipped by identity against
  // a snapshot taken at load, so the planted name is still reported.
  Object.defineProperty(Object.prototype, "gamma", { value: 3, writable: true, configurable: true, enumerable: false });
  var pollutedCode, restored;
  try {
    pollutedCode = errOf(function () { identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown "); }).code;
  } finally {
    restored = delete Object.prototype.gamma;
  }
  check("a name planted on Object.prototype is reported on an empty object", pollutedCode === "x/bad");
  check("the pollution vector leaves Object.prototype as it found it",
        restored === true && !("gamma" in Object.prototype));
  check("an empty object is accepted again once the pollution is gone",
        identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown ") === undefined);

  // A cyclic prototype chain. `Object.setPrototypeOf` refuses to build one out of ordinary
  // objects ("Cyclic __proto__ value"), so a Proxy whose `getPrototypeOf` trap returns itself is
  // the only way to have one, and the Proxy refusal reaches every such value before any walk of
  // it starts. The cycle test inside the walk is a second line under that, unreachable through
  // any door while the first one holds. What is observable, and what is pinned here, is that a
  // cyclic bag is refused rather than hanging the verb.
  var cyclicTarget = { alpha: 1, gamma: 3 };
  var cyclic = new Proxy(cyclicTarget, { getPrototypeOf: function () { return cyclic; } });
  check("the fixture really is a cycle", Object.getPrototypeOf(cyclic) === cyclic);
  check("a cyclic prototype chain is refused rather than walked", errOf(function () {
    identifier.assertKnownKeys(cyclic, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
  check("and the exported name walk refuses it too, with the caller's code", errOf(function () {
    identifier.readableNames(cyclic, E, "x/bad", "opts");
  }).code === "x/bad");

  // A primitive supplies no option names, and `Reflect.ownKeys` refuses one outright, so the walk
  // must start above it. Otherwise a caller who passes a number where an options bag belongs gets
  // a raw TypeError about a reflection method they never called.
  check("a number reports no readable name rather than throwing a TypeError",
        identifier.readableNames(7, E, "x/bad", "opts").length === 0);
  check("and null and undefined the same",
        identifier.readableNames(null, E, "x/bad", "opts").length === 0 &&
        identifier.readableNames(undefined, E, "x/bad", "opts").length === 0);
  // A string boxes to something with own names, and those ARE readable, so the check refuses it.
  check("a string in the options position is refused rather than passed over",
        errOf(function () { identifier.assertKnownKeys("ab", KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");

  // An array, a byte view, a Map, a Set and an ArrayBuffer report only what the CALLER added.
  // A verb reads an option by name whatever the argument's type, so `opts = []; opts.alpha = 1`
  // is an options bag, and these kinds have to keep working. Their own surface is structural:
  // `length` is intrinsic on an empty array, and the prototypes carry `buffer`, `byteLength`,
  // `size` and `BYTES_PER_ELEMENT`. A walk of the whole chain reports all of it and the verb
  // then refuses a shape it supports. guard-bytes states the same rule for which names it copies.
  check("an empty array reports no option name", identifier.readableNames([], E, "x/bad", "o").length === 0);
  check("and is accepted as an options bag",
        identifier.assertKnownKeys([], KNOWN, E, "x/bad", "unknown ") === undefined);
  var arrOpts = []; arrOpts.alpha = 1;
  check("an array carrying a known option is accepted",
        identifier.assertKnownKeys(arrOpts, KNOWN, E, "x/bad", "unknown ") === undefined);
  var arrBad = []; arrBad.gamma = 1;
  check("and one carrying an unknown option is still refused",
        errOf(function () { identifier.assertKnownKeys(arrBad, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");
  // An index is what the language calls one: an integer in [0, 2^32 - 2] spelled canonically.
  // `String(Number(k)) === k` looks like that test and also admits "-1", "1.5", "NaN",
  // "Infinity" and "4294967295", each an ordinary NAMED property on an array. Passing over them
  // means an unknown option under one of those names is accepted in silence.
  ["-1", "1.5", "NaN", "Infinity", "4294967295", "01"].forEach(function (k) {
    var bag = [];
    bag[k] = "x";
    check("an unknown option named " + JSON.stringify(k) + " on an array is refused",
          errOf(function () { identifier.assertKnownKeys(bag, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");
  });
  var realIndices = [1, 2, 3];
  check("while real elements are not reported as options",
        identifier.readableNames(realIndices, E, "x/bad", "o").length === 0);

  // A value from another realm carries that realm's root prototype, so a rule keyed on identity
  // with the local `Object.prototype` misses it and reads the foreign `__proto__` accessor as a
  // name the caller supplied. The root is the last level before null in every realm.
  var foreignBag = vm.runInNewContext("({ alpha: 1 })");
  check("the fixture's root is not this realm's Object.prototype",
        Object.getPrototypeOf(Object.getPrototypeOf(foreignBag)) === null &&
        Object.getPrototypeOf(foreignBag) !== Object.prototype);
  check("a plain options bag from another realm reports only what it holds",
        identifier.readableNames(foreignBag, E, "x/bad", "o").join(",") === "alpha");
  check("and is accepted where its names are known",
        identifier.assertKnownKeys(foreignBag, { alpha: 1 }, E, "x/bad", "unknown ") === undefined);
  // A collection built in another realm inherits from that realm's prototypes, which are not the
  // objects the kind set below holds, so its levels are read and the members the language put
  // there look like names its caller chose. Every one of these is a bag a verb accepted before,
  // and reporting `size` or `Symbol.unscopables` off it turns that into a refusal.
  var foreignKinds = {
    array: "[]", Map: "new Map()", Set: "new Set()",
    Uint8Array: "new Uint8Array(2)", ArrayBuffer: "new ArrayBuffer(2)",
    DataView: "new DataView(new ArrayBuffer(2))",
  };
  Object.keys(foreignKinds).forEach(function (kind) {
    var bag = vm.runInNewContext(foreignKinds[kind]);
    bag.pem = true;
    check("a " + kind + " options bag from another realm reports only what its caller set",
      identifier.readableNames(bag, E, "x/bad", "o").map(String).join(",") === "pem");
  });
  // A kind's prototype gets no exemption as a LEVEL, only its member names get one. Passing the
  // level over whole hid anything planted on it, so `Array.prototype.password = "pw"` answered
  // `opts.password` while the check saw nothing, and `pki.key.export(privateKey, [])` handed back
  // an unprotected private key. Object.prototype was already read for this reason; every level is
  // read the same way now. The plant is removed in a finally, since leaving it set would decide
  // the result of every later check in this file.
  var polluted = { Array: Array.prototype, Map: Map.prototype, Set: Set.prototype,
    ArrayBuffer: ArrayBuffer.prototype, Uint8Array: Uint8Array.prototype };
  Object.keys(polluted).forEach(function (kind) {
    var proto = polluted[kind];
    var bag = kind === "Array" ? [] : kind === "Map" ? new Map() : kind === "Set" ? new Set()
      : kind === "ArrayBuffer" ? new ArrayBuffer(2) : new Uint8Array(2);
    Object.defineProperty(proto, "password", { value: "pw", writable: true, configurable: true });
    try {
      check("a name planted on " + kind + ".prototype is reported off a bag of that kind",
        identifier.readableNames(bag, E, "x/bad", "o").map(String).indexOf("password") !== -1);
    } finally {
      delete proto.password;
    }
    check("and the same bag reports nothing once it is gone",
      identifier.readableNames(bag, E, "x/bad", "o").length === 0);
  });
  // Carrying a name a kind defines is not enough to be passed over; it has to be shaped the way
  // the language leaves one. A planted `size` would otherwise hide behind the name alone, which
  // is the same hole one level down from passing the whole level over.
  Object.defineProperty(Array.prototype, "size", { value: "pw", writable: true, configurable: true });
  var plantedMemberNames;
  try {
    plantedMemberNames = identifier.readableNames([], E, "x/bad", "o").map(String);
  } finally {
    delete Array.prototype.size;
  }
  check("a planted name that borrows a kind's member name is still reported",
        plantedMemberNames.indexOf("size") !== -1);
  check("while the real members of every kind stay unreported",
        identifier.readableNames([], E, "x/bad", "o").length === 0 &&
        identifier.readableNames(new Map(), E, "x/bad", "o").length === 0 &&
        identifier.readableNames(Buffer.alloc(2), E, "x/bad", "o").length === 0 &&
        identifier.readableNames(new DataView(new ArrayBuffer(2)), E, "x/bad", "o").length === 0);
  // The member names are passed over above the value and never on it. An own one shadows the
  // intrinsic, so `opts.detached` answers with the caller's value, and pki.cms.sign reads an
  // option under that name.
  var ownDetached = new ArrayBuffer(2);
  Object.defineProperty(ownDetached, "detached", { value: true, enumerable: true, configurable: true });
  check("an own member name on a buffer is still the caller's option",
        identifier.readableNames(ownDetached, E, "x/bad", "o").join(",") === "detached");
  // A caller's own null-prototype bag has no prototype either, and its OWN names are theirs.
  var nullProto = Object.create(null);
  nullProto.alpha = 1;
  check("a null-prototype bag still reports the names its caller set",
        identifier.readableNames(nullProto, E, "x/bad", "o").join(",") === "alpha");

  // The chain of a collection-kind bag is READ; only the levels that describe a KIND are skipped.
  // Declining to read it at all left a hole with nothing intrinsic anywhere in the chain:
  // `Object.setPrototypeOf([], { password: "pw" })` is still an array by `Array.isArray`, has no
  // `Array.prototype` above it, and `opts.password` resolves. The option went unreported and
  // `pki.key.export` returned a plaintext private key.
  var replacedProto = [];
  Object.setPrototypeOf(replacedProto, { password: "pw" });
  check("the fixture is an array whose chain holds no kind prototype",
        Array.isArray(replacedProto) && Object.getPrototypeOf(replacedProto) !== Array.prototype);
  check("an option on a replaced prototype of an array is reported",
        identifier.readableNames(replacedProto, E, "x/bad", "o").join(",") === "password");
  check("and refused as unknown", errOf(function () {
    identifier.assertKnownKeys(replacedProto, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
  // A subclass sits below the kind's prototype, so its own additions are reported too.
  function SubArr() {}
  SubArr.prototype = Object.create(Array.prototype);
  Object.defineProperty(SubArr.prototype, "gamma", { value: 1, configurable: true });
  var subBag = [];
  Object.setPrototypeOf(subBag, SubArr.prototype);
  check("an option on a subclass prototype of an array is reported",
        identifier.readableNames(subBag, E, "x/bad", "o").join(",") === "gamma");
  // ...while every kind's own surface stays silent, which is what the skip is for.
  ["length", "buffer", "byteLength", "byteOffset", "BYTES_PER_ELEMENT", "size", "parent"]
    .forEach(function (n) { void n; });
  [[], new Uint8Array(2), Buffer.alloc(2), new Map(), new Set(), new ArrayBuffer(2),
    new DataView(new ArrayBuffer(2))].forEach(function (v, i) {
    check("kind " + i + " reports none of its own structural surface",
          identifier.readableNames(v, E, "x/bad", "o").length === 0);
  });

  var viewOpts = new Uint8Array(2); viewOpts.alpha = 1;
  check("a byte view reports the caller's name and not its own surface",
        identifier.readableNames(viewOpts, E, "x/bad", "o").join(",") === "alpha");
  check("a Buffer with nothing added reports nothing",
        identifier.readableNames(Buffer.alloc(2), E, "x/bad", "o").length === 0);
  var mapOpts = new Map(); mapOpts.alpha = 1;
  check("a Map reports the caller's name and not `size`",
        identifier.readableNames(mapOpts, E, "x/bad", "o").join(",") === "alpha");
  check("an ArrayBuffer reports nothing of its own",
        identifier.readableNames(new ArrayBuffer(2), E, "x/bad", "o").length === 0);
  // `length` belongs to an array and a byte view and to nothing else, so on the kinds that have
  // no own one it is a name the caller added and has to be reported like any other.
  var abLen = new ArrayBuffer(2); abLen.length = 5;
  check("a `length` a caller adds to an ArrayBuffer is reported rather than taken for intrinsic",
        identifier.readableNames(abLen, E, "x/bad", "o").join(",") === "length");
  var setLen = new Set(); setLen.length = 5;
  check("and the same on a Set",
        identifier.readableNames(setLen, E, "x/bad", "o").join(",") === "length");
  check("while an array's own intrinsic length stays out",
        identifier.readableNames([1, 2], E, "x/bad", "o").length === 0);

  // The factory is checked before it is needed. The one moment it is called is the moment
  // something has already gone wrong, so a factory that is not one would turn the refusal into a
  // TypeError from inside the guard, at the exact point the guard exists to be clear.
  var noFactory;
  try { identifier.readableNames({}, undefined, "x/bad", "opts"); noFactory = { message: "NO-THROW" }; }
  catch (e) { noFactory = e; }
  check("a missing error factory is named plainly", /needs an error factory/.test(noFactory.message));
  // What it catches is a MISSING or non-callable E. A class cannot be told from a factory by
  // `typeof`, both being functions, so the convention that E is called without `new` stays a
  // convention the adapted-class vector above pins rather than something this can enforce.

  // A Proxy answers `ownKeys` and `get` from two independent traps, so no walk can be complete:
  // one reporting no keys while its get returns a value presents an object every enumeration
  // calls empty and every read calls populated. The object is refused rather than enumerated
  // harder, because a more thorough walk still reads only what a trap chooses to say.
  var liar = new Proxy({}, {
    ownKeys: function () { return []; },
    get: function (_, k) { return k === "gamma" ? 3 : undefined; },
  });
  check("the fixture reports no keys while answering a read",
        Object.getOwnPropertyNames(liar).length === 0 && liar.gamma === 3);
  var liarErr = errOf(function () { identifier.assertKnownKeys(liar, KNOWN, E, "x/bad", "unknown "); });
  check("a Proxy options bag is refused by assertKnownKeys", liarErr.code === "x/bad");
  check("and the refusal names the shape", /Proxy/.test(liarErr.message));
  check("optionsObject refuses it at the entry point too",
        errOf(function () { identifier.optionsObject(liar, E, "x/bad", "opts"); }).code === "x/bad");
  // A Proxy is refused by identity, never by probing its traps for a contradiction: a trap can
  // answer consistently for as long as the check looks and differ afterwards.
  var honest = new Proxy({ alpha: 1 }, {});
  check("a Proxy whose traps are all default is refused on the same rule",
        errOf(function () { identifier.assertKnownKeys(honest, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");
  // A plain object INHERITING from a liar. `opts.gamma` resolves through the chain, so the read
  // reaches the trap while the object handed in is not itself a Proxy: testing only that object
  // leaves one line of indirection open.
  var viaProto = Object.create(liar);
  check("the fixture is not itself a Proxy and still answers through the chain",
        !require("util").types.isProxy(viaProto) && viaProto.gamma === 3);
  var viaErr = errOf(function () { identifier.assertKnownKeys(viaProto, KNOWN, E, "x/bad", "unknown "); });
  check("an object inheriting from a Proxy is refused", viaErr.code === "x/bad");
  check("and the refusal says the bag inherits one", /inherits from a Proxy/.test(viaErr.message));

  // Object.getOwnPropertyNames never returns a Symbol key, so a walk built on it cannot see one.
  // Such a name answers no `opts.password` and reaches no verb, but it is still an option the
  // caller supplied and nothing read, which is the thing being refused.
  var symKey = Symbol("gamma");
  var symBag = {};
  symBag[symKey] = 3;
  check("the fixture is invisible to getOwnPropertyNames but not to Reflect.ownKeys",
        Object.getOwnPropertyNames(symBag).length === 0 && Reflect.ownKeys(symBag).length === 1);
  var symErr = errOf(function () { identifier.assertKnownKeys(symBag, KNOWN, E, "x/bad", "unknown "); });
  check("a Symbol-named unknown option is refused", symErr.code === "x/bad");
  // JSON.stringify returns undefined for a Symbol, which would name the option "undefined".
  check("and the refusal names the symbol", /Symbol\(gamma\)/.test(symErr.message));
  // A caller's own message builder stringifies the key itself, so the Symbol has to be readable
  // before it arrives rather than only in the default builder.
  var builtSym = errOf(function () {
    identifier.assertKnownKeys(symBag, KNOWN, E, "x/bad", function (k) {
      return "unknown extension " + JSON.stringify(k);
    });
  });
  check("a caller's own message builder names the symbol too",
        /Symbol\(gamma\)/.test(builtSym.message));

  // A name IS in the load-time snapshot of Object.prototype and yet is not a built-in: the
  // built-in it shadows has been replaced by a planted value. Snapshot membership alone cannot
  // tell those apart, and the same hole is what a name planted BEFORE this module loads walks
  // through. Every real member is a function-valued data property or an accessor, so a planted
  // value fails the shape test whatever the snapshot says about its name.
  var realToString = Object.prototype.toString;
  var plantedCode, restoredToString;
  Object.defineProperty(Object.prototype, "toString", {
    value: "pw", writable: true, configurable: true, enumerable: false,
  });
  try {
    plantedCode = errOf(function () { identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown "); }).code;
  } finally {
    Object.defineProperty(Object.prototype, "toString", {
      value: realToString, writable: true, configurable: true, enumerable: false,
    });
    restoredToString = (Object.prototype.toString === realToString);
  }
  check("a snapshot name replaced by a planted value is reported", plantedCode === "x/bad");
  check("the vector restores Object.prototype.toString", restoredToString);
  check("the real built-ins still pass the shape test",
        identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown ") === undefined);

  // The built-ins are named from the spec rather than read off the live Object.prototype, because
  // reading them is the runtime under attack answering the question: a name planted before the
  // module loads would be captured as a built-in. That trade needs this test, or an engine adding
  // a member would report it to every caller as an unknown option. Compared here against the live
  // object so the divergence fails in one place instead of at every verb.
  var live = Reflect.ownKeys(Object.prototype).map(String).sort();
  var expected = ["__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
    "__proto__", "constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable",
    "toLocaleString", "toString", "valueOf"].sort();
  check("the spec list matches this runtime's Object.prototype",
        live.length === expected.length && live.every(function (k, i) { return k === expected[i]; }));
  // A plain `{}` reports nothing, which is that agreement observed through the walk itself.
  check("so a plain object reports no readable option name",
        identifier.readableNames({}, E, "x/bad", "opts").length === 0);
}

// The same defense against a name planted BEFORE this module loads, which is the shape that
// actually reaches an operator: guard-identifier snapshots Object.prototype as it loads, so a
// name already there is inside the snapshot and no later comparison can call it foreign. The
// plant has to precede the require, so it runs in a child.
function testPollutionPlantedBeforeLoad() {
  var script = [
    'Object.defineProperty(Object.prototype, "password", { value: "pw", writable: true, configurable: true });',
    'var pki = require(process.argv[1]);',
    'pki.key.generate("Ed25519").then(function (pair) {',
    '  return pki.key.export(pair.privateKey, {});',
    '}).then(function (out) { console.log("ACCEPTED:" + out.length); },',
    '  function (e) { console.log("REFUSED:" + e.code); });',
  ].join("\n");
  var r = spawnSync(process.execPath, ["-e", script, INDEX], { encoding: "utf8" });
  check("the pre-load pollution fixture ran", !r.error && r.status === 0);
  check("a private key is not exported in the clear on a runtime polluted before load",
        /REFUSED:key\/bad-input/.test(r.stdout));
  // A verb given NO options must still work there: it is handed a bag with no prototype, so it
  // inherits nothing and the caller is never refused for a name they did not write.
  var noOpts = [
    'Object.defineProperty(Object.prototype, "password", { value: "pw", writable: true, configurable: true });',
    'var pki = require(process.argv[1]);',
    'pki.key.generate("Ed25519").then(function (pair) { return pki.key.export(pair.publicKey); })',
    '  .then(function (out) { console.log("OK:" + out.length); }, function (e) { console.log("REFUSED:" + e.code); });',
  ].join("\n");
  var r2 = spawnSync(process.execPath, ["-e", noOpts, INDEX], { encoding: "utf8" });
  check("a verb called with no options still works on a polluted runtime", /OK:\d+/.test(r2.stdout));

  // The same plant, function-valued. A shape test alone calls it a built-in, since every real
  // member is function-valued too; only naming the members from the spec separates them.
  var fnPlant = [
    'Object.defineProperty(Object.prototype, "password", { value: function () { return "pw"; },',
    '  writable: true, configurable: true });',
    'var pki = require(process.argv[1]);',
    'pki.key.generate("Ed25519").then(function (pair) {',
    '  return pki.key.export(pair.privateKey, {});',
    '}).then(function (out) { console.log("ACCEPTED:" + out.length); },',
    '  function (e) { console.log("REFUSED:" + e.code); });',
  ].join("\n");
  var r3 = spawnSync(process.execPath, ["-e", fnPlant, INDEX], { encoding: "utf8" });
  check("the function-valued pre-load plant fixture ran", !r3.error && r3.status === 0);
  check("a function-valued name planted before load is reported too",
        /REFUSED:key\/bad-input/.test(r3.stdout));
}

// Every config-time boundary that composes assertKnownKeys must still raise its OWN typed error.
//
// This is the behavioral guard for routing those checks through one home. The failure it catches is
// invisible from the happy path: a caller that hands the guard an error CLASS where it expects a
// (code, message) FACTORY raises "class constructor cannot be invoked without new" instead of the
// verdict -- and only when the check actually fires, which is the branch a valid-input test never
// takes. So each boundary is driven through the SHIPPED verb with an unrecognized key.
async function testConsumersFailClosed() {
  var pki = require("../../index.js");
  var BAD = { nope___: 1 };
  // The issuance verbs check for a signing key BEFORE they walk the spec, so a case built without
  // one never reaches the check under test and passes on an unrelated fault. A real key is cheaper
  // than reordering the verb's gates, which would weaken a check to suit a test.
  var kp = await pki.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var keySpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", kp.publicKey));
  var ISSUER = { key: kp.privateKey, name: [{ commonName: "Test Issuer" }], publicKey: keySpki };
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2027-01-01T00:00:00Z");
  function cert(over) {
    return Object.assign({ subject: [{ commonName: "x" }], subjectPublicKey: keySpki,
      serialNumber: Buffer.from([1]), notBefore: NB, notAfter: NA }, over);
  }
  function crl(over) {
    return Object.assign({ issuer: [{ commonName: "x" }], thisUpdate: NB, nextUpdate: NA }, over);
  }
  function ac(over) {
    return Object.assign({ holder: { entityName: [{ dNSName: "holder.test" }] }, serialNumber: Buffer.from([1]),
      notBeforeTime: NB, notAfterTime: NA, attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:test" } } } }, over);
  }
  var CASES = [
    ["x509.sign extensions", "x509/bad-input", function () { return pki.x509.sign(cert({ extensions: BAD }), ISSUER); }],
    ["csr.sign spec", "csr/bad-input", function () { return pki.csr.sign(Object.assign({ subject: [{ commonName: "x" }] }, BAD), null); }],
    ["crl.sign extensions", "crl/bad-input", function () { return pki.crl.sign(crl({ extensions: BAD }), ISSUER); }],
    ["crl.sign issuingDistributionPoint", "crl/bad-idp", function () { return pki.crl.sign(crl({ extensions: { issuingDistributionPoint: BAD } }), ISSUER); }],
    ["attrcert.sign spec", "attrcert/bad-input", function () { return pki.attrcert.sign(ac(BAD), ISSUER); }],
    ["attrcert.sign holder", "attrcert/bad-input", function () { return pki.attrcert.sign(ac({ holder: BAD }), ISSUER); }],
    ["attrcert.sign attributes", "attrcert/bad-input", function () { return pki.attrcert.sign(ac({ attributes: BAD }), ISSUER); }],
    ["attrcert.sign extensions", "attrcert/bad-input", function () { return pki.attrcert.sign(ac({ extensions: BAD }), ISSUER); }],
    ["crmf.build spec", "crmf/bad-input", function () { return pki.crmf.build(Object.assign({ certTemplate: {} }, BAD), {}); }],
    ["crmf.build certTemplate", "crmf/bad-input", function () { return pki.crmf.build({ certTemplate: BAD }, {}); }],
    ["crmf.build controls", "crmf/bad-input", function () { return pki.crmf.build({ certTemplate: {}, controls: BAD }, {}); }],
    ["cmp.build message", "cmp/bad-input", function () { return pki.cmp.build(Object.assign({ header: {}, body: {} }, BAD), {}); }],
    ["cmp.build opts", "cmp/bad-input", function () { return pki.cmp.build({ header: {}, body: {} }, BAD); }],
    ["cmp.wellKnownUrl opts", "cmp/bad-input", function () { return pki.cmp.wellKnownUrl("https://a.test", BAD); }],
    ["cmp.session opts", "cmp/bad-input", function () { return pki.cmp.session(BAD); }],
    ["cmp.verify opts", "cmp/bad-input", function () { return pki.cmp.verify(Buffer.alloc(4), BAD); }],
    ["ct.fetchLogList opts", "ct/bad-input", function () { return pki.ct.fetchLogList(BAD); }],
    ["webauthn.verifyMetadataBlob opts", "webauthn/bad-input", function () { return pki.webauthn.verifyMetadataBlob("a.b.c", BAD); }],
  ];
  // The assertion is on the code AND on the message naming the offending key. Asserting the code
  // alone is worthless here: every one of these verbs has other config-time faults that raise the
  // same generic code, so a vector whose spec is incomplete passes while never reaching the walk at
  // all -- which is exactly what happened to the first draft of this list.
  for (var i = 0; i < CASES.length; i++) {
    var c = CASES[i], got;
    try { await c[2](); got = "NO-THROW"; }
    catch (e) {
      got = !(e instanceof pki.errors.PkiError) ? "RAW " + e.constructor.name
        : e.message.indexOf("nope___") === -1 ? "reached a different gate: " + e.message.slice(0, 60)
          : e.code;
    }
    check("unknown key at " + c[0] + " -> " + c[1], got === c[1]);
  }
}

async function run() {
  testAcceptsCanonical();
  testSyntaxRejects();
  testBoundsRejects();
  testBoundsWaived();
  testKnownKeys();
  testPollutionPlantedBeforeLoad();
  await testConsumersFailClosed();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
