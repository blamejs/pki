// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// primitives whose input boundaries compose these guards (pki.asn1.decode,
// pki.cbor.decode, pki.ct.parseSctList, pki.webcrypto.*).
//
var async = require("./guard-async");
var identifier = require("./guard-identifier");
var util = require("util");

// isByteSource(x) -> boolean: is this one of the four forms the toolkit calls bytes?
//
// A Buffer, any typed-array view, a DataView, or a bare ArrayBuffer. Exported so a door deciding
// whether an argument is bytes asks the module that finally reads them, instead of restating the
// list. A restatement narrows without anyone noticing. An `x instanceof ArrayBuffer` at such a
// door turns away a real buffer from another realm, and the caller's container is then accepted
// at one door and refused at the next.
// @enforced-by behavioral -- a narrowed restatement of a list has no rename-proof code shape;
// the RED vector (a byte form accepted by one door and refused by the other) is the guard.
function isByteSource(x) {
  return Buffer.isBuffer(x) || ArrayBuffer.isView(x) || _isArrayBuffer(x);
}

// Is this value a byte store, asked of the internal slot rather than the prototype?
//
// `v instanceof ArrayBuffer` answers what a value inherits from, which is a different question
// from what it holds. `Object.create(ArrayBuffer.prototype)` inherits everything and holds no
// bytes, so it passes and the read that follows throws a raw TypeError out of a boundary whose
// contract is a typed error. The same test also misses a real buffer from another realm, whose
// prototype is that realm's. `util.types` reads the slot, so both answers come out right.
function _isArrayBuffer(v) {
  return util.types.isArrayBuffer(v);
}

// Shared memory is refused rather than accepted as bytes.
//
// This module exists to hand a verb bytes its caller can no longer change once they have been
// checked, and a SharedArrayBuffer is writable from another thread for as long as it lives, so
// no copy taken here can hold that promise for the value the caller passed. Copying it into a
// private ArrayBuffer would keep the bytes and change the kind, which is the same-kind contract
// broken quietly; refusing says so instead. The message names the shape, since "not a byte
// container" about a container that plainly holds bytes reads as the toolkit being wrong.
function _refuseShared(v, ErrorClass, code, label) {
  if (util.types.isSharedArrayBuffer(v) ||
      (ArrayBuffer.isView(v) && util.types.isSharedArrayBuffer(v.buffer))) {
    throw _raise(ErrorClass, code, label + ": shared memory cannot be used here, because another " +
      "thread can rewrite it after it has been checked; pass a Buffer or a Uint8Array over " +
      "memory this process owns");
  }
}

// guard-bytes -- fail-closed coercion of an untrusted byte-source input to a
// Buffer view. One of the enforced choke points of the guard family: a
// codebase-patterns detector requires every byte-input boundary to route
// through here, so the defense below cannot be forgotten at a new boundary.
//
// Defends the detached-buffer fail-OPEN: a transferred / structuredClone'd
// Buffer or view has a detached backing ArrayBuffer and reads as ZERO-LENGTH.
// An identity fast-path (`Buffer.isBuffer(x) return x`) that skips the re-view
// hands the caller an empty buffer, so a downstream digest / signature / parse
// silently processes EMPTY input instead of failing (CWE-20 improper input
// validation feeding a CWE-347-style verification-of-nothing). Always re-viewing
// through Buffer.from(x.buffer, x.byteOffset, x.byteLength) turns the detached
// read into a typed reject at the boundary. Size / length-field allocation
// bounds (CWE-770 / CWE-400, the parser-DoS class) are not enforced here. They
// are per-format (a multi-MB CRL is legitimate, a Merkle proof is tiny), so they
// live in guard-params and each decoder's own cap.

// Choosing between `view` and `snapshot` at a boundary: a byte argument that is read only
// during the synchronous pass that received it can be re-viewed, because nothing can run
// between the check and the use. One that survives that pass (stored in state, compared
// after an await, embedded into output the verb assembles later) must be snapshotted, or the
// caller can still rewrite the bytes after they were validated. The exceptions are the two
// places holding a caller's SECRET, where a copy is the worse defect: a password or a private
// key is re-viewed and left borrowed only when this module also clears the copy it made, so
// no plaintext duplicate outlives the derivation.

// The guard family threads a caller's typed error under two conventions: most guards take a
// FACTORY (`E(code, message, cause)`, no `new`) because the engines that call them (sign-scheme,
// composite-sig, pki-build) carry a bound factory that prefixes the caller's domain onto the
// code; guard-bytes and guard-header take the error CLASS. A boundary that has only one of the two
// would otherwise have to hand-roll the re-view to reach this guard at all, which is precisely what
// the re-inline detector forbids, so accept either: a class (its prototype is an Error) is
// constructed, anything else is called.
function _raise(E, code, message, cause) {
  return (E.prototype instanceof Error) ? new E(code, message, cause) : E(code, message, cause);
}

// view(input, ErrorClass, code, label) -> Buffer view | throws ErrorClass(code, msg, cause)
// Accepts a Buffer / Uint8Array -- the DER / CBOR / CT / Merkle input contract.
// ErrorClass MUST be a withCause PkiError subclass (the raw detach failure is
// threaded as the cause).
// The kind is read from the slot. A prototype test turns away a real Uint8Array built in another
// realm, whose prototype is that realm's, and tells the caller their bytes are not bytes. It
// admits the mirror shape, `Object.create(Uint8Array.prototype)`, which holds none; that one comes
// back as this guard's own code either way, since the read below is wrapped, so reading the slot
// only moves the refusal to the door from the failing read.
// @enforced-by guard-shape-reinlined
// @guard-shape Buffer\.from\(\s*([A-Za-z_$][\w$]*)\.buffer\s*,\s*\1\.byteOffset
function view(input, ErrorClass, code, label) {
  _refuseShared(input, ErrorClass, code, label);
  if (util.types.isUint8Array(input)) {
    try {
      return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    } catch (e) {
      throw _raise(ErrorClass, code, label + ": input is not a usable byte view (detached backing buffer?)", e);
    }
  }
  throw _raise(ErrorClass, code, label + ": expected a Buffer / Uint8Array");
}

// source(input, ErrorClass, code, label) -> Buffer | throws ErrorClass
// Accepts the full W3C BufferSource (Buffer / TypedArray view / raw ArrayBuffer)
// -- the WebCrypto input contract. Re-views in every case, sharing the caller's
// memory instead of taking a copy: `Buffer.from(arrayBuffer)` wraps the backing
// store, it does not duplicate it. That is what makes this safe to call before a
// size ceiling has been applied (nothing is materialized), and it is also why a
// caller that must hold the bytes across an await wants `snapshotSource`, which
// copies. Throws on a detached backing store.
// @enforced-by guard-shape-reinlined  (the re-view shape is declared on view above)
function source(input, ErrorClass, code, label) {
  _refuseShared(input, ErrorClass, code, label);
  var isAb = _isArrayBuffer(input);
  if (isAb || ArrayBuffer.isView(input)) {
    try {
      return isAb ? Buffer.from(input) : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    } catch (e) {
      throw _raise(ErrorClass, code, label + ": input is not a usable byte source (detached backing buffer?)", e);
    }
  }
  throw _raise(ErrorClass, code, label + ": expected a BufferSource (ArrayBuffer / TypedArray / Buffer)");
}

// snapshot(input, ErrorClass, code, label) -> private Buffer copy | throws ErrorClass
//
// The parse-then-verify time-of-check/time-of-use defense. A verification entry
// point that PARSES its input synchronously and then VERIFIES a signature over
// the same bytes in a later promise turn is reading the caller's memory twice
// with an await in between. Every byte range the parse surfaced (the signed
// content, the signer set, the values the verdict is built from) is a view into
// that memory, so anything that rewrites the buffer in the gap makes the verdict
// describe bytes other than the ones the signature was checked against
// (CWE-367 TOCTOU reaching a CWE-347 wrong-verdict). The window is real without
// an attacker in the process: a caller recycling a pooled read buffer across
// concurrent verifies hits it by accident.
//
// So take one private copy at the boundary and read everything from it. `view`
// re-views and is the right guard where the input is consumed in one synchronous
// pass; this is its sibling for the boundary that spans an await.
// @enforced-by behavioral -- a copy has no rename-proof code shape to detect (any
//   `Buffer.from(x)` is one, and most are legitimate). The guard is the RED vector
//   that mutates the caller's buffer between parse and verify and asserts the
//   verdict still describes the bytes that were verified.
function snapshot(input, ErrorClass, code, label) {
  return Buffer.from(view(input, ErrorClass, code, label));
}

// snapshotSource(input, ErrorClass, code, label) -> private Buffer copy | throws
// The same parse-then-verify defense as `snapshot`, over the whole W3C BufferSource
// (raw ArrayBuffer / DataView / any typed-array view) and not only the
// Buffer / Uint8Array contract. A parser that accepts a BufferSource must snapshot
// the same set: leaving an ArrayBuffer or a DataView aliased reopens the window for
// exactly the inputs that took the wider path in.
// @enforced-by behavioral -- a copy has no rename-proof shape to detect; the guard
//   is the RED vector that mutates the caller's backing buffer across the await.
function snapshotSource(input, ErrorClass, code, label) {
  return Buffer.from(source(input, ErrorClass, code, label));
}

// snapshotDeep(value, ErrorClass, code, label) -> a private copy of every byte leaf | throws
//
// `snapshot` closes the parse-then-verify window for one buffer. This closes it for a whole
// caller-supplied spec: the object a producing verb is handed and then reads across several
// promise turns while it resolves a key, hashes, and signs. Every byte the verb ends up
// encoding reaches it through some field of that object, and the caller still owns all of them,
// so a spec validated at entry and read again after the first turn need not describe the same
// certificate, CRL, or request. It is the same defect as an aliased buffer, one level up: the
// value that passed the checks and the value that gets signed are two different reads.
//
// Copies byte views (through `snapshotSource`, so a detached backing store is refused instead
// of copied as empty), arrays, dates, and plain objects. Everything else (a string, number,
// bigint, boolean, a CryptoKey, any class instance) is passed through by reference, because a
// non-plain object is a platform or library handle whose identity is what makes it work; cloning
// one would break it. `opts.maxDepth` bounds a cyclic or hostile structure; the cap is set far
// above any real spec (the deepest is a certificate policy's UserNotice noticeRef, around 12).
//
// A spec that carries secret material must pass `opts.collect`, an array this fills with every
// buffer it copied. Copying a password or a private key produces a plaintext duplicate, and a
// module whose ownership rules say "a caller's Buffer is borrowed, so leave it alone" will not
// clear it: the copy outlives the operation with no one accountable for it. Collect the copies
// and zeroize them in a `finally`, so the fix for one defect does not open another.
// @enforced-by behavioral -- a copy has no rename-proof code shape to detect (any `Buffer.from(x)`
//   is one). The guards are the RED vector that rewrites a field of the caller's spec after the
//   verb has returned its promise and asserts the emitted artifact carries the entry value, and
//   the vector that holds a reference to every copy and asserts it reads all-zero after the call.
function snapshotDeep(value, ErrorClass, code, label, opts) {
  var o = opts || {};
  var cap = o.maxDepth == null ? 64 : o.maxDepth;
  return _deep(value, ErrorClass, code, label, cap, 0, o.collect || null);
}

// Is this object a handle, meaning something a copy would break instead of duplicate?
//
// The line is not "does it have Object.prototype". A caller's own class instance used as an
// options bag is data, and passing it through by reference on the strength of its prototype left
// exactly the window this exists to close: `cms.sign` accepts any non-Buffer object as options, so
// an instance whose `signedAttributes` flipped to false after the call still reached the signing
// turn. What a copy genuinely breaks is an object whose meaning lives somewhere other than its own
// properties: a key handle, a live collection, a pending result. Those are named here, never
// inferred, because inference gets it wrong in both directions: this engine's own CryptoKey carries
// its Node key handle as an own property, so "has no own keys" would have copied it into a shell
// that cannot sign, while a URL has none and would have copied into one that cannot be read.
// isCryptoKeyLike is the toolkit's own answer to "is this a key handle", the same one key.js and
// jose.js ask, so a foreign implementation's CryptoKey is recognized here too.
// The WebCrypto surface a CryptoKey presents, and nothing else. A real one (this engine's, the
// platform's, or another implementation's) carries exactly these (its key material lives in an
// internal slot or a non-enumerable own property). A caller's options bag that happens to satisfy
// the structural predicate carries its own fields alongside, and those are what give it away.
var _CRYPTO_KEY_SURFACE = { type: 1, extractable: 1, algorithm: 1, usages: 1 };
// The same, for the other kinds whose state cannot be copied: what belongs to the kind, so that
// anything else on the object is recognizably the caller's own and gets the refusal below.
var _ERROR_SURFACE = { message: 1, stack: 1, name: 1, cause: 1 };
var _REGEXP_SURFACE = { lastIndex: 1, source: 1, flags: 1, global: 1, ignoreCase: 1, multiline: 1,
  sticky: 1, unicode: 1, unicodeSets: 1, hasIndices: 1, dotAll: 1 };
var _THENABLE_SURFACE = { then: 1, catch: 1, finally: 1 };

// Is this an object whose state this module cannot read, and therefore cannot copy?
//
// Everything else is copied. Enumerating "handle shapes" to pass through was the wrong shape of
// answer and lost repeatedly: every kind named as a handle turned out to be usable as an options
// bag with fields glued on, and each new shape reopened the window for exactly the fields that
// were glued on. There are only two honest outcomes for a caller's argument: copy it, or refuse
// it. This names the small set where copying is impossible, so the refusal below can be the
// rule for all of them at once, never a shape to be found later.
// The surface an opaque kind is defined by, or null when the value is not one of them. A plain
// object literal is never opaque whatever it looks like: it is data this module can read and copy,
// and isCryptoKeyLike is structural by design so a literal can wear the key shape.
function _opaqueSurface(v, ErrorClass, code, label) {
  var proto = Object.getPrototypeOf(v);
  if (proto === Object.prototype || proto === null) return null;
  if (util.types.isWeakMap(v) || util.types.isWeakSet(v)) return {};   // deliberately not enumerable
  if (v instanceof Error) return _ERROR_SURFACE;
  if (util.types.isRegExp(v)) return _REGEXP_SURFACE;
  if (require("./webcrypto").isCryptoKeyLike(v)) return _CRYPTO_KEY_SURFACE;   // allow:inline-require -- circular load: webcrypto requires this module
  // Asking whether it is a thenable reads a property, and a caller's accessor can throw: the
  // same fault the copy itself types, so it is typed here too and never escapes raw from a
  // question this module asked on its own behalf.
  var then;
  try { then = v.then; }
  catch (e) { throw _raise(ErrorClass, code, label + ": reading \"then\" threw", e); }
  if (typeof then === "function") return _THENABLE_SURFACE;      // a pending result, not a value
  return null;
}

// Is this opaque object safe to pass through, carrying nothing beyond the surface its kind is
// defined by? Anything more is the case with no safe answer: the object cannot be copied, and
// passing it through would leave that data the caller's to change after the checks have read it.
// Every reachable name is examined, not only the own ones; a verb reads a field by name and does
// not care where on the chain it sits.
function _opaqueIsSafeToPass(v, surface, ErrorClass, code, label) {
  var keys = _namesToCopy(v, ErrorClass, code, label);
  for (var i = 0; i < keys.length; i++) {
    if (surface[keys[i]]) continue;
    // Only what the caller put there. An implementation's own internals are non-enumerable by
    // construction (this engine's key handle, a platform object's slots), and so are the methods
    // on any prototype, built-in or class-declared. What a caller adds, they add by assignment,
    // which is enumerable; that is the case the refusal is for, whatever the value's type. A
    // callable value is no exemption: an option is read for what it is, and `signedAttributes`
    // holding a function is neither false nor a method of anything.
    //
    // Enumerability is also the line for a SYMBOL key, which this walk reports so a caller
    // cannot hide a field on a handle that is passed through by reference and stays theirs to
    // change. A platform that cached under an enumerable symbol would have its keys refused
    // here, so the vectors pin both directions on a real `node:crypto` CryptoKey: one passes
    // through untouched, and one carrying a caller-added symbol is refused. If a future runtime
    // ever does cache that way, that first vector fails at the upgrade rather than an operator's
    // key being refused in production.
    if (!_wasEnumerable(v, keys[i])) continue;
    return false;
  }
  return true;
}

// A private copy of a byte value of the same kind the caller passed. The kind is
// load-bearing: each verb's own field validators decide which byte forms that field accepts, and
// most accept only Buffer / Uint8Array. Handing them a Buffer made from a DataView or a
// Uint16Array would have those inputs quietly accepted, reinterpreted through a platform's own
// element layout, where they were rejected before. Copying is not the place to decide what a
// field takes, so the copy preserves the type and the validator still sees what it was given.
function _copyBytesSameKind(v, ErrorClass, code, label, collect) {
  var src = source(v, ErrorClass, code, label);   // re-views; a detached backing store is refused
  var owned = new ArrayBuffer(src.length);
  new Uint8Array(owned).set(src);
  // What `release` clears: a Buffer over the whole private store, whatever kind is handed back.
  if (collect) collect.push(Buffer.from(owned, 0, src.length));
  if (Buffer.isBuffer(v)) return Buffer.from(owned, 0, src.length);
  if (_isArrayBuffer(v)) return owned;
  if (util.types.isDataView(v)) return new DataView(owned);
  return new v.constructor(owned, 0, src.length / v.BYTES_PER_ELEMENT);
}

// Is this value's prototype chain cyclic? A Proxy whose `getPrototypeOf` trap returns the proxy
// itself makes one, and the engine permits it while the target stays extensible.
//
// It has to be asked before anything else this module does with the value. Almost every question
// about a kind is an `instanceof`, and `instanceof` walks the prototype chain. On a cyclic chain
// it exhausts the stack, and a raw RangeError escapes from a guard whose whole contract is a
// typed error.
//
// Naming the shape is the fail-closed answer. An options bag cannot need a prototype chain that
// loops, and copying one has no meaning to fall back to.
function _protoChainIsCyclic(v) {
  var visited = new Set();
  for (var o = v; o; o = Object.getPrototypeOf(o)) {
    if (visited.has(o)) return true;
    visited.add(o);
  }
  return false;
}

// Is a Proxy anywhere on this chain? The copy reads names from the whole chain, so one sitting
// above a plain object decides what the copy takes while the original answers reads from its
// `get` trap. Testing only the value handed in leaves that one line of indirection open.
function _protoChainHasProxy(v) {
  var visited = new Set();
  for (var o = v; o && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    if (util.types.isProxy(o)) return true;
  }
  return false;
}

// Give the copy of a collection the same prototype the original carries.
//
// The object branch does this with `Object.create(Object.getPrototypeOf(v))`, so an instance of a
// caller's class keeps its methods. A collection branch builds a plain `[]`, `Map` or `Set`, and
// a subclass of one holds its additions on a prototype above that. Copying the chain down onto a
// plain array turns `class Opts extends Array { describe() {} }` into an array with `describe` as
// an own function that nothing above supplies, which the check reads as a typed option and
// refuses, though the same bag passed that check before the copy.
//
// A subclass of a built-in is the caller's own class, so this is the same trade the object branch
// makes. The prototype is theirs and stays theirs, while every readable name is copied down so no
// value is re-read through it after the checks have run.
function _keepPrototype(from, copy) {
  var proto = Object.getPrototypeOf(from);
  if (proto !== Object.getPrototypeOf(copy)) Object.setPrototypeOf(copy, proto);
  return copy;
}

function _deep(v, ErrorClass, code, label, cap, depth, collect) {
  if (depth > cap) throw _raise(ErrorClass, code, label + " is nested too deeply to copy");
  if (v == null || typeof v !== "object") return v;
  _refuseShared(v, ErrorClass, code, label);
  // The Proxy test comes FIRST, ahead of the cycle walk and every `instanceof` below, because
  // both of those read the prototype chain and a `getPrototypeOf` trap runs the caller's code.
  // A trap that throws then escapes as its own raw Error from a guard whose whole contract is a
  // typed one. This test reaches `Object.getPrototypeOf` only on links it has already cleared,
  // so no trap runs before the refusal that makes running it unnecessary.
  //
  // A Proxy answers `ownKeys` and `get` from two independent traps, so the copy takes the names
  // one trap reports while the original answers reads from the other. One reporting no keys and
  // returning "pw" for `password` copies to an object holding nothing, and the field the caller
  // supplied is gone with no fault raised. Copying it is therefore not copying it, which is the
  // case this refusal is for: an argument is copied or refused, never half-taken.
  if (_protoChainHasProxy(v)) {
    throw _raise(ErrorClass, code, label + ": a Proxy cannot be copied faithfully, because the " +
      "keys it reports need not be the ones it answers; pass a plain object");
  }
  // A second line under the Proxy rule, and unreachable while that one holds: `setPrototypeOf`
  // refuses to build a cycle out of ordinary objects, so a Proxy is the only way to have one and
  // the refusal above already covers every such value. It stays because the cost is one walk and
  // the failure it prevents is an unbounded loop rather than a wrong answer.
  if (_protoChainIsCyclic(v)) {
    throw _raise(ErrorClass, code, label + ": its prototype chain is a cycle, so it cannot be " +
      "read or copied; pass a plain object");
  }
  if (Buffer.isBuffer(v) || ArrayBuffer.isView(v) || _isArrayBuffer(v)) {
    var bytesCopy = _copyBytesSameKind(v, ErrorClass, code, label, collect);
    // A byte value can carry named properties too, and a verb reads an option by name whatever the
    // argument's type: `opts = new Uint8Array(0); opts.pem = true` is an options object as far as
    // `opts.pem` is concerned. An ArrayBuffer is extensible and takes them the same way.
    _copyNamed(v, bytesCopy, ErrorClass, code, label, cap, depth, collect);
    return bytesCopy;
  }
  // A parsed structure carrying guard-parsed's provenance record is a handle: the record is keyed
  // on the object's identity, so a copy of it carries none and every door that decides integrity
  // refuses the copy. It is also safe to leave alone, since that door re-derives from the bytes the
  // record names, so nothing done to the object since matters. That holds for it as a parse
  // result; a caller who adds an option to one and passes it where options are read by name has
  // added a field no door re-derives, so `AsProduced` is what is asked, not `isRecorded`.
  // Required inline because guard-parsed requires this module; at call time it is fully loaded.
  if (require("./guard-parsed").isRecordedAsProduced(v)) return v;   // allow:inline-require -- circular load: guard-parsed requires this module
  if (util.types.isDate(v)) {
    // A Date can carry named properties too, and a verb reads an option by name whatever the
    // argument's type. Returning the instant alone dropped anything the caller had added, so the
    // copy held nothing while the original still answered, and the check read the copy.
    var dateCopy = new Date(v.getTime());
    _copyNamed(v, dateCopy, ErrorClass, code, label, cap, depth, collect);
    return _keepPrototype(v, dateCopy);
  }
  if (Array.isArray(v)) {
    var arr = [];
    // The indices that are present, rather than a count from zero to `length`. An array is sparse
    // whenever a caller sets a high index or assigns `length`, and `[].length = 4e9` is one
    // statement: walking to `length` then does four billion iterations for an array holding
    // nothing, inside a guard whose job includes keeping a caller's argument from costing
    // unbounded work. Copying the present indices costs what the array actually holds. `length`
    // is carried across afterwards so trailing holes survive and the copy measures the same.
    Reflect.ownKeys(v).forEach(function (k) {
      if (typeof k !== "string" || !_isArrayIndex(k)) return;
      arr[k] = _deep(v[k], ErrorClass, code, label, cap, depth + 1, collect);
    });
    arr.length = v.length;
    // An array can carry named properties too, and a verb reads an option by name whatever the
    // argument's type: `opts = []; opts.pem = true` is an options object as far as `opts.pem` is
    // concerned. Copying only the indexed elements dropped those fields, which silently changed
    // what the verb was asked to do instead of failing.
    _copyNamed(v, arr, ErrorClass, code, label, cap, depth, collect);
    return _keepPrototype(v, arr);
  }
  // The only kinds this module cannot read the state of. One carrying nothing of its own is passed
  // through: there is no data on it to fix, and a copy would break it. One carrying its own
  // fields has no safe handling at all: it cannot be copied, and passing it through would leave
  // those fields the caller's to rewrite after the checks read them. That case is refused outright,
  // never half-handled, which is what keeps this from being another shape to be found later.
  var surface = _opaqueSurface(v, ErrorClass, code, label);
  if (surface) {
    if (_opaqueIsSafeToPass(v, surface, ErrorClass, code, label)) return v;
    throw _raise(ErrorClass, code, label + ": a " + (v.constructor && v.constructor.name || "value") +
      " carrying its own fields cannot be used here -- its state cannot be copied, so those fields " +
      "would stay changeable after they were checked; pass the fields as a plain object");
  }
  if (util.types.isMap(v)) {
    return _keepPrototype(v, _copyEntries(v, new Map(), ErrorClass, code, label, cap, depth, collect));
  }
  if (util.types.isSet(v)) {
    return _keepPrototype(v, _copyEntries(v, new Set(), ErrorClass, code, label, cap, depth, collect));
  }
  // The prototype is kept so an instance's methods still resolve. A null-prototype dictionary
  // (what `JSON.parse` or an explicit `Object.create(null)` produces) must not come back
  // inheriting from Object.prototype either, which is why the prototype is carried across and
  // never assumed.
  var out = Object.create(Object.getPrototypeOf(v));
  _copyNamed(v, out, ErrorClass, code, label, cap, depth, collect);
  return out;
}

// Which names to carry across, given what the copy is.
//
// For a plain object or a class instance (the shapes an options bag actually takes) it is every
// name a lookup could resolve, inherited included, because that is what the verb reads.
//
// For an array, a byte view, a Map or a Set, it is the caller's own added names only. Their
// prototypes are full of accessors that describe the kind, not the caller (`length`,
// `buffer`, `size`, and Node's `parent`, which hands back the 64 KiB arena a small Buffer was
// allocated from). Every one of those is already correct on the copy, and reading them would
// copy things the caller never passed. Enumerating the accessors to skip is the wrong way round;
// what the caller added is exactly what is own and not an index.
// An ARRAY INDEX as the language defines one: an integer in [0, 2^32 - 2] whose canonical decimal
// spelling is the string itself. Kept identical to guard-identifier's copy of this question, so
// the set of names that module checks and the set this one copies cannot disagree.
function _isArrayIndex(k) {
  var n = Number(k);
  return Number.isInteger(n) && n >= 0 && n < 4294967295 && String(n) === k;
}

// The names to carry across, asked of the module that decides which names a caller supplied.
//
// One walk answers for both questions, because a second walk here drifts from it and the two then
// disagree about one value. A walk that stops at whatever object is identical to `Object.prototype`
// reads a foreign realm's root as caller data and copies `__proto__` down as a field. One that
// reads every level outside a collection gives `Object.create(Array.prototype)` an own `length`
// and `Symbol.unscopables`. Either way the copy holds a different set than the check accepted, and
// a bag that passes the check is refused once it has been copied.
//
// The prototype is kept on every branch, so a name skipped here still resolves through it, and the
// indices of an array are carried by that branch as the structure they are. What the check reads
// is therefore what the copy answers to.
function _namesToCopy(src, ErrorClass, code, label, atArgument) {
  var E = function (c, m) { return _raise(ErrorClass, c, m); };
  var names = identifier.readableNames(src, E, code, label);
  // Refused here as well as at the options door, because this copy runs FIRST for the verbs that
  // take a spec. Reading an accessor and writing what it returned as plain data leaves the later
  // check nothing to find: it sees a value and cannot tell an accessor was ever there, so a field
  // that answers differently on the next read passes as a settled one.
  //
  // The argument itself, not everything under it. A platform object nested in a spec carries its
  // own accessors, and a Node KeyObject inside a signer holds `asymmetricKeyType` among others;
  // those belong to the platform and refusing them turns an ordinary signer into a bad input.
  if (atArgument) identifier.refuseAccessorFields(src, names, E, code, label);
  return names;
}

// A Map or a Set is data the caller can still change, entry by entry, so it is copied like any
// other: entries first, then the named properties one can carry alongside them.
function _copyEntries(src, dst, ErrorClass, code, label, cap, depth, collect) {
  src.forEach(function (value, key) {
    var copiedValue = _deep(value, ErrorClass, code, label, cap, depth + 1, collect);
    if (util.types.isSet(dst)) dst.add(copiedValue);
    else dst.set(_deep(key, ErrorClass, code, label, cap, depth + 1, collect), copiedValue);
  });
  _copyNamed(src, dst, ErrorClass, code, label, cap, depth, collect);
  return dst;
}

// Copy every value a name lookup on `src` could reach onto `dst`, as an own data property.
//
// Own matters: a key literally named `__proto__` would otherwise re-point `dst`, so the field the
// caller passed disappears from Object.keys and an unknown-option check walks a different object
// than the verb goes on to read. Shadowing matters for the same reason it is done at all: an own
// copy is what makes an inherited value stop tracking the caller's prototype. A method is left
// where it is, since copying a function would only move it, and it is the prototype's behavior,
// not the caller's data.
function _copyNamed(src, dst, ErrorClass, code, label, cap, depth, collect) {
  var keys = _namesToCopy(src, ErrorClass, code, label, depth === 0);
  for (var k = 0; k < keys.length; k++) {
    var value;
    // Reading a caller's property can run a caller's accessor, and one that throws is a bad input
    // like any other: the fault gets this boundary's typed code with the raw error as its cause,
    // and never escapes as itself from inside a verb the caller called for something else.
    try { value = src[keys[k]]; }
    catch (e) { throw _raise(ErrorClass, code, label + ": reading " + JSON.stringify(keys[k]) + " threw", e); }
    // A function is carried across by reference, since there is nothing in it to copy, but it is
    // still carried. Dropping it changed what the caller passed: an unknown spec
    // field whose value happened to be a function stopped reaching the verb's own key check, so a
    // typo that used to be refused was silently accepted.
    Object.defineProperty(dst, keys[k], {
      value: typeof value === "function" ? value
        : _deep(value, ErrorClass, code, label, cap, depth + 1, collect),
      writable: true, enumerable: _wasEnumerable(src, keys[k]), configurable: true,
    });
  }
}

// Whether a name lookup on `v` would have found this property as an enumerable one, anywhere on
// the chain -- so the copy's own keys enumerate the way the original's did.
function _wasEnumerable(v, name) {
  for (var o = v; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
    var d = Object.getOwnPropertyDescriptor(o, name);
    if (d) return !!d.enumerable;
  }
  return false;
}

// fixArguments(ErrorClass, code, args) -> { values, release }
//
// The whole rule for a verb that spans a promise turn, in one call. `args` is a list of
// `[value, label]` pairs, one per argument the verb was handed. Each is deep-copied, so no field
// of any of them, at any depth, is still the caller's to change once the verb has begun; `release`
// clears every copy that was made and belongs in a `finally`, so a copied password or private key
// does not outlive the call.
//
// Both halves are needed and neither is optional. Copying only the argument that looks like data
// leaves a secret nested inside the one that looks like a handle (`opts.mac.secret` sitting a
// level below a shallow copy) readable and rewritable across the turn. Copying without releasing
// answers that by duplicating the secret instead. Deciding per field which is which is the judgment
// that keeps going wrong, so there is no per-field decision here: everything is copied, everything
// copied is cleared, and the only things left alone are the ones a copy would break: a CryptoKey
// or any class instance (its identity is what makes it work) and a recorded parse result (its
// provenance is keyed to the object).
// @enforced-by behavioral -- there is no rename-proof code shape for "copied every argument". The
//   guard is the per-verb RED vector that mutates each argument after the verb returns its promise
//   and asserts the artifact carries the entry value.
function fixArguments(ErrorClass, code, args) {
  var copies = [];
  var values = [];
  // Through guard.secret, which owns what clearing a secret means. Required inline because
  // guard-secret requires this module; at call time it is fully loaded.
  function release() {
    require("./guard-secret").zeroizeAll(copies, ErrorClass, code,   // allow:inline-require -- circular load: guard-secret requires this module
      "a copy of a caller-supplied argument");
  }
  try {
    for (var i = 0; i < args.length; i++) {
      values.push(snapshotDeep(args[i][0], ErrorClass, code, args[i][1], { collect: copies }));
    }
  } catch (e) {
    // The copying itself can fail partway (a detached leaf, a structure past the depth cap, a
    // getter that throws), and the arguments already copied by then are just as much ours as if
    // the call had gone on to succeed. Returning nothing would leave the caller with no handle to
    // release them, so a signer key or a password copied before the fault would stay readable for
    // as long as the heap held it. Clear what was made, then let the fault out unchanged.
    release();
    throw e;
  }
  return { values: values, release: release };
}

// fixedCall(ErrorClass, code, args, body) -> Promise
//
// The form every Promise-returning producing verb uses, because the halves have to be arranged in
// exactly one way and this is it. The copy runs inside guard-async's boundary, so a fault in the
// copy itself (a detached view, a structure nested past the cap, a getter that throws) leaves
// as a rejection like every other fault of a verb documented `-> Promise<...>`, never as a
// synchronous throw past the caller's `.catch`. It still runs at the call, before any turn passes,
// which is what fixes the arguments. And the release runs whether the body resolved, rejected, or
// never ran, so a copied secret is cleared on every path out.
// @enforced-by behavioral -- an arrangement of two calls has no rename-proof shape to detect. The
//   guards are promise-contract.test.js (every documented Promise verb refuses by rejecting, now
//   including a fault raised by the copy itself) and the per-verb entry-value vectors.
function fixedCall(ErrorClass, code, args, body) {
  var handle = null;
  return async.deferred(function () {
    handle = fixArguments(ErrorClass, code, args);
    return body.apply(null, handle.values);
  }).finally(function () { if (handle) handle.release(); });
}

module.exports = {
  view: view, source: source, snapshot: snapshot, snapshotSource: snapshotSource,
  isByteSource: isByteSource,
  snapshotDeep: snapshotDeep, fixArguments: fixArguments, fixedCall: fixedCall,
};
