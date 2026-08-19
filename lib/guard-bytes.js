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
var time = require("./guard-time");
var intrinsic = require("./guard-intrinsic");
// The slot predicates, snapshotted at load. `util.types` is an ordinary object, so reading a
// predicate off it at call time would let a caller decide what this guard calls a typed array, a
// DataView, an ArrayBuffer or a Proxy -- which is every question this module asks about a value it
// was handed.
var util = { types: intrinsic.types };
var _isArray = intrinsic.isArray;
// The Buffer constructor, taken at load. It is how this module turns a backing store into
// something the toolkit can read or clear, so one returning a buffer over DIFFERENT memory hands
// every later step a decoy: a wipe then zeroes the decoy while the plaintext it was aimed at stays
// readable, and every check in between still passes.
var _bufferFrom = intrinsic.bufferFrom;

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

// Where a view's bytes actually are, asked of the language rather than of the view.
//
// `v.buffer`, `v.byteOffset` and `v.byteLength` are accessors on the shared typed-array prototype,
// so `class Opts extends Uint8Array { get buffer() { return elsewhere; } }` answers all three
// questions itself. Two things followed from reading them off the value. A getter that throws left
// this module through the caller's own exception, from a boundary whose contract is a typed error.
// And a getter that lied substituted the memory: an array holding AA AA AA AA whose `buffer`
// returned another store had `view` and `snapshot` hand back that other store's bytes, so the
// bytes a verb went on to hash, sign or parse were not the bytes in the array it was given.
//
// The getters are taken off the prototypes the language installs them on and called against the
// view, which reaches the internal slot whatever the value's own class says. A subclass override
// is then what it is -- a property of the caller's object -- and answers no question asked here.
var _TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);

function _intrinsicGetter(proto, name, who) {
  var d = Object.getOwnPropertyDescriptor(proto, name);
  if (!d || typeof d.get !== "function") {
    throw new TypeError("guard.bytes: this runtime has no intrinsic " + who + "." + name +
      " accessor, so a view's backing store cannot be read without invoking the value's own");
  }
  return d.get;
}

// Uncurried as they are captured, so the reads below invoke them directly. A getter taken off a
// prototype is still reachable there, and an own `call` assigned to it would shadow
// `Function.prototype.call` and hand back whatever store, offset and length a caller chose (see
// guard-intrinsic).
function _uncurriedGetter(proto, name, who) {
  return intrinsic.uncurry(_intrinsicGetter(proto, name, who));
}
var _taBuffer     = _uncurriedGetter(_TYPED_ARRAY_PROTO, "buffer", "%TypedArray%.prototype");
var _taByteOffset = _uncurriedGetter(_TYPED_ARRAY_PROTO, "byteOffset", "%TypedArray%.prototype");
var _taByteLength = _uncurriedGetter(_TYPED_ARRAY_PROTO, "byteLength", "%TypedArray%.prototype");
var _dvBuffer     = _uncurriedGetter(DataView.prototype, "buffer", "DataView.prototype");
var _dvByteOffset = _uncurriedGetter(DataView.prototype, "byteOffset", "DataView.prototype");
var _dvByteLength = _uncurriedGetter(DataView.prototype, "byteLength", "DataView.prototype");

// A DataView carries its own accessors rather than the typed-array ones, so the pair is chosen by
// the value's slot. Either getter refuses a receiver with no slot behind it, which is the same
// refusal a detached store gets, and every caller here already types that.
function _storeOf(v)  { return util.types.isDataView(v) ? _dvBuffer(v) : _taBuffer(v); }
function _offsetOf(v) { return util.types.isDataView(v) ? _dvByteOffset(v) : _taByteOffset(v); }
function _lengthOf(v) { return util.types.isDataView(v) ? _dvByteLength(v) : _taByteLength(v); }

// The Buffer over a view's own bytes. The single place this module turns a view into a Buffer, so
// the intrinsic reads above cannot be skipped at one of the two call sites and kept at the other.
function _reView(v) {
  return _bufferFrom(_storeOf(v), _offsetOf(v), _lengthOf(v));
}

// Which concrete typed-array kind a value is, decided by its slot and answered with this realm's
// own constructor. `v.constructor` is an ordinary inherited property, so a subclass answers it and
// a copy built through it is whatever the caller said.
//
// The pairs are DERIVED from what this runtime offers, never written out. A hand-written list is
// complete on the day it is written and silently short afterwards: `Float16Array` landed on Node 24
// and a list drafted before it refused the kind outright, since the fallback that used to catch it
// was `v.constructor` -- which is the read this table exists to replace. Deriving covers the next
// kind on the day the runtime exposes its predicate, and covers nothing the runtime does not.
//
// `util.types` names each concrete kind's predicate `is<Constructor>`, so the global of that name
// is the constructor for it. `BYTES_PER_ELEMENT` on the CONSTRUCTOR is what separates a concrete
// kind from the umbrella predicates: `isTypedArray` has no `TypedArray` global to pair with, and
// `isArrayBufferView` would pair with none either.
// The predicate FUNCTION is held, never its name. A name is looked up afresh on every call, and
// `util.types` is an ordinary object: replacing a predicate on it after this module loads would
// hand the kind decision, and with it the constructor the copy is built from, to whoever did.
// Reading it once at load leaves nothing to replace.
var _CONCRETE_KINDS = Object.keys(util.types)
  .filter(function (name) { return /^is[A-Za-z0-9]+Array$/.test(name); })
  .map(function (name) { return [util.types[name], globalThis[name.slice(2)]]; })
  .filter(function (row) {
    return typeof row[0] === "function" && typeof row[1] === "function" &&
           typeof row[1].BYTES_PER_ELEMENT === "number" && row[1].BYTES_PER_ELEMENT > 0;
  });

function _concreteKindOf(v) {
  for (var i = 0; i < _CONCRETE_KINDS.length; i++) {
    if (_CONCRETE_KINDS[i][0](v)) return _CONCRETE_KINDS[i][1];
  }
  return null;
}

// A name for a refused value, for the message alone. Taken from what the value IS, since
// `v.constructor.name` is two ordinary property reads a caller answers: a getter under either one
// took the refusal below out through the caller's exception, in place of the typed error whose
// whole purpose here is to say why the value was refused.
var _NAMED_KINDS = [
  ["isNativeError", "Error"], ["isRegExp", "RegExp"], ["isPromise", "Promise"],
  ["isWeakMap", "WeakMap"], ["isWeakSet", "WeakSet"], ["isMap", "Map"], ["isSet", "Set"],
  ["isDate", "Date"], ["isProxy", "Proxy"]
].filter(function (row) { return typeof util.types[row[0]] === "function"; });

function _kindName(v) {
  for (var i = 0; i < _NAMED_KINDS.length; i++) {
    if (util.types[_NAMED_KINDS[i][0]](v)) return _NAMED_KINDS[i][1];
  }
  return typeof v === "function" ? "function" : "value";
}

function _article(name) { return /^[AEIOU]/i.test(name) ? "an" : "a"; }

// outputView(input, ErrorClass, code, label) -> a Buffer aliasing a caller's view, for WRITING.
//
// The same slot-based re-view as `view`, without the shared-memory refusal. That refusal answers a
// question about INPUT: bytes another thread can rewrite after they have been checked cannot be
// checked at all. A write target is the other direction. The caller is asking to be handed random
// bytes in memory they chose, and choosing shared memory is a decision they are entitled to make;
// `crypto.getRandomValues` on a `SharedArrayBuffer`-backed view is ordinary, and both the platform
// and this runtime fill it. Refusing it here turned a supported W3C call into an error.
//
// The bytes still come back through the intrinsic accessors, so a subclass cannot redirect the
// write to memory the caller does not own, and a detached store is still refused.
// @enforced-by behavioral -- an input door reaching for this instead of `view` has no rename-proof
// code shape; the RED vectors (a shared view filled here, and a detached one refused) are the guard.
function outputView(input, ErrorClass, code, label) {
  if (!util.types.isUint8Array(input) && !ArrayBuffer.isView(input)) {
    throw _raise(ErrorClass, code, label + ": expected a Buffer / TypedArray to write into");
  }
  try {
    return _reView(input);
  } catch (e) {
    throw _raise(ErrorClass, code, label + ": output is not a usable byte view (detached backing buffer?)", e);
  }
}

// lengthOf(view) -> how many bytes a view holds, read the same way.
//
// For the boundaries that size a value rather than read it: a response-body cap, an emptiness
// test. `length` is an accessor on the shared typed-array prototype AND shadowable by an own
// property on any instance, so `Object.defineProperty(buf, "length", { get: () => 0 })` answers
// for a Buffer holding megabytes. A cap measured that way is a cap its caller sets.
// @enforced-by behavioral -- `x.length` is the ordinary spelling wherever the value is this
// toolkit's own, so the misuse has no rename-proof code shape; the RED vector (a planted `length`
// getting a body past a documented size cap) is the guard.
function lengthOf(view) {
  return _lengthOf(view);
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
      (ArrayBuffer.isView(v) && util.types.isSharedArrayBuffer(_storeOf(v)))) {
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
// The shape covers the re-view however the view is constructed. It was anchored on `Buffer.from(`
// alone, and `Buffer.from(new Uint8Array(v.buffer, v.byteOffset, v.byteLength))` slipped past it
// into two format modules, where a caller's subclass could answer all three accessors and hand the
// copy a different store than the array held.
// @guard-shape (?:Buffer\.from|new\s+[A-Za-z_$][\w$]*Array)\(\s*(?:new\s+[A-Za-z_$][\w$]*Array\(\s*)?([A-Za-z_$][\w$]*)\.buffer\s*,\s*\1\.byteOffset
function view(input, ErrorClass, code, label) {
  _refuseShared(input, ErrorClass, code, label);
  if (util.types.isUint8Array(input)) {
    try {
      return _reView(input);
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
      return isAb ? _bufferFrom(input) : _reView(input);
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
  return _bufferFrom(view(input, ErrorClass, code, label));
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
  return _bufferFrom(source(input, ErrorClass, code, label));
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
// `Symbol.toStringTag` is the language's own name for what a value is, and a key handle carries it
// as a non-enumerable own property. It answers no named option, so it is surface rather than data,
// and naming it here is what lets the pass-through test below judge every key by the same rule it
// judges every other property by.
// A surface is a table of names, so it is built WITHOUT a prototype. An ordinary object literal
// answers `surface["toString"]` with a function it inherited, and every table is then read as
// though it listed `toString`, `constructor`, `valueOf`, `hasOwnProperty` and `__proto__` -- names
// a caller can write, on an object that is passed on by reference. Membership has to be a fact
// about the table rather than about what any object answers to a lookup.
//
// `Symbol.toStringTag` is on every surface: it is the language's own name for what a value is, a
// key handle carries it as a non-enumerable own property, and it answers no named option.
function _surface(names) {
  var t = Object.create(null);
  names.forEach(function (n) { t[n] = 1; });
  t[Symbol.toStringTag] = 1;
  return t;
}
// `_handle` is this engine's own state on its own key object, the counterpart of the
// `asymmetricKeyType` and `asymmetricKeyDetails` that Node puts on a KeyObject. What it holds
// varies by algorithm -- a KeyObject for a signing key, the raw bytes for an HMAC one -- and it is
// reachable only on a value already recognized as a key, whose material the caller holds anyway.
var _CRYPTO_KEY_SURFACE = _surface(["type", "extractable", "algorithm", "usages",
  "asymmetricKeyType", "asymmetricKeyDetails", "_handle"]);
// The same, for the other kinds whose state cannot be copied: what belongs to the kind, so that
// anything else on the object is recognizably the caller's own and gets the refusal below.
var _ERROR_SURFACE = _surface(["message", "stack", "name", "cause"]);
var _REGEXP_SURFACE = _surface(["lastIndex", "source", "flags", "global", "ignoreCase", "multiline",
  "sticky", "unicode", "unicodeSets", "hasIndices", "dotAll"]);
var _THENABLE_SURFACE = _surface(["then", "catch", "finally"]);

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
  // A node:crypto KeyObject, read off its internal slot. `pki.hpke` documents one as a key input
  // and `pki.ct` names it too, and a copy of a key handle is not a key: its material lives behind
  // the slot, so what the copy holds is the shape of a key and none of the key. Recognized here so
  // it reaches the verb as itself, which is the same treatment a WebCrypto CryptoKey gets.
  // `util.types.isKeyObject` reads the slot, so it answers for a handle from any realm and says no
  // to `Object.create(KeyObject.prototype)`.
  if (util.types.isKeyObject(v)) return _CRYPTO_KEY_SURFACE;
  // Asking whether it is key-shaped reads its properties, and a value wearing a key's prototype
  // without a key behind it answers with a getter that throws: `Object.create(KeyObject.prototype)`
  // raises a raw TypeError from inside `type`. Typed here, like the `then` read below, so a
  // question this module asked on its own behalf cannot escape as somebody else's error.
  var keyLike;
  try {
    keyLike = require("./webcrypto").isCryptoKeyLike(v);   // allow:inline-require -- circular load: webcrypto requires this module
  } catch (e) {
    throw _raise(ErrorClass, code, label + ": reading the key surface threw", e);
  }
  if (keyLike) return _CRYPTO_KEY_SURFACE;
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
// Can this name answer differently after the checks have read it? That is the whole question for a
// value handed on BY REFERENCE, and it is a fact about the property rather than a guess about who
// wrote it. An accessor answers afresh every read. A writable or configurable data property can be
// assigned or redefined. A data property that is neither is settled: whatever the checks saw is
// what the verb gets.
//
// Judged where the property is found, walking up as a read does. A `getPrototypeOf` trap can hand
// back a fresh object forever, so the walk stops at one it has already visited, the same bound the
// name walk uses.
//
// One limit, stated rather than papered over: a caller can still swap the whole prototype after the
// call and change what an inherited name answers. That is true of every value passed by reference,
// and a platform object's prototype is the platform's.
function _canChangeAfterTheCheck(v, name) {
  var visited = new Set();
  for (var o = v; o && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    var d = Object.getOwnPropertyDescriptor(o, name);
    if (!d) continue;
    if (d.get || d.set || d.writable || d.configurable) return true;
    // Settled where it sits. Reached through the chain it is settled only while nothing can be put
    // in front of it: an extensible receiver takes an own property of the same name at any time,
    // and the read then answers with that one. Own on the value itself, or a value nothing can be
    // added to, is the case where what was read is what stays.
    return o !== v && Object.isExtensible(v);
  }
  return false;
}

// Is what a settled binding POINTS AT settled too? A property that cannot be reassigned still
// answers with whatever its value has become: a frozen `signingTime` holding a Date is a binding
// nobody can move and an instant anybody can move, and `pki.cms.sign` signed 2030 while the
// operator read 2040 off the same object afterwards. A primitive cannot change. Another handle is
// settled exactly when the same question about it comes back clean, which is this function one
// level down. Everything else is state the caller keeps, and this module would have copied it.
//
// Bounded, because the chain is the caller's to make as long as they like.
var _SETTLED_DEPTH = 4;
function _settledValueIsFixed(value, ErrorClass, code, label, depth) {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return true;
  if (depth >= _SETTLED_DEPTH) return false;
  // A Proxy answers every question through a handler, so it is never settled and asking is the
  // harm: reading its prototype runs a trap, and a trap that throws would leave this module over
  // a question it asked on its own behalf. `util.types.isProxy` reads the slot and runs nothing.
  if (util.types.isProxy(value)) return false;
  var surface = _opaqueSurface(value, ErrorClass, code, label);
  if (!surface) return false;
  return _opaqueFieldOutsideSurface(value, surface, ErrorClass, code, label, depth + 1) === null;
}

function _opaqueFieldOutsideSurface(v, surface, ErrorClass, code, label, depth) {
  var keys = _namesToCopy(v, ErrorClass, code, label);
  for (var i = 0; i < keys.length; i++) {
    // The kind's own surface, and nothing else. Enumerability says how a property was written,
    // never who wrote it: `Object.defineProperty` is available to a caller as much as to a
    // platform, so skipping the non-enumerable ones let a field ride in on a handle that is
    // passed through BY REFERENCE and stays the caller's to change afterwards. A foreign RegExp
    // carrying a non-enumerable `detached` reached pki.cms.sign that way, and flipping it after
    // the call moved the content out of the message the call had already been asked to sign.
    //
    // The surfaces are what makes this affordable rather than a blanket refusal: each names what
    // the real platform object of that kind carries, so the ordinary value passes and anything
    // beyond it is the caller's. A callable value is no exemption either -- an option is read for
    // what it is, and `signedAttributes` holding a function is neither false nor a method of
    // anything.
    if (surface[keys[i]]) continue;
    // A symbol is not an option. Every verb reads its options by name, so nothing under a symbol
    // key reaches one, and refusing a handle for carrying one buys nothing. What it costs is real:
    // a CryptoKey from another WebCrypto implementation is a documented input, and an
    // implementation that keeps its internals under a symbol -- written the ordinary way, by
    // assignment -- would have its keys refused at every verb.
    //
    // The options door is unaffected and still refuses one. `assertKnownKeys` walks the bag a
    // caller passed as options and reports a symbol there, because a caller who wrote one meant it
    // as an option and no verb will ever read it. That is a different question from whether a key
    // handle may be handed on.
    if (typeof keys[i] === "symbol") continue;
    // A name outside the surface is refused only if it can still move. Enumerability was the old
    // test and it decided the wrong question: it describes how a property was written, and
    // `Object.defineProperty` belongs to a caller as much as to a platform, so a hidden `detached`
    // on a foreign RegExp rode into pki.cms.sign and moved the content out of the signed message
    // after the call. Position was no better -- a key is an argument in its own right at
    // `pki.csr.sign(spec, key)`, so refusing everything at the argument refused the key.
    //
    // Settled data is what an implementation's internals are: this engine writes `_handle` on a key
    // with neither `writable` nor `configurable`, so it cannot be reassigned or redefined, and
    // nothing the checks read about that key can change afterwards. A field a caller can still
    // assign to, redefine, or answer with a getter is the case this refusal is for -- whatever
    // kind of object it rides on, and wherever in the arguments that object sits.
    if (!_canChangeAfterTheCheck(v, keys[i]) &&
      _settledValueIsFixed(v[keys[i]], ErrorClass, code, label, depth || 0)) continue;
    return keys[i];
  }
  return null;
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
  if (collect) collect.push(_bufferFrom(owned, 0, src.length));
  if (Buffer.isBuffer(v)) return _bufferFrom(owned, 0, src.length);
  if (_isArrayBuffer(v)) return owned;
  if (util.types.isDataView(v)) return new DataView(owned);
  // The kind comes from the value's slot, never from `v.constructor` or `v.BYTES_PER_ELEMENT`.
  // Both are ordinary properties a subclass answers: a `constructor` that threw took this module
  // out through the caller's own exception, and a `BYTES_PER_ELEMENT` that lied built the copy
  // with a different element count and a different kind than the value it was copying.
  var Ctor = _concreteKindOf(v);
  if (!Ctor) {
    throw _raise(ErrorClass, code, label + ": a " +
      (util.types.isTypedArray(v) ? "typed array of a kind this runtime added" : "byte view") +
      " cannot be copied while keeping its kind; pass a Buffer or a Uint8Array");
  }
  return new Ctor(owned, 0, src.length / Ctor.BYTES_PER_ELEMENT);
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
// The copy's class is this module's, never the caller's.
//
// A copy used to be given the original's prototype back, so that the walk which reports option
// names read the copy the way it read the original. It does that anyway: a method the caller's
// class defines is not a name that walk reports, so it is never copied across as one, and the two
// sides agree without the prototype. Measured, not assumed -- the vectors compare both.
//
// What restoring it cost was the whole point of copying. The prototype is part of the argument, so
// the copy went on dispatching into the caller's code: `list.map(...)` inside a signing verb
// reached an override on an Array subclass, `getUTCFullYear()` reached one on a Date subclass, and
// an override that threw surfaced the caller's own exception from inside a verb whose contract is
// a typed error. Worse, a prototype can be rewritten after the call has begun, so a copy taken to
// stop the argument changing under the verb changed with it.
function _plainCopy(copy) { return copy; }

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
    //
    // The instant comes through the time guard's intrinsic read. `getTime` is an ordinary method
    // a subclass answers, so reading it off the value put a different instant in the copy than the
    // original holds, and the value validated and the value used were two different reads.
    //
    // What the copy carries is the caller's DATA. A name the language already supplies on a Date
    // is that Date's behavior, and copying an own one down put a caller's function on an object
    // whose whole purpose is to answer as a plain Date holding that instant: an own
    // `getUTCFullYear` that throws rode onto the copy and threw out of pki.cms.sign when the
    // signing time was encoded. Normalizing the prototype does not reach an own shadow, so the
    // shadow is left behind here. The excluded set is read off `Date.prototype` rather than
    // written out, so it cannot fall behind the language.
    var dateCopy = new Date(time.instantOf(v));
    _copyNamed(v, dateCopy, ErrorClass, code, label, cap, depth, collect, _DATE_BEHAVIOR);
    return _plainCopy(dateCopy);
  }
  if (_isArray(v)) {
    var arr = [];
    // The indices a read on the array resolves, rather than a count from zero to `length`. An
    // array is sparse whenever a caller sets a high index or assigns `length`, and
    // `[].length = 4e9` is one statement: walking to `length` then does four billion iterations
    // for an array holding nothing, inside a guard whose job includes keeping a caller's argument
    // from costing unbounded work. Copying the indices that resolve costs what the array actually
    // holds. `length` is carried across afterwards so trailing holes survive and the copy measures
    // the same.
    //
    // Asked of guard-identifier, which owns the same question for names. Its own keys are not the
    // answer: an array consults its prototype for a hole, so a length-one signer list holding its
    // only signer on its prototype reports no own index while every consumer reads one element.
    // Copying the own keys alone handed the verb an empty list.
    var indexE = function (c, m) { return _raise(ErrorClass, c, m); };
    var indices = identifier.readableIndices(v, indexE, code, label);
    // An accessor is refused among the elements for the reason it is refused among the names:
    // reading it once and writing what it returned as plain data leaves the later check nothing
    // to find, since it sees a value and cannot tell an accessor was ever there. The refusal
    // covered names only, so the same trick under an index passed -- and a list is exactly where
    // it pays, an element answering as a trusted signer to the check and as another afterwards.
    // The argument itself, not everything under it, matching the rule for names.
    if (depth === 0) identifier.refuseAccessorFields(v, indices, indexE, code, label);
    indices.forEach(function (k) {
      // Reading an element can run a caller's accessor, the same as reading a named field: an
      // index can carry a getter too, and one that threw escaped as itself from a boundary whose
      // contract is a typed error. Typed here with the raw fault as its cause, as the named walk
      // below does, so an element and a field fail the same way.
      var element;
      try { element = v[k]; }
      catch (e) { throw _raise(ErrorClass, code, label + ": reading element " + k + " threw", e); }
      arr[k] = _deep(element, ErrorClass, code, label, cap, depth + 1, collect);
    });
    arr.length = v.length;
    // An array can carry named properties too, and a verb reads an option by name whatever the
    // argument's type: `opts = []; opts.pem = true` is an options object as far as `opts.pem` is
    // concerned. Copying only the indexed elements dropped those fields, which silently changed
    // what the verb was asked to do instead of failing.
    _copyNamed(v, arr, ErrorClass, code, label, cap, depth, collect);
    return _plainCopy(arr);
  }
  // The only kinds this module cannot read the state of. One carrying nothing of its own is passed
  // through: there is no data on it to fix, and a copy would break it. One carrying its own
  // fields has no safe handling at all: it cannot be copied, and passing it through would leave
  // those fields the caller's to rewrite after the checks read them. That case is refused outright,
  // never half-handled, which is what keeps this from being another shape to be found later.
  var surface = _opaqueSurface(v, ErrorClass, code, label);
  if (surface) {
    // The name that decided it, so the message says which field to move rather than leaving the
    // caller to find it on an object whose whole problem is that its state cannot be read.
    var carried = _opaqueFieldOutsideSurface(v, surface, ErrorClass, code, label);
    if (carried === null) return v;
    throw _raise(ErrorClass, code, label + ": " + _article(_kindName(v)) + " " + _kindName(v) +
      " carrying its own field " + JSON.stringify(String(carried)) + " cannot be used here -- its " +
      "state cannot be copied, so that field would stay changeable after it was checked; pass the " +
      "fields as a plain object");
  }
  if (util.types.isMap(v)) {
    return _plainCopy(_copyEntries(v, new Map(), ErrorClass, code, label, cap, depth, collect));
  }
  if (util.types.isSet(v)) {
    return _plainCopy(_copyEntries(v, new Set(), ErrorClass, code, label, cap, depth, collect));
  }
  // A plain object, or a dictionary with no prototype at all -- never the caller's class.
  //
  // Carrying the class across was for its methods, and it cost what copying is for: the copy went
  // on dispatching into the caller's code, and their class could be rewritten after the call had
  // begun. The names the copy reports do not depend on it, which the vectors measure rather than
  // assume, and no verb calls a method on an options bag.
  //
  // Having NO prototype is different and is kept. `Object.create(null)` and what `JSON.parse`
  // produces inherit nothing, and a copy that gained `Object.prototype` would inherit whatever a
  // runtime has planted there -- names the original never answered, reported against a caller who
  // never wrote them.
  var out = Object.create(Object.getPrototypeOf(v) === null ? null : Object.prototype);
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
//
// Which strings are indices is guard-identifier's to answer, for names and for elements alike. A
// second copy of that test here could drift from it, and the set of names that module passes over
// would then stop matching the set this one carries across as structure.

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
  // The walk uses the intrinsic `forEach`, called against the collection. `forEach` is an ordinary
  // method on `Map.prototype` and `Set.prototype`, so an own one or a subclass's answers instead:
  // one that threw took this module out through the caller's own exception, and one that yielded
  // different entries filled the copy with something other than what the collection holds.
  var walk = util.types.isSet(src) ? Set.prototype.forEach : Map.prototype.forEach;
  walk.call(src, function (value, key) {
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
// The names `Date.prototype` supplies, read off the language rather than written out, so a method
// the language gains later is behavior here on the day it lands.
var _DATE_BEHAVIOR = (function () {
  var t = Object.create(null);
  Reflect.ownKeys(Date.prototype).forEach(function (n) { t[n] = 1; });
  return t;
})();

// `behavior`, when given, names what belongs to the destination's KIND rather than to the caller.
// An own property under one of those names is a shadow of the kind's own method, and copying it
// down would make the copy answer with the caller's function where the original answered with the
// language's. The copy is meant to be that kind holding the caller's data.
function _copyNamed(src, dst, ErrorClass, code, label, cap, depth, collect, behavior) {
  var keys = _namesToCopy(src, ErrorClass, code, label, depth === 0);
  for (var k = 0; k < keys.length; k++) {
    var value;
    // Reading a caller's property can run a caller's accessor, and one that throws is a bad input
    // like any other: the fault gets this boundary's typed code with the raw error as its cause,
    // and never escapes as itself from inside a verb the caller called for something else.
    try { value = src[keys[k]]; }
    catch (e) { throw _raise(ErrorClass, code, label + ": reading " + JSON.stringify(keys[k]) + " threw", e); }
    // A name the destination's KIND already defines, holding a FUNCTION, is a shadow of that
    // kind's own method: copying it down would make the copy answer with the caller's code where
    // the original answered with the language's. The value decides, not the name -- a plain
    // `date.getTime = "unused"` is a field, and dropping it took the caller's typo out of reach of
    // the unknown-option check, which is the silence this release exists to end.
    if (behavior && behavior[keys[k]] && typeof value === "function") continue;
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
  isByteSource: isByteSource, lengthOf: lengthOf, outputView: outputView,
  snapshotDeep: snapshotDeep, fixArguments: fixArguments, fixedCall: fixedCall,
};
