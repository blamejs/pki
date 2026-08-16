// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// primitives whose input boundaries compose these guards (pki.asn1.decode,
// pki.cbor.decode, pki.ct.parseSctList, pki.webcrypto.*).
//
var async = require("./guard-async");

// guard-bytes -- fail-closed coercion of an untrusted byte-source input to a
// Buffer view. One of the enforced choke points of the guard family: a
// codebase-patterns detector requires every byte-input boundary to route
// through here, so the defence below cannot be forgotten at a new boundary.
//
// Defends the detached-buffer fail-OPEN: a transferred / structuredClone'd
// Buffer or view has a detached backing ArrayBuffer and reads as ZERO-LENGTH.
// An identity fast-path (`Buffer.isBuffer(x) return x`) that skips the re-view
// hands the caller an empty buffer, so a downstream digest / signature / parse
// silently processes EMPTY input instead of failing (CWE-20 improper input
// validation feeding a CWE-347-style verification-of-nothing). Always re-viewing
// through Buffer.from(x.buffer, x.byteOffset, x.byteLength) turns the detached
// read into a typed reject at the boundary. Size / length-field allocation
// bounds (CWE-770 / CWE-400, the parser-DoS class) are NOT enforced here -- they
// are per-format (a multi-MB CRL is legitimate, a Merkle proof is tiny), so they
// live in guard-params and each decoder's own cap.

// Choosing between `view` and `snapshot` at a boundary: a byte argument that is read only
// during the synchronous pass that received it can be re-VIEWED, because nothing can run
// between the check and the use. One that survives that pass -- stored in state, compared
// after an await, embedded into output the verb assembles later -- must be SNAPSHOT, or the
// caller can still rewrite the bytes after they were validated. The exceptions are the two
// places holding a caller's SECRET, where a copy is the worse defect: a password or a private
// key is re-viewed and left borrowed only when this module also clears the copy it made, so
// no plaintext duplicate outlives the derivation.

// The guard family threads a caller's typed error under two conventions: most guards take a
// FACTORY (`E(code, message, cause)`, no `new`) because the engines that call them -- sign-scheme,
// composite-sig, pki-build -- carry a bound factory that prefixes the caller's domain onto the
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
// @enforced-by guard-shape-reinlined
// @guard-shape Buffer\.from\(\s*([A-Za-z_$][\w$]*)\.buffer\s*,\s*\1\.byteOffset
function view(input, ErrorClass, code, label) {
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
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
// -- the WebCrypto input contract. Re-VIEWS in every case, sharing the caller's
// memory rather than taking a copy: `Buffer.from(arrayBuffer)` wraps the backing
// store, it does not duplicate it. That is what makes this safe to call before a
// size ceiling has been applied -- nothing is materialized -- and it is also why a
// caller that must hold the bytes across an await wants `snapshotSource`, which
// copies, rather than this. Throws on a detached backing store.
// @enforced-by guard-shape-reinlined  (the re-view shape is declared on view above)
function source(input, ErrorClass, code, label) {
  var isAb = input instanceof ArrayBuffer;
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
// The parse-then-verify time-of-check/time-of-use defence. A verification entry
// point that PARSES its input synchronously and then VERIFIES a signature over
// the same bytes in a later promise turn is reading the caller's memory twice
// with an await in between. Every byte range the parse surfaced -- the signed
// content, the signer set, the values the verdict is built from -- is a VIEW into
// that memory, so anything that rewrites the buffer in the gap makes the verdict
// describe bytes other than the ones the signature was checked against
// (CWE-367 TOCTOU reaching a CWE-347 wrong-verdict). The window is real without
// an attacker in the process: a caller recycling a pooled read buffer across
// concurrent verifies hits it by accident.
//
// So take one private copy at the boundary and read EVERYTHING from it. `view`
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
// The same parse-then-verify defence as `snapshot`, over the FULL W3C BufferSource
// (raw ArrayBuffer / DataView / any typed-array view) rather than only the
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
// `snapshot` closes the parse-then-verify window for ONE buffer. This closes it for a whole
// caller-supplied SPEC -- the object a producing verb is handed and then reads across several
// promise turns while it resolves a key, hashes, and signs. Every byte the verb ends up
// encoding reaches it through some field of that object, and the caller still owns all of them,
// so a spec validated at entry and read again after the first turn need not describe the same
// certificate, CRL, or request. It is the same defect as an aliased buffer, one level up: the
// value that passed the checks and the value that gets signed are two different reads.
//
// Copies byte views (through `snapshotSource`, so a detached backing store is refused rather
// than copied as empty), arrays, dates, and PLAIN objects. Everything else -- a string, number,
// bigint, boolean, a CryptoKey, any class instance -- is passed through by reference, because a
// non-plain object is a platform or library handle whose identity is what makes it work; cloning
// one would break it. `opts.maxDepth` bounds a cyclic or hostile structure; the cap is set far
// above any real spec (the deepest is a certificate policy's UserNotice noticeRef, around 12).
//
// **A spec that carries SECRET material must pass `opts.collect`**, an array this fills with every
// buffer it copied. Copying a password or a private key produces a plaintext duplicate, and a
// module whose ownership rules say "a caller's Buffer is borrowed, so leave it alone" will not
// clear it -- the copy outlives the operation with no one accountable for it. Collect the copies
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

// Is this object a HANDLE -- something a copy would break rather than duplicate?
//
// The line is not "does it have Object.prototype". A caller's own class instance used as an
// options bag is data, and passing it through by reference on the strength of its prototype left
// exactly the window this exists to close: `cms.sign` accepts any non-Buffer object as options, so
// an instance whose `signedAttributes` flipped to false after the call still reached the signing
// turn. What a copy genuinely breaks is an object whose meaning lives somewhere other than its own
// properties -- a key handle, a live collection, a pending result. Those are named here rather than
// inferred, because inference gets it wrong in both directions: this engine's own CryptoKey carries
// its Node key handle as an own property, so "has no own keys" would have copied it into a shell
// that cannot sign, while a URL has none and would have copied into one that cannot be read.
// isCryptoKeyLike is the toolkit's own answer to "is this a key handle" -- the same one key.js and
// jose.js ask -- so a foreign implementation's CryptoKey is recognized here too.
function _isHandle(v) {
  if (require("./guard-parsed").isRecorded(v)) return true;   // allow:inline-require -- circular load: guard-parsed requires this module
  if (require("./webcrypto").isCryptoKeyLike(v)) return true; // allow:inline-require -- circular load: webcrypto requires this module
  if (typeof v.then === "function") return true;              // a promise or any thenable
  if (v instanceof Map || v instanceof Set || v instanceof WeakMap || v instanceof WeakSet) return true;
  if (v instanceof RegExp || v instanceof Error) return true;
  return false;
}

// Every property name a `v.field` lookup could resolve: own and inherited, enumerable or not.
//
// The enumerable-only version of this was wrong three times running, each time in the same
// direction -- own keys missed an inherited field, enumerable keys missed a non-enumerable one --
// and each miss left the caller's object reachable behind a copy that looked complete. A verb reads
// an option BY NAME, so the set that has to be fixed is the set a name lookup can reach, and
// nothing narrower. Object.prototype's own members are excluded: they are the language's, not the
// caller's, and copying them onto every spec would shadow the prototype for no gain.
function _reachableKeys(v) {
  var names = [];
  var seen = Object.create(null);
  for (var o = v; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
    var own = Object.getOwnPropertyNames(o);
    for (var i = 0; i < own.length; i++) {
      if (own[i] === "constructor" || seen[own[i]]) continue;
      seen[own[i]] = true;
      names.push(own[i]);
    }
  }
  return names;
}

// A private copy of a byte value that is the SAME KIND as what the caller passed. The kind is
// load-bearing: each verb's own field validators decide which byte forms that field accepts, and
// most accept only Buffer / Uint8Array. Handing them a Buffer made from a DataView or a
// Uint16Array would have those inputs quietly accepted -- reinterpreted through a platform's own
// element layout -- where they were rejected before. Copying is not the place to decide what a
// field takes, so the copy preserves the type and the validator still sees what it was given.
function _copyBytesSameKind(v, ErrorClass, code, label, collect) {
  var src = source(v, ErrorClass, code, label);   // re-views; a detached backing store is refused
  var owned = new ArrayBuffer(src.length);
  new Uint8Array(owned).set(src);
  // What `release` clears: a Buffer over the whole private store, whatever kind is handed back.
  if (collect) collect.push(Buffer.from(owned, 0, src.length));
  if (Buffer.isBuffer(v)) return Buffer.from(owned, 0, src.length);
  if (v instanceof ArrayBuffer) return owned;
  if (v instanceof DataView) return new DataView(owned);
  return new v.constructor(owned, 0, src.length / v.BYTES_PER_ELEMENT);
}

function _deep(v, ErrorClass, code, label, cap, depth, collect) {
  if (depth > cap) throw _raise(ErrorClass, code, label + " is nested too deeply to copy");
  if (v == null || typeof v !== "object") return v;
  if (Buffer.isBuffer(v) || ArrayBuffer.isView(v) || v instanceof ArrayBuffer) {
    return _copyBytesSameKind(v, ErrorClass, code, label, collect);
  }
  // A parsed structure carrying guard-parsed's provenance record is a HANDLE: the record is keyed
  // on the object's identity, so a copy of it carries none and every door that decides integrity
  // refuses the copy. It is also already safe to leave alone -- that door re-parses from the bytes
  // the record names, so nothing done to the object since matters. Required inline because
  // guard-parsed requires this module; at call time it is fully loaded.
  if (require("./guard-parsed").isRecorded(v)) return v;   // allow:inline-require -- circular load: guard-parsed requires this module
  if (v instanceof Date) return new Date(v.getTime());
  if (Array.isArray(v)) {
    var arr = [];
    for (var i = 0; i < v.length; i++) arr.push(_deep(v[i], ErrorClass, code, label, cap, depth + 1, collect));
    return arr;
  }
  if (_isHandle(v)) return v;
  var proto = Object.getPrototypeOf(v);
  // Same prototype, and every key defined as an OWN data property. Neither is cosmetic. A
  // null-prototype dictionary -- what `JSON.parse` reviving or an explicit `Object.create(null)`
  // produces -- must not come back inheriting from Object.prototype, and a key literally named
  // `__proto__` must stay an own property: plain assignment would instead re-point the clone's
  // prototype, so the field the caller passed disappears from `Object.keys` and an unknown-option
  // check walks a different object than the one the verb goes on to read.
  // The prototype is kept so an instance's methods still resolve, and every value a name lookup
  // could reach through it is copied to an OWN property, which shadows the original. A method is
  // left where it is: copying a function would only move it, and it is the prototype's behaviour
  // rather than the caller's data.
  var out = Object.create(proto);
  var keys = _reachableKeys(v);
  for (var k = 0; k < keys.length; k++) {
    var value;
    // Reading a caller's property can run a caller's accessor, and one that throws is a bad input
    // like any other -- the fault gets this boundary's typed code with the raw error as its cause,
    // rather than escaping as itself from inside a verb the caller called for something else.
    try { value = v[keys[k]]; }
    catch (e) { throw _raise(ErrorClass, code, label + ": reading " + JSON.stringify(keys[k]) + " threw", e); }
    if (typeof value === "function") continue;
    Object.defineProperty(out, keys[k], {
      value: _deep(value, ErrorClass, code, label, cap, depth + 1, collect),
      writable: true, enumerable: _wasEnumerable(v, keys[k]), configurable: true,
    });
  }
  return out;
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
// `[value, label]` pairs -- every argument the verb was handed. Each is deep-copied, so no field
// of any of them, at any depth, is still the caller's to change once the verb has begun; `release`
// clears every copy that was made and belongs in a `finally`, so a copied password or private key
// does not outlive the call.
//
// Both halves are needed and neither is optional. Copying only the argument that looks like data
// leaves a secret nested inside the one that looks like a handle -- `opts.mac.secret` sitting a
// level below a shallow copy -- readable and rewritable across the turn. Copying without releasing
// answers that by duplicating the secret instead. Deciding per field which is which is the judgment
// that keeps going wrong, so there is no per-field decision here: everything is copied, everything
// copied is cleared, and the only things left alone are the ones a copy would BREAK -- a CryptoKey
// or any class instance (its identity is what makes it work) and a recorded parse result (its
// provenance is keyed to the object).
// @enforced-by behavioral -- there is no rename-proof code shape for "copied every argument". The
//   guard is the per-verb RED vector that mutates each argument after the verb returns its promise
//   and asserts the artifact carries the entry value.
function fixArguments(ErrorClass, code, args) {
  var copies = [];
  var values = [];
  // Through guard.secret, which owns what clearing a secret means -- required inline because
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
    // The copying itself can fail partway -- a detached leaf, a structure past the depth cap, a
    // getter that throws -- and the arguments already copied by then are just as much ours as if
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
// exactly one way and this is it. The copy runs INSIDE guard-async's boundary, so a fault in the
// copy itself -- a detached view, a structure nested past the cap, a getter that throws -- leaves
// as a REJECTION like every other fault of a verb documented `-> Promise<...>`, rather than as a
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
  snapshotDeep: snapshotDeep, fixArguments: fixArguments, fixedCall: fixedCall,
};
