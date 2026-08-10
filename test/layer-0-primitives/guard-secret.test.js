// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-secret (@internal): best-effort wipe of a secret buffer the
 * toolkit ALLOCATED, at the moment it stops being needed (NIST SP 800-227 RS5 /
 * sec. 4.2, RFC 9629 sec. 7).
 *
 * Two properties carry the module. It must clear what it is given -- only the
 * caller's window of a shared ArrayBuffer, never past it -- and it must REFUSE a
 * buffer the toolkit does not own: silently destroying a caller's key material is
 * a worse defect than leaving a copy of a secret in the heap, so ownership is a
 * contract the guard enforces rather than a convention its call sites remember.
 *
 * Scope honesty: this shortens the window in which a secret is readable. It does
 * not make it unreachable -- the runtime copies buffers (node's decapsulate
 * return, importKey("raw")) into places no JS can reach, and V8 may relocate a
 * backing store. The vectors below pin what the guard does, not a stronger claim.
 */

var secret = require("../../lib/guard-secret");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
// guard-secret delegates its only throw to guard-bytes.view, which CONSTRUCTS the
// error, so the currency here is the class -- not the (code, message) factory the
// other nine guards take. The two conventions coexist in the family; a guard must
// pass what the guard it composes expects.
var E = TestError;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || (e instanceof TypeError ? "TYPE" : "OTHER"); } }

function run() {
  // ---- clears what it owns ----
  var buf = Buffer.from([1, 2, 3, 4, 5]);
  var ret = secret.zeroize(buf, E, "test/bad-secret", "buf");
  check("zeroize clears every byte", buf.every(function (b) { return b === 0; }));
  check("zeroize returns the same object identity (no reallocation)", ret === buf);

  // ---- absent values are a no-op, so call sites carry no branch ----
  check("zeroize(null) does not throw", code(function () { secret.zeroize(null, E, "test/bad-secret", "n"); }) === "NO-THROW");
  check("zeroize(undefined) does not throw", code(function () { secret.zeroize(undefined, E, "test/bad-secret", "u"); }) === "NO-THROW");

  // ---- clears ONLY the caller's window of a shared ArrayBuffer ----
  // A wipe that ran past the view would destroy bytes the caller still owns -- the
  // same class of defect as wiping a caller-supplied buffer, one level down.
  var backing = new Uint8Array([9, 9, 1, 2, 3, 9, 9]);
  var window = backing.subarray(2, 5);
  secret.zeroize(window, E, "test/bad-secret", "window");
  check("zeroize clears the view's window", backing[2] === 0 && backing[3] === 0 && backing[4] === 0);
  check("zeroize leaves bytes outside the view untouched",
    backing[0] === 9 && backing[1] === 9 && backing[5] === 9 && backing[6] === 9);

  // ---- a detached buffer is the caller's typed error, never a raw TypeError ----
  var det = new Uint8Array(8);
  try { structuredClone(det.buffer, { transfer: [det.buffer] }); } catch (_e) { /* older runtime: skip below */ }
  if (det.buffer.byteLength === 0) {
    check("zeroize on a detached buffer throws the caller's typed code",
      code(function () { secret.zeroize(det, E, "test/bad-secret", "detached"); }) === "test/bad-secret");
  }

  // ---- zeroizeAll: absent is a no-op for the LIST too, not only for its members ----
  // The whole point of the no-op contract is that a `finally` needs no branch around the call, and
  // a caller that never reached the point of collecting intermediates has no list to pass.
  check("zeroizeAll(null) does not throw", code(function () { secret.zeroizeAll(null, E, "test/bad-secret", "none"); }) === "NO-THROW");
  check("zeroizeAll(undefined) does not throw", code(function () { secret.zeroizeAll(undefined, E, "test/bad-secret", "none"); }) === "NO-THROW");
  check("zeroizeAll([]) does not throw", code(function () { secret.zeroizeAll([], E, "test/bad-secret", "empty"); }) === "NO-THROW");

  // ---- zeroizeAll tolerates holes ----
  var a = Buffer.from([7, 7]), b = Buffer.from([8, 8, 8]);
  secret.zeroizeAll([a, null, b, undefined], E, "test/bad-secret", "list");
  check("zeroizeAll clears every present member and tolerates holes",
    a.every(function (x) { return x === 0; }) && b.every(function (x) { return x === 0; }));

  // ---- the error currency is the CLASS, matching the guard it composes ----
  // The class must also be declared withCause: guard-bytes threads the raw detach
  // fault through as the cause, so a class without it fails to construct at the one
  // moment the caller needs a real error.
  var det2 = new Uint8Array(4);
  try { structuredClone(det2.buffer, { transfer: [det2.buffer] }); } catch (_e2) { /* skip */ }
  if (det2.buffer.byteLength === 0) {
    var thrown = null;
    try { secret.zeroize(det2, TestError, "test/bad-secret", "probe"); } catch (e) { thrown = e; }
    check("a detached buffer yields the caller's own error type, constructed",
      thrown instanceof TestError && thrown.code === "test/bad-secret");
  }

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
