// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the KEM
// key-establishment paths that compose this guard (pki.cms.encrypt / decrypt).
//
// guard-secret -- wipe a secret buffer the TOOLKIT ALLOCATED at the moment it
// stops being needed. NIST SP 800-227 RS5 / sec. 4.2 requires that a KEM shared
// secret and every intermediate value be destroyed as soon as they are no longer
// needed; RFC 9629 sec. 7 says the same of the KEK a KEMRecipientInfo derives.
//
// The defended class is secret lifetime, not secret disclosure: a shared secret
// or KEK left readable in the heap widens the window in which a later memory
// disclosure -- a core dump, a swapped page, a same-process read primitive --
// yields key material for traffic that was already decrypted.
//
// SCOPE, stated honestly because the docstring is the only place a reader learns
// it: this is BEST EFFORT. The runtime copies buffers into places no JS can
// reach (node's decapsulate return is copied on the way out; importKey("raw")
// copies into a KeyObject), and V8 may relocate a backing store, leaving the
// original bytes behind. Wiping the copies the toolkit holds shortens the
// window. It does not support a claim that a secret never persists in memory,
// and no operator-facing text may imply that it does.
//
// Ownership is the contract. Only a buffer the toolkit allocated may be wiped:
// never a caller's opts.key / opts.cert / opts.kek / opts.password, and never the
// input DER. Silently destroying a caller's own memory is a worse defect than
// leaving a secret readable, and it is the failure mode a zeroization patch
// reaches for first, so the call sites pass only their own intermediates.

var bytes = require("./guard-bytes");
var intrinsic = require("./guard-intrinsic");

// The fill this guard performs, taken from the typed-array prototype at module load and uncurried
// so the wipe site reads no property at all. Buffer overrides the fill with a writable
// `Buffer.prototype.fill`, so reading the method off the value would let a caller decide what
// wiping means; reading `call` off the captured function would let them decide it again, since
// that function is still the one sitting on the prototype (see guard-intrinsic).
var _fill = intrinsic.uncurry(Uint8Array.prototype.fill);
// The join that produces the buffer cipherFinish hands back. Captured for the same reason as
// the fill: a replaced `Buffer.concat` decides what the caller receives, and it would receive it
// while the two intermediates this module is responsible for clearing were cleared as promised.
var _concat = intrinsic.bufferConcat;

// zeroize(value, ErrorClass, code, label) -> the same object, cleared.
//   value      : a Buffer / TypedArray the TOOLKIT allocated, or null / undefined
//                (absent is a no-op so a `finally` needs no branch around it).
//   ErrorClass : the caller's typed error CONSTRUCTOR, declared with
//                `{ withCause: true }`. The guard family carries two currencies --
//                most guards take a (code, message) factory and call it without
//                `new`, while guard-bytes / guard-header take the class and
//                construct it. This module's one throw is the delegated re-view
//                below, so it must pass what guard-bytes expects: the class, and
//                one that accepts a cause, because guard-bytes threads the raw
//                detach fault through as one. A plain class fails to construct at
//                the single moment the caller needs a real error.
//   code       : the frozen domain/reason code a detached buffer rejects under.
//   label      : field phrase for the message.
//
// A detached ArrayBuffer cannot be written, and reaching one here means a caller
// handed over memory that was transferred away. That is a real fault and not
// something to swallow, so it routes through the shared re-view guard and throws
// typed.
//
// The `.fill(0)` shape lives only in this module. A wipe re-inlined anywhere in
// lib/, including a module not yet written, is flagged, so the safe implementation
// is also the tripwire that stops the next consumer from rolling its own partial
// one.
// @enforced-by guard-shape-reinlined
// @guard-shape \.fill\s*\(\s*0\s*[,)]
function zeroize(value, ErrorClass, code, label) {
  if (value === null || value === undefined) return value;
  // Re-view through the shared bytes guard: it is the single place that decides
  // what counts as a writable BufferSource and rejects a detached one typed.
  var view = bytes.view(value, ErrorClass, code, label);
  // Through the fill captured at module load, never `view.fill(0)`. Buffer overrides the typed-array
  // fill with its own, and that property is writable, so a caller who replaces it with a no-op turns
  // every wipe in the toolkit into a silent nothing -- and nothing observable changes, because the
  // wipe still runs, still walks the right buffer, and still returns. A secret that survives a call
  // whose whole purpose was to clear it is the failure this guard exists to prevent, so the one
  // operation it performs is the one operation a caller must not be able to reach.
  _fill(view, 0);
  return value;
}

// zeroizeAll(list, ErrorClass, code, label) wipes every present member, tolerating
// holes so a `finally` can name intermediates that may not have been reached.
//
// @enforced-by behavioral -- this is a loop over zeroize, which carries the family's only
// rename-proof shape (the `.fill(0)` above). It introduces no shape of its own, so a lexical
// detector here would anchor on a renameable symbol and go silently green (drift rule sec. 3).
// The behavioral guards are guard-secret.test.js (holes tolerated, every member cleared) and the
// CMS vectors that assert the shared secret and KEK are wiped on both the success and failure paths.
function zeroizeAll(list, ErrorClass, code, label) {
  if (!list) return list;
  for (var i = 0; i < list.length; i++) zeroize(list[i], ErrorClass, code, label);
  return list;
}

// cipherFinish(transform, input, ErrorClass, code, label) -> the output, as one fresh buffer
//   transform : a node:crypto Cipher or Decipher the CALLER built and configured (key, iv, AAD,
//               auth tag, padding mode). This guard performs the two calls and nothing else.
//   input     : the bytes to feed it.
//
// The single place this toolkit runs a configured cipher to completion, because
// `Buffer.concat([c.update(x), c.final()])` abandons a copy on BOTH of its exits and the leak is
// invisible at the call site.
//
// On a DECIPHER the abandoned copy is plaintext. `update` returns the recovered plaintext while
// `final` is what decides whether the message was authentic at all -- a GCM tag mismatch, a CBC
// padding failure -- so on a forged message the whole plaintext exists before anything has judged
// it, and the `concat` never runs: that buffer becomes unreferenced garbage holding readable
// plaintext. RFC 5083 sec. 1 requires a receiver whose integrity check fails to destroy the
// plaintext, and withholding it from the caller is not destroying it. On the success path `concat`
// COPIES, so the update buffer is a second full copy the caller never receives and nothing else
// will ever clear.
//
// It covers the ENCRYPT direction too, where the intermediates are ciphertext and clearing them
// buys little. That is deliberate: any rule for which of the two directions must clear is a
// judgment made at each call site, and the sites where it is wrong are the ones nobody re-reads.
// One shape, cleared everywhere, needs no such judgment -- and the encrypt intermediates of a
// key-wrap are not obviously worthless to an attacker either.
//
// @enforced-by guard-shape-reinlined
// @guard-shape \.update\s*\([\s\S]{0,300}?\)\s*,\s*[A-Za-z_$][\w$]*\s*\.\s*final\s*\(\s*\)
function cipherFinish(transform, input, ErrorClass, code, label) {
  var head = null, tail = null;
  try {
    head = transform.update(input);
    tail = transform.final();
    // Always a fresh copy, never `head` itself: the returned buffer belongs to the caller and the
    // two intermediates have to be clearable independently of it.
    return _concat([head, tail]);
  } finally {
    zeroize(head, ErrorClass, code, label);
    zeroize(tail, ErrorClass, code, label);
  }
}

// Frozen for the reason the family header gives: a boundary reads its guard off this object at the
// call, so a writable export would let a caller replace the check rather than pass it.
module.exports = intrinsic.freeze({ zeroize: zeroize, zeroizeAll: zeroizeAll, cipherFinish: cipherFinish });
