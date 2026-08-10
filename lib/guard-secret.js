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
// OWNERSHIP IS THE CONTRACT. Only a buffer the toolkit allocated may be wiped --
// never a caller's opts.key / opts.cert / opts.kek / opts.password, and never the
// input DER. Silently destroying a caller's own memory is a worse defect than
// leaving a secret readable, and it is the failure mode a zeroization patch
// reaches for first, so the call sites pass only their own intermediates.

var bytes = require("./guard-bytes");

// zeroize(value, ErrorClass, code, label) -> the same object, cleared.
//   value      : a Buffer / TypedArray the TOOLKIT allocated, or null / undefined
//                (absent is a no-op so a `finally` needs no branch around it).
//   ErrorClass : the caller's typed error CONSTRUCTOR, declared with
//                `{ withCause: true }`. The guard family carries two currencies --
//                most guards take a (code, message) factory and call it without
//                `new`, while guard-bytes / guard-header take the class and
//                construct it. This module's ONLY throw is the delegated re-view
//                below, so it must pass what guard-bytes expects: the class, and
//                one that accepts a cause, because guard-bytes threads the raw
//                detach fault through as one. A plain class fails to construct at
//                the single moment the caller needs a real error.
//   code       : the frozen domain/reason code a detached buffer rejects under.
//   label      : field phrase for the message.
//
// A detached ArrayBuffer cannot be written, and reaching one here means a caller
// handed over memory that was transferred away -- a real fault, not something to
// swallow, so it routes through the shared re-view guard and throws typed.
//
// The `.fill(0)` shape lives ONLY in this module: a wipe re-inlined anywhere in
// lib/ -- including a module not yet written -- is flagged, so the safe
// implementation is also the tripwire that stops the next consumer from rolling
// its own partial one.
// @enforced-by guard-shape-reinlined
// @guard-shape \.fill\s*\(\s*0\s*[,)]
function zeroize(value, ErrorClass, code, label) {
  if (value === null || value === undefined) return value;
  // Re-view through the shared bytes guard: it is the single place that decides
  // what counts as a writable BufferSource and rejects a detached one typed.
  var view = bytes.view(value, ErrorClass, code, label);
  view.fill(0);
  return value;
}

// zeroizeAll(list, ErrorClass, code, label) -- wipe every present member, tolerating
// holes so a `finally` can name intermediates that may not have been reached.
//
// @enforced-by behavioral -- this is a loop over zeroize, which carries the family's only
// rename-proof shape (the `.fill(0)` above). It introduces no shape of its own, so a lexical
// detector here would anchor on a renameable symbol and go silently green (drift rule sec. 3).
// The behavioural guards are guard-secret.test.js (holes tolerated, every member cleared) and the
// CMS vectors that assert the shared secret and KEK are wiped on BOTH the success and failure paths.
function zeroizeAll(list, ErrorClass, code, label) {
  if (!list) return list;
  for (var i = 0; i < list.length; i++) zeroize(list[i], ErrorClass, code, label);
  return list;
}

module.exports = { zeroize: zeroize, zeroizeAll: zeroizeAll };
