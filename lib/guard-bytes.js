// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// primitives whose input boundaries compose these guards (pki.asn1.decode,
// pki.cbor.decode, pki.ct.parseSctList, pki.webcrypto.*).
//
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
      throw new ErrorClass(code, label + ": input is not a usable byte view (detached backing buffer?)", e);
    }
  }
  throw new ErrorClass(code, label + ": expected a Buffer / Uint8Array");
}

// source(input, ErrorClass, code, label) -> Buffer | throws ErrorClass
// Accepts the full W3C BufferSource (Buffer / TypedArray view / raw ArrayBuffer)
// -- the WebCrypto input contract. A raw ArrayBuffer is copied via Buffer.from,
// which also throws on a detached backing store.
// @enforced-by guard-shape-reinlined  (the re-view shape is declared on view above)
function source(input, ErrorClass, code, label) {
  var isAb = input instanceof ArrayBuffer;
  if (isAb || ArrayBuffer.isView(input)) {
    try {
      return isAb ? Buffer.from(input) : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    } catch (e) {
      throw new ErrorClass(code, label + ": input is not a usable byte source (detached backing buffer?)", e);
    }
  }
  throw new ErrorClass(code, label + ": expected a BufferSource (ArrayBuffer / TypedArray / Buffer)");
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

module.exports = { view: view, source: source, snapshot: snapshot };
