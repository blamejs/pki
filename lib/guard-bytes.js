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

module.exports = { view: view, source: source };
