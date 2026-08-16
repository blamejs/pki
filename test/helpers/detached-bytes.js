// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Detached byte inputs -- the fixture behind the guard-bytes contract.
 *
 * Transferring an ArrayBuffer (structuredClone with `transfer`, a worker
 * postMessage, a stream hand-off) leaves every view of it reading ZERO-LENGTH
 * rather than throwing. A boundary that accepts a caller's bytes and passes the
 * object straight through therefore hands the rest of the toolkit an EMPTY
 * buffer, and the operation succeeds over nothing: a signature over no content,
 * a key identifier of no bytes, a key derived from no password. These builders
 * produce that input so a test can assert the boundary refuses it.
 */

// detachedBuffer(bytes) -> a Buffer whose backing ArrayBuffer has been transferred away.
// `bytes` is a Buffer / Uint8Array / array of octets / byte count; the returned view reports
// length 0 and every read of it throws internally.
function detachedBuffer(bytes) {
  var src = typeof bytes === "number" ? new Uint8Array(bytes) : Uint8Array.from(bytes);
  var ab = src.buffer;
  var view = Buffer.from(ab, 0, src.length);
  structuredClone(ab, { transfer: [ab] });
  return view;
}

// The same, as a plain Uint8Array -- the second byte form every door accepts, so a test
// can prove BOTH arms of a coercion refuse rather than only the Buffer one.
function detachedUint8(bytes) {
  var src = typeof bytes === "number" ? new Uint8Array(bytes) : Uint8Array.from(bytes);
  var ab = src.buffer;
  structuredClone(ab, { transfer: [ab] });
  return src;
}

module.exports = { detachedBuffer: detachedBuffer, detachedUint8: detachedUint8 };
