// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.tls.decompressCertificate (RFC 8879 CompressedCertificate).
 *
 * libFuzzer / jazzer.js harness. Every byte of the input is attacker-controlled and drives a
 * distinct decode stage: the uint16 algorithm selects one of three decompressors, the uint24
 * uncompressed_length becomes the decompression cap AND the exact-length assertion, and the
 * opaque<1..2^24-1> body is fed to zlib / brotli / zstd. Whatever the body decompresses to is
 * then decoded again as an RFC 8446 sec. 4.4.2 Certificate message -- a second, fully
 * attacker-controlled framing walk over nested uint24 / uint16 vectors -- so one input reaches
 * both the compression and the TLS-presentation surfaces.
 *
 * The cap is what keeps this bounded: it is the message's own declared length, itself bounded by
 * the handshake framing ceiling, applied at the decompressor. So a bomb is a caught tls/too-large
 * rather than an OOM or a hang, for all three codecs.
 *
 * Contract: decompressing attacker-controlled bytes has exactly two acceptable outcomes -- a
 * returned result, or a thrown `pki.errors.PkiError` (TlsError here). Any other throw (a RangeError
 * out of a length computation, a bare TypeError, a stack overflow, an OOM, a hang) is an unguarded
 * invariant break -- rethrow so jazzer records the reproducer.
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = function (data) {
  var buf = Buffer.from(data);
  try {
    pki.tls.decompressCertificate(buf);
  } catch (e) { if (!isPki(e)) throw e; }
  // The inner message decoder is also reachable on its own -- drive it directly so the
  // Certificate-message framing walk is fuzzed without having to survive decompression first.
  try {
    pki.tls.parseCertificateMessage(buf);
  } catch (e2) { if (!isPki(e2)) throw e2; }
};
