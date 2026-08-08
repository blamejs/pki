// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.tls
 * @nav        Transparency
 * @title      TLS
 * @order      215
 * @slug       tls
 *
 * @intro
 *   TLS handshake structures that carry certificates. `decompressCertificate`
 *   and `compressCertificate` are the RFC 8879 `CompressedCertificate` codec --
 *   the compressed form of a TLS 1.3 `Certificate` message, which shrinks the
 *   largest thing a handshake sends and matters most for post-quantum chains,
 *   where certificates grow by kilobytes. `parseCertificateMessage` decodes the
 *   RFC 8446 sec. 4.4.2 `Certificate` message itself, so a compressed chain
 *   arrives as certificate DER ready for `pki.schema.x509.parse` rather than as
 *   an opaque blob.
 *
 *   These are encoded in the TLS presentation language -- positional, tag-less,
 *   fixed-width big-endian integers and length-prefixed opaque vectors -- NOT
 *   ASN.1/DER, so this module composes the toolkit's bounded big-endian cursor
 *   rather than the DER schema engine.
 *
 *   Decompression is the attack surface and is fail-closed on both sides of the
 *   bound RFC 8879 sec. 5 requires: the decompressor is capped at the message's
 *   OWN declared uncompressed length (so a bomb is refused mid-stream, never
 *   allocated), and the output must then equal that length EXACTLY (which catches
 *   the under-length direction a cap cannot see). The caller's policy cap applies
 *   independently, so a peer declaring 16 MiB does not get 16 MiB. This module
 *   decodes structure only -- it never verifies a certificate, builds a path, or
 *   speaks the handshake.
 *
 *   All three registered algorithms -- zlib, brotli and zstd -- are implemented,
 *   and each is offered only where the running Node can decompress it safely. A
 *   decompressor must fault on a frame it could not finish; where one instead
 *   returns a short result and reports the whole input consumed, a peer could cut
 *   a frame's tail and have the receiver read a prefix as the whole message. Any
 *   algorithm whose decompressor behaves that way is dropped at startup and is
 *   then neither advertised nor accepted. On the current long-term-support Node
 *   this leaves zlib and brotli.
 *
 * @card
 *   Encode and decode RFC 8879 TLS compressed certificate messages and the
 *   RFC 8446 Certificate message inside them -- a two-sided decompression
 *   bound, exact-length enforcement, per-entry certificate DER surfaced raw,
 *   fail-closed. All three registered algorithms are implemented; each is
 *   offered only where the running Node decompresses it safely.
 */

var C = require("./constants");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");
var validator = require("./validator-all");
var ByteWriter = require("./byte-writer");
var zlib = require("zlib");

var TlsError = frameworkError.TlsError;
function _err(code, message, cause) { return new TlsError(code, message, cause); }

// RFC 8879 sec. 7.3 -- the CertificateCompressionAlgorithm registry. The wire value is
// what travels; the name is what this toolkit's guard dispatches on. 0 is Reserved and
// 16384..65535 are Experimental Use, but neither needs a row: anything absent here is
// refused the same way, and adding a row for a value we cannot decompress would be the
// fail-open. Every name here is checked against the decompression guard at load, so a
// runtime without one of the three cannot advertise it.
var ALG_BY_NUMBER = { 1: "zlib", 2: "brotli", 3: "zstd" };
var ALG_BY_NAME = {};
Object.keys(ALG_BY_NUMBER).forEach(function (n) { ALG_BY_NAME[ALG_BY_NUMBER[n]] = Number(n); });

// The compressors, paired with the guard's decompressors. RFC 8879 sec. 4 binds each
// algorithm to its format: zlib -> RFC 1950, brotli -> RFC 7932, zstd -> RFC 8478.
var COMPRESS = { zlib: zlib.deflateSync, brotli: zlib.brotliCompressSync, zstd: zlib.zstdCompressSync };

// Each codec takes its compression level through a DIFFERENT option: zlib as a top-level
// `level`, brotli and zstd as numbered entries in `params`. Passing `{ level: n }` to the
// latter two is silently ignored by node, so a caller asking for a level would quietly get the
// default. Each is mapped to the option its codec actually reads.
var LEVEL_OPT = {
  zlib: function (n) { return { level: n }; },
  brotli: function (n) { var p = {}; p[zlib.constants.BROTLI_PARAM_QUALITY] = n; return { params: p }; },
  zstd: function (n) { var p = {}; p[zlib.constants.ZSTD_c_compressionLevel] = n; return { params: p }; },
};

// The names that are BOTH registered by RFC 8879 and reachable through the decompression
// guard on this runtime. An algorithm the guard cannot decompress must never be offered
// or accepted -- advertising one would mean accepting a message we then cannot open.
var SUPPORTED = guard.compress.algorithms().filter(function (n) {
  return Object.prototype.hasOwnProperty.call(ALG_BY_NAME, n) && typeof COMPRESS[n] === "function";
});

// The minimum Certificate message size and the widest opaque<..2^24-1> vector -- both owned
// by validator-tls, alongside the rest of the framing rule set. A declared
// uncompressed_length below the minimum cannot be a Certificate message, and refusing it
// also keeps a zero-length declaration away from the decompression cap, which is a positive
// integer by contract.
var MIN_CERT_MSG_BYTES = validator.tls.MIN_CERT_MSG_BYTES;
var MAX_VECTOR_24 = validator.tls.MAX_VECTOR_24;

// The fault codes validator-tls raises for each framing violation it owns.
var FRAMING_CODES = { truncated: "tls/truncated", framing: "tls/bad-framing", trailing: "tls/trailing-data" };

// The fixed part of a CompressedCertificate: uint16 algorithm + uint24 uncompressed_length +
// the uint24 length prefix of the compressed body (RFC 8879 sec. 4).
var HEADER_BYTES = 8;

// Resolve the caller's policy cap, which may only tighten the protocol ceiling DOWNWARD.
// A cap that could be raised would let an option undo the framing limit RFC 8879 sec. 5
// requires be applied "as if no compression were used".
function _resolveCap(opts) {
  var cap = C.LIMITS.TLS_CERT_MSG_MAX_BYTES;
  if (opts.maxOutputBytes !== undefined) {
    var mo = opts.maxOutputBytes;
    if (typeof mo !== "number" || !isFinite(mo) || mo <= 0 || Math.floor(mo) !== mo) {
      throw _err("tls/bad-input", "opts.maxOutputBytes must be a positive integer");
    }
    if (mo < cap) cap = mo;
  }
  return cap;
}

// The algorithm names the caller will accept, defaulting to everything supported. This is
// the peer's `compress_certificate` advertisement: RFC 8879 sec. 4 requires the algorithm
// to be one the receiver offered, so accepting an unadvertised one would decompress bytes
// under a codec we never agreed to.
function _resolveAllowed(opts) {
  if (opts.allowedAlgorithms === undefined) return SUPPORTED.slice();
  var list = opts.allowedAlgorithms;
  if (!Array.isArray(list)) throw _err("tls/bad-input", "opts.allowedAlgorithms must be an array of algorithm names or numbers");
  return list.map(function (a) {
    var name = (typeof a === "number") ? ALG_BY_NUMBER[a] : a;
    if (typeof name !== "string" || SUPPORTED.indexOf(name) === -1) {
      throw _err("tls/bad-input", "opts.allowedAlgorithms names an algorithm this toolkit cannot decompress: " + JSON.stringify(a));
    }
    return name;
  });
}

/**
 * @primitive  pki.tls.decompressCertificate
 * @signature  pki.tls.decompressCertificate(bytes, opts?) -> { algorithm, algorithmName, uncompressedLength, certificateMessage, certificate }
 * @since      0.4.3
 * @status     experimental
 * @spec       RFC 8879, RFC 8446
 * @related    pki.tls.compressCertificate, pki.tls.parseCertificateMessage, pki.schema.x509.parse
 *
 * Decode an RFC 8879 sec. 4 `CompressedCertificate`: the `algorithm` code point, the
 * declared `uncompressedLength`, the recovered `certificateMessage` (the raw RFC 8446
 * sec. 4.4.2 `Certificate` message bytes, surfaced verbatim), and `certificate` -- that
 * message already decoded into its request context and per-entry certificate DER.
 *
 * The decompression bound is two-sided, as RFC 8879 sec. 5 requires. The decompressor is
 * capped at `min(uncompressedLength, policy cap)`, so a bomb is refused the moment its
 * output would exceed what the message itself declared -- it is never allocated. The
 * recovered length must then equal `uncompressedLength` exactly, which catches the
 * under-length direction no cap can see. A message that fails either way is refused;
 * RFC 8879 sec. 5 maps both to the `bad_certificate` alert, but they keep distinct codes
 * here because "this is a bomb" and "these bytes are not that codec" are different
 * diagnoses.
 *
 * An algorithm outside the RFC 8879 registry, one this runtime cannot decompress, or one
 * absent from `opts.allowedAlgorithms` is refused before any decompressor runs -- the
 * algorithm MUST be one the receiver advertised (RFC 8879 sec. 4). An empty compressed
 * body is a framing violation (`opaque<1..2^24-1>`), not an empty certificate list.
 *
 * Throws `TlsError` with a stable `tls/*` code on any malformed input, never a raw
 * `TypeError`. Structure only -- no certificate here is verified or path-built.
 *
 * @opts
 *   maxOutputBytes   - tighten the decompression cap DOWNWARD from the RFC 8446 sec. 4
 *                      framing ceiling (2^24-1). A value above it does not raise it.
 *   allowedAlgorithms- the algorithms the receiver advertised, as names or code points;
 *                      defaults to every algorithm this runtime can decompress.
 *   certificateType  - "X509" (default) or "RawPublicKey" (RFC 7250). Not self-describing
 *                      on the wire -- it is negotiated by a separate extension -- so it is
 *                      declared, never guessed.
 *
 * @example
 *   // The Certificate message this codec carries: an empty request context, then one
 *   // entry -- the certificate DER followed by its (here empty) extensions vector.
 *   var u24 = function (n) { var b = Buffer.alloc(3); b.writeUIntBE(n, 0, 3); return b; };
 *   var entry = Buffer.concat([u24(certDer.length), certDer, Buffer.from([0, 0])]);
 *   var message = Buffer.concat([Buffer.from([0]), u24(entry.length), entry]);
 *
 *   var out = pki.tls.decompressCertificate(pki.tls.compressCertificate(message));
 *   out.algorithmName;                                  // "zlib"
 *   out.uncompressedLength === out.certificateMessage.length;   // true
 *   pki.schema.x509.parse(out.certificate.entries[0].certData).subject;
 */
function decompressCertificate(bytes, opts) {
  opts = opts || {};
  var view = guard.bytes.view(bytes, TlsError, "tls/bad-input", "the compressed certificate message");
  // The CompressedCertificate travels as a handshake message body, framed by RFC 8446 sec. 4
  // with a uint24 length, so one longer than that ceiling could not have been sent at all.
  if (view.length > C.LIMITS.TLS_CERT_MSG_MAX_BYTES) {
    throw _err("tls/too-large", "the compressed certificate message is " + view.length +
      " bytes, over the " + C.LIMITS.TLS_CERT_MSG_MAX_BYTES + "-byte handshake framing limit");
  }
  var cap = _resolveCap(opts);
  var allowed = _resolveAllowed(opts);

  // Framing decode + bounds live in validator-tls (the type's rule set); which algorithms
  // are acceptable, the output cap, and the length agreement are this codec's policy and
  // stay here. Note the currency split the two families use: the validator takes the error
  // CLASS, the guard below takes the `_err` FACTORY.
  var framed = validator.tls.compressedCertificate(view, TlsError, FRAMING_CODES);
  var algorithm = framed.algorithm;
  var name = ALG_BY_NUMBER[algorithm];
  if (!name) {
    throw _err("tls/unsupported-algorithm", "compression algorithm " + algorithm + " is not in the RFC 8879 registry");
  }
  // SUPPORTED is the RFC 8879 registry intersected with what the decompression guard can
  // actually open safely, so this fires wherever one of the three is dropped -- which is the
  // long-term-support Node, where zstd cannot report a truncated frame. Covered there by the
  // dropped-algorithm vector; unreachable on a runtime where all three qualify.
  if (SUPPORTED.indexOf(name) === -1) {
    throw _err("tls/unsupported-algorithm", "compression algorithm " + algorithm + " (" + name + ") is not decompressible on this runtime");
  }
  if (allowed.indexOf(name) === -1) {
    throw _err("tls/unsupported-algorithm", "compression algorithm " + algorithm + " (" + name + ") was not among the advertised algorithms");
  }
  var uncompressedLength = framed.uncompressedLength;
  var body = framed.body;
  if (uncompressedLength < MIN_CERT_MSG_BYTES) {
    throw _err("tls/bad-framing", "uncompressed_length " + uncompressedLength +
      " is below the " + MIN_CERT_MSG_BYTES + "-byte minimum of a Certificate message (RFC 8446 sec. 4.4.2)");
  }
  if (uncompressedLength > cap) {
    throw _err("tls/too-large", "uncompressed_length " + uncompressedLength + " exceeds the " + cap + "-byte limit");
  }
  // The declared length IS the cap: a stream that expands past what the message itself
  // claims is refused mid-decompression rather than after the memory is committed.
  var message = guard.compress.bounded(name, Buffer.from(body), uncompressedLength, _err,
    { tooLarge: "tls/too-large", failed: "tls/decompress-failed" }, "the compressed certificate message");
  // RFC 8879 sec. 5: if the length after decompression does not match the declared one,
  // the message is invalid. The cap above only bounds the OVER direction.
  if (message.length !== uncompressedLength) {
    throw _err("tls/length-mismatch", "the decompressed message is " + message.length +
      " bytes but uncompressed_length declared " + uncompressedLength);
  }
  return {
    algorithm: algorithm,
    algorithmName: name,
    uncompressedLength: uncompressedLength,
    certificateMessage: message,
    certificate: parseCertificateMessage(message, opts),
  };
}

/**
 * @primitive  pki.tls.parseCertificateMessage
 * @signature  pki.tls.parseCertificateMessage(bytes, opts?) -> { certificateRequestContext, entries }
 * @since      0.4.3
 * @status     experimental
 * @spec       RFC 8446, RFC 7250
 * @related    pki.tls.decompressCertificate, pki.schema.x509.parse
 *
 * Decode an RFC 8446 sec. 4.4.2 `Certificate` message into its
 * `certificateRequestContext` (raw, empty in a server's handshake certificate) and its
 * `entries`. Each entry surfaces `certData` -- the certificate DER exactly as it appeared
 * on the wire, ready for `pki.schema.x509.parse` and never re-serialized -- plus the raw
 * `extensions` bytes that follow it.
 *
 * `certificate_type` is negotiated by a separate extension (RFC 7250) and is NOT present
 * in this message, so it cannot be inferred from the bytes. It is declared through
 * `opts.certificateType` and defaults to X509; under `"RawPublicKey"` the same slot is a
 * `SubjectPublicKeyInfo` and is surfaced as `spki` instead of `certData`.
 *
 * Throws `TlsError` with a stable `tls/*` code on any framing violation -- a lying vector
 * length, a field past its bound, or bytes trailing the entry list.
 *
 * @opts
 *   certificateType - "X509" (default) or "RawPublicKey" (RFC 7250).
 *
 * @example
 *   var u24 = function (n) { var b = Buffer.alloc(3); b.writeUIntBE(n, 0, 3); return b; };
 *   var entry = Buffer.concat([u24(certDer.length), certDer, Buffer.from([0, 0])]);
 *   var message = Buffer.concat([Buffer.from([0]), u24(entry.length), entry]);
 *
 *   var msg = pki.tls.parseCertificateMessage(message);
 *   msg.certificateRequestContext.length;               // 0
 *   pki.schema.x509.parse(msg.entries[0].certData).subject;
 */
function parseCertificateMessage(bytes, opts) {
  opts = opts || {};
  var type = opts.certificateType === undefined ? "X509" : opts.certificateType;
  if (type !== "X509" && type !== "RawPublicKey") {
    throw _err("tls/bad-input", "opts.certificateType must be \"X509\" or \"RawPublicKey\"");
  }
  var view = guard.bytes.view(bytes, TlsError, "tls/bad-input", "the certificate message");
  // A Certificate message is a handshake message body, framed by RFC 8446 sec. 4 with a uint24
  // length, so one longer than that ceiling could not have appeared on the wire. This entry point
  // is public and reachable without going through decompression, so it applies the bound itself
  // rather than inheriting the one the compression paths enforce.
  if (view.length > C.LIMITS.TLS_CERT_MSG_MAX_BYTES) {
    throw _err("tls/too-large", "the certificate message is " + view.length +
      " bytes, over the " + C.LIMITS.TLS_CERT_MSG_MAX_BYTES + "-byte handshake framing limit");
  }
  return validator.tls.certificateMessage(view, TlsError, FRAMING_CODES, type);
}

/**
 * @primitive  pki.tls.compressCertificate
 * @signature  pki.tls.compressCertificate(certificateMessage, opts?) -> Buffer
 * @since      0.4.3
 * @status     experimental
 * @spec       RFC 8879
 * @related    pki.tls.decompressCertificate
 *
 * Build an RFC 8879 sec. 4 `CompressedCertificate` around an already-encoded RFC 8446
 * sec. 4.4.2 `Certificate` message. `opts.algorithm` selects the codec by name
 * (`"zlib"` / `"brotli"` / `"zstd"`) or by its registry code point; zlib is the default,
 * being the one every RFC 8879 implementation supports. An algorithm the running Node
 * cannot decompress safely is refused here as well as on decode, so this never produces a
 * message it could not itself read back.
 *
 * The result is verified before it is returned: the emitted message is decoded back
 * through `decompressCertificate` and the recovered bytes compared to the input, so a
 * message this toolkit produces can never be one this toolkit's own decoder refuses.
 *
 * Throws `TlsError` with a stable `tls/*` code -- for an unknown algorithm, a message
 * that cannot be framed (empty, or past the 2^24-1 ceiling either compressed or not).
 *
 * @opts
 *   algorithm - the compression algorithm, by name or RFC 8879 code point. Default "zlib".
 *   level     - the codec's compression level, passed through unchanged where it applies.
 *
 * @example
 *   var u24 = function (n) { var b = Buffer.alloc(3); b.writeUIntBE(n, 0, 3); return b; };
 *   var entry = Buffer.concat([u24(certDer.length), certDer, Buffer.from([0, 0])]);
 *   var message = Buffer.concat([Buffer.from([0]), u24(entry.length), entry]);
 *
 *   var wire = pki.tls.compressCertificate(message, { algorithm: "brotli" });
 *   wire.readUInt16BE(0);                               // 2 -- the brotli code point
 *   wire.length < message.length;                       // true
 */
function compressCertificate(certificateMessage, opts) {
  opts = opts || {};
  var view = guard.bytes.view(certificateMessage, TlsError, "tls/bad-input", "the certificate message");
  var sel = opts.algorithm === undefined ? "zlib" : opts.algorithm;
  var name = (typeof sel === "number") ? ALG_BY_NUMBER[sel] : sel;
  if (typeof name !== "string" || SUPPORTED.indexOf(name) === -1) {
    throw _err("tls/unsupported-algorithm", "opts.algorithm names an algorithm this toolkit cannot compress: " + JSON.stringify(sel));
  }
  if (view.length < MIN_CERT_MSG_BYTES) {
    throw _err("tls/bad-input", "a Certificate message is at least " + MIN_CERT_MSG_BYTES + " bytes (RFC 8446 sec. 4.4.2)");
  }
  if (view.length > C.LIMITS.TLS_CERT_MSG_MAX_BYTES) {
    throw _err("tls/too-large", "the certificate message is " + view.length + " bytes, over the " +
      C.LIMITS.TLS_CERT_MSG_MAX_BYTES + "-byte handshake framing limit");
  }
  if (opts.level !== undefined && (typeof opts.level !== "number" || !isFinite(opts.level) || Math.floor(opts.level) !== opts.level)) {
    throw _err("tls/bad-input", "opts.level must be an integer");
  }
  var stream;
  try {
    stream = COMPRESS[name](view, opts.level !== undefined ? LEVEL_OPT[name](opts.level) : undefined);
  } catch (e) {
    throw _err("tls/bad-input", "the certificate message could not be compressed (check opts.level)", e);
  }
  // The CompressedCertificate is itself a handshake message body, so the WHOLE emitted message --
  // not just the message it carries -- must fit the RFC 8446 sec. 4 uint24 framing. Incompressible
  // content near the ceiling grows by the 8-byte header, so bounding only the input would emit a
  // message that cannot be framed and no peer could receive. Checked BEFORE the writer so this
  // stays one verdict rather than surfacing as the body vector's own bound.
  var wireLength = HEADER_BYTES + stream.length;
  if (wireLength > C.LIMITS.TLS_CERT_MSG_MAX_BYTES) {
    throw _err("tls/too-large", "the compressed certificate message would be " + wireLength +
      " bytes, over the " + C.LIMITS.TLS_CERT_MSG_MAX_BYTES + "-byte handshake framing limit");
  }
  var w = new ByteWriter(TlsError, "tls/bad-input");
  w.u16(ALG_BY_NAME[name]);
  w.u24(view.length);
  w.vector(3, 1, MAX_VECTOR_24, stream, "tls/bad-framing");
  var wire = w.build();
  // Self-check: a produced message must be one this decoder accepts, and must recover the
  // input byte-for-byte. This is what stops a codec-level defect from shipping a message
  // that only a permissive peer can read.
  var back = decompressCertificate(wire, { allowedAlgorithms: [name] });
  // Coverage residual -- unreachable while the codec is correct, which is the point: this
  // fires only if a compressor and its decompressor disagree, and there is no input that
  // makes them. It stays as the assertion that a message this toolkit emits is one this
  // toolkit accepts, so a future codec defect surfaces here rather than at a peer.
  if (!back.certificateMessage.equals(view)) {
    throw _err("tls/bad-input", "the compressed certificate message did not round-trip to the input");
  }
  return wire;
}

module.exports = {
  decompressCertificate: decompressCertificate,
  compressCertificate: compressCertificate,
  parseCertificateMessage: parseCertificateMessage,
};
