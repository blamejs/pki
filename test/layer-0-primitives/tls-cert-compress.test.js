// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.tls.compressCertificate / decompressCertificate / parseCertificateMessage:
 * the RFC 8879 CompressedCertificate codec over the RFC 8446 sec. 4.4.2 Certificate message,
 * across all three registered algorithms (zlib / brotli / zstd). Drives the SHIPPED consumer
 * paths and asserts the fail-closed verdict for every framing and decompression fault.
 *
 * The load-bearing vectors are the TWO SIDES of the RFC 8879 sec. 5 bound: the decompressor is
 * capped at the message's OWN declared uncompressed_length, so a bomb is refused mid-stream
 * rather than allocated; and the recovered length must then equal that declaration EXACTLY,
 * which catches the under-length direction a cap cannot see. Both map to bad_certificate on
 * the wire but keep distinct codes here. Alongside them: an algorithm the receiver never
 * advertised is refused before any decompressor runs, and a trailing byte -- after the wire
 * message or after the compressed frame -- is refused, so one certificate chain has exactly
 * one encoding.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var zlib = require("zlib");
var crypto = require("crypto");

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

// Build an RFC 8446 sec. 4.4.2 Certificate message around the given entry payloads.
// struct { opaque certificate_request_context<0..2^8-1>; CertificateEntry certificate_list<0..2^24-1>; }
function certMessage(payloads, context) {
  var ctx = context || Buffer.alloc(0);
  var list = Buffer.concat(payloads.map(function (d) {
    var len = Buffer.alloc(3); len.writeUIntBE(d.length, 0, 3);
    return Buffer.concat([len, d, Buffer.from([0x00, 0x00])]);   // extensions<0..2^16-1>, empty
  }));
  var listLen = Buffer.alloc(3); listLen.writeUIntBE(list.length, 0, 3);
  return Buffer.concat([Buffer.from([ctx.length]), ctx, listLen, list]);
}

// Assemble a CompressedCertificate by hand so every field can be made adversarial.
// struct { uint16 algorithm; uint24 uncompressed_length; opaque compressed<1..2^24-1>; }
function buildCC(algorithm, uncompressedLength, stream) {
  var head = Buffer.alloc(8);
  head.writeUInt16BE(algorithm, 0);
  head.writeUIntBE(uncompressedLength, 2, 3);
  head.writeUIntBE(stream.length, 5, 3);
  return Buffer.concat([head, stream]);
}

var LEAF = Buffer.alloc(900, 0x41);
var CA = Buffer.alloc(700, 0x42);
var MSG = certMessage([LEAF, CA]);
// The RFC 8879 registry, intersected with what this runtime can decompress SAFELY. The codec
// refuses to offer or accept an algorithm whose decompressor cannot report an unfinished frame,
// so the usable set is a property of the runtime; these vectors assert behaviour over the set
// that is actually offered, and 7i proves one outside it is refused.
var REGISTERED = [{ name: "zlib", n: 1 }, { name: "brotli", n: 2 }, { name: "zstd", n: 3 }];
var SAFE = require("../../lib/guard-all").compress.algorithms();
var ALGS = REGISTERED.filter(function (a) { return SAFE.indexOf(a.name) !== -1; });
var UNSAFE = REGISTERED.filter(function (a) { return SAFE.indexOf(a.name) === -1; });

function run() {
  // ==== accept: every registered algorithm round-trips, structure fully decoded ==============
  ALGS.forEach(function (a, i) {
    var wire = pki.tls.compressCertificate(MSG, { algorithm: a.name });
    var out = pki.tls.decompressCertificate(wire);
    check((i + 1) + ". " + a.name + " round-trips the certificate message byte-for-byte", out.certificateMessage.equals(MSG));
    check((i + 1) + "a. " + a.name + " reports its RFC 8879 code point " + a.n, out.algorithm === a.n && out.algorithmName === a.name);
    check((i + 1) + "b. " + a.name + " declares the true uncompressed length", out.uncompressedLength === MSG.length);
    check((i + 1) + "c. " + a.name + " surfaces both certificates as raw DER slots",
      out.certificate.entries.length === 2 && out.certificate.entries[0].certData.equals(LEAF) && out.certificate.entries[1].certData.equals(CA));
  });
  check("4. the algorithm may also be selected by its code point",
    pki.tls.compressCertificate(MSG, { algorithm: ALGS[0].n }).readUInt16BE(0) === ALGS[0].n);
  check("4a. zlib is the default algorithm", pki.tls.compressCertificate(MSG).readUInt16BE(0) === 1);
  check("4b. a compressed message is smaller than the message it carries", pki.tls.compressCertificate(MSG).length < MSG.length);

  // ==== the Certificate message decode (RFC 8446 sec. 4.4.2) =================================
  var withCtx = certMessage([LEAF], Buffer.from([0xab, 0xcd]));
  var parsed = pki.tls.parseCertificateMessage(withCtx);
  check("5. a non-empty certificate_request_context is surfaced raw", parsed.certificateRequestContext.equals(Buffer.from([0xab, 0xcd])));
  check("5a. an empty certificate_request_context is the empty buffer", pki.tls.parseCertificateMessage(MSG).certificateRequestContext.length === 0);
  check("5b. per-entry extensions are surfaced raw (empty here)", parsed.entries[0].extensions.length === 0);
  // RFC 8446 sec. 4.2: an Extension is a uint16 type plus a uint16-prefixed value, so the
  // extensions vector is a whole number of them. Walking it is what stops a malformed Certificate
  // message being reported as structurally valid -- a one-byte vector cannot be an Extension.
  function entryWithExts(extBytes) {
    var elen = Buffer.alloc(2); elen.writeUInt16BE(extBytes.length);
    var e = Buffer.concat([Buffer.from([0, 0, 1]), Buffer.from([0x41]), elen, extBytes]);
    var len = Buffer.alloc(3); len.writeUIntBE(e.length, 0, 3);
    return Buffer.concat([Buffer.from([0]), len, e]);
  }
  check("5b1. an empty extensions vector decodes to no records",
    pki.tls.parseCertificateMessage(entryWithExts(Buffer.alloc(0))).entries[0].extensionList.length === 0);
  check("5b2. well-formed extensions decode to their type and raw value", (function () {
    var l = pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x2b, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0xff]))).entries[0].extensionList;
    return l.length === 2 && l[0].type === 43 && l[0].data.length === 0 && l[1].type === 10 && l[1].data.length === 1 && l[1].data[0] === 0xff;
  })());
  check("5b3. an extensions vector too short to be an Extension -> tls/bad-framing",
    codeOf(function () { return pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0xff]))); }) === "tls/bad-framing");
  check("5b4. a truncated extension header -> tls/truncated",
    codeOf(function () { return pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x2b, 0x00]))); }) === "tls/truncated");
  check("5b5. an extension value length past the vector -> tls/bad-framing",
    codeOf(function () { return pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x2b, 0x00, 0x09, 0x01]))); }) === "tls/bad-framing");
  // RFC 8446 sec. 4.2: "There MUST NOT be more than one extension of the same type in a given
  // extension block." Two records of one type make the block mean different things to a consumer
  // that reads the first and one that reads the last -- the same ambiguity a duplicate DER SET
  // member creates, so it is refused rather than surfaced.
  check("5b6. two extensions of the same type -> tls/bad-framing",
    codeOf(function () { return pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x2b, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00]))); }) === "tls/bad-framing");
  check("5b7. a duplicate is refused even when the values differ",
    codeOf(function () { return pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x0a, 0x00, 0x01, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x02]))); }) === "tls/bad-framing");
  check("5b8. distinct types in any order are still accepted",
    pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x33, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00]))).entries[0].extensionList.length === 3);
  // type 0 must not be special-cased away by a falsy-keyed seen-set.
  check("5b9. extension type 0 duplicated is refused (no falsy-key hole)",
    codeOf(function () { return pki.tls.parseCertificateMessage(entryWithExts(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))); }) === "tls/bad-framing");
  var empty = certMessage([]);
  check("5c. an empty certificate list is a valid message with no entries", pki.tls.parseCertificateMessage(empty).entries.length === 0);
  check("5d. RawPublicKey surfaces the slot as spki, not certData", (function () {
    var e = pki.tls.parseCertificateMessage(certMessage([LEAF]), { certificateType: "RawPublicKey" }).entries[0];
    return e.spki !== undefined && e.certData === undefined && e.spki.equals(LEAF);
  })());
  check("5e. certificate_type is declared, never guessed -- an unknown value is refused",
    codeOf(function () { return pki.tls.parseCertificateMessage(MSG, { certificateType: "GuessIt" }); }) === "tls/bad-input");
  // The entry payload is opaque<1..2^24-1>: a zero-length certificate is a framing violation.
  var zeroEntry = Buffer.concat([Buffer.from([0]), Buffer.from([0, 0, 5]), Buffer.from([0, 0, 0]), Buffer.from([0, 0])]);
  check("5f. a zero-length certificate entry -> tls/bad-framing",
    codeOf(function () { return pki.tls.parseCertificateMessage(zeroEntry); }) === "tls/bad-framing");
  check("5g. bytes after the certificate list -> tls/trailing-data",
    codeOf(function () { return pki.tls.parseCertificateMessage(Buffer.concat([MSG, Buffer.from([0x00])])); }) === "tls/trailing-data");
  check("5h. a certificate list length past the buffer -> tls/bad-framing", (function () {
    var b = Buffer.from(MSG); b.writeUIntBE(0xfffff0, 1, 3); return codeOf(function () { return pki.tls.parseCertificateMessage(b); });
  })() === "tls/bad-framing");
  // The byte ceiling does not bound the ENTRY COUNT: the smallest legal entry is 6 bytes, so a
  // message well inside the framing limit can declare hundreds of thousands, each costing far
  // more heap than wire. Unbounded, a 2.4 MB message allocated 400,000 entries.
  var tiny = Buffer.concat([Buffer.from([0, 0, 1]), Buffer.from([0x41]), Buffer.from([0, 0])]);
  function listOf(n) {
    var body = Buffer.concat(new Array(n).fill(tiny));
    var len = Buffer.alloc(3); len.writeUIntBE(body.length, 0, 3);
    return Buffer.concat([Buffer.from([0]), len, body]);
  }
  check("5i. a certificate list at the entry cap is accepted",
    pki.tls.parseCertificateMessage(listOf(pki.C.LIMITS.TLS_CERT_MAX_ENTRIES)).entries.length === pki.C.LIMITS.TLS_CERT_MAX_ENTRIES);
  check("5j. one entry past the cap -> tls/bad-framing",
    codeOf(function () { return pki.tls.parseCertificateMessage(listOf(pki.C.LIMITS.TLS_CERT_MAX_ENTRIES + 1)); }) === "tls/bad-framing");
  check("5k. a huge entry list is refused rather than allocated",
    codeOf(function () { return pki.tls.parseCertificateMessage(listOf(200000)); }) === "tls/bad-framing");
  // RFC 8446 sec. 4.4.2: under RawPublicKey the list "MUST contain no more than one CertificateEntry".
  check("5l. RawPublicKey accepts exactly one entry",
    pki.tls.parseCertificateMessage(listOf(1), { certificateType: "RawPublicKey" }).entries.length === 1);
  check("5m. RawPublicKey refuses a second entry (RFC 8446 sec. 4.4.2)",
    codeOf(function () { return pki.tls.parseCertificateMessage(listOf(2), { certificateType: "RawPublicKey" }); }) === "tls/bad-framing");
  // A Certificate message is a handshake message BODY, framed by a uint24, so one past that
  // ceiling could never have appeared on the wire. This entry point is reachable without going
  // through decompression, so it applies the bound itself rather than inheriting it. The smallest
  // over-limit message is only 4 bytes past: 1 context byte + a 3-byte list length of 0xffffff.
  check("5n. a certificate message past the handshake framing limit -> tls/too-large", (function () {
    var body = Buffer.alloc(0xffffff);
    body.writeUIntBE(0xffffff - 5, 0, 3);
    body.writeUInt16BE(0, 0xffffff - 2);
    var over = Buffer.concat([Buffer.from([0]), Buffer.from([0xff, 0xff, 0xff]), body]);
    return over.length === pki.C.LIMITS.TLS_CERT_MSG_MAX_BYTES + 4 &&
      codeOf(function () { return pki.tls.parseCertificateMessage(over); }) === "tls/too-large";
  })());

  // ==== the RFC 8879 sec. 5 bound, BOTH sides ================================================
  var good = zlib.deflateSync(MSG);
  check("6. uncompressed_length larger than the true output -> tls/length-mismatch",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length + 1, good)); }) === "tls/length-mismatch");
  check("6a. uncompressed_length smaller than the true output -> tls/too-large (the cap IS the declaration)",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length - 1, good)); }) === "tls/too-large");
  // The bomb. uncompressed_length is a uint24 and the default ceiling is 2^24-1, so a
  // declaration can never exceed it -- the ceiling is only ever binding once a caller
  // tightens it (6d). What defends the default case is that the DECLARATION IS THE CAP:
  // a stream that expands past what it claimed is refused mid-decompression either way.
  var bomb = zlib.deflateSync(Buffer.alloc(40 * 1024 * 1024, 0));
  check("6b. a bomb declaring the largest legal length is still refused -> tls/too-large",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, 0xffffff, bomb)); }) === "tls/too-large");
  check("6c. a bomb declaring a small length is refused at that declaration -> tls/too-large",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, 1000, bomb)); }) === "tls/too-large");
  check("6d. opts.maxOutputBytes tightens the cap DOWNWARD",
    codeOf(function () { return pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { maxOutputBytes: 100 }); }) === "tls/too-large");
  check("6e. a maxOutputBytes above the framing ceiling does not raise it",
    pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { maxOutputBytes: 0x7fffffff }).certificateMessage.length === MSG.length);
  check("6f. opts.maxOutputBytes must be a positive integer",
    codeOf(function () { return pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { maxOutputBytes: -1 }); }) === "tls/bad-input");
  check("6g. a declaration below a Certificate message's 4-byte minimum -> tls/bad-framing",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, 3, good)); }) === "tls/bad-framing");

  // ==== algorithm agreement (RFC 8879 sec. 4: it MUST be one the receiver offered) ===========
  check("7. an algorithm outside the RFC 8879 registry -> tls/unsupported-algorithm",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(9, MSG.length, good)); }) === "tls/unsupported-algorithm");
  check("7a. the reserved code point 0 -> tls/unsupported-algorithm",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(0, MSG.length, good)); }) === "tls/unsupported-algorithm");
  check("7b. an experimental-range code point -> tls/unsupported-algorithm",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(16384, MSG.length, good)); }) === "tls/unsupported-algorithm");
  check("7c. a registered algorithm the receiver did NOT advertise -> tls/unsupported-algorithm",
    codeOf(function () { return pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { allowedAlgorithms: ALGS.filter(function (a) { return a.name !== "zlib"; }).map(function (a) { return a.name; }) }); }) === "tls/unsupported-algorithm");
  check("7d. an advertised algorithm is accepted",
    pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { allowedAlgorithms: ["zlib"] }).algorithmName === "zlib");
  check("7e. allowedAlgorithms accepts code points too",
    pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { allowedAlgorithms: [1] }).algorithmName === "zlib");
  check("7f. allowedAlgorithms naming an unknown algorithm is refused at config time",
    codeOf(function () { return pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { allowedAlgorithms: ["lzma"] }); }) === "tls/bad-input");
  check("7g. allowedAlgorithms must be an array",
    codeOf(function () { return pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { allowedAlgorithms: "zlib" }); }) === "tls/bad-input");
  check("7h. compressing under an algorithm this toolkit lacks -> tls/unsupported-algorithm",
    codeOf(function () { return pki.tls.compressCertificate(MSG, { algorithm: "lzma" }); }) === "tls/unsupported-algorithm");
  // A registered algorithm this runtime cannot decompress safely is neither offered nor
  // accepted: advertising it would mean accepting a message whose truncation we could not
  // detect. It is refused on BOTH sides, and by name as well as by code point.
  check("7i. a registered algorithm dropped for this runtime is refused on both sides",
    UNSAFE.every(function (a) {
      return codeOf(function () { return pki.tls.compressCertificate(MSG, { algorithm: a.name }); }) === "tls/unsupported-algorithm" &&
             codeOf(function () { return pki.tls.compressCertificate(MSG, { algorithm: a.n }); }) === "tls/unsupported-algorithm" &&
             codeOf(function () { return pki.tls.decompressCertificate(buildCC(a.n, MSG.length, good)); }) === "tls/unsupported-algorithm" &&
             codeOf(function () { return pki.tls.decompressCertificate(pki.tls.compressCertificate(MSG), { allowedAlgorithms: [a.name] }); }) === "tls/bad-input";
    }));

  // ==== framing: one chain, one encoding =====================================================
  var wire = pki.tls.compressCertificate(MSG);
  check("8. a byte after the CompressedCertificate -> tls/trailing-data",
    codeOf(function () { return pki.tls.decompressCertificate(Buffer.concat([wire, Buffer.from([0x00])])); }) === "tls/trailing-data");
  check("8a. a truncated message -> tls/bad-framing",
    codeOf(function () { return pki.tls.decompressCertificate(wire.subarray(0, wire.length - 3)); }) === "tls/bad-framing");
  check("8b. a message shorter than the fixed header -> tls/truncated",
    codeOf(function () { return pki.tls.decompressCertificate(Buffer.from([0x00, 0x01, 0x00])); }) === "tls/truncated");
  check("8c. an empty compressed body (opaque<1..>) -> tls/bad-framing",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, 100, Buffer.alloc(0))); }) === "tls/bad-framing");
  // Trailing bytes INSIDE the compressed frame: every decompressor stops at the frame end and
  // would otherwise ignore them, giving one chain a second encoding under one signature.
  check("8d. trailing bytes after the compressed frame -> tls/decompress-failed",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length, Buffer.concat([good, Buffer.from("junk")]))); }) === "tls/decompress-failed");
  check("8e. a second complete frame appended -> tls/decompress-failed",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length, Buffer.concat([good, zlib.deflateSync(Buffer.from("x"))]))); }) === "tls/decompress-failed");
  check("8f. a body that is not the declared codec -> tls/decompress-failed",
    codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length, zlib.brotliCompressSync(MSG))); }) === "tls/decompress-failed");
  check("8g. a corrupt stream -> tls/decompress-failed", (function () {
    var bad = Buffer.from(good); bad[bad.length - 3] ^= 0xff;
    return codeOf(function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length, bad)); });
  })() === "tls/decompress-failed");

  // ==== producer-side input validation =======================================================
  check("9. a certificate message below the 4-byte minimum -> tls/bad-input",
    codeOf(function () { return pki.tls.compressCertificate(Buffer.from([0x00])); }) === "tls/bad-input");
  check("9a. a non-byte-source input -> tls/bad-input",
    codeOf(function () { return pki.tls.compressCertificate(42); }) === "tls/bad-input");
  check("9b. a non-byte-source input to decompress -> tls/bad-input",
    codeOf(function () { return pki.tls.decompressCertificate(null); }) === "tls/bad-input");
  check("9c. an invalid compression level -> tls/bad-input",
    codeOf(function () { return pki.tls.compressCertificate(MSG, { level: 99 }); }) === "tls/bad-input");
  // The handshake framing ceiling on the producing side: RFC 8446 sec. 4 frames a Handshake
  // with a uint24 length, so a message at 2^24 bytes cannot be sent compressed or otherwise.
  check("9d. a certificate message past the handshake framing limit -> tls/too-large",
    codeOf(function () { return pki.tls.compressCertificate(Buffer.alloc(pki.C.LIMITS.TLS_CERT_MSG_MAX_BYTES + 1)); }) === "tls/too-large");
  check("9e. opts.level must be an integer",
    codeOf(function () { return pki.tls.compressCertificate(MSG, { level: 1.5 }); }) === "tls/bad-input");
  // Each codec reads its level through a DIFFERENT option -- zlib a top-level `level`, brotli
  // and zstd numbered `params` entries -- and node silently ignores the wrong one. So the proof
  // is byte equality with a direct call using that codec's own option: if the level were dropped,
  // the emitted body would be the default encoding instead. (Comparing two levels to each other
  // proves nothing: content this compressible reaches the same encoding at every level.)
  check("9f. opts.level reaches the codec it names, through that codec's own option",
    ALGS.every(function (a) {
      var body = pki.tls.compressCertificate(MSG, { algorithm: a.name, level: 1 }).subarray(8);
      var p = {};
      var direct;
      if (a.name === "zlib") direct = zlib.deflateSync(MSG, { level: 1 });
      else if (a.name === "brotli") { p[zlib.constants.BROTLI_PARAM_QUALITY] = 1; direct = zlib.brotliCompressSync(MSG, { params: p }); }
      else { p[zlib.constants.ZSTD_c_compressionLevel] = 1; direct = zlib.zstdCompressSync(MSG, { params: p }); }
      return body.equals(direct);
    }));
  // The CompressedCertificate is ITSELF a handshake message body, so the emitted message -- not
  // just the message it carries -- must fit the uint24 framing. Incompressible content just under
  // the ceiling grows by the 8-byte header, which is the case that escapes an input-only bound.
  check("9g. an emitted message that would exceed the framing limit -> tls/too-large", (function () {
    var room = pki.C.LIMITS.TLS_CERT_MSG_MAX_BYTES - 12;
    var payload = crypto.randomBytes(room);            // incompressible, so the wire message grows
    var big = certMessage([payload]);
    if (big.length > pki.C.LIMITS.TLS_CERT_MSG_MAX_BYTES) return true;   // rejected as input instead
    return codeOf(function () { return pki.tls.compressCertificate(big); }) === "tls/too-large";
  })());
  check("9h. a compressed message longer than the framing limit is refused on decode",
    codeOf(function () { return pki.tls.decompressCertificate(Buffer.alloc(pki.C.LIMITS.TLS_CERT_MSG_MAX_BYTES + 1)); }) === "tls/too-large");

  // ==== every fault is a typed TlsError, never a raw TypeError ===============================
  var faults = [
    function () { return pki.tls.decompressCertificate(buildCC(9, MSG.length, good)); },
    function () { return pki.tls.decompressCertificate(buildCC(1, MSG.length + 1, good)); },
    function () { return pki.tls.decompressCertificate(Buffer.alloc(2)); },
    function () { return pki.tls.parseCertificateMessage(Buffer.alloc(0)); },
  ];
  check("10. every decode fault is a typed TlsError with a tls/* code", faults.every(function (f) {
    try { f(); return false; } catch (e) { return e instanceof pki.errors.TlsError && /^tls\//.test(e.code); }
  }));
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
