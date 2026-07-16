// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cms.compress / pki.cms.decompress implementation. The operator-facing
// @module pki.cms + the @primitive blocks live in cms-verify.js, which re-exports these (the
// cms-encrypt.js / cms-decrypt.js model).
//
// CMS CompressedData (RFC 3274) -- the size-transform content type. compress ZLIB-compresses
// (RFC 1950 / RFC 1951) the content and wraps it as a CompressedData ContentInfo; decompress parses
// one (over the shipped strict schema-cms parser), enforces version 0 + id-alg-zlibCompress +
// absent-or-NULL params (RFC 3274 sec. 2), and BOUNDED-inflates the eContent. There is NO crypto
// here -- CompressedData provides no integrity / confidentiality / authentication (RFC 8551 sec.
// 2.4.5); it is purely a size transform. The one load-bearing defense is the decompression-bomb
// cap: inflate stops at C.LIMITS.COMPRESS_MAX_BYTES BEFORE the output is materialized (a
// resource-exhaustion defense, CWE-409), and every zlib fault collapses to a uniform typed error.

var zlib = require("zlib");
var oid = require("./oid");
var schemaCms = require("./schema-cms");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var C = require("./constants");
var asn1 = require("./asn1-der");
var b = asn1.build;
var CmsError = frameworkError.CmsError;

function O(n) { return oid.byName(n); }
function _err(code, message, cause) { return new CmsError(code, message, cause); }

var OID_ZLIB = O("id-alg-zlibCompress");
// The NULL params DER (0x05 0x00) -- the one non-absent encoding RFC 3274 sec. 2 permits (MAY be NULL).
var NULL_PARAMS_DER = Buffer.from([0x05, 0x00]);

// Compress `content` and wrap it as a CMS CompressedData ContentInfo (RFC 3274 sec. 1.1): version 0,
// compressionAlgorithm = id-alg-zlibCompress with ABSENT parameters, encapContentInfo = { eContentType
// (default id-data), eContent = the RFC 1950 ZLIB stream }.
async function compress(content, opts) {
  opts = opts || {};
  var raw = guard.bytes.view(content, CmsError, "cms/bad-input", "content");
  var level = opts.level;
  if (level !== undefined && (typeof level !== "number" || !isFinite(level) || Math.floor(level) !== level)) throw _err("cms/bad-input", "opts.level must be an integer");
  var ctName = opts.contentType || "data";
  var ctOid = O(ctName);
  if (!ctOid) throw _err("cms/bad-input", "opts.contentType is not a known OID name: " + ctName);
  var stream;
  try { stream = zlib.deflateSync(raw, level !== undefined ? { level: level } : undefined); }
  catch (e) { throw _err("cms/bad-input", "the content could not be compressed (check opts.level)", e); }
  var cd = b.sequence([
    b.integer(0),
    b.sequence([b.oid(OID_ZLIB)]),                 // compressionAlgorithm, params ABSENT (RFC 3274 sec. 2)
    b.sequence([b.oid(ctOid), b.explicit(0, b.octetString(stream))]),
  ]);
  var ci = b.sequence([b.oid(O("compressedData")), b.explicit(0, cd)]);
  return opts.pem ? schemaCms.pemEncode(ci, "CMS") : ci;
}

// Parse a CMS CompressedData and recover its content. Requires contentTypeName == compressedData,
// version 0 (enforced by the parser), compressionAlgorithm == id-alg-zlibCompress with absent-or-NULL
// params, and a present eContent; then BOUNDED-inflates. Every failure is a typed CmsError.
async function decompress(input, opts) {
  opts = opts || {};
  var cap = C.LIMITS.COMPRESS_MAX_BYTES;
  if (opts.maxOutputBytes !== undefined) {
    var mo = opts.maxOutputBytes;
    if (typeof mo !== "number" || !isFinite(mo) || mo <= 0 || Math.floor(mo) !== mo) throw _err("cms/bad-input", "opts.maxOutputBytes must be a positive integer");
    if (mo < cap) cap = mo;   // a caller may tighten the cap DOWNWARD only, never loosen it
  }
  var parsed = schemaCms.parse(_toDer(input));
  if (parsed.contentTypeName !== "compressedData") throw _err("cms/unsupported-content-type", "input is not a CMS CompressedData (got " + parsed.contentTypeName + ")");
  var alg = parsed.compressionAlgorithm;
  if (alg.oid !== OID_ZLIB) throw _err("cms/unsupported-algorithm", "unsupported compressionAlgorithm " + (alg.name || alg.oid) + " (only id-alg-zlibCompress, RFC 3274 sec. 2)");
  // RFC 3274 sec. 2: the parameters SHOULD be omitted but MAY be NULL -- reject any other encoding.
  if (alg.parameters != null && Buffer.compare(alg.parameters, NULL_PARAMS_DER) !== 0) throw _err("cms/bad-algorithm-parameters", "id-alg-zlibCompress parameters must be absent or NULL (RFC 3274 sec. 2)");
  var eci = parsed.encapContentInfo;
  if (eci.eContent == null) throw _err("cms/no-encapsulated-content", "the CompressedData carries no encapsulated content (a detached CompressedData cannot be decompressed)");
  var content = _inflateBounded(eci.eContent, cap);
  return {
    content: content,
    contentType: eci.eContentType,
    contentTypeName: oid.name(eci.eContentType) || eci.eContentType,
    // Coverage residual: reaching here requires alg.oid === id-alg-zlibCompress (line above), which is
    // always a registered name, so the `|| alg.oid` fallback is a defensive belt, never selected.
    compressionAlgorithm: alg.name || alg.oid,
  };
}

function _toDer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input === "string") { try { return schemaCms.pemDecode(input); } catch (e) { throw _err("cms/bad-input", "the CMS PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "input must be a DER Buffer, Uint8Array, or PEM string");
}

// Inflate an RFC 1950 ZLIB stream, bounding the output at `cap` bytes BEFORE it is materialized:
// Node's maxOutputLength throws ERR_BUFFER_TOO_LARGE the moment the output would exceed the bound
// (it does not first allocate the whole output), so a decompression bomb cannot exhaust memory
// (CWE-409). The cap breach maps to cms/decompress-too-large; every other zlib fault (bad RFC-1950
// header, truncated stream, corrupt DEFLATE, trailing garbage) collapses to the uniform
// cms/decompress-failed -- a per-errno surface would be needless attack telemetry.
function _inflateBounded(stream, cap) {
  var view = guard.bytes.view(stream, CmsError, "cms/decompress-failed", "the compressed content");
  try {
    return zlib.inflateSync(view, { maxOutputLength: cap });
  } catch (e) {
    if (e && e.code === "ERR_BUFFER_TOO_LARGE") throw _err("cms/decompress-too-large", "the decompressed output exceeds the " + cap + "-byte cap (a decompression-bomb defense)", e);
    throw _err("cms/decompress-failed", "the compressed content could not be decompressed", e);
  }
}

module.exports = { compress: compress, decompress: decompress };
