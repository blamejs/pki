// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// @module pki.cms + the @primitive blocks live in cms-verify.js, which re-exports these (the

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
var NULL_PARAMS_DER = Buffer.from([0x05, 0x00]);

async function compress(content, opts) {
  opts = opts || {};
  var raw = guard.bytes.source(content, CmsError, "cms/bad-input", "content");
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
    b.sequence([b.oid(OID_ZLIB)]),
    b.sequence([b.oid(ctOid), b.explicit(0, b.octetString(stream))]),
  ]);
  var ci = b.sequence([b.oid(O("compressedData")), b.explicit(0, cd)]);
  return opts.pem ? schemaCms.pemEncode(ci, "CMS") : ci;
}

async function decompress(input, opts) {
  opts = opts || {};
  var cap = C.LIMITS.COMPRESS_MAX_BYTES;
  if (opts.maxOutputBytes !== undefined) {
    var mo = opts.maxOutputBytes;
    if (typeof mo !== "number" || !isFinite(mo) || mo <= 0 || Math.floor(mo) !== mo) throw _err("cms/bad-input", "opts.maxOutputBytes must be a positive integer");
    if (mo < cap) cap = mo;
  }
  var parsed = schemaCms.parse(_toDer(input));
  if (parsed.contentTypeName !== "compressedData") throw _err("cms/unsupported-content-type", "input is not a CMS CompressedData (got " + parsed.contentTypeName + ")");
  var alg = parsed.compressionAlgorithm;
  if (alg.oid !== OID_ZLIB) throw _err("cms/unsupported-algorithm", "unsupported compressionAlgorithm " + (alg.name || alg.oid) + " (only id-alg-zlibCompress, RFC 3274 sec. 2)");
  if (alg.parameters != null && Buffer.compare(alg.parameters, NULL_PARAMS_DER) !== 0) throw _err("cms/bad-algorithm-parameters", "id-alg-zlibCompress parameters must be absent or NULL (RFC 3274 sec. 2)");
  var eci = parsed.encapContentInfo;
  if (eci.eContent == null) throw _err("cms/no-encapsulated-content", "the CompressedData carries no encapsulated content (a detached CompressedData cannot be decompressed)");
  var content = _inflateBounded(eci.eContent, cap);
  return {
    content: content,
    contentType: eci.eContentType,
    contentTypeName: oid.name(eci.eContentType) || eci.eContentType,
    compressionAlgorithm: alg.name || alg.oid,
  };
}

function _toDer(input) {
  if (guard.bytes.isByteSource(input)) return guard.bytes.snapshotSource(input, CmsError, "cms/bad-input", "input");
  if (typeof input === "string") { try { return schemaCms.pemDecode(input); } catch (e) { throw _err("cms/bad-input", "the CMS PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "input must be a DER Buffer, Uint8Array, or PEM string");
}

function _inflateBounded(stream, cap) {
  var view = guard.bytes.view(stream, CmsError, "cms/decompress-failed", "the compressed content");
  return guard.compress.bounded("zlib", view, cap, _err,
    { tooLarge: "cms/decompress-too-large", failed: "cms/decompress-failed" }, "the compressed content");
}

module.exports = { compress: compress, decompress: decompress };
