// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var C = require("./constants");
var ByteReader = require("./byte-reader");

var MAX_VECTOR_24 = 0xffffff;
var MAX_VECTOR_16 = 0xffff;

var MIN_CERT_MSG_BYTES = 4;

// @enforced-by behavioral -- a packed TLS presentation-language decode has no rename-proof
function compressedCertificate(view, E, codes) {
  var r = new ByteReader(view, 0, view.length, E, codes.truncated);
  var algorithm = r.u16(codes.truncated);
  var uncompressedLength = r.u24(codes.truncated);
  var body = r.vector(3, 1, MAX_VECTOR_24, codes.framing);
  if (!r.atEnd()) {
    throw new E(codes.trailing, "the CompressedCertificate carries " + r.remaining() +
      " byte(s) after the compressed message");
  }
  return { algorithm: algorithm, uncompressedLength: uncompressedLength, body: Buffer.from(body) };
}

function _extensionRecords(view, E, codes) {
  var r = new ByteReader(view, 0, view.length, E, codes.truncated);
  var out = [];
  var seen = Object.create(null);
  while (!r.atEnd()) {
    var type = r.u16(codes.framing);
    var data = r.vector(2, 0, MAX_VECTOR_16, codes.framing);
    if (seen[type]) {
      throw new E(codes.framing, "the extension block carries more than one extension of type " +
        type + " (RFC 8446 sec. 4.2)");
    }
    seen[type] = true;
    out.push({ type: type, data: Buffer.from(data) });
  }
  return out;
}

// @enforced-by behavioral -- a packed TLS presentation-language decode has no rename-proof
function certificateMessage(view, E, codes, certificateType) {
  var r = new ByteReader(view, 0, view.length, E, codes.truncated);
  var ctxLen = r.u8(codes.truncated);
  var context = r.fixed(ctxLen, codes.framing);
  var listLen = r.u24(codes.truncated);
  var list = r.subReader(listLen, codes.framing);
  if (!r.atEnd()) {
    throw new E(codes.trailing, "the Certificate message carries " + r.remaining() +
      " byte(s) after the certificate list");
  }
  var maxEntries = certificateType === "RawPublicKey" ? 1 : C.LIMITS.TLS_CERT_MAX_ENTRIES;
  var entries = [];
  while (!list.atEnd()) {
    if (entries.length >= maxEntries) {
      throw new E(codes.framing, "the certificate list carries more than " + maxEntries +
        " entr" + (maxEntries === 1 ? "y" : "ies") +
        (certificateType === "RawPublicKey" ? " (RFC 8446 sec. 4.4.2 permits at most one under RawPublicKey)" : ""));
    }
    var data = list.vector(3, 1, MAX_VECTOR_24, codes.framing);
    var extensions = list.vector(2, 0, MAX_VECTOR_16, codes.framing);
    var entry = {
      extensions: Buffer.from(extensions),
      extensionList: _extensionRecords(extensions, E, codes),
    };
    if (certificateType === "RawPublicKey") entry.spki = Buffer.from(data);
    else entry.certData = Buffer.from(data);
    entries.push(entry);
  }
  return { certificateRequestContext: Buffer.from(context), entries: entries };
}

module.exports = {
  compressedCertificate: compressedCertificate,
  certificateMessage: certificateMessage,
  MIN_CERT_MSG_BYTES: MIN_CERT_MSG_BYTES,
  MAX_VECTOR_24: MAX_VECTOR_24,
};
