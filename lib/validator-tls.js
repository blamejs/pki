// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the codec whose
// TLS handshake handling composes this validator (pki.tls).
//
// validator-tls -- the SINGLE home for the framing conformance of the TLS handshake
// structures that carry certificates: the RFC 8879 sec. 4 CompressedCertificate and the
// RFC 8446 sec. 4.4.2 Certificate message it decompresses to. Sibling to the guard family:
// a validator owns a decoded TYPE's COMPLETE framing rule set once, so the vector bounds,
// the minimum sizes and the trailing-byte rejection cannot drift as consumers are added.
//
// Every field is unsigned big-endian, packed with no padding, in the TLS presentation
// language: `uintN` is a fixed-width integer and `opaque<min..max>` is a length prefix wide
// enough for `max` followed by exactly that many bytes. The caller supplies its typed error
// constructor E (a validator takes a class, `new E(code, msg)`, where the guard family
// takes a factory) plus the `codes` its domain uses for each fault.
//
// Rule set (verbatim against RFC 8879 sec. 4 and RFC 8446 sec. 4.4.2):
//   - compressedCertificate: uint16 algorithm, uint24 uncompressed_length, then
//     opaque compressed_certificate_message<1..2^24-1>, where the minimum of 1 makes an empty
//     compressed body a framing violation, which matters because the three decompressors do
//     not agree on what empty input means. Bytes after the vector are rejected: one chain
//     must have exactly one encoding.
//   - certificateMessage: opaque certificate_request_context<0..2^8-1>, then
//     CertificateEntry certificate_list<0..2^24-1>, each entry an opaque<1..2^24-1> payload
//     (cert_data, or a SubjectPublicKeyInfo under RFC 7250 RawPublicKey) plus
//     Extension extensions<0..2^16-1>. Bytes after the list are rejected. A zero-length
//     entry payload is a framing violation, not a blank certificate.
//
// This validator decodes and bounds STRUCTURE only. Which algorithms are acceptable, what
// the output cap is, and whether the recovered length matches its declaration are the
// codec's policy and stay with the codec.
//
// The RFC 8446 sec. 4.4.2 / sec. 4.2 rules that bind a Certificate-message DECODER, and where
// each one lands, enumerated so the ones deliberately left unenforced are a recorded decision
// and not an oversight:
//   ENFORCED here:
//     - RawPublicKey carries at most one CertificateEntry (sec. 4.4.2).
//     - No extension type appears twice in one extension block (sec. 4.2).
//     - Every vector's framing, its declared minimum, and no trailing bytes at either level.
//   Not enforced, deliberately:
//     - "The sender's certificate MUST come in the first CertificateEntry" is about which
//       certificate a consumer treats as the leaf, not about framing. Entries are surfaced in
//       wire order and never reordered, so the caller sees exactly what arrived, and the same
//       section tells implementations to tolerate extraneous certificates and arbitrary
//       orderings beyond the first, so refusing any order here would be wrong.
//     - "The server's certificate_list MUST always be non-empty" is conditioned on the sender's
//       role: a client legitimately sends an empty list when it has no certificate to offer.
//       This decoder has no role, so an empty list decodes to zero entries and the caller, which
//       does know the role, decides.
//     - Extension correspondence ("extensions MUST correspond to ones from the client") and any
//       extension's own contents (a status_request body being a CertificateStatus) need the
//       negotiation state and the extension's semantics. Neither exists here: extension values
//       are surfaced raw.
//     - The OpenPGP certificate type is unreachable, not checked: the only accepted
//       types are X509 and RawPublicKey, and anything else is refused at the entry point.

var C = require("./constants");
var ByteReader = require("./byte-reader");

// The widest an opaque<..2^24-1> vector can be, and the width of the length prefix that
// frames it. Both come straight from the TLS presentation language.
var MAX_VECTOR_24 = 0xffffff;
var MAX_VECTOR_16 = 0xffff;

// RFC 8446 sec. 4.4.2 frames a Certificate message as a 1-byte-prefixed request context plus
// a 3-byte-prefixed entry list, so the smallest well-formed message is 4 bytes.
var MIN_CERT_MSG_BYTES = 4;

// compressedCertificate(view, E, codes) -> { algorithm, uncompressedLength, body }.
// Decode the RFC 8879 sec. 4 framing. `codes` names { truncated, framing, trailing }.
// @enforced-by behavioral -- a packed TLS presentation-language decode has no rename-proof
// code shape; the framing rules are pinned by the RED conformance vectors that drive the
// shipped consumer (pki.tls.decompressCertificate) on each malformed shape.
function compressedCertificate(view, E, codes) {
  var r = new ByteReader(view, 0, view.length, E, codes.truncated);
  var algorithm = r.u16(codes.truncated);
  var uncompressedLength = r.u24(codes.truncated);
  // opaque compressed_certificate_message<1..2^24-1>, minimum 1, so an empty body is a
  // framing violation and not something a decompressor gets to interpret.
  var body = r.vector(3, 1, MAX_VECTOR_24, codes.framing);
  if (!r.atEnd()) {
    throw new E(codes.trailing, "the CompressedCertificate carries " + r.remaining() +
      " byte(s) after the compressed message");
  }
  return { algorithm: algorithm, uncompressedLength: uncompressedLength, body: Buffer.from(body) };
}

// The extensions vector of a CertificateEntry, decoded to its records. RFC 8446 sec. 4.2 makes an
// Extension a uint16 type plus a uint16-prefixed value, so the vector is a whole number of them and
// the smallest is 4 bytes. Walking it is what keeps a malformed Certificate message from passing as
// structurally valid: a one-byte vector cannot be an Extension, and accepting the bytes opaquely
// would report it as well-formed. Each record's value is surfaced raw: this decodes the framing,
// never the extension's own contents.
function _extensionRecords(view, E, codes) {
  var r = new ByteReader(view, 0, view.length, E, codes.truncated);
  var out = [];
  var seen = Object.create(null);
  while (!r.atEnd()) {
    // Each iteration consumes at least 4 bytes and every read is bounds-checked, so the walk
    // always terminates or faults.
    var type = r.u16(codes.framing);
    var data = r.vector(2, 0, MAX_VECTOR_16, codes.framing);
    // RFC 8446 sec. 4.2: "There MUST NOT be more than one extension of the same type in a given
    // extension block." Left unenforced, one type could appear twice and a consumer reading only
    // the first (or only the last) would act on a different value than another implementation --
    // the same one-structure-two-meanings ambiguity a duplicate DER SET member creates.
    if (seen[type]) {
      throw new E(codes.framing, "the extension block carries more than one extension of type " +
        type + " (RFC 8446 sec. 4.2)");
    }
    seen[type] = true;
    out.push({ type: type, data: Buffer.from(data) });
  }
  return out;
}

// certificateMessage(view, E, codes, certificateType) -> { certificateRequestContext, entries }.
// Decode the RFC 8446 sec. 4.4.2 Certificate message. `codes` names { truncated, framing,
// trailing }. `certificateType` is "X509" or "RawPublicKey" and is DECLARED by the caller --
// it is negotiated by a separate extension (RFC 7250) and is not present in these bytes, so
// it can never be inferred from them.
// @enforced-by behavioral -- a packed TLS presentation-language decode has no rename-proof
// code shape; the framing rules are pinned by the RED conformance vectors that drive the
// shipped consumer (pki.tls.parseCertificateMessage) on each malformed shape.
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
  // RFC 8446 sec. 4.4.2: under a negotiated RawPublicKey certificate type the list "MUST contain
  // no more than one CertificateEntry". Otherwise the count is bounded because the byte ceiling
  // does not bound it -- the smallest legal entry is 6 bytes, so a message well inside the
  // framing limit can declare millions, each costing far more heap than wire.
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
