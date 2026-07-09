// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.ct
 * @nav        Transparency
 * @title      CT
 * @order      210
 * @slug       ct
 *
 * @intro
 *   Certificate Transparency SCT-list handling per RFC 6962. `parseSctList`
 *   decodes the `SignedCertificateTimestampList` an X.509 certificate (or an
 *   OCSP response) carries in the SCT extension into its individual signed
 *   certificate timestamps.
 *
 *   The SCT payload is encoded in the TLS presentation language (RFC 8446 §3 /
 *   RFC 5246 §4 conventions) — positional, tag-less, fixed-width big-endian
 *   integers and length-prefixed opaque vectors — NOT ASN.1/DER. So this module
 *   owns a bounded big-endian TLS-struct reader rather than composing the DER
 *   schema engine; the only ASN.1 surface is the §3.3 double wrap (the
 *   extension value is a DER OCTET STRING whose content is another DER OCTET
 *   STRING whose content is the TLS list — the certificate/OCSP layer peels the
 *   outer, this module peels the inner).
 *
 *   Structure is decoded, crypto is surfaced RAW: each SCT surfaces its `logId`
 *   (32 raw bytes — SHA-256 of the log's SPKI, never recomputed), the exact
 *   `timestamp` as a BigInt, the raw `extensions`, the named-but-not-interpreted
 *   `hashAlg`/`sigAlg` code points, and the raw `signature`. The parser NEVER
 *   verifies a signature, recomputes a LogID, or trusts a log — a verifier
 *   composes `webcrypto` over `reconstructSignedData(...)`, the exact
 *   `digitally-signed` preimage. DER-only carrier, fail-closed.
 *
 * @card
 *   Parse RFC 6962 Certificate Transparency SCT lists from a certificate or OCSP
 *   extension — per-SCT logId / timestamp (BigInt) / algorithm / raw signature,
 *   the signed-preimage reconstruction surfaced for external verification,
 *   bounded TLS-struct decode, fail-closed.
 */

var asn1 = require("./asn1-der.js");
var constants = require("./constants.js");
var frameworkError = require("./framework-error.js");

var CtError = frameworkError.CtError;
var C = constants;

// RFC 5246 §7.4.1.4.1 code points — 1-byte, NOT OIDs. Surfaced named; an
// unknown code surfaces as its numeric byte with a null name (never rejected —
// off-profile-pair rejection is a verifier-tier log-conformance concern).
var HASH_ALGORITHMS = {
  0: "none", 1: "md5", 2: "sha1", 3: "sha224", 4: "sha256", 5: "sha384", 6: "sha512",
};
var SIGNATURE_ALGORITHMS = { 0: "anonymous", 1: "rsa", 2: "dsa", 3: "ecdsa" };

// A minimum viable v1 SCT body: version(1) + LogID(32) + timestamp(8) +
// empty-extensions(2) + digitally-signed{ hash(1) + sig(1) + empty-sig(2) } = 47.
var SCT_MIN_BODY = 47;
var LOGID_BYTES = 32;
var MAX_SAFE = 9007199254740991n;   // 2^53 - 1; above this a Number loses precision

// ---- TlsReader — the one net-new primitive (an ENCODING layer, not a schema
// combinator): a bounded big-endian TLS-vector cursor with a hard [pos, end).
// A lying inner length can overrun only the current sub-reader's `end`, never
// the parent buffer, so bounds-before-slice is structural.
function TlsReader(buf, start, end) { this.buf = buf; this.pos = start; this.end = end; }
TlsReader.prototype._need = function (n, code) {
  if (this.pos + n > this.end) {
    throw new CtError(code || "ct/truncated", "need " + n + " byte(s), only " + (this.end - this.pos) + " remain");
  }
};
TlsReader.prototype.u8 = function (code) { this._need(1, code); return this.buf[this.pos++]; };
TlsReader.prototype.u16 = function (code) { this._need(2, code); var v = this.buf.readUInt16BE(this.pos); this.pos += 2; return v; };
TlsReader.prototype.u24 = function (code) {
  this._need(3, code);
  var v = (this.buf[this.pos] << 16) | (this.buf[this.pos + 1] << 8) | this.buf[this.pos + 2];
  this.pos += 3; return v;
};
TlsReader.prototype.u64 = function (code) { this._need(8, code); var v = this.buf.readBigUInt64BE(this.pos); this.pos += 8; return v; };
TlsReader.prototype.fixed = function (n, code) {
  this._need(n, code);
  var s = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return s;
};
// opaque<min..max> — a length-prefixed vector (lenWidth-byte big-endian prefix).
// The length prefix itself is a plain read (a truncation there is ct/truncated);
// only a LYING length whose body overruns the bound carries the field's own code.
TlsReader.prototype.vector = function (lenWidth, min, max, code) {
  var len = lenWidth === 3 ? this.u24() : this.u16();
  if (len < min) throw new CtError(code, "vector length " + len + " below minimum " + min);
  if (max != null && len > max) throw new CtError(code, "vector length " + len + " above maximum " + max);
  this._need(len, code);
  var s = this.buf.subarray(this.pos, this.pos + len); this.pos += len; return s;
};
TlsReader.prototype.subReader = function (len, code) {
  this._need(len, code);
  var r = new TlsReader(this.buf, this.pos, this.pos + len); this.pos += len; return r;
};
TlsReader.prototype.remaining = function () { return this.end - this.pos; };
TlsReader.prototype.atEnd = function () { return this.pos === this.end; };

// Peel the RFC 6962 §3.3 inner DER OCTET STRING (the certificate/OCSP layer
// already peeled the outer extnValue OCTET STRING). Rides the strict codec, so
// an indefinite length / constructed OCTET STRING / trailing bytes / single
// wrap all fail closed here; the asn1/* fault attaches as `.cause`.
function _peelInner(extValue) {
  var node;
  try { node = asn1.decode(extValue); }
  catch (e) { throw new CtError("ct/bad-der", "the SCT-list extension value is not valid DER (RFC 6962 §3.3)", e); }
  try { return asn1.read.octetString(node); }
  catch (e) { throw new CtError("ct/bad-der", "the SCT-list extension value must be a DER OCTET STRING wrapping the TLS list (RFC 6962 §3.3)", e); }
}

function _toBuffer(v, field) {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  throw new CtError("ct/bad-input", field + " must be a Buffer or Uint8Array");
}

// Parse one SerializedSCT body inside a sub-reader bounded to the element (so a
// lying extensions/signature length overruns the element, never the list). A
// version this parser does not define is preserved OPAQUE, not rejected: RFC 6962
// §3.3 gives every SerializedSCT its own length prefix precisely so a client "can
// still parse old SCTs while skipping over new SCTs whose versions they don't
// understand" — so an unknown version yields { unknown, version, rawSct } and the
// v1-specific field decode (and the 47-byte floor) is skipped.
function _parseSct(r, sctLen) {
  var bodyStart = r.pos;
  var version = r.u8();   // sctLen >= 1 is guaranteed by the SerializedSCT<1..> check
  if (version !== 0) {
    return { unknown: true, version: version, rawSct: r.buf.subarray(bodyStart, r.end) };
  }
  if (sctLen < SCT_MIN_BODY) {
    throw new CtError("ct/sct-too-short", "a v1 SCT body is at least " + SCT_MIN_BODY + " bytes, got " + sctLen + " (RFC 6962 §3.2)");
  }
  var logId = r.fixed(LOGID_BYTES);
  var timestamp = r.u64();
  var extensions = r.vector(2, 0, null, "ct/ext-overrun");
  var hashAlg = r.u8();
  var sigAlg = r.u8();
  var signature = r.vector(2, 0, null, "ct/sig-overrun");
  if (!r.atEnd()) {
    throw new CtError("ct/sct-trailing-bytes", (r.end - r.pos) + " byte(s) left in a SerializedSCT after the signature (RFC 6962 §3.3)");
  }
  var timestampMs = timestamp <= MAX_SAFE ? Number(timestamp) : null;
  return {
    version: 0,
    logId: logId, logIdHex: logId.toString("hex"),
    timestamp: timestamp,
    timestampMs: timestampMs,
    timestampDate: new Date(timestampMs != null ? timestampMs : Number(timestamp)),
    extensions: extensions,
    hashAlg: hashAlg, sigAlg: sigAlg,
    signatureAlgorithm: {
      hash: hashAlg, hashName: HASH_ALGORITHMS[hashAlg] || null,
      signature: sigAlg, signatureName: SIGNATURE_ALGORITHMS[sigAlg] || null,
    },
    signature: signature,
    rawSct: r.buf.subarray(bodyStart, r.end),
  };
}

/**
 * @primitive  pki.ct.parseSctList
 * @signature  pki.ct.parseSctList(extValue) -> { scts, unknownScts }
 * @since      0.1.20
 * @status     experimental
 * @spec       RFC 6962, RFC 5246, RFC 8446
 * @related    pki.ct.reconstructSignedData, pki.schema.x509.parse
 *
 * Parse the value of an RFC 6962 SCT-list extension (the raw `extnValue`
 * content an `x509.parse` / OCSP extension already surfaces) into
 * `{ scts, unknownScts }`. Each entry of `scts` is a fully decoded v1 SCT:
 * `version` (0), `logId` (32-byte Buffer) + `logIdHex`, `timestamp` (BigInt,
 * exact) + `timestampMs` (Number or `null` above 2^53) + `timestampDate`,
 * `extensions` (raw Buffer), `hashAlg` / `sigAlg` (1-byte code points) + a named
 * `signatureAlgorithm`, the raw `signature` Buffer, and `rawSct` (the full
 * SerializedSCT body). A SerializedSCT whose version this parser does not define
 * is preserved OPAQUE in `unknownScts` as `{ version, rawSct }` rather than
 * failing the list — RFC 6962 §3.3 frames each SerializedSCT with its own length
 * so unknown versions are skippable (forward compatibility).
 *
 * The extension value is a DER `OCTET STRING` wrapping the TLS-encoded list
 * (RFC 6962 §3.3 double wrap); everything below that peel is TLS presentation
 * language, decoded with a bounded cursor. Structure is decoded, crypto is
 * surfaced RAW — the signature is never verified and the LogID never recomputed.
 *
 * Throws `CtError` with a stable `ct/*` code on any malformed input (a bad inner
 * DER wrap is `ct/bad-der` with the `asn1/*` fault as `.cause`), never a raw
 * `TypeError`.
 *
 * @example
 *   var cert = pki.schema.x509.parse(pem);
 *   var sctOid = pki.oid.byName("signedCertificateTimestampList");
 *   var ext = (cert.extensions || []).find(function (e) { return e.oid === sctOid; });
 *   if (ext) {
 *     var list = pki.ct.parseSctList(ext.value);
 *     list.scts[0].logIdHex;      // the log's key id
 *     list.scts[0].timestamp;     // exact BigInt ms since epoch
 *   }
 */
function parseSctList(extValue) {
  if (!Buffer.isBuffer(extValue) && !(extValue instanceof Uint8Array)) {
    throw new CtError("ct/bad-input", "parseSctList expects the SCT-list extension value as a Buffer or Uint8Array");
  }
  var blob = _peelInner(Buffer.isBuffer(extValue) ? extValue : Buffer.from(extValue));
  if (blob.length > C.LIMITS.SCT_MAX_BYTES) {
    throw new CtError("ct/too-large", "SCT list " + blob.length + " bytes exceeds the cap " + C.LIMITS.SCT_MAX_BYTES);
  }
  var outer = new TlsReader(blob, 0, blob.length);
  var listLen = outer.u16("ct/bad-list");
  if (listLen + 2 !== blob.length) {
    throw new CtError("ct/bad-list", "the SCT list declared length " + listLen + " does not match the " + (blob.length - 2) + " byte(s) present (RFC 6962 §3.3)");
  }
  if (listLen < 1) {
    throw new CtError("ct/empty-list", "an SCT list must contain at least one SCT (RFC 6962 §3.3)");
  }
  var scts = [], unknownScts = [];
  while (!outer.atEnd()) {
    if (outer.remaining() < 2) {
      throw new CtError("ct/list-trailing-bytes", "a dangling partial element after the last complete SCT (RFC 6962 §3.3)");
    }
    var sctLen = outer.u16("ct/list-trailing-bytes");
    if (sctLen < 1) {
      throw new CtError("ct/sct-empty", "a SerializedSCT must be non-empty (RFC 6962 §3.3)");
    }
    if (outer.remaining() < sctLen) {
      throw new CtError("ct/list-trailing-bytes", "a SerializedSCT length " + sctLen + " overruns the list (RFC 6962 §3.3)");
    }
    var one = _parseSct(outer.subReader(sctLen, "ct/list-trailing-bytes"), sctLen);
    if (one.unknown) unknownScts.push({ version: one.version, rawSct: one.rawSct });
    else scts.push(one);
    // The cap bounds the TOTAL element count (known + preserved-unknown) before it
    // can drive unbounded per-element work.
    if (scts.length + unknownScts.length > C.LIMITS.SCT_MAX_COUNT) {
      throw new CtError("ct/too-many-scts", "SCT count exceeds the cap " + C.LIMITS.SCT_MAX_COUNT);
    }
  }
  return { scts: scts, unknownScts: unknownScts };
}

function _u24Bytes(n) {
  if (n < 1 || n > 0xffffff) {
    throw new CtError("ct/bad-tbs-length", "a certificate / TBSCertificate length must be in 1..2^24-1, got " + n + " (RFC 6962 §3.1)");
  }
  return Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

/**
 * @primitive  pki.ct.reconstructSignedData
 * @signature  pki.ct.reconstructSignedData(entry, sct) -> Buffer
 * @since      0.1.20
 * @status     experimental
 * @spec       RFC 6962
 * @related    pki.ct.parseSctList
 *
 * Rebuild the exact `digitally-signed` preimage bytes an external verifier
 * hashes to check an SCT's signature (RFC 6962 §3.2), for a parsed `sct`.
 * `entry` selects the log-entry arm:
 *   - `{ entryType: 0, leafCert: <DER Buffer> }` — an SCT delivered over TLS /
 *     OCSP, signed over `x509_entry(0)` with the leaf certificate.
 *   - `{ entryType: 1, tbsCertificate: <DER Buffer>, issuerKeyHash: <32B> }` —
 *     an SCT EMBEDDED in a certificate, signed over `precert_entry(1)` with the
 *     issuer key hash + the precertificate TBS (the TBS with only the SCT
 *     extension removed). `issuerKeyHash` is SHA-256 of the issuer's SPKI DER.
 *
 * The preimage reuses the parsed SCT's raw `extensions` byte-for-byte and
 * re-emits the fixed-width scalars canonically. This never verifies anything —
 * a verifier hashes the returned bytes and checks the signature with the log's
 * public key (compose `webcrypto`). Throws `CtError` (`ct/bad-entry-type`,
 * `ct/bad-issuer-key-hash`, `ct/bad-tbs-length`) on a malformed entry.
 *
 * @example
 *   var sct = pki.ct.parseSctList(sctExtValue).scts[0];
 *   var preimage = pki.ct.reconstructSignedData({ entryType: 0, leafCert: der }, sct);
 *   // hash `preimage` + verify against the log's public key at the verify layer
 */
function reconstructSignedData(entry, sct) {
  entry = entry || {};
  var entryType = entry.entryType;
  if (entryType !== 0 && entryType !== 1) {
    throw new CtError("ct/bad-entry-type", "entryType must be x509_entry(0) or precert_entry(1), got " + entryType + " (RFC 6962 §3.1)");
  }
  // A fully decoded v1 SCT (from parseSctList().scts[]) — not an opaque
  // unknownScts entry, whose body layout is undefined and cannot be signed over.
  if (!sct || typeof sct.timestamp !== "bigint" || sct.version !== 0) {
    throw new CtError("ct/bad-input", "reconstructSignedData expects a decoded v1 SCT from parseSctList().scts[]");
  }
  var parts = [];
  parts.push(Buffer.from([sct.version & 0xff]));                          // Version — v1(0)
  parts.push(Buffer.from([0]));                                          // SignatureType — certificate_timestamp(0)
  var ts = Buffer.alloc(8); ts.writeBigUInt64BE(BigInt(sct.timestamp)); parts.push(ts);   // uint64 timestamp
  parts.push(Buffer.from([(entryType >> 8) & 0xff, entryType & 0xff]));  // LogEntryType (2 bytes BE)
  if (entryType === 0) {
    var cert = _toBuffer(entry.leafCert, "leafCert");
    parts.push(_u24Bytes(cert.length)); parts.push(cert);                // ASN.1Cert<1..2^24-1>
  } else {
    var ikh = _toBuffer(entry.issuerKeyHash, "issuerKeyHash");
    if (ikh.length !== 32) {
      throw new CtError("ct/bad-issuer-key-hash", "issuer_key_hash must be exactly 32 bytes (SHA-256 of the issuer SPKI), got " + ikh.length + " (RFC 6962 §3.2)");
    }
    var tbs = _toBuffer(entry.tbsCertificate, "tbsCertificate");
    parts.push(ikh);
    parts.push(_u24Bytes(tbs.length)); parts.push(tbs);                  // PreCert.tbs_certificate<1..2^24-1>
  }
  var ext = _toBuffer(sct.extensions, "sct.extensions");                 // reuse the parsed raw bytes, never re-encode
  parts.push(Buffer.from([(ext.length >> 8) & 0xff, ext.length & 0xff])); parts.push(ext);   // CtExtensions
  return Buffer.concat(parts);
}

module.exports = {
  parseSctList: parseSctList,
  reconstructSignedData: reconstructSignedData,
  HASH_ALGORITHMS: HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
};
