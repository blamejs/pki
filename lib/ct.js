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
 *   The SCT payload is encoded in the TLS presentation language (RFC 8446 sec. 3 /
 *   RFC 5246 sec. 4 conventions) -- positional, tag-less, fixed-width big-endian
 *   integers and length-prefixed opaque vectors -- NOT ASN.1/DER. So this module
 *   owns a bounded big-endian TLS-struct reader rather than composing the DER
 *   schema engine; the only ASN.1 surface is the sec. 3.3 double wrap (the
 *   extension value is a DER OCTET STRING whose content is another DER OCTET
 *   STRING whose content is the TLS list -- the certificate/OCSP layer peels the
 *   outer, this module peels the inner).
 *
 *   Structure is decoded, crypto is surfaced RAW: each SCT surfaces its `logId`
 *   (32 raw bytes -- SHA-256 of the log's SPKI, never recomputed), the exact
 *   `timestamp` as a BigInt, the raw `extensions`, the named-but-not-interpreted
 *   `hashAlg`/`sigAlg` code points, and the raw `signature`. The parser NEVER
 *   verifies a signature, recomputes a LogID, or trusts a log -- a verifier
 *   composes `webcrypto` over `reconstructSignedData(...)`, the exact
 *   `digitally-signed` preimage. DER-only carrier, fail-closed.
 *
 * @card
 *   Parse RFC 6962 Certificate Transparency SCT lists from a certificate or OCSP
 *   extension -- per-SCT logId / timestamp (BigInt) / algorithm / raw signature,
 *   the signed-preimage reconstruction surfaced for external verification,
 *   bounded TLS-struct decode, fail-closed.
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der.js");
var constants = require("./constants.js");
var frameworkError = require("./framework-error.js");
var guard = require("./guard-all.js");
var ByteReader = require("./byte-reader.js");
var ByteWriter = require("./byte-writer.js");
var oid = require("./oid.js");
var webcrypto = require("./webcrypto.js");
var validator = require("./validator-all.js");
var rfc3339 = require("./rfc3339.js");
var subtle = webcrypto.webcrypto.subtle;

var CtError = frameworkError.CtError;
var C = constants;

// (code, message) -> CtError, the factory the composed guards throw through so a
// malformed value keeps the ct/* typed verdict.
function _ctErr(c, m) { return new CtError(c, m); }

// RFC 5246 sec. 7.4.1.4.1 code points -- 1-byte, NOT OIDs. Surfaced named; an
// unknown code surfaces as its numeric byte with a null name (never rejected --
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

// ---- TlsReader -- the RFC 6962 TLS-vector cursor, the shared bounded big-endian
// ByteReader engine primitive bound to the ct/* fault domain. A lying inner length
// can overrun only the current sub-reader's `end`, never the parent buffer, so
// bounds-before-slice is structural (see lib/byte-reader.js).
function TlsReader(buf, start, end) { return new ByteReader(buf, start, end, CtError, "ct/truncated"); }

// Peel the RFC 6962 sec. 3.3 inner DER OCTET STRING (the certificate/OCSP layer
// already peeled the outer extnValue OCTET STRING). Rides the strict codec, so
// an indefinite length / constructed OCTET STRING / trailing bytes / single
// wrap all fail closed here; the asn1/* fault attaches as `.cause`.
function _peelInner(extValue) {
  var node;
  try { node = asn1.decode(extValue); }
  catch (e) { throw new CtError("ct/bad-der", "the SCT-list extension value is not valid DER (RFC 6962 sec. 3.3)", e); }
  try { return asn1.read.octetString(node); }
  catch (e) { throw new CtError("ct/bad-der", "the SCT-list extension value must be a DER OCTET STRING wrapping the TLS list (RFC 6962 sec. 3.3)", e); }
}

function _toBuffer(v, field) {
  return guard.bytes.view(v, CtError, "ct/bad-input", field);
}

// Parse one SerializedSCT body inside a sub-reader bounded to the element (so a
// lying extensions/signature length overruns the element, never the list). A
// version this parser does not define is preserved OPAQUE, not rejected: RFC 6962
// sec. 3.3 gives every SerializedSCT its own length prefix precisely so a client "can
// still parse old SCTs while skipping over new SCTs whose versions they don't
// understand" -- so an unknown version yields { unknown, version, rawSct } and the
// v1-specific field decode (and the 47-byte floor) is skipped.
function _parseSct(r, sctLen) {
  var bodyStart = r.pos;
  var version = r.u8();   // sctLen >= 1 is guaranteed by the SerializedSCT<1..> check
  if (version !== 0) {
    return { unknown: true, version: version, rawSct: r.buf.subarray(bodyStart, r.end) };
  }
  if (sctLen < SCT_MIN_BODY) {
    throw new CtError("ct/sct-too-short", "a v1 SCT body is at least " + SCT_MIN_BODY + " bytes, got " + sctLen + " (RFC 6962 sec. 3.2)");
  }
  var logId = r.fixed(LOGID_BYTES);
  var timestamp = r.u64();
  var extensions = r.vector(2, 0, null, "ct/ext-overrun");
  var hashAlg = r.u8();
  var sigAlg = r.u8();
  var signature = r.vector(2, 0, null, "ct/sig-overrun");
  if (!r.atEnd()) {
    throw new CtError("ct/sct-trailing-bytes", (r.end - r.pos) + " byte(s) left in a SerializedSCT after the signature (RFC 6962 sec. 3.3)");
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
 * @signature  pki.ct.parseSctList(extValue) -> { scts, unknownScts, all }
 * @since      0.1.20
 * @status     experimental
 * @spec       RFC 6962, RFC 5246, RFC 8446
 * @related    pki.ct.reconstructSignedData, pki.ct.encodeSctList, pki.schema.x509.parse
 *
 * Parse the value of an RFC 6962 SCT-list extension (the raw `extnValue`
 * content an `x509.parse` / OCSP extension already surfaces) into
 * `{ scts, unknownScts, all }`. Each entry of `scts` is a fully decoded v1 SCT:
 * `version` (0), `logId` (32-byte Buffer) + `logIdHex`, `timestamp` (BigInt,
 * exact) + `timestampMs` (Number or `null` above 2^53) + `timestampDate`,
 * `extensions` (raw Buffer), `hashAlg` / `sigAlg` (1-byte code points) + a named
 * `signatureAlgorithm`, the raw `signature` Buffer, and `rawSct` (the full
 * SerializedSCT body). A SerializedSCT whose version this parser does not define
 * is preserved OPAQUE in `unknownScts` as `{ version, rawSct }` rather than
 * failing the list -- RFC 6962 sec. 3.3 frames each SerializedSCT with its own length
 * so unknown versions are skippable (forward compatibility). `all` lists every
 * SerializedSCT (known and unknown) in the exact wire order, so
 * `encodeSctList(all)` reproduces the list byte-identically even when the two
 * kinds are interleaved.
 *
 * The extension value is a DER `OCTET STRING` wrapping the TLS-encoded list
 * (RFC 6962 sec. 3.3 double wrap); everything below that peel is TLS presentation
 * language, decoded with a bounded cursor. Structure is decoded, crypto is
 * surfaced RAW -- the signature is never verified and the LogID never recomputed.
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
  var blob = _peelInner(_toBuffer(extValue, "the SCT-list extension value"));
  if (blob.length > C.LIMITS.SCT_MAX_BYTES) {
    throw new CtError("ct/too-large", "SCT list " + blob.length + " bytes exceeds the cap " + C.LIMITS.SCT_MAX_BYTES);
  }
  var outer = new TlsReader(blob, 0, blob.length);
  var listLen = outer.u16("ct/bad-list");
  if (listLen + 2 !== blob.length) {
    throw new CtError("ct/bad-list", "the SCT list declared length " + listLen + " does not match the " + (blob.length - 2) + " byte(s) present (RFC 6962 sec. 3.3)");
  }
  if (listLen < 1) {
    throw new CtError("ct/empty-list", "an SCT list must contain at least one SCT (RFC 6962 sec. 3.3)");
  }
  var scts = [], unknownScts = [], all = [];
  // The shared item counter bounds the TOTAL element count (known + preserved-
  // unknown) before it can drive unbounded per-element work (RFC 6962 sec. 3.3).
  var sctCount = guard.limits.counter(C.LIMITS.SCT_MAX_COUNT, _ctErr, "ct/too-many-scts", "SCT");
  while (!outer.atEnd()) {
    if (outer.remaining() < 2) {
      throw new CtError("ct/list-trailing-bytes", "a dangling partial element after the last complete SCT (RFC 6962 sec. 3.3)");
    }
    var sctLen = outer.u16("ct/list-trailing-bytes");
    if (sctLen < 1) {
      throw new CtError("ct/sct-empty", "a SerializedSCT must be non-empty (RFC 6962 sec. 3.3)");
    }
    if (outer.remaining() < sctLen) {
      throw new CtError("ct/list-trailing-bytes", "a SerializedSCT length " + sctLen + " overruns the list (RFC 6962 sec. 3.3)");
    }
    sctCount.tick();
    var one = _parseSct(outer.subReader(sctLen, "ct/list-trailing-bytes"), sctLen);
    if (one.unknown) { var u = { version: one.version, rawSct: one.rawSct }; unknownScts.push(u); all.push(u); }
    else { scts.push(one); all.push(one); }
  }
  // `all` preserves the exact wire order across known + unknown entries, so encodeSctList(all)
  // reproduces the list byte-identically even when the two kinds were interleaved.
  return { scts: scts, unknownScts: unknownScts, all: all };
}

function _u24Bytes(n) {
  if (n < 1 || n > 0xffffff) {
    throw new CtError("ct/bad-tbs-length", "a certificate / TBSCertificate length must be in 1..2^24-1, got " + n + " (RFC 6962 sec. 3.1)");
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
 * hashes to check an SCT's signature (RFC 6962 sec. 3.2), for a parsed `sct`.
 * `entry` selects the log-entry arm:
 *   - `{ entryType: 0, leafCert: <DER Buffer> }` -- an SCT delivered over TLS /
 *     OCSP, signed over `x509_entry(0)` with the leaf certificate.
 *   - `{ entryType: 1, tbsCertificate: <DER Buffer>, issuerKeyHash: <32B> }` --
 *     an SCT EMBEDDED in a certificate, signed over `precert_entry(1)` with the
 *     issuer key hash + the precertificate TBS (the TBS with only the SCT
 *     extension removed). `issuerKeyHash` is SHA-256 of the issuer's SPKI DER.
 *
 * The preimage reuses the parsed SCT's raw `extensions` byte-for-byte and
 * re-emits the fixed-width scalars canonically. This never verifies anything --
 * a verifier hashes the returned bytes and checks the signature with the log's
 * public key (compose `webcrypto`). Throws `CtError` (`ct/bad-entry-type`,
 * `ct/bad-issuer-key-hash`, `ct/bad-tbs-length`) on a malformed entry, and
 * `ct/bad-input` / `ct/bad-extensions` on an `sct` whose timestamp or
 * extensions exceed their RFC 6962 3.2 wire ranges (uint64 / opaque<0..2^16-1>).
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
    throw new CtError("ct/bad-entry-type", "entryType must be x509_entry(0) or precert_entry(1), got " + entryType + " (RFC 6962 sec. 3.1)");
  }
  // A fully decoded v1 SCT (from parseSctList().scts[]) -- not an opaque
  // unknownScts entry, whose body layout is undefined and cannot be signed over.
  if (!sct || typeof sct.timestamp !== "bigint" || sct.version !== 0) {
    throw new CtError("ct/bad-input", "reconstructSignedData expects a decoded v1 SCT from parseSctList().scts[]");
  }
  // RFC 6962 3.2: the timestamp is a uint64. The BigInt-preserving range guard
  // refuses a value that cannot fill the fixed 8-byte field, typed, rather than
  // letting it escape as a raw RangeError from the Buffer write.
  var tsVal = guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp (RFC 6962 3.2)");
  var parts = [];
  parts.push(Buffer.from([sct.version & 0xff]));                          // Version -- v1(0)
  parts.push(Buffer.from([0]));                                          // SignatureType -- certificate_timestamp(0)
  var ts = Buffer.alloc(8); ts.writeBigUInt64BE(tsVal); parts.push(ts);   // uint64 timestamp
  parts.push(Buffer.from([(entryType >> 8) & 0xff, entryType & 0xff]));  // LogEntryType (2 bytes BE)
  if (entryType === 0) {
    var cert = _toBuffer(entry.leafCert, "leafCert");
    parts.push(_u24Bytes(cert.length)); parts.push(cert);                // ASN.1Cert<1..2^24-1>
  } else {
    var ikh = _toBuffer(entry.issuerKeyHash, "issuerKeyHash");
    if (ikh.length !== 32) {
      throw new CtError("ct/bad-issuer-key-hash", "issuer_key_hash must be exactly 32 bytes (SHA-256 of the issuer SPKI), got " + ikh.length + " (RFC 6962 sec. 3.2)");
    }
    var tbs = _toBuffer(entry.tbsCertificate, "tbsCertificate");
    parts.push(ikh);
    parts.push(_u24Bytes(tbs.length)); parts.push(tbs);                  // PreCert.tbs_certificate<1..2^24-1>
  }
  var ext = _toBuffer(sct.extensions, "sct.extensions");                 // reuse the parsed raw bytes, never re-encode
  // RFC 6962 3.2: CtExtensions is opaque<0..2^16-1>. A longer value is
  // unrepresentable -- its 2-byte prefix would silently truncate mod 65536,
  // an internally inconsistent preimage -- so it is refused, matching the
  // range check the u24 certificate lengths get.
  if (ext.length > 0xffff) {
    throw new CtError("ct/bad-extensions", "CtExtensions must be 0..65535 bytes, got " + ext.length + " (RFC 6962 3.2)");
  }
  parts.push(Buffer.from([(ext.length >> 8) & 0xff, ext.length & 0xff])); parts.push(ext);   // CtExtensions
  return Buffer.concat(parts);
}

// RFC 6962 sec. 2.1.4 constrains an SCT to SHA-256 with either ECDSA (NIST P-256) or RSA;
// the verifier enforces exactly that rather than accepting an off-profile hash / curve a
// conformant log never uses. The SCT hash name -> the WebCrypto digest.
var CT_HASH = { sha256: "SHA-256" };
// The one EC named curve an SCT log key may use (P-256), keyed by the curve OID its SPKI
// carries -> the WebCrypto curve name + the r/s coordinate width.
var CT_EC_CURVE = {};
CT_EC_CURVE[oid.byName("prime256v1")] = { curve: "P-256", coordLen: 32 };

// Read the SubjectPublicKeyInfo algorithm OID (+ the EC curve OID) off a log key SPKI so
// the verifier picks the WebCrypto import descriptor from the KEY, not just the SCT's
// self-declared signature type. Fail-closed: a non-SPKI shape throws a typed ct/bad-input.
function _spkiAlg(spki) {
  var node;
  try { node = asn1.decode(spki); } catch (e) { throw new CtError("ct/bad-input", "the CT log public key is not a well-formed SubjectPublicKeyInfo", e); }
  var algId = node.children && node.children[0];
  if (!algId || !algId.children || !algId.children.length) throw new CtError("ct/bad-input", "the CT log public key is not a SubjectPublicKeyInfo");
  var out;
  try { out = { algOid: asn1.read.oid(algId.children[0]) }; }
  catch (e1) { throw new CtError("ct/bad-input", "the CT log key SPKI algorithm identifier is not an OID", e1); }
  if (out.algOid === oid.byName("ecPublicKey")) {
    if (!algId.children[1]) throw new CtError("ct/bad-input", "the EC log key SPKI is missing its named-curve parameters");
    try { out.curveOid = asn1.read.oid(algId.children[1]); }
    catch (e2) { throw new CtError("ct/bad-input", "the EC log key SPKI curve parameters are not a named-curve OID", e2); }
  } else if (out.algOid === oid.byName("rsaEncryption")) {
    // RFC 6962 sec. 2.1.4 requires an RSA log key of at least 2048 bits -- size it from the
    // RSAPublicKey modulus in the subjectPublicKey BIT STRING.
    var mod, exp;
    try {
      var rsaSeq = asn1.decode(asn1.read.bitString(node.children[1]).bytes);
      mod = asn1.read.integer(rsaSeq.children[0]);
      exp = asn1.read.integer(rsaSeq.children[1]);
    } catch (e3) { throw new CtError("ct/bad-input", "the RSA log key SPKI is not a well-formed RSAPublicKey", e3); }
    // A non-positive modulus is malformed -- fail closed rather than size its absolute value.
    if (mod <= 0n) throw new CtError("ct/bad-input", "the RSA log key modulus is not a positive integer");
    // A small or even public exponent makes RSASSA-PKCS1-v1_5 verification forgeable (with
    // e=1 the signature is simply the encoded DigestInfo). Require an odd exponent >= 3 --
    // critical when the log key is taken from an untrusted log list rather than a pinned key.
    if (exp < 3n || (exp & 1n) === 0n) throw new CtError("ct/bad-input", "the RSA log key public exponent must be an odd integer >= 3");
    out.rsaBits = mod.toString(2).length;
  }
  return out;
}

/**
 * @primitive  pki.ct.verifySct
 * @signature  pki.ct.verifySct(entry, sct, logPublicKey) -> Promise<boolean>
 * @since      0.2.12
 * @status     experimental
 * @spec       RFC 6962
 * @defends    sct-signature-forgery (CWE-347)
 * @related    pki.ct.parseSctList, pki.ct.reconstructSignedData
 *
 * Verify a Signed Certificate Timestamp's signature against a Certificate Transparency
 * log's public key (RFC 6962 sec. 3.2). `entry` is the log entry the SCT covers
 * (`{ entryType: 0, leafCert }` or `{ entryType: 1, tbsCertificate, issuerKeyHash }`,
 * as for `reconstructSignedData`), `sct` a decoded v1 SCT from `parseSctList().scts[]`,
 * and `logPublicKey` the log's SubjectPublicKeyInfo (DER `Buffer`). Reconstructs the exact
 * signed data, imports the log key, and verifies the SCT signature -- an ECDSA signature is
 * routed through the strict DER ECDSA-Sig-Value conformance gate before conversion to the
 * raw r||s WebCrypto expects, an RSA signature verifies directly.
 *
 * Resolves `true` on a valid signature and `false` on a cryptographic mismatch (a false
 * verdict is a verdict). Throws a typed `CtError` on structural failure -- a malformed
 * entry/SCT, an unusable log key, or an unsupported hash/signature algorithm.
 *
 * @example
 *   var sct = pki.ct.parseSctList(sctExtValue).scts[0];
 *   // Resolve the CT log's DER SubjectPublicKeyInfo from a trusted log list, keyed by log id.
 *   var logKeysByLogId = {};                       // { sct.logIdHex: <SPKI Buffer>, ... }
 *   var logKey = logKeysByLogId[sct.logIdHex];
 *   var ok = await pki.ct.verifySct({ entryType: 0, leafCert: certDer }, sct, logKey);
 */
async function verifySct(entry, sct, logPublicKey) {
  // reconstructSignedData validates the entry + SCT and rebuilds the exact preimage.
  var message = reconstructSignedData(entry, sct);
  var spki = _toBuffer(logPublicKey, "the CT log public key (SPKI)");
  // RFC 6962 sec. 3.2: an SCT names its log by LogID = SHA-256(log SPKI). When the SCT
  // carries a logId, it MUST match the key it is verified against, so an SCT is never
  // accepted against a different log's key (a key-confusion the bare signature check misses).
  if (sct.logId != null) {
    var keyId = Buffer.from(await subtle.digest("SHA-256", spki));
    if (!keyId.equals(_toBuffer(sct.logId, "sct.logId"))) {
      throw new CtError("ct/log-id-mismatch", "the SCT logId does not match SHA-256 of the provided log key (RFC 6962 sec. 3.2)");
    }
  }
  var sigInfo = sct.signatureAlgorithm || {};
  var hashName = CT_HASH[sigInfo.hashName];
  if (!hashName) throw new CtError("ct/unsupported-algorithm", "unsupported SCT hash algorithm " + JSON.stringify(sigInfo.hashName) + " (RFC 6962 sec. 2.1.4 mandates sha256)");
  var alg = _spkiAlg(spki);
  var imp, ver, sig = _toBuffer(sct.signature, "sct.signature");
  if (sigInfo.signatureName === "ecdsa") {
    if (alg.algOid !== oid.byName("ecPublicKey")) throw new CtError("ct/bad-input", "the SCT declares an ECDSA signature but the log key is not an EC key");
    var ec = CT_EC_CURVE[alg.curveOid];
    if (!ec) throw new CtError("ct/unsupported-algorithm", "unsupported SCT log EC curve (RFC 6962 sec. 2.1.4 mandates NIST P-256)");
    imp = { name: "ECDSA", namedCurve: ec.curve };
    ver = { name: "ECDSA", hash: hashName };
    // The SCT signature is a DER ECDSA-Sig-Value; route it through the ORDER-AWARE conformance gate
    // (primitive, minimal, and r,s in [1, n-1] per FIPS 186-5 sec. 6.4.2 -- rejecting an out-of-range
    // r/s >= the curve order n, not only the r=s=0 shape) before converting to raw r||s.
    sig = validator.sig.ecdsaDerToP1363(sig, ec.curve, CtError, "ct/bad-signature");
  } else if (sigInfo.signatureName === "rsa") {
    if (alg.algOid !== oid.byName("rsaEncryption")) throw new CtError("ct/bad-input", "the SCT declares an RSA signature but the log key is not an RSA key");
    if (!(alg.rsaBits >= 2048)) throw new CtError("ct/unsupported-algorithm", "the SCT log RSA key is below the RFC 6962 sec. 2.1.4 minimum of 2048 bits");
    imp = { name: "RSASSA-PKCS1-v1_5", hash: hashName };
    ver = { name: "RSASSA-PKCS1-v1_5" };
  } else {
    throw new CtError("ct/unsupported-algorithm", "unsupported SCT signature algorithm " + JSON.stringify(sigInfo.signatureName) + " (RFC 6962 sec. 2.1.4 supports ecdsa/rsa)");
  }
  // A wrong signature resolves false from subtle.verify (a verdict); a structural failure
  // -- an unimportable key, an algorithm/key mismatch -- is re-thrown fail-closed.
  try {
    var key = await subtle.importKey("spki", spki, imp, false, ["verify"]);
    return await subtle.verify(ver, key, sig, message);
  } catch (e) {
    throw new CtError("ct/verify-error", "the SCT signature could not be evaluated", e);
  }
}

// The TLS-vector WRITER bound to the ct/* fault domain -- the encode twin of TlsReader,
// over the shared ByteWriter engine primitive (see lib/byte-writer.js).
function TlsWriter() { return new ByteWriter(CtError, "ct/bad-input"); }

// Encode one SerializedSCT body. A v1 SCT is rebuilt from its fields in the exact _parseSct
// order (so it round-trips byte-identically); an opaque non-v1 entry re-emits its rawSct
// verbatim (RFC 6962 sec. 3.3 forward-compat symmetry -- encode preserves what parse preserved).
function _encodeSctBody(sct) {
  if (!sct || typeof sct !== "object") throw new CtError("ct/bad-input", "each SCT must be an object");
  if (sct.version !== 0) {
    // The SerializedSCT version is a single byte (RFC 6962 sec. 3.2), so a declared version must be a
    // 0..255 integer -- reject a non-byte value rather than masking it (a masked 263 would spoof v7).
    if (typeof sct.version !== "number" || !Number.isInteger(sct.version) || sct.version < 0 || sct.version > 255) {
      throw new CtError("ct/bad-input", "an SCT version must be a byte in 0..255 (RFC 6962 sec. 3.2)");
    }
    // An opaque entry re-emits its rawSct verbatim, but the SerializedSCT's on-wire version is
    // rawSct[0] -- refuse a rawSct whose leading byte disagrees with the declared version, so encode
    // never emits a list whose framing our own parser would reject or re-classify (RFC 6962 sec. 3.3).
    var raw = _toBuffer(sct.rawSct, "sct.rawSct");
    if (raw.length < 1 || raw[0] !== sct.version) {
      throw new CtError("ct/bad-input", "an opaque SCT's rawSct[0] must equal its declared version (RFC 6962 sec. 3.3)");
    }
    return raw;
  }
  var w = new TlsWriter();
  w.u8(0, "ct/bad-input");                                                            // Version -- v1(0)
  var logId = _toBuffer(sct.logId, "sct.logId");
  if (logId.length !== LOGID_BYTES) throw new CtError("ct/bad-input", "an SCT logId must be exactly " + LOGID_BYTES + " bytes (RFC 6962 sec. 3.2)");
  w.bytes(logId);
  w.u64(guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp"), "ct/bad-input");   // uint64 timestamp
  w.vector(2, 0, 0xffff, _toBuffer(sct.extensions, "sct.extensions"), "ct/bad-input");  // CtExtensions<0..2^16-1>
  w.u8(sct.hashAlg, "ct/bad-input");                                                   // digitally-signed hash
  w.u8(sct.sigAlg, "ct/bad-input");                                                    // digitally-signed signature
  w.vector(2, 0, 0xffff, _toBuffer(sct.signature, "sct.signature"), "ct/bad-input");   // signature<0..2^16-1>
  return w.build();
}

/**
 * @primitive  pki.ct.encodeSctList
 * @signature  pki.ct.encodeSctList(scts) -> Buffer
 * @since      0.2.24
 * @status     experimental
 * @spec       RFC 6962, RFC 5246
 * @related    pki.ct.parseSctList, pki.ct.signSct
 *
 * Build the value of an RFC 6962 SCT-list extension from an array of SCTs -- the exact
 * inverse of `parseSctList`, such that `parseSctList(encodeSctList(list.all))` round-trips to
 * identical bytes. Each element is either a decoded v1 SCT (the shape `parseSctList().scts[]`
 * or `signSct` returns: `version` 0, 32-byte `logId`, `timestamp` BigInt, raw `extensions`,
 * `hashAlg` / `sigAlg` code points, raw `signature`) -- rebuilt from its fields in the RFC
 * 6962 sec. 3.2 field order -- or an opaque non-v1 entry (`{ version, rawSct }`) whose
 * `rawSct` is re-emitted verbatim (forward compatibility, sec. 3.3). Pass `parseSctList().all`
 * (not `.scts`) to preserve the exact wire order and every unknown-version entry.
 *
 * Returns the DER `OCTET STRING`-wrapped TLS `SignedCertificateTimestampList` (the same
 * `extnValue` content `parseSctList` consumes). The list must be non-empty and stays within
 * the parser's `SCT_MAX_COUNT` element cap and the RFC 6962 sec. 3.3 65535-byte list-body cap so
 * encode cannot emit what parse would reject. Throws a typed `CtError` (`ct/empty-list`,
 * `ct/bad-input`, `ct/too-large`, `ct/too-many-scts`) on malformed input.
 *
 * @example
 *   var list = pki.ct.parseSctList(sctExtValue);
 *   var reEncoded = pki.ct.encodeSctList(list.all);   // byte-identical to sctExtValue
 */
function encodeSctList(scts) {
  if (!Array.isArray(scts)) throw new CtError("ct/bad-input", "encodeSctList expects an array of SCTs");
  if (scts.length < 1) throw new CtError("ct/empty-list", "an SCT list must contain at least one SCT (RFC 6962 sec. 3.3)");
  var sctCount = guard.limits.counter(C.LIMITS.SCT_MAX_COUNT, _ctErr, "ct/too-many-scts", "SCT");
  var elements = [], total = 0;
  for (var i = 0; i < scts.length; i++) {
    sctCount.tick();
    var ew = new TlsWriter();
    ew.vector(2, 1, 0xffff, _encodeSctBody(scts[i]), "ct/bad-input");   // SerializedSCT<1..2^16-1>
    var el = ew.build();
    total += el.length;
    // Enforce the sct_list<1..2^16-1> body cap INCREMENTALLY, so an over-long list fails at the first
    // element that crosses the bound instead of accumulating the whole (potentially large) set first.
    if (total > 0xffff) throw new CtError("ct/too-large", "the SCT list body exceeds the 65535-byte maximum (RFC 6962 sec. 3.3)");
    elements.push(el);
  }
  var lw = new TlsWriter();
  lw.vector(2, 1, 0xffff, Buffer.concat(elements, total), "ct/too-large");   // sct_list<1..2^16-1>
  return asn1.build.octetString(lw.build());                                 // RFC 6962 sec. 3.3 DER OCTET STRING wrap
}

// A CT log private key -> its PKCS#8 DER (for WebCrypto sign) + the SPKI DER (for the LogID +
// the sec. 2.1.4 algorithm profile). Accepts a PKCS#8 DER Buffer, a PEM string, a node
// KeyObject, or a { key, format, type } input.
function _logKeyMaterial(logKey) {
  // Every key operation runs inside the guard: a duck-typed impostor (an object carrying an
  // asymmetricKeyType but not a real KeyObject) fails at export/createPublicKey and surfaces the
  // typed ct/bad-input, never a raw TypeError. The private-key check keeps its own CtError.
  try {
    var keyObj;
    if (logKey && typeof logKey === "object" && logKey.asymmetricKeyType) keyObj = logKey;
    else if (Buffer.isBuffer(logKey)) keyObj = nodeCrypto.createPrivateKey({ key: logKey, format: "der", type: "pkcs8" });
    else keyObj = nodeCrypto.createPrivateKey(logKey);
    if (keyObj.type !== "private") throw new CtError("ct/bad-input", "signSct requires the CT log PRIVATE key");
    return { pkcs8: keyObj.export({ type: "pkcs8", format: "der" }), spki: nodeCrypto.createPublicKey(keyObj).export({ type: "spki", format: "der" }) };
  } catch (e) {
    if (e instanceof CtError) throw e;
    throw new CtError("ct/bad-input", "the CT log private key could not be loaded", e);
  }
}

/**
 * @primitive  pki.ct.signSct
 * @signature  pki.ct.signSct(entry, logKey, opts?) -> Promise<sct>
 * @since      0.2.24
 * @status     experimental
 * @spec       RFC 6962
 * @related    pki.ct.verifySct, pki.ct.reconstructSignedData, pki.ct.encodeSctList
 *
 * Perform a Certificate Transparency log's signing step (RFC 6962 sec. 3.2): rebuild the exact
 * `digitally-signed` preimage over `entry` (via `reconstructSignedData`, the SAME builder the
 * verifier hashes), sign it with the log's private key, and return a fully-formed v1 SCT that
 * `verifySct` accepts against the log's public key. `entry` is the log entry the SCT covers
 * (`{ entryType: 0, leafCert }` or `{ entryType: 1, tbsCertificate, issuerKeyHash }`, as for
 * `reconstructSignedData`); `logKey` is the log's private key (PKCS#8 DER `Buffer`, PEM string,
 * or a node `KeyObject`).
 *
 * The log-key profile is RFC 6962 sec. 2.1.4: ECDSA NIST P-256 (`sigAlg` 3) or RSA >= 2048
 * (`sigAlg` 1), SHA-256 only -- an unsupported key fails closed `ct/unsupported-algorithm`. The
 * `logId` is derived as SHA-256 of the log SPKI (sec. 3.4); a supplied `opts.logId` must match.
 * The returned SCT is the parseSctList/verifySct shape and composes with `encodeSctList`.
 *
 * @opts timestamp   ms since the epoch (finite non-negative integer/BigInt). Default `Date.now()`.
 * @opts extensions  raw `CtExtensions` bytes (opaque<0..2^16-1>). Default empty.
 * @opts logId       assert the derived LogID equals this 32-byte value (fail closed on mismatch).
 * @example
 *   var sct = await pki.ct.signSct({ entryType: 0, leafCert: der }, signerKeyPkcs8);
 *   var ext = pki.ct.encodeSctList([sct]);
 */
async function signSct(entry, logKey, opts) {
  opts = opts || {};
  var mat = _logKeyMaterial(logKey);
  var alg = _spkiAlg(mat.spki);
  var hashAlg = 4, sigAlg, imp, sign, ecdsaDer = false, coordLen;
  if (alg.algOid === oid.byName("ecPublicKey")) {
    var ec = CT_EC_CURVE[alg.curveOid];
    if (!ec) throw new CtError("ct/unsupported-algorithm", "unsupported SCT log EC curve (RFC 6962 sec. 2.1.4 mandates NIST P-256)");
    sigAlg = 3; imp = { name: "ECDSA", namedCurve: ec.curve }; sign = { name: "ECDSA", hash: "SHA-256" }; ecdsaDer = true; coordLen = ec.coordLen;
  } else if (alg.algOid === oid.byName("rsaEncryption")) {
    if (!(alg.rsaBits >= 2048)) throw new CtError("ct/unsupported-algorithm", "the SCT log RSA key is below the RFC 6962 sec. 2.1.4 minimum of 2048 bits");
    sigAlg = 1; imp = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }; sign = { name: "RSASSA-PKCS1-v1_5" };
  } else {
    throw new CtError("ct/unsupported-algorithm", "unsupported SCT log key algorithm (RFC 6962 sec. 2.1.4 supports ecdsa P-256 / rsa)");
  }
  var timestamp;
  if (opts.timestamp == null) timestamp = BigInt(Date.now());
  else if (typeof opts.timestamp === "bigint") timestamp = opts.timestamp;
  else if (typeof opts.timestamp === "number" && Number.isSafeInteger(opts.timestamp) && opts.timestamp >= 0) timestamp = BigInt(opts.timestamp);
  else throw new CtError("ct/bad-input", "timestamp must be a finite non-negative integer or BigInt (RFC 6962 sec. 3.2)");
  var extensions = opts.extensions == null ? Buffer.alloc(0) : _toBuffer(opts.extensions, "opts.extensions");
  var logId = Buffer.from(await subtle.digest("SHA-256", mat.spki));
  if (opts.logId != null && !_toBuffer(opts.logId, "opts.logId").equals(logId)) {
    throw new CtError("ct/bad-input", "opts.logId does not match SHA-256 of the log key (RFC 6962 sec. 3.4)");
  }
  // Reuse the ONE preimage builder the verifier uses -- sign and verify cannot diverge.
  var preimage = reconstructSignedData(entry, { version: 0, timestamp: timestamp, extensions: extensions });
  var priv = await subtle.importKey("pkcs8", mat.pkcs8, imp, false, ["sign"]);
  var sigRaw = Buffer.from(await subtle.sign(sign, priv, preimage));
  var signature = ecdsaDer ? validator.sig.rawToEcdsaDer(sigRaw, coordLen) : sigRaw;
  return {
    version: 0,
    logId: logId, logIdHex: logId.toString("hex"),
    timestamp: timestamp,
    extensions: extensions,
    hashAlg: hashAlg, sigAlg: sigAlg,
    // The `|| null` fallbacks mirror parseSctList's shape; unreachable here since signSct only ever
    // emits the in-map sha256(4) + ecdsa(3)/rsa(1) code points (coverage residual).
    signatureAlgorithm: { hash: hashAlg, hashName: HASH_ALGORITHMS[hashAlg] || null, signature: sigAlg, signatureName: SIGNATURE_ALGORITHMS[sigAlg] || null },
    signature: signature,
  };
}

// ---- CT log-list trust surface (RFC 6962 sec. 3.2 + the CT log-list v3 JSON schema) --------------

// The recognized CT log states (the schema `state` oneOf) mapped to a trust decision (the deployed
// Chrome/Apple CT policy): usable/qualified/readonly are trusted; retired is CONDITIONALLY trusted
// (only for an SCT timestamped before the retirement instant, checked at verify); pending/rejected
// are not trusted.
var LOG_STATE_TRUST = { pending: "no", qualified: "yes", usable: "yes", readonly: "yes", retired: "conditional", rejected: "no" };

// Decode a log's `state` oneOf: EXACTLY ONE recognized member, whose timestamp is an RFC 3339 instant.
// Zero, multiple, or an unrecognized member -> ct/bad-state (fail-closed, never a silent default-trust).
function _parseLogState(state) {
  if (state == null || typeof state !== "object") throw _ctErr("ct/bad-state", "a CT log entry is missing its state");
  var keys = Object.keys(state);
  if (keys.length !== 1 || !Object.prototype.hasOwnProperty.call(LOG_STATE_TRUST, keys[0])) {
    throw _ctErr("ct/bad-state", "a CT log state must carry exactly one recognized member (pending/qualified/usable/readonly/retired/rejected)");
  }
  var name = keys[0], member = state[name];
  if (member == null || typeof member !== "object") throw _ctErr("ct/bad-state", "the CT log state " + name + " is malformed");
  var since = rfc3339.parse(member.timestamp, _ctErr, "ct/bad-date", "the CT log state timestamp");
  var trust = LOG_STATE_TRUST[name];
  return { name: name, since: since, trusted: trust === "yes", conditional: trust === "conditional" };
}

// Decode a log's `temporal_interval` (both bounds RFC 3339, start strictly before end) or null.
function _parseTemporalInterval(ti) {
  if (ti == null) return null;
  if (typeof ti !== "object") throw _ctErr("ct/bad-log-list", "a CT log temporal_interval must be an object");
  var start = rfc3339.parse(ti.start_inclusive, _ctErr, "ct/bad-date", "temporal_interval.start_inclusive");
  var end = rfc3339.parse(ti.end_exclusive, _ctErr, "ct/bad-date", "temporal_interval.end_exclusive");
  // allow:nan-date-comparison-unguarded -- start/end are rfc3339.parse results, guaranteed non-NaN (rfc3339.isValid rejects a NaN date).
  if (start.getTime() >= end.getTime()) throw _ctErr("ct/bad-log-list", "a CT log temporal_interval start_inclusive must be strictly before end_exclusive");
  return { startInclusive: start, endExclusive: end };
}

// One log-list entry -> a constraint-carrying trusted-log record. The load-bearing M-BIND step: the
// log-id is RECOMPUTED as SHA-256(SPKI) and MUST equal the stated log_id (RFC 6962 sec. 3.2), so the
// trusted set is keyed by the authoritative binding, never the document's self-assertion -- a swapped
// key or a flipped id is refused. The key is also validated as a well-formed, on-profile SPKI at ingest.
function _parseLog(log, operatorName) {
  if (log == null || typeof log !== "object") throw _ctErr("ct/bad-log-list", "a CT log entry is not an object");
  if (typeof log.key !== "string" || typeof log.log_id !== "string") throw _ctErr("ct/bad-log-list", "a CT log entry is missing its key or log_id");
  var spki = guard.encoding.base64(log.key, C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, "ct/bad-log-list", "the CT log key");
  var statedId = guard.encoding.base64(log.log_id, 64, _ctErr, "ct/bad-log-list", "the CT log id");
  if (statedId.length !== 32) throw _ctErr("ct/bad-log-list", "a CT log_id must be 32 bytes (SHA-256), got " + statedId.length);
  _spkiAlg(spki);   // fail-fast: a non-SPKI / malformed key (or a forgeable RSA e < 3) throws ct/bad-input; the full EC-curve / RSA-size profile is enforced by verifySct at verify time
  var logId = nodeCrypto.createHash("sha256").update(spki).digest();
  if (!logId.equals(statedId)) throw _ctErr("ct/log-id-mismatch", "the CT log_id does not match SHA-256 of the log key (RFC 6962 sec. 3.2)");
  return {
    logId: logId, logIdHex: logId.toString("hex"), key: spki,
    description: typeof log.description === "string" ? log.description : null,
    url: typeof log.url === "string" ? log.url : (typeof log.submission_url === "string" ? log.submission_url : null),
    mmd: typeof log.mmd === "number" ? log.mmd : null,
    operator: operatorName, state: _parseLogState(log.state), temporalInterval: _parseTemporalInterval(log.temporal_interval),
    trusted: false,   // set below from the state (usable/qualified/readonly), so a consumer reads a plain bool
  };
}

// Two entries for one recomputed log-id must be byte-identical (collapse) or the list is inconsistent.
function _sameTemporal(a, b) {
  if (a == null && b == null) return true;
  // Coverage residual: the || guard is exercised across null/interval, interval/null, and both-interval
  // inputs; the remaining c8 sub-arm is a short-circuit path (when `a == null` is true, `b == null` is
  // never evaluated) with no additional reachable input.
  if (a == null || b == null) return false;
  return a.startInclusive.getTime() === b.startInclusive.getTime() && a.endExclusive.getTime() === b.endExclusive.getTime();
}
function _logsAgree(a, b) {
  return a.state.name === b.state.name && a.state.since.getTime() === b.state.since.getTime() && _sameTemporal(a.temporalInterval, b.temporalInterval);
}

/**
 * @primitive  pki.ct.parseLogList
 * @signature  pki.ct.parseLogList(json, opts?) -> { logs, byLogId }
 * @since      0.2.28
 * @status     experimental
 * @spec       RFC 6962
 * @related    pki.ct.verifySctWithLogList, pki.ct.verifySct
 *
 * Ingest a Certificate Transparency log-list JSON document (the `log_list.json` browsers consume) into a
 * set of constraint-carrying trusted logs, keyed by log-id. `json` is a Buffer or string -- the caller
 * supplies the already-fetched, already-authenticated bytes (offline, no network fetch). Parsing routes
 * through the bounded, duplicate-member-rejecting JSON reader; for each log it base64-decodes the `key`
 * to its DER SubjectPublicKeyInfo, validates it as a well-formed on-profile key, **recomputes**
 * `SHA-256(SPKI)` and fail-closed **requires** it equal the stated `log_id` (RFC 6962 sec. 3.2 -- a log
 * whose stated id disagrees with its key is refused as `ct/log-id-mismatch`), and decodes the `state`
 * (exactly one of pending/qualified/usable/readonly/retired/rejected) and `temporal_interval`. Returns
 * `{ logs, byLogId }` where each log is `{ logId, logIdHex, key, description, url, mmd, operator, state:
 * { name, since, trusted, conditional }, temporalInterval, trusted }` and `byLogId` is a null-proto
 * `{ logIdHex: log }` map. Every malformed / oversized / mis-bound input is a typed `CtError`.
 *
 * @example
 *   var logList = pki.ct.parseLogList(logListJsonBytes);
 *   logList.logs[0].trusted;   // was the first log trusted (usable/qualified/readonly)?
 */
function parseLogList(json, opts) {
  void opts;
  var doc = guard.json.parse(json, _ctErr, {
    maxBytes: C.LIMITS.CT_LOG_LIST_MAX_BYTES, maxDepth: C.LIMITS.JSON_MAX_DEPTH,
    badJson: "ct/bad-json", tooDeep: "ct/too-deep", duplicateMember: "ct/duplicate-member",
    tooLarge: "ct/too-large", badInput: "ct/bad-input", label: "the CT log list",
  });
  if (doc == null || typeof doc !== "object" || !Array.isArray(doc.operators)) throw _ctErr("ct/bad-log-list", "the CT log list must be a JSON object with an operators array");
  var logs = [], byLogId = Object.create(null);
  for (var i = 0; i < doc.operators.length; i++) {
    var op = doc.operators[i];
    if (op == null || typeof op !== "object" || typeof op.name !== "string") throw _ctErr("ct/bad-log-list", "a CT log-list operator is missing its name");
    var arrays = [op.logs, op.tiled_logs];
    for (var a = 0; a < arrays.length; a++) {
      var arr = arrays[a];
      if (arr == null) continue;
      if (!Array.isArray(arr)) throw _ctErr("ct/bad-log-list", "a CT log-list operator's logs / tiled_logs must be an array");
      for (var j = 0; j < arr.length; j++) {
        var rec = _parseLog(arr[j], op.name);
        rec.trusted = rec.state.trusted;   // usable/qualified/readonly; retired stays false (conditional at verify)
        var prev = byLogId[rec.logIdHex];
        if (prev) {
          if (!_logsAgree(prev, rec)) throw _ctErr("ct/duplicate-log", "two CT log entries share log-id " + rec.logIdHex + " but disagree");
          continue;   // a byte-identical duplicate collapses to the one already recorded
        }
        byLogId[rec.logIdHex] = rec;
        logs.push(rec);
      }
    }
  }
  return { logs: logs, byLogId: byLogId };
}

// The covered certificate's notAfter for the temporal gate: an explicit opts.certNotAfter, else derived
// from a leafCert (entryType 0) via the shipped x509 parser, else null (a precert TBS can't be parsed).
function _resolveNotAfter(entry, opts) {
  if (opts.certNotAfter instanceof Date) return opts.certNotAfter;
  if (entry && entry.entryType === 0 && entry.leafCert != null) {
    // Inline require (circular-load): ct.js is loaded before schema-x509 finishes initializing in the
    // index chain (schema-x509 -> schema-pkix is mid-init when ct.js is first required), so a top-level
    // require would see a half-built pkix. Deferred to first use, when every module is initialized.
    var x509 = require("./schema-x509.js");   // allow:inline-require -- circular load with schema-x509 -> schema-pkix (see note above)
    try {
      return x509.parse(_toBuffer(entry.leafCert, "entry.leafCert")).validity.notAfter;
    } catch (_e) {
      return null;   // a malformed leafCert -> no resolvable notAfter -> fail-closed ct/temporal-interval at the caller
    }
  }
  return null;
}

/**
 * @primitive  pki.ct.verifySctWithLogList
 * @signature  pki.ct.verifySctWithLogList(entry, sct, logList, opts?) -> Promise<boolean>
 * @since      0.2.28
 * @status     experimental
 * @spec       RFC 6962
 * @related    pki.ct.parseLogList, pki.ct.verifySct
 *
 * Resolve the trusted CT log for an SCT and verify it in one step. `logList` is a `parseLogList` result;
 * the log is resolved by `sct.logIdHex` (an unknown log is `ct/log-not-found`). The log's **state** gates
 * trust (usable/qualified/readonly proceed; a retired log proceeds only for an SCT timestamped before its
 * retirement instant; pending/rejected are `ct/log-untrusted`); its **temporal_interval** gates the
 * covered certificate (the cert's `notAfter` -- from `entry.leafCert` when `entryType` is 0, or
 * `opts.certNotAfter` -- must fall in `[start_inclusive, end_exclusive)`, and a windowed log with no
 * resolvable notAfter is `ct/temporal-interval`, never silently skipped). Then the crypto is delegated to
 * the shipped `verifySct(entry, sct, log.key)` (which independently re-checks `logId == SHA-256(key)`).
 * Resolves `true` for a valid signature from a trusted, in-window log; `false` on a cryptographic
 * mismatch (a verdict); throws a typed `CtError` on any structural / trust failure.
 *
 * @opts certNotAfter A `Date` -- the covered certificate's notAfter for the temporal-interval gate (required for a precert entry).
 * @example
 *   var ok = await pki.ct.verifySctWithLogList(sctEntry, embeddedSct, logList);
 */
async function verifySctWithLogList(entry, sct, logList, opts) {
  opts = opts || {};
  if (logList == null || typeof logList !== "object" || logList.byLogId == null) throw _ctErr("ct/bad-input", "logList must be a pki.ct.parseLogList result");
  if (sct == null || typeof sct !== "object" || typeof sct.logIdHex !== "string") throw _ctErr("ct/bad-input", "the SCT is missing its logIdHex");
  var log = logList.byLogId[sct.logIdHex];
  if (log == null) throw _ctErr("ct/log-not-found", "no trusted CT log matches the SCT's logId " + sct.logIdHex);
  // State gate (fail-closed): trusted proceed; retired only before its retirement; else untrusted.
  if (!log.state.trusted) {
    if (!log.state.conditional) throw _ctErr("ct/log-untrusted", "the CT log state '" + log.state.name + "' is not trusted");
    var ts = guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp");
    if (ts >= BigInt(log.state.since.getTime())) throw _ctErr("ct/log-untrusted", "the CT log is retired and the SCT is not timestamped before its retirement (" + log.state.since.toISOString() + ")");
  }
  // Temporal gate (fail-closed): the covered cert's notAfter must be in [start_inclusive, end_exclusive).
  if (log.temporalInterval) {
    var notAfter = _resolveNotAfter(entry, opts);
    // An Invalid Date (getTime() === NaN) is still `instanceof Date`, and NaN < x / NaN >= x are both
    // false, so it would silently BYPASS the window containment -- reject it fail-closed, exactly like
    // the codec's readTime rejects a NaN instant (a caller may pass a lenient `new Date(badString)`).
    if (!(notAfter instanceof Date) || isNaN(notAfter.getTime())) throw _ctErr("ct/temporal-interval", "the CT log has a temporal_interval but the covered certificate's notAfter is not available or not a valid date (pass a valid opts.certNotAfter)");
    var t = notAfter.getTime();
    if (t < log.temporalInterval.startInclusive.getTime() || t >= log.temporalInterval.endExclusive.getTime()) {
      throw _ctErr("ct/temporal-interval", "the covered certificate's notAfter is outside the CT log's temporal_interval");
    }
  }
  return verifySct(entry, sct, log.key);   // the shipped crypto verdict (re-checks the logId binding)
}

/**
 * @primitive  pki.ct.verifyLogListSignature
 * @signature  pki.ct.verifyLogListSignature(json, signature, publicKey) -> Promise<boolean>
 * @since      0.2.29
 * @status     experimental
 * @spec       RFC 6962, RFC 8017
 * @related    pki.ct.parseLogList, pki.ct.verifySct
 *
 * Verify the detached signature published alongside the Certificate Transparency log list (the
 * `log_list.sig` over `log_list.json`). `json` is the RAW log-list bytes (a Buffer, or the fetched text
 * as a string -- verified byte-for-byte, never re-serialized), `signature` is the detached signature, and
 * `publicKey` is the caller-PINNED signer SubjectPublicKeyInfo (DER; there is no baked-in key). The scheme
 * is RSASSA-PKCS1-v1.5 with SHA-256 over an RSA key (the deployed scheme; an EC P-256 / ECDSA-SHA-256 arm
 * is accepted for future-proofing). Resolves `true` for a valid signature, `false` on a cryptographic
 * mismatch (a verdict). Fail-closed forgery defenses throw before any verify: an RSA public exponent below
 * 3 or even (`ct/bad-input`), a sub-2048-bit RSA key or an unsupported key type / curve
 * (`ct/unsupported-algorithm`), a non-conformant ECDSA DER Sig-Value (`ct/bad-signature`); a structural
 * evaluation failure is `ct/verify-error`. Offline: the caller fetches and pins; the toolkit only verifies.
 *
 * @example
 *   var ok = await pki.ct.verifyLogListSignature(logListJsonBytes, logListSig, googleSignerSpki);
 */
async function verifyLogListSignature(json, signature, publicKey) {
  var message = typeof json === "string" ? Buffer.from(json) : _toBuffer(json, "the CT log list JSON");
  // Bound the signed message before the digest/verify (the same cap parseLogList enforces) so a hostile
  // caller cannot force unbounded hashing work on an oversized input (CWE-400).
  if (message.length > C.LIMITS.CT_LOG_LIST_MAX_BYTES) throw new CtError("ct/too-large", "the CT log list exceeds the " + C.LIMITS.CT_LOG_LIST_MAX_BYTES + "-byte cap");
  var sig = _toBuffer(signature, "the CT log list signature");
  var spki = _toBuffer(publicKey, "the CT log list signer public key (SPKI)");
  var alg = _spkiAlg(spki);   // fail-closed: a non-SPKI key or a forgeable RSA e < 3 throws ct/bad-input
  var imp, ver;
  if (alg.algOid === oid.byName("rsaEncryption")) {
    if (!(alg.rsaBits >= 2048)) throw new CtError("ct/unsupported-algorithm", "the CT log-list signer RSA key is below the 2048-bit minimum");
    imp = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    ver = { name: "RSASSA-PKCS1-v1_5" };
  } else if (alg.algOid === oid.byName("ecPublicKey")) {
    var ec = CT_EC_CURVE[alg.curveOid];
    if (!ec) throw new CtError("ct/unsupported-algorithm", "unsupported CT log-list signer EC curve (only NIST P-256)");
    imp = { name: "ECDSA", namedCurve: ec.curve };
    ver = { name: "ECDSA", hash: "SHA-256" };
    // A DER ECDSA-Sig-Value: route through the ORDER-AWARE conformance gate (primitive, minimal, and
    // r,s in [1, n-1] per FIPS 186-5 sec. 6.4.2 -- defeating the CVE-2022-21449 r=s=0 forgery AND an
    // out-of-range r/s >= the curve order n) before the raw r||s conversion.
    sig = validator.sig.ecdsaDerToP1363(sig, ec.curve, CtError, "ct/bad-signature");
  } else {
    throw new CtError("ct/unsupported-algorithm", "unsupported CT log-list signer key algorithm (only rsaEncryption / ecPublicKey P-256)");
  }
  // A wrong signature resolves false from subtle.verify (a verdict); a structural failure -- an
  // unimportable key -- is re-thrown fail-closed.
  try {
    var key = await subtle.importKey("spki", spki, imp, false, ["verify"]);
    return await subtle.verify(ver, key, sig, message);
  } catch (e) {
    throw new CtError("ct/verify-error", "the CT log-list signature could not be evaluated", e);
  }
}

module.exports = {
  parseSctList: parseSctList,
  reconstructSignedData: reconstructSignedData,
  verifySct: verifySct,
  encodeSctList: encodeSctList,
  signSct: signSct,
  parseLogList: parseLogList,
  verifySctWithLogList: verifySctWithLogList,
  verifyLogListSignature: verifyLogListSignature,
  HASH_ALGORITHMS: HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
};
