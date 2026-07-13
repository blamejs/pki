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

var asn1 = require("./asn1-der.js");
var constants = require("./constants.js");
var frameworkError = require("./framework-error.js");
var guard = require("./guard-all.js");
var ByteReader = require("./byte-reader.js");
var oid = require("./oid.js");
var webcrypto = require("./webcrypto.js");
var validator = require("./validator-all.js");
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
 * failing the list -- RFC 6962 sec. 3.3 frames each SerializedSCT with its own length
 * so unknown versions are skippable (forward compatibility).
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
  var scts = [], unknownScts = [];
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
    if (one.unknown) unknownScts.push({ version: one.version, rawSct: one.rawSct });
    else scts.push(one);
  }
  return { scts: scts, unknownScts: unknownScts };
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
    // The SCT signature is a DER ECDSA-Sig-Value; route it through the strict conformance
    // gate (primitive, minimal, positive, bounded r/s) before converting to raw r||s.
    sig = validator.sig.ecdsaSigToRaw(sig, ec.coordLen, CtError, "ct/bad-signature");
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

module.exports = {
  parseSctList: parseSctList,
  reconstructSignedData: reconstructSignedData,
  verifySct: verifySct,
  HASH_ALGORITHMS: HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
};
