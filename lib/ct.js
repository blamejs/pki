// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.ct
 * @nav        Transparency
 * @title      CT
 * @fullname   Certificate Transparency (CT) logs and SCTs
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
 *   RFC 5246 sec. 4 conventions): positional, tag-less, fixed-width big-endian
 *   integers and length-prefixed opaque vectors, never ASN.1/DER. So this module
 *   owns a bounded big-endian TLS-struct reader instead of composing the DER
 *   schema engine; the only ASN.1 surface is the sec. 3.3 double wrap (the
 *   extension value is a DER OCTET STRING whose content is another DER OCTET
 *   STRING whose content is the TLS list; the certificate/OCSP layer peels the
 *   outer, this module peels the inner).
 *
 *   Structure is decoded, crypto is surfaced raw: each SCT surfaces its `logId`
 *   (32 raw bytes, the SHA-256 of the log's SPKI, never recomputed), the exact
 *   `timestamp` as a BigInt, the raw `extensions`, the named-but-not-interpreted
 *   `hashAlg`/`sigAlg` code points, and the raw `signature`. The parser never
 *   verifies a signature, recomputes a LogID, or trusts a log. A verifier
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
var intrinsic = require("./guard-intrinsic.js");
var _hasOwn = intrinsic.hasOwn;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _JSON_SUFFIX = ".json";
function _endsWithJson(s) { return s.length >= _JSON_SUFFIX.length && _strSlice(s, s.length - _JSON_SUFFIX.length) === _JSON_SUFFIX; }
var ByteReader = require("./byte-reader.js");
var ByteWriter = require("./byte-writer.js");
var oid = require("./oid.js");
var webcrypto = require("./webcrypto.js");
var validator = require("./validator-all.js");
var rfc3339 = require("./rfc3339.js");
var httpTransport = require("./http-transport.js");
var subtle = webcrypto.webcrypto.subtle;

var CtError = frameworkError.CtError;
var PkiError = frameworkError.PkiError;
var C = constants;

function _ctErr(c, m, cause) { return new CtError(c, m, cause); }

var HASH_ALGORITHMS = {
  0: "none", 1: "md5", 2: "sha1", 3: "sha224", 4: "sha256", 5: "sha384", 6: "sha512",
};
var SIGNATURE_ALGORITHMS = { 0: "anonymous", 1: "rsa", 2: "dsa", 3: "ecdsa" };

var SCT_MIN_BODY = 47;
var LOGID_BYTES = 32;
var MAX_SAFE = 9007199254740991n;

function TlsReader(buf, start, end) { return new ByteReader(buf, start, end, CtError, "ct/truncated"); }

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

function _parseSct(r, sctLen) {
  var bodyStart = r.pos;
  var version = r.u8();
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
 * @status     stable
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
 * is preserved opaque in `unknownScts` as `{ version, rawSct }` and does not fail
 * the list: RFC 6962 sec. 3.3 frames each SerializedSCT with its own length
 * so unknown versions are skippable (forward compatibility). `all` lists every
 * SerializedSCT (known and unknown) in the exact wire order, so
 * `encodeSctList(all)` reproduces the list byte-identically even when the two
 * kinds are interleaved.
 *
 * The extension value is a DER `OCTET STRING` wrapping the TLS-encoded list
 * (RFC 6962 sec. 3.3 double wrap); everything below that peel is TLS presentation
 * language, decoded with a bounded cursor. Structure is decoded, crypto is
 * surfaced raw: the signature is never verified and the LogID never recomputed.
 *
 * Throws `CtError` with a stable `ct/*` code on any malformed input (a bad inner
 * DER wrap is `ct/bad-der` with the `asn1/*` fault as `.cause`), never a raw
 * `TypeError`.
 *
 * @example
 *   // a certificate with an embedded SCT list, as a log would return it
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var kp = await pki.key.generate("Ed25519");
 *   var leaf = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
 *   var sct = await pki.ct.signSct({ entryType: 0, leafCert: leaf }, await pki.key.export(log.privateKey));
 *   var sctExt = pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("signedCertificateTimestampList")),
 *     pki.asn1.build.octetString(pki.ct.encodeSctList([sct]))]);
 *   var pem = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: [sctExt] }, { key: await pki.key.export(kp.privateKey) }, { pem: true });
 *
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
  guard.limits.byteCap(blob, C.LIMITS.SCT_MAX_BYTES, _ctErr, "ct/too-large", "SCT list");
  var outer = new TlsReader(blob, 0, blob.length);
  var listLen = outer.u16("ct/bad-list");
  if (listLen + 2 !== blob.length) {
    throw new CtError("ct/bad-list", "the SCT list declared length " + listLen + " does not match the " + (blob.length - 2) + " byte(s) present (RFC 6962 sec. 3.3)");
  }
  if (listLen < 1) {
    throw new CtError("ct/empty-list", "an SCT list must contain at least one SCT (RFC 6962 sec. 3.3)");
  }
  var scts = [], unknownScts = [], all = [];
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
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.parseSctList
 *
 * Rebuild the exact `digitally-signed` preimage bytes an external verifier
 * hashes to check an SCT's signature (RFC 6962 sec. 3.2), for a parsed `sct`.
 * `entry` selects the log-entry arm:
 *   - `{ entryType: 0, leafCert: <DER Buffer> }`, an SCT delivered over TLS /
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
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var kp = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
 *   var sctExtValue = pki.ct.encodeSctList([
 *     await pki.ct.signSct({ entryType: 0, leafCert: der }, await pki.key.export(log.privateKey))]);
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
  if (!sct || typeof sct.timestamp !== "bigint" || sct.version !== 0) {
    throw new CtError("ct/bad-input", "reconstructSignedData expects a decoded v1 SCT from parseSctList().scts[]");
  }
  var tsVal = guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp (RFC 6962 3.2)");
  var parts = [];
  parts.push(Buffer.from([sct.version & 0xff]));
  parts.push(Buffer.from([0]));
  var ts = Buffer.alloc(8); ts.writeBigUInt64BE(tsVal); parts.push(ts);
  parts.push(Buffer.from([(entryType >> 8) & 0xff, entryType & 0xff]));
  if (entryType === 0) {
    var cert = _toBuffer(entry.leafCert, "leafCert");
    parts.push(_u24Bytes(cert.length)); parts.push(cert);
  } else {
    var ikh = _toBuffer(entry.issuerKeyHash, "issuerKeyHash");
    if (ikh.length !== 32) {
      throw new CtError("ct/bad-issuer-key-hash", "issuer_key_hash must be exactly 32 bytes (SHA-256 of the issuer SPKI), got " + ikh.length + " (RFC 6962 sec. 3.2)");
    }
    var tbs = _toBuffer(entry.tbsCertificate, "tbsCertificate");
    parts.push(ikh);
    parts.push(_u24Bytes(tbs.length)); parts.push(tbs);
  }
  var ext = _toBuffer(sct.extensions, "sct.extensions");
  if (ext.length > 0xffff) {
    throw new CtError("ct/bad-extensions", "CtExtensions must be 0..65535 bytes, got " + ext.length + " (RFC 6962 3.2)");
  }
  parts.push(Buffer.from([(ext.length >> 8) & 0xff, ext.length & 0xff])); parts.push(ext);
  return Buffer.concat(parts);
}

var CT_HASH = { sha256: "SHA-256" };
var CT_EC_CURVE = {};
CT_EC_CURVE[oid.byName("prime256v1")] = { curve: "P-256", coordLen: 32 };

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
    var mod, exp;
    try {
      var rsaSeq = asn1.decode(asn1.read.bitString(node.children[1]).bytes);
      mod = asn1.read.integer(rsaSeq.children[0]);
      exp = asn1.read.integer(rsaSeq.children[1]);
    } catch (e3) { throw new CtError("ct/bad-input", "the RSA log key SPKI is not a well-formed RSAPublicKey", e3); }
    if (mod <= 0n) throw new CtError("ct/bad-input", "the RSA log key modulus is not a positive integer");
    if (exp < 3n || (exp & 1n) === 0n) throw new CtError("ct/bad-input", "the RSA log key public exponent must be an odd integer >= 3");
    out.rsaBits = mod.toString(2).length;
  }
  return out;
}

/**
 * @primitive  pki.ct.verifySct
 * @signature  pki.ct.verifySct(entry, sct, logPublicKey) -> Promise<boolean>
 * @since      0.2.12
 * @status     stable
 * @spec       RFC 6962
 * @defends    sct-signature-forgery (CWE-347)
 * @related    pki.ct.parseSctList, pki.ct.reconstructSignedData
 *
 * Verify a Signed Certificate Timestamp's signature against a Certificate Transparency
 * log's public key (RFC 6962 sec. 3.2). `entry` is the log entry the SCT covers
 * (`{ entryType: 0, leafCert }` or `{ entryType: 1, tbsCertificate, issuerKeyHash }`,
 * as for `reconstructSignedData`), `sct` a decoded v1 SCT from `parseSctList().scts[]`,
 * and `logPublicKey` the log's SubjectPublicKeyInfo (DER `Buffer`). Reconstructs the exact
 * signed data, imports the log key, and verifies the SCT signature. An ECDSA signature is
 * routed through the strict DER ECDSA-Sig-Value conformance gate before conversion to the
 * raw r||s WebCrypto expects, an RSA signature verifies directly.
 *
 * Resolves `true` on a valid signature and `false` on a cryptographic mismatch (a false
 * verdict is a verdict). Throws a typed `CtError` on structural failure: a malformed
 * entry/SCT, an unusable log key, or an unsupported hash/signature algorithm.
 *
 * @example
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var kp = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
 *   var sctExtValue = pki.ct.encodeSctList([
 *     await pki.ct.signSct({ entryType: 0, leafCert: certDer }, await pki.key.export(log.privateKey))]);
 *   var sct = pki.ct.parseSctList(sctExtValue).scts[0];
 *   // Resolve the CT log's DER SubjectPublicKeyInfo from a trusted log list, keyed by log id.
 *   var logKeysByLogId = {};                       // { sct.logIdHex: <SPKI Buffer>, ... }
 *   logKeysByLogId[sct.logIdHex] = await pki.key.export(log.publicKey);
 *   var logKey = logKeysByLogId[sct.logIdHex];
 *   var ok = await pki.ct.verifySct({ entryType: 0, leafCert: certDer }, sct, logKey);
 */
async function verifySct(entry, sct, logPublicKey) {
  var message = reconstructSignedData(entry, sct);
  var spki = _toBuffer(logPublicKey, "the CT log public key (SPKI)");
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
    sig = validator.sig.ecdsaDerToP1363(sig, ec.curve, CtError, "ct/bad-signature");
  } else if (sigInfo.signatureName === "rsa") {
    if (alg.algOid !== oid.byName("rsaEncryption")) throw new CtError("ct/bad-input", "the SCT declares an RSA signature but the log key is not an RSA key");
    if (!(alg.rsaBits >= 2048)) throw new CtError("ct/unsupported-algorithm", "the SCT log RSA key is below the RFC 6962 sec. 2.1.4 minimum of 2048 bits");
    imp = { name: "RSASSA-PKCS1-v1_5", hash: hashName };
    ver = { name: "RSASSA-PKCS1-v1_5" };
  } else {
    throw new CtError("ct/unsupported-algorithm", "unsupported SCT signature algorithm " + JSON.stringify(sigInfo.signatureName) + " (RFC 6962 sec. 2.1.4 supports ecdsa/rsa)");
  }
  try {
    var key = await subtle.importKey("spki", spki, imp, false, ["verify"]);
    return await subtle.verify(ver, key, sig, message);
  } catch (e) {
    throw new CtError("ct/verify-error", "the SCT signature could not be evaluated", e);
  }
}

function TlsWriter() { return new ByteWriter(CtError, "ct/bad-input"); }

function _encodeSctBody(sct) {
  if (!sct || typeof sct !== "object") throw new CtError("ct/bad-input", "each SCT must be an object");
  if (sct.version !== 0) {
    if (typeof sct.version !== "number" || !Number.isInteger(sct.version) || sct.version < 0 || sct.version > 255) {
      throw new CtError("ct/bad-input", "an SCT version must be a byte in 0..255 (RFC 6962 sec. 3.2)");
    }
    var raw = _toBuffer(sct.rawSct, "sct.rawSct");
    if (raw.length < 1 || raw[0] !== sct.version) {
      throw new CtError("ct/bad-input", "an opaque SCT's rawSct[0] must equal its declared version (RFC 6962 sec. 3.3)");
    }
    return raw;
  }
  var w = new TlsWriter();
  w.u8(0, "ct/bad-input");
  var logId = _toBuffer(sct.logId, "sct.logId");
  if (logId.length !== LOGID_BYTES) throw new CtError("ct/bad-input", "an SCT logId must be exactly " + LOGID_BYTES + " bytes (RFC 6962 sec. 3.2)");
  w.bytes(logId);
  w.u64(guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp"), "ct/bad-input");
  w.vector(2, 0, 0xffff, _toBuffer(sct.extensions, "sct.extensions"), "ct/bad-input");
  w.u8(sct.hashAlg, "ct/bad-input");
  w.u8(sct.sigAlg, "ct/bad-input");
  w.vector(2, 0, 0xffff, _toBuffer(sct.signature, "sct.signature"), "ct/bad-input");
  return w.build();
}

/**
 * @primitive  pki.ct.encodeSctList
 * @signature  pki.ct.encodeSctList(scts) -> Buffer
 * @since      0.2.24
 * @status     stable
 * @spec       RFC 6962, RFC 5246
 * @related    pki.ct.parseSctList, pki.ct.signSct
 *
 * Build the value of an RFC 6962 SCT-list extension from an array of SCTs: the exact
 * inverse of `parseSctList`, such that `parseSctList(encodeSctList(list.all))` round-trips to
 * identical bytes. Each element is either a decoded v1 SCT (the shape `parseSctList().scts[]`
 * or `signSct` returns: `version` 0, 32-byte `logId`, `timestamp` BigInt, raw `extensions`,
 * `hashAlg` / `sigAlg` code points, raw `signature`), rebuilt from its fields in the RFC
 * 6962 sec. 3.2 field order, or an opaque non-v1 entry (`{ version, rawSct }`) whose
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
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var kp = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
 *   var sctExtValue = pki.ct.encodeSctList([
 *     await pki.ct.signSct({ entryType: 0, leafCert: der }, await pki.key.export(log.privateKey))]);
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
    ew.vector(2, 1, 0xffff, _encodeSctBody(scts[i]), "ct/bad-input");
    var el = ew.build();
    total += el.length;
    if (total > 0xffff) throw new CtError("ct/too-large", "the SCT list body exceeds the 65535-byte maximum (RFC 6962 sec. 3.3)");
    elements.push(el);
  }
  var lw = new TlsWriter();
  lw.vector(2, 1, 0xffff, Buffer.concat(elements, total), "ct/too-large");
  return asn1.build.octetString(lw.build());
}

function _logKeyMaterial(logKey) {
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
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.verifySct, pki.ct.reconstructSignedData, pki.ct.encodeSctList
 *
 * Perform a Certificate Transparency log's signing step (RFC 6962 sec. 3.2): rebuild the exact
 * `digitally-signed` preimage over `entry` (via `reconstructSignedData`, the same builder the
 * verifier hashes), sign it with the log's private key, and return a fully-formed v1 SCT that
 * `verifySct` accepts against the log's public key. `entry` is the log entry the SCT covers
 * (`{ entryType: 0, leafCert }` or `{ entryType: 1, tbsCertificate, issuerKeyHash }`, as for
 * `reconstructSignedData`); `logKey` is the log's private key (PKCS#8 DER `Buffer`, PEM string,
 * or a node `KeyObject`).
 *
 * The log-key profile is RFC 6962 sec. 2.1.4: ECDSA NIST P-256 (`sigAlg` 3) or RSA >= 2048
 * (`sigAlg` 1), SHA-256 only; an unsupported key fails closed `ct/unsupported-algorithm`. The
 * `logId` is derived as SHA-256 of the log SPKI (sec. 3.4); a supplied `opts.logId` must match.
 * The returned SCT is the parseSctList/verifySct shape and composes with `encodeSctList`.
 *
 * @opts timestamp   ms since the epoch (finite non-negative integer/BigInt). Default `Date.now()`.
 * @opts extensions  raw `CtExtensions` bytes (opaque<0..2^16-1>). Default empty.
 * @opts logId       assert the derived LogID equals this 32-byte value (fail closed on mismatch).
 * @example
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var signerKeyPkcs8 = await pki.key.export(log.privateKey);
 *   var kp = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
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
    signatureAlgorithm: { hash: hashAlg, hashName: HASH_ALGORITHMS[hashAlg] || null, signature: sigAlg, signatureName: SIGNATURE_ALGORITHMS[sigAlg] || null },
    signature: signature,
  };
}


var LOG_STATE_TRUST = { pending: "no", qualified: "yes", usable: "yes", readonly: "yes", retired: "conditional", rejected: "no" };

function _parseLogState(state) {
  if (state == null || typeof state !== "object") throw _ctErr("ct/bad-state", "a CT log entry is missing its state");
  var keys = Object.keys(state);
  if (keys.length !== 1 || !_hasOwn(LOG_STATE_TRUST, keys[0])) {
    throw _ctErr("ct/bad-state", "a CT log state must carry exactly one recognized member (pending/qualified/usable/readonly/retired/rejected)");
  }
  var name = keys[0], member = state[name];
  if (member == null || typeof member !== "object") throw _ctErr("ct/bad-state", "the CT log state " + name + " is malformed");
  var since = rfc3339.parse(member.timestamp, _ctErr, "ct/bad-date", "the CT log state timestamp");
  var trust = LOG_STATE_TRUST[name];
  return { name: name, since: since, trusted: trust === "yes", conditional: trust === "conditional" };
}

function _parseTemporalInterval(ti) {
  if (ti == null) return null;
  if (typeof ti !== "object") throw _ctErr("ct/bad-log-list", "a CT log temporal_interval must be an object");
  var start = rfc3339.parse(ti.start_inclusive, _ctErr, "ct/bad-date", "temporal_interval.start_inclusive");
  var end = rfc3339.parse(ti.end_exclusive, _ctErr, "ct/bad-date", "temporal_interval.end_exclusive");
  // allow:nan-date-comparison-unguarded -- start/end are rfc3339.parse results, guaranteed non-NaN (rfc3339.isValid rejects a NaN date).
  if (guard.time.instantOf(start) >= guard.time.instantOf(end)) throw _ctErr("ct/bad-log-list", "a CT log temporal_interval start_inclusive must be strictly before end_exclusive");
  return { startInclusive: start, endExclusive: end };
}

function _parseLog(log, operatorName) {
  if (log == null || typeof log !== "object") throw _ctErr("ct/bad-log-list", "a CT log entry is not an object");
  if (typeof log.key !== "string" || typeof log.log_id !== "string") throw _ctErr("ct/bad-log-list", "a CT log entry is missing its key or log_id");
  var spki = guard.encoding.base64(log.key, C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, "ct/bad-log-list", "the CT log key");
  var statedId = guard.encoding.base64(log.log_id, 64, _ctErr, "ct/bad-log-list", "the CT log id");
  if (statedId.length !== 32) throw _ctErr("ct/bad-log-list", "a CT log_id must be 32 bytes (SHA-256), got " + statedId.length);
  _spkiAlg(spki);
  var logId = nodeCrypto.createHash("sha256").update(spki).digest();
  if (!logId.equals(statedId)) throw _ctErr("ct/log-id-mismatch", "the CT log_id does not match SHA-256 of the log key (RFC 6962 sec. 3.2)");
  return {
    logId: logId, logIdHex: logId.toString("hex"), key: spki,
    description: typeof log.description === "string" ? log.description : null,
    url: typeof log.url === "string" ? log.url : (typeof log.submission_url === "string" ? log.submission_url : null),
    mmd: typeof log.mmd === "number" ? log.mmd : null,
    operator: operatorName, state: _parseLogState(log.state), temporalInterval: _parseTemporalInterval(log.temporal_interval),
    trusted: false,
  };
}

function _sameTemporal(a, b) {
  if (a == null && b == null) return true;
  if (a == null || b == null) return false;
  return guard.time.instantOf(a.startInclusive) === guard.time.instantOf(b.startInclusive) &&
    guard.time.instantOf(a.endExclusive) === guard.time.instantOf(b.endExclusive);
}
function _logsAgree(a, b) {
  return a.state.name === b.state.name &&
    guard.time.instantOf(a.state.since) === guard.time.instantOf(b.state.since) &&
    _sameTemporal(a.temporalInterval, b.temporalInterval);
}

/**
 * @primitive  pki.ct.parseLogList
 * @signature  pki.ct.parseLogList(json, opts?) -> { logs, byLogId, version, timestamp }
 * @since      0.2.28
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.verifySctWithLogList, pki.ct.verifySct
 *
 * Ingest a Certificate Transparency log-list JSON document (the `log_list.json` browsers consume) into a
 * set of constraint-carrying trusted logs, keyed by log-id. `json` is a Buffer or string; the caller
 * supplies the already-fetched, already-authenticated bytes (offline, no network fetch). Parsing routes
 * through the bounded, duplicate-member-rejecting JSON reader; for each log it base64-decodes the `key`
 * to its DER SubjectPublicKeyInfo, validates it as a well-formed on-profile key, **recomputes**
 * `SHA-256(SPKI)` and fail-closed **requires** it equal the stated `log_id` (RFC 6962 sec. 3.2; a log
 * whose stated id disagrees with its key is refused as `ct/log-id-mismatch`), and decodes the `state`
 * (exactly one of pending/qualified/usable/readonly/retired/rejected) and `temporal_interval`. Returns
 * `{ logs, byLogId, version, timestamp }` where each log is `{ logId, logIdHex, key, description, url, mmd,
 * operator, state: { name, since, trusted, conditional }, temporalInterval, trusted }`, `byLogId` is a
 * null-proto `{ logIdHex: log }` map, `version` is the document's version string (or null), and `timestamp`
 * is the parsed `log_list_timestamp` `Date` (or null when absent/unparseable; the staleness surface, read
 * leniently, never a throw). Every malformed / oversized / mis-bound input is a typed `CtError`.
 *
 * @example
 *   // the v3 log-list JSON shape, as published by a CT log-list operator
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var logSpki = await pki.key.export(log.publicKey);
 *   var logId = Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", logSpki));
 *   var logListJsonBytes = Buffer.from(JSON.stringify({ operators: [{ name: "Example Operator", logs: [{
 *     description: "Example Log", log_id: logId.toString("base64"), key: logSpki.toString("base64"),
 *     url: "https://ct.example/log/", mmd: 86400,
 *     state: { usable: { timestamp: "2026-01-01T00:00:00Z" } } }] }] }), "utf8");
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
        rec.trusted = rec.state.trusted;
        var prev = byLogId[rec.logIdHex];
        if (prev) {
          if (!_logsAgree(prev, rec)) throw _ctErr("ct/duplicate-log", "two CT log entries share log-id " + rec.logIdHex + " but disagree");
          continue;
        }
        byLogId[rec.logIdHex] = rec;
        logs.push(rec);
      }
    }
  }
  var version = typeof doc.version === "string" ? doc.version : null;
  var timestamp = (typeof doc.log_list_timestamp === "string" && rfc3339.isValid(doc.log_list_timestamp))
    ? rfc3339.parse(doc.log_list_timestamp, _ctErr, "ct/bad-date", "log_list_timestamp") : null;
  return { logs: logs, byLogId: byLogId, version: version, timestamp: timestamp };
}

function _resolveNotAfter(entry, opts) {
  if (guard.time.isDate(opts.certNotAfter)) return opts.certNotAfter;
  if (entry && entry.entryType === 0 && entry.leafCert != null) {
    var x509 = require("./schema-x509.js");   // allow:inline-require -- circular load with schema-x509 -> schema-pkix (see note above)
    try {
      return x509.parse(_toBuffer(entry.leafCert, "entry.leafCert")).validity.notAfter;
    } catch (_e) {
      return null;
    }
  }
  return null;
}

/**
 * @primitive  pki.ct.verifySctWithLogList
 * @signature  pki.ct.verifySctWithLogList(entry, sct, logList, opts?) -> Promise<{ valid, logId, logIdHex, operator, logState, timestamp }>
 * @since      0.2.28
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.parseLogList, pki.ct.verifySct
 *
 * Resolve the trusted CT log for an SCT and verify it in one step. `logList` is a `parseLogList` result;
 * the log is resolved by `sct.logIdHex` (an unknown log is `ct/log-not-found`). The log's **state** gates
 * trust (usable/qualified/readonly proceed; a retired log proceeds only for an SCT timestamped before its
 * retirement instant; pending/rejected are `ct/log-untrusted`); its **temporal_interval** gates the
 * covered certificate: the cert's `notAfter`, from `entry.leafCert` when `entryType` is 0 or from
 * `opts.certNotAfter`, must fall in `[start_inclusive, end_exclusive)`, and a windowed log with no
 * resolvable notAfter is `ct/temporal-interval`, never silently skipped). Then the crypto is delegated to
 * the shipped `verifySct(entry, sct, log.key)` (which independently re-checks `logId == SHA-256(key)`).
 * The verdict's `valid` is `true` for a valid signature from a trusted, in-window log and `false` on a
 * cryptographic mismatch; `logId` / `logIdHex` / `operator` / `logState` / `timestamp` carry the resolved
 * log record so a caller can record which trusted log accepted the SCT and when, for a policy decision,
 * without re-deriving them. It throws a typed `CtError` on any structural / trust failure.
 *
 * @opts certNotAfter A `Date` -- the covered certificate's notAfter for the temporal-interval gate (required for a precert entry).
 * @example
 *   var log = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var logSpki = await pki.key.export(log.publicKey);
 *   var kp = await pki.key.generate("Ed25519");
 *   var leafCert = await pki.x509.sign({ subject: "example.org", subjectPublicKey: await pki.key.export(kp.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(kp.privateKey) });
 *   var sctEntry = { entryType: 0, leafCert: leafCert };
 *   var embeddedSct = pki.ct.parseSctList(pki.ct.encodeSctList([
 *     await pki.ct.signSct(sctEntry, await pki.key.export(log.privateKey))])).scts[0];
 *   var logId = Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", logSpki));
 *   var logList = pki.ct.parseLogList(Buffer.from(JSON.stringify({ operators: [{ name: "Example Operator", logs: [{
 *     description: "Example Log", log_id: logId.toString("base64"), key: logSpki.toString("base64"),
 *     url: "https://ct.example/log/", mmd: 86400,
 *     state: { usable: { timestamp: "2026-01-01T00:00:00Z" } } }] }] }), "utf8"));
 *   var res = await pki.ct.verifySctWithLogList(sctEntry, embeddedSct, logList);   // { valid, logId, logIdHex, operator, logState, timestamp }
 */
function _classifyLog(sct, logList, entry, opts) {
  if (logList == null || typeof logList !== "object" || logList.byLogId == null) return { status: "bad-input", code: "ct/bad-input", message: "logList must be a pki.ct.parseLogList result" };
  if (sct == null || typeof sct !== "object" || typeof sct.logIdHex !== "string") return { status: "bad-input", code: "ct/bad-input", message: "the SCT is missing its logIdHex" };
  var log = logList.byLogId[sct.logIdHex];
  if (log == null) return { status: "not-found", code: "ct/log-not-found", message: "no trusted CT log matches the SCT's logId " + sct.logIdHex };
  if (!log.state.trusted) {
    if (!log.state.conditional) return { status: "untrusted", log: log, code: "ct/log-untrusted", message: "the CT log state '" + log.state.name + "' is not trusted" };
    var ts = guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp");
    if (ts >= BigInt(guard.time.instantOf(log.state.since))) return { status: "untrusted", log: log, code: "ct/log-untrusted", message: "the CT log is retired and the SCT is not timestamped before its retirement (" + log.state.since.toISOString() + ")" };
  }
  if (log.temporalInterval) {
    var notAfter = _resolveNotAfter(entry, opts);
    if (notAfter == null) return { status: "temporal", log: log, code: "ct/temporal-interval", message: "the windowed CT log has no resolvable covered-certificate notAfter (pass a valid opts.certNotAfter)" };
    if (!guard.time.within(notAfter, log.temporalInterval.startInclusive, log.temporalInterval.endExclusive, _ctErr, "ct/temporal-interval", "the covered certificate notAfter (pass a valid opts.certNotAfter)")) {
      return { status: "temporal", log: log, code: "ct/temporal-interval", message: "the covered certificate's notAfter is outside the CT log's temporal_interval" };
    }
  }
  return { status: "ok", log: log };
}

async function verifySctWithLogList(entry, sct, logList, opts) {
  opts = opts || {};
  var c = _classifyLog(sct, logList, entry, opts);
  if (c.status !== "ok") throw _ctErr(c.code, c.message);
  var valid = await verifySct(entry, sct, c.log.key);
  return {
    valid: valid,
    logId: c.log.logId,
    logIdHex: c.log.logIdHex,
    operator: c.log.operator,
    logState: c.log.state.name,
    timestamp: sct.timestamp,
  };
}

var _VERIFY_SCT_LIST_OPTS = { minScts: 1, minOperators: 1, certNotAfter: 1, at: 1 };

function _policyCount(v, name) {
  if (v == null) return null;
  if (typeof v !== "number" || !intrinsic.isInteger(v) || v < 1) throw _ctErr("ct/bad-input", name + " must be a positive integer");
  return v;
}

/**
 * @primitive  pki.ct.verifySctList
 * @signature  pki.ct.verifySctList(entry, list, logList, opts?) -> Promise<verdict>
 * @since      0.6.1
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.verifySct, pki.ct.verifySctWithLogList, pki.ct.parseLogList, pki.ct.parseSctList
 *
 * Render a certificate-level Certificate Transparency verdict over the SET of SCTs a certificate carries
 * (RFC 6962 sec. 3.3), rather than one SCT at a time. Each SCT is resolved to a trusted log through
 * `logList` and verified with the shipped `verifySct`; the verdict reports how many distinct trusted
 * logs verified an SCT (`validScts`, so a duplicated SCT cannot inflate the count), from how many
 * distinct trusted operators, and whether that meets the caller's CT policy. The RFC floor is one valid
 * SCT (sec. 3.3), so `minScts` and `minOperators` both default to 1; the distinct-operator axis is a
 * browser CT policy layered on top of the RFC, so the caller sets the threshold and the verdict surfaces
 * the counts rather than hardcoding a browser's numbers.
 *
 * `entry` is the shared log-entry context for every SCT (`{ entryType: 0, leafCert }` for SCTs delivered
 * over TLS/OCSP, or `{ entryType: 1, tbsCertificate, issuerKeyHash }` for embedded SCTs; the shape
 * `pki.ct.x509CertEntry` produces). `list` is a `parseSctList` result, its `.scts` array, or an array of
 * decoded v1 SCTs; unknown-version entries are counted `unknownScts` and never as valid. `logList` is a
 * `parseLogList` result. A policy shortfall is a verdict (`policyOk: false`), not a throw; a per-SCT
 * trust or crypto failure is recorded into its result row (`valid: false`, with a `code` for a
 * structural or trust exclusion, without one for a cryptographic mismatch) and the loop continues; only
 * a mis-shaped `entry` / `list` / `logList` / `opts` throws a typed `CtError`.
 *
 * @opts
 *   - `minScts` (int, default 1) -- required count of valid SCTs from trusted, in-window logs.
 *   - `minOperators` (int, default 1) -- required count of distinct trusted operators among them.
 *   - `certNotAfter` (Date) -- the covered certificate's notAfter for each windowed log's temporal gate;
 *     auto-derived from `entry.leafCert` for entryType 0, required for a precert entry against a windowed log.
 *   - `at` (Date) -- the validation time; when supplied, an SCT whose timestamp is later than it is
 *     rejected and not counted (RFC 6962 sec. 5.2, a client rejects a future-dated SCT). The
 *     pki.path.validate CT gate passes its opts.time here.
 * @example
 *   // requires: logListJsonBytes -- the CT log-list JSON a distributor publishes (the log_list.json browsers consume)
 *   // requires: sctExtValue -- a certificate's SCT-list extension value (a signedCertificateTimestampList extension)
 *   // requires: certDer -- the DER of the certificate the SCTs cover
 *   var logList = pki.ct.parseLogList(logListJsonBytes);
 *   var list = pki.ct.parseSctList(sctExtValue);
 *   var verdict = await pki.ct.verifySctList({ entryType: 0, leafCert: certDer }, list, logList,
 *     { minScts: 2, minOperators: 2 });
 *   verdict.policyOk;        // did the certificate meet the CT policy?
 *   verdict.operators;       // the distinct trusted operators whose logs verified an SCT
 */
async function verifySctList(entry, list, logList, opts) {
  opts = guard.identifier.optionsObject(opts, _ctErr, "ct/bad-input", "pki.ct.verifySctList options");
  guard.identifier.assertKnownKeys(opts, _VERIFY_SCT_LIST_OPTS, _ctErr, "ct/bad-input", "pki.ct.verifySctList has an unknown option: ");
  var minScts = _policyCount(opts.minScts, "opts.minScts"); if (minScts == null) minScts = 1;
  var minOperators = _policyCount(opts.minOperators, "opts.minOperators"); if (minOperators == null) minOperators = 1;
  if (logList == null || typeof logList !== "object" || logList.byLogId == null) throw _ctErr("ct/bad-input", "logList must be a pki.ct.parseLogList result");
  if (entry == null || (entry.entryType !== 0 && entry.entryType !== 1)) throw _ctErr("ct/bad-entry-type", "entryType must be x509_entry(0) or precert_entry(1) (RFC 6962 sec. 3.1)");
  var atMs = null;
  if (opts.at != null) { guard.time.assertValid(opts.at, _ctErr, "ct/bad-input", "opts.at (the validation time)"); atMs = guard.time.instantOf(opts.at); }
  if (opts.certNotAfter != null) guard.time.assertValid(opts.certNotAfter, _ctErr, "ct/bad-input", "opts.certNotAfter (the covered certificate's notAfter)");
  if (entry.entryType === 0) { _toBuffer(entry.leafCert, "entry.leafCert"); }
  else {
    if (_toBuffer(entry.issuerKeyHash, "entry.issuerKeyHash").length !== 32) throw _ctErr("ct/bad-issuer-key-hash", "entry.issuerKeyHash must be exactly 32 bytes (SHA-256 of the issuer SPKI, RFC 6962 sec. 3.2)");
    _toBuffer(entry.tbsCertificate, "entry.tbsCertificate");
  }
  var scts, unknownScts;
  if (list != null && intrinsic.isArray(list.scts)) { scts = list.scts; unknownScts = intrinsic.isArray(list.unknownScts) ? list.unknownScts.length : 0; }
  else if (intrinsic.isArray(list)) { scts = list; unknownScts = 0; }
  else throw _ctErr("ct/bad-input", "list must be a pki.ct.parseSctList result, its .scts array, or an array of decoded v1 SCTs");
  if (scts.length > C.LIMITS.SCT_MAX_COUNT) throw _ctErr("ct/too-many-scts", "the SCT list has " + scts.length + " entries, exceeding the SCT_MAX_COUNT cap of " + C.LIMITS.SCT_MAX_COUNT + " (RFC 6962 sec. 3.3)");

  var results = [], validScts = 0, operators = [], seenOps = intrinsic.create(null), seenLogs = intrinsic.create(null);
  for (var i = 0; i < scts.length; i++) {
    var sct = scts[i];
    var row = { logIdHex: (sct && typeof sct.logIdHex === "string") ? sct.logIdHex : null, valid: false,
      operator: null, logState: null,
      timestamp: (sct && typeof sct.timestamp === "bigint") ? sct.timestamp : null, code: undefined, reason: undefined };
    var c;
    try { c = _classifyLog(sct, logList, entry, opts); }
    catch (e) {
      if (!(e && e.isPkiError)) throw e;
      row.code = e.code; row.reason = e.message; intrinsic.push(results, row); continue;
    }
    if (c.log) { row.operator = c.log.operator; row.logState = c.log.state.name; }
    if (c.status !== "ok") { row.code = c.code; row.reason = c.message; intrinsic.push(results, row); continue; }
    var ok;
    try { ok = await verifySct(entry, sct, c.log.key); }
    catch (e) {
      if (!(e && e.isPkiError)) throw e;
      row.code = e.code; row.reason = e.message; intrinsic.push(results, row); continue;
    }
    if (ok === true && atMs != null && sct.timestamp > atMs) {
      row.code = "ct/future-timestamp"; row.reason = "the SCT timestamp is later than the validation time (RFC 6962 sec. 5.2)";
      intrinsic.push(results, row); continue;
    }
    row.valid = ok === true;
    if (row.valid && !seenLogs[sct.logIdHex]) {
      seenLogs[sct.logIdHex] = true;
      validScts++;
      if (c.log.operator != null && !seenOps[c.log.operator]) { seenOps[c.log.operator] = true; intrinsic.push(operators, c.log.operator); }
    }
    intrinsic.push(results, row);
  }
  var operatorCount = operators.length;
  var policyOk = validScts >= minScts && operatorCount >= minOperators;
  return {
    valid: policyOk,
    policyOk: policyOk, totalScts: scts.length + unknownScts, validScts: validScts, unknownScts: unknownScts,
    operatorCount: operatorCount, operators: operators, required: { minScts: minScts, minOperators: minOperators },
    results: results,
    reason: policyOk ? null : ("CT policy not met: " + validScts + " valid SCT(s) from " + operatorCount + " distinct operator(s); require at least " + minScts + " SCT(s) from at least " + minOperators + " operator(s)"),
  };
}

function _asParsedCert(v, field) {
  var x509 = require("./schema-x509.js");   // allow:inline-require -- circular load (see _resolveNotAfter)
  return guard.parsed.acceptDerived(v, "certificate", x509.parse, _ctErr, "ct/bad-cert-entry", field);
}

/**
 * @primitive  pki.ct.x509CertEntry
 * @signature  pki.ct.x509CertEntry(cert, issuer) -> { entryType, tbsCertificate, issuerKeyHash }
 * @since      0.6.1
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.verifySctList, pki.ct.reconstructSignedData, pki.ct.verifySct
 *
 * Reconstruct the precertificate log entry from a FINAL certificate carrying embedded SCTs, so those
 * SCTs can be verified end to end (RFC 6962 sec. 3.2): "reconstruct this TBSCertificate from the final
 * certificate by extracting the TBSCertificate from it and deleting the SCT extension". Returns the
 * `{ entryType: 1, tbsCertificate, issuerKeyHash }` entry `pki.ct.verifySctList` / `reconstructSignedData`
 * consume, where `tbsCertificate` is the leaf TBS with ONLY the signedCertificateTimestampList extension
 * removed and `issuerKeyHash` is `SHA-256(issuer SubjectPublicKeyInfo DER)` (32 bytes). The signed
 * `tbs_certificate` an SCT covers is also without the CT poison extension (RFC 6962 sec. 3.2, "without
 * the signature and the poison extension"), which sits in the same position the SCT list takes in the
 * final certificate, so deleting the SCT-list extension IS the whole reconstruction: no poison extension
 * is re-added. (The Precertificate Signing Certificate case, where the precert issuer differs from the
 * final issuer, is out of scope; the common flow issues both from the one CA.)
 *
 * The removal is byte surgery on the CA-signed bytes, never a value re-serialization: the extensions
 * list and the two enclosing containers are rebuilt from every OTHER element's raw DER, so the only
 * bytes that change are the removed extension and the recomputed canonical DER length prefixes. `cert`
 * and `issuer` each accept a DER `Buffer`, a PEM string, or a `pki.schema.x509.parse` result. A
 * certificate with no extensions or no SCT-list extension is `ct/no-sct-extension`; an argument that is
 * not a certificate is `ct/bad-cert-entry`, and malformed certificate bytes carry the X.509 parse fault.
 *
 * @example
 *   // requires: leafCertDer -- the DER of a final certificate carrying embedded SCTs
 *   // requires: issuerCertDer -- the DER of the certificate that issued it
 *   // requires: sctExtValue -- the leaf's signedCertificateTimestampList extension value
 *   // requires: logList -- a pki.ct.parseLogList result
 *   var entry = pki.ct.x509CertEntry(leafCertDer, issuerCertDer);
 *   var verdict = await pki.ct.verifySctList(entry, pki.ct.parseSctList(sctExtValue), logList,
 *     { certNotAfter: pki.schema.x509.parse(leafCertDer).validity.notAfter });
 */
function _issuerSpki(v, field) {
  if (v != null && typeof v === "object" && !intrinsic.isBuffer(v) && v.subjectPublicKeyInfo != null && v.subjectPublicKeyInfo.bytes != null) {
    return guard.bytes.view(v.subjectPublicKeyInfo.bytes, CtError, "ct/bad-cert-entry", field + " subjectPublicKeyInfo.bytes");
  }
  return _asParsedCert(v, field).subjectPublicKeyInfo.bytes;
}

function x509CertEntry(cert, issuer) {
  var leaf = _asParsedCert(cert, "cert"), issSpki = _issuerSpki(issuer, "issuer");
  var tbs = asn1.decode(leaf.tbsBytes);
  var wrapIdx = -1;
  for (var i = 0; i < tbs.children.length; i++) {
    if (tbs.children[i].tagClass === "context" && tbs.children[i].tagNumber === 3) { wrapIdx = i; break; }
  }
  if (wrapIdx < 0) throw _ctErr("ct/no-sct-extension", "the certificate has no extensions, so it carries no embedded SCT list (RFC 6962 sec. 3.2)");
  var extsSeq = tbs.children[wrapIdx].children[0];
  var sctOid = asn1.build.oid(oid.byName("signedCertificateTimestampList"));
  var kept = [], removed = 0;
  for (var j = 0; j < extsSeq.children.length; j++) {
    var ext = extsSeq.children[j];
    if (ext.children[0] && intrinsic.bufferEquals(ext.children[0].bytes, sctOid)) { removed++; continue; }
    intrinsic.push(kept, ext.bytes);
  }
  if (removed === 0) throw _ctErr("ct/no-sct-extension", "the certificate carries no signedCertificateTimestampList extension (RFC 6962 sec. 3.2)");
  var tbsChildren = [];
  for (var k = 0; k < tbs.children.length; k++) {
    if (k !== wrapIdx) { intrinsic.push(tbsChildren, tbs.children[k].bytes); continue; }
    if (kept.length > 0) intrinsic.push(tbsChildren, asn1.build.explicit(3, asn1.build.sequence(kept)));
  }
  var issuerKeyHash = nodeCrypto.createHash("sha256").update(issSpki).digest();
  return { entryType: 1, tbsCertificate: asn1.build.sequence(tbsChildren), issuerKeyHash: issuerKeyHash };
}

/**
 * @primitive  pki.ct.verifyLogListSignature
 * @signature  pki.ct.verifyLogListSignature(json, signature, publicKey) -> Promise<boolean>
 * @since      0.2.29
 * @status     stable
 * @spec       RFC 6962, RFC 8017
 * @related    pki.ct.parseLogList, pki.ct.verifySct
 *
 * Verify the detached signature published alongside the Certificate Transparency log list (the
 * `log_list.sig` over `log_list.json`). `json` is the raw log-list bytes (a Buffer, or the fetched text
 * as a string, verified byte-for-byte and never re-serialized), `signature` is the detached signature, and
 * `publicKey` is the caller-pinned signer SubjectPublicKeyInfo (DER; there is no baked-in key). The scheme
 * is RSASSA-PKCS1-v1.5 with SHA-256 over an RSA key (the deployed scheme; an EC P-256 / ECDSA-SHA-256 arm
 * is accepted for future-proofing). Resolves `true` for a valid signature, `false` on a cryptographic
 * mismatch (a verdict). Fail-closed forgery defenses throw before any verify: an RSA public exponent below
 * 3 or even (`ct/bad-input`), a sub-2048-bit RSA key or an unsupported key type / curve
 * (`ct/unsupported-algorithm`), a non-conformant ECDSA DER Sig-Value (`ct/bad-signature`); a structural
 * evaluation failure is `ct/verify-error`. Offline: the caller fetches and pins; the toolkit only verifies.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var signer = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var googleSignerSpki = await pki.key.export(signer.publicKey);
 *   var logListJsonBytes = Buffer.from(JSON.stringify({ operators: [] }), "utf8");
 *   // the published signature is DER SEQUENCE(r, s); WebCrypto emits the raw r||s pair
 *   var raw = Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
 *     signer.privateKey, logListJsonBytes));
 *   var logListSig = b.sequence([b.integer(BigInt("0x" + raw.subarray(0, raw.length / 2).toString("hex"))),
 *                                b.integer(BigInt("0x" + raw.subarray(raw.length / 2).toString("hex")))]);
 *   var ok = await pki.ct.verifyLogListSignature(logListJsonBytes, logListSig, googleSignerSpki);
 */
async function verifyLogListSignature(json, signature, publicKey) {
  var message = typeof json === "string" ? Buffer.from(json) : _toBuffer(json, "the CT log list JSON");
  guard.limits.byteCap(message, C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, "ct/too-large", "the CT log list");
  var sig = _toBuffer(signature, "the CT log list signature");
  var spki = _toBuffer(publicKey, "the CT log list signer public key (SPKI)");
  var alg = _spkiAlg(spki);
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
    sig = validator.sig.ecdsaDerToP1363(sig, ec.curve, CtError, "ct/bad-signature");
  } else {
    throw new CtError("ct/unsupported-algorithm", "unsupported CT log-list signer key algorithm (only rsaEncryption / ecPublicKey P-256)");
  }
  try {
    var key = await subtle.importKey("spki", spki, imp, false, ["verify"]);
    return await subtle.verify(ver, key, sig, message);
  } catch (e) {
    throw new CtError("ct/verify-error", "the CT log-list signature could not be evaluated", e);
  }
}


var DEFAULT_FETCH_TIMEOUT = C.TIME.seconds(30);
var MAX_FETCH_TIMEOUT = C.TIME.seconds(600);
var KNOWN_FETCH_OPTS = { url: 1, signerKey: 1, sigUrl: 1, transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, requireJsonContentType: 1 };

function _tlsForFetch(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}

function _sameOrigin(a, b) { return new URL(a).origin === new URL(b).origin; }

function _fetchCtypeToken(headers) { return String((headers || {})["content-type"] || "").split(";")[0].trim().toLowerCase(); }

function _parseHttpsUrl(u, label) {
  var parsed;
  try { parsed = new URL(String(u)); }
  catch (e) { throw _ctErr("ct/bad-url", "the CT log-list " + label + " did not parse: " + String(u), e); }
  if (parsed.protocol !== "https:") throw _ctErr("ct/insecure-url", "the CT log-list " + label + " must be https, got " + parsed.protocol + " for " + String(u));
  return parsed;
}

function _sigUrlFor(parsed) {
  if (!_endsWithJson(parsed.pathname)) throw _ctErr("ct/bad-input", "cannot derive the detached-signature URL from a non-.json path (" + JSON.stringify(parsed.pathname) + "); pass opts.sigUrl explicitly");
  var sig = new URL(parsed.href);
  sig.pathname = _strSlice(parsed.pathname, 0, parsed.pathname.length - _JSON_SUFFIX.length) + ".sig";
  return sig.href;
}

function _fetchBody(transport, url, req, label) {
  return Promise.resolve().then(function () {
    return transport({ method: "GET", url: url, headers: req.headers, tls: req.tls, timeout: req.timeout, maxResponseBytes: req.maxResponseBytes });
  }).then(function (res) {
    res = res || {};
    var h = {};
    Object.keys(res.headers || {}).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
    var body = guard.bytes.isByteSource(res.body)
      ? guard.bytes.source(res.body, CtError, "ct/bad-input", label)
      : Buffer.from(String(res.body == null ? "" : res.body), "utf8");
    if (body.length > req.maxResponseBytes) throw _ctErr("ct/response-too-large", "the " + label + " (" + body.length + " bytes) exceeds the " + req.maxResponseBytes + "-byte cap");
    if (res.status !== 200) throw _ctErr("ct/http-error", "the CT server returned HTTP " + JSON.stringify(res.status) + " for the " + label);
    if (body.length === 0) throw _ctErr("ct/empty-response", "the CT server returned a 200 with an empty " + label);
    return { body: body, status: res.status, contentType: _fetchCtypeToken(h), tls: res.tls || null };
  }).catch(function (e) {
    if (e instanceof PkiError) throw e;
    throw _ctErr("ct/transport-error", "the CT " + label + " request failed in the transport", e);
  });
}

/**
 * @primitive  pki.ct.fetchLogList
 * @signature  pki.ct.fetchLogList(opts) -> Promise<{ logs, byLogId, version, timestamp, raw, status, contentType, tls }>
 * @since      0.3.21
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.parseLogList, pki.ct.verifyLogListSignature, pki.ct.verifySctWithLogList
 *
 * Fetch the Certificate Transparency log list live and return the trusted-log set only after the detached
 * signature verifies against the caller-pinned distributor key. It GETs `opts.url` (the `log_list.json`)
 * and the detached `opts.sigUrl` (the `log_list.sig`, by default `opts.url` with a `.json` path suffix
 * rewritten to `.sig`) over the shared, fail-closed `pki.transport` (or an injected `opts.transport`), then
 * verifies the detached signature over the raw fetched JSON bytes against `opts.signerKey` and only on a
 * strict `true` verdict ingests those same bytes through `parseLogList`, so the client never parses, reads,
 * caches, or surfaces any field of an unverified document (verify-before-parse). No baked-in vendor URL and
 * no baked-in key: the caller pins both out-of-band. Trust is explicit: an `opts.tls.anchors` set or an
 * `opts.tls.useSystemStore` opt-in, `rejectUnauthorized` always on. The returned `timestamp` is surfaced
 * (never policed) so the caller enforces its own freshness policy; chaining a resolved log to an SCT is the
 * caller's `verifySctWithLogList` step. Every fetch / verify / parse failure is a typed `CtError`.
 *
 * @opts url REQUIRED -- the `log_list.json` URL; must be https (no baked-in vendor URL).
 * @opts signerKey REQUIRED and caller-pinned -- the distributor SubjectPublicKeyInfo as a DER Buffer; no baked-in key.
 * @opts sigUrl OPTIONAL -- the detached `log_list.sig` URL (https, must share the log-list URL's origin); default `url` with `.json` -> `.sig` (a non-.json url requires an explicit sigUrl).
 * @opts transport OPTIONAL injectable `transport(request) -> Promise<{status,headers,body}>` (default `pki.transport.https`); the test seam.
 * @opts tls OPTIONAL `{ anchors, useSystemStore, cert, key, minVersion, servername, checkServerIdentity }` threaded to the default transport (ignored when a transport is injected); `rejectUnauthorized` is always on.
 * @opts headers OPTIONAL extra request headers (the request-framing headers are stripped; the verb owns the GET method).
 * @opts timeout OPTIONAL ms budget, default 30s (cap-validated).
 * @opts maxResponseBytes OPTIONAL per-GET size cap, default 4 MiB, tightenable DOWNWARD only.
 * @opts requireJsonContentType OPTIONAL boolean (default false) -- opt in to a strict `ct/bad-content-type` gate on the JSON GET.
 * @example
 *   // a live distributor uses the default pki.transport.https; here an injected transport returns the pair
 *   var r = await pki.ct.fetchLogList({ url: "https://ct.example/log_list.json", signerKey: googleSignerSpki,
 *     transport: function (req) {
 *       var isSig = /\.sig$/.test(req.url);
 *       return Promise.resolve({ status: 200, headers: { "content-type": isSig ? "application/octet-stream" : "application/json" }, body: isSig ? logListSig : logListJsonBytes });
 *     } });
 *   r.logs[0] && r.logs[0].trusted;   // the verified, trusted-log set (the detached signature checked first)
 */
async function fetchLogList(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, KNOWN_FETCH_OPTS, _ctErr, "ct/bad-input", "unknown opts field ");
  if (opts.signerKey == null) throw _ctErr("ct/bad-input", "opts.signerKey is required -- the caller-pinned CT log-list distributor SPKI (there is no baked-in key)");
  if (opts.url == null) throw _ctErr("ct/bad-input", "opts.url is required -- the log_list.json URL (there is no baked-in vendor URL)");
  var jsonParsed = _parseHttpsUrl(opts.url, "URL");
  var jsonUrl = jsonParsed.href;
  var sigUrl = opts.sigUrl != null ? _parseHttpsUrl(opts.sigUrl, "signature URL").href : _sigUrlFor(jsonParsed);
  if (!_sameOrigin(jsonUrl, sigUrl)) throw _ctErr("ct/bad-input", "opts.sigUrl must share the log-list URL's origin (" + jsonParsed.origin + "); a cross-origin detached-signature host is not supported");
  var transport = opts.transport;
  if (!transport) {
    var t = opts.tls || {};
    var hasAnchors = t.anchors !== undefined && t.anchors !== null && !(Array.isArray(t.anchors) && t.anchors.length === 0);
    if (!hasAnchors && t.useSystemStore !== true) throw _ctErr("ct/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true -- refusing an unpinned CT server (RFC 6962 sec. 3.2)");
    transport = httpTransport.https({ E: _ctErr, errPrefix: "ct" });
  }
  var timeout = guard.limits.cap(opts.timeout, "timeout", DEFAULT_FETCH_TIMEOUT, { E: _ctErr, code: "ct/bad-input", min: 1, max: MAX_FETCH_TIMEOUT });
  var maxResponseBytes = guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", C.LIMITS.CT_LOG_LIST_MAX_BYTES, { E: _ctErr, code: "ct/bad-input", min: 1, max: C.LIMITS.CT_LOG_LIST_MAX_BYTES });
  var headers = {};
  Object.keys(opts.headers || {}).forEach(function (k) {
    var lk = k.toLowerCase();
    if (lk !== "content-length" && lk !== "transfer-encoding") headers[k] = opts.headers[k];
  });
  var req = { headers: headers, tls: _tlsForFetch(opts), timeout: timeout, maxResponseBytes: maxResponseBytes };
  var jsonRes = await _fetchBody(transport, jsonUrl, req, "CT log-list JSON");
  if (opts.requireJsonContentType === true && jsonRes.contentType !== "application/json") throw _ctErr("ct/bad-content-type", "the CT log-list JSON GET returned content-type " + JSON.stringify(jsonRes.contentType || null) + " (opts.requireJsonContentType is set)");
  var sigRes = await _fetchBody(transport, sigUrl, req, "CT log-list signature");
  var ok = await verifyLogListSignature(jsonRes.body, sigRes.body, opts.signerKey);
  if (ok !== true) throw _ctErr("ct/log-list-untrusted", "the CT log-list detached signature did not verify against the pinned distributor key -- the fetched list is untrusted and was not parsed");
  var parsed = parseLogList(jsonRes.body);
  return {
    logs: parsed.logs, byLogId: parsed.byLogId, version: parsed.version, timestamp: parsed.timestamp,
    raw: { json: jsonRes.body, sig: sigRes.body }, status: jsonRes.status, contentType: jsonRes.contentType, tls: jsonRes.tls,
  };
}

module.exports = {
  parseSctList: parseSctList,
  reconstructSignedData: reconstructSignedData,
  verifySct: verifySct,
  encodeSctList: encodeSctList,
  signSct: signSct,
  parseLogList: parseLogList,
  verifySctWithLogList: verifySctWithLogList,
  verifySctList: verifySctList,
  x509CertEntry: x509CertEntry,
  verifyLogListSignature: verifyLogListSignature,
  fetchLogList: fetchLogList,
  HASH_ALGORITHMS: HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
};
