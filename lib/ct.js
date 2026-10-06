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
 *   extension: per-SCT logId / timestamp (BigInt) / algorithm / raw signature,
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
/** @internal The log fetch is gated on a resolved promise, and `resolve` builds from the RECEIVER, so
 *  reading the global binding at the call decides whether the request is made at all. Taken at load. */
var _Promise = intrinsic.Promise;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);
/** @internal The operations the RFC 6962 sec. 4 client reads, taken at load. A log's response decides
 *  a verdict, so which function answers "these bytes as base64", "this number as text" or "is this
 *  the pinned log id" is fixed before any caller code runs. */
var _stringOf = intrinsic.String;
var _jsonStringify = intrinsic.stringify;
var _bufferAlloc = intrinsic.bufferAlloc;
var _bufferFrom = intrinsic.bufferFrom;
var _byteLength = intrinsic.byteLength;
var _bufToString = intrinsic.bufToString;
var _bufferCompare = intrinsic.compare;
var _subarray = intrinsic.subarray;
var _toLowerCase = intrinsic.toLowerCase;
var _bufCopy = intrinsic.uncurry(Buffer.prototype.copy);
var _writeU64BE = intrinsic.uncurry(Buffer.prototype.writeBigUInt64BE);
var _searchSet = intrinsic.uncurry(URLSearchParams.prototype.set);
var _numberOf = intrinsic.Number;
var _URL = intrinsic.URL;
/** @internal Every part of a parsed destination is read through the accessor captured at load, not off
 *  the value's own prototype: a header getter that redefined `URL.prototype.href` had the request go to
 *  the host its getter named while the url the caller passed was still the one reported. */
var _urlHref = intrinsic.urlHref;
var _urlOrigin = intrinsic.urlOrigin;
var _urlProtocol = intrinsic.urlProtocol;
var _urlPathname = intrinsic.urlPathname;
var _urlSearchParams = intrinsic.urlSearchParams;
var _urlSetPathname = intrinsic.urlSetPathname;
var _urlSetSearch = intrinsic.urlSetSearch;
var _JSON_SUFFIX = ".json";
function _endsWithJson(s) { return s.length >= _JSON_SUFFIX.length && _strSlice(s, s.length - _JSON_SUFFIX.length) === _JSON_SUFFIX; }
var ByteReader = require("./byte-reader.js");
var ByteWriter = require("./byte-writer.js");
var oid = require("./oid.js");
var webcrypto = require("./webcrypto.js");
var validator = require("./validator-all.js");
var rfc3339 = require("./rfc3339.js");
var httpTransport = require("./http-transport.js");
var merkle = require("./merkle.js");
var subtle = webcrypto.webcrypto.subtle;
/** @internal The two operations every signature check here runs, captured at load. The object was held
 * and its METHODS fetched per call, which leaves them replaceable: a `verify` answering true accepts a
 * signed tree head, a log list or an SCT that no log signed, and the import beside it decides which key
 * the check runs under. `path-validate` holds the same pair the same way. */
var _subtleImportKey = intrinsic.uncurry(subtle.importKey);
var _subtleVerify = intrinsic.uncurry(subtle.verify);

var CtError = frameworkError.CtError;
var PkiError = frameworkError.PkiError;
var C = constants;

function _ctErr(c, m, cause) { return new CtError(c, m, cause); }

var HASH_ALGORITHMS = intrinsic.assign(intrinsic.create(null), {
  0: "none", 1: "md5", 2: "sha1", 3: "sha224", 4: "sha256", 5: "sha384", 6: "sha512",
});
var SIGNATURE_ALGORITHMS = intrinsic.assign(intrinsic.create(null), { 0: "anonymous", 1: "rsa", 2: "dsa", 3: "ecdsa" });

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

/** @internal The response members read as integers, and so the members whose number tokens must denote
 *  exactly the integer they are read as. These are the names `_uintField` is called with: a tree size, a
 *  timestamp and a leaf index, each folded into a reconstructed binary preimage that a log signature is
 *  checked over. A spelling that rounds to a different value than it denotes verifies under the log's
 *  signature while the value handed back is not the one the log sent. */
var EXACT_INTEGER_RESPONSE_MEMBERS = intrinsic.assign(intrinsic.create(null), {
  tree_size: 1, timestamp: 1, leaf_index: 1,
});

/** @internal Every caller byte input enters through here, and it COPIES rather than views. A view stays
 *  a window onto the caller's buffer, and these verbs import a key with an await before they verify: a
 *  tree-head signature held as a view could be overwritten in that window, so the bytes verified would not
 *  be the bytes supplied. Copying at the door makes the value checked the value used, on every route. */
function _toBuffer(v, field, E, code, cap, capCode) {
  /** @internal Normalized to a byte view before it is copied. The docs for these verbs name their byte
   *  inputs `BufferSource`, and `guard.bytes.snapshot` takes a Buffer or a Uint8Array only, so the
   *  ArrayBuffer `crypto.subtle.exportKey("spki", ...)` returns, which is how a caller holding a WebCrypto
   *  key has it, was refused before the transport ran while a Buffer of identical bytes verified.
   *  `guard.bytes.source` shares the caller's store, so the copy below is still the only allocation and
   *  the copy-before-await reasoning above is unchanged.
   *
   *  The comment above said every caller byte input entered here and SEVEN sites called the narrow copy
   *  directly, each with its own error factory, so the single door was a claim rather than a fact and the
   *  normalization added here would have reached one of them. The factory and the code are parameters so
   *  those sites can route through this one and keep the refusal they already gave. */
  var cls = E === undefined ? CtError : E;
  var reason = code === undefined ? "ct/bad-input" : code;
  var viewed = guard.bytes.source(v, cls, reason, field);
  /** @internal `cap`, where a caller passes one, is measured on the VIEW. The view shares the caller's
   *  store and allocates nothing, so an input over the cap is refused before the copy below would take
   *  it. Every cap in this module used to run after that copy, so a verb refusing a 64 MiB input had
   *  already allocated 64 MiB to do it (CWE-770). The size comes off the view rather than off the
   *  caller's own `length`, which a caller can shadow independently of the bytes. */
  /** @internal `guard.bytes.*` takes the error CLASS and constructs it; `guard.limits.byteCap` takes a
   *  FACTORY and calls it. Handing the class to both throws "Class constructor cannot be invoked without
   *  new" instead of the refusal, so the factory is built from whichever class this call is using. */
  /** @internal A site passing NO cap gets the DER ceiling rather than no bound at all. Leaving it
   *  optional left most of this module's inputs copied at whatever size arrived: measured, a 32 MiB
   *  value supplied as a 32-byte tree head hash allocated 32 MiB, and one supplied as its signature
   *  allocated 64 MiB across the two reads, with the same on the chain, pinned-key, leaf-hash and
   *  issuer-hash inputs. The default means a call added later is bounded without anyone remembering to
   *  bound it, and a site that knows a narrower width still passes one. The refusal is `ct/too-large`,
   *  which is what the value is. */
  var bound = cap === undefined ? C.LIMITS.DER_MAX_BYTES : cap;
  var boundCode = cap === undefined ? "ct/too-large" : (capCode === undefined ? reason : capCode);
  guard.limits.byteCap(viewed, bound, function (c, m) { return new cls(c, m); }, boundCode, field);
  return guard.bytes.snapshot(viewed, cls, reason, field);
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
  /** @internal The raw value is bounded before it is copied, and then the peeled list is held to the
   *  exact cap as before. The two differ by the DER header `_peelInner` may strip, at most five bytes for
   *  an OCTET STRING of this size (tag, a 0x83 long-form marker and three length octets), so the outer
   *  bound carries that slack and the semantic cap below is unchanged. */
  var blob = _peelInner(_toBuffer(extValue, "the SCT-list extension value", undefined, undefined,
    C.LIMITS.SCT_MAX_BYTES + SCT_LIST_WRAPPER_SLACK, "ct/too-large"));
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
  return guard.verdict.of({ scts: scts, unknownScts: unknownScts, all: all });
}

/** @internal The DER header `_peelInner` may strip from an SCT-list extension value: an OCTET STRING
 *  tag, a long-form length marker and three length octets reach five bytes at this size. The outer bound
 *  on the raw value carries this slack so that bounding it cannot refuse a list the exact cap accepts. */
var SCT_LIST_WRAPPER_SLACK = 8;

function _u24Bytes(n) {
  if (n < 1 || n > 0xffffff) {
    throw new CtError("ct/bad-tbs-length", "a certificate / TBSCertificate length must be in 1..2^24-1, got " + n + " (RFC 6962 sec. 3.1)");
  }
  return _bufferFrom([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
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
 *   - `{ entryType: 1, tbsCertificate: <DER Buffer>, issuerKeyHash: <32B> }`,
 *     an SCT EMBEDDED in a certificate, signed over `precert_entry(1)` with the
 *     issuer key hash + the precertificate TBS (the TBS with only the SCT
 *     extension removed). `issuerKeyHash` is SHA-256 of the issuer's SPKI DER.
 *
 * The preimage reuses the parsed SCT's raw `extensions` byte-for-byte and
 * re-emits the fixed-width scalars canonically. This never verifies anything;
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
/** @internal The two log-entry arms read different fields, and a field belonging to the other arm
 *  is refused the same way a misspelled one is: a value the arm never reads cannot be in the entry. */
var _X509_ENTRY_KEYS = intrinsic.assign(intrinsic.create(null), { entryType: 1, leafCert: 1 });
var _PRECERT_ENTRY_KEYS = intrinsic.assign(intrinsic.create(null), { entryType: 1, tbsCertificate: 1, issuerKeyHash: 1 });
function reconstructSignedData(entry, sct) {
  entry = entry || {};
  if (typeof entry !== "object") throw new CtError("ct/bad-input", "the log entry must be an object { entryType, ... } (RFC 6962 sec. 3.1)");
  var entryType = entry.entryType;
  if (entryType !== 0 && entryType !== 1) {
    throw new CtError("ct/bad-entry-type", "entryType must be x509_entry(0) or precert_entry(1), got " + guard.text.showValue(entryType) + " (RFC 6962 sec. 3.1)");
  }
  guard.identifier.assertKnownKeys(entry, entryType === 0 ? _X509_ENTRY_KEYS : _PRECERT_ENTRY_KEYS, _ctErr, "ct/bad-input",
    entryType === 0 ? "unknown x509_entry field (accepted: entryType, leafCert): " : "unknown precert_entry field (accepted: entryType, tbsCertificate, issuerKeyHash): ");
  if (!sct || typeof sct.timestamp !== "bigint" || sct.version !== 0) {
    throw new CtError("ct/bad-input", "reconstructSignedData expects a decoded v1 SCT from parseSctList().scts[]");
  }
  var tsVal = guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp (RFC 6962 3.2)");
  var parts = [];
  parts.push(_bufferFrom([sct.version & 0xff]));
  parts.push(_bufferFrom([0]));
  var ts = _bufferAlloc(8); ts.writeBigUInt64BE(tsVal); parts.push(ts);
  parts.push(_bufferFrom([(entryType >> 8) & 0xff, entryType & 0xff]));
  if (entryType === 0) {
    var cert = _toBuffer(entry.leafCert, "leafCert", undefined, undefined, 0xffffff, "ct/bad-tbs-length");
    parts.push(_u24Bytes(cert.length)); parts.push(cert);
  } else {
    var ikh = _toBuffer(entry.issuerKeyHash, "issuerKeyHash");
    if (ikh.length !== 32) {
      throw new CtError("ct/bad-issuer-key-hash", "issuer_key_hash must be exactly 32 bytes (SHA-256 of the issuer SPKI), got " + ikh.length + " (RFC 6962 sec. 3.2)");
    }
    var tbs = _toBuffer(entry.tbsCertificate, "tbsCertificate", undefined, undefined, 0xffffff, "ct/bad-tbs-length");
    parts.push(ikh);
    parts.push(_u24Bytes(tbs.length)); parts.push(tbs);
  }
  var ext = _toBuffer(sct.extensions, "sct.extensions", undefined, undefined, 0xffff, "ct/bad-extensions");
  if (ext.length > 0xffff) {
    throw new CtError("ct/bad-extensions", "CtExtensions must be 0..65535 bytes, got " + ext.length + " (RFC 6962 3.2)");
  }
  parts.push(_bufferFrom([(ext.length >> 8) & 0xff, ext.length & 0xff])); parts.push(ext);
  return Buffer.concat(parts);
}

var CT_HASH = intrinsic.assign(intrinsic.create(null), { sha256: "SHA-256" });
var CT_EC_CURVE = intrinsic.create(null);
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
  if (sct === null || typeof sct !== "object") {
    throw new CtError("ct/bad-input", "the SCT must be an object from pki.ct.parseSctList or pki.ct.signSct");
  }
  /** @internal Every member of the caller's SCT is taken ONCE, and everything below reads this record. The
   *  preimage is built from some of them and the verification runs after an awaited digest, so reading a
   *  member on both sides would let the value that shaped the preimage differ from the value checked
   *  against it. One read each removes the question rather than answering it per member. */
  var rec = {
    version: sct.version, logId: sct.logId, timestamp: sct.timestamp,
    extensions: sct.extensions, signatureAlgorithm: sct.signatureAlgorithm, signature: sct.signature,
  };
  var message = reconstructSignedData(entry, rec);
  /** @internal COPIED. The logId check digests this key and awaits that digest, and the key is then read
   *  again to resolve its algorithm and to import it for the verification. Held as a view, the key whose
   *  SHA-256 matched sct.logId need not be the key the signature is checked under: a caller reusing the
   *  buffer in that window passes the logId check with one key and verifies with another, so the SCT
   *  verifies while naming a log that did not sign it. */
  var spki = _toBuffer(logPublicKey, "the CT log public key (SPKI)");
  if (rec.logId != null) {
    var keyId = Buffer.from(await subtle.digest("SHA-256", spki));
    if (!keyId.equals(_toBuffer(rec.logId, "sct.logId"))) {
      throw new CtError("ct/log-id-mismatch", "the SCT logId does not match SHA-256 of the provided log key (RFC 6962 sec. 3.2)");
    }
  }
  var sigInfo = rec.signatureAlgorithm || {};
  var hashName = CT_HASH[sigInfo.hashName];
  if (!hashName) throw new CtError("ct/unsupported-algorithm", "unsupported SCT hash algorithm " + JSON.stringify(sigInfo.hashName) + " (RFC 6962 sec. 2.1.4 mandates sha256)");
  var alg = _spkiAlg(spki);
  var imp, ver, sig = _toBuffer(rec.signature, "sct.signature");
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
    var key = await _subtleImportKey(subtle, "spki", spki, imp, false, ["verify"]);
    return await _subtleVerify(subtle, ver, key, sig, message);
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
  w.vector(2, 0, 0xffff, _toBuffer(sct.extensions, "sct.extensions", undefined, undefined, 0xffff), "ct/bad-input");
  w.u8(sct.hashAlg, "ct/bad-input");
  w.u8(sct.sigAlg, "ct/bad-input");
  w.vector(2, 0, 0xffff, _toBuffer(sct.signature, "sct.signature", undefined, undefined, 0xffff), "ct/bad-input");
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
var _SIGN_SCT_OPTS = intrinsic.assign(intrinsic.create(null), { timestamp: 1, extensions: 1, logId: 1 });
async function signSct(entry, logKey, opts) {
  opts = guard.identifier.optionsObject(opts, _ctErr, "ct/bad-input", "pki.ct.signSct options");
  guard.identifier.assertKnownKeys(opts, _SIGN_SCT_OPTS, _ctErr, "ct/bad-input", "unknown pki.ct.signSct option (accepted: timestamp, extensions, logId): ");
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
  return guard.verdict.of({
    version: 0,
    logId: logId, logIdHex: logId.toString("hex"),
    timestamp: timestamp,
    extensions: extensions,
    hashAlg: hashAlg, sigAlg: sigAlg,
    signatureAlgorithm: { hash: hashAlg, hashName: HASH_ALGORITHMS[hashAlg] || null, signature: sigAlg, signatureName: SIGNATURE_ALGORITHMS[sigAlg] || null },
    signature: signature,
  });
}


var LOG_STATE_TRUST = intrinsic.assign(intrinsic.create(null), { pending: "no", qualified: "yes", usable: "yes", readonly: "yes", retired: "conditional", rejected: "no" });

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
  return guard.verdict.of({ name: name, since: since, trusted: trust === "yes", conditional: trust === "conditional" });
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
  return guard.verdict.of({
    logId: logId, logIdHex: logId.toString("hex"), key: spki,
    description: typeof log.description === "string" ? log.description : null,
    url: typeof log.url === "string" ? log.url : (typeof log.submission_url === "string" ? log.submission_url : null),
    mmd: typeof log.mmd === "number" ? log.mmd : null,
    operator: operatorName, state: _parseLogState(log.state), temporalInterval: _parseTemporalInterval(log.temporal_interval),
    trusted: false,
  });
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
  /** @internal The named members, for the reason at the response reader: a log list carries tree sizes and
   *  state timestamps that are read as integers, and the list is signed, so a spelling that rounds to a
   *  different value than it denotes would verify under the distributor's signature while naming
   *  something else. */
  var doc = guard.json.parse(json, _ctErr, {
    maxBytes: C.LIMITS.CT_LOG_LIST_MAX_BYTES, maxDepth: C.LIMITS.JSON_MAX_DEPTH,
    exactIntegerMembers: EXACT_INTEGER_RESPONSE_MEMBERS,
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
  return guard.verdict.of({ logs: logs, byLogId: byLogId, version: version, timestamp: timestamp });
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
  if (logList == null || typeof logList !== "object" || logList.byLogId == null) return guard.verdict.of({ status: "bad-input", code: "ct/bad-input", message: "logList must be a pki.ct.parseLogList result" });
  if (sct == null || typeof sct !== "object" || typeof sct.logIdHex !== "string") return guard.verdict.of({ status: "bad-input", code: "ct/bad-input", message: "the SCT is missing its logIdHex" });
  var log = logList.byLogId[sct.logIdHex];
  if (log == null) return guard.verdict.of({ status: "not-found", code: "ct/log-not-found", message: "no trusted CT log matches the SCT's logId " + sct.logIdHex });
  if (!log.state.trusted) {
    if (!log.state.conditional) return guard.verdict.of({ status: "untrusted", log: log, code: "ct/log-untrusted", message: "the CT log state '" + log.state.name + "' is not trusted" });
    var ts = guard.range.uint64(sct.timestamp, _ctErr, "ct/bad-input", "sct.timestamp");
    if (ts >= BigInt(guard.time.instantOf(log.state.since))) return guard.verdict.of({ status: "untrusted", log: log, code: "ct/log-untrusted", message: "the CT log is retired and the SCT is not timestamped before its retirement (" + log.state.since.toISOString() + ")" });
  }
  if (log.temporalInterval) {
    var notAfter = _resolveNotAfter(entry, opts);
    if (notAfter == null) return guard.verdict.of({ status: "temporal", log: log, code: "ct/temporal-interval", message: "the windowed CT log has no resolvable covered-certificate notAfter (pass a valid opts.certNotAfter)" });
    if (!guard.time.within(notAfter, log.temporalInterval.startInclusive, log.temporalInterval.endExclusive, _ctErr, "ct/temporal-interval", "the covered certificate notAfter (pass a valid opts.certNotAfter)")) {
      return guard.verdict.of({ status: "temporal", log: log, code: "ct/temporal-interval", message: "the covered certificate's notAfter is outside the CT log's temporal_interval" });
    }
  }
  return guard.verdict.of({ status: "ok", log: log });
}

async function verifySctWithLogList(entry, sct, logList, opts) {
  opts = opts || {};
  var c = _classifyLog(sct, logList, entry, opts);
  if (c.status !== "ok") throw _ctErr(c.code, c.message);
  /** @internal Read before the verify, so the timestamp the verdict states is the one the signature covered.
   *  Read after it, a caller's record could answer the verification with one instant and the report with
   *  another, and the verdict would name a time nothing signed. */
  var reportedTimestamp = sct.timestamp;
  var valid = await verifySct(entry, sct, c.log.key);
  return guard.verdict.of({
    valid: valid,
    logId: c.log.logId,
    logIdHex: c.log.logIdHex,
    operator: c.log.operator,
    logState: c.log.state.name,
    timestamp: reportedTimestamp,
  });
}

var _VERIFY_SCT_LIST_OPTS = intrinsic.assign(intrinsic.create(null), { minScts: 1, minOperators: 1, certNotAfter: 1, at: 1 });

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
    /** @internal The row is a per-SCT verdict a caller reads `valid` off, so it carries the sentinel
     *  from the moment it exists rather than at each of the five places it is appended. */
    var row = guard.verdict.of({ logIdHex: (sct && typeof sct.logIdHex === "string") ? sct.logIdHex : null, valid: false,
      operator: null, logState: null,
      timestamp: (sct && typeof sct.timestamp === "bigint") ? sct.timestamp : null, code: undefined, reason: undefined });
    var c;
    try { c = _classifyLog(sct, logList, entry, opts); }
    catch (e) {
      if (!(e && e.isPkiError)) throw e;
      row.code = e.code; row.reason = e.message; guard.list.append(results, row); continue;
    }
    if (c.log) { row.operator = c.log.operator; row.logState = c.log.state.name; }
    if (c.status !== "ok") { row.code = c.code; row.reason = c.message; guard.list.append(results, row); continue; }
    var ok;
    try { ok = await verifySct(entry, sct, c.log.key); }
    catch (e) {
      if (!(e && e.isPkiError)) throw e;
      row.code = e.code; row.reason = e.message; guard.list.append(results, row); continue;
    }
    if (ok === true && atMs != null && sct.timestamp > atMs) {
      row.code = "ct/future-timestamp"; row.reason = "the SCT timestamp is later than the validation time (RFC 6962 sec. 5.2)";
      guard.list.append(results, row); continue;
    }
    row.valid = ok === true;
    if (row.valid && !seenLogs[sct.logIdHex]) {
      seenLogs[sct.logIdHex] = true;
      validScts++;
      if (c.log.operator != null && !seenOps[c.log.operator]) { seenOps[c.log.operator] = true; guard.list.append(operators, c.log.operator); }
    }
    guard.list.append(results, row);
  }
  var operatorCount = operators.length;
  var policyOk = validScts >= minScts && operatorCount >= minOperators;
  return guard.verdict.of({
    valid: policyOk,
    policyOk: policyOk, totalScts: scts.length + unknownScts, validScts: validScts, unknownScts: unknownScts,
    operatorCount: operatorCount, operators: operators, required: { minScts: minScts, minOperators: minOperators },
    results: results,
    reason: policyOk ? null : ("CT policy not met: " + validScts + " valid SCT(s) from " + operatorCount + " distinct operator(s); require at least " + minScts + " SCT(s) from at least " + minOperators + " operator(s)"),
  });
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
    /** @internal A VIEW rather than a copy, as the parsed-certificate branch below also returns, and the
     *  wide guard so the whole BufferSource set this module documents is read. The narrow one took a
     *  Buffer or a Uint8Array only, so an issuer named by a DataView or by the ArrayBuffer a WebCrypto
     *  export returns was refused with `ct/bad-cert-entry`, blaming the certificate for the container its
     *  key arrived in; the issuerKeyHash binds the entry to its issuer, so one key has to give one hash
     *  however it is held. */
    return guard.bytes.source(v.subjectPublicKeyInfo.bytes, CtError, "ct/bad-cert-entry",
      field + " subjectPublicKeyInfo.bytes");
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
  /** @internal Both arms are bounded before they allocate. A string is measured with
   *  `Buffer.byteLength`, which computes the UTF-8 size without encoding it, so a string over the cap is
   *  refused before `Buffer.from` would take it; its character count would not do, a character reaching
   *  four bytes. The byte arm caps the view inside `_toBuffer`, before its copy. */
  var message;
  if (typeof json === "string") {
    var jsonBytes = _byteLength(json);
    if (jsonBytes > C.LIMITS.CT_LOG_LIST_MAX_BYTES) {
      throw _ctErr("ct/too-large", "the CT log list is " + jsonBytes + " bytes, over the " +
        C.LIMITS.CT_LOG_LIST_MAX_BYTES + "-byte cap");
    }
    message = _bufferFrom(json, "utf8");
  } else {
    message = _toBuffer(json, "the CT log list JSON", undefined, undefined,
      C.LIMITS.CT_LOG_LIST_MAX_BYTES, "ct/too-large");
  }
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
    var key = await _subtleImportKey(subtle, "spki", spki, imp, false, ["verify"]);
    return await _subtleVerify(subtle, ver, key, sig, message);
  } catch (e) {
    throw new CtError("ct/verify-error", "the CT log-list signature could not be evaluated", e);
  }
}


var DEFAULT_FETCH_TIMEOUT = C.TIME.seconds(30);
var MAX_FETCH_TIMEOUT = C.TIME.seconds(600);
var KNOWN_FETCH_OPTS = intrinsic.assign(intrinsic.create(null), { url: 1, signerKey: 1, sigUrl: 1, transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, requireJsonContentType: 1 });

/** @internal The TLS settings flattened into a record of plain values, with the anchor LIST copied.
 *  `opts.tls` is the caller's object and its members are read later than the trust-anchor check that
 *  approves them, so leaving either shared let a getter elsewhere in the bag empty the pinned anchors
 *  and rewrite the servername after the check had passed: the anchors checked were then not the anchors
 *  the connection used. Copying the list is what closes that, since emptying an array the caller still
 *  holds is the lever. Flatten once, check that record, and connect under the same one. */
/** @internal One piece of trust material, copied rather than referenced. An anchor, a client
 *  certificate and a client key are each a Buffer the caller still holds, and copying the list that
 *  holds them copies the references in it: a header getter that wrote an attacker's PEM OVER an
 *  anchor's bytes left every reference pointing where it did and still opened the connection under
 *  trust material the unpinned-log check had already approved, MEASURED on this module. A PEM string
 *  cannot be changed after the fact and is taken as it is; anything that is neither is handed on
 *  unchanged, so the transport keeps giving the refusal it gives today for a shape it does not
 *  accept. */
function _trustValue(v, field) {
  if (typeof v === "string") return v;
  if (guard.bytes.isByteSource(v)) return _toBuffer(v, field, _ctErr, "ct/bad-input");
  return v;
}

function _tlsForFetch(opts) {
  /** @internal A record with NO prototype where the caller supplied no TLS at all, because the empty
   *  object a literal gives inherits from `Object.prototype` and every field below is then answerable
   *  from there. MEASURED: a getter inside `opts.sth` set `Object.prototype.useSystemStore = true`, the
   *  record built here inherited it, and the refusal that turns away an unpinned log was skipped, so a
   *  call that had named neither a transport nor an anchor opened a connection trusting the system
   *  store. Where the caller DID supply a TLS record this is settled at the door and the record read
   *  here is the flat one taken then, whose seven fields are its own. */
  var t = opts.tls != null ? opts.tls : intrinsic.create(null);
  var anchors = t.anchors;
  /** @internal Copied by index rather than with `slice`, which consults the array's species and so
   *  would run a caller's constructor. `guard.list.copyMap` walks it with a narrowed count and copies
   *  each element's bytes as it goes. */
  anchors = intrinsic.isArray(anchors)
    ? guard.list.copyMap(anchors, function (a, i) { return _trustValue(a, "opts.tls.anchors[" + i + "]"); })
    : _trustValue(anchors, "opts.tls.anchors");
  return { anchors: anchors, useSystemStore: t.useSystemStore, cert: _trustValue(t.cert, "opts.tls.cert"),
    key: _trustValue(t.key, "opts.tls.key"), minVersion: t.minVersion, servername: t.servername,
    checkServerIdentity: t.checkServerIdentity };
}

function _sameOrigin(a, b) { return _urlOrigin(new _URL(a)) === _urlOrigin(new _URL(b)); }

/** @internal Refused at the door and again where the value is used. */
function _assertTransport(opts) {
  return guard.identifier.assertCallableOption(opts, "transport", _ctErr, "ct/bad-input", "opts.transport",
    "(request) => Promise<{ status, headers, body }>");
}

function _fetchCtypeToken(headers) { return String((headers || {})["content-type"] || "").split(";")[0].trim().toLowerCase(); }

function _parseHttpsUrl(u, label) {
  var parsed;
  var text = _stringOf(u);
  try { parsed = new _URL(text); }
  catch (e) { throw _ctErr("ct/bad-url", "the CT log-list " + label + " did not parse: " + text, e); }
  var scheme = _urlProtocol(parsed);
  if (scheme !== "https:") throw _ctErr("ct/insecure-url", "the CT log-list " + label + " must be https, got " + scheme + " for " + text);
  return parsed;
}

function _sigUrlFor(parsed) {
  var path = _urlPathname(parsed);
  if (!_endsWithJson(path)) throw _ctErr("ct/bad-input", "cannot derive the detached-signature URL from a non-.json path (" + JSON.stringify(path) + "); pass opts.sigUrl explicitly");
  var sig = new _URL(_urlHref(parsed));
  _urlSetPathname(sig, _strSlice(path, 0, path.length - _JSON_SUFFIX.length) + ".sig");
  return _urlHref(sig);
}

function _fetchBody(transport, url, req, label) {
  return _promiseResolve(_Promise, undefined).then(function () {
    var request = { method: req.method || "GET", url: url, headers: req.headers, tls: req.tls,
      timeout: req.timeout, maxResponseBytes: req.maxResponseBytes };
    if (req.body !== undefined) request.body = req.body;
    return transport(request);
  }).then(function (res) {
    res = res || {};
    var h = intrinsic.create(null);
    guard.identifier.optionNames(res.headers).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
    var body = guard.bytes.isByteSource(res.body)
      ? guard.bytes.source(res.body, CtError, "ct/bad-input", label)
      : Buffer.from(String(res.body == null ? "" : res.body), "utf8");
    if (body.length > req.maxResponseBytes) throw _ctErr("ct/response-too-large", "the " + label + " (" + body.length + " bytes) exceeds the " + req.maxResponseBytes + "-byte cap");
    if (res.status !== 200) throw _ctErr("ct/http-error", "the CT server returned HTTP " + JSON.stringify(res.status) + " for the " + label);
    if (body.length === 0) throw _ctErr("ct/empty-response", "the CT server returned a 200 with an empty " + label);
    return guard.verdict.of({ body: body, status: res.status, contentType: _fetchCtypeToken(h), tls: res.tls || null });
  }).catch(function (e) {
    if (e instanceof PkiError) throw e;
    throw _ctErr("ct/transport-error", "the CT " + label + " request failed in the transport", e);
  });
}

/** @internal RFC 6962 sec. 3.5 fixes the TreeHeadSignature preimage at these 50 bytes: the version,
 *  the signature type, the timestamp and tree size as big-endian uint64s, then the 32-byte root.
 *  `v1(0)` and `tree_hash(1)` are the sec. 3.2 enum values. */
var STH_PREIMAGE_BYTES = 50;
var CT_VERSION_V1 = 0;
var SIG_TYPE_TREE_HASH = 1;
var CT_V1_PREFIX = "ct/v1/";
/** @internal The union across the sec. 4 messages rather than one set per message, because a caller
 *  drives several of them from a single options bag: the same record carries the pinned key for the
 *  tree head and the range for the entries. An option a message does not read is ignored by it, so the
 *  refusal this list makes is of a name no message knows. */
var KNOWN_CLIENT_OPTS = intrinsic.assign(intrinsic.create(null), {
  url: 1, logKey: 1, transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1,
  sth: 1, oldSth: 1, newSth: 1, leafHash: 1, start: 1, end: 1, chain: 1,
  tbsCertificate: 1, issuerKeyHash: 1,
});

/** @internal The endpoint URL for one of the sec. 4 messages. A caller may pin the log's base URL
 *  with or without the `ct/v1/` prefix the specification fixes, and neither spelling doubles it. */
function _endpoint(url, message) {
  var parsed = _parseHttpsUrl(url, "log URL");
  var path = _urlPathname(parsed);
  if (path.length === 0 || path[path.length - 1] !== "/") path += "/";
  var tail = CT_V1_PREFIX;
  if (path.length >= CT_V1_PREFIX.length + 1 &&
      _strSlice(path, path.length - CT_V1_PREFIX.length) === CT_V1_PREFIX) tail = "";
  var out = new _URL(_urlHref(parsed));
  _urlSetPathname(out, path + tail + message);
  _urlSetSearch(out, "");
  return out;
}

/** @internal The door every sec. 4 message enters by: the declared options refused if one is not
 *  recognized, then taken ONCE into a plain record. A caller's bag is the caller's, so an option
 *  reached through an accessor answers each read separately, and this code read several of them twice:
 *  `url` for a presence check and again to build the endpoint, which let the check approve one host
 *  while the request went to another; `tls` for the anchor check and again for the connection, which
 *  would be a pin approved on one object and a socket opened under another. Reading from the record
 *  afterwards means the value that was checked is the value that is used. Every verb calls this at its
 *  own entry and passes the record down, rather than relying on a check further in. */
/** @internal `keyName` is the option this message VERIFIES against, or null for one that verifies
 *  nothing. The option list is the union across the messages so that one bag drives several of them,
 *  and an option a message does not read is ignored by it; settling the pinned key at every door
 *  instead would make a message that never checks a signature refuse a bag over a field it does not
 *  consume. `getSth` and the two chain submissions name it; the proof, consistency, entries and roots
 *  messages pass null. */
function _clientDoor(opts, keyName) {
  /** @internal `optionsObject` is the door `signSct` in this module already enters by, and it REFUSES
   *  an options bag carrying an accessor rather than tolerating one: a bag whose properties are not
   *  plain values is a shape no set of checks can answer for, and it also refuses one that changes
   *  which options it carries while they are read. Refusing beats copying, because a copy leaves the
   *  caller's shape acceptable and every future read in this module has to remember to use the copy.
   *  It also leaves ABSENCE intact, which materializing the declared names would not: an absent
   *  `transport` means "open the connection yourself, under the pinned anchors", while one present
   *  holding `undefined` is a transport that is not callable. */
  var bag = guard.identifier.optionsObject(opts, _ctErr, "ct/bad-input", "pki.ct client options");
  guard.identifier.assertKnownKeys(bag, KNOWN_CLIENT_OPTS, _ctErr, "ct/bad-input", "unknown opts field ");
  /** @internal The bag is returned as it came, not copied. A copy cannot reproduce what reading it
   *  does: an option supplied through a caller's defaults object is reached along the prototype chain,
   *  and the enumeration that would drive a copy deliberately omits an inherited FUNCTION member,
   *  because that is how `Object.prototype.toString` is kept from counting as an option. Copying
   *  therefore dropped an inherited `transport`, and dropping a transport is not a smaller result: it
   *  falls through to opening a real connection where the caller passed a fake one. What makes the
   *  repeated reads safe instead is that this door refuses a bag whose properties are not plain values,
   *  and that each option below is taken into a local ONCE, before anything that could run caller code.
   *  EVERY DECLARED OPTION IS TAKEN HERE, and the ones a verdict rests on are made immune, but the
   *  request is NOT shaped here. Shaping it here was tried and is wrong: copying the request headers
   *  runs whatever getters the caller's header object carries, and doing that before a verb reads its
   *  own options put every verification input at the mercy of one. A header getter swapped `logKey` for
   *  an attacker's SPKI, then overwrote the same buffer in place once the reference was held, then
   *  overwrote `sth.rootHash` so an empty audit proof verified. Each was worse than the wrong-host case
   *  the move was meant to close. The verb's inputs are the more valuable thing, so the headers are
   *  copied at send time as they always were, and the destination is protected by making it immune
   *  instead: a string url cannot be rewritten, and a flattened tls with its anchor list copied cannot
   *  be emptied. Taking the top level is safe because the door has already refused a bag whose
   *  properties are not plain values, so no read here runs caller code. */
  return { o: _settleDecisive(_takeTopLevel(bag, KNOWN_CLIENT_OPTS), keyName) };
}

/** @internal Every DECLARED option the bag can answer, read once into a record of plain values, before
 *  anything derives from one. The presence-preserving snapshot is the one this module needs: absence
 *  survives, so a name the bag cannot answer is left out rather than materialized as `undefined`,
 *  which is what lets an absent `transport` still mean "open the connection yourself, under the
 *  pinned anchors". It consults the prototype chain exactly as the direct reads it replaces did,
 *  because the door accepts an option supplied through a caller's defaults object and an enumeration
 *  omits an inherited FUNCTION member, which silently dropped a `transport` and fell through to
 *  opening a real connection. */
// @guard-via guard.identifier.snapshotPresentOptions
function _takeTopLevel(bag, known) {
  return guard.identifier.snapshotPresentOptions(bag, known);
}

/** @internal The two values a verdict rests on, made IMMUNE rather than merely taken. Holding a
 *  reference is not holding a value: a header getter copied an attacker's SPKI OVER the caller's
 *  `logKey` buffer in place and an attacker-signed tree head was accepted, and a getter inside `tls`
 *  rewrote an object-valued url's `hostname` and the request went to another host. Both happened after
 *  the option had been taken, because what was taken could still be changed from outside. A string and
 *  a copied buffer cannot be, so the destination and the pin stop depending on what the caller does
 *  next. Done here, before anything nested is read, for the same reason the taking is. */
function _settleDecisive(o, keyName) {
  /** @internal There is no order that fixes this by itself, which is what two rounds of reordering
   *  showed: converting the url asks an object for its text and that runs the caller's code, which
   *  emptied the anchor list not yet flattened; flattening the anchors first reads `tls.anchors` and
   *  that runs the caller's code too, which rewrote the url not yet converted. So the caller's code is
   *  refused HERE instead of ordered around. A url has to be a string, which needs no conversion, and
   *  a tls carries no accessor, which makes reading its members inert. After that nothing in settling
   *  runs caller code and the order stops mattering. */
  if (o.url != null && typeof o.url !== "string") {
    throw _ctErr("ct/bad-input", "opts.url must be a string -- an object is asked for its text form, " +
      "and asking runs the caller's code, which is how a request reached a host its URL had not named");
  }
  /** @internal The detached-signature URL is a destination too, and only the log-list fetch declares
   *  it, so the rule is the same one: a value that has to be converted is a value whose conversion
   *  runs here, after everything else has been settled, where it could still rewrite what was. */
  if (o.sigUrl != null && typeof o.sigUrl !== "string") {
    throw _ctErr("ct/bad-input", "opts.sigUrl must be a string -- an object is asked for its text " +
      "form, and asking runs the caller's code after the other options have been settled");
  }
  if (o.tls != null) {
    guard.identifier.refuseAccessorFields(o.tls,
      guard.identifier.readableNames(o.tls, _ctErr, "ct/bad-input", "opts.tls"),
      _ctErr, "ct/bad-input", "opts.tls");
    /** @internal And the ELEMENTS of the anchor list, which refusing accessors on `tls` itself does not
     *  reach. An accessor on `anchors[0]` runs when the list is copied, and one that overwrote
     *  `sth.rootHash` with the leaf being proven had an empty audit path verify. The refusal has to go
     *  as deep as the reading does. */
    var suppliedAnchors = o.tls.anchors;
    if (suppliedAnchors != null) {
      guard.identifier.refuseAccessorFields(suppliedAnchors,
        guard.identifier.readableIndices(suppliedAnchors, _ctErr, "ct/bad-input", "opts.tls.anchors"),
        _ctErr, "ct/bad-input", "opts.tls.anchors");
    }
    /** @internal Flattened HERE, with the anchor list copied, because the caller still holds the object
     *  and a getter anywhere else in the bag emptied the list after the trust-anchor check approved it.
     *  Reading its members and its elements is inert now that both refuse an accessor, so this runs no
     *  caller code and the order it runs in stops mattering. */
    o.tls = _tlsForFetch(o);
  }
  if (keyName !== null && o[keyName] != null) {
    o[keyName] = _toBuffer(o[keyName], "opts." + keyName, _ctErr, "ct/bad-input");
  }
  return o;
}

/** @internal The shared request shape every message uses: the caller's transport or a pinned-anchor
 *  one, the caps, and the header filter. Factored so a verb adds a path and a body and nothing else,
 *  and so a rule about reaching a log is stated once. `o` has already been through `_clientDoor`, so
 *  every read here is of a plain value. */
function _clientRequest(o) {
  var transport = _assertTransport(o);
  /** @internal ONE read, and the presence check and the endpoint both decide from it. Read again after
   *  the header copy below, which runs whatever getters the caller's header object carries, it was
   *  whatever that code had since made it: a getter on a header name rewrote `url` and moved the request
   *  to another host after this check had approved the original.
   *  AND CONVERTED HERE, not at the endpoint. Holding the value alone is not enough when it is an
   *  object, because the text form is what names the host and `String()` asks the object for it: a
   *  header getter that rewrote an object-valued url's `href` moved the request just the same, the
   *  conversion being the last reader. The endpoint is built from this string. */
  if (o.url == null) throw _ctErr("ct/bad-input", "opts.url is required -- the log's base URL (there is no baked-in log)");
  var url = _stringOf(o.url);
  /** @internal Flattened BEFORE the header copy below, which invokes whatever getters the caller's
   *  header object carries. One of those emptied the pinned anchors after this check had approved them,
   *  so the check and the connection have to read the same flat record and it has to exist first. */
  var tls = _tlsForFetch(o);
  if (!transport) {
    var hasAnchors = tls.anchors !== undefined && tls.anchors !== null && !(intrinsic.isArray(tls.anchors) && tls.anchors.length === 0);
    if (!hasAnchors && tls.useSystemStore !== true) {
      throw _ctErr("ct/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true -- refusing an unpinned CT log server (RFC 6962 sec. 3.2)");
    }
    transport = httpTransport.https({ E: _ctErr, errPrefix: "ct" });
  }
  var timeout = guard.limits.cap(o.timeout, "timeout", DEFAULT_FETCH_TIMEOUT, { E: _ctErr, code: "ct/bad-input", min: 1, max: MAX_FETCH_TIMEOUT });
  var maxResponseBytes = guard.limits.cap(o.maxResponseBytes, "maxResponseBytes", C.LIMITS.CT_LOG_LIST_MAX_BYTES, { E: _ctErr, code: "ct/bad-input", min: 1, max: C.LIMITS.CT_LOG_LIST_MAX_BYTES });
  var headers = intrinsic.create(null);
  var supplied = o.headers;
  intrinsic.forEach(guard.identifier.optionNames(supplied), function (k) {
    var lk = _toLowerCase(k);
    if (lk !== "content-length" && lk !== "transfer-encoding") headers[k] = supplied[k];
  });
  return { transport: transport, url: url, req: { headers: headers, tls: tls, timeout: timeout,
    maxResponseBytes: maxResponseBytes } };
}

/** @internal A sec. 4 message, fetched and read as JSON. The specification returns every error as a
 *  4xx or 5xx with a human-readable message, which `_fetchBody` already turns into a typed refusal,
 *  so a non-200 never reaches the reader. */
async function _clientJson(door, message, label, query, body) {
  /** @internal Shaped at send time, from the record the door settled. Shaping it at the door instead
   *  ran the caller's header getters before any verb had captured its verification inputs. */
  var ctx = _clientRequest(door.o);
  var url = _endpoint(ctx.url, message);
  if (query) intrinsic.keys(query).forEach(function (k) { _searchSet(_urlSearchParams(url), k, query[k]); });
  var req = ctx.req;
  if (body !== undefined) {
    req = intrinsic.assign(intrinsic.create(null), req);
    req.method = "POST";
    req.body = body;
    var h = intrinsic.create(null);
    intrinsic.keys(req.headers).forEach(function (k) { h[k] = req.headers[k]; });
    h["content-type"] = "application/json";
    req.headers = h;
  }
  var res = await _fetchBody(ctx.transport, _urlHref(url), req, label);
  /** @internal The exact-integer rule applies to the NAMED members, the ones `_uintField` reads. RFC 6962
   *  responses are ordinary JSON, where `1e3` is legal, so the stricter `integersOnly` would refuse a
   *  document a conforming log may emit; what this refuses is a spelling whose value is not exactly its
   *  own integer. `1.0000000000000001` converts to the Number 1, so `_uintField` cannot be asked about it
   *  afterwards, and a tree size or timestamp read that way is folded into the reconstructed binary
   *  preimage a signature is checked over: the rounded spelling verifies, and the value the caller is
   *  handed is not the one the log sent.
   *
   *  Named rather than applied document-wide even though RFC 6962 closes every schema here, because a
   *  rule over every number is a bet that no field anywhere in the format is fractional, and that bet
   *  reads as safe right up until a field nobody thought about. Naming the members that need it says what
   *  is actually meant and cannot be wrong about the rest. */
  var parsed = guard.json.parse(res.body, _ctErr, {
    maxBytes: req.maxResponseBytes, maxDepth: C.LIMITS.JSON_MAX_DEPTH,
    exactIntegerMembers: EXACT_INTEGER_RESPONSE_MEMBERS,
    badJson: "ct/bad-json", tooDeep: "ct/too-deep", duplicateMember: "ct/duplicate-member",
    tooLarge: "ct/too-large", badInput: "ct/bad-input", label: "the " + label + " response",
  });
  if (!parsed || typeof parsed !== "object" || intrinsic.isArray(parsed)) {
    throw _ctErr("ct/bad-json", "the " + label + " is not a JSON object");
  }
  return parsed;
}

/** @internal A base64 field, decoded and held to a byte length where the specification fixes one. */
function _b64Field(obj, name, code, label, exactLen) {
  var v = obj[name];
  if (typeof v !== "string") throw _ctErr(code, "the " + label + " field " + name + " is not a base64 string");
  var buf = guard.encoding.base64(v, C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, code, name);
  if (exactLen !== undefined && buf.length !== exactLen) {
    throw _ctErr(code, "the " + label + " field " + name + " is " + buf.length + " bytes, expected " + exactLen);
  }
  return buf;
}

/** @internal A non-negative integer field the specification states in decimal. */
function _uintField(obj, name, code, label) {
  var v = obj[name];
  if (typeof v !== "number" || !intrinsic.isSafeInteger(v) || v < 0) {
    if (typeof v !== "string") {
      throw _ctErr(code, "the " + label + " field " + name + " is not a non-negative integer");
    }
    return guard.range.decimalUint64(v, _ctErr, code, "the " + label + " field " + name);
  }
  return intrinsic.BigInt(v);
}

/**
 * @primitive  pki.ct.sthSignedData
 * @signature  pki.ct.sthSignedData(sth) -> Buffer
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.verifySth, pki.ct.getSth
 *
 * The 50 bytes a log signs to produce a signed tree head, which RFC 6962 sec. 3.5 fixes as the
 * `TreeHeadSignature` structure: the version, the signature type `tree_hash`, the timestamp and the
 * tree size as big-endian uint64s, then the 32-byte root hash. Given as a verb so a caller holding an
 * STH from anywhere can check it without a fetch.
 *
 * @opts
 *   timestamp:  number | bigint,  // the log's timestamp, milliseconds since the epoch
 *   treeSize:   number | bigint,  // the number of entries the head commits to
 *   rootHash:   Buffer,           // the 32-byte Merkle tree head
 *
 * @example
 *   pki.ct.sthSignedData({ timestamp: 1800000000000, treeSize: 3,
 *     rootHash: pki.merkle.emptyRootHash() }).length;   // -> 50
 */
/** @internal Two of these five are here so that what `pki.ct.getSth` RETURNS is what this verb TAKES. A
 *  client that fetches a tree head and then wants the bytes the log signed has to be able to hand one
 *  verb's result to the other, and both fields the fetch adds were refused as unknown:
 *
 *  - `raw` is the log's own JSON document, which getSth hands back beside the decoded fields.
 *  - `then` is the sentinel `guard.verdict.of` defines on every verdict, own and non-enumerable, so that
 *    resolving one cannot run an inherited accessor. `guard.identifier.assertKnownKeys` reads own
 *    non-enumerable names deliberately, so it sees it.
 *
 *  Neither reaches the preimage, which is built from the timestamp, the tree size and the root hash. The
 *  allowlist still catches what it is for: a caller's misspelling of one of those three. */
var _STH_KEYS = intrinsic.assign(intrinsic.create(null),
  { timestamp: 1, treeSize: 1, rootHash: 1, signature: 1, raw: 1, then: 1 });
function sthSignedData(sth) {
  sth = sth || {};
  guard.identifier.assertKnownKeys(sth, _STH_KEYS, _ctErr, "ct/bad-input", "unknown sth field ");
  var ts = guard.range.uint64(sth.timestamp, _ctErr, "ct/bad-input", "sth.timestamp");
  var size = guard.range.uint64(sth.treeSize, _ctErr, "ct/bad-input", "sth.treeSize");
  var root = _toBuffer(sth.rootHash, "sth.rootHash");
  if (root.length !== 32) {
    throw _ctErr("ct/bad-input", "sth.rootHash must be exactly 32 bytes (SHA-256), got " + root.length);
  }
  var out = _bufferAlloc(STH_PREIMAGE_BYTES);
  out[0] = CT_VERSION_V1;
  out[1] = SIG_TYPE_TREE_HASH;
  _writeU64BE(out, ts, 2);
  _writeU64BE(out, size, 10);
  _bufCopy(root, out, 18);
  return out;
}

/**
 * @primitive  pki.ct.verifySth
 * @signature  pki.ct.verifySth(sth, logKey) -> Promise<boolean>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.sthSignedData, pki.ct.getSth
 *
 * Verify a signed tree head's `tree_head_signature` over the `sthSignedData` preimage under a log's
 * SubjectPublicKeyInfo. Resolves `true` or `false`: whether a given key signed a given head is a
 * verdict about the head, not a fault in it. A malformed input throws.
 *
 * `sth.signature` is the `digitally-signed` structure the log returns, hash and signature algorithm
 * bytes included, which is what `pki.ct.verifySct` also takes.
 *
 * @example
 *   var pair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var logSpki = await pki.key.export(pair.publicKey);
 *   var head = { timestamp: 1800000000000, treeSize: 1, rootHash: pki.merkle.emptyRootHash() };
 *   var raw = Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
 *     pair.privateKey, pki.ct.sthSignedData(head)));
 *   var der = pki.asn1.build.sequence([
 *     pki.asn1.build.integer(BigInt("0x" + raw.subarray(0, 32).toString("hex"))),
 *     pki.asn1.build.integer(BigInt("0x" + raw.subarray(32).toString("hex")))]);
 *   head.signature = Buffer.concat([Buffer.from([4, 3, (der.length >> 8) & 0xff, der.length & 0xff]), der]);
 *   await pki.ct.verifySth(head, logSpki);
 *   // -> true
 */
async function verifySth(sth, logKey) {
  sth = sth || {};
  var signature = _toBuffer(sth.signature, "sth.signature");
  var signedData = sthSignedData({ timestamp: sth.timestamp, treeSize: sth.treeSize, rootHash: sth.rootHash });
  return await _verifyDigitallySigned(signedData, signature, logKey, "the signed tree head");
}

/**
 * @primitive  pki.ct.getSth
 * @signature  pki.ct.getSth(opts) -> Promise<{ treeSize, timestamp, rootHash, signature, raw }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @defends    signature-bypass (CWE-347)
 * @related    pki.ct.verifySth, pki.ct.getProofByHash, pki.merkle.verifyInclusion
 *
 * Fetch a log's latest signed tree head (RFC 6962 sec. 4.3) and verify it under the key
 * `opts.logKey` pins. An STH whose signature does not verify is `ct/sth-untrusted` and no field of it
 * is returned: a tree head nobody vouched for is not a tree head, and everything a client does next
 * is measured against its root.
 *
 * `opts.logKey` is required. There is no unverified mode and no baked-in key.
 *
 * `treeSize` and `timestamp` come back as `BigInt`, since both are uint64 on the wire.
 *
 * @opts
 *   url:              string,    // the log's base URL, with or without the ct/v1/ prefix
 *   logKey:           BufferSource, // the log's SubjectPublicKeyInfo, pinned by the caller
 *   transport:        function,  // optional (request) => Promise<{ status, headers, body }>
 *   tls:              object,    // optional { anchors, useSystemStore, ... } when no transport is given
 *   headers:          object,    // optional extra request headers
 *   timeout:          number,    // optional per-request timeout in milliseconds
 *   maxResponseBytes: number,    // optional response cap
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   var sth = await pki.ct.getSth({ url: base, logKey: spki, transport: t });
 *   sth.treeSize;   // -> 3n
 */
async function getSth(opts) {
  var door = _clientDoor(opts || {}, "logKey");
  opts = door.o;
  /** @internal ONE read of the option, and the presence check and the copy both decide from it. Reading
   *  it twice let an accessor answer the two separately: a non-null value for the check and an
   *  attacker's SPKI for the copy, and the tree head was then verified against a key the caller never
   *  pinned. The key is COPIED at the call, before the request goes out. Read after the fetch instead,
   *  it is whatever the caller's buffer holds by then: a caller reusing that buffer has the tree head
   *  checked against a key it never pinned, so the log that answered need not be the log it asked. */
  var suppliedLogKey = opts.logKey;
  if (suppliedLogKey == null) {
    throw _ctErr("ct/bad-input", "opts.logKey is required -- the caller-pinned log SPKI; an unverified tree head is not a result");
  }
  var pinnedKey = _toBuffer(suppliedLogKey, "opts.logKey", _ctErr, "ct/bad-input");
  var doc = await _clientJson(door,"get-sth", "sth");
  var sth = {
    treeSize: _uintField(doc, "tree_size", "ct/bad-sth", "sth"),
    timestamp: _uintField(doc, "timestamp", "ct/bad-sth", "sth"),
    rootHash: _b64Field(doc, "sha256_root_hash", "ct/bad-sth", "sth", 32),
    signature: _b64Field(doc, "tree_head_signature", "ct/bad-sth", "sth"),
  };
  var ok = await verifySth(sth, pinnedKey);
  if (ok !== true) {
    throw _ctErr("ct/sth-untrusted", "the signed tree head did not verify under the pinned log key -- " +
      "its tree size, timestamp and root are not attested and were not returned");
  }
  sth.raw = doc;
  return guard.verdict.of(sth);
}

/**
 * @primitive  pki.ct.getProofByHash
 * @signature  pki.ct.getProofByHash(opts) -> Promise<{ leafIndex, auditPath, verified }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.getSth, pki.merkle.verifyInclusion
 *
 * Fetch the Merkle audit proof for a leaf hash (RFC 6962 sec. 4.5) and fold it to the root of the
 * tree head it was requested at. `opts.sth` is a VERIFIED head, from `pki.ct.getSth`: the tree size
 * the query needs comes from it, so a size and a head cannot disagree, and its root is what the proof
 * is folded against. A proof that does not fold, or that does not support the leaf index the log
 * states, is `ct/proof-mismatch`.
 *
 * @opts
 *   url:      string,       // the log's base URL
 *   leafHash: BufferSource, // the 32-byte v1 leaf hash to prove
 *   sth:      object,       // a verified { treeSize, rootHash } from pki.ct.getSth
 *   transport, tls, headers, timeout, maxResponseBytes  // as pki.ct.getSth takes them
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   // requires: lh -- a v1 leaf hash, from pki.ct.getEntries or a certificate you hold
 *   // requires: sth -- a verified tree head from pki.ct.getSth
 *   var p = await pki.ct.getProofByHash({ url: base, leafHash: lh, sth: sth, transport: t });
 *   p.verified;   // -> true
 */
async function getProofByHash(opts) {
  var door = _clientDoor(opts || {}, null);
  opts = door.o;
  var sth = _assertSth(opts.sth, "opts.sth");
  /** @internal Copied for the reason the tree head is: it is sent on the wire and then folded against the
   *  head after the fetch returns, so a view would let the leaf being proved differ from the leaf asked
   *  about. */
  var leafHash = _toBuffer(opts.leafHash, "opts.leafHash", _ctErr, "ct/bad-input");
  if (leafHash.length !== 32) {
    throw _ctErr("ct/bad-input", "opts.leafHash must be exactly 32 bytes (a v1 leaf hash), got " + leafHash.length);
  }
  var doc = await _clientJson(door,"get-proof-by-hash", "audit proof", {
    hash: _bufToString(leafHash, "base64"), tree_size: _stringOf(sth.treeSize),
  });
  var leafIndex = _uintField(doc, "leaf_index", "ct/bad-proof", "audit proof");
  var auditPath = _b64Array(doc, "audit_path", "ct/bad-proof", "audit proof", 32, C.LIMITS.MERKLE_MAX_PROOF_NODES);
  var folded = merkle.verifyInclusion({
    leafIndex: leafIndex, treeSize: sth.treeSize, leafHash: leafHash,
    proof: auditPath, rootHash: sth.rootHash,
  });
  if (folded !== true) {
    throw _ctErr("ct/proof-mismatch", "the audit proof the log served does not fold this leaf to the " +
      "root of the tree head it was requested at");
  }
  return guard.verdict.of({ leafIndex: leafIndex, auditPath: auditPath, verified: true });
}

/**
 * @primitive  pki.ct.getSthConsistency
 * @signature  pki.ct.getSthConsistency(opts) -> Promise<{ consistency, verified }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.getSth, pki.merkle.verifyConsistency
 *
 * Fetch the Merkle consistency proof between two tree heads (RFC 6962 sec. 4.4) and check that the
 * older is a prefix of the newer. Both `opts.oldSth` and `opts.newSth` are VERIFIED heads, so the two
 * sizes the query needs and both roots the proof is checked against come from heads a log signed. A
 * proof that does not reconstruct both roots is `ct/consistency-mismatch`, which is the append-only
 * failure: the log rewrote history or served a proof for a different pair.
 *
 * @opts
 *   url:    string,  // the log's base URL
 *   oldSth: object,  // the earlier verified { treeSize, rootHash }
 *   newSth: object,  // the later verified { treeSize, rootHash }
 *   transport, tls, headers, timeout, maxResponseBytes  // as pki.ct.getSth takes them
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   // requires: a -- an earlier verified tree head from pki.ct.getSth
 *   // requires: b -- a later verified tree head from pki.ct.getSth
 *   var c = await pki.ct.getSthConsistency({ url: base, oldSth: a, newSth: b, transport: t });
 *   c.verified;   // -> true
 */
async function getSthConsistency(opts) {
  var door = _clientDoor(opts || {}, null);
  opts = door.o;
  var oldSth = _assertSth(opts.oldSth, "opts.oldSth");
  var newSth = _assertSth(opts.newSth, "opts.newSth");
  if (oldSth.treeSize > newSth.treeSize) {
    throw _ctErr("ct/bad-input", "opts.oldSth names tree size " + oldSth.treeSize +
      ", which is larger than opts.newSth's " + newSth.treeSize);
  }
  var doc = await _clientJson(door,"get-sth-consistency", "consistency proof", {
    first: _stringOf(oldSth.treeSize), second: _stringOf(newSth.treeSize),
  });
  var consistency = _b64Array(doc, "consistency", "ct/bad-consistency", "consistency proof", 32, C.LIMITS.MERKLE_MAX_PROOF_NODES);
  var ok = merkle.verifyConsistency({
    oldSize: oldSth.treeSize, newSize: newSth.treeSize,
    oldRoot: oldSth.rootHash, newRoot: newSth.rootHash, proof: consistency,
  });
  if (ok !== true) {
    throw _ctErr("ct/consistency-mismatch", "the consistency proof the log served does not reconstruct " +
      "both tree heads -- the older is not shown to be a prefix of the newer");
  }
  return guard.verdict.of({ consistency: consistency, verified: true });
}

/**
 * @primitive  pki.ct.getEntries
 * @signature  pki.ct.getEntries(opts) -> Promise<{ entries, requested, truncated }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.getSth, pki.merkle.root
 *
 * Fetch log entries by index range (RFC 6962 sec. 4.6). Each entry comes back as `leafInput` and
 * `extraData` buffers.
 *
 * **This response carries no signature.** The specification states that this message is not signed,
 * and that the retrieved data is verified by constructing the Merkle Tree Hash corresponding to a
 * retrieved tree head. So nothing here is verified, and a caller that needs the entries to be the
 * log's must build the tree and compare it with a head from `pki.ct.getSth`.
 *
 * A log may serve fewer entries than the range asks for, which the specification permits: "Logs MAY
 * restrict the number of entries that can be retrieved per 'get-entries' request." That is reported
 * as `truncated` beside `requested` rather than treated as a fault, so a caller paginates. MORE
 * entries than the range asks for is a fault and is refused.
 *
 * @opts
 *   url:   string,          // the log's base URL
 *   start: number | bigint, // the first index, 0-based and inclusive
 *   end:   number | bigint, // the last index, inclusive
 *   transport, tls, headers, timeout, maxResponseBytes  // as pki.ct.getSth takes them
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   var e = await pki.ct.getEntries({ url: base, start: 0, end: 1, transport: t });
 *   e.entries[0].leafInput;   // -> <Buffer ...>
 */
async function getEntries(opts) {
  var door = _clientDoor(opts || {}, null);
  opts = door.o;
  var start = guard.range.uint64(opts.start, _ctErr, "ct/bad-input", "opts.start");
  var end = guard.range.uint64(opts.end, _ctErr, "ct/bad-input", "opts.end");
  if (end < start) {
    throw _ctErr("ct/bad-input", "opts.end (" + end + ") is before opts.start (" + start + ")");
  }
  var requested = end - start + 1n;
  if (requested > intrinsic.BigInt(C.LIMITS.CT_MAX_ENTRIES_PER_REQUEST)) {
    throw _ctErr("ct/bad-input", "a range of " + requested + " entries exceeds the " +
      C.LIMITS.CT_MAX_ENTRIES_PER_REQUEST + "-entry request cap");
  }
  var doc = await _clientJson(door,"get-entries", "entries", { start: _stringOf(start), end: _stringOf(end) });
  var raw = doc.entries;
  if (!intrinsic.isArray(raw)) throw _ctErr("ct/bad-entries", "the entries field is not an array");
  if (intrinsic.BigInt(raw.length) > requested) {
    throw _ctErr("ct/bad-entries", "the log served " + raw.length + " entries for a range of " + requested);
  }
  var entries = [];
  for (var i = 0; i < raw.length; i++) {
    var e = raw[i];
    if (!e || typeof e !== "object") throw _ctErr("ct/bad-entries", "entries[" + i + "] is not an object");
    if (typeof e.leaf_input !== "string" || typeof e.extra_data !== "string") {
      throw _ctErr("ct/bad-entries", "entries[" + i + "] is missing leaf_input or extra_data");
    }
    guard.list.append(entries, {
      leafInput: guard.encoding.base64(e.leaf_input, C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, "ct/bad-entries", "entries[" + i + "].leaf_input"),
      extraData: guard.encoding.base64(e.extra_data, C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, "ct/bad-entries", "entries[" + i + "].extra_data"),
    });
  }
  return guard.verdict.of({ entries: entries, requested: _numberOf(requested),
    truncated: intrinsic.BigInt(entries.length) < requested });
}

/**
 * @primitive  pki.ct.getRoots
 * @signature  pki.ct.getRoots(opts) -> Promise<{ certificates }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @related    pki.ct.addChain
 *
 * Fetch the root certificates a log accepts (RFC 6962 sec. 4.7), as DER buffers. This response
 * carries no signature either, so it tells a caller what to submit rather than what to trust.
 *
 * @opts
 *   url: string,   // the log's base URL
 *   transport, tls, headers, timeout, maxResponseBytes  // as pki.ct.getSth takes them
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   var r = await pki.ct.getRoots({ url: base, transport: t });
 *   r.certificates.length;   // -> 2
 */
async function getRoots(opts) {
  /** @internal This message carries no options of its own, so the door's record is all that is used. */
  var door = _clientDoor(opts || {}, null);
  var doc = await _clientJson(door, "get-roots", "roots");
  return guard.verdict.of({ certificates: _b64Array(doc, "certificates", "ct/bad-roots", "roots", undefined, C.LIMITS.CT_MAX_ROOTS) });
}

/**
 * @primitive  pki.ct.addChain
 * @signature  pki.ct.addChain(opts) -> Promise<{ sct, verified }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @defends    signature-bypass (CWE-347)
 * @related    pki.ct.addPreChain, pki.ct.verifySct
 *
 * Submit a certificate chain to a log (RFC 6962 sec. 4.1) and verify the signed certificate timestamp
 * it returns. The SCT is the log's promise to include the certificate, so it is checked against the
 * chain it was issued for and the key `opts.logKey` pins: one that does not verify, or that names a
 * different log, is `ct/sct-untrusted` and is not returned. A receipt nobody can check is not a
 * receipt.
 *
 * `opts.chain[0]` is the end-entity certificate the SCT covers; the rest are the issuers the log needs
 * to build a path, and are submitted unread.
 *
 * @opts
 *   url:     string,         // the log's base URL
 *   logKey:  BufferSource,   // the log's SubjectPublicKeyInfo, pinned by the caller
 *   chain:   Array,          // [leafDer, ...issuerDers], each a DER Buffer
 *   transport, tls, headers, timeout, maxResponseBytes  // as pki.ct.getSth takes them
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   // requires: leafDer -- the end-entity certificate to submit (DER)
 *   var r = await pki.ct.addChain({ url: base, logKey: spki, chain: [leafDer], transport: t });
 *   r.verified;   // -> true
 */
async function addChain(opts) {
  return await _addChain(opts, "add-chain", 0);
}

/**
 * @primitive  pki.ct.addPreChain
 * @signature  pki.ct.addPreChain(opts) -> Promise<{ sct, verified }>
 * @since      0.8.40
 * @status     stable
 * @spec       RFC 6962
 * @defends    signature-bypass (CWE-347)
 * @related    pki.ct.addChain, pki.ct.verifySct
 *
 * Submit a precertificate chain to a log (RFC 6962 sec. 4.2) and verify the signed certificate
 * timestamp it returns. A precertificate SCT covers the `precert_entry` form, whose signed data is the
 * issuer key hash and the TBSCertificate rather than the certificate itself, so `opts.tbsCertificate`
 * and `opts.issuerKeyHash` supply what that form needs. Verification is otherwise as `addChain`
 * describes it.
 *
 * @opts
 *   url:            string,       // the log's base URL
 *   logKey:         BufferSource, // the log's SubjectPublicKeyInfo, pinned by the caller
 *   chain:          Array,        // [precertDer, ...issuerDers]
 *   tbsCertificate: BufferSource, // the TBSCertificate the SCT covers
 *   issuerKeyHash:  BufferSource, // SHA-256 of the issuer's SubjectPublicKeyInfo, 32 bytes
 *   transport, tls, headers, timeout, maxResponseBytes  // as pki.ct.getSth takes them
 *
 * @example
 *   // requires: base -- the CT log's base URL, e.g. https://ct.googleapis.com/logs/us/argon2025h1/
 *   // requires: spki -- the log's SubjectPublicKeyInfo, from a verified log list
 *   // requires: t -- a transport, e.g. the one pki.ct.fetchLogList uses by default
 *   // requires: preDer -- the precertificate to submit (DER)
 *   // requires: tbs -- its TBSCertificate
 *   // requires: ikh -- SHA-256 of the issuer SubjectPublicKeyInfo
 *   var r = await pki.ct.addPreChain({ url: base, logKey: spki, chain: [preDer],
 *     tbsCertificate: tbs, issuerKeyHash: ikh, transport: t });
 *   r.verified;   // -> true
 */
async function addPreChain(opts) {
  return await _addChain(opts, "add-pre-chain", 1);
}

/** @internal The two submission messages differ in their path and in the entry form the SCT covers.
 *  The chain encoding, the response shape, and the refusal when the receipt does not verify are one
 *  rule stated once. */
async function _addChain(opts, message, entryType) {
  var door = _clientDoor(opts || {}, "logKey");
  opts = door.o;
  /** @internal ONE read of the option, used by the presence check here and by the copy below. Reading it
   *  twice let an accessor answer the two separately, presenting a non-null value to the check and an
   *  attacker's SPKI to the copy, and the returned receipt was then verified against a key the caller
   *  never pinned. */
  var suppliedLogKey = opts.logKey;
  if (suppliedLogKey == null) {
    throw _ctErr("ct/bad-input", "opts.logKey is required -- the caller-pinned log SPKI; an unverified SCT is not a receipt");
  }
  if (!intrinsic.isArray(opts.chain) || opts.chain.length === 0) {
    throw _ctErr("ct/bad-input", "opts.chain must be a non-empty array of DER certificates, leaf first");
  }
  /** @internal Each element is copied ONCE and both the submitted body and the entry the returned SCT is
   *  verified over are derived from that one copy. Reading `opts.chain[0]` a second time lets an indexed
   *  accessor hand one certificate to the log and another to the check, so the receipt would attest a
   *  certificate that was never submitted. The length is bound for the same reason. */
  var chainLen = opts.chain.length;
  var chainDer = [], chain = [];
  for (var i = 0; i < chainLen; i++) {
    guard.list.append(chainDer, _toBuffer(opts.chain[i], "opts.chain[" + i + "]"));
    guard.list.append(chain, _bufToString(chainDer[i], "base64"));
  }
  /** @internal The entry and the pinned key are COPIED before the request goes out. Both are read again
   *  after it returns: the entry is the preimage the returned SCT is verified over, and the key is what
   *  the SCT's logId is matched against and what the signature is checked under. Held as views, a caller
   *  reusing either buffer during the request gets a receipt for bytes it did not submit, or one checked
   *  against a log it did not pin. */
  function _snap(v, label) { return _toBuffer(v, label, _ctErr, "ct/bad-input"); }
  var entry = entryType === 0
    ? { entryType: 0, leafCert: chainDer[0] }
    : { entryType: 1, tbsCertificate: _snap(opts.tbsCertificate, "opts.tbsCertificate"),
      issuerKeyHash: _snap(opts.issuerKeyHash, "opts.issuerKeyHash") };
  var pinnedKey = _snap(suppliedLogKey, "opts.logKey");
  var doc = await _clientJson(door,message, "SCT", null, _jsonStringify({ chain: chain }));
  var version = doc.sct_version;
  if (version !== 0) {
    throw _ctErr("ct/bad-sct", "the log returned sct_version " + guard.text.showValue(version) +
      "; this build reads v1(0) (RFC 6962 sec. 3.2)");
  }
  var sct = {
    version: 0,
    logId: _b64Field(doc, "id", "ct/bad-sct", "sct", 32),
    timestamp: _uintField(doc, "timestamp", "ct/bad-sct", "sct"),
    extensions: typeof doc.extensions === "string" && doc.extensions.length === 0
      ? _bufferAlloc(0) : _b64Field(doc, "extensions", "ct/bad-sct", "sct"),
    signature: _b64Field(doc, "signature", "ct/bad-sct", "sct"),
  };
  var pinnedId = nodeCrypto.createHash("sha256").update(pinnedKey).digest();
  if (_bufferCompare(sct.logId, pinnedId) !== 0) {
    throw _ctErr("ct/sct-untrusted", "the SCT names log id " + _bufToString(sct.logId, "hex") +
      " where the pinned key's id is " + _bufToString(pinnedId, "hex") + " -- it is not this log's receipt");
  }
  var signedData = reconstructSignedData(entry, sct);
  var ok = await _verifyDigitallySigned(signedData, sct.signature, pinnedKey, "the SCT");
  if (ok !== true) {
    throw _ctErr("ct/sct-untrusted", "the SCT the log returned did not verify over the chain it was " +
      "issued for -- it is not a receipt and was not returned");
  }
  /** @internal Returned in the SCT shape the rest of this module reads, which is what `parseSctList` and
   *  `signSct` produce: the algorithm bytes decoded into `signatureAlgorithm`, and `signature` the raw
   *  signature rather than the TLS digitally-signed structure it arrived in. A receipt is only useful if
   *  it can be embedded and re-verified, and `encodeSctList` and `verifySct` both take that shape, so
   *  handing back the wire structure made the receipt unusable by every verb that consumes one. The
   *  verification above ran over the wire structure, which is the form the log signed. */
  var decodedSig = _parseDigitallySigned(sct.signature, "the SCT");
  var alg = decodedSig.signatureAlgorithm;
  return guard.verdict.of({
    sct: {
      version: sct.version, logId: sct.logId,
      /** @internal `logIdHex` as well as the bytes, because the log-list verbs key a log by the hex and
       *  not by the Buffer: without it a receipt this verb had just verified was refused outright by
       *  `verifySctWithLogList` and dropped by `verifySctList` as a policy failure. The comment below
       *  claims this is the shape `parseSctList` produces, and that claim is only true with this field,
       *  which `parseSctList` and `signSct` both carry. */
      logIdHex: _bufToString(sct.logId, "hex"),
      timestamp: sct.timestamp, extensions: sct.extensions,
      /** @internal Both spellings, because the module's own consumers read different ones:
       *  `encodeSctList` takes the flat algorithm bytes and `verifySct` the named object. This is the
       *  shape `parseSctList` produces, which is what makes the two round-trip. */
      hashAlg: alg.hash, sigAlg: alg.signature,
      signatureAlgorithm: alg, signature: decodedSig.signature,
    },
    verified: true,
  });
}

/** @internal The TLS `digitally-signed` structure a log returns, read into the shape `verifySct`
 *  already takes: a hash-algorithm byte, a signature-algorithm byte, a uint16 length, then that many
 *  signature bytes. The length is held to the bytes that follow it rather than trusted, and trailing
 *  bytes are refused, so a structure claiming less than it carries cannot hide one. */
function _parseDigitallySigned(buf, label) {
  if (buf.length < 4) {
    throw _ctErr("ct/bad-signature", label + " is shorter than a digitally-signed header (4 bytes), got " + buf.length);
  }
  var hashAlg = buf[0], sigAlg = buf[1];
  var len = (buf[2] << 8) | buf[3];
  if (buf.length !== 4 + len) {
    throw _ctErr("ct/bad-signature", label + " states a " + len + "-byte signature but carries " +
      (buf.length - 4) + " bytes after its header");
  }
  return {
    signatureAlgorithm: { hash: hashAlg, hashName: HASH_ALGORITHMS[hashAlg] || null,
      signature: sigAlg, signatureName: SIGNATURE_ALGORITHMS[sigAlg] || null },
    signature: _subarray(buf, 4),
  };
}

/** @internal A digitally-signed structure verified over a preimage under a log's SPKI, through the
 *  one signature path this module already uses for an SCT. Resolves a boolean: whether a key signed
 *  something is a verdict, and a malformed structure throws before any verify is attempted. */
async function _verifyDigitallySigned(preimage, wireSignature, logKey, label) {
  var parsed = _parseDigitallySigned(_toBuffer(wireSignature, label + " signature"), label);
  var spki = _toBuffer(logKey, "the CT log public key (SPKI)");
  var hashName = CT_HASH[parsed.signatureAlgorithm.hashName];
  if (!hashName) {
    throw _ctErr("ct/unsupported-algorithm", "unsupported " + label + " hash algorithm " +
      guard.text.showValue(parsed.signatureAlgorithm.hashName) + " (RFC 6962 sec. 2.1.4 mandates sha256)");
  }
  var alg = _spkiAlg(spki);
  var imp, ver, sig = parsed.signature;
  if (parsed.signatureAlgorithm.signatureName === "ecdsa") {
    if (alg.algOid !== oid.byName("ecPublicKey")) throw _ctErr("ct/bad-input", label + " declares an ECDSA signature but the log key is not an EC key");
    var ec = CT_EC_CURVE[alg.curveOid];
    if (!ec) throw _ctErr("ct/unsupported-algorithm", "unsupported CT log EC curve (RFC 6962 sec. 2.1.4 mandates NIST P-256)");
    imp = { name: "ECDSA", namedCurve: ec.curve };
    ver = { name: "ECDSA", hash: hashName };
    sig = validator.sig.ecdsaDerToP1363(sig, ec.curve, CtError, "ct/bad-signature");
  } else if (parsed.signatureAlgorithm.signatureName === "rsa") {
    if (alg.algOid !== oid.byName("rsaEncryption")) throw _ctErr("ct/bad-input", label + " declares an RSA signature but the log key is not an RSA key");
    if (!(alg.rsaBits >= 2048)) throw _ctErr("ct/unsupported-algorithm", "the CT log RSA key is below the RFC 6962 sec. 2.1.4 minimum of 2048 bits");
    imp = { name: "RSASSA-PKCS1-v1_5", hash: hashName };
    ver = { name: "RSASSA-PKCS1-v1_5" };
  } else {
    throw _ctErr("ct/unsupported-algorithm", "unsupported " + label + " signature algorithm " +
      guard.text.showValue(parsed.signatureAlgorithm.signatureName) + " (RFC 6962 sec. 2.1.4 supports ecdsa/rsa)");
  }
  try {
    var key = await _subtleImportKey(subtle, "spki", spki, imp, false, ["verify"]);
    return await _subtleVerify(subtle, ver, key, sig, preimage);
  } catch (e) {
    throw _ctErr("ct/verify-error", label + " signature could not be evaluated", e);
  }
}

/** @internal A tree head a caller passes in, held to carrying the two values a proof is checked
 *  against. It is expected to have come from `getSth`, which returns nothing unverified. */
function _assertSth(sth, label) {
  if (!sth || typeof sth !== "object") {
    throw _ctErr("ct/bad-input", label + " is required -- a verified tree head from pki.ct.getSth; a proof against nothing proves nothing");
  }
  /** @internal COPIED, not viewed. Every caller of this holds the result across a network fetch and then
   *  folds a proof against it, so a view would let the trusted root change between the moment the caller
   *  supplied it and the moment the fold reads it. An empty proof folds a one-leaf tree to its own leaf
   *  hash, so a root overwritten with a leaf hash mid-fetch would make an empty proof verify against a
   *  tree head nobody ever supplied. */
  var root = _toBuffer(sth.rootHash, label + ".rootHash", _ctErr, "ct/bad-input");
  if (root.length !== 32) throw _ctErr("ct/bad-input", label + ".rootHash must be exactly 32 bytes, got " + root.length);
  return { treeSize: guard.range.uint64(sth.treeSize, _ctErr, "ct/bad-input", label + ".treeSize"), rootHash: root };
}

/** @internal An array of base64 members, each decoded and held to a byte length where one is fixed. */
/** @internal `maxCount` bounds the ELEMENT COUNT, and every caller passes one. The bound used to be keyed
 *  on `exactLen === 32`, the fixed width a proof node has, so the one caller whose entries have no fixed
 *  width, the accepted-roots response, had no bound at all: a configured log is trusted for its own
 *  signatures and not for its resource use, and a response body well inside the transport's byte cap
 *  carries about a million empty strings, each of which becomes its own Buffer here (CWE-770). Keying a
 *  resource bound on an unrelated shape test is what left one caller out of it. */
function _b64Array(obj, name, code, label, exactLen, maxCount) {
  var arr = obj[name];
  if (!intrinsic.isArray(arr)) throw _ctErr(code, "the " + label + " field " + name + " is not an array");
  if (arr.length > maxCount) {
    throw _ctErr(code, "the " + label + " carries " + arr.length + " entries, exceeding " + maxCount);
  }
  void exactLen;
  var out = [];
  for (var i = 0; i < arr.length; i++) {
    if (typeof arr[i] !== "string") throw _ctErr(code, name + "[" + i + "] is not a base64 string");
    var buf = guard.encoding.base64(arr[i], C.LIMITS.CT_LOG_LIST_MAX_BYTES, _ctErr, code, name + "[" + i + "]");
    if (exactLen !== undefined && buf.length !== exactLen) {
      throw _ctErr(code, name + "[" + i + "] is " + buf.length + " bytes, expected " + exactLen);
    }
    guard.list.append(out, buf);
  }
  return out;
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
 * @opts requireJsonContentType OPTIONAL boolean (default false) -- opt in to a strict `ct/bad-content-type` gate on the JSON GET. A value other than `true`, `false`, `null` or an absent option is refused `ct/bad-input` before the request goes out.
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
  /** @internal The same door the sec. 4 verbs enter by, over this verb's own option set. Checking the
   *  NAMES alone left every value still to be read from the caller's object, and `url` was read twice,
   *  once to parse and once to fetch, so an accessor sent the request somewhere the parse never saw. */
  opts = guard.identifier.optionsObject(opts, _ctErr, "ct/bad-input", "pki.ct.fetchLogList options");
  guard.identifier.assertKnownKeys(opts, KNOWN_FETCH_OPTS, _ctErr, "ct/bad-input", "unknown opts field ");
  /** @internal Every declared option taken before anything derives from one, for the reason
   *  `_clientDoor` does it: there is no safe order, because reading a NESTED value inside any of them
   *  runs the caller's code and that code can rewrite the ones not yet taken. Parsing the url first let
   *  its `toString` empty the pinned anchor list; taking the tls first let a getter on `tls.anchors`
   *  rewrite the url and the signer key. Taking the top level first closes both. */
  opts = _settleDecisive(_takeTopLevel(opts, KNOWN_FETCH_OPTS), "signerKey");
  /** @internal Read once, at the door, and carried from here. Asking again would let an option that
   * answers differently on each read hand back something other than the value that was checked. */
  var transport = _assertTransport(opts);
  var fetchTls = _tlsForFetch(opts);
  /** @internal ONE read, and both the presence check and the copy decide from it. Reading it twice let an
   *  accessor present a non-null value to the check and an attacker's SPKI to the copy, so the list was
   *  verified under a distributor key the caller never pinned.
   *  COPIED at the call, before either fetch. The list is verified under this key after BOTH requests
   *  return, so read from the caller's object at that point it is whatever the buffer holds by then: a
   *  caller reusing it has the list checked against a distributor it never pinned. */
  var suppliedSignerKey = opts.signerKey;
  if (suppliedSignerKey == null) throw _ctErr("ct/bad-input", "opts.signerKey is required -- the caller-pinned CT log-list distributor SPKI (there is no baked-in key)");
  var pinnedSigner = _toBuffer(suppliedSignerKey, "opts.signerKey", _ctErr, "ct/bad-input");
  if (opts.url == null) throw _ctErr("ct/bad-input", "opts.url is required -- the log_list.json URL (there is no baked-in vendor URL)");
  var jsonParsed = _parseHttpsUrl(opts.url, "URL");
  var jsonUrl = _urlHref(jsonParsed);
  /** @internal ONE read: the presence test and the parse decide from the same value. */
  var suppliedSigUrl = opts.sigUrl;
  /** @internal Through the captured accessor like every other read of a parsed destination here. No
   *  caller code can run between the settle above and this line, the bag refusing an accessor and both
   *  urls having to be strings, so this one has no vector of its own; it is read this way because a
   *  site that reads a destination off the prototype is the shape that has to stay absent. */
  var sigUrl = suppliedSigUrl != null
    ? _urlHref(_parseHttpsUrl(suppliedSigUrl, "signature URL"))
    : _sigUrlFor(jsonParsed);
  if (!_sameOrigin(jsonUrl, sigUrl)) throw _ctErr("ct/bad-input", "opts.sigUrl must share the log-list URL's origin (" + _urlOrigin(jsonParsed) + "); a cross-origin detached-signature host is not supported");
  if (!transport) {
    var hasAnchors = fetchTls.anchors !== undefined && fetchTls.anchors !== null && !(intrinsic.isArray(fetchTls.anchors) && fetchTls.anchors.length === 0);
    if (!hasAnchors && fetchTls.useSystemStore !== true) throw _ctErr("ct/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true -- refusing an unpinned CT server (RFC 6962 sec. 3.2)");
    transport = httpTransport.https({ E: _ctErr, errPrefix: "ct" });
  }
  var timeout = guard.limits.cap(opts.timeout, "timeout", DEFAULT_FETCH_TIMEOUT, { E: _ctErr, code: "ct/bad-input", min: 1, max: MAX_FETCH_TIMEOUT });
  var maxResponseBytes = guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", C.LIMITS.CT_LOG_LIST_MAX_BYTES, { E: _ctErr, code: "ct/bad-input", min: 1, max: C.LIMITS.CT_LOG_LIST_MAX_BYTES });
  var headers = intrinsic.create(null);
  var suppliedHeaders = opts.headers;
  intrinsic.forEach(guard.identifier.optionNames(suppliedHeaders), function (k) {
    var lk = _toLowerCase(k);
    if (lk !== "content-length" && lk !== "transfer-encoding") headers[k] = suppliedHeaders[k];
  });
  var req = { headers: headers, tls: fetchTls, timeout: timeout, maxResponseBytes: maxResponseBytes };
  /** @internal Read before the request goes out, so the option that decides the check is the one the call
   *  was made with rather than whatever it says once the response is back. */
  var requireJsonContentType = guard.identifier.booleanOption(opts.requireJsonContentType, _ctErr,
    "ct/bad-input", "fetchLogList opts.requireJsonContentType");
  var jsonRes = await _fetchBody(transport, jsonUrl, req, "CT log-list JSON");
  if (requireJsonContentType && jsonRes.contentType !== "application/json") throw _ctErr("ct/bad-content-type", "the CT log-list JSON GET returned content-type " + JSON.stringify(jsonRes.contentType || null) + " (opts.requireJsonContentType is set)");
  var sigRes = await _fetchBody(transport, sigUrl, req, "CT log-list signature");
  var ok = await verifyLogListSignature(jsonRes.body, sigRes.body, pinnedSigner);
  if (ok !== true) throw _ctErr("ct/log-list-untrusted", "the CT log-list detached signature did not verify against the pinned distributor key -- the fetched list is untrusted and was not parsed");
  var parsed = parseLogList(jsonRes.body);
  return guard.verdict.of({
    logs: parsed.logs, byLogId: parsed.byLogId, version: parsed.version, timestamp: parsed.timestamp,
    raw: { json: jsonRes.body, sig: sigRes.body }, status: jsonRes.status, contentType: jsonRes.contentType, tls: jsonRes.tls,
  });
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
  sthSignedData: sthSignedData,
  verifySth: verifySth,
  getSth: getSth,
  getProofByHash: getProofByHash,
  getSthConsistency: getSthConsistency,
  getEntries: getEntries,
  getRoots: getRoots,
  addChain: addChain,
  addPreChain: addPreChain,
  HASH_ALGORITHMS: HASH_ALGORITHMS,
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
};
