// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var util = require("util");
var intrinsic = require("./guard-intrinsic");
var constants = require("./constants");
var gBytes = require("./guard-bytes");
var gList = require("./guard-list");
var gCrypto = require("./guard-crypto");

var _freeze = intrinsic.freeze;
var _isArray = intrinsic.isArray;
var _create = intrinsic.create;
var _hasOwn = intrinsic.hasOwn;
var _getOwnPropertyDescriptor = intrinsic.getOwnPropertyDescriptor;
var _bufToString = intrinsic.bufToString;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _fromCharCode = intrinsic.fromCharCode;
var _isProxy = util.types.isProxy;

var DIGEST_BYTES = 32;
var DIGEST_HEX = 64;

/** @internal One hexadecimal character, folded to lower case, or -1. The fold is arithmetic on the
 *  character code, so the normalized digest is not the answer of a `toLowerCase` read off the live
 *  prototype. */
function _lowerHexCode(c) {
  if (c >= 48 && c <= 57) return c;
  if (c >= 97 && c <= 102) return c;
  if (c >= 65 && c <= 70) return c + 32;
  return -1;
}

function _hexEntry(s, E, code, where) {
  if (s.length !== DIGEST_HEX) {
    throw E(code, where + " must be a SHA-256 digest of a SubjectPublicKeyInfo: 64 hexadecimal characters or 32 bytes, got " + s.length + " characters");
  }
  var out = "";
  for (var i = 0; i < DIGEST_HEX; i++) {
    var c = _lowerHexCode(_charCodeAt(s, i));
    if (c === -1) throw E(code, where + " must be 64 hexadecimal characters with no separators; character " + i + " is not a hexadecimal digit");
    out += _fromCharCode(c);
  }
  return out;
}

function _bytesEntry(v, E, code, where) {
  var copy = gBytes.snapshotSource(v, E, code, where);
  if (copy.length !== DIGEST_BYTES) {
    throw E(code, where + " must be a SHA-256 digest of a SubjectPublicKeyInfo: 32 bytes or 64 hexadecimal characters, got " + copy.length + " bytes");
  }
  return _bufToString(copy, "hex");
}

/** The caller's list of distrusted keys, read once and returned as a frozen list of lower-case hex
 * digests with duplicates removed, or `null` when the option is absent or `null`. Each entry is the
 * SHA-256 digest of a certificate's DER SubjectPublicKeyInfo, given as 64 hexadecimal characters or
 * as 32 bytes.
 *
 * Every slot is read through its descriptor, so a hole, an accessor and a Proxy are refused rather
 * than read: a hole is answered by the array prototype and an accessor answers each read separately,
 * and either one makes the list the check uses differ from the list the caller wrote. The list is a
 * refusal list, so reading it as shorter than it is lets through a key the caller distrusted.
 *
 * @enforced-by behavioral -- the defect is a door that does not call this, which has no rename-proof
 * code shape; the guard is the RED vector each verb carries, driving a listed key through the
 * shipped verb and asserting the refusal.
 */
function keys(value, E, code, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || _isProxy(value) || !_isArray(value)) {
    throw E(code, label + " must be an array of SHA-256 SubjectPublicKeyInfo digests");
  }
  var n = gList.count(value, "keys");
  if (n > constants.LIMITS.DISTRUSTED_KEYS_MAX) {
    throw E(code, label + " has " + n + " entries, more than the " + constants.LIMITS.DISTRUSTED_KEYS_MAX + " this toolkit reads");
  }
  var seen = _create(null);
  var out = [];
  for (var i = 0; i < n; i++) {
    var where = label + "[" + i + "]";
    var d = _getOwnPropertyDescriptor(value, i);
    if (!d) throw E(code, where + " is a hole; every entry must be present");
    if (d.get || d.set) throw E(code, where + " is an accessor; every entry must be a data property");
    var v = d.value;
    var hex;
    if (typeof v === "string") hex = _hexEntry(v, E, code, where);
    else if (gBytes.isByteSource(v)) hex = _bytesEntry(v, E, code, where);
    else throw E(code, where + " must be 64 hexadecimal characters or 32 bytes");
    if (_hasOwn(seen, hex)) continue;
    seen[hex] = true;
    gList.append(out, hex);
  }
  return _freeze(out);
}

/** The lower-case hex SHA-256 of `spkiBytes`, the DER SubjectPublicKeyInfo exactly as a certificate
 * or an anchor carries it.
 *
 * @enforced-by behavioral -- a digest has no rename-proof shape that separates this use from the
 * others `guard-crypto` serves; the guard is the membership vector, which fails if the bytes hashed
 * are not the ones listed.
 */
function digest(spkiBytes) {
  return gCrypto.digest("sha256", spkiBytes, { output: "hex" });
}

/** @internal The codec and the registry, reached through inline requires: both load this module
 *  through guard-all, so both are loaded by the time a digest is asked for. */
function _codec() {
  return {
    asn1: require("./asn1-der"),   // allow:inline-require -- circular load: asn1-der -> guard-all -> this module
    oid: require("./oid"),         // allow:inline-require -- circular load: oid -> guard-all -> this module
  };
}

/** @internal The SubjectPublicKeyInfo with an identifier that restricts the key's use replaced by the
 *  key's own: id-ecDH and id-ecMQV (RFC 5480 sec. 2.1.2) become ecPublicKey with the curve kept, and
 *  RSASSA-PSS and RSAES-OAEP (RFC 4055) become rsaEncryption with NULL. The subjectPublicKey bits are
 *  the same key in each pair. Any other identifier is returned unchanged. */
function _unrestricted(spkiBytes, c) {
  var b = c.asn1.build;
  var root = c.asn1.decode(spkiBytes);
  var alg = root.children[0];
  var name = c.oid.name(c.asn1.read.oid(alg.children[0]));
  if (name === "ecDH" || name === "ecMQV") {
    var params = alg.children.length > 1 ? [b.raw(alg.children[1].bytes)] : [];
    return b.sequence([b.sequence(intrinsic.concatList([b.oid(c.oid.byName("ecPublicKey"))], params)), b.raw(root.children[1].bytes)]);
  }
  if (name === "rsassaPss" || name === "rsaesOaep") {
    return b.sequence([b.sequence([b.oid(c.oid.byName("rsaEncryption")), b.nullValue()]), b.raw(root.children[1].bytes)]);
  }
  return spkiBytes;
}

/** @internal The key in canonical form, or null when node does not read the bytes as a public key.
 *  An elliptic curve key is written with ecPublicKey, its named curve and an uncompressed point,
 *  whatever point form or parameter form it was read in. Any other key node writes as a JWK is
 *  written the way node writes a key it builds from one, which puts an RSA key under rsaEncryption
 *  with NULL. A key with neither form is re-exported as node read it. */
function _canonicalSpki(spkiBytes) {
  try {
    var c = _codec();
    var spki = _unrestricted(spkiBytes, c);
    var key = gCrypto.publicKey({ key: spki, format: "der", type: "spki" });
    if (gCrypto.keyTypeOf(key) === "ec") {
      var details = gCrypto.keyDetailsOf(key);
      var curveOid = details && typeof details.namedCurve === "string" ? c.oid.byName(details.namedCurve) : undefined;
      if (curveOid !== undefined) {
        var b = c.asn1.build;
        var point = c.asn1.read.bitString(c.asn1.decode(spki).children[1]).bytes;
        var uncompressed = gCrypto.ecConvertPoint(point, details.namedCurve, "uncompressed");
        return b.sequence([b.sequence([b.oid(c.oid.byName("ecPublicKey")), b.oid(curveOid)]), b.bitString(uncompressed, 0)]);
      }
    }
    var jwk = null;
    try { jwk = gCrypto.exportKey(key, { format: "jwk" }); }
    catch (_je) {
      // allow:swallow-unverified a key type with no JWK form is re-exported as node read it
      jwk = null;
    }
    if (jwk !== null) key = gCrypto.publicKey({ key: jwk, format: "jwk" });
    return gCrypto.exportKey(key, { type: "spki", format: "der" });
  } catch (_e) {
    // allow:swallow-unverified a key node does not read has no second encoding, and the raw digest still decides
    return null;
  }
}

/** The digest a distrust entry names a key by: the lower-case hex SHA-256 of the key's
 * SubjectPublicKeyInfo in canonical form, an uncompressed EC point with its named curve and an RSA
 * key with NULL parameters. That is how nearly every certificate encodes a key, so for those it is
 * the digest of the bytes the certificate carries. A key node does not read is digested as given.
 *
 * @enforced-by behavioral -- a digest has no rename-proof shape; the guard is the two-direction
 * re-encoding vectors in guard-distrust.test.js.
 */
function keyDigest(spkiBytes) {
  var canonical = _canonicalSpki(spkiBytes);
  return digest(canonical !== null ? canonical : spkiBytes);
}

/** Whether the key `spkiBytes` names is on `list`, a value `keys` returned. A `null` or empty list
 * answers `false`. The digest of the bytes as given is compared, and so is `keyDigest`, so an entry
 * `keyDigest` computed matches the key however a certificate encodes it (a compressed EC point, RSA
 * parameters without NULL), and an entry computed over raw bytes matches a certificate with the same
 * bytes.
 *
 * @enforced-by behavioral -- membership has no rename-proof code shape; the RED vectors are the
 * listed-key refusals at each verb, and the re-encodings in guard-distrust.test.js in both directions.
 */
function has(list, spkiBytes) {
  if (list === null || list === undefined || list.length === 0 || spkiBytes === null || spkiBytes === undefined) return false;
  if (gList.contains(list, digest(spkiBytes))) return true;
  return gList.contains(list, keyDigest(spkiBytes));
}

/** Every entry of two lists that `keys` returned, once, as a frozen list; `null` when both are
 * `null`. A transport default and a per-request list are combined this way, so a request cannot
 * remove a key the default distrusts by naming a shorter list.
 *
 * @enforced-by behavioral -- a union has no rename-proof code shape; the RED vector is a request
 * list that omits a default entry and the default entry still being refused.
 */
function union(a, b) {
  if ((a === null || a === undefined) && (b === null || b === undefined)) return null;
  var seen = _create(null);
  var out = [];
  var parts = [a || [], b || []];
  for (var p = 0; p < 2; p++) {
    var part = parts[p];
    for (var i = 0, n = gList.count(part, "union"); i < n; i++) {
      var hex = part[i];
      if (_hasOwn(seen, hex)) continue;
      seen[hex] = true;
      gList.append(out, hex);
    }
  }
  return _freeze(out);
}

module.exports = _freeze({ keys: keys, digest: digest, keyDigest: keyDigest, has: has, union: union });
