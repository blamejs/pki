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
var compromisedKeys = require("./compromised-keys");

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

/** @internal The built-in list, keyed by digest. */
var COMPROMISED = _create(null);
for (var _ci = 0; _ci < compromisedKeys.KEYS.length; _ci++) COMPROMISED[compromisedKeys.KEYS[_ci].spkiSha256] = compromisedKeys.KEYS[_ci];

/** @internal The curves the small-scalar table is built for, by JWK curve name, with the width of a
 *  coordinate in bytes, and the scalar bound. Each table holds the x-coordinates of d*G for d from 1
 *  to the bound minus one, built once per curve on first use (measured on Node 26: 4 ms for P-256,
 *  138 ms for P-384, 321 ms for P-521). The points d*G and (n-d)*G share an x-coordinate, so one
 *  comparison covers both. */
var SMALL_SCALAR_CURVES = intrinsic.assign(_create(null), {
  "P-256": { name: "prime256v1", width: 32 },
  "P-384": { name: "secp384r1", width: 48 },
  "P-521": { name: "secp521r1", width: 66 },
  "secp256k1": { name: "secp256k1", width: 32 },
});
var SMALL_SCALAR_BOUND = 256;
var _smallScalarTables = _create(null);
function _smallScalarTable(curve) {
  if (_smallScalarTables[curve.name]) return _smallScalarTables[curve.name];
  var table = _create(null);
  var scalar = intrinsic.bufferAlloc(curve.width);
  for (var d = 1; d < SMALL_SCALAR_BOUND; d++) {
    scalar[curve.width - 1] = d;
    table[_bufToString(gCrypto.ecPointFromScalar(curve.name, scalar), "hex", 1, 1 + curve.width)] = true;
  }
  _smallScalarTables[curve.name] = table;
  return table;
}

/** The curve name of an elliptic curve key whose private scalar is below 256, or below 256 short of
 * the group order, or `null` for any other key. Anyone can recover such a private key from the public
 * key by trying each candidate. The key is read through node's own import after an id-ecDH or
 * id-ecMQV identifier is read as ecPublicKey, so a named or explicit curve and an uncompressed,
 * compressed or hybrid point are all judged; a point that is not on the curve is not a key and
 * answers `null`. The covered curves are P-256, P-384, P-521 and secp256k1.
 *
 * @enforced-by behavioral -- the defect is a curve or an encoding the table does not reach, which has
 * no code shape; the guard is the per-curve and per-encoding vectors in guard-distrust.test.js and
 * lint-key-compromise.test.js.
 */
function smallEcScalar(spkiBytes) {
  var jwk;
  try {
    var spki = _unrestricted(spkiBytes, _codec());
    var key = gCrypto.publicKey({ key: spki, format: "der", type: "spki" });
    if (gCrypto.keyTypeOf(key) !== "ec") return null;
    jwk = gCrypto.exportKey(key, { format: "jwk" });
  } catch (_e) {
    // allow:swallow-unverified a key node does not import as an elliptic curve point has no scalar to judge
    return null;
  }
  var curve = typeof jwk.crv === "string" && _hasOwn(SMALL_SCALAR_CURVES, jwk.crv) ? SMALL_SCALAR_CURVES[jwk.crv] : null;
  if (curve === null || typeof jwk.x !== "string") return null;
  return _smallScalarTable(curve)[_bufToString(intrinsic.bufferFrom(jwk.x, "base64url"), "hex")] === true ? curve.name : null;
}

/** Why the private key of `spkiBytes` is public, as one sentence, or `null`. A key is compromised
 * when its digest, as given or as `keyDigest` computes it, is on the list `pki.trust.knownCompromisedKeys()`
 * returns, or when `smallEcScalar` answers a curve for it. Every verifier in this toolkit refuses such
 * a key, with no option that turns the refusal off.
 *
 * @enforced-by behavioral -- the defect is a door that does not refuse, which has no rename-proof code
 * shape; every door reaches this through `has`, and the guard is the compromised-key vector each verb
 * carries.
 */
function compromised(spkiBytes) {
  if (spkiBytes === null || spkiBytes === undefined) return null;
  var entry = COMPROMISED[digest(spkiBytes)] || COMPROMISED[keyDigest(spkiBytes)];
  if (entry) return "the key is the published key of " + entry.name + ": " + entry.reason;
  var curve = smallEcScalar(spkiBytes);
  if (curve !== null) return "the " + curve + " private key is an integer below " + SMALL_SCALAR_BOUND + ", so anyone can recover it from the public key";
  return null;
}

/** Throws `E(code, ...)` when `compromised(spkiBytes)` answers, naming the key by `label` and saying
 * why its private key is public. A verb that certifies a key, signs with one or requests a
 * certificate for one calls this on each key it is handed.
 *
 * @enforced-by behavioral -- the defect is a signing verb that does not call this, which has no
 * rename-proof code shape; the guard is the compromised-key vector each signing verb carries.
 */
function refuseCompromised(spkiBytes, E, code, label) {
  var why = compromised(spkiBytes);
  if (why !== null) throw E(code, label + " is a compromised key: " + why);
}

/** Why the key `spkiBytes` names is refused, as the end of a sentence about the key, or `null` when
 * `has(list, spkiBytes)` is false: "is a compromised key: " and the `compromised` reason, or "is
 * listed in " and `label`, the option the caller's list came from.
 *
 * @enforced-by behavioral -- a message has no rename-proof code shape; the guard is the vectors that
 * assert each door's message names a compromised key as one and a listed key as listed.
 */
function refusal(list, spkiBytes, label) {
  var why = compromised(spkiBytes);
  if (why !== null) return "is a compromised key: " + why;
  return has(list, spkiBytes) ? "is listed in " + label : null;
}

/** Whether the key `spkiBytes` names is refused: it is compromised (see `compromised`), or it is on
 * `list`, a value `keys` returned. A `null` or empty list still refuses a compromised key. The digest
 * of the bytes as given is compared with the list, and so is `keyDigest`, so an entry `keyDigest`
 * computed matches the key however a certificate encodes it (a compressed EC point, RSA parameters
 * without NULL), and an entry computed over raw bytes matches a certificate with the same bytes.
 *
 * @enforced-by behavioral -- membership has no rename-proof code shape; the RED vectors are the
 * listed-key and compromised-key refusals at each verb, and the re-encodings in guard-distrust.test.js
 * in both directions.
 */
function has(list, spkiBytes) {
  if (spkiBytes === null || spkiBytes === undefined) return false;
  if (compromised(spkiBytes) !== null) return true;
  if (list === null || list === undefined || list.length === 0) return false;
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

/** A copy of the built-in list: one `{ spkiSha256, name, reason, sources }` record per key, each
 * frozen, in a new array the caller may change.
 *
 * @enforced-by behavioral -- a copy has no rename-proof code shape; the guard is the vector that
 * changes the returned array and reads the list again.
 */
function knownCompromised() {
  var out = [];
  for (var i = 0; i < compromisedKeys.KEYS.length; i++) gList.append(out, compromisedKeys.KEYS[i]);
  return out;
}

module.exports = _freeze({
  keys: keys, digest: digest, keyDigest: keyDigest, has: has, union: union,
  compromised: compromised, refuseCompromised: refuseCompromised, refusal: refusal,
  smallEcScalar: smallEcScalar, knownCompromised: knownCompromised,
  SMALL_SCALAR_BOUND: SMALL_SCALAR_BOUND,
});
