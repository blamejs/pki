// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-distrust (@internal): the one normalizer for a caller's list of distrusted
 * keys, and the one membership test every verifier asks. An entry is the SHA-256 digest of a
 * certificate's DER SubjectPublicKeyInfo, as 64 hexadecimal characters or as 32 bytes.
 *
 * The list is a refusal list, so the failure that matters is a list that reads as shorter than
 * the caller wrote it: a hole answered by the array prototype, an accessor that answers one value
 * to the check and another to the copy, or a caller mutating the array after handing it over.
 * Each of those is refused or snapshotted here, and the result is frozen.
 */

var nodeCrypto = require("crypto");
var distrust = require("../../lib/guard-distrust");
var constants = require("../../lib/constants");
var helpers = require("../helpers");
var check = helpers.check;

function E(code, message) { var e = new Error(message); e.code = code; return e; }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || "UNTYPED"; } }
function keys(v) { return distrust.keys(v, E, "test/bad-input", "opts.distrustedKeys"); }
function sha(b) { return nodeCrypto.createHash("sha256").update(b).digest("hex"); }

// The small-scalar table: d*G for d = 1..255 on every covered curve, built by point addition from G.
// Every entry is compared with node's own scalar multiplication, so a wrong field prime, a wrong
// coefficient or a wrong formula fails here.
var SS_CURVES = [["P-256", "prime256v1", 32], ["P-384", "secp384r1", 48], ["P-521", "secp521r1", 66], ["secp256k1", "secp256k1", 32]];
function testSmallScalarTable() {
  SS_CURVES.forEach(function (row) {
    var xs = distrust.smallScalarXs(row[0]);
    var bad = [];
    for (var d = 1; d < 256; d++) {
      var ecdh = nodeCrypto.createECDH(row[1]);
      var s = Buffer.alloc(row[2]);
      s[row[2] - 1] = d;
      ecdh.setPrivateKey(s);
      if (xs[d - 1] !== ecdh.getPublicKey("hex", "uncompressed").slice(2, 2 + 2 * row[2])) bad.push(d);
    }
    check("SS1. " + row[0] + ": all 255 x-coordinates equal setPrivateKey's, in order of d",
      xs.length === 255 && Object.isFrozen(xs) && bad.length === 0);
    var n1 = nodeCrypto.createECDH(row[1]);
    var top = Buffer.alloc(row[2]);
    top[row[2] - 1] = 255;
    n1.setPrivateKey(top);
    var spki = nodeCrypto.createPublicKey({ key: { kty: "EC", crv: row[0],
      x: n1.getPublicKey().subarray(1, 1 + row[2]).toString("base64url"),
      y: n1.getPublicKey().subarray(1 + row[2]).toString("base64url") }, format: "jwk" }).export({ format: "der", type: "spki" });
    check("SS2. " + row[0] + ": a key with private scalar 255 is caught", distrust.smallEcScalar(spki) === row[1]);
  });
  check("SS3. an uncovered curve has no table", distrust.smallScalarXs("X25519") === null && distrust.smallScalarXs("constructor") === null &&
    distrust.smallScalarXs(undefined) === null);
  // Ten fresh P-521 tables. Measured: about 50 ms built by point addition (4 to 6 ms each on Node
  // 26.12.1 and 24.22.1), against 241 to 277 ms EACH built by 255 scalar multiplications, about 2.5 s
  // for ten. The bound sits twenty times above the first and well below the second.
  var t0 = Date.now();
  for (var k = 0; k < 10; k++) distrust.smallScalarXs("P-521");
  var ms = Date.now() - t0;
  check("SS4. ten P-521 tables build in under 1000 ms (took " + ms + " ms)", ms < 1000);
}

function run() {
  testSmallScalarTable();
  var spkiA = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004" + "11".repeat(64), "hex");
  var spkiB = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004" + "22".repeat(64), "hex");
  var hexA = sha(spkiA), hexB = sha(spkiB);

  // ---- absence ----
  check("keys(undefined) is null (no list was given)", keys(undefined) === null);
  check("keys(null) is null (a null option reads as an omitted one)", keys(null) === null);
  var empty = keys([]);
  check("keys([]) is an empty frozen list", Array.isArray(empty) && empty.length === 0 && Object.isFrozen(empty));

  // ---- the two accepted spellings, normalized to one ----
  var fromHex = keys([hexA.toUpperCase()]);
  check("an upper-case hex digest normalizes to lower case", fromHex.length === 1 && fromHex[0] === hexA);
  var fromBytes = keys([nodeCrypto.createHash("sha256").update(spkiA).digest()]);
  check("a 32-byte digest normalizes to the same hex", fromBytes.length === 1 && fromBytes[0] === hexA);
  var fromView = keys([new Uint8Array(nodeCrypto.createHash("sha256").update(spkiB).digest())]);
  check("a Uint8Array digest is accepted", fromView[0] === hexB);
  var dup = keys([hexA, hexA.toUpperCase(), hexB]);
  check("duplicates collapse", dup.length === 2 && dup[0] === hexA && dup[1] === hexB);
  check("the result is frozen", Object.isFrozen(dup));

  // ---- refusals, each the caller's typed code ----
  check("a non-array is refused", code(function () { keys(hexA); }) === "test/bad-input");
  check("an object is refused", code(function () { keys({ 0: hexA, length: 1 }); }) === "test/bad-input");
  check("63 hex characters are refused", code(function () { keys([hexA.slice(1)]); }) === "test/bad-input");
  check("65 hex characters are refused", code(function () { keys([hexA + "0"]); }) === "test/bad-input");
  check("a non-hex character is refused", code(function () { keys(["g" + hexA.slice(1)]); }) === "test/bad-input");
  check("a colon-separated fingerprint is refused", code(function () { keys([hexA.match(/../g).join(":")]); }) === "test/bad-input");
  check("31 bytes are refused", code(function () { keys([Buffer.alloc(31)]); }) === "test/bad-input");
  check("33 bytes are refused", code(function () { keys([Buffer.alloc(33)]); }) === "test/bad-input");
  check("a number entry is refused", code(function () { keys([42]); }) === "test/bad-input");
  check("a null entry is refused", code(function () { keys([null]); }) === "test/bad-input");
  var msg = "";
  try { keys([hexA, "nope"]); } catch (e) { msg = e.message; }
  check("the refusal names the label and the index", msg.indexOf("opts.distrustedKeys[1]") !== -1);

  // ---- a list that could read shorter than written ----
  var holey = [hexA, , hexB];  // eslint-disable-line no-sparse-arrays
  check("a hole is refused", code(function () { keys(holey); }) === "test/bad-input");
  var protoHole = [hexA, , hexB];  // eslint-disable-line no-sparse-arrays
  Object.defineProperty(Array.prototype, 1, { value: hexB, configurable: true, writable: true });
  try {
    check("a hole answered by Array.prototype is still refused", code(function () { keys(protoHole); }) === "test/bad-input");
  } finally { delete Array.prototype[1]; }
  var reads = 0;
  var accessor = [hexA];
  Object.defineProperty(accessor, 0, { enumerable: true, configurable: true, get: function () { reads += 1; return reads === 1 ? hexA : "zz"; } });
  check("an accessor entry is refused", code(function () { keys(accessor); }) === "test/bad-input");
  var proxied = new Proxy([hexA], {});
  check("a Proxy over an array is refused", code(function () { keys(proxied); }) === "test/bad-input");
  var tooMany = [];
  for (var i = 0; i <= constants.LIMITS.DISTRUSTED_KEYS_MAX; i++) tooMany.push(hexA);
  check("a list over LIMITS.DISTRUSTED_KEYS_MAX is refused", code(function () { keys(tooMany); }) === "test/bad-input");
  var atCap = tooMany.slice(0, constants.LIMITS.DISTRUSTED_KEYS_MAX);
  check("a list at LIMITS.DISTRUSTED_KEYS_MAX is accepted", keys(atCap).length === 1);

  // ---- the snapshot does not follow the caller's array ----
  var mine = [hexA];
  var snap = keys(mine);
  mine[0] = hexB;
  mine.push(hexA);
  check("mutating the caller's array after the call does not change the snapshot", snap.length === 1 && snap[0] === hexA);
  var bytesEntry = nodeCrypto.createHash("sha256").update(spkiA).digest();
  var snapBytes = keys([bytesEntry]);
  bytesEntry.fill(0);
  check("zeroing a byte entry after the call does not change the snapshot", snapBytes[0] === hexA);

  // ---- membership ----
  var list = keys([hexA]);
  check("has() is true for a listed SubjectPublicKeyInfo", distrust.has(list, spkiA) === true);
  check("has() is false for an unlisted one", distrust.has(list, spkiB) === false);
  check("has() is false for a null list", distrust.has(null, spkiA) === false);
  check("has() is false for an empty list", distrust.has(keys([]), spkiA) === false);
  check("digest() is the lower-case SHA-256 of the bytes", distrust.digest(spkiA) === hexA);

  // ---- one key, two encodings ----
  // A certificate can carry the same key encoded another way: an EC point compressed rather than
  // uncompressed, or an RSA AlgorithmIdentifier without its NULL parameters. The listed digest is
  // the one the certificate as usually issued carries, so membership also asks for the digest of the
  // key re-encoded the canonical way.
  var b = require("../../lib/asn1-der").build;
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  var ecSpki = ec.publicKey.export({ type: "spki", format: "der" });
  var ecPoint = nodeCrypto.ECDH.convertKey(ecSpki.subarray(ecSpki.length - 97), "secp384r1", undefined, undefined, "compressed");
  var compressedSpki = b.sequence([b.sequence([b.oid("1.2.840.10045.2.1"), b.oid("1.3.132.0.34")]), b.bitString(ecPoint, 0)]);
  check("CONTROL the compressed encoding has a different raw digest", distrust.digest(compressedSpki) !== distrust.digest(ecSpki));
  check("has() matches a compressed EC point against the listed uncompressed key",
    distrust.has(keys([distrust.digest(ecSpki)]), compressedSpki) === true);
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaSpki = rsa.publicKey.export({ type: "spki", format: "der" });
  var rsaKeyBits = require("../../lib/asn1-der").decode(rsaSpki).children[1].bytes;
  var noNullSpki = b.sequence([b.sequence([b.oid("1.2.840.113549.1.1.1")]), b.raw(rsaKeyBits)]);
  check("CONTROL the RSA encoding without NULL has a different raw digest", distrust.digest(noNullSpki) !== distrust.digest(rsaSpki));
  check("has() matches an RSA key without NULL parameters against the listed key",
    distrust.has(keys([distrust.digest(rsaSpki)]), noNullSpki) === true);
  check("has() is false for bytes node cannot read as a key", distrust.has(keys([hexA]), Buffer.from("not a key")) === false);
  // The other direction: a list entry computed from the compressed certificate with keyDigest
  // matches the same key carried uncompressed, because keyDigest digests the canonical encoding.
  check("keyDigest() of the compressed and the uncompressed encoding of one key is the same digest",
    distrust.keyDigest(compressedSpki) === distrust.keyDigest(ecSpki) && distrust.keyDigest(ecSpki) === distrust.digest(ecSpki));
  check("has() matches the uncompressed key against an entry computed from the compressed one",
    distrust.has(keys([distrust.keyDigest(compressedSpki)]), ecSpki) === true);
  check("keyDigest() of the RSA key without NULL parameters is the canonical digest",
    distrust.keyDigest(noNullSpki) === distrust.digest(rsaSpki));
  // An RSA key under the RSASSA-PSS algorithm identifier is the same key: the subjectPublicKey bits
  // are the same RSAPublicKey. Node writes no JWK for it, so the canonical step re-labels it.
  var pssSpki = b.sequence([b.sequence([b.oid("1.2.840.113549.1.1.10")]), b.raw(rsaKeyBits)]);
  check("CONTROL node reads the RSASSA-PSS encoding as an rsa-pss key",
    nodeCrypto.createPublicKey({ key: pssSpki, format: "der", type: "spki" }).asymmetricKeyType === "rsa-pss");
  check("keyDigest() of the RSASSA-PSS encoding is the rsaEncryption digest of the same key",
    distrust.keyDigest(pssSpki) === distrust.digest(rsaSpki));
  check("has() matches the RSASSA-PSS encoding against the listed rsaEncryption key",
    distrust.has(keys([distrust.digest(rsaSpki)]), pssSpki) === true);
  // Curves node writes no JWK for, and the algorithm identifiers that restrict a key to one use, are
  // the same key too.
  var asn1d = require("../../lib/asn1-der");
  function pointOf(spki) { return asn1d.read.bitString(asn1d.decode(spki).children[1]).bytes; }
  function algOf(spki) { return asn1d.decode(spki).children[0].bytes; }
  ["brainpoolP256r1", "secp224r1"].forEach(function (curve) {
    var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: curve });
    var plain = kp.publicKey.export({ type: "spki", format: "der" });
    var point = pointOf(plain);
    var alg = algOf(plain);
    var comp = b.sequence([b.raw(alg), b.bitString(nodeCrypto.ECDH.convertKey(point, curve, undefined, undefined, "compressed"), 0)]);
    var hyb = b.sequence([b.raw(alg), b.bitString(nodeCrypto.ECDH.convertKey(point, curve, undefined, undefined, "hybrid"), 0)]);
    var explicitParams = asn1d.decode(nodeCrypto.generateKeyPairSync("ec", { namedCurve: curve, paramEncoding: "explicit",
      publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "der" } }).publicKey).children[0].children[1].bytes;
    var expl = b.sequence([b.sequence([b.oid("1.2.840.10045.2.1"), b.raw(explicitParams)]), b.bitString(point, 0)]);
    var ecdh = b.sequence([b.sequence([b.oid("1.3.132.1.12"), b.raw(asn1d.decode(alg).children[1].bytes)]), b.bitString(point, 0)]);
    [["compressed", comp], ["hybrid", hyb], ["explicit parameters", expl], ["id-ecDH", ecdh]].forEach(function (pair) {
      check("keyDigest() of the " + pair[0] + " form of a " + curve + " key is the named uncompressed digest",
        distrust.keyDigest(pair[1]) === distrust.digest(plain));
      check("has() matches the named uncompressed " + curve + " key against an entry from the " + pair[0] + " form",
        distrust.has(keys([distrust.keyDigest(pair[1])]), plain) === true);
    });
  });
  var ecmqv = b.sequence([b.sequence([b.oid("1.3.132.1.13"), b.raw(asn1d.decode(algOf(ecSpki)).children[1].bytes)]), b.bitString(pointOf(ecSpki), 0)]);
  check("keyDigest() of the id-ecMQV form of a P-384 key is its ecPublicKey digest", distrust.keyDigest(ecmqv) === distrust.digest(ecSpki));
  var oaepSpki = b.sequence([b.sequence([b.oid("1.2.840.113549.1.1.7")]), b.raw(rsaKeyBits)]);
  check("keyDigest() of the RSAES-OAEP form of an RSA key is its rsaEncryption digest", distrust.keyDigest(oaepSpki) === distrust.digest(rsaSpki));
  var ecdhNoParams = b.sequence([b.sequence([b.oid("1.3.132.1.12")]), b.bitString(pointOf(ecSpki), 0)]);
  check("keyDigest() of an id-ecDH key with no curve is its raw digest, since no curve names the point",
    distrust.keyDigest(ecdhNoParams) === distrust.digest(ecdhNoParams));
  var dh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
  var dhSpki = dh.publicKey.export({ type: "spki", format: "der" });
  check("keyDigest() of a key type node writes no JWK for is the digest of node's own encoding",
    distrust.keyDigest(dhSpki) === distrust.digest(nodeCrypto.createPublicKey({ key: dhSpki, format: "der", type: "spki" }).export({ type: "spki", format: "der" })));
  check("keyDigest() of bytes node cannot read is their raw digest", distrust.keyDigest(Buffer.from("not a key")) === distrust.digest(Buffer.from("not a key")));

  // ---- a replaced prototype method after load does not change the answer ----
  var realLower = String.prototype.toLowerCase;
  String.prototype.toLowerCase = function () { return "0".repeat(64); };
  var underReplace;
  try { underReplace = keys([hexA.toUpperCase()]); }
  finally { String.prototype.toLowerCase = realLower; }
  check("a replaced String.prototype.toLowerCase does not decide the normalized digest", underReplace[0] === hexA);

  // ---- union, for a default list and a per-request list ----
  var u = distrust.union(keys([hexA]), keys([hexB, hexA]));
  check("union() keeps every entry of both, once", u.length === 2 && u.indexOf(hexA) !== -1 && u.indexOf(hexB) !== -1);
  check("union() with an empty second list keeps the first", distrust.union(keys([hexA]), keys([])).length === 1);
  check("union() of two nulls is null", distrust.union(null, null) === null);
  check("union() of null and a list is that list's entries", distrust.union(null, keys([hexB]))[0] === hexB);
  check("union() is frozen", Object.isFrozen(u));
}

module.exports = { run: run };
if (require.main === module) { run(); console.log("CHECKS " + helpers.getChecks()); }
