// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var cbor = require("./cbor-det");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var edwardsPoint = require("./edwards-point");
var nodeCrypto = require("crypto");

var EC2_CRV_LEN = { 1: 32, 2: 48, 3: 66 };
var EC2_CRV_OID = { 1: "prime256v1", 2: "secp384r1", 3: "secp521r1" };
var OKP_CRV = { 6: { oid: "Ed25519", len: 32 }, 7: { oid: "Ed448", len: 57 } };
var RSA_MIN_MODULUS_BITS = 2048;
var RSA_MAX_EXPONENT_BYTES = 8;
function _modulusBits(n) { return (n.length - 1) * 8 + (32 - Math.clz32(n[0])); }

var ALG_PROFILE = {
  "-7": { kty: 2, crv: 1 }, "-35": { kty: 2, crv: 2 }, "-36": { kty: 2, crv: 3 },
  "-9": { kty: 2, crv: 1 }, "-51": { kty: 2, crv: 2 }, "-52": { kty: 2, crv: 3 },
  "-8": { kty: 1, crv: 6 }, "-19": { kty: 1, crv: 6 }, "-53": { kty: 1, crv: 7 },
  "-257": { kty: 3 }, "-258": { kty: 3 }, "-259": { kty: 3 },
  "-37": { kty: 3 }, "-38": { kty: 3 }, "-39": { kty: 3 }, "-65535": { kty: 3 },
};

// @enforced-by validator-shape-reinlined
// @validator-shape kty\s*===\s*2n
// @validator-shape EC2_CRV_LEN|ALG_PROFILE
function credentialKey(node, E, code, unsupportedCode) {
  function bad(msg, cause) { return new E(code, msg, cause); }
  if (!node || node.majorType !== 5) throw bad("a COSE_Key must be a CBOR map (RFC 9052 sec. 7)");
  function ib(label) { var n = cbor.read.mapGet(node, label); if (!n) return null; try { return cbor.read.byteString(n); } catch (e) { throw bad("COSE_Key parameter " + label + " must be a byte string", e); } }
  function ii(label) { var n = cbor.read.mapGet(node, label); if (!n) return null; try { return cbor.read.int(n); } catch (e) { throw bad("COSE_Key parameter " + label + " must be an integer", e); } }
  var ktyN = cbor.read.mapGet(node, 1), algN = cbor.read.mapGet(node, 3);
  if (!ktyN) throw bad("a COSE_Key is missing the kty (label 1) parameter");
  if (!algN) throw bad("a COSE_Key is missing the alg (label 3) parameter");
  var kty, algv;
  try { kty = cbor.read.int(ktyN); algv = cbor.read.int(algN); }
  catch (e) { throw bad("COSE_Key kty (label 1) and alg (label 3) must be integers", e); }
  var key = { kty: Number(kty), alg: Number(algv) };
  if (kty === 2n) {
    key.crv = ii(-1) != null ? Number(ii(-1)) : null;
    var yNode = cbor.read.mapGet(node, -3);
    if (yNode && yNode.majorType === 7) throw bad("an EC2 credential key must use the uncompressed point form (a compressed y sign-bit is not permitted for WebAuthn)");
    key.x = ib(-2); key.y = ib(-3);
    if (key.crv == null || !key.x || !key.y) throw bad("an EC2 COSE_Key must carry crv (-1), x (-2), and y (-3)");
    var el = EC2_CRV_LEN[key.crv];
    if (!el || key.x.length !== el || key.y.length !== el) throw bad("an EC2 COSE_Key x/y length is inconsistent with its curve");
  } else if (kty === 1n) {
    key.crv = ii(-1) != null ? Number(ii(-1)) : null; key.x = ib(-2);
    var okp = OKP_CRV[key.crv];
    if (!okp || !key.x || key.x.length !== okp.len) throw bad("an OKP COSE_Key must be Ed25519 (crv 6) or Ed448 (crv 7) with a matching-length x (-2)");
  } else if (kty === 3n) {
    key.n = ib(-1); key.e = ib(-2);
    if (!key.n || !key.n.length || !key.e || !key.e.length) throw bad("an RSA COSE_Key must carry n (-1) and e (-2)");
    if (key.n[0] === 0) throw bad("an RSA COSE_Key modulus (-1) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    if (key.e[0] === 0) throw bad("an RSA COSE_Key exponent (-2) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    var modulusBits = _modulusBits(key.n);
    if (modulusBits < RSA_MIN_MODULUS_BITS) {
      throw bad("an RSA COSE_Key modulus (-1) is " + modulusBits + " bits, below the " +
        RSA_MIN_MODULUS_BITS + "-bit minimum");
    }
    if (key.e.length > RSA_MAX_EXPONENT_BYTES) throw bad("an RSA COSE_Key exponent (-2) is longer than " + RSA_MAX_EXPONENT_BYTES + " bytes");
    if ((key.e[key.e.length - 1] & 1) === 0) throw bad("an RSA COSE_Key exponent (-2) must be odd");
    if (key.e.length === 1 && key.e[0] <= 1) throw bad("an RSA COSE_Key exponent (-2) must be greater than 1; e = 1 makes RSA the identity function");
  } else {
    throw bad("unsupported COSE_Key kty " + Number(kty));
  }
  var expectedParams = kty === 2n ? 5 : 4;
  if (node.children.length !== expectedParams) throw bad("the COSE_Key carries parameters beyond the canonical set for its key type (WebAuthn sec. 6.5.1)");
  return assertKeyMaterial(key, E, code, unsupportedCode);
}

// @enforced-by behavioral -- key-material rules have no rename-proof code shape distinct
function assertKeyMaterial(key, E, code, unsupportedCode) {
  function bad(msg, cause) { return new E(code, msg, cause); }
  if (!key || typeof key !== "object") throw bad("a credential key must be a decoded COSE_Key object");
  try {
    key = { kty: key.kty, alg: key.alg, crv: key.crv, x: key.x, y: key.y, n: key.n, e: key.e };
  } catch (e) { throw bad("a credential key field could not be read", e); }
  var MAX = BigInt(Number.MAX_SAFE_INTEGER);
  function _isInt(v) {
    if (typeof v === "bigint") return v <= MAX && v >= -MAX;
    return typeof v === "number" && Number.isSafeInteger(v);
  }
  if (!_isInt(key.kty)) throw bad("a COSE_Key kty (label 1) must be an integer");
  if (!_isInt(key.alg)) throw bad("a COSE_Key alg (label 3) must be an integer");
  if (key.crv !== undefined && key.crv !== null && !_isInt(key.crv)) throw bad("a COSE_Key crv (label -1) must be an integer");
  key.kty = Number(key.kty);
  key.alg = Number(key.alg);
  if (key.crv !== undefined && key.crv !== null) key.crv = Number(key.crv);
  var kty = BigInt(key.kty);
  if (kty === 2n) {
    var el2 = EC2_CRV_LEN[key.crv];
    if (!Buffer.isBuffer(key.x) || !Buffer.isBuffer(key.y)) throw bad("an EC2 COSE_Key must carry crv (-1), x (-2), and y (-3)");
    if (!el2 || key.x.length !== el2 || key.y.length !== el2) throw bad("an EC2 COSE_Key x/y length is inconsistent with its curve");
  } else if (kty === 1n) {
    var okp2 = OKP_CRV[key.crv];
    if (!okp2 || !Buffer.isBuffer(key.x) || key.x.length !== okp2.len) throw bad("an OKP COSE_Key must be Ed25519 (crv 6) or Ed448 (crv 7) with a matching-length x (-2)");
  } else if (kty === 3n) {
    if (!Buffer.isBuffer(key.n) || !key.n.length || !Buffer.isBuffer(key.e) || !key.e.length) throw bad("an RSA COSE_Key must carry n (-1) and e (-2)");
    if (key.n[0] === 0) throw bad("an RSA COSE_Key modulus (-1) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    if (key.e[0] === 0) throw bad("an RSA COSE_Key exponent (-2) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    var bits = _modulusBits(key.n);
    if (bits < RSA_MIN_MODULUS_BITS) throw bad("an RSA COSE_Key modulus (-1) is " + bits + " bits, below the " + RSA_MIN_MODULUS_BITS + "-bit minimum");
    if (key.e.length > RSA_MAX_EXPONENT_BYTES) throw bad("an RSA COSE_Key exponent (-2) is longer than " + RSA_MAX_EXPONENT_BYTES + " bytes");
    if ((key.e[key.e.length - 1] & 1) === 0) throw bad("an RSA COSE_Key exponent (-2) must be odd");
    if (key.e.length === 1 && key.e[0] <= 1) throw bad("an RSA COSE_Key exponent (-2) must be greater than 1; e = 1 makes RSA the identity function");
  } else {
    throw bad("unsupported COSE_Key kty " + Number(key.kty));
  }
  var prof = ALG_PROFILE[String(key.alg)];
  if (!prof) throw new E(unsupportedCode || code, "unsupported credential key algorithm " + key.alg);
  if (prof.kty !== key.kty) throw bad("credential key algorithm " + key.alg + " is inconsistent with key type " + key.kty);
  if (prof.crv != null && prof.crv !== key.crv) throw bad("credential key algorithm " + key.alg + " requires a different curve");
  try { nodeCrypto.createPublicKey({ key: toSpki(key, E, code), format: "der", type: "spki" }); }
  catch (e) { throw bad("the credential public key point is not valid for its curve", e); }
  if (Number(key.kty) === 1 && !edwardsPoint.validate(key.x, key.crv)) throw bad("the OKP credential public key is not a valid, full-order Edwards point");
  return key;
}

// @enforced-by behavioral -- an SPKI encoding of a validated COSE key has no rename-proof
function toSpki(key, E, code) {
  function bad(msg) { return new E(code, msg); }
  if (key.kty === 2 && key.x && key.y) {
    var curveOid = EC2_CRV_OID[key.crv];
    if (!curveOid) throw bad("unsupported EC2 curve " + key.crv);
    var b = asn1.build;
    return b.sequence([
      b.sequence([b.oid(oid.byName("ecPublicKey")), b.oid(oid.byName(curveOid))]),
      b.bitString(Buffer.concat([Buffer.from([0x04]), key.x, key.y])),
    ]);
  }
  if (key.kty === 3 && key.n && key.n.length && key.e && key.e.length) {
    var bb = asn1.build;
    return bb.sequence([
      bb.sequence([bb.oid(oid.byName("rsaEncryption")), bb.nullValue()]),
      bb.bitString(bb.sequence([bb.integer(BigInt("0x" + key.n.toString("hex"))), bb.integer(BigInt("0x" + key.e.toString("hex")))])),
    ]);
  }
  if (key.kty === 1 && OKP_CRV[key.crv] && key.x && key.x.length === OKP_CRV[key.crv].len) {
    var eb = asn1.build;
    return eb.sequence([eb.sequence([eb.oid(oid.byName(OKP_CRV[key.crv].oid))]), eb.bitString(key.x)]);
  }
  throw bad("cannot build an SPKI for this COSE key type");
}

module.exports = {
  credentialKey: credentialKey,
  assertKeyMaterial: assertKeyMaterial,
  toSpki: toSpki,
  EC2_CRV_LEN: EC2_CRV_LEN,
  EC2_CRV_OID: EC2_CRV_OID,
  OKP_CRV: OKP_CRV,
};
