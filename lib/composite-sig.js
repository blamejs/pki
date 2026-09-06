// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");
var oid = require("./oid");
var webcrypto = require("./webcrypto");
var validator = require("./validator-all");
var edwardsPoint = require("./edwards-point");
var subtle = webcrypto.webcrypto.subtle;
var _b = asn1.build;

function _codeOf(e, fallback) {
  var prefix = fallback.slice(0, fallback.indexOf("/") + 1);
  return (e && typeof e.code === "string" && e.code.indexOf(prefix) === 0) ? e.code : fallback;
}

var COMPOSITE_PREFIX = Buffer.from("CompositeAlgorithmSignatures2025", "ascii");
var MLDSA_COMPONENT = Object.assign(Object.create(null), {
  "ML-DSA-44": { pk: 1312, sig: 2420, oid: "id-ml-dsa-44" },
  "ML-DSA-65": { pk: 1952, sig: 3309, oid: "id-ml-dsa-65" },
  "ML-DSA-87": { pk: 2592, sig: 4627, oid: "id-ml-dsa-87" },
});
var EC_CURVE_OID = Object.assign(Object.create(null), { "P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1" });
var PH_CMS = Object.assign(Object.create(null), { "SHA-256": "sha256", "SHA-512": "sha512", "SHAKE256": "shake256" });
var COMPOSITE_ALGS = Object.create(null);
function _comp(name, mldsa, ph, label, trad) {
  var sz = MLDSA_COMPONENT[mldsa];
  COMPOSITE_ALGS[oid.byName(name)] = {
    name: name, mldsa: mldsa, mldsaPk: sz.pk, mldsaSig: sz.sig, mldsaOid: sz.oid,
    ph: ph, phCms: PH_CMS[ph], label: Buffer.from(label, "ascii"), trad: trad,
  };
}
_comp("id-MLDSA44-RSA2048-PSS-SHA256", "ML-DSA-44", "SHA-256", "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", { rsaPss: true, hash: "SHA-256", salt: 32, rsaBits: 2048 });
_comp("id-MLDSA44-RSA2048-PKCS15-SHA256", "ML-DSA-44", "SHA-256", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", { rsaPkcs1: true, hash: "SHA-256", rsaBits: 2048 });
_comp("id-MLDSA44-Ed25519-SHA512", "ML-DSA-44", "SHA-512", "COMPSIG-MLDSA44-Ed25519-SHA512", { eddsa: "Ed25519" });
_comp("id-MLDSA44-ECDSA-P256-SHA256", "ML-DSA-44", "SHA-256", "COMPSIG-MLDSA44-ECDSA-P256-SHA256", { ec: "P-256", hash: "SHA-256" });
_comp("id-MLDSA65-RSA3072-PSS-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", { rsaPss: true, hash: "SHA-256", salt: 32, rsaBits: 3072 });
_comp("id-MLDSA65-RSA3072-PKCS15-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", { rsaPkcs1: true, hash: "SHA-256", rsaBits: 3072 });
_comp("id-MLDSA65-RSA4096-PSS-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", { rsaPss: true, hash: "SHA-384", salt: 48, rsaBits: 4096 });
_comp("id-MLDSA65-RSA4096-PKCS15-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", { rsaPkcs1: true, hash: "SHA-384", rsaBits: 4096 });
_comp("id-MLDSA65-ECDSA-P256-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-ECDSA-P256-SHA512", { ec: "P-256", hash: "SHA-256" });
_comp("id-MLDSA65-ECDSA-P384-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-ECDSA-P384-SHA512", { ec: "P-384", hash: "SHA-384" });
_comp("id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", { unsupported: "brainpoolP256r1 is not in the WebCrypto ECDSA curve set" });
_comp("id-MLDSA65-Ed25519-SHA512", "ML-DSA-65", "SHA-512", "COMPSIG-MLDSA65-Ed25519-SHA512", { eddsa: "Ed25519" });
_comp("id-MLDSA87-ECDSA-P384-SHA512", "ML-DSA-87", "SHA-512", "COMPSIG-MLDSA87-ECDSA-P384-SHA512", { ec: "P-384", hash: "SHA-384" });
_comp("id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "ML-DSA-87", "SHA-512", "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", { unsupported: "brainpoolP384r1 is not in the WebCrypto ECDSA curve set" });
_comp("id-MLDSA87-Ed448-SHAKE256", "ML-DSA-87", "SHAKE256", "COMPSIG-MLDSA87-Ed448-SHAKE256", { eddsa: "Ed448" });
_comp("id-MLDSA87-RSA3072-PSS-SHA512", "ML-DSA-87", "SHA-512", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", { rsaPss: true, hash: "SHA-256", salt: 32, rsaBits: 3072 });
_comp("id-MLDSA87-RSA4096-PSS-SHA512", "ML-DSA-87", "SHA-512", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", { rsaPss: true, hash: "SHA-384", salt: 48, rsaBits: 4096 });
_comp("id-MLDSA87-ECDSA-P521-SHA512", "ML-DSA-87", "SHA-512", "COMPSIG-MLDSA87-ECDSA-P521-SHA512", { ec: "P-521", hash: "SHA-512" });

function _spkiFor(algNode, keyBytes) { return _b.sequence([algNode, _b.bitString(keyBytes, 0)]); }
function _mldsaSpki(mldsaOid, raw) { return _spkiFor(_b.sequence([_b.oid(oid.byName(mldsaOid))]), raw); }
function _ecSpki(curve, point) { return _spkiFor(_b.sequence([_b.oid(oid.byName("ecPublicKey")), _b.oid(oid.byName(EC_CURVE_OID[curve]))]), point); }
function _edSpki(name, raw) { return _spkiFor(_b.sequence([_b.oid(oid.byName(name))]), raw); }
function _rsaSpki(rsaPub) { return _spkiFor(_b.sequence([_b.oid(oid.byName("rsaEncryption")), _b.nullValue()]), rsaPub); }

function _rsaModulusBits(rsaPubDer) {
  return asn1.read.integer(asn1.decode(rsaPubDer).children[0]).toString(2).length;
}

function compositeMprime(d, phBuf, ctx) {
  ctx = ctx || Buffer.alloc(0);
  return Buffer.concat([COMPOSITE_PREFIX, d.label, Buffer.from([ctx.length]), ctx, Buffer.from(phBuf)]);
}

function _verifyTradComponent(trad, tradPK, tradSig, mprime, E, badSig) {
  if (trad.ec) {
    if (tradPK.length < 1 || tradPK[0] !== 0x04) return Promise.resolve(false);
    return subtle.importKey("spki", _ecSpki(trad.ec, tradPK), { name: "ECDSA" }, false, ["verify"]).then(function (k) {
      var p1363 = validator.sig.ecdsaDerToP1363(tradSig, trad.ec, E, badSig);
      return subtle.verify({ name: "ECDSA", hash: trad.hash }, k, p1363, mprime);
    });
  }
  if (trad.eddsa) {
    if (!edwardsPoint.validate(tradPK, trad.eddsa === "Ed25519" ? 6 : 7)) {
      throw new E(badSig, "the composite EdDSA component public key is not a valid, full-order Edwards point");
    }
    return subtle.importKey("spki", _edSpki(trad.eddsa, tradPK), { name: trad.eddsa }, false, ["verify"])
      .then(function (k) { return subtle.verify({ name: trad.eddsa }, k, tradSig, mprime); });
  }
  if (trad.rsaPss || trad.rsaPkcs1) {
    var bits;
    try { bits = _rsaModulusBits(tradPK); }
    catch (_e) { return Promise.resolve(false); }
    if (bits !== trad.rsaBits) return Promise.resolve(false);
    if (trad.rsaPss) {
      return subtle.importKey("spki", _rsaSpki(tradPK), { name: "RSA-PSS", hash: trad.hash }, false, ["verify"])
        .then(function (k) { return subtle.verify({ name: "RSA-PSS", saltLength: trad.salt }, k, tradSig, mprime); });
    }
    return subtle.importKey("spki", _rsaSpki(tradPK), { name: "RSASSA-PKCS1-v1_5", hash: trad.hash }, false, ["verify"])
      .then(function (k) { return subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, k, tradSig, mprime); });
  }
  return Promise.resolve(false);
}

function compositeVerify(spkiBytes, sigBytes, message, d, E, unsupported, badSig) {
  if (d.trad.unsupported) {
    return Promise.resolve({ ok: false, code: unsupported,
      error: new E(unsupported, "composite " + d.name + ": " + d.trad.unsupported) });
  }
  var rawKey;
  try {
    var bs = asn1.read.bitString(asn1.decode(spkiBytes).children[1]);
    if (bs.unusedBits !== 0) throw new E(badSig, "composite subjectPublicKey has unused bits");
    rawKey = bs.bytes;
  } catch (e) { return Promise.resolve({ ok: false, code: _codeOf(e, badSig), error: e }); }
  if (rawKey.length <= d.mldsaPk || sigBytes.length <= d.mldsaSig) {
    return Promise.resolve({ ok: false, code: badSig,
      error: new E(badSig, "composite key/signature shorter than the fixed ML-DSA component") });
  }
  var mldsaPK = rawKey.subarray(0, d.mldsaPk), tradPK = rawKey.subarray(d.mldsaPk);
  var mldsaSig = sigBytes.subarray(0, d.mldsaSig), tradSig = sigBytes.subarray(d.mldsaSig);
  return subtle.digest({ name: d.ph }, message).then(function (phBuf) {
    var mprime = compositeMprime(d, phBuf);
    var mldsaP = subtle.importKey("spki", _mldsaSpki(d.mldsaOid, mldsaPK), { name: d.mldsa }, false, ["verify"])
      .then(function (mk) { return subtle.verify({ name: d.mldsa, context: d.label }, mk, mldsaSig, mprime); });
    var tradP = _verifyTradComponent(d.trad, tradPK, tradSig, mprime, E, badSig);
    return Promise.all([mldsaP, tradP]).then(function (r) { return { ok: r[0] === true && r[1] === true }; });
  }).catch(function (e) { return { ok: false, code: _codeOf(e, badSig), error: e }; });
}

function resolveCompositeDescriptor(sigAlg, E, unsupported) {
  var comp = COMPOSITE_ALGS[sigAlg.oid];
  if (!comp) return null;
  if (sigAlg.parameters !== null && sigAlg.parameters !== undefined) {
    throw new E(unsupported, "composite signature algorithm parameters must be absent (draft-ietf-lamps-pq-composite-sigs sec. 5.3)");
  }
  return { composite: comp, sameKeyOid: true };
}

function compositeSign(d, keys, message, ctx) {
  return subtle.digest({ name: d.ph }, message).then(function (phBuf) {
    var mprime = compositeMprime(d, phBuf, ctx);
    var mldsaP = subtle.importKey("pkcs8", keys.mldsa, { name: d.mldsa }, false, ["sign"])
      .then(function (k) { return subtle.sign({ name: d.mldsa, context: d.label }, k, mprime); });
    var tradP = _signTradComponent(d.trad, keys.trad, mprime);
    return Promise.all([mldsaP, tradP]).then(function (s) { return Buffer.concat([Buffer.from(s[0]), Buffer.from(s[1])]); });
  });
}
function _signTradComponent(trad, pkcs8, mprime) {
  if (trad.ec) {
    return subtle.importKey("pkcs8", pkcs8, { name: "ECDSA", namedCurve: trad.ec }, false, ["sign"])
      .then(function (k) { return subtle.sign({ name: "ECDSA", hash: trad.hash }, k, mprime); })
      .then(function (raw) { var r = Buffer.from(raw); return validator.sig.rawToEcdsaDer(r, r.length / 2); });
  }
  if (trad.eddsa) {
    return subtle.importKey("pkcs8", pkcs8, { name: trad.eddsa }, false, ["sign"])
      .then(function (k) { return subtle.sign({ name: trad.eddsa }, k, mprime); }).then(function (s) { return Buffer.from(s); });
  }
  var imp = trad.rsaPss ? { name: "RSA-PSS", hash: trad.hash } : { name: "RSASSA-PKCS1-v1_5", hash: trad.hash };
  var alg = trad.rsaPss ? { name: "RSA-PSS", saltLength: trad.salt } : { name: "RSASSA-PKCS1-v1_5" };
  return subtle.importKey("pkcs8", pkcs8, imp, false, ["sign"]).then(function (k) { return subtle.sign(alg, k, mprime); }).then(function (s) { return Buffer.from(s); });
}

module.exports = {
  COMPOSITE_ALGS: COMPOSITE_ALGS,
  compositeVerify: compositeVerify,
  resolveCompositeDescriptor: resolveCompositeDescriptor,
  compositeMprime: compositeMprime,
  compositeSign: compositeSign,
};
