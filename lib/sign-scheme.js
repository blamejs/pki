// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");
var oid = require("./oid");
var pkcs8 = require("./schema-pkcs8");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var validator = require("./validator-all");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var compositeSig = require("./composite-sig");
var b = asn1.build;
function O(name) { return oid.byName(name); }

var _BigInt = intrinsic.BigInt;
var _String = intrinsic.String;
var _filter = intrinsic.filter;
var _stringify = intrinsic.stringify;
var _toUpperCase = intrinsic.toUpperCase;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _isU8 = intrinsic.types.isUint8Array;

var HASH = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
var NODE_DIGEST = { sha256: "sha256", sha384: "sha384", sha512: "sha512", shake128: "shake128", shake256: "shake256" };
var PSS_SALT = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };
var ECDSA_ALG = { sha256: "ecdsaWithSHA256", sha384: "ecdsaWithSHA384", sha512: "ecdsaWithSHA512" };
var RSA_PKCS1_SIG = { sha256: "sha256WithRSAEncryption", sha384: "sha384WithRSAEncryption", sha512: "sha512WithRSAEncryption" };
var HASH_NAME_BY_OID = {};
HASH_NAME_BY_OID[O("sha256")] = "sha256";
HASH_NAME_BY_OID[O("sha384")] = "sha384";
HASH_NAME_BY_OID[O("sha512")] = "sha512";
var EC_BY_CURVE_OID = {};
EC_BY_CURVE_OID[O("prime256v1")] = { curve: "P-256", coordLen: 32 };
EC_BY_CURVE_OID[O("secp384r1")] = { curve: "P-384", coordLen: 48 };
EC_BY_CURVE_OID[O("secp521r1")] = { curve: "P-521", coordLen: 66 };
var MLDSA_BY_OID = {};
MLDSA_BY_OID[O("id-ml-dsa-44")] = "ML-DSA-44";
MLDSA_BY_OID[O("id-ml-dsa-65")] = "ML-DSA-65";
MLDSA_BY_OID[O("id-ml-dsa-87")] = "ML-DSA-87";
var MLDSA_SUITABLE_DIGEST = {
  "ML-DSA-44": { sha256: 1, sha384: 1, sha512: 1, shake256: 1 },
  "ML-DSA-65": { sha384: 1, sha512: 1, shake256: 1 },
  "ML-DSA-87": { sha512: 1, shake256: 1 },
};
// @enforced-by behavioral -- an own-property table read has no rename-proof shape distinct from a
function mldsaDigestSuitable(mlName, md) {
  if (!intrinsic.hasOwn(MLDSA_SUITABLE_DIGEST, mlName)) return false;
  var row = MLDSA_SUITABLE_DIGEST[mlName];
  return !!row && intrinsic.hasOwn(row, md) && !!row[md];
}

var SLHDSA_BY_OID = {};
[["sha2-128s", "sha256"], ["sha2-128f", "sha256"], ["sha2-192s", "sha512"], ["sha2-192f", "sha512"],
 ["sha2-256s", "sha512"], ["sha2-256f", "sha512"], ["shake-128s", "shake128"], ["shake-128f", "shake128"],
 ["shake-192s", "shake256"], ["shake-192f", "shake256"], ["shake-256s", "shake256"], ["shake-256f", "shake256"]
].forEach(function (r) { SLHDSA_BY_OID[O("id-slh-dsa-" + r[0])] = { wc: "SLH-DSA-" + r[0].toUpperCase(), digest: r[1] }; });

function _algId(name, shape) { return shape === "null" ? b.sequence([b.oid(O(name)), b.nullValue()]) : b.sequence([b.oid(O(name))]); }
function _pssAlgId(digestName) {
  var hashAlg = b.sequence([b.oid(O(digestName)), b.nullValue()]);
  var mgf = b.sequence([b.oid(O("mgf1")), hashAlg]);
  var params = b.sequence([b.explicit(0, hashAlg), b.explicit(1, mgf), b.explicit(2, b.integer(_BigInt(PSS_SALT[HASH[digestName]])))]);
  return b.sequence([b.oid(O("rsassaPss")), params]);
}
function _pssHashFromSpki(cert, E) {
  var params = cert.subjectPublicKeyInfo.algorithm.parameters;
  if (params == null) return null;
  var node;
  try { node = asn1.decode(params); }
  catch (e) { throw E("unsupported-algorithm", "the id-RSASSA-PSS key parameters are not decodable, so the restriction they carry cannot be honored", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children) {
    throw E("unsupported-algorithm", "the id-RSASSA-PSS key parameters are not an RSASSA-PSS-params SEQUENCE (RFC 4055 sec. 3.1)");
  }
  var hashField = _filter(node.children, function (c) { return c.tagClass === "context" && c.tagNumber === 0; })[0];
  if (!hashField) return "sha1";
  if (!hashField.children || !hashField.children[0] || !hashField.children[0].children) {
    throw E("unsupported-algorithm", "the id-RSASSA-PSS key parameters carry a malformed hashAlgorithm");
  }
  var oidNode = hashField.children[0].children[0];
  if (!oidNode || oidNode.tagClass !== "universal" || oidNode.tagNumber !== asn1.TAGS.OBJECT_IDENTIFIER) {
    throw E("unsupported-algorithm", "the id-RSASSA-PSS key parameters hashAlgorithm is not an OBJECT IDENTIFIER");
  }
  var pinnedOid = asn1.read.oid(oidNode);
  var name = HASH_NAME_BY_OID[pinnedOid];
  if (!name) throw E("unsupported-algorithm", "the id-RSASSA-PSS signer key pins an unsupported hash algorithm (" + pinnedOid + ")");
  return name;
}

// @internal
function pssSpkiPinnedHash(cert, E) {
  var d = _pssHashFromSpki(cert, E);
  if (!d) return null;
  if (!HASH[d]) throw E("unsupported-algorithm", "the id-RSASSA-PSS key is restricted to " + d + ", which this toolkit does not verify with");
  return HASH[d];
}

function resolveSignScheme(cert, so, noSignedAttrs, E) {
  so = so || {};
  var alg = cert.subjectPublicKeyInfo.algorithm;
  var keyOid = alg.oid;
  var comp = compositeSig.COMPOSITE_ALGS[keyOid];
  if (comp) {
    if (comp.trad.unsupported) throw E("unsupported-algorithm", "composite " + comp.name + ": " + comp.trad.unsupported);
    if (so.digestAlgorithm && so.digestAlgorithm !== comp.phCms) throw E("bad-input", "composite " + comp.name + " fixes the digestAlgorithm to " + comp.phCms + " (draft-ietf-lamps-cms-composite-sigs sec. 3.4); " + _stringify(so.digestAlgorithm) + " conflicts");
    return { composite: comp, digest: comp.phCms, digestAlgId: _algId(comp.phCms, "absent"), sigAlgId: _algId(comp.name, "absent") };
  }
  if (keyOid === O("rsaEncryption") || keyOid === O("rsassaPss")) {
    var isPssKey = keyOid === O("rsassaPss");
    var pinned = isPssKey ? _pssHashFromSpki(cert, E) : null;
    if (pinned && so.digestAlgorithm && so.digestAlgorithm !== pinned) throw E("bad-input", "the signer key restricts the RSASSA-PSS digest to " + pinned + ", but digestAlgorithm " + _stringify(so.digestAlgorithm) + " was requested");
    var d = so.digestAlgorithm || pinned || "sha256";
    if (!HASH[d]) throw E("unsupported-algorithm", "unsupported RSA digest algorithm " + _stringify(d));
    if (so.pss || isPssKey) return { digest: d, digestAlgId: _algId(d, "absent"), sigAlgId: _pssAlgId(d), imp: { name: "RSA-PSS", hash: HASH[d] }, sign: { name: "RSA-PSS", saltLength: PSS_SALT[HASH[d]] }, ecdsaDer: false };
    var rsaSigAlgId = so.combinedRsaSig ? _algId(RSA_PKCS1_SIG[d], "null") : _algId("rsaEncryption", "null");
    return { digest: d, digestAlgId: _algId(d, "absent"), sigAlgId: rsaSigAlgId, imp: { name: "RSASSA-PKCS1-v1_5", hash: HASH[d] }, sign: { name: "RSASSA-PKCS1-v1_5" }, ecdsaDer: false };
  }
  if (keyOid === O("ecPublicKey")) {
    var curveOid;
    try { curveOid = asn1.read.oid(asn1.decode(alg.parameters)); }
    catch (e) { throw E("unsupported-algorithm", "the signer EC key parameters are not a named-curve OID", e); }
    var ec = EC_BY_CURVE_OID[curveOid];
    if (!ec) throw E("unsupported-algorithm", "the signer key is on an unsupported EC curve");
    var de = so.digestAlgorithm || "sha256";
    if (!HASH[de]) throw E("unsupported-algorithm", "unsupported ECDSA digest algorithm " + _stringify(de));
    return { digest: de, digestAlgId: _algId(de, "absent"), sigAlgId: _algId(ECDSA_ALG[de], "absent"), imp: { name: "ECDSA", namedCurve: ec.curve }, sign: { name: "ECDSA", hash: HASH[de] }, ecdsaDer: true, coordLen: ec.coordLen };
  }
  if (keyOid === O("Ed25519") || keyOid === O("Ed448")) {
    var name = keyOid === O("Ed25519") ? "Ed25519" : "Ed448";
    var dd = so.digestAlgorithm || (name === "Ed25519" ? "sha512" : "shake256");
    if (!NODE_DIGEST[dd]) throw E("unsupported-algorithm", "unsupported " + name + " digest algorithm " + _stringify(dd));
    return { digest: dd, digestAlgId: _algId(dd, "absent"), sigAlgId: _algId(name, "absent"), imp: { name: name }, sign: { name: name }, ecdsaDer: false };
  }
  if (MLDSA_BY_OID[keyOid]) {
    var mlName = MLDSA_BY_OID[keyOid];
    var md;
    if (noSignedAttrs) {
      md = "sha512";
    } else {
      md = so.digestAlgorithm || "sha512";
      if (!NODE_DIGEST[md]) throw E("unsupported-algorithm", "unsupported ML-DSA message digest " + _stringify(md));
      if (!mldsaDigestSuitable(mlName, md)) throw E("unsupported-algorithm", "the " + md + " message digest is below the security strength of " + mlName + " (RFC 9882 sec. 3.3)");
    }
    return { digest: md, digestAlgId: _algId(md, "absent"), sigAlgId: _algId(oid.name(keyOid), "absent"), imp: { name: mlName }, sign: { name: mlName }, ecdsaDer: false };
  }
  if (SLHDSA_BY_OID[keyOid]) {
    var slh = SLHDSA_BY_OID[keyOid];
    if (so.digestAlgorithm && so.digestAlgorithm !== slh.digest) throw E("bad-input", "SLH-DSA " + slh.wc + " requires the " + slh.digest + " message digest (RFC 9814 sec. 4); digestAlgorithm " + _stringify(so.digestAlgorithm) + " conflicts");
    return { digest: slh.digest, digestAlgId: _algId(slh.digest, "absent"), sigAlgId: _algId(oid.name(keyOid), "absent"), imp: { name: slh.wc }, sign: { name: slh.wc }, ecdsaDer: false };
  }
  throw E("unsupported-algorithm", "unsupported signer key algorithm " + keyOid);
}

function _assertKeyMatchesScheme(key, imp, E) {
  var ka = key.algorithm || {};
  if (_toUpperCase(_String(ka.name)) !== _toUpperCase(_String(imp.name))) {
    var hint = (_toUpperCase(_String(ka.name)) === "RSA-PSS" && _toUpperCase(_String(imp.name)) === "RSASSA-PKCS1-V1_5")
      ? "; this CryptoKey is bound to RSASSA-PSS -- pass opts.pss to sign with RSASSA-PSS" : "";
    throw E("bad-input", "the signer CryptoKey algorithm (" + ka.name + ") does not match the certificate's key algorithm (" + imp.name + ")" + hint);
  }
  if (imp.hash && (!ka.hash || ka.hash.name !== imp.hash)) throw E("bad-input", "the signer CryptoKey hash (" + (ka.hash && ka.hash.name) + ") does not match the signing digest (" + imp.hash + ")");
  if (imp.namedCurve && ka.namedCurve !== imp.namedCurve) throw E("bad-input", "the signer CryptoKey curve (" + ka.namedCurve + ") does not match the certificate curve (" + imp.namedCurve + ")");
}
function _normPkcs8(k, label, E) {
  if (_isBuffer(k)) return guard.bytes.view(k, E, "bad-input", label);
  if (_isU8(k)) return guard.bytes.snapshot(k, E, "bad-input", label);
  if (typeof k === "string") { try { return pkcs8.pemDecode(k); } catch (e) { throw E("bad-input", label + " PEM could not be decoded", e); } }
  throw E("bad-input", label + " must be a PKCS#8 DER Buffer, Uint8Array, or PEM string");
}
function _normCompositeKeys(key, comp, E) {
  if (!key || typeof key !== "object" || _isBuffer(key) || _isU8(key) || key.mldsa == null || key.trad == null) {   // allow:byte-source-narrow -- composite-key discrimination: a raw-key BufferSource (incl an ArrayBuffer, which is neither) is correctly classed non-composite and normalized by _normPkcs8
    throw E("bad-input", "a composite " + comp.name + " signer key must be { mldsa: <PKCS#8>, trad: <PKCS#8> }");
  }
  return { mldsa: _normPkcs8(key.mldsa, "the composite ML-DSA component key", E), trad: _normPkcs8(key.trad, "the composite traditional component key", E) };
}
function _importKey(key, imp, E) {
  if (key && typeof key === "object" && !_isBuffer(key) && !_isU8(key) && typeof key.type === "string" && key.algorithm != null) {
    if (key.type !== "private") {
      throw E("bad-input", "the signing key is a WebCrypto CryptoKey of type " + _stringify(key.type) + "; a signing key must be a private key (type \"private\")");
    }
    _assertKeyMatchesScheme(key, imp, E);
    return webcrypto.adoptKey(key, imp, ["sign"], E, "bad-input");
  }
  var der, owned = false;
  if (_isBuffer(key)) der = guard.bytes.view(key, E, "bad-input", "the signer private key");
  else if (_isU8(key)) { der = guard.bytes.snapshot(key, E, "bad-input", "the signer private key"); owned = true; }
  else if (typeof key === "string") {
    try { der = pkcs8.pemDecode(key); }
    catch (e) { throw E("bad-input", "the signer PEM private key could not be decoded", e); }
    owned = true;
  } else if (intrinsic.types.isKeyObject(key)) {
    throw E("bad-input", "the signing key is a node:crypto KeyObject, not a WebCrypto CryptoKey; pass a CryptoKey (e.g. from pki.key.generate) or export it to a PKCS#8 DER Buffer or PEM string");
  } else throw E("bad-input", "a signer key must be a WebCrypto CryptoKey, a PKCS#8 DER Buffer, or a PKCS#8 PEM string");
  var imported = subtle.importKey("pkcs8", der, imp, false, ["sign"]);
  if (!owned) return imported;
  return imported.then(function (k) {
    guard.secret.zeroize(der, E, "bad-input", "the signer private-key copy");
    return k;
  }, function (e) {
    guard.secret.zeroize(der, E, "bad-input", "the signer private-key copy");
    throw e;
  });
}

function signOverTbs(scheme, key, signedBytes, E) {
  if (scheme.composite) {
    return compositeSig.compositeSign(scheme.composite, _normCompositeKeys(key, scheme.composite, E), signedBytes).then(function (sig) { return _bufferFrom(sig); });
  }
  return _importKey(key, scheme.imp, E).then(function (priv) {
    return subtle.sign(scheme.sign, priv, signedBytes).then(function (sigRaw) {
      var sig = _bufferFrom(sigRaw);
      if (scheme.ecdsaDer) sig = validator.sig.rawToEcdsaDer(sig, scheme.coordLen);
      return sig;
    });
  });
}

module.exports = {
  resolveSignScheme: resolveSignScheme,
  pssSpkiPinnedHash: pssSpkiPinnedHash,
  signOverTbs: signOverTbs,
  MLDSA_SUITABLE_DIGEST: MLDSA_SUITABLE_DIGEST,
  mldsaDigestSuitable: mldsaDigestSuitable,
  SLHDSA_BY_OID: SLHDSA_BY_OID,
};
