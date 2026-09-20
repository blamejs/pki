// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");
var oid = require("./oid");
var nodeCrypto = require("crypto");
var pkcs8 = require("./schema-pkcs8");
var pkix = require("./schema-pkix");
var frameworkError = require("./framework-error");
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
var _toLowerCase = intrinsic.toLowerCase;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _isU8 = intrinsic.types.isUint8Array;
var _resolve = intrinsic.uncurry(intrinsic.promiseResolve);

var HASH = intrinsic.assign(intrinsic.create(null), { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" });
var NODE_DIGEST = intrinsic.assign(intrinsic.create(null), { sha256: "sha256", sha384: "sha384", sha512: "sha512", shake128: "shake128", shake256: "shake256" });
var PSS_SALT = intrinsic.assign(intrinsic.create(null), { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 });
var ECDSA_ALG = intrinsic.assign(intrinsic.create(null), { sha256: "ecdsaWithSHA256", sha384: "ecdsaWithSHA384", sha512: "ecdsaWithSHA512" });
var RSA_PKCS1_SIG = intrinsic.assign(intrinsic.create(null), { sha256: "sha256WithRSAEncryption", sha384: "sha384WithRSAEncryption", sha512: "sha512WithRSAEncryption" });
var HASH_NAME_BY_OID = intrinsic.create(null);
HASH_NAME_BY_OID[O("sha256")] = "sha256";
HASH_NAME_BY_OID[O("sha384")] = "sha384";
HASH_NAME_BY_OID[O("sha512")] = "sha512";
var EC_BY_CURVE_OID = intrinsic.create(null);
EC_BY_CURVE_OID[O("prime256v1")] = { curve: "P-256", coordLen: 32 };
EC_BY_CURVE_OID[O("secp384r1")] = { curve: "P-384", coordLen: 48 };
EC_BY_CURVE_OID[O("secp521r1")] = { curve: "P-521", coordLen: 66 };
var MLDSA_BY_OID = intrinsic.create(null);
MLDSA_BY_OID[O("id-ml-dsa-44")] = "ML-DSA-44";
MLDSA_BY_OID[O("id-ml-dsa-65")] = "ML-DSA-65";
MLDSA_BY_OID[O("id-ml-dsa-87")] = "ML-DSA-87";
var MLDSA_SUITABLE_DIGEST = intrinsic.assign(intrinsic.create(null), {
  "ML-DSA-44": { sha256: 1, sha384: 1, sha512: 1, shake256: 1 },
  "ML-DSA-65": { sha384: 1, sha512: 1, shake256: 1 },
  "ML-DSA-87": { sha512: 1, shake256: 1 },
});
// @enforced-by behavioral -- an own-property table read has no rename-proof shape distinct from a legitimate lookup, so a RED conformance vector is the guard
function mldsaDigestSuitable(mlName, md) {
  if (!intrinsic.hasOwn(MLDSA_SUITABLE_DIGEST, mlName)) return false;
  var row = MLDSA_SUITABLE_DIGEST[mlName];
  return !!row && intrinsic.hasOwn(row, md) && !!row[md];
}

var SLHDSA_BY_OID = intrinsic.create(null);
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

/** @internal The SPKI the signature will be verified against travels on the scheme, because the
 *  signer form declares a public key and the door has to hold it to the one the certificate names.
 *  Attached here rather than on each return, so a new algorithm branch cannot omit it. */
function resolveSignScheme(cert, so, noSignedAttrs, E) {
  var scheme = _resolveSignScheme(cert, so, noSignedAttrs, E);
  var spki = cert && cert.subjectPublicKeyInfo;
  scheme.spki = (spki && spki.bytes) || null;
  return scheme;
}

function _resolveSignScheme(cert, so, noSignedAttrs, E) {
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

function _assertKeyMatchesScheme(key, imp, E, what) {
  var ka = key.algorithm || {};
  var subject = what || "CryptoKey";
  if (_toUpperCase(_String(ka.name)) !== _toUpperCase(_String(imp.name))) {
    var hint = (_toUpperCase(_String(ka.name)) === "RSA-PSS" && _toUpperCase(_String(imp.name)) === "RSASSA-PKCS1-V1_5")
      ? "; this " + subject + " is bound to RSASSA-PSS -- pass opts.pss to sign with RSASSA-PSS" : "";
    throw E("bad-input", "the signer " + subject + " algorithm (" + ka.name + ") does not match the certificate's key algorithm (" + imp.name + ")" + hint);
  }
  if (imp.hash && (!ka.hash || ka.hash.name !== imp.hash)) throw E("bad-input", "the signer " + subject + " hash (" + (ka.hash && ka.hash.name) + ") does not match the signing digest (" + imp.hash + ")");
  if (imp.namedCurve && ka.namedCurve !== imp.namedCurve) throw E("bad-input", "the signer " + subject + " curve (" + ka.namedCurve + ") does not match the certificate curve (" + imp.namedCurve + ")");
}
/** @internal `owned`, when given, collects the copies this makes of the caller's key so the caller can
 * wipe them: a Buffer is viewed and stays the caller's, while a Uint8Array or a PEM string produces a
 * new buffer holding the private key. The branch is taken once here, so no caller has to re-derive
 * which shape it passed. */
function _normPkcs8(k, label, E, owned) {
  if (_isBuffer(k)) return guard.bytes.view(k, E, "bad-input", label);
  if (_isU8(k)) {
    var snap = guard.bytes.snapshot(k, E, "bad-input", label);
    if (owned) guard.list.append(owned, snap);
    return snap;
  }
  if (typeof k === "string") {
    var der;
    try { der = pkcs8.pemDecode(k); } catch (e) { throw E("bad-input", label + " PEM could not be decoded", e); }
    if (owned) guard.list.append(owned, der);
    return der;
  }
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
  } else {
    throw E("bad-input", "a signer key must be a WebCrypto CryptoKey, a node:crypto KeyObject, a PKCS#8 DER Buffer, " +
      "a PKCS#8 PEM string, or a signer { algorithm, publicKey, sign }");
  }
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

/** @internal The signer form, read ONCE. A caller's object is not asked the same question twice:
 *  an accessor that answers differently on a second read would let the algorithm the door checked
 *  differ from the one that signs, and the callback the door validated differ from the one it
 *  calls. `sign` doubles as the discriminator, so the read that classifies is the read that runs. */
function _snapshotSigner(key) {
  if (!key || typeof key !== "object" || _isBuffer(key) || _isU8(key)) return null;   // allow:byte-source-narrow -- signer-form discrimination: a raw-key BufferSource is correctly classed as not a signer and normalized by _importKey
  var sign = key.sign;
  if (typeof sign !== "function") return null;
  var algorithm = key.algorithm;
  if (typeof algorithm === "string") algorithm = { name: algorithm };
  var flat = null;
  if (algorithm != null && typeof algorithm === "object") {
    var hash = algorithm.hash;
    var hashName = typeof hash === "string" ? hash : (hash == null ? undefined : hash.name);
    flat = {
      name: algorithm.name,
      hash: hashName === undefined ? undefined : { name: hashName },
      namedCurve: algorithm.namedCurve,
    };
  }
  /** @internal `receiver` is the object this door was handed, so `sign` is called on it and plain
   *  configuration read off `this` answers. A signing verb snapshots its options, so a client or a
   *  counter a signer holds on itself is a copy by the time it arrives; a callback keeps those in
   *  its closure instead, which is where the documented examples put them. */
  return { sign: sign, receiver: key, algorithm: flat, publicKey: key.publicKey };
}

/** @internal An SPKI a signer declares, from the shapes a public key arrives in. */
function _signerSpki(publicKey, E) {
  if (typeof publicKey === "string") {
    try { return pkix.pemDecode(publicKey, "PUBLIC KEY", frameworkError.PemError); }
    catch (e) { throw E("bad-input", "the signer publicKey PEM could not be decoded", e); }
  }
  return guard.bytes.snapshotSource(publicKey, E, "bad-input", "the signer publicKey");
}

/** @internal The signature a signer returned, held to the contract the callback is documented
 *  against: the bytes `subtle.sign` would return for this scheme. An ECDSA signature is the
 *  fixed-width r||s of RFC 9053 sec. 2.1, and the DER SEQUENCE a token usually emits is named
 *  rather than re-derived, because guessing which encoding arrived is how one gets converted twice. */
function _assertSignerSignature(sig, scheme, E) {
  if (!scheme.ecdsaDer) return sig;
  var want = scheme.coordLen * 2;
  if (sig.length === want) return sig;
  if (sig.length > 1 && sig[0] === 0x30) {
    throw E("bad-input", "the signer returned a DER SEQUENCE for an ECDSA signature; sign() returns the " +
      want + "-byte r||s a WebCrypto signature carries (RFC 9053 sec. 2.1), and this toolkit encodes it");
  }
  throw E("bad-input", "the signer returned " + sig.length + " byte(s) for an ECDSA signature on this curve; " +
    "sign() returns the " + want + "-byte r||s a WebCrypto signature carries (RFC 9053 sec. 2.1)");
}

function _signExternally(signer, scheme, signedBytes, E) {
  if (scheme.composite) {
    throw E("bad-input", "a composite " + scheme.composite.name + " signature is produced from both component private keys, " +
      "which one sign() callback cannot do; pass { mldsa, trad } PKCS#8 keys");
  }
  if (signer.algorithm == null) throw E("bad-input", "a signer must declare the algorithm it signs with: { algorithm, publicKey, sign }");
  if (signer.publicKey == null) throw E("bad-input", "a signer must declare its publicKey as SPKI DER, so the door can hold it to the key the signature is verified against");
  _assertKeyMatchesScheme(signer, scheme.imp, E, "signer");
  /** @internal The digest a scheme signs under is not always part of the key's import parameters:
   *  an ECDSA key names only its curve, and the digest is chosen per signature. A signer declares
   *  what it will do, so it is held to that here rather than after a remote signing request. */
  var wantHash = scheme.sign && scheme.sign.hash;
  if (wantHash && signer.algorithm.hash && signer.algorithm.hash.name !== wantHash) {
    throw E("bad-input", "the signer algorithm hash (" + signer.algorithm.hash.name +
      ") does not match the signing digest (" + wantHash + ")");
  }
  var declared = _signerSpki(signer.publicKey, E);
  if (!scheme.spki) throw E("bad-input", "this signing path does not name the public key a signature is verified against, so a signer's publicKey cannot be held to it");
  var named = guard.bytes.snapshotSource(scheme.spki, E, "bad-input", "the public key this signature is verified against");
  if (!guard.crypto.constantTimeEqual(declared, named)) {
    throw E("bad-input", "the signer publicKey is not the key this signature is verified against");
  }
  /** @internal The callback is handed a COPY, in an allocation of its own. It is a caller's
   *  function over the bytes an artifact is built from, and a callback that rewrote them in place
   *  would rewrite what is verified and what is emitted together, so the self-check would pass on
   *  the rewritten artifact. `Buffer.from` is not enough: a small copy comes out of Node's shared
   *  pool, whose backing ArrayBuffer the callback could reach the original through. */
  var handed = new intrinsic.Uint8Array(signedBytes.length);
  handed.set(signedBytes);
  var produced;
  try { produced = intrinsic.apply(signer.sign, signer.receiver, [handed]); }
  catch (e) { throw E("bad-input", "the signer sign() callback failed", e); }
  return _resolve(Promise, produced).then(function (raw) {
    var sig = guard.bytes.snapshotSource(raw, E, "bad-input", "the signature the signer returned");
    return _assertSignerSignature(sig, scheme, E);
  }, function (e) {
    throw E("bad-input", "the signer sign() callback failed", e);
  });
}

/** @internal What `node:crypto` calls the key an algorithm the toolkit signs with uses, keyed by
 *  the WebCrypto name the scheme resolved to. The two vocabularies differ, and the map is the one
 *  place that knows it, so a new algorithm adds a row rather than a branch. */
var NODE_KEY_TYPE = intrinsic.assign(intrinsic.create(null), {
  "RSASSA-PKCS1-v1_5": "rsa", "RSA-PSS": "rsa-pss", ECDSA: "ec", Ed25519: "ed25519", Ed448: "ed448",
});
/** @internal The curve a KeyObject reports, keyed by the WebCrypto curve a scheme names. */
var NODE_CURVE = intrinsic.assign(intrinsic.create(null), {
  "P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1",
});

/** @internal An RSA key carries no padding in its type, so an RSA-PSS scheme signs with a plain
 *  `rsa` key too; the padding is named on the signature, not on the key. */
function _keyTypeAccepts(reported, wanted) {
  if (reported === wanted) return true;
  return wanted === "rsa-pss" && reported === "rsa";
}

function _assertKeyObjectMatchesScheme(key, scheme, E) {
  var reported = key.asymmetricKeyType;
  var wanted = NODE_KEY_TYPE[scheme.imp.name] || _toLowerCase(_String(scheme.imp.name));
  if (!_keyTypeAccepts(reported, wanted)) {
    throw E("bad-input", "the signer KeyObject algorithm (" + reported +
      ") does not match the certificate's key algorithm (" + scheme.imp.name + ")");
  }
  if (scheme.imp.namedCurve) {
    var details = key.asymmetricKeyDetails;
    var curve = details && details.namedCurve;
    if (curve !== NODE_CURVE[scheme.imp.namedCurve]) {
      throw E("bad-input", "the signer KeyObject curve (" + curve +
        ") does not match the certificate curve (" + scheme.imp.namedCurve + ")");
    }
  }
}

/** @internal The options `node:crypto` signs a scheme under, so the bytes it returns are the bytes
 *  WebCrypto would have returned: an ECDSA signature in the fixed-width form of RFC 9053 sec. 2.1,
 *  which the caller then encodes, and a PSS signature at the salt length the scheme fixed. */
function _nodeSignOptions(key, scheme) {
  var name = scheme.sign.name;
  if (name === "ECDSA") return { key: key, dsaEncoding: "ieee-p1363" };
  if (name === "RSA-PSS") {
    return { key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: scheme.sign.saltLength };
  }
  return key;
}

/** @internal A digest `node:crypto` applies before signing. An algorithm that hashes the message
 *  itself (the Edwards curves, ML-DSA, SLH-DSA) takes none, and naming one there is an error. */
function _nodeDigest(scheme) {
  var name = scheme.sign.name;
  if (name === "ECDSA" || name === "RSA-PSS" || name === "RSASSA-PKCS1-v1_5") return NODE_DIGEST[scheme.digest] || scheme.digest;
  return null;
}

function _signWithKeyObject(key, scheme, signedBytes, E) {
  if (scheme.composite) {
    throw E("bad-input", "a composite " + scheme.composite.name + " signature is produced from both component private keys, " +
      "which one KeyObject cannot hold; pass { mldsa, trad } PKCS#8 keys");
  }
  if (key.type !== "private") {
    throw E("bad-input", "the signing key is a node:crypto KeyObject of type " + _stringify(key.type) +
      "; a signing key must be a private key (type \"private\")");
  }
  _assertKeyObjectMatchesScheme(key, scheme, E);
  try {
    return _bufferFrom(nodeCrypto.sign(_nodeDigest(scheme), signedBytes, _nodeSignOptions(key, scheme)));
  } catch (e) {
    throw E("bad-input", "the signer KeyObject could not produce a " + scheme.imp.name + " signature", e);
  }
}

function signOverTbs(scheme, key, signedBytes, E) {
  if (intrinsic.types.isKeyObject(key)) {
    var koSig = _signWithKeyObject(key, scheme, signedBytes, E);
    return _resolve(Promise, scheme.ecdsaDer ? validator.sig.rawToEcdsaDer(koSig, scheme.coordLen) : koSig);
  }
  var signer = _snapshotSigner(key);
  if (signer) {
    return _signExternally(signer, scheme, signedBytes, E).then(function (sig) {
      return scheme.ecdsaDer ? validator.sig.rawToEcdsaDer(sig, scheme.coordLen) : sig;
    });
  }
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
  /** @internal A PKCS#8 private key from the shapes every signer option accepts, so a verb that takes
   * a private key for something other than signing reads it the same way. */
  normalizePkcs8: _normPkcs8,
  pssSpkiPinnedHash: pssSpkiPinnedHash,
  signOverTbs: signOverTbs,
  MLDSA_SUITABLE_DIGEST: MLDSA_SUITABLE_DIGEST,
  mldsaDigestSuitable: mldsaDigestSuitable,
  SLHDSA_BY_OID: SLHDSA_BY_OID,
};
