// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The signature-scheme resolver + signer shared by
// every producer that signs a raw preimage with a certificate's key: pki.cms.sign (SignerInfo),
// pki.ocsp.sign (BasicOCSPResponse), and future X.509 / CRL issuance. It owns the ONE key ->
// { signatureAlgorithm, WebCrypto import/sign params } dispatch across the whole algorithm set
// (RSA-PKCS1 / RSA-PSS / ECDSA P-256/384/521 / Ed25519 / Ed448 / ML-DSA / SLH-DSA / composite
// ML-DSA), so a new signer surface inherits the full registry -- PQC included -- instead of
// re-deriving a partial, drifting copy (Hard rule #2: registry not switch; and no second signer).
//
// Error-parameterized like the guard / validator families: the caller passes its typed error
// factory `E(kind, message, cause)` where kind is "bad-input" | "unsupported-algorithm", so every
// domain keeps its own code (cms/bad-input vs ocsp/bad-input). The digest choice (a CMS
// digestAlgorithm concern) is surfaced as `scheme.digest`; the caller that has a digestAlgorithm
// field (CMS) builds it, the caller that signs raw bytes (OCSP) ignores it.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var pkcs8 = require("./schema-pkcs8");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var validator = require("./validator-all");
var compositeSig = require("./composite-sig");
var b = asn1.build;
function O(name) { return oid.byName(name); }

var HASH = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
var NODE_DIGEST = { sha256: "sha256", sha384: "sha384", sha512: "sha512", shake128: "shake128", shake256: "shake256" };
var PSS_SALT = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };
var ECDSA_ALG = { sha256: "ecdsaWithSHA256", sha384: "ecdsaWithSHA384", sha512: "ecdsaWithSHA512" };
// RSA-PKCS1 signatures fold the digest into a combined signature OID when there is NO separate
// digestAlgorithm field to carry it (X.509 / CRL / OCSP -- RFC 5280 sec. 4.1.1.2, RFC 6960). CMS
// SignerInfo has that field, so it signs under the bare rsaEncryption key OID instead.
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
var SLHDSA_BY_OID = {};
[["sha2-128s", "sha256"], ["sha2-128f", "sha256"], ["sha2-192s", "sha512"], ["sha2-192f", "sha512"],
 ["sha2-256s", "sha512"], ["sha2-256f", "sha512"], ["shake-128s", "shake128"], ["shake-128f", "shake128"],
 ["shake-192s", "shake256"], ["shake-192f", "shake256"], ["shake-256s", "shake256"], ["shake-256f", "shake256"]
].forEach(function (r) { SLHDSA_BY_OID[O("id-slh-dsa-" + r[0])] = { wc: "SLH-DSA-" + r[0].toUpperCase(), digest: r[1] }; });

// An AlgorithmIdentifier { OID } (absent parameters) or { OID, NULL }.
function _algId(name, shape) { return shape === "null" ? b.sequence([b.oid(O(name)), b.nullValue()]) : b.sequence([b.oid(O(name))]); }
// The RSASSA-PSS AlgorithmIdentifier: explicit SHA-2 hash, MGF1 keyed to it, hash-length salt,
// default trailerField omitted (RFC 4055).
function _pssAlgId(digestName) {
  var hashAlg = b.sequence([b.oid(O(digestName)), b.nullValue()]);
  var mgf = b.sequence([b.oid(O("mgf1")), hashAlg]);
  var params = b.sequence([b.explicit(0, hashAlg), b.explicit(1, mgf), b.explicit(2, b.integer(BigInt(PSS_SALT[HASH[digestName]])))]);
  return b.sequence([b.oid(O("rsassaPss")), params]);
}
// An id-RSASSA-PSS SPKI MAY pin its permitted hash in the params (RFC 4055 sec. 1.2 / 3.1). Read
// it so signing honors the restriction; absent params or an unrecognized hash returns null.
function _pssHashFromSpki(cert, E) {
  var params = cert.subjectPublicKeyInfo.algorithm.parameters;
  if (params == null) return null;
  var node = asn1.decode(params);
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children) return null;
  var hashField = node.children.filter(function (c) { return c.tagClass === "context" && c.tagNumber === 0; })[0];
  if (!hashField || !hashField.children || !hashField.children[0] || !hashField.children[0].children) return null;
  var oidNode = hashField.children[0].children[0];
  if (!oidNode || oidNode.tagClass !== "universal" || oidNode.tagNumber !== asn1.TAGS.OBJECT_IDENTIFIER) return null;
  var pinnedOid = asn1.read.oid(oidNode);
  var name = HASH_NAME_BY_OID[pinnedOid];
  if (!name) throw E("unsupported-algorithm", "the id-RSASSA-PSS signer key pins an unsupported hash algorithm (" + pinnedOid + ")");
  return name;
}

// resolveSignScheme(cert, so, noSignedAttrs, E) -> the signature scheme from the signer cert's
// public-key algorithm + per-signer opts (so.digestAlgorithm / so.pss / so.combinedRsaSig -- the
// last folds the digest into a combined RSA signature OID for a caller with no digestAlgorithm
// field). Returns
// { composite?, digest, digestAlgId, sigAlgId, imp?, sign?, ecdsaDer?, coordLen? }. `digest`/
// `digestAlgId` matter only to a caller with a CMS digestAlgorithm field; OCSP ignores them.
function resolveSignScheme(cert, so, noSignedAttrs, E) {
  so = so || {};
  var alg = cert.subjectPublicKeyInfo.algorithm;
  var keyOid = alg.oid;
  var comp = compositeSig.COMPOSITE_ALGS[keyOid];
  if (comp) {
    if (comp.trad.unsupported) throw E("unsupported-algorithm", "composite " + comp.name + ": " + comp.trad.unsupported);
    if (so.digestAlgorithm && so.digestAlgorithm !== comp.phCms) throw E("bad-input", "composite " + comp.name + " fixes the digestAlgorithm to " + comp.phCms + " (draft-ietf-lamps-cms-composite-sigs sec. 3.4); " + JSON.stringify(so.digestAlgorithm) + " conflicts");
    return { composite: comp, digest: comp.phCms, digestAlgId: _algId(comp.phCms, "absent"), sigAlgId: _algId(comp.name, "absent") };
  }
  if (keyOid === O("rsaEncryption") || keyOid === O("rsassaPss")) {
    var isPssKey = keyOid === O("rsassaPss");
    var pinned = isPssKey ? _pssHashFromSpki(cert, E) : null;
    if (pinned && so.digestAlgorithm && so.digestAlgorithm !== pinned) throw E("bad-input", "the signer key restricts the RSASSA-PSS digest to " + pinned + ", but digestAlgorithm " + JSON.stringify(so.digestAlgorithm) + " was requested");
    var d = so.digestAlgorithm || pinned || "sha256";
    if (!HASH[d]) throw E("unsupported-algorithm", "unsupported RSA digest algorithm " + JSON.stringify(d));
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
    if (!HASH[de]) throw E("unsupported-algorithm", "unsupported ECDSA digest algorithm " + JSON.stringify(de));
    return { digest: de, digestAlgId: _algId(de, "absent"), sigAlgId: _algId(ECDSA_ALG[de], "absent"), imp: { name: "ECDSA", namedCurve: ec.curve }, sign: { name: "ECDSA", hash: HASH[de] }, ecdsaDer: true, coordLen: ec.coordLen };
  }
  if (keyOid === O("Ed25519") || keyOid === O("Ed448")) {
    var name = keyOid === O("Ed25519") ? "Ed25519" : "Ed448";
    var dd = so.digestAlgorithm || (name === "Ed25519" ? "sha512" : "shake256");
    if (!NODE_DIGEST[dd]) throw E("unsupported-algorithm", "unsupported " + name + " digest algorithm " + JSON.stringify(dd));
    return { digest: dd, digestAlgId: _algId(dd, "absent"), sigAlgId: _algId(name, "absent"), imp: { name: name }, sign: { name: name }, ecdsaDer: false };
  }
  if (MLDSA_BY_OID[keyOid]) {
    var mlName = MLDSA_BY_OID[keyOid];
    var md;
    if (noSignedAttrs) {
      md = "sha512";
    } else {
      md = so.digestAlgorithm || "sha512";
      if (!NODE_DIGEST[md]) throw E("unsupported-algorithm", "unsupported ML-DSA message digest " + JSON.stringify(md));
      if (!MLDSA_SUITABLE_DIGEST[mlName][md]) throw E("unsupported-algorithm", "the " + md + " message digest is below the security strength of " + mlName + " (RFC 9882 sec. 3.3)");
    }
    return { digest: md, digestAlgId: _algId(md, "absent"), sigAlgId: _algId(oid.name(keyOid), "absent"), imp: { name: mlName }, sign: { name: mlName }, ecdsaDer: false };
  }
  if (SLHDSA_BY_OID[keyOid]) {
    var slh = SLHDSA_BY_OID[keyOid];
    if (so.digestAlgorithm && so.digestAlgorithm !== slh.digest) throw E("bad-input", "SLH-DSA " + slh.wc + " requires the " + slh.digest + " message digest (RFC 9814 sec. 4); digestAlgorithm " + JSON.stringify(so.digestAlgorithm) + " conflicts");
    return { digest: slh.digest, digestAlgId: _algId(slh.digest, "absent"), sigAlgId: _algId(oid.name(keyOid), "absent"), imp: { name: slh.wc }, sign: { name: slh.wc }, ecdsaDer: false };
  }
  throw E("unsupported-algorithm", "unsupported signer key algorithm " + keyOid);
}

// A CryptoKey's algorithm must match the resolved scheme (name / hash / curve).
function _assertKeyMatchesScheme(key, imp, E) {
  var ka = key.algorithm || {};
  if (ka.name !== imp.name) throw E("bad-input", "the signer CryptoKey algorithm (" + ka.name + ") does not match the certificate's key algorithm (" + imp.name + ")");
  if (imp.hash && (!ka.hash || ka.hash.name !== imp.hash)) throw E("bad-input", "the signer CryptoKey hash (" + (ka.hash && ka.hash.name) + ") does not match the signing digest (" + imp.hash + ")");
  if (imp.namedCurve && ka.namedCurve !== imp.namedCurve) throw E("bad-input", "the signer CryptoKey curve (" + ka.namedCurve + ") does not match the certificate curve (" + imp.namedCurve + ")");
}
function _normPkcs8(k, label, E) {
  if (Buffer.isBuffer(k)) return k;
  if (k instanceof Uint8Array) return Buffer.from(k);
  if (typeof k === "string") { try { return pkcs8.pemDecode(k); } catch (e) { throw E("bad-input", label + " PEM could not be decoded", e); } }
  throw E("bad-input", label + " must be a PKCS#8 DER Buffer, Uint8Array, or PEM string");
}
function _normCompositeKeys(key, comp, E) {
  if (!key || typeof key !== "object" || Buffer.isBuffer(key) || key instanceof Uint8Array || key.mldsa == null || key.trad == null) {
    throw E("bad-input", "a composite " + comp.name + " signer key must be { mldsa: <PKCS#8>, trad: <PKCS#8> }");
  }
  return { mldsa: _normPkcs8(key.mldsa, "the composite ML-DSA component key", E), trad: _normPkcs8(key.trad, "the composite traditional component key", E) };
}
function _importKey(key, imp, E) {
  if (key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type === "private") {
    _assertKeyMatchesScheme(key, imp, E);
    return Promise.resolve(key);
  }
  var der;
  if (Buffer.isBuffer(key)) der = key;
  else if (key instanceof Uint8Array) der = Buffer.from(key);
  else if (typeof key === "string") { try { der = pkcs8.pemDecode(key); } catch (e) { throw E("bad-input", "the signer PEM private key could not be decoded", e); } }
  else throw E("bad-input", "a signer key must be a CryptoKey, a PKCS#8 DER Buffer, or a PKCS#8 PEM string");
  return subtle.importKey("pkcs8", der, imp, false, ["sign"]);
}

// signOverTbs(scheme, key, signedBytes, E) -> Promise<Buffer> the raw signature over signedBytes.
// The classical path imports the key + signs (re-encoding ECDSA to canonical DER); the composite
// path signs BOTH component keys and returns mldsaSig || tradSig (composite-sig.js owns it).
function signOverTbs(scheme, key, signedBytes, E) {
  if (scheme.composite) {
    return compositeSig.compositeSign(scheme.composite, _normCompositeKeys(key, scheme.composite, E), signedBytes).then(function (sig) { return Buffer.from(sig); });
  }
  return _importKey(key, scheme.imp, E).then(function (priv) {
    return subtle.sign(scheme.sign, priv, signedBytes).then(function (sigRaw) {
      var sig = Buffer.from(sigRaw);
      if (scheme.ecdsaDer) sig = validator.sig.rawToEcdsaDer(sig, scheme.coordLen);
      return sig;
    });
  });
}

// MLDSA_SUITABLE_DIGEST + SLHDSA_BY_OID are the RFC 9882 sec. 3.3 / RFC 9814 sec. 4 per-parameter-
// set digest policy, exported so the VERIFY side (cms-verify) shares the EXACT same table this
// resolver signs under -- a digest accepted on sign is precisely the set accepted on verify, with
// no drift between the two.
module.exports = {
  resolveSignScheme: resolveSignScheme,
  signOverTbs: signOverTbs,
  MLDSA_SUITABLE_DIGEST: MLDSA_SUITABLE_DIGEST,
  SLHDSA_BY_OID: SLHDSA_BY_OID,
};
