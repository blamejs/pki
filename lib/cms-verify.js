// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.cms
 * @nav        Verification
 * @title      CMS
 * @fullname   CMS (Cryptographic Message Syntax) signing and verification
 * @intro Verify a CMS SignedData signature (RFC 5652 sec. 5) -- the structure S/MIME signed
 *   mail, RFC 3161 timestamp tokens, and code-signing all rest on. `verify(cms, opts)` parses
 *   the SignedData (over the strict `pki.schema.cms` codec), locates each SignerInfo's signer
 *   certificate by its issuerAndSerialNumber or subjectKeyIdentifier, and checks the signature
 *   over the exact bytes RFC 5652 sec. 5.4 defines: when signed attributes are present it
 *   confirms the message-digest attribute equals the digest of the content and verifies the
 *   signature over the DER re-encoding of the SignedAttributes (the on-wire `[0]` tag replaced
 *   by a universal SET OF); otherwise it verifies directly over the content. Attached and
 *   detached content, single and multiple signers, and RSA / RSASSA-PSS / ECDSA / EdDSA, the
 *   post-quantum ML-DSA (ML-DSA-44/65/87, RFC 9882) and SLH-DSA (the twelve FIPS 205 sets, RFC 9814),
 *   and composite ML-DSA (pairing ML-DSA with a traditional RSA / ECDSA / EdDSA, accepted only when
 *   both components verify, per draft-ietf-lamps-cms-composite-sigs) are covered. It reports a
 *   per-signer verdict;
 *   it does not chain the signer certificate to a trust anchor, which is the caller's step through
 *   `pki.path.validate`.
 * @spec RFC 5652
 * @spec RFC 9882
 * @spec RFC 9814
 * @card Verify a CMS SignedData signature (S/MIME, timestamps, code signing).
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var cms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var edwardsPoint = require("./edwards-point");
var cmsSign = require("./cms-sign");
var cmsEncrypt = require("./cms-encrypt");
var cmsDecrypt = require("./cms-decrypt");
var cmsCompress = require("./cms-compress");
var signScheme = require("./sign-scheme");
// The digest-strength question is asked of sign-scheme, which owns the policy table, so the signer
// and this verifier cannot drift (RFC 9882 sec. 3.3).
var _mldsaDigestSuitable = signScheme.mldsaDigestSuitable;
var SLHDSA_BY_OID = signScheme.SLHDSA_BY_OID;                   // shared SLH-DSA set -> { wc, digest } (RFC 9814 sec. 4 pinned digest)
var validator = require("./validator-all");
var compositeSig = require("./composite-sig");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");

var CmsError = frameworkError.CmsError;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
// Promise.resolve captured at load and invoked through the captured Reflect.apply, so a streamed
// opts.content -- whose iterator runs during the digest await and can replace Promise.resolve -- cannot
// turn a resolved { ok: false } verdict into acceptance. The verify path resolves every value through
// this and awaits every step: Promise.all is deliberately NOT used, since its spec-internal element
// handling dispatches through the caller-replaceable Promise.prototype.then, which await does not.
var _Promise = Promise, _promiseResolveRaw = Promise.resolve;
function _pResolve(v) { return intrinsic.apply(_promiseResolveRaw, _Promise, [v]); }

var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_COUNTERSIGNATURE = oid.byName("countersignature");

// A digest-algorithm name -> the engine's hash name, for computing a MESSAGE DIGEST (the
// message-digest attribute and the content digest). The FIPS 202 extendable-output functions
// belong here at the lengths RFC 8702 sec. 4 fixes for that use (SHAKE128 32 bytes, SHAKE256 64).
var DIGEST_HASH = {
  sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512",
  shake128: "SHAKE128", shake256: "SHAKE256",
};
// The SIGNATURE hash a bare-key-OID scheme (rsaEncryption, ecPublicKey) inherits from the
// SignerInfo digestAlgorithm. Deliberately a SEPARATE table from DIGEST_HASH, and deliberately
// without the extendable-output functions: RFC 8702 sec. 3.2 gives RSASSA-PKCS1-v1_5-with-SHAKE
// and ECDSA-with-SHAKE their own signature OIDs and never pairs a bare key OID with a SHAKE
// digestAlgorithm, so that combination is non-conformant and must keep its precise refusal.
// Folding the two roles into one table would resolve a signature hash for it instead, letting
// it past the fail-closed gate below and into the engine, where the caller gets a relabeled
// foreign fault and loses this module's own unsupported-algorithm verdict.
var SIG_HASH = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
// Is `name` a message-digest algorithm this verifier supports?
function _supportedDigest(name) { return intrinsic.hasOwn(DIGEST_HASH, name) && !!DIGEST_HASH[name]; }
// The digest of `content` under the named algorithm, resolved to a Buffer.
async function _computeDigest(name, content) {
  return intrinsic.bufferFrom(await subtle.digest(DIGEST_HASH[name], content));
}
// A signatureAlgorithm name -> its verify scheme. A combined OID (sha256WithRSAEncryption,
// ecdsaWithSHA256) carries its own hash; a bare key OID (rsaEncryption, ecPublicKey) takes the
// hash from the SignerInfo digestAlgorithm.
// `params` pins the AlgorithmIdentifier parameters shape RFC 5754 requires: "null" for the
// RSASSA-PKCS1-v1_5 family (RFC 4055), "absent" for ECDSA (RFC 5758) and EdDSA (RFC 8410).
// RSASSA-PSS omits it -- its parameters ARE the RSASSA-PSS-params, resolved by _resolvePss.
var SIG_SCHEME = {
  rsaEncryption: { kind: "rsa", params: "null" },
  rsassaPss: { kind: "rsapss" },
  ecPublicKey: { kind: "ec", params: "absent" },
  // One-shot families (EdDSA, ML-DSA): the same OID identifies the key and the signature, so the
  // signer cert SPKI algorithm OID MUST equal the signatureAlgorithm OID. `sameKeyOid` enables
  // that agreement check (RFC 8410 / RFC 9882; enforced in _verifyAgainstCandidates).
  Ed25519: { kind: "eddsa", name: "Ed25519", params: "absent", sameKeyOid: true },
  Ed448: { kind: "eddsa", name: "Ed448", params: "absent", sameKeyOid: true },
  "id-ml-dsa-44": { kind: "mldsa", name: "ML-DSA-44", params: "absent", sameKeyOid: true },
  "id-ml-dsa-65": { kind: "mldsa", name: "ML-DSA-65", params: "absent", sameKeyOid: true },
  "id-ml-dsa-87": { kind: "mldsa", name: "ML-DSA-87", params: "absent", sameKeyOid: true },
  sha1WithRSAEncryption: { kind: "rsa", hash: "SHA-1", params: "null" },
  sha256WithRSAEncryption: { kind: "rsa", hash: "SHA-256", params: "null" },
  sha384WithRSAEncryption: { kind: "rsa", hash: "SHA-384", params: "null" },
  sha512WithRSAEncryption: { kind: "rsa", hash: "SHA-512", params: "null" },
  ecdsaWithSHA1: { kind: "ec", hash: "SHA-1", params: "absent" },
  ecdsaWithSHA256: { kind: "ec", hash: "SHA-256", params: "absent" },
  ecdsaWithSHA384: { kind: "ec", hash: "SHA-384", params: "absent" },
  ecdsaWithSHA512: { kind: "ec", hash: "SHA-512", params: "absent" },
};
// SLH-DSA (RFC 9814): the twelve pure FIPS 205 sets, seeded like webcrypto's SLH_DSA_NODE. Each is
// a one-shot family (kind "slhdsa"), params absent, sig-OID == key-OID (sameKeyOid). The WebCrypto
// name is "SLH-DSA-"+SET, matching path-validate's transform (drift rule sec. 5: one name map).
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { SIG_SCHEME["id-slh-dsa-" + s] = { kind: "slhdsa", name: "SLH-DSA-" + s.toUpperCase(), params: "absent", sameKeyOid: true, digest: SLHDSA_BY_OID[oid.byName("id-slh-dsa-" + s)].digest }; });
// The signatureAlgorithm parameters match the algorithm's fixed shape (RFC 5754). A DER NULL
// is exactly `05 00`; "absent" is the parameters field omitted entirely.
function _isDerNull(p) { return Buffer.isBuffer(p) && p.length === 2 && p[0] === 0x05 && p[1] === 0x00; }
function _algParamsOk(shape, p) { return shape === "null" ? _isDerNull(p) : (p === null || p === undefined); }
// An EC named-curve OID (in the signer cert SPKI) -> the WebCrypto curve + r/s coordinate width.
var EC_CURVE = {};
EC_CURVE[oid.byName("prime256v1")] = { curve: "P-256", coordLen: 32 };
EC_CURVE[oid.byName("secp384r1")] = { curve: "P-384", coordLen: 48 };
EC_CURVE[oid.byName("secp521r1")] = { curve: "P-521", coordLen: 66 };

function _toBuf(v, what) {
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
  throw _err("cms/bad-input", what + " must be a Buffer");
}

// Every certificate a SignerInfo's signer identifier matches, among the SignedData's embedded
// certificates plus any the caller supplies. issuerAndSerialNumber matches on the canonical
// DN + serial; subjectKeyIdentifier matches the cert's SKI extension. ALL matches are returned
// (in candidate order) so a colliding certificate placed before the real signer cannot hide it.
function _findSignerCerts(sid, parsedCerts) {
  var out = [];
  for (var i = 0; i < parsedCerts.length; i++) {
    var c = parsedCerts[i];
    if (sid.subjectKeyIdentifier != null) {
      // Captured equality: over a streamed content the untrusted iterator ran during the digest await
      // and could replace Buffer.prototype.equals to match the wrong certificate to a signer.
      if (c.ski && intrinsic.bufferEquals(c.ski, _toBuf(sid.subjectKeyIdentifier, "sid.subjectKeyIdentifier"))) intrinsic.push(out, c);
    } else if (sid.issuer && sid.serialNumberHex != null) {
      if (c.cert.serialNumberHex === sid.serialNumberHex && guard.name.dnEqual(c.cert.issuer.rdns, sid.issuer.rdns, _err, "cms/bad-name", "the signer certificate issuer")) intrinsic.push(out, c);
    }
  }
  return out;
}

// Verify `sigBytes` over `signedBytes` against each matching candidate certificate in turn; the
// signer is valid iff one candidate verifies. A candidate whose key is structurally unusable (a
// low-order EdDSA point, an unsupported curve) or whose signature simply does not verify falls
// through to the next -- so a colliding certificate cannot make a valid signature read invalid.
// When no candidate verifies, a plain false is a code-less verdict; the last structural fault's
// code is surfaced if one occurred (so the diagnostic is not lost).
async function _verifyAgainstCandidates(scheme, sigHash, sigBytes, signedBytes, sid, candidates, pssSalt, expectedKeyOid) {
  var lastErr = null;
  for (var idx = 0; idx < candidates.length; idx++) {
    var c = candidates[idx];
    // One-shot family (EdDSA/ML-DSA): the signer cert public-key algorithm OID MUST equal the
    // SignerInfo signatureAlgorithm OID. A candidate whose SPKI disagrees is skipped with a precise
    // verdict; importing it under the wrong name would surface a foreign webcrypto/data throw.
    if (expectedKeyOid && c.cert.subjectPublicKeyInfo.algorithm.oid !== expectedKeyOid) {
      lastErr = _err("cms/unsupported-algorithm", "the signer certificate public-key algorithm does not match the SignerInfo signatureAlgorithm");
      continue;
    }
    // `await`, not `.then`: over a streamed content the untrusted iterator ran during the digest await
    // and could replace Promise.prototype.then to return a fabricated `true`; await is immune (it does
    // not dispatch through the caller-replaceable prototype method).
    try {
      var ok = await _verifySignature(scheme, sigHash, sigBytes, c.cert.subjectPublicKeyInfo.bytes, signedBytes, _certCurveOid(c.cert), pssSalt);
      if (ok === true) return { ok: true, sid: sid, cert: c.der };
    } catch (e) {
      lastErr = (e instanceof CmsError) ? e : _err("cms/verify-error", "the SignerInfo signature could not be evaluated", e);
    }
  }
  return lastErr ? { ok: false, code: lastErr.code, sid: sid, cert: candidates[0].der, message: lastErr.message }
    : { ok: false, sid: sid, cert: candidates[0].der };
}

// The cert's subjectKeyIdentifier extension value (the raw key id), or null.
function _certSki(cert) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === oid.byName("subjectKeyIdentifier"); })[0];
  if (!ext) return null;
  try {
    return asn1.read.octetString(asn1.decode(ext.value));
  } catch (_e) { return null; }
}

// RSASSA-PSS-params resolution (RFC 4055). A SHA-2 hashAlgorithm name -> its WebCrypto hash
// and the salt length WebCrypto verifies (the hash-length salt of the supported profile).
var OID_MGF1 = oid.byName("mgf1");
var PSS_HASH = {};
PSS_HASH[oid.byName("sha256")] = "SHA-256";
PSS_HASH[oid.byName("sha384")] = "SHA-384";
PSS_HASH[oid.byName("sha512")] = "SHA-512";

// A hash AlgorithmIdentifier { OID, parameters? } whose parameters, when present, MUST be a
// DER NULL with empty content (RFC 4055 sec. 2.1 / RFC 5754). Returns the hash OID, or null
// on any malformed shape.
function _hashAlgOid(seq) {
  if (!seq || seq.tagClass !== "universal" || seq.tagNumber !== asn1.TAGS.SEQUENCE || !seq.children || seq.children.length < 1 || seq.children.length > 2) return null;
  var o;
  try {
    o = asn1.read.oid(seq.children[0]);
  } catch (_e) { return null; }
  if (seq.children.length === 2) {
    var p = seq.children[1];
    if (p.tagClass !== "universal" || p.tagNumber !== asn1.TAGS.NULL) return null;
    try {
      asn1.read.nullValue(p);
    } catch (_e2) { return null; }
  }
  return o;
}

// Resolve RSASSA-PSS-params (RFC 4055) to { hash, saltLength }, or null if the parameters
// deviate from the supported profile: an explicit SHA-2 hashAlgorithm, MGF1 keyed to the same
// hash, saltLength equal to the hash length, and trailerField 1. The SHA-1 DEFAULTs are
// rejected (params must be explicit), matching the certification-path validator, so a
// non-conformant PSS AlgorithmIdentifier is a fail-closed verdict. Falling back to WebCrypto's
// own defaults would be a signatureAlgorithm bypass.
function _resolvePss(paramsBytes) {
  if (!paramsBytes) return null;
  var n;
  try {
    n = asn1.decode(paramsBytes);
  } catch (_e) { return null; }
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children) return null;
  var hash = null, saltLen = null, mgfNode = null, trailer = 1n, last = -1;
  for (var i = 0; i < n.children.length; i++) {
    var f = n.children[i];
    // Each field is an EXPLICIT context [0..3] wrapper carrying exactly one value, at most
    // once and in ascending order; anything else is malformed.
    if (f.tagClass !== "context" || f.tagNumber > 3 || f.tagNumber <= last || !f.children || f.children.length !== 1) return null;
    last = f.tagNumber;
    try {
      if (f.tagNumber === 0) { hash = PSS_HASH[_hashAlgOid(f.children[0])]; if (!hash) return null; }
      else if (f.tagNumber === 1) { mgfNode = f.children[0]; }
      else if (f.tagNumber === 2) { saltLen = asn1.read.integer(f.children[0]); }
      else { trailer = asn1.read.integer(f.children[0]); }
    } catch (_e3) { return null; }
  }
  if (hash === null || mgfNode === null) return null;   // both MUST be explicit (SHA-1 default rejected)
  if (mgfNode.tagClass !== "universal" || mgfNode.tagNumber !== asn1.TAGS.SEQUENCE || !mgfNode.children || mgfNode.children.length !== 2) return null;
  var mgfOid;
  try {
    mgfOid = asn1.read.oid(mgfNode.children[0]);
  } catch (_e4) { return null; }
  if (mgfOid !== OID_MGF1 || PSS_HASH[_hashAlgOid(mgfNode.children[1])] !== hash) return null;
  if (trailer !== 1n) return null;
  // saltLength: an absent field is the RFC 4055 DEFAULT of 20; a declared value is honored and
  // passed through to WebCrypto (RSASSA-PSS is not pinned to hash-length salt). It is bounded to
  // a non-negative int -- a negative value maps to OpenSSL's RSA_PSS_SALTLEN_DIGEST/AUTO/MAX
  // magic, and AUTO accepts any salt length, defeating the salt-length binding.
  var saltLength = saltLen === null ? 20 : guard.range.uint31(saltLen, _err, "cms/unsupported-algorithm", "RSASSA-PSS saltLength");
  return { hash: hash, saltLength: saltLength };
}

// Verify the signature over `signedBytes` with the signer certificate's public key under the
// resolved scheme + hash. Resolves true/false (a false verdict is a verdict); a structural
// fault throws a typed CmsError.
async function _verifySignature(scheme, hashName, sigBytes, spki, signedBytes, curveOid, pssSalt) {
  // `await` throughout, never `.then`: a streamed content's untrusted iterator ran during the digest
  // await and could replace Promise.prototype.then to answer a fabricated `true`; await does not
  // dispatch through it.
  if (scheme.kind === "rsa") {
    var kRsa = await subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: hashName }, false, ["verify"]);
    return subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, kRsa, sigBytes, signedBytes);
  }
  if (scheme.kind === "rsapss") {
    var kPss = await subtle.importKey("spki", spki, { name: "RSA-PSS", hash: hashName }, false, ["verify"]);
    return subtle.verify({ name: "RSA-PSS", saltLength: pssSalt }, kPss, sigBytes, signedBytes);
  }
  if (scheme.kind === "ec") {
    var ec = EC_CURVE[curveOid];
    if (!ec) throw _err("cms/unsupported-algorithm", "the signer key is on an unsupported EC curve");
    // The ORDER-AWARE gate: r,s in [1, n-1] per FIPS 186-5 sec. 6.4.2 (rejecting an out-of-range r/s >= the
    // curve order n, not only the r=s=0 forgery). A verifier that knows the curve MUST use it.
    var raw = validator.sig.ecdsaDerToP1363(sigBytes, ec.curve, CmsError, "cms/bad-signature");
    var kEc = await subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: ec.curve }, false, ["verify"]);
    return subtle.verify({ name: "ECDSA", hash: hashName }, kEc, raw, signedBytes);
  }
  if (scheme.kind === "mldsa" || scheme.kind === "slhdsa") {
    // ML-DSA (RFC 9882) / SLH-DSA (RFC 9814): a one-shot post-quantum verify, pure mode, empty
    // context -- no external signature hash and no Edwards-point validation (FIPS 204 sec. 5.3 /
    // FIPS 205 sec. 10.3; node structurally validates the SPKI on import). The signature is raw and
    // fixed-length (not ECDSA-DER).
    var kPq = await subtle.importKey("spki", spki, { name: scheme.name }, false, ["verify"]);
    return subtle.verify({ name: scheme.name }, kPq, sigBytes, signedBytes);
  }
  // EdDSA -- the WebCrypto name follows the signing key's SPKI OID (Ed25519 / Ed448). node/
  // OpenSSL imports any Ed25519/Ed448 SPKI without validating the point, and a low-order (e.g.
  // all-zeroes) key verifies a forged signature, so reject a non-full-order point first.
  _requireValidEdPoint(spki, scheme.name);
  var kEd = await subtle.importKey("spki", spki, { name: scheme.name }, false, ["verify"]);
  return subtle.verify({ name: scheme.name }, kEd, sigBytes, signedBytes);
}

// The EdDSA signer key's point MUST be a valid, canonical, full-order Edwards point: reject an
// off-curve or low-order key before it verifies a signature (WebCrypto import does not check it).
// Routed through the shared edwards-point gate every EdDSA verify path uses; curve from the name.
function _requireValidEdPoint(spkiBytes, name) {
  edwardsPoint.validateSpki(spkiBytes, name === "Ed25519" ? 6 : 7, CmsError, "cms/bad-signature");
}

// The EC named-curve OID carried in a signer cert's SubjectPublicKeyInfo, or null (non-EC).
function _certCurveOid(cert) {
  var p = cert.subjectPublicKeyInfo.algorithm.parameters;
  if (cert.subjectPublicKeyInfo.algorithm.oid !== oid.byName("ecPublicKey") || !Buffer.isBuffer(p)) return null;
  try {
    return asn1.read.oid(asn1.decode(p));
  } catch (_e) { return null; }
}

// Decode the SignedAttributes SET OF Attribute from the exact bytes the signature covers
// (the re-tagged signedAttrsBytes), returning [{ type, values: [valueNode] }]. Binding the
// content-type / message-digest checks to these decoded attributes means a parsed-object input
// cannot desync the checked attributes from the verified preimage (RFC 5652 sec. 5.4). The
// caller-mutable parsed si.signedAttrs is deliberately left out of that decision.
function _decodeSignedAttrs(setOfBytes) {
  var set = asn1.decode(setOfBytes);
  if (set.tagClass !== "universal" || set.tagNumber !== asn1.TAGS.SET || !set.children) throw _err("cms/bad-signed-attrs", "signedAttrs is not a SET OF Attribute");
  return intrinsic.map(set.children, function (attr) {
    if (attr.tagClass !== "universal" || attr.tagNumber !== asn1.TAGS.SEQUENCE || !attr.children || attr.children.length !== 2) throw _err("cms/bad-signed-attrs", "a signed Attribute is not a SEQUENCE { type, values }");
    var valuesSet = attr.children[1];
    if (valuesSet.tagClass !== "universal" || valuesSet.tagNumber !== asn1.TAGS.SET || !valuesSet.children) throw _err("cms/bad-signed-attrs", "a signed Attribute values field is not a SET OF");
    return { type: asn1.read.oid(attr.children[0]), values: valuesSet.children };
  });
}

// Verify one SignerInfo. Returns { ok, sid, cert, ... }, where a resolved false is a verdict and
// a structural failure carries a code.
// `csTarget`, when set (a Buffer), makes this a COUNTERSIGNATURE verify (RFC 5652 sec. 11.4): the
// preimage is the countersigned signature octets, not the sec. 5.4 content preimage, and no
// content-type attribute is required or checked (_computeCountersigBytes). content/eContentType are
// unused in that mode.
async function _verifyOne(si, content, eContentType, parsedCerts, csTarget, digestByName) {
  // A composite ML-DSA SignerInfo (draft-ietf-lamps-cms-composite-sigs) is keyed by its composite
  // OID, not a SIG_SCHEME name; intercept it before the classical dispatch (its verify has no
  // single external signature hash, so it never routes through the SIG_SCHEME/sigHash gate below).
  var composite = compositeSig.COMPOSITE_ALGS[si.signatureAlgorithm.oid];
  if (composite) return _verifyComposite(si, composite, content, eContentType, parsedCerts, csTarget, digestByName);
  var scheme = SIG_SCHEME[si.signatureAlgorithm.name];
  if (!scheme) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported signature algorithm " + JSON.stringify(si.signatureAlgorithm.name) });
  var digestHash = SIG_HASH[si.digestAlgorithm.name];
  // RSASSA-PSS takes its signature hash and salt length from the RSASSA-PSS-params, not the
  // digestAlgorithm; a non-conformant parameter set is a fail-closed unsupported verdict.
  var pss = scheme.kind === "rsapss" ? _resolvePss(si.signatureAlgorithm.parameters) : null;
  if (scheme.kind === "rsapss" && !pss) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported or non-conformant RSASSA-PSS parameters (RFC 4055)" });
  // signatureAlgorithm is outside the signed preimage, so a forbidden/missing parameters field
  // (a present parameter on ECDSA/EdDSA, a non-NULL or absent one on RSA) must fail closed --
  // otherwise it is a parser differential a caller trusting the verdict inherits (RFC 5754).
  if (scheme.params && !_algParamsOk(scheme.params, si.signatureAlgorithm.parameters)) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.signatureAlgorithm.name + " signature algorithm parameters must be " + (scheme.params === "null" ? "DER NULL (RFC 4055)" : "absent (RFC 5758/8410)") });
  // The digestAlgorithm parameters, when present, MUST be a DER NULL (RFC 5754 sec. 2 accepts
  // absent OR NULL; a present non-NULL is malformed and, being outside the signed preimage,
  // must fail closed like the signatureAlgorithm parameters above). EXCEPT for an ML-DSA
  // SignerInfo carrying no signed attributes: RFC 9882 sec. 3.3 says the whole digestAlgorithm field
  // has no meaning there and MUST be ignored, so neither its parameters nor its name may reject.
  var dp = si.digestAlgorithm.parameters;
  var mldsaNoAttrs = scheme.kind === "mldsa" && !si.signedAttrsBytes;
  if (!mldsaNoAttrs && dp !== null && dp !== undefined && !_isDerNull(dp)) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.digestAlgorithm.name + " digest algorithm parameters must be absent or DER NULL (RFC 5754 sec. 2)" });
  // A SHAKE digest algorithm identifier (id-shake128 / id-shake256) carries NO parameters at all --
  // not even a DER NULL (RFC 8702 sec. 3.1) -- so for a one-shot PQC SignerInfo (ML-DSA per RFC 9882,
  // SLH-DSA per RFC 9814 sec. 4, both citing RFC 8702) with signed attributes a present SHAKE
  // parameter fails closed. The SHA-2 digests (id-sha256/384/512) follow RFC 5754, which requires a
  // verifier to accept absent OR NULL (the generic rule above); the RFCs' omit-on-encode rule binds
  // the signer, not the verifier, so a SHA-2 NULL is not tightened here.
  if ((scheme.kind === "mldsa" || scheme.kind === "slhdsa") && si.signedAttrsBytes && (si.digestAlgorithm.name === "shake128" || si.digestAlgorithm.name === "shake256") && dp !== null && dp !== undefined) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "a SHAKE digestAlgorithm carries no parameters (RFC 8702 sec. 3.1)" });
  var sigHash = pss ? pss.hash : (scheme.hash || digestHash);
  // The signature hash is required for every non-EdDSA scheme (EdDSA hashes internally);
  // the content digest is required whenever signed attributes are present, for every scheme
  // (the message-digest attribute is computed under digestAlgorithm). Either gap is a
  // fail-closed unsupported-algorithm verdict, never a foreign-domain throw from the digest.
  if ((scheme.kind !== "eddsa" && scheme.kind !== "mldsa" && scheme.kind !== "slhdsa" && !sigHash) || (si.signedAttrsBytes && !_supportedDigest(si.digestAlgorithm.name))) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported digest algorithm " + JSON.stringify(si.digestAlgorithm.name) });
  // ML-DSA (RFC 9882 sec. 3.3): with signed attributes present, the message-digest algorithm MUST
  // meet the parameter set's security strength -- a below-strength digest is the weaker link and is
  // rejected fail-closed (the RFC's "verifiers MAY reject", taken by the strict-verifier posture).
  // With signed attributes absent the digestAlgorithm has no meaning (sec. 3.3) and is not checked.
  if (scheme.kind === "mldsa" && si.signedAttrsBytes && !_mldsaDigestSuitable(scheme.name, si.digestAlgorithm.name)) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.digestAlgorithm.name + " message digest is below the security strength of " + scheme.name + " (RFC 9882 sec. 3.3)" });
  // RFC 9814 sec. 4: an SLH-DSA SignerInfo's message-digest algorithm is the one paired with the
  // parameter set (the sec. 4 list, always at least twice the tree-hash size); the signer emits it
  // and this strict verifier requires it, so a digest that does not match the set's paired hash fails
  // closed -- otherwise a signer could compute the message-digest attribute under a weaker hash the
  // set does not pair. Gated on signed attributes (absent -> the digest is not consulted, sec. 4).
  if (scheme.kind === "slhdsa" && si.signedAttrsBytes && si.digestAlgorithm.name !== scheme.digest) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "SLH-DSA " + scheme.name + " requires the " + scheme.digest + " message digest (RFC 9814 sec. 4)" });
  var signers = _findSignerCerts(si.sid, parsedCerts);
  if (!signers.length) return _pResolve({ ok: false, code: "cms/signer-cert-not-found", sid: si.sid, message: "no certificate matches this SignerInfo's signer identifier" });
  var sigBytes = _toBuf(si.signature, "the SignerInfo signature");

  // `await`, not `.then`: see _verifyAgainstCandidates -- a streamed content's iterator could replace
  // Promise.prototype.then to skip the signed-bytes computation and fabricate a passing verdict.
  var signedBytes = await (csTarget != null ? _computeCountersigBytes(si, csTarget) : _computeSignedBytes(si, content, eContentType, digestByName));
  if (signedBytes && signedBytes.mismatch) return { ok: false, code: signedBytes.mismatch.code, sid: si.sid, cert: signers[0].der, message: signedBytes.mismatch.message };
  return _verifyAgainstCandidates(scheme, sigHash, sigBytes, signedBytes, si.sid, signers, pss ? pss.saltLength : 0, scheme.sameKeyOid ? oid.byName(si.signatureAlgorithm.name) : null);
}

// The exact bytes a countersignature covers (RFC 5652 sec. 11.4): the countersigned SignerInfo's
// signature value octets (`csTarget`). With signed attributes present, the message-digest attribute
// MUST equal digest(csTarget) under the countersignature's own digestAlgorithm and the signature
// covers the re-tagged SignedAttributes ([0] -> universal SET OF) -- the identical transform the
// top-level signer uses, minus the content-type attribute (which sec. 11.4 FORBIDS). Resolves the
// signed bytes, or { mismatch } when the message-digest disagrees.
async function _computeCountersigBytes(si, csTarget) {
  // async, not `_pResolve().then`: a synchronous throw still becomes a rejection, and the digest await
  // below dispatches through no caller-replaceable Promise.prototype.then (see _verifyAgainstCandidates).
  if (!si.signedAttrsBytes) return csTarget;   // no signed attributes: sign over the target signature octets directly
  var reTagged = intrinsic.bufferFrom(si.signedAttrsBytes);
  reTagged[0] = 0x31;   // [0] IMPLICIT -> universal SET OF
  var attrs;
  try {
    attrs = _decodeSignedAttrs(reTagged);
  } catch (e) { if (e instanceof CmsError) throw e; throw _err("cms/bad-signed-attrs", "the countersignature signedAttrs is not a valid SET OF Attribute", e); }
  // sec. 11.4: a content-type attribute MUST NOT appear (the parser already rejects it at parse, but
  // verify never relies on the parse alone: a parsed-object input could carry one).
  if (intrinsic.filter(attrs, function (a) { return a.type === OID_CONTENT_TYPE; }).length) throw _err("cms/misplaced-attr", "a countersignature must not carry a content-type attribute (RFC 5652 sec. 11.4)");
  var mdAttr = intrinsic.filter(attrs, function (a) { return a.type === OID_MESSAGE_DIGEST; })[0];
  if (!mdAttr || mdAttr.values.length !== 1) throw _err("cms/bad-signed-attrs", "a countersignature's signedAttrs must carry exactly one message-digest attribute (RFC 5652 sec. 11.4)");
  var declared;
  try {
    declared = asn1.read.octetString(mdAttr.values[0]);
  } catch (e) { throw _err("cms/bad-signed-attrs", "the message-digest attribute value is not an OCTET STRING", e); }
  var d = await _computeDigest(si.digestAlgorithm.name, csTarget);
  if (!intrinsic.bufferEquals(d, declared)) return { mismatch: { code: "cms/message-digest-mismatch", message: "the countersignature message-digest does not match the countersigned signature" } };
  return reTagged;
}

// The exact bytes the signature covers (RFC 5652 sec. 5.4), shared by the classical and composite
// verify paths so both bind the message-digest / content-type checks to the VERIFIED preimage (not
// the caller-mutable parsed si.signedAttrs). Resolves the signed bytes, or { mismatch } when a
// content-type / message-digest attribute disagrees.
async function _computeSignedBytes(si, content, eContentType, digestByName) {
  // async, not `_pResolve().then`: a synchronous throw still becomes a rejection, and every digest step
  // dispatches through no caller-replaceable Promise.prototype.then (see _verifyAgainstCandidates).
  if (!si.signedAttrsBytes) {
    // No signed attributes: the signature is over the content itself (RFC 5652 sec. 5.4). A streamed
    // content is not retained, so there are no content bytes to verify that signature against; this
    // is a per-signer verdict, not a whole-message abort, so the other signers of a mixed message
    // still verify (the same shape the buffered path gives every per-signer condition). `digestByName`
    // is the streaming marker: an object (possibly empty) when streamed, null when buffered.
    if (digestByName) {
      return { mismatch: {
        code: "cms/streamed-content-unverifiable",
        message: "a SignerInfo that signs the content directly (no signed attributes) cannot be " +
          "verified against a streamed content, whose bytes are not retained; pass opts.content as a Buffer",
      } };
    }
    // Signing content directly is also exactly what a stripped-attributes forgery looks like, because
    // a CMS signature does not commit to whether attributes were present -- so a signature made over a
    // SignedAttributes block re-presented as one made over content verifies, and with no attributes
    // there is no message-digest or content-type attribute left to disagree. Refuse the shape: content
    // that parses as a SignedAttributes block cannot be told apart from that forgery, and it is not
    // the verifier's place to guess which one it is holding.
    if (cms.looksLikeSignedAttributes(content)) {
      return { mismatch: {
        code: "cms/ambiguous-content",
        message: "the content of a SignerInfo with no signed attributes is itself an encoded " +
          "SignedAttributes block, which is indistinguishable from a signature over attributes " +
          "re-presented as one over content (RFC 5652 sec. 5.4); sign such content WITH signed attributes",
      } };
    }
    return content;
  }
  // With signed attributes: decode them from the EXACT bytes the signature covers, namely the
  // SignedAttributes SET OF with the on-wire [0] IMPLICIT tag replaced by a universal SET OF
  // (RFC 5652 sec. 5.4). The content-type / message-digest checks then bind the same bytes
  // that are verified. Reading the caller-mutable parsed si.signedAttrs instead would let a
  // parsed-object input desync the checked attributes from the verified preimage.
  var reTagged = intrinsic.bufferFrom(si.signedAttrsBytes);
  reTagged[0] = 0x31;   // [0] IMPLICIT -> universal SET OF
  var attrs;
  try {
    attrs = _decodeSignedAttrs(reTagged);
  } catch (e) { if (e instanceof CmsError) throw e; throw _err("cms/bad-signed-attrs", "signedAttrs is not a valid SET OF Attribute", e); }
  // The content-type attribute MUST be present, single-valued, and equal the eContentType
  // (RFC 5652 sec. 5.3).
  var ctAttr = intrinsic.filter(attrs, function (a) { return a.type === OID_CONTENT_TYPE; });
  if (ctAttr.length !== 1 || ctAttr[0].values.length !== 1) throw _err("cms/bad-signed-attrs", "signedAttrs must carry exactly one content-type attribute (RFC 5652 sec. 5.3)");
  var ctOid;
  try {
    ctOid = asn1.read.oid(ctAttr[0].values[0]);
  } catch (e) { throw _err("cms/bad-signed-attrs", "the content-type attribute value is not an OBJECT IDENTIFIER", e); }
  if (ctOid !== eContentType) return { mismatch: { code: "cms/content-type-mismatch", message: "the content-type signed attribute does not match the SignedData eContentType (RFC 5652 sec. 5.3)" } };
  // The message-digest attribute MUST be present, single-valued, and equal the digest of the
  // content (RFC 5652 sec. 5.4).
  var mdAttr = intrinsic.filter(attrs, function (a) { return a.type === OID_MESSAGE_DIGEST; })[0];
  if (!mdAttr || mdAttr.values.length !== 1) throw _err("cms/bad-signed-attrs", "signedAttrs must carry exactly one message-digest attribute (RFC 5652 sec. 5.4)");
  var declared;
  try {
    declared = asn1.read.octetString(mdAttr.values[0]);
  } catch (e) { throw _err("cms/bad-signed-attrs", "the message-digest attribute value is not an OCTET STRING", e); }
  // Over a buffered content the digest is computed here; over a streamed content it was computed once,
  // incrementally, before any signer was verified, and looked up by algorithm.
  var d = digestByName ? digestByName[si.digestAlgorithm.name] : await _computeDigest(si.digestAlgorithm.name, content);
  // Captured equality, not d.equals: over a streamed content the untrusted iterator's next() ran during
  // the digest await and could have replaced Buffer.prototype.equals with one that always answers true,
  // passing this message-digest check for content that was never signed (CWE-347).
  if (!intrinsic.bufferEquals(d, declared)) return { mismatch: { code: "cms/message-digest-mismatch", message: "the message-digest attribute does not match the content digest" } };
  return reTagged;
}

// Verify a composite ML-DSA SignerInfo (draft-ietf-lamps-cms-composite-sigs). The composite
// verify engine lives in composite-sig.js (shared with certification-path validation); this branch
// enforces the CMS-specific rules the X.509 path does not: params-absent on the signatureAlgorithm
// (sec. 3.4, defense-in-depth over the parse-time _PARAMS_ABSENT gate), the unsupported-arm refusal,
// and the sec. 3.4/sec. 5 coherence gate binding the SignerInfo digestAlgorithm to the arm's Table-1
// pre-hash. It reuses the sec. 5.4 preimage + message-digest binding UNCHANGED, then dispatches
// compositeVerify per candidate certificate (both components must verify, with no AND->OR
// downgrade).
async function _verifyComposite(si, comp, content, eContentType, parsedCerts, csTarget, digestByName) {
  if (si.signatureAlgorithm.parameters !== null && si.signatureAlgorithm.parameters !== undefined) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the composite signatureAlgorithm parameters must be absent (draft-ietf-lamps-cms-composite-sigs sec. 3.4)" });
  }
  // The 2 arms Node's WebCrypto surface cannot verify (the brainpool curves) fail closed --
  // never a silent single-component accept (the AND->OR downgrade this feature prevents).
  if (comp.trad.unsupported) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "composite " + comp.name + ": " + comp.trad.unsupported });
  }
  // draft sec. 3.4: for a composite SignerInfo the digestAlgorithm parameters MUST be OMITTED
  // (id-sha256/id-sha512 and id-shake256). That is stricter than the generic RFC 5754 absent-OR-NULL
  // rule (which the classical/ML-DSA paths follow), because the composite draft explicitly requires the
  // field omitted. A present parameter -- even a DER NULL -- is non-conformant and fails closed
  // (it is outside the signed preimage, so a parser differential must not verify).
  var dp = si.digestAlgorithm.parameters;
  if (dp !== null && dp !== undefined) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the composite " + si.digestAlgorithm.name + " digestAlgorithm parameters must be omitted (draft-ietf-lamps-cms-composite-sigs sec. 3.4)" });
  }
  // sec. 3.4 / sec. 5 (the one CMS-specific MUST the X.509 path does not cover): the SignerInfo
  // digestAlgorithm MUST equal the arm's pre-hash (Table 1) -- compositeVerify takes the pre-hash
  // from the OID-keyed descriptor, so a disagreeing digestAlgorithm would recompute the
  // message-digest attribute under the WRONG algorithm. The sec. 5 SHOULD-reject is taken
  // fail-closed; the MAY-verify-anyway leniency is deliberately not taken.
  if (si.digestAlgorithm.name !== comp.phCms) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the SignerInfo digestAlgorithm " + JSON.stringify(si.digestAlgorithm.name) + " is not the composite " + comp.name + " pre-hash " + JSON.stringify(comp.phCms) + " (draft-ietf-lamps-cms-composite-sigs sec. 3.4)" });
  }
  var signers = _findSignerCerts(si.sid, parsedCerts);
  if (!signers.length) return _pResolve({ ok: false, code: "cms/signer-cert-not-found", sid: si.sid, message: "no certificate matches this SignerInfo's signer identifier" });
  var sigBytes = _toBuf(si.signature, "the SignerInfo signature");
  // `await`, not `.then`: see _verifyAgainstCandidates.
  var signedBytes = await (csTarget != null ? _computeCountersigBytes(si, csTarget) : _computeSignedBytes(si, content, eContentType, digestByName));
  if (signedBytes && signedBytes.mismatch) return { ok: false, code: signedBytes.mismatch.code, sid: si.sid, cert: signers[0].der, message: signedBytes.mismatch.message };
  return _verifyCompositeAgainstCandidates(comp, sigBytes, signedBytes, si.sid, signers, si.signatureAlgorithm.oid);
}

// Dispatch compositeVerify against each matching candidate; the signer is valid iff one candidate
// verifies both components. A candidate whose SPKI composite OID != the SignerInfo signatureAlgorithm
// OID is skipped with a precise verdict (RFC 9814 sec. 4 key<->signature agreement); a candidate that
// returns a structural fault code (bad split length, unsupported) falls through, its code surfaced if
// none verifies. A clean both-components-checked failure (the AND-downgrade) is a code-less false.
async function _verifyCompositeAgainstCandidates(comp, sigBytes, signedBytes, sid, candidates, expectedKeyOid) {
  var lastErr = null;
  for (var idx = 0; idx < candidates.length; idx++) {
    var c = candidates[idx];
    if (c.cert.subjectPublicKeyInfo.algorithm.oid !== expectedKeyOid) {
      lastErr = _err("cms/unsupported-algorithm", "the signer certificate public-key algorithm does not match the SignerInfo signatureAlgorithm");
      continue;
    }
    // `await`, not `.then`: see _verifyAgainstCandidates.
    var r = await compositeSig.compositeVerify(c.cert.subjectPublicKeyInfo.bytes, sigBytes, signedBytes, comp, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
    if (r.ok === true) return { ok: true, sid: sid, cert: c.der };
    if (r.code) lastErr = (r.error instanceof CmsError) ? r.error : _err(r.code, r.error && r.error.message ? r.error.message : "the composite signature could not be evaluated");
  }
  return lastErr ? { ok: false, code: lastErr.code, sid: sid, cert: candidates[0].der, message: lastErr.message }
    : { ok: false, sid: sid, cert: candidates[0].der };
}

// The decoded unsigned attributes of a SignerInfo, surfaced UNAUTHENTICATED (they are outside
// the signature) with each OID resolved to a name, so a caller can read an attached RFC 3161
// timestamp token or inspect a countersignature attribute. They are never counted toward a
// signer's ok / res.valid.
function _surfaceUnsignedAttrs(si) {
  return intrinsic.map(si.unsignedAttrs || [], function (a) {
    return { type: a.type, typeName: oid.name(a.type) || null, values: a.values };
  });
}

// Verify every countersignature attached to `si` (RFC 5652 sec. 11.4): each id-countersignature
// value is a SignerInfo over `si`'s signature octets. Returns per-countersignature verdicts; a
// countersignature's own countersignatures verify over its signature octets (recursive). A
// countersignature that fails to verify is surfaced ok:false. It is never silently dropped, and
// never allowed to change the primary verdict. A countersignature value that is not a well-formed
// SignerInfo does not reach here at all: the decoder validates every id-countersignature value by
// its content, so such a message is refused whole. The recursion terminates because it only walks
// the FINITE parsed structure: each nested countersignature value is a sub-encoding of its parent,
// and the strict decoder already bounds total nesting by C.LIMITS.DER_MAX_DEPTH at parse
// (CWE-834/770), so a hostile deep chain fails closed before verify.
async function _verifyCountersignatures(si, parsedCerts) {
  // si.signature is always a Buffer from the strict parser (and from walkCountersignature on the
  // recursive path), so _toBuf is a pass-through here. The SignerInfo is already well-formed.
  var targetSig = _toBuf(si.signature, "the countersigned signature");
  var values = [];
  // Captured enumeration: over a streamed content the untrusted iterator's next() ran during the
  // digest await and could replace Array.prototype.forEach / push to drop a failing countersignature.
  intrinsic.forEach(si.unsignedAttrs || [], function (a) {
    if (a.type !== OID_COUNTERSIGNATURE) return;
    intrinsic.forEach(a.values, function (v) { intrinsic.push(values, v && v.bytes ? v.bytes : v); });
  });
  // Sequential, started only as awaited (see _verify): not Promise.all (its element handling dispatches
  // through the replaceable Promise.prototype.then), and not started-all-then-awaited (an early
  // rejection would leave a later one unobserved).
  var out = [];
  for (var _cp = 0; _cp < values.length; _cp++) intrinsic.push(out, await _verifyOneCountersig(values[_cp], targetSig, parsedCerts));
  return out;
}

async function _verifyOneCountersig(vDer, targetSig, parsedCerts) {
  var csSi;
  // Coverage residual, and deliberately kept. Every value reaching here was already walked by the
  // decoder, which validates an id-countersignature by content and not by the attribute type. A
  // malformed one therefore refused the whole message before verify was entered, so this catch
  // cannot be reached through the public path. That is settled behavior: a message the decoder
  // has found to be malformed has no sound remainder to report a verdict over, so it is refused
  // whole instead of surfaced as one failed countersignature.
  // cms-verify.test.js pins that through the shipped verbs; this stays because the walk is also
  // reachable recursively and a backstop that returns a NEGATIVE verdict costs nothing.
  try { csSi = cms.walkCountersignature(asn1.decode(intrinsic.isBuffer(vDer) ? vDer : intrinsic.bufferFrom(vDer))); }
  catch (e) { return { ok: false, code: (e instanceof CmsError ? e.code : "cms/bad-countersignature"), message: e && e.message }; }
  // `await`, not `.then`: see _verifyAgainstCandidates.
  var verdict = await _verifyOne(csSi, targetSig, null, parsedCerts, targetSig);
  var nested = await _verifyCountersignatures(csSi, parsedCerts);
  var node = { ok: verdict.ok, sid: verdict.sid, cert: verdict.cert, digestAlgorithm: csSi.digestAlgorithm.name };
  if (verdict.code) node.code = verdict.code;
  node.unsignedAttrs = _surfaceUnsignedAttrs(csSi);
  node.countersignatures = nested;
  return node;
}

/**
 * @primitive  pki.cms.verify
 * @signature  pki.cms.verify(input, opts?) -> Promise<{ valid, trusted, eContentType, signers }>
 * @since      0.2.14
 * @status     stable
 * @spec       RFC 5652
 * @spec       RFC 9882
 * @spec       RFC 9814
 * @defends    cms-signature-forgery (CWE-347)
 * @related    pki.schema.cms.parse, pki.path.validate
 *
 * Verify a CMS SignedData signature (RFC 5652 sec. 5). `input` is a PEM string, a DER
 * `Buffer`, or a parsed `pki.schema.cms` object. Returns `{ valid, trusted, eContentType, signers }`
 * where each `signers[i]` is `{ ok, sid, cert, trusted, signedAttributesPresent }` (`cert` the
 * matched signer certificate DER) or carries a `code` on a structural failure; `valid` is true when
 * there is at least one signer and every signer verified.
 *
 * `eContentType` and `signedAttributesPresent` are there for a caller whose profile is stricter
 * than RFC 5652's. Signing WITH attributes and signing the content directly are different claims --
 * attributes bind a content type and a signing time alongside the digest, content-only binds
 * nothing but the bytes -- and one message may carry a signer of each. A profile that requires
 * attributes (RFC 8551 S/MIME does) or a particular content type can enforce it from the verdict,
 * with no need to parse the message a second time.
 *
 * `valid` and `trusted` are DIFFERENT claims and neither implies the other. A SignedData carries
 * its own certificates, so `valid` establishes that the message is internally consistent: the
 * signature is sound under a certificate the message or `opts.certs` supplied. Anyone can mint a
 * certificate, sign with it, and embed it, so that says nothing about WHO signed. `trusted` says
 * every signer chained to a root named in `opts.trustAnchors`, validated through the same RFC 5280
 * path engine `pki.path.validate` uses. Without anchors there is nothing to chain to and `trusted`
 * is `false` -- a definite answer, not a missing one. Anchors that cannot be read are a
 * configuration fault and throw. Absorbing them into `trusted: false` would report a verdict
 * about the message for a check that never ran.
 *
 * Trust is decided from the certificate the SignerInfo selected, the one reported as
 * `signers[i].cert`, never from another certificate that happens to share its key. A
 * `subjectKeyIdentifier` names a key, and several certificates can hold it with different
 * validity windows, key usage and policies; deciding from a sibling would let an expired or
 * wrong-purpose signer certificate be reported trusted because a different certificate chained.
 * Supply the certificate you want used. RSA (PKCS#1 v1.5 and RSASSA-PSS), ECDSA, EdDSA, and the post-quantum
 * ML-DSA (ML-DSA-44/65/87, RFC 9882) and SLH-DSA (the twelve FIPS 205 sets, RFC 9814) signatures
 * are recognized, the post-quantum families in pure mode with an empty context, as is composite
 * ML-DSA (draft-ietf-lamps-cms-composite-sigs), which pairs ML-DSA with a traditional
 * RSA / ECDSA / EdDSA and verifies only when both components pass (never an AND-to-OR downgrade).
 *
 * @opts  content  The detached content when the SignedData carries no encapsulated eContent, and
 *                 required for a detached signature. A `Buffer`, or an async iterable of byte chunks
 *                 to verify a large payload without holding it in memory. The streamed form is hashed
 *                 once for every signer, so every signer must carry signed attributes; a signer that
 *                 signs the content directly needs the content as a `Buffer`.
 * @opts  certs    Extra signer certificates (an array of DER `Buffer`s) to match against, in
 *                 addition to the certificates embedded in the SignedData.
 * @opts  trustAnchors  The roots the caller accepts (DER `Buffer`s or anchor tuples). Supplying
 *                 them is what makes `trusted` answerable; the SignedData's own certificates are
 *                 offered as intermediates, never as anchors.
 * @opts  time     The instant to validate the signer's chain at (default now). Only read when
 *                 `trustAnchors` is supplied.
 * @opts  requiredEku   Key purposes the SIGNER certificate must carry, as OID names or dotted OIDs.
 * @opts  checkPurpose  The purpose the ANCHOR's own trust metadata must permit. This is a separate
 *                 question from `requiredEku`, since a root distributed with NSS trust bits can be
 *                 marked untrusted for one purpose and good for another. Those bits and
 *                 `distrustAfter` are consulted only when this names a purpose.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var detachedBytes = Buffer.from("hello");
 *   var p7sDer = await pki.cms.sign(detachedBytes, { cert: cert, key: key, detached: true });
 *   var res = await pki.cms.verify(p7sDer, { content: detachedBytes });
 *   res.valid;                         // boolean
 *   res.signers[0].ok;                 // per-signer verdict
 */
// A private copy of the input when -- and only when -- it is memory the caller can
// still write to. Anything else (a PEM string, and whatever else the parser accepts)
// is returned untouched so this cannot narrow the input contract of the parse it
// feeds; the parser stays the one place that decides what an acceptable input is.
function _snapshotIfBytes(input, label) {
  // Every byte form the parser accepts -- an ArrayBuffer or a DataView reaches the
  // decoder as readily as a Buffer, and leaving those aliased would reopen the
  // window for exactly the inputs that came in by the wider door.
  if (guard.bytes.isByteSource(input)) {
    return guard.bytes.snapshotSource(input, CmsError, "cms/bad-input", label);
  }
  return input;
}

// For a streamed (async-iterable) detached content: hash the stream ONCE, incrementally, under every
// distinct SUPPORTED SignerInfo digest algorithm, returning { <digestName>: Buffer } (streaming), or
// null (not streaming; digest per-signer over the buffered content). No per-signer condition aborts
// the whole message here, matching the buffered path's per-signer verdicts: a content-only signer
// (no signed attributes, whose signature is over content a stream does not retain) and an unsupported
// digest each contribute no name and are verdicted per-signer by _verifyOne / _computeSignedBytes.
// An empty map is still the streaming marker, so those per-signer verdicts are produced. `streamSource`
// is the lazy stream classified at the door (null when not streaming, buffered per-signer); its
// iterator is acquired only if a digest is actually needed, so an all-content-only message never opens it.
async function _resolveContentDigests(parsed, streamSource) {
  if (streamSource == null) return null;
  var names = [], seen = {};
  intrinsic.forEach(parsed.signerInfos, function (si) {
    var dn = si.digestAlgorithm.name;
    if (si.signedAttrsBytes && _supportedDigest(dn) && !seen[dn]) { seen[dn] = 1; intrinsic.push(names, dn); }
  });
  // No signer needs a streamed digest (all content-only or unsupported): nothing to hash, but the
  // empty map still marks streaming mode so each signer gets its per-signer verdict.
  if (!names.length) return {};
  // `await`, not `.then`: this is where the UNTRUSTED stream is consumed, so the very next promise step
  // must not dispatch through a Promise.prototype.then the stream may have replaced.
  var ds;
  try {
    ds = await subtle.digestStream(intrinsic.map(names, function (n) { return DIGEST_HASH[n]; }), streamSource);
  } catch (e) {
    // The engine reports malformed streamed content in its own domain; report it in this verb's via the
    // shared guard, rather than leaking the engine code. The digest algorithm names are this module's own,
    // so a webcrypto/syntax here is never an algorithm fault.
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
  var byName = {};
  intrinsic.forEach(names, function (n, i) { byName[n] = intrinsic.bufferFrom(ds[i]); });
  return byName;
}

// Every option pki.cms.verify reads. Adding one here is the only way to make it accepted, so a
// capability cannot arrive with its option silently ignored at this boundary.
var _VERIFY_OPTS = { certs: 1, content: 1, trustAnchors: 1, time: 1, requiredEku: 1, checkPurpose: 1 };

// Documented `-> Promise`, so a fault leaves as a REJECTION (guard-async). The checks below stay
// synchronous -- they read a caller's mutable options and bytes, and resolving those before any turn
// passes is what stops a value being swapped between the check and the use.
function verify(input, opts) {
  return guard.async.deferred(function () { return _verify(input, opts); });
}

async function _verify(input, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.verify options");
  // An unrecognized option is refused, not swallowed. This is what kept the missing trust seam
  // silent: a caller writing `trustAnchors` before it existed -- or `trustAnchor` now -- got a
  // verdict that looked anchored and was not. The guard rejects through a (code, message) FACTORY
  // and tests membership with hasOwnProperty, so the permitted set is a lookup object.
  guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "cms/bad-input", "pki.cms.verify has an unknown option ");
  // Handed MUTABLE BYTES, parse a private copy. This function decodes synchronously
  // and checks signatures in a later promise turn, so without the copy every range
  // the parse surfaced -- the signed content above all -- stays a view into the
  // caller's memory across that await, and a buffer rewritten in the gap would leave
  // the result describing one message while the signature was checked over another.
  // Re-derived from the bytes the parser read, never trusted as the object it arrives as. A
  // SignedData's meaning is a signature over a byte range, but a parsed one presents that range
  // (`signedAttrsBytes`, or the encapsulated `eContent` when there are no signed attributes), the
  // signature, the algorithms and the certificates as SEPARATE properties. Keep a genuine signer's
  // signature and signed attributes and put different content beside them and every part of this
  // check passes for a message that signer never signed -- the forgery this verb's own block claims
  // to defend (CWE-347). A duck-type test on `signerInfos` cannot see that, because every field is
  // individually well-formed; only re-deriving them all from one byte string can.
  var parsed = guard.parsed.acceptDerived(input, "cms", function (bytes) {
    return cms.parse(_snapshotIfBytes(bytes, "pki.cms.verify"));
  }, _err, "cms/bad-input", "the SignedData");
  if (!Array.isArray(parsed.signerInfos)) throw _err("cms/bad-input", "input is not a CMS SignedData");
  // The trust configuration is snapshotted HERE, before opts.content is read at all. A streamed
  // content's Symbol.asyncIterator accessor runs the moment asyncStreamOf reads it, one turn before a
  // snapshot taken further down would run; from that accessor a caller can replace a global the snapshot
  // itself relies on -- the Date it defaults the validation instant from, or the Array.isArray /
  // Array.prototype.map / slice it copies the anchors and requiredEku with -- and steer the trust
  // decision. Taken before the content object is touched, every value the snapshot reads comes from a
  // pristine global. It also stays caller-owned across the later await: the array cannot be re-pointed,
  // an anchor's DER rewritten, or the instant moved, once copied -- the same defense the input and the
  // certificates already have.
  var trustCfg = _snapshotTrust(opts);
  // Pre-parse every candidate certificate (embedded + caller-supplied) once, BEFORE opts.content is
  // touched. The caller-supplied set (opts.certs) is read here; a streamed content's accessor -- run the
  // moment asyncStreamOf reads it below -- could otherwise mutate that array, or replace the
  // Array.prototype.forEach this loop uses, and change which certificates the signer match and the trust
  // build see. Taken first, the candidate pool is the one the caller passed.
  var parsedCerts = [];
  (parsed.certificates || []).forEach(function (c) { _addCert(parsedCerts, c && c.bytes ? c.bytes : c); });
  (opts.certs || []).forEach(function (c) { _addCert(parsedCerts, c); });
  var content = parsed.encapContentInfo.eContent;
  var streamSource = null;
  if (content == null) {
    if (opts.content == null) throw _err("cms/detached-content-required", "this SignedData is detached; opts.content (the external content) is required");
    // A streamed (async-iterable) detached content is classified by asyncStreamOf, which reads
    // Symbol.asyncIterator a single time and returns a LAZY stream whose iterator is acquired only when
    // it is driven below, after the per-signer digest algorithms are known, so a single-use stream
    // serves every signer in one pass and a message needing no streamed digest never acquires it. It is
    // not snapshotted: a stream has no bytes to copy, and it is consumed exactly once. A byte source (or
    // any non-iterable) yields null and is buffered.
    streamSource = guard.bytes.asyncStreamOf(opts.content);
    if (streamSource == null) {
      // Copied, not aliased: the digest over this content is computed in a later promise turn,
      // and a detached signature's content is the whole of what the signature speaks about. A
      // caller who rewrote the buffer in that gap would have the signature checked against the
      // original bytes while holding the replacement, and the verdict would report a valid
      // signature over content that was never signed.
      content = _toBuf(_snapshotIfBytes(opts.content, "opts.content"), "opts.content");
    }
  } else if (opts.content != null) {
    // A caller supplied external content AND the SignedData is attached. A redundant COPY that equals
    // the encapsulated content is fine; content that DIFFERS is a substitution trap -- silently
    // preferring the embedded copy would let the caller believe it verified opts.content when the
    // signature covers different embedded bytes. Fail closed on a mismatch.
    if (Buffer.compare(_toBuf(opts.content, "opts.content"), Buffer.from(content)) !== 0) {
      throw _err("cms/content-conflict", "opts.content disagrees with this SignedData's own encapsulated content (a detached signature must omit eContent)");
    }
  }
  var eContentType = parsed.encapContentInfo.eContentType;
  // `await` throughout the aggregation, never `.then`: the streamed content is consumed inside
  // _resolveContentDigests, so from here on every promise step must dispatch through no
  // caller-replaceable Promise.prototype.then. Captured enumeration (intrinsic.map) guards
  // Array.prototype.map; awaiting each promise (never Promise.all) guards the chaining (CWE-347).
  var digestByName = await _resolveContentDigests(parsed, streamSource);
  // Each signer is verified SEQUENTIALLY -- started only as it is awaited. NOT Promise.all: its
  // spec-internal element handling calls the caller-replaceable Promise.prototype.then, so a streamed
  // content that replaced it could fabricate a resolved `{ ok: true }` for every signer; await
  // dispatches through no such method. And NOT started-all-then-awaited-each: an earlier signer's
  // rejection would leave a later one's rejection unobserved, which Node can escalate to a crash.
  // Per-signer work is small, so the sequential cost is negligible.
  var signers = [];
  for (var _sp = 0; _sp < parsed.signerInfos.length; _sp++) {
    var siOne = parsed.signerInfos[_sp];
    // res.valid reflects only the PRIMARY signerInfos; a countersignature / unsigned attribute is
    // outside the signature and NEVER flips the top-level verdict. Both are surfaced per signer.
    var verdict = await _verifyOne(siOne, content, eContentType, parsedCerts, null, digestByName);
    verdict.countersignatures = await _verifyCountersignatures(siOne, parsedCerts);
    verdict.unsignedAttrs = _surfaceUnsignedAttrs(siOne);
    // Whether THIS signer signed attributes or signed the content directly. The two are different
    // claims -- attributes bind a content type and a signing time alongside the digest, and content-only
    // binds nothing but the bytes -- and RFC 5652 lets a message carry one signer of each. A caller
    // whose profile requires attributes (RFC 8551 S/MIME does) can only enforce it if the verdict says
    // which they got.
    verdict.signedAttributesPresent = !!siOne.signedAttrsBytes;
    intrinsic.push(signers, verdict);
  }
  // The content type travels with the verdict. An operator applying a policy of their own -- "I only
  // accept id-data", or a profile that names its own type -- otherwise had to parse the message a
  // second time to learn it, and a check that needs a second parse is a check most callers will not write.
  var res = {
    // Signature soundness is decided by comparison for the same reason the trust verdict below is:
    // `every` replaced after load reports the whole set sound without reading one signer.
    valid: signers.length > 0 && guard.list.allMatch(signers, function (s) { return s.ok === true; }),
    eContentType: parsed.encapContentInfo.eContentType,
    signers: signers,
  };
  await _applyTrust(res, parsedCerts, trustCfg);
  return res;
}

// The full path build + validate, injected by path-validate the way it injects into crl-verify and
// cmp-verify. It is a seam rather than a require because path-validate is the higher layer: taking
// the dependency the other way round would be a cycle, and re-implementing a weaker chain walk here
// is exactly how a second, divergent notion of trust gets into a toolkit.
var _engine = null;
function setEngine(engine) { _engine = engine; }

// `valid` and `trusted` are DIFFERENT claims and neither implies the other. `valid` says every
// signature is sound under a certificate the message or the caller supplied -- a message carries its
// own certificates, so that establishes internal consistency and nothing about who signed. `trusted`
// says the signer chained to a root the CALLER named. Without anchors there is no one to chain to,
// so it is false: not null, because "nobody anchored this" is a definite answer, and the same one a
// caller gets from pki.cmp.verify.
// A private copy of the trust configuration, taken at the entry point. The array is copied so it
// cannot be re-pointed or grown; each anchor's BYTES are copied because rewriting those in place is
// the same substitution one level down; the instant is copied because a Date is mutable. An anchor
// TUPLE is copied too, field by field: `{ name, publicKey, algorithm }` is an ordinary object whose
// key bytes and name can be rewritten just as readily as a DER buffer's, and copying only the DER
// form would leave the documented tuple form aliased across the same gap -- the window closed for
// one spelling of an anchor and left open for the other. A PEM string needs no copy: it cannot be
// rewritten. `requiredEku` is copied for the same reason as the array.
var _ANCHOR_CLONE_DEPTH = 8;
function _cloneAnchorValue(v, depth) {
  if (guard.bytes.isByteSource(v)) {
    return _snapshotIfBytes(v, "opts.trustAnchors[]");
  }
  if (v === null || typeof v !== "object") return v;
  // A Date BEFORE the generic object walk. It has no enumerable own properties, so copying it
  // field by field yields `{}` -- an anchor's `distrustAfter: { emailProtection: <Date> }` would
  // survive the snapshot as an empty object and be rejected as an invalid date, disabling the very
  // policy it encodes. Copied by value, like the validation instant.
  // The instant comes through the guard's intrinsic read, so a caller's `getTime` override can
  // neither throw out of the snapshot nor put a different instant in the copy than the original
  // holds -- which would leave the anchor policy that was checked and the one that is applied two
  // different values.
  if (guard.time.isDate(v)) return new intrinsic.Date(guard.time.instantOf(v));
  // A structure too deep to copy is REFUSED, not shared. Returning it by reference at the cap
  // would leave part of the anchor caller-mutable across the chain walk while the rest was
  // snapshotted -- a guarantee that holds for the shallow fields and quietly lapses for the deep
  // ones, which is worse than not offering it. An anchor tuple is a handful of levels deep; a
  // deeper one is a caller's mistake, and it fails closed at the entry point.
  if (depth >= _ANCHOR_CLONE_DEPTH) {
    throw _err("cms/bad-input", "an opts.trustAnchors entry nests deeper than " + _ANCHOR_CLONE_DEPTH +
      " levels, so it cannot be copied before the chain is walked; pass the anchor as certificate DER or a { name, publicKey, algorithm } tuple");
  }
  if (Array.isArray(v)) return v.map(function (e) { return _cloneAnchorValue(e, depth + 1); });
  var out = {}, k;
  for (k in v) {
    if (!intrinsic.hasOwn(v, k)) continue;
    out[k] = _cloneAnchorValue(v[k], depth + 1);
  }
  return out;
}
function _snapshotTrust(opts) {
  var raw = opts.trustAnchors;
  var anchors = null;
  if (raw != null) {
    anchors = (Array.isArray(raw) ? raw : [raw]).map(function (a) {
      return typeof a === "string" ? a : _cloneAnchorValue(a, 0);
    });
  }
  return {
    trustAnchors: anchors,
    // The validation instant, read from the captured Date intrinsic, never the live global Date. The
    // snapshot is taken before opts.content is touched (see _verify), so no content accessor has run to
    // replace a global yet; reading the instant through the captured constructor holds even if that
    // ordering regresses. A caller Date is cloned; undefined becomes now.
    time: guard.time.isDate(opts.time) ? new intrinsic.Date(guard.time.instantOf(opts.time)) : (opts.time === undefined ? new intrinsic.Date() : opts.time),
    requiredEku: Array.isArray(opts.requiredEku) ? opts.requiredEku.slice() : opts.requiredEku,
    checkPurpose: opts.checkPurpose,
  };
}

// A signer certificate whose keyUsage FORBIDS signing has not been permitted to sign, however well
// it chains. RFC 5280 sec. 4.2.1.3: when the extension is present it is binding, and a leaf
// asserting keyEncipherment alone must not verify a signature. Path validation checks the CA's
// keyCertSign, not the target's own usage, so the format that knows a signature was made asks the
// question -- the same format-local gate on top of path.validate that pki.cmp.verify applies.
// contentCommitment (nonRepudiation) counts: RFC 5652 signatures are made under either bit.
// The value is read through the ONE strict decoder, which enforces the X.690 sec. 11.2.2 minimal
// NamedBitList form, so a malformed keyUsage fails the gate rather than a hand-rolled bit test
// authorizing it.
// The shared RFC 5280 sec. 4.2.1 extension-value decoders, the same set pki.cmp.verify reads its
// signer keyUsage through -- one structurally-strict decoder rather than a second, weaker bit test.
var _CERT_EXT_DECODERS = pkix.certExtensionDecoders(pkix.makeNS("cms", CmsError, oid)).byOid;

function _keyUsagePermitsSigning(parsedCerts, der) {
  // Captured filter + equality: this runs after the streamed content was consumed, and the fail-open
  // `if (!entry) return true` below would otherwise be reachable by a hostile iterator that replaced
  // Buffer.prototype.equals to return false, making the signer certificate un-findable and its
  // keyUsage un-read -- a keyEncipherment-only certificate would then be reported trusted (CWE-347).
  var entry = intrinsic.filter(parsedCerts, function (c) { return intrinsic.bufferEquals(c.der, der); })[0];
  if (!entry) return true;                    // not among the candidates: nothing to read
  var kuOid = oid.byName("keyUsage");
  var exts = entry.cert.extensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== kuOid) continue;
    var ku;
    try { ku = _CERT_EXT_DECODERS[kuOid](exts[i].value); }
    catch (_e) { return false; }              // unreadable usage is not permission
    return ku.digitalSignature === true || ku.contentCommitment === true || ku.nonRepudiation === true;
  }
  return true;                                // absent: unconstrained (sec. 4.2.1.3)
}

// Every signer trusted? The answer IS the message-level trust verdict, so it is decided by
// comparison instead of by an `every`. See guard-list.
function _allTrusted(signers) {
  return guard.list.allMatch(signers, function (s) { return s.trusted === true; });
}

// `cfg` is verify's SNAPSHOT, never the caller's options object -- the parameter is named for that
// so a future caller cannot hand it the live one without noticing.
async function _applyTrust(res, parsedCerts, cfg) {
  res.trusted = false;
  // Every signer carries the field too, whether or not anchors were supplied. A verdict whose
  // per-signer shape depends on which options were passed makes a caller iterating `signers` write
  // a different loop for each case -- and the absent field reads as "unknown" where the answer is
  // a definite "nothing anchored this".
  // async + captured enumeration + await (see _verify): the trust verdict is decided after the streamed
  // content was consumed, so a hostile iterator must not steer it through a replaced Array.prototype or
  // Promise.prototype.then.
  intrinsic.forEach(res.signers, function (s) { s.trusted = false; });
  if (cfg.trustAnchors == null) return;
  if (!_engine) {
    throw _err("cms/bad-input", "opts.trustAnchors requires the path validator; load pki.path before verifying (require the toolkit through its index)");
  }
  // Every signer, not merely one: a multi-signer message's signers are independent claims, and
  // reporting the whole as trusted because one of them anchored would let an unanchored signer ride
  // out on another's chain -- the same rule the per-signer `ok` already follows for signatures.
  var pool = intrinsic.map(parsedCerts, function (c) { return c.der; });
  // The default instant was captured at snapshot time (see _snapshotTrust), before the stream ran, so
  // no live `new Date()` is read here where a replaced Date could steer the validation instant.
  var at = cfg.time;
  var anchors = cfg.trustAnchors;
  // The configuration is checked HERE, once, before any signer is looked at. Leaving it to the
  // chain walk would make a caller's mistake depend on the message: a SignedData whose every signer
  // failed to verify never reaches a build call, so unusable anchors would be accepted in silence
  // and reported as `trusted: false` -- the config fault dressed as a verdict, which is exactly the
  // conflation this seam exists to remove. An empty anchor list is refused for the same reason a
  // policy that constrains nothing is: it cannot make anything trusted, so asking for it is a
  // mistake rather than a request.
  if (!anchors.length) {
    throw _err("cms/bad-input", "opts.trustAnchors is empty -- name at least one root, or omit it to state that the signer is not being anchored");
  }
  // The INSTANT and the key purposes, before the anchors -- the anchor check reads the NORMALIZED
  // purpose the resolver returns, so it has to run first.
  if (cfg.time !== undefined) guard.time.assertValid(cfg.time, _err, "cms/bad-input", "opts.time");
  // The resolver's RETURN is what the walk goes on to use: it normalizes a dotted purpose OID to
  // its registered name, which is the key an anchor's per-purpose metadata is stored under.
  // Preflighting with the caller's raw spelling would look up `distrustAfter["1.3.6.1.5.5.7.3.4"]`
  // where the walk reads `distrustAfter.emailProtection` -- the same value checked under two
  // different keys, so the early check would pass on metadata the walk then rejects.
  var purposes = _engine.resolvePurposeOpts({ requiredEku: cfg.requiredEku, checkPurpose: cfg.checkPurpose });
  // The WHOLE anchor, not only its identity: `toAnchor` settles the name / key / algorithm tuple,
  // and the constraint metadata beside it -- the per-purpose distrustAfter dates -- is validated
  // through the same definition the walk uses. Checking one and not the other is how this rule has
  // repeatedly come back: each new part of the configuration has to join the preflight, not wait
  // to be caught where it is consumed.
  intrinsic.forEach(anchors, function (a) {
    _engine.toAnchor(a);
    if (purposes.checkPurpose != null) _engine.assertAnchorConstraints(a, purposes.checkPurpose);
  });
  // The INSTANT is checked here for the same reason the anchors are, and in the same place: a
  // Everything above is the preflight: the anchor list, the instant, the key purposes, and each
  // anchor's own constraint metadata -- all judged before a single signer is looked at, and all
  // through the definitions the walk itself uses. A new option joins it here; validating one only
  // where it is consumed is what made a caller's mistake depend on the message.
  for (var _si = 0; _si < res.signers.length; _si++) {
    var s = res.signers[_si];
    {
      if (s.ok !== true || !s.cert) { s.trusted = false; continue; }
      var buildOpts = { trustAnchors: anchors, intermediates: pool, validate: true, time: at };
      // A key purpose, when the caller names one. "Trusted" is not a property of a chain alone: a
      // certificate restricted to serverAuth chains perfectly well and is still the wrong key to
      // have signed an email. The verb that KNOWS the purpose supplies it -- pki.smime.verify asks
      // for emailProtection -- rather than this layer guessing one for every CMS use.
      if (cfg.requiredEku != null) buildOpts.requiredEku = cfg.requiredEku;
      // The ANCHOR's own trust metadata, which is a separate question from the leaf's EKU. A root
      // distributed with NSS trust bits can be marked untrusted for email while remaining a
      // perfectly good TLS root, and `pki.path` consults those bits -- and distrustAfter -- only
      // when a purpose is named. Requiring the leaf's EKU without naming the purpose checks one
      // end of the chain and not the other, so a root explicitly distrusted for the very purpose
      // being asked about would still answer "trusted".
      if (cfg.checkPurpose != null) buildOpts.checkPurpose = cfg.checkPurpose;
      // THE certificate this SignerInfo selected, and only that one -- the same certificate the
      // verdict reports as `cert`. When a subjectKeyIdentifier is used, several certificates can
      // hold the signing key, and it is tempting to let any of them answer: the embedded one may
      // be self-signed while the caller supplied a CA-issued twin. Doing so would decide trust
      // from a certificate the message did not present, carrying a different validity window, key
      // usage and policy set -- so an expired or wrong-purpose signer certificate could be
      // reported trusted through its sibling. `trusted` describes the certificate named in the
      // same verdict; a caller who wants a particular one used supplies that one.
      // Permitted to have signed, as well as chained. Checked BEFORE the chain walk because a
      // certificate that forbids signing cannot become trusted by chaining, so there is nothing to
      // learn from walking it.
      if (!_keyUsagePermitsSigning(parsedCerts, s.cert)) { s.trusted = false; continue; }
      // `await`, not `.then`: see _verify.
      try {
        var r = await _engine.build(s.cert, buildOpts);
        s.trusted = !!(r && r.valid);
      } catch (e) {
        // A CONFIG fault -- unusable anchors, an invalid time -- is the caller's mistake and must
        // not be absorbed into "untrusted", which would read as a verdict about the message. A
        // chain that simply does not reach an anchor is not that: it is the answer.
        if (e && e.code) {
          var code = intrinsic.String(e.code);
          if (intrinsic.stringIndexOf(code, "bad-input") !== -1 ||
              intrinsic.stringIndexOf(code, "bad-anchor") !== -1 ||
              intrinsic.stringIndexOf(code, "bad-time") !== -1) throw e;
        }
        s.trusted = false;
      }
    }
  }
  // The trust verdict is decided by comparison, not by a prototype method: `every` replaced after
  // load answers true without consulting a single signer, and a message no anchor covers reports
  // trusted:true.
  res.trusted = res.valid && res.signers.length > 0 && _allTrusted(res.signers);
}
// Parse a candidate cert DER and index its SKI; a cert that will not parse is skipped (it
// simply cannot be a signer match, and a malformed embedded cert must not fail the verify).
// The certificate bytes are copied BEFORE they are parsed, not after: the parse surfaces the
// signed portion and the public key as VIEWS into this buffer, and both are read in a later
// promise turn to check the signer's signature and walk the chain. Copying afterwards would
// leave those views pointing at bytes the caller can still rewrite -- a signer certificate
// swapped for another in that gap, with the verdict still naming the first.
function _addCert(out, der) {
  var buf;
  try {
    buf = _toBuf(_snapshotIfBytes(der, "a certificate"), "a certificate");
  } catch (_e) { return; }
  var cert;
  try {
    cert = x509.parse(buf);
  } catch (_e2) { return; }
  out.push({ cert: cert, der: buf, ski: _certSki(cert) });
}

// Coverage residual -- these defensive branches are unreachable through the shipped path
// because an upstream contract already narrows the shape:
//   * `cert.extensions || []` -- x509.parse always surfaces `extensions` as an array (empty
//     when absent), so the `|| []` fallback never fires.
//   * `_decodeSignedAttrs`'s `tagNumber !== SET` / `!children` guard -- the caller forces the
//     leading byte to a universal SET OF before decoding, so `asn1.decode` yields a SET whose
//     `children` is always an array; the guard is belt-and-suspenders against a future caller.
//   * `if (!Array.isArray(parsed.signerInfos))` -- the object-input branch is only taken when
//     `signerInfos` is already an array, and cms.parse yields a SignedData whose `signerInfos`
//     is always an array (or it throws), so this belt-and-suspenders throw never fires.
//   * `c && c.bytes ? c.bytes : c` -- schema-cms surfaces every embedded certificate as an
//     object carrying a `bytes` Buffer, so the raw-value fallback never fires.
/**
 * @primitive  pki.cms.sign
 * @signature  pki.cms.sign(content, signers, opts?) -> Promise<Buffer|string>
 * @since      0.2.15
 * @status     stable
 * @spec       RFC 5652
 * @spec       RFC 9882
 * @spec       RFC 9814
 * @related    pki.cms.verify, pki.schema.cms.parse
 *
 * Produce a CMS SignedData (RFC 5652 sec. 5) over `content` (a `Buffer`): the structure
 * S/MIME signed mail, RFC 3161 timestamp tokens, and code signing rest on, and exactly what
 * `pki.cms.verify` consumes and OpenSSL `cms -verify` validates. Each `signers[i]` is
 * `{ cert, key, digestAlgorithm?, pss? }`: `cert` the signer certificate (PEM or DER), `key`
 * its private key (a WebCrypto `CryptoKey` or a PKCS#8 DER `Buffer` / PEM string; for a composite
 * ML-DSA signer, the two component keys `{ mldsa, trad }`, each PKCS#8). The
 * signature covers the RFC 5652 sec. 5.4 preimage: with signed attributes (the default) the
 * message-digest attribute is bound to the content digest and the signature is over the
 * canonical DER SET OF SignedAttributes; otherwise over the content directly. RSA (PKCS#1 v1.5
 * and, with `pss`, RSASSA-PSS), ECDSA (P-256/384/521), Ed25519, Ed448, and the post-quantum ML-DSA
 * (ML-DSA-44/65/87, RFC 9882) and SLH-DSA (the twelve FIPS 205 sets, RFC 9814, with the message
 * digest pinned per parameter set) are covered, as is composite ML-DSA
 * (draft-ietf-lamps-cms-composite-sigs), where the arm's pre-hash fixes the digestAlgorithm and
 * the two component keys are signed together.
 *
 * `content` may instead be an async iterable of byte chunks, such as an async generator, which signs
 * a large payload without holding it in memory. This form requires `detached: true` and signed
 * attributes. The payload is hashed incrementally to build the message-digest attribute, in a single
 * pass that serves every signer, so signers may use different digest algorithms. The signature covers
 * the same content as the buffered form.
 *
 * @opts  detached          Omit the encapsulated content (a detached signature; the verifier
 *                          supplies the content). Default false.
 * @opts  eContentType      The encapsulated content type (an OID name). Default `data`.
 * @opts  signedAttributes  Include signed attributes (content-type, message-digest, signing-time);
 *                          false signs the content directly. Default true.
 * @opts  signingTime       A `Date` for the signing-time attribute, or false to omit it.
 * @opts  sid               `"issuerAndSerial"` (default) or `"ski"` (subjectKeyIdentifier).
 * @opts  certificates      Embed the signer certificates in the output. Default true.
 * @opts  pem               Return a PEM string (`-----BEGIN CMS-----`) instead of a DER Buffer.
 * @opts  unsignedAttributes  Unsigned attributes for every SignerInfo, each `{ type, values }`
 *                          (`type` an OID name or dotted string, `values` an array of DER value
 *                          `Buffer`s). Placed in the SignerInfo `[1]` unsignedAttrs, outside the
 *                          signature, so they carry no cryptographic assurance and a verifier never
 *                          reports them authenticated. The vehicle for an RFC 3161 timestamp token
 *                          (`timeStampToken`); content-type / message-digest / signing-time are
 *                          rejected here (RFC 5652 sec. 11). Use `pki.cms.countersign` for a
 *                          countersignature specifically.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var p7 = await pki.cms.sign(Buffer.from("hello"), { cert: signerCertDer, key: signerKeyPkcs8 });
 *   var res = await pki.cms.verify(p7);   // res.valid === true
 */
var sign = cmsSign.sign;

/**
 * @primitive  pki.cms.countersign
 * @signature  pki.cms.countersign(cms, signers, opts?) -> Promise<Buffer|string>
 * @since      0.3.13
 * @status     stable
 * @spec       RFC 5652
 * @related    pki.cms.sign, pki.cms.verify, pki.schema.cms.parse
 *
 * Add one or more countersignatures to an existing CMS SignedData (RFC 5652 sec. 11.4). A
 * countersignature is itself a `SignerInfo` whose signature covers the CONTENTS of the countersigned
 * SignerInfo's signature value (not the content), attached as the `id-countersignature` unsigned
 * attribute -- the construction Authenticode timestamps and signature-attestation workflows rest on.
 * `cms` is the SignedData (a DER `Buffer` or a PEM `CMS` string; the wire bytes are preserved, so
 * the countersigned primary still verifies byte-for-byte). Each `signers[i]` is the same descriptor
 * `pki.cms.sign` takes (`{ cert, key, digestAlgorithm?, pss? }`, any RSA / RSASSA-PSS / ECDSA /
 * EdDSA / ML-DSA / SLH-DSA / composite key), and countersigns over the target signature octets;
 * `pki.cms.verify` returns each countersignature verdict under `signers[i].countersignatures`. A
 * countersignature never carries a content-type attribute (sec. 11.4); multiple countersignatures on
 * one signer are multiple values of the one id-countersignature attribute.
 *
 * @opts  signerIndex           Which primary SignerInfo(s) to countersign: an index (default 0), an
 *                              array of indices, or `"all"`.
 * @opts  countersignatureOf    Countersign the Nth existing countersignature of the target signer
 *                              instead of the primary signature (a nested countersignature).
 * @opts  signedAttributes      Include signed attributes (message-digest + signing-time; never a
 *                              content-type). Default true; false signs the target signature octets
 *                              directly.
 * @opts  signingTime           A `Date` for the countersignature's signing-time, or false to omit it.
 * @opts  additionalSignedAttributes  Extra signed attributes on the countersignature (a content-type
 *                              is rejected, RFC 5652 sec. 11.4).
 * @opts  sid                   `"issuerAndSerial"` (default) or `"ski"`.
 * @opts  certificates          Embed the countersigner certificate(s) in the SignedData. Default true.
 * @opts  pem                   Return a PEM string instead of a DER Buffer.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var p7 = await pki.cms.sign(Buffer.from("hi"), { cert: signerCertDer, key: signerKeyPkcs8 });
 *   var cs = await pki.cms.countersign(p7, { cert: signerCertDer, key: signerKeyPkcs8 });
 *   var res = await pki.cms.verify(cs);
 *   res.signers[0].countersignatures[0].ok;   // true
 */
var countersign = cmsSign.countersign;

/**
 * @primitive pki.cms.encrypt
 * @signature pki.cms.encrypt(content, recipients, opts?) -> Promise<Buffer | string>
 * @since 0.2.23
 * @status stable
 * @spec RFC 5652, RFC 5083, RFC 5084, RFC 3560, RFC 5753, RFC 8418, RFC 9629, RFC 9936, RFC 3211, RFC 8018
 * @related pki.cms.decrypt, pki.schema.cms.parse
 *
 * Encrypt content as a CMS EnvelopedData (CBC content), AuthEnvelopedData (AEAD content, the
 * default), or EncryptedData. `recipients` is an ARRAY of recipient descriptors for the enveloped
 * family, each wrapping the same fresh content-encryption key: `{ cert }` auto-dispatches off the
 * recipient certificate's public-key algorithm -- RSA yields a ktri with RSAES-OAEP-SHA256 (PKCS#1
 * v1.5 is never emitted); EC P-256/384/521 a kari with ephemeral-static ECDH and the X9.63 KDF;
 * X25519/X448 a kari per RFC 8418 (HKDF); ML-KEM-512/768/1024 an ori/KEMRecipientInfo per RFC
 * 9629 + 9936. `{ password }` yields a pwri (PBKDF2 + RFC 3211 PWRI-KEK); `{ kek, kekId }` a kekri
 * (AES key wrap). For EncryptedData (no RecipientInfos), pass a single non-array `{ cek }` or
 * `{ password }` descriptor. The default AES-256-GCM content encryption produces an
 * authenticated AuthEnvelopedData; a CBC choice produces an unauthenticated EnvelopedData.
 * `content` is a byte source (a `Buffer`, typed array, `DataView`, or `ArrayBuffer`) OR an async
 * iterable of byte chunks. An async iterable is streamed through the content cipher incrementally, so
 * a large plaintext is never buffered whole; the ciphertext is assembled before the DER is emitted, and
 * the emitted message is byte-for-byte what the buffered form of the same plaintext would produce.
 * Malformed input throws a typed `CmsError`.
 *
 * @opts contentEncryptionAlgorithm `"aes-256-gcm"` (default, AuthEnvelopedData) / `"aes-128-gcm"` / `"aes-256-cbc"` / `"aes-128-cbc"` (EnvelopedData).
 * @opts contentType   The encapsulated content type (an OID name). Default `data`.
 * @opts oaepHash      The RSAES-OAEP hash for ktri recipients: `"sha256"` (default) / `"sha384"` / `"sha512"`.
 * @opts keyIdentifier The recipient identifier form: `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts ukm           User keying material (a Buffer) for kari / kemri recipients.
 * @opts authAttrs     Authenticated attributes (SET OF Attribute) for AuthEnvelopedData. Each must be a
 *   well-formed `Attribute SEQUENCE { type, non-empty SET OF value }` and no type may repeat (RFC 5652
 *   sec. 5.3). `message-digest` is refused: its value is the unencrypted hash of the plaintext, which
 *   enables content tracking and confirms a guessed plaintext (RFC 5083 sec. 2.1, sec. 5).
 * @opts pem           Return a PEM string instead of a DER Buffer.
 * @example
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: recipientKeyPkcs8 });
 *   var env = await pki.cms.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 */
var encrypt = cmsEncrypt.encrypt;

/**
 * @primitive pki.cms.authenticate
 * @signature pki.cms.authenticate(content, recipients, opts?) -> Promise<Buffer | string>
 * @since 0.3.14
 * @status stable
 * @spec RFC 5652, RFC 2104, RFC 4231, RFC 3370
 * @related pki.cms.decrypt, pki.schema.cms.parse
 *
 * Produce a CMS AuthenticatedData (RFC 5652 sec. 9): CLEARTEXT content plus a MAC (HMAC-SHA-2) --
 * authenticated but not encrypted, the authenticated-only sibling of AuthEnvelopedData. A single
 * fresh MAC key is minted and wrapped for every recipient with the same RecipientInfo model
 * `pki.cms.encrypt` uses for a content-encryption key, so `recipients` is the identical array of
 * descriptors: `{ cert }` (RSA -> ktri RSAES-OAEP, EC/X25519/X448 -> kari, ML-KEM -> ori/KEMRI),
 * `{ password }` (pwri), or `{ kek, kekId }` (kekri). By default the MAC covers the authenticated
 * attributes (a content-type and a message-digest = digest of the content) re-tagged to the EXPLICIT
 * SET OF (RFC 5652 sec. 9.2); with `authenticatedAttributes: false` (id-data content only) it covers
 * the content octets directly. `pki.cms.decrypt` recovers the MAC key, recomputes the MAC, and --
 * with authenticated attributes -- independently confirms the message-digest before releasing the
 * content, returning `authenticated: true`. Malformed input throws a typed `CmsError`.
 *
 * @opts macAlgorithm `"hmac-sha256"` (default) / `"hmac-sha384"` / `"hmac-sha512"`.
 * @opts digestAlgorithm The authenticated-attributes message-digest hash (defaults to the MAC hash).
 * @opts authenticatedAttributes Include the content-type + message-digest authenticated attributes
 *                          (the default, and required for a non-`data` content type); false MACs the
 *                          content directly.
 * @opts authAttrs Extra authenticated attributes appended to the content-type + message-digest pair.
 * @opts contentType The encapsulated content type (an OID name). Default `data`.
 * @opts keyIdentifier `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts pem Return a PEM string (`-----BEGIN CMS-----`) instead of a DER Buffer.
 * @example
 *   // authenticate a message to an RSA recipient, then verify the MAC via decrypt
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: recipientKeyPkcs8 });
 *   var auth = await pki.cms.authenticate(Buffer.from("hi"), [{ cert: recipientCertDer }]);
 *   var out = await pki.cms.decrypt(auth, { key: recipientKeyPkcs8, cert: recipientCertDer });
 *   out.authenticated;   // true
 */
var authenticate = cmsEncrypt.authenticate;

/**
 * @primitive pki.cms.decrypt
 * @signature pki.cms.decrypt(input, keyMaterial, opts?) -> Promise<{ content, contentType, contentTypeName, recipientType, recipientIndex, contentEncryptionAlgorithm, authenticated, authenticatedBy, originAuthenticated, originatorInfo }>
 * @since 0.2.23
 * @status stable
 * @spec RFC 5652, RFC 5083, RFC 5084, RFC 3560, RFC 5753, RFC 8418, RFC 9629, RFC 9936, RFC 3211, RFC 8018, RFC 3218, RFC 2104
 * @related pki.cms.encrypt, pki.cms.authenticate, pki.schema.cms.parse
 *
 * Decrypt a CMS EnvelopedData / AuthEnvelopedData / EncryptedData, or verify a CMS AuthenticatedData
 * (DER Buffer or PEM). It selects the recipient the key material targets, acquires the
 * content-encryption or MAC key through the matching arm (ktri OAEP or PKCS#1 v1.5 decrypt-only; kari
 * ECDH / X25519 / X448; kekri; pwri; ori/ML-KEM), and decrypts (or MAC-verifies) the content.
 * `keyMaterial` is `{ key, cert }` (the recipient private key + its certificate, which drives recipient
 * matching), `{ password }`, `{ kek, kekId? }`, or `{ cek }` (EncryptedData raw-key mode). Fail-closed
 * and oracle-free: every secret-dependent failure collapses to the SINGLE uniform
 * `cms/decrypt-failed` verdict (Bleichenbacher / EFAIL oracle freedom, and no unwrap-success bit
 * for the MAC path). That covers a bad key-wrap, a padding fault, a GCM tag mismatch, a PWRI
 * check-byte mismatch, and an AuthenticatedData MAC/message-digest mismatch. The PKCS#1 v1.5 arm
 * applies the RFC 3218 implicit-rejection countermeasure so its failure is indistinguishable. For an AuthenticatedData the MAC (HMAC-SHA-2)
 * and, when authenticated attributes are present, the message-digest are verified before the content
 * is released, and the result carries `macAlgorithm` / `digestAlgorithm` in place of
 * `contentEncryptionAlgorithm`. `authenticated` is true for AuthEnvelopedData and AuthenticatedData; a
 * CBC EnvelopedData surfaces `authenticated: false` (the EFAIL caveat in the verdict itself).
 *
 * `authenticated` is a claim about the CONTENT and the key that opened it, never about who sent the
 * message, so the origin question is answered separately. `originAuthenticated` is `false` for every
 * recipient type: a `ktri` or ephemeral-static `kari` message is minted by anyone holding the recipient's
 * PUBLIC key, and a `pwri` or `kekri` message by any co-recipient sharing the secret. Read
 * `authenticated: true` as "these bytes were not altered after the key was chosen", and do not read it as
 * a sender identity -- to bind one, verify a signature (`pki.cms.verify`) over the plaintext.
 * `authenticatedBy` names what the integrity rests on (`"content-encryption-key"` for AEAD,
 * `"message-authentication-key"` for AuthenticatedData, `null` for an unauthenticated cipher).
 * `originatorInfo` is surfaced as the sender supplied it and is UNAUTHENTICATED: it sits outside the
 * AEAD's authenticated data, so it is a hint, never evidence, and any certificate it carries must be
 * validated before use.
 *
 * @opts recipientIndex Explicitly select the recipient by index (overrides key-material matching).
 * @opts maxIterations  Lower the PBKDF2 iteration cap (a DoS bound; downward only).
 * @example
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: recipientKeyPkcs8 });
 *   var envDer = await pki.cms.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 *   var res = await pki.cms.decrypt(envDer, { key: recipientKeyPkcs8, cert: recipientCertDer });
 *   res.content;   // the recovered plaintext Buffer
 */
var decrypt = cmsDecrypt.decrypt;

/**
 * @primitive pki.cms.compress
 * @signature pki.cms.compress(content, opts?) -> Promise<Buffer | string>
 * @since 0.2.27
 * @status stable
 * @spec RFC 3274, RFC 1950, RFC 1951
 * @related pki.cms.decompress, pki.schema.cms.parse
 *
 * ZLIB-compress `content` and wrap it as a CMS `CompressedData` ContentInfo (RFC 3274): version 0,
 * `compressionAlgorithm` = id-alg-zlibCompress (parameters omitted), `encapContentInfo` = the inner
 * content type plus the RFC 1950 ZLIB stream (RFC 1951 DEFLATE) as the eContent. There is exactly
 * one compression algorithm in RFC 3274, ZLIB, so there is no algorithm selector. CompressedData
 * is a size transform with NO integrity, confidentiality, or authentication (RFC 8551 sec. 2.4.5);
 * compress it, then sign or encrypt it if you need protection. Malformed input throws a typed `CmsError`.
 *
 * @opts contentType The inner eContentType (an OID name). Default `data`.
 * @opts level       The DEFLATE compression level (an integer) forwarded to zlib. Default zlib's default.
 * @opts pem         Return a PEM string instead of a DER Buffer.
 * @example
 *   var z = await pki.cms.compress(Buffer.from("compress me"));
 */
var compress = cmsCompress.compress;

/**
 * @primitive pki.cms.decompress
 * @signature pki.cms.decompress(input, opts?) -> Promise<{ content, contentType, contentTypeName, compressionAlgorithm }>
 * @since 0.2.27
 * @status stable
 * @spec RFC 3274, RFC 1950, RFC 1951
 * @related pki.cms.compress, pki.schema.cms.parse
 *
 * Parse a CMS `CompressedData` (DER Buffer or PEM) and recover its content. It requires version 0,
 * `compressionAlgorithm` = id-alg-zlibCompress with absent-or-NULL parameters (RFC 3274 sec. 2), and a
 * present eContent, then inflates the RFC 1950 ZLIB stream. The inflate is BOUNDED at
 * `C.LIMITS.COMPRESS_MAX_BYTES` (16 MiB) and stops before the output is materialized, a
 * decompression-bomb / resource-exhaustion defense (CWE-409): a cap breach throws
 * `cms/decompress-too-large`, and every malformed / truncated / corrupt stream collapses to the uniform
 * `cms/decompress-failed`. `opts.maxOutputBytes` tightens the cap DOWNWARD only. The verdict carries NO
 * `authenticated` / `valid` field -- CompressedData is not a security assertion (RFC 8551 sec. 2.4.5).
 *
 * @opts maxOutputBytes Lower the decompressed-output cap (a DoS bound; downward only).
 * @example
 *   var compressedDer = await pki.cms.compress(Buffer.from("compress me"));
 *   var res = await pki.cms.decompress(compressedDer);
 *   res.content;   // the recovered plaintext Buffer
 */
var decompress = cmsCompress.decompress;

// `setEngine` is @internal -- the path-validate injection seam, never part of pki.cms.
module.exports = { verify: verify, sign: sign, countersign: countersign, encrypt: encrypt, authenticate: authenticate, decrypt: decrypt, compress: compress, decompress: decompress, setEngine: setEngine };
