// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.cms
 * @nav        Verification
 * @title      CMS
 * @intro Verify a CMS SignedData signature (RFC 5652 sec. 5) -- the structure S/MIME signed
 *   mail, RFC 3161 timestamp tokens, and code-signing all rest on. `verify(cms, opts)` parses
 *   the SignedData (over the strict `pki.schema.cms` codec), locates each SignerInfo's signer
 *   certificate by its issuerAndSerialNumber or subjectKeyIdentifier, and checks the signature
 *   over the exact bytes RFC 5652 sec. 5.4 defines: when signed attributes are present it
 *   confirms the message-digest attribute equals the digest of the content and verifies the
 *   signature over the DER re-encoding of the SignedAttributes (the on-wire `[0]` tag replaced
 *   by a universal SET OF); otherwise it verifies directly over the content. Attached and
 *   detached content, single and multiple signers, and RSA / RSASSA-PSS / ECDSA / EdDSA and the
 *   post-quantum ML-DSA (ML-DSA-44/65/87, RFC 9882) are covered. It reports a per-signer verdict;
 *   it does NOT chain the signer certificate to a trust anchor -- that is the caller's step through
 *   `pki.path.validate`.
 * @spec RFC 5652
 * @spec RFC 9882
 * @card Verify a CMS SignedData signature (S/MIME, timestamps, code signing).
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var cms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var edwardsPoint = require("./edwards-point");
var cmsSign = require("./cms-sign");
var MLDSA_SUITABLE_DIGEST = cmsSign.MLDSA_SUITABLE_DIGEST;   // shared sign/verify digest-strength policy (RFC 9882 sec. 3.3)
var validator = require("./validator-all");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var CmsError = frameworkError.CmsError;
function _err(code, message, cause) { return new CmsError(code, message, cause); }

var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_CONTENT_TYPE = oid.byName("contentType");

// A digest-algorithm name -> the WebCrypto hash.
var DIGEST_HASH = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
// SHAKE256 (RFC 8419 sec. 2.3, the Ed448 message digest) has no WebCrypto hash, so it is computed
// with node:crypto; its 512-bit (64-byte) output length is fixed by the profile.
var SHAKE_OUT = { shake256: 64 };
// Is `name` a message-digest algorithm this verifier supports (SHA-2 family or SHAKE256)?
function _supportedDigest(name) { return !!(DIGEST_HASH[name] || SHAKE_OUT[name]); }
// The digest of `content` under the named algorithm, resolved to a Buffer.
function _computeDigest(name, content) {
  if (SHAKE_OUT[name]) return Promise.resolve(nodeCrypto.createHash(name, { outputLength: SHAKE_OUT[name] }).update(content).digest());
  return subtle.digest(DIGEST_HASH[name], content).then(function (d) { return Buffer.from(d); });
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
  // signer cert SPKI algorithm OID MUST equal the signatureAlgorithm OID -- `sameKeyOid` enables
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
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
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
      if (c.ski && c.ski.equals(_toBuf(sid.subjectKeyIdentifier, "sid.subjectKeyIdentifier"))) out.push(c);
    } else if (sid.issuer && sid.serialNumberHex != null) {
      if (c.cert.serialNumberHex === sid.serialNumberHex && guard.name.dnEqual(c.cert.issuer, sid.issuer, CmsError, "cms/bad-name")) out.push(c);
    }
  }
  return out;
}

// Verify `sigBytes` over `signedBytes` against EACH matching candidate certificate in turn; the
// signer is valid iff one candidate verifies. A candidate whose key is structurally unusable (a
// low-order EdDSA point, an unsupported curve) or whose signature simply does not verify falls
// through to the next -- so a colliding certificate cannot make a valid signature read invalid.
// When no candidate verifies, a plain false is a code-less verdict; the last structural fault's
// code is surfaced if one occurred (so the diagnostic is not lost).
function _verifyAgainstCandidates(scheme, sigHash, sigBytes, signedBytes, sid, candidates, pssSalt, expectedKeyOid) {
  var lastErr = null;
  function attempt(idx) {
    if (idx >= candidates.length) {
      return lastErr ? { ok: false, code: lastErr.code, sid: sid, cert: candidates[0].der, message: lastErr.message }
        : { ok: false, sid: sid, cert: candidates[0].der };
    }
    var c = candidates[idx];
    // One-shot family (EdDSA/ML-DSA): the signer cert public-key algorithm OID MUST equal the
    // SignerInfo signatureAlgorithm OID. A candidate whose SPKI disagrees is skipped with a precise
    // verdict, rather than a foreign webcrypto/data throw from importing under the wrong name.
    if (expectedKeyOid && c.cert.subjectPublicKeyInfo.algorithm.oid !== expectedKeyOid) {
      lastErr = _err("cms/unsupported-algorithm", "the signer certificate public-key algorithm does not match the SignerInfo signatureAlgorithm");
      return attempt(idx + 1);
    }
    return Promise.resolve()
      .then(function () { return _verifySignature(scheme, sigHash, sigBytes, c.cert.subjectPublicKeyInfo.bytes, signedBytes, _certCurveOid(c.cert), pssSalt); })
      .then(function (ok) { return ok === true ? { ok: true, sid: sid, cert: c.der } : attempt(idx + 1); },
        function (e) { lastErr = (e instanceof CmsError) ? e : _err("cms/verify-error", "the SignerInfo signature could not be evaluated", e); return attempt(idx + 1); });
  }
  return attempt(0);
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
// deviate from the supported profile: an explicit SHA-2 hashAlgorithm, MGF1 keyed to the SAME
// hash, saltLength equal to the hash length, and trailerField 1. The SHA-1 DEFAULTs are
// rejected (params must be explicit), matching the certification-path validator, so a
// non-conformant PSS AlgorithmIdentifier is a fail-closed verdict -- never verified under
// WebCrypto's own defaults (a signatureAlgorithm bypass otherwise).
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
function _verifySignature(scheme, hashName, sigBytes, spki, signedBytes, curveOid, pssSalt) {
  if (scheme.kind === "rsa") {
    return subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: hashName }, false, ["verify"])
      .then(function (k) { return subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, k, sigBytes, signedBytes); });
  }
  if (scheme.kind === "rsapss") {
    return subtle.importKey("spki", spki, { name: "RSA-PSS", hash: hashName }, false, ["verify"])
      .then(function (k) { return subtle.verify({ name: "RSA-PSS", saltLength: pssSalt }, k, sigBytes, signedBytes); });
  }
  if (scheme.kind === "ec") {
    var ec = EC_CURVE[curveOid];
    if (!ec) throw _err("cms/unsupported-algorithm", "the signer key is on an unsupported EC curve");
    var raw = validator.sig.ecdsaSigToRaw(sigBytes, ec.coordLen, CmsError, "cms/bad-signature");
    return subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: ec.curve }, false, ["verify"])
      .then(function (k) { return subtle.verify({ name: "ECDSA", hash: hashName }, k, raw, signedBytes); });
  }
  if (scheme.kind === "mldsa") {
    // ML-DSA (RFC 9882): a one-shot post-quantum verify, pure mode, empty context -- no external
    // signature hash and no Edwards-point validation (FIPS 204 sec. 5.3; node structurally
    // validates the SPKI on import). The signature is raw and fixed-length (not ECDSA-DER).
    return subtle.importKey("spki", spki, { name: scheme.name }, false, ["verify"])
      .then(function (k) { return subtle.verify({ name: scheme.name }, k, sigBytes, signedBytes); });
  }
  // EdDSA -- the WebCrypto name follows the signing key's SPKI OID (Ed25519 / Ed448). node/
  // OpenSSL imports any Ed25519/Ed448 SPKI without validating the point, and a low-order (e.g.
  // all-zeroes) key verifies a forged signature -- so reject a non-full-order point first.
  _requireValidEdPoint(spki, scheme.name);
  return subtle.importKey("spki", spki, { name: scheme.name }, false, ["verify"])
    .then(function (k) { return subtle.verify({ name: scheme.name }, k, sigBytes, signedBytes); });
}

// The raw Edwards point an OKP SPKI carries (its BIT STRING body, past the unused-bits octet)
// MUST be a valid, canonical, full-order point -- reject an off-curve or low-order key before
// it verifies a signature (WebCrypto import does not check it). Curve from the WebCrypto name.
function _requireValidEdPoint(spkiBytes, name) {
  var content;
  try {
    content = asn1.decode(spkiBytes).children[1].content;
  } catch (e) { throw _err("cms/bad-signature", "the EdDSA public key is not a well-formed SPKI", e); }
  var point = content && content.length ? content.subarray(1) : Buffer.alloc(0);
  if (!edwardsPoint.validate(point, name === "Ed25519" ? 6 : 7)) {
    throw _err("cms/bad-signature", "the EdDSA public key is not a valid, full-order Edwards point");
  }
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
// content-type / message-digest checks to THESE decoded attributes -- not the caller-mutable
// parsed si.signedAttrs -- means a parsed-object input cannot desync the checked attributes
// from the verified preimage (RFC 5652 sec. 5.4).
function _decodeSignedAttrs(setOfBytes) {
  var set = asn1.decode(setOfBytes);
  if (set.tagClass !== "universal" || set.tagNumber !== asn1.TAGS.SET || !set.children) throw _err("cms/bad-signed-attrs", "signedAttrs is not a SET OF Attribute");
  return set.children.map(function (attr) {
    if (attr.tagClass !== "universal" || attr.tagNumber !== asn1.TAGS.SEQUENCE || !attr.children || attr.children.length !== 2) throw _err("cms/bad-signed-attrs", "a signed Attribute is not a SEQUENCE { type, values }");
    var valuesSet = attr.children[1];
    if (valuesSet.tagClass !== "universal" || valuesSet.tagNumber !== asn1.TAGS.SET || !valuesSet.children) throw _err("cms/bad-signed-attrs", "a signed Attribute values field is not a SET OF");
    return { type: asn1.read.oid(attr.children[0]), values: valuesSet.children };
  });
}

// Verify one SignerInfo. Returns { ok, sid, cert, ... } -- a resolved false is a verdict; a
// structural failure carries a code.
function _verifyOne(si, content, eContentType, parsedCerts) {
  var scheme = SIG_SCHEME[si.signatureAlgorithm.name];
  if (!scheme) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported signature algorithm " + JSON.stringify(si.signatureAlgorithm.name) });
  var digestHash = DIGEST_HASH[si.digestAlgorithm.name];
  // RSASSA-PSS takes its signature hash and salt length from the RSASSA-PSS-params, not the
  // digestAlgorithm; a non-conformant parameter set is a fail-closed unsupported verdict.
  var pss = scheme.kind === "rsapss" ? _resolvePss(si.signatureAlgorithm.parameters) : null;
  if (scheme.kind === "rsapss" && !pss) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported or non-conformant RSASSA-PSS parameters (RFC 4055)" });
  // signatureAlgorithm is outside the signed preimage, so a forbidden/missing parameters field
  // (a present parameter on ECDSA/EdDSA, a non-NULL or absent one on RSA) must fail closed --
  // otherwise it is a parser differential a caller trusting the verdict inherits (RFC 5754).
  if (scheme.params && !_algParamsOk(scheme.params, si.signatureAlgorithm.parameters)) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.signatureAlgorithm.name + " signature algorithm parameters must be " + (scheme.params === "null" ? "DER NULL (RFC 4055)" : "absent (RFC 5758/8410)") });
  // The digestAlgorithm parameters, when present, MUST be a DER NULL (RFC 5754 sec. 2 accepts
  // absent OR NULL; a present non-NULL is malformed and, being outside the signed preimage,
  // must fail closed like the signatureAlgorithm parameters above).
  var dp = si.digestAlgorithm.parameters;
  if (dp !== null && dp !== undefined && !_isDerNull(dp)) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.digestAlgorithm.name + " digest algorithm parameters must be absent or DER NULL (RFC 5754 sec. 2)" });
  // RFC 9882 sec. 3.3: an ML-DSA SignerInfo's digestAlgorithm (id-sha512 / id-shake256) parameters
  // MUST be OMITTED -- stricter than the generic absent-or-NULL rule above -- so a present DER NULL
  // is outside the ML-DSA profile and fails closed. Gated on signed attributes (with none present
  // the digestAlgorithm field has no meaning, M9).
  if (scheme.kind === "mldsa" && si.signedAttrsBytes && dp !== null && dp !== undefined) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the ML-DSA digestAlgorithm parameters must be absent (RFC 9882 sec. 3.3)" });
  var sigHash = pss ? pss.hash : (scheme.hash || digestHash);
  // The signature hash is required for every non-EdDSA scheme (EdDSA hashes internally);
  // the content digest is required whenever signed attributes are present, for every scheme
  // (the message-digest attribute is computed under digestAlgorithm). Either gap is a
  // fail-closed unsupported-algorithm verdict, never a foreign-domain throw from the digest.
  if ((scheme.kind !== "eddsa" && scheme.kind !== "mldsa" && !sigHash) || (si.signedAttrsBytes && !_supportedDigest(si.digestAlgorithm.name))) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported digest algorithm " + JSON.stringify(si.digestAlgorithm.name) });
  // ML-DSA (RFC 9882 sec. 3.3): with signed attributes present, the message-digest algorithm MUST
  // meet the parameter set's security strength -- a below-strength digest is the weaker link and is
  // rejected fail-closed (the RFC's "verifiers MAY reject", taken by the strict-verifier posture).
  // With signed attributes absent the digestAlgorithm has no meaning (sec. 3.3) and is not checked.
  if (scheme.kind === "mldsa" && si.signedAttrsBytes && !MLDSA_SUITABLE_DIGEST[scheme.name][si.digestAlgorithm.name]) return Promise.resolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.digestAlgorithm.name + " message digest is below the security strength of " + scheme.name + " (RFC 9882 sec. 3.3)" });
  var signers = _findSignerCerts(si.sid, parsedCerts);
  if (!signers.length) return Promise.resolve({ ok: false, code: "cms/signer-cert-not-found", sid: si.sid, message: "no certificate matches this SignerInfo's signer identifier" });
  var sigBytes = _toBuf(si.signature, "the SignerInfo signature");

  return Promise.resolve().then(function () {
    if (!si.signedAttrsBytes) return content;   // no signed attributes: sign over the content directly
    // With signed attributes: decode them from the EXACT bytes the signature covers -- the
    // SignedAttributes SET OF, the on-wire [0] IMPLICIT tag replaced by a universal SET OF
    // (RFC 5652 sec. 5.4) -- so the content-type / message-digest checks bind the same bytes
    // that are verified. Reading the caller-mutable parsed si.signedAttrs instead would let a
    // parsed-object input desync the checked attributes from the verified preimage.
    var reTagged = Buffer.from(si.signedAttrsBytes);
    reTagged[0] = 0x31;   // [0] IMPLICIT -> universal SET OF
    var attrs;
    try {
      attrs = _decodeSignedAttrs(reTagged);
    } catch (e) { if (e instanceof CmsError) throw e; throw _err("cms/bad-signed-attrs", "signedAttrs is not a valid SET OF Attribute", e); }
    // The content-type attribute MUST be present, single-valued, and equal the eContentType
    // (RFC 5652 sec. 5.3).
    var ctAttr = attrs.filter(function (a) { return a.type === OID_CONTENT_TYPE; });
    if (ctAttr.length !== 1 || ctAttr[0].values.length !== 1) throw _err("cms/bad-signed-attrs", "signedAttrs must carry exactly one content-type attribute (RFC 5652 sec. 5.3)");
    var ctOid;
    try {
      ctOid = asn1.read.oid(ctAttr[0].values[0]);
    } catch (e) { throw _err("cms/bad-signed-attrs", "the content-type attribute value is not an OBJECT IDENTIFIER", e); }
    if (ctOid !== eContentType) return { mismatch: { code: "cms/content-type-mismatch", message: "the content-type signed attribute does not match the SignedData eContentType (RFC 5652 sec. 5.3)" } };
    // The message-digest attribute MUST be present, single-valued, and equal the digest of the
    // content (RFC 5652 sec. 5.4).
    var mdAttr = attrs.filter(function (a) { return a.type === OID_MESSAGE_DIGEST; })[0];
    if (!mdAttr || mdAttr.values.length !== 1) throw _err("cms/bad-signed-attrs", "signedAttrs must carry exactly one message-digest attribute (RFC 5652 sec. 5.4)");
    var declared;
    try {
      declared = asn1.read.octetString(mdAttr.values[0]);
    } catch (e) { throw _err("cms/bad-signed-attrs", "the message-digest attribute value is not an OCTET STRING", e); }
    return _computeDigest(si.digestAlgorithm.name, content).then(function (d) {
      if (!d.equals(declared)) return { mismatch: { code: "cms/message-digest-mismatch", message: "the message-digest attribute does not match the content digest" } };
      return reTagged;
    });
  }).then(function (signedBytes) {
    if (signedBytes && signedBytes.mismatch) return { ok: false, code: signedBytes.mismatch.code, sid: si.sid, cert: signers[0].der, message: signedBytes.mismatch.message };
    return _verifyAgainstCandidates(scheme, sigHash, sigBytes, signedBytes, si.sid, signers, pss ? pss.saltLength : 0, scheme.sameKeyOid ? oid.byName(si.signatureAlgorithm.name) : null);
  });
}

/**
 * @primitive  pki.cms.verify
 * @signature  pki.cms.verify(input, opts?) -> Promise<{ valid, signers }>
 * @since      0.2.14
 * @status     experimental
 * @spec       RFC 5652
 * @spec       RFC 9882
 * @defends    cms-signature-forgery (CWE-347)
 * @related    pki.schema.cms.parse, pki.path.validate
 *
 * Verify a CMS SignedData signature (RFC 5652 sec. 5). `input` is a PEM string, a DER
 * `Buffer`, or a parsed `pki.schema.cms` object. Returns `{ valid, signers }` where each
 * `signers[i]` is `{ ok, sid, cert }` (`cert` the matched signer certificate DER) or carries
 * a `code` on a structural failure; `valid` is true when there is at least one signer and
 * every signer verified. RSA (PKCS#1 v1.5 and RSASSA-PSS), ECDSA, EdDSA, and the post-quantum
 * ML-DSA (ML-DSA-44/65/87, RFC 9882 -- pure mode, empty context) signatures are recognized.
 *
 * @opts  content  The detached content (a `Buffer`) when the SignedData carries no
 *                 encapsulated eContent. Required for a detached signature.
 * @opts  certs    Extra signer certificates (an array of DER `Buffer`s) to match against, in
 *                 addition to the certificates embedded in the SignedData.
 * @example
 *   var res = await pki.cms.verify(p7sDer, { content: detachedBytes });
 *   res.valid;                         // boolean
 *   res.signers[0].ok;                 // per-signer verdict
 */
function verify(input, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("cms/bad-input", "pki.cms.verify options must be an object");
  var parsed = (input && typeof input === "object" && !Buffer.isBuffer(input) && Array.isArray(input.signerInfos)) ? input : cms.parse(input);
  if (!Array.isArray(parsed.signerInfos)) throw _err("cms/bad-input", "input is not a CMS SignedData");
  var content = parsed.encapContentInfo.eContent;
  if (content == null) {
    if (opts.content == null) throw _err("cms/detached-content-required", "this SignedData is detached; opts.content (the external content) is required");
    content = _toBuf(opts.content, "opts.content");
  }
  // Pre-parse every candidate certificate (embedded + caller-supplied) once.
  var parsedCerts = [];
  (parsed.certificates || []).forEach(function (c) { _addCert(parsedCerts, c && c.bytes ? c.bytes : c); });
  (opts.certs || []).forEach(function (c) { _addCert(parsedCerts, c); });
  var eContentType = parsed.encapContentInfo.eContentType;
  return Promise.all(parsed.signerInfos.map(function (si) { return _verifyOne(si, content, eContentType, parsedCerts); }))
    .then(function (signers) { return { valid: signers.length > 0 && signers.every(function (s) { return s.ok === true; }), signers: signers }; });
}
// Parse a candidate cert DER and index its SKI; a cert that will not parse is skipped (it
// simply cannot be a signer match, and a malformed embedded cert must not fail the verify).
function _addCert(out, der) {
  var buf;
  try {
    buf = _toBuf(der, "a certificate");
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
//   * `_requireValidEdPoint`'s SPKI-decode catch and its empty-content `Buffer.alloc(0)`
//     fallback -- a signer certificate accepted by x509.parse always carries a well-formed,
//     non-empty SubjectPublicKeyInfo BIT STRING, so the decode never throws and the content is
//     never empty here.
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
 * @status     experimental
 * @spec       RFC 5652
 * @spec       RFC 9882
 * @related    pki.cms.verify, pki.schema.cms.parse
 *
 * Produce a CMS SignedData (RFC 5652 sec. 5) over `content` (a `Buffer`) -- the structure
 * S/MIME signed mail, RFC 3161 timestamp tokens, and code signing rest on, and exactly what
 * `pki.cms.verify` consumes and OpenSSL `cms -verify` validates. Each `signers[i]` is
 * `{ cert, key, digestAlgorithm?, pss? }`: `cert` the signer certificate (PEM or DER), `key`
 * its private key (a WebCrypto `CryptoKey` or a PKCS#8 DER `Buffer` / PEM string). The
 * signature covers the RFC 5652 sec. 5.4 preimage: with signed attributes (the default) the
 * message-digest attribute is bound to the content digest and the signature is over the
 * canonical DER SET OF SignedAttributes; otherwise over the content directly. RSA (PKCS#1 v1.5
 * and, with `pss`, RSASSA-PSS), ECDSA (P-256/384/521), Ed25519, Ed448, and the post-quantum ML-DSA
 * (ML-DSA-44/65/87, RFC 9882 -- pure mode; SHA-512 message digest by default, SHAKE256 optional)
 * are covered.
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
 * @example
 *   var p7 = await pki.cms.sign(Buffer.from("hello"), { cert: signerCertDer, key: signerKeyPkcs8 });
 *   var res = await pki.cms.verify(p7);   // res.valid === true
 */
var sign = cmsSign.sign;

module.exports = { verify: verify, sign: sign };
