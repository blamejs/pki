// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.cms
 * @nav        Verification
 * @title      CMS
 * @fullname   CMS (Cryptographic Message Syntax) signing and verification
 * @intro Verify a CMS SignedData signature (RFC 5652 sec. 5), the structure S/MIME signed
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
var _mldsaDigestSuitable = signScheme.mldsaDigestSuitable;
var SLHDSA_BY_OID = signScheme.SLHDSA_BY_OID;
var validator = require("./validator-all");
var compositeSig = require("./composite-sig");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");

var CmsError = frameworkError.CmsError;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
var _Promise = Promise, _promiseResolveRaw = Promise.resolve;
/**
 * @internal Every value resolved here is a signer row, and resolving a promise reads `then` off the
 * value. Building the row through the verdict guard ends that lookup on the row itself, so an
 * accessor installed while the signature check is pending cannot rewrite the `ok` the message
 * verdict is derived from before it is read.
 */
function _pResolve(v) { return intrinsic.apply(_promiseResolveRaw, _Promise, [_row(v)]); }
function _row(o) { return guard.verdict.of(o); }

var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_COUNTERSIGNATURE = oid.byName("countersignature");

var DIGEST_HASH = intrinsic.assign(intrinsic.create(null), {
  sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512",
  shake128: "SHAKE128", shake256: "SHAKE256",
});
var SIG_HASH = intrinsic.assign(intrinsic.create(null), { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" });
function _supportedDigest(name) { return intrinsic.hasOwn(DIGEST_HASH, name) && !!DIGEST_HASH[name]; }
async function _computeDigest(name, content) {
  return intrinsic.bufferFrom(await subtle.digest(DIGEST_HASH[name], content));
}
var SIG_SCHEME = intrinsic.assign(intrinsic.create(null), {
  rsaEncryption: { kind: "rsa", params: "null" },
  rsassaPss: { kind: "rsapss" },
  ecPublicKey: { kind: "ec", params: "absent" },
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
});
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { SIG_SCHEME["id-slh-dsa-" + s] = { kind: "slhdsa", name: "SLH-DSA-" + s.toUpperCase(), params: "absent", sameKeyOid: true, digest: SLHDSA_BY_OID[oid.byName("id-slh-dsa-" + s)].digest }; });
function _isDerNull(p) { return Buffer.isBuffer(p) && p.length === 2 && p[0] === 0x05 && p[1] === 0x00; }
function _algParamsOk(shape, p) { return shape === "null" ? _isDerNull(p) : (p === null || p === undefined); }
var EC_CURVE = intrinsic.create(null);
EC_CURVE[oid.byName("prime256v1")] = { curve: "P-256", coordLen: 32 };
EC_CURVE[oid.byName("secp384r1")] = { curve: "P-384", coordLen: 48 };
EC_CURVE[oid.byName("secp521r1")] = { curve: "P-521", coordLen: 66 };

function _toBuf(v, what) {
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
  throw _err("cms/bad-input", what + " must be a Buffer");
}

function _findSignerCerts(sid, parsedCerts) {
  var out = [];
  for (var i = 0; i < parsedCerts.length; i++) {
    var c = parsedCerts[i];
    if (sid.subjectKeyIdentifier != null) {
      if (c.ski && intrinsic.bufferEquals(c.ski, _toBuf(sid.subjectKeyIdentifier, "sid.subjectKeyIdentifier"))) intrinsic.push(out, c);
    } else if (sid.issuer && sid.serialNumberHex != null) {
      if (c.cert.serialNumberHex === sid.serialNumberHex && guard.name.dnEqual(c.cert.issuer.rdns, sid.issuer.rdns, _err, "cms/bad-name", "the signer certificate issuer")) intrinsic.push(out, c);
    }
  }
  return out;
}

async function _verifyAgainstCandidates(scheme, sigHash, sigBytes, signedBytes, sid, candidates, pssSalt, expectedKeyOid) {
  var lastErr = null;
  for (var idx = 0; idx < candidates.length; idx++) {
    var c = candidates[idx];
    if (expectedKeyOid && c.cert.subjectPublicKeyInfo.algorithm.oid !== expectedKeyOid) {
      lastErr = _err("cms/unsupported-algorithm", "the signer certificate public-key algorithm does not match the SignerInfo signatureAlgorithm");
      continue;
    }
    try {
      var ok = await _verifySignature(scheme, sigHash, sigBytes, c.cert.subjectPublicKeyInfo.bytes, signedBytes, _certCurveOid(c.cert), pssSalt);
      if (ok === true) return _row({ ok: true, sid: sid, cert: c.der });
    } catch (e) {
      lastErr = (e instanceof CmsError) ? e : _err("cms/verify-error", "the SignerInfo signature could not be evaluated", e);
    }
  }
  return _row(lastErr ? { ok: false, code: lastErr.code, sid: sid, cert: candidates[0].der, message: lastErr.message }
    : { ok: false, sid: sid, cert: candidates[0].der });
}

function _certSki(cert) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === oid.byName("subjectKeyIdentifier"); })[0];
  if (!ext) return null;
  try {
    return asn1.read.octetString(asn1.decode(ext.value));
  } catch (_e) { return null; }
}

var OID_MGF1 = oid.byName("mgf1");
var PSS_HASH = {};
PSS_HASH[oid.byName("sha256")] = "SHA-256";
PSS_HASH[oid.byName("sha384")] = "SHA-384";
PSS_HASH[oid.byName("sha512")] = "SHA-512";

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
    if (f.tagClass !== "context" || f.tagNumber > 3 || f.tagNumber <= last || !f.children || f.children.length !== 1) return null;
    last = f.tagNumber;
    try {
      if (f.tagNumber === 0) { hash = PSS_HASH[_hashAlgOid(f.children[0])]; if (!hash) return null; }
      else if (f.tagNumber === 1) { mgfNode = f.children[0]; }
      else if (f.tagNumber === 2) { saltLen = asn1.read.integer(f.children[0]); }
      else { trailer = asn1.read.integer(f.children[0]); }
    } catch (_e3) { return null; }
  }
  if (hash === null || mgfNode === null) return null;
  if (mgfNode.tagClass !== "universal" || mgfNode.tagNumber !== asn1.TAGS.SEQUENCE || !mgfNode.children || mgfNode.children.length !== 2) return null;
  var mgfOid;
  try {
    mgfOid = asn1.read.oid(mgfNode.children[0]);
  } catch (_e4) { return null; }
  if (mgfOid !== OID_MGF1 || PSS_HASH[_hashAlgOid(mgfNode.children[1])] !== hash) return null;
  if (trailer !== 1n) return null;
  var saltLength = saltLen === null ? 20 : guard.range.uint31(saltLen, _err, "cms/unsupported-algorithm", "RSASSA-PSS saltLength");
  return { hash: hash, saltLength: saltLength };
}

async function _verifySignature(scheme, hashName, sigBytes, spki, signedBytes, curveOid, pssSalt) {
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
    var raw = validator.sig.ecdsaDerToP1363(sigBytes, ec.curve, CmsError, "cms/bad-signature");
    var kEc = await subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: ec.curve }, false, ["verify"]);
    return subtle.verify({ name: "ECDSA", hash: hashName }, kEc, raw, signedBytes);
  }
  if (scheme.kind === "mldsa" || scheme.kind === "slhdsa") {
    var kPq = await subtle.importKey("spki", spki, { name: scheme.name }, false, ["verify"]);
    return subtle.verify({ name: scheme.name }, kPq, sigBytes, signedBytes);
  }
  _requireValidEdPoint(spki, scheme.name);
  var kEd = await subtle.importKey("spki", spki, { name: scheme.name }, false, ["verify"]);
  return subtle.verify({ name: scheme.name }, kEd, sigBytes, signedBytes);
}

function _requireValidEdPoint(spkiBytes, name) {
  edwardsPoint.validateSpki(spkiBytes, name === "Ed25519" ? 6 : 7, CmsError, "cms/bad-signature");
}

function _certCurveOid(cert) {
  var p = cert.subjectPublicKeyInfo.algorithm.parameters;
  if (cert.subjectPublicKeyInfo.algorithm.oid !== oid.byName("ecPublicKey") || !Buffer.isBuffer(p)) return null;
  try {
    return asn1.read.oid(asn1.decode(p));
  } catch (_e) { return null; }
}

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

async function _verifyOne(si, content, eContentType, parsedCerts, csTarget, digestByName) {
  var composite = compositeSig.COMPOSITE_ALGS[si.signatureAlgorithm.oid];
  if (composite) return _verifyComposite(si, composite, content, eContentType, parsedCerts, csTarget, digestByName);
  var scheme = SIG_SCHEME[si.signatureAlgorithm.name];
  if (!scheme) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported signature algorithm " + JSON.stringify(si.signatureAlgorithm.name) });
  var digestHash = SIG_HASH[si.digestAlgorithm.name];
  var pss = scheme.kind === "rsapss" ? _resolvePss(si.signatureAlgorithm.parameters) : null;
  if (scheme.kind === "rsapss" && !pss) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported or non-conformant RSASSA-PSS parameters (RFC 4055)" });
  if (scheme.params && !_algParamsOk(scheme.params, si.signatureAlgorithm.parameters)) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.signatureAlgorithm.name + " signature algorithm parameters must be " + (scheme.params === "null" ? "DER NULL (RFC 4055)" : "absent (RFC 5758/8410)") });
  var dp = si.digestAlgorithm.parameters;
  var mldsaNoAttrs = scheme.kind === "mldsa" && !si.signedAttrsBytes;
  if (!mldsaNoAttrs && dp !== null && dp !== undefined && !_isDerNull(dp)) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.digestAlgorithm.name + " digest algorithm parameters must be absent or DER NULL (RFC 5754 sec. 2)" });
  if ((scheme.kind === "mldsa" || scheme.kind === "slhdsa") && si.signedAttrsBytes && (si.digestAlgorithm.name === "shake128" || si.digestAlgorithm.name === "shake256") && dp !== null && dp !== undefined) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "a SHAKE digestAlgorithm carries no parameters (RFC 8702 sec. 3.1)" });
  var sigHash = pss ? pss.hash : (scheme.hash || digestHash);
  if ((scheme.kind !== "eddsa" && scheme.kind !== "mldsa" && scheme.kind !== "slhdsa" && !sigHash) || (si.signedAttrsBytes && !_supportedDigest(si.digestAlgorithm.name))) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "unsupported digest algorithm " + JSON.stringify(si.digestAlgorithm.name) });
  if (scheme.kind === "mldsa" && si.signedAttrsBytes && !_mldsaDigestSuitable(scheme.name, si.digestAlgorithm.name)) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the " + si.digestAlgorithm.name + " message digest is below the security strength of " + scheme.name + " (RFC 9882 sec. 3.3)" });
  if (scheme.kind === "slhdsa" && si.signedAttrsBytes && si.digestAlgorithm.name !== scheme.digest) return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "SLH-DSA " + scheme.name + " requires the " + scheme.digest + " message digest (RFC 9814 sec. 4)" });
  var signers = _findSignerCerts(si.sid, parsedCerts);
  if (!signers.length) return _pResolve({ ok: false, code: "cms/signer-cert-not-found", sid: si.sid, message: "no certificate matches this SignerInfo's signer identifier" });
  var sigBytes = _toBuf(si.signature, "the SignerInfo signature");

  var signedBytes = await (csTarget != null ? _computeCountersigBytes(si, csTarget) : _computeSignedBytes(si, content, eContentType, digestByName));
  if (signedBytes && signedBytes.mismatch) return _row({ ok: false, code: signedBytes.mismatch.code, sid: si.sid, cert: signers[0].der, message: signedBytes.mismatch.message });
  return _verifyAgainstCandidates(scheme, sigHash, sigBytes, signedBytes, si.sid, signers, pss ? pss.saltLength : 0, scheme.sameKeyOid ? oid.byName(si.signatureAlgorithm.name) : null);
}

async function _computeCountersigBytes(si, csTarget) {
  if (!si.signedAttrsBytes) return csTarget;
  var reTagged = intrinsic.bufferFrom(si.signedAttrsBytes);
  reTagged[0] = 0x31;
  var attrs;
  try {
    attrs = _decodeSignedAttrs(reTagged);
  } catch (e) { if (e instanceof CmsError) throw e; throw _err("cms/bad-signed-attrs", "the countersignature signedAttrs is not a valid SET OF Attribute", e); }
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

async function _computeSignedBytes(si, content, eContentType, digestByName) {
  if (!si.signedAttrsBytes) {
    if (digestByName) {
      return { mismatch: {
        code: "cms/streamed-content-unverifiable",
        message: "a SignerInfo that signs the content directly (no signed attributes) cannot be " +
          "verified against a streamed content, whose bytes are not retained; pass opts.content as a Buffer",
      } };
    }
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
  var reTagged = intrinsic.bufferFrom(si.signedAttrsBytes);
  reTagged[0] = 0x31;
  var attrs;
  try {
    attrs = _decodeSignedAttrs(reTagged);
  } catch (e) { if (e instanceof CmsError) throw e; throw _err("cms/bad-signed-attrs", "signedAttrs is not a valid SET OF Attribute", e); }
  var ctAttr = intrinsic.filter(attrs, function (a) { return a.type === OID_CONTENT_TYPE; });
  if (ctAttr.length !== 1 || ctAttr[0].values.length !== 1) throw _err("cms/bad-signed-attrs", "signedAttrs must carry exactly one content-type attribute (RFC 5652 sec. 5.3)");
  var ctOid;
  try {
    ctOid = asn1.read.oid(ctAttr[0].values[0]);
  } catch (e) { throw _err("cms/bad-signed-attrs", "the content-type attribute value is not an OBJECT IDENTIFIER", e); }
  if (ctOid !== eContentType) return { mismatch: { code: "cms/content-type-mismatch", message: "the content-type signed attribute does not match the SignedData eContentType (RFC 5652 sec. 5.3)" } };
  var mdAttr = intrinsic.filter(attrs, function (a) { return a.type === OID_MESSAGE_DIGEST; })[0];
  if (!mdAttr || mdAttr.values.length !== 1) throw _err("cms/bad-signed-attrs", "signedAttrs must carry exactly one message-digest attribute (RFC 5652 sec. 5.4)");
  var declared;
  try {
    declared = asn1.read.octetString(mdAttr.values[0]);
  } catch (e) { throw _err("cms/bad-signed-attrs", "the message-digest attribute value is not an OCTET STRING", e); }
  var d = digestByName ? digestByName[si.digestAlgorithm.name] : await _computeDigest(si.digestAlgorithm.name, content);
  if (!intrinsic.bufferEquals(d, declared)) return { mismatch: { code: "cms/message-digest-mismatch", message: "the message-digest attribute does not match the content digest" } };
  return reTagged;
}

async function _verifyComposite(si, comp, content, eContentType, parsedCerts, csTarget, digestByName) {
  if (si.signatureAlgorithm.parameters !== null && si.signatureAlgorithm.parameters !== undefined) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the composite signatureAlgorithm parameters must be absent (draft-ietf-lamps-cms-composite-sigs sec. 3.4)" });
  }
  if (comp.trad.unsupported) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "composite " + comp.name + ": " + comp.trad.unsupported });
  }
  var dp = si.digestAlgorithm.parameters;
  if (dp !== null && dp !== undefined) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the composite " + si.digestAlgorithm.name + " digestAlgorithm parameters must be omitted (draft-ietf-lamps-cms-composite-sigs sec. 3.4)" });
  }
  if (si.digestAlgorithm.name !== comp.phCms) {
    return _pResolve({ ok: false, code: "cms/unsupported-algorithm", sid: si.sid, message: "the SignerInfo digestAlgorithm " + JSON.stringify(si.digestAlgorithm.name) + " is not the composite " + comp.name + " pre-hash " + JSON.stringify(comp.phCms) + " (draft-ietf-lamps-cms-composite-sigs sec. 3.4)" });
  }
  var signers = _findSignerCerts(si.sid, parsedCerts);
  if (!signers.length) return _pResolve({ ok: false, code: "cms/signer-cert-not-found", sid: si.sid, message: "no certificate matches this SignerInfo's signer identifier" });
  var sigBytes = _toBuf(si.signature, "the SignerInfo signature");
  var signedBytes = await (csTarget != null ? _computeCountersigBytes(si, csTarget) : _computeSignedBytes(si, content, eContentType, digestByName));
  if (signedBytes && signedBytes.mismatch) return _row({ ok: false, code: signedBytes.mismatch.code, sid: si.sid, cert: signers[0].der, message: signedBytes.mismatch.message });
  return _verifyCompositeAgainstCandidates(comp, sigBytes, signedBytes, si.sid, signers, si.signatureAlgorithm.oid);
}

async function _verifyCompositeAgainstCandidates(comp, sigBytes, signedBytes, sid, candidates, expectedKeyOid) {
  var lastErr = null;
  for (var idx = 0; idx < candidates.length; idx++) {
    var c = candidates[idx];
    if (c.cert.subjectPublicKeyInfo.algorithm.oid !== expectedKeyOid) {
      lastErr = _err("cms/unsupported-algorithm", "the signer certificate public-key algorithm does not match the SignerInfo signatureAlgorithm");
      continue;
    }
    var r = await compositeSig.compositeVerify(c.cert.subjectPublicKeyInfo.bytes, sigBytes, signedBytes, comp, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
    if (r.ok === true) return _row({ ok: true, sid: sid, cert: c.der });
    if (r.code) lastErr = (r.error instanceof CmsError) ? r.error : _err(r.code, r.error && r.error.message ? r.error.message : "the composite signature could not be evaluated");
  }
  return _row(lastErr ? { ok: false, code: lastErr.code, sid: sid, cert: candidates[0].der, message: lastErr.message }
    : { ok: false, sid: sid, cert: candidates[0].der });
}

function _surfaceUnsignedAttrs(si) {
  return intrinsic.map(si.unsignedAttrs || [], function (a) {
    return { type: a.type, typeName: oid.name(a.type) || null, values: a.values };
  });
}

function _surfaceSignedAttrs(si) {
  return intrinsic.map(si.signedAttrs || [], function (a) {
    return { type: a.type, typeName: oid.name(a.type) || null, values: a.values };
  });
}

async function _verifyCountersignatures(si, parsedCerts) {
  var targetSig = _toBuf(si.signature, "the countersigned signature");
  var values = [];
  intrinsic.forEach(si.unsignedAttrs || [], function (a) {
    if (a.type !== OID_COUNTERSIGNATURE) return;
    intrinsic.forEach(a.values, function (v) { intrinsic.push(values, v && v.bytes ? v.bytes : v); });
  });
  var out = [];
  for (var _cp = 0; _cp < values.length; _cp++) guard.list.append(out, await _verifyOneCountersig(values[_cp], targetSig, parsedCerts));
  return out;
}

async function _verifyOneCountersig(vDer, targetSig, parsedCerts) {
  var csSi;
  try { csSi = cms.walkCountersignature(asn1.decode(intrinsic.isBuffer(vDer) ? vDer : intrinsic.bufferFrom(vDer))); }
  catch (e) { return _row({ ok: false, code: (e instanceof CmsError ? e.code : "cms/bad-countersignature"), message: e && e.message }); }
  var verdict = await _verifyOne(csSi, targetSig, null, parsedCerts, targetSig);
  var nested = await _verifyCountersignatures(csSi, parsedCerts);
  var head = { ok: verdict.ok, sid: verdict.sid, cert: verdict.cert, digestAlgorithm: csSi.digestAlgorithm.name };
  return guard.verdict.of(
    verdict.code ? guard.verdict.of(head, { code: verdict.code }) : head,
    { unsignedAttrs: _surfaceUnsignedAttrs(csSi), countersignatures: nested });
}

/**
 * @primitive  pki.cms.verify
 * @signature  pki.cms.verify(input, opts?) -> Promise<{ valid, trusted, eContentType, eContent, signers }>
 * @since      0.2.14
 * @status     stable
 * @spec       RFC 5652
 * @spec       RFC 9882
 * @spec       RFC 9814
 * @defends    cms-signature-forgery (CWE-347)
 * @related    pki.schema.cms.parse, pki.path.validate
 *
 * Verify a CMS SignedData signature (RFC 5652 sec. 5). `input` is a PEM string, a DER
 * `Buffer`, or a parsed `pki.schema.cms` object. Returns `{ valid, trusted, eContentType, eContent, signers }`
 * (`eContent` the encapsulated content when present, else null) where each `signers[i]` is
 * `{ ok, sid, cert, trusted, signedAttributesPresent, signedAttributes, unsignedAttrs, digestAlgorithm, countersignatures }`
 * (`cert` the matched signer certificate DER) or carries a `code` on a structural failure; `valid` is true when
 * there is at least one signer and every signer verified.
 *
 * `eContentType` and `signedAttributesPresent` are there for a caller whose profile is stricter
 * than RFC 5652's. Signing WITH attributes and signing the content directly are different claims:
 * attributes bind a content type and a signing time alongside the digest, content-only binds
 * nothing but the bytes. One message may carry a signer of each. A profile that requires
 * attributes (RFC 8551 S/MIME does) or a particular content type can enforce it from the verdict,
 * with no need to parse the message a second time.
 *
 * `valid` and `trusted` are DIFFERENT claims and neither implies the other. A SignedData carries
 * its own certificates, so `valid` establishes that the message is internally consistent: the
 * signature is sound under a certificate the message or `opts.certs` supplied. Anyone can mint a
 * certificate, sign with it, and embed it, so that says nothing about WHO signed. `trusted` says
 * every signer chained to a root named in `opts.trustAnchors`, validated through the same RFC 5280
 * path engine `pki.path.validate` uses. Without anchors there is nothing to chain to and `trusted`
 * is `false`, a definite answer, not a missing one. Anchors that cannot be read are a
 * configuration fault and throw.
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
function _snapshotIfBytes(input, label) {
  if (guard.bytes.isByteSource(input)) {
    return guard.bytes.snapshotSource(input, CmsError, "cms/bad-input", label);
  }
  return input;
}

async function _resolveContentDigests(parsed, streamSource) {
  if (streamSource == null) return null;
  var names = [], seen = {};
  intrinsic.forEach(parsed.signerInfos, function (si) {
    var dn = si.digestAlgorithm.name;
    if (si.signedAttrsBytes && _supportedDigest(dn) && !seen[dn]) { seen[dn] = 1; intrinsic.push(names, dn); }
  });
  if (!names.length) return {};
  var ds;
  try {
    ds = await subtle.digestStream(intrinsic.map(names, function (n) { return DIGEST_HASH[n]; }), streamSource);
  } catch (e) {
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
  var byName = {};
  intrinsic.forEach(names, function (n, i) { byName[n] = intrinsic.bufferFrom(ds[i]); });
  return byName;
}

var _VERIFY_OPTS = { certs: 1, content: 1, trustAnchors: 1, time: 1, requiredEku: 1, checkPurpose: 1 };

function verify(input, opts) {
  return guard.async.deferred(function () { return _verify(input, opts); });
}

async function _verify(input, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.verify options");
  guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "cms/bad-input", "pki.cms.verify has an unknown option ");
  var parsed = guard.parsed.acceptDerived(input, "cms", function (bytes) {
    return cms.parse(_snapshotIfBytes(bytes, "pki.cms.verify"));
  }, _err, "cms/bad-input", "the SignedData");
  if (!Array.isArray(parsed.signerInfos)) throw _err("cms/bad-input", "input is not a CMS SignedData");
  var trustCfg = _snapshotTrust(opts);
  var parsedCerts = [];
  (parsed.certificates || []).forEach(function (c) { _addCert(parsedCerts, c && c.bytes ? c.bytes : c); });
  (opts.certs || []).forEach(function (c) { _addCert(parsedCerts, c); });
  var content = parsed.encapContentInfo.eContent;
  var streamSource = null;
  if (content == null) {
    if (opts.content == null) throw _err("cms/detached-content-required", "this SignedData is detached; opts.content (the external content) is required");
    streamSource = guard.bytes.asyncStreamOf(opts.content);
    if (streamSource == null) {
      content = _toBuf(_snapshotIfBytes(opts.content, "opts.content"), "opts.content");
    }
  } else if (opts.content != null) {
    if (Buffer.compare(_toBuf(opts.content, "opts.content"), Buffer.from(content)) !== 0) {
      throw _err("cms/content-conflict", "opts.content disagrees with this SignedData's own encapsulated content (a detached signature must omit eContent)");
    }
  }
  var eContentType = parsed.encapContentInfo.eContentType;
  var digestByName = await _resolveContentDigests(parsed, streamSource);
  var signers = [];
  for (var _sp = 0; _sp < parsed.signerInfos.length; _sp++) {
    var siOne = parsed.signerInfos[_sp];
    var verdict = await _verifyOne(siOne, content, eContentType, parsedCerts, null, digestByName);
    var counters = await _verifyCountersignatures(siOne, parsedCerts);
    guard.list.append(signers, guard.verdict.of(verdict, {
      countersignatures: counters,
      unsignedAttrs: _surfaceUnsignedAttrs(siOne),
      signedAttributesPresent: !!siOne.signedAttrsBytes,
      signedAttributes: _surfaceSignedAttrs(siOne),
      digestAlgorithm: siOne.digestAlgorithm.name,
      trusted: false,
    }));
  }
  var res = guard.verdict.of({
    valid: signers.length > 0 && guard.list.allMatch(signers, function (s) { return s.ok === true; }),
    eContentType: parsed.encapContentInfo.eContentType,
    eContent: parsed.encapContentInfo.eContent != null ? parsed.encapContentInfo.eContent : null,
    signers: signers,
    trusted: false,
  });
  await _applyTrust(res, parsedCerts, trustCfg);
  return res;
}

var _engine = null;
function setEngine(engine) { _engine = engine; }

var _ANCHOR_CLONE_DEPTH = 8;
function _cloneAnchorValue(v, depth) {
  if (guard.bytes.isByteSource(v)) {
    return _snapshotIfBytes(v, "opts.trustAnchors[]");
  }
  if (v === null || typeof v !== "object") return v;
  if (guard.time.isDate(v)) return new intrinsic.Date(guard.time.instantOf(v));
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
    time: guard.time.isDate(opts.time) ? new intrinsic.Date(guard.time.instantOf(opts.time)) : (opts.time === undefined ? new intrinsic.Date() : opts.time),
    requiredEku: Array.isArray(opts.requiredEku) ? opts.requiredEku.slice() : opts.requiredEku,
    checkPurpose: opts.checkPurpose,
  };
}

var _CERT_EXT_DECODERS = pkix.certExtensionDecoders(pkix.makeNS("cms", CmsError, oid)).byOid;

function _keyUsagePermitsSigning(parsedCerts, der) {
  var entry = intrinsic.filter(parsedCerts, function (c) { return intrinsic.bufferEquals(c.der, der); })[0];
  if (!entry) return true;
  var kuOid = oid.byName("keyUsage");
  var exts = entry.cert.extensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== kuOid) continue;
    var ku;
    try { ku = _CERT_EXT_DECODERS[kuOid](exts[i].value); }
    catch (_e) { return false; }
    return ku.digitalSignature === true || ku.contentCommitment === true || ku.nonRepudiation === true;
  }
  return true;
}

function _allTrusted(signers) {
  return guard.list.allMatch(signers, function (s) { return s.trusted === true; });
}

async function _applyTrust(res, parsedCerts, cfg) {
  res.trusted = false;
  intrinsic.forEach(res.signers, function (s) { s.trusted = false; });
  if (cfg.trustAnchors == null) return;
  if (!_engine) {
    throw _err("cms/bad-input", "opts.trustAnchors requires the path validator; load pki.path before verifying (require the toolkit through its index)");
  }
  var pool = intrinsic.map(parsedCerts, function (c) { return c.der; });
  var at = cfg.time;
  var anchors = cfg.trustAnchors;
  if (!anchors.length) {
    throw _err("cms/bad-input", "opts.trustAnchors is empty -- name at least one root, or omit it to state that the signer is not being anchored");
  }
  if (cfg.time !== undefined) guard.time.assertValid(cfg.time, _err, "cms/bad-input", "opts.time");
  var purposes = _engine.resolvePurposeOpts({ requiredEku: cfg.requiredEku, checkPurpose: cfg.checkPurpose });
  intrinsic.forEach(anchors, function (a) {
    _engine.toAnchor(a);
    if (purposes.checkPurpose != null) _engine.assertAnchorConstraints(a, purposes.checkPurpose);
  });
  for (var _si = 0; _si < res.signers.length; _si++) {
    var s = res.signers[_si];
    {
      if (s.ok !== true || !s.cert) { s.trusted = false; continue; }
      var buildOpts = { trustAnchors: anchors, intermediates: pool, validate: true, time: at };
      if (cfg.requiredEku != null) buildOpts.requiredEku = cfg.requiredEku;
      if (cfg.checkPurpose != null) buildOpts.checkPurpose = cfg.checkPurpose;
      if (!_keyUsagePermitsSigning(parsedCerts, s.cert)) { s.trusted = false; continue; }
      try {
        var r = await _engine.build(s.cert, buildOpts);
        s.trusted = !!(r && r.valid);
      } catch (e) {
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
  res.trusted = res.valid && res.signers.length > 0 && _allTrusted(res.signers);
}
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
 * @opts  additionalSignedAttributes  Extra signed attributes to add to every SignerInfo, each
 *                          `{ type, values }` (`type` an OID name or dotted string, `values` an
 *                          array of DER value `Buffer`s). Covered by the signature.
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
 * attribute, the construction Authenticode timestamps and signature-attestation workflows rest on.
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
 * recipient certificate's public-key algorithm: RSA yields a ktri with RSAES-OAEP-SHA256 (PKCS#1
 * v1.5 is never emitted); EC P-256/384/521 a kari with ephemeral-static ECDH and the X9.63 KDF;
 * X25519/X448 a kari per RFC 8418 (HKDF); ML-KEM-512/768/1024 an ori/KEMRecipientInfo per RFC
 * 9629 + 9936; a composite ML-KEM (id-MLKEM768-* / id-MLKEM1024-*, draft-lamps-pq-composite-kem) the
 * same ori/KEMRecipientInfo with the composite as the kem algorithm and AES-256-Wrap. `{ password }`
 * yields a pwri (PBKDF2 + RFC 3211 PWRI-KEK); `{ kek, kekId }` a kekri
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
 * Produce a CMS AuthenticatedData (RFC 5652 sec. 9): CLEARTEXT content plus a MAC (HMAC-SHA-2),
 * authenticated but not encrypted, the authenticated-only sibling of AuthEnvelopedData. A single
 * fresh MAC key is minted and wrapped for every recipient with the same RecipientInfo model
 * `pki.cms.encrypt` uses for a content-encryption key, so `recipients` is the identical array of
 * descriptors: `{ cert }` (RSA -> ktri RSAES-OAEP, EC/X25519/X448 -> kari, ML-KEM or composite ML-KEM -> ori/KEMRI),
 * `{ password }` (pwri), or `{ kek, kekId }` (kekri). By default the MAC covers the authenticated
 * attributes (a content-type and a message-digest = digest of the content) re-tagged to the EXPLICIT
 * SET OF (RFC 5652 sec. 9.2); with `authenticatedAttributes: false` (id-data content only) it covers
 * the content octets directly. `pki.cms.decrypt` recovers the MAC key, recomputes the MAC, and
 * (with authenticated attributes) independently confirms the message-digest before releasing the
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
 * @opts oaepHash The RSAES-OAEP hash for ktri recipients wrapping the MAC key: `"sha256"` (default) / `"sha384"` / `"sha512"`.
 * @opts ukm User keying material (a Buffer) for kari / kemri recipients.
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
 * ECDH / X25519 / X448; kekri; pwri; ori/ML-KEM or composite ML-KEM), and decrypts (or MAC-verifies) the content.
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
 * a sender identity. To bind one, verify a signature (`pki.cms.verify`) over the plaintext.
 * `authenticatedBy` names what the integrity rests on (`"content-encryption-key"` for AEAD,
 * `"message-authentication-key"` for AuthenticatedData, `null` for an unauthenticated cipher).
 * `originatorInfo` is surfaced as the sender supplied it and is UNAUTHENTICATED: it sits outside the
 * AEAD's authenticated data, so it is a hint, never evidence, and any certificate it carries must be
 * validated before use.
 *
 * With `stream: true` the result's `content` is an async iterable of plaintext `Buffer` chunks rather
 * than a single `Buffer`, for a payload too large to hold whole. An AuthEnvelopedData, an
 * AuthenticatedData, and the AEAD path verify integrity before the iterable yields, so a forged message
 * throws `cms/decrypt-failed` and no unverified plaintext is ever exposed. A CBC EnvelopedData or
 * EncryptedData carries no integrity, so it yields plaintext as the cipher produces it and a corrupt
 * message surfaces the same uniform `cms/decrypt-failed` on iteration, after earlier chunks reached the
 * caller who holds the key.
 *
 * @opts recipientIndex Explicitly select the recipient by index (overrides key-material matching).
 * @opts maxIterations  Lower the PBKDF2 iteration cap (a DoS bound; downward only).
 * @opts stream         Return `content` as an async iterable of plaintext `Buffer` chunks instead of a single `Buffer`.
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
 * `authenticated` / `valid` field. CompressedData is not a security assertion (RFC 8551 sec. 2.4.5).
 *
 * @opts maxOutputBytes Lower the decompressed-output cap (a DoS bound; downward only).
 * @example
 *   var compressedDer = await pki.cms.compress(Buffer.from("compress me"));
 *   var res = await pki.cms.decompress(compressedDer);
 *   res.content;   // the recovered plaintext Buffer
 */
var decompress = cmsCompress.decompress;

var KNOWN_PARSE_CERTS_ONLY_OPTS = { maxCerts: 1 };
function _certsOnlyInputDer(input, verb) {
  if (guard.bytes.isByteSource(input)) {
    var buf = guard.bytes.snapshotSource(input, CmsError, "cms/bad-input", verb + " input");
    if (buf[0] === 0x30) return buf;
    input = intrinsic.bufToString(buf, "latin1");
  }
  if (typeof input === "string") {
    var der = pkix.pemDecodeLenient(input, "CMS");
    if (der === null) der = pkix.pemDecodeLenient(input, "PKCS7");
    if (der === null) throw _err("cms/bad-input", verb + " input is neither DER nor a PEM CMS/PKCS7 block");
    return der;
  }
  throw _err("cms/bad-input", verb + " input must be a DER Buffer or a PEM string");
}

/**
 * @primitive  pki.cms.certsOnly
 * @signature  pki.cms.certsOnly(certs, opts?) -> Buffer | string
 * @since      0.6.3
 * @status     stable
 * @spec       RFC 8551, RFC 5652
 * @related    pki.cms.parseCertsOnly, pki.cms.isCertsOnly, pki.smime.buildCertsOnly
 *
 * Build a "certs-only" certificate-management message (RFC 8551 sec. 3.8): a degenerate CMS
 * `SignedData` that conveys certificates and/or CRLs and signs nothing. The emitted structure is
 * version 1 with an empty `digestAlgorithms`, an id-data `encapContentInfo` whose `eContent` is absent,
 * the certificates in `certificates [0]` and any CRLs in `crls [1]` (both DER-sorted and deduplicated),
 * and an empty `signerInfos`. It is how an AIA `caIssuers` bundle or an `application/pkcs7-mime;
 * smime-type=certs-only` attachment distributes a set of certificates. `certs` is a certificate or an
 * array of them (DER `Buffer` or PEM string), each parsed before embedding so a non-certificate is a
 * typed `CmsError` and is never emitted. At least one certificate or CRL is required.
 *
 * @opts crls A CRL or array of CRLs (DER Buffer or PEM string) to convey alongside the certificates.
 * @opts pem  Return a PEM string instead of a DER Buffer.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "Leaf", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: await pki.key.export(pair.privateKey) });
 *   var bundle = pki.cms.certsOnly([leafDer]);
 *   var r = pki.cms.parseCertsOnly(bundle);   // { certificates: [leafDer], crls: [] }
 */
var certsOnly = cmsSign.certsOnly;

/**
 * @primitive  pki.cms.parseCertsOnly
 * @signature  pki.cms.parseCertsOnly(input, opts?) -> { certificates, crls }
 * @since      0.6.3
 * @status     stable
 * @spec       RFC 8551, RFC 5652
 * @related    pki.cms.certsOnly, pki.cms.isCertsOnly, pki.est.parseCertsOnly
 *
 * Read a certs-only certificate-management message (DER Buffer or PEM) and recover the raw certificate
 * and CRL DER it carries. It requires a degenerate `SignedData` (id-data with no eContent, empty
 * `signerInfos`) and returns `{ certificates: [DER], crls: [DER] }`; a non-degenerate structure is a
 * typed `cms/not-certs-only`. A CRL-only message is accepted (RFC 8551 sec. 3.8 conveys "certificates
 * and/or CRLs"), unlike the stricter RFC 5272 Simple PKI Response `pki.est.parseCertsOnly`; a message
 * carrying neither certificates nor CRLs is refused. Each embedded certificate and CRL is validated
 * before it is returned.
 *
 * @opts maxCerts Cap the number of certificates and CRLs parsed and returned (a DoS bound on an untrusted bundle).
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "Leaf", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: await pki.key.export(pair.privateKey) });
 *   var bundleDer = pki.cms.certsOnly([certDer]);
 *   var r = pki.cms.parseCertsOnly(bundleDer);
 *   r.certificates;   // array of raw certificate DER Buffers
 */
function parseCertsOnly(input, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.parseCertsOnly options");
  guard.identifier.assertKnownKeys(opts, KNOWN_PARSE_CERTS_ONLY_OPTS, _err, "cms/bad-input", "pki.cms.parseCertsOnly has an unknown option ");
  var maxCerts = guard.limits.cap(opts.maxCerts == null ? undefined : opts.maxCerts, "maxCerts", undefined, { E: _err, code: "cms/bad-input" });
  return cms.parseCertsOnly(_certsOnlyInputDer(input, "pki.cms.parseCertsOnly"), _err, "cms", maxCerts, false);
}

/**
 * @primitive  pki.cms.isCertsOnly
 * @signature  pki.cms.isCertsOnly(input) -> boolean
 * @since      0.6.3
 * @status     stable
 * @spec       RFC 8551, RFC 5652
 * @related    pki.cms.certsOnly, pki.cms.parseCertsOnly
 *
 * Recognize a certs-only certificate-management message structurally: `true` when `input` (DER Buffer
 * or PEM) is a CMS `SignedData` with an id-data `encapContentInfo` whose `eContent` is absent and an
 * empty `signerInfos`, `false` for any other well-formed CMS (a signed message, an EnvelopedData).
 * Undecodable bytes throw a typed `CmsError`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var certDer = await pki.x509.sign({ subject: "Leaf", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: await pki.key.export(pair.privateKey) });
 *   pki.cms.isCertsOnly(pki.cms.certsOnly([certDer]));   // true
 */
function isCertsOnly(input) {
  var der = _certsOnlyInputDer(input, "pki.cms.isCertsOnly");
  var r;
  try {
    r = cms.parse(der);
  } catch (e) {
    if (e && e.code === "cms/unsupported-content-type") return false;
    throw e;
  }
  return r.contentTypeName === "signedData" &&
    r.encapContentInfo.eContentType === oid.byName("data") &&
    r.encapContentInfo.eContent === null &&
    r.signerInfos.length === 0;
}

// @internal
module.exports = { verify: verify, sign: sign, countersign: countersign, encrypt: encrypt, authenticate: authenticate, decrypt: decrypt, compress: compress, decompress: decompress, certsOnly: certsOnly, parseCertsOnly: parseCertsOnly, isCertsOnly: isCertsOnly, setEngine: setEngine };
