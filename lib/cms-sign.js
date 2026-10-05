// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// the operator-facing @module pki.cms + the @primitive pki.cms.sign documentation block live in

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var crlSchema = require("./schema-crl");
var pkix = require("./schema-pkix");
var frameworkError = require("./framework-error");

var webcrypto = require("./webcrypto");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
/** @internal `resolve` and `all` build their promise from the RECEIVER, so reading the global binding
 *  at the call hands the construction to whatever that binding holds. Each signer's digest and
 *  signature are awaited through one of these, and a replacement that settles without awaiting emits a
 *  SignedData whose SignerInfos were never completed. The constructor and both operations are taken at
 *  load. */
var _Promise = intrinsic.Promise;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);
var _promiseAll = intrinsic.uncurry(intrinsic.promiseAll);
var pkiBuild = require("./pki-build");
var cms = require("./schema-cms");
var constants = require("./constants");
/** @internal The RFC 3161 structural layer, for the one thing this module asks of a token: which
 *  octets its message imprint claims to cover. `schema-tsp` reaches only the schema modules, so this
 *  is not the signing module's own cycle back through `tsp-sign`. */
var tsp = require("./schema-tsp");

var subtle = webcrypto.webcrypto.subtle;
var CmsError = frameworkError.CmsError;
var b = asn1.build;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
function _signE(kind, message, cause) { return new CmsError("cms/" + kind, message, cause); }
function O(name) { return oid.byName(name); }

var KNOWN_SIGN_OPTS = intrinsic.assign(intrinsic.create(null), {
  signedAttributes: 1, signingTime: 1, additionalSignedAttributes: 1, unsignedAttributes: 1,
  algorithmProtection: 1,
  sid: 1, eContentType: 1, detached: 1, certificates: 1, pem: 1,
});
var KNOWN_SIGNER_CERT_KEYS = intrinsic.assign(intrinsic.create(null), { cert: 1, key: 1, pss: 1, digestAlgorithm: 1, combinedRsaSig: 1 });
var KNOWN_SIGNER_KEY_ONLY_KEYS = intrinsic.assign(intrinsic.create(null), { spki: 1, keyIdentifier: 1, key: 1, pss: 1, digestAlgorithm: 1, combinedRsaSig: 1 });
var KNOWN_COUNTERSIGN_OPTS = intrinsic.assign(intrinsic.create(null), {
  signerIndex: 1, countersignatureOf: 1, signingTime: 1, certificates: 1, pem: 1,
  signedAttributes: 1, additionalSignedAttributes: 1, sid: 1, algorithmProtection: 1,
});
var NS = pkix.makeNS("cms", CmsError, oid);
var _b = pkiBuild.makeBuilder({
  ErrorClass: CmsError, prefix: "cms", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: {},
});

var DIGEST_HASH = intrinsic.assign(intrinsic.create(null), {
  sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512",
  shake128: "SHAKE128", shake256: "SHAKE256",
});

var OID_DATA = O("data");
var OID_PKI_DATA = O("id-cct-PKIData");
var OID_SIGNED_DATA = O("signedData");
var OID_SKI = O("subjectKeyIdentifier");


function _digest(digestName, content) {
  return subtle.digest(DIGEST_HASH[digestName], content).then(function (d) { return Buffer.from(d); });
}


function _skiValue(cert) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (!ext) throw _err("cms/no-ski", "a subjectKeyIdentifier signer identifier requires the signer certificate to carry an SKI extension");
  try { return asn1.read.octetString(asn1.decode(ext.value)); }
  catch (e) { throw _err("cms/no-ski", "the signer certificate's subjectKeyIdentifier extension value is not an OCTET STRING", e); }
}


function _buildSid(cert, useSki) {
  var sid = useSki
    ? b.contextPrimitive(0, _skiValue(cert))
    : b.sequence([b.raw(pkiBuild.tbsNameField(cert, "issuer")), b.integer(cert.serialNumber)]);
  return { sid: sid, version: useSki ? 3 : 1 };
}

/** @internal The signed side keeps its blanket refusal of a repeated type, and the citation is what
 *  changes. RFC 5652 clause 5.3 does not state that rule: what it states is per type, "The
 *  SignedAttributes in a signerInfo MUST include only one instance of the message-digest attribute".
 *  Refusing every repeat is this builder's posture, stricter than the RFC and in the safe direction for
 *  something being emitted, so it stands; naming a clause that does not say it did not. The unsigned
 *  side had the same misattribution and could not keep the rule, a repeat being ordinary there. */
function _buildSignedAttrs(pairs) {
  var seenTypes = intrinsic.create(null);
  var attrs = intrinsic.map(pairs, function (p) {
    if (intrinsic.hasOwn(seenTypes, p.type)) throw _err("cms/bad-input", "this builder emits one instance of each signed attribute type, and " + p.type + " is repeated; RFC 5652 sec. 11.2 requires it of the message-digest attribute and this build asks it of all of them");
    seenTypes[p.type] = 1;
    return b.sequence([b.oid(p.type), b.set(p.values)]);
  });
  var setOf = b.set(attrs);
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA0;
  return { setOf: setOf, wire: wire };
}

var KNOWN_ATTRIBUTE_KEYS = intrinsic.assign(intrinsic.create(null), { type: 1, values: 1 });
function _resolveAttrPairs(list, what) {
  return intrinsic.map(list || [], function (a) {
    if (!a || typeof a !== "object") throw _err("cms/bad-input", "an attribute must be { type, values }");
    guard.identifier.assertKnownKeys(a, KNOWN_ATTRIBUTE_KEYS, _err, "cms/bad-input", "unknown attribute field (an attribute is { type, values }): ");
    var vals = intrinsic.map(a.values || [], function (v) { return _toBuf(v, what); });
    if (!vals.length) throw _err("cms/bad-input", "a signed attribute must carry at least one value (RFC 5652 -- Attribute values is SET SIZE (1..MAX))");
    return { type: oid.isDottedDecimal(a.type) ? a.type : O(a.type), values: vals };
  });
}

var UNSIGNED_FORBIDDEN = intrinsic.create(null);
UNSIGNED_FORBIDDEN[O("contentType")] = "content-type";
UNSIGNED_FORBIDDEN[O("messageDigest")] = "message-digest";
UNSIGNED_FORBIDDEN[O("signingTime")] = "signing-time";
/** @internal RFC 6211 sec. 2: the algorithm protection attribute "MUST NOT be an unsigned
 *  attribute", and sec. 5 adds that one placed there "does not provide any additional security".
 *  Both identifiers, since the two spell one attribute. The parser refuses the placement, so without
 *  the door here this verb would emit a message its own verifier rejects. */
UNSIGNED_FORBIDDEN[O("cmsAlgorithmProtection")] = "algorithm protection";
UNSIGNED_FORBIDDEN[O("cmsAlgorithmProtect")] = "algorithm protection";

function _buildUnsignedAttrs(list) {
  if (list == null) return null;
  if (!intrinsic.isArray(list)) throw _err("cms/bad-input", "opts.unsignedAttributes must be an array of { type, values }");
  if (!list.length) return null;
  var pairs = _resolveAttrPairs(list, "an unsigned attribute value");
  /** @internal A TYPE MAY REPEAT HERE, and the RFC is the authority for that rather than against it.
   *  `UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute` imposes no per-type uniqueness; clause 5.3
   *  says of the field only that it "is a collection of attributes that are not signed. The field is
   *  optional"; and the uniqueness rules the RFC does state are per type, "The SignedAttributes in a
   *  signerInfo MUST include only one instance of the message-digest attribute", while clause 11.4's
   *  countersignature type "specifies one or more signatures". A blanket refusal citing clause 5.3
   *  therefore denied a conforming message, and the shape it denied is the ordinary one: a signature
   *  re-timestamped by several authorities carries one timeStampToken attribute per authority. The
   *  per-type rules below are kept, and they are the ones with a clause behind them. */
  intrinsic.forEach(pairs, function (p) {
    if (intrinsic.hasOwn(UNSIGNED_FORBIDDEN, p.type)) throw _err("cms/bad-input", "the " + UNSIGNED_FORBIDDEN[p.type] + " attribute must not appear as an unsigned attribute (RFC 5652 sec. 11)");
  });
  var setOf = b.set(intrinsic.map(pairs, function (p) { return b.sequence([b.oid(p.type), b.set(p.values)]); }));
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA1;
  return wire;
}

/** @internal The RFC 6211 attribute built from the very TLVs the structure's own fields are built
 *  from. Sec. 2 says the attribute "contains a copy of the SignerInfo.digestAlgorithm field ...
 *  including any parameters associated with it", so the copy is made from the value in hand rather
 *  than re-derived from a registry row: a re-derivation can differ from the field it claims to copy,
 *  and the parameters are the substitution target the attribute exists to pin.
 *
 *  `armTag` is 1 for a `SignerInfo` signature algorithm and 2 for an `AuthenticatedData` MAC
 *  algorithm, which sec. 2 makes exclusive to their own placements. `which` names the identifier to
 *  emit: the RFC body value by default, the S/MIME registry value on request. */
function _algorithmProtectionPair(which, digestAlgId, armAlgId, armTag) {
  var type = which === "registry" ? O("cmsAlgorithmProtect") : O("cmsAlgorithmProtection");
  return { type: type, values: [b.sequence([digestAlgId, b.implicit(armTag, armAlgId)])] };
}

/** @internal An asked-for protection that cannot be placed is a refusal rather than a message that
 *  silently lacks it. The attribute rides in the signed attributes, so with none there is nowhere to
 *  put it, which is why RFC 8933 sec. 4.1 conditions its SHOULD on their presence. A caller who
 *  names both options is asking for two things that cannot both hold. */
function _assertProtectionPlaceable(opts) {
  if (opts.signedAttributes === false && opts.algorithmProtection) {
    throw _err("cms/bad-input", "algorithmProtection needs signed attributes to ride in, and " +
      "signedAttributes: false signs the content directly (RFC 6211 sec. 2 places the attribute in " +
      "SignerInfo.signedAttrs); drop one of the two");
  }
}

/** @internal The producer door, applied to this verb's attribute records. The policy itself lives in
 *  `schema-cms`, so the signing verbs and the authenticate verb enforce one rule rather than three
 *  copies of it. */
function _assertAlgorithmProtectionPairs(pairs, digestAlgId, armAlgId, armTag) {
  cms.assertAlgorithmProtectionEmission(pairs, b.sequence([digestAlgId, b.implicit(armTag, armAlgId)]), _err);
}

function _resolveSignerContext(signer, opts) {
  var so = signer || {};
  var keyOnly = so.cert == null && so.spki != null;
  var soKey = so.key;
  var soSpki = keyOnly ? guard.bytes.snapshotSource(so.spki, CmsError, "cms/bad-input", "a key-only signer's spki") : null;
  var certDer = keyOnly ? null : _normCertDer(so.cert);
  var cert = keyOnly ? _keyOnlyCertStandIn(soSpki) : x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var sidv = keyOnly
    ? { sid: b.contextPrimitive(0, _keyOnlyKeyId(so)), version: 3 }
    : _buildSid(cert, opts.sid === "ski");
  return { keyOnly: keyOnly, soKey: soKey, soSpki: soSpki, certDer: certDer, cert: cert,
    scheme: scheme, sid: sidv.sid, version: sidv.version };
}

async function _finishSignerInfo(rc, md, content, eContentType, opts) {
  var toSign;
  if (opts.signedAttributes === false) {
    toSign = content;
  } else {
    var pairs = [
      { type: O("contentType"), values: [b.oid(eContentType)] },
      { type: O("messageDigest"), values: [b.octetString(md)] },
    ];
    if (opts.signingTime !== false) intrinsic.push(pairs, { type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
    if (opts.algorithmProtection) {
      intrinsic.push(pairs, _algorithmProtectionPair(opts.algorithmProtection,
        rc.scheme.digestAlgId, rc.scheme.sigAlgId, 1));
    }
    pairs = intrinsic.concat(pairs, _resolveAttrPairs(opts.additionalSignedAttributes, "a signed attribute value"));
    _assertAlgorithmProtectionPairs(pairs, rc.scheme.digestAlgId, rc.scheme.sigAlgId, 1);
    toSign = _buildSignedAttrs(pairs);
  }
  var signedBytes = toSign.setOf ? toSign.setOf : toSign;
  var sig = await signScheme.signOverTbs(rc.scheme, rc.soKey, signedBytes, _signE);
  await _assertKeyMatchesSpki(rc.keyOnly, rc.soKey, rc.soSpki, rc.scheme, sig, signedBytes, rc.cert);
  var fields = [b.integer(BigInt(rc.version)), rc.sid, rc.scheme.digestAlgId];
  if (toSign.wire) intrinsic.push(fields, toSign.wire);
  intrinsic.push(fields, rc.scheme.sigAlgId, b.octetString(sig));
  var ua = _buildUnsignedAttrs(opts.unsignedAttributes);
  if (ua) intrinsic.push(fields, ua);
  return { si: b.sequence(fields), digestAlgId: rc.scheme.digestAlgId, version: rc.version, certDer: rc.certDer };
}

function _buildSignerInfo(signer, content, eContentType, opts) {
  var rc = _resolveSignerContext(signer, opts);
  var mdP = opts.signedAttributes === false ? _promiseResolve(_Promise, null) : _digest(rc.scheme.digest, content);
  return mdP.then(function (md) { return _finishSignerInfo(rc, md, content, eContentType, opts); });
}



async function _assertKeyMatchesSpki(keyOnly, soKey, soSpki, scheme, sig, signedBytes, cert) {
  var declared = keyOnly ? soSpki : (cert && cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.bytes);
  if (!declared) {
    throw _signE("bad-input",
      "a signer certificate did not surface its subjectPublicKeyInfo, so the signature it produced could " +
      "not be checked against the key the SignerInfo declares");
  }
  try {
    await _b.assertSignatureVerifies(signedBytes, sig, declared, scheme);
  } catch (e) {
    if (e && typeof e.code === "string" && e.code.indexOf("cms/") === 0) throw e;
    throw _signE("bad-input",
      "a signer's `key` does not match the public key its SignerInfo declares (" +
      (keyOnly ? "`spki`" : "its certificate") + "): the signature it produced does not verify under that key", e);
  }
}

function _timeValue(when) {
  var d = guard.time.isDate(when) ? when : new intrinsic.Date();
  return d.getUTCFullYear() < 2050 ? b.utcTime(d) : b.generalizedTime(d);
}

function _keyOnlyCertStandIn(spkiDer) {
  var alg;
  try {
    var node = asn1.decode(spkiDer);
    if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children ||
        node.children.length !== 2) {
      throw _err("cms/bad-input",
        "a key-only signer's spki is SEQUENCE { algorithm, subjectPublicKey BIT STRING } (RFC 5280 sec. 4.1.2.7)");
    }
    var keyNode = node.children[1];
    if (keyNode.tagClass !== "universal" || keyNode.tagNumber !== asn1.TAGS.BIT_STRING) {
      throw _err("cms/bad-input",
        "a key-only signer's spki subjectPublicKey must be a BIT STRING (RFC 5280 sec. 4.1.2.7)");
    }
    asn1.read.bitString(keyNode);
    var algNode = node.children[0];
    if (algNode.tagClass !== "universal" || algNode.tagNumber !== asn1.TAGS.SEQUENCE ||
        !algNode.children || !algNode.children.length || algNode.children.length > 2) {
      throw _err("cms/bad-input",
        "a key-only signer's spki algorithm is SEQUENCE { algorithm OID, parameters OPTIONAL } (RFC 5280 sec. 4.1.1.2)");
    }
    alg = {
      oid: asn1.read.oid(algNode.children[0]),
      parameters: algNode.children[1] ? algNode.children[1].bytes : null,
    };
  } catch (e) {
    if (e && typeof e.code === "string" && e.code.indexOf("cms/") === 0) throw e;
    throw _err("cms/bad-input", "a key-only signer's spki is not a SubjectPublicKeyInfo", e);
  }
  /** @internal The SPKI bytes travel with the stand-in, because the key this signature is verified
   * against is what a signer's declared publicKey is held to, and this form names that key by SPKI
   * rather than by certificate. */
  return { subjectPublicKeyInfo: { bytes: spkiDer, algorithm: alg } };
}

function _keyOnlyKeyId(so) {
  if (so.keyIdentifier == null) {
    throw _err("cms/bad-input",
      "a key-only signer requires keyIdentifier -- the subjectKeyIdentifier the certification request declares (RFC 5272 sec. 3.2)");
  }
  var id = guard.bytes.view(so.keyIdentifier, CmsError, "cms/bad-input", "a key-only signer's keyIdentifier");
  if (!id.length) throw _err("cms/bad-input", "a key-only signer's keyIdentifier must not be empty");
  return id;
}

function _normCertDer(c) {
  if (c == null) throw _err("cms/bad-input", "each signer requires a certificate (cert)");
  if (guard.bytes.isByteSource(c)) {
    c = guard.bytes.snapshotSource(c, CmsError, "cms/bad-input", "a signer certificate");
    return c[0] === 0x30 ? c : _pemToDer(c.toString("latin1"));
  }
  if (typeof c === "string") return _pemToDer(c);
  throw _err("cms/bad-input", "a signer certificate must be a DER Buffer or a PEM string");
}
function _pemToDer(text) {
  var der = pkix.pemDecodeLenient(text, "CERTIFICATE", _err, "cms/bad-input");
  if (der === null) throw _err("cms/bad-input", "a signer certificate PEM is not a CERTIFICATE block");
  return der;
}

// pki.cms.sign -- documented by the @primitive block in cms-verify.js (the @module pki.cms home).
function sign(content, signers, opts) {
  return guard.async.deferred(function () { return _signDispatch(content, signers, opts); });
}

function _signDispatch(content, signers, opts) {
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [signers, "the signer list"], [opts, "pki.cms.sign options"],
  ], function (copiedSigners, copiedOpts) {
    var stream = guard.bytes.asyncStreamOf(content);
    if (stream) return _signStream(stream, copiedSigners, copiedOpts);
    return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
      [content, "content"],
    ], function (copiedContent) { return _sign(copiedContent, copiedSigners, copiedOpts); });
  });
}

async function _signStream(stream, signers, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.sign options");
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "cms/bad-input", "unknown opts field ");
  _assertProtectionPlaceable(opts);
  if (opts.detached !== true) {
    throw _err("cms/bad-input", "a streaming (async-iterable) content requires opts.detached: true; an attached " +
      "SignedData embeds the content as a definite-length OCTET STRING, which cannot be produced without buffering it");
  }
  if (opts.signedAttributes === false) {
    throw _err("cms/bad-input", "a streaming content cannot be signed without signed attributes: the message-digest " +
      "attribute is the streamed hash, and there is no content to sign directly (RFC 5652 sec. 5.4)");
  }
  var list = intrinsic.isArray(signers) ? _b.reqDenseArray(signers, "the signer list") : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.sign requires at least one signer");
  var eContentType = opts.eContentType ? O(opts.eContentType) : OID_DATA;
  if (eContentType === OID_PKI_DATA && list.length > 1 &&
      intrinsic.some(list, function (s) { return s && s.cert == null && s.spki != null; })) {
    throw _err("cms/bad-input",
      "a key-only signer must be the ONLY SignerInfo in a Full PKI Request (RFC 5272 sec. 3.2)");
  }
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertEncodable(opts.signingTime, _err, "cms/bad-input", "signingTime");
  var rcs = intrinsic.map(list, function (s) { return _resolveSignerContext(s, opts); });
  var digestNames = [], seenDigest = intrinsic.create(null);
  intrinsic.forEach(rcs, function (r) { if (!seenDigest[r.scheme.digest]) { seenDigest[r.scheme.digest] = 1; intrinsic.push(digestNames, r.scheme.digest); } });
  var wcNames = intrinsic.map(digestNames, function (n) { return DIGEST_HASH[n]; });
  var digests;
  try {
    digests = await subtle.digestStream(wcNames, stream);
  } catch (e) {
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
  var byName = intrinsic.create(null);
  intrinsic.forEach(digestNames, function (n, i) { byName[n] = intrinsic.bufferFrom(digests[i]); });
  var built = [];
  for (var _ip = 0; _ip < rcs.length; _ip++) {
    intrinsic.push(built, await _finishSignerInfo(rcs[_ip], byName[rcs[_ip].scheme.digest], null, eContentType, opts));
  }
  return _assembleSignedData(built, eContentType, opts, null);
}

function _sign(content, signers, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.sign options");
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "cms/bad-input", "unknown opts field ");
  _assertProtectionPlaceable(opts);
  var contentBuf = _toBuf(content, "content");
  var list = Array.isArray(signers) ? _b.reqDenseArray(signers, "the signer list") : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.sign requires at least one signer");
  var eContentType = opts.eContentType ? O(opts.eContentType) : OID_DATA;
  if (eContentType === OID_PKI_DATA && list.length > 1 &&
      list.some(function (s) { return s && s.cert == null && s.spki != null; })) {
    throw _err("cms/bad-input",
      "a key-only signer must be the ONLY SignerInfo in a Full PKI Request (RFC 5272 sec. 3.2)");
  }
  if (opts.signedAttributes === false && eContentType !== OID_DATA) {
    throw _err("cms/bad-input", "signed attributes are required when eContentType is not id-data (RFC 5652 sec. 5.3)");
  }
  if (opts.signedAttributes === false && cms.looksLikeSignedAttributes(contentBuf)) {
    throw _err("cms/ambiguous-content", "this content is itself an encoded SignedAttributes block, so signing " +
      "it WITHOUT signed attributes would produce a signature that could be re-presented as one over " +
      "attributes (RFC 5652 sec. 5.4); sign it with signed attributes instead");
  }
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertEncodable(opts.signingTime, _err, "cms/bad-input", "signingTime");

  return _promiseAll(_Promise, list.map(function (s) { return _buildSignerInfo(s, contentBuf, eContentType, opts); }))
    .then(function (built) { return _assembleSignedData(built, eContentType, opts, contentBuf); });
}

function _assembleSignedData(built, eContentType, opts, contentBuf) {
  var seen = intrinsic.create(null), digestAlgs = [];
  intrinsic.forEach(built, function (x) { var k = intrinsic.bufToString(x.digestAlgId, "hex"); if (!seen[k]) { seen[k] = 1; intrinsic.push(digestAlgs, x.digestAlgId); } });
  var v3 = intrinsic.some(built, function (x) { return x.version === 3; }) || eContentType !== OID_DATA;
  var version = v3 ? 3 : 1;
  var encapFields = [b.oid(eContentType)];
  if (!opts.detached) intrinsic.push(encapFields, b.explicit(0, b.octetString(contentBuf)));
  var encap = b.sequence(encapFields);
  var sdFields = [b.integer(BigInt(version)), b.set(digestAlgs), encap];
  if (opts.certificates !== false) {
    var certDers = intrinsic.sort(_dedupe(intrinsic.filter(intrinsic.map(built, function (x) { return x.certDer; }),
      function (d) { return d != null; })), intrinsic.compare);
    if (certDers.length) intrinsic.push(sdFields, b.contextConstructed(0, intrinsic.bufferConcat(certDers)));
  }
  intrinsic.push(sdFields, b.set(intrinsic.map(built, function (x) { return x.si; })));
  var signedData = b.sequence(sdFields);
  var contentInfo = b.sequence([b.oid(OID_SIGNED_DATA), b.explicit(0, signedData)]);
  return opts.pem ? pkix.pemEncode(contentInfo, "CMS", frameworkError.PemError) : contentInfo;
}

/** @internal The OID and parameters of a digest AlgorithmIdentifier TLV, in the shape the schema
 *  module's RFC 5754 sec. 2 comparison reads a parsed one. */
function _digestAlgIdentifier(der) {
  var n = asn1.decode(der);
  return {
    oid: asn1.read.oid(n.children[0]),
    parameters: n.children.length > 1 ? n.children[1].bytes : null,
  };
}

function _dedupe(ders) {
  var seen = intrinsic.create(null), out = [];
  intrinsic.forEach(ders, function (d) { var k = intrinsic.bufToString(d, "hex"); if (!seen[k]) { seen[k] = 1; intrinsic.push(out, d); } });
  return out;
}

// certificates and/or CRLs and signs nothing. Documented by the @primitive block in cms-verify.js
// (the @module pki.cms home).
var KNOWN_CERTS_ONLY_OPTS = intrinsic.assign(intrinsic.create(null), { crls: 1, pem: 1 });

function _certsOnlyList(v, what) {
  if (v == null) return [];
  return intrinsic.isArray(v) ? _b.reqDenseArray(v, what) : [v];
}

function _normEntityDer(v, what, pemLabel, parseFn) {
  var der;
  if (guard.bytes.isByteSource(v)) {
    der = guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
    if (der[0] !== 0x30) {
      var decoded = pkix.pemDecodeLenient(intrinsic.bufToString(der, "latin1"), pemLabel, _err, "cms/bad-input");
      if (decoded === null) throw _err("cms/bad-input", what + " must be a plain DER " + pemLabel + " (a tagged alternative is not permitted) or a PEM block");
      der = decoded;
    }
  } else if (typeof v === "string") {
    var d2 = pkix.pemDecodeLenient(v, pemLabel, _err, "cms/bad-input");
    if (d2 === null) throw _err("cms/bad-input", what + " PEM is not a " + pemLabel + " block");
    der = d2;
  } else {
    throw _err("cms/bad-input", what + " must be a DER Buffer or a PEM string");
  }
  try { parseFn(der); }
  catch (e) { throw _err("cms/bad-input", what + " is not a valid " + pemLabel, e); }
  return der;
}
function _parseX509(der) { return x509.parse(der); }
function _parseCrl(der) { return crlSchema.parse(der); }

function certsOnly(certs, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.certsOnly options");
  guard.identifier.assertKnownKeys(opts, KNOWN_CERTS_ONLY_OPTS, _err, "cms/bad-input", "unknown opts field ");
  var certList = _certsOnlyList(certs, "certificates");
  var crlList = _certsOnlyList(opts.crls, "crls");
  if (!certList.length && !crlList.length) throw _err("cms/bad-input", "a certs-only message must carry at least one certificate or CRL (RFC 8551 sec. 3.8)");
  var certDers = intrinsic.sort(_dedupe(intrinsic.map(certList, function (c) { return _normEntityDer(c, "a certificate", "CERTIFICATE", _parseX509); })), intrinsic.compare);
  var crlDers = intrinsic.sort(_dedupe(intrinsic.map(crlList, function (c) { return _normEntityDer(c, "a CRL", "X509 CRL", _parseCrl); })), intrinsic.compare);
  var encap = b.sequence([b.oid(OID_DATA)]);
  var sdFields = [b.integer(1n), b.set([]), encap];
  if (certDers.length) intrinsic.push(sdFields, b.contextConstructed(0, intrinsic.bufferConcat(certDers)));
  if (crlDers.length) intrinsic.push(sdFields, b.contextConstructed(1, intrinsic.bufferConcat(crlDers)));
  intrinsic.push(sdFields, b.set([]));
  var signedData = b.sequence(sdFields);
  var contentInfo = b.sequence([b.oid(OID_SIGNED_DATA), b.explicit(0, signedData)]);
  return opts.pem ? pkix.pemEncode(contentInfo, "CMS", frameworkError.PemError) : contentInfo;
}

function _toBuf(v, what) {
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
  throw _err("cms/bad-input", what + " must be a Buffer");
}


function _resolveSignerIndices(spec, n) {
  if (spec == null) { if (n < 1) throw _err("cms/bad-input", "the SignedData carries no SignerInfo to countersign"); return [0]; }
  if (spec === "all") { var all = []; for (var i = 0; i < n; i++) all.push(i); return all; }
  var arr = Array.isArray(spec) ? spec : [spec];
  if (!arr.length) throw _err("cms/bad-input", "signerIndex must select at least one signer");
  arr.forEach(function (i) { if (typeof i !== "number" || !Number.isInteger(i) || i < 0 || i >= n) throw _err("cms/bad-input", "signerIndex out of range: " + i); });
  return arr;
}

function _buildCountersignature(targetSigOctets, countersigner, opts) {
  var so = countersigner || {};
  var certDer = _normCertDer(so.cert);
  var cert = x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var sidv = _buildSid(cert, opts.sid === "ski");
  var soKey = so.key;
  return _promiseResolve(_Promise, undefined).then(function () {
    if (opts.signedAttributes === false) return null;
    return _digest(scheme.digest, targetSigOctets).then(function (md) {
      var pairs = [{ type: O("messageDigest"), values: [b.octetString(md)] }];
      if (opts.signingTime !== false) pairs.push({ type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
      if (opts.algorithmProtection) {
        intrinsic.push(pairs, _algorithmProtectionPair(opts.algorithmProtection, scheme.digestAlgId, scheme.sigAlgId, 1));
      }
      var extra = _resolveAttrPairs(opts.additionalSignedAttributes, "a countersignature signed attribute value");
      extra.forEach(function (p) { if (p.type === O("contentType")) throw _err("cms/bad-input", "a countersignature must not carry a content-type attribute (RFC 5652 sec. 11.4)"); });
      var all = intrinsic.concat(pairs, extra);
      _assertAlgorithmProtectionPairs(all, scheme.digestAlgId, scheme.sigAlgId, 1);
      return _buildSignedAttrs(all);
    });
  }).then(function (attrs) {
    var preimage = attrs ? attrs.setOf : targetSigOctets;
    return signScheme.signOverTbs(scheme, soKey, preimage, _signE).then(function (sig) {
      /** @internal The countersignature is held to the same proof the signature is: it verifies
       * against the public key the countersigner's certificate declares. */
      return guard.async.deferred(function () {
        return _b.assertSignatureVerifies(preimage, sig, cert.subjectPublicKeyInfo.bytes, scheme);
      }).then(function () {
        var fields = [b.integer(BigInt(sidv.version)), sidv.sid, scheme.digestAlgId];
        if (attrs) fields.push(attrs.wire);
        fields.push(scheme.sigAlgId, b.octetString(sig));
        return { value: b.sequence(fields), certDer: certDer, digestAlgId: scheme.digestAlgId };
      });
    });
  });
}

function _mergeCountersig(uaNode, newCsValues) {
  var CS = O("countersignature");
  var others = [], csValues = [];
  if (uaNode) uaNode.children.forEach(function (attr) {
    if (asn1.read.oid(attr.children[0]) === CS) attr.children[1].children.forEach(function (v) { csValues.push(v.bytes); });
    else others.push(attr.bytes);
  });
  newCsValues.forEach(function (v) { csValues.push(v); });
  var csAttr = b.sequence([b.oid(CS), b.set(csValues)]);
  var setOf = b.set(others.concat([csAttr]));
  var wire = Buffer.from(setOf); wire[0] = 0xA1;
  return wire;
}

function _appendCountersigs(siNode, newCsValues) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var hasUa = last.tagClass === "context" && last.tagNumber === 1;
  var base = (hasUa ? kids.slice(0, kids.length - 1) : kids).map(function (k) { return k.bytes; });
  base.push(_mergeCountersig(hasUa ? last : null, newCsValues));
  return b.sequence(base);
}

function _spliceNested(siNode, j, newCsValues) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var CS = O("countersignature");
  if (!last || last.tagClass !== "context" || last.tagNumber !== 1) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var found = false;
  var attrs = last.children.map(function (attr) {
    if (asn1.read.oid(attr.children[0]) !== CS) return attr.bytes;
    var values = attr.children[1].children;
    if (j < 0 || j >= values.length) throw _err("cms/bad-input", "countersignatureOf out of range: " + j);
    found = true;
    return b.sequence([b.oid(CS), b.set(values.map(function (v, vi) { return vi === j ? _appendCountersigs(v, newCsValues) : v.bytes; }))]);
  });
  if (!found) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var setOf = b.set(attrs); var wire = Buffer.from(setOf); wire[0] = 0xA1;
  var base = kids.slice(0, kids.length - 1).map(function (k) { return k.bytes; });
  base.push(wire);
  return b.sequence(base);
}

function _signatureOctets(siNode) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var sigNode = (last.tagClass === "context" && last.tagNumber === 1) ? kids[kids.length - 2] : last;
  return asn1.read.octetString(sigNode);
}

function _targetPreimage(siNode, opts) {
  if (opts.countersignatureOf == null) return _signatureOctets(siNode);
  var last = siNode.children[siNode.children.length - 1];
  var CS = O("countersignature");
  if (!last || last.tagClass !== "context" || last.tagNumber !== 1) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var attr = last.children.filter(function (a) { return asn1.read.oid(a.children[0]) === CS; })[0];
  if (!attr) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var values = attr.children[1].children;
  var j = opts.countersignatureOf;
  if (typeof j !== "number" || !Number.isInteger(j) || j < 0 || j >= values.length) throw _err("cms/bad-input", "countersignatureOf out of range: " + j);
  return _signatureOctets(values[j]);
}

// pki.cms.countersign -- documented by the @primitive block in cms-verify.js (the @module pki.cms home).
function countersign(cmsInput, signers, opts) {
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [cmsInput, "the CMS message"], [signers, "the signer list"], [opts, "pki.cms.countersign options"],
  ], _countersign);
}

function _countersign(cmsInput, signers, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.countersign options");
  guard.identifier.assertKnownKeys(opts, KNOWN_COUNTERSIGN_OPTS, _err, "cms/bad-input", "unknown opts field ");
  _assertProtectionPlaceable(opts);
  var list = Array.isArray(signers) ? signers : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.countersign requires at least one countersigner");
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertEncodable(opts.signingTime, _err, "cms/bad-input", "signingTime");
  var der = pkix.coerceToDer(cmsInput, { pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CmsError, prefix: "cms" });
  var parsed = cms.parse(der);
  if (!Array.isArray(parsed.signerInfos)) throw _err("cms/bad-input", "pki.cms.countersign input is not a CMS SignedData");
  var targets = _resolveSignerIndices(opts.signerIndex, parsed.signerInfos.length);
  var root = asn1.decode(der);
  var sd = root.children[1].children[0];
  var sdKids = sd.children;
  var siSet = sdKids[sdKids.length - 1];

  var jobs = [];
  targets.forEach(function (t) {
    var preimage = _targetPreimage(siSet.children[t], opts);
    list.forEach(function (cs) { jobs.push({ t: t, p: _buildCountersignature(preimage, cs, opts) }); });
  });
  return _promiseAll(_Promise, jobs.map(function (j) { return j.p; })).then(function (built) {
    var byTarget = intrinsic.create(null), certDers = [], csDigestAlgs = [];
    intrinsic.forEach(built, function (res, i) {
      var slot = byTarget[jobs[i].t] || (byTarget[jobs[i].t] = []);
      intrinsic.push(slot, res.value);
      intrinsic.push(certDers, res.certDer);
      intrinsic.push(csDigestAlgs, res.digestAlgId);
    });

    var newSiSet = b.set(siSet.children.map(function (siNode, idx) {
      if (!byTarget[idx]) return siNode.bytes;
      return opts.countersignatureOf == null ? _appendCountersigs(siNode, byTarget[idx]) : _spliceNested(siNode, opts.countersignatureOf, byTarget[idx]);
    }));

    var certsNode = null, crlsNode = null;
    for (var i = 3; i < sdKids.length - 1; i++) {
      if (sdKids[i].tagClass === "context" && sdKids[i].tagNumber === 0) certsNode = sdKids[i];
      else if (sdKids[i].tagClass === "context" && sdKids[i].tagNumber === 1) crlsNode = sdKids[i];
    }
    var existing = [];
    if (certsNode) certsNode.children.forEach(function (c) { existing.push(c.bytes); });
    if (opts.certificates !== false) certDers.forEach(function (d) { existing.push(d); });
    /** @internal The DER SET ordering through the captured copy, sort AND comparator: read off its own
     * home, any of the three decides which certificate lands where in the set this message carries. */
    var allCerts = guard.list.sortedCopy(_dedupe(existing), intrinsic.compare);

    /** @internal RFC 5652 sec. 5.1 has this collection list "the message digest algorithms employed
     * by all of the signers", and sec. 11.4 makes a countersignature a SignerInfo, so sec. 5.3's
     * "the message digest algorithm SHOULD be among those listed in the digestAlgorithms field"
     * reaches a countersigner's digest too. The set is outside every signature in the message, the
     * way the unsigned attribute the countersignature lands in is, so adding to it here leaves each
     * existing signature verifying over the same bytes.
     * Whether an algorithm is ALREADY listed is asked through the schema module's RFC 5754 sec. 2
     * comparison, not by matching bytes: a message from another producer may spell a digest with an
     * explicit NULL where this one omits the parameters, and those are one algorithm, so a byte
     * comparison would list it a second time. */
    var listed = [];
    intrinsic.forEach(intrinsic.isArray(parsed.digestAlgorithms) ? parsed.digestAlgorithms : [],
      function (a) { intrinsic.push(listed, a); });
    var digestAlgs = intrinsic.map(sdKids[1].children, function (d) { return d.bytes; });
    intrinsic.forEach(csDigestAlgs, function (der) {
      var info = _digestAlgIdentifier(der);
      var already = false;
      intrinsic.forEach(listed, function (alg) { if (cms.sameDigestAlgorithm(alg, info)) already = true; });
      if (already) return;
      intrinsic.push(listed, info);
      intrinsic.push(digestAlgs, der);
    });
    var newSdFields = [sdKids[0].bytes, b.set(digestAlgs), sdKids[2].bytes];
    if (allCerts.length) newSdFields.push(b.contextConstructed(0, Buffer.concat(allCerts)));
    if (crlsNode) newSdFields.push(crlsNode.bytes);
    newSdFields.push(newSiSet);
    var newCi = b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(newSdFields))]);
    return opts.pem ? pkix.pemEncode(newCi, "CMS", frameworkError.PemError) : newCi;
  });
}

/** @internal One Attribute appended to a SignerInfo's `[1] unsignedAttrs`, with every attribute
 *  already there kept byte for byte and the SET OF re-sorted. A NEW attribute member rather than a
 *  value merged into an existing one of the same type: ETSI EN 319 122-1 clause 5.3 reads "The
 *  signature-time-stamp attribute shall contain exactly one component of AttributeValue type", while
 *  RFC 5126 clause 6.1.1 has "Several instances of this attribute may occur with an electronic
 *  signature, from different TSAs", so n timestamps are n attribute instances each carrying a
 *  one-element SET. That is the opposite of the countersignature above, where RFC 5652 clause 11.4
 *  puts n signatures in one attribute's values, which is why the two do not share this helper.
 *
 *  `build.set` sorts with the same comparison the parser's `derSetOrder` check applies, so the
 *  rebuilt SET OF cannot be in an order the reader refuses. The `0x31` to `0xA1` re-tag is sound
 *  because both identifiers are a single octet, leaving the length encoding untouched. */
function _appendUnsignedAttr(siNode, attrDer) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var hasUa = last.tagClass === "context" && last.tagNumber === 1;
  var base = intrinsic.map((hasUa ? intrinsic.arraySlice(kids, 0, kids.length - 1) : kids), function (k) { return k.bytes; });
  var existing = hasUa ? intrinsic.map(last.children, function (a) { return a.bytes; }) : [];
  var setOf = b.set(intrinsic.concat(existing, [attrDer]));
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA1;
  intrinsic.push(base, wire);
  return b.sequence(base);
}

/** @internal The SignerInfo node a verb is targeting, with the index checked against what the message
 *  carries rather than against a caller's assertion. */
function _timestampTarget(der, signerIndex, who) {
  var parsed = cms.parse(der);
  if (!intrinsic.isArray(parsed.signerInfos)) throw _err("cms/bad-input", who + " input is not a CMS SignedData");
  var idx = signerIndex == null ? 0 : signerIndex;
  if (typeof idx !== "number" || !intrinsic.isInteger(idx) || idx < 0 || idx >= parsed.signerInfos.length) {
    throw _err("cms/bad-input", who + " signerIndex out of range: " + guard.text.showValue(signerIndex) +
      " (the message carries " + parsed.signerInfos.length + " signer" + (parsed.signerInfos.length === 1 ? "" : "s") + ")");
  }
  var root = asn1.decode(der);
  var sd = root.children[1].children[0];
  var siSet = sd.children[sd.children.length - 1];
  return { parsed: parsed, root: root, sd: sd, siSet: siSet, idx: idx, siNode: siSet.children[idx] };
}

var KNOWN_IMPRINT_OPTS = intrinsic.assign(intrinsic.create(null), { signerIndex: 1, digestAlgorithm: 1 });

/**
 * @primitive pki.cms.timestampImprint
 * @signature  pki.cms.timestampImprint(input, opts?) -> Promise<{ imprint, signerIndex }>
 * @since      0.8.52
 * @status     stable
 * @spec       ETSI EN 319 122-1 clause 5.3, RFC 5126 clause 6.1.1, RFC 3161 clause 2.4.1
 * @related    pki.cms.attachTimestamp, pki.tsp.request, pki.tsp.verify, pki.cms.verify
 *
 * The message imprint a time-stamping authority is asked to sign over, for the CAdES
 * signature-time-stamp attribute. EN 319 122-1 clause 5.3 fixes what it covers: "the hash value of
 * the signature field (without the ASN.1 tag and length) within SignerInfo for which the
 * signature-time-stamp attribute is created". So this is a digest of the contents octets of
 * `SignerInfo.signature`, with the tag and length excluded, which is the same octet rule RFC 5652
 * clause 11.4 states for a countersignature.
 *
 * `input` is the SignedData as a DER `Buffer` or a PEM `CMS` string, the same input
 * `pki.cms.countersign` takes and for the same reason: the imprint covers exact octets of the
 * message as it stands, so this reads the wire bytes rather than a representation of them. The
 * result is `{ imprint, signerIndex }`: `imprint` is `{ hashAlgorithm, hashedMessage }`, the
 * argument `pki.tsp.request` and `pki.tsp.sign` take, so a third-party authority can be driven
 * without this package signing anything, and `signerIndex` is the signer it was taken for, which is
 * what `pki.cms.attachTimestamp` is given when the token comes back.
 *
 * @opts  signerIndex      which signer to take the imprint for (default 0).
 * @opts  digestAlgorithm  the digest to take (default `"sha256"`). MD5 is refused: EN 319 122-1
 *                         clause 6.2.1 reads "In addition, MD5 algorithm shall not be used as digest
 *                         algorithm".
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var signedDer = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   var taken = await pki.cms.timestampImprint(signedDer);
 *   var req = pki.tsp.request(taken.imprint, { certReq: true });
 *   taken.imprint.hashAlgorithm;   // "sha256"
 */
function timestampImprint(input, opts) {
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [input, "the CMS message"], [opts, "pki.cms.timestampImprint options"],
  ], _timestampImprint);
}

function _timestampImprint(input, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.timestampImprint options");
  guard.identifier.assertKnownKeys(opts, KNOWN_IMPRINT_OPTS, _err, "cms/bad-input", "unknown opts field ");
  var name = opts.digestAlgorithm == null ? "sha256" : opts.digestAlgorithm;
  /** @internal MD5 is answered before the build's own digest table, which does not carry it either:
   *  asked for by name, it gets the clause that forbids it rather than the generic "this build does
   *  not have that digest", which is a different thing to tell an operator. */
  if (name === "md5") throw _err("cms/bad-input", "MD5 shall not be used as a digest algorithm (ETSI EN 319 122-1 clause 6.2.1)");
  /** @internal Admitted against the digests a timestamp VERIFIER reads an imprint under, not the
   *  build's general digest table: a digest outside that set produces an imprint whose token every
   *  verifier here refuses, so taking one would hand an operator a request for an unusable token. */
  if (typeof name !== "string" || !intrinsic.hasOwn(constants.NAMES.TIMESTAMP_IMPRINT_DIGESTS, name)) {
    throw _err("cms/bad-input", "digestAlgorithm must name a digest a signature timestamp is read " +
      "under (sha256, sha384 or sha512), got " + guard.text.showValue(opts.digestAlgorithm));
  }
  /** @internal A weak digest is refused outright here, with no opt-in beside it. `attachTimestamp`
   *  has one because a token that already exists may be archived under a digest that was current
   *  when it was made; a token this imprint would be sent for does not exist yet, so the only thing
   *  the option could buy is a request for a token this verb's own sibling then refuses. */
  if (intrinsic.hasOwn(constants.NAMES.WEAK_DIGESTS, name)) {
    throw _err("cms/bad-input", "the imprint digest " + name + " is one a signature timestamp is " +
      "refused for, so a token taken over it could not be attached or verified");
  }
  var der = pkix.coerceToDer(input, { pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CmsError, prefix: "cms" });
  var t = _timestampTarget(der, opts.signerIndex, "pki.cms.timestampImprint");
  /** @internal `imprint` is nested rather than spread across the result, so the object this returns
   *  is the one `pki.tsp.request` and `pki.tsp.sign` take: their message-imprint door admits
   *  `hashAlgorithm` and `hashedMessage` and refuses any other field, which a flat result carrying
   *  the signer index would trip. The index is what `pki.cms.attachTimestamp` is then given, so it
   *  is reported beside the imprint instead of inside it. */
  return guard.verdict.of({
    imprint: guard.verdict.of({
      hashAlgorithm: name,
      hashedMessage: guard.crypto.digest(name, _signatureOctets(t.siNode)),
    }),
    signerIndex: t.idx,
  });
}

var KNOWN_ATTACH_OPTS = intrinsic.assign(intrinsic.create(null), { signerIndex: 1, pem: 1, allowWeakDigests: 1 });

/**
 * @primitive pki.cms.attachTimestamp
 * @signature pki.cms.attachTimestamp(input, token, opts?) -> Promise<Buffer>
 * @since      0.8.52
 * @status     stable
 * @spec       ETSI EN 319 122-1 clause 5.3, RFC 5126 clause 6.1.1, RFC 3161
 * @related    pki.cms.timestampImprint, pki.cms.verify, pki.tsp.sign, pki.cms.countersign
 *
 * Attach an RFC 3161 `TimeStampToken` to a signature as the CAdES signature-time-stamp unsigned
 * attribute `{ 1 2 840 113549 1 9 16 2 14 }`, taking a `SignedData` to the EN 319 122-1 B-T level.
 * `input` is that SignedData as a DER `Buffer` or a PEM `CMS` string and `token` the token a
 * time-stamping authority returned for the imprint `pki.cms.timestampImprint` produced, as DER or
 * PEM. Both are read as wire bytes rather than as a parsed representation, because this verb
 * rewrites the message's own octets.
 *
 * It SPLICES rather than re-signs. Re-signing produces a different signature value, so a token taken
 * over the first one would no longer match it, which is measured and not reasoned: with ECDSA the
 * second signature differs every time. What is preserved byte for byte is therefore everything the
 * four signature inputs cover: the encapsulated content and its type, and per signer the `version`,
 * `sid`, `digestAlgorithm`, `[0] signedAttrs`, `signatureAlgorithm` and `signature` TLVs, plus every
 * embedded certificate, every revocation entry, and every attribute already in `unsignedAttrs`. What
 * is re-encoded is the targeted signer's `[1] unsignedAttrs` SET OF and the five enclosing lengths,
 * none of which appears in any signature input.
 *
 * Several instances may be attached, one per authority, which is what RFC 5126 clause 6.1.1 permits
 * and EN 319 122-1 clause 5.3 shapes: each is its own attribute carrying exactly one value.
 *
 * `signerIndex` names a signer of the INPUT. `signerInfos` is a SET OF, whose members are emitted in
 * DER order, so giving one member an attribute changes its encoding and can change its position:
 * identify a signer of the OUTPUT by its signature value or its certificate, not by the index it
 * held on the way in.
 *
 * The imprint is checked before anything is written, so this verb cannot produce a message its own
 * verifier would reject: the token's imprint must be the hash of the targeted signer's signature
 * value, and its digest must be one the verifier admits. Nothing else about the token is judged
 * here; `pki.cms.verify` does that.
 *
 * @opts  signerIndex  which signer to attach to (default 0).
 * @opts  pem          return a PEM `CMS` block rather than DER.
 * @opts  allowWeakDigests  attach a token whose imprint is a weak digest, which both this verb and
 *                   `pki.cms.verify` refuse by default. This is the archived-token path, and the
 *                   same option is needed again at verification.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var spki = await pki.key.export(pair.publicKey);
 *   var nb = new Date("2026-01-01T00:00:00Z"), na = new Date("2036-01-01T00:00:00Z");
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: spki, notBefore: nb, notAfter: na }, { key: key });
 *   // RFC 3161 sec. 2.3: a TSA certificate's extendedKeyUsage MUST be critical and name timeStamping alone
 *   var tsaCert = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: spki, notBefore: nb, notAfter: na,
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var signedDer = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   var taken = await pki.cms.timestampImprint(signedDer);
 *   var token = await pki.tsp.sign(taken.imprint, { cert: tsaCert, key: key },
 *     { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var bT = await pki.cms.attachTimestamp(signedDer, token, { signerIndex: taken.signerIndex });
 *   (await pki.cms.verify(bT, { certs: [cert] })).signers[0].signatureTimeStamps[0].valid;   // true
 */
function attachTimestamp(input, token, opts) {
  return guard.async.deferred(function () {
    return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
      [input, "the CMS message"], [token, "the time-stamp token"], [opts, "pki.cms.attachTimestamp options"],
    ], _attachTimestamp);
  });
}

function _attachTimestamp(input, token, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.attachTimestamp options");
  guard.identifier.assertKnownKeys(opts, KNOWN_ATTACH_OPTS, _err, "cms/bad-input", "unknown opts field ");
  var der = pkix.coerceToDer(input, { pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CmsError, prefix: "cms" });
  var tokenDer = pkix.coerceToDer(token, { pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CmsError, prefix: "cms" });
  var t = _timestampTarget(der, opts.signerIndex, "pki.cms.attachTimestamp");

  /** @internal The imprint is checked HERE, before a byte is written, against the signature this
   *  attribute will hang on. A verb that wrote first would produce a message `pki.cms.verify` refuses
   *  on the row it just created, and the caller would have no way to tell a mis-addressed token from
   *  a corrupt one. The token's own structure, its authority's certificate and its chain are not
   *  judged here: those are the verifier's, and judging them twice in two places is two answers. */
  var tst = tsp.parseToken(tokenDer);
  var want = tst.tstInfo.messageImprint;
  var name = want.hashAlgorithm && want.hashAlgorithm.name;
  if (!name || !intrinsic.hasOwn(constants.NAMES.TIMESTAMP_IMPRINT_DIGESTS, name)) {
    throw _err("cms/bad-input", "the token's message imprint names a digest a signature timestamp " +
      "is not read under: " + guard.text.showValue(name || (want.hashAlgorithm && want.hashAlgorithm.oid)));
  }
  /** @internal The identifier is held to its own encoding as well as to its name: a digest
   *  AlgorithmIdentifier carries absent or DER NULL parameters (RFC 5754 clause 2), and the ANY
   *  field is carried through the parse unvalidated, so one naming sha256 beside arbitrary bytes
   *  would otherwise be hashed as a well-formed imprint. */
  if (!guard.der.paramsAbsentOrNull(want.hashAlgorithm.parameters)) {
    throw _err("cms/bad-input", "the token's message imprint algorithm identifier carries " +
      "parameters other than DER NULL, which a digest identifier does not (RFC 5754 clause 2)");
  }
  /** @internal The same digest posture the verifier holds this attribute to, read from the one
   *  membership list: a token whose imprint is a weak digest is refused here too, under the option
   *  that admits it there, so the verb does not write an attribute whose row `pki.cms.verify` then
   *  refuses by default. The imprint carries the whole binding between the token and the signature,
   *  and a collision in it substitutes one signature under a genuine token. */
  if (opts.allowWeakDigests !== true && intrinsic.hasOwn(constants.NAMES.WEAK_DIGESTS, name)) {
    throw _err("cms/weak-timestamp-imprint", "the token's message imprint is a " + name + " digest, " +
      "which a signature timestamp is refused for by default; pass allowWeakDigests: true to attach " +
      "an archived token under it");
  }
  var have = guard.crypto.digest(name, _signatureOctets(t.siNode));
  if (!guard.crypto.constantTimeEqual(have, want.hashedMessage)) {
    throw _err("cms/timestamp-imprint-mismatch", "the token's message imprint is not the hash of this " +
      "signer's signature value, so attaching it would produce a signature timestamp that does not " +
      "verify (ETSI EN 319 122-1 clause 5.3)");
  }

  var attr = b.sequence([b.oid(O("timeStampToken")), b.set([tokenDer])]);
  var newSiSet = b.set(intrinsic.map(t.siSet.children, function (siNode, i) {
    return i === t.idx ? _appendUnsignedAttr(siNode, attr) : siNode.bytes;
  }));
  var sdKids = t.sd.children;
  var newSdFields = intrinsic.map(intrinsic.arraySlice(sdKids, 0, sdKids.length - 1), function (k) { return k.bytes; });
  intrinsic.push(newSdFields, newSiSet);
  var out = b.sequence([t.root.children[0].bytes, b.explicit(0, b.sequence(newSdFields))]);
  return opts.pem ? pkix.pemEncode(out, "CMS", frameworkError.PemError) : out;
}

module.exports = {
  sign: sign, countersign: countersign, certsOnly: certsOnly,
  timestampImprint: timestampImprint, attachTimestamp: attachTimestamp,
  // @internal
  KNOWN_SIGNER_CERT_KEYS: KNOWN_SIGNER_CERT_KEYS,
  KNOWN_SIGNER_KEY_ONLY_KEYS: KNOWN_SIGNER_KEY_ONLY_KEYS,
};
