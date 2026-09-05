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
var pkiBuild = require("./pki-build");
var cms = require("./schema-cms");

var subtle = webcrypto.webcrypto.subtle;
var CmsError = frameworkError.CmsError;
var b = asn1.build;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
function _signE(kind, message, cause) { return new CmsError("cms/" + kind, message, cause); }
function O(name) { return oid.byName(name); }

var KNOWN_SIGN_OPTS = {
  signedAttributes: 1, signingTime: 1, additionalSignedAttributes: 1, unsignedAttributes: 1,
  sid: 1, eContentType: 1, detached: 1, certificates: 1, pem: 1,
};
var KNOWN_SIGNER_CERT_KEYS = { cert: 1, key: 1, pss: 1, digestAlgorithm: 1, combinedRsaSig: 1 };
var KNOWN_SIGNER_KEY_ONLY_KEYS = { spki: 1, keyIdentifier: 1, key: 1, pss: 1, digestAlgorithm: 1, combinedRsaSig: 1 };
var KNOWN_COUNTERSIGN_OPTS = {
  signerIndex: 1, countersignatureOf: 1, signingTime: 1, certificates: 1, pem: 1,
  signedAttributes: 1, additionalSignedAttributes: 1, sid: 1,
};
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

function _buildSignedAttrs(pairs) {
  var seenTypes = {};
  var attrs = intrinsic.map(pairs, function (p) {
    if (intrinsic.hasOwn(seenTypes, p.type)) throw _err("cms/bad-input", "signedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + p.type);
    seenTypes[p.type] = 1;
    return b.sequence([b.oid(p.type), b.set(p.values)]);
  });
  var setOf = b.set(attrs);
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA0;
  return { setOf: setOf, wire: wire };
}

function _resolveAttrPairs(list, what) {
  return intrinsic.map(list || [], function (a) {
    var vals = intrinsic.map(a.values || [], function (v) { return _toBuf(v, what); });
    if (!vals.length) throw _err("cms/bad-input", "a signed attribute must carry at least one value (RFC 5652 -- Attribute values is SET SIZE (1..MAX))");
    return { type: oid.isDottedDecimal(a.type) ? a.type : O(a.type), values: vals };
  });
}

var UNSIGNED_FORBIDDEN = intrinsic.create(null);
UNSIGNED_FORBIDDEN[O("contentType")] = "content-type";
UNSIGNED_FORBIDDEN[O("messageDigest")] = "message-digest";
UNSIGNED_FORBIDDEN[O("signingTime")] = "signing-time";

function _buildUnsignedAttrs(list) {
  if (list == null) return null;
  if (!intrinsic.isArray(list)) throw _err("cms/bad-input", "opts.unsignedAttributes must be an array of { type, values }");
  if (!list.length) return null;
  var pairs = _resolveAttrPairs(list, "an unsigned attribute value");
  var seen = {};
  intrinsic.forEach(pairs, function (p) {
    if (intrinsic.hasOwn(UNSIGNED_FORBIDDEN, p.type)) throw _err("cms/bad-input", "the " + UNSIGNED_FORBIDDEN[p.type] + " attribute must not appear as an unsigned attribute (RFC 5652 sec. 11)");
    if (intrinsic.hasOwn(seen, p.type)) throw _err("cms/bad-input", "unsignedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + p.type);
    seen[p.type] = 1;
  });
  var setOf = b.set(intrinsic.map(pairs, function (p) { return b.sequence([b.oid(p.type), b.set(p.values)]); }));
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA1;
  return wire;
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
    pairs = intrinsic.concat(pairs, _resolveAttrPairs(opts.additionalSignedAttributes, "a signed attribute value"));
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
  var mdP = opts.signedAttributes === false ? Promise.resolve(null) : _digest(rc.scheme.digest, content);
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
  return { subjectPublicKeyInfo: { algorithm: alg } };
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
  var der = pkix.pemDecodeLenient(text, "CERTIFICATE");
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
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");
  var rcs = intrinsic.map(list, function (s) { return _resolveSignerContext(s, opts); });
  var digestNames = [], seenDigest = {};
  intrinsic.forEach(rcs, function (r) { if (!seenDigest[r.scheme.digest]) { seenDigest[r.scheme.digest] = 1; intrinsic.push(digestNames, r.scheme.digest); } });
  var wcNames = intrinsic.map(digestNames, function (n) { return DIGEST_HASH[n]; });
  var digests;
  try {
    digests = await subtle.digestStream(wcNames, stream);
  } catch (e) {
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
  var byName = {};
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
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");

  return Promise.all(list.map(function (s) { return _buildSignerInfo(s, contentBuf, eContentType, opts); }))
    .then(function (built) { return _assembleSignedData(built, eContentType, opts, contentBuf); });
}

function _assembleSignedData(built, eContentType, opts, contentBuf) {
  var seen = {}, digestAlgs = [];
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

function _dedupe(ders) {
  var seen = {}, out = [];
  intrinsic.forEach(ders, function (d) { var k = intrinsic.bufToString(d, "hex"); if (!seen[k]) { seen[k] = 1; intrinsic.push(out, d); } });
  return out;
}

// certificates and/or CRLs and signs nothing. Documented by the @primitive block in cms-verify.js
// (the @module pki.cms home).
var KNOWN_CERTS_ONLY_OPTS = { crls: 1, pem: 1 };

function _certsOnlyList(v, what) {
  if (v == null) return [];
  return intrinsic.isArray(v) ? _b.reqDenseArray(v, what) : [v];
}

function _normEntityDer(v, what, pemLabel, parseFn) {
  var der;
  if (guard.bytes.isByteSource(v)) {
    der = guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
    if (der[0] !== 0x30) {
      var decoded = pkix.pemDecodeLenient(intrinsic.bufToString(der, "latin1"), pemLabel);
      if (decoded === null) throw _err("cms/bad-input", what + " must be a plain DER " + pemLabel + " (a tagged alternative is not permitted) or a PEM block");
      der = decoded;
    }
  } else if (typeof v === "string") {
    var d2 = pkix.pemDecodeLenient(v, pemLabel);
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
  return Promise.resolve().then(function () {
    if (opts.signedAttributes === false) return null;
    return _digest(scheme.digest, targetSigOctets).then(function (md) {
      var pairs = [{ type: O("messageDigest"), values: [b.octetString(md)] }];
      if (opts.signingTime !== false) pairs.push({ type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
      var extra = _resolveAttrPairs(opts.additionalSignedAttributes, "a countersignature signed attribute value");
      extra.forEach(function (p) { if (p.type === O("contentType")) throw _err("cms/bad-input", "a countersignature must not carry a content-type attribute (RFC 5652 sec. 11.4)"); });
      return _buildSignedAttrs(pairs.concat(extra));
    });
  }).then(function (attrs) {
    return signScheme.signOverTbs(scheme, soKey, attrs ? attrs.setOf : targetSigOctets, _signE).then(function (sig) {
      var fields = [b.integer(BigInt(sidv.version)), sidv.sid, scheme.digestAlgId];
      if (attrs) fields.push(attrs.wire);
      fields.push(scheme.sigAlgId, b.octetString(sig));
      return { value: b.sequence(fields), certDer: certDer };
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
  var list = Array.isArray(signers) ? signers : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.countersign requires at least one countersigner");
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");
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
  return Promise.all(jobs.map(function (j) { return j.p; })).then(function (built) {
    var byTarget = {}, certDers = [];
    built.forEach(function (res, i) { (byTarget[jobs[i].t] = byTarget[jobs[i].t] || []).push(res.value); certDers.push(res.certDer); });

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
    var allCerts = _dedupe(existing).sort(Buffer.compare);

    var newSdFields = [sdKids[0].bytes, sdKids[1].bytes, sdKids[2].bytes];
    if (allCerts.length) newSdFields.push(b.contextConstructed(0, Buffer.concat(allCerts)));
    if (crlsNode) newSdFields.push(crlsNode.bytes);
    newSdFields.push(newSiSet);
    var newCi = b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(newSdFields))]);
    return opts.pem ? pkix.pemEncode(newCi, "CMS", frameworkError.PemError) : newCi;
  });
}

module.exports = {
  sign: sign, countersign: countersign, certsOnly: certsOnly,
  // @internal
  KNOWN_SIGNER_CERT_KEYS: KNOWN_SIGNER_CERT_KEYS,
  KNOWN_SIGNER_KEY_ONLY_KEYS: KNOWN_SIGNER_KEY_ONLY_KEYS,
};
