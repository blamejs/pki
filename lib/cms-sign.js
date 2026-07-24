// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cms.sign implementation. So the pki.cms namespace has ONE @module home,
// the operator-facing @module pki.cms + the @primitive pki.cms.sign documentation block live in
// cms-verify.js, which re-exports this sign function.
//
// CMS SignedData signing (RFC 5652 sec. 5), the producing side of pki.cms.verify: composes the
// strict asn1 build layer (canonical DER, and build.set SET-OF-sorts the signed attributes for
// free), the WebCrypto sign surface over node:crypto, and the shared validator.sig.rawToEcdsaDer
// DER-ECDSA home -- emitting exactly the shapes cms.verify checks (NULL params for RSA, absent
// for ECDSA/EdDSA, the RSASSA-PSS params SEQUENCE), with the sign->verify round-trip (and OpenSSL
// cms -verify) as the guard.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var frameworkError = require("./framework-error");

var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var pkiBuild = require("./pki-build");
var cms = require("./schema-cms");
var CmsError = frameworkError.CmsError;
var b = asn1.build;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
// The domain error factory the shared sign-scheme resolver/signer throws through (kind ->
// cms/<kind>), so its faults keep the cms/* codes.
function _signE(kind, message, cause) { return new CmsError("cms/" + kind, message, cause); }
function O(name) { return oid.byName(name); }

var NODE_DIGEST = { sha256: "sha256", sha384: "sha384", sha512: "sha512", shake128: "shake128", shake256: "shake256" };
var SHAKE_OUT = { shake128: 32, shake256: 64 };   // SHAKE output lengths: SHAKE128 256-bit (RFC 9814 sec. 4), SHAKE256 512-bit (RFC 8419 sec. 2.3 / RFC 9814)

var OID_DATA = O("data");
var OID_SIGNED_DATA = O("signedData");
var OID_SKI = O("subjectKeyIdentifier");


// The message digest of the content under the digest algorithm (SHA-2 or SHAKE256).
function _digest(digestName, content) {
  var h = SHAKE_OUT[digestName]
    ? nodeCrypto.createHash(NODE_DIGEST[digestName], { outputLength: SHAKE_OUT[digestName] })
    : nodeCrypto.createHash(NODE_DIGEST[digestName]);
  return h.update(content).digest();
}


// The cert's subjectKeyIdentifier extension value (the raw key id), or throws.
function _skiValue(cert) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (!ext) throw _err("cms/no-ski", "a subjectKeyIdentifier signer identifier requires the signer certificate to carry an SKI extension");
  try { return asn1.read.octetString(asn1.decode(ext.value)); }
  catch (e) { throw _err("cms/no-ski", "the signer certificate's subjectKeyIdentifier extension value is not an OCTET STRING", e); }
}


// The SignerInfo SignerIdentifier + its coupled CMSVersion (RFC 5652 sec. 5.3): a [0] IMPLICIT
// subjectKeyIdentifier => version 3, else an IssuerAndSerialNumber => version 1. Shared by the
// top-level signer and the sec. 11.4 countersignature (a countersignature IS a SignerInfo).
function _buildSid(cert, useSki) {
  var sid = useSki
    ? b.contextPrimitive(0, _skiValue(cert))                                       // [0] IMPLICIT SubjectKeyIdentifier
    : b.sequence([b.raw(pkiBuild.tbsNameField(cert, "issuer")), b.integer(cert.serialNumber)]);   // IssuerAndSerialNumber
  return { sid: sid, version: useSki ? 3 : 1 };
}

// Assemble a SignedAttributes SET from resolved attribute pairs (each { type: <dotted OID>, values:
// [<build node or DER Buffer>] }), returning { setOf, wire }: `setOf` is the canonical DER SET OF
// (tag 0x31, build.set SET-OF-sorts) the signature covers (RFC 5652 sec. 5.4); `wire` is the same
// bytes with the on-wire [0] IMPLICIT tag (0xA0). Each attribute type appears AT MOST ONCE (sec.
// 5.3) -- a duplicate throws. Shared by the top-level signer (content-type + message-digest +
// signing-time + caller attrs) and the countersignature builder (message-digest over the target
// signature octets + signing-time, content-type OMITTED per sec. 11.4).
function _buildSignedAttrs(pairs) {
  var seenTypes = {};
  var attrs = pairs.map(function (p) {
    if (seenTypes[p.type]) throw _err("cms/bad-input", "signedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + p.type);
    seenTypes[p.type] = 1;
    return b.sequence([b.oid(p.type), b.set(p.values)]);
  });
  var setOf = b.set(attrs);   // SET OF (tag 0x31) -- the exact bytes the signature covers (sec. 5.4)
  var wire = Buffer.from(setOf); wire[0] = 0xA0;   // the on-wire [0] IMPLICIT tag
  return { setOf: setOf, wire: wire };
}

// Resolve caller-supplied additional signed attributes ({ type: OID name or dotted, values: [DER] })
// into the pair shape _buildSignedAttrs consumes; each MUST carry >= 1 value (Attribute values is
// SET SIZE (1..MAX)).
function _resolveAttrPairs(list, what) {
  return (list || []).map(function (a) {
    var vals = (a.values || []).map(function (v) { return _toBuf(v, what); });
    if (!vals.length) throw _err("cms/bad-input", "a signed attribute must carry at least one value (RFC 5652 -- Attribute values is SET SIZE (1..MAX))");
    return { type: /^\d+(\.\d+)+$/.test(a.type) ? a.type : O(a.type), values: vals };
  });
}

// content-type / message-digest / signing-time are content-binding SIGNED attributes and MUST NOT
// appear as unsigned attributes (RFC 5652 sec. 11.1/11.2/11.3 -- the parser's ATTR_FORBIDDEN_IN).
var UNSIGNED_FORBIDDEN = {};
UNSIGNED_FORBIDDEN[O("contentType")] = "content-type";
UNSIGNED_FORBIDDEN[O("messageDigest")] = "message-digest";
UNSIGNED_FORBIDDEN[O("signingTime")] = "signing-time";

// Build the [1] IMPLICIT unsignedAttrs SET OF (on-wire tag 0xA1) from opts.unsignedAttributes
// (each { type, values: [DER] } -- a countersignature, an RFC 3161 timestamp token), or null when
// absent/empty. Unsigned attributes are OUTSIDE the signature; a placement-forbidden type or a
// duplicate type (RFC 5652 sec. 11 / sec. 5.3) is a config-time cms/bad-input.
function _buildUnsignedAttrs(list) {
  if (list == null) return null;
  if (!Array.isArray(list)) throw _err("cms/bad-input", "opts.unsignedAttributes must be an array of { type, values }");
  if (!list.length) return null;
  var pairs = _resolveAttrPairs(list, "an unsigned attribute value");
  var seen = {};
  pairs.forEach(function (p) {
    if (UNSIGNED_FORBIDDEN[p.type]) throw _err("cms/bad-input", "the " + UNSIGNED_FORBIDDEN[p.type] + " attribute must not appear as an unsigned attribute (RFC 5652 sec. 11)");
    if (seen[p.type]) throw _err("cms/bad-input", "unsignedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + p.type);
    seen[p.type] = 1;
  });
  var setOf = b.set(pairs.map(function (p) { return b.sequence([b.oid(p.type), b.set(p.values)]); }));
  var wire = Buffer.from(setOf); wire[0] = 0xA1;   // SET OF -> [1] IMPLICIT UnsignedAttributes
  return wire;
}

// Build one SignerInfo (RFC 5652 sec. 5.3) and sign it. Resolves the SignerInfo (as a build
// node) plus its digestAlgorithm AlgorithmIdentifier and the signer certificate DER (for the
// SignedData digestAlgorithms + certificates sets).
function _buildSignerInfo(signer, content, eContentType, opts) {
  var so = signer || {};
  var certDer = _normCertDer(so.cert);
  var cert = x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var sidv = _buildSid(cert, opts.sid === "ski");
  var sid = sidv.sid, version = sidv.version;

  return Promise.resolve().then(function () {
    if (opts.signedAttributes === false) return content;   // sign the content directly (no signed attributes)
    // Signed attributes (RFC 5652 sec. 5.3): content-type == eContentType, message-digest ==
    // digest(content), and (by default) signing-time, plus any caller-supplied attribute.
    var pairs = [
      { type: O("contentType"), values: [b.oid(eContentType)] },
      { type: O("messageDigest"), values: [b.octetString(_digest(scheme.digest, content))] },
    ];
    if (opts.signingTime !== false) pairs.push({ type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
    pairs = pairs.concat(_resolveAttrPairs(opts.additionalSignedAttributes, "a signed attribute value"));
    return _buildSignedAttrs(pairs);
  }).then(function (toSign) {
    var signedBytes = toSign.setOf ? toSign.setOf : toSign;   // SET-OF form for signing (sec. 5.4)
    return signScheme.signOverTbs(scheme, so.key, signedBytes, _signE).then(function (sig) {
      var fields = [b.integer(BigInt(version)), sid, scheme.digestAlgId];
      if (toSign.wire) fields.push(toSign.wire);              // [0] IMPLICIT signedAttrs
      fields.push(scheme.sigAlgId, b.octetString(sig));
      var ua = _buildUnsignedAttrs(opts.unsignedAttributes);
      if (ua) fields.push(ua);                                 // [1] IMPLICIT unsignedAttrs
      return { si: b.sequence(fields), digestAlgId: scheme.digestAlgId, version: version, certDer: certDer };
    });
  });
}



// A signing-time Time value: UTCTime before 2050, GeneralizedTime from 2050 (RFC 5652 sec. 11.3 /
// RFC 5280 sec. 4.1.2.5). A caller Date overrides; false omits the attribute (handled above).
function _timeValue(when) {
  var d = (when instanceof Date) ? when : new Date();
  return d.getUTCFullYear() < 2050 ? b.utcTime(d) : b.generalizedTime(d);
}

// Normalize a signer certificate input to its raw DER (DER Buffer / PEM string / Uint8Array).
// The same bytes drive scheme resolution and the certificates [0] embedding, so a parsed
// certificate (which does not retain its full DER) is rejected -- pass DER or PEM.
function _normCertDer(c) {
  if (c == null) throw _err("cms/bad-input", "each signer requires a certificate (cert)");
  if (c instanceof Uint8Array && !Buffer.isBuffer(c)) c = Buffer.from(c);   // a Uint8Array -> Buffer (below)
  if (Buffer.isBuffer(c)) return c[0] === 0x30 ? c : _pemToDer(c.toString("latin1"));   // DER as-is, else PEM
  if (typeof c === "string") return _pemToDer(c);
  throw _err("cms/bad-input", "a signer certificate must be a DER Buffer or a PEM string");
}
function _pemToDer(text) {
  var m = text.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!m) throw _err("cms/bad-input", "a signer certificate PEM is not a CERTIFICATE block");
  return Buffer.from(m[1].replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
}

// pki.cms.sign -- documented by the @primitive block in cms-verify.js (the @module pki.cms home).
function sign(content, signers, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("cms/bad-input", "pki.cms.sign options must be an object");
  var contentBuf = _toBuf(content, "content");
  var list = Array.isArray(signers) ? signers : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.sign requires at least one signer");
  var eContentType = opts.eContentType ? O(opts.eContentType) : OID_DATA;
  // RFC 5652 sec. 5.3: signed attributes MUST be present (carrying a content-type attribute)
  // whenever the encapsulated content type is not id-data -- so signedAttributes:false is only
  // valid for id-data content. Refusing it here keeps cms.sign from emitting a non-conformant
  // SignedData (e.g. a timestamp token, id-ct-TSTInfo, with no signed attributes).
  if (opts.signedAttributes === false && eContentType !== OID_DATA) {
    throw _err("cms/bad-input", "signed attributes are required when eContentType is not id-data (RFC 5652 sec. 5.3)");
  }
  // A supplied signing-time MUST be a valid Date (or false to omit the attribute) -- never a
  // silently-ignored non-Date or an Invalid Date that would encode a garbage Time.
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");

  return Promise.all(list.map(function (s) { return _buildSignerInfo(s, contentBuf, eContentType, opts); })).then(function (built) {
    // digestAlgorithms: the distinct SignerInfo digestAlgorithm AlgorithmIdentifiers, deduped.
    var seen = {}, digestAlgs = [];
    built.forEach(function (x) { var k = x.digestAlgId.toString("hex"); if (!seen[k]) { seen[k] = 1; digestAlgs.push(x.digestAlgId); } });
    // CMSVersion (RFC 5652 sec. 5.1): 3 if any SignerInfo is v3 (ski) or eContentType != id-data;
    // otherwise 1 (v1 emits only X.509 certificates, so the v4/v5 attribute-certificate cases
    // do not arise).
    var v3 = built.some(function (x) { return x.version === 3; }) || eContentType !== OID_DATA;
    var version = v3 ? 3 : 1;
    // EncapsulatedContentInfo: eContentType + [0] EXPLICIT eContent (omitted when detached).
    var encapFields = [b.oid(eContentType)];
    if (!opts.detached) encapFields.push(b.explicit(0, b.octetString(contentBuf)));
    var encap = b.sequence(encapFields);
    // certificates [0] IMPLICIT SET OF (the signer certs), deduped + SET-OF-ordered, when embedded.
    var sdFields = [b.integer(BigInt(version)), b.set(digestAlgs), encap];
    if (opts.certificates !== false) {
      var certDers = _dedupe(built.map(function (x) { return x.certDer; })).sort(Buffer.compare);   // X.690 sec. 11.6
      sdFields.push(b.contextConstructed(0, Buffer.concat(certDers)));              // [0] IMPLICIT SET OF
    }
    sdFields.push(b.set(built.map(function (x) { return x.si; })));                 // signerInfos SET OF
    var signedData = b.sequence(sdFields);
    var contentInfo = b.sequence([b.oid(OID_SIGNED_DATA), b.explicit(0, signedData)]);   // ContentInfo
    return opts.pem ? pkix.pemEncode(contentInfo, "CMS", frameworkError.PemError) : contentInfo;
  });
}

// Dedupe certificate DERs (two signers may share a cert -- embed it once).
function _dedupe(ders) {
  var seen = {}, out = [];
  ders.forEach(function (d) { var k = d.toString("hex"); if (!seen[k]) { seen[k] = 1; out.push(d); } });
  return out;
}

function _toBuf(v, what) {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  throw _err("cms/bad-input", what + " must be a Buffer");
}

// ---- pki.cms.countersign (RFC 5652 sec. 11.4) ------------------------------
// A countersignature is a SignerInfo (Countersignature ::= SignerInfo) over the CONTENTS of the
// countersigned SignerInfo's signature OCTET STRING -- NOT the eContent -- attached as the
// id-countersignature unsigned attribute. It reuses the whole build+sign flow (resolveSignScheme /
// _buildSid / _buildSignedAttrs / signOverTbs); only the preimage (the target signature octets) and
// the content-type OMISSION are the deltas, and the orchestrator splices the [1] unsignedAttrs into
// an existing SignedData while preserving the targeted SignerInfo's signed bytes BYTE-FOR-BYTE.

// Resolve opts.signerIndex (a number, an array of numbers, or "all"; default 0) to primary indices.
function _resolveSignerIndices(spec, n) {
  if (spec == null) { if (n < 1) throw _err("cms/bad-input", "the SignedData carries no SignerInfo to countersign"); return [0]; }
  if (spec === "all") { var all = []; for (var i = 0; i < n; i++) all.push(i); return all; }
  var arr = Array.isArray(spec) ? spec : [spec];
  if (!arr.length) throw _err("cms/bad-input", "signerIndex must select at least one signer");
  arr.forEach(function (i) { if (typeof i !== "number" || !Number.isInteger(i) || i < 0 || i >= n) throw _err("cms/bad-input", "signerIndex out of range: " + i); });
  return arr;
}

// Build one countersignature value (RFC 5652 sec. 11.4) over `targetSigOctets`: message-digest bound
// to digest(targetSigOctets) under the countersignature's own digestAlgorithm, content-type OMITTED,
// signed through the SAME per-algorithm scheme machinery as a top-level signer.
function _buildCountersignature(targetSigOctets, countersigner, opts) {
  var so = countersigner || {};
  var certDer = _normCertDer(so.cert);
  var cert = x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var sidv = _buildSid(cert, opts.sid === "ski");
  return Promise.resolve().then(function () {
    if (opts.signedAttributes === false) return null;   // sign the target signature octets directly
    var pairs = [{ type: O("messageDigest"), values: [b.octetString(_digest(scheme.digest, targetSigOctets))] }];
    if (opts.signingTime !== false) pairs.push({ type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
    var extra = _resolveAttrPairs(opts.additionalSignedAttributes, "a countersignature signed attribute value");
    extra.forEach(function (p) { if (p.type === O("contentType")) throw _err("cms/bad-input", "a countersignature must not carry a content-type attribute (RFC 5652 sec. 11.4)"); });
    return _buildSignedAttrs(pairs.concat(extra));
  }).then(function (attrs) {
    return signScheme.signOverTbs(scheme, so.key, attrs ? attrs.setOf : targetSigOctets, _signE).then(function (sig) {
      var fields = [b.integer(BigInt(sidv.version)), sidv.sid, scheme.digestAlgId];
      if (attrs) fields.push(attrs.wire);          // [0] IMPLICIT signedAttrs
      fields.push(scheme.sigAlgId, b.octetString(sig));
      return { value: b.sequence(fields), certDer: certDer };
    });
  });
}

// Build the [1] IMPLICIT unsignedAttrs bytes for a SignerInfo, merging `newCsValues` into the ONE
// id-countersignature attribute (RFC 5652 sec. 11: single instance per type, MULTIPLE values), and
// keeping every OTHER unsigned attribute and every EXISTING countersignature value verbatim.
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
  var wire = Buffer.from(setOf); wire[0] = 0xA1;   // SET OF -> [1] IMPLICIT UnsignedAttributes
  return wire;
}

// Append countersignature values to a SignerInfo node, preserving version / sid / digestAlgorithm /
// signedAttrs / signatureAlgorithm / signature BYTE-FOR-BYTE (the signed preimage), only adding the
// [1] unsignedAttrs. Returns the new SignerInfo bytes.
function _appendCountersigs(siNode, newCsValues) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var hasUa = last.tagClass === "context" && last.tagNumber === 1;
  var base = (hasUa ? kids.slice(0, kids.length - 1) : kids).map(function (k) { return k.bytes; });
  base.push(_mergeCountersig(hasUa ? last : null, newCsValues));
  return b.sequence(base);
}

// Splice countersignature values into the j-th countersignature VALUE of a SignerInfo node (nested
// countersignature, RFC 5652 sec. 11.4). Returns the new SignerInfo bytes.
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

// The signature-value octets of a SignerInfo node: the last universal OCTET STRING, i.e. the last
// child unless a [1] IMPLICIT unsignedAttrs (a prior countersignature) follows it.
function _signatureOctets(siNode) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var sigNode = (last.tagClass === "context" && last.tagNumber === 1) ? kids[kids.length - 2] : last;
  return asn1.read.octetString(sigNode);
}

// The sec. 11.4 preimage for a target: the primary SignerInfo's signature octets, or (nested) the
// j-th countersignature value's signature octets.
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
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("cms/bad-input", "pki.cms.countersign options must be an object");
  var list = Array.isArray(signers) ? signers : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.countersign requires at least one countersigner");
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");
  var der = pkix.coerceToDer(cmsInput, { pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CmsError, prefix: "cms" });
  // cms.parse throws a typed cms/* error on a malformed input (mirroring verify's own parse call); a
  // structurally-valid but non-SignedData CMS (an EnvelopedData) parses without a signerInfos array.
  var parsed = cms.parse(der);
  if (!Array.isArray(parsed.signerInfos)) throw _err("cms/bad-input", "pki.cms.countersign input is not a CMS SignedData");
  var targets = _resolveSignerIndices(opts.signerIndex, parsed.signerInfos.length);
  var root = asn1.decode(der);
  var sd = root.children[1].children[0];
  var sdKids = sd.children;
  var siSet = sdKids[sdKids.length - 1];

  // Build every countersignature value (target x countersigner), then splice into the node tree.
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

    // Rebuild SignedData: version, digestAlgorithms (UNCHANGED -- a countersignature digest is not a
    // SignedData digestAlgorithm), encapContentInfo, certificates [0]?, crls [1]?, the new signerInfos.
    var certsNode = null, crlsNode = null;
    for (var i = 3; i < sdKids.length - 1; i++) {
      if (sdKids[i].tagClass === "context" && sdKids[i].tagNumber === 0) certsNode = sdKids[i];
      else if (sdKids[i].tagClass === "context" && sdKids[i].tagNumber === 1) crlsNode = sdKids[i];
    }
    var existing = [];
    if (certsNode) certsNode.children.forEach(function (c) { existing.push(c.bytes); });
    if (opts.certificates !== false) certDers.forEach(function (d) { existing.push(d); });
    var allCerts = _dedupe(existing).sort(Buffer.compare);   // X.690 sec. 11.6

    var newSdFields = [sdKids[0].bytes, sdKids[1].bytes, sdKids[2].bytes];   // version, digestAlgs, encap (raw)
    if (allCerts.length) newSdFields.push(b.contextConstructed(0, Buffer.concat(allCerts)));
    if (crlsNode) newSdFields.push(crlsNode.bytes);
    newSdFields.push(newSiSet);
    var newCi = b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(newSdFields))]);
    return opts.pem ? pkix.pemEncode(newCi, "CMS", frameworkError.PemError) : newCi;
  });
}

// Coverage residual -- three defensive branches are unreachable through the shipped path:
//   * `_skiValue`'s `cert.extensions || []` fallback -- x509.parse always surfaces `extensions`
//     as an array (empty when absent), so the `|| []` never fires.
//   * `_assertKeyMatchesScheme`'s `key.algorithm || {}` -- a WebCrypto CryptoKey always carries
//     an `algorithm`, so the `|| {}` fallback never fires.
//   * `_assertKeyMatchesScheme`'s `!ka.hash` guard -- an `imp.hash` is set only for an RSA
//     scheme, which requires `ka.name` to already equal the RSA name (else the earlier name
//     check throws); an RSA CryptoKey always carries a `hash`, so `!ka.hash` never fires.
// Countersign-side residuals also unreachable through the shipped path:
//   * `_resolveSignerIndices`'s `n < 1` throw -- a parsed SignedData always carries at least one
//     SignerInfo, so the default index [0] is always in range.
//   * `_spliceNested`'s no-countersignature / index-out-of-range / not-found throws -- the same node
//     is validated by `_targetPreimage` FIRST (it computes the nested preimage before the build), so
//     by the time `_spliceNested` re-walks it those conditions cannot hold; the checks are
//     belt-and-suspenders against a future caller reordering the two.
//   * the `crls [1]` preservation branches in `countersign` -- pki.cms.sign never emits a crls field,
//     so a store this producer countersigns never carries one to preserve.
module.exports = { sign: sign, countersign: countersign };
