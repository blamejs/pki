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


// The raw issuer Name TLV from a parsed certificate (byte-identical to the cert, so the sid the
// verifier canonically compares matches exactly). The issuer is the Name after the optional
// version [0] and the serial + signature AlgorithmIdentifier in the tbsCertificate.
function _issuerBytes(cert) {
  var tbs = asn1.decode(cert.tbsBytes);
  var hasVersion = tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0;
  return tbs.children[hasVersion ? 3 : 2].bytes;
}
// The cert's subjectKeyIdentifier extension value (the raw key id), or throws.
function _skiValue(cert) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (!ext) throw _err("cms/no-ski", "a subjectKeyIdentifier signer identifier requires the signer certificate to carry an SKI extension");
  try { return asn1.read.octetString(asn1.decode(ext.value)); }
  catch (e) { throw _err("cms/no-ski", "the signer certificate's subjectKeyIdentifier extension value is not an OCTET STRING", e); }
}


// Build one SignerInfo (RFC 5652 sec. 5.3) and sign it. Resolves the SignerInfo (as a build
// node) plus its digestAlgorithm AlgorithmIdentifier and the signer certificate DER (for the
// SignedData digestAlgorithms + certificates sets).
function _buildSignerInfo(signer, content, eContentType, opts) {
  var so = signer || {};
  var certDer = _normCertDer(so.cert);
  var cert = x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var useSki = opts.sid === "ski";
  var sid = useSki
    ? b.contextPrimitive(0, _skiValue(cert))                                       // [0] IMPLICIT SubjectKeyIdentifier
    : b.sequence([b.raw(_issuerBytes(cert)), b.integer(cert.serialNumber)]);        // IssuerAndSerialNumber
  var version = useSki ? 3 : 1;

  return Promise.resolve().then(function () {
    if (opts.signedAttributes === false) return content;   // sign the content directly (no signed attributes)
    // Signed attributes (RFC 5652 sec. 5.3): content-type == eContentType, message-digest ==
    // digest(content), and (by default) signing-time. build.set canonical-DER SET-OF-sorts them.
    // Each attribute type appears AT MOST ONCE across the whole set (RFC 5652 sec. 5.3);
    // `seenTypes` catches a caller-supplied attribute that duplicates a built-in or another.
    var seenTypes = {};
    function _pushAttr(typeOid, values) {
      if (seenTypes[typeOid]) throw _err("cms/bad-input", "signedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + typeOid);
      seenTypes[typeOid] = 1;
      attrs.push(b.sequence([b.oid(typeOid), b.set(values)]));
    }
    var attrs = [];
    _pushAttr(O("contentType"), [b.oid(eContentType)]);
    _pushAttr(O("messageDigest"), [b.octetString(_digest(scheme.digest, content))]);
    if (opts.signingTime !== false) _pushAttr(O("signingTime"), [_timeValue(opts.signingTime)]);
    // Caller-supplied signed attributes (e.g. an RFC 3161 signing-certificate attribute): each
    // { type: <OID name or dotted string>, values: [<DER value Buffer>] }. build.set sorts them in.
    (opts.additionalSignedAttributes || []).forEach(function (a) {
      var vals = (a.values || []).map(function (v) { return _toBuf(v, "a signed attribute value"); });
      if (!vals.length) throw _err("cms/bad-input", "a signed attribute must carry at least one value (RFC 5652 -- Attribute values is SET SIZE (1..MAX))");
      _pushAttr(/^\d+(\.\d+)+$/.test(a.type) ? a.type : O(a.type), vals);
    });
    var setOf = b.set(attrs);   // SET OF (tag 0x31) -- the exact bytes the signature covers (sec. 5.4)
    var wire = Buffer.from(setOf); wire[0] = 0xA0;   // the on-wire [0] IMPLICIT tag
    return { setOf: setOf, wire: wire };
  }).then(function (toSign) {
    var signedBytes = toSign.setOf ? toSign.setOf : toSign;   // SET-OF form for signing (sec. 5.4)
    return signScheme.signOverTbs(scheme, so.key, signedBytes, _signE).then(function (sig) {
      var fields = [b.integer(BigInt(version)), sid, scheme.digestAlgId];
      if (toSign.wire) fields.push(toSign.wire);              // [0] IMPLICIT signedAttrs
      fields.push(scheme.sigAlgId, b.octetString(sig));
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
  if (opts.signingTime != null && opts.signingTime !== false && (!(opts.signingTime instanceof Date) || isNaN(opts.signingTime.getTime()))) {
    throw _err("cms/bad-input", "signingTime must be a valid Date, or false to omit it");
  }

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

// Coverage residual -- three defensive branches are unreachable through the shipped path:
//   * `_skiValue`'s `cert.extensions || []` fallback -- x509.parse always surfaces `extensions`
//     as an array (empty when absent), so the `|| []` never fires.
//   * `_assertKeyMatchesScheme`'s `key.algorithm || {}` -- a WebCrypto CryptoKey always carries
//     an `algorithm`, so the `|| {}` fallback never fires.
//   * `_assertKeyMatchesScheme`'s `!ka.hash` guard -- an `imp.hash` is set only for an RSA
//     scheme, which requires `ka.name` to already equal the RSA name (else the earlier name
//     check throws); an RSA CryptoKey always carries a `hash`, so `!ka.hash` never fires.
module.exports = { sign: sign };
