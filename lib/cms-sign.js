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
var pkcs8 = require("./schema-pkcs8");
var pkix = require("./schema-pkix");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var validator = require("./validator-all");
var frameworkError = require("./framework-error");

var CmsError = frameworkError.CmsError;
var b = asn1.build;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
function O(name) { return oid.byName(name); }

// A digest-algorithm name -> the WebCrypto hash (sign path). SHAKE256 has no WebCrypto hash, so
// the message digest is always computed with node:crypto (below), uniform across the family.
var HASH = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
var NODE_DIGEST = { sha256: "sha256", sha384: "sha384", sha512: "sha512", shake256: "shake256" };
var SHAKE_OUT = { shake256: 64 };   // RFC 8419 sec. 2.3 -- Ed448 uses SHAKE256 with 512-bit output
var PSS_SALT = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };
var ECDSA_ALG = { sha256: "ecdsaWithSHA256", sha384: "ecdsaWithSHA384", sha512: "ecdsaWithSHA512" };
var EC_BY_CURVE_OID = {};
EC_BY_CURVE_OID[O("prime256v1")] = { curve: "P-256", coordLen: 32 };
EC_BY_CURVE_OID[O("secp384r1")] = { curve: "P-384", coordLen: 48 };
EC_BY_CURVE_OID[O("secp521r1")] = { curve: "P-521", coordLen: 66 };

var OID_DATA = O("data");
var OID_SIGNED_DATA = O("signedData");
var OID_SKI = O("subjectKeyIdentifier");

// An AlgorithmIdentifier { OID } (absent parameters) or { OID, NULL }.
function _algId(name, shape) { return shape === "null" ? b.sequence([b.oid(O(name)), b.nullValue()]) : b.sequence([b.oid(O(name))]); }
// The RSASSA-PSS AlgorithmIdentifier with the params SEQUENCE cms.verify's _resolvePss accepts:
// an explicit SHA-2 hashAlgorithm, MGF1 keyed to the same hash, the hash-length saltLength, and
// the default trailerField (omitted). RFC 4055.
function _pssAlgId(digestName) {
  var hashAlg = b.sequence([b.oid(O(digestName)), b.nullValue()]);
  var mgf = b.sequence([b.oid(O("mgf1")), hashAlg]);
  var params = b.sequence([b.explicit(0, hashAlg), b.explicit(1, mgf), b.explicit(2, b.integer(BigInt(PSS_SALT[HASH[digestName]])))]);
  return b.sequence([b.oid(O("rsassaPss")), params]);
}

// The message digest of the content under the digest algorithm (SHA-2 or SHAKE256).
function _digest(digestName, content) {
  var h = SHAKE_OUT[digestName]
    ? nodeCrypto.createHash(NODE_DIGEST[digestName], { outputLength: SHAKE_OUT[digestName] })
    : nodeCrypto.createHash(NODE_DIGEST[digestName]);
  return h.update(content).digest();
}

// Resolve the sign scheme from the signer certificate's public-key algorithm + per-signer opts:
// the digest, the digestAlgorithm and signatureAlgorithm AlgorithmIdentifiers (with the exact
// parameter shape cms.verify requires), and the WebCrypto import + sign algorithms.
function _scheme(cert, so) {
  var alg = cert.subjectPublicKeyInfo.algorithm;
  var keyOid = alg.oid;
  if (keyOid === O("rsaEncryption") || keyOid === O("rsassaPss")) {
    var d = so.digestAlgorithm || "sha256";
    if (!HASH[d]) throw _err("cms/unsupported-algorithm", "unsupported RSA digest algorithm " + JSON.stringify(d));
    // An id-RSASSA-PSS signer key is restricted to RSASSA-PSS (RFC 4055 sec. 1.2); a general
    // rsaEncryption key signs PKCS#1 v1.5 by default, or RSASSA-PSS when opts.pss is set.
    if (so.pss || keyOid === O("rsassaPss")) return { digest: d, digestAlgId: _algId(d, "absent"), sigAlgId: _pssAlgId(d), imp: { name: "RSA-PSS", hash: HASH[d] }, sign: { name: "RSA-PSS", saltLength: PSS_SALT[HASH[d]] }, ecdsaDer: false };
    return { digest: d, digestAlgId: _algId(d, "absent"), sigAlgId: _algId("rsaEncryption", "null"), imp: { name: "RSASSA-PKCS1-v1_5", hash: HASH[d] }, sign: { name: "RSASSA-PKCS1-v1_5" }, ecdsaDer: false };
  }
  if (keyOid === O("ecPublicKey")) {
    var curveOid;
    try { curveOid = asn1.read.oid(asn1.decode(alg.parameters)); }
    catch (e) { throw _err("cms/unsupported-algorithm", "the signer EC key parameters are not a named-curve OID", e); }
    var ec = EC_BY_CURVE_OID[curveOid];
    if (!ec) throw _err("cms/unsupported-algorithm", "the signer key is on an unsupported EC curve");
    var de = so.digestAlgorithm || "sha256";
    if (!HASH[de]) throw _err("cms/unsupported-algorithm", "unsupported ECDSA digest algorithm " + JSON.stringify(de));
    return { digest: de, digestAlgId: _algId(de, "absent"), sigAlgId: _algId(ECDSA_ALG[de], "absent"), imp: { name: "ECDSA", namedCurve: ec.curve }, sign: { name: "ECDSA", hash: HASH[de] }, ecdsaDer: true, coordLen: ec.coordLen };
  }
  if (keyOid === O("Ed25519") || keyOid === O("Ed448")) {
    var name = keyOid === O("Ed25519") ? "Ed25519" : "Ed448";
    var dd = so.digestAlgorithm || (name === "Ed25519" ? "sha512" : "shake256");
    if (!NODE_DIGEST[dd]) throw _err("cms/unsupported-algorithm", "unsupported " + name + " digest algorithm " + JSON.stringify(dd));
    return { digest: dd, digestAlgId: _algId(dd, "absent"), sigAlgId: _algId(name, "absent"), imp: { name: name }, sign: { name: name }, ecdsaDer: false };
  }
  throw _err("cms/unsupported-algorithm", "unsupported signer key algorithm " + keyOid);
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

// Import the signer private key: a CryptoKey passed through, or a PKCS#8 DER Buffer / PEM string.
function _importKey(key, imp) {
  if (key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type === "private") {
    return Promise.resolve(key);
  }
  var der;
  if (Buffer.isBuffer(key)) der = key;
  else if (key instanceof Uint8Array) der = Buffer.from(key);
  else if (typeof key === "string") { try { der = pkcs8.pemDecode(key); } catch (e) { throw _err("cms/bad-input", "the signer PEM private key could not be decoded", e); } }
  else throw _err("cms/bad-input", "a signer key must be a CryptoKey, a PKCS#8 DER Buffer, or a PKCS#8 PEM string");
  return subtle.importKey("pkcs8", der, imp, false, ["sign"]);
}

// Build one SignerInfo (RFC 5652 sec. 5.3) and sign it. Resolves the SignerInfo (as a build
// node) plus its digestAlgorithm AlgorithmIdentifier and the signer certificate DER (for the
// SignedData digestAlgorithms + certificates sets).
function _buildSignerInfo(signer, content, eContentType, opts) {
  var so = signer || {};
  var certDer = _normCertDer(so.cert);
  var cert = x509.parse(certDer);
  var scheme = _scheme(cert, so);
  var useSki = opts.sid === "ski";
  var sid = useSki
    ? b.contextPrimitive(0, _skiValue(cert))                                       // [0] IMPLICIT SubjectKeyIdentifier
    : b.sequence([b.raw(_issuerBytes(cert)), b.integer(cert.serialNumber)]);        // IssuerAndSerialNumber
  var version = useSki ? 3 : 1;

  return _importKey(so.key, scheme.imp).then(function (priv) {
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
      return subtle.sign(scheme.sign, priv, signedBytes).then(function (sigRaw) {
        var sig = Buffer.from(sigRaw);
        if (scheme.ecdsaDer) sig = validator.sig.rawToEcdsaDer(sig, scheme.coordLen);
        var fields = [b.integer(BigInt(version)), sid, scheme.digestAlgId];
        if (toSign.wire) fields.push(toSign.wire);              // [0] IMPLICIT signedAttrs
        fields.push(scheme.sigAlgId, b.octetString(sig));
        return { si: b.sequence(fields), digestAlgId: scheme.digestAlgId, version: version, certDer: certDer };
      });
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
  if (Buffer.isBuffer(c)) return c[0] === 0x30 ? c : _pemToDer(c.toString("latin1"));
  if (c instanceof Uint8Array) return Buffer.from(c);
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

// Coverage residual -- `_skiValue`'s `cert.extensions || []` fallback never fires: x509.parse
// always surfaces `extensions` as an array (empty when absent), so the `|| []` guard is
// belt-and-suspenders against a future caller passing a hand-built parsed shape.
module.exports = { sign: sign };
