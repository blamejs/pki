// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.x509
 * @nav        Signing
 * @title      Certificates
 * @fullname   X.509 certificates: parse, sign and inspect
 * @intro The X.509 certificate-issuance producing side. `pki.x509.sign` builds a `TBSCertificate`,
 *   signs it, and emits a `Certificate` (RFC 5280 sec. 4) that `pki.schema.x509.parse`,
 *   `pki.path.validate`, and OpenSSL all accept, self-signed or CA-signed, over any signature
 *   algorithm the toolkit registry resolves: RSA (PKCS#1 v1.5 / PSS), ECDSA, EdDSA, ML-DSA, SLH-DSA,
 *   and the composite (hybrid) arms. Parsing lives at `pki.schema.x509.parse`.
 * @spec RFC 5280
 * @card Build and sign an X.509 certificate, self-signed or CA-signed, over any registry algorithm.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray;
var frameworkError = require("./framework-error");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");

var CertificateError = frameworkError.CertificateError;
var NS = pkix.makeNS("x509", CertificateError, oid);
var NAME_SCHEMA = pkix.name(NS);
var SPKI_SCHEMA = pkix.spki(NS);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var b = asn1.build;
function _err(code, message, cause) { return new CertificateError(code, message, cause); }
function _signE(kind, message, cause) { return new CertificateError("x509/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var OID_SKI = O("subjectKeyIdentifier");

var KNOWN_SPEC_KEYS = {
  subject: 1, subjectPublicKey: 1, notBefore: 1, notAfter: 1, serialNumber: 1, extensions: 1,
};
var KNOWN_ISSUER_CERT_KEYS = { key: 1, cert: 1 };
var KNOWN_ISSUER_EXPLICIT_KEYS = { key: 1, name: 1, publicKey: 1 };
var KNOWN_SIGN_OPTS = { digestAlgorithm: 1, pem: 1, pss: 1 };

var KNOWN_EXT_KEYS = {
  subjectKeyIdentifier: 1, authorityKeyIdentifier: 1, keyUsage: 1, keyUsageCritical: 1,
  extendedKeyUsage: 1, extendedKeyUsageCritical: 1, basicConstraints: 1, subjectAltName: 1,
  certificatePolicies: 1, certificatePoliciesCritical: 1,
};

var _b = pkiBuild.makeBuilder({ ErrorClass: CertificateError, prefix: "x509", O: O, NS: NS, NAME_SCHEMA: NAME_SCHEMA, SPKI_SCHEMA: SPKI_SCHEMA, EXT_DECODERS: EXT_DECODERS });
var _encodeName = _b.encodeName, _isEmptyName = _b.isEmptyName, _reqDer = _b.reqDer,
  _assertValidSpki = _b.assertValidSpki, _assertValidExtension = _b.assertValidExtension,
  _certLikeFromSpki = _b.certLikeFromSpki, _assertCertVerifies = _b.assertSignatureVerifies,
  _ext = _b.ext, _extBasicConstraints = _b.extBasicConstraints, _validateBcSpec = _b.validateBcSpec,
  _extKeyUsage = _b.extKeyUsage, _extExtKeyUsage = _b.extExtKeyUsage, _extSki = _b.extSki,
  _extAki = _b.extAki, _extSan = _b.extSan, _extCertPolicies = _b.extCertPolicies,
  _skiKeyId = _b.skiKeyId, _spkiKeyId = _b.spkiKeyId, _serialInteger = _b.serialInteger;


function _skiValueOf(caCert) {
  var ext = (caCert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (ext) { try { return asn1.read.octetString(asn1.decode(ext.value)); } catch (_e) { } }   // allow:swallow-unverified -- a malformed CA SKI is read as absent; _akiKeyId then derives the authorityKeyIdentifier keyIdentifier from the issuer public key
  return null;
}
function _akiKeyId(val, ctx) {
  if (guard.bytes.isByteSource(val)) return guard.bytes.snapshotSource(val, CertificateError, "x509/bad-input", "the authorityKeyIdentifier keyIdentifier");
  if (val === true) {
    if (ctx.issuerCert) { var ski = _skiValueOf(ctx.issuerCert); if (ski) return ski; }
    return _spkiKeyId(ctx.issuerSpki);
  }
  throw _err("x509/bad-input", "authorityKeyIdentifier must be true (auto-derive from the issuer) or a Buffer key id");
}

function _buildExtensions(extSpec, ctx) {
  if (extSpec == null) return [];
  if (_isArray(extSpec)) {
    var seenExt = {}, arrCa = false, arrKeyCertSign = false, arrPathLen = false;
    var oidBc = O("basicConstraints"), oidKu = O("keyUsage");
    var arr = extSpec.map(function (e, i) {
      var der = _reqDer(e, "extension");
      _assertValidExtension(der, i);
      var n = asn1.decode(der);
      var extnId = asn1.read.oid(n.children[0]);
      if (seenExt[extnId]) throw _err("x509/bad-input", "duplicate extension " + extnId + " in the extensions array (RFC 5280 sec. 4.2 -- at most one instance of an extension)");
      seenExt[extnId] = true;
      var dec = EXT_DECODERS[extnId];
      if (dec) {
        var decoded;
        try { decoded = dec(asn1.read.octetString(n.children[n.children.length - 1])); }
        catch (e) {
          if (e instanceof CertificateError) throw e;
          throw _err("x509/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", e);
        }
        if (extnId === oidBc) {
          arrCa = decoded.cA === true; arrPathLen = decoded.pathLenConstraint != null;
          if (arrCa && n.children.length !== 3) throw _err("x509/bad-input", "a CA certificate's basicConstraints MUST be critical (RFC 5280 sec. 4.2.1.9)");
        }
        else if (extnId === oidKu) { arrKeyCertSign = decoded.keyCertSign === true; }
      }
      return b.raw(der);
    });
    if (arrKeyCertSign && !arrCa) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
    if (arrPathLen && (!arrCa || !arrKeyCertSign)) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE and keyUsage keyCertSign (RFC 5280 sec. 4.2.1.9)");
    return arr;
  }
  if (typeof extSpec !== "object") throw _err("x509/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  guard.identifier.assertKnownKeys(extSpec, KNOWN_EXT_KEYS, _err, "x509/bad-input", function (k) {
    return "unknown extension " + JSON.stringify(k) + " in the extensions spec; pass a pre-encoded Extension DER via the array form for a custom extension";
  });

  var bc = extSpec.basicConstraints;
  if (bc != null) _validateBcSpec(bc);
  var caTrue = !!(bc && bc.cA === true);
  var ku = extSpec.keyUsage;
  var assertsKeyCertSign = _isArray(ku) && ku.indexOf("keyCertSign") >= 0;
  if (assertsKeyCertSign && !caTrue) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
  if (bc && bc.pathLen != null) {
    if (!caTrue) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE (RFC 5280 sec. 4.2.1.9)");
    if (!assertsKeyCertSign) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires keyUsage keyCertSign (RFC 5280 sec. 4.2.1.9)");
  }

  var out = [];
  if (extSpec.subjectKeyIdentifier != null) out.push(_ext(O("subjectKeyIdentifier"), false, _extSki(_skiKeyId(extSpec.subjectKeyIdentifier, ctx.spki))));
  if (extSpec.authorityKeyIdentifier != null) out.push(_ext(O("authorityKeyIdentifier"), false, _extAki(_akiKeyId(extSpec.authorityKeyIdentifier, ctx))));
  if (ku != null) out.push(_ext(O("keyUsage"), extSpec.keyUsageCritical !== false, _extKeyUsage(ku)));
  if (extSpec.extendedKeyUsage != null) out.push(_ext(O("extKeyUsage"), !!extSpec.extendedKeyUsageCritical, _extExtKeyUsage(extSpec.extendedKeyUsage)));
  if (bc != null) {
    if (bc.cA === true && bc.critical === false) throw _err("x509/bad-input", "a CA certificate's basicConstraints MUST be critical (RFC 5280 sec. 4.2.1.9)");
    out.push(_ext(O("basicConstraints"), bc.critical !== false, _extBasicConstraints(bc)));
  }
  if (extSpec.subjectAltName != null) out.push(_ext(O("subjectAltName"), ctx.subjectEmpty, _extSan(extSpec.subjectAltName)));
  if (extSpec.certificatePolicies != null) out.push(_ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, _extCertPolicies(extSpec.certificatePolicies)));
  return out;
}


function _timeDer(date, which) { return _b.timeDer(date, "certificate " + which); }
function _assertIssuerIsCa(issuerCert) {
  var exts = issuerCert.extensions || [];
  function ext(name) { return exts.filter(function (x) { return x.oid === O(name); })[0] || null; }
  var bcExt = ext("basicConstraints");
  if (!bcExt) throw _err("x509/bad-input", "the issuer certificate is not a CA -- it has no basicConstraints extension (RFC 5280 sec. 4.2.1.9)");
  if (bcExt.critical !== true) throw _err("x509/bad-input", "the issuer certificate basicConstraints is not marked critical (RFC 5280 sec. 4.2.1.9 requires it on a CA)");
  var bc;
  try { bc = EXT_DECODERS[O("basicConstraints")](bcExt.value); }
  catch (e) { if (e instanceof CertificateError) throw e; throw _err("x509/bad-input", "the issuer certificate basicConstraints is malformed", e); }
  if (bc.cA !== true) throw _err("x509/bad-input", "the issuer certificate is not a CA (basicConstraints cA is not TRUE)");
  var kuExt = ext("keyUsage");
  if (kuExt) {
    var ku;
    try { ku = EXT_DECODERS[O("keyUsage")](kuExt.value); }
    catch (e) { if (e instanceof CertificateError) throw e; throw _err("x509/bad-input", "the issuer certificate keyUsage is malformed", e); }
    if (ku.keyCertSign !== true) throw _err("x509/bad-input", "the issuer certificate keyUsage does not assert keyCertSign -- it cannot sign certificates (RFC 5280 sec. 4.2.1.3)");
  }
  return bc.pathLenConstraint;
}
function _issuedCaInfo(extSpec) {
  if (extSpec == null) return { cA: false, pathLen: null };
  if (!_isArray(extSpec)) {
    var bc = extSpec.basicConstraints;
    return { cA: !!(bc && bc.cA === true), pathLen: bc && bc.pathLen != null ? Number(bc.pathLen) : null };
  }
  for (var i = 0; i < extSpec.length; i++) {
    var n = asn1.decode(_reqDer(extSpec[i], "extension"));
    if (asn1.read.oid(n.children[0]) !== O("basicConstraints")) continue;
    var dec = EXT_DECODERS[O("basicConstraints")](asn1.read.octetString(n.children[n.children.length - 1]));
    return { cA: dec.cA === true, pathLen: dec.pathLenConstraint != null ? Number(dec.pathLenConstraint) : null };
  }
  return { cA: false, pathLen: null };
}
function _hasCriticalSan(extSpec) {
  if (extSpec == null) return false;
  if (!_isArray(extSpec)) return !!extSpec.subjectAltName;
  var sanOid = O("subjectAltName");
  for (var i = 0; i < extSpec.length; i++) {
    var n = asn1.decode(_reqDer(extSpec[i], "extension"));
    if (n.children.length === 3 && asn1.read.oid(n.children[0]) === sanOid && asn1.read.boolean(n.children[1]) === true) return true;
  }
  return false;
}


/**
 * @primitive pki.x509.sign
 * @signature pki.x509.sign(spec, issuer, opts?) -> Promise<Buffer|string>
 * @since 0.3.0
 * @status stable
 * @spec RFC 5280 sec. 4, RFC 9909, RFC 9814
 * @defends forged-certificate-issuance (CWE-347)
 * @related pki.schema.x509.parse, pki.path.validate, pki.cms.sign
 *
 * Build, sign, and DER-encode an X.509 certificate. `spec` describes the certificate to issue:
 * `subject` (a string CN, an array of RDNs, or raw Name DER), `subjectPublicKey` (the SPKI DER of the
 * key being certified), `notBefore` / `notAfter` (`Date`s), an optional `serialNumber`, and an optional
 * `extensions` object. `issuer` is the signing side: `{ key }` alone issues a self-signed certificate
 * (issuer = subject, signed with the subject's own key); `{ name, publicKey, key }` or `{ cert, key }`
 * issues a CA-signed one. The signing key `key` is a WebCrypto `CryptoKey` (a `pki.key.generate`
 * private key passed directly, without exporting) or a PKCS#8 private key as DER (`Buffer`) or PEM
 * (`string`); a public or secret CryptoKey, or a `node:crypto` KeyObject, is refused. A `subjectAltName`
 * (or any `GeneralName`) entry may be a form object (`{ dNSName: "..." }`) or a bare string classified
 * fail-closed into its form (`"host.example"`, `"a@b.example"`, `"10.0.0.1"`, `"https://host.example/"`).
 * The signature algorithm is resolved from the signing key: RSA (PKCS#1 v1.5
 * or PSS via `opts.pss`), ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm, so every algorithm the
 * toolkit signs with is available here without a per-algorithm branch.
 *
 * The version is derived from the field set (v3 when extensions are present, else v1). Serial bounds
 * (positive, <= 20 octets), the validity UTCTime/GeneralizedTime cutover, the DER DEFAULT omissions
 * (v1 tag, `critical=FALSE`, `cA=FALSE`), and the CA cross-field rules (keyCertSign and
 * pathLenConstraint require cA=TRUE) are all enforced; a violation throws a typed `CertificateError`.
 * Where the spec carries raw DER (a `Name` Buffer, a pre-encoded `Extension`, an issuer `publicKey`
 * SPKI), a structural fault throws `CertificateError`, while a malformed leaf inside those bytes
 * throws `Asn1Error`, the same two-error contract the parsers present.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerSpki = await pki.key.export(pair.publicKey);
 *   var root = await pki.x509.sign(
 *     { subject: "Example Root CA", subjectPublicKey: signerSpki,
 *       notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *       extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } },
 *     { key: pair.privateKey });   // a WebCrypto CryptoKey signs directly (or pass a PKCS#8 DER Buffer / PEM string)
 *   pki.schema.x509.parse(root).subject.dn;   // "CN=Example Root CA"
 */
function sign(spec, issuer, opts) {
  return guard.bytes.fixedCall(CertificateError, "x509/bad-input", [
    [spec, "the certificate spec"], [issuer, "the issuer"], [opts, "pki.x509.sign options"],
  ], _sign);
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("x509/bad-input", "the certificate spec must be an object");
  issuer = issuer || {};
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "x509/bad-input", function (k) {
    return "unknown certificate spec field " + JSON.stringify(k) +
      (k === "issuer" ? "; the issuer is the SECOND argument to pki.x509.sign, not a spec field" : "") +
      (k === "extension" ? "; the extensions spec field is `extensions`" : "");
  });
  var byCert = issuer.cert != null;
  guard.identifier.assertKnownKeys(issuer, byCert ? KNOWN_ISSUER_CERT_KEYS : KNOWN_ISSUER_EXPLICIT_KEYS,
    _err, "x509/bad-input", function (k) {
      return "unknown issuer field " + JSON.stringify(k) + " for the " + (byCert
        ? "certificate form; issuer.cert supplies the name and the public key, so they are not read here"
        : "explicit form; the issuer takes { key, name, publicKey }, or { key, cert } to take both from a certificate");
    });
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "x509/bad-input", "pki.x509.sign has an unknown option ");
  if (issuer.key == null) throw _err("x509/bad-input", "a signing key (issuer.key, a WebCrypto CryptoKey or a PKCS#8 private key DER/PEM) is required");

  var spki = _reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the certified key)");
  _assertValidSpki(spki, "spec.subjectPublicKey");
  var subjectDer = _encodeName(spec.subject == null ? [] : spec.subject);
  var subjectEmpty = _isEmptyName(subjectDer);

  var issuerDer, issuerSpki, issuerCert = null, issuerPathLen = null;
  var selfSigned = issuer.name == null && issuer.cert == null && issuer.publicKey == null;
  if (selfSigned) {
    issuerDer = subjectDer;
    issuerSpki = spki;
  } else if (issuer.cert != null) {
    issuerCert = guard.parsed.acceptDerived(issuer.cert, "certificate", x509.parse, _err, "x509/bad-input", "issuer.cert");
    issuerPathLen = _assertIssuerIsCa(issuerCert);
    issuerDer = pkiBuild.tbsNameField(issuerCert, "subject");
    issuerSpki = issuerCert.subjectPublicKeyInfo.bytes;
  } else {
    issuerDer = _encodeName(issuer.name == null ? [] : issuer.name);
    issuerSpki = _reqDer(issuer.publicKey, "issuer.publicKey (the issuer SPKI DER)");
    _assertValidSpki(issuerSpki, "issuer.publicKey");
  }
  if (_isEmptyName(issuerDer)) throw _err("x509/bad-issuer", "issuer must be a non-empty distinguished name");

  var scheme = signScheme.resolveSignScheme(_certLikeFromSpki(issuerSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var serialTlv = _serialInteger(spec.serialNumber);
  guard.time.assertValid(spec.notBefore, _err, "x509/bad-input", "notBefore");
  guard.time.assertValid(spec.notAfter, _err, "x509/bad-input", "notAfter");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd on the two lines above (an Invalid Date throws before this comparison).
  if (guard.time.instantOf(spec.notBefore) > guard.time.instantOf(spec.notAfter)) throw _err("x509/bad-input", "notBefore must not be after notAfter (RFC 5280 sec. 4.1.2.5)");
  var validityDer = b.sequence([_timeDer(spec.notBefore, "notBefore"), _timeDer(spec.notAfter, "notAfter")]);

  var extSpec = spec.extensions;
  var exts = _buildExtensions(extSpec, { spki: spki, issuerSpki: issuerSpki, issuerCert: issuerCert, subjectEmpty: subjectEmpty });
  if (subjectEmpty && !_hasCriticalSan(extSpec)) {
    throw _err("x509/bad-input", "an empty subject requires a critical subjectAltName (RFC 5280 sec. 4.1.2.6)");
  }
  if (issuerPathLen != null) {
    var issued = _issuedCaInfo(extSpec);
    var selfIssued = guard.name.dnEqual(
      schema.walk(NAME_SCHEMA, asn1.decode(subjectDer), NS).result.rdns,
      schema.walk(NAME_SCHEMA, asn1.decode(issuerDer), NS).result.rdns,
      _err, "x509/bad-input", "issuer/subject DN");
    if (issued.cA && !selfIssued) {
      if (issuerPathLen < 1) throw _err("x509/bad-input", "the issuer certificate pathLenConstraint (0) forbids issuing a non-self-issued CA certificate below it (RFC 5280 sec. 4.2.1.9)");
      if (issued.pathLen != null && issued.pathLen > issuerPathLen - 1) throw _err("x509/bad-input", "the issued CA certificate pathLenConstraint exceeds the issuer's remaining path length (RFC 5280 sec. 4.2.1.9)");
    }
  }
  var version = exts.length ? 3 : 1;

  var tbsChildren = [];
  if (version !== 1) tbsChildren.push(b.explicit(0, b.integer(BigInt(version - 1))));
  tbsChildren.push(serialTlv);
  tbsChildren.push(scheme.sigAlgId);
  tbsChildren.push(issuerDer);
  tbsChildren.push(validityDer);
  tbsChildren.push(subjectDer);
  tbsChildren.push(b.raw(spki));
  if (exts.length) tbsChildren.push(b.explicit(3, b.sequence(exts)));
  var tbsDer = b.sequence(tbsChildren);

  return signScheme.signOverTbs(scheme, issuer.key, tbsDer, _signE).then(function (sig) {
    return Promise.resolve(_assertCertVerifies(tbsDer, sig, issuerSpki, scheme)).then(function () {
      var certDer = b.sequence([tbsDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? x509.pemEncode(certDer, "CERTIFICATE") : certDer;
    });
  }, function (e) {
    if (e instanceof CertificateError) throw e;
    throw _err("x509/bad-input", "signing the certificate failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

module.exports = { sign: sign };
