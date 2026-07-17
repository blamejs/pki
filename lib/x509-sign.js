// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.x509
 * @nav        Signing
 * @title      Certificates
 * @intro The X.509 certificate-issuance producing side. `pki.x509.sign` builds a `TBSCertificate`,
 *   signs it, and emits a `Certificate` (RFC 5280 sec. 4) that `pki.schema.x509.parse`,
 *   `pki.path.validate`, and OpenSSL all accept -- self-signed or CA-signed, over any signature
 *   algorithm the toolkit registry resolves: RSA (PKCS#1 v1.5 / PSS), ECDSA, EdDSA, ML-DSA, SLH-DSA,
 *   and the composite (hybrid) arms. Parsing lives at `pki.schema.x509.parse`.
 * @spec RFC 5280
 * @card Build and sign an X.509 certificate -- self-signed or CA-signed, over any registry algorithm.
 */
//
// The whole algorithm matrix comes from the shared sign-scheme resolver (the same registry
// pki.cms.sign / pki.tsp.sign drive), so a new algorithm is a registry row, never a branch here. The
// TBS + extension DER is hand-assembled through the canonical asn1.build.* layer (the shipped
// cms/tsp/ocsp producing pattern); the strict schema-x509 decoder round-trips it, and that round-trip
// -- plus OpenSSL interop -- is the divergence guard.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");

var CertificateError = frameworkError.CertificateError;
// The x509 schema namespace + Name parser -- the SAME RDNSequence parser pki.schema.x509.parse uses, so
// a raw Name DER is validated fully (structure, DirectoryString types) with the frozen x509/* codes.
var NS = pkix.makeNS("x509", CertificateError, oid);
var NAME_SCHEMA = pkix.name(NS);
var SPKI_SCHEMA = pkix.spki(NS);
// The SAME RFC 5280 sec. 4.2.1 extension value decoders pki.schema.x509.parse uses, so a recognized
// pre-encoded (array-form) extension is fully validated with the frozen x509/* codes.
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var b = asn1.build;
// Two error factories (cms-sign.js pattern): `_err` takes a full x509/* code; `_signE` prepends the
// domain so the shared sign-scheme resolver/signer faults keep the x509/* codes. Both are FACTORIES
// -- guard.time.assertValid and resolveSignScheme invoke them as `E(code, msg)` with no `new`.
function _err(code, message, cause) { return new CertificateError(code, message, cause); }
function _signE(kind, message, cause) { return new CertificateError("x509/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var OID_SKI = O("subjectKeyIdentifier");

// The recognized keys of the `extensions` spec object; an unknown key is a typo and throws at
// config-time (a custom extension is passed as pre-encoded DER via the array form).
var KNOWN_EXT_KEYS = {
  subjectKeyIdentifier: 1, authorityKeyIdentifier: 1, keyUsage: 1, keyUsageCritical: 1,
  extendedKeyUsage: 1, extendedKeyUsageCritical: 1, basicConstraints: 1, subjectAltName: 1,
  certificatePolicies: 1, certificatePoliciesCritical: 1,
};

// The shared PKIX producing primitives (lib/pki-build.js), bound to the x509 namespace so they keep the
// frozen x509/* codes. Thin local aliases let the x509 call sites read unchanged. csr-sign binds the same
// builder to its own namespace (Hard rule #5 -- one encode definition, no per-format hand-roll).
var _b = pkiBuild.makeBuilder({ ErrorClass: CertificateError, prefix: "x509", O: O, NS: NS, NAME_SCHEMA: NAME_SCHEMA, SPKI_SCHEMA: SPKI_SCHEMA, EXT_DECODERS: EXT_DECODERS });
var _encodeName = _b.encodeName, _isEmptyName = _b.isEmptyName, _reqDer = _b.reqDer,
  _assertValidSpki = _b.assertValidSpki, _assertValidExtension = _b.assertValidExtension,
  _certLikeFromSpki = _b.certLikeFromSpki, _assertCertVerifies = _b.assertSignatureVerifies,
  _ext = _b.ext, _extBasicConstraints = _b.extBasicConstraints, _validateBcSpec = _b.validateBcSpec,
  _extKeyUsage = _b.extKeyUsage, _extExtKeyUsage = _b.extExtKeyUsage, _extSki = _b.extSki,
  _extAki = _b.extAki, _extSan = _b.extSan, _extCertPolicies = _b.extCertPolicies,
  _skiKeyId = _b.skiKeyId, _spkiKeyId = _b.spkiKeyId, _serialInteger = _b.serialInteger;

// ---- issuer-side extension helpers (subjectKeyIdentifier lookup + authorityKeyIdentifier) ----

function _skiValueOf(caCert) {
  var ext = (caCert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (ext) { try { return asn1.read.octetString(asn1.decode(ext.value)); } catch (_e) { /* fall through to re-derive from the issuer SPKI */ } }
  return null;
}
function _akiKeyId(val, ctx) {
  if (Buffer.isBuffer(val)) return val;
  if (val === true) {
    if (ctx.issuerCert) { var ski = _skiValueOf(ctx.issuerCert); if (ski) return ski; }
    return _spkiKeyId(ctx.issuerSpki);
  }
  throw _err("x509/bad-input", "authorityKeyIdentifier must be true (auto-derive from the issuer) or a Buffer key id");
}

// Build the extensions [3] block from the spec object (or pass through an array of pre-encoded
// Extension DER buffers). Enforces the RFC 5280 CA cross-field gates, then emits a deterministic order.
function _buildExtensions(extSpec, ctx) {
  if (extSpec == null) return [];
  if (Array.isArray(extSpec)) {
    // Validate each pre-encoded extension, reject a duplicate extnID (RFC 5280 sec. 4.2 -- at most one
    // instance of an extension), and decode basicConstraints + keyUsage to apply the same CA
    // cross-field rules the object form enforces (below), so the array escape hatch cannot bypass them.
    var seenExt = {}, arrCa = false, arrKeyCertSign = false, arrPathLen = false;
    var oidBc = O("basicConstraints"), oidKu = O("keyUsage");
    var arr = extSpec.map(function (e, i) {
      var der = _reqDer(e, "extension");
      _assertValidExtension(der, i);
      var n = asn1.decode(der);
      var extnId = asn1.read.oid(n.children[0]);
      if (seenExt[extnId]) throw _err("x509/bad-input", "duplicate extension " + extnId + " in the extensions array (RFC 5280 sec. 4.2 -- at most one instance of an extension)");
      seenExt[extnId] = true;
      // Fully validate a RECOGNIZED extension by running its real value decoder (which enforces the
      // RFC 5280 sec. 4.2.1 rules and throws a typed x509/* on malformed), and take the CA cross-field
      // inputs from the decoded value; an unrecognized extension is opaque (the caller's own concern).
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
          // RFC 5280 sec. 4.2.1.9 -- a CA's basicConstraints MUST be critical (3 children = an explicit
          // TRUE critical flag, since _assertValidExtension already rejects an explicit FALSE).
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
  // Reject a typo'd / unsupported extension key at config-time rather than silently dropping it (a
  // misspelled `keyUsag` would otherwise omit keyUsage). A custom extension goes in the array form.
  Object.keys(extSpec).forEach(function (k) {
    if (!KNOWN_EXT_KEYS[k]) throw _err("x509/bad-input", "unknown extension " + JSON.stringify(k) + " in the extensions spec; pass a pre-encoded Extension DER via the array form for a custom extension");
  });

  var bc = extSpec.basicConstraints;
  if (bc != null) _validateBcSpec(bc);
  var caTrue = !!(bc && bc.cA === true);
  var ku = extSpec.keyUsage;
  var assertsKeyCertSign = Array.isArray(ku) && ku.indexOf("keyCertSign") >= 0;
  // RFC 5280 sec. 4.2.1.3 -- keyCertSign requires basicConstraints cA=TRUE.
  if (assertsKeyCertSign && !caTrue) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
  // RFC 5280 sec. 4.2.1.9 -- pathLenConstraint requires cA=TRUE AND keyCertSign.
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
    // RFC 5280 sec. 4.2.1.9 -- a CA certificate's basicConstraints MUST be critical.
    if (bc.cA === true && bc.critical === false) throw _err("x509/bad-input", "a CA certificate's basicConstraints MUST be critical (RFC 5280 sec. 4.2.1.9)");
    out.push(_ext(O("basicConstraints"), bc.critical !== false, _extBasicConstraints(bc)));
  }
  if (extSpec.subjectAltName != null) out.push(_ext(O("subjectAltName"), ctx.subjectEmpty, _extSan(extSpec.subjectAltName)));
  if (extSpec.certificatePolicies != null) out.push(_ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, _extCertPolicies(extSpec.certificatePolicies)));
  return out;
}

// ---- serial + validity + key plumbing --------------------------------------

// RFC 5280 sec. 4.1.2.5 UTCTime/GeneralizedTime cutover -- the shared builder primitive (pki-build), a
// thin wrapper here so the certificate validity label reads "certificate notBefore/notAfter".
function _timeDer(date, which) { return _b.timeDer(date, "certificate " + which); }
// A supplied issuer certificate MUST be a CA that may sign certificates: basicConstraints present AND
// critical AND cA=TRUE (RFC 5280 sec. 4.2.1.9), and -- when a keyUsage extension is present -- the
// keyCertSign bit (sec. 4.2.1.3). Refuse a non-CA issuer rather than mint a certificate that will not
// chain. Returns the issuer's pathLenConstraint (or null) so the caller can honor it.
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
  return bc.pathLenConstraint;   // BigInt-narrowed integer or null
}
// The cA flag + pathLenConstraint of the certificate being issued, from either the object or the
// pre-encoded array extensions form (used to honor a supplied issuer's pathLenConstraint).
function _issuedCaInfo(extSpec) {
  if (extSpec == null) return { cA: false, pathLen: null };
  if (!Array.isArray(extSpec)) {
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
// Does the extensions spec carry a subjectAltName that will be emitted critical? The object form forces
// SAN critical when the subject is empty (so any subjectAltName qualifies); the pre-encoded array form
// is decoded to look for an Extension whose extnID is subjectAltName with a TRUE critical flag.
function _hasCriticalSan(extSpec) {
  if (extSpec == null) return false;
  if (!Array.isArray(extSpec)) return !!extSpec.subjectAltName;
  var sanOid = O("subjectAltName");
  for (var i = 0; i < extSpec.length; i++) {
    var n = asn1.decode(_reqDer(extSpec[i], "extension"));
    if (n.children.length === 3 && asn1.read.oid(n.children[0]) === sanOid && asn1.read.boolean(n.children[1]) === true) return true;
  }
  return false;
}

// ---- the primitive ---------------------------------------------------------

/**
 * @primitive pki.x509.sign
 * @signature pki.x509.sign(spec, issuer, opts?) -> Promise<Buffer|string>
 * @since 0.3.0
 * @status stable
 * @spec RFC 5280 sec. 4, RFC 9909, RFC 9814
 * @defends forged-certificate-issuance (CWE-347)
 * @related pki.schema.x509.parse, pki.path.validate, pki.cms.sign
 *
 * Build, sign, and DER-encode an X.509 certificate. `spec` describes the certificate to issue --
 * `subject` (a string CN, an array of RDNs, or raw Name DER), `subjectPublicKey` (the SPKI DER of the
 * key being certified), `notBefore` / `notAfter` (`Date`s), an optional `serialNumber`, and an optional
 * `extensions` object. `issuer` is the signing side: `{ key }` alone issues a self-signed certificate
 * (issuer = subject, signed with the subject's own key); `{ name, publicKey, key }` or `{ cert, key }`
 * issues a CA-signed one. The signature algorithm is resolved from the signing key -- RSA (PKCS#1 v1.5
 * or PSS via `opts.pss`), ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm -- so every algorithm the
 * toolkit signs with is available here without a per-algorithm branch.
 *
 * The version is derived from the field set (v3 when extensions are present, else v1). Serial bounds
 * (positive, <= 20 octets), the validity UTCTime/GeneralizedTime cutover, the DER DEFAULT omissions
 * (v1 tag, `critical=FALSE`, `cA=FALSE`), and the CA cross-field rules (keyCertSign and
 * pathLenConstraint require cA=TRUE) are all enforced; a violation throws a typed `CertificateError`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS rather than PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var root = await pki.x509.sign(
 *     { subject: "Example Root CA", subjectPublicKey: signerSpki,
 *       notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *       extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.x509.parse(root).subject.dn;   // "CN=Example Root CA"
 */
function sign(spec, issuer, opts) {
  return Promise.resolve().then(function () { return _sign(spec, issuer, opts); });
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("x509/bad-input", "the certificate spec must be an object");
  issuer = issuer || {};
  if (issuer.key == null) throw _err("x509/bad-input", "a signing key (issuer.key, a PKCS#8 private key) is required");

  var spki = _reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the certified key)");
  _assertValidSpki(spki, "spec.subjectPublicKey");
  var subjectDer = _encodeName(spec.subject == null ? [] : spec.subject);
  var subjectEmpty = _isEmptyName(subjectDer);

  // Resolve the issuer name + signing-key SPKI. `{ key }` alone -> self-signed.
  var issuerDer, issuerSpki, issuerCert = null, issuerPathLen = null;
  var selfSigned = issuer.name == null && issuer.cert == null && issuer.publicKey == null;
  if (selfSigned) {
    issuerDer = subjectDer;
    issuerSpki = spki;
  } else if (issuer.cert != null) {
    issuerCert = (Buffer.isBuffer(issuer.cert) || typeof issuer.cert === "string") ? x509.parse(issuer.cert) : issuer.cert;
    if (!issuerCert || !issuerCert.tbsBytes) throw _err("x509/bad-input", "issuer.cert must be a certificate DER/PEM or a parsed certificate");
    issuerPathLen = _assertIssuerIsCa(issuerCert);
    issuerDer = pkiBuild.tbsNameField(issuerCert, "subject");
    issuerSpki = issuerCert.subjectPublicKeyInfo.bytes;
  } else {
    issuerDer = _encodeName(issuer.name == null ? [] : issuer.name);
    issuerSpki = _reqDer(issuer.publicKey, "issuer.publicKey (the issuer SPKI DER)");
    _assertValidSpki(issuerSpki, "issuer.publicKey");
  }
  // RFC 5280 sec. 4.1.2.4 -- the issuer MUST be a non-empty distinguished name.
  if (_isEmptyName(issuerDer)) throw _err("x509/bad-issuer", "issuer must be a non-empty distinguished name");

  // Resolve the signature scheme from the SIGNING key's SPKI algorithm (the whole registry, for free).
  var scheme = signScheme.resolveSignScheme(_certLikeFromSpki(issuerSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var serialTlv = _serialInteger(spec.serialNumber);
  // Validate both instants, then reject an inverted window before encoding (a notBefore after notAfter
  // is a nonsensical validity period, RFC 5280 sec. 4.1.2.5).
  guard.time.assertValid(spec.notBefore, _err, "x509/bad-input", "notBefore");
  guard.time.assertValid(spec.notAfter, _err, "x509/bad-input", "notAfter");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd on the two lines above (an Invalid Date throws before this comparison).
  if (spec.notBefore.getTime() > spec.notAfter.getTime()) throw _err("x509/bad-input", "notBefore must not be after notAfter (RFC 5280 sec. 4.1.2.5)");
  var validityDer = b.sequence([_timeDer(spec.notBefore, "notBefore"), _timeDer(spec.notAfter, "notAfter")]);

  var exts = _buildExtensions(spec.extensions, { spki: spki, issuerSpki: issuerSpki, issuerCert: issuerCert, subjectEmpty: subjectEmpty });
  // RFC 5280 sec. 4.1.2.6 -- an empty subject requires a critical subjectAltName (recognized in both the
  // object form and a pre-encoded array-form extension).
  if (subjectEmpty && !_hasCriticalSan(spec.extensions)) {
    throw _err("x509/bad-input", "an empty subject requires a critical subjectAltName (RFC 5280 sec. 4.1.2.6)");
  }
  // Honor a supplied issuer's pathLenConstraint (RFC 5280 sec. 4.2.1.9): a CA certificate issued below
  // it consumes one unit of path length, so pathLen=0 forbids issuing a CA below it, and an issued CA's
  // own pathLenConstraint must leave room within the issuer's remaining depth.
  if (issuerPathLen != null) {
    var issued = _issuedCaInfo(spec.extensions);
    // A self-issued CA certificate (subject == issuer, e.g. a CA key rollover) does NOT consume path
    // length (RFC 5280 sec. 6.1 counts only non-self-issued intermediates), so it is permitted even at
    // pathLen 0. Compare canonically (sec. 7.1) via the parsed RDN sequences.
    var selfIssued = guard.name.dnEqual(
      schema.walk(NAME_SCHEMA, asn1.decode(subjectDer), NS).result.rdns,
      schema.walk(NAME_SCHEMA, asn1.decode(issuerDer), NS).result.rdns,
      _err, "x509/bad-input", "issuer/subject DN");
    if (issued.cA && !selfIssued) {
      if (issuerPathLen < 1) throw _err("x509/bad-input", "the issuer certificate pathLenConstraint (0) forbids issuing a non-self-issued CA certificate below it (RFC 5280 sec. 4.2.1.9)");
      if (issued.pathLen != null && issued.pathLen > issuerPathLen - 1) throw _err("x509/bad-input", "the issued CA certificate pathLenConstraint exceeds the issuer's remaining path length (RFC 5280 sec. 4.2.1.9)");
    }
  }
  // Version is derived from the emitted field set (RFC 5280 sec. 4.1.2.1); the builder never emits
  // unique identifiers, so extensions => v3, otherwise v1 (the [0] tag is omitted under DER DEFAULT).
  var version = exts.length ? 3 : 1;

  var tbsChildren = [];
  if (version !== 1) tbsChildren.push(b.explicit(0, b.integer(BigInt(version - 1))));   // v2->INTEGER 1, v3->INTEGER 2
  tbsChildren.push(serialTlv);
  tbsChildren.push(scheme.sigAlgId);   // signature == signatureAlgorithm (RFC 5280 sec. 4.1.1.2), single source
  tbsChildren.push(issuerDer);
  tbsChildren.push(validityDer);
  tbsChildren.push(subjectDer);
  tbsChildren.push(b.raw(spki));
  if (exts.length) tbsChildren.push(b.explicit(3, b.sequence(exts)));
  var tbsDer = b.sequence(tbsChildren);

  return signScheme.signOverTbs(scheme, issuer.key, tbsDer, _signE).then(function (sig) {
    // The signature MUST verify under the issuer public key, or the certificate would not chain (the
    // composite arm returns a promise; the classical/PQC path throws synchronously on a mismatch).
    return Promise.resolve(_assertCertVerifies(tbsDer, sig, issuerSpki, scheme)).then(function () {
      var certDer = b.sequence([tbsDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? x509.pemEncode(certDer, "CERTIFICATE") : certDer;
    });
  }, function (e) {
    // A signing failure at a well-formed tbs is a bad signing key or a key/algorithm mismatch; keep a
    // typed CertificateError (composite key-shape faults already are), and re-type a raw WebCrypto
    // rejection to x509/bad-input rather than leaking a DOMException from the boundary.
    if (e instanceof CertificateError) throw e;
    throw _err("x509/bad-input", "signing the certificate failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

module.exports = { sign: sign };
