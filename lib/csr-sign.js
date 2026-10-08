// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.csr
 * @nav        Signing
 * @title      Certification requests
 * @fullname   CSRs (PKCS#10 certification requests): build, sign and verify
 * @intro The PKCS#10 certification-request producing side. `pki.csr.sign` builds a
 *   `CertificationRequestInfo`, signs it with the subject's own private key (proof of possession, since
 *   a CSR has no issuer), and emits a `CertificationRequest` (RFC 2986) that `pki.schema.csr.parse`,
 *   OpenSSL, and a CA enrollment pipeline all accept. Requested v3 extensions ride in a PKCS#9
 *   `extensionRequest` attribute (RFC 2985) a CA copies into the issued certificate. Parsing lives at
 *   `pki.schema.csr.parse`.
 * @spec RFC 2986
 * @card Build and sign a PKCS#10 certification request (proof of possession by the subject key).
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var csr = require("./schema-csr");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
/** @internal The append every list here is built with: `push` stores at the index and a store
 *  consults a setter inherited there, and these lists become the bytes that get signed. */
var _push = intrinsic.append;
/** @internal The promise a self-check is awaited through, built from the constructor captured at load.
 *  `Promise.resolve` builds from its RECEIVER, so reading the global binding at the call hands the
 *  construction to whatever that binding holds, and a constructor settling without awaiting its
 *  argument runs the continuation before the check has finished. */
var _Promise = intrinsic.Promise;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);
require("./path-validate");
var csrVerify = require("./csr-verify");
var relatedCert = require("./related-cert");
var possession = require("./possession");
var x509Schema = require("./schema-x509");
var lint = require("./lint");

var CsrError = frameworkError.CsrError;
var KNOWN_SPEC_KEYS = Object.assign(Object.create(null), { subject: 1, subjectPublicKey: 1, extensionRequest: 1, challengePassword: 1, relatedCertRequest: 1, privateKeyPossessionStatement: 1, attributes: 1 });
/** @internal The four this verb reads, which are the four `pki.x509.sign` reads. A name outside
 * them was accepted and dropped, so asking for PEM and misspelling the option returned DER and
 * reported nothing. */
var KNOWN_SIGN_OPTS = Object.assign(Object.create(null), { digestAlgorithm: 1, pem: 1, pss: 1, profile: 1 });

/** @internal The signature the build-time gate lints against, standing in for one that does not exist
 * until the key is used. It is non-empty so the gate is not answering a rule about its own placeholder. */
var GATE_PLACEHOLDER_SIG = Buffer.alloc(64, 0xff);
var KNOWN_KEY_WRAPPER_KEYS = Object.assign(Object.create(null), { key: 1 });
var b = asn1.build;
function _err(code, message, cause) { return new CsrError(code, message, cause); }
function _signE(kind, message, cause) { return new CsrError("csr/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var NS = pkix.makeNS("csr", CsrError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var _b = pkiBuild.makeBuilder({
  ErrorClass: CsrError, prefix: "csr", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: EXT_DECODERS,
});

function _implicitSetOf0(members) {
  /** @internal The copy, the DER SET-OF ordering AND the comparator go through captured operations.
   *  Read off their own homes, `slice`, `sort` and `Buffer.compare` each decide the bytes emitted:
   *  measured, replacing any of them made this set encode an attribute other than the one just
   *  validated, on bytes this verb then signs. */
  return b.contextConstructed(0, Buffer.concat(guard.list.sortedCopy(members, guard.bytes.compare)));
}

function _buildRequestedExtensions(extSpec, subjectSpki) { return _b.requestedExtensions(extSpec, subjectSpki); }

function _challengePassword(pw) {
  if (typeof pw !== "string" || pw.length < 1 || pw.length > 255) throw _err("csr/bad-input", "challengePassword must be a 1..255 character string (RFC 2985 sec. 5.4.1)");
  return asn1.isPrintableString(pw) ? b.printable(pw) : b.utf8(pw);
}

var KNOWN_POSSESSION_KEYS = Object.assign(Object.create(null), { signer: 1, certificate: 1, includeCertificate: 1 });
/** @internal PrivateKeyPossessionStatement ::= SEQUENCE { signer IssuerAndSerialNumber,
 *  cert Certificate OPTIONAL } (RFC 9883 sec. 3). The statement declares that this request is signed by
 *  a key OTHER than the one being certified, which is what lets a key-establishment key be certified at
 *  all: it cannot sign, so it cannot prove possession the PKCS#10 way. A carried certificate must be the
 *  one the signer names, since the two would otherwise describe different keys and only one of them
 *  signed. */
function _possessionStatement(spec) {
  if (spec === null || typeof spec !== "object" || Buffer.isBuffer(spec)) {
    throw _err("csr/bad-input", "privateKeyPossessionStatement must be an object { signer, certificate? }");
  }
  guard.identifier.assertKnownKeys(spec, KNOWN_POSSESSION_KEYS, _err, "csr/bad-input",
    "privateKeyPossessionStatement has an unknown field: ");
  var signer = spec.signer;
  if (signer === null || typeof signer !== "object" || Buffer.isBuffer(signer)) {
    throw _err("csr/bad-input", "privateKeyPossessionStatement needs a signer naming the signature certificate's issuer and serial (RFC 9883 sec. 3)");
  }
  var issuerRaw = (signer.issuer !== null && typeof signer.issuer === "object" && !Buffer.isBuffer(signer.issuer) &&
    signer.issuer.bytes !== undefined) ? signer.issuer.bytes : signer.issuer;
  var issuerDer = _b.reqDer(issuerRaw, "privateKeyPossessionStatement signer.issuer (the signature certificate's issuer Name DER)");
  var serial = guard.range.authoredInteger(signer.serialNumber, _err, "csr/bad-input",
    "privateKeyPossessionStatement signer.serialNumber");
  if (serial < 1n) throw _err("csr/bad-input", "privateKeyPossessionStatement signer.serialNumber must be a positive integer (RFC 5280 sec. 4.1.2.2)");

  /** @internal The certificate is required HERE even though RFC 9883 sec. 3 lets the wire form omit it,
   *  because this verb has to know which key signs: it resolves the signature algorithm from that key and
   *  checks its own signature against it. The omission the RFC allows is for the CA's benefit, and a
   *  requester holding the signing key holds its certificate too, so `includeCertificate: false` emits
   *  the compact form while the builder still knows the key. */
  if (spec.certificate == null) {
    throw _err("csr/bad-input",
      "privateKeyPossessionStatement needs the certificate: this verb resolves the signature algorithm from its key and checks the signature against it. Pass includeCertificate: false to leave it off the wire, which RFC 9883 sec. 3 allows");
  }
  var certDer = _b.reqDer(spec.certificate, "privateKeyPossessionStatement certificate");
  var include = spec.includeCertificate === undefined ? true : spec.includeCertificate;
  if (include !== true && include !== false) {
    throw _err("csr/bad-input", "privateKeyPossessionStatement includeCertificate is a flag, so it is true, false or omitted");
  }
  var signerIsn = b.sequence([b.raw(issuerDer), b.integer(serial)]);
  /** @internal Read back through the one statement reader with the certificate ALWAYS present, so the
   *  shape rule and the signer-names-the-certificate rule are applied by the same code a consumer
   *  applies. The emitted form may then drop it; dropping it cannot make a checked statement wrong. */
  try { possession.parse(b.sequence([signerIsn, b.raw(certDer)])); }
  catch (e) { throw _err("csr/bad-input", "privateKeyPossessionStatement: " + ((e && e.message) || String(e)), e); }
  return { der: b.sequence(include ? [signerIsn, b.raw(certDer)] : [signerIsn]), certificate: certDer };
}

var KNOWN_RELATED_CERT_KEYS = Object.assign(Object.create(null), { certID: 1, requestTime: 1, locationInfo: 1, signature: 1 });
/** @internal RequesterCertificate ::= SEQUENCE { certID IssuerAndSerialNumber, requestTime BinaryTime,
 *  locationInfo UniformResourceIdentifiers, signature BIT STRING } (RFC 9763 sec. 3.1), where
 *  UniformResourceIdentifiers ::= SEQUENCE SIZE (1..MAX) OF IA5String. The first two fields are the
 *  ones the signature covers, so they are encoded by the module that defines that preimage rather than
 *  a second time here: an encoder that disagreed with it would produce a proof no verifier accepts. */
function _relatedCertRequest(spec) {
  if (spec === null || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("csr/bad-input", "relatedCertRequest must be an object { certID, requestTime, locationInfo, signature }");
  guard.identifier.assertKnownKeys(spec, KNOWN_RELATED_CERT_KEYS, _err, "csr/bad-input", "relatedCertRequest has an unknown field: ");
  var signed;
  try { signed = relatedCert.requestSignedData({ certID: spec.certID, requestTime: spec.requestTime }); }
  catch (e) { throw _err("csr/bad-input", "relatedCertRequest certID and requestTime: " + ((e && e.message) || String(e)), e); }

  var locations = spec.locationInfo;
  if (!Array.isArray(locations)) throw _err("csr/bad-input", "relatedCertRequest locationInfo must be an array of URI strings (RFC 9763 sec. 3.1)");
  if (locations.length < 1) throw _err("csr/bad-input", "relatedCertRequest locationInfo must name at least one URI (SEQUENCE SIZE (1..MAX))");
  var uris = guard.list.copyMap(locations, function (u, i) {
    if (typeof u !== "string" || u.length === 0) throw _err("csr/bad-input", "relatedCertRequest locationInfo[" + i + "] must be a non-empty URI string");
    if (!guard.encoding.isAsciiText(u)) throw _err("csr/bad-input", "relatedCertRequest locationInfo[" + i + "] must be an IA5String, so every character is ASCII (RFC 9763 sec. 3.1)");
    return b.ia5(u);
  });

  var sig = _b.reqDer(spec.signature, "relatedCertRequest signature (the proof of possession over pki.relatedCert.requestSignedData)");
  if (sig.length === 0) throw _err("csr/bad-input", "relatedCertRequest signature must not be empty");
  return b.sequence([b.raw(signed), b.sequence(uris), b.bitString(sig, 0)]);
}

/**
 * @primitive pki.csr.sign
 * @signature pki.csr.sign(spec, key, opts?) -> Promise<Buffer|string>
 * @since 0.3.1
 * @status stable
 * @spec RFC 2986, RFC 2985
 * @defends forged-certification-request (CWE-347)
 * @related pki.schema.csr.parse, pki.x509.sign
 *
 * Build, sign, and DER-encode a PKCS#10 certification request. `spec` describes the request: `subject`
 * (a common-name string, an array of RDNs, or raw Name DER; MAY be empty), `subjectPublicKey` (the SPKI
 * DER of the key being certified), and optional `extensionRequest` (requested v3 extensions, as an object
 * of subjectAltName / keyUsage / extendedKeyUsage / basicConstraints / certificatePolicies /
 * subjectKeyIdentifier / qcStatements / msCertificateTemplate / msEnrollCertType /
 * msApplicationPolicies / subjectInfoAccess / subjectDirectoryAttributes and the rest of the
 * subject-owned set `pki.x509.sign` takes, or an array of pre-encoded Extension DER) and
 * `challengePassword`. An extension the issuing CA assigns (authorityKeyIdentifier, the
 * certificate-transparency pair, the CA version and previous-certificate hash, ocspNoCheck) is not a
 * request and is refused by name. `key` (or
 * `{ key }`) is the subject's own PKCS#8 private key, WebCrypto CryptoKey, or signer
 * `{ algorithm, publicKey, sign }`, so the request is self-signed
 * to prove possession of the private half of `subjectPublicKey`, and that proof is verified before the
 * request is returned. The signature algorithm is resolved from the subject key (RSA PKCS#1 v1.5 or PSS,
 * ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm). Returns DER, or a PEM `CERTIFICATE REQUEST` with
 * `opts.pem`. Malformed input throws a typed `CsrError`; where the spec carries raw DER (a `Name`
 * Buffer, a pre-encoded requested `Extension` or `Attribute`) a malformed leaf inside those bytes
 * throws `Asn1Error` instead. Certificate-request parsing is `pki.schema.csr.parse`.
 *
 * Before the key is used, the request the spec describes is linted against the RFC 2986 profile and
 * refused with `csr/profile-violation` if any rule grades it `error`, naming the rule and its clause.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE REQUEST` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 *   - `profile` (string) -- a second lint profile to hold the request to beside RFC 2986, named from
 *     `pki.lint.profiles()`. `"none"` runs no rules at all and emits what the spec describes, which is
 *     how a deliberately non-conforming request is produced.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerSpki = await pki.key.export(pair.publicKey);
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var req = await pki.csr.sign(
 *     { subject: "req.example.com", subjectPublicKey: signerSpki,
 *       extensionRequest: { subjectAltName: [{ dNSName: "req.example.com" }] } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.csr.parse(req).subject.dn;   // "CN=req.example.com"
 */
function sign(spec, key, opts) {
  return guard.bytes.fixedCall(CsrError, "csr/bad-input", [
    [spec, "the certification-request spec"], [key, "the signing key"], [opts, "pki.csr.sign options"],
  ], _sign);
}

function _sign(spec, key, opts) {
  opts = opts || intrinsic.create(null);
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("csr/bad-input", "the certification-request spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "csr/bad-input", "unknown spec field ");
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "csr/bad-input", "pki.csr.sign has an unknown option ");
  lint.assertKnownBuildProfile("csr", opts.profile, _err, "csr/bad-input");
  var wrapped = key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key;
  if (wrapped) guard.identifier.assertKnownKeys(key, KNOWN_KEY_WRAPPER_KEYS, _err, "csr/bad-input", "unknown field in the { key } wrapper (a signing option belongs in the third argument): ");
  var signingKey = wrapped ? key.key : key;
  if (signingKey == null) throw _err("csr/bad-input", "a signing key (the subject's private key) is required");

  var subjectSpki = _b.reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the requested key)");
  _b.assertValidSpki(subjectSpki, "spec.subjectPublicKey");
  var subjectDer = _b.encodeName(spec.subject == null ? [] : spec.subject);

  var attrs = [], seenAttr = Object.create(null);
  function addAttr(attrType, valueTlv) {
    if (seenAttr[attrType]) throw _err("csr/bad-input", "duplicate " + (oid.name(attrType) || attrType) + " attribute");
    seenAttr[attrType] = true;
    _push(attrs,b.sequence([b.oid(attrType), b.set([valueTlv])]));
  }
  if (spec.extensionRequest != null) addAttr(O("extensionRequest"), _buildRequestedExtensions(spec.extensionRequest, subjectSpki));
  if (spec.challengePassword != null) addAttr(O("challengePassword"), _challengePassword(spec.challengePassword));
  if (spec.relatedCertRequest != null) addAttr(O("relatedCertRequest"), _relatedCertRequest(spec.relatedCertRequest));
  /** @internal The statement, and the key its certificate carries: the signature is made by that key, so
   *  the scheme below resolves from it. A statement that omits the certificate leaves the signing key
   *  unverifiable here, since there is nothing to check it against, so the certificate is required at
   *  build time even though RFC 9883 sec. 3 lets the wire form omit it. */
  var possessionCertSpki = null;
  if (spec.privateKeyPossessionStatement != null) {
    var statement = _possessionStatement(spec.privateKeyPossessionStatement);
    addAttr(O("statementOfPossession"), b.raw(statement.der));
    possessionCertSpki = x509Schema.parse(statement.certificate).subjectPublicKeyInfo.bytes;
  }
  if (spec.attributes != null) {
    if (!Array.isArray(spec.attributes)) throw _err("csr/bad-input", "spec.attributes must be an array of pre-encoded Attribute DER");
    /** @internal Through the captured walk, never the caller's own `forEach`: a request's attributes are
     *  signed content, and a replaced walk hands the callback a list it never validated. */
    guard.list.copyMap(spec.attributes, function (a, i) {
      var der = _b.reqDer(a, "attribute [" + i + "]");
      var n;
      try { n = asn1.decode(der); }
      catch (e) { throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] is not valid DER", e); }
      if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length !== 2 || n.children[1].tagNumber !== asn1.TAGS.SET) throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] must be an Attribute SEQUENCE { type OID, SET OF value }");
      var at;
      try { at = asn1.read.oid(n.children[0]); }
      catch (e) { throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] type is not an OBJECT IDENTIFIER", e); }
      if (at === O("extensionRequest")) throw _err("csr/bad-input", "pass requested extensions via spec.extensionRequest, not a pre-encoded extensionRequest attribute");
      if (at === O("challengePassword")) throw _err("csr/bad-input", "pass the challenge password via spec.challengePassword, not a pre-encoded challengePassword attribute");
      if (at === O("relatedCertRequest")) throw _err("csr/bad-input", "pass the related-certificate request via spec.relatedCertRequest, not a pre-encoded relatedCertRequest attribute");
      if (at === O("statementOfPossession")) throw _err("csr/bad-input", "pass the possession statement via spec.privateKeyPossessionStatement, not a pre-encoded statementOfPossession attribute");
      if (!n.children[1].children || n.children[1].children.length === 0) throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] value SET must contain at least one value (RFC 2986 SET SIZE(1..MAX))");
      if (seenAttr[at]) throw _err("csr/bad-input", "duplicate " + (oid.name(at) || at) + " attribute");
      seenAttr[at] = true;
      _push(attrs,b.raw(der));
    });
  }

  /** @internal Which key signs, and therefore which key the scheme resolves from. Normally the subject's
   *  own, because a PKCS#10 signature IS the proof of possession of the key being certified. With an
   *  RFC 9883 statement of possession the signature is made by the key of the certificate the statement
   *  names, which is the whole mechanism: a key-establishment key cannot sign, so it cannot prove
   *  possession that way. The relaxation is scoped to a request that declares the statement, so a
   *  request without one is still held to signing with the key it certifies. */
  var provingSpki = subjectSpki;
  if (possessionCertSpki !== null) provingSpki = possessionCertSpki;
  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(provingSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var criDer = b.sequence([b.integer(0n), subjectDer, b.raw(subjectSpki), _implicitSetOf0(attrs)]);
  lint.assertBuildClean("csr",
    b.sequence([criDer, scheme.sigAlgId, b.bitString(GATE_PLACEHOLDER_SIG, 0)]),
    opts.profile, _err, "csr/profile-violation");

  return signScheme.signOverTbs(scheme, signingKey, criDer, _signE).then(function (sig) {
    return _promiseResolve(_Promise, _b.assertSignatureVerifies(criDer, sig, provingSpki, scheme)).then(function () {
      var der = b.sequence([criDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? csr.pemEncode(der, "CERTIFICATE REQUEST") : der;
    });
  }, function (e) {
    if (e instanceof CsrError) throw e;
    throw _err("csr/bad-input", "signing the certification request failed -- the signing key does not match the subject public key or is invalid", e);
  });
}

function _coerceCsr(request) {
  return guard.parsed.acceptDerived(request, "csr", csr.parse, _err, "csr/bad-input", "the certification request");
}

/**
 * @primitive pki.csr.verify
 * @signature pki.csr.verify(request) -> Promise<{ valid, verified, subject, subjectPublicKeyInfo, attributes, certificationRequestInfoBytes }>
 * @since 0.5.13
 * @status stable
 * @spec RFC 2986 sec. 4.2
 * @defends csr-proof-of-possession-bypass (CWE-347)
 * @related pki.csr.sign, pki.schema.csr.parse, pki.x509.sign
 *
 * Verify a certification request's signature over its exact parsed `certificationRequestInfo` bytes.
 * `request` is a DER `Buffer`, a PEM string, or a parsed request. A CSR carries no issuer: the
 * verifying key is the `subjectPKInfo` inside the signed preimage, so this is the proof of
 * possession `openssl req -verify` checks, and a CA that issues without it certifies a key the
 * requester may not hold.
 *
 * The result carries `verified` alongside the `subject`, `subjectPublicKeyInfo`, `attributes` and
 * `certificationRequestInfoBytes` that were verified, all re-derived from the request's own bytes.
 * Issue from those rather than from the argument: a request normalized in place before verifying
 * leaves the caller holding edited fields, and a bare boolean would answer about the signed bytes
 * while the certificate got built from the edits.
 *
 * What `true` establishes is bounded, and the bound is the point. It says the producer held the
 * private half of the key inside this request, over bytes that include the subject name and every
 * requested extension, so none of them were altered after signing. It says nothing about who the
 * producer is: the key is self-asserted, the name is self-asserted, and a requester free to choose
 * both can prove possession of a key they generated a moment ago under any name they like. Binding
 * that name to an identity is the enrollment protocol's job (`pki.est`, `pki.cmc`, `pki.cmp`, or
 * an out-of-band check), and remains one after this returns `true`.
 *
 * Verification composes the one path-validation signature engine, with the same algorithm-confusion
 * (RFC 9814 sec. 4 key-OID == sig-OID) and EdDSA low-order-point gates, rather than the self-check
 * this module's signing side runs over a key the caller already controls. It fails closed to
 * `false` on any import or verification fault; malformed input throws a typed `CsrError`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var pkcs8 = await pki.key.export(pair.privateKey);
 *   // A bare string is the commonName VALUE, so this asks for CN=device-42.
 *   var req = await pki.csr.sign({ subject: "device-42", subjectPublicKey: spki }, { key: pkcs8 });
 *   var r = await pki.csr.verify(req);
 *   // Issue from r.subject / r.subjectPublicKeyInfo / r.attributes, which are the verified fields.
 *   var issued = r.verified
 *     ? await pki.x509.sign({ subject: r.subject.dn, subjectPublicKey: r.subjectPublicKeyInfo.bytes,
 *         notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") },
 *       { key: pkcs8 })
 *     : null;
 */
function verify(request) { return guard.async.deferred(function () { return _verify(request); }); }
function _verify(request) {
  var parsed = _coerceCsr(request);
  return _promiseResolve(_Promise, csrVerify.verifyCsrSignature(parsed)).then(function (ok) {
    return guard.verdict.of({
      valid: ok === true,
      verified: ok === true,
      subject: parsed.subject,
      subjectPublicKeyInfo: parsed.subjectPublicKeyInfo,
      attributes: parsed.attributes,
      certificationRequestInfoBytes: parsed.certificationRequestInfoBytes,
    });
  });
}

module.exports = { sign: sign, verify: verify };
