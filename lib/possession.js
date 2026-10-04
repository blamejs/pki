// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.possession
 * @nav        Enrollment
 * @title      Possession statements
 * @order      238
 * @slug       possession
 * @fullname   Statement of possession: certifying a key that cannot sign
 *
 * @intro
 *   PKCS#10 proves possession of the key being certified by signing the request
 *   with it, which a key-establishment key cannot do. An ML-KEM, X25519 or X448 key
 *   therefore cannot be certified through a plain PKCS#10 request at all. RFC 9883
 *   answers that by signing the request with a DIFFERENT key, one the requester
 *   already holds a certificate for, and naming that certificate in an attribute:
 *
 *     PrivateKeyPossessionStatement ::= SEQUENCE {
 *       signer  IssuerAndSerialNumber,
 *       cert    Certificate OPTIONAL }
 *
 *   So the request's own signature is the proof, made by a key that is not the
 *   subject's. `pki.csr.sign` takes the statement as
 *   `spec.privateKeyPossessionStatement` and signs with the key given, which is the
 *   one case where it accepts a signing key that is not the subject's and a subject
 *   key that cannot sign. Without the statement both are still refused, so the
 *   relaxation is scoped to the request that declares it. The same value is a CRMF
 *   registration control, which is why `parse` reads either.
 *
 *   `verifyRequest` is the CA's side, and it applies the two requirements RFC 9883
 *   states as MUSTs: the signature on the request is validated with the public key
 *   from the signature certificate, and that certificate's certification path is
 *   validated. Path validation is not optional, so the verb needs `trustAnchors` and
 *   refuses without them rather than answering a question it did not fully ask.
 *
 *   The two name comparisons the RFC states as SHOULDs end in a question a library
 *   cannot answer: "If they are different, the certificate policy MUST describe how
 *   the CA can determine that the two subject names identify the same entity." So
 *   `subjectMatches` and `subjectAltNamesMatch` are REPORTED, and a request whose
 *   names differ resolves `valid: false` with the reason naming the policy decision
 *   rather than being refused outright. A caller whose policy resolves it reads the
 *   fields and decides.
 *
 *   `requestsSignatureCertificate` reports the one MUST NOT: the attribute is for a
 *   key-establishment certificate, so a request that asks for a signature key usage,
 *   or that asks to certify a subject key which can only ever sign, is the misuse the
 *   RFC forbids.
 *
 * @card Read and check an RFC 9883 statement of possession, the attribute that lets a
 *   key-establishment key be certified by a request another key signed.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var schemaX509 = require("./schema-x509");
var schemaCsr = require("./schema-csr");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var seam = require("./verify-seam");

var PossessionError = frameworkError.PossessionError;
var _create = intrinsic.create;
var _assign = intrinsic.assign;
var _forEach = intrinsic.forEach;
var _map = intrinsic.map;
var _isArray = intrinsic.isArray;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);
/** @internal The promise constructor captured at load, used as the RECEIVER for the captured
 *  `Promise.resolve`. Handing it the live `globalThis.Promise` instead put the capture back under a
 *  replaceable constructor: `Promise.resolve` builds through its receiver, so a replacement installed
 *  after load decided what the awaited value became. Here that value is a path-validation result, and a
 *  constructor substituting `{ valid: true }` for it made a correctly signed request report `valid`
 *  while its signature certificate chained to an untrusted CA, which is the RFC 9883 sec. 4 MUST this
 *  verb exists to apply. */
var _Promise = intrinsic.Promise;
var _push = intrinsic.push;
var _join = intrinsic.join;
var _every = intrinsic.every;
var _filter = intrinsic.filter;
var _keys = intrinsic.keys;
var _hasOwn = intrinsic.hasOwn;
var _strIndexOf = intrinsic.uncurry(String.prototype.indexOf);
var _bufToString = intrinsic.bufToString;

function _err(code, message, cause) { return new PossessionError(code, message, cause); }

var _seam = seam.makeSeam("possession", PossessionError, "possession/bad-input");
/** @internal Set by path-validate at load, so the path check runs through the same validator a caller
 *  would call and this module does not hold a second copy of it. */
var _validatePath = null;
function setEngine(engine) { _seam.setEngine(engine.verifyWithSpki); _validatePath = engine.validate; }

var OID_SOP = oid.byName("statementOfPossession");
if (!OID_SOP) throw new Error("possession: the RFC 9883 attribute OID is not in the registry");

var NS = pkix.makeNS("possession", PossessionError, oid);
/** @internal The signer is an IssuerAndSerialNumber, the same type CMS names and RFC 9763 reuses, read
 *  through the one shared definition so the three cannot diverge on the structure. */
var STATEMENT = schema.seq([
  schema.field("signer", pkix.issuerAndSerialNumber(NS, { code: "possession/bad-statement" })),
  schema.optional("certificate", schema.any(), { whenUniversal: [asn1.TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 1, max: 2 },
  code: "possession/bad-statement", what: "PrivateKeyPossessionStatement",
  build: function (m) {
    return {
      signer: m.fields.signer.value.result,
      certificate: m.fields.certificate.present ? m.fields.certificate.node.bytes : null,
    };
  },
});

var KNOWN_VERIFY_OPTS = _assign(_create(null), {
  trustAnchors: 1, time: 1, signatureCertificate: 1, intermediates: 1,
});

/** @internal Whether a certificate is the one an IssuerAndSerialNumber names. Both halves are compared,
 *  because a serial is unique only within an issuer. The DN comparison is the canonical one RFC 5280
 *  sec. 7.1 states, through the shared guard, so two spellings of one name are one name. */
function _namesCertificate(signer, certParsed) {
  if (signer.serialNumber !== certParsed.serialNumber) return false;
  try {
    return guard.name.dnEqual(signer.issuer.rdns, certParsed.issuer.rdns,
      _err, "possession/bad-input", "the signer issuer name") === true;
  } catch (_e) { return false; }
}

/**
 * @primitive pki.possession.parse
 * @signature pki.possession.parse(value) -> { signer, certificate }
 * @since 0.8.44
 * @status stable
 * @spec RFC 9883 sec. 3
 * @defends possession-statement-confusion (CWE-347)
 * @related pki.possession.verifyRequest, pki.csr.sign, pki.crmf.build
 *
 * Read a `PrivateKeyPossessionStatement`. `value` is the attribute value of a PKCS#10
 * `statementOfPossession` attribute or the value of the CRMF registration control of the same name,
 * which RFC 9883 gives the same OID, so one reader serves both.
 *
 * `signer` is "the issuer name and certificate serial number of the signature certificate", and
 * `certificate` is that certificate when the statement carries it, or `null`. The RFC allows the
 * omission: "If the issuer of the key establishment certificate will be the same as the issuer of the
 * signature certificate, then this component MAY be omitted", leaving the CA to look it up.
 *
 * A carried certificate that `signer` does not name throws `possession/signer-mismatch`. The two would
 * describe different certificates, and therefore different keys, while only one of them signed the
 * request.
 *
 * @example
 *   var kem = await pki.key.generate({ name: "ML-KEM-768" });
 *   var sig = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var kemSpki = await pki.key.export(kem.publicKey, { format: "der" });
 *   var sigSpki = await pki.key.export(sig.publicKey, { format: "der" });
 *   var sigCert = await pki.x509.sign({
 *     subject: "CN=kem.example", subjectPublicKey: sigSpki, serialNumber: 34n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *   }, { key: sig.privateKey });
 *   var parsedCert = pki.schema.x509.parse(sigCert);
 *   var csr = await pki.csr.sign({
 *     subject: "CN=kem.example", subjectPublicKey: kemSpki,
 *     privateKeyPossessionStatement: {
 *       signer: { issuer: parsedCert.issuer.bytes, serialNumber: parsedCert.serialNumber },
 *       certificate: sigCert,
 *     },
 *   }, { key: sig.privateKey });
 *   var attr = pki.schema.csr.parse(csr).attributes
 *     .filter(function (a) { return a.type === pki.oid.byName("statementOfPossession"); })[0];
 *   pki.possession.parse(attr.values[0]).certificate !== null;   // -> true
 */
function parse(value) {
  var der = guard.bytes.snapshot(value, _err, "possession/bad-statement", "the possession statement");
  var node;
  try { node = asn1.decode(der); }
  catch (e) { throw _err("possession/bad-statement", "the possession statement must be DER", e); }
  var out;
  try { out = schema.walk(STATEMENT, node, NS).result; }
  catch (e) {
    if (e instanceof PossessionError) throw e;
    throw _err("possession/bad-statement", "the possession statement must be a SEQUENCE { signer, cert? } (RFC 9883 sec. 3)", e);
  }
  return _bindSignerToCertificate(out);
}

/** @internal The signer-names-the-carried-certificate rule, in one place because the statement reaches a
 *  consumer through TWO doors: this module's `parse`, and the certification-request parser's
 *  recognized-attribute reader, which decodes the value in place while parsing the request. A statement
 *  naming one certificate while carrying another describes two different keys, and only one of them
 *  signed the request, so a door that skips the rule hands back a signer that does not identify the key
 *  the signature was made with. Both doors call this. */
function _bindSignerToCertificate(out) {
  if (out.certificate !== null) {
    var certParsed;
    try { certParsed = schemaX509.parse(out.certificate); }
    catch (e) { throw _err("possession/bad-statement", "the possession statement cert component must be an X.509 certificate", e); }
    if (!_namesCertificate(out.signer, certParsed)) {
      throw _err("possession/signer-mismatch",
        "the certificate the statement carries is not the one its signer names (RFC 9883 sec. 3)");
    }
  }
  return out;
}

/** @internal The statement of a parsed certification request, or null when it carries none. The
 *  recognized-attribute reader decodes it in place, so the value is read again only when a caller
 *  handed over a request some other reader parsed. The in-place record has been through the SHAPE rules
 *  and not the binding rule, which lives here rather than in the request parser, so it is applied to
 *  that record on the way out and neither door returns a statement the other would refuse. */
function statementOf(parsedCsr) {
  var found = _filter(parsedCsr.attributes || [], function (a) { return a.type === OID_SOP; });
  /** @internal More than one is REFUSED rather than resolved by taking the first. Selecting `[0]` skipped
   *  every binding check on the rest, so a request carrying a sound statement followed by one naming a
   *  different certificate was accepted on the strength of the first alone. Which of them a CA should honor
   *  is stated nowhere, the same reason the extensionRequest ambiguity is refused. */
  _assertOneAttribute(found.length, "statementOfPossession");
  if (!found.length) return null;
  var attr = found[0];
  if (attr.privateKeyPossessionStatement) return _bindSignerToCertificate(attr.privateKeyPossessionStatement);
  return parse(attr.values[0]);
}

/** @internal One ambiguity refusal for every attribute this module selects a single instance of. A CSR's
 *  attributes are a SET and nothing orders them, so a verb that takes the first of several checks one and
 *  certifies against the others. */
function _assertOneAttribute(count, name) {
  if (count > 1) {
    throw _err("possession/bad-request", "this request carries " + count + " " + name +
      " attributes, and which of them a CA should honor is not stated anywhere, so the RFC 9883 " +
      "checks cannot be made against one of them alone");
  }
}

/** @internal A requested extension of a certification request, decoded, or null when the request asks for
 *  none. The extensions a request asks for hang off its extensionRequest attribute, so they are reached
 *  through the attribute rather than off the request itself.
 *
 *  An extension that is PRESENT but will not decode is a fault, not an absence. The sec. 3 name comparisons
 *  and the sec. 6 prohibition read these, so reporting an unreadable one as absent leaves the check with
 *  nothing to read and the verdict saying it does not apply, while the request itself is accepted. The
 *  certification-request parser holds the extension WRAPPER to its shape and not its decoded value, so
 *  nothing upstream refuses it either. Naming the fault is the only reading that does not quietly drop a
 *  check the specification asks for. */
function _requestedExtension(parsedCsr, name) {
  var wanted = oid.byName(name);
  var attrs = parsedCsr.attributes || [];
  for (var i = 0; i < attrs.length; i++) {
    var exts = attrs[i].extensions || [];
    for (var j = 0; j < exts.length; j++) {
      if (exts[j].oid !== wanted) continue;
      /** @internal The extension IS present, its OID having matched. `decodeExtension` reports a value it
       *  cannot read as `decoded: null` rather than throwing, which is the same thing this function would
       *  otherwise return for an extension the request never asked for, so the two have to be told apart
       *  here or the caller cannot. */
      var record;
      try { record = schemaCsr.decodeExtension(exts[j]); }
      catch (e) {
        throw _err("possession/bad-request", "the request asks for a " + name +
          " extension this build cannot read, so the RFC 9883 check it feeds cannot be " +
          "made; an unreadable policy field is not an absent one", e);
      }
      if (record.decoded === null || record.decoded === undefined) {
        throw _err("possession/bad-request", "the request asks for a " + name +
          " extension whose value does not decode" + (record.code ? " (" + record.code + ")" : "") +
          ", so the RFC 9883 check it feeds cannot be made; an unreadable policy field is " +
          "not an absent one");
      }
      return record.decoded;
    }
  }
  return null;
}

/** @internal Whether a signature certificate's subjectAltName carries the entry a request asks for, each
 *  form compared under its own RFC 5280 rule by `guard.name.generalNameEqual`. Keying both lists by the
 *  rendered value instead made the comparison verbatim for every form at once, so `EXAMPLE.com` in the
 *  certificate and `example.com` in the request read as two hosts although RFC 4343 makes DNS
 *  case-insensitive, and a directoryName re-encoded to equivalent bytes read as a second name although
 *  RFC 5280 sec. 7.1 compares it attribute by attribute. A form the guard cannot hold to its rule answers
 *  "not-comparable", which is not a match: the comparison this verb reports is one it actually made. */
function _sanCarries(certNames, asked) {
  var names = certNames || [];
  for (var i = 0; i < names.length; i++) {
    if (guard.name.generalNameEqual(names[i], asked, _err, "possession/bad-input",
      "a subjectAltName entry") === "match") return true;
  }
  return false;
}

/** @internal The key-usage bits that make a certificate a signature certificate, which RFC 9883 sec. 6
 *  states the attribute MUST NOT be used to obtain. The decoded keyUsage is a flags object, so the
 *  names are read off it rather than from a list of set bits. */
var SIGNATURE_USAGES = ["digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"];

/** @internal The subject keys that can ONLY sign, from the shared table in `schema-pkix`. The
 *  `lint/rfc9883/signature-certificate-requested` row reads the same one, so `pki.lint.csr` under that
 *  profile and this verb reach the same verdict about the same request: the linter grading conforming what
 *  this refuses is what the shared table removes. */
var _isSignatureOnlyKey = pkix.signatureOnlyKeyOid(NS);

/**
 * @primitive pki.possession.verifyRequest
 * @signature pki.possession.verifyRequest(request, opts) -> Promise<verdict>
 * @since 0.8.44
 * @status stable
 * @spec RFC 9883 sec. 3, RFC 9883 sec. 4, RFC 9883 sec. 6
 * @defends possession-statement-forgery (CWE-347)
 * @related pki.possession.parse, pki.csr.sign, pki.path.validate
 *
 * The CA's side of RFC 9883. `request` is a PKCS#10 certification request carrying a
 * `statementOfPossession` attribute. Applies the two requirements section 3 states as MUSTs, and
 * reports the two it states as SHOULDs.
 *
 * The MUSTs are enforced. "The CA MUST validate the signature on the certificate request using the
 * public key from the signature certificate", so the signature is checked against that key and not
 * against the key being certified, which for a key-establishment key could not have signed anything.
 * "The CA MUST perform certification path validation for the signature certificate as specified in
 * Section 6 of [RFC5280]", so `opts.trustAnchors` is required and the verb throws without it instead of
 * returning a verdict that skipped a MUST.
 *
 * The SHOULDs are reported. Both end in "the certificate policy MUST describe how the CA can determine
 * that the two subject names identify the same entity", which is a question this library cannot answer,
 * so `subjectMatches` and `subjectAltNamesMatch` carry the comparison and `valid` is `false` with a
 * reason naming the policy decision when they differ. A caller whose policy resolves it reads those
 * fields and decides for itself.
 *
 * `requestsSignatureCertificate` reports the section 6 MUST NOT: "The privateKeyPossessionStatement
 * attribute MUST NOT be used to obtain a signature certificate." A request asking for `digitalSignature`,
 * `nonRepudiation`, `keyCertSign` or `cRLSign` is that misuse, and so is a request whose subject key can
 * only ever sign, which section 4 states as a property of the request: "the subjectPKInfo MUST contain the
 * public key for the key establishment algorithm". Either way `valid` is `false`.
 *
 * A request carrying no statement throws `possession/absent`: it is not an unverified RFC 9883 request,
 * it is a different question, and `pki.csr.verify` is the verb for it.
 *
 * @opts trustAnchors  Required. The anchors the signature certificate's path is validated to, in the form `pki.path.validate` takes.
 * @opts time  The instant the path is validated at, defaulting to now when omitted or `null`. A value
 *             that is present and is not a usable `Date` is `possession/bad-input`.
 * @opts signatureCertificate  The signature certificate, for a statement that omits it; refused when it is not the one `signer` names.
 * @opts intermediates  The rest of the signature certificate's path, when an intermediate CA issued it rather than an anchor directly. Ordered as `pki.path.validate` takes a path, from the certificate nearest an anchor down to the issuer of the signature certificate, which this verb appends. Omitted, the signature certificate is validated on its own, which succeeds only when an anchor issued it.
 *
 * @example
 *   var kem = await pki.key.generate({ name: "ML-KEM-768" });
 *   var sig = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var kemSpki = await pki.key.export(kem.publicKey, { format: "der" });
 *   var sigSpki = await pki.key.export(sig.publicKey, { format: "der" });
 *   var ca = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var caSpki = await pki.key.export(ca.publicKey, { format: "der" });
 *   var caCert = await pki.x509.sign({
 *     subject: "CN=Possession CA", subjectPublicKey: caSpki, serialNumber: 1n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
 *   }, { key: ca.privateKey });
 *   var sigCert = await pki.x509.sign({
 *     subject: "CN=kem.example", subjectPublicKey: sigSpki, serialNumber: 34n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"] },
 *   }, { cert: caCert, key: ca.privateKey });
 *   var p = pki.schema.x509.parse(sigCert);
 *   var csr = await pki.csr.sign({
 *     subject: "CN=kem.example", subjectPublicKey: kemSpki,
 *     privateKeyPossessionStatement: {
 *       signer: { issuer: p.issuer.bytes, serialNumber: p.serialNumber }, certificate: sigCert,
 *     },
 *   }, { key: sig.privateKey });
 *   var v = await pki.possession.verifyRequest(csr,
 *     { trustAnchors: [caCert], time: new Date("2027-06-01T00:00:00Z") });
 *   v.valid;   // -> true
 */
function verifyRequest(request, opts) {
  return guard.async.deferred(function () { return _verifyRequest(request, opts); });
}

function _verifyRequest(request, opts) {
  guard.identifier.assertKnownKeys(opts, KNOWN_VERIFY_OPTS, _err, "possession/bad-input",
    "pki.possession.verifyRequest has an unknown option: ");
  var o = guard.identifier.snapshotOptions(opts, KNOWN_VERIFY_OPTS);
  if (o.trustAnchors == null || !_isArray(o.trustAnchors) || o.trustAnchors.length === 0) {
    throw _err("possession/bad-input",
      "opts.trustAnchors is required: RFC 9883 sec. 4 makes certification path validation of the signature certificate a MUST, and a verdict that skipped it would not answer the question asked");
  }
  if (_validatePath === null) {
    throw _err("possession/bad-input", "the possession path validator is not initialized (require pki before use)");
  }
  /** @internal The documented default, constructed here. Forwarded as `undefined`, it reached the path
   *  validator's always-on validity check, which requires a valid Date and refuses `path/bad-input`, so
   *  the default never applied and every caller had to supply a clock to get any verdict at all. A value
   *  that is present and is not a usable Date is refused HERE, under this verb's own code, rather than
   *  reported against the validator a caller did not call. */
  var at = o.time;
  if (at === undefined || at === null) at = new intrinsic.Date();
  else guard.time.assertValid(at, _err, "possession/bad-input", "opts.time (the instant the signature certificate's path is validated at)");

  var der = guard.bytes.snapshot(request, _err, "possession/bad-input", "the certification request");
  var parsed;
  try { parsed = schemaCsr.parse(der); }
  catch (e) { throw _err("possession/bad-input", "the certification request must be a PKCS#10 CertificationRequest", e); }

  var statement = statementOf(parsed);
  if (statement === null) {
    throw _err("possession/absent",
      "the certification request carries no statementOfPossession attribute, so there is no statement to check (RFC 9883 sec. 3)");
  }

  var sigCertDer = statement.certificate;
  if (sigCertDer === null) {
    if (o.signatureCertificate == null) {
      throw _err("possession/no-certificate",
        "the statement omits the signature certificate, so opts.signatureCertificate must supply the one its signer names (RFC 9883 sec. 3)");
    }
    sigCertDer = guard.bytes.snapshot(o.signatureCertificate, _err, "possession/bad-input", "opts.signatureCertificate");
    var supplied;
    try { supplied = schemaX509.parse(sigCertDer); }
    catch (e) { throw _err("possession/bad-input", "opts.signatureCertificate must be an X.509 certificate", e); }
    if (!_namesCertificate(statement.signer, supplied)) {
      throw _err("possession/signer-mismatch",
        "opts.signatureCertificate is not the certificate the statement's signer names (RFC 9883 sec. 3)");
    }
  } else if (o.signatureCertificate != null) {
    throw _err("possession/bad-input",
      "the statement already carries its signature certificate, so opts.signatureCertificate would name a second one");
  }

  var sigCert = schemaX509.parse(sigCertDer);
  var reasons = [];

  /** @internal A request carrying more than one extensionRequest attribute is REFUSED before any of it is
   *  read, the way `pki.schema.csr.decodeExtensions` refuses it. The lookups below take the first attribute
   *  whose extension matches, so a second attribute's `keyUsage` was never seen: a request asking for
   *  `keyAgreement` in the first and `digitalSignature` in the second reported the RFC 9883 sec. 6
   *  prohibition as not engaged. Which attribute a CA should honor is not stated anywhere, so naming the
   *  ambiguity is the only reading that does not silently check one and certify the other. */
  var extensionRequests = 0;
  _forEach(parsed.attributes || [], function (a) {
    if (a.type === oid.byName("extensionRequest")) extensionRequests += 1;
  });
  _assertOneAttribute(extensionRequests, "extensionRequest");
  /** @internal The MUST NOT, decided from the usages the request asks for AND from the subject key itself.
   *  The usages alone let a request omit the keyUsage extension and report the prohibition as not engaged,
   *  while asking to certify a key that can only ever sign. The reason names which of the two fired, since
   *  one message covering both would tell an operator a request named a usage when it named none. */
  var requestedUsage = _requestedExtension(parsed, "keyUsage");
  var askedSignatureUsage = false;
  if (requestedUsage !== null) {
    _forEach(SIGNATURE_USAGES, function (u) { if (requestedUsage[u] === true) askedSignatureUsage = true; });
  }
  var subjectKeyOid = parsed.subjectPublicKeyInfo && parsed.subjectPublicKeyInfo.algorithm
    ? parsed.subjectPublicKeyInfo.algorithm.oid : null;
  var subjectKeySignsOnly = _isSignatureOnlyKey(subjectKeyOid);
  var requestsSignatureCertificate = askedSignatureUsage || subjectKeySignsOnly;
  if (askedSignatureUsage) {
    _push(reasons, "the request asks for a signature key usage, and RFC 9883 sec. 6 states the attribute MUST NOT be used to obtain a signature certificate");
  }
  if (subjectKeySignsOnly) {
    _push(reasons, "the request asks to certify a " + (oid.name(subjectKeyOid) || subjectKeyOid) +
      " subject key, which can only sign, and RFC 9883 sec. 4 requires the subjectPKInfo to carry the " +
      "public key for the key establishment algorithm");
  }

  /** @internal The two SHOULDs, compared and reported. */
  var subjectMatches = false;
  try {
    subjectMatches = guard.name.dnEqual(parsed.subject.rdns, sigCert.subject.rdns,
      _err, "possession/bad-input", "the request subject") === true;
  } catch (_e) { subjectMatches = false; }
  if (!subjectMatches) {
    _push(reasons, "the request subject differs from the signature certificate subject, and RFC 9883 sec. 3 leaves to the certificate policy how a CA determines the two name the same entity");
  }

  var requestedSan = _requestedSan(parsed);
  var certSan = _certSan(sigCert);
  var subjectAltNamesMatch = null;
  if (requestedSan !== null) {
    subjectAltNamesMatch = _every(requestedSan || [], function (asked) {
      return _sanCarries(certSan, asked);
    });
    if (!subjectAltNamesMatch) {
      _push(reasons, "a subject alternative name the request asks for is not in the signature certificate, and RFC 9883 sec. 3 leaves to the certificate policy how a CA determines the two name the same entity");
    }
  }

  /** @internal RFC 9883 sec. 4 makes path validation of the signature certificate a MUST, and a CA
   *  normally issues end-entity certificates from an intermediate. The validator is handed an ordered
   *  path and does not build one, so without the rest of the chain the only request that can pass is one
   *  whose signature certificate the anchor issued directly, and every other valid request is refused
   *  for a path that is in fact valid. The order is the validator's own: from the certificate nearest
   *  the anchor down to the issuer of the signature certificate, which goes last. */
  var chain = [];
  if (o.intermediates != null) {
    if (!_isArray(o.intermediates)) {
      throw _err("possession/bad-input",
        "opts.intermediates is the rest of the signature certificate's path as an array of certificates, ordered from the one nearest a trust anchor down to the issuer of the signature certificate");
    }
    for (var ci = 0; ci < o.intermediates.length; ci++) {
      guard.list.append(chain, guard.bytes.snapshot(o.intermediates[ci], _err, "possession/bad-input",
        "opts.intermediates[" + ci + "]"));
    }
  }
  guard.list.append(chain, sigCertDer);

  var signerMaySign = _maySign(sigCert);
  if (!signerMaySign) {
    _push(reasons, "the signature certificate's keyUsage does not permit signing, so its key may not " +
      "authorize a certification request (RFC 5280 sec. 4.2.1.3)");
  }

  return _promiseResolve(_Promise, _validatePath(chain, { trustAnchors: o.trustAnchors, time: at }))
    .then(function (pathResult) {
      var pathValidated = pathResult.valid === true;
      if (!pathValidated) _push(reasons, "the signature certificate's certification path is not valid, and RFC 9883 sec. 4 makes that a MUST");
      return _seam.verify(parsed.signatureAlgorithm, parsed.signatureValue,
        sigCert.subjectPublicKeyInfo.bytes, parsed.certificationRequestInfoBytes)
        .then(function (verified) {
          if (verified !== true) _push(reasons, "the request signature does not verify under the signature certificate's public key, and RFC 9883 sec. 4 makes that a MUST");
          return guard.verdict.of({}, {
            valid: verified === true && pathValidated && signerMaySign && !requestsSignatureCertificate &&
              subjectMatches && subjectAltNamesMatch !== false,
            verified: verified === true,
            pathValidated: pathValidated,
            signerMaySign: signerMaySign,
            signer: statement.signer,
            signatureCertificate: sigCertDer,
            subjectMatches: subjectMatches,
            subjectAltNamesMatch: subjectAltNamesMatch,
            requestsSignatureCertificate: requestsSignatureCertificate,
            reason: reasons.length ? _join(reasons, "; ") : undefined,
          });
        });
    });
}

/** @internal Whether the signature certificate's key may make this signature at all. A certificate confined
 *  to `keyAgreement` does not authorize a signature over a certification request, and accepting one lets a
 *  key never issued for signing authorize issuance. The accepted set is `pki.cms`'s: a signature over
 *  content is authorized by digitalSignature, contentCommitment or nonRepudiation alike. */
var _maySign = pkix.keyUsagePermits(NS, ["digitalSignature", "contentCommitment", "nonRepudiation"]);

/** @internal The subjectAltName a request asks for, or null when it asks for none. */
function _requestedSan(parsedCsr) {
  var d = _requestedExtension(parsedCsr, "subjectAltName");
  return d === null ? null : (d.names || []);
}

/** @internal The subjectAltName a certificate carries. */
function _certSan(parsedCert) {
  var ext = _filter(parsedCert.extensions || [], function (e) { return e.oid === oid.byName("subjectAltName"); })[0];
  if (ext === undefined) return [];
  try { return schemaX509.decodeExtension(ext).decoded.names || []; }
  catch (_e) { return []; }
}

module.exports = {
  parse: parse,
  verifyRequest: verifyRequest,
  /** @internal The attribute OID and the statement reader, for the builders and verifiers that
   *  compose them; not on the curated surface. */
  OID_SOP: OID_SOP, statementOf: statementOf, namesCertificate: _namesCertificate,
  setEngine: setEngine,
};
