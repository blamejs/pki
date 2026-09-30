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
 *   key-establishment certificate, and a request that asks for a signature key usage
 *   is the misuse the RFC forbids.
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
var _push = intrinsic.push;
var _join = intrinsic.join;
var _every = intrinsic.every;
var _filter = intrinsic.filter;
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
  trustAnchors: 1, time: 1, signatureCertificate: 1,
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
 *  handed over a request some other reader parsed. */
function statementOf(parsedCsr) {
  var attr = _filter(parsedCsr.attributes || [], function (a) { return a.type === OID_SOP; })[0];
  if (attr === undefined) return null;
  return attr.privateKeyPossessionStatement || parse(attr.values[0]);
}

/** @internal A requested extension of a certification request, decoded, or null. The extensions a
 *  request asks for hang off its extensionRequest attribute, so they are reached through the attribute
 *  rather than off the request itself. */
function _requestedExtension(parsedCsr, name) {
  var wanted = oid.byName(name);
  var attrs = parsedCsr.attributes || [];
  for (var i = 0; i < attrs.length; i++) {
    var exts = attrs[i].extensions || [];
    for (var j = 0; j < exts.length; j++) {
      if (exts[j].oid !== wanted) continue;
      try { return schemaCsr.decodeExtension(exts[j]).decoded; }
      catch (_e) { return null; }
    }
  }
  return null;
}

/** @internal The GeneralName entries of a subjectAltName as comparable strings: the context tag that
 *  names the form, then the rendered value. A form the decoder does not render to a string is keyed by
 *  its raw bytes instead, so two entries of such a form compare as themselves rather than as equal. */
function _sanKeys(names) {
  return _map(names || [], function (n) {
    if (typeof n.value === "string") return n.tagNumber + ":" + n.value;
    if (n.bytes) return n.tagNumber + ":" + _bufToString(n.bytes, "hex");
    return n.tagNumber + ":?";
  });
}

/** @internal The key-usage bits that make a certificate a signature certificate, which RFC 9883 sec. 4
 *  states the attribute MUST NOT be used to obtain. The decoded keyUsage is a flags object, so the
 *  names are read off it rather than from a list of set bits. */
var SIGNATURE_USAGES = ["digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"];

/**
 * @primitive pki.possession.verifyRequest
 * @signature pki.possession.verifyRequest(request, opts) -> Promise<verdict>
 * @since 0.8.44
 * @status stable
 * @spec RFC 9883 sec. 4
 * @defends possession-statement-forgery (CWE-347)
 * @related pki.possession.parse, pki.csr.sign, pki.path.validate
 *
 * The CA's side of RFC 9883. `request` is a PKCS#10 certification request carrying a
 * `statementOfPossession` attribute. Applies the two requirements section 4 states as MUSTs, and
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
 * `requestsSignatureCertificate` reports the MUST NOT: "The privateKeyPossessionStatement attribute
 * MUST NOT be used to obtain a signature certificate." A request asking for `digitalSignature`,
 * `nonRepudiation`, `keyCertSign` or `cRLSign` is that misuse, and `valid` is `false`.
 *
 * A request carrying no statement throws `possession/absent`: it is not an unverified RFC 9883 request,
 * it is a different question, and `pki.csr.verify` is the verb for it.
 *
 * @opts trustAnchors  Required. The anchors the signature certificate's path is validated to, in the form `pki.path.validate` takes.
 * @opts time  The instant the path is validated at, defaulting to now.
 * @opts signatureCertificate  The signature certificate, for a statement that omits it; refused when it is not the one `signer` names.
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

  /** @internal The MUST NOT, read off the usages the request asks for. */
  var requestedUsage = _requestedExtension(parsed, "keyUsage");
  var requestsSignatureCertificate = false;
  if (requestedUsage !== null) {
    _forEach(SIGNATURE_USAGES, function (u) { if (requestedUsage[u] === true) requestsSignatureCertificate = true; });
  }
  if (requestsSignatureCertificate) {
    _push(reasons, "the request asks for a signature key usage, and RFC 9883 sec. 4 states the attribute MUST NOT be used to obtain a signature certificate");
  }

  /** @internal The two SHOULDs, compared and reported. */
  var subjectMatches = false;
  try {
    subjectMatches = guard.name.dnEqual(parsed.subject.rdns, sigCert.subject.rdns,
      _err, "possession/bad-input", "the request subject") === true;
  } catch (_e) { subjectMatches = false; }
  if (!subjectMatches) {
    _push(reasons, "the request subject differs from the signature certificate subject, and RFC 9883 sec. 4 leaves to the certificate policy how a CA determines the two name the same entity");
  }

  var requestedSan = _requestedSan(parsed);
  var certSan = _certSan(sigCert);
  var subjectAltNamesMatch = null;
  if (requestedSan !== null) {
    var have = _create(null);
    _forEach(_sanKeys(certSan), function (k) { have[k] = 1; });
    subjectAltNamesMatch = _every(_sanKeys(requestedSan), function (k) { return have[k] === 1; });
    if (!subjectAltNamesMatch) {
      _push(reasons, "a subject alternative name the request asks for is not in the signature certificate, and RFC 9883 sec. 4 leaves to the certificate policy how a CA determines the two name the same entity");
    }
  }

  return _promiseResolve(Promise, _validatePath([sigCertDer], { trustAnchors: o.trustAnchors, time: o.time }))
    .then(function (pathResult) {
      var pathValidated = pathResult.valid === true;
      if (!pathValidated) _push(reasons, "the signature certificate's certification path is not valid, and RFC 9883 sec. 4 makes that a MUST");
      return _seam.verify(parsed.signatureAlgorithm, parsed.signatureValue,
        sigCert.subjectPublicKeyInfo.bytes, parsed.certificationRequestInfoBytes)
        .then(function (verified) {
          if (verified !== true) _push(reasons, "the request signature does not verify under the signature certificate's public key, and RFC 9883 sec. 4 makes that a MUST");
          return guard.verdict.of({}, {
            valid: verified === true && pathValidated && !requestsSignatureCertificate &&
              subjectMatches && subjectAltNamesMatch !== false,
            verified: verified === true,
            pathValidated: pathValidated,
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
