// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.scep
 * @nav        Schema
 * @title      SCEP
 * @fullname   Simple Certificate Enrolment Protocol (RFC 8894)
 * @order      193
 * @slug       scep
 *
 * @intro
 *   The SCEP pkiMessage codec. SCEP wraps a PKCS#10 certification request (or an
 *   issued certificate) in two nested CMS layers: an inner EnvelopedData
 *   (`pkcsPKIEnvelope`) that encrypts the messageData to the recipient, and an
 *   outer SignedData that signs it under a set of authenticated transaction
 *   attributes: messageType, transactionID, pkiStatus, failInfo, and the
 *   sender/recipient nonces (RFC 8894 sec. 3). `pki.scep.build` assembles a
 *   request pkiMessage (PKCSReq, RenewalReq, CertPoll, GetCert, or GetCRL) or a
 *   CA-side CertRep response; `pki.scep.parse` verifies the
 *   outer signature, reads the transaction attributes BOUND to the verified
 *   signer, and (given the recipient key) decrypts the pkcsPKIEnvelope to the
 *   messageData.
 *
 *   The transaction attributes are surfaced only from a signature that verified:
 *   a pkiMessage whose outer signature does not check is refused, never returned
 *   with a false verdict. The pkcsPKIEnvelope is built with AES-128-CBC. This is
 *   the message layer, transport-agnostic; a live SCEP CA is driven over
 *   pki.transport separately.
 *
 * @card
 *   Build and read SCEP (RFC 8894) messages: a PKCSReq, RenewalReq, CertPoll,
 *   GetCert, or GetCRL request, or a CA-side CertRep response, wrapped in the
 *   signed-over-encrypted CMS layering, and any of them parsed back to its verified
 *   transaction attributes and decrypted messageData.
 */

var frameworkError = require("./framework-error");
var ScepError = frameworkError.ScepError;
var oid = require("./oid");
var asn1 = require("./asn1-der");
var b = asn1.build;
var cmsSign = require("./cms-sign");
var cmsVerify = require("./cms-verify");
var cmsEncrypt = require("./cms-encrypt");
var cmsDecrypt = require("./cms-decrypt");
require("./path-validate");
var csrVerify = require("./csr-verify");
var schemaCms = require("./schema-cms");
var schemaCsr = require("./schema-csr");
var schemaX509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var guard = require("./guard-all");
var C = require("./constants");
var httpTransport = require("./http-transport");
var retryAfter = require("./http-retry-after");
var _defaultSleep = require("./sleep").sleep;
var nodeCrypto = require("node:crypto");

function _err(code, msg, cause) { return new ScepError(code, msg, cause); }
function _showValue(v) { return guard.text.showValue(v); }

var _KU_NS = pkix.makeNS("scep", ScepError, oid);

var MESSAGE_TYPE = Object.assign(Object.create(null), { CertRep: "3", RenewalReq: "17", PKCSReq: "19", CertPoll: "20", GetCert: "21", GetCRL: "22" });
var PKI_STATUS = Object.assign(Object.create(null), { SUCCESS: "0", FAILURE: "2", PENDING: "3" });
var FAIL_INFO = Object.assign(Object.create(null), { badAlg: "0", badMessageCheck: "1", badRequest: "2", badTime: "3", badCertId: "4" });

function _invert(table) { var o = Object.create(null); for (var k in table) if (Object.prototype.hasOwnProperty.call(table, k)) o[table[k]] = k; return o; }
var MESSAGE_TYPE_BY_CODE = _invert(MESSAGE_TYPE), PKI_STATUS_BY_CODE = _invert(PKI_STATUS), FAIL_INFO_BY_CODE = _invert(FAIL_INFO);

var _PARSE_SUPPORTED = Object.assign(Object.create(null), { PKCSReq: 1, RenewalReq: 1, CertRep: 1, CertPoll: 1, GetCert: 1, GetCRL: 1 });

var ENVELOPE_CIPHER = "aes-128-cbc";

var EMPTY_CONTENT = Buffer.alloc(0);

function _nonce(v, label) {
  if (v == null) return nodeCrypto.randomBytes(16);
  var buf = guard.bytes.snapshotSource(v, ScepError, "scep/bad-nonce", label);
  if (buf.length !== 16) throw _err("scep/bad-nonce", label + " must be exactly 16 bytes (RFC 8894 sec. 3.2.1.5), got " + buf.length);
  return buf;
}

function _transactionId(v) {
  if (typeof v !== "string" || v.length === 0) throw _err("scep/bad-input", "transactionId must be a non-empty string (RFC 8894 sec. 3.2.1.1)");
  if (v.length > C.LIMITS.SCEP_TRANSACTION_ID_MAX) throw _err("scep/bad-input", "transactionId exceeds the " + C.LIMITS.SCEP_TRANSACTION_ID_MAX + "-character cap");
  return v;
}

function _assertValidEnvelope(bytes, messageType) {
  if (bytes == null) throw _err("scep/missing-envelope", "the pkcsPKIEnvelope is mandatory for a " + messageType + " message but the signed content is absent (RFC 8894 sec. 3.2)");
  var parsed;
  try { parsed = schemaCms.parse(bytes); }
  catch (e) { throw _err("scep/missing-envelope", "the pkcsPKIEnvelope of a " + messageType + " message is not a decodable CMS EnvelopedData (RFC 8894 sec. 3.2)", e); }
  if (parsed.contentTypeName !== "envelopedData") throw _err("scep/missing-envelope", "the pkcsPKIEnvelope of a " + messageType + " message must be an EnvelopedData (RFC 8894 sec. 3.2), got " + parsed.contentTypeName);
  if (parsed.encryptedContentInfo.contentType !== oid.byName("data")) throw _err("scep/bad-envelope-content-type", "the pkcsPKIEnvelope's encrypted content type must be id-data (RFC 8894 sec. 3.2.2), got " + parsed.encryptedContentInfo.contentType);
  var ct = parsed.encryptedContentInfo.encryptedContent;
  if (ct == null || ct.length === 0) throw _err("scep/missing-envelope", "the pkcsPKIEnvelope of a " + messageType + " message carries no encrypted content (RFC 8894 sec. 3.2)");
}

function _readIssuancePayload(der) {
  var r;
  try { r = schemaCms.parse(der); }
  catch (e) { throw _err("scep/bad-response", "a SUCCESS CertRep messageData did not decode as a CMS SignedData (RFC 8894 sec. 3.4)", e); }
  if (r.contentTypeName !== "signedData" || r.encapContentInfo.eContentType !== oid.byName("data") ||
      r.encapContentInfo.eContent !== null || r.signerInfos.length !== 0) {
    throw _err("scep/not-certs-only", "a SUCCESS CertRep messageData must be a degenerate certificates-only CMS SignedData (RFC 8894 sec. 3.4)");
  }
  var certs = [], crls = [], i;
  var rc = r.certificates || [], rl = r.crls || [];
  for (i = 0; i < rc.length; i++) {
    if (rc[i].tagClass !== "universal") throw _err("scep/bad-certificate", "a SUCCESS CertRep certificates field carried a tagged CertificateChoices alternative, not a plain X.509 certificate (RFC 8894 sec. 3.4)");
    try { schemaX509.parse(rc[i].bytes); }
    catch (e) { throw _err("scep/bad-certificate", "a SUCCESS CertRep carried a non-certificate in its certificates field", e); }
    certs[i] = rc[i].bytes;
  }
  for (i = 0; i < rl.length; i++) {
    if (rl[i].tagClass !== "universal") throw _err("scep/bad-crl", "a SUCCESS CertRep crls field carried a tagged RevocationInfoChoice alternative, not a plain X.509 CRL (RFC 5652 sec. 10.2.1)");
    try { schemaCrl.parse(rl[i].bytes); }
    catch (e) { throw _err("scep/bad-crl", "a SUCCESS CertRep carried a non-CRL in its crls field", e); }
    crls[i] = rl[i].bytes;
  }
  if (certs.length === 0 && crls.length === 0) {
    throw _err("scep/empty-response", "a SUCCESS CertRep messageData carried neither a certificate nor a CRL (RFC 8894 sec. 3.3.2)");
  }
  return { certificates: certs, crls: crls };
}

function _attr(name, valueDer) { return { type: oid.byName(name), values: [valueDer] }; }

function _find(attrs, name) {
  var want = oid.byName(name);
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type !== want) continue;
    if (!attrs[i].values || attrs[i].values.length !== 1) {
      throw _err("scep/bad-attribute", "the " + name + " transaction attribute must carry exactly one value (RFC 8894 sec. 3.2.1)");
    }
    return attrs[i];
  }
  return null;
}
function _readStr(attrs, name, expectedTag) {
  var a = _find(attrs, name);
  if (a == null) return null;
  var node;
  try { node = asn1.decode(a.values[0]); }
  catch (e) { throw _err("scep/bad-attribute", "the " + name + " transaction attribute is not decodable", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== expectedTag) {
    throw _err("scep/bad-attribute", "the " + name + " transaction attribute is not the ASN.1 string type RFC 8894 sec. 3.2 requires");
  }
  try { return asn1.read.string(node); }
  catch (e) { throw _err("scep/bad-attribute", "the " + name + " transaction attribute is not a readable string", e); }
}
var _T_PRINTABLE = asn1.TAGS.PRINTABLE_STRING, _T_UTF8 = asn1.TAGS.UTF8_STRING;
function _readNonce(attrs, name) {
  var a = _find(attrs, name);
  if (a == null) return null;
  var n;
  try { n = asn1.read.octetString(asn1.decode(a.values[0])); }
  catch (e) { throw _err("scep/bad-nonce", "the " + name + " transaction attribute is not a readable OCTET STRING", e); }
  if (n.length !== 16) throw _err("scep/bad-nonce", "the " + name + " nonce must be exactly 16 bytes (RFC 8894 sec. 3.2.1.5), got " + n.length);
  return n;
}

function _sameKey(certA, certB) {
  var a, bb;
  try { a = schemaX509.parse(certA).subjectPublicKeyInfo.bytes; bb = schemaX509.parse(certB).subjectPublicKeyInfo.bytes; }
  catch (e) { throw _err("scep/bad-input", "a certificate could not be parsed for signer authentication: " + e.message, e); }
  return guard.crypto.constantTimeEqual(a, bb);
}

function _assertRsaRecipient(recipientDer) {
  var spki;
  try { spki = schemaX509.parse(recipientDer).subjectPublicKeyInfo; }
  catch (e) { throw _err("scep/bad-input", "the recipient is not a parseable certificate: " + e.message, e); }
  if (spki.algorithm.oid !== oid.byName("rsaEncryption")) {
    throw _err("scep/bad-recipient", "the SCEP recipient must be an RSA key-transport certificate (RFC 8894 sec. 3); its public-key algorithm is " + spki.algorithm.oid);
  }
}

function _assertSigningKeyUsage(certDer, label) {
  var cert;
  try { cert = schemaX509.parse(certDer); }
  catch (e) { throw _err("scep/bad-input", "the " + label + " could not be parsed for its key usage: " + e.message, e); }
  var ku = pkix.keyUsageOf(_KU_NS, cert, _err, "scep/bad-input", "the " + label + "'s");
  if (ku != null && ku.digitalSignature !== true) {
    throw _err("scep/bad-signer-usage", "the " + label + " keyUsage does not assert digitalSignature, so it is not authorized to sign (RFC 8894 sec. 2.3)");
  }
}

function _captureRecipientKey(rk) {
  if (rk == null) return null;
  rk = guard.identifier.optionsObject(rk, _err, "scep/bad-input", "opts.recipientKey");
  var out = {};
  if (rk.cert != null) out.cert = guard.bytes.snapshotSource(rk.cert, ScepError, "scep/bad-input", "opts.recipientKey.cert");
  if (rk.key != null) out.key = rk.key;
  if (rk.cek != null) out.cek = rk.cek;
  return out;
}

/**
 * @primitive  pki.scep.build
 * @signature  pki.scep.build(spec) -> Promise<Buffer>
 * @since      0.6.2
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.parse, pki.cms.sign, pki.cms.encrypt, pki.csr.sign
 *
 * Assemble a SCEP pkiMessage (RFC 8894 sec. 3). A request (`PKCSReq` / `RenewalReq`) encrypts the
 * supplied PKCS#10 `messageData` to the recipient CA certificate as the inner EnvelopedData
 * (`pkcsPKIEnvelope`, AES-128-CBC), then signs it under the transaction attributes with the caller's
 * signer certificate and key. A `CertPoll` (GetCertInitial) query wraps an IssuerAndSubject that names
 * the issuing CA and the request subject; a `GetCert` or `GetCRL` query wraps an IssuerAndSerialNumber
 * that names a certificate by its issuer and serial. Every form is enveloped and signed the same way.
 * `transactionId` is a caller-unique PrintableString; `senderNonce` is a
 * 16-byte value (a fresh random one is generated when omitted). The recipient CA certificate must
 * assert the `keyEncipherment` key usage (the EnvelopedData uses RSA key transport). The content key
 * is transported under RSAES-OAEP (SHA-256), the toolkit's key-transport algorithm; the legacy
 * RSAES-PKCS1-v1_5 that older SCEP servers expect is never emitted, so the CA must support OAEP.
 *
 * For a `PKCSReq` the caller's signer SHOULD be a self-signed certificate using the same subject name
 * and key as the PKCS#10 request (RFC 8894 sec. 2.3); a `RenewalReq` is signed with the existing
 * CA-issued certificate instead, which is why this is the caller's choice rather than an enforced
 * match. The proof-of-possession over the PKCS#10 itself is verified regardless.
 *
 * A `CertRep` response is the CA (responder) side: it carries the transaction `pkiStatus`, echoes the
 * request's senderNonce as `recipientNonce`, and is signed under the CA's `signer`. A SUCCESS response
 * envelopes a certs-only SignedData of the issued `certificates` (or the `crls` of a GetCRL response) to
 * the requester's `recipient` certificate; a FAILURE (which carries a `failInfo`) or a PENDING response
 * omits the pkcsPKIEnvelope and is signed detached (RFC 8894 sec. 3.3.2).
 *
 * @opts
 *   - `messageType` -- "PKCSReq" | "RenewalReq" | "CertPoll" | "GetCert" | "GetCRL" | "CertRep".
 *   - `messageData` -- the PKCS#10 CertificationRequest DER, for a PKCSReq or RenewalReq.
 *   - `requestSubject` -- the request subject Name DER, for a CertPoll.
 *   - `certificate` -- for a GetCert or GetCRL, the certificate DER whose issuer and serial name the target (the convenience form).
 *   - `issuer` / `serialNumber` -- for a GetCert or GetCRL, the issuer Name DER and a positive serial (a BigInt, number, or hex string) naming the target directly. For a CertPoll, `issuer` alone names the issuing CA (defaulting to the recipient's subject) when the request is encrypted to a separate RA.
 *   - `recipient` -- the certificate DER the pkcsPKIEnvelope is encrypted to (an RSA key-transport certificate; a non-RSA recipient is refused, since the envelope uses RSAES-OAEP): the CA or RA certificate for a request, the requester's certificate for a SUCCESS CertRep.
 *   - `signer` -- `{ cert, key }`, the outer SignedData signer (the client for a request, the CA for a CertRep).
 *   - `transactionId` -- a caller-unique PrintableString identifying the transaction (echoes the request's on a CertRep).
 *   - `senderNonce` -- a 16-byte Buffer (generated when omitted).
 *   - `pkiStatus` -- for a CertRep, "SUCCESS" | "FAILURE" | "PENDING".
 *   - `recipientNonce` -- for a CertRep, the 16-byte value echoing the request's senderNonce (required).
 *   - `certificates` / `crls` -- for a SUCCESS CertRep, arrays of the issued certificate DER (or CRL DER) the certs-only SignedData carries.
 *   - `failInfo` / `failInfoText` -- for a FAILURE CertRep, the failInfo (badAlg / badMessageCheck / badRequest / badTime / badCertId) and an optional detail string.
 * @example
 *   // requires: csrDer -- the PKCS#10 CertificationRequest DER to enrol
 *   // requires: caCertDer -- the SCEP CA (or RA) certificate the request is encrypted to (keyEncipherment)
 *   // requires: clientCertDer -- the client's own certificate, the outer signer
 *   // requires: clientKeyPkcs8 -- the client's private key matching clientCertDer
 *   var msg = await pki.scep.build({ messageType: "PKCSReq", messageData: csrDer,
 *     recipient: caCertDer, signer: { cert: clientCertDer, key: clientKeyPkcs8 },
 *     transactionId: "txn-0001" });
 */
async function build(spec) {
  spec = guard.identifier.optionsObject(spec, _err, "scep/bad-input", "pki.scep.build spec");
  var mtCode = MESSAGE_TYPE[guard.text.keyOf(spec.messageType)];
  if (mtCode == null) throw _err("scep/bad-message-type", "unknown messageType " + _showValue(spec.messageType) + " (RFC 8894 sec. 3.2.1.2)");
  if (spec.messageType === "CertRep") {
    guard.identifier.assertKnownKeys(spec, _CERTREP_KEYS, _err, "scep/bad-input", "pki.scep.build (CertRep) has an unknown option: ");
    return await _buildCertRep(spec);
  }
  guard.identifier.assertKnownKeys(spec, _REQUEST_KEYS, _err, "scep/bad-input", "pki.scep.build has an unknown option: ");
  if (spec.messageType !== "PKCSReq" && spec.messageType !== "RenewalReq" && spec.messageType !== "CertPoll" && spec.messageType !== "GetCert" && spec.messageType !== "GetCRL") {
    throw _err("scep/bad-message-type", "pki.scep.build issues a request (PKCSReq / RenewalReq / CertPoll / GetCert / GetCRL) or a CertRep response; " + spec.messageType + " is not built in this release");
  }
  if (spec.signer == null || typeof spec.signer !== "object") throw _err("scep/bad-input", "a signer { cert, key } is required");
  var senderNonce = _nonce(spec.senderNonce, "senderNonce");
  var txnId = _transactionId(spec.transactionId);
  var recipient = guard.bytes.snapshotSource(spec.recipient, ScepError, "scep/bad-input", "recipient");
  _assertRsaRecipient(recipient);
  var signerCert = guard.bytes.snapshotSource(spec.signer.cert, ScepError, "scep/bad-input", "signer.cert");
  _assertSigningKeyUsage(signerCert, "signer certificate");
  var signerKey = spec.signer.key;
  var messageData;
  if (spec.messageType === "CertPoll") {
    messageData = _buildIssuerAndSubject(recipient, spec.requestSubject, spec.issuer);
  } else if (spec.messageType === "GetCert" || spec.messageType === "GetCRL") {
    messageData = _buildIssuerAndSerial(spec);
  } else {
    messageData = guard.bytes.snapshotSource(spec.messageData, ScepError, "scep/bad-input", "messageData");
    var parsedCsr;
    try { parsedCsr = schemaCsr.parse(messageData); }
    catch (e) { throw _err("scep/bad-input", "messageData is not a valid PKCS#10 CertificationRequest (RFC 8894 sec. 3.3.1): " + e.message, e); }
    if (!(await csrVerify.verifyCsrSignature(parsedCsr))) {
      throw _err("scep/bad-popo", "the PKCS#10 messageData failed its proof-of-possession: its self-signature does not verify under its own subject public key, so a CA would reject it");
    }
  }
  var pkcsPKIEnvelope;
  try {
    pkcsPKIEnvelope = await cmsEncrypt.encrypt(messageData, [{ cert: recipient }], { contentEncryptionAlgorithm: ENVELOPE_CIPHER });
  } catch (e) {
    if (e && e.isPkiError) throw _err("scep/bad-input", "the pkcsPKIEnvelope could not be built (recipient must be a keyEncipherment CA certificate and messageData a PKCS#10): " + e.message, e);
    throw e;
  }
  var attrs = [
    _attr("scepMessageType", b.printable(mtCode)),
    _attr("scepTransactionId", b.printable(txnId)),
    _attr("scepSenderNonce", b.octetString(senderNonce)),
  ];
  try {
    return await cmsSign.sign(pkcsPKIEnvelope, { cert: signerCert, key: signerKey }, { additionalSignedAttributes: attrs });
  } catch (e) {
    if (e && e.isPkiError) throw _err("scep/bad-input", "the pkiMessage could not be signed: " + e.message, e);
    throw e;
  }
}
var _REQUEST_KEYS = Object.assign(Object.create(null), { messageType: 1, messageData: 1, recipient: 1, requestSubject: 1, issuer: 1, certificate: 1, serialNumber: 1, signer: 1, transactionId: 1, senderNonce: 1 });
var _CERTREP_KEYS = Object.assign(Object.create(null), { messageType: 1, signer: 1, transactionId: 1, senderNonce: 1, pkiStatus: 1, recipientNonce: 1, certificates: 1, crls: 1, recipient: 1, failInfo: 1, failInfoText: 1 });

async function _buildCertRep(spec) {
  if (spec.signer == null || typeof spec.signer !== "object") throw _err("scep/bad-input", "a signer { cert, key } is required");
  if (typeof spec.pkiStatus !== "string") throw _err("scep/bad-input", "a CertRep pkiStatus must be SUCCESS, FAILURE, or PENDING (RFC 8894 sec. 3.2.1.3), got " + _showValue(spec.pkiStatus));
  var statusCode = PKI_STATUS[spec.pkiStatus];
  if (statusCode == null) throw _err("scep/bad-input", "a CertRep pkiStatus must be SUCCESS, FAILURE, or PENDING (RFC 8894 sec. 3.2.1.3), got " + _showValue(spec.pkiStatus));
  var txnId = _transactionId(spec.transactionId);
  if (spec.recipientNonce == null) throw _err("scep/bad-input", "a CertRep must echo the request's senderNonce as recipientNonce (RFC 8894 sec. 3.2.1.5)");
  var recipientNonce = _nonce(spec.recipientNonce, "recipientNonce");
  var senderNonce = _nonce(spec.senderNonce, "senderNonce");
  var signerCert = guard.bytes.snapshotSource(spec.signer.cert, ScepError, "scep/bad-input", "signer.cert");
  var signerKey = spec.signer.key;
  _assertSigningKeyUsage(signerCert, "signer certificate");
  var attrs = [
    _attr("scepMessageType", b.printable(MESSAGE_TYPE.CertRep)),
    _attr("scepTransactionId", b.printable(txnId)),
    _attr("scepSenderNonce", b.octetString(senderNonce)),
    _attr("scepPkiStatus", b.printable(statusCode)),
    _attr("scepRecipientNonce", b.octetString(recipientNonce)),
  ];
  if (spec.pkiStatus !== "FAILURE" && (spec.failInfo != null || spec.failInfoText != null)) {
    throw _err("scep/bad-input", "failInfo and failInfoText are only valid on a FAILURE CertRep (RFC 8894 sec. 3.2.1.4)");
  }
  var content = null;
  if (spec.pkiStatus === "SUCCESS") {
    var certs = spec.certificates != null ? spec.certificates : [];
    var crls = spec.crls != null ? spec.crls : [];
    if (!Array.isArray(certs) || !Array.isArray(crls)) throw _err("scep/bad-input", "a CertRep certificates and crls must be arrays of certificate / CRL DER");
    if (certs.length === 0 && crls.length === 0) throw _err("scep/bad-input", "a SUCCESS CertRep must carry at least one certificate or CRL (RFC 8894 sec. 3.3.2.1)");
    if (spec.recipient == null) throw _err("scep/bad-input", "a SUCCESS CertRep needs a recipient certificate to encrypt the pkcsPKIEnvelope to (RFC 8894 sec. 3.2.2)");
    var recipient = guard.bytes.snapshotSource(spec.recipient, ScepError, "scep/bad-input", "recipient");
    _assertRsaRecipient(recipient);
    var certsOnlyDer;
    try { certsOnlyDer = cmsSign.certsOnly(certs, { crls: crls }); }
    catch (e) { throw _err("scep/bad-input", "a SUCCESS CertRep certificates / crls must be valid certificate / CRL DER (RFC 8894 sec. 3.4): " + e.message, e); }
    try { content = await cmsEncrypt.encrypt(certsOnlyDer, [{ cert: recipient }], { contentEncryptionAlgorithm: ENVELOPE_CIPHER }); }
    catch (e) {
      if (e && e.isPkiError) throw _err("scep/bad-input", "the SUCCESS CertRep pkcsPKIEnvelope could not be built (the recipient must be a keyEncipherment certificate): " + e.message, e);
      throw e;
    }
  } else {
    if (spec.certificates != null || spec.crls != null || spec.recipient != null) {
      throw _err("scep/bad-input", "a " + spec.pkiStatus + " CertRep must omit certificates, crls, and recipient: the pkcsPKIEnvelope is omitted (RFC 8894 sec. 3.3.2." + (spec.pkiStatus === "FAILURE" ? "2" : "3") + ")");
    }
    if (spec.pkiStatus === "FAILURE") {
      var failCode = FAIL_INFO[guard.text.keyOf(spec.failInfo)];
      if (failCode == null) throw _err("scep/bad-input", "a FAILURE CertRep must carry a failInfo of badAlg / badMessageCheck / badRequest / badTime / badCertId (RFC 8894 sec. 3.2.1.4), got " + _showValue(spec.failInfo));
      attrs.push(_attr("scepFailInfo", b.printable(failCode)));
      if (spec.failInfoText != null) attrs.push(_attr("scepFailInfoText", b.utf8(String(spec.failInfoText))));
    }
  }
  var signOpts = { additionalSignedAttributes: attrs };
  var signContent = content;
  if (content == null) { signContent = Buffer.alloc(0); signOpts.detached = true; }
  try {
    return await cmsSign.sign(signContent, { cert: signerCert, key: signerKey }, signOpts);
  } catch (e) {
    if (e && e.isPkiError) throw _err("scep/bad-input", "the CertRep could not be signed: " + e.message, e);
    throw e;
  }
}

function _buildIssuerAndSubject(recipientCertDer, requestSubjectSource, issuerOverride) {
  var subject = guard.bytes.snapshotSource(requestSubjectSource, ScepError, "scep/bad-input", "requestSubject");
  var issuer, issuerNode, subjNode;
  try {
    issuer = issuerOverride != null
      ? guard.bytes.snapshotSource(issuerOverride, ScepError, "scep/bad-input", "issuer")
      : schemaX509.parse(recipientCertDer).subject.bytes;
    issuerNode = asn1.decode(issuer);
    subjNode = asn1.decode(subject);
  } catch (e) {
    if (e instanceof ScepError) throw e;
    throw _err("scep/bad-input", "the CertPoll IssuerAndSubject Names are not valid DER (RFC 8894 sec. 3.3.3): " + e.message, e);
  }
  _assertNameNode(issuerNode, "scep/bad-input", "the CertPoll issuer must be an X.509 Name DER (RFC 8894 sec. 3.3.3)", true);
  _assertNameNode(subjNode, "scep/bad-input", "the CertPoll requestSubject must be an X.509 Name DER (RFC 8894 sec. 3.3.3)");
  return b.sequence([issuer, subject]);
}

function _serialToInteger(s) {
  var n;
  if (typeof s === "bigint") n = s;
  else if (typeof s === "number") { if (!Number.isSafeInteger(s)) throw _err("scep/bad-input", "serialNumber as a number must be a safe integer"); n = BigInt(s); }
  else if (typeof s === "string" && s.length > 0) {
    var t = (s.slice(0, 2) === "0x" || s.slice(0, 2) === "0X") ? s.slice(2) : s;
    try { n = BigInt("0x" + t); } catch (_e) { throw _err("scep/bad-input", "serialNumber must be a hex string, a non-negative safe integer, or a BigInt: " + _showValue(s)); }
  } else {
    throw _err("scep/bad-input", "serialNumber must be a hex string, a non-negative safe integer, or a BigInt");
  }
  if (n <= 0n) throw _err("scep/bad-input", "serialNumber must be a positive integer (RFC 5280 sec. 4.1.2.2)");
  return n;
}

function _assertNameNode(node, code, message, requireNonEmpty) {
  var walked;
  try { walked = schema.walk(pkix.name(_KU_NS), node, _KU_NS); }
  catch (e) {
    throw _err(code, message + " (RFC 5280 sec. 4.1.2.4): " + e.message, e);
  }
  if (requireNonEmpty && !walked.result.rdns.length) {
    throw _err(code, message + ": a distinguished name naming a certificate issuer must be non-empty (RFC 5280 sec. 4.1.2.4)");
  }
}

function _buildIssuerAndSerial(spec) {
  var hasCert = spec.certificate != null;
  var hasExplicit = spec.issuer != null || spec.serialNumber != null;
  if (hasCert === hasExplicit) throw _err("scep/bad-input", "a GetCert / GetCRL query needs exactly one of { certificate } or { issuer, serialNumber } (RFC 8894 sec. 3.3.4)");
  var issuer, serial;
  if (hasCert) {
    var cert = guard.bytes.snapshotSource(spec.certificate, ScepError, "scep/bad-input", "certificate");
    try { var w = schemaX509.parse(cert); issuer = w.issuer.bytes; serial = w.serialNumber; }
    catch (e) { throw _err("scep/bad-input", "certificate is not a parseable X.509 certificate (RFC 8894 sec. 3.3.4): " + e.message, e); }
  } else {
    if (spec.issuer == null || spec.serialNumber == null) throw _err("scep/bad-input", "the explicit form of a GetCert / GetCRL query needs both issuer and serialNumber (RFC 8894 sec. 3.3.4)");
    serial = _serialToInteger(spec.serialNumber);
    issuer = guard.bytes.snapshotSource(spec.issuer, ScepError, "scep/bad-input", "issuer");
    var node;
    try { node = asn1.decode(issuer); } catch (e) { throw _err("scep/bad-input", "issuer is not a valid Name DER (RFC 8894 sec. 3.3.4): " + e.message, e); }
    _assertNameNode(node, "scep/bad-input", "issuer must be an X.509 Name DER (RFC 8894 sec. 3.3.4)", true);
  }
  if (serial <= 0n) throw _err("scep/bad-input", "the query serialNumber must be a positive integer; a certificate with a non-positive serial cannot be named in a conforming query (RFC 5280 sec. 4.1.2.2)");
  var serialTlv = b.integer(serial);
  if (asn1.decode(serialTlv).content.length > 20) throw _err("scep/bad-input", "the query serialNumber must not exceed 20 octets (RFC 5280 sec. 4.1.2.2)");
  return b.sequence([issuer, serialTlv]);
}

/**
 * @primitive  pki.scep.parse
 * @signature  pki.scep.parse(bytes, opts?) -> Promise<verdict>
 * @since      0.6.2
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.build, pki.cms.verify, pki.cms.decrypt
 *
 * Disassemble a SCEP pkiMessage (RFC 8894 sec. 3): verify the outer SignedData signature, read the
 * transaction attributes BOUND to the verified signer (never from a separate untrusted parse), and,
 * given the recipient key, decrypt the pkcsPKIEnvelope to recover the messageData. It reads the
 * message types PKCSReq, RenewalReq, CertRep, CertPoll, GetCert, and GetCRL; a messageType the RFC 8894
 * registry does not define is refused (`scep/bad-message-type`). The verdict is
 * `{ signatureValid, signerAuthenticated, signerCert, messageType, transactionId, senderNonce,
 * recipientNonce, pkiStatus, failInfo, failInfoText, messageData, certificates, crls }` (fields null
 * when the message does not carry them). For a decrypted SUCCESS CertRep, `certificates` and `crls`
 * hold the issued certificate(s) and any CRL validated out of the certs-only messageData, raw for the
 * caller to path-validate; a GetCRL response carries the CRL and no certificate (RFC 8894 sec. 3.3.4). A malformed message, a missing mandatory attribute, an unknown enumerant, or a
 * nonce mismatch is a typed `ScepError`.
 *
 * `signatureValid` proves only that the message is self-consistent with the certificate it embeds; it
 * does NOT authenticate the signer. A SCEP client MUST authenticate a CA response against the CA
 * certificate it holds: pass `opts.signerCert` and this refuses a signer whose public key does not
 * match (`scep/untrusted-signer`) and reports `signerAuthenticated: true`. A caller that omits it gets
 * a crypto-only verdict (`signerAuthenticated: false`) and MUST authenticate the surfaced `signerCert`
 * itself before acting on the transaction state.
 *
 * @opts
 *   - `recipientKey` -- `{ cert, key }` for the recipient, to decrypt the pkcsPKIEnvelope into `messageData`.
 *   - `signerCert` -- the expected signer certificate DER (the CA certificate for a CertRep); the message signer's public key must match it, or the message is refused.
 *   - `expectedSenderNonce` -- a 16-byte Buffer; a message whose `recipientNonce` does not echo it is refused.
 * @example
 *   // requires: pkiMessage -- a SCEP pkiMessage DER (from pki.scep.build, or a CA's response)
 *   // requires: caCertDer -- the recipient certificate the pkcsPKIEnvelope was encrypted to
 *   // requires: caKeyPkcs8 -- the private key matching caCertDer, to decrypt the messageData
 *   var v = await pki.scep.parse(pkiMessage, { recipientKey: { cert: caCertDer, key: caKeyPkcs8 } });
 *   v.messageType;   // "PKCSReq"
 *   v.messageData;   // the recovered PKCS#10 DER
 */
async function parse(bytes, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep.parse options");
  guard.identifier.assertKnownKeys(opts, _PARSE_KEYS, _err, "scep/bad-input", "pki.scep.parse has an unknown option: ");
  var msgBytes = guard.bytes.snapshotSource(bytes, ScepError, "scep/bad-der", "pkiMessage");
  var expectedSignerCert = opts.signerCert != null ? guard.bytes.snapshotSource(opts.signerCert, ScepError, "scep/bad-input", "opts.signerCert") : null;
  var expectedSenderNonce = opts.expectedSenderNonce != null ? _nonce(opts.expectedSenderNonce, "expectedSenderNonce") : null;
  var recipientKey = _captureRecipientKey(opts.recipientKey);
  var v;
  try { v = await cmsVerify.verify(msgBytes); }
  catch (e) {
    if (e && e.code === "cms/detached-content-required") {
      try { v = await cmsVerify.verify(msgBytes, { content: EMPTY_CONTENT }); }
      catch (e2) {
        if (e2 && e2.isPkiError) throw _err("scep/bad-der", "the pkiMessage is not a verifiable CMS SignedData (RFC 8894 sec. 3): " + e2.message, e2);
        throw e2;
      }
    } else if (e && e.isPkiError) {
      throw _err("scep/bad-der", "the pkiMessage is not a verifiable CMS SignedData (RFC 8894 sec. 3): " + e.message, e);
    } else { throw e; }
  }
  if (v.signers.length !== 1) throw _err("scep/bad-signer", "a SCEP pkiMessage MUST carry exactly one SignerInfo (RFC 8894 sec. 3.1), got " + v.signers.length);
  if (v.valid !== true) throw _err("scep/bad-signature", "the pkiMessage outer signature did not verify (RFC 8894 sec. 3.1)");
  if (v.eContentType !== oid.byName("data")) throw _err("scep/bad-content-type", "the pkiMessage eContentType must be id-data (RFC 8894 sec. 3.2)");
  var signer = v.signers[0];
  _assertSigningKeyUsage(signer.cert, "pkiMessage signer certificate");
  var signerAuthenticated = false;
  if (expectedSignerCert != null) {
    _assertSigningKeyUsage(expectedSignerCert, "opts.signerCert");
    if (!_sameKey(signer.cert, expectedSignerCert)) {
      throw _err("scep/untrusted-signer", "the pkiMessage signer's public key does not match opts.signerCert (RFC 8894 sec. 3.1)");
    }
    signerAuthenticated = true;
  }
  var attrs = signer.signedAttributes;
  var messageTypeCode = _readStr(attrs, "scepMessageType", _T_PRINTABLE);
  var transactionId = _readStr(attrs, "scepTransactionId", _T_PRINTABLE);
  var senderNonce = _readNonce(attrs, "scepSenderNonce");
  if (messageTypeCode == null) throw _err("scep/missing-attribute", "the pkiMessage is missing its messageType attribute (RFC 8894 sec. 3.2.1)");
  if (transactionId == null) throw _err("scep/missing-attribute", "the pkiMessage is missing its transactionID attribute (RFC 8894 sec. 3.2.1)");
  if (senderNonce == null) throw _err("scep/missing-attribute", "the pkiMessage is missing its senderNonce attribute (RFC 8894 sec. 3.2.1)");
  var messageType = MESSAGE_TYPE_BY_CODE[messageTypeCode];
  if (messageType == null) throw _err("scep/bad-message-type", "unknown messageType " + JSON.stringify(messageTypeCode) + " (RFC 8894 sec. 3.2.1.2)");
  if (_PARSE_SUPPORTED[messageType] !== 1) {
    throw _err("scep/unsupported-message-type", "pki.scep.parse reads " + Object.keys(_PARSE_SUPPORTED).join(", ") + "; " + messageType + " is not read in this release");
  }
  var out = {
    signatureValid: true, signerAuthenticated: signerAuthenticated, signerCert: signer.cert,
    messageType: messageType, transactionId: transactionId, senderNonce: senderNonce,
    recipientNonce: null, pkiStatus: null, failInfo: null, failInfoText: null, messageData: null,
    certificates: null, crls: null,
  };
  if (messageType === "CertRep") {
    var statusCode = _readStr(attrs, "scepPkiStatus", _T_PRINTABLE);
    if (statusCode == null) throw _err("scep/missing-attribute", "a CertRep is missing its pkiStatus attribute (RFC 8894 sec. 3.2.1.3)");
    out.pkiStatus = PKI_STATUS_BY_CODE[statusCode];
    if (out.pkiStatus == null) throw _err("scep/bad-pki-status", "unknown pkiStatus " + JSON.stringify(statusCode) + " (RFC 8894 sec. 3.2.1.3)");
    out.recipientNonce = _readNonce(attrs, "scepRecipientNonce");
    if (out.recipientNonce == null) throw _err("scep/missing-attribute", "a CertRep is missing its recipientNonce attribute (RFC 8894 sec. 3.2.1.5)");
    if (out.pkiStatus === "FAILURE") {
      var failCode = _readStr(attrs, "scepFailInfo", _T_PRINTABLE);
      if (failCode == null) throw _err("scep/missing-attribute", "a FAILURE CertRep is missing its failInfo attribute (RFC 8894 sec. 3.2.1.4)");
      out.failInfo = FAIL_INFO_BY_CODE[failCode];
      if (out.failInfo == null) throw _err("scep/bad-fail-info", "unknown failInfo " + JSON.stringify(failCode) + " (RFC 8894 sec. 3.2.1.4)");
      out.failInfoText = _readStr(attrs, "scepFailInfoText", _T_UTF8);
    } else if (_find(attrs, "scepFailInfo") != null || _find(attrs, "scepFailInfoText") != null) {
      throw _err("scep/unexpected-attribute", "a " + out.pkiStatus + " CertRep must not carry a failInfo or failInfoText attribute (RFC 8894 sec. 3.2.1.4)");
    }
  } else {
    if (_find(attrs, "scepPkiStatus") != null || _find(attrs, "scepFailInfo") != null ||
        _find(attrs, "scepFailInfoText") != null || _find(attrs, "scepRecipientNonce") != null) {
      throw _err("scep/unexpected-attribute", "a " + messageType + " request must not carry a CertRep response attribute, pkiStatus / failInfo / failInfoText / recipientNonce (RFC 8894 sec. 3.2.1)");
    }
  }
  if (expectedSenderNonce != null) {
    if (out.recipientNonce == null || !guard.crypto.constantTimeEqual(out.recipientNonce, expectedSenderNonce)) {
      throw _err("scep/nonce-mismatch", "the pkiMessage recipientNonce does not echo the sent senderNonce (RFC 8894 sec. 3.2.1.5)");
    }
  }
  var carriesEnvelope = !(messageType === "CertRep" && (out.pkiStatus === "FAILURE" || out.pkiStatus === "PENDING"));
  if (carriesEnvelope) {
    _assertValidEnvelope(v.eContent, messageType);
  } else {
    if (v.eContent != null) {
      throw _err("scep/unexpected-envelope", "a " + out.pkiStatus + " CertRep must omit the pkcsPKIEnvelope (RFC 8894 sec. 3.3.2), but it carries encapsulated content");
    }
  }
  if (recipientKey != null && carriesEnvelope && v.eContent != null) {
    var dec;
    try { dec = await cmsDecrypt.decrypt(v.eContent, recipientKey); }
    catch (e) {
      if (e && e.isPkiError) throw _err("scep/decrypt-failed", "the pkcsPKIEnvelope could not be decrypted with the recipient key: " + e.message, e);
      throw e;
    }
    out.messageData = dec.content;
    if (messageType === "CertRep" && out.pkiStatus === "SUCCESS") {
      var payload = _readIssuancePayload(dec.content);
      out.certificates = payload.certificates;
      out.crls = payload.crls;
    } else if (messageType === "PKCSReq" || messageType === "RenewalReq") {
      try { schemaCsr.parse(dec.content); }
      catch (e) { throw _err("scep/bad-request-payload", "a " + messageType + " messageData must be a PKCS#10 CertificationRequest (RFC 8894 sec. 3.3.1)", e); }
    } else if (messageType === "CertPoll") {
      var ias;
      try { ias = asn1.decode(dec.content); }
      catch (e) { throw _err("scep/bad-request-payload", "a CertPoll messageData must be an IssuerAndSubject (RFC 8894 sec. 3.3.3)", e); }
      var iasCh = pkix.rootSequenceChildren(ias, 2, 2);
      if (!iasCh) throw _err("scep/bad-request-payload", "a CertPoll messageData must be an IssuerAndSubject: a SEQUENCE of two Name values (RFC 8894 sec. 3.3.3)");
      _assertNameNode(iasCh[0], "scep/bad-request-payload", "a CertPoll messageData issuer must be an X.509 Name (RFC 8894 sec. 3.3.3)", true);
      _assertNameNode(iasCh[1], "scep/bad-request-payload", "a CertPoll messageData requestSubject must be an X.509 Name (RFC 8894 sec. 3.3.3)");
    } else if (messageType === "GetCert" || messageType === "GetCRL") {
      var isn;
      try { isn = asn1.decode(dec.content); }
      catch (e) { throw _err("scep/bad-request-payload", "a " + messageType + " messageData must be an IssuerAndSerialNumber (RFC 8894 sec. 3.3.4)", e); }
      var isnCh = pkix.rootSequenceChildren(isn, 2, 2);
      if (!isnCh) throw _err("scep/bad-request-payload", "a " + messageType + " messageData must be an IssuerAndSerialNumber: a SEQUENCE of a Name and an INTEGER (RFC 8894 sec. 3.3.4)");
      _assertNameNode(isnCh[0], "scep/bad-request-payload", "a " + messageType + " messageData issuer must be an X.509 Name (RFC 8894 sec. 3.3.4)", true);
      var isnSerial;
      try { isnSerial = asn1.read.integer(isnCh[1]); }
      catch (e) { throw _err("scep/bad-request-payload", "a " + messageType + " messageData serialNumber must be a DER INTEGER (RFC 8894 sec. 3.3.4)", e); }
      if (isnSerial <= 0n) throw _err("scep/bad-request-payload", "a " + messageType + " messageData serialNumber must be a positive integer (RFC 5280 sec. 4.1.2.2)");
      if (isnCh[1].content.length > 20) throw _err("scep/bad-request-payload", "a " + messageType + " messageData serialNumber must not exceed 20 octets (RFC 5280 sec. 4.1.2.2)");
    }
  }
  return out;
}
var _PARSE_KEYS = Object.assign(Object.create(null), { recipientKey: 1, expectedSenderNonce: 1, signerCert: 1 });

var DEFAULT_TIMEOUT = C.TIME.seconds(30);
var MAX_TIMEOUT = C.TIME.seconds(600);

var CT_CA_CERT = "application/x-x509-ca-cert";
var CT_CA_RA_CERT = "application/x-x509-ca-ra-cert";
var CT_PKI_MESSAGE = "application/x-pki-message";
var CT_NEXT_CA_CERT = "application/x-x509-next-ca-cert";
var CT_PLAIN = "text/plain";

function _isWs(c) { return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x0b || c === 0x0c; }
function _foldLower(s) { var o = "", i, n = s.length; for (i = 0; i < n; i++) { var c = s.charCodeAt(i); o += String.fromCharCode(c >= 65 && c <= 90 ? c + 32 : c); } return o; }
function _foldUpper(s) { var o = "", i, n = s.length; for (i = 0; i < n; i++) { var c = s.charCodeAt(i); o += String.fromCharCode(c >= 97 && c <= 122 ? c - 32 : c); } return o; }
function _trim(s) { var a = 0, e = s.length; while (a < e && _isWs(s.charCodeAt(a))) a += 1; while (e > a && _isWs(s.charCodeAt(e - 1))) e -= 1; return s.slice(a, e); }

function _header(headers, name) {
  if (!headers || typeof headers !== "object") return null;
  var found = null, seen = 0, k;
  for (k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    if (_foldLower(String(k)) === name) { found = headers[k]; seen += 1; }
  }
  if (seen > 1) throw _err("scep/bad-response", "the response carried more than one " + name + " header");
  return found == null ? null : String(found);
}
function _mediaType(ct) {
  if (ct == null) return "";
  var s = String(ct), semi = s.indexOf(";");
  return _foldLower(_trim(semi === -1 ? s : s.slice(0, semi)));
}
function _bodyBuf(body) {
  if (Buffer.isBuffer(body)) return body;
  if (body == null) return Buffer.alloc(0);
  if (typeof body === "string") return Buffer.from(body, "utf8");
  return guard.bytes.snapshotSource(body, ScepError, "scep/bad-response", "the response body");
}
function _responseLen(body) {
  if (body == null) return 0;
  if (typeof body === "string") return Buffer.byteLength(body, "utf8");
  if (Buffer.isBuffer(body)) return guard.bytes.lengthOf(body);
  return guard.bytes.lengthOf(guard.bytes.source(body, ScepError, "scep/bad-response", "the response body"));
}
function _tlsForRequest(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}
function _redirectTarget(current, location, method, allowCrossOrigin) {
  if (location == null || _trim(String(location)) === "") throw _err("scep/bad-response", "a redirect response carried no Location header");
  var resolved;
  try { resolved = new URL(String(location), current.href); }
  catch (e) { throw _err("scep/bad-url", "a redirect Location did not parse: " + location, e); }
  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") throw _err("scep/bad-url", "a redirect to a non-HTTP scheme is refused: " + resolved.protocol);
  if (current.protocol === "https:" && resolved.protocol !== "https:") throw _err("scep/insecure-redirect", "a redirect from https to " + resolved.protocol + " is refused");
  var safe = method === "GET" || method === "HEAD";
  if (resolved.origin !== current.origin && !safe && !allowCrossOrigin) throw _err("scep/cross-origin-redirect", "a cross-origin redirect on a " + method + " needs opts.allowCrossOriginRedirect");
  return resolved;
}
function _scepUrl(baseUrl, operation) {
  var url;
  try { url = new URL(String(baseUrl)); }
  catch (e) { throw _err("scep/bad-url", "the SCEP base URL did not parse: " + _showValue(baseUrl), e); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw _err("scep/bad-url", "the SCEP base URL must be http or https, got " + url.protocol);
  if (url.hash) throw _err("scep/bad-url", "the SCEP base URL must not carry a fragment");
  url.searchParams.set("operation", operation);
  return url;
}
function _pkiMethod(opts) {
  var m = opts.httpMethod;
  if (m == null) return "POST";
  if (m !== "POST" && m !== "GET") throw _err("scep/bad-input", "httpMethod must be \"POST\" or \"GET\" (RFC 8894 sec. 4.1), got " + _showValue(m));
  return m;
}
function _pkiRequest(method, opUrl, reqMsg, clientOpts) {
  if (method === "GET") {
    var getUrl = new URL(opUrl.href);
    getUrl.searchParams.set("message", Buffer.from(reqMsg).toString("base64"));
    return _client("GET", getUrl, null, {}, clientOpts);
  }
  return _client("POST", opUrl, reqMsg, { "content-type": CT_PKI_MESSAGE }, clientOpts);
}
function _drive(method, url, body, headers, opts, transport, budgets) {
  var redirects = 0, curMethod = method, curBody = body, initialOrigin = url.origin;
  var proxySnap = _snapshotProxy(opts.proxy);
  var tlsBase = _tlsForRequest(opts);
  var allowCrossOrigin = !!opts.allowCrossOriginRedirect;
  function _hopTls(current) {
    var t = tlsBase;
    if (current.origin !== initialOrigin) {
      t = Object.assign({}, t);
      t.cert = null; t.key = null; t.servername = null;
    }
    return t;
  }
  function step(current) {
    var req = { method: curMethod, url: current.href, headers: headers, tls: _hopTls(current), timeout: budgets.timeout, maxResponseBytes: budgets.maxResponseBytes };
    if (proxySnap != null) req.proxy = proxySnap;
    if (curBody != null) req.body = curBody;
    return guard.async.invoked(transport, [req], _err, "scep/bad-input", "opts.transport").then(function (res) {
      res = res || {};
      var blen = _responseLen(res.body);
      if (blen > budgets.maxResponseBytes) throw _err("scep/response-too-large", "the response body (" + blen + " bytes) exceeds the " + budgets.maxResponseBytes + "-byte cap");
      var status = res.status;
      if (status >= 300 && status < 400) {
        if (redirects >= budgets.maxRedirects) throw _err("scep/too-many-redirects", "the SCEP request exceeded the " + budgets.maxRedirects + "-redirect cap");
        redirects += 1;
        var target = _redirectTarget(current, _header(res.headers, "location"), curMethod, allowCrossOrigin);
        if (status === 303 && curMethod !== "GET" && curMethod !== "HEAD") { curMethod = "GET"; curBody = null; }
        return step(target);
      }
      return res;
    });
  }
  return step(url);
}
function _snapshotProxy(p) { return httpTransport.snapshotProxy(p); }

/** @internal Refused at every network verb's door and again where the value is used. */
function _assertTransport(opts) {
  guard.identifier.assertCallableOption(opts, "transport", _err, "scep/bad-input", "opts.transport",
    "(request) => Promise<{ status, headers, body }>");
}

function _client(method, url, body, headers, opts) {
  _assertTransport(opts);
  var transport = opts.transport || httpTransport.https({ E: _err, errPrefix: "scep" });
  var budgets = {
    timeout: guard.limits.cap(opts.timeout, "timeout", DEFAULT_TIMEOUT, { E: _err, code: "scep/bad-input", min: 1, max: MAX_TIMEOUT }),
    maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", C.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: _err, code: "scep/bad-input", min: 1, max: C.LIMITS.HTTP_MAX_RESPONSE_BYTES }),
    maxRedirects: guard.limits.cap(opts.maxRedirects, "maxRedirects", 5, { E: _err, code: "scep/bad-input", min: 0, max: 32 }),
  };
  return _drive(method, url, body, Object.assign({}, headers), opts, transport, budgets);
}
function _requireOk(res, expected, what) {
  var status = res.status;
  if (status !== 200) {
    var text = Buffer.isBuffer(res.body) ? res.body.toString("utf8", 0, 256) : String(res.body == null ? "" : res.body).slice(0, 256);
    throw _err("scep/http-error", "the SCEP " + what + " returned HTTP " + status + (text ? ": " + text : ""));
  }
  if (expected) {
    var ct = _mediaType(_header(res.headers, "content-type"));
    if (expected.indexOf(ct) === -1) throw _err("scep/bad-content-type", "a 200 " + what + " response must carry content-type " + expected.join(" or ") + ", got " + JSON.stringify(ct));
  }
  return _bodyBuf(res.body);
}

var CAP_CANON = Object.assign(Object.create(null), { AES: "AES", DES3: "DES3", GETNEXTCACERT: "GetNextCACert", POSTPKIOPERATION: "POSTPKIOperation",
  RENEWAL: "Renewal", "SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-512": "SHA-512", SCEPSTANDARD: "SCEPStandard" });
function _splitLines(s) {
  var out = [], start = 0, i, n = s.length;
  for (i = 0; i < n; i++) if (s.charCodeAt(i) === 0x0a) { out.push(s.slice(start, i)); start = i + 1; }
  out.push(s.slice(start));
  return out;
}

/**
 * @primitive  pki.scep.parseCapabilities
 * @signature  pki.scep.parseCapabilities(text) -> { AES?, "SHA-256"?, POSTPKIOperation?, ... }
 * @since      0.6.7
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.getCACaps
 *
 * Parse a GetCACaps response body (RFC 8894 sec. 3.5.2): one capability keyword per line, CR/LF or LF
 * delimited. The returned object has a `true` property for each recognized keyword (`AES`, `DES3`,
 * `GetNextCACert`, `POSTPKIOperation`, `Renewal`, `SHA-1`, `SHA-256`, `SHA-512`, `SCEPStandard`);
 * comparison is case-insensitive and an unknown keyword is ignored (sec. 3.5.2). `SCEPStandard` implies
 * `AES`, `POSTPKIOperation`, and `SHA-256` (the sec. 2.9 mandatory profile), which are set on the result.
 * An empty body yields an empty set ("none supported", sec. 3.5.1).
 *
 * @example
 *   var caps = pki.scep.parseCapabilities("AES\r\nSHA-256\r\nPOSTPKIOperation\r\n");
 *   caps.POSTPKIOperation === true;
 */
function parseCapabilities(text) {
  var raw = Buffer.isBuffer(text) ? text.toString("latin1") : String(text == null ? "" : text);
  var set = Object.create(null), lines = _splitLines(raw), i;
  for (i = 0; i < lines.length; i++) {
    var kw = _foldUpper(_trim(lines[i]));
    if (kw !== "" && CAP_CANON[kw]) set[CAP_CANON[kw]] = true;
  }
  if (set.SCEPStandard) { set.AES = true; set.POSTPKIOperation = true; set["SHA-256"] = true; }
  return set;
}
function _assertStrongProfile(caps, profile) {
  if (profile.expectSCEPStandard && !caps.SCEPStandard) throw _err("scep/weak-profile", "the CA did not advertise SCEPStandard (RFC 8894 sec. 3.5.2); the GetCACaps response is unauthenticated, so its absence is a downgrade signal (sec. 7.5)");
  if (profile.requireStrongProfile && (!caps.AES || !caps["SHA-256"] || !caps.POSTPKIOperation)) throw _err("scep/weak-profile", "the CA did not advertise the strong profile (AES + SHA-256 + POSTPKIOperation)");
}

/**
 * @primitive  pki.scep.getCACaps
 * @signature  pki.scep.getCACaps(baseUrl, opts?) -> Promise<capabilities>
 * @since      0.6.7
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.parseCapabilities, pki.scep.enroll
 *
 * Query a SCEP CA's advertised capabilities (RFC 8894 sec. 3.5.1): a GET `?operation=GetCACaps` whose
 * `text/plain` body is parsed by `parseCapabilities`. The GetCACaps response is UNAUTHENTICATED (sec.
 * 7.5), so a client MUST NOT downgrade its algorithm choice based on it; this verb only reports what the
 * CA claims. Pass `expectSCEPStandard: true` (or `requireStrongProfile: true`) to fail closed when the
 * strong profile is absent, treating the absence as the downgrade signal it is.
 *
 * @opts
 *   - `transport` -- an injected transport (defaults to `pki.transport.https`); the request is a GET with no body.
 *   - `expectSCEPStandard` -- refuse (`scep/weak-profile`) if the response does not advertise `SCEPStandard`.
 *   - `requireStrongProfile` -- refuse unless AES + SHA-256 + POSTPKIOperation are all advertised.
 *   - `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` / `proxy` -- transport bounds (`proxy` reaches the CA through a forward HTTP proxy; see pki.transport).
 * @example
 *   // requires: scepTransport -- an injected transport (omit to use pki.transport.https)
 *   var caps = await pki.scep.getCACaps("http://ca.example/scep", { transport: scepTransport });
 *   caps.AES === true;
 */
async function getCACaps(baseUrl, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep.getCACaps options");
  guard.identifier.assertKnownKeys(opts, _CACAPS_KEYS, _err, "scep/bad-input", "pki.scep.getCACaps has an unknown option: ");
  _assertTransport(opts);
  var profile = { expectSCEPStandard: !!opts.expectSCEPStandard, requireStrongProfile: !!opts.requireStrongProfile };
  var res = await _client("GET", _scepUrl(baseUrl, "GetCACaps"), null, {}, opts);
  if (res.status === 200) {
    var caps = parseCapabilities(_requireOk(res, [CT_PLAIN], "GetCACaps"));
    _assertStrongProfile(caps, profile);
    return caps;
  }
  if (res.status === 204 || res.status === 400 || res.status === 404 || res.status === 405 || res.status === 501) { _assertStrongProfile({}, profile); return {}; }
  throw _err("scep/http-error", "the SCEP GetCACaps returned HTTP " + res.status);
}

function findIssuedCert(certs, wantSpki) {
  if (!Buffer.isBuffer(wantSpki)) return null;
  for (var i = 0; i < certs.length; i++) {
    var spki;
    try { spki = schemaX509.parse(certs[i]).subjectPublicKeyInfo; }
    catch (_e) { continue; }
    if (spki && Buffer.isBuffer(spki.bytes) && spki.bytes.equals(wantSpki)) return certs[i];
  }
  return null;
}
function _normalizeFingerprint(fp, algName) {
  var algorithm = _foldLower(String(algName == null ? "sha256" : algName));
  try { nodeCrypto.createHash(algorithm); }
  catch (_e) { throw _err("scep/bad-input", "fingerprintAlgorithm " + _showValue(algorithm) + " is not an available hash"); }
  var value;
  if (Buffer.isBuffer(fp)) value = Buffer.from(fp);
  else if (typeof fp === "string") {
    var hex = "", i, n = fp.length;
    for (i = 0; i < n; i++) {
      var c = fp.charCodeAt(i);
      if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70)) hex += fp.charAt(i);
      else if (c === 0x3a || c === 0x20) continue;
      else throw _err("scep/bad-input", "expectedFingerprint must be a hex string or a Buffer");
    }
    if (hex.length === 0 || hex.length % 2 !== 0) throw _err("scep/bad-input", "expectedFingerprint hex has an odd or zero length");
    value = Buffer.from(hex, "hex");
  } else throw _err("scep/bad-input", "expectedFingerprint must be a hex string or a Buffer");
  return { algorithm: algorithm, value: value };
}

/**
 * @primitive  pki.scep.getCACert
 * @signature  pki.scep.getCACert(baseUrl, opts?) -> Promise<{ caCertificate, certificates }>
 * @since      0.6.7
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.enroll, pki.path.validate
 *
 * Retrieve a SCEP CA's certificate (RFC 8894 sec. 4.2): a GET `?operation=GetCACert` returning either a
 * single DER certificate (`application/x-x509-ca-cert`) or a certs-only CMS chain
 * (`application/x-x509-ca-ra-cert`). GetCACert is served in the clear; the ONLY authentication is an
 * out-of-band fingerprint (RFC 8894 sec. 2.2). Pass `expectedFingerprint` (a hex string or Buffer, with
 * `fingerprintAlgorithm` defaulting to SHA-256) and this refuses (`scep/fingerprint-mismatch`) unless a
 * returned certificate matches it, returning that certificate as `caCertificate`. A single-certificate
 * response is unambiguously the CA, so `caCertificate` holds it. A ca-ra chain lists the CA, any
 * intermediates, and RA certificate(s) in a CMS order that does not identify the CA role, so without a
 * fingerprint `caCertificate` is null and the caller reads `certificates` to identify and authenticate
 * the CA itself.
 *
 * @opts
 *   - `expectedFingerprint` -- a hex string or Buffer; a returned certificate must hash to it, or the response is refused.
 *   - `fingerprintAlgorithm` -- the hash for the fingerprint (default "sha256").
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` / `proxy` -- transport bounds (`proxy` reaches the CA through a forward HTTP proxy; see pki.transport).
 * @example
 *   // requires: scepCaCertTransport -- an injected transport returning a single CA certificate
 *   var ca = await pki.scep.getCACert("http://ca.example/scep", { transport: scepCaCertTransport });
 *   ca.caCertificate;   // the CA certificate DER (a single-certificate response identifies it)
 */
async function getCACert(baseUrl, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep.getCACert options");
  guard.identifier.assertKnownKeys(opts, _CACERT_KEYS, _err, "scep/bad-input", "pki.scep.getCACert has an unknown option: ");
  _assertTransport(opts);
  var fp = opts.expectedFingerprint != null ? _normalizeFingerprint(opts.expectedFingerprint, opts.fingerprintAlgorithm) : null;
  var res = await _client("GET", _scepUrl(baseUrl, "GetCACert"), null, {}, opts);
  var body = _requireOk(res, [CT_CA_CERT, CT_CA_RA_CERT], "GetCACert");
  var ct = _mediaType(_header(res.headers, "content-type")), certs, single = false;
  if (ct === CT_CA_CERT) {
    try { schemaX509.parse(body); } catch (e) { throw _err("scep/bad-response", "the GetCACert response is not a valid X.509 certificate", e); }
    certs = [Buffer.from(body)];
    single = true;
  } else {
    certs = schemaCms.parseCertsOnly(body, _err, "scep").certificates;
  }
  var caCertificate = null;
  if (fp != null) {
    var matched = null, j;
    for (j = 0; j < certs.length; j++) {
      var got = nodeCrypto.createHash(fp.algorithm).update(certs[j]).digest();
      if (got.length === fp.value.length && got.equals(fp.value)) { matched = certs[j]; break; }
    }
    if (!matched) throw _err("scep/fingerprint-mismatch", "no GetCACert certificate matched the expected " + fp.algorithm + " fingerprint (RFC 8894 sec. 2.2)");
    caCertificate = matched;
  } else if (single) {
    caCertificate = certs[0];
  }
  return { caCertificate: caCertificate, certificates: certs };
}

/**
 * @primitive  pki.scep.getNextCACert
 * @signature  pki.scep.getNextCACert(baseUrl, opts) -> Promise<{ certificates }>
 * @since      0.6.14
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.getCACert, pki.cms.verify
 *
 * Retrieve a SCEP CA's next (rollover) certificate (RFC 8894 sec. 4.7): a GET
 * `?operation=GetNextCACert` returning a SignedData signed by the CURRENT CA signing key
 * (`application/x-x509-next-ca-cert`), whose content is a degenerate certs-only SignedData carrying the
 * CA certificate(s) to install when the current one expires. The current CA certificate the caller
 * already holds authenticates the response: the outer signature is verified AND pinned to that
 * certificate's key, so a self-consistent CMS signed by any other (embedded) certificate is refused
 * (`scep/untrusted-signer`) rather than trusted as the rollover certificate. `caCertificate` is
 * required; an unauthenticated rollover certificate becomes a future trust anchor, so it is refused
 * rather than returned. The verified next certificate(s) are returned in `certificates`.
 *
 * @opts
 *   - `caCertificate` -- the current SCEP CA certificate DER; the response is authenticated against its key (required).
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` / `proxy` -- transport bounds (`proxy` reaches the CA through a forward HTTP proxy; see pki.transport).
 * @example
 *   // requires: caCertDer -- the current CA certificate (from getCACert), scepTransport
 *   var next = await pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: caCertDer, transport: scepTransport });
 *   next.certificates[0];   // the next CA certificate DER, to install when the current one expires
 */
async function getNextCACert(baseUrl, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep.getNextCACert options");
  guard.identifier.assertKnownKeys(opts, _NEXTCACERT_KEYS, _err, "scep/bad-input", "pki.scep.getNextCACert has an unknown option: ");
  _assertTransport(opts);
  if (opts.caCertificate == null) throw _err("scep/bad-input", "a caCertificate (the current SCEP CA certificate DER) is required to authenticate the GetNextCACert response (RFC 8894 sec. 4.7.1)");
  var currentCa = guard.bytes.snapshotSource(opts.caCertificate, ScepError, "scep/bad-input", "the caCertificate");
  _assertSigningKeyUsage(currentCa, "the caCertificate");
  var url = _scepUrl(baseUrl, "GetNextCACert");
  var res = await _client("GET", url, null, {}, opts);
  var body = _requireOk(res, [CT_NEXT_CA_CERT], "GetNextCACert");
  var v;
  try { v = await cmsVerify.verify(body, { certs: [currentCa] }); }
  catch (e) {
    if (e && e.code === "cms/detached-content-required") throw _err("scep/bad-response", "the GetNextCACert SignedData has no content; the rollover certificate(s) are the content (RFC 8894 sec. 4.7.1)", e);
    if (e && e.isPkiError) throw _err("scep/bad-response", "the GetNextCACert response is not a verifiable CMS SignedData (RFC 8894 sec. 4.7.1): " + e.message, e);
    throw e;
  }
  if (v.signers.length !== 1) throw _err("scep/bad-signer", "a GetNextCACert response must carry exactly one SignerInfo (RFC 8894 sec. 4.7.1), got " + v.signers.length);
  if (v.valid !== true) throw _err("scep/bad-signature", "the GetNextCACert outer signature did not verify (RFC 8894 sec. 4.7.1)");
  if (!_sameKey(v.signers[0].cert, currentCa)) throw _err("scep/untrusted-signer", "the GetNextCACert response was not signed by the current CA key (RFC 8894 sec. 4.7.1)");
  var certs = schemaCms.parseCertsOnly(v.eContent, _err, "scep").certificates;
  return { certificates: certs };
}

function _defaultTransactionId() {
  return nodeCrypto.randomBytes(16).toString("hex");
}
var POLL_COUNT_MAX = 1000;

function _dispatchCertRep(rep, transactionId, spki) {
  if (rep.messageType !== "CertRep") throw _err("scep/unexpected-message-type", "the SCEP response is a " + rep.messageType + ", not a CertRep");
  if (rep.transactionId !== transactionId) throw _err("scep/transaction-id-mismatch", "the CertRep transactionID does not match the request (RFC 8894 sec. 3.2.1.1)");
  if (rep.pkiStatus === "FAILURE") {
    var failErr = _err("scep/enrollment-failed", "the CA refused the request with failInfo " + JSON.stringify(rep.failInfo) + (rep.failInfoText ? " (" + rep.failInfoText + ")" : ""));
    failErr.failInfo = rep.failInfo;
    failErr.failInfoText = rep.failInfoText;
    throw failErr;
  }
  if (rep.pkiStatus === "PENDING") return { pending: true };
  var repCerts = rep.certificates || [];
  var issued = findIssuedCert(repCerts, spki.bytes);
  if (issued == null) throw _err("scep/no-issued-cert", "the SUCCESS CertRep did not carry a certificate matching the request public key");
  if (findIssuedCert(repCerts.filter(function (c) { return c !== issued; }), spki.bytes) != null) {
    throw _err("scep/ambiguous-issued-cert", "the SUCCESS CertRep carried more than one certificate matching the request public key; the issued certificate is ambiguous (RFC 8894 sec. 3.3)");
  }
  return { pending: false, result: { status: "SUCCESS", certificate: issued, certificates: repCerts, transactionId: rep.transactionId } };
}

function _pollExhausted(which, transactionId, senderNonce) {
  var e = _err("scep/poll-exhausted", "the CA kept the request PENDING and " + which + " was exhausted before it resolved (RFC 8894 sec. 4.4); resume the transaction later with this transactionId");
  e.transactionId = transactionId;
  e.senderNonce = senderNonce;
  return e;
}

async function _pollForIssuance(ctx) {
  var issuerName;
  try { issuerName = schemaX509.parse(ctx.issuerCert).subject.bytes; }
  catch (e) { throw _err("scep/bad-input", "the issuerCert whose subject names the CertPoll issuer is not a parseable certificate (RFC 8894 sec. 3.3.3)", e); }
  var res = ctx.firstResponse, count = 0, waitedMs = 0, lastNonce = ctx.firstSenderNonce;
  for (;;) {
    var delaySec = 1;
    var ra = _header(res.headers, "retry-after");
    if (typeof ra === "string" && ra.trim() !== "") {
      var parsed = retryAfter.parse(ra, { now: Date.now(), E: _err, code: "scep/bad-input", lenient: true });
      if (parsed.retryAfterSeconds != null) delaySec = parsed.retryAfterSeconds;
    }
    count += 1;
    if (count > ctx.pollCount) throw _pollExhausted("the poll count", ctx.transactionId, lastNonce);
    waitedMs += delaySec * C.TIME.seconds(1);
    if (waitedMs > ctx.maxTotalWait * C.TIME.seconds(1)) throw _pollExhausted("the total wait budget", ctx.transactionId, lastNonce);
    if (ctx.onRetryAfter) ctx.onRetryAfter(delaySec);
    await ctx.sleep(delaySec * C.TIME.seconds(1));
    var sn = nodeCrypto.randomBytes(16);
    lastNonce = sn;
    var certPoll = await build({ messageType: "CertPoll", requestSubject: ctx.csrSubject, issuer: issuerName, recipient: ctx.caCert, signer: ctx.signer, transactionId: ctx.transactionId, senderNonce: sn });
    res = await _pkiRequest(ctx.httpMethod, ctx.postUrl, certPoll, ctx.clientOpts);
    var body = _requireOk(res, [CT_PKI_MESSAGE], "PKIOperation");
    var rep = await parse(body, { signerCert: ctx.signerCert, expectedSenderNonce: sn, recipientKey: ctx.recipientKey });
    var d = _dispatchCertRep(rep, ctx.transactionId, ctx.spki);
    if (!d.pending) return d.result;
  }
}
async function _pkiOperation(messageType, baseUrl, opts, verbName) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep." + verbName + " options");
  guard.identifier.assertKnownKeys(opts, _ENROLL_KEYS, _err, "scep/bad-input", "pki.scep." + verbName + " has an unknown option: ");
  _assertTransport(opts);
  if (opts.csr == null) throw _err("scep/bad-input", "a csr (PKCS#10 DER) is required");
  if (opts.caCert == null) throw _err("scep/bad-input", "a caCert (the SCEP CA certificate DER) is required");
  if (opts.signer == null || typeof opts.signer !== "object") throw _err("scep/bad-input", "a signer { cert, key } is required");
  if (opts.recipientKey == null || typeof opts.recipientKey !== "object") throw _err("scep/bad-input", "a recipientKey { cert, key } is required to decrypt the CA response");
  var caCert = guard.bytes.snapshotSource(opts.caCert, ScepError, "scep/bad-input", "the caCert");
  var signerCert = opts.responderCert != null ? guard.bytes.snapshotSource(opts.responderCert, ScepError, "scep/bad-input", "the responderCert") : caCert;
  var issuerCert = opts.issuerCert != null ? guard.bytes.snapshotSource(opts.issuerCert, ScepError, "scep/bad-input", "the issuerCert") : caCert;
  var recipientKey = _captureRecipientKey(opts.recipientKey);
  var signer = { cert: guard.bytes.snapshotSource(opts.signer.cert, ScepError, "scep/bad-input", "signer.cert"), key: opts.signer.key };
  var clientOpts = {
    tls: opts.tls != null ? Object.assign({}, opts.tls) : opts.tls,
    maxRedirects: opts.maxRedirects,
    allowCrossOriginRedirect: opts.allowCrossOriginRedirect,
    timeout: opts.timeout,
    maxResponseBytes: opts.maxResponseBytes,
    proxy: _snapshotProxy(opts.proxy),
  };
  /** @internal Carried only when the caller supplied it, so an omitted transport does not arrive
   * downstream as a key that is present and undefined, which counts as a value the caller set. */
  if ("transport" in Object(opts)) clientOpts.transport = opts.transport;
  var postUrl = _scepUrl(baseUrl, "PKIOperation");
  var httpMethod = _pkiMethod(opts);
  var csrView = guard.bytes.snapshotSource(opts.csr, ScepError, "scep/bad-input", "the csr");
  var spki, csrSubject;
  try { var _pcsr = schemaCsr.parse(csrView); spki = _pcsr.subjectPublicKeyInfo; csrSubject = _pcsr.subject.bytes; }
  catch (e) { throw _err("scep/bad-input", "the csr is not a valid PKCS#10 CertificationRequest", e); }
  var pollCount = guard.limits.cap(opts.pollCount, "pollCount", 5, { E: _err, code: "scep/bad-input", min: 0, max: POLL_COUNT_MAX });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "maxTotalWait", retryAfter.MAX_RETRY_AFTER_SECONDS, { E: _err, code: "scep/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = typeof opts.sleep === "function" ? opts.sleep : _defaultSleep;
  var onRetryAfter = typeof opts.onRetryAfter === "function" ? opts.onRetryAfter : null;
  var senderNonce = nodeCrypto.randomBytes(16);
  var transactionId = opts.transactionId != null ? opts.transactionId : _defaultTransactionId();
  var reqMsg = await build({ messageType: messageType, messageData: csrView, recipient: caCert, signer: signer, transactionId: transactionId, senderNonce: senderNonce });
  var res = await _pkiRequest(httpMethod, postUrl, reqMsg, clientOpts);
  var body = _requireOk(res, [CT_PKI_MESSAGE], "PKIOperation");
  var rep = await parse(body, { signerCert: signerCert, expectedSenderNonce: senderNonce, recipientKey: recipientKey });
  var d = _dispatchCertRep(rep, transactionId, spki);
  if (!d.pending) return d.result;
  if (pollCount <= 0) return { status: "PENDING", transactionId: rep.transactionId, senderNonce: senderNonce };
  return _pollForIssuance({
    firstResponse: res, firstSenderNonce: senderNonce, postUrl: postUrl, httpMethod: httpMethod, clientOpts: clientOpts,
    caCert: caCert, csrSubject: csrSubject, issuerCert: issuerCert, signer: signer, signerCert: signerCert, recipientKey: recipientKey,
    spki: spki, transactionId: transactionId, pollCount: pollCount, maxTotalWait: maxTotalWait,
    sleep: sleep, onRetryAfter: onRetryAfter,
  });
}

/**
 * @primitive  pki.scep.enroll
 * @signature  pki.scep.enroll(baseUrl, opts) -> Promise<{ status, certificate?, certificates?, transactionId }>
 * @since      0.6.7
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.build, pki.scep.getCACert, pki.csr.sign
 *
 * Enrol for a certificate over SCEP (RFC 8894 sec. 4.3): build a PKCSReq wrapping the caller's PKCS#10 in
 * a pkcsPKIEnvelope encrypted to the CA certificate, HTTP POST it to `?operation=PKIOperation`, and read
 * the CertRep. The CA response is authenticated against the CA certificate and its `recipientNonce` must
 * echo the request's fresh `senderNonce`. On SUCCESS the issued certificate is selected out of the
 * response by SubjectPublicKeyInfo byte-match against the request; a FAILURE throws
 * `scep/enrollment-failed` carrying the CA's failInfo. A CA that answers PENDING (manual enrollment, RFC
 * 8894 sec. 2.5) is polled automatically: the client issues CertPoll (GetCertInitial) messages reusing
 * the transactionID, each authenticated against the CA certificate with a fresh nonce it must echo,
 * until the CA answers SUCCESS or FAILURE or a `pollCount` / `maxTotalWait` budget is exhausted
 * (`scep/poll-exhausted`, carrying the `transactionId` to resume). Pass `pollCount: 0` to disable polling
 * and get the single `{ status: "PENDING", transactionId }` return for a caller that drives the retry
 * itself. The content key is transported under RSAES-OAEP, so the CA
 * certificate must be an RSA `keyEncipherment` certificate that accepts OAEP; the shared-secret
 * authenticator (RFC 8894 sec. 2.4) is the `challengePassword` the caller placed in the PKCS#10.
 *
 * @opts
 *   - `csr` -- the PKCS#10 CertificationRequest DER to enrol (place a `challengePassword` in it for shared-secret auth).
 *   - `caCert` -- the SCEP CA certificate DER the request is encrypted to.
 *   - `signer` -- `{ cert, key }`, the outer SignedData signer (for a PKCSReq, a self-signed certificate over the request key).
 *   - `recipientKey` -- `{ cert, key }`, the RSA key the CA encrypts the response to, to decrypt the CertRep.
 *   - `responderCert` -- the certificate to authenticate the CA's response signature against (defaults to `caCert`).
 *   - `issuerCert` -- the issuing CA certificate whose subject names the CertPoll issuer (defaults to `caCert`; set it when the request is encrypted to a separate RA certificate, RFC 8894 sec. 3.3.3).
 *   - `transactionId` -- a caller-unique PrintableString (defaults to 16 random bytes, hex-encoded, unique per call).
 *   - `pollCount` -- the maximum number of CertPoll requests on a PENDING response (default 5; `0` disables polling).
 *   - `maxTotalWait` -- the total Retry-After sleep budget in seconds across all polls (default the Retry-After horizon).
 *   - `sleep` -- an injectable sleeper `(ms) -> Promise` for the Retry-After wait (default a real timer).
 *   - `onRetryAfter` -- an optional observer `(delaySeconds) -> void` called before each poll sleep.
 *   - `httpMethod` -- `"POST"` (default) or `"GET"`. RFC 8894 sec. 4.1 sends the PKIOperation message over POST; `"GET"` carries it base64-encoded in the URL `message` query for a legacy CA that lacks POST.
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` / `proxy` -- transport bounds (`proxy` reaches the CA through a forward HTTP proxy; see pki.transport).
 * @example
 *   // requires: scepCsr, caCertDer, clientCertDer, clientKeyPkcs8, scepTransport
 *   var out = await pki.scep.enroll("http://ca.example/scep", { csr: scepCsr, caCert: caCertDer,
 *     signer: { cert: clientCertDer, key: clientKeyPkcs8 },
 *     recipientKey: { cert: clientCertDer, key: clientKeyPkcs8 }, transport: scepTransport });
 *   out.status;   // "SUCCESS" (a PENDING request is polled to a terminal status unless pollCount is 0)
 */
function enroll(baseUrl, opts) { return _pkiOperation("PKCSReq", baseUrl, opts, "enroll"); }

/**
 * @primitive  pki.scep.renew
 * @signature  pki.scep.renew(baseUrl, opts) -> Promise<{ status, certificate?, certificates?, transactionId }>
 * @since      0.6.7
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.enroll
 *
 * Renew a certificate over SCEP (RFC 8894 sec. 4.3): identical to `enroll` but building a RenewalReq,
 * whose outer SignedData is signed with the caller's existing CA-issued certificate rather than a
 * self-signed one. Because the request is signed with the existing key and not the new PKCS#10 key, a
 * RenewalReq does not itself prove possession of the new key (RFC 8894 sec. 7.6); the proof-of-possession
 * over the PKCS#10 is still verified. Options are the same as `enroll`, with `signer` being the existing
 * certificate and key.
 *
 * @example
 *   // requires: scepCsr, caCertDer, clientCertDer, clientKeyPkcs8, scepTransport
 *   var out = await pki.scep.renew("http://ca.example/scep", { csr: scepCsr, caCert: caCertDer,
 *     signer: { cert: clientCertDer, key: clientKeyPkcs8 },
 *     recipientKey: { cert: clientCertDer, key: clientKeyPkcs8 }, transport: scepTransport });
 */
function renew(baseUrl, opts) { return _pkiOperation("RenewalReq", baseUrl, opts, "renew"); }

function _dispatchQueryRep(rep, transactionId) {
  if (rep.messageType !== "CertRep") throw _err("scep/unexpected-message-type", "the SCEP response is a " + rep.messageType + ", not a CertRep");
  if (rep.transactionId !== transactionId) throw _err("scep/transaction-id-mismatch", "the CertRep transactionID does not match the request (RFC 8894 sec. 3.2.1.1)");
  if (rep.pkiStatus === "FAILURE") {
    var e = _err("scep/query-failed", "the CA refused the query with failInfo " + JSON.stringify(rep.failInfo) + (rep.failInfoText ? " (" + rep.failInfoText + ")" : ""));
    e.failInfo = rep.failInfo;
    e.failInfoText = rep.failInfoText;
    throw e;
  }
  if (rep.pkiStatus === "PENDING") throw _err("scep/unexpected-pending", "a GetCert / GetCRL query cannot be answered PENDING; the CA grants or rejects it (RFC 8894 sec. 4.5.1)");
}

function _resolveQueryTarget(opts) {
  var hasCert = opts.certificate != null;
  var hasExplicit = opts.issuer != null || opts.serialNumber != null;
  if (hasCert === hasExplicit) throw _err("scep/bad-input", "a GetCert / GetCRL query needs exactly one of { certificate } or { issuer, serialNumber } (RFC 8894 sec. 3.3.4)");
  if (hasCert) {
    var certDer = guard.bytes.snapshotSource(opts.certificate, ScepError, "scep/bad-input", "certificate");
    var w;
    try { w = schemaX509.parse(certDer); }
    catch (e) { throw _err("scep/bad-input", "certificate is not a parseable X.509 certificate (RFC 8894 sec. 3.3.4): " + e.message, e); }
    return { issuerRdns: w.issuer.rdns, serial: w.serialNumber, buildSpec: { certificate: certDer } };
  }
  if (opts.issuer == null || opts.serialNumber == null) throw _err("scep/bad-input", "the explicit form of a GetCert / GetCRL query needs both issuer and serialNumber (RFC 8894 sec. 3.3.4)");
  var serial = _serialToInteger(opts.serialNumber);
  var issuerDer = guard.bytes.snapshotSource(opts.issuer, ScepError, "scep/bad-input", "issuer");
  var issuerRdns;
  try { issuerRdns = schema.walk(pkix.name(_KU_NS), asn1.decode(issuerDer), _KU_NS).result.rdns; }
  catch (e) { throw _err("scep/bad-input", "issuer is not a valid Name DER (RFC 8894 sec. 3.3.4): " + e.message, e); }
  return { issuerRdns: issuerRdns, serial: serial, buildSpec: { issuer: issuerDer, serialNumber: opts.serialNumber } };
}

async function _queryOperation(messageType, baseUrl, opts, verbName) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep." + verbName + " options");
  guard.identifier.assertKnownKeys(opts, _QUERY_KEYS, _err, "scep/bad-input", "pki.scep." + verbName + " has an unknown option: ");
  _assertTransport(opts);
  if (opts.caCert == null) throw _err("scep/bad-input", "a caCert (the SCEP CA certificate DER) is required");
  if (opts.signer == null || typeof opts.signer !== "object") throw _err("scep/bad-input", "a signer { cert, key } is required");
  if (opts.recipientKey == null || typeof opts.recipientKey !== "object") throw _err("scep/bad-input", "a recipientKey { cert, key } is required to decrypt the CA response");
  var caCert = guard.bytes.snapshotSource(opts.caCert, ScepError, "scep/bad-input", "the caCert");
  var signerCert = opts.responderCert != null ? guard.bytes.snapshotSource(opts.responderCert, ScepError, "scep/bad-input", "the responderCert") : caCert;
  var recipientKey = _captureRecipientKey(opts.recipientKey);
  var signer = { cert: guard.bytes.snapshotSource(opts.signer.cert, ScepError, "scep/bad-input", "signer.cert"), key: opts.signer.key };
  var want = _resolveQueryTarget(opts);
  var clientOpts = { tls: opts.tls != null ? Object.assign({}, opts.tls) : opts.tls, maxRedirects: opts.maxRedirects, allowCrossOriginRedirect: opts.allowCrossOriginRedirect, timeout: opts.timeout, maxResponseBytes: opts.maxResponseBytes, proxy: _snapshotProxy(opts.proxy) };
  if ("transport" in Object(opts)) clientOpts.transport = opts.transport;
  var senderNonce = nodeCrypto.randomBytes(16);
  var transactionId = opts.transactionId != null ? opts.transactionId : _defaultTransactionId();
  var httpMethod = _pkiMethod(opts);
  var reqMsg = await build(Object.assign({ messageType: messageType, recipient: caCert, signer: signer, transactionId: transactionId, senderNonce: senderNonce }, want.buildSpec));
  var res = await _pkiRequest(httpMethod, _scepUrl(baseUrl, "PKIOperation"), reqMsg, clientOpts);
  var body = _requireOk(res, [CT_PKI_MESSAGE], "PKIOperation");
  var rep = await parse(body, { signerCert: signerCert, expectedSenderNonce: senderNonce, recipientKey: recipientKey });
  _dispatchQueryRep(rep, transactionId);
  return { rep: rep, want: want, transactionId: transactionId };
}

/**
 * @primitive  pki.scep.getCert
 * @signature  pki.scep.getCert(baseUrl, opts) -> Promise<{ certificate, certificates, transactionId }>
 * @since      0.6.17
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.enroll, pki.scep.getCrl
 *
 * Retrieve an already-issued certificate over SCEP (RFC 8894 sec. 3.3.4): POST a GetCert query naming the
 * certificate's issuer and serial number, and select it out of the CA's certs-only CertRep by canonical
 * issuer-name and serial match. This is an OPTIONAL fallback: RFC 8894 sec. 3.3.4 advises a client to prefer
 * an HTTP certificate store (RFC 4387) or LDAP and to use this only against a CA that offers no such access.
 * The response is authenticated against the CA certificate and its recipientNonce must echo the request's
 * fresh senderNonce; a FAILURE throws `scep/query-failed`, a PENDING is refused (`scep/unexpected-pending`, a
 * query grants or rejects), and a SUCCESS not carrying the requested certificate throws `scep/cert-not-found`.
 * `certificate` is the one matched to the requested issuer and serial; `certificates` is every certificate the
 * authenticated response carried, raw, so a caller relies on `certificate` for the queried identity.
 *
 * @opts
 *   - `certificate` -- the certificate DER whose issuer and serial name the one to retrieve (the convenience form).
 *   - `issuer` / `serialNumber` -- the issuer Name DER and serial (a BigInt, number, or hex string) naming the certificate, for a caller that did not retain it.
 *   - `caCert` -- the SCEP CA certificate DER the query is encrypted to.
 *   - `signer` -- `{ cert, key }`, the outer SignedData signer.
 *   - `recipientKey` -- `{ cert, key }`, the RSA key the CA encrypts the response to, to decrypt the CertRep.
 *   - `responderCert` -- the certificate to authenticate the CA response signature against (defaults to `caCert`).
 *   - `transactionId` -- a caller-unique PrintableString (defaults to 16 random bytes, hex-encoded).
 *   - `httpMethod` -- `"POST"` (default) or `"GET"`. RFC 8894 sec. 4.1 sends the PKIOperation message over POST; `"GET"` carries it base64-encoded in the URL `message` query for a legacy CA that lacks POST.
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` / `proxy` -- transport bounds (`proxy` reaches the CA through a forward HTTP proxy; see pki.transport).
 * @example
 *   // requires: clientCertDer, caCertDer, clientKeyPkcs8, scepTransport
 *   var out = await pki.scep.getCert("http://ca.example/scep", { certificate: clientCertDer, caCert: caCertDer,
 *     signer: { cert: clientCertDer, key: clientKeyPkcs8 },
 *     recipientKey: { cert: clientCertDer, key: clientKeyPkcs8 }, transport: scepTransport });
 *   out.certificate;   // the retrieved certificate DER
 */
async function getCert(baseUrl, opts) {
  var q = await _queryOperation("GetCert", baseUrl, opts, "getCert");
  var certs = q.rep.certificates || [];
  var match = null;
  for (var i = 0; i < certs.length; i++) {
    var w = schemaX509.parse(certs[i]);
    if (guard.name.dnEqual(w.issuer.rdns, q.want.issuerRdns, _err, "scep/bad-response", "the returned certificate issuer") && w.serialNumber === q.want.serial) {
      if (match != null) throw _err("scep/ambiguous-cert", "the CA returned more than one certificate matching the requested issuer and serial (RFC 8894 sec. 3.3.4)");
      match = certs[i];
    }
  }
  if (match == null) throw _err("scep/cert-not-found", "the CA response did not carry a certificate matching the requested issuer and serial (RFC 8894 sec. 3.3.4)");
  return { certificate: match, certificates: certs, transactionId: q.transactionId };
}

/**
 * @primitive  pki.scep.getCrl
 * @signature  pki.scep.getCrl(baseUrl, opts) -> Promise<{ crl, crls, transactionId }>
 * @since      0.6.17
 * @status     stable
 * @spec       RFC 8894
 * @related    pki.scep.getCert, pki.crl.verify
 *
 * Retrieve a CRL over SCEP (RFC 8894 sec. 3.3.4): POST a GetCRL query naming the CA by the issuer and serial
 * of a certificate it issued, and read the CRL out of the CA's CRL-only CertRep. This is an OPTIONAL fallback:
 * RFC 8894 sec. 2.7 says a client should compose a GetCRL only if the CA supports neither a CRL distribution
 * point nor HTTP access, and prefer those. The response is authenticated against the CA certificate and its
 * recipientNonce must echo the request's fresh senderNonce; a FAILURE throws `scep/query-failed`, and a PENDING is
 * refused. The returned CRL is bound to the query: `crl` is the one whose issuer matches the requested CA, so a
 * response carrying no such CRL throws `scep/no-crl` and one carrying more than one throws `scep/ambiguous-crl`.
 * The full response list is on `crls`, raw for the caller to validate with `pki.crl.verify`.
 *
 * @opts
 *   - `certificate` -- a certificate DER the CA issued, whose issuer and serial name the CA to query (the convenience form).
 *   - `issuer` / `serialNumber` -- the issuer Name DER and serial (a BigInt, number, or hex string) naming the CA, when the caller did not retain such a certificate.
 *   - `caCert` -- the SCEP CA certificate DER the query is encrypted to.
 *   - `signer` -- `{ cert, key }`, the outer SignedData signer.
 *   - `recipientKey` -- `{ cert, key }`, the RSA key the CA encrypts the response to.
 *   - `responderCert` -- the certificate to authenticate the CA response against (defaults to `caCert`).
 *   - `transactionId` -- a caller-unique PrintableString (defaults to 16 random bytes, hex-encoded).
 *   - `httpMethod` -- `"POST"` (default) or `"GET"`. RFC 8894 sec. 4.1 sends the PKIOperation message over POST; `"GET"` carries it base64-encoded in the URL `message` query for a legacy CA that lacks POST.
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` / `proxy` -- transport bounds (`proxy` reaches the CA through a forward HTTP proxy; see pki.transport).
 * @example
 *   // requires: clientCertDer, caCertDer, clientKeyPkcs8, scepTransport
 *   var out = await pki.scep.getCrl("http://ca.example/scep", { certificate: clientCertDer, caCert: caCertDer,
 *     signer: { cert: clientCertDer, key: clientKeyPkcs8 },
 *     recipientKey: { cert: clientCertDer, key: clientKeyPkcs8 }, transport: scepTransport });
 *   out.crl;   // the retrieved CRL DER
 */
async function getCrl(baseUrl, opts) {
  var q = await _queryOperation("GetCRL", baseUrl, opts, "getCrl");
  var crls = q.rep.crls || [];
  var match = null;
  for (var i = 0; i < crls.length; i++) {
    var w = schemaCrl.parse(crls[i]);
    if (guard.name.dnEqual(w.issuer.rdns, q.want.issuerRdns, _err, "scep/bad-response", "the returned CRL issuer")) {
      if (match != null) throw _err("scep/ambiguous-crl", "the CA returned more than one CRL issued by the requested CA (RFC 8894 sec. 3.3.4)");
      match = crls[i];
    }
  }
  if (match == null) throw _err("scep/no-crl", "the CA response did not carry a CRL issued by the requested CA (RFC 8894 sec. 3.3.4)");
  return { crl: match, crls: crls, transactionId: q.transactionId };
}

var _TRANSPORT_KEYS = Object.assign(Object.create(null), { transport: 1, timeout: 1, maxResponseBytes: 1, maxRedirects: 1, tls: 1, allowCrossOriginRedirect: 1, proxy: 1 });
function _withKeys(extra) { var o = {}, k; for (k in _TRANSPORT_KEYS) o[k] = 1; for (k in extra) o[k] = 1; return o; }
var _CACAPS_KEYS = _withKeys({ expectSCEPStandard: 1, requireStrongProfile: 1 });
var _CACERT_KEYS = _withKeys({ expectedFingerprint: 1, fingerprintAlgorithm: 1 });
var _NEXTCACERT_KEYS = _withKeys({ caCertificate: 1 });
var _ENROLL_KEYS = _withKeys({ csr: 1, caCert: 1, signer: 1, recipientKey: 1, responderCert: 1, issuerCert: 1, transactionId: 1, pollCount: 1, maxTotalWait: 1, sleep: 1, onRetryAfter: 1, httpMethod: 1 });
var _QUERY_KEYS = _withKeys({ certificate: 1, issuer: 1, serialNumber: 1, caCert: 1, signer: 1, recipientKey: 1, responderCert: 1, transactionId: 1, httpMethod: 1 });

module.exports = {
  build: build,
  parse: parse,
  getCACaps: getCACaps,
  getCACert: getCACert,
  getNextCACert: getNextCACert,
  enroll: enroll,
  renew: renew,
  getCert: getCert,
  getCrl: getCrl,
  parseCapabilities: parseCapabilities,
  MESSAGE_TYPES: MESSAGE_TYPE,
  PKI_STATUS: PKI_STATUS,
  FAIL_INFO: FAIL_INFO,
};
