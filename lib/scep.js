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
 *   attributes -- messageType, transactionID, pkiStatus, failInfo, and the
 *   sender/recipient nonces (RFC 8894 sec. 3). `pki.scep.build` assembles a
 *   request pkiMessage (PKCSReq / RenewalReq); `pki.scep.parse` verifies the
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
 *   Build and read SCEP (RFC 8894) enrollment messages: a PKCSReq / RenewalReq
 *   request wrapped in the signed-over-encrypted CMS layering, and any pkiMessage
 *   parsed back to its verified transaction attributes and decrypted messageData.
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
require("./path-validate");   // side-effect: injects the certification-path signature engine into csr-verify at load
var csrVerify = require("./csr-verify");   // verify an embedded PKCS#10's proof-of-possession before enveloping it
var schemaCms = require("./schema-cms");
var schemaCsr = require("./schema-csr");
var schemaX509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");
var guard = require("./guard-all");
var C = require("./constants");
var nodeCrypto = require("node:crypto");

function _err(code, msg, cause) { return new ScepError(code, msg, cause); }

// The messageType values are a DATA table (RFC 8894 sec. 3.2.1.2, Table 3), never a switch: name <-> the
// decimal ASCII a PrintableString carries. RFC 8894 renumbered the legacy draft (RenewalReq is 17, and
// there is no GetCertInitial -- it is CertPoll 20).
var MESSAGE_TYPE = { CertRep: "3", RenewalReq: "17", PKCSReq: "19", CertPoll: "20", GetCert: "21", GetCRL: "22" };
// pkiStatus (Table 4): SUCCESS 0, FAILURE 2, PENDING 3 -- note there is NO value 1.
var PKI_STATUS = { SUCCESS: "0", FAILURE: "2", PENDING: "3" };
// failInfo (Table 5).
var FAIL_INFO = { badAlg: "0", badMessageCheck: "1", badRequest: "2", badTime: "3", badCertId: "4" };

// name -> code and code -> name, built once from each table so a lookup is a data read, not a switch.
function _invert(table) { var o = Object.create(null); for (var k in table) if (Object.prototype.hasOwnProperty.call(table, k)) o[table[k]] = k; return o; }
var MESSAGE_TYPE_BY_CODE = _invert(MESSAGE_TYPE), PKI_STATUS_BY_CODE = _invert(PKI_STATUS), FAIL_INFO_BY_CODE = _invert(FAIL_INFO);

// The RFC 8894 sec. 3 EnvelopedData content-encryption profile. AES-128-CBC is the mandatory strong
// cipher; the toolkit's own cms.encrypt refuses the weak legacy ciphers structurally, so the builder
// only names the one it emits.
var ENVELOPE_CIPHER = "aes-128-cbc";

// The empty external content a conforming FAILURE / PENDING CertRep is verified against: its
// pkcsPKIEnvelope is omitted, so the SignedData carries no encapsulated content (RFC 8894 sec. 3.3.2).
var EMPTY_CONTENT = Buffer.alloc(0);

// A 16-byte nonce (RFC 8894 sec. 3.2.1.5): a caller value copied at the door and validated to width, or
// a fresh random one. The copy makes a caller value read after an await immune to concurrent mutation.
function _nonce(v, label) {
  if (v == null) return nodeCrypto.randomBytes(16);
  var buf = guard.bytes.snapshotSource(v, ScepError, "scep/bad-nonce", label);
  if (buf.length !== 16) throw _err("scep/bad-nonce", label + " must be exactly 16 bytes (RFC 8894 sec. 3.2.1.5), got " + buf.length);
  return buf;
}

// A caller PrintableString for a transaction id: bounded (the RFC sets no length, so cap it against a DoS)
// and restricted to the PrintableString character set (asn1.build.printable enforces the set).
function _transactionId(v) {
  if (typeof v !== "string" || v.length === 0) throw _err("scep/bad-input", "transactionId must be a non-empty string (RFC 8894 sec. 3.2.1.1)");
  if (v.length > C.LIMITS.SCEP_TRANSACTION_ID_MAX) throw _err("scep/bad-input", "transactionId exceeds the " + C.LIMITS.SCEP_TRANSACTION_ID_MAX + "-character cap");
  return v;
}

// Assert some bytes are a CMS ContentInfo wrapping a well-formed EnvelopedData whose encrypted content
// type is id-data -- the pkcsPKIEnvelope profile (RFC 8894 sec. 3.2, sec. 3.2.2). Delegated to the
// strict CMS parser, and checked structurally without decryption, so an absent, malformed, or
// off-profile envelope is refused for every envelope-carrying message whether or not a recipient key
// was supplied.
function _assertValidEnvelope(bytes, messageType) {
  if (bytes == null) throw _err("scep/missing-envelope", "the pkcsPKIEnvelope is mandatory for a " + messageType + " message but the signed content is absent (RFC 8894 sec. 3.2)");
  var parsed;
  try { parsed = schemaCms.parse(bytes); }
  catch (e) { throw _err("scep/missing-envelope", "the pkcsPKIEnvelope of a " + messageType + " message is not a decodable CMS EnvelopedData (RFC 8894 sec. 3.2)", e); }
  if (parsed.contentTypeName !== "envelopedData") throw _err("scep/missing-envelope", "the pkcsPKIEnvelope of a " + messageType + " message must be an EnvelopedData (RFC 8894 sec. 3.2), got " + parsed.contentTypeName);
  if (parsed.encryptedContentInfo.contentType !== oid.byName("data")) throw _err("scep/bad-envelope-content-type", "the pkcsPKIEnvelope's encrypted content type must be id-data (RFC 8894 sec. 3.2.2), got " + parsed.encryptedContentInfo.contentType);
}

// Validate a SUCCESS CertRep's messageData as a degenerate certificates-only CMS SignedData (RFC 8894
// sec. 3.4) and surface its certificates and CRLs raw, for the caller to path-validate. The issued
// certificate(s) answer an enrollment; a CRL answers a GetCRL (sec. 3.3.4), so certificates and CRLs are
// accepted independently and a payload carrying neither is refused.
function _readIssuancePayload(der) {
  var r;
  try { r = schemaCms.parse(der); }
  catch (e) { throw _err("scep/bad-response", "a SUCCESS CertRep messageData did not decode as a CMS SignedData (RFC 8894 sec. 3.4)", e); }
  if (r.contentTypeName !== "signedData" || r.encapContentInfo.eContentType !== oid.byName("data") ||
      r.encapContentInfo.eContent !== null || r.signerInfos.length !== 0) {
    throw _err("scep/not-certs-only", "a SUCCESS CertRep messageData must be a degenerate certificates-only CMS SignedData (RFC 8894 sec. 3.4)");
  }
  // Validate each entry as a plain X.509 certificate / CRL: a universal-SEQUENCE CertificateChoice or
  // RevocationInfoChoice must be a well-formed certificate / CRL, and a tagged alternative (attribute
  // cert, other-message, otherRevInfo) is not a plain issuance object and is refused.
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

// Build one SCEP transaction attribute { type, values:[valueDER] } for cms.sign's additionalSignedAttributes.
function _attr(name, valueDer) { return { type: oid.byName(name), values: [valueDer] }; }

// Find the single surfaced signed attribute of a given OID name (the values are raw AttributeValue
// DER). The CMS parser rejects a repeated attribute type (cms/duplicate-signed-attr) before these
// attributes are surfaced, so a SCEP transaction attribute appears at most once. It is also
// single-valued: a value SET that does not hold exactly one value is an ambiguous transaction state
// and is refused rather than resolved to the first value (RFC 8894 sec. 3.2.1).
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
// Read a string transaction attribute to its JS string, requiring the exact ASN.1 string type RFC 8894
// sec. 3.2 pins for it (a generic string reader would accept an off-profile UTF8String or IA5String
// where a PrintableString is required). Returns null when the attribute is absent.
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
// Read a 16-byte OCTET STRING nonce attribute, or null when absent.
function _readNonce(attrs, name) {
  var a = _find(attrs, name);
  if (a == null) return null;
  var n;
  try { n = asn1.read.octetString(asn1.decode(a.values[0])); }
  catch (e) { throw _err("scep/bad-nonce", "the " + name + " transaction attribute is not a readable OCTET STRING", e); }
  if (n.length !== 16) throw _err("scep/bad-nonce", "the " + name + " nonce must be exactly 16 bytes (RFC 8894 sec. 3.2.1.5), got " + n.length);
  return n;
}

// Whether two certificates carry the same subject public key -- the SCEP signer-authentication test
// (a CertRep must be signed by the CA the client already holds, RFC 8894 sec. 3.1). Compared by the
// SubjectPublicKeyInfo so a re-encoded certificate of the same key still matches.
function _sameKey(certA, certB) {
  var a, bb;
  try { a = schemaX509.parse(certA).subjectPublicKeyInfo.bytes; bb = schemaX509.parse(certB).subjectPublicKeyInfo.bytes; }
  catch (e) { throw _err("scep/bad-input", "a certificate could not be parsed for signer authentication: " + e.message, e); }
  return guard.crypto.constantTimeEqual(a, bb);
}

// The pkcsPKIEnvelope uses RSAES-OAEP key transport, so the recipient MUST be an RSA key-transport
// certificate (RFC 8894 sec. 3). An EC / X25519 / ML-KEM recipient would make cms.encrypt emit a
// key-agreement or KEM recipient off the SCEP profile, so it is refused before the CMS dispatch.
function _assertRsaRecipient(recipientDer) {
  var spki;
  try { spki = schemaX509.parse(recipientDer).subjectPublicKeyInfo; }
  catch (e) { throw _err("scep/bad-input", "the recipient is not a parseable certificate: " + e.message, e); }
  if (spki.algorithm.oid !== oid.byName("rsaEncryption")) {
    throw _err("scep/bad-recipient", "the SCEP recipient must be an RSA key-transport certificate (RFC 8894 sec. 3); its public-key algorithm is " + spki.algorithm.oid);
  }
}

// Snapshot the recipient key material at the parse door: the certificate byte source is copied so a
// concurrent mutation cannot redirect the decryption, and the private / content key is held by
// reference (copying a secret is the worse defect). null passes through unchanged.
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
 * signer certificate and key. `transactionId` is a caller-unique PrintableString; `senderNonce` is a
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
 * @opts
 *   - `messageType` -- "PKCSReq" | "RenewalReq" (this release's request set).
 *   - `messageData` -- the PKCS#10 CertificationRequest DER to enrol.
 *   - `recipient` -- the CA (or RA) certificate DER the messageData is encrypted to (an RSA key-transport certificate; a non-RSA recipient is refused, since the envelope uses RSAES-OAEP).
 *   - `signer` -- `{ cert, key }`, the outer SignedData signer (the client for a request).
 *   - `transactionId` -- a caller-unique PrintableString identifying the transaction.
 *   - `senderNonce` -- a 16-byte Buffer (generated when omitted).
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
  guard.identifier.assertKnownKeys(spec, _BUILD_KEYS, _err, "scep/bad-input", "pki.scep.build has an unknown option: ");
  var mtCode = MESSAGE_TYPE[spec.messageType];
  if (mtCode == null) throw _err("scep/bad-message-type", "unknown messageType " + JSON.stringify(spec.messageType) + " (RFC 8894 sec. 3.2.1.2)");
  if (spec.messageType !== "PKCSReq" && spec.messageType !== "RenewalReq") {
    throw _err("scep/bad-message-type", "pki.scep.build issues a request (PKCSReq / RenewalReq); " + spec.messageType + " is not built in this release");
  }
  if (spec.signer == null || typeof spec.signer !== "object") throw _err("scep/bad-input", "a signer { cert, key } is required");
  var senderNonce = _nonce(spec.senderNonce, "senderNonce");
  var txnId = _transactionId(spec.transactionId);
  // The messageData is a PKCS#10 CertificationRequest whose self-signature is its proof-of-possession
  // (RFC 8894 sec. 3.3.1, over RFC 2986). Verify the structure and that proof before enveloping it, so
  // arbitrary bytes or a request whose signature does not verify under its own subject public key are
  // refused here rather than encrypted into a message a CA would reject.
  // Capture every input read after an await at this synchronous door, so a caller that mutates or reuses
  // the spec while verification or encryption is pending cannot desync what was verified from what is
  // emitted, or substitute the recipient a request is encrypted to. The certificate byte sources are
  // copied; the signer private key is held by reference (copying a secret is the worse defect).
  var messageData = guard.bytes.snapshotSource(spec.messageData, ScepError, "scep/bad-input", "messageData");
  var recipient = guard.bytes.snapshotSource(spec.recipient, ScepError, "scep/bad-input", "recipient");
  _assertRsaRecipient(recipient);
  var signerCert = guard.bytes.snapshotSource(spec.signer.cert, ScepError, "scep/bad-input", "signer.cert");
  var signerKey = spec.signer.key;
  var parsedCsr;
  try { parsedCsr = schemaCsr.parse(messageData); }
  catch (e) { throw _err("scep/bad-input", "messageData is not a valid PKCS#10 CertificationRequest (RFC 8894 sec. 3.3.1): " + e.message, e); }
  if (!(await csrVerify.verifyCsrSignature(parsedCsr))) {
    throw _err("scep/bad-popo", "the PKCS#10 messageData failed its proof-of-possession: its self-signature does not verify under its own subject public key, so a CA would reject it");
  }
  // Inner EnvelopedData: encrypt the PKCS#10 to the recipient CA, AES-128-CBC (RFC 8894 sec. 3).
  var pkcsPKIEnvelope;
  try {
    pkcsPKIEnvelope = await cmsEncrypt.encrypt(messageData, [{ cert: recipient }], { contentEncryptionAlgorithm: ENVELOPE_CIPHER });
  } catch (e) {
    if (e && e.isPkiError) throw _err("scep/bad-input", "the pkcsPKIEnvelope could not be built (recipient must be a keyEncipherment CA certificate and messageData a PKCS#10): " + e.message, e);
    throw e;
  }
  // Outer SignedData over the envelope, carrying the transaction attributes as authenticated attributes.
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
var _BUILD_KEYS = { messageType: 1, messageData: 1, recipient: 1, signer: 1, transactionId: 1, senderNonce: 1 };

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
 * given the recipient key, decrypt the pkcsPKIEnvelope to recover the messageData. The verdict is
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
  // Snapshot the message bytes once at this synchronous door: parse verifies them twice (a detached
  // FAILURE / PENDING is re-verified against an empty payload), so a caller that swaps a mutable Buffer
  // between the two attempts must not be able to return one message's attributes for another.
  var msgBytes = guard.bytes.snapshotSource(bytes, ScepError, "scep/bad-der", "pkiMessage");
  // Capture every option read after the awaited verification at this synchronous door, so a caller that
  // mutates or reuses opts while verification is pending cannot swap the authenticated signer, the echo
  // nonce, or the decryption recipient after the checks that depend on them have started. Certificate
  // byte sources are copied; the recipient private key is held by reference.
  var expectedSignerCert = opts.signerCert != null ? guard.bytes.snapshotSource(opts.signerCert, ScepError, "scep/bad-input", "opts.signerCert") : null;
  var expectedSenderNonce = opts.expectedSenderNonce != null ? _nonce(opts.expectedSenderNonce, "expectedSenderNonce") : null;
  var recipientKey = _captureRecipientKey(opts.recipientKey);
  var v;
  try { v = await cmsVerify.verify(msgBytes); }
  catch (e) {
    // A conforming FAILURE or PENDING CertRep omits the pkcsPKIEnvelope, so the SignedData has no
    // encapsulated content and cms.verify reports it as detached. Re-verify against an empty payload,
    // which the signature accepts only when the message-digest was taken over no content; a message
    // signed over any other bytes still fails (RFC 8894 sec. 3.3.2).
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
  // Fail closed: the transaction attributes are only trustworthy once the outer signature verifies.
  // cms.verify returns a per-signer verdict rather than throwing, so a bad signature MUST be refused
  // here before any attribute is read -- never surfaced as a false verdict alongside the attributes.
  if (v.valid !== true) throw _err("scep/bad-signature", "the pkiMessage outer signature did not verify (RFC 8894 sec. 3.1)");
  // The SignedData eContentType MUST be id-data (RFC 8894 sec. 3.2): a message that verifies as CMS but
  // names another encapsulated content type is not a valid SCEP pkiMessage.
  if (v.eContentType !== oid.byName("data")) throw _err("scep/bad-content-type", "the pkiMessage eContentType must be id-data (RFC 8894 sec. 3.2)");
  var signer = v.signers[0];
  // A valid signature proves only that the message is self-consistent with the certificate it embeds,
  // NOT that the signer is the expected party: anyone can mint a certificate and sign a forged CertRep
  // that echoes an observed nonce. A SCEP client MUST authenticate a CA response against the CA
  // certificate it already holds (RFC 8894 sec. 3.1). When opts.signerCert names the expected signer,
  // require the message signer's public key to match it; a caller that omits it gets a crypto-only
  // verdict (signerAuthenticated: false) and MUST authenticate the surfaced signerCert itself before
  // acting on the transaction state.
  var signerAuthenticated = false;
  if (expectedSignerCert != null) {
    if (!_sameKey(signer.cert, expectedSignerCert)) {
      throw _err("scep/untrusted-signer", "the pkiMessage signer's public key does not match opts.signerCert (RFC 8894 sec. 3.1)");
    }
    signerAuthenticated = true;
  }
  var attrs = signer.signedAttributes;
  // The mandatory attributes (RFC 8894 sec. 3.2.1): transactionID, messageType, senderNonce.
  var messageTypeCode = _readStr(attrs, "scepMessageType", _T_PRINTABLE);
  var transactionId = _readStr(attrs, "scepTransactionId", _T_PRINTABLE);
  var senderNonce = _readNonce(attrs, "scepSenderNonce");
  if (messageTypeCode == null) throw _err("scep/missing-attribute", "the pkiMessage is missing its messageType attribute (RFC 8894 sec. 3.2.1)");
  if (transactionId == null) throw _err("scep/missing-attribute", "the pkiMessage is missing its transactionID attribute (RFC 8894 sec. 3.2.1)");
  if (senderNonce == null) throw _err("scep/missing-attribute", "the pkiMessage is missing its senderNonce attribute (RFC 8894 sec. 3.2.1)");
  var messageType = MESSAGE_TYPE_BY_CODE[messageTypeCode];
  if (messageType == null) throw _err("scep/bad-message-type", "unknown messageType " + JSON.stringify(messageTypeCode) + " (RFC 8894 sec. 3.2.1.2)");
  var out = {
    signatureValid: true, signerAuthenticated: signerAuthenticated, signerCert: signer.cert,
    messageType: messageType, transactionId: transactionId, senderNonce: senderNonce,
    recipientNonce: null, pkiStatus: null, failInfo: null, failInfoText: null, messageData: null,
    certificates: null, crls: null,
  };
  // A CertRep carries pkiStatus (+ failInfo/failInfoText on FAILURE) and echoes the request's senderNonce.
  if (messageType === "CertRep") {
    var statusCode = _readStr(attrs, "scepPkiStatus", _T_PRINTABLE);
    if (statusCode == null) throw _err("scep/missing-attribute", "a CertRep is missing its pkiStatus attribute (RFC 8894 sec. 3.2.1.3)");
    out.pkiStatus = PKI_STATUS_BY_CODE[statusCode];
    if (out.pkiStatus == null) throw _err("scep/bad-pki-status", "unknown pkiStatus " + JSON.stringify(statusCode) + " (RFC 8894 sec. 3.2.1.3)");
    out.recipientNonce = _readNonce(attrs, "scepRecipientNonce");
    // A CertRep MUST echo the request's senderNonce in a recipientNonce (RFC 8894 sec. 3.1), so a
    // response missing it cannot be correlated to its request and is refused regardless of whether the
    // caller supplied expectedSenderNonce.
    if (out.recipientNonce == null) throw _err("scep/missing-attribute", "a CertRep is missing its recipientNonce attribute (RFC 8894 sec. 3.2.1.5)");
    if (out.pkiStatus === "FAILURE") {
      var failCode = _readStr(attrs, "scepFailInfo", _T_PRINTABLE);
      if (failCode == null) throw _err("scep/missing-attribute", "a FAILURE CertRep is missing its failInfo attribute (RFC 8894 sec. 3.2.1.4)");
      out.failInfo = FAIL_INFO_BY_CODE[failCode];
      if (out.failInfo == null) throw _err("scep/bad-fail-info", "unknown failInfo " + JSON.stringify(failCode) + " (RFC 8894 sec. 3.2.1.4)");
      out.failInfoText = _readStr(attrs, "scepFailInfoText", _T_UTF8);
    } else if (_find(attrs, "scepFailInfo") != null || _find(attrs, "scepFailInfoText") != null) {
      // failInfo and failInfoText are defined for a FAILURE response (RFC 8894 sec. 3.2.1.4): a SUCCESS
      // or PENDING CertRep carrying them asserts a contradictory authenticated status and is refused.
      throw _err("scep/unexpected-attribute", "a " + out.pkiStatus + " CertRep must not carry a failInfo or failInfoText attribute (RFC 8894 sec. 3.2.1.4)");
    }
  } else {
    out.recipientNonce = _readNonce(attrs, "scepRecipientNonce");
  }
  // A caller-stated expected senderNonce echo (RFC 8894 sec. 3.2.1.5): a message whose recipientNonce
  // does not match the nonce we sent MUST be rejected.
  if (expectedSenderNonce != null) {
    if (out.recipientNonce == null || !guard.crypto.constantTimeEqual(out.recipientNonce, expectedSenderNonce)) {
      throw _err("scep/nonce-mismatch", "the pkiMessage recipientNonce does not echo the sent senderNonce (RFC 8894 sec. 3.2.1.5)");
    }
  }
  // The pkcsPKIEnvelope is carried by a request and a SUCCESS CertRep, and is OMITTED by a FAILURE or
  // PENDING CertRep, whose payload is the status itself (RFC 8894 sec. 3.3.2.1). Decrypt only when the
  // message is one that carries the envelope, so a non-SUCCESS CertRep's authenticated status is
  // returned rather than turned into a decrypt failure over content that is not an EnvelopedData. The
  // eContent is bound to the verified signature (cms.verify).
  var carriesEnvelope = !(messageType === "CertRep" && (out.pkiStatus === "FAILURE" || out.pkiStatus === "PENDING"));
  if (carriesEnvelope) {
    // For a message that carries messageData, the pkcsPKIEnvelope is mandatory, MUST be an EnvelopedData,
    // and MUST encrypt id-data (RFC 8894 sec. 3.2, sec. 3.2.2). This is checked structurally, before any
    // recipient-key decryption, so an absent or off-profile envelope is never accepted as a valid
    // message with a null messageData, whether or not a recipient key was supplied.
    _assertValidEnvelope(v.eContent, messageType);
  } else {
    // A FAILURE or PENDING CertRep MUST omit the pkcsPKIEnvelope (RFC 8894 sec. 3.3.2): its payload is
    // the status itself. A message of those types that carries signed content is off-profile and
    // refused, so arbitrary attacker-supplied bytes are never accepted under a non-SUCCESS verdict.
    if (v.eContent != null && v.eContent.length > 0) {
      throw _err("scep/unexpected-envelope", "a " + out.pkiStatus + " CertRep must omit the pkcsPKIEnvelope (RFC 8894 sec. 3.3.2), but it carries signed content");
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
    // A SUCCESS CertRep's messageData MUST be a degenerate certs-only CMS SignedData carrying the
    // issued certificate(s) (RFC 8894 sec. 3.3.2, sec. 3.4). Validate that structure through the strict
    // CMS parser and surface the certificates, so a decrypted payload that is not a valid issuance
    // cannot read as a successful enrollment. The certificates are raw, for the caller to path-validate.
    if (messageType === "CertRep" && out.pkiStatus === "SUCCESS") {
      var payload = _readIssuancePayload(dec.content);
      out.certificates = payload.certificates;
      out.crls = payload.crls;
    } else if (messageType === "PKCSReq" || messageType === "RenewalReq") {
      // A request's messageData MUST be a PKCS#10 CertificationRequest (RFC 8894 sec. 3.3.1). Validate
      // the structure so a decrypted payload that is not one cannot read as a valid request; the raw
      // bytes stay in messageData for the caller to verify the proof-of-possession.
      try { schemaCsr.parse(dec.content); }
      catch (e) { throw _err("scep/bad-request-payload", "a " + messageType + " messageData must be a PKCS#10 CertificationRequest (RFC 8894 sec. 3.3.1)", e); }
    }
  }
  return out;
}
var _PARSE_KEYS = { recipientKey: 1, expectedSenderNonce: 1, signerCert: 1 };

module.exports = {
  build: build,
  parse: parse,
  MESSAGE_TYPES: MESSAGE_TYPE,
  PKI_STATUS: PKI_STATUS,
  FAIL_INFO: FAIL_INFO,
};
