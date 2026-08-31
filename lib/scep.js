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
 *   request wrapped in the signed-over-encrypted CMS layering, and a PKCSReq,
 *   RenewalReq, or CertRep parsed back to its verified transaction attributes and
 *   decrypted messageData.
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
var pkix = require("./schema-pkix");
var guard = require("./guard-all");
var C = require("./constants");
var httpTransport = require("./http-transport");   // the injectable https transport for the client verbs (sec. 4)
var nodeCrypto = require("node:crypto");

function _err(code, msg, cause) { return new ScepError(code, msg, cause); }

// The namespace pkix.keyUsageOf reads a certificate's keyUsage extension through.
var _KU_NS = pkix.makeNS("scep", ScepError, oid);

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

// The message types pki.scep.parse reads: the enrollment request pair a client builds and the CertRep
// response it receives. The CertPoll / GetCert / GetCRL client queries are refused (see parse).
var _PARSE_SUPPORTED = { PKCSReq: 1, RenewalReq: 1, CertRep: 1 };

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
  // The EnvelopedData must actually carry ciphertext: an inner envelope whose encryptedContent is absent
  // or a zero-length OCTET STRING has no messageData to recover (SCEP provides none out of band), so it
  // is refused (RFC 8894 sec. 3.2).
  var ct = parsed.encryptedContentInfo.encryptedContent;
  if (ct == null || ct.length === 0) throw _err("scep/missing-envelope", "the pkcsPKIEnvelope of a " + messageType + " message carries no encrypted content (RFC 8894 sec. 3.2)");
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

// A SCEP signer's certificate MUST be authorized to sign: its keyUsage extension, when present, must
// assert digitalSignature (RFC 8894 sec. 2.3 requires that bit specifically). A certificate whose
// keyUsage omits it, permitting only encryption or non-repudiation, is refused, so a signature it makes
// is not read as authenticated. A certificate with no keyUsage extension is unrestricted and passes.
function _assertSigningKeyUsage(certDer, label) {
  var cert;
  try { cert = schemaX509.parse(certDer); }
  catch (e) { throw _err("scep/bad-input", "the " + label + " could not be parsed for its key usage: " + e.message, e); }
  var ku = pkix.keyUsageOf(_KU_NS, cert, _err, "scep/bad-input", "the " + label + "'s");
  if (ku != null && ku.digitalSignature !== true) {
    throw _err("scep/bad-signer-usage", "the " + label + " keyUsage does not assert digitalSignature, so it is not authorized to sign (RFC 8894 sec. 2.3)");
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
  _assertSigningKeyUsage(signerCert, "signer certificate");
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
 * given the recipient key, decrypt the pkcsPKIEnvelope to recover the messageData. It reads the
 * enrollment message types PKCSReq, RenewalReq, and CertRep; the CertPoll, GetCert, and GetCRL client
 * queries a CA processes are refused (`scep/unsupported-message-type`). The verdict is
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
  // A SCEP signer's certificate must be authorized to sign (RFC 8894 sec. 2.3): a signature from a
  // certificate whose keyUsage permits only encryption is not read as an authenticated pkiMessage.
  _assertSigningKeyUsage(signer.cert, "pkiMessage signer certificate");
  // A valid signature proves only that the message is self-consistent with the certificate it embeds,
  // NOT that the signer is the expected party: anyone can mint a certificate and sign a forged CertRep
  // that echoes an observed nonce. A SCEP client MUST authenticate a CA response against the CA
  // certificate it already holds (RFC 8894 sec. 3.1). When opts.signerCert names the expected signer,
  // require the message signer's public key to match it; a caller that omits it gets a crypto-only
  // verdict (signerAuthenticated: false) and MUST authenticate the surfaced signerCert itself before
  // acting on the transaction state.
  var signerAuthenticated = false;
  if (expectedSignerCert != null) {
    // The certificate the caller pins is authenticated only if it is itself authorized to sign: a
    // same-key certificate embedded in the message cannot lend its digitalSignature bit to a pinned
    // certificate that permits only encryption (RFC 8894 sec. 2.3).
    _assertSigningKeyUsage(expectedSignerCert, "opts.signerCert");
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
  // This release reads the enrollment messages a SCEP client builds and receives: PKCSReq, RenewalReq,
  // and the CertRep response. The CertPoll / GetCert / GetCRL client queries a CA processes carry
  // IssuerAndSubject / IssuerAndSerialNumber messageData this codec does not model, so they are refused
  // rather than accepted with an unvalidated payload (RFC 8894 sec. 3.3.3, sec. 3.3.4).
  if (_PARSE_SUPPORTED[messageType] !== 1) {
    throw _err("scep/unsupported-message-type", "pki.scep.parse reads PKCSReq, RenewalReq, and CertRep; " + messageType + " is not read in this release");
  }
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
    // A request (PKCSReq / RenewalReq) is an initial message: the response-only attributes pkiStatus,
    // failInfo, failInfoText, and recipientNonce are defined for a CertRep and MUST NOT appear here
    // (RFC 8894 sec. 3.2.1). A request carrying any of them is off-profile and refused.
    if (_find(attrs, "scepPkiStatus") != null || _find(attrs, "scepFailInfo") != null ||
        _find(attrs, "scepFailInfoText") != null || _find(attrs, "scepRecipientNonce") != null) {
      throw _err("scep/unexpected-attribute", "a " + messageType + " request must not carry a CertRep response attribute, pkiStatus / failInfo / failInfoText / recipientNonce (RFC 8894 sec. 3.2.1)");
    }
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
    // the status itself, so the SignedData carries no encapsulated content (cms.verify surfaces it as a
    // null eContent). Any present eContent -- an attached OCTET STRING even a zero-length one -- is
    // off-profile and refused, so attacker-supplied bytes are never accepted under a non-SUCCESS verdict.
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

// ---- HTTP client (RFC 8894 sec. 4) -------------------------------------------
//
// The client verbs compose the shipped pkiMessage codec (build / parse) over an injectable transport
// (pki.transport.https by default; tests inject a fake). SCEP's message security is the CMS layer, not
// the transport (RFC 8894 sec. 2.8), so https is not forced at the URL level; a caller with a plain-HTTP
// CA injects its own transport. This release ships the mandatory-to-implement set (GetCACaps, GetCACert,
// PKCSReq via HTTP POST, AES-128-CBC + SHA-256, sec. 2.9) plus RenewalReq. Deferred, each re-opening
// under its named condition: GetNextCACert (the rollover-certificate authentication model, sec. 4.7);
// auto-poll / GetCert / GetCRL (their CertPoll / IssuerAndSerialNumber messageData builders are not in
// this codec); GET-carried PKIOperation (POST is mandatory, sec. 4.3); and HTTP auth (a CA behind an
// authenticating proxy).
var DEFAULT_TIMEOUT = C.TIME.seconds(30);
var MAX_TIMEOUT = C.TIME.seconds(600);

// The SCEP media types (RFC 8894 sec. 4.2 / 4.6). A 200 response MUST carry the operation's media type;
// a proxy error page or a wrong type is refused (fail-closed).
var CT_CA_CERT = "application/x-x509-ca-cert";       // GetCACert, a single DER certificate
var CT_CA_RA_CERT = "application/x-x509-ca-ra-cert";  // GetCACert, a certs-only CMS chain
var CT_PKI_MESSAGE = "application/x-pki-message";      // PKIOperation, a pkiMessage
var CT_PLAIN = "text/plain";                           // GetCACaps, a newline-separated capability list

function _isWs(c) { return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x0b || c === 0x0c; }
function _foldLower(s) { var o = "", i, n = s.length; for (i = 0; i < n; i++) { var c = s.charCodeAt(i); o += String.fromCharCode(c >= 65 && c <= 90 ? c + 32 : c); } return o; }
function _foldUpper(s) { var o = "", i, n = s.length; for (i = 0; i < n; i++) { var c = s.charCodeAt(i); o += String.fromCharCode(c >= 97 && c <= 122 ? c - 32 : c); } return o; }
function _trim(s) { var a = 0, e = s.length; while (a < e && _isWs(s.charCodeAt(a))) a += 1; while (e > a && _isWs(s.charCodeAt(e - 1))) e -= 1; return s.slice(a, e); }

// A case-insensitive single-header read. A duplicated header is refused: an injected transport promises
// only { status, headers, body }, and a smuggled duplicate must never be silently coalesced.
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
// The bare media type of a Content-Type (strip parameters, lower-case), by character scan (no regex).
function _mediaType(ct) {
  if (ct == null) return "";
  var s = String(ct), semi = s.indexOf(";");
  return _foldLower(_trim(semi === -1 ? s : s.slice(0, semi)));
}
function _bodyBuf(body) {
  if (Buffer.isBuffer(body)) return body;
  if (body == null) return Buffer.alloc(0);
  if (typeof body === "string") return Buffer.from(body, "utf8");
  // A BufferSource (Uint8Array, ArrayBuffer, DataView) from an injected transport: normalize its raw bytes
  // rather than String()-coercing it, which would turn a Uint8Array into its "48,1,..." toString.
  return guard.bytes.snapshotSource(body, ScepError, "scep/bad-response", "the response body");
}
// The byte length of a transport response body, read without a full copy so the size cap is enforced before
// the body is materialized (cap-before-copy): a string is measured as UTF-8, a Buffer or other BufferSource
// through the byte guard, which reads the length via a captured intrinsic rather than a shadowable accessor.
function _responseLen(body) {
  if (body == null) return 0;
  if (typeof body === "string") return Buffer.byteLength(body, "utf8");
  if (Buffer.isBuffer(body)) return guard.bytes.lengthOf(body);
  return guard.bytes.lengthOf(guard.bytes.source(body, ScepError, "scep/bad-response", "the response body"));
}
// Map opts.tls to the transport request.tls shape. rejectUnauthorized is NOT set -- the transport forces
// it on for an https connection.
function _tlsForRequest(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}
// Resolve a redirect target: refuse an https->http downgrade (a stripping MITM) and a cross-origin
// redirect on a non-idempotent method without opt-in; an unparseable Location is scep/bad-url.
function _redirectTarget(current, location, method, allowCrossOrigin) {
  if (location == null || _trim(String(location)) === "") throw _err("scep/bad-response", "a redirect response carried no Location header");
  var resolved;
  try { resolved = new URL(String(location), current.href); }
  catch (e) { throw _err("scep/bad-url", "a redirect Location did not parse: " + location, e); }
  // SCEP is an HTTP operation (RFC 8894 sec. 4): a redirect target on any other scheme (ftp:, file:, ...)
  // is refused before it reaches the transport, so a CA cannot steer an injected transport off HTTP.
  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") throw _err("scep/bad-url", "a redirect to a non-HTTP scheme is refused: " + resolved.protocol);
  if (current.protocol === "https:" && resolved.protocol !== "https:") throw _err("scep/insecure-redirect", "a redirect from https to " + resolved.protocol + " is refused");
  var safe = method === "GET" || method === "HEAD";
  if (resolved.origin !== current.origin && !safe && !allowCrossOrigin) throw _err("scep/cross-origin-redirect", "a cross-origin redirect on a " + method + " needs opts.allowCrossOriginRedirect");
  return resolved;
}
// Build a SCEP operation URL: the caller's base URL with ?operation=<op> appended (RFC 8894 sec. 4.1;
// SCEPPATH is whatever the base carries, the CA typically ignores it).
function _scepUrl(baseUrl, operation) {
  var url;
  try { url = new URL(String(baseUrl)); }
  catch (e) { throw _err("scep/bad-url", "the SCEP base URL did not parse: " + String(baseUrl), e); }
  // SCEP is an HTTP operation (RFC 8894 sec. 4): any other scheme (ftp:, file:, ...) is refused before the
  // URL reaches the transport, so an injected transport cannot be steered off HTTP.
  if (url.protocol !== "http:" && url.protocol !== "https:") throw _err("scep/bad-url", "the SCEP base URL must be http or https, got " + url.protocol);
  if (url.hash) throw _err("scep/bad-url", "the SCEP base URL must not carry a fragment");
  url.searchParams.set("operation", operation);
  return url;
}
// The transport request / redirect loop. Returns the terminal transport response ({ status, headers,
// body }). Digest / Basic auth is not answered (deferred); a 401 is returned to the verb, which throws.
function _drive(method, url, body, headers, opts, transport, budgets) {
  var redirects = 0, curMethod = method, curBody = body, initialOrigin = url.origin;
  // Snapshot the caller's TLS fields and redirect policy once, at the start, before the first transport call:
  // the redirect loop reruns per hop after each transport promise settles, so a hop must use the identity and
  // policy the initial hop did even if opts (or opts.tls) is replaced while a request is in flight.
  var tlsBase = _tlsForRequest(opts);
  var allowCrossOrigin = !!opts.allowCrossOriginRedirect;
  // The mTLS client identity (cert / key / pinned SNI) is sent ONLY to the origin the caller intended; a
  // cross-origin redirect gets a copy with those stripped, so a CA that redirects to another origin cannot
  // make the client authenticate to it with the caller's client credential. Derived fresh each hop, so a
  // redirect back to the original origin restores it.
  function _hopTls(current) {
    var t = tlsBase;
    if (current.origin !== initialOrigin) {
      // Every cross-origin hop overrides the client identity with an explicit null, unconditionally: an
      // omitted field falls back to the transport's own configured defaults (http-transport resolves
      // reqTls.cert !== undefined ? reqTls.cert : tlsDefaults.cert), so the override must fire even when the
      // request-level tls carries no credential, or a transport default would still reach the new origin.
      t = Object.assign({}, t);
      t.cert = null; t.key = null; t.servername = null;
    }
    return t;
  }
  function step(current) {
    var req = { method: curMethod, url: current.href, headers: headers, tls: _hopTls(current), timeout: budgets.timeout, maxResponseBytes: budgets.maxResponseBytes };
    if (curBody != null) req.body = curBody;
    return transport(req).then(function (res) {
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
function _client(method, url, body, headers, opts) {
  var transport = opts.transport || httpTransport.https({ E: _err, errPrefix: "scep" });
  var budgets = {
    timeout: guard.limits.cap(opts.timeout, "timeout", DEFAULT_TIMEOUT, { E: _err, code: "scep/bad-input", min: 1, max: MAX_TIMEOUT }),
    maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", C.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: _err, code: "scep/bad-input", min: 1, max: C.LIMITS.HTTP_MAX_RESPONSE_BYTES }),
    maxRedirects: guard.limits.cap(opts.maxRedirects, "maxRedirects", 5, { E: _err, code: "scep/bad-input", min: 0, max: 32 }),
  };
  return _drive(method, url, body, Object.assign({}, headers), opts, transport, budgets);
}
// Require a 200 with one of the expected media types; otherwise a typed error. Returns the body Buffer.
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

// The GetCACaps keyword set (RFC 8894 sec. 3.5.2, Table 7). Comparison is case-folded; the canonical
// spelling is stored. An unknown keyword is ignored (sec. 3.5.2). SCEPStandard implies the sec. 2.9 set.
var CAP_CANON = { AES: "AES", DES3: "DES3", GETNEXTCACERT: "GetNextCACert", POSTPKIOPERATION: "POSTPKIOperation",
  RENEWAL: "Renewal", "SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-512": "SHA-512", SCEPSTANDARD: "SCEPStandard" };
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
  var set = {}, lines = _splitLines(raw), i;
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
 *   - `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` -- transport bounds.
 * @example
 *   // requires: scepTransport -- an injected transport (omit to use pki.transport.https)
 *   var caps = await pki.scep.getCACaps("http://ca.example/scep", { transport: scepTransport });
 *   caps.AES === true;
 */
async function getCACaps(baseUrl, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep.getCACaps options");
  guard.identifier.assertKnownKeys(opts, _CACAPS_KEYS, _err, "scep/bad-input", "pki.scep.getCACaps has an unknown option: ");
  // Capture the strong-profile policy at the door: the downgrade check runs only after the GET await, so a
  // caller must not be able to relax its own guard by mutating opts while the request is in flight.
  var profile = { expectSCEPStandard: !!opts.expectSCEPStandard, requireStrongProfile: !!opts.requireStrongProfile };
  var res = await _client("GET", _scepUrl(baseUrl, "GetCACaps"), null, {}, opts);
  // An HTTP error or empty body means "none supported" (RFC 8894 sec. 3.5.1); a non-200 that is not a
  // clean error is still surfaced so a caller is not silently told "no capabilities" on a broken CA.
  if (res.status === 200) {
    // A conforming GetCACaps response carries content-type text/plain (RFC 8894 sec. 3.5.1). Enforcing it
    // stops a proxy's 200 HTML error page from being read as an empty (no capabilities) capability set.
    var caps = parseCapabilities(_requireOk(res, [CT_PLAIN], "GetCACaps"));
    _assertStrongProfile(caps, profile);
    return caps;
  }
  // A CA that does not implement GetCACaps signals it with an HTTP error, which RFC 8894 sec. 3.5.1 reads
  // as "no capabilities advertised": the codes that mean the operation is unsupported or unrecognized are
  // 400 (an old CA that does not parse the query), 404 (no such operation), 405 (GET not allowed on it), and
  // 501 Not Implemented. A transient server error (500, 502, 503) is surfaced instead of masked.
  if (res.status === 204 || res.status === 400 || res.status === 404 || res.status === 405 || res.status === 501) { _assertStrongProfile({}, profile); return {}; }
  throw _err("scep/http-error", "the SCEP GetCACaps returned HTTP " + res.status);
}

// The exact SPKI byte-match that identifies an issued certificate (RFC 5272 sec. 4.1); positional
// guessing is forbidden. `certs` is an array of raw cert Buffers, `wantSpki` the SPKI Buffer to match.
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
// Normalize an expected fingerprint (hex string, optionally colon/space separated, or a Buffer) to
// { algorithm, value }. Character-scan the hex (Hard rule #11).
function _normalizeFingerprint(fp, algName) {
  var algorithm = _foldLower(String(algName == null ? "sha256" : algName));
  // Validate the digest name at the entry point so a misspelled or build-unavailable fingerprintAlgorithm
  // is the typed scep/bad-input the client API documents, not a native createHash exception downstream.
  try { nodeCrypto.createHash(algorithm); }
  catch (_e) { throw _err("scep/bad-input", "fingerprintAlgorithm " + JSON.stringify(algorithm) + " is not an available hash"); }
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
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` -- transport bounds.
 * @example
 *   // requires: scepCaCertTransport -- an injected transport returning a single CA certificate
 *   var ca = await pki.scep.getCACert("http://ca.example/scep", { transport: scepCaCertTransport });
 *   ca.caCertificate;   // the CA certificate DER (a single-certificate response identifies it)
 */
async function getCACert(baseUrl, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep.getCACert options");
  guard.identifier.assertKnownKeys(opts, _CACERT_KEYS, _err, "scep/bad-input", "pki.scep.getCACert has an unknown option: ");
  // Normalize the expected fingerprint at the synchronous entry point: fail fast on a bad hash before the
  // network call, and pin against the value the caller supplied at the call rather than one mutated while
  // the GET is in flight.
  var fp = opts.expectedFingerprint != null ? _normalizeFingerprint(opts.expectedFingerprint, opts.fingerprintAlgorithm) : null;
  var res = await _client("GET", _scepUrl(baseUrl, "GetCACert"), null, {}, opts);
  var body = _requireOk(res, [CT_CA_CERT, CT_CA_RA_CERT], "GetCACert");
  var ct = _mediaType(_header(res.headers, "content-type")), certs, single = false;
  if (ct === CT_CA_CERT) {
    try { schemaX509.parse(body); } catch (e) { throw _err("scep/bad-response", "the GetCACert response is not a valid X.509 certificate", e); }
    certs = [Buffer.from(body)];
    single = true;
  } else {
    // parseCertsOnly fails closed with scep/no-certificates on an empty CertificateSet, so certs is non-empty here.
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
    // A single-certificate response (application/x-x509-ca-cert) is unambiguously the CA certificate. A
    // ca-ra chain carries the CA, any intermediates, and RA certificate(s) in a CMS CertificateSet whose
    // DER order does not identify the CA role, so caCertificate stays null there unless a fingerprint pins it.
    caCertificate = certs[0];
  }
  return { caCertificate: caCertificate, certificates: certs };
}

// The default transaction ID: 16 random bytes, hex-encoded. RFC 8894 sec. 3.2.1.1 requires the ID to be
// unique per operation, so a per-key value would collide across separate enrollments of the same key (a
// renewal could not be told from the original request). A caller wanting a stable per-device ID passes an
// explicit transactionId.
function _defaultTransactionId() {
  return nodeCrypto.randomBytes(16).toString("hex");
}
async function _pkiOperation(messageType, baseUrl, opts, verbName) {
  opts = guard.identifier.optionsObject(opts, _err, "scep/bad-input", "pki.scep." + verbName + " options");
  guard.identifier.assertKnownKeys(opts, _ENROLL_KEYS, _err, "scep/bad-input", "pki.scep." + verbName + " has an unknown option: ");
  if (opts.csr == null) throw _err("scep/bad-input", "a csr (PKCS#10 DER) is required");
  if (opts.caCert == null) throw _err("scep/bad-input", "a caCert (the SCEP CA certificate DER) is required");
  if (opts.signer == null || typeof opts.signer !== "object") throw _err("scep/bad-input", "a signer { cert, key } is required");
  if (opts.recipientKey == null || typeof opts.recipientKey !== "object") throw _err("scep/bad-input", "a recipientKey { cert, key } is required to decrypt the CA response");
  // Snapshot the response-authentication inputs at the synchronous entry point: the response is
  // authenticated (signerCert) and decrypted (recipientKey) only after the build and POST awaits, so a
  // caller mutating opts mid-flight cannot switch the trusted signer, or the CA the request was encrypted
  // to, out from under the exchange. Certificate bytes are copied; the recipient private key and the
  // request signer are held by reference.
  var caCert = guard.bytes.snapshotSource(opts.caCert, ScepError, "scep/bad-input", "the caCert");
  var signerCert = opts.responderCert != null ? guard.bytes.snapshotSource(opts.responderCert, ScepError, "scep/bad-input", "the responderCert") : caCert;
  // Capture the recipient-key FIELDS at the door (snapshotSource copies the cert bytes; the private key is
  // held by reference), not the opts.recipientKey object: a caller replacing opts.recipientKey.cert or .key
  // while the POST is in flight must not switch the credential the response is decrypted with.
  var recipientKey = _captureRecipientKey(opts.recipientKey);
  var signer = opts.signer;
  // The transport options are read by _client only after the build await, so snapshot them at the door too:
  // a caller replacing opts.transport (rerouting the completed request) or opts.tls.cert/.key (presenting the
  // next operation's mTLS identity) while the POST is in flight must not take effect. tls is shallow-copied
  // so a replaced field does not reach the transport; the transport function and budgets are held by value.
  var clientOpts = {
    transport: opts.transport,
    tls: opts.tls != null ? Object.assign({}, opts.tls) : opts.tls,
    maxRedirects: opts.maxRedirects,
    allowCrossOriginRedirect: opts.allowCrossOriginRedirect,
    timeout: opts.timeout,
    maxResponseBytes: opts.maxResponseBytes,
  };
  // Resolve the request URL at the door: _scepUrl reads String(baseUrl) only when the POST is sent (after the
  // build await), so a baseUrl whose toString() the caller changes mid-flight could otherwise redirect it.
  var postUrl = _scepUrl(baseUrl, "PKIOperation");
  var csrView = guard.bytes.snapshotSource(opts.csr, ScepError, "scep/bad-input", "the csr");
  var spki;
  try { spki = schemaCsr.parse(csrView).subjectPublicKeyInfo; }
  catch (e) { throw _err("scep/bad-input", "the csr is not a valid PKCS#10 CertificationRequest", e); }
  var senderNonce = nodeCrypto.randomBytes(16);
  var transactionId = opts.transactionId != null ? opts.transactionId : _defaultTransactionId();
  var reqMsg = await build({ messageType: messageType, messageData: csrView, recipient: caCert, signer: signer, transactionId: transactionId, senderNonce: senderNonce });
  var res = await _client("POST", postUrl, reqMsg, { "content-type": CT_PKI_MESSAGE }, clientOpts);
  var body = _requireOk(res, [CT_PKI_MESSAGE], "PKIOperation");
  var rep = await parse(body, { signerCert: signerCert, expectedSenderNonce: senderNonce, recipientKey: recipientKey });
  if (rep.messageType !== "CertRep") throw _err("scep/unexpected-message-type", "the SCEP response is a " + rep.messageType + ", not a CertRep");
  // Every message in one SCEP transaction carries the same transactionID (RFC 8894 sec. 3.2.1.1); a
  // response whose transactionID does not echo the request is for a different exchange and is refused,
  // even if its nonce and signer check out.
  if (rep.transactionId !== transactionId) throw _err("scep/transaction-id-mismatch", "the CertRep transactionID does not match the request (RFC 8894 sec. 3.2.1.1)");
  if (rep.pkiStatus === "FAILURE") {
    // Surface the CA's reason as structured fields, not only interpolated text, so a caller can branch on
    // the failInfo enumerant (RFC 8894 sec. 3.3.2.1) without parsing the human-readable message.
    var failErr = _err("scep/enrollment-failed", "the CA refused the request with failInfo " + JSON.stringify(rep.failInfo) + (rep.failInfoText ? " (" + rep.failInfoText + ")" : ""));
    failErr.failInfo = rep.failInfo;
    failErr.failInfoText = rep.failInfoText;
    throw failErr;
  }
  if (rep.pkiStatus === "PENDING") return { status: "PENDING", transactionId: rep.transactionId, senderNonce: senderNonce };
  var repCerts = rep.certificates || [];
  var issued = findIssuedCert(repCerts, spki.bytes);
  if (issued == null) throw _err("scep/no-issued-cert", "the SUCCESS CertRep did not carry a certificate matching the request public key");
  // A CMS CertificateSet states no issuance order, so a second certificate carrying the request public key
  // (a same-key renewal returning old and new, or a duplicate) leaves the issued certificate ambiguous; it
  // is refused rather than resolved by position.
  if (findIssuedCert(repCerts.filter(function (c) { return c !== issued; }), spki.bytes) != null) {
    throw _err("scep/ambiguous-issued-cert", "the SUCCESS CertRep carried more than one certificate matching the request public key; the issued certificate is ambiguous (RFC 8894 sec. 3.3)");
  }
  return { status: "SUCCESS", certificate: issued, certificates: repCerts, transactionId: rep.transactionId };
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
 * `scep/enrollment-failed` carrying the CA's failInfo; a PENDING returns `{ status: "PENDING",
 * transactionId }` for the caller to retry. The content key is transported under RSAES-OAEP, so the CA
 * certificate must be an RSA `keyEncipherment` certificate that accepts OAEP; the shared-secret
 * authenticator (RFC 8894 sec. 2.4) is the `challengePassword` the caller placed in the PKCS#10.
 *
 * @opts
 *   - `csr` -- the PKCS#10 CertificationRequest DER to enrol (place a `challengePassword` in it for shared-secret auth).
 *   - `caCert` -- the SCEP CA certificate DER the request is encrypted to.
 *   - `signer` -- `{ cert, key }`, the outer SignedData signer (for a PKCSReq, a self-signed certificate over the request key).
 *   - `recipientKey` -- `{ cert, key }`, the RSA key the CA encrypts the response to, to decrypt the CertRep.
 *   - `responderCert` -- the certificate to authenticate the CA's response signature against (defaults to `caCert`).
 *   - `transactionId` -- a caller-unique PrintableString (defaults to 16 random bytes, hex-encoded, unique per call).
 *   - `transport` / `timeout` / `maxResponseBytes` / `maxRedirects` / `tls` / `allowCrossOriginRedirect` -- transport bounds.
 * @example
 *   // requires: scepCsr, caCertDer, clientCertDer, clientKeyPkcs8, scepTransport
 *   var out = await pki.scep.enroll("http://ca.example/scep", { csr: scepCsr, caCert: caCertDer,
 *     signer: { cert: clientCertDer, key: clientKeyPkcs8 },
 *     recipientKey: { cert: clientCertDer, key: clientKeyPkcs8 }, transport: scepTransport });
 *   out.status;   // "SUCCESS", or "PENDING" to retry
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

var _TRANSPORT_KEYS = { transport: 1, timeout: 1, maxResponseBytes: 1, maxRedirects: 1, tls: 1, allowCrossOriginRedirect: 1 };
function _withKeys(extra) { var o = {}, k; for (k in _TRANSPORT_KEYS) o[k] = 1; for (k in extra) o[k] = 1; return o; }
var _CACAPS_KEYS = _withKeys({ expectSCEPStandard: 1, requireStrongProfile: 1 });
var _CACERT_KEYS = _withKeys({ expectedFingerprint: 1, fingerprintAlgorithm: 1 });
var _ENROLL_KEYS = _withKeys({ csr: 1, caCert: 1, signer: 1, recipientKey: 1, responderCert: 1, transactionId: 1 });

module.exports = {
  build: build,
  parse: parse,
  getCACaps: getCACaps,
  getCACert: getCACert,
  enroll: enroll,
  renew: renew,
  parseCapabilities: parseCapabilities,
  MESSAGE_TYPES: MESSAGE_TYPE,
  PKI_STATUS: PKI_STATUS,
  FAIL_INFO: FAIL_INFO,
};
