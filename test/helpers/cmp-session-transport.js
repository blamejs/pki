// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// CMP session test transport: a STATEFUL routing fake CMP CA over the shared fakeTransport contract, so a
// pki.cmp.session enrollment (ir -> [waiting -> pollReq/pollRep]* -> granted -> certConf/pkiConf) is driven
// end to end WITHOUT a socket. On every request POST it DECODES the request PKIMessage header (via the
// shipped pki.schema.cmp.parse) to read the session-minted transactionID + senderNonce, then BUILDS a
// PROTECTED response (via pki.cmp.build under the CA key) that ECHOES transactionID + recipNonce (:= the
// request senderNonce) and carries a fresh senderNonce -- so the session's verify (with its opt-in
// transactionID / expectRecipNonce checks) accepts every leg. Each leg's response body arm is scripted.
// transport.calls records every request so a test asserts the exact chained nonces / stable transactionID.

var nodeCrypto = require("node:crypto");
var fakeTransport = require("./fake-transport").fakeTransport;

var PKIXCMP = "application/pkixcmp";
// The CA trust chain, built once by init(): a self-signed CA ANCHOR (cA + keyCertSign) and a CMP-signer cert
// issued by it (keyUsage digitalSignature). Every signed response is signed by the signer key with its cert
// in extraCerts and the header sender := the signer subject, so a session with trustAnchors:[caCert] resolves
// the signer, chains it to the anchor, and reports trusted (RFC 9483 sec. 3.1 / 3.2). Populated by init(pki).
var _caCertDer = null, _caKeyPk8 = null, _signerKeyPk8 = null, _signerCertDer = null, _signerDN = null, _leafCertDer = null;
var _signer2KeyPk8 = null, _signer2CertDer = null;   // a SECOND signer issued by the same CA (a clustered CA rotating its protection cert)
var NB = new Date(0), NA = new Date(4102444800000);

// Build the CA anchor + CMP-signer certs ONCE (async: x509.sign), plus an issued LEAF cert whose subject key
// is `subjectSpki` -- so the session's issued-cert key-match (RFC 4211) passes on the happy path. Idempotent;
// sets module.exports.caCert + .leafCert.
async function init(pki, subjectSpki) {
  if (_caCertDer) return { caCert: _caCertDer, leafCert: _leafCertDer };
  var caKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  _caKeyPk8 = caKp.privateKey.export({ format: "der", type: "pkcs8" });
  var caSpki = caKp.publicKey.export({ format: "der", type: "spki" });
  _caCertDer = await pki.x509.sign({ subject: "CN=CMP Test CA", subjectPublicKey: caSpki, serialNumber: 1, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: _caKeyPk8 });
  var sKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  _signerKeyPk8 = sKp.privateKey.export({ format: "der", type: "pkcs8" });
  var sSpki = sKp.publicKey.export({ format: "der", type: "spki" });
  _signerCertDer = await pki.x509.sign({ subject: [{ commonName: "cmp-ca.example" }], subjectPublicKey: sSpki, serialNumber: 2, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  _signerDN = pki.schema.x509.parse(_signerCertDer).subject.bytes;
  var s2Kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });   // the rotated signer: same subject, a different key, chains to the same CA
  _signer2KeyPk8 = s2Kp.privateKey.export({ format: "der", type: "pkcs8" });
  _signer2CertDer = await pki.x509.sign({ subject: [{ commonName: "cmp-ca.example" }], subjectPublicKey: s2Kp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 4, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  _leafCertDer = await pki.x509.sign({ subject: [{ commonName: "leaf" }], subjectPublicKey: subjectSpki, serialNumber: 3, notBefore: NB, notAfter: NA }, { key: _caKeyPk8, cert: _caCertDer });
  module.exports.caCert = _caCertDer;
  module.exports.leafCert = _leafCertDer;
  return { caCert: _caCertDer, leafCert: _leafCertDer };
}

// A leaf cert whose subject key is `subjectSpki` but whose SIGNATURE is Ed25519 / RSASSA-PSS-SHA384 (the OID
// does / does not convey the certConf hash): the key-match still passes, the certConf digest path is exercised.
function makeEd25519Cert(pki, subjectSpki) {
  var kp = nodeCrypto.generateKeyPairSync("ed25519");
  // the issuer name + public key go in the SIGNER opts so the signatureAlgorithm resolves from the Ed25519 signer, not the EC subject key
  return pki.x509.sign({ subject: [{ commonName: "ed-leaf" }], subjectPublicKey: subjectSpki, serialNumber: 1, notBefore: NB, notAfter: NA },
    { key: kp.privateKey.export({ format: "der", type: "pkcs8" }), publicKey: kp.publicKey.export({ format: "der", type: "spki" }), name: [{ commonName: "ed-ca" }] });
}
function makePssCert(pki, subjectSpki) {
  var kp = nodeCrypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048, hashAlgorithm: "sha384", saltLength: 48 });
  return pki.x509.sign({ subject: [{ commonName: "pss-leaf" }], subjectPublicKey: subjectSpki, serialNumber: 1, notBefore: NB, notAfter: NA },
    { key: kp.privateKey.export({ format: "der", type: "pkcs8" }), publicKey: kp.publicKey.export({ format: "der", type: "spki" }), name: [{ commonName: "pss-ca" }] });
}
// An ecdsaWithSHA256 leaf whose signatureAlgorithm OID final arc is bumped to an UNREGISTERED value (both the
// tbsCertificate.signature and outer signatureAlgorithm) -- x509.parse accepts the structure but resolves no
// name, so the certConf hash is indeterminate. The subject key (subjectSpki) is untouched (the key-match passes).
async function makeUnknownSigAlgCert(pki, subjectSpki) {
  var der = Buffer.from(await pki.x509.sign({ subject: [{ commonName: "unk-leaf" }], subjectPublicKey: subjectSpki, serialNumber: 1, notBefore: NB, notAfter: NA }, { key: _caKeyPk8, cert: _caCertDer }));
  var oidBytes = Buffer.from([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]);   // ecdsaWithSHA256
  var i = 0;
  while ((i = der.indexOf(oidBytes, i)) !== -1) { der[i + 9] = 0x63; i += 10; }   // final arc 2 -> 99 (unregistered)
  return der;
}

// legs: an array played in order, ONE per request. Each entry is either a body spec object (the response
// body arm, e.g. { ip: { response: [...] } }) OR { body, generalInfo?, tamper?, protect? } OR a
// function (reqMsg) -> one of those. `generalInfo` is set on the response header (e.g. a granted
// implicitConfirm). `tamper` flips a protection byte AFTER build (an unprotected/forged leg). `protect:false`
// emits the response UNprotected (no signature). cfg.macSecret protects with PBMAC1 instead of the signer key.
// Requires init(pki) to have run. Returns { transport, caCert }.
function fakeCa(pki, legs, cfg) {
  cfg = cfg || {};
  if (!_signerCertDer && !cfg.macSecret) throw new Error("cmp-session-transport: call await H.init(pki) before fakeCa (a signature CA chain is required)");
  var i = 0;
  var transport = fakeTransport(function (request) {
    var reqMsg = pki.schema.cmp.parse(request.body);
    var spec = legs[Math.min(i, legs.length - 1)];
    i += 1;
    if (typeof spec === "function") spec = spec(reqMsg);
    var leg = (spec && spec.body !== undefined) ? spec : { body: spec };
    // A signed response's sender := the SIGNER cert subject (RFC 9483 sec. 3.1); a MAC response uses a NULL-DN.
    var header = {
      sender: { directoryName: cfg.macSecret ? [] : _signerDN }, recipient: { directoryName: [] },
      transactionID: reqMsg.header.transactionID,
      recipNonce: reqMsg.header.senderNonce,
      senderNonce: nodeCrypto.randomBytes(16),
    };
    if (leg.generalInfo) header.generalInfo = leg.generalInfo;
    if (leg.noSenderNonce) delete header.senderNonce;   // a response that omits its senderNonce (breaks the chain for a follow-up leg)
    // MAC (PBMAC1) responses when cfg.macSecret is set; otherwise sign under the CMP-signer key (its cert,
    // issued by the CA anchor, is carried in extraCerts so the session chains it to trustAnchors:[caCert]).
    // leg.rotateSigner signs with the SECOND signer (a clustered CA rotating its protection cert mid-transaction).
    var sigKey = leg.rotateSigner ? _signer2KeyPk8 : _signerKeyPk8;
    var sigCert = leg.rotateSigner ? _signer2CertDer : _signerCertDer;
    var buildProt = cfg.macSecret ? { mac: { secret: cfg.macSecret } } : { key: sigKey, cert: sigCert };
    var protectOpts = leg.protect === false ? { key: sigKey, cert: sigCert } : buildProt;
    return Promise.resolve(pki.cmp.build({ header: header, body: leg.body }, protectOpts)).then(function (der) {
      if (leg.protect === false) {
        // strip the protection [0] + extraCerts [1] envelope children -> an unprotected SEQUENCE { header, body }
        der = _unprotect(pki, der);
      }
      if (leg.tamper) der = _tamperProtection(pki, der);   // flip a byte INSIDE the protection [0] -> the signature no longer matches
      if (leg.noExtraCerts) der = _stripExtraCerts(pki, der);   // drop the extraCerts [1] (a later leg the recipient already has the signer for)
      if (leg.malformedCert) der = _malformCert(pki, der, leg.certOf);   // swap the issued cert for a non-X.509 SEQUENCE + re-sign
      return { status: leg.status || 200, headers: { "content-type": leg.contentType || PKIXCMP }, body: der };
    });
  });
  return { transport: transport, caCert: _caCertDer };
}

// Tamper the protection: flip one byte INSIDE the message-protection [0] BIT STRING (a forged signature over
// the same ProtectedPart) so verify fails on the signature -- NOT a trailing extraCerts byte, which a signer
// resolved from trustAnchors would ignore. Rebuild the SEQUENCE with the mutated protection element in place.
function _tamperProtection(pki, der) {
  var b = pki.asn1.build;
  var kids = pki.asn1.decode(der).children;   // [header, body, protection[0], extraCerts[1]?]
  return b.sequence(kids.map(function (c) {
    if (c.tagClass === "context" && c.tagNumber === 0) {   // the [0] message protection
      var t = Buffer.from(c.bytes); t[t.length - 1] ^= 0xff; return b.raw(t);
    }
    return b.raw(c.bytes);
  }));
}

// Strip protection: rebuild SEQUENCE { header', body } dropping the header protectionAlg [1] + the message
// protection [0] + extraCerts [1] envelope children (the parser accepts an unprotected message; verify rejects it).
function _unprotect(pki, der) {
  var b = pki.asn1.build;
  var kids = pki.asn1.decode(der).children;   // [header, body, protection[0]?, extraCerts[1]?]
  var hk = pki.asn1.decode(kids[0].bytes).children.filter(function (c) { return !(c.tagClass === "context" && c.tagNumber === 1); });
  var headerDer = b.sequence(hk.map(function (c) { return b.raw(c.bytes); }));
  return b.sequence([b.raw(headerDer), b.raw(kids[1].bytes)]);
}

// Drop the extraCerts [1] envelope child -- the message stays protection-valid (protection covers only
// { header, body }), modelling a conforming CA that omits its signer cert on a later leg (RFC 9483 sec. 3.3).
function _stripExtraCerts(pki, der) {
  var b = pki.asn1.build;
  var kids = pki.asn1.decode(der).children.filter(function (c) { return !(c.tagClass === "context" && c.tagNumber === 1); });
  return b.sequence(kids.map(function (c) { return b.raw(c.bytes); }));
}

// A well-formed DER SEQUENCE of an EXACT byte length that is NOT a valid X.509 certificate (a SEQUENCE whose
// single child is an OCTET STRING) -- the CMP parser accepts it as opaque certificate bytes; x509.parse rejects it.
function _sequenceOfLength(pki, L) {
  var b = pki.asn1.build;
  for (var d = 0; d <= 8; d++) {
    for (var i = 0; i < 2; i++) {
      var s = L - 8 + (i === 0 ? d : -d);
      if (s < 0) continue;
      var m = b.sequence([b.octetString(Buffer.alloc(s, 0x41))]);
      if (m.length === L) return m;
    }
  }
  throw new Error("cmp-session-transport: cannot build a non-cert SEQUENCE of length " + L);
}

// Swap the issued certificate (certOf) for a same-length non-X.509 SEQUENCE and RE-SIGN the ProtectedPart with
// the CMP-signer key, so the forged response is protection-VALID + TRUSTED but carries a certificate x509.parse
// rejects -- what a non-conformant / hostile CA (not using our strict builder) could send over the wire.
function _malformCert(pki, der, certOf) {
  var b = pki.asn1.build;
  var idx = der.indexOf(certOf);
  if (idx < 0) throw new Error("cmp-session-transport: issued cert not found for malformCert");
  var malformed = _sequenceOfLength(pki, certOf.length);
  var swapped = Buffer.concat([der.slice(0, idx), malformed, der.slice(idx + certOf.length)]);
  var kids = pki.asn1.decode(swapped).children;   // [header, body, protection[0], extraCerts[1]?]
  var protectedPart = b.sequence([b.raw(kids[0].bytes), b.raw(kids[1].bytes)]);
  var key = nodeCrypto.createPrivateKey({ key: _signerKeyPk8, format: "der", type: "pkcs8" });
  var sig = nodeCrypto.sign("sha256", protectedPart, key);
  var out = [b.raw(kids[0].bytes), b.raw(kids[1].bytes), b.raw(b.explicit(0, b.bitString(sig, 0)))];
  if (kids[3]) out.push(b.raw(kids[3].bytes));
  return b.sequence(out);
}

// ---- response body-arm builders (RFC 9810 sec. 5.2.3 / 5.3.4 / 5.3.22) ----
// `extra` may carry { caPubs: [certDer,...] } (issuer certs on the CertRepMessage) and/or { privateKey } (a
// central-key-generation payload on the certifiedKeyPair).
function _certRep(arm, certReqId, statusCode, certDer, extra) {
  var r = { certReqId: certReqId, status: { status: statusCode } };
  if (certDer) { r.certifiedKeyPair = { certificate: certDer }; if (extra && extra.privateKey != null) r.certifiedKeyPair.privateKey = extra.privateKey; }
  var content = { response: [r] };
  if (extra && extra.caPubs != null) content.caPubs = extra.caPubs;
  var body = {}; body[arm] = content;
  return body;
}
function ip(certReqId, statusCode, certDer, extra) { return _certRep("ip", certReqId, statusCode, certDer, extra); }
function cp(certReqId, statusCode, certDer, extra) { return _certRep("cp", certReqId, statusCode, certDer, extra); }   // a cr / p10cr response
function kup(certReqId, statusCode, certDer, extra) { return _certRep("kup", certReqId, statusCode, certDer, extra); } // a kur response
function ipRejected(certReqId, failInfo, statusString) { return { ip: { response: [{ certReqId: certReqId, status: { status: 2, failInfo: failInfo || ["badRequest"], statusString: statusString || ["denied"] } }] } }; }
function ipEmpty() { return { ip: { response: [] } }; }   // a CertRepContent with no CertResponse -> no transition
function pollRep(certReqId, checkAfter) { return { pollRep: [{ certReqId: certReqId, checkAfter: checkAfter }] }; }
function pkiconf() { return { pkiconf: null }; }
function genp() { return { genp: [] }; }   // a general response -- an unexpected arm in an enrollment transaction
function errorBody(statusCode, failInfo) { return { error: { pKIStatusInfo: { status: statusCode, failInfo: failInfo || ["badRequest"], statusString: ["error"] } } }; }

// An enrollment request spec (an ir) whose template publicKey is the ENROLLING key -- it MUST equal the
// signature-protection key so the CRMF proof-of-possession (which defaults to the protection key) verifies.
// An optional certReqId sets the CRMF request id the session must echo in pollReq / certConf (RFC 4211).
function irRequest(spki, certReqId) {
  var ir = { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: spki } };
  if (certReqId != null) ir.certReqId = certReqId;
  return { ir: ir };
}

module.exports = {
  init: init, fakeCa: fakeCa, caCert: null, leafCert: null,
  ip: ip, cp: cp, kup: kup, ipRejected: ipRejected, ipEmpty: ipEmpty, pollRep: pollRep, pkiconf: pkiconf, genp: genp, errorBody: errorBody, irRequest: irRequest, makeEd25519Cert: makeEd25519Cert, makePssCert: makePssCert, makeUnknownSigAlgCert: makeUnknownSigAlgCert,
  IMPLICIT_CONFIRM_GI: [{ infoType: "implicitConfirm" }],
};
