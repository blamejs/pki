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
var _issuerSignerKey = null, _issuerSignerCert = null, _issuerSignerDN = null;   // a CA that BOTH signs CMP protection AND issues the leaf
var _intCaKey = null, _intCaCert = null, _deepSignerKey = null, _deepSignerCert = null, _deepSignerDN = null;   // a signer under an INTERMEDIATE CA (chain [signer, intermediate])
var _deepSigner2Cert = null;   // a same-subject decoy for the deep signer (a meddler's parseable extraCerts[0])
var _untrustedSignerDecoy = null;   // the signer's key + subject under an UNTRUSTED root (verifies but is not trusted)
var _wrongSubjectSignerDecoy = null;   // the signer's key under a WRONG subject (verifies but the sender does not bind)
var _sanSignerAKey = null, _sanSignerACert = null, _sanSignerBKey = null, _sanSignerBCert = null;   // two EMPTY-subject signers with distinct SANs
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
  var isKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });   // a signer that BOTH protects CMP messages AND issues certs (cA + keyCertSign + digitalSignature)
  _issuerSignerKey = isKp.privateKey.export({ format: "der", type: "pkcs8" });
  _issuerSignerCert = await pki.x509.sign({ subject: [{ commonName: "cmp-issuer.example" }], subjectPublicKey: isKp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 5, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"], subjectKeyIdentifier: true, authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  _issuerSignerDN = pki.schema.x509.parse(_issuerSignerCert).subject.bytes;
  var intKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });   // an INTERMEDIATE CA issued by the root, and a signer under it
  _intCaKey = intKp.privateKey.export({ format: "der", type: "pkcs8" });
  _intCaCert = await pki.x509.sign({ subject: [{ commonName: "cmp-int-ca.example" }], subjectPublicKey: intKp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 7, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true, authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  var dsKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  _deepSignerKey = dsKp.privateKey.export({ format: "der", type: "pkcs8" });
  _deepSignerCert = await pki.x509.sign({ subject: [{ commonName: "cmp-deep-signer.example" }], subjectPublicKey: dsKp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 8, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: _intCaKey, cert: _intCaCert });
  _deepSignerDN = pki.schema.x509.parse(_deepSignerCert).subject.bytes;
  var ds2Kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });   // a same-subject DECOY for the deep signer (different key, also under the intermediate)
  _deepSigner2Cert = await pki.x509.sign({ subject: [{ commonName: "cmp-deep-signer.example" }], subjectPublicKey: ds2Kp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 12, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: _intCaKey, cert: _intCaCert });
  // A DECOY for the response signer: the SAME public key + subject as _signerCert (so the protection signature
  // verifies under it -> valid:true) but issued by an UNTRUSTED throwaway root (so it fails path validation ->
  // trusted:false / cmp/untrusted-signer). Models an intermediary swapping the signer cert for an unanchored copy.
  var untrustedKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var untrustedRoot = await pki.x509.sign({ subject: [{ commonName: "untrusted-root" }], subjectPublicKey: untrustedKp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 1, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: untrustedKp.privateKey.export({ format: "der", type: "pkcs8" }) });
  var signerSpki = pki.schema.x509.parse(_signerCertDer).subjectPublicKeyInfo.bytes;
  _untrustedSignerDecoy = await pki.x509.sign({ subject: [{ commonName: "cmp-ca.example" }], subjectPublicKey: signerSpki, serialNumber: 99, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: untrustedKp.privateKey.export({ format: "der", type: "pkcs8" }), cert: untrustedRoot });
  // The signer's key under a DIFFERENT subject (issued by the trusted CA so ONLY the sender binding fails): the
  // protection signature verifies under it, but the header sender (the real signer's subject) does not bind ->
  // cmp/sender-mismatch, another meddler-selected-decoy variant the cached-signer fallback must recover.
  _wrongSubjectSignerDecoy = await pki.x509.sign({ subject: [{ commonName: "evil-signer.example" }], subjectPublicKey: signerSpki, serialNumber: 100, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  // Two EMPTY-SUBJECT signers identified by DIFFERENT subjectAltName directoryNames, both issued by the root with
  // digitalSignature -- a forger and the legit CA are INDISTINGUISHABLE by the null subject but NOT by the SAN.
  var sanAKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  _sanSignerAKey = sanAKp.privateKey.export({ format: "der", type: "pkcs8" });
  _sanSignerACert = await pki.x509.sign({ subject: [], subjectPublicKey: sanAKp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 14, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ directoryName: [{ commonName: "san-ca-a" }] }], authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  var sanBKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  _sanSignerBKey = sanBKp.privateKey.export({ format: "der", type: "pkcs8" });
  _sanSignerBCert = await pki.x509.sign({ subject: [], subjectPublicKey: sanBKp.publicKey.export({ format: "der", type: "spki" }), serialNumber: 15, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ directoryName: [{ commonName: "san-ca-b" }] }], authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
  module.exports.caCert = _caCertDer;
  module.exports.leafCert = _leafCertDer;
  module.exports.intCaCert = _intCaCert;
  module.exports.signerCert = _signerCertDer;   // the CA's response-signer cert (subject cmp-ca.example) -- pin it via opts.expectedSender
  module.exports.sanSignerACert = _sanSignerACert;   // an EMPTY-subject signer named only by a directoryName SAN (san-ca-a)
  module.exports.sanSignerBCert = _sanSignerBCert;   // a distinct empty-subject signer (san-ca-b)
  return { caCert: _caCertDer, leafCert: _leafCertDer };
}

// A self-contained chain whose LEAF subject key is `subjectSpki` but whose SIGNATURE is Ed25519 /
// RSASSA-PSS-SHA384 (the OID does / does not convey the certConf hash). Returns { cert, ca } -- the leaf plus
// the self-signed CA that signed it, so the session (which now validates the issued leaf's chain) can be given
// the CA as a trust anchor. The key-match still passes; the certConf digest path is exercised on a VALID leaf.
async function _hashlessChain(pki, subjectSpki, caKp, edname) {
  var caKey = caKp.privateKey.export({ format: "der", type: "pkcs8" });
  var caSpki = caKp.publicKey.export({ format: "der", type: "spki" });
  var ca = await pki.x509.sign({ subject: [{ commonName: edname }], subjectPublicKey: caSpki, serialNumber: 1, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: caKey });
  var cert = await pki.x509.sign({ subject: [{ commonName: edname + "-leaf" }], subjectPublicKey: subjectSpki, serialNumber: 2, notBefore: NB, notAfter: NA, extensions: { authorityKeyIdentifier: true } }, { key: caKey, cert: ca });
  return { cert: cert, ca: ca };
}
// A leaf issued by the combined CMP-issuer signer (its cert is the response's protection signer, delivered
// only in extraCerts) -- used with fakeCa(..., { issuerSigner: true }) so the session must reuse the cached signer.
function makeSignerIssuedLeaf(pki, subjectSpki) {
  return pki.x509.sign({ subject: [{ commonName: "si-leaf" }], subjectPublicKey: subjectSpki, serialNumber: 6, notBefore: NB, notAfter: NA, extensions: { authorityKeyIdentifier: true } }, { key: _issuerSignerKey, cert: _issuerSignerCert });
}
// A leaf signed by the INTERMEDIATE CA (used with fakeCa(..., { deepSigner: true }) whose extraCerts carry the
// intermediate): the leaf chains leaf -> intermediate -> root, so its validation needs the cached chain material.
function makeIntSignedLeaf(pki, subjectSpki) {
  return pki.x509.sign({ subject: [{ commonName: "int-leaf" }], subjectPublicKey: subjectSpki, serialNumber: 9, notBefore: NB, notAfter: NA, extensions: { authorityKeyIdentifier: true } }, { key: _intCaKey, cert: _intCaCert });
}
// A CA-issued leaf whose SPKI shares the requested key's exact BIT STRING but declares a DIFFERENT EC named
// curve (P-256 -> secp384r1 OID). The keys are NOT equal -- the identity check must keep the AlgorithmIdentifier
// parameters and reject, not collapse the two onto one identity by dropping them. x509.sign embeds the SPKI
// verbatim, and the CA signature is valid, so the leaf path-validates; only the key-match must fail.
function makeCurveSwappedLeaf(pki, subjectSpki) {
  var b = pki.asn1.build, node = pki.asn1.decode(subjectSpki), algId = node.children[0];
  var swapped = b.sequence([
    b.sequence([b.raw(algId.children[0].bytes), b.oid(pki.oid.byName("secp384r1"))]),
    b.raw(node.children[1].bytes),
  ]);
  return pki.x509.sign({ subject: [{ commonName: "curve-swapped-leaf" }], subjectPublicKey: swapped, serialNumber: 10, notBefore: NB, notAfter: NA, extensions: { authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
}
// A CA-issued leaf whose rsaEncryption SPKI shares the requested key's exact bits but carries a MALFORMED
// parameter (an empty OCTET STRING instead of the required NULL/absent). x509.parse + Node tolerate it, but the
// identity check must NOT normalize it to the clean key -- a parameter-changed certificate is not the requested key.
// An RSASSA-PSS-signed leaf whose PSS parameters carry NO explicit hashAlgorithm (defaulting to SHA-1, which the
// certConf-hash resolver does not map) -- so _pssDigest returns null and the certConf hash is indeterminate.
function makePssIndeterminateCert(pki, subjectSpki) {
  var pssAlgId = pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("rsassaPss")), pki.asn1.build.sequence([])]);   // rssaPss + empty params
  return _rebuildSigAlg(pki, subjectSpki, "pss-indet-leaf", pssAlgId);
}
// An RSASSA-PSS-signed leaf whose params carry an EXPLICIT hashAlgorithm [0] naming an UNMAPPED digest (SHA-1) --
// so _pssDigest reads the OID but the map returns null: the explicit-but-unresolvable branch of the resolver.
function makePssExplicitUnknownHashCert(pki, subjectSpki) {
  var b = pki.asn1.build;
  var params = b.sequence([b.explicit(0, b.sequence([b.oid(pki.oid.byName("sha1")), b.nullValue()]))]);   // [0] EXPLICIT { sha1, NULL }
  return _rebuildSigAlg(pki, subjectSpki, "pss-sha1-leaf", b.sequence([b.oid(pki.oid.byName("rsassaPss")), params]));
}
function makeMalformedRsaParamCert(pki, rsaSpki) {
  var b = pki.asn1.build, node = pki.asn1.decode(rsaSpki), algId = node.children[0];
  var variant = b.sequence([
    b.sequence([b.raw(algId.children[0].bytes), b.octetString(Buffer.alloc(0))]),   // rsaEncryption + empty OCTET STRING (malformed param)
    b.raw(node.children[1].bytes),
  ]);
  return pki.x509.sign({ subject: [{ commonName: "malformed-rsa-leaf" }], subjectPublicKey: variant, serialNumber: 13, notBefore: NB, notAfter: NA, extensions: { authorityKeyIdentifier: true } }, { key: _caKeyPk8, cert: _caCertDer });
}
// N DISTINCT self-signed filler certificates (one key, distinct serial numbers -> distinct TBS -> distinct
// identity), so a near-ceiling caller intermediates pool reaches the candidate ceiling by DISTINCT count (not
// duplicate copies the session now collapses). Inert filler: none chains to a session leaf or signer.
async function manyDistinctCerts(pki, n) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var key = kp.privateKey.export({ format: "der", type: "pkcs8" }), spki = kp.publicKey.export({ format: "der", type: "spki" });
  var out = [];
  for (var i = 0; i < n; i++) out.push(await pki.x509.sign({ subject: [{ commonName: "filler-" + i }], subjectPublicKey: spki, serialNumber: 100000 + i, notBefore: NB, notAfter: NA }, { key: key }));
  return out;
}
function makeEd25519Cert(pki, subjectSpki) { return _hashlessChain(pki, subjectSpki, nodeCrypto.generateKeyPairSync("ed25519"), "ed-ca"); }
function makePssCert(pki, subjectSpki) { return _hashlessChain(pki, subjectSpki, nodeCrypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048, hashAlgorithm: "sha384", saltLength: 48 }), "pss-ca"); }
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
// A leaf whose signatureAlgorithm is a REGISTERED but NON-SIGNATURE algorithm (rsaEncryption): x509.parse
// resolves a name, but it conveys no certConf hash and is not a hashless signature -- the transaction must be
// refused, not defaulted to SHA-256. Rebuilds the tbs.signature + outer signatureAlgorithm as rsaEncryption.
async function makeRegisteredNonSigCert(pki, subjectSpki) { return _rebuildSigAlg(pki, subjectSpki, "nonsig-leaf", pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("rsaEncryption")), pki.asn1.build.nullValue()])); }
// A leaf carrying a COMPOSITE signatureAlgorithm OID (its OID conveys no single message hash). Rebuilt (the
// signature bytes are not a real composite sig), so it must be delivered to a MAC session -- which skips
// leaf path-validation -- to exercise the composite branch of the certConf-hash resolver.
async function makeCompositeSigOidCert(pki, subjectSpki, oidName) { return _rebuildSigAlg(pki, subjectSpki, "comp-leaf", pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName(oidName || "id-MLDSA44-ECDSA-P256-SHA256"))])); }
async function _rebuildSigAlg(pki, subjectSpki, cn, newAlgId) {
  var b = pki.asn1.build;
  var der = await pki.x509.sign({ subject: [{ commonName: cn }], subjectPublicKey: subjectSpki, serialNumber: 1, notBefore: NB, notAfter: NA }, { key: _caKeyPk8, cert: _caCertDer });
  var certKids = pki.asn1.decode(der).children;   // [tbs, signatureAlgorithm, signatureValue]
  var tbsKids = pki.asn1.decode(certKids[0].bytes).children;
  var newTbs = b.sequence(tbsKids.map(function (c) { return c.bytes.equals(certKids[1].bytes) ? b.raw(newAlgId) : b.raw(c.bytes); }));
  return b.sequence([b.raw(newTbs), b.raw(newAlgId), b.raw(certKids[2].bytes)]);
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
    // signer2 (rotateSigner) shares signer1's subject, so both use _signerDN; the issuer-signer has its own DN.
    var header = {
      sender: { directoryName: cfg.macSecret ? [] : (cfg.deepSigner ? _deepSignerDN : (cfg.issuerSigner ? _issuerSignerDN : _signerDN)) }, recipient: { directoryName: [] },
      transactionID: reqMsg.header.transactionID,
      recipNonce: reqMsg.header.senderNonce,
      senderNonce: nodeCrypto.randomBytes(16),
    };
    if (leg.foreignSigner) header.sender = { directoryName: _issuerSignerDN };   // a DIFFERENT trusted signer (own subject) forging a leg
    if (leg.emptySanSigner) header.sender = { directoryName: [{ commonName: leg.emptySanSigner === "b" ? "san-ca-b" : "san-ca-a" }] };   // an EMPTY-subject signer's sender IS its SAN (RFC 9483 sec. 3.1)
    if (leg.generalInfo) header.generalInfo = leg.generalInfo;
    if (leg.noSenderNonce) delete header.senderNonce;   // a response that omits its senderNonce (breaks the chain for a follow-up leg)
    // MAC (PBMAC1) responses when cfg.macSecret is set; otherwise sign under the CMP-signer key (its cert,
    // issued by the CA anchor, is carried in extraCerts so the session chains it to trustAnchors:[caCert]).
    // leg.rotateSigner signs with the SECOND signer (a clustered CA rotating its protection cert mid-transaction);
    // cfg.issuerSigner signs with the combined CA that both protects the message AND issued the leaf.
    var defaultKey = cfg.deepSigner ? _deepSignerKey : (cfg.issuerSigner ? _issuerSignerKey : _signerKeyPk8);
    var defaultCert = cfg.deepSigner ? _deepSignerCert : (cfg.issuerSigner ? _issuerSignerCert : _signerCertDer);
    var sigKey = leg.emptySanSigner === "b" ? _sanSignerBKey : (leg.emptySanSigner ? _sanSignerAKey : (leg.foreignSigner ? _issuerSignerKey : (leg.rotateSigner ? _signer2KeyPk8 : defaultKey)));
    var sigCert = leg.emptySanSigner === "b" ? _sanSignerBCert : (leg.emptySanSigner ? _sanSignerACert : (leg.foreignSigner ? _issuerSignerCert : (leg.rotateSigner ? _signer2CertDer : defaultCert)));
    var sigProt = { key: sigKey, cert: sigCert };
    if (cfg.deepSigner && !leg.rotateSigner && !cfg.deepSignerBareExtra) sigProt.extraCerts = [_intCaCert];   // carry the intermediate so extraCerts = [signer, intermediate]
    // deepSignerBareExtra: the response carries ONLY its signer (no intermediate) -- the signer's issuer must come
    // from the CALLER intermediates pool, so the signer-path reserve must NOT forfeit that caller slot.
    var buildProt = cfg.macSecret ? { mac: { secret: cfg.macSecret } } : sigProt;
    var protectOpts = leg.protect === false ? { key: sigKey, cert: sigCert } : buildProt;
    return Promise.resolve(pki.cmp.build({ header: header, body: leg.body }, protectOpts)).then(function (der) {
      if (leg.protect === false) {
        // strip the protection [0] + extraCerts [1] envelope children -> an unprotected SEQUENCE { header, body }
        der = _unprotect(pki, der);
      }
      if (leg.tamper) der = _tamperProtection(pki, der);   // flip a byte INSIDE the protection [0] -> the signature no longer matches
      if (leg.noExtraCerts) der = _stripExtraCerts(pki, der);   // drop the extraCerts [1] (a later leg the recipient already has the signer for)
      if (leg.badExtraCert) der = _addBadExtraCert(pki, der);   // append a malformed entry to extraCerts (bounded away by verify)
      if (leg.padExtraCerts) der = _padExtraCerts(pki, der, leg.padExtraCerts);   // flood extraCerts with duplicate certs
      if (leg.decoyExtraCert) der = _prependExtraCert(pki, der);   // prepend a same-subject decoy the resolver selects first
      if (leg.deepDecoyExtra) der = _deepDecoyExtra(pki, der);   // replace extraCerts with a lone deep-signer decoy (omits the real intermediate)
      if (leg.untrustedDecoy) der = _prependExtraCert(pki, der, _untrustedSignerDecoy);   // prepend the signer's key under an untrusted root (valid but untrusted)
      if (leg.wrongSubjectDecoy) der = _prependExtraCert(pki, der, _wrongSubjectSignerDecoy);   // prepend the signer's key under a wrong subject (valid but sender-mismatched)
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
  var kids = pki.asn1.decode(der).children;   // [header, body, protection[0]?, extraCerts[1]?]
  // extraCerts is the LAST child when present; the ip/cp/kup body is ALSO context [1] (ip is arm 1) but earlier,
  // so drop only the trailing [1] child (the extraCerts), never the body.
  var last = kids.length - 1;
  if (last >= 0 && kids[last].tagClass === "context" && kids[last].tagNumber === 1) kids = kids.slice(0, last);
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

// Append a malformed (non-X.509) SEQUENCE to the response's extraCerts [1]. extraCerts is OUTSIDE the
// protected part, so no re-sign is needed -- cmp.verify bounds the malformed entry away yet still verifies.
function _addBadExtraCert(pki, der) {
  var b = pki.asn1.build;
  var kids = pki.asn1.decode(der).children;   // [header, body[N], protection[0]?, extraCerts[1]?]
  var last = kids.length - 1;   // extraCerts is the LAST child; the ip body is ALSO context [1], so match by position
  return b.sequence(kids.map(function (c, i) {
    if (i === last && c.tagClass === "context" && c.tagNumber === 1) {
      var certs = c.children[0].children.map(function (x) { return b.raw(x.bytes); });
      certs.push(b.raw(b.sequence([b.integer(1n)])));   // a non-cert SEQUENCE
      return b.raw(b.explicit(1, b.sequence(certs)));
    }
    return b.raw(c.bytes);
  }));
}
// REPLACE the extraCerts [1] envelope with a single same-subject deep-signer decoy: the resolver selects it
// first (protection fails under it -> the cached-signer fallback rescues the leg), and its bytes are what a
// cache refresh WOULD store -- a pool that omits the real intermediate the deep signer needs to reach the root.
function _deepDecoyExtra(pki, der) {
  var b = pki.asn1.build;
  var kids = pki.asn1.decode(der).children;
  var last = kids.length - 1;
  var out = kids.map(function (c, i) {
    if (i === last && c.tagClass === "context" && c.tagNumber === 1) return b.raw(b.explicit(1, b.sequence([b.raw(_deepSigner2Cert)])));
    return b.raw(c.bytes);
  });
  return b.sequence(out);
}
// PREPEND a same-subject decoy certificate (signer2 shares signer1's subject but has a different key) to the
// unsigned extraCerts, so the verifier's RFC 9483 sec. 3.3 "extraCerts[0] is the protection cert" rule selects
// the decoy first and protection fails under a key that never signed -- modelling a network meddler.
function _prependExtraCert(pki, der, decoyCert) {
  var b = pki.asn1.build;
  var lead = decoyCert || _signer2CertDer;
  var kids = pki.asn1.decode(der).children;
  var last = kids.length - 1;
  return b.sequence(kids.map(function (c, i) {
    if (i === last && c.tagClass === "context" && c.tagNumber === 1) {
      var certs = [b.raw(lead)].concat(c.children[0].children.map(function (x) { return b.raw(x.bytes); }));
      return b.raw(b.explicit(1, b.sequence(certs)));
    }
    return b.raw(c.bytes);
  }));
}
// Append N duplicate copies of the first extraCerts entry (all valid, all identical) -- a flood the verifier
// dedups + caps but which, un-bounded, would push a cached pool past path.build's candidate ceiling.
function _padExtraCerts(pki, der, n) {
  var b = pki.asn1.build;
  var kids = pki.asn1.decode(der).children;
  var last = kids.length - 1;
  return b.sequence(kids.map(function (c, i) {
    if (i === last && c.tagClass === "context" && c.tagNumber === 1) {
      var existing = c.children[0].children;
      var certs = existing.map(function (x) { return b.raw(x.bytes); });
      for (var k = 0; k < n; k++) certs.push(b.raw(existing[0].bytes));
      return b.raw(b.explicit(1, b.sequence(certs)));
    }
    return b.raw(c.bytes);
  }));
}
// A leaf signed by the ROOT CA (chains directly to the anchor) for an arbitrary subject SPKI.
function makeCaSignedLeaf(pki, subjectSpki, cn) {
  return pki.x509.sign({ subject: [{ commonName: cn }], subjectPublicKey: subjectSpki, serialNumber: 12, notBefore: NB, notAfter: NA }, { key: _caKeyPk8, cert: _caCertDer });
}
// Re-encode an SPKI with the AlgorithmIdentifier parameters DROPPED (e.g. strip the rsaEncryption NULL) --
// a different byte encoding of the SAME key, to prove the issued-cert key-match compares keys, not bytes.
function stripSpkiParams(pki, spkiDer) {
  var b = pki.asn1.build;
  var node = pki.asn1.decode(spkiDer);
  return b.sequence([b.raw(b.sequence([b.raw(node.children[0].children[0].bytes)])), b.raw(node.children[1].bytes)]);
}

// Flip a byte in the leaf's signatureValue (the final BIT STRING content) -- x509.parse still succeeds
// (structural), the key still matches, but the ECDSA signature no longer verifies, so the leaf must fail the
// session's issued-certificate path validation (RFC 5280 sec. 6.1) rather than reach certConf.
function corruptLeafSig(leafDer) {
  var d = Buffer.from(leafDer);
  d[d.length - 1] ^= 0xff;
  return d;
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
function irRequest(spki, certReqId, key) {
  var ir = { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: spki } };
  if (certReqId != null) ir.certReqId = certReqId;
  if (key != null) ir.key = key;   // the requested key's private half for the CRMF proof of possession (required for a MAC session)
  return { ir: ir };
}

module.exports = {
  init: init, fakeCa: fakeCa, caCert: null, leafCert: null, intCaCert: null, signerCert: null, sanSignerACert: null, sanSignerBCert: null,
  ip: ip, cp: cp, kup: kup, ipRejected: ipRejected, ipEmpty: ipEmpty, pollRep: pollRep, pkiconf: pkiconf, genp: genp, errorBody: errorBody, irRequest: irRequest, makeEd25519Cert: makeEd25519Cert, makePssCert: makePssCert, makeUnknownSigAlgCert: makeUnknownSigAlgCert, makeRegisteredNonSigCert: makeRegisteredNonSigCert, makeCompositeSigOidCert: makeCompositeSigOidCert, corruptLeafSig: corruptLeafSig, makeSignerIssuedLeaf: makeSignerIssuedLeaf, makeIntSignedLeaf: makeIntSignedLeaf, makeCaSignedLeaf: makeCaSignedLeaf, makeCurveSwappedLeaf: makeCurveSwappedLeaf, makeMalformedRsaParamCert: makeMalformedRsaParamCert, makePssIndeterminateCert: makePssIndeterminateCert, makePssExplicitUnknownHashCert: makePssExplicitUnknownHashCert, manyDistinctCerts: manyDistinctCerts, stripSpkiParams: stripSpkiParams,
  IMPLICIT_CONFIRM_GI: [{ infoType: "implicitConfirm" }],
};
