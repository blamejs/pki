// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// lib/cmp-build.js; this file adds the @primitive pki.cmp.session block and re-exports the cmp message

var cmp = require("./cmp-verify");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var schemaCmp = require("./schema-cmp");
var schemaCrmf = require("./schema-crmf");
var schemaCrl = require("./schema-crl");
var crmfSign = require("./crmf-sign");
var cmpBuild = require("./cmp-build");
var csr = require("./schema-csr");
var guard = require("./guard-all");
var compositeSig = require("./composite-sig");
var constants = require("./constants");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var sleepUtil = require("./sleep");
var retryAfter = require("./http-retry-after");
var httpTransport = require("./http-transport");

var CmpError = frameworkError.CmpError;
function _err(code, message, cause) { return new CmpError(code, message, cause); }
var OID_IMPLICIT_CONFIRM = oid.byName("implicitConfirm");

var _engine = null;
function setEngine(engine) { _engine = engine; }

var HASHLESS_SIG_OIDS = {};
(function () {
  var names = ["Ed25519", "Ed448", "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87"];
  ["sha2", "shake"].forEach(function (h) { ["128s", "128f", "192s", "192f", "256s", "256f"].forEach(function (s) { names.push("id-slh-dsa-" + h + "-" + s); }); });
  names.forEach(function (n) { var o = oid.byName(n); if (o) HASHLESS_SIG_OIDS[o] = 1; });
})();
var SIG_OID_TO_HASH = {};
[["sha256WithRSAEncryption", "SHA-256"], ["sha384WithRSAEncryption", "SHA-384"], ["sha512WithRSAEncryption", "SHA-512"],
  ["ecdsaWithSHA256", "SHA-256"], ["ecdsaWithSHA384", "SHA-384"], ["ecdsaWithSHA512", "SHA-512"]].forEach(function (row) {
  var o = oid.byName(row[0]); if (o) SIG_OID_TO_HASH[o] = row[1];
});
var OID_RSASSA_PSS = oid.byName("rsassaPss");
var OID_RSA_ENCRYPTION = oid.byName("rsaEncryption");
var OID_IDP = oid.byName("issuingDistributionPoint");
var OID_BASIC_CONSTRAINTS = oid.byName("basicConstraints");
var OID_KEY_USAGE = oid.byName("keyUsage");
var HASH_OID_TO_DIGEST = {};
[["sha256", "SHA-256"], ["sha384", "SHA-384"], ["sha512", "SHA-512"]].forEach(function (row) { var o = oid.byName(row[0]); if (o) HASH_OID_TO_DIGEST[o] = row[1]; });
var COMPOSITE_PH_HASHALG = { "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512" };

var KNOWN_SESSION_OPTS = {
  url: 1, key: 1, cert: 1, mac: 1, trustAnchors: 1, intermediates: 1, recipient: 1, sender: 1,
  extraCerts: 1, implicitConfirm: 1, maxPolls: 1, maxTotalWait: 1, sleep: 1, time: 1,
  transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, proxy: 1, pss: 1, digestAlgorithm: 1,
  acceptCert: 1, senderKID: 1, recipKID: 1, expectedSender: 1,
};

var TRANSCRIPT_RETAIN_RESPONSES = 2;
var DEFAULT_MAX_POLLS = 20;
var DEFAULT_MAX_TOTAL_WAIT = retryAfter.MAX_RETRY_AFTER_SECONDS;
var DEFAULT_CERT_REQ_ID = 0;
var P10CR_CERT_REQ_ID = -1;
var ENROLL_ARMS = { ir: 1, cr: 1, kur: 1, p10cr: 1 };
var RESPONSE_ARM = { ir: "ip", cr: "cp", kur: "kup", p10cr: "cp", rr: "rp", genm: "genp" };
var WHOLE_MESSAGE_CERT_REQ_ID = -1;

var INFO_OPS = Object.assign(Object.create(null), {
  caCerts: { name: "caCerts", requestOid: "caCerts", responseOid: "caCerts", value: false, read: "readCaCerts" },
  rootCaCert: { name: "rootCaCert", requestOid: "rootCaCert", responseOid: "rootCaKeyUpdate", value: "cert", read: "readRootCaKeyUpdate" },
  certReqTemplate: { name: "certReqTemplate", requestOid: "certReqTemplate", responseOid: "certReqTemplate", value: false, read: "readCertReqTemplate" },
  crlUpdate: { name: "crlUpdate", requestOid: "crlStatusList", responseOid: "crls", value: "crlStatus", read: "readCrls" },
});
var KNOWN_REVOKE_KEYS = { certificate: 1, certDetails: 1, reason: 1 };
var RSA_ARCS = ["rsaEncryption", "rsaSignatureWithripemd160", "id-TA-RSA-v1-5-SHA-256",
  "sigS-ISO9796-1-DFUE", "sigS-ISO9796-2Withrsa", "sigS-ISO9796-2rndWithrsa"].map(function (n) {
  return oid.toArcs(oid.byName(n)).slice(0, -1);
});
var RSA_OFF_ARC = Object.create(null);
["id-rsa-kem", "id-kem-rsa",
  "id-rsassa-pkcs1-v1_5-with-sha3-224", "id-rsassa-pkcs1-v1_5-with-sha3-256",
  "id-rsassa-pkcs1-v1_5-with-sha3-384", "id-rsassa-pkcs1-v1_5-with-sha3-512",
  "id-RSASSA-PSS-SHAKE128", "id-RSASSA-PSS-SHAKE256",
  "md4WithRSA", "md5WithRSA", "md4WithRSAEncryption", "rsaSignature", "mdc2WithRSASignature",
  "shaWithRSAEncryption", "rsaKeyTransport",
  "md2WithRSASignature", "md5WithRSASignature", "sha1WithRSASignature",
  "rsa",
  "sqMod-nWithRSA", "mdc2WithRSA",
  "sm3WithRSAEncryption",
  "sigS-ISO9796-1", "sigS-ISO9796-2", "sigS-ISO9796-2rnd",
].forEach(function (n) { var d = oid.byName(n); if (d) RSA_OFF_ARC[d] = 1; });
var RSA_ARC_EXCLUDE = Object.create(null);
["mgf1", "pSpecified"].forEach(function (n) { var d = oid.byName(n); if (d) RSA_ARC_EXCLUDE[d] = 1; });

var CRL_REASON_NAMES = Object.create(null);
Object.keys(constants.NAMES.CRL_REASON).forEach(function (v) { CRL_REASON_NAMES[constants.NAMES.CRL_REASON[v]] = 1; });

function _isGranted(code) { return code === 0 || code === 1; }
var PKI_STATUS_NAMES = { 0: "accepted", 1: "grantedWithMods", 2: "rejection", 3: "waiting" };

function _certReqIdEq(a, b) { return a != null && b != null && BigInt(a) === BigInt(b); }

function _asCertList(v) { return v == null ? [] : (Array.isArray(v) ? v.slice() : [v]); }

function _boundedPool(base, added) {
  var ceiling = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES;
  var seen = Object.create(null), distinctBase = [];
  base.forEach(function (c) { var k = _certIdentity(c); if (k == null) { distinctBase.push(c); return; } if (!seen[k]) { seen[k] = 1; distinctBase.push(c); } });
  var room = ceiling - distinctBase.length;
  if (room <= 0) return distinctBase;
  var useful = [];
  added.forEach(function (c) { var k = _certIdentity(c); if (k != null && seen[k]) return; if (k != null) seen[k] = 1; useful.push(c); });
  return distinctBase.concat(useful.slice(0, room));
}
function _certIdentity(cert) {
  try {
    var p = guard.parsed.acceptDerived(cert, "certificate", x509.parse, _err, "cmp/bad-input", "a pool certificate");
    if (!guard.parsed.isCert(p)) return null;
    return p.tbsBytes.toString("base64") + "|" + p.signatureValue.bytes.toString("base64");
  } catch (_e) {
    return null;
  }
}

function _spkiKeyIdentity(spkiDer) {
  var node = asn1.decode(spkiDer);
  var algId = node.children[0];
  var algOid = asn1.read.oid(algId.children[0]);
  var pn = algId.children[1];
  var params;
  if (algOid === OID_RSA_ENCRYPTION) {
    params = (pn == null || _isDerNull(pn)) ? "" : pn.bytes.toString("latin1");
  } else {
    params = pn ? pn.bytes.toString("latin1") : "";
  }
  return algOid + "|" + params + "|" + node.children[1].bytes.toString("latin1");
}
function _isDerNull(pn) { return pn.tagClass === "universal" && pn.tagNumber === 5 && pn.content.length === 0; }

var MAX_EXTRA_CERTS = 32, MAX_EXTRA_SCAN = 256;
var CAPUBS_MAX = 2 * MAX_EXTRA_CERTS;
var SESSION_MAX_INTERMEDIATES = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - CAPUBS_MAX - MAX_EXTRA_CERTS;
var SESSION_MAX_INTERMEDIATES_MAC = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - CAPUBS_MAX;
function _isRecoverableVerify(code) {
  return code === "cmp/signer-cert-not-found" || code === "cmp/protection-failed" ||
    code === "cmp/sender-mismatch" || code === "cmp/untrusted-signer";
}
function _responseExtraCerts(responseBytes) {
  var extra = schemaCmp.parse(responseBytes).extraCerts;
  if (!Array.isArray(extra)) return [];
  var out = [], seen = Object.create(null);
  for (var i = 0; i < extra.length && out.length < MAX_EXTRA_CERTS && i < MAX_EXTRA_SCAN; i++) {
    var c = extra[i];
    if (!Buffer.isBuffer(c)) continue;
    var key = c.toString("base64");
    if (seen[key]) continue;
    seen[key] = true;
    try { x509.parse(c); }
    catch (_e) { continue; }
    out.push(Buffer.from(c));
  }
  return out;
}

function _normalizeCertReqId(cid, dflt) {
  if (typeof cid === "bigint" || typeof cid === "number") return cid;
  if (typeof cid === "string") {
    try { return BigInt(cid); }
    catch (_e) { /* allow:swallow-unverified an invalid certReqId string fails closed at the cmp.build boundary; this best-effort normalize just does not pre-empt that typed error */ return dflt; }
  }
  return dflt;
}

function _pssDigest(paramsBytes) {
  if (!Buffer.isBuffer(paramsBytes) || paramsBytes.length === 0) return null;
  try {
    var node = asn1.decode(paramsBytes);
    if (!node.children) return null;
    for (var i = 0; i < node.children.length; i++) {
      var f = node.children[i];
      if (f.tagClass === "context" && f.tagNumber === 0 && f.children && f.children.length === 1) {
        var algSeq = f.children[0];
        if (!algSeq.children || algSeq.children.length < 1) return null;
        return HASH_OID_TO_DIGEST[asn1.read.oid(algSeq.children[0])] || null;
      }
    }
  } catch (_e) { /* allow:swallow-unverified a malformed PSS-params blob falls back to null -> the caller's declared-SHA-256 path; a display-hash inference never throws */ return null; }
  return null;
}

function _certConfHash(certDer) {
  var sa;
  try { sa = x509.parse(certDer).signatureAlgorithm; }
  catch (e) { throw _err("cmp/bad-cert-response", "the issued certificate is unexpectedly unparseable at certConf", e); }
  if (HASHLESS_SIG_OIDS[sa.oid]) return { digest: "SHA-256", hashAlg: "sha256" };
  var comp = compositeSig.COMPOSITE_ALGS[sa.oid];
  if (comp) {
    var ha = COMPOSITE_PH_HASHALG[comp.ph];
    if (ha) return { digest: comp.ph, hashAlg: ha };
    throw _err("cmp/bad-cert-response", "the issued certificate's composite signature prehash (" + comp.ph + ") is not a certConf-representable hash; the certConf certHash cannot be declared truthfully (RFC 9810 sec. 5.3.18)");
  }
  if (SIG_OID_TO_HASH[sa.oid]) return { digest: SIG_OID_TO_HASH[sa.oid], hashAlg: null };
  if (sa.oid === OID_RSASSA_PSS) {
    var pd = _pssDigest(sa.parameters);
    if (pd) return { digest: pd, hashAlg: null };
    throw _err("cmp/bad-cert-response", "the issued RSASSA-PSS certificate's hash cannot be resolved from its parameters (RFC 4055); the certConf hash is indeterminate");
  }
  throw _err("cmp/bad-cert-response", "the issued certificate's signature algorithm does not determine a certConf hash (an unrecognized or non-signature algorithm); the transaction is refused (RFC 9810 sec. 5.3.18)");
}

/**
 * @primitive  pki.cmp.session
 * @signature  pki.cmp.session(opts) -> session
 * @since      0.3.27
 * @status     stable
 * @spec       RFC 9810, RFC 9811, RFC 9483
 * @related    pki.cmp.build, pki.cmp.verify, pki.cmp.transfer
 *
 * A stateful RFC 9810 CMP enrollment-transaction orchestrator, the `pki.acme.client` analogue. It drives
 * an enrollment (`ir` / `cr` / `kur` / `p10cr`) end to end over the shared `pki.transport` (inject
 * `opts.transport`, else a fail-closed `pki.transport.https`), composing the shipped message layer
 * (`build` / `transfer` / `verify`). It mints a stable 128-bit `transactionID`, and on every request a
 * fresh `senderNonce`, echoing the peer's last `senderNonce` back as `recipNonce` (RFC 9810 sec. 5.1.1
 * anti-replay / anti-interleave). The load-bearing invariant: every response is protection-verified and
 * nonce-bound to this exchange before its body is read, so a meddler who flips an HTTP response cannot
 * forge a granted status or a poison `checkAfter`. A `waiting` status drives a bounded `pollReq`/`pollRep`
 * loop (an injectable sleeper, capped by `maxPolls` + `maxTotalWait`); a grant extracts the issued cert and
 * confirms it (`certConf` -> `pkiConf`, unless an `implicitConfirm` was granted). A verified `rejection` /
 * `error` or a poll-budget timeout is a terminal typed verdict the caller reads (`outcome`:
 * `issued` / `rejected` / `poll-timeout`); a tampered / unverifiable / desynchronized response is a
 * hard-stop `CmpError` throw. Exactly one protection flavor: `{ key, cert }` (signature) XOR `{ mac }`
 * (PBMAC1). A crypto-valid response is not enough: the signer must chain to a supplied trust anchor
 * (signature) or the shared secret must match (MAC); a valid-but-untrusted response is a hard stop, so the
 * signature flavor REQUIRES `opts.trustAnchors` at construction. Returns a session with `enroll(request)`,
 * `revoke(request)`, `info(request)`,
 * and read-only `transactionID` + `transcript` (each leg's request/response bytes, retained up to a
 * transaction-wide cap; a later leg beyond the cap keeps its metadata + `byteLength` but drops the payload as
 * `bytes: null, truncated: true`, so a padded-response flood across polls cannot exhaust memory). The granted certificate must be valid X.509, carry the key
 * the request submitted (else it is a misrouted certificate the caller cannot use), and, for the signature
 * flavor, have its signature + chain validated to a supplied trust anchor before it is confirmed. The `certConf`
 * `certHash` uses the certificate's signature hash: from the OID when it conveys one, or from the
 * RSASSA-PSS parameters when it does not, with `hashAlg` omitted; only a truly hashless signature
 * (Ed25519 / Ed448, ML-DSA / SLH-DSA) computes under SHA-256 and declares an explicit `hashAlg`
 * (RFC 9810 sec. 5.3.18). The `certReqId` echoed in `pollReq` / `certConf` and matched in every
 * `CertResponse` is the caller's CRMF request id (`request.ir.certReqId`, ...) when supplied, else the
 * single-request default. One transaction per session: a second or concurrent `enroll`, or a batched
 * CRMF request, is refused (a local build error leaves the session retryable). The returned `chain` is the
 * issued leaf plus any authenticated `caPubs` the CA delivered (chain material, never trust anchors); a
 * server-generated (central key generation) private key is out of scope and the grant is refused.
 *
 * `revoke(request)` drives the RFC 9483 sec. 4.2 revocation exchange (`rr` -> `rp`) through the same shell.
 * The request names the certificate, either as `{ certificate }` or as `{ certDetails: { issuer,
 * serialNumber } }`, plus an optional `reason` (a CRLReason name). A session revokes ITS OWN certificate:
 * the signature over the request is the proof of authorization to revoke, so the named certificate must be
 * `opts.cert`, and a PBMAC1 session, holding no certificate, is refused. The `crlEntryDetails` reasonCode
 * is always emitted, at `unspecified(0)` when no reason is given, which sec. 4.2 requires and is the
 * opposite of the RFC 5280 sec. 5.3.1 rule for a CRL entry. Terminal `outcome`: `revoked` (the response's
 * single accepted status), `rejected`, or `poll-timeout`.
 *
 * `info(request)` drives the sec. 4.3 support messages (`genm` -> `genp`), one operation per call:
 * `{ caCerts: true }` for the CA certificates available for chain construction; `{ rootCaCert: <cert> }`
 * for a root CA key update, whose response carries a DIFFERENT infoType and must include the `newWithOld`
 * certificate an entity trusting the old root needs; `{ certReqTemplate: true }` for the certificate-request
 * requirements, whose template must omit `publicKey`, `serialNumber`, `signingAlg`, `issuerUID` and
 * `subjectUID`, and whose `keySpec` states key requirements as `algId` (a non-RSA AlgorithmIdentifier) or
 * `rsaKeyLen` (a positive integer); and `{ crlUpdate: { issuer, dpn?, thisUpdate? } }` for a CRL from a
 * named source, held to that source (the issuer under the RFC 5280 sec. 7.1 rule, a distribution point
 * against the CRL's own `issuingDistributionPoint` where it states one) and to the supplied `thisUpdate`.
 * A request naming both sends the dpn (sec. 4.3.4: the dpn choice when a distribution point name is
 * available) and holds the answer to the issuer as well. The issuer is REQUIRED, since a distribution
 * point name alone leaves the answer unbound: a complete CRL states no scope to compare it against.
 * Terminal `outcome`: `answered` (with `operation`, `present`, and the decoded `value`),
 * `rejected`, or `poll-timeout`. An absent response value is `present: false` with a null `value`, which is
 * how each of the four says "nothing available", never conflated with an empty result. Delayed delivery
 * for both verbs arrives as an error message carrying the `waiting` status (sec. 4.4) and drives the same
 * bounded poll loop, with the `pollReq` referring to the whole message.
 *
 * @opts
 *   - `url` -- REQUIRED: the CMP endpoint URL.
 *   - `key` + `cert` -- signature protection (the enrolling key pair + its cert), XOR `mac: { secret, ... }` for PBMAC1 protection.
 *   - `trustAnchors` -- REQUIRED for the signature flavor (chains + authenticates the CA's response signer cert); OPTIONAL for a MAC session, where it validates the issued certificate's own signature + chain before confirmation (not the response protection). `intermediates` supplies an extra chain pool.
 *   - `sender` / `recipient` -- header GeneralNames; default the signer cert's subject DN (sender) and a NULL-DN (recipient). A signature-protection certificate with an empty subject (identified only by its subjectAltName) REQUIRES an explicit `sender`, because the empty subject cannot name the requester for a peer that binds the sender to the SAN.
 *   - `senderKID` / `recipKID` -- optional key identifiers emitted on every request header, so a CA selecting among several shared secrets (senderKID) or recipient keys resolves the right credential.
 *   - `expectedSender` -- optional CA signer certificate (DER Buffer / PEM string / already-parsed `pki.schema.x509.parse` object); when set, every signed response's authenticated header sender MUST bind to it under the RFC 5280 sec. 7 subject-or-subjectAltName rule cmp.verify uses, so a re-encoded-but-equivalent DN and an empty-subject CA named only by a directoryName SAN both match. Given as bytes/PEM it also resolves a first response that omits its own extraCerts (a CA that assumes the client already holds its certificate). Absent, the session pins the first signed response's signer certificate and requires every later leg's sender to bind to it, rejecting a switch to a different trusted signer while permitting same-identity certificate/key rotation.
 *   - `implicitConfirm` -- request implicit confirmation (skip the certConf leg when the CA grants it).
 *   - `acceptCert` -- an async policy `(certDer, { status, grantedWithMods }) => boolean` consulted before the certConf; return true to accept, anything else to veto (a `grantedWithMods` certificate the CA changed). A veto sends a rejecting certConf and yields `outcome: "rejected"` with the certificate still surfaced. Incompatible with `implicitConfirm` (no reject leg exists), so the combination throws at construction.
 *   - `transport` -- injectable `transport(request) -> Promise<{status, headers, body}>`; default pki.transport.https. It must return a promise of the response; anything else is `cmp/bad-input`.
 *   - `tls` / `headers` / `timeout` / `maxResponseBytes` -- transport config + budgets.
 *   - `proxy` -- reach the CA through a forward HTTP proxy (`{ url, auth?, tls? }`; see pki.transport).
 *   - `maxPolls` / `maxTotalWait` / `sleep` -- poll-loop budgets + an injectable sleeper; `time` -- verify-time clock.
 *   - `extraCerts` / `pss` / `digestAlgorithm` -- passed through to the request protection build.
 * @example
 *   var session = pki.cmp.session({ url: "https://ca.example/cmp", key: signerKeyPkcs8, cert: signerCertDer, trustAnchors: [cmpCaCert], transport: cmpTransport });
 *   var result = await session.enroll({ ir: { certTemplate: { subject: [{ commonName: "device-42" }], publicKey: signerSpki } } });
 *   if (result.outcome === "issued") { var leaf = result.certificate; }
 *
 *   var revoking = pki.cmp.session({ url: "https://ca.example/cmp", key: signerKeyPkcs8, cert: signerCertDer, trustAnchors: [cmpCaCert], transport: cmpTransport });
 *   var gone = await revoking.revoke({ certificate: signerCertDer, reason: "keyCompromise" });
 *   if (gone.outcome === "revoked") { var when = gone.status; }
 *
 *   var asking = pki.cmp.session({ url: "https://ca.example/cmp", key: signerKeyPkcs8, cert: signerCertDer, trustAnchors: [cmpCaCert], transport: cmpTransport });
 *   var answer = await asking.info({ caCerts: true });
 *   if (answer.outcome === "answered" && answer.present) { var caCerts = answer.value; }
 */
function session(opts) {
  if (opts == null) opts = {};
  guard.identifier.assertPlainRecord(opts, _err, "cmp/bad-input", "opts");
  guard.identifier.optionsObject(opts, _err, "cmp/bad-input", "opts");
  guard.identifier.assertKnownKeys(opts, KNOWN_SESSION_OPTS, _err, "cmp/bad-input", "unknown session opts field ");
  opts = Object.assign({}, opts);
  if (typeof opts.url !== "string" || !opts.url) throw _err("cmp/bad-input", "opts.url (the CMP endpoint) is required");

  var isSig = opts.key != null || opts.cert != null;
  var isMac = opts.mac != null;
  if (isSig === isMac) throw _err("cmp/bad-input", "supply EXACTLY ONE protection flavor: { key, cert } (signature) OR { mac } (PBMAC1)");
  if (isSig && (opts.key == null || opts.cert == null)) throw _err("cmp/bad-input", "signature protection requires BOTH opts.key and opts.cert");
  if (isSig) {
    var hasAnchors = opts.trustAnchors != null && !(Array.isArray(opts.trustAnchors) && opts.trustAnchors.length === 0);
    if (!hasAnchors) throw _err("cmp/bad-input", "signature protection requires opts.trustAnchors to authenticate the CA's response signer (RFC 9483 sec. 3.2)");
  }
  if (isMac && Array.isArray(opts.trustAnchors) && opts.trustAnchors.length === 0) opts.trustAnchors = null;
  if (opts.trustAnchors != null && _engine && _engine.toAnchor) _asCertList(opts.trustAnchors).forEach(function (a) { try { _engine.toAnchor(a); } catch (e) { throw _err("cmp/bad-input", "opts.trustAnchors: each entry must be a certificate (DER/PEM/parsed) or a { name, publicKey, algorithm } anchor tuple -- " + ((e && e.message) || e), e); } });
  if (opts.intermediates != null && _engine && _engine.coerceCert) _asCertList(opts.intermediates).forEach(function (c) { try { _engine.coerceCert(c); } catch (e) { throw _err("cmp/bad-input", "opts.intermediates: each entry must be a certificate (DER/PEM/parsed) -- " + ((e && e.message) || e), e); } });
  var _proxySnap = httpTransport.snapshotProxy(opts.proxy);
  var _expectedSenderCert = null;
  var _expectedSenderDer = null;
  if (opts.expectedSender != null) {
    var _es = opts.expectedSender;
    try {
      if (_es && Buffer.isBuffer(_es.tbsBytes)) {
        _expectedSenderCert = (_engine && _engine.coerceCert) ? _engine.coerceCert(_es) : _es;
      }
      else if (guard.bytes.isByteSource(_es)) { _expectedSenderDer = guard.bytes.snapshotSource(_es, CmpError, "cmp/bad-input", "opts.expectedSender"); _expectedSenderCert = x509.parse(_expectedSenderDer); }
      else if (typeof _es === "string") { _expectedSenderDer = x509.pemDecode(_es); _expectedSenderCert = x509.parse(_expectedSenderDer); }
      else { throw _err("cmp/bad-input", "opts.expectedSender must be a certificate DER BufferSource / PEM string / parsed certificate"); }
    } catch (e) {
      if (e.isCmpError) throw e;
      throw _err("cmp/bad-input", "opts.expectedSender must be the CA signer certificate (DER BufferSource / PEM / parsed) so every signed response can be bound to it -- " + ((e && e.message) || e), e);
    }
  }
  var maxIntermediates = isSig ? SESSION_MAX_INTERMEDIATES : SESSION_MAX_INTERMEDIATES_MAC;
  if (opts.intermediates != null) {
    var seenInt = Object.create(null), distinctInt = 0;
    _asCertList(opts.intermediates).forEach(function (c) { var k = _certIdentity(c); if (k == null) { distinctInt++; return; } if (!seenInt[k]) { seenInt[k] = 1; distinctInt++; } });
    if (distinctInt > maxIntermediates) throw _err("cmp/bad-input", "opts.intermediates has " + distinctInt + " distinct certificates, exceeding the " + maxIntermediates + " limit (room is reserved below the path-builder ceiling for the CA's own delivered issuer certificates" + (isSig ? " and signer chain" : "") + ")");
  }

  if (opts.acceptCert != null && typeof opts.acceptCert !== "function") throw _err("cmp/bad-input", "opts.acceptCert must be a function (certDer, info) => boolean");
  if (opts.implicitConfirm != null && typeof opts.implicitConfirm !== "boolean") throw _err("cmp/bad-input", "opts.implicitConfirm must be a boolean");
  if (opts.sleep != null && typeof opts.sleep !== "function") throw _err("cmp/bad-input", "opts.sleep must be a function (delayMs) => Promise");
  if (opts.transport != null && typeof opts.transport !== "function") throw _err("cmp/bad-input", "opts.transport must be a function (url, reqDer, opts) => Promise<{ responseBytes, status }>");
  if (opts.acceptCert != null && opts.implicitConfirm) throw _err("cmp/bad-input", "opts.acceptCert cannot be combined with opts.implicitConfirm -- implicit confirmation leaves no certConf leg to reject on (drop implicitConfirm to vet a grant)");

  if (opts.time != null) guard.time.assertValid(opts.time, _err, "cmp/bad-input", "opts.time (the verify/validation clock)");
  var maxPolls = guard.limits.cap(opts.maxPolls, "opts.maxPolls", DEFAULT_MAX_POLLS, { E: _err, code: "cmp/bad-input", min: 1, max: 1000 });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "opts.maxTotalWait", DEFAULT_MAX_TOTAL_WAIT, { E: _err, code: "cmp/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = opts.sleep || sleepUtil.sleep;

  var transactionID = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(16)));
  var lastPeerNonce = null;
  var haveResponse = false;
  var cachedSignerCert = null;
  var pinnedSignerCert = null, signerPinned = false;
  var cachedChain = [];
  var caPubsAccum = [];
  var caPubsSeen = Object.create(null);
  var caPubsBytes = 0;
  var caPubsWaitingCount = 0;
  var activeCertReqId = DEFAULT_CERT_REQ_ID;
  var expectedRespArm = "ip";
  var txnKind = "enroll";
  var expectedInfoOp = null;
  var crlQuery = null;
  var requestedSpki = null;
  var inFlight = false, completed = false, started = false;
  var transcript = [];
  var transcriptBytes = 0;
  var _perRespCap = (typeof opts.maxResponseBytes === "number" && isFinite(opts.maxResponseBytes) && opts.maxResponseBytes > 0) ? opts.maxResponseBytes : constants.LIMITS.HTTP_MAX_RESPONSE_BYTES;
  var transcriptCap = _perRespCap * TRANSCRIPT_RETAIN_RESPONSES;
  var caPubsByteBudget = _perRespCap * TRANSCRIPT_RETAIN_RESPONSES;

  var NULL_DN = { directoryName: [] };
  var defaultSender = NULL_DN;
  if (isSig) {
    try {
      var _signerSubject = x509.parse(opts.cert).subject;
      if (_signerSubject.rdns && _signerSubject.rdns.length > 0) defaultSender = { directoryName: _signerSubject.bytes };
      else if (opts.sender == null) throw _err("cmp/bad-input", "the signature-protection certificate has an empty subject, so it cannot name the request sender -- an empty-subject certificate is identified by its subjectAltName; set opts.sender explicitly (e.g. a subjectAltName identity the CA will bind the sender to)");
    } catch (e) {
      if (e && e.isCmpError) throw e;
      defaultSender = NULL_DN;
    }
  }

  function _baseHeader(fresh) {
    var h = { transactionID: transactionID, senderNonce: fresh };
    if (haveResponse) {
      if (!Buffer.isBuffer(lastPeerNonce) || lastPeerNonce.length === 0) throw _err("cmp/bad-nonce", "the previous CMP response omitted its senderNonce, so this follow-up request cannot echo it as recipNonce (RFC 9810 sec. 5.1.1)");
      h.recipNonce = lastPeerNonce;
    }
    h.sender = opts.sender != null ? opts.sender : defaultSender;
    h.recipient = opts.recipient != null ? opts.recipient : NULL_DN;
    if (opts.senderKID != null) h.senderKID = opts.senderKID;
    if (opts.recipKID != null) h.recipKID = opts.recipKID;
    return h;
  }
  function _buildOpts() {
    var o = isSig ? { key: opts.key, cert: opts.cert } : { mac: opts.mac };
    if (opts.extraCerts != null) o.extraCerts = opts.extraCerts;
    if (opts.pss != null) o.pss = opts.pss;
    if (opts.digestAlgorithm != null) o.digestAlgorithm = opts.digestAlgorithm;
    return o;
  }
  function _verifyOpts(fresh, signerCertOverride, extraIntermediates, responseExtra) {
    var o = { transactionID: transactionID, expectRecipNonce: fresh };
    if (isMac) o.sharedSecret = opts.mac.secret;
    else if (opts.trustAnchors != null) o.trustAnchors = opts.trustAnchors;
    var issuers = Array.isArray(responseExtra) ? responseExtra : [];
    var extra = [];
    if (Array.isArray(extraIntermediates)) {
      extra = signerCertOverride == null ? extraIntermediates : extraIntermediates.filter(function (c) {
        return !(Buffer.isBuffer(c) && Buffer.isBuffer(signerCertOverride) && c.equals(signerCertOverride));
      });
    }
    var ints = _boundedPool(issuers.concat(extra), _asCertList(opts.intermediates));
    if (ints.length) o.intermediates = ints;
    if (opts.time != null) o.time = opts.time;
    if (signerCertOverride != null) o.signerCert = signerCertOverride;
    return o;
  }
  function _transferOpts() {
    var o = {};
    ["transport", "tls", "headers", "timeout", "maxResponseBytes"].forEach(function (k) { if (opts[k] != null) o[k] = opts[k]; });
    if (_proxySnap != null) o.proxy = _proxySnap;
    return o;
  }

  async function _send(bodySpec, arm) {
    var fresh = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(16)));
    var header = Object.assign(_baseHeader(fresh), ENROLL_ARMS[arm] && opts.implicitConfirm ? { generalInfo: [{ infoType: "implicitConfirm" }] } : {});
    var reqDer = await cmp.build({ header: header, body: bodySpec }, _buildOpts());
    _recordTranscript({ direction: "out", arm: arm, bytes: reqDer });
    var engaged = false;
    var topts = _transferOpts();
    if (opts.transport != null) topts.transport = function (a) { engaged = true; return opts.transport(a); };
    var res;
    try {
      res = await cmp.transfer(opts.url, reqDer, topts);
    } catch (e) {
      var reached = opts.transport != null
        ? engaged
        : !(e && (e.code === "cmp/bad-url" || e.code === "cmp/no-trust-anchors" || e.code === "cmp/bad-input"));
      if (reached) started = true;
      throw e;
    }
    started = true;
    var responseExtra = _responseExtraCerts(res.responseBytes);
    var verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh, null, cachedChain, responseExtra));
    var usedCachedFallback = false;
    var fallbackSigner = cachedSignerCert != null ? cachedSignerCert : _expectedSenderDer;
    var recoverable = _isRecoverableVerify(verdict.code);
    if ((verdict.valid !== true || verdict.trusted !== true) && isSig && fallbackSigner != null && recoverable) {
      usedCachedFallback = cachedSignerCert != null;
      verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh, fallbackSigner, cachedChain, responseExtra));
    }
    _recordTranscript({ direction: "in", arm: verdict.body ? verdict.body.arm : null, status: res.status, bytes: res.responseBytes, verdict: { valid: verdict.valid, trusted: verdict.trusted, code: verdict.code || null } });
    if (verdict.valid !== true) throw _err(verdict.code || "cmp/protection-failed", "the CMP response protection did not verify (" + (verdict.reason || "invalid") + ") -- the transaction is NOT advanced", null);
    if (verdict.trusted !== true) throw _err(verdict.code || "cmp/untrusted-signer", "the CMP response protection verified but its signer is not trusted (it did not chain to a supplied trust anchor) -- the transaction is NOT advanced", null);
    if (isSig && verdict.signer && verdict.header && verdict.header.sender) {
      if (_expectedSenderCert && !cmp.senderBoundToCert(verdict.header.sender, _expectedSenderCert)) {
        throw _err("cmp/untrusted-signer", "the response signer does not match the expected CA identity (opts.expectedSender) -- refusing a response from a different trusted signer", null);
      }
      if (!signerPinned) { pinnedSignerCert = x509.parse(verdict.signer.cert); signerPinned = true; }
      else if (!cmp.senderBoundToCert(verdict.header.sender, pinnedSignerCert)) {
        throw _err("cmp/untrusted-signer", "the response signer identity changed mid-transaction -- a different trusted signer, not a same-identity certificate rotation; the transaction is NOT advanced", null);
      }
    }
    lastPeerNonce = verdict.senderNonce;
    haveResponse = true;
    if (isSig && !usedCachedFallback && verdict.signer && Buffer.isBuffer(verdict.signer.cert)) {
      var extras = _responseExtraCerts(res.responseBytes);
      if (extras.length) {
        cachedSignerCert = Buffer.from(verdict.signer.cert);
        cachedChain = (Array.isArray(verdict.signer.chain) && verdict.signer.chain.length) ? verdict.signer.chain : extras;
      }
    }
    return verdict;
  }

  function _classify(verdict) {
    var body = verdict.body || {};
    var arm = body.arm;
    if (arm === expectedRespArm && txnKind === "revoke") return _classifyRevRep(body);
    if (arm === expectedRespArm && txnKind === "info") return _classifyGenRep(body);
    if (arm === expectedRespArm) {
      var responses = (body.decoded && body.decoded.response) || [];
      var resp = null;
      for (var ri = 0; ri < responses.length; ri++) { if (_certReqIdEq(responses[ri].certReqId, activeCertReqId)) { resp = responses[ri]; break; } }
      if (!resp) return { state: "unexpected", reason: "a " + arm + " carried no CertResponse for certReqId " + activeCertReqId };
      var code = resp.status && resp.status.status ? resp.status.status.code : null;
      var isGrantLeg = _isGranted(code);
      if (code === 3 && resp.status && resp.status.failInfo != null) {
        return { state: "unexpected", reason: "a waiting " + arm + " CertResponse must not carry failInfo (RFC 9483 sec. 4.4)" };
      }
      if (body.decoded && Array.isArray(body.decoded.caPubs)) body.decoded.caPubs.forEach(function (c) {
        if (!Buffer.isBuffer(c)) return;
        var k = c.toString("base64");
        if (caPubsSeen[k]) {
          if (isGrantLeg) { for (var pi = 0; pi < caPubsAccum.length; pi++) { if (caPubsAccum[pi].toString("base64") === k) { caPubsAccum.push(caPubsAccum.splice(pi, 1)[0]); if (pi < caPubsWaitingCount) caPubsWaitingCount--; break; } } }
          return;
        }
        try { x509.parse(c); } catch (e) { throw _err("cmp/bad-cert-response", "an authenticated caPubs entry is not a valid X.509 certificate", e); }
        if (isGrantLeg) {
          while (caPubsWaitingCount > 0 && (caPubsAccum.length >= CAPUBS_MAX || caPubsBytes + c.length > caPubsByteBudget)) {
            var evicted = caPubsAccum.shift();
            caPubsBytes -= evicted.length;
            caPubsWaitingCount--;
            delete caPubsSeen[evicted.toString("base64")];
          }
        }
        if (caPubsAccum.length >= CAPUBS_MAX || caPubsBytes + c.length > caPubsByteBudget) return;
        caPubsSeen[k] = 1;
        caPubsBytes += c.length;
        caPubsAccum.push(Buffer.from(c));
        if (!isGrantLeg) caPubsWaitingCount++;
      });
      if (isGrantLeg) return { state: "granted", resp: resp, code: code };
      if (code === 3) return { state: "waiting", resp: resp };
      if (code === 2) return { state: "rejected", resp: resp };
      return { state: "unexpected", reason: "a " + arm + " CertResponse status code " + code + " has no transition" };
    }
    if (arm === "error") return _classifyError(body);
    if (arm === "pollRep") return { state: "pollRep", entries: body.decoded };
    if (arm === "pkiconf") return { state: "pkiconf" };
    return { state: "unexpected", reason: "response arm " + JSON.stringify(arm) + " has no transition in a " + txnKind + " transaction" };
  }

  function _classifyError(body) {
    var si = body.decoded && body.decoded.pKIStatusInfo;
    var code = si && si.status ? si.status.code : null;
    if (code === 3) {
      if (txnKind === "enroll") throw _err("cmp/bad-error", "an error message answering an enrollment must not carry status waiting -- the profile places enrollment waiting in an ip/cp/kup (RFC 9483 sec. 4.4)");
      if (si.failInfo != null) throw _err("cmp/bad-error", "an error message with status waiting must not carry failInfo (RFC 9483 sec. 4.4)");
      return { state: "waiting", resp: { status: si } };
    }
    if (code !== 2) throw _err("cmp/bad-error", "an error message carries status rejection(2), or waiting(3) for a revoke/info delayed delivery (RFC 9483 sec. 4.2); got " + (code == null ? "no status" : code));
    return { state: "rejected", status: si };
  }

  function _classifyRevRep(body) {
    var d = body.decoded || {};
    var list = d.status || [];
    if (list.length !== 1) {
      return { state: "unexpected", reason: "an rp answering a revocation must carry exactly one status (RFC 9483 sec. 4.2); got " + list.length };
    }
    var si = list[0];
    var code = si && si.status ? si.status.code : null;
    if (code === 0) {
      if (si.failInfo != null) {
        return { state: "unexpected", reason: "an accepted rp must not carry failInfo (RFC 9483 sec. 4.2)" };
      }
      return { state: "granted", status: si, revCerts: d.revCerts, crls: d.crls };
    }
    if (code === 2) return { state: "rejected", status: si };
    return { state: "unexpected", reason: "an rp status code " + code + " has no transition in a revocation (RFC 9483 sec. 4.2 allows accepted or rejection)" };
  }

  function _classifyGenRep(body) {
    var items = body.decoded || [];
    if (items.length !== 1) {
      return { state: "unexpected", reason: "a genp must carry exactly one InfoTypeAndValue (RFC 9483 sec. 4.3); got " + items.length };
    }
    var itav = items[0];
    var want = oid.byName(expectedInfoOp.responseOid);
    if (itav.type !== want) {
      return { state: "unexpected", reason: "a genp answering " + expectedInfoOp.name + " must carry infoType " + expectedInfoOp.responseOid + " (" + want + "); got " + itav.type };
    }
    return { state: "granted", itav: itav };
  }

  function _statusOf(resp) { return resp && resp.status ? resp.status : null; }

  function _implicitConfirmGranted(header) {
    var gi = header && header.generalInfo;
    if (!Array.isArray(gi)) return false;
    for (var i = 0; i < gi.length; i++) { if (gi[i] && gi[i].type === OID_IMPLICIT_CONFIRM) return true; }
    return false;
  }

  function _recordTranscript(entry) {
    var len = Buffer.isBuffer(entry.bytes) ? entry.bytes.length : 0;
    var over = transcriptBytes + len > transcriptCap;
    if (!over) transcriptBytes += len;
    transcript.push(over
      ? guard.verdict.of(entry, { byteLength: len, bytes: null, truncated: true })
      : guard.verdict.of(entry));
  }

  function _transcriptSnapshot() {
    return transcript.map(function (e) {
      var c = guard.verdict.of(e);
      if (Buffer.isBuffer(c.bytes)) c.bytes = Buffer.from(c.bytes);
      if (guard.verdict.carries(c, "verdict") && c.verdict) c.verdict = guard.verdict.of(c.verdict);
      return c;
    });
  }
  function _terminal(outcome, extra) {
    return guard.verdict.of({
      outcome: outcome, certificate: null, chain: [], status: null, trusted: true,
      confirmed: false, implicitConfirm: false, transactionID: Buffer.from(transactionID),
      polls: 0, transcript: _transcriptSnapshot(),
    }, extra);
  }

  async function _pollLoop(lastWaitingResp) {
    var polls = 0, waited = 0, lastStatus = _statusOf(lastWaitingResp);
    for (;;) {
      if (polls >= maxPolls || waited > maxTotalWait) return { timeout: true, polls: polls, status: lastStatus };
      var verdict = await _send({ pollReq: [{ certReqId: activeCertReqId }] }, "pollReq");
      polls += 1;
      var t = _classify(verdict);
      if (t.state === "pollRep") {
        var entries = t.entries || [];
        var entry = null;
        for (var pe = 0; pe < entries.length; pe++) { if (_certReqIdEq(entries[pe].certReqId, activeCertReqId)) { entry = entries[pe]; break; } }
        if (!entry) return { done: { state: "unexpected", reason: "a pollRep carried no entry for certReqId " + activeCertReqId }, polls: polls, header: verdict.header };
        var checkAfter = typeof entry.checkAfter === "number" ? entry.checkAfter : 0;
        waited += checkAfter;
        if (waited > maxTotalWait) return { timeout: true, polls: polls, status: lastStatus };
        if (polls >= maxPolls) return { timeout: true, polls: polls, status: lastStatus };
        await sleep(checkAfter * constants.TIME.seconds(1));
        continue;
      }
      if (t.state === "waiting") { lastStatus = _statusOf(t.resp); continue; }
      return { done: t, polls: polls, header: verdict.header };
    }
  }

  async function _confirm(certDer, header, info) {
    if (opts.implicitConfirm && _implicitConfirmGranted(header)) return { confirmed: true, implicit: true };
    var accept = true;
    if (typeof opts.acceptCert === "function") accept = (await opts.acceptCert(Buffer.from(certDer), info)) === true;
    var h = _certConfHash(certDer);
    var certHash = Buffer.from(await webcrypto.webcrypto.subtle.digest(h.digest, certDer));
    var cs = { certHash: certHash, certReqId: activeCertReqId };
    if (!accept) cs.statusInfo = { status: 2, statusString: ["the enrolling client rejected the issued certificate"] };
    if (h.hashAlg) cs.hashAlg = h.hashAlg;
    var verdict = await _send({ certConf: [cs] }, "certConf");
    if (!verdict.body || verdict.body.arm !== "pkiconf") throw _err("cmp/bad-confirmation", "expected a pkiConf acknowledgement to the certConf but got " + JSON.stringify(verdict.body && verdict.body.arm) + " (RFC 9810 sec. 5.3.18)");
    return { confirmed: accept, implicit: false, rejected: !accept };
  }

  function _leafOf(resp) {
    var ckp = resp && resp.certifiedKeyPair;
    var cert = ckp && ckp.certificate;
    if (!Buffer.isBuffer(cert)) throw _err("cmp/unexpected-arm", "a granted CertResponse carried no plain issued certificate (an encryptedCert form is out of enrollment v1 scope) (RFC 9810 sec. 5.3.4)");
    if (ckp.privateKey != null) throw _err("cmp/unexpected-arm", "a granted CertResponse carried a server-generated privateKey (central key generation is out of enrollment v1 scope; a session enrolls a client-generated key) (RFC 9810 sec. 5.3.4)");
    var parsed;
    try { parsed = x509.parse(cert); }
    catch (e) { throw _err("cmp/bad-cert-response", "the granted CertResponse's certificate is not a valid X.509 certificate", e); }
    if (requestedSpki != null && _spkiKeyIdentity(parsed.subjectPublicKeyInfo.bytes) !== _spkiKeyIdentity(requestedSpki)) {
      throw _err("cmp/bad-cert-response", "the issued certificate's public key does not match the requested key -- a misrouted certificate the caller has no private key for");
    }
    return cert;
  }

  function _extractRequestedSpki(arm, armSpec) {
    if (arm === "p10cr") {
      if (!guard.bytes.isByteSource(armSpec)) return null;
      try { return csr.parse(armSpec).subjectPublicKeyInfo.bytes; }
      catch (_e) { /* allow:swallow-unverified an unparseable p10cr CSR fails closed at the cmp.build boundary; the key-match is simply not applied to a request that never sends */ return null; }
    }
    var pk = armSpec && armSpec.certTemplate ? armSpec.certTemplate.publicKey : null;
    if (guard.bytes.isByteSource(pk)) return guard.bytes.snapshotSource(pk, CmpError, "cmp/bad-input", "the certTemplate publicKey");
    return null;
  }

  async function _validateLeaf(leaf, caPubs) {
    if (_engine == null || opts.trustAnchors == null) return;
    var caPubsList = [];
    if (Array.isArray(caPubs)) caPubs.forEach(function (c) { if (Buffer.isBuffer(c)) caPubsList.push(c); });
    var added = _asCertList(opts.intermediates);
    if (Buffer.isBuffer(cachedSignerCert)) added.push(cachedSignerCert);
    cachedChain.forEach(function (c) { if (Buffer.isBuffer(c)) added.push(c); });
    var pool = _boundedPool(caPubsList, added);
    var res;
    try { res = await _engine.build(leaf, { trustAnchors: _asCertList(opts.trustAnchors), intermediates: pool, validate: true, time: opts.time != null ? opts.time : new Date() }); }
    catch (e) {
      if (e.code === "path/bad-input") throw _err("cmp/bad-input", "invalid trust / validation options for issued-certificate validation: " + (e.message || e), e);
      throw _err("cmp/bad-cert-response", "the issued certificate could not be validated to a supplied trust anchor: " + (e.message || e), e);
    }
    if (!res || res.valid !== true) throw _err("cmp/bad-cert-response", "the issued certificate did not validate to a supplied trust anchor (its signature or chain is invalid) (RFC 5280 sec. 6.1)");
  }

  async function _finish(granted, header) {
    var leaf = _leafOf(granted.resp);
    var chain = [leaf], seenChain = Object.create(null);
    caPubsAccum.forEach(function (c) {
      if (!Buffer.isBuffer(c)) return;
      try { x509.parse(c); }
      catch (e) { throw _err("cmp/bad-cert-response", "a caPubs certificate in the granting response is not a valid X.509 certificate", e); }
      var k = _certIdentity(c);
      if (k != null && seenChain[k]) return;
      if (k != null) seenChain[k] = 1;
      chain.push(c);
    });
    await _validateLeaf(leaf, caPubsAccum);
    var info = { status: PKI_STATUS_NAMES[granted.code] || granted.code, grantedWithMods: granted.code === 1 };
    var conf = await _confirm(leaf, header, info);
    var certOut = Buffer.from(leaf), chainOut = chain.map(function (c) { return Buffer.from(c); });
    if (conf.rejected) {
      return _terminal("rejected", { certificate: certOut, chain: chainOut, status: _statusOf(granted.resp), polls: granted.polls || 0 });
    }
    return _terminal("issued", {
      certificate: certOut, chain: chainOut, status: _statusOf(granted.resp),
      confirmed: conf.confirmed, implicitConfirm: conf.implicit, polls: granted.polls || 0,
    });
  }

  function _assertFresh(what) {
    if (completed || inFlight) {
      throw _err("cmp/bad-input", "this pki.cmp.session transaction is already " + (completed ? "completed" : "in flight") + "; create a new session per " + what + " (RFC 9810 sec. 5.1.1: one transactionID per transaction)");
    }
  }

  async function _runOneShot(bodySpec, arm, kind) {
    txnKind = kind;
    expectedRespArm = RESPONSE_ARM[arm];
    activeCertReqId = WHOLE_MESSAGE_CERT_REQ_ID;
    var verdict = await _send(bodySpec, arm);
    var t = _classify(verdict);
    var polls = 0;
    if (t.state === "waiting") {
      var polled = await _pollLoop(t.resp);
      polls = polled.polls;
      if (polled.timeout) return { timeout: true, polls: polls, status: polled.status };
      t = polled.done;
    }
    return { done: t, polls: polls };
  }

  async function enroll(request) {
    _assertFresh("enrollment");
    guard.identifier.assertPlainRecord(request, _err, "cmp/bad-input", "enroll(request), a body spec { ir | cr | kur | p10cr },");
    var arms = Object.keys(request).filter(function (k) { return request[k] != null; });
    if (arms.length !== 1 || !ENROLL_ARMS[arms[0]]) {
      throw _err("cmp/bad-input", "enroll(request) must carry EXACTLY ONE enrollment arm (ir / cr / kur / p10cr)");
    }
    var armSpec = request[arms[0]];
    if (armSpec && typeof armSpec === "object" && !Buffer.isBuffer(armSpec) && armSpec.messages != null) {
      throw _err("cmp/bad-input", "a batched CRMF request ({ messages: [...] }) is not supported by a session -- submit one certificate request per pki.cmp.session");
    }
    var reqSpki = _extractRequestedSpki(arms[0], armSpec);
    if (arms[0] !== "p10cr" && reqSpki == null) {
      throw _err("cmp/bad-input", "an ir / cr / kur enrollment must submit certTemplate.publicKey -- a session enrolls a client-generated key (a raVerified keyless request or central key generation is not supported)");
    }
    if (arms[0] !== "p10cr" && armSpec != null && armSpec.pop != null && armSpec.pop.type != null && armSpec.pop.type !== "signature") {
      throw _err("cmp/bad-input", "a session ir / cr / kur proves possession by signing the CRMF proof of possession; a non-signature POP mode (" + guard.text.showValue(armSpec.pop.type) + ") is not supported (RFC 4211 sec. 4)");
    }
    if (isMac && arms[0] !== "p10cr" && (armSpec == null || armSpec.key == null)) {
      throw _err("cmp/bad-input", "a MAC-protected ir / cr / kur must carry the requested key's private half as `key` for the CRMF proof of possession -- a signature session reuses opts.key, but a PBMAC1 session has no signing key, so the request would carry no proof of possession (RFC 4211 sec. 4)");
    }
    inFlight = true;
    try {
      txnKind = "enroll";
      expectedRespArm = RESPONSE_ARM[arms[0]];
      var cid = (typeof armSpec === "object" && !Buffer.isBuffer(armSpec)) ? armSpec.certReqId : undefined;
      activeCertReqId = _normalizeCertReqId(cid, arms[0] === "p10cr" ? P10CR_CERT_REQ_ID : DEFAULT_CERT_REQ_ID);
      requestedSpki = reqSpki;
      var initial = await _send(request, arms[0]);
      var t = _classify(initial);
      var grantHeader = initial.header;
      var pollCount = 0;
      if (t.state === "waiting") {
        var polled = await _pollLoop(t.resp);
        pollCount = polled.polls;
        if (polled.timeout) return _terminal("poll-timeout", { status: polled.status, polls: pollCount });
        t = polled.done;
        grantHeader = polled.header;
        t.polls = pollCount;
      }
      if (t.state === "granted") { var r = await _finish({ resp: t.resp, polls: pollCount, code: t.code }, grantHeader); r.polls = pollCount; return r; }
      if (t.state === "rejected") return _terminal("rejected", { status: t.status || _statusOf(t.resp), polls: pollCount });
      throw _err("cmp/unexpected-arm", t.reason || "the enrollment transaction reached an unexpected state");
    } finally {
      inFlight = false;
      completed = started;
    }
  }

  function _assertRevokingOwnCertificate(certTemplateDer) {
    var own;
    try {
      own = guard.parsed.acceptDerived(opts.cert, "certificate", x509.parse, _err, "cmp/bad-input", "opts.cert");
    } catch (e) {
      if (e && e.isCmpError) throw e;
      throw _err("cmp/bad-input", "opts.cert must be a certificate to revoke one (RFC 9483 sec. 4.2)", e);
    }
    var tmpl = schemaCrmf.walkCertTemplate(asn1.decode(certTemplateDer));
    var sameSerial = tmpl.serialNumber != null && own.serialNumber != null && BigInt(tmpl.serialNumber) === BigInt(own.serialNumber);
    var sameIssuer = tmpl.issuer != null && guard.name.dnEqual(tmpl.issuer.rdns, own.issuer.rdns, _err, "cmp/bad-input", "the revoked certificate issuer");
    if (!sameSerial || !sameIssuer) {
      throw _err("cmp/bad-input", "a session revokes ITS OWN certificate: the issuer and serialNumber in certDetails must name opts.cert, because the signature over the request is the proof of authorization to revoke (RFC 9483 sec. 4.2). Revocation on behalf of another entity is an RA operation -- drive it with pki.cmp.build + pki.cmp.transfer.");
    }
    return own;
  }

  function _bindRevCerts(revCerts, own) {
    if (revCerts == null) return null;
    if (revCerts.length !== 1) {
      throw _err("cmp/bad-rev-rep", "an rp for a single revocation must name exactly one certificate in revCerts (RFC 9483 sec. 4.2); got " + revCerts.length);
    }
    var cid = revCerts[0];
    var dn = cid.issuer && cid.issuer.tagClass === "context" && cid.issuer.tagNumber === 4 ? cid.issuer.value : null;
    var sameSerial = cid.serialNumber != null && own.serialNumber != null && BigInt(cid.serialNumber) === BigInt(own.serialNumber);
    var sameIssuer = dn != null && guard.name.dnEqual(dn.rdns, own.issuer.rdns, _err, "cmp/bad-rev-rep", "the revCerts issuer");
    if (!sameSerial || !sameIssuer) {
      throw _err("cmp/bad-rev-rep", "the rp revCerts names a certificate other than the one this session revoked (RFC 9483 sec. 4.2), so a verified verdict must not report it as revoked");
    }
    return revCerts;
  }

  
  async function revoke(request) {
    _assertFresh("revocation");
    guard.identifier.assertPlainRecord(request, _err, "cmp/bad-input", "revoke(request), an object { certificate | certDetails, reason? },");
    guard.identifier.assertKnownKeys(request, KNOWN_REVOKE_KEYS, _err, "cmp/bad-input", "unknown revoke request field ");
    if (isMac) throw _err("cmp/bad-input", "a PBMAC1 session cannot revoke: the request must be signature-protected with the certificate being revoked (RFC 9483 sec. 4.2). Use a signature session ({ key, cert }).");
    var certificateArg = request.certificate, reasonArg = request.reason;
    var certDetails = request.certDetails;
    if ((certificateArg == null) === (certDetails == null)) {
      throw _err("cmp/bad-input", "revoke(request) names the certificate by EXACTLY ONE of certificate (the certificate itself) or certDetails ({ issuer, serialNumber })");
    }
    if (reasonArg != null && (typeof reasonArg !== "string" || !CRL_REASON_NAMES[reasonArg])) {
      throw _err("cmp/bad-input", "revoke request.reason must be a CRLReason name (RFC 5280 sec. 5.3.1); got " + guard.text.showValue(reasonArg));
    }
    if (certificateArg != null) {
      var target;
      try {
        target = guard.parsed.acceptDerived(certificateArg, "certificate", x509.parse, _err, "cmp/bad-input", "revoke request.certificate");
      } catch (e) {
        if (e && e.isCmpError) throw e;
        throw _err("cmp/bad-input", "revoke request.certificate must be a certificate (DER / PEM / parsed)", e);
      }
      certDetails = { issuer: target.issuer.bytes, serialNumber: target.serialNumber };
    }
    var certTemplateDer;
    try {
      certTemplateDer = crmfSign.buildCertTemplate(certDetails);
    } catch (e) {
      if (e && e.isCmpError) throw e;
      throw _err("cmp/bad-rev-req", "revoke request.certDetails must be a CertTemplate naming issuer and serialNumber -- " + ((e && e.message) || e), e);
    }
    var own = _assertRevokingOwnCertificate(certTemplateDer);
    var body = { rr: [{ certDetails: certTemplateDer, crlEntryDetails: { reason: reasonArg == null ? undefined : reasonArg } }] };
    inFlight = true;
    try {
      var out = await _runOneShot(body, "rr", "revoke");
      if (out.timeout) return _terminal("poll-timeout", { status: out.status, polls: out.polls });
      var t = out.done;
      if (t.state === "granted") {
        return _terminal("revoked", {
          status: t.status, polls: out.polls,
          revokedCerts: _bindRevCerts(t.revCerts, own),
          crls: (t.crls || []).map(_asCrl),
        });
      }
      if (t.state === "rejected") return _terminal("rejected", { status: t.status || null, polls: out.polls });
      throw _err("cmp/unexpected-arm", t.reason || "the revocation transaction reached an unexpected state");
    } finally {
      inFlight = false;
      completed = started;
    }
  }

  
  async function info(request) {
    _assertFresh("support message");
    guard.identifier.assertPlainRecord(request, _err, "cmp/bad-input", "info(request), an object naming one support operation (caCerts / rootCaCert / certReqTemplate / crlUpdate),");
    guard.identifier.assertKnownKeys(request, INFO_OPS, _err, "cmp/bad-input", "unknown info request field ");
    var keys = Object.keys(request), names = [], values = [];
    for (var ki = 0; ki < keys.length; ki++) {
      var kv = request[keys[ki]];
      if (kv == null) continue;
      names[names.length] = keys[ki];
      values[values.length] = kv;
    }
    if (names.length !== 1) {
      throw _err("cmp/bad-input", "info(request) must name EXACTLY ONE support operation (caCerts / rootCaCert / certReqTemplate / crlUpdate); a genm carries a sequence of one InfoTypeAndValue (RFC 9483 sec. 4.3)");
    }
    var op = INFO_OPS[names[0]], asked = values[0];
    var itav = { infoType: op.requestOid };
    if (op.value === false) {
      if (asked !== true) throw _err("cmp/bad-input", "info request." + op.name + " takes `true`: this operation's genm carries no infoValue (RFC 9483 sec. 4.3.1 and sec. 4.3.3)");
    } else if (op.value === "cert") {
      var rootCaCertDer = _certificateArgument(asked, "info request rootCaCert");
      _assertCaCapable(x509.parse(rootCaCertDer), "info request rootCaCert", "cmp/bad-input");
      itav.infoValue = rootCaCertDer;
    } else if (op.value === "crlStatus") {
      var built = cmpBuild.buildCrlStatusList(asked);
      itav.infoValue = built.der;
      crlQuery = { issuerName: built.issuerName, thisUpdate: built.thisUpdate, dpn: built.dpn };
    }
    expectedInfoOp = op;
    inFlight = true;
    try {
      var out = await _runOneShot({ genm: [itav] }, "genm", "info");
      if (out.timeout) return _terminal("poll-timeout", { operation: op.name, status: out.status, polls: out.polls });
      var t = out.done;
      if (t.state === "granted") {
        var raw = t.itav.value;
        var value = null;
        if (raw != null) {
          try {
            value = schemaCmp[op.read](raw);
          } catch (e) {
            if (e && e.isCmpError) throw e;
            throw _err("cmp/bad-info-value", "the " + op.name + " response value is malformed -- " + ((e && e.message) || e), e);
          }
          value = await _checkInfoValue(op, value, itav.infoValue);
        }
        return _terminal("answered", { operation: op.name, present: raw != null, value: value, status: null, polls: out.polls });
      }
      if (t.state === "rejected") return _terminal("rejected", { operation: op.name, status: t.status || null, polls: out.polls });
      throw _err("cmp/unexpected-arm", t.reason || "the support-message transaction reached an unexpected state");
    } finally {
      inFlight = false;
      completed = started;
    }
  }

  function _checkInfoValue(op, value, requestValue) {
    if (op.name === "rootCaCert") {
      if (value.newWithOld == null) throw _err("cmp/bad-info-value", "a rootCaKeyUpdate response must carry newWithOld -- the certificate that lets an entity trusting the OLD root gain trust in the new one (RFC 9483 sec. 4.3.2)");
      return _checkRootCaKeyUpdate(value, requestValue);
    }
    if (op.name === "certReqTemplate") {
      var t = value.certTemplate;
      ["publicKey", "serialNumber", "signingAlg", "issuerUID", "subjectUID"].forEach(function (f) {
        if (t[f] != null) throw _err("cmp/bad-info-value", "a certReqTemplate certTemplate must omit " + f + " (RFC 9483 sec. 4.3.3)");
      });
      if (value.keySpec != null) value.keySpec.forEach(_checkKeySpec);
      return value;
    }
    if (op.name === "caCerts") return value.map(function (d) {
      var der = _asCertificate(d, "a caCerts entry");
      _assertCaCapable(x509.parse(der), "caCerts entry");
      return der;
    });
    if (op.name === "crlUpdate") {
      if (value.length !== 1) throw _err("cmp/bad-info-value", "a crlUpdate response answers a single-source query with exactly one CRL -- the latest from the named source (RFC 9483 sec. 4.3.4); got " + value.length);
      return value.map(_bindCrlToQuery);
    }
    throw _err("cmp/bad-info-value", "no response rules are defined for the " + op.name + " support message");
  }

  async function _checkRootCaKeyUpdate(value, oldRootDer) {
    var newWithNew = _asCertificate(value.newWithNew, "the rootCaKeyUpdate newWithNew");
    var newWithOld = _asCertificate(value.newWithOld, "the rootCaKeyUpdate newWithOld");
    var oldWithNew = value.oldWithNew == null ? null : _asCertificate(value.oldWithNew, "the rootCaKeyUpdate oldWithNew");
    var pNewNew = x509.parse(newWithNew), pNewOld = x509.parse(newWithOld), pOldRoot = x509.parse(oldRootDer);
    _assertCaCapable(pNewNew, "rootCaKeyUpdate newWithNew");
    _assertCaCapable(pNewOld, "rootCaKeyUpdate newWithOld");
    if (!cmpBuild.samePublicKey(pNewOld.subjectPublicKeyInfo.bytes, pNewNew.subjectPublicKeyInfo.bytes)) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate newWithOld must certify the NEW root key, the one newWithNew carries (RFC 9483 sec. 4.3.2)");
    }
    _assertSameName(pNewOld.issuer, pOldRoot.subject, "newWithOld", "be issued by the OLD root named in the request");
    _assertSameName(pNewOld.subject, pNewNew.subject, "newWithOld", "name the same subject as newWithNew, the certificate it vouches for");
    if (guard.name.dnEqual(pNewNew.issuer.rdns, pNewNew.subject.rdns, _err, "cmp/bad-info-value", "the rootCaKeyUpdate newWithNew name")) {
      await _assertSignedBy(pNewNew, pNewNew, "newWithNew", "its own key, which a self-issued root certificate must be");
    }
    await _assertSignedBy(pNewOld, pOldRoot, "newWithOld", "the OLD root CA key");
    if (oldWithNew !== null) {
      var pOldNew = x509.parse(oldWithNew);
      _assertCaCapable(pOldNew, "rootCaKeyUpdate oldWithNew");
      if (!cmpBuild.samePublicKey(pOldNew.subjectPublicKeyInfo.bytes, pOldRoot.subjectPublicKeyInfo.bytes)) {
        throw _err("cmp/bad-info-value", "the rootCaKeyUpdate oldWithNew must certify the OLD root key (RFC 9483 sec. 4.3.2)");
      }
      _assertSameName(pOldNew.issuer, pNewNew.subject, "oldWithNew", "be issued by the NEW root");
      _assertSameName(pOldNew.subject, pOldRoot.subject, "oldWithNew", "name the OLD root it vouches for");
      await _assertSignedBy(pOldNew, pNewNew, "oldWithNew", "the NEW root CA key");
    }
    return { newWithNew: newWithNew, newWithOld: newWithOld, oldWithNew: oldWithNew };
  }
  function _assertCaCapable(cert, which, code) {
    code = code || "cmp/bad-info-value";
    var bc = null, ku = null, bcCritical = false;
    cert.extensions.forEach(function (e) {
      if (e.oid === OID_BASIC_CONSTRAINTS) { bc = cmpBuild.decodeCertExtension(e.oid, e.value); bcCritical = e.critical === true; }
      if (e.oid === OID_KEY_USAGE) ku = cmpBuild.decodeCertExtension(e.oid, e.value);
    });
    if (!bc || bc.cA !== true) {
      throw _err(code, "the " + which + " must be a CA certificate (basicConstraints cA TRUE): an end-entity certificate certifies nothing and cannot serve as an issuer for chain construction (RFC 5280 sec. 6.1.4)");
    }
    if (!bcCritical) {
      throw _err(code, "the " + which + " marks basicConstraints non-critical, so a relying party that skips unrecognized extensions would not see the cA bit it must act on (RFC 5280 sec. 4.2.1.9)");
    }
    if (ku && ku.keyCertSign !== true) {
      throw _err(code, "the " + which + " carries a keyUsage that withholds keyCertSign, so it cannot sign certificates as a CA must (RFC 5280 sec. 6.1.4)");
    }
  }

  function _assertSameName(a, b, which, must) {
    if (!guard.name.dnEqual(a.rdns, b.rdns, _err, "cmp/bad-info-value", "a rootCaKeyUpdate name")) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate " + which + " must " + must + " (RFC 9483 sec. 4.3.2); got " + JSON.stringify(a.dn));
    }
  }
  async function _assertSignedBy(cert, signer, which, whose) {
    if (!_engine || !_engine.verifyWithSpki) {
      throw _err("cmp/bad-info-value", "the signature engine is unavailable, so a rootCaKeyUpdate cannot be checked; require pki.path to install it");
    }
    if (!guard.crypto.isOctetAligned(cert.signatureValue)) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate " + which + " signature is not octet-aligned (a BIT STRING with unused bits), which no valid signature is (RFC 9483 sec. 4.3.2)");
    }
    var ok = await _engine.verifyWithSpki(cert.signatureAlgorithm, cert.signatureValue.bytes, signer.subjectPublicKeyInfo.bytes, cert.tbsBytes);
    if (ok !== true) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate " + which + " is not signed by " + whose + ", so it cannot carry the trust transition it exists for (RFC 9483 sec. 4.3.2)");
    }
  }

  function _certificateArgument(value, what) {
    var der;
    if (typeof value === "string") {
      try { der = x509.pemDecode(value); }
      catch (e) { throw _err("cmp/bad-input", what + " is a string but not a PEM certificate", e); }
    } else if (value != null && Buffer.isBuffer(value.tbsBytes)) {
      throw _err("cmp/bad-input", what + " must carry the certificate's own bytes (DER or PEM): a parsed certificate keeps no source DER, and this request has to send the bytes the issuer signed");
    } else {
      der = guard.bytes.snapshot(value, CmpError, "cmp/bad-input", what);
    }
    return _asCertificate(der, what, "cmp/bad-input");
  }

  function _asCertificate(der, what, code) {
    try { x509.parse(der); }
    catch (e) { throw _err(code || "cmp/bad-info-value", what + " is not a valid X.509 certificate (RFC 9483 sec. 4.3)", e); }
    return Buffer.from(der);
  }
  function _asCrl(der) {
    try { schemaCrl.parse(der); }
    catch (e) { throw _err("cmp/bad-info-value", "a crlUpdate entry is not a valid CertificateList (RFC 9483 sec. 4.3.4)", e); }
    return Buffer.from(der);
  }
  function _bindCrlToQuery(der) {
    var parsed;
    try { parsed = schemaCrl.parse(der); }
    catch (e) { throw _err("cmp/bad-info-value", "a crlUpdate entry is not a valid CertificateList (RFC 9483 sec. 4.3.4)", e); }
    if (crlQuery && crlQuery.issuerName != null) {
      var want = schemaCmp.readName(crlQuery.issuerName);
      if (!guard.name.dnEqual(parsed.issuer.rdns, want.rdns, _err, "cmp/bad-info-value", "the crlUpdate issuer")) {
        throw _err("cmp/bad-info-value", "the returned CRL was issued by " + JSON.stringify(parsed.issuer.dn) + ", not by the source this request named (RFC 9483 sec. 4.3.4)");
      }
    }
    if (crlQuery && crlQuery.dpn != null) {
      var idpDpn = null, idpCritical = false, crlExts = parsed.crlExtensions || [];
      for (var xi = 0; xi < crlExts.length; xi++) {
        if (crlExts[xi].oid !== OID_IDP) continue;
        idpDpn = cmpBuild.decodeIdpDistributionPoint(crlExts[xi].value);
        idpCritical = crlExts[xi].critical === true;
        break;
      }
      if (idpDpn !== null && (!idpCritical || !guard.name.dpnCorresponds(crlQuery.dpn, idpDpn, _err, "cmp/bad-info-value", "the crlUpdate distribution point"))) {
        throw _err("cmp/bad-info-value", "the returned CRL is scoped to a distribution point other than the one this request named, or marks that scope non-critical where a relying party may ignore it (RFC 9483 sec. 4.3.4, RFC 5280 sec. 5.2.5)");
      }
    }
    if (crlQuery && crlQuery.thisUpdate != null) {
      var asked = crlQuery.thisUpdate;
      var got = guard.time.instantOf(parsed.thisUpdate, _err, "cmp/bad-info-value", "the returned CRL's thisUpdate");
      if (got <= asked) {
        throw _err("cmp/bad-info-value", "the returned CRL is no more recent than the thisUpdate this request supplied, so sec. 4.3.4 requires the response to carry no value at all");
      }
    }
    return Buffer.from(der);
  }

  var OID_REG_CTRL_ALG_ID = oid.byName("algId");
  var OID_REG_CTRL_RSA_KEY_LEN = oid.byName("rsaKeyLen");
  function _isRsaAlgorithm(dotted) {
    if (RSA_ARC_EXCLUDE[dotted] === 1) return false;
    var arcs = oid.toArcs(dotted);
    var underAny = false;
    for (var a = 0; !underAny && a < RSA_ARCS.length; a++) {
      var arc = RSA_ARCS[a];
      if (arcs.length > arc.length) {
        underAny = true;
        for (var i = 0; underAny && i < arc.length; i++) { underAny = arcs[i] === arc[i]; }
      }
    }
    return underAny || RSA_OFF_ARC[dotted] === 1;
  }
  function _checkKeySpec(ctrl) {
    if (ctrl.type === OID_REG_CTRL_RSA_KEY_LEN) {
      var len;
      try { len = asn1.read.integer(asn1.decode(ctrl.value)); }
      catch (e) { throw _err("cmp/bad-info-value", "a keySpec rsaKeyLen must be an INTEGER (RFC 9483 sec. 4.3.3)", e); }
      if (len <= 0n) throw _err("cmp/bad-info-value", "a keySpec rsaKeyLen must be a positive integer (RFC 9483 sec. 4.3.3); got " + len);
      ctrl.rsaKeyLen = len;
      return;
    }
    if (ctrl.type === OID_REG_CTRL_ALG_ID) {
      var alg;
      try { alg = schemaCmp.readAlgorithmIdentifier(ctrl.value); }
      catch (e) {
        if (e && e.isCmpError) throw e;
        throw _err("cmp/bad-info-value", "a keySpec algId must be an AlgorithmIdentifier (RFC 9483 sec. 4.3.3)", e);
      }
      if (_isRsaAlgorithm(alg.oid)) {
        throw _err("cmp/bad-info-value", "a keySpec algId must give an algorithm other than RSA, whose requirement is stated with rsaKeyLen instead (RFC 9483 sec. 4.3.3); got " + (alg.name || alg.oid));
      }
      ctrl.algorithm = alg.oid;
      ctrl.algorithmName = alg.name;
      ctrl.algorithmParameters = alg.parameters;
      return;
    }
    throw _err("cmp/bad-info-value", "a keySpec control must be id-regCtrl-algId or id-regCtrl-rsaKeyLen (RFC 9483 sec. 4.3.3); got " + ctrl.type);
  }

  return {
    enroll: enroll,
    revoke: revoke,
    info: info,
    get transactionID() { return Buffer.from(transactionID); },
    get transcript() { return _transcriptSnapshot(); },
  };
}

module.exports = {
  build: cmp.build,
  transfer: cmp.transfer,
  wellKnownUrl: cmp.wellKnownUrl,
  verify: cmp.verify,
  session: session,
  setEngine: setEngine,   // @internal
};
