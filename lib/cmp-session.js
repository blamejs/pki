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

var HASHLESS_SIG_OIDS = Object.create(null);
(function () {
  var names = ["Ed25519", "Ed448", "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87"];
  ["sha2", "shake"].forEach(function (h) { ["128s", "128f", "192s", "192f", "256s", "256f"].forEach(function (s) { names.push("id-slh-dsa-" + h + "-" + s); }); });
  names.forEach(function (n) { var o = oid.byName(n); if (o) HASHLESS_SIG_OIDS[o] = 1; });
})();
var SIG_OID_TO_HASH = Object.create(null);
[["sha256WithRSAEncryption", "SHA-256"], ["sha384WithRSAEncryption", "SHA-384"], ["sha512WithRSAEncryption", "SHA-512"],
  ["ecdsaWithSHA256", "SHA-256"], ["ecdsaWithSHA384", "SHA-384"], ["ecdsaWithSHA512", "SHA-512"]].forEach(function (row) {
  var o = oid.byName(row[0]); if (o) SIG_OID_TO_HASH[o] = row[1];
});
var OID_RSASSA_PSS = oid.byName("rsassaPss");
var OID_RSA_ENCRYPTION = oid.byName("rsaEncryption");
var OID_IDP = oid.byName("issuingDistributionPoint");
var OID_BASIC_CONSTRAINTS = oid.byName("basicConstraints");
var OID_KEY_USAGE = oid.byName("keyUsage");
var HASH_OID_TO_DIGEST = Object.create(null);
[["sha256", "SHA-256"], ["sha384", "SHA-384"], ["sha512", "SHA-512"]].forEach(function (row) { var o = oid.byName(row[0]); if (o) HASH_OID_TO_DIGEST[o] = row[1]; });
var COMPOSITE_PH_HASHALG = Object.assign(Object.create(null), { "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512" });
var RESUMABLE_ARMS = Object.assign(Object.create(null), { ip: 1, cp: 1, kup: 1 });
var RESUME_TOKEN_KEYS = Object.assign(Object.create(null), {
  transactionId: 1, recipNonce: 1, certReqId: 1, arm: 1, polls: 1, requestedSpki: 1,
  signer: 1, signerCache: 1, chain: 1, caPubs: 1, nextPollAt: 1, implicitConfirm: 1, protection: 1,
});
var RESUMABLE_PROTECTION = Object.assign(Object.create(null), { signature: 1, mac: 1 });

var KNOWN_SESSION_OPTS = Object.assign(Object.create(null), {
  url: 1, key: 1, cert: 1, mac: 1, trustAnchors: 1, intermediates: 1, recipient: 1, sender: 1,
  extraCerts: 1, implicitConfirm: 1, maxPolls: 1, maxTotalWait: 1, sleep: 1, time: 1,
  transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, proxy: 1, pss: 1, digestAlgorithm: 1,
  acceptCert: 1, senderKID: 1, recipKID: 1, expectedSender: 1,
});

var TRANSCRIPT_RETAIN_RESPONSES = 2;
var DEFAULT_MAX_POLLS = 20;
var DEFAULT_MAX_TOTAL_WAIT = retryAfter.MAX_RETRY_AFTER_SECONDS;
var DEFAULT_CERT_REQ_ID = 0;
var P10CR_CERT_REQ_ID = -1;
var ENROLL_ARMS = Object.assign(Object.create(null), { ir: 1, cr: 1, kur: 1, p10cr: 1 });
var RESPONSE_ARM = Object.assign(Object.create(null), { ir: "ip", cr: "cp", kur: "kup", p10cr: "cp", rr: "rp", genm: "genp" });
var WHOLE_MESSAGE_CERT_REQ_ID = -1;

var INFO_OPS = Object.assign(Object.create(null), {
  caCerts: { name: "caCerts", requestOid: "caCerts", responseOid: "caCerts", value: false, read: "readCaCerts" },
  rootCaCert: { name: "rootCaCert", requestOid: "rootCaCert", responseOid: "rootCaKeyUpdate", value: "cert", read: "readRootCaKeyUpdate" },
  certReqTemplate: { name: "certReqTemplate", requestOid: "certReqTemplate", responseOid: "certReqTemplate", value: false, read: "readCertReqTemplate" },
  crlUpdate: { name: "crlUpdate", requestOid: "crlStatusList", responseOid: "crls", value: "crlStatus", read: "readCrls" },
});
var KNOWN_REVOKE_KEYS = Object.assign(Object.create(null), { certificate: 1, certDetails: 1, reason: 1 });
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
var PKI_STATUS_NAMES = Object.assign(Object.create(null), { 0: "accepted", 1: "grantedWithMods", 2: "rejection", 3: "waiting" });
var PKI_STATUS_WAITING = 3;
/** @internal The status a transaction a token can continue is in, by construction: a token exists only
 * because a response said waiting, and a poll that times out is still waiting. A process that read no
 * CertResponse of its own reports this, so a wait split across processes reads the same as one held in a
 * single process. The authority's own diagnostic strings are not reproduced from stored state, since a
 * verdict must not present text the authority did not sign in this exchange as though it had. */
function _waitingStatus() {
  return { status: { code: PKI_STATUS_WAITING, name: PKI_STATUS_NAMES[PKI_STATUS_WAITING] },
    statusString: null, failInfo: null };
}

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
  _expectSeq(node, 2, 2);
  var algId = node.children[0];
  _expectSeq(algId, 1, 2);
  var algOid = asn1.read.oid(algId.children[0]);
  var key = guard.crypto.assertOctetAligned(asn1.read.bitString(node.children[1]), _err,
    "cmp/bad-input", "a SubjectPublicKeyInfo subjectPublicKey");
  var pn = algId.children[1];
  var params;
  if (algOid === OID_RSA_ENCRYPTION) {
    params = (pn == null || _isDerNull(pn)) ? "" : pn.bytes.toString("latin1");
  } else {
    params = pn ? pn.bytes.toString("latin1") : "";
  }
  return algOid + "|" + params + "|" + key.bytes.toString("latin1");
}
/** @internal A SubjectPublicKeyInfo and the AlgorithmIdentifier inside it are SEQUENCEs of a known
 * width. Reading a child without asking for the shape reads whatever sits in that position, which is
 * how DER that is not a public key at all is fingerprinted as one. */
function _expectSeq(node, min, max) {
  if (node.tagClass !== "universal" || node.tagNumber !== 16 || !node.children ||
      node.children.length < min || node.children.length > max) {
    throw _err("cmp/bad-input", "a SubjectPublicKeyInfo is a SEQUENCE of an AlgorithmIdentifier and a BIT STRING (RFC 5280 sec. 4.1.2.7)");
  }
}
function _isDerNull(pn) { return pn.tagClass === "universal" && pn.tagNumber === 5 && pn.content.length === 0; }

var CERT_MAX_BYTES = constants.LIMITS.DER_MAX_BYTES;
/** @internal The spelling `String(BigInt)` produces, and only that one: an optional leading minus
 * (0x2d), then ASCII digits (0x30 to 0x39), with a leading zero only when the value is zero itself, so
 * `007` and `-0` are refused along with every non-digit. */
function _isCanonicalDecimal(s) {
  var i = s.charCodeAt(0) === CH_MINUS ? 1 : 0;
  if (i >= s.length) return false;
  for (var j = i; j < s.length; j++) {
    var c = s.charCodeAt(j);
    if (c < CH_ZERO || c > CH_NINE) return false;
  }
  var leadingZero = s.charCodeAt(i) === CH_ZERO;
  if (leadingZero && s.length - i > 1) return false;
  return !(leadingZero && i === 1);
}
var CH_MINUS = 0x2d, CH_ZERO = 0x30, CH_NINE = 0x39;
/** @internal A ceiling on the decimal string, not on the identifier: converting one to a BigInt costs
 * more than linear time, so the length is bounded before the conversion runs. It sits above the widest
 * identifier the codec encodes (an INTEGER of the maximum width takes about 2.41 digits per byte), and
 * the encoder itself is what the door then holds the converted value to. */
var CERTREQID_MAX_DIGITS = constants.LIMITS.DER_MAX_INTEGER_BYTES * 3;
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
 * hard-stop `CmpError` throw.
 *
 * A certification authority can take longer to answer than a process is held open, so a `poll-timeout`
 * carries a `resumeToken` and `session.resumePoll(token)` continues the same transaction in a later
 * one. The token is plain JSON: the transaction identifier, the nonce the next request must echo, the
 * polled request identifier (a decimal string, so an identifier of any width survives) and the arm its
 * grant arrives on, whether the request that opened the transaction asked for implicit confirmation,
 * how the transaction authenticates, the polls already spent, the key the grant must certify, the signer identity the
 * first process authenticated and, separately, the certificate it currently verifies a response with
 * when that response omits its extraCerts, the certificates the authority had already sent, and the
 * instant its own `checkAfter` allows the next poll. It carries no secret, because the protection material and the
 * endpoint come from the session built to resume with, and it grants nothing: the resumed poll verifies
 * and nonce-binds every response, holds it to the signer identity the token names, and holds the grant to
 * the key the token names. Those fields are what the exchange is held to, so the token is
 * integrity-sensitive: someone who can rewrite it can widen what the resumed session accepts, as far as
 * that session's trust anchors and the authority's protection allow and no further. Store it the way the
 * enrollment's own state is stored, and resume it in a session configured the way the first one was: the
 * token carries what the transaction established, and the protection material, the trust anchors, the
 * endpoint and an `expectedSender` pin are given again, so a resumed poll accepts and refuses exactly
 * what an uninterrupted one in the same session would. The authority's polling interval is waited out
 * before the first resumed request, while this session's own `maxTotalWait` still bounds it: a
 * remainder longer than the budget times out now and hands the same due time on. A further timeout
 * hands back a token again, so a wait can span any number of processes, and each timeout reports the
 * waiting status whether or not that process read a CertResponse of its own. The authority's own
 * diagnostic strings are not reproduced from the token, so a verdict never presents text as the
 * authority's that it did not send in that exchange. A token is refused before a
 * request is sent when it is mis-shaped, when the key it names is not a `SubjectPublicKeyInfo`, when a
 * field that names a certificate is not one, or when it carries more certificates than the list it
 * restores is built under. The two fields that bind the transaction are required rather than
 * optional, since a token lives in storage where it can be edited and dropping a field must not drop
 * the check it feeds: the key the grant is held to, and, for a signature session, the identity every
 * response is held to. A shared-secret session pins no certificate, and its secret is the binding. Exactly one protection flavor: `{ key, cert }` (signature) XOR `{ mac }`
 * (PBMAC1). A crypto-valid response is not enough: the signer must chain to a supplied trust anchor
 * (signature) or the shared secret must match (MAC); a valid-but-untrusted response is a hard stop, so the
 * signature flavor REQUIRES `opts.trustAnchors` at construction. Returns a session with `enroll(request)`,
 * `resumePoll(token)`, `revoke(request)`, `info(request)`,
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
  /** @internal Taken from the caller's object, before the copy below keeps own properties only. A
   * defaults bag carries its options on a prototype, so checking the copy would find no transport,
   * drop the one the caller supplied, and send the session to the default client instead. */
  var _transport = guard.identifier.assertCallableOption(opts, "transport", _err, "cmp/bad-input",
    "opts.transport", "(url, reqDer, opts) => Promise<{ responseBytes, status }>");
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
  if (opts.acceptCert != null && opts.implicitConfirm) throw _err("cmp/bad-input", "opts.acceptCert cannot be combined with opts.implicitConfirm -- implicit confirmation leaves no certConf leg to reject on (drop implicitConfirm to vet a grant)");

  if (opts.time != null) guard.time.assertValid(opts.time, _err, "cmp/bad-input", "opts.time (the verify/validation clock)");
  var maxPolls = guard.limits.cap(opts.maxPolls, "opts.maxPolls", DEFAULT_MAX_POLLS, { E: _err, code: "cmp/bad-input", min: 1, max: 1000 });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "opts.maxTotalWait", DEFAULT_MAX_TOTAL_WAIT, { E: _err, code: "cmp/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = opts.sleep || sleepUtil.sleep;

  var transactionID = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(constants.LIMITS.CMP_TRANSACTION_ID_BYTES)));
  var lastPeerNonce = null;
  var haveResponse = false;
  var cachedSignerCert = null;
  var pinnedSignerCert = null, pinnedSignerDer = null, signerPinned = false;
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
  /** @internal What the request asked for, not what this session was configured with. A resumed poll
   * finishes a transaction whose confirmation was negotiated in a request an earlier process sent, so
   * the grant is confirmed the way that request asked and not the way this session's options read. */
  var requestedImplicitConfirm = opts.implicitConfirm === true;
  var inFlight = false, completed = false, started = false;
  var transcript = [];
  var transcriptBytes = 0;
  /** @internal The response size is a bound the token decode and the certificate pools are measured
   * against, so it is checked here rather than at the first transfer: a value that is not a positive
   * whole number of bytes is refused where it is supplied, not carried into whatever reads it first. */
  var _perRespCap = opts.maxResponseBytes == null ? constants.LIMITS.HTTP_MAX_RESPONSE_BYTES
    : guard.limits.cap(opts.maxResponseBytes, "opts.maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES,
      { E: _err, code: "cmp/bad-input", min: 1, max: constants.LIMITS.HTTP_MAX_RESPONSE_BYTES });
  var transcriptCap = _perRespCap * TRANSCRIPT_RETAIN_RESPONSES;
  var caPubsByteBudget = _perRespCap * TRANSCRIPT_RETAIN_RESPONSES;
  /** @internal What a restored token's certificates are held to, which is what the list it restores can
   * hold. Every bound below is a module constant or the response size, which `guard.limits.cap` has
   * already refused unless it is a positive whole number, so none can arrive unusable. The authority's
   * own pool arrives in responses, so it keeps both the response size and the
   * total the session accumulates under. The chain that validates the signer is also built from
   * `opts.intermediates`, whose certificates never crossed the wire and are bounded only by the path
   * length and the codec, so those two are its bounds and it carries no third one: a session holds a
   * caller's intermediates at that same size already, and a total below the two would refuse a token
   * the session itself issued. */
  var CAPUBS_LIMIT = { count: CAPUBS_MAX, each: _perRespCap, total: caPubsByteBudget };
  var CHAIN_LIMIT = { count: constants.LIMITS.PATH_MAX_CERTS, each: CERT_MAX_BYTES, total: null };

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
    var o = Object.assign(Object.create(null), { transactionID: transactionID, expectRecipNonce: fresh });
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
    var o = Object.create(null);
    ["tls", "headers", "timeout", "maxResponseBytes"].forEach(function (k) { if (opts[k] != null) o[k] = opts[k]; });
    if (_transport !== undefined) o.transport = _transport;
    if (_proxySnap != null) o.proxy = _proxySnap;
    return o;
  }

  async function _send(bodySpec, arm) {
    var fresh = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(16)));
    var header = Object.assign(_baseHeader(fresh), ENROLL_ARMS[arm] && requestedImplicitConfirm ? { generalInfo: [{ infoType: "implicitConfirm" }] } : {});
    var reqDer = await cmp.build({ header: header, body: bodySpec }, _buildOpts());
    _recordTranscript({ direction: "out", arm: arm, bytes: reqDer });
    var engaged = false;
    var topts = _transferOpts();
    if (_transport !== undefined) topts.transport = function (a) { engaged = true; return _transport(a); };
    var res;
    try {
      res = await cmp.transfer(opts.url, reqDer, topts);
    } catch (e) {
      var reached = _transport !== undefined
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
      if (!signerPinned) { pinnedSignerCert = x509.parse(verdict.signer.cert); pinnedSignerDer = Buffer.from(verdict.signer.cert); signerPinned = true; }
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
          if (isGrantLeg) { for (var pi = 0; pi < caPubsAccum.length; pi++) { if (caPubsAccum[pi].toString("base64") === k) { guard.list.append(caPubsAccum, caPubsAccum.splice(pi, 1)[0]); if (pi < caPubsWaitingCount) caPubsWaitingCount--; break; } } }
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
        guard.list.append(caPubsAccum, Buffer.from(c));
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
    guard.list.append(transcript, over
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
  /** @internal What a later process needs to carry THIS transaction on: the identifier the exchange is
   * keyed by, the nonce the next request must echo, which request is being polled and on which arm its
   * grant will arrive, and the key the grant must certify (RFC 9810 sec. 5.1.1). Plain JSON values, since
   * it crosses a process boundary. Everything else, the protection material and the endpoint, comes from
   * the session the caller builds to resume with, so the token carries no secret. */
  /** @internal The instant an outstanding checkAfter falls due, or null when the authority named none. */
  function _pollDueAt(dueInSeconds) {
    if (typeof dueInSeconds !== "number" || !isFinite(dueInSeconds) || dueInSeconds <= 0) return null;
    return guard.time.instantOf(new Date()) + constants.TIME.seconds(dueInSeconds);
  }

  function _resumeToken(polls, nextPollAt) {
    /** @internal Only an enrollment reaches here, and only after a response, so the nonce to echo is the
     * one thing that could still be missing: a responder that omitted its senderNonce leaves the chain
     * unable to continue, and a token that cannot be continued is not offered. */
    if (!Buffer.isBuffer(lastPeerNonce) || lastPeerNonce.length === 0) return null;
    /** @internal Two different certificates: the identity pinned on the FIRST response, which every
     * later response is bound to, and the one currently used to verify when a response omits its
     * extraCerts. A same-identity rotation moves the second and never the first, so collapsing them
     * would let a restart accept an identity the uninterrupted transaction refuses. */
    var pinDer = pinnedSignerDer;
    return {
      transactionId: transactionID.toString("hex"),
      recipNonce: lastPeerNonce.toString("base64"),
      /** @internal A request identifier is an INTEGER of any width, so it travels as a decimal string:
       * a BigInt is not JSON, and a token that cannot be serialized is not a resumable one. */
      certReqId: activeCertReqId.toString(),
      arm: expectedRespArm,
      polls: polls,
      /** @internal Negotiated in the request this token continues, so it travels with the transaction:
       * a later process confirms the grant the way that request asked, whatever its own options say. */
      implicitConfirm: requestedImplicitConfirm,
      /** @internal How the exchange authenticates. The signer identity below is only a binding under
       * signature protection; under a shared secret the secret is the binding, so a session resuming
       * this transaction has to authenticate it the way the transaction already does. */
      protection: isSig ? "signature" : "mac",
      requestedSpki: requestedSpki ? Buffer.from(requestedSpki).toString("base64") : null,
      /** @internal The identity the first process pinned on the first response it verified. Restoring it
       * is what keeps a restart from admitting a DIFFERENT trusted signer, which an uninterrupted
       * transaction refuses (RFC 9483 sec. 3.1), and it carries the certificate a responder that sent
       * its chain only once would not send again. */
      signer: pinDer ? Buffer.from(pinDer).toString("base64") : null,
      signerCache: cachedSignerCert != null ? Buffer.from(cachedSignerCert).toString("base64") : null,
      chain: cachedChain.map(function (c) { return Buffer.from(c).toString("base64"); }),
      /** @internal An authority may deliver the issued certificate's intermediate in a WAITING response
       * and omit it from the grant, so the certificates accumulated before the timeout travel too, or
       * the resumed grant would fail a validation the uninterrupted transaction passes. */
      caPubs: caPubsAccum.map(function (c) { return Buffer.from(c).toString("base64"); }),
      /** @internal The instant the authority's own checkAfter allows the next poll. Resuming earlier
       * would poll faster than it asked to be polled. */
      nextPollAt: nextPollAt != null ? nextPollAt : null,
    };
  }

  function _terminal(outcome, extra) {
    return guard.verdict.of({
      outcome: outcome, certificate: null, chain: [], status: null, trusted: true,
      confirmed: false, implicitConfirm: false, transactionID: Buffer.from(transactionID),
      polls: 0, transcript: _transcriptSnapshot(),
    }, extra);
  }

  async function _pollLoop(lastWaitingResp, alreadyWaited) {
    var polls = 0, waited = alreadyWaited || 0, lastStatus = _statusOf(lastWaitingResp);
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
        /** @internal The authority asked to be polled again after `checkAfter`, and the budget ran out
         * before that wait was taken. Reporting it lets a resumed poll honor the interval rather than
         * poll immediately in a new process. */
        if (waited > maxTotalWait) return { timeout: true, polls: polls, status: lastStatus, dueIn: checkAfter };
        if (polls >= maxPolls) return { timeout: true, polls: polls, status: lastStatus, dueIn: checkAfter };
        await sleep(checkAfter * constants.TIME.seconds(1));
        continue;
      }
      if (t.state === "waiting") { lastStatus = _statusOf(t.resp); continue; }
      return { done: t, polls: polls, header: verdict.header };
    }
  }

  async function _confirm(certDer, header, info) {
    if (requestedImplicitConfirm && _implicitConfirmGranted(header)) return { confirmed: true, implicit: true };
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
    if (requestedSpki != null) {
      var granted, wanted;
      try { granted = _spkiKeyIdentity(parsed.subjectPublicKeyInfo.bytes); wanted = _spkiKeyIdentity(requestedSpki); }
      catch (e) { throw _err("cmp/bad-cert-response", "the issued certificate's public key cannot be compared with the requested key", e); }
      if (granted !== wanted) {
        throw _err("cmp/bad-cert-response", "the issued certificate's public key does not match the requested key -- a misrouted certificate the caller has no private key for");
      }
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
      guard.list.append(chain, c);
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
        if (polled.timeout) return _terminal("poll-timeout", { status: polled.status, polls: pollCount, resumeToken: _resumeToken(pollCount, _pollDueAt(polled.dueIn)) });
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

  /** @internal The state a poll-timeout handed the caller, read back. It is the caller's own record of
   * a transaction it started, so it says WHICH exchange to continue, never who may continue it: the
   * protection material and the endpoint come from this session, every response is verified the way the
   * first process verified them, and the grant is still bound to the key the token names. */
  function _readResumeToken(token) {
    if (token === null || typeof token !== "object" || Array.isArray(token)) {
      throw _err("cmp/bad-input", "resumePoll expects the resumeToken a poll-timeout verdict carried");
    }
    guard.identifier.assertKnownKeys(token, RESUME_TOKEN_KEYS, _err, "cmp/bad-input", "the resumeToken has an unknown field ");
    /** @internal Every field is taken once, here, and the checks below run on what was taken. A token is
     * any object a caller hands in, so a field read a second time can answer differently than it did when
     * it was checked, and the restored state would carry the second answer past the check. */
    var raw = {
      transactionId: token.transactionId, recipNonce: token.recipNonce, certReqId: token.certReqId,
      arm: token.arm, polls: token.polls, requestedSpki: token.requestedSpki, signer: token.signer,
      signerCache: token.signerCache, chain: token.chain, caPubs: token.caPubs,
      nextPollAt: token.nextPollAt, implicitConfirm: token.implicitConfirm,
      protection: token.protection,
    };
    var txn = _hexField(raw.transactionId, "transactionId");
    /** @internal The width a first message opens a transaction with (RFC 9483 sec. 3.1), which is the
     * width this session writes, so a token naming any other names a transaction it cannot have opened. */
    if (txn.length !== constants.LIMITS.CMP_TRANSACTION_ID_BYTES) {
      throw _err("cmp/bad-input", "the resumeToken transactionId must name the transaction to continue, as the " + constants.LIMITS.CMP_TRANSACTION_ID_BYTES + " bytes a first message opens one with (RFC 9483 sec. 3.1)");
    }
    var nonce = _b64Field(raw.recipNonce, "recipNonce");
    /** @internal The same floor a received message is held to, so a nonce no response could have carried
     * is refused here rather than echoed into a request that cannot continue the chain. */
    if (nonce.length < constants.LIMITS.CMP_MIN_NONCE_BYTES) {
      throw _err("cmp/bad-input", "the resumeToken recipNonce must carry the nonce the next request echoes, at least " + constants.LIMITS.CMP_MIN_NONCE_BYTES + " bytes of it (RFC 9483 sec. 3.5)");
    }
    /** @internal A decimal string, so an identifier of any width a request can carry survives the round
     * trip, including the PKCS#10 sentinel (-1, which names the whole message rather than one request).
     * The reader accepts every identifier an enrollment can put in a token: it names which response to
     * match, and the grant is bound by the nonce, the protection, the signer and the key. */
    var certReqId;
    if (typeof raw.certReqId !== "string" || raw.certReqId.length === 0 || raw.certReqId.length > CERTREQID_MAX_DIGITS) {
      throw _err("cmp/bad-input", "the resumeToken certReqId must be a decimal string identifying the polled request, of at most " + CERTREQID_MAX_DIGITS + " characters");
    }
    /** @internal `BigInt` also reads a hexadecimal, binary or octal literal, a leading plus and
     * surrounding whitespace, none of which a token carries: the identifier is written the way the
     * emitting session writes it, so anything else names a different request than it appears to. */
    if (!_isCanonicalDecimal(raw.certReqId)) {
      throw _err("cmp/bad-input", "the resumeToken certReqId must be written as the emitting session writes it, in decimal with no sign but a leading minus, no leading zero and no surrounding space");
    }
    try { certReqId = BigInt(raw.certReqId); }
    catch (_e) { throw _err("cmp/bad-input", "the resumeToken certReqId must be a decimal string identifying the polled request"); }
    /** @internal The identifier is encoded again on the next request, so the door asks the encoder what
     * it accepts rather than approximating it from a digit count: a width the encoder refuses would
     * otherwise pass here and fail after the restored state had already consumed the session. */
    try { asn1.build.integer(certReqId); }
    catch (e) { throw _err("cmp/bad-input", "the resumeToken certReqId is wider than a CertReqMsg request identifier can encode", e); }
    var arm = raw.arm;
    if (typeof arm !== "string" || RESUMABLE_ARMS[arm] !== 1) {
      throw _err("cmp/bad-input", "the resumeToken arm must be an enrollment response arm (ip, cp or kup), got " + guard.text.showValue(arm));
    }
    var polls = raw.polls;
    if (polls != null && (!Number.isInteger(polls) || polls < 0)) {
      throw _err("cmp/bad-input", "the resumeToken polls must be a non-negative integer count of the polls already spent");
    }
    /** @internal A token is state a caller stored, and storage is where it can be edited. Dropping a
     * field must not drop the check that field feeds, so the two that bind the transaction are required:
     * the key the grant is held to, and, for a signature session, the identity every response is held
     * to. A shared-secret session pins no certificate, and its secret is the binding instead. */
    if (raw.requestedSpki == null) {
      throw _err("cmp/bad-input", "the resumeToken requestedSpki must name the key the granted certificate certifies -- without it the grant would be bound to nothing");
    }
    var spki = _b64Field(raw.requestedSpki, "requestedSpki", CERT_MAX_BYTES);
    /** @internal Read at the door, not when the grant arrives: stored state that is not a public key
     * would otherwise advance the exchange with the authority before it was found to be unusable. */
    try { _spkiKeyIdentity(spki); }
    catch (e) { throw _err("cmp/bad-input", "the resumeToken requestedSpki is not a SubjectPublicKeyInfo", e); }
    var signer = null;
    if (raw.signer != null) signer = _certField(raw.signer, "signer", CERT_MAX_BYTES);
    else if (isSig) {
      throw _err("cmp/bad-input", "the resumeToken signer must name the identity the transaction authenticated -- without it a resumed response from a different trusted signer would be accepted (RFC 9483 sec. 3.1)");
    }
    var signerCache = null;
    if (raw.signerCache != null) signerCache = _certField(raw.signerCache, "signerCache", CERT_MAX_BYTES);
    var chain = _certListField(raw.chain, "chain", CHAIN_LIMIT);
    var caPubs = _certListField(raw.caPubs, "caPubs", CAPUBS_LIMIT);
    /** @internal How the transaction authenticates is fixed by the request that opened it, and the two
     * flavors bind a response differently: under signature protection the pinned signer identity is the
     * binding, and under a shared secret the secret is. A session that authenticates the other way would
     * carry the transaction on under a binding it never had, so it is refused rather than adapted to.
     * A token trimmed of the field is read from its own contents rather than from this session, since
     * taking it from the session would let either flavor answer for the other: a signature transaction
     * pins the signer it authenticated, and a shared-secret one has none to pin. */
    var protection = raw.protection == null ? (raw.signer != null ? "signature" : "mac") : raw.protection;
    if (typeof protection !== "string" || RESUMABLE_PROTECTION[protection] !== 1) {
      throw _err("cmp/bad-input", "the resumeToken protection must name how the transaction authenticates, either signature or mac, got " + guard.text.showValue(raw.protection));
    }
    if ((protection === "signature") !== isSig) {
      throw _err("cmp/bad-input", "the resumeToken continues a transaction protected by " + protection + ", so it cannot be resumed by a session protected by " + (isSig ? "signature" : "mac") + " (RFC 9483 sec. 3.1 binds a transaction to how its sender authenticates)");
    }
    /** @internal Read from the token, never from this session's option, since it is what the request
     * that opened the transaction asked for. A token that omits it resumes as though the request asked
     * for nothing, which sends a certConf the authority may already have made unnecessary but never
     * accepts an implicit confirmation the request did not solicit. */
    var implicitConfirm = raw.implicitConfirm == null ? false : raw.implicitConfirm;
    if (typeof implicitConfirm !== "boolean") {
      throw _err("cmp/bad-input", "the resumeToken implicitConfirm must be a boolean saying whether the request that opened this transaction asked for implicit confirmation");
    }
    /** @internal The same pairing the constructor refuses, refused again where the token can reintroduce
     * it: an implicitly confirmed grant has no certConf leg, so a policy that vets one would never run. */
    if (implicitConfirm === true && typeof opts.acceptCert === "function") {
      throw _err("cmp/bad-input", "the resumeToken continues a transaction that asked for implicit confirmation, which leaves no certConf leg for opts.acceptCert to reject on -- resume it with a session that vets no grant");
    }
    var nextPollAt = raw.nextPollAt;
    if (nextPollAt != null && (typeof nextPollAt !== "number" || !isFinite(nextPollAt) || nextPollAt < 0)) {
      throw _err("cmp/bad-input", "the resumeToken nextPollAt must be the instant the next poll is due, in milliseconds since the epoch");
    }
    return { transactionID: txn, recipNonce: nonce, certReqId: certReqId, arm: arm,
      implicitConfirm: implicitConfirm,
      polls: polls || 0, requestedSpki: spki, signer: signer, signerCache: signerCache,
      chain: chain, caPubs: caPubs,
      nextPollAt: nextPollAt != null ? nextPollAt : null };
  }

  /** @internal The token crosses a process boundary as text, so each field is decoded through the
   * canonical readers, which refuse a non-alphabet character, a short group and a re-encoding that does
   * not reproduce the input, and cap the size before allocating. */
  function _hexField(v, name) {
    return guard.encoding.hex(v, _perRespCap, _err, "cmp/bad-input", "the resumeToken " + name);
  }

  function _b64Field(v, name, cap) {
    return guard.encoding.base64(v, cap || _perRespCap, _err, "cmp/bad-input", "the resumeToken " + name);
  }

  /** @internal A certificate the token carries. Parsed at the door, not when it is first needed: stored
   * bytes that are not a certificate would otherwise advance the exchange with the authority, spending a
   * nonce the token cannot be used again after, before they were found to be unusable. The cap is the
   * one the bytes were admitted under. A response-borne certificate is held to the response size, while
   * the signer identity and the chain that validates it can be a certificate the caller supplied through
   * `opts.intermediates`, which never crossed the wire and is bounded by the codec instead. */
  function _certField(v, name, cap) {
    var der = _b64Field(v, name, cap);
    try { x509.parse(der); }
    catch (e) { throw _err("cmp/bad-input", "the resumeToken " + name + " is not a certificate", e); }
    return der;
  }

  /** @internal A list of certificates the token carries, held to the count and the total size the list it
   * restores is built under, so a token cannot hand a resumed transaction a larger pool than the
   * transaction itself could reach. */
  function _certListField(v, name, limit) {
    if (v == null) return [];
    if (!Array.isArray(v)) throw _err("cmp/bad-input", "the resumeToken " + name + " must be an array of base64 certificates");
    if (v.length > limit.count) throw _err("cmp/bad-input", "the resumeToken " + name + " carries more than the " + limit.count + " certificates a transaction holds");
    var out = [], total = 0;
    for (var i = 0; i < v.length; i++) {
      var der = _certField(v[i], name + "[" + i + "]", limit.each);
      total += der.length;
      if (limit.total !== null && total > limit.total) {
        throw _err("cmp/bad-input", "the resumeToken " + name + " exceeds the " + limit.total + "-byte pool a transaction holds");
      }
      out.push(der);
    }
    return out;
  }

  /** @internal Continue polling a transaction an earlier process started, and finish it the way that
   * process would have: the grant is confirmed, bound to the requested key, and returned as the same
   * verdict `enroll` returns. A further timeout hands back a token again, so a long wait can span any
   * number of processes. */
  async function resumePoll(token) {
    _assertFresh("resumed poll");
    var t = _readResumeToken(token);
    inFlight = true;
    try {
      txnKind = "enroll";
      /** @internal Installing the restored state consumes the session, whether or not a request follows:
       * this session now holds another transaction's identifier and nonce, and a later enroll on it would
       * open a new enrollment under them (RFC 9810 sec. 5.1.1 gives each transaction its own identifier). */
      started = true;
      transactionID = t.transactionID;
      lastPeerNonce = t.recipNonce;
      haveResponse = true;
      activeCertReqId = t.certReqId;
      expectedRespArm = t.arm;
      requestedSpki = t.requestedSpki;
      requestedImplicitConfirm = t.implicitConfirm;
      /** @internal Restoring the pinned identity is what makes a restart no weaker than staying in one
       * process: the resumed responses are held to the signer the first process authenticated, and the
       * certificates it had already been sent are available to verify them with. */
      if (t.signer != null) {
        try { pinnedSignerCert = x509.parse(t.signer); pinnedSignerDer = t.signer; signerPinned = true; }
        catch (e) { throw _err("cmp/bad-input", "the resumeToken signer is not a valid X.509 certificate", e); }
      }
      /** @internal The pin and the cache are separate state and stay separate here. The pin says which
       * identity every response is held to; the cache is the certificate the first process had actually
       * been sent to verify one with, and a token that names no cache is a transaction that had none, so
       * standing the pin in for it would let a resumed poll read a response, and validate a grant, that
       * the same exchange in one process refuses. */
      cachedSignerCert = t.signerCache;
      cachedChain = t.chain;
      /** @internal The certificates the earlier process was sent, restored under the same bookkeeping the
       * session accumulates with, so the pool stays bounded across the restart. */
      for (var ci = 0; ci < t.caPubs.length; ci++) {
        var pub = t.caPubs[ci];
        var pk = pub.toString("base64");
        if (caPubsSeen[pk]) continue;
        caPubsSeen[pk] = true;
        caPubsBytes += pub.length;
        guard.list.append(caPubsAccum, pub);
      }
      /** @internal Every restored certificate arrived on a waiting leg, so it is evictable the same way:
       * leaving the count at zero would stop the grant's own issuer displacing one when the pool is full. */
      caPubsWaitingCount = caPubsAccum.length;
      /** @internal The authority's own interval is honored, but the CALLER's wait budget still bounds
       * this process: a remainder longer than the budget is a timeout now, carrying the same due time on
       * so a later process with more room can still wait it out. */
      var restWaited = 0;
      if (t.nextPollAt != null) {
        var waitMs = t.nextPollAt - guard.time.instantOf(new Date());
        if (waitMs > 0) {
          var waitSeconds = Math.ceil(waitMs / constants.TIME.seconds(1));
          if (waitSeconds > maxTotalWait) {
            return _terminal("poll-timeout", { status: _waitingStatus(), polls: t.polls, resumeToken: _resumeToken(t.polls, t.nextPollAt) });
          }
          await sleep(waitMs);
          restWaited = waitSeconds;
        }
      }
      var polled = await _pollLoop(null, restWaited);
      var spent = t.polls + polled.polls;
      if (polled.timeout) return _terminal("poll-timeout", { status: polled.status || _waitingStatus(), polls: spent, resumeToken: _resumeToken(spent, _pollDueAt(polled.dueIn)) });
      var done = polled.done;
      if (done.state === "granted") {
        var r = await _finish({ resp: done.resp, polls: spent, code: done.code }, polled.header);
        r.polls = spent;
        return r;
      }
      if (done.state === "rejected") return _terminal("rejected", { status: done.status || _statusOf(done.resp), polls: spent });
      throw _err("cmp/unexpected-arm", done.reason || "the resumed enrollment reached an unexpected state");
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
    resumePoll: resumePoll,
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
