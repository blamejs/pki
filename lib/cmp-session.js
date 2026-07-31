// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cmp.session implementation. The operator-facing @module pki.cmp home is
// lib/cmp-build.js; this file adds the @primitive pki.cmp.session block and re-exports the cmp message
// surface (build / transfer / wellKnownUrl / verify) so the whole pki.cmp namespace wires through here
// (index.js requires this file as `cmp`).
//
// pki.cmp.session -- the STATEFUL CMP enrollment-transaction orchestrator (the pki.acme.client analogue).
// It composes the shipped message layer (build / transfer / verify) into a single enroll(request): mint a
// stable transactionID, build + protect + transfer a request, VERIFY every response's protection BEFORE
// reading its body, chain the nonces (recipNonce echoes the peer's senderNonce, a fresh senderNonce per
// request) and the transactionID (RFC 9810 sec. 5.1.1 anti-replay / anti-interleave), interpret the
// CertResponse PKIStatus (grant -> extract the cert, waiting -> a bounded pollReq/pollRep loop, rejection
// -> a terminal verdict), and confirm (certConf -> pkiConf, unless implicitConfirm was granted). The
// single invariant is transfer -> verify (fail-closed) -> ONLY THEN read the body off the verdict.

var cmp = require("./cmp-verify");   // re-exports build / transfer / wellKnownUrl / verify (the whole message layer)
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var schemaCmp = require("./schema-cmp");
var csr = require("./schema-csr");
var guard = require("./guard-all");
var compositeSig = require("./composite-sig");
var constants = require("./constants");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var sleepUtil = require("./sleep");
var retryAfter = require("./http-retry-after");

var CmpError = frameworkError.CmpError;
function _err(code, message, cause) { return new CmpError(code, message, cause); }
var OID_IMPLICIT_CONFIRM = oid.byName("implicitConfirm");   // classify a granted implicitConfirm by its IMMUTABLE OID

// The certification-path build/validate engine, injected by path-validate (the crl/ocsp/cmp-verify seam) so
// the session can VALIDATE the issued leaf certificate's signature + chain -- x509.parse is structural only.
var _engine = null;
function setEngine(engine) { _engine = engine; }

// The signature algorithms whose OID conveys NO message hash -- EdDSA (the hash is the scheme) and the FIPS
// PQC signatures (ML-DSA / SLH-DSA, internally hashed). ONLY these may take the certConf SHA-256 + explicit
// hashAlg fallback (RFC 9810 sec. 5.3.18); any other indeterminate/non-signature AlgorithmIdentifier (e.g.
// rsaEncryption, an ML-KEM OID) is refused. Resolved to a dotted-OID set at load (never a runtime lookup).
var HASHLESS_SIG_OIDS = {};
(function () {
  var names = ["Ed25519", "Ed448", "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87"];
  ["sha2", "shake"].forEach(function (h) { ["128s", "128f", "192s", "192f", "256s", "256f"].forEach(function (s) { names.push("id-slh-dsa-" + h + "-" + s); }); });
  names.forEach(function (n) { var o = oid.byName(n); if (o) HASHLESS_SIG_OIDS[o] = 1; });
})();
// Hash-conveying signature algorithms -> the certConf hash, dispatched by the IMMUTABLE OID (never the mutable
// display name, which pki.oid.register can override). Resolved to a dotted-OID map at load.
var SIG_OID_TO_HASH = {};
[["sha256WithRSAEncryption", "SHA-256"], ["sha384WithRSAEncryption", "SHA-384"], ["sha512WithRSAEncryption", "SHA-512"],
  ["ecdsaWithSHA256", "SHA-256"], ["ecdsaWithSHA384", "SHA-384"], ["ecdsaWithSHA512", "SHA-512"]].forEach(function (row) {
  var o = oid.byName(row[0]); if (o) SIG_OID_TO_HASH[o] = row[1];
});
var OID_RSASSA_PSS = oid.byName("rsassaPss");
// Message-digest OID -> the WebCrypto digest name, for the RSASSA-PSS hashAlgorithm parameter -- dispatched by
// the IMMUTABLE OID (never oid.name, which pki.oid.register can rename). Resolved to a dotted-OID map at load.
var HASH_OID_TO_DIGEST = {};
[["sha256", "SHA-256"], ["sha384", "SHA-384"], ["sha512", "SHA-512"]].forEach(function (row) { var o = oid.byName(row[0]); if (o) HASH_OID_TO_DIGEST[o] = row[1]; });
// A composite signature's declared prehash (COMPOSITE_ALGS[oid].ph) -> the certConf hashAlg field value.
var COMPOSITE_PH_HASHALG = { "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512" };

var KNOWN_SESSION_OPTS = {
  url: 1, key: 1, cert: 1, mac: 1, trustAnchors: 1, intermediates: 1, recipient: 1, sender: 1,
  extraCerts: 1, implicitConfirm: 1, maxPolls: 1, maxTotalWait: 1, sleep: 1, time: 1,
  transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, pss: 1, digestAlgorithm: 1,
};

var DEFAULT_MAX_POLLS = 20;
var DEFAULT_MAX_TOTAL_WAIT = retryAfter.MAX_RETRY_AFTER_SECONDS;   // the shared retry-after ceiling (seconds)
var DEFAULT_CERT_REQ_ID = 0;   // the CRMF single-request certReqId when the caller supplies none (ir / cr / kur)
var P10CR_CERT_REQ_ID = -1;    // a PKCS#10 request has no CRMF id; a conforming cp identifies it with the -1 sentinel (RFC 9483)
var ENROLL_ARMS = { ir: 1, cr: 1, kur: 1, p10cr: 1 };   // the initial request arms enroll() accepts
// The response body arm each enrollment request is answered by (RFC 9810 sec. 5.3.2/5.3.4): ir->ip, cr/p10cr
// ->cp, kur->kup. A response of a DIFFERENT cert-response arm than the request is misrouted -- never confirmed.
var RESPONSE_ARM = { ir: "ip", cr: "cp", kur: "kup", p10cr: "cp" };

// PKIStatus codes (RFC 9810 sec. 5.2.3): 0 accepted, 1 grantedWithMods, 2 rejection, 3 waiting.
function _isGranted(code) { return code === 0 || code === 1; }

// certReqId equality across the encode side (a number or bigint in the request) and the decode side (a BigInt
// off the wire): compare as BigInts so two distinct large ids above 2^53 never collide under Number rounding.
function _certReqIdEq(a, b) { return a != null && b != null && BigInt(a) === BigInt(b); }

// Normalize a certificate-list option (the constructor + cmp.verify accept a lone Buffer / PEM OR an array) to
// an array the path engine requires; a copy so a caller's array is never mutated by the caPubs append.
function _asCertList(v) { return v == null ? [] : (Array.isArray(v) ? v.slice() : [v]); }

// The raw extraCerts (signer + intermediates) of an already-verified response, cached so a later leg that
// omits extraCerts can still rebuild the signer path. The bytes already parsed during verify, so this cannot throw.
function _responseExtraCerts(responseBytes) {
  var m = schemaCmp.parse(responseBytes);
  return Array.isArray(m.extraCerts) ? m.extraCerts.filter(Buffer.isBuffer) : [];
}

// Normalize a caller-supplied CRMF certReqId to the value the session echoes + matches, the SAME way
// crmf-sign._certReqId encodes it: a number or bigint is kept; a STRING (decimal or 0x-hex) is parsed via
// BigInt so a supported form ("5" / "0x5") is not silently replaced by the default; anything else -> `dflt`.
function _normalizeCertReqId(cid, dflt) {
  if (typeof cid === "bigint" || typeof cid === "number") return cid;
  if (typeof cid === "string") {
    try { return BigInt(cid); }
    catch (_e) { /* allow:swallow-unverified an invalid certReqId string fails closed at the cmp.build boundary; this best-effort normalize just does not pre-empt that typed error */ return dflt; }
  }
  return dflt;
}

// The hash inside RSASSA-PSS-params (the hashAlgorithm [0] AlgorithmIdentifier OID) -- for id-RSASSA-PSS the
// digest lives in the parameters, not the OID name (RFC 4055). Returns "SHA-256" / "SHA-384" / "SHA-512", or
// null when the params are absent / unreadable / name an unmapped hash (the caller then declares SHA-256).
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
        return HASH_OID_TO_DIGEST[asn1.read.oid(algSeq.children[0])] || null;   // by immutable OID, not oid.name
      }
    }
  } catch (_e) { /* allow:swallow-unverified a malformed PSS-params blob falls back to null -> the caller's declared-SHA-256 path; a display-hash inference never throws */ return null; }
  return null;
}

// The certConf certHash algorithm (RFC 9810 sec. 5.3.18): use the SAME hash the certificate signature uses.
// If the signatureAlgorithm OID conveys the hash (sha256WithRSAEncryption / ecdsaWithSHA384 / ...) use THAT
// hash and OMIT hashAlg. For id-RSASSA-PSS the hash is carried in the params, so decode it and likewise omit
// hashAlg. Only when the hash is genuinely not conveyed (Ed25519 / Ed448; ML-DSA / SLH-DSA) is SHA-256 used
// and DECLARED in the explicit hashAlg field so the CA recomputes certHash under the same stated hash.
function _certConfHash(certDer) {
  var sa;
  try { sa = x509.parse(certDer).signatureAlgorithm; }
  catch (e) { throw _err("cmp/bad-cert-response", "the issued certificate is unexpectedly unparseable at certConf", e); }   // unreachable: _leafOf already validated it; re-throw fail-closed
  // Dispatch by the IMMUTABLE signatureAlgorithm OID (never the mutable display name). A hashless SIGNATURE
  // (EdDSA / ML-DSA / SLH-DSA) -> SHA-256 + an explicit hashAlg; a hash-conveying signature -> its hash, no
  // hashAlg; id-RSASSA-PSS -> the hash from its parameters, no hashAlg.
  if (HASHLESS_SIG_OIDS[sa.oid]) return { digest: "SHA-256", hashAlg: "sha256" };
  // A composite signature (draft-ietf-lamps-pq-composite-sigs): compute certHash under the composite's own
  // declared PREHASH digest (COMPOSITE_ALGS[oid].ph -- SHA-256 / SHA-512) and DECLARE it in the explicit
  // hashAlg. A composite whose prehash is not a certConf-supported hash (SHAKE) falls back to SHA-256.
  var comp = compositeSig.COMPOSITE_ALGS[sa.oid];
  if (comp) { var ha = COMPOSITE_PH_HASHALG[comp.ph]; return ha ? { digest: comp.ph, hashAlg: ha } : { digest: "SHA-256", hashAlg: "sha256" }; }
  if (SIG_OID_TO_HASH[sa.oid]) return { digest: SIG_OID_TO_HASH[sa.oid], hashAlg: null };
  if (sa.oid === OID_RSASSA_PSS) {
    var pd = _pssDigest(sa.parameters);
    if (pd) return { digest: pd, hashAlg: null };
    throw _err("cmp/bad-cert-response", "the issued RSASSA-PSS certificate's hash cannot be resolved from its parameters (RFC 4055); the certConf hash is indeterminate");
  }
  // Any other AlgorithmIdentifier -- an unregistered OID, or a registered NON-signature / indeterminate one
  // (rsaEncryption, an ML-KEM OID, ...): the required certConf hash cannot be determined. Do NOT guess
  // SHA-256 (a wrong certHash the CA rejects); fail the transaction closed before confirming.
  throw _err("cmp/bad-cert-response", "the issued certificate's signature algorithm does not determine a certConf hash (an unrecognized or non-signature algorithm); the transaction is refused (RFC 9810 sec. 5.3.18)");
}

/**
 * @primitive  pki.cmp.session
 * @signature  pki.cmp.session(opts) -> session
 * @since      0.3.27
 * @status     experimental
 * @spec       RFC 9810, RFC 9811, RFC 9483
 * @related    pki.cmp.build, pki.cmp.verify, pki.cmp.transfer
 *
 * A stateful RFC 9810 CMP enrollment-transaction orchestrator -- the `pki.acme.client` analogue. It drives
 * an enrollment (`ir` / `cr` / `kur` / `p10cr`) end to end over the shared `pki.transport` (inject
 * `opts.transport`, else a fail-closed `pki.transport.https`), composing the shipped message layer
 * (`build` / `transfer` / `verify`). It mints a stable 128-bit `transactionID`, and on every request a
 * FRESH `senderNonce`, echoing the peer's last `senderNonce` back as `recipNonce` (RFC 9810 sec. 5.1.1
 * anti-replay / anti-interleave). The load-bearing invariant: every response is protection-VERIFIED and
 * nonce-bound to this exchange BEFORE its body is read -- so a meddler who flips an HTTP response cannot
 * forge a granted status or a poison `checkAfter`. A `waiting` status drives a bounded `pollReq`/`pollRep`
 * loop (an injectable sleeper, capped by `maxPolls` + `maxTotalWait`); a grant extracts the issued cert and
 * confirms it (`certConf` -> `pkiConf`, unless an `implicitConfirm` was granted). A verified `rejection` /
 * `error` or a poll-budget timeout is a terminal typed VERDICT the caller reads (`outcome`:
 * `issued` / `rejected` / `poll-timeout`); a tampered / unverifiable / desynchronized response is a
 * hard-stop `CmpError` throw. Exactly ONE protection flavor: `{ key, cert }` (signature) XOR `{ mac }`
 * (PBMAC1). A crypto-valid response is not enough -- the signer must chain to a supplied trust anchor
 * (signature) or the shared secret must match (MAC); a valid-but-untrusted response is a hard stop, so the
 * signature flavor REQUIRES `opts.trustAnchors` at construction. Returns a session with `enroll(request)`,
 * and read-only `transactionID` + `transcript`. The granted certificate must be valid X.509, carry the key
 * the request submitted (else it is a misrouted certificate the caller cannot use), and -- for the signature
 * flavor -- have its signature + chain validated to a supplied trust anchor before it is confirmed. The `certConf`
 * `certHash` uses the certificate's signature hash -- from the OID when it conveys one, or from the
 * RSASSA-PSS parameters when it does not, with `hashAlg` omitted; only a truly hashless signature
 * (Ed25519 / Ed448, ML-DSA / SLH-DSA) computes under SHA-256 and declares an explicit `hashAlg`
 * (RFC 9810 sec. 5.3.18). The `certReqId` echoed in `pollReq` / `certConf` and matched in every
 * `CertResponse` is the caller's CRMF request id (`request.ir.certReqId`, ...) when supplied, else the
 * single-request default. One transaction per session -- a second or concurrent `enroll`, or a batched
 * CRMF request, is refused (a local build error leaves the session retryable). The returned `chain` is the
 * issued leaf plus any authenticated `caPubs` the CA delivered (chain material, never trust anchors); a
 * server-generated (central key generation) private key is out of scope and the grant is refused.
 *
 * @opts
 *   - `url` -- REQUIRED: the CMP endpoint URL.
 *   - `key` + `cert` -- signature protection (the enrolling key pair + its cert), XOR `mac: { secret, ... }` -- PBMAC1 protection.
 *   - `trustAnchors` -- REQUIRED for the signature flavor: anchors to chain + authenticate the CA's response signer cert. `intermediates` -- extra chain pool.
 *   - `sender` / `recipient` -- header GeneralNames; default the signer cert's subject DN (sender) and a NULL-DN (recipient).
 *   - `implicitConfirm` -- request implicit confirmation (skip the certConf leg when the CA grants it).
 *   - `transport` -- injectable transport(request) -> {status, headers, body}; default pki.transport.https.
 *   - `tls` / `headers` / `timeout` / `maxResponseBytes` -- transport config + budgets.
 *   - `maxPolls` / `maxTotalWait` / `sleep` -- poll-loop budgets + an injectable sleeper; `time` -- verify-time clock.
 *   - `extraCerts` / `pss` / `digestAlgorithm` -- passed through to the request protection build.
 * @example
 *   var session = pki.cmp.session({ url: "https://ca.example/cmp", key: signerKeyPkcs8, cert: signerCertDer, trustAnchors: [cmpCaCert], transport: cmpTransport });
 *   var result = await session.enroll({ ir: { certTemplate: { subject: [{ commonName: "device-42" }], publicKey: signerSpki } } });
 *   if (result.outcome === "issued") { var leaf = result.certificate; }
 */
function session(opts) {
  if (opts == null) opts = {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("cmp/bad-input", "opts must be an object");
  Object.keys(opts).forEach(function (k) { if (!KNOWN_SESSION_OPTS[k]) throw _err("cmp/bad-input", "unknown session opts field " + JSON.stringify(k)); });
  if (typeof opts.url !== "string" || !opts.url) throw _err("cmp/bad-input", "opts.url (the CMP endpoint) is required");

  // EXACTLY ONE protection flavor -- signature (key + cert) XOR PBMAC1 (mac), mirroring cmp.build / cmp.verify.
  var isSig = opts.key != null || opts.cert != null;
  var isMac = opts.mac != null;
  if (isSig === isMac) throw _err("cmp/bad-input", "supply EXACTLY ONE protection flavor: { key, cert } (signature) OR { mac } (PBMAC1)");
  if (isSig && (opts.key == null || opts.cert == null)) throw _err("cmp/bad-input", "signature protection requires BOTH opts.key and opts.cert");
  // Signature protection can only be AUTHENTICATED against a trust anchor: without one, a response signer is
  // resolved from the message's own (unsigned) extraCerts and can be any self-signed key an attacker on the
  // transport supplies. Require trustAnchors up front so the session fails closed rather than advancing on a
  // crypto-valid-but-untrusted signer. A MAC (PBMAC1) session authenticates by the shared secret, not a cert.
  if (isSig) {
    var hasAnchors = opts.trustAnchors != null && !(Array.isArray(opts.trustAnchors) && opts.trustAnchors.length === 0);
    if (!hasAnchors) throw _err("cmp/bad-input", "signature protection requires opts.trustAnchors to authenticate the CA's response signer (RFC 9483 sec. 3.2)");
  }

  // Poll budgets, validated at construction (NaN / negative / over-max -> cmp/bad-input, never a disabled bound).
  var maxPolls = guard.limits.cap(opts.maxPolls, "opts.maxPolls", DEFAULT_MAX_POLLS, { E: _err, code: "cmp/bad-input", min: 1, max: 1000 });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "opts.maxTotalWait", DEFAULT_MAX_TOTAL_WAIT, { E: _err, code: "cmp/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = typeof opts.sleep === "function" ? opts.sleep : sleepUtil.sleep;

  // Transaction identity: mint ONE 128-bit transactionID (stable for the whole transaction), held here.
  var transactionID = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(16)));
  var lastPeerNonce = null;   // recipNonce for the NEXT request := the previous response's senderNonce
  var haveResponse = false;   // a response has been received -> every subsequent request MUST echo a recipNonce
  var cachedSignerCert = null;   // the CA's verified signature-protection signer cert, reused when a later leg omits extraCerts
  var cachedChain = [];   // the extraCerts (signer + intermediates) that validated it, so a later leg can rebuild the signer path
  var activeCertReqId = DEFAULT_CERT_REQ_ID;   // the certReqId of the in-flight enrollment; echoed in pollReq / certConf
  var expectedRespArm = "ip";   // the cert-response arm the in-flight enrollment must be answered by (RESPONSE_ARM)
  var requestedSpki = null;   // the SPKI DER of the key the enrollment requested; the issued cert MUST carry it
  var inFlight = false, completed = false, started = false;   // one transaction per session; `started` = a request may have hit the transport
  var transcript = [];

  // Sender / recipient routing (RFC 9810 sec. 5.1.1). The sender NAMES the requester: signature protection
  // defaults it to the signer cert's own subject DN; a MAC transaction (no cert) has no established name, so
  // it defaults to the NULL-DN (an empty RDNSequence). The recipient (the CA) defaults to the NULL-DN too --
  // the CA is addressed by the endpoint URL, not by a name we can assert. opts.sender / opts.recipient override.
  var NULL_DN = { directoryName: [] };
  var defaultSender = NULL_DN;
  if (isSig) {
    try { defaultSender = { directoryName: x509.parse(opts.cert).subject.bytes }; }
    catch (_e) { defaultSender = NULL_DN; }   // a malformed signer cert -> the sender falls back to a NULL-DN (driven by the unparseable-cert construction vector)
  }

  // The header the session OWNS on every request (transaction identity + routing), plus the protection opts.
  function _baseHeader(fresh) {
    var h = { transactionID: transactionID, senderNonce: fresh };
    // The first request carries no recipNonce; every FOLLOW-UP leg MUST echo the previous response's
    // senderNonce (RFC 9810 sec. 5.1.1). A prior response that omitted its senderNonce leaves nothing to
    // echo -- the anti-replay chain is broken, so fail closed rather than send an unchained request.
    if (haveResponse) {
      if (!Buffer.isBuffer(lastPeerNonce) || lastPeerNonce.length === 0) throw _err("cmp/bad-nonce", "the previous CMP response omitted its senderNonce, so this follow-up request cannot echo it as recipNonce (RFC 9810 sec. 5.1.1)");
      h.recipNonce = lastPeerNonce;
    }
    h.sender = opts.sender != null ? opts.sender : defaultSender;
    h.recipient = opts.recipient != null ? opts.recipient : NULL_DN;
    return h;
  }
  function _buildOpts() {
    var o = isSig ? { key: opts.key, cert: opts.cert } : { mac: opts.mac };
    if (opts.extraCerts != null) o.extraCerts = opts.extraCerts;
    if (opts.pss != null) o.pss = opts.pss;
    if (opts.digestAlgorithm != null) o.digestAlgorithm = opts.digestAlgorithm;
    return o;
  }
  function _verifyOpts(fresh, signerCertOverride, extraIntermediates) {
    // Verify the RESPONSE protection + bind it to THIS exchange via the opt-in echo checks. The CA's signer
    // cert is resolved from the response extraCerts (RFC 9483 sec. 3.3); trustAnchors chain it. A MAC response
    // verifies under the shared secret. transactionID + expectRecipNonce fail-close a mismatched response.
    var o = { transactionID: transactionID, expectRecipNonce: fresh };
    if (isMac) o.sharedSecret = opts.mac.secret;
    if (opts.trustAnchors != null) o.trustAnchors = opts.trustAnchors;
    var ints = _asCertList(opts.intermediates);
    if (Array.isArray(extraIntermediates)) ints = ints.concat(extraIntermediates);   // fallback: the cached signer chain
    if (ints.length) o.intermediates = ints;
    if (opts.time != null) o.time = opts.time;
    // An explicit signerCert takes ABSOLUTE precedence in cmp.verify, so it is passed ONLY as a fallback for a
    // response that cannot resolve its own signer -- never by default, else a clustered CA that rotates the
    // protection cert mid-transaction (a valid later cert in that leg's extraCerts) would verify under the wrong key.
    if (signerCertOverride != null) o.signerCert = signerCertOverride;
    return o;
  }
  function _transferOpts() {
    var o = {};
    ["transport", "tls", "headers", "timeout", "maxResponseBytes"].forEach(function (k) { if (opts[k] != null) o[k] = opts[k]; });
    return o;
  }

  // ONE leg: mint a fresh senderNonce, build+protect the request, transfer it, VERIFY the response BEFORE
  // reading its body (a !valid verdict is a HARD STOP throw), chain the peer nonce, record both directions.
  async function _send(bodySpec, arm) {
    var fresh = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(16)));
    var header = Object.assign(_baseHeader(fresh), ENROLL_ARMS[arm] && opts.implicitConfirm ? { generalInfo: [{ infoType: "implicitConfirm" }] } : {});
    var reqDer = await cmp.build({ header: header, body: bodySpec }, _buildOpts());
    transcript.push({ direction: "out", arm: arm, bytes: reqDer });
    started = true;   // the request is built; the transaction now engages the transport -> the session is consumed
    var res = await cmp.transfer(opts.url, reqDer, _transferOpts());
    var verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh));
    // Fallback: if a signature-flavor response could not resolve its OWN signer (a later leg that omitted
    // extraCerts once the recipient holds the cert, RFC 9483 sec. 3.3), retry with the signer AND the chain
    // material cached from an earlier leg -- the cached intermediates let the signer path rebuild to the anchor.
    // The response's own certs are preferred first, so a clustered CA's rotated cert still wins.
    if (verdict.valid !== true && isSig && cachedSignerCert != null && verdict.code === "cmp/signer-cert-not-found") {
      verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh, cachedSignerCert, cachedChain));
    }
    transcript.push({ direction: "in", arm: verdict.body ? verdict.body.arm : null, status: res.status, bytes: res.responseBytes, verdict: { valid: verdict.valid, trusted: verdict.trusted, code: verdict.code || null } });
    if (verdict.valid !== true) throw _err(verdict.code || "cmp/protection-failed", "the CMP response protection did not verify (" + (verdict.reason || "invalid") + ") -- the transaction is NOT advanced", null);
    // Cryptographically valid is NOT enough: the signer (signature flavor) must chain to a supplied trust
    // anchor, or the shared secret (MAC flavor) must match -- both surface as verdict.trusted. A valid-but-
    // untrusted response is an unauthenticated signer; fail closed rather than read a certificate off it.
    if (verdict.trusted !== true) throw _err(verdict.code || "cmp/untrusted-signer", "the CMP response protection verified but its signer is not trusted (it did not chain to a supplied trust anchor) -- the transaction is NOT advanced", null);
    lastPeerNonce = verdict.senderNonce;   // may be absent; _baseHeader enforces its presence before a follow-up leg
    haveResponse = true;
    // Refresh the cached signer + its validated chain material from EVERY verified signature response that
    // carried extraCerts -- the MOST RECENTLY authenticated cert + the intermediates that chained it (a
    // clustered CA may rotate its protection cert across legs) -- so a later leg that omits extraCerts falls
    // back to the current signer AND can rebuild its path. The verdict is already valid + trusted at this point.
    if (isSig && verdict.signer && Buffer.isBuffer(verdict.signer.cert)) {
      var extras = _responseExtraCerts(res.responseBytes);   // [signer, intermediates...]
      if (extras.length) { cachedSignerCert = verdict.signer.cert; cachedChain = extras; }
    }
    return verdict;
  }

  // Classify a verified response into a transaction transition. For ip/cp/kup, read the FIRST CertResponse
  // status; error carries a terminal PKIStatusInfo; pollRep drives the loop; any other arm is unexpected.
  function _classify(verdict) {
    var body = verdict.body || {};
    var arm = body.arm;
    if (arm === expectedRespArm) {
      // Select the CertResponse for OUR request by its certReqId (RFC 9810 sec. 5.3.4) -- never blindly
      // response[0], so a batch / misrouted response for a different request id is not read as ours.
      var responses = (body.decoded && body.decoded.response) || [];
      var resp = null;
      for (var ri = 0; ri < responses.length; ri++) { if (_certReqIdEq(responses[ri].certReqId, activeCertReqId)) { resp = responses[ri]; break; } }
      if (!resp) return { state: "unexpected", reason: "a " + arm + " carried no CertResponse for certReqId " + activeCertReqId };
      var code = resp.status && resp.status.status ? resp.status.status.code : null;
      if (_isGranted(code)) return { state: "granted", resp: resp, caPubs: body.decoded.caPubs };
      if (code === 3) return { state: "waiting", resp: resp };
      if (code === 2) return { state: "rejected", resp: resp };
      return { state: "unexpected", reason: "a " + arm + " CertResponse status code " + code + " has no transition" };
    }
    if (arm === "error") return { state: "rejected", status: body.decoded && body.decoded.pKIStatusInfo };
    if (arm === "pollRep") return { state: "pollRep", entries: body.decoded };
    if (arm === "pkiconf") return { state: "pkiconf" };
    return { state: "unexpected", reason: "response arm " + JSON.stringify(arm) + " has no transition in an enrollment transaction" };
  }

  function _statusOf(resp) { return resp && resp.status ? resp.status : null; }

  // A granted implicitConfirm in the RESPONSE header's generalInfo (RFC 9810 sec. 5.1.1.1) -- classified by
  // the IMMUTABLE id-it OID, never the mutable display name.
  function _implicitConfirmGranted(header) {
    var gi = header && header.generalInfo;
    if (!Array.isArray(gi)) return false;
    for (var i = 0; i < gi.length; i++) { if (gi[i] && gi[i].type === OID_IMPLICIT_CONFIRM) return true; }
    return false;
  }

  function _terminal(outcome, extra) {
    // Every terminal outcome is reached only through _send, which throws unless the response was both valid
    // AND trusted -- so a returned verdict is always authenticated (trusted:true), surfaced for the caller.
    return Object.assign({
      outcome: outcome, certificate: null, chain: [], status: null, trusted: true,
      confirmed: false, implicitConfirm: false, transactionID: Buffer.from(transactionID),   // a copy: mutating it must not corrupt the session identity
      polls: 0, transcript: transcript,
    }, extra);
  }

  // The bounded pollReq/pollRep loop (RFC 9810 sec. 5.3.22): sleep >= checkAfter each round, re-classify a
  // non-pollRep response as an initial response, END as poll-timeout when maxPolls / maxTotalWait is hit.
  async function _pollLoop(lastWaitingResp) {
    var polls = 0, waited = 0, lastStatus = _statusOf(lastWaitingResp);
    for (;;) {
      if (polls >= maxPolls || waited > maxTotalWait) return { timeout: true, polls: polls, status: lastStatus };
      var verdict = await _send({ pollReq: [{ certReqId: activeCertReqId }] }, "pollReq");
      polls += 1;
      var t = _classify(verdict);
      if (t.state === "pollRep") {
        // Select the pollRep entry for OUR request by certReqId (RFC 9810 sec. 5.3.22) -- never entry zero,
        // so an unrelated entry's checkAfter cannot stall us and a pollRep that never mentions our request
        // (its entry absent) is a misrouted response, not a silent zero-delay re-poll.
        var entries = t.entries || [];
        var entry = null;
        for (var pe = 0; pe < entries.length; pe++) { if (_certReqIdEq(entries[pe].certReqId, activeCertReqId)) { entry = entries[pe]; break; } }
        if (!entry) return { done: { state: "unexpected", reason: "a pollRep carried no entry for certReqId " + activeCertReqId }, polls: polls, header: verdict.header };
        var checkAfter = typeof entry.checkAfter === "number" ? entry.checkAfter : 0;
        waited += checkAfter;
        if (waited > maxTotalWait) return { timeout: true, polls: polls, status: lastStatus };
        // Do NOT sleep after the FINAL permitted poll: this pollRep answered poll number maxPolls, so the
        // budget is already spent -- sleeping its checkAfter (up to a year) before the loop-top count check
        // would defeat the poll-count bound. Detect exhaustion here, before scheduling the delay.
        if (polls >= maxPolls) return { timeout: true, polls: polls, status: lastStatus };
        await sleep(checkAfter * constants.TIME.seconds(1));
        continue;
      }
      if (t.state === "waiting") { lastStatus = _statusOf(t.resp); continue; }   // still processing -> keep polling
      // granted / rejected / unexpected -> advance out of the loop, carrying the GRANTING response's header
      // (an implicitConfirm grant / a fresh nonce lives in THIS response, not the initial waiting one).
      return { done: t, polls: polls, header: verdict.header };
    }
  }

  // Confirm delivery (RFC 9810 sec. 5.1.1.1 / 5.3.18): if implicitConfirm was granted, END; else send a
  // certConf (certHash under the cert's signature hash) and require a verified pkiConf, else cmp/bad-confirmation.
  async function _confirm(certDer, header) {
    // Honor an implicitConfirm grant ONLY when the caller REQUESTED it (opts.implicitConfirm): implicit
    // confirmation is negotiated (RFC 9810 sec. 5.1.1.1), so an UNSOLICITED implicitConfirm from a
    // nonconforming server is ignored -- the session performs the explicit certConf the caller expects.
    if (opts.implicitConfirm && _implicitConfirmGranted(header)) return { confirmed: true, implicit: true };
    var h = _certConfHash(certDer);
    var certHash = Buffer.from(await webcrypto.webcrypto.subtle.digest(h.digest, certDer));
    var cs = { certHash: certHash, certReqId: activeCertReqId };
    if (h.hashAlg) cs.hashAlg = h.hashAlg;   // declare the hash for a sig alg whose OID does not convey it (PSS / EdDSA / ML-DSA)
    var verdict = await _send({ certConf: [cs] }, "certConf");
    if (!verdict.body || verdict.body.arm !== "pkiconf") throw _err("cmp/bad-confirmation", "expected a pkiConf acknowledgement to the certConf but got " + JSON.stringify(verdict.body && verdict.body.arm) + " (RFC 9810 sec. 5.3.18)");
    return { confirmed: true, implicit: false };
  }

  function _leafOf(resp) {
    var ckp = resp && resp.certifiedKeyPair;
    var cert = ckp && ckp.certificate;
    if (!Buffer.isBuffer(cert)) throw _err("cmp/unexpected-arm", "a granted CertResponse carried no plain issued certificate (an encryptedCert form is out of enrollment v1 scope) (RFC 9810 sec. 5.3.4)");
    // A central-key-generation privateKey (the CA generated the key, delivered encrypted) is out of a
    // client-key enrollment session's scope: the caller submitted the key + its proof of possession, so the
    // session would otherwise confirm a certificate whose private key it discarded -- a result the caller cannot use.
    if (ckp.privateKey != null) throw _err("cmp/unexpected-arm", "a granted CertResponse carried a server-generated privateKey (central key generation is out of enrollment v1 scope; a session enrolls a client-generated key) (RFC 9810 sec. 5.3.4)");
    // The CMP parser surfaces certifiedKeyPair.certificate as opaque bytes (any non-empty SEQUENCE); a
    // non-conformant / hostile CA could deliver bytes that are not a real X.509 certificate. Validate them
    // BEFORE confirming, so the session never returns outcome:issued with a value pki.schema.x509.parse rejects.
    var parsed;
    try { parsed = x509.parse(cert); }
    catch (e) { throw _err("cmp/bad-cert-response", "the granted CertResponse's certificate is not a valid X.509 certificate", e); }
    // For a client-generated-key enrollment, the issued cert MUST carry the key the request submitted -- else
    // it is a misrouted certificate the caller holds no private key for. Compare the SPKI bytes (RFC 4211).
    if (requestedSpki != null && !parsed.subjectPublicKeyInfo.bytes.equals(requestedSpki)) {
      throw _err("cmp/bad-cert-response", "the issued certificate's public key does not match the requested key -- a misrouted certificate the caller has no private key for");
    }
    return cert;
  }

  // The SPKI DER the enrollment requested, for the issued-cert key match: an ir/cr/kur certTemplate.publicKey
  // (a SPKI Buffer), or a p10cr CSR's subjectPublicKeyInfo. null when the form is not a plain SPKI/CSR (the
  // build path validates the key separately) or the CSR is unparseable (which fails at the build boundary).
  function _extractRequestedSpki(arm, armSpec) {
    if (arm === "p10cr") {
      if (!Buffer.isBuffer(armSpec) && !(armSpec instanceof Uint8Array)) return null;
      try { return csr.parse(armSpec).subjectPublicKeyInfo.bytes; }
      catch (_e) { /* allow:swallow-unverified an unparseable p10cr CSR fails closed at the cmp.build boundary; the key-match is simply not applied to a request that never sends */ return null; }
    }
    var pk = armSpec && armSpec.certTemplate ? armSpec.certTemplate.publicKey : null;
    if (Buffer.isBuffer(pk)) return pk;
    if (pk instanceof Uint8Array) return Buffer.from(pk);
    return null;
  }

  // Validate the issued leaf's SIGNATURE + chain (pki.schema.x509.parse is structural only, so a corrupted
  // signature would otherwise be confirmed). Signature flavor only -- it supplies the trust anchors the leaf
  // chains to; a MAC session has no anchor for the issuing CA, and the MAC authenticates the response instead.
  // The pool is the caller's intermediates plus the granting response's (validated) caPubs.
  async function _validateLeaf(leaf, caPubs) {
    if (!isSig || _engine == null) return;
    // Normalize the singleton certificate-list forms the constructor + cmp.verify accept (a lone Buffer / PEM)
    // to arrays, as the path engine requires -- else a single-cert trustAnchors throws and a single-cert
    // intermediates is silently dropped from the leaf pool (a false chain failure).
    var pool = _asCertList(opts.intermediates);
    if (Array.isArray(caPubs)) caPubs.forEach(function (c) { if (Buffer.isBuffer(c)) pool.push(c); });
    // The issued leaf may be signed by the CMP protection signer OR its issuing intermediate, delivered only in
    // the response's extraCerts. Include the verified signer AND its cached chain material (the intermediates
    // that authenticated it) in the pool so the leaf builds a path -- pool material, still re-validated to the
    // anchor, never trust anchors themselves.
    if (Buffer.isBuffer(cachedSignerCert)) pool.push(cachedSignerCert);
    cachedChain.forEach(function (c) { if (Buffer.isBuffer(c)) pool.push(c); });
    var res;
    try { res = await _engine.build(leaf, { trustAnchors: _asCertList(opts.trustAnchors), intermediates: pool, validate: true, time: opts.time != null ? opts.time : new Date() }); }
    catch (e) {
      if (e && e.code === "path/bad-input") throw _err("cmp/bad-input", "invalid trust / validation options for issued-certificate validation: " + (e.message || e), e);
      throw _err("cmp/bad-cert-response", "the issued certificate could not be validated to a supplied trust anchor", e);
    }
    if (!res || res.valid !== true) throw _err("cmp/bad-cert-response", "the issued certificate did not validate to a supplied trust anchor (its signature or chain is invalid) (RFC 5280 sec. 6.1)");
  }

  async function _finish(granted, header) {
    var leaf = _leafOf(granted.resp);
    // The returned chain is the issued leaf followed by the granting response's authenticated caPubs (the
    // issuer certs the CA delivered, RFC 9810 sec. 5.3.4) -- surfaced so a caller whose intermediate arrives
    // ONLY in the CMP response can assemble the full chain. They are chain material, NOT trust anchors. The CMP
    // parser surfaces each caPubs entry as a raw sequence, so validate every one as X.509 BEFORE the certConf
    // acknowledges the grant -- the returned chain must never carry bytes pki.schema.x509.parse rejects.
    var chain = [leaf];
    if (Array.isArray(granted.caPubs)) {
      granted.caPubs.forEach(function (c) {
        if (!Buffer.isBuffer(c)) return;
        try { x509.parse(c); }
        catch (e) { throw _err("cmp/bad-cert-response", "a caPubs certificate in the granting response is not a valid X.509 certificate", e); }
        chain.push(c);
      });
    }
    await _validateLeaf(leaf, granted.caPubs);   // verify the leaf's signature + chain BEFORE confirming it
    var conf = await _confirm(leaf, header);
    return _terminal("issued", {
      certificate: leaf, chain: chain, status: _statusOf(granted.resp),
      confirmed: conf.confirmed, implicitConfirm: conf.implicit, polls: granted.polls || 0,
    });
  }

  // The transaction driver: build the initial request arm, send it, then poll / confirm / terminate.
  async function enroll(request) {
    // One transaction per session (RFC 9810: one transactionID per transaction). A second or concurrent
    // enroll would reuse this transaction's transactionID / nonce chain / certReqId -- a replay or a corrupted
    // interleave -- so it is refused. The request-shape checks run BEFORE the transaction is marked in-flight,
    // so a malformed-request call does not consume the session and the caller may retry with a valid request.
    if (completed || inFlight) throw _err("cmp/bad-input", "this pki.cmp.session transaction is already " + (completed ? "completed" : "in flight") + "; create a new session per enrollment (RFC 9810 sec. 5.1.1: one transactionID per transaction)");
    if (!request || typeof request !== "object" || Buffer.isBuffer(request)) throw _err("cmp/bad-input", "enroll(request) requires a body spec object { ir | cr | kur | p10cr }");
    var arms = Object.keys(request).filter(function (k) { return request[k] != null; });
    if (arms.length !== 1 || !ENROLL_ARMS[arms[0]]) {
      throw _err("cmp/bad-input", "enroll(request) must carry EXACTLY ONE enrollment arm (ir / cr / kur / p10cr)");
    }
    // A batched CRMF request ({ messages: [...] }) asks for several certificates in one message; this session
    // drives ONE request (single transactionID, one certReqId, one certConf), so a batch is refused rather than
    // silently confirming only the first CertResponse and leaving the rest unprocessed. Submit one per session.
    var armSpec = request[arms[0]];
    if (armSpec && typeof armSpec === "object" && !Buffer.isBuffer(armSpec) && armSpec.messages != null) {
      throw _err("cmp/bad-input", "a batched CRMF request ({ messages: [...] }) is not supported by a session -- submit one certificate request per pki.cmp.session");
    }
    // The session enrolls a CLIENT-submitted key: an ir / cr / kur MUST carry certTemplate.publicKey (a p10cr
    // carries it in the CSR). A keyless request (e.g. raVerified POP with no publicKey, or central key
    // generation) is refused -- else the session would confirm an arbitrary issued key it can neither match
    // to a submitted key nor return a private key for. Checked before the transaction engages the transport.
    var reqSpki = _extractRequestedSpki(arms[0], armSpec);
    if (arms[0] !== "p10cr" && reqSpki == null) {
      throw _err("cmp/bad-input", "an ir / cr / kur enrollment must submit certTemplate.publicKey -- a session enrolls a client-generated key (a raVerified keyless request or central key generation is not supported)");
    }
    inFlight = true;
    try {
      expectedRespArm = RESPONSE_ARM[arms[0]];   // ir->ip, cr/p10cr->cp, kur->kup: the arm this request must be answered by
      // The certReqId the session echoes in pollReq / certConf and matches in every CertResponse: the caller's
      // CRMF request id (ir / cr / kur) when supplied, else the arm default -- a p10cr has no CRMF id, so a
      // conforming cp identifies it with the -1 sentinel (RFC 9483), while ir / cr / kur default to 0.
      var cid = (typeof armSpec === "object" && !Buffer.isBuffer(armSpec)) ? armSpec.certReqId : undefined;
      activeCertReqId = _normalizeCertReqId(cid, arms[0] === "p10cr" ? P10CR_CERT_REQ_ID : DEFAULT_CERT_REQ_ID);
      requestedSpki = reqSpki;   // the key the issued cert must carry (RFC 4211 key match)
      var initial = await _send(request, arms[0]);
      var t = _classify(initial);
      var grantHeader = initial.header;   // the header of the response that produced the terminal classification `t`
      var pollCount = 0;
      if (t.state === "waiting") {
        var polled = await _pollLoop(t.resp);
        pollCount = polled.polls;
        if (polled.timeout) return _terminal("poll-timeout", { status: polled.status, polls: pollCount });
        t = polled.done;
        grantHeader = polled.header;   // the GRANTING (post-poll) response's header -- where an implicitConfirm grant lives
        t.polls = pollCount;
      }
      if (t.state === "granted") { var r = await _finish({ resp: t.resp, caPubs: t.caPubs, polls: pollCount }, grantHeader); r.polls = pollCount; return r; }
      if (t.state === "rejected") return _terminal("rejected", { status: t.status || _statusOf(t.resp), polls: pollCount });
      throw _err("cmp/unexpected-arm", t.reason || "the enrollment transaction reached an unexpected state");
    } finally {
      inFlight = false;
      // Consume the session only if a request may have reached the transport. A purely LOCAL failure (a build
      // error before the first transfer -- e.g. a missing CRMF template) leaves the session retryable.
      completed = started;
    }
  }

  return {
    enroll: enroll,
    get transactionID() { return Buffer.from(transactionID); },   // a copy: a caller mutating it must not desync the transaction
    get transcript() { return transcript; },
  };
}

module.exports = {
  build: cmp.build,
  transfer: cmp.transfer,
  wellKnownUrl: cmp.wellKnownUrl,
  verify: cmp.verify,
  session: session,
  setEngine: setEngine,   // @internal -- path-validate injects the path build/validate engine (issued-leaf validation)
};
