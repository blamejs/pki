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
var oid = require("./oid");
var x509 = require("./schema-x509");
var guard = require("./guard-all");
var constants = require("./constants");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var sleepUtil = require("./sleep");
var retryAfter = require("./http-retry-after");

var CmpError = frameworkError.CmpError;
function _err(code, message, cause) { return new CmpError(code, message, cause); }
var OID_IMPLICIT_CONFIRM = oid.byName("implicitConfirm");   // classify a granted implicitConfirm by its IMMUTABLE OID

var KNOWN_SESSION_OPTS = {
  url: 1, key: 1, cert: 1, mac: 1, trustAnchors: 1, intermediates: 1, recipient: 1, sender: 1,
  extraCerts: 1, implicitConfirm: 1, maxPolls: 1, maxTotalWait: 1, sleep: 1, time: 1,
  transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, pss: 1, digestAlgorithm: 1,
};

var DEFAULT_MAX_POLLS = 20;
var DEFAULT_MAX_TOTAL_WAIT = retryAfter.MAX_RETRY_AFTER_SECONDS;   // the shared retry-after ceiling (seconds)
var DEFAULT_CERT_REQ_ID = 0;   // the enrollment single-request certReqId when the caller supplies none (RFC 4210/9810)
var ENROLL_ARMS = { ir: 1, cr: 1, kur: 1, p10cr: 1 };   // the initial request arms enroll() accepts

// PKIStatus codes (RFC 9810 sec. 5.2.3): 0 accepted, 1 grantedWithMods, 2 rejection, 3 waiting.
function _isGranted(code) { return code === 0 || code === 1; }

// certReqId equality across the encode side (a JS number in the request) and the decode side (a BigInt off
// the wire): compare as Numbers -- a certReqId is a small request index, never near the safe-integer ceiling.
function _certReqIdEq(a, b) { return a != null && Number(a) === Number(b); }

// The certConf certHash algorithm (RFC 9810 sec. 5.3.18): if the issued cert's signatureAlgorithm OID conveys
// the hash (sha256WithRSAEncryption / ecdsaWithSHA384 / ...), compute certHash under THAT hash and OMIT the
// hashAlg field (the RFC requires it absent then). If the OID does NOT convey the hash (id-RSASSA-PSS, whose
// hash lives in the params; Ed25519 / Ed448; ML-DSA / SLH-DSA), compute under SHA-256 and DECLARE it in the
// explicit hashAlg field so the CA recomputes certHash under the same stated hash rather than guessing.
function _certConfHash(certDer) {
  var name;
  try { name = x509.parse(certDer).signatureAlgorithm.name || ""; } catch (_e) { name = ""; }
  var m = /sha-?(256|384|512)/i.exec(name);
  if (m) return { digest: "SHA-" + m[1], hashAlg: null };
  return { digest: "SHA-256", hashAlg: "sha256" };
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
 * and read-only `transactionID` + `transcript`. The `certConf` `certHash` uses the issued cert's signature
 * hash when the algorithm OID conveys it; for a PSS / Ed25519 / Ed448 / ML-DSA cert (whose OID does not) it
 * is computed under SHA-256 and declared in the explicit `hashAlg` field (RFC 9810 sec. 5.3.18). The
 * `certReqId` echoed in `pollReq` / `certConf` and matched in every `CertResponse` is the caller's CRMF
 * request id (`request.ir.certReqId`, ...) when supplied, else the single-request default.
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
  var activeCertReqId = DEFAULT_CERT_REQ_ID;   // the certReqId of the in-flight enrollment; echoed in pollReq / certConf
  var transcript = [];

  // Sender / recipient routing (RFC 9810 sec. 5.1.1). The sender NAMES the requester: signature protection
  // defaults it to the signer cert's own subject DN; a MAC transaction (no cert) has no established name, so
  // it defaults to the NULL-DN (an empty RDNSequence). The recipient (the CA) defaults to the NULL-DN too --
  // the CA is addressed by the endpoint URL, not by a name we can assert. opts.sender / opts.recipient override.
  var NULL_DN = { directoryName: [] };
  var defaultSender = NULL_DN;
  if (isSig) { try { defaultSender = { directoryName: x509.parse(opts.cert).subject.bytes }; } catch (_e) { defaultSender = NULL_DN; } }

  // The header the session OWNS on every request (transaction identity + routing), plus the protection opts.
  function _baseHeader(fresh) {
    var h = { transactionID: transactionID, senderNonce: fresh };
    if (lastPeerNonce != null) h.recipNonce = lastPeerNonce;
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
  function _verifyOpts(fresh) {
    // Verify the RESPONSE protection + bind it to THIS exchange via the opt-in echo checks. The CA's signer
    // cert is resolved from the response extraCerts (RFC 9483 sec. 3.3); trustAnchors chain it. A MAC response
    // verifies under the shared secret. transactionID + expectRecipNonce fail-close a mismatched response.
    var o = { transactionID: transactionID, expectRecipNonce: fresh };
    if (isMac) o.sharedSecret = opts.mac.secret;
    if (opts.trustAnchors != null) o.trustAnchors = opts.trustAnchors;
    if (opts.intermediates != null) o.intermediates = opts.intermediates;
    if (opts.time != null) o.time = opts.time;
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
    var res = await cmp.transfer(opts.url, reqDer, _transferOpts());
    var verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh));
    transcript.push({ direction: "in", arm: verdict.body ? verdict.body.arm : null, status: res.status, bytes: res.responseBytes, verdict: { valid: verdict.valid, trusted: verdict.trusted, code: verdict.code || null } });
    if (verdict.valid !== true) throw _err(verdict.code || "cmp/protection-failed", "the CMP response protection did not verify (" + (verdict.reason || "invalid") + ") -- the transaction is NOT advanced", null);
    // Cryptographically valid is NOT enough: the signer (signature flavor) must chain to a supplied trust
    // anchor, or the shared secret (MAC flavor) must match -- both surface as verdict.trusted. A valid-but-
    // untrusted response is an unauthenticated signer; fail closed rather than read a certificate off it.
    if (verdict.trusted !== true) throw _err(verdict.code || "cmp/untrusted-signer", "the CMP response protection verified but its signer is not trusted (it did not chain to a supplied trust anchor) -- the transaction is NOT advanced", null);
    lastPeerNonce = verdict.senderNonce;
    return verdict;
  }

  // Classify a verified response into a transaction transition. For ip/cp/kup, read the FIRST CertResponse
  // status; error carries a terminal PKIStatusInfo; pollRep drives the loop; any other arm is unexpected.
  function _classify(verdict) {
    var body = verdict.body || {};
    var arm = body.arm;
    if (arm === "ip" || arm === "cp" || arm === "kup") {
      // Select the CertResponse for OUR request by its certReqId (RFC 9810 sec. 5.3.4) -- never blindly
      // response[0], so a batch / misrouted response for a different request id is not read as ours.
      var responses = (body.decoded && body.decoded.response) || [];
      var resp = null;
      for (var ri = 0; ri < responses.length; ri++) { if (_certReqIdEq(responses[ri].certReqId, activeCertReqId)) { resp = responses[ri]; break; } }
      if (!resp) return { state: "unexpected", reason: "a " + arm + " carried no CertResponse for certReqId " + activeCertReqId };
      var code = resp.status && resp.status.status ? resp.status.status.code : null;
      if (_isGranted(code)) return { state: "granted", resp: resp };
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
      confirmed: false, implicitConfirm: false, transactionID: transactionID,
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
        var entry = t.entries && t.entries[0];
        var checkAfter = entry && typeof entry.checkAfter === "number" ? entry.checkAfter : 0;
        waited += checkAfter;
        if (waited > maxTotalWait) return { timeout: true, polls: polls, status: lastStatus };
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
    if (_implicitConfirmGranted(header)) return { confirmed: true, implicit: true };
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
    return cert;
  }

  async function _finish(granted, header) {
    var leaf = _leafOf(granted.resp);
    var conf = await _confirm(leaf, header);
    return _terminal("issued", {
      certificate: leaf, chain: [leaf], status: _statusOf(granted.resp),
      confirmed: conf.confirmed, implicitConfirm: conf.implicit, polls: granted.polls || 0,
    });
  }

  // The transaction driver: build the initial request arm, send it, then poll / confirm / terminate.
  async function enroll(request) {
    if (!request || typeof request !== "object" || Buffer.isBuffer(request)) throw _err("cmp/bad-input", "enroll(request) requires a body spec object { ir | cr | kur | p10cr }");
    var arms = Object.keys(request).filter(function (k) { return request[k] != null; });
    if (arms.length !== 1 || !ENROLL_ARMS[arms[0]]) {
      throw _err("cmp/bad-input", "enroll(request) must carry EXACTLY ONE enrollment arm (ir / cr / kur / p10cr)");
    }
    // The certReqId the session echoes in pollReq / certConf and matches in every CertResponse: the caller's
    // CRMF request id (ir / cr / kur) when supplied, else the single-request default. p10cr carries no CRMF id.
    var armSpec = request[arms[0]];
    activeCertReqId = (armSpec && typeof armSpec === "object" && !Buffer.isBuffer(armSpec) && armSpec.certReqId != null) ? Number(armSpec.certReqId) : DEFAULT_CERT_REQ_ID;
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
    if (t.state === "granted") { var r = await _finish({ resp: t.resp, polls: pollCount }, grantHeader); r.polls = pollCount; return r; }
    if (t.state === "rejected") return _terminal("rejected", { status: t.status || _statusOf(t.resp), polls: pollCount });
    throw _err("cmp/unexpected-arm", t.reason || "the enrollment transaction reached an unexpected state");
  }

  return {
    enroll: enroll,
    get transactionID() { return transactionID; },
    get transcript() { return transcript; },
  };
}

module.exports = {
  build: cmp.build,
  transfer: cmp.transfer,
  wellKnownUrl: cmp.wellKnownUrl,
  verify: cmp.verify,
  session: session,
};
