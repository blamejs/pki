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
var OID_RSA_ENCRYPTION = oid.byName("rsaEncryption");
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
  acceptCert: 1, senderKID: 1, recipKID: 1, expectedSender: 1,
};

// The read-only transcript retains at most this many responses' worth of payload bytes (a response is bounded by
// the transport's maxResponseBytes). Bounding it PROPORTIONALLY to the per-response cap keeps the ceiling above
// any single legitimate response while still preventing a polling loop from multiplying a padded-response flood
// across legs into memory exhaustion; a tightened maxResponseBytes tightens the transcript ceiling in step.
var TRANSCRIPT_RETAIN_RESPONSES = 2;
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
// The PKIStatus name surfaced to an acceptance policy so it can distinguish a clean grant from a modified one.
var PKI_STATUS_NAMES = { 0: "accepted", 1: "grantedWithMods", 2: "rejection", 3: "waiting" };

// certReqId equality across the encode side (a number or bigint in the request) and the decode side (a BigInt
// off the wire): compare as BigInts so two distinct large ids above 2^53 never collide under Number rounding.
function _certReqIdEq(a, b) { return a != null && b != null && BigInt(a) === BigInt(b); }

// Normalize a certificate-list option (the constructor + cmp.verify accept a lone Buffer / PEM OR an array) to
// an array the path engine requires; a copy so a caller's array is never mutated by the caPubs append.
function _asCertList(v) { return v == null ? [] : (Array.isArray(v) ? v.slice() : [v]); }

// Append session-supplied pool material (a CA-delivered caPubs, a cached protection-signer chain part-derived
// from the response's UNSIGNED extraCerts) to a `base` pool (the caller's OWN intermediates) up to the path
// builder's candidate ceiling, deduped against each other AND the base's Buffer entries so a copy of an existing
// candidate never spends a slot. The base is never truncated (if it alone exceeds the ceiling, that is a genuine
// config error path.build reports). So neither a legitimate caPubs nor a meddler's extraCerts flood can push a
// valid caller pool over the ceiling and fail an otherwise-valid grant. Used for BOTH the response signer path
// (cmp.verify) and the issued-leaf path (path.build), the two places session material joins a caller pool.
function _boundedPool(base, added) {
  // Dedup the BASE (the priority pool) FIRST: duplicate copies would otherwise inflate its length, drive the
  // remaining room to zero, and evict genuinely needed added material even though the DISTINCT candidate count is
  // small (path.build dedups internally, so dropping exact duplicates is behavior-preserving). An uncanonicalizable
  // entry is kept as-is (path.build judges it) and cannot dedup an added cert. The base holds the priority material
  // (a signed response's OWN delivered issuers + the cached chain, or the grant's caPubs) so it is never truncated;
  // the added caller pool fills the remaining room to the candidate ceiling.
  var ceiling = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES;
  var seen = Object.create(null), distinctBase = [];
  base.forEach(function (c) { var k = _certIdentity(c); if (k == null) { distinctBase.push(c); return; } if (!seen[k]) { seen[k] = 1; distinctBase.push(c); } });
  var room = ceiling - distinctBase.length;
  if (room <= 0) return distinctBase;
  var useful = [];
  added.forEach(function (c) { var k = _certIdentity(c); if (k != null && seen[k]) return; if (k != null) seen[k] = 1; useful.push(c); });
  return distinctBase.concat(useful.slice(0, room));
}
// A canonical byte identity for a certificate in ANY form path.build accepts -- a DER Buffer, a PEM string, or
// an already-parsed certificate object -- so a caller intermediate supplied as PEM or parsed still dedups against
// a byte-identical DER caPubs / cached certificate and does not spend a scarce candidate slot on a copy. The
// identity is the tbsCertificate bytes PLUS the signature (mirroring cmp.verify's _certKey): a meddler controls
// the unsigned extraCerts ordering, so a corrupted-signature copy sharing a valid issuer's TBS must NOT collapse
// onto it and evict the valid one. Returns null when the identity cannot be derived; a NON-deduped entry is safe
// (a redundant slot), a wrong merge (dropping a distinct or the only valid certificate) is not.
function _certIdentity(cert) {
  try {
    var p = (cert && Buffer.isBuffer(cert.tbsBytes)) ? cert : x509.parse(cert);   // x509.parse accepts a DER Buffer OR a PEM string
    if (!p || !Buffer.isBuffer(p.tbsBytes)) return null;
    return p.tbsBytes.toString("base64") + "|" + (p.signatureValue && p.signatureValue.bytes ? p.signatureValue.bytes.toString("base64") : "");
  } catch (_e) { return null; }
}

// A canonical identity for a SubjectPublicKeyInfo: the algorithm OID + the AlgorithmIdentifier parameters +
// the raw subjectPublicKey BIT STRING. The parameters ARE part of the key identity (an EC curve OID, an
// RSASSA-PSS constraint set) and are kept -- EXCEPT for rsaEncryption, whose parameters are NULL or omitted,
// both naming the same key. So the issued-cert key-match compares KEYS (with their constraints), not byte
// encodings, and neither rejects an equivalent rsaEncryption re-encoding nor accepts a constraint-changed key.
function _spkiKeyIdentity(spkiDer) {
  var node = asn1.decode(spkiDer);   // SEQUENCE { AlgorithmIdentifier { OID, params? }, BIT STRING }
  var algId = node.children[0];
  var algOid = asn1.read.oid(algId.children[0]);
  var pn = algId.children[1];
  var params;
  if (algOid === OID_RSA_ENCRYPTION) {
    // rsaEncryption parameters MUST be absent or a NULL (RFC 3279 sec. 2.3.1). Normalize ONLY those two
    // equivalent forms to "" so a NULL-vs-omitted re-encoding matches. ANY other value (a malformed empty OCTET
    // STRING the parser/importer may tolerate, or a changed parameter) keeps its bytes -- so a parameter-changed
    // certificate a stricter consumer rejects gets a DISTINCT identity and the key-match refuses it.
    params = (pn == null || _isDerNull(pn)) ? "" : pn.bytes.toString("latin1");
  } else {
    // Every other algorithm's parameters ARE part of the key identity (an EC curve OID, an RSASSA-PSS constraint set).
    params = pn ? pn.bytes.toString("latin1") : "";
  }
  return algOid + "|" + params + "|" + node.children[1].bytes.toString("latin1");
}
// A well-formed DER NULL node (universal tag 5, empty content) -- the only rsaEncryption parameter form treated
// as equivalent to an absent parameter.
function _isDerNull(pn) { return pn.tagClass === "universal" && pn.tagNumber === 5 && pn.content.length === 0; }

// The BOUNDED, distinct, parseable extraCerts of an already-verified response, cached so a later leg that
// omits extraCerts can rebuild the signer path -- MIRRORING cmp.verify's own extraCerts bounding: dedup, drop
// any non-X.509 entry, cap at MAX_EXTRA_CERTS, and stop after MAX_EXTRA_SCAN entries. So a meddler appending a
// flood of unsigned certs cannot make an otherwise-valid enrollment fail when the cache reaches path.build.
var MAX_EXTRA_CERTS = 32, MAX_EXTRA_SCAN = 256;
// A verify verdict whose failure a DIFFERENT candidate pool or the cached/prebound signer might still recover:
// extraCerts is outside the protected part, so a signer that did not resolve, a wrong-key/wrong-subject decoy
// selected first, or an untrusted chain can all be retried. A transaction-integrity failure (transactionID /
// recipNonce mismatch) is NOT here -- it is decoy-independent and re-running would only mask the real desync.
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
    catch (_e) { continue; }   // drop a malformed entry, mirroring cmp.verify's bounding
    out.push(c);
  }
  return out;
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
  // declared PREHASH digest (COMPOSITE_ALGS[oid].ph) and DECLARE it in the explicit hashAlg. If the prehash is
  // not a certConf-representable hash (SHAKE256, which the CMP CertStatus hashAlg cannot name), FAIL closed --
  // substituting SHA-256 would send a certHash under a hash that contradicts the signature's declared prehash,
  // which a conforming CA rejects. Refuse rather than confirm under a false algorithm (RFC 9810 sec. 5.3.18).
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
 * and read-only `transactionID` + `transcript` (each leg's request/response bytes, retained up to a
 * transaction-wide cap; a later leg beyond the cap keeps its metadata + `byteLength` but drops the payload as
 * `bytes: null, truncated: true`, so a padded-response flood across polls cannot exhaust memory). The granted certificate must be valid X.509, carry the key
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
 *   - `trustAnchors` -- REQUIRED for the signature flavor (chains + authenticates the CA's response signer cert); OPTIONAL for a MAC session, where it validates the ISSUED certificate's own signature + chain before confirmation (not the response protection). `intermediates` -- extra chain pool.
 *   - `sender` / `recipient` -- header GeneralNames; default the signer cert's subject DN (sender) and a NULL-DN (recipient). A signature-protection certificate with an EMPTY subject (identified only by its subjectAltName) REQUIRES an explicit `sender` -- the empty subject cannot name the requester for a peer that binds the sender to the SAN.
 *   - `senderKID` / `recipKID` -- optional key identifiers emitted on every request header, so a CA selecting among several shared secrets (senderKID) or recipient keys resolves the right credential.
 *   - `expectedSender` -- optional CA signer CERTIFICATE (DER Buffer / PEM string / already-parsed `pki.schema.x509.parse` object); when set, every signed response's authenticated header sender MUST bind to it under the RFC 5280 sec. 7 subject-or-subjectAltName rule cmp.verify uses, so a re-encoded-but-equivalent DN and an empty-subject CA named only by a directoryName SAN both match. Given as bytes/PEM it ALSO resolves a first response that omits its own extraCerts (a CA that assumes the client already holds its certificate). Absent, the session pins the first signed response's signer certificate and requires every later leg's sender to bind to it -- rejecting a switch to a different trusted signer while permitting same-identity certificate/key rotation.
 *   - `implicitConfirm` -- request implicit confirmation (skip the certConf leg when the CA grants it).
 *   - `acceptCert` -- an async policy `(certDer, { status, grantedWithMods }) => boolean` consulted before the certConf; return true to accept, anything else to veto (a `grantedWithMods` certificate the CA changed). A veto sends a REJECTING certConf and yields `outcome: "rejected"` with the certificate still surfaced. Incompatible with `implicitConfirm` (no reject leg exists) -- the combination throws at construction.
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
  // transport supplies. Require trustAnchors up front for the signature flavor. A MAC (PBMAC1) session
  // authenticates the RESPONSE by the shared secret, so anchors are OPTIONAL there -- but when supplied they
  // still validate the ISSUED certificate's own signature + chain before it is confirmed (the MAC authenticates
  // the exchange, not the embedded X.509 signature); they are NOT forwarded to the MAC response verify.
  if (isSig) {
    var hasAnchors = opts.trustAnchors != null && !(Array.isArray(opts.trustAnchors) && opts.trustAnchors.length === 0);
    if (!hasAnchors) throw _err("cmp/bad-input", "signature protection requires opts.trustAnchors to authenticate the CA's response signer (RFC 9483 sec. 3.2)");
  }
  // Parse + validate each supplied anchor + intermediate NOW (through the SAME path-builder normalization the
  // verify + issued-cert validation use), so an unusable trust input (a non-certificate string, a malformed
  // tuple, junk bytes) is a construction error rather than a failure discovered only after the one-shot
  // transaction has already engaged the transport.
  if (opts.trustAnchors != null && _engine && _engine.toAnchor) _asCertList(opts.trustAnchors).forEach(function (a) { try { _engine.toAnchor(a); } catch (e) { throw _err("cmp/bad-input", "opts.trustAnchors: each entry must be a certificate (DER/PEM/parsed) or a { name, publicKey, algorithm } anchor tuple -- " + ((e && e.message) || e), e); } });
  if (opts.intermediates != null && _engine && _engine.coerceCert) _asCertList(opts.intermediates).forEach(function (c) { try { _engine.coerceCert(c); } catch (e) { throw _err("cmp/bad-input", "opts.intermediates: each entry must be a certificate (DER/PEM/parsed) -- " + ((e && e.message) || e), e); } });
  // opts.expectedSender pins the CA's SIGNER CERTIFICATE (not a subject string): every signed response's
  // authenticated header sender must bind to it under cmp.verify's own subject-or-subjectAltName rule, so an
  // empty-subject CA named only by a directoryName SAN -- which a subject-string pin reads as an unmatchable null
  // -- is bound correctly. Accept the documented DER Buffer / PEM string / already-parsed certificate at
  // construction; a non-certificate value would otherwise consume the one-shot transaction before the first
  // verify could reject it. The parsed form drives the identity bind; the DER (kept when supplied as bytes/PEM)
  // resolves a first response that omits its extraCerts (below).
  var _expectedSenderCert = null;   // parsed, for the senderBoundToCert identity pin
  var _expectedSenderDer = null;    // DER, for the omitted-extraCerts signer fallback (null when given the already-parsed form, which retains no source DER)
  if (opts.expectedSender != null) {
    var _es = opts.expectedSender;
    try {
      if (_es && Buffer.isBuffer(_es.tbsBytes)) { _expectedSenderCert = _es; }   // the documented already-parsed form (pki.schema.x509.parse output), detected like _certIdentity
      else if (Buffer.isBuffer(_es) || _es instanceof Uint8Array) { _expectedSenderDer = Buffer.from(_es); _expectedSenderCert = x509.parse(_expectedSenderDer); }
      else if (typeof _es === "string") { _expectedSenderDer = x509.pemDecode(_es); _expectedSenderCert = x509.parse(_expectedSenderDer); }
      else { throw _err("cmp/bad-input", "opts.expectedSender must be a certificate DER Buffer / PEM string / parsed certificate"); }
    } catch (e) {
      if (e.isCmpError) throw e;
      throw _err("cmp/bad-input", "opts.expectedSender must be the CA signer certificate (DER Buffer / PEM / parsed) so every signed response can be bound to it -- " + ((e && e.message) || e), e);
    }
  }
  // Reject a DISTINCT intermediate pool that alone exceeds the path builder's candidate ceiling: the caller pool
  // is never truncated, so an oversized one would otherwise raise path/bad-input only at the first verify, after
  // the one-shot transaction has been consumed. (Duplicates collapse, so the count is by distinct identity.)
  if (opts.intermediates != null) {
    var seenInt = Object.create(null), distinctInt = 0;
    _asCertList(opts.intermediates).forEach(function (c) { var k = _certIdentity(c); if (k == null) { distinctInt++; return; } if (!seenInt[k]) { seenInt[k] = 1; distinctInt++; } });
    if (distinctInt > constants.LIMITS.PATH_BUILD_MAX_CANDIDATES) throw _err("cmp/bad-input", "opts.intermediates has " + distinctInt + " distinct certificates, exceeding the " + constants.LIMITS.PATH_BUILD_MAX_CANDIDATES + " candidate ceiling");
  }

  // A certificate-acceptance policy must be a function -- a non-function value (a config typo) would otherwise
  // be silently skipped, auto-accepting a grantedWithMods certificate the caller meant to vet. Fail at config.
  if (opts.acceptCert != null && typeof opts.acceptCert !== "function") throw _err("cmp/bad-input", "opts.acceptCert must be a function (certDer, info) => boolean");
  // implicitConfirm must be a boolean -- a truthy non-boolean (the string "false", say) would silently REQUEST
  // implicit confirmation and reverse the caller's confirmation policy. Reject a non-boolean at construction.
  if (opts.implicitConfirm != null && typeof opts.implicitConfirm !== "boolean") throw _err("cmp/bad-input", "opts.implicitConfirm must be a boolean");
  // sleep, when supplied, must be a function -- a non-function value would silently fall back to the REAL timer,
  // reversing the caller's intent (a bounded / injected sleeper) into a real-time wait. Reject it at construction.
  if (opts.sleep != null && typeof opts.sleep !== "function") throw _err("cmp/bad-input", "opts.sleep must be a function (delayMs) => Promise");
  // acceptCert and implicitConfirm are incompatible: under implicit confirmation the CA treats the certificate
  // as delivered at grant time, so there is no reject leg to honor a veto -- a policy could only produce a
  // misleading rejected verdict for a certificate the CA still considers issued. Refuse the combination up front.
  if (opts.acceptCert != null && opts.implicitConfirm) throw _err("cmp/bad-input", "opts.acceptCert cannot be combined with opts.implicitConfirm -- implicit confirmation leaves no certConf leg to reject on (drop implicitConfirm to vet a grant)");

  // The verify/validation clock, when supplied, must be a valid Date -- else path.build would only reject it while
  // verifying a response, AFTER the one-shot transaction has already engaged the transport and been consumed.
  if (opts.time != null) guard.time.assertValid(opts.time, _err, "cmp/bad-input", "opts.time (the verify/validation clock)");
  // Poll budgets, validated at construction (NaN / negative / over-max -> cmp/bad-input, never a disabled bound).
  var maxPolls = guard.limits.cap(opts.maxPolls, "opts.maxPolls", DEFAULT_MAX_POLLS, { E: _err, code: "cmp/bad-input", min: 1, max: 1000 });
  var maxTotalWait = guard.limits.cap(opts.maxTotalWait, "opts.maxTotalWait", DEFAULT_MAX_TOTAL_WAIT, { E: _err, code: "cmp/bad-input", min: 0, max: retryAfter.MAX_RETRY_AFTER_SECONDS });
  var sleep = opts.sleep || sleepUtil.sleep;   // validated a function (or absent) at construction

  // Transaction identity: mint ONE 128-bit transactionID (stable for the whole transaction), held here.
  var transactionID = Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(16)));
  var lastPeerNonce = null;   // recipNonce for the NEXT request := the previous response's senderNonce
  var haveResponse = false;   // a response has been received -> every subsequent request MUST echo a recipNonce
  var cachedSignerCert = null;   // the CA's verified signature-protection signer cert, reused when a later leg omits extraCerts
  var pinnedSignerCert = null, signerPinned = false;   // the parsed signer certificate of the FIRST signed response -- every later leg's authenticated sender must bind to it (a boolean flag, so it is pinned exactly once)
  var cachedChain = [];   // the extraCerts (signer + intermediates) that validated it, so a later leg can rebuild the signer path
  var caPubsAccum = [];   // the AUTHENTICATED caPubs (issuer certs) accumulated across EVERY ip/cp/kup leg -- a CA may deliver the issuing chain in a `waiting` response and omit it from the eventual grant
  var caPubsSeen = Object.create(null);   // byte-identity dedup for caPubsAccum, bounding cross-leg accumulation (below)
  var caPubsBytes = 0;   // running total of retained caPubs bytes -- a transaction-wide byte budget (below) bounds it independent of the count cap, since a single certificate can approach the DER limit
  var activeCertReqId = DEFAULT_CERT_REQ_ID;   // the certReqId of the in-flight enrollment; echoed in pollReq / certConf
  var expectedRespArm = "ip";   // the cert-response arm the in-flight enrollment must be answered by (RESPONSE_ARM)
  var requestedSpki = null;   // the SPKI DER of the key the enrollment requested; the issued cert MUST carry it
  var inFlight = false, completed = false, started = false;   // one transaction per session; `started` = a request may have hit the transport
  var transcript = [];
  var transcriptBytes = 0;   // running total of RETAINED transcript payload bytes -- bounds a padded-response flood across polling legs (below)
  // The transcript-retention ceiling: TRANSCRIPT_RETAIN_RESPONSES times the effective per-response byte cap. A
  // non-positive / non-finite maxResponseBytes falls back to the default here (a bad value throws in the transport
  // on the first transfer, before any response is recorded) so the ceiling is ALWAYS a positive finite number --
  // a NaN ceiling would make `total > ceiling` perpetually false and silently disable the bound.
  var _perRespCap = (typeof opts.maxResponseBytes === "number" && isFinite(opts.maxResponseBytes) && opts.maxResponseBytes > 0) ? opts.maxResponseBytes : constants.LIMITS.HTTP_MAX_RESPONSE_BYTES;
  var transcriptCap = _perRespCap * TRANSCRIPT_RETAIN_RESPONSES;
  // The caPubs byte budget, proportional to the per-response cap and above one full response, so the GRANT leg's
  // own caPubs (bounded by one response) always fit after evicting waiting entries -- while the total stays bounded
  // (a count-only cap would still admit ~16 GiB of DER-limit-sized certs) independent of the candidate-count cap.
  var caPubsByteBudget = _perRespCap * TRANSCRIPT_RETAIN_RESPONSES;

  // Sender / recipient routing (RFC 9810 sec. 5.1.1). The sender NAMES the requester: signature protection
  // defaults it to the signer cert's own subject DN; a MAC transaction (no cert) has no established name, so
  // it defaults to the NULL-DN (an empty RDNSequence). The recipient (the CA) defaults to the NULL-DN too --
  // the CA is addressed by the endpoint URL, not by a name we can assert. opts.sender / opts.recipient override.
  var NULL_DN = { directoryName: [] };
  var defaultSender = NULL_DN;
  if (isSig) {
    try {
      var _signerSubject = x509.parse(opts.cert).subject;
      // An EMPTY-subject certificate (RFC 5280 sec. 4.1.2.6) is identified only by its subjectAltName, and a
      // conforming peer binds the sender to that SAN (never to the empty subject). Defaulting the sender to the
      // empty DN would name the requester with a value no peer accepts, so REQUIRE opts.sender for such a cert.
      if (_signerSubject.rdns && _signerSubject.rdns.length > 0) defaultSender = { directoryName: _signerSubject.bytes };
      else if (opts.sender == null) throw _err("cmp/bad-input", "the signature-protection certificate has an empty subject, so it cannot name the request sender -- an empty-subject certificate is identified by its subjectAltName; set opts.sender explicitly (e.g. a subjectAltName identity the CA will bind the sender to)");
    } catch (e) {
      if (e && e.isCmpError) throw e;
      defaultSender = NULL_DN;   // a malformed signer cert -> the sender falls back to a NULL-DN (driven by the unparseable-cert construction vector)
    }
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
    // Key identifiers the endpoint uses to select a credential -- a PBMAC1 shared secret (senderKID) among several,
    // or the recipient key (recipKID). Propagated on EVERY leg so the CA resolves the same credential throughout.
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
    // Verify the RESPONSE protection + bind it to THIS exchange via the opt-in echo checks. The CA's signer
    // cert is resolved from the response extraCerts (RFC 9483 sec. 3.3); trustAnchors chain it. A MAC response
    // verifies under the shared secret. transactionID + expectRecipNonce fail-close a mismatched response.
    var o = { transactionID: transactionID, expectRecipNonce: fresh };
    if (isMac) o.sharedSecret = opts.mac.secret;
    // Forward trustAnchors to the RESPONSE verify ONLY for the signature flavor -- the MAC branch of cmp.verify
    // rejects them as a stray signature credential. A MAC session's anchors are used solely for issued-cert
    // validation (_validateLeaf), never the MAC response authentication (which the shared secret establishes).
    else if (opts.trustAnchors != null) o.trustAnchors = opts.trustAnchors;
    // Give cmp.verify ONE bounded pool that already contains the signer's OWN delivered issuers, so it needs no
    // room RESERVED for an internal append (no pre-verify count to estimate, no duplicate to over-reserve). Order
    // by priority: the response's extraCerts first (when responseExtra is passed), then the cached signer chain,
    // then the broad caller pool fills to the ceiling -- _boundedPool dedups the whole thing, so a response cert
    // duplicating a caller one spends no slot, and cmp.verify's re-append of the response extraCerts is all
    // duplicates path.build collapses. The signer itself may sit in this pool as a redundant candidate (a slot);
    // rather than try to IDENTIFY it among extraCerts (senderKID can select one that is not first), the caller of
    // _send retries with responseExtra=null (caller pool at the full ceiling) if this response-prioritized pool
    // truncated a needed caller issuer -- the two attempts cover both truncation priorities without identifying the signer.
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
    _recordTranscript({ direction: "out", arm: arm, bytes: reqDer });
    started = true;   // the request is built; the transaction now engages the transport -> the session is consumed
    var res = await cmp.transfer(opts.url, reqDer, _transferOpts());
    // The response's OWN deduped extraCerts (the signer + its delivered issuers) -- _verifyOpts folds them into the
    // signer-path pool as priority so cmp.verify needs no reserved room for its internal append. cmp.transfer has
    // already parsed res.responseBytes as a PKIMessage (its cmp.parse gate on every return path), so this cannot throw.
    var responseExtra = _responseExtraCerts(res.responseBytes);
    var verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh, null, null, responseExtra));
    // A ceiling-filling caller pool AND the response's own issuers cannot both fit below the candidate ceiling.
    // The attempt above PRIORITIZES the response's delivered issuers; if it fails recoverably, the needed issuer
    // may instead be a CALLER intermediate that the signer (a redundant candidate) or a response-echoed caller cert
    // crowded out. Retry with the caller pool at the FULL ceiling (responseExtra omitted from the priority base) --
    // cmp.verify still appends the response's OWN extraCerts, so its issuers remain available. The two attempts
    // cover BOTH truncation priorities without identifying the signer among extraCerts (senderKID may select a cert
    // that is not first), so no valid response is rejected for lack of candidate room, and neither can admit a
    // genuinely untrusted one -- each re-runs every signature + trust gate.
    if ((verdict.valid !== true || verdict.trusted !== true) && isSig && _isRecoverableVerify(verdict.code)) {
      var callerFirst = await cmp.verify(res.responseBytes, _verifyOpts(fresh, null, null, null));
      if (callerFirst.valid === true && callerFirst.trusted === true) verdict = callerFirst;
    }
    // Fallback: a signature-flavor response's OWN signer resolution can fail FOUR ways that the earlier,
    // authenticated signer still recovers, all because extraCerts is OUTSIDE the protected part and a meddler
    // controls which cert the resolver selects -- (a) NO signer resolved (a later leg omitted extraCerts once the
    // recipient holds the cert, RFC 9483 sec. 3.3) -> signer-cert-not-found; (b) a same-subject decoy with a
    // DIFFERENT key selected first -> protection-failed; (c) a decoy carrying the REAL signer's key but a WRONG
    // subject -> the signature verifies yet the header sender does not bind to it -> sender-mismatch; (d) a decoy
    // carrying the REAL signer's key + identity but chaining to an UNTRUSTED issuer -> verifies yet trust fails
    // -> untrusted-signer. All retry against the cached (already trusted) signer + its chain, whose subject IS the
    // authenticated sender and whose key is fixed. The response's own certs are still preferred on the FIRST
    // attempt, so a clustered CA's legitimately rotated cert wins there; the retry can only rescue a message
    // ACTUALLY signed by the cached signer, never a genuinely tampered / mismatched / untrusted one (it re-runs
    // every gate against the cached cert -- a wrong-key message stays valid:false, a wrong sender stays mismatched).
    // A transaction-integrity failure (transactionID / recipNonce) is NOT retried: it is decoy-independent and a
    // real desync, so the cached signer would fail it identically -- retrying would only mask the diagnostic.
    // The fallback signer is the already-authenticated cached signer, or -- before any response has succeeded --
    // the caller's prebound CA certificate (opts.expectedSender). The latter rescues a FIRST response that omits
    // its own extraCerts because the CA assumes the client already holds its certificate (RFC 9483 sec. 3.3): the
    // signer cannot resolve from an empty extraCerts, yet the exact certificate is locally provisioned.
    var usedCachedFallback = false;
    var fallbackSigner = cachedSignerCert != null ? cachedSignerCert : _expectedSenderDer;
    var recoverable = _isRecoverableVerify(verdict.code);
    if ((verdict.valid !== true || verdict.trusted !== true) && isSig && fallbackSigner != null && recoverable) {
      // A CACHED-signer fallback re-verifies against material a PRIOR leg authenticated, so THIS response's
      // extraCerts are decoy-suspect and must NOT overwrite the cache. A PREBORN fallback (no prior cache, the
      // caller's opts.expectedSender) instead verifies this response's OWN extraCerts against the prebound signer,
      // so they ARE authenticated -- cache them, else a later extraCerts-less leg retries with an empty chain.
      usedCachedFallback = cachedSignerCert != null;
      verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh, fallbackSigner, cachedChain, responseExtra));
    }
    _recordTranscript({ direction: "in", arm: verdict.body ? verdict.body.arm : null, status: res.status, bytes: res.responseBytes, verdict: { valid: verdict.valid, trusted: verdict.trusted, code: verdict.code || null } });
    if (verdict.valid !== true) throw _err(verdict.code || "cmp/protection-failed", "the CMP response protection did not verify (" + (verdict.reason || "invalid") + ") -- the transaction is NOT advanced", null);
    // Cryptographically valid is NOT enough: the signer (signature flavor) must chain to a supplied trust
    // anchor, or the shared secret (MAC flavor) must match -- both surface as verdict.trusted. A valid-but-
    // untrusted response is an unauthenticated signer; fail closed rather than read a certificate off it.
    if (verdict.trusted !== true) throw _err(verdict.code || "cmp/untrusted-signer", "the CMP response protection verified but its signer is not trusted (it did not chain to a supplied trust anchor) -- the transaction is NOT advanced", null);
    // Bind a SIGNED response to the intended CA IDENTITY, not merely to "any trusted signer". A trust anchor that
    // issues to more than one party would otherwise let an on-path holder of ANY chaining digitalSignature cert
    // sign a forged response under its OWN subject and still pass the trust gate. The binding reuses cmp.verify's
    // OWN sender<->certificate rule (RFC 5280 sec. 7 per-type comparison: a directoryName under the sec. 7.1
    // canonical DN comparison, a dNSName / rfc822Name / URI case-folded, every other type by exact DER) so a
    // re-encoded-but-equivalent DN (PrintableString<->UTF8String) and an empty-subject CA named only by a
    // subjectAltName both compare correctly -- neither a raw byte pin nor a subject-string pin can do that.
    if (isSig && verdict.signer && verdict.header && verdict.header.sender) {
      // (1) opts.expectedSender pinned the CA's signer certificate up front: every signed response's authenticated
      // header sender MUST bind to it, enforced from the FIRST response (so a forged first response is caught too).
      if (_expectedSenderCert && !cmp.senderBoundToCert(verdict.header.sender, _expectedSenderCert)) {
        throw _err("cmp/untrusted-signer", "the response signer does not match the expected CA identity (opts.expectedSender) -- refusing a response from a different trusted signer", null);
      }
      // (2) The FIRST signed response pins the CA certificate; every later leg's authenticated sender MUST bind to
      // it under the same rule -- permitting same-identity certificate/key rotation (the sender identity survives a
      // re-encoding) while rejecting a mid-transaction switch to a different trusted signer.
      if (!signerPinned) { pinnedSignerCert = x509.parse(verdict.signer.cert); signerPinned = true; }   // a boolean flag: the pin is set once, never re-initialized per leg
      else if (!cmp.senderBoundToCert(verdict.header.sender, pinnedSignerCert)) {
        throw _err("cmp/untrusted-signer", "the response signer identity changed mid-transaction -- a different trusted signer, not a same-identity certificate rotation; the transaction is NOT advanced", null);
      }
    }
    lastPeerNonce = verdict.senderNonce;   // may be absent; _baseHeader enforces its presence before a follow-up leg
    haveResponse = true;
    // Refresh the cached signer + its validated chain material from a response that verified ON ITS OWN OR via the
    // PREBORN (opts.expectedSender) fallback -- in both, its extraCerts IS the chain that established trust (the
    // most recently authenticated cert + the intermediates that chained it; a clustered CA may rotate its
    // protection cert across legs), so a later extraCerts-less leg falls back to the current signer AND can rebuild
    // its path. A response that verified only via the CACHED-signer fallback did NOT authenticate its own extraCerts
    // (which may hold a meddler's decoy or omit the real intermediate); keep the existing cached signer + chain --
    // the material that actually established trust -- rather than overwriting it with that response's untrusted pool.
    if (isSig && !usedCachedFallback && verdict.signer && Buffer.isBuffer(verdict.signer.cert)) {
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
      var isGrantLeg = _isGranted(code);
      // Accumulate the AUTHENTICATED caPubs of EVERY ip/cp/kup leg (waiting AND granting): a CA may deliver the
      // issuing chain in a `waiting` response and omit it from the grant, so the leaf's issuer must survive the poll.
      // Bound + validate + dedup the caPubs AS ACCUMULATED, not only when _finish is reached: an authenticated CA
      // can return `waiting` up to the poll budget with large or repeated caPubs, so without a cross-leg cap this
      // array would retain unbounded material before validation. Enforce a count AND a byte budget; a byte-identical
      // repeat is dropped; a non-X.509 entry is REJECTED (fail-closed -- the leaf validation would otherwise defer
      // it to _finish). The GRANT leg's caPubs are the issued leaf's OWN chain (highest priority): they EVICT the
      // oldest WAITING entries to fit ALL of them within the budget, so no fixed reserve can starve the leaf's own
      // required issuer no matter how many waiting caPubs preceded it (a caPubs field carries no MAX_EXTRA_CERTS cap).
      if (body.decoded && Array.isArray(body.decoded.caPubs)) body.decoded.caPubs.forEach(function (c) {
        if (!Buffer.isBuffer(c)) return;
        var k = c.toString("base64");
        if (caPubsSeen[k]) return;
        try { x509.parse(c); } catch (e) { throw _err("cmp/bad-cert-response", "an authenticated caPubs entry is not a valid X.509 certificate", e); }
        if (isGrantLeg) {
          while (caPubsAccum.length > 0 && (caPubsAccum.length >= constants.LIMITS.PATH_BUILD_MAX_CANDIDATES || caPubsBytes + c.length > caPubsByteBudget)) {
            var evicted = caPubsAccum.shift();   // drop the oldest (a WAITING entry -- the grant is the last leg) to make room
            caPubsBytes -= evicted.length;
            delete caPubsSeen[evicted.toString("base64")];   // keep the dedup set == the retained set, so a grant re-delivering an evicted issuer (also seen in a waiting leg) can re-add it
          }
        }
        if (caPubsAccum.length >= constants.LIMITS.PATH_BUILD_MAX_CANDIDATES || caPubsBytes + c.length > caPubsByteBudget) return;   // a single certificate larger than the whole budget
        caPubsSeen[k] = 1;
        caPubsBytes += c.length;
        caPubsAccum.push(Buffer.from(c));   // COPY out of the parser's subarray -- retaining the slice would pin the whole multi-MB response buffer, so caPubsBytes (the cert length) would not bound the real allocation across polls
      });
      if (isGrantLeg) return { state: "granted", resp: resp, code: code };
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

  // Append a transcript entry, bounding the RETAINED payload bytes transaction-wide. A polling enrollment runs
  // many legs and an on-path party can pad every otherwise-valid signed response with unsigned extraCerts up to
  // the per-response cap; retaining each full payload would multiply that cap across legs into memory exhaustion.
  // Once the running total crosses the ceiling, the entry keeps its metadata + `byteLength` but drops the payload
  // (`bytes: null, truncated: true`) so the internal reference is released to GC and the transcript stays a
  // fixed-size diagnostic. Normal kilobyte messages never reach the ceiling, so the payloads are retained intact.
  function _recordTranscript(entry) {
    var len = Buffer.isBuffer(entry.bytes) ? entry.bytes.length : 0;
    if (transcriptBytes + len > transcriptCap) {
      entry.byteLength = len; entry.bytes = null; entry.truncated = true;
    } else {
      transcriptBytes += len;
    }
    transcript.push(entry);
  }

  // A defensive SNAPSHOT of the transcript: a fresh array of shallow-copied entries with copied byte Buffers, so
  // freezing or mutating the returned value cannot break the internal transcript (_send keeps appending to it)
  // nor mutate a Buffer still shared with an in-flight request/response body.
  function _transcriptSnapshot() {
    return transcript.map(function (e) {
      var c = Object.assign({}, e);
      if (Buffer.isBuffer(c.bytes)) c.bytes = Buffer.from(c.bytes);
      if (c.verdict) c.verdict = Object.assign({}, c.verdict);
      return c;
    });
  }
  function _terminal(outcome, extra) {
    // Every terminal outcome is reached only through _send, which throws unless the response was both valid
    // AND trusted -- so a returned verdict is always authenticated (trusted:true), surfaced for the caller.
    return Object.assign({
      outcome: outcome, certificate: null, chain: [], status: null, trusted: true,
      confirmed: false, implicitConfirm: false, transactionID: Buffer.from(transactionID),   // a copy: mutating it must not corrupt the session identity
      polls: 0, transcript: _transcriptSnapshot(),
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
  // `info` carries the grant status so an acceptance policy can veto a grantedWithMods certificate.
  async function _confirm(certDer, header, info) {
    // Honor an implicitConfirm grant ONLY when the caller REQUESTED it (opts.implicitConfirm): implicit
    // confirmation is negotiated (RFC 9810 sec. 5.1.1.1), so an UNSOLICITED implicitConfirm from a nonconforming
    // server is ignored -- the session performs the explicit certConf the caller expects. No acceptance policy
    // runs here: acceptCert + implicitConfirm is refused at construction (there is no reject leg to honor a veto).
    if (opts.implicitConfirm && _implicitConfirmGranted(header)) return { confirmed: true, implicit: true };
    // Consult the caller's acceptance policy before the explicit confirmation. A grantedWithMods response (RFC
    // 9810 sec. 5.2.3) carries a certificate the CA CHANGED (subject / validity / extensions), and an accepting
    // certConf is irrevocable, so the caller may inspect + veto it here. The policy MUST return true to accept;
    // anything else is a veto (a thrown rejection is NOT swallowed -- it propagates). No policy accepts (default).
    var accept = true;
    if (typeof opts.acceptCert === "function") accept = (await opts.acceptCert(Buffer.from(certDer), info)) === true;
    var h = _certConfHash(certDer);
    var certHash = Buffer.from(await webcrypto.webcrypto.subtle.digest(h.digest, certDer));
    var cs = { certHash: certHash, certReqId: activeCertReqId };
    // A veto sends a REJECTING certConf (CertStatus.statusInfo status rejection, RFC 9810 sec. 5.3.18) so the CA
    // learns the EE declined and does not treat the certificate as delivered; an acceptance omits statusInfo.
    if (!accept) cs.statusInfo = { status: 2, statusString: ["the enrolling client rejected the issued certificate"] };
    if (h.hashAlg) cs.hashAlg = h.hashAlg;   // declare the hash for a sig alg whose OID does not convey it (PSS / EdDSA / ML-DSA)
    var verdict = await _send({ certConf: [cs] }, "certConf");
    if (!verdict.body || verdict.body.arm !== "pkiconf") throw _err("cmp/bad-confirmation", "expected a pkiConf acknowledgement to the certConf but got " + JSON.stringify(verdict.body && verdict.body.arm) + " (RFC 9810 sec. 5.3.18)");
    return { confirmed: accept, implicit: false, rejected: !accept };
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
    // it is a misrouted certificate the caller holds no private key for. Compare the KEY identity (alg OID +
    // key bits), not the raw SPKI bytes, so an equivalent re-encoding (rsaEncryption NULL vs omitted) matches.
    if (requestedSpki != null && _spkiKeyIdentity(parsed.subjectPublicKeyInfo.bytes) !== _spkiKeyIdentity(requestedSpki)) {
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
  // signature would otherwise be confirmed) whenever trust anchors are supplied. A signature session always has
  // them (required); a MAC session validates the issued cert ONLY when the caller opts in with anchors -- the
  // response MAC authenticates the exchange, NOT the embedded X.509 signature, so without anchors an invalid-sig
  // MAC-issued cert would otherwise be confirmed. The pool prioritizes the AUTHENTICATED, leaf-relevant caPubs
  // (the CA's OWN issuer chain for this leaf) as the base -- never evicted by a caller pool that fills the
  // ceiling -- then the caller's intermediates, then the cached protection-signer chain, deduped + ceiling-bounded.
  async function _validateLeaf(leaf, caPubs) {
    if (_engine == null || opts.trustAnchors == null) return;
    var caPubsList = [];
    if (Array.isArray(caPubs)) caPubs.forEach(function (c) { if (Buffer.isBuffer(c)) caPubsList.push(c); });
    var callerInts = _asCertList(opts.intermediates);   // the caller pool alone (config-bounded to <= the ceiling)
    var cachedMaterial = [];   // the response-signer's cached chain -- secondary in BOTH attempts, so neither priority base can exceed the ceiling
    if (Buffer.isBuffer(cachedSignerCert)) cachedMaterial.push(cachedSignerCert);
    cachedChain.forEach(function (c) { if (Buffer.isBuffer(c)) cachedMaterial.push(c); });
    var anchors = _asCertList(opts.trustAnchors);
    var when = opts.time != null ? opts.time : new Date();
    // TWO priority attempts, exactly as the response-signer path: the authenticated caPubs first (a CA's OWN issuer
    // chain, never evicted by a ceiling-filling caller pool), else -- if that pool cannot build a path -- the caller
    // pool first, so a required caller issuer late in a ceiling-filling pool is not truncated by an unrelated caPubs
    // entry. path.build dedups, so a cert in both is not double-counted; each attempt re-runs the full RFC 5280 check.
    var res = await _tryBuildLeaf(leaf, _boundedPool(caPubsList, callerInts.concat(cachedMaterial)), anchors, when);
    if (!(res && res.valid === true)) {
      var res2 = await _tryBuildLeaf(leaf, _boundedPool(callerInts, caPubsList.concat(cachedMaterial)), anchors, when);
      if (res2 && res2.valid === true) res = res2;
    }
    if (!res || res.valid !== true) throw _err("cmp/bad-cert-response", "the issued certificate did not validate to a supplied trust anchor (its signature or chain is invalid) (RFC 5280 sec. 6.1)");
  }
  async function _tryBuildLeaf(leaf, pool, anchors, when) {
    try { return await _engine.build(leaf, { trustAnchors: anchors, intermediates: pool, validate: true, time: when }); }
    catch (e) {
      if (e.code === "path/bad-input") throw _err("cmp/bad-input", "invalid trust / validation options for issued-certificate validation: " + (e.message || e), e);
      // path.build THROWS path/no-path when the leaf cannot chain with THIS candidate pool -- signal "try the other
      // priority"; a genuine unbuildable leaf (both attempts fail) surfaces as cmp/bad-cert-response in _validateLeaf.
      return null;
    }
  }

  async function _finish(granted, header) {
    var leaf = _leafOf(granted.resp);
    // The returned chain is the issued leaf followed by the authenticated caPubs accumulated across the WHOLE
    // transaction (the issuer certs the CA delivered on any ip/cp/kup leg, RFC 9810 sec. 5.3.4) -- surfaced so a
    // caller whose intermediate arrived only on a `waiting` leg can still assemble the full chain. They are chain
    // material, NOT trust anchors. The CMP parser surfaces each caPubs entry as a raw sequence, so validate every
    // one as X.509 BEFORE the certConf acknowledges the grant -- the returned chain must never carry bytes
    // pki.schema.x509.parse rejects -- and deduplicate a chain re-delivered across the waiting + granting legs.
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
    await _validateLeaf(leaf, caPubsAccum);   // verify the leaf's signature + chain BEFORE confirming it
    var info = { status: PKI_STATUS_NAMES[granted.code] || granted.code, grantedWithMods: granted.code === 1 };
    var conf = await _confirm(leaf, header, info);
    // Surface COPIES of the issued certificate + chain, not the internal Buffers (slices of the response bytes),
    // so a caller mutating the returned value cannot reach back into session state -- consistent with the
    // transactionID + transcript defensive copies.
    var certOut = Buffer.from(leaf), chainOut = chain.map(function (c) { return Buffer.from(c); });
    // A caller acceptance-policy veto (typically of a grantedWithMods certificate) is a terminal `rejected`
    // outcome that still surfaces the certificate the caller inspected -- the accepting certConf was replaced by
    // a rejecting one (explicit path) so the CA does not treat it as delivered.
    if (conf.rejected) {
      return _terminal("rejected", { certificate: certOut, chain: chainOut, status: _statusOf(granted.resp), polls: granted.polls || 0 });
    }
    return _terminal("issued", {
      certificate: certOut, chain: chainOut, status: _statusOf(granted.resp),
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
    // The session proves possession by SIGNING the CRMF proof of possession with the requested key (opts.key for
    // a signature session, the arm-local `key` for a MAC session). A raVerified / other non-signature POP override
    // would make crmf.build emit THAT mode and skip the signature entirely -- no requester proof of possession --
    // so refuse it: it would also bypass the MAC key requirement below (a present key is ignored under raVerified).
    if (arms[0] !== "p10cr" && armSpec != null && armSpec.pop != null && armSpec.pop.type != null && armSpec.pop.type !== "signature") {
      throw _err("cmp/bad-input", "a session ir / cr / kur proves possession by signing the CRMF proof of possession; a non-signature POP mode (" + JSON.stringify(armSpec.pop.type) + ") is not supported (RFC 4211 sec. 4)");
    }
    // A signature session signs the CRMF proof of possession with opts.key; a PBMAC1 session has NO signing key,
    // so an ir / cr / kur under MAC protection MUST carry the requested key's private half as the arm-local
    // `key`. Without it crmf.build emits NO proof of possession (RFC 4211 sec. 4) and a POP-enforcing CA rejects
    // the request. crmf.build then verifies the POP signature against certTemplate.publicKey, so a WRONG key
    // fails at build -- here we only require the key is present. (A p10cr proves possession via the CSR signature.)
    if (isMac && arms[0] !== "p10cr" && (armSpec == null || armSpec.key == null)) {
      throw _err("cmp/bad-input", "a MAC-protected ir / cr / kur must carry the requested key's private half as `key` for the CRMF proof of possession -- a signature session reuses opts.key, but a PBMAC1 session has no signing key, so the request would carry no proof of possession (RFC 4211 sec. 4)");
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
      if (t.state === "granted") { var r = await _finish({ resp: t.resp, polls: pollCount, code: t.code }, grantHeader); r.polls = pollCount; return r; }
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
    get transcript() { return _transcriptSnapshot(); },   // a defensive snapshot; never the mutable internal array
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
