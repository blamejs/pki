// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cmp.session implementation. The operator-facing @module pki.cmp home is
// lib/cmp-build.js; this file adds the @primitive pki.cmp.session block and re-exports the cmp message
// surface (build / transfer / wellKnownUrl / verify) so the whole pki.cmp namespace wires through here
// (index.js requires this file as `cmp`).
//
// pki.cmp.session -- the stateful CMP enrollment-transaction orchestrator (the pki.acme.client analogue).
// It composes the shipped message layer (build / transfer / verify) into a single enroll(request): mint a
// stable transactionID, build + protect + transfer a request, verify every response's protection before
// reading its body, chain the nonces (recipNonce echoes the peer's senderNonce, a fresh senderNonce per
// request) and the transactionID (RFC 9810 sec. 5.1.1 anti-replay / anti-interleave), interpret the
// CertResponse PKIStatus (grant -> extract the cert, waiting -> a bounded pollReq/pollRep loop, rejection
// -> a terminal verdict), and confirm (certConf -> pkiConf, unless implicitConfirm was granted). The
// single invariant is transfer -> verify (fail-closed) -> only then read the body off the verdict.

var cmp = require("./cmp-verify");   // re-exports build / transfer / wellKnownUrl / verify (the whole message layer)
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

var CmpError = frameworkError.CmpError;
function _err(code, message, cause) { return new CmpError(code, message, cause); }
var OID_IMPLICIT_CONFIRM = oid.byName("implicitConfirm");   // classify a granted implicitConfirm by its IMMUTABLE OID

// The certification-path build/validate engine, injected by path-validate (the crl/ocsp/cmp-verify seam) so
// the session can validate the issued leaf certificate's signature + chain; x509.parse is structural only.
var _engine = null;
function setEngine(engine) { _engine = engine; }

// The signature algorithms whose OID conveys no message hash: EdDSA (the hash is the scheme) and the FIPS
// PQC signatures (ML-DSA / SLH-DSA, internally hashed). Only these may take the certConf SHA-256 + explicit
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
// A CRL states the point it speaks for in this extension (RFC 5280 sec. 5.2.5); taken at load, by
// identifier, so a later pki.oid.register cannot rename the extension the scope is read from.
var OID_IDP = oid.byName("issuingDistributionPoint");
// The two extensions that decide whether a certificate can act as an authority, taken at load and
// matched by identifier. pki.oid.register replaces an OID's display name, so a test asking whether
// an extension is NAMED basicConstraints reads a present one as absent after a rename, and every
// valid root key update is refused.
var OID_BASIC_CONSTRAINTS = oid.byName("basicConstraints");
var OID_KEY_USAGE = oid.byName("keyUsage");
// Message-digest OID -> the WebCrypto digest name, for the RSASSA-PSS hashAlgorithm parameter, dispatched by
// the immutable OID (never oid.name, which pki.oid.register can rename). Resolved to a dotted-OID map at load.
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
// ->cp, kur->kup. A response on a different cert-response arm than the request is misrouted, never confirmed.
var RESPONSE_ARM = { ir: "ip", cr: "cp", kur: "kup", p10cr: "cp", rr: "rp", genm: "genp" };
// A pollReq for a non-enrollment operation refers to the WHOLE message rather than to a
// CertResponse element inside it. RFC 9483 sec. 4.4: an entity "sends a poll request with certReqId
// 0 if referring to the CertResponse element contained in the ip/cp/kup message, else -1 to refer
// to the whole message". A revocation or a support message has no CertResponse element, so the
// second half of that sentence is the one that applies and the id is -1. The 0 is not a default for
// polling; it is the id OF an element these operations do not carry.
var WHOLE_MESSAGE_CERT_REQ_ID = -1;

// The four support messages RFC 9483 sec. 4.3 defines, keyed by the name a caller asks for.
// `requestOid` and `responseOid` differ only for rootCaCert (sec. 4.3.2), which is the reason
// the pair is a table rather than one field: a response echoing the request OID is a different
// operation's answer, and only the table can say so. `value` is absent for an operation whose
// request carries no infoValue (sec. 4.3.1 and sec. 4.3.3 both say it MUST be absent).
// The table is null-prototype: the key comes from a caller's request object, so a plain literal
// would answer `toString` or `constructor` with an inherited value and dispatch on it.
var INFO_OPS = Object.assign(Object.create(null), {
  caCerts: { name: "caCerts", requestOid: "caCerts", responseOid: "caCerts", value: false, read: "readCaCerts" },
  rootCaCert: { name: "rootCaCert", requestOid: "rootCaCert", responseOid: "rootCaKeyUpdate", value: "cert", read: "readRootCaKeyUpdate" },
  certReqTemplate: { name: "certReqTemplate", requestOid: "certReqTemplate", responseOid: "certReqTemplate", value: false, read: "readCertReqTemplate" },
  crlUpdate: { name: "crlUpdate", requestOid: "crlStatusList", responseOid: "crls", value: "crlStatus", read: "readCrls" },
});
var KNOWN_REVOKE_KEYS = { certificate: 1, certDetails: 1, reason: 1 };
// The CRLReason names a revocation may state, read off the same shared table pki.crl.sign and
// pki.cmp.build encode from, so the three cannot drift apart on what a reason is called. Checked at
// this door so a mistyped name reads as the request-shape error it is, before the transport engages.
// A keySpec algId (RFC 9483 sec. 4.3.3, RFC 9480 sec. 2.16) MUST "give an algorithm other than RSA",
// and that is the ONLY constraint the responder is held to: the control names a public-key type an
// entity MAY be asked to generate, one AttributeTypeAndValue per algorithm the CA supports, and the
// entity picks one it can do. So the check refuses an algId ONLY when it names an RSA algorithm (whose
// requirement is stated with rsaKeyLen instead); every other value -- a non-RSA algorithm this toolkit
// knows, or an OID it does not recognize -- is surfaced to the caller. Refusing an unrecognized
// algorithm would break interop with a CA offering one newer than this registry AND drop the other
// algorithms the same keySpec offers, since one bad element fails the whole exchange.
//
// "RSA" is decided by OID FAMILY, not a hand-list. An RSA-DEDICATED arc -- one whose every member is
// RSA -- is matched by its prefix, so a standardized member this registry has not named is caught with
// the ones it has: PKCS#1 (rsaEncryption, PSS, OAEP, every sha*/md*WithRSAEncryption) and the TeleTrusT
// rsaSignature arc (RSA with SHA-1 and the RIPEMD family). Each prefix is the arc a registered member
// sits directly under, read from the registry, so no dotted-decimal literal appears here and
// pki.oid.register cannot move it. RSA also sits off those arcs on ones it SHARES with non-RSA
// algorithms, where no prefix can isolate it, so those are listed by name: id-rsa-kem (S/MIME) and
// id-kem-rsa (ISO 18033-2); the RSASSA-PKCS1-v1_5-with-SHA-3 set on the NIST signature arc, shared with
// ML-DSA and SLH-DSA; RSASSA-PSS-with-SHAKE (RFC 8692) on the PKIX arc; and the legacy OIW
// md2/md5/sha1-WithRSASignature set on the OIW Secsig arc, shared with DSA and the SHA-1 hash. A
// composite signature naming RSA as one half is a composite key, not an RSA one, and lives on the PKIX
// arc, so it is outside all of these.
var RSA_ARCS = ["rsaEncryption", "rsaSignatureWithripemd160"].map(function (n) {
  return oid.toArcs(oid.byName(n)).slice(0, -1);   // the RSA-dedicated arc a registered member sits directly under
});
var RSA_OFF_ARC = Object.create(null);
["id-rsa-kem", "id-kem-rsa",
  "id-rsassa-pkcs1-v1_5-with-sha3-224", "id-rsassa-pkcs1-v1_5-with-sha3-256",
  "id-rsassa-pkcs1-v1_5-with-sha3-384", "id-rsassa-pkcs1-v1_5-with-sha3-512",
  "id-RSASSA-PSS-SHAKE128", "id-RSASSA-PSS-SHAKE256",
  "md2WithRSASignature", "md5WithRSASignature", "sha1WithRSASignature",
].forEach(function (n) { var d = oid.byName(n); if (d) RSA_OFF_ARC[d] = 1; });

var CRL_REASON_NAMES = Object.create(null);
Object.keys(constants.NAMES.CRL_REASON).forEach(function (v) { CRL_REASON_NAMES[constants.NAMES.CRL_REASON[v]] = 1; });

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
// from the response's unsigned extraCerts) to a `base` pool (the caller's own intermediates) up to the path
// builder's candidate ceiling, deduped against each other AND the base's Buffer entries so a copy of an existing
// candidate never spends a slot. The base is never truncated (if it alone exceeds the ceiling, that is a genuine
// config error path.build reports). So neither a legitimate caPubs nor a meddler's extraCerts flood can push a
// valid caller pool over the ceiling and fail an otherwise-valid grant. Used for both the response signer path
// (cmp.verify) and the issued-leaf path (path.build), the two places session material joins a caller pool.
function _boundedPool(base, added) {
  // Dedup the base (the priority pool) first: duplicate copies would otherwise inflate its length, drive the
  // remaining room to zero, and evict genuinely needed added material even though the distinct candidate count is
  // small (path.build dedups internally, so dropping exact duplicates is behavior-preserving). An uncanonicalizable
  // entry is kept as-is (path.build judges it) and cannot dedup an added cert. The base holds the priority material
  // (a signed response's own delivered issuers + the cached chain, or the grant's caPubs) so it is never truncated;
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
// A canonical byte identity for a certificate in any form path.build accepts (a DER Buffer, a PEM string, or
// an already-parsed certificate object), so a caller intermediate supplied as PEM or parsed still dedups against
// a byte-identical DER caPubs / cached certificate and does not spend a scarce candidate slot on a copy. The
// identity is the tbsCertificate bytes plus the signature (mirroring cmp.verify's _certKey): a meddler controls
// the unsigned extraCerts ordering, so a corrupted-signature copy sharing a valid issuer's TBS must not collapse
// onto it and evict the valid one. Returns null when the identity cannot be derived; a non-deduped entry is safe
// (a redundant slot), a wrong merge (dropping a distinct or the only valid certificate) is not.
// The identity comes from the same derivation every other certificate door uses: the bytes the
// parser recorded, never the fields of the object handed in. This is a dedupe, not a verdict,
// and no collision attack on it is apparent, since carrying another certificate's exact tbsBytes and
// signature means being that certificate. But "no attack is apparent" is the reasoning that put a
// completeness-only door on nine deciding boundaries, so it is not the reasoning this uses: one
// derivation for certificates, everywhere, and the exceptions have to argue for themselves.
//
// Failure returns null instead of throwing, which is this function's own contract and is why the
// door is wrapped: an underivable identity is a redundant pool slot, while a wrong merge (dropping
// a distinct or the only valid certificate) is not. So a rebuilt entry simply does not dedupe.
function _certIdentity(cert) {
  try {
    var p = guard.parsed.acceptDerived(cert, "certificate", x509.parse, _err, "cmp/bad-input", "a pool certificate");
    if (!guard.parsed.isCert(p)) return null;
    return p.tbsBytes.toString("base64") + "|" + p.signatureValue.bytes.toString("base64");
  } catch (_e) {
    return null;   // underivable: kept as its own slot, never merged onto another certificate's
  }
}

// A canonical identity for a SubjectPublicKeyInfo: the algorithm OID + the AlgorithmIdentifier parameters +
// the raw subjectPublicKey BIT STRING. The parameters are part of the key identity (an EC curve OID, an
// RSASSA-PSS constraint set) and are kept, with one exception: rsaEncryption, whose parameters are NULL or
// omitted, both naming the same key. So the issued-cert key-match compares keys (with their constraints), not byte
// encodings, and neither rejects an equivalent rsaEncryption re-encoding nor accepts a constraint-changed key.
function _spkiKeyIdentity(spkiDer) {
  var node = asn1.decode(spkiDer);   // SEQUENCE { AlgorithmIdentifier { OID, params? }, BIT STRING }
  var algId = node.children[0];
  var algOid = asn1.read.oid(algId.children[0]);
  var pn = algId.children[1];
  var params;
  if (algOid === OID_RSA_ENCRYPTION) {
    // rsaEncryption parameters MUST be absent or a NULL (RFC 3279 sec. 2.3.1). Normalize only those two
    // equivalent forms to "" so a NULL-vs-omitted re-encoding matches. Any other value (a malformed empty OCTET
    // STRING the parser/importer may tolerate, or a changed parameter) keeps its bytes, so a parameter-changed
    // certificate a stricter consumer rejects gets a distinct identity and the key-match refuses it.
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

// The bounded, distinct, parseable extraCerts of an already-verified response, cached so a later leg that
// omits extraCerts can rebuild the signer path, mirroring cmp.verify's own extraCerts bounding: dedup, drop
// any non-X.509 entry, cap at MAX_EXTRA_CERTS, and stop after MAX_EXTRA_SCAN entries. So a meddler appending a
// flood of unsigned certs cannot make an otherwise-valid enrollment fail when the cache reaches path.build.
var MAX_EXTRA_CERTS = 32, MAX_EXTRA_SCAN = 256;
// The caller intermediates pool is capped below the path-builder candidate ceiling, reserving room for the CA's
// own authenticated material (a response's extraCerts + the cached signer chain, or the grant's caPubs + cache,
// each <= MAX_EXTRA_CERTS). So the authenticated certs and the whole caller pool always fit in one candidate pool:
// no priority attempt has to choose between them, and a chain assembled from both sources validates in one build.
var CAPUBS_MAX = 2 * MAX_EXTRA_CERTS;   // the leaf's authenticated issuer material (caPubs), bounded so caPubs + cached chain + the caller pool fit under the ceiling
// The caller intermediates pool is capped below the path-builder ceiling by the room the session's own material
// can occupy. A signature session reserves CAPUBS_MAX (a grant's caPubs, leaf validation) plus MAX_EXTRA_CERTS (the
// response's extraCerts + cached signer chain, the signer-path pool). A MAC session authenticates the response by
// the shared secret and never adds a signer chain (its cache gate is isSig), so it reserves CAPUBS_MAX alone; its
// sole pool is _validateLeaf's caPubs + caller. So every candidate pool the session builds holds the whole caller
// pool and all authenticated material at once: one build, no priority choice, no retry.
var SESSION_MAX_INTERMEDIATES = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - CAPUBS_MAX - MAX_EXTRA_CERTS;   // signature
var SESSION_MAX_INTERMEDIATES_MAC = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - CAPUBS_MAX;                 // MAC (no signer chain reserved)
// A verify verdict whose failure a DIFFERENT candidate pool or the cached/prebound signer might still recover:
// extraCerts is outside the protected part, so a signer that did not resolve, a wrong-key/wrong-subject decoy
// selected first, or an untrusted chain can all be retried. A transaction-integrity failure (transactionID /
// recipNonce mismatch) is deliberately absent: it is decoy-independent, and re-running would only mask the desync.
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
    out.push(Buffer.from(c));   // COPY out of the parser's subarray -- retaining the slice would pin the whole multi-MB response buffer if this entry is cached (the caPubs accumulator copies for the same reason)
  }
  return out;
}

// Normalize a caller-supplied CRMF certReqId to the value the session echoes + matches, the same way
// crmf-sign._certReqId encodes it: a number or bigint is kept; a string (decimal or 0x-hex) is parsed via
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

// The certConf certHash algorithm (RFC 9810 sec. 5.3.18): use the same hash the certificate signature uses.
// If the signatureAlgorithm OID conveys the hash (sha256WithRSAEncryption / ecdsaWithSHA384 / ...) use that
// hash and omit hashAlg. For id-RSASSA-PSS the hash is carried in the params, so decode it and likewise omit
// hashAlg. Only when the hash is genuinely not conveyed (Ed25519 / Ed448; ML-DSA / SLH-DSA) is SHA-256 used
// and declared in the explicit hashAlg field so the CA recomputes certHash under the same stated hash.
function _certConfHash(certDer) {
  var sa;
  try { sa = x509.parse(certDer).signatureAlgorithm; }
  catch (e) { throw _err("cmp/bad-cert-response", "the issued certificate is unexpectedly unparseable at certConf", e); }   // unreachable: _leafOf already validated it; re-throw fail-closed
  // Dispatch by the IMMUTABLE signatureAlgorithm OID (never the mutable display name). A hashless SIGNATURE
  // (EdDSA / ML-DSA / SLH-DSA) -> SHA-256 + an explicit hashAlg; a hash-conveying signature -> its hash, no
  // hashAlg; id-RSASSA-PSS -> the hash from its parameters, no hashAlg.
  if (HASHLESS_SIG_OIDS[sa.oid]) return { digest: "SHA-256", hashAlg: "sha256" };
  // A composite signature (draft-ietf-lamps-pq-composite-sigs): compute certHash under the composite's own
  // declared prehash digest (COMPOSITE_ALGS[oid].ph) and declare it in the explicit hashAlg. If the prehash is
  // not a certConf-representable hash (SHAKE256, which the CMP CertStatus hashAlg cannot name), fail closed:
  // substituting SHA-256 would send a certHash under a hash that contradicts the signature's declared prehash,
  // which a conforming CA rejects. Refuse, never confirm under a false algorithm (RFC 9810 sec. 5.3.18).
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
  // Any other AlgorithmIdentifier (an unregistered OID, or a registered non-signature / indeterminate one
  // such as rsaEncryption or an ML-KEM OID): the required certConf hash cannot be determined. Do not guess
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
 * named source, held to that source -- the issuer under the RFC 5280 sec. 7.1 rule, a distribution point
 * against the CRL's own `issuingDistributionPoint` where it states one -- and to the supplied `thisUpdate`.
 * A request naming both sends the dpn (sec. 4.3.4: the dpn choice when a distribution point name is
 * available) and holds the answer to the issuer as well. The issuer is REQUIRED, since a distribution
 * point name alone leaves the answer unbound: a complete CRL states no scope to compare it against.
 * Terminal `outcome`: `answered` (with `operation`, `present`, and the decoded `value`),
 * `rejected`, or `poll-timeout`. An absent response value is `present: false` with a null `value`, which is
 * how each of the four says "nothing available" -- never conflated with an empty result. Delayed delivery
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
 *   - `transport` -- injectable transport(request) -> {status, headers, body}; default pki.transport.https.
 *   - `tls` / `headers` / `timeout` / `maxResponseBytes` -- transport config + budgets.
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
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("cmp/bad-input", "opts must be an object");
  guard.identifier.assertKnownKeys(opts, KNOWN_SESSION_OPTS, _err, "cmp/bad-input", "unknown session opts field ");
  // Work on a SHALLOW COPY so a later normalization (e.g. an empty MAC trustAnchors list) never mutates the
  // caller's object -- which may be frozen or reused across sessions -- and normalizing a frozen input does not
  // throw a raw TypeError. Only top-level fields are reassigned; nested values are read, never mutated.
  opts = Object.assign({}, opts);
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
  // A MAC session's anchors are OPTIONAL (used only to validate the issued certificate's own chain, never the MAC
  // response authentication): an empty list means "no issued-cert chain validation", exactly like omitting it. The
  // signature branch above already rejects [] outright. Normalize the MAC empty list to absent so _validateLeaf /
  // _verifyOpts treat it uniformly -- otherwise the empty trust store reaches _engine.build and rejects the issued
  // certificate only in _finish, AFTER the authenticated grant has consumed the one-shot session. This assigns to
  // the shallow COPY made above, never the caller's (possibly frozen) options object.
  if (isMac && Array.isArray(opts.trustAnchors) && opts.trustAnchors.length === 0) opts.trustAnchors = null;
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
      if (_es && Buffer.isBuffer(_es.tbsBytes)) {   // the documented already-parsed form (pki.schema.x509.parse output), detected like _certIdentity
        // The door's RETURN is what gets pinned, not the object handed in. coerceCert re-derives the
        // certificate from the bytes its parser read, so calling it only as a check and then storing
        // the caller's object keeps every edit the re-derivation exists to discard: this pin is
        // compared against each response signer's subject and SAN, so an edited one would accept a
        // different CMP signer than the caller meant to pin. A validator that normalizes has its
        // return value as its contract -- using it as a predicate throws that contract away.
        _expectedSenderCert = (_engine && _engine.coerceCert) ? _engine.coerceCert(_es) : _es;
      }
      else if (Buffer.isBuffer(_es) || _es instanceof Uint8Array) { _expectedSenderDer = Buffer.from(_es); _expectedSenderCert = x509.parse(_expectedSenderDer); }
      else if (typeof _es === "string") { _expectedSenderDer = x509.pemDecode(_es); _expectedSenderCert = x509.parse(_expectedSenderDer); }
      else { throw _err("cmp/bad-input", "opts.expectedSender must be a certificate DER Buffer / PEM string / parsed certificate"); }
    } catch (e) {
      if (e.isCmpError) throw e;
      throw _err("cmp/bad-input", "opts.expectedSender must be the CA signer certificate (DER Buffer / PEM / parsed) so every signed response can be bound to it -- " + ((e && e.message) || e), e);
    }
  }
  // Reject a DISTINCT intermediate pool exceeding the per-flavor cap (the candidate ceiling MINUS the room reserved
  // for the CA's own authenticated material). The caller pool is never truncated, so the whole pool + that material
  // must fit under path.build's ceiling; an oversized one would otherwise raise path/bad-input only at the first
  // verify, after the one-shot transaction is consumed. A MAC session reserves LESS (no signer chain), so its cap is
  // higher. (Duplicates collapse, so the count is by distinct id.)
  var maxIntermediates = isSig ? SESSION_MAX_INTERMEDIATES : SESSION_MAX_INTERMEDIATES_MAC;
  if (opts.intermediates != null) {
    var seenInt = Object.create(null), distinctInt = 0;
    _asCertList(opts.intermediates).forEach(function (c) { var k = _certIdentity(c); if (k == null) { distinctInt++; return; } if (!seenInt[k]) { seenInt[k] = 1; distinctInt++; } });
    if (distinctInt > maxIntermediates) throw _err("cmp/bad-input", "opts.intermediates has " + distinctInt + " distinct certificates, exceeding the " + maxIntermediates + " limit (room is reserved below the path-builder ceiling for the CA's own delivered issuer certificates" + (isSig ? " and signer chain" : "") + ")");
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
  // The transport, when supplied, must be a function -- a non-function value passes cmp.transfer's LOCAL url/budget
  // checks and then throws a raw TypeError when the transport is invoked, before any request is sent. That local
  // type error carries none of the typed cmp/* local codes, so the send path would mark the one-shot session
  // consumed on it. Reject it at construction so the transport call can only throw AFTER it has engaged the network.
  if (opts.transport != null && typeof opts.transport !== "function") throw _err("cmp/bad-input", "opts.transport must be a function (url, reqDer, opts) => Promise<{ responseBytes, status }>");
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
  var cachedChain = [];   // the VALIDATED signer chain (signer + the intermediates path.build used) from cmp.verify -- INDEPENDENT DER copies, so a later leg rebuilds the signer path from only trusted-path material (not paddable extraCerts) without pinning a response allocation
  var caPubsAccum = [];   // the AUTHENTICATED caPubs (issuer certs) accumulated across EVERY ip/cp/kup leg -- a CA may deliver the issuing chain in a `waiting` response and omit it from the eventual grant
  var caPubsSeen = Object.create(null);   // byte-identity dedup for caPubsAccum, bounding cross-leg accumulation (below)
  var caPubsBytes = 0;   // running total of retained caPubs bytes -- a transaction-wide byte budget (below) bounds it independent of the count cap, since a single certificate can approach the DER limit
  var caPubsWaitingCount = 0;   // WAITING-leg entries retained at the FRONT of caPubsAccum -- only these are evictable to fit a grant entry; a grant entry (at the back) is the issued leaf's own chain and is never evicted
  var activeCertReqId = DEFAULT_CERT_REQ_ID;   // the certReqId of the in-flight enrollment; echoed in pollReq / certConf
  var expectedRespArm = "ip";   // the response arm the in-flight transaction must be answered by (RESPONSE_ARM)
  // Which operation is in flight: it decides how the expected arm's body is read, and, for an error
  // body, whether a `waiting` status announces delayed delivery. RFC 9483 sec. 4.4 puts that status
  // in the ip/cp/kup of an enrollment and in an error message for every other operation, so the two
  // readings are exclusive rather than a leniency applied to both.
  var txnKind = "enroll";
  var expectedInfoOp = null;   // the INFO_OPS row of an in-flight support message
  var crlQuery = null;   // what a crlUpdate asked for: the encoded issuer Name and any thisUpdate
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
    // The one-shot `started` flag must flip iff a request MAY have reached the transport, so the caller can fix a
    // purely-local config error (url parse, transfer-budget caps, TLS-anchor check) and retry, but a request that
    // reached the CA is never silently replayed under the same transactionID/nonce. cmp.transfer runs those local
    // checks BEFORE it invokes the transport. A CUSTOM transport, though, can itself throw the SAME cmp/* codes as
    // those preflight checks AFTER receiving the request, so the error code cannot distinguish the two -- WRAP it so
    // `engaged` flips the instant cmp.transfer hands it the request (past its preflight). The DEFAULT transport never
    // reuses the preflight codes for its own network errors, so for it those codes reliably mean a pre-send failure.
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
    started = true;   // the transport returned a response -> the transaction has engaged, the session is consumed
    // The response's OWN deduped extraCerts (the signer + its delivered issuers) -- _verifyOpts folds them into the
    // signer-path pool as priority so cmp.verify needs no reserved room for its internal append. cmp.transfer has
    // already parsed res.responseBytes as a PKIMessage (its cmp.parse gate on every return path), so this cannot throw.
    var responseExtra = _responseExtraCerts(res.responseBytes);
    // The response's OWN issuers, the CACHED chain from an earlier authenticated leg, AND the whole caller pool fit
    // in ONE candidate pool (SESSION_MAX_INTERMEDIATES reserves room below the ceiling), so a single verify sees every
    // candidate -- no priority attempt has to choose between them, and a signer path assembled from any of the three
    // sources builds. cachedChain is included in the PRIMARY (not only the fallback) so a same-identity signer
    // rotation -- a later leg's extraCerts carries the rotated signer B, but B's issuer was delivered only alongside
    // signer A on an earlier leg -- resolves B from its own extraCerts AND chains it via the cached issuer, rather
    // than reporting B untrusted and falling through to a fallback that (forcing signer A's key) cannot verify B's
    // signature. No signer identification is needed (senderKID may name a cert that is not extraCerts[0]); every
    // candidate is simply present. cachedChain is [] before any response has authenticated, so this is inert then.
    var verdict = await cmp.verify(res.responseBytes, _verifyOpts(fresh, null, cachedChain, responseExtra));
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
      var extras = _responseExtraCerts(res.responseBytes);   // the response's own delivered extraCerts (bounded)
      // Cache the VALIDATED chain cmp.verify assembled (the signer + the intermediates path.build actually used),
      // NOT the raw extraCerts. extraCerts is UNSIGNED: a peer can pad it with the real signer plus unrelated
      // parseable certificates, and caching that raw list (even newest-first, bounded) would evict the issuer a
      // same-identity rotation relied on -- a subsequent bare leg from the rotated signer would then fail to chain.
      // verdict.signer.chain holds ONLY certificates on the trusted path, so the establishing issuer always
      // survives. Fall back to the delivered extraCerts if a chain is somehow absent (defensive; a trusted verdict
      // always carries one). Only refresh when the response delivered its OWN extraCerts (an extraCerts-less leg
      // keeps the prior chain).
      if (extras.length) {
        cachedSignerCert = Buffer.from(verdict.signer.cert);   // COPY: an extraCerts-resolved signer.cert is a slice of the response, so caching it raw pins that allocation (the chain is copied by cmp.verify; keep this one consistent)
        cachedChain = (Array.isArray(verdict.signer.chain) && verdict.signer.chain.length) ? verdict.signer.chain : extras;
      }
    }
    return verdict;
  }

  // Classify a verified response into a transaction transition. For ip/cp/kup, read the FIRST CertResponse
  // status; error carries a terminal PKIStatusInfo; pollRep drives the loop; any other arm is unexpected.
  function _classify(verdict) {
    var body = verdict.body || {};
    var arm = body.arm;
    if (arm === expectedRespArm && txnKind === "revoke") return _classifyRevRep(body);
    if (arm === expectedRespArm && txnKind === "info") return _classifyGenRep(body);
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
        if (caPubsSeen[k]) {
          // Already retained (from a waiting leg). On the GRANT leg it is the issued leaf's OWN material -- PROMOTE
          // it to the newest position so a LATER grant entry's eviction cannot drop it while its grant occurrence is
          // skipped as a duplicate. (A waiting-leg duplicate keeps its position; only the grant confers priority.)
          if (isGrantLeg) { for (var pi = 0; pi < caPubsAccum.length; pi++) { if (caPubsAccum[pi].toString("base64") === k) { caPubsAccum.push(caPubsAccum.splice(pi, 1)[0]); if (pi < caPubsWaitingCount) caPubsWaitingCount--; break; } } }
          return;
        }
        try { x509.parse(c); } catch (e) { throw _err("cmp/bad-cert-response", "an authenticated caPubs entry is not a valid X.509 certificate", e); }
        if (isGrantLeg) {
          // Evict ONLY the WAITING entries at the front to fit this grant entry -- never an earlier GRANT entry (the
          // issued leaf's own chain). Once no waiting entries remain, this grant entry is dropped by the cap below.
          while (caPubsWaitingCount > 0 && (caPubsAccum.length >= CAPUBS_MAX || caPubsBytes + c.length > caPubsByteBudget)) {
            var evicted = caPubsAccum.shift();
            caPubsBytes -= evicted.length;
            caPubsWaitingCount--;
            delete caPubsSeen[evicted.toString("base64")];   // keep the dedup set == the retained set, so a grant re-delivering an evicted issuer (also seen in a waiting leg) can re-add it
          }
        }
        if (caPubsAccum.length >= CAPUBS_MAX || caPubsBytes + c.length > caPubsByteBudget) return;   // no waiting entry left to evict (a grant would evict a grant) OR over budget -> drop
        caPubsSeen[k] = 1;
        caPubsBytes += c.length;
        caPubsAccum.push(Buffer.from(c));   // COPY out of the parser's subarray -- retaining the slice would pin the whole multi-MB response buffer, so caPubsBytes (the cert length) would not bound the real allocation across polls
        if (!isGrantLeg) caPubsWaitingCount++;   // a waiting entry joins the evictable front region
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

  // An error body. For a revocation or a support message it is ALSO how delayed delivery is announced:
  // RFC 9483 sec. 4.4 puts the "waiting" status in an ip/cp/kup for ir/cr/kur/p10cr "and for responses
  // to other request message types in an error message". An error answering an ENROLLMENT therefore
  // stays a rejection -- that operation announces its own delay in its own cert-response arm, so
  // reading waiting out of an error there would accept a shape the profile does not produce.
  function _classifyError(body) {
    var si = body.decoded && body.decoded.pKIStatusInfo;
    var code = si && si.status ? si.status.code : null;
    if (code === 3 && txnKind !== "enroll") return { state: "waiting", resp: { status: si } };
    return { state: "rejected", status: si };
  }

  // RevRepContent. RFC 9483 sec. 4.2: the response to an rr "MUST be an rp message containing a single
  // status field", whose positive value is "accepted" and negative "rejection", with failInfo "MUST be
  // absent if the status is accepted". A status with no transition here is a hard stop, never a verdict.
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

  // GenRepContent. RFC 9483 sec. 4.3: a genp "MUST contain a sequence of one element of type
  // InfoTypeAndValue" whose infoType names the operation. The OID is checked against the RESPONSE
  // side of the INFO_OPS row, which for rootCaCert is not the OID the request carried.
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
    // SNAPSHOT: this is held in session state across the transport round trip and then compared
    // against the issued certificate's key, so an alias would let the caller rewrite the key the
    // response is checked against after the request went out.
    if (Buffer.isBuffer(pk) || pk instanceof Uint8Array) return guard.bytes.snapshot(pk, CmpError, "cmp/bad-input", "the certTemplate publicKey");
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
    var added = _asCertList(opts.intermediates);   // the caller pool (config-bounded to SESSION_MAX_INTERMEDIATES)
    if (Buffer.isBuffer(cachedSignerCert)) added.push(cachedSignerCert);   // the CMP signer MAY be the issued leaf's issuer (a combined CA)
    // cachedChain holds the VALIDATED signer chain from cmp.verify as independent DER copies (or delivered
    // extraCerts DER on the defensive fallback) -- path.build's coerceCert parses each, so add them directly.
    cachedChain.forEach(function (c) { if (Buffer.isBuffer(c)) added.push(c); });
    // ONE candidate pool holds everything: the AUTHENTICATED caPubs (the CA's OWN issuer chain for this leaf) as the
    // priority base -- never evicted -- then the whole caller pool + cached signer chain. All fit under the ceiling
    // (caPubs <= CAPUBS_MAX, cached chain <= MAX_EXTRA_CERTS, caller <= SESSION_MAX_INTERMEDIATES = ceiling minus
    // both), so a path assembled from the caPubs AND a late caller intermediate builds in this single attempt.
    var pool = _boundedPool(caPubsList, added);
    var res;
    try { res = await _engine.build(leaf, { trustAnchors: _asCertList(opts.trustAnchors), intermediates: pool, validate: true, time: opts.time != null ? opts.time : new Date() }); }
    catch (e) {
      if (e.code === "path/bad-input") throw _err("cmp/bad-input", "invalid trust / validation options for issued-certificate validation: " + (e.message || e), e);
      // path.build THROWS path/no-path when the issued leaf cannot chain to a supplied anchor -- a CA that grants a
      // certificate whose issuer it never delivered. Re-type it to the domain error so the transaction fails closed
      // before confirmation, never leaking a path/* code.
      throw _err("cmp/bad-cert-response", "the issued certificate could not be validated to a supplied trust anchor: " + (e.message || e), e);
    }
    if (!res || res.valid !== true) throw _err("cmp/bad-cert-response", "the issued certificate did not validate to a supplied trust anchor (its signature or chain is invalid) (RFC 5280 sec. 6.1)");
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

  // One transaction per session (RFC 9810 sec. 5.1.1: one transactionID per transaction). A second or
  // concurrent call on any verb would reuse this transaction's transactionID / nonce chain / certReqId --
  // a replay or a corrupted interleave -- so it is refused. Every verb checks this BEFORE marking the
  // transaction in flight, so a malformed-request call does not consume the session.
  function _assertFresh(what) {
    if (completed || inFlight) {
      throw _err("cmp/bad-input", "this pki.cmp.session transaction is already " + (completed ? "completed" : "in flight") + "; create a new session per " + what + " (RFC 9810 sec. 5.1.1: one transactionID per transaction)");
    }
  }

  // The shared tail of a non-enrollment transaction: send the one request, poll through a delayed
  // delivery, and hand back the terminal classification. Both verbs reach a verdict the same way, so
  // the poll budget, the nonce chaining and the verify-before-read ordering cannot differ between them.
  async function _runOneShot(bodySpec, arm, kind) {
    txnKind = kind;
    expectedRespArm = RESPONSE_ARM[arm];
    // A pollReq raised by this transaction refers to the whole message (RFC 9483 sec. 4.4).
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

  // The transaction driver: build the initial request arm, send it, then poll / confirm / terminate.
  async function enroll(request) {
    _assertFresh("enrollment");
    if (!request || typeof request !== "object" || Buffer.isBuffer(request)) throw _err("cmp/bad-input", "enroll(request) requires a body spec object { ir | cr | kur | p10cr }");
    // A key here that is not an arm needs no door of its own: this whole object becomes the message
    // body, and pki.cmp.build counts the body's keys without filtering out the null-valued ones, so
    // a misspelling set to null is already refused there ("must have exactly one arm, got 2"). The
    // info() request is the opposite case and does carry a door, because that object is read for a
    // name and never handed to the builder.
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
      txnKind = "enroll";
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

  // RFC 9483 sec. 4.2: "The revocation request message MUST be signed using the certificate that is to
  // be revoked to prove the authorization to revoke." The signature over this message IS the
  // authorization, so the certificate named in certDetails has to be the one this session protects with.
  // Both request shapes are compared here, through the same encode-then-read path, so the certificate
  // form and the explicit certDetails form cannot diverge on what counts as the same certificate.
  // The issuer comparison is the RFC 5280 sec. 7.1 canonical one, since two spellings of a
  // distinguished name name the same issuer and a byte compare would refuse a caller who wrote it out.
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
    return own;   // the parsed session certificate, so the response's revCerts can be bound to it
  }

  // An rp MAY name the certificates it revoked in revCerts (RFC 4210 RevRepContent). This session
  // revokes exactly one -- its own -- so a conforming rp names exactly that one, and a response that
  // names another issuer/serial, or several, is not a verdict about this request. Left unbound, a
  // verified verdict would report an unrelated certificate as revoked. Compared to the session
  // certificate `own` the request was already held to, by serialNumber and the RFC 5280 sec. 7.1
  // canonical issuer rule. A CertId issuer is a GeneralName; a certificate's issuer is a directoryName,
  // so any other arm cannot name the revoked certificate.
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

  /**
   * Request revocation of this session's own certificate (RFC 9483 sec. 4.2).
   * `request` is `{ certificate }` or `{ certDetails: { issuer, serialNumber } }`, plus an optional
   * `reason` (a CRLReason name). Returns a terminal verdict: `revoked`, `rejected`, or `poll-timeout`.
   */
  async function revoke(request) {
    _assertFresh("revocation");
    if (!request || typeof request !== "object" || Buffer.isBuffer(request)) throw _err("cmp/bad-input", "revoke(request) requires an object { certificate | certDetails, reason? }");
    guard.identifier.assertKnownKeys(request, KNOWN_REVOKE_KEYS, _err, "cmp/bad-input", "unknown revoke request field ");
    // A PBMAC1 session shares a secret with the CA; it holds no certificate, so it has nothing to sign
    // the request with and no way to demonstrate which certificate it is entitled to revoke.
    if (isMac) throw _err("cmp/bad-input", "a PBMAC1 session cannot revoke: the request must be signature-protected with the certificate being revoked (RFC 9483 sec. 4.2). Use a signature session ({ key, cert }).");
    // Each field is read ONCE, here, and every use below is of the value that was read. A caller
    // field can be an accessor, so a second read can answer with a different certificate or reason
    // from the one that was checked, and the message would carry what the checks never saw.
    var certificateArg = request.certificate, reasonArg = request.reason;
    var certDetails = request.certDetails;
    if ((certificateArg == null) === (certDetails == null)) {
      throw _err("cmp/bad-input", "revoke(request) names the certificate by EXACTLY ONE of certificate (the certificate itself) or certDetails ({ issuer, serialNumber })");
    }
    if (reasonArg != null && (typeof reasonArg !== "string" || !CRL_REASON_NAMES[reasonArg])) {
      throw _err("cmp/bad-input", "revoke request.reason must be a CRLReason name (RFC 5280 sec. 5.3.1); got " + JSON.stringify(reasonArg));
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
    // Encode the CertTemplate HERE rather than letting cmp.build do it, so the identity check below
    // reads the same bytes the message will carry instead of a second interpretation of the spec.
    var certTemplateDer;
    try {
      certTemplateDer = crmfSign.buildCertTemplate(certDetails);
    } catch (e) {
      if (e && e.isCmpError) throw e;
      throw _err("cmp/bad-rev-req", "revoke request.certDetails must be a CertTemplate naming issuer and serialNumber -- " + ((e && e.message) || e), e);
    }
    var own = _assertRevokingOwnCertificate(certTemplateDer);
    // sec. 4.2: exactly one RevDetails, and crlEntryDetails REQUIRED carrying one reasonCode. The
    // builder emits the reasonCode even at unspecified(0), which the same clause requires.
    var body = { rr: [{ certDetails: certTemplateDer, crlEntryDetails: { reason: reasonArg == null ? undefined : reasonArg } }] };
    inFlight = true;
    try {
      var out = await _runOneShot(body, "rr", "revoke");
      if (out.timeout) return _terminal("poll-timeout", { status: out.status, polls: out.polls });
      var t = out.done;
      if (t.state === "granted") {
        return _terminal("revoked", {
          status: t.status, polls: out.polls,
          revokedCerts: _bindRevCerts(t.revCerts, own),   // the CertIds the responder confirms it revoked, bound to the certificate this session revoked
          // An rp MAY deliver CRLs, and the schema reads those slots as raw SEQUENCEs for the same
          // reason it does in a genp. They are surfaced on a verdict an operator acts on, so they
          // are held to being CertificateLists here, exactly as the support-message values are.
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

  /**
   * Ask the PKI management entity for one of the RFC 9483 sec. 4.3 support values.
   * `request` names exactly one operation: `{ caCerts: true }`, `{ rootCaCert: <cert> }`,
   * `{ certReqTemplate: true }`, or `{ crlUpdate: { issuer, dpn?, thisUpdate? } }`.
   * Returns a terminal verdict: `answered` (with `value` and `present`), `rejected`, or `poll-timeout`.
   */
  async function info(request) {
    _assertFresh("support message");
    if (!request || typeof request !== "object" || Buffer.isBuffer(request)) throw _err("cmp/bad-input", "info(request) requires an object naming one support operation (caCerts / rootCaCert / certReqTemplate / crlUpdate)");
    // The name door runs BEFORE the arm count, so a key that is not an operation is refused whatever
    // its value is. Counting non-null keys alone would let a misspelled one set to null pass as
    // absent, and the caller would watch a different operation go out than the one they wrote.
    guard.identifier.assertKnownKeys(request, INFO_OPS, _err, "cmp/bad-input", "unknown info request field ");
    // Each field is read ONCE, here, and everything below uses the value that was read. A caller
    // field can be an accessor, so a second read can answer with a different request from the one
    // the arm count was taken over, and what goes on the wire would not be what was checked.
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
    // sec. 4.3.1 and sec. 4.3.3 both make the request infoValue absent; the other two carry one.
    // For the two that carry none, the only accepted value is `true` -- a caller who supplies a
    // certificate or a template to one of them means something this operation cannot send, and
    // taking it silently would have the request go out without the constraint they wrote.
    if (op.value === false) {
      if (asked !== true) throw _err("cmp/bad-input", "info request." + op.name + " takes `true`: this operation's genm carries no infoValue (RFC 9483 sec. 4.3.1 and sec. 4.3.3)");
    } else if (op.value === "cert") {
      // sec. 4.3.2: the request SHOULD carry the root CA certificate the update is requested for,
      // and the field is a CMPCertificate. It goes through the SAME door revoke() gives a
      // certificate -- DER, PEM, or an already-parsed one -- because it is the same kind of value
      // and a caller should not have to remember which of the two verbs takes which form. Holding
      // it to being a certificate here keeps a mistake a local refusal; sending it unchecked would
      // put a malformed request on the wire and consume this one-shot transaction to learn what the
      // caller could have been told before it started.
      itav.infoValue = _certificateArgument(asked, "info request rootCaCert");
    } else if (op.value === "crlStatus") {
      var built = cmpBuild.buildCrlStatusList(asked);
      itav.infoValue = built.der;
      // What the request asked for, kept so the answer can be held to it. sec. 4.3.4 says the
      // responder returns the latest CRL FROM THE REFERENCED SOURCE, and only when it is more
      // recent than a supplied thisUpdate; in every other case the response value is absent.
      // The cutoff comes back FROM the builder, which read it once while encoding. Reading the
      // caller's field a second time here would let an accessor, or a Date moved during the
      // transport round-trip, judge the response against a query the request never carried.
      crlQuery = { issuerName: built.issuerName, thisUpdate: built.thisUpdate, dpn: built.dpn };
    }
    expectedInfoOp = op;
    inFlight = true;
    try {
      var out = await _runOneShot({ genm: [itav] }, "genm", "info");
      if (out.timeout) return _terminal("poll-timeout", { operation: op.name, status: out.status, polls: out.polls });
      var t = out.done;
      if (t.state === "granted") {
        // sec. 4.3: the infoValue is OPTIONAL in every one of the four responses, and its absence is
        // the answer "nothing is available" rather than a malformed message -- so `present` reports
        // which of the two a caller received, and never conflates them into an empty value.
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

  // The RFC 9483 profile rules that sit ON TOP of the RFC 9480 syntax the decoders enforce. Each is a
  // requirement the ASN.1 cannot express, so a structurally valid response can still be non-conforming.
  // `requestValue` is the infoValue this operation SENT, which the rootCaCert rules compare against:
  // the old root the caller named is what the update has to chain from. It is read here rather than
  // off `request`, so the comparison uses the bytes that went on the wire.
  function _checkInfoValue(op, value, requestValue) {
    if (op.name === "rootCaCert") {
      // sec. 4.3.2 makes newWithOld REQUIRED of a response ("it is needed for the receiving entity
      // trusting the old root CA certificate to gain trust in the new one"), where RFC 9480's ASN.1
      // marks it OPTIONAL. Without it the update cannot be trusted by the entity that asked for it.
      if (value.newWithOld == null) throw _err("cmp/bad-info-value", "a rootCaKeyUpdate response must carry newWithOld -- the certificate that lets an entity trusting the OLD root gain trust in the new one (RFC 9483 sec. 4.3.2)");
      return _checkRootCaKeyUpdate(value, requestValue);
    }
    if (op.name === "certReqTemplate") {
      var t = value.certTemplate;
      // sec. 4.3.3: "The publicKey field of type SubjectPublicKeyInfo in the CertTemplate of the
      // CertReqTemplateValue MUST be omitted", and "the serialNumber, signingAlg, issuerUID, and
      // subjectUID fields MUST be omitted". A template stating a key would tell an entity to request
      // a certificate over a key the responder chose, which is what the keySpec field exists to avoid.
      ["publicKey", "serialNumber", "signingAlg", "issuerUID", "subjectUID"].forEach(function (f) {
        if (t[f] != null) throw _err("cmp/bad-info-value", "a certReqTemplate certTemplate must omit " + f + " (RFC 9483 sec. 4.3.3)");
      });
      if (value.keySpec != null) value.keySpec.forEach(_checkKeySpec);
      return value;
    }
    if (op.name === "caCerts") return value.map(function (d) {
      // sec. 4.3.1 returns CA certificates for chain construction, so each is held to being one: an
      // authenticated responder placing an end-entity certificate here would hand back a list nothing
      // can chain through. The same CA-capability rule the rootCaKeyUpdate rollover certificates get.
      var der = _asCertificate(d, "a caCerts entry");
      _assertCaCapable(x509.parse(der), "caCerts entry");
      return der;
    });
    if (op.name === "crlUpdate") return value.map(_bindCrlToQuery);
    // Unreachable while INFO_OPS holds exactly the four operations above, each with a branch here.
    // It refuses rather than passing the value through, so adding a fifth operation without its
    // profile rules fails at once instead of surfacing a value nothing checked.
    throw _err("cmp/bad-info-value", "no response rules are defined for the " + op.name + " support message");
  }

  // A support-message response is surfaced as an ANSWER an operator acts on, so what it carries is
  // held to being the structure it claims. The CMP schema reads these slots as raw SEQUENCEs on
  // purpose (the parser confers no trust and a CMPCertificate slot is opaque to it), which leaves
  // "is this actually a certificate" to the verb that hands the bytes back -- the same division
  // this module already applies to an authenticated caPubs entry. Without it a responder could
  // answer a chain-construction request with any well-formed SEQUENCE and have it read as a
  // certificate, and a CRL request with a certificate. Returns a COPY, since the decoded value is
  // a slice of the response buffer.
  // A root CA key update is three certificates in NAMED relationships, and the relationships are the
  // whole mechanism (RFC 9483 sec. 4.3.2): newWithOld carries "the new public root CA key signed
  // with the old private root CA key", which is what lets an entity that trusts the old root reach
  // the new one, and oldWithNew carries "the old public root CA key signed with the new private root
  // CA key" for the reverse. Three certificates that merely parse establish neither, so a responder
  // could answer with any three it holds and the update would be reported as usable. Each signature
  // is checked by the path engine, so the EdDSA low-order-point and algorithm-confusion gates apply
  // here as they do to any other untrusted signature.
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
    // A key alone does not make a trust transition. If the old CA has ever signed ANY certificate
    // for the new key -- an ordinary end-entity certificate its holder legitimately obtained --
    // then key equality plus a valid signature is satisfied by that certificate, and its holder
    // could pair it with a self-signed newWithNew of their own choosing and have the result read as
    // the authority's own rollover. What sec. 4.3.2 describes is a certificate FOR the new root
    // issued BY the old one, so both names are bound too, under the RFC 5280 sec. 7.1 comparison.
    _assertSameName(pNewOld.issuer, pOldRoot.subject, "newWithOld", "be issued by the OLD root named in the request");
    _assertSameName(pNewOld.subject, pNewNew.subject, "newWithOld", "name the same subject as newWithNew, the certificate it vouches for");
    // newWithNew is the replacement certificate, and for a root it is self-issued, so its own key is
    // the only thing that can vouch for the name, validity and extensions the caller would install.
    // sec. 4.3.2's note extends this operation to "trusted non-root certificates, e.g., directly
    // trusted intermediate or issuing CA certificates", and such a certificate is signed by an
    // issuer this message does not carry -- there is nothing here to check it against, and claiming
    // otherwise would refuse a use the profile allows. So the signature is verified exactly when it
    // is verifiable: when the certificate is self-issued. Either way the new KEY is authenticated by
    // newWithOld below, which the old root signed and which must carry this same key.
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
  // A certificate a caller will build a chain from -- a rootCaKeyUpdate rollover certificate or a
  // caCerts entry -- has to actually be a CA. Names, a key and a signature are satisfied by an
  // ordinary end-entity certificate that certifies nothing, so surfacing one as an issuer reports the
  // answer as usable while handing back a list nothing can chain through. The rule is RFC 5280 sec.
  // 6.1.4's, the one pki.path.validate applies to any intermediate: basicConstraints cA TRUE, marked
  // critical (sec. 4.2.1.9), and keyUsage, where present, allowing keyCertSign. Criticality matters
  // because a relying party that skips extensions it does not recognize would not see the cA bit at
  // all, which is why the path validator refuses a non-critical cA:TRUE; this check holds to the same
  // line so the two never disagree on what a CA certificate is. `which` names the surface for the
  // error. Extensions are read through the shared certificate-extension decoders rather than walked here.
  function _assertCaCapable(cert, which) {
    var bc = null, ku = null, bcCritical = false;
    cert.extensions.forEach(function (e) {
      if (e.oid === OID_BASIC_CONSTRAINTS) { bc = cmpBuild.decodeCertExtension(e.oid, e.value); bcCritical = e.critical === true; }
      if (e.oid === OID_KEY_USAGE) ku = cmpBuild.decodeCertExtension(e.oid, e.value);
    });
    if (!bc || bc.cA !== true) {
      throw _err("cmp/bad-info-value", "the " + which + " must be a CA certificate (basicConstraints cA TRUE): an end-entity certificate certifies nothing and cannot serve as an issuer for chain construction (RFC 5280 sec. 6.1.4)");
    }
    if (!bcCritical) {
      throw _err("cmp/bad-info-value", "the " + which + " marks basicConstraints non-critical, so a relying party that skips unrecognized extensions would not see the cA bit it must act on (RFC 5280 sec. 4.2.1.9)");
    }
    if (ku && ku.keyCertSign !== true) {
      throw _err("cmp/bad-info-value", "the " + which + " carries a keyUsage that withholds keyCertSign, so it cannot sign certificates as a CA must (RFC 5280 sec. 6.1.4)");
    }
  }

  // Names are compared through guard-name's RFC 5280 sec. 7.1 canonical rule, the one place a
  // distinguished-name identity is decided here: two spellings of the same name are the same
  // authority, and a byte compare would refuse a re-encoded but equal one.
  function _assertSameName(a, b, which, must) {
    if (!guard.name.dnEqual(a.rdns, b.rdns, _err, "cmp/bad-info-value", "a rootCaKeyUpdate name")) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate " + which + " must " + must + " (RFC 9483 sec. 4.3.2); got " + JSON.stringify(a.dn));
    }
  }
  async function _assertSignedBy(cert, signer, which, whose) {
    if (!_engine || !_engine.verifyWithSpki) {
      throw _err("cmp/bad-info-value", "the signature engine is unavailable, so a rootCaKeyUpdate cannot be checked; require pki.path to install it");
    }
    // The signature is a BIT STRING and a valid one is octet-aligned (no unused bits). Passing only its
    // octets to the engine would drop the unusedBits metadata, so a signature declaring unused bits would
    // verify on its octets while being a malformed shape the path verifier refuses (path-validate) before
    // the engine. Hold a rollover signature to the same rule.
    if (!guard.crypto.isOctetAligned(cert.signatureValue)) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate " + which + " signature is not octet-aligned (a BIT STRING with unused bits), which no valid signature is (RFC 9483 sec. 4.3.2)");
    }
    var ok = await _engine.verifyWithSpki(cert.signatureAlgorithm, cert.signatureValue.bytes, signer.subjectPublicKeyInfo.bytes, cert.tbsBytes);
    if (ok !== true) {
      throw _err("cmp/bad-info-value", "the rootCaKeyUpdate " + which + " is not signed by " + whose + ", so it cannot carry the trust transition it exists for (RFC 9483 sec. 4.3.2)");
    }
  }

  // A certificate this verb has to put BACK on the wire, so it takes the two forms that carry their
  // own bytes: DER, and PEM which decodes to them. An already-parsed certificate is refused rather
  // than re-encoded -- the parsed form retains no source DER, and rebuilding one would emit bytes
  // that are not the ones the issuer signed. revoke() takes the parsed form because it reads an
  // issuer and a serial out of it and never re-emits the certificate itself.
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

  // `code` names the boundary: a response value is malformed protocol (cmp/bad-info-value), while a
  // value the CALLER supplied for a request is an authoring error (cmp/bad-input), and the two must
  // not read alike to whoever catches them.
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
  // sec. 4.3.4 does not say "a CRL", it says the latest one FROM THE REFERENCED SOURCE, and only
  // when it is more recent than a supplied thisUpdate; in every other case the value is absent.
  // A CRL that answers some other query is not the answer to this one, and reporting it as one
  // hands the caller a list whose scope they did not ask about.
  //
  // The issuer arm is bound by name. The dpn arm is bound where a CRL says which point it speaks
  // for: RFC 5280 sec. 5.2.5 puts that in the issuingDistributionPoint extension, and sec. 4.3.4's
  // own note points there for where a distribution point name comes from. A CRL carrying no such
  // scope is claiming to be its issuer's complete list, which sec. 5.2.5 permits and which answers
  // a request for any point of that issuer, so there is nothing to refuse -- and nothing to bind,
  // since the request named no issuer. The freshness rule applies to both arms.
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
      // The comparison is the one the path validator applies to a shard CRL, so a CRL either speaks
      // for the point this request named or it does not, and the answer does not depend on which verb
      // is asking. Only a CRITICAL issuingDistributionPoint establishes that scope (sec. 5.2.5): a
      // relying party may ignore a non-critical one, so a scope it could ignore cannot bind the answer
      // to the named point -- the path validator makes the same fail-closed decision for a shard CRL.
      // A CRL naming no point is a complete list and is left to the freshness rule.
      if (idpDpn !== null && (!idpCritical || !guard.name.dpnCorresponds(crlQuery.dpn, idpDpn, _err, "cmp/bad-info-value", "the crlUpdate distribution point"))) {
        throw _err("cmp/bad-info-value", "the returned CRL is scoped to a distribution point other than the one this request named, or marks that scope non-critical where a relying party may ignore it (RFC 9483 sec. 4.3.4, RFC 5280 sec. 5.2.5)");
      }
    }
    if (crlQuery && crlQuery.thisUpdate != null) {
      var asked = crlQuery.thisUpdate;   // already an instant, reduced when the request was built
      // The CRL's own thisUpdate goes through the same door: it arrived from a responder, so it is
      // the side more likely to be missing or unusable, and reading its epoch value directly would
      // compare NaN and quietly answer false.
      var got = guard.time.instantOf(parsed.thisUpdate, _err, "cmp/bad-info-value", "the returned CRL's thisUpdate");
      if (got <= asked) {
        throw _err("cmp/bad-info-value", "the returned CRL is no more recent than the thisUpdate this request supplied, so sec. 4.3.4 requires the response to carry no value at all");
      }
    }
    return Buffer.from(der);
  }

  var OID_REG_CTRL_ALG_ID = oid.byName("algId");
  var OID_REG_CTRL_RSA_KEY_LEN = oid.byName("rsaKeyLen");
  // True for an RSA algorithm, which sec. 4.3.3 excludes from a keySpec algId (RSA uses rsaKeyLen).
  // Membership is decided by OID family: any OID under the PKCS#1 arc, plus the two RSA identifiers
  // that sit off it. A standardized RSA OID the registry has not named (sha1WithRSAEncryption, the
  // md*/sha224 variants) is still under the arc, so it is caught without being listed. An OID that is
  // not an encodable dotted string, or one outside every RSA arc, is NOT RSA here -- it is surfaced.
  function _isRsaAlgorithm(dotted) {
    var arcs = oid.toArcs(dotted);   // dotted is a decoded OID string (readAlgorithmIdentifier), always encodable
    var underAny = false;
    for (var a = 0; !underAny && a < RSA_ARCS.length; a++) {
      var arc = RSA_ARCS[a];
      if (arcs.length > arc.length) {   // the arc node itself is not an algorithm
        underAny = true;
        for (var i = 0; underAny && i < arc.length; i++) { underAny = arcs[i] === arc[i]; }
      }
    }
    return underAny || RSA_OFF_ARC[dotted] === 1;
  }
  // sec. 4.3.3: a keySpec element carries "attribute id-regCtrl-algId or id-regCtrl-rsaKeyLen", the
  // first "MUST be of type AlgorithmIdentifier and give an algorithm other than RSA", the second
  // "MUST be a positive integer value". A control outside the pair states a requirement this
  // operation has no meaning for, so it is refused rather than surfaced as an understood one.
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
      // Read through the shared AlgorithmIdentifier sub-schema rather than probing the node, so the
      // structure is held to its whole definition: a SEQUENCE of an OID and at most one parameters
      // field. A hand-rolled tag test says only that the first child is an OID, which a SEQUENCE of
      // three fields also satisfies -- and that value would then reach the caller as an algorithm
      // requirement no conforming responder can have meant.
      var alg;
      try { alg = schemaCmp.readAlgorithmIdentifier(ctrl.value); }
      catch (e) {
        if (e && e.isCmpError) throw e;
        throw _err("cmp/bad-info-value", "a keySpec algId must be an AlgorithmIdentifier (RFC 9483 sec. 4.3.3)", e);
      }
      // sec. 4.3.3 / RFC 9480 sec. 2.16 hold the algId to ONE rule: not RSA. A known RSA algorithm is
      // refused (its requirement is stated with rsaKeyLen); every other value -- a known non-RSA
      // algorithm OR an OID the registry does not name -- is surfaced. The responder offers one control
      // per algorithm it supports and the entity picks one, so an unrecognized offer must not fail the
      // whole exchange.
      if (_isRsaAlgorithm(alg.oid)) {
        throw _err("cmp/bad-info-value", "a keySpec algId must give an algorithm other than RSA, whose requirement is stated with rsaKeyLen instead (RFC 9483 sec. 4.3.3); got " + (alg.name || alg.oid));
      }
      ctrl.algorithm = alg.oid;
      ctrl.algorithmName = alg.name;   // null for an OID the registry does not name -- surfaced as-is for the caller to weigh
      ctrl.algorithmParameters = alg.parameters;
      return;
    }
    throw _err("cmp/bad-info-value", "a keySpec control must be id-regCtrl-algId or id-regCtrl-rsaKeyLen (RFC 9483 sec. 4.3.3); got " + ctrl.type);
  }

  return {
    enroll: enroll,
    revoke: revoke,
    info: info,
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
