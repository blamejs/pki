// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module pki.path
 * @nav Path validation
 * @title Certification path validation (RFC 5280 6)
 * @fullname Certificate chain validation (RFC 5280 sec. 6 path validation)
 * @intro
 * RFC 5280 6 certification-path validation as a pure, re-entrant algorithm
 * over already-parsed certificates. `pki.path.validate(path, opts)` runs the
 * 6.1 state machine -- signature chaining, validity windows, name chaining,
 * basic constraints and path length, key usage, name constraints, and the
 * certificate-policy tree -- and returns a structured verdict with a per-check
 * reason code for every step. Validity-window enforcement is always on, with
 * the check date an explicit input; the trust anchor is an input, never one of
 * the validated certificates, and no input object is mutated.
 *
 * Revocation is a pluggable hook: `pki.path.crlChecker(crls)` ships a CRL
 * consultation built on `pki.schema.crl.parse`; an OCSP checker satisfies the
 * same interface. Signature verification derives its algorithm from the
 * certificate and the issuer key -- never from a value the message controls --
 * and fails closed on an unknown critical extension, an undetermined
 * revocation status, or any structural fault.
 *
 * @card
 *   RFC 5280 6 certification-path validation -- run the 6.1 state machine over
 *   an ordered path and a trust anchor for a structured, fail-closed verdict
 *   with per-check reason codes. Pure and re-entrant.
 */

var webcrypto = require("./webcrypto");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var errors = require("./framework-error");
var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");
var ocsp = require("./schema-ocsp");
var ocspVerify = require("./ocsp-verify");
var crlVerify = require("./crl-verify");
var csrVerify = require("./csr-verify");
var crmfVerify = require("./crmf-verify");
var attrcertVerify = require("./attrcert-verify");
var cmpVerify = require("./cmp-verify");
var cmsVerify = require("./cms-verify");
var cmpSession = require("./cmp-session");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var constants = require("./constants");
var validator = require("./validator-all");
var cms = require("./schema-cms");
var httpTransport = require("./http-transport");
var net = require("net");
var compositeSig = require("./composite-sig");
var edwardsPoint = require("./edwards-point");

var PathError = errors.PathError;
function E(code, message, cause) { return new PathError(code, message, cause); }
// Every code placed into the public validate() verdict must be a path/* code.
// A direct DER decode (resolveDescriptor's asn1.decode, run outside the ns-
// wrapping schema engine) can throw a raw asn1/* Asn1Error; normalize any
// non-path error code to the given path/* fallback so an internal domain code
// never leaks into the documented verdict. The original error is kept as `error`.
function pathCode(e, fallback) {
  return (e && typeof e.code === "string" && e.code.indexOf("path/") === 0) ? e.code : fallback;
}

// Membership decided by comparison rather than by a prototype method, through the shared guard.
// Every use below is a RULE: whether a certificate's extended key usages cover the ones the caller
// required, whether a policy is already expected at a node, whether anyPolicy is in the user's
// initial set. See guard-list for what a replaced Array.prototype.indexOf did to this validator.
var contains = guard.list.contains;
var containsAll = guard.list.containsAll;
// RFC 5280 6.1.4(a): a policyMappings extension MUST NOT map to or from anyPolicy. The scan for a
// violating pair is the rule, so it routes through the guard for the same reason.
function mapsAnyPolicy(mappings) {
  return guard.list.anyMatches(mappings, function (m) {
    return !!m && (m.issuerDomainPolicy === OID.anyPolicy || m.subjectDomainPolicy === OID.anyPolicy);
  });
}

var NS = pkix.makeNS("path", PathError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
// Validates a trust-anchor tuple's raw publicKey as a COMPLETE SubjectPublicKeyInfo (AlgorithmIdentifier +
// key BIT STRING), not just a decodable first OID -- a structurally-incomplete SPKI must fail closed at the
// anchor door, not slip through to a soft valid:false when key import later rejects it.
var ANCHOR_SPKI_SCHEMA = pkix.spki(NS);
// A trust anchor carries a CLOSED, producer-derived field set -- the shape pki.trust.parseCertdata documents
// and path validation + trust dedup consume: name, publicKey, algorithm, parameters, purposes, distrustAfter,
// subjectDer, label, mozillaCaPolicy. Normalizing a caller tuple reads each of those fields exactly once (by
// property access, which follows the prototype chain, so an inherited restriction is kept) and builds a fresh
// object from those reads -- publicKey pinned to a private copy, algorithm/parameters taken from the validated
// SubjectPublicKeyInfo (never the caller's declared value), the validation-read metadata (name, purposes,
// distrustAfter) materialized as DATA because validation reads each more than once and a live accessor could
// answer inconsistently. entry's own shape is NEVER enumerated (no `in` / ownKeys / getOwnPropertyDescriptor)
// and the prototype chain is never walked, so a Proxy anchor cannot use an enumeration trap to mutate state
// mid-normalization and a hostile getPrototypeOf cannot be driven into a loop (Buffer.isBuffer invokes
// getPrototypeOf once). A field the caller attached OUTSIDE the closed set is not carried. See toAnchor.

var subtle = webcrypto.webcrypto.subtle;

var OID = {
  basicConstraints: oid.byName("basicConstraints"),
  keyUsage: oid.byName("keyUsage"),
  nameConstraints: oid.byName("nameConstraints"),
  certificatePolicies: oid.byName("certificatePolicies"),
  policyMappings: oid.byName("policyMappings"),
  policyConstraints: oid.byName("policyConstraints"),
  inhibitAnyPolicy: oid.byName("inhibitAnyPolicy"),
  subjectAltName: oid.byName("subjectAltName"),
  anyPolicy: oid.byName("anyPolicy"),
  emailAddress: oid.byName("emailAddress"),
  extKeyUsage: oid.byName("extKeyUsage"),
  anyExtendedKeyUsage: oid.byName("anyExtendedKeyUsage"),
  cRLDistributionPoints: oid.byName("cRLDistributionPoints"),
  subjectKeyIdentifier: oid.byName("subjectKeyIdentifier"),
  authorityKeyIdentifier: oid.byName("authorityKeyIdentifier"),
  authorityInfoAccess: oid.byName("authorityInfoAccess"),
  caIssuers: oid.byName("caIssuers"),
};

// The set of extension OIDs the validator processes. An unrecognized critical
// extension outside this set fails the path (6.1.4(o), 6.1.5(e)).
// extendedKeyUsage is recognized: the critical form is legal (4.2.1.12) and
// appears in the wild (RFC 6960 4.2.2.2 delegated OCSP responders); its
// structure is validated wherever it is critical, and key-purpose enforcement
// is the caller's opt-in via opts.requiredEku (RFC 5280 6.1 defines no EKU
// processing step -- the required purpose is application context).
var PROCESSED_EXTENSIONS = {};
// cRLDistributionPoints is processed: the CRL checker consults it for the
// sec. 6.3.3 shard correspondence, and a critical instance (sec. 4.2.1.13 is a
// SHOULD-non-critical) is structurally validated by
// validateCriticalExtensionStructure via the registered decoder. freshestCRL
// stays OUT: sec. 4.2.1.15 requires it non-critical and the validator does not
// consult it (no delta merge), so a critical instance fails unrecognized.
// qcStatements is deliberately left unprocessed: a critical QC statement (QcLimitValue reliance limit,
// QcType certificate purpose) asserts qualified-certificate semantics a relying party MUST enforce, and
// this validator does not enforce them (nor expose a handler to). Marking it processed would let a caller
// treat a certificate as valid outside its asserted critical QC constraints, so a critical qcStatements
// fails as an unrecognized-critical extension (RFC 5280 sec. 6.1.4); a non-critical instance is
// informational and does not affect the verdict. The extension is still decoded for pki.inspect / lint.
[OID.basicConstraints, OID.keyUsage, OID.nameConstraints, OID.certificatePolicies,
 OID.policyMappings, OID.policyConstraints, OID.inhibitAnyPolicy, OID.subjectAltName,
 OID.extKeyUsage, OID.cRLDistributionPoints].
  forEach(function (o) { PROCESSED_EXTENSIONS[o] = true; });
// Frozen after seeding: this exact object is both consulted by the critical-extension check here and
// exported (for pki.lint to stay consistent). A caller must not be able to add an OID, because that
// would make an attacker's critical, decoder-less extension pass as "processed" and skip both the
// unrecognized-critical check and structural validation. Freezing makes any such write a no-op.
Object.freeze(PROCESSED_EXTENSIONS);

// ---- signature verify bridge (NEW 6) ---------------------------------------

// Signature-algorithm OID -> the WebCrypto verify descriptor + how to import
// the issuer SPKI. Keyed via oid.byName so no dotted-decimal OID literal
// appears in source (the registry owns arc<->name). The algorithm is a property
// of the CERTIFICATE and the issuer key, never of a message-selected field
// (CVE-2015-9235).
var SIG_ALGS = {};
// `params` is the REQUIRED AlgorithmIdentifier parameters shape: "null" (a DER
// NULL must be present -- RSASSA-PKCS1-v1_5, RFC 4055 sec. 5) or "absent" (parameters
// must be omitted -- ECDSA/EdDSA/ML-DSA, RFC 5758/8410). A cert deviating from
// its algorithm's required shape is malformed and rejected before verify.
// `sameKeyOid` marks the one-shot families whose public-key algorithm OID equals
// the signature algorithm OID: EdDSA, ML-DSA, SLH-DSA. For these, Node's
// WebCrypto imports an SPKI of another type under the requested name and verifies
// with the real key (unlike RSA/ECDSA, where a mismatched SPKI is refused at
// import), so the issuer-key <-> signature-algorithm consistency (RFC 9814 sec. 4)
// must be checked structurally: the SPKI OID must equal the signature OID.
function _sig(name, verify, imp, params, ecdsa, sameKeyOid) {
  var entry = { verify: verify, imp: imp, params: params };
  if (ecdsa) entry.ecdsa = true;
  if (sameKeyOid) entry.sameKeyOid = true;
  // EdDSA descriptors carry the Edwards curve id (6 = Ed25519, 7 = Ed448) so the verify path
  // validates the issuer point through the shared gate without re-branching on the algorithm name.
  if (verify.name === "Ed25519") entry.eddsa = 6;
  else if (verify.name === "Ed448") entry.eddsa = 7;
  SIG_ALGS[oid.byName(name)] = entry;
}
// RSASSA-PKCS1-v1_5 -- parameters MUST be NULL.
_sig("sha256WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, "null");
_sig("sha384WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, "null");
_sig("sha512WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, "null");
// ECDSA (hash in the OID; the curve comes from the imported key) -- params absent.
_sig("ecdsaWithSHA256", { name: "ECDSA", hash: "SHA-256" }, { name: "ECDSA" }, "absent", true);
_sig("ecdsaWithSHA384", { name: "ECDSA", hash: "SHA-384" }, { name: "ECDSA" }, "absent", true);
_sig("ecdsaWithSHA512", { name: "ECDSA", hash: "SHA-512" }, { name: "ECDSA" }, "absent", true);
// EdDSA (one-shot, no hash parameter) -- params absent; key OID == sig OID.
_sig("Ed25519", { name: "Ed25519" }, { name: "Ed25519" }, "absent", false, true);
_sig("Ed448", { name: "Ed448" }, { name: "Ed448" }, "absent", false, true);
// ML-DSA (FIPS 204) -- params absent; key OID == sig OID.
_sig("id-ml-dsa-44", { name: "ML-DSA-44" }, { name: "ML-DSA-44" }, "absent", false, true);
_sig("id-ml-dsa-65", { name: "ML-DSA-65" }, { name: "ML-DSA-65" }, "absent", false, true);
_sig("id-ml-dsa-87", { name: "ML-DSA-87" }, { name: "ML-DSA-87" }, "absent", false, true);
// SLH-DSA (FIPS 205) -- params absent; key OID == sig OID. The twelve pure sets;
// the RFC 9909 sec. 3 OID name maps to the WebCrypto set name by id-slh-dsa-<set> ->
// SLH-DSA-<SET> (the webcrypto SLH_DSA_NODE keys). One-shot verify like ML-DSA.
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (set) {
  var wc = "SLH-DSA-" + set.toUpperCase();
  _sig("id-slh-dsa-" + set, { name: wc }, { name: wc }, "absent", false, true);
});

// RSASSA-PSS resolves its hash + salt from the AlgorithmIdentifier parameters.
var OID_RSA_PSS = oid.byName("rsassaPss");
var OID_MGF1 = oid.byName("mgf1");
// SHA-1 is deliberately ABSENT -- a SHA-1 signature (PKCS#1 or PSS) is rejected,
// matching the no-sha1WithRSAEncryption posture (SHAttered chosen-prefix).
var HASH_BY_OID = {};
HASH_BY_OID[oid.byName("sha256")] = "SHA-256";
HASH_BY_OID[oid.byName("sha384")] = "SHA-384";
HASH_BY_OID[oid.byName("sha512")] = "SHA-512";

// The order-aware ECDSA DER->P1363 converter + its CURVE_FIELD_BYTES / CURVE_ORDER tables now
// live in validator-sig.js (validator.sig.ecdsaDerToP1363), shared with the composite engine.

// The algorithm OID of an AlgorithmIdentifier SEQUENCE { algorithm OID,
// parameters OPTIONAL }. STRICT: a universal SEQUENCE with the OID and AT MOST
// one optional parameters element -- a bare [n]-wrapped OID (no SEQUENCE) or a
// SEQUENCE carrying a spurious third element is malformed and must not be read
// leniently as its named algorithm.
function seqAlgOid(seq) {
  if (!seq || seq.tagClass !== "universal" || seq.tagNumber !== asn1.TAGS.SEQUENCE || !seq.children || seq.children.length < 1 || seq.children.length > 2) {
    throw E("path/unsupported-algorithm", "expected an AlgorithmIdentifier SEQUENCE { OID, parameters? }");
  }
  return asn1.read.oid(seq.children[0]);
}
// A hash AlgorithmIdentifier { OID, parameters? } whose parameters, when present,
// MUST be DER NULL (RFC 4055 sec. 2.1 / RFC 5754) -- never a SEQUENCE or arbitrary
// value. Used for the PSS hashAlgorithm and the MGF1 inner hash.
function hashAlgOid(seq) {
  var o = seqAlgOid(seq);
  if (seq.children.length === 2) {
    var p = seq.children[1];
    if (p.tagClass !== "universal" || p.tagNumber !== asn1.TAGS.NULL) throw E("path/unsupported-algorithm", "hash AlgorithmIdentifier parameters must be NULL or absent (RFC 4055)");
    // A NULL is well-formed only with empty content (X.690 sec. 8.8.2); the tag check
    // alone would accept a non-empty NULL as valid parameters.
    try { asn1.read.nullValue(p); }
    catch (e) { throw E("path/unsupported-algorithm", "hash AlgorithmIdentifier NULL parameters must have empty content (RFC 4055)", e); }
  }
  return o;
}
// The hash OID inside an EXPLICIT [n] wrapper around a hash AlgorithmIdentifier.
function explicitHashAlgOid(wrapper) {
  // Coverage residual -- unreachable: the sole caller (resolveRsaPss) already
  // asserts the EXPLICIT wrapper carries exactly one child before calling this, so
  // this identical inner check cannot fire; it is a local defense-in-depth backstop.
  if (!wrapper.children || wrapper.children.length !== 1) throw E("path/unsupported-algorithm", "malformed EXPLICIT hash AlgorithmIdentifier");
  return hashAlgOid(wrapper.children[0]);
}

function resolveRsaPss(paramsBytes) {
  // RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] DEFAULT sha1,
  //   maskGenAlgorithm [1] DEFAULT mgf1SHA1, saltLength [2] INTEGER DEFAULT 20,
  //   trailerField [3] DEFAULT 1 }. WebCrypto verifies with MGF1 keyed to the
  //   same hash as the signature and trailerField 0xBC (1). A declared value
  //   that deviates cannot be honored, so it is rejected; verifying it under
  //   WebCrypto's defaults would be a signatureAlgorithm bypass.
  // RFC 4055 DEFAULTs are SHA-1 (hashAlgorithm and mgf1SHA1). Because SHA-1 is
  // rejected, an absent hashAlgorithm or maskGenAlgorithm would resolve to SHA-1
  // and must be REJECTED -- a supported PSS AlgorithmIdentifier must state both
  // explicitly, with the MGF1 hash matching the signature hash.
  var hash = null, saltLength = 20, mgfNode = null, trailer = 1;
  if (!paramsBytes) throw E("path/unsupported-algorithm", "RSASSA-PSS requires explicit parameters (the SHA-1 defaults are rejected)");
  var n = asn1.decode(paramsBytes);
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children) {
    throw E("path/unsupported-algorithm", "RSASSA-PSS parameters must be an RSASSA-PSS-params SEQUENCE (RFC 4055)");
  }
  var pssLastTag = -1;
  n.children.forEach(function (f) {
    if (f.tagClass !== "context") throw E("path/unsupported-algorithm", "RSASSA-PSS-params fields must be context-tagged (RFC 4055)");
    // Fields are the OPTIONAL [0..3], each at most once and in ascending DER
    // order; an unknown or repeated/out-of-order tag is malformed.
    if (f.tagNumber > 3 || f.tagNumber <= pssLastTag) throw E("path/unsupported-algorithm", "RSASSA-PSS-params has an unexpected, duplicate, or out-of-order field [" + f.tagNumber + "]");
    pssLastTag = f.tagNumber;
    // Every RSASSA-PSS-params field is an EXPLICIT [n] wrapper (constructed)
    // around exactly one value (an AlgorithmIdentifier or an INTEGER); a
    // primitive/childless or multi-child context field is malformed: reading
    // f.children[0] and ignoring the rest would accept non-DER parameters.
    if (!f.children || f.children.length !== 1) throw E("path/unsupported-algorithm", "malformed RSASSA-PSS parameter field [" + f.tagNumber + "] (an EXPLICIT wrapper carries exactly one value)");
    if (f.tagNumber === 0) {
      var h = explicitHashAlgOid(f);
      if (!HASH_BY_OID[h]) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS hash algorithm " + h);
      hash = HASH_BY_OID[h];
    } else if (f.tagNumber === 1) {
      mgfNode = f.children[0];   // MaskGenAlgorithm SEQUENCE { mgf1, HashAlgorithm }
    } else if (f.tagNumber === 2) {
      var sl = asn1.read.integer(f.children[0]);
      // A negative saltLength must be rejected: the OpenSSL-backed verify shim
      // reads -1/-2/-3 as RSA_PSS_SALTLEN_DIGEST/AUTO/MAX, and AUTO (-2) accepts
      // a signature of ANY salt length -- defeating the salt-length binding.
      // The upper bound keeps the value exact through Number conversion: the
      // verifier binds to the salt length the certificate states, so a value
      // that would round is not verifiable material (no real salt exceeds the
      // modulus size, let alone this).
      saltLength = guard.range.uint31(sl, E, "path/unsupported-algorithm", "RSASSA-PSS saltLength");
    } else if (f.tagNumber === 3) {
      // Compared for equality with 1 below -- bound before conversion so an
      // oversized value cannot round on its way to the comparison.
      trailer = guard.range.uint31(asn1.read.integer(f.children[0]), E, "path/unsupported-algorithm", "RSASSA-PSS trailerField");
    }
  });
  if (hash === null) throw E("path/unsupported-algorithm", "RSASSA-PSS hashAlgorithm must be stated explicitly (the SHA-1 default is rejected)");
  if (!mgfNode) throw E("path/unsupported-algorithm", "RSASSA-PSS maskGenAlgorithm must be stated explicitly (the mgf1SHA1 default is rejected)");
  var mgfOid = seqAlgOid(mgfNode);
  if (mgfOid !== OID_MGF1) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS mask-generation function " + mgfOid);
  if (!mgfNode.children[1]) throw E("path/unsupported-algorithm", "RSASSA-PSS MGF1 requires an explicit hash parameter");
  var mgfHashOid = hashAlgOid(mgfNode.children[1]);
  if (HASH_BY_OID[mgfHashOid] !== hash) throw E("path/unsupported-algorithm", "RSASSA-PSS MGF1 hash must match the signature hash (RFC 4055)");
  if (trailer !== 1) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS trailerField " + trailer);
  return { verify: { name: "RSA-PSS", saltLength: saltLength }, imp: { name: "RSA-PSS", hash: hash } };
}

// A DER NULL parameters field is the 2-byte 05 00.
function isDerNull(p) { return p && p.length === 2 && p[0] === 0x05 && p[1] === 0x00; }

function resolveDescriptor(sigAlg) {
  if (sigAlg.oid === OID_RSA_PSS) return resolveRsaPss(sigAlg.parameters);
  // Composite ML-DSA: the OID-keyed registry + the parameters-absent check
  // (draft-ietf-lamps-pq-composite-sigs sec. 5.3) live in composite-sig.js, shared with
  // CMS. sameKeyOid enforces the RFC 9814 sec. 4 key<->signature OID consistency.
  var comp = compositeSig.resolveCompositeDescriptor(sigAlg, PathError, "path/unsupported-algorithm");
  if (comp) return comp;
  var d = SIG_ALGS[sigAlg.oid];
  if (!d) throw E("path/unsupported-algorithm", "no verify descriptor for signature algorithm " + (sigAlg.name || sigAlg.oid));
  // The signatureAlgorithm's parameters MUST match the algorithm's fixed shape:
  // RSASSA-PKCS1-v1_5 requires a NULL; ECDSA/EdDSA/ML-DSA require absence. A
  // deviating AlgorithmIdentifier is malformed and must not verify.
  var p = sigAlg.parameters;
  if (d.params === "null" && !isDerNull(p)) throw E("path/unsupported-algorithm", "signature algorithm parameters must be NULL (RFC 4055)");
  if (d.params === "absent" && p !== null && p !== undefined) throw E("path/unsupported-algorithm", "signature algorithm parameters must be absent (RFC 5758/8410)");
  return d;
}

// RFC 9814 sec. 4 issuer-key <-> signature-algorithm consistency (algorithm-confusion
// defense). For the one-shot families whose public key shares the signature OID
// (EdDSA, ML-DSA, SLH-DSA), Node's WebCrypto imports an SPKI of a DIFFERENT type
// under the requested name and verifies with the real key, so an Ed25519-signed
// certificate labeled SLH-DSA would otherwise validate. Enforce structurally:
// the issuer SPKI's algorithm OID MUST equal the signature algorithm OID. (For
// RSA/ECDSA -- different key vs signature OIDs -- WebCrypto's import already rejects
// a mismatched key type, so `sameKeyOid` is not set and this is a no-op.)
function assertKeyMatchesSigAlg(spkiBytes, sigOid, d) {
  if (!d || !d.sameKeyOid) return;
  var keyOid;
  // The working-key SPKI is decodable on the shipped path (the anchor's is validated at toAnchor entry and
  // every chain SPKI is strict-parsed), so this catch is defense-in-depth -- unreachable through
  // pki.path.validate, kept to keep a typed verdict for any future caller that supplies raw key bytes. The
  // RFC 9814 sec. 4 algorithm-confusion check below stays reachable and covered.
  try { keyOid = asn1.read.oid(asn1.decode(spkiBytes).children[0].children[0]); }
  catch (e) { throw E("path/algorithm-mismatch", "cannot read the issuer public-key algorithm identifier", e); }
  if (keyOid !== sigOid) {
    throw E("path/algorithm-mismatch", "issuer public-key algorithm " + keyOid + " does not match the signature algorithm " + sigOid + " (RFC 9814 sec. 4 - algorithm confusion)");
  }
}

// ecdsaDerToP1363 relocated to validator-sig.js; the composite trad-ECDSA and classical ECDSA
// paths call validator.sig.ecdsaDerToP1363(sig, curve, PathError, "path/bad-signature").

// ---- composite ML-DSA signatures (draft-ietf-lamps-pq-composite-sigs) -------
// The composite verify/sign engine + the COMPOSITE_ALGS OID-keyed registry live in
// composite-sig.js (shared with CMS composite SignerInfo). Path validation composes it:
// resolveDescriptor (above) delegates to compositeSig.resolveCompositeDescriptor, the
// certificate + OCSP verify paths to compositeSig.compositeVerify, and
// compositeKeyUsageCheck (below) enforces the sec. 5.2 signature-only keyUsage restriction.

// draft-ietf-lamps-pq-composite-sigs sec. 5.2: a certificate whose SubjectPublicKeyInfo
// carries a composite ML-DSA OID, if it has a keyUsage extension, MUST assert at least
// one signature bit (digitalSignature / nonRepudiation / keyCertSign / cRLSign) and
// MUST NOT assert any encryption or key-establishment bit. A composite ML-DSA key is a
// signature-only key (ML-DSA cannot encrypt or agree, so a "dual usage" key is forbidden
// even when the traditional component could encrypt). The caller invokes this only for a
// composite-keyed certificate; an absent keyUsage places no restriction (RFC 5280 4.2.1.3).
function compositeKeyUsageCheck(cert) {
  var ku;
  try { ku = decodeExt(cert, OID.keyUsage); }
  catch (e) { return { ok: false, code: "path/composite-key-usage", error: e }; }
  if (!ku) return { ok: true };
  var v = ku.value;
  if (v.keyEncipherment || v.dataEncipherment || v.keyAgreement || v.encipherOnly || v.decipherOnly) {
    return { ok: false, code: "path/composite-key-usage",
      error: E("path/composite-key-usage", "a composite ML-DSA key asserts a forbidden encryption/key-establishment keyUsage bit (draft-ietf-lamps-pq-composite-sigs sec. 5.2)") };
  }
  if (!(v.digitalSignature || v.nonRepudiation || v.keyCertSign || v.cRLSign)) {
    return { ok: false, code: "path/composite-key-usage",
      error: E("path/composite-key-usage", "a composite ML-DSA key's keyUsage asserts no signature bit (draft-ietf-lamps-pq-composite-sigs sec. 5.2)") };
  }
  return { ok: true };
}

// The ML-KEM SubjectPublicKeyInfo OIDs (RFC 9935 / FIPS 203). A certificate carrying one of
// these keys is a KEM key-establishment certificate: it can neither sign nor agree.
var ML_KEM_OIDS = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) { ML_KEM_OIDS[oid.byName(n)] = true; });

// RFC 9935 sec. 5: a certificate whose SubjectPublicKeyInfo carries an id-ml-kem-* OID, if it
// has a keyUsage extension, MUST assert keyEncipherment as the only key usage set, since an
// ML-KEM key is a key-establishment-only key (it cannot sign or agree, so no other bit is legitimate,
// and an unnamed/reserved bit set alongside keyEncipherment is equally forbidden). The caller
// invokes this only for an ML-KEM-keyed certificate; an absent keyUsage places no restriction
// (RFC 5280 sec. 4.2.1.3). This also makes an ML-KEM "CA" (keyCertSign) an explicit reject.
function kemKeyUsageCheck(cert) {
  var ku;
  try { ku = decodeExt(cert, OID.keyUsage); }
  catch (e) { return { ok: false, code: "path/kem-key-usage", error: e }; }
  if (!ku) return { ok: true };
  var v = ku.value;
  var others = v.digitalSignature || v.nonRepudiation || v.dataEncipherment || v.keyAgreement ||
    v.keyCertSign || v.cRLSign || v.encipherOnly || v.decipherOnly || (v.reservedBitsSet === true);
  if (!v.keyEncipherment || others) {
    return { ok: false, code: "path/kem-key-usage",
      error: E("path/kem-key-usage", "an ML-KEM key's keyUsage must assert keyEncipherment as the only bit (RFC 9935 sec. 5)") };
  }
  return { ok: true };
}

// Import a descriptor's verification key, validating an EdDSA point before the import runs:
// node/OpenSSL import a low-order (e.g. identity or all-zeroes) Ed25519/Ed448 SPKI without
// complaint and such a key verifies a forged signature. Both the certificate path and the
// revocation (CRL / OCSP-response) path import through this single seam, so neither can skip
// the point gate; a low-order issuer / responder key fails the caller closed (a rejected
// promise the caller maps to a bad verdict), never verifying a forged chain or a forged
// revocation.
function _importVerifyKey(spkiBytes, d) {
  try {
    if (d.eddsa) edwardsPoint.validateSpki(spkiBytes, d.eddsa, PathError, "path/bad-signature");
  } catch (e) { return Promise.reject(e); }
  return subtle.importKey("spki", spkiBytes, d.imp, false, ["verify"]);
}

// Verify cert.signatureValue over cert.tbsBytes with the working public key.
function builtinVerify(state, cert) {
  var d;
  try {
    d = resolveDescriptor(cert.signatureAlgorithm);
    assertKeyMatchesSigAlg(state.workingPublicKey, cert.signatureAlgorithm.oid, d);
  } catch (e) { return Promise.resolve({ ok: false, code: pathCode(e, "path/unsupported-algorithm"), error: e }); }
  // The signature is an octet-aligned BIT STRING (no unused bits) for every
  // supported algorithm; a non-zero unused-bit count is malformed.
  if (!guard.crypto.isOctetAligned(cert.signatureValue)) return Promise.resolve({ ok: false, code: "path/bad-signature" });
  // A composite signature verifies its ML-DSA and traditional halves and accepts
  // IFF both pass -- delegated to the composite combinator (which reuses this
  // file's ECDSA range-check + the same import/verify seam).
  if (d.composite) return compositeSig.compositeVerify(state.workingPublicKey, cert.signatureValue.bytes, cert.tbsBytes, d.composite, PathError, "path/unsupported-algorithm", "path/bad-signature");
  var key;
  return _importVerifyKey(state.workingPublicKey, d).then(function (k) {
    key = k;
    var sig = cert.signatureValue.bytes;
    if (d.ecdsa) sig = validator.sig.ecdsaDerToP1363(sig, key.algorithm.namedCurve, PathError, "path/bad-signature");
    return subtle.verify(d.verify, key, sig, cert.tbsBytes);
  }).then(function (ok) {
    return { ok: ok === true };
  }, function (e) {
    // A raw OpenSSL / WebCrypto fault (wrong key type for the declared
    // algorithm -- the algorithm-confusion case) is a signature failure, not a
    // path/* verdict of its own; only a PathError code is preserved.
    return { ok: false, code: pathCode(e, "path/bad-signature"), error: e };
  });
}

// ---- 7.1 name comparison ---------------------------------------------------

// RFC 5280 sec. 7.1 canonical DN / RDN comparison, via the shared name guard: the
// canonical form (case-fold + internal-whitespace collapse) and the embedded
// control-byte reject (CVE-2009-2408 -> path/name-chaining) live once in
// guard-name, so no path-validation caller can reintroduce a raw-byte DN
// comparison that treats two RFC 5280-equal names as different.
function dnEqual(rdnsA, rdnsB) {
  return guard.name.dnEqual(rdnsA, rdnsB, E, "path/name-chaining", "distinguished name");
}

function rdnEqual(a, b) {
  return guard.name.rdnEqual(a, b, E, "path/name-chaining", "distinguished name");
}

// ---- extension access ------------------------------------------------------

function findExt(cert, extOid) {
  for (var i = 0; i < cert.extensions.length; i++) {
    if (cert.extensions[i].oid === extOid) return cert.extensions[i];
  }
  return null;
}

// Decode an extension value, mapping the typed decoder throw to a check.
function decodeExt(cert, extOid) {
  var ext = findExt(cert, extOid);
  if (!ext) return null;
  var dec = EXT_DECODERS[extOid];
  return { critical: ext.critical, value: dec(ext.value) };
}

// RFC 5280 requires several CA-scoped extensions to be marked critical:
// basicConstraints (4.2.1.9), nameConstraints (4.2.1.10),
// policyConstraints (4.2.1.11), inhibitAnyPolicy (4.2.1.14). A conforming
// validator rejects the non-critical form -- an extension a non-supporting
// relying party would ignore must not silently pass here either. Returns a
// typed PathError when a PRESENT extension is not critical, else null.
function requireCriticalExt(ext, name, checks) {
  if (ext && ext.critical !== true) {
    checks.push({ name: name, ok: false, code: "path/extension-not-critical" });
    return E("path/extension-not-critical", name + " extension must be marked critical (RFC 5280 4.2.1)");
  }
  return null;
}

// ---- name constraints ------------------------------------------------------

// Split an addr-spec into [localPart, host] at its single "@". Returns null when
// there is no "@" (a bare host/domain constraint), or "ambiguous" when there are
// multiple "@": a conformant certificate rfc822Name is a simple addr-spec with
// exactly one "@" (RFC 5280 sec. 4.2.1.6 deprecates the quoted local part, and an
// addr-spec domain never contains "@"), so a multi-"@" mailbox like
// "a@b"@example.com cannot be split reliably and must fail closed.
function splitMailbox(addr) {
  var first = addr.indexOf("@");
  if (first === -1) return null;
  if (first !== addr.lastIndexOf("@")) return "ambiguous";
  return [addr.slice(0, first), addr.slice(first + 1)];
}

function emailMatch(constraint, mailbox) {
  // RFC 5280 sec. 4.2.1.10 rfc822Name: a constraint with an "@" is a full mailbox;
  // a leading "." is a domain matching mailboxes at a SUBDOMAIN; otherwise it is
  // a host matching mailboxes AT that host only. RFC 5321: the local part is
  // CASE-SENSITIVE (exact); only the host is compared case-insensitively.
  var mb = splitMailbox(mailbox);
  if (mb === "ambiguous") return "unsupported";   // multi-"@" mailbox -> fail closed
  if (constraint.indexOf("@") !== -1) {
    // Full-mailbox constraint: exact local part + case-insensitive host. The
    // host is canonicalized like dNSName/URI (strip the absolute-FQDN root dot)
    // so a trailing-dot mailbox cannot escape the constraint.
    var cb = splitMailbox(constraint);
    if (cb === "ambiguous" || cb === null || mb === null) return "unsupported";
    return mb[0] === cb[0] && stripTrailingDot(mb[1].toLowerCase()) === stripTrailingDot(cb[1].toLowerCase());
  }
  // Host/domain constraint: compare the mailbox host case-insensitively, with the
  // trailing FQDN root dot stripped on both sides (as hostConstraintMatch does)
  // so "user@evil.com." does not slip a constraint on "evil.com".
  if (mb === null) return "unsupported";          // no host -> cannot determine domain
  var host = stripTrailingDot(mb[1].toLowerCase());
  if (host === "") return "unsupported";
  var c = stripTrailingDot(constraint.toLowerCase());
  if (c.charAt(0) === ".") return host.length > c.length && host.slice(-c.length) === c;
  return host === c;
}

// Strip a single trailing dot (the absolute-FQDN root label) so "evil.com."
// and "evil.com" compare equal. Without that, a trailing-dot SAN would escape
// a dNSName constraint.
function stripTrailingDot(s) { return s.charAt(s.length - 1) === "." ? s.slice(0, -1) : s; }

// Host-suffix match with the RFC 5280 sec. 4.2.1.10 leading-period rule shared by
// dNSName and uniformResourceIdentifier constraints on a host.
function hostConstraintMatch(constraint, host) {
  var c = stripTrailingDot(constraint.toLowerCase()), h = stripTrailingDot(host.toLowerCase());
  if (c === "") return true;
  if (c.charAt(0) === ".") return h.length > c.length && h.slice(-c.length) === c;   // subdomain only
  return h === c || (h.length > c.length && h.slice(-(c.length + 1)) === "." + c);   // host + subdomains
}

// Is `host` a fully qualified domain name (as a URI host constraint requires,
// RFC 5280 sec. 4.2.1.10)? A dotless single label (localhost), an IPv4/IPv6 literal,
// or a value carrying non-hostname characters (a scheme "://", a path "/", a
// port ":") is not a FQDN and cannot be matched against a domain-suffix
// constraint. Only [A-Za-z0-9.-] with at least one dot qualifies.
function isFqdnHost(host) {
  var h = stripTrailingDot(host);
  if (h === "" || h.indexOf(".") === -1) return false;       // empty or single-label (localhost)
  if (!/^[a-z0-9.-]+$/i.test(h)) return false;               // scheme/path/port/IPv6 chars, "@", etc.
  if (/^[0-9.]+$/.test(h)) return false;                     // IPv4 dotted-quad literal
  return true;
}

// A URI constraint applies to the host part: a leading "." matches subdomains
// only; a bare host matches that host exactly (not subdomains, per sec. 4.2.1.10).
// Both sides must be a fully qualified domain name. A URI SAN with no host / an
// IP literal, or a malformed constraint that is not an FQDN (e.g. a full URI
// "http://blocked.example" where the required form is "blocked.example"), cannot
// be evaluated, so it returns "unsupported" and the caller fails closed; reporting
// it as a plain non-match would let the name silently escape a critical constraint.
function uriMatch(constraint, uri) {
  var host = uriHost(uri);
  if (host === null) return "unsupported";
  if (!isFqdnHost(host)) return "unsupported";
  var c = stripTrailingDot(constraint.toLowerCase()), h = stripTrailingDot(host.toLowerCase());
  // Validate the constraint's own host form (strip a single leading "." domain marker).
  if (!isFqdnHost(c.charAt(0) === "." ? c.slice(1) : c)) return "unsupported";
  if (c.charAt(0) === ".") return h.length > c.length && h.slice(-c.length) === c;
  return h === c;
}

function uriHost(uri) {
  var m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(uri);
  if (!m) return null;
  var authority = m[1];
  // authority = [ userinfo "@" ] host [ ":" port ]. RFC 3986 userinfo does not
  // contain a raw "@", so a conformant authority has at most one "@". With more
  // than one the host cannot be determined reliably, so this fails closed
  // (null -> uriMatch returns "unsupported" -> the caller rejects the path);
  // guessing a host could slip a URI name constraint.
  var firstAt = authority.indexOf("@");
  if (firstAt !== authority.lastIndexOf("@")) return null;
  if (firstAt !== -1) authority = authority.slice(firstAt + 1);
  var host = authority.replace(/:\d+$/, "");
  return host === "" ? null : host;   // an empty authority cannot be evaluated -> unsupported
}

function ipMatch(constraint, addr) {
  // constraint = address+mask (8 or 32 octets); addr = 4 or 16.
  var half = constraint.length / 2;
  if (addr.length !== half) return false;
  for (var i = 0; i < half; i++) {
    if ((addr[i] & constraint[half + i]) !== (constraint[i] & constraint[half + i])) return false;
  }
  return true;
}

// Does GeneralName-like {tagNumber, value} match a constraint base of the same
// form? Returns true/false for a supported form, null when the forms differ
// (not comparable), or the string "unsupported" when the forms match but this
// validator does not implement that form's comparison. The caller must then fail
// closed: an unenforceable constraint cannot be read as "no match".
function nameMatchesConstraint(gnTag, gnValue, base) {
  if (base.tagNumber !== gnTag) return null;         // different form -> not comparable
  switch (gnTag) {
    case 1: return emailMatch(base.value, gnValue);       // rfc822Name
    case 2: return hostConstraintMatch(base.value, gnValue); // dNSName
    case 6: return uriMatch(base.value, gnValue);         // uniformResourceIdentifier
    case 7: return ipMatch(base.value, gnValue);          // iPAddress
    case 4: return dnStartsWith(gnValue, base.value);     // directoryName
    default: return "unsupported";                        // otherName / x400 / ediParty / registeredID
  }
}

// directoryName constraint: the name DN must contain the constraint DN as an
// initial RDN sequence.
function dnStartsWith(nameDn, constraintDn) {
  if (constraintDn.rdns.length > nameDn.rdns.length) return false;
  for (var i = 0; i < constraintDn.rdns.length; i++) {
    if (!rdnEqual(nameDn.rdns[i], constraintDn.rdns[i])) return false;
  }
  return true;
}

// Collect the name forms a cert presents for constraint checking: its SAN
// entries plus (per 4.2.1.10 / 6.1.3) an emailAddress in the subject DN as an
// rfc822Name, plus the subject DN itself as a directoryName.
function certNameForms(cert) {
  var forms = [];
  var san = decodeExt(cert, OID.subjectAltName);
  var hasRfc822San = false;
  if (san) {
    // Preserve every SAN entry, including a form whose value the validator does
    // not decode (x400Address [3] / ediPartyName [5]); dropping one would let a
    // critical constraint of that same unsupported form pass unenforced. The
    // constraint check fails such a form closed (name-constraint-unsupported).
    san.value.names.forEach(function (nm) {
      if (nm.tagNumber === 1) hasRfc822San = true;   // an rfc822Name SAN carries the email identity
      // Coverage residual -- the `undefined -> null` arm is unreachable: the SAN
      // decoder (schema-pkix altName, decodeValue:true) routes through generalName,
      // which already maps an undecoded value to null, so nm.value is never undefined.
      forms.push({ tag: nm.tagNumber, value: nm.value === undefined ? null : nm.value });
    });
  }
  // RFC 5280 sec. 4.2.1.10: the legacy emailAddress in the subject DN is checked as
  // an rfc822Name unless the SAN already carries the email identity as an
  // rfc822Name entry. A SAN of a different form (e.g. dNSName only) does not
  // cover the email, so the subject-DN email must still be constrained. Otherwise
  // an excluded/non-permitted mailbox would slip an rfc822Name constraint.
  if (!hasRfc822San) {
    cert.subject.rdns.forEach(function (rdn) {
      rdn.forEach(function (atv) {
        if (atv.type === OID.emailAddress && typeof atv.value === "string") forms.push({ tag: 1, value: atv.value });
      });
    });
  }
  if (cert.subject.rdns.length > 0) forms.push({ tag: 4, value: cert.subject });
  return forms;
}

// Check a cert's own names against the accumulated constraints. `excluded` is
// a union (any match rejects). `permitted` is the intersection of every
// absorbing cert's permittedSubtrees (6.1.4(g)): the permitted set is tracked
// as one generation per absorbing cert, and a name of form F must match a
// subtree of form F in every generation that constrains form F. A flat pool
// would compute the union, letting a subordinate CA broaden what its parent
// permitted (a name-constraint bypass).
function checkNameConstraints(state, cert) {
  var forms = certNameForms(cert);
  // Excluded: any match -> reject. A constraint of the same form the validator
  // cannot compare ("unsupported") means a critical exclusion it cannot
  // enforce, so it fails closed on the same footing as a match.
  for (var e = 0; e < state.excludedSubtrees.length; e++) {
    var ex = state.excludedSubtrees[e];
    for (var i = 0; i < forms.length; i++) {
      var m = nameMatchesConstraint(forms[i].tag, forms[i].value, { tagNumber: ex.tag, value: ex.base });
      if (m === true) return { ok: false, code: "path/name-constraint-excluded" };
      if (m === "unsupported") return { ok: false, code: "path/name-constraint-unsupported" };
    }
  }
  // Permitted: for each name form, every generation that constrains that form
  // must admit it (intersection across generations). If the only subtrees of
  // that form are unenforceable, the name cannot be confirmed permitted.
  for (var f = 0; f < forms.length; f++) {
    var nf = forms[f];
    for (var g = 0; g < state.permittedGenerations.length; g++) {
      var formSubtrees = state.permittedGenerations[g].filter(function (s) { return s.tag === nf.tag; });
      if (!formSubtrees.length) continue;              // this generation does not constrain the form
      var permitted = false, unsupported = false;
      formSubtrees.forEach(function (s) {
        var r = nameMatchesConstraint(nf.tag, nf.value, { tagNumber: s.tag, value: s.base });
        if (r === true) permitted = true;
        else if (r === "unsupported") unsupported = true;
      });
      if (!permitted) return { ok: false, code: unsupported ? "path/name-constraint-unsupported" : "path/name-constraint-not-permitted" };
    }
  }
  return { ok: true };
}

// Absorb a cert's nameConstraints (6.1.4(g)): permittedSubtrees becomes a new
// GENERATION (intersection is enforced at check time by requiring a match in
// every generation); excludedSubtrees union into the flat excluded pool.
function absorbNameConstraints(state, decoded) {
  if (decoded.permittedSubtrees.length) {
    state.permittedGenerations.push(decoded.permittedSubtrees.map(function (st) {
      return { tag: st.base.tagNumber, base: st.base.value };
    }));
  }
  decoded.excludedSubtrees.forEach(function (st) {
    state.excludedSubtrees.push({ tag: st.base.tagNumber, base: st.base.value });
  });
}

// ---- certificate-policy tree ----------------------------------------------

function rootNode() {
  return { depth: 0, validPolicy: OID.anyPolicy, qualifierSet: [], expectedPolicySet: [OID.anyPolicy], children: [], parent: null };
}
// A deep copy of the valid-policy tree that omits the internal `parent` back-pointer,
// so the structured verdict returned to callers is acyclic (JSON.stringify-safe).
// The `parent` link is an implementation detail of the 6.1.3 processing, not part
// of the RFC 5280 valid_policy_tree a consumer inspects.
function treeWithoutParent(node) {
  if (!node) return null;
  return {
    depth: node.depth,
    validPolicy: node.validPolicy,
    qualifierSet: node.qualifierSet,
    expectedPolicySet: node.expectedPolicySet,
    children: node.children.map(treeWithoutParent),
  };
}
function leavesAt(tree, depth) {
  var out = [];
  // Coverage residual -- unreachable: every call site guards state.validPolicyTree
  // truthy before calling leavesAt; the null-tree early return is a backstop.
  if (!tree) return out;   // a pruned-empty tree has no nodes
  (function walk(node) {
    if (node.depth === depth) { out.push(node); return; }
    node.children.forEach(walk);
  })(tree);
  return out;
}
function pruneChildless(tree, depth) {
  // Delete depth-`depth` nodes with no children, then propagate upward.
  for (var d = depth; d > 0; d--) {
    leavesAt(tree, d).forEach(function (node) {
      if (node.children.length === 0 && node.parent) {
        var idx = node.parent.children.indexOf(node);
        if (idx !== -1) node.parent.children.splice(idx, 1);
      }
    });
  }
}
function treeIsEmpty(tree) { return tree.children.length === 0; }

// ---- the state machine -----------------------------------------------------

// Is `base` the value shape the constraint matcher compares for a GeneralName
// form? Forms 0/3/5/8 (otherName / x400Address / ediPartyName / registeredID)
// carry any present value -- the matcher fails them closed as unsupported.
function isSubtreeBaseValid(tag, base) {
  switch (tag) {
    case 1: case 2: case 6: return typeof base === "string";                       // rfc822Name / dNSName / URI
    case 7: return (Buffer.isBuffer(base) || base instanceof Uint8Array) &&
                   (base.length === 8 || base.length === 32);                      // iPAddress: address + mask
    case 4: return base !== null && typeof base === "object" && !!base.rdns && intrinsic.isArray(base.rdns);   // directoryName
    default: return base !== undefined;
  }
}

// Entry-point validation of a 6.1.1(b,c) user-initial subtree seed. A
// mis-shaped entry (e.g. the { base: { tagNumber, value } } shape the
// nameConstraints decoder emits) would never match any name, silently
// disabling the constraint the caller configured -- so it throws instead.
function checkedSubtreeSeeds(list, optName) {
  if (list === undefined || list === null) return [];
  if (!intrinsic.isArray(list)) throw E("path/bad-input", "validate: opts." + optName + " must be an array of { tag, base } subtree entries");
  return list.map(function (st) {
    if (!st || typeof st !== "object" || !Number.isInteger(st.tag) || st.tag < 0 || st.tag > 8 || !isSubtreeBaseValid(st.tag, st.base)) {
      throw E("path/bad-input", "validate: opts." + optName + " entries must be { tag: <GeneralName tag number 0..8>, base: <that form's constraint value> }");
    }
    return { tag: st.tag, base: st.base };
  });
}

function initialize(certs, params, seeds, anchor) {
  var n = certs.length;
  return {
    validPolicyTree: rootNode(),
    policyNodeCount: 1,
    maxPolicyNodes: params.maxPolicyNodes !== undefined ? params.maxPolicyNodes : constants.LIMITS.PATH_MAX_POLICY_NODES,
    // Each absorbing cert's permittedSubtrees is one generation; a name must be
    // admitted by every generation (intersection). An initial seed is generation 0.
    permittedGenerations: seeds.permitted.length ? [seeds.permitted] : [],
    excludedSubtrees: seeds.excluded,
    explicitPolicy: params.initialExplicitPolicy ? 0 : n + 1,
    inhibitAnyPolicy: params.initialAnyPolicyInhibit ? 0 : n + 1,
    policyMapping: params.initialPolicyMappingInhibit ? 0 : n + 1,
    workingPublicKeyAlgorithm: anchor.algorithm,
    workingPublicKey: anchor.publicKey,
    workingPublicKeyParameters: anchor.parameters || null,
    workingIssuerName: anchor.name,
    maxPathLength: n,
    userInitialPolicySet: params.userInitialPolicySet || [OID.anyPolicy],
    results: [],
  };
}

// self-issued = subject DN equals issuer DN. dnEqual throws on a NUL/control
// DN (CVE-2009-2408); a malformed-DN cert is never "self-issued" (and is failed
// by the name-chaining check), so the throw is swallowed here, keeping it from
// rejecting the whole validate() promise at these unwrapped call sites.
function selfIssued(cert) {
  try { return dnEqual(cert.subject.rdns, cert.issuer.rdns); }
  catch (_e) { return false; }
}

function processPolicies(state, cert, i, checks) {
  var cp;
  try { cp = decodeExt(cert, OID.certificatePolicies); }
  catch (e) { checks.push({ name: "policies", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }

  if (cp && state.validPolicyTree) {
    var policies = cp.value;
    var depth = i - 1;
    // anyPolicy processing is active only while inhibit_anyPolicy > 0, or for a
    // self-issued non-final cert. What the gate covers is the (d)(2) expansion of
    // a cert-asserted anyPolicy and nothing more. 4.2.1.14 inhibition rests entirely on
    // that gate: a depth-(i-1) anyPolicy node created while processing was
    // active remains matchable in (d)(1)(ii).
    var anyPolicyActive = state.inhibitAnyPolicy > 0 || (i < state._n && selfIssued(cert));
    var anyPolicyPresent = false;
    var anyPolicyQualifiers = null;
    policies.forEach(function (p) {
      if (p.policyIdentifier === OID.anyPolicy) { anyPolicyPresent = true; anyPolicyQualifiers = p.qualifiersBytes; return; }
      var matched = false;
      leavesAt(state.validPolicyTree, depth).forEach(function (node) {
        if (contains(node.expectedPolicySet, p.policyIdentifier)) {
          addChild(state, node, p.policyIdentifier, p.qualifiersBytes, [p.policyIdentifier], checks);
          matched = true;
        }
      });
      if (!matched) {
        // 6.1.3(d)(1)(ii): with no expected-policy match, create the node from a
        // depth-(i-1) anyPolicy node. The RFC runs this step UNCONDITIONALLY
        // (no inhibit clause); gating it would false-reject a path whose
        // specific policy chains through a legitimately created anyPolicy node.
        leavesAt(state.validPolicyTree, depth).forEach(function (node) {
          if (node.validPolicy === OID.anyPolicy) addChild(state, node, p.policyIdentifier, p.qualifiersBytes, [p.policyIdentifier], checks);
        });
      }
    });
    if (anyPolicyPresent && anyPolicyActive) {
      // 6.1.3(d)(2): expand anyPolicy into unmatched expected-policy values.
      // Each generated child carries AP-Q -- the qualifier set of the
      // certificate's own anyPolicy entry ("set the qualifier_set to AP-Q").
      leavesAt(state.validPolicyTree, depth).forEach(function (node) {
        node.expectedPolicySet.forEach(function (ep) {
          var already = guard.list.anyMatches(node.children, function (ch) { return ch.validPolicy === ep; });
          if (!already) addChild(state, node, ep, anyPolicyQualifiers, [ep], checks);
        });
      });
    }
    if (state._capHit) return { fatal: true, error: E("path/policy-tree-cap", "policy tree exceeded the node cap") };
    pruneChildless(state.validPolicyTree, depth);
    if (treeIsEmpty(state.validPolicyTree)) state.validPolicyTree = null;
  } else if (!cp) {
    state.validPolicyTree = null;
  }

  // 6.1.3(f): interim check.
  if (!(state.explicitPolicy > 0 || state.validPolicyTree !== null)) {
    checks.push({ name: "policy", ok: false, code: "path/policy-required" });
    return { fatal: true, error: E("path/policy-required", "explicit policy required but the valid-policy tree is empty") };
  }
  return { fatal: false };
}

function addChild(state, parent, validPolicy, qualifiers, expectedPolicySet, checks) {
  if (state.policyNodeCount >= state.maxPolicyNodes) { state._capHit = true; return; }
  var node = { depth: parent.depth + 1, validPolicy: validPolicy, qualifierSet: qualifiers ? [qualifiers] : [], expectedPolicySet: expectedPolicySet, children: [], parent: parent };
  parent.children.push(node);
  state.policyNodeCount++;
  void checks;
}

// A DER explicit NULL (05 00) as an AlgorithmIdentifier parameters field is
// treated identically to omitted parameters (RFC 5280 6.1.4(e)).
function isNullOrAbsentParams(p) {
  return p === null || p === undefined || (p.length === 2 && p[0] === 0x05 && p[1] === 0x00);
}

// Rebuild a SubjectPublicKeyInfo with the given AlgorithmIdentifier parameters
// spliced in, so a key that inherited its domain parameters (an EC public key
// whose SPKI omits the namedCurve, RFC 5280 6.1.4(f)/6.1.5(d)) becomes a
// self-contained SPKI that importKey("spki", ...) can consume.
function spliceSpkiParameters(spki, algOid, paramsBytes) {
  return asn1.build.sequence([
    asn1.build.sequence([asn1.build.oid(algOid), asn1.build.raw(paramsBytes)]),
    asn1.build.bitString(spki.publicKey.bytes, spki.publicKey.unusedBits),
  ]);
}

// RFC 5280 6.1.4(d,e,f) / 6.1.5(c,d): set working_public_key / _algorithm /
// _parameters from a certificate. Present non-null parameters are copied;
// NULL-or-absent parameters inherit the prior parameters iff the key algorithm
// is unchanged, else clear them.
function updateWorkingKey(state, cert) {
  var keyAlg = cert.subjectPublicKeyInfo.algorithm;
  if (!isNullOrAbsentParams(keyAlg.parameters)) {
    state.workingPublicKeyParameters = keyAlg.parameters;
  } else if (keyAlg.oid !== state.workingPublicKeyAlgorithm) {
    state.workingPublicKeyParameters = null;
  }
  // When this cert's SPKI omits its algorithm parameters but the working set
  // carries inherited ones, store a reconstructed SPKI: the next signature verify
  // needs a complete key and would fail on the bare bytes.
  if (isNullOrAbsentParams(keyAlg.parameters) && state.workingPublicKeyParameters) {
    state.workingPublicKey = spliceSpkiParameters(cert.subjectPublicKeyInfo, keyAlg.oid, state.workingPublicKeyParameters);
  } else {
    state.workingPublicKey = cert.subjectPublicKeyInfo.bytes;
  }
  state.workingPublicKeyAlgorithm = keyAlg.oid;
}

// RFC 5280 4.2.1.12 -- when the caller states required key purposes, a cert
// carrying an extendedKeyUsage must assert every one (or anyExtendedKeyUsage).
// Applied to the TARGET cert (its own purposes) AND to every intermediate CA
// (EKU chaining: an EKU on a CA constrains the purposes below it), so marking
// extKeyUsage a processed critical extension is sound. The semantic gate runs
// wherever the extension appears, never only on the leaf. A cert with no EKU is
// unconstrained. Returns true if the cert FAILS the required-purpose check.
function ekuPurposeFails(cert, requiredEku, checks) {
  var eku;
  try { eku = decodeExt(cert, OID.extKeyUsage); }
  catch (e) { checks.push({ name: "extendedKeyUsage", ok: false, code: pathCode(e, "path/bad-extension-value") }); return true; }
  if (!eku) return false;   // absent EKU: unrestricted (4.2.1.12 restricts only when present)
  var purposes = eku.value;
  var ok = contains(purposes, OID.anyExtendedKeyUsage) || containsAll(purposes, requiredEku);
  checks.push({ name: "extendedKeyUsage", ok: ok, code: ok ? undefined : "path/eku-not-permitted" });
  return !ok;
}

function prepareNext(state, cert, i, checks) {
  var isSelfIssued = selfIssued(cert);

  // RFC 5280 4.2.1.12 EKU chaining -- an intermediate CA's EKU constrains the
  // purposes of the certs beneath it. Enforced here so a critical EKU on an
  // intermediate (now a PROCESSED extension) is not merely tolerated but honored.
  if (state.requiredEku && ekuPurposeFails(cert, state.requiredEku, checks)) {
    return { fatal: true, error: E("path/eku-not-permitted", "an intermediate CA extendedKeyUsage does not permit a required purpose (RFC 5280 4.2.1.12)") };
  }

  // (a),(b) policy mappings.
  var pm;
  try { pm = decodeExt(cert, OID.policyMappings); }
  catch (e) { checks.push({ name: "policyMappings", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }
  if (pm) {
    // The scan for a forbidden anyPolicy mapping is the rule itself (RFC 5280 6.1.4(a)), so it is a
    // loop rather than a `some`: one answering false makes the forbidden mapping invisible and the
    // certificate is accepted carrying it.
    var badAny = mapsAnyPolicy(pm.value);
    if (badAny) { checks.push({ name: "policyMappings", ok: false, code: "path/bad-policy" }); return { fatal: true, error: E("path/bad-policy", "policyMappings must not map to or from anyPolicy (RFC 5280 6.1.4(a))") }; }
    if (state.validPolicyTree) applyPolicyMappings(state, pm.value, i);
  }

  // (c) working issuer name; (d),(e),(f) working key + algorithm + parameters.
  state.workingIssuerName = cert.subject;
  updateWorkingKey(state, cert);

  // (g) name constraints absorb, once this cert's own names have been checked.
  var nc;
  try { nc = decodeExt(cert, OID.nameConstraints); }
  catch (e) { checks.push({ name: "nameConstraints", ok: false, code: pathCode(e, "path/bad-name-constraints") }); return { fatal: true, error: e }; }
  var ncCritErr = requireCriticalExt(nc, "nameConstraints", checks);
  if (ncCritErr) return { fatal: true, error: ncCritErr };
  if (nc) absorbNameConstraints(state, nc.value);

  // (h) decrement counters for a non-self-issued cert.
  if (!isSelfIssued) {
    if (state.explicitPolicy > 0) state.explicitPolicy--;
    if (state.policyMapping > 0) state.policyMapping--;
    if (state.inhibitAnyPolicy > 0) state.inhibitAnyPolicy--;
  }

  // (i),(j) policy/inhibit clamps.
  var pc;
  try { pc = decodeExt(cert, OID.policyConstraints); }
  catch (e) { checks.push({ name: "policyConstraints", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }
  var pcCritErr = requireCriticalExt(pc, "policyConstraints", checks);
  if (pcCritErr) return { fatal: true, error: pcCritErr };
  if (pc) {
    if (pc.value.requireExplicitPolicy !== null && pc.value.requireExplicitPolicy < state.explicitPolicy) state.explicitPolicy = pc.value.requireExplicitPolicy;
    if (pc.value.inhibitPolicyMapping !== null && pc.value.inhibitPolicyMapping < state.policyMapping) state.policyMapping = pc.value.inhibitPolicyMapping;
  }
  var iap;
  try { iap = decodeExt(cert, OID.inhibitAnyPolicy); }
  catch (e) { checks.push({ name: "inhibitAnyPolicy", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }
  var iapCritErr = requireCriticalExt(iap, "inhibitAnyPolicy", checks);
  if (iapCritErr) return { fatal: true, error: iapCritErr };
  if (iap && iap.value < state.inhibitAnyPolicy) state.inhibitAnyPolicy = iap.value;

  // (k) basicConstraints cA gate, the single authoritative CA check.
  var bc;
  try { bc = decodeExt(cert, OID.basicConstraints); }
  catch (e) { checks.push({ name: "basicConstraints", ok: false, code: "path/bad-basic-constraints" }); return { fatal: true, error: e }; }
  if (!bc || bc.value.cA !== true) {
    checks.push({ name: "basicConstraints", ok: false, code: "path/not-a-ca" });
    return { fatal: true, error: E("path/not-a-ca", "intermediate certificate is not a CA (basicConstraints cA is not TRUE, RFC 5280 6.1.4(k))") };
  }
  // 4.2.1.9: a CA certificate used to validate certificate signatures MUST mark
  // basicConstraints critical. A non-critical cA:TRUE is non-conforming. A
  // relying party that skips non-critical extensions would not see the CA bit.
  var bcCritErr = requireCriticalExt(bc, "basicConstraints", checks);
  if (bcCritErr) return { fatal: true, error: bcCritErr };
  // (l),(m) path length.
  if (!isSelfIssued) {
    if (state.maxPathLength <= 0) { checks.push({ name: "pathLength", ok: false, code: "path/path-length-exceeded" }); return { fatal: true, error: E("path/path-length-exceeded", "certification path is longer than the CA path-length constraint allows") }; }
    state.maxPathLength--;
  }
  if (bc.value.pathLenConstraint !== null && bc.value.pathLenConstraint < state.maxPathLength) state.maxPathLength = bc.value.pathLenConstraint;

  // (n) keyUsage.keyCertSign.
  var ku;
  try { ku = decodeExt(cert, OID.keyUsage); }
  catch (e) { checks.push({ name: "keyUsage", ok: false, code: "path/bad-key-usage" }); return { fatal: true, error: e }; }
  if (ku && ku.value.keyCertSign !== true) {
    checks.push({ name: "keyUsage", ok: false, code: "path/missing-key-cert-sign" });
    return { fatal: true, error: E("path/missing-key-cert-sign", "CA certificate keyUsage does not assert keyCertSign (RFC 5280 6.1.4(n))") };
  }
  return { fatal: false };
}

function applyPolicyMappings(state, mappings, i) {
  var depth = i;
  if (state.policyMapping > 0) {
    // 6.1.4(b)(1): for each depth-i node whose valid_policy is an ID-P that
    // the extension maps, REPLACE its expected_policy_set with the SET of
    // subjectDomainPolicy values mapped from that ID-P. Appending would retain
    // the pre-mapping policy, letting a later cert satisfy the chain by
    // asserting the mapped-away policy.
    var mappedFrom = {};   // issuerDomainPolicy -> [subjectDomainPolicy, ...]
    mappings.forEach(function (m) { (mappedFrom[m.issuerDomainPolicy] = mappedFrom[m.issuerDomainPolicy] || []).push(m.subjectDomainPolicy); });
    var depthI = leavesAt(state.validPolicyTree, depth);
    var anyNodes = depthI.filter(function (nd) { return nd.validPolicy === OID.anyPolicy; });
    Object.keys(mappedFrom).forEach(function (idp) {
      var idpNodes = depthI.filter(function (nd) { return nd.validPolicy === idp; });
      if (idpNodes.length) {
        idpNodes.forEach(function (nd) { nd.expectedPolicySet = mappedFrom[idp].slice(); });
      } else {
        // 6.1.4(b)(1): with no depth-i ID-P node but a depth-i anyPolicy node, generate
        // the missing ID-P node under the anyPolicy node's parent with the mapped
        // expected set (else an anyPolicy-only CA loses the mapping).
        anyNodes.forEach(function (anyNode) {
          if (anyNode.parent) addChild(state, anyNode.parent, idp, anyNode.qualifierSet[0] || null, mappedFrom[idp].slice(), []);
        });
      }
    });
  } else {
    // 6.1.4(b)(2), policy_mapping == 0: delete every depth-i node whose
    // valid_policy is a mapped ID-P, then prune. A prior mapping in the same
    // extension may have already emptied the tree, so stop if it is gone.
    var mappedSet = {};
    mappings.forEach(function (m) { mappedSet[m.issuerDomainPolicy] = true; });
    // Coverage residual -- unreachable today: applyPolicyMappings is invoked once per
    // certificate under an `if (state.validPolicyTree)` guard and does not null the
    // tree before this point. Retained as a cheap correctness backstop for a future
    // per-mapping-batch refactor; do not remove.
    if (!state.validPolicyTree) return;
    leavesAt(state.validPolicyTree, depth).forEach(function (node) {
      if (mappedSet[node.validPolicy] && node.parent) {
        var idx = node.parent.children.indexOf(node);
        if (idx !== -1) node.parent.children.splice(idx, 1);
      }
    });
    // Prune from the PARENT depth (i-1): a pass starting at depth i would
    // delete the surviving unmapped depth-i leaves (all leaves are childless),
    // wrongly emptying the tree and false-rejecting a valid path.
    pruneChildless(state.validPolicyTree, depth - 1);
    if (treeIsEmpty(state.validPolicyTree)) state.validPolicyTree = null;
  }
}

// policyMappings is semantically processed only in the prepare-for-next step
// (sec. 6.1.4(a),(b)), which does not run for the target certificate. It is also
// SHOULD-be-non-critical (sec. 4.2.1.5), so a critical policyMappings on the target
// is both anomalous and unprocessed, and must fail closed (sec. 6.1.5(f)); accepting
// it would let, e.g., a mapping to/from anyPolicy slip past the sec. 6.1.4(a) rejection
// the intermediate path applies. (nameConstraints / inhibitAnyPolicy are also
// prepare-next-only but are MUST-be-critical CA extensions, so a critical one on
// a terminal CA cert is conforming and is not treated as unprocessed here.)
var TARGET_UNPROCESSED_IF_CRITICAL = {};
TARGET_UNPROCESSED_IF_CRITICAL[OID.policyMappings] = true;
Object.freeze(TARGET_UNPROCESSED_IF_CRITICAL);

// Membership is asked of the table's OWN properties. Freezing the table stops a write to it and
// stops nothing about the prototype chain: a name planted on Object.prototype answers for every OID
// the table does not carry, and read live this reported an unrecognized critical extension as
// processed. On a CA certificate only the first table is consulted, so the chain was accepted.
function unrecognizedCriticalExtension(cert, isTarget) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (!ext.critical) continue;
    if (!intrinsic.hasOwn(PROCESSED_EXTENSIONS, ext.oid)) return ext.oid;
    if (isTarget && intrinsic.hasOwn(TARGET_UNPROCESSED_IF_CRITICAL, ext.oid)) return ext.oid;
  }
  return null;
}

// Decode every RECOGNIZED critical extension to enforce that its extnValue is
// structurally valid -- even where the semantic gate is skipped (the leaf).
// Returns the failing typed code, or null.
function validateCriticalExtensionStructure(cert) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (!ext.critical) continue;
    var dec = EXT_DECODERS[ext.oid];
    if (!dec) continue;   // unrecognized-critical handled separately
    try { dec(ext.value); }
    catch (e) { return pathCode(e, "path/bad-extension-value"); }
  }
  return null;
}

/**
 * @primitive  pki.path.validate
 * @signature  pki.path.validate(path, opts) -> Promise<result>
 * @since      0.1.16
 * @status     stable
 * @spec       RFC 5280
 * @related    pki.schema.x509.parse, pki.path.crlChecker
 *
 * Validate an ordered certification `path` (anchor->target) against a trust
 * anchor per RFC 5280 6.1. `path` is an array of `pki.schema.x509.parse`
 * objects (or DER/PEM the function parses); `opts` carries `time` (the
 * always-on window check), `trustAnchor` ({ name, publicKey, algorithm,
 * parameters? }), the 6.1.1 user-initial inputs (`initialExplicitPolicy`,
 * `initialAnyPolicyInhibit`, `initialPolicyMappingInhibit`,
 * `userInitialPolicySet`, and `initialPermittedSubtrees` /
 * `initialExcludedSubtrees` -- arrays of `{ tag, base }` where `tag` is the
 * GeneralName tag number and `base` that form's constraint value), an
 * optional `requiredEku` (key purposes the target's extendedKeyUsage must
 * assert, given as registered OID names or dotted OID strings; an absent
 * extension is unrestricted, RFC 5280 4.2.1.12), and an optional
 * `revocationChecker`. The value-carrying options (`time`, `maxPathCerts`,
 * `maxPolicyNodes`, the subtree seeds, `userInitialPolicySet`, `requiredEku`)
 * are validated at the entry point. A mis-shaped value throws `path/bad-input`,
 * so it cannot silently go unapplied. Returns `{ valid, revocationChecked, anchorConstraints,
 * path, results, workingPublicKey, workingPublicKeyAlgorithm,
 * workingPublicKeyParameters, validPolicyTree }` where `results[i].checks`
 * carries a per-check reason code (`path/*`) for every step. Pure and
 * re-entrant -- no input object is mutated. An empty path or a missing anchor
 * throws a typed `PathError`.
 *
 * `valid` alone cannot say whether revocation was ever established, so
 * `revocationChecked` answers separately, taking the WEAKEST outcome on the
 * path: `false` when no `revocationChecker` was supplied, `"determined"` when
 * every certificate got an explicit good or revoked answer, `"waived"` when
 * `softFail` turned an undetermined one into a pass, and `"undetermined"` when
 * one could not be answered at all and the path fails for it. The
 * per-certificate `revocation` check carries the `status` it was decided on and
 * marks a waiver, so "checked, good" is distinguishable from "could not check,
 * and you waived it", a distinction a stored verdict is re-read to settle. A
 * throw from a checker is a fault in the checker: no status was reported, so the
 * path fails as `path/revocation-checker-error` carrying the fault whatever
 * `softFail` says. `softFail` opts into an undetermined answer; the built-in
 * checkers report one as `{ status: "unknown" }` and do not throw.
 *
 * `anchorConstraints` reports what the anchor's own trust metadata decided:
 * the `checkedPurpose` it was judged under, and whether the `distrustAfter`
 * date and the `purposes` delegator map each applied. That metadata is keyed BY
 * key purpose, so an anchor carrying it while `opts.checkPurpose` is absent is a
 * configuration fault (`path/bad-input`). A silently inert constraint would let
 * a root distrusted years ago quietly validate a current leaf.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2019-01-01T00:00:00Z"), notAfter: new Date("2029-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var cert = pki.schema.x509.parse(der);
 *   var res = await pki.path.validate([cert], {
 *     time: new Date("2020-01-01T00:00:00Z"),
 *     // the anchor's own key algorithm, not the algorithm its issuer signed it with
 *     trustAnchor: { name: cert.issuer, publicKey: cert.subjectPublicKeyInfo.bytes,
 *       algorithm: cert.subjectPublicKeyInfo.algorithm.oid },
 *   });
 *   res.valid;  // boolean; res.results[0].checks carries the per-check codes
 */
// Every option pki.path.validate reads. The anchor option here is the singular `trustAnchor`,
// while pki.path.build in this same module spells it `trustAnchors` and takes a list. A caller
// moving between the two verbs carries the wrong spelling without leaving the namespace, and
// before this it bought them no anchoring and no error, just "a trustAnchor is required" about
// an option they believed they had passed.
// Derived from three sources, because no one of them is complete: the `opts.*` reads in this
// function, the `params.*` reads in the RFC 5280 6.1.1 state it is passed down to, and the
// documented prose above, which is the only place `requiredEku` and the three initial-policy
// inputs appear together. A grep of one function would have shipped a list missing four real
// options and rejected callers that work today.
var _VALIDATE_OPTS = {
  checkPurpose: 1, historicalMode: 1, initialAnyPolicyInhibit: 1, initialExcludedSubtrees: 1,
  initialExplicitPolicy: 1, initialPermittedSubtrees: 1, initialPolicyMappingInhibit: 1,
  maxPathCerts: 1, maxPolicyNodes: 1, requireRevocation: 1, requiredEku: 1, revocationChecker: 1,
  softFail: 1, time: 1, trustAnchor: 1, userInitialPolicySet: 1, verifier: 1
};

async function validate(path, opts) {
  opts = guard.identifier.optionsObject(opts, E, "path/bad-input", "validate: opts");
  guard.identifier.assertKnownKeys(opts, _VALIDATE_OPTS, E, "path/bad-input",
    "pki.path.validate has an unknown option. The anchor here is `trustAnchor`, singular; " +
    "pki.path.build takes `trustAnchors`. The unknown option was: ");
  if (!intrinsic.isArray(path)) throw E("path/bad-input", "validate: path must be an array of certificates");
  // Bound the per-cert asymmetric-verify work BEFORE parsing an untrusted bundle
  // (the policy-tree cap guards CVE-2023-0464-style blow-up; this guards linear
  // crypto amplification from an oversized path). Entry-point tier: throw.
  var maxCerts = guard.limits.cap(opts.maxPathCerts, "validate: opts.maxPathCerts", constants.LIMITS.PATH_MAX_CERTS, { E: E, code: "path/bad-input", min: 1 });
  if (path.length > maxCerts) throw E("path/bad-input", "validate: the certification path has " + path.length + " certificates, exceeding the maxPathCerts limit (" + maxCerts + ")");
  // Through the same door `build` uses, and for the same reason: every certificate this walk decides
  // over is re-derived from the bytes its parser read (see coerceCert), so a rebuilt object cannot
  // present a genuine signed range alongside substituted fields.
  var certs = path.map(function (c, ci) { return coerceCert(c, "validate: path[" + ci + "]"); });
  var n = certs.length;
  if (n < 1) throw E("path/empty-path", "validate: the certification path is empty");
  if (!opts.trustAnchor) throw E("path/bad-input", "validate: a trustAnchor is required");
  // Normalize the anchor at the door: a parsed root CERTIFICATE becomes a { name, publicKey, algorithm }
  // tuple, and a mis-shaped tuple fails closed with path/bad-input rather than seeding an undefined
  // working key that a self-describing SPKI could still validate against (a soft-verdict fail-open).
  var anchor = toAnchor(opts.trustAnchor, "validate");
  // The validity-window check is always on (6.1.3(a)(2)); a missing/invalid
  // check date must fail closed, never silently disable it.
  guard.time.assertValid(opts.time, E, "path/bad-input", "validate: opts.time (the always-on validity-window check date)");
  // Entry-point tier for the remaining 6.1.1 user-initial inputs: a bad value
  // throws here rather than silently disabling the behavior it configures.
  // Validate-if-present (the default is applied where the policy state is built);
  // the shared integer cap rejects a fractional / negative / non-numeric budget.
  guard.limits.cap(opts.maxPolicyNodes, "validate: opts.maxPolicyNodes", undefined, { E: E, code: "path/bad-input", min: 1 });
  // user-initial-policy-set is a non-empty SET of policy OID strings (6.1.1(c)).
  // Membership is tested with indexOf, so a raw string here would be consulted
  // as a SUBSTRING match -- validated to an array of strings instead.
  if (opts.userInitialPolicySet !== undefined) {
    var uipsOk = intrinsic.isArray(opts.userInitialPolicySet) && opts.userInitialPolicySet.length > 0 &&
      guard.list.allMatch(opts.userInitialPolicySet, function (p) { return typeof p === "string" && p.length > 0; });
    if (!uipsOk) throw E("path/bad-input", "validate: opts.userInitialPolicySet must be a non-empty array of policy OID strings");
    // Each entry is compared (indexOf) against canonical decoder output, so a
    // non-canonical key would silently never match -- fail the typo closed here.
    opts.userInitialPolicySet.forEach(function (p) {
      guard.identifier.assertCanonicalOid(p, E, "path/bad-input", "validate: opts.userInitialPolicySet entry " + JSON.stringify(p));
    });
  }
  var seeds = {
    permitted: checkedSubtreeSeeds(opts.initialPermittedSubtrees, "initialPermittedSubtrees"),
    excluded: checkedSubtreeSeeds(opts.initialExcludedSubtrees, "initialExcludedSubtrees"),
  };
  // opts.requiredEku -- the key purposes the TARGET certificate must be good
  // for, each a registered OID name or a dotted OID string. Resolved (and
  // typo-checked) here at the entry point.
  var purposeOpts = resolvePurposeOpts(opts);
  var requiredEku = purposeOpts.requiredEku;
  var checkPurpose = purposeOpts.checkPurpose;

  var state = initialize(certs, opts, seeds, anchor);
  state._n = n;
  state.requiredEku = requiredEku;
  var verifier = opts.verifier || null;
  var revocationChecker = opts.revocationChecker || null;
  var softFail = opts.softFail === true;
  // Revocation is a pluggable, opt-in step: by default a path with no checker is
  // not revocation-checked. opts.requireRevocation makes the 6.1.3(a)(3)
  // determination mandatory -- an absent checker (or an undetermined result)
  // then fails the path closed instead of silently skipping the step.
  var requireRevocation = opts.requireRevocation === true;
  var failed = false;
  // Whether the revocation rule RAN, and whether any certificate's answer had to be waived. The
  // verdict reports the two separately because they are different claims: a caller re-reading a
  // stored result needs to tell "every certificate was determined not revoked" from "the step was
  // skipped" from "the step could not conclude and you had asked for that to pass".
  var revocationRan = false, revocationWaived = false, revocationUndetermined = false;
  // Which of the anchor's purpose-scoped constraints actually decided anything, reported so a
  // verdict can be re-read to tell an anchor that was judged from one that carried nothing to judge.
  var anchorDistrustApplied = false, anchorPurposeApplied = false;
  // A trust anchor carrying purpose-scoped metadata, validated with no purpose to select by, is a
  // configuration fault. The constraint is KEYED by purpose -- there is no way to apply
  // `distrustAfter.serverAuth` without being told the validation is about serverAuth -- so without
  // one the caller's stated intent would be discarded silently, and a root distrusted years ago
  // would validate a current leaf. An anchor carrying no such metadata is unaffected.
  if (!checkPurpose && _hasPurposeScopedMetadata(anchor)) {
    throw E("path/bad-input", "validate: the trust anchor carries purpose-scoped metadata (distrustAfter / purposes), which is keyed by key purpose -- supply opts.checkPurpose to say which purpose this validation is for, or the constraint cannot be applied");
  }

  for (var idx = 0; idx < n; idx++) {
    var i = idx + 1;
    var cert = certs[idx];
    var checks = [];

    // 6.1.3(a)(1) signature.
    var sigRes;
    if (verifier) {
      var vv;
      try {
        vv = await verifier.verify({
          cert: cert,
          workingPublicKey: state.workingPublicKey,
          workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm,
          workingPublicKeyParameters: state.workingPublicKeyParameters,
        });
      } catch (_e) { vv = false; }
      sigRes = { ok: vv === true };
    } else {
      sigRes = await builtinVerify(state, cert);
    }
    checks.push({ name: "signature", ok: sigRes.ok, code: sigRes.ok ? undefined : (sigRes.code || "path/bad-signature") });
    if (!sigRes.ok) failed = true;

    // draft-ietf-lamps-pq-composite-sigs sec. 5.2: a composite-keyed certificate's
    // keyUsage must be signature-only (no dual-usage). Runs for the target AND every
    // intermediate whose own subject key is composite.
    if (compositeSig.COMPOSITE_ALGS[cert.subjectPublicKeyInfo.algorithm.oid]) {
      var cku = compositeKeyUsageCheck(cert);
      checks.push({ name: "compositeKeyUsage", ok: cku.ok, code: cku.ok ? undefined : cku.code });
      if (!cku.ok) failed = true;
    }

    // RFC 9935 sec. 5: an ML-KEM-keyed certificate's keyUsage must be keyEncipherment-only.
    // Runs for the target AND every intermediate whose own subject key is ML-KEM.
    if (ML_KEM_OIDS[cert.subjectPublicKeyInfo.algorithm.oid]) {
      var kku = kemKeyUsageCheck(cert);
      checks.push({ name: "kemKeyUsage", ok: kku.ok, code: kku.ok ? undefined : kku.code });
      if (!kku.ok) failed = true;
    }

    // 6.1.3(a)(2) validity window.
    //
    // Instants, never the Date objects. Comparing two Dates coerces each one, and coercion runs
    // `Symbol.toPrimitive` or `valueOf`, which a caller's subclass answers. opts.time was checked
    // for a valid held instant at entry, and comparing the object here asked it again through a
    // door the check never used -- so the value validated and the value compared were two reads.
    var t = guard.time.instantOf(opts.time);
    var vOk = true, vCode;
    if (t < guard.time.instantOf(cert.validity.notBefore)) { vOk = false; vCode = "path/not-yet-valid"; }
    else if (t > guard.time.instantOf(cert.validity.notAfter)) { vOk = false; vCode = "path/expired"; }
    checks.push({ name: "validity", ok: vOk, code: vCode });
    if (!vOk) failed = true;

    // 6.1.3(a)(4) name chaining.
    var chainOk;
    try { chainOk = dnEqual(cert.issuer.rdns, state.workingIssuerName.rdns); }
    catch (_e) { chainOk = false; }
    checks.push({ name: "nameChaining", ok: chainOk === true, code: chainOk === true ? undefined : "path/name-chaining" });
    if (chainOk !== true) failed = true;

    // 6.1.3(b,c) name constraints on this cert's own names (skip for a
    // self-issued non-terminal cert).
    if (!(selfIssued(cert) && i !== n)) {
      var ncRes;
      try { ncRes = checkNameConstraints(state, cert); }
      catch (e) { ncRes = { ok: false, code: pathCode(e, "path/bad-name-constraints") }; }
      checks.push({ name: "nameConstraints", ok: ncRes.ok, code: ncRes.ok ? undefined : ncRes.code });
      if (!ncRes.ok) failed = true;
    }

    // 6.1.3(a)(3) revocation.
    if (revocationChecker) {
      var issuerCert = idx > 0 ? certs[idx - 1] : null;   // the anchor issues cert[1]
      var rv, rvError = null;
      // A checker that THROWS -- or whose promise rejects -- is not a checker reporting "unknown".
      // Laundering the two together made a broken checker indistinguishable from a working one that
      // could not reach the responder, and under softFail both became a pass. The fault is carried
      // onto the check so an operator can tell their own bug from a network condition, and it fails
      // the path whatever softFail says (see the branch below).
      try { rv = await revocationChecker.check(cert, { workingIssuerName: state.workingIssuerName, workingPublicKey: state.workingPublicKey, workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm, issuerCert: issuerCert }, { time: opts.time, historicalMode: opts.historicalMode === true }); }
      catch (e) { rv = { status: "error" }; rvError = e; }
      // ONLY an explicit "good" is a determined non-revocation; "revoked" fails;
      // every other value ("unknown", an OCSP tryLater/unauthorized, a typo, a
      // missing status) is undetermined and fails closed unless softFail.
      //
      // The two `ok: true` outcomes are NOT the same claim and no longer the same object. "checked,
      // and it said good" and "could not check, and you waived it" read identically from a bare
      // boolean, which is the whole reason a stored verdict cannot be re-read to answer whether
      // revocation was ever established. Each entry now names the status it was decided on, and a
      // waiver marks itself.
      var rvStatus = (rv && typeof rv.status === "string") ? rv.status : "unknown";
      if (rv && rv.status === "good") { checks.push({ name: "revocation", ok: true, status: "good" }); }
      else if (rv && rv.status === "revoked") { checks.push({ name: "revocation", ok: false, status: "revoked", code: "path/revoked" }); failed = true; }
      else if (rvError) {
        // A checker that threw is a FAULT in the checker, not a status it could not reach, and
        // softFail is the caller opting into an undetermined ANSWER. The built-in CRL and OCSP
        // checkers return `{status:"unknown"}` for every unreachable or unverifiable condition and
        // never throw, so a throw here is the caller's own bug -- waiving it would pass the
        // certificate with no revocation result at all, which is the outcome softFail is asked for
        // and this is not.
        checks.push({ name: "revocation", ok: false, status: "error", code: "path/revocation-checker-error", error: rvError });
        revocationUndetermined = true;
        failed = true;
      }
      else if (softFail) {
        // No `error` slot here or below: a fault took the branch above, so anything reaching these
        // two is a status the checker actually reported.
        checks.push({ name: "revocation", ok: true, status: rvStatus, waived: true });
        revocationWaived = true;
      } else {
        checks.push({ name: "revocation", ok: false, status: rvStatus, code: "path/revocation-undetermined" });
        revocationUndetermined = true;
        failed = true;
      }
      revocationRan = true;
    } else if (requireRevocation) {
      // No checker was supplied but the caller demands a revocation determination:
      // the step cannot be performed, so fail closed (never silently skip).
      checks.push({ name: "revocation", ok: false, code: "path/revocation-undetermined" }); failed = true;
    }

    // 6.1.3(d-f) policies.
    var polRes = processPolicies(state, cert, i, checks);
    if (state._capHit) { checks.push({ name: "policyTree", ok: false, code: "path/policy-tree-cap" }); failed = true; }
    else if (polRes.fatal) failed = true;

    // empty subject requires a critical SAN (4.1.2.6).
    if (cert.subject.rdns.length === 0) {
      var san = findExt(cert, OID.subjectAltName);
      if (!san || !san.critical) { checks.push({ name: "emptySubject", ok: false, code: "path/empty-subject-no-critical-san" }); failed = true; }
    }

    // 6.1.4 / 6.1.5.
    if (i !== n) {
      if (!state._capHit) {
        var prep = prepareNext(state, cert, i, checks);
        if (prep.fatal) failed = true;
      }
    } else {
      // 6.1.5 wrap-up.
      if (state.explicitPolicy > 0) state.explicitPolicy--;   // 6.1.5(a)
      var lpc;
      try { lpc = decodeExt(cert, OID.policyConstraints); }
      catch (_e) { lpc = null; checks.push({ name: "policyConstraints", ok: false, code: "path/bad-policy" }); failed = true; }
      // 4.2.1.11: policyConstraints MUST be critical -- apply the same check the
      // intermediate path (prepareNext) uses, so a non-critical policyConstraints
      // on the TARGET cert fails closed consistently.
      if (requireCriticalExt(lpc, "policyConstraints", checks)) failed = true;
      if (lpc && lpc.value.requireExplicitPolicy === 0) state.explicitPolicy = 0;   // 6.1.5(b)
      // 6.1.4(a) / 4.2.1.5: policyMappings must never map to/from anyPolicy. The
      // intermediate path enforces this in prepareNext; the target cert skips it,
      // so apply the structural rejection here too (covers a non-critical mapping
      // that the unrecognized-critical check above does not reach).
      var lpm;
      try { lpm = decodeExt(cert, OID.policyMappings); }
      catch (_e) { lpm = null; checks.push({ name: "policyMappings", ok: false, code: "path/bad-policy" }); failed = true; }
      if (lpm && mapsAnyPolicy(lpm.value)) {
        checks.push({ name: "policyMappings", ok: false, code: "path/bad-policy" }); failed = true;
      }
      // 4.2.1.10 / 4.2.1.14: nameConstraints and inhibitAnyPolicy MUST be
      // critical wherever they appear -- apply to the TARGET cert the same
      // check prepareNext applies to every intermediate (their semantic gates
      // do not run for the target, but the criticality rule still binds).
      var lnc;
      try { lnc = decodeExt(cert, OID.nameConstraints); }
      catch (e) { lnc = null; checks.push({ name: "nameConstraints", ok: false, code: pathCode(e, "path/bad-name-constraints") }); failed = true; }
      if (requireCriticalExt(lnc, "nameConstraints", checks)) failed = true;
      var liap;
      try { liap = decodeExt(cert, OID.inhibitAnyPolicy); }
      catch (e) { liap = null; checks.push({ name: "inhibitAnyPolicy", ok: false, code: pathCode(e, "path/bad-policy") }); failed = true; }
      if (requireCriticalExt(liap, "inhibitAnyPolicy", checks)) failed = true;
      // 4.2.1.12: when the caller states required key purposes, the target's
      // extendedKeyUsage must assert every one (or anyExtendedKeyUsage -- the
      // 4.2.1.12 wildcard; rejecting it is an application MAY, not the
      // default). An ABSENT extension leaves the key unrestricted, so it
      // satisfies any required purpose.
      if (requiredEku && ekuPurposeFails(cert, requiredEku, checks)) failed = true;
      // Trust-anchor constraint contract (NSS / CCADB metadata; gated so a bare
      // anchor or an absent checkPurpose is byte-identical to today). The anchor's
      // per-purpose distrust-after date and delegator purposes apply to the
      // end-entity leaf it ultimately certifies.
      var ta = anchor;
      // A PRESENT-but-malformed distrustAfter (an Invalid Date: instanceof Date yet a
      // NaN time) would make `notBefore > it` NaN-false and SILENTLY drop the distrust
      // restriction -- the NaN-Date fail-open. Validate a present date fail-closed
      // before the comparison; an absent (undefined/null) date is no restriction.
      var distrustDate = assertAnchorConstraints(ta, checkPurpose);
      if (distrustDate != null) {
        anchorDistrustApplied = true;
        // STRICTLY > : a leaf whose notBefore == the distrust date stays trusted
        // (Mozilla certverifier isDistrustedCertificateChain: endEntityNotBefore
        // <= distrustAfterTime -> not distrusted; the end-of-day ...235959Z
        // convention keeps the whole boundary day trusted).
        if (guard.time.instantOf(cert.validity.notBefore) > guard.time.instantOf(distrustDate)) {
          checks.push({ name: "distrustAfter", ok: false, code: "path/distrusted-after" }); failed = true;
        }
      }
      if (checkPurpose && ta.purposes) {
        anchorPurposeApplied = true;
        // The map is the operator's RESTRICTION, so it is asked for its own entry: an inherited
        // `true` would grant the purpose on every anchor whose map does not name it.
        if (!intrinsic.hasOwn(ta.purposes, checkPurpose) || ta.purposes[checkPurpose] !== true) {
          checks.push({ name: "purposeTrust", ok: false, code: "path/purpose-not-trusted" }); failed = true;
        }
      }
      updateWorkingKey(state, cert);   // 6.1.5(c),(d) -- key AND algorithm AND parameters
    }

    // 6.1.4(o) / 6.1.5(e) unrecognized critical extension.
    var unk = unrecognizedCriticalExtension(cert, i === n);
    if (unk) { checks.push({ name: "criticalExtensions", ok: false, code: "path/unrecognized-critical-extension" }); failed = true; }

    // A RECOGNIZED critical extension must still be structurally valid even
    // when its semantic gate does not run on this cert (the leaf is not subject
    // to 6.1.4, so its basicConstraints/keyUsage/policy* are never read in
    // prepareNext) -- a malformed critical extnValue must fail closed, not slip
    // through as "recognized". Decode every recognized critical extension to
    // validate it (a no-op for one already decoded above; the decoders are pure).
    var crit = validateCriticalExtensionStructure(cert);
    if (crit) { checks.push({ name: "criticalExtensionValue", ok: false, code: crit }); failed = true; }

    state.results.push({ index: idx, checks: checks });
  }

  // 6.1.5(g) success condition. The tree is first INTERSECTED with the
  // user-initial-policy-set (userConstrainedPolicies); success requires
  // explicit_policy > 0 OR that pruned tree to be non-empty. Using the raw tree
  // would accept a path whose only surviving policies are outside the user set
  // when an explicit policy is required.
  var ucps = userConstrainedPolicies(state, n);
  var policyOk = state.explicitPolicy > 0 || ucps.length > 0;
  if (!policyOk) {
    var last = state.results[state.results.length - 1];
    if (!guard.list.anyMatches(last.checks, function (c) { return c.code === "path/policy-required"; })) {
      last.checks.push({ name: "policy", ok: false, code: "path/policy-required" });
    }
    failed = true;
  }

  return {
    valid: !failed,
    // What the revocation rule and the anchor's own trust metadata actually decided. `valid` alone
    // cannot answer either, and both are questions a stored verdict is re-read to settle: was this
    // certificate ever established as un-revoked, and was the anchor's distrust date consulted.
    // The WEAKEST outcome on the path, not the fact that a checker ran: a certificate nobody could
    // answer for leaves revocation unestablished however many others answered, and deriving the word
    // from "a checker ran" put that run on the same value as one that established every answer.
    revocationChecked: !revocationRan ? false
      : revocationUndetermined ? "undetermined"
        : revocationWaived ? "waived" : "determined",
    anchorConstraints: {
      checkedPurpose: checkPurpose || null,
      distrustAfterApplied: anchorDistrustApplied,
      purposeTrustApplied: anchorPurposeApplied,
    },
    path: certs,
    results: state.results,
    workingPublicKey: state.workingPublicKey,
    workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm,
    workingPublicKeyParameters: state.workingPublicKeyParameters,
    validPolicyTree: treeWithoutParent(state.validPolicyTree),
    // 6.1.5(f): the authority-constrained policy set = the leaf-depth policies
    // in the valid-policy tree intersected with user-initial-policy-set.
    userConstrainedPolicySet: ucps,
  };
}

function userConstrainedPolicies(state, n) {
  if (!state.validPolicyTree) return [];
  var uips = state.userInitialPolicySet;
  var anyUser = contains(uips, OID.anyPolicy);
  var leaves = leavesAt(state.validPolicyTree, n);
  var explicit = {}, hasAnyLeaf = false;
  leaves.forEach(function (node) {
    if (node.validPolicy === OID.anyPolicy) hasAnyLeaf = true;
    else explicit[node.validPolicy] = true;
  });
  var set = {};
  Object.keys(explicit).forEach(function (p) { if (anyUser || contains(uips, p)) set[p] = true; });
  // 6.1.5(g) step 3: a depth-n anyPolicy node under a restrictive user set
  // expands to each user policy (the intersection of anyPolicy with the user
  // set is the user set itself).
  if (hasAnyLeaf) {
    if (anyUser) set[OID.anyPolicy] = true;
    else uips.forEach(function (p) { set[p] = true; });
  }
  return Object.keys(set);
}

// ---- the CRL revocation checker (6.3) -------------------------------------

var OID_IDP = oid.byName("issuingDistributionPoint");
var OID_DELTA_CRL = oid.byName("deltaCRLIndicator");
var OID_AUTHORITY_KEY_ID = oid.byName("authorityKeyIdentifier");
var OID_CRL_NUMBER = oid.byName("cRLNumber");
var OID_FRESHEST_CRL = oid.byName("freshestCRL");

// The RFC 5280 sec. 5.2.5 IssuingDistributionPoint grammar, shared with the CRL
// verbs (pkix.issuingDistributionPoint) so the scope this validator reads and the
// scope pki.crl.isRevoked refuses to answer past are read by the same rules.
var IDP_SCHEMA = pkix.issuingDistributionPoint("path/bad-idp");

// RFC 5280 sec. 6.3.2(a): the legal members of reasons_mask are exactly the eight
// named ReasonFlags bits, 1..8 (`unused` bit 0 is not a reason, and `unspecified`
// has no ReasonFlags bit at all). 0x1FE is bits 1..8 set.
//
// NOTE the numbering divergence, which is the trap in this area: a ReasonFlags BIT
// is not a CRLReason VALUE. Bits 1..6 coincide with codes 1..6, but bit 7 is
// privilegeWithdrawn (code 9) and bit 8 is aACompromise (code 10). sec. 6.3.3 never
// needs a mapping between them -- the mask comes only from IDP/DP ReasonFlags and
// cert_status only from an entry's CRLReason -- so no bit<->code table exists here,
// deliberately. constants.NAMES.REASON_FLAGS and NAMES.CRL_REASON stay separate.
var ALL_REASONS = 0x1FE;

// A ReasonFlags BIT STRING { unusedBits, bytes } -> a bit mask, or null when the
// encoding is not minimal DER (X.690 sec. 11.2.2 NamedBitList: trailing zero bits
// MUST be dropped). A null tells the caller the CRL's scope is unknown, which is
// the same fail-closed posture decodeIdp already takes for a malformed IDP.
//
// Bits at or above 9 are undefined by sec. 4.2.1.13. They are IGNORED rather than
// rejected: an undefined bit can never help reach all-reasons, so ignoring it can
// only withhold coverage, never grant it. Reading a bounded prefix also means a
// hostile multi-kilobyte ReasonFlags costs nothing.
function reasonMaskFromBitString(bs) {
  if (!bs || !bs.bytes) return null;
  try { schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (msg) { throw E("path/bad-idp", msg); }); }
  catch (_e) { return null; }
  var mask = 0;
  // From bit 1: sec. 6.3.2(a) defines the legal members as the eight NAMED reasons, and ReasonFlags
  // bit 0 is  -- not a reason at all. Admitting it could not grant coverage (the completeness
  // test masks with ALL_REASONS) but would make a shard that asserts ONLY bit 0 look like partial
  // coverage rather than none, which is the wrong verdict to report.
  for (var bit = 1; bit <= 8; bit++) {
    var byteI = bit >> 3;
    if (byteI >= bs.bytes.length) break;
    if (bs.bytes[byteI] & (0x80 >> (bit & 7))) mask |= (1 << bit);
  }
  return mask;
}

// RFC 5280 sec. 6.3.3(d)(1)-(4) -- the interim_reasons_mask, in ONE place.
//   (1) both present            -> intersection
//   (2) IDP present, DP absent  -> the IDP's reasons
//   (3) IDP absent, DP present  -> the DP's reasons
//   (4) both absent             -> all-reasons
// A null mask means "present but unreadable"; the caller has already marked such a
// CRL unusable, so treating it as 0 here is belt-and-braces, never a coverage grant.
function interimReasonMask(idpMask, dpMask) {
  if (idpMask != null && dpMask != null) return idpMask & dpMask;      // (d)(1)
  if (idpMask != null) return idpMask;                                  // (d)(2)
  if (dpMask != null) return dpMask;                                    // (d)(3)
  return ALL_REASONS;                                                   // (d)(4)
}

function decodeIdp(ext) {
  // Surface the scope flags the checker gates on. ANY structural or value fault
  // -- non-SEQUENCE, unknown/duplicate/out-of-order field tag, a non-DER BOOLEAN,
  // an encoded-FALSE default, a malformed DistributionPointName -- leaves the
  // CRL's scope unknown: the CRL is unusable, never assumed unrestricted.
  var out = { hasDistributionPoint: false, distributionPoint: null, onlyUser: false, onlyCa: false, onlySomeReasons: null, indirect: false, onlyAttr: false, malformed: false };
  var m;
  try {
    m = schema.walk(IDP_SCHEMA, asn1.decode(ext.value), NS);
    if (m.fields.distributionPoint.present) {
      // distributionPoint [0] EXPLICIT-wraps the DistributionPointName CHOICE
      // (a context tag on a CHOICE-typed field is always EXPLICIT). The decoded
      // name feeds the sec. 6.3.3(b)(2)(i) correspondence against the
      // certificate's own DistributionPoints in the checker below.
      var dpnWrap = m.fields.distributionPoint.node;
      if (!dpnWrap.children || dpnWrap.children.length !== 1) {
        throw E("path/bad-idp", "IssuingDistributionPoint distributionPoint [0] must wrap exactly one DistributionPointName");
      }
      out.distributionPoint = pkix.distributionPointName(NS, dpnWrap.children[0], "path/bad-idp");
    }
  }
  catch (_e) { out.malformed = true; return out; }
  function flag(f) {
    if (!f.present) return false;
    // A present flag must encode DER-TRUE; a FALSE is the omitted DEFAULT
    // (X.690 sec. 11.5), so mark the scope unknown and report not-set.
    var isSet = f.value === true;
    if (!isSet) out.malformed = true;
    return isSet;
  }
  out.hasDistributionPoint = m.fields.distributionPoint.present;
  out.onlyUser = flag(m.fields.onlyContainsUserCerts);
  out.onlyCa = flag(m.fields.onlyContainsCACerts);
  out.onlySomeReasons = m.fields.onlySomeReasons.present ? true : null;
  // The reason BITS, not just their presence: sec. 6.3.3(d)(1)/(d)(2) need the
  // value. A present-but-non-minimal ReasonFlags leaves the CRL's scope unknown,
  // which is the same unusable posture every other IDP fault takes -- otherwise
  // the (d)(1) intersection would be computed over an encoding DER forbids.
  out.onlySomeReasonsMask = null;
  if (m.fields.onlySomeReasons.present) {
    out.onlySomeReasonsMask = reasonMaskFromBitString(m.fields.onlySomeReasons.value);
    if (out.onlySomeReasonsMask === null) out.malformed = true;
  }
  out.indirect = flag(m.fields.indirectCRL);
  out.onlyAttr = flag(m.fields.onlyContainsAttributeCerts);
  return out;
}

// RFC 5280 sec. 6.3.3(b)(2)(i): find the certificate DistributionPoint that
// CORRESPONDS to a shard CRL's IDP distribution point name. The correspondence
// rule itself -- at least one name in common, compared by BYTE-IDENTICAL DER,
// mixed name forms never corresponding -- is guard.name.dpnCorresponds, which
// is also what a CMP crlUpdate answer is held to, so one definition decides
// whether a CRL speaks for a point wherever the question is asked. Per sec.
// 6.3.3(b)(1), a DP naming a cRLIssuer participates only when that cRLIssuer
// is the certificate issuer itself: the checker only consults CRLs issued BY
// the certificate issuer and rejects indirect CRLs, so a DP delegated to
// another CRL issuer is out of play. Returns the matched DP (its `reasons`
// feeds the coarse reason-mask rule) or null.
function correspondingCertDp(idpDpn, certDPs, issuerRdns) {
  if (!idpDpn || !certDPs) return null;
  for (var i = 0; i < certDPs.length; i++) {
    var dp = certDPs[i];
    if (!dp.distributionPoint) continue;
    if (dp.cRLIssuer && !crlIssuerNamesIssuer(dp.cRLIssuer, issuerRdns)) continue;
    if (guard.name.dpnCorresponds(idpDpn, dp.distributionPoint, E, "path/bad-idp", "a CRL distribution point")) return dp;
  }
  return null;
}

// Does a DistributionPoint's cRLIssuer name the certificate issuer? True iff
// one of its GeneralNames is a directoryName equal to the issuer DN under the
// RFC 5280 sec. 7.1 comparison (the shared name guard, via this file's dnEqual
// wrapper). Any fault -- a DN the comparison rejects for an embedded control
// byte -- resolves false: the DP stays out of the correspondence (fail closed).
function crlIssuerNamesIssuer(cRLIssuer, issuerRdns) {
  for (var i = 0; i < cRLIssuer.names.length; i++) {
    var n = cRLIssuer.names[i];
    if (n.tagNumber !== 4 || !n.value || !n.value.rdns) continue;
    // dnEqual throws only on a control-byte / malformed cRLIssuer DN; returning false excludes
    // that DP from the correspondence (a malformed indirect-CRL issuer name never corresponds).
    try { if (dnEqual(n.value.rdns, issuerRdns)) return true; }
    catch (_e) { return false; }
  }
  return false;
}

// The raw extnValue octets of a CRL extension, or null. sec. 6.3.3(c)(2)/(c)(3)
// compare the IDP and authorityKeyIdentifier of a delta and its base for identity;
// the comparison is over the exact encoded octets (the sec. 5.2.5 @3648
// "identical encoding" discipline already used for distributionPoint matching),
// never over a re-normalized decode.
function crlExtValue(theCrl, wantOid) {
  for (var i = 0; i < theCrl.crlExtensions.length; i++) {
    if (theCrl.crlExtensions[i].oid === wantOid) return theCrl.crlExtensions[i].value;
  }
  return null;
}

// One pass over the bundle: split complete CRLs from deltas and decode, per CRL,
// the values the merge preconditions compare. A delta whose BaseCRLNumber will not
// decode as a non-negative INTEGER is unusable AS A DELTA but stays consultable for
// revocation -- dropping it wholesale would lose a revocation it lists (T1).
// RFC 5280 sec. 5.2.3 @3404 bounds a CRL number at 20 octets, and pki.crl.sign enforces that on
// emission. A number past it is non-conforming, so it does not earn the merge -- which can RELEASE
// a certificate. The value still decodes and the CRL is still consulted for revocation; only the
// new capability is withheld. Measured on the ENCODED length, matching the producer-side check
// rather than a re-derived numeric bound.
function crlNumberWithinBound(n) {
  if (typeof n !== "bigint" || n < 0n) return false;
  try { return asn1.decode(asn1.build.integer(n)).content.length <= 20; }
  catch (_e) { return false; }
}

function classifyCrls(parsed) {
  var completes = [], deltas = [];
  for (var i = 0; i < parsed.length; i++) {
    var theCrl = parsed[i];
    var deltaRaw = crlExtValue(theCrl, OID_DELTA_CRL);
    var deltaCritical = false;
    for (var dz = 0; dz < theCrl.crlExtensions.length; dz++) {
      if (theCrl.crlExtensions[dz].oid === OID_DELTA_CRL) { deltaCritical = theCrl.crlExtensions[dz].critical === true; break; }
    }
    // schema-crl already decoded cRLNumber to a non-negative BigInt; the IDP,
    // authorityKeyIdentifier and deltaCRLIndicator values stay RAW octets there,
    // which is exactly what the byte-identical compares below need.
    var num = crlExtValue(theCrl, OID_CRL_NUMBER);
    var rec = {
      crl: theCrl,
      crlNumber: crlNumberWithinBound(num) ? num : null,
      idpRaw: crlExtValue(theCrl, OID_IDP),
      akiRaw: crlExtValue(theCrl, OID_AUTHORITY_KEY_ID),
      baseCrlNumber: null,
      mergeable: false,
    };
    if (deltaRaw === null) { completes.push(rec); continue; }
    try {
      var n = asn1.read.integer(asn1.decode(deltaRaw));
      // sec. 5.2.3 @3404: a CRL number may be up to 20 octets. It stays a BigInt
      // through every comparison below -- narrowing through Number would collapse
      // large values and make 5.2.4(c)/(d) compare the wrong things.
      // sec. 5.2.4 @3447 makes deltaCRLIndicator a MUST-be-critical extension. A non-critical one
      // is non-conforming, so it does not earn the NEW capability of being merged -- merging can
      // RELEASE a certificate, and that must rest on a conforming indicator. It is still classified
      // as a delta and still consulted for revocation, which is the shipped behavior and the
      // conservative direction.
      if (crlNumberWithinBound(n) && deltaCritical) { rec.baseCrlNumber = n; rec.mergeable = true; }
    } catch (_e) {
      // Unusable AS A DELTA, but still scanned for revocation. That is the conservative direction:
      // the CRL is still the issuer's, signed and current (it must pass every gate before it is
      // consulted), so a serial it lists is a genuine revocation and dropping it wholesale could
      // lose one. Consulting it can only ever find MORE revocations, never grant coverage -- a
      // delta contributes no reason mask.
    }
    deltas.push(rec);
  }
  return { completes: completes, deltas: deltas };
}

// RFC 5280 sec. 6.3.3(c)(1)-(3) + sec. 5.2.4(a)-(d), as one predicate. Every
// comparison is BigInt or byte-exact: no narrowing, no canonicalization. An
// extension ABSENT on both sides matches; present on one side only does not.
function deltaMergesWith(delta, complete) {
  if (!delta.mergeable) return false;
  // Both numbers are required: 5.2.4(c)/(d) are ordering rules, and a missing
  // cRLNumber on either side leaves the ordering unknowable -- fail closed.
  if (complete.crlNumber === null || delta.crlNumber === null) return false;
  if (!dnEqualUsable(delta.crl.issuer.rdns, complete.crl.issuer.rdns)) return false;  // (c)(1)
  if (!sameRawExt(delta.idpRaw, complete.idpRaw)) return false; // (c)(2) / 5.2.4(b)
  if (!sameRawExt(delta.akiRaw, complete.akiRaw)) return false; // (c)(3)
  if (!(complete.crlNumber >= delta.baseCrlNumber)) return false;  // 5.2.4(c)
  if (!(complete.crlNumber < delta.crlNumber)) return false;      // 5.2.4(d)
  return true;
}
// dnEqual THROWS on a DN carrying an embedded NUL/control byte (CVE-2009-2408).
// For the merge preconditions a DN that cannot be compared is simply not a match:
// the delta and the base are not shown to share an issuer, so they are not merged.
// The throw is contained here rather than at the call site so the predicate itself
// stays a straight-line sequence of comparisons.
function dnEqualUsable(a, b) {
  try { return dnEqual(a, b); }
  catch (_e) { return false; }
}

function sameRawExt(a, b) {
  if (a === null && b === null) return true;
  if (a === null || b === null) return false;
  return a.equals(b);
}

// sec. 5.2.4 @3580 makes MULTIPLE current deltas for one scope legal and says the
// application SHOULD take the one with the latest thisUpdate. Selection, never
// rejection: treating two current deltas as a fault would refuse a conforming
// publication. Ties break on the greater cRLNumber, then first-wins.
function selectDelta(candidates) {
  var best = null;
  for (var i = 0; i < candidates.length; i++) {
    var c = candidates[i];
    if (best === null) { best = c; continue; }
    var t = guard.time.instantOf(c.crl.thisUpdate), bt = guard.time.instantOf(best.crl.thisUpdate);
    if (t > bt) { best = c; continue; }
    if (t === bt && c.crlNumber !== null && best.crlNumber !== null && c.crlNumber > best.crlNumber) best = c;
  }
  return best;
}

/**
 * @primitive  pki.path.crlChecker
 * @signature  pki.path.crlChecker(crls, opts?) -> RevocationChecker
 * @since      0.1.16
 * @status     stable
 * @spec       RFC 5280
 * @related    pki.path.validate, pki.schema.crl.parse
 *
 * Build a CRL-backed `RevocationChecker` for `pki.path.validate`'s
 * `revocationChecker` option from a set of CRLs (DER/PEM or already-parsed).
 * For each certificate it locates a CRL issued by the certificate's issuer,
 * verifies the CRL signature over its `tbsBytes`, honors the issuing
 * distribution point scope and reason coverage, checks currency
 * (`thisUpdate`/`nextUpdate`), and reports `{ status: "good"|"revoked"|
 * "unknown" }`. A partitioned/sharded CRL (a critical IDP naming a
 * distribution point) establishes "good" when it corresponds to one of the
 * certificate's own cRLDistributionPoints -- at least one identically-encoded
 * name in common (RFC 5280 sec. 6.3.3). Reason-sharded CRLs ACCUMULATE: each
 * corresponding CRL contributes its interim reason mask (sec. 6.3.3(d)) and the
 * certificate is "good" once the shards together cover all eight revocation
 * reasons, so a CA that partitions by reason code is served. A DELTA CRL is
 * merged onto a complete CRL it may be combined with (sec. 5.2.4 / 6.3.3(c)):
 * the delta is searched first, the complete CRL only if the delta left the
 * status unrevoked, and `removeFromCRL` then releases the certificate. A
 * base+delta pair reports a real verdict where the base alone could not. A
 * delta that merges with nothing is still consulted for revocation and still
 * blocks "good": merging may turn undetermined into good or revoked, never a
 * revoked into a good. A non-corresponding shard is consulted for revocation
 * only. An out-of-scope, stale, unauthorized, or unverifiable CRL yields
 * `unknown`, which the validator fails closed unless `softFail` is set.
 *
 * A `revoked` verdict carries `reasonCode` (the CRLReason integer, 0 for
 * `unspecified`) and a `reason` naming it.
 *
 * @opts
 *   useDeltas  boolean  merge delta CRLs onto their base (RFC 5280 sec. 6.3.1(b)).
 *                       Default true. When false a delta is never merged; it is
 *                       still consulted for revocation.
 *
 * @example
 *   var checker = pki.path.crlChecker([]);   // no CRLs -> every cert is "unknown"
 *   typeof checker.check;                     // "function"
 */
function crlChecker(crls, opts) {
  var parsed = (crls || []).map(function (c, ci) {
    // Re-derived from the bytes the parser read, exactly as a certificate is. A CRL's answer is a
    // verdict, and its signature covers a byte range while the revocation list and the scope
    // extensions are separate properties of the parsed object: keep a correctly signed CRL's
    // `tbsBytes` and signature, empty `revokedCertificates`, and the signature still verifies while
    // a revoked certificate reports good. The scope fields fail the same way -- an emptied
    // `crlExtensions` turns a scope-restricted CRL into one that answers for everything.
    return guard.parsed.acceptDerived(c, "crl", crl.parse, E, "path/bad-input",
      "crlChecker: crls[" + ci + "]");
  });
  // RFC 5280 sec. 6.3.1(b): use-deltas is an INPUT to the algorithm. Default ON --
  // a caller holding a delta wants it used -- and turning it off never makes a
  // verdict weaker, only less determined.
  var useDeltas = !(opts && opts.useDeltas === false);
  return {
    check: async function (cert, issuer, ctx) {
      var time = ctx.time;
      var historical = ctx.historicalMode === true;
      // The cert's CA-ness gates the IDP scope flags (onlyContainsUserCerts /
      // onlyContainsCACerts, RFC 5280 sec. 6.3.3(b)(2)). An UNREADABLE
      // basicConstraints leaves that scope undeterminable -- guessing "not a
      // CA" would consult a user-only CRL for what may be a CA certificate
      // (out of the CRL's scope, so its silence proves nothing) -- so certIsCa
      // stays null, BOTH scoped forms are skipped below, and only a
      // full-scope CRL can speak for this certificate. The decode fault is
      // carried into the undetermined verdict's reason.
      var certIsCa = null, certScopeFault = null;
      try {
        var bc = decodeExt(cert, OID.basicConstraints);
        certIsCa = !!(bc && bc.value.cA === true);
      } catch (e) {
        certScopeFault = pathCode(e, "path/bad-extension-value");
      }
      // The certificate's own cRLDistributionPoints, decoded once per check:
      // the sec. 6.3.3(b)(2)(i) correspondence gate below needs the DP names.
      // A decode fault leaves certDPs null -- every DP-scoped shard then stays
      // revocation-only (no correspondence can be shown; fail closed) while
      // the full-CRL path is unaffected (mirrors the basicConstraints
      // handling above); the check never crashes on a malformed extension.
      var certDPs = null;
      var certCdpExt = findExt(cert, OID.cRLDistributionPoints);
      if (certCdpExt) {
        try { certDPs = EXT_DECODERS[OID.cRLDistributionPoints](certCdpExt.value); }
        catch (_e) { certDPs = null; }
      }
      // RFC 5280 sec. 6.3.3(f): IF a keyUsage extension is present in the CRL issuer's
      // certificate, the cRLSign bit must be VERIFIED set. An issuer that OMITS
      // keyUsage is unconstrained (the same rule the sec. 6.1.4(n) keyCertSign gate
      // applies to certificate signing), so its CRL is authoritative. The anchor
      // is likewise unconstrained (issuerCert is null for the cert it directly
      // issued). A PRESENT-but-unreadable keyUsage cannot be verified -- treating
      // it like an absent one would let garbage keyUsage bytes authorize CRL
      // signing -- so no CRL from this issuer can be authoritative.
      var signerAuthorized = true;
      if (issuer && issuer.issuerCert) {
        var iku;
        try { iku = decodeExt(issuer.issuerCert, OID.keyUsage); }
        catch (e) {
          return { status: "unknown", reason: "the CRL issuer's keyUsage extension is unreadable (" + pathCode(e, "path/bad-key-usage") + "), so its authorization to sign CRLs cannot be verified" };
        }
        if (iku && iku.value.cRLSign !== true) signerAuthorized = false;
      }

      // Consult EVERY CRL issued by the cert's issuer -- a clean CRL must not
      // shadow a revoking one (RFC 5280 sec. 6.3.3). A serial listed in ANY
      // authoritative, in-scope, current, verified CRL is revoked; the cert is
      // "good" only when the CRLs consulted together cover ALL EIGHT revocation
      // reasons (sec. 6.3.3(l) + the termination rule at @5291) and none list it.
      //
      // Note there is deliberately no early exit once the mask is complete: the
      // shipped checker scans every CRL so a clean one cannot shadow a revoking
      // one, and stopping at full coverage would reintroduce exactly that.
      var certStatus = null;          // sec. 6.3.2(b) cert_status; null = UNREVOKED
      var reasonsMask = 0;            // sec. 6.3.2(a) reasons_mask; the empty set
      var releasedByUnmergedDelta = false;
      // A CURRENT, authoritative delta that merged with nothing means the local
      // revocation picture is incomplete: the base it names may be newer than any
      // complete CRL held here, so a clean base proves less than it appears to.
      // The shipped checker blocks  on exactly this, and the merge must only
      // ever turn undetermined INTO good -- never make an unmerged delta weaker
      // than it was before this feature existed.
      var sawUnmergedDelta = false;
      var classified = classifyCrls(parsed);
      var consumedDeltas = [];

      // Every gate a CRL must pass before it may speak for this certificate, in
      // the shipped order. Returns null when the CRL is unusable, otherwise the
      // interim_reasons_mask it may contribute -- 0 meaning "consulted for
      // revocation only", which is how a non-corresponding shard is honestly
      // encoded (it can reveal a revocation but can never establish coverage).
      async function gateCrl(rec) {
        // Memoized per RECORD, and the records are rebuilt by classifyCrls on every check(), so the
        // cache is per-call and the checker stays re-entrant. Without it the base-by-delta pairing
        // below would repeat an asynchronous public-key signature verification for every pair --
        // O(completes x deltas) verifications where the shipped loop did O(crls).
        if (rec._gated) return rec._gate;
        rec._gate = await gateCrlUncached(rec);
        rec._gated = true;
        return rec._gate;
      }
      async function gateCrlUncached(rec) {
        var theCrl = rec.crl;
        // dnEqual throws on a DN carrying an embedded NUL/control byte (CVE-2009-2408).
        // A single malformed CRL in the bundle must NOT abort the whole check (which
        // would mask a later authoritative CRL and pass under softFail) -- treat it
        // as unusable and skip it, consulting the remaining CRLs.
        var issuerMatches;
        try { issuerMatches = dnEqual(theCrl.issuer.rdns, cert.issuer.rdns); }
        catch (_e) { return null; }
        if (!issuerMatches) return null;
        if (!signerAuthorized) return null;

        // A validly-signed CRL carrying a CRITICAL extension this checker does
        // not understand (anything but issuingDistributionPoint / deltaCRLIndicator)
        // may change the CRL's scope or meaning -- treat it as unusable (RFC 5280
        // sec. 5.2 critical-extension semantics), never authoritative.
        var unhandledCritical = false;
        for (var x = 0; x < theCrl.crlExtensions.length; x++) {
          var xe = theCrl.crlExtensions[x];
          if (xe.critical && xe.oid !== OID_IDP && xe.oid !== OID_DELTA_CRL) { unhandledCritical = true; break; }
        }
        // RFC 5280 sec. 5.3: a critical CRL-ENTRY extension the checker cannot
        // process (anything but reasonCode) makes the CRL unusable for ANY
        // certificate, not just the entry that carries it.
        for (var ry = 0; ry < theCrl.revokedCertificates.length && !unhandledCritical; ry++) {
          // Coverage residual -- the `|| []` fallback is unreachable: schema-crl sets
          // crlEntryExtensions to [] when absent, so it is always an array.
          var ees = theCrl.revokedCertificates[ry].crlEntryExtensions || [];
          for (var ex = 0; ex < ees.length; ex++) {
            // Key on the stable OID only -- a display name is registry-dependent
            // (a custom OID could be registered as "reasonCode"), so matching by
            // name would let an unhandled critical entry extension fail open.
            if (ees[ex].critical && ees[ex].oid !== OID_REASON_CODE) { unhandledCritical = true; break; }
          }
        }
        if (unhandledCritical) return null;

        // sec. 6.3.3(d): the interim reason mask this CRL contributes. Its two
        // inputs are the IDP's onlySomeReasons and the CORRESPONDING certificate
        // DistributionPoint's reasons -- never an entry's reasonCode (sec. 5.2.5
        // @3628 explicitly permits a shard entry to omit one).
        // Set when the shard covers no reasons for this certificate. It is recorded rather than
        // RETURNED here: the currency and signature gates below still have to run, or an expired,
        // not-yet-valid or FORGED shard could be scanned for revocations and falsely revoke.
        var noCoverage = false;
        var idpMask = null, dpMask = null, sawIdp = false;
        var idpExtension = null;
        for (var e = 0; e < theCrl.crlExtensions.length; e++) if (theCrl.crlExtensions[e].oid === OID_IDP) idpExtension = theCrl.crlExtensions[e];
        if (idpExtension) {
          sawIdp = true;
          var idp = decodeIdp(idpExtension);
          if (idp.malformed) return null;                    // scope unknown -> unusable
          // An indirect CRL carries entries for other issuers keyed by the
          // per-entry certificateIssuer attribute (not tracked here) -- matching
          // by serial alone could revoke the wrong cert or falsely cover it, so
          // treat an indirect CRL as unusable until certificateIssuer is honored.
          if (idp.indirect) return null;
          if (idp.onlyAttr) return null;                     // scoped to attribute certs, not this public-key cert
          if (idp.onlyCa && certIsCa !== true) return null;   // out of scope (or CA-ness undeterminable)
          if (idp.onlyUser && certIsCa !== false) return null;
          // The same fail-closed decision the distributionPoint correspondence rests on (sec. 5.2.5
          // @3601 lets a relying party not support the IDP at all): a scope a non-supporting
          // verifier would IGNORE is not a scope to build coverage on. So a non-critical IDP's
          // onlySomeReasons contributes nothing -- which also preserves the shipped property that
          // an onlySomeReasons shard could only ever WITHHOLD good, never establish it.
          if (idpExtension.critical === true) idpMask = idp.onlySomeReasonsMask;
          else if (idp.onlySomeReasons) noCoverage = true;
          if (idp.hasDistributionPoint) {
            // RFC 5280 sec. 6.3.3(b)(2)(i): a partition shard speaks for this
            // certificate only when the IDP's distribution point shares at
            // least one IDENTICALLY-ENCODED name with one of the certificate's
            // own DistributionPoints (sec. 5.2.5: "The identical encoding MUST
            // be used in the distributionPoint fields of the certificate and
            // the CRL"). The IDP must also be CRITICAL to be relied on for
            // scope: sec. 5.2.5 describes the IDP as "a critical CRL extension"
            // (descriptive phrasing, not an imperative MUST -- and @3601 lets a
            // relying party not support it at all), so building coverage on a
            // scope a non-supporting verifier would ignore is a deliberate
            // fail-closed decision. A non-corresponding shard contributes NO
            // coverage but is still consulted for revocation below: serials are
            // unique per issuer, so a listed serial is a genuine revocation.
            var matchedDp = idpExtension.critical === true
              ? correspondingCertDp(idp.distributionPoint, certDPs, cert.issuer.rdns)
              : null;
            if (!matchedDp) noCoverage = true;
            // sec. 6.3.3(d)(1)/(d)(3): a matched DP carrying `reasons` bounds the
            // interim mask. A present-but-unreadable value cannot bound anything
            // safely, so it contributes nothing rather than defaulting open.
            else if (matchedDp.reasons) {
              dpMask = reasonMaskFromBitString(matchedDp.reasons);
              if (dpMask === null) noCoverage = true;
            }
          }
        }
        if (guard.time.instantOf(theCrl.thisUpdate) > guard.time.instantOf(time)) return null;   // not yet valid
        // A CRL with no nextUpdate has no bounded validity -- its currency
        // cannot be confirmed (RFC 5280 sec. 5.1.2.5 requires nextUpdate), so a
        // replayed old CRL must not read "good". Treat it as unusable.
        if (!theCrl.nextUpdate ||
          guard.time.instantOf(theCrl.nextUpdate) < guard.time.instantOf(time)) return null;   // stale / no bound

        var sigOk = await crlVerify.verifyCrlSignature(theCrl, issuer.workingPublicKey);
        if (!sigOk) return null;                              // unverifiable -> not authoritative

        // sec. 6.3.3 @5295: a CRL not named by any distribution point is processed
        // as though under a DP whose `reasons` and `cRLIssuer` are absent -- i.e.
        // all-reasons. That is why a full-scope CRL still covers a certificate
        // that happens to carry a cRLDistributionPoints extension.
        void sawIdp;
        return { interim: noCoverage ? 0 : interimReasonMask(idpMask, dpMask) };
      }

      // sec. 6.3.3(i)/(j): the certificate's entry on one CRL, as a CRLReason
      // value, or null for UNREVOKED. sec. 6.3.3(i)(2): an entry with no
      // reasonCode extension is `unspecified` (0), which is a revocation.
      function scanCrl(theCrl) {
        for (var r = 0; r < theCrl.revokedCertificates.length; r++) {
          var entry = theCrl.revokedCertificates[r];
          if (entry.serialNumberHex !== cert.serialNumberHex) continue;
          // A revocation is effective as of its revocationDate (RFC 5280 sec. 5.3).
          // In the DEFAULT present-time validation a listed serial is revoked
          // regardless of that date -- a future revocationDate is post-dating or
          // clock skew and must NOT read good. Only under an EXPLICIT historical
          // validation (opts.historicalMode) -- validating as of a past instant,
          // e.g. a timestamped signature -- does an entry dated AFTER the
          // validation time not yet apply.
          // allow:nan-date-comparison-unguarded -- revocationDate is codec-parsed (NaN-rejected); a NaN check time makes this FAIL CLOSED (the skip is not taken -> the entry is treated as revoked), and `time` is validated at the path.validate / crlChecker entry points.
          if (historical && guard.time.isDate(entry.revocationDate) &&
            guard.time.instantOf(entry.revocationDate) > guard.time.instantOf(time)) continue;
          var rc = crlEntryReason(entry);
          return rc === null ? 0 : rc;
        }
        return null;
      }

      // sec. 6.3.3(a)(2): a delta is obtained only when use-deltas is set AND a
      // locator exists -- freshestCRL on the certificate or on the complete CRL.
      // sec. 5.2.6 @3719: the locator's CONTENTS are only ever used to find a
      // delta, never to validate one, so its presence is the whole gate.
      // PRESENCE only, deliberately. sec. 5.2.6 @3719 says the freshestCRL contents are used to
      // LOCATE a delta and never to validate one, so decoding them would be using a value the RFC
      // says not to use. It is also not a security control: enabling the merge grants nothing on its
      // own, because a delta still has to pass every gate -- issuer, authorization, criticality,
      // scope, currency and SIGNATURE -- plus the sec. 5.2.4 merge preconditions. An attacker who
      // could satisfy those already controls the issuing key.
      var certHasFreshest = !!findExt(cert, OID_FRESHEST_CRL);
      function deltaLocatorPresent(completeRec) {
        return certHasFreshest || crlExtValue(completeRec.crl, OID_FRESHEST_CRL) !== null;
      }

      for (var ci = 0; ci < classified.completes.length; ci++) {
        var rec = classified.completes[ci];
        var gate = await gateCrl(rec);
        if (!gate) continue;

        // sec. 6.3.3(c): pair this complete CRL with a delta it may be combined
        // with. The delta passes its OWN gates first -- sec. 6.3.3(h) requires
        // its signature verified and (f) its issuer authorized, exactly as for a
        // complete CRL -- so a stale, unverifiable or out-of-scope delta is never
        // merged.
        var chosenDelta = null;
        if (useDeltas && deltaLocatorPresent(rec)) {
          var candidates = [];
          for (var di = 0; di < classified.deltas.length; di++) {
            var cand = classified.deltas[di];
            if (!deltaMergesWith(cand, rec)) continue;
            if (!(await gateCrl(cand))) continue;
            // Mergeable and usable: this delta's scope IS covered by a merge, even
            // if sec. 5.2.4 @3580 selection prefers a sibling with a later
            // thisUpdate. Only a delta that pairs with NO complete CRL leaves the
            // picture incomplete -- a losing candidate must not block a good result,
            // or publishing two current deltas (which the RFC permits) would be
            // worse than publishing one.
            cand.accounted = true;
            candidates.push(cand);
          }
          chosenDelta = selectDelta(candidates);
        }

        var status;
        if (chosenDelta) {
          consumedDeltas.push(chosenDelta);
          status = scanCrl(chosenDelta.crl);                   // (i) search the delta FIRST
          if (status === null) status = scanCrl(rec.crl);      // (j) the complete CRL only if still UNREVOKED
        } else {
          status = scanCrl(rec.crl);
        }
        // (k): removeFromCRL means the certificate is no longer revoked. It is
        // normalized wherever it appears -- sec. 5.3.1's "only in delta CRLs" binds
        // the CA that emits it, not this consumer, and rejecting a complete CRL
        // that carries one would make an unusual-but-harmless CRL unusable.
        if (status === 8) status = null;

        if (status !== null && certStatus === null) certStatus = status;
        else if (status === null) reasonsMask |= gate.interim;  // (l): only a clean scope covers
      }

      // An unmerged delta still speaks, under the shipped fail-closed posture: a
      // serial it lists is a genuine revocation (serials are unique per issuer),
      // and a removeFromCRL it carries blocks a definitive revoked without being
      // able to establish good. This is what keeps the merge MONOTONIC -- it may
      // turn undetermined into good or revoked, but a delta that merges with
      // nothing can never erase a revocation the checker would otherwise report.
      for (var dj = 0; dj < classified.deltas.length; dj++) {
        var dRec = classified.deltas[dj];
        if (contains(consumedDeltas, dRec)) continue;
        // A delta that was MERGEABLE with some complete CRL but lost the sec. 5.2.4 @3580 selection
        // does not speak for its scope at all -- the selected delta does, and it was evaluated
        // against the base. Letting a superseded delta contribute its revocation while ignoring its
        // release would be incoherent: an older delta revoking a certificate that the newer one
        // releases would resurrect the revocation the CA withdrew.
        if (dRec.accounted) continue;
        if (!(await gateCrl(dRec))) continue;
        sawUnmergedDelta = true;
        var dStatus = scanCrl(dRec.crl);
        if (dStatus === null) continue;
        if (dStatus === 8) { releasedByUnmergedDelta = true; continue; }
        if (certStatus === null) certStatus = dStatus;
      }

      // A delta released this serial from hold but its base was not merged: a
      // definitive revoked would leave a released certificate rejected, so the
      // status is undetermined. This outranks a base CRL's revocation.
      if (releasedByUnmergedDelta) return { status: "unknown", reason: "a delta CRL released this serial from hold; without merging its base CRL the revocation status is undetermined" };
      if (certStatus !== null) {
        var reasonName = constants.NAMES.CRL_REASON[String(certStatus)] || "unspecified";
        return { status: "revoked", reasonCode: certStatus, reason: "serial listed in a CRL (" + reasonName + ")" };
      }
      if (sawUnmergedDelta) return { status: "unknown", reason: "a delta CRL cannot be combined with any complete CRL held here, so the revocation picture is incomplete" };
      if ((reasonsMask & ALL_REASONS) === ALL_REASONS) return { status: "good" };
      if (certScopeFault) {
        return { status: "unknown", reason: "no authoritative in-scope CRL covers this certificate; its basicConstraints extension is unreadable (" + certScopeFault + "), so scope-limited CRLs were skipped" };
      }
      if (reasonsMask !== 0) {
        return { status: "unknown", reason: "the CRLs available cover only some revocation reasons for this certificate; no combination covers all of them" };
      }
      return { status: "unknown", reason: "no authoritative in-scope CRL covers this certificate" };
    },
  };
}

// The decoded reasonCode of a revoked CRL entry (crl.parse surfaces it as a
// number), or null when absent.
var OID_REASON_CODE = oid.byName("reasonCode");
function crlEntryReason(entry) {
  // Coverage residual -- the `|| []` fallback is unreachable: schema-crl guarantees
  // crlEntryExtensions is an array (empty when absent).
  var exts = entry.crlEntryExtensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid === OID_REASON_CODE) return exts[i].value;   // stable OID, not the display name
  }
  return null;
}

// Verify a raw signature over tbsBytes with an SPKI public key -- the shared core
// of every certificate / CRL / OCSP signature check. Resolve the algorithm
// descriptor, enforce the key-OID <-> sig-OID binding (the algorithm-confusion
// guard, RFC 9814 sec. 4), import the SPKI, bridge an ECDSA DER signature to
// P1363, and verify. Any fault -- an unresolvable/forbidden algorithm, a
// key/sig mismatch, an import or verify failure -- resolves false: a signature
// check never throws out of this path, it fails closed. `rawSig` is the raw
// signature octets (the caller has already unwrapped any BIT STRING and rejected
// a non-octet-aligned one).
function _verifyWithSpki(sigAlg, rawSig, spkiBytes, tbsBytes) {
  var d;
  try {
    d = resolveDescriptor(sigAlg);
    assertKeyMatchesSigAlg(spkiBytes, sigAlg.oid, d);
  } catch (_e) { return Promise.resolve(false); }
  // A composite-signed CRL / OCSP response verifies through the same combinator
  // (both halves must pass) that the certificate path uses -- one composite verify,
  // never a second parallel one.
  if (d.composite) return compositeSig.compositeVerify(spkiBytes, rawSig, tbsBytes, d.composite, PathError, "path/unsupported-algorithm", "path/bad-signature").then(function (r) { return r.ok === true; });
  return _importVerifyKey(spkiBytes, d).then(function (key) {
    var sig = rawSig;
    if (d.ecdsa) sig = validator.sig.ecdsaDerToP1363(sig, key.algorithm.namedCurve, PathError, "path/bad-signature");
    return subtle.verify(d.verify, key, sig, tbsBytes);
  }).then(function (ok) { return ok === true; }, function () { return false; });
}

// Inject this validator's signature engine into the shared internal crl-verify seam, so pki.crl.verify and
// pki.path.crlChecker both route through this ONE engine (no second, weaker CRL verifier) without exposing
// the seam on the public pki.path surface.
crlVerify.setEngine(_verifyWithSpki);

// The same seam for PKCS#10 proof of possession, so pki.csr.verify checks an inbound certification
// request through this ONE engine rather than the producing side's self-check, which waives the
// EdDSA low-order-point gate because it runs over a key the caller already controls.
csrVerify.setEngine(_verifyWithSpki);

// And for RFC 4211 proof of possession, so an inbound CertReqMsg is checked through the same one
// engine as the PKCS#10 form of the same question.
crmfVerify.setEngine(_verifyWithSpki);

// And for an RFC 5755 attribute certificate, whose AC issuer is an out-of-path signer reached the
// same way.
attrcertVerify.setEngine(_verifyWithSpki);

// ---- the OCSP revocation checker (RFC 6960) -------------------------------

// The OCSP response-verification core (responder authorization + CertID binding + currency +
// status) lives ONCE in lib/ocsp-verify.js, composed here by pki.path.ocspChecker AND by
// pki.ocsp.verify -- there is no second, weaker OCSP verify path. This binds the path-validate-
// owned signature engine + RFC 5280 cert-profile gates into that shared core.
var ocspCore = ocspVerify.makeOcspVerify({
  verifyWithSpki: _verifyWithSpki,
  decodeExt: decodeExt, findExt: findExt,
  unrecognizedCriticalExtension: unrecognizedCriticalExtension,
  validateCriticalExtensionStructure: validateCriticalExtensionStructure,
  compositeKeyUsageCheck: compositeKeyUsageCheck,
  isNullOrAbsentParams: isNullOrAbsentParams, spliceSpkiParameters: spliceSpkiParameters,
  dnEqual: dnEqual,
});

// Inject this validator's signature engine + full path build/validate into the internal cmp-verify seam,
// so pki.cmp.verify routes incoming CMP signature protection through the SAME engine (never a second, weaker
// CMP verifier; never build's self-check, which skips the EdDSA low-order-point gate) and chains an
// out-of-path signer certificate through the FULL RFC 5280 sec. 6.1 path validation -- without exposing any
// of it on the public pki.path surface (index.js exports the whole path-validate module).
cmpVerify.setEngine({ verifyWithSpki: _verifyWithSpki, build: build, validate: validate });
// pki.cmp.session validates the ISSUED leaf certificate (its signature + chain) through the same engine.
// `verifyWithSpki` so a root CA key update's rollover signatures are checked by the same signature
// engine (with its EdDSA low-order-point and algorithm-confusion gates) that verifies a message's
// protection, rather than a second, weaker check inside the session.
cmpSession.setEngine({ build: build, validate: validate, toAnchor: toAnchor, coerceCert: coerceCert, verifyWithSpki: _verifyWithSpki });
// pki.cms.verify chains a SignedData's signer certificate to the anchors the CALLER named, so its
// `trusted` is decided by this one path engine rather than a second, weaker walk of its own.
// `toAnchor` so cms.verify can validate the caller's anchors ONCE at entry, before any signer is
// walked -- otherwise a message whose signers all failed would never reach a build call and a
// malformed anchor would pass unnoticed.
// `resolvePurposeOpts` so cms.verify can reject a malformed requiredEku / checkPurpose at ITS entry
// point, through the SAME definition the walk uses -- a message whose signers all failed never
// reaches a build call, and a caller's configuration must not be judged by the message's quality.
cmsVerify.setEngine({ build: build, validate: validate, toAnchor: toAnchor,
  resolvePurposeOpts: resolvePurposeOpts, assertAnchorConstraints: assertAnchorConstraints });

/**
 * @primitive  pki.path.ocspChecker
 * @signature  pki.path.ocspChecker(responses) -> RevocationChecker
 * @since      0.1.32
 * @status     stable
 * @spec       RFC 6960
 * @related    pki.path.validate, pki.schema.ocsp.parseResponse, pki.path.crlChecker
 *
 * Build an OCSP-backed `RevocationChecker` for `pki.path.validate`'s
 * `revocationChecker` option from a set of pre-fetched OCSP responses (DER/PEM
 * or already-parsed). For each certificate it locates a SingleResponse whose
 * CertID binds this cert's serial to its issuer (recomputing `issuerNameHash`
 * and `issuerKeyHash` under the CertID's own hashAlgorithm, SHA-1 or SHA-2, so
 * a response using either matches), confirms the responder is authorized (the
 * issuing CA directly, or a valid CA-issued delegate bearing both id-kp-OCSPSigning
 * and id-pkix-ocsp-nocheck), verifies the response signature over
 * `tbsResponseDataBytes`, checks currency
 * (`thisUpdate`/`nextUpdate`), and reports `{ status: "good"|"revoked"|
 * "unknown" }`. A wrong-issuer CertID, an unauthorized responder, a stale,
 * not-yet-valid, nextUpdate-less, non-successful, or unverifiable response
 * yields `unknown`, which the validator fails closed unless `softFail` is set;
 * a `revoked` status surfaces its `revocationReason`. It is transport-free: the
 * caller supplies bytes it collected (an OCSP fetch or a stapled response), so
 * nonce anti-replay is the live client's responsibility and the residual replay
 * defense is the `thisUpdate`/`nextUpdate` currency window.
 *
 * @example
 *   var checker = pki.path.ocspChecker([]);   // no responses -> every cert is "unknown"
 *   typeof checker.check;                       // "function"
 */
function ocspChecker(responses) {
  // The same door verifyOcspResponse uses. This checker's responses reach the identical three-part
  // signature check, so accepting a parsed object here on a truthy responseStatus would leave the
  // door shut on one of the two ways into that check and open on the other.
  var parsed = (responses || []).map(function (r) { return _ocspFromBytes(r); });
  return {
    check: async function (cert, issuer, ctx) {
      var time = ctx.time;
      var historical = ctx.historicalMode === true;
      // Issuer DN candidates to match the CertID against (RFC 6960 sec. 4.1.1 names
      // the checked cert's issuer field; a response MAY instead carry the issuer
      // certificate's own subject encoding -- sec. 7.1-equal but not byte-identical).
      var issuerNameCandidates = [cert.issuer.bytes];
      function addNameCandidate(nm) {
        if (nm && nm.bytes && !guard.list.anyMatches(issuerNameCandidates, function (e) { return e.equals(nm.bytes); })) issuerNameCandidates.push(nm.bytes);
      }
      if (issuer.issuerCert) addNameCandidate(issuer.issuerCert.subject);
      addNameCandidate(issuer.workingIssuerName);
      var issuerKeyBits;
      try { issuerKeyBits = ocspVerify.ocspKeyValue(issuer.workingPublicKey); }
      catch (_e) { return { status: "unknown", reason: "the issuer public key could not be read to recompute the OCSP CertID" }; }

      // A serial is revoked if ANY authoritative, verified, current response says
      // so -- a clean response must never shadow a revoking one (the crlChecker
      // fail-closed law). "good" needs at least one authoritative match; every
      // other outcome is undetermined. The shared verify core evaluates each
      // response (responder authorization + signature + CertID + currency +
      // status) and returns a per-response summary this aggregates.
      var revokedResult = null;
      var sawGood = false;
      var sawUnknownStatus = false;

      for (var k = 0; k < parsed.length; k++) {
        var v = await ocspCore.evaluateResponse(parsed[k], cert, issuer, issuerKeyBits, issuerNameCandidates, time, historical);
        if (v.revoked && !revokedResult) {
          revokedResult = { status: "revoked", revocationReason: v.revoked.revocationReason, reason: v.revoked.reason };
        }
        if (v.sawGood) sawGood = true;
        if (v.sawUnknownStatus) sawUnknownStatus = true;
      }
      if (revokedResult) return revokedResult;
      if (sawGood) return { status: "good" };
      return {
        status: "unknown",
        reason: sawUnknownStatus
          ? "the OCSP responder reported certStatus unknown for this certificate"
          : "no authoritative, current, in-scope OCSP response covers this certificate",
      };
    },
  };
}

/**
 * @primitive  pki.path.verifyOcspResponse
 * @signature  pki.path.verifyOcspResponse(response, cert, issuerCert, time, opts?) -> Promise<{ status, responderAuthorized, signatureValid, matched, thisUpdate, nextUpdate, revocationReason?, reason }>
 * @since       0.2.22
 * @status      stable
 * @spec        RFC 6960
 * @related     pki.ocsp.verify, pki.path.ocspChecker
 *
 * Verify a single OCSP response for one certificate
 * against its already-parsed issuer certificate at `time`. This is the lower-level
 * primitive `pki.ocsp.verify` composes after parsing its inputs (most callers want
 * that ergonomic entry, which also handles DER/PEM decoding and request-nonce
 * matching). It runs exactly the gates the path validator's `ocspChecker`
 * does: it locates the SingleResponse whose CertID binds this cert's serial to
 * its issuer (recomputing `issuerNameHash`/`issuerKeyHash` under the CertID's
 * own hashAlgorithm), confirms the responder is authorized (the issuing CA
 * directly, or a CA-issued delegate bearing both id-kp-OCSPSigning and
 * id-pkix-ocsp-nocheck and passing the full out-of-path certificate gates),
 * verifies the response signature over `tbsResponseDataBytes`, and checks
 * currency (`thisUpdate`/`nextUpdate`) -- there is no weaker second OCSP verify
 * path. It is fail-closed and never throws on an unauthorized, stale, or
 * unverifiable response: those yield `{ status: "unknown" }` with the granular
 * `responderAuthorized`/`signatureValid`/`matched` flags and a `reason`; a
 * `revoked` status surfaces its `revocationReason`. Setting `opts.historicalMode`
 * treats a revocation whose `revocationTime` is strictly after `time` as not-yet-
 * revoked (`good`) -- for validating a signature as of a past `time`, before the
 * certificate was later revoked; the responder certificate is still validated at
 * `time` either way. `time` must be a valid `Date`. A malformed response's parse
 * fault surfaces as the parser's typed `ocsp/*` / `asn1/*` error.
 *
 * The response is its DER bytes, a PEM string, or an unmodified
 * `pki.schema.ocsp.parseResponse` result. A REBUILT parsed response is refused. A
 * signature check has three parts -- the signature, the algorithm that verifies it,
 * and the bytes it covers -- and on a parsed object all three are separate properties:
 * a genuine CA signature over a certificate that CA issued, relabeled, verifies as a
 * ResponseData signature for a response that never existed. The parser marks what it
 * returns, so those three are known to have been derived together from one byte
 * string; `Object.assign`, spread and a JSON round-trip all drop the mark, which is
 * exactly how such an object is assembled.
 *
 * @example
 *   var ca = await pki.key.generate("Ed25519");
 *   var caKey = await pki.key.export(ca.privateKey);
 *   var caDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } },
 *     { key: caKey });
 *   var leaf = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(leaf.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { cert: caDer, key: caKey });
 *   var der = await pki.ocsp.sign(
 *     { responderID: "byName", responses: [{ cert: leafDer, issuer: caDer, status: "good" }] },
 *     { cert: caDer, key: caKey });
 *   var cert = pki.schema.x509.parse(leafDer), issuerCert = pki.schema.x509.parse(caDer);
 *   var v = await pki.path.verifyOcspResponse(der, cert, issuerCert, new Date());
 *   v.status;   // "good" | "revoked" | "unknown"
 */
function verifyOcspResponse(response, cert, issuerCert, time, opts) {
  var parsedResponse, subject, issuer;
  try {
    parsedResponse = _ocspFromBytes(response);
    // The two certificates go through the same door as the response, for the same reason: this
    // verdict is about a certificate's IDENTITY -- its serial and its issuer's name and key are
    // what the CertID is matched against, and the issuer's key is what authorizes a delegated
    // responder. A caller-assembled certificate could name one identity while carrying another's
    // signed bytes, so both are re-derived from the bytes their parser read.
    subject = coerceCert(cert, "the certificate");
    issuer = coerceCert(issuerCert, "the issuer certificate");
  } catch (e) { return Promise.reject(e); }
  return _verifyOcspParsed(parsedResponse, subject, issuer, time, opts);
}

// The response, always parsed from the bytes the caller handed over.
//
// A signature check has three parts -- the signature, the algorithm that verifies it, and the byte
// range it covers -- and on a claimed-parsed response all three are separate properties of one
// caller-supplied object. Pair a real CA's signature over a certificate IT issued with that
// certificate's own tbsBytes and algorithm, label them `signature` / `tbsResponseDataBytes` /
// `signatureAlgorithm`, and the check verifies: a genuine signature, over the bytes it was made
// over, under the right key -- for a structure the responder never produced. Parsing binds the three
// to one byte string, which is the only thing that makes the verdict about a response at all.
var _OCSP_CLAIM = ["responseStatus", "basicResponse", "tbsResponseDataBytes"];
function _ocspFromBytes(response) {
  return guard.parsed.fromTrustedSource(response, "ocspResponse", _OCSP_CLAIM, function (bytes) {
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array) && typeof bytes !== "string") {
      throw E("path/bad-input", "verifyOcspResponse: the response must be an OCSP response DER Buffer, a PEM string, or a pki.schema.ocsp.parseResponse result");
    }
    return ocsp.parseResponse(bytes);
  }, E, "path/bad-input",
  "verifyOcspResponse: the response must be its DER bytes, a PEM string, or an unmodified pki.schema.ocsp.parseResponse result: the signature, the algorithm that verifies it and the bytes it covers are separate properties of a parsed object, so a REBUILT response (Object.assign, spread, a JSON round-trip) could have the three describe different responses and is refused");
}

// The verification over a response this module has ALREADY derived from bytes -- reached only
// through the door above and through ocspChecker, which parses the responder's own reply. Not
// exported: this module's export object IS pki.path, so anything on it is public surface and frozen
// by the API snapshot, whatever a comment beside it claims.
function _verifyOcspParsed(parsedResponse, cert, issuerCert, time, opts) {
  opts = opts || {};
  // The currency + responder-cert validity windows compare against `time`; a missing or invalid
  // check date must fail closed (a NaN compares false against every bound), never silently pass.
  if (!guard.time.isDate(time) || isNaN(guard.time.instantOf(time))) {
    return Promise.reject(E("path/bad-input", "verifyOcspResponse: time must be a valid Date (the currency + responder-validity check date)"));
  }
  // Bind the supplied issuer certificate to the target: the target's issuer DN must equal the
  // issuer cert's subject DN AND the target's signature must verify under the issuer's key. A
  // direct-CA responder is authorized by exactly this issuer identity and the CertID is recomputed
  // under the issuer's key, so without the cryptographic binding a rogue certificate sharing the
  // issuer's subject DN (but a different key) could recompute a matching CertID and sign a "good"
  // response for a certificate that CA never issued. ocspChecker gets an issuer already chained by
  // the path validator; the standalone entry must establish the binding itself. Fail closed.
  function unbound(reason) { return { status: "unknown", responderAuthorized: false, signatureValid: false, matched: false, reason: reason }; }
  var boundName;
  try { boundName = dnEqual(cert.issuer.rdns, issuerCert.subject.rdns); }
  catch (e) { return Promise.reject(e); }   // an embedded control byte in a DN -> path/name-chaining
  if (!boundName) {
    return Promise.resolve(unbound("the supplied issuer certificate's subject does not match the target certificate's issuer"));
  }
  return builtinVerify({ workingPublicKey: issuerCert.subjectPublicKeyInfo.bytes }, cert).then(function (sig) {
    if (!sig.ok) return unbound("the target certificate's signature does not verify under the supplied issuer certificate's key");
    var issuerCtx = { workingPublicKey: issuerCert.subjectPublicKeyInfo.bytes, workingIssuerName: issuerCert.subject, issuerCert: issuerCert };
    var issuerNameCandidates = [cert.issuer.bytes];
    function add(nm) { if (nm && nm.bytes && !guard.list.anyMatches(issuerNameCandidates, function (e) { return e.equals(nm.bytes); })) issuerNameCandidates.push(nm.bytes); }
    add(issuerCert.subject);
    var issuerKeyBits;
    try { issuerKeyBits = ocspVerify.ocspKeyValue(issuerCert.subjectPublicKeyInfo.bytes); }
    catch (_e) { return unbound("the issuer public key could not be read to recompute the OCSP CertID"); }
    return ocspCore.evaluateResponse(parsedResponse, cert, issuerCtx, issuerKeyBits, issuerNameCandidates, time, opts.historicalMode === true).then(function (v) {
      if (v.revoked) return { status: "revoked", responderAuthorized: true, signatureValid: true, matched: true, thisUpdate: v.thisUpdate, nextUpdate: v.nextUpdate, revocationReason: v.revoked.revocationReason, reason: v.revoked.reason };
      if (v.sawGood) return { status: "good", responderAuthorized: true, signatureValid: true, matched: true, thisUpdate: v.thisUpdate, nextUpdate: v.nextUpdate, reason: "good" };
      return { status: "unknown", responderAuthorized: v.responderAuthorized === true, signatureValid: v.signatureValid === true, matched: v.matched === true, thisUpdate: v.thisUpdate, nextUpdate: v.nextUpdate, reason: v.reason };
    });
  });
}

// ---- certification path BUILDING (pki.path.build, RFC 4158) ----------------

// A soft extension decode for the RFC 4158 sec. 3.5 SORT hints (AKI/SKI/
// basicConstraints/keyUsage): a present-but-undecodable extension on an
// UNTRUSTED pool candidate degrades to "no hint", never a hard fail -- the sort
// weight is advisory, the branch is still tried, and validate is the authority.
function softDecode(cert, extOid) {
  try { return decodeExt(cert, extOid); }
  catch (_e) { return null; }
}

// dnEqual that fails a control-byte DN (CVE-2009-2408) closed to "not a match"
// rather than rejecting the whole build -- one malformed pool cert must not
// poison a buildable path (parity with selfIssued's swallow). The hard
// name-chaining gate remains validate's own dnEqual over the chosen path.
function nameMatchSoft(rdnsA, rdnsB) {
  try { return dnEqual(rdnsA, rdnsB); }
  catch (_e) { return false; }
}

// A certificate reaching a VERDICT is re-derived from the bytes the parser read, never trusted as
// the object it arrives as. Completeness -- every field present with the right type -- is not enough
// here, because a certificate's meaning is one signature over one byte range while a parsed
// certificate presents that range, the signature, and the fields the range encodes as separate
// properties. Keep a real CA certificate's `tbsBytes` and signature and substitute only its
// `subjectPublicKeyInfo`, and every completeness rule passes, this walk verifies the ORIGINAL signed
// range, and then uses the substituted key to check the next certificate -- a forged chain built out
// of a genuine certificate. Emptying `extensions` is the same move against basicConstraints,
// keyUsage, the name constraints and the unknown-critical rule.
//
// So the door takes the parser's record instead: a certificate from pki.schema.x509.parse re-parses
// from the bytes it was read from, and anything done to that object since is discarded. One a caller
// assembled has no record and is refused rather than silently believed.
function coerceCert(input, label) {
  return guard.parsed.acceptDerived(input, "certificate", x509.parse, E, "path/bad-input",
    label || "a certificate");
}

// A trust-store entry is either a ready anchor tuple { name, publicKey,
// algorithm, parameters? } or a self-signed root certificate reduced to that
// tuple. The algorithm is the SPKI KEY-algorithm OID (the sec. 6.1.4(f)
// parameter-inheritance value), mirroring trust.js _mkAnchor -- NOT the
// signature OID. The anchor is an input to validate, never one of the path certs.
// The two key-purpose options, resolved and typo-checked. Extracted so a CALLER can validate them
// at ITS entry point rather than only when a path is actually walked: a format verb that skips the
// walk -- pki.cms.verify does when no signer verified -- would otherwise accept a malformed
// purpose in silence, making configuration validity depend on the message. One definition, so the
// answer cannot drift between the caller's early check and the walk's own.
//
// `requiredEku` gates the TARGET certificate's own EKU extension; `checkPurpose` selects which
// per-purpose key the ANCHOR's NSS trust metadata (purposes / distrustAfter) is consulted under.
// They are independent, and each is a registered OID name or a canonical dotted OID.
// An anchor's CONSTRAINT metadata for one purpose, validated fail-closed and returned normalized.
// A PRESENT-but-malformed distrustAfter (an Invalid Date: instanceof Date yet a NaN time) would
// make `notBefore > it` NaN-false and SILENTLY drop the distrust restriction -- the NaN-Date
// fail-open. Absent metadata is no restriction and returns null.
//
// Separate from resolvePurposeOpts because it validates the ANCHOR rather than the options, and
// exposed for the same reason: a caller that may never reach the walk -- pki.cms.verify when no
// signer verified -- has to be able to reject a malformed anchor at ITS entry point, through this
// same definition, so configuration validity never depends on the message.
// Does this anchor carry trust metadata that only a named key purpose can unlock? A non-empty
// `distrustAfter` or `purposes` map is such metadata -- both are indexed BY purpose, so both are
// inert without one. An EMPTY map states no constraint and is not a reason to refuse.
function _hasPurposeScopedMetadata(ta) {
  if (!ta || typeof ta !== "object") return false;
  return guard.list.anyMatches(["distrustAfter", "purposes"], function (k) {
    var m = ta[k];
    // Own names, not Object.keys: a non-enumerable own entry is still a restriction and must count, so it cannot
    // evade this "the anchor carries purpose-scoped metadata -> require checkPurpose" gate. An inherited map
    // (Object.create(base) or a polluted Object.prototype) is already refused by toAnchor before an anchor
    // reaches here, so this read does not resolve an inherited value.
    return !!m && typeof m === "object" && intrinsic.getOwnPropertyNames(m).length > 0;
  });
}

function assertAnchorConstraints(ta, checkPurpose) {
  if (!checkPurpose || !ta) return null;
  // Read distrustAfter ONCE into a local: reading the anchor field for the presence gate and again for the
  // value would let an accessor-backed field answer the two reads differently and slip the distrust control.
  // The normalized anchor already materializes this to plain data; reading once holds the guarantee for any
  // caller and keeps this from being a live-getter multi-read even if a future path skips normalization. An
  // inherited distrustAfter (Object.create(base), or a polluted Object.prototype) is already refused by toAnchor
  // -- _captureConstraintMap / the certificate branch reject a `"distrustAfter" in entry` that is not own -- so
  // this read never resolves an inherited value on an anchor that reached here.
  var da = ta.distrustAfter;
  var d = (da && intrinsic.hasOwn(da, checkPurpose)) ? da[checkPurpose] : null;
  if (d == null) return null;
  return guard.time.assertValid(d, E, "path/bad-input", "trustAnchor.distrustAfter." + checkPurpose);
}

function resolvePurposeOpts(opts) {
  var requiredEku = null;
  if (opts.requiredEku !== undefined) {
    if (!intrinsic.isArray(opts.requiredEku) || opts.requiredEku.length === 0) {
      throw E("path/bad-input", "validate: opts.requiredEku must be a non-empty array of key-purpose OID names or dotted OID strings");
    }
    requiredEku = opts.requiredEku.map(function (p) {
      if (typeof p !== "string" || p.length === 0) throw E("path/bad-input", "validate: opts.requiredEku entries must be non-empty strings");
      // A dotted-form attempt (leads with a digit) must be a canonical OID -- a
      // loose regex accepted a leading-zero / out-of-bounds key that would never
      // match the canonical EKU the target advertises; anything else is a name.
      if (/^[0-9]/.test(p)) return guard.identifier.assertCanonicalOid(p, E, "path/bad-input", "validate: opts.requiredEku entry " + JSON.stringify(p));
      var dotted = oid.byName(p);
      if (typeof dotted !== "string") throw E("path/bad-input", "validate: opts.requiredEku entry " + JSON.stringify(p) + " is not a registered OID name");
      return dotted;
    });
  }
  var checkPurpose = null;
  if (opts.checkPurpose !== undefined) {
    if (typeof opts.checkPurpose !== "string" || opts.checkPurpose.length === 0) {
      throw E("path/bad-input", "validate: opts.checkPurpose must be a key-purpose OID name or dotted OID string");
    }
    if (/^[0-9]/.test(opts.checkPurpose)) {
      var cpDotted = guard.identifier.assertCanonicalOid(opts.checkPurpose, E, "path/bad-input", "validate: opts.checkPurpose");
      checkPurpose = oid.name(cpDotted) || cpDotted;   // normalize a dotted purpose OID to its name for the anchor map
    } else {
      if (typeof oid.byName(opts.checkPurpose) !== "string") throw E("path/bad-input", "validate: opts.checkPurpose " + JSON.stringify(opts.checkPurpose) + " is not a registered OID name");
      checkPurpose = opts.checkPurpose;
    }
  }
  return { requiredEku: requiredEku, checkPurpose: checkPurpose };
}

// Snapshot a trust-anchor purposes / distrustAfter map (purpose name -> boolean or Date) to a fresh plain
// object, reading each own entry from its DATA DESCRIPTOR -- never by property access. Reading by value would
// invoke an accessor entry (a `get serverAuth()`), which is caller code that could mutate the sibling map
// before it is captured, so an accessor entry is REFUSED instead. A later getter cannot mutate the fresh copy.
// A distrustAfter entry is a Date: copy it BY VALUE (guard.time.instantOf via the intrinsic) so a later
// setTime() cannot move the cutoff. Entry enumerability is preserved so the purpose gates see the same shape.
function _snapshotConstraintMap(m, E, code, who) {
  var out = {};
  // getOwnPropertyNames below reads only OWN keys, so a restriction reached through the prototype --
  // Object.create({ serverAuth: pastDate }) -- would be silently dropped and its cutoff lost. Require the map to
  // be a plain object of THIS realm: its prototype is Object.prototype (the common case) or null. Anything else
  // -- a custom prototype, a null-prototype object carrying entries, a Proxy prototype, or a map from another
  // realm -- is refused, so a prototype-reached restriction is never silently dropped. Only IDENTITY is sound
  // here: a hostile object can mimic every STRUCTURAL signal of a genuine Object.prototype (a non-enumerable
  // data entry is indistinguishable from a built-in), so a structural "looks plain" test always leaves a bypass.
  // A cross-realm map is therefore refused fail-closed -- the operator passes a same-realm plain object (what
  // pki.trust.parseCertdata emits, or a literal in their own code), which is the norm for this security-critical
  // input. A name planted on Object.prototype ITSELF is still tolerated (proto === ObjectProto): the map is plain
  // and consumption reads OWN entries only (the hasOwn gates), so global pollution is ignored, not read. m is
  // non-Proxy (refused at capture) and this is a reference comparison, so no getPrototypeOf / ownKeys trap runs
  // even when the prototype is a Proxy.
  var proto = intrinsic.getPrototypeOf(m);
  if (proto !== null && proto !== intrinsic.ObjectProto) throw E(code, who + ": a trustAnchor constraint map must be a plain object (its own entries only), not one with a custom or cross-realm prototype");
  var keys = intrinsic.getOwnPropertyNames(m);
  // A constraint map is plain STRING-keyed data. A symbol-keyed entry (getOwnPropertyNames omits symbols) or an
  // own __proto__ data property (skipped below so it can't pollute the fresh map) would be DROPPED from the
  // snapshot -- and, keyed by neither a checkPurpose OID name, never applied. Refuse the map rather than silently
  // drop a caller entry, so the snapshot faithfully carries every restriction or the anchor is refused. ownKeys
  // (Reflect.ownKeys) counts strings + symbols; more than the string-only names means a symbol key is present.
  if (intrinsic.ownKeys(m).length !== keys.length) throw E(code, who + ": a trustAnchor constraint map must not have symbol-keyed entries");
  for (var i = 0; i < keys.length; i++) {
    if (keys[i] === "__proto__") throw E(code, who + ": a trustAnchor constraint map must not have an own __proto__ entry");
    var d = intrinsic.getOwnPropertyDescriptor(m, keys[i]);
    if (!d || !intrinsic.hasOwn(d, "value")) throw E(code, who + ": a trustAnchor constraint-map entry must be a data property, not an accessor");
    var v = d.value;
    if (intrinsic.types.isDate(v)) v = new intrinsic.Date(guard.time.instantOf(v));
    // Materialize every entry ENUMERABLE. A constraint map is plain data (purpose -> boolean / Date); a caller
    // entry defined non-enumerable would otherwise be copied non-enumerable and then be invisible to the
    // Object.keys-based purpose-scoped-metadata gate, letting a restriction slip the "supply checkPurpose" check.
    intrinsic.defineProperty(out, keys[i], { value: v, enumerable: true, configurable: true, writable: true });
  }
  return out;
}

// Normalize a captured constraint MAP field for storage. An absent map (null / undefined) carries no
// restriction and passes through. A present map MUST be a plain object and is snapshotted; a present non-object
// -- a primitive, a Buffer, or (refused inside the snapshot by the plain-prototype check) an array -- cannot hold
// a purpose -> boolean/Date restriction, so it is refused rather than passed through as an unusable value that
// would silently apply no restriction.
function _normalizeConstraintField(v, E, code, who) {
  if (v === null || v === undefined) return v;
  if (typeof v !== "object" || intrinsic.isBuffer(v)) throw E(code, who + ": a trustAnchor constraint map must be a plain object");
  return _snapshotConstraintMap(v, E, code, who);
}

// Capture a trust-anchor constraint MAP field (purposes / distrustAfter) WITHOUT invoking a getter: read its
// OWN DATA descriptor. An accessor-backed map (a `get purposes()`) is caller code that could mutate the sibling
// map when read, so it is refused; an INHERITED map is refused too (own-only capture), never silently dropped,
// so a restriction is never lost. A truly absent field is no restriction (undefined).
function _captureConstraintMap(entry, key, E, code, who) {
  var d = intrinsic.getOwnPropertyDescriptor(entry, key);
  if (d === undefined) {
    if (key in entry) throw E(code, who + ": a trustAnchor " + key + " must be an own data property, not inherited");
    return undefined;
  }
  if (!intrinsic.hasOwn(d, "value")) throw E(code, who + ": a trustAnchor " + key + " must be a data property, not an accessor");
  // A constraint map that is a Proxy is refused, the same way the top-level anchor is: its ownKeys / descriptor
  // traps could answer inconsistently -- an empty key list drops a restriction the caller attached, and an
  // isBuffer-answering trap could skip the snapshot entirely -- so the map cannot be trusted to describe itself.
  if (intrinsic.types.isProxy(d.value)) throw E(code, who + ": a trustAnchor " + key + " map must not be a Proxy");
  return d.value;
}

// Read a field's OWN DATA value from its descriptor, WITHOUT invoking a getter -- an accessor or an inherited
// field yields undefined. Used for the optional identity metadata (subjectDer / label / mozillaCaPolicy): a
// getter there, invoked before the key is pinned, could overwrite the key Buffer or mutate the name, so it is
// never invoked. This metadata does not enter a validation decision, so an accessor / inherited form is simply
// not carried (unlike a constraint map, which is refused).
function _captureOwnData(entry, key) {
  var d = intrinsic.getOwnPropertyDescriptor(entry, key);
  return (d && intrinsic.hasOwn(d, "value")) ? d.value : undefined;
}

// A fresh copy of a distinguished-name attribute record { type, value, name }, so the normalized anchor does
// not share it with the caller. The consumed fields -- type + value drive the RFC 5280 sec. 7.1 dnEqual
// comparison, name is the optional registry label -- are read by PROPERTY ACCESS, which follows the prototype
// chain and reads an accessor once. The anchor API deliberately accepts an inherited / accessor name.rdns
// (Object.create(base), a prototype getter), so an inherited attribute value must be SNAPSHOT here, not
// dropped; a field the caller did not supply is omitted.
function _copyAtv(atv) {
  var out = {};
  var t = atv.type;
  if (t !== undefined) intrinsic.defineProperty(out, "type", { value: t, enumerable: true, configurable: true, writable: true });
  var v = atv.value;
  if (v !== undefined) intrinsic.defineProperty(out, "value", { value: v, enumerable: true, configurable: true, writable: true });
  var nm = atv.name;
  if (nm !== undefined) intrinsic.defineProperty(out, "name", { value: nm, enumerable: true, configurable: true, writable: true });
  return out;
}

// DEEP-copy a caller's rdns so the normalized anchor's DN is independent of the caller's object. A single
// arraySlice copies only the outer RDN sequence, leaving each nested RDN array and attribute record shared, so
// a caller mutating name.rdns[i][j].value after normalization (or while an async validate awaits signature
// verification) would change the issuer identity name chaining re-reads. Copy the outer array, each RDN array,
// and each attribute record (its type/value are strings, so an own-data copy is enough) -- matching the
// trust-store name copy (lib/trust.js _copyName).
function _copyRdnsDeep(rdns) {
  if (!intrinsic.isArray(rdns)) return rdns;
  // Copy only OWN indexed elements and PRESERVE holes -- never read an inherited Array.prototype[i] slot. A
  // slice reads inherited indices (HasProperty walks the chain), so on a SPARSE rdns a polluted Array.prototype
  // slot would be materialized as an own element, filling a hole that guard.name.dnEqual explicitly rejects and
  // letting a malformed name pass chaining. Keeping the array sparse leaves the hole for the downstream guard.
  // Read own indices only (hasOwn) and CREATE each copied index with defineProperty, never a plain assignment:
  // both the read side (a slice walks the chain) and the write side (`out[i] = v` respects an inherited
  // non-writable data property or accessor -- it can throw, fail silently, or invoke an inherited setter) touch
  // the prototype, so a polluted Array.prototype could fill a hole or corrupt a dense rdns into a sparse one.
  // defineProperty is CreateDataProperty: it always makes an own data property regardless of the prototype.
  var out = [];
  out.length = rdns.length;
  for (var i = 0; i < rdns.length; i++) {
    if (!intrinsic.hasOwn(rdns, i)) continue;   // leave a hole where the source has one
    var rdn = rdns[i], val;
    if (intrinsic.isArray(rdn)) {
      var rdnOut = [];
      rdnOut.length = rdn.length;
      for (var j = 0; j < rdn.length; j++) {
        if (!intrinsic.hasOwn(rdn, j)) continue;   // preserve inner holes for the same reason
        var atv = (rdn[j] !== null && typeof rdn[j] === "object") ? _copyAtv(rdn[j]) : rdn[j];
        intrinsic.defineProperty(rdnOut, j, { value: atv, enumerable: true, configurable: true, writable: true });
      }
      val = rdnOut;
    } else { val = rdn; }
    intrinsic.defineProperty(out, i, { value: val, enumerable: true, configurable: true, writable: true });
  }
  return out;
}

function toAnchor(entry, verb) {
  var who = verb || "build";
  // Decide tuple-vs-certificate by the discriminator fields, read under try/catch: a throwing name /
  // publicKey / algorithm accessor is a malformed anchor and must surface as the documented path/bad-input
  // entry refusal, not a raw exception leaked past the typed guards. `alg` and the raw publicKey are PINNED
  // to ONE read here and used throughout, so a stateful accessor that returns a value now and throws (or
  // returns a different value) on a later read cannot slip past this guard at the shape check or the snapshot.
  var isTuple = false, alg = null, pubRaw = null, nameRaw = null, pk = null, purposesSnap, distrustSnap;
  var subjectDerRaw, labelRaw, mozRaw;
  // A Proxy anchor is refused outright. Every field read below -- whether by property access or from an own
  // data descriptor -- is answered by the anchor's own reflection, and a Proxy's traps let the same read
  // return different values on different lookups or report a field absent while forwarding its siblings, so a
  // Proxy could hide a purposes / distrustAfter restriction the operator attached and validate against a
  // weaker anchor than the one supplied. A legitimate anchor is a plain tuple, a parsed certificate, or an
  // Object.create(base) inheriting from one -- none is a Proxy -- so refusing it here costs no real use and
  // removes the whole class of trap-driven anchor forgery. isProxy is an internal-slot check that runs no
  // caller code, so it sits outside the accessor try below and its message is not re-wrapped as an accessor throw.
  if (intrinsic.types.isProxy(entry)) {
    throw E("path/bad-input", who + ": a trustAnchor must not be a Proxy");
  }
  // A Proxy anywhere in the anchor's prototype CHAIN is refused too. entry may legitimately inherit its fields
  // (an Object.create(base) anchor is supported), and those inherited reads -- the `in` tests and the property
  // accesses below -- walk the chain, so a Proxy prototype would run its has / get traps: the has trap could
  // report purposes / distrustAfter absent while the get trap still supplies inherited name / publicKey /
  // algorithm, dropping the restriction and validating a weaker anchor. Walk the chain refusing any Proxy,
  // checking isProxy BEFORE reading its prototype so a Proxy never runs a getPrototypeOf trap here. A legitimate
  // anchor -- a tuple, a certificate, or an Object.create(base) over a plain object -- has a Proxy-free chain.
  if (entry !== null && typeof entry === "object") {
    var proto = intrinsic.getPrototypeOf(entry);
    while (proto !== null) {
      if (intrinsic.types.isProxy(proto)) throw E("path/bad-input", who + ": a trustAnchor must not inherit from a Proxy");
      proto = intrinsic.getPrototypeOf(proto);
    }
  }
  try {
    // Recognize a parsed CERTIFICATE first and route it to coerceCert below -- by PROVENANCE, not by reading
    // its fields. guard.parsed.isRecorded is a getter-free WeakMap lookup: a certificate from
    // pki.schema.x509.parse carries a provenance record, a hand-built tuple does not. A certificate does not
    // carry name / publicKey / algorithm as own properties, but the tuple discriminator reads those by
    // property access, which FOLLOWS the prototype chain -- so a polluted Object.prototype supplying those
    // three would otherwise misclassify a real certificate as a tuple and bind the INHERITED (attacker) key
    // instead of the certificate's own. Recognizing the certificate by its forge-proof provenance mark routes
    // it to coerceCert and never binds an inherited key. Crucially the check is a WeakMap lookup that invokes
    // NO caller getter -- so, unlike a structural probe that would read tbsBytes / subject / ... , it cannot run
    // a tuple-controlled accessor (e.g. a polluted Object.prototype.tbsBytes getter) before publicKey is pinned
    // below, which would otherwise defeat the key-pinning guarantee.
    if (entry && typeof entry === "object" && !Buffer.isBuffer(entry) && !guard.parsed.isRecorded(entry)) {
      // Not a recorded certificate (isRecorded is a getter-free WeakMap lookup), so treat entry as a tuple
      // candidate. entry is not a Proxy (refused at the door above), so its own reflection is truthful: a
      // getOwnPropertyDescriptor read reports its real own data, and an absent field is really absent rather
      // than a trap hiding a forwarded one. The discriminator fields (publicKey / name / algorithm) are read
      // by PROPERTY ACCESS (follows the prototype chain, so an Object.create(base) inherited anchor is
      // recognized), each exactly once, so a stateful own accessor answers each at most once. The prototype
      // chain is never WALKED (Buffer.isBuffer / isRecorded above invoke getPrototypeOf a bounded number of
      // times only), so a hostile getPrototypeOf cannot be driven into a loop.
      //
      // Snapshot the constraint maps FIRST -- before ANY discriminator field (publicKey / name / algorithm) is
      // read -- so no discriminator getter can flip a denied purpose to allowed or move a distrust cutoff
      // between the map's capture and validation. A getter for publicKey or name runs when that field is read;
      // capturing purposes / distrustAfter beforehand puts them out of its reach (the same protection the
      // ordering already gave against the later algorithm getter, now extended to the earlier ones). The
      // identity passthrough (subjectDer, label, mozillaCaPolicy -- the closed producer-derived set) is read
      // once each here too. entry is not a recorded certificate, so these reads do not touch a cert's accessors.
      var pRaw = _captureConstraintMap(entry, "purposes", E, "path/bad-input", who);
      purposesSnap = _normalizeConstraintField(pRaw, E, "path/bad-input", who);
      var dRaw = _captureConstraintMap(entry, "distrustAfter", E, "path/bad-input", who);
      distrustSnap = _normalizeConstraintField(dRaw, E, "path/bad-input", who);
      // The identity passthrough (subjectDer, label, mozillaCaPolicy) is captured from its OWN DATA descriptor
      // too, never by property access: an accessor identity field, read before the key is pinned below, could
      // overwrite the key Buffer or mutate the name, so its getter is never invoked. An accessor / inherited
      // identity field is not carried (it is non-validation metadata), not refused.
      subjectDerRaw = _captureOwnData(entry, "subjectDer");
      labelRaw = _captureOwnData(entry, "label");
      mozRaw = _captureOwnData(entry, "mozillaCaPolicy");
      // Every mutable, validation-relevant field above (the constraint maps and the identity metadata) was
      // captured from a descriptor WITHOUT invoking a getter, so the publicKey read below -- and the name /
      // algorithm reads after it -- cannot have mutated them. publicKey is read (property access, so an
      // inherited publicKey is supported) and pinned to a private Buffer IMMEDIATELY, before the name /
      // algorithm accessors run, so a later getter cannot overwrite the key Buffer after it is read but before
      // it is captured. A non-tuple leaves pk null / isTuple false and falls through to coerceCert below.
      pubRaw = entry.publicKey;
      if (guard.bytes.isByteSource(pubRaw)) {
        pk = guard.bytes.snapshot(pubRaw, PathError, "path/bad-input", who + ": trustAnchor publicKey");
      }
      nameRaw = entry.name;
      alg = entry.algorithm;
      isTuple = !!(nameRaw && pubRaw && alg);
    }
  } catch (e) {
    throw E("path/bad-input", who + ": a trustAnchor accessor threw", e);
  }
  if (isTuple) {
    // publicKey was read FIRST and pinned to `pk` in the discriminator above, before the algorithm and name
    // accessors ran, so no caller getter can have mutated the key Buffer between its read and its capture.
    // (A non-Buffer publicKey leaves pk null and is refused by the Buffer.isBuffer shape check below.)
    // A ready anchor tuple: validate the shape build + validate consume -- name.rdns
    // (name matching), publicKey bytes and the algorithm OID (the sec. 6.1.4 key
    // hand-off). trustAnchors is a caller option, so a malformed tuple is a config
    // error and fails closed at entry, not a downstream no-path / soft verdict.
    // `algorithm` is the anchor key's own algorithm: an OID string, or the SubjectPublicKeyInfo
    // `algorithm` object a parsed certificate carries ({ oid, parameters }), which validate has always
    // accepted. Built-in verification derives the key algorithm from the (valid) publicKey SPKI and never
    // consults this value, so any algorithm that slips through -- an object with no `oid`, or an oid that
    // is not a real OID -- would validate the path on the SPKI alone and leave the very fail-open this
    // check exists to close. A number, an object without an oid, or another non-shape is a malformed tuple
    // and fails closed; a MISSING algorithm skips this branch and is caught below as not-a-certificate.
    // Materialize the anchor name to a fresh plain object carrying only its CONSUMED sub-fields: rdns (used
    // for DN matching -- read through the chain, so an inherited / Object.create(base) rdns is kept, then
    // DEEP-copied (the outer array, each RDN array, and each attribute record) so a later mutation of the
    // caller's nested RDN cannot change the issuer DN name chaining re-reads) and bytes (the DN DER a
    // cert-derived name carries, kept for a lossless round-trip; not consumed in a name-matching decision, so
    // it is held by reference). Each is read ONCE as DATA; the name object's own shape is never enumerated. path
    // validation re-reads
    // workingIssuerName.rdns during name chaining, so a stateful rdns accessor that answered the shape check
    // with one array must not hand chaining a different issuer DN; the single read stores that one value. A
    // throwing name / name.rdns accessor is a malformed anchor -> path/bad-input, not a raw throw.
    // Capture the two NESTED tuple fields -- algorithm.oid and name.rdns / name.bytes -- GETTER-FREE, from their
    // own data descriptors, never by property access. An ACCESSOR nested field runs caller code that could mutate
    // the sibling before it is captured: a name.rdns getter rewriting a wrong algorithm.oid to the SPKI's real one
    // past the mismatch refusal, or an algorithm.oid getter rewriting the anchor DN. Because BOTH directions
    // cross-mutate, no read ORDER is safe -- so an accessor nested field is refused and no getter ever runs. A
    // Proxy-hosted algorithm / name object is refused before its traps can answer. A legitimate anchor -- a tuple
    // with a plain { oid } algorithm and a plain { rdns, bytes } name, or a parsed certificate's own -- carries
    // plain data and is unaffected.
    var algStr;
    try {
      if (typeof alg === "string") {
        algStr = alg;
      } else if (alg !== null && typeof alg === "object") {
        if (intrinsic.types.isProxy(alg)) throw E("path/bad-input", who + ": a trustAnchor algorithm must not be a Proxy");
        var algOidD = intrinsic.getOwnPropertyDescriptor(alg, "oid");
        if (algOidD && !intrinsic.hasOwn(algOidD, "value")) throw E("path/bad-input", who + ": a trustAnchor algorithm.oid must be a data property, not an accessor");
        var algOid = algOidD ? algOidD.value : undefined;
        algStr = typeof algOid === "string" ? algOid : null;
      } else {
        algStr = null;
      }
    } catch (e) { throw E("path/bad-input", who + ": a trustAnchor algorithm.oid accessor threw", e); }
    var nameOut = {};
    try {
      var nsrc = (nameRaw !== null && typeof nameRaw === "object") ? nameRaw : null;
      if (nsrc !== null && intrinsic.types.isProxy(nsrc)) throw E("path/bad-input", who + ": a trustAnchor name must not be a Proxy");
      var rdnsD = nsrc ? intrinsic.getOwnPropertyDescriptor(nsrc, "rdns") : undefined;
      if (rdnsD && !intrinsic.hasOwn(rdnsD, "value")) throw E("path/bad-input", who + ": a trustAnchor name.rdns must be a data property, not an accessor");
      var rdnsVal = rdnsD ? rdnsD.value : undefined;
      if (rdnsVal !== undefined) {
        intrinsic.defineProperty(nameOut, "rdns", { value: _copyRdnsDeep(rdnsVal), enumerable: true, configurable: true, writable: true });
      }
      var bytesD = nsrc ? intrinsic.getOwnPropertyDescriptor(nsrc, "bytes") : undefined;
      if (bytesD && !intrinsic.hasOwn(bytesD, "value")) throw E("path/bad-input", who + ": a trustAnchor name.bytes must be a data property, not an accessor");
      var nBytes = bytesD ? bytesD.value : undefined;
      if (nBytes !== undefined) {
        intrinsic.defineProperty(nameOut, "bytes", { value: nBytes, enumerable: true, configurable: true, writable: true });
      }
    } catch (e) { throw E("path/bad-input", who + ": trustAnchor name could not be materialized", e); }
    // hasOwn-gate the read: nameOut is materialized here, so its rdns is either an OWN data property (set above
    // from the caller's own rdns) or absent. Testing the OWN property -- not a plain nameOut.rdns, which would
    // resolve a polluted Object.prototype.rdns on a name that supplied none (and could invoke an inherited
    // throwing getter) -- means a name with no own rdns is refused, never accepted on an inherited array.
    var nameHasRdns = intrinsic.hasOwn(nameOut, "rdns") && intrinsic.isArray(nameOut.rdns);
    if (!nameHasRdns || !Buffer.isBuffer(pubRaw) || algStr === null) {
      throw E("path/bad-input", who + ": a trustAnchor tuple must be { name: { rdns: [...] }, publicKey: Buffer, algorithm: an OID string or a SubjectPublicKeyInfo algorithm carrying an oid }");
    }
    // Hold the stated algorithm to a canonical dotted-decimal OID: a shape-valid but non-canonical value
    // ("not-an-oid", { oid: "garbage" }) would otherwise pass and never match the SPKI-derived algorithm.
    guard.identifier.assertCanonicalOid(algStr, E, "path/bad-input", who + ": trustAnchor algorithm " + algStr);
    // The declared algorithm is redundant with the self-describing publicKey SPKI, and built-in verification
    // reads the SPKI's own key algorithm, never this field. A canonical but WRONG OID (declaring one key
    // algorithm for a key that is actually another) would otherwise be accepted and the path validate on the
    // SPKI alone. Reject a declared OID that does not equal the SubjectPublicKeyInfo's key-algorithm OID.
    // (publicKey was pinned to `pk` at the top of this branch, before any caller getter could mutate it.)
    //
    // Walk the whole SubjectPublicKeyInfo through the shared PKIX schema, not just its first OID: a structure
    // that carries a decodable AlgorithmIdentifier but no key BIT STRING would otherwise pass this gate and
    // slip to a soft valid:false at key-import time, bypassing the promised path/bad-input entry refusal.
    var spkiAlg;
    try { spkiAlg = schema.walk(ANCHOR_SPKI_SCHEMA, asn1.decode(pk), NS).result.algorithm; }
    catch (e) { throw E("path/bad-input", who + ": trustAnchor publicKey is not a valid SubjectPublicKeyInfo", e); }
    if (spkiAlg.oid !== algStr) {
      throw E("path/bad-input", who + ": trustAnchor algorithm " + algStr + " does not match its publicKey key algorithm " + spkiAlg.oid);
    }
    // Return a SELF-CONTAINED anchor: a fresh plain object carrying ONLY the closed, producer-derived anchor
    // field set -- name, publicKey, algorithm, parameters, purposes, distrustAfter, subjectDer, label,
    // mozillaCaPolicy -- the shape pki.trust.parseCertdata documents and path validation + trust dedup
    // consume. Every field was read exactly once above (or is derived from the validated SPKI / pinned key),
    // so a caller getter or Proxy trap runs at most once per field and no second read can disagree with the
    // first; the anchor's own shape is NEVER enumerated (no ownKeys / getOwnPropertyDescriptor / `in`) and the
    // prototype chain is never walked, so a Proxy cannot use an enumeration trap to mutate state and a hostile
    // getPrototypeOf cannot be driven into a loop (Buffer.isBuffer invokes it at most once). A field the caller
    // attached OUTSIDE this set is not carried -- an anchor has a DEFINED shape, not an arbitrary passthrough --
    // and `__proto__` is never assigned, so no caller field reaches Object.prototype's setter.
    //  - name, purposes, distrustAfter: materialized above from ONE read each as DATA (an inherited
    //    restriction is kept, since those reads followed the prototype chain). Storing DATA is load-bearing --
    //    assertAnchorConstraints reads distrustAfter several times (a truthy gate, a hasOwn gate, then the
    //    value) and _hasPurposeScopedMetadata / the purpose block read purposes at more than one site, so a
    //    live accessor could answer those reads inconsistently and silently drop a distrust or purpose control.
    //  - subjectDer, label, mozillaCaPolicy: the trust-store identity fields, read once each in the
    //    discriminator, so a store's own entry round-trips onto build's result.trustAnchor.
    //  - publicKey is the pinned copy; algorithm and parameters come from the validated SPKI, never a
    //    caller-declared field. Seeding the working key from a string OID keeps the sec. 6.1.4 key-algorithm
    //    comparison working (an object never equals a cert's keyAlg.oid); taking parameters from the key's own
    //    AlgorithmIdentifier stops a declared value that disagrees with it (e.g. P-384 params on a P-256
    //    anchor) from being promoted into workingPublicKeyParameters and inherited by a child that omits its
    //    own, which would validate a chain RFC 5280 inheritance from the real params rejects.
    var flat = {};
    intrinsic.defineProperty(flat, "name", { value: nameOut, enumerable: true, configurable: true, writable: true });
    if (purposesSnap !== undefined) intrinsic.defineProperty(flat, "purposes", { value: purposesSnap, enumerable: true, configurable: true, writable: true });
    if (distrustSnap !== undefined) intrinsic.defineProperty(flat, "distrustAfter", { value: distrustSnap, enumerable: true, configurable: true, writable: true });
    if (subjectDerRaw !== undefined) intrinsic.defineProperty(flat, "subjectDer", { value: subjectDerRaw, enumerable: true, configurable: true, writable: true });
    if (labelRaw !== undefined) intrinsic.defineProperty(flat, "label", { value: labelRaw, enumerable: true, configurable: true, writable: true });
    if (mozRaw !== undefined) intrinsic.defineProperty(flat, "mozillaCaPolicy", { value: mozRaw, enumerable: true, configurable: true, writable: true });
    intrinsic.defineProperty(flat, "publicKey", { value: pk, enumerable: true, configurable: true, writable: true });
    intrinsic.defineProperty(flat, "algorithm", { value: spkiAlg.oid, enumerable: true, configurable: true, writable: true });
    intrinsic.defineProperty(flat, "parameters", { value: spkiAlg.parameters, enumerable: true, configurable: true, writable: true });
    return flat;
  }
  // A certificate anchor carries no per-purpose constraints: the certificate branch below returns { name,
  // publicKey, algorithm, ... } only. Per-purpose purposes / distrustAfter come from a trust-anchor TUPLE (what
  // pki.trust emits), never from properties attached to a parsed certificate -- attaching them there would
  // silently drop the restriction and validate a path the caller meant to forbid. Refuse rather than drop. The
  // `in` check catches an OWN or an INHERITED purposes / distrustAfter (a name reached through the prototype, e.g.
  // a polluted Object.prototype), matching how the tuple branch refuses an inherited constraint field; it invokes
  // no getter (an existence test), and entry is not a Proxy (refused at the door), so no trap runs. A normal
  // certificate has neither on its chain, so this only catches the footgun of hanging a constraint on a cert.
  if (entry && typeof entry === "object" && (("purposes" in entry) || ("distrustAfter" in entry))) {
    throw E("path/bad-input", who + ": a trustAnchor certificate must not carry purposes / distrustAfter -- put per-purpose constraints on a { name, publicKey, algorithm, purposes, distrustAfter } tuple (or a pki.trust anchor), not on a parsed certificate");
  }
  var cert;
  try { cert = coerceCert(entry); }
  catch (e) { throw E("path/bad-input", who + ": a trustAnchor entry must be a { name, publicKey, algorithm } tuple or a certificate", e); }
  var spki = cert.subjectPublicKeyInfo;
  return { name: cert.subject, publicKey: spki.bytes, algorithm: spki.algorithm.oid, parameters: spki.algorithm.parameters, subjectDer: cert.subject.bytes };
}

/**
 * @primitive  pki.path.anchorFromCert
 * @signature  pki.path.anchorFromCert(cert) -> { name, publicKey, algorithm, parameters, subjectDer }
 * @status     stable
 * @spec       RFC 5280 sec. 6.1.1
 *
 * Turn a parsed certificate into the trust-anchor tuple `pki.path.validate` (`opts.trustAnchor`) and
 * `pki.path.build` (`opts.trustAnchors`) consume, so a root can be pinned directly instead of
 * hand-building `{ name, publicKey, algorithm }`. The subject becomes the anchor name and its
 * SubjectPublicKeyInfo the anchor key and algorithm. A value that is neither a parsed certificate nor a
 * ready anchor tuple is refused with `path/bad-input`. `validate` and `build` already normalize a
 * certificate passed directly; this exposes the same conversion for a caller that wants the tuple.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var rootDer = await pki.x509.sign({ subject: "Root CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date(0), notAfter: new Date("2999-01-01") }, { key: pair.privateKey });
 *   var anchor = pki.path.anchorFromCert(pki.schema.x509.parse(rootDer));
 *   // anchor is { name, publicKey, algorithm, ... } -- pass it as opts.trustAnchor to pki.path.validate
 */
function anchorFromCert(cert) { return toAnchor(cert, "anchorFromCert"); }

// RFC 4158 sec. 2.4.2 loop key: the (subject DN + subjectAltName + subject
// public key) tuple, NOT the DN alone. DN-alone keying wrongly prunes a
// legitimate distinct cross-cert (cross-certs share a DN) and misses a same-key
// loop; the key differentiates a rollover (same DN, new key) from a true repeat.
function identityKey(cert) {
  var san = findExt(cert, OID.subjectAltName);
  return cert.subject.bytes.toString("hex") + "|" + (san ? san.value.toString("hex") : "") + "|" +
    cert.subjectPublicKeyInfo.bytes.toString("hex");
}

// A byte-EXACT certificate identity (the signed tbs region + the signature), for deduping certificates fetched
// over AIA before they enter the shared pool. Unlike identityKey (a subject/SAN/key tuple, deliberately broad for
// loop pruning), this collapses ONLY true byte-duplicates -- so a mirror URL or a repeating CMS returning the same
// issuer is added once, but a functionally-different cert sharing a subject+key (e.g. a key rollover) is kept.
function certDerKey(cert) {
  return cert.tbsBytes.toString("base64") + "|" + (cert.signatureValue && cert.signatureValue.bytes ? cert.signatureValue.bytes.toString("base64") : "");
}

function childAkiKeyId(cert) {
  var d = softDecode(cert, OID.authorityKeyIdentifier);
  return (d && d.value && d.value.keyIdentifier) ? d.value.keyIdentifier : null;
}

// RFC 4158 sec. 3.5 candidate prioritization -- a SORT weight, never a gate.
// Higher = tried first (fewer validate calls to reach a valid path). Every term
// is a hint: a KID match, an anchor-adjacent issuer, CA + keyCertSign presence,
// and validity at the check time all raise priority, but a lower-scoring
// candidate is STILL attempted, and validate makes every accept decision.
function scoreCandidate(cand, childAki, anchors, time) {
  var score = 0;
  if (childAki) {
    var d = softDecode(cand, OID.subjectKeyIdentifier);
    if (d && Buffer.isBuffer(d.value) && d.value.equals(childAki)) score += 1000;   // sec. 3.5.12 KID match: heaviest
  }
  for (var i = 0; i < anchors.length; i++) {
    if (nameMatchSoft(cand.issuer.rdns, anchors[i].name.rdns)) { score += 100; break; }   // sec. 3.5.15/.16 anchor-adjacent
  }
  var bc = softDecode(cand, OID.basicConstraints);
  if (bc && bc.value && bc.value.cA === true) score += 10;                          // sec. 3.5.1 basicConstraints cA
  var ku = softDecode(cand, OID.keyUsage);
  if (ku && ku.value && ku.value.keyCertSign === true) score += 10;                 // sec. 3.5.3 keyUsage keyCertSign
  var v = cand.validity;
  // allow:nan-date-comparison-unguarded -- cand.validity dates are codec-parsed (asn1 readTime rejects a NaN instant) and time is guard.time.assertValid'd at entry; the validity term is a fail-safe sort hint regardless.
  if (v && guard.time.isDate(v.notBefore) && guard.time.isDate(v.notAfter) &&
    guard.time.instantOf(v.notBefore) <= guard.time.instantOf(time) &&
    guard.time.instantOf(time) <= guard.time.instantOf(v.notAfter)) score += 5;   // sec. 3.5.4 validity
  return score;
}

// Sort scored issuer candidates by descending priority and push each non-looping one onto the DFS stack as a
// child frame (the chain grows leaf-ward by PREPENDING the issuer). Shared by the static-pool expansion and the
// AIA-fallback expansion so both enforce the SAME total-work counter (sec. 3.5 breadth cap), loop pruning
// (the identity visited-set), and priority order. `scored` is [{cand, score}]; returns the number of candidates
// ticked so the caller can advance its `considered` tally.
function _pushCandidates(frame, scored, stack, counter) {
  scored.sort(function (a, b) { return a.score - b.score; });   // ascending -> push lowest first so the highest is popped first
  var n = 0;
  for (var ci = 0; ci < scored.length; ci++) {
    counter.tick();          // breadth / total-work cap -> throws path/build-limit
    n += 1;
    var cand = scored[ci].cand, candKey = identityKey(cand);
    // Loop detection and the dedupe sets below are resource bounds, so they are asked through the
    // captured methods: a replaced `Set.prototype.has` answering false never prunes and the build
    // walks a cycle until a cap stops it.
    if (intrinsic.setHas(frame.keys, candKey)) continue;
    var childKeys = new Set(frame.keys);
    intrinsic.setAdd(childKeys, candKey);
    stack.push({ chain: [cand].concat(frame.chain), hop: frame.hop + 1, keys: childKeys });
  }
  return n;
}

// ---- AIA caIssuers network fetching (RFC 5280 sec. 4.2.2.1, opt-in over pki.transport) --------------------
// Discover a MISSING intermediate by GETting the caIssuers accessLocation of the certificate being chained
// past, feeding the fetched cert(s) into the SAME candidate search. SSRF / amplification bounded: https-only,
// NO private / loopback / link-local destination -- an IP LITERAL is refused by the pre-check, and a DNS NAME
// that RESOLVES to such an address is refused (and the address pinned) by the transport's blockPrivateAddresses
// filter set on every AIA request, so an untrusted cert cannot drive an authenticated GET to an internal service
// / cloud metadata by literal OR by hostname; a
// total fetch budget (a SILENT cap -- stop fetching, never a throw that aborts a buildable path), a per-cert URL
// cap over DISTINCT normalized URLs, a build-wide URL dedupe (fragment-free), a response size + certificate-count
// cap, no redirect following. Every fetch fault is a SKIP (the DFS continues over the pool). A fetched cert is UNTRUSTED pool
// material -- when validate is on (the default) it flows through validate() like any candidate and is NEVER a
// trust anchor; in pure-builder mode (opts.validate:false) it is returned unvalidated, exactly like a static candidate.

// SSRF guard (literal pre-check): is a URL host a private / loopback / link-local / reserved IP LITERAL? An AIA
// URL comes from an UNTRUSTED certificate, so a literal address into RFC 1918 / loopback / the 169.254 cloud-
// metadata range must not be fetched (with enterprise TLS trust it would be an authenticated GET to an internal
// service). This is a fast pre-filter that avoids even opening a socket for an obvious literal; a DNS NAME is
// judged at RESOLUTION time by the transport's blockPrivateAddresses filter (set on the AIA request below), which
// also pins the checked address. The IP classification is shared with the transport (one range set, no drift).
function _isBlockedAiaHost(host) {
  if (host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") host = host.slice(1, -1);   // an IPv6 literal: URL.hostname keeps the [brackets]
  if (net.isIP(host) === 0) return false;   // a DNS name -> not judged here; the transport's resolution-time filter blocks a private resolution
  return httpTransport.isBlockedIp(host);   // an IP literal -> the shared private/loopback/link-local classifier
}

// Parse an AIA response body as a single DER certificate (RFC 2585) OR a certs-only CMS bundle (RFC 5272).
// The media type is only an ordering HINT (RFC 5280 sec. 4.2.2.1: "should not depend solely on the ... media
// type") -- both structures are attempted, the wire decides. Returns raw certificate DER Buffers; throws
// (caught upstream as a skip) if the body is neither.
function _aiaParseBody(body, contentType, maxCerts) {
  var certsFirst = String(contentType || "").toLowerCase().indexOf("pkcs7") >= 0;   // HINT: order the attempts only
  var order = certsFirst ? ["certs", "cert"] : ["cert", "certs"];
  for (var i = 0; i < order.length; i++) {
    try {
      if (order[i] === "cert") { x509.parse(body); return [Buffer.from(body)]; }
      return cms.parseCertsOnly(body, E, "path", maxCerts).certificates;   // maxCerts bounds the parse of an untrusted bundle
    } catch (_e) { /* structure-sniff: try the other form */ }
  }
  throw E("path/aia-bad-body", "an AIA response body is neither a DER certificate nor a certs-only CMS");
}

// Fetch ONE caIssuers URL over the injected/default transport; returns the parsed candidate certs, or throws
// (the caller collapses any throw to a skip). Only a 200 with a non-empty, in-cap body is a cert source (M12).
async function _aiaFetchOne(uri, aia) {
  // blockPrivateAddresses: the real transport refuses -- and pins -- a hostname that RESOLVES to a private /
  // loopback / link-local address (the literal pre-check only catches an IP literal). An injected test transport
  // ignores the flag; the DFS treats a blocked-address transport error as a silent skip like any fetch fault.
  var res = await aia.transport({ method: "GET", url: uri, tls: aia.tls, timeout: aia.timeout, maxResponseBytes: aia.maxResponseBytes, blockPrivateAddresses: true });
  res = res || {};
  if (res.status !== 200) throw E("path/aia-status", "an AIA fetch returned HTTP " + res.status + " (only 200 is a cert source; no redirect following)");
  var body = Buffer.isBuffer(res.body) ? res.body : Buffer.from(res.body == null ? "" : String(res.body), "latin1");
  if (body.length === 0) throw E("path/aia-empty", "an AIA fetch returned an empty body");
  // Belt for an INJECTED transport that ignores maxResponseBytes (the real transport streaming-aborts at the cap).
  if (body.length > aia.maxResponseBytes) throw E("path/aia-too-large", "an AIA response exceeds the " + aia.maxResponseBytes + "-byte cap");
  var headers = {};
  Object.keys(res.headers || {}).forEach(function (k) { headers[k.toLowerCase()] = res.headers[k]; });
  return _aiaParseBody(body, headers["content-type"], aia.maxCertsPerResponse);
}

// Discover issuer candidates for `current` from its AIA caIssuers URLs. Returns parsed candidate certs (coerced
// like any pool cert). Bounded + fail-closed; ticks aia.fetchCounter (the total-budget throw) and mutates
// aia.fetchedUrls (build-wide dedupe). A cert with no AIA, a malformed AIA, or no fetchable https caIssuers
// URI simply yields no candidates (RFC 5280 sec. 4.2.2.1 AIA is advisory / non-critical).
async function _fetchAiaIssuers(current, aia) {
  var d = softDecode(current, OID.authorityInfoAccess);   // no / malformed AIA -> no fetch
  if (!d || !d.value) return [];
  // Collect DISTINCT, normalized, fetchable https URLs, deduping BEFORE the per-cert cap so a flood of duplicate
  // (or fragment-variant) entries can never crowd out a usable later URL.
  var uris = [];
  var seenThisCert = new Set();
  for (var i = 0; i < d.value.length; i++) {
    var ad = d.value[i];
    if (ad.accessMethod !== OID.caIssuers) continue;      // ONLY id-ad-caIssuers, never id-ad-ocsp
    if (!ad.accessLocation || ad.accessLocation.tag !== 6) continue;   // ONLY a uniformResourceIdentifier [6]
    // Parse the URI ONCE: the NORMALIZED href is both the dedupe key AND the exact URL handed to the transport.
    var u;
    try { u = new URL(ad.accessLocation.value); }
    catch (_e) { continue; }                              // an unparseable URI -> skip (catch on its own line so the swallow gate can trace it)
    if (u.protocol !== "https:") continue;                // https-only: no socket for http/ldap/ftp/file/mailto
    if (_isBlockedAiaHost(u.hostname)) continue;          // SSRF: never fetch a private / loopback / link-local IP literal
    // A DNS-NAME host's private RESOLUTION can only be blocked by a transport that filters the resolved address;
    // with an UNGUARDED transport (an injected fn that does not vouch blocksPrivateAddresses) fail closed -- fetch
    // IP literals only (already validated above), never a hostname whose resolved address we cannot verify.
    if (net.isIP(u.hostname.replace(/^\[(.*)\]$/, "$1")) === 0 && !aia.transportGuardsAddresses) continue;
    u.hash = "";                                          // the fragment is never sent on the wire -> not part of the request/dedupe identity
    if (intrinsic.setHas(aia.fetchedUrls, u.href) || intrinsic.setHas(seenThisCert, u.href)) continue;   // dedupe (build-wide OR same-cert) on the normalized URL
    if (seenThisCert.size >= aia.maxPerCert) break;       // per-cert DISTINCT-url cap, checked BEFORE appending so maxAiaPerCert:0 collects nothing (no fetch at all)
    intrinsic.setAdd(seenThisCert, u.href);
    uris.push(u.href);
  }
  var out = [];
  for (var k = 0; k < uris.length; k++) {
    if (intrinsic.setHas(aia.fetchedUrls, uris[k])) continue;   // a same-cert normalization-equal duplicate
    if (aia.fetches >= aia.maxFetches) break;     // total budget reached -> STOP fetching (a SILENT cap, never a throw that denies a buildable path)
    intrinsic.setAdd(aia.fetchedUrls, uris[k]);   // mark BEFORE the fetch -> fetched at most once, even on failure
    aia.fetches += 1;
    var certs;
    try { certs = await _aiaFetchOne(uris[k], aia); }
    catch (_e2) { continue; }   // any fetch / parse fault is a skip; the DFS continues over the pool + other URLs
    // Each response is already capped to maxCertsPerResponse by parseCertsOnly (per RESPONSE), so an earlier
    // URL's bundle never consumes a later URL's allowance -- coerce every returned cert.
    for (var c = 0; c < certs.length; c++) {
      var parsed;
      try { parsed = coerceCert(certs[c]); }
      catch (_e3) { /* allow:swallow-unverified verified-unreachable: every cert here already passed the IDENTICAL x509.parse in _aiaParseBody (single-DER validates `body`; certs-only validates each via parseCertsOnly), so coerceCert re-parsing the same bytes cannot throw -- the guard stays as defense-in-depth */ continue; }
      out.push(parsed);
    }
  }
  return out;
}

/**
 * @primitive  pki.path.build
 * @signature  pki.path.build(leaf, opts) -> Promise<{ valid, path, trustAnchor, result, candidatesConsidered, aiaFetches }>
 * @since       0.3.7
 * @status      experimental
 * @spec        RFC 4158, RFC 5280
 * @related     pki.path.validate, pki.schema.x509.parse, pki.trust.parseCertdata
 *
 * Discover the ordered certification path from a leaf certificate up to a trust anchor, over an
 * untrusted pool of candidate CA certificates, then validate it. `build` is the discovering
 * complement of `validate`: `validate` takes an already-ordered path and a trust anchor and runs
 * the 6.1 state machine; `build` takes a leaf, an unordered pool of candidate issuers, and a
 * trust store, and searches for the ordered leaf->anchor path `validate` accepts.
 *
 * Candidate issuers are matched by RFC 5280 7.1 name chaining, prioritized by the RFC 4158 3.5
 * heuristics (a subjectKeyIdentifier/authorityKeyIdentifier match, an anchor-adjacent issuer,
 * CA + keyCertSign, validity at the check time; each orders the search without excluding a
 * candidate), and searched depth-first with backtracking: the first ordered path that
 * `pki.path.validate` accepts wins. A name or key-identifier match is only an ordering hint;
 * every accept flows through `validate`, so `build` never weakens or duplicates a 6.1 check. The
 * search over the untrusted pool is bounded: a depth cap on chain length, a total-work cap on
 * candidate expansions, and a visited-set keyed on the (subject, subjectAltName, public key)
 * tuple. A cross-certificate cycle or Bridge-CA fan-out therefore terminates deterministically;
 * the search cannot grow without bound.
 *
 * `leaf` is a DER `Buffer`, a PEM string, or an already-parsed `pki.schema.x509` object. Returns
 * `{ valid, path, trustAnchor, result, candidatesConsidered }`, where `path` is the ordered array
 * `validate` consumes (anchor-proximal first, leaf last, the anchor excluded). Fail-closed: bad
 * options throw `path/bad-input`; no chain to any anchor throws `path/no-path`; chains that
 * assemble but none validate return `{ valid:false }` with the best failing `validate` result;
 * the search bound throws `path/build-limit`. By default `build` is OFFLINE (zero network), so supply
 * intermediates in `opts.candidates`. Set `opts.fetchAia: true` to opt in to fetching a MISSING intermediate
 * from a certificate's Authority Information Access `caIssuers` URL (RFC 5280 sec. 4.2.2.1) over
 * `pki.transport`: the fetch triggers only on a pool miss, every fetched certificate is UNTRUSTED pool material
 * that still flows through `validate` when validation is on (never a trust anchor), and the whole surface is
 * SSRF/amplification bounded -- https-only, a total fetch budget (a SILENT cap, never a throw that denies a
 * buildable path), a per-cert URL cap, a build-wide URL dedupe, a response size + certificate-count cap, and no
 * redirect following; every fetch fault is a silent skip. `aiaFetches` reports how many network GETs the build
 * performed (`0` when `fetchAia` is off). NOTE: with `opts.validate:false` (pure-builder mode) a fetched cert is
 * returned unvalidated, identical to a static candidate; the "flows through validate" guarantee needs validation on.
 *
 * @opts  candidates             The untrusted candidate CA pool (array of DER/PEM/parsed certs; alias `intermediates`).
 * @opts  trustAnchors           The trust store (non-empty array of `{ name, publicKey, algorithm }` tuples or self-signed root certificates).
 * @opts  time                   The check date (`Date`, required); forwarded to every internal `validate` call.
 * @opts  maxDepth               Chain-length depth cap (default `C.LIMITS.PATH_BUILD_MAX_DEPTH`).
 * @opts  maxCandidatesConsidered  Total-work cap on candidate expansions (default `C.LIMITS.PATH_BUILD_MAX_CANDIDATES`).
 * @opts  validate               `false` returns the ordered path without validating (pure-builder mode; default `true`).
 * @opts  fetchAia               `true` opts in to AIA caIssuers network fetching of a missing intermediate (default `false`, fully offline). Off unless set; when set, a fetch runs only on a pool miss for a non-anchor-adjacent cert, and (with validation on) every fetched cert still flows through `validate`.
 * @opts  transport              The injectable transport seam (`fn(request) -> Promise<{ status, headers, body }>`); tests drive the fetch offline. With none, the default `pki.transport.https` is used, which fails closed unless `opts.tls` carries trust. SSRF: for a caIssuers URL with a DNS hostname, a custom transport is used only if it declares `fn.blocksPrivateAddresses = true`, which vouches that it refuses (and pins) a resolved private / loopback / link-local / special-use address, as the default transport does. Without that marker a DNS-name AIA URL is fail-closed (skipped) and only an IP-literal URL (validated up front) is fetched; set the marker on your transport when it filters resolved addresses.
 * @opts  tls                    The TLS trust for the AIA HTTPS host (`{ anchors, useSystemStore, ... }`). This is distinct from `opts.trustAnchors`, the PKI trust store the path validates against. The default transport refuses an unpinned server.
 * @opts  maxAiaFetches          Total AIA network GET budget across the whole build (default `C.LIMITS.PATH_AIA_MAX_FETCHES`); on reaching it the builder stops fetching (a silent cap) and does not throw, so a fetch bound cannot deny a path the pool could build.
 * @opts  maxAiaPerCert          Cap on caIssuers URLs tried per certificate (default `C.LIMITS.PATH_AIA_MAX_PER_CERT`).
 * @opts  aiaTimeout             Per-fetch timeout in ms, forwarded to the transport.
 * @opts  maxResponseBytes       Per-fetch response size cap, forwarded to the transport (tightenable downward only).
 * @opts  (validate options)     Every `pki.path.validate` option (`requiredEku`, `revocationChecker`, `checkPurpose`, the initial policy inputs, ...) is forwarded unchanged.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pemString = await pki.x509.sign({ subject: "Example Root", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } },
 *     { key: await pki.key.export(pair.privateKey) }, { pem: true });
 *   var result = await pki.path.build(pemString, {
 *     candidates: [],              // untrusted intermediates (the openssl -untrusted set)
 *     trustAnchors: [pemString],   // a self-signed root, or a { name, publicKey, algorithm } tuple
 *     time: new Date(),
 *   });
 *   result.valid;                  // true when a path to a trust anchor was found and validated
 */
// pki.path.build takes its own options AND forwards every pki.path.validate option to each
// internal validate() call. The documented contract above says so, and validateOpts() copies
// them wholesale. So the accepted set is the union, derived from _VALIDATE_OPTS. Retyping it
// would let the two lists drift the first time validate gains an option.
//
// `trustAnchor` is removed from the union on purpose: build assigns it per candidate anchor,
// so a caller passing the singular would have it overwritten and silently ignored. Refusing it
// is what makes the singular/plural message below actionable rather than trivia.
var _BUILD_OPTS = (function () {
  var o = {
    aiaTimeout: 1, candidates: 1, fetchAia: 1, intermediates: 1, maxAiaFetches: 1,
    maxAiaPerCert: 1, maxCandidatesConsidered: 1, maxDepth: 1, maxPathCerts: 1,
    maxResponseBytes: 1, time: 1, tls: 1, transport: 1, trustAnchors: 1, validate: 1
  };
  Object.keys(_VALIDATE_OPTS).forEach(function (k) { o[k] = 1; });
  delete o.trustAnchor;
  return o;
})();

async function build(leaf, opts) {
  opts = guard.identifier.optionsObject(opts, E, "path/bad-input", "build: opts");
  guard.identifier.assertKnownKeys(opts, _BUILD_OPTS, E, "path/bad-input",
    "pki.path.build has an unknown option. The anchors here are `trustAnchors`, plural; " +
    "pki.path.validate takes `trustAnchor`. The unknown option was: ");
  var leafCert;
  try { leafCert = coerceCert(leaf); }
  catch (e) { throw E("path/bad-input", "build: the leaf certificate did not parse", e); }

  var poolInput = opts.candidates !== undefined ? opts.candidates : opts.intermediates;
  if (poolInput === undefined) poolInput = [];
  if (!intrinsic.isArray(poolInput)) throw E("path/bad-input", "build: opts.candidates must be an array of certificates");
  // A pool larger than the absolute ceiling is rejected at entry (bounds the
  // parse work on an untrusted bundle) -- distinct from the per-search tick
  // budget below, which an operator may set lower to cap the DFS.
  var poolCeiling = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES;
  if (poolInput.length > poolCeiling) throw E("path/bad-input", "build: the candidate pool has " + poolInput.length + " certificates, exceeding the " + poolCeiling + " ceiling");
  var pool;
  try { pool = poolInput.map(coerceCert); }
  catch (e) { throw E("path/bad-input", "build: a candidate certificate did not parse", e); }
  // Byte-exact identities of every cert already in the shared pool, so an AIA-fetched duplicate (a mirror URL or a
  // repeating CMS returning the same issuer) is appended AT MOST ONCE -- it otherwise inflates the pool, charging
  // the candidate budget and the ceiling for each copy before the issuer is ever evaluated.
  var poolDerKeys = new Set();
  for (var pdk = 0; pdk < pool.length; pdk++) intrinsic.setAdd(poolDerKeys, certDerKey(pool[pdk]));

  if (!intrinsic.isArray(opts.trustAnchors) || opts.trustAnchors.length === 0) throw E("path/bad-input", "build: opts.trustAnchors must be a non-empty array of anchor tuples or root certificates");
  var anchors = opts.trustAnchors.map(function (a) { return toAnchor(a, "build"); });

  guard.time.assertValid(opts.time, E, "path/bad-input", "build: opts.time (the validity-window check date, forwarded to validate)");
  // The chain-length bound is tied to the EFFECTIVE maxPathCerts the interleaved
  // validate uses: a built path holds hop + 1 certificates (the leaf plus each
  // intermediate), so capping hops at maxPathCerts - 1 keeps every path validate
  // sees within its own per-path ceiling -- otherwise a maxDepth of maxPathCerts
  // would assemble a maxPathCerts + 1 path that validate rejects with
  // path/bad-input. The same cap value is computed the way validate computes it
  // (opts.maxPathCerts forwarded), and the explicit-stack search below carries no
  // native-recursion stack risk regardless of the depth.
  var effectiveMaxCerts = guard.limits.cap(opts.maxPathCerts, "build: opts.maxPathCerts", constants.LIMITS.PATH_MAX_CERTS, { E: E, code: "path/bad-input", min: 1 });
  // depthCeiling is 0 when maxPathCerts is 1: the only path within the limit is a
  // single leaf directly under an anchor (a zero-hop search). maxDepth's minimum
  // is therefore 0, not 1 -- a zero-hop search is legitimate and a maxPathCerts of
  // 1 must not throw before the anchor is even checked.
  var depthCeiling = effectiveMaxCerts - 1;
  var maxDepth = guard.limits.cap(opts.maxDepth, "build: opts.maxDepth", Math.min(constants.LIMITS.PATH_BUILD_MAX_DEPTH, depthCeiling), { E: E, code: "path/bad-input", min: 0, max: depthCeiling });
  var maxConsidered = guard.limits.cap(opts.maxCandidatesConsidered, "build: opts.maxCandidatesConsidered", poolCeiling, { E: E, code: "path/bad-input", min: 1 });
  var doValidate = opts.validate !== false;

  // AIA caIssuers fetching is OFF unless opts.fetchAia === true -- the default build is byte-identical to
  // today's offline search (no transport constructed, no socket, no new path executed). When on, opts.transport
  // is the injectable seam (tests drive it offline); with no injected transport the default https transport
  // fails closed unless opts.tls carries an anchor / useSystemStore. opts.tls is the TLS trust for the AIA
  // HTTPS host -- DISTINCT from opts.trustAnchors (the PKI trust store the built path validates against).
  var aiaCtx = null;
  if (opts.fetchAia === true) {
    // Validate the AIA-specific options at CONFIG time (a caller typo is a path/bad-input throw, tier 1), not
    // lazily inside the fetch where a bad transport / timeout would be caught as an ordinary fetch fault and
    // silently degrade to path/no-path. A non-function transport can never be called; an injected transport gets
    // a validated timeout (it may not cap the value itself).
    if (opts.transport !== undefined && typeof opts.transport !== "function") {
      throw E("path/bad-input", "build: opts.transport must be a transport function (request) -> Promise<{ status, headers, body }>");
    }
    // Validate aiaTimeout against the SAME bounds the built-in transport enforces (integer, 1..MAX_TIMEOUT) at
    // CONFIG time, so a non-integer / over-ceiling value is a path/bad-input throw here rather than a transport
    // rejection swallowed later as a fetch fault. guard.limits.cap is the exact primitive the transport applies.
    if (opts.aiaTimeout !== undefined) {
      guard.limits.cap(opts.aiaTimeout, "build: opts.aiaTimeout", 1, { E: E, code: "path/bad-input", min: 1, max: httpTransport.MAX_TIMEOUT });
    }
    var aiaTransport = opts.transport || httpTransport.https({ E: E, errPrefix: "path" });
    aiaCtx = {
      transport: aiaTransport,
      // SSRF for a DNS-name AIA host needs resolution-time address filtering + pinning, which only a transport
      // that ADVERTISES the capability performs (the built-in, or an injected one that sets blocksPrivateAddresses
      // to vouch it filters). An injected fn(request) that ignores the flag is treated as UNGUARDED: a DNS-name AIA
      // URL is then fail-closed (skipped) and only an IP literal (validated by the literal pre-check) is fetched.
      transportGuardsAddresses: aiaTransport.blocksPrivateAddresses === true,
      tls: opts.tls || {},
      timeout: opts.aiaTimeout,               // validated above; the transport applies its own default + cap
      // Default the AIA response cap BELOW the general HTTP ceiling (a caIssuers response is small); tighten
      // downward only, never above HTTP_MAX_RESPONSE_BYTES.
      maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "build: opts.maxResponseBytes", constants.LIMITS.PATH_AIA_MAX_RESPONSE_BYTES, { E: E, code: "path/bad-input", min: 1, max: constants.LIMITS.PATH_AIA_MAX_RESPONSE_BYTES }),
      maxPerCert: guard.limits.cap(opts.maxAiaPerCert, "build: opts.maxAiaPerCert", constants.LIMITS.PATH_AIA_MAX_PER_CERT, { E: E, code: "path/bad-input", min: 0 }),
      maxCertsPerResponse: constants.LIMITS.PATH_AIA_MAX_CERTS_PER_RESPONSE,
      // The total fetch budget is a SILENT cap (stop initiating fetches when reached), NOT a throw: a bound on
      // an ADVISORY fetch must never abort a build that the static pool could still complete. maxFetches may be
      // 0 (fetchAia:true but no network -- identical to offline).
      maxFetches: guard.limits.cap(opts.maxAiaFetches, "build: opts.maxAiaFetches", constants.LIMITS.PATH_AIA_MAX_FETCHES, { E: E, code: "path/bad-input", min: 0 }),
      fetchedUrls: new Set(),
      fetches: 0,
    };
  }

  // The build-specific options are consumed here; every remaining validate
  // option is forwarded unchanged to the interleaved validate call. Object.keys
  // enumerates only own enumerable properties, so no prototype-pollution belt.
  var BUILD_ONLY_OPT = { candidates: 1, intermediates: 1, trustAnchors: 1, maxDepth: 1, maxCandidatesConsidered: 1, validate: 1,
    fetchAia: 1, transport: 1, tls: 1, maxAiaFetches: 1, maxAiaPerCert: 1, aiaTimeout: 1, maxResponseBytes: 1 };
  // No prototype, so the set forwarded to each internal validate holds what was put in it and
  // nothing a runtime carries. A plain `{}` here re-acquired a polluted name after the caller's
  // own value had been dropped, which is how an explicit `softFail: false` became a waiver.
  var forwarded = Object.create(null);
  // Driven by the contract. Walk the validate options this verb forwards and take the ones the
  // bag answers for.
  //
  // Enumerating the bag reads whatever a property walk chooses to report, and that walk skips a
  // method so a caller's class keeps its own. A known option whose value were a bare function
  // would be indistinguishable from one, and a defaults-style bag like
  // `Object.create({ someOption: fn })` would have it dropped here, leaving each internal
  // validate running without something the caller supplied.
  //
  // No option takes a bare function today. `revocationChecker` is `{ check }`, `verifier` is
  // `{ verify }`, and `transport` is build-only and never forwarded. So this is a hardening
  // rather than a live defect, and there is no vector that fails without it. It is here because
  // asking the contract cannot drop a known option whatever its value, and the alternative makes
  // the forwarded set depend on a walk whose rules exist for an unrelated question.
  //
  // `in` rather than an own check, because an option carried on a prototype is one the caller
  // supplied and `opts.softFail` answers for it. Own membership decides only whether a name is
  // build-only, which is a question about this module's own table and never about the caller.
  Object.keys(_VALIDATE_OPTS).forEach(function (k) {
    if (intrinsic.hasOwn(BUILD_ONLY_OPT, k)) return;
    if (k in opts) forwarded[k] = opts[k];
  });
  function validateOpts(anchor) {
    var vo = Object.create(null);   // same reason as `forwarded` above
    // Every name in the forwarded set, which was built from the contract above and has no
    // prototype, so its own keys are exactly what was put in it. A property walk here would
    // apply the method rule a second time and drop a function-valued option all over again;
    // forwarding less than was validated is worse than refusing the bag.
    Object.keys(forwarded).forEach(function (f) { vo[f] = forwarded[f]; });
    vo.trustAnchor = anchor;
    return vo;
  }

  // The DoS terminator: tick() once per candidate-issuer expansion so a hostile
  // mesh cannot fan the search without bound (RFC 4158 8.1). A breach throws
  // path/build-limit. candidatesConsidered mirrors the tick count for the caller.
  var counter = guard.limits.counter(maxConsidered, E, "path/build-limit", "build: candidate-issuer expansion");
  var considered = 0;
  var anyChainAssembled = false;
  var bestFail = null;
  var success = null;

  // A bounded, EXPLICIT-stack forward DFS from the leaf toward an anchor -- no
  // native recursion, so an operator-raised maxDepth cannot overflow the stack
  // over an untrusted graph. Each frame is a candidate chain [top, ...toward the
  // leaf] (leaf last) plus the identity keys already on it; a frame is expanded
  // by prepending a name-chaining issuer. Highest-priority candidates are pushed
  // LAST so they are popped (explored) FIRST -- depth-first in priority order.
  // Caps are enforced before every expansion; a candidate whose (subject, SAN,
  // public key) tuple is already on the chain is a loop and is pruned.
  var stack = [{ chain: [leafCert], hop: 0, keys: new Set([identityKey(leafCert)]) }];
  // AIA fetch frames are DEFERRED into this queue and drained ONLY when `stack` is empty -- i.e. once the ENTIRE
  // local (static-pool) search has failed. This enforces RFC 4158 sec. 7.2 "local before remote" GLOBALLY across
  // the whole search, not per-branch: a build the static pool can complete never issues a network request, and a
  // higher-priority local dead-end can never fetch ahead of a still-unexplored lower-priority static sibling.
  // Drained DEEPEST-first, and among equal depth EARLIEST-deferred (= highest DFS priority) first: the actual
  // dead end (a missing deeper hop) is fetched before an ancestor whose issuer the pool ALREADY supplies (so a
  // scarce budget is never spent re-retrieving a locally-resolved hop), and a higher-scoring sibling's AIA is
  // tried before a lower-scoring one (a plain LIFO pop would reverse sibling priority and let a stale low-priority
  // branch's dead URL waste a tight budget before the preferred branch).
  var deferredAia = [];
  var deferSeq = 0;   // monotonic deferral order (DFS priority): the drain tie-breaks same-depth frames by it
  while (!success) {
    if (!stack.length) {
      // The local search is drained. Begin / continue the fetch phase: pick a deferred frame with PENDING WORK --
      // one that has NOT yet fetched, OR whose poolMark trails the shared pool (a SIBLING branch fetched a cert
      // SINCE this frame last ran, which may complete it). A drained frame is NOT discarded: a later sibling's
      // fetch can add the very issuer an earlier, already-run branch needed, so every frame stays eligible for
      // pool growth until it has fetched AND seen the whole pool. Among eligible frames pick the deepest, then the
      // earliest-deferred (highest DFS priority). No eligible frame -> the whole search is exhausted.
      var _bi = -1;
      for (var _di = 0; _di < deferredAia.length; _di++) {
        var _f = deferredAia[_di];
        if (_f.fetched && _f.poolMark >= pool.length) continue;   // nothing left to fetch or to re-expand against
        if (_bi === -1) { _bi = _di; continue; }
        var _bf = deferredAia[_bi];
        if (_f.hop > _bf.hop || (_f.hop === _bf.hop && _f.seq < _bf.seq)) _bi = _di;
      }
      if (_bi === -1) break;   // no deferred frame can make further progress
      var fb = deferredAia[_bi];   // NOT removed: it stays eligible for certs a later sibling fetch adds
      var fbCur = fb.chain[0];
      if (!fb.fetched && aiaCtx && aiaCtx.fetches < aiaCtx.maxFetches) {
        var fetched = await _fetchAiaIssuers(fbCur, aiaCtx);   // append newly-fetched issuer(s) to the SHARED pool
        for (var fj = 0; fj < fetched.length; fj++) {
          var fdk = certDerKey(fetched[fj]);
          if (intrinsic.setHas(poolDerKeys, fdk)) continue;   // a byte-duplicate (mirror URL / repeating CMS) -> add once, never re-charge the budget/ceiling
          intrinsic.setAdd(poolDerKeys, fdk);
          if (pool.length < poolCeiling) pool.push(fetched[fj]);
        }
      }
      fb.fetched = true;   // the fetch attempt is done (or budget-skipped); the frame stays eligible for FUTURE pool growth
      // Re-expand fb against every pool cert added SINCE it last ran -- its OWN just-fetched certs AND any a SIBLING
      // branch fetched into the shared pool. The pool-index mark skips certs fb already scored (no redundant work);
      // advancing it means fb re-scores only certs added even later. This runs even when the budget is exhausted, so
      // a budget-capped frame still benefits from a sibling fetch.
      var fbAki = childAkiKeyId(fbCur);
      var fbScored = [];
      for (var pj = fb.poolMark; pj < pool.length; pj++) {
        if (nameMatchSoft(pool[pj].subject.rdns, fbCur.issuer.rdns)) {
          fbScored.push({ cand: pool[pj], score: scoreCandidate(pool[pj], fbAki, anchors, opts.time) });
        }
      }
      fb.poolMark = pool.length;
      considered += _pushCandidates(fb, fbScored, stack, counter);
      continue;
    }
    var frame = stack.pop();
    var current = frame.chain[0];

    // Terminate: is `current` issued by a configured anchor? An anchor-adjacent
    // cert completes a candidate path; validate is the authority on acceptance.
    // A found path breaks out here and the enclosing while exits on !success.
    for (var ai = 0; ai < anchors.length; ai++) {
      if (!nameMatchSoft(current.issuer.rdns, anchors[ai].name.rdns)) continue;
      if (!doValidate) { success = { path: frame.chain.slice(), trustAnchor: anchors[ai] }; break; }
      anyChainAssembled = true;
      var res = await validate(frame.chain, validateOpts(anchors[ai]));
      if (res.valid) { success = { valid: true, path: frame.chain.slice(), trustAnchor: anchors[ai], result: res }; break; }
      if (!bestFail) bestFail = { path: frame.chain.slice(), trustAnchor: anchors[ai], result: res };
    }
    if (success || frame.hop >= maxDepth) continue;   // depth cap: this branch is exhausted

    var childAki = childAkiKeyId(current);
    var scored = [];
    for (var pi = 0; pi < pool.length; pi++) {
      if (nameMatchSoft(pool[pi].subject.rdns, current.issuer.rdns)) {
        scored.push({ cand: pool[pi], score: scoreCandidate(pool[pi], childAki, anchors, opts.time) });
      }
    }
    // Opt-in AIA caIssuers fetch as a FALLBACK: DEFER it (drained above only after the ENTIRE local search is
    // exhausted, RFC 4158 sec. 7.2 "local before remote") rather than pushing it onto the stack, so it can never
    // run ahead of an unexplored local sibling -- a build the static pool can complete never fetches. It is gated
    // on `success` being unset (guaranteed by the continue above), NOT on the issuer name failing to match an
    // anchor: an issuer DN that matches an anchor whose KEY did not validate this chain (a CA key rollover -- the
    // real same-DN, different-key intermediate is missing and reachable only via AIA) still needs the fetch.
    if (aiaCtx && frame.hop < maxDepth && aiaCtx.fetches < aiaCtx.maxFetches) {
      // poolMark: the shared-pool length now, so the drain re-expands this frame only against certs added LATER
      // (its own fetch + any sibling branch's fetch), never re-scoring the static pool it expands against below.
      // seq: the deferral order, so the drain can tie-break same-depth frames by DFS priority (earliest first).
      // fetched: false until this frame's own AIA fetch runs; it then stays eligible for later sibling pool growth.
      deferredAia.push({ chain: frame.chain, hop: frame.hop, keys: frame.keys, poolMark: pool.length, seq: deferSeq, fetched: false });
      deferSeq += 1;
    }
    considered += _pushCandidates(frame, scored, stack, counter);
  }

  var aiaFetches = aiaCtx ? aiaCtx.fetches : 0;   // the count of AIA caIssuers network GETs this build performed (0 when opts.fetchAia is off)
  if (success) {
    if (doValidate) return { valid: true, path: success.path, trustAnchor: success.trustAnchor, result: success.result, candidatesConsidered: considered, aiaFetches: aiaFetches };
    return { path: success.path, trustAnchor: success.trustAnchor, candidatesConsidered: considered, aiaFetches: aiaFetches };
  }
  if (anyChainAssembled) {
    // Chains reached an anchor but none validated -> the soft verdict carrying
    // the best failing validate result (parity with validate; never a throw).
    return { valid: false, path: bestFail.path, trustAnchor: bestFail.trustAnchor, result: bestFail.result, candidatesConsidered: considered, aiaFetches: aiaFetches };
  }
  // No chain to any configured anchor could even be assembled -- a permanent
  // structural verdict (name/key chaining dead-ended before the trust store).
  throw E("path/no-path", "build: no certification path from the leaf to any configured trust anchor could be assembled");
}

module.exports = {
  validate: validate,
  build: build,
  anchorFromCert: anchorFromCert,
  crlChecker: crlChecker,
  ocspChecker: ocspChecker,
  verifyOcspResponse: verifyOcspResponse,
  // The set of extension OIDs whose CRITICAL semantics this validator processes (RFC 5280 sec. 6.1).
  // Exposed so a linter can distinguish "processed" from "merely decoded" and stay consistent with
  // the path-validation verdict on a critical extension -- a decoder in certExtensionDecoders is NOT
  // by itself proof the criticality is honored. Both sets are frozen so a caller cannot mutate them.
  PROCESSED_EXTENSIONS: PROCESSED_EXTENSIONS,
  // Extensions that ARE processed for an intermediate CA but are unprocessed on the target/leaf, so a
  // critical instance on the target fails closed (RFC 5280 sec. 6.1.5(f)) -- policyMappings is
  // prepare-next-only and SHOULD-be-non-critical. A linter mirrors this for a leaf certificate.
  TARGET_UNPROCESSED_IF_CRITICAL: TARGET_UNPROCESSED_IF_CRITICAL,
};
