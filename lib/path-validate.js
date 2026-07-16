// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module pki.path
 * @nav Path validation
 * @title Certification path validation (RFC 5280 6)
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
var guard = require("./guard-all");
var constants = require("./constants");
var validator = require("./validator-all");
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

var NS = pkix.makeNS("path", PathError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;

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
};

// The set of extension OIDs the validator PROCESSES -- an unrecognized critical
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
// qcStatements is deliberately NOT processed: a critical QC statement (QcLimitValue reliance limit,
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
// exported (for pki.lint to stay consistent). A caller must not be able to add an OID -- doing so
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
// `sameKeyOid` marks the one-shot families whose PUBLIC-KEY algorithm OID is the
// SAME as the signature algorithm OID -- EdDSA, ML-DSA, SLH-DSA. For these, Node's
// WebCrypto imports an SPKI of ANOTHER type under the requested name and verifies
// with the real key (it does NOT reject a mismatched SPKI the way it does for
// RSA/ECDSA), so the issuer-key <-> signature-algorithm consistency (RFC 9814 sec. 4)
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
  //   SAME hash as the signature and trailerField 0xBC (1); any declared value
  //   that deviates cannot be honored, so it is REJECTED rather than verified
  //   under WebCrypto's defaults (a signatureAlgorithm bypass otherwise).
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
    // around EXACTLY ONE value (an AlgorithmIdentifier or an INTEGER); a
    // primitive/childless or multi-child context field is malformed -- reading
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
// under the requested name and verifies with the real key -- so an Ed25519-signed
// certificate labelled SLH-DSA would otherwise validate. Enforce structurally:
// the issuer SPKI's algorithm OID MUST equal the signature algorithm OID. (For
// RSA/ECDSA -- different key vs signature OIDs -- WebCrypto's import already rejects
// a mismatched key type, so `sameKeyOid` is not set and this is a no-op.)
function assertKeyMatchesSigAlg(spkiBytes, sigOid, d) {
  if (!d || !d.sameKeyOid) return;
  var keyOid;
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
// carries a composite ML-DSA OID, IF it has a keyUsage extension, MUST assert at least
// one signature bit (digitalSignature / nonRepudiation / keyCertSign / cRLSign) and MUST
// NOT assert any encryption or key-establishment bit -- a composite ML-DSA key is a
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

// RFC 9935 sec. 5: a certificate whose SubjectPublicKeyInfo carries an id-ml-kem-* OID, IF it
// has a keyUsage extension, MUST assert keyEncipherment as the ONLY key usage set -- an ML-KEM
// key is a key-establishment-only key (it cannot sign or agree, so no other bit is legitimate,
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

// Import a descriptor's verification key, validating an EdDSA point FIRST: node/OpenSSL import a
// low-order (e.g. identity or all-zeroes) Ed25519/Ed448 SPKI without complaint and such a key
// verifies a forged signature. This is the ONE seam both the certificate path and the revocation
// (CRL / OCSP-response) path import through, so neither can skip the point gate -- a low-order
// issuer / responder key fails the caller closed (a rejected promise the caller maps to a bad
// verdict), never verifying a forged chain or a forged revocation.
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
// EXACTLY ONE "@" (RFC 5280 sec. 4.2.1.6 deprecates the quoted local part, and an
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
// and "evil.com" compare equal -- otherwise a trailing-dot SAN would escape a
// dNSName constraint.
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
// port ":") is NOT a FQDN and cannot be matched against a domain-suffix
// constraint. Only [A-Za-z0-9.-] with at least one dot qualifies.
function isFqdnHost(host) {
  var h = stripTrailingDot(host);
  if (h === "" || h.indexOf(".") === -1) return false;       // empty or single-label (localhost)
  if (!/^[a-z0-9.-]+$/i.test(h)) return false;               // scheme/path/port/IPv6 chars, "@", etc.
  if (/^[0-9.]+$/.test(h)) return false;                     // IPv4 dotted-quad literal
  return true;
}

// A URI constraint applies to the host part: a leading "." matches subdomains
// only; a bare host matches that host EXACTLY (not subdomains, per sec. 4.2.1.10).
// BOTH sides must be a fully qualified domain name: a URI SAN with no host / an
// IP literal, OR a malformed constraint that is not an FQDN (e.g. a full URI
// "http://blocked.example" rather than "blocked.example"), cannot be evaluated
// and returns "unsupported" so the caller fails closed rather than letting the
// name silently escape a critical constraint by never matching.
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
  // contain a raw "@", so a conformant authority has AT MOST ONE "@". Multiple
  // "@" is ambiguous -- the host cannot be determined reliably -- so fail CLOSED
  // (null -> uriMatch returns "unsupported" -> the caller rejects the path)
  // rather than guess a host that could slip a URI name constraint.
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
// (not comparable), or the string "unsupported" when the forms are the SAME
// but this validator does not implement that form's comparison -- the caller
// must then fail closed rather than treat it as "no match".
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
    // Preserve EVERY SAN entry, including a form whose value the validator does
    // not decode (x400Address [3] / ediPartyName [5]) -- dropping it would let a
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
  // an rfc822Name UNLESS the SAN already carries the email identity as an
  // rfc822Name entry. A SAN of a DIFFERENT form (e.g. dNSName only) does NOT
  // cover the email, so the subject-DN email must still be constrained -- else an
  // excluded/non-permitted mailbox would slip an rfc822Name constraint.
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
// a UNION (any match rejects). `permitted` is the INTERSECTION of every
// absorbing cert's permittedSubtrees (6.1.4(g)): the permitted set is tracked
// as one GENERATION per absorbing cert, and a name of form F must match a
// subtree of form F in EVERY generation that constrains form F. A flat pool
// would compute the UNION -- letting a subordinate CA BROADEN what its parent
// permitted (a name-constraint bypass).
function checkNameConstraints(state, cert) {
  var forms = certNameForms(cert);
  // Excluded: any match -> reject. A constraint of the same form the validator
  // cannot compare ("unsupported") means a critical exclusion it cannot
  // enforce -> fail closed rather than treat it as "no match".
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
// A deep copy of the valid-policy tree WITHOUT the internal `parent` back-pointer,
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
    case 4: return base !== null && typeof base === "object" && !!base.rdns && Array.isArray(base.rdns);   // directoryName
    default: return base !== undefined;
  }
}

// Entry-point validation of a 6.1.1(b,c) user-initial subtree seed. A
// mis-shaped entry (e.g. the { base: { tagNumber, value } } shape the
// nameConstraints decoder emits) would never match any name, silently
// disabling the constraint the caller configured -- so it throws instead.
function checkedSubtreeSeeds(list, optName) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw E("path/bad-input", "validate: opts." + optName + " must be an array of { tag, base } subtree entries");
  return list.map(function (st) {
    if (!st || typeof st !== "object" || !Number.isInteger(st.tag) || st.tag < 0 || st.tag > 8 || !isSubtreeBaseValid(st.tag, st.base)) {
      throw E("path/bad-input", "validate: opts." + optName + " entries must be { tag: <GeneralName tag number 0..8>, base: <that form's constraint value> }");
    }
    return { tag: st.tag, base: st.base };
  });
}

function initialize(certs, params, seeds) {
  var n = certs.length;
  return {
    validPolicyTree: rootNode(),
    policyNodeCount: 1,
    maxPolicyNodes: params.maxPolicyNodes !== undefined ? params.maxPolicyNodes : constants.LIMITS.PATH_MAX_POLICY_NODES,
    // Each absorbing cert's permittedSubtrees is one generation; a name must be
    // admitted by EVERY generation (intersection). An initial seed is generation 0.
    permittedGenerations: seeds.permitted.length ? [seeds.permitted] : [],
    excludedSubtrees: seeds.excluded,
    explicitPolicy: params.initialExplicitPolicy ? 0 : n + 1,
    inhibitAnyPolicy: params.initialAnyPolicyInhibit ? 0 : n + 1,
    policyMapping: params.initialPolicyMappingInhibit ? 0 : n + 1,
    workingPublicKeyAlgorithm: params.trustAnchor.algorithm,
    workingPublicKey: params.trustAnchor.publicKey,
    workingPublicKeyParameters: params.trustAnchor.parameters || null,
    workingIssuerName: params.trustAnchor.name,
    maxPathLength: n,
    userInitialPolicySet: params.userInitialPolicySet || [OID.anyPolicy],
    results: [],
  };
}

// self-issued = subject DN equals issuer DN. dnEqual throws on a NUL/control
// DN (CVE-2009-2408); a malformed-DN cert is never "self-issued" (and is failed
// by the name-chaining check), so swallow the throw rather than reject the
// whole validate() promise from these unwrapped call sites.
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
    // self-issued non-final cert -- this gates ONLY the (d)(2) expansion of a
    // cert-asserted anyPolicy. 4.2.1.14 inhibition is implemented entirely by
    // that gate: a depth-(i-1) anyPolicy node created while processing was
    // active remains matchable in (d)(1)(ii).
    var anyPolicyActive = state.inhibitAnyPolicy > 0 || (i < state._n && selfIssued(cert));
    var anyPolicyPresent = false;
    var anyPolicyQualifiers = null;
    policies.forEach(function (p) {
      if (p.policyIdentifier === OID.anyPolicy) { anyPolicyPresent = true; anyPolicyQualifiers = p.qualifiersBytes; return; }
      var matched = false;
      leavesAt(state.validPolicyTree, depth).forEach(function (node) {
        if (node.expectedPolicySet.indexOf(p.policyIdentifier) !== -1) {
          addChild(state, node, p.policyIdentifier, p.qualifiersBytes, [p.policyIdentifier], checks);
          matched = true;
        }
      });
      if (!matched) {
        // 6.1.3(d)(1)(ii): no expected-policy match -- create the node from a
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
          var already = node.children.some(function (ch) { return ch.validPolicy === ep; });
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
  // carries inherited ones, store a reconstructed SPKI so the next signature
  // verify can import a complete key rather than failing on the bare bytes.
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
// extKeyUsage a PROCESSED critical extension is sound -- the semantic gate runs
// wherever the extension appears, never only on the leaf. A cert with no EKU is
// unconstrained. Returns true if the cert FAILS the required-purpose check.
function ekuPurposeFails(cert, requiredEku, checks) {
  var eku;
  try { eku = decodeExt(cert, OID.extKeyUsage); }
  catch (e) { checks.push({ name: "extendedKeyUsage", ok: false, code: pathCode(e, "path/bad-extension-value") }); return true; }
  if (!eku) return false;   // absent EKU: unrestricted (4.2.1.12 restricts only when present)
  var purposes = eku.value;
  var ok = purposes.indexOf(OID.anyExtendedKeyUsage) !== -1 ||
    requiredEku.every(function (p) { return purposes.indexOf(p) !== -1; });
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
    var badAny = pm.value.some(function (m) { return m.issuerDomainPolicy === OID.anyPolicy || m.subjectDomainPolicy === OID.anyPolicy; });
    if (badAny) { checks.push({ name: "policyMappings", ok: false, code: "path/bad-policy" }); return { fatal: true, error: E("path/bad-policy", "policyMappings must not map to or from anyPolicy (RFC 5280 6.1.4(a))") }; }
    if (state.validPolicyTree) applyPolicyMappings(state, pm.value, i);
  }

  // (c) working issuer name; (d),(e),(f) working key + algorithm + parameters.
  state.workingIssuerName = cert.subject;
  updateWorkingKey(state, cert);

  // (g) name constraints absorb (AFTER this cert's own names were checked).
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

  // (k) basicConstraints cA gate -- the single authoritative CA check.
  var bc;
  try { bc = decodeExt(cert, OID.basicConstraints); }
  catch (e) { checks.push({ name: "basicConstraints", ok: false, code: "path/bad-basic-constraints" }); return { fatal: true, error: e }; }
  if (!bc || bc.value.cA !== true) {
    checks.push({ name: "basicConstraints", ok: false, code: "path/not-a-ca" });
    return { fatal: true, error: E("path/not-a-ca", "intermediate certificate is not a CA (basicConstraints cA is not TRUE, RFC 5280 6.1.4(k))") };
  }
  // 4.2.1.9: a CA certificate used to validate certificate signatures MUST mark
  // basicConstraints critical. A non-critical cA:TRUE is non-conforming -- a
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
    // subjectDomainPolicy values mapped from that ID-P (not append -- retaining
    // the pre-mapping policy would let a later cert satisfy the chain by
    // asserting the mapped-away policy).
    var mappedFrom = {};   // issuerDomainPolicy -> [subjectDomainPolicy, ...]
    mappings.forEach(function (m) { (mappedFrom[m.issuerDomainPolicy] = mappedFrom[m.issuerDomainPolicy] || []).push(m.subjectDomainPolicy); });
    var depthI = leavesAt(state.validPolicyTree, depth);
    var anyNodes = depthI.filter(function (nd) { return nd.validPolicy === OID.anyPolicy; });
    Object.keys(mappedFrom).forEach(function (idp) {
      var idpNodes = depthI.filter(function (nd) { return nd.validPolicy === idp; });
      if (idpNodes.length) {
        idpNodes.forEach(function (nd) { nd.expectedPolicySet = mappedFrom[idp].slice(); });
      } else {
        // 6.1.4(b)(1): no depth-i ID-P node, but a depth-i anyPolicy node -- GENERATE
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
    // extension may have already emptied the tree -- stop if it is gone.
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

// policyMappings is semantically processed ONLY in the prepare-for-next step
// (sec. 6.1.4(a),(b)), which does not run for the target certificate. It is also
// SHOULD-be-non-critical (sec. 4.2.1.5), so a CRITICAL policyMappings on the target
// is both anomalous and unprocessed -- it must fail closed (sec. 6.1.5(f)) rather
// than let, e.g., a mapping to/from anyPolicy slip past the sec. 6.1.4(a) rejection
// the intermediate path applies. (nameConstraints / inhibitAnyPolicy are also
// prepare-next-only but are MUST-be-critical CA extensions, so a critical one on
// a terminal CA cert is conforming and is NOT treated as unprocessed here.)
var TARGET_UNPROCESSED_IF_CRITICAL = {};
TARGET_UNPROCESSED_IF_CRITICAL[OID.policyMappings] = true;

function unrecognizedCriticalExtension(cert, isTarget) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (!ext.critical) continue;
    if (!PROCESSED_EXTENSIONS[ext.oid]) return ext.oid;
    if (isTarget && TARGET_UNPROCESSED_IF_CRITICAL[ext.oid]) return ext.oid;
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
 * @status     experimental
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
 * optional `requiredEku` (key purposes -- registered OID names or dotted OID
 * strings -- the target's extendedKeyUsage must assert; an absent extension
 * is unrestricted, RFC 5280 4.2.1.12), and an optional `revocationChecker`.
 * The value-carrying options (`time`, `maxPathCerts`, `maxPolicyNodes`, the
 * subtree seeds, `userInitialPolicySet`, `requiredEku`) are validated at the
 * entry point -- a mis-shaped value throws `path/bad-input` rather than
 * silently not applying. Returns `{ valid, path,
 * results, workingPublicKey, workingPublicKeyAlgorithm,
 * workingPublicKeyParameters, validPolicyTree }` where `results[i].checks`
 * carries a per-check reason code (`path/*`) for every step. Pure and
 * re-entrant -- no input object is mutated. An empty path or a missing anchor
 * throws a typed `PathError`.
 *
 * @example
 *   var cert = pki.schema.x509.parse(der);
 *   var res = await pki.path.validate([cert], {
 *     time: new Date("2020-01-01T00:00:00Z"),
 *     trustAnchor: { name: cert.issuer, publicKey: cert.subjectPublicKeyInfo.bytes, algorithm: cert.signatureAlgorithm.oid },
 *   });
 *   res.valid;  // boolean; res.results[0].checks carries the per-check codes
 */
async function validate(path, opts) {
  opts = opts || {};
  if (!Array.isArray(path)) throw E("path/bad-input", "validate: path must be an array of certificates");
  // Bound the per-cert asymmetric-verify work BEFORE parsing an untrusted bundle
  // (the policy-tree cap guards CVE-2023-0464-style blow-up; this guards linear
  // crypto amplification from an oversized path). Entry-point tier: throw.
  var maxCerts = guard.limits.cap(opts.maxPathCerts, "validate: opts.maxPathCerts", constants.LIMITS.PATH_MAX_CERTS, { E: E, code: "path/bad-input", min: 1 });
  if (path.length > maxCerts) throw E("path/bad-input", "validate: the certification path has " + path.length + " certificates, exceeding the maxPathCerts limit (" + maxCerts + ")");
  var certs = path.map(function (c) { return (c && c.tbsBytes) ? c : x509.parse(c); });
  var n = certs.length;
  if (n < 1) throw E("path/empty-path", "validate: the certification path is empty");
  if (!opts.trustAnchor) throw E("path/bad-input", "validate: a trustAnchor is required");
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
    var uipsOk = Array.isArray(opts.userInitialPolicySet) && opts.userInitialPolicySet.length > 0 &&
      opts.userInitialPolicySet.every(function (p) { return typeof p === "string" && p.length > 0; });
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
  var requiredEku = null;
  if (opts.requiredEku !== undefined) {
    if (!Array.isArray(opts.requiredEku) || opts.requiredEku.length === 0) {
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
  // opts.checkPurpose -- the single key purpose the ANCHOR's NSS trust metadata
  // (distrustAfter / purposes) is consulted for. Independent of requiredEku
  // (which gates the leaf's own EKU extension): this selects the per-purpose
  // key in the trust-anchor constraint contract. A purpose OID name (or a
  // canonical dotted OID normalized to its name); a bad value throws here.
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

  var state = initialize(certs, opts, seeds);
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
    var t = opts.time;
    var vOk = true, vCode;
    if (t < cert.validity.notBefore) { vOk = false; vCode = "path/not-yet-valid"; }
    else if (t > cert.validity.notAfter) { vOk = false; vCode = "path/expired"; }
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
      var rv;
      try { rv = await revocationChecker.check(cert, { workingIssuerName: state.workingIssuerName, workingPublicKey: state.workingPublicKey, workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm, issuerCert: issuerCert }, { time: opts.time, historicalMode: opts.historicalMode === true }); }
      catch (_e) { rv = { status: "unknown" }; }
      // ONLY an explicit "good" is a determined non-revocation; "revoked" fails;
      // every other value ("unknown", an OCSP tryLater/unauthorized, a typo, a
      // missing status) is undetermined and fails closed unless softFail.
      if (rv && rv.status === "good") { checks.push({ name: "revocation", ok: true }); }
      else if (rv && rv.status === "revoked") { checks.push({ name: "revocation", ok: false, code: "path/revoked" }); failed = true; }
      else if (softFail) { checks.push({ name: "revocation", ok: true }); }
      else { checks.push({ name: "revocation", ok: false, code: "path/revocation-undetermined" }); failed = true; }
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
      if (lpm && lpm.value.some(function (m) { return m.issuerDomainPolicy === OID.anyPolicy || m.subjectDomainPolicy === OID.anyPolicy; })) {
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
      var ta = opts.trustAnchor;
      // A PRESENT-but-malformed distrustAfter (an Invalid Date: instanceof Date yet a
      // NaN time) would make `notBefore > it` NaN-false and SILENTLY drop the distrust
      // restriction -- the NaN-Date fail-open. Validate a present date fail-closed
      // before the comparison; an absent (undefined/null) date is no restriction.
      var distrustDate = (checkPurpose && ta.distrustAfter) ? ta.distrustAfter[checkPurpose] : null;
      if (distrustDate != null) {
        distrustDate = guard.time.assertValid(distrustDate, E, "path/bad-input", "trustAnchor.distrustAfter." + checkPurpose);
        // STRICTLY > : a leaf whose notBefore == the distrust date stays trusted
        // (Mozilla certverifier isDistrustedCertificateChain: endEntityNotBefore
        // <= distrustAfterTime -> not distrusted; the end-of-day ...235959Z
        // convention keeps the whole boundary day trusted).
        if (cert.validity.notBefore > distrustDate) {
          checks.push({ name: "distrustAfter", ok: false, code: "path/distrusted-after" }); failed = true;
        }
      }
      if (checkPurpose && ta.purposes && ta.purposes[checkPurpose] !== true) {
        checks.push({ name: "purposeTrust", ok: false, code: "path/purpose-not-trusted" }); failed = true;
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
    if (!last.checks.some(function (c) { return c.code === "path/policy-required"; })) {
      last.checks.push({ name: "policy", ok: false, code: "path/policy-required" });
    }
    failed = true;
  }

  return {
    valid: !failed,
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
  var anyUser = uips.indexOf(OID.anyPolicy) !== -1;
  var leaves = leavesAt(state.validPolicyTree, n);
  var explicit = {}, hasAnyLeaf = false;
  leaves.forEach(function (node) {
    if (node.validPolicy === OID.anyPolicy) hasAnyLeaf = true;
    else explicit[node.validPolicy] = true;
  });
  var set = {};
  Object.keys(explicit).forEach(function (p) { if (anyUser || uips.indexOf(p) !== -1) set[p] = true; });
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

// IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0] OPTIONAL,
// onlyContainsUserCerts [1] DEFAULT FALSE, onlyContainsCACerts [2] DEFAULT FALSE,
// onlySomeReasons [3] ReasonFlags OPTIONAL, indirectCRL [4] DEFAULT FALSE,
// onlyContainsAttributeCerts [5] DEFAULT FALSE } (RFC 5280 sec. 5.2.5). Declared
// through the engine so the trailing-field grammar (strictly-ascending tags, each
// at most once) and the DER BOOLEAN value rules are the shared enforcement, not a
// hand-walk; a present DEFAULT-FALSE flag encoding FALSE is the omitted default
// (X.690 sec. 11.5) and rejects at the leaf-value level below.
var IDP_SCHEMA = schema.seq([
  schema.trailing([
    { tag: 0, name: "distributionPoint", schema: schema.any() },
    { tag: 1, name: "onlyContainsUserCerts", schema: schema.implicitBoolean(1) },
    { tag: 2, name: "onlyContainsCACerts", schema: schema.implicitBoolean(2) },
    { tag: 3, name: "onlySomeReasons", schema: schema.implicitBitString(3) },
    { tag: 4, name: "indirectCRL", schema: schema.implicitBoolean(4) },
    { tag: 5, name: "onlyContainsAttributeCerts", schema: schema.implicitBoolean(5) },
  ], { minTag: 0, maxTag: 5, unexpectedCode: "path/bad-idp", orderCode: "path/bad-idp" }),
], { assert: "sequence", code: "path/bad-idp", what: "IssuingDistributionPoint" });

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
  out.indirect = flag(m.fields.indirectCRL);
  out.onlyAttr = flag(m.fields.onlyContainsAttributeCerts);
  return out;
}

// RFC 5280 sec. 6.3.3(b)(2)(i): find the certificate DistributionPoint that
// CORRESPONDS to a shard CRL's IDP distribution point name -- at least one
// name in common between the two DistributionPointNames, compared by
// BYTE-IDENTICAL DER encoding (Buffer.equals on the raw GeneralName / RDN
// TLVs). sec. 5.2.5 pins the comparison key: "The identical encoding MUST be
// used in the distributionPoint fields of the certificate and the CRL" -- so
// a canonicalized or semantic comparison (which would equate two
// differently-encoded names) is forbidden, and whole-set equality (which
// would falsely reject a legitimate multi-URI DP sharing one name) is
// over-strict. Mixed forms -- fullName on one side, nameRelativeToCRLIssuer
// on the other -- never correspond here: resolving an RDN fragment against
// the issuer DN is not attempted (fail closed). Per sec. 6.3.3(b)(1), a DP
// naming a cRLIssuer participates only when that cRLIssuer is the certificate
// issuer itself: the checker only consults CRLs issued BY the certificate
// issuer and rejects indirect CRLs, so a DP delegated to another CRL issuer
// is out of play. Returns the matched DP (its `reasons` feeds the coarse
// reason-mask rule) or null.
function correspondingCertDp(idpDpn, certDPs, issuerRdns) {
  if (!idpDpn || !certDPs) return null;
  for (var i = 0; i < certDPs.length; i++) {
    var dp = certDPs[i];
    if (!dp.distributionPoint) continue;
    if (dp.cRLIssuer && !crlIssuerNamesIssuer(dp.cRLIssuer, issuerRdns)) continue;
    var cdpn = dp.distributionPoint;
    if (idpDpn.kind === "fullName" && cdpn.kind === "fullName") {
      for (var a = 0; a < idpDpn.names.length; a++) {
        for (var c = 0; c < cdpn.names.length; c++) {
          if (idpDpn.names[a].equals(cdpn.names[c])) return dp;
        }
      }
    } else if (idpDpn.kind === "rdn" && cdpn.kind === "rdn") {
      if (idpDpn.bytes.equals(cdpn.bytes)) return dp;
    }
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

/**
 * @primitive  pki.path.crlChecker
 * @signature  pki.path.crlChecker(crls) -> RevocationChecker
 * @since      0.1.16
 * @status     experimental
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
 * name in common (RFC 5280 sec. 6.3.3) -- and neither side restricts reason
 * codes; a non-corresponding or reason-restricted shard is consulted for
 * revocation only. An out-of-scope, stale, unauthorized, or unverifiable CRL
 * yields `unknown`, which the validator fails closed unless `softFail` is set.
 *
 * @example
 *   var checker = pki.path.crlChecker([]);   // no CRLs -> every cert is "unknown"
 *   typeof checker.check;                     // "function"
 */
function crlChecker(crls) {
  var parsed = (crls || []).map(function (c) { return (c && c.tbsBytes) ? c : crl.parse(c); });
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
      // shadow a revoking one (RFC 5280 6.3.3). A serial listed in ANY
      // authoritative, in-scope, current, verified CRL is revoked; the cert is
      // "good" only if at least one such CRL was consulted and none list it;
      // otherwise the status is undetermined.
      var sawAuthoritative = false;
      var sawDelta = false;
      var sawDeltaRemoval = false;   // a delta released this serial from hold
      var revokedResult = null;      // a base/full CRL revocation, decided at the end
      for (var k = 0; k < parsed.length; k++) {
        var theCrl = parsed[k];
        // dnEqual throws on a DN carrying an embedded NUL/control byte (CVE-2009-2408).
        // A single malformed CRL in the bundle must NOT abort the whole check (which
        // would mask a later authoritative CRL and pass under softFail) -- treat it
        // as unusable and skip it, consulting the remaining CRLs.
        var issuerMatches;
        try { issuerMatches = dnEqual(theCrl.issuer.rdns, cert.issuer.rdns); }
        catch (_e) { continue; }
        if (!issuerMatches) continue;
        if (!signerAuthorized) continue;

        // A CRL carrying deltaCRLIndicator is a DELTA CRL: it lists only the
        // CHANGES since a base CRL (RFC 5280 sec. 5.2.4). deltaCRLIndicator is a
        // RECOGNIZED extension (so a critical one is not "unhandled"); the delta
        // is acted on only AFTER it passes the currency + signature checks below,
        // so a stale, malformed, or unverifiable delta cannot spuriously block a
        // good result. An AUTHORITATIVE delta blocks "good" (its base is not
        // merged here) and can still reveal a revocation for a serial it lists.
        var isDelta = false;
        for (var dz = 0; dz < theCrl.crlExtensions.length; dz++) {
          if (theCrl.crlExtensions[dz].oid === OID_DELTA_CRL) { isDelta = true; break; }
        }

        // A validly-signed CRL carrying a CRITICAL extension this checker does
        // not understand (anything but issuingDistributionPoint / deltaCRLIndicator)
        // may change the CRL's scope or meaning -- treat it as unusable (RFC 5280
        // 5.2 critical-extension semantics), never authoritative.
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
        if (unhandledCritical) continue;

        // A partition-scoped CRL (a specific distributionPoint, or reason-sharded
        // via onlySomeReasons) covers only part of the issuer's revocations, so it
        // cannot by itself establish "good" (full coverage is unconfirmed). But a
        // serial it LISTS is a genuine revocation of this certificate (serials are
        // unique per issuer), so such a CRL must still be consulted for revocation
        // -- dropping it wholesale would let a revoked cert slip under softFail.
        var scopeRevocationOnly = false;
        var idpExt = null;
        for (var e = 0; e < theCrl.crlExtensions.length; e++) if (theCrl.crlExtensions[e].oid === OID_IDP) idpExt = theCrl.crlExtensions[e];
        if (idpExt) {
          var idp = decodeIdp(idpExt);
          if (idp.malformed) continue;                       // scope unknown -> unusable
          // An indirect CRL carries entries for other issuers keyed by the
          // per-entry certificateIssuer attribute (not tracked here) -- matching
          // by serial alone could revoke the wrong cert or falsely cover it, so
          // treat an indirect CRL as unusable until certificateIssuer is honored.
          if (idp.indirect) continue;
          if (idp.onlyAttr) continue;                        // scoped to attribute certs, not this public-key cert
          if (idp.onlyCa && certIsCa !== true) continue;     // out of scope (or CA-ness undeterminable)
          if (idp.onlyUser && certIsCa !== false) continue;
          if (idp.hasDistributionPoint) {
            // RFC 5280 sec. 6.3.3(b)(2)(i): a partition shard speaks for this
            // certificate only when the IDP's distribution point shares at
            // least one IDENTICALLY-ENCODED name with one of the certificate's
            // own DistributionPoints (sec. 5.2.5: "The identical encoding MUST
            // be used in the distributionPoint fields of the certificate and
            // the CRL"). The IDP must also be CRITICAL to be relied on for
            // scope: sec. 5.2.5 defines the IDP as "a critical CRL extension"
            // (descriptive phrasing, not an imperative MUST), and a partition
            // scope a non-supporting relying party would ignore is not a scope
            // to build "good" on -- a deliberate fail-closed decision. A
            // non-corresponding shard cannot establish "good" but is still
            // consulted for revocation below: serials are unique per issuer,
            // so a listed serial is a genuine revocation (fail closed toward
            // revoked).
            var matchedDp = idpExt.critical === true
              ? correspondingCertDp(idp.distributionPoint, certDPs, cert.issuer.rdns)
              : null;
            if (!matchedDp) scopeRevocationOnly = true;
            // sec. 6.3.3(d)(3): a matched DP carrying `reasons` bounds the
            // interim reason mask below all-reasons -- under the coarse rule
            // ("good" only at the (d)(4) all-reasons case) that shard is
            // revocation-only.
            else if (matchedDp.reasons) scopeRevocationOnly = true;
          }
          // sec. 6.3.3(d)(1)/(d)(2): any onlySomeReasons restriction keeps the
          // interim reason mask below all-reasons -- revocation-only (coarse).
          if (idp.onlySomeReasons) scopeRevocationOnly = true;
        }
        if (theCrl.thisUpdate > time) continue;              // not yet valid
        // A CRL with no nextUpdate has no bounded validity -- its currency
        // cannot be confirmed (RFC 5280 sec. 5.1.2.5 requires nextUpdate), so a
        // replayed old CRL must not read "good". Treat it as unusable.
        if (!theCrl.nextUpdate || theCrl.nextUpdate < time) continue;   // stale / no bound

        var sigOk = await verifyCrlSignature(theCrl, issuer);
        if (!sigOk) continue;                                // unverifiable -> not authoritative

        // The CRL is now authoritative + current + verified. An authoritative
        // delta blocks a "good" result (its base is not merged here) and can only
        // reveal a revocation -- never establish "good" on its own.
        if (isDelta) { sawDelta = true; scopeRevocationOnly = true; }

        for (var r = 0; r < theCrl.revokedCertificates.length; r++) {
          var entry = theCrl.revokedCertificates[r];
          if (entry.serialNumberHex !== cert.serialNumberHex) continue;
          // reasonCode removeFromCRL (8) means the entry was un-revoked. In a
          // DELTA this releases the serial from hold; because the base is not
          // merged here, a definitive "revoked" is no longer possible for it -- a
          // base CRL that still lists it must not override the delta removal.
          if (crlEntryReason(entry) === 8) { if (isDelta) sawDeltaRemoval = true; continue; }
          // A revocation is effective as of its revocationDate (RFC 5280 sec. 5.3).
          // In the DEFAULT present-time validation a listed serial is revoked
          // regardless of that date -- a future revocationDate is post-dating or
          // clock skew and must NOT read good. Only under an EXPLICIT historical
          // validation (opts.historicalMode) -- validating as of a past instant,
          // e.g. a timestamped signature -- does an entry dated AFTER the
          // validation time not yet apply.
          // allow:nan-date-comparison-unguarded -- revocationDate is codec-parsed (NaN-rejected); a NaN check time makes this FAIL CLOSED (the skip is not taken -> the entry is treated as revoked), and `time` is validated at the path.validate / crlChecker entry points.
          if (historical && entry.revocationDate instanceof Date && entry.revocationDate.getTime() > time.getTime()) continue;
          // Record the revocation but keep scanning: a delta removeFromCRL for the
          // same serial (in another CRL) overrides it (base/delta not merged).
          revokedResult = { status: "revoked", reason: "serial listed in a CRL" };
          break;
        }
        // A partition-scoped CRL that did not list this serial does NOT prove the
        // cert is unrevoked (another shard/reason may revoke it) -- only a
        // full-scope CRL can establish "good".
        if (!scopeRevocationOnly) sawAuthoritative = true;   // covered this cert, not listed
      }
      // A delta released this serial from hold: without merging its base we cannot
      // return a definitive revoked (else a released cert stays rejected) -- the
      // status is undetermined. This outranks a base CRL's revocation.
      if (sawDeltaRemoval) return { status: "unknown", reason: "a delta CRL released this serial from hold; without merging its base CRL the revocation status is undetermined" };
      if (revokedResult) return revokedResult;
      // A delta CRL for this issuer was seen but cannot be merged with its base,
      // so the current revocation picture is incomplete -- never report "good".
      if (sawDelta) return { status: "unknown", reason: "a delta CRL cannot be evaluated without combining it with its base CRL, so the revocation status is undetermined" };
      if (sawAuthoritative) return { status: "good" };
      if (certScopeFault) {
        return { status: "unknown", reason: "no authoritative in-scope CRL covers this certificate; its basicConstraints extension is unreadable (" + certScopeFault + "), so scope-limited CRLs were skipped" };
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

function verifyCrlSignature(theCrl, issuer) {
  if (!guard.crypto.isOctetAligned(theCrl.signatureValue)) return Promise.resolve(false);   // non-octet-aligned signature
  return _verifyWithSpki(theCrl.signatureAlgorithm, theCrl.signatureValue.bytes, issuer.workingPublicKey, theCrl.tbsBytes);
}

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

/**
 * @primitive  pki.path.ocspChecker
 * @signature  pki.path.ocspChecker(responses) -> RevocationChecker
 * @since      0.1.32
 * @status     experimental
 * @spec       RFC 6960
 * @related    pki.path.validate, pki.schema.ocsp.parseResponse, pki.path.crlChecker
 *
 * Build an OCSP-backed `RevocationChecker` for `pki.path.validate`'s
 * `revocationChecker` option from a set of pre-fetched OCSP responses (DER/PEM
 * or already-parsed). For each certificate it locates a SingleResponse whose
 * CertID binds this cert's serial to its issuer -- recomputing `issuerNameHash`
 * and `issuerKeyHash` under the CertID's own hashAlgorithm (SHA-1 or SHA-2), so
 * a response using either matches -- confirms the responder is authorized (the
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
  var parsed = (responses || []).map(function (r) { return (r && r.responseStatus) ? r : ocsp.parseResponse(r); });
  return {
    check: async function (cert, issuer, ctx) {
      var time = ctx.time;
      var historical = ctx.historicalMode === true;
      // Issuer DN candidates to match the CertID against (RFC 6960 sec. 4.1.1 names
      // the checked cert's issuer field; a response MAY instead carry the issuer
      // certificate's own subject encoding -- sec. 7.1-equal but not byte-identical).
      var issuerNameCandidates = [cert.issuer.bytes];
      function addNameCandidate(nm) {
        if (nm && nm.bytes && !issuerNameCandidates.some(function (e) { return e.equals(nm.bytes); })) issuerNameCandidates.push(nm.bytes);
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
 * @signature  pki.path.verifyOcspResponse(parsedResponse, cert, issuerCert, time, opts?) -> Promise<{ status, responderAuthorized, signatureValid, matched, thisUpdate, nextUpdate, revocationReason?, reason }>
 * @since       0.2.22
 * @status      experimental
 * @spec        RFC 6960
 * @related     pki.ocsp.verify, pki.path.ocspChecker
 *
 * Verify a single already-parsed OCSP response for one certificate against its
 * already-parsed issuer certificate at `time` -- the lower-level primitive
 * `pki.ocsp.verify` composes after parsing its inputs (most callers want that
 * ergonomic entry, which also handles DER/PEM decoding and request-nonce
 * matching). It runs the EXACT SAME gates the path validator's `ocspChecker`
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
 * @example
 *   var resp = pki.schema.ocsp.parseResponse(der);
 *   var v = await pki.path.verifyOcspResponse(resp, cert, issuerCert, new Date());
 *   v.status;   // "good" | "revoked" | "unknown"
 */
function verifyOcspResponse(parsedResponse, cert, issuerCert, time, opts) {
  opts = opts || {};
  // The currency + responder-cert validity windows compare against `time`; a missing or invalid
  // check date must fail closed (a NaN compares false against every bound), never silently pass.
  if (!(time instanceof Date) || isNaN(time.getTime())) {
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
    function add(nm) { if (nm && nm.bytes && !issuerNameCandidates.some(function (e) { return e.equals(nm.bytes); })) issuerNameCandidates.push(nm.bytes); }
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

module.exports = {
  validate: validate,
  crlChecker: crlChecker,
  ocspChecker: ocspChecker,
  verifyOcspResponse: verifyOcspResponse,
  // The set of extension OIDs whose CRITICAL semantics this validator processes (RFC 5280 sec. 6.1).
  // Exposed so a linter can distinguish "processed" from "merely decoded" and stay consistent with
  // the path-validation verdict on a critical extension -- a decoder in certExtensionDecoders is NOT
  // by itself proof the criticality is honoured.
  PROCESSED_EXTENSIONS: PROCESSED_EXTENSIONS,
};
