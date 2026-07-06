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
 * 6.1 state machine — signature chaining, validity windows, name chaining,
 * basic constraints and path length, key usage, name constraints, and the
 * certificate-policy tree — and returns a structured verdict with a per-check
 * reason code for every step. Validity-window enforcement is always on, with
 * the check date an explicit input; the trust anchor is an input, never one of
 * the validated certificates, and no input object is mutated.
 *
 * Revocation is a pluggable hook: `pki.path.crlChecker(crls)` ships a CRL
 * consultation built on `pki.schema.crl.parse`; an OCSP checker satisfies the
 * same interface. Signature verification derives its algorithm from the
 * certificate and the issuer key — never from a value the message controls —
 * and fails closed on an unknown critical extension, an undetermined
 * revocation status, or any structural fault.
 *
 * @card
 *   RFC 5280 6 certification-path validation — run the 6.1 state machine over
 *   an ordered path and a trust anchor for a structured, fail-closed verdict
 *   with per-check reason codes. Pure and re-entrant.
 */

var webcrypto = require("./webcrypto");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var errors = require("./framework-error");
var asn1 = require("./asn1-der");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");

var PathError = errors.PathError;
function E(code, message, cause) { return new PathError(code, message, cause); }

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
};

// The set of extension OIDs the validator PROCESSES — an unrecognized critical
// extension outside this set fails the path (6.1.4(o), 6.1.5(e)).
var PROCESSED_EXTENSIONS = {};
[OID.basicConstraints, OID.keyUsage, OID.nameConstraints, OID.certificatePolicies,
 OID.policyMappings, OID.policyConstraints, OID.inhibitAnyPolicy, OID.subjectAltName].
  forEach(function (o) { PROCESSED_EXTENSIONS[o] = true; });

// ---- signature verify bridge (NEW 6) ---------------------------------------

// Signature-algorithm OID -> the WebCrypto verify descriptor + how to import
// the issuer SPKI. Keyed via oid.byName so no dotted-decimal OID literal
// appears in source (the registry owns arc↔name). The algorithm is a property
// of the CERTIFICATE and the issuer key, never of a message-selected field
// (CVE-2015-9235).
var SIG_ALGS = {};
// `params` is the REQUIRED AlgorithmIdentifier parameters shape: "null" (a DER
// NULL must be present — RSASSA-PKCS1-v1_5, RFC 4055 §5) or "absent" (parameters
// must be omitted — ECDSA/EdDSA/ML-DSA, RFC 5758/8410). A cert deviating from
// its algorithm's required shape is malformed and rejected before verify.
function _sig(name, verify, imp, params, ecdsa) {
  var entry = { verify: verify, imp: imp, params: params };
  if (ecdsa) entry.ecdsa = true;
  SIG_ALGS[oid.byName(name)] = entry;
}
// RSASSA-PKCS1-v1_5 — parameters MUST be NULL.
_sig("sha256WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, "null");
_sig("sha384WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, "null");
_sig("sha512WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, "null");
// ECDSA (hash in the OID; the curve comes from the imported key) — params absent.
_sig("ecdsaWithSHA256", { name: "ECDSA", hash: "SHA-256" }, { name: "ECDSA" }, "absent", true);
_sig("ecdsaWithSHA384", { name: "ECDSA", hash: "SHA-384" }, { name: "ECDSA" }, "absent", true);
_sig("ecdsaWithSHA512", { name: "ECDSA", hash: "SHA-512" }, { name: "ECDSA" }, "absent", true);
// EdDSA (one-shot, no hash parameter) — params absent.
_sig("Ed25519", { name: "Ed25519" }, { name: "Ed25519" }, "absent");
_sig("Ed448", { name: "Ed448" }, { name: "Ed448" }, "absent");
// ML-DSA (FIPS 204) — params absent.
_sig("id-ml-dsa-44", { name: "ML-DSA-44" }, { name: "ML-DSA-44" }, "absent");
_sig("id-ml-dsa-65", { name: "ML-DSA-65" }, { name: "ML-DSA-65" }, "absent");
_sig("id-ml-dsa-87", { name: "ML-DSA-87" }, { name: "ML-DSA-87" }, "absent");

// RSASSA-PSS resolves its hash + salt from the AlgorithmIdentifier parameters.
var OID_RSA_PSS = oid.byName("rsassaPss");
var OID_MGF1 = oid.byName("mgf1");
// SHA-1 is deliberately ABSENT — a SHA-1 signature (PKCS#1 or PSS) is rejected,
// matching the no-sha1WithRSAEncryption posture (SHAttered chosen-prefix).
var HASH_BY_OID = {};
HASH_BY_OID[oid.byName("sha256")] = "SHA-256";
HASH_BY_OID[oid.byName("sha384")] = "SHA-384";
HASH_BY_OID[oid.byName("sha512")] = "SHA-512";

var CURVE_FIELD_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 };
// Curve group orders n — a valid ECDSA signature has r,s in [1, n-1].
var CURVE_ORDER = {
  "P-256": BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  "P-384": BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
  "P-521": BigInt("0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
};

// The algorithm OID of an AlgorithmIdentifier SEQUENCE { algorithm OID, params }.
// STRICT: the node must be a universal SEQUENCE whose first child is the OID —
// a bare [n]-wrapped OID (no AlgorithmIdentifier SEQUENCE) is malformed.
function seqAlgOid(seq) {
  if (!seq || seq.tagClass !== "universal" || seq.tagNumber !== asn1.TAGS.SEQUENCE || !seq.children || !seq.children.length) {
    throw E("path/unsupported-algorithm", "expected an AlgorithmIdentifier SEQUENCE");
  }
  return asn1.read.oid(seq.children[0]);
}
// The algorithm OID inside an EXPLICIT [n] wrapper around an AlgorithmIdentifier.
function explicitAlgOid(wrapper) {
  if (!wrapper.children || wrapper.children.length !== 1) throw E("path/unsupported-algorithm", "malformed EXPLICIT AlgorithmIdentifier");
  return seqAlgOid(wrapper.children[0]);
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
  // and must be REJECTED — a supported PSS AlgorithmIdentifier must state both
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
    // Every RSASSA-PSS-params field is an EXPLICIT [n] wrapper (constructed); a
    // primitive/childless context field is malformed — fail closed.
    if (!f.children || !f.children.length) throw E("path/unsupported-algorithm", "malformed RSASSA-PSS parameter field [" + f.tagNumber + "]");
    if (f.tagNumber === 0) {
      var h = explicitAlgOid(f);
      if (!HASH_BY_OID[h]) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS hash algorithm " + h);
      hash = HASH_BY_OID[h];
    } else if (f.tagNumber === 1) {
      mgfNode = f.children[0];   // MaskGenAlgorithm SEQUENCE { mgf1, HashAlgorithm }
    } else if (f.tagNumber === 2) {
      var sl = asn1.read.integer(f.children[0]);
      // A negative saltLength must be rejected: the OpenSSL-backed verify shim
      // reads -1/-2/-3 as RSA_PSS_SALTLEN_DIGEST/AUTO/MAX, and AUTO (-2) accepts
      // a signature of ANY salt length — defeating the salt-length binding.
      if (sl < 0n) throw E("path/unsupported-algorithm", "RSASSA-PSS saltLength must be non-negative");
      saltLength = Number(sl);
    } else if (f.tagNumber === 3) {
      trailer = Number(asn1.read.integer(f.children[0]));
    }
  });
  if (hash === null) throw E("path/unsupported-algorithm", "RSASSA-PSS hashAlgorithm must be stated explicitly (the SHA-1 default is rejected)");
  if (!mgfNode) throw E("path/unsupported-algorithm", "RSASSA-PSS maskGenAlgorithm must be stated explicitly (the mgf1SHA1 default is rejected)");
  var mgfOid = seqAlgOid(mgfNode);
  if (mgfOid !== OID_MGF1) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS mask-generation function " + mgfOid);
  if (!mgfNode.children[1]) throw E("path/unsupported-algorithm", "RSASSA-PSS MGF1 requires an explicit hash parameter");
  var mgfHashOid = seqAlgOid(mgfNode.children[1]);
  if (HASH_BY_OID[mgfHashOid] !== hash) throw E("path/unsupported-algorithm", "RSASSA-PSS MGF1 hash must match the signature hash (RFC 4055)");
  if (trailer !== 1) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS trailerField " + trailer);
  return { verify: { name: "RSA-PSS", saltLength: saltLength }, imp: { name: "RSA-PSS", hash: hash } };
}

// A DER NULL parameters field is the 2-byte 05 00.
function isDerNull(p) { return p && p.length === 2 && p[0] === 0x05 && p[1] === 0x00; }

function resolveDescriptor(sigAlg) {
  if (sigAlg.oid === OID_RSA_PSS) return resolveRsaPss(sigAlg.parameters);
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

// DER Ecdsa-Sig-Value SEQUENCE { r, s } -> fixed-width r||s (P1363), rejecting
// r or s outside [1, n-1] (CVE-2022-21449 "Psychic Signatures").
function ecdsaDerToP1363(der, curve) {
  var width = CURVE_FIELD_BYTES[curve];
  var order = CURVE_ORDER[curve];
  if (!width || !order) throw E("path/bad-signature", "unsupported ECDSA curve " + curve);
  var n;
  try { n = asn1.decode(der); }
  catch (e) { throw E("path/bad-signature", "ECDSA signature is not a DER SEQUENCE(r,s)", e); }
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children || n.children.length !== 2) {
    throw E("path/bad-signature", "ECDSA signature must be a SEQUENCE of exactly two INTEGERs");
  }
  var r = asn1.read.integer(n.children[0]);
  var s = asn1.read.integer(n.children[1]);
  if (r < 1n || s < 1n || r >= order || s >= order) {
    throw E("path/bad-signature", "ECDSA signature component out of range [1, n-1] (CVE-2022-21449)");
  }
  function pad(v) {
    var hex = v.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    var buf = Buffer.from(hex, "hex");
    if (buf.length > width) throw E("path/bad-signature", "ECDSA signature component wider than the curve field");
    var out = Buffer.alloc(width);
    buf.copy(out, width - buf.length);
    return out;
  }
  return Buffer.concat([pad(r), pad(s)]);
}

// Verify cert.signatureValue over cert.tbsBytes with the working public key.
function builtinVerify(state, cert) {
  var d;
  try { d = resolveDescriptor(cert.signatureAlgorithm); }
  catch (e) { return Promise.resolve({ ok: false, code: e.code || "path/unsupported-algorithm", error: e }); }
  // The signature is an octet-aligned BIT STRING (no unused bits) for every
  // supported algorithm; a non-zero unused-bit count is malformed.
  if (cert.signatureValue.unusedBits !== 0) return Promise.resolve({ ok: false, code: "path/bad-signature" });
  var key;
  return subtle.importKey("spki", state.workingPublicKey, d.imp, false, ["verify"]).then(function (k) {
    key = k;
    var sig = cert.signatureValue.bytes;
    if (d.ecdsa) sig = ecdsaDerToP1363(sig, key.algorithm.namedCurve);
    return subtle.verify(d.verify, key, sig, cert.tbsBytes);
  }).then(function (ok) {
    return { ok: ok === true };
  }, function (e) {
    // A raw OpenSSL / WebCrypto fault (wrong key type for the declared
    // algorithm — the algorithm-confusion case) is a signature failure, not a
    // path/* verdict of its own; only a PathError code is preserved.
    var code = (e && typeof e.code === "string" && e.code.indexOf("path/") === 0) ? e.code : "path/bad-signature";
    return { ok: false, code: code, error: e };
  });
}

// ---- 7.1 name comparison ---------------------------------------------------

function normalizeAttrValue(v) {
  // RFC 5280 7.1: case-fold + collapse internal whitespace for the
  // caseIgnoreMatch string types (the common CA case). Reject embedded NUL /
  // control bytes so a truncation attack (CVE-2009-2408) cannot make two
  // different names compare equal.
  if (typeof v !== "string") return v;
  for (var i = 0; i < v.length; i++) {
    var c = v.charCodeAt(i);
    if (c === 0 || (c < 0x20 && c !== 0x09)) throw E("path/name-chaining", "distinguished name contains an embedded control byte (CVE-2009-2408)");
  }
  return v.trim().replace(/\s+/g, " ").toLowerCase();
}

function rdnEqual(a, b) {
  if (a.length !== b.length) return false;
  // An RDN is an unordered SET of type/value pairs; compare as multisets.
  var used = [];
  for (var i = 0; i < a.length; i++) {
    var found = false;
    for (var j = 0; j < b.length; j++) {
      if (used[j]) continue;
      if (a[i].type === b[j].type && normalizeAttrValue(a[i].value) === normalizeAttrValue(b[j].value)) {
        used[j] = true; found = true; break;
      }
    }
    if (!found) return false;
  }
  return true;
}

function dnEqual(rdnsA, rdnsB) {
  if (rdnsA.length !== rdnsB.length) return false;
  for (var i = 0; i < rdnsA.length; i++) {
    if (!rdnEqual(rdnsA[i], rdnsB[i])) return false;
  }
  return true;
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
// validator rejects the non-critical form — an extension a non-supporting
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

function emailMatch(constraint, mailbox) {
  // RFC 5280 §4.2.1.10 rfc822Name: a constraint with an "@" is a full mailbox
  // (exact match); a leading "." is a domain that matches mailboxes at a
  // SUBDOMAIN (one or more prepended labels); otherwise it is a host that
  // matches mailboxes AT that host only (not subdomains).
  var c = constraint.toLowerCase(), m = mailbox.toLowerCase();
  if (c.indexOf("@") !== -1) return m === c;
  var at = m.indexOf("@");
  var host = at === -1 ? m : m.slice(at + 1);
  if (c.charAt(0) === ".") return host.length > c.length && host.slice(-c.length) === c;
  return host === c;
}

// Strip a single trailing dot (the absolute-FQDN root label) so "evil.com."
// and "evil.com" compare equal — otherwise a trailing-dot SAN would escape a
// dNSName constraint.
function stripTrailingDot(s) { return s.charAt(s.length - 1) === "." ? s.slice(0, -1) : s; }

// Host-suffix match with the RFC 5280 §4.2.1.10 leading-period rule shared by
// dNSName and uniformResourceIdentifier constraints on a host.
function hostConstraintMatch(constraint, host) {
  var c = stripTrailingDot(constraint.toLowerCase()), h = stripTrailingDot(host.toLowerCase());
  if (c === "") return true;
  if (c.charAt(0) === ".") return h.length > c.length && h.slice(-c.length) === c;   // subdomain only
  return h === c || (h.length > c.length && h.slice(-(c.length + 1)) === "." + c);   // host + subdomains
}

// A URI constraint applies to the host part: a leading "." matches subdomains
// only; a bare host matches that host EXACTLY (not subdomains, per §4.2.1.10).
// A URI with no extractable host authority cannot be evaluated against a host
// constraint — return "unsupported" so the caller fails closed rather than
// letting the name escape a critical constraint.
function uriMatch(constraint, uri) {
  var host = uriHost(uri);
  if (host === null) return "unsupported";
  var c = stripTrailingDot(constraint.toLowerCase()), h = stripTrailingDot(host.toLowerCase());
  if (c.charAt(0) === ".") return h.length > c.length && h.slice(-c.length) === c;
  return h === c;
}

function uriHost(uri) {
  var m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(uri);
  if (!m) return null;
  var authority = m[1];
  var at = authority.indexOf("@");
  if (at !== -1) authority = authority.slice(at + 1);
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
// but this validator does not implement that form's comparison — the caller
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
  if (san) {
    // Preserve EVERY SAN entry, including a form whose value the validator does
    // not decode (x400Address [3] / ediPartyName [5]) — dropping it would let a
    // critical constraint of that same unsupported form pass unenforced. The
    // constraint check fails such a form closed (name-constraint-unsupported).
    san.value.names.forEach(function (nm) {
      forms.push({ tag: nm.tagNumber, value: nm.value === undefined ? null : nm.value });
    });
  }
  cert.subject.rdns.forEach(function (rdn) {
    rdn.forEach(function (atv) {
      if (atv.type === OID.emailAddress && typeof atv.value === "string") forms.push({ tag: 1, value: atv.value });
    });
  });
  if (cert.subject.rdns.length > 0) forms.push({ tag: 4, value: cert.subject });
  return forms;
}

// Check a cert's own names against the accumulated constraints. `excluded` is
// a UNION (any match rejects). `permitted` is the INTERSECTION of every
// absorbing cert's permittedSubtrees (6.1.4(g)): the permitted set is tracked
// as one GENERATION per absorbing cert, and a name of form F must match a
// subtree of form F in EVERY generation that constrains form F. A flat pool
// would compute the UNION — letting a subordinate CA BROADEN what its parent
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

function initialize(certs, params) {
  var n = certs.length;
  return {
    validPolicyTree: rootNode(),
    policyNodeCount: 1,
    maxPolicyNodes: params.maxPolicyNodes || 4096,
    // Each absorbing cert's permittedSubtrees is one generation; a name must be
    // admitted by EVERY generation (intersection). An initial seed is generation 0.
    permittedGenerations: (params.initialPermittedSubtrees && params.initialPermittedSubtrees.length) ? [params.initialPermittedSubtrees.slice()] : [],
    excludedSubtrees: (params.initialExcludedSubtrees || []).slice(),
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
    // self-issued non-final cert (6.1.3(d)) — this gates BOTH the (d)(1)(ii)
    // child-from-anyPolicy fallback and the (d)(2) expansion.
    var anyPolicyActive = state.inhibitAnyPolicy > 0 || (i < state._n && selfIssued(cert));
    var anyPolicyPresent = false;
    policies.forEach(function (p) {
      if (p.policyIdentifier === OID.anyPolicy) { anyPolicyPresent = true; return; }
      var matched = false;
      leavesAt(state.validPolicyTree, depth).forEach(function (node) {
        if (node.expectedPolicySet.indexOf(p.policyIdentifier) !== -1) {
          addChild(state, node, p.policyIdentifier, p.qualifiersBytes, [p.policyIdentifier], checks);
          matched = true;
        }
      });
      if (!matched && anyPolicyActive) {
        // 6.1.3(d)(1)(ii): create the node from a depth-(i-1) anyPolicy node —
        // ONLY while anyPolicy processing is active (else a leaf policy would
        // wrongly survive after inhibit_anyPolicy reached 0).
        leavesAt(state.validPolicyTree, depth).forEach(function (node) {
          if (node.validPolicy === OID.anyPolicy) addChild(state, node, p.policyIdentifier, p.qualifiersBytes, [p.policyIdentifier], checks);
        });
      }
    });
    if (anyPolicyPresent && anyPolicyActive) {
      // 6.1.3(d)(2): expand anyPolicy into unmatched expected-policy values.
      leavesAt(state.validPolicyTree, depth).forEach(function (node) {
        node.expectedPolicySet.forEach(function (ep) {
          var already = node.children.some(function (ch) { return ch.validPolicy === ep; });
          if (!already) addChild(state, node, ep, null, [ep], checks);
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

// RFC 5280 6.1.4(d,e,f) / 6.1.5(c,d): set working_public_key / _algorithm /
// _parameters from a certificate. Present non-null parameters are copied;
// NULL-or-absent parameters inherit the prior parameters iff the key algorithm
// is unchanged, else clear them.
function updateWorkingKey(state, cert) {
  var keyAlg = cert.subjectPublicKeyInfo.algorithm;
  state.workingPublicKey = cert.subjectPublicKeyInfo.bytes;
  if (!isNullOrAbsentParams(keyAlg.parameters)) {
    state.workingPublicKeyParameters = keyAlg.parameters;
  } else if (keyAlg.oid !== state.workingPublicKeyAlgorithm) {
    state.workingPublicKeyParameters = null;
  }
  state.workingPublicKeyAlgorithm = keyAlg.oid;
}

function prepareNext(state, cert, i, checks) {
  var isSelfIssued = selfIssued(cert);

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
  catch (e) { checks.push({ name: "nameConstraints", ok: false, code: e.code || "path/bad-name-constraints" }); return { fatal: true, error: e }; }
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

  // (k) basicConstraints cA gate — the single authoritative CA check.
  var bc;
  try { bc = decodeExt(cert, OID.basicConstraints); }
  catch (e) { checks.push({ name: "basicConstraints", ok: false, code: "path/bad-basic-constraints" }); return { fatal: true, error: e }; }
  if (!bc || bc.value.cA !== true) {
    checks.push({ name: "basicConstraints", ok: false, code: "path/not-a-ca" });
    return { fatal: true, error: E("path/not-a-ca", "intermediate certificate is not a CA (basicConstraints cA is not TRUE, RFC 5280 6.1.4(k))") };
  }
  // 4.2.1.9: a CA certificate used to validate certificate signatures MUST mark
  // basicConstraints critical. A non-critical cA:TRUE is non-conforming — a
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
    // subjectDomainPolicy values mapped from that ID-P (not append — retaining
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
        // 6.1.4(b)(1): no depth-i ID-P node, but a depth-i anyPolicy node — GENERATE
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
    // extension may have already emptied the tree — stop if it is gone.
    var mappedSet = {};
    mappings.forEach(function (m) { mappedSet[m.issuerDomainPolicy] = true; });
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

function unrecognizedCriticalExtension(cert) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (ext.critical && !PROCESSED_EXTENSIONS[ext.oid]) return ext.oid;
  }
  return null;
}

// Decode every RECOGNIZED critical extension to enforce that its extnValue is
// structurally valid — even where the semantic gate is skipped (the leaf).
// Returns the failing typed code, or null.
function validateCriticalExtensionStructure(cert) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (!ext.critical) continue;
    var dec = EXT_DECODERS[ext.oid];
    if (!dec) continue;   // unrecognized-critical handled separately
    try { dec(ext.value); }
    catch (e) { return e.code || "path/bad-extension-value"; }
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
 * Validate an ordered certification `path` (anchor→target) against a trust
 * anchor per RFC 5280 6.1. `path` is an array of `pki.schema.x509.parse`
 * objects (or DER/PEM the function parses); `opts` carries `time` (the
 * always-on window check), `trustAnchor` ({ name, publicKey, algorithm,
 * parameters? }), the optional policy inputs, and an optional
 * `revocationChecker`. Returns `{ valid, path, results, workingPublicKey,
 * workingPublicKeyAlgorithm, workingPublicKeyParameters, validPolicyTree }`
 * where `results[i].checks` carries a per-check reason code (`path/*`) for
 * every step. Pure and re-entrant — no input object is mutated. An empty path
 * or a missing anchor throws a typed `PathError`.
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
  var certs = path.map(function (c) { return (c && c.tbsBytes) ? c : x509.parse(c); });
  var n = certs.length;
  if (n < 1) throw E("path/empty-path", "validate: the certification path is empty");
  if (!opts.trustAnchor) throw E("path/bad-input", "validate: a trustAnchor is required");
  // The validity-window check is always on (6.1.3(a)(2)); a missing/invalid
  // check date must fail closed, never silently disable it.
  if (!(opts.time instanceof Date) || isNaN(opts.time.getTime())) {
    throw E("path/bad-input", "validate: opts.time must be a Date (the always-on validity-window check date)");
  }

  var state = initialize(certs, opts);
  state._n = n;
  var verifier = opts.verifier || null;
  var revocationChecker = opts.revocationChecker || null;
  var softFail = opts.softFail === true;
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
      catch (e) { ncRes = { ok: false, code: e.code || "path/bad-name-constraints" }; }
      checks.push({ name: "nameConstraints", ok: ncRes.ok, code: ncRes.ok ? undefined : ncRes.code });
      if (!ncRes.ok) failed = true;
    }

    // 6.1.3(a)(3) revocation.
    if (revocationChecker) {
      var issuerCert = idx > 0 ? certs[idx - 1] : null;   // the anchor issues cert[1]
      var rv;
      try { rv = await revocationChecker.check(cert, { workingIssuerName: state.workingIssuerName, workingPublicKey: state.workingPublicKey, workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm, issuerCert: issuerCert }, { time: opts.time }); }
      catch (_e) { rv = { status: "unknown" }; }
      // ONLY an explicit "good" is a determined non-revocation; "revoked" fails;
      // every other value ("unknown", an OCSP tryLater/unauthorized, a typo, a
      // missing status) is undetermined and fails closed unless softFail.
      if (rv && rv.status === "good") { checks.push({ name: "revocation", ok: true }); }
      else if (rv && rv.status === "revoked") { checks.push({ name: "revocation", ok: false, code: "path/revoked" }); failed = true; }
      else if (softFail) { checks.push({ name: "revocation", ok: true }); }
      else { checks.push({ name: "revocation", ok: false, code: "path/revocation-undetermined" }); failed = true; }
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
      if (lpc && lpc.value.requireExplicitPolicy === 0) state.explicitPolicy = 0;   // 6.1.5(b)
      updateWorkingKey(state, cert);   // 6.1.5(c),(d) — key AND algorithm AND parameters
    }

    // 6.1.4(o) / 6.1.5(e) unrecognized critical extension.
    var unk = unrecognizedCriticalExtension(cert);
    if (unk) { checks.push({ name: "criticalExtensions", ok: false, code: "path/unrecognized-critical-extension" }); failed = true; }

    // A RECOGNIZED critical extension must still be structurally valid even
    // when its semantic gate does not run on this cert (the leaf is not subject
    // to 6.1.4, so its basicConstraints/keyUsage/policy* are never read in
    // prepareNext) — a malformed critical extnValue must fail closed, not slip
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

function decodeIdp(ext) {
  // IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0]?,
  //   onlyContainsUserCerts [1]?, onlyContainsCACerts [2]?, onlySomeReasons [3]?,
  //   indirectCRL [4]?, onlyContainsAttributeCerts [5]? }. Surface the scope
  //   flags the checker gates on.
  var out = { hasDistributionPoint: false, onlyUser: false, onlyCa: false, onlySomeReasons: null, indirect: false, onlyAttr: false, malformed: false };
  var n;
  try { n = asn1.decode(ext.value); }
  catch (_e) { out.malformed = true; return out; }
  // A present IDP whose value is not a SEQUENCE leaves the CRL's scope unknown
  // — treat the CRL as unusable rather than assuming an unrestricted scope.
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children) { out.malformed = true; return out; }
  n.children.forEach(function (f) {
    if (f.tagClass !== "context") { out.malformed = true; return; }
    if (f.tagNumber === 0) out.hasDistributionPoint = true;   // scoped to a specific DP
    else if (f.tagNumber === 1) { if (idpBoolTrue(f, out)) out.onlyUser = true; }
    else if (f.tagNumber === 2) { if (idpBoolTrue(f, out)) out.onlyCa = true; }
    else if (f.tagNumber === 3) out.onlySomeReasons = true;   // BIT STRING; presence gates out-of-scope
    else if (f.tagNumber === 4) { if (idpBoolTrue(f, out)) out.indirect = true; }
    else if (f.tagNumber === 5) { if (idpBoolTrue(f, out)) out.onlyAttr = true; }
    else out.malformed = true;
  });
  return out;
}

// An IMPLICIT BOOLEAN scope flag is primitive with the single DER-TRUE octet
// 0xFF (a present DEFAULT-FALSE field is TRUE); anything else — constructed,
// wrong length, non-0xFF — is malformed, so mark the scope unknown.
function idpBoolTrue(f, out) {
  if (f.children || !f.content || f.content.length !== 1 || f.content[0] !== 0xff) { out.malformed = true; return false; }
  return true;
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
 * "unknown" }`. An out-of-scope, stale, unauthorized, or unverifiable CRL
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
      var certIsCa = (function () { try { var bc = decodeExt(cert, OID.basicConstraints); return bc && bc.value.cA === true; } catch (_e) { return false; } })();
      // The CRL signer (the cert's issuer) must assert keyUsage.cRLSign when it
      // is itself a path certificate (a keyUsage-less anchor is unconstrained).
      var signerAuthorized = true;
      if (issuer && issuer.issuerCert) {
        var iku;
        try { iku = decodeExt(issuer.issuerCert, OID.keyUsage); } catch (_e) { iku = null; }
        if (iku && iku.value.cRLSign !== true) signerAuthorized = false;
      }

      // Consult EVERY CRL issued by the cert's issuer — a clean CRL must not
      // shadow a revoking one (RFC 5280 6.3.3). A serial listed in ANY
      // authoritative, in-scope, current, verified CRL is revoked; the cert is
      // "good" only if at least one such CRL was consulted and none list it;
      // otherwise the status is undetermined.
      var sawAuthoritative = false;
      for (var k = 0; k < parsed.length; k++) {
        var theCrl = parsed[k];
        if (!dnEqual(theCrl.issuer.rdns, cert.issuer.rdns)) continue;
        if (!signerAuthorized) continue;

        // A validly-signed CRL carrying a CRITICAL extension this checker does
        // not understand (anything but issuingDistributionPoint) may change the
        // CRL's scope or meaning — treat it as unusable (RFC 5280 5.2 critical-
        // extension semantics), never authoritative.
        var unhandledCritical = false;
        for (var x = 0; x < theCrl.crlExtensions.length; x++) {
          var xe = theCrl.crlExtensions[x];
          if (xe.critical && xe.oid !== OID_IDP) { unhandledCritical = true; break; }
        }
        // RFC 5280 §5.3: a critical CRL-ENTRY extension the checker cannot
        // process (anything but reasonCode) makes the CRL unusable for ANY
        // certificate, not just the entry that carries it.
        for (var ry = 0; ry < theCrl.revokedCertificates.length && !unhandledCritical; ry++) {
          var ees = theCrl.revokedCertificates[ry].crlEntryExtensions || [];
          for (var ex = 0; ex < ees.length; ex++) {
            // Key on the stable OID only — a display name is registry-dependent
            // (a custom OID could be registered as "reasonCode"), so matching by
            // name would let an unhandled critical entry extension fail open.
            if (ees[ex].critical && ees[ex].oid !== OID_REASON_CODE) { unhandledCritical = true; break; }
          }
        }
        if (unhandledCritical) continue;

        var idpExt = null;
        for (var e = 0; e < theCrl.crlExtensions.length; e++) if (theCrl.crlExtensions[e].oid === OID_IDP) idpExt = theCrl.crlExtensions[e];
        if (idpExt) {
          var idp = decodeIdp(idpExt);
          if (idp.malformed) continue;                       // scope unknown -> unusable
          // An indirect CRL carries entries for other issuers keyed by the
          // per-entry certificateIssuer attribute (not tracked here) — matching
          // by serial alone could revoke the wrong cert or falsely cover it, so
          // treat an indirect CRL as unusable until certificateIssuer is honored.
          if (idp.indirect) continue;
          // A CRL scoped to a specific distributionPoint cannot be confirmed
          // in-scope for this certificate without matching the cert's
          // cRLDistributionPoints — treat it as non-authoritative (fail-closed).
          if (idp.hasDistributionPoint) continue;
          if (idp.onlyAttr) continue;                        // scoped to attribute certs, not this public-key cert
          if (idp.onlyCa && !certIsCa) continue;             // out of scope for this cert
          if (idp.onlyUser && certIsCa) continue;
          if (idp.onlySomeReasons) continue;                 // partial reason coverage -> not authoritative
        }
        if (theCrl.thisUpdate > time) continue;              // not yet valid
        // A CRL with no nextUpdate has no bounded validity — its currency
        // cannot be confirmed (RFC 5280 §5.1.2.5 requires nextUpdate), so a
        // replayed old CRL must not read "good". Treat it as unusable.
        if (!theCrl.nextUpdate || theCrl.nextUpdate < time) continue;   // stale / no bound

        var sigOk = await verifyCrlSignature(theCrl, issuer);
        if (!sigOk) continue;                                // unverifiable -> not authoritative

        for (var r = 0; r < theCrl.revokedCertificates.length; r++) {
          var entry = theCrl.revokedCertificates[r];
          if (entry.serialNumberHex !== cert.serialNumberHex) continue;
          // reasonCode removeFromCRL (8) means the entry was un-revoked (a delta-CRL
          // convention) — it is NOT a revocation.
          if (crlEntryReason(entry) === 8) continue;
          return { status: "revoked", reason: "serial listed in a CRL" };
        }
        sawAuthoritative = true;                              // covered this cert, not listed
      }
      if (sawAuthoritative) return { status: "good" };
      return { status: "unknown", reason: "no authoritative in-scope CRL covers this certificate" };
    },
  };
}

// The decoded reasonCode of a revoked CRL entry (crl.parse surfaces it as a
// number), or null when absent.
var OID_REASON_CODE = oid.byName("reasonCode");
function crlEntryReason(entry) {
  var exts = entry.crlEntryExtensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid === OID_REASON_CODE) return exts[i].value;   // stable OID, not the display name
  }
  return null;
}

function verifyCrlSignature(theCrl, issuer) {
  var d;
  try { d = resolveDescriptor(theCrl.signatureAlgorithm); }
  catch (_e) { return Promise.resolve(false); }
  if (theCrl.signatureValue.unusedBits !== 0) return Promise.resolve(false);   // non-octet-aligned signature
  var key;
  return subtle.importKey("spki", issuer.workingPublicKey, d.imp, false, ["verify"]).then(function (k) {
    key = k;
    var sig = theCrl.signatureValue.bytes;
    if (d.ecdsa) sig = ecdsaDerToP1363(sig, key.algorithm.namedCurve);
    return subtle.verify(d.verify, key, sig, theCrl.tbsBytes);
  }).then(function (ok) { return ok === true; }, function () { return false; });
}

module.exports = {
  validate: validate,
  crlChecker: crlChecker,
};
