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
 * 6.1 state machine (signature chaining, validity windows, name chaining,
 * basic constraints and path length, key usage, name constraints, and the
 * certificate-policy tree) and returns a structured verdict with a per-check
 * reason code for every step. Validity-window enforcement is always on, with
 * the check date an explicit input; the trust anchor is an input, never one of
 * the validated certificates, and no input object is mutated.
 *
 * Revocation is a pluggable hook: `pki.path.crlChecker(crls)` ships a CRL
 * consultation built on `pki.schema.crl.parse`; an OCSP checker satisfies the
 * same interface. Signature verification derives its algorithm from the
 * certificate and the issuer key, never from a value the message controls,
 * and fails closed on an unknown critical extension, an undetermined
 * revocation status, or any structural fault.
 *
 * @card
 *   RFC 5280 6 certification-path validation: run the 6.1 state machine over
 *   an ordered path and a trust anchor for a structured, fail-closed verdict
 *   with per-check reason codes. Pure and re-entrant.
 */

var webcrypto = require("./webcrypto");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var ct = require("./ct");
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
var ocspRequestVerify = require("./ocsp-request-verify");
var cmpVerify = require("./cmp-verify");
var cmsVerify = require("./cms-verify");
var cmpSession = require("./cmp-session");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var constants = require("./constants");
var validator = require("./validator-all");
var cms = require("./schema-cms");
var httpTransport = require("./http-transport");
var net = require("net");
var compositeSig = require("./composite-sig");
var edwardsPoint = require("./edwards-point");

var PathError = errors.PathError;
function E(code, message, cause) { return new PathError(code, message, cause); }
function pathCode(e, fallback) {
  return (e && typeof e.code === "string" && e.code.indexOf("path/") === 0) ? e.code : fallback;
}

var contains = guard.list.contains;
var containsAll = guard.list.containsAll;
function mapsAnyPolicy(mappings) {
  return guard.list.anyMatches(mappings, function (m) {
    return !!m && (m.issuerDomainPolicy === OID.anyPolicy || m.subjectDomainPolicy === OID.anyPolicy);
  });
}

var NS = pkix.makeNS("path", PathError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var ANCHOR_SPKI_SCHEMA = pkix.spki(NS);

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

var PROCESSED_EXTENSIONS = {};
[OID.basicConstraints, OID.keyUsage, OID.nameConstraints, OID.certificatePolicies,
 OID.policyMappings, OID.policyConstraints, OID.inhibitAnyPolicy, OID.subjectAltName,
 OID.extKeyUsage, OID.cRLDistributionPoints].
  forEach(function (o) { PROCESSED_EXTENSIONS[o] = true; });
Object.freeze(PROCESSED_EXTENSIONS);


var SIG_ALGS = intrinsic.create(null);
function _sig(name, verify, imp, params, ecdsa, sameKeyOid) {
  var entry = { verify: verify, imp: imp, params: params };
  if (ecdsa) entry.ecdsa = true;
  if (sameKeyOid) entry.sameKeyOid = true;
  if (verify.name === "Ed25519") entry.eddsa = 6;
  else if (verify.name === "Ed448") entry.eddsa = 7;
  SIG_ALGS[oid.byName(name)] = entry;
}
_sig("sha256WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, "null");
_sig("sha384WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, "null");
_sig("sha512WithRSAEncryption", { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, "null");
_sig("ecdsaWithSHA256", { name: "ECDSA", hash: "SHA-256" }, { name: "ECDSA" }, "absent", true);
_sig("ecdsaWithSHA384", { name: "ECDSA", hash: "SHA-384" }, { name: "ECDSA" }, "absent", true);
_sig("ecdsaWithSHA512", { name: "ECDSA", hash: "SHA-512" }, { name: "ECDSA" }, "absent", true);
_sig("Ed25519", { name: "Ed25519" }, { name: "Ed25519" }, "absent", false, true);
_sig("Ed448", { name: "Ed448" }, { name: "Ed448" }, "absent", false, true);
_sig("id-ml-dsa-44", { name: "ML-DSA-44" }, { name: "ML-DSA-44" }, "absent", false, true);
_sig("id-ml-dsa-65", { name: "ML-DSA-65" }, { name: "ML-DSA-65" }, "absent", false, true);
_sig("id-ml-dsa-87", { name: "ML-DSA-87" }, { name: "ML-DSA-87" }, "absent", false, true);
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (set) {
  var wc = "SLH-DSA-" + set.toUpperCase();
  _sig("id-slh-dsa-" + set, { name: wc }, { name: wc }, "absent", false, true);
});

var OID_RSA_PSS = oid.byName("rsassaPss");
var OID_MGF1 = oid.byName("mgf1");
var HASH_BY_OID = {};
HASH_BY_OID[oid.byName("sha256")] = "SHA-256";
HASH_BY_OID[oid.byName("sha384")] = "SHA-384";
HASH_BY_OID[oid.byName("sha512")] = "SHA-512";


function seqAlgOid(seq) {
  if (!seq || seq.tagClass !== "universal" || seq.tagNumber !== asn1.TAGS.SEQUENCE || !seq.children || seq.children.length < 1 || seq.children.length > 2) {
    throw E("path/unsupported-algorithm", "expected an AlgorithmIdentifier SEQUENCE { OID, parameters? }");
  }
  return asn1.read.oid(seq.children[0]);
}
function hashAlgOid(seq) {
  var o = seqAlgOid(seq);
  if (seq.children.length === 2) {
    var p = seq.children[1];
    if (p.tagClass !== "universal" || p.tagNumber !== asn1.TAGS.NULL) throw E("path/unsupported-algorithm", "hash AlgorithmIdentifier parameters must be NULL or absent (RFC 4055)");
    try { asn1.read.nullValue(p); }
    catch (e) { throw E("path/unsupported-algorithm", "hash AlgorithmIdentifier NULL parameters must have empty content (RFC 4055)", e); }
  }
  return o;
}
function explicitHashAlgOid(wrapper) {
  if (!wrapper.children || wrapper.children.length !== 1) throw E("path/unsupported-algorithm", "malformed EXPLICIT hash AlgorithmIdentifier");
  return hashAlgOid(wrapper.children[0]);
}

function resolveRsaPss(paramsBytes) {
  var hash = null, saltLength = 20, mgfNode = null, trailer = 1;
  if (!paramsBytes) throw E("path/unsupported-algorithm", "RSASSA-PSS requires explicit parameters (the SHA-1 defaults are rejected)");
  var n = asn1.decode(paramsBytes);
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children) {
    throw E("path/unsupported-algorithm", "RSASSA-PSS parameters must be an RSASSA-PSS-params SEQUENCE (RFC 4055)");
  }
  var pssLastTag = -1;
  n.children.forEach(function (f) {
    if (f.tagClass !== "context") throw E("path/unsupported-algorithm", "RSASSA-PSS-params fields must be context-tagged (RFC 4055)");
    if (f.tagNumber > 3 || f.tagNumber <= pssLastTag) throw E("path/unsupported-algorithm", "RSASSA-PSS-params has an unexpected, duplicate, or out-of-order field [" + f.tagNumber + "]");
    pssLastTag = f.tagNumber;
    if (!f.children || f.children.length !== 1) throw E("path/unsupported-algorithm", "malformed RSASSA-PSS parameter field [" + f.tagNumber + "] (an EXPLICIT wrapper carries exactly one value)");
    if (f.tagNumber === 0) {
      var h = explicitHashAlgOid(f);
      if (!HASH_BY_OID[h]) throw E("path/unsupported-algorithm", "unsupported RSASSA-PSS hash algorithm " + h);
      hash = HASH_BY_OID[h];
    } else if (f.tagNumber === 1) {
      mgfNode = f.children[0];
    } else if (f.tagNumber === 2) {
      var sl = asn1.read.integer(f.children[0]);
      saltLength = guard.range.uint31(sl, E, "path/unsupported-algorithm", "RSASSA-PSS saltLength");
    } else if (f.tagNumber === 3) {
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

function isDerNull(p) { return p && p.length === 2 && p[0] === 0x05 && p[1] === 0x00; }

function resolveDescriptor(sigAlg) {
  if (sigAlg.oid === OID_RSA_PSS) return resolveRsaPss(sigAlg.parameters);
  var comp = compositeSig.resolveCompositeDescriptor(sigAlg, PathError, "path/unsupported-algorithm");
  if (comp) return comp;
  var d = SIG_ALGS[sigAlg.oid];
  if (!d) throw E("path/unsupported-algorithm", "no verify descriptor for signature algorithm " + (sigAlg.name || sigAlg.oid));
  var p = sigAlg.parameters;
  if (d.params === "null" && !isDerNull(p)) throw E("path/unsupported-algorithm", "signature algorithm parameters must be NULL (RFC 4055)");
  if (d.params === "absent" && p !== null && p !== undefined) throw E("path/unsupported-algorithm", "signature algorithm parameters must be absent (RFC 5758/8410)");
  return d;
}

function assertKeyMatchesSigAlg(spkiBytes, sigOid, d) {
  if (!d || !d.sameKeyOid) return;
  var keyOid;
  try { keyOid = asn1.read.oid(asn1.decode(spkiBytes).children[0].children[0]); }
  catch (e) { throw E("path/algorithm-mismatch", "cannot read the issuer public-key algorithm identifier", e); }
  if (keyOid !== sigOid) {
    throw E("path/algorithm-mismatch", "issuer public-key algorithm " + keyOid + " does not match the signature algorithm " + sigOid + " (RFC 9814 sec. 4 - algorithm confusion)");
  }
}



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

var ML_KEM_OIDS = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) { ML_KEM_OIDS[oid.byName(n)] = true; });

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

function _importVerifyKey(spkiBytes, d) {
  try {
    if (d.eddsa) edwardsPoint.validateSpki(spkiBytes, d.eddsa, PathError, "path/bad-signature");
  } catch (e) { return Promise.reject(e); }
  return subtle.importKey("spki", spkiBytes, d.imp, false, ["verify"]);
}

function builtinVerify(state, cert) {
  var d;
  try {
    d = resolveDescriptor(cert.signatureAlgorithm);
    assertKeyMatchesSigAlg(state.workingPublicKey, cert.signatureAlgorithm.oid, d);
  } catch (e) { return Promise.resolve({ ok: false, code: pathCode(e, "path/unsupported-algorithm"), error: e }); }
  if (!guard.crypto.isOctetAligned(cert.signatureValue)) return Promise.resolve({ ok: false, code: "path/bad-signature" });
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
    return { ok: false, code: pathCode(e, "path/bad-signature"), error: e };
  });
}


function dnEqual(rdnsA, rdnsB) {
  return guard.name.dnEqual(rdnsA, rdnsB, E, "path/name-chaining", "distinguished name");
}

function rdnEqual(a, b) {
  return guard.name.rdnEqual(a, b, E, "path/name-chaining", "distinguished name");
}


function findExt(cert, extOid) {
  for (var i = 0; i < cert.extensions.length; i++) {
    if (cert.extensions[i].oid === extOid) return cert.extensions[i];
  }
  return null;
}

function decodeExt(cert, extOid) {
  var ext = findExt(cert, extOid);
  if (!ext) return null;
  var dec = EXT_DECODERS[extOid];
  return { critical: ext.critical, value: dec(ext.value) };
}

function requireCriticalExt(ext, name, checks) {
  if (ext && ext.critical !== true) {
    guard.list.append(checks,{ name: name, ok: false, code: "path/extension-not-critical" });
    return E("path/extension-not-critical", name + " extension must be marked critical (RFC 5280 4.2.1)");
  }
  return null;
}


function splitMailbox(addr) {
  var first = addr.indexOf("@");
  if (first === -1) return null;
  if (first !== addr.lastIndexOf("@")) return "ambiguous";
  return [addr.slice(0, first), addr.slice(first + 1)];
}

function emailMatch(constraint, mailbox) {
  var mb = splitMailbox(mailbox);
  if (mb === "ambiguous") return "unsupported";
  if (constraint.indexOf("@") !== -1) {
    var cb = splitMailbox(constraint);
    if (cb === "ambiguous" || cb === null || mb === null) return "unsupported";
    return mb[0] === cb[0] && stripTrailingDot(mb[1].toLowerCase()) === stripTrailingDot(cb[1].toLowerCase());
  }
  if (mb === null) return "unsupported";
  var host = stripTrailingDot(mb[1].toLowerCase());
  if (host === "") return "unsupported";
  var c = stripTrailingDot(constraint.toLowerCase());
  if (c.charAt(0) === ".") return host.length > c.length && host.slice(-c.length) === c;
  return host === c;
}

function stripTrailingDot(s) { return s.charAt(s.length - 1) === "." ? s.slice(0, -1) : s; }

function hostConstraintMatch(constraint, host) {
  var c = stripTrailingDot(constraint.toLowerCase()), h = stripTrailingDot(host.toLowerCase());
  if (c === "") return true;
  if (c.charAt(0) === ".") return h.length > c.length && h.slice(-c.length) === c;
  return h === c || (h.length > c.length && h.slice(-(c.length + 1)) === "." + c);
}

function _charTable(chars) { var t = []; for (var i = 0; i < chars.length; i++) t[_charCodeAt(chars, i)] = true; return t; }
var _FQDN_TABLE = _charTable("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-");
var _DIGDOT_TABLE = _charTable("0123456789.");
function _allCharsIn(s, table) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) if (!table[_charCodeAt(s, i)]) return false;
  return true;
}
function _startsWithDigit(s) { if (s.length === 0) return false; var c = _charCodeAt(s, 0); return c >= 48 && c <= 57; }

var _SCHEME_TABLE = _charTable("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-");
function _uriAuthorityRange(uri) {
  var n = uri.length;
  if (n === 0) return null;
  var c0 = _charCodeAt(uri, 0);
  if (!((c0 >= 65 && c0 <= 90) || (c0 >= 97 && c0 <= 122))) return null;
  var p = 1;
  while (p < n && _SCHEME_TABLE[_charCodeAt(uri, p)]) p += 1;
  if (_charCodeAt(uri, p) !== 58 || _charCodeAt(uri, p + 1) !== 47 || _charCodeAt(uri, p + 2) !== 47) return null;
  p += 3;
  var authStart = p;
  while (p < n) { var d = _charCodeAt(uri, p); if (d === 47 || d === 63 || d === 35) break; p += 1; }
  return [authStart, p];
}
function _portStripIndex(s) {
  var i = s.length;
  while (i > 0) { var c = _charCodeAt(s, i - 1); if (c >= 48 && c <= 57) i -= 1; else break; }
  return (i < s.length && i > 0 && _charCodeAt(s, i - 1) === 58) ? i - 1 : s.length;
}
function _stripBrackets(s) {
  var n = s.length;
  return (n >= 2 && _charCodeAt(s, 0) === 91 && _charCodeAt(s, n - 1) === 93) ? s.slice(1, n - 1) : s;
}

function isFqdnHost(host) {
  var h = stripTrailingDot(host);
  if (h === "" || h.indexOf(".") === -1) return false;
  if (!_allCharsIn(h, _FQDN_TABLE)) return false;
  if (_allCharsIn(h, _DIGDOT_TABLE)) return false;
  return true;
}

function uriMatch(constraint, uri) {
  var host = uriHost(uri);
  if (host === null) return "unsupported";
  if (!isFqdnHost(host)) return "unsupported";
  var c = stripTrailingDot(constraint.toLowerCase()), h = stripTrailingDot(host.toLowerCase());
  if (!isFqdnHost(c.charAt(0) === "." ? c.slice(1) : c)) return "unsupported";
  if (c.charAt(0) === ".") return h.length > c.length && h.slice(-c.length) === c;
  return h === c;
}

function uriHost(uri) {
  var r = _uriAuthorityRange(uri);
  if (r === null) return null;
  var authority = uri.slice(r[0], r[1]);
  var firstAt = authority.indexOf("@");
  if (firstAt !== authority.lastIndexOf("@")) return null;
  if (firstAt !== -1) authority = authority.slice(firstAt + 1);
  var host = authority.slice(0, _portStripIndex(authority));
  return host === "" ? null : host;
}

function ipMatch(constraint, addr) {
  var half = constraint.length / 2;
  if (addr.length !== half) return false;
  for (var i = 0; i < half; i++) {
    if ((addr[i] & constraint[half + i]) !== (constraint[i] & constraint[half + i])) return false;
  }
  return true;
}

function nameMatchesConstraint(gnTag, gnValue, base) {
  if (base.tagNumber !== gnTag) return null;
  switch (gnTag) {
    case 1: return emailMatch(base.value, gnValue);
    case 2: return hostConstraintMatch(base.value, gnValue);
    case 6: return uriMatch(base.value, gnValue);
    case 7: return ipMatch(base.value, gnValue);
    case 4: return dnStartsWith(gnValue, base.value);
    default: return "unsupported";
  }
}

function dnStartsWith(nameDn, constraintDn) {
  if (constraintDn.rdns.length > nameDn.rdns.length) return false;
  for (var i = 0; i < constraintDn.rdns.length; i++) {
    if (!rdnEqual(nameDn.rdns[i], constraintDn.rdns[i])) return false;
  }
  return true;
}

function certNameForms(cert) {
  var forms = [];
  var san = decodeExt(cert, OID.subjectAltName);
  var hasRfc822San = false;
  if (san) {
    san.value.names.forEach(function (nm) {
      if (nm.tagNumber === 1) hasRfc822San = true;
      guard.list.append(forms, { tag: nm.tagNumber, value: nm.value === undefined ? null : nm.value });
    });
  }
  if (!hasRfc822San) {
    cert.subject.rdns.forEach(function (rdn) {
      rdn.forEach(function (atv) {
        if (atv.type === OID.emailAddress && typeof atv.value === "string") guard.list.append(forms, { tag: 1, value: atv.value });
      });
    });
  }
  if (cert.subject.rdns.length > 0) guard.list.append(forms, { tag: 4, value: cert.subject });
  return forms;
}

function checkNameConstraints(state, cert) {
  var forms = certNameForms(cert);
  for (var e = 0; e < state.excludedSubtrees.length; e++) {
    var ex = state.excludedSubtrees[e];
    for (var i = 0; i < forms.length; i++) {
      var m = nameMatchesConstraint(forms[i].tag, forms[i].value, { tagNumber: ex.tag, value: ex.base });
      if (m === true) return { ok: false, code: "path/name-constraint-excluded" };
      if (m === "unsupported") return { ok: false, code: "path/name-constraint-unsupported" };
    }
  }
  for (var f = 0; f < forms.length; f++) {
    var nf = forms[f];
    for (var g = 0; g < state.permittedGenerations.length; g++) {
      var formSubtrees = state.permittedGenerations[g].filter(function (s) { return s.tag === nf.tag; });
      if (!formSubtrees.length) continue;
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

function absorbNameConstraints(state, decoded) {
  if (decoded.permittedSubtrees.length) {
    guard.list.append(state.permittedGenerations, decoded.permittedSubtrees.map(function (st) {
      return { tag: st.base.tagNumber, base: st.base.value };
    }));
  }
  decoded.excludedSubtrees.forEach(function (st) {
    guard.list.append(state.excludedSubtrees, { tag: st.base.tagNumber, base: st.base.value });
  });
}


function rootNode() {
  return { depth: 0, validPolicy: OID.anyPolicy, qualifierSet: [], expectedPolicySet: [OID.anyPolicy], children: [], parent: null };
}
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
  if (!tree) return out;
  (function walk(node) {
    if (node.depth === depth) { guard.list.append(out, node); return; }
    node.children.forEach(walk);
  })(tree);
  return out;
}
function pruneChildless(tree, depth) {
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


function isSubtreeBaseValid(tag, base) {
  switch (tag) {
    case 1: case 2: case 6: return typeof base === "string";
    case 7: return Buffer.isBuffer(base) && (base.length === 8 || base.length === 32);
    case 4: return base !== null && typeof base === "object" && !!base.rdns && intrinsic.isArray(base.rdns);
    default: return base !== undefined;
  }
}

function checkedSubtreeSeeds(list, optName) {
  if (list === undefined || list === null) return [];
  if (!intrinsic.isArray(list) || intrinsic.types.isProxy(list)) throw E("path/bad-input", "validate: opts." + optName + " must be a plain array of { tag, base } subtree entries");
  for (var li = 0; li < list.length; li++) {
    var ld = intrinsic.getOwnPropertyDescriptor(list, li);
    if (ld === undefined) throw E("path/bad-input", "validate: opts." + optName + " must not be a sparse array; index " + li + " is a hole");
    if (!intrinsic.hasOwn(ld, "value")) throw E("path/bad-input", "validate: opts." + optName + " entry " + li + " must be a data property, not an accessor");
  }
  /** @internal Built with a plain loop into a fresh array: Array.prototype.map consults the caller
   * array's constructor and Symbol.species, which is more caller code running mid-copy. */
  var seedsOut = [];
  for (var si = 0; si < list.length; si++) {
    guard.list.append(seedsOut, (function (st) {
    var shapeMsg = "validate: opts." + optName + " entries must be { tag: <GeneralName tag number 0..8>, base: <that form's constraint value> }";
    if (!st || typeof st !== "object" || intrinsic.types.isProxy(st)) throw E("path/bad-input", shapeMsg);
    /** @internal Read tag and base once each, from their own data properties: an accessor could
     * answer with a restrictive value to a check and a permissive one to the copy. */
    var tagD = intrinsic.getOwnPropertyDescriptor(st, "tag");
    var baseD = intrinsic.getOwnPropertyDescriptor(st, "base");
    if (tagD !== undefined && !intrinsic.hasOwn(tagD, "value")) throw E("path/bad-input", "validate: opts." + optName + " entry tag must be a data property, not an accessor");
    if (baseD !== undefined && !intrinsic.hasOwn(baseD, "value")) throw E("path/bad-input", "validate: opts." + optName + " entry base must be a data property, not an accessor");
    var tag = tagD === undefined ? undefined : tagD.value;
    var base = baseD === undefined ? undefined : baseD.value;
    if (!Number.isInteger(tag) || tag < 0 || tag > 8) throw E("path/bad-input", shapeMsg);
    if (tag === 7 && guard.bytes.isByteSource(base)) {
      base = guard.bytes.snapshotSource(base, PathError, "path/bad-input", "an iPAddress subtree base");
    }
    if (tag === 4 && base !== null && typeof base === "object") {
      var seedRdns = _capturedRdns(base, "validate: opts." + optName);
      if (seedRdns !== undefined) {
        var dnCopy = {};
        intrinsic.defineProperty(dnCopy, "rdns", { value: seedRdns, enumerable: true, configurable: true, writable: true });
        base = dnCopy;
      }
    }
    if (!isSubtreeBaseValid(tag, base)) throw E("path/bad-input", shapeMsg);
    return { tag: tag, base: base };
    })(intrinsic.getOwnPropertyDescriptor(list, si).value));
  }
  return seedsOut;
}

/**
 * @internal RFC 5280 sec. 6.1.1(h)(i): the anchor's own permitted/excluded subtrees, the way a root
 * program restricts a root to a namespace its certificate does not state. Validated through the same
 * entry-point checker the caller's seeds use, so a mis-shaped subtree is refused rather than dropped.
 */
function _anchorSubtreeSeeds(anchor) {
  var nc = anchor.nameConstraints;
  if (nc === undefined || nc === null) return { permitted: [], excluded: [] };
  if (typeof nc !== "object" || intrinsic.isArray(nc)) {
    throw E("path/bad-input", "validate: a trustAnchor nameConstraints must be a { permitted, excluded } object of { tag, base } subtree entries");
  }
  return {
    permitted: checkedSubtreeSeeds(nc.permitted, "trustAnchors[].nameConstraints.permitted"),
    excluded: checkedSubtreeSeeds(nc.excluded, "trustAnchors[].nameConstraints.excluded"),
  };
}

function initialize(certs, params, seeds, anchor) {
  var n = certs.length;
  return {
    validPolicyTree: rootNode(),
    policyNodeCount: 1,
    maxPolicyNodes: params.maxPolicyNodes !== undefined ? params.maxPolicyNodes : constants.LIMITS.PATH_MAX_POLICY_NODES,
    permittedGenerations: intrinsic.filter(seeds.permittedGenerations, function (g) { return g.length > 0; }),
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

function selfIssued(cert) {
  try { return dnEqual(cert.subject.rdns, cert.issuer.rdns); }
  catch (_e) { return false; }
}

function processPolicies(state, cert, i, checks) {
  var cp;
  try { cp = decodeExt(cert, OID.certificatePolicies); }
  catch (e) { guard.list.append(checks,{ name: "policies", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }

  if (cp && state.validPolicyTree) {
    var policies = cp.value;
    var depth = i - 1;
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
        leavesAt(state.validPolicyTree, depth).forEach(function (node) {
          if (node.validPolicy === OID.anyPolicy) addChild(state, node, p.policyIdentifier, p.qualifiersBytes, [p.policyIdentifier], checks);
        });
      }
    });
    if (anyPolicyPresent && anyPolicyActive) {
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

  if (!(state.explicitPolicy > 0 || state.validPolicyTree !== null)) {
    guard.list.append(checks,{ name: "policy", ok: false, code: "path/policy-required" });
    return { fatal: true, error: E("path/policy-required", "explicit policy required but the valid-policy tree is empty") };
  }
  return { fatal: false };
}

function addChild(state, parent, validPolicy, qualifiers, expectedPolicySet, checks) {
  if (state.policyNodeCount >= state.maxPolicyNodes) { state._capHit = true; return; }
  var node = { depth: parent.depth + 1, validPolicy: validPolicy, qualifierSet: qualifiers ? [qualifiers] : [], expectedPolicySet: expectedPolicySet, children: [], parent: parent };
  guard.list.append(parent.children, node);
  state.policyNodeCount++;
  void checks;
}

function isNullOrAbsentParams(p) {
  return p === null || p === undefined || (p.length === 2 && p[0] === 0x05 && p[1] === 0x00);
}

function spliceSpkiParameters(spki, algOid, paramsBytes) {
  return asn1.build.sequence([
    asn1.build.sequence([asn1.build.oid(algOid), asn1.build.raw(paramsBytes)]),
    asn1.build.bitString(spki.publicKey.bytes, spki.publicKey.unusedBits),
  ]);
}

function updateWorkingKey(state, cert) {
  var keyAlg = cert.subjectPublicKeyInfo.algorithm;
  if (!isNullOrAbsentParams(keyAlg.parameters)) {
    state.workingPublicKeyParameters = keyAlg.parameters;
  } else if (keyAlg.oid !== state.workingPublicKeyAlgorithm) {
    state.workingPublicKeyParameters = null;
  }
  if (isNullOrAbsentParams(keyAlg.parameters) && state.workingPublicKeyParameters) {
    state.workingPublicKey = spliceSpkiParameters(cert.subjectPublicKeyInfo, keyAlg.oid, state.workingPublicKeyParameters);
  } else {
    state.workingPublicKey = cert.subjectPublicKeyInfo.bytes;
  }
  state.workingPublicKeyAlgorithm = keyAlg.oid;
}

function ekuPurposeFails(cert, requiredEku, checks) {
  var eku;
  try { eku = decodeExt(cert, OID.extKeyUsage); }
  // allow:fail-open-verify -- ekuPurposeFails returns true to mean the EKU purpose FAILS (a rejecting verdict); a bad extension is recorded in checks and the purpose is treated as failed, which is fail-closed
  catch (e) { guard.list.append(checks,{ name: "extendedKeyUsage", ok: false, code: pathCode(e, "path/bad-extension-value") }); return true; }
  if (!eku) return false;
  var purposes = eku.value;
  var ok = contains(purposes, OID.anyExtendedKeyUsage) || containsAll(purposes, requiredEku);
  guard.list.append(checks,{ name: "extendedKeyUsage", ok: ok, code: ok ? undefined : "path/eku-not-permitted" });
  return !ok;
}

function prepareNext(state, cert, i, checks) {
  var isSelfIssued = selfIssued(cert);

  if (state.requiredEku && ekuPurposeFails(cert, state.requiredEku, checks)) {
    return { fatal: true, error: E("path/eku-not-permitted", "an intermediate CA extendedKeyUsage does not permit a required purpose (RFC 5280 4.2.1.12)") };
  }

  var pm;
  try { pm = decodeExt(cert, OID.policyMappings); }
  catch (e) { guard.list.append(checks,{ name: "policyMappings", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }
  if (pm) {
    var badAny = mapsAnyPolicy(pm.value);
    if (badAny) { guard.list.append(checks,{ name: "policyMappings", ok: false, code: "path/bad-policy" }); return { fatal: true, error: E("path/bad-policy", "policyMappings must not map to or from anyPolicy (RFC 5280 6.1.4(a))") }; }
    if (state.validPolicyTree) applyPolicyMappings(state, pm.value, i);
  }

  state.workingIssuerName = cert.subject;
  updateWorkingKey(state, cert);

  var nc;
  try { nc = decodeExt(cert, OID.nameConstraints); }
  catch (e) { guard.list.append(checks,{ name: "nameConstraints", ok: false, code: pathCode(e, "path/bad-name-constraints") }); return { fatal: true, error: e }; }
  var ncCritErr = requireCriticalExt(nc, "nameConstraints", checks);
  if (ncCritErr) return { fatal: true, error: ncCritErr };
  if (nc) absorbNameConstraints(state, nc.value);

  if (!isSelfIssued) {
    if (state.explicitPolicy > 0) state.explicitPolicy--;
    if (state.policyMapping > 0) state.policyMapping--;
    if (state.inhibitAnyPolicy > 0) state.inhibitAnyPolicy--;
  }

  var pc;
  try { pc = decodeExt(cert, OID.policyConstraints); }
  catch (e) { guard.list.append(checks,{ name: "policyConstraints", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }
  var pcCritErr = requireCriticalExt(pc, "policyConstraints", checks);
  if (pcCritErr) return { fatal: true, error: pcCritErr };
  if (pc) {
    if (pc.value.requireExplicitPolicy !== null && pc.value.requireExplicitPolicy < state.explicitPolicy) state.explicitPolicy = pc.value.requireExplicitPolicy;
    if (pc.value.inhibitPolicyMapping !== null && pc.value.inhibitPolicyMapping < state.policyMapping) state.policyMapping = pc.value.inhibitPolicyMapping;
  }
  var iap;
  try { iap = decodeExt(cert, OID.inhibitAnyPolicy); }
  catch (e) { guard.list.append(checks,{ name: "inhibitAnyPolicy", ok: false, code: "path/bad-policy" }); return { fatal: true, error: e }; }
  var iapCritErr = requireCriticalExt(iap, "inhibitAnyPolicy", checks);
  if (iapCritErr) return { fatal: true, error: iapCritErr };
  if (iap && iap.value < state.inhibitAnyPolicy) state.inhibitAnyPolicy = iap.value;

  var bc;
  try { bc = decodeExt(cert, OID.basicConstraints); }
  catch (e) { guard.list.append(checks,{ name: "basicConstraints", ok: false, code: "path/bad-basic-constraints" }); return { fatal: true, error: e }; }
  if (!bc || bc.value.cA !== true) {
    guard.list.append(checks,{ name: "basicConstraints", ok: false, code: "path/not-a-ca" });
    return { fatal: true, error: E("path/not-a-ca", "intermediate certificate is not a CA (basicConstraints cA is not TRUE, RFC 5280 6.1.4(k))") };
  }
  var bcCritErr = requireCriticalExt(bc, "basicConstraints", checks);
  if (bcCritErr) return { fatal: true, error: bcCritErr };
  if (!isSelfIssued) {
    if (state.maxPathLength <= 0) { guard.list.append(checks,{ name: "pathLength", ok: false, code: "path/path-length-exceeded" }); return { fatal: true, error: E("path/path-length-exceeded", "certification path is longer than the CA path-length constraint allows") }; }
    state.maxPathLength--;
  }
  if (bc.value.pathLenConstraint !== null && bc.value.pathLenConstraint < state.maxPathLength) state.maxPathLength = bc.value.pathLenConstraint;

  var ku;
  try { ku = decodeExt(cert, OID.keyUsage); }
  catch (e) { guard.list.append(checks,{ name: "keyUsage", ok: false, code: "path/bad-key-usage" }); return { fatal: true, error: e }; }
  if (ku && ku.value.keyCertSign !== true) {
    guard.list.append(checks,{ name: "keyUsage", ok: false, code: "path/missing-key-cert-sign" });
    return { fatal: true, error: E("path/missing-key-cert-sign", "CA certificate keyUsage does not assert keyCertSign (RFC 5280 6.1.4(n))") };
  }
  return { fatal: false };
}

function applyPolicyMappings(state, mappings, i) {
  var depth = i;
  if (state.policyMapping > 0) {
    var mappedFrom = {};
    mappings.forEach(function (m) { guard.list.append(mappedFrom[m.issuerDomainPolicy] = mappedFrom[m.issuerDomainPolicy] || [], m.subjectDomainPolicy); });
    var depthI = leavesAt(state.validPolicyTree, depth);
    var anyNodes = depthI.filter(function (nd) { return nd.validPolicy === OID.anyPolicy; });
    Object.keys(mappedFrom).forEach(function (idp) {
      var idpNodes = depthI.filter(function (nd) { return nd.validPolicy === idp; });
      if (idpNodes.length) {
        idpNodes.forEach(function (nd) { nd.expectedPolicySet = mappedFrom[idp].slice(); });
      } else {
        anyNodes.forEach(function (anyNode) {
          if (anyNode.parent) addChild(state, anyNode.parent, idp, anyNode.qualifierSet[0] || null, mappedFrom[idp].slice(), []);
        });
      }
    });
  } else {
    var mappedSet = {};
    mappings.forEach(function (m) { mappedSet[m.issuerDomainPolicy] = true; });
    if (!state.validPolicyTree) return;
    leavesAt(state.validPolicyTree, depth).forEach(function (node) {
      if (mappedSet[node.validPolicy] && node.parent) {
        var idx = node.parent.children.indexOf(node);
        if (idx !== -1) node.parent.children.splice(idx, 1);
      }
    });
    pruneChildless(state.validPolicyTree, depth - 1);
    if (treeIsEmpty(state.validPolicyTree)) state.validPolicyTree = null;
  }
}

var TARGET_UNPROCESSED_IF_CRITICAL = {};
TARGET_UNPROCESSED_IF_CRITICAL[OID.policyMappings] = true;
Object.freeze(TARGET_UNPROCESSED_IF_CRITICAL);

function unrecognizedCriticalExtension(cert, isTarget) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (!ext.critical) continue;
    if (!intrinsic.hasOwn(PROCESSED_EXTENSIONS, ext.oid)) return ext.oid;
    if (isTarget && intrinsic.hasOwn(TARGET_UNPROCESSED_IF_CRITICAL, ext.oid)) return ext.oid;
  }
  return null;
}

function validateCriticalExtensionStructure(cert) {
  for (var i = 0; i < cert.extensions.length; i++) {
    var ext = cert.extensions[i];
    if (!ext.critical) continue;
    var dec = EXT_DECODERS[ext.oid];
    if (!dec) continue;
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
 * always-on window check), `trustAnchors` (a single { name, publicKey,
 * algorithm, parameters? } anchor or a non-empty array of them; with several,
 * the one that issued the path terminus is selected), the 6.1.1 user-initial
 * inputs (`initialExplicitPolicy`,
 * `initialAnyPolicyInhibit`, `initialPolicyMappingInhibit`,
 * `userInitialPolicySet`, and `initialPermittedSubtrees` /
 * `initialExcludedSubtrees`: arrays of `{ tag, base }` where `tag` is the
 * GeneralName tag number and `base` that form's constraint value), an
 * optional `requiredEku` (key purposes the target's extendedKeyUsage must
 * assert, given as registered OID names or dotted OID strings; an absent
 * extension is unrestricted, RFC 5280 4.2.1.12), and an optional
 * `revocationChecker`. The value-carrying options (`time`, `maxPathCerts`,
 * `maxPolicyNodes`, the subtree seeds, `userInitialPolicySet`, `requiredEku`)
 * are validated at the entry point. A mis-shaped value throws `path/bad-input`,
 * so it cannot silently go unapplied. Returns `{ valid, revocationChecked, anchorConstraints,
 * path, results, workingPublicKey, workingPublicKeyAlgorithm,
 * workingPublicKeyParameters, validPolicyTree, userConstrainedPolicySet }` where `results[i].checks`
 * carries a per-check reason code (`path/*`) for every step. Pure and
 * re-entrant: no input object is mutated. An empty path or a missing anchor
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
 * date, the `purposes` delegator map and the `nameConstraints` namespace each
 * applied. The purpose-keyed metadata is keyed BY key purpose, so an anchor
 * carrying it while `opts.checkPurpose` is absent is a configuration fault
 * (`path/bad-input`). A silently inert constraint would let a root distrusted
 * years ago quietly validate a current leaf.
 *
 * An anchor may also carry `nameConstraints`, a `{ permitted, excluded }` pair
 * of `{ tag, base }` subtrees naming the namespace that root is trusted for.
 * A root program restricts a root this way when the restriction appears in no
 * `nameConstraints` extension the root certificate carries. The subtrees become
 * the RFC 5280 sec. 6.1.1(h)(i) initial permitted and excluded state, so an
 * intermediate's own `nameConstraints` extension intersects with them and a leaf
 * must satisfy both. They are a separate generation from
 * `opts.initialPermittedSubtrees`, so those two intersect as well. A mis-shaped
 * subtree is refused with `path/bad-input` rather than left inert.
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
 *     trustAnchors: [{ name: cert.issuer, publicKey: cert.subjectPublicKeyInfo.bytes,
 *       algorithm: cert.subjectPublicKeyInfo.algorithm.oid }],
 *   });
 *   res.valid;  // boolean; res.results[0].checks carries the per-check codes
 */
var _VALIDATE_OPTS = {
  checkPurpose: 1, ctLogList: 1, ctPolicy: 1, historicalMode: 1, initialAnyPolicyInhibit: 1,
  initialExcludedSubtrees: 1, initialExplicitPolicy: 1, initialPermittedSubtrees: 1,
  initialPolicyMappingInhibit: 1, maxPathCerts: 1, maxPolicyNodes: 1, requireRevocation: 1,
  requiredEku: 1, revocationChecker: 1, softFail: 1, time: 1, trustAnchors: 1,
  userInitialPolicySet: 1, verifier: 1
};

var OID_SCT_LIST = oid.byName("signedCertificateTimestampList");
async function ctGateCheck(leaf, certs, anchor, ctLogList, ctPolicy, n, at) {
  var exts = leaf.extensions || [], sctExt = null;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i] && (exts[i].oid === OID_SCT_LIST || exts[i].name === "signedCertificateTimestampList")) { sctExt = exts[i]; break; }
  }
  if (sctExt == null) return guard.verdict.of({ name: "ct", ok: false, code: "path/ct-required" });
  var issuer = n >= 2 ? certs[n - 2] : { subjectPublicKeyInfo: { bytes: anchor.publicKey } };
  var entry, list;
  try {
    entry = ct.x509CertEntry(leaf, issuer);
    list = ct.parseSctList(sctExt.value);
  } catch (e) {
    return guard.verdict.of({ name: "ct", ok: false, code: pathCode(e, "path/ct-required") });
  }
  var verdict;
  try {
    verdict = await ct.verifySctList(entry, list, ctLogList,
      { minScts: ctPolicy.minScts, minOperators: ctPolicy.minOperators, certNotAfter: leaf.validity.notAfter, at: at });
  } catch (e) {
    if (e && e.isPkiError) throw E("path/bad-input", "validate: the CT policy or log-list is invalid (" + (e.code || "ct/bad-input") + "): " + e.message);
    throw e;
  }
  return guard.verdict.of({ name: "ct", ok: verdict.policyOk === true, code: verdict.policyOk ? undefined : "path/ct-policy-not-met" });
}

async function validate(path, opts) {
  opts = guard.identifier.optionsObject(opts, E, "path/bad-input", "validate: opts");
  guard.identifier.assertKnownKeys(opts, _VALIDATE_OPTS, E, "path/bad-input",
    "pki.path.validate has an unknown option (the anchor option is `trustAnchors`, a single anchor or an array). The unknown option was: ");
  if (opts.ctPolicy != null && opts.ctLogList == null) throw E("path/bad-input", "validate: opts.ctPolicy requires opts.ctLogList (the trusted CT log-list to verify the certificate's SCTs against)");
  if (opts.ctLogList != null) {
    if (typeof opts.ctLogList !== "object" || opts.ctLogList.byLogId == null) throw E("path/bad-input", "validate: opts.ctLogList must be a pki.ct.parseLogList result");
    var ctp = guard.identifier.optionsObject(opts.ctPolicy, E, "path/bad-input", "validate: opts.ctPolicy");
    guard.identifier.assertKnownKeys(ctp, { minScts: 1, minOperators: 1 }, E, "path/bad-input", "validate: opts.ctPolicy has an unknown key (the CT policy keys are minScts / minOperators): ");
    if (ctp.minScts != null && (typeof ctp.minScts !== "number" || !intrinsic.isInteger(ctp.minScts) || ctp.minScts < 1)) throw E("path/bad-input", "validate: opts.ctPolicy.minScts must be a positive integer");
    if (ctp.minOperators != null && (typeof ctp.minOperators !== "number" || !intrinsic.isInteger(ctp.minOperators) || ctp.minOperators < 1)) throw E("path/bad-input", "validate: opts.ctPolicy.minOperators must be a positive integer");
  }
  if (!intrinsic.isArray(path)) throw E("path/bad-input", "validate: path must be an array of certificates");
  var maxCerts = guard.limits.cap(opts.maxPathCerts, "validate: opts.maxPathCerts", constants.LIMITS.PATH_MAX_CERTS, { E: E, code: "path/bad-input", min: 1 });
  if (path.length > maxCerts) throw E("path/bad-input", "validate: the certification path has " + path.length + " certificates, exceeding the maxPathCerts limit (" + maxCerts + ")");
  var certs = path.map(function (c, ci) { return coerceCert(c, "validate: path[" + ci + "]"); });
  var n = certs.length;
  if (n < 1) throw E("path/empty-path", "validate: the certification path is empty");
  /** @internal Captured before any anchor is normalized: an anchor field may be an accessor, and
   * that getter runs caller code which could otherwise clear these lists first. */
  var callerPermitted = checkedSubtreeSeeds(opts.initialPermittedSubtrees, "initialPermittedSubtrees");
  var callerExcluded = checkedSubtreeSeeds(opts.initialExcludedSubtrees, "initialExcludedSubtrees");
  var rawAnchors = opts.trustAnchors;
  var anchorList = intrinsic.isArray(rawAnchors) ? rawAnchors : [rawAnchors];
  if (rawAnchors == null || anchorList.length === 0) throw E("path/bad-input", "validate: trustAnchors is required (a single anchor or a non-empty array of anchors)");
  /** @internal Read the caller's list once here, whatever its length, so neither branch below reads
   * one of its indices twice. */
  if (intrinsic.isArray(rawAnchors)) anchorList = _ownAnchorEntries(rawAnchors, "validate");
  if (anchorList.length > 1) {
    var anchorEntries = anchorList;
    var preNc = _precaptureAnchorNameConstraints(anchorEntries, "validate");
    var tuples = [];
    for (var ti = 0; ti < anchorEntries.length; ti++) {
      tuples[ti] = toAnchor(anchorEntries[ti], "validate");
      if (preNc[ti] !== undefined) intrinsic.defineProperty(tuples[ti], "nameConstraints", { value: preNc[ti], enumerable: true, configurable: true, writable: true });
    }
    /** @internal Each anchor is a separate attempt and the later ones run after an await, so the
     * caller's own subtree lists are read once here rather than again per attempt. */
    var permRawOnce = opts.initialPermittedSubtrees;
    var exclRawOnce = opts.initialExcludedSubtrees;
    var singleOpts = function (a) {
      var keys = intrinsic.ownKeys(opts);
      var o = {};
      for (var ki = 0; ki < keys.length; ki++) { o[keys[ki]] = opts[keys[ki]]; }
      o.trustAnchors = a;
      if (permRawOnce != null) o.initialPermittedSubtrees = callerPermitted;
      if (exclRawOnce != null) o.initialExcludedSubtrees = callerExcluded;
      return o;
    };
    var lastMatched = null, anyMatched = false;
    for (var ai = 0; ai < tuples.length; ai++) {
      if (!dnEqual(tuples[ai].name.rdns, certs[0].issuer.rdns)) continue;
      anyMatched = true;
      var oneRes = await validate(path, singleOpts(tuples[ai]));
      if (oneRes && oneRes.valid) return oneRes;
      lastMatched = oneRes;
    }
    return anyMatched ? lastMatched : validate(path, singleOpts(tuples[0]));
  }
  var anchor = toAnchor(anchorList[0], "validate");
  guard.time.assertValid(opts.time, E, "path/bad-input", "validate: opts.time (the always-on validity-window check date)");
  guard.limits.cap(opts.maxPolicyNodes, "validate: opts.maxPolicyNodes", undefined, { E: E, code: "path/bad-input", min: 1 });
  _assertUserInitialPolicySet(opts.userInitialPolicySet, "validate");
  var anchorNc = _anchorSubtreeSeeds(anchor);
  var seeds = {
    permittedGenerations: [callerPermitted, anchorNc.permitted],
    excluded: intrinsic.concat(callerExcluded, anchorNc.excluded),
  };
  var anchorNameConstraintsApplied = anchorNc.permitted.length > 0 || anchorNc.excluded.length > 0;
  var purposeOpts = resolvePurposeOpts(opts);
  var requiredEku = purposeOpts.requiredEku;
  var checkPurpose = purposeOpts.checkPurpose;

  var state = initialize(certs, opts, seeds, anchor);
  state._n = n;
  state.requiredEku = requiredEku;
  var verifier = opts.verifier || null;
  var revocationChecker = opts.revocationChecker || null;
  var softFail = opts.softFail === true;
  var requireRevocation = opts.requireRevocation === true;
  var failed = false;
  var revocationRan = false, revocationWaived = false, revocationUndetermined = false;
  var anchorDistrustApplied = false, anchorPurposeApplied = false;
  if (!checkPurpose && _hasPurposeScopedMetadata(anchor)) {
    throw E("path/bad-input", "validate: the trust anchor carries purpose-scoped metadata (distrustAfter / purposes), which is keyed by key purpose -- supply opts.checkPurpose to say which purpose this validation is for, or the constraint cannot be applied");
  }

  for (var idx = 0; idx < n; idx++) {
    var i = idx + 1;
    var cert = certs[idx];
    var checks = [];

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
    guard.list.append(checks, { name: "signature", ok: sigRes.ok, code: sigRes.ok ? undefined : (sigRes.code || "path/bad-signature") });
    if (!sigRes.ok) failed = true;

    if (compositeSig.COMPOSITE_ALGS[cert.subjectPublicKeyInfo.algorithm.oid]) {
      var cku = compositeKeyUsageCheck(cert);
      guard.list.append(checks,{ name: "compositeKeyUsage", ok: cku.ok, code: cku.ok ? undefined : cku.code });
      if (!cku.ok) failed = true;
    }

    if (ML_KEM_OIDS[cert.subjectPublicKeyInfo.algorithm.oid]) {
      var kku = kemKeyUsageCheck(cert);
      guard.list.append(checks,{ name: "kemKeyUsage", ok: kku.ok, code: kku.ok ? undefined : kku.code });
      if (!kku.ok) failed = true;
    }

    var t = guard.time.instantOf(opts.time);
    var vOk = true, vCode;
    if (t < guard.time.instantOf(cert.validity.notBefore)) { vOk = false; vCode = "path/not-yet-valid"; }
    else if (t > guard.time.instantOf(cert.validity.notAfter)) { vOk = false; vCode = "path/expired"; }
    guard.list.append(checks,{ name: "validity", ok: vOk, code: vCode });
    if (!vOk) failed = true;

    var chainOk;
    try { chainOk = dnEqual(cert.issuer.rdns, state.workingIssuerName.rdns); }
    catch (_e) { chainOk = false; }
    guard.list.append(checks,{ name: "nameChaining", ok: chainOk === true, code: chainOk === true ? undefined : "path/name-chaining" });
    if (chainOk !== true) failed = true;

    if (!(selfIssued(cert) && i !== n)) {
      var ncRes;
      try { ncRes = checkNameConstraints(state, cert); }
      catch (e) { ncRes = { ok: false, code: pathCode(e, "path/bad-name-constraints") }; }
      guard.list.append(checks,{ name: "nameConstraints", ok: ncRes.ok, code: ncRes.ok ? undefined : ncRes.code });
      if (!ncRes.ok) failed = true;
    }

    if (revocationChecker) {
      var issuerCert = idx > 0 ? certs[idx - 1] : null;
      var rv, rvError = null;
      try { rv = await revocationChecker.check(cert, { workingIssuerName: state.workingIssuerName, workingPublicKey: state.workingPublicKey, workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm, issuerCert: issuerCert }, { time: opts.time, historicalMode: opts.historicalMode === true }); }
      catch (e) { rv = { status: "error" }; rvError = e; }
      var rvStatus = (rv && typeof rv.status === "string") ? rv.status : "unknown";
      if (rv && rv.status === "good") { guard.list.append(checks,{ name: "revocation", ok: true, status: "good" }); }
      else if (rv && rv.status === "revoked") { guard.list.append(checks,{ name: "revocation", ok: false, status: "revoked", code: "path/revoked" }); failed = true; }
      else if (rvError) {
        guard.list.append(checks,{ name: "revocation", ok: false, status: "error", code: "path/revocation-checker-error", error: rvError });
        revocationUndetermined = true;
        failed = true;
      }
      else if (softFail) {
        guard.list.append(checks,{ name: "revocation", ok: true, status: rvStatus, waived: true });
        revocationWaived = true;
      } else {
        guard.list.append(checks,{ name: "revocation", ok: false, status: rvStatus, code: "path/revocation-undetermined" });
        revocationUndetermined = true;
        failed = true;
      }
      revocationRan = true;
    } else if (requireRevocation) {
      guard.list.append(checks,{ name: "revocation", ok: false, code: "path/revocation-undetermined" }); failed = true;
    }

    var polRes = processPolicies(state, cert, i, checks);
    if (state._capHit) { guard.list.append(checks,{ name: "policyTree", ok: false, code: "path/policy-tree-cap" }); failed = true; }
    else if (polRes.fatal) failed = true;

    if (cert.subject.rdns.length === 0) {
      var san = findExt(cert, OID.subjectAltName);
      if (!san || !san.critical) { guard.list.append(checks,{ name: "emptySubject", ok: false, code: "path/empty-subject-no-critical-san" }); failed = true; }
    }

    if (i !== n) {
      if (!state._capHit) {
        var prep = prepareNext(state, cert, i, checks);
        if (prep.fatal) failed = true;
      }
    } else {
      if (state.explicitPolicy > 0) state.explicitPolicy--;
      var lpc;
      try { lpc = decodeExt(cert, OID.policyConstraints); }
      catch (_e) { lpc = null; guard.list.append(checks,{ name: "policyConstraints", ok: false, code: "path/bad-policy" }); failed = true; }
      if (requireCriticalExt(lpc, "policyConstraints", checks)) failed = true;
      if (lpc && lpc.value.requireExplicitPolicy === 0) state.explicitPolicy = 0;
      var lpm;
      try { lpm = decodeExt(cert, OID.policyMappings); }
      catch (_e) { lpm = null; guard.list.append(checks,{ name: "policyMappings", ok: false, code: "path/bad-policy" }); failed = true; }
      if (lpm && mapsAnyPolicy(lpm.value)) {
        guard.list.append(checks,{ name: "policyMappings", ok: false, code: "path/bad-policy" }); failed = true;
      }
      var lnc;
      try { lnc = decodeExt(cert, OID.nameConstraints); }
      catch (e) { lnc = null; guard.list.append(checks,{ name: "nameConstraints", ok: false, code: pathCode(e, "path/bad-name-constraints") }); failed = true; }
      if (requireCriticalExt(lnc, "nameConstraints", checks)) failed = true;
      var liap;
      try { liap = decodeExt(cert, OID.inhibitAnyPolicy); }
      catch (e) { liap = null; guard.list.append(checks,{ name: "inhibitAnyPolicy", ok: false, code: pathCode(e, "path/bad-policy") }); failed = true; }
      if (requireCriticalExt(liap, "inhibitAnyPolicy", checks)) failed = true;
      if (requiredEku && ekuPurposeFails(cert, requiredEku, checks)) failed = true;
      var ta = anchor;
      var distrustDate = assertAnchorConstraints(ta, checkPurpose);
      if (distrustDate != null) {
        anchorDistrustApplied = true;
        if (guard.time.instantOf(cert.validity.notBefore) > guard.time.instantOf(distrustDate)) {
          guard.list.append(checks,{ name: "distrustAfter", ok: false, code: "path/distrusted-after" }); failed = true;
        }
      }
      if (checkPurpose && ta.purposes) {
        anchorPurposeApplied = true;
        if (!intrinsic.hasOwn(ta.purposes, checkPurpose) || ta.purposes[checkPurpose] !== true) {
          guard.list.append(checks,{ name: "purposeTrust", ok: false, code: "path/purpose-not-trusted" }); failed = true;
        }
      }
      updateWorkingKey(state, cert);
    }

    var unk = unrecognizedCriticalExtension(cert, i === n);
    if (unk) { guard.list.append(checks,{ name: "criticalExtensions", ok: false, code: "path/unrecognized-critical-extension" }); failed = true; }

    var crit = validateCriticalExtensionStructure(cert);
    if (crit) { guard.list.append(checks,{ name: "criticalExtensionValue", ok: false, code: crit }); failed = true; }

    guard.list.append(state.results, { index: idx, checks: checks });
  }

  var ucps = userConstrainedPolicies(state, n);
  var policyOk = state.explicitPolicy > 0 || ucps.length > 0;
  if (!policyOk) {
    var last = state.results[state.results.length - 1];
    if (!guard.list.anyMatches(last.checks, function (c) { return c.code === "path/policy-required"; })) {
      guard.list.append(last.checks, { name: "policy", ok: false, code: "path/policy-required" });
    }
    failed = true;
  }

  if (opts.ctLogList != null) {
    var ctCheck = await ctGateCheck(certs[n - 1], certs, anchor, opts.ctLogList, opts.ctPolicy || {}, n, opts.time);
    var target = null;
    for (var tr = 0; tr < state.results.length; tr++) { if (state.results[tr].index === n - 1) { target = state.results[tr]; break; } }
    if (target) guard.list.append(target.checks, ctCheck);
    if (!ctCheck.ok) failed = true;
  }

  return guard.verdict.of({
    valid: !failed,
    revocationChecked: !revocationRan ? false
      : revocationUndetermined ? "undetermined"
        : revocationWaived ? "waived" : "determined",
    anchorConstraints: {
      checkedPurpose: checkPurpose || null,
      distrustAfterApplied: anchorDistrustApplied,
      purposeTrustApplied: anchorPurposeApplied,
      nameConstraintsApplied: anchorNameConstraintsApplied,
    },
    path: certs,
    results: state.results,
    workingPublicKey: state.workingPublicKey,
    workingPublicKeyAlgorithm: state.workingPublicKeyAlgorithm,
    workingPublicKeyParameters: state.workingPublicKeyParameters,
    validPolicyTree: treeWithoutParent(state.validPolicyTree),
    userConstrainedPolicySet: ucps,
  });
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
  if (hasAnyLeaf) {
    if (anyUser) set[OID.anyPolicy] = true;
    else uips.forEach(function (p) { set[p] = true; });
  }
  return Object.keys(set);
}


var OID_IDP = oid.byName("issuingDistributionPoint");
var OID_DELTA_CRL = oid.byName("deltaCRLIndicator");
var OID_AUTHORITY_KEY_ID = oid.byName("authorityKeyIdentifier");
var OID_CRL_NUMBER = oid.byName("cRLNumber");
var OID_FRESHEST_CRL = oid.byName("freshestCRL");

var IDP_SCHEMA = pkix.issuingDistributionPoint("path/bad-idp");

var ALL_REASONS = 0x1FE;

function reasonMaskFromBitString(bs) {
  if (!bs || !bs.bytes) return null;
  try { schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (msg) { throw E("path/bad-idp", msg); }); }
  catch (_e) { return null; }
  var mask = 0;
  for (var bit = 1; bit <= 8; bit++) {
    var byteI = bit >> 3;
    if (byteI >= bs.bytes.length) break;
    if (bs.bytes[byteI] & (0x80 >> (bit & 7))) mask |= (1 << bit);
  }
  return mask;
}

function interimReasonMask(idpMask, dpMask) {
  if (idpMask != null && dpMask != null) return idpMask & dpMask;
  if (idpMask != null) return idpMask;
  if (dpMask != null) return dpMask;
  return ALL_REASONS;
}

function decodeIdp(ext) {
  var out = { hasDistributionPoint: false, distributionPoint: null, onlyUser: false, onlyCa: false, onlySomeReasons: null, indirect: false, onlyAttr: false, malformed: false };
  var m;
  try {
    m = schema.walk(IDP_SCHEMA, asn1.decode(ext.value), NS);
    if (m.fields.distributionPoint.present) {
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
    var isSet = f.value === true;
    if (!isSet) out.malformed = true;
    return isSet;
  }
  out.hasDistributionPoint = m.fields.distributionPoint.present;
  out.onlyUser = flag(m.fields.onlyContainsUserCerts);
  out.onlyCa = flag(m.fields.onlyContainsCACerts);
  out.onlySomeReasons = m.fields.onlySomeReasons.present ? true : null;
  out.onlySomeReasonsMask = null;
  if (m.fields.onlySomeReasons.present) {
    out.onlySomeReasonsMask = reasonMaskFromBitString(m.fields.onlySomeReasons.value);
    if (out.onlySomeReasonsMask === null) out.malformed = true;
  }
  out.indirect = flag(m.fields.indirectCRL);
  out.onlyAttr = flag(m.fields.onlyContainsAttributeCerts);
  return out;
}

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

function crlIssuerNamesIssuer(cRLIssuer, issuerRdns) {
  for (var i = 0; i < cRLIssuer.names.length; i++) {
    var n = cRLIssuer.names[i];
    if (n.tagNumber !== 4 || !n.value || !n.value.rdns) continue;
    try { if (dnEqual(n.value.rdns, issuerRdns)) return true; }
    catch (_e) { return false; }
  }
  return false;
}

function crlExtValue(theCrl, wantOid) {
  for (var i = 0; i < theCrl.crlExtensions.length; i++) {
    if (theCrl.crlExtensions[i].oid === wantOid) return theCrl.crlExtensions[i].value;
  }
  return null;
}

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
    var num = crlExtValue(theCrl, OID_CRL_NUMBER);
    var rec = {
      crl: theCrl,
      crlNumber: crlNumberWithinBound(num) ? num : null,
      idpRaw: crlExtValue(theCrl, OID_IDP),
      akiRaw: crlExtValue(theCrl, OID_AUTHORITY_KEY_ID),
      baseCrlNumber: null,
      mergeable: false,
    };
    if (deltaRaw === null) { guard.list.append(completes, rec); continue; }
    try {
      var n = asn1.read.integer(asn1.decode(deltaRaw));
      if (crlNumberWithinBound(n) && deltaCritical) { rec.baseCrlNumber = n; rec.mergeable = true; }
    } catch (_e) {
    }
    guard.list.append(deltas, rec);
  }
  return { completes: completes, deltas: deltas };
}

function deltaMergesWith(delta, complete) {
  if (!delta.mergeable) return false;
  if (complete.crlNumber === null || delta.crlNumber === null) return false;
  if (!dnEqualUsable(delta.crl.issuer.rdns, complete.crl.issuer.rdns)) return false;
  if (!sameRawExt(delta.idpRaw, complete.idpRaw)) return false;
  if (!sameRawExt(delta.akiRaw, complete.akiRaw)) return false;
  if (!(complete.crlNumber >= delta.baseCrlNumber)) return false;
  if (!(complete.crlNumber < delta.crlNumber)) return false;
  return true;
}
function dnEqualUsable(a, b) {
  try { return dnEqual(a, b); }
  catch (_e) { return false; }
}

function sameRawExt(a, b) {
  if (a === null && b === null) return true;
  if (a === null || b === null) return false;
  return a.equals(b);
}

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
 * certificate's own cRLDistributionPoints: at least one identically-encoded
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
    return guard.parsed.acceptDerived(c, "crl", crl.parse, E, "path/bad-input",
      "crlChecker: crls[" + ci + "]");
  });
  var useDeltas = !(opts && opts.useDeltas === false);
  return {
    check: async function (cert, issuer, ctx) {
      var time = ctx.time;
      var historical = ctx.historicalMode === true;
      var certIsCa = null, certScopeFault = null;
      try {
        var bc = decodeExt(cert, OID.basicConstraints);
        certIsCa = !!(bc && bc.value.cA === true);
      } catch (e) {
        certScopeFault = pathCode(e, "path/bad-extension-value");
      }
      var certDPs = null;
      var certCdpExt = findExt(cert, OID.cRLDistributionPoints);
      if (certCdpExt) {
        try { certDPs = EXT_DECODERS[OID.cRLDistributionPoints](certCdpExt.value); }
        catch (_e) { certDPs = null; }
      }
      var signerAuthorized = true;
      if (issuer && issuer.issuerCert) {
        var iku;
        try { iku = decodeExt(issuer.issuerCert, OID.keyUsage); }
        catch (e) {
          return guard.verdict.of({ status: "unknown", reason: "the CRL issuer's keyUsage extension is unreadable (" + pathCode(e, "path/bad-key-usage") + "), so its authorization to sign CRLs cannot be verified" });
        }
        if (iku && iku.value.cRLSign !== true) signerAuthorized = false;
      }

      var certStatus = null;
      var reasonsMask = 0;
      var releasedByUnmergedDelta = false;
      var sawUnmergedDelta = false;
      var classified = classifyCrls(parsed);
      var consumedDeltas = [];

      async function gateCrl(rec) {
        if (rec._gated) return rec._gate;
        rec._gate = await gateCrlUncached(rec);
        rec._gated = true;
        return rec._gate;
      }
      async function gateCrlUncached(rec) {
        var theCrl = rec.crl;
        var issuerMatches;
        try { issuerMatches = dnEqual(theCrl.issuer.rdns, cert.issuer.rdns); }
        catch (_e) { return null; }
        if (!issuerMatches) return null;
        if (!signerAuthorized) return null;

        var unhandledCritical = false;
        for (var x = 0; x < theCrl.crlExtensions.length; x++) {
          var xe = theCrl.crlExtensions[x];
          if (xe.critical && xe.oid !== OID_IDP && xe.oid !== OID_DELTA_CRL) { unhandledCritical = true; break; }
        }
        for (var ry = 0; ry < theCrl.revokedCertificates.length && !unhandledCritical; ry++) {
          var ees = theCrl.revokedCertificates[ry].crlEntryExtensions || [];
          for (var ex = 0; ex < ees.length; ex++) {
            if (ees[ex].critical && ees[ex].oid !== OID_REASON_CODE) { unhandledCritical = true; break; }
          }
        }
        if (unhandledCritical) return null;

        var noCoverage = false;
        var idpMask = null, dpMask = null, sawIdp = false;
        var idpExtension = null;
        for (var e = 0; e < theCrl.crlExtensions.length; e++) if (theCrl.crlExtensions[e].oid === OID_IDP) idpExtension = theCrl.crlExtensions[e];
        if (idpExtension) {
          sawIdp = true;
          var idp = decodeIdp(idpExtension);
          if (idp.malformed) return null;
          if (idp.indirect) return null;
          if (idp.onlyAttr) return null;
          if (idp.onlyCa && certIsCa !== true) return null;
          if (idp.onlyUser && certIsCa !== false) return null;
          if (idpExtension.critical === true) idpMask = idp.onlySomeReasonsMask;
          else if (idp.onlySomeReasons) noCoverage = true;
          if (idp.hasDistributionPoint) {
            var matchedDp = idpExtension.critical === true
              ? correspondingCertDp(idp.distributionPoint, certDPs, cert.issuer.rdns)
              : null;
            if (!matchedDp) noCoverage = true;
            else if (matchedDp.reasons) {
              dpMask = reasonMaskFromBitString(matchedDp.reasons);
              if (dpMask === null) noCoverage = true;
            }
          }
        }
        if (guard.time.instantOf(theCrl.thisUpdate) > guard.time.instantOf(time)) return null;
        if (!theCrl.nextUpdate ||
          guard.time.instantOf(theCrl.nextUpdate) < guard.time.instantOf(time)) return null;

        var sigOk = await crlVerify.verifyCrlSignature(theCrl, issuer.workingPublicKey);
        if (!sigOk) return null;

        void sawIdp;
        return { interim: noCoverage ? 0 : interimReasonMask(idpMask, dpMask) };
      }

      function scanCrl(theCrl) {
        for (var r = 0; r < theCrl.revokedCertificates.length; r++) {
          var entry = theCrl.revokedCertificates[r];
          if (entry.serialNumberHex !== cert.serialNumberHex) continue;
          // allow:nan-date-comparison-unguarded -- revocationDate is codec-parsed (NaN-rejected); a NaN check time makes this FAIL CLOSED (the skip is not taken -> the entry is treated as revoked), and `time` is validated at the path.validate / crlChecker entry points.
          if (historical && guard.time.isDate(entry.revocationDate) &&
            guard.time.instantOf(entry.revocationDate) > guard.time.instantOf(time)) continue;
          var rc = crlEntryReason(entry);
          return rc === null ? 0 : rc;
        }
        return null;
      }

      var certHasFreshest = !!findExt(cert, OID_FRESHEST_CRL);
      function deltaLocatorPresent(completeRec) {
        return certHasFreshest || crlExtValue(completeRec.crl, OID_FRESHEST_CRL) !== null;
      }

      for (var ci = 0; ci < classified.completes.length; ci++) {
        var rec = classified.completes[ci];
        var gate = await gateCrl(rec);
        if (!gate) continue;

        var chosenDelta = null;
        if (useDeltas && deltaLocatorPresent(rec)) {
          var candidates = [];
          for (var di = 0; di < classified.deltas.length; di++) {
            var cand = classified.deltas[di];
            if (!deltaMergesWith(cand, rec)) continue;
            if (!(await gateCrl(cand))) continue;
            cand.accounted = true;
            guard.list.append(candidates, cand);
          }
          chosenDelta = selectDelta(candidates);
        }

        var status;
        if (chosenDelta) {
          guard.list.append(consumedDeltas, chosenDelta);
          status = scanCrl(chosenDelta.crl);
          if (status === null) status = scanCrl(rec.crl);
        } else {
          status = scanCrl(rec.crl);
        }
        if (status === 8) status = null;

        if (status !== null && certStatus === null) certStatus = status;
        else if (status === null) reasonsMask |= gate.interim;
      }

      for (var dj = 0; dj < classified.deltas.length; dj++) {
        var dRec = classified.deltas[dj];
        if (contains(consumedDeltas, dRec)) continue;
        if (dRec.accounted) continue;
        if (!(await gateCrl(dRec))) continue;
        sawUnmergedDelta = true;
        var dStatus = scanCrl(dRec.crl);
        if (dStatus === null) continue;
        if (dStatus === 8) { releasedByUnmergedDelta = true; continue; }
        if (certStatus === null) certStatus = dStatus;
      }

      if (releasedByUnmergedDelta) return guard.verdict.of({ status: "unknown", reason: "a delta CRL released this serial from hold; without merging its base CRL the revocation status is undetermined" });
      if (certStatus !== null) {
        var reasonName = constants.NAMES.CRL_REASON[String(certStatus)] || "unspecified";
        return guard.verdict.of({ status: "revoked", reasonCode: certStatus, reason: "serial listed in a CRL (" + reasonName + ")" });
      }
      if (sawUnmergedDelta) return guard.verdict.of({ status: "unknown", reason: "a delta CRL cannot be combined with any complete CRL held here, so the revocation picture is incomplete" });
      if ((reasonsMask & ALL_REASONS) === ALL_REASONS) return guard.verdict.of({ status: "good" });
      if (certScopeFault) {
        return guard.verdict.of({ status: "unknown", reason: "no authoritative in-scope CRL covers this certificate; its basicConstraints extension is unreadable (" + certScopeFault + "), so scope-limited CRLs were skipped" });
      }
      if (reasonsMask !== 0) {
        return guard.verdict.of({ status: "unknown", reason: "the CRLs available cover only some revocation reasons for this certificate; no combination covers all of them" });
      }
      return guard.verdict.of({ status: "unknown", reason: "no authoritative in-scope CRL covers this certificate" });
    },
  };
}

var OID_REASON_CODE = oid.byName("reasonCode");
function crlEntryReason(entry) {
  var exts = entry.crlEntryExtensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid === OID_REASON_CODE) return exts[i].value;
  }
  return null;
}

function _verifyWithSpki(sigAlg, rawSig, spkiBytes, tbsBytes) {
  var d;
  try {
    d = resolveDescriptor(sigAlg);
    assertKeyMatchesSigAlg(spkiBytes, sigAlg.oid, d);
  } catch (_e) { return Promise.resolve(false); }
  if (d.composite) return compositeSig.compositeVerify(spkiBytes, rawSig, tbsBytes, d.composite, PathError, "path/unsupported-algorithm", "path/bad-signature").then(function (r) { return r.ok === true; });
  return _importVerifyKey(spkiBytes, d).then(function (key) {
    var sig = rawSig;
    if (d.ecdsa) sig = validator.sig.ecdsaDerToP1363(sig, key.algorithm.namedCurve, PathError, "path/bad-signature");
    return subtle.verify(d.verify, key, sig, tbsBytes);
  }).then(function (ok) { return ok === true; }, function () { return false; });
}

crlVerify.setEngine(_verifyWithSpki);

csrVerify.setEngine(_verifyWithSpki);

crmfVerify.setEngine(_verifyWithSpki);

attrcertVerify.setEngine(_verifyWithSpki);

ocspRequestVerify.setEngine(_verifyWithSpki);


var ocspCore = ocspVerify.makeOcspVerify({
  verifyWithSpki: _verifyWithSpki,
  decodeExt: decodeExt, findExt: findExt,
  unrecognizedCriticalExtension: unrecognizedCriticalExtension,
  validateCriticalExtensionStructure: validateCriticalExtensionStructure,
  compositeKeyUsageCheck: compositeKeyUsageCheck,
  isNullOrAbsentParams: isNullOrAbsentParams, spliceSpkiParameters: spliceSpkiParameters,
  dnEqual: dnEqual,
});

cmpVerify.setEngine({ verifyWithSpki: _verifyWithSpki, build: build, validate: validate });
cmpSession.setEngine({ build: build, validate: validate, toAnchor: toAnchor, coerceCert: coerceCert, verifyWithSpki: _verifyWithSpki });
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
  var parsed = (responses || []).map(function (r) { return _ocspFromBytes(r); });
  return {
    check: async function (cert, issuer, ctx) {
      var time = ctx.time;
      var historical = ctx.historicalMode === true;
      var issuerNameCandidates = [cert.issuer.bytes];
      function addNameCandidate(nm) {
        if (nm && nm.bytes && !guard.list.anyMatches(issuerNameCandidates, function (e) { return e.equals(nm.bytes); })) guard.list.append(issuerNameCandidates, nm.bytes);
      }
      if (issuer.issuerCert) addNameCandidate(issuer.issuerCert.subject);
      addNameCandidate(issuer.workingIssuerName);
      var issuerKeyBits;
      try { issuerKeyBits = ocspVerify.ocspKeyValue(issuer.workingPublicKey); }
      catch (_e) { return guard.verdict.of({ status: "unknown", reason: "the issuer public key could not be read to recompute the OCSP CertID" }); }

      var revokedResult = null;
      var sawGood = false;
      var sawUnknownStatus = false;

      for (var k = 0; k < parsed.length; k++) {
        var v = await ocspCore.evaluateResponse(parsed[k], cert, issuer, issuerKeyBits, issuerNameCandidates, time, historical);
        if (v.revoked && !revokedResult) {
          revokedResult = guard.verdict.of({ status: "revoked", revocationReason: v.revoked.revocationReason, revocationTime: v.revoked.revocationTime, reason: v.revoked.reason });
        }
        if (v.sawGood) sawGood = true;
        if (v.sawUnknownStatus) sawUnknownStatus = true;
      }
      if (revokedResult) return revokedResult;
      if (sawGood) return guard.verdict.of({ status: "good" });
      return guard.verdict.of({
        status: "unknown",
        reason: sawUnknownStatus
          ? "the OCSP responder reported certStatus unknown for this certificate"
          : "no authoritative, current, in-scope OCSP response covers this certificate",
      });
    },
  };
}

/**
 * @primitive  pki.path.verifyOcspResponse
 * @signature  pki.path.verifyOcspResponse(response, cert, issuerCert, time, opts?) -> Promise<{ valid, status, responderAuthorized, signatureValid, matched, thisUpdate, nextUpdate, revocationReason?, revocationTime?, reason }>
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
 * currency (`thisUpdate`/`nextUpdate`). There is no weaker second OCSP verify
 * path. It is fail-closed and never throws on an unauthorized, stale, or
 * unverifiable response: those yield `{ status: "unknown" }` with the granular
 * `responderAuthorized`/`signatureValid`/`matched` flags and a `reason`; a
 * `revoked` status surfaces its `revocationReason`. Setting `opts.historicalMode`
 * treats a revocation whose `revocationTime` is strictly after `time` as not-yet-
 * revoked (`good`): for validating a signature as of a past `time`, before the
 * certificate was later revoked; the responder certificate is still validated at
 * `time` either way. `time` must be a valid `Date`. A malformed response's parse
 * fault surfaces as the parser's typed `ocsp/*` / `asn1/*` error.
 *
 * The response is its DER bytes, a PEM string, or an unmodified
 * `pki.schema.ocsp.parseResponse` result. A REBUILT parsed response is refused. A
 * signature check has three parts (the signature, the algorithm that verifies it,
 * and the bytes it covers) and on a parsed object all three are separate properties:
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
async function verifyOcspResponse(response, cert, issuerCert, time, opts) {
  var parsedResponse, subject, issuer;
  try {
    parsedResponse = _ocspFromBytes(response);
    subject = coerceCert(cert, "the certificate");
    issuer = coerceCert(issuerCert, "the issuer certificate");
  } catch (e) { return Promise.reject(e); }
  var v = await _verifyOcspParsed(parsedResponse, subject, issuer, time, opts);
  var out = guard.verdict.of(v);
  return guard.verdict.of(out, { valid: out.status === "good" });
}

var _OCSP_CLAIM = ["responseStatus", "basicResponse", "tbsResponseDataBytes"];
function _ocspFromBytes(response) {
  return guard.parsed.fromTrustedSource(response, "ocspResponse", _OCSP_CLAIM, function (bytes) {
    if (!guard.bytes.isByteSource(bytes) && typeof bytes !== "string") {
      throw E("path/bad-input", "verifyOcspResponse: the response must be an OCSP response DER BufferSource, a PEM string, or a pki.schema.ocsp.parseResponse result");
    }
    return ocsp.parseResponse(bytes);
  }, E, "path/bad-input",
  "verifyOcspResponse: the response must be its DER bytes, a PEM string, or an unmodified pki.schema.ocsp.parseResponse result: the signature, the algorithm that verifies it and the bytes it covers are separate properties of a parsed object, so a REBUILT response (Object.assign, spread, a JSON round-trip) could have the three describe different responses and is refused");
}

function _verifyOcspParsed(parsedResponse, cert, issuerCert, time, opts) {
  opts = opts || {};
  if (!guard.time.isDate(time) || isNaN(guard.time.instantOf(time))) {
    return Promise.reject(E("path/bad-input", "verifyOcspResponse: time must be a valid Date (the currency + responder-validity check date)"));
  }
  function unbound(reason) { return guard.verdict.of({ status: "unknown", responderAuthorized: false, signatureValid: false, matched: false, thisUpdate: null, nextUpdate: null, reason: reason }); }
  var boundName;
  try { boundName = dnEqual(cert.issuer.rdns, issuerCert.subject.rdns); }
  catch (e) { return Promise.reject(e); }
  if (!boundName) {
    return Promise.resolve(unbound("the supplied issuer certificate's subject does not match the target certificate's issuer"));
  }
  return builtinVerify({ workingPublicKey: issuerCert.subjectPublicKeyInfo.bytes }, cert).then(function (sig) {
    if (!sig.ok) return unbound("the target certificate's signature does not verify under the supplied issuer certificate's key");
    var issuerCtx = { workingPublicKey: issuerCert.subjectPublicKeyInfo.bytes, workingIssuerName: issuerCert.subject, issuerCert: issuerCert };
    var issuerNameCandidates = [cert.issuer.bytes];
    function add(nm) { if (nm && nm.bytes && !guard.list.anyMatches(issuerNameCandidates, function (e) { return e.equals(nm.bytes); })) guard.list.append(issuerNameCandidates, nm.bytes); }
    add(issuerCert.subject);
    var issuerKeyBits;
    try { issuerKeyBits = ocspVerify.ocspKeyValue(issuerCert.subjectPublicKeyInfo.bytes); }
    catch (_e) { return unbound("the issuer public key could not be read to recompute the OCSP CertID"); }
    return ocspCore.evaluateResponse(parsedResponse, cert, issuerCtx, issuerKeyBits, issuerNameCandidates, time, opts.historicalMode === true).then(function (v) {
      if (v.revoked) return guard.verdict.of({ status: "revoked", responderAuthorized: true, signatureValid: true, matched: true, thisUpdate: v.thisUpdate, nextUpdate: v.nextUpdate, revocationReason: v.revoked.revocationReason, revocationTime: v.revoked.revocationTime, reason: v.revoked.reason });
      if (v.sawGood) return guard.verdict.of({ status: "good", responderAuthorized: true, signatureValid: true, matched: true, thisUpdate: v.thisUpdate, nextUpdate: v.nextUpdate, reason: "good" });
      return guard.verdict.of({ status: "unknown", responderAuthorized: v.responderAuthorized === true, signatureValid: v.signatureValid === true, matched: v.matched === true, thisUpdate: v.thisUpdate, nextUpdate: v.nextUpdate, reason: v.reason });
    });
  });
}


function softDecode(cert, extOid) {
  try { return decodeExt(cert, extOid); }
  catch (_e) { return null; }
}

function nameMatchSoft(rdnsA, rdnsB) {
  try { return dnEqual(rdnsA, rdnsB); }
  catch (_e) { return false; }
}

function coerceCert(input, label) {
  return guard.parsed.acceptDerived(input, "certificate", x509.parse, E, "path/bad-input",
    label || "a certificate");
}

function _hasPurposeScopedMetadata(ta) {
  if (!ta || typeof ta !== "object") return false;
  return guard.list.anyMatches(["distrustAfter", "purposes"], function (k) {
    var m = ta[k];
    return !!m && typeof m === "object" && intrinsic.getOwnPropertyNames(m).length > 0;
  });
}

function assertAnchorConstraints(ta, checkPurpose) {
  if (!checkPurpose || !ta) return null;
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
      if (_startsWithDigit(p)) return guard.identifier.assertCanonicalOid(p, E, "path/bad-input", "validate: opts.requiredEku entry " + JSON.stringify(p));
      var dotted = oid.byName(p);
      if (typeof dotted !== "string") throw E("path/bad-input", "validate: opts.requiredEku entry " + guard.text.showValue(p) + " is not a registered OID name");
      return dotted;
    });
  }
  var checkPurpose = null;
  if (opts.checkPurpose !== undefined) {
    if (typeof opts.checkPurpose !== "string" || opts.checkPurpose.length === 0) {
      throw E("path/bad-input", "validate: opts.checkPurpose must be a key-purpose OID name or dotted OID string");
    }
    if (_startsWithDigit(opts.checkPurpose)) {
      var cpDotted = guard.identifier.assertCanonicalOid(opts.checkPurpose, E, "path/bad-input", "validate: opts.checkPurpose");
      checkPurpose = oid.name(cpDotted) || cpDotted;
    } else {
      if (typeof oid.byName(opts.checkPurpose) !== "string") throw E("path/bad-input", "validate: opts.checkPurpose " + guard.text.showValue(opts.checkPurpose) + " is not a registered OID name");
      checkPurpose = opts.checkPurpose;
    }
  }
  return { requiredEku: requiredEku, checkPurpose: checkPurpose };
}

function _snapshotConstraintMap(m, E, code, who) {
  var out = {};
  var proto = intrinsic.getPrototypeOf(m);
  if (proto !== null && proto !== intrinsic.ObjectProto) throw E(code, who + ": a trustAnchor constraint map must be a plain object (its own entries only), not one with a custom or cross-realm prototype");
  var keys = intrinsic.getOwnPropertyNames(m);
  if (intrinsic.ownKeys(m).length !== keys.length) throw E(code, who + ": a trustAnchor constraint map must not have symbol-keyed entries");
  for (var i = 0; i < keys.length; i++) {
    if (keys[i] === "__proto__") throw E(code, who + ": a trustAnchor constraint map must not have an own __proto__ entry");
    var d = intrinsic.getOwnPropertyDescriptor(m, keys[i]);
    if (!d || !intrinsic.hasOwn(d, "value")) throw E(code, who + ": a trustAnchor constraint-map entry must be a data property, not an accessor");
    var v = d.value;
    if (intrinsic.types.isDate(v)) v = new intrinsic.Date(guard.time.instantOf(v));
    intrinsic.defineProperty(out, keys[i], { value: v, enumerable: true, configurable: true, writable: true });
  }
  return out;
}

function _normalizeConstraintField(v, E, code, who) {
  if (v === null || v === undefined) return v;
  if (typeof v !== "object" || intrinsic.isBuffer(v)) throw E(code, who + ": a trustAnchor constraint map must be a plain object");
  return _snapshotConstraintMap(v, E, code, who);
}

function _captureConstraintMap(entry, key, E, code, who) {
  var d = intrinsic.getOwnPropertyDescriptor(entry, key);
  if (d === undefined) {
    if (key in entry) throw E(code, who + ": a trustAnchor " + key + " must be an own data property, not inherited");
    return undefined;
  }
  if (!intrinsic.hasOwn(d, "value")) throw E(code, who + ": a trustAnchor " + key + " must be a data property, not an accessor");
  if (intrinsic.types.isProxy(d.value)) throw E(code, who + ": a trustAnchor " + key + " map must not be a Proxy");
  return d.value;
}

function _captureOwnData(entry, key) {
  var d = intrinsic.getOwnPropertyDescriptor(entry, key);
  return (d && intrinsic.hasOwn(d, "value")) ? d.value : undefined;
}

/**
 * @internal Copy the anchor's subtree lists getter-free, so a caller mutating the entry afterwards
 * cannot widen the namespace the validation already resolved.
 */
/**
 * @internal Read a directoryName base's `rdns` once, from its own data property. Reading it twice,
 * to test its shape and then to copy it, lets an accessor answer differently each time and hand the
 * validation an empty DN, which matches every name.
 */
var _ATV_KEYS = ["type", "value", "name"];
/**
 * @internal Build the directoryName's own copy from property descriptors alone, so no caller code
 * runs while the namespace is read: a getter, own or inherited, could clear another part of the
 * namespace before it is captured. A directoryName is a relative-name sequence of attribute lists
 * and nothing deeper, so exactly those levels are walked and a self-referencing array is refused
 * rather than followed.
 */
function _copyDnRdns(rdns, who) {
  _assertPlainDnRdns(rdns, who);
  var out = [];
  for (var i = 0; i < rdns.length; i++) {
    var rd = intrinsic.getOwnPropertyDescriptor(rdns, i);
    if (rd === undefined) throw E("path/bad-input", who + " index " + i + " is a hole or is inherited; every entry must be its own");
    var rdn = rd.value;
    if (!intrinsic.isArray(rdn)) throw E("path/bad-input", who + "[" + i + "] must be an array of attributes");
    var rdnOut = [];
    for (var j = 0; j < rdn.length; j++) {
      var ad = intrinsic.getOwnPropertyDescriptor(rdn, j);
      if (ad === undefined) throw E("path/bad-input", who + "[" + i + "] index " + j + " is a hole or is inherited; every entry must be its own");
      var atv = ad.value;
      if (atv === null || typeof atv !== "object") throw E("path/bad-input", who + "[" + i + "][" + j + "] must be an attribute object carrying a type and a value");
      var atvOut = {};
      for (var k = 0; k < _ATV_KEYS.length; k++) {
        var fd = intrinsic.getOwnPropertyDescriptor(atv, _ATV_KEYS[k]);
        if (fd === undefined) continue;
        intrinsic.defineProperty(atvOut, _ATV_KEYS[k], { value: fd.value, enumerable: true, configurable: true, writable: true });
      }
      if (!intrinsic.hasOwn(atvOut, "type") || !intrinsic.hasOwn(atvOut, "value")) {
        throw E("path/bad-input", who + "[" + i + "][" + j + "] must carry its type and value as own data properties");
      }
      guard.list.append(rdnOut, atvOut);
    }
    guard.list.append(out, rdnOut);
  }
  return out;
}
/**
 * @internal The shape check the copy above relies on: a Proxy answers its own reads and an accessor
 * runs caller code, so either one at any level of the directoryName is refused before it is copied.
 */
function _assertPlainDnRdns(rdns, who) {
  if (intrinsic.types.isProxy(rdns)) throw E("path/bad-input", who + " must be a plain array, not a Proxy");
  for (var i = 0; i < rdns.length; i++) {
    var rd = intrinsic.getOwnPropertyDescriptor(rdns, i);
    if (rd === undefined) continue;
    if (!intrinsic.hasOwn(rd, "value")) throw E("path/bad-input", who + " entry " + i + " must be a data property, not an accessor");
    var rdn = rd.value;
    if (!intrinsic.isArray(rdn)) continue;
    if (intrinsic.types.isProxy(rdn)) throw E("path/bad-input", who + "[" + i + "] must be a plain array, not a Proxy");
    for (var j = 0; j < rdn.length; j++) {
      var ad = intrinsic.getOwnPropertyDescriptor(rdn, j);
      if (ad === undefined) continue;
      if (!intrinsic.hasOwn(ad, "value")) throw E("path/bad-input", who + "[" + i + "] entry " + j + " must be a data property, not an accessor");
      var atv = ad.value;
      if (atv === null || typeof atv !== "object") continue;
      if (intrinsic.types.isProxy(atv)) throw E("path/bad-input", who + "[" + i + "][" + j + "] must not be a Proxy");
      if (intrinsic.isArray(atv)) throw E("path/bad-input", who + "[" + i + "][" + j + "] must be an attribute object, not an array");
      for (var k = 0; k < _ATV_KEYS.length; k++) {
        var fd = intrinsic.getOwnPropertyDescriptor(atv, _ATV_KEYS[k]);
        if (fd !== undefined && !intrinsic.hasOwn(fd, "value")) {
          throw E("path/bad-input", who + "[" + i + "][" + j + "]." + _ATV_KEYS[k] + " must be a data property, not an accessor");
        }
      }
    }
  }
}
function _capturedRdns(base, who) {
  if (intrinsic.types.isProxy(base)) throw E("path/bad-input", who + ": a trustAnchor nameConstraints directoryName base must not be a Proxy");
  /** @internal An inherited Proxy answers `in` through its has trap, which is caller code running
   * inside what is meant to be a getter-free read. */
  var baseProto = intrinsic.getPrototypeOf(base);
  while (baseProto !== null) {
    if (intrinsic.types.isProxy(baseProto)) throw E("path/bad-input", who + ": a trustAnchor nameConstraints directoryName base must not inherit from a Proxy");
    baseProto = intrinsic.getPrototypeOf(baseProto);
  }
  var d = intrinsic.getOwnPropertyDescriptor(base, "rdns");
  if (d === undefined) {
    if ("rdns" in base) throw E("path/bad-input", who + ": a trustAnchor nameConstraints directoryName rdns must be an own data property, not inherited");
    return undefined;
  }
  if (!intrinsic.hasOwn(d, "value")) throw E("path/bad-input", who + ": a trustAnchor nameConstraints directoryName rdns must be a data property, not an accessor");
  if (!intrinsic.isArray(d.value)) return undefined;
  return _copyDnRdns(d.value, who + ": a trustAnchor nameConstraints directoryName rdns");
}
var _NC_SUBTREE_KEYS = ["tag", "base"];
var _NC_LIST_KEYS = ["permitted", "excluded"];
function _copyAnchorSubtreeList(list, key, who) {
  if (list === undefined || list === null) return undefined;
  if (!intrinsic.isArray(list) || intrinsic.types.isProxy(list)) throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " must be a plain array of { tag, base } subtree entries");
  var copied = [];
  var len = list.length;
  for (var i = 0; i < len; i++) {
    var entryD = intrinsic.getOwnPropertyDescriptor(list, i);
    if (entryD === undefined) throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " must not be a sparse array; index " + i + " is a hole");
    if (!intrinsic.hasOwn(entryD, "value")) throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " entry " + i + " must be a data property, not an accessor");
    var st = entryD.value;
    if (st === null || typeof st !== "object" || intrinsic.types.isProxy(st)) {
      throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " entry must be a plain { tag, base } object");
    }
    var out = {};
    for (var k = 0; k < _NC_SUBTREE_KEYS.length; k++) {
      var field = _NC_SUBTREE_KEYS[k];
      var fd = intrinsic.getOwnPropertyDescriptor(st, field);
      if (fd === undefined) continue;
      if (!intrinsic.hasOwn(fd, "value")) throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " " + field + " must be a data property, not an accessor");
      var fv = fd.value;
      if (field === "base" && fv !== null && typeof fv === "object") {
        var rdnsOwn = _capturedRdns(fv, who);
        if (rdnsOwn !== undefined) {
          var dnBase = {};
          intrinsic.defineProperty(dnBase, "rdns", { value: rdnsOwn, enumerable: true, configurable: true, writable: true });
          fv = dnBase;
        } else if (guard.bytes.isByteSource(fv)) {
          fv = guard.bytes.snapshotSource(fv, PathError, "path/bad-input", who + ": a trustAnchor nameConstraints iPAddress subtree base");
        }
      }
      intrinsic.defineProperty(out, field, { value: fv, enumerable: true, configurable: true, writable: true });
    }
    guard.list.append(copied, out);
  }
  return copied;
}
/**
 * @internal Anchors are normalized one at a time, and each may expose fields through getters that
 * run caller code. Capture every anchor's namespace first, so an earlier anchor's getter cannot
 * clear a later anchor's restriction before that anchor is reached.
 */
/**
 * @internal Read a caller's anchor list once, from its own indices, into a fresh array. The list is
 * walked twice, to capture namespaces and then to normalize, and an accessor index could answer
 * differently each time.
 */
function _ownAnchorEntries(list, who) {
  if (intrinsic.types.isProxy(list)) throw E("path/bad-input", who + ": trustAnchors must be a plain array, not a Proxy");
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var d = intrinsic.getOwnPropertyDescriptor(list, i);
    if (d === undefined) throw E("path/bad-input", who + ": trustAnchors index " + i + " is a hole or is inherited; every entry must be its own");
    if (!intrinsic.hasOwn(d, "value")) throw E("path/bad-input", who + ": trustAnchors entry " + i + " must be a data property, not an accessor");
    guard.list.append(out, d.value);
  }
  return out;
}
function _precaptureAnchorNameConstraints(list, who) {
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var entry = list[i];
    var captured;
    if (entry && typeof entry === "object" && !intrinsic.isBuffer(entry) && !guard.parsed.isRecorded(entry) && !intrinsic.types.isProxy(entry)) {
      var raw = _captureConstraintMap(entry, "nameConstraints", E, "path/bad-input", who);
      captured = raw == null ? undefined : _copyAnchorNameConstraints(raw, who);
    }
    guard.list.append(out, captured);
  }
  return out;
}
function _copyAnchorNameConstraints(nc, who) {
  if (nc === null || typeof nc !== "object" || intrinsic.isArray(nc)) {
    throw E("path/bad-input", who + ": a trustAnchor nameConstraints must be a { permitted, excluded } object of { tag, base } subtree entries");
  }
  guard.identifier.assertPlainRecord(nc, E, "path/bad-input", who + ": a trustAnchor nameConstraints");
  guard.identifier.assertKnownKeys(nc, { permitted: 1, excluded: 1 }, E, "path/bad-input",
    who + ": a trustAnchor nameConstraints names its subtree lists `permitted` and `excluded`. The unknown key was: ");
  var out = {};
  for (var i = 0; i < _NC_LIST_KEYS.length; i++) {
    var key = _NC_LIST_KEYS[i];
    var d = intrinsic.getOwnPropertyDescriptor(nc, key);
    if (d === undefined) {
      if (key in nc) throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " must be an own data property, not inherited");
      continue;
    }
    if (!intrinsic.hasOwn(d, "value")) throw E("path/bad-input", who + ": a trustAnchor nameConstraints." + key + " must be a data property, not an accessor");
    var copiedList = _copyAnchorSubtreeList(d.value, key, who);
    if (copiedList === undefined) continue;
    /** @internal Validated while the anchor is normalized, so a malformed subtree is refused
     * wherever the anchor sits in the list rather than only once that anchor is reached. */
    var checkedList = checkedSubtreeSeeds(copiedList, "trustAnchors[].nameConstraints." + key);
    intrinsic.defineProperty(out, key, { value: checkedList, enumerable: true, configurable: true, writable: true });
  }
  return out;
}

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

function _copyRdnsDeep(rdns) {
  if (!intrinsic.isArray(rdns)) return rdns;
  var out = [];
  out.length = rdns.length;
  for (var i = 0; i < rdns.length; i++) {
    if (!intrinsic.hasOwn(rdns, i)) continue;
    var rdn = rdns[i], val;
    if (intrinsic.isArray(rdn)) {
      var rdnOut = [];
      rdnOut.length = rdn.length;
      for (var j = 0; j < rdn.length; j++) {
        if (!intrinsic.hasOwn(rdn, j)) continue;
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
  var isTuple = false, alg = null, pubRaw, nameRaw = null, pk = null, purposesSnap, distrustSnap;
  var subjectDerRaw, labelRaw, mozRaw, ncSnap;
  if (intrinsic.types.isProxy(entry)) {
    throw E("path/bad-input", who + ": a trustAnchor must not be a Proxy");
  }
  if (entry !== null && typeof entry === "object") {
    var proto = intrinsic.getPrototypeOf(entry);
    while (proto !== null) {
      if (intrinsic.types.isProxy(proto)) throw E("path/bad-input", who + ": a trustAnchor must not inherit from a Proxy");
      proto = intrinsic.getPrototypeOf(proto);
    }
  }
  try {
    if (entry && typeof entry === "object" && !Buffer.isBuffer(entry) && !guard.parsed.isRecorded(entry)) {
      var pRaw = _captureConstraintMap(entry, "purposes", E, "path/bad-input", who);
      purposesSnap = _normalizeConstraintField(pRaw, E, "path/bad-input", who);
      var dRaw = _captureConstraintMap(entry, "distrustAfter", E, "path/bad-input", who);
      distrustSnap = _normalizeConstraintField(dRaw, E, "path/bad-input", who);
      var ncRaw = _captureConstraintMap(entry, "nameConstraints", E, "path/bad-input", who);
      ncSnap = ncRaw == null ? undefined : _copyAnchorNameConstraints(ncRaw, who);
      subjectDerRaw = _captureOwnData(entry, "subjectDer");
      labelRaw = _captureOwnData(entry, "label");
      mozRaw = _captureOwnData(entry, "mozillaCaPolicy");
      pubRaw = entry.publicKey;
      if (guard.bytes.isByteSource(pubRaw)) {
        pk = guard.bytes.snapshotSource(pubRaw, PathError, "path/bad-input", who + ": trustAnchor publicKey");
      }
      nameRaw = entry.name;
      alg = entry.algorithm;
      isTuple = !!(nameRaw && pubRaw && alg);
    }
  } catch (e) {
    throw E("path/bad-input", who + ": a trustAnchor accessor threw", e);
  }
  if (isTuple) {
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
      var dnD = nsrc ? intrinsic.getOwnPropertyDescriptor(nsrc, "dn") : undefined;
      if (dnD && !intrinsic.hasOwn(dnD, "value")) throw E("path/bad-input", who + ": a trustAnchor name.dn must be a data property, not an accessor");
      var nDn = dnD ? dnD.value : undefined;
      if (typeof nDn === "string") {
        intrinsic.defineProperty(nameOut, "dn", { value: nDn, enumerable: true, configurable: true, writable: true });
      }
    } catch (e) { throw E("path/bad-input", who + ": trustAnchor name could not be materialized", e); }
    var nameHasRdns = intrinsic.hasOwn(nameOut, "rdns") && intrinsic.isArray(nameOut.rdns);
    if (!nameHasRdns || !Buffer.isBuffer(pk) || algStr === null) {
      throw E("path/bad-input", who + ": a trustAnchor tuple must be { name: { rdns: [...] }, publicKey: Buffer, algorithm: an OID string or a SubjectPublicKeyInfo algorithm carrying an oid }");
    }
    guard.identifier.assertCanonicalOid(algStr, E, "path/bad-input", who + ": trustAnchor algorithm " + algStr);
    var spkiAlg;
    try { spkiAlg = schema.walk(ANCHOR_SPKI_SCHEMA, asn1.decode(pk), NS).result.algorithm; }
    catch (e) { throw E("path/bad-input", who + ": trustAnchor publicKey is not a valid SubjectPublicKeyInfo", e); }
    if (spkiAlg.oid !== algStr) {
      throw E("path/bad-input", who + ": trustAnchor algorithm " + algStr + " does not match its publicKey key algorithm " + spkiAlg.oid);
    }
    var flat = {};
    intrinsic.defineProperty(flat, "name", { value: nameOut, enumerable: true, configurable: true, writable: true });
    if (purposesSnap !== undefined) intrinsic.defineProperty(flat, "purposes", { value: purposesSnap, enumerable: true, configurable: true, writable: true });
    if (distrustSnap !== undefined) intrinsic.defineProperty(flat, "distrustAfter", { value: distrustSnap, enumerable: true, configurable: true, writable: true });
    if (ncSnap !== undefined) intrinsic.defineProperty(flat, "nameConstraints", { value: ncSnap, enumerable: true, configurable: true, writable: true });
    if (subjectDerRaw !== undefined) intrinsic.defineProperty(flat, "subjectDer", { value: subjectDerRaw, enumerable: true, configurable: true, writable: true });
    if (labelRaw !== undefined) intrinsic.defineProperty(flat, "label", { value: labelRaw, enumerable: true, configurable: true, writable: true });
    if (mozRaw !== undefined) intrinsic.defineProperty(flat, "mozillaCaPolicy", { value: mozRaw, enumerable: true, configurable: true, writable: true });
    intrinsic.defineProperty(flat, "publicKey", { value: pk, enumerable: true, configurable: true, writable: true });
    intrinsic.defineProperty(flat, "algorithm", { value: spkiAlg.oid, enumerable: true, configurable: true, writable: true });
    intrinsic.defineProperty(flat, "parameters", { value: spkiAlg.parameters, enumerable: true, configurable: true, writable: true });
    return flat;
  }
  if (entry && typeof entry === "object" && (("purposes" in entry) || ("distrustAfter" in entry) || ("nameConstraints" in entry))) {
    throw E("path/bad-input", who + ": a trustAnchor certificate must not carry purposes / distrustAfter / nameConstraints -- put anchor constraints on a { name, publicKey, algorithm, purposes, distrustAfter, nameConstraints } tuple (or a pki.trust anchor), not on a parsed certificate");
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
 * Turn a parsed certificate into the trust-anchor tuple `pki.path.validate` and `pki.path.build` consume
 * as `opts.trustAnchors` (a single anchor or an array), so a root can be pinned directly instead of
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
 *   // anchor is { name, publicKey, algorithm, ... } -- pass it as opts.trustAnchors to pki.path.validate
 */
function anchorFromCert(cert) { return toAnchor(cert, "anchorFromCert"); }

function identityKey(cert) {
  var san = findExt(cert, OID.subjectAltName);
  return cert.subject.bytes.toString("hex") + "|" + (san ? san.value.toString("hex") : "") + "|" +
    cert.subjectPublicKeyInfo.bytes.toString("hex");
}

function certDerKey(cert) {
  return cert.tbsBytes.toString("base64") + "|" + (cert.signatureValue && cert.signatureValue.bytes ? cert.signatureValue.bytes.toString("base64") : "");
}

function childAkiKeyId(cert) {
  var d = softDecode(cert, OID.authorityKeyIdentifier);
  return (d && d.value && d.value.keyIdentifier) ? d.value.keyIdentifier : null;
}

function _candBaseScore(cand, time) {
  var score = 0;
  var bc = softDecode(cand, OID.basicConstraints);
  if (bc && bc.value && bc.value.cA === true) score += 10;
  var ku = softDecode(cand, OID.keyUsage);
  if (ku && ku.value && ku.value.keyCertSign === true) score += 10;
  var v = cand.validity;
  // allow:nan-date-comparison-unguarded -- cand.validity dates are codec-parsed (asn1 readTime rejects a NaN instant) and time is guard.time.assertValid'd at entry; the validity term is a fail-safe sort hint regardless.
  if (v && guard.time.isDate(v.notBefore) && guard.time.isDate(v.notAfter) &&
    guard.time.instantOf(v.notBefore) <= guard.time.instantOf(time) &&
    guard.time.instantOf(time) <= guard.time.instantOf(v.notAfter)) score += 5;
  return score;
}

function scoreCandidate(cand, childAki, anchors, time) {
  var score = _candBaseScore(cand, time);
  if (childAki) {
    var d = softDecode(cand, OID.subjectKeyIdentifier);
    if (d && Buffer.isBuffer(d.value) && d.value.equals(childAki)) score += 1000;
  }
  for (var i = 0; i < anchors.length; i++) {
    if (nameMatchSoft(cand.issuer.rdns, anchors[i].name.rdns)) { score += 100; break; }
  }
  return score;
}

function scoreCandidateReverse(cand, parentCert, leafCert, time) {
  var score = _candBaseScore(cand, time);
  if (parentCert) {
    var candAki = childAkiKeyId(cand);
    if (candAki) {
      var d = softDecode(parentCert, OID.subjectKeyIdentifier);
      if (d && intrinsic.isBuffer(d.value) && intrinsic.bufferEquals(d.value, candAki)) score += 1000;
    }
  }
  if (nameMatchSoft(leafCert.issuer.rdns, cand.subject.rdns)) score += 100;
  return score;
}

function _pickBuildDirection(leafCert, pool, anchors, fetchAia) {
  if (fetchAia) return "forward";
  var fwdFirstHop = 0, revFirstHop = 0;
  for (var i = 0; i < pool.length; i++) {
    if (nameMatchSoft(pool[i].subject.rdns, leafCert.issuer.rdns)) fwdFirstHop += 1;
    for (var a = 0; a < anchors.length; a++) {
      if (nameMatchSoft(pool[i].issuer.rdns, anchors[a].name.rdns)) { revFirstHop += 1; break; }
    }
  }
  return revFirstHop < fwdFirstHop ? "reverse" : "forward";
}

function _policyScore(result, uips) {
  var ucps = result && result.userConstrainedPolicySet;
  if (!ucps) return 0;
  var n = 0;
  for (var i = 0; i < ucps.length; i++) {
    for (var j = 0; j < uips.length; j++) {
      if (ucps[i] === uips[j]) { n += 1; break; }
    }
  }
  return n;
}

function _bestByPolicy(accepted, uips) {
  var best = accepted[0], bestScore = _policyScore(accepted[0].result, uips);
  for (var i = 1; i < accepted.length; i++) {
    var s = _policyScore(accepted[i].result, uips);
    if (s > bestScore) { best = accepted[i]; bestScore = s; }
  }
  return best;
}

function _assertUserInitialPolicySet(uips, prefix) {
  if (uips === undefined) return;
  var ok = intrinsic.isArray(uips) && uips.length > 0 &&
    guard.list.allMatch(uips, function (p) { return typeof p === "string" && p.length > 0; });
  if (!ok) throw E("path/bad-input", prefix + ": opts.userInitialPolicySet must be a non-empty array of policy OID strings");
  for (var i = 0; i < uips.length; i++) {
    guard.identifier.assertCanonicalOid(uips[i], E, "path/bad-input", prefix + ": opts.userInitialPolicySet entry " + guard.text.showValue(uips[i]));
  }
}

function _pushCandidates(frame, scored, stack, counter, down) {
  scored.sort(function (a, b) { return a.score - b.score; });
  var n = 0;
  for (var ci = 0; ci < scored.length; ci++) {
    counter.tick();
    n += 1;
    var cand = scored[ci].cand, candKey = identityKey(cand);
    if (intrinsic.setHas(frame.keys, candKey)) continue;
    var childKeys = new Set(frame.keys);
    intrinsic.setAdd(childKeys, candKey);
    guard.list.append(stack, down
      ? { chain: intrinsic.concat(frame.chain, [cand]), hop: frame.hop + 1, keys: childKeys, anchor: frame.anchor }
      : { chain: [cand].concat(frame.chain), hop: frame.hop + 1, keys: childKeys });
  }
  return n;
}


function _isBlockedAiaHost(host) {
  if (host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") host = host.slice(1, -1);
  if (net.isIP(host) === 0) return false;
  return httpTransport.isBlockedIp(host);
}

function _aiaParseBody(body, contentType, maxCerts) {
  var certsFirst = String(contentType || "").toLowerCase().indexOf("pkcs7") >= 0;
  var order = certsFirst ? ["certs", "cert"] : ["cert", "certs"];
  for (var i = 0; i < order.length; i++) {
    try {
      if (order[i] === "cert") { x509.parse(body); return [Buffer.from(body)]; }
      return cms.parseCertsOnly(body, E, "path", maxCerts).certificates;
    } catch (_e) { }
  }
  throw E("path/aia-bad-body", "an AIA response body is neither a DER certificate nor a certs-only CMS");
}

async function _aiaFetchOne(uri, aia) {
  var res = await aia.transport({ method: "GET", url: uri, tls: aia.tls, timeout: aia.timeout, maxResponseBytes: aia.maxResponseBytes, blockPrivateAddresses: true });
  res = res || {};
  if (res.status !== 200) throw E("path/aia-status", "an AIA fetch returned HTTP " + res.status + " (only 200 is a cert source; no redirect following)");
  var body = guard.bytes.isByteSource(res.body)
    ? guard.bytes.source(res.body, PathError, "path/aia-bad-body", "the AIA response body")
    : Buffer.from(res.body == null ? "" : String(res.body), "latin1");
  if (body.length === 0) throw E("path/aia-empty", "an AIA fetch returned an empty body");
  if (body.length > aia.maxResponseBytes) throw E("path/aia-too-large", "an AIA response exceeds the " + aia.maxResponseBytes + "-byte cap");
  var headers = {};
  Object.keys(res.headers || {}).forEach(function (k) { headers[k.toLowerCase()] = res.headers[k]; });
  return _aiaParseBody(body, headers["content-type"], aia.maxCertsPerResponse);
}

async function _fetchAiaIssuers(current, aia) {
  var d = softDecode(current, OID.authorityInfoAccess);
  if (!d || !d.value) return [];
  var uris = [];
  var seenThisCert = new Set();
  for (var i = 0; i < d.value.length; i++) {
    var ad = d.value[i];
    if (ad.accessMethod !== OID.caIssuers) continue;
    if (!ad.accessLocation || ad.accessLocation.tag !== 6) continue;
    var u;
    try { u = new URL(ad.accessLocation.value); }
    catch (_e) { continue; }
    if (u.protocol !== "https:") continue;
    if (_isBlockedAiaHost(u.hostname)) continue;
    if (net.isIP(_stripBrackets(u.hostname)) === 0 && !aia.transportGuardsAddresses) continue;
    u.hash = "";
    if (intrinsic.setHas(aia.fetchedUrls, u.href) || intrinsic.setHas(seenThisCert, u.href)) continue;
    if (seenThisCert.size >= aia.maxPerCert) break;
    intrinsic.setAdd(seenThisCert, u.href);
    guard.list.append(uris, u.href);
  }
  var out = [];
  for (var k = 0; k < uris.length; k++) {
    if (intrinsic.setHas(aia.fetchedUrls, uris[k])) continue;
    if (aia.fetches >= aia.maxFetches) break;
    intrinsic.setAdd(aia.fetchedUrls, uris[k]);
    aia.fetches += 1;
    var certs;
    try { certs = await _aiaFetchOne(uris[k], aia); }
    catch (_e2) { continue; }
    for (var c = 0; c < certs.length; c++) {
      var parsed;
      try { parsed = coerceCert(certs[c]); }
      catch (_e3) { /* allow:swallow-unverified verified-unreachable: every cert here already passed the IDENTICAL x509.parse in _aiaParseBody (single-DER validates `body`; certs-only validates each via parseCertsOnly), so coerceCert re-parsing the same bytes cannot throw -- the guard stays as defense-in-depth */ continue; }
      guard.list.append(out, parsed);
    }
  }
  return out;
}

/**
 * @primitive  pki.path.build
 * @signature  pki.path.build(leaf, opts) -> Promise<{ valid, path, trustAnchor, result, candidatesConsidered, aiaFetches }>
 * @since       0.3.7
 * @status      stable
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
 * SSRF/amplification bounded: https-only, a total fetch budget (a SILENT cap, never a throw that denies a
 * buildable path), a per-cert URL cap, a build-wide URL dedupe, a response size + certificate-count cap, and no
 * redirect following; every fetch fault is a silent skip. `aiaFetches` reports how many network GETs the build
 * performed (`0` when `fetchAia` is off). NOTE: with `opts.validate:false` (pure-builder mode) a fetched cert is
 * returned unvalidated, identical to a static candidate; the "flows through validate" guarantee needs validation on.
 *
 * @opts  candidates             The untrusted candidate CA pool (array of DER/PEM/parsed certs; alias `intermediates`).
 * @opts  trustAnchors           The trust store (non-empty array of `{ name, publicKey, algorithm }` tuples or self-signed root certificates).
 * @opts  time                   The check date (`Date`, required); forwarded to every internal `validate` call.
 * @opts  direction              Search direction: `"forward"` (default, from the leaf toward an anchor), `"reverse"` (from an anchor toward the leaf, RFC 4158 sec. 3.1, narrower when the anchor set is small and the leaf fans out), or `"auto"` (pick by first-hop fan-out). Reverse building is pool-only and does not combine with `fetchAia`. Every direction hands each assembled path to `validate`, so the direction changes only search order, never which paths are accepted.
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
 * @opts  (validate options)     Every `pki.path.validate` option (`requiredEku`, `revocationChecker`, `checkPurpose`, the initial policy inputs, ...) is forwarded unchanged. When `userInitialPolicySet` is supplied, build returns the accepted path whose user-constrained policy set best satisfies it (RFC 4158 sec. 4 forward policy chaining) rather than the first accepted path; `validate` still gates every path, so this changes only which valid path is chosen. The ranking explores more of the candidate graph than a first-accept build, so it is bounded by `maxCandidatesConsidered` like the rest of the search. Reaching that cap means stop looking, not nothing found: if a valid path was already accepted, build returns the best-policy one of those; it reaches `path/build-limit` only when the cap is hit before any valid path is accepted. An `anyPolicy` entry makes the set unconstrained, so ranking is skipped and the first accepted path is returned.
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
var _BUILD_OPTS = (function () {
  var o = {
    aiaTimeout: 1, candidates: 1, direction: 1, fetchAia: 1, intermediates: 1, maxAiaFetches: 1,
    maxAiaPerCert: 1, maxCandidatesConsidered: 1, maxDepth: 1, maxPathCerts: 1,
    maxResponseBytes: 1, time: 1, tls: 1, transport: 1, trustAnchors: 1, validate: 1
  };
  Object.keys(_VALIDATE_OPTS).forEach(function (k) { o[k] = 1; });
  return o;
})();

async function build(leaf, opts) {
  opts = guard.identifier.optionsObject(opts, E, "path/bad-input", "build: opts");
  guard.identifier.assertKnownKeys(opts, _BUILD_OPTS, E, "path/bad-input",
    "pki.path.build has an unknown option (the anchor option is `trustAnchors`). The unknown option was: ");
  var leafCert;
  try { leafCert = coerceCert(leaf); }
  catch (e) { throw E("path/bad-input", "build: the leaf certificate did not parse", e); }

  var poolInput = opts.candidates !== undefined ? opts.candidates : opts.intermediates;
  if (poolInput === undefined) poolInput = [];
  if (!intrinsic.isArray(poolInput)) throw E("path/bad-input", "build: opts.candidates must be an array of certificates");
  var poolCeiling = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES;
  if (poolInput.length > poolCeiling) throw E("path/bad-input", "build: the candidate pool has " + poolInput.length + " certificates, exceeding the " + poolCeiling + " ceiling");
  var pool;
  try { pool = poolInput.map(coerceCert); }
  catch (e) { throw E("path/bad-input", "build: a candidate certificate did not parse", e); }
  var poolDerKeys = new Set();
  for (var pdk = 0; pdk < pool.length; pdk++) intrinsic.setAdd(poolDerKeys, certDerKey(pool[pdk]));

  if (!intrinsic.isArray(opts.trustAnchors) || opts.trustAnchors.length === 0) throw E("path/bad-input", "build: opts.trustAnchors must be a non-empty array of anchor tuples or root certificates");
  /** @internal Captured before any anchor is normalized: an anchor field may be an accessor whose
   * getter runs caller code, and every candidate is validated in its own pass after an await. */
  var buildPermRaw = opts.initialPermittedSubtrees;
  var buildExclRaw = opts.initialExcludedSubtrees;
  var buildPermSeeds = checkedSubtreeSeeds(buildPermRaw, "initialPermittedSubtrees");
  var buildExclSeeds = checkedSubtreeSeeds(buildExclRaw, "initialExcludedSubtrees");
  var buildEntries = _ownAnchorEntries(opts.trustAnchors, "build");
  var buildPreNc = _precaptureAnchorNameConstraints(buildEntries, "build");
  var anchors = [];
  for (var bai = 0; bai < buildEntries.length; bai++) {
    var bAnchor = toAnchor(buildEntries[bai], "build");
    if (buildPreNc[bai] !== undefined) intrinsic.defineProperty(bAnchor, "nameConstraints", { value: buildPreNc[bai], enumerable: true, configurable: true, writable: true });
    guard.list.append(anchors, bAnchor);
  }

  guard.time.assertValid(opts.time, E, "path/bad-input", "build: opts.time (the validity-window check date, forwarded to validate)");
  var effectiveMaxCerts = guard.limits.cap(opts.maxPathCerts, "build: opts.maxPathCerts", constants.LIMITS.PATH_MAX_CERTS, { E: E, code: "path/bad-input", min: 1 });
  var depthCeiling = effectiveMaxCerts - 1;
  // allow:guard-shape-reinlined -- opts.maxDepth here is the path-building chain depth (capped via guard.limits.cap against the PATH_BUILD_MAX_DEPTH ceiling), a different concept from the decode-recursion depth guard.limits.depthCap enforces
  var maxDepth = guard.limits.cap(opts.maxDepth, "build: opts.maxDepth", Math.min(constants.LIMITS.PATH_BUILD_MAX_DEPTH, depthCeiling), { E: E, code: "path/bad-input", min: 0, max: depthCeiling });
  var maxConsidered = guard.limits.cap(opts.maxCandidatesConsidered, "build: opts.maxCandidatesConsidered", poolCeiling, { E: E, code: "path/bad-input", min: 1 });
  var doValidate = opts.validate !== false;

  var direction = opts.direction !== undefined ? opts.direction : "forward";
  if (direction !== "forward" && direction !== "reverse" && direction !== "auto") {
    throw E("path/bad-input", "build: opts.direction must be \"forward\", \"reverse\", or \"auto\", got " + guard.text.showValue(opts.direction));
  }
  if (direction === "auto") direction = _pickBuildDirection(leafCert, pool, anchors, opts.fetchAia === true);
  if (direction === "reverse" && opts.fetchAia === true) throw E("path/bad-input", "build: opts.fetchAia is only supported with forward building; reverse building is pool-only (RFC 4158 sec. 3.1)");

  var aiaCtx = null;
  if (opts.fetchAia === true) {
    if (opts.transport !== undefined && typeof opts.transport !== "function") {
      throw E("path/bad-input", "build: opts.transport must be a transport function (request) -> Promise<{ status, headers, body }>");
    }
    if (opts.aiaTimeout !== undefined) {
      guard.limits.cap(opts.aiaTimeout, "build: opts.aiaTimeout", 1, { E: E, code: "path/bad-input", min: 1, max: httpTransport.MAX_TIMEOUT });
    }
    var aiaTransport = opts.transport || httpTransport.https({ E: E, errPrefix: "path" });
    aiaCtx = {
      transport: aiaTransport,
      transportGuardsAddresses: aiaTransport.blocksPrivateAddresses === true,
      tls: opts.tls || {},
      timeout: opts.aiaTimeout,
      maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "build: opts.maxResponseBytes", constants.LIMITS.PATH_AIA_MAX_RESPONSE_BYTES, { E: E, code: "path/bad-input", min: 1, max: constants.LIMITS.PATH_AIA_MAX_RESPONSE_BYTES }),
      maxPerCert: guard.limits.cap(opts.maxAiaPerCert, "build: opts.maxAiaPerCert", constants.LIMITS.PATH_AIA_MAX_PER_CERT, { E: E, code: "path/bad-input", min: 0 }),
      maxCertsPerResponse: constants.LIMITS.PATH_AIA_MAX_CERTS_PER_RESPONSE,
      maxFetches: guard.limits.cap(opts.maxAiaFetches, "build: opts.maxAiaFetches", constants.LIMITS.PATH_AIA_MAX_FETCHES, { E: E, code: "path/bad-input", min: 0 }),
      fetchedUrls: new Set(),
      fetches: 0,
    };
  }

  var BUILD_ONLY_OPT = { candidates: 1, intermediates: 1, trustAnchors: 1, maxDepth: 1, maxCandidatesConsidered: 1, validate: 1,
    fetchAia: 1, transport: 1, tls: 1, maxAiaFetches: 1, maxAiaPerCert: 1, aiaTimeout: 1, maxResponseBytes: 1 };
  var forwarded = Object.create(null);
  Object.keys(_VALIDATE_OPTS).forEach(function (k) {
    if (intrinsic.hasOwn(BUILD_ONLY_OPT, k)) return;
    if (k in opts) forwarded[k] = opts[k];
  });
  if (buildPermRaw != null) forwarded.initialPermittedSubtrees = buildPermSeeds;
  if (buildExclRaw != null) forwarded.initialExcludedSubtrees = buildExclSeeds;
  function validateOpts(anchor) {
    var vo = Object.create(null);
    Object.keys(forwarded).forEach(function (f) { vo[f] = forwarded[f]; });
    vo.trustAnchors = anchor;
    return vo;
  }

  var counter = guard.limits.counter(maxConsidered, E, "path/build-limit", "build: candidate-issuer expansion");
  var considered = 0;
  var anyChainAssembled = false;
  var bestFail = null;
  var success = null;
  _assertUserInitialPolicySet(opts.userInitialPolicySet, "build");
  var uipsDistinct = null, selectByPolicy = false;
  if (doValidate && intrinsic.isArray(opts.userInitialPolicySet)) {
    uipsDistinct = [];
    var containsAny = false;
    for (var ui = 0; ui < opts.userInitialPolicySet.length; ui++) {
      var uip = opts.userInitialPolicySet[ui];
      if (uip === OID.anyPolicy) { containsAny = true; break; }
      var dupUip = false;
      for (var uj = 0; uj < uipsDistinct.length; uj++) { if (uipsDistinct[uj] === uip) { dupUip = true; break; } }
      if (!dupUip) guard.list.append(uipsDistinct, uip);
    }
    selectByPolicy = !containsAny;
  }
  var accepted = selectByPolicy ? [] : null;

  try {
  if (direction === "reverse") {
    var rstack = [];
    for (var rsi = 0; rsi < anchors.length; rsi++) guard.list.append(rstack, { chain: [], hop: 0, keys: new Set([identityKey(leafCert)]), anchor: anchors[rsi] });
    while (rstack.length) {
      var rframe = rstack.pop();
      var frontierCert = rframe.chain.length ? rframe.chain[rframe.chain.length - 1] : null;
      var frontierName = frontierCert ? frontierCert.subject.rdns : rframe.anchor.name.rdns;
      if (nameMatchSoft(leafCert.issuer.rdns, frontierName)) {
        var rpath = intrinsic.concat(rframe.chain, [leafCert]);
        if (!doValidate) { success = { path: rpath, trustAnchor: rframe.anchor }; break; }
        anyChainAssembled = true;
        var rres = await validate(rpath, validateOpts(rframe.anchor));
        if (rres.valid) {
          var racc = { valid: true, path: rpath, trustAnchor: rframe.anchor, result: rres };
          if (!selectByPolicy) { success = racc; break; }
          if (_policyScore(rres, uipsDistinct) >= uipsDistinct.length) { success = racc; break; }
          guard.list.append(accepted, racc);
        } else if (!bestFail) bestFail = { path: rpath, trustAnchor: rframe.anchor, result: rres };
      }
      if (rframe.hop >= maxDepth) continue;
      var rscored = [];
      for (var rpi = 0; rpi < pool.length; rpi++) {
        if (nameMatchSoft(pool[rpi].subject.rdns, rframe.anchor.name.rdns) &&
          intrinsic.bufferEquals(pool[rpi].subjectPublicKeyInfo.bytes, rframe.anchor.publicKey)) continue;
        if (nameMatchSoft(pool[rpi].issuer.rdns, frontierName)) {
          guard.list.append(rscored, { cand: pool[rpi], score: scoreCandidateReverse(pool[rpi], frontierCert, leafCert, opts.time) });
        }
      }
      considered += _pushCandidates(rframe, rscored, rstack, counter, true);
    }
  } else {
  var stack = [{ chain: [leafCert], hop: 0, keys: new Set([identityKey(leafCert)]) }];
  var deferredAia = [];
  var deferSeq = 0;
  while (!success) {
    if (!stack.length) {
      var _bi = -1;
      for (var _di = 0; _di < deferredAia.length; _di++) {
        var _f = deferredAia[_di];
        if (_f.fetched && _f.poolMark >= pool.length) continue;
        if (_bi === -1) { _bi = _di; continue; }
        var _bf = deferredAia[_bi];
        if (_f.hop > _bf.hop || (_f.hop === _bf.hop && _f.seq < _bf.seq)) _bi = _di;
      }
      if (_bi === -1) break;
      var fb = deferredAia[_bi];
      var fbCur = fb.chain[0];
      if (!fb.fetched && aiaCtx && aiaCtx.fetches < aiaCtx.maxFetches) {
        var fetched = await _fetchAiaIssuers(fbCur, aiaCtx);
        for (var fj = 0; fj < fetched.length; fj++) {
          var fdk = certDerKey(fetched[fj]);
          if (intrinsic.setHas(poolDerKeys, fdk)) continue;
          intrinsic.setAdd(poolDerKeys, fdk);
          if (pool.length < poolCeiling) guard.list.append(pool, fetched[fj]);
        }
      }
      fb.fetched = true;
      var fbAki = childAkiKeyId(fbCur);
      var fbScored = [];
      for (var pj = fb.poolMark; pj < pool.length; pj++) {
        if (nameMatchSoft(pool[pj].subject.rdns, fbCur.issuer.rdns)) {
          guard.list.append(fbScored, { cand: pool[pj], score: scoreCandidate(pool[pj], fbAki, anchors, opts.time) });
        }
      }
      fb.poolMark = pool.length;
      considered += _pushCandidates(fb, fbScored, stack, counter);
      continue;
    }
    var frame = stack.pop();
    var current = frame.chain[0];

    for (var ai = 0; ai < anchors.length; ai++) {
      if (!nameMatchSoft(current.issuer.rdns, anchors[ai].name.rdns)) continue;
      if (!doValidate) { success = { path: frame.chain.slice(), trustAnchor: anchors[ai] }; break; }
      anyChainAssembled = true;
      var res = await validate(frame.chain, validateOpts(anchors[ai]));
      if (res.valid) {
        var acc = { valid: true, path: frame.chain.slice(), trustAnchor: anchors[ai], result: res };
        if (!selectByPolicy) { success = acc; break; }
        if (_policyScore(res, uipsDistinct) >= uipsDistinct.length) { success = acc; break; }
        guard.list.append(accepted, acc);
      } else if (!bestFail) bestFail = { path: frame.chain.slice(), trustAnchor: anchors[ai], result: res };
    }
    if (success || frame.hop >= maxDepth) continue;

    var childAki = childAkiKeyId(current);
    var scored = [];
    for (var pi = 0; pi < pool.length; pi++) {
      if (nameMatchSoft(pool[pi].subject.rdns, current.issuer.rdns)) {
        guard.list.append(scored, { cand: pool[pi], score: scoreCandidate(pool[pi], childAki, anchors, opts.time) });
      }
    }
    if (aiaCtx && frame.hop < maxDepth && aiaCtx.fetches < aiaCtx.maxFetches) {
      guard.list.append(deferredAia, { chain: frame.chain, hop: frame.hop, keys: frame.keys, poolMark: pool.length, seq: deferSeq, fetched: false });
      deferSeq += 1;
    }
    considered += _pushCandidates(frame, scored, stack, counter);
  }
  }
  } catch (_limitErr) {
    // allow:swallow-unverified the candidate cap means "stop looking", not "nothing found": once a valid path has
    if (!(selectByPolicy && accepted && accepted.length && _limitErr && _limitErr.code === "path/build-limit")) throw _limitErr;
    considered = counter.count();
  }

  if (selectByPolicy && !success && accepted.length) success = _bestByPolicy(accepted, uipsDistinct);

  var aiaFetches = aiaCtx ? aiaCtx.fetches : 0;
  if (success) {
    if (doValidate) return guard.verdict.of({ valid: true, path: success.path, trustAnchor: success.trustAnchor, result: success.result, candidatesConsidered: considered, aiaFetches: aiaFetches });
    return guard.verdict.of({ path: success.path, trustAnchor: success.trustAnchor, candidatesConsidered: considered, aiaFetches: aiaFetches });
  }
  if (anyChainAssembled) {
    return guard.verdict.of({ valid: false, path: bestFail.path, trustAnchor: bestFail.trustAnchor, result: bestFail.result, candidatesConsidered: considered, aiaFetches: aiaFetches });
  }
  throw E("path/no-path", "build: no certification path from the leaf to any configured trust anchor could be assembled");
}

module.exports = {
  validate: validate,
  build: build,
  anchorFromCert: anchorFromCert,
  crlChecker: crlChecker,
  ocspChecker: ocspChecker,
  verifyOcspResponse: verifyOcspResponse,
  PROCESSED_EXTENSIONS: PROCESSED_EXTENSIONS,
  TARGET_UNPROCESSED_IF_CRITICAL: TARGET_UNPROCESSED_IF_CRITICAL,
};
