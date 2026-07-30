// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cmp.verify implementation. The operator-facing @module pki.cmp home is
// lib/cmp-build.js; this file adds the @primitive pki.cmp.verify block and re-exports the cmp producing
// surface (build / transfer / wellKnownUrl) so the whole pki.cmp namespace wires through here (index.js).
//
// pki.cmp.verify -- incoming CMP PKIMessage protection verification (the verify-inverse of the
// pki.cmp.build protection). This module is the cms-verify mirror: it composes the HEAVY verify
// dependency set (the path-validate signature engine + full path building) that pki.cmp.build never
// pulls, and re-exports the cmp-build producing surface so the whole pki.cmp namespace is wired here.
//
// The load-bearing rule: the protection is recomputed over the EXACT ProtectedPart bytes the builder
// signed -- SEQUENCE { header, body } reconstructed from the parser-surfaced RAW headerBytes / bodyBytes
// (schema-cmp), NEVER a re-serialization of the decoded structs. A re-encoder that normalized a malleable
// interior field would run the recompute over different bytes than a strict signer covered: both a false
// reject for a canonical peer AND a bypass. The signature path routes through the ONE path-validate engine
// (with the EdDSA low-order-point gate) injected via setEngine -- never build's self-check, which skips it.
// RFC 9810 sec. 5.1.3, algorithms RFC 9481 / RFC 9579, out-of-path signer profile RFC 9483.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var cmpBuild = require("./cmp-build");
var cmp = require("./schema-cmp");
var pkix = require("./schema-pkix");
var pbes2 = require("./pbes2");
var x509 = require("./schema-x509");
var schema = require("./schema-engine");
var guard = require("./guard-all");
var constants = require("./constants");
var frameworkError = require("./framework-error");

var CmpError = frameworkError.CmpError;
var b = asn1.build;
function _err(code, message, cause) { return new CmpError(code, message, cause); }

// The cmp error namespace, reused so PBMAC1-params decode faults surface as cmp/bad-mac-data.
var NS = pkix.makeNS("cmp", CmpError, oid);
var PBMAC1_PARAMS = pkix.pbmac1Params(NS);

var KNOWN_VERIFY_OPTS = {
  sharedSecret: 1, signerCert: 1, trustAnchors: 1, intermediates: 1, time: 1,
  transactionID: 1, expectRecipNonce: 1, revocationChecker: 1, maxIterations: 1,
};

// PBMAC1 PBKDF2-PRF / messageAuthScheme name -> WebCrypto hash. Only SHA-256/384/512 are supported
// (RFC 9481 sec. 7 mandates SHA-256; RFC 9579 sec. 7 bars a <= 160-bit digest, so hmacWithSHA1 -- and an
// omitted-PRF that resolves to it -- is unsupported, never MAC-verified under a weak digest).
// Keyed by the IMMUTABLE dotted OID, never the display name: pki.oid.register() can rename hmacWithSHA256/384/512,
// so a name-keyed lookup would reject a valid PBMAC1 message under a renamed registry (the immutable-OID-dispatch rule).
var PRF_HASH = {};
PRF_HASH[oid.byName("hmacWithSHA256")] = "SHA-256";
PRF_HASH[oid.byName("hmacWithSHA384")] = "SHA-384";
PRF_HASH[oid.byName("hmacWithSHA512")] = "SHA-512";

// Attacker-controlled PBKDF2 work-factor bounds (RFC 8018 sec. 4.2; the pkcs12 verifyMac / _capWork model).
var PBMAC1_MAX_ITER = constants.LIMITS.PBKDF2_MAX_ITERATIONS;
var PBMAC1_MIN_ITER = 1000;    // RFC 8018 sec. 4.2 floor -- matches pki.cmp.build; a trivially small count is refused
var PBMAC1_MAX_SALT = constants.LIMITS.PBKDF2_MAX_SALT;
var PBMAC1_KEYLEN_MIN = 20;    // RFC 9579 sec. 9 -- a short derived key is refused
var PBMAC1_KEYLEN_MAX = 1024;
// PBKDF2 PRF output length (octets) -- the size of one derived block; keyLength beyond it costs extra HMAC rounds.
var PRF_HLEN = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };

// The legacy / KEM MAC protection OIDs (RFC 9810 sec. 5.1.3.1/.2/.4) the v1 verifier recognizes and refuses
// -- build emits only PBMAC1, so the verifier rejects a legacy/KEM MAC OID rather than accept a construction
// it does not verify (a silent accept of an unverified algorithm would be fail-open).
var UNSUPPORTED_MAC_OIDS = {};
["passwordBasedMac", "dhBasedMac", "kemBasedMac"].forEach(function (n) {
  var o = oid.byName(n);
  if (o) UNSUPPORTED_MAC_OIDS[o] = n;
});

// The signature engine + full path build/validate, injected by path-validate (the crl/ocsp seam pattern) so
// there is never a second, weaker CMP signature verifier and no require cycle. Null until path-validate loads
// (index.js always loads pki.path before a pki.cmp.verify call).
var _engine = null;
function setEngine(engine) { _engine = engine; }

// ---- verdict builders ----
// One verdict shape (mirrors cms.verify / tsp.verify): `valid` is crypto intactness under the DECLARED
// protectionAlg; `trusted` is mac=secret-matched / signature=chained-to-a-supplied-anchor; `code`/`reason`
// are set on a rejected verdict. Only a config-tier / malformed-DER error throws.
function _verdict(m, type, protectionAlg, valid, trusted, code, reason, signer) {
  var v = {
    valid: valid,
    trusted: trusted,
    protectionType: type,
    protectionAlg: protectionAlg ? { oid: protectionAlg.oid, name: protectionAlg.name || null } : null,
    signer: signer ? { cert: signer.der, spki: signer.spki, subject: signer.subject } : null,
    transactionID: m.header.transactionID || null,
    senderNonce: m.header.senderNonce || null,
    recipNonce: m.header.recipNonce || null,
    header: m.header,
    body: m.body,
  };
  if (code) { v.code = code; v.reason = reason; }
  return v;
}
function _ok(m, type, alg, trusted, signer) { return _verdict(m, type, alg, true, trusted, null, null, signer); }
function _fail(m, type, alg, code, reason, signer) { return _verdict(m, type, alg, false, false, code, reason, signer || null); }

// ---- input coercion: parse a DER Buffer / PEM string, or RE-DERIVE an authenticated view of an
// already-parsed object. A caller-supplied parsed object's DECODED struct (header.transactionID, body, ...)
// is UNTRUSTED -- middleware that mutated a decoded field after parsing must not have it returned in a
// valid verdict or slip past the opt-in echo checks while the crypto verifies over the original raw slices.
// So a parsed object is reassembled from its AUTHENTICATED raw slices (headerBytes / bodyBytes / protection /
// extraCerts) and re-parsed, so every security-relevant and returned field derives from the authenticated
// bytes, never the caller's decoded representation.
function _coerce(message) {
  if (message && typeof message === "object" && !Buffer.isBuffer(message) && !(message instanceof Uint8Array) &&
    message.headerBytes !== undefined && message.bodyBytes !== undefined &&
    message.header !== undefined && message.body !== undefined) {
    return cmp.parse(_reassemble(message));
  }
  // A raw Buffer / Uint8Array parses into zero-copy views; a caller that mutates the input after verify would
  // change the returned authenticated fields (transactionID, nonces, header, body) while valid stays true.
  // Parse a PRIVATE copy so every verdict field is bound to the verified snapshot, never the caller's mutable
  // buffer. (A PEM string is immutable and base64-decodes into fresh bytes, so it needs no copy.)
  if (Buffer.isBuffer(message) || message instanceof Uint8Array) return cmp.parse(Buffer.from(message));
  return cmp.parse(message);   // a PEM CMP string (throws cmp/* on malformed input)
}

// Rebuild the PKIMessage DER from a parsed object's raw slices: SEQUENCE { header, body, protection [0]
// EXPLICIT BIT STRING OPTIONAL, extraCerts [1] EXPLICIT SEQUENCE OPTIONAL } -- the exact inverse of the
// parser's surfaced fields (cmp-build.js assembles the identical shape). Re-parsing this authenticates every
// field against the raw bytes, discarding any mutated decoded field the caller may have carried.
function _reassemble(m) {
  var kids = [b.raw(m.headerBytes), b.raw(m.bodyBytes)];
  if (m.protection != null) kids.push(b.explicit(0, b.bitString(m.protection.bytes, m.protection.unusedBits)));
  if (m.extraCerts != null && m.extraCerts.length) {
    kids.push(b.explicit(1, b.sequence(m.extraCerts.map(function (c) { return b.raw(c); }))));
  }
  return b.sequence(kids);
}

// A certificate DER from a Buffer/Uint8Array (detached-view-safe) or a PEM string.
function _certDer(cert, what) {
  if (Buffer.isBuffer(cert) || cert instanceof Uint8Array) return guard.bytes.view(cert, CmpError, "cmp/bad-input", what);
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("cmp/bad-input", what + " PEM could not be decoded", e); } }
  throw _err("cmp/bad-input", what + " must be a certificate DER Buffer/Uint8Array or PEM string");
}

// The subjectKeyIdentifier extension value of a parsed certificate, or null when absent/undecodable.
// x509.parse surfaces extensions as an array of { oid, name, critical, value } (value = raw extnValue DER).
function _certSki(parsed) {
  var skiOid = oid.byName("subjectKeyIdentifier");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== skiOid) continue;
    try { return asn1.read.octetString(asn1.decode(exts[i].value)); } catch (_e) { return null; }
  }
  return null;
}
function _subjectDn(parsed) { return parsed.subject.dn || null; }

// The decoded GeneralName nodes of a parsed certificate's subjectAltName (empty if none / undecodable).
// x509.parse surfaces `value` as the unwrapped extnValue content -- for SAN that is the SEQUENCE OF GeneralName.
function _sanGeneralNames(parsed) {
  var sanOid = oid.byName("subjectAltName");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== sanOid) continue;
    // A malformed SAN value decodes to no entries -> an empty-subject sender fails closed to sender-mismatch.
    try { return asn1.decode(exts[i].value).children || []; }
    catch (_e) { return []; }
  }
  return [];
}

// RFC 9483 sec. 3.1 sender <-> protection-certificate binding. The sender matches the certificate identity if
// it equals the POPULATED subject DN (a [4] directoryName under the RFC 5280 sec. 7.1 canonical comparison) OR
// a subjectAltName GeneralName entry -- checked regardless of whether the subject is empty, so a certificate
// that carries both a subject and a SAN can be identified by either, and an empty subject (RFC 5280 sec.
// 4.1.2.6 requires a critical SAN) is bound to its SAN identity rather than accepted with an anonymous sender.
function _senderBoundToCert(sender, parsed) {
  if (!sender || !sender.bytes) return false;
  var subjectRdns = parsed.subject.rdns;
  if (subjectRdns.length > 0) {
    var isDirName = sender.tagClass === "context" && sender.tagNumber === 4 && sender.value && Array.isArray(sender.value.rdns);
    if (isDirName && guard.name.dnEqual(sender.value.rdns, subjectRdns, NS.E, "cmp/sender-mismatch", "the header sender / signer subject")) return true;
  }
  var san = _sanGeneralNames(parsed);
  for (var i = 0; i < san.length; i++) if (_generalNameMatches(sender, san[i])) return true;
  return false;
}

// GeneralName equality (RFC 5280 sec. 7) for the sender <-> SAN binding, applying the per-type comparison
// rules rather than a universal byte compare: a dNSName [2] case-insensitively (sec. 4.2.1.6 / 7.2), an
// rfc822Name [1] with a case-insensitive domain (sec. 7.5), a uniformResourceIdentifier [6] with a
// case-insensitive scheme + host (sec. 4.2.1.6 / RFC 3986 sec. 6.2.2.1), a directoryName [4] under the sec.
// 7.1 canonical DN comparison, and every other type by exact DER (fail-closed). `sender` is the parsed [n]
// GeneralName from schema-cmp; `sanNode` is a decoded certificate SAN GeneralName node.
function _generalNameMatches(sender, sanNode) {
  if (sanNode.tagClass !== sender.tagClass || sanNode.tagNumber !== sender.tagNumber) return false;
  if (sanNode.tagClass === "context") {
    if (sanNode.tagNumber === 2 && sanNode.content) {   // dNSName IA5String: case-insensitive
      return String(sender.value).toLowerCase() === sanNode.content.toString("latin1").toLowerCase();
    }
    if (sanNode.tagNumber === 1 && sanNode.content) {   // rfc822Name IA5String: case-insensitive domain
      return _rfc822Equal(String(sender.value), sanNode.content.toString("latin1"));
    }
    if (sanNode.tagNumber === 6 && sanNode.content) {   // uniformResourceIdentifier IA5String: case-insensitive scheme + host
      return _uriEqual(String(sender.value), sanNode.content.toString("latin1"));
    }
    if (sanNode.tagNumber === 4 && sanNode.children && sanNode.children.length) {   // directoryName: canonical DN
      if (!sender.value || !Array.isArray(sender.value.rdns)) return false;
      var sanName;
      try { sanName = schema.embeddedDer(pkix.name(NS), sanNode.children[0].bytes, NS, { code: "cmp/sender-mismatch", what: "SAN directoryName" }).result; }
      catch (_e) { return false; }
      return guard.name.dnEqual(sender.value.rdns, sanName.rdns, NS.E, "cmp/sender-mismatch", "SAN directoryName");
    }
  }
  return sanNode.bytes.equals(sender.bytes);
}

// RFC 5280 sec. 7.5 rfc822Name comparison: the local-part is case-sensitive, the domain case-insensitive.
function _rfc822Equal(a, b) {
  var ai = a.lastIndexOf("@"), bi = b.lastIndexOf("@");
  if (ai < 0 || bi < 0) return a === b;
  return a.slice(0, ai) === b.slice(0, bi) && a.slice(ai + 1).toLowerCase() === b.slice(bi + 1).toLowerCase();
}

// RFC 5280 sec. 4.2.1.6 / RFC 3986 sec. 6.2.2.1 URI comparison: the scheme and the authority host are
// case-insensitive; every other component (userinfo, port, path, query, fragment) is byte-exact. Return
// null for anything that is not a well-formed absolute URI so the caller falls back to exact-DER (fail-closed
// -- never normalize an input we cannot confidently parse into a false identity match).
function _normalizeUri(u) {
  var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(u);   // scheme ":" rest (RFC 3986 sec. 3.1)
  if (!m) return null;
  var scheme = m[1].toLowerCase();
  var rest = m[2];
  if (rest.slice(0, 2) !== "//") return scheme + ":" + rest;   // no authority -> scheme-specific-part is exact
  var body = rest.slice(2);
  var cut = body.search(/[/?#]/);   // authority ends at the first "/", "?" or "#" (RFC 3986 sec. 3.2)
  var split = cut < 0 ? body.length : cut;
  var authority = body.slice(0, split), tail = body.slice(split);   // tail: path/query/fragment -- exact
  var at = authority.lastIndexOf("@");   // [ userinfo "@" ] host [ ":" port ] -- userinfo stays case-sensitive
  var userinfo = at < 0 ? "" : authority.slice(0, at + 1);
  var hostport = (at < 0 ? authority : authority.slice(at + 1)).toLowerCase();   // host case-insensitive; port is digits
  return scheme + "://" + userinfo + hostport + tail;
}
function _uriEqual(a, b) {
  var na = _normalizeUri(a), nb = _normalizeUri(b);
  if (na === null || nb === null) return a === b;
  return na === nb;
}

// M11/M14: resolve the signature-protection signer certificate. An explicit opts.signerCert wins (with the
// senderKID SKI binding when present); else `extra` (the ALREADY dedup+validity+count-bounded extraCerts) by
// senderKID, else RFC 9483 sec. 3.3 -- extraCerts[0] IS the protection certificate. `extra` is bounded BEFORE
// this search so an unsigned flood cannot force unbounded X.509 parsing. Returns { der, spki, subject, parsed }
// or null (never verify against an unauthenticated key).
function _resolveSignerCert(m, opts, extra) {
  var senderKID = m.header.senderKID;   // Buffer or null
  function accept(der) {
    var p;
    try { p = x509.parse(der); } catch (_e) { return null; }
    if (senderKID != null) {
      var ski = _certSki(p);
      if (ski == null || !guard.crypto.constantTimeEqual(ski, senderKID)) return null;
    }
    return { der: der, spki: p.subjectPublicKeyInfo.bytes, subject: _subjectDn(p), parsed: p };
  }
  // Snapshot the explicit signer certificate: _certDer returns a VIEW into a caller Buffer, and der/spki are
  // surfaced in the verdict, so a caller mutating opts.signerCert after verify would change verdict.signer.cert
  // / .spki while valid/trusted stay fixed -- a later anchor/authorize decision could then act on a different
  // certificate than the one whose key verified the protection. (The message path is already copied in _coerce.)
  if (opts.signerCert != null) return accept(Buffer.from(_certDer(opts.signerCert, "opts.signerCert")));
  if (senderKID != null) {
    for (var i = 0; i < extra.length; i++) { var r = accept(extra[i]); if (r) return r; }
    return null;
  }
  if (extra.length) return accept(extra[0]);   // RFC 9483 sec. 3.3: extraCerts[0] is the protection cert
  return null;
}

// M20-M22 header consistency (opt-in echoes). Returns { code, reason } on a mismatch, else null. These are
// public transaction identifiers, not secrets, so a length-checked equality (not a MAC compare) is correct.
function _bufEq(a, x) { return Buffer.isBuffer(a) && Buffer.isBuffer(x) && a.length === x.length && a.equals(x); }
function _headerChecks(m, opts) {
  if (opts.transactionID != null && !_bufEq(m.header.transactionID, opts.transactionID)) {
    return { code: "cmp/transaction-id-mismatch", reason: "header.transactionID does not equal the expected value (RFC 9810 sec. 5.1.1)" };
  }
  if (opts.expectRecipNonce != null && !_bufEq(m.header.recipNonce, opts.expectRecipNonce)) {
    return { code: "cmp/bad-recip-nonce", reason: "header.recipNonce does not echo the expected sender nonce" };
  }
  return null;
}

// M13 keyUsage.digitalSignature gate -- a format-local check ON TOP of path.validate: if the signer cert
// carries a keyUsage extension, digitalSignature MUST be asserted (RFC 9483 sec. 3.2, RFC 9810 sec. 5.1.3.3).
// Takes the already-parsed signer cert (parsed once in _resolveSignerCert); a malformed keyUsage fails closed.
function _keyUsageAllowsSigning(parsed) {
  var kuOid = oid.byName("keyUsage");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== kuOid) continue;
    var bs;
    try { bs = asn1.read.bitString(asn1.decode(exts[i].value)); } catch (_e) { return false; }
    return bs.bytes.length > 0 && (bs.bytes[0] & 0x80) !== 0;   // bit 0 = digitalSignature (MSB of first octet)
  }
  return true;   // no keyUsage extension present -> unconstrained
}

// M15-M19: recompute + constant-time-compare the PBMAC1 protection.
async function _verifyMac(m, protectedPart, protectionAlg, protection, opts) {
  if (protectionAlg.parameters === null) {
    return _fail(m, "mac", protectionAlg, "cmp/protection-failed", "the PBMAC1 protectionAlg carries no PBMAC1-params (RFC 9579 sec. 4)");
  }
  var params;
  try {
    params = schema.embeddedDer(PBMAC1_PARAMS, protectionAlg.parameters, NS, { code: "cmp/bad-mac-data", what: "PBMAC1-params" }).result;
  } catch (e) {
    // Malformed / keyLength-omitted (RFC 9579 sec. 5) / non-canonical PRF params -> a fail-closed verdict.
    return _fail(m, "mac", protectionAlg, e instanceof CmpError ? e.code : "cmp/protection-failed", "the PBMAC1-params did not decode: " + ((e && e.message) || e));
  }
  var kdf = params.kdf;   // { salt, iterationCount, keyLength, prfOid, prfName }
  var prfHash = PRF_HASH[kdf.prfOid];          // dispatch on the immutable OID, not the mutable display name
  var macHash = PRF_HASH[params.schemeOid];
  if (!prfHash) return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "unsupported PBMAC1 PBKDF2 PRF " + JSON.stringify(kdf.prfName) + " (SHA-256/384/512 only; RFC 9481 sec. 7, RFC 9579 sec. 7)");
  if (!macHash) return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "unsupported PBMAC1 messageAuthScheme " + JSON.stringify(params.schemeName) + " (SHA-256/384/512 only)");

  // M18: bound the attacker-controlled work factors BEFORE deriving (CWE-834/400). A config-tier throw.
  _capWork(kdf.iterationCount, kdf.salt, kdf.keyLength, prfHash, opts);

  // M19: recompute the MAC over the reconstructed ProtectedPart and compare in constant time.
  var secret = typeof opts.sharedSecret === "string" ? Buffer.from(opts.sharedSecret, "utf8") : guard.bytes.view(opts.sharedSecret, CmpError, "cmp/bad-input", "opts.sharedSecret");
  var computed = await pbes2.pbmac1(secret, kdf.salt, kdf.iterationCount, kdf.keyLength, prfHash, macHash, protectedPart);
  if (!guard.crypto.constantTimeEqual(computed, protection.bytes)) {
    return _fail(m, "mac", protectionAlg, "cmp/protection-failed", "the PBMAC1 MAC does not verify (a wrong shared secret or a tampered ProtectedPart)");
  }
  var hc = _headerChecks(m, opts);
  if (hc) return _fail(m, "mac", protectionAlg, hc.code, hc.reason);
  return _ok(m, "mac", protectionAlg, true, null);   // mac: valid protection == secret matched == trusted
}

function _capWork(iterationCount, salt, keyLength, prfHash, opts) {
  var cap = PBMAC1_MAX_ITER;
  if (opts.maxIterations != null) {
    if (typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations) {
      throw _err("cmp/bad-input", "opts.maxIterations must be a positive integer");
    }
    cap = Math.min(opts.maxIterations, cap);
  }
  // A trivially small count lets a peer run cheap offline PBMAC1 guesses against a password-like shared secret
  // with parameters pki.cmp.build refuses to produce (RFC 8018 sec. 4.2). Enforce the same floor on verify.
  if (iterationCount < PBMAC1_MIN_ITER) throw _err("cmp/bad-input", "the PBMAC1 iterationCount " + iterationCount + " is below the floor " + PBMAC1_MIN_ITER + " (RFC 8018 sec. 4.2)");
  if (iterationCount > cap) throw _err("cmp/bad-input", "the PBMAC1 iterationCount " + iterationCount + " exceeds the cap " + cap);
  if (salt && salt.length > PBMAC1_MAX_SALT) throw _err("cmp/bad-input", "the PBMAC1 salt exceeds the " + PBMAC1_MAX_SALT + "-octet cap");
  if (keyLength < PBMAC1_KEYLEN_MIN || keyLength > PBMAC1_KEYLEN_MAX) throw _err("cmp/bad-input", "the PBMAC1 keyLength must be in [" + PBMAC1_KEYLEN_MIN + ", " + PBMAC1_KEYLEN_MAX + "] (RFC 9579 sec. 9)");
  // Bound the COMBINED work: PBKDF2 derives ceil(keyLength / hLen) blocks, each costing iterationCount HMACs, so a
  // maximal keyLength multiplies the per-block iteration ceiling (a 1024-octet key over SHA-256 = 32x). Cap the
  // product against the same ceiling so no keyLength/iteration combination exceeds the single-block work (CWE-834/400).
  var blocks = Math.ceil(keyLength / (PRF_HLEN[prfHash] || 32));
  if (iterationCount * blocks > cap) throw _err("cmp/bad-input", "the PBMAC1 combined work (iterationCount " + iterationCount + " x " + blocks + " derived blocks) exceeds the cap " + cap);
}

// M9-M14 + M20-M22: verify signature protection, then (with a trust store) FULL out-of-path cert validation.
async function _verifySignature(m, protectedPart, protectionAlg, protection, opts) {
  // Bound the UNSIGNED extraCerts ONCE (dedup + drop non-certificates + cap + scan cap) before either the
  // senderKID signer search or path building, so a hostile peer padding extraCerts cannot force unbounded
  // X.509 parsing or a candidate-pool overflow.
  var extra = _boundExtraCerts(m.extraCerts);
  var signer = _resolveSignerCert(m, opts, extra);
  if (!signer) return _fail(m, "signature", protectionAlg, "cmp/signer-cert-not-found", "no signer certificate resolved (opts.signerCert, senderKID, or extraCerts)");

  // M2/M9: verify over the reconstructed ProtectedPart through the ONE path-validate engine (the EdDSA
  // low-order-point gate + the sig-OID<->key-OID algorithm-confusion gate apply); fail-closed to false.
  var ok = await _engine.verifyWithSpki(protectionAlg, protection.bytes, signer.spki, protectedPart);
  if (ok !== true) return _fail(m, "signature", protectionAlg, "cmp/protection-failed", "the protection signature does not verify over the ProtectedPart under the declared protectionAlg", signer);

  // RFC 9483 sec. 3.1: for signature-based protection the authenticated header sender field MUST match the
  // protection certificate identity (failInfo badMessageCheck). Without this binding a holder of ANY
  // certificate the anchor trusts could set the sender to another party's name and be accepted as that
  // sender -- the signature and path both pass while the claimed identity is forged.
  if (!_senderBoundToCert(m.header.sender, signer.parsed)) {
    return _fail(m, "signature", protectionAlg, "cmp/sender-mismatch", "the header sender field does not match the signer certificate subject, or (for an empty subject) a subjectAltName entry (RFC 9483 sec. 3.1, RFC 5280 sec. 7.1)", signer);
  }

  // A failed opt-in echo check is a REJECTION verdict (valid:false), consistent with the MAC path -- a caller
  // that requested a transactionID / recipNonce binding must not see valid:true when it does not hold.
  var hc = _headerChecks(m, opts);
  if (hc) return _fail(m, "signature", protectionAlg, hc.code, hc.reason, signer);

  // M5/M12: with no trust store the verdict is crypto-only (trusted:false) and the signer is surfaced for
  // the caller to anchor. With a trust store the signer cert gets the FULL RFC 5280 sec. 6.1 path gates.
  if (opts.trustAnchors == null) return _ok(m, "signature", protectionAlg, false, signer);
  var trust = await _chainSigner(signer, m, opts, extra);
  return _verdict(m, "signature", protectionAlg, true, trust.trusted, trust.trusted ? null : "cmp/untrusted-signer", trust.reason, signer);
}

async function _chainSigner(signer, m, opts, extra) {
  // M13 first (cheap, format-local): a keyUsage that omits digitalSignature rejects the protection.
  if (!_keyUsageAllowsSigning(signer.parsed)) {
    return { trusted: false, reason: "the signer certificate keyUsage does not assert digitalSignature (RFC 9483 sec. 3.2)" };
  }
  // Validate the signer path at a TRUSTED current time by default -- NOT the message's self-asserted
  // messageTime, which the sender controls: a holder of a now-expired but once-valid signer certificate
  // could otherwise backdate messageTime into the certificate's validity window and be reported trusted.
  // A caller doing historical verification opts into a specific instant via opts.time; a falsy but PRESENT
  // opts.time (0 / false / "") is NOT silently replaced -- it reaches path.build and is rejected as bad-input.
  var time = opts.time != null ? opts.time : new Date();
  var anchors = _certList(opts.trustAnchors);
  // `extra` is the already dedup + validity + count-bounded extraCerts (unsigned pool material), so a flood
  // of duplicate / junk / non-certificate entries cannot exhaust the candidate-search budget or raise a
  // path/bad-input from a malformed pool certificate. Add it only up to the path-builder pool ceiling AFTER
  // the caller's intermediates, so unsigned extraCerts can never push a valid caller configuration over the
  // ceiling (if the caller's intermediates alone exceed it, that is a genuine config error path.build reports).
  var pool = _certList(opts.intermediates);
  var room = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - pool.length;
  if (room > 0) {
    // Drop the signer leaf (already passed to build as the path TARGET) and any extraCert duplicating a caller
    // intermediate BEFORE truncating to the remaining slots, so a tight ceiling spends those slots on genuinely
    // useful embedded issuers rather than a redundant copy of the signer or a duplicate the pool already holds.
    var seen = Object.create(null);
    seen[Buffer.from(signer.der).toString("base64")] = 1;
    pool.forEach(function (c) { if (Buffer.isBuffer(c) || c instanceof Uint8Array) seen[Buffer.from(c).toString("base64")] = 1; });
    var useful = extra.filter(function (c) { return !seen[Buffer.from(c).toString("base64")]; });
    pool = pool.concat(useful.slice(0, room));
  }
  var buildOpts = { trustAnchors: anchors, intermediates: pool, validate: true, time: time };
  if (opts.revocationChecker != null) buildOpts.revocationChecker = opts.revocationChecker;
  try {
    var res = await _engine.build(signer.der, buildOpts);
    if (!res || res.valid !== true) return { trusted: false, reason: "the signer certificate did not chain to a supplied trust anchor" };
    return { trusted: true, reason: null };
  } catch (e) {
    // A config-tier fault from path.build (an invalid opts.time, an empty / malformed trustAnchors or
    // intermediate) is a DEPLOYMENT error, not an untrusted signer -- rethrow it as cmp/bad-input so it is
    // not masked as a routine trust failure (the API contract: a bad required opt throws). A genuine
    // no-assemblable-path / validation failure collapses to an untrusted-signer verdict.
    if (e && e.code === "path/bad-input") {
      throw _err("cmp/bad-input", "invalid trust / validation options for signer-certificate path validation: " + (e.message || e), e);
    }
    return { trusted: false, reason: "signer certificate path validation failed: " + (e.message || e) };
  }
}

// Sanitize the message-provided extraCerts -- they are UNSIGNED pool material a hostile peer can pad without
// breaking protection: deduplicate by exact DER, DROP any entry that is not a parseable X.509 certificate (a
// bare non-cert SEQUENCE would otherwise reach path.build and raise a config-tier path/bad-input), and keep at
// most MAX_EXTRA_CERTS. The whole scan is bounded to MAX_EXTRA_SCAN entries so a flood of junk cannot force
// unbounded X.509 parsing; the RFC 9483 sec. 3.3 protection cert is extraCerts[0], so it is examined first.
var MAX_EXTRA_CERTS = 32;      // valid, distinct certificates kept for signer resolution + path building
var MAX_EXTRA_SCAN = 256;      // total entries examined -- bounds parse work regardless of the flood size
function _boundExtraCerts(extra) {
  if (!Array.isArray(extra) || !extra.length) return [];
  var out = [], seen = Object.create(null);
  for (var i = 0; i < extra.length && out.length < MAX_EXTRA_CERTS && i < MAX_EXTRA_SCAN; i++) {
    var c = extra[i];
    if (!Buffer.isBuffer(c) && !(c instanceof Uint8Array)) continue;
    var key = Buffer.from(c).toString("base64");
    if (seen[key]) continue;
    seen[key] = true;
    // drop a non-certificate entry (unsigned, attacker-supplied pool material) before it reaches path.build
    try { x509.parse(c); }
    catch (_e) { continue; }
    out.push(c);
  }
  return out;
}

// A trust-anchor / pool list from a single cert (DER/PEM) or an array of them.
function _certList(v) {
  if (v == null) return [];
  var arr = Array.isArray(v) ? v : [v];
  return arr.map(function (c) { return (Buffer.isBuffer(c) || c instanceof Uint8Array || typeof c === "string") ? _certDer(c, "a trust anchor / intermediate") : c; });
}

// A usable PBMAC1 shared secret: a non-empty string or a non-empty Buffer/Uint8Array (mirrors cmp-build).
function _nonEmptySecret(s) {
  if (typeof s === "string") return s.length > 0;
  return (Buffer.isBuffer(s) || s instanceof Uint8Array) && s.length > 0;
}

function verify(message, opts) {
  return Promise.resolve().then(function () { return _verify(message, opts); });
}

async function _verify(message, opts) {
  opts = opts || {};   // null / undefined -> the default empty opts
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("cmp/bad-input", "opts must be an object");
  Object.keys(opts).forEach(function (k) { if (!KNOWN_VERIFY_OPTS[k]) throw _err("cmp/bad-input", "unknown opts field " + JSON.stringify(k)); });
  if (_engine == null) throw _err("cmp/bad-input", "the cmp-verify signature engine is not initialized (require pki before use)");

  var m = _coerce(message);
  var protectionAlg = m.header.protectionAlg;
  var protection = m.protection;

  // M3/M5: the parser guarantees protection<->protectionAlg presence agreement; an absent protection is a
  // hard reject -- absence is never "verified".
  if (protection === null || protectionAlg === null) {
    return _fail(m, null, protectionAlg, "cmp/no-protection", "the PKIMessage carries no protection (RFC 9810 sec. 5.1.3); an unprotected message is never verified");
  }

  // M2: reconstruct the ProtectedPart from the RAW surfaced slices -- byte-identical to what build signed,
  // never a re-serialization of the decoded header/body structs.
  var protectedPart = b.sequence([b.raw(m.headerBytes), b.raw(m.bodyBytes)]);

  // M7: a recognized legacy / KEM MAC OID is refused before any dispatch (never a silent accept).
  if (UNSUPPORTED_MAC_OIDS[protectionAlg.oid]) {
    return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "the " + UNSUPPORTED_MAC_OIDS[protectionAlg.oid] + " protection algorithm is not supported (v1 verifies PBMAC1 and signature protection; RFC 9481 sec. 6.1.1)");
  }

  // M6: flavor from the protectionAlg OID alone, never guessed from the caller's credential.
  var isMac = protectionAlg.oid === oid.byName("pbmac1");
  var hasSigCred = opts.signerCert != null || opts.trustAnchors != null;
  var hasSecret = opts.sharedSecret != null;

  // M8: flavor<->credential coherence (the wrongIntegrity condition) is a config-tier throw.
  if (isMac) {
    if (hasSigCred) throw _err("cmp/bad-input", "a MAC-protected message takes opts.sharedSecret, not signerCert/trustAnchors");
    // The shared secret must be NON-EMPTY (matching pki.cmp.build): an empty "" / zero-length secret has no
    // entropy, so a peer could forge a matching PBMAC1 with no secret and be reported valid + trusted.
    if (!_nonEmptySecret(opts.sharedSecret)) throw _err("cmp/bad-input", "a PBMAC1-protected message requires a non-empty opts.sharedSecret");
    return _verifyMac(m, protectedPart, protectionAlg, protection, opts);
  }
  if (hasSecret) throw _err("cmp/bad-input", "a signature-protected message takes opts.signerCert/trustAnchors, not sharedSecret");
  return _verifySignature(m, protectedPart, protectionAlg, protection, opts);
}

/**
 * @primitive  pki.cmp.verify
 * @signature  pki.cmp.verify(message, opts?) -> Promise<verdict>
 * @since      0.3.26
 * @status     experimental
 * @spec       RFC 9810, RFC 9481, RFC 9579, RFC 9483
 * @related    pki.cmp.build, pki.schema.cmp.parse
 * @defends    cmp-unverified-protection (CWE-347), cmp-mac-timing (CWE-208)
 *
 * Verify the protection on an incoming RFC 9810 CMP `PKIMessage` -- the verify-inverse of
 * `pki.cmp.build`. `message` is a raw DER `Buffer`, a PEM `CMP` string, or an already-parsed
 * `pki.schema.cmp.parse` result (the protection is always recomputed from the parser-surfaced raw
 * `headerBytes` / `bodyBytes`, so a mutated display field on a parsed object cannot desync the crypto).
 * The protection flavor is read from the header `protectionAlg` alone: `id-PBMAC1` selects the MAC path,
 * a signature `AlgorithmIdentifier` the signature path; an unprotected message, or a recognized legacy /
 * KEM MAC algorithm (`id-PasswordBasedMac` / `id-DHBasedMac` / `id-KemBasedMac`), fails closed. On the
 * signature path the authenticated header `sender` field MUST match the signer certificate subject (RFC 9483
 * sec. 3.1), so a certificate the anchor trusts cannot sign under another party's sender name.
 *
 * Returns a verdict (never a bare boolean): `{ valid, trusted, protectionType, protectionAlg, signer,
 * transactionID, senderNonce, recipNonce, header, body, code?, reason? }`. `valid` is whether the
 * protection is cryptographically intact under the declared algorithm; `trusted` is whether a MAC secret
 * matched or a signature signer certificate chained to a supplied trust anchor. A well-formed but
 * unverifiable message is a `{ valid: false }` verdict carrying a `cmp/*` code, not a throw; only malformed
 * input (a non-PKIMessage, a bad required opt, a flavor/credential mismatch) throws a typed `CmpError`.
 *
 * @opts
 *   - `sharedSecret` (string|Buffer) -- the PBMAC1 secret; REQUIRED for a MAC-protected message (UTF-8).
 *   - `signerCert` (Buffer|PEM) -- the expected signature signer certificate (else resolved from
 *     `extraCerts` by `senderKID` or, per RFC 9483 sec. 3.3, `extraCerts[0]`).
 *   - `trustAnchors` (Buffer|Buffer[]|PEM) -- when present the signer certificate is FULLY path-validated
 *     (RFC 5280 sec. 6.1 plus the `keyUsage.digitalSignature` gate) to report `trusted`; absent -> the
 *     verdict is crypto-only (`trusted: false`) and the signer certificate is surfaced for the caller to
 *     anchor. The signature verify never routes through build's self-check (which skips the EdDSA
 *     low-order-point gate) -- it uses the same engine `pki.crl.verify` / `pki.ocsp.verify` do.
 *   - `intermediates` (Buffer|Buffer[]|PEM) -- extra untrusted pool certificates for path building
 *     (`extraCerts` are added automatically, as untrusted pool material).
 *   - `time` (Date) -- the validity instant for path validation. Defaults to the current time (the message's
 *     self-asserted `messageTime` is NOT trusted for this); pass an explicit instant for historical verification.
 *   - `transactionID` (Buffer) -- opt-in: require `header.transactionID` to equal it (response-echo defense).
 *   - `expectRecipNonce` (Buffer) -- opt-in: require `header.recipNonce` to echo the sent sender nonce.
 *   - `revocationChecker` -- forwarded to `pki.path.validate` when chaining the signer certificate.
 *   - `maxIterations` (number) -- downward-only override of the PBKDF2 iteration cap.
 *
 * @example
 *   var v = await pki.cmp.verify(cmpDer, { signerCert: signerCertDer, trustAnchors: [certDer] });
 *   if (v.valid && v.trusted) console.log("the response protection is authentic and the signer is trusted");
 */

module.exports = {
  build: cmpBuild.build,
  transfer: cmpBuild.transfer,
  wellKnownUrl: cmpBuild.wellKnownUrl,
  verify: verify,
  setEngine: setEngine,
};
