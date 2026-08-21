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
// The load-bearing rule: the protection is recomputed over the exact ProtectedPart bytes the builder
// signed, a SEQUENCE { header, body } reconstructed from the parser-surfaced raw headerBytes / bodyBytes
// (schema-cmp), never a re-serialization of the decoded structs. A re-encoder that normalized a malleable
// interior field would run the recompute over different bytes than a strict signer covered: both a false
// reject for a canonical peer and a bypass. The signature path routes through the single path-validate engine
// (with the EdDSA low-order-point gate) injected via setEngine, never build's self-check, which skips it.
// RFC 9810 sec. 5.1.3, algorithms RFC 9481 / RFC 9579, out-of-path signer profile RFC 9483.

// The slot predicates and the array test, snapshotted at load through the guard family's own home
// for that. Both decide whether a caller's value gets COPIED, so reading either at call time hands
// the copy decision to the caller: an `isUint8Array` answering false leaves a live caller buffer
// where the copy belongs and leaves that buffer out of the wipe list, and an `Array.isArray`
// answering false routes a trust list past the list door and back out by reference.
var intrinsic = require("./guard-intrinsic");
var _sizeOf = intrinsic.sizeOf;
var util = { types: intrinsic.types };
// The rest of what this verb reads from the runtime while it is reducing a caller's options, taken
// at load. The option door decides what gets copied and what gets refused, which is the same kind
// of decision a guard makes, so it is held to the same rule: the check over lib/ that refuses a
// live read covers every module importing these, and this one does. See guard-intrinsic.
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _fromCharCode = intrinsic.fromCharCode;
var _stringify = intrinsic.stringify;
var _getOwnPropertyNames = intrinsic.getOwnPropertyNames;
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _create = intrinsic.create;
var _floor = intrinsic.floor;
var _ceil = intrinsic.ceil;
var _min = intrinsic.min;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _toLowerCase = intrinsic.uncurry(String.prototype.toLowerCase);
var _strIndexOf = intrinsic.uncurry(String.prototype.indexOf);
var _compare = intrinsic.compare;
// The byte-to-text step of the SAN comparison below, and of the certificate identity key. One
// returning a constant makes every sender name equal every SAN, and collapses every certificate in
// the pool to one key.
var _toString = intrinsic.uncurry(Buffer.prototype.toString);
var _map = intrinsic.map;
// The conversions, captured for the same reason as everything above them: `String` is a writable
// property of globalThis, it renders the sender name that the SAN comparison compares, and it
// decides which own property names count as array indices in the density check below.
var _String = intrinsic.String;
var _isFinite = intrinsic.isFinite;
// The rest of the string and pattern surface the rfc822Name and URI comparisons below are built
// out of. Those comparisons decide whether a signer is allowed to speak for a sender, and every
// step of them -- where the mailbox separator is, which substring is the domain, whether a
// local-part is well-formed, how a URI splits into scheme and authority -- is one of these calls.
// A replacement anywhere in the chain moves the boundary, and the identity the verb ends up
// comparing is no longer the one the certificate carries.
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _strLastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _strSearch = intrinsic.uncurry(String.prototype.search);
var _reTest = intrinsic.uncurry(RegExp.prototype.test);
var _reExec = intrinsic.uncurry(RegExp.prototype.exec);
var _isArray = Array.isArray;
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
var ipUtils = require("./ip-utils");
var frameworkError = require("./framework-error");

var CmpError = frameworkError.CmpError;
var b = asn1.build;
function _err(code, message, cause) { return new CmpError(code, message, cause); }

// The cmp error namespace, reused so PBMAC1-params decode faults surface as cmp/bad-mac-data.
var NS = pkix.makeNS("cmp", CmpError, oid);
var PBMAC1_PARAMS = pkix.pbmac1Params(NS);
// The shared RFC 5280 sec. 4.2.1 extension-value decoders (the acme / inspect home): the signer keyUsage gate
// reads through the single structurally-strict decoder (X.690 sec. 11.2.2 minimal NamedBitList), not a
// hand-rolled bit test, so a malformed KeyUsage fails the gate independently of the path validator also rejecting it.
var _certExtDecoders = pkix.certExtensionDecoders(NS).byOid;

var KNOWN_VERIFY_OPTS = {
  sharedSecret: 1, signerCert: 1, trustAnchors: 1, intermediates: 1, time: 1,
  transactionID: 1, expectRecipNonce: 1, revocationChecker: 1, maxIterations: 1,
};

// PBMAC1 PBKDF2-PRF / messageAuthScheme name -> WebCrypto hash. Only SHA-256/384/512 are supported
// (RFC 9481 sec. 7 mandates SHA-256; RFC 9579 sec. 7 bars a <= 160-bit digest, so hmacWithSHA1, and an
// omitted-PRF that resolves to it, is unsupported and never MAC-verified under a weak digest).
// Keyed by the immutable dotted OID, never the display name: pki.oid.register() can rename hmacWithSHA256/384/512,
// so a name-keyed lookup would reject a valid PBMAC1 message under a renamed registry (the immutable-OID-dispatch rule).
// Null-prototype, because this table is read as an allowlist: on a `{}` a planted
// `Object.prototype["1.2.3"]` names a hash for a PRF OID the table never carried, and an
// unsupported PRF is then admitted and dispatched.
var PRF_HASH = _create(null);
PRF_HASH[oid.byName("hmacWithSHA256")] = "SHA-256";
PRF_HASH[oid.byName("hmacWithSHA384")] = "SHA-384";
PRF_HASH[oid.byName("hmacWithSHA512")] = "SHA-512";

// Attacker-controlled PBKDF2 work-factor bounds (RFC 8018 sec. 4.2; the pkcs12 verifyMac / _capWork model).
var PBMAC1_MAX_ITER = constants.LIMITS.PBKDF2_MAX_ITERATIONS;
var PBMAC1_MIN_ITER = 1000;    // RFC 8018 sec. 4.2 floor -- matches pki.cmp.build; a trivially small count is refused
var PBMAC1_MIN_SALT = 8;       // octets -- RFC 8018 sec. 4.1 (64-bit) floor; an empty/short salt loses precomputation resistance
var PBMAC1_MAX_SALT = constants.LIMITS.PBKDF2_MAX_SALT;
var PBMAC1_KEYLEN_MIN = 20;    // RFC 9579 sec. 9 -- a short derived key is refused
var PBMAC1_KEYLEN_MAX = 1024;
// PBKDF2 PRF output length (octets) -- the size of one derived block; keyLength beyond it costs extra HMAC rounds.
var PRF_HLEN = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };

// The legacy / KEM MAC protection OIDs (RFC 9810 sec. 5.1.3.1/.2/.4) the v1 verifier recognizes and refuses.
// Build emits only PBMAC1, so the verifier rejects a legacy/KEM MAC OID and never accepts a construction
// it does not verify (a silent accept of an unverified algorithm would be fail-open).
var UNSUPPORTED_MAC_OIDS = _create(null);
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
    signer: signer ? { cert: signer.der, spki: signer.spki, subject: signer.subject, chain: signer.chain || null } : null,
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
  if (message && typeof message === "object" && !_isBuffer(message) && !util.types.isUint8Array(message) &&
    message.headerBytes !== undefined && message.bodyBytes !== undefined &&
    message.header !== undefined && message.body !== undefined) {
    // A malformed raw slice (a null protection.bytes, a non-buffer extraCerts entry) makes _reassemble throw a
    // raw Asn1Error; normalize it to the documented typed cmp/bad-input so every malformed input surfaces a
    // cmp/* code (cmp.parse's own faults are already CmpError and propagate unchanged).
    try { return cmp.parse(_reassemble(message)); }
    catch (e) { throw e instanceof CmpError ? e : _err("cmp/bad-input", "the parsed PKIMessage object carries a malformed raw slice (headerBytes / bodyBytes / protection / extraCerts): " + ((e && e.message) || e), e); }
  }
  // A raw Buffer / Uint8Array parses into zero-copy views; a caller that mutates the input after verify would
  // change the returned authenticated fields (transactionID, nonces, header, body) while valid stays true.
  // Parse a PRIVATE copy so every verdict field is bound to the verified snapshot, never the caller's mutable
  // buffer. (A PEM string is immutable and base64-decodes into fresh bytes, so it needs no copy.)
  // The slot, not the prototype: this decides whether the message is privately copied before it is
  // parsed, and `instanceof` consults `Uint8Array[Symbol.hasInstance]` at call time.
  if (_isBuffer(message) || util.types.isUint8Array(message)) return cmp.parse(_bufferFrom(message));
  return cmp.parse(message);   // a PEM CMP string (throws cmp/* on malformed input)
}

// Rebuild the PKIMessage DER from a parsed object's raw slices: SEQUENCE { header, body, protection [0]
// EXPLICIT BIT STRING OPTIONAL, extraCerts [1] EXPLICIT SEQUENCE OPTIONAL }, the exact inverse of the
// parser's surfaced fields (cmp-build.js assembles the identical shape). Re-parsing this authenticates every
// field against the raw bytes, discarding any mutated decoded field the caller may have carried.
function _reassemble(m) {
  var kids = [b.raw(m.headerBytes), b.raw(m.bodyBytes)];
  if (m.protection != null) _append(kids, b.explicit(0, b.bitString(m.protection.bytes, m.protection.unusedBits)));
  if (m.extraCerts != null && m.extraCerts.length) {
    // Through the captured `map`: this rebuilds the exact bytes the protection is checked against,
    // so a replacement returning a different array decides what the signature is verified over.
    _append(kids, b.explicit(1, b.sequence(_map(m.extraCerts, function (c) { return b.raw(c); }))));
  }
  return b.sequence(kids);
}

// A certificate DER from a Buffer/Uint8Array (detached-view-safe) or a PEM string.
function _certDer(cert, what) {
  if (_isBuffer(cert) || util.types.isUint8Array(cert)) return guard.bytes.view(cert, CmpError, "cmp/bad-input", what);
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

// The decoded GeneralName nodes of a parsed certificate's subjectAltName (empty if none / malformed).
// x509.parse surfaces `value` as the unwrapped extnValue content; for SAN that is the SEQUENCE OF GeneralName.
function _sanGeneralNames(parsed) {
  var sanOid = oid.byName("subjectAltName");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== sanOid) continue;
    // RFC 5280 sec. 4.2.1.6: subjectAltName is a SEQUENCE OF GeneralName. Validate the outer structure AND every
    // entry through the shared generalNames schema before any child is used for identity binding: path validation
    // does not decode a non-critical, otherwise-unused SAN, so a malformed outer tag (e.g. a SET wrapping a valid
    // [2]) or a malformed entry must fail closed to no entries (a sender-mismatch), never bind an unvalidated name.
    try {
      var node = asn1.decode(exts[i].value);
      schema.walk(pkix.generalNames(NS, { code: "cmp/sender-mismatch" }), node, NS);
      return node.children || [];
    } catch (_e) { return []; }
  }
  return [];
}

// RFC 9483 sec. 3.1 sender <-> protection-certificate binding. The sender matches the certificate identity if
// it equals the POPULATED subject DN (a [4] directoryName under the RFC 5280 sec. 7.1 canonical comparison) OR
// a subjectAltName GeneralName entry -- checked regardless of whether the subject is empty, so a certificate
// that carries both a subject and a SAN can be identified by either, and an empty subject (RFC 5280 sec.
// 4.1.2.6 requires a critical SAN) is bound to its SAN identity, never accepted with an anonymous sender.
function _senderBoundToCert(sender, parsed) {
  if (!sender || !sender.bytes) return false;
  var subjectRdns = parsed.subject.rdns;
  if (subjectRdns.length > 0) {
    var isDirName = sender.tagClass === "context" && sender.tagNumber === 4 && sender.value && _isArray(sender.value.rdns);
    if (isDirName && guard.name.dnEqual(sender.value.rdns, subjectRdns, NS.E, "cmp/sender-mismatch", "the header sender / signer subject")) return true;
  }
  var san = _sanGeneralNames(parsed);
  for (var i = 0; i < san.length; i++) if (_generalNameMatches(sender, san[i])) return true;
  return false;
}

// GeneralName equality (RFC 5280 sec. 7) for the sender <-> SAN binding, applying the per-type comparison
// rules in place of a universal byte compare: a dNSName [2] case-insensitively (sec. 4.2.1.6 / 7.2), an
// rfc822Name [1] with a case-insensitive domain (sec. 7.5), a uniformResourceIdentifier [6] with a
// case-insensitive scheme + host (sec. 4.2.1.6 / RFC 3986 sec. 6.2.2.1), a directoryName [4] under the sec.
// 7.1 canonical DN comparison, and every other type by exact DER (fail-closed). `sender` is the parsed [n]
// GeneralName from schema-cmp; `sanNode` is a decoded certificate SAN GeneralName node.
function _generalNameMatches(sender, sanNode) {
  if (sanNode.tagClass !== sender.tagClass || sanNode.tagNumber !== sender.tagNumber) return false;
  if (sanNode.tagClass === "context") {
    if (sanNode.tagNumber === 2 && sanNode.content) {   // dNSName IA5String
      var dnsSan = _toString(sanNode.content, "latin1"), dnsSender = _String(sender.value);
      // Case-fold only a well-formed dNSName (RFC 5280 sec. 4.2.1.6 / RFC 1034, via the shared validator): a
      // malformed name (an empty label like "victim..com", a leading/trailing dot, bad LDH) is compared
      // byte-exact and never folded, so it cannot bind a byte-distinct identity.
      if (pkix.dnsNameProblem(dnsSan) !== null || pkix.dnsNameProblem(dnsSender) !== null) return dnsSan === dnsSender;
      return _toLowerCase(dnsSender) === _toLowerCase(dnsSan);
    }
    if (sanNode.tagNumber === 1 && sanNode.content) {   // rfc822Name IA5String: case-insensitive domain
      return _rfc822Equal(_String(sender.value), _toString(sanNode.content, "latin1"));
    }
    if (sanNode.tagNumber === 6 && sanNode.content) {   // uniformResourceIdentifier IA5String: case-insensitive scheme + host
      return _uriEqual(_String(sender.value), _toString(sanNode.content, "latin1"));
    }
    if (sanNode.tagNumber === 4 && sanNode.children && sanNode.children.length) {   // directoryName: canonical DN
      if (!sender.value || !_isArray(sender.value.rdns)) return false;
      var sanName;
      try { sanName = schema.embeddedDer(pkix.name(NS), sanNode.children[0].bytes, NS, { code: "cmp/sender-mismatch", what: "SAN directoryName" }).result; }
      catch (_e) { return false; }
      return guard.name.dnEqual(sender.value.rdns, sanName.rdns, NS.E, "cmp/sender-mismatch", "SAN directoryName");
    }
  }
  return _compare(sanNode.bytes, sender.bytes) === 0;
}

// Index of the "@" separating an RFC 5321 addr-spec Local-part from its Domain, honoring a Quoted-string
// local-part ("...") that MAY itself contain "@" and backslash escapes. Returns -1 for a malformed mailbox
// (no separator, an unterminated quote, a quoted local-part not immediately followed by "@", or an unquoted
// local-part with more than one "@") so the caller compares byte-exact.
function _mailboxSplit(s) {
  var sep;
  if (_charAt(s,0) === "\"") {
    var i = 1;
    while (i < s.length) {
      var c = _charAt(s,i);
      if (c === "\\") { i += 2; continue; }   // an escaped pair (\c) -- skip both octets
      if (c === "\"") break;
      i++;
    }
    if (i >= s.length || _charAt(s,i) !== "\"" || _charAt(s,i + 1) !== "@") return -1;   // unterminated / not "@"-separated
    sep = i + 1;
  } else {
    sep = _strIndexOf(s, "@");   // an unquoted (Dot-string) local-part cannot contain a raw "@" -> exactly one total
    if (sep < 0 || sep !== _strLastIndexOf(s, "@")) return -1;
  }
  // The Domain that follows the separator must be a well-formed FQDN (RFC 1034, via the shared validator): an
  // empty / empty-label / extra-"@" domain is malformed. An unquoted Local-part must be a Dot-string: non-empty,
  // no leading/trailing dot, no empty atom ("a..b"). A quoted Local-part is already balanced above. A malformed
  // mailbox returns -1 so _rfc822Equal compares it byte-exact and never case-folds a malformed domain.
  var local = _strSlice(s, 0, sep), domain = _strSlice(s, sep + 1);
  if (pkix.dnsNameProblem(domain) !== null) return -1;
  // An unquoted (Dot-string) Local-part is atext atoms joined by single dots (RFC 5321 sec. 4.1.2): every
  // character must be an atext octet or a "." with no empty atom / leading-trailing dot. A malformed atom
  // character (e.g. a space in "user name") makes the whole address malformed -> byte-exact comparison.
  if (_charAt(s, 0) !== "\"" && (local.length === 0 || _charAt(local, 0) === "." || _charAt(local, local.length - 1) === "." || _strIndexOf(local, "..") !== -1 || !_reTest(/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/, local))) return -1;
  return sep;
}

// RFC 5280 sec. 7.5 rfc822Name comparison: the local-part is case-sensitive, the domain case-insensitive. The
// mailbox separator is located by _mailboxSplit (quoting-aware) so a valid quoted local-part carrying "@"
// still binds, while a truly malformed address falls back to byte-exact comparison.
function _rfc822Equal(a, b) {
  var ai = _mailboxSplit(a), bi = _mailboxSplit(b);
  if (ai < 0 || bi < 0) return a === b;
  return _strSlice(a, 0, ai) === _strSlice(b, 0, bi) &&
    _lowerAsciiDomain(_strSlice(a, ai + 1)) === _lowerAsciiDomain(_strSlice(b, bi + 1));
}

// sec. 7.5 authorizes a case-insensitive ASCII comparison of the host-part, and nothing
// wider. String.toLowerCase() is Unicode-aware and folds well beyond A-Z: U+212A KELVIN
// SIGN lowercases to "k", so a host carrying it would compare EQUAL to the ASCII spelling
// and two distinct domains would read as one identity. Fold only A-Z and leave every other
// octet alone, so a non-ASCII host can differ from an ASCII one but never collide with it.
function _lowerAsciiDomain(h) {
  var out = "";
  for (var i = 0; i < h.length; i++) {
    var c = _charCodeAt(h, i);
    out += (c >= 0x41 && c <= 0x5a) ? _fromCharCode(c + 32) : _charAt(h, i);
  }
  return out;
}

// RFC 5280 sec. 4.2.1.6 / RFC 3986 sec. 6.2.2.1 URI comparison: the scheme and the authority host are
// case-insensitive; every other component (userinfo, port, path, query, fragment) is byte-exact. Return
// null for anything that is not a well-formed absolute URI so the caller falls back to exact-DER (fail-closed
// -- never normalize an input we cannot confidently parse into a false identity match).
function _normalizeUri(u) {
  // RFC 3986 syntax: every character must be a URI character and every "%" must introduce a valid pct-encoding
  // (%HH). A URI with an out-of-charset byte or a malformed percent-escape ("%zz") in any component (path,
  // query, fragment, userinfo) is not normalized; return null so it is compared byte-exact.
  if (!_reTest(/^[A-Za-z0-9._~:/?#@!$&'()*+,;=%[\]-]*$/, u) || _reTest(/%(?![0-9A-Fa-f]{2})/, u)) return null;
  var m = _reExec(/^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/, u);   // scheme ":" rest (RFC 3986 sec. 3.1)
  if (!m) return null;
  var scheme = _toLowerCase(m[1]);
  var rest = m[2];
  // A URI SAN identity is host-based (RFC 5280 sec. 4.2.1.6): an authority-free URI (no "//", e.g. a URN) has
  // no host to anchor the comparison, so compare it byte-exact and never case-fold its scheme; the shared
  // GeneralName parser only enforces printable IA5, not a present authority.
  if (_strSlice(rest, 0, 2) !== "//") return null;
  var body = _strSlice(rest, 2);
  var cut = _strSearch(body, /[/?#]/);   // authority ends at the first "/", "?" or "#" (RFC 3986 sec. 3.2)
  var split = cut < 0 ? body.length : cut;
  var authority = _strSlice(body, 0, split), tail = _strSlice(body, split);   // tail: path/query/fragment -- exact
  // A raw "@" is not permitted inside userinfo (RFC 3986 sec. 3.2.1); more than one "@" is a MALFORMED
  // authority -> return null so it is compared byte-exact, never split into a userinfo that folds the host.
  if (_strIndexOf(authority, "@") !== _strLastIndexOf(authority, "@")) return null;
  var at = _strLastIndexOf(authority, "@");   // [ userinfo "@" ] host [ ":" port ] -- userinfo stays case-sensitive
  var userinfo = at < 0 ? "" : _strSlice(authority, 0, at + 1);
  var hostport = at < 0 ? authority : _strSlice(authority, at + 1);
  // Split the host from an optional ":port": an IPv6 literal "[...]" carries the port after the "]", otherwise
  // the port follows the first ":". Case-fold only the host (RFC 3986 sec. 6.2.2.1); the port stays byte-exact
  // so a malformed non-numeric port (":ADMIN" vs ":admin") is never folded into a false identity match.
  var host, port;
  if (_charAt(hostport, 0) === "[") {
    var rb = _strIndexOf(hostport, "]");
    if (rb < 0) return null;   // an unterminated IPv6 literal is malformed -> exact-DER fallback (fail-closed)
    host = _strSlice(hostport, 0, rb + 1); port = _strSlice(hostport, rb + 1);
  } else {
    var ci = _strIndexOf(hostport, ":");
    host = ci < 0 ? hostport : _strSlice(hostport, 0, ci); port = ci < 0 ? "" : _strSlice(hostport, ci);
  }
  // The port must be numeric (RFC 3986 sec. 3.2.3 port = *DIGIT). A non-numeric port is a malformed authority:
  // return null so the caller compares the raw values exactly and never case-folds the host of an input the
  // normalizer cannot confidently parse (which would bind two byte-distinct malformed authorities).
  if (port !== "" && !_reTest(/^:[0-9]*$/, port)) return null;
  // The authority host must be a well-formed FQDN or IP literal (RFC 5280 sec. 4.2.1.6 requires a URI SAN
  // authority to carry an FQDN/IP host): an empty, malformed ("Victim..COM"), or bad IPv6-literal host is
  // compared byte-exact and never case-folded, since the GeneralName parser only enforces printable IA5.
  var hostOk = _charAt(host, 0) === "["
    ? (_charAt(host, host.length - 1) === "]" && ipUtils.expandIpv6Hex(_strSlice(host, 1, -1)) !== null)
    : (pkix.dnsNameProblem(host) === null);
  if (!hostOk) return null;
  return scheme + "://" + userinfo + _toLowerCase(host) + port + tail;
}
function _uriEqual(a, b) {
  var na = _normalizeUri(a), nb = _normalizeUri(b);
  if (na === null || nb === null) return a === b;
  return na === nb;
}

// M11/M14: resolve the signature-protection signer certificate. An explicit opts.signerCert wins (with the
// senderKID SKI binding when present); else `extra` (the already dedup+validity+count-bounded extraCerts) by
// senderKID, else RFC 9483 sec. 3.3, where extraCerts[0] is the protection certificate. `extra` is bounded before
// this search so an unsigned flood cannot force unbounded X.509 parsing. Returns { der, spki, subject, parsed }
// or null (never verify against an unauthenticated key).
function _resolveSignerCert(m, opts, extra) {
  var senderKID = m.header.senderKID;   // Buffer or null
  function _signerObj(der, p) { return { der: der, spki: p.subjectPublicKeyInfo.bytes, subject: _subjectDn(p), parsed: p }; }
  function accept(der) {   // an UNTRUSTED message candidate: the senderKID (when present) narrows the search to the
    var p;                 // certificate whose SKI it names; a non-parseable / SKI-mismatched entry is skipped (null).
    try { p = x509.parse(der); } catch (_e) { return null; }
    if (senderKID != null) {
      var ski = _certSki(p);
      if (ski == null || !guard.crypto.constantTimeEqual(ski, senderKID)) return null;
    }
    return _signerObj(der, p);
  }
  if (opts.signerCert != null) {
    // The explicit signer certificate is REQUIRED CONFIG, not untrusted pool material. Snapshot it (_certDer
    // returns a VIEW into a caller Buffer, and der/spki are surfaced in the verdict, so a post-verify mutation
    // would change verdict.signer.cert/.spki). Parse it SEPARATELY: a corrupt / mistyped certificate is a
    // deployment error that THROWS cmp/bad-input, never a routine signer-cert-not-found verdict indistinguishable
    // from a message that simply omitted its signer (the nullable path is reserved for message candidates).
    // The caller explicitly selected this certificate, so the senderKID (a hint for narrowing a candidate search)
    // is not applied here: the protection signature verification against this cert's key is the real gate; a
    // valid message from a signer certificate that omits an SKI still resolves to its exact opts.signerCert.
    var scDer = _bufferFrom(_certDer(opts.signerCert, "opts.signerCert"));
    var scParsed;
    try { scParsed = x509.parse(scDer); }
    catch (e) { throw _err("cmp/bad-input", "opts.signerCert is not a parseable X.509 certificate", e); }
    return _signerObj(scDer, scParsed);
  }
  if (senderKID != null) {
    for (var i = 0; i < extra.length; i++) { var r = accept(extra[i]); if (r) return r; }
    return null;
  }
  if (extra.length) return accept(extra[0]);   // RFC 9483 sec. 3.3: extraCerts[0] is the protection cert
  return null;
}

// M20-M22 header consistency (opt-in echoes). Returns { code, reason } on a mismatch, else null. These are
// public transaction identifiers, not secrets, so a length-checked equality (not a MAC compare) is correct.
// The comparison runs through the captured `Buffer.compare`, which decides length and content
// together from the values' slots. `a.equals(x)` reads `equals` off the prototype at call time, so
// one returning true matches any expected identifier against any received one -- and it sat behind
// a length gate reading the same replaceable accessor, which cannot refuse what it is told.
function _bufEq(a, x) {
  if (!_isBuffer(a)) return false;
  if (!_isBuffer(x)) { if (util.types.isUint8Array(x)) x = _bufferFrom(x); else return false; }
  return _compare(a, x) === 0;
}
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
    var ku;
    // Decode through the shared keyUsage decoder: it enforces the RFC 5280 sec. 4.2.1.3 BIT STRING form + the
    // X.690 sec. 11.2.2 minimal NamedBitList rule (rejecting a non-minimal 03 02 00 80). A malformed KeyUsage
    // fails this gate, so no hand-rolled bit test authorizes it and leans on path validation to reject it.
    try { ku = _certExtDecoders[kuOid](exts[i].value); }
    catch (_e) { return false; }
    return ku.digitalSignature === true;
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
  if (!prfHash) return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "unsupported PBMAC1 PBKDF2 PRF " + _stringify(kdf.prfName) + " (SHA-256/384/512 only; RFC 9481 sec. 7, RFC 9579 sec. 7)");
  if (!macHash) return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "unsupported PBMAC1 messageAuthScheme " + _stringify(params.schemeName) + " (SHA-256/384/512 only)");

  // M18: bound the attacker-controlled work factors before deriving (CWE-834/400). A config-tier throw.
  _capWork(kdf.iterationCount, kdf.salt, kdf.keyLength, prfHash, opts);

  // M19: recompute the MAC over the reconstructed ProtectedPart and compare in constant time.
  var secret = typeof opts.sharedSecret === "string" ? _bufferFrom(opts.sharedSecret, "utf8") : guard.bytes.view(opts.sharedSecret, CmpError, "cmp/bad-input", "opts.sharedSecret");
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
    if (typeof opts.maxIterations !== "number" || !_isFinite(opts.maxIterations) || opts.maxIterations < 1 || _floor(opts.maxIterations) !== opts.maxIterations) {
      throw _err("cmp/bad-input", "opts.maxIterations must be a positive integer");
    }
    cap = _min(opts.maxIterations, cap);
  }
  // A trivially small count lets a peer run cheap offline PBMAC1 guesses against a password-like shared secret
  // with parameters pki.cmp.build refuses to produce (RFC 8018 sec. 4.2). Enforce the same floor on verify.
  if (iterationCount < PBMAC1_MIN_ITER) throw _err("cmp/bad-input", "the PBMAC1 iterationCount " + iterationCount + " is below the floor " + PBMAC1_MIN_ITER + " (RFC 8018 sec. 4.2)");
  if (iterationCount > cap) throw _err("cmp/bad-input", "the PBMAC1 iterationCount " + iterationCount + " exceeds the cap " + cap);
  var saltLen = salt ? _sizeOf(salt) : 0;
  if (!salt || saltLen < PBMAC1_MIN_SALT || saltLen > PBMAC1_MAX_SALT) throw _err("cmp/bad-input", "the PBMAC1 salt length must be in [" + PBMAC1_MIN_SALT + ", " + PBMAC1_MAX_SALT + "] octets (RFC 8018 sec. 4.1)");
  if (keyLength < PBMAC1_KEYLEN_MIN || keyLength > PBMAC1_KEYLEN_MAX) throw _err("cmp/bad-input", "the PBMAC1 keyLength must be in [" + PBMAC1_KEYLEN_MIN + ", " + PBMAC1_KEYLEN_MAX + "] (RFC 9579 sec. 9)");
  // Bound the COMBINED work: PBKDF2 derives ceil(keyLength / hLen) blocks, each costing iterationCount HMACs, so a
  // maximal keyLength multiplies the per-block iteration ceiling (a 1024-octet key over SHA-256 = 32x). Cap the
  // product against the same ceiling so no keyLength/iteration combination exceeds the single-block work (CWE-834/400).
  var blocks = _ceil(keyLength / (PRF_HLEN[prfHash] || 32));
  if (iterationCount * blocks > cap) throw _err("cmp/bad-input", "the PBMAC1 combined work (iterationCount " + iterationCount + " x " + blocks + " derived blocks) exceeds the cap " + cap);
}

// M9-M14 + M20-M22: verify signature protection, then (with a trust store) full out-of-path cert validation.
async function _verifySignature(m, protectedPart, protectionAlg, protection, opts) {
  // Bound the unsigned extraCerts once (dedup + drop non-certificates + cap + scan cap) before either the
  // senderKID signer search or path building, so a hostile peer padding extraCerts cannot force unbounded
  // X.509 parsing or a candidate-pool overflow.
  var extra = _boundExtraCerts(m.extraCerts);
  var signer = _resolveSignerCert(m, opts, extra);
  if (!signer) return _fail(m, "signature", protectionAlg, "cmp/signer-cert-not-found", "no signer certificate resolved (opts.signerCert, senderKID, or extraCerts)");

  // M2/M9: verify over the reconstructed ProtectedPart through the single path-validate engine (the EdDSA
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

  // A failed opt-in echo check is a rejection verdict (valid:false), consistent with the MAC path: a caller
  // that requested a transactionID / recipNonce binding must not see valid:true when it does not hold.
  var hc = _headerChecks(m, opts);
  if (hc) return _fail(m, "signature", protectionAlg, hc.code, hc.reason, signer);

  // M5/M12: with no trust store the verdict is crypto-only (trusted:false) and the signer is surfaced for
  // the caller to anchor. With a trust store the signer cert gets the full RFC 5280 sec. 6.1 path gates.
  if (opts.trustAnchors == null) return _ok(m, "signature", protectionAlg, false, signer);
  var trust = await _chainSigner(signer, m, opts, extra);
  // Surface the chain that actually validated (signer + the intermediates path.build used) on a trusted verdict,
  // so a caller can cache exactly the certificates that established trust, not the unsigned extraCerts a peer
  // can pad: an appended-but-unused certificate never enters this chain.
  if (trust.chain) signer.chain = trust.chain;
  return _verdict(m, "signature", protectionAlg, true, trust.trusted, trust.trusted ? null : "cmp/untrusted-signer", trust.reason, signer);
}

// A canonical certificate identity (tbs + signature) for the extraCerts pool dedup: it keys a Buffer /
// Uint8Array (parse) and an already-parsed candidate object identically (path.build accepts both forms), so
// an extraCert duplicating a caller intermediate is dropped regardless of which representation the caller used.
// The key is derived from the bytes the parser recorded, through the same door every other
// certificate boundary uses -- never from the fields of the object handed in. Deriving it from a
// caller-shaped object would let two different certificates collapse onto one key, which is the one
// outcome this must not have. Failure returns null (the caller's contract here): an underivable
// identity leaves a redundant pool slot, which is safe, while a wrong merge is not.
function _certKey(c) {
  try {
    var p = guard.parsed.acceptDerived(c, "certificate", x509.parse, _err, "cmp/bad-input", "a pool certificate");
    if (!guard.parsed.isCert(p)) return null;
    return _toString(p.tbsBytes, "base64") + "|" + _toString(p.signatureValue.bytes, "base64");
  } catch (_e) {
    return null;   // underivable: kept as its own slot, never merged onto another certificate's
  }
}

async function _chainSigner(signer, m, opts, extra) {
  // M13 first (cheap, format-local): a keyUsage that omits digitalSignature rejects the protection.
  if (!_keyUsageAllowsSigning(signer.parsed)) {
    return { trusted: false, reason: "the signer certificate keyUsage does not assert digitalSignature (RFC 9483 sec. 3.2)" };
  }
  // Validate the signer path at a trusted current time by default, never the message's self-asserted
  // messageTime, which the sender controls: a holder of a now-expired but once-valid signer certificate
  // could otherwise backdate messageTime into the certificate's validity window and be reported trusted.
  // A caller doing historical verification opts into a specific instant via opts.time; a falsy but present
  // opts.time (0 / false / "") is never silently replaced: it reaches path.build and is rejected as bad-input.
  // The default validation time, from the captured constructor. A replacement chooses the instant
  // every not-before / not-after and every revocation window is judged against, so an expired or
  // revoked certificate can be validated at a moment when it was neither.
  var time = opts.time != null ? opts.time : new _Date();
  var anchors = _certList(opts.trustAnchors);
  // `extra` is the already dedup + validity + count-bounded extraCerts (unsigned pool material), so a flood
  // of duplicate / junk / non-certificate entries cannot exhaust the candidate-search budget or raise a
  // path/bad-input from a malformed pool certificate. Add it only up to the path-builder pool ceiling, after
  // the caller's intermediates, so unsigned extraCerts can never push a valid caller configuration over the
  // ceiling (if the caller's intermediates alone exceed it, that is a genuine config error path.build reports).
  var pool = _certList(opts.intermediates);
  var room = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - pool.length;
  if (room > 0) {
    // Drop the signer leaf (already passed to build as the path TARGET) and any extraCert duplicating a caller
    // intermediate before truncating to the remaining slots, so a tight ceiling spends those slots on genuinely
    // useful embedded issuers, not on a redundant copy of the signer or a duplicate the pool already holds.
    // The identity is the canonical tbs+signature key so a Buffer extraCert dedups against a caller intermediate
    // supplied either as raw bytes or as an already-parsed certificate object (path.build accepts both).
    // Explicit loops, never forEach / filter / concat / slice. Everything from here to the verdict
    // runs after verification suspended, and every one of those is a replaceable global, so a
    // caller who swaps one during the window would have the pool assembled by their code.
    var seen = _create(null);
    var sk = _certKey(signer.parsed); if (sk) seen[sk] = 1;
    var pi, pk;
    for (pi = 0; pi < pool.length; pi++) { pk = _certKey(pool[pi]); if (pk) seen[pk] = 1; }
    var merged = [];
    // Indexed assignment, never push: push is a replaceable global too, and everything here runs
    // after verification suspended, so a swapped one could put a certificate into the pool that the
    // caller never supplied. Writing the slot dispatches nothing.
    for (pi = 0; pi < pool.length; pi++) _append(merged, pool[pi]);
    for (pi = 0; pi < extra.length && merged.length - pool.length < room; pi++) {
      pk = _certKey(extra[pi]);
      if (pk == null || !seen[pk]) _append(merged, extra[pi]);
    }
    pool = merged;
  }
  var buildOpts = { trustAnchors: anchors, intermediates: pool, validate: true, time: time };
  if (opts.revocationChecker != null) buildOpts.revocationChecker = opts.revocationChecker;
  try {
    var res = await _engine.build(signer.der, buildOpts);
    if (!res || res.valid !== true) return { trusted: false, reason: "the signer certificate did not chain to a supplied trust anchor" };
    // res.path is the ordered certificates path.build assembled (signer + the intermediates it used), as PARSED
    // objects whose byte fields are subarrays of the (possibly multi-MB) response allocation. Map each back to its
    // source DER (the signer, or a DER pool entry) and return an INDEPENDENT copy, so a caller caching the chain
    // holds standalone buffers, never slices pinning the whole response. Only certs on the trusted path enter it,
    // so unsigned extraCerts padding is excluded. (A path cert sourced from an already-parsed intermediate carries
    // no DER to copy and is omitted; for a Buffer/DER pool, the cmp.session case, the chain is complete.)
    var byKey = _create(null);
    var skey = _certKey(signer.parsed); if (skey) byKey[skey] = signer.der;
    var ci, ck;
    for (ci = 0; ci < pool.length; ci++) {
      var pc = pool[ci];
      if (!_isBuffer(pc) && !util.types.isUint8Array(pc)) continue;
      ck = _certKey(pc); if (ck && !byKey[ck]) byKey[ck] = pc;
    }
    var chain = [];
    for (ci = 0; ci < res.path.length; ci++) {
      ck = _certKey(res.path[ci]);
      var d = ck ? byKey[ck] : null;
      if (d) _append(chain, _bufferFrom(d));
    }
    return { trusted: true, reason: null, chain: chain };
  } catch (e) {
    // A config-tier fault from path.build (an invalid opts.time, an empty / malformed trustAnchors or
    // intermediate) is a deployment error, not an untrusted signer, so rethrow it as cmp/bad-input and it is
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
  if (!_isArray(extra) || !extra.length) return [];
  var out = [], seen = _create(null);
  for (var i = 0; i < extra.length && out.length < MAX_EXTRA_CERTS && i < MAX_EXTRA_SCAN; i++) {
    var c = extra[i];
    if (!_isBuffer(c) && !util.types.isUint8Array(c)) continue;   // the slot, not the prototype
    // The pool's other identity key, through the same capture as _certKey's: one `toString`
    // returning a constant collapses every peer-supplied certificate onto one key, so the first
    // entry scanned suppresses all the rest.
    var key = _toString(_bufferFrom(c), "base64");
    if (seen[key]) continue;
    seen[key] = true;
    // drop a non-certificate entry (unsigned, attacker-supplied pool material) before it reaches path.build
    try { x509.parse(c); }
    catch (_e) { continue; }
    _append(out, c);
  }
  return out;
}

// Appending to a list this module owns, without dispatching anywhere a caller can reach.
//
// Everything that assembles a trust set runs AFTER verification has suspended, which is a window a
// caller can act in. `arr.push(v)` goes through Array.prototype.push, a replaceable global; and
// `arr[arr.length] = v` is a [[Set]], which walks the prototype chain and finds an
// `Array.prototype[0]` setter when the fresh array has no own slot there yet. Both hand control to
// caller code at the moment the anchor set is being decided.
//
// defineProperty is [[DefineOwnProperty]]: it creates the own slot outright, consulting no setter.
// The reference is captured at module load, before any caller code has run, so replacing
// `Object.defineProperty` afterwards cannot reach this either.
var _defineOwn = Object.defineProperty;
// The Date constructor, captured for the same reason and at the same moment. `global.Date` is
// replaceable, and a replacement asked for a fresh instant could hand back the caller's own object
// instead -- leaving the "copy" of opts.time as the very Date the caller can still call setTime on.
var _Date = Date;
// And Buffer.from, for the string shared secret. `Buffer.from` is a writable own property of the
// Buffer global, and the FIRST thing the reduction does is read opts.sharedSecret -- so that very
// accessor can install a replacement and then return the string, and an unguarded conversion would
// hand the plaintext to caller code and take back whatever it returned as the PBMAC1 key. The
// reference itself is the one taken at the top of this file, through guard-intrinsic.
function _append(arr, v) {
  _defineOwn(arr, arr.length, { value: v, writable: true, enumerable: true, configurable: true });
}

// A trust-anchor / pool list from a single cert (DER/PEM) or an array of them.
//
// Built with an explicit loop and INDEXED ASSIGNMENT -- never `arr.map`, and never `out.push`. This
// runs AFTER verification has suspended, and every Array.prototype method is a replaceable global,
// so a caller who swaps one during that window would otherwise have this call dispatch into their
// code -- and an implementation that recognized the unrelated-anchor list and answered with the real
// CA would make a verification started with only the unrelated anchor settle `trusted: true`.
// Copying the caller's array at the door does not close that on its own: the fresh array is still an
// Array, and the replacement is on the prototype. Writing `out[out.length]` dispatches nothing.
function _certList(v) {
  if (v == null) return [];
  var arr = _isArray(v) ? v : [v];
  var out = [];
  for (var i = 0, n = arr.length; i < n; i++) {
    var c = arr[i];
    _append(out, (_isBuffer(c) || util.types.isUint8Array(c) || typeof c === "string")
      ? _certDer(c, "a trust anchor / intermediate") : c);
  }
  return out;
}

// A usable PBMAC1 shared secret: a non-empty string or a non-empty Buffer/Uint8Array (mirrors cmp-build).
// The size comes from the slot rather than from `s.length`. This gate stands in front of PBMAC1, and
// a typed array's `length` is a replaceable accessor: one reporting a positive value for an empty
// buffer lets `sharedSecret: ""` past, and a peer-generated message authenticated under an empty key
// then verifies. A string secret has already been converted to bytes at the option door, so the
// value measured here is a view whenever it is not refused outright.
function _nonEmptySecret(s) {
  if (typeof s === "string") return _sizeOf(s) > 0;
  if (!_isBuffer(s) && !util.types.isUint8Array(s)) return false;
  return _sizeOf(s) > 0;
}

function verify(message, opts) {
  // The reduced options are built here rather than inside _verify so the copy of a PBMAC1 shared
  // secret has an owner for its whole lifetime. That copy is this module's, holding the plaintext
  // secret, and pbes2.pbmac1 clears only the MAC key it derives -- so without this the secret would
  // sit in the heap until the allocator happened to reuse it. Cleared on every path out: resolved,
  // rejected, or never run.
  // The list is owned HERE and handed down, so a copy is clearable from the moment it exists rather
  // than from the moment the whole reduction succeeds. Reducing the options can fault partway -- a
  // subsequent getter throws, a certificate list turns out not to be dense -- and the secret's
  // copy has already been made by then. Binding it to the returned object would leave that copy with
  // no owner on exactly the paths where the caller learns something went wrong.
  // The cleanup is a language-level try/finally inside the async body, never a `.finally(...)` on
  // the returned promise. `Promise.prototype.finally` is a replaceable global, and reducing the
  // options runs caller getters, so one of those could install a replacement that this very line
  // would then dispatch into -- handing back a promise of its own choosing while the genuine
  // rejection went unobserved and the copied secret went unwiped. `try/finally` is syntax: nothing
  // is looked up, so nothing can be swapped.
  //
  // The `await` below is a different matter, and this comment previously claimed otherwise. `await v`
  // performs PromiseResolve, which reads `v.constructor`; when that no longer names %Promise% the
  // fast path is skipped and `v.then` is called instead -- both properties live on Promise.prototype
  // and both are writable. So a caller CAN interpose on the awaited value, here and at every other
  // await this module makes. That is a toolkit-wide exposure rather than one this function can close,
  // and it is not closed here: see the tracked work on capturing the promise plumbing.
  var made = [];
  return guard.async.deferred(async function () {
    try {
      return await _verify(message, _fixVerifyOptions(opts, made));
    } finally {
      guard.secret.zeroizeAll(made, CmpError, "cmp/bad-input", "the copied PBMAC1 shared secret");
    }
  });
}

// Every caller-owned option, reduced HERE to a value the caller no longer reaches.
//
// Verification suspends this call: PBMAC1 derivation on the MAC path, the signature engine on the
// other. Options read after it resumes answer for whatever the caller last wrote, so a caller could
// pass a transactionID that does not match the message, overwrite the buffer while the MAC derived,
// and be told the message was valid. `transactionID`, `expectRecipNonce`, `trustAnchors`,
// `intermediates` and `time` are all read past that suspension.
//
// The rule is two exhaustive outcomes rather than a list of which fields matter: anything carrying
// bytes is COPIED, and anything else is passed through by reference. Passing through is what a
// parsed certificate needs -- guard.parsed records provenance against the object's identity, so a
// copy is a different object and stops being recognized as parser output -- and it is also right for
// a caller's revocationChecker, which is a handle rather than data. Only the array CONTAINER of a
// certificate list is copied, so appending to the caller's array cannot widen the anchor set while
// the chain is being built.
//
// Two things therefore stay caller-owned, and both are safe for their own reason. A parsed anchor or
// intermediate is held by reference, and path validation re-derives it from the bytes it recorded,
// so a field edited on the caller's object never reaches the decision (pinned by vector 23l). A
// revocationChecker is the caller's callback, and what it answers is theirs to decide by definition.
// Copied through guard.bytes.snapshot, never a bare Buffer.from. The guard is this toolkit's door
// for a caller-supplied byte source, and it refuses the ones the rest of the code is entitled to
// assume it never sees -- a detached view, or one backed by a SharedArrayBuffer whose contents
// another thread can still rewrite. Copying with Buffer.from would launder such a source into an
// ordinary Buffer that every later check accepts without ever having applied the door's rules.
// The kind test asks the internal SLOT, never the prototype. `Buffer.isBuffer` is a writable
// property of the Buffer global and `v instanceof Uint8Array` consults Uint8Array[Symbol.hasInstance],
// and both are reachable from an option getter that has already run by the time this is evaluated.
// A caller who makes this answer `false` for their own bytes gets the copy skipped, which puts a
// live caller buffer where the copy should be -- and one that the wipe would then destroy, memory
// the toolkit does not own. util.types.isUint8Array is a fact about the value.
function _fixByteish(v, label) {
  if (!util.types.isUint8Array(v)) return v;
  return guard.bytes.snapshot(v, CmpError, "cmp/bad-input", "opts." + label);
}
// An opt-in echo value is a byte buffer or it is absent. A non-buffer (a string from JSON config,
// say) is a DEPLOYMENT error that throws cmp/bad-input, never a routine transaction/nonce mismatch
// verdict that would misreport a caller's typing mistake as a peer authentication failure.
function _assertEchoBytes(v, name) {
  if (v == null) return;
  if (util.types.isUint8Array(v)) return;   // the slot, not the prototype -- see _fixByteish
  throw _err("cmp/bad-input", "opts." + name + " must be a Buffer / Uint8Array");
}

// The shared secret, copied and recorded in one step so the copy is never unowned.
function _fixSecret(v, made) {
  // A string secret is converted to bytes HERE, once, and recorded -- not deeper inside the MAC
  // path. The conversion is the thing that creates a wipeable plaintext copy, so leaving it
  // downstream left that copy with no owner and the wipe never reached it. The immutable string
  // itself still cannot be cleared, which is the reason a caller who needs the secret gone from
  // memory hands over bytes; what changes here is that the toolkit stops adding a second copy it
  // then abandons.
  if (typeof v === "string") {
    var fromString = _bufferFrom(v, "utf8");
    _append(made, fromString);
    return fromString;
  }
  var copy = _fixByteish(v, "sharedSecret");
  // Slot test again, and for the sharper reason: this decides whether the copy is ENTERED in the
  // wipe list. A caller who makes it answer false leaves a genuine toolkit-allocated plaintext copy
  // with no owner, so the wipe never reaches it.
  if (util.types.isUint8Array(copy)) _append(made, copy);
  return copy;
}

function _fixCertList(v, label) {
  if (v == null) return v;
  if (!_isArray(v)) return _fixByteish(v, label);
  // Copied through a plain loop rather than v.map(). `map` is a property of the CALLER's array, and
  // an own property or a subclass can define it to return the receiver -- which would leave this
  // "copy" aliasing the very array the caller can still append a trusted CA to while verification
  // is suspended, defeating the copy entirely. `length` and each index are read once, into a fresh
  // array this module owns.
  //
  // The elements that EXIST are enumerated, rather than walking 0..length. An array's `length` is
  // independent of how many elements it holds, so a sparse list carrying one certificate at index
  // 100000000 costs nothing to build and would cost a dense hundred-million-entry allocation to
  // walk. Own index keys come back in ascending numeric order, so a dense list copies exactly as it
  // did and a sparse one collapses to the certificates it actually carries. No ceiling is imposed
  // here: a trust store is the caller's own configuration and path.build sets no limit on how many
  // anchors it may hold, so capping the list would refuse a large store that verifies today.
  // A certificate list is a PLAIN DENSE array or it is refused. Two outcomes, no third.
  //
  // Faithfully reproducing what an ordinary array operation would consume means handling holes,
  // elements inherited from a subclass or a custom prototype, non-enumerable elements, and indices
  // at the uint32 boundary -- and each of those pulls against the next: reading `length` positions
  // covers inheritance but scans every hole of a sparse list, while enumerating present keys is
  // bounded but silently drops an inherited anchor. Silently dropping one turns a trusted
  // verification into an untrusted one, and that is not a trade to make quietly inside a trust
  // decision.
  //
  // So the shape is refused instead of emulated. The own index properties below `length` are counted
  // -- bounded by how many properties the object actually has, never by `length` -- and the list is
  // accepted only when that count IS the length, which is exactly a dense array with nothing
  // inherited. A caller holding an exotic array normalizes it themselves, and the failure is a typed
  // error naming the problem rather than an anchor that quietly went missing.
  // The door comes first, ahead of every property read below it. `Array.isArray` pierces a Proxy
  // without reaching a trap, so at this point nothing caller-written has run; the `length` read and
  // the descriptor walk are what would hand control over. A Proxy whose target is an array answers
  // both from traps, and its `ownKeys` and `get` traps need not agree with each other or with the
  // answer an element read gives afterwards, so a count through them describes nothing. guard.identifier
  // refuses a Proxy anywhere in the chain by identity, and it has to do that while the list is still
  // untouched for the refusal to mean anything.
  //
  // The elements are then held to the same rule as the option names, through the same primitive: an
  // accessor under an index is caller code exactly as an accessor under a name is, and a list is
  // where it pays -- an element can answer as one certificate to the check and as another to the
  // read, or simply run and rewrite a predicate the reduction has not reached yet. guard-bytes
  // refuses index accessors on the arguments it copies for this reason; a certificate list is the
  // same shape and gets the same treatment.
  var indices = guard.identifier.readableIndices(v, _err, "cmp/bad-input", "opts." + label);
  guard.identifier.refuseAccessorFields(v, indices, _err, "cmp/bad-input", "opts." + label);
  var n = v.length;
  var names = _getOwnPropertyNames(v);
  var own = 0, j, k, ix;
  for (j = 0; j < names.length; j++) {
    k = names[j]; ix = k >>> 0;
    if (_String(ix) === k && ix !== 0xFFFFFFFF && ix < n) own += 1;
  }
  if (own !== n) {
    throw _err("cmp/bad-input", "a certificate list must be a dense array of certificates; this one holds " +
      own + " of its " + n + " positions as its own elements, so the rest are holes or come from its prototype");
  }
  var out = [];
  for (var i = 0; i < n; i++) _append(out, _fixByteish(v[i], label + "[" + i + "]"));
  return out;
}
// The evaluation instant, taken from ONE read of the caller's value. A real Date is re-made at the
// same instant, so setTime on the caller's object cannot move it. Anything else passes through
// untouched, including a falsy-but-present value, so the rejection it already earns downstream is
// the one it still gets.
function _fixTime(v) {
  return guard.time.isDate(v) ? new _Date(guard.time.instantOf(v)) : v;
}
function _fixVerifyOptions(opts, made) {
  if (opts == null) opts = {};   // ONLY null / undefined -> the default empty opts (a falsy false/0/"" is a bad config, not a default)
  // Through the toolkit's own options door rather than a pair of local field checks. The door
  // REFUSES an options bag whose fields are accessors, and refuses one that changes which fields it
  // carries while they are read; a local check on each field it needs can do neither.
  //
  // That is what closes this whole class rather than one member of it. An accessor is caller code
  // running inside the call, before the verb has done anything, and from there it can rewrite the
  // very predicates and constructors the verb is about to use -- Buffer.from, Array.isArray,
  // util.types.isUint8Array, Promise.prototype.then. Each one hardened in turn is another entry on
  // a list with no end; refusing the accessor removes the window they all need. What is asked of a
  // caller is only that the options themselves be values.
  opts = guard.identifier.optionsObject(opts, _err, "cmp/bad-input", "pki.cmp.verify options");
  guard.identifier.assertKnownKeys(opts, KNOWN_VERIFY_OPTS, _err, "cmp/bad-input", "unknown opts field ");
  // Each field is read from the caller's object exactly once AND reduced in the same step, before
  // the next field is read. Both halves matter, and each closes a way the caller could otherwise
  // still be holding the value the verdict turns on:
  //
  //   reading once -- a property can be an accessor, and an accessor is free to answer a different
  //   value each time it is asked, so a second read would let the value that passed the check
  //   differ from the value that was used;
  //
  //   reducing immediately -- an accessor invoked for a LATER field can reach back and mutate the
  //   buffer an EARLIER field handed over, so reading everything first and copying afterwards would
  //   copy whatever the last getter left behind.
  //
  // An object literal evaluates its properties in source order, so each line below is one read
  // followed at once by its copy.
  var f = {
    // Recorded in `made` the instant it is copied. Only the byte form: a string secret is a
    // JavaScript string, immutable and interned wherever the caller created it, so there is nothing
    // here to wipe -- a caller who needs the secret gone from memory passes it as bytes.
    sharedSecret: _fixSecret(opts.sharedSecret, made),
    signerCert: _fixByteish(opts.signerCert, "signerCert"),
    trustAnchors: _fixCertList(opts.trustAnchors, "trustAnchors"),
    intermediates: _fixCertList(opts.intermediates, "intermediates"),
    time: _fixTime(opts.time),
    transactionID: _fixByteish(opts.transactionID, "transactionID"),
    expectRecipNonce: _fixByteish(opts.expectRecipNonce, "expectRecipNonce"),
    revocationChecker: opts.revocationChecker,
    maxIterations: opts.maxIterations,
  };

  // Checked on the COPY, which is what the comparison later runs against.
  //
  // Written out rather than looped with forEach. The reduction above has already run the caller's
  // getters, so one of them could have replaced Array.prototype.forEach with a no-op -- and this
  // check would then simply not happen, turning a configuration error the caller must see into a
  // routine mismatch verdict that blames the peer. Two named checks dispatch nothing.
  _assertEchoBytes(f.transactionID, "transactionID");
  _assertEchoBytes(f.expectRecipNonce, "expectRecipNonce");
  return f;
}

async function _verify(message, opts) {
  if (_engine == null) throw _err("cmp/bad-input", "the cmp-verify signature engine is not initialized (require pki before use)");

  var m = _coerce(message);
  var protectionAlg = m.header.protectionAlg;
  var protection = m.protection;

  // M3/M5: the parser guarantees protection<->protectionAlg presence agreement; an absent protection is a
  // hard reject -- absence is never "verified".
  if (protection === null || protectionAlg === null) {
    return _fail(m, null, protectionAlg, "cmp/no-protection", "the PKIMessage carries no protection (RFC 9810 sec. 5.1.3); an unprotected message is never verified");
  }

  // M2: reconstruct the ProtectedPart from the raw surfaced slices, byte-identical to what build signed,
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
 * @status     stable
 * @spec       RFC 9810, RFC 9481, RFC 9579, RFC 9483
 * @related    pki.cmp.build, pki.schema.cmp.parse
 * @defends    cmp-unverified-protection (CWE-347), cmp-mac-timing (CWE-208)
 *
 * Verify the protection on an incoming RFC 9810 CMP `PKIMessage`, the verify-inverse of
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
 * matched or a signature signer certificate chained to a supplied trust anchor. On a trusted signature
 * verdict `signer.chain` is the validated certificate path as independent DER buffers (the signer plus the
 * intermediates that chained it to the anchor): the certificates actually used, never the unsigned
 * `extraCerts` a peer can pad, and never a slice pinning the response allocation. A
 * well-formed but unverifiable message is a `{ valid: false }` verdict carrying a `cmp/*` code, not a throw;
 * only malformed input (a non-PKIMessage, a bad required opt, a flavor/credential mismatch) throws a typed `CmpError`.
 *
 * @opts
 *   - `sharedSecret` (string|Buffer) -- the PBMAC1 secret; REQUIRED for a MAC-protected message (UTF-8).
 *   - `signerCert` (Buffer|PEM) -- the expected signature signer certificate (else resolved from
 *     `extraCerts` by `senderKID` or, per RFC 9483 sec. 3.3, `extraCerts[0]`).
 *   - `trustAnchors` (Buffer|Buffer[]|PEM) -- when present the signer certificate is FULLY path-validated
 *     (RFC 5280 sec. 6.1 plus the `keyUsage.digitalSignature` gate) to report `trusted`; absent -> the
 *     verdict is crypto-only (`trusted: false`) and the signer certificate is surfaced for the caller to
 *     anchor. The signature verify never routes through build's self-check (which skips the EdDSA
 *     low-order-point gate); it uses the same engine `pki.crl.verify` / `pki.ocsp.verify` do.
 *   - `intermediates` (Buffer|Buffer[]|PEM) -- extra untrusted pool certificates for path building
 *     (`extraCerts` are added automatically, as untrusted pool material).
 *   - `time` (Date) -- the validity instant for path validation. Defaults to the current time (the message's
 *     self-asserted `messageTime` is not trusted for this); pass an explicit instant for historical verification.
 *   - `transactionID` (Buffer) -- opt-in: require `header.transactionID` to equal it (response-echo defense).
 *   - `expectRecipNonce` (Buffer) -- opt-in: require `header.recipNonce` to echo the sent sender nonce.
 *   - `revocationChecker` -- forwarded to `pki.path.validate` when chaining the signer certificate.
 *   - `maxIterations` (number) -- downward-only override of the PBKDF2 iteration cap.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "client", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var certDer = signerCertDer;   // self-signed here, so it is also its own anchor
 *   var csrDer = await pki.csr.sign({ subject: "client", subjectPublicKey: await pki.key.export(pair.publicKey) },
 *     { key: signerKeyPkcs8 });
 *   var cmpDer = await pki.cmp.build(
 *     { header: { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" } },
 *       body: { p10cr: csrDer } }, { key: signerKeyPkcs8, cert: signerCertDer });
 *   var v = await pki.cmp.verify(cmpDer, { signerCert: signerCertDer, trustAnchors: [certDer] });
 *   if (v.valid && v.trusted) console.log("the response protection is authentic and the signer is trusted");
 */

module.exports = {
  build: cmpBuild.build,
  transfer: cmpBuild.transfer,
  wellKnownUrl: cmpBuild.wellKnownUrl,
  verify: verify,
  setEngine: setEngine,
  senderBoundToCert: _senderBoundToCert,
};
