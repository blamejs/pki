// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// lib/cmp-build.js; this file adds the @primitive pki.cmp.verify block and re-exports the cmp producing

var intrinsic = require("./guard-intrinsic");
var _sizeOf = intrinsic.sizeOf;
var util = intrinsic.assign(intrinsic.create(null), { types: intrinsic.types });
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
var _toString = intrinsic.uncurry(Buffer.prototype.toString);
var _map = intrinsic.map;
var _String = intrinsic.String;
var _isFinite = intrinsic.isFinite;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _strLastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
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

var NS = pkix.makeNS("cmp", CmpError, oid);
var PBMAC1_PARAMS = pkix.pbmac1Params(NS);
var _certExtDecoders = pkix.certExtensionDecoders(NS).byOid;

var KNOWN_VERIFY_OPTS = intrinsic.assign(intrinsic.create(null), {
  sharedSecret: 1, signerCert: 1, trustAnchors: 1, intermediates: 1, time: 1,
  transactionID: 1, expectRecipNonce: 1, revocationChecker: 1, maxIterations: 1,
});

var PRF_HASH = _create(null);
PRF_HASH[oid.byName("hmacWithSHA256")] = "SHA-256";
PRF_HASH[oid.byName("hmacWithSHA384")] = "SHA-384";
PRF_HASH[oid.byName("hmacWithSHA512")] = "SHA-512";

var PBMAC1_MAX_ITER = constants.LIMITS.PBKDF2_MAX_ITERATIONS;
var PBMAC1_MIN_ITER = 1000;
var PBMAC1_MIN_SALT = 8;
var PBMAC1_MAX_SALT = constants.LIMITS.PBKDF2_MAX_SALT;
var PBMAC1_KEYLEN_MIN = 20;
var PBMAC1_KEYLEN_MAX = 1024;
var PRF_HLEN = intrinsic.assign(intrinsic.create(null), { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 });

var UNSUPPORTED_MAC_OIDS = _create(null);
["passwordBasedMac", "dhBasedMac", "kemBasedMac"].forEach(function (n) {
  var o = oid.byName(n);
  if (o) UNSUPPORTED_MAC_OIDS[o] = n;
});

var _engine = null;
function setEngine(engine) { _engine = engine; }

function _verdict(m, type, protectionAlg, valid, trusted, code, reason, signer) {
  return guard.verdict.of({
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
  }, code ? { code: code, reason: reason } : null);
}
function _ok(m, type, alg, trusted, signer) { return _verdict(m, type, alg, true, trusted, null, null, signer); }
function _fail(m, type, alg, code, reason, signer) { return _verdict(m, type, alg, false, false, code, reason, signer || null); }

function _coerce(message) {
  if (message && typeof message === "object" && !_isBuffer(message) && !util.types.isUint8Array(message) &&
    message.headerBytes !== undefined && message.bodyBytes !== undefined &&
    message.header !== undefined && message.body !== undefined) {
    try { return cmp.parse(_reassemble(message)); }
    catch (e) { throw e instanceof CmpError ? e : _err("cmp/bad-input", "the parsed PKIMessage object carries a malformed raw slice (headerBytes / bodyBytes / protection / extraCerts): " + ((e && e.message) || e), e); }
  }
  if (guard.bytes.isByteSource(message)) return cmp.parse(guard.bytes.snapshotSource(message, CmpError, "cmp/bad-input", "the CMP message"));
  return cmp.parse(message);
}

function _reassemble(m) {
  var kids = [b.raw(m.headerBytes), b.raw(m.bodyBytes)];
  if (m.protection != null) _append(kids, b.explicit(0, b.bitString(m.protection.bytes, m.protection.unusedBits)));
  if (m.extraCerts != null && m.extraCerts.length) {
    _append(kids, b.explicit(1, b.sequence(_map(m.extraCerts, function (c) { return b.raw(c); }))));
  }
  return b.sequence(kids);
}

function _certDer(cert, what) {
  if (guard.bytes.isByteSource(cert)) return guard.bytes.source(cert, CmpError, "cmp/bad-input", what);
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("cmp/bad-input", what + " PEM could not be decoded", e); } }
  throw _err("cmp/bad-input", what + " must be a certificate DER BufferSource or PEM string");
}

function _certSki(parsed) {
  var skiOid = oid.byName("subjectKeyIdentifier");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== skiOid) continue;
    try { return asn1.read.octetString(asn1.decode(exts[i].value)); } catch (_e) { return null; }   // allow:swallow-unverified -- fail-closed: a malformed subjectKeyIdentifier yields null, so no SKI is used to match
  }
  return null;
}
function _subjectDn(parsed) { return parsed.subject.dn || null; }

function _sanGeneralNames(parsed) {
  var sanOid = oid.byName("subjectAltName");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== sanOid) continue;
    try {
      var node = asn1.decode(exts[i].value);
      schema.walk(pkix.generalNames(NS, { code: "cmp/sender-mismatch" }), node, NS);
      return node.children || [];
    } catch (_e) { return []; }
  }
  return [];
}

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

function _generalNameMatches(sender, sanNode) {
  if (sanNode.tagClass !== sender.tagClass || sanNode.tagNumber !== sender.tagNumber) return false;
  if (sanNode.tagClass === "context") {
    if (sanNode.tagNumber === 2 && sanNode.content) {
      var dnsSan = _toString(sanNode.content, "latin1"), dnsSender = _String(sender.value);
      if (pkix.dnsNameProblem(dnsSan) !== null || pkix.dnsNameProblem(dnsSender) !== null) return dnsSan === dnsSender;
      return _toLowerCase(dnsSender) === _toLowerCase(dnsSan);
    }
    if (sanNode.tagNumber === 1 && sanNode.content) {
      return _rfc822Equal(_String(sender.value), _toString(sanNode.content, "latin1"));
    }
    if (sanNode.tagNumber === 6 && sanNode.content) {
      return _uriEqual(_String(sender.value), _toString(sanNode.content, "latin1"));
    }
    if (sanNode.tagNumber === 4 && sanNode.children && sanNode.children.length) {
      if (!sender.value || !_isArray(sender.value.rdns)) return false;
      var sanName;
      try { sanName = schema.embeddedDer(pkix.name(NS), sanNode.children[0].bytes, NS, { code: "cmp/sender-mismatch", what: "SAN directoryName" }).result; }
      catch (_e) { return false; }
      return guard.name.dnEqual(sender.value.rdns, sanName.rdns, NS.E, "cmp/sender-mismatch", "SAN directoryName");
    }
  }
  return _compare(sanNode.bytes, sender.bytes) === 0;
}

function _mailboxSplit(s) {
  var sep;
  if (_charAt(s,0) === "\"") {
    var i = 1;
    while (i < s.length) {
      var c = _charAt(s,i);
      if (c === "\\") { i += 2; continue; }
      if (c === "\"") break;
      i++;
    }
    if (i >= s.length || _charAt(s,i) !== "\"" || _charAt(s,i + 1) !== "@") return -1;
    sep = i + 1;
  } else {
    sep = _strIndexOf(s, "@");
    if (sep < 0 || sep !== _strLastIndexOf(s, "@")) return -1;
  }
  var local = _strSlice(s, 0, sep), domain = _strSlice(s, sep + 1);
  if (pkix.dnsNameProblem(domain) !== null) return -1;
  if (_charAt(s, 0) !== "\"" && (local.length === 0 || _charAt(local, 0) === "." || _charAt(local, local.length - 1) === "." || _strIndexOf(local, "..") !== -1 || !_isEmailLocalPart(local))) return -1;
  return sep;
}

function _rfc822Equal(a, b) {
  var ai = _mailboxSplit(a), bi = _mailboxSplit(b);
  if (ai < 0 || bi < 0) return a === b;
  return _strSlice(a, 0, ai) === _strSlice(b, 0, bi) &&
    _lowerAsciiDomain(_strSlice(a, ai + 1)) === _lowerAsciiDomain(_strSlice(b, bi + 1));
}

var _lowerAsciiDomain = guard.name.lowerAscii;

var _EMAIL_LOCAL_SPECIALS = "!#$%&'*+/=?^_`{|}~.-";
var _URI_SPECIALS = "._~:/?#@!$&'()*+,;=%[]-";
function _isAsciiAlnum(ch) { return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9"); }
function _isHexDigit(ch) { return (ch >= "0" && ch <= "9") || (ch >= "A" && ch <= "F") || (ch >= "a" && ch <= "f"); }

function _isEmailLocalPart(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) {
    var ch = _charAt(s, i);
    if (!(_isAsciiAlnum(ch) || _strIndexOf(_EMAIL_LOCAL_SPECIALS, ch) !== -1)) return false;
  }
  return true;
}

function _isAllUriChars(s) {
  for (var i = 0; i < s.length; i++) {
    var ch = _charAt(s, i);
    if (!(_isAsciiAlnum(ch) || _strIndexOf(_URI_SPECIALS, ch) !== -1)) return false;
  }
  return true;
}

function _hasInvalidPercent(u) {
  for (var i = 0; i < u.length; i++) {
    if (_charAt(u, i) === "%" && !(_isHexDigit(_charAt(u, i + 1)) && _isHexDigit(_charAt(u, i + 2)))) return true;
  }
  return false;
}

function _splitScheme(u) {
  if (u.length === 0) return null;
  var first = _charAt(u, 0);
  if (!((first >= "A" && first <= "Z") || (first >= "a" && first <= "z"))) return null;
  var p = 1;
  while (p < u.length) {
    var ch = _charAt(u, p);
    if (!(_isAsciiAlnum(ch) || ch === "+" || ch === "." || ch === "-")) break;
    p += 1;
  }
  if (_charAt(u, p) !== ":") return null;
  return { scheme: _strSlice(u, 0, p), rest: _strSlice(u, p + 1) };
}

function _firstAuthorityDelim(s) {
  for (var i = 0; i < s.length; i++) {
    var ch = _charAt(s, i);
    if (ch === "/" || ch === "?" || ch === "#") return i;
  }
  return -1;
}

function _isColonPort(s) {
  if (s.length === 0 || _charAt(s, 0) !== ":") return false;
  for (var i = 1; i < s.length; i++) {
    var ch = _charAt(s, i);
    if (!(ch >= "0" && ch <= "9")) return false;
  }
  return true;
}

function _normalizeUri(u) {
  if (!_isAllUriChars(u) || _hasInvalidPercent(u)) return null;
  var m = _splitScheme(u);
  if (!m) return null;
  var scheme = _toLowerCase(m.scheme);
  var rest = m.rest;
  if (_strSlice(rest, 0, 2) !== "//") return null;
  var body = _strSlice(rest, 2);
  var cut = _firstAuthorityDelim(body);
  var split = cut < 0 ? body.length : cut;
  var authority = _strSlice(body, 0, split), tail = _strSlice(body, split);
  if (_strIndexOf(authority, "@") !== _strLastIndexOf(authority, "@")) return null;
  var at = _strLastIndexOf(authority, "@");
  var userinfo = at < 0 ? "" : _strSlice(authority, 0, at + 1);
  var hostport = at < 0 ? authority : _strSlice(authority, at + 1);
  var host, port;
  if (_charAt(hostport, 0) === "[") {
    var rb = _strIndexOf(hostport, "]");
    if (rb < 0) return null;
    host = _strSlice(hostport, 0, rb + 1); port = _strSlice(hostport, rb + 1);
  } else {
    var ci = _strIndexOf(hostport, ":");
    host = ci < 0 ? hostport : _strSlice(hostport, 0, ci); port = ci < 0 ? "" : _strSlice(hostport, ci);
  }
  if (port !== "" && !_isColonPort(port)) return null;
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

function _resolveSignerCert(m, opts, extra) {
  var senderKID = m.header.senderKID;
  function _signerObj(der, p) { return { der: der, spki: p.subjectPublicKeyInfo.bytes, subject: _subjectDn(p), parsed: p }; }
  function accept(der) {
    var p;
    try { p = x509.parse(der); }
    catch (_e) { return null; }
    if (senderKID != null) {
      var ski = _certSki(p);
      if (ski == null || !guard.crypto.constantTimeEqual(ski, senderKID)) return null;
    }
    return _signerObj(der, p);
  }
  if (opts.signerCert != null) {
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
  if (extra.length) return accept(extra[0]);
  return null;
}

function _bufEq(a, x) {
  if (!_isBuffer(a)) return false;
  if (!_isBuffer(x)) { if (util.types.isUint8Array(x)) x = _bufferFrom(x); else return false; }
  return _compare(a, x) === 0;
}
function _headerChecks(m, opts) {
  if (m.header.pvno !== 2 && m.header.pvno !== 3) {
    return { code: "cmp/unsupported-version", reason: "the header pvno is " + m.header.pvno + "; a received PKIMessage MUST carry cmp2000(2) or cmp2021(3) (RFC 9483 sec. 3.5)" };
  }
  if (!guard.bytes.isByteSource(m.header.transactionID)) {
    return { code: "cmp/bad-transaction-id", reason: "the header transactionID is absent; a received PKIMessage MUST carry one (RFC 9483 sec. 3.5)" };
  }
  if (!guard.bytes.isByteSource(m.header.senderNonce) || guard.bytes.lengthOf(m.header.senderNonce) < 16) {
    return { code: "cmp/bad-sender-nonce", reason: "the header senderNonce is absent or shorter than 128 bits (RFC 9483 sec. 3.5)" };
  }
  if (opts.transactionID != null && !_bufEq(m.header.transactionID, opts.transactionID)) {
    return { code: "cmp/transaction-id-mismatch", reason: "header.transactionID does not equal the expected value (RFC 9810 sec. 5.1.1)" };
  }
  if (opts.expectRecipNonce != null && !_bufEq(m.header.recipNonce, opts.expectRecipNonce)) {
    return { code: "cmp/bad-recip-nonce", reason: "header.recipNonce does not echo the expected sender nonce" };
  }
  return null;
}

function _keyUsageAllowsSigning(parsed) {
  var kuOid = oid.byName("keyUsage");
  var exts = parsed.extensions;
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== kuOid) continue;
    var ku;
    try { ku = _certExtDecoders[kuOid](exts[i].value); }
    catch (_e) { return false; }
    return ku.digitalSignature === true;
  }
  return true;
}

async function _verifyMac(m, protectedPart, protectionAlg, protection, opts) {
  if (protectionAlg.parameters === null) {
    return _fail(m, "mac", protectionAlg, "cmp/protection-failed", "the PBMAC1 protectionAlg carries no PBMAC1-params (RFC 9579 sec. 4)");
  }
  var params;
  try {
    params = schema.embeddedDer(PBMAC1_PARAMS, protectionAlg.parameters, NS, { code: "cmp/bad-mac-data", what: "PBMAC1-params" }).result;
  } catch (e) {
    return _fail(m, "mac", protectionAlg, e instanceof CmpError ? e.code : "cmp/protection-failed", "the PBMAC1-params did not decode: " + ((e && e.message) || e));
  }
  var kdf = params.kdf;
  var prfHash = PRF_HASH[kdf.prfOid];
  var macHash = PRF_HASH[params.schemeOid];
  if (!prfHash) return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "unsupported PBMAC1 PBKDF2 PRF " + _stringify(kdf.prfName) + " (SHA-256/384/512 only; RFC 9481 sec. 7, RFC 9579 sec. 7)");
  if (!macHash) return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "unsupported PBMAC1 messageAuthScheme " + _stringify(params.schemeName) + " (SHA-256/384/512 only)");

  _capWork(kdf.iterationCount, kdf.salt, kdf.keyLength, prfHash, opts);

  var secret = typeof opts.sharedSecret === "string" ? _bufferFrom(opts.sharedSecret, "utf8") : guard.bytes.view(opts.sharedSecret, CmpError, "cmp/bad-input", "opts.sharedSecret");
  var computed = await pbes2.pbmac1(secret, kdf.salt, kdf.iterationCount, kdf.keyLength, prfHash, macHash, protectedPart);
  if (!guard.crypto.constantTimeEqual(computed, protection.bytes)) {
    return _fail(m, "mac", protectionAlg, "cmp/protection-failed", "the PBMAC1 MAC does not verify (a wrong shared secret or a tampered ProtectedPart)");
  }
  var hc = _headerChecks(m, opts);
  if (hc) return _fail(m, "mac", protectionAlg, hc.code, hc.reason);
  return _ok(m, "mac", protectionAlg, true, null);
}

function _capWork(iterationCount, salt, keyLength, prfHash, opts) {
  var cap = PBMAC1_MAX_ITER;
  if (opts.maxIterations != null) {
    if (typeof opts.maxIterations !== "number" || !_isFinite(opts.maxIterations) || opts.maxIterations < 1 || _floor(opts.maxIterations) !== opts.maxIterations) {
      throw _err("cmp/bad-input", "opts.maxIterations must be a positive integer");
    }
    cap = _min(opts.maxIterations, cap);
  }
  if (iterationCount < PBMAC1_MIN_ITER) throw _err("cmp/bad-input", "the PBMAC1 iterationCount " + iterationCount + " is below the floor " + PBMAC1_MIN_ITER + " (RFC 8018 sec. 4.2)");
  if (iterationCount > cap) throw _err("cmp/bad-input", "the PBMAC1 iterationCount " + iterationCount + " exceeds the cap " + cap);
  var saltLen = salt ? _sizeOf(salt) : 0;
  if (!salt || saltLen < PBMAC1_MIN_SALT || saltLen > PBMAC1_MAX_SALT) throw _err("cmp/bad-input", "the PBMAC1 salt length must be in [" + PBMAC1_MIN_SALT + ", " + PBMAC1_MAX_SALT + "] octets (RFC 8018 sec. 4.1)");
  if (keyLength < PBMAC1_KEYLEN_MIN || keyLength > PBMAC1_KEYLEN_MAX) throw _err("cmp/bad-input", "the PBMAC1 keyLength must be in [" + PBMAC1_KEYLEN_MIN + ", " + PBMAC1_KEYLEN_MAX + "] (RFC 9579 sec. 9)");
  var blocks = _ceil(keyLength / (PRF_HLEN[prfHash] || 32));
  if (iterationCount * blocks > cap) throw _err("cmp/bad-input", "the PBMAC1 combined work (iterationCount " + iterationCount + " x " + blocks + " derived blocks) exceeds the cap " + cap);
}

async function _verifySignature(m, protectedPart, protectionAlg, protection, opts) {
  var extra = _boundExtraCerts(m.extraCerts);
  var signer = _resolveSignerCert(m, opts, extra);
  if (!signer) return _fail(m, "signature", protectionAlg, "cmp/signer-cert-not-found", "no signer certificate resolved (opts.signerCert, senderKID, or extraCerts)");

  var ok = await _engine.verifyWithSpki(protectionAlg, protection.bytes, signer.spki, protectedPart);
  if (ok !== true) return _fail(m, "signature", protectionAlg, "cmp/protection-failed", "the protection signature does not verify over the ProtectedPart under the declared protectionAlg", signer);

  if (!_senderBoundToCert(m.header.sender, signer.parsed)) {
    return _fail(m, "signature", protectionAlg, "cmp/sender-mismatch", "the header sender field does not match the signer certificate subject, or (for an empty subject) a subjectAltName entry (RFC 9483 sec. 3.1, RFC 5280 sec. 7.1)", signer);
  }

  var hc = _headerChecks(m, opts);
  if (hc) return _fail(m, "signature", protectionAlg, hc.code, hc.reason, signer);

  if (opts.trustAnchors == null) return _ok(m, "signature", protectionAlg, false, signer);
  var trust = await _chainSigner(signer, m, opts, extra);
  if (trust.chain) guard.verdict.set(signer, "chain", trust.chain);
  return _verdict(m, "signature", protectionAlg, true, trust.trusted, trust.trusted ? null : "cmp/untrusted-signer", trust.reason, signer);
}

function _certKey(c) {
  try {
    var p = guard.parsed.acceptDerived(c, "certificate", x509.parse, _err, "cmp/bad-input", "a pool certificate");
    if (!guard.parsed.isCert(p)) return null;
    return _toString(p.tbsBytes, "base64") + "|" + _toString(p.signatureValue.bytes, "base64");
  } catch (_e) {
    return null;
  }
}

async function _chainSigner(signer, m, opts, extra) {
  if (!_keyUsageAllowsSigning(signer.parsed)) {
    return { trusted: false, reason: "the signer certificate keyUsage does not assert digitalSignature (RFC 9483 sec. 3.2)" };
  }
  var time = opts.time != null ? opts.time : new _Date();
  var anchors = _certList(opts.trustAnchors);
  var pool = _certList(opts.intermediates);
  var room = constants.LIMITS.PATH_BUILD_MAX_CANDIDATES - pool.length;
  if (room > 0) {
    var seen = _create(null);
    var sk = _certKey(signer.parsed); if (sk) seen[sk] = 1;
    var pi, pk;
    for (pi = 0; pi < pool.length; pi++) { pk = _certKey(pool[pi]); if (pk) seen[pk] = 1; }
    var merged = [];
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
    if (e && e.code === "path/bad-input") {
      throw _err("cmp/bad-input", "invalid trust / validation options for signer-certificate path validation: " + (e.message || e), e);
    }
    return { trusted: false, reason: "signer certificate path validation failed: " + (e.message || e) };
  }
}

var MAX_EXTRA_CERTS = 32;
var MAX_EXTRA_SCAN = 256;
function _boundExtraCerts(extra) {
  if (!_isArray(extra) || !extra.length) return [];
  var out = [], seen = _create(null);
  for (var i = 0; i < extra.length && out.length < MAX_EXTRA_CERTS && i < MAX_EXTRA_SCAN; i++) {
    var c = extra[i];
    if (!_isBuffer(c) && !util.types.isUint8Array(c)) continue;
    var key = _toString(_bufferFrom(c), "base64");
    if (seen[key]) continue;
    seen[key] = true;
    try { x509.parse(c); }
    catch (_e) { continue; }
    _append(out, c);
  }
  return out;
}

var _defineOwn = Object.defineProperty;
var _Date = Date;
var _append = guard.list.append;

function _certList(v) {
  if (v == null) return [];
  var arr = _isArray(v) ? v : [v];
  var out = [];
  for (var i = 0, n = arr.length; i < n; i++) {
    var c = arr[i];
    _append(out, (guard.bytes.isByteSource(c) || typeof c === "string")
      ? _certDer(c, "a trust anchor / intermediate") : c);
  }
  return out;
}

function _nonEmptySecret(s) {
  if (typeof s === "string") return _sizeOf(s) > 0;
  if (!_isBuffer(s) && !util.types.isUint8Array(s)) return false;
  return _sizeOf(s) > 0;
}

function verify(message, opts) {
  var made = [];
  return guard.async.deferred(async function () {
    try {
      return await _verify(message, _fixVerifyOptions(opts, made));
    } finally {
      guard.secret.zeroizeAll(made, CmpError, "cmp/bad-input", "the copied PBMAC1 shared secret");
    }
  });
}

function _fixByteish(v, label) {
  if (!util.types.isUint8Array(v)) return v;
  return guard.bytes.snapshot(v, CmpError, "cmp/bad-input", "opts." + label);
}
function _assertEchoBytes(v, name) {
  if (v == null) return;
  if (util.types.isUint8Array(v)) return;
  throw _err("cmp/bad-input", "opts." + name + " must be a Buffer / Uint8Array");
}

function _fixSecret(v, made) {
  if (typeof v === "string") {
    var fromString = _bufferFrom(v, "utf8");
    _append(made, fromString);
    return fromString;
  }
  var copy = _fixByteish(v, "sharedSecret");
  if (util.types.isUint8Array(copy)) _append(made, copy);
  return copy;
}

function _fixCertList(v, label) {
  if (v == null) return v;
  if (!_isArray(v)) return _fixByteish(v, label);
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
function _fixTime(v) {
  return guard.time.isDate(v) ? new _Date(guard.time.instantOf(v)) : v;
}
function _fixVerifyOptions(opts, made) {
  if (opts == null) opts = {};
  opts = guard.identifier.optionsObject(opts, _err, "cmp/bad-input", "pki.cmp.verify options");
  guard.identifier.assertKnownKeys(opts, KNOWN_VERIFY_OPTS, _err, "cmp/bad-input", "unknown opts field ");
  var f = {
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

  _assertEchoBytes(f.transactionID, "transactionID");
  _assertEchoBytes(f.expectRecipNonce, "expectRecipNonce");
  return f;
}

async function _verify(message, opts) {
  if (_engine == null) throw _err("cmp/bad-input", "the cmp-verify signature engine is not initialized (require pki before use)");

  var m = _coerce(message);
  var protectionAlg = m.header.protectionAlg;
  var protection = m.protection;

  if (protection === null || protectionAlg === null) {
    return _fail(m, null, protectionAlg, "cmp/no-protection", "the PKIMessage carries no protection (RFC 9810 sec. 5.1.3); an unprotected message is never verified");
  }

  var protectedPart = b.sequence([b.raw(m.headerBytes), b.raw(m.bodyBytes)]);

  if (UNSUPPORTED_MAC_OIDS[protectionAlg.oid]) {
    return _fail(m, "mac", protectionAlg, "cmp/unsupported-algorithm", "the " + UNSUPPORTED_MAC_OIDS[protectionAlg.oid] + " protection algorithm is not supported (v1 verifies PBMAC1 and signature protection; RFC 9481 sec. 6.1.1)");
  }

  var isMac = protectionAlg.oid === oid.byName("pbmac1");
  var hasSigCred = opts.signerCert != null || opts.trustAnchors != null;
  var hasSecret = opts.sharedSecret != null;

  if (isMac) {
    if (hasSigCred) throw _err("cmp/bad-input", "a MAC-protected message takes opts.sharedSecret, not signerCert/trustAnchors");
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
 * On a protection-verified message the RFC 9483 sec. 3.5 receiving-side header rules apply: the `pvno` MUST be
 * cmp2000(2) or cmp2021(3) (a cmp1999(1) message stays valid RFC 9810 syntax `pki.schema.cmp.parse` decodes,
 * refused only on receipt), the `transactionID` MUST be present, and the `senderNonce` MUST be present and
 * carry at least 128 bits; a violation is a `{ valid: false }` verdict carrying `cmp/unsupported-version`,
 * `cmp/bad-transaction-id`, or `cmp/bad-sender-nonce`.
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
