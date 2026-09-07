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
var cms = require("./schema-cms");
var cmsVerify = require("./cms-verify");
var cmsDecrypt = require("./cms-decrypt");
var pkcs8 = require("./schema-pkcs8");
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
  transactionID: 1, expectRecipNonce: 1, revocationChecker: 1, maxIterations: 1, kem: 1,
  messageTimeTolerance: 1,
});
var KNOWN_KEM_VERIFY_KEYS = intrinsic.assign(intrinsic.create(null),
  { sharedSecret: 1, transactionID: 1 });

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
["passwordBasedMac", "dhBasedMac"].forEach(function (n) {
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

/** @internal An anonymous sender: the NULL-DN a requester uses when it knows nothing about its own
 * name (RFC 9810 sec. 5.1.1), encoded as a directoryName with no relative names. */
function _isNullDnSender(sender) {
  return !!sender && sender.tagClass === "context" && sender.tagNumber === 4 &&
    !!sender.value && _isArray(sender.value.rdns) && sender.value.rdns.length === 0;
}

/** @internal The commonName of a sender given as a directoryName, which is the name a MAC-protected
 * message identifies its shared secret by (RFC 9483 sec. 4.1.5). A sender in any other GeneralName
 * form, or one carrying no commonName, names nothing a senderKID could equal. */
function _senderCommonName(sender) {
  if (!sender || sender.tagClass !== "context" || sender.tagNumber !== 4) return null;
  var rdns = sender.value && sender.value.rdns;
  if (!_isArray(rdns)) return null;
  var cnOid = oid.byName("commonName");
  for (var i = 0; i < rdns.length; i++) {
    var rdn = rdns[i];
    for (var j = 0; j < rdn.length; j++) {
      if (rdn[j].type === cnOid && typeof rdn[j].value === "string") return rdn[j].value;
    }
  }
  return null;
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

/** @internal Whether a declared key identifier names this certificate. Absent means the rule does not
 * apply; present with no subjectKeyIdentifier to compare means it cannot be satisfied, so the message
 * is refused rather than admitted for want of a value. */
function _senderKidMatchesCert(senderKID, parsed) {
  if (senderKID == null) return true;
  var ski = _certSki(parsed);
  return ski != null && guard.crypto.constantTimeEqual(ski, senderKID);
}

function _resolveSignerCert(m, opts, extra) {
  var senderKID = m.header.senderKID;
  function _signerObj(der, p) { return { der: der, spki: p.subjectPublicKeyInfo.bytes, subject: _subjectDn(p), parsed: p }; }
  function accept(der) {
    var p;
    try { p = x509.parse(der); }
    catch (_e) { return null; }
    if (!_senderKidMatchesCert(senderKID, p)) return null;
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
  if (!guard.bytes.isByteSource(m.header.senderNonce) ||
      guard.bytes.lengthOf(m.header.senderNonce) < constants.LIMITS.CMP_MIN_NONCE_BYTES) {
    return { code: "cmp/bad-sender-nonce", reason: "the header senderNonce is absent or shorter than 128 bits (RFC 9483 sec. 3.5)" };
  }
  if (opts.transactionID != null && !_bufEq(m.header.transactionID, opts.transactionID)) {
    return { code: "cmp/transaction-id-mismatch", reason: "header.transactionID does not equal the expected value (RFC 9810 sec. 5.1.1)" };
  }
  if (opts.expectRecipNonce != null && !_bufEq(m.header.recipNonce, opts.expectRecipNonce)) {
    return { code: "cmp/bad-recip-nonce", reason: "header.recipNonce does not echo the expected sender nonce" };
  }
  /** @internal A stated window is checked in both directions: a clock runs fast as readily as slow, and
   * a message dated ahead of the receiver is as much a replay signal as one dated behind it. */
  if (opts.messageTimeTolerance != null && m.header.messageTime != null) {
    var at = guard.time.instantOf(opts.time != null ? opts.time : new _Date());
    var sent = guard.time.instantOf(m.header.messageTime);
    if (!intrinsic.isFinite(at) || !intrinsic.isFinite(sent)) {
      return { code: "cmp/bad-message-time", reason: "the header messageTime could not be read as an instant to compare against the verification time (RFC 9483 sec. 3.5)" };
    }
    // allow:nan-date-comparison-unguarded -- both instants are finite by the check above
    var skew = (at > sent ? at - sent : sent - at) / 1000;
    if (skew > opts.messageTimeTolerance) {
      return { code: "cmp/bad-message-time", reason: "the header messageTime is " + intrinsic.floor(skew) +
        " seconds from the verification time, outside the " + opts.messageTimeTolerance +
        "-second window this caller accepts (RFC 9483 sec. 3.5)" };
    }
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

/** @internal The verifying half of RFC 9810 sec. 5.1.3.4. The peer that encapsulated holds the same
 * shared secret, and derives the key from it through the derivation `pki.cmp.build` uses, so the two
 * halves cannot disagree about the context. The transaction identifier the context binds to is the one
 * from the message that carried the ciphertext, which the caller names when it is not this message's. */
async function _verifyKem(m, protectedPart, protectionAlg, protection, opts) {
  var kemOpts = opts.kem;
  if (!kemOpts) {
    throw _err("cmp/bad-input", "a KEM-protected message requires opts.kem { sharedSecret, transactionID? }");
  }
  if (!_nonEmptySecret(kemOpts.sharedSecret)) {
    throw _err("cmp/bad-input", "opts.kem.sharedSecret is the KEM shared secret the peer encapsulated");
  }
  if (protectionAlg.parameters === null) {
    return _fail(m, "kem", protectionAlg, "cmp/protection-failed", "the KEM protectionAlg carries no KemBMParameter (RFC 9810 sec. 5.1.3.4)");
  }
  var params;
  try { params = cmp.readKemBMParameter(protectionAlg.parameters); }
  catch (e) {
    return _fail(m, "kem", protectionAlg, e instanceof CmpError ? e.code : "cmp/protection-failed",
      "the KemBMParameter did not decode: " + ((e && e.message) || e));
  }
  if (params.kdf.oid !== oid.byName("hkdfWithSha256")) {
    return _fail(m, "kem", protectionAlg, "cmp/unsupported-algorithm",
      "unsupported KEM key-derivation " + _stringify(params.kdf.name || params.kdf.oid) + " (HKDF-SHA256 only)");
  }
  if (params.mac.oid !== oid.byName("hmacWithSHA256")) {
    return _fail(m, "kem", protectionAlg, "cmp/unsupported-algorithm",
      "unsupported KEM message-authentication algorithm " + _stringify(params.mac.name || params.mac.oid) + " (HMAC-SHA256 only)");
  }
  /** @internal The sender chooses `len`, so a peer could name a key short enough to search. The
   * message is refused rather than verified under a key that carries no strength. */
  if (params.len < constants.LIMITS.CMP_KEM_MIN_KEY_BYTES) {
    return _fail(m, "kem", protectionAlg, "cmp/protection-failed",
      "the KemBMParameter names a " + params.len + "-byte protection key, and a key shorter than " +
      constants.LIMITS.CMP_KEM_MIN_KEY_BYTES + " bytes would not carry the strength the MAC is meant to have");
  }
  var txid = kemOpts.transactionID != null
    ? guard.bytes.view(kemOpts.transactionID, CmpError, "cmp/bad-input", "opts.kem.transactionID")
    : m.header.transactionID;
  if (txid == null) {
    return _fail(m, "kem", protectionAlg, "cmp/protection-failed",
      "a KEM-derived key is bound to the transaction identifier of the message that carried the ciphertext, and neither this message nor opts.kem names one");
  }
  var secret = guard.bytes.view(kemOpts.sharedSecret, CmpError, "cmp/bad-input", "opts.kem.sharedSecret");
  var ssk = null;
  try {
    ssk = await cmpBuild.kemSharedKey(secret, params.len, txid, params.kemContext);
    var computed = await cmpBuild.kemMac(ssk, protectedPart);
    if (!guard.crypto.constantTimeEqual(computed, protection.bytes)) {
      return _fail(m, "kem", protectionAlg, "cmp/protection-failed",
        "the KEM-based MAC does not verify (a different shared secret, a different derivation context, or a tampered ProtectedPart)");
    }
  } finally {
    if (ssk) guard.secret.zeroize(ssk, CmpError, "cmp/bad-input", "the KEM-derived protection key");
  }
  var khc = _headerChecks(m, opts);
  if (khc) return _fail(m, "kem", protectionAlg, khc.code, khc.reason);
  return _ok(m, "kem", protectionAlg, true, null);
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
  /** @internal Under MAC protection the sender names the shared secret, and sec. 4.1.5 requires the
   * senderKID to carry that same name: the identifier and the name the message is attributed to are
   * one value, so a message pointing them at different entities is refused. */
  /** @internal The name rule governs a sender that HAS a name. An anonymous NULL-DN sender carries a
   * reference number instead (RFC 9810 sec. 5.1.1), which names no commonName to equal, so it is
   * required to be present above and left uncompared here rather than refused for failing a match the
   * base protocol does not ask of it. */
  if (m.header.senderKID != null && !_isNullDnSender(m.header.sender)) {
    var cn = _senderCommonName(m.header.sender);
    if (cn === null || !guard.crypto.constantTimeEqual(_bufferFrom(cn, "utf8"), m.header.senderKID)) {
      return _fail(m, "mac", protectionAlg, "cmp/bad-sender-kid",
        "the header senderKID must carry the same name as the commonName of the sender field, which " +
        "is how a MAC-protected message identifies the shared secret it was protected with " +
        "(RFC 9483 sec. 4.1.5)");
    }
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
  if (!signer) {
    /** @internal Selecting from `extraCerts` narrows by the declared key identifier, so "nothing
     * matched" and "nothing was offered" are different failures. Reporting them apart keeps one
     * defect from carrying two codes depending on how the certificate would have arrived. */
    if (m.header.senderKID != null && extra.length) {
      return _fail(m, "signature", protectionAlg, "cmp/bad-sender-kid",
        "no certificate in extraCerts carries the subjectKeyIdentifier the header senderKID declares, " +
        "so nothing offered identifies the key that would verify the protection (RFC 9483 sec. 3.5)");
    }
    return _fail(m, "signature", protectionAlg, "cmp/signer-cert-not-found", "no signer certificate resolved (opts.signerCert, senderKID, or extraCerts)");
  }

  var ok = await _engine.verifyWithSpki(protectionAlg, protection.bytes, signer.spki, protectedPart);
  if (ok !== true) return _fail(m, "signature", protectionAlg, "cmp/protection-failed", "the protection signature does not verify over the ProtectedPart under the declared protectionAlg", signer);

  if (!_senderBoundToCert(m.header.sender, signer.parsed)) {
    return _fail(m, "signature", protectionAlg, "cmp/sender-mismatch", "the header sender field does not match the signer certificate subject, or (for an empty subject) a subjectAltName entry (RFC 9483 sec. 3.1, RFC 5280 sec. 7.1)", signer);
  }
  /** @internal The declared key identifier is checked against the certificate whose key ACTUALLY
   * verified, on every route that certificate arrives by. Selecting from `extraCerts` already matches
   * it while choosing, and a caller-supplied certificate reaches the same rule here, so a message
   * naming one key and signed by another is refused however the verifier came by the certificate
   * (RFC 9483 sec. 3.5). */
  if (!_senderKidMatchesCert(m.header.senderKID, signer.parsed)) {
    return _fail(m, "signature", protectionAlg, "cmp/bad-sender-kid",
      "the header senderKID does not identify the certificate whose key verified the protection: it " +
      "must equal that certificate's subjectKeyIdentifier (RFC 9483 sec. 3.5)", signer);
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

/** @internal A shared secret, taken once and registered for wiping. Every byte-source shape is
 * accepted, not only the ones a caller happens to have converted: a KEM encapsulation hands back an
 * ArrayBuffer, and a secret read from a larger allocation arrives as a view over it. */
function _fixSecret(v, made, label) {
  if (typeof v === "string") {
    var fromString = _bufferFrom(v, "utf8");
    _append(made, fromString);
    return fromString;
  }
  if (v != null && guard.bytes.isByteSource(v)) {
    var snap = guard.bytes.snapshotSource(v, CmpError, "cmp/bad-input", "opts." + (label || "sharedSecret"));
    _append(made, snap);
    return snap;
  }
  return v;
}

/** @internal The freshness window, in seconds. RFC 9483 sec. 3.5 leaves the threshold to the use case
 * and lists the check under local policy, so it is stated by the caller rather than defaulted: a
 * window this library invented would refuse conforming messages from a peer whose clock is merely
 * further off than that number. */
function _fixTolerance(v) {
  if (v == null) return null;
  if (typeof v !== "number" || !intrinsic.isFinite(v) || v < 0) {
    throw _err("cmp/bad-input", "opts.messageTimeTolerance is the accepted messageTime skew in seconds, a non-negative number");
  }
  return v;
}

/** @internal The KEM verification material, taken once at the door like every other caller value: the
 * shared secret is copied and registered for wiping, and the transaction identifier is snapshot, so
 * neither can answer differently when the derivation reads it. */
function _fixKem(v, made) {
  if (v == null) return null;
  if (typeof v !== "object" || guard.bytes.isByteSource(v)) {
    throw _err("cmp/bad-input", "opts.kem must be an object { sharedSecret, transactionID? }");
  }
  guard.identifier.assertKnownKeys(v, KNOWN_KEM_VERIFY_KEYS, _err, "cmp/bad-input", "unknown opts.kem field ");
  return {
    sharedSecret: _fixSecret(v.sharedSecret, made, "kem.sharedSecret"),
    transactionID: _fixByteish(v.transactionID, "kem.transactionID"),
  };
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
/** @internal The verification instant, copied so a caller cannot move it after the fact. A value that
 * is not a Date is refused here rather than carried into a comparison that would throw from whichever
 * check happened to read it first. */
function _fixTime(v) {
  if (v == null) return v;
  if (!guard.time.isDate(v)) throw _err("cmp/bad-input", "opts.time must be a Date");
  return new _Date(guard.time.instantOf(v));
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
    kem: _fixKem(opts.kem, made),
    messageTimeTolerance: _fixTolerance(opts.messageTimeTolerance),
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
  var isKem = protectionAlg.oid === oid.byName("kemBasedMac");
  var hasSigCred = opts.signerCert != null || opts.trustAnchors != null;
  var hasSecret = opts.sharedSecret != null;

  if (isKem) {
    if (hasSigCred) throw _err("cmp/bad-input", "a KEM-protected message takes opts.kem, not signerCert/trustAnchors");
    if (hasSecret) throw _err("cmp/bad-input", "a KEM-protected message takes opts.kem.sharedSecret, not opts.sharedSecret");
    return _verifyKem(m, protectedPart, protectionAlg, protection, opts);
  }
  if (opts.kem != null) throw _err("cmp/bad-input", "opts.kem verifies a KEM-based MAC, and this message is protected another way");

  if (isMac) {
    if (hasSigCred) throw _err("cmp/bad-input", "a MAC-protected message takes opts.sharedSecret, not signerCert/trustAnchors");
    if (!_nonEmptySecret(opts.sharedSecret)) throw _err("cmp/bad-input", "a PBMAC1-protected message requires a non-empty opts.sharedSecret");
    return _verifyMac(m, protectedPart, protectionAlg, protection, opts);
  }
  if (hasSecret) throw _err("cmp/bad-input", "a signature-protected message takes opts.signerCert/trustAnchors, not sharedSecret");
  return _verifySignature(m, protectedPart, protectionAlg, protection, opts);
}

var KNOWN_OPEN_KEY_PACKAGE_OPTS = intrinsic.assign(intrinsic.create(null), {
  key: 1, cert: 1, password: 1, trustAnchors: 1, intermediates: 1, time: 1,
  authorizedBySharedSecret: 1,
});
var OID_A_KEY_PACKAGE = oid.byName("aKeyPackage");
var OID_SIGNED_DATA = oid.byName("signedData");
var OID_ENVELOPED_DATA = oid.byName("envelopedData");
var OID_CM_KGA = oid.byName("cmKGA");

function _keyPackageErr(reason, cause) { return _err("cmp/bad-key-package", reason, cause); }

/** @internal The three shapes sec. 4.1.6 profiles out of an EnvelopedData, read from the parsed
 * container before anything is decrypted: the structure is an EnvelopedData, exactly one party can
 * open it, and what it holds is a SignedData. */
function _assertKeyPackageContainer(parsed) {
  if (parsed.contentTypeName !== "envelopedData") {
    throw _keyPackageErr("a delivered key package is carried in a CMS EnvelopedData, and this container is a " +
      parsed.contentTypeName + " (RFC 9483 sec. 4.1.6)");
  }
  var ris = parsed.recipientInfos;
  if (!_isArray(ris) || ris.length !== 1) {
    throw _keyPackageErr("a delivered key package names exactly one RecipientInfo, and this container names " +
      guard.text.showValue(ris && ris.length) +
      "; a second recipient is a second party able to open a key generated for this entity (RFC 9483 sec. 4.1.6)");
  }
  /** @internal A `KeyAgreeRecipientInfo` wraps the content-encryption key once per entry in its
   * `recipientEncryptedKeys` (RFC 5652 sec. 6.2.2), each for a different recipient under one
   * originator, so counting RecipientInfos alone would admit a second party under one of them. */
  var reks = ris[0].recipientEncryptedKeys;
  if (_isArray(reks) && reks.length !== 1) {
    throw _keyPackageErr("the key agreement RecipientInfo of a delivered key package wraps the content-encryption key once, and this one wraps it " +
      reks.length + " times; each is a party able to open a key generated for this entity (RFC 9483 sec. 4.1.6, RFC 5652 sec. 6.2.2)");
  }
  var eci = parsed.encryptedContentInfo;
  if (!eci || eci.contentType !== OID_SIGNED_DATA) {
    throw _keyPackageErr("the encrypted content of a delivered key package is declared id-signedData, and this container declares " +
      guard.text.showValue(eci && eci.contentType) + " (RFC 9483 sec. 4.1.6)");
  }
}

/** @internal RFC 5958 sec. 2: AsymmetricKeyPackage ::= SEQUENCE SIZE (1..MAX) OF OneAsymmetricKey.
 * Each element is surfaced as its own DER buffer, which is what a PKCS#8 `PrivateKeyInfo` is
 * (`PrivateKeyInfo ::= OneAsymmetricKey`), so a caller imports it without re-encoding. Copied off the
 * decrypted content rather than sliced from it, so holding one key does not hold the package. */
var ASYMMETRIC_KEY_PACKAGE = schema.seqOf(
  schema.decode(function (n, ctx) {
    if (!(n.tagClass === "universal" && n.tagNumber === asn1.TAGS.SEQUENCE && n.children && n.children.length >= 1)) {
      throw ctx.E("cmp/bad-key-package", "an AsymmetricKeyPackage element must be a OneAsymmetricKey SEQUENCE (RFC 5958 sec. 2)");
    }
    /** @internal OneAsymmetricKey and a PKCS#8 PrivateKeyInfo are the same structure (RFC 5958
     * sec. 2), so the shipped strict parser decides whether an element is one; a SEQUENCE that merely
     * looks like a container is not a delivered key. */
    try { pkcs8.parse(n.bytes); }
    catch (e) { throw ctx.E("cmp/bad-key-package", "an AsymmetricKeyPackage element is not a OneAsymmetricKey (RFC 5958 sec. 2)", e); }
    return _bufferFrom(n.bytes);
  }),
  { assert: "sequence", min: 1, code: "cmp/bad-key-package", what: "AsymmetricKeyPackage",
    build: function (m) { return _map(m.items, function (it) { return it.value; }); } });

function _readKeyPackage(der) {
  var node;
  try { node = asn1.decode(der); }
  catch (e) { throw _keyPackageErr("the signed content is not DER", e); }
  return schema.walk(ASYMMETRIC_KEY_PACKAGE, node, NS).result;
}

function _fixOpenKeyPackageOptions(opts, made) {
  opts = guard.identifier.optionsObject(opts, _err, "cmp/bad-input", "pki.cmp.openKeyPackage options");
  guard.identifier.assertKnownKeys(opts, KNOWN_OPEN_KEY_PACKAGE_OPTS, _err, "cmp/bad-input", "unknown opts field ");
  var f = {
    key: opts.key,
    cert: _fixByteish(opts.cert, "cert"),
    password: _fixSecret(opts.password, made, "password"),
    trustAnchors: _fixCertList(opts.trustAnchors, "trustAnchors"),
    intermediates: _fixPoolCerts(opts.intermediates, "intermediates"),
    time: _fixTime(opts.time),
    exempt: opts.authorizedBySharedSecret === true,
  };
  if (opts.authorizedBySharedSecret != null && typeof opts.authorizedBySharedSecret !== "boolean") {
    throw _err("cmp/bad-input", "opts.authorizedBySharedSecret is a boolean stating that this entity protected its request with the shared secret");
  }
  if (f.key == null && f.password == null) {
    throw _err("cmp/bad-input", "opening a delivered key package needs the key material the content-encryption key was protected to: opts.key (with opts.cert) for the key transport and key agreement techniques, or opts.password for the password technique (RFC 9483 sec. 4.1.6.1 to 4.1.6.3)");
  }
  if (f.key != null && f.password != null) {
    throw _err("cmp/bad-input", "a delivered key package is opened by one key management technique: pass opts.key or opts.password, not both");
  }
  /** @internal sec. 4.1.6 offers the shared-secret exemption only to an entity that protected its
   * request with a MAC, which is the entity opening this container with that secret. Stating it
   * alongside a private key claims the exemption for a signature-protected exchange, where the
   * section's requirement to validate the signer stands. */
  if (f.exempt && f.password == null) {
    throw _err("cmp/bad-input", "opts.authorizedBySharedSecret authorizes the key generation authority by the secret that protected the request, so it applies only to a container opened with opts.password (RFC 9483 sec. 4.1.6)");
  }
  if (f.exempt && f.trustAnchors != null) {
    throw _err("cmp/bad-input", "opts.authorizedBySharedSecret and opts.trustAnchors state two different rules for authorizing the key generation authority; supply one");
  }
  if (!f.exempt && f.trustAnchors == null) {
    throw _err("cmp/bad-input", "authorizing the key generation authority needs opts.trustAnchors, or opts.authorizedBySharedSecret when this entity protected its request with the shared secret (RFC 9483 sec. 4.1.6)");
  }
  return f;
}

async function _openKeyPackage(container, opts) {
  var bytes = _asContentInfo(
    guard.bytes.snapshotSource(_coerceKeyPackageBytes(container), CmpError, "cmp/bad-input", "the delivered key package container"),
    OID_ENVELOPED_DATA, "the delivered key package container");
  var parsed;
  try { parsed = cms.parse(bytes); }
  catch (e) { throw _keyPackageErr("the delivered key package container is not a CMS ContentInfo", e); }
  _assertKeyPackageContainer(parsed);

  /** @internal The profile fixes the recipient count at one, so the arm to open is named instead of
   * matched: a caller holding only the private key need not supply the certificate as well. */
  /** @internal Every way the container fails to open reports the one code, so the verdict carries no
   * more than "it did not open": `pki.cms.decrypt` already collapses each secret-dependent failure to
   * a single uniform result, and splitting that back out here would rebuild the oracle it removes. */
  var opened;
  try {
    opened = await cmsDecrypt.decrypt(bytes, opts.password != null ? { password: opts.password } : { key: opts.key, cert: opts.cert },
      { recipientIndex: 0 });
  } catch (e) {
    throw _keyPackageErr("the delivered key package could not be opened under the supplied key material", e);
  }

  var verdict;
  var signedData = _asContentInfo(opened.content, OID_SIGNED_DATA, "the encrypted content");
  try { verdict = await cmsVerify.verify(signedData, _signedDataVerifyOpts(opts)); }
  catch (e) { throw _keyPackageErr("the SignedData wrapping the key package could not be verified", e); }
  if (!verdict.valid) {
    throw _keyPackageErr("the signature over the delivered key package does not verify; the SignedData reports [" +
      intrinsic.join(_map(verdict.signers, function (s) { return s.code || "a signature mismatch"; }), ", ") + "]");
  }
  if (verdict.eContentType !== OID_A_KEY_PACKAGE) {
    throw _keyPackageErr("the signed content type is " + verdict.eContentType + ", not id-ct-KP-aKeyPackage; the signature must bind what it covers to a key package (RFC 9483 sec. 4.1.6, RFC 5958 sec. 2)");
  }
  var signerCert = verdict.signers[0] && verdict.signers[0].cert;
  if (!signerCert) throw _keyPackageErr("the SignedData names no signer certificate to authorize as the key generation authority");
  _authorizeKga(verdict, signerCert, opts);
  if (verdict.eContent == null) throw _keyPackageErr("the SignedData carries no encapsulated content, so no key package was delivered");
  return { keys: _readKeyPackage(verdict.eContent), kga: _bufferFrom(signerCert), trusted: opts.exempt ? false : true };
}

/** @internal sec. 4.1.6: the entity "MUST use a certificate containing the additional extended key
 * usage extension id-kp-cmKGA in order to be accepted by the EE as a legitimate key generation
 * authority", and the EE "MUST validate the signer certificate". `pki.path.validate`'s `requiredEku`
 * answers the RFC 5280 sec. 4.2.1.12 question (does this certificate PERMIT the purpose), which an
 * absent extension satisfies, so the assertion is checked here as well as the chain. */
function _authorizeKga(verdict, signerCert, opts) {
  if (opts.exempt) return;
  if (!verdict.trusted) {
    throw _err("cmp/unauthorized-kga", "the certificate that signed the delivered key package does not chain to an accepted trust anchor (RFC 9483 sec. 4.1.6)");
  }
  var parsedSigner;
  try { parsedSigner = x509.parse(signerCert); }
  catch (e) { throw _err("cmp/unauthorized-kga", "the certificate that signed the delivered key package could not be read", e); }
  if (!pkix.assertsPurpose(NS, parsedSigner, OID_CM_KGA)) {
    throw _err("cmp/unauthorized-kga", "the certificate that signed the delivered key package does not assert the id-kp-cmKGA extended key usage, which is what a key generation authority uses to show it is one (RFC 9483 sec. 4.1.6, RFC 9480 sec. 2.2)");
  }
}

function _signedDataVerifyOpts(opts) {
  if (opts.exempt) return {};
  var v = { trustAnchors: opts.trustAnchors, requiredEku: [OID_CM_KGA] };
  if (opts.intermediates != null) v.certs = opts.intermediates;
  if (opts.time != null) v.time = opts.time;
  return v;
}

/** @internal The certificate options here take one certificate or a list of them, as DER or PEM, which
 * is the shape `pki.cmp.verify` takes. `pki.cms.verify` takes `certs` as a list of DER, so the pool is
 * normalized at the door: a single certificate forwarded unwrapped would be walked as a sequence of
 * its own bytes and contribute nothing, and a PEM string would not be read at all. */
function _fixPoolCerts(v, label) {
  if (v == null) return v;
  var list = _fixCertList(_isArray(v) ? v : [v], label);
  return _map(list, function (c, i) {
    if (typeof c !== "string") return c;
    try { return x509.pemDecode(c); }
    catch (e) { throw _err("cmp/bad-input", "opts." + label + "[" + i + "] PEM could not be decoded", e); }
  });
}

/** @internal Both CMS layers arrive in either of two forms, and the two are structurally exclusive so
 * neither is guessed at. A ContentInfo opens with an OBJECT IDENTIFIER naming its content type; the
 * bare structure opens with its own `CMSVersion` INTEGER. Both forms are seen in practice. A CMP
 * `EncryptedKey` carries the `EnvelopedData` itself (RFC 9810 sec. 5.2.2), and RFC 5652 sec. 6.1
 * encrypts the CONTENT rather than a ContentInfo around it, so the plaintext under an `id-signedData`
 * `encryptedContentInfo` is a `SignedData`. Each is wrapped so one code path reads both. Anything
 * else is left alone for the ContentInfo parse to refuse by name. */
function _asContentInfo(der, contentTypeOid, what) {
  var node;
  try { node = asn1.decode(der); }
  catch (e) { throw _keyPackageErr(what + " is not DER", e); }
  var first = node.constructed && node.children ? node.children[0] : null;
  if (!first || first.tagClass !== "universal" || first.tagNumber !== asn1.TAGS.INTEGER) return der;
  return b.sequence([b.oid(contentTypeOid), b.explicit(0, b.raw(der))]);
}

function _coerceKeyPackageBytes(container) {
  if (typeof container === "string") {
    try { return cms.pemDecode(container); }
    catch (e) { throw _err("cmp/bad-input", "the delivered key package container PEM could not be decoded", e); }
  }
  return container;
}

/**
 * @primitive pki.cmp.openKeyPackage
 * @signature pki.cmp.openKeyPackage(container, opts) -> Promise<{ keys, kga, trusted }>
 * @since 0.6.52
 * @status stable
 * @spec RFC 9483 sec. 4.1.6, RFC 5958, RFC 5652, RFC 9480 sec. 2.2
 * @defends unauthorized-key-generation-authority (CWE-863)
 * @related pki.cmp.session, pki.cms.decrypt, pki.cms.verify
 *
 * Open a centrally generated private key delivered in a CMP response (RFC 9483 sec. 4.1.6). A CA that
 * generates the key pair on the end entity's behalf puts it in the `privateKey` field of the granted
 * `CertifiedKeyPair`: an RFC 5958 `AsymmetricKeyPackage`, signed by the Key Generation Authority in a
 * CMS `SignedData`, sealed to this entity in a CMS `EnvelopedData`. `container` is those
 * `EnvelopedData` bytes (DER `Buffer` or PEM), which `pki.cmp.session` surfaces as
 * `deliveredKey` when the session is told to accept one.
 *
 * The two layers are undone in order and the authority is authorized BEFORE any key material is
 * returned. Which key management technique opens the container follows the protection of the request
 * that asked for the key: `opts.key` (with `opts.cert`) for the key transport and key agreement
 * techniques a signature-protected request selects (sec. 4.1.6.1, sec. 4.1.6.2), `opts.password` for
 * the password technique a MAC-protected request selects (sec. 4.1.6.3).
 *
 * Authorization is the point of the verb. The section requires the signer's certificate to carry the
 * `id-kp-cmKGA` extended key usage "in order to be accepted by the EE as a legitimate key generation
 * authority", so a certificate that merely PERMITS the purpose by carrying no `extendedKeyUsage` at
 * all does not authorize: the assertion must be present, and the certificate must chain to an anchor
 * in `opts.trustAnchors`. The one exception is the section's own: an entity that protected its request
 * with a shared secret "MAY omit the validation" and authorize the authority by that secret instead.
 * That is stated with `opts.authorizedBySharedSecret`, it applies only to a container opened with
 * `opts.password`, and the result then reports `trusted: false`.
 *
 * Returns `{ keys, kga, trusted }`. `keys` is every `OneAsymmetricKey` in the package, in order, each
 * as its own DER `Buffer` that is a PKCS#8 `PrivateKeyInfo` ready for `pki.key.import`. `kga` is the
 * signer certificate whose signature was checked. `trusted` says whether that certificate chained.
 * Malformed input, an unopenable container, an unverifiable signature, or an unauthorized authority
 * all throw a typed `CmpError`; no key material is returned on any of them.
 *
 * The container's shape is held to the profile where the shape decides who reads the key or what the
 * signature covers: it must be an `EnvelopedData`, it must name exactly one `RecipientInfo`, its
 * encrypted content type must be `id-signedData`, and the signed content type must be
 * `id-ct-KP-aKeyPackage`. The profile's CMS version literals are not enforced, because RFC 5652
 * sec. 5.1 and sec. 6.1 derive those from the signer and recipient forms in use and a conforming
 * sender reaches different values. Its choice-of-form rules, the signer identifier form and the
 * ordering of the certificates the SignedData carries, are not judged either. Both live inside the
 * encrypted SignedData rather than in the `container` bytes, and the result carries only the signer
 * certificate, so a caller holding a stricter profile cannot judge them from this verdict.
 *
 * `keys` is the whole RFC 5958 `AsymmetricKeyPackage`, which is `SIZE (1..MAX)`, so a package carrying
 * several is opened and every key returned. RFC 9483 sec. 4.1.6 profiles that to a sequence of one,
 * and where the count decides something it is held: a `pki.cmp.session` enrollment requires exactly
 * one, since one grant certifies one key and every further key is one the issued certificate says
 * nothing about. A caller using this verb on its own owns that binding.
 *
 * @opts
 *   - `key` (Buffer|PEM|CryptoKey) -- this entity's private key, for a container opened by the key
 *     transport or key agreement technique.
 *   - `cert` (Buffer|PEM) -- the certificate for `key`. Optional: the profile fixes the recipient
 *     count at one, so the arm is named rather than matched.
 *   - `password` (string|Buffer) -- the shared secret, for a container opened by the password
 *     technique. Copied at the door and wiped when the call returns.
 *   - `trustAnchors` (Buffer|Buffer[]|PEM) -- the roots this entity accepts for the key generation
 *     authority. REQUIRED unless `authorizedBySharedSecret` is set.
 *   - `intermediates` (Buffer|Buffer[]|PEM) -- extra untrusted pool certificates for path building.
 *   - `time` (Date) -- the validity instant for path validation. Defaults to the current time.
 *   - `authorizedBySharedSecret` (boolean) -- authorize the authority by the secret that protected
 *     the request rather than by a chain, which sec. 4.1.6 permits a MAC-protected exchange. Requires
 *     `opts.password` and refuses `opts.trustAnchors`.
 * @example
 *   var nb = new Date("2026-01-01T00:00:00Z"), na = new Date("2036-01-01T00:00:00Z");
 *   var kgaPair = await pki.key.generate("Ed25519");                       // the key generation authority
 *   var kgaKey = await pki.key.export(kgaPair.privateKey);
 *   var kgaCert = await pki.x509.sign({ subject: "Key Generation Authority",
 *     subjectPublicKey: await pki.key.export(kgaPair.publicKey), notBefore: nb, notAfter: na,
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"],
 *       extendedKeyUsage: ["cmKGA"], subjectKeyIdentifier: true } }, { key: kgaKey });
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var eePair = await pki.key.generate(rsa);                              // the enrolling end entity
 *   var eeKey = await pki.key.export(eePair.privateKey);
 *   var eeCert = await pki.x509.sign({ subject: "Enrolling client",
 *     subjectPublicKey: await pki.key.export(eePair.publicKey), notBefore: nb, notAfter: na,
 *     extensions: { keyUsage: ["keyEncipherment"] } }, { key: eeKey });
 *   var generated = await pki.key.export((await pki.key.generate("Ed25519")).privateKey);
 *   var signedPackage = await pki.cms.sign(pki.asn1.build.sequence([pki.asn1.build.raw(generated)]),
 *     [{ key: kgaKey, cert: kgaCert }], { eContentType: "aKeyPackage", sid: "ski" });
 *   var deliveredKeyDer = await pki.cms.encrypt(signedPackage, [{ cert: eeCert }],
 *     { contentEncryptionAlgorithm: "aes-256-cbc", contentType: "signedData" });
 *   var opened = await pki.cmp.openKeyPackage(deliveredKeyDer,
 *     { key: eeKey, cert: eeCert, trustAnchors: [kgaCert] });
 *   opened.keys.length;                                   // 1
 *   var privateKey = await pki.key.import(opened.keys[0]);
 */
function openKeyPackage(container, opts) {
  var made = [];
  return guard.async.deferred(async function () {
    try {
      return await _openKeyPackage(container, _fixOpenKeyPackageOptions(opts, made));
    } finally {
      guard.secret.zeroizeAll(made, CmpError, "cmp/bad-input", "the copied key package shared secret");
    }
  });
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
 * A present `senderKID` must identify the key material that verified the protection (RFC 9483
 * sec. 3.5), whichever way that key was resolved. Under signature protection it must equal the
 * `subjectKeyIdentifier` of the certificate whose key verified, so a certificate supplied as
 * `opts.signerCert` is held to the declared identifier exactly as one selected out of `extraCerts` is,
 * and a certificate carrying no `subjectKeyIdentifier` cannot satisfy one. Under MAC protection it must
 * carry the same name as the `commonName` of the sender field, which is how such a message names the
 * shared secret it was protected with (sec. 4.1.5). A mismatch is a `cmp/bad-sender-kid` verdict.
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
 *   - `messageTimeTolerance` (number) -- the accepted `messageTime` skew in seconds. RFC 9483
 *     sec. 3.5 requires a present `messageTime` to be close to the receiver's current time but leaves
 *     the threshold to the use case, so stating it turns the check on; a message outside the window in
 *     either direction is a `cmp/bad-message-time` verdict. Absent, the `messageTime` is not judged.
 *   - `kem` ({ sharedSecret, transactionID? }) -- REQUIRED for a KEM-protected message (RFC 9810
 *     sec. 5.1.3.4). `sharedSecret` is what this side encapsulated to the sender's KEM public key, and
 *     `transactionID` names the message that carried the ciphertext when it was not this one. The
 *     verdict's `protectionType` is `kem`.
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
  openKeyPackage: openKeyPackage,
  setEngine: setEngine,
  senderBoundToCert: _senderBoundToCert,
};
