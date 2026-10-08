// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.transport
 * @nav        Protocols
 * @title      Transport
 * @fullname   HTTP transport for OCSP, CRL, EST and ACME requests
 * @order      195
 * @slug       transport
 *
 * @intro
 *   The shared, fail-closed `node:https` transport the enrollment protocol clients
 *   drive: `pki.est` now, `pki.acme` and `pki.cmp` next. This is the only module in
 *   the toolkit that opens a socket; every protocol layer stays transport-agnostic and
 *   composes it (or an injected substitute) through one contract:
 *   `transport(request) -> Promise<{ status, headers, body, tls }>`. The first three are
 *   exactly what a message layer's classifier consumes, so no protocol semantics leak
 *   into the socket layer: the transport owns socket lifecycle, the TLS trust policy,
 *   the streaming size cap, and the timeout budget; the caller owns HTTP status,
 *   content-type, redirect, and authentication decisions. `tls` reports the negotiated
 *   channel, `{ protocol, cipher, peerCertificate, tlsUnique, tlsExporter }`, facts a caller
 *   cannot recover from the response bytes. The two bindings are complementary, one per version,
 *   so a caller reads whichever the negotiated protocol defines. `tlsUnique` is the RFC 5929
 *   channel binding (the first TLS Finished) on a TLS 1.2 connection, which
 *   `pki.est.challengePasswordFromTlsUnique` base64-encodes into an EST challengePassword
 *   (RFC 7030 sec. 3.5); it is `null` on TLS 1.3, where RFC 5929 defines no tls-unique.
 *   `tlsExporter` is the RFC 9266 binding on a TLS 1.3 connection: 32 bytes exported under the
 *   label `EXPORTER-Channel-Binding` with a zero-length context, the value both peers derive.
 *   It is `null` below TLS 1.3, where RFC 9266 sec. 2 additionally requires the RFC 7627 extended
 *   master secret, which node gives no way to confirm, so the binding is withheld rather than
 *   offered unproven; it is also `null` if the socket cannot export. No shipped verb consumes
 *   tls-exporter yet: RFC 7030 sec. 3.5 binds tls-unique specifically, so a caller must not put a
 *   tls-exporter value in that challengePassword. An INJECTED substitute should return these too:
 *   `pki.est.serverkeygen` asserts the negotiated cipher can protect the private key it
 *   is about to accept, and a transport that reports no cipher is trusted instead of
 *   refused (so a loopback test channel works), which means omitting the field silently
 *   skips that assertion. Because `tlsUnique` on the response arrives after the request
 *   body was already sent, a request `body` MAY instead be a function `(tls) -> bytes`.
 *   The transport invokes it once the handshake completes and before it writes the body,
 *   passing the same `{ protocol, cipher, peerCertificate, tlsUnique }` object, so the
 *   caller builds the request body (a channel-bound CSR) from `tlsUnique` on the very
 *   connection the request is sent over. The callback returns bytes or a string, or a
 *   promise of either, so the CSR can be signed with the toolkit's own asynchronous
 *   signer while the connection is held open. A throw, a rejection, a missing return,
 *   `null`, or any other value fails the request closed, so a callback that forgets to
 *   return cannot post an empty enrollment to a CA. An explicit empty string is an
 *   intentional empty body, and the request budget still bounds the whole exchange.
 *
 *   `pki.transport.https(defaults?)` binds TLS + budget defaults and returns a
 *   transport. Trust is EXPLICIT and fail-closed: a request is refused unless it
 *   carries an https URL and either a `tls.anchors` set (an Explicit trust-anchor
 *   database, mapped to the node `ca` option) or an explicit `tls.useSystemStore`
 *   opt-in to node's bundled roots. `rejectUnauthorized` is always on: there is no
 *   code path that disables server-certificate verification. The response body is
 *   bounded WHILE it streams: the accumulator aborts the socket the instant the running
 *   total crosses `maxResponseBytes`, before a byte reaches a decoder. A protocol
 *   client MAY parameterize the transport with its own `(code, message, cause)` error
 *   factory + code prefix, so the same choke point surfaces domain-specific codes.
 *
 * @card
 *   The shared fail-closed node:https transport (est / acme / cmp): explicit trust
 *   anchors, rejectUnauthorized always on, a TLS floor, a streaming response-size cap,
 *   and a timeout, behind one `transport(request) -> {status, headers, body, tls}` seam.
 */

var nodeHttps = require("node:https");
var nodeHttp = require("node:http");
var nodeNet = require("node:net");
/** @internal The address-family classification, captured at load. It is consulted BEFORE any of the
 * string operations in `_isBlockedIp`, and the export is writable: answering `0` for `127.0.0.1`
 * makes the function fall through to "not blocked", so a request under `blockPrivateAddresses`
 * reaches the private address no matter how carefully the operations after it are captured. */
var _isIP = nodeNet.isIP;
/** @internal The TLS identity check, captured at load. It RETURNS A VERDICT about whether a
 * certificate belongs to the host that was asked for, and the export is writable: a replacement
 * answering with no error is the server-authentication step reporting success for a certificate
 * issued to someone else. Every route that asks the question reads this one reference. */
var nodeTls = require("node:tls");
/** @internal The TLS identity check, captured where `nodeTls` is in scope. It RETURNS A VERDICT about
 * whether a certificate belongs to the host that was asked for, and the export is writable: a
 * replacement answering with no error is the server-authentication step reporting success for a
 * certificate issued to someone else. Every route that asks the question reads this one reference. */
var _checkServerIdentity = nodeTls.checkServerIdentity;
var nodeDns = require("node:dns");
var nodeUtil = require("node:util");
var constants = require("./constants");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
/** @internal `resolve` and `reject` build their promise from the RECEIVER, so reading the global
 *  binding at the call hands the construction to whatever that binding holds. A refusal returned as a
 *  rejected promise is a verdict: a replacement whose `reject` resolves lets a request the preparation
 *  step rejected proceed, and `peerChain`'s refusal to tunnel through a proxy is one of those. Taken at
 *  load. */
var _Promise = intrinsic.Promise;
/** @internal The URL parser, taken at load: what it returns names the host the socket is opened to,
 *  for the request itself and for a proxy it is tunneled through. The conversion it is handed is taken
 *  with it, since a replacement answers with a host of its own. */
var _URL = intrinsic.URL;
var _stringOf = intrinsic.String;
/** @internal The split an address literal is classified by. Read off the live prototype, it decides
 * which octets the blocklist sees, and a replacement answering with a public address's octets is
 * admitted: measured, `127.0.0.1` split into `93.184.216.34` cleared the private-address refusal and
 * the request went out. */
var _strSplit = intrinsic.uncurry(String.prototype.split);
/** @internal The parts of that destination are read through the accessors captured at load, not off the
 *  prototype the parsed value reads through: a replaced `URL.prototype.hostname` names the host this
 *  module then opens a socket to. */
var _urlProtocol = intrinsic.urlProtocol;
var _urlHostname = intrinsic.urlHostname;
var _urlPort = intrinsic.urlPort;
var _urlPathname = intrinsic.urlPathname;
var _urlSearch = intrinsic.urlSearch;
var _urlUsername = intrinsic.urlUsername;
var _urlPassword = intrinsic.urlPassword;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);
var _promiseReject = intrinsic.uncurry(intrinsic.promiseReject);
/** @internal The rest of the operations this module decides on, bound at load. Every one of them
 *  participates in a decision a socket is opened on: which scheme and host the request goes to,
 *  whether an address is private, which header a value is read under, how a body is sized and
 *  framed, and which TLS material a hop may carry. Read off the live prototype instead, a
 *  co-resident replacement answers the comparison rather than the value. */
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _strIndexOf = intrinsic.stringIndexOf;
var _toLowerCase = intrinsic.toLowerCase;
var _fromCharCode = intrinsic.fromCharCode;
var _isArray = intrinsic.isArray;
var _arrIndexOf = intrinsic.indexOf;
/** @internal `append`, not a captured `push`: a store at an index walks the prototype chain for a
 *  setter, so an accessor there takes the element being appended, and this list is the peer chain a
 *  caller reads. `append` defines the index. */
var _arrPush = intrinsic.append;
var _arrForEach = intrinsic.forEach;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferAlloc = intrinsic.bufferAlloc;
var _bufToString = intrinsic.bufToString;
var _byteLength = intrinsic.byteLength;
var _objectCreate = intrinsic.create;
var _objectAssign = intrinsic.assign;
var _objectKeys = intrinsic.keys;
var _getPrototypeOf = intrinsic.getPrototypeOf;
var _getOwnPropertyNames = intrinsic.getOwnPropertyNames;
var _getOwnPropertyDescriptor = intrinsic.getOwnPropertyDescriptor;
var _objectProto = intrinsic.ObjectProto;
var _arrayProto = intrinsic.ArrayProto;
var _hasOwn = intrinsic.hasOwn;
var _concatList = intrinsic.concatList;
var _taSet = intrinsic.typedArraySet;
var _bufferAllocUnsafe = Buffer.allocUnsafe;
/** @internal The three functions that actually open a connection, bound at load. Looked up on the
 *  module when the connection is made, a replacement installed afterwards sent a request prepared
 *  for one destination to another and handed the caller that peer's answer. */
var _httpsRequest = nodeHttps.request;
var _httpRequest = nodeHttp.request;
var _tlsConnect = nodeTls.connect;
var _netConnect = nodeNet.connect;
var _mathMin = intrinsic.min;
var _mathMax = intrinsic.max;
var frameworkError = require("./framework-error");

var TransportError = frameworkError.TransportError;
function defaultE(code, message, cause) { return new TransportError(code, message, cause); }

var DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var MAX_TIMEOUT = constants.TIME.seconds(600);
var DEFAULT_MIN_VERSION = "TLSv1.2";

function _budget(value, key, dflt, max, E, code) {
  return guard.limits.cap(value, key, dflt, { E: E, code: code, min: 1, max: max, label: key });
}

var _LATIN1_WS = _fromCharCode(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0);

/** @internal The received bytes, copied out at the length that was counted. The copy is its own
 *  allocation rather than a view, because the buffer it is taken from is reused as more data
 *  arrives. */
function _bodyCopy(buf, len) {
  var out = _bufferAllocUnsafe(len);
  _taSet(out, intrinsic.byteSlice(buf, 0, len), 0);
  return out;
}

function _looksLikePemArmor(s) {
  var i = 0;
  while (i < s.length && _strIndexOf(_LATIN1_WS, _charAt(s, i)) !== -1) i += 1;
  return _strSlice(s, i, i + 11) === "-----BEGIN ";
}
function _wrap64Lines(s) {
  var out = "";
  for (var i = 0; i < s.length; i += 64) out += _strSlice(s, i, i + 64) + "\n";
  return out;
}
function _stripIpv6Brackets(s) {
  return (s.length >= 2 && _charAt(s, 0) === "[" && _charAt(s, s.length - 1) === "]")
    ? _strSlice(s, 1, s.length - 1) : s;
}

var TLS_EXPORTER_LABEL = "EXPORTER-Channel-Binding";
var TLS_EXPORTER_LENGTH = 32;

function _tlsExporter(socket, proto) {
  if (proto !== "TLSv1.3" || !socket || typeof socket.exportKeyingMaterial !== "function") return null;
  var out;
  try { out = socket.exportKeyingMaterial(TLS_EXPORTER_LENGTH, TLS_EXPORTER_LABEL, _bufferAlloc(0)); }
  catch (_ee) { return null; }
  return (_isBuffer(out) && out.length === TLS_EXPORTER_LENGTH) ? out : null;
}

function _tlsInfo(socket) {
  var proto = socket && socket.getProtocol ? socket.getProtocol() : null;
  var cipher = socket && socket.getCipher ? socket.getCipher() : null;
  var peer = socket && socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  var reused = socket && socket.isSessionReused ? socket.isSessionReused() : false;
  var tlsUnique = (socket && socket.getFinished && socket.getPeerFinished && proto === "TLSv1.2")
    ? (reused ? socket.getPeerFinished() : socket.getFinished()) : null;
  if (tlsUnique != null && tlsUnique.length === 0) tlsUnique = null;
  var tlsExporter = _tlsExporter(socket, proto);
  return { protocol: proto, cipher: cipher, peerCertificate: peer && peer.raw ? peer.raw : null, tlsUnique: tlsUnique, tlsExporter: tlsExporter };
}

/** @internal The chain the TLS session resolved, leaf first, walked through the detailed peer
 * certificate's `issuerCertificate` links. The walk is bounded twice over: the top certificate
 * issues itself, so the identity comparison ends it, and a cap ends any cycle a runtime could
 * report instead.
 * IT IS NOT THE SAME AS WHAT THE ENDPOINT TRANSMITTED, which this comment used to claim. Node
 * completes `issuerCertificate` from the trust store in scope, so an endpoint that sends its leaf
 * alone still yields a chain whose upper entries came from the configured anchors rather than off
 * the wire. Node exposes no API for the transmitted list, so the distinction cannot be recovered
 * here and is stated instead of guessed at: filtering the entries that match an anchor would drop
 * a root an endpoint really did send. */
function _peerChain(socket) {
  if (!socket || typeof socket.getPeerCertificate !== "function") return [];
  var out = [];
  var seen = [];
  var cur = socket.getPeerCertificate(true);
  while (cur && _isBuffer(cur.raw) && out.length < constants.LIMITS.TLS_MAX_PEER_CHAIN) {
    if (_arrIndexOf(seen, cur) !== -1) break;
    _arrPush(seen, cur);
    _arrPush(out, cur.raw);
    cur = cur.issuerCertificate;
  }
  return out;
}

function _pemifyAnchor(a) {
  if (typeof a === "string") return a;
  if (_isBuffer(a)) {
    if (_looksLikePemArmor(_bufToString(a, "latin1", 0, 64))) return a;
    var b64 = _wrap64Lines(_bufToString(a, "base64"));
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n";
  }
  return a;
}
function _pemifyAnchors(anchors) {
  var list = _isArray(anchors) ? guard.list.copyMap(anchors, _pemifyAnchor) : [_pemifyAnchor(anchors)];
  return list;
}

/** @internal The platform trust store is read through the provider bound at load. Looked up on the
 *  module at call time, a replacement installed after load answered with its own list and became the
 *  trust a `useSystemStore` connection is accepted under. */
var _getCACertificates = typeof nodeTls.getCACertificates === "function" ? nodeTls.getCACertificates : null;

var _systemCaCache = null;
function _systemCa() {
  if (_systemCaCache !== null) return _systemCaCache;
  var out = [];
  if (_getCACertificates !== null) {
    _arrForEach(["system", "bundled"], function (t) {
      // allow:swallow-unverified a store TYPE unsupported on this node is skipped; the other type
      try { var c = intrinsic.apply(_getCACertificates, nodeTls, [t]); if (_isArray(c)) out = _concatList(out, c); } catch (_e) { }
    });
  }
  _systemCaCache = out;
  return out;
}

function _isBlockedIp(ip) {
  /** @internal The argument has to BE a string, and what cannot be classified is blocked. `isIP`
   * converts its argument, so a value whose conversion answers a loopback literal to the family
   * check and a public one to the octet scan was classified twice and the second answer decided:
   * measured, such a value came back NOT blocked while the family check had seen `127.0.0.1`. A
   * caller-supplied `lookup` reaches this with whatever it yields, and `pki.transport.isBlockedIp`
   * takes the value directly. A non-IP STRING is still not an address literal and answers false. */
  if (typeof ip !== "string") return true;
  var fam = _isIP(ip);
  if (fam === 4) {
    /** @internal The literal is scanned on the delimiter CHARACTER rather than split on a separator
     * string. `String.prototype.split` is specified to look the separator's `Symbol.split` method up
     * and call it, so the separator's prototype chain is part of the operation and capturing `split`
     * does not close it; hard rule 11 bans `split` in lib/ for that reason. MEASURED on Node 24.21,
     * the supported runtime: a hook answering with a public address's octets made this refusal clear
     * for `127.0.0.1` and a request to loopback proceeded. */
    var o = intrinsic.splitChar(ip, 46), a = +o[0], b = +o[1], c = +o[2];
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113);
  }
  if (fam === 6) {
    /** @internal The fold and the index read come from the load-time captures. This classification
     * ADMITS anything inside global unicast, so a replaced `toLowerCase` answering with a
     * global-unicast spelling for a private address turns a refusal into a connection attempt:
     * measured, `fc00::1` folded to `2606:4700::1` was admitted past this blocklist and the request
     * went out. The substitute has to be an address this function admits, or the refusal comes from
     * another rule and the probe measures nothing. */
    var l = intrinsic.toLowerCase(ip);
    if (intrinsic.stringIndexOf(l, "::ffff:") === 0) return true;
    var parts = intrinsic.splitChar(l, 58);
    /** @internal The numeric conversion is captured too. The fold and the split were converted first
     * and this was still live, so `parseInt("fc00", 16)` answering `0x2606` put the address inside
     * global unicode and the refusal was skipped: converting the operations that produce the hextets
     * without the one that reads them leaves the gate exactly as open. */
    var h = intrinsic.parseInt(parts[0], 16);
    if (!(h >= 0x2000 && h <= 0x3fff)) return true;
    var h2 = parts[1] ? intrinsic.parseInt(parts[1], 16) : 0;
    if (h === 0x2002) return true;
    if (h === 0x2001 && h2 < 0x0200) return true;
    if (h === 0x2001 && h2 === 0x0db8) return true;
    if (h === 0x3fff && h2 < 0x1000) return true;
    return false;
  }
  return false;
}

function _blockedAddrErr(hostname, address) {
  var e = new Error("refusing to connect to " + hostname + " -> " + address + " (private / loopback / link-local address blocked)");
  e.pkiBlockedAddress = true;
  return e;
}
function _makeGuardedLookup(lookupFn) {
  return function guardedLookup(hostname, options, callback) {
    lookupFn(hostname, options || intrinsic.create(null), function (err, address, family) {
      if (err) return callback(err);
      /** @internal Each address is read ONCE, the read is what gets classified, and the SNAPSHOT is
       *  what the socket layer is handed. Forwarding the list the resolver returned let the entry be
       *  read again after it was cleared: a `lookup` answering a public address to this check and a
       *  loopback one to the connection reached loopback with `blockPrivateAddresses` set. */
      if (_isArray(address)) {
        var checked = [];
        for (var i = 0; i < address.length; i++) {
          var entry = address[i];
          var one = { address: entry && entry.address, family: entry && entry.family };
          if (_isBlockedIp(one.address)) return callback(_blockedAddrErr(hostname, one.address));
          /** @internal Appended by defining the index. Stored at, the store walks the prototype chain
           *  for a setter, so an accessor there took the checked entry and node read the address it
           *  connects to back from the getter instead: an address this check never saw. */
          _arrPush(checked, one);
        }
        return callback(null, checked);
      }
      if (_isBlockedIp(address)) return callback(_blockedAddrErr(hostname, address));
      return callback(null, address, family);
    });
  };
}
var _guardedLookup = _makeGuardedLookup(nodeDns.lookup);

function _hasSelfSigned(l) {
  for (var i = 0; i + 4 <= l.length; i++) {
    if (_charCodeAt(l, i) === 0x73 && _charCodeAt(l, i + 1) === 0x65 && _charCodeAt(l, i + 2) === 0x6c && _charCodeAt(l, i + 3) === 0x66) {
      if (_strIndexOf(l, "signed", i + 4) === i + 4) return true;
      var mid = _charCodeAt(l, i + 4);
      if (i + 4 < l.length && mid !== 0x0a && mid !== 0x0d && mid !== 0x2028 && mid !== 0x2029 && _strIndexOf(l, "signed", i + 5) === i + 5) return true;
    }
  }
  return false;
}
function _hasWordBounded(l, word) {
  var at = _strIndexOf(l, word);
  while (at !== -1) {
    var before = at === 0 || !_isLowerWordChar(_charCodeAt(l, at - 1));
    var afterI = at + word.length;
    var after = afterI === l.length || !_isLowerWordChar(_charCodeAt(l, afterI));
    if (before && after) return true;
    at = _strIndexOf(l, word, at + 1);
  }
  return false;
}
function _isLowerWordChar(c) { return (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95; }
function _classifyError(e, C) {
  if (e && e.pkiBlockedAddress) return C("blocked-address");
  var s = _stringOf((e && e.code) || "") + " " + _stringOf((e && e.message) || "");
  var l = _toLowerCase(s);
  if (_strIndexOf(l, "protocol_version") !== -1 || _strIndexOf(l, "unsupported_protocol") !== -1 || _strIndexOf(l, "version_too_low") !== -1 ||
      _strIndexOf(l, "wrong_version") !== -1 || _strIndexOf(l, "no_protocols_available") !== -1 || _strIndexOf(l, "inappropriate_fallback") !== -1) return C("tls-floor");
  if (_strIndexOf(l, "cert") !== -1 || _strIndexOf(l, "verify") !== -1 || _strIndexOf(l, "altname") !== -1 || _strIndexOf(l, "hostname") !== -1 ||
      _strIndexOf(l, "depth_zero") !== -1 || _strIndexOf(l, "local_issuer") !== -1 || _strIndexOf(l, "handshake") !== -1 ||
      _hasSelfSigned(l) || _hasWordBounded(l, "ssl") || _hasWordBounded(l, "tls")) return C("server-auth-failed");
  return C("transport-error");
}

function _keySet(names) { var m = _objectCreate(null); for (var i = 0; i < names.length; i++) m[names[i]] = true; return m; }
var PROXY_KEYS = _keySet(["url", "auth", "tls"]);
var PROXY_AUTH_KEYS = _keySet(["scheme", "username", "password", "allowMD5", "allowLegacyQop"]);
var PROXY_DIGEST_KNOBS = ["allowMD5", "allowLegacyQop"];
var PROXY_TLS_KEYS = _keySet(["anchors", "useSystemStore", "servername", "minVersion"]);

function _copyAnchor(a) { return (a !== null && typeof a === "object" && nodeUtil.types.isProxy(a)) ? a : (_isBuffer(a) ? _bufferFrom(a) : a); }
function _noopProxyErr(code, message) { var e = new Error(message); e.code = code; e.isPkiError = true; return e; }
function _copyableRecord(p) {
  if (!guard.identifier.isPlainRecord(p)) return false;
  var proto = _getPrototypeOf(p);
  if (proto !== _objectProto && proto !== null) return false;
  if (Object.getOwnPropertySymbols(p).length !== 0) return false;
  var ownEnumData = 0;
  var names = _getOwnPropertyNames(p);
  for (var i = 0; i < names.length; i++) {
    var d = _getOwnPropertyDescriptor(p, names[i]);
    if (!d.enumerable || d.get || d.set) return false;
    ownEnumData++;
  }
  var readable = guard.identifier.readableNames(p, _noopProxyErr, "transport/bad-proxy", "opts.proxy");
  if (readable.length !== ownEnumData) return false;
  for (var j = 0; j < readable.length; j++) {
    var rd = _getOwnPropertyDescriptor(p, readable[j]);
    if (!rd || !rd.enumerable || rd.get || rd.set) return false;
  }
  return true;
}
function _copyableArray(a) {
  if (a === null || typeof a !== "object" || nodeUtil.types.isProxy(a) || !_isArray(a) || _getPrototypeOf(a) !== _arrayProto) return false;
  if (a.length > constants.LIMITS.PROXY_MAX_TLS_ANCHORS) return false;
  if (Object.getOwnPropertySymbols(a).length !== 0) return false;
  var names = _getOwnPropertyNames(a);
  for (var i = 0; i < names.length; i++) {
    var d = _getOwnPropertyDescriptor(a, names[i]);
    if (d.get || d.set) return false;
  }
  /** @internal Every index has to be the array's OWN. A descriptor walk cannot see a HOLE, so a
   *  sparse list whose gap is answered by an accessor on `Array.prototype` passed this check and
   *  then read a different value at each read: the validation saw one anchor and the conversion
   *  used another. Reading by index is specified to consult the prototype at a hole, which is why
   *  the gap is refused here rather than read carefully later. */
  for (var k = 0; k < a.length; k++) { if (!_hasOwn(a, k)) return false; }
  return true;
}
function snapshotProxy(p) {
  try {
    if (!_copyableRecord(p)) return p;
    var out = guard.identifier.ownOptions(p);
    if (_copyableRecord(p.auth)) out.auth = guard.identifier.ownOptions(p.auth);
    if (_copyableRecord(p.tls)) {
      out.tls = guard.identifier.ownOptions(p.tls);
      var a = p.tls.anchors;
      if (_copyableArray(a)) {
        var copied = [];
        /** @internal Appended by defining the index, for the reason the address list above is: these
         *  are the trust anchors the handshake runs under, and a store consults a setter inherited at
         *  the index. */
        for (var i = 0; i < a.length; i++) _arrPush(copied, _copyAnchor(a[i]));
        out.tls.anchors = copied;
      } else if (typeof a === "string") out.tls.anchors = a;
      else if (a !== null && typeof a === "object" && !nodeUtil.types.isProxy(a) && _isBuffer(a)) out.tls.anchors = _bufferFrom(a);
    }
    return out;
  } catch (_e) {
    // allow:swallow-unverified an input whose introspection throws (a revoked Proxy, a throwing trap) returns unchanged for _validateProxy to refuse
    return p;
  }
}

/** @internal `originHost`, `statedPort` and `scheme` are the values the request path already read off
 *  the parsed origin; they are passed in rather than read again here, so the authority this builds for
 *  the CONNECT target is the same authority the socket options were built from. */
function _validateProxy(request, defaults, E, C, originHost, originStatedPort, originScheme) {
  var rawProxy = request.proxy;
  var proxy = rawProxy !== undefined ? rawProxy : defaults.proxy;
  if (proxy === undefined || proxy === null) return null;
  guard.identifier.assertPlainRecord(proxy, E, C("bad-proxy"), "opts.proxy");
  if (!_copyableRecord(proxy)) throw E(C("bad-proxy"), "opts.proxy must be a plain object with only own enumerable data properties");
  guard.identifier.assertKnownKeys(proxy, PROXY_KEYS, E, C("bad-proxy"), "opts.proxy has an unknown option ");
  if (typeof proxy.url !== "string") throw E(C("bad-proxy"), "opts.proxy.url must be a string, got " + guard.text.showValue(proxy.url));
  var purl;
  try { purl = new _URL(proxy.url); }
  catch (e) { throw E(C("bad-proxy"), "opts.proxy.url did not parse: " + guard.text.showValue(proxy.url), e); }
  var pscheme = _urlProtocol(purl);
  if (pscheme !== "http:" && pscheme !== "https:") throw E(C("bad-proxy"), "opts.proxy.url must be an http or https URL, got " + pscheme);
  if (_urlUsername(purl) || _urlPassword(purl)) throw E(C("bad-proxy"), "opts.proxy.url must not carry credentials in its userinfo; supply opts.proxy.auth over an https proxy");
  var secure = pscheme === "https:";
  if (!secure && proxy.tls !== undefined && proxy.tls !== null) throw E(C("bad-proxy"), "opts.proxy.tls applies only to an https proxy; an http proxy connection is plaintext (a supplied tls policy would be silently ignored)");

  var auth = null;
  if (proxy.auth !== undefined && proxy.auth !== null) {
    if (!secure) throw E(C("proxy-auth-requires-tls"), "proxy credentials cannot be sent over a plaintext http proxy, where the proxy hop would expose them; use an https proxy URL");
    guard.identifier.assertPlainRecord(proxy.auth, E, C("bad-proxy"), "opts.proxy.auth");
    if (!_copyableRecord(proxy.auth)) throw E(C("bad-proxy"), "opts.proxy.auth must be a plain object with only own enumerable data properties");
    guard.identifier.assertKnownKeys(proxy.auth, PROXY_AUTH_KEYS, E, C("bad-proxy"), "opts.proxy.auth has an unknown option ");
    var scheme = proxy.auth.scheme;
    if (scheme !== "basic" && scheme !== "digest") throw E(C("bad-proxy"), "opts.proxy.auth.scheme must be 'basic' or 'digest', got " + guard.text.showValue(scheme));
    if (typeof proxy.auth.username !== "string" || typeof proxy.auth.password !== "string") throw E(C("bad-proxy"), "opts.proxy.auth requires a string username and password");
    for (var ki = 0; ki < PROXY_DIGEST_KNOBS.length; ki++) {
      var kn = PROXY_DIGEST_KNOBS[ki], kv = proxy.auth[kn];
      if (kv === undefined) continue;
      if (scheme !== "digest") throw E(C("bad-proxy"), "opts.proxy.auth." + kn + " applies only to Digest authentication");
      if (typeof kv !== "boolean") throw E(C("bad-proxy"), "opts.proxy.auth." + kn + " must be a boolean, got " + guard.text.showValue(kv));
    }
    if (scheme === "basic" && intrinsic.stringIndexOf(proxy.auth.username, ":") !== -1) throw E(C("bad-proxy"), "a Basic proxy user-id must not contain a colon (RFC 7617 sec. 2)");
    auth = { scheme: scheme, username: proxy.auth.username, password: proxy.auth.password,
      allowMD5: proxy.auth.allowMD5 === true, allowLegacyQop: proxy.auth.allowLegacyQop === true };
  }

  var proxyTls = null;
  if (secure) {
    var ptls = proxy.tls;
    if (ptls !== undefined && ptls !== null) {
      guard.identifier.assertPlainRecord(ptls, E, C("bad-proxy"), "opts.proxy.tls");
      if (!_copyableRecord(ptls)) throw E(C("bad-proxy"), "opts.proxy.tls must be a plain object with only own enumerable data properties");
      guard.identifier.assertKnownKeys(ptls, PROXY_TLS_KEYS, E, C("bad-proxy"), "opts.proxy.tls has an unknown option ");
      if (ptls.servername !== undefined && ptls.servername !== null && typeof ptls.servername !== "string") throw E(C("bad-proxy"), "opts.proxy.tls.servername must be a string");
    }
    /** @internal Taken here, so the value the tunnel is opened under is the one typed above rather
     * than a later read of the caller's record. The door refuses an accessor and refuses a Proxy, so
     * the two reads cannot differ today; holding the value keeps that true without depending on it. */
    var pServername = (ptls && ptls.servername) || null;
    var pAnchors = ptls ? ptls.anchors : undefined;
    if (pAnchors !== undefined && pAnchors !== null && typeof pAnchors === "object" && nodeUtil.types.isProxy(pAnchors)) throw E(C("bad-proxy"), "opts.proxy.tls.anchors must not be a Proxy");
    var pUseSystem = ptls ? ptls.useSystemStore === true : false;
    var pHasAnchors = pAnchors !== undefined && pAnchors !== null && !(_isArray(pAnchors) && pAnchors.length === 0);
    if (!pHasAnchors && !pUseSystem) throw E(C("bad-proxy"), "an https proxy requires explicit tls trust: set proxy.tls.anchors or proxy.tls.useSystemStore");
    if (pHasAnchors) {
      if (_isArray(pAnchors) && !_copyableArray(pAnchors)) throw E(C("bad-proxy"), "opts.proxy.tls.anchors must be a plain array of PEM strings or DER Buffers");
      var pAnchorList = _isArray(pAnchors) ? pAnchors : [pAnchors];
      for (var pai = 0; pai < pAnchorList.length; pai++) {
        var pan = pAnchorList[pai];
        if ((pan !== null && typeof pan === "object" && nodeUtil.types.isProxy(pan)) || (typeof pan !== "string" && !_isBuffer(pan))) throw E(C("bad-proxy"), "opts.proxy.tls.anchors must be a PEM string or a DER Buffer (or an array of them)");
      }
    }
    var pMinVersion = (ptls && ptls.minVersion !== undefined && ptls.minVersion !== null) ? ptls.minVersion : DEFAULT_MIN_VERSION;
    if (pMinVersion !== "TLSv1.2" && pMinVersion !== "TLSv1.3") throw E(C("bad-proxy"), "proxy.tls.minVersion must be 'TLSv1.2' or 'TLSv1.3', got " + guard.text.showValue(pMinVersion));
    var pCa = [];
    /** @internal `concatList`, not the captured `concat`: `Array.prototype.concat` is specified to
     * consult `Symbol.isConcatSpreadable` on each argument, so capturing the method leaves the
     * SPREADING replaceable and an inherited hook replaced a validated anchor with another one in
     * the CONNECT options. `concatList` copies own indexes and appends own indexes. */
    if (pHasAnchors) pCa = _concatList(pCa, _pemifyAnchors(pAnchors));
    if (pUseSystem) pCa = _concatList(pCa, _systemCa());
    proxyTls = { ca: pCa.length ? pCa : undefined, minVersion: pMinVersion, servername: pServername };
  }

  var originAuthHost = _isIP(originHost) === 6 ? "[" + originHost + "]" : originHost;
  var phost = _stripIpv6Brackets(_urlHostname(purl));
  /** @internal The CONNECT target is the origin's own authority, so an origin URL that states no
   * port takes the default for the origin's scheme, not the proxy's. Defaulting it to 443 opens
   * the tunnel to a port an `http:` origin does not listen on. */
  var originPort = originStatedPort || (originScheme === "http:" ? 80 : 443);
  var pport = _urlPort(purl);
  return { secure: secure, host: phost, port: pport ? +pport : (secure ? 443 : 80), originHost: originHost, originAuthority: originAuthHost + ":" + originPort, auth: auth, proxyTls: proxyTls };
}

function _basicProxyHeader(auth) {
  return "Basic " + _bufToString(_bufferFrom(auth.username + ":" + auth.password, "utf8"), "base64");
}

/** @internal The `Proxy-Authorization` value answering a proxy's `Proxy-Authenticate: Digest` challenge
 * (RFC 7616 sec. 3.3, RFC 9110 sec. 11.7.1). The challenge grammar is the one the origin uses, so the
 * shipped parser reads it unchanged; a CONNECT hashes the method `CONNECT` over the authority-form target
 * the request line carries (RFC 9112 sec. 3.2.3), which is the pair the proxy checks it against. */
function _digestProxyCredential(headers, pinfo, C, E) {
  var httpDigest = require("./http-digest");   // allow:inline-require -- circular load: http-digest -> schema-pkix -> ct -> this module
  /** @internal Captured: this is the challenge the digest credential is computed against, so the
   * conversion decides which parameters, and which algorithm, the response is built for. */
  var offered = intrinsic.String((headers && headers["proxy-authenticate"]) || "");
  var policy = {
    allowMD5: pinfo.auth.allowMD5, allowLegacyQop: pinfo.auth.allowLegacyQop,
    codes: {
      unsupportedAlgorithm: C("proxy-digest-unsupported-algorithm"), weakAlgorithm: C("proxy-digest-weak-algorithm"),
      noQop: C("proxy-digest-no-qop"), badChallenge: C("proxy-digest-bad-challenge"),
    },
  };
  var challenge = httpDigest.parseChallenge(offered, E, C("proxy-digest-bad-challenge"), policy);
  if (!challenge) {
    throw E(C("proxy-auth-required"), "opts.proxy.auth.scheme is \"digest\" but the proxy offered no usable Digest challenge: " + guard.text.showValue(offered));
  }
  return httpDigest.answer(challenge, {
    method: "CONNECT", uri: pinfo.originAuthority,
    username: pinfo.auth.username, password: pinfo.auth.password, nc: 1, policy: policy,
  }, E);
}
function _proxyErrorClass(e, C) {
  var code = _stringOf((e && e.code) || "");
  if (_strIndexOf(code, "ERR_TLS") === 0 || _strIndexOf(code, "ERR_SSL") === 0 || _strIndexOf(code, "SSL") !== -1 ||
      _strIndexOf(code, "CERT") !== -1 || _strIndexOf(code, "SELF_SIGNED") !== -1 || _strIndexOf(code, "VERIFY") !== -1 ||
      _strIndexOf(code, "_SIGNATURE") !== -1 || _strIndexOf(code, "ALTNAME") !== -1) return C("proxy-tls-failed");
  return C("proxy-connect-failed");
}

/**
 * @primitive  pki.transport.https
 * @signature  pki.transport.https(defaults?) -> transport
 * @since      0.3.16
 * @status     stable
 * @spec       RFC 7030, RFC 8996
 * @defends    tls-downgrade (CWE-757), server-impersonation (CWE-297), response-flooding (CWE-770), ssrf (CWE-918)
 * @related    pki.est.cacerts, pki.est.simpleenroll
 *
 * Build a fail-closed `node:https` transport: `transport(request) -> Promise<{ status,
 * headers, body }>`. `defaults` binds a `tls` policy (`anchors` -> the node `ca`;
 * `useSystemStore` to opt into the bundled roots; `cert`/`key` for mutual TLS;
 * `minVersion` 'TLSv1.2' (default) or 'TLSv1.3'; `servername`; a `checkServerIdentity`
 * that may only tighten) plus `timeout` and `maxResponseBytes` budgets. Each `request`
 * ({ method, url, headers, body, tls, timeout, maxResponseBytes }) may override them.
 * A non-https URL (`transport/insecure-url`), a request with neither an explicit
 * anchor nor `useSystemStore` (`transport/no-trust-anchors`), a body over the streaming
 * cap (`transport/response-too-large`), a stalled socket (`transport/timeout`), a below
 * -floor negotiation (`transport/tls-floor`), or a failed server authentication
 * (`transport/server-auth-failed`) all fail closed; `rejectUnauthorized` is always on.
 * A protocol client passes its own error factory (`defaults.E`) + `defaults.errPrefix`
 * to surface domain codes (`est/...`). The transport owns no HTTP/redirect/auth
 * semantics; those live in the message layer that consumes the response triple.
 *
 * @opts
 *   - `tls.anchors` -- Explicit trust anchor(s): a DER/PEM Buffer, an array, or PEM string(s) (node `ca`).
 *   - `tls.useSystemStore` -- boolean; the one opt-in to node's bundled CA store (default false).
 *   - `tls.cert` / `tls.key` -- client certificate + key for mutual-TLS re-enrollment.
 *   - `tls.minVersion` -- 'TLSv1.2' (default) or 'TLSv1.3'; never below the floor.
 *   - `tls.servername` / `tls.checkServerIdentity` -- SNI + RFC 6125 identity; may tighten, never disable.
 *   - `timeout` -- ms (default C.TIME.seconds(30)); `maxResponseBytes` -- default LIMITS.HTTP_MAX_RESPONSE_BYTES, tightenable downward only.
 *   - `blockPrivateAddresses` -- boolean; when true, an IP-literal host OR a hostname resolving to a private / loopback / link-local address is refused (`transport/blocked-address`), and a resolved address is pinned for the connection. For fetching an untrusted-certificate URL (AIA caIssuers); default false. It cannot be combined with `proxy`: a forward proxy resolves the origin itself, so the transport cannot enforce the block on it, and the combination is refused (`transport/bad-proxy`).
 *   - `proxy` -- reach the https origin through a forward HTTP proxy: `{ url: "http://proxy:3128" | "https://proxy:3128", auth?: { scheme: "basic" | "digest", username, password, allowMD5?, allowLegacyQop? }, tls?: { anchors, useSystemStore, servername, minVersion } }`. A CONNECT tunnel is opened to the proxy and the origin's TLS is negotiated inside it under the identical origin trust policy, so the proxy cannot read the origin's encrypted session or substitute the origin certificate. `auth` requires an `https://` proxy: the credentials ride the authenticated TLS-to-proxy channel (verified against `proxy.tls`, which is required for an https proxy), so a plaintext `http://` proxy carrying `auth` is refused (`transport/proxy-auth-requires-tls`) rather than exposing them to the proxy hop. An `http://` proxy is tunnel-only. Basic (RFC 7617) sends its credential on the first CONNECT. Digest (RFC 7616) answers the proxy's `Proxy-Authenticate` challenge on a `407`, hashing the method `CONNECT` over the authority-form target, and answers exactly once: a proxy that repeats its challenge has rejected the credential. The Digest policy is the one the origin verbs use, so MD5 and a challenge carrying no `qop` are refused unless `allowMD5` / `allowLegacyQop` says otherwise (`transport/proxy-digest-weak-algorithm`, `transport/proxy-digest-unsupported-algorithm`, `transport/proxy-digest-no-qop`, `transport/proxy-digest-bad-challenge`). A `407` is `transport/proxy-auth-failed` (credentials rejected) or `transport/proxy-auth-required` (none supplied, or none of the offered schemes is the configured one); a proxy certificate that does not verify is `transport/proxy-tls-failed`; a non-2xx CONNECT is `transport/proxy-connect-failed`; a malformed option is `transport/bad-proxy`. Off by default (a direct connection).
 * @example
 *   var t = pki.transport.https({ tls: { anchors: [caPem] } });
 *   var res = await t({ method: "GET", url: "https://ca.example/.well-known/est/cacerts" });
 *   res.status;   // 200
 */
function httpsTransport(defaults) {
  defaults = defaults || intrinsic.create(null);
  /** @internal Each of these is read ONCE, into the value both the test and the use see, and the
   *  error factory a refusal is built from is one of them. */
  var rawE = defaults.E;
  var E = typeof rawE === "function" ? rawE : defaultE;
  var prefix = defaults.errPrefix || "transport";
  function C(name) { return prefix + "/" + name; }
  /** @internal No prototype where no TLS was bound: an empty object literal inherits from
   *  `Object.prototype`, so a value installed there would answer for a setting nobody set, and one of
   *  the settings read from this record is the opt-in that turns away an unpinned server. */
  var rawDefaultTls = defaults.tls;
  var tlsDefaults = rawDefaultTls != null ? rawDefaultTls : intrinsic.create(null);

  function _prepare(request) {
    var url;
    try { url = new _URL(_stringOf(request.url)); }
    catch (e) { throw E(C("bad-url"), "the request URL did not parse: " + _stringOf(request.url), e); }
    /** @internal https is the floor, and `request.allowPlaintextHttp` is the one thing that moves
     * it, per request and never as a default. It exists for the two objects whose integrity does
     * not come from the transport: a CRL and an OCSP response are signed, their signatures are
     * verified after the fetch, and an https-only revocation fetch needs the responder's own
     * certificate validated first, which is the loop the plaintext form exists to break. Nothing
     * else in this toolkit sets it. Every other guard stays: the address checks, the size cap, the
     * timeout, and the refusal to follow a redirect, which is what would otherwise turn one
     * plaintext hop into a downgrade of the next. */
    var plaintextAllowed = request.allowPlaintextHttp === true;
    /** @internal Read ONCE, through the captured accessor, and every decision below made from that
     *  string. The scheme decides whether the request is allowed at all, whether an anchor is
     *  required and which port it defaults to, so a prototype whose getter answers each read
     *  differently would have those three agree on nothing. */
    var scheme = _urlProtocol(url);
    if (scheme !== "https:" && !(plaintextAllowed && scheme === "http:")) {
      throw E(C("insecure-url"), "transport requires https (RFC 7030 sec. 3.3), got " + scheme);
    }

    /** @internal Each setting is read ONCE, into the value the presence test and the use share. Read
     *  twice, the second read decided: a `tls` answering an object to the test and nothing to the use
     *  left `reqTls` undefined, and the anchor read on the next line threw a raw TypeError out of a
     *  public verb instead of this module's typed refusal. */
    var rawReqTls = request.tls;
    var reqTls = rawReqTls != null ? rawReqTls : intrinsic.create(null);
    var rawAnchors = reqTls.anchors;
    var anchors = rawAnchors !== undefined ? rawAnchors : tlsDefaults.anchors;
    var rawUseSystem = reqTls.useSystemStore;
    var useSystem = (rawUseSystem !== undefined ? rawUseSystem : tlsDefaults.useSystemStore) === true;
    var hasAnchors = anchors !== undefined && anchors !== null && !(_isArray(anchors) && anchors.length === 0);
    /** @internal A trust anchor is what makes an https server identifiable, so a request with
     * neither an anchor nor the system store is refused rather than left unpinned. A plaintext hop
     * negotiates no certificate, so there is nothing for an anchor to pin; what protects the object
     * fetched over one is its own signature, checked after the fetch by the verb that asked. */
    if (scheme === "https:" && !hasAnchors && !useSystem) {
      throw E(C("no-trust-anchors"), "no explicit trust anchor and useSystemStore not set -- refusing an unpinned server (RFC 7030 sec. 3.6)");
    }

    var rawTimeout = request.timeout;
    var timeout = _budget(rawTimeout !== undefined ? rawTimeout : defaults.timeout, "timeout", DEFAULT_TIMEOUT, MAX_TIMEOUT, E, C("bad-input"));
    var rawMaxBytes = request.maxResponseBytes;
    var maxBytes = _budget(rawMaxBytes !== undefined ? rawMaxBytes : defaults.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, E, C("bad-input"));

    var minVersion = reqTls.minVersion || tlsDefaults.minVersion || DEFAULT_MIN_VERSION;
    if (minVersion !== "TLSv1.2" && minVersion !== "TLSv1.3") throw E(C("bad-input"), "tls.minVersion must be 'TLSv1.2' or 'TLSv1.3' (never below the floor), got " + minVersion);

    var body = request.body;
    var bodyIsFn = typeof body === "function";
    if (!bodyIsFn && guard.bytes.isByteSource(body)) body = guard.bytes.source(body, E, C("bad-input"), "the request body");

    var reqHeaders = guard.identifier.ownOptions(request.headers);
    _arrForEach(_objectKeys(reqHeaders), function (k) { var lk = _toLowerCase(k); if (lk === "proxy-authorization" || lk === "proxy-connection") delete reqHeaders[k]; });
    if (bodyIsFn) {
      _arrForEach(_objectKeys(reqHeaders), function (k) { var lk = _toLowerCase(k); if (lk === "content-length" || lk === "transfer-encoding" || lk === "expect") delete reqHeaders[k]; });
    } else if (body != null && body !== "") {
      _arrForEach(_objectKeys(reqHeaders), function (k) { var lk = _toLowerCase(k); if (lk === "content-length" || lk === "transfer-encoding") delete reqHeaders[k]; });
      reqHeaders["Content-Length"] = _byteLength(body);
    }

    var host = _stripIpv6Brackets(_urlHostname(url));
    var plaintext = scheme === "http:";
    var statedPort = _urlPort(url);
    var options = {
      method: request.method || "GET",
      hostname: host,
      port: statedPort || (plaintext ? 80 : 443),
      path: _urlPathname(url) + _urlSearch(url),
      headers: reqHeaders,
      minVersion: minVersion,
      rejectUnauthorized: true,
      agent: false,
    };
    var rawCert = reqTls.cert, rawKey = reqTls.key;
    var cert = rawCert !== undefined ? rawCert : tlsDefaults.cert;
    var key = rawKey !== undefined ? rawKey : tlsDefaults.key;
    /** @internal The hook is read once and that one value is both type-checked and installed. Read
     *  twice, the type check passed on a function and something else was installed as the identity
     *  check this connection is accepted on. The transport's default is read ONLY where the request
     *  supplied no function of its own, because a per-request hook overrides it and reading it anyway
     *  runs an accessor the request opted out of. */
    var rawCsi = reqTls.checkServerIdentity;
    var callerCsi = null;
    if (typeof rawCsi === "function") callerCsi = rawCsi;
    else {
      var rawDefaultCsi = tlsDefaults.checkServerIdentity;
      if (typeof rawDefaultCsi === "function") callerCsi = rawDefaultCsi;
    }
    var rawSni = reqTls.servername;
    var sni = (rawSni !== undefined ? rawSni : tlsDefaults.servername) || host;
    /** @internal Typed here, the way `opts.proxy.tls.servername` is typed on the proxy arm. The value
     * is read three times after this point and each read is a separate conversion: once to decide it
     * is not an address literal, once by the TLS layer for the name sent in the handshake, and once
     * as `idHost` for the name the server certificate is matched against. A value answering a
     * different string per read sends one name and verifies another. */
    if (typeof sni !== "string") throw E(C("bad-input"), "tls.servername must be a string, got " + guard.text.showValue(sni));
    if (sni && !_isIP(sni)) options.servername = sni;
    var caList = [];
    if (hasAnchors) caList = _concatList(caList, _pemifyAnchors(anchors));
    if (useSystem) caList = _concatList(caList, _systemCa());
    if (caList.length) options.ca = caList;
    if (cert) options.cert = cert;
    if (key) options.key = key;
    if (callerCsi) {
      options.checkServerIdentity = function (host, cert2) {
        var baseErr = _checkServerIdentity(host, cert2);
        if (baseErr) return baseErr;
        return callerCsi(host, cert2);
      };
    } else {
      /** @internal With no caller hook, the option is set to the CAPTURE rather than left out. Left
       * out, node's own TLS stack looks the function up on its module export when the handshake
       * completes, so a replacement there answers the identity question and a certificate issued to
       * another host is accepted. Measured: with this absent, a request asking for a name the
       * server's certificate does not carry was admitted. The function is node's own default, taken
       * at load, so the verdict is the one it would have reached anyway. */
      options.checkServerIdentity = _checkServerIdentity;
    }
    var proxyInfo;
    try { proxyInfo = _validateProxy(request, defaults, E, C, host, statedPort, scheme); }
    catch (e) {
      var typedProxyError = false;
      try {
        var ec = (e instanceof Error) && !nodeUtil.types.isProxy(e) ? e.code : undefined;
        typedProxyError = ec === C("bad-proxy") || ec === C("proxy-auth-requires-tls");
      } catch (_ie) { /* allow:swallow-unverified reading .code on a hostile error object can throw; treat any such failure as untyped */ }
      if (typedProxyError) throw e;
      throw E(C("bad-proxy"), "opts.proxy could not be validated", e);
    }
    var rawBlockPrivate = request.blockPrivateAddresses;
    var blockPrivate = (rawBlockPrivate !== undefined ? rawBlockPrivate : defaults.blockPrivateAddresses) === true;
    if (blockPrivate && proxyInfo) throw E(C("bad-proxy"), "blockPrivateAddresses cannot be enforced through a forward proxy, which resolves the origin itself and would reach a private origin the transport never checks; use a direct connection for a private-address-blocked fetch");
    if (blockPrivate) {
      if (_isBlockedIp(host)) throw E(C("blocked-address"), "refusing to connect to the private / loopback / link-local address literal " + host);
      options.lookup = _guardedLookup;
    }

    return { options: options, timeout: timeout, maxBytes: maxBytes, body: body, proxy: proxyInfo, blockPrivate: blockPrivate, callerCsi: callerCsi, plaintext: plaintext };
  }

  var _transportFn = function transport(request) {
    request = request || intrinsic.create(null);
    var prep;
    try { prep = _prepare(request); }
    catch (e) { return _promiseReject(_Promise, e); }
    return new _Promise(function (resolve, reject) {
      var settled = false;
      var req = null;
      var creq = null;
      var tunnelSocket = null;
      var timer = null;
      function clearTimer() { if (timer) { clearTimeout(timer); timer = null; } }
      function _quietDestroy(x) {
        // allow:swallow-unverified destroy() is idempotent and does not throw in practice; a
        try { if (x) x.destroy(); } catch (_e) { }
      }
      function _settleReject(err) {
        if (settled) return;
        settled = true;
        clearTimer();
        _quietDestroy(req);
        _quietDestroy(creq);
        _quietDestroy(tunnelSocket);
        reject(err);
      }
      function fail(code, msg, cause) { _settleReject(E(code, msg, cause)); }
      timer = setTimeout(function () { fail(C("timeout"), "the request timed out after " + prep.timeout + "ms"); }, prep.timeout);

      function issue(options) {
        try {
          /** @internal A plaintext request goes through `node:http`, which has no TLS options to
           * ignore; `prep.plaintext` is set only where the scheme check let `http:` through. */
          /** @internal The request function is the one bound at load, not the property looked up on
           * the module when the request is made: a replacement installed afterwards sent a request
           * prepared for one host to another and handed the caller that server's response. */
          var client = prep.plaintext ? nodeHttp : nodeHttps;
          var clientRequest = prep.plaintext ? _httpRequest : _httpsRequest;
          /** @internal The socket is built here rather than by the agent node makes for the request.
           * `agent: false` still leaves the construction on the agent prototype, so a replacement
           * installed after load returned a connection to another destination and the request went
           * out over it: measured, an `https:` request under `blockPrivateAddresses` reached a local
           * plaintext listener, presented no certificate, and its body reached the caller. The
           * options are the ones node computed for this hop, forwarded unchanged, so every TLS
           * setting the request carries still applies; only the function that opens the socket is
           * this module's. The tunnel path already supplies its own and keeps it. */
          if (options.createConnection === undefined) {
            options.createConnection = prep.plaintext
              ? function (opts) { return intrinsic.apply(_netConnect, nodeNet, [opts]); }
              : function (opts) { return intrinsic.apply(_tlsConnect, nodeTls, [opts]); };
          }
          /** @internal `agent: false` is NOT no agent: node builds one from the default agent's
           * constructor and that agent's own builder opens the socket, so the builder above was never
           * reached. Left unset with a builder present, node skips the agent altogether, which is the
           * same no-pooling behavior `agent: false` was there for. */
          options.agent = undefined;
          req = intrinsic.apply(clientRequest, client, [options, function (res) {
            var tlsInfo = _tlsInfo(res.socket);
            /** @internal Captured for consistency with the rest of the file, not because this gates
             * anything: an understated `content-length` only skips this EARLY refusal, and the cap is
             * enforced below on the bytes actually counted as they arrive. */
            var declared = intrinsic.parseInt((res.headers || intrinsic.create(null))["content-length"], 10);
            if (intrinsic.numberIsFinite(declared) && declared > prep.maxBytes) { fail(C("response-too-large"), "the declared content-length " + declared + " exceeds the " + prep.maxBytes + "-byte cap (RFC 7030 sec. 6)"); return; }
            var buf = _bufferAllocUnsafe(0);
            var len = 0;
            var total = 0;
            res.on("data", function (chunk) {
              /** @internal The arriving chunk is measured ONCE, from its bytes rather than from a
               * `length` property. Read four times off the chunk, a value answering one size to the
               * cap and another to the accounting resolved a response LONGER than the bytes that
               * arrived and longer than the cap allowed: measured, eight bytes under a cap of eight
               * resolved as sixteen. `sizeOf` reads the view's own byte length. */
              var n = intrinsic.sizeOf(chunk);
              total += n;
              if (total > prep.maxBytes) { fail(C("response-too-large"), "the response exceeded the " + prep.maxBytes + "-byte cap (RFC 7030 sec. 6)"); return; }
              if (len + n > buf.length) {
                var want = _mathMin(prep.maxBytes, _mathMax(buf.length ? buf.length * 2 : 8192, len + n));
                var grown = _bufferAllocUnsafe(want);
                /** @internal The bytes already received are moved, and the arriving chunk is placed,
                 * through the typed-array write bound at load. `Buffer.prototype.copy` read off the
                 * prototype decided what the response body holds: replaced after load, a response
                 * that arrived as one value reached the caller as another. */
                _taSet(grown, intrinsic.byteSlice(buf, 0, len), 0);
                buf = grown;
              }
              _taSet(buf, chunk, len);
              len += n;
            });
            res.on("end", function () {
              if (settled) return;
              settled = true;
              clearTimer();
              var lower = guard.header.lowerCased(res.headers);
              resolve({
                status: res.statusCode,
                headers: lower,
                /** @internal The body is allocated at the counted length and written through the
                 *  typed-array write, so neither the length nor the bytes come from an operation a
                 *  replacement answers. Two earlier spellings were both steerable: a typed array's
                 *  `subarray` builds its result through the SPECIES constructor, and `Buffer.from`
                 *  handed an object reads that object's `valueOf` and `length`, which decided both
                 *  what the body held and how long it was: measured, a response of eight bytes came
                 *  back as 64 under a `maxResponseBytes` of 8. `byteSlice` reads the backing buffer,
                 *  the byte offset and the length directly and builds the view itself. */
                body: _bodyCopy(buf, len),
                tls: tlsInfo,
              });
            });
            res.on("error", function (e) { fail(C("transport-error"), "the response stream failed", e); });
          }]);
          req.on("error", function (e) { fail(_classifyError(e, C), "the request failed: " + ((e && e.message) || _stringOf(e)), e); });
          if (typeof prep.body === "function") {
            req.once("socket", function (socket) {
              function _writeBoundBody() {
                if (settled) return;
                var info = _tlsInfo(socket);
                _promiseResolve(_Promise, undefined).then(function () { return prep.body(info); }).then(function (b) {
                  if (settled) return;
                  try {
                    if (guard.bytes.isByteSource(b)) b = guard.bytes.source(b, E, C("bad-input"), "the channel-binding body");
                    else if (typeof b !== "string") { fail(C("bad-input"), "the request body callback must return bytes or a string; a missing return, null, or any other value is refused"); return; }
                  } catch (ve) { _settleReject(ve); return; }
                  try {
                    if (b !== "") { req.setHeader("Content-Length", _byteLength(b)); req.write(b); }
                    req.end();
                  } catch (e2) { fail(C("transport-error"), "the request body could not be written: " + ((e2 && e2.message) || _stringOf(e2)), e2); }
                }, function (e) { fail(C("transport-error"), "the channel-binding body callback failed", e); });
              }
              if (socket.getFinished && socket.getFinished()) { _writeBoundBody(); return; }
              socket.once("secureConnect", _writeBoundBody);
            });
          } else {
            if (prep.body != null && prep.body !== "") req.write(prep.body);
            req.end();
          }
        } catch (e) { fail(C("transport-error"), "the request could not be initiated: " + ((e && e.message) || _stringOf(e)), e); }
      }

      if (!prep.proxy) { issue(prep.options); return; }

      var pinfo = prep.proxy;
      /** @internal The client counts its own attempts. A 407 is answered once, from the challenge the proxy
       * sent; a proxy that answers the credentialed CONNECT with another 407 has rejected the credential,
       * and repeating its challenge cannot obtain a further attempt. */
      var digestAnswered = false;
      var cr, done;

      function issueConnect(credential) {
        var pheaders = _objectAssign(_objectCreate(null), { Host: pinfo.originAuthority, Connection: "keep-alive" });
        if (credential) pheaders["Proxy-Authorization"] = credential;
        /** @internal The CONNECT socket is opened the same way the request's is, and for the same
         * reason: `agent: false` leaves the construction on the agent prototype, where a replacement
         * can return a raw socket in place of the proxy's TLS connection. On this path that costs
         * more than a redirected request, because the CONNECT carries `Proxy-Authorization`. */
        var connectOpts = { host: pinfo.host, port: pinfo.port, method: "CONNECT", path: pinfo.originAuthority, headers: pheaders };
        try {
          if (pinfo.secure) {
            connectOpts.ca = pinfo.proxyTls.ca;
            connectOpts.rejectUnauthorized = true;
            connectOpts.minVersion = pinfo.proxyTls.minVersion;
            var pIdentity = pinfo.proxyTls.servername || pinfo.host;
            connectOpts.servername = (pIdentity && !_isIP(pIdentity)) ? pIdentity : "";
            connectOpts.checkServerIdentity = function (host, cert) { return _checkServerIdentity(pIdentity, cert); };
            connectOpts.createConnection = function (opts) { return intrinsic.apply(_tlsConnect, nodeTls, [opts]); };
            cr = intrinsic.apply(_httpsRequest, nodeHttps, [connectOpts]);
          } else {
            connectOpts.createConnection = function (opts) { return intrinsic.apply(_netConnect, nodeNet, [opts]); };
            cr = intrinsic.apply(_httpRequest, nodeHttp, [connectOpts]);
          }
        } catch (e) { fail(C("proxy-connect-failed"), "the CONNECT request could not be initiated: " + ((e && e.message) || _stringOf(e)), e); return; }
        creq = cr;
        done = false;
        cr.on("connect", function (res, socket) { onProxyResponse(res, socket); });
        cr.on("response", function (res) {
          // allow:swallow-unverified draining the proxy error body is best-effort; the verdict is the status
          res.on("data", function () { });
          res.on("error", function () { });
          res.on("end", function () { });
          onProxyResponse(res, null);
        });
        cr.on("error", function (e) { fail(pinfo.secure ? _proxyErrorClass(e, C) : C("proxy-connect-failed"), "the CONNECT request failed: " + ((e && e.message) || _stringOf(e)), e); });
        cr.end();
      }

      function onProxyResponse(res, socket) {
        if (done) { if (socket) _quietDestroy(socket); return; }
        done = true;
        if (settled) { if (socket) _quietDestroy(socket); return; }
        var sc = res.statusCode;
        if (socket && sc >= 200 && sc < 300) {
          tunnelSocket = socket;
          creq = null;
          socket.on("error", function (e) { fail(_classifyError(e, C), "the tunnel socket failed: " + ((e && e.message) || _stringOf(e)), e); });
          var idHost = prep.options.servername || pinfo.originHost;
          /** @internal A plaintext origin speaks HTTP over the tunnel the CONNECT opened, so the
           * connection the request is issued on is that socket. Handing back a TLS wrapper would
           * start a handshake against a server that does not speak TLS. */
          if (prep.plaintext) {
            issue(_objectAssign({}, prep.options, { createConnection: function () { return socket; } }));
            return;
          }
          issue(_objectAssign({}, prep.options, {
            createConnection: function () {
              return intrinsic.apply(_tlsConnect, nodeTls, [{
                socket: socket,
                host: prep.options.hostname,
                servername: prep.options.servername,
                ca: prep.options.ca,
                minVersion: prep.options.minVersion,
                rejectUnauthorized: true,
                checkServerIdentity: function (host, cert) {
                  var baseErr = _checkServerIdentity(idHost, cert);
                  if (baseErr) return baseErr;
                  return prep.callerCsi ? prep.callerCsi(idHost, cert) : undefined;
                },
                cert: prep.options.cert,
                key: prep.options.key,
              }]);
            },
          }));
          return;
        }
        if (socket) _quietDestroy(socket);
        if (sc === 407) {
          if (pinfo.auth && pinfo.auth.scheme === "digest" && !digestAnswered) {
            digestAnswered = true;
            var credential;
            try { credential = _digestProxyCredential(res.headers, pinfo, C, E); }
            catch (e) { fail(e.code || C("proxy-auth-failed"), e.message, e); return; }
            issueConnect(credential);
            return;
          }
          fail(C(pinfo.auth ? "proxy-auth-failed" : "proxy-auth-required"), pinfo.auth ? "the proxy rejected the supplied credentials (HTTP 407)" : "the proxy requires authentication; supply proxy.auth over an https proxy (HTTP 407)");
          return;
        }
        fail(C("proxy-connect-failed"), "the proxy answered CONNECT with HTTP " + sc);
      }

      issueConnect(pinfo.auth && pinfo.auth.scheme === "basic" ? _basicProxyHeader(pinfo.auth) : null);
    });
  };
  _transportFn.blocksPrivateAddresses = true;

  /** @internal peerChain negotiates TLS and hands back the channel without sending a request. It
   * prepares the connection through the SAME `_prepare` the request path uses, so the anchors, the
   * SNI, the version floor, the identity hook, the private-address block and the URL scheme gate are
   * one policy with two entry points rather than two policies. `tls.connect` takes `host` where
   * `https.request` takes `hostname`, and ignores the method, path and headers `_prepare` also
   * builds. A proxy is refused rather than bypassed: tunnelling belongs to the request path, and
   * connecting directly while a proxy is configured would reach an origin the caller asked not to
   * reach directly. */
  _transportFn.peerChain = function peerChain(request) {
    request = request || intrinsic.create(null);
    var prep;
    try { prep = _prepare({
      url: request.url,
      method: "GET",
      tls: request.tls,
      timeout: request.timeout,
      blockPrivateAddresses: request.blockPrivateAddresses,
      allowPlaintextHttp: false,
      proxy: request.proxy,
    }); }
    catch (e) { return _promiseReject(_Promise, e); }
    if (prep.proxy) {
      return _promiseReject(_Promise, E(C("bad-proxy"),
        "peerChain opens a direct connection and does not tunnel; fetch through a proxy with the request verb"));
    }
    var o = prep.options;
    var connectOpts = {
      host: o.hostname, port: o.port, minVersion: o.minVersion,
      rejectUnauthorized: o.rejectUnauthorized,
    };
    if (o.servername !== undefined) connectOpts.servername = o.servername;
    if (o.ca !== undefined) connectOpts.ca = o.ca;
    if (o.cert !== undefined) connectOpts.cert = o.cert;
    if (o.key !== undefined) connectOpts.key = o.key;
    if (o.checkServerIdentity !== undefined) connectOpts.checkServerIdentity = o.checkServerIdentity;
    if (o.lookup !== undefined) connectOpts.lookup = o.lookup;

    return new _Promise(function (resolve, reject) {
      var settled = false;
      var socket;
      var timer = null;
      function done(fn, arg) {
        if (settled) return;
        settled = true;
        if (timer !== null) { clearTimeout(timer); timer = null; }
        try { if (socket) socket.destroy(); } catch (_de) { /* allow:swallow-unverified the socket is being abandoned either way */ }
        fn(arg);
      }
      try { socket = intrinsic.apply(_tlsConnect, nodeTls, [connectOpts]); }
      catch (e) {
        reject(E(_classifyError(e, C), "the TLS connection failed: " + e.message, e));
        return;
      }
      /** @internal The budget is an ABSOLUTE deadline, the same timer the request path above uses, and not
       *  `socket.setTimeout`: that one bounds INACTIVITY, so what it measures is the gap between bytes
       *  rather than the elapsed time a caller asked to be bounded by. A peer that keeps the socket busy
       *  without completing the handshake is the case the two differ on. The socket inactivity timeout is
       *  kept as well, since it ends a connection that goes silent sooner than the deadline would. */
      timer = setTimeout(function () {
        done(reject, E(C("timeout"), "the TLS handshake did not complete within " + prep.timeout + "ms"));
      }, prep.timeout);
      socket.setTimeout(prep.timeout, function () {
        done(reject, E(C("timeout"), "the TLS handshake did not complete within " + prep.timeout + "ms"));
      });
      socket.once("secureConnect", function () {
        var info = _tlsInfo(socket);
        info.peerChain = _peerChain(socket);
        done(resolve, info);
      });
      socket.once("error", function (e) {
        var code = _classifyError(e, C);
        done(reject, E(code || C("tls-failed"), "the TLS connection failed: " + e.message, e));
      });
    });
  };

  return _transportFn;
}

/**
 * @primitive  pki.transport.peerChain
 * @signature  pki.transport.peerChain(request, defaults?) -> Promise<channel>
 * @since      0.8.32
 * @status     stable
 * @spec       RFC 8446, RFC 6125
 * @defends    server-impersonation (CWE-297), tls-downgrade (CWE-757), ssrf (CWE-918)
 * @related    pki.transport.https, pki.path.validate
 *
 * Negotiate TLS with an endpoint and return the channel it established, without sending a
 * request: `{ protocol, cipher, peerCertificate, peerChain, tlsUnique, tlsExporter }`.
 * `peerChain` is the chain the session resolved as DER, leaf first, walked up from the peer
 * certificate and stopping at the one that issues itself. It is not a record of what crossed the
 * wire: the runtime completes the chain from the trust anchors in scope, so an endpoint that sends
 * only its leaf still yields the entries above it, and those came from the configured anchors.
 * Treat the list as the chain this session built, and read `peerCertificate` for the one
 * certificate the endpoint certainly sent. Nothing reaches the application behind the endpoint,
 * which is the difference from making a request for the same purpose.
 *
 * The connection is prepared by the same code `pki.transport.https` prepares a request with,
 * so the trust anchors, the SNI, the version floor, the `checkServerIdentity` hook, the
 * private-address block and the https-only rule are one policy rather than a second copy of
 * one. A request with neither an explicit anchor nor `useSystemStore` is refused
 * (`transport/no-trust-anchors`) before any socket is opened, and an endpoint whose chain does
 * not build to the configured anchors, or whose name does not match the URL, is refused
 * (`transport/server-auth-failed`). A configured proxy is refused (`transport/bad-proxy`)
 * rather than bypassed, since connecting directly would reach an origin the caller asked to
 * reach through the proxy.
 *
 * **A chain this returns is not a validated one.** The handshake checked that it builds to a
 * configured anchor and matches the name in the URL, and checked no revocation status and no
 * policy. `pki.path.validate` is what validates a path.
 *
 * @example
 *   var channel = await pki.transport.peerChain(
 *     { url: "https://example.com/" }, { tls: { useSystemStore: true } });
 *   channel.peerChain.length;                                  // the chain the session resolved
 *   pki.schema.x509.parse(channel.peerChain[0]).subject.dn;    // the leaf's subject
 *   channel.peerCertificate;                                   // the one certificate the endpoint sent
 */
function peerChain(request, defaults) { return httpsTransport(defaults || intrinsic.create(null)).peerChain(request); }

module.exports = { https: httpsTransport, peerChain: peerChain, isBlockedIp: _isBlockedIp, _makeGuardedLookup: _makeGuardedLookup, MAX_TIMEOUT: MAX_TIMEOUT, snapshotProxy: snapshotProxy };
