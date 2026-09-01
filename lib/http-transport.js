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
 *   into the socket layer -- the transport owns socket lifecycle, the TLS trust policy,
 *   the streaming size cap, and the timeout budget; the caller owns HTTP status,
 *   content-type, redirect, and authentication decisions. `tls` reports the negotiated
 *   channel -- `{ protocol, cipher, peerCertificate }` -- which is the one fact a caller
 *   cannot recover from the response bytes. An INJECTED substitute should return it too:
 *   `pki.est.serverkeygen` asserts the negotiated cipher can protect the private key it
 *   is about to accept, and a transport that reports no cipher is trusted instead of
 *   refused (so a loopback test channel works), which means omitting the field silently
 *   skips that assertion.
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
 *   and a timeout -- behind one `transport(request) -> {status, headers, body, tls}` seam.
 */

var nodeHttps = require("node:https");
var nodeNet = require("node:net");
var nodeTls = require("node:tls");
var nodeDns = require("node:dns");
var constants = require("./constants");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var TransportError = frameworkError.TransportError;
function defaultE(code, message, cause) { return new TransportError(code, message, cause); }

var DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var MAX_TIMEOUT = constants.TIME.seconds(600);
var DEFAULT_MIN_VERSION = "TLSv1.2";

function _budget(value, key, dflt, max, E, code) {
  return guard.limits.cap(value, key, dflt, { E: E, code: code, min: 1, max: max, label: key });
}

var _LATIN1_WS = String.fromCharCode(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0);

function _looksLikePemArmor(s) {
  var i = 0;
  while (i < s.length && _LATIN1_WS.indexOf(s.charAt(i)) !== -1) i += 1;
  return s.slice(i, i + 11) === "-----BEGIN ";
}
function _wrap64Lines(s) {
  var out = "";
  for (var i = 0; i < s.length; i += 64) out += s.slice(i, i + 64) + "\n";
  return out;
}
function _stripIpv6Brackets(s) {
  return (s.length >= 2 && s.charAt(0) === "[" && s.charAt(s.length - 1) === "]") ? s.slice(1, s.length - 1) : s;
}

function _pemifyAnchor(a) {
  if (typeof a === "string") return a;
  if (Buffer.isBuffer(a)) {
    if (_looksLikePemArmor(a.toString("latin1", 0, 64))) return a;
    var b64 = _wrap64Lines(a.toString("base64"));
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n";
  }
  return a;
}
function _pemifyAnchors(anchors) {
  var list = Array.isArray(anchors) ? anchors.map(_pemifyAnchor) : [_pemifyAnchor(anchors)];
  return list;
}

var _systemCaCache = null;
function _systemCa() {
  if (_systemCaCache !== null) return _systemCaCache;
  var out = [];
  if (typeof nodeTls.getCACertificates === "function") {
    ["system", "bundled"].forEach(function (t) {
      // allow:swallow-unverified a store TYPE unsupported on this node is skipped; the other type
      try { var c = nodeTls.getCACertificates(t); if (Array.isArray(c)) out = out.concat(c); } catch (_e) { }
    });
  }
  _systemCaCache = out;
  return out;
}

function _isBlockedIp(ip) {
  var fam = nodeNet.isIP(ip);
  if (fam === 4) {
    var o = ip.split("."), a = +o[0], b = +o[1], c = +o[2];
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
    var l = ip.toLowerCase();
    if (l.indexOf("::ffff:") === 0) return true;
    var parts = l.split(":");
    var h = parseInt(parts[0], 16);
    if (!(h >= 0x2000 && h <= 0x3fff)) return true;
    var h2 = parts[1] ? parseInt(parts[1], 16) : 0;
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
    lookupFn(hostname, options || {}, function (err, address, family) {
      if (err) return callback(err);
      if (Array.isArray(address)) {
        for (var i = 0; i < address.length; i++) if (_isBlockedIp(address[i].address)) return callback(_blockedAddrErr(hostname, address[i].address));
        return callback(null, address);
      }
      if (_isBlockedIp(address)) return callback(_blockedAddrErr(hostname, address));
      return callback(null, address, family);
    });
  };
}
var _guardedLookup = _makeGuardedLookup(nodeDns.lookup);

function _hasSelfSigned(l) {
  for (var i = 0; i + 4 <= l.length; i++) {
    if (l.charCodeAt(i) === 0x73 && l.charCodeAt(i + 1) === 0x65 && l.charCodeAt(i + 2) === 0x6c && l.charCodeAt(i + 3) === 0x66) {
      if (l.indexOf("signed", i + 4) === i + 4) return true;
      var mid = l.charCodeAt(i + 4);
      if (i + 4 < l.length && mid !== 0x0a && mid !== 0x0d && mid !== 0x2028 && mid !== 0x2029 && l.indexOf("signed", i + 5) === i + 5) return true;
    }
  }
  return false;
}
function _hasWordBounded(l, word) {
  var at = l.indexOf(word);
  while (at !== -1) {
    var before = at === 0 || !_isLowerWordChar(l.charCodeAt(at - 1));
    var afterI = at + word.length;
    var after = afterI === l.length || !_isLowerWordChar(l.charCodeAt(afterI));
    if (before && after) return true;
    at = l.indexOf(word, at + 1);
  }
  return false;
}
function _isLowerWordChar(c) { return (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95; }
function _classifyError(e, C) {
  if (e && e.pkiBlockedAddress) return C("blocked-address");
  var s = String((e && e.code) || "") + " " + String((e && e.message) || "");
  var l = s.toLowerCase();
  if (l.indexOf("protocol_version") !== -1 || l.indexOf("unsupported_protocol") !== -1 || l.indexOf("version_too_low") !== -1 ||
      l.indexOf("wrong_version") !== -1 || l.indexOf("no_protocols_available") !== -1 || l.indexOf("inappropriate_fallback") !== -1) return C("tls-floor");
  if (l.indexOf("cert") !== -1 || l.indexOf("verify") !== -1 || l.indexOf("altname") !== -1 || l.indexOf("hostname") !== -1 ||
      l.indexOf("depth_zero") !== -1 || l.indexOf("local_issuer") !== -1 || l.indexOf("handshake") !== -1 ||
      _hasSelfSigned(l) || _hasWordBounded(l, "ssl") || _hasWordBounded(l, "tls")) return C("server-auth-failed");
  return C("transport-error");
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
 * semantics -- those live in the message layer that consumes the response triple.
 *
 * @opts
 *   - `tls.anchors` -- Explicit trust anchor(s): a DER/PEM Buffer, an array, or PEM string(s) (node `ca`).
 *   - `tls.useSystemStore` -- boolean; the one opt-in to node's bundled CA store (default false).
 *   - `tls.cert` / `tls.key` -- client certificate + key for mutual-TLS re-enrollment.
 *   - `tls.minVersion` -- 'TLSv1.2' (default) or 'TLSv1.3'; never below the floor.
 *   - `tls.servername` / `tls.checkServerIdentity` -- SNI + RFC 6125 identity; may tighten, never disable.
 *   - `timeout` -- ms (default C.TIME.seconds(30)); `maxResponseBytes` -- default LIMITS.HTTP_MAX_RESPONSE_BYTES, tightenable downward only.
 *   - `blockPrivateAddresses` -- boolean; when true, an IP-literal host OR a hostname resolving to a private / loopback / link-local address is refused (`transport/blocked-address`), and a resolved address is pinned for the connection. For fetching an untrusted-certificate URL (AIA caIssuers); default false.
 * @example
 *   var t = pki.transport.https({ tls: { anchors: [caPem] } });
 *   var res = await t({ method: "GET", url: "https://ca.example/.well-known/est/cacerts" });
 *   res.status;   // 200
 */
function httpsTransport(defaults) {
  defaults = defaults || {};
  var E = typeof defaults.E === "function" ? defaults.E : defaultE;
  var prefix = defaults.errPrefix || "transport";
  function C(name) { return prefix + "/" + name; }
  var tlsDefaults = defaults.tls || {};

  function _prepare(request) {
    var url;
    try { url = new URL(String(request.url)); }
    catch (e) { throw E(C("bad-url"), "the request URL did not parse: " + String(request.url), e); }
    if (url.protocol !== "https:") throw E(C("insecure-url"), "transport requires https (RFC 7030 sec. 3.3), got " + url.protocol);

    var reqTls = request.tls || {};
    var anchors = reqTls.anchors !== undefined ? reqTls.anchors : tlsDefaults.anchors;
    var useSystem = (reqTls.useSystemStore !== undefined ? reqTls.useSystemStore : tlsDefaults.useSystemStore) === true;
    var hasAnchors = anchors !== undefined && anchors !== null && !(Array.isArray(anchors) && anchors.length === 0);
    if (!hasAnchors && !useSystem) throw E(C("no-trust-anchors"), "no explicit trust anchor and useSystemStore not set -- refusing an unpinned server (RFC 7030 sec. 3.6)");

    var timeout = _budget(request.timeout !== undefined ? request.timeout : defaults.timeout, "timeout", DEFAULT_TIMEOUT, MAX_TIMEOUT, E, C("bad-input"));
    var maxBytes = _budget(request.maxResponseBytes !== undefined ? request.maxResponseBytes : defaults.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, E, C("bad-input"));

    var minVersion = reqTls.minVersion || tlsDefaults.minVersion || DEFAULT_MIN_VERSION;
    if (minVersion !== "TLSv1.2" && minVersion !== "TLSv1.3") throw E(C("bad-input"), "tls.minVersion must be 'TLSv1.2' or 'TLSv1.3' (never below the floor), got " + minVersion);

    var body = request.body;
    if (guard.bytes.isByteSource(body)) body = guard.bytes.source(body, E, C("bad-input"), "the request body");

    var reqHeaders = Object.assign({}, request.headers || {});
    if (body != null && body !== "") {
      Object.keys(reqHeaders).forEach(function (k) { var lk = k.toLowerCase(); if (lk === "content-length" || lk === "transfer-encoding") delete reqHeaders[k]; });
      reqHeaders["Content-Length"] = Buffer.byteLength(body);
    }

    var host = _stripIpv6Brackets(url.hostname);
    var options = {
      method: request.method || "GET",
      hostname: host,
      port: url.port || 443,
      path: url.pathname + url.search,
      headers: reqHeaders,
      minVersion: minVersion,
      rejectUnauthorized: true,
      agent: false,
    };
    var cert = reqTls.cert !== undefined ? reqTls.cert : tlsDefaults.cert;
    var key = reqTls.key !== undefined ? reqTls.key : tlsDefaults.key;
    var callerCsi = typeof reqTls.checkServerIdentity === "function" ? reqTls.checkServerIdentity
      : (typeof tlsDefaults.checkServerIdentity === "function" ? tlsDefaults.checkServerIdentity : null);
    var sni = (reqTls.servername !== undefined ? reqTls.servername : tlsDefaults.servername) || host;
    if (sni && !nodeNet.isIP(sni)) options.servername = sni;
    var caList = [];
    if (hasAnchors) caList = caList.concat(_pemifyAnchors(anchors));
    if (useSystem) caList = caList.concat(_systemCa());
    if (caList.length) options.ca = caList;
    if (cert) options.cert = cert;
    if (key) options.key = key;
    if (callerCsi) {
      options.checkServerIdentity = function (host, cert2) {
        var baseErr = nodeTls.checkServerIdentity(host, cert2);
        if (baseErr) return baseErr;
        return callerCsi(host, cert2);
      };
    }
    var blockPrivate = (request.blockPrivateAddresses !== undefined ? request.blockPrivateAddresses : defaults.blockPrivateAddresses) === true;
    if (blockPrivate) {
      if (_isBlockedIp(host)) throw E(C("blocked-address"), "refusing to connect to the private / loopback / link-local address literal " + host);
      options.lookup = _guardedLookup;
    }

    return { options: options, timeout: timeout, maxBytes: maxBytes, body: body };
  }

  var _transportFn = function transport(request) {
    request = request || {};
    var prep;
    try { prep = _prepare(request); }
    catch (e) { return Promise.reject(e); }
    return new Promise(function (resolve, reject) {
      var settled = false;
      var req;
      var timer = null;
      function clearTimer() { if (timer) { clearTimeout(timer); timer = null; } }
      function fail(code, msg, cause) {
        if (settled) return;
        settled = true;
        clearTimer();
        // allow:swallow-unverified req.destroy() is idempotent and does not throw in practice; a
        try { if (req) req.destroy(); } catch (_e) { }
        reject(E(code, msg, cause));
      }
      timer = setTimeout(function () { fail(C("timeout"), "the request timed out after " + prep.timeout + "ms"); }, prep.timeout);
      try {
        req = nodeHttps.request(prep.options, function (res) {
          var proto = res.socket && res.socket.getProtocol ? res.socket.getProtocol() : null;
          var cipher = res.socket && res.socket.getCipher ? res.socket.getCipher() : null;
          var peer = res.socket && res.socket.getPeerCertificate ? res.socket.getPeerCertificate() : null;
          var declared = parseInt((res.headers || {})["content-length"], 10);
          if (Number.isFinite(declared) && declared > prep.maxBytes) { fail(C("response-too-large"), "the declared content-length " + declared + " exceeds the " + prep.maxBytes + "-byte cap (RFC 7030 sec. 6)"); return; }
          var buf = Buffer.allocUnsafe(0);
          var len = 0;
          var total = 0;
          res.on("data", function (chunk) {
            total += chunk.length;
            if (total > prep.maxBytes) { fail(C("response-too-large"), "the response exceeded the " + prep.maxBytes + "-byte cap (RFC 7030 sec. 6)"); return; }
            if (len + chunk.length > buf.length) {
              var want = Math.min(prep.maxBytes, Math.max(buf.length ? buf.length * 2 : 8192, len + chunk.length));
              var grown = Buffer.allocUnsafe(want);
              buf.copy(grown, 0, 0, len);
              buf = grown;
            }
            chunk.copy(buf, len);
            len += chunk.length;
          });
          res.on("end", function () {
            if (settled) return;
            settled = true;
            clearTimer();
            var lower = {};
            Object.keys(res.headers || {}).forEach(function (k) { lower[k.toLowerCase()] = res.headers[k]; });
            resolve({
              status: res.statusCode,
              headers: lower,
              body: Buffer.from(buf.subarray(0, len)),
              tls: { protocol: proto, cipher: cipher, peerCertificate: peer && peer.raw ? peer.raw : null },
            });
          });
          res.on("error", function (e) { fail(C("transport-error"), "the response stream failed", e); });
        });
        req.on("error", function (e) { fail(_classifyError(e, C), "the request failed: " + ((e && e.message) || String(e)), e); });
        if (prep.body != null && prep.body !== "") req.write(prep.body);
        req.end();
      } catch (e) { fail(C("transport-error"), "the request could not be initiated: " + ((e && e.message) || String(e)), e); }
    });
  };
  _transportFn.blocksPrivateAddresses = true;
  return _transportFn;
}

module.exports = { https: httpsTransport, isBlockedIp: _isBlockedIp, _makeGuardedLookup: _makeGuardedLookup, MAX_TIMEOUT: MAX_TIMEOUT };
