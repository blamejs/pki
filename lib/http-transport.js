// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.transport
 * @nav        Protocols
 * @title      Transport
 * @order      195
 * @slug       transport
 *
 * @intro
 *   The shared, fail-closed `node:https` transport the enrollment protocol clients
 *   drive -- `pki.est` now, `pki.acme` and `pki.cmp` next. This is the ONLY module in
 *   the toolkit that opens a socket; every protocol layer stays transport-agnostic and
 *   composes it (or an injected substitute) through one contract:
 *   `transport(request) -> Promise<{ status, headers, body }>`. The response triple is
 *   exactly what a message layer's classifier consumes, so no protocol semantics leak
 *   into the socket layer -- the transport owns socket lifecycle, the TLS trust policy,
 *   the streaming size cap, and the timeout budget; the caller owns HTTP status,
 *   content-type, redirect, and authentication decisions.
 *
 *   `pki.transport.https(defaults?)` binds TLS + budget defaults and returns a
 *   transport. Trust is EXPLICIT and fail-closed: a request is refused unless it
 *   carries an https URL and either a `tls.anchors` set (an Explicit trust-anchor
 *   database, mapped to the node `ca` option) or an explicit `tls.useSystemStore`
 *   opt-in to node's bundled roots. `rejectUnauthorized` is ALWAYS on -- there is no
 *   code path that disables server-certificate verification. The response body is
 *   bounded WHILE it streams: the accumulator aborts the socket the instant the running
 *   total crosses `maxResponseBytes`, before a byte reaches a decoder. A protocol
 *   client MAY parameterize the transport with its own `(code, message, cause)` error
 *   factory + code prefix, so the same choke point surfaces domain-specific codes.
 *
 * @card
 *   The shared fail-closed node:https transport (est / acme / cmp): explicit trust
 *   anchors, rejectUnauthorized always on, a TLS floor, a streaming response-size cap,
 *   and a timeout -- behind one `transport(request) -> {status, headers, body}` seam.
 */

var nodeHttps = require("node:https");
var nodeNet = require("node:net");
var nodeTls = require("node:tls");
var constants = require("./constants");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var TransportError = frameworkError.TransportError;
function defaultE(code, message, cause) { return new TransportError(code, message, cause); }

var DEFAULT_TIMEOUT = constants.TIME.seconds(30);
var MAX_TIMEOUT = constants.TIME.seconds(600);
var DEFAULT_MIN_VERSION = "TLSv1.2";

// A config-time budget: cap() with the caller's typed factory + a >= 1 floor and an
// upper bound (maxResponseBytes may only be tightened DOWNWARD from the default). A
// NaN / negative / over-max value is a typed reject, never a silently-disabled bound.
function _budget(value, key, dflt, max, E, code) {
  return guard.limits.cap(value, key, dflt, { E: E, code: code, min: 1, max: max, label: key });
}

// Node's `ca` option expects PEM; a raw DER certificate Buffer -- the toolkit's native trust-anchor
// form (e.g. what pki.est.cacerts / parseCertsOnly return) -- is silently ignored there, so the
// connection would fail server authentication despite a valid anchor. Wrap a DER anchor as PEM
// (a Buffer already carrying PEM text, or a PEM string, passes through unchanged).
function _pemifyAnchor(a) {
  if (typeof a === "string") return a;
  if (Buffer.isBuffer(a)) {
    // Detect PEM by its armor at the START (after optional whitespace) only: a DER certificate begins
    // with the SEQUENCE tag 0x30 and may itself contain the bytes "-----BEGIN" in a subject / extension
    // value, so an anywhere-search would leave such a DER anchor unwrapped and unusable.
    if (/^\s*-----BEGIN /.test(a.toString("latin1", 0, 64))) return a;
    var b64 = a.toString("base64").replace(/.{1,64}/g, "$&\n");
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n";
  }
  return a;
}
function _pemifyAnchors(anchors) {
  return Array.isArray(anchors) ? anchors.map(_pemifyAnchor) : _pemifyAnchor(anchors);
}

// Classify a node request/TLS error into the transport's fail-closed verdict: a
// protocol-version mismatch is the TLS floor; a certificate / identity / handshake
// failure is a server-authentication failure; anything else is a generic transport
// error. Every arm threads the raw fault as `.cause`, so the diagnostic survives.
function _classifyError(e, C) {
  var s = String((e && e.code) || "") + " " + String((e && e.message) || "");
  if (/PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL|VERSION_TOO_LOW|WRONG_VERSION|NO_PROTOCOLS_AVAILABLE|INAPPROPRIATE_FALLBACK/i.test(s)) return C("tls-floor");
  if (/CERT|SELF.?SIGNED|VERIFY|ALTNAME|HOSTNAME|DEPTH_ZERO|LOCAL_ISSUER|HANDSHAKE|\bSSL\b|\bTLS\b/i.test(s)) return C("server-auth-failed");
  return C("transport-error");
}

/**
 * @primitive  pki.transport.https
 * @signature  pki.transport.https(defaults?) -> transport
 * @since      0.3.16
 * @status     experimental
 * @spec       RFC 7030, RFC 8996
 * @defends    tls-downgrade (CWE-757), server-impersonation (CWE-297), response-flooding (CWE-770)
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
 *   - `tls.useSystemStore` -- boolean; the ONLY opt-in to node's bundled CA store (default false).
 *   - `tls.cert` / `tls.key` -- client certificate + key for mutual-TLS re-enrollment.
 *   - `tls.minVersion` -- 'TLSv1.2' (default) or 'TLSv1.3'; never below the floor.
 *   - `tls.servername` / `tls.checkServerIdentity` -- SNI + RFC 6125 identity; may tighten, never disable.
 *   - `timeout` -- ms (default C.TIME.seconds(30)); `maxResponseBytes` -- default LIMITS.HTTP_MAX_RESPONSE_BYTES, tightenable downward only.
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

  // Synchronous config validation + node-options build. Throws the typed verdict on any
  // fault (a non-https URL, no trust anchor, a bad budget, a sub-floor minVersion) so the
  // async executor below never has to `return reject(...)`. rejectUnauthorized is forced on.
  function _prepare(request) {
    var url;
    try { url = new URL(String(request.url)); }
    catch (e) { throw E(C("bad-url"), "the request URL did not parse: " + String(request.url), e); }
    if (url.protocol !== "https:") throw E(C("insecure-url"), "transport requires https (RFC 7030 sec. 3.3), got " + url.protocol);

    var reqTls = request.tls || {};
    var anchors = reqTls.anchors !== undefined ? reqTls.anchors : tlsDefaults.anchors;
    var useSystem = reqTls.useSystemStore !== undefined ? reqTls.useSystemStore : tlsDefaults.useSystemStore;
    var hasAnchors = anchors !== undefined && anchors !== null && !(Array.isArray(anchors) && anchors.length === 0);
    if (!hasAnchors && !useSystem) throw E(C("no-trust-anchors"), "no explicit trust anchor and useSystemStore not set -- refusing an unpinned server (RFC 7030 sec. 3.6)");

    var timeout = _budget(request.timeout !== undefined ? request.timeout : defaults.timeout, "timeout", DEFAULT_TIMEOUT, MAX_TIMEOUT, E, C("bad-input"));
    var maxBytes = _budget(request.maxResponseBytes !== undefined ? request.maxResponseBytes : defaults.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, E, C("bad-input"));

    var minVersion = reqTls.minVersion || tlsDefaults.minVersion || DEFAULT_MIN_VERSION;
    if (minVersion !== "TLSv1.2" && minVersion !== "TLSv1.3") throw E(C("bad-input"), "tls.minVersion must be 'TLSv1.2' or 'TLSv1.3' (never below the floor), got " + minVersion);

    var body = request.body;
    if (Buffer.isBuffer(body)) body = guard.bytes.view(body, E, C("bad-input"), "the request body");

    // URL.hostname keeps the square brackets on an IPv6 literal ([2001:db8::1]); node's `hostname`
    // option and its IP-detection expect the bare address, so strip the brackets once here.
    var host = url.hostname.replace(/^\[(.*)\]$/, "$1");
    var options = {
      method: request.method || "GET",
      hostname: host,
      port: url.port || 443,
      path: url.pathname + url.search,
      headers: request.headers || {},
      minVersion: minVersion,
      rejectUnauthorized: true,   // ALWAYS on -- there is no code path that disables server verification
    };
    // Every TLS field falls back to the factory defaults (as anchors / minVersion already do), so a
    // reusable transport built with pki.transport.https({ tls: { cert, key, servername } }) applies
    // them to a request that carries no per-request tls (mTLS enrollment, a configured SNI).
    var cert = reqTls.cert !== undefined ? reqTls.cert : tlsDefaults.cert;
    var key = reqTls.key !== undefined ? reqTls.key : tlsDefaults.key;
    var callerCsi = typeof reqTls.checkServerIdentity === "function" ? reqTls.checkServerIdentity
      : (typeof tlsDefaults.checkServerIdentity === "function" ? tlsDefaults.checkServerIdentity : null);
    // SNI (and RFC 6125 identity) uses a hostname; node forbids a servername that is an IP
    // literal, so it is omitted for an IP host (node then matches the IP against the cert's
    // IP SANs). A caller connecting by hostname gets SNI + name verification by default.
    var sni = reqTls.servername || tlsDefaults.servername || host;
    if (sni && !nodeNet.isIP(sni)) options.servername = sni;
    if (hasAnchors) options.ca = _pemifyAnchors(anchors);   // operator-facing `anchors` -> node's `ca` (DER wrapped as PEM)
    if (cert) options.cert = cert;
    if (key) options.key = key;
    // A caller checkServerIdentity may only TIGHTEN, never REPLACE, name verification: node uses a
    // supplied callback in place of its default RFC 6125 check, so a hook that returns undefined
    // (pinning/metrics only) would silently disable hostname verification. Run node's default first
    // and reject on its verdict; the caller's hook adds checks only after the default has passed.
    if (callerCsi) {
      options.checkServerIdentity = function (host, cert2) {
        var baseErr = nodeTls.checkServerIdentity(host, cert2);
        if (baseErr) return baseErr;
        return callerCsi(host, cert2);
      };
    }

    return { options: options, timeout: timeout, maxBytes: maxBytes, body: body };
  }

  return function transport(request) {
    request = request || {};
    var prep;
    try { prep = _prepare(request); }
    catch (e) { return Promise.reject(e); }
    return new Promise(function (resolve, reject) {
      var settled = false;
      var req;
      function fail(code, msg, cause) {
        if (settled) return;
        settled = true;
        // allow:swallow-unverified req.destroy() is idempotent and does not throw in practice; a
        // raw throw from this best-effort abort would mask the real fail-closed verdict below.
        try { if (req) req.destroy(); } catch (_e) { /* best-effort abort */ }
        reject(E(code, msg, cause));
      }
      try {
        req = nodeHttps.request(prep.options, function (res) {
          // Capture the TLS session facts while the socket is live -- getProtocol() /
          // getPeerCertificate() return null once the socket detaches at stream end.
          var proto = res.socket && res.socket.getProtocol ? res.socket.getProtocol() : null;
          var peer = res.socket && res.socket.getPeerCertificate ? res.socket.getPeerCertificate() : null;
          // Pre-check a declared content-length so an oversized body is refused before it streams.
          var declared = parseInt((res.headers || {})["content-length"], 10);
          if (Number.isFinite(declared) && declared > prep.maxBytes) { fail(C("response-too-large"), "the declared content-length " + declared + " exceeds the " + prep.maxBytes + "-byte cap (RFC 7030 sec. 6)"); return; }
          var chunks = [];
          var total = 0;
          res.on("data", function (chunk) {
            total += chunk.length;
            if (total > prep.maxBytes) { fail(C("response-too-large"), "the response exceeded the " + prep.maxBytes + "-byte cap (RFC 7030 sec. 6)"); return; }
            chunks.push(chunk);
          });
          res.on("end", function () {
            if (settled) return;
            settled = true;
            var lower = {};
            Object.keys(res.headers || {}).forEach(function (k) { lower[k.toLowerCase()] = res.headers[k]; });
            resolve({
              status: res.statusCode,
              headers: lower,
              body: Buffer.concat(chunks),
              tls: { protocol: proto, peerCertificate: peer && peer.raw ? peer.raw : null },
            });
          });
          res.on("error", function (e) { fail(C("transport-error"), "the response stream failed", e); });
        });
        req.on("error", function (e) { fail(_classifyError(e, C), "the request failed: " + ((e && e.message) || String(e)), e); });
        req.setTimeout(prep.timeout, function () { fail(C("timeout"), "the request timed out after " + prep.timeout + "ms"); });
        // Write a provided body for ANY method (POST / PUT / PATCH / ...), not only POST, so a body
        // is never silently dropped on a body-bearing request through this generic transport seam.
        if (prep.body != null && prep.body !== "") req.write(prep.body);
        req.end();
      } catch (e) { fail(C("transport-error"), "the request could not be initiated: " + ((e && e.message) || String(e)), e); }
    });
  };
}

module.exports = { https: httpsTransport };
