// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// ACME test transport: a ROUTING fake server over the shared fakeTransport contract, so a
// pki.acme.client session (directory -> nonce -> account -> order -> challenge -> finalize ->
// download) is driven end-to-end WITHOUT a socket. It stamps the ACME content-types
// (application/json, application/problem+json, application/pem-certificate-chain), injects a fresh
// Replay-Nonce on every response, and advances the order status by poll count. Every request is
// recorded on transport.calls (method / url / headers / body) so a test asserts the exact JWS that
// crossed the seam (decode protected.nonce/kid, prove a gate ran before any POST via calls.length).

var fakeTransport = require("./fake-transport").fakeTransport;
var subtle = require("../../lib/webcrypto").webcrypto.subtle;
var signing = require("./signing");

// A real (structurally parseable) X.509 certificate PEM -- the default download chain, so the client's
// strict per-certificate parse accepts it (a test wanting a non-cert body passes its own certPems).
function certToPem(der) { return "-----BEGIN CERTIFICATE-----\n" + Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END CERTIFICATE-----"; }
var REAL_CERT_PEM = certToPem(signing.makeSigner("ec-p256", { cn: "leaf.example" }).cert);

var BASE = "https://acme.example";
var URLS = {
  base: BASE,
  directory: BASE + "/directory",
  newNonce: BASE + "/new-nonce",
  newAccount: BASE + "/new-account",
  newOrder: BASE + "/new-order",
  revokeCert: BASE + "/revoke-cert",
  keyChange: BASE + "/key-change",
  renewalInfo: BASE + "/renewal-info",
  account: BASE + "/acct/1",
  order: BASE + "/order/1",
  finalize: BASE + "/order/1/finalize",
  authz: BASE + "/authz/1",
  challenge: BASE + "/chal/1",
  certificate: BASE + "/cert/1",
};

// A directory object; drop a key (e.g. delete d.newNonce) to test a missing required resource.
function directory(overrides) {
  return Object.assign({
    newNonce: URLS.newNonce, newAccount: URLS.newAccount, newOrder: URLS.newOrder,
    revokeCert: URLS.revokeCert, keyChange: URLS.keyChange, renewalInfo: URLS.renewalInfo,
  }, overrides || {});
}

// A real EC account key + its public JWK (the client signs every JWS with it via the acme builders).
async function makeAccount() {
  var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return {
    key: kp.privateKey,
    jwk: await subtle.exportKey("jwk", kp.publicKey),
    spki: Buffer.from(await subtle.exportKey("spki", kp.publicKey)),
  };
}

// ---- response builders (each stamps content-type; nonce/location added by the server) -----------
function json(status, obj, headers) { return { status: status, headers: Object.assign({ "content-type": "application/json" }, headers || {}), body: JSON.stringify(obj) }; }
function problem(status, type, detail, extra) { return { status: status, headers: { "content-type": "application/problem+json" }, body: JSON.stringify(Object.assign({ type: "urn:ietf:params:acme:error:" + type, detail: detail || type }, extra || {})) }; }
function pemChain(pems, headers) { return { status: 200, headers: Object.assign({ "content-type": "application/pem-certificate-chain" }, headers || {}), body: pems.join("\n") }; }

// A stateful server that routes by method + pathname and injects Replay-Nonce. `opts` tunes behavior:
//   directory: the directory object (default full); orderStates: the status sequence a GET /order/1
//   walks (default pending->ready->valid); challenges: the /authz challenge list; certPems: the
//   download chain; badNonceRounds: N leading POSTs answered with a badNonce+fresh nonce; problemOn:
//   { pathname: problem-response } to force a problem on a route.
function acmeServer(opts) {
  opts = opts || {};
  var nonceSeq = 0;
  function nextNonce() { var b = Buffer.alloc(6); b.writeUIntBE(nonceSeq++, 0, 6); return b.toString("base64url"); }   // canonical base64url, unique
  var dir = opts.directory || directory();
  var orderStates = opts.orderStates || ["pending", "ready", "valid"];
  var orderPoll = -1;   // index into orderStates for GET /order/1
  var authzPoll = -1;   // index into opts.authzStates for GET /authz/1 (when set)
  var badLeft = opts.badNonceRounds || 0;
  var EXPIRES = "2030-01-01T00:00:00Z";
  var TOKEN = Buffer.from("acme-challenge-token-000001").toString("base64url");   // canonical base64url, > 128 bits
  var challenges = opts.challenges || [{ type: "http-01", url: URLS.challenge, status: "pending", token: TOKEN }];
  var orderIdentifiers = opts.identifiers || [{ type: "dns", value: "example.org" }];
  var certPems = opts.certPems || [REAL_CERT_PEM];
  // strictNonce mode: only a nonce the server issued in a POST-response or a badNonce error is valid;
  // nonces harvested off unauthenticated GETs (directory, renewalInfo) are decoys. This distinguishes a
  // retry that consumes the error's fresh nonce (accepted) from one that reuses a staler pooled nonce.
  var validNonces = {};
  // Decode the nonce from a POST's protected header. Only ever called on a client POST, which always
  // carries a well-formed Flattened JWS, so a decode failure is surfaced (not swallowed) as a signal.
  function reqNonce(request) {
    var raw = Buffer.isBuffer(request.body) ? request.body.toString("utf8") : String(request.body);
    return JSON.parse(Buffer.from(JSON.parse(raw).protected, "base64url").toString("utf8")).nonce;
  }
  function orderObj(status) {
    var o = { status: status, expires: EXPIRES, identifiers: orderIdentifiers, authorizations: [URLS.authz], finalize: URLS.finalize };
    if (status === "valid") o.certificate = URLS.certificate;
    return o;
  }
  function challengeObj(status) { return { type: "http-01", url: URLS.challenge, status: status, token: TOKEN }; }

  function route(request) {
    var u = new URL(request.url);
    var path = u.pathname;
    var method = request.method;
    var withNonce = function (r) { r.headers = Object.assign({ "replay-nonce": nextNonce() }, r.headers || {}); return r; };

    // an optional redirect map { fromPath: toUrl } -> a 301 a safe-method request follows (or loops).
    if (opts.redirects && opts.redirects[path]) return { status: 301, headers: { location: opts.redirects[path] }, body: "" };
    // a malformed 301 with NO Location header, to exercise the client's fail-closed redirect handling.
    if (opts.redirectNoLocationPath === path) return { status: 301, headers: {}, body: "" };

    // GET directory / HEAD newNonce (unauthenticated). In strictNonce mode the directory + renewalInfo
    // responses carry a DECOY nonce (harvested by the client, rejected on a POST) to seed the pool.
    if (path === "/directory") return opts.strictNonce ? withNonce(json(200, dir)) : json(200, dir);
    if (path === "/new-nonce") return withNonce({ status: 200, headers: {} });
    if (path === "/renewal-info" || path.indexOf("/renewal-info/") === 0) {
      var ri = opts.renewalInfoResponse || json(200, { suggestedWindow: { start: "2027-01-01T00:00:00Z", end: "2027-01-15T00:00:00Z" } });
      return opts.strictNonce ? withNonce(ri) : ri;
    }

    // strictNonce: a POST must carry a server-issued (POST/badNonce) nonce; any other -> badNonce + fresh.
    if (opts.strictNonce && method === "POST") {
      var used = reqNonce(request);
      if (!validNonces[used]) { var fresh = nextNonce(); validNonces[fresh] = true; return { status: 400, headers: { "replay-nonce": fresh, "content-type": "application/problem+json" }, body: JSON.stringify({ type: "urn:ietf:params:acme:error:badNonce", detail: "bad or stale nonce" }) }; }
      delete validNonces[used];   // single-use; fall through to the normal route (its response nonce is a decoy)
    }

    // a forced problem on any authenticated route (with a fresh nonce, per sec. 6.5)
    if (opts.problemOn && opts.problemOn[path]) return withNonce(opts.problemOn[path]);

    // a bounded run of badNonce on the first N POSTs
    if (method === "POST" && badLeft > 0) { badLeft--; return withNonce(problem(400, "badNonce", "bad nonce, retry")); }

    if (path === "/new-account") {
      var loc = opts.accountLocation || URLS.account;
      // accountNonceInvalid: the 201 carries a non-base64url Replay-Nonce the client must DISCARD.
      if (opts.accountNonceInvalid) return { status: 201, headers: { "replay-nonce": "invalid nonce!!", "content-type": "application/json", location: loc }, body: JSON.stringify(opts.account || { status: "valid" }) };
      return withNonce(json(201, opts.account || { status: "valid" }, { location: loc }));
    }
    if (path === "/new-order") return withNonce(json(201, opts.order || orderObj("pending"), { location: URLS.order }));
    if (path === "/authz/1") {
      var azStatus = "pending";
      if (opts.authzStates) { authzPoll = Math.min(authzPoll + 1, opts.authzStates.length - 1); azStatus = opts.authzStates[authzPoll]; }
      return withNonce(json(200, { status: azStatus, expires: EXPIRES, identifier: orderIdentifiers[0], challenges: challenges }));
    }
    if (path === "/chal/1") return withNonce(json(200, challengeObj("processing")));
    if (path === "/order/1/finalize") return withNonce(json(200, orderObj("processing")));
    if (path === "/order/1") {
      orderPoll = Math.min(orderPoll + 1, orderStates.length - 1);
      var extraHdr = opts.pollRetryAfter ? { "retry-after": opts.pollRetryAfter } : {};
      return withNonce(json(200, orderObj(orderStates[orderPoll]), extraHdr));
    }
    if (path === "/cert/1") {
      if (opts.certRequiresPemAccept && String((request.headers || {}).accept || "").indexOf("application/pem-certificate-chain") === -1) return withNonce(problem(406, "malformed", "the certificate resource requires Accept: application/pem-certificate-chain"));
      return withNonce(pemChain(certPems, opts.certContentType ? { "content-type": opts.certContentType } : {}));
    }
    if (path === "/acct/1") return withNonce(json(200, opts.accountAfter || { status: "deactivated" }));
    if (path === "/key-change") return withNonce({ status: 200, headers: {}, body: opts.keyChangeBody !== undefined ? opts.keyChangeBody : "" });
    if (path === "/revoke-cert") return withNonce({ status: opts.revokeStatus || 200, headers: {}, body: "" });

    return withNonce({ status: 404, headers: {}, body: "no route " + method + " " + path });
  }
  var t = fakeTransport(route);
  return { transport: t, calls: t.calls, urls: URLS, directory: dir };
}

// Build the client opts: the account key + a fake transport (+ a real anchor to satisfy any default-
// transport gate, though the injected transport ignores it). Pass a prebuilt server or a route fn.
function clientOpts(acct, server, extra) {
  return Object.assign({
    accountKey: acct.key, accountJwk: acct.jwk, alg: "ES256",
    transport: server.transport || server,
    sleep: function () { return Promise.resolve(); },   // never really sleep in a poll loop
  }, extra || {});
}

module.exports = {
  URLS: URLS, directory: directory, makeAccount: makeAccount,
  json: json, problem: problem, pemChain: pemChain,
  acmeServer: acmeServer, clientOpts: clientOpts,
};
