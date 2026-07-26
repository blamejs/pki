// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// CT log-list fetch test transport: an OFFLINE routing fake over the shared pki.transport contract, plus
// the in-repo fixture pair, so pki.ct.fetchLogList(opts) is driven end to end WITHOUT a socket. The fixture
// is cryptographically real: the log-list JSON carries one log whose log_id = SHA-256(SPKI) (so
// parseLogList's recompute matches), and the detached signature is an RSASSA-PKCS1-v1.5/SHA-256 signature
// over the EXACT JSON bytes under a generated RSA-2048 "distributor" key -- opts.signerKey is that
// distributor's SPKI (what an operator pins out-of-band). The routing transport dispatches by request.url
// (JSON URL -> the JSON response, sig URL -> the sig response) and records .calls, so a test asserts what
// crossed the seam and that a config gate ran before the wire (calls.length === 0).

var crypto = require("crypto");

var JSON_URL = "https://ct.example.test/log_list.json";
var SIG_URL = "https://ct.example.test/log_list.sig";   // the .json -> .sig default derivation of JSON_URL

// Build a fixture: { json, sig, signerKey, distPriv, logId, logIdHex, spki, version, timestamp }. `over`
// overrides the document version / log_list_timestamp (for the stale-timestamp + version vectors).
function makeFixture(over) {
  over = over || {};
  var logKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spki = logKp.publicKey.export({ format: "der", type: "spki" });
  var logId = crypto.createHash("sha256").update(spki).digest();
  var entry = {
    description: "Test Log",
    log_id: logId.toString("base64"),
    key: spki.toString("base64"),
    url: "https://ct.example.com/",
    mmd: 86400,
    state: { usable: { timestamp: "2022-01-01T00:00:00Z" } },
  };
  var version = over.version !== undefined ? over.version : "3";
  var timestamp = over.timestamp !== undefined ? over.timestamp : "2024-01-01T00:00:00Z";
  var doc = { version: version, log_list_timestamp: timestamp,
    operators: [{ name: "Test Operator", email: ["ct@example.com"], logs: [entry], tiled_logs: [] }] };
  var json = Buffer.from(JSON.stringify(doc));
  var dist = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var signerKey = dist.publicKey.export({ format: "der", type: "spki" });
  var sig = crypto.sign("sha256", json, dist.privateKey);
  return {
    json: json, sig: sig, signerKey: signerKey, distPriv: dist.privateKey,
    logId: logId, logIdHex: logId.toString("hex"), spki: spki, version: version, timestamp: timestamp,
  };
}

// A DIFFERENT well-formed distributor public key (SPKI DER) -- for the wrong-pinned-key vector.
function otherSignerKey() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" });
}

// A response object for the routing transport.
function resp(status, body, contentType) {
  return { status: status, headers: contentType ? { "content-type": contentType } : {}, body: body == null ? "" : body };
}

// A transport routing by request.url: `routes` maps an exact URL -> a response object OR a function
// (request) -> response|Promise (so a route can REJECT, for a transport-fault vector). An unrouted URL
// rejects. Records .calls (method / url / headers / body) so a test asserts what crossed the seam and that a
// config gate ran before the wire (calls.length === 0).
function routeByUrl(routes) {
  var calls = [];
  function transport(request) {
    calls.push(request);
    var r = routes[request.url];
    if (r === undefined) return Promise.reject(new Error("ct-fetch-transport: no route for " + request.url));
    if (typeof r === "function") return Promise.resolve().then(function () { return r(request); });
    return Promise.resolve({ status: r.status, headers: r.headers || {}, body: r.body == null ? "" : r.body });
  }
  transport.calls = calls;
  return transport;
}

// The happy routes: the fixture JSON at JSON_URL (application/json), the sig at SIG_URL
// (application/octet-stream). `over.json` / `over.sig` replace either leg (an error / partial / oversized
// response, or a different content-type).
function okRoutes(fx, over) {
  over = over || {};
  var routes = {};
  routes[JSON_URL] = over.json !== undefined ? over.json : resp(200, fx.json, "application/json");
  routes[SIG_URL] = over.sig !== undefined ? over.sig : resp(200, fx.sig, "application/octet-stream");
  return routes;
}

// Build fetchLogList opts driving the routing transport with the pinned signerKey. The default sigUrl is
// DERIVED by the verb (JSON_URL .json -> .sig === SIG_URL), so it is intentionally NOT passed unless `extra`
// supplies it. Returns { opts, transport } so a test asserts transport.calls.
function ctFetchOpts(fx, routes, extra) {
  var transport = routeByUrl(routes);
  var opts = Object.assign({ transport: transport, url: JSON_URL, signerKey: fx.signerKey }, extra || {});
  return { opts: opts, transport: transport };
}

module.exports = {
  JSON_URL: JSON_URL, SIG_URL: SIG_URL,
  makeFixture: makeFixture, otherSignerKey: otherSignerKey,
  resp: resp, routeByUrl: routeByUrl, okRoutes: okRoutes, ctFetchOpts: ctFetchOpts,
};
