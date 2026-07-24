// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.transport.https, the shared fail-closed node:https transport. The config gates
// (scheme / trust-anchor / budget / minVersion) are pure and socket-free; the socket-lifecycle
// branches (handshake, response streaming, size cap, timeout, TLS floor, server-auth failure) run
// against a node:https LOOPBACK server presenting a REAL self-signed certificate supplied to the
// client as its explicit trust anchor -- TLS verification stays ON (rejectUnauthorized:true), no
// external host, no disabled verification. Errors carry the default transport/* identity (the
// transport is used directly here, not parameterized by a protocol client's factory).

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var https = require("node:https");

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// A REAL self-signed TLS certificate (valid ECDSA signature, SAN dNSName localhost) so a loopback
// https server presents it and the client trusts it as an explicit anchor -- verification ON.
async function selfSigned(cn) {
  var s = signing.makeSigner("ec-p256", { cn: cn });
  var certDer = await pki.x509.sign({
    subject: cn, subjectPublicKey: s.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyEncipherment", "keyCertSign"], subjectAltName: [{ dNSName: "localhost" }], subjectKeyIdentifier: true },
  }, { key: s.key });
  return { certPem: pki.schema.x509.pemEncode(certDer, "CERTIFICATE"), keyPem: pki.schema.pkcs8.pemEncode(s.key, "PRIVATE KEY") };
}

function startServer(tls, handler, extra) {
  return new Promise(function (resolve) {
    var srv = https.createServer(Object.assign({ cert: tls.certPem, key: tls.keyPem }, extra || {}), handler);
    srv.on("clientError", function () { /* swallow -- a rejected handshake is the test's point */ });
    srv.listen(0, "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port }); });
  });
}
function urlFor(port, path) { return "https://127.0.0.1:" + port + (path || "/x"); }

// ---- config gates (socket-free) --------------------------------------------
async function testConfigGates() {
  var t = pki.transport.https({});
  check("1 an http: URL is refused", (await codeOf(t({ method: "GET", url: "http://ca.example/x" }))) === "transport/insecure-url");
  check("2 an unparseable URL is refused", (await codeOf(t({ method: "GET", url: "::::" }))) === "transport/bad-url");
  check("3 no explicit anchor and no useSystemStore is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x" }))) === "transport/no-trust-anchors");
  check("4 a sub-floor minVersion is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")], minVersion: "TLSv1.1" } }))) === "transport/bad-input");
  check("5 a negative maxResponseBytes is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")] }, maxResponseBytes: -5 }))) === "transport/bad-input");
  check("6 a maxResponseBytes above the ceiling is refused (tighten-only)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")] }, maxResponseBytes: pki.C.LIMITS.HTTP_MAX_RESPONSE_BYTES + 1 }))) === "transport/bad-input");
  check("6b a missing request object is refused (bad-url)", (await codeOf(t())) === "transport/bad-url");
  check("6c a malformed trust anchor fails closed at request init", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [undefined] } }))) === "transport/transport-error");
}

// ---- happy loopback round-trip ---------------------------------------------
async function testHappy() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) {
    var chunks = []; req.on("data", function (c) { chunks.push(c); }); req.on("end", function () {
      res.writeHead(200, { "Content-Type": "application/pkcs7-mime", "X-Echo": String(Buffer.concat(chunks)) });
      res.end("PONG");
    });
  });
  try {
    var t = pki.transport.https({});
    var idChecks = 0;
    // also exercises the mutual-TLS cert/key plumbing (the server ignores an unrequested client
    // cert) and a caller checkServerIdentity that tightens (returning undefined = accept).
    var r = await t({ method: "POST", url: urlFor(s.port), headers: { "content-type": "application/pkcs10" }, body: Buffer.from("PING"),
      tls: { anchors: [tls.certPem], servername: "localhost", cert: tls.certPem, key: tls.keyPem, checkServerIdentity: function () { idChecks++; return undefined; } } });
    check("7 the caller checkServerIdentity hook is invoked", idChecks >= 1);
    check("7 loopback POST resolves 200", r.status === 200);
    check("7 the body is returned as a Buffer", Buffer.isBuffer(r.body) && r.body.toString() === "PONG");
    check("7 response headers are lowercased", r.headers["content-type"] === "application/pkcs7-mime");
    check("7 the request body reached the server", r.headers["x-echo"] === "PING");
    check("7 the negotiated TLS protocol is surfaced", /^TLSv1\.[23]$/.test(r.tls.protocol));
    check("7 the peer certificate DER is surfaced", Buffer.isBuffer(r.tls.peerCertificate));
  } finally { s.srv.close(); }
}

// ---- server authentication failure (wrong anchor) --------------------------
async function testServerAuthFailed() {
  var server = await selfSigned("Real Server");
  var other = await selfSigned("Impostor");
  var s = await startServer(server, function (req, res) { res.end("x"); });
  try {
    var t = pki.transport.https({});
    check("8 a server whose cert does not chain to the anchor fails closed",
      (await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { anchors: [other.certPem], servername: "localhost" } }))) === "transport/server-auth-failed");
  } finally { s.srv.close(); }
}

// ---- response size cap: content-length pre-check AND streaming abort --------
async function testSizeCap() {
  var tls = await selfSigned("Big Server");
  var big = Buffer.alloc(4096, 0x41);
  var declared = await startServer(tls, function (req, res) { res.writeHead(200, { "content-type": "application/octet-stream" }); res.end(big); });
  try {
    var t = pki.transport.https({});
    check("9 a declared content-length over the cap is refused before streaming",
      (await codeOf(t({ method: "GET", url: urlFor(declared.port), tls: { anchors: [tls.certPem], servername: "localhost" }, maxResponseBytes: 1024 }))) === "transport/response-too-large");
  } finally { declared.srv.close(); }
  var chunkedTls = await selfSigned("Chunked Server");
  var chunked = await startServer(chunkedTls, function (req, res) {
    res.writeHead(200, { "content-type": "application/octet-stream", "transfer-encoding": "chunked" });
    res.write(Buffer.alloc(700, 0x42)); res.write(Buffer.alloc(700, 0x43)); res.end();
  });
  try {
    var t2 = pki.transport.https({});
    check("10 a chunked body crossing the cap is aborted while streaming",
      (await codeOf(t2({ method: "GET", url: urlFor(chunked.port), tls: { anchors: [chunkedTls.certPem], servername: "localhost" }, maxResponseBytes: 1024 }))) === "transport/response-too-large");
  } finally { chunked.srv.close(); }
}

// ---- timeout on a stalled server -------------------------------------------
async function testTimeout() {
  var tls = await selfSigned("Stalled Server");
  var s = await startServer(tls, function (req, res) { /* accept, never respond */ });
  try {
    var t = pki.transport.https({});
    check("11 a stalled response times out and destroys the socket",
      (await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" }, timeout: 300 }))) === "transport/timeout");
  } finally { s.srv.close(); }
}

// ---- TLS floor: client requires 1.3, server caps at 1.2 --------------------
async function testTlsFloor() {
  var tls = await selfSigned("Old Server");
  var s = await startServer(tls, function (req, res) { res.end("x"); }, { maxVersion: "TLSv1.2" });
  try {
    var t = pki.transport.https({});
    var code = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost", minVersion: "TLSv1.3" } }));
    check("12 a below-floor negotiation fails closed", code === "transport/tls-floor" || code === "transport/server-auth-failed");
  } finally { s.srv.close(); }
}

// ---- useSystemStore opt-in bypasses the anchor gate ------------------------
async function testSystemStore() {
  var t = pki.transport.https({});
  // No explicit anchor, but useSystemStore:true -> the anchor gate passes; the connection to a
  // dead port then fails as a transport error (proving the gate did not fire).
  var code = await codeOf(t({ method: "GET", url: "https://127.0.0.1:1/x", tls: { useSystemStore: true }, timeout: 500 }));
  check("13 useSystemStore:true opts into the bundled roots (anchor gate bypassed)", code === "transport/transport-error" || code === "transport/server-auth-failed");
}

// ---- protocol-client error parameterization --------------------------------
async function testErrorFactoryParam() {
  var seen = [];
  var t = pki.transport.https({ E: function (code, msg) { var e = new Error(msg); e.code = code; seen.push(code); return e; }, errPrefix: "acme" });
  check("14 a parameterized transport surfaces the caller's code prefix", (await codeOf(t({ method: "GET", url: "http://x/y" }))) === "acme/insecure-url");
}

// ---- a caller checkServerIdentity cannot disable name verification ---------
async function testIdentityHookCannotBypass() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) { res.end("x"); });
  try {
    var t = pki.transport.https({});
    // the cert's SAN is 'localhost'; connecting with a mismatched servername must fail closed EVEN
    // when the caller's checkServerIdentity returns undefined (accept) -- node's default RFC 6125
    // check runs first and its rejection is never bypassed.
    var code = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "wrong.invalid", checkServerIdentity: function () { return undefined; } } }));
    check("14b an accepting checkServerIdentity cannot disable hostname verification", code === "transport/server-auth-failed");
  } finally { s.srv.close(); }
}

async function main() {
  await testConfigGates();
  await testHappy();
  await testIdentityHookCannotBypass();
  await testServerAuthFailed();
  await testSizeCap();
  await testTimeout();
  await testTlsFloor();
  await testSystemStore();
  await testErrorFactoryParam();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
