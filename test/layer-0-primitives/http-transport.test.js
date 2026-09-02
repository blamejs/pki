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
var dns = require("node:dns");

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
  return { certDer: certDer, certPem: pki.schema.x509.pemEncode(certDer, "CERTIFICATE"), keyPem: pki.schema.pkcs8.pemEncode(s.key, "PRIVATE KEY") };
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
  check("3b a non-boolean useSystemStore ('false' string) is not a trust opt-in", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { useSystemStore: "false" } }))) === "transport/no-trust-anchors");
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
      res.writeHead(200, { "Content-Type": "application/pkcs7-mime", "X-Echo": String(Buffer.concat(chunks)),
        "X-Req-CL": String(req.headers["content-length"] || ""), "X-Req-TE": String(req.headers["transfer-encoding"] || "") });
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
    // the POST is framed length-delimited (a fixed Content-Length from the body), not Transfer-Encoding:
    // chunked -- strict enrollment / CMP appliances require a fixed-length DER POST.
    check("7 the POST carries a fixed Content-Length matching the body", r.headers["x-req-cl"] === "4");
    check("7 the POST is not sent Transfer-Encoding: chunked", r.headers["x-req-te"] === "");
    check("7 the negotiated TLS protocol is surfaced", /^TLSv1\.[23]$/.test(r.tls.protocol));
    check("7 the peer certificate DER is surfaced", Buffer.isBuffer(r.tls.peerCertificate));
    // The request body accepts any BufferSource, not only a Buffer: an ArrayBuffer body is written and
    // framed with the same fixed Content-Length. Before the widening the one-form Buffer.isBuffer gate
    // left an ArrayBuffer un-viewed and node's socket write rejected it.
    var pingAB = new ArrayBuffer(4); new Uint8Array(pingAB).set(Buffer.from("PING"));
    var rAB = await t({ method: "POST", url: urlFor(s.port), headers: { "content-type": "application/pkcs10" }, body: pingAB,
      tls: { anchors: [tls.certPem], servername: "localhost" } });
    check("7 an ArrayBuffer request body reaches the server, length-delimited (#68 http-transport body 1-form widening)",
      rAB.status === 200 && rAB.headers["x-echo"] === "PING" && rAB.headers["x-req-cl"] === "4");
    // a body is written for ANY body-bearing method, not only POST.
    var rput = await t({ method: "PUT", url: urlFor(s.port), body: Buffer.from("PUTBODY"), tls: { anchors: [tls.certPem], servername: "localhost" } });
    check("7 a PUT body is transmitted, not silently dropped", rput.headers["x-echo"] === "PUTBODY");
    // a caller that supplies Transfer-Encoding: chunked with a body must not leave BOTH framing headers on
    // the request (node rejects Content-Length + Transfer-Encoding together); the transport strips it and
    // frames length-delimited, so the request still completes.
    var rte = await t({ method: "POST", url: urlFor(s.port), headers: { "Transfer-Encoding": "chunked" }, body: Buffer.from("PING"),
      tls: { anchors: [tls.certPem], servername: "localhost" } });
    check("7 a caller Transfer-Encoding is stripped and the request completes", rte.status === 200 && rte.headers["x-echo"] === "PING");
    check("7 the request is framed by Content-Length, not chunked", rte.headers["x-req-cl"] === "4" && rte.headers["x-req-te"] === "");
  } finally { s.srv.close(); }
}

// ---- a raw DER trust anchor is accepted (converted to PEM) -----------------
async function testDerAnchor() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) { res.end("der"); });
  try {
    var t = pki.transport.https({});
    // the toolkit's native anchor form is a DER Buffer (what pki.est.cacerts returns); node's `ca`
    // needs PEM, so a DER anchor must be converted, not silently ignored (which would fail auth).
    var r = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certDer], servername: "localhost" } });
    check("14e a raw DER trust anchor is accepted (converted to PEM)", r.status === 200 && r.body.toString() === "der");
  } finally { s.srv.close(); }
}

// a DER anchor whose own bytes contain the "-----BEGIN" marker (in the subject) must still be wrapped:
// PEM is detected by the armor PREFIX, never an anywhere-substring that a DER field could spoof.
async function testDerAnchorWithArmorBytes() {
  var tls = await selfSigned("-----BEGIN sneaky");   // the subject CN embeds the PEM armor bytes
  check("14f fixture: the DER anchor really contains the -----BEGIN marker", tls.certDer.indexOf("-----BEGIN") > 0);
  var s = await startServer(tls, function (req, res) { res.end("armor"); });
  try {
    var t = pki.transport.https({});
    var r = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certDer], servername: "localhost" } });
    check("14f a DER anchor containing the PEM armor bytes is still wrapped and accepted", r.status === 200 && r.body.toString() === "armor");
  } finally { s.srv.close(); }
}

// ---- an IPv6-literal URL reaches TLS (square brackets stripped) -------------
async function testIpv6BracketHost() {
  var probe = require("node:net").createServer();
  var ok6 = await new Promise(function (res) { probe.once("error", function () { res(false); }); probe.listen(0, "::1", function () { probe.close(); res(true); }); });
  if (!ok6) { helpers.skip("IPv6 loopback unavailable in this environment"); return; }
  var tls = await selfSigned("Loopback A");   // SAN is 'localhost', not ::1
  var srv = https.createServer({ cert: tls.certPem, key: tls.keyPem }, function (req, res) { res.end("v6"); });
  var port = await new Promise(function (res) { srv.listen(0, "::1", function () { res(srv.address().port); }); });
  try {
    var t = pki.transport.https({});
    // Without the bracket strip, node would pass "[::1]" as a hostname and getaddrinfo would fail
    // (a DNS-shaped transport-error). Stripping the brackets makes node CONNECT to ::1 and reach the
    // TLS handshake; the localhost cert does not match ::1, so it fails at identity verification --
    // server-auth-failed proves the request reached TLS rather than failing name resolution. (The
    // identity-match encoding for an IPv6 IP SAN is node-version-sensitive, so this asserts the
    // reached-TLS behavior, not a positive match.)
    var code = await codeOf(t({ method: "GET", url: "https://[::1]:" + port + "/x", tls: { anchors: [tls.certPem] } }));
    check("14d an IPv6-literal URL reaches TLS (brackets stripped from the node hostname)", code === "transport/server-auth-failed");
  } finally { srv.close(); }
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

// ---- factory tls defaults are honored on a request with no per-request tls -
async function testTlsDefaultsHonored() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) { res.end("ok"); });
  try {
    var idChecks = 0;
    // a reusable transport binds tls defaults (anchors + servername + checkServerIdentity); a request
    // that carries no per-request tls must still use them (else SNI defaults to the 127.0.0.1 IP and
    // name verification fails against the localhost SAN, and the default hook never runs).
    var t = pki.transport.https({ tls: { anchors: [tls.certPem], servername: "localhost", checkServerIdentity: function () { idChecks++; return undefined; } } });
    var r = await t({ method: "GET", url: urlFor(s.port) });
    check("14c factory tls defaults (servername + checkServerIdentity) apply without per-request tls", r.status === 200 && idChecks >= 1);
  } finally { s.srv.close(); }
}

// ---- an explicit null servername overrides a factory default (SNI is not falsy-coalesced) -
async function testServernameNullOverride() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) { res.end("ok"); });
  try {
    // A request that overrides servername to null must SUPPRESS the transport's default servername, not
    // fall through to it: null is falsy, so a resolver coalescing with `reqTls.servername || default` would
    // leak the default. With the "localhost" default suppressed, SNI falls to the 127.0.0.1 host (an IP, so
    // no SNI is sent) and the localhost-SAN identity check fails closed, which is what proves the override.
    var t = pki.transport.https({ tls: { anchors: [tls.certPem], servername: "localhost" } });
    var code = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { servername: null } }));
    check("14d a null servername override suppresses the transport default rather than coalescing to it", code === "transport/server-auth-failed");
  } finally { s.srv.close(); }
}

// ---- a stalled connection setup is bounded by the wall-clock timeout -------
async function testConnectStallTimeout() {
  // a raw TCP server accepts the connection but never speaks TLS, so the handshake (connection setup,
  // before any HTTP response) stalls; the independent wall-clock timer must still fire.
  var raw = require("node:net").createServer(function () { /* accept, never respond */ });
  var port = await new Promise(function (res) { raw.listen(0, "127.0.0.1", function () { res(raw.address().port); }); });
  try {
    var t = pki.transport.https({});
    var code = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + port + "/x", tls: { anchors: [Buffer.from("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")] }, timeout: 400 }));
    check("14g a stalled connection setup is bounded by the wall-clock timeout", code === "transport/timeout");
  } finally { raw.close(); }
}

// ---- useSystemStore loads a real CA store ----------------------------------
async function testSystemStoreLoaded() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) { res.end("x"); });
  try {
    var t = pki.transport.https({});
    // useSystemStore loads the OS system + bundled CA store; a self-signed loopback cert is not in it,
    // so authentication fails closed -- the loader ran and the store is real, not a trust-all fallback.
    var code = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { useSystemStore: true, servername: "localhost" } }));
    check("14h useSystemStore loads the system store (a self-signed cert outside it fails closed)", code === "transport/server-auth-failed");
  } finally { s.srv.close(); }
}

// ---- a per-request identity check is not bypassed by socket reuse ----------
async function testSocketNotReusedAcrossIdentityPolicy() {
  var tls = await selfSigned("Loopback A");
  var s = await startServer(tls, function (req, res) { res.end("ok"); });
  try {
    var t = pki.transport.https({});
    // request 1 (accepting hook) succeeds and would leave a pooled keep-alive socket.
    var r1 = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost", checkServerIdentity: function () { return undefined; } } });
    // request 2 tightens with a REJECTING hook: a reused socket would skip the handshake identity
    // check and return 200. Fail-closed, and the caller-hook's own error surfaces as the cause --
    // proving the hook actually ran on request 2 (a fresh connection, not the pooled socket).
    var threw = false, causeMsg = null;
    try { await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost", checkServerIdentity: function () { return new Error("pinned mismatch"); } } }); }
    catch (e) { threw = true; causeMsg = e.cause && String(e.cause.message); }
    check("14i a per-request identity hook fires on every request (no socket-reuse bypass)", r1.status === 200 && threw && causeMsg === "pinned mismatch");
  } finally { s.srv.close(); }
}

// ---- the doubling accumulator reassembles a chunked body exactly ----------
async function testChunkedBodyAccumulation() {
  var tls = await selfSigned("Loopback A");
  var big = Buffer.alloc(50000);
  for (var i = 0; i < big.length; i++) big[i] = i & 0xff;
  var s = await startServer(tls, function (req, res) {
    res.writeHead(200, { "content-type": "application/octet-stream", "transfer-encoding": "chunked" });
    // many small writes force the accumulator through several grow + copy cycles at odd offsets.
    for (var off = 0; off < big.length; off += 137) res.write(big.subarray(off, Math.min(off + 137, big.length)));
    res.end();
  });
  try {
    var t = pki.transport.https({});
    var r = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } });
    check("14j a chunked body is reassembled byte-exactly by the doubling accumulator", r.status === 200 && r.body.length === 50000 && r.body.equals(big));
  } finally { s.srv.close(); }
}

// ---- the resolution-time SSRF classifier + filter, unit-driven over a fake resolver (every branch) ----------
async function testResolutionFilterUnits() {
  var ht = require("../../lib/http-transport");
  check("isBlockedIp: v4 special-use (RFC1918/loopback/CGNAT/link-local/benchmark/TEST-NET/6to4/multicast) blocked", ["10.0.0.1", "127.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "192.0.0.1", "192.88.99.1"].every(ht.isBlockedIp));
  check("isBlockedIp: v4 global public allowed (range edges)", !ht.isBlockedIp("8.8.8.8") && !ht.isBlockedIp("172.32.0.1") && !ht.isBlockedIp("192.169.0.1") && !ht.isBlockedIp("100.128.0.1") && !ht.isBlockedIp("198.20.0.1"));
  check("isBlockedIp: v6 non-global (loopback/ULA/link-local/site-local/multicast) + in-2000::/3 special-use (6to4/IETF/doc) blocked", ["::1", "::", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "fec0::1", "feff::1", "ff02::1", "2001:db8::1", "2002::1", "2001:2::1", "2001::1", "3fff::1", "3fff:fff::1"].every(ht.isBlockedIp));
  check("isBlockedIp: v6 true global unicast allowed (outside every special-use prefix) + a non-IP is not classified", !ht.isBlockedIp("2606:4700::1") && !ht.isBlockedIp("2001:4860:4860::8888") && !ht.isBlockedIp("3fff:1000::1") && !ht.isBlockedIp("example.com"));
  function resolver(err, addr, fam) { return function (h, o, cb) { cb(err, addr, fam); }; }
  function drive(lookupFn) { return new Promise(function (res) { lookupFn("host", {}, function (e, a) { res({ e: e, a: a }); }); }); }
  var errIn = new Error("dns fail");
  check("guardedLookup: a resolve error passes through unchanged", (await drive(ht._makeGuardedLookup(resolver(errIn)))).e === errIn);
  var pass = await drive(ht._makeGuardedLookup(resolver(null, "8.8.8.8", 4)));
  check("guardedLookup: a single public address passes (pinned)", pass.e == null && pass.a === "8.8.8.8");
  check("guardedLookup: a single private address is blocked", (await drive(ht._makeGuardedLookup(resolver(null, "127.0.0.1", 4)))).e.pkiBlockedAddress === true);
  check("guardedLookup: an all-array with any private entry is blocked", (await drive(ht._makeGuardedLookup(resolver(null, [{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.1", family: 4 }])))).e.pkiBlockedAddress === true);
  var passArr = await drive(ht._makeGuardedLookup(resolver(null, [{ address: "8.8.8.8", family: 4 }])));
  check("guardedLookup: an all-array of public addresses passes", passArr.e == null && Array.isArray(passArr.a));
}

// ---- blockPrivateAddresses: DNS-resolution SSRF (a hostname pointing at an internal address) -----------------
// The literal-address check alone misses a DNS NAME that resolves to a private / loopback / link-local address;
// blockPrivateAddresses installs a resolution-time filter that refuses -- and pins -- such a result. Proven on a
// loopback-resolving hostname (localhost -> 127.0.0.1 / ::1), the reachable stand-in for an internal service.
async function testBlockPrivateAddresses() {
  var tls = await selfSigned("Block Priv");
  // Bind the loopback server to exactly where localhost resolves, so the control request reaches it regardless of
  // the v4/v6 resolution order; the cert SAN is 'localhost', so connecting by that name verifies.
  var lh = await new Promise(function (res) { dns.lookup("localhost", function (e, addr) { res(e ? "127.0.0.1" : addr); }); });
  var s = await new Promise(function (resolve) {
    var srv = https.createServer({ cert: tls.certPem, key: tls.keyPem }, function (req, res) { res.end("OK"); });
    srv.on("clientError", function () { /* a rejected handshake is not this test's point */ });
    srv.listen(0, lh, function () { resolve({ srv: srv, port: srv.address().port }); });
  });
  try {
    var t = pki.transport.https({ tls: { anchors: [tls.certPem], servername: "localhost" } });
    var url = "https://localhost:" + s.port + "/x";   // a DNS NAME (not a literal) that resolves to a loopback address
    var ok = await t({ method: "GET", url: url });
    check("blockPrivateAddresses off: a loopback-resolving hostname connects (the literal check alone misses it)", ok.status === 200);
    check("blockPrivateAddresses on: a hostname resolving to a loopback address is refused (transport/blocked-address)",
      (await codeOf(t({ method: "GET", url: url, blockPrivateAddresses: true }))) === "transport/blocked-address");
    // A private IP LITERAL host: node does NOT call the custom lookup (nothing to resolve), so the option must
    // reject the literal in _prepare -- otherwise a direct transport caller would connect to it.
    check("blockPrivateAddresses on: a private IP-literal host is refused (node skips lookup for literals) -> transport/blocked-address",
      (await codeOf(t({ method: "GET", url: "https://127.0.0.1:9/x", blockPrivateAddresses: true }))) === "transport/blocked-address");
    check("blockPrivateAddresses on: an IPv6 private literal host is refused too",
      (await codeOf(t({ method: "GET", url: "https://[fc00::1]:9/x", blockPrivateAddresses: true }))) === "transport/blocked-address");
    check("blockPrivateAddresses off (default): the private-literal guard is opt-in, not applied",
      (await codeOf(t({ method: "GET", url: "https://127.0.0.1:9/x" }))) !== "transport/blocked-address");
  } finally { s.srv.close(); }
}

// ---- CONNECT-proxy support: a real localhost proxy that speaks the CONNECT tunnel ---------------------------
// A server that reads a CONNECT request, optionally demands Basic via a 407, and on success pipes the socket to a
// loopback upstream so the client's TLS-in-tunnel handshake reaches the real origin. With opts.tls it is a TLS
// server (an https proxy), so proxy credentials ride an authenticated channel.
function startConnectProxy(opts) {
  opts = opts || {};
  var net = require("node:net");
  var seen = [];
  function onConn(client) {
    var buf = "";
    var handled = false;
    function onData(chunk) {
      if (handled) return;
      buf += chunk.toString("latin1");
      var idx = buf.indexOf("\r\n\r\n");
      if (idx === -1) return;
      handled = true;
      client.removeListener("data", onData);
      var headerBlock = buf.slice(0, idx);
      var rest = buf.slice(idx + 4);
      var lines = headerBlock.split("\r\n");
      var reqLine = lines[0];
      var headers = {};
      for (var i = 1; i < lines.length; i++) { var c = lines[i].indexOf(":"); if (c !== -1) headers[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim(); }
      seen.push({ requestLine: reqLine, headers: headers });
      var pa = headers["proxy-authorization"] || "";
      if (opts.rejectStatus) { client.write("HTTP/1.1 " + opts.rejectStatus + " Blocked\r\nContent-Length: 0\r\n\r\n"); client.end(); return; }
      if (opts.requireAuth === "basic" && pa !== ("Basic " + Buffer.from(opts.username + ":" + opts.password).toString("base64"))) {
        client.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\nContent-Length: 0\r\n\r\n');
        client.end();
        return;
      }
      var target = reqLine.split(" ")[1] || "";
      var lastColon = target.lastIndexOf(":");
      var thost = target.slice(0, lastColon);
      if (thost.charAt(0) === "[" && thost.charAt(thost.length - 1) === "]") thost = thost.slice(1, -1);
      var tport = parseInt(target.slice(lastColon + 1), 10);
      var upstream = net.connect(tport, thost, function () {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (rest.length) upstream.write(Buffer.from(rest, "latin1"));
        client.pipe(upstream); upstream.pipe(client);
      });
      upstream.on("error", function () { try { client.destroy(); } catch (_e) { } });
    }
    client.on("data", onData);
    client.on("error", function () { });
  }
  var srv = opts.tls ? require("node:tls").createServer({ cert: opts.tls.certPem, key: opts.tls.keyPem }, onConn) : net.createServer(onConn);
  srv.on("tlsClientError", function () { });
  return new Promise(function (resolve) { srv.listen(0, "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port, seen: seen }); }); });
}

async function testProxyConnect() {
  var tls = await selfSigned("Origin A");
  var proxyTls = await selfSigned("Proxy");
  var origin = await startServer(tls, function (req, res) {
    res.setHeader("x-had-proxy-auth", req.headers["proxy-authorization"] ? "yes" : "no");
    res.end("TUNNELED");
  });
  var t = pki.transport.https({ tls: { anchors: [tls.certPem], servername: "localhost" } });
  var originUrl = "https://127.0.0.1:" + origin.port + "/x";
  var pTrust = { anchors: [proxyTls.certPem], servername: "localhost" };
  try {
    // PX-1 control: no proxy still reaches the origin directly
    var r1 = await t({ method: "GET", url: originUrl });
    check("PX-1 no proxy: the direct GET still succeeds", r1.status === 200 && r1.body.toString() === "TUNNELED");

    // PX-2 Basic proxy auth over an authenticated https-proxy CONNECT tunnel
    var pxBasic = await startConnectProxy({ tls: proxyTls, requireAuth: "basic", username: "u", password: "p" });
    try {
      var r2 = await t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxBasic.port, auth: { scheme: "basic", username: "u", password: "p" }, tls: pTrust } });
      check("PX-2 Basic proxy auth over an https proxy: the tunneled GET succeeds", r2.status === 200 && r2.body.toString() === "TUNNELED");
      check("PX-2b the CONNECT carried a Basic Proxy-Authorization", pxBasic.seen.some(function (s) { return (s.headers["proxy-authorization"] || "").slice(0, 6) === "Basic "; }));
      check("PX-4 the origin request carried NO Proxy-Authorization (hop-by-hop)", r2.headers["x-had-proxy-auth"] === "no");
      check("PX-12 the tls report reflects the ORIGIN handshake over the tunnel", !!(r2.tls && r2.tls.cipher && r2.tls.cipher.name));
    } finally { pxBasic.srv.close(); }

    // PX-3 an open http proxy (no auth) is tunnel-only and still works
    var pxOpen = await startConnectProxy({});
    try {
      var r3 = await t({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + pxOpen.port } });
      check("PX-3 an open http proxy tunnels (no credentials sent)", r3.status === 200 && r3.body.toString() === "TUNNELED");
      check("PX-3b the tunnel-only CONNECT carried NO Proxy-Authorization", pxOpen.seen.every(function (s) { return !s.headers["proxy-authorization"]; }));
    } finally { pxOpen.srv.close(); }

    // PX-14 the proxy channel is authenticated: an untrusted https-proxy certificate is refused
    var pxUntrusted = await startConnectProxy({ tls: proxyTls });
    try {
      check("PX-14 an untrusted https-proxy certificate -> proxy-tls-failed", (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxUntrusted.port, auth: { scheme: "basic", username: "u", password: "p" }, tls: { anchors: [tls.certPem], servername: "localhost" } } }))) === "transport/proxy-tls-failed");
    } finally { pxUntrusted.srv.close(); }

    // PX-6 a non-2xx CONNECT is fail-closed
    var px502 = await startConnectProxy({ rejectStatus: 502 });
    try {
      check("PX-6 a non-2xx CONNECT (502) -> proxy-connect-failed", (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + px502.port } }))) === "transport/proxy-connect-failed");
    } finally { px502.srv.close(); }

    // PX-7 an http proxy that demands auth, with no credentials -> proxy-auth-required (open-proxy path)
    var pxNoCred = await startConnectProxy({ requireAuth: "basic", username: "u", password: "p" });
    try {
      check("PX-7 a 407 with no credentials -> proxy-auth-required", (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + pxNoCred.port } }))) === "transport/proxy-auth-required");
    } finally { pxNoCred.srv.close(); }

    // PX-8 a wrong Basic password over an https proxy -> proxy-auth-failed (single attempt, no loop)
    var pxWrong = await startConnectProxy({ tls: proxyTls, requireAuth: "basic", username: "u", password: "correct" });
    try {
      check("PX-8 a wrong Basic password -> proxy-auth-failed", (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxWrong.port, auth: { scheme: "basic", username: "u", password: "wrong" }, tls: pTrust } }))) === "transport/proxy-auth-failed");
    } finally { pxWrong.srv.close(); }

    // PX-5 the security anchor: the origin cert is validated over the tunnel, never bypassed by the proxy
    var pxTrust = await startConnectProxy({});
    try {
      var otherTls = await selfSigned("Untrusted Origin");
      var tNoTrust = pki.transport.https({ tls: { anchors: [otherTls.certPem], servername: "localhost" } });
      check("PX-5 an untrusted origin cert over the tunnel -> server-auth-failed (trust NOT bypassed)", (await codeOf(tNoTrust({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + pxTrust.port } }))) === "transport/server-auth-failed");
    } finally { pxTrust.srv.close(); }

    // PX-13 an IPv6 origin: the CONNECT authority brackets the host (RFC 9112 sec. 3.2.3), so the proxy can parse it
    var ok6 = await new Promise(function (res) { var p = require("node:net").createServer(); p.once("error", function () { res(false); }); p.listen(0, "::1", function () { p.close(); res(true); }); });
    if (ok6) {
      var origin6 = await new Promise(function (resolve) {
        var srv = https.createServer({ cert: tls.certPem, key: tls.keyPem }, function (req, r) { r.end("V6"); });
        srv.on("clientError", function () { });
        srv.listen(0, "::1", function () { resolve({ srv: srv, port: srv.address().port }); });
      });
      var px6 = await startConnectProxy({});
      try {
        var r6 = await t({ method: "GET", url: "https://[::1]:" + origin6.port + "/x", proxy: { url: "http://127.0.0.1:" + px6.port } });
        check("PX-13 IPv6 origin: the tunneled GET succeeds", r6.status === 200 && r6.body.toString() === "V6");
        check("PX-13b the CONNECT authority brackets the IPv6 host ([::1]:port)", px6.seen.some(function (s) { return s.requestLine.indexOf("[::1]:" + origin6.port) !== -1; }));
      } finally { px6.srv.close(); origin6.srv.close(); }
    }
  } finally { origin.srv.close(); }

  // PX-9 config-time rejects (no socket opened)
  check("PX-9a a non-object proxy is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: "http://p:8080" }))) === "transport/bad-proxy");
  check("PX-9b an unparseable proxy.url is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "::::" } }))) === "transport/bad-proxy");
  check("PX-9c auth over a plaintext http proxy is refused -> proxy-auth-requires-tls", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "http://p:8080", auth: { scheme: "basic", username: "u", password: "p" } } }))) === "transport/proxy-auth-requires-tls");
  check("PX-9d Digest proxy auth is refused -> proxy-unsupported-scheme", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "digest", username: "u", password: "p" } } }))) === "transport/proxy-unsupported-scheme");
  check("PX-9e an unknown proxy.auth.scheme is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "ntlm", username: "u", password: "p" } } }))) === "transport/bad-proxy");
  check("PX-9f a mistyped proxy key is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "http://p:8080", usernam: "x" } }))) === "transport/bad-proxy");
  check("PX-9g a Basic user-id with a colon is refused (RFC 7617)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "basic", username: "a:b", password: "p" }, tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  check("PX-9h an https proxy with no tls trust is refused -> no-trust-anchors", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080" } }))) === "transport/no-trust-anchors");
  check("PX-10 an http origin with a proxy is refused (https-only) -> insecure-url", (await codeOf(t({ method: "GET", url: "http://ca.example/x", proxy: { url: "http://p:8080" } }))) === "transport/insecure-url");

  // PX-11 SSRF: a private proxy address is blocked when blockPrivateAddresses is on (the block moves to the proxy hop)
  check("PX-11 blockPrivateAddresses on: a private proxy literal -> blocked-address", (await codeOf(t({ method: "GET", url: "https://example.com/x", proxy: { url: "http://127.0.0.1:8080" }, blockPrivateAddresses: true }))) === "transport/blocked-address");
  // PX-11b a proxy HOSTNAME that resolves to a private address is blocked at CONNECT (the DNS-resolution path), and
  // the address-policy rejection keeps its blocked-address verdict rather than collapsing to proxy-connect-failed.
  check("PX-11b blockPrivateAddresses on: a proxy hostname resolving to loopback -> blocked-address", (await codeOf(t({ method: "GET", url: "https://example.com/x", proxy: { url: "http://localhost:9" }, blockPrivateAddresses: true }))) === "transport/blocked-address");
}

async function main() {
  await testConfigGates();
  await testResolutionFilterUnits();
  await testBlockPrivateAddresses();
  await testChunkedBodyAccumulation();
  await testConnectStallTimeout();
  await testSystemStoreLoaded();
  await testSocketNotReusedAcrossIdentityPolicy();
  await testHappy();
  await testIdentityHookCannotBypass();
  await testTlsDefaultsHonored();
  await testServernameNullOverride();
  await testDerAnchor();
  await testDerAnchorWithArmorBytes();
  await testIpv6BracketHost();
  await testServerAuthFailed();
  await testSizeCap();
  await testTimeout();
  await testTlsFloor();
  await testSystemStore();
  await testErrorFactoryParam();
  await testProxyConnect();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
