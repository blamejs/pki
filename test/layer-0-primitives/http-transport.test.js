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
var nodeTls = require("node:tls");
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

// A cert whose only SAN is an iPAddress (no dNSName), to prove the proxy identity is verified against a configured
// IP servername rather than the connect host name.
async function selfSignedIpSan(cn, ip) {
  var s = signing.makeSigner("ec-p256", { cn: cn });
  var certDer = await pki.x509.sign({
    subject: cn, subjectPublicKey: s.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyEncipherment", "keyCertSign"], subjectAltName: [{ iPAddress: ip }], subjectKeyIdentifier: true },
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
  /* A request that names no tls at all still has a record of the settings built for it, and an empty
     object literal inherits from Object.prototype, so a value installed there would answer for the
     opt-in that turns this refusal off. The record is built with no prototype. This is the backstop
     for every verb that delegates its fetch here, each of which reads the same setting from a record
     of its own. */
  var polluted;
  try {
    Object.prototype.useSystemStore = true;
    polluted = await codeOf(t({ method: "GET", url: "https://ca.example/x" }));
  } finally { delete Object.prototype.useSystemStore; }
  check("3c a useSystemStore on Object.prototype is not a trust opt-in either (" + polluted + ")",
    polluted === "transport/no-trust-anchors");
  var pollutedDefaults;
  try {
    Object.prototype.useSystemStore = true;
    pollutedDefaults = await codeOf(pki.transport.https({})({ method: "GET", url: "https://ca.example/x" }));
  } finally { delete Object.prototype.useSystemStore; }
  check("3d nor when the transport was built with no tls defaults (" + pollutedDefaults + ")",
    pollutedDefaults === "transport/no-trust-anchors");
  check("4 a sub-floor minVersion is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")], minVersion: "TLSv1.1" } }))) === "transport/bad-input");
  check("5 a negative maxResponseBytes is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")] }, maxResponseBytes: -5 }))) === "transport/bad-input");
  check("6 a maxResponseBytes above the ceiling is refused (tighten-only)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")] }, maxResponseBytes: pki.C.LIMITS.HTTP_MAX_RESPONSE_BYTES + 1 }))) === "transport/bad-input");
  // The name a TLS handshake is opened under is read again twice after it is accepted: by the TLS
  // layer for the name sent, and as the identity the server certificate is matched against. A value
  // that is not already a string converts afresh at each, so one name is sent and another verified.
  // The proxy arm has always typed this option; the origin arm now does too.
  var twoFacedSni = { toString: function () { return "ca.example"; } };
  check("6b1 a non-string tls.servername is refused at request init",
    (await codeOf(t({ method: "GET", url: "https://ca.example/x", tls: { anchors: [Buffer.from("x")], servername: twoFacedSni } }))) === "transport/bad-input");
  check("6b2 and so is one supplied as a transport default",
    (await codeOf(pki.transport.https({ tls: { anchors: [Buffer.from("x")], servername: twoFacedSni } })({ method: "GET", url: "https://ca.example/x" }))) === "transport/bad-input");
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
    // The identity question is answered through a captured reference, not the writable module export.
    // node:tls.checkServerIdentity RETURNS A VERDICT, so a replacement answering with no error is the
    // server-authentication step reporting success for a certificate issued to another host. The
    // request below asks for a name the server's certificate does not carry.
    var nodeTlsMod = require("node:tls");
    var realCSI = nodeTlsMod.checkServerIdentity;
    var csiCalls = 0;
    var wrongHostCode;
    try {
      nodeTlsMod.checkServerIdentity = function () { csiCalls += 1; return undefined; };
      wrongHostCode = await codeOf(t({ method: "GET", url: urlFor(s.port),
        tls: { anchors: [tls.certPem], servername: "not-the-server.example" } }));
    } finally {
      nodeTlsMod.checkServerIdentity = realCSI;
    }
    check("7 the TLS identity check does not consult a replaced node:tls export (calls=" +
      csiCalls + ")", csiCalls === 0);
    check("7 and a certificate for another host is still refused (" + wrongHostCode + ")",
      wrongHostCode === "transport/server-auth-failed");
    check("7 loopback POST resolves 200", r.status === 200);
    check("7 the body is returned as a Buffer", Buffer.isBuffer(r.body) && r.body.toString() === "PONG");
    check("7 response headers are lowercased", r.headers["content-type"] === "application/pkcs7-mime");
    check("7 the request body reached the server", r.headers["x-echo"] === "PING");
    // the POST is framed length-delimited (a fixed Content-Length from the body), not Transfer-Encoding:
    // chunked -- strict enrollment / CMP appliances require a fixed-length DER POST.
    check("7 the POST carries a fixed Content-Length matching the body", r.headers["x-req-cl"] === "4");
    check("7 the POST is not sent Transfer-Encoding: chunked", r.headers["x-req-te"] === "");
    check("7 the negotiated TLS protocol is surfaced", /^TLSv1\.[23]$/.test(r.tls.protocol));
    // Request headers parsed out of JSON can carry a __proto__ member. The copy the transport
    // makes of them keeps its own entries only, so the member lands as a header field rather than
    // as the copy's prototype. Node drops a field by that name further down, so the request goes
    // out the same either way; what this pins is that supplying one still produces a normal
    // request instead of a copy whose later lookups answer from the caller's value.
    var protoHeaders = JSON.parse('{"content-type":"application/pkcs10","__proto__":"probe"}');
    var rProto = await t({ method: "POST", url: urlFor(s.port), headers: protoHeaders, body: Buffer.from("PING"),
      tls: { anchors: [tls.certPem], servername: "localhost" } });
    check("7 a __proto__ member among the request headers leaves the request well-formed",
      rProto.status === 200 && rProto.headers["x-echo"] === "PING" && rProto.headers["x-req-cl"] === "4");
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
// The decisions this module makes are read through the operations it captured at load, so a
// co-resident replacement cannot answer them. Both vectors drive the shipped verb against a real
// loopback server whose certificate is trusted ONLY by the anchor the caller names, so losing the
// anchor is observable as a failed handshake rather than as an internal difference.
async function testCapturedOperations() {
  var tls = await selfSigned("Captured Ops");
  var s = await startServer(tls, function (req, res) { res.end("captured"); });
  var realConcat = Array.prototype.concat;
  try {
    var t = pki.transport.https({});
    /** The anchor list is built by appending to an empty array. Through the live prototype, a
     *  replacement answering [] for an empty receiver left the list empty, nothing was assigned to
     *  node's `ca`, and the connection fell back to the system store: a caller that named an anchor
     *  got an unpinned handshake instead. Narrowed to an empty receiver so the rest of the request
     *  still runs and the vector measures this call and not an earlier one. */
    var hijacked = 0;
    Array.prototype.concat = function () {
      if (this.length === 0) { hijacked += 1; return []; }
      return realConcat.apply(this, arguments);
    };
    var r1 = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } });
    Array.prototype.concat = realConcat;
    // The anchor still reaches the handshake AND the replacement was never asked: a verdict alone
    // could come out right while the module still read the prototype on some other path.
    check("14g a replaced Array.prototype.concat is never consulted for the anchor list (" + hijacked + " call(s))",
      r1.status === 200 && r1.body.toString() === "captured" && hijacked === 0);

    /** `tls` is read ONCE. Read twice, the second read decided: a value present to the test and
     *  absent to the use left the TLS record undefined and the anchor read threw a raw TypeError out
     *  of the verb, which is neither this module's typed refusal nor a connection. */
    var tlsReads = 0;
    var twoFacedRequest = { method: "GET", url: urlFor(s.port) };
    Object.defineProperty(twoFacedRequest, "tls", {
      enumerable: true,
      get: function () {
        tlsReads += 1;
        return tlsReads === 1 ? { anchors: [tls.certPem], servername: "localhost" } : undefined;
      },
    });
    var out2 = await codeOf(t(twoFacedRequest));
    check("14g a tls record read twice cannot throw untyped out of the verb (" + out2 + ", " + tlsReads + " read(s))",
      out2 === "NO-THROW" && tlsReads === 1);

    /** The settings a refusal is decided on are read once each. Each of these answered one value to
     *  the presence test and another to the use, so the check and the connection disagreed: the
     *  private-address refusal was asked for and not applied, the identity the handshake is accepted
     *  under was swapped after it was checked, and the caller's identity hook disappeared after it
     *  had been found to be a function. */
    var blockReads = 0;
    var twoFacedBlock = { method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } };
    Object.defineProperty(twoFacedBlock, "blockPrivateAddresses", {
      enumerable: true,
      get: function () { blockReads += 1; return blockReads === 1; },
    });
    var blocked = await codeOf(t(twoFacedBlock));
    check("14i a blockPrivateAddresses read twice still refuses the loopback address (" + blocked + ")",
      blocked === "transport/blocked-address" && blockReads === 1);

    var sniReads = 0;
    var twoFacedSniTls = { anchors: [tls.certPem] };
    Object.defineProperty(twoFacedSniTls, "servername", {
      enumerable: true,
      get: function () { sniReads += 1; return sniReads === 1 ? "localhost" : "other.example"; },
    });
    var sniOut = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: twoFacedSniTls }));
    check("14i a servername read twice is the one the handshake was checked against (" + sniOut + ")",
      sniOut === "NO-THROW" && sniReads === 1);

    var csiReads = 0, csiCalled = 0;
    var twoFacedCsiTls = { anchors: [tls.certPem], servername: "localhost" };
    Object.defineProperty(twoFacedCsiTls, "checkServerIdentity", {
      enumerable: true,
      get: function () {
        csiReads += 1;
        return csiReads === 1 ? function () { csiCalled += 1; return new Error("refused by the caller's hook"); } : undefined;
      },
    });
    var csiOut = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: twoFacedCsiTls }));
    check("14i an identity hook read twice is the one that runs (" + csiOut + ", called " + csiCalled + ")",
      csiReads === 1 && csiCalled === 1 && csiOut !== "NO-THROW");

    /** A sparse anchor list is refused rather than read. A descriptor walk cannot see a HOLE, so a
     *  gap answered by an accessor on Array.prototype was validated as one anchor and converted as
     *  another. */
    var sparse = [tls.certPem, tls.certPem, tls.certPem];
    sparse.length = 4;
    var protoReads = 0;
    // The accessor answers only for THIS array, and an assignment still defines an own property, so
    // node's own arrays keep working while the probe runs: a bare getter on the prototype makes
    // every `push` past index 2 anywhere in the process throw.
    Object.defineProperty(Array.prototype, "3", {
      configurable: true, enumerable: false,
      get: function () {
        if (this !== sparse) return undefined;
        protoReads += 1;
        return protoReads === 1 ? tls.certPem : "-----BEGIN CERTIFICATE-----\nUSED\n-----END CERTIFICATE-----\n";
      },
      set: function (v) { Object.defineProperty(this, "3", { value: v, writable: true, enumerable: true, configurable: true }); },
    });
    var sparseOut;
    try {
      sparseOut = await codeOf(t({ method: "GET", url: urlFor(s.port),
        tls: { anchors: [tls.certPem], servername: "localhost" },
        proxy: { url: "https://127.0.0.1:1/", tls: { anchors: sparse } } }));
    } finally { delete Array.prototype[3]; }
    check("14i a sparse proxy anchor list is refused rather than read through the prototype (" + sparseOut + ")",
      sparseOut === "transport/bad-proxy");

    /** The address the blocklist cleared is the address the socket layer is handed. The resolver's
     *  own entry was forwarded, so an entry whose `address` answered a public value to the check and
     *  a loopback one afterwards reached loopback with the private-address block in force. */
    var transportMod = require("../../lib/http-transport");
    var addrReads = 0;
    var guarded = transportMod._makeGuardedLookup(function (host, opts, cb) {
      var entry = {};
      Object.defineProperty(entry, "address", {
        enumerable: true,
        get: function () { addrReads += 1; return addrReads === 1 ? "93.184.216.34" : "127.0.0.1"; },
      });
      entry.family = 4;
      cb(null, [entry]);
    });
    var handed = await new Promise(function (res) {
      guarded("host.example", { all: true }, function (err, out) { res(err ? ("ERR:" + (err.pkiBlockedAddress ? "blocked" : "other")) : out); });
    });
    var handedAddr = Array.isArray(handed) ? handed[0].address : handed;
    check("14i the address the blocklist cleared is the one handed on (" + handedAddr + ", " + addrReads + " read(s))",
      handedAddr === "93.184.216.34" && addrReads === 1);

    /** The bytes the caller reads are the bytes that arrived. `Buffer.prototype.copy` moved both the
     *  received bytes and each arriving chunk, so a replacement installed after load decided what
     *  the response body holds. */
    var realBufCopy = Buffer.prototype.copy;
    var copyCalls = 0;
    var bodyOut;
    try {
      Buffer.prototype.copy = function () { copyCalls += 1; return realBufCopy.apply(this, arguments); };
      var rBody = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } });
      bodyOut = rBody.body.toString();
    } finally { Buffer.prototype.copy = realBufCopy; }
    check("14i the response body is framed without the live Buffer.prototype.copy (" + bodyOut + ", " + copyCalls + " call(s))",
      bodyOut === "captured" && copyCalls === 0);

    /** A trust list is assembled without consulting a spreading hook. `Array.prototype.concat` is
     *  specified to read `Symbol.isConcatSpreadable` on each argument, so capturing the method left
     *  an inherited hook able to replace a validated anchor. */
    var spreadReads = 0;
    Object.defineProperty(Array.prototype, Symbol.isConcatSpreadable, {
      configurable: true, enumerable: false,
      get: function () { spreadReads += 1; return false; },
    });
    var spreadOut;
    try {
      spreadOut = await codeOf(t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } }));
    } finally { delete Array.prototype[Symbol.isConcatSpreadable]; }
    check("14i a spreading hook is never consulted while the trust list is built (" + spreadOut + ", " + spreadReads + " read(s))",
      spreadOut === "NO-THROW" && spreadReads === 0);

    /** The body is as long as the bytes that were counted. Built with `Buffer.from` over the received
     *  view, the LENGTH came from that object's own `valueOf` and `length`, so a replacement returned
     *  more bytes than arrived and more than the cap allowed. */
    var realValueOf = Buffer.prototype.valueOf;
    var capOut, capLen;
    try {
      // Answers hostilely only for a buffer the size of this response, so the rest of the request
      // keeps working and the vector measures the body rather than an earlier step.
      Buffer.prototype.valueOf = function () {
        return this.length === 8 ? Buffer.alloc(64, 0x58) : realValueOf.call(this);
      };
      var rCap = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } });
      capLen = rCap.body.length;
      capOut = rCap.body.toString();
    } finally { Buffer.prototype.valueOf = realValueOf; }
    check("14i the body is the bytes that were counted, whatever valueOf answers (" + capLen + " bytes)",
      capOut === "captured" && capLen === 8);

    /** The arriving chunk is measured from its bytes. Read off a `length` property, a value answering
     *  one size to the cap and another to the accounting resolved a response longer than the bytes
     *  that arrived and longer than the cap allowed. */
    var chunkOut, chunkLen;
    var realOn = require("node:http").IncomingMessage.prototype.on;
    try {
      require("node:http").IncomingMessage.prototype.on = function (ev, fn) {
        if (ev !== "data") return realOn.call(this, ev, fn);
        return realOn.call(this, ev, function (chunk) {
          var real = chunk.byteLength;
          try {
            Object.defineProperty(chunk, "length", {
              configurable: true,
              get: function () { return real * 2; },
            });
          } catch (_e) { /* a chunk that refuses the redefinition is measured as it is */ }
          return fn(chunk);
        });
      };
      var rChunk = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } });
      chunkLen = rChunk.body.length;
      chunkOut = rChunk.body.toString();
    } finally { require("node:http").IncomingMessage.prototype.on = realOn; }
    check("14i a chunk whose length overstates its bytes cannot lengthen the response (" + chunkLen + " bytes)",
      chunkLen === 8 && chunkOut === "captured");

    /** The socket is this module's to open. `agent: false` still left the construction on the agent
     *  prototype, so a replacement there returned a connection to another destination and the
     *  request went out over it: an `https:` request reached a plaintext listener that presented no
     *  certificate. */
    var httpsAgentProto = require("node:https").Agent.prototype;
    var realCreate = httpsAgentProto.createConnection;
    var agentCalls = 0, agentOut;
    try {
      httpsAgentProto.createConnection = function () {
        agentCalls += 1;
        return realCreate.apply(this, arguments);
      };
      var rAgent = await t({ method: "GET", url: urlFor(s.port), tls: { anchors: [tls.certPem], servername: "localhost" } });
      agentOut = rAgent.body.toString();
    } finally { httpsAgentProto.createConnection = realCreate; }
    check("14i the agent's connection builder is never consulted (" + agentOut + ", " + agentCalls + " call(s))",
      agentOut === "captured" && agentCalls === 0);

    /** The CONNECT socket is opened the same way, which matters more there: the request that carries
     *  `Proxy-Authorization` would otherwise be dispatched through the replaced builder, which can
     *  answer with a raw socket in place of the proxy's TLS connection. */
    var httpAgentProto = require("node:http").Agent.prototype;
    var realHttpCreate = httpAgentProto.createConnection;
    var realHttpsCreate = httpsAgentProto.createConnection;
    var proxyAgentCalls = 0, proxyOut;
    try {
      httpAgentProto.createConnection = function () { proxyAgentCalls += 1; return realHttpCreate.apply(this, arguments); };
      httpsAgentProto.createConnection = function () { proxyAgentCalls += 1; return realHttpsCreate.apply(this, arguments); };
      proxyOut = await codeOf(t({ method: "GET", url: urlFor(s.port),
        tls: { anchors: [tls.certPem], servername: "localhost" },
        proxy: { url: "http://127.0.0.1:1/" }, timeout: 1500 }));
    } finally {
      httpAgentProto.createConnection = realHttpCreate;
      httpsAgentProto.createConnection = realHttpsCreate;
    }
    check("14i nor on the proxy CONNECT path (" + proxyOut + ", " + proxyAgentCalls + " call(s))",
      proxyOut === "transport/proxy-connect-failed" && proxyAgentCalls === 0);

    /** The transport's default identity hook is read only where the request supplied none. Read
     *  anyway, an accessor the per-request override opted out of still ran and could refuse the
     *  request before it connected. */
    var defaultCsiReads = 0;
    var defaultTls = { anchors: [tls.certPem] };
    Object.defineProperty(defaultTls, "checkServerIdentity", {
      enumerable: true,
      get: function () { defaultCsiReads += 1; throw new Error("the default hook must not be read when the request overrides it"); },
    });
    var tDefaults = pki.transport.https({ tls: defaultTls });
    var overrideOut = await codeOf(tDefaults({ method: "GET", url: urlFor(s.port),
      tls: { anchors: [tls.certPem], servername: "localhost", checkServerIdentity: function () { return undefined; } } }));
    check("14i a per-request identity hook keeps the default from being read (" + overrideOut + ", " + defaultCsiReads + " read(s))",
      overrideOut === "NO-THROW" && defaultCsiReads === 0);
  } finally {
    Array.prototype.concat = realConcat;
    s.srv.close();
  }
}

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

// ---- the peerChain handshake is bounded by a WALL-CLOCK deadline -----------
// `socket.setTimeout` bounds INACTIVITY, not elapsed time: every byte that arrives resets it. An endpoint
// that trickles handshake bytes below that interval keeps the socket "active" forever and the advertised
// timeout never fires, so `pki.transport.peerChain` (and the verbs built on it) hang past their budget.
// The server here accepts the connection and writes one byte every 40ms without ever speaking TLS, which
// is inactivity-timeout-proof, so only an absolute timer can end it.
async function testPeerChainTrickleDeadline() {
  var net = require("node:net");
  var sockets = [];
  var raw = net.createServer(function (s) {
    sockets.push(s);
    // A well-formed TLS record HEADER announcing a 16384-byte handshake body, then the body one byte at a
    // time. The client cannot act on a partial record, so it waits; every byte resets an inactivity
    // timeout while the record never completes. Writing garbage instead makes TLS fail fast, which tests
    // the error path rather than the stall.
    var iv = null;
    // The socket's own state decides whether to write, rather than a try/catch around the write: a
    // destroyed socket is the only reason it would fail here, and asking is clearer than swallowing.
    s.on("data", function () {
      if (iv !== null || s.destroyed) return;
      s.write(Buffer.from([0x16, 0x03, 0x03, 0x40, 0x00]));
      iv = setInterval(function () {
        if (s.destroyed) { clearInterval(iv); return; }
        s.write(Buffer.from([0x00]));
      }, 40);
    });
    // The client destroys the connection when its deadline fires, which surfaces here as an error or a
    // close; either ends the trickle.
    s.on("error", function () { if (iv !== null) clearInterval(iv); });
    s.on("close", function () { if (iv !== null) clearInterval(iv); });
  });
  var port = await new Promise(function (res) { raw.listen(0, "127.0.0.1", function () { res(raw.address().port); }); });
  try {
    var started = Date.now();
    var code = await codeOf(pki.transport.peerChain({
      url: "https://127.0.0.1:" + port + "/",
      tls: { anchors: [Buffer.from("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")] },
      timeout: 400,
    }));
    var elapsed = Date.now() - started;
    check("14h a trickling handshake is ended by the wall-clock deadline (" + code + ")",
      code === "transport/timeout");
    // The budget is 400ms. A generous ceiling, since the point is that it ends at all rather than the
    // precision of when: an inactivity timeout would never have fired while bytes kept arriving.
    check("14i and it ends within a bounded wall-clock, not when the peer stops writing (" + elapsed + "ms)",
      elapsed < 8000);
  } finally {
    sockets.forEach(function (s) { s.destroy(); });   // destroy() is idempotent and does not throw
    raw.close();
  }
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
  // The literal is divided into octets, and dividing a string on a separator is specified to look a
  // `Symbol.split` method up on that separator and call it, so the separator's prototype chain is
  // part of the operation and taking the split from a capture does not close it. A hook answering
  // with a public address's octets clears this refusal for a loopback literal. MEASURED: this is
  // engine-dependent -- Node 24.21 performs the lookup and Node 26.9 fast-paths a primitive-string
  // separator past it -- so the assertion is on the verdict, which must hold on either.
  var realSplitHook = Object.getOwnPropertyDescriptor(String.prototype, Symbol.split);
  var hookedV4, hookedV6;
  try {
    Object.defineProperty(String.prototype, Symbol.split, {
      value: function () { return ["93", "184", "216", "34"]; }, configurable: true,
    });
    hookedV4 = ht.isBlockedIp("127.0.0.1");
    hookedV6 = ht.isBlockedIp("fc00::1");
  } finally {
    if (realSplitHook) Object.defineProperty(String.prototype, Symbol.split, realSplitHook);
    else delete String.prototype[Symbol.split];
  }
  check("isBlockedIp: an installed @@split hook cannot clear the refusal for a loopback literal", hookedV4 === true);
  check("isBlockedIp: nor for a unique-local IPv6 literal", hookedV6 === true);
  check("isBlockedIp: v4 global public allowed (range edges)", !ht.isBlockedIp("8.8.8.8") && !ht.isBlockedIp("172.32.0.1") && !ht.isBlockedIp("192.169.0.1") && !ht.isBlockedIp("100.128.0.1") && !ht.isBlockedIp("198.20.0.1"));
  check("isBlockedIp: v6 non-global (loopback/ULA/link-local/site-local/multicast) + in-2000::/3 special-use (6to4/IETF/doc) blocked", ["::1", "::", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "fec0::1", "feff::1", "ff02::1", "2001:db8::1", "2002::1", "2001:2::1", "2001::1", "3fff::1", "3fff:fff::1"].every(ht.isBlockedIp));
  check("isBlockedIp: v6 true global unicast allowed (outside every special-use prefix) + a non-IP is not classified", !ht.isBlockedIp("2606:4700::1") && !ht.isBlockedIp("2001:4860:4860::8888") && !ht.isBlockedIp("3fff:1000::1") && !ht.isBlockedIp("example.com"));
  // The classifier converts its argument, so a value that is not already a string is converted once
  // for the family check and again for the octet scan, and the SECOND answer decides. A resolver
  // supplied through `opts.lookup` reaches this with whatever it yields, and the verb is public, so
  // a value that cannot be classified is refused rather than measured twice.
  var coerceReads = 0;
  var twoFaced = { toString: function () { coerceReads += 1; return coerceReads === 1 ? "127.0.0.1" : "93.184.216.34"; } };
  check("isBlockedIp: a value converted afresh per read is blocked rather than classified twice",
    ht.isBlockedIp(twoFaced) === true);
  check("isBlockedIp: a boxed string is blocked whichever address it holds, and a plain string is unaffected",
    ht.isBlockedIp(new String("127.0.0.1")) === true && ht.isBlockedIp(new String("8.8.8.8")) === true &&
    ht.isBlockedIp("8.8.8.8") === false);
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
    // The IPv6 arm of the blocklist folds the address through String.prototype.toLowerCase before
    // classifying it, and the classification ADMITS anything inside global unicast. Read off the live
    // prototype, a replacement that answers with a global-unicast spelling for a private address
    // turns a refusal into a connection attempt. The replacement is narrowed to the one address so an
    // earlier step does not break first and hide the gate.
    // The substitute has to be an address the classifier ADMITS, or the refusal comes from another
    // rule and the probe measures nothing: 2001:db8:: is the documentation range and is blocked on
    // its own, while 2606:4700::1 is ordinary global unicast. This control establishes that.
    check("CONTROL a global-unicast IPv6 literal is not blocked, so it is a valid substitute",
      (await codeOf(t({ method: "GET", url: "https://[2606:4700::1]:9/x", blockPrivateAddresses: true }))) !== "transport/blocked-address");
    var realLowerT = String.prototype.toLowerCase;
    var foldedCode;
    try {
      String.prototype.toLowerCase = function () {
        var s = realLowerT.call(this);
        return s === "fc00::1" ? "2606:4700::1" : s;
      };
      foldedCode = await codeOf(t({ method: "GET", url: "https://[fc00::1]:9/x", blockPrivateAddresses: true }));
    } finally {
      String.prototype.toLowerCase = realLowerT;
    }
    check("blockPrivateAddresses on: the IPv6 blocklist still refuses under a replaced toLowerCase (" +
      foldedCode + ")", foldedCode === "transport/blocked-address");
    // The IPv4 arm splits the literal into octets, so a replaced String.prototype.split answering
    // with octets of a public address is the same admission in the other family.
    var realSplit = String.prototype.split;
    var splitCode;
    try {
      String.prototype.split = function (sep) {
        var parts = realSplit.call(this, sep);
        return (parts.length === 4 && parts[0] === "127") ? ["93", "184", "216", "34"] : parts;
      };
      splitCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:9/x", blockPrivateAddresses: true }));
    } finally {
      String.prototype.split = realSplit;
    }
    check("blockPrivateAddresses on: the IPv4 blocklist still refuses under a replaced split (" +
      splitCode + ")", splitCode === "transport/blocked-address");
    // The hextets are produced by the split and READ by parseInt, so converting the split without
    // the conversion leaves the gate as open as before: making parseInt("fc00", 16) answer 0x2606
    // puts the address inside global unicast and the refusal is skipped.
    var realParseInt = global.parseInt;
    var intCode;
    try {
      global.parseInt = function (s, radix) {
        if (radix === 16 && s === "fc00") return 0x2606;
        return realParseInt(s, radix);
      };
      intCode = await codeOf(t({ method: "GET", url: "https://[fc00::1]:9/x", blockPrivateAddresses: true }));
    } finally {
      global.parseInt = realParseInt;
    }
    check("blockPrivateAddresses on: the IPv6 blocklist still refuses under a replaced parseInt (" +
      intCode + ")", intCode === "transport/blocked-address");
    // The family classification is consulted BEFORE any of those operations and comes from a module
    // export, not a prototype or a global. Answering 0 for a literal makes the blocklist fall through
    // to "not blocked", so every captured operation after it decides nothing.
    var nodeNetMod = require("node:net");
    var realIsIP = nodeNetMod.isIP;
    var famCode;
    try {
      nodeNetMod.isIP = function (s) { return s === "127.0.0.1" ? 0 : realIsIP(s); };
      famCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:9/x", blockPrivateAddresses: true }));
    } finally {
      nodeNetMod.isIP = realIsIP;
    }
    check("blockPrivateAddresses on: the blocklist still refuses under a replaced net.isIP (" +
      famCode + ")", famCode === "transport/blocked-address");
    check("blockPrivateAddresses off (default): the private-literal guard is opt-in, not applied",
      (await codeOf(t({ method: "GET", url: "https://127.0.0.1:9/x" }))) !== "transport/blocked-address");
  } finally { s.srv.close(); }
}

// ---- CONNECT-proxy support: a real localhost proxy that speaks the CONNECT tunnel ---------------------------
// A server that reads a CONNECT request, optionally demands Basic via a 407, and on success pipes the socket to a
// loopback upstream so the client's TLS-in-tunnel handshake reaches the real origin. With opts.tls it is a TLS
// server (an https proxy), so proxy credentials ride an authenticated channel.
// Recompute the RFC 7616 response the client should have sent for this CONNECT, from the credential it did
// send, so the fake proxy accepts only a correct answer. Returns the pair to compare, or null when the
// credential is not a well-formed Digest value.
function digestExpected(reqLine, credential, opts) {
  if (credential.slice(0, 7) !== "Digest ") return null;
  var params = {};
  credential.slice(7).split(",").forEach(function (piece) {
    var eq = piece.indexOf("=");
    if (eq === -1) return;
    var k = piece.slice(0, eq).trim().toLowerCase();
    var v = piece.slice(eq + 1).trim();
    if (v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') v = v.slice(1, -1);
    params[k] = v;
  });
  var crypto = require("node:crypto");
  var algName = (params.algorithm || "MD5").toUpperCase() === "SHA-256" ? "sha256" : "md5";
  function h(s) { return crypto.createHash(algName).update(s, "utf8").digest("hex"); }
  var ha1 = h(opts.username + ":" + (params.realm || "") + ":" + opts.password);
  var method = reqLine.split(" ")[0];
  var ha2 = params.qop === "auth-int"
    ? h(method + ":" + (params.uri || "") + ":" + h(""))
    : h(method + ":" + (params.uri || ""));
  var response = params.qop
    ? h(ha1 + ":" + (params.nonce || "") + ":" + (params.nc || "") + ":" + (params.cnonce || "") + ":" + params.qop + ":" + ha2)
    : h(ha1 + ":" + (params.nonce || "") + ":" + ha2);
  return { response: response, got: params.response || "", uri: params.uri || "", method: method };
}

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
      seen.push({ requestLine: reqLine, headers: headers, sni: client.servername || null });
      var pa = headers["proxy-authorization"] || "";
      if (opts.rejectStatus) { client.write("HTTP/1.1 " + opts.rejectStatus + " Blocked\r\nContent-Length: 0\r\n\r\n"); client.end(); return; }
      if (opts.requireAuth === "basic" && pa !== ("Basic " + Buffer.from(opts.username + ":" + opts.password).toString("base64"))) {
        client.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\nContent-Length: 0\r\n\r\n');
        client.end();
        return;
      }
      if (opts.requireAuth === "digest") {
        var expected = pa ? digestExpected(reqLine, pa, opts) : null;
        if (!pa || expected === null || expected.response !== expected.got) {
          client.write("HTTP/1.1 407 Proxy Authentication Required\r\n" +
            (opts.noChallenge ? "" : "Proxy-Authenticate: " +
              (opts.challenge || 'Digest realm="proxy", nonce="' + (opts.nonce || "n0nce") + '", qop="auth", algorithm=SHA-256') + "\r\n") +
            "Content-Length: 0\r\n\r\n");
          client.end();
          return;
        }
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
  return new Promise(function (resolve) { srv.listen(0, opts.listenHost || "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port, seen: seen }); }); });
}

/* peerChain negotiates TLS and hands back the channel without sending a request, which is what a
 * verb that reads a certificate off an endpoint needs: a request would reach the application. It is
 * built on the SAME _prepare the request path uses, so the anchors, the SNI, the version floor, the
 * identity hook and the private-address block are one policy rather than two.
 *
 * The chain is what this exercises: the server presents a leaf issued by a CA, and the vector
 * asserts both certificates come back leaf-first as DER the parsers read. A single self-signed
 * certificate cannot tell a one-element chain from a walk that stopped after one step. */
async function testPeerChain() {
  var ca = signing.makeSigner("ec-p256", { cn: "chain-ca.example" });
  var caCert = await pki.x509.sign({
    subject: "chain-ca.example", subjectPublicKey: ca.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
  }, { key: ca.key });
  var leaf = signing.makeSigner("ec-p256", { cn: "localhost" });
  var leafCert = await pki.x509.sign({
    subject: "localhost", subjectPublicKey: leaf.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { subjectAltName: [{ iPAddress: "127.0.0.1" }], keyUsage: ["digitalSignature"], subjectKeyIdentifier: true },
  }, { key: ca.key, cert: caCert });

  var srv = https.createServer({
    cert: pki.schema.x509.pemEncode(leafCert, "CERTIFICATE") + pki.schema.x509.pemEncode(caCert, "CERTIFICATE"),
    key: pki.schema.pkcs8.pemEncode(leaf.key, "PRIVATE KEY"),
  }, function (req, res) { res.end("should not be reached"); });
  var requests = 0;
  srv.on("request", function () { requests += 1; });
  srv.on("clientError", function () { /* a bare TLS close is not an HTTP error the test cares about */ });
  var port = await new Promise(function (res) { srv.listen(0, "127.0.0.1", function () { res(srv.address().port); }); });
  try {
    var anchors = [pki.schema.x509.pemEncode(caCert, "CERTIFICATE")];
    var ch = await pki.transport.peerChain({ url: urlFor(port, "/") }, { tls: { anchors: anchors } });
    check("P1 peerChain returns the channel facts the request path returns",
      ch !== null && typeof ch.protocol === "string" && Buffer.isBuffer(ch.peerCertificate));
    check("P2 peerChain returns the whole chain the endpoint presented, leaf first",
      Array.isArray(ch.peerChain) && ch.peerChain.length === 2 &&
        Buffer.compare(ch.peerChain[0], leafCert) === 0 &&
        Buffer.compare(ch.peerChain[1], caCert) === 0);
    check("P3 the chain's entries are certificates the parser reads",
      pki.schema.x509.parse(ch.peerChain[0]).subject.dn === "CN=localhost" &&
        pki.schema.x509.parse(ch.peerChain[1]).subject.dn === "CN=chain-ca.example");
    check("P4 peerCertificate is the same leaf, so the request path's field is unchanged",
      Buffer.compare(ch.peerCertificate, ch.peerChain[0]) === 0);
    check("P5 no request reached the application", requests === 0);

    /* The identity check is the request path's, not a second one: an endpoint whose certificate
     * does not chain to the configured anchors is refused here exactly as it is there. */
    check("P6 an unpinned endpoint is refused by the gate _prepare applies, before any connect",
      (await codeOf(pki.transport.peerChain({ url: urlFor(port, "/") }, {}))) === "transport/no-trust-anchors");
    var otherCa = signing.makeSigner("ec-p256", { cn: "other-ca.example" });
    var otherCert = await pki.x509.sign({
      subject: "other-ca.example", subjectPublicKey: otherCa.spki,
      notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
    }, { key: otherCa.key });
    check("P6b an endpoint that does not chain to the configured anchors is refused",
      (await codeOf(pki.transport.peerChain({ url: urlFor(port, "/") },
        { tls: { anchors: [pki.schema.x509.pemEncode(otherCert, "CERTIFICATE")] } }))) === "transport/server-auth-failed");
    check("P7 an http: URL is refused by the same gate the request path applies",
      (await codeOf(pki.transport.peerChain({ url: "http://127.0.0.1:" + port + "/" }, {}))) === "transport/insecure-url");
    check("P8 a private address is blocked when the caller asks for it",
      (await codeOf(pki.transport.peerChain({ url: urlFor(port, "/"), blockPrivateAddresses: true },
        { tls: { anchors: anchors } }))) === "transport/blocked-address");
  } finally {
    await new Promise(function (res) { srv.close(res); });
  }
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

    // PX-18 Digest proxy auth (RFC 7616) over the CONNECT tunnel. The proxy answers the first CONNECT with a
    // 407 carrying its challenge, and the client answers it once. The credential is computed over the CONNECT
    // method and the authority-form target, which is what the proxy hashes to check it.
    var pxDigest = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "p" });
    try {
      var rd = await t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxDigest.port, auth: { scheme: "digest", username: "u", password: "p" }, tls: pTrust } });
      check("PX-18 Digest proxy auth over an https proxy: the tunneled GET succeeds", rd.status === 200 && rd.body.toString() === "TUNNELED");
      check("PX-18b the first CONNECT carried no credential and the second carried a Digest one",
        pxDigest.seen.length === 2 && !pxDigest.seen[0].headers["proxy-authorization"] &&
        (pxDigest.seen[1].headers["proxy-authorization"] || "").slice(0, 7) === "Digest ");
      var sentUri = digestExpected(pxDigest.seen[1].requestLine, pxDigest.seen[1].headers["proxy-authorization"], { username: "u", password: "p" });
      check("PX-18c the credential names the CONNECT method and the authority-form target",
        sentUri.method === "CONNECT" && sentUri.uri === "127.0.0.1:" + origin.port);
      check("PX-18d the origin request carried no Proxy-Authorization", rd.headers["x-had-proxy-auth"] === "no");
    } finally { pxDigest.srv.close(); }

    // PX-19 a wrong password is answered once and then refused. The retry is a single attempt the client
    // counts, never a loop the proxy can drive by repeating its challenge.
    var pxDigestBad = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "correct" });
    try {
      check("PX-19 a rejected Digest credential -> proxy-auth-failed",
        (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxDigestBad.port, auth: { scheme: "digest", username: "u", password: "wrong" }, tls: pTrust } }))) === "transport/proxy-auth-failed");
      check("PX-19b the client answered exactly once, so a repeated challenge is not a loop", pxDigestBad.seen.length === 2);
    } finally { pxDigestBad.srv.close(); }

    // PX-20 the challenge is held to the toolkit's Digest policy: an MD5 challenge is refused rather than
    // answered, and a challenge offering no Digest at all is a refusal naming what was offered.
    var pxMd5 = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "p",
      challenge: 'Digest realm="proxy", nonce="n0nce", qop="auth", algorithm=MD5' });
    try {
      var md5Opts = { method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxMd5.port, auth: { scheme: "digest", username: "u", password: "p" }, tls: pTrust } };
      check("PX-20 an MD5 Digest challenge is refused by default",
        (await codeOf(t(md5Opts))) === "transport/proxy-digest-weak-algorithm");
      // The challenge the policy is applied to is read through a string conversion. Read off the live
      // global, a replacement that rewrites the challenge to a strong one makes the weak-algorithm
      // refusal into an accepted credential, so the policy is applied to text the proxy never sent.
      var realStringPx = global.String;
      var rewrittenCode;
      try {
        global.String = function (v) {
          var s = realStringPx(v);
          return s.indexOf("algorithm=MD5") !== -1
            ? 'Digest realm="proxy", nonce="n0nce", qop="auth", algorithm=SHA-256' : s;
        };
        global.String.prototype = realStringPx.prototype;
        rewrittenCode = await codeOf(t(md5Opts));
      } finally {
        global.String = realStringPx;
      }
      check("PX-20 the Digest policy still refuses MD5 under a replaced String (" +
        rewrittenCode + ")", rewrittenCode === "transport/proxy-digest-weak-algorithm");
      // The whole auth-param is trimmed before anything slices it, so that outer trim controls what
      // the algorithm is read from: mapping the segment algorithm=MD5 to algorithm=SHA-256
      // classifies a weak challenge as strong and the refusal never fires.
      var realTrimPx = String.prototype.trim;
      var segCode;
      try {
        String.prototype.trim = function () {
          var s = realTrimPx.call(this);
          return s === "algorithm=MD5" ? "algorithm=SHA-256" : s;
        };
        segCode = await codeOf(t(md5Opts));
      } finally {
        String.prototype.trim = realTrimPx;
      }
      check("PX-20 the Digest policy still refuses MD5 under a replaced trim (" +
        segCode + ")", segCode === "transport/proxy-digest-weak-algorithm");
      // And at the characters: the lexer copies the challenge one character at a time, so a replaced
      // charAt rewrites MD5 to SHA-256 while the split is copying it and the parse reports a strong
      // algorithm. Capturing the token handling does not make the parse safe end to end.
      var realCharAt = String.prototype.charAt;
      var charCode2;
      try {
        // The replacement answers from a rewritten copy of whatever string is being lexed, which is
        // what a per-character attack amounts to: every index the lexer asks for comes back from the
        // rewritten text, so the token it assembles says SHA-256.
        String.prototype.charAt = function (i) {
          var self = realStringPx(this);
          var swapped = self.indexOf("algorithm=MD5") !== -1
            ? self.split("algorithm=MD5").join("algorithm=SHA-256") : self;
          return realCharAt.call(swapped, i);
        };
        charCode2 = await codeOf(t(md5Opts));
      } finally {
        String.prototype.charAt = realCharAt;
      }
      // This one pins the REASON, not the refusal: measured, the character rewrite does not reach an
      // accepted credential either way, but without the capture the refusal comes back as
      // proxy-digest-unsupported-algorithm instead of naming the weak algorithm it actually found.
      check("PX-20 the Digest refusal still names the weak algorithm under a replaced charAt (" +
        charCode2 + ")", charCode2 === "transport/proxy-digest-weak-algorithm");
    } finally { pxMd5.srv.close(); }
    var pxMd5Ok = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "p",
      challenge: 'Digest realm="proxy", nonce="n0nce", qop="auth", algorithm=MD5' });
    try {
      var rMd5 = await t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxMd5Ok.port, auth: { scheme: "digest", username: "u", password: "p", allowMD5: true }, tls: pTrust } });
      check("PX-20b MD5 is answered when the caller opts in", rMd5.status === 200 && rMd5.body.toString() === "TUNNELED");
    } finally { pxMd5Ok.srv.close(); }
    var pxBasicOffer = await startConnectProxy({ tls: proxyTls, requireAuth: "basic", username: "u", password: "p" });
    try {
      check("PX-20c a proxy offering only Basic while digest was configured -> proxy-auth-required",
        (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxBasicOffer.port, auth: { scheme: "digest", username: "u", password: "p" }, tls: pTrust } }))) === "transport/proxy-auth-required");
    } finally { pxBasicOffer.srv.close(); }
    // PX-21 a 407 that names no scheme at all is the same refusal: there is nothing to answer.
    var pxSilent = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "p", noChallenge: true });
    try {
      check("PX-21 a 407 carrying no Proxy-Authenticate -> proxy-auth-required",
        (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxSilent.port, auth: { scheme: "digest", username: "u", password: "p" }, tls: pTrust } }))) === "transport/proxy-auth-required");
    } finally { pxSilent.srv.close(); }
    // PX-22 a challenge the parser reads but the policy cannot answer: no qop is refused by default and
    // answered when the caller opts in, the same pair as the algorithm knob.
    var pxNoQop = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "p",
      challenge: 'Digest realm="proxy", nonce="n0nce", algorithm=SHA-256' });
    try {
      check("PX-22 a Digest challenge carrying no qop is refused by default",
        (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxNoQop.port, auth: { scheme: "digest", username: "u", password: "p" }, tls: pTrust } }))) === "transport/proxy-digest-no-qop");
    } finally { pxNoQop.srv.close(); }
    var pxNoQopOk = await startConnectProxy({ tls: proxyTls, requireAuth: "digest", username: "u", password: "p",
      challenge: 'Digest realm="proxy", nonce="n0nce", algorithm=SHA-256' });
    try {
      var rNoQop = await t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxNoQopOk.port, auth: { scheme: "digest", username: "u", password: "p", allowLegacyQop: true }, tls: pTrust } });
      check("PX-22b a qop-less challenge is answered when the caller opts in", rNoQop.status === 200 && rNoQop.body.toString() === "TUNNELED");
    } finally { pxNoQopOk.srv.close(); }

    // PX-23 allowPlaintextHttp with a proxy. The tunnel is opened to the origin's own port and the
    // request rides it as plain HTTP: a CONNECT defaulting to 443, or a TLS handshake started
    // inside the tunnel, would each reach the wrong thing.
    var plainOrigin = await new Promise(function (res) {
      var srv = require("node:http").createServer(function (req, r) { r.end("PLAINTUNNELED"); });
      srv.listen(0, "127.0.0.1", function () { res({ srv: srv, port: srv.address().port }); });
    });
    var pxPlain = await startConnectProxy({});
    try {
      var rPlain = await t({ method: "GET", url: "http://127.0.0.1:" + plainOrigin.port + "/x",
        allowPlaintextHttp: true, proxy: { url: "http://127.0.0.1:" + pxPlain.port } });
      check("PX-23 a plaintext origin through a proxy reaches the origin over the tunnel",
        rPlain.status === 200 && rPlain.body.toString() === "PLAINTUNNELED");
      check("PX-23b the CONNECT named the origin's own port, not 443",
        pxPlain.seen.length === 1 &&
        pxPlain.seen[0].requestLine.indexOf("127.0.0.1:" + plainOrigin.port) !== -1);
    } finally { pxPlain.srv.close(); plainOrigin.srv.close(); }

    // PX-23c an origin URL stating no port takes its own scheme's default. The upstream connect
    // then fails (nothing is listening there in a test), which is why the assertion is on what the
    // proxy was asked to open rather than on the response.
    var pxPort = await startConnectProxy({});
    try {
      await codeOf(t({ method: "GET", url: "http://127.0.0.1/x", allowPlaintextHttp: true,
        proxy: { url: "http://127.0.0.1:" + pxPort.port } }));
      check("PX-23c an http origin naming no port tunnels to 80, not 443",
        pxPort.seen.length === 1 && pxPort.seen[0].requestLine === "CONNECT 127.0.0.1:80 HTTP/1.1");
    } finally { pxPort.srv.close(); }

    // PX-3 an open http proxy (no auth) is tunnel-only and still works
    var pxOpen = await startConnectProxy({});
    try {
      var r3 = await t({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + pxOpen.port } });
      check("PX-3 an open http proxy tunnels (no credentials sent)", r3.status === 200 && r3.body.toString() === "TUNNELED");
      check("PX-3b the tunnel-only CONNECT carried NO Proxy-Authorization", pxOpen.seen.every(function (s) { return !s.headers["proxy-authorization"]; }));
    } finally { pxOpen.srv.close(); }

    // PX-18 an IP-literal proxy.tls.servername verifies the proxy cert against the configured IP (SNI omitted for an
    // IP), not the connect host name: the proxy is reached by the loopback name but its cert covers only the IP.
    var lh18 = await new Promise(function (res) { require("node:dns").lookup("localhost", function (e, addr) { res(e ? "127.0.0.1" : addr); }); });
    var proxyIp = await selfSignedIpSan("Proxy IP", "127.0.0.1");
    var pxByName = await startConnectProxy({ tls: proxyIp, listenHost: lh18 });
    try {
      var r18 = await t({ method: "GET", url: originUrl, proxy: { url: "https://localhost:" + pxByName.port, tls: { anchors: [proxyIp.certPem], servername: "127.0.0.1" } } });
      check("PX-18 an IP proxy.tls.servername verifies the proxy cert against the IP, not the connect host", r18.status === 200 && r18.body.toString() === "TUNNELED");
    } finally { pxByName.srv.close(); }

    // PX-19 the CONNECT asks for a persistent connection (Connection: keep-alive) rather than the Node default of
    // Connection: close, so a proxy honoring that hop-by-hop directive does not tear the tunnel down after its 200.
    var pxKA = await startConnectProxy({});
    try {
      var r19 = await t({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + pxKA.port } });
      check("PX-19 the CONNECT requests keep-alive (not Connection: close)", r19.status === 200 && (pxKA.seen[0].headers.connection || "").toLowerCase() === "keep-alive");
    } finally { pxKA.srv.close(); }

    // PX-20 an IP-addressed https proxy is sent NO SNI: Node must not infer it from the origin Host header (which
    // would leak the origin name to the proxy or misselect its certificate).
    var pxIpSni = await startConnectProxy({ tls: proxyIp, listenHost: "127.0.0.1" });
    try {
      await codeOf(t({ method: "GET", url: "https://origin-name.example:8443/x", proxy: { url: "https://127.0.0.1:" + pxIpSni.port, tls: { anchors: [proxyIp.certPem] } } }));
      check("PX-20 an IP-addressed https proxy receives no SNI (the origin name is not leaked as the proxy SNI)", pxIpSni.seen.length > 0 && pxIpSni.seen[0].sni === null);
    } finally { pxIpSni.srv.close(); }

    // PX-14 the proxy channel is authenticated: an untrusted https-proxy certificate is refused
    var pxUntrusted = await startConnectProxy({ tls: proxyTls });
    try {
      check("PX-14 an untrusted https-proxy certificate -> proxy-tls-failed", (await codeOf(t({ method: "GET", url: originUrl, proxy: { url: "https://127.0.0.1:" + pxUntrusted.port, auth: { scheme: "basic", username: "u", password: "p" }, tls: { anchors: [tls.certPem], servername: "localhost" } } }))) === "transport/proxy-tls-failed");
    } finally { pxUntrusted.srv.close(); }

    // PX-21 a caller-supplied Proxy-Authorization header is hop-by-hop; it must be stripped from the tunneled origin
    // request, never forwarded to the origin.
    var pxHdr = await startConnectProxy({});
    try {
      var r21 = await t({ method: "GET", url: originUrl, headers: { "Proxy-Authorization": "Basic Y2FsbGVy" }, proxy: { url: "http://127.0.0.1:" + pxHdr.port } });
      check("PX-21 a caller Proxy-Authorization header is not forwarded to the origin over the tunnel", r21.status === 200 && r21.headers["x-had-proxy-auth"] === "no");
    } finally { pxHdr.srv.close(); }

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

    // PX-17 the tunnel verifies the origin cert IDENTITY for an IP-literal origin with no servername (the cert covers
    // dNSName localhost, not the IP): tls.connect would otherwise skip the identity check without SNI, so it is done
    // explicitly, matching the direct path.
    var pxIp = await startConnectProxy({});
    try {
      var tIp = pki.transport.https({ tls: { anchors: [tls.certPem] } });
      check("PX-17 an IP-literal origin whose cert does not cover the IP -> server-auth-failed (identity checked over the tunnel)", (await codeOf(tIp({ method: "GET", url: originUrl, proxy: { url: "http://127.0.0.1:" + pxIp.port } }))) === "transport/server-auth-failed");
    } finally { pxIp.srv.close(); }

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
  check("PX-9d Digest proxy auth over a plaintext http proxy is refused, like Basic", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "http://p:8080", auth: { scheme: "digest", username: "u", password: "p" } } }))) === "transport/proxy-auth-requires-tls");
  check("PX-9d2 a Digest knob on a Basic proxy auth is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "basic", username: "u", password: "p", allowMD5: true }, tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  check("PX-9d3 a non-boolean Digest knob is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "digest", username: "u", password: "p", allowMD5: "yes" }, tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  // RFC 7617 sec. 2 forbids a colon in a Basic user-id, and the check asks String.prototype.indexOf.
  // Read off the live prototype, a replacement answering -1 accepts the configuration, so the
  // credential this transport would send is one the scheme cannot encode unambiguously.
  var colonProxy = { method: "GET", url: "https://ca.example/x",
    proxy: { url: "https://p:8080", auth: { scheme: "basic", username: "a:b", password: "p" }, tls: { useSystemStore: true } } };
  check("CONTROL a colon in a Basic proxy user-id is refused",
    (await codeOf(t(colonProxy))) === "transport/bad-proxy");
  var realIndexOfP = String.prototype.indexOf;
  var colonCode;
  try {
    String.prototype.indexOf = function (needle) {
      var r = realIndexOfP.apply(this, arguments);
      return (needle === ":" && String(this) === "a:b") ? -1 : r;
    };
    colonCode = await codeOf(t(colonProxy));
  } finally {
    String.prototype.indexOf = realIndexOfP;
  }
  check("PX-9d5 the Basic user-id colon rule holds under a replaced indexOf (" + colonCode + ")",
    colonCode === "transport/bad-proxy");
  check("PX-9d4 a non-string Digest password is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "digest", username: "u", password: 7 }, tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  check("PX-9d5 an auth record supplying a field through an accessor is refused", (await codeOf((function () {
    var a = { scheme: "digest", username: "u" };
    Object.defineProperty(a, "password", { enumerable: true, configurable: true, get: function () { return "p"; } });
    return t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: a, tls: { useSystemStore: true } } });
  })())) === "transport/bad-proxy");
  check("PX-9e an unknown proxy.auth.scheme is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "ntlm", username: "u", password: "p" } } }))) === "transport/bad-proxy");
  check("PX-9f a mistyped proxy key is refused", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "http://p:8080", usernam: "x" } }))) === "transport/bad-proxy");
  check("PX-9g a Basic user-id with a colon is refused (RFC 7617)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", auth: { scheme: "basic", username: "a:b", password: "p" }, tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  check("PX-9h an https proxy with no tls trust is refused -> bad-proxy", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080" } }))) === "transport/bad-proxy");
  check("PX-9i a non-string proxy.tls.servername is refused at config time (never reaches the socket)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", tls: { useSystemStore: true, servername: 7 } } }))) === "transport/bad-proxy");
  check("PX-9j proxy.tls on a plaintext http proxy is refused (never silently ignored)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "http://p:8080", tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  check("PX-9k a malformed proxy CA anchor (null in the array) is refused as bad-proxy, not a connect error", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", tls: { anchors: [null] } } }))) === "transport/bad-proxy");
  check("PX-9l a non-byte proxy CA anchor (a plain object) is refused as bad-proxy", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", tls: { anchors: {} } } }))) === "transport/bad-proxy");
  check("PX-9m a proxy CA anchor must be a PEM string or DER Buffer (a Uint8Array view is refused)", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", tls: { anchors: [new Uint8Array([1, 2, 3])] } } }))) === "transport/bad-proxy");
  check("PX-9n an invalid proxy.tls.minVersion is a proxy config error (bad-proxy), consistent with other proxy options", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://p:8080", tls: { useSystemStore: true, minVersion: "TLSv1.1" } } }))) === "transport/bad-proxy");
  check("PX-9o a proxy URL carrying userinfo credentials is refused, not silently dropped", (await codeOf(t({ method: "GET", url: "https://ca.example/x", proxy: { url: "https://user:pass@p:8080", tls: { useSystemStore: true } } }))) === "transport/bad-proxy");
  check("PX-10 an http origin with a proxy is refused (https-only) -> insecure-url", (await codeOf(t({ method: "GET", url: "http://ca.example/x", proxy: { url: "http://p:8080" } }))) === "transport/insecure-url");

  // PX-11 blockPrivateAddresses is incompatible with a proxy: the proxy resolves the origin, so the transport cannot
  // enforce the private-address block on it. The combination is refused rather than silently unenforced.
  check("PX-11 blockPrivateAddresses + an https proxy is refused (block cannot be enforced through a proxy)", (await codeOf(t({ method: "GET", url: "https://example.com/x", proxy: { url: "https://p:8080", tls: { useSystemStore: true } }, blockPrivateAddresses: true }))) === "transport/bad-proxy");
  check("PX-11b blockPrivateAddresses + an http proxy is refused too (before any socket)", (await codeOf(t({ method: "GET", url: "https://example.com/x", proxy: { url: "http://p:8080" }, blockPrivateAddresses: true }))) === "transport/bad-proxy");
  // PX-16 a connectivity failure to a proxy whose hostname contains "tls"/"ssl" is a connect error, not a cert error:
  // classification reads the error CODE (ENOTFOUND), never the hostname carried in the message.
  check("PX-16 a DNS failure to a TLS-named proxy is proxy-connect-failed, not misread as proxy-tls-failed", (await codeOf(t({ method: "GET", url: "https://example.com/x", proxy: { url: "https://tls.invalid:9", auth: { scheme: "basic", username: "u", password: "p" }, tls: { useSystemStore: true } } }))) === "transport/proxy-connect-failed");
}

// ---- TU: tls-unique channel binding surfaced from the transport (RFC 7030 sec. 3.5 / RFC 5929) ----
// RFC 5929 tls-unique is the first Finished on the handshake: on a full handshake the CLIENT's Finished,
// which the server observes as its peer-Finished. The transport surfaces that value for TLS 1.2 and null
// on TLS 1.3 (RFC 5929 is undefined there). It feeds pki.est.challengePasswordFromTlsUnique end to end.
// The transport does one request per connection (agent: false), so no TLS session is resumed through it;
// the getPeerFinished (resumed abbreviated-handshake) branch is RFC 5929 behavior kept for correctness but
// not reachable via the shipped transport, so only the full-handshake getFinished path is driven here.
async function testTlsUnique() {
  var tlsFx = await selfSigned("Loopback CB");
  var acceptId = function () { return undefined; };

  var serverPeerFinished = null;
  var s12 = await startServer(tlsFx, function (req, res) {
    try { serverPeerFinished = req.socket.getPeerFinished ? req.socket.getPeerFinished() : null; } catch (_e) { serverPeerFinished = null; }
    res.end("ok");
  }, { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" });
  try {
    var t = pki.transport.https({});
    var r = await t({ method: "GET", url: urlFor(s12.port), tls: { anchors: [tlsFx.certPem], servername: "localhost", checkServerIdentity: acceptId } });
    check("TU-1 tls-unique is surfaced on a TLS 1.2 handshake", r.tls.protocol === "TLSv1.2" && Buffer.isBuffer(r.tls.tlsUnique) && r.tls.tlsUnique.length > 0);
    check("TU-1b the surfaced tls-unique is the client Finished (the server's peer-Finished, RFC 5929)",
      Buffer.isBuffer(serverPeerFinished) && serverPeerFinished.length > 0 && r.tls.tlsUnique.equals(serverPeerFinished));
    var attr = pki.est.challengePasswordFromTlsUnique(r.tls.tlsUnique);
    var expectB64 = Buffer.from(r.tls.tlsUnique).toString("base64");
    check("TU-2 challengePasswordFromTlsUnique consumes the surfaced tls-unique end to end",
      Buffer.isBuffer(attr) && attr.indexOf(Buffer.from(expectB64, "ascii")) !== -1);
  } finally { s12.srv.close(); }

  var s13 = await startServer(tlsFx, function (req, res) { res.end("ok"); }, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  try {
    var t3 = pki.transport.https({});
    var r3 = await t3({ method: "GET", url: urlFor(s13.port), tls: { anchors: [tlsFx.certPem], servername: "localhost", checkServerIdentity: acceptId } });
    check("TU-3 tls-unique is null on TLS 1.3 (RFC 5929 is undefined there, never substituted)",
      r3.tls.protocol === "TLSv1.3" && r3.tls.tlsUnique === null);
  } finally { s13.srv.close(); }
}

// A request body given as a function is the post-handshake / pre-body hook for RFC 7030 sec. 3.5
// channel binding: it is invoked after the TLS handshake with the connection's tls object, so the
// caller builds the request body (a channel-bound CSR) from tls-unique on the same connection it
// posts over. The value the callback saw equals what the response reports and what the server saw.
// RFC 9266 tls-exporter, the TLS 1.3 channel binding, complementary to RFC 5929 tls-unique (TLS <= 1.2).
// Section 2 fixes the label "EXPORTER-Channel-Binding", a 32-byte output, and a zero-length context, and
// makes the binding unconditionally defined on TLS 1.3. On TLS 1.2 it additionally requires the RFC 7627
// extended master secret, which node exposes no way to confirm, so the value is withheld there rather
// than surfaced unproven. Both peers must derive the same bytes, so the server computes its own.
var EXPORTER_LABEL = "EXPORTER-Channel-Binding";
var EXPORTER_LEN = 32;

async function testTlsExporter() {
  var tlsFx = await selfSigned("Loopback EXP");
  var acceptId = function () { return undefined; };
  var anchors = function () { return { anchors: [tlsFx.certPem], servername: "localhost", checkServerIdentity: acceptId }; };

  var serverExporter = null;
  var s13 = await startServer(tlsFx, function (req, res) {
    try { serverExporter = req.socket.exportKeyingMaterial(EXPORTER_LEN, EXPORTER_LABEL, Buffer.alloc(0)); }
    catch (_e) { serverExporter = null; }
    res.end("ok");
  }, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  try {
    var t = pki.transport.https({});
    var r = await t({ method: "GET", url: urlFor(s13.port), tls: anchors() });
    check("TE-1 tls-exporter is surfaced on a TLS 1.3 connection as 32 bytes (RFC 9266 sec. 2)",
      r.tls.protocol === "TLSv1.3" && Buffer.isBuffer(r.tls.tlsExporter) && r.tls.tlsExporter.length === EXPORTER_LEN);
    check("TE-2 both peers derive the same binding, computed independently by the server",
      Buffer.isBuffer(serverExporter) && r.tls.tlsExporter.equals(serverExporter));
    check("TE-3 tls-unique stays null on TLS 1.3, so exactly one binding is defined per version",
      r.tls.tlsUnique === null);
  } finally { s13.srv.close(); }

  var received = null;
  var s13b = await startServer(tlsFx, function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { received = Buffer.concat(chunks); res.end("ok"); });
  }, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  try {
    var t2 = pki.transport.https({});
    var seen = null;
    var r2 = await t2({ method: "POST", url: urlFor(s13b.port),
      body: function (info) { seen = info.tlsExporter; return Buffer.from("bound"); }, tls: anchors() });
    check("TE-4 the pre-body callback carries the same tls-exporter the response reports",
      Buffer.isBuffer(seen) && seen.length === EXPORTER_LEN && Buffer.isBuffer(r2.tls.tlsExporter) && seen.equals(r2.tls.tlsExporter));
    check("TE-5 and the request still completed normally", Buffer.isBuffer(received) && received.toString("ascii") === "bound");
  } finally { s13b.srv.close(); }

  var s12 = await startServer(tlsFx, function (req, res) { res.end("ok"); }, { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" });
  try {
    var t3 = pki.transport.https({});
    var r3 = await t3({ method: "GET", url: urlFor(s12.port), tls: anchors() });
    check("TE-6 tls-exporter is withheld on TLS 1.2, where its uniqueness condition cannot be confirmed",
      r3.tls.protocol === "TLSv1.2" && r3.tls.tlsExporter === null);
    check("TE-7 and tls-unique is still the binding defined for that version",
      Buffer.isBuffer(r3.tls.tlsUnique) && r3.tls.tlsUnique.length > 0);
  } finally { s12.srv.close(); }

  // Drop-safe: a socket whose exporter throws yields null rather than failing the request. The stub is
  // restored in the finally so no later vector observes it.
  var s13c = await startServer(tlsFx, function (req, res) { res.end("ok"); }, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  var realExport = nodeTls.TLSSocket.prototype.exportKeyingMaterial;
  try {
    nodeTls.TLSSocket.prototype.exportKeyingMaterial = function () { throw new Error("exporter unavailable"); };
    var t4 = pki.transport.https({});
    var r4 = await t4({ method: "GET", url: urlFor(s13c.port), tls: anchors() });
    check("TE-8 an exporter that throws yields null and does not fail the request",
      r4.status === 200 && r4.tls.tlsExporter === null);
  } finally {
    nodeTls.TLSSocket.prototype.exportKeyingMaterial = realExport;
    s13c.srv.close();
  }

  // The binding is a fixed 32 octets (RFC 9266 sec. 2). Anything else is not that value, so it is
  // withheld rather than surfaced under its name.
  var s13d = await startServer(tlsFx, function (req, res) { res.end("ok"); }, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  var realExport2 = nodeTls.TLSSocket.prototype.exportKeyingMaterial;
  try {
    nodeTls.TLSSocket.prototype.exportKeyingMaterial = function () { return Buffer.alloc(16, 7); };
    var t5 = pki.transport.https({});
    var r5 = await t5({ method: "GET", url: urlFor(s13d.port), tls: anchors() });
    check("TE-9 an export of the wrong length is not surfaced as the binding",
      r5.status === 200 && r5.tls.tlsExporter === null);
    nodeTls.TLSSocket.prototype.exportKeyingMaterial = function () { return "not-bytes"; };
    var r6 = await t5({ method: "GET", url: urlFor(s13d.port), tls: anchors() });
    check("TE-10 nor is a non-byte export", r6.status === 200 && r6.tls.tlsExporter === null);
  } finally {
    nodeTls.TLSSocket.prototype.exportKeyingMaterial = realExport2;
    s13d.srv.close();
  }
}

async function testBodyFunctionChannelBinding() {
  var tlsFx = await selfSigned("Loopback CBhook");
  var acceptId = function () { return undefined; };
  var received = null;
  var serverPeerFinished = null;
  var s = await startServer(tlsFx, function (req, res) {
    try { serverPeerFinished = req.socket.getPeerFinished ? req.socket.getPeerFinished() : null; } catch (_e) { serverPeerFinished = null; }
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { received = Buffer.concat(chunks); res.end("ok"); });
  }, { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" });
  try {
    var t = pki.transport.https({});
    var anchors = { anchors: [tlsFx.certPem], servername: "localhost", checkServerIdentity: acceptId };
    var seenBinding = null;
    var r = await t({ method: "POST", url: urlFor(s.port), headers: { "content-type": "application/octet-stream" },
      body: function (info) { seenBinding = info.tlsUnique; return Buffer.concat([Buffer.from("CSR:"), info.tlsUnique]); },
      tls: anchors });
    check("CB-1 the body callback ran post-handshake with the connection tls-unique",
      Buffer.isBuffer(seenBinding) && seenBinding.length > 0 && Buffer.isBuffer(serverPeerFinished) && seenBinding.equals(serverPeerFinished));
    check("CB-2 the server received exactly the body built from that binding",
      Buffer.isBuffer(received) && received.equals(Buffer.concat([Buffer.from("CSR:"), seenBinding])));
    check("CB-3 the response tls-unique matches the binding the body used (one connection)",
      Buffer.isBuffer(r.tls.tlsUnique) && r.tls.tlsUnique.equals(seenBinding));

    received = null;
    var r2 = await t({ method: "POST", url: urlFor(s.port), body: function () { return "plain-string-body"; }, tls: anchors });
    check("CB-4 a string returned by the body callback is sent as the body",
      r2.status === 200 && Buffer.isBuffer(received) && received.toString("ascii") === "plain-string-body");

    received = null;
    var rExpect = await t({ method: "POST", url: urlFor(s.port), headers: { "content-type": "application/octet-stream", "Expect": "100-continue" },
      body: function () { return Buffer.from("expect-body"); }, tls: anchors });
    check("CB-7 a function body still works when the caller set Expect: 100-continue (headers are not flushed before the deferred write)",
      rExpect.status === 200 && Buffer.isBuffer(received) && received.toString("ascii") === "expect-body");

    var threw = await codeOf(t({ method: "POST", url: urlFor(s.port), body: function () { throw new Error("boom"); }, tls: anchors }));
    check("CB-5 a throwing body callback rejects with a typed transport error", threw === "transport/transport-error");
    var badret = await codeOf(t({ method: "POST", url: urlFor(s.port), body: function () { return 123; }, tls: anchors }));
    check("CB-6 a body callback returning a non-byte, non-string value is refused", badret === "transport/bad-input");

    var nullret = await codeOf(t({ method: "POST", url: urlFor(s.port), body: function () { return null; }, tls: anchors }));
    check("CB-8 a body callback returning null is refused, never sent to the CA as an empty enrollment", nullret === "transport/bad-input");
    var noret = await codeOf(t({ method: "POST", url: urlFor(s.port), body: function () { Buffer.from("forgot-to-return"); }, tls: anchors }));
    check("CB-9 a body callback with a missing return is refused rather than posting an empty body", noret === "transport/bad-input");
    received = null;
    var rEmpty = await t({ method: "POST", url: urlFor(s.port), body: function () { return ""; }, tls: anchors });
    check("CB-10 an explicit empty-string return is still an intentional empty body",
      rEmpty.status === 200 && Buffer.isBuffer(received) && received.length === 0);

    received = null;
    var rAsync = await t({ method: "POST", url: urlFor(s.port),
      body: function (info) { return Promise.resolve().then(function () { return Buffer.concat([Buffer.from("ASYNC:"), info.tlsUnique]); }); },
      tls: anchors });
    check("CB-12 the callback may return a promise, so a caller can sign a CSR with the toolkit's async signer",
      rAsync.status === 200 && Buffer.isBuffer(received) && received.equals(Buffer.concat([Buffer.from("ASYNC:"), rAsync.tls.tlsUnique])));
    var rejCode = await codeOf(t({ method: "POST", url: urlFor(s.port), body: function () { return Promise.reject(new Error("async boom")); }, tls: anchors }));
    check("CB-13 a callback whose promise rejects fails the request closed", rejCode === "transport/transport-error");

    var detachedAb = new ArrayBuffer(8);
    var detachedView = new Uint8Array(detachedAb);
    structuredClone(detachedAb, { transfer: [detachedAb] });
    var detachedCode = await codeOf(t({ method: "POST", url: urlFor(s.port), body: function () { return detachedView; }, tls: anchors }));
    check("CB-11 an unusable byte source from the callback keeps its typed bad-input verdict, not a write failure",
      detachedCode === "transport/bad-input");
  } finally { s.srv.close(); }
}

async function main() {
  await testConfigGates();
  await testResolutionFilterUnits();
  await testBlockPrivateAddresses();
  await testChunkedBodyAccumulation();
  await testConnectStallTimeout();
  await testPeerChainTrickleDeadline();
  await testSystemStoreLoaded();
  await testSocketNotReusedAcrossIdentityPolicy();
  await testHappy();
  await testIdentityHookCannotBypass();
  await testTlsDefaultsHonored();
  await testServernameNullOverride();
  await testDerAnchor();
  await testCapturedOperations();
  await testDerAnchorWithArmorBytes();
  await testIpv6BracketHost();
  await testServerAuthFailed();
  await testSizeCap();
  await testTimeout();
  await testTlsFloor();
  await testTlsUnique();
  await testTlsExporter();
  await testBodyFunctionChannelBinding();
  await testSystemStore();
  await testErrorFactoryParam();
  await testPeerChain();
  await testProxyConnect();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
