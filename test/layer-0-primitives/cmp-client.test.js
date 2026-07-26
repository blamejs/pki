// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.cmp.transfer / pki.cmp.wellKnownUrl -- the RFC 9811 HTTP transfer verb over
// the shared pki.transport. Every fail-closed branch of the CMP HTTP state machine (200-only success,
// non-200-2xx reject, 3xx not-followed, a 4xx/5xx carrying a CMP error body FORWARDED, content-type gate,
// empty-body reject, size cap, injected-http reachability) is driven through the shipped consumer
// pki.cmp.transfer over an injectable fake transport with NO socket; a node:https loopback covers the
// socket-lifecycle branches a fake cannot reach. Fixtures are real PKIMessages from pki.cmp.build.

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var A = require("../helpers/cmp-transport");
var https = require("node:https");

var BASE = "https://ca.example/.well-known/cmp";

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// A real self-signed TLS cert (SAN localhost) for the loopback socket-path vector.
async function selfSigned(cn) {
  var s = signing.makeSigner("ec-p256", { cn: cn });
  var certDer = await pki.x509.sign({
    subject: cn, subjectPublicKey: s.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyEncipherment", "keyCertSign"], subjectAltName: [{ dNSName: "localhost" }], subjectKeyIdentifier: true },
  }, { key: s.key });
  return { certPem: pki.schema.x509.pemEncode(certDer, "CERTIFICATE"), keyPem: pki.schema.pkcs8.pemEncode(s.key, "PRIVATE KEY") };
}
function startServer(tls, handler) {
  return new Promise(function (resolve) {
    var srv = https.createServer({ cert: tls.certPem, key: tls.keyPem }, handler);
    srv.on("clientError", function () {});
    srv.listen(0, "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port }); });
  });
}

async function run() {
  var f = await A.makeFixtures(pki);

  // 1. happy transfer: ir -> 200 application/pkixcmp <ip> resolves, POST + content-type + verbatim body.
  var s1 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  var r1 = await pki.cmp.transfer(BASE, f.irDer, s1.opts);
  check("1 ir->ip resolves { status:200, body.arm:'ip' }", r1.status === 200 && r1.response.body.arm === "ip");
  check("1 the request is POST with content-type application/pkixcmp", s1.transport.calls[0].method === "POST" && s1.transport.calls[0].headers["content-type"] === A.PKIXCMP);
  check("1 the protected request bytes are POSTed verbatim", Buffer.isBuffer(s1.transport.calls[0].body) && s1.transport.calls[0].body.equals(f.irDer));
  check("1 the raw response DER + content-type are surfaced", Buffer.isBuffer(r1.responseBytes) && r1.responseBytes.equals(f.ipDer) && r1.contentType.indexOf("application/pkixcmp") === 0);

  // 2. PEM message input is transfer-decoded and POSTed as the SAME DER (protection intact).
  var irPem = pki.schema.cmp.pemEncode(f.irDer, "CMP");
  var s2 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  await pki.cmp.transfer(BASE, irPem, s2.opts);
  check("2 a PEM CMP message is decoded to the same DER before POST", s2.transport.calls[0].body.equals(f.irDer));

  // 3. non-200 2xx is nonconforming (M3): body NOT decoded.
  for (var st of [201, 202, 204]) {
    var s3 = A.cmpOpts(A.pkixcmp(st, f.ipDer));
    check("3 a " + st + " response -> cmp/unexpected-status (not decoded)", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s3.opts))) === "cmp/unexpected-status");
  }

  // 4/5. a 4xx/5xx carrying a well-formed CMP error body is FORWARDED (M4): resolves, status surfaced.
  var s4 = A.cmpOpts(A.pkixcmp(400, f.errorDer));
  var r4 = await pki.cmp.transfer(BASE, f.irDer, s4.opts);
  check("4 a 400 with a CMP error body resolves { status:400, body.arm:'error' }", r4.status === 400 && r4.response.body.arm === "error");
  var s5 = A.cmpOpts(A.pkixcmp(500, f.errorDer));
  var r5 = await pki.cmp.transfer(BASE, f.irDer, s5.opts);
  check("5 a 500 with a CMP error body resolves { status:500, body.arm:'error' }", r5.status === 500 && r5.response.body.arm === "error");

  // 6. a 4xx/5xx with NO CMP body throws cmp/http-error carrying the numeric status.
  var s6a = A.cmpOpts(A.resp(400, "<html>bad</html>", "text/html"));
  check("6 a 400 text/html (no CMP body) -> cmp/http-error", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s6a.opts))) === "cmp/http-error");
  var s6b = A.cmpOpts(A.resp(500, "", null));
  check("6 a 500 empty body -> cmp/http-error", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s6b.opts))) === "cmp/http-error");

  // 7. wrong content-type on a 200 -> cmp/bad-content-type; body not decoded.
  var s7 = A.cmpOpts(A.resp(200, f.ipDer, "text/plain"));
  check("7 a 200 text/plain <ip> -> cmp/bad-content-type", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s7.opts))) === "cmp/bad-content-type");
  check("7 the body was not decoded (one call, no follow)", s7.transport.calls.length === 1);

  // 8. the legacy application/pkixcmp-poll type is handled like application/pkixcmp (M9).
  var s8 = A.cmpOpts(A.pkixcmpPoll(200, f.ipDer));
  var r8 = await pki.cmp.transfer(BASE, f.irDer, s8.opts);
  check("8 a 200 application/pkixcmp-poll <ip> resolves", r8.response.body.arm === "ip");

  // 9. an empty 200 body -> cmp/empty-response.
  var s9 = A.cmpOpts(A.pkixcmp(200, ""));
  check("9 a 200 application/pkixcmp with an empty body -> cmp/empty-response", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s9.opts))) === "cmp/empty-response");

  // 10. a malformed 200 body surfaces the parser's cmp/* verdict, fail-closed (M8).
  var s10 = A.cmpOpts(A.pkixcmp(200, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])));
  var c10 = await codeOf(pki.cmp.transfer(BASE, f.irDer, s10.opts));
  check("10 a malformed CMP 200 body surfaces a fail-closed cmp/* verdict", /^cmp\//.test(c10) && c10 !== "NO-THROW");

  // 11. a 3xx is NOT followed (M7): cmp/redirect-not-followed, one call, the original URL targeted.
  var s11 = A.cmpOpts({ status: 301, headers: { location: "https://evil.example/cmp" }, body: "" });
  check("11 a 301 with a Location -> cmp/redirect-not-followed", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s11.opts))) === "cmp/redirect-not-followed");
  check("11 the redirect is not auto-followed (one call, original URL)", s11.transport.calls.length === 1 && s11.transport.calls[0].url === BASE);

  // 12. no client scheme gate (Build decision 6): default transport refuses http; an injected one carries it.
  check("12a default transport + http URL -> cmp/insecure-url (transport, not the verb)", (await codeOf(pki.cmp.transfer("http://ca.example/cmp", f.irDer, { tls: { anchors: [A.CERT_DER] } }))) === "cmp/insecure-url");
  var s12 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  var r12 = await pki.cmp.transfer("http://ca.example/cmp", f.irDer, s12.opts);
  check("12b an injected http-capable transport + http URL transfers the PKIMessage", r12.response.body.arm === "ip");

  // 13. an unparseable URL -> cmp/bad-url before any transport call.
  var s13 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("13 an unparseable URL -> cmp/bad-url", (await codeOf(pki.cmp.transfer("::::", f.irDer, s13.opts))) === "cmp/bad-url");
  check("13 no request crossed the seam", s13.transport.calls.length === 0);

  // 14. default transport with no anchors/useSystemStore -> cmp/no-trust-anchors (no socket).
  check("14 default transport, no trust anchor -> cmp/no-trust-anchors", (await codeOf(pki.cmp.transfer(BASE, f.irDer, {}))) === "cmp/no-trust-anchors");

  // 15. a non-DER/PEM message -> cmp/bad-input before the wire.
  var s15 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("15 a non-DER/PEM message -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, 12345, s15.opts))) === "cmp/bad-input");
  check("15 the config gate precedes the wire (no POST)", s15.transport.calls.length === 0);

  // 16. a 200 body over maxResponseBytes -> cmp/response-too-large before decode.
  var s16 = A.cmpOpts(A.pkixcmp(200, f.ipDer), { maxResponseBytes: 10 });
  check("16 an oversized 200 body -> cmp/response-too-large", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s16.opts))) === "cmp/response-too-large");

  // 17. a transport rejection (no HTTP response) surfaces unchanged; the client does NOT re-POST (M5).
  var calls17 = [];
  var rejTransport = function (req) { calls17.push(req); var e = new Error("timed out"); e.code = "cmp/timeout"; return Promise.reject(e); };
  check("17 a transport rejection surfaces unchanged", (await codeOf(pki.cmp.transfer(BASE, f.irDer, { transport: rejTransport, tls: { anchors: [A.CERT_DER] } }))) === "cmp/timeout");
  check("17 a failed delivery is not re-POSTed", calls17.length === 1);

  // 18. mTLS material is passed through to the request tls (CMP under TLS client auth).
  var s18 = A.cmpOpts(A.pkixcmp(200, f.ipDer), { tls: { anchors: [A.CERT_DER], cert: A.CERT_DER, key: Buffer.from("k") } });
  await pki.cmp.transfer(BASE, f.irDer, s18.opts);
  check("18 opts.tls.cert/key reach the request tls", s18.transport.calls[0].tls && s18.transport.calls[0].tls.cert === A.CERT_DER && s18.transport.calls[0].tls.key != null);

  // 19. the content-type is set + not overridable via opts.headers; the method is POST.
  var s19 = A.cmpOpts(A.pkixcmp(200, f.ipDer), { headers: { "content-type": "text/plain", "x-extra": "1" } });
  await pki.cmp.transfer(BASE, f.irDer, s19.opts);
  check("19 the content-type stays application/pkixcmp despite an opts.headers override", s19.transport.calls[0].headers["content-type"] === A.PKIXCMP);
  check("19 an unrelated custom header is still forwarded", s19.transport.calls[0].headers["x-extra"] === "1");

  // 20. wellKnownUrl RFC 9811 sec. 3.4 forms + fail-closed rejects.
  check("20 base -> /.well-known/cmp", pki.cmp.wellKnownUrl("https://ca.example") === "https://ca.example/.well-known/cmp");
  check("20 {operation} -> /.well-known/cmp/<op>", pki.cmp.wellKnownUrl("https://ca.example", { operation: "initialization" }) === "https://ca.example/.well-known/cmp/initialization");
  check("20 {label} -> /.well-known/cmp/p/<label>", pki.cmp.wellKnownUrl("https://ca.example", { label: "myca" }) === "https://ca.example/.well-known/cmp/p/myca");
  check("20 {label,operation} -> /.well-known/cmp/p/<label>/<op>", pki.cmp.wellKnownUrl("https://ca.example", { label: "myca", operation: "cr" }) === "https://ca.example/.well-known/cmp/p/myca/cr");
  check("20 a base with a query -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example/?x=1"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 a label containing '/' -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { label: "a/b" }); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 an operation with a dot-segment -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { operation: ".." }); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 an http base is BUILT (the transport enforces scheme, not this builder)", pki.cmp.wellKnownUrl("http://ca.example") === "http://ca.example/.well-known/cmp");

  // 21. budget guards run before the wire.
  var s21 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("21 timeout:NaN -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, f.irDer, Object.assign({}, s21.opts, { timeout: NaN })))) === "cmp/bad-input");
  var s21b = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("21 maxResponseBytes:-1 -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, f.irDer, Object.assign({}, s21b.opts, { maxResponseBytes: -1 })))) === "cmp/bad-input");
  check("21 no POST on a bad budget", s21.transport.calls.length === 0 && s21b.transport.calls.length === 0);

  // 22. the socket path over the REAL pki.transport.https loopback (verification ON).
  var tlsSrv = await selfSigned("cmp-loopback");
  var srv = await startServer(tlsSrv, function (req, res) {
    var chunks = []; req.on("data", function (c) { chunks.push(c); }); req.on("end", function () {
      res.writeHead(200, { "Content-Type": "application/pkixcmp" }); res.end(f.ipDer);
    });
  });
  try {
    var url22 = "https://127.0.0.1:" + srv.port + "/.well-known/cmp";
    var r22 = await pki.cmp.transfer(url22, f.irDer, { tls: { anchors: [tlsSrv.certPem], servername: "localhost" } });
    check("22 the real transport round-trips 200 ip", r22.status === 200 && r22.response.body.arm === "ip");
    check("22 the negotiated TLS protocol + peer cert are surfaced", /^TLSv1\.[23]$/.test(r22.tls.protocol) && Buffer.isBuffer(r22.tls.peerCertificate));
    check("22 an untrusted server (no anchor) fails closed", (await codeOf(pki.cmp.transfer(url22, f.irDer, { tls: { useSystemStore: true, servername: "localhost" } }))) === "cmp/server-auth-failed");
  } finally { srv.srv.close(); }

  console.log("CHECKS " + helpers.getChecks());
}

run();
