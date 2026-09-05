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
  // a typed-array (Uint8Array) response body from an injected transport is preserved byte-for-byte and
  // parsed, not stringified to "48,130,..." garbage.
  var s1u = A.cmpOpts({ status: 200, headers: { "content-type": A.PKIXCMP }, body: new Uint8Array(f.ipDer) });
  var r1u = await pki.cmp.transfer(BASE, f.irDer, s1u.opts);
  check("1 a Uint8Array response body is preserved and parsed", r1u.response.body.arm === "ip" && r1u.responseBytes.equals(f.ipDer));

  // 1b. A transport that is not callable is a wiring fault the operator makes at config time, so the
  // option is named at the door. A FALSY transport is the same fault and must not be read as "none
  // supplied": falling back to the default client would reach the CA over the network on behalf of a
  // caller that believed it had injected one.
  async function badTransport(v) {
    try { await pki.cmp.transfer(BASE, f.irDer, { transport: v }); return "NO-THROW"; }
    catch (e) { return (e && e.code === "cmp/bad-input" && String(e.message).indexOf("opts.transport") !== -1) ? "typed" : ((e && e.code) || ("RAW:" + (e && e.message || "").slice(0, 40))); }
  }
  check("1b a non-callable transport is refused, naming the option", (await badTransport(42)) === "typed");
  check("1b an object transport is refused, naming the option", (await badTransport({})) === "typed");
  check("1b a falsy transport is refused rather than falling back to the network", (await badTransport(0)) === "typed");

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
  // a missing / non-numeric / out-of-range HTTP status carrying a valid CMP error body is NOT a forwardable
  // 4xx/5xx failure -- the status must be a real HTTP code, else fail closed (cmp/unexpected-status).
  var s3s = A.cmpOpts({ status: "500", headers: { "content-type": A.PKIXCMP }, body: f.errorDer });
  check("3 a string-valued status with a CMP error body -> cmp/unexpected-status", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s3s.opts))) === "cmp/unexpected-status");
  var s3i = A.cmpOpts({ status: 100, headers: { "content-type": A.PKIXCMP }, body: f.errorDer });
  check("3 a 1xx informational status with a CMP error body -> cmp/unexpected-status", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s3i.opts))) === "cmp/unexpected-status");
  var s3h = A.cmpOpts({ status: 700, headers: { "content-type": A.PKIXCMP }, body: f.errorDer });
  check("3 an out-of-range (>599) status -> cmp/unexpected-status", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s3h.opts))) === "cmp/unexpected-status");

  // 4/5. a 4xx/5xx carrying a well-formed CMP error body is FORWARDED (M4): resolves, status surfaced.
  var s4 = A.cmpOpts(A.pkixcmp(400, f.errorDer));
  var r4 = await pki.cmp.transfer(BASE, f.irDer, s4.opts);
  check("4 a 400 with a CMP error body resolves { status:400, body.arm:'error' }", r4.status === 400 && r4.response.body.arm === "error");
  var s5 = A.cmpOpts(A.pkixcmp(500, f.errorDer));
  var r5 = await pki.cmp.transfer(BASE, f.irDer, s5.opts);
  check("5 a 500 with a CMP error body resolves { status:500, body.arm:'error' }", r5.status === 500 && r5.response.body.arm === "error");
  // a 4xx/5xx carrying a NON-error CMP body (a granting ip / a pkiconf) is contradictory -- only a CMP error
  // message is a forwardable verdict on an HTTP failure; otherwise cmp/http-error (the HTTP failure stands).
  var s5b = A.cmpOpts(A.pkixcmp(500, f.ipDer));
  check("5 a 500 with a non-error CMP body -> cmp/http-error (only an error arm is forwarded)", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s5b.opts))) === "cmp/http-error");
  var s5c = A.cmpOpts(A.pkixcmp(400, f.pkiconfDer));
  check("5 a 400 with a pkiconf body -> cmp/http-error", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s5c.opts))) === "cmp/http-error");

  // 6. a 4xx/5xx with NO CMP body throws cmp/http-error carrying the numeric status.
  var s6a = A.cmpOpts(A.resp(400, "<html>bad</html>", "text/html"));
  check("6 a 400 text/html (no CMP body) -> cmp/http-error", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s6a.opts))) === "cmp/http-error");
  var s6b = A.cmpOpts(A.resp(500, "", null));
  check("6 a 500 empty body -> cmp/http-error", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s6b.opts))) === "cmp/http-error");
  // a 4xx/5xx WITH the pkixcmp content-type but an UNDECODABLE body -> cmp/http-error (the parse-catch arm).
  var s6c = A.cmpOpts(A.pkixcmp(500, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])));
  check("6 a 500 pkixcmp with an undecodable body -> cmp/http-error", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s6c.opts))) === "cmp/http-error");

  // 7. wrong content-type on a 200 -> cmp/bad-content-type; body not decoded.
  var s7 = A.cmpOpts(A.resp(200, f.ipDer, "text/plain"));
  check("7 a 200 text/plain <ip> -> cmp/bad-content-type", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s7.opts))) === "cmp/bad-content-type");
  check("7 the body was not decoded (one call, no follow)", s7.transport.calls.length === 1);
  // a 200 with NO content-type header at all -> cmp/bad-content-type (the ctype-absent default arm).
  var s7b = A.cmpOpts({ status: 200, headers: {}, body: f.ipDer });
  check("7 a 200 with no content-type header -> cmp/bad-content-type", (await codeOf(pki.cmp.transfer(BASE, f.irDer, s7b.opts))) === "cmp/bad-content-type");

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
  check("14 with the opts argument omitted entirely -> cmp/no-trust-anchors", (await codeOf(pki.cmp.transfer(BASE, f.irDer))) === "cmp/no-trust-anchors");

  // 15. a non-DER/PEM message -> cmp/bad-input before the wire.
  var s15 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("15 a non-DER/PEM message -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, 12345, s15.opts))) === "cmp/bad-input");
  check("15 the config gate precedes the wire (no POST)", s15.transport.calls.length === 0);
  // a DETACHED request byte view (its backing ArrayBuffer transferred away) reads as length 0; it must be
  // rejected (cmp/bad-input) rather than POSTing an empty body in place of the protected message.
  var ab = new ArrayBuffer(f.irDer.length);
  new Uint8Array(ab).set(f.irDer);
  var detachedU8 = new Uint8Array(ab);
  structuredClone(ab, { transfer: [ab] });   // detaches ab -> detachedU8 now reads length 0
  var s15d = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("15 a detached request byte view -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, detachedU8, s15d.opts))) === "cmp/bad-input");
  check("15 no POST on a detached message", s15d.transport.calls.length === 0);
  // a well-formed Buffer that is NOT a PKIMessage (arbitrary / empty bytes) is validated locally as
  // cmp/bad-input rather than crossing the network seam (transfer accepts a DER PKIMessage).
  var s15g = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("15 a non-PKIMessage request buffer -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, Buffer.from([1, 2, 3]), s15g.opts))) === "cmp/bad-input");
  check("15 no POST on an invalid request message", s15g.transport.calls.length === 0);
  var s15e = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("15 an empty request buffer -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, Buffer.alloc(0), s15e.opts))) === "cmp/bad-input");
  // a malformed / non-PEM string message normalizes to cmp/bad-input (not a leaked PemError) at the boundary.
  var s15p = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("15 a non-PEM string message -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, "not a pem block", s15p.opts))) === "cmp/bad-input");

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
  // request-framing headers (content-length, transfer-encoding) and a case-variant content-type from
  // opts.headers are stripped: the verb sets the media type and the transport computes Content-Length, so a
  // caller cannot desync the request framing (HTTP smuggling) or override the media type through casing.
  var s19h = A.cmpOpts(A.pkixcmp(200, f.ipDer), { headers: { "Content-Length": "3", "Transfer-Encoding": "chunked", "Content-Type": "text/plain", "x-keep": "1" } });
  await pki.cmp.transfer(BASE, f.irDer, s19h.opts);
  var sentH = s19h.transport.calls[0].headers;
  var lowerH = {}; Object.keys(sentH).forEach(function (k) { lowerH[k.toLowerCase()] = sentH[k]; });
  check("19 a caller-supplied content-length is stripped", lowerH["content-length"] === undefined);
  check("19 a caller-supplied transfer-encoding is stripped", lowerH["transfer-encoding"] === undefined);
  check("19 a case-variant content-type cannot override the media type", lowerH["content-type"] === A.PKIXCMP && Object.keys(sentH).filter(function (k) { return k.toLowerCase() === "content-type"; }).length === 1);
  check("19 an unrelated custom header survives the strip", lowerH["x-keep"] === "1");

  // 20. wellKnownUrl RFC 9811 sec. 3.4 forms + fail-closed rejects.
  check("20 base -> /.well-known/cmp", pki.cmp.wellKnownUrl("https://ca.example") === "https://ca.example/.well-known/cmp");
  check("20 {operation} -> /.well-known/cmp/<op>", pki.cmp.wellKnownUrl("https://ca.example", { operation: "initialization" }) === "https://ca.example/.well-known/cmp/initialization");
  check("20 {label} -> /.well-known/cmp/p/<label>", pki.cmp.wellKnownUrl("https://ca.example", { label: "myca" }) === "https://ca.example/.well-known/cmp/p/myca");
  check("20 {label,operation} -> /.well-known/cmp/p/<label>/<op>", pki.cmp.wellKnownUrl("https://ca.example", { label: "myca", operation: "cr" }) === "https://ca.example/.well-known/cmp/p/myca/cr");
  check("20 a base with a query -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example/?x=1"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 a label containing '/' -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { label: "a/b" }); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 an operation with a dot-segment -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { operation: ".." }); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 an http base is BUILT (the transport enforces scheme, not this builder)", pki.cmp.wellKnownUrl("http://ca.example") === "http://ca.example/.well-known/cmp");
  check("20 a base with a non-root path -> cmp/bad-url (well-known is authority-rooted, RFC 8615)", (function () { try { pki.cmp.wellKnownUrl("https://ca.example/tenant"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 an authority-only base with a trailing slash is accepted", pki.cmp.wellKnownUrl("https://ca.example/") === "https://ca.example/.well-known/cmp");
  check("20 a non-http(s) base with an opaque origin (file://) -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("file:///"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 a data: base -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("data:text/plain,x"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  // an unencodable label/operation (an unpaired UTF-16 surrogate from malformed config) normalizes to
  // cmp/bad-url, not a raw untyped URIError. The surrogate is built at runtime (source stays pure ASCII).
  check("20 an unpaired-surrogate label -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { label: String.fromCharCode(0xd800) }); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 an unpaired-surrogate operation -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { operation: String.fromCharCode(0xdc00) }); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  // a mistyped option key is rejected (not silently ignored, which would target the default endpoint).
  check("20 an unknown wellKnownUrl option (typo) -> cmp/bad-input", (function () { try { pki.cmp.wellKnownUrl("https://ca.example", { lable: "myca" }); return null; } catch (e) { return e.code; } })() === "cmp/bad-input");
  check("20 an unparseable base -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl(":::"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  // a base whose path WHATWG normalizes to "/" (a literal or percent-encoded dot-segment) is still rejected:
  // the raw path is inspected before normalization, so a supplied path cannot silently target the root.
  check("20 a dot-segment base (/tenant/..) -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example/tenant/.."); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  check("20 a percent-encoded-dot base (/%2e) -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example/%2e"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");
  // a backslash after the authority (WHATWG rewrites it to a path separator) is rejected, not swallowed.
  check("20 a backslash-path base -> cmp/bad-url", (function () { try { pki.cmp.wellKnownUrl("https://ca.example\\tenant"); return null; } catch (e) { return e.code; } })() === "cmp/bad-url");

  // 21. budget guards run before the wire.
  var s21 = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("21 timeout:NaN -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, f.irDer, Object.assign({}, s21.opts, { timeout: NaN })))) === "cmp/bad-input");
  var s21b = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("21 maxResponseBytes:-1 -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, f.irDer, Object.assign({}, s21b.opts, { maxResponseBytes: -1 })))) === "cmp/bad-input");
  check("21 no POST on a bad budget", s21.transport.calls.length === 0 && s21b.transport.calls.length === 0);
  // an unknown transfer opt key is rejected (config typo fails closed), like build/wellKnownUrl.
  var s21u = A.cmpOpts(A.pkixcmp(200, f.ipDer));
  check("21 an unknown transfer opt -> cmp/bad-input", (await codeOf(pki.cmp.transfer(BASE, f.irDer, Object.assign({}, s21u.opts, { bogusOpt: 1 })))) === "cmp/bad-input");
  check("21 no POST on an unknown opt", s21u.transport.calls.length === 0);
  // defensive transport-contract guards: a transport returning undefined, or a null body, fails closed
  // (not a crash) -- covers the res/headers/body null-default arms.
  var calls21n = [];
  var nullTransport = function (req) { calls21n.push(req); return Promise.resolve(undefined); };
  check("21 a transport returning undefined -> cmp/unexpected-status (no crash)", (await codeOf(pki.cmp.transfer(BASE, f.irDer, { transport: nullTransport, tls: { anchors: [A.CERT_DER] } }))) === "cmp/unexpected-status");
  var nullBody = A.cmpOpts({ status: 200, headers: { "content-type": A.PKIXCMP }, body: null });
  check("21 a 200 pkixcmp with a null body -> cmp/empty-response", (await codeOf(pki.cmp.transfer(BASE, f.irDer, nullBody.opts))) === "cmp/empty-response");

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

  // An injected transport that yields no promise is a wiring fault in the caller's own code, so it is
  // reported as a typed option error naming the option rather than a confusing response verdict.
  var noReturn = Object.assign({}, A.cmpOpts(A.pkixcmp(200, f.ipDer)).opts, { transport: function () { } });
  check("a transport returning nothing is a typed option fault",
    (await codeOf(pki.cmp.transfer(BASE, f.irDer, noReturn))) === "cmp/bad-input");
  var plain = Object.assign({}, A.cmpOpts(A.pkixcmp(200, f.ipDer)).opts, { transport: function () { return { status: 200, headers: {}, body: "" }; } });
  check("a transport returning a non-promise response is refused the same way",
    (await codeOf(pki.cmp.transfer(BASE, f.irDer, plain))) === "cmp/bad-input");
  // Ordinary promise assimilation QUEUES the call to a foreign then rather than running it inline. This
  // verb reaches the transport synchronously, so it is where an inline call would be observable: a
  // thenable expecting to run after transfer() returned would instead see reentrant execution.
  var order = [];
  var deferredThenable = Object.assign({}, A.cmpOpts(A.pkixcmp(200, f.ipDer)).opts, {
    transport: function () {
      return { then: function (res) { order.push("then"); res({ status: 200, headers: { "content-type": A.PKIXCMP }, body: f.ipDer }); } };
    },
  });
  var pendingTransfer = pki.cmp.transfer(BASE, f.irDer, deferredThenable);
  order.push("verb-returned");
  await pendingTransfer;
  check("a foreign then is invoked after transfer returns, not inline during the call",
    order.join(",") === "verb-returned,then");

  console.log("CHECKS " + helpers.getChecks());
}

run();
