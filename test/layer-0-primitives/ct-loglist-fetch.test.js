// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.ct.fetchLogList (RFC 6962 sec. 3.2; the Chrome/Apple detached log_list.sig model). The
 * live-fetch arm that turns the shipped OFFLINE pair (verifyLogListSignature + parseLogList) into a
 * fetch-then-verify-then-ingest client over the shared injectable pki.transport. The load-bearing security
 * property is VERIFY-BEFORE-PARSE: the fetched log_list.json is attacker-influenced bytes until the detached
 * log_list.sig verifies over the RAW bytes against the caller-PINNED distributor key -- the client must NOT
 * parse, read the timestamp/version/logs, cache, or surface any field of an unverified document. Every
 * vector runs OFFLINE through the routing fixture transport (no socket); the fixture pair is
 * cryptographically real (a log key whose SHA-256(SPKI) matches its log_id + a generated distributor key
 * signing the exact JSON bytes). The node:https/tls loopback end-to-end path is covered by the interop test.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");
var https = require("node:https");
var signing = require("../helpers/signing");
var ctx = require("../helpers/ct-fetch-transport");

var JSON_URL = ctx.JSON_URL, SIG_URL = ctx.SIG_URL;

async function code(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function got(fn) { try { return await fn(); } catch (e) { return (e && e.code) || e.constructor.name; } }

// A one-byte content flip that keeps the JSON structurally valid (flips a letter inside the operator name).
function tamper(json) {
  var out = Buffer.from(json);
  var idx = out.indexOf(Buffer.from("Test Operator"));
  out[idx] = out[idx] ^ 0x01;   // 'T' (0x54) -> 'U' (0x55): still a valid JSON string, sig no longer matches
  return out;
}

// A structurally-valid-JSON but parse-REJECTED log list (a log whose log_id disagrees with its key), signed
// under a fresh distributor key that is pinned -- so the signature VERIFIES but parseLogList fail-closes.
function malformedButSigned() {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var doc = { version: "3", log_list_timestamp: "2024-01-01T00:00:00Z", operators: [{ name: "Op", email: ["x@example.com"],
    logs: [{ description: "Bad", log_id: Buffer.alloc(32, 9).toString("base64"), key: spki.toString("base64"), url: "https://x/", mmd: 86400, state: { usable: { timestamp: "2022-01-01T00:00:00Z" } } }], tiled_logs: [] }] };
  var json = Buffer.from(JSON.stringify(doc));
  var dist = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { json: json, sig: crypto.sign("sha256", json, dist.privateKey), signerKey: dist.publicKey.export({ format: "der", type: "spki" }) };
}

async function run() {
  var fx = ctx.makeFixture();

  // ==== 1. happy / round-trip (M1/M2/M4/M9/M10) =====================================================
  var h = ctx.ctFetchOpts(fx, ctx.okRoutes(fx));
  var out = await got(function () { return pki.ct.fetchLogList(h.opts); });
  check("1. resolves the trusted-log set on a verified fixture", out && Array.isArray(out.logs) && out.logs.length === 1);
  check("1. byLogId is keyed by the recomputed SHA-256(SPKI) id", out.byLogId && !!out.byLogId[fx.logIdHex]);
  check("1. the recovered log key byte-equals the fixture SPKI", out.logs && out.logs[0].key && out.logs[0].key.equals(fx.spki));
  check("1. the log-id recompute matches", out.logs && crypto.createHash("sha256").update(out.logs[0].key).digest("hex") === fx.logIdHex);
  check("1. the log state is trusted (usable)", out.logs && out.logs[0].trusted === true);
  check("1. status is 200", out.status === 200);
  check("1. version is surfaced from the verified doc", out.version === "3");
  check("1. timestamp is surfaced as a Date", out.timestamp instanceof Date && out.timestamp.toISOString() === "2024-01-01T00:00:00.000Z");
  check("1. raw.json/raw.sig are the exact authenticated bytes", out.raw && out.raw.json.equals(fx.json) && out.raw.sig.equals(fx.sig));

  // ==== 2. VERIFY-BEFORE-PARSE -- the load-bearing negative (M1) ====================================
  var t2 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { json: ctx.resp(200, tamper(fx.json), "application/json") }));
  var c2 = await code(function () { return pki.ct.fetchLogList(t2.opts); });
  check("2. a one-byte-tampered (still valid JSON) list with the original sig -> ct/log-list-untrusted", c2 === "ct/log-list-untrusted");
  check("2. the verdict is NOT a parse-domain code (parse never ran)", c2 !== "ct/bad-log-list" && c2 !== "ct/log-id-mismatch" && c2 !== "ct/bad-json");

  // ==== 3. wrong pinned key (M3) ====================================================================
  var t3 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { signerKey: ctx.otherSignerKey() });
  check("3. a valid document under the WRONG pinned key -> ct/log-list-untrusted", (await code(function () { return pki.ct.fetchLogList(t3.opts); })) === "ct/log-list-untrusted");

  // ==== 4. missing signerKey (M3/M11) ==============================================================
  var t4 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { signerKey: undefined });
  check("4. an omitted signerKey -> config-time ct/bad-input", (await code(function () { return pki.ct.fetchLogList(t4.opts); })) === "ct/bad-input");
  check("4. no socket was reached (calls.length === 0)", t4.transport.calls.length === 0);
  var t4b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { signerKey: null });
  check("4. a null signerKey -> ct/bad-input", (await code(function () { return pki.ct.fetchLogList(t4b.opts); })) === "ct/bad-input");

  // ==== 5. byte-identity: the surfaced raw is the exact fetched bytes (M2) ==========================
  var t5 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx));
  var o5 = await got(function () { return pki.ct.fetchLogList(t5.opts); });
  check("5. raw.json is the fetched JSON verbatim (no re-serialize between verify and parse)", o5 && o5.raw && o5.raw.json.equals(fx.json) && o5.raw.sig.equals(fx.sig));

  // ==== 6. oversized response (M5) =================================================================
  var t6 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { maxResponseBytes: 8 });
  var c6 = await code(function () { return pki.ct.fetchLogList(t6.opts); });
  check("6. a JSON body over maxResponseBytes -> ct/response-too-large before verify/parse", c6 === "ct/response-too-large");
  check("6. the oversized verdict is NOT a parse-domain code", c6 !== "ct/bad-log-list" && c6 !== "ct/bad-json");

  // ==== 7. partial fetch -- both GETs must succeed (M8) =============================================
  var t7a = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { sig: ctx.resp(404) }));
  check("7. JSON 200 but sig 404 -> ct/http-error", (await code(function () { return pki.ct.fetchLogList(t7a.opts); })) === "ct/http-error");
  var t7b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { json: ctx.resp(404) }));
  check("7. sig would 200 but JSON 404 -> ct/http-error", (await code(function () { return pki.ct.fetchLogList(t7b.opts); })) === "ct/http-error");

  // ==== 8. non-200 statuses + empty bodies (M8) ====================================================
  var t8a = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { json: ctx.resp(500, fx.json, "application/json") }));
  check("8. a 500 on the JSON GET -> ct/http-error", (await code(function () { return pki.ct.fetchLogList(t8a.opts); })) === "ct/http-error");
  var t8b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { json: ctx.resp(200, "", "application/json") }));
  check("8. a 200 with an empty JSON body -> ct/empty-response", (await code(function () { return pki.ct.fetchLogList(t8b.opts); })) === "ct/empty-response");
  var t8c = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { sig: ctx.resp(200, "", "application/octet-stream") }));
  check("8. a 200 with an empty SIG body -> ct/empty-response", (await code(function () { return pki.ct.fetchLogList(t8c.opts); })) === "ct/empty-response");

  // ==== 9. bad url / sigUrl (M11, Build #3) ========================================================
  var t9a = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { url: "http://[oops" });
  check("9. an unparseable url -> ct/bad-url before the wire", (await code(function () { return pki.ct.fetchLogList(t9a.opts); })) === "ct/bad-url");
  check("9. no socket reached on a bad url (calls.length === 0)", t9a.transport.calls.length === 0);
  var t9b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { url: "https://ct.example.test/logs" });
  check("9. a non-.json url with no explicit sigUrl -> ct/bad-input", (await code(function () { return pki.ct.fetchLogList(t9b.opts); })) === "ct/bad-input");
  check("9. no socket reached when sigUrl cannot be derived", t9b.transport.calls.length === 0);
  // an http url is refused BEFORE the wire -- the https gate runs across the injectable seam, so an insecure
  // URL never reaches the transport (a generic injected transport cannot be steered to cleartext).
  var t9c = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { url: "http://ct.example.test/log_list.json" });
  check("9. an http url is refused (ct/insecure-url) even with an injected transport", (await code(function () { return pki.ct.fetchLogList(t9c.opts); })) === "ct/insecure-url");
  check("9. no socket reached on an insecure url", t9c.transport.calls.length === 0);
  var t9d = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { sigUrl: "http://ct.example.test/log_list.sig" });
  check("9. an http explicit sigUrl is refused (ct/insecure-url)", (await code(function () { return pki.ct.fetchLogList(t9d.opts); })) === "ct/insecure-url");
  check("9. no socket reached on an insecure sigUrl", t9d.transport.calls.length === 0);

  // ==== 10. default sigUrl derivation (Build #3) ===================================================
  var t10 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx));   // no sigUrl -> derived .json -> .sig
  await got(function () { return pki.ct.fetchLogList(t10.opts); });
  check("10. the JSON GET targets the url", t10.transport.calls[0] && t10.transport.calls[0].url === JSON_URL);
  check("10. the sig GET targets the derived .sig url", t10.transport.calls[1] && t10.transport.calls[1].url === SIG_URL);
  // an explicit sigUrl (a non-standard layout) is used verbatim, not derived
  var explicitSig = "https://ct.example.test/detached/log_list.signature";
  var routes10b = {}; routes10b[JSON_URL] = ctx.resp(200, fx.json, "application/json"); routes10b[explicitSig] = ctx.resp(200, fx.sig, "application/octet-stream");
  var t10b = ctx.routeByUrl(routes10b);
  var o10b = await got(function () { return pki.ct.fetchLogList({ transport: t10b, url: JSON_URL, sigUrl: explicitSig, signerKey: fx.signerKey }); });
  check("10. an explicit sigUrl is used verbatim (not derived)", o10b && Array.isArray(o10b.logs) && t10b.calls[1] && t10b.calls[1].url === explicitSig);

  // ==== 11. request conformance (M7/M8/M10) ========================================================
  var t11 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx));
  await got(function () { return pki.ct.fetchLogList(t11.opts); });
  check("11. exactly two requests crossed the seam", t11.transport.calls.length === 2);
  check("11. both are GET", t11.transport.calls[0].method === "GET" && t11.transport.calls[1].method === "GET");
  check("11. neither GET carries a body", t11.transport.calls[0].body == null && t11.transport.calls[1].body == null);

  // ==== 11b. the detached signature must SHARE the log-list origin (no cross-origin credential/TLS leak) ====
  // A cross-origin sigUrl is refused BEFORE the wire, so a caller's Authorization/Cookie header or mTLS client
  // cert configured for the log-list host can never reach a different signature host.
  var t11b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { sigUrl: "https://sig-cdn.example.test/log_list.sig" });
  check("11b. a cross-origin sigUrl is refused (ct/bad-input) before the wire", (await code(function () { return pki.ct.fetchLogList(t11b.opts); })) === "ct/bad-input");
  check("11b. no socket reached on a cross-origin sigUrl", t11b.transport.calls.length === 0);

  // ==== 12. stale timestamp SURFACED, not rejected (M9, Build #6) ===================================
  var stale = ctx.makeFixture({ timestamp: "2019-01-01T00:00:00Z" });
  var t12 = ctx.ctFetchOpts(stale, ctx.okRoutes(stale));
  var o12 = await got(function () { return pki.ct.fetchLogList(t12.opts); });
  check("12. an old (2019) but validly-signed list resolves (staleness is surfaced, not policed)", o12 && Array.isArray(o12.logs));
  check("12. the old timestamp is returned for the caller to police", o12 && o12.timestamp instanceof Date && o12.timestamp.toISOString() === "2019-01-01T00:00:00.000Z");

  // ==== 12b. a transport that is not callable ======================================================
  // A wiring fault the operator makes at config time, so the option is named at the door. A FALSY
  // transport is the same fault and must not be read as "none supplied": falling back to the default
  // client would fetch the log list over the network for a caller that believed it had injected one.
  async function badTransport(v) {
    try { await pki.ct.fetchLogList({ transport: v, url: JSON_URL, sigUrl: SIG_URL, signerKey: fx.signerKey }); return "NO-THROW"; }
    catch (e) { return (e && e.code === "ct/bad-input" && String(e.message).indexOf("opts.transport") !== -1) ? "typed" : ((e && e.code) || "RAW"); }
  }
  check("12b. a non-callable transport is refused, naming the option", (await badTransport(42)) === "typed");
  check("12b. an object transport is refused, naming the option", (await badTransport({})) === "typed");
  check("12b. a falsy transport is refused rather than falling back to the network", (await badTransport(0)) === "typed");
  check("12b. an explicit null transport is refused, not read as an omitted option", (await badTransport(null)) === "typed");

  // ==== 13. no-trust-anchors on the DEFAULT transport (M6) ==========================================
  check("13. no injected transport + no anchors + no useSystemStore -> ct/no-trust-anchors", (await code(function () {
    return pki.ct.fetchLogList({ url: JSON_URL, sigUrl: SIG_URL, signerKey: fx.signerKey });
  })) === "ct/no-trust-anchors");

  // ==== 14. transport fault surfaces, no re-fetch (M8) ==============================================
  var faults = { }; faults[JSON_URL] = function () { return Promise.reject(new pki.errors.PkiError("the CT request timed out", "ct/timeout")); };
  var t14 = ctx.routeByUrl(faults);
  var c14 = await code(function () { return pki.ct.fetchLogList({ transport: t14, url: JSON_URL, signerKey: fx.signerKey }); });
  check("14. an injected transport fault surfaces unchanged", c14 === "ct/timeout");
  check("14. the client does not re-GET after a fault (calls.length === 1)", t14.calls.length === 1);
  // an injected transport that rejects with an ORDINARY (untyped) Error is wrapped as a typed
  // ct/transport-error -- the documented typed-error contract holds even for a custom transport that simply
  // forwards a raw fetch/socket failure; an already-typed PkiError (vector 14 above) is preserved unchanged.
  var rawReject = {}; rawReject[JSON_URL] = function () { return Promise.reject(new Error("ECONNREFUSED")); };
  var traw = ctx.routeByUrl(rawReject);
  check("14. a raw (untyped) transport rejection is wrapped as ct/transport-error", (await code(function () { return pki.ct.fetchLogList({ transport: traw, url: JSON_URL, signerKey: fx.signerKey }); })) === "ct/transport-error");
  // a SYNCHRONOUS throw from an injected transport is likewise wrapped (never a raw error crossing the boundary)
  var syncThrow = function () { throw new Error("boom"); };
  check("14. a synchronous transport throw is wrapped as ct/transport-error", (await code(function () { return pki.ct.fetchLogList({ transport: syncThrow, url: JSON_URL, signerKey: fx.signerKey }); })) === "ct/transport-error");

  // ==== 15. config budget guards (M5/M11) ==========================================================
  var t15a = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { timeout: NaN });
  check("15. timeout:NaN -> ct/bad-input", (await code(function () { return pki.ct.fetchLogList(t15a.opts); })) === "ct/bad-input");
  check("15. no socket reached on a bad budget", t15a.transport.calls.length === 0);
  var t15b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { maxResponseBytes: -1 });
  check("15. maxResponseBytes:-1 -> ct/bad-input", (await code(function () { return pki.ct.fetchLogList(t15b.opts); })) === "ct/bad-input");
  var t15c = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { maxResponseBytes: pki.C.LIMITS.CT_LOG_LIST_MAX_BYTES * 4 });
  check("15. maxResponseBytes above the CT cap -> ct/bad-input (tightenable downward only)", (await code(function () { return pki.ct.fetchLogList(t15c.opts); })) === "ct/bad-input");

  // ==== 16. unknown opts key (M11) =================================================================
  var t16 = ctx.ctFetchOpts(fx, ctx.okRoutes(fx), { notAnOpt: 1 });
  check("16. a typo'd opts key -> ct/bad-input before the wire", (await code(function () { return pki.ct.fetchLogList(t16.opts); })) === "ct/bad-input");
  check("16. no socket reached on an unknown opt", t16.transport.calls.length === 0);

  // ==== 17. content-type: lenient by default, strict opt-in (Build #4) ==============================
  var t17a = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { json: ctx.resp(200, fx.json, "text/plain") }));
  var o17a = await got(function () { return pki.ct.fetchLogList(t17a.opts); });
  check("17. a text/plain JSON GET still resolves by default (lenient)", o17a && Array.isArray(o17a.logs));
  var t17b = ctx.ctFetchOpts(fx, ctx.okRoutes(fx, { json: ctx.resp(200, fx.json, "text/plain") }), { requireJsonContentType: true });
  check("17. requireJsonContentType:true -> ct/bad-content-type on a non-JSON type", (await code(function () { return pki.ct.fetchLogList(t17b.opts); })) === "ct/bad-content-type");

  // ==== 18. malformed post-verify JSON -- parse runs ONLY after verify (M4) =========================
  var mal = malformedButSigned();
  var routes18 = {}; routes18[JSON_URL] = ctx.resp(200, mal.json, "application/json"); routes18[SIG_URL] = ctx.resp(200, mal.sig, "application/octet-stream");
  var t18 = ctx.routeByUrl(routes18);
  var c18 = await code(function () { return pki.ct.fetchLogList({ transport: t18, url: JSON_URL, signerKey: mal.signerKey }); });
  check("18. a verified-but-malformed list surfaces the parser's fail-closed verdict", c18 === "ct/log-id-mismatch" || c18 === "ct/bad-log-list" || c18 === "ct/bad-json");

  await testLoopback(fx);
  console.log("CHECKS " + helpers.getChecks());
}

// ==== 19. end to end over the REAL pki.transport.https (a node:https/tls loopback) ==================
// A self-signed cert (SAN dNSName localhost) supplied as the explicit anchor -- verification ON, no
// external host -- so fetchLogList drives the real socket + TLS trust + streaming cap end to end.
async function selfSigned() {
  var s = signing.makeSigner("ec-p256", { cn: "ct-distributor.example" });
  var certDer = await pki.x509.sign({
    subject: "ct-distributor.example", subjectPublicKey: s.spki,
    notBefore: new Date("2024-01-01T00:00:00Z"), notAfter: new Date("2044-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"], subjectAltName: [{ dNSName: "localhost" }], subjectKeyIdentifier: true },
  }, { key: s.key });
  return { certPem: pki.schema.x509.pemEncode(certDer, "CERTIFICATE"), keyPem: pki.schema.pkcs8.pemEncode(s.key, "PRIVATE KEY") };
}
function startServer(tls, handler) {
  return new Promise(function (resolve) {
    var srv = https.createServer({ cert: tls.certPem, key: tls.keyPem }, handler);
    srv.on("clientError", function () { /* a rejected handshake is a test's point */ });
    srv.listen(0, "127.0.0.1", function () { resolve({ srv: srv, port: srv.address().port }); });
  });
}

async function testLoopback(fx) {
  var tls = await selfSigned();
  // (a) happy end-to-end: serve the fixture pair; fetchLogList over the real transport recovers the set.
  var s = await startServer(tls, function (req, res) {
    if (/\.sig$/.test(req.url)) { res.writeHead(200, { "content-type": "application/octet-stream" }); res.end(fx.sig); }
    else { res.writeHead(200, { "content-type": "application/json" }); res.end(fx.json); }
  });
  try {
    var base = "https://127.0.0.1:" + s.port;
    var out = await pki.ct.fetchLogList({ url: base + "/log_list.json", signerKey: fx.signerKey, tls: { anchors: [tls.certPem], servername: "localhost" } });
    check("19. a full round-trip over the real node:https transport recovers the trusted set", out && out.logs.length === 1 && out.logs[0].key.equals(fx.spki));
    check("19. the negotiated TLS is surfaced", out.tls && /^TLSv1\.[23]$/.test(out.tls.protocol));
  } finally { s.srv.close(); }
  // (b) a stalled server: the wall-clock timeout fires and the socket is destroyed -> ct/timeout.
  var stall = await startServer(tls, function () { /* never respond */ });
  try {
    var c = await code(function () {
      return pki.ct.fetchLogList({ url: "https://127.0.0.1:" + stall.port + "/log_list.json", signerKey: fx.signerKey, timeout: 800, tls: { anchors: [tls.certPem], servername: "localhost" } });
    });
    check("19. a stalled server -> ct/timeout (the wall-clock budget, socket destroyed)", c === "ct/timeout");
  } finally { stall.srv.close(); }
}

run().then(null, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); });
