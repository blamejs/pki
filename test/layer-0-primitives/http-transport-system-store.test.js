// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- what `tls.useSystemStore` trusts, and the Host header a default-port request sends.
 *
 * The transport binds `tls.getCACertificates`, `tls.connect` and `net.connect` when it loads, so a
 * wrapper installed afterwards is never consulted. Each vector therefore runs in a child process
 * that installs its wrappers BEFORE requiring the toolkit: one records the `ca` list every TLS
 * connection is opened with, one decides what the platform store answers, and one routes a
 * connection made to port 80 or 443 to a loopback server, so a URL that names no port reaches it.
 *
 * Every child runs with NODE_EXTRA_CA_CERTS naming the test root. Node adds that file to its
 * default store, which is the store a connection uses when it is given no `ca` at all. A vector
 * that reaches the server under it has fallen back to Node's default store.
 *
 *   SS1-SS2  useSystemStore hands TLS the platform store and nothing else
 *   SS3-SS4  an empty platform store is refused, on the origin and on an https proxy
 *   SS5-SS6  a request that states no port sends a Host header with no port
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var childProcess = require("child_process");

if (process.argv[2] === "--child") {
  childMain(process.argv[3], JSON.parse(process.env.PKI_TEST_FIXTURE)).then(function (out) {
    process.stdout.write("RESULT " + JSON.stringify(out) + "\n");
    process.exit(0);
  }, function (e) {
    process.stdout.write("RESULT " + JSON.stringify({ crashed: String(e && e.stack || e) }) + "\n");
    process.exit(0);
  });
} else {
  module.exports = { run: run };
  if (require.main === module) {
    run().then(function () {}, function (e) { console.error(e && e.stack || e); process.exit(1); });
  }
}

async function childMain(mode, fx) {
  var tls = require("tls");
  var net = require("net");
  var realGetCa = tls.getCACertificates;
  var realTlsConnect = tls.connect;
  var realNetConnect = net.connect;
  var recordedCa = [];
  if (mode === "throw-system") {
    tls.getCACertificates = function (type) {
      if (type === "system") throw new Error("the platform store could not be read");
      return realGetCa.call(tls, type);
    };
  }
  if (mode === "empty-system" || mode === "empty-all" || mode === "proxy-empty") {
    tls.getCACertificates = function (type) {
      if (type === "system") return [];
      if (type === "bundled" && mode === "empty-all") return [];
      return realGetCa.call(tls, type);
    };
  }
  tls.connect = function (opts) {
    if (opts && typeof opts === "object") {
      recordedCa.push(opts.ca === undefined ? null : (Array.isArray(opts.ca) ? opts.ca.length : 1));
      if (mode === "host" && (opts.port === 443 || opts.port === "443") && !opts.socket) opts.port = fx.httpsPort;
    }
    return realTlsConnect.apply(this, arguments);
  };
  net.connect = function (opts) {
    if (mode === "host" && opts && typeof opts === "object" && (opts.port === 80 || opts.port === "80")) opts.port = fx.httpPort;
    return realNetConnect.apply(this, arguments);
  };

  var pki = require(fx.repo + "/index.js");
  var https = require("https");
  var http = require("http");
  var seenHosts = [];
  var srv = https.createServer({ cert: fs.readFileSync(fx.leafChainPem), key: fs.readFileSync(fx.leafKeyPem) },
    function (req, res) { seenHosts.push(req.headers.host); res.end("reached"); });
  srv.on("clientError", function () {});
  var plain = http.createServer(function (req, res) { seenHosts.push(req.headers.host); res.end("reached"); });
  await new Promise(function (r) { srv.listen(fx.httpsPort || 0, "127.0.0.1", r); });
  await new Promise(function (r) { plain.listen(fx.httpPort || 0, "127.0.0.1", r); });
  var port = srv.address().port;
  function codeOf(p) { return p.then(function (res) { return "OK " + res.status; }, function (e) { return e.code || ("RAW " + e.message); }); }
  var out = { mode: mode };
  try {
    var t = pki.transport.https({});
    if (mode === "real") {
      out.code = await codeOf(t({ method: "GET", url: "https://localhost:" + port + "/", tls: { useSystemStore: true }, timeout: 5000 }));
      out.systemLen = realGetCa.call(tls, "system").length;
      out.recorded = recordedCa;
    } else if (mode === "throw-system") {
      out.code = await codeOf(t({ method: "GET", url: "https://localhost:" + port + "/", tls: { useSystemStore: true }, timeout: 5000 }));
    } else if (mode === "empty-system" || mode === "empty-all") {
      out.code = await codeOf(t({ method: "GET", url: "https://localhost:" + port + "/", tls: { useSystemStore: true }, timeout: 5000 }));
      out.connectsBeforeAnchor = recordedCa.length;
      out.peerCode = await codeOf(pki.transport.peerChain({ url: "https://localhost:" + port + "/", timeout: 5000 }, { tls: { useSystemStore: true } }));
      out.withAnchor = await codeOf(t({ method: "GET", url: "https://localhost:" + port + "/",
        tls: { useSystemStore: true, anchors: [fs.readFileSync(fx.rootPem, "latin1")] }, timeout: 5000 }));
      out.recorded = recordedCa;
    } else if (mode === "proxy-empty") {
      out.code = await codeOf(t({ method: "GET", url: "https://localhost:" + port + "/",
        tls: { anchors: [fs.readFileSync(fx.rootPem, "latin1")] },
        proxy: { url: "https://127.0.0.1:" + port, tls: { useSystemStore: true } }, timeout: 5000 }));
    } else if (mode === "host") {
      out.plain = await codeOf(t({ method: "GET", url: "http://localhost/", allowPlaintextHttp: true, timeout: 5000 }));
      out.secure = await codeOf(t({ method: "GET", url: "https://localhost/", tls: { anchors: [fs.readFileSync(fx.rootPem, "latin1")] }, timeout: 5000 }));
      out.explicit = await codeOf(t({ method: "GET", url: "http://localhost:" + plain.address().port + "/", allowPlaintextHttp: true, timeout: 5000 }));
      out.explicitPort = plain.address().port;
      out.hosts = seenHosts;
    }
  } finally {
    srv.close();
    plain.close();
  }
  return out;
}

async function run() {
  var helpers = require("../helpers");
  var pki = helpers.pki;
  var check = helpers.check;
  var signing = require("../helpers/signing");
  var tlsMod = require("tls");

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-sysstore-"));
  var root = signing.makeSigner("ec-p256");
  var leaf = signing.makeSigner("ec-p256");
  var NB = new Date("2024-01-01T00:00:00Z"), NA = new Date("2044-01-01T00:00:00Z");
  var rootDer = await pki.x509.sign({ subject: "System Store Test Root", subjectPublicKey: root.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: root.key });
  var leafDer = await pki.x509.sign({ subject: "localhost", subjectPublicKey: leaf.spki, notBefore: NB, notAfter: NA,
    extensions: { subjectAltName: [{ dNSName: "localhost" }, { iPAddress: "127.0.0.1" }], keyUsage: ["digitalSignature"] } },
    { cert: rootDer, key: root.key });
  var rootPem = path.join(dir, "root.pem");
  var chainPem = path.join(dir, "chain.pem");
  var keyPem = path.join(dir, "key.pem");
  fs.writeFileSync(rootPem, pki.schema.x509.pemEncode(rootDer, "CERTIFICATE"));
  fs.writeFileSync(chainPem, pki.schema.x509.pemEncode(leafDer, "CERTIFICATE") + pki.schema.x509.pemEncode(rootDer, "CERTIFICATE"));
  fs.writeFileSync(keyPem, pki.schema.pkcs8.pemEncode(leaf.key, "PRIVATE KEY"));

  function child(mode, extra) {
    var fx = Object.assign({ repo: path.resolve(__dirname, "../.."), rootPem: rootPem, leafChainPem: chainPem, leafKeyPem: keyPem }, extra || {});
    var env = Object.assign({}, process.env, { NODE_EXTRA_CA_CERTS: rootPem, PKI_TEST_FIXTURE: JSON.stringify(fx) });
    var r = childProcess.spawnSync(process.execPath, [__filename, "--child", mode], { env: env, encoding: "utf8", timeout: 60000 });
    var line = String(r.stdout || "").split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0];
    if (!line) throw new Error("child " + mode + " produced no result: " + r.stdout + r.stderr);
    var out = JSON.parse(line.slice(7));
    if (out.crashed) throw new Error("child " + mode + " crashed: " + out.crashed);
    return out;
  }

  // ---- SS1-SS2: the platform store, and nothing else ------------------------------------------
  var real = child("real");
  check("SS1. useSystemStore does not trust a root that only Node's default store carries (" + real.code + ")",
    real.code === "transport/server-auth-failed");
  check("SS2. the CA list handed to TLS is the platform store alone, not the platform store plus Node's bundled set (" +
    JSON.stringify(real.recorded) + " vs system " + real.systemLen + ")",
    real.recorded.length === 1 && real.recorded[0] === real.systemLen);

  // ---- SS3-SS4: an empty platform store is a refusal, not Node's default store ----------------
  if (typeof tlsMod.getCACertificates === "function") {
    var emptySys = child("empty-system");
    check("SS3. an empty platform store is refused before a socket opens (" + emptySys.code + ")",
      emptySys.code === "transport/no-trust-anchors" && emptySys.connectsBeforeAnchor === 0);
    check("SS3b. ...on peerChain as well (" + emptySys.peerCode + ")", emptySys.peerCode === "transport/no-trust-anchors");
    check("SS3c. ...while a request that also names an anchor still connects under that anchor (" + emptySys.withAnchor + ")",
      emptySys.withAnchor === "OK 200");
    var emptyAll = child("empty-all");
    check("SS3d. with every store empty the request is refused rather than handed Node's default store (" + emptyAll.code + ")",
      emptyAll.code === "transport/no-trust-anchors");
    var throwing = child("throw-system");
    check("SS3e a platform store that cannot be read is refused like an empty one (" + throwing.code + ")",
      throwing.code === "transport/no-trust-anchors");
    var proxyEmpty = child("proxy-empty");
    check("SS4. an https proxy under useSystemStore with an empty platform store is refused (" + proxyEmpty.code + ")",
      proxyEmpty.code === "transport/no-trust-anchors");
  }

  // ---- SS5-SS6: the Host header -------------------------------------------------------------
  var free = await new Promise(function (r) {
    var s = require("net").createServer(); s.listen(0, "127.0.0.1", function () { var p = s.address().port; s.close(function () { r(p); }); });
  });
  var free2 = await new Promise(function (r) {
    var s = require("net").createServer(); s.listen(0, "127.0.0.1", function () { var p = s.address().port; s.close(function () { r(p); }); });
  });
  var host = child("host", { httpPort: free, httpsPort: free2 });
  check("SS5. an http URL with no port sends Host without :80 (" + JSON.stringify(host.hosts) + ")",
    host.plain === "OK 200" && host.hosts[0] === "localhost");
  check("SS5b. an https URL with no port sends Host without :443", host.secure === "OK 200" && host.hosts[1] === "localhost");
  check("SS6. a URL that states a port still sends it", host.explicit === "OK 200" && host.hosts[2] === "localhost:" + host.explicitPort);

  fs.rmSync(dir, { recursive: true, force: true });
  console.log("CHECKS " + helpers.getChecks());
}
