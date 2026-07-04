// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// examples/wiki/test/e2e.js — end-to-end gate for the source-driven
// documentation site.
//
// Boots the real HTTP server on an ephemeral port and drives it the way a
// browser would: fetch the home page and every namespace page, assert a
// 200, an <h1>, and populated content (the intro + at least one rendered
// @primitive section with its signature). Also runs the comment-block
// validator against the toolkit's lib/ so block drift fails the wiki gate
// as well as the standalone static gate.
//
// Prints "CHECKS <n>" on success; prints the error and exits 1 on the
// first failure — matching the smoke-runner convention.

var http = require("node:http");

var server    = require("../server");
var site      = require("../site.config");
var generator = require("../lib/page-generator");
var engine    = require("../lib/source-comment-block-validator");
var parser    = require("../lib/source-doc-parser");

var _checks = 0;
function check(label, cond) {
  if (!cond) throw new Error("FAIL: " + label);
  _checks += 1;
}

function _get(port, urlPath) {
  return new Promise(function (resolve, reject) {
    var req = http.get({ host: "127.0.0.1", port: port, path: urlPath }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8"), headers: res.headers });
      });
    });
    req.on("error", reject);
    req.setTimeout(5000, function () { req.destroy(new Error("request timeout for " + urlPath)); });
  });
}

async function run() {
  // ---- Comment-block validity is a precondition for a coherent site ----
  var findings = engine.validate({ libDir: site.LIB_DIR, parser: parser });
  check("comment blocks validate with zero findings", findings.length === 0);
  if (findings.length) {
    findings.forEach(function (f) {
      console.error("  [" + f.kind + "] " + f.file + (f.primitive ? " :: " + f.primitive : "") + " — " + f.msg);
    });
  }

  // ---- The generated site must have a home + one page per namespace ----
  var built = generator.build({});
  var entries = site.entries();
  check("at least one namespace was derived from lib/", entries.length >= 1);
  check("home page exists", !!built.pages["/"]);

  entries.forEach(function (e) {
    check("page generated for namespace " + e.slug, !!built.pages["/" + e.slug]);
  });

  // Every nav item round-trips through groupForPath().
  built.navGroups.forEach(function (g) {
    check("nav group '" + g.group + "' is non-empty", g.items.length >= 1);
    g.items.forEach(function (it) {
      check("groupForPath resolves " + it.path, built.groupForPath(it.path) === g.group);
    });
  });

  // ---- Boot the real server + drive it over HTTP ----
  var srv = server.createServer(built);
  await new Promise(function (resolve) { srv.listen(0, "127.0.0.1", resolve); });
  var port = srv.address().port;

  try {
    // Home page.
    var home = await _get(port, "/");
    check("GET / -> 200", home.status === 200);
    check("home renders an <h1>", /<h1[^>]*>[\s\S]*?<\/h1>/.test(home.body));
    check("home references the brand pkijs.com", home.body.indexOf("pkijs.com") !== -1);
    check("home links the logo", home.body.indexOf("/pkijs-logo.png") !== -1);
    // At least one home card links to a namespace page.
    check("home shows at least one namespace card", entries.some(function (e) {
      return home.body.indexOf('href="/' + e.slug + '"') !== -1;
    }));

    // Logo asset serves as image/png.
    var logo = await _get(port, "/pkijs-logo.png");
    check("GET /pkijs-logo.png -> 200", logo.status === 200);
    check("logo served as image/png", String(logo.headers["content-type"]).indexOf("image/png") === 0);

    // Each namespace page.
    var docs = parser.parseTree(site.LIB_DIR);
    var primCountByNs = {};
    Object.keys(docs).forEach(function (f) {
      var rec = docs[f];
      if (!rec.module) return;
      var ns = String(rec.module.tags.module || "").replace(/^\s*pki\./, "").trim();
      if (ns) primCountByNs[ns] = rec.primitives.length;
    });

    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var pth = "/" + e.slug;
      var resp = await _get(port, pth);
      check("GET " + pth + " -> 200", resp.status === 200);
      check(pth + " renders an <h1>", /<h1[^>]*>[\s\S]*?<\/h1>/.test(resp.body));
      check(pth + " <h1> carries the title", resp.body.indexOf(">" + e.title + "</h1>") !== -1 ||
        resp.body.indexOf(e.title + "</h1>") !== -1);
      // Populated content: at least one rendered primitive section.
      var wantPrims = primCountByNs[e.namespaces[0]] || 0;
      check(pth + " renders " + wantPrims + " primitive section(s)",
        (resp.body.match(/<section class="primitive"/g) || []).length === wantPrims);
      check(pth + " content is substantial", resp.body.length > 800);
      // Every documented primitive of this namespace appears by name.
      docs && Object.keys(docs).forEach(function (f) {
        var rec = docs[f];
        if (!rec.module) return;
        var ns = String(rec.module.tags.module || "").replace(/^\s*pki\./, "").trim();
        if (ns !== e.namespaces[0]) return;
        rec.primitives.forEach(function (p) {
          var tag = p.tags && p.tags.primitive;
          if (tag) check(pth + " documents " + tag, resp.body.indexOf(tag) !== -1);
        });
      });
    }

    // Unknown path 404s.
    var missing = await _get(port, "/definitely-not-a-real-namespace");
    check("unknown path -> 404", missing.status === 404);
  } finally {
    await new Promise(function (resolve) { srv.close(resolve); });
  }
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () {
      console.log("CHECKS " + _checks);
    },
    function (e) {
      console.error((e && e.stack) || String(e));
      process.exit(1);
    }
  );
}
