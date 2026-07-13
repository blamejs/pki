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
// Beyond the page walk, the gate covers: the content-hashed CSS/JS assets
// and the no-unsafe-inline CSP (JSON-LD admitted per page by sha256);
// ETag conditional GET; the collapsible nav (aria-current, open group);
// /symbols.json (every symbol's page and anchor must exist); /search
// (hits, misses, escaped echo); the /api and /reference-errors generated
// pages; sitemap/robots; the vendored Prism bundle (pinned sha256 in
// public/vendor/MANIFEST.json verified, and every language-X class used
// anywhere on the site must be highlightable by the bundle, proven in a
// node:vm sandbox); and an internal-link crawler that resolves every
// href and fragment anchor across every generated page.
//
// Prints "CHECKS <n>" on success; prints the error and exits 1 on the
// first failure — matching the smoke-runner convention.

var http   = require("node:http");
var fs     = require("node:fs");
var path   = require("node:path");
var vm     = require("node:vm");
var crypto = require("node:crypto");

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

function _get(port, urlPath, headers) {
  return new Promise(function (resolve, reject) {
    var req = http.get({ host: "127.0.0.1", port: port, path: urlPath, headers: headers || {} }, function (res) {
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

    // Overview: the repository README rendered to HTML.
    var overview = await _get(port, "/overview");
    check("GET /overview -> 200", overview.status === 200);
    check("overview renders the README table (What ships)", overview.body.indexOf("<table>") !== -1);
    // A table cell whose inline code carries an escaped pipe (`certificate(pem \| der \| parsed)`)
    // must render as ONE cell with the pipe as content -- a naive split("|") would shatter it
    // into phantom columns, mangling the whole table with a wide blank gap.
    check("overview renders an escaped-pipe code span intact (not shattered)",
      overview.body.indexOf("certificate(pem | der | parsed)") !== -1);
    check("overview leaks no stray table-escape backslash", overview.body.indexOf("(pem \\|") === -1);
    check("overview renders fenced code", overview.body.indexOf("<pre><code>") !== -1);
    check("overview rewrites the logo asset to the wiki route", overview.body.indexOf('src="/pkijs-logo.png"') !== -1);
    check("overview rewrites a repo-relative .md link to GitHub", overview.body.indexOf("github.com/blamejs/pki/blob/main/ROADMAP.md") !== -1);
    check("overview escapes nothing raw from the badge image-links", overview.body.indexOf('<img src="https://img.shields.io') !== -1);
    check("overview appears in the nav", overview.body.indexOf('href="/overview"') !== -1);

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

    // ---- Hashed assets: CSS/JS serve immutable under their content hash ----
    var hrefs = built.assets.hrefs;
    check("stylesheet href is content-hashed", /^\/dist\/wiki\.[0-9a-f]{16}\.css$/.test(String(hrefs.css)));
    check("client script href is content-hashed", /^\/dist\/wiki\.[0-9a-f]{16}\.js$/.test(String(hrefs.js)));
    var cssResp = await _get(port, hrefs.css);
    check("GET hashed css -> 200", cssResp.status === 200);
    check("hashed css served as text/css", String(cssResp.headers["content-type"]).indexOf("text/css") === 0);
    check("hashed css cache-control is immutable", String(cssResp.headers["cache-control"]).indexOf("immutable") !== -1);
    var jsResp = await _get(port, hrefs.js);
    check("GET hashed client js -> 200 as javascript", jsResp.status === 200 && String(jsResp.headers["content-type"]).indexOf("text/javascript") === 0);
    var prismJsResp = await _get(port, hrefs.prismJs);
    check("GET vendored prism js -> 200", prismJsResp.status === 200);
    var prismCssResp = await _get(port, hrefs.prismCss);
    check("GET vendored prism css -> 200", prismCssResp.status === 200);
    check("shell links the hashed stylesheet", home.body.indexOf('href="' + hrefs.css + '"') !== -1);
    check("shell loads the client script deferred", home.body.indexOf('src="' + hrefs.js + '" defer') !== -1);
    check("shell carries no inline style block", home.body.indexOf("<style>") === -1);

    // ---- CSP: no unsafe-inline anywhere; JSON-LD admitted by sha256 hash ----
    var homeCsp = String(home.headers["content-security-policy"]);
    check("CSP carries no unsafe-inline", homeCsp.indexOf("unsafe-inline") === -1);
    check("CSP style-src is self only", homeCsp.indexOf("style-src 'self';") !== -1);
    check("CSP admits the page's JSON-LD by hash", /script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/.test(homeCsp));
    // img-src must admit every README badge host, including OpenSSF Best Practices
    // (bestpractices.dev), or the /overview page shows a broken badge image.
    check("CSP img-src admits the OpenSSF Best Practices badge host", homeCsp.indexOf("https://www.bestpractices.dev") !== -1);
    // permissions-policy carries no deprecated interest-cohort token (FLoC is retired;
    // the token now only draws a console warning).
    check("permissions-policy drops the deprecated interest-cohort token",
      String(home.headers["permissions-policy"]).indexOf("interest-cohort") === -1);
    check("home carries WebSite JSON-LD", home.body.indexOf('"@type":"WebSite"') !== -1);

    // ---- Conditional GET: If-None-Match answers 304 with no body ----
    var homeEtag = String(home.headers.etag || "");
    check("page carries a strong ETag", /^"[0-9a-f]{32}"$/.test(homeEtag));
    check("page carries a cache-control", String(home.headers["cache-control"]).indexOf("max-age") !== -1);
    var notMod = await _get(port, "/", { "if-none-match": homeEtag });
    check("If-None-Match answers 304", notMod.status === 304);
    check("304 body is empty", notMod.body.length === 0);

    // ---- Nav: collapsible groups, current page marked, skip link ----
    check("nav renders collapsible groups", home.body.indexOf('<details class="navgrp"') !== -1);
    check("skip-to-content link present", home.body.indexOf('class="skip-link"') !== -1);
    check("sidebar carries the full-text search form", home.body.indexOf('action="/search"') !== -1);
    check("sidebar carries the symbol autocomplete box", home.body.indexOf('id="symq"') !== -1);
    var navProbe = await _get(port, "/" + entries[0].slug);
    check("active page carries aria-current", navProbe.body.indexOf('aria-current="page"') !== -1);
    check("the active group is server-rendered open", navProbe.body.indexOf('<details class="navgrp" open>') !== -1);
    check("namespace page carries TechArticle JSON-LD", navProbe.body.indexOf('"@type":"TechArticle"') !== -1);

    // ---- Home: quick start + pills + tenets ----
    check("home shows the install command", home.body.indexOf("npm install @blamejs/pki") !== -1);
    check("home tip documents the real format detector", home.body.indexOf("pki.schema.parse(der)") !== -1);
    check("home quick-start example is highlighted", home.body.indexOf('class="language-js"') !== -1);
    check("home shows the feature pills", home.body.indexOf('class="pill"') !== -1);
    check("home lists the design tenets", home.body.indexOf('class="tenets"') !== -1);

    // ---- /symbols.json: the autocomplete manifest matches the site ----
    var sym = await _get(port, "/symbols.json");
    check("GET /symbols.json -> 200 json", sym.status === 200 && String(sym.headers["content-type"]).indexOf("application/json") === 0);
    var symData = JSON.parse(sym.body);
    check("symbols manifest is populated", Array.isArray(symData.symbols) && symData.symbols.length >= 50);
    symData.symbols.forEach(function (s) {
      var target = built.pages[s.page];
      check("symbol " + s.bare + " points at an existing page", !!target);
      check("symbol " + s.bare + " anchor exists on " + s.page, target.html.indexOf('id="' + s.anchor + '"') !== -1);
    });

    // ---- /search: server-rendered, marked excerpts, escaped input ----
    var foundSearch = await _get(port, "/search?q=certificate");
    check("search finds results with marked excerpts", foundSearch.status === 200 && foundSearch.body.indexOf("<mark>") !== -1);
    // Excerpt marking must never re-scan its own output: a second term
    // matching inside an inserted <mark> tag, or a term matching inside
    // an HTML entity the escaper produced, corrupts the markup.
    var multiTerm = await _get(port, "/search?q=certificate+a");
    check("multi-term excerpts emit no nested-mark corruption", multiTerm.body.indexOf("<m<mark>") === -1);
    check("multi-term excerpts balance their mark tags",
      (multiTerm.body.match(/<mark>/g) || []).length === (multiTerm.body.match(/<\/mark>/g) || []).length);
    var entityTerm = await _get(port, "/search?q=lt");
    check("excerpt marks never split an HTML entity", !/&<mark>/.test(entityTerm.body));
    var slashSearch = await _get(port, "/search/?q=certificate");
    check("search tolerates a trailing slash like every page", slashSearch.status === 200);
    var noneSearch = await _get(port, "/search?q=zzqxjvzzznotaword");
    check("search misses cleanly with a zero count", noneSearch.status === 200 && noneSearch.body.indexOf("0 results") !== -1);
    var hostile = await _get(port, "/search?q=" + encodeURIComponent("<script>alert(1)</script>"));
    check("search escapes the echoed query", hostile.status === 200 && hostile.body.indexOf("<script>alert(1)") === -1);
    var blankSearch = await _get(port, "/search");
    check("blank search renders the empty state", blankSearch.status === 200);

    // ---- /api: the auto-generated master index ----
    var api = await _get(port, "/api");
    check("GET /api -> 200", api.status === 200);
    var totalPrims = 0;
    entries.forEach(function (e) { totalPrims += primCountByNs[e.namespaces[0]] || 0; });
    check("/api counts every documented primitive", api.body.indexOf(totalPrims + " primitives") !== -1);
    entries.forEach(function (e) {
      if ((primCountByNs[e.namespaces[0]] || 0) === 0) return;
      check("/api deep-links into /" + e.slug, api.body.indexOf('href="/' + e.slug + '#') !== -1);
    });

    // ---- /reference-errors: the harvested error catalog ----
    var errCat = await _get(port, "/reference-errors");
    check("GET /reference-errors -> 200", errCat.status === 200);
    check("error catalog lists the classes table", errCat.body.indexOf("Error classes") !== -1);
    check("error catalog carries a known class", errCat.body.indexOf("CertificateError") !== -1);
    check("error catalog carries a known domain section", errCat.body.indexOf('id="domain-asn1"') !== -1);
    check("error catalog is populated", (errCat.body.match(/<tr>/g) || []).length >= 450);
    // Codes carried in option-object keys (code:, emptyCode:, ...) and in
    // non-first argument positions must be harvested, not only the
    // E("domain/reason", ...) first-argument shape.
    check("error catalog carries an option-object code", errCat.body.indexOf("cms/bad-signed-data") !== -1);
    check("error catalog carries a non-first-argument code", errCat.body.indexOf("asn1/not-buffer") !== -1);
    check("error catalog carries a default-assignment code", errCat.body.indexOf("byte-reader/truncated") !== -1);

    // ---- Concepts pages ----
    var conceptGroup = built.navGroups.filter(function (g) { return g.group === "Concepts"; })[0];
    check("Concepts group exists in the nav", !!conceptGroup && conceptGroup.items.length >= 1);
    for (var ci = 0; ci < conceptGroup.items.length; ci++) {
      var cit = conceptGroup.items[ci];
      var cResp = await _get(port, cit.path);
      check("GET " + cit.path + " -> 200", cResp.status === 200);
      check(cit.path + " renders its title", cResp.body.indexOf(cit.title + "</h1>") !== -1);
      check(cit.path + " renders sections", (cResp.body.match(/<h2 id="/g) || []).length >= 2);
    }

    // ---- sitemap + robots ----
    var sm = await _get(port, "/sitemap.xml");
    check("GET /sitemap.xml -> 200 xml", sm.status === 200 && String(sm.headers["content-type"]).indexOf("application/xml") === 0);
    check("sitemap lists every page", (sm.body.match(/<url>/g) || []).length === Object.keys(built.pages).length);
    var rb = await _get(port, "/robots.txt");
    check("GET /robots.txt -> 200", rb.status === 200);
    check("robots points at the sitemap", rb.body.indexOf("Sitemap: ") !== -1);

    // ---- Vendored Prism: pinned hashes verify, languages cover the site ----
    var vendorDir = path.join(__dirname, "..", "public", "vendor");
    var manifest = JSON.parse(fs.readFileSync(path.join(vendorDir, "MANIFEST.json"), "utf8"));
    Object.keys(manifest.prism.files).forEach(function (f) {
      var want = manifest.prism.files[f].sha256;
      var got = crypto.createHash("sha256").update(fs.readFileSync(path.join(vendorDir, f))).digest("hex");
      check("vendored " + f + " matches its pinned sha256", got === want);
    });
    var sandbox = {};
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(path.join(vendorDir, "prism.js"), "utf8"), sandbox);
    check("prism bundle evaluates in a bare sandbox", !!(sandbox.Prism && sandbox.Prism.languages));
    var usedLangs = {};
    Object.keys(built.pages).forEach(function (p) {
      var langRe = /class="language-([a-z0-9+-]+)"/g;
      var lm;
      while ((lm = langRe.exec(built.pages[p].html)) !== null) usedLangs[lm[1]] = true;
    });
    check("the site uses at least one highlighted language", Object.keys(usedLangs).length >= 1);
    Object.keys(usedLangs).forEach(function (l) {
      check("prism bundle highlights language-" + l, !!sandbox.Prism.languages[l]);
    });

    // ---- Internal-link crawler: every internal href resolves, anchors exist ----
    var linkRefs = [];
    Object.keys(built.pages).forEach(function (p) {
      var hrefRe = /href="(\/[^"]*|#[^"]*)"/g;
      var hm;
      while ((hm = hrefRe.exec(built.pages[p].html)) !== null) {
        var href = hm[1];
        if (href.indexOf("//") === 0) continue; // protocol-relative = external
        var hashIdx = href.indexOf("#");
        var pathPart = hashIdx === -1 ? href : href.slice(0, hashIdx);
        var frag = hashIdx === -1 ? null : href.slice(hashIdx + 1);
        if (pathPart === "") pathPart = p;
        linkRefs.push({ from: p, href: href, pathPart: pathPart, frag: frag });
      }
    });
    var fetchedStatus = {};
    for (var li = 0; li < linkRefs.length; li++) {
      var pp = linkRefs[li].pathPart;
      if (!(pp in fetchedStatus)) fetchedStatus[pp] = (await _get(port, pp)).status;
    }
    var brokenLinks = linkRefs.filter(function (lk) { return fetchedStatus[lk.pathPart] !== 200; });
    check("internal links all resolve" + (brokenLinks.length ? " (broken: " + brokenLinks.map(function (b) { return b.from + " -> " + b.href; }).join(", ") + ")" : ""), brokenLinks.length === 0);
    var badFrags = linkRefs.filter(function (lk) {
      if (!lk.frag) return false;
      var target = built.pages[lk.pathPart];
      if (!target) return false; // asset or dynamic route: no fragment to check
      return target.html.indexOf('id="' + lk.frag + '"') === -1;
    });
    check("fragment anchors all exist" + (badFrags.length ? " (bad: " + badFrags.map(function (b) { return b.from + " -> " + b.href; }).join(", ") + ")" : ""), badFrags.length === 0);

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
