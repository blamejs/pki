// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// pkijs.com documentation site — production entry.
//
// The site is generated entirely from the @module + @primitive comment
// blocks in the toolkit's lib/ (see lib/page-generator). This file is the
// zero-dependency HTTP shim: it builds the page map once at boot and
// serves it, plus the static assets, the content-hashed CSS/JS, the
// /search route, the /symbols.json autocomplete manifest, and the
// sitemap/robots crawl surface. Rebuild-at-boot keeps the pages a pure
// function of the source — no database, no seeders, no runtime deps.
//
// Env vars:
//   WIKI_PORT       HTTP port (default 3009)
//   WIKI_BIND       bind address (default 0.0.0.0)
//   WIKI_SITE_URL   canonical public URL (default https://pkijs.com)

var http = require("node:http");
var fs   = require("node:fs");
var path = require("node:path");

var generator = require("./lib/page-generator");

var PORT = parseInt(process.env.WIKI_PORT, 10) || 3009;
var BIND = process.env.WIKI_BIND || "0.0.0.0";

var PUBLIC_DIR = path.join(__dirname, "public");

// Static assets served from public/ by exact request path. The favicons are
// resized from the logo (a multi-size .ico for the browser's default probe plus
// 16/32 PNGs), and the PWA manifest + apple-touch + maskable icons complete the
// install surface. CSS/JS are NOT here — those serve content-hashed from the
// in-memory map lib/assets builds at boot.
var STATIC_ASSETS = {
  "/pkijs-logo.png":       { file: "pkijs-logo.png",       type: "image/png" },
  "/favicon.ico":          { file: "favicon.ico",          type: "image/x-icon" },
  "/favicon-16.png":       { file: "favicon-16.png",       type: "image/png" },
  "/favicon-32.png":       { file: "favicon-32.png",       type: "image/png" },
  "/apple-touch-icon.png": { file: "apple-touch-icon.png", type: "image/png" },
  "/icon-192.png":         { file: "icon-192.png",         type: "image/png" },
  "/icon-512.png":         { file: "icon-512.png",         type: "image/png" },
  "/manifest.webmanifest": { file: "manifest.webmanifest", type: "application/manifest+json" },
};

// Response security headers on EVERY response. Styles and scripts are
// external content-hashed files, so the CSP carries no 'unsafe-inline'
// anywhere; the only inline <script> is each page's JSON-LD block, admitted
// by its sha256 hash (per page, passed to _csp below). The img-src allows
// the README status badges (shields.io, GitHub Actions, OpenSSF Scorecard,
// OpenSSF Best Practices, SLSA) to load as images.
function _csp(scriptHashes) {
  var script = "'self'" + (scriptHashes && scriptHashes.length ? " " + scriptHashes.join(" ") : "");
  return "default-src 'self'; " +
    "img-src 'self' data: https://img.shields.io https://github.com https://api.securityscorecards.dev https://www.bestpractices.dev https://slsa.dev; " +
    "style-src 'self'; " +
    "script-src " + script + "; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "manifest-src 'self'; " +
    "base-uri 'self'; " +
    "form-action 'self'; " +
    "frame-ancestors 'none'; " +
    "object-src 'none'; " +
    "upgrade-insecure-requests";
}

var SECURITY_HEADERS = {
  "content-security-policy": _csp(null),
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-frame-options": "DENY",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
};

function _withSecurity(headers) {
  var h = {};
  Object.keys(SECURITY_HEADERS).forEach(function (k) { h[k] = SECURITY_HEADERS[k]; });
  Object.keys(headers || {}).forEach(function (k) { h[k] = headers[k]; });
  return h;
}

// Strong-ETag conditional GET: a matching If-None-Match answers 304 with
// no body. Pages are prebuilt so the etag is computed once at boot.
function _etagMatches(req, etag) {
  var inm = req.headers["if-none-match"];
  if (!inm || !etag) return false;
  return inm.split(",").some(function (t) {
    return t.trim().replace(/^W\//, "") === etag;
  });
}

// buildSite() is exported so test/e2e.js boots the identical page map
// in-process without opening a socket.
function buildSite() {
  return generator.build({});
}

function createServer(site) {
  return http.createServer(function (req, res) {
    var q = req.url.indexOf("?") !== -1 ? req.url.slice(req.url.indexOf("?") + 1) : "";
    var url = req.url.split("?")[0];

    // Normalize a trailing slash (except root) BEFORE any route matching,
    // so "/search/" and "/asn1/" behave exactly like their canonical forms.
    if (url.length > 1 && url.charAt(url.length - 1) === "/") url = url.slice(0, -1);

    // Liveness/readiness probe for the container healthcheck + the
    // release-container post-publish smoke test. Pages are generated at
    // boot, so a served /healthz means the site is up.
    if (url === "/healthz") {
      res.writeHead(200, _withSecurity({ "content-type": "application/json" }));
      res.end(JSON.stringify({ status: "ok", pages: Object.keys(site.pages).length }));
      return;
    }

    // Content-hashed CSS/JS from memory: the hash in the URL makes the
    // body immutable for that URL, so the cache lifetime is maximal.
    var hashed = site.assets && site.assets.files[url];
    if (hashed) {
      res.writeHead(200, _withSecurity({
        "content-type": hashed.type,
        "cache-control": "public, max-age=31536000, immutable",
      }));
      res.end(hashed.body);
      return;
    }

    var asset = STATIC_ASSETS[url];
    if (asset) {
      fs.readFile(path.join(PUBLIC_DIR, asset.file), function (err, buf) {
        if (err) { res.writeHead(404, _withSecurity({ "content-type": "text/plain" })); res.end("not found"); return; }
        res.writeHead(200, _withSecurity({ "content-type": asset.type, "cache-control": "public, max-age=86400" }));
        res.end(buf);
      });
      return;
    }

    // The symbol-search autocomplete manifest (see lib/symbol-index).
    if (url === "/symbols.json") {
      res.writeHead(200, _withSecurity({
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=300",
      }));
      res.end(site.symbolsJson);
      return;
    }

    if (url === "/sitemap.xml") {
      res.writeHead(200, _withSecurity({ "content-type": "application/xml; charset=utf-8", "cache-control": "public, max-age=3600" }));
      res.end(site.sitemapXml);
      return;
    }

    if (url === "/robots.txt") {
      res.writeHead(200, _withSecurity({ "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" }));
      res.end(site.robotsTxt);
      return;
    }

    // Server-rendered full-text search: a plain GET form target, so search
    // works with JavaScript disabled.
    if (url === "/search") {
      var query;
      try { query = new URLSearchParams(q).get("q") || ""; } catch (_e) { query = ""; }
      res.writeHead(200, _withSecurity({
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-cache",
      }));
      res.end(generator.renderSearch(site, query));
      return;
    }

    var page = site.pages[url];
    if (!page) {
      res.writeHead(404, _withSecurity({ "content-type": "text/html; charset=utf-8" }));
      res.end("<!doctype html><meta charset=utf-8><title>404 — pkijs.com</title><h1>404</h1><p>No such page. <a href=\"/\">Home</a></p>");
      return;
    }
    var pageHeaders = {
      "content-security-policy": _csp(page.cspScriptHashes),
      "cache-control": "public, max-age=300",
      "etag": page.etag,
    };
    if (_etagMatches(req, page.etag)) {
      res.writeHead(304, _withSecurity(pageHeaders));
      res.end();
      return;
    }
    pageHeaders["content-type"] = "text/html; charset=utf-8";
    res.writeHead(200, _withSecurity(pageHeaders));
    res.end(page.html);
  });
}

function start() {
  var site = buildSite();
  var server = createServer(site);
  server.listen(PORT, BIND, function () {
    var host = BIND === "0.0.0.0" ? "localhost" : BIND;
    var pageCount = Object.keys(site.pages).length;
    console.log("pkijs.com docs listening on http://" + host + ":" + PORT + " (" + pageCount + " pages)");
  });
  return server;
}

module.exports = {
  buildSite:    buildSite,
  createServer: createServer,
  start:        start,
};

if (require.main === module) {
  start();
}
