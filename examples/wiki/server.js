// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// pkijs.com documentation site — production entry.
//
// The site is generated entirely from the @module + @primitive comment
// blocks in the toolkit's lib/ (see lib/page-generator). This file is the
// zero-dependency HTTP shim: it builds the page map once at boot and
// serves it, plus the logo asset. Rebuild-at-boot keeps the pages a pure
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

var LOGO_PATH = path.join(__dirname, "public", "pkijs-logo.png");

// buildSite() is exported so test/e2e.js boots the identical page map
// in-process without opening a socket.
function buildSite() {
  return generator.build({});
}

function createServer(site) {
  return http.createServer(function (req, res) {
    var url = req.url.split("?")[0];

    if (url === "/pkijs-logo.png") {
      fs.readFile(LOGO_PATH, function (err, buf) {
        if (err) { res.writeHead(404, { "content-type": "text/plain" }); res.end("not found"); return; }
        res.writeHead(200, { "content-type": "image/png", "cache-control": "public, max-age=86400" });
        res.end(buf);
      });
      return;
    }

    // Normalize a trailing slash (except root) so "/asn1/" == "/asn1".
    if (url.length > 1 && url.charAt(url.length - 1) === "/") url = url.slice(0, -1);

    var page = site.pages[url];
    if (!page) {
      res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
      res.end("<!doctype html><meta charset=utf-8><title>404 — pkijs.com</title><h1>404</h1><p>No such page. <a href=\"/\">Home</a></p>");
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
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
