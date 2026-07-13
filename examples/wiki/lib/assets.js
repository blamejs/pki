// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// assets — content-hashed CSS/JS for the wiki shell.
//
// The stylesheet and client script are read once at boot, hashed
// (sha256, 16 hex chars), and served under /dist/<name>.<hash>.<ext> from
// memory with an immutable cache-control. The hash in the URL means a
// redeploy can never serve stale CSS against new HTML, and the external
// files let every page carry a strict style-src 'self' CSP with no
// inline styles.
//
//   build() -> {
//     hrefs: { css, js, prismCss, prismJs },   // hashed URL paths (null when absent)
//     files: { "<path>": { body, type } },     // in-memory serve map
//   }
//
// The vendored Prism bundle (public/vendor/, pinned in MANIFEST.json) is
// optional: when the files are missing the shell simply omits the tags.

var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

var PUBLIC_DIR = path.join(__dirname, "..", "public");

var SOURCES = [
  { key: "css",      file: "wiki.css",         name: "wiki",  ext: "css", type: "text/css; charset=utf-8" },
  { key: "js",       file: "wiki.js",          name: "wiki",  ext: "js",  type: "text/javascript; charset=utf-8" },
  { key: "prismCss", file: "vendor/prism.css", name: "prism", ext: "css", type: "text/css; charset=utf-8" },
  { key: "prismJs",  file: "vendor/prism.js",  name: "prism", ext: "js",  type: "text/javascript; charset=utf-8" },
];

function _hash(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex").slice(0, 16);
}

function build() {
  var hrefs = { css: null, js: null, prismCss: null, prismJs: null };
  var files = {};
  SOURCES.forEach(function (s) {
    var buf;
    try { buf = fs.readFileSync(path.join(PUBLIC_DIR, s.file)); }
    catch (_e) { return; }
    var href = "/dist/" + s.name + "." + _hash(buf) + "." + s.ext;
    hrefs[s.key] = href;
    files[href] = { body: buf, type: s.type };
  });
  return { hrefs: hrefs, files: files };
}

module.exports = { build: build };
