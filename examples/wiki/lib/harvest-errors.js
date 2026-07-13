// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// harvest-errors — the /reference-errors catalog, generated from the
// toolkit source at boot.
//
// Two harvests, both line-based over lib/ (vendor/ and node_modules
// excluded, comment lines skipped so a documentation example is never
// mistaken for a declaration):
//
//   1. Error classes — every `defineClass("Name", { ... })` call site,
//      with its flags and declaring file.
//   2. Error codes — every `domain/reason` string literal in a position a
//      code travels through: a call argument at any position (the
//      `E("cms/bad-version", ...)` throw shape and the `guard.*(x, E,
//      "asn1/not-buffer", label)` routing shape) and a `...code:` option
//      key (`code: "cms/bad-signed-data"`, `emptyCode:`, `dupCode:` — the
//      schema-combinator configuration shape), grouped by domain with
//      the carrying files.
//
// MIME-type-shaped literals ("application/pkcs7-mime") also match the
// domain/reason grammar, so the harvest drops the IANA top-level media
// types — no error domain is named after one.

var fs   = require("node:fs");
var path = require("node:path");

var DEFINE_RE = /defineClass\(\s*"(\w+)"\s*(?:,\s*(\{[^}]*\}))?\s*\)/g;
var CODE_RES = [
  /[(,]\s*"([a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*)"\s*[,)]/g, // call argument, any position
  /[a-zA-Z]*[cC]ode\s*:\s*"([a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*)"/g, // ...code: option key
  /(?:^\s*|\|\|\s*|=\s*)"([a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*)"\s*[,;)]/g, // multi-line call arg / default assignment
];

// IANA top-level media types: a "type/subtype" literal under one of these
// is a content type, not an error code.
var MEDIA_TYPE_DOMAINS = {
  application: true, audio: true, font: true, example: true, haptics: true,
  image: true, message: true, model: true, multipart: true, text: true, video: true,
};

function _isCommentLine(line) {
  var t = line.replace(/^\s+/, "");
  return t.indexOf("*") === 0 || t.indexOf("//") === 0 || t.indexOf("/*") === 0;
}

function _eachSourceFile(libDir, fn) {
  function _walk(dir) {
    var names;
    try { names = fs.readdirSync(dir); } catch (_e) { return; }
    names.forEach(function (name) {
      if (name === "vendor" || name === "node_modules") return;
      var full = path.join(dir, name);
      var stat;
      try { stat = fs.statSync(full); } catch (_e) { return; }
      if (stat.isDirectory()) { _walk(full); return; }
      if (!stat.isFile() || !/\.js$/.test(name)) return;
      var src;
      try { src = fs.readFileSync(full, "utf8"); } catch (_e) { return; }
      fn(path.relative(libDir, full).replace(/\\/g, "/"), src);
    });
  }
  _walk(libDir);
}

// harvest(libDir) -> {
//   classes: [ { name, file, flags: [..] } ],
//   domains: [ { domain, codes: [ { code, files: [..] } ] } ],
//   classCount, codeCount,
// }
function harvest(libDir) {
  var classes = [];
  var seenClass = {};
  var byDomain = {};

  _eachSourceFile(libDir, function (rel, src) {
    var lines = src.split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (_isCommentLine(line)) continue;

      var m;
      DEFINE_RE.lastIndex = 0;
      while ((m = DEFINE_RE.exec(line)) !== null) {
        if (seenClass[m[1]]) continue;
        seenClass[m[1]] = true;
        var flags = [];
        if (m[2] && /withCause\s*:\s*true/.test(m[2])) flags.push("withCause");
        classes.push({ name: m[1], file: "lib/" + rel, flags: flags });
      }

      for (var ri = 0; ri < CODE_RES.length; ri++) {
        var re = CODE_RES[ri];
        re.lastIndex = 0;
        while ((m = re.exec(line)) !== null) {
          var code = m[1];
          var domain = code.split("/")[0];
          if (MEDIA_TYPE_DOMAINS[domain]) continue;
          if (!byDomain[domain]) byDomain[domain] = {};
          if (!byDomain[domain][code]) byDomain[domain][code] = {};
          byDomain[domain][code]["lib/" + rel] = true;
          // A ",code," argument both closes one candidate and opens the
          // next; step back over the trailing delimiter so back-to-back
          // code arguments are all seen.
          if (ri === 0) re.lastIndex = re.lastIndex - 1;
        }
      }
    }
  });

  classes.sort(function (a, b) { return a.name < b.name ? -1 : a.name > b.name ? 1 : 0; });

  var codeCount = 0;
  var domains = Object.keys(byDomain).sort().map(function (d) {
    var codes = Object.keys(byDomain[d]).sort().map(function (c) {
      codeCount += 1;
      return { code: c, files: Object.keys(byDomain[d][c]).sort() };
    });
    return { domain: d, codes: codes };
  });

  return { classes: classes, domains: domains, classCount: classes.length, codeCount: codeCount };
}

module.exports = { harvest: harvest };
