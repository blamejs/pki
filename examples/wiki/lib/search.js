// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// search — server-side full-text search over the boot-generated page map.
//
// The wiki holds every page in memory, so search needs no database and no
// index build: at generation time each page stores a plain-text rendering
// of its main content (extractText), and GET /search?q= scans those texts
// with AND-of-terms matching. Results are ranked (title hit > heading hit
// > body frequency) and each carries an excerpt with every query term
// wrapped in <mark>. The search form is a plain GET form — it works with
// JavaScript disabled.
//
// Bounds (a docs site, but still a network input): query capped at 200
// chars and 8 terms, results capped at 50.

var ent = require("./html-entities");
var esc = ent.escapeHtml;

var MAX_QUERY_CHARS = 200;
var MAX_TERMS = 8;
var MAX_RESULTS = 50;
var EXCERPT_RADIUS = 90;

// Strip tags to a fixpoint and collapse entities/whitespace so the stored
// searchable text carries no markup. Runs on generator-produced HTML at
// boot (trusted), never on request input.
function extractText(html) {
  var s = String(html || "");
  var prev;
  do { prev = s; s = s.replace(/<[^>]*>/g, " "); } while (s !== prev);
  s = ent.unescapeBuiltinEntities(s);
  return s.replace(/\s+/g, " ").trim();
}

function _terms(q) {
  return String(q || "")
    .slice(0, MAX_QUERY_CHARS)
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, MAX_TERMS);
}

function _countOccurrences(haystack, needle) {
  var n = 0;
  var idx = 0;
  for (;;) {
    idx = haystack.indexOf(needle, idx);
    if (idx === -1) return n;
    n += 1;
    idx += needle.length;
  }
}

// Excerpt around the first occurrence of the first matching term, with
// every term <mark>ed. Match ranges are computed on the PLAIN text and
// each segment is escaped independently — the marker never re-scans its
// own output, so a later term cannot match inside an inserted <mark> tag
// and a term cannot match inside an entity the escaper produced.
function _excerpt(text, terms) {
  var lower = text.toLowerCase();
  var at = -1;
  var i;
  for (i = 0; i < terms.length; i++) {
    var hit = lower.indexOf(terms[i]);
    if (hit !== -1 && (at === -1 || hit < at)) at = hit;
  }
  if (at === -1) at = 0;
  var start = Math.max(0, at - EXCERPT_RADIUS);
  var end = Math.min(text.length, at + EXCERPT_RADIUS * 2);
  var slice = text.slice(start, end);
  var lowerSlice = slice.toLowerCase();

  // Collect all term match ranges in the plain slice, then merge overlaps
  // so nested/adjacent matches produce one well-formed <mark> each.
  var ranges = [];
  terms.forEach(function (t) {
    var idx = 0;
    for (;;) {
      idx = lowerSlice.indexOf(t, idx);
      if (idx === -1) return;
      ranges.push([idx, idx + t.length]);
      idx += t.length;
    }
  });
  ranges.sort(function (a, b) { return a[0] - b[0] || b[1] - a[1]; });
  var merged = [];
  ranges.forEach(function (r) {
    var last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) { if (r[1] > last[1]) last[1] = r[1]; return; }
    merged.push([r[0], r[1]]);
  });

  var out = [];
  if (start > 0) out.push("…");
  var pos = 0;
  merged.forEach(function (r) {
    out.push(esc(slice.slice(pos, r[0])));
    out.push("<mark>" + esc(slice.slice(r[0], r[1])) + "</mark>");
    pos = r[1];
  });
  out.push(esc(slice.slice(pos)));
  if (end < text.length) out.push("…");
  return out.join("");
}

// search(index, q) -> [ { path, title, excerpt } ]
//
// index: [ { path, title, text, headings } ] built at generation time.
// Every term must match somewhere in title/headings/text (AND semantics).
function search(index, q) {
  var terms = _terms(q);
  if (!terms.length) return [];
  var hits = [];
  index.forEach(function (page) {
    var titleL = page.title.toLowerCase();
    var headingsL = (page.headings || "").toLowerCase();
    var textL = page.text.toLowerCase();
    var score = 0;
    for (var i = 0; i < terms.length; i++) {
      var t = terms[i];
      var inTitle = titleL.indexOf(t) !== -1;
      var inHeadings = headingsL.indexOf(t) !== -1;
      var bodyCount = _countOccurrences(textL, t);
      if (!inTitle && !inHeadings && bodyCount === 0) return; // AND: a missing term drops the page
      score += (inTitle ? 100 : 0) + (inHeadings ? 25 : 0) + Math.min(bodyCount, 20);
    }
    hits.push({ path: page.path, title: page.title, score: score, excerpt: _excerpt(page.text, terms) });
  });
  hits.sort(function (a, b) { return b.score - a.score || (a.path < b.path ? -1 : 1); });
  return hits.slice(0, MAX_RESULTS);
}

module.exports = {
  extractText: extractText,
  search:      search,
  MAX_QUERY_CHARS: MAX_QUERY_CHARS,
};
