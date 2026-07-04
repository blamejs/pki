// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// html-entities — the built-in entity encode/decode the wiki page
// generator uses. Both directions are single-pass: a chained decode
// double-decodes (`&amp;lt;` -> `&lt;` -> `<`), un-escaping a level that
// was never escaped at the source, so one regex pass consumes each entity
// exactly once and a replacement output is never re-scanned.

var _ESC = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};
var _ESC_RE = /[&<>"']/g;

var _UNESC = {
  "&amp;":  "&",
  "&lt;":   "<",
  "&gt;":   ">",
  "&quot;": "\"",
  "&#39;":  "'",
  "&#x27;": "'",
};
var _UNESC_RE = /&(?:amp|lt|gt|quot|#39|#x27);/g;

function escapeHtml(s) {
  return String(s).replace(_ESC_RE, function (m) { return _ESC[m]; });
}

function unescapeBuiltinEntities(s) {
  return String(s).replace(_UNESC_RE, function (m) { return _UNESC[m]; });
}

module.exports = {
  escapeHtml:                escapeHtml,
  unescapeBuiltinEntities:   unescapeBuiltinEntities,
};
