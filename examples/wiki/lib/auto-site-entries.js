// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// auto-site-entries — derive site.config entries directly from @module
// blocks in the toolkit's lib/. Each namespace whose @module block
// carries @nav + @card metadata produces one site entry automatically.
//
// Supported @module tags:
//
//   @module pki.X            — namespace identifier (REQUIRED)
//   @nav     <Group Name>    — sidebar concern group (e.g. "Core",
//                              "Certificates"). Omitted -> "Other".
//   @title   <Display Name>  — sidebar label + page <h1>. Omitted ->
//                              "pki.X".
//   @card    <description>   — landing-page card description. Omitted ->
//                              no card (the page still exists).
//   @slug    <url-slug>      — optional URL slug override. Default
//                              kebab-cases the namespace.
//   @order   <n>             — within-group sort key (default 100).
//   @featured true           — opt the namespace into the home-page card
//                              grid.
//
// The derivation runs every page-generator pass. New @module blocks land
// in the wiki on the next boot — no edits to site.config.js required.

var parser = require("./source-doc-parser");

function _kebab(ns) {
  return ns
    .replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); })
    .replace(/\./g, "-");
}

function _moduleNs(modTag) {
  return String(modTag || "").replace(/^\s*pki\./, "").trim();
}

// Build entries from every @module block parsed under libDir. Returns an
// array shaped like site.config rows: { slug, title, group, order,
// namespaces: [ns], featured, card?: { description } }.
function deriveFromLib(libDir) {
  var docs = parser.parseTree(libDir);
  var entries = [];
  var seenSlugs = {};
  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    if (!rec.module) return;
    var modTags = rec.module.tags || {};
    var ns = _moduleNs(modTags.module);
    if (!ns) return;
    // Only namespaces that actually document at least one primitive.
    if (!rec.primitives || rec.primitives.length === 0) return;
    var slug = modTags.slug || _kebab(ns);
    if (seenSlugs[slug]) return;
    seenSlugs[slug] = true;

    var orderRaw = modTags.order != null ? parseInt(modTags.order, 10) : NaN;
    var order = isFinite(orderRaw) ? orderRaw : 100;

    var entry = {
      slug:       slug,
      title:      modTags.title || ("pki." + ns),
      group:      modTags.nav || "Other",
      order:      order,
      namespaces: [ns],
      featured:   false,
      intro:      modTags.intro || "",
    };
    if (modTags.card) {
      entry.card = {
        description: String(modTags.card).replace(/\s+/g, " ").replace(/^\s+|\s+$/g, ""),
      };
    }
    if (modTags.featured && /^(true|yes|1)$/i.test(modTags.featured)) {
      entry.featured = true;
    }
    entries.push(entry);
  });
  // Stable order: by group, then within-group @order, then slug.
  entries.sort(function (a, b) {
    if (a.group < b.group) return -1;
    if (a.group > b.group) return 1;
    if (a.order !== b.order) return a.order - b.order;
    if (a.slug < b.slug) return -1;
    if (a.slug > b.slug) return 1;
    return 0;
  });
  return entries;
}

module.exports = {
  deriveFromLib: deriveFromLib,
};
