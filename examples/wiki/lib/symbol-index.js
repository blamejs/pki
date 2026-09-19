// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// symbol-index — the /symbols.json autocomplete manifest.
//
// Built at generation time from the same primitive index that resolves
// @related cross-references, so the sidebar symbol search and the page
// anchors can never disagree. Each entry:
//
//   { sig, bare, page, anchor, title }
//
//   sig    display signature ("pki.asn1.decode(bytes, opts?) -> node",
//          falling back to the @primitive tag when no @signature exists)
//   bare   match key without the pki. prefix or arguments ("asn1.decode")
//   page   the page path ("/asn1")
//   anchor the section anchor on that page ("asn1-decode")
//   title  the owning page title (shown under the signature)

// `recsFor(entry)` returns the parsed records the entry's page renders, in the
// order it renders them, so a symbol's page and anchor follow the section that
// actually exists rather than the entry that happens to own the namespace.
function build(entries, recsFor, helpers) {
  var symbols = [];
  entries.forEach(function (e) {
    recsFor(e).forEach(function (rec) {
      rec.primitives.forEach(function (p) {
        var tags = p.tags || {};
        if (!tags.primitive) return;
        var bare = helpers.bare(tags.primitive);
        symbols.push({
          sig:    tags.signature ? String(tags.signature).replace(/\s+/g, " ").trim() : tags.primitive,
          bare:   bare,
          page:   "/" + e.slug,
          anchor: helpers.anchor(bare),
          title:  e.title,
        });
      });
    });
  });
  symbols.sort(function (a, b) { return a.bare < b.bare ? -1 : a.bare > b.bare ? 1 : 0; });
  return symbols;
}

module.exports = { build: build };
