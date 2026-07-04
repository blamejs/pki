// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// site.config — the single source of truth for the wiki's navigation and
// landing-page curation. Everything is DERIVED: the entries come straight
// from the @module blocks in the toolkit's lib/ (see lib/auto-site-entries).
// There are no hand-authored seeders — adding or moving a page is a
// comment-block edit alone.
//
// Exposes:
//   LIB_DIR             absolute path to the toolkit's lib/
//   siteUrl             canonical public URL of the deploy
//   entries()           the auto-derived site entries (sorted)
//   navGroups()         [ { group, items: [ { slug, title, path } ] } ]
//   groupForPath(path)  the nav group a page path belongs to, or null

var path = require("node:path");
var auto = require("./lib/auto-site-entries");

var LIB_DIR = path.resolve(__dirname, "..", "..", "lib");
var SITE_URL = (process.env.WIKI_SITE_URL || "https://pkijs.com").replace(/\/+$/, "");

function entries() {
  return auto.deriveFromLib(LIB_DIR);
}

function navGroups() {
  var order = [];
  var map = {};
  entries().forEach(function (e) {
    if (!map[e.group]) { map[e.group] = []; order.push(e.group); }
    map[e.group].push({ slug: e.slug, title: e.title, path: "/" + e.slug });
  });
  return order.map(function (g) { return { group: g, items: map[g] }; });
}

function groupForPath(p) {
  var found = null;
  entries().forEach(function (e) {
    if ("/" + e.slug === p) found = e.group;
  });
  return found;
}

module.exports = {
  LIB_DIR:      LIB_DIR,
  siteUrl:      SITE_URL,
  entries:      entries,
  navGroups:    navGroups,
  groupForPath: groupForPath,
};
