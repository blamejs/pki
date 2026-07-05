// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration — comment-block-driven interop.
 *
 * The primitive set is DISCOVERED, not hardcoded: this runner parses the
 * `@primitive` blocks out of every lib/ source file (via the same
 * source-doc-parser the wiki builds from) and, for each primitive that
 * registers interop fixtures under its name in interop-fixtures.js, runs
 * those fixtures against the OpenSSL oracle. Adding a primitive with its
 * comment block makes it show up here automatically; adding a fixture keyed
 * by its `@primitive` name gives it cross-implementation coverage — the
 * harness adapts to the comment blocks rather than to a maintained list.
 *
 * Runs under scripts/test-integration.js (each integration file as its own
 * process); the service-check gate confirms `openssl` before any file runs.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var path    = require("node:path");

var parser   = require("../../examples/wiki/lib/source-doc-parser");
var ctx      = require("./_interop-ctx");
var FIXTURES = require("./interop-fixtures");

var LIB_DIR = path.join(__dirname, "..", "..", "lib");

// Discover every primitive name from the lib/ @primitive comment blocks.
function _discoverPrimitives() {
  var tree = parser.parseTree(LIB_DIR);
  var names = [];
  Object.keys(tree).forEach(function (file) {
    tree[file].primitives.forEach(function (prim) {
      var name = prim.tags && prim.tags.primitive;
      if (name && names.indexOf(name) === -1) names.push(name);
    });
  });
  return names.sort();
}

async function run() {
  var primitives = _discoverPrimitives();
  check("primitives discovered from lib/ comment blocks", primitives.length > 0);

  var covered = 0;
  var fixturesRun = 0;
  for (var i = 0; i < primitives.length; i++) {
    var name = primitives[i];
    var fixtures = FIXTURES[name];
    if (!fixtures || !fixtures.length) continue;
    covered += 1;
    for (var j = 0; j < fixtures.length; j++) {
      await Promise.resolve(fixtures[j].run(ctx));
      fixturesRun += 1;
    }
  }

  console.log("[auto-interop] " + primitives.length + " primitive(s) discovered from comment blocks; " +
    covered + " with interop fixtures; " + fixturesRun + " fixture(s) run against openssl; " +
    helpers.getSkips() + " skipped (oracle capability absent)");

  // Every fixture registered for a discovered primitive must have run —
  // guards against a fixture keyed to a primitive that no longer exists.
  var orphaned = Object.keys(FIXTURES).filter(function (k) { return primitives.indexOf(k) === -1; });
  check("no interop fixtures orphaned from a removed primitive", orphaned.length === 0);
  check("at least one discovered primitive has interop coverage", covered > 0);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); console.log("SKIPS " + helpers.getSkips()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
