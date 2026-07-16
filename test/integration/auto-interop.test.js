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

// Format namespaces whose parse surface has no interop fixture yet. The
// structural check below fails any discovered `pki.schema.<fmt>.parse*`
// namespace that is in NEITHER interop-fixtures.js NOR this ledger, so a new
// format cannot ship silently uncovered — it must either register fixtures
// or add a row here naming the oracle command that builds them. Every row is
// surfaced as an explicit SKIP (a skip is never a pass); deleting a row
// without registering the fixture fails the run.
var NO_FIXTURE_YET = {
  "pki.schema.cms":      "oracle available (`openssl cms`); register a fixtures row keyed pki.schema.cms.parse to cover it and drop this skip",
  "pki.schema.crl":      "oracle available (`openssl crl`); register a fixtures row keyed pki.schema.crl.parse to cover it and drop this skip",
  "pki.schema.csr":      "oracle available (`openssl req`); register a fixtures row keyed pki.schema.csr.parse to cover it and drop this skip",
  "pki.schema.pkcs8":    "oracle available (`openssl pkcs8`/`openssl pkey`); register a fixtures row keyed pki.schema.pkcs8.parse to cover it and drop this skip",
  "pki.schema.ocsp":     "oracle available (`openssl ocsp`); register a fixtures row keyed pki.schema.ocsp.parseRequest/parseResponse to cover it and drop this skip",
  "pki.schema.tsp":      "oracle available (`openssl ts`); register a fixtures row keyed pki.schema.tsp.parse to cover it and drop this skip",
  "pki.schema.smime":    "oracle available (`openssl cms` emits the ESS signing-certificate attribute); register a fixtures row keyed to a pki.schema.smime.parse* primitive to cover it and drop this skip",
  "pki.schema.crmf":     "openssl has no offline CRMF generator (`openssl cmp` needs a live server); add a fixtures row when an oracle path exists",
  "pki.schema.cmp":      "openssl's `cmp` subcommand is client-only (needs a live server as the oracle peer); add a fixtures row when an oracle path exists",
  "pki.schema.attrcert": "openssl cannot emit RFC 5755 attribute certificates; add a fixtures row when an independent oracle exists",
  "pki.schema.csrattrs": "openssl/NSS have no generator for the EST CSR Attributes wire format (RFC 8951 / 9908 CsrAttrs); add a fixtures row when an independent oracle exists",
  "pki.schema.c509":     "openssl/NSS have no C509 (draft-ietf-cose-cbor-encoded-cert) codec; the type-3 reconstruction emits standard DER that is byte-exact to the Appendix A known-answer certificates and is cross-checked by the x509 interop, so there is no independent C509 oracle to add until a C509 toolchain exists",
};

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

  // Structural coverage expectation, mirroring the schema-all dispatch
  // matrix: every format namespace with a discovered parse-shaped primitive
  // (`pki.schema.<fmt>.parse*`) must either register interop fixtures or
  // carry an explicit NO_FIXTURE_YET row — cross-implementation coverage is
  // structural, never per-format authoring discipline a new format can skip.
  var fmtNamespaces = [];
  primitives.forEach(function (name) {
    var m = /^(pki\.schema\.\w+)\.parse\w*$/.exec(name);
    if (m && fmtNamespaces.indexOf(m[1]) === -1) fmtNamespaces.push(m[1]);
  });
  var fixtureKeys = Object.keys(FIXTURES);
  fmtNamespaces.forEach(function (ns) {
    var hasFixture = fixtureKeys.some(function (k) { return k.indexOf(ns + ".") === 0; });
    if (hasFixture) {
      check(ns + ".* has interop fixtures", true);
      return;
    }
    check(ns + ".* has interop fixtures or an explicit no-fixture row",
      Object.prototype.hasOwnProperty.call(NO_FIXTURE_YET, ns));
    helpers.skip("no interop fixture for " + ns + ".* — " + NO_FIXTURE_YET[ns]);
  });
  // A stale ledger row (its format gained fixtures, or was removed) must be
  // deleted — a dead row would mask the gate the day the fixtures regress.
  var staleRows = Object.keys(NO_FIXTURE_YET).filter(function (ns) {
    var hasFixture = fixtureKeys.some(function (k) { return k.indexOf(ns + ".") === 0; });
    return hasFixture || fmtNamespaces.indexOf(ns) === -1;
  });
  check("no stale no-fixture rows (format covered or gone)", staleRows.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); console.log("SKIPS " + helpers.getSkips()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
