// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- every @example in lib/ runs SELF-CONTAINED, on nothing but `pki`.
 *
 * How this differs from doc-examples.test.js, which also executes examples:
 * that harness injects a per-namespace FIXTURE SET (a real certificate, a
 * minimal instance of each format) into scope, so an example whose first line
 * reads `pki.asn1.decode(der)` runs there because the harness supplies `der`.
 * An operator copying that line off the wiki page gets `der is not defined`.
 * This gate supplies NOTHING but the package export, so it measures the thing
 * the reader actually experiences -- and its EXECUTED_FLOOR ratchet is what
 * drives the corpus toward being copy-pasteable.
 *
 * The two are complementary, not redundant: doc-examples additionally proves
 * every documented path resolves, is referenced by a test, and has its namespace
 * described in the README, and it keeps covering examples that legitimately need
 * a fixture. As the ratchet here rises, the fixture set there becomes dead weight
 * that can be retired.
 *
 * `scripts/validate-source-comment-blocks.js` is the third and weakest layer: it
 * compiles each @example and never runs it, so an example can be syntactically
 * perfect and semantically dead -- a renamed primitive, an option that no longer
 * exists, an argument shape the code stopped accepting.
 *
 * This walks the SAME parse tree the validator uses and runs each example,
 * asserting it does not throw for a reason that means the documented API is
 * wrong. What counts as such a reason lives in _jsdoc-example-runtime.js, so the
 * classification is stated once.
 *
 * TRUST BOUNDARY, because this compiles strings: the only source of an example
 * body is `parseTree(lib/)` over this repository's own checked-in files -- the
 * code under test, not input. That is enforced below rather than assumed: the
 * parse root is resolved and asserted to sit inside the repo before a single
 * body is compiled, so a future caller cannot point this at a tree it does not
 * own. There is no interpolation of any other value.
 *
 * Run standalone: node test/layer-0-primitives/jsdoc-example-execution.test.js
 */

var path = require("path");
var fs = require("node:fs");
var os = require("node:os");
var helpers = require("../helpers");
var check = helpers.check;
var runtime = require("./_jsdoc-example-runtime.js");

var ROOT = runtime.ROOT;
var parser = require(path.join(ROOT, "examples", "wiki", "lib", "source-doc-parser.js"));

async function run() {
  // The trust boundary, enforced rather than asserted in prose. ROOT is derived
  // from __dirname, so it is wherever this test file physically lives; confirm
  // that tree really is this package before compiling a single body out of it,
  // and that the parse root sits inside it.
  var libDir = path.resolve(ROOT, "lib");
  var pkgName;
  try { pkgName = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).name; }
  catch (_e0) { /* an unreadable package.json fails the check below, which is the point */ }
  var inRepo = pkgName === "@blamejs/pki" &&
    libDir.startsWith(path.resolve(ROOT) + path.sep) &&
    fs.existsSync(path.join(libDir, "asn1-der.js"));
  check("the @example source root is this package's own lib/ (nothing outside it is compiled)", inRepo === true);
  if (!inRepo) throw new Error("refusing to execute examples: " + libDir + " is not this package's lib/");

  var docs = parser.parseTree(libDir);

  // Contain any stray write: run from a sacrificial cwd and restore after. No
  // example in this library writes a file today, and this is what keeps that
  // true by accident rather than by luck.
  var origCwd = process.cwd();
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-example-exec-"));
  // Unhandled rejections are ATTRIBUTED, never discarded. An example that starts a
  // rejecting promise without awaiting or returning it settles runExample happily,
  // so a listener that swallowed the rejection would count a broken asynchronous
  // example as passing -- the same silent-acceptance hole the typed-error and
  // fragment buckets had. Collect them and charge each to the example that ran.
  var rejections = [];
  var onReject = function (reason) { rejections.push(reason); };
  process.on("unhandledRejection", onReject);
  process.chdir(tmp);

  // An unhandledRejection is emitted a turn AFTER the example settles, so yield to
  // the loop before reading the queue or the rejection lands on the next example.
  function drainRejections() {
    return new Promise(function (resolve) {
      setImmediate(function () {
        var taken = rejections.slice();
        rejections.length = 0;
        resolve(taken);
      });
    });
  }

  var ran = 0, skipped = 0, failures = [], skipReasons = {};
  try {
    var files = Object.keys(docs);
    for (var fi = 0; fi < files.length; fi += 1) {
      var prims = docs[files[fi]].primitives || [];
      for (var pi = 0; pi < prims.length; pi += 1) {
        var sig = (prims[pi].tags && prims[pi].tags.primitive) || files[fi];
        var exs = (prims[pi].tags && prims[pi].tags.examples) || [];
        for (var ei = 0; ei < exs.length; ei += 1) {
          var res = await runtime.runExample(exs[ei]);
          var stray = await drainRejections();
          if (stray.length) {
            // Whatever the example's own outcome was, it left a rejection nobody
            // handled -- that is a defect in the documented code.
            var why = (stray[0] && (stray[0].message || stray[0].code)) || String(stray[0]);
            res = { outcome: "fail", error: "left " + stray.length + " unhandled rejection(s): " + why +
              " -- the example starts a promise it never awaits or returns" };
          }
          if (res.outcome === "ran") { ran += 1; continue; }
          if (res.outcome === "skip") {
            skipped += 1;
            skipReasons[res.reason] = (skipReasons[res.reason] || 0) + 1;
            continue;
          }
          failures.push({ sig: sig, error: String(res.error).split("\n").slice(0, 2).join(" ") });
        }
      }
    }
  } finally {
    process.chdir(origCwd);
    process.removeListener("unhandledRejection", onReject);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }

  var summary = "[jsdoc-example-execution] executed " + ran + ", skipped " + skipped +
    ", failed " + failures.length;
  console.log(summary);
  Object.keys(skipReasons).sort().forEach(function (r) {
    console.log("  skip: " + r + " x" + skipReasons[r]);
  });
  // Persist the detail: under a forked smoke worker whose stdout the parent does
  // not fold into its log, a failure list printed here would otherwise be lost.
  var report = summary + "\n" +
    Object.keys(skipReasons).sort().map(function (r) { return "  skip: " + r + " x" + skipReasons[r]; }).join("\n") + "\n" +
    failures.map(function (f) { return "  FAIL " + f.sig + " :: " + f.error; }).join("\n") + "\n";
  try { fs.writeFileSync(path.join(ROOT, ".test-output", "jsdoc-example-execution.log"), report); }
  catch (_e2) { /* best-effort */ }
  failures.slice(0, 50).forEach(function (f) { console.log("  FAIL " + f.sig + " :: " + f.error); });

  // The gate itself.
  check("every executed @example runs without throwing (catches a renamed / removed / reshaped API)",
    failures.length === 0);

  // ...and the gate has to actually be RUNNING things. Every skip-based gate can
  // rot the same way: a change that turns examples back into fragments leaves
  // this file green while checking less and less. Two floors, because they fail
  // on different things.
  //
  // EXECUTED_FLOOR is a RATCHET -- it only ever moves UP. If a primitive is
  // legitimately removed along with its example, raise/lower it in the same
  // reviewed diff that removes the primitive; do not relax it to make a red
  // gate green.
  var EXECUTED_FLOOR = 199;
  check("the @example gate executes at least " + EXECUTED_FLOOR + " examples (ratchet: got " + ran + ")",
    ran >= EXECUTED_FLOOR);
  // The proportional floor catches DILUTION the absolute one cannot: adding many
  // new fragment examples keeps `ran` above the ratchet while the share of the
  // corpus actually covered falls.
  check("the @example gate executes a majority of the corpus (it is not silently skipping)",
    ran >= (ran + skipped) * 0.5);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
