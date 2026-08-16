// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the documentation and the exported surface describe the same toolkit.
 *
 * Two directions, and each has produced a real defect in this repo:
 *
 *   - A doc block names a verb the package does not export. An operator reads the reference, writes
 *     the call, and gets a TypeError from their own code. The wiki is generated from these blocks,
 *     so the claim reaches the website as well as the source.
 *   - A verb is exported with no block at all. It appears in no reference, so the only way to learn
 *     it exists is to read lib/ -- and an undocumented verb is one nobody reviews the contract of.
 *
 * This is checked by RESOLVING each documented name against the real `require("..")` surface rather
 * than by comparing two lists in the repo, because two lists can agree with each other while both
 * being wrong about what ships. It is deliberately NOT a frozen inventory of names (drift rule
 * sec. 2): it holds no list of its own, so a renamed verb that is renamed in both places passes,
 * and only a genuine disagreement between the docs and the export fails.
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

var LIB = path.resolve(__dirname, "..", "..", "lib");

// Every name a doc block claims, from the blocks the wiki generator reads.
function documentedNames() {
  var out = new Set();
  fs.readdirSync(LIB).filter(function (f) { return /\.js$/.test(f); }).forEach(function (f) {
    var src = fs.readFileSync(path.join(LIB, f), "utf8");
    var re = /@(?:primitive|module)\s+(pki[A-Za-z0-9_.]*)/g, m;
    while ((m = re.exec(src))) out.add(m[1]);
  });
  return out;
}

// Resolve a dotted name against the real export, without invoking anything.
function resolveName(name) {
  var parts = name.split(".").slice(1);   // drop the leading "pki"
  var cur = pki;
  for (var i = 0; i < parts.length; i++) {
    if (cur == null || typeof cur !== "object" || !(parts[i] in cur)) return { found: false };
    cur = cur[parts[i]];
  }
  return { found: true, value: cur };
}

function run() {
  var documented = documentedNames();
  check("the doc blocks were found at all", documented.size > 100);

  // ---- direction 1: every documented name exists on the shipped surface -------------------------
  var absent = [];
  documented.forEach(function (name) {
    if (name === "pki") return;
    var r = resolveName(name);
    if (!r.found) absent.push(name);
  });
  check("every documented name resolves on the exported surface" +
    (absent.length ? " (missing: " + absent.slice(0, 5).join(", ") + ")" : ""), absent.length === 0);

  // A documented name is a function or a namespace object -- never undefined, and never a bare
  // value pretending to be callable surface.
  var wrongKind = [];
  documented.forEach(function (name) {
    if (name === "pki") return;
    var r = resolveName(name);
    if (!r.found) return;
    var t = typeof r.value;
    if (t !== "function" && t !== "object") wrongKind.push(name + " is a " + t);
  });
  check("no documented name resolves to a non-callable, non-namespace value" +
    (wrongKind.length ? " (" + wrongKind.slice(0, 3).join("; ") + ")" : ""), wrongKind.length === 0);

  // ---- direction 2: every exported verb is documented -------------------------------------------
  // A namespace-level block covers the members beneath it (pki.C.TIME documents its unit helpers),
  // and an error CLASS is a constructor rather than a verb, so neither needs its own block.
  //
  // A namespace exported under two names -- `pki.C` and its long-form alias `pki.constants` are the
  // same object -- is documented once. The alias is resolved by object IDENTITY rather than by
  // requiring a duplicate block: a second block would be a second thing to keep true, and the two
  // could then disagree about a namespace that is physically one object.
  var documentedObjects = [];
  documented.forEach(function (n) {
    var r = resolveName(n);
    if (r.found && r.value && typeof r.value === "object") documentedObjects.push(r.value);
  });
  function coveredByNamespace(name) {
    var parts = name.split(".");
    for (var i = parts.length - 1; i > 1; i--) {
      var prefix = parts.slice(0, i).join(".");
      if (documented.has(prefix)) return true;
      var r = resolveName(prefix);
      if (r.found && r.value && typeof r.value === "object" && documentedObjects.indexOf(r.value) >= 0) return true;
    }
    return false;
  }
  var undocumented = [];
  (function walk(obj, prefix, depth) {
    if (depth > 2 || obj == null) return;
    Object.keys(obj).forEach(function (k) {
      if (k.charAt(0) === "_") return;
      // Read it plainly. A property of the PUBLIC export that throws on read is a defect in its own
      // right -- an operator enumerating the surface would hit it -- so letting it surface here is
      // more useful than stepping around it.
      var v = obj[k];
      var name = prefix + "." + k;
      if (typeof v === "function") {
        if (/^[A-Z]/.test(k)) return;   // an error class, documented with its family
        if (!documented.has(name) && !coveredByNamespace(name)) undocumented.push(name);
      } else if (v && typeof v === "object" && depth < 2 && !Buffer.isBuffer(v) && !Array.isArray(v)) {
        walk(v, name, depth + 1);
      }
    });
  })(pki, "pki", 0);
  check("every exported verb carries a doc block" +
    (undocumented.length ? " (missing: " + undocumented.slice(0, 5).join(", ") + ")" : ""),
    undocumented.length === 0);

  // ---- the check can actually fail ---------------------------------------------------------------
  // A gate nobody has seen fail is a gate nobody knows works. These drive the same two comparisons
  // over a surface that is deliberately wrong, so the logic is proven rather than assumed.
  var fakeDocumented = new Set(["pki.x509.sign", "pki.notAVerb.atAll"]);
  var fakeAbsent = [];
  fakeDocumented.forEach(function (name) { if (!resolveName(name).found) fakeAbsent.push(name); });
  check("the resolver reports a documented name the package does not export",
    fakeAbsent.length === 1 && fakeAbsent[0] === "pki.notAVerb.atAll");
  check("...and does not report one it does", resolveName("pki.x509.sign").found === true);
  // The alias rule is proven too, not assumed: pki.constants and pki.C must be the SAME object, so
  // one block covers both. If they ever become separate objects the alias needs its own block, and
  // this is what says so.
  check("the long-form constants alias is the same object as pki.C", pki.constants === pki.C);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
