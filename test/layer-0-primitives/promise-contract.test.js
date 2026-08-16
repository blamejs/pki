// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- a verb documented as returning a Promise REJECTS; it never throws synchronously.
 *
 * The failure this prevents is silent at the call site. An operator reads `-> Promise<...>` in the
 * reference and writes the documented shape:
 *
 *     pki.est.cacerts(url, opts).catch(handleIt);
 *
 * A validation that runs BEFORE the promise is created throws past that `.catch` entirely, so a
 * misspelled option or a malformed input becomes an uncaught exception in code that already handles
 * errors. Nothing in the type of the call says which verbs do this -- the caller cannot tell by
 * looking, which is why it needs a gate rather than a convention.
 *
 * The set is DERIVED from the `@signature` blocks rather than listed here (drift rule sec. 2): a
 * verb whose documented return type says `Promise` is in scope automatically, so a new one is
 * covered the day it is written and a verb that stops being async leaves scope on its own.
 *
 * The probe is "call it with no arguments". That is a bad input for every verb in scope, it needs no
 * per-verb knowledge that could drift, and a verb that legitimately succeeds without arguments
 * simply reports no failure. What is asserted is only the SHAPE of the refusal -- that it arrives as
 * a rejection -- never which error, which each verb's own vectors pin.
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

var LIB = path.resolve(__dirname, "..", "..", "lib");

// Every `@signature pki.x.y(...) -> Promise<...>` in lib/, as the name it documents.
function promiseVerbs() {
  var names = [];
  fs.readdirSync(LIB).filter(function (f) { return /\.js$/.test(f); }).forEach(function (f) {
    var src = fs.readFileSync(path.join(LIB, f), "utf8");
    var re = /@signature\s+(pki\.[A-Za-z0-9_.]+)\s*\([^)]*\)\s*->\s*([^\r\n]*)/g, m;
    while ((m = re.exec(src))) {
      if (/\bPromise\s*</.test(m[2])) names.push({ name: m[1], file: f });
    }
  });
  return names;
}

function resolveVerb(name) {
  var parts = name.split(".").slice(1);
  var cur = pki;
  for (var i = 0; i < parts.length; i++) {
    if (cur == null || !(parts[i] in cur)) return null;
    cur = cur[parts[i]];
  }
  return typeof cur === "function" ? cur : null;
}

async function run() {
  var verbs = promiseVerbs();
  check("the @signature blocks name some Promise-returning verbs", verbs.length > 20);

  var broken = [];
  for (var v of verbs) {
    var fn = resolveVerb(v.name);
    if (!fn) continue;   // doc-surface.test.js owns the "documented but absent" rule
    var threwSync = false;
    var ret;
    try { ret = fn(); }
    catch (_e) {
      threwSync = true;   // escaped before a promise existed: the caller's .catch() never sees it
    }
    if (ret && typeof ret.then === "function") {
      try { await ret; } catch (_e2) { /* a rejection is the correct shape; the code is each verb's own */ }
    } else if (!threwSync) {
      continue;   // returned a non-promise without throwing: not this gate's business
    }
    if (threwSync) broken.push(v.name + " (" + v.file + ")");
  }

  check("every verb documented as Promise-returning rejects rather than throwing synchronously" +
    (broken.length ? " -- " + broken.length + " break it: " + broken.slice(0, 6).join(", ") : ""),
    broken.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
