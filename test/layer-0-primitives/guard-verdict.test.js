// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard.verdict: every field of a verify verdict is an own property,
 * installed by definition rather than by assignment. Assignment consults the
 * prototype chain, so a co-resident that installs a setter on Object.prototype
 * while a verification is pending can swallow the write and leave its own getter
 * answering the read. Pins the guard's own contract: fields survive a polluted
 * prototype, later sources win over earlier ones, an accessor on a source is
 * flattened to a value, and the result is a plain object a caller can read.
 *
 * `of` carries `@enforced-by behavioral`: the defect is the ABSENCE of the call at
 * a construction site, so these vectors and the per-consumer ones (pki.ocsp.verify,
 * pki.path.verifyOcspResponse, pki.crmf.verifyPop) ARE the guard.
 */

var helpers = require("../helpers");
var check = helpers.check;
var verdict = require("../../lib/guard-all").verdict;

var hasOwn = Object.prototype.hasOwnProperty;

function withPollution(key, value, fn) {
  Object.defineProperty(Object.prototype, key,
    { configurable: true, get: function () { return value; }, set: function () {} });
  try { return fn(); } finally { delete Object.prototype[key]; }
}

function run() {
  var out = verdict.of({ status: "revoked", reason: "keyCompromise" });
  check("1. of copies every own enumerable field", out.status === "revoked" && out.reason === "keyCompromise");
  check("2. each copied field is an own property", hasOwn.call(out, "status") && hasOwn.call(out, "reason"));
  check("3. the result is a plain object", Object.getPrototypeOf(out) === Object.prototype);

  var merged = verdict.of({ status: "good", matched: true }, { status: "unknown", nonceMatched: false });
  check("4. extras win over the source", merged.status === "unknown");
  check("5. fields the extras do not name are kept", merged.matched === true);
  check("6. fields only the extras name are added", merged.nonceMatched === false);

  check("7. of accepts an absent extras argument", verdict.of({ valid: true }).valid === true);
  check("8. of accepts a null extras argument", verdict.of({ valid: true }, null).valid === true);

  var polluted = withPollution("status", "good", function () {
    return verdict.of({ status: "revoked" });
  });
  check("9. a swallowing setter on the prototype cannot intercept a field",
    hasOwn.call(polluted, "status") && polluted.status === "revoked");

  var pollutedExtra = withPollution("valid", true, function () {
    return verdict.of({ status: "revoked" }, { valid: false });
  });
  check("10. a swallowing setter cannot intercept a field the extras add",
    hasOwn.call(pollutedExtra, "valid") && pollutedExtra.valid === false);

  // A field a source carries as an accessor is read once and stored as the value it
  // answered, so the copy never re-enters caller code on a later read.
  var reads = 0;
  var src = {};
  Object.defineProperty(src, "status", { enumerable: true, configurable: true,
    get: function () { reads++; return "revoked"; } });
  var flattened = verdict.of(src);
  var after = flattened.status;
  check("11. an accessor on a source is flattened to its value",
    after === "revoked" && !!Object.getOwnPropertyDescriptor(flattened, "status").writable);
  check("12. the accessor runs once, at copy time", reads === 1);

  // A field the source never carried stays absent, so a caller reading it sees the
  // same undefined it would have seen from the source.
  var narrow = verdict.of({ status: "good" });
  check("13. a field no source names is not invented", !hasOwn.call(narrow, "valid"));

  check("14. a symbol-keyed field on a source is not copied",
    (function () {
      var s = Symbol("tag");
      var withSym = {};
      withSym[s] = 1;
      withSym.status = "good";
      return verdict.of(withSym)[s] === undefined;
    })());

  check("15. a non-enumerable field on a source is not copied",
    (function () {
      var hidden = { status: "good" };
      Object.defineProperty(hidden, "secret", { value: 1, enumerable: false });
      return !hasOwn.call(verdict.of(hidden), "secret");
    })());

  var writable = verdict.of({ status: "good" });
  writable.status = "unknown";
  check("16. a copied field stays writable by the caller", writable.status === "unknown");

  // Resolving a promise reads `then` off the value. The own `then` ends that lookup, so an
  // inherited accessor never runs with the verdict as its receiver.
  var shielded = verdict.of({ status: "revoked", valid: false });
  check("17. the result carries an own then", hasOwn.call(shielded, "then") && shielded.then === undefined);
  check("18. the own then is not enumerable",
    Object.keys(shielded).join(",") === "status,valid" && JSON.stringify(shielded) === "{\"status\":\"revoked\",\"valid\":false}");

  return (async function () {
    var ran = false;
    var pending = Promise.resolve().then(function () { return shielded; });
    Object.defineProperty(Object.prototype, "then", { configurable: true,
      get: function () { ran = true; this.valid = true; return undefined; } });
    var settled;
    try { settled = await pending; } finally { delete Object.prototype.then; }
    check("19. an inherited then accessor does not run against the verdict", ran === false);
    check("20. the verdict the caller receives is the one that was built",
      settled === shielded && settled.valid === false && settled.status === "revoked");

    // A source that carries its own enumerable then cannot displace the shield.
    var hostile = verdict.of({ status: "good", then: function (res) { res({ status: "revoked" }); } });
    check("21. a then a source carries is replaced, not adopted",
      hostile.then === undefined && !Object.keys(hostile).includes("then"));
    check("22. such a verdict still resolves as itself",
      (await Promise.resolve(hostile)) === hostile);

    // `carries` answers from a captured own-property check, so replacing Object.hasOwn or
    // Object.prototype.hasOwnProperty after load does not change what it reports.
    var own = verdict.of({ status: "good" });
    check("23. carries reports a field the object owns", verdict.carries(own, "status"));
    check("24. carries reports an inherited field as absent",
      withPollution("verdict", { valid: true }, function () { return verdict.carries(own, "verdict") === false; }));
    check("25. carries answers for a primitive and a nullish argument without throwing",
      verdict.carries(null, "status") === false && verdict.carries(undefined, "status") === false &&
      verdict.carries("ab", "0") === true && verdict.carries(7, "status") === false);

    var realHasOwn = Object.hasOwn;
    var realHasOwnProperty = Object.prototype.hasOwnProperty;
    var swapped;
    try {
      Object.hasOwn = function () { return true; };
      Object.defineProperty(Object.prototype, "hasOwnProperty",
        { configurable: true, writable: true, value: function () { return true; } });
      swapped = verdict.carries(own, "verdict") === false && verdict.carries(own, "status") === true;
    } finally {
      Object.hasOwn = realHasOwn;
      Object.defineProperty(Object.prototype, "hasOwnProperty",
        { configurable: true, writable: true, value: realHasOwnProperty });
    }
    check("26. a replaced Object.hasOwn and hasOwnProperty do not change what carries reports", swapped);

    console.log("CHECKS " + helpers.getChecks());
  })();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
