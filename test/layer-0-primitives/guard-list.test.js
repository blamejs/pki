// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard.list: membership decided by comparison, never by a prototype
 * method (the intrinsic-substitution defense). Pins the guard's own contract: each
 * of the four verbs answers from `===` and from the caller's own predicate, so
 * replacing Array.prototype.indexOf / some / every after load changes no answer;
 * an absent list is honestly empty rather than a throw, because these run on
 * verdict paths where a throw would read as a different verdict; and the vacuous
 * cases match what a rule needs (no required values is satisfied, an empty list
 * satisfies allMatch and fails anyMatches).
 *
 * The four verbs carry `@enforced-by behavioral`: `.indexOf(x) !== -1` has no
 * rename-proof shape that separates a membership rule from a substring search, so
 * these vectors and the per-consumer ones (path.validate requiredEku, cms.verify
 * trust, the OCSP delegated-responder check, the TPM AIK purpose check, the
 * timestamp unknown-critical gate) ARE the guard.
 */

var helpers = require("../helpers");
var check = helpers.check;
var list = require("../../lib/guard-all").list;

// Replace the three prototype methods a membership test would otherwise consult, run
// `fn`, and restore them whatever happens. Each replacement answers the OPPOSITE of a
// correct scan, so any surviving read flips the verdict rather than merely weakening it.
function underSubstitution(fn) {
  var realIndexOf = Array.prototype.indexOf;
  var realSome = Array.prototype.some;
  var realEvery = Array.prototype.every;
  var realIncludes = Array.prototype.includes;
  Array.prototype.indexOf = function () { return 0; };
  Array.prototype.some = function () { return false; };
  Array.prototype.every = function () { return true; };
  Array.prototype.includes = function () { return true; };
  try { return fn(); }
  finally {
    Array.prototype.indexOf = realIndexOf;
    Array.prototype.some = realSome;
    Array.prototype.every = realEvery;
    Array.prototype.includes = realIncludes;
  }
}

function run() {
  var purposes = ["serverAuth", "clientAuth"];
  var isLong = function (v) { return String(v).length > 6; };
  var isShort = function (v) { return String(v).length < 3; };

  // ==== contains ====
  check("1. contains finds a member", list.contains(purposes, "clientAuth") === true);
  check("2. contains refuses a non-member", list.contains(purposes, "codeSigning") === false);
  check("3. contains compares strictly, so a coercible lookalike is not a member",
    list.contains([1, 2, 3], "2") === false);
  check("4. contains treats an absent list as empty rather than throwing",
    list.contains(null, "x") === false && list.contains(undefined, "x") === false);
  check("5. contains reports false for an empty list", list.contains([], "x") === false);

  // ==== containsAll ====
  check("6. containsAll is satisfied when every required value is present",
    list.containsAll(purposes, ["clientAuth", "serverAuth"]) === true);
  check("7. containsAll fails when one required value is missing",
    list.containsAll(purposes, ["serverAuth", "codeSigning"]) === false);
  check("8. containsAll is vacuously satisfied by no required values",
    list.containsAll(purposes, []) === true && list.containsAll(purposes, null) === true);
  check("9. containsAll fails when the list is absent but values are required",
    list.containsAll(null, ["serverAuth"]) === false);

  // ==== anyMatches ====
  check("10. anyMatches reports a satisfying member", list.anyMatches(purposes, isLong) === true);
  check("11. anyMatches reports false when none satisfies", list.anyMatches(purposes, isShort) === false);
  check("12. anyMatches is false for an empty or absent list",
    list.anyMatches([], isLong) === false && list.anyMatches(null, isLong) === false);
  check("13. anyMatches passes the index as the predicate's second argument",
    list.anyMatches(["a", "b"], function (v, i) { return i === 1 && v === "b"; }) === true);

  // ==== allMatch ====
  check("14. allMatch reports true when every member satisfies", list.allMatch(purposes, isLong) === true);
  check("15. allMatch reports false when one member does not",
    list.allMatch(["serverAuth", "ab"], isLong) === false);
  check("16. allMatch is vacuously true for an empty list, matching Array.prototype.every",
    list.allMatch([], isLong) === true && list.allMatch(null, isLong) === true);
  check("17. allMatch passes the index as the predicate's second argument",
    list.allMatch(["a", "b"], function (v, i) { return typeof i === "number"; }) === true);

  // ==== the defense itself: every answer survives prototype substitution ====
  // Each of these would flip if the verb consulted the prototype: indexOf answering 0
  // makes any value a member, some answering false hides a match, every answering true
  // reports a whole list conforming without reading one element.
  check("18. contains still refuses a non-member with the prototype replaced after load",
    underSubstitution(function () { return list.contains(purposes, "codeSigning"); }) === false);
  check("19. contains still finds a real member with the prototype replaced after load",
    underSubstitution(function () { return list.contains(purposes, "serverAuth"); }) === true);
  check("20. containsAll still fails a missing requirement with the prototype replaced after load",
    underSubstitution(function () { return list.containsAll(purposes, ["codeSigning"]); }) === false);
  check("21. anyMatches still reports a match with the prototype replaced after load",
    underSubstitution(function () { return list.anyMatches(purposes, isLong); }) === true);
  check("22. anyMatches still reports no match with the prototype replaced after load",
    underSubstitution(function () { return list.anyMatches(purposes, isShort); }) === false);
  check("23. allMatch still reports a non-conforming member with the prototype replaced after load",
    underSubstitution(function () { return list.allMatch(["serverAuth", "ab"], isLong); }) === false);

  // A list whose own indexOf lies: the guard reads elements, so an own property that
  // shadows the prototype method changes no answer either.
  var liar = ["serverAuth"];
  liar.indexOf = function () { return 0; };
  liar.some = function () { return true; };
  liar.every = function () { return true; };
  check("24. contains refuses a non-member on a list carrying its own lying indexOf",
    list.contains(liar, "codeSigning") === false);
  check("25. anyMatches refuses on a list carrying its own lying some",
    list.anyMatches(liar, isShort) === false);
  check("26. allMatch refuses on a list carrying its own lying every",
    list.allMatch(["ab"], isLong) === false);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
