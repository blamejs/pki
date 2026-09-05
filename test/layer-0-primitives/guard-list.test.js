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

  // ==== the scan is bounded by the length it started with ====
  // Array.prototype.every reads length once. A loop that re-reads it can be driven forever by a
  // caller-owned array whose indexed read appends, which is a synchronous denial of service on the
  // option lists that reach these verbs (pki.tsp.request/verify certs and extensions,
  // pki.path.validate userInitialPolicySet). The predicate here gives up after 50 calls so a
  // regression fails the assertion instead of hanging the suite.
  function grower(initial) {
    var backing = [];
    for (var i = 0; i < initial; i++) backing.push(1);
    return new Proxy(backing, {
      get: function (t, k) {
        if (typeof k === "string" && String(Number(k)) === k) { t.push(1); return 1; }
        return t[k];
      },
    });
  }
  var calls = 0;
  var allRes = list.allMatch(grower(2), function () { calls++; return calls < 50; });
  check("27. allMatch scans only the length the list had at entry, so a growing list terminates",
    calls === 2 && allRes === true);

  calls = 0;
  var anyRes = list.anyMatches(grower(3), function () { calls++; return false; });
  check("28. anyMatches is bounded the same way", calls === 3 && anyRes === false);

  calls = 0;
  var containsRes = list.contains(grower(4), "absent");
  check("29. contains is bounded the same way", containsRes === false);

  // containsAll iterates the caller's REQUIRED values, which is the caller-owned list on the
  // pki.path.validate requiredEku route.
  var allValsRes = list.containsAll(["serverAuth"], grower(2));
  check("30. containsAll is bounded by the required-values length at entry", allValsRes === false);

  // ---- append: an own-data-property write, so no inherited setter sees the value ----
  // `arr.push(v)` on a list of length N performs Set(arr, "N", v), which walks the prototype
  // chain. A setter installed at that index swallows the value and a getter answers the read in
  // its place, so a list the toolkit builds hands its caller something the toolkit never put there.
  var grown = [];
  check("31. append returns the list it wrote to", list.append(grown, "a") === grown && grown.length === 1 && grown[0] === "a");
  list.append(grown, "b");
  check("32. append writes successive indices", grown.length === 2 && grown[1] === "b" && Object.keys(grown).join(",") === "0,1");
  check("33. an appended entry is a writable own property", (function () {
    var d = Object.getOwnPropertyDescriptor(grown, 1);
    return d.writable === true && d.enumerable === true && d.configurable === true && d.value === "b";
  })());

  var realZero = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  var swallowed = [], decoyRead;
  Object.defineProperty(Array.prototype, "0",
    { configurable: true, get: function () { return "decoy"; }, set: function () {} });
  try {
    list.append(swallowed, "real");
    decoyRead = swallowed[0];
  } finally {
    if (realZero) Object.defineProperty(Array.prototype, "0", realZero);
    else delete Array.prototype[0];
  }
  check("34. a setter at the appended index cannot swallow the value", decoyRead === "real");
  check("35. ...and the value is the list's own property, not the prototype's",
    Object.prototype.hasOwnProperty.call(swallowed, "0") && swallowed.length === 1);

  check("36. append writes past a hole without consulting the prototype", (function () {
    var sparse = new Array(3);
    list.append(sparse, "tail");
    return sparse.length === 4 && sparse[3] === "tail" && !Object.prototype.hasOwnProperty.call(sparse, 0);
  })());

  // Defining a property does not grow `length` the way an assignment does, so the two boundaries
  // `Array.prototype.push` reports have to be reported here rather than passed over: a receiver that
  // is not an array, where a definition would leave `length` behind, and a full array, where the
  // index has nowhere to go and a definition would overwrite the last entry instead of failing.
  function threw(fn) { try { fn(); return null; } catch (e) { return e.constructor.name; } }
  check("37. append refuses a receiver that is not an array",
    threw(function () { list.append({ length: 0 }, "x"); }) === "TypeError" &&
    threw(function () { list.append("ab", "x"); }) === "TypeError" &&
    threw(function () { list.append(null, "x"); }) === "TypeError");
  check("38. append refuses a full array rather than overwriting its last entry", (function () {
    var full = new Array(4294967295);
    var err = threw(function () { list.append(full, "x"); });
    return err === "RangeError" && !Object.prototype.hasOwnProperty.call(full, 4294967294);
  })());
  check("39. append refuses a frozen list, as push does", (function () {
    var frozen = Object.freeze([]);
    return threw(function () { list.append(frozen, "x"); }) === "TypeError" && frozen.length === 0;
  })());

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
