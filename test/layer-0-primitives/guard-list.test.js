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

  // ---- snapshot / copyMap: a copy the caller's array cannot decide the contents of ----
  // `caller.slice()` and `caller.map(fn)` call a method the caller's own object carries, so an own
  // method on that array, or a replacement installed on Array.prototype, chooses the elements the
  // toolkit then treats as its private copy. Both verbs read `length` once and write each element
  // as an own data property, so neither the method nor an inherited index accessor is consulted.
  function underCopySubstitution(fn) {
    var realSlice = Array.prototype.slice;
    var realMap = Array.prototype.map;
    Array.prototype.slice = function () { return ["substituted"]; };
    Array.prototype.map = function () { return ["substituted"]; };
    try { return fn(); }
    finally { Array.prototype.slice = realSlice; Array.prototype.map = realMap; }
  }

  check("40. snapshot copies the elements the list holds", (function () {
    var src = ["a", "b", "c"];
    var copy = list.snapshot(src);
    return copy !== src && copy.length === 3 && copy.join("|") === "a|b|c";
  })());
  check("41. ...and the copy is independent of the source", (function () {
    var src = ["a"], copy = list.snapshot(src);
    src[0] = "changed";
    return copy[0] === "a";
  })());
  check("42. snapshot ignores a replaced Array.prototype.slice",
    underCopySubstitution(function () { return list.snapshot(["kept"]).join("|"); }) === "kept");
  check("43. copyMap ignores a replaced Array.prototype.map",
    underCopySubstitution(function () {
      return list.copyMap(["kept"], function (v) { return v + "!"; }).join("|");
    }) === "kept!");
  check("44. snapshot ignores an OWN slice the caller installed on its array", (function () {
    var hostile = ["kept"];
    hostile.slice = function () { return ["substituted"]; };
    return list.snapshot(hostile).join("|") === "kept";
  })());
  check("45. copyMap ignores an OWN map the caller installed on its array", (function () {
    var hostile = ["kept"];
    hostile.map = function () { return ["substituted"]; };
    return list.copyMap(hostile, function (v) { return v; }).join("|") === "kept";
  })());
  check("46. copyMap passes the element and its index", (function () {
    var seen = [];
    var out = list.copyMap(["x", "y"], function (v, i) { seen.push(v + i); return v + i; });
    return seen.join("|") === "x0|y1" && out.join("|") === "x0|y1";
  })());
  // `.slice()` carries a hole across as a hole, so every later read of that index consults
  // Array.prototype and an accessor installed after the copy answers it. Both verbs settle each
  // index to an own data property at copy time, so the value a later read sees is the value the
  // copy was taken from.
  check("47. a hole is settled to an own property, so a later prototype accessor cannot answer it", (function () {
    var sparse = ["a", , "c"];   // eslint-disable-line no-sparse-arrays
    var copy = list.snapshot(sparse);
    var realOne = Object.getOwnPropertyDescriptor(Array.prototype, "1");
    var read, sliced, slicedRead;
    sliced = sparse.slice();
    Object.defineProperty(Array.prototype, "1", { configurable: true, get: function () { return "decoy"; } });
    try { read = copy[1]; slicedRead = sliced[1]; }
    finally {
      if (realOne) Object.defineProperty(Array.prototype, "1", realOne);
      else delete Array.prototype[1];
    }
    return read === undefined && Object.prototype.hasOwnProperty.call(copy, 1) && slicedRead === "decoy";
  })());
  check("48. snapshot carries the whole length, trailing holes included", (function () {
    var trailing = ["a"];
    trailing.length = 3;
    var copy = list.snapshot(trailing);
    return copy.length === 3 && Object.prototype.hasOwnProperty.call(copy, 2) && copy[2] === undefined;
  })());
  check("49. both verbs refuse a receiver that is not an array",
    threw(function () { list.snapshot({ length: 0 }); }) === "TypeError" &&
    threw(function () { list.snapshot(null); }) === "TypeError" &&
    threw(function () { list.copyMap({ length: 0 }, function (v) { return v; }); }) === "TypeError");
  check("50. copyMap refuses a callback that is not a function",
    threw(function () { list.copyMap([], null); }) === "TypeError" &&
    threw(function () { list.copyMap(["a"], "notAFunction"); }) === "TypeError");

  /* The narrow is shared, because the walks in `guard.bytes` and `guard.identifier` take a caller's
     list too and one of them is a DOOR. A Proxy over `["a", "secret"]` whose length answered 2 and then
     0 walked `refuseAccessorFields` past the accessor named `secret` and returned as though it had
     checked it; one answering an OBJECT walked it with a value that was never a number. */
  var guard = require("../../lib/guard-all.js");
  function E(c, m) { var e = new Error(m); e.code = c; return e; }
  var subject = { a: 1 };
  Object.defineProperty(subject, "secret", {
    enumerable: true, configurable: true, get: function () { return "leaked"; },
  });
  function shrinking(values) {
    var k = 0;
    return new Proxy(["a", "secret"], {
      get: function (t, p, r) {
        if (p === "length") { var v = k < values.length ? values[k] : t.length; k++; return v; }
        return Reflect.get(t, p, r);
      },
    });
  }
  check("51. a names list whose length shrinks mid-walk does not walk the door past a field",
    threw(function () {
      guard.identifier.refuseAccessorFields(subject, shrinking([2, 0]), E, "x/bad", "the options");
    }) === "Error");
  check("52. and one whose length is an object is refused rather than coerced",
    threw(function () {
      guard.identifier.refuseAccessorFields(subject, shrinking([{ valueOf: function () { return 2; } }]),
        E, "x/bad", "the options");
    }) === "TypeError");
  /* CONTROL: a plain names list still reaches the accessor and still refuses it, so the two checks
     above are about the count rather than about the subject. */
  check("53. CONTROL a plain names list refuses the accessor it names",
    threw(function () {
      guard.identifier.refuseAccessorFields(subject, ["a", "secret"], E, "x/bad", "the options");
    }) === "Error");
  /* A Proxy whose TARGET is a function reports `typeof "function"`, so a receiver tested for
     `typeof !== "object"` was returned on unexamined and hid an own name through its `ownKeys` trap. */
  var callable = new Proxy(function () {}, {
    ownKeys: function () { return ["nope"]; },
    getOwnPropertyDescriptor: function () { return { value: 42, enumerable: true, configurable: true }; },
  });
  check("54. a callable Proxy is refused as an options bag, as an object Proxy is",
    threw(function () {
      guard.identifier.assertKnownKeys(callable, { nope: 1 }, E, "x/bad", "unknown option ");
    }) === "Error");
  /* CONTROL: a plain function is not a Proxy, so it goes through the ordinary name check and is
     reported for the names it really carries. The refusal above is about the Proxy, not about being
     callable. */
  var plainFnMessage = "";
  try { guard.identifier.assertKnownKeys(function () {}, {}, E, "x/bad", "unknown option "); }
  catch (e) { plainFnMessage = String(e.message); }
  check("55. CONTROL a plain function is reported for its own names, not as a Proxy (" +
    plainFnMessage + ")",
  plainFnMessage.indexOf("unknown option") === 0 && plainFnMessage.indexOf("Proxy") === -1);

  // guard.list.firstMatch -- the first element a predicate selects, or null. The written form it
  // replaces is `list.filter(p)[0]`: that indexes a result which is EMPTY when nothing matched, and
  // index 0 of an empty array answers from the array prototype, so a value installed there reads at
  // the call site as a selected element. `filter` also builds its result through the receiver's
  // Symbol.species, so the array indexed need not be one this toolkit made.
  var rows = [{ id: "a", n: 1 }, { id: "b", n: 2 }, { id: "b", n: 3 }];
  check("56. firstMatch returns the first element the predicate selects",
    guard.list.firstMatch(rows, function (r) { return r.id === "b"; }).n === 2);
  check("57. firstMatch returns null when nothing matches",
    guard.list.firstMatch(rows, function (r) { return r.id === "z"; }) === null);
  var realZeroFm = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  var planted = { id: "z", n: 99 };
  Object.defineProperty(Array.prototype, "0", { configurable: true, get: function () { return planted; }, set: function () {} });
  var underAccessor, viaFilter;
  try {
    underAccessor = guard.list.firstMatch(rows, function (r) { return r.id === "z"; });
    viaFilter = rows.filter(function (r) { return r.id === "z"; })[0];
  } finally {
    if (realZeroFm) Object.defineProperty(Array.prototype, "0", realZeroFm);
    else delete Array.prototype[0];
  }
  check("58. a value at Array.prototype[0] does not become a selected element (" +
    JSON.stringify(underAccessor) + ")", underAccessor === null);
  check("59. CONTROL the form it replaces does answer with it, so the vector is not vacuous",
    viaFilter === planted);
  check("60. firstMatch on an absent list is null, not a prototype value",
    guard.list.firstMatch(null, function () { return true; }) === null);
  check("61. firstMatch skips a hole rather than reading through it",
    guard.list.firstMatch(sparseWithHole(), function (v) { return v !== undefined; }) === "real");

  // guard.list.removeAt -- a removal that returns nothing, so it constructs nothing. `splice(i, 1)`
  // returns what it removed and builds that result through ArraySpeciesCreate, which reads the
  // receiver's `constructor` and then its Symbol.species: a getter there is handed the live array.
  var shrink = ["a", "b", "c", "d"];
  guard.list.removeAt(shrink, 1);
  check("62. removeAt drops the element and shifts the tail down (" + shrink.join(",") + ")",
    shrink.length === 3 && shrink[0] === "a" && shrink[1] === "c" && shrink[2] === "d");
  check("63. and every surviving index is the array's own",
    Object.prototype.hasOwnProperty.call(shrink, 0) &&
      Object.prototype.hasOwnProperty.call(shrink, 2) &&
      !Object.prototype.hasOwnProperty.call(shrink, 3));
  var realCtor = Object.getOwnPropertyDescriptor(Array.prototype, "constructor");
  var ctorReads = 0;
  Object.defineProperty(Array.prototype, "constructor", { configurable: true, get: function () { ctorReads += 1; return Array; } });
  var spliced = ["a", "b", "c"], removed = ["a", "b", "c"];
  try {
    guard.list.removeAt(removed, 0);
    spliced.splice(0, 1);
  } finally {
    if (realCtor) Object.defineProperty(Array.prototype, "constructor", realCtor);
    else delete Array.prototype.constructor;
  }
  check("64. removeAt consults no construction protocol while splice does (" + ctorReads + " read(s))",
    ctorReads === 1 && removed.length === 2 && spliced.length === 2);
  check("65. removeAt refuses an index the array does not hold",
    threw(function () { guard.list.removeAt(["a"], 1); }) === "RangeError" &&
      threw(function () { guard.list.removeAt(["a"], -1); }) === "RangeError");
  check("66. removeAt refuses a receiver that is not an array",
    threw(function () { guard.list.removeAt({ 0: "a", length: 1 }, 0); }) === "TypeError");

  console.log("CHECKS " + helpers.getChecks());
}

/* A list with a real element after a hole, built by defining only the slots it holds. */
function sparseWithHole() {
  var out = [];
  out.length = 2;
  Object.defineProperty(out, 1, { value: "real", writable: true, enumerable: true, configurable: true });
  return out;
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
