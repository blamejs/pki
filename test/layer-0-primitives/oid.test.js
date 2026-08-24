// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.oid (OID ↔ name registry).
 * Oracle: known RFC / NIST names + hand-computed arc conversions.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = helpers.vectors;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testRegistry() {
  check("name(commonName)", pki.oid.name("2.5.4.3") === "commonName");
  check("name(sha256WithRSA)", pki.oid.name("1.2.840.113549.1.1.11") === "sha256WithRSAEncryption");
  check("name(ecPublicKey)", pki.oid.name("1.2.840.10045.2.1") === "ecPublicKey");
  check("name(Ed25519)", pki.oid.name("1.3.101.112") === "Ed25519");
  check("name(ML-DSA-87)", pki.oid.name("2.16.840.1.101.3.4.3.19") === "id-ml-dsa-87");
  check("name(ML-KEM-1024)", pki.oid.name("2.16.840.1.101.3.4.4.3") === "id-ml-kem-1024");
  check("name(basicConstraints)", pki.oid.name("2.5.29.19") === "basicConstraints");
  check("unregistered returns undefined", pki.oid.name("1.3.6.1.4.1.99999.7") === undefined);
  check("byName reverse lookup", pki.oid.byName("commonName") === "2.5.4.3");
  check("has()", pki.oid.has("2.5.4.3") === true && pki.oid.has("9.9.9") === false);
}

function testRegister() {
  pki.oid.register("1.3.6.1.4.1.99999.1", "acmeWidgetPolicy");
  check("register forward", pki.oid.name("1.3.6.1.4.1.99999.1") === "acmeWidgetPolicy");
  check("register reverse", pki.oid.byName("acmeWidgetPolicy") === "1.3.6.1.4.1.99999.1");
  check("register rejects bad oid", code(function () { pki.oid.register("nope", "x"); }) === "oid/bad-input");
  // registerFamily registers a whole arc family, deriving each OID from the
  // shared base + a numeric or multi-level-array leaf.
  pki.oid.registerFamily([1, 3, 6, 1, 4, 1, 88888], { widget: 1, gadget: [2, 4] });
  check("registerFamily forward + multi-level leaf", pki.oid.name("1.3.6.1.4.1.88888.2.4") === "gadget");
  // A large arc must survive as BigInt — a 128-bit UUID-based arc (X.667)
  // exceeds 2^53, so a Number would lose precision.
  pki.oid.registerFamily([2, 25], { bigUuidArc: 340282366920938463463374607431768211455n });
  check("registerFamily preserves a 128-bit BigInt arc",
    pki.oid.name("2.25.340282366920938463463374607431768211455") === "bigUuidArc");
  check("registerFamily rejects an unsafe Number arc",
    code(function () { pki.oid.registerFamily([2, 26], { x: 9007199254740992 }); }) === "oid/bad-arc");
  // Collision semantics: a later registration of the same OID replaces the
  // forward name; the reverse (name -> OID) keeps the first registration.
  pki.oid.register("1.3.6.1.4.1.99999.200", "fwdA");
  pki.oid.register("1.3.6.1.4.1.99999.200", "fwdB");
  check("re-register replaces the forward name", pki.oid.name("1.3.6.1.4.1.99999.200") === "fwdB");
  check("first reverse registration stays canonical", pki.oid.byName("fwdA") === "1.3.6.1.4.1.99999.200");
  // A leading-zero component is a key no decoded OID can produce — the same
  // string round-trips through the arc converters to a DIFFERENT OID.
  check("register rejects a leading-zero component", code(function () { pki.oid.register("01.2.840.113549", "x"); }) === "oid/bad-input");
  check("name rejects a leading-zero component", code(function () { pki.oid.name("01.2.840.113549"); }) === "oid/bad-input");
  // X.660 encodability: root arc 0..2; second arc 0..39 under roots 0 and 1.
  check("register rejects a root arc above 2", code(function () { pki.oid.register("9.9.9", "x"); }) === "oid/bad-arc");
  check("register rejects second arc 40 under root 1", code(function () { pki.oid.register("1.40.1", "x"); }) === "oid/bad-arc");
  check("register accepts second arc 40 under root 2", code(function () { pki.oid.register("2.40.99999", "joint40"); }) === "NO-THROW");
  // A member whose derived OID has fewer than 2 arcs can never round-trip
  // through name()/has()/toDER() (all require >= 2 arcs) — reject at register.
  check("registerFamily rejects a one-arc member", code(function () { pki.oid.registerFamily([2], { loneArc: [] }); }) === "oid/bad-input");
  // The base and members arguments are validated before any member is assembled: a base that is not a
  // non-empty arc array, and a members that is not an object, each fail at entry rather than deriving a
  // malformed OID or reading properties off a non-object.
  check("registerFamily rejects a non-array base", code(function () { pki.oid.registerFamily("1.3.6", { x: 1 }); }) === "oid/bad-input");
  check("registerFamily rejects an empty base", code(function () { pki.oid.registerFamily([], { x: 1 }); }) === "oid/bad-input");
  check("registerFamily rejects a base with a non-arc component", code(function () { pki.oid.registerFamily([1, -3], { x: 1 }); }) === "oid/bad-input");
  check("registerFamily rejects a null members", code(function () { pki.oid.registerFamily([1, 3, 6], null); }) === "oid/bad-input");
  check("registerFamily rejects a non-object members", code(function () { pki.oid.registerFamily([1, 3, 6], 42); }) === "oid/bad-input");
  // all() dumps the whole registry as a dotted -> name map, and hands back a COPY: mutating the returned
  // object must not reach the registry, so a caller cannot poison a later name() lookup through it.
  var dump = pki.oid.all();
  check("all() returns the registry map including a known entry", dump && dump["1.2.840.113549.1.1.1"] === "rsaEncryption");
  dump["1.2.840.113549.1.1.1"] = "POISONED";
  check("all() hands back a copy -- mutating it does not corrupt the registry", pki.oid.name("1.2.840.113549.1.1.1") === "rsaEncryption");
}

function testArcs() {
  check("toArcs", JSON.stringify(pki.oid.toArcs("2.5.4.3")) === JSON.stringify([2, 5, 4, 3]));
  // The string OID path must enforce the same X.660 arc bounds the register /
  // arc paths do -- a root above 2 (or a second arc >= 40 under roots 0/1) can
  // never DER-encode, so toArcs must reject it, not silently return the arcs.
  check("toArcs rejects a root arc above 2", code(function () { pki.oid.toArcs("9.9.9"); }) === "oid/bad-arc");
  check("toArcs rejects second arc 40 under root 1", code(function () { pki.oid.toArcs("1.40.1"); }) === "oid/bad-arc");
  check("fromArcs", pki.oid.fromArcs([1, 2, 840, 113549]) === "1.2.840.113549");
  check("arc round-trip", pki.oid.fromArcs(pki.oid.toArcs("2.16.840.1.101.3.4.2.1")) === "2.16.840.1.101.3.4.2.1");
  check("fromArcs rejects short", code(function () { pki.oid.fromArcs([1]); }) === "oid/bad-input");
  check("fromArcs rejects negative bigint arc", code(function () { pki.oid.fromArcs([2n, -5n, 1n]); }) === "oid/bad-arc");
  // An integer above 2^53 is not representable precisely as a Number, so a
  // large arc must be a BigInt — reject an unsafe-integer Number outright.
  check("fromArcs rejects an unsafe (>2^53) Number arc",
    code(function () { pki.oid.fromArcs([2, 9007199254740992]); }) === "oid/bad-arc");
  check("fromArcs accepts the same arc as a BigInt", pki.oid.fromArcs([2, 9007199254740992n]) === "2.9007199254740992");
}

function testDer() {
  vectors.OID_CONTENT.forEach(function (t) {
    var full = pki.oid.toDER(t[0]);
    check("toDER/fromDER round-trip " + t[0], pki.oid.fromDER(full) === t[0]);
  });
  // fromDER routes its input through the shared byte guard: a non-Buffer and a
  // detached-backed Buffer now fail closed as a typed OidError, not a raw
  // TypeError or a Buffer.from coercion of a string/number into stray bytes.
  check("fromDER non-buffer -> oid/bad-input", code(function () { pki.oid.fromDER("not der bytes"); }) === "oid/bad-input");
  check("fromDER detached-backed Buffer -> oid/bad-input", code(function () {
    var ab = new ArrayBuffer(4); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.oid.fromDER(b);
  }) === "oid/bad-input");
}

// RFC 9909 §3 — the 12 Pure SLH-DSA parameter-set OIDs under sigAlgs
// (2.16.840.1.101.3.4.3), assigned sequentially: the SHA-2 sets .20-.25, then the
// SHAKE sets .26-.31. Every id-slh-dsa-* name must round-trip to its exact arc.
function testSlhDsa() {
  var SIG = "2.16.840.1.101.3.4.3.";
  var expect = {
    "id-slh-dsa-sha2-128s": 20, "id-slh-dsa-sha2-128f": 21,
    "id-slh-dsa-sha2-192s": 22, "id-slh-dsa-sha2-192f": 23,
    "id-slh-dsa-sha2-256s": 24, "id-slh-dsa-sha2-256f": 25,
    "id-slh-dsa-shake-128s": 26, "id-slh-dsa-shake-128f": 27,
    "id-slh-dsa-shake-192s": 28, "id-slh-dsa-shake-192f": 29,
    "id-slh-dsa-shake-256s": 30, "id-slh-dsa-shake-256f": 31,
    // pre-hash HashSLH-DSA sets (RFC 9909 §3), .35-.46
    "id-hash-slh-dsa-sha2-128s-with-sha256": 35, "id-hash-slh-dsa-sha2-128f-with-sha256": 36,
    "id-hash-slh-dsa-sha2-192s-with-sha512": 37, "id-hash-slh-dsa-sha2-192f-with-sha512": 38,
    "id-hash-slh-dsa-sha2-256s-with-sha512": 39, "id-hash-slh-dsa-sha2-256f-with-sha512": 40,
    "id-hash-slh-dsa-shake-128s-with-shake128": 41, "id-hash-slh-dsa-shake-128f-with-shake128": 42,
    "id-hash-slh-dsa-shake-192s-with-shake256": 43, "id-hash-slh-dsa-shake-192f-with-shake256": 44,
    "id-hash-slh-dsa-shake-256s-with-shake256": 45, "id-hash-slh-dsa-shake-256f-with-shake256": 46,
  };
  Object.keys(expect).forEach(function (nm) {
    var dotted = SIG + expect[nm];
    check("byName(" + nm + ") -> ." + expect[nm], pki.oid.byName(nm) === dotted);
    check("name(." + expect[nm] + ") -> " + nm, pki.oid.name(dotted) === nm);
  });
  // The two arcs that were historically swapped: .24 is sha2-256s (not shake-128s),
  // .27 is shake-128f (not shake-256s) — pin them explicitly.
  check(".24 is sha2-256s", pki.oid.name(SIG + "24") === "id-slh-dsa-sha2-256s");
  check(".27 is shake-128f", pki.oid.name(SIG + "27") === "id-slh-dsa-shake-128f");
}

// paramsMustBeAbsent — the algorithm identifiers whose AlgorithmIdentifier
// parameters field MUST be absent (RFC 9909 §3 / 9814 §4 / 9881 §2 / 8410 §3 /
// 9936 §3 ML-KEM / 8619 §2 HKDF).
function testParamsMustBeAbsent() {
  var must = [
    "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87",
    "id-slh-dsa-sha2-128s", "id-slh-dsa-sha2-128f", "id-slh-dsa-sha2-192s",
    "id-slh-dsa-sha2-192f", "id-slh-dsa-sha2-256s", "id-slh-dsa-sha2-256f",
    "id-slh-dsa-shake-128s", "id-slh-dsa-shake-128f", "id-slh-dsa-shake-192s",
    "id-slh-dsa-shake-192f", "id-slh-dsa-shake-256s", "id-slh-dsa-shake-256f",
    "id-hash-slh-dsa-sha2-128s-with-sha256", "id-hash-slh-dsa-sha2-128f-with-sha256",
    "id-hash-slh-dsa-sha2-192s-with-sha512", "id-hash-slh-dsa-sha2-192f-with-sha512",
    "id-hash-slh-dsa-sha2-256s-with-sha512", "id-hash-slh-dsa-sha2-256f-with-sha512",
    "id-hash-slh-dsa-shake-128s-with-shake128", "id-hash-slh-dsa-shake-128f-with-shake128",
    "id-hash-slh-dsa-shake-192s-with-shake256", "id-hash-slh-dsa-shake-192f-with-shake256",
    "id-hash-slh-dsa-shake-256s-with-shake256", "id-hash-slh-dsa-shake-256f-with-shake256",
    "Ed25519", "Ed448", "X25519", "X448",
    "id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024",
    "hkdfWithSha256", "hkdfWithSha384", "hkdfWithSha512",
  ];
  must.forEach(function (nm) {
    check("paramsMustBeAbsent(" + nm + ") -> true", pki.oid.paramsMustBeAbsent(pki.oid.byName(nm)) === true);
  });
  check("count of the must-absent set is 37 (12 pure + 12 hash SLH-DSA + 3 ML-DSA + 4 Ed/X + 3 ML-KEM + 3 HKDF)", must.length === 37);
  // Algorithms that legitimately CARRY parameters (or a NULL) are NOT in the set.
  ["rsaEncryption", "sha256WithRSAEncryption", "rsassaPss", "ecPublicKey", "prime256v1", "aes256-GCM"].forEach(function (nm) {
    check("paramsMustBeAbsent(" + nm + ") -> false", pki.oid.paramsMustBeAbsent(pki.oid.byName(nm)) === false);
  });
  // An unregistered dotted OID is not in the set (no throw, plain false).
  check("paramsMustBeAbsent of an unknown OID -> false", pki.oid.paramsMustBeAbsent("1.2.3.4.5.6.7.8") === false);
}

// Config-time argument validation (three-tier model: bad input at the
// registration/lookup boundary THROWS so an operator catches the typo at boot).
function testConfigTimeValidation() {
  // byName demands a non-empty string.
  check("byName rejects a non-string", code(function () { pki.oid.byName(123); }) === "oid/bad-input");
  check("byName rejects an empty string", code(function () { pki.oid.byName(""); }) === "oid/bad-input");
  // register demands a non-empty string NAME (the dotted OID is validated separately).
  check("register rejects a non-string name", code(function () { pki.oid.register("1.3.6.1.4.1.99999.301", 42); }) === "oid/bad-input");
  // registerFamily argument validation.
  check("registerFamily rejects a non-array base", code(function () { pki.oid.registerFamily("1.3.6", { x: 1 }); }) === "oid/bad-input");
  check("registerFamily rejects a base with a non-arc component", code(function () { pki.oid.registerFamily([1, "x"], { y: 1 }); }) === "oid/bad-input");
  check("registerFamily rejects non-object members", code(function () { pki.oid.registerFamily([1, 3, 6], null); }) === "oid/bad-input");
  check("registerFamily rejects an empty-string member name", code(function () { pki.oid.registerFamily([1, 3, 6, 1, 4, 1, 77777], { "": 1 }); }) === "oid/bad-input");
  // registerFamily assembles the arcs then enforces X.660 encodability ON them
  // (a distinct path from register's dotted-string check): a base whose root arc
  // exceeds 2, or -- under roots 0/1 -- whose second arc reaches 40.
  check("registerFamily rejects a root arc above 2 (assembled)", code(function () { pki.oid.registerFamily([9, 1], { z: 1 }); }) === "oid/bad-arc");
  check("registerFamily rejects a second arc 40 under root 1 (assembled)", code(function () { pki.oid.registerFamily([1, 40], { z: 1 }); }) === "oid/bad-arc");
  // ...with the base arcs supplied as BigInt (the already-bigint branch of the
  // arc-coercion; a UUID-based OID under root 2 uses BigInt arcs).
  check("registerFamily accepts a BigInt base + leaf", code(function () { pki.oid.registerFamily([2n, 25n], { bigBaseName: 7n }); }) === "NO-THROW");
  check("registerFamily(BigInt base) resolves forward", pki.oid.name("2.25.7") === "bigBaseName");
  // toArcs keeps an arc above 2^53 as a BigInt (a Number would lose precision).
  var arcs = pki.oid.toArcs("2.25.340282366920938463463374607431768211456");
  check("toArcs keeps an unsafe (>2^53) arc as BigInt",
    typeof arcs[2] === "bigint" && arcs[2] === 340282366920938463463374607431768211456n);
}

// The ML-KEM parameter sets are a property OF the algorithm identifier, so they resolve from the
// registry rather than from whichever module needed a size first. These vectors pin the FIPS 203
// Table 3 values and -- the load-bearing part -- that the previously separate per-module tables are
// GONE: three copies of the same constants is how one consumer silently disagrees with another, and
// the encapsulation-key lengths were already duplicated verbatim in two modules before this landed.
function testKemParams() {
  var fs = require("fs"), path = require("path");
  var LIB = path.join(__dirname, "..", "..", "lib");
  var EXPECT = {
    "id-ml-kem-512": { ek: 800, dk: 1632, ct: 768, ss: 32 },
    "id-ml-kem-768": { ek: 1184, dk: 2400, ct: 1088, ss: 32 },
    "id-ml-kem-1024": { ek: 1568, dk: 3168, ct: 1568, ss: 32 },
  };
  Object.keys(EXPECT).forEach(function (n) {
    var row = pki.oid.kemParams(n);
    var want = EXPECT[n];
    check("kemParams(" + n + ") carries the FIPS 203 Table 3 sizes",
      !!row && row.ek === want.ek && row.dk === want.dk && row.ct === want.ct && row.ss === want.ss);
    check("kemParams resolves " + n + " by dotted OID to the SAME row",
      pki.oid.kemParams(pki.oid.byName(n)) === row);
  });
  check("kemParams fails closed for a non-KEM identifier", pki.oid.kemParams("1.2.3.4") === undefined);
  // The rows are PUBLIC and now govern a security check: decapsulateBits reads .ct to enforce the
  // FIPS 203 sec. 7.3 ciphertext length. A shared mutable row would let any code in the process
  // rewrite that bound once, for everyone -- so the row is frozen and a write to it does not take.
  var row768 = pki.oid.kemParams("id-ml-kem-768");
  check("a kemParams row is frozen", Object.isFrozen(row768));
  try { row768.ct = 100; } catch (_e) { /* strict-mode callers get a TypeError; both outcomes are fine */ }
  check("a write to a kemParams row does not take effect", pki.oid.kemParams("id-ml-kem-768").ct === 1088);
  try { row768.newField = 1; } catch (_e2) { /* likewise */ }
  check("a kemParams row cannot be extended", pki.oid.kemParams("id-ml-kem-768").newField === undefined);
  check("kemParams fails closed for an unregistered name", pki.oid.kemParams("id-ml-kem-9999") === undefined);
  // Fail-closed means fail-closed for EVERY input, including the names every object inherits.
  // A plain-object registry answers "toString" with a function, so a caller probing an untrusted
  // identifier would receive a truthy row for a parameter set that does not exist.
  ["toString", "constructor", "valueOf", "hasOwnProperty", "__proto__"].forEach(function (k) {
    check("kemParams fails closed for the inherited name " + JSON.stringify(k), pki.oid.kemParams(k) === undefined);
  });
  // No module may reintroduce a literal size table: a re-inlined copy is exactly the drift the
  // registry removes, and it would not show up in any behavioral test until the two disagreed.
  var LITERALS = [/\bek:\s*800\b/, /\bdk:\s*1632\b/, /=\s*1088;/, /\[800,\s*1184,\s*1568\]/];
  var offenders = [];
  fs.readdirSync(LIB).filter(function (f) { return /\.js$/.test(f); }).forEach(function (f) {
    var src = fs.readFileSync(path.join(LIB, f), "utf8");
    if (LITERALS.some(function (re) { return re.test(src); })) offenders.push(f);
  });
  check("no lib module carries its own ML-KEM size table (the registry is the sole source)",
    offenders.length === 0, offenders.join(", "));
}

function run() {
  testRegistry();
  testRegister();
  testArcs();
  testDer();
  testSlhDsa();
  testParamsMustBeAbsent();
  testKemParams();
  testConfigTimeValidation();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
