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

function run() {
  testRegistry();
  testRegister();
  testArcs();
  testDer();
  testSlhDsa();
  testParamsMustBeAbsent();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
