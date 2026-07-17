// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.cbor (strict deterministic CBOR codec).
 * Oracle: RFC 8949 hand-computed vectors + adversarial non-deterministic
 * inputs the decoder must reject (indefinite length, non-minimal argument,
 * unsorted / duplicate map keys, non-shortest / non-canonical-NaN float,
 * bad UTF-8, reserved additional-info, trailing bytes, depth / size caps).
 * Every reject vector maps to one RFC 8949 sec. 4.2 determinism rule; the
 * whole set is the RED corpus the codec must flip GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
function B(h) { return Buffer.from(h, "hex"); }

// ---- Accept: one canonical vector per major type + tagged form + boundary ----

function testAccept() {
  var d = pki.cbor.decode;
  var r = pki.cbor.read;

  // major type 0 — unsigned int, at every argument-width boundary (uniform BigInt)
  check("acc-uint-0", r.uint(d(B("00"))) === 0n);
  check("acc-uint-23", r.uint(d(B("17"))) === 23n);
  check("acc-uint-24", r.uint(d(B("1818"))) === 24n);
  check("acc-uint-255", r.uint(d(B("18ff"))) === 255n);
  check("acc-uint-256", r.uint(d(B("190100"))) === 256n);
  check("acc-uint-65535", r.uint(d(B("19ffff"))) === 65535n);
  check("acc-uint-65536", r.uint(d(B("1a00010000"))) === 65536n);
  check("acc-uint-4294967295", r.uint(d(B("1affffffff"))) === 4294967295n);
  check("acc-uint-4294967296", r.uint(d(B("1b0000000100000000"))) === 4294967296n);
  check("acc-uint-max64", r.uint(d(B("1bffffffffffffffff"))) === 18446744073709551615n);

  // major type 1 — negative int (both the type-pinned nint reader and the polymorphic int)
  check("acc-nint-neg1", r.int(d(B("20"))) === -1n);
  check("acc-nint-neg100", r.int(d(B("3863"))) === -100n);
  check("acc-nint-direct", r.nint(d(B("20"))) === -1n);

  // major type 2 — byte string
  check("acc-bstr-empty", r.byteString(d(B("40"))).length === 0);
  check("acc-bstr", r.byteString(d(B("4401020304"))).toString("hex") === "01020304");

  // major type 3 — text string (strict UTF-8)
  check("acc-tstr-empty", r.textString(d(B("60"))) === "");
  check("acc-tstr-a", r.textString(d(B("6161"))) === "a");

  // major type 4 — array
  check("acc-arr-empty", (function () { var n = d(B("80")); return n.majorType === 4 && r.array(n).length === 0; })());
  check("acc-arr-123", r.uint(r.array(d(B("83010203")))[1]) === 2n);
  check("acc-arr-nested", (function () {
    var n = d(B("8201820203")); var outer = r.array(n);
    return r.uint(outer[0]) === 1n && r.uint(r.array(outer[1])[1]) === 3n;
  })());

  // major type 5 — map (ordering + uniqueness enforced at decode)
  check("acc-map-empty", (function () { var n = d(B("a0")); return n.majorType === 5 && r.map(n).length === 0; })());
  check("acc-map-12", (function () {
    var pairs = r.map(d(B("a10102")));
    return pairs.length === 1 && r.uint(pairs[0][0]) === 1n && r.uint(pairs[0][1]) === 2n;
  })());
  check("acc-map-nested", (function () {
    var pairs = r.map(d(B("a101a10203")));
    var inner = r.map(pairs[0][1]);
    return r.uint(inner[0][0]) === 2n && r.uint(inner[0][1]) === 3n;
  })());
  check("acc-map-sorted-2", r.map(d(B("a201000200"))).length === 2);
  check("acc-map-sorted-bytewise", r.map(d(B("a20000181800"))).length === 2);

  // major type 6 — tagged forms
  check("acc-biguint", r.biguint(d(B("c249010000000000000000"))) === 18446744073709551616n);
  check("acc-time", r.time(d(B("c11a514b67b0"))).getTime() === 1363896240000);
  check("acc-oid", r.oid(d(B("d86f43550403"))) === "2.5.4.3");

  // major type 7 — simple + float
  check("acc-false", r.boolean(d(B("f4"))) === false);
  check("acc-true", r.boolean(d(B("f5"))) === true);
  check("acc-null", r.nullValue(d(B("f6"))) === null);
  check("acc-undefined", r.undefinedValue(d(B("f7"))) === undefined);
  check("acc-float-half", r.float(d(B("f93e00"))) === 1.5);
  check("acc-float-nan", Number.isNaN(r.float(d(B("f97e00")))));
  check("acc-float-inf", r.float(d(B("f97c00"))) === Infinity);
}

// ---- Reject: every determinism violation, at the decode layer ----

var DECODE_REJECTS = [
  // preferred / minimal argument (RFC 8949 sec. 4.2.1)
  ["1817", "cbor/non-minimal-argument"],
  ["190017", "cbor/non-minimal-argument"],
  ["1a00000017", "cbor/non-minimal-argument"],
  ["1b0000000000000017", "cbor/non-minimal-argument"],
  ["190018", "cbor/non-minimal-argument"],
  ["1a00000100", "cbor/non-minimal-argument"],
  ["59000141", "cbor/non-minimal-argument"],
  ["d900024101", "cbor/non-minimal-argument"],
  ["3800", "cbor/non-minimal-argument"],
  // indefinite length (sec. 4.2.1)
  ["5fff", "cbor/indefinite-length"],
  ["7fff", "cbor/indefinite-length"],
  ["9fff", "cbor/indefinite-length"],
  ["bfff", "cbor/indefinite-length"],
  ["5f420102420304ff", "cbor/indefinite-length"],
  // map ordering + uniqueness (sec. 4.2.1 / 5.6)
  ["a202000100", "cbor/unsorted-map-keys"],
  ["a21818000000", "cbor/unsorted-map-keys"],
  ["a201000101", "cbor/duplicate-map-key"],
  // shortest / canonical float (sec. 4.2.1 / 4.2.2)
  ["fa3fc00000", "cbor/non-minimal-float"],
  ["fb3ff8000000000000", "cbor/non-minimal-float"],
  ["fb40f86a0000000000", "cbor/non-minimal-float"],
  ["fa7f800000", "cbor/non-minimal-float"],
  ["fb7ff8000000000000", "cbor/non-canonical-nan"],
  ["f97e01", "cbor/non-canonical-nan"],
  // strict UTF-8 (sec. 3.1)
  ["61ff", "cbor/bad-utf8"],
  ["62c328", "cbor/bad-utf8"],
  // whole-buffer consumption (sec. 4.1)
  ["0000", "cbor/trailing-bytes"],
  // reserved / ill-formed heads (sec. 3.2.1 / 3.3)
  ["f800", "cbor/reserved-simple"],
  ["f81f", "cbor/reserved-simple"],
  ["1c", "cbor/reserved-ai"],
  ["1d", "cbor/reserved-ai"],
  ["1e", "cbor/reserved-ai"],
  ["1f", "cbor/reserved-ai"],
  ["df", "cbor/reserved-ai"],
  ["ff", "cbor/unexpected-break"],
  // truncation (sec. 3)
  ["1a0000", "cbor/truncated"],
  ["4401", "cbor/truncated"],
  ["9bffffffffffffffff", "cbor/truncated"],
];

function testRejectDecode() {
  DECODE_REJECTS.forEach(function (v) {
    check("decode " + v[0] + " -> " + v[1], code(function () { pki.cbor.decode(B(v[0])); }) === v[1]);
  });
  // opt-bearing bounds
  check("rej-too-deep", code(function () { pki.cbor.decode(B("818181818100"), { maxDepth: 2 }); }) === "cbor/too-deep");
  check("rej-too-large", code(function () { pki.cbor.decode(B("4100"), { maxBytes: 1 }); }) === "cbor/too-large");
  // oversized bignum: a valid tag-2 byte string of 65536 bytes; the reader caps it
  var bigBody = Buffer.concat([B("c25a00010000"), Buffer.alloc(65536, 0x01)]);
  var bigNode = pki.cbor.decode(bigBody);
  check("rej-biguint-too-large", code(function () { pki.cbor.read.biguint(bigNode); }) === "cbor/biguint-too-large");
}

// ---- Reader-layer rejects: tagged-value content + minimality ----

var READER_REJECTS = [
  ["c2420001", "biguint", "cbor/non-minimal-biguint"],
  ["c24101", "biguint", "cbor/non-minimal-biguint"],
  ["c200", "biguint", "cbor/bad-tag-content"],
  ["c1f93c00", "time", "cbor/bad-tag-content"],
  ["d86f00", "oid", "cbor/bad-tag-content"],
];

function testReaderRejects() {
  READER_REJECTS.forEach(function (v) {
    check("read." + v[1] + " " + v[0] + " -> " + v[2],
      code(function () { var n = pki.cbor.decode(B(v[0])); pki.cbor.read[v[1]](n); }) === v[2]);
  });
}

// ---- Read-mismatch: typed-reader assertions ----

var READ_MISMATCH = [
  ["4161", "textString", "cbor/unexpected-major"],
  ["6161", "uint", "cbor/unexpected-major"],
  ["20", "uint", "cbor/unexpected-major"],
  ["40", "int", "cbor/unexpected-major"],
  ["00", "byteString", "cbor/unexpected-major"],
  ["a10102", "array", "cbor/unexpected-major"],
  ["83010203", "map", "cbor/unexpected-major"],
  ["00", "biguint", "cbor/unexpected-tag"],
  ["00", "time", "cbor/unexpected-tag"],
  ["4161", "oid", "cbor/unexpected-tag"],
  ["c100", "biguint", "cbor/unexpected-tag"],
  ["c24101", "time", "cbor/unexpected-tag"],
  ["f7", "boolean", "cbor/bad-simple"],
];

function testReadMismatch() {
  READ_MISMATCH.forEach(function (v) {
    check("read." + v[1] + " on " + v[0] + " -> " + v[2],
      code(function () { var n = pki.cbor.decode(B(v[0])); pki.cbor.read[v[1]](n); }) === v[2]);
  });
}

// ---- Config-time: input guard + no-lenient-mode invariant ----

function testConfig() {
  check("rej-not-buffer", code(function () { pki.cbor.decode(123); }) === "cbor/not-buffer");
  // A detached-backed view (transferred / structuredClone'd) must fail closed
  // as a typed CborError, not a raw TypeError from Buffer.from in the byte walk.
  check("rej-detached-view", code(function () {
    var u = new Uint8Array([0]); structuredClone(u.buffer, { transfer: [u.buffer] });
    pki.cbor.decode(u);
  }) === "cbor/not-buffer");
  // A detached-backed BUFFER (not just a view) must also fail closed — the
  // Buffer arm has no as-is fast-path that would hand the walk empty bytes.
  check("rej-detached-buffer", code(function () {
    var ab = new ArrayBuffer(1); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.cbor.decode(b);
  }) === "cbor/not-buffer");
  check("rej-bad-profile is a config-time TypeError",
    threw(function () { pki.cbor.decode(B("00"), { profile: "lenient" }); }) instanceof TypeError);
  check("bad maxBytes is a config-time TypeError",
    threw(function () { pki.cbor.decode(B("00"), { maxBytes: -1 }); }) instanceof TypeError);
  // allowTrailing suppresses the trailing-bytes reject (CBOR-Sequence mode):
  // decode returns the FIRST item; the caller slices buf from node.bytes.length.
  check("allowTrailing accepts trailing bytes and returns the first item",
    (function () { var n = pki.cbor.decode(B("0001"), { allowTrailing: true }); return n.majorType === 0 && n.bytes.length === 1; })());
  // A maxDepth above the stack-safe ceiling is refused at config time, so a
  // deeply nested input can never overflow the native call stack with a raw
  // RangeError (the fail-closed contract): the recursion is bounded by the
  // ceiling regardless of the operator's maxDepth.
  check("maxDepth above the ceiling is a config-time TypeError",
    threw(function () { pki.cbor.decode(B("00"), { maxDepth: 1000000 }); }) instanceof TypeError);
  check("deeply nested input + a huge maxDepth throws a typed error, not a RangeError",
    (function () {
      var deep = Buffer.concat([Buffer.alloc(400, 0x81), Buffer.from([0x00])]);
      return threw(function () { pki.cbor.decode(deep, { maxDepth: 1000000 }); }) instanceof TypeError;
    })());
  check("a maxDepth override up to the ceiling still decodes nested input",
    pki.cbor.decode(Buffer.concat([Buffer.alloc(100, 0x81), Buffer.from([0x00])]), { maxDepth: 200 }).majorType === 4);
  // A high-fanout container that would allocate more nodes than the cap fails
  // closed with cbor/too-many-items instead of exhausting memory; a small
  // maxItems override exercises the same guard the default 1,000,000 cap applies
  // to a multi-million-item bomb (e.g. an array declaring 16M one-byte elements).
  check("an array exceeding maxItems throws too-many-items",
    code(function () { pki.cbor.decode(B("83010203"), { maxItems: 2 }); }) === "cbor/too-many-items");
  check("nested items also count toward the item cap",
    code(function () { pki.cbor.decode(B("8181818100"), { maxItems: 3 }); }) === "cbor/too-many-items");
  check("a container within the item cap decodes",
    pki.cbor.decode(B("83010203"), { maxItems: 4 }).majorType === 4);
}

// ---- Edge branches: valid-simple head, non-float/non-null/non-undefined
// simple readers, and the tag-1 time sign / out-of-range legs ----

function testEdgeBranches() {
  var d = pki.cbor.decode;
  var r = pki.cbor.read;

  // A simple value in [32,255] is validly encoded in the f8 (one-argument-byte)
  // form; only values < 32 must use the immediate head. f820 (simple 32)
  // decodes successfully rather than tripping cbor/reserved-simple.
  check("acc-simple-32-f8-form", (function () {
    var n = d(B("f820"));
    return n.majorType === 7 && n.ai === 24 && n.argument === 32n;
  })());
  check("acc-simple-255-f8-form", (function () {
    var n = d(B("f8ff"));
    return n.majorType === 7 && n.ai === 24 && n.argument === 255n;
  })());

  // read.nullValue / read.undefinedValue / read.float on a simple-value node
  // that is major 7 but the WRONG simple value throws cbor/bad-simple (the
  // ai-mismatch leg, distinct from the cbor/unexpected-major wrong-type leg).
  check("read.nullValue on false(f4) -> bad-simple",
    code(function () { r.nullValue(d(B("f4"))); }) === "cbor/bad-simple");
  check("read.nullValue on undefined(f7) -> bad-simple",
    code(function () { r.nullValue(d(B("f7"))); }) === "cbor/bad-simple");
  check("read.undefinedValue on null(f6) -> bad-simple",
    code(function () { r.undefinedValue(d(B("f6"))); }) === "cbor/bad-simple");
  check("read.undefinedValue on true(f5) -> bad-simple",
    code(function () { r.undefinedValue(d(B("f5"))); }) === "cbor/bad-simple");
  check("read.float on false(f4) -> bad-simple",
    code(function () { r.float(d(B("f4"))); }) === "cbor/bad-simple");
  check("read.float on null(f6) -> bad-simple",
    code(function () { r.float(d(B("f6"))); }) === "cbor/bad-simple");

  // read.time over a tag-1 NEGATIVE integer (major 1): the sign leg the
  // acc-time positive vector never exercises. c120 wraps -1 -> Date at -1000ms.
  check("read.time tag1-negative in range", r.time(d(B("c120"))).getTime() === -1000);
  check("read.time tag1-negative -100", r.time(d(B("c13863"))).getTime() === -100000);

  // Epoch out of the ECMAScript Date window fails closed with cbor/bad-time,
  // BEFORE the BigInt is narrowed to a Number -- both signs of the bound:
  //   positive: tag 1 wrapping 8_640_000_000_001 (one second past the ceiling)
  //   negative: tag 1 wrapping -8_640_000_000_001 (one second past the floor)
  check("read.time above the epoch ceiling -> bad-time",
    code(function () { r.time(d(B("c11b000007dba8218001"))); }) === "cbor/bad-time");
  check("read.time below the epoch floor -> bad-time",
    code(function () { r.time(d(B("c13b000007dba8218000"))); }) === "cbor/bad-time");
  // The inclusive boundary (exactly the ceiling / floor) still decodes to a
  // valid Date, so the out-of-range guard is a strict past-the-edge reject.
  check("read.time at the exact epoch ceiling is accepted",
    r.time(d(B("c11b000007dba8218000"))).getTime() === 8640000000000000);
  check("read.time at the exact epoch floor is accepted",
    r.time(d(B("c13b000007dba8217fff"))).getTime() === -8640000000000000);
}

// Advertised-surface exercise: every public primitive is reachable by its
// full documented path (also what the doc-examples surface gate checks for).
function testSurface() {
  check("pki.cbor.decode is exposed", typeof pki.cbor.decode === "function");
  check("pki.cbor.read.uint is exposed", typeof pki.cbor.read.uint === "function");
  check("pki.cbor.read.nint is exposed", typeof pki.cbor.read.nint === "function");
  check("pki.cbor.read.int is exposed", typeof pki.cbor.read.int === "function");
  check("pki.cbor.read.byteString is exposed", typeof pki.cbor.read.byteString === "function");
  check("pki.cbor.read.textString is exposed", typeof pki.cbor.read.textString === "function");
  check("pki.cbor.read.array is exposed", typeof pki.cbor.read.array === "function");
  check("pki.cbor.read.map is exposed", typeof pki.cbor.read.map === "function");
  check("pki.cbor.read.mapGet is exposed", typeof pki.cbor.read.mapGet === "function");
  check("pki.cbor.read.boolean is exposed", typeof pki.cbor.read.boolean === "function");
  check("pki.cbor.read.nullValue is exposed", typeof pki.cbor.read.nullValue === "function");
  check("pki.cbor.read.undefinedValue is exposed", typeof pki.cbor.read.undefinedValue === "function");
  check("pki.cbor.read.float is exposed", typeof pki.cbor.read.float === "function");
  check("pki.cbor.read.biguint is exposed", typeof pki.cbor.read.biguint === "function");
  check("pki.cbor.read.time is exposed", typeof pki.cbor.read.time === "function");
  check("pki.cbor.read.oid is exposed", typeof pki.cbor.read.oid === "function");
}

// read.mapGet -- the single keyed-lookup home over a decoded map's [key, value]
// pairs (a text-string key, or an integer key as COSE labels are). The map major
// type is asserted INSIDE the primitive, so a consumer's lookup can never walk a
// non-map's children as pairs (single nodes, whose pair index reads undefined).
function testMapGet() {
  var d = pki.cbor.decode;
  var r = pki.cbor.read;
  // text-keyed lookup: hit, miss (null), and no cross-type coercion
  var tm = d(B("a2616101616202"));               // { "a": 1, "b": 2 }
  check("mapGet-text-hit", r.uint(r.mapGet(tm, "b")) === 2n);
  check("mapGet-text-miss-null", r.mapGet(tm, "c") === null);
  check("mapGet-int-key-vs-text-map-null", r.mapGet(tm, 1) === null);
  // int-keyed lookup (COSE labels): positive, negative, BigInt form, miss
  var im = d(B("a3010203042005"));               // { 1: 2, 3: 4, -1: 5 }
  check("mapGet-int-hit", r.uint(r.mapGet(im, 3)) === 4n);
  check("mapGet-negint-hit", r.uint(r.mapGet(im, -1)) === 5n);
  check("mapGet-bigint-key-hit", r.uint(r.mapGet(im, 1n)) === 2n);
  check("mapGet-int-miss-null", r.mapGet(im, 2) === null);
  check("mapGet-text-key-vs-int-map-null", r.mapGet(im, "1") === null);
  check("mapGet-empty-map-null", r.mapGet(d(B("a0")), "a") === null);
  // a non-map node fails closed as the codec's wrong-major verdict, never null
  check("mapGet-on-array-unexpected-major", code(function () { r.mapGet(d(B("80")), "a"); }) === "cbor/unexpected-major");
  check("mapGet-on-uint-unexpected-major", code(function () { r.mapGet(d(B("01")), 1); }) === "cbor/unexpected-major");
  // a key that is neither a text string nor an integer is a caller bug: TypeError
  check("mapGet-float-key-typeerror", threw(function () { r.mapGet(im, 1.5); }) instanceof TypeError);
  check("mapGet-object-key-typeerror", threw(function () { r.mapGet(im, {}); }) instanceof TypeError);
  check("mapGet-unsafe-number-key-typeerror", threw(function () { r.mapGet(im, Number.MAX_SAFE_INTEGER + 1); }) instanceof TypeError);
}

// ---- build: the deterministic-CBOR encoder, byte-exact inverse of decode ----

function testBuildEncoder() {
  var b = pki.cbor.build;
  var d = pki.cbor.decode;
  var r = pki.cbor.read;
  function hex(x) { return x.toString("hex"); }
  // shortest-form heads at every argument-width boundary (the exact mirror of the non-minimal-argument reject).
  check("build-uint-0 -> 00", hex(b.uint(0n)) === "00");
  check("build-uint-23 -> 17", hex(b.uint(23n)) === "17");
  check("build-uint-24 -> 1818", hex(b.uint(24n)) === "1818");
  check("build-uint-255 -> 18ff", hex(b.uint(255n)) === "18ff");
  check("build-uint-256 -> 190100", hex(b.uint(256n)) === "190100");
  check("build-uint-65536 -> 1a00010000", hex(b.uint(65536n)) === "1a00010000");
  check("build-uint-epoch -> 1a63b0cd00", hex(b.uint(1672531200n)) === "1a63b0cd00");
  check("build-uint-2^32 -> 1b0000000100000000", hex(b.uint(4294967296n)) === "1b0000000100000000");
  check("build-int-neg1 -> 20", hex(b.int(-1n)) === "20");
  check("build-int-neg500 -> 3901f3", hex(b.int(-500n)) === "3901f3");
  check("build-byteString-33 head -> 5821", hex(b.byteString(Buffer.alloc(33))).slice(0, 4) === "5821");
  check("build-textString hi -> 626869", hex(b.textString("hi")) === "626869");
  check("build-bool-true -> f5", hex(b.boolean(true)) === "f5");
  check("build-bool-false -> f4", hex(b.boolean(false)) === "f4");
  check("build-null -> f6", hex(b.nullValue()) === "f6");
  // round-trip through the strict decoder -- decode(build.x) accepts (canonical by construction).
  check("build-uint round-trips", r.uint(d(b.uint(300000n))) === 300000n);
  check("build-int round-trips", r.int(d(b.int(-42n))) === -42n);
  check("build-byteString round-trips", Buffer.compare(r.byteString(d(b.byteString(Buffer.from([1, 2, 3])))), Buffer.from([1, 2, 3])) === 0);
  check("build-oid round-trips", r.oid(d(b.oid("2.16.840.1.101.3.4.2.1"))) === "2.16.840.1.101.3.4.2.1");
  check("build-time round-trips to the epoch second", r.time(d(b.time(new Date("2013-03-21T20:04:00Z")))).getTime() === Date.parse("2013-03-21T20:04:00Z"));
  // build.time never emits a tag-1 read.time would reject: an out-of-range epoch and an Invalid Date fail closed.
  check("build-time rejects an out-of-range epoch (matches read.time's bound)", code(function () { b.time(8640000000001n); }) === "cbor/bad-time");
  check("build-time rejects an Invalid Date", code(function () { b.time(new Date("nope")); }) === "cbor/bad-time");
  // array + map compose; map keys are sorted + deduped (decode enforces the same, so decode accepts).
  var arr = b.array([b.uint(1n), b.textString("a"), b.byteString(Buffer.from([0xaa]))]);
  check("build-array head + child count", hex(arr).slice(0, 2) === "83" && d(arr).children.length === 3);
  var m = b.map([[b.uint(2n), b.uint(20n)], [b.uint(1n), b.uint(10n)]]);
  check("build-map sorts keys bytewise (1 before 2)", d(m).children[0][0].bytes[0] === 0x01);
  // RFC 8949 sec. 4.2.1 is BYTEWISE, not the length-first sec. 4.2.3 order: for keys where the two differ
  // (a 1-byte key 0x20 that is bytewise-GREATER than a 2-byte key 0x1818), bytewise puts the 2-byte key
  // FIRST -- and the strict decoder (also bytewise) accepts the result, proving the encoder matches it.
  var divergent = b.map([[b.int(-1n), b.uint(0n)], [b.uint(24n), b.uint(1n)]]);   // keys 0x20 and 0x1818
  check("build-map uses bytewise (4.2.1), not length-first (4.2.3): 2-byte key sorts before the 1-byte key", d(divergent).children[0][0].bytes.length === 2);
  var dm = d(divergent);
  check("build-map bytewise output decodes (matches the strict decoder's ordering)", r.uint(r.mapGet(dm, 24)) === 1n && r.uint(r.mapGet(dm, -1)) === 0n);
  check("build-map round-trips both entries", r.mapGet(d(m), 1) !== null && r.mapGet(d(m), 2) !== null);
  check("build-map rejects a duplicate key", code(function () { b.map([[b.uint(1n), b.uint(1n)], [b.uint(1n), b.uint(2n)]]); }) === "cbor/duplicate-map-key");
  // tag composition + the biguint preferred-serialization guard.
  check("build-tag-2 biguint (>8 bytes)", r.biguint(d(b.biguint(1n << 100n))) === (1n << 100n));
  check("build-biguint rejects a <=8-byte value (use uint)", code(function () { b.biguint(255n); }) === "cbor/bad-argument");
  check("build-uint rejects a negative value", code(function () { b.uint(-1n); }) === "cbor/bad-argument");
  check("build-nint rejects a non-negative value", code(function () { b.nint(0n); }) === "cbor/bad-argument");
  check("build-array rejects a non-Buffer item", code(function () { b.array([5]); }) === "cbor/not-buffer");
  // a container never embeds bytes the strict decoder would reject: a nested item must be one well-formed item.
  check("build-array rejects a stray break byte item", code(function () { b.array([Buffer.from([0xff])]); }) === "cbor/bad-item");
  check("build-array rejects an item with trailing bytes", code(function () { b.array([Buffer.from([0x00, 0x00])]); }) === "cbor/bad-item");
  check("build-array rejects an indefinite-length item", code(function () { b.array([Buffer.from([0x9f, 0xff])]); }) === "cbor/bad-item");
  check("build-map rejects a malformed key item", code(function () { b.map([[Buffer.from([0xff]), b.uint(1n)]]); }) === "cbor/bad-item");
  check("build-tag rejects a malformed content item", code(function () { b.tag(2, Buffer.from([0x00, 0x00])); }) === "cbor/bad-item");
  // a container never emits output beyond the decoder depth cap (a container adds one level, so a nested
  // build past the cap fails at build time rather than emitting bytes the decoder would reject).
  check("build-array rejects output beyond the decoder depth cap", code(function () { var cur = b.uint(1n); for (var i = 0; i < 66; i++) cur = b.array([cur]); }) === "cbor/bad-item");
  var deep = b.uint(1n); for (var k = 0; k < 10; k++) deep = b.array([deep]);
  check("build-array within the depth cap decodes", d(deep).majorType === 4);
}

function run() {
  testSurface();
  testAccept();
  testMapGet();
  testRejectDecode();
  testReaderRejects();
  testReadMismatch();
  testConfig();
  testEdgeBranches();
  testBuildEncoder();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
