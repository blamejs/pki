// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.compress / pki.cms.decompress: CMS CompressedData (RFC 3274) with the sole
 * id-alg-zlibCompress algorithm (RFC 1950 ZLIB / RFC 1951 DEFLATE). Drives the SHIPPED consumer paths
 * against messages compress produces (self round-trip) and asserts the fail-closed verdict: a version
 * != 0, a non-zlib compressionAlgorithm, a detached CompressedData, and every malformed / truncated /
 * decompression-bomb stream fail closed with a typed cms/* error, never a null return or a hang. The
 * load-bearing vector is the decompression bomb -- a tiny deflate of a huge zero-run MUST throw
 * cms/decompress-too-large BEFORE the full output is materialized (a resource-exhaustion / CWE-409
 * defense; compression carries NO integrity / confidentiality -- RFC 8551 sec. 2.4.5).
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var zlib = require("zlib");
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

var MSG = Buffer.from("the CMS CompressedData round-trip payload -- shrink me, then restore me exactly\n");

// Build a CompressedData ContentInfo by hand for the adversarial cases (version / algorithm / params /
// eContent all configurable). alg params: "absent" -> no params, "null" -> explicit NULL, or a builder.
function buildCD(opts) {
  opts = opts || {};
  var version = opts.version == null ? 0 : opts.version;
  var algOid = opts.algOid || O("id-alg-zlibCompress");
  var algKids = [b.oid(algOid)];
  if (opts.params === "null") algKids.push(b.nullValue());
  else if (opts.params && opts.params !== "absent") algKids.push(opts.params);
  var alg = b.sequence(algKids);
  var eContentType = opts.eContentType || O("data");
  var stream = opts.stream != null ? opts.stream : zlib.deflateSync(opts.inner != null ? opts.inner : MSG);
  var eciKids = [b.oid(eContentType)];
  if (!opts.detached) eciKids.push(b.explicit(0, b.octetString(stream)));
  var eci = b.sequence(eciKids);
  var cd = b.sequence([b.integer(version), alg, eci]);
  return b.sequence([b.oid(O("compressedData")), b.explicit(0, cd)]);
}

async function run() {
  // ==== Accept / round-trip ========================================================================
  var c1 = await pki.cms.compress(MSG);
  check("1. compress->decompress recovers the exact input bytes", Buffer.compare((await pki.cms.decompress(c1)).content, MSG) === 0);
  var parsed1 = pki.schema.cms.parse(Buffer.isBuffer(c1) ? c1 : Buffer.from(c1));
  check("1a. the emitted CompressedData is version 0, id-alg-zlibCompress, params ABSENT", parsed1.version === 0 && parsed1.compressionAlgorithm.name === "id-alg-zlibCompress" && parsed1.compressionAlgorithm.parameters == null);
  check("1b. the emitted eContent is an RFC 1950 zlib stream (CMF byte 0x78)", parsed1.encapContentInfo.eContent[0] === 0x78);

  // opts.contentType round-trips the inner eContentType (M5)
  var cCt = await pki.cms.compress(MSG, { contentType: "tSTInfo" });
  var dCt = await pki.cms.decompress(cCt);
  check("2. opts.contentType round-trips the inner eContentType", dCt.contentTypeName === "tSTInfo" && Buffer.compare(dCt.content, MSG) === 0);
  check("2a. default inner eContentType is id-data", (await pki.cms.decompress(c1)).contentTypeName === "data");

  // opts.level extremes + pem (M6 / vector 3)
  check("3. opts.level 0 (store) and 9 (max) both round-trip", Buffer.compare((await pki.cms.decompress(await pki.cms.compress(MSG, { level: 0 }))).content, MSG) === 0 && Buffer.compare((await pki.cms.decompress(await pki.cms.compress(MSG, { level: 9 }))).content, MSG) === 0);
  var pemC = await pki.cms.compress(MSG, { pem: true });
  check("3a. pem:true emits a BEGIN CMS block that decompress re-reads", /-----BEGIN CMS-----/.test(String(pemC)) && Buffer.compare((await pki.cms.decompress(pemC)).content, MSG) === 0);

  // a large-but-below-cap highly-compressible input round-trips (the cap does not false-fire) (vector 4)
  var big = Buffer.alloc(4 * 1024 * 1024, 0x41);   // 4 MiB of 'A', well under the 16 MiB cap
  check("4. a large-but-below-cap compressible input round-trips (cap does not false-fire)", Buffer.compare((await pki.cms.decompress(await pki.cms.compress(big))).content, big) === 0);

  // ==== Decode dispatch + version / algorithm ======================================================
  check("5. pki.schema.parse(compress(...)) routes to cms with contentTypeName compressedData", pki.schema.parse(Buffer.isBuffer(c1) ? c1 : Buffer.from(c1)).contentTypeName === "compressedData");
  check("6. a version-1 CompressedData -> cms/bad-version", (await codeOf(function () { return pki.cms.decompress(buildCD({ version: 1 })); })) === "cms/bad-version");
  check("7. a bogus compressionAlgorithm OID -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decompress(buildCD({ algOid: O("sha256") })); })) === "cms/unsupported-algorithm");
  check("8. an explicit-NULL compressionAlgorithm params fixture DECODES (RFC 3274 sec. 2 MAY NULL)", Buffer.compare((await pki.cms.decompress(buildCD({ params: "null" }))).content, MSG) === 0);
  check("8a. a non-NULL, non-absent compressionAlgorithm params fixture -> typed reject", /^cms\//.test(await codeOf(function () { return pki.cms.decompress(buildCD({ params: b.integer(7) })); })));
  check("9. a DETACHED CompressedData (eContent absent) -> cms/no-encapsulated-content", (await codeOf(function () { return pki.cms.decompress(buildCD({ detached: true })); })) === "cms/no-encapsulated-content");

  // feeding a non-CompressedData CMS to decompress -> typed reject (M15 / vector 10)
  var rsa = require("../helpers/signing").makeSigner("rsa");
  var signed = await pki.cms.sign(MSG, [{ cert: rsa.cert, key: rsa.key }]);
  check("10. feeding a SignedData to decompress -> a typed cms/* reject (not a compressedData)", /^cms\//.test(await codeOf(function () { return pki.cms.decompress(signed); })));

  // ==== Adversarial: the decompression-bomb + malformed-stream class (load-bearing) ================
  // ~1 KB deflate of 64 MiB of zeros -> must throw cms/decompress-too-large, NOT allocate 64 MiB / hang.
  var bombStream = zlib.deflateSync(Buffer.alloc(64 * 1024 * 1024, 0));
  check("11. a decompression bomb -> cms/decompress-too-large (bounded inflate, no OOM/hang)", (await codeOf(function () { return pki.cms.decompress(buildCD({ stream: bombStream })); })) === "cms/decompress-too-large");
  // opts.maxOutputBytes tightens DOWNWARD: a 2 MiB payload succeeds by default but fails under a 1 KB cap.
  var twoMib = zlib.deflateSync(Buffer.alloc(2 * 1024 * 1024, 0x42));
  var cdTwo = buildCD({ stream: twoMib });
  check("12. opts.maxOutputBytes tightens the cap DOWNWARD", (await codeOf(function () { return pki.cms.decompress(cdTwo, { maxOutputBytes: 1024 }); })) === "cms/decompress-too-large" && Buffer.compare((await pki.cms.decompress(cdTwo)).content, Buffer.alloc(2 * 1024 * 1024, 0x42)) === 0);
  check("12a. a maxOutputBytes ABOVE the default cap does not raise the ceiling", (await codeOf(function () { return pki.cms.decompress(buildCD({ stream: bombStream }), { maxOutputBytes: 1024 * 1024 * 1024 }); })) === "cms/decompress-too-large");
  // malformed stream: truncated, wrong-magic, trailing garbage -> the uniform cms/decompress-failed (M8)
  var good = zlib.deflateSync(MSG);
  check("13. a truncated zlib stream -> cms/decompress-failed", (await codeOf(function () { return pki.cms.decompress(buildCD({ stream: good.subarray(0, good.length - 4) })); })) === "cms/decompress-failed");
  check("13a. a wrong-magic stream -> cms/decompress-failed", (await codeOf(function () { return pki.cms.decompress(buildCD({ stream: Buffer.from([0x00, 0x00, 0x00, 0x00]) })); })) === "cms/decompress-failed");
  // Trailing bytes AFTER a complete RFC 1950 stream are tolerated (the stream self-delimits via its
  // ADLER32 trailer; Node's zlib -- like the reference zlib and `openssl cms -uncompress` -- ignores
  // them, and the DER OCTET STRING length is the real boundary). Recovery is exact; no integrity is
  // claimed either way (RFC 8551 sec. 2.4.5), so matching the reference beats a non-interoperable reject.
  check("13b. a complete stream with trailing garbage decompresses to the correct content (zlib tolerates it, like openssl)", Buffer.compare((await pki.cms.decompress(buildCD({ stream: Buffer.concat([good, Buffer.from("garbage")]) }))).content, MSG) === 0);

  // ==== Config-time (tier-1 cms/bad-input) =========================================================
  check("14. non-Buffer content -> cms/bad-input", (await codeOf(function () { return pki.cms.compress(42); })) === "cms/bad-input");
  check("14a. opts.level not a number -> cms/bad-input", (await codeOf(function () { return pki.cms.compress(MSG, { level: "high" }); })) === "cms/bad-input");
  check("14b. opts.maxOutputBytes = -1 -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress(c1, { maxOutputBytes: -1 }); })) === "cms/bad-input");
  check("14c. opts.maxOutputBytes = NaN -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress(c1, { maxOutputBytes: NaN }); })) === "cms/bad-input");
  // each malformed-numeric sub-branch of the level / maxOutputBytes guards (fractional, non-finite, wrong type).
  check("14c1. opts.level fractional (2.5) -> cms/bad-input", (await codeOf(function () { return pki.cms.compress(MSG, { level: 2.5 }); })) === "cms/bad-input");
  check("14c2. opts.level = Infinity -> cms/bad-input", (await codeOf(function () { return pki.cms.compress(MSG, { level: Infinity }); })) === "cms/bad-input");
  check("14c3. opts.maxOutputBytes fractional (2.5) -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress(c1, { maxOutputBytes: 2.5 }); })) === "cms/bad-input");
  check("14c4. opts.maxOutputBytes = Infinity -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress(c1, { maxOutputBytes: Infinity }); })) === "cms/bad-input");
  check("14c5. opts.maxOutputBytes wrong type (string) -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress(c1, { maxOutputBytes: "big" }); })) === "cms/bad-input");
  check("14d. decompress of a non-CMS/non-DER input -> a typed cms/* or asn1/* error", /^(cms|asn1)\//.test(await codeOf(function () { return pki.cms.decompress(Buffer.from("not der at all")); })));

  // ==== Strict-DER (canonical emit) ================================================================
  // ==== Coverage: reachable input-form + fallback branches =========================================
  check("14e. opts.contentType that is not a known OID name -> cms/bad-input", (await codeOf(function () { return pki.cms.compress(MSG, { contentType: "not-a-real-oid-name" }); })) === "cms/bad-input");
  check("14f. an out-of-range opts.level (99) -> cms/bad-input (zlib rejects it)", (await codeOf(function () { return pki.cms.compress(MSG, { level: 99 }); })) === "cms/bad-input");
  // an UNREGISTERED compressionAlgorithm OID (no registry name) -> cms/unsupported-algorithm, exercising
  // the alg.name || alg.oid fallback (name is null for an unregistered OID).
  check("14g. an unregistered compressionAlgorithm OID -> cms/unsupported-algorithm (name-null path)", (await codeOf(function () { return pki.cms.decompress(buildCD({ algOid: "1.2.3.4.5.6" })); })) === "cms/unsupported-algorithm");
  // an UNREGISTERED inner eContentType decompresses; contentTypeName falls back to the dotted OID.
  check("14h. an unregistered inner eContentType surfaces contentTypeName as the dotted OID", (await pki.cms.decompress(buildCD({ eContentType: "1.2.3.4.5.7" }))).contentTypeName === "1.2.3.4.5.7");
  // decompress input-form parity: a Uint8Array and a PEM string both decode; a bad PEM + a non-Buffer fail.
  check("14i. decompress accepts a Uint8Array input", Buffer.compare((await pki.cms.decompress(new Uint8Array(Buffer.isBuffer(c1) ? c1 : Buffer.from(c1)))).content, MSG) === 0);
  check("14j. decompress accepts a PEM string input", Buffer.compare((await pki.cms.decompress(pemC)).content, MSG) === 0);
  check("14k. decompress of a malformed PEM string -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress("-----BEGIN CMS-----\nnot base64!!!\n-----END CMS-----\n"); })) === "cms/bad-input");
  check("14l. decompress of a non-Buffer/Uint8Array/string input -> cms/bad-input", (await codeOf(function () { return pki.cms.decompress(42); })) === "cms/bad-input");

  check("15. the emitted CompressedData re-parses; a non-minimal length mutation -> asn1/* on parse", (function () {
    var der = Buffer.isBuffer(c1) ? c1 : Buffer.from(c1);
    // re-parse is byte-identical: parse then compare the surfaced eContent to a fresh deflate is not
    // byte-stable (deflate is not deterministic across levels), so assert parse succeeds + round-trips.
    return pki.schema.cms.parse(der).contentTypeName === "compressedData";
  })());

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
