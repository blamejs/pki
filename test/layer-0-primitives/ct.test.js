// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.ct (RFC 6962 Certificate Transparency SCT lists). The SCT
 * payload is TLS presentation language (positional, tag-less, big-endian),
 * NOT ASN.1/DER, so the parser owns a bounded TLS-struct reader; the only DER
 * surface is the §3.3 inner OCTET-STRING peel. Spec-first conformance vectors,
 * RED-first: every valid list decodes to the documented per-SCT shape; every
 * malformed shape is rejected fail-closed with a typed ct/* (or leaf asn1/*)
 * error. reconstructSignedData rebuilds the exact digitally-signed preimage a
 * verifier hashes — golden-byte pinned, never re-verified here.
 *
 * RED baseline: pki.ct.* is undefined until the module lands, so every vector
 * throws — the suite drives the build to GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

// ---- TLS-encoding fixture builders -----------------------------------
function u16(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }

// A v1 SerializedSCT body. Every field overridable so a vector can pin one defect.
function sctBody(o) {
  o = o || {};
  var logId = o.logId || Buffer.alloc(32, 0xAB);
  var ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(o.ts != null ? o.ts : 1700000000000n);
  var ext = o.ext || Buffer.alloc(0);
  var sig = o.sig || Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
  var extLen = o.extLen != null ? o.extLen : ext.length;
  var sigLen = o.sigLen != null ? o.sigLen : sig.length;
  var parts = [
    Buffer.from([o.version != null ? o.version : 0]),
    logId, ts,
    u16(extLen), ext,
    Buffer.from([o.hash != null ? o.hash : 4]),
    Buffer.from([o.sigAlg != null ? o.sigAlg : 3]),
    u16(sigLen), sig,
  ];
  return Buffer.concat(parts);
}
function serialized(body, declaredLen) {
  return Buffer.concat([u16(declaredLen != null ? declaredLen : body.length), body]);
}
function listBlob(sers, declaredLen) {
  var all = Buffer.concat(sers);
  return Buffer.concat([u16(declaredLen != null ? declaredLen : all.length), all]);
}
// The RFC 6962 §3.3 double wrap: the extension VALUE is a DER OCTET STRING whose
// content is the TLS list. `x509.parse` surfaces this inner-OCTET-STRING content.
function wrapInner(tlsBlob) { return b.octetString(tlsBlob); }
function extValueOf(sers) { return wrapInner(listBlob(sers)); }

function code(fn) {
  try { fn(); return "NO-THROW"; }
  catch (e) { return e && e.code ? e.code : ("RAW:" + (e && e.message)); }
}

// ---- ACCEPT ----------------------------------------------------------
function testAccept() {
  var one = pki.ct.parseSctList(extValueOf([serialized(sctBody({}))]));
  check("1. single SCT list -> one SCT", one.scts.length === 1 && one.unknownScts.length === 0);
  var s = one.scts[0];
  check("2. version is v1 (0)", s.version === 0);
  check("3. logId is a 32-byte Buffer", Buffer.isBuffer(s.logId) && s.logId.length === 32);
  check("4. logIdHex matches logId", s.logIdHex === s.logId.toString("hex") && s.logIdHex === "ab".repeat(32));
  check("5. timestamp is the exact BigInt", typeof s.timestamp === "bigint" && s.timestamp === 1700000000000n);
  check("6. timestampMs is the safe Number", s.timestampMs === 1700000000000);
  check("7. timestampDate is a Date", s.timestampDate instanceof Date && s.timestampDate.getTime() === 1700000000000);
  check("8. hashAlg named sha256", s.hashAlg === 4 && s.signatureAlgorithm.hashName === "sha256");
  check("9. sigAlg named ecdsa", s.sigAlg === 3 && s.signatureAlgorithm.signatureName === "ecdsa");
  check("10. signature surfaced raw", Buffer.isBuffer(s.signature) && s.signature.equals(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])));
  check("11. empty extensions surfaced as empty Buffer", Buffer.isBuffer(s.extensions) && s.extensions.length === 0);
  check("12. rawSct is the full SerializedSCT body", Buffer.isBuffer(s.rawSct) && s.rawSct.equals(sctBody({})));

  // two SCTs, order + independence
  var two = pki.ct.parseSctList(extValueOf([
    serialized(sctBody({ ts: 1n, hash: 4, sigAlg: 1 })),
    serialized(sctBody({ ts: 2n, hash: 5, sigAlg: 3 })),
  ]));
  check("13. two SCTs preserve order", two.scts.length === 2 && two.scts[0].timestamp === 1n && two.scts[1].timestamp === 2n);
  check("14. per-SCT algorithm independent", two.scts[0].signatureAlgorithm.signatureName === "rsa" && two.scts[1].signatureAlgorithm.hashName === "sha384");

  // non-empty extensions surfaced byte-identical
  var extBytes = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
  var we = pki.ct.parseSctList(extValueOf([serialized(sctBody({ ext: extBytes }))]));
  check("15. non-empty extensions surfaced raw", we.scts[0].extensions.equals(extBytes));

  // unknown hash/sig code points -> numeric, null name, NOT rejected
  var uk = pki.ct.parseSctList(extValueOf([serialized(sctBody({ hash: 99, sigAlg: 88 }))]));
  check("16. unknown hash code -> numeric + null name", uk.scts[0].hashAlg === 99 && uk.scts[0].signatureAlgorithm.hashName === null);
  check("17. unknown sig code -> numeric + null name", uk.scts[0].sigAlg === 88 && uk.scts[0].signatureAlgorithm.signatureName === null);

  // timestamp above 2^53 -> exact BigInt, timestampMs null
  var big = 9007199254740993n; // 2^53 + 1
  var bg = pki.ct.parseSctList(extValueOf([serialized(sctBody({ ts: big }))]));
  check("18. timestamp > 2^53 stays exact BigInt", bg.scts[0].timestamp === big);
  check("19. timestampMs null above safe range", bg.scts[0].timestampMs === null);

  // minimum viable SCT (47 bytes: empty ext + empty sig)
  var minBody = sctBody({ ext: Buffer.alloc(0), sig: Buffer.alloc(0) });
  check("20. minimum 47-byte SCT accepted", minBody.length === 47 && pki.ct.parseSctList(extValueOf([serialized(minBody)])).scts.length === 1);
}

// ---- REJECT: the RFC 6962 §3.3 inner DER wrap ------------------------
function testInnerWrap() {
  check("21. non-Buffer input -> ct/bad-input", code(function () { pki.ct.parseSctList(42); }) === "ct/bad-input");
  // a detached-backed Buffer (backing ArrayBuffer transferred away) reads as
  // zero-length: it must fail closed typed here, not slip through as empty bytes.
  check("21b. detached-backed Buffer -> ct/bad-input", code(function () {
    var ab = new ArrayBuffer(4); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.ct.parseSctList(b);
  }) === "ct/bad-input");
  // a NULL, not an OCTET STRING
  check("22. inner not an OCTET STRING -> ct/bad-der", code(function () { pki.ct.parseSctList(Buffer.from([0x05, 0x00])); }) === "ct/bad-der");
  // raw TLS bytes (no DER wrap at all)
  check("23. un-wrapped TLS bytes -> ct/bad-der", code(function () { pki.ct.parseSctList(listBlob([serialized(sctBody({}))])); }) === "ct/bad-der");
  // a constructed OCTET STRING (indefinite-form / BER) is rejected by the strict codec
  var constructed = Buffer.concat([Buffer.from([0x24, 0x02, 0x04, 0x00])]); // constructed OCTET STRING, malformed for DER
  check("24. constructed OCTET STRING -> ct/bad-der", code(function () { pki.ct.parseSctList(constructed); }) === "ct/bad-der");
  // trailing bytes after a valid inner OCTET STRING
  var good = wrapInner(listBlob([serialized(sctBody({}))]));
  check("25. trailing bytes after inner OCTET STRING -> ct/bad-der", code(function () { pki.ct.parseSctList(Buffer.concat([good, Buffer.from([0x00])])); }) === "ct/bad-der");
  // the ct/bad-der carries the underlying asn1/* fault as .cause
  var causeCode;
  try { pki.ct.parseSctList(Buffer.from([0x05, 0x00])); }
  catch (e) { causeCode = e.cause && e.cause.code; }
  check("26. ct/bad-der carries the asn1/* cause", typeof causeCode === "string" && causeCode.indexOf("asn1/") === 0);
}

// ---- REJECT: the outer TLS list framing ------------------------------
function testListFraming() {
  // empty list (declared length 0)
  check("27. empty list -> ct/empty-list", code(function () { pki.ct.parseSctList(wrapInner(Buffer.from([0x00, 0x00]))); }) === "ct/empty-list");
  // declared list length shorter than the bytes present (trailing garbage)
  var blob = listBlob([serialized(sctBody({}))]);
  check("28. one trailing byte past the list -> ct/bad-list", code(function () { pki.ct.parseSctList(wrapInner(Buffer.concat([blob, Buffer.from([0xFF])]))); }) === "ct/bad-list");
  // declared list length longer than the bytes present
  var over = Buffer.concat([u16(0xFFFF), Buffer.concat([serialized(sctBody({}))])]);
  check("29. declared list length overruns -> ct/bad-list", code(function () { pki.ct.parseSctList(wrapInner(over)); }) === "ct/bad-list");
  // blob too short even for the 2-byte list header
  check("30. one-byte blob -> ct/bad-list", code(function () { pki.ct.parseSctList(wrapInner(Buffer.from([0x00]))); }) === "ct/bad-list");
  // a SerializedSCT with declared length 0
  var emptyElem = Buffer.concat([u16(0)]); // one element, length prefix 0
  var lst = Buffer.concat([u16(emptyElem.length), emptyElem]);
  check("31. zero-length SerializedSCT -> ct/sct-empty", code(function () { pki.ct.parseSctList(wrapInner(lst)); }) === "ct/sct-empty");
  // a dangling partial element (1 byte where a 2-byte length prefix is required)
  var body = sctBody({});
  var dangling = Buffer.concat([serialized(body), Buffer.from([0x00])]);
  var lst2 = Buffer.concat([u16(dangling.length), dangling]);
  check("32. dangling partial element -> ct/list-trailing-bytes", code(function () { pki.ct.parseSctList(wrapInner(lst2)); }) === "ct/list-trailing-bytes");
  // an element length that overruns the list region
  var lyElem = Buffer.concat([u16(body.length + 50), body]); // element claims 50 more than present
  var lst3 = Buffer.concat([u16(lyElem.length), lyElem]);
  check("33. element length overruns the list -> ct/list-trailing-bytes", code(function () { pki.ct.parseSctList(wrapInner(lst3)); }) === "ct/list-trailing-bytes");
}

// ---- Forward compat: an unknown SCT version is preserved, not rejected ----
function testUnknownVersion() {
  // RFC 6962 §3.3: a SerializedSCT whose version this parser does not define is
  // preserved opaque in unknownScts (not a hard-reject of the whole list).
  var uv = pki.ct.parseSctList(extValueOf([serialized(sctBody({ version: 1 }))]));
  check("34. unknown version preserved opaque, not rejected", uv.scts.length === 0 && uv.unknownScts.length === 1 && uv.unknownScts[0].version === 1);
  check("34b. unknown SCT rawSct preserved byte-exact", uv.unknownScts[0].rawSct.equals(sctBody({ version: 1 })));
  // a mixed list: one v1 (fully decoded) + one unknown (opaque), order preserved
  var mixed = pki.ct.parseSctList(extValueOf([
    serialized(sctBody({ ts: 7n })),
    serialized(sctBody({ version: 2, ext: Buffer.alloc(0), sig: Buffer.alloc(0) })),
  ]));
  check("34c. mixed list splits known / unknown", mixed.scts.length === 1 && mixed.scts[0].timestamp === 7n && mixed.unknownScts.length === 1 && mixed.unknownScts[0].version === 2);
  // an unknown SCT below the v1 47-byte floor is still preserved (the floor is v1-only)
  var su = pki.ct.parseSctList(extValueOf([serialized(Buffer.from([9]))]));
  check("34d. sub-47 unknown SCT preserved (v1 floor is version-specific)", su.unknownScts.length === 1 && su.unknownScts[0].version === 9 && su.unknownScts[0].rawSct.length === 1);
}

// ---- REJECT: the SerializedSCT body ----------------------------------
function testSctBody() {
  // SCT shorter than the 47-byte floor
  var shortBody = sctBody({ ext: Buffer.alloc(0), sig: Buffer.alloc(0) }).subarray(0, 46);
  check("35. sub-47-byte SCT -> ct/sct-too-short", code(function () { pki.ct.parseSctList(extValueOf([serialized(shortBody)])); }) === "ct/sct-too-short");
  // extensions length lies (overruns the SCT bound)
  var extLie = sctBody({ ext: Buffer.alloc(0), extLen: 100, sig: Buffer.alloc(0) });
  check("36. extensions length overruns -> ct/ext-overrun", code(function () { pki.ct.parseSctList(extValueOf([serialized(extLie)])); }) === "ct/ext-overrun");
  // signature length lies (overruns the SCT bound)
  var sigLie = sctBody({ ext: Buffer.alloc(0), sig: Buffer.alloc(0), sigLen: 100 });
  check("37. signature length overruns -> ct/sig-overrun", code(function () { pki.ct.parseSctList(extValueOf([serialized(sigLie)])); }) === "ct/sig-overrun");
  // trailing bytes inside the SerializedSCT after the signature (declared length too big)
  var padded = Buffer.concat([sctBody({ ext: Buffer.alloc(0), sig: Buffer.alloc(0) }), Buffer.from([0x00, 0x00])]);
  check("38. trailing bytes inside SCT -> ct/sct-trailing-bytes", code(function () { pki.ct.parseSctList(extValueOf([serialized(padded)])); }) === "ct/sct-trailing-bytes");
  // truncation partway through a field (47-byte SCT whose ext length consumes room needed for sigAlg)
  var trunc = sctBody({ ext: Buffer.from([1, 2, 3]), sig: Buffer.alloc(0) }).subarray(0, 47);
  check("39. field truncation -> ct/truncated", code(function () { pki.ct.parseSctList(extValueOf([serialized(trunc, trunc.length)])); }) === "ct/truncated");
}

// ---- REJECT: DoS caps ------------------------------------------------
function testCaps() {
  // count cap: 257 minimal SCTs -> ct/too-many-scts
  var many = [];
  var minBody = sctBody({ ext: Buffer.alloc(0), sig: Buffer.alloc(0) });
  for (var i = 0; i < 257; i++) many.push(serialized(minBody));
  check("40. > 256 SCTs -> ct/too-many-scts", code(function () { pki.ct.parseSctList(extValueOf(many)); }) === "ct/too-many-scts");
  // byte cap: an inner blob larger than SCT_MAX_BYTES (64 KiB) -> ct/too-large.
  // The 2-byte outer length caps a well-formed list at 65535; the cap is asserted
  // on the peeled blob length before iteration, so a 65535-byte list is under it
  // and a >64KiB wrap is refused. Build a blob just over the cap.
  var cap = pki.C.LIMITS.SCT_MAX_BYTES;
  var filler = Buffer.alloc(cap + 10, 0);
  check("41. inner blob over the byte cap -> ct/too-large", code(function () { pki.ct.parseSctList(wrapInner(filler)); }) === "ct/too-large");
  // A conforming MAX-size list: the outer sct_list vector is <1..2^16-1>, so the
  // body is up to 65535 bytes and the full blob (2-byte length prefix + body) is
  // 65537. The byte cap MUST include that prefix, else the largest legal list is
  // rejected as too-large. One SCT with its signature padded fills the body exactly.
  var padSig = Buffer.alloc(65535 - 2 - 47, 0x5A);          // 65535 body - 2 SCT-len - 47 min = 65486
  var maxBody = sctBody({ ext: Buffer.alloc(0), sig: padSig });
  var maxBlob = extValueOf([serialized(maxBody)]);
  var parsedMax = pki.ct.parseSctList(maxBlob);
  check("41b. maximal well-formed list (65537-byte blob) is accepted, not too-large", parsedMax.scts.length === 1 && parsedMax.scts[0].signature.length === padSig.length);
}

// ---- reconstructSignedData: the digitally-signed preimage ------------
function testReconstruct() {
  var s = pki.ct.parseSctList(extValueOf([serialized(sctBody({ ts: 1700000000000n }))])).scts[0];
  var leaf = Buffer.alloc(120, 0x11);

  // x509 arm golden bytes: version(00) sigType(00) ts(8) entryType(0000) u24(len) cert u16(0)
  var pre = pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, s);
  var expTs = Buffer.alloc(8); expTs.writeBigUInt64BE(1700000000000n);
  var expected = Buffer.concat([
    Buffer.from([0x00, 0x00]), expTs, Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00, 0x78]), leaf, Buffer.from([0x00, 0x00]),
  ]);
  check("42. x509 preimage is byte-exact", pre.equals(expected));

  // precert arm: ... entryType(0001) issuerKeyHash(32) u24(tbsLen) tbs u16(0)
  var tbs = Buffer.alloc(90, 0x22);
  var ikh = Buffer.alloc(32, 0x33);
  var pre2 = pki.ct.reconstructSignedData({ entryType: 1, tbsCertificate: tbs, issuerKeyHash: ikh }, s);
  var expected2 = Buffer.concat([
    Buffer.from([0x00, 0x00]), expTs, Buffer.from([0x00, 0x01]),
    ikh, Buffer.from([0x00, 0x00, 0x5A]), tbs, Buffer.from([0x00, 0x00]),
  ]);
  check("43. precert preimage is byte-exact (uses precert_entry 1)", pre2.equals(expected2));

  // extensions reused byte-for-byte (never re-encoded)
  var extBytes = Buffer.from([0xAA, 0xBB]);
  var se = pki.ct.parseSctList(extValueOf([serialized(sctBody({ ext: extBytes }))])).scts[0];
  var preE = pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, se);
  check("44. extensions reused byte-identical in preimage", preE.subarray(preE.length - 4).equals(Buffer.concat([u16(2), extBytes])));

  // rejects
  check("45. bad entryType -> ct/bad-entry-type", code(function () { pki.ct.reconstructSignedData({ entryType: 2 }, s); }) === "ct/bad-entry-type");
  check("46. non-32 issuerKeyHash -> ct/bad-issuer-key-hash", code(function () { pki.ct.reconstructSignedData({ entryType: 1, tbsCertificate: Buffer.alloc(10), issuerKeyHash: Buffer.alloc(31) }, s); }) === "ct/bad-issuer-key-hash");
  check("47. empty leafCert -> ct/bad-tbs-length", code(function () { pki.ct.reconstructSignedData({ entryType: 0, leafCert: Buffer.alloc(0) }, s); }) === "ct/bad-tbs-length");
  check("48. non-Buffer leafCert -> ct/bad-input", code(function () { pki.ct.reconstructSignedData({ entryType: 0, leafCert: "nope" }, s); }) === "ct/bad-input");
  // an opaque unknownScts entry has no decoded body to sign over -> ct/bad-input
  var uk = pki.ct.parseSctList(extValueOf([serialized(sctBody({ version: 3 }))])).unknownScts[0];
  check("48b. unknown SCT to reconstruct -> ct/bad-input", code(function () { pki.ct.reconstructSignedData({ entryType: 0, leafCert: Buffer.alloc(10) }, uk); }) === "ct/bad-input");

  // RFC 6962 §3.2: the timestamp is a uint64. A hand-built sct outside
  // 0..2^64-1 must be refused typed, never escape as a raw Node RangeError
  // from the fixed-width Buffer write.
  var tsOver = Object.assign({}, s, { timestamp: 1n << 64n });
  check("48c. timestamp 2^64 -> ct/bad-input", code(function () { pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, tsOver); }) === "ct/bad-input");
  var tsNeg = Object.assign({}, s, { timestamp: -1n });
  check("48d. negative timestamp -> ct/bad-input", code(function () { pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, tsNeg); }) === "ct/bad-input");
  // control: the uint64 maximum is representable.
  var tsMax = Object.assign({}, s, { timestamp: 0xffffffffffffffffn });
  var preTsMax = pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, tsMax);
  check("48e. control: timestamp 2^64-1 emitted exactly", preTsMax.subarray(2, 10).equals(Buffer.alloc(8, 0xff)));

  // RFC 6962 §3.2: CtExtensions is opaque<0..2^16-1>. A hand-built sct whose
  // extensions exceed 65535 bytes cannot be length-prefixed (the prefix would
  // silently truncate mod 65536, an internally inconsistent preimage) -> refuse.
  var extOver = Object.assign({}, s, { extensions: Buffer.alloc(65536, 0x41) });
  check("48f. extensions > 65535 bytes -> ct/bad-extensions", code(function () { pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, extOver); }) === "ct/bad-extensions");
  // control: a 65535-byte extensions value is representable with an exact prefix.
  var extMax = Object.assign({}, s, { extensions: Buffer.alloc(65535, 0x42) });
  var preExtMax = pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, extMax);
  check("48g. control: 65535-byte extensions emitted with an exact prefix",
    preExtMax.subarray(preExtMax.length - 65537, preExtMax.length - 65535).equals(Buffer.from([0xff, 0xff])) &&
    preExtMax.subarray(preExtMax.length - 65535).equals(extMax.extensions));
}

// ---- extension-decoder registry integration (schema-pkix byOid) ------
var pkix = require("../../lib/schema-pkix");
function testExtensionDecoderRegistry() {
  var NS = pkix.makeNS("x509", pki.errors.CertificateError, pki.oid);
  var byOid = pkix.certExtensionDecoders(NS).byOid;
  var sctOid = pki.oid.byName("signedCertificateTimestampList");
  var poisonOid = pki.oid.byName("precertificatePoison");

  // the SCT-list decoder routes to pki.ct.parseSctList (same result)
  var extValue = extValueOf([serialized(sctBody({}))]);
  var viaRegistry = byOid[sctOid](extValue);
  check("49. SCT-list extension decoder returns the parsed list", viaRegistry.scts.length === 1 && viaRegistry.scts[0].version === 0);
  // the registry contract is <prefix>/bad-*: the CT module's ct/* fault is wrapped
  // as x509/bad-extension-value and carried as .cause, not leaked at the registry tier.
  var regErr;
  try { byOid[sctOid](Buffer.from([0x05, 0x00])); } catch (e) { regErr = e; }
  check("50. SCT-list decoder wraps as x509/bad-extension-value", regErr && regErr.code === "x509/bad-extension-value");
  check("50b. wrapped decoder preserves the ct/* fault as .cause", regErr && regErr.cause && regErr.cause.code === "ct/bad-der");

  // the poison decoder: exactly ASN.1 NULL (05 00)
  var poisonVal = b.nullValue ? b.nullValue() : Buffer.from([0x05, 0x00]);
  check("51. poison NULL value accepted", byOid[poisonOid](poisonVal).poison === true);
  check("52. poison non-NULL value -> x509/bad-extension-value", code(function () { byOid[poisonOid](b.integer(1n)); }) === "x509/bad-extension-value");
  check("53. poison NULL with trailing bytes -> x509/bad-extension-value", code(function () { byOid[poisonOid](Buffer.from([0x05, 0x00, 0x00])); }) === "x509/bad-extension-value");
  check("54. poison non-empty NULL content -> x509/bad-extension-value", code(function () { byOid[poisonOid](Buffer.from([0x05, 0x01, 0x00])); }) === "x509/bad-extension-value");
}

// ---- orchestrator exclusion: ct is NOT a pki.schema.parse format ------
function testNotASchemaFormat() {
  // An SCT list has no self-describing DER root (its only shape is a bare OCTET
  // STRING), so it is deliberately NOT registered with the format orchestrator.
  check("55. pki.schema.all() does not contain ct", pki.schema.all().indexOf("ct") === -1);
  // a raw SCT-list DER (a bare OCTET STRING) routes to no format, fail-closed.
  var raw = extValueOf([serialized(sctBody({}))]);
  check("56. pki.schema.parse of a raw SCT-list DER -> schema/unknown-format", code(function () { pki.schema.parse(raw); }) === "schema/unknown-format");
}

// ---- known-answer vector: a real, independently produced SCT ----------
// A production Let's Encrypt leaf certificate (CN valid-isrgrootx1.letsencrypt.org)
// carrying two embedded v1 SCTs. The expected logId / timestamp / extensions
// values below are pinned from an independent decode of the same certificate
// (OpenSSL's SCT text output), so a mis-derivation of the RFC 6962 TLS layout
// shared by the parser and this file's fixture builders cannot pass. Driven
// end-to-end through the documented operator flow: pki.schema.x509.parse ->
// find the SCT extension -> pki.ct.parseSctList(ext.value).
var REAL_CT_LEAF_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "MIIFGzCCBAOgAwIBAgISBScwL3h0YjfOIWf42EnShaPZMA0GCSqGSIb3DQEBCwUA",
  "MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD",
  "EwNZUjIwHhcNMjYwNzAxMTczODMzWhcNMjYwOTI5MTczODMyWjArMSkwJwYDVQQD",
  "EyB2YWxpZC1pc3Jncm9vdHgxLmxldHNlbmNyeXB0Lm9yZzCCASIwDQYJKoZIhvcN",
  "AQEBBQADggEPADCCAQoCggEBAJ0zYXLkgDHFg/2R3n2Elz69RSKjvuNKTIMZmygM",
  "JHmwFOt+4IA8WW0+3mm3xQwocdL1qpDdsyklPHLbyloK6XVDAIPYdrP97BK0rZ9Q",
  "W531xEhOj89JbMQK/IzvJvnS1EADHFn83qHex/SpXsb9WAfz+NA1v9Of8hxAACs9",
  "2ab5De+UpTj6PvdgKS9iVu1YkrM7WUZvSqb3H67pjHa0taTET+FrMNVpJL41NDkV",
  "T5FzM52X2AAwC90jfbWfXoRsUXPsHqoBBCPBuw15JD9tj6iradBTb3xILoqhaUTi",
  "xAM2wRyj7RQSp4WkzN2U6db8Z7WGmQBq0Doo+usAOSXMaSkCAwEAAaOCAi8wggIr",
  "MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8E",
  "AjAAMB0GA1UdDgQWBBS9xWPTtqCiJfWLHyC7m9quhvU3TzAfBgNVHSMEGDAWgBRA",
  "FS0mee0yIJ7fmnId1jIfgQyBDDAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAKG",
  "F2h0dHA6Ly95cjIuaS5sZW5jci5vcmcvMCsGA1UdEQQkMCKCIHZhbGlkLWlzcmdy",
  "b290eDEubGV0c2VuY3J5cHQub3JnMBMGA1UdIAQMMAowCAYGZ4EMAQIBMC4GA1Ud",
  "HwQnMCUwI6AhoB+GHWh0dHA6Ly95cjIuYy5sZW5jci5vcmcvOTAuY3JsMIIBDQYK",
  "KwYBBAHWeQIEAgSB/gSB+wD5AHcAlE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9",
  "VTcuGdgAAAGfHvhnOgAABAMASDBGAiEApph0bB2+jablka/lzTH8QVGibWr3JrfV",
  "Ab7XExHY6BYCIQDAkOXIjF03IIstuFyAubypsM5xj4Vd1BK2Ag1prUJaZgB+AKgm",
  "y+MKxjUSRlM/4GXxTxnZbhkIE8Qd2W15ALMSPFUnAAABnx74aZ8ACAAABQAR7Pcd",
  "BAMARzBFAiAZH5kB9nPBERQUbQziMFS7SvOQMcmJxQtNMtdSok9WEQIhAKh+QYmF",
  "BCavMZNF2gkyrLX91m1d+IJwPKLPnjXIUC6xMA0GCSqGSIb3DQEBCwUAA4IBAQAA",
  "YXvpP0EfWxeSptnjn79DByvoPT1wziN/EjIgAuaAUTUf0L+MNLgGg4gAxIAb9m2u",
  "Fwj/zL5w+qIuSfPPvVq6LMnJQUibBggMCJU3o/wloWqLzNFYKeIRhoHlZAeGpYKP",
  "9FxY2fsEeLBXdg0La44+LS78I3A44mxxoCNmtJxj8i4EdjfdpSoYTQ2cGZtc9qOY",
  "cMvsoc5MtryNh0kGp2FbcqSNC6bGUUTdO37MEXIz2kM8P0cnxvLSrpuXQb7ui5QO",
  "KBlzKwJL9TRfIxtUawg+im+HTgEU4Am8NM9x72gZxPw8wh5H9BVypXEMnOV8DpCf",
  "00aajhuGyvSbZcOB/Wdf",
  "-----END CERTIFICATE-----",
].join("\n");

function testKnownAnswerVector() {
  var cert = pki.schema.x509.parse(REAL_CT_LEAF_PEM);
  var sctOid = pki.oid.byName("signedCertificateTimestampList");
  var ext = cert.extensions.filter(function (e) { return e.oid === sctOid; })[0];
  check("57. real leaf carries the SCT-list extension", !!ext && ext.critical === false);
  var list = pki.ct.parseSctList(ext.value);
  check("58. real leaf decodes two v1 SCTs, none unknown", list.scts.length === 2 && list.unknownScts.length === 0);
  var s0 = list.scts[0], s1 = list.scts[1];
  check("59. SCT[0] logId matches the published log key id", s0.logIdHex === "944e4387faecc1ef81f3192426a8186501c7d35f3802013f72677d55372e19d8");
  check("60. SCT[0] exact timestamp", s0.timestamp === 1782931023674n && s0.timestampDate.toISOString() === "2026-07-01T18:37:03.674Z");
  check("61. SCT[0] empty extensions + ecdsa/sha256", s0.extensions.length === 0 && s0.signatureAlgorithm.hashName === "sha256" && s0.signatureAlgorithm.signatureName === "ecdsa");
  check("62. SCT[0] DER ECDSA signature surfaced raw", s0.signature.length === 72 && s0.signature[0] === 0x30);
  check("63. SCT[1] logId matches the published log key id", s1.logIdHex === "a826cbe30ac6351246533fe065f14f19d96e190813c41dd96d7900b3123c5527");
  check("64. SCT[1] exact timestamp", s1.timestamp === 1782931024287n && s1.timestampDate.toISOString() === "2026-07-01T18:37:04.287Z");
  check("65. SCT[1] non-empty extensions surfaced byte-exact", s1.extensions.toString("hex") === "0000050011ecf71d");
  check("66. SCT[1] DER ECDSA signature surfaced raw", s1.signature.length === 71 && s1.signature[0] === 0x30);
}

// ---- verifySct: verify an SCT signature against a log key (RFC 6962 sec. 3.2) ----
// Round-trip KAT: sign a reconstructed preimage with a generated log key (real node crypto),
// then assert verifySct accepts it and rejects every corruption -- the log-signature-forgery
// defense the SCT surface exists for.
var crypto = require("crypto");
async function vres(fn) { try { return await fn(); } catch (e) { return (e && e.code) || String(e); } }
async function testVerifySct() {
  var certDer = pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE");
  var entry = { entryType: 0, leafCert: certDer };
  function sctFor(hashName, hash, signatureName, signature, signature2) {
    return { version: 0, timestamp: 1700000000000n, signatureAlgorithm: { hash: hash, hashName: hashName, signature: signature2, signatureName: signatureName }, signature: signature, extensions: Buffer.alloc(0) };
  }
  async function signedSct(privKey, hashName, hash, sigName, sigCode) {
    var sct = sctFor(hashName, hash, sigName, null, sigCode);
    sct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData(entry, sct), privKey);
    return sct;
  }
  // ECDSA (P-256) round-trip.
  var ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecSpki = ec.publicKey.export({ format: "der", type: "spki" });
  var ecSct = await signedSct(ec.privateKey, "sha256", 4, "ecdsa", 3);
  check("67. verifySct accepts a valid ECDSA SCT", (await vres(function () { return pki.ct.verifySct(entry, ecSct, ecSpki); })) === true);
  var corrupt = Buffer.from(ecSct.signature); corrupt[corrupt.length - 1] ^= 0xff;
  check("68. verifySct rejects a corrupted signature (false, not throw)", (await vres(function () { return pki.ct.verifySct(entry, Object.assign({}, ecSct, { signature: corrupt }), ecSpki); })) === false);
  var ec2 = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  check("69. verifySct rejects the wrong log key", (await vres(function () { return pki.ct.verifySct(entry, ecSct, ec2.publicKey.export({ format: "der", type: "spki" })); })) === false);
  // A different entry than the one signed reconstructs a different preimage -> reject.
  check("70. verifySct rejects an SCT bound to a different entry", (await vres(function () { return pki.ct.verifySct({ entryType: 1, tbsCertificate: certDer, issuerKeyHash: Buffer.alloc(32, 7) }, ecSct, ecSpki); })) === false);

  // RSA round-trip (precert entry type 1).
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaEntry = { entryType: 1, tbsCertificate: certDer, issuerKeyHash: Buffer.alloc(32, 9) };
  var rsaSct = sctFor("sha256", 4, "rsa", null, 1);
  rsaSct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData(rsaEntry, rsaSct), rsa.privateKey);
  var rsaSpki = rsa.publicKey.export({ format: "der", type: "spki" });
  check("71. verifySct accepts a valid RSA SCT over a precert entry", (await vres(function () { return pki.ct.verifySct(rsaEntry, rsaSct, rsaSpki); })) === true);

  // Structural fail-closed vectors (throw, not a false verdict).
  // A NON-MINIMAL DER ECDSA-Sig-Value -- SEQUENCE { r = INTEGER 00 01 (redundant sign octet),
  // s = INTEGER 01 } -- is rejected by the shared validator-sig conformance gate before verify.
  var nonMinimal = Buffer.from([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]);
  check("72. verifySct rejects a non-minimal DER ECDSA signature (ct/bad-signature)", (await vres(function () { return pki.ct.verifySct(entry, Object.assign({}, ecSct, { signature: nonMinimal }), ecSpki); })) === "ct/bad-signature");
  // An SCT declaring ECDSA but a log key that is RSA -> typed bad-input, not a silent false.
  check("73. verifySct rejects an ECDSA SCT against an RSA log key (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, rsaSpki); })) === "ct/bad-input");
  // An unsupported hash / signature algorithm -> typed unsupported-algorithm.
  check("74. verifySct rejects an unsupported hash algorithm", (await vres(function () { return pki.ct.verifySct(entry, Object.assign({}, ecSct, { signatureAlgorithm: { hash: 2, hashName: "sha1", signature: 3, signatureName: "ecdsa" } }), ecSpki); })) === "ct/unsupported-algorithm");
  check("75. verifySct rejects an unsupported signature algorithm", (await vres(function () { return pki.ct.verifySct(entry, Object.assign({}, ecSct, { signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 2, signatureName: "dsa" } }), ecSpki); })) === "ct/unsupported-algorithm");
  // A malformed log key (not an SPKI) -> typed bad-input.
  check("76. verifySct rejects an undecodable log public key (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, Buffer.from([0x30, 0x82, 0xff, 0xff])); })) === "ct/bad-input");
  check("76b. verifySct rejects a decodable non-SPKI log key (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, b.integer(5n)); })) === "ct/bad-input");
  // An EC log key SPKI missing its named-curve parameters, or carrying non-OID params.
  var ecPub = pki.oid.byName("ecPublicKey"), dummyPoint = b.bitString(Buffer.alloc(65, 4), 0);
  var noParams = b.sequence([b.sequence([b.oid(ecPub)]), dummyPoint]);
  check("77. verifySct rejects an EC log key missing curve params (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, noParams); })) === "ct/bad-input");
  var badParams = b.sequence([b.sequence([b.oid(ecPub), b.integer(5n)]), dummyPoint]);
  check("78. verifySct rejects an EC log key with non-OID curve params (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, badParams); })) === "ct/bad-input");
  // An EC log key on a non-approved curve (secp256k1) -> unsupported.
  var k256 = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" }).publicKey.export({ format: "der", type: "spki" });
  check("79. verifySct rejects an unsupported log EC curve (ct/unsupported-algorithm)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, k256); })) === "ct/unsupported-algorithm");
  // An SCT declaring RSA but an EC log key -> bad-input.
  check("80. verifySct rejects an RSA SCT against an EC log key (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(rsaEntry, rsaSct, ecSpki); })) === "ct/bad-input");
  // An SCT with no signatureAlgorithm block -> the hash check fails unsupported.
  check("81. verifySct rejects an SCT with no signatureAlgorithm (ct/unsupported-algorithm)", (await vres(function () { return pki.ct.verifySct(entry, { version: 0, timestamp: 1700000000000n, extensions: Buffer.alloc(0) }, ecSpki); })) === "ct/unsupported-algorithm");
  // logId binding (RFC 6962 sec. 3.2): an SCT names its log by SHA-256(SPKI). When present,
  // it must match the key it is verified against.
  var sha256 = function (buf) { return crypto.createHash("sha256").update(buf).digest(); };
  var ecSctId = Object.assign({}, ecSct, { logId: sha256(ecSpki) });
  check("82. verifySct accepts an SCT whose logId matches the log key", (await vres(function () { return pki.ct.verifySct(entry, ecSctId, ecSpki); })) === true);
  check("83. verifySct rejects an SCT whose logId does not match the log key (ct/log-id-mismatch)", (await vres(function () { return pki.ct.verifySct(entry, Object.assign({}, ecSct, { logId: Buffer.alloc(32, 0xaa) }), ecSpki); })) === "ct/log-id-mismatch");
  // A structurally-valid EC SPKI (ecPublicKey + a P-256 curve OID) whose public point does
  // not import -> the import/verify seam maps it to a typed ct/verify-error, not a raw fault.
  var badPoint = b.sequence([b.sequence([b.oid(ecPub), b.oid(pki.oid.byName("prime256v1"))]), b.bitString(Buffer.alloc(65, 0), 0)]);
  check("84. verifySct maps an unimportable log key to ct/verify-error", (await vres(function () { return pki.ct.verifySct(entry, ecSct, badPoint); })) === "ct/verify-error");
  // An SPKI whose AlgorithmIdentifier does not lead with an OID -> typed ct/bad-input, not a
  // raw asn1/* error leaking out of the verifier.
  var noAlgOid = b.sequence([b.sequence([b.integer(5n)]), dummyPoint]);
  check("85. verifySct wraps a non-OID SPKI algorithm identifier (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, noAlgOid); })) === "ct/bad-input");
  // RFC 6962 sec. 2.1.4 constrains an SCT to SHA-256 + (P-256 ECDSA | RSA): an off-profile
  // hash or EC curve a conformant log never uses is rejected, not accepted defensively.
  check("86. verifySct rejects a non-SHA-256 SCT hash (ct/unsupported-algorithm)", (await vres(function () { return pki.ct.verifySct(entry, Object.assign({}, ecSct, { signatureAlgorithm: { hash: 5, hashName: "sha384", signature: 3, signatureName: "ecdsa" } }), ecSpki); })) === "ct/unsupported-algorithm");
  var p384 = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ format: "der", type: "spki" });
  check("87. verifySct rejects a non-P-256 ECDSA log key (ct/unsupported-algorithm)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, p384); })) === "ct/unsupported-algorithm");
  // RFC 6962 sec. 2.1.4 requires an RSA log key of at least 2048 bits.
  var rsa1024 = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
  var rsa1024Sct = sctFor("sha256", 4, "rsa", null, 1);
  rsa1024Sct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData(rsaEntry, rsa1024Sct), rsa1024.privateKey);
  check("88. verifySct rejects an RSA log key below 2048 bits (ct/unsupported-algorithm)", (await vres(function () { return pki.ct.verifySct(rsaEntry, rsa1024Sct, rsa1024.publicKey.export({ format: "der", type: "spki" })); })) === "ct/unsupported-algorithm");
  // A malformed RSAPublicKey in the log SPKI -> typed ct/bad-input.
  var badRsa = b.sequence([b.sequence([b.oid(pki.oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(Buffer.from([0xde, 0xad]), 0)]);
  check("89. verifySct wraps a malformed RSA log key SPKI (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, badRsa); })) === "ct/bad-input");
  // A negative RSA modulus is malformed -- fail closed, not sized by absolute value.
  var negRsa = b.sequence([b.sequence([b.oid(pki.oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(b.sequence([b.integer(-(1n << 2047n)), b.integer(65537n)]), 0)]);
  check("90. verifySct rejects a negative RSA modulus (ct/bad-input)", (await vres(function () { return pki.ct.verifySct(entry, ecSct, negRsa); })) === "ct/bad-input");
}

async function run() {
  testAccept();
  testInnerWrap();
  testListFraming();
  testUnknownVersion();
  testSctBody();
  testCaps();
  testReconstruct();
  testExtensionDecoderRegistry();
  testNotASchemaFormat();
  testKnownAnswerVector();
  await testVerifySct();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
