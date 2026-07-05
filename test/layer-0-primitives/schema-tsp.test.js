// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.tsp (RFC 3161 timestamp protocol: TSTInfo payload,
 * TimeStampResp wire message, and the TimeStampToken wrapper over CMS). Spec-first
 * conformance vectors, RED-first: every valid structure parses to the documented
 * shape; every malformed structure is rejected fail-closed with a typed tsp/* (or
 * leaf-level asn1/*) error. The TSTInfo payload parses standalone; the token wrapper
 * composes pki.schema.cms.parse and asserts the id-ct-TSTInfo content type + the
 * single-signer rule.
 *
 * RED baseline: pki.schema.tsp.* is undefined until the parser lands, so every vector
 * throws — the suite drives the build to GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var TAGS = pki.asn1.TAGS;

// ---- OIDs ------------------------------------------------------------
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_DATA        = "1.2.840.113549.1.7.1";
var ID_CT_TSTINFO  = "1.2.840.113549.1.9.16.1.4";
var CT_ATTR        = "1.2.840.113549.1.9.3";  // id-contentType
var MD_ATTR        = "1.2.840.113549.1.9.4";  // id-messageDigest
var SHA256         = "2.16.840.1.101.3.4.2.1";
var SIG_ALG        = "1.2.840.113549.1.1.11";
var POLICY         = "1.3.6.1.4.1.4146.2.3";  // a sample TSA policy OID
var CN             = "2.5.4.3";

// ---- fixture builders ------------------------------------------------
function algId(o) { return b.sequence([b.oid(o)]); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid(CN), b.utf8(cn)])])]); }
function genRaw(str) { return pki.asn1.encode(0x00, false, TAGS.GENERALIZED_TIME, Buffer.from(str, "latin1")); }
function utcRaw(str) { return pki.asn1.encode(0x00, false, TAGS.UTC_TIME, Buffer.from(str, "latin1")); }
function messageImprint(hashOid, hashBytes) { return b.sequence([algId(hashOid || SHA256), b.octetString(hashBytes || Buffer.alloc(32, 0xAB))]); }
// [tag] IMPLICIT INTEGER: context-primitive over the minimal INTEGER content.
function implicitInt(tag, n) { return b.contextPrimitive(tag, b.integer(BigInt(n)).slice(2)); }
function accuracy(o) {
  o = o || {};
  var c = [];
  if (o.seconds !== undefined) c.push(b.integer(BigInt(o.seconds)));
  if (o.millis !== undefined) c.push(implicitInt(0, o.millis));
  if (o.micros !== undefined) c.push(implicitInt(1, o.micros));
  return b.sequence(c);
}
function tstExtensions(list) { return b.contextConstructed(1, Buffer.concat(list)); }
function extension(oid, val) { return b.sequence([b.oid(oid), b.octetString(val || b.octetString(Buffer.from([1])))]); }

// TSTInfo builder — the 5 mandatory fields, then tag-ordered optionals.
function tstInfo(o) {
  o = o || {};
  if (o.children) return b.sequence(o.children);
  var c = [
    o.version !== undefined ? o.version : b.integer(1n),
    o.policy || b.oid(POLICY),
    o.imprint || messageImprint(),
    o.serial || b.integer(42n),
    o.genTime || genRaw("20260705120000Z"),
  ];
  if (o.accuracy) c.push(o.accuracy);
  if (o.ordering !== undefined) c.push(b.boolean(o.ordering));
  if (o.orderingRaw) c.push(o.orderingRaw);
  if (o.nonce !== undefined) c.push(b.integer(BigInt(o.nonce)));
  if (o.tsa) c.push(b.explicit(0, o.tsa));
  if (o.extensions) c.push(tstExtensions(o.extensions));
  if (o.tail) o.tail.forEach(function (t) { c.push(t); });
  return b.sequence(c);
}

// CMS SignedData token wrapper. A non-id-data eContentType requires signedAttrs
// (content-type == eContentType + message-digest), per RFC 5652 §5.3.
function attribute(typeOid, values) { return b.sequence([b.oid(typeOid), b.set(values)]); }
function implicitSetOf(tag, members) { var a = members.slice().sort(Buffer.compare); return b.contextConstructed(tag, Buffer.concat(a)); }
function iasn(cn, s) { return b.sequence([name(cn), b.integer(BigInt(s))]); }
function signerInfo(ctOid) {
  // The content-type signed attribute value MUST equal the eContentType (RFC 5652
  // §5.3), so thread the token's eContentType through.
  var attrs = [attribute(CT_ATTR, [b.oid(ctOid || ID_CT_TSTINFO)]), attribute(MD_ATTR, [b.octetString(Buffer.alloc(32, 0x01))])];
  return b.sequence([
    b.integer(1n), iasn("TSA", 7), algId(SHA256),
    implicitSetOf(0, attrs), algId(SIG_ALG), b.octetString(Buffer.from([0xDE, 0xAD])),
  ]);
}
function signedData(eContentType, eContent, signerCount) {
  var n = signerCount === undefined ? 1 : signerCount;
  var signers = [];
  for (var i = 0; i < n; i++) signers.push(signerInfo(eContentType));
  var encap = eContent !== null
    ? b.sequence([b.oid(eContentType), b.explicit(0, b.octetString(eContent))])
    : b.sequence([b.oid(eContentType)]);
  // RFC 5652 §5.1 — SignedData version is v1 for id-data content, v3 otherwise.
  var version = eContentType === ID_DATA ? 1n : 3n;
  return b.sequence([b.integer(version), b.set([algId(SHA256)]), encap, b.set(signers)]);
}
function timeStampToken(tstInfoDer, opts) {
  opts = opts || {};
  var ct = opts.eContentType || ID_CT_TSTINFO;
  var ec = opts.detached ? null : (tstInfoDer || tstInfo({}));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, signedData(ct, ec, opts.signerCount))]);
}
function pkiStatusInfo(o) {
  o = o || {};
  var c = [b.integer(BigInt(o.status === undefined ? 0 : o.status))];
  if (o.statusString) c.push(b.sequence(o.statusString.map(function (s) { return b.utf8(s); })));
  if (o.failInfo) c.push(o.failInfo);
  return b.sequence(c);
}
function timeStampResp(o) {
  o = o || {};
  if (o.children) return b.sequence(o.children);
  var c = [o.status || pkiStatusInfo({ status: 0 })];
  if (o.token) c.push(o.token);
  return b.sequence(c);
}

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function tstCode(der) { return code(function () { pki.schema.tsp.parseTstInfo(der); }); }
function respCode(der) { return code(function () { pki.schema.tsp.parse(der); }); }
function tokenCode(der) { return code(function () { pki.schema.tsp.parseToken(der); }); }

// ---- ACCEPT — TSTInfo ------------------------------------------------
function testAcceptTstInfo() {
  var m = pki.schema.tsp.parseTstInfo(tstInfo({}));
  check("2. minimal: version 1", m.version === 1);
  check("2. minimal: policy dotted", m.policy === POLICY);
  check("2. minimal: hashedMessage 32 raw bytes", Buffer.isBuffer(m.messageImprint.hashedMessage) && m.messageImprint.hashedMessage.length === 32);
  check("2. minimal: serialNumberHex", m.serialNumberHex === "2a");
  check("2. minimal: genTime Date", m.genTime instanceof Date && m.genTime.toISOString() === "2026-07-05T12:00:00.000Z");
  check("2. minimal: accuracy null", m.accuracy === null);
  check("2. minimal: ordering false", m.ordering === false);
  check("2. minimal: nonce null", m.nonce === null);
  check("2. minimal: tsa null", m.tsa === null);

  var s = pki.schema.tsp.parseTstInfo(tstInfo({ accuracy: accuracy({ seconds: 1 }) }));
  check("3. accuracy seconds only", s.accuracy.seconds === 1 && s.accuracy.millis === 0 && s.accuracy.micros === 0);
  var mm = pki.schema.tsp.parseTstInfo(tstInfo({ accuracy: accuracy({ millis: 500, micros: 250 }) }));
  check("4. accuracy millis/micros [0]/[1] IMPLICIT", mm.accuracy.millis === 500 && mm.accuracy.micros === 250 && mm.accuracy.seconds === 0);
  check("5. ordering TRUE present", pki.schema.tsp.parseTstInfo(tstInfo({ ordering: true })).ordering === true);
  var n = pki.schema.tsp.parseTstInfo(tstInfo({ nonce: 123456789 }));
  check("6. nonce BigInt + hex", typeof n.nonce === "bigint" && n.nonce === 123456789n && typeof n.nonceHex === "string");
  var t = pki.schema.tsp.parseTstInfo(tstInfo({ tsa: b.contextPrimitive(2, Buffer.from("tsa@ca.example", "latin1")) }));
  check("7. tsa surfaced raw", t.tsa && Buffer.isBuffer(t.tsa.bytes) && t.tsa.tagNumber === 2);
  check("7b. non-GeneralName tsa rejected", tstCode(tstInfo({ tsa: b.integer(5n) })) === "tsp/bad-tsa");
  var e = pki.schema.tsp.parseTstInfo(tstInfo({ extensions: [extension("1.3.6.1.5.5.7.48.1.2")] }));
  check("8. extensions [1] IMPLICIT decoded", Array.isArray(e.extensions) && e.extensions.length === 1 && typeof e.extensions[0].oid === "string");
  var big = Buffer.from("00ffffffffffffffff", "hex"); // 9-byte positive with sign pad
  var bs = pki.schema.tsp.parseTstInfo(tstInfo({ serial: pki.asn1.encode(0x00, false, TAGS.INTEGER, big) }));
  check("9. big serial lossless hex", bs.serialNumberHex === "00ffffffffffffffff" && typeof bs.serialNumber === "bigint");
  var fr = pki.schema.tsp.parseTstInfo(tstInfo({ genTime: genRaw("20260705120000.5Z") }));
  check("10. fractional genTime sub-second", fr.genTime.getUTCMilliseconds() === 500);
}

// ---- REJECT — TSTInfo ------------------------------------------------
function testRejectTstInfo() {
  check("11. version 2 rejected", tstCode(tstInfo({ version: b.integer(2n) })) === "tsp/bad-version");
  check("12. version ENUMERATED rejected", tstCode(tstInfo({ version: b.enumerated(1n) })) === "asn1/unexpected-tag");
  check("13. missing policy rejected", tstCode(b.sequence([b.integer(1n), messageImprint(), b.integer(42n), genRaw("20260705120000Z")])) !== "NO-THROW");
  check("14. policy not an OID rejected", tstCode(tstInfo({ policy: b.integer(5n) })) === "asn1/unexpected-tag");
  check("15. messageImprint not a SEQUENCE rejected", tstCode(tstInfo({ imprint: b.set([algId(SHA256), b.octetString(Buffer.alloc(32))]) })) === "tsp/bad-message-imprint");
  check("16. hashedMessage not OCTET STRING rejected", tstCode(tstInfo({ imprint: b.sequence([algId(SHA256), b.bitString(Buffer.alloc(32), 0)]) })) === "asn1/unexpected-tag");
  check("17. genTime UTCTime rejected", tstCode(tstInfo({ genTime: utcRaw("260705120000Z") })) === "tsp/bad-gentime");
  check("18. genTime no seconds rejected", tstCode(tstInfo({ genTime: genRaw("202607051200Z") })) === "asn1/bad-generalizedtime");
  check("19. genTime trailing-zero fraction rejected", tstCode(tstInfo({ genTime: genRaw("20260705120000.500Z") })) === "asn1/bad-generalizedtime");
  check("20. genTime empty fraction rejected", tstCode(tstInfo({ genTime: genRaw("20260705120000.Z") })) === "asn1/bad-generalizedtime");
  check("21. genTime comma separator rejected", tstCode(tstInfo({ genTime: genRaw("20260705120000,5Z") })) === "asn1/bad-generalizedtime");
  check("22. genTime no Z rejected", tstCode(tstInfo({ genTime: genRaw("20260705120000") })) === "asn1/bad-generalizedtime");
  check("23. accuracy millis 0 rejected", tstCode(tstInfo({ accuracy: accuracy({ millis: 0 }) })) !== "NO-THROW");
  check("24. accuracy micros 1000 rejected", tstCode(tstInfo({ accuracy: accuracy({ micros: 1000 }) })) === "tsp/bad-accuracy");
  check("26. ordering explicit FALSE rejected", tstCode(tstInfo({ ordering: false })) === "tsp/bad-ordering");
  check("28. accuracy after nonce (out of order) rejected", tstCode(tstInfo({ nonce: 5, tail: [accuracy({ seconds: 1 })] })) !== "NO-THROW");
  check("30. extensions [1] before tsa [0] rejected", tstCode(tstInfo({ tail: [tstExtensions([extension("1.2.3")]), b.explicit(0, b.contextPrimitive(2, Buffer.from("x")))] })) === "tsp/bad-tst-info");
  check("31. unknown [2] trailing field rejected", tstCode(tstInfo({ tail: [b.contextPrimitive(2, Buffer.from("x"))] })) === "tsp/bad-tst-info");
}

// ---- PKIStatusInfo / TimeStampResp -----------------------------------
function testResp() {
  var g = pki.schema.tsp.parse(timeStampResp({ status: pkiStatusInfo({ status: 0 }), token: timeStampToken(tstInfo({})) }));
  check("32. granted response: status 0 + token", g.status === 0 && Buffer.isBuffer(g.timeStampToken));
  var badRequestBit = b.bitString(Buffer.from([0x20]), 0); // bit 2 set (badRequest)
  var rej = pki.schema.tsp.parse(timeStampResp({ status: pkiStatusInfo({ status: 2, failInfo: badRequestBit }) }));
  check("33. rejection: status 2, failInfo named bits, no token", rej.status === 2 && rej.failInfo.bits.indexOf("badRequest") !== -1 && rej.timeStampToken === null);
  check("34. status ENUMERATED rejected", respCode(timeStampResp({ status: b.sequence([b.enumerated(0n)]) })) === "asn1/unexpected-tag");
  check("35. status 6 (outside 0..5) rejected", respCode(timeStampResp({ status: pkiStatusInfo({ status: 6 }) })) === "tsp/bad-status");
  check("36. granted without token rejected", respCode(timeStampResp({ status: pkiStatusInfo({ status: 0 }) })) === "tsp/missing-token");
  check("37. rejection WITH token rejected", respCode(timeStampResp({ status: pkiStatusInfo({ status: 2 }), token: timeStampToken(tstInfo({})) })) === "tsp/unexpected-token");
  check("39. statusString non-UTF8 rejected", respCode(timeStampResp({ status: b.sequence([b.integer(0n), b.sequence([b.printable("hi")])]), token: timeStampToken(tstInfo({})) })) !== "NO-THROW");
}

// ---- Strict-DER (inherited asn1/*) -----------------------------------
function testStrictDer() {
  check("40. indefinite-length outer rejected", tstCode(Buffer.from([0x30, 0x80, 0x00, 0x00])) === "tsp/bad-der");
  check("41. trailing byte rejected", tstCode(Buffer.concat([tstInfo({}), Buffer.from([0x00])])) === "tsp/bad-der");
  check("43. non-minimal serial rejected", tstCode(tstInfo({ serial: Buffer.from([0x02, 0x02, 0x00, 0x01]) })) === "asn1/non-minimal-integer");
}

// ---- Token composition (over CMS) ------------------------------------
function testToken() {
  var tk = timeStampToken(tstInfo({ nonce: 99 }));
  var parsed = pki.schema.tsp.parseToken(tk);
  check("44. token accept: TSTInfo decoded", parsed.tstInfo.version === 1 && parsed.tstInfo.nonce === 99n);
  check("44. token accept: single signerInfo surfaced", parsed.signerInfo && Array.isArray(parsed.certificates));
  check("45. wrong eContentType rejected", tokenCode(timeStampToken(tstInfo({}), { eContentType: ID_DATA })) === "tsp/wrong-econtent-type");
  check("46. detached token rejected", tokenCode(timeStampToken(tstInfo({}), { detached: true })) === "tsp/detached-token");
  check("47. multi-signer token rejected", tokenCode(timeStampToken(tstInfo({}), { signerCount: 2 })) === "tsp/multi-signer");
}

// ---- Dispatch + coercion ---------------------------------------------
function testDispatch() {
  var resp = timeStampResp({ status: pkiStatusInfo({ status: 0 }), token: timeStampToken(tstInfo({})) });
  var r = pki.schema.parse(resp);
  check("48. response routes to tsp", r && r.status !== undefined && r.validity === undefined);
  check("48. all() lists tsp", pki.schema.all().indexOf("tsp") !== -1);
  // 49. a CMS SignedData (OID-first) still routes to cms, not tsp.
  var cmsMsg = b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence([b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)]), b.set([])]))]);
  check("49. cms routes to cms, not tsp", pki.schema.parse(cmsMsg).signerInfos !== undefined);
  // 50. a bare TSTInfo is NOT auto-routed (INTEGER-then-OID leads; no tsp detector matches a payload).
  check("50. bare TSTInfo not auto-routed", code(function () { pki.schema.parse(tstInfo({})); }) === "schema/unknown-format");
  // 51. input coercion via the shared parse-entry.
  check("51. non-buffer input -> tsp/bad-input", respCode(42) === "tsp/bad-input");
  // 52. multi-defect fail-closed.
  var c52 = tstCode(tstInfo({ version: b.integer(2n), genTime: utcRaw("260705120000Z"), ordering: false }));
  check("52. multi-defect fail-closed (typed reject)", c52 !== "NO-THROW" && c52.indexOf("RAW:") !== 0);
}

function run() {
  testAcceptTstInfo();
  testRejectTstInfo();
  testResp();
  testStrictDer();
  testToken();
  testDispatch();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
