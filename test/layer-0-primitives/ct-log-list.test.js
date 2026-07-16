// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.ct.parseLogList / pki.ct.verifySctWithLogList (RFC 6962 sec. 3.2 + the CT log-list v3
 * JSON schema). The trust layer over the shipped verifySct: ingest the CT log-list JSON into
 * constraint-carrying trusted logs (keyed by the RECOMPUTED log-id = SHA-256(SPKI), never the document's
 * self-asserted id), then resolve a log key by an SCT's logId and verify through the shipped crypto.
 * The load-bearing security gates: the log-id identity binding (a swapped key or flipped id is refused),
 * the state gate (retired trusted only before retirement; pending/rejected refused), and the
 * temporal-interval gate (an SCT is not trusted for a cert outside the log's notAfter window). Every
 * malformed/oversized/mis-bound document is a typed CtError. Fixtures are cryptographically real
 * (self-round-trip: a generated log key signs an SCT whose logId = SHA-256 of that key's SPKI).
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

async function code(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function vres(fn) { try { return await fn(); } catch (e) { return (e && e.code) || String(e); } }

var certDer = pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE");
var ENTRY = { entryType: 0, leafCert: certDer };
var NOT_AFTER = pki.schema.x509.parse(certDer).validity.notAfter;   // a Date, for the temporal gate

// A cryptographically-real log: an EC keypair, its DER SPKI, the recomputed log-id, and a log-list entry
// object whose log_id = SHA-256(SPKI) (so the M-BIND recompute matches). `over` overrides the entry.
function makeLog(over) {
  over = over || {};
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var logId = crypto.createHash("sha256").update(spki).digest();
  var entry = {
    description: over.description || "Test Log",
    log_id: over.log_id !== undefined ? over.log_id : logId.toString("base64"),
    key: over.key !== undefined ? over.key : spki.toString("base64"),
    url: over.url || "https://ct.example.com/",
    mmd: over.mmd || 86400,
    state: over.state !== undefined ? over.state : { usable: { timestamp: "2022-01-01T00:00:00Z" } },
  };
  if (over.temporal_interval !== undefined) entry.temporal_interval = over.temporal_interval;
  return { kp: kp, spki: spki, logId: logId, logIdHex: logId.toString("hex"), entry: entry };
}

// The log-list JSON document wrapping logs under one operator.
function logListJson(logs, opOver) {
  var op = Object.assign({ name: "Test Operator", email: ["ct@example.com"], logs: logs, tiled_logs: [] }, opOver || {});
  return Buffer.from(JSON.stringify({ version: "3", log_list_timestamp: "2024-01-01T00:00:00Z", operators: [op] }));
}

// A signed SCT for `log` over ENTRY, at timestamp `tsMs` (a BigInt). logId = the log's recomputed id.
function signedSct(log, tsMs) {
  var sct = { version: 0, logId: log.logId, logIdHex: log.logIdHex, timestamp: tsMs === undefined ? 1700000000000n : tsMs,
    signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 3, signatureName: "ecdsa" }, signature: null, extensions: Buffer.alloc(0) };
  sct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData(ENTRY, sct), log.kp.privateKey);
  return sct;
}

async function run() {
  // ==== Accept / round-trip (M1/M2/M3/M4/M6) =======================================================
  var L = makeLog({ temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2040-01-01T00:00:00Z" } });
  var list = pki.ct.parseLogList(logListJson([L.entry]));
  check("1. parseLogList yields one log with the expected shape", list.logs.length === 1 && list.logs[0].logIdHex === L.logIdHex && Buffer.isBuffer(list.logs[0].key) && list.logs[0].key.equals(L.spki));
  check("2. the log's state + operator + mmd + temporalInterval decode", list.logs[0].state.name === "usable" && list.logs[0].operator === "Test Operator" && list.logs[0].mmd === 86400 && list.logs[0].temporalInterval.startInclusive instanceof Date);
  check("3. byLogId resolves each log by hex", list.byLogId[L.logIdHex] === list.logs[0]);
  // the M3 binding is independently observable: SHA-256(key) === logIdHex for every parsed log
  check("4. SHA-256(log.key) equals log.logIdHex (the recomputed identity binding)", crypto.createHash("sha256").update(list.logs[0].key).digest("hex") === list.logs[0].logIdHex);
  check("5. a usable log parses as trusted", list.logs[0].trusted === true);

  // ==== End-to-end resolve+verify (the headline, M9/M10/M11) ========================================
  var sct = signedSct(L);
  check("6. verifySctWithLogList resolves the key by logId + verifies -> true", (await vres(function () { return pki.ct.verifySctWithLogList(ENTRY, sct, list, { certNotAfter: NOT_AFTER }); })) === true);
  var badSig = Object.assign({}, sct, { signature: (function (b) { var c = Buffer.from(b); c[c.length - 1] ^= 0xff; return c; })(sct.signature) });
  check("7. a flipped signature byte -> false (a verdict, not a throw)", (await vres(function () { return pki.ct.verifySctWithLogList(ENTRY, badSig, list, { certNotAfter: NOT_AFTER }); })) === false);

  // ==== The identity binding (M-BIND / M3) =========================================================
  var flip = makeLog();
  var flippedId = Buffer.from(flip.logId); flippedId[0] ^= 0x01;
  check("8. a log_id flipped one byte -> ct/log-id-mismatch", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ log_id: flippedId.toString("base64") }).entry])); })) === "ct/log-id-mismatch");
  var a = makeLog(), b = makeLog();
  check("9. a key swapped for a different valid SPKI (id kept) -> ct/log-id-mismatch", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ log_id: a.logId.toString("base64"), key: b.spki.toString("base64") }).entry])); })) === "ct/log-id-mismatch");
  check("10. a key that is not a well-formed SPKI -> ct/bad-input", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ key: Buffer.from("not an spki").toString("base64"), log_id: crypto.createHash("sha256").update(Buffer.from("not an spki")).digest("base64") }).entry])); })) === "ct/bad-input");
  check("11. a log_id that decodes to != 32 bytes -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ log_id: Buffer.alloc(16).toString("base64") }).entry])); })) === "ct/bad-log-list");

  // ==== State + temporal trust gates (M4/M5/M9/M10) ================================================
  var rejected = makeLog({ state: { rejected: { timestamp: "2023-01-01T00:00:00Z" } } });
  var rlist = pki.ct.parseLogList(logListJson([rejected.entry]));
  check("12. a rejected log parses trusted:false; an SCT against it -> ct/log-untrusted", rlist.logs[0].trusted === false && (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(rejected), rlist); })) === "ct/log-untrusted");
  var pending = makeLog({ state: { pending: { timestamp: "2023-01-01T00:00:00Z" } } });
  check("13. an SCT against a pending log -> ct/log-untrusted", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(pending), pki.ct.parseLogList(logListJson([pending.entry]))); })) === "ct/log-untrusted");
  // retired: trusted only for an SCT timestamped BEFORE the retirement instant.
  var retired = makeLog({ state: { retired: { timestamp: "2023-06-01T00:00:00Z" } } });   // retired 2023-06-01
  var retList = pki.ct.parseLogList(logListJson([retired.entry]));
  var before = signedSct(retired, BigInt(Date.parse("2023-01-01T00:00:00Z")));
  check("14. a retired log verifies an SCT timestamped BEFORE retirement", (await vres(function () { return pki.ct.verifySctWithLogList(ENTRY, before, retList, { certNotAfter: NOT_AFTER }); })) === true);
  var after = signedSct(retired, BigInt(Date.parse("2024-01-01T00:00:00Z")));
  check("15. a retired log refuses an SCT timestamped AT/AFTER retirement -> ct/log-untrusted", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, after, retList, { certNotAfter: NOT_AFTER }); })) === "ct/log-untrusted");
  check("16. a state {} (zero members) -> ct/bad-state", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ state: {} }).entry])); })) === "ct/bad-state");
  check("17. a two-member state -> ct/bad-state", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ state: { usable: { timestamp: "2022-01-01T00:00:00Z" }, retired: { timestamp: "2023-01-01T00:00:00Z" } } }).entry])); })) === "ct/bad-state");
  check("18. an unrecognized state key -> ct/bad-state", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ state: { frozen: { timestamp: "2022-01-01T00:00:00Z" } } }).entry])); })) === "ct/bad-state");

  // temporal_interval gate
  var win = makeLog({ temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2021-01-01T00:00:00Z" } });   // window ends 2021
  var wlist = pki.ct.parseLogList(logListJson([win.entry]));
  check("19. an SCT whose cert notAfter is >= end_exclusive -> ct/temporal-interval", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(win), wlist, { certNotAfter: new Date("2025-06-01T00:00:00Z") }); })) === "ct/temporal-interval");
  check("20. an SCT with a cert notAfter < start_inclusive -> ct/temporal-interval", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(win), wlist, { certNotAfter: new Date("2019-06-01T00:00:00Z") }); })) === "ct/temporal-interval");
  check("21. a windowed log with no resolvable notAfter -> ct/temporal-interval (fail-closed, not skipped)", (await code(function () { return pki.ct.verifySctWithLogList({ entryType: 1, tbsCertificate: certDer, issuerKeyHash: Buffer.alloc(32, 7) }, signedSct(win), wlist); })) === "ct/temporal-interval");
  check("22. an inverted temporal_interval at parse -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ temporal_interval: { start_inclusive: "2030-01-01T00:00:00Z", end_exclusive: "2020-01-01T00:00:00Z" } }).entry])); })) === "ct/bad-log-list");

  // ==== Resolve miss + dedup (M8/M9) ===============================================================
  check("23. an SCT whose logId is absent from the list -> ct/log-not-found", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(makeLog()), list); })) === "ct/log-not-found");
  var dup = makeLog();
  check("24. a duplicated identical log collapses to one entry", pki.ct.parseLogList(logListJson([dup.entry, JSON.parse(JSON.stringify(dup.entry))])).logs.length === 1);
  var dupA = makeLog(), dupDisagree = makeLog({ log_id: dupA.logId.toString("base64"), key: dupA.spki.toString("base64"), state: { rejected: { timestamp: "2023-01-01T00:00:00Z" } } });
  check("25. two entries for one recomputed id that disagree -> ct/duplicate-log", (await code(function () { return pki.ct.parseLogList(logListJson([dupA.entry, dupDisagree.entry])); })) === "ct/duplicate-log");

  // ==== Adversarial JSON (the guard.json class) ====================================================
  check("26. a duplicate JSON member -> ct/duplicate-member (never JSON.parse last-wins)", (await code(function () { var m = makeLog(); return pki.ct.parseLogList(Buffer.from('{"operators":[{"name":"O","logs":[{"description":"d","log_id":"' + m.logId.toString("base64") + '","log_id":"' + m.logId.toString("base64") + '","key":"' + m.spki.toString("base64") + '","url":"https://x/","mmd":1,"state":{"usable":{"timestamp":"2022-01-01T00:00:00Z"}}}],"tiled_logs":[]}]}')); })) === "ct/duplicate-member");
  check("27. a __proto__ member does not pollute the prototype", (function () { try { pki.ct.parseLogList(Buffer.from('{"operators":[],"__proto__":{"polluted":true}}')); } catch (_e) { /* structural reject is fine */ } return ({}).polluted === undefined; })());
  check("28. a malformed RFC 3339 timestamp -> ct/bad-date", (await code(function () { return pki.ct.parseLogList(logListJson([makeLog({ state: { usable: { timestamp: "2022-13-40T00:00:00Z" } } }).entry])); })) === "ct/bad-date");

  // ==== Structural + config-time (M1/M12) ==========================================================
  check("29. {} (no operators) -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(Buffer.from("{}")); })) === "ct/bad-log-list");
  check("30. parseLogList(123) -> ct/bad-input", (await code(function () { return pki.ct.parseLogList(123); })) === "ct/bad-input");
  check("31. verifySctWithLogList with an sct missing logIdHex -> ct/bad-input", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, { version: 0 }, list); })) === "ct/bad-input");
  check("32. verifySctWithLogList with a non-object logList -> ct/bad-input", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, sct, null); })) === "ct/bad-input");

  // ==== Coverage: reachable defensive + fallback branches ==========================================
  var kbase = makeLog();
  // build a raw log object with configurable presence of fields (bypassing makeLog's always-set fields)
  function rawLog(fields) { return Object.assign({ log_id: kbase.logId.toString("base64"), key: kbase.spki.toString("base64"), state: { usable: { timestamp: "2022-01-01T00:00:00Z" } } }, fields); }
  check("33. a log with NO state -> ct/bad-state", (await code(function () { var l = rawLog({}); delete l.state; return pki.ct.parseLogList(logListJson([l])); })) === "ct/bad-state");
  check("34. a state whose member is not an object -> ct/bad-state", (await code(function () { return pki.ct.parseLogList(logListJson([rawLog({ state: { usable: "not-an-object" } })])); })) === "ct/bad-state");
  check("35. a temporal_interval that is not an object -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(logListJson([rawLog({ temporal_interval: "nope" })])); })) === "ct/bad-log-list");
  check("36. a log entry that is not an object -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(logListJson(["not-an-object"])); })) === "ct/bad-log-list");
  check("37. a log missing key/log_id -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(logListJson([{ state: { usable: { timestamp: "2022-01-01T00:00:00Z" } } }])); })) === "ct/bad-log-list");
  // the description/url/mmd fallbacks: a minimal log (no description, no url, no mmd) parses with nulls
  var minimal = pki.ct.parseLogList(logListJson([rawLog({})]));
  check("38. a log with no description/url/mmd surfaces them as null", minimal.logs[0].description === null && minimal.logs[0].url === null && minimal.logs[0].mmd === null);
  // a tiled_logs entry uses submission_url; both log arrays walked
  var tiled = makeLog();
  var tlist = pki.ct.parseLogList(Buffer.from(JSON.stringify({ operators: [{ name: "Op", logs: [], tiled_logs: [{ description: "Tiled", log_id: tiled.logId.toString("base64"), key: tiled.spki.toString("base64"), submission_url: "https://tile.example/", mmd: 86400, state: { usable: { timestamp: "2022-01-01T00:00:00Z" } } }] }] })));
  check("39. a tiled_logs entry is walked and surfaces submission_url as url", tlist.logs.length === 1 && tlist.logs[0].url === "https://tile.example/");
  check("40. an operator missing its name -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(Buffer.from(JSON.stringify({ operators: [{ logs: [] }] }))); })) === "ct/bad-log-list");
  check("41. an operator logs that is not an array -> ct/bad-log-list", (await code(function () { return pki.ct.parseLogList(Buffer.from(JSON.stringify({ operators: [{ name: "Op", logs: "nope" }] }))); })) === "ct/bad-log-list");
  // the entryType-0 leafCert notAfter auto-derive path (no certNotAfter passed): a windowed log covering
  // the leaf's notAfter (2036) verifies purely from the parsed leafCert.
  var autoWin = makeLog({ temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2040-01-01T00:00:00Z" } });
  check("42. entryType-0 derives the cert notAfter from leafCert (no certNotAfter opt)", (await vres(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(autoWin), pki.ct.parseLogList(logListJson([autoWin.entry]))); })) === true);
  // dedup where one duplicate has a temporal_interval and the other does not (same recomputed id) -> disagree
  var tiA = makeLog({ temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2040-01-01T00:00:00Z" } });
  var tiB = makeLog({ log_id: tiA.logId.toString("base64"), key: tiA.spki.toString("base64") });   // no temporal_interval
  check("43. a dedup where one entry has a temporal_interval and the other does not -> ct/duplicate-log", (await code(function () { return pki.ct.parseLogList(logListJson([tiA.entry, tiB.entry])); })) === "ct/duplicate-log");
  check("44. the same dedup in the reverse order (no-interval first) -> ct/duplicate-log", (await code(function () { return pki.ct.parseLogList(logListJson([tiB.entry, tiA.entry])); })) === "ct/duplicate-log");
  // an operator with a name + logs but NO tiled_logs field: the tiled_logs array is absent -> skipped.
  check("45. an operator with no tiled_logs field parses its logs", pki.ct.parseLogList(Buffer.from(JSON.stringify({ operators: [{ name: "Op", logs: [makeLog().entry] }] }))).logs.length === 1);
  // the entryType-0 leafCert parse catch: a malformed leafCert + a windowed log + no certNotAfter fails
  // closed at the temporal gate (the notAfter cannot be derived), never a silent skip.
  check("46. entryType-0 with a malformed leafCert (windowed log, no certNotAfter) -> ct/temporal-interval", (await code(function () { return pki.ct.verifySctWithLogList({ entryType: 0, leafCert: Buffer.from("not a certificate") }, signedSct(win), wlist); })) === "ct/temporal-interval");
  // two dups (same key/id) with DIFFERENT temporal_intervals -> disagree (the interval getTime compare).
  var wc = makeLog({ temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2040-01-01T00:00:00Z" } });
  var wc2 = makeLog({ log_id: wc.logId.toString("base64"), key: wc.spki.toString("base64"), temporal_interval: { start_inclusive: "2021-01-01T00:00:00Z", end_exclusive: "2041-01-01T00:00:00Z" } });
  check("47. a dedup with two differing temporal_intervals (same id) -> ct/duplicate-log", (await code(function () { return pki.ct.parseLogList(logListJson([wc.entry, wc2.entry])); })) === "ct/duplicate-log");

  // ==== SECURITY: the temporal gate must reject a NaN (Invalid) Date, not silently bypass the window ====
  // An Invalid Date is still `instanceof Date`, and NaN < start / NaN >= end are both false, so without an
  // explicit isNaN guard an out-of-window SCT would verify true (the shard-containment gate disabled).
  check("48. an Invalid Date certNotAfter (windowed log, out-of-window SCT) -> ct/temporal-interval (no NaN bypass)", (await code(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(win), wlist, { certNotAfter: new Date("not a date") }); })) === "ct/temporal-interval");
  check("49. new Date(NaN) certNotAfter -> ct/temporal-interval (the entryType-1 mandatory path)", (await code(function () { return pki.ct.verifySctWithLogList({ entryType: 1, tbsCertificate: certDer, issuerKeyHash: Buffer.alloc(32, 7) }, signedSct(win), wlist, { certNotAfter: new Date(NaN) }); })) === "ct/temporal-interval");

  // ==== the qualified / readonly trusted states also verify (all three trusted states, not just usable) ====
  var qualified = makeLog({ state: { qualified: { timestamp: "2022-01-01T00:00:00Z" } } });
  check("50. a qualified log is trusted + verifies an SCT", pki.ct.parseLogList(logListJson([qualified.entry])).logs[0].trusted === true && (await vres(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(qualified), pki.ct.parseLogList(logListJson([qualified.entry])), { certNotAfter: NOT_AFTER }); })) === true);
  var readonly = makeLog({ state: { readonly: { timestamp: "2022-01-01T00:00:00Z", final_tree_head: { tree_size: 10, sha256_root_hash: Buffer.alloc(32, 5).toString("base64") } } } });
  check("51. a readonly log is trusted + verifies an SCT", pki.ct.parseLogList(logListJson([readonly.entry])).logs[0].trusted === true && (await vres(function () { return pki.ct.verifySctWithLogList(ENTRY, signedSct(readonly), pki.ct.parseLogList(logListJson([readonly.entry])), { certNotAfter: NOT_AFTER }); })) === true);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
