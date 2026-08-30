// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.ct.verifySctList (RFC 6962 sec. 3.3): the aggregate, certificate-level CT verdict over
 * the SET of SCTs a certificate carries. Composes the shipped per-SCT verifySct + the parseLogList trust
 * gates and renders how many SCTs verified, from how many distinct trusted operators, and whether that
 * meets a caller-supplied CT policy (minScts / minOperators; both default to the RFC 6962 floor of 1).
 * Policy failure is a VERDICT (policyOk:false), not a throw; per-SCT structural/trust/crypto failures are
 * captured into a result row and the loop continues; only a mis-shaped caller input throws a typed
 * CtError. Fixtures are cryptographically real (a generated log key signs an SCT whose logId is
 * SHA-256 of that key's SPKI), mirroring ct-log-list.test.js.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

async function code(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

var certDer = pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE");
var ENTRY = { entryType: 0, leafCert: certDer };
var NOT_AFTER = pki.schema.x509.parse(certDer).validity.notAfter;

// A cryptographically-real log (mirrors ct-log-list.test.js makeLog).
function makeLog(over) {
  over = over || {};
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var logId = crypto.createHash("sha256").update(spki).digest();
  var entry = {
    description: over.description || "Test Log",
    log_id: over.log_id !== undefined ? over.log_id : logId.toString("base64"),
    key: over.key !== undefined ? over.key : spki.toString("base64"),
    url: "https://ct.example.com/", mmd: 86400,
    state: over.state !== undefined ? over.state : { usable: { timestamp: "2022-01-01T00:00:00Z" } },
  };
  if (over.temporal_interval !== undefined) entry.temporal_interval = over.temporal_interval;
  return { kp: kp, spki: spki, logId: logId, logIdHex: logId.toString("hex"), entry: entry };
}

// A log-list JSON grouping logs under named operators: ops is [{ name, logs: [makeLog().entry, ...] }].
function logListJson(ops) {
  return Buffer.from(JSON.stringify({ version: "3", log_list_timestamp: "2024-01-01T00:00:00Z",
    operators: ops.map(function (o) { return { name: o.name, email: ["ct@example.com"], logs: o.logs, tiled_logs: [] }; }) }));
}

// A signed SCT for `log` over ENTRY at BigInt `tsMs`.
function signedSct(log, tsMs) {
  var sct = { version: 0, logId: log.logId, logIdHex: log.logIdHex, timestamp: tsMs === undefined ? 1700000000000n : tsMs,
    signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 3, signatureName: "ecdsa" }, signature: null, extensions: Buffer.alloc(0) };
  sct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData(ENTRY, sct), log.kp.privateKey);
  return sct;
}

async function run() {
  // ---- Accept / happy path ----
  var opA = makeLog(), opB = makeLog();
  var listAB = pki.ct.parseLogList(logListJson([{ name: "Operator A", logs: [opA.entry] }, { name: "Operator B", logs: [opB.entry] }]));
  var v1 = await pki.ct.verifySctList(ENTRY, [signedSct(opA), signedSct(opB)], listAB, { certNotAfter: NOT_AFTER });
  check("VL1. two SCTs, two distinct operators -> policyOk, validScts:2, operatorCount:2",
    v1.policyOk === true && v1.validScts === 2 && v1.operatorCount === 2 && v1.results.length === 2 && v1.results[0].valid === true && v1.results[1].valid === true);

  var v2 = await pki.ct.verifySctList(ENTRY, [signedSct(opA)], listAB, { certNotAfter: NOT_AFTER });
  check("VL2. one valid SCT, default policy -> policyOk", v2.policyOk === true && v2.validScts === 1 && v2.operatorCount === 1);

  // ---- Policy (verdict, not throw) ----
  var opC1 = makeLog(), opC2 = makeLog();
  var listC = pki.ct.parseLogList(logListJson([{ name: "One Operator", logs: [opC1.entry, opC2.entry] }]));
  var v3 = await pki.ct.verifySctList(ENTRY, [signedSct(opC1), signedSct(opC2)], listC, { certNotAfter: NOT_AFTER, minOperators: 2 });
  check("VL3. two valid SCTs, same operator, minOperators:2 -> policyOk:false, operatorCount:1",
    v3.policyOk === false && v3.operatorCount === 1 && v3.validScts === 2 && v3.results[0].valid === true && v3.results[1].valid === true && typeof v3.reason === "string");
  var v3b = await pki.ct.verifySctList(ENTRY, [signedSct(opC1), signedSct(opC2)], listC, { certNotAfter: NOT_AFTER, minOperators: 1 });
  check("VL3b. same inputs, minOperators:1 -> policyOk", v3b.policyOk === true);

  var opUnknown = makeLog();   // a real log+key, but NOT placed in the list
  var v4 = await pki.ct.verifySctList(ENTRY, [signedSct(opUnknown)], listAB, { certNotAfter: NOT_AFTER });
  check("VL4. zero valid SCTs (log unknown to list) -> policyOk:false, validScts:0, row code ct/log-not-found (no throw)",
    v4.policyOk === false && v4.validScts === 0 && v4.results.length === 1 && v4.results[0].valid === false && v4.results[0].code === "ct/log-not-found");

  var v5 = await pki.ct.verifySctList(ENTRY, [signedSct(opA), signedSct(opB)], listAB, { certNotAfter: NOT_AFTER, minScts: 3 });
  check("VL5. minScts:3 with two valid SCTs -> policyOk:false", v5.policyOk === false && v5.validScts === 2);

  // ---- Adversarial / capture-not-throw ----
  var good = signedSct(opA), corrupt = signedSct(opB);
  corrupt.signature = Buffer.from(corrupt.signature); corrupt.signature[corrupt.signature.length - 1] ^= 0xff;   // flip a signature byte
  var v6 = await pki.ct.verifySctList(ENTRY, [good, corrupt], listAB, { certNotAfter: NOT_AFTER });
  check("VL6. one valid + one signature-corrupt SCT -> corrupt row valid:false no code, good valid:true, policyOk (>=1)",
    v6.policyOk === true && v6.validScts === 1 && v6.results[1].valid === false && v6.results[1].code === undefined && v6.results[0].valid === true);

  var retired = makeLog({ state: { retired: { timestamp: "2023-06-01T00:00:00Z" } } });
  var listRet = pki.ct.parseLogList(logListJson([{ name: "Op A", logs: [opA.entry] }, { name: "Retired Op", logs: [retired.entry] }]));
  var afterRet = signedSct(retired, BigInt(Date.parse("2023-07-01T00:00:00Z")));   // timestamped AFTER retirement
  var v7 = await pki.ct.verifySctList(ENTRY, [signedSct(opA), afterRet], listRet, { certNotAfter: NOT_AFTER });
  check("VL7. an SCT for a retired log after retirement -> row valid:false code ct/log-untrusted, sibling still counts",
    v7.validScts === 1 && v7.results[1].valid === false && v7.results[1].code === "ct/log-untrusted" && v7.results[0].valid === true);

  var windowed = makeLog({ temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2021-01-01T00:00:00Z" } });
  var listWin = pki.ct.parseLogList(logListJson([{ name: "Windowed Op", logs: [windowed.entry] }]));
  var v8 = await pki.ct.verifySctList(ENTRY, [signedSct(windowed)], listWin, { certNotAfter: NOT_AFTER });   // NOT_AFTER is outside [2020,2021)
  check("VL8. a windowed log with certNotAfter outside [start,end) -> row valid:false code ct/temporal-interval",
    v8.results[0].valid === false && v8.results[0].code === "ct/temporal-interval");

  // A parseSctList-shaped result carrying a forward-compat unknown-version entry beside a valid v1 SCT.
  var sctA = signedSct(opA);
  var parsedUnknown = { scts: [sctA], unknownScts: [{ version: 7, rawSct: Buffer.concat([Buffer.from([7]), Buffer.alloc(10, 0xEE)]) }], all: [sctA] };
  var v9 = await pki.ct.verifySctList(ENTRY, parsedUnknown, listAB, { certNotAfter: NOT_AFTER });
  check("VL9. an unknown-version entry alongside a valid v1 SCT -> unknownScts:1, absent from results, validScts:1, totalScts:2",
    v9.unknownScts === 1 && v9.validScts === 1 && v9.results.length === 1 && v9.results[0].valid === true && v9.totalScts === 2);

  // ---- Mis-shaped inputs THROW typed CtError ----
  check("VL10a. logList not a parseLogList result -> ct/bad-input",
    (await code(function () { return pki.ct.verifySctList(ENTRY, [signedSct(opA)], { nope: 1 }, { certNotAfter: NOT_AFTER }); })) === "ct/bad-input");
  check("VL10b. entry.entryType neither 0 nor 1 -> ct/bad-entry-type",
    (await code(function () { return pki.ct.verifySctList({ entryType: 9 }, [signedSct(opA)], listAB, { certNotAfter: NOT_AFTER }); })) === "ct/bad-entry-type");
  check("VL10c. opts.minOperators non-integer -> ct/bad-input",
    (await code(function () { return pki.ct.verifySctList(ENTRY, [signedSct(opA)], listAB, { certNotAfter: NOT_AFTER, minOperators: 1.5 }); })) === "ct/bad-input");
  check("VL10d. list neither an array nor a parseSctList result -> ct/bad-input",
    (await code(function () { return pki.ct.verifySctList(ENTRY, "nope", listAB, { certNotAfter: NOT_AFTER }); })) === "ct/bad-input");

  // ---- x509CertEntry / precert reconstruction (M8 -- the load-bearing vectors) ----
  var caKp = await pki.key.generate("Ed25519");
  var caKey = await pki.key.export(caKp.privateKey), caSpki = await pki.key.export(caKp.publicKey);
  var caCert = await pki.x509.sign({ subject: "CT Test CA", subjectPublicKey: caSpki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: caKey });
  var issuerKeyHash = crypto.createHash("sha256").update(pki.schema.x509.parse(caCert).subjectPublicKeyInfo.bytes).digest();
  var leafSpki = await pki.key.export((await pki.key.generate("Ed25519")).publicKey);
  var otherExt = pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("basicConstraints")), pki.asn1.build.octetString(pki.asn1.build.sequence([]))]);
  var common = { serialNumber: 4242, subject: "CT Leaf", subjectPublicKey: leafSpki, notBefore: new Date("2026-06-01T00:00:00Z"), notAfter: new Date("2027-06-01T00:00:00Z") };
  var issuerArg = { key: caKey, cert: caCert };
  // A: the precert TBS (no SCT). B: the final cert = A + the SCT extension (SCT NOT last -> mid-list removal).
  var certA = await pki.x509.sign(Object.assign({}, common, { extensions: [otherExt] }), issuerArg);
  var tbsA = pki.schema.x509.parse(certA).tbsBytes;
  var logKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var logSpki = logKp.publicKey.export({ format: "der", type: "spki" });
  var logIdE = crypto.createHash("sha256").update(logSpki).digest();
  var eSct = { version: 0, logId: logIdE, logIdHex: logIdE.toString("hex"), timestamp: 1700000000000n, hashAlg: 4, sigAlg: 3,
    signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 3, signatureName: "ecdsa" }, signature: null, extensions: Buffer.alloc(0) };
  eSct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData({ entryType: 1, tbsCertificate: tbsA, issuerKeyHash: issuerKeyHash }, eSct), logKp.privateKey);
  var sctExt = pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("signedCertificateTimestampList")), pki.asn1.build.octetString(pki.ct.encodeSctList([eSct]))]);
  var certB = await pki.x509.sign(Object.assign({}, common, { extensions: [sctExt, otherExt] }), issuerArg);

  var entry11 = pki.ct.x509CertEntry(certB, caCert);
  check("VL11. x509CertEntry(final, issuer) reconstructs an entry whose SCT verifySct accepts",
    (await pki.ct.verifySct(entry11, eSct, logSpki)) === true);
  check("VL12. M8 byte-exactness: reconstructed tbsCertificate equals the precert TBS (mid-list SCT removed)",
    Buffer.isBuffer(entry11.tbsCertificate) && Buffer.compare(entry11.tbsCertificate, tbsA) === 0);
  check("VL13. issuerKeyHash is SHA-256(issuer SPKI), 32 bytes; a wrong issuer -> the SCT fails to verify",
    entry11.issuerKeyHash.length === 32 && entry11.issuerKeyHash.equals(issuerKeyHash) &&
    (await pki.ct.verifySct(pki.ct.x509CertEntry(certB, certDer), eSct, logSpki)) === false);

  // Error branches (coverage): no SCT extension, no extensions at all, malformed input.
  check("VL14a. a cert with extensions but no SCT-list extension -> ct/no-sct-extension",
    (await code(function () { return pki.ct.x509CertEntry(certA, caCert); })) === "ct/no-sct-extension");
  var noExtCert = await pki.x509.sign({ subject: "No Ext Leaf", subjectPublicKey: leafSpki, notBefore: new Date("2026-06-01T00:00:00Z"), notAfter: new Date("2027-06-01T00:00:00Z") }, issuerArg);
  check("VL14b. a v1 cert with no extensions field -> ct/no-sct-extension",
    (await code(function () { return pki.ct.x509CertEntry(noExtCert, caCert); })) === "ct/no-sct-extension");
  check("VL14c. malformed certificate bytes surface the x509 parse fault (matches pki.path.validate)",
    (await code(function () { return pki.ct.x509CertEntry(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]), caCert); })).indexOf("x509/") === 0);
  check("VL14e. a wrong-type cert argument (not bytes, not a parsed cert) -> ct/bad-cert-entry",
    (await code(function () { return pki.ct.x509CertEntry({ nope: 1 }, caCert); })) === "ct/bad-cert-entry");
  check("VL14d. a parsed-x509 result is accepted directly (no re-parse)",
    Buffer.compare(pki.ct.x509CertEntry(pki.schema.x509.parse(certB), pki.schema.x509.parse(caCert)).tbsCertificate, tbsA) === 0);

  // ---- path.validate CT gate ----
  var ctLog = { description: "CT Log", log_id: logIdE.toString("base64"), key: logSpki.toString("base64"),
    url: "https://ct.example/", mmd: 86400, state: { usable: { timestamp: "2022-01-01T00:00:00Z" } },
    temporal_interval: { start_inclusive: "2020-01-01T00:00:00Z", end_exclusive: "2030-01-01T00:00:00Z" } };
  var ctLogList = pki.ct.parseLogList(logListJson([{ name: "CT Operator", logs: [ctLog] }]));
  var atTime = new Date("2026-09-01T00:00:00Z");   // within certB validity (2026-06 .. 2027-06)
  function ctCheckOf(res) {
    for (var i = 0; i < res.results.length; i++) for (var j = 0; j < res.results[i].checks.length; j++) if (res.results[i].checks[j].name === "ct") return res.results[i].checks[j];
    return null;
  }
  var r15 = await pki.path.validate([certB], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minScts: 1, minOperators: 1 } });
  var c15 = ctCheckOf(r15);
  check("VL15. path.validate with a valid embedded SCT -> a ct check ok:true, path valid", c15 !== null && c15.ok === true && r15.valid === true);

  var r16 = await pki.path.validate([certA], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minScts: 1, minOperators: 1 } });
  var c16 = ctCheckOf(r16);
  check("VL16. path.validate on a leaf with no SCT extension + ctPolicy -> ct ok:false code path/ct-required, valid:false",
    c16 !== null && c16.ok === false && c16.code === "path/ct-required" && r16.valid === false);

  var r17 = await pki.path.validate([certB], { trustAnchor: caCert, time: atTime });
  check("VL17. no ctLogList/ctPolicy -> no ct check is added (behavior-preserving)", ctCheckOf(r17) === null);

  var r18 = await pki.path.validate([certB], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minScts: 2, minOperators: 1 } });
  var c18 = ctCheckOf(r18);
  check("VL18. an unmet CT policy (minScts:2, one SCT) -> ct ok:false code path/ct-policy-not-met, valid:false",
    c18 !== null && c18.ok === false && c18.code === "path/ct-policy-not-met" && r18.valid === false);

  // VL19 (P1): an SCT from a trusted log whose declared hash algorithm is unsupported makes verifySct
  // THROW (ct/unsupported-algorithm), not return false. The aggregate records it per-SCT and continues,
  // so the throwing SCT does not sink the verdict or a valid sibling.
  var badAlg = signedSct(opA);
  badAlg.signatureAlgorithm = { hash: 2, hashName: "sha1", signature: 3, signatureName: "ecdsa" };
  var v19 = await pki.ct.verifySctList(ENTRY, [signedSct(opB), badAlg], listAB, { certNotAfter: NOT_AFTER });
  check("VL19. a structurally-defective SCT (unsupported hash) is recorded, not thrown; sibling still counts",
    v19.validScts === 1 && v19.results.length === 2 && v19.results[1].valid === false && v19.results[1].code === "ct/unsupported-algorithm" && v19.results[0].valid === true);

  // VL20 (P2): a CT policy supplied without a log-list cannot be enforced -> refused at entry, never a
  // silently-skipped CT gate that returns a valid path.
  check("VL20. path.validate with ctPolicy but no ctLogList -> path/bad-input (fail-closed)",
    (await code(function () { return pki.path.validate([certB], { trustAnchor: caCert, time: atTime, ctPolicy: { minScts: 1 } }); })) === "path/bad-input");

  // VL21 (dedup): the same SCT repeated cannot inflate the count -- each distinct trusted log counts
  // once, so a duplicated SCT does not satisfy a higher minScts. Both rows are kept for diagnostics.
  var dupA = signedSct(opA);
  var v21 = await pki.ct.verifySctList(ENTRY, [dupA, dupA], listAB, { certNotAfter: NOT_AFTER, minScts: 2 });
  check("VL21. the same SCT twice counts as one distinct log -> validScts:1, minScts:2 unmet, both rows valid",
    v21.validScts === 1 && v21.results.length === 2 && v21.results[0].valid === true && v21.results[1].valid === true && v21.policyOk === false);

  // VL22 (P1): a misspelled ctPolicy key would read as undefined and silently default the threshold to
  // the RFC floor of 1 -- refuse it at entry so the caller cannot get a weaker policy than requested.
  check("VL22. path.validate with a misspelled ctPolicy key (minSCTs) -> path/bad-input, not silently defaulted",
    (await code(function () { return pki.path.validate([certB], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minSCTs: 2 } }); })) === "path/bad-input");

  // VL23 (P2a): a mis-shaped shared entry (valid entryType, missing required fields) is a caller error
  // that throws up front, even when the SCT list is empty (never a verdict rendered without examining it).
  check("VL23. entry entryType:1 missing its fields, empty list -> throws ct/bad-input (not a verdict)",
    (await code(function () { return pki.ct.verifySctList({ entryType: 1 }, [], listAB, { certNotAfter: NOT_AFTER }); })) === "ct/bad-input");

  // VL24 (P2b): an invalid CT policy value reaches verifySctList through the path gate; the path
  // boundary surfaces it as path/bad-input, never leaking the ct/* domain code of a layer not called.
  check("VL24. path.validate with an invalid ctPolicy value (minScts:0) -> path/bad-input, not a leaked ct/*",
    (await code(function () { return pki.path.validate([certB], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minScts: 0 } }); })) === "path/bad-input");

  // VL25 (P2): the bare { subjectPublicKeyInfo: { bytes } } issuer form whose bytes is not a BufferSource
  // fails through the typed CT error contract, not a native TypeError from the downstream SHA-256 update.
  check("VL25. x509CertEntry with a bare issuer whose bytes is not a BufferSource -> ct/bad-cert-entry",
    (await code(function () { return pki.ct.x509CertEntry(certB, { subjectPublicKeyInfo: { bytes: "not bytes" } }); })) === "ct/bad-cert-entry");

  // VL26: when the SCT-list is the certificate's ONLY extension, removing it leaves no extensions, so the
  // optional [3] field is dropped entirely (an empty [3] SEQUENCE {} is invalid, RFC 5280 Extensions is
  // 1..MAX). R is a v3 TBS with no extensions (certB's fields minus its [3]); the SCT signs over R.
  var certBNode = pki.asn1.decode(pki.schema.x509.parse(certB).tbsBytes);
  var noExtKids = [];
  for (var ci = 0; ci < certBNode.children.length; ci++) { var ch = certBNode.children[ci]; if (!(ch.tagClass === "context" && ch.tagNumber === 3)) noExtKids.push(pki.asn1.build.raw(ch.bytes)); }
  var R = pki.asn1.build.sequence(noExtKids);
  var rSct = { version: 0, logId: logIdE, logIdHex: logIdE.toString("hex"), timestamp: 1700000000000n, hashAlg: 4, sigAlg: 3,
    signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 3, signatureName: "ecdsa" }, signature: null, extensions: Buffer.alloc(0) };
  rSct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData({ entryType: 1, tbsCertificate: R, issuerKeyHash: issuerKeyHash }, rSct), logKp.privateKey);
  var rSctExt = pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("signedCertificateTimestampList")), pki.asn1.build.octetString(pki.ct.encodeSctList([rSct]))]);
  var onlySctCert = await pki.x509.sign(Object.assign({}, common, { extensions: [rSctExt] }), issuerArg);
  var re26 = pki.ct.x509CertEntry(onlySctCert, caCert);
  var re26Node = pki.asn1.decode(re26.tbsCertificate);
  var hasExt3 = false;
  for (var hi = 0; hi < re26Node.children.length; hi++) if (re26Node.children[hi].tagClass === "context" && re26Node.children[hi].tagNumber === 3) hasExt3 = true;
  check("VL26. SCT-list as the only extension -> the extensions field is dropped (no empty [3]) and the SCT verifies",
    hasExt3 === false && Buffer.compare(re26.tbsCertificate, R) === 0 && (await pki.ct.verifySct(re26, rSct, logSpki)) === true);

  // VL27 (RFC 6962 sec. 5.2): a future-dated SCT is rejected even with a valid signature, and not counted.
  var futureSct = signedSct(opA, BigInt(Date.parse("2030-01-01T00:00:00Z")));
  var v27 = await pki.ct.verifySctList(ENTRY, [signedSct(opB), futureSct], listAB, { certNotAfter: NOT_AFTER, at: new Date("2026-06-01T00:00:00Z") });
  check("VL27. a future-dated SCT is rejected (ct/future-timestamp) and not counted; a valid sibling counts",
    v27.validScts === 1 && v27.results[1].valid === false && v27.results[1].code === "ct/future-timestamp" && v27.results[0].valid === true);

  // VL28: the path gate forwards opts.time as `at`, so a certificate whose embedded SCT is dated after the
  // validation time fails the CT gate. The SCT signs over the reconstruction (tbsA) at a future timestamp.
  var certFutSct = { version: 0, logId: logIdE, logIdHex: logIdE.toString("hex"), timestamp: BigInt(Date.parse("2027-01-01T00:00:00Z")), hashAlg: 4, sigAlg: 3,
    signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 3, signatureName: "ecdsa" }, signature: null, extensions: Buffer.alloc(0) };
  certFutSct.signature = crypto.sign("sha256", pki.ct.reconstructSignedData({ entryType: 1, tbsCertificate: tbsA, issuerKeyHash: issuerKeyHash }, certFutSct), logKp.privateKey);
  var futSctExt = pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("signedCertificateTimestampList")), pki.asn1.build.octetString(pki.ct.encodeSctList([certFutSct]))]);
  var certFuture = await pki.x509.sign(Object.assign({}, common, { extensions: [futSctExt, otherExt] }), issuerArg);
  var rFut = await pki.path.validate([certFuture], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minScts: 1, minOperators: 1 } });
  var cFut = ctCheckOf(rFut);
  check("VL28. the path gate rejects a future-dated SCT (opts.time forwarded as at) -> ct ok:false, path invalid",
    cFut !== null && cFut.ok === false && rFut.valid === false);

  // VL29 (DoS bound): a caller-supplied array over the SCT_MAX_COUNT cap (256) is refused before any
  // verification, matching the bound parseSctList enforces on wire input.
  var tooMany = new Array(257).fill(signedSct(opA));
  check("VL29. an SCT array over the SCT_MAX_COUNT cap -> ct/too-many-scts (no unbounded verification)",
    (await code(function () { return pki.ct.verifySctList(ENTRY, tooMany, listAB, { certNotAfter: NOT_AFTER }); })) === "ct/too-many-scts");

  // VL30: the CT configuration is validated independent of the target certificate -- a cert with no SCT
  // extension plus a bad policy value is path/bad-input at entry, not masked as path/ct-required.
  check("VL30. no-SCT cert + an invalid ctPolicy value -> path/bad-input (config validated before the cert)",
    (await code(function () { return pki.path.validate([certA], { trustAnchor: caCert, time: atTime, ctLogList: ctLogList, ctPolicy: { minScts: 0 } }); })) === "path/bad-input");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
