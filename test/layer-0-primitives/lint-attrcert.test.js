// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.lint.attrcert, the RFC 5755 profile. RED conformance vectors written BEFORE the
 * verb.
 *
 * Third of the three verbs this item adds, and the same shape as the other two: the attribute
 * certificate parser already refuses most of section 4.2, so R4 pins that list and the rows cover
 * what survives it.
 *
 *   R1-R3   the verb's shape: a clean control, the registry, hostile bytes
 *   R4      the clauses the parser settles, asserted against its codes rather than against rows
 *   R5-R7   sec. 4.3, the criticality each extension the profile defines must carry
 *   R8      sec. 4.2.9, a critical extension the profile does not define
 *   R9      sec. 4.2.2, a Holder naming more than one option
 *   R10     sec. 4.2.8, an issuerUniqueID
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");
var ROLE = { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } };

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function findingsOf(rep, id) {
  return rep.findings.filter(function (f) { return f.id === id; });
}
function sevOf(rep, id) {
  var f = findingsOf(rep, id)[0];
  return f && f.severity;
}
function acIds(rep) {
  return ids(rep).filter(function (id) { return id.indexOf("lint/rfc5755/") === 0; });
}

/** Rewrite one Extension inside the AttributeCertificateInfo, found by its extnID. `critical` is
 *  true, false, or null to write the DEFAULT FALSE omission the DER requires. */
function reExtension(der, oidName, opts) {
  var wanted = b.oid(pki.oid.byName(oidName));
  return surgery.patch(der, function (n) {
    if (!n.constructed || n.tagNumber !== 16 || !n.children || !n.children.length) return undefined;
    if (!wanted.equals(n.children[0].bytes)) return undefined;
    var value = n.children[n.children.length - 1];
    var kids = [b.raw(opts.oid ? b.oid(opts.oid) : wanted)];
    if (opts.critical === true) kids.push(b.boolean(true));
    kids.push(opts.value ? b.octetString(opts.value) : b.raw(value.bytes));
    return b.sequence(kids);
  });
}

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var key = await pki.key.export(ed.privateKey), spki = await pki.key.export(ed.publicKey);
  var aa = { name: "CN=Example AA", publicKey: spki, key: key };
  function spec(over) {
    return Object.assign({ holder: { entityName: { directoryName: "CN=Alice" } },
      notBeforeTime: NB, notAfterTime: NA, attributes: ROLE }, over || {});
  }

  // ---- R1-R3: the verb's shape ----------------------------------------------------------------
  var clean = await pki.attrcert.sign(spec({ extensions: {
    auditIdentity: Buffer.from("audit-tag"), authorityKeyIdentifier: true } }), aa);
  var cleanRep = pki.lint.attrcert(clean);
  check("R1. CONTROL: a conforming attribute certificate reports nothing (" +
    acIds(cleanRep).join(",") + ")", acIds(cleanRep).length === 0);
  check("R2. rules() enumerates the rfc5755 rows",
    pki.lint.rules().filter(function (r) { return r.source === "rfc5755"; }).length >= 4 &&
    pki.lint.rules("rfc5755", "attrcert").length >= 4);
  var hostile = pki.lint.attrcert(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]));
  check("R3. hostile bytes are a fatal finding rather than a throw",
    hostile.findings.length === 1 && hostile.findings[0].id === "lint/unparseable" &&
    hostile.findings[0].severity === "fatal" &&
    typeof hostile.findings[0].context.code === "string");

  // ---- R4: what the parser settles, so no row is written for it -------------------------------
  // Each is an RFC 5755 sec. 4.2 MUST the parser refuses. The producer refuses some of them first,
  // which is the same verdict reaching the operator one step earlier.
  var settled = [];
  settled.push(["a repeated attribute type",
    await pki.attrcert.sign(spec({ attributes: [ROLE, ROLE] }), aa).then(
      function (d) { return d; }, function (e) { return e; })]);
  settled.push(["a serial number wider than 20 octets",
    await pki.attrcert.sign(spec({ serialNumber: (1n << 200n) + 1n }), aa).then(
      function (d) { return d; }, function (e) { return e; })]);
  settled.push(["no attributes at all",
    await pki.attrcert.sign(spec({ attributes: [] }), aa).then(
      function (d) { return d; }, function (e) { return e; })]);
  var settledVerdicts = settled.map(function (c) {
    if (!Buffer.isBuffer(c[1])) return c[1] && c[1].code ? "producer" : "unknown";
    var rep = pki.lint.attrcert(c[1]);
    if (rep.findings.length === 1 && rep.findings[0].id === "lint/unparseable") return "parser";
    return "row:" + acIds(rep).join("+");
  });
  check("R4. the clauses the parser settles reach an operator as a refusal, not as a row (" +
    settledVerdicts.join(",") + ")",
    settledVerdicts.length === 3 &&
    settledVerdicts.every(function (v) { return v === "parser" || v === "producer"; }));

  // ---- R5-R7: sec. 4.3, the criticality each extension must carry ------------------------------
  var CRIT_ID = "lint/rfc5755/extension-criticality";
  // "this extension MUST be critical" (sec. 4.3.1), written as the DEFAULT FALSE omission instead.
  var auditNotCritical = reExtension(clean, "acAuditIdentity", { critical: null });
  check("R5. an audit identity that is not critical is reported, naming the extension",
    sevOf(pki.lint.attrcert(auditNotCritical), CRIT_ID) === "error" &&
    findingsOf(pki.lint.attrcert(auditNotCritical), CRIT_ID)[0].context.extension === "acAuditIdentity");
  // "criticality MUST be FALSE" (sec. 4.3.3), written as an explicit TRUE instead.
  var akiCritical = reExtension(clean, "authorityKeyIdentifier", { critical: true });
  check("R6. an authorityKeyIdentifier marked critical is reported",
    findingsOf(pki.lint.attrcert(akiCritical), CRIT_ID)
      .some(function (f) { return f.context.extension === "authorityKeyIdentifier"; }));
  check("R7. CONTROL: the criticality the builder writes is the one each clause states",
    !has(cleanRep, CRIT_ID));

  // ---- R8: sec. 4.2.9, a critical extension the profile does not define -----------------------
  // "If any other critical extension is used, the AC does not conform to this profile." The audit
  // identity is already critical, so relabeling it with an identifier this profile does not know
  // leaves a critical extension that is not one of section 4.3's.
  var unknownCritical = reExtension(clean, "acAuditIdentity",
    { critical: true, oid: pki.oid.byName("subjectDirectoryAttributes") });
  check("R8. a critical extension outside the profile is reported",
    sevOf(pki.lint.attrcert(unknownCritical),
      "lint/rfc5755/critical-extension-outside-profile") === "error");
  // What counts as "other" is membership in the profile, not whether this toolkit happens to
  // decode the value. AAControls is decoded here and section 7.4 puts it in "CA and AC issuer
  // PKCs", not in an attribute certificate, so a critical one is outside this profile.
  var criticalAaControls = reExtension(clean, "acAuditIdentity",
    { critical: true, oid: pki.oid.byName("aaControls"), value: b.sequence([]) });
  check("R8c. a critical extension the parser can decode but the profile does not define is reported",
    has(pki.lint.attrcert(criticalAaControls),
      "lint/rfc5755/critical-extension-outside-profile"));
  // ProxyInfo is the other way round: section 7.2 defines it for an attribute certificate and
  // fixes its criticality at TRUE, so a critical one is inside the profile.
  var criticalProxying = reExtension(clean, "acAuditIdentity",
    { critical: true, oid: pki.oid.byName("acProxying"),
      value: b.sequence([b.sequence([b.explicit(0, b.sequence([
        b.contextConstructed(0, b.contextPrimitive(2, Buffer.from("t.example")))]))])]) });
  check("R8d. CONTROL: an extension section 7.2 defines is inside the profile",
    !has(pki.lint.attrcert(criticalProxying),
      "lint/rfc5755/critical-extension-outside-profile"));
  check("R8b. CONTROL: the same extension left non-critical is not reported",
    !has(pki.lint.attrcert(reExtension(clean, "acAuditIdentity",
      { critical: null, oid: pki.oid.byName("subjectDirectoryAttributes") })),
    "lint/rfc5755/critical-extension-outside-profile"));

  // ---- R9: sec. 4.2.2, a Holder naming more than one option -----------------------------------
  // The builder refuses a Holder naming two forms, which is it keeping to the clause, so the
  // fixture is cut by hand: a [0] baseCertificateID is put in front of the [1] entityName the
  // builder wrote, reusing that entityName's own GeneralNames as the IssuerSerial issuer.
  var twoOptions = surgery.patch(clean, function (n, path) {
    // the Holder SEQUENCE: AttributeCertificateInfo field 1, inside the AC's field 0.
    if (path.length !== 2 || path[0].index !== 0 || path[1].index !== 1) return undefined;
    if (n.tagNumber !== 16 || !n.children || !n.children.length) return undefined;
    var entityName = n.children[0];
    if (entityName.tagClass !== "context" || entityName.tagNumber !== 1) return undefined;
    // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial INTEGER }, reusing the names the
    // entityName already carries, which the [1] wrapper holds implicitly.
    var issuer = b.sequence((entityName.children || []).map(function (c) { return b.raw(c.bytes); }));
    var baseId = b.implicit(0, b.sequence([b.raw(issuer), b.integer(7n)]), true);
    return b.sequence([b.raw(baseId), b.raw(entityName.bytes)]);
  });
  check("R9. a Holder naming more than one option is reported at warn",
    sevOf(pki.lint.attrcert(twoOptions), "lint/rfc5755/holder-multiple-options") === "warn" &&
    !has(cleanRep, "lint/rfc5755/holder-multiple-options"));

  // ---- R10: sec. 4.2.8, an issuerUniqueID ------------------------------------------------------
  // "This field MUST NOT be used unless it is also used in the AC issuer's PKC", which is a fact
  // about another certificate, so the row warns and names the condition. The builder writes no
  // such field, so the fixture inserts one before the extensions.
  var withUid = surgery.patch(clean, function (n, path) {
    if (path.length !== 1 || path[0].index !== 0 || n.tagNumber !== 16 || !n.children) return undefined;
    var kids = n.children.map(function (c) { return b.raw(c.bytes); });
    kids.splice(kids.length - 1, 0, b.bitString(Buffer.from([0xa5]), 0));
    return b.sequence(kids);
  });
  check("R10. an issuerUniqueID is reported at warn",
    sevOf(pki.lint.attrcert(withUid), "lint/rfc5755/issuer-unique-id-present") === "warn" &&
    !has(cleanRep, "lint/rfc5755/issuer-unique-id-present"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
