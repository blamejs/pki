// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the Chrome Root Program Policy profile in pki.lint.certificate. RED conformance
 * vectors written BEFORE the rules, each driving the shipped verb and asserting the finding id.
 *
 * Every row is derived from Chrome Root Program Policy Version 1.8, read from the markdown the
 * policy is maintained in. Like mozilla-root and unlike every other profile here, this one is NAMED
 * and never detected: a root program's requirements apply because the certificate chains to a root
 * in that store, which the certificate does not state.
 *
 *   C1-C4    the profile is named, never detected, and a root is not a subordinate CA
 *   C5-C11   the sec. 1.3.2 subordinate CA extended key usage rules
 *   C12-C17  the sec. 1.3.2 subscriber rules, gated on the issuance date
 *   C18-C21  the sec. 1.3.1.3 subordinate CA validity ceiling
 *   C22-C27  the sec. 1.3.1.2 root CA term limit
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-04-01T00:00:00Z");
var NA = new Date("2026-06-01T00:00:00Z");
var SUBORDINATE_NA = new Date("2029-04-01T00:00:00Z");
var SUBSCRIBER_CUTOVER = new Date("2027-03-15T00:00:00Z");
var BEFORE_CUTOVER = new Date("2027-03-14T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function findingsOf(rep, id) {
  return rep.findings.filter(function (f) { return f.id === id; });
}
function sevOf(rep, id) {
  var f = findingsOf(rep, id)[0];
  return f && f.severity;
}
function lint(der) { return pki.lint.certificate(der, { profile: "chrome-root" }); }

async function run() {
  var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ecPriv = await pki.key.export(ec.privateKey), ecPub = await pki.key.export(ec.publicKey);

  var issuingCa = await pki.x509.sign({ subject: [{ commonName: "Chrome Issuing CA" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv });

  /** A SUBORDINATE CA certificate: a CA issued by another name, which is what sec. 1.3.2 governs.
   *  The default window runs to the three-year ceiling, which also puts it past the date the
   *  clause begins to reach a certificate. */
  async function subordinate(ekus, window) {
    var w = window || {};
    var e = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] };
    if (ekus) e.extendedKeyUsage = ekus;
    return pki.x509.sign({ subject: [{ commonName: "A Subordinate CA" }], subjectPublicKey: ecPub,
      notBefore: w.notBefore || NB, notAfter: w.notAfter || SUBORDINATE_NA, extensions: e },
      { cert: issuingCa, key: ecPriv });
  }
  /** A SUBSCRIBER certificate, which sec. 1.3.2 gates on the issuance date. */
  async function subscriber(ekus, notBefore) {
    var nb = notBefore || NB;
    var e = {};
    if (ekus) e.extendedKeyUsage = ekus;
    return pki.x509.sign({ subject: [{ commonName: "A Subscriber" }], subjectPublicKey: ecPub,
      notBefore: nb, notAfter: new Date(nb.getTime() + 86400000 * 60), extensions: e },
      { cert: issuingCa, key: ecPriv });
  }
  /** A self-signed ROOT, which sec. 1.3.1.2 governs and sec. 1.3.2 does not. */
  async function root(notBefore, notAfter) {
    return pki.x509.sign({ subject: [{ commonName: "A Chrome Root" }], subjectPublicKey: ecPub,
      notBefore: notBefore, notAfter: notAfter,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv });
  }

  // ---- C1-C4: named, never detected ----------------------------------------------------------
  var conforming = await subordinate(["serverAuth"]);
  var conformingRep = lint(conforming);
  var conformingErrors = conformingRep.findings.filter(function (f) {
    return f.source === "chrome-root" && (f.severity === "error" || f.severity === "fatal");
  });
  check("C1. CONTROL: a conforming subordinate CA reports nothing at error or worse (" +
    conformingErrors.map(function (f) { return f.id; }).join(",") + ")",
    conformingErrors.length === 0);
  check("C2. no row runs unless the profile is named",
    pki.lint.certificate(conforming).ran.every(function (id) {
      return id.indexOf("lint/chrome-root/") !== 0;
    }) && conformingRep.ran.some(function (id) { return id.indexOf("lint/chrome-root/") === 0; }));
  check("C3. rules() enumerates the chrome-root rows",
    pki.lint.rules().filter(function (r) { return r.source === "chrome-root"; }).length >= 9);
  // A clause naming subordinate CAs does not govern a root. mozilla-root took two review rounds to
  // stop reporting one, so the root control comes before the rows it must stay silent on.
  var bareRoot = await root(new Date("2020-06-01T00:00:00Z"), new Date("2030-06-01T00:00:00Z"));
  var bareRootIds = ids(lint(bareRoot)).filter(function (id) {
    return id.indexOf("lint/chrome-root/subordinate-ca-") === 0 ||
      id.indexOf("lint/chrome-root/subscriber-") === 0;
  });
  check("C4. a self-signed root draws no subordinate CA row and no subscriber row (" +
    bareRootIds.join(",") + ")", bareRootIds.length === 0);

  // ---- C5-C11: sec. 1.3.2, subordinate CA extended key usage ---------------------------------
  // Both admitted forms include the extension, so its absence breaks the clause either side of the
  // CCADB disclosure cutover and the row carries no date.
  check("C5. a subordinate CA with no extKeyUsage is reported",
    has(lint(await subordinate(null)), "lint/chrome-root/subordinate-ca-eku-missing"));
  // Both forms require id-kp-serverAuth in it, so a subordinate CA naming only id-kp-clientAuth
  // breaks the clause outright rather than depending on when it was disclosed.
  var clientOnly = lint(await subordinate(["clientAuth"]));
  check("C6. a subordinate CA whose extKeyUsage omits id-kp-serverAuth is reported",
    has(clientOnly, "lint/chrome-root/subordinate-ca-eku-server-auth-missing"));
  // A purpose outside the two is admitted by neither form.
  var withEmail = lint(await subordinate(["serverAuth", "emailProtection"]));
  var emailFindings = findingsOf(withEmail, "lint/chrome-root/subordinate-ca-eku-not-tls");
  check("C7. a subordinate CA naming a purpose outside id-kp-serverAuth and id-kp-clientAuth is " +
    "reported, naming the purpose",
    emailFindings.length === 1 && emailFindings[0].context.purpose === "emailProtection");
  check("C8. anyExtendedKeyUsage is such a purpose",
    findingsOf(lint(await subordinate(["serverAuth", "anyExtendedKeyUsage"])),
      "lint/chrome-root/subordinate-ca-eku-not-tls")
      .some(function (f) { return f.context.purpose === "anyExtendedKeyUsage"; }));
  // Two offending purposes draw two findings, not a single boolean that cannot tell them apart.
  check("C9. each offending purpose draws its own finding",
    findingsOf(lint(await subordinate(["serverAuth", "emailProtection", "codeSigning"])),
      "lint/chrome-root/subordinate-ca-eku-not-tls").length === 2);
  // Form (b) is open only to a subordinate CA disclosed to the CCADB before the cutover, and a
  // certificate does not carry its disclosure date, so the row reports below error.
  var serverAndClient = lint(await subordinate(["serverAuth", "clientAuth"]));
  check("C10. a subordinate CA naming id-kp-clientAuth is reported at warn and at nothing worse",
    sevOf(serverAndClient, "lint/chrome-root/subordinate-ca-eku-client-auth") === "warn" &&
    !has(serverAndClient, "lint/chrome-root/subordinate-ca-eku-not-tls") &&
    !has(serverAndClient, "lint/chrome-root/subordinate-ca-eku-server-auth-missing"));
  var soloIds = ids(lint(await subordinate(["serverAuth"]))).filter(function (id) {
    return id.indexOf("lint/chrome-root/subordinate-ca-eku-") === 0;
  });
  check("C11. CONTROL: id-kp-serverAuth alone draws none of the four (" + soloIds.join(",") + ")",
    soloIds.length === 0);
  // The clause reaches a NON-TLS branch, and that is its purpose rather than an overreach: it
  // governs "all corresponding unexpired and unrevoked subordinate CA certificates operated
  // beneath an existing root included in the Chrome Root Store", and it exists "to align all PKI
  // hierarchies included in the Chrome Root Store on the principle of serving only TLS server
  // authentication use cases". A code signing intermediate beneath such a root is the
  // multi-purpose hierarchy the section phases out, so it is reported on both counts. Pinned so
  // the reading is a decision rather than a drift.
  var codeSigningSub = lint(await subordinate(["codeSigning"]));
  check("C11b. a code signing subordinate CA is reported, which is what this clause phases out",
    has(codeSigningSub, "lint/chrome-root/subordinate-ca-eku-server-auth-missing") &&
    findingsOf(codeSigningSub, "lint/chrome-root/subordinate-ca-eku-not-tls")
      .some(function (f) { return f.context.purpose === "codeSigning"; }));
  // The clause reaches "all corresponding UNEXPIRED and unrevoked subordinate CA certificates",
  // and its phase-out begins on 15 June 2026. A certificate already expired on that day was never
  // among the unexpired ones it names, whatever its extended key usage.
  var expiredSub = lint(await subordinate(null, { notBefore: new Date("2024-01-01T00:00:00Z"),
    notAfter: new Date("2026-06-14T00:00:00Z") }));
  var liveSub = lint(await subordinate(null, { notBefore: new Date("2024-01-01T00:00:00Z"),
    notAfter: new Date("2026-06-15T00:00:00Z") }));
  check("C11c. a subordinate CA expired before the clause takes effect is not reported",
    !has(expiredSub, "lint/chrome-root/subordinate-ca-eku-missing") &&
    has(liveSub, "lint/chrome-root/subordinate-ca-eku-missing"));

  // ---- C12-C17: sec. 1.3.2, subscriber certificates, gated on the issuance date ---------------
  var earlyIds = ids(lint(await subscriber(null, BEFORE_CUTOVER))).filter(function (id) {
    return id.indexOf("lint/chrome-root/subscriber-") === 0;
  });
  check("C12. CONTROL: a subscriber issued before 15 March 2027 draws no subscriber row (" +
    earlyIds.join(",") + ")", earlyIds.length === 0);
  check("C13. a subscriber issued on 15 March 2027 with no extKeyUsage is reported",
    has(lint(await subscriber(null, SUBSCRIBER_CUTOVER)), "lint/chrome-root/subscriber-eku-missing"));
  var lateClient = lint(await subscriber(["clientAuth"], SUBSCRIBER_CUTOVER));
  check("C14. a subscriber's extKeyUsage omitting id-kp-serverAuth is reported",
    has(lateClient, "lint/chrome-root/subscriber-eku-server-auth-missing"));
  // The subscriber form admits id-kp-serverAuth alone, so id-kp-clientAuth is an error here and a
  // warning on a subordinate CA. The same purpose, graded by which clause reads it.
  check("C15. id-kp-clientAuth on a subscriber is an error, unlike on a subordinate CA",
    findingsOf(lateClient, "lint/chrome-root/subscriber-eku-not-server-auth")
      .some(function (f) { return f.context.purpose === "clientAuth"; }) &&
    sevOf(lateClient, "lint/chrome-root/subscriber-eku-not-server-auth") === "error");
  check("C16. each offending subscriber purpose draws its own finding",
    findingsOf(lint(await subscriber(["serverAuth", "clientAuth", "emailProtection"],
      SUBSCRIBER_CUTOVER)), "lint/chrome-root/subscriber-eku-not-server-auth").length === 2);
  var lateSoloIds = ids(lint(await subscriber(["serverAuth"], SUBSCRIBER_CUTOVER)))
    .filter(function (id) { return id.indexOf("lint/chrome-root/subscriber-") === 0; });
  check("C17. CONTROL: id-kp-serverAuth alone draws none of the three (" + lateSoloIds.join(",") +
    ")", lateSoloIds.length === 0);
  // The clause governs a SUBSCRIBER certificate, which is not every end entity. A delegated OCSP
  // responder is an end entity with its own profile in the Baseline Requirements that sec. 1.1.1
  // binds, and that profile requires id-kp-OCSPSigning and no other purpose, so holding one to
  // id-kp-serverAuth alone would report a conforming responder.
  var responderIds = ids(lint(await subscriber(["ocspSigning"], SUBSCRIBER_CUTOVER)))
    .filter(function (id) { return id.indexOf("lint/chrome-root/subscriber-") === 0; });
  check("C17b. a delegated OCSP responder is not read as a subscriber certificate (" +
    responderIds.join(",") + ")", responderIds.length === 0);
  // The responder profile asks for id-kp-OCSPSigning and NO other purpose, so a certificate naming
  // it beside others is not one. Exempting on the purpose being present rather than alone would
  // let a certificate buy its way out of every row by adding it, and no other row here reads the
  // responder profile: naming chrome-root does not run the cabf-tls set.
  var mixedResponder = lint(await subscriber(["serverAuth", "clientAuth", "ocspSigning"],
    SUBSCRIBER_CUTOVER));
  check("C17c. a certificate naming id-kp-OCSPSigning beside other purposes is still a subscriber",
    findingsOf(mixedResponder, "lint/chrome-root/subscriber-eku-not-server-auth")
      .map(function (f) { return f.context.purpose; }).sort().join(",") ===
      "clientAuth,ocspSigning");

  // ---- C18-C21: sec. 1.3.1.3, the three-year subordinate CA ceiling --------------------------
  var VAL_ID = "lint/chrome-root/subordinate-ca-validity-over-three-years";
  var atCeiling = await subordinate(["serverAuth"], { notBefore: new Date("2026-04-01T00:00:00Z"),
    notAfter: new Date("2029-04-01T00:00:00Z") });
  check("C18. CONTROL: a subordinate CA at exactly three years is not reported", !has(lint(atCeiling), VAL_ID));
  var overCeiling = await subordinate(["serverAuth"], { notBefore: new Date("2026-04-01T00:00:00Z"),
    notAfter: new Date("2029-04-02T00:00:00Z") });
  check("C19. a subordinate CA one day past three years is reported at warn",
    sevOf(lint(overCeiling), VAL_ID) === "warn");
  // A ceiling stated in years is measured in months, so a 29 February notBefore clamps to the 28th
  // rather than sliding into March.
  var leapAt = await subordinate(["serverAuth"], { notBefore: new Date("2028-02-29T00:00:00Z"),
    notAfter: new Date("2031-02-28T00:00:00Z") });
  var leapOver = await subordinate(["serverAuth"], { notBefore: new Date("2028-02-29T00:00:00Z"),
    notAfter: new Date("2031-03-01T00:00:00Z") });
  check("C20. a 29 February notBefore clamps to 28 February three years on",
    !has(lint(leapAt), VAL_ID) && has(lint(leapOver), VAL_ID));
  check("C21. CONTROL: the ceiling reads a subordinate CA and not a subscriber",
    !has(lint(await subscriber(["serverAuth"], new Date("2026-04-01T00:00:00Z"))), VAL_ID));

  // ---- C22-C27: sec. 1.3.1.2, the root CA term limit -----------------------------------------
  var TERM_ID = "lint/chrome-root/self-signed-ca-term-limit-outlived";
  // The determined key date is at or before this certificate's own notBefore, and the schedule is
  // monotone, so the removal date computed from notBefore is the LATEST the removal can fall. A
  // notAfter past it therefore outlives the term whatever earlier certificate carries the key.
  var old2007 = lint(await root(new Date("2007-06-01T00:00:00Z"), new Date("2027-01-01T00:00:00Z")));
  check("C22. a root outliving its scheduled removal is reported at notice, naming the date",
    sevOf(old2007, TERM_ID) === "notice" &&
    findingsOf(old2007, TERM_ID)[0].context.removal === "2026-04-15");
  check("C23. CONTROL: a root expiring before its scheduled removal is not reported",
    !has(lint(await root(new Date("2007-06-01T00:00:00Z"), new Date("2026-01-01T00:00:00Z"))), TERM_ID));
  var BRACKETS = [
    ["2005-06-01T00:00:00Z", "2026-04-15"],
    ["2007-12-31T00:00:00Z", "2026-04-15"],
    ["2008-01-01T00:00:00Z", "2027-04-15"],
    ["2009-12-31T00:00:00Z", "2027-04-15"],
    ["2010-01-01T00:00:00Z", "2028-04-15"],
    ["2011-12-31T00:00:00Z", "2028-04-15"],
    ["2012-01-01T00:00:00Z", "2029-04-15"],
    ["2014-04-14T00:00:00Z", "2029-04-15"],
    ["2014-04-15T00:00:00Z", "2029-04-15"],
    ["2020-06-01T00:00:00Z", "2035-06-01"],
  ];
  var bracketDates = [];
  for (var bi = 0; bi < BRACKETS.length; bi++) {
    var r = lint(await root(new Date(BRACKETS[bi][0]), new Date("2060-01-01T00:00:00Z")));
    var f = findingsOf(r, TERM_ID)[0];
    bracketDates.push(f ? f.context.removal : "none");
  }
  check("C24. every row of the schedule maps its bracket to its removal date (" +
    bracketDates.join(",") + ")",
    bracketDates.length === BRACKETS.length && BRACKETS.every(function (row, i) {
      return bracketDates[i] === row[1];
    }));
  // The table's first bracket opens on 1 January 2006 and it gives no row for an older key. An
  // older key is removed no later than a 2006 one, so folding it into the first bracket keeps the
  // sound direction, which C24's first row pins.
  check("C25. the boundary day the table leaves unstated lands on one date either way",
    bracketDates[7] === bracketDates[8]);
  check("C26. CONTROL: the term limit reads a self-signed root and not a subordinate CA",
    !has(lint(await subordinate(["serverAuth"], { notBefore: new Date("2005-06-01T00:00:00Z"),
      notAfter: new Date("2060-01-01T00:00:00Z") })), TERM_ID));
  check("C27. CONTROL: the term limit reads a CA certificate and not a subscriber",
    !has(lint(await subscriber(["serverAuth"], new Date("2005-06-01T00:00:00Z"))), TERM_ID));

  // ---- C28-C30: a certificate issued in its own name is not proof of a root ------------------
  // A ROLLOVER CA is reissued in its own name with a NEW key and signed by its predecessor, so the
  // names match while the authorityKeyIdentifier holds a key that is not this certificate's own.
  // Section 1.3.1.2 governs a root, which this is not.
  var rollKeys = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var rollPub = await pki.key.export(rollKeys.publicKey);
  var predecessor = await pki.x509.sign({ subject: [{ commonName: "A Rollover CA" }],
    subjectPublicKey: ecPub, notBefore: new Date("2000-01-01T00:00:00Z"),
    notAfter: new Date("2060-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv });
  var rollover = await pki.x509.sign({ subject: [{ commonName: "A Rollover CA" }],
    subjectPublicKey: rollPub, notBefore: new Date("2005-06-01T00:00:00Z"),
    notAfter: new Date("2060-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } },
    { cert: predecessor, key: ecPriv });
  check("C28. a rollover CA reissued in its own name is not held to the root term limit",
    !has(lint(rollover), TERM_ID));
  // A self-signed root either omits the extension, which RFC 5280 sec. 4.2.1.1 permits only there,
  // or names its own subjectKeyIdentifier in it. Both are still reported.
  var rootNoAki = await root(new Date("2005-06-01T00:00:00Z"), new Date("2060-01-01T00:00:00Z"));
  var rootWithAki = await pki.x509.sign({ subject: [{ commonName: "A Chrome Root" }],
    subjectPublicKey: ecPub, notBefore: new Date("2005-06-01T00:00:00Z"),
    notAfter: new Date("2060-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      authorityKeyIdentifier: true } }, { key: ecPriv });
  check("C29. CONTROL: a self-signed root is reported whether or not it carries the extension",
    has(lint(rootNoAki), TERM_ID) && has(lint(rootWithAki), TERM_ID));
  // The under-report is a stated contract rather than an accident: a rollover CA is governed by
  // section 1.3.2, and the names do not tell it from a root, so it is passed over on both sides.
  var rolloverIds = ids(lint(rollover)).filter(function (id) {
    return id.indexOf("lint/chrome-root/") === 0;
  });
  check("C30. a rollover CA draws no chrome-root row at all, which is the stated limit (" +
    rolloverIds.join(",") + ")", rolloverIds.length === 0);
  // A keyIdentifier with no readable subjectKeyIdentifier beside it settles nothing, and the row
  // rests on settling it. The signer refuses to build a CA without the extension, since RFC 5280
  // sec. 4.2.1.2 requires one, so the fixture is cut by hand from a certificate it did build.
  var SKI_OID_DER = b.oid(pki.oid.byName("subjectKeyIdentifier"));
  var brokenSki = surgery.patch(rollover, function (n) {
    if (!n.constructed || n.tagNumber !== 16 || !n.children || n.children.length !== 2) return undefined;
    if (!SKI_OID_DER.equals(n.children[0].bytes)) return undefined;
    return b.sequence([b.raw(SKI_OID_DER), b.octetString(b.sequence([]))]);
  });
  var brokenRep = lint(brokenSki);
  check("C31. an unreadable subjectKeyIdentifier beside a keyIdentifier is not read as a root",
    !has(brokenRep, TERM_ID) &&
    has(brokenRep, "lint/rfc5280/extension-undecodable"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
