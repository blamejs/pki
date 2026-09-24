// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the Apple Root Program Policy profile in pki.lint.certificate. RED conformance vectors
 * written BEFORE the rules, each driving the shipped verb and asserting the finding id.
 *
 * Every row is derived from Apple Root Program Policy version 2.0, read from the markdown it is
 * maintained in. Like the other three root programs, the profile is NAMED and never detected.
 *
 *   A1-A5    the profile is named, and its three scopes do not leak into each other
 *   A6-A8    sec. 1.5, the root key floor
 *   A9-A16   sec. 1.7 and appendix A, the subordinate CA trust purpose rules
 *   A17-A20  appendix A and sec. 2.3, the end entity rules
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

var BEFORE_EKU = new Date("2026-07-31T00:00:00Z");
var EKU_FROM = new Date("2026-08-01T00:00:00Z");
var SMIME_FROM = new Date("2027-02-01T00:00:00Z");
var BEFORE_SINGLE = new Date("2027-06-30T00:00:00Z");
var SINGLE_FROM = new Date("2027-07-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function findingsOf(rep, id) {
  return rep.findings.filter(function (f) { return f.id === id; });
}
function lint(der) { return pki.lint.certificate(der, { profile: "apple-root" }); }
function appleIds(rep, prefix) {
  return ids(rep).filter(function (id) { return id.indexOf("lint/apple-root/" + prefix) === 0; });
}

async function run() {
  var rsa4096 = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, hash: "SHA-256" });
  var rsa4096Priv = await pki.key.export(rsa4096.privateKey);
  var rsa4096Pub = await pki.key.export(rsa4096.publicKey);
  // A root is SELF-SIGNED, so each key it is built from needs both halves: the signer refuses a
  // self-signature whose subject key is not the one signing, which is the signer doing its job.
  async function pair(spec) {
    var k = await pki.key.generate(spec);
    return { pub: await pki.key.export(k.publicKey), priv: await pki.key.export(k.privateKey) };
  }
  var rsa2048 = await pair({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var p384 = await pair({ name: "ECDSA", namedCurve: "P-384" });
  var p256 = await pair({ name: "ECDSA", namedCurve: "P-256" });
  var p521 = await pair({ name: "ECDSA", namedCurve: "P-521" });
  var ed = await pair("Ed25519");

  var LATER = new Date("2032-01-01T00:00:00Z");

  /** A self-signed ROOT, which sec. 1.5 names. */
  async function root(key, notBefore) {
    var k = key || { pub: rsa4096Pub, priv: rsa4096Priv };
    return pki.x509.sign({ subject: [{ commonName: "An Apple Program Root" }],
      subjectPublicKey: k.pub, notBefore: notBefore || EKU_FROM, notAfter: LATER,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } },
    { key: k.priv });
  }
  var issuer = await root(null, new Date("2026-01-01T00:00:00Z"));

  /** A SUBORDINATE CA certificate, which sec. 1.7 governs by its signing date. */
  async function subordinate(ekus, notBefore) {
    var e = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] };
    if (ekus) e.extendedKeyUsage = ekus;
    return pki.x509.sign({ subject: [{ commonName: "An Apple Subordinate CA" }],
      subjectPublicKey: rsa4096Pub, notBefore: notBefore || EKU_FROM, notAfter: LATER,
      extensions: e }, { cert: issuer, key: rsa4096Priv });
  }
  /** A SUBSCRIBER certificate. */
  async function subscriber(over, notBefore) {
    var e = {};
    Object.keys(over || {}).forEach(function (n) {
      if (over[n] === undefined) delete e[n]; else e[n] = over[n];
    });
    return pki.x509.sign({ subject: [{ commonName: "An Apple Subscriber" }],
      subjectPublicKey: rsa4096Pub, notBefore: notBefore || EKU_FROM, notAfter: LATER,
      extensions: e }, { cert: issuer, key: rsa4096Priv });
  }

  // ---- A1-A5: named, never detected, and three scopes -----------------------------------------
  var conforming = await subordinate(["serverAuth"]);
  var conformingRep = lint(conforming);
  var conformingErrors = conformingRep.findings.filter(function (f) {
    return f.source === "apple-root" && (f.severity === "error" || f.severity === "fatal");
  });
  check("A1. CONTROL: a conforming subordinate CA reports nothing at error or worse (" +
    conformingErrors.map(function (f) { return f.id; }).join(",") + ")",
    conformingErrors.length === 0);
  check("A2. no row runs unless the profile is named",
    pki.lint.certificate(conforming).ran.every(function (id) {
      return id.indexOf("lint/apple-root/") !== 0;
    }) && conformingRep.ran.some(function (id) { return id.indexOf("lint/apple-root/") === 0; }));
  check("A3. rules() enumerates the apple-root rows",
    pki.lint.rules().filter(function (r) { return r.source === "apple-root"; }).length >= 7);
  var rootRep = lint(await root());
  check("A4. a root draws no subordinate CA row and no subscriber row (" +
    appleIds(rootRep, "subordinate-ca-").concat(appleIds(rootRep, "subscriber-")).join(",") + ")",
    appleIds(rootRep, "subordinate-ca-").length === 0 &&
    appleIds(rootRep, "subscriber-").length === 0);
  // A CA reissued in its own name under a new key carries one name in both fields and was signed by
  // its predecessor. The root row reads the key identifiers and passes over it; the subordinate
  // rows read the names and pass over it too, the same reading the other three profiles carry.
  var rollover = await pki.x509.sign({ subject: [{ commonName: "An Apple Program Root" }],
    subjectPublicKey: p384.pub, notBefore: EKU_FROM, notAfter: LATER,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } },
  { cert: issuer, key: rsa4096Priv });
  var rolloverIds = ids(lint(rollover)).filter(function (id) {
    return id.indexOf("lint/apple-root/") === 0;
  });
  check("A5. a CA reissued in its own name draws no apple-root row (" + rolloverIds.join(",") + ")",
    rolloverIds.length === 0);

  // ---- A6-A8: sec. 1.5, "a minimum key size of RSA 4096-bit or ECDSA 384-bit" ------------------
  var ROOT_KEY = "lint/apple-root/root-key-too-small";
  var floorAccepted = [];
  var okKeys = [{ pub: rsa4096Pub, priv: rsa4096Priv }, p384, p521];
  for (var ki = 0; ki < okKeys.length; ki++) {
    floorAccepted.push(!has(lint(await root(okKeys[ki])), ROOT_KEY));
  }
  check("A6. CONTROL: RSA 4096, P-384 and P-521 all meet the floor (" + floorAccepted.join(",") +
    ")", floorAccepted.length === 3 && floorAccepted.every(function (v) { return v === true; }));
  var belowFloor = [];
  var smallKeys = [rsa2048, p256];
  for (var si = 0; si < smallKeys.length; si++) {
    belowFloor.push(has(lint(await root(smallKeys[si])), ROOT_KEY));
  }
  check("A7. a root below the floor is reported (" + belowFloor.join(",") + ")",
    belowFloor.length === 2 && belowFloor.every(function (v) { return v === true; }));
  // The clause names RSA and ECDSA and no other family, so a key outside both is outside it.
  check("A8. a root whose key is of neither family is reported",
    has(lint(await root(ed)), ROOT_KEY));

  // ---- A9-A16: sec. 1.7 and appendix A, the subordinate CA rules -------------------------------
  var EKU_MISSING = "lint/apple-root/subordinate-ca-eku-missing";
  var EKU_ANY = "lint/apple-root/subordinate-ca-eku-any";
  var MIXES = "lint/apple-root/subordinate-ca-mixes-trust-purposes";
  var NOT_SINGLE = "lint/apple-root/subordinate-ca-not-single-purpose";
  check("A9. a subordinate CA signed on or after 2026-08-01 with no extKeyUsage is reported",
    has(lint(await subordinate(null, EKU_FROM)), EKU_MISSING) &&
    !has(lint(await subordinate(null, BEFORE_EKU)), EKU_MISSING));
  check("A10. a subordinate CA asserting anyExtendedKeyUsage is reported",
    has(lint(await subordinate(["anyExtendedKeyUsage"], EKU_FROM)), EKU_ANY) &&
    !has(lint(await subordinate(["anyExtendedKeyUsage"], BEFORE_EKU)), EKU_ANY));
  // Dedication is a SUBSET test, which appendix A states twice: a subordinate CA "MUST contain only
  // the EKU(s) specified for that Trust Purpose". So each purpose's own set, and each proper subset
  // of a two-EKU purpose, is dedicated.
  var DEDICATED = [["serverAuth"], ["serverAuth", "clientAuth"], ["emailProtection"],
    ["emailProtection", "clientAuth"], ["clientAuth"], ["timeStamping"],
    ["brandIndicatorforMessageIdentification"]];
  var dedicatedClean = [];
  for (var di = 0; di < DEDICATED.length; di++) {
    dedicatedClean.push(!has(lint(await subordinate(DEDICATED[di], EKU_FROM)), MIXES));
  }
  check("A11. each of the seven trust purposes is a dedication (" + dedicatedClean.join(",") + ")",
    dedicatedClean.length === 7 && dedicatedClean.every(function (v) { return v === true; }));
  // Every cross-purpose pair, driven one at a time so a single boolean cannot hide one.
  var CROSS = [["serverAuth", "emailProtection"], ["serverAuth", "timeStamping"],
    ["emailProtection", "timeStamping"], ["clientAuth", "timeStamping"],
    ["serverAuth", "brandIndicatorforMessageIdentification"],
    ["emailProtection", "brandIndicatorforMessageIdentification"]];
  var crossReported = [];
  for (var xi = 0; xi < CROSS.length; xi++) {
    crossReported.push(has(lint(await subordinate(CROSS[xi], EKU_FROM)), MIXES));
  }
  check("A12. every cross-purpose pair is reported (" + crossReported.join(",") + ")",
    crossReported.length === 6 && crossReported.every(function (v) { return v === true; }));
  // The finding names the set it read, so an operator sees which identifiers span the purposes
  // rather than only that some do.
  var mixedContext = findingsOf(lint(await subordinate(["serverAuth", "timeStamping"], EKU_FROM)),
    MIXES)[0];
  check("A12b. the finding names the extended key usages it read",
    mixedContext && mixedContext.context.extKeyUsage.slice().sort().join(",") ===
      "serverAuth,timeStamping");
  check("A13. the mixing row is silent before 2026-08-01",
    !has(lint(await subordinate(["serverAuth", "emailProtection"], BEFORE_EKU)), MIXES));
  // Arm (b) of the clause admits a subordinate CA carrying NO trust purpose EKU, and its other two
  // conditions are the issuing root's configuration and a CP/CPS. So one is passed over in that
  // window, and reported once the window closes and arm (b) is gone.
  check("A14. a subordinate CA naming no trust purpose EKU is passed over in the first window",
    !has(lint(await subordinate(["codeSigning"], BEFORE_SINGLE)), MIXES) &&
    !has(lint(await subordinate(["codeSigning"], BEFORE_SINGLE)), NOT_SINGLE));
  check("A15. ...and is reported once dedication is required outright",
    has(lint(await subordinate(["codeSigning"], SINGLE_FROM)), NOT_SINGLE));
  // The two rows hold different windows, so one certificate never draws both.
  var lateMixed = lint(await subordinate(["serverAuth", "emailProtection"], SINGLE_FROM));
  var earlyMixed = lint(await subordinate(["serverAuth", "emailProtection"], BEFORE_SINGLE));
  check("A16. the two windows do not overlap",
    has(lateMixed, NOT_SINGLE) && !has(lateMixed, MIXES) &&
    has(earlyMixed, MIXES) && !has(earlyMixed, NOT_SINGLE));

  // ---- A17-A20: appendix A and sec. 2.3, the end entity rules ----------------------------------
  var SMIME_SAN = "lint/apple-root/smime-subscriber-without-rfc822-name";
  var SUB_MIXES = "lint/apple-root/subscriber-mixes-trust-purposes";
  check("A17. an S/MIME subscriber signed on or after 2027-02-01 with no rfc822Name is reported",
    has(lint(await subscriber({ extendedKeyUsage: ["emailProtection"] }, SMIME_FROM)), SMIME_SAN) &&
    !has(lint(await subscriber({ extendedKeyUsage: ["emailProtection"] },
      new Date("2027-01-31T00:00:00Z"))), SMIME_SAN));
  check("A18. CONTROL: an rfc822Name satisfies it, and a dNSName alone does not",
    !has(lint(await subscriber({ extendedKeyUsage: ["emailProtection"],
      subjectAltName: [{ rfc822Name: "a@example.com" }] }, SMIME_FROM)), SMIME_SAN) &&
    has(lint(await subscriber({ extendedKeyUsage: ["emailProtection"],
      subjectAltName: [{ dNSName: "mail.example.com" }] }, SMIME_FROM)), SMIME_SAN));
  // Appendix A's last note gives a dated PERMISSION rather than a prohibition, so the scoping binds
  // once the permission's date passes.
  check("A19. a subscriber mixing trust purposes is reported from 2027-07-01 and not before",
    has(lint(await subscriber({ extendedKeyUsage: ["serverAuth", "timeStamping"] }, SINGLE_FROM)),
      SUB_MIXES) &&
    !has(lint(await subscriber({ extendedKeyUsage: ["serverAuth", "timeStamping"] },
      BEFORE_SINGLE)), SUB_MIXES));
  check("A20. CONTROL: a dedicated subscriber and one naming no trust purpose EKU are both clean",
    !has(lint(await subscriber({ extendedKeyUsage: ["serverAuth", "clientAuth"] }, SINGLE_FROM)),
      SUB_MIXES) &&
    !has(lint(await subscriber({ extendedKeyUsage: ["codeSigning"] }, SINGLE_FROM)), SUB_MIXES));
  // anyExtendedKeyUsage is not in the appendix's table, but it is not outside the table the way
  // id-kp-codeSigning is: RFC 5280 sec. 4.2.1.12 makes it a certificate "not restricted to any
  // specific key purpose", so it names EVERY trust purpose rather than none and conforms to no
  // single one. A subscriber carrying it is in scope, where a Document Signing one is not.
  check("A21. a subscriber naming anyExtendedKeyUsage is reported from 2027-07-01",
    has(lint(await subscriber({ extendedKeyUsage: ["anyExtendedKeyUsage"] }, SINGLE_FROM)),
      SUB_MIXES) &&
    !has(lint(await subscriber({ extendedKeyUsage: ["anyExtendedKeyUsage"] }, BEFORE_SINGLE)),
      SUB_MIXES));
  // On a subordinate CA the same bytes breach two sentences of sec. 1.7, the one naming
  // anyExtendedKeyUsage outright and the one requiring dedication, so both rows cite their own.
  var anyCa = lint(await subordinate(["anyExtendedKeyUsage"], SINGLE_FROM));
  check("A22. a subordinate CA naming anyExtendedKeyUsage breaches both sentences",
    has(anyCa, EKU_ANY) && has(anyCa, NOT_SINGLE));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
