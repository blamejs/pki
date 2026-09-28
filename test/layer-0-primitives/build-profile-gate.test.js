// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the build-time profile gate on pki.x509.sign, pki.csr.sign and pki.crl.sign.
 *
 * An authoring verb refuses to emit an artifact that this toolkit's own linter grades `error`. The
 * rules of the profile the artifact is written to run at every call, because standards are the
 * contract and an opt-out would be the accepts-on-error ergonomic; `opts.profile` names one more set
 * to run beside them.
 *
 *   G1-G3    the gate refuses, and refuses BEFORE the signing key is used
 *   G4       the one exemption that is a reading of the spec rather than a limit of the gate
 *   G5-G8    opts.profile: an added set, an unknown name, a misspelled option, a no-op
 *   G9-G10   the set the gate runs, and the exempt set, both derived rather than listed here
 *   G11-G13  the same gate on a request and on a revocation list
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var lintModule = require("../../lib/lint");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2030-01-01T00:00:00Z");
var SKI_OID = "2.5.29.14";

function codeOf(p) {
  return p.then(function () { return "NO-THROW"; }, function (e) { return e.code || e.constructor.name; });
}
function messageOf(p) {
  return p.then(function () { return ""; }, function (e) { return e.message || ""; });
}
function errorIds(rep) {
  return rep.findings.filter(function (f) { return f.severity === "error" || f.severity === "fatal"; })
    .map(function (f) { return f.id; });
}
function tailOf(id) { var c = id.lastIndexOf("/"); return c === -1 ? id : id.slice(c + 1); }

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var key = await pki.key.export(ed.privateKey), pub = await pki.key.export(ed.publicKey);
  var issuer = { name: [{ commonName: "An Issuer" }], publicKey: pub, key: key };
  var subjectSpec = { subject: [{ commonName: "A Subject" }], subjectPublicKey: pub,
    notBefore: NB, notAfter: NA };
  function spec(extensions) {
    return Object.assign({}, subjectSpec, { extensions: extensions });
  }

  // ---- G1-G3: the gate refuses what the linter grades an error ---------------------------------
  // The object form adds the key identifiers RFC 5280 sec. 4.2.1.1 and 4.2.1.2 require. The
  // pre-encoded array form is the caller supplying the whole extension set, so it carries what the
  // caller wrote and nothing else: a certificate built that way without an authorityKeyIdentifier is
  // one the linter grades an error, and before this gate the builder emitted it.
  var conforming = await pki.x509.sign(spec({ keyUsage: ["digitalSignature"] }), issuer);
  check("G1. CONTROL: a conforming certificate signs and lints clean at error",
    Buffer.isBuffer(conforming) && errorIds(pki.lint.certificate(conforming)).length === 0);

  // The issuer key id the object form derived, read back off that certificate rather than computed
  // here, so the array-form fixtures below carry the value the shipped builder would have used.
  var parsed = pki.schema.x509.parse(conforming);
  var skiExt = parsed.extensions.filter(function (e) { return e.oid === SKI_OID; })[0];
  var keyId = Buffer.from(skiExt.value.slice(skiExt.value.length - 20));

  var arrayNoAki = spec([pki.x509.extension("keyUsage", ["digitalSignature"]),
    pki.x509.extension("subjectKeyIdentifier", keyId)]);
  check("G2. a spec whose certificate would violate an always-on rule is refused, naming the rule",
    await codeOf(pki.x509.sign(arrayNoAki, issuer)) === "x509/profile-violation" &&
    (await messageOf(pki.x509.sign(arrayNoAki, issuer))).indexOf("lint/rfc5280/aki-missing") !== -1 &&
    (await messageOf(pki.x509.sign(arrayNoAki, issuer))).indexOf("RFC 5280") !== -1);
  // The refusal has to come before the signing key is used: a certificate that is never returned is
  // still one a real key signed and an audit log recorded. The key's sign operation is replaced with
  // one that throws, so reaching it would report that error instead of the gate's.
  var throwingIssuer = { name: [{ commonName: "An Issuer" }], publicKey: pub,
    key: { sign: function () { throw new Error("the signing key was used"); } } };
  check("G3. the refusal happens before the signing key is reached",
    await codeOf(pki.x509.sign(arrayNoAki, throwingIssuer)) === "x509/profile-violation");

  // ---- G4: the exemption that reads the spec ----------------------------------------------------
  // RFC 5280 sec. 4.2: "A certificate-using system MUST reject the certificate if it encounters a
  // critical extension it does not recognize". That requirement falls on the relying party, and the
  // same section states that conforming CAs MAY support extensions the specification does not
  // identify, so a CA emitting a private critical extension conforms and the gate must not refuse
  // one. The linter still grades it an error, which is what makes this an exemption rather than
  // agreement, and G10 reads the reason from the source.
  var privateCritical = spec([pki.x509.extension("keyUsage", ["digitalSignature"]),
    pki.x509.extension("subjectKeyIdentifier", keyId),
    pki.x509.extension("authorityKeyIdentifier", { keyIdentifier: keyId }),
    pki.x509.extension("1.3.6.1.4.1.99999.7", Buffer.from([0x05, 0x00]), { critical: true })]);
  var withPrivate = await pki.x509.sign(privateCritical, issuer);
  check("G4. a private critical extension still signs, and the linter still grades it an error",
    Buffer.isBuffer(withPrivate) &&
    errorIds(pki.lint.certificate(withPrivate)).indexOf("lint/rfc5280/unknown-critical-extension") !== -1);

  // ---- G5-G8: opts.profile ----------------------------------------------------------------------
  // A named profile runs BESIDE the always-on set rather than instead of it. A TLS server certificate
  // needs a subjectAltName that RFC 5280 does not require, so the same spec signs without the name
  // and is refused with it.
  var noSan = spec({ keyUsage: ["digitalSignature"], extendedKeyUsage: ["serverAuth"] });
  check("G5. a named profile adds its rules to the always-on set",
    Buffer.isBuffer(await pki.x509.sign(noSan, issuer)) &&
    await codeOf(pki.x509.sign(noSan, issuer, { profile: "cabf-tls" })) === "x509/profile-violation");
  check("G6. an unknown profile name is refused, naming the names that are known",
    await codeOf(pki.x509.sign(noSan, issuer, { profile: "nope" })) === "x509/bad-input" &&
    (await messageOf(pki.x509.sign(noSan, issuer, { profile: "nope" }))).indexOf("rfc5280") !== -1);
  check("G6b. a profile that belongs to another artifact is refused by name",
    await codeOf(pki.x509.sign(noSan, issuer, { profile: "rfc6960" })) === "x509/bad-input");
  check("G7. a misspelled option is refused by name, as every other unknown option is",
    await codeOf(pki.x509.sign(noSan, issuer, { profil: "cabf-tls" })) === "x509/bad-input");
  check("G8. naming the profile that always runs is accepted and changes nothing",
    Buffer.isBuffer(await pki.x509.sign(noSan, issuer, { profile: "rfc5280" })));
  // The escape, which exists because a toolkit that cannot emit a non-conforming artifact cannot build
  // the corpus its own linter is tested against. It is a name the caller writes, so the gate stays
  // closed unless somebody asked for it, and the refusal above points at it.
  var byRequest = await pki.x509.sign(arrayNoAki, issuer, { profile: "none" });
  check("G8b. the profile \"none\" emits what the spec describes, and what it emits is the violation",
    Buffer.isBuffer(byRequest) &&
    errorIds(pki.lint.certificate(byRequest)).indexOf("lint/rfc5280/aki-missing") !== -1);
  check("G8c. a refusal names the escape, so an operator who hits the gate can find it",
    (await messageOf(pki.x509.sign(noSan, issuer, { profile: "nope" }))).indexOf("\"none\"") !== -1);
  // A profile is a name, so a value that is not one is refused as a name would be rather than read for
  // its string form: `profile: true` is not a request to hold the certificate to anything.
  check("G8d. a profile that is not a string is refused, and still names the known profiles",
    await codeOf(pki.x509.sign(noSan, issuer, { profile: true })) === "x509/bad-input" &&
    (await messageOf(pki.x509.sign(noSan, issuer, { profile: true }))).indexOf("rfc5280") !== -1 &&
    await codeOf(pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, revoked: [], crlNumber: 1 },
      { key: key, name: "An Issuer", publicKey: pub }, { profile: 7 })) === "crl/bad-input");

  // ---- G9-G10: the set the gate acts on, and the two reasons a rule is left out -----------------
  // Every set is derived rather than restated: G9 from the registry under the same profile name the
  // gate reads, G10 by measuring the shipped linter. What G9 catches is a rule the gate would pass over
  // that nothing accounts for, and a rule the linter runs that the gate's set does not contain. It does
  // not catch a rule whose own appliesTo stops matching, which is a per-rule behavioral question its
  // own vector answers, so the refusals above drive real violating artifacts through the shipped verbs.
  var exempt = lintModule.buildGateExemptions();
  var exemptTails = Object.keys(exempt);
  var declared = lintModule.buildGateSignatureRules();
  function gateActsOn(id) { return !declared[id] && !exempt[tailOf(id)]; }
  var alwaysOn = lintModule.buildGateProfile("certificate");
  var runs = pki.lint.rules(alwaysOn, "certificate")
    .filter(function (r) { return (r.severity === "error" || r.severity === "fatal") && gateActsOn(r.id); });
  var runIds = runs.map(function (r) { return r.id; });
  // What the linter ACTUALLY executed on a conforming certificate under that profile. Every
  // error-severity rule among them is either one the gate acts on or one of the two accounted-for
  // kinds, so a rule the gate quietly ignores cannot be added without failing here.
  var executed = pki.lint.certificate(conforming, { profile: alwaysOn }).ran
    .filter(function (id) { return pki.lint.rules(alwaysOn, "certificate")
      .some(function (r) { return r.id === id && (r.severity === "error" || r.severity === "fatal"); }); });
  check("G9. the always-on certificate set is the profile's own error rows less what is accounted for (" +
    alwaysOn + ": " + runs.length + " acted on, " + executed.length + " executed, " +
    exemptTails.length + " exempt, " + Object.keys(declared).length + " signature-reading)",
    alwaysOn === "rfc5280" && runs.length >= 15 && executed.length > 0 &&
    runIds.indexOf("lint/rfc5280/unknown-critical-extension") === -1 &&
    runIds.indexOf("lint/rfc5280/signature-empty") === -1 &&
    executed.every(function (id) { return runIds.indexOf(id) !== -1 || !gateActsOn(id); }) &&
    exemptTails.every(function (t) { return typeof exempt[t] === "string" && exempt[t].length > 20; }));

  // The artifacts G10 probes: each of the three the gate runs on, under a classical key and under
  // ML-DSA-87, because a rule that reads a signature LENGTH exists only where the algorithm fixes one.
  var GATE_ARTIFACTS = [], allProfiles = pki.lint.profiles();
  for (var algi = 0; algi < 2; algi++) {
    var alg = algi === 0 ? "Ed25519" : "ML-DSA-87";
    var akp = await pki.key.generate(alg);
    var akey = await pki.key.export(akp.privateKey), apub = await pki.key.export(akp.publicKey);
    var aca = await pki.x509.sign({ subject: [{ commonName: "A Probe CA" }], subjectPublicKey: apub,
      notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true },
        keyUsage: ["keyCertSign", "cRLSign"], keyUsageCritical: true } }, { key: akey });
    GATE_ARTIFACTS.push({ kind: "certificate", der: aca });
    GATE_ARTIFACTS.push({ kind: "crl", der: await pki.crl.sign({ thisUpdate: NB, nextUpdate: NA,
      crlNumber: 1n, revoked: [] }, { cert: aca, key: akey }) });
    GATE_ARTIFACTS.push({ kind: "csr", der: await pki.csr.sign({ subject: [{ commonName: "A Probe" }],
      subjectPublicKey: apub }, { key: akey }) });
  }

  // Which rules actually read the signature value, measured on the shipped linter: the same
  // tbsCertificate wrapped with a one-byte signature and with a 64-byte one. A rule whose verdict
  // differs between the two is answering about the signature rather than about the spec, and the gate
  // cannot hold a caller to it because at gate time the value is a placeholder.
  // Which rules read the signature VALUE is measured rather than assumed, and measured over every
  // artifact the gate runs on, every profile it can be handed, and both a classical and an ML-DSA key,
  // because a rule that reads a signature length exists only where a length is fixed. The set the rules
  // DECLARE must be exactly the set that moves: a declaration nothing measures is drift, and a rule
  // that moves without declaring is a conforming artifact the gate would refuse. Deriving from one
  // profile and one artifact is what let lint/cnsa-2.0/crl-signature-length go unanswered.
  var bld = pki.asn1.build;
  function reSigned(der, len) {
    var o = pki.asn1.decode(der);
    return bld.sequence([bld.raw(o.children[0].bytes), bld.raw(o.children[1].bytes),
      bld.bitString(Buffer.alloc(len, 0xff), 0)]);
  }
  // Three lengths, not two: zero, so a rule testing the signature for emptiness is MEASURED here rather
  // than accounted for by name; one, so a rule testing a fixed length moves; and the ML-DSA-87 length,
  // so that rule falls silent on the arm where it applies.
  var PROBE_LENGTHS = [0, 1, 4627];
  // A profile one artifact runs and another does not is refused by name, so the skip is recorded with
  // the code that caused it and asserted below: a skip for any other reason would otherwise shrink the
  // measurement silently.
  var skipped = [];
  var measured = Object.create(null), probes = 0, kindsProbed = Object.create(null);
  for (var ai = 0; ai < GATE_ARTIFACTS.length; ai++) {
    var art = GATE_ARTIFACTS[ai];
    for (var pi = 0; pi < allProfiles.length; pi++) {
      var pn = allProfiles[pi], seen = [];
      try {
        for (var li = 0; li < PROBE_LENGTHS.length; li++) {
          seen.push(errorIds(pki.lint[art.kind](reSigned(art.der, PROBE_LENGTHS[li]), { profile: pn })));
        }
      } catch (notThisArtifact) {
        skipped.push(art.kind + "/" + pn + ": " + (notThisArtifact && notThisArtifact.code));
        continue;
      }
      probes += 1;
      kindsProbed[art.kind] = true;
      // A rule the signature moves is one that is not reported under every length.
      var union = [];
      seen.forEach(function (ids) { ids.forEach(function (id) { if (union.indexOf(id) === -1) union.push(id); }); });
      union.forEach(function (id) {
        if (!seen.every(function (ids) { return ids.indexOf(id) !== -1; })) measured[id] = true;
      });
    }
  }
  var measuredIds = Object.keys(measured).sort();
  var undeclared = measuredIds.filter(function (id) { return !declared[id]; });
  // The breadth is asserted as the three artifact kinds the gate runs on, rather than as a probe count
  // a later profile would quietly change.
  check("G10. every rule whose verdict moves with the signature value declares it (" + probes +
    " probes over " + Object.keys(kindsProbed).sort().join(", ") + "; moved: " +
    (measuredIds.join(", ") || "none") + ")",
    Object.keys(kindsProbed).length === 3 && probes >= allProfiles.length && undeclared.length === 0 &&
    measuredIds.indexOf("lint/cnsa-2.0/crl-signature-length") !== -1 &&
    measuredIds.indexOf("lint/rfc9881/mldsa-signature-length") !== -1 &&
    skipped.every(function (s) { return s.indexOf("lint/unknown-profile") !== -1; }));
  // The declaration is what the gate reads, so a rule declaring it without reading the signature would
  // be a rule the gate silently never runs. One difference remains, and it is derived rather than named:
  // a rule belonging to an artifact no authoring verb builds, which the gate never reaches at all.
  var gateReachable = Object.create(null), notEnumerable = [];
  Object.keys(kindsProbed).forEach(function (kind) {
    allProfiles.forEach(function (p) {
      var rws;
      try { rws = pki.lint.rules(p, kind); }
      catch (notThisKind) { notEnumerable.push(kind + "/" + p + ": " + (notThisKind && notThisKind.code)); return; }
      rws.forEach(function (r) { gateReachable[r.id] = true; });
    });
  });
  var declaredIds = Object.keys(declared).sort();
  var unexplained = declaredIds.filter(function (id) { return !measured[id] && gateReachable[id]; });
  check("G10b. every declaration the gate can reach is one the signature actually moves (" +
    declaredIds.length + " declared, " + Object.keys(gateReachable).length + " reachable)",
    declaredIds.length >= measuredIds.length && unexplained.length === 0 &&
    declaredIds.some(function (id) { return !gateReachable[id]; }) &&
    notEnumerable.every(function (s) { return s.indexOf("lint/unknown-profile") !== -1; }));
  check("G10c. the one exemption that is a reading of the spec carries its reason",
    Object.keys(exempt).length === 1 &&
    typeof exempt["unknown-critical-extension"] === "string" &&
    exempt["unknown-critical-extension"].indexOf("certificate-using system") !== -1);

  // ---- G11-G13: the request and the revocation list --------------------------------------------
  // The same gate, each verb reporting in its own domain, because a request that asks for a
  // non-conforming certificate and a revocation list that is itself non-conforming are one mistake
  // caught at one moment.
  var csrSpec = { subject: [{ commonName: "A Subject" }], subjectPublicKey: pub };
  var csrClean = await pki.csr.sign(csrSpec, key);
  check("G11. CONTROL: a conforming request signs and lints clean at error",
    Buffer.isBuffer(csrClean) && errorIds(pki.lint.csr(csrClean)).length === 0);
  check("G11b. an unknown profile name is refused by the request verb too",
    await codeOf(pki.csr.sign(csrSpec, key, { profile: "nope" })) === "csr/bad-input");
  // RFC 2986: a request with no subject and no subjectAltName names nobody, which the linter grades
  // an error. Either door may answer first, so the vector accepts the spec check and the gate alike
  // and pins only that the builder does not emit one.
  var anonymous = { subject: [], subjectPublicKey: pub };
  var anonCode = await codeOf(pki.csr.sign(anonymous, key));
  check("G12. a request that names nobody is refused rather than emitted (" + anonCode + ")",
    anonCode === "csr/profile-violation" || anonCode === "csr/bad-input");

  var caCert = await pki.x509.sign(Object.assign({}, subjectSpec,
    { subject: [{ commonName: "An Issuer" }],
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }), { key: key });
  var crlClean = await pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, revoked: [], crlNumber: 1 },
    { cert: caCert, key: key });
  check("G13. CONTROL: a conforming revocation list signs and lints clean at error",
    Buffer.isBuffer(crlClean) && errorIds(pki.lint.crl(crlClean)).length === 0);
  // RFC 5280 sec. 5.2.3 requires a cRLNumber of a conforming CRL issuer, and the builder emitted one
  // without it.
  var crlNoNumber = { thisUpdate: NB, nextUpdate: NA, revoked: [] };
  check("G13b. a revocation list the linter grades an error is refused, naming the rule",
    await codeOf(pki.crl.sign(crlNoNumber, { cert: caCert, key: key })) === "crl/profile-violation" &&
    (await messageOf(pki.crl.sign(crlNoNumber, { cert: caCert, key: key }))).indexOf("crl-number-missing") !== -1);
  check("G13c. an unknown profile name is refused by the revocation-list verb too",
    await codeOf(pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, revoked: [], crlNumber: 1 },
      { cert: caCert, key: key }, { profile: "nope" })) === "crl/bad-input");

  // The pre-encoded array suppresses the derived key identifiers on a CRL as it does on a certificate,
  // so the same upgrade applies to both and the gate says so for both.
  check("G13d. a revocation list built through the pre-encoded array is refused for its missing key id",
    await codeOf(pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, crlNumber: 1n, revoked: [], extensions: [] },
      { cert: caCert, key: key })) === "crl/profile-violation" &&
    (await messageOf(pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, crlNumber: 1n, revoked: [], extensions: [] },
      { cert: caCert, key: key }))).indexOf("aki-missing") !== -1);
  // And the gate does not ask for an authorityKeyIdentifier where the RFC does not: sec. 4.2.1.1 permits
  // its absence on a self-signed certificate, so one signs carrying none.
  var selfSigned = await pki.x509.sign({ subject: [{ commonName: "A Self-Signed Root" }],
    subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
  check("G13e. a self-signed certificate signs carrying no authorityKeyIdentifier",
    Buffer.isBuffer(selfSigned) && errorIds(pki.lint.certificate(selfSigned)).length === 0 &&
    pki.schema.x509.parse(selfSigned).extensions
      .every(function (e) { return e.oid !== pki.oid.byName("authorityKeyIdentifier"); }));

  // ---- G14: a named profile whose rules read the signature -------------------------------------
  // The gate must not refuse a conforming artifact because of a rule it cannot answer. CNSA 2.0 states
  // the length FIPS 204 fixes for an ML-DSA-87 signature, and at gate time the signature is a 64-byte
  // placeholder, so a certificate and a CRL that both satisfy the profile were refused for the
  // placeholder's length rather than for anything the caller asked to emit. Both arms sign, and the
  // emitted artifacts lint clean under the same profile they were held to, which is what proves the
  // gate and the linter agree about what the caller asked for.
  var mldsa = await pki.key.generate("ML-DSA-87");
  var mlKey = await pki.key.export(mldsa.privateKey), mlPub = await pki.key.export(mldsa.publicKey);
  var cnsaCa = await pki.x509.sign({ subject: [{ commonName: "A CNSA Root" }], subjectPublicKey: mlPub,
    notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true },
      keyUsage: ["keyCertSign", "cRLSign"], keyUsageCritical: true } }, { key: mlKey },
  { profile: "cnsa-2.0" });
  check("G14. an ML-DSA-87 CA certificate signs under cnsa-2.0 and lints clean under it",
    Buffer.isBuffer(cnsaCa) && errorIds(pki.lint.certificate(cnsaCa, { profile: "cnsa-2.0" })).length === 0);
  var cnsaCrl = await pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, crlNumber: 1n, revoked: [] },
    { cert: cnsaCa, key: mlKey }, { profile: "cnsa-2.0" });
  check("G14b. an ML-DSA-87 CRL signs under cnsa-2.0 and lints clean under it",
    Buffer.isBuffer(cnsaCrl) && errorIds(pki.lint.crl(cnsaCrl, { profile: "cnsa-2.0" })).length === 0);
  // And the profile still refuses what it is for: a classical key is not in the suite.
  check("G14c. the same profile still refuses a key outside the suite",
    await codeOf(pki.x509.sign({ subject: [{ commonName: "A Classical Root" }], subjectPublicKey: pub,
      notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true },
        keyUsage: ["keyCertSign", "cRLSign"], keyUsageCritical: true } }, { key: key },
    { profile: "cnsa-2.0" })) === "x509/profile-violation");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
