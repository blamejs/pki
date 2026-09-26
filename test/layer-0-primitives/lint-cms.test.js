// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.lint.cms, the RFC 5652 profile. RED conformance vectors written BEFORE the verb,
 * each driving the shipped verb and asserting the finding id.
 *
 * The profile is SHORT, and the vectors say why: this toolkit's strict CMS parser already refuses
 * most of what RFC 5652 sections 5 and 11 require, so those clauses reach an operator as
 * lint/unparseable carrying the parser's own code rather than as a row. Q7 pins that, because a
 * decision not to write a row is only a decision while something asserts it.
 *
 *   Q1-Q4   the verb's shape: a clean control, the registry, hostile bytes, a non-SignedData input
 *   Q5-Q6   sec. 11.3, the signing-time encoding the parser does not settle
 *   Q7      the clauses the parser settles, asserted against its codes rather than against rows
 *   Q8-Q9   sec. 5.3, the digest algorithm a signer uses and the set that lists it
 *   Q10     sec. 5.1, a version 1 attribute certificate
 *   Q11-Q12 the two structural notices, no signers and detached content
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");
var CONTENT = Buffer.from("the content pki.lint.cms reads");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function findingsOf(rep, id) {
  return rep.findings.filter(function (f) { return f.id === id; });
}
function sevOf(rep, id) {
  var f = findingsOf(rep, id)[0];
  return f && f.severity;
}
function cmsIds(rep) {
  return ids(rep).filter(function (id) { return id.indexOf("lint/rfc5652/") === 0; });
}

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var key = await pki.key.export(ed.privateKey), pub = await pki.key.export(ed.publicKey);
  var cert = await pki.x509.sign({ subject: [{ commonName: "A CMS Signer" }], subjectPublicKey: pub,
    notBefore: NB, notAfter: NA, extensions: { subjectKeyIdentifier: true } }, { key: key });
  var signer = { cert: cert, key: key };

  // ---- Q1-Q4: the verb's shape ----------------------------------------------------------------
  var attached = await pki.cms.sign(CONTENT, signer);
  var attachedRep = pki.lint.cms(attached);
  check("Q1. CONTROL: a conforming attached SignedData reports nothing (" +
    cmsIds(attachedRep).join(",") + ")", cmsIds(attachedRep).length === 0);
  check("Q2. rules() enumerates the rfc5652 rows",
    pki.lint.rules().filter(function (r) { return r.source === "rfc5652"; }).length >= 5 &&
    pki.lint.rules("rfc5652", "cms").length >= 5);
  // The lint data path never throws, which is what lets an operator walk a directory without a
  // try/catch per file. Hostile bytes are a fatal finding carrying the parser's own code.
  var hostile = pki.lint.cms(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]));
  check("Q3. hostile bytes are a fatal finding rather than a throw",
    hostile.findings.length === 1 && hostile.findings[0].id === "lint/unparseable" &&
    hostile.findings[0].severity === "fatal" &&
    typeof hostile.findings[0].context.code === "string");
  // certs-only is a SignedData carrying zero signers, which Q11 reads. A ContentInfo that is not
  // signed-data at all is Q4b below.
  var certsOnly = await pki.cms.certsOnly([cert]);
  // A STRING input takes the PEM door rather than the DER one, and a string that is not a decodable
  // PEM must arrive as the same fatal finding: the never-throw promise covers both doors.
  var badPem = pki.lint.cms("-----BEGIN CMS-----\nnot base64 at all\n-----END CMS-----");
  check("Q3b. a string that is not a decodable PEM is a fatal finding, not a throw",
    badPem.findings.length === 1 && badPem.findings[0].id === "lint/unparseable" &&
    badPem.findings[0].severity === "fatal" && typeof badPem.findings[0].context.code === "string");
  check("Q4. a profile name belonging to another verb is refused by name",
    (function () {
      try { pki.lint.cms(attached, { profile: "rfc5280" }); return false; }
      catch (e) { return e.code === "lint/unknown-profile"; }
    })());

  // ---- Q4b-Q4d: which content types the rows apply to -----------------------------------------
  // Every row reads a signer, so a content type that carries none gets not-applicable rather than a
  // finding. This is asserted on each content type the parser reads, because the claim is about all
  // of them and a fixture built from one says nothing about the rest.
  var notSigned = [["digestedData", await pki.cms.digest(CONTENT)],
    ["compressedData", await pki.cms.compress(CONTENT)]];
  check("Q4b. a content type the parser reads that is not signed-data runs no row (" +
    notSigned.map(function (p) { return p[0]; }).join(",") + ")",
  notSigned.every(function (p) {
    var rep = pki.lint.cms(p[1]);
    return rep.ran.length === 0 && rep.counts.na === 5 && cmsIds(rep).length === 0;
  }));
  // A content type the parser does not read is refused before a row is reached, so it arrives as the
  // parser's own code rather than as five not-applicable rows. Sec. 4's id-data is that case.
  var idData = b.sequence([b.oid(pki.oid.byName("data")), b.explicit(0, b.octetString(CONTENT))]);
  var idRep = pki.lint.cms(idData);
  check("Q4c. id-data is a fatal lint/unparseable carrying the parser's code, not five na rows",
    idRep.findings.length === 1 && idRep.findings[0].id === "lint/unparseable" &&
    idRep.findings[0].severity === "fatal" &&
    idRep.findings[0].context.code === "cms/unsupported-content-type" && idRep.counts.na === 0);
  // Applicability is decided by the content type the parser recorded, which is the ContentInfo's own
  // field. A field name that a signed-data body happens to carry is reachable through the prototype
  // chain on a content type that has none, so deciding on one would run every row against a message
  // with no signers at all. The same walk must not throw on a value it did not build either: the
  // verb's contract is a report.
  function underPollutedSignerInfos(value, fn) {
    Object.defineProperty(Object.prototype, "signerInfos",
      { value: value, writable: true, configurable: true, enumerable: false });
    try { return fn(); } finally { delete Object.prototype.signerInfos; }
  }
  var polluted = [["an empty signer list", []],
    ["a signer naming an unlisted digest", [{ digestAlgorithm: { oid: pki.oid.byName("sha512") } }]],
    ["a countersignature whose values is not an array",
      [{ unsignedAttrs: [{ type: pki.oid.byName("countersignature"), values: null }] }]],
    ["a signing-time attribute whose values is not an array",
      [{ signedAttrs: [{ type: pki.oid.byName("signingTime"), values: null }] }]]];
  check("Q4d. an inherited signerInfos runs no row on a non-signed-data content type, and throws out of no door",
    polluted.every(function (p) {
      return notSigned.every(function (f) {
        // No try/catch: the verb's contract is a report, so a throw here is the failure this vector
        // exists to catch and it is more use surfacing with its own stack than as a false return.
        var rep = underPollutedSignerInfos(p[1], function () { return pki.lint.cms(f[1]); });
        return rep.ran.length === 0 && rep.counts.na === 5 && cmsIds(rep).length === 0;
      });
    }));
  check("Q4d2. CONTROL: the same rows DO run on a real signed-data message, so Q4d is not silence",
    pki.lint.cms(attached).ran.length === 5);

  // ---- Q5-Q6: sec. 11.3, the signing-time encoding --------------------------------------------
  var TIME_ID = "lint/rfc5652/signing-time-encoding";
  // "Dates between 1 January 1950 and 31 December 2049 (inclusive) MUST be encoded as UTCTime."
  // The signer emits the right form for the year, so the non-conforming one is asked for outright:
  // the signing-time it would have written is suppressed and a GeneralizedTime put in its place.
  var when = new Date("2030-06-01T00:00:00Z");
  var genForUtcYear = await pki.cms.sign(CONTENT, signer, { signingTime: false,
    additionalSignedAttributes: [{ type: pki.oid.byName("signingTime"),
      values: [b.generalizedTime(when)] }] });
  check("Q5. a GeneralizedTime signing-time for a year the clause puts in UTCTime is reported",
    has(pki.lint.cms(genForUtcYear), TIME_ID) &&
    sevOf(pki.lint.cms(genForUtcYear), TIME_ID) === "error");
  check("Q6. CONTROL: the same instant as a UTCTime is not reported",
    !has(pki.lint.cms(await pki.cms.sign(CONTENT, signer, { signingTime: when })), TIME_ID));
  // The other direction of the clause, a year outside 1950..2049 encoded as UTCTime, cannot be
  // built at all: UTCTime carries two year digits and sec. 11.3 reads YY >= 50 as 19YY and YY < 50
  // as 20YY, so every UTCTime names a year inside the window. The row needs one direction because
  // the encoding provides only one.
  // Every two-digit year is put to the PARSER and the year it resolves is read back, rather than
  // recomputed here: a vector that applies the pivot itself asserts its own arithmetic and stays
  // green if `asn1.read.time` ever reads the digits differently.
  check("Q6b. a UTCTime cannot name a year outside the window, whatever digits it carries",
    (function () {
      var years = [];
      for (var yy = 0; yy < 100; yy++) {
        var two = (yy < 10 ? "0" : "") + yy;
        var tlv = Buffer.concat([Buffer.from([0x17, 13]),
          Buffer.from(two + "0601000000Z", "latin1")]);
        years.push(pki.asn1.read.time(pki.asn1.decode(tlv)).getUTCFullYear());
      }
      return years.length === 100 &&
        Math.min.apply(null, years) === 1950 && Math.max.apply(null, years) === 2049;
    })());

  // A countersignature is a SignerInfo with its own signedAttrs, and section 11.3 governs a
  // signing-time wherever one appears. The rule reads the countersignatures a message carries as
  // well as its own signers, or a message can put the shape it forbids one level down.
  var counterTime = new Date("2031-06-01T00:00:00Z");
  var countersigned = await pki.cms.countersign(attached, signer, { signingTime: false,
    additionalSignedAttributes: [{ type: pki.oid.byName("signingTime"),
      values: [b.generalizedTime(counterTime)] }] });
  check("Q6c. a countersignature's signing-time is read by the same rule",
    has(pki.lint.cms(countersigned), TIME_ID) &&
    !has(pki.lint.cms(await pki.cms.countersign(attached, signer,
      { signingTime: counterTime })), TIME_ID));
  // The finding names the signer an operator can find: the index into the message's own
  // signerInfos, and whether the attribute sat on a countersignature under it. A flattened walk
  // position would send a reader to a signer that is not the one at fault.
  var counterContext = findingsOf(pki.lint.cms(countersigned), TIME_ID)[0].context;
  check("Q6d. the finding names the message's own signer, and says it was a countersignature",
    counterContext.signerIndex === 0 && counterContext.countersignature === true &&
    findingsOf(pki.lint.cms(genForUtcYear), TIME_ID)[0].context.countersignature === false);

  // ---- Q7: what the parser settles, so no row is written for it -------------------------------
  // Each of these is an RFC 5652 MUST. None has a row, because the strict parser refuses it and the
  // operator sees the parser's verdict. Driving them here is what keeps that a decision.
  var PARSER_SETTLED = [];
  // sec. 11.1: the content-type attribute value must match eContentType.
  var CT = pki.oid.byName("contentType");
  var mismatched = await pki.cms.sign(CONTENT, signer).then(function (der) {
    return surgery.patch(der, function (n) {
      if (!n.constructed || n.tagNumber !== 16 || !n.children || n.children.length !== 2) return undefined;
      if (!b.oid(CT).equals(n.children[0].bytes)) return undefined;
      return b.sequence([b.raw(b.oid(CT)), b.setOf([b.oid(pki.oid.byName("signedData"))])]);
    });
  });
  PARSER_SETTLED.push(["content-type against eContentType", mismatched]);
  // sec. 11.3: a signing-time with two values, which the clause forbids outright.
  PARSER_SETTLED.push(["a multi-valued signing-time",
    await pki.cms.sign(CONTENT, signer, { signingTime: false,
      additionalSignedAttributes: [{ type: pki.oid.byName("signingTime"),
        values: [b.utcTime(when), b.utcTime(NB)] }] })]);
  // sec. 5.3: signedAttrs carrying no message-digest attribute at all.
  var MD = pki.oid.byName("messageDigest");
  PARSER_SETTLED.push(["signedAttrs with no message-digest",
    surgery.patch(attached, function (n) {
      if (!n.constructed || n.tagNumber !== 16 || !n.children || n.children.length !== 2) return undefined;
      if (!b.oid(MD).equals(n.children[0].bytes)) return undefined;
      return b.sequence([b.raw(b.oid(pki.oid.byName("challengePassword"))),
        b.raw(n.children[1].bytes)]);
    })]);
  var settledVerdicts = PARSER_SETTLED.map(function (c) {
    var rep = pki.lint.cms(c[1]);
    if (rep.findings.length === 1 && rep.findings[0].id === "lint/unparseable") return "parser";
    return "row:" + cmsIds(rep).join("+");
  });
  check("Q7. the clauses the parser settles reach an operator as its verdict, not as a row (" +
    settledVerdicts.join(",") + ")",
    settledVerdicts.length === 3 &&
    settledVerdicts.every(function (v) { return v === "parser"; }));

  // ---- Q8-Q9: sec. 5.3, the digest algorithm and the set that lists it ------------------------
  var DIGEST_ID = "lint/rfc5652/signer-digest-not-listed";
  var parsed = pki.schema.cms.parse(attached);
  var listed = parsed.digestAlgorithms[0].oid;
  var otherAlg = b.sequence([b.oid(pki.oid.byName(
    listed === pki.oid.byName("sha256") ? "sha512" : "sha256"))]);
  var unlisted = surgery.patch(attached, function (n) {
    if (!n.constructed || n.tagNumber !== 17 || !n.children || n.children.length !== 1) return undefined;
    var kid = n.children[0];
    if (!kid.children || !kid.children[0] || !kid.children[0].bytes.equals(b.oid(listed))) return undefined;
    return b.setOf([otherAlg]);
  });
  check("Q8. a signer digest the digestAlgorithms set does not list is reported at warn",
    sevOf(pki.lint.cms(unlisted), DIGEST_ID) === "warn");
  check("Q9. CONTROL: the set the signer emits lists its own digest",
    !has(attachedRep, DIGEST_ID));
  // RFC 5754 sec. 2: "Implementations MUST accept SHA2 AlgorithmIdentifiers with absent
  // parameters. Implementations MUST accept SHA2 AlgorithmIdentifiers with NULL parameters." So a
  // set naming the signer's digest with NULL parameters beside a signer that omits them is naming
  // the same algorithm, and comparing the parameter bytes alone would report a conforming message.
  var nullParams = surgery.patch(attached, function (n) {
    if (!n.constructed || n.tagNumber !== 17 || !n.children || n.children.length !== 1) return undefined;
    var kid = n.children[0];
    if (!kid.children || !kid.children[0] || !kid.children[0].bytes.equals(b.oid(listed))) return undefined;
    return b.setOf([b.sequence([b.raw(b.oid(listed)), b.nullValue()])]);
  });
  check("Q9b. a digest identifier carrying NULL parameters names the same algorithm as one omitting them",
    !has(pki.lint.cms(nullParams), DIGEST_ID));

  // ---- Q10: sec. 5.1, a version 1 attribute certificate ----------------------------------------
  // "The use of version 1 attribute certificates is strongly discouraged." The certificates field
  // is a CertificateChoices SET, and a [1] element is the v1 attribute certificate alternative.
  // Section 5.1 then requires version 3, which the parser enforces, so the fixture carries both.
  var withV1Attr = surgery.patch(attached, function (n, path) {
    if (path.length === 3 && path[0].index === 1 && path[1].index === 0 && path[2].index === 0) {
      return b.integer(3n);
    }
    if (n.tagClass === "context" && n.tagNumber === 0 && n.constructed && n.children &&
      n.children.length === 1) {
      var kid = n.children[0];
      if (kid.tagClass === "universal" && kid.tagNumber === 16 && kid.children &&
        kid.children.length === 3) {
        return b.implicit(0, b.setOf([b.contextConstructed(1,
          Buffer.concat(kid.children.map(function (c) { return c.bytes; })))]), true);
      }
    }
    return undefined;
  });
  check("Q10. a version 1 attribute certificate is reported at warn",
    sevOf(pki.lint.cms(withV1Attr), "lint/rfc5652/attribute-certificate-v1") === "warn" &&
    !has(attachedRep, "lint/rfc5652/attribute-certificate-v1"));

  // ---- Q11-Q12: the two structural notices -----------------------------------------------------
  check("Q11. a SignedData carrying no signers is a notice",
    sevOf(pki.lint.cms(certsOnly), "lint/rfc5652/no-signers") === "notice" &&
    !has(attachedRep, "lint/rfc5652/no-signers"));
  var detached = await pki.cms.sign(CONTENT, signer, { detached: true });
  check("Q12. a detached signature is a notice",
    sevOf(pki.lint.cms(detached), "lint/rfc5652/detached-content") === "notice" &&
    !has(attachedRep, "lint/rfc5652/detached-content"));
  // A certs-only message has no content AND no signer, and the detached notice exists to tell a
  // verifier it must supply the content. There is no signature to verify, so it does not apply.
  check("Q12b. a certs-only message is not also reported as a detached signature",
    !has(pki.lint.cms(certsOnly), "lint/rfc5652/detached-content"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
