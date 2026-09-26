// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.lint.tsp, the RFC 3161 profile. RED conformance vectors written BEFORE the verb.
 *
 * This profile is the shortest of the three, and for the same reason lint.cms is short: the token
 * parser refuses nearly everything section 2.4.2 requires. T4 pins that list, because the rows this
 * profile does NOT carry are as much a decision as the ones it does.
 *
 *   T1-T3   the verb's shape: a clean control, the registry, hostile bytes
 *   T4      the clauses parseToken settles, asserted against its codes rather than against rows
 *   T5-T7   the tsa hint against the certificate that verifies the token
 *   T8-T9   the serial number width, and an absent accuracy
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;
var crypto = require("node:crypto");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function sevOf(rep, id) {
  var f = rep.findings.filter(function (x) { return x.id === id; })[0];
  return f && f.severity;
}
function tspIds(rep) {
  return ids(rep).filter(function (id) { return id.indexOf("lint/rfc3161/") === 0; });
}
/** The subject Name TLV of a certificate, which is TBSCertificate field 5 when the version
 *  wrapper is present: version, serialNumber, signature, issuer, validity, subject. */
function subjectNameDer(certDer) {
  var tbs = pki.asn1.decode(certDer).children[0];
  return tbs.children[5].bytes;
}

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var key = await pki.key.export(ed.privateKey), pub = await pki.key.export(ed.publicKey);
  function tsaCert(name) {
    return pki.x509.sign({ subject: [{ commonName: name }], subjectPublicKey: pub,
      notBefore: NB, notAfter: NA,
      extensions: { subjectKeyIdentifier: true, keyUsage: ["digitalSignature"],
        extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } }, { key: key });
  }
  var cert = await tsaCert("A Time Stamping Authority");
  var other = await tsaCert("Some Other Authority");
  var imprint = { hashAlgorithm: "sha256",
    hashedMessage: crypto.createHash("sha256").update(Buffer.from("hello")).digest() };
  function token(opts) {
    return pki.tsp.sign(imprint, { cert: cert, key: key },
      Object.assign({ policy: "1.2.3", serialNumber: 1, accuracy: { seconds: 1 } }, opts || {}));
  }

  // ---- T1-T3: the verb's shape ----------------------------------------------------------------
  var clean = await token();
  var cleanRep = pki.lint.tsp(clean);
  check("T1. CONTROL: a conforming token reports nothing (" + tspIds(cleanRep).join(",") + ")",
    tspIds(cleanRep).length === 0);
  check("T2. rules() enumerates the rfc3161 rows",
    pki.lint.rules().filter(function (r) { return r.source === "rfc3161"; }).length >= 3 &&
    pki.lint.rules("rfc3161", "tsp").length >= 3);
  var hostile = pki.lint.tsp(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]));
  check("T3. hostile bytes are a fatal finding rather than a throw",
    hostile.findings.length === 1 && hostile.findings[0].id === "lint/unparseable" &&
    hostile.findings[0].severity === "fatal" &&
    typeof hostile.findings[0].context.code === "string");

  // A STRING input takes the PEM door rather than the DER one, and a string that is not a decodable
  // PEM must arrive as the same fatal finding: the never-throw promise covers both doors.
  var badPem = pki.lint.tsp("-----BEGIN TIMESTAMP TOKEN-----\nnot base64\n-----END TIMESTAMP TOKEN-----");
  check("T3b. a string that is not a decodable PEM is a fatal finding, not a throw",
    badPem.findings.length === 1 && badPem.findings[0].id === "lint/unparseable" &&
    badPem.findings[0].severity === "fatal" && typeof badPem.findings[0].context.code === "string");

  // ---- T4: what parseToken settles, so no row is written for it -------------------------------
  // Each of these is an RFC 3161 sec. 2.4.2 MUST that the token parser refuses outright, so the
  // operator sees its verdict. Driving them is what keeps the absent rows a decision.
  var asCms = pki.schema.cms.parse(clean);
  var twoSigners = await pki.tsp.sign(imprint, { cert: cert, key: key },
    { policy: "1.2.3", serialNumber: 1 }).then(function (der) {
    // duplicate the single SignerInfo inside the signerInfos SET
    return surgery.patch(der, function (n) {
      if (!n.constructed || n.tagNumber !== 17 || !n.children || n.children.length !== 1) return undefined;
      var kid = n.children[0];
      if (!kid.children || kid.children.length < 5) return undefined;
      return b.setOf([b.raw(kid.bytes), b.raw(kid.bytes)]);
    });
  });
  var wrongContentType = surgery.patch(clean, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 6) return undefined;
    if (!n.bytes.equals(b.oid(asCms.encapContentInfo.eContentType))) return undefined;
    return b.oid(pki.oid.byName("data"));
  });
  var settled = [["two signerInfos", twoSigners], ["an eContentType that is not id-ct-TSTInfo", wrongContentType]];
  var settledVerdicts = settled.map(function (c) {
    var rep = pki.lint.tsp(c[1]);
    if (rep.findings.length === 1 && rep.findings[0].id === "lint/unparseable") return "parser";
    return "row:" + tspIds(rep).join("+");
  });
  check("T4. the clauses the token parser settles reach an operator as its verdict (" +
    settledVerdicts.join(",") + ")",
    settledVerdicts.length === 2 && settledVerdicts.every(function (v) { return v === "parser"; }));

  // ---- T5-T7: the tsa hint against the certificate that verifies the token --------------------
  var TSA_ID = "lint/rfc3161/tsa-name-mismatch";
  // "The purpose of the tsa field is to give a hint in identifying the name of the TSA. If present,
  // it MUST correspond to one of the subject names included in the certificate that is to be used
  // to verify the token." The signer emits no tsa hint at all, so both fixtures are cut by hand:
  // TSTInfo's tsa is a [0] EXPLICIT GeneralName, appended after the fields the signer wrote.
  function withTsaHint(tokenDer, nameDer) {
    return withTsaHintRaw(tokenDer, b.contextConstructed(4, Buffer.from(nameDer)));
  }
  function withTsaHintRaw(tokenDer, generalName) {
    var hint = b.explicit(0, generalName);
    // The eContent OCTET STRING by its PATH rather than by trying to decode every octet string:
    // ContentInfo content [1], SignedData, encapContentInfo (2), its [0] wrapper, the string.
    var AT = [1, 0, 2, 1, 0];
    return surgery.patch(tokenDer, function (n, path) {
      if (path.length !== AT.length) return undefined;
      for (var i = 0; i < AT.length; i++) { if (path[i].index !== AT[i]) return undefined; }
      var inner = pki.asn1.decode(n.content);
      var kids = inner.children.map(function (c) { return b.raw(c.bytes); });
      kids.push(b.raw(hint));
      return b.octetString(b.sequence(kids));
    });
  }
  var matching = withTsaHint(clean, subjectNameDer(cert));
  var mismatching = withTsaHint(clean, subjectNameDer(other));
  check("T5. a tsa hint naming a different subject than the token's certificate is reported",
    sevOf(pki.lint.tsp(mismatching), TSA_ID) === "error");
  check("T6. CONTROL: a tsa hint naming that certificate's own subject is not reported",
    !has(pki.lint.tsp(matching), TSA_ID));
  check("T7. CONTROL: a token carrying no tsa hint is not reported",
    !has(cleanRep, TSA_ID));
  // The clause says "one of the subject names included in the certificate", which is the subject
  // AND the subjectAltName. A directoryName hint that the subject does not carry but a SAN entry
  // does is one of them.
  var altCert = await pki.x509.sign({ subject: [{ commonName: "A Time Stamping Authority" }],
    subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { subjectKeyIdentifier: true, keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true,
      subjectAltName: [{ directoryName: [{ commonName: "An Alternative Authority" }] },
        { otherName: { typeId: "1.2.3.4.5", value: b.utf8("alpha") } }] } }, { key: key });
  var altToken = await pki.tsp.sign(imprint, { cert: altCert, key: key },
    { policy: "1.2.3", serialNumber: 1, accuracy: { seconds: 1 } });
  var altName = await tsaCert("An Alternative Authority");
  check("T7b. a directoryName hint the subjectAltName carries is not reported",
    !has(pki.lint.tsp(withTsaHint(altToken, subjectNameDer(altName))), TSA_ID));
  // A form whose decoded value is a structure rather than a string must be compared by what it
  // holds: two otherNames with different contents are different names, and comparing a decoded
  // object against another decoded object by identity would call every pair of them equal.
  function otherNameHint(text) {
    return b.contextConstructed(0, Buffer.concat([b.oid("1.2.3.4.5"), b.explicit(0, b.utf8(text))]));
  }
  check("T7c. an otherName hint the certificate does not carry is reported",
    has(pki.lint.tsp(withTsaHintRaw(altToken, otherNameHint("beta"))), TSA_ID));
  // A DNS name is compared without regard to ASCII case (RFC 5280 sec. 7.2), so the encoding alone
  // does not settle it: DER canonicalizes the bytes, not the letters.
  var dnsCert = await pki.x509.sign({ subject: [{ commonName: "A Time Stamping Authority" }],
    subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { subjectKeyIdentifier: true, keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true,
      subjectAltName: [{ dNSName: "tsa.example.com" }] } }, { key: key });
  var dnsToken = await pki.tsp.sign(imprint, { cert: dnsCert, key: key },
    { policy: "1.2.3", serialNumber: 1, accuracy: { seconds: 1 } });
  function dnsHint(name) { return b.contextPrimitive(2, Buffer.from(name, "latin1")); }
  // Carrying one certificate is not the same fact as carrying the SIGNER's certificate: a token
  // may embed an intermediate and leave the signer to be supplied out of band, which pki.tsp.verify
  // accepts through opts.certs. The row reads the certificate the SignerInfo's own identifier
  // names, and passes over a token where that certificate is not there to compare against.
  var strangerCert = await tsaCert("An Unrelated Authority");
  var strangerToken = surgery.patch(mismatching, function (n) {
    if (n.tagClass !== "context" || n.tagNumber !== 0 || !n.constructed) return undefined;
    if (!n.children || n.children.length !== 1) return undefined;
    var kid = n.children[0];
    if (kid.tagClass !== "universal" || kid.tagNumber !== 16 || !kid.children ||
      kid.children.length !== 3) return undefined;
    return b.implicit(0, b.setOf([b.raw(strangerCert)]), true);
  });
  check("T7e. a token whose embedded certificate is not the signer's is passed over",
    !has(pki.lint.tsp(strangerToken), TSA_ID));
  // The other form of the identifier names the certificate by its subjectKeyIdentifier, and the
  // rule must resolve it the same way: a SignerInfo written that way is still a signer.
  var skiToken = await pki.tsp.sign(imprint, { cert: cert, key: key },
    { policy: "1.2.3", serialNumber: 1, accuracy: { seconds: 1 }, sid: "ski" });
  check("T7f. a subjectKeyIdentifier signer identifier resolves the same certificate",
    has(pki.lint.tsp(withTsaHint(skiToken, subjectNameDer(other))), TSA_ID) &&
    !has(pki.lint.tsp(withTsaHint(skiToken, subjectNameDer(cert))), TSA_ID));
  // Which embedded certificate signed the token is settled by the ESS SigningCertificate or
  // SigningCertificateV2 certHash that sec. 2.4.2 requires and parseToken refuses a token without.
  // The SignerInfo sid settles nothing on its own: an issuer with a serial, and a subject key
  // identifier, are values an issuer wrote, and two certificates can carry either. `cert` and
  // `other` share a key here, so they share a subjectKeyIdentifier. The `certificates` SET is
  // outside every signature in the token, so anything between the TSA and the reader can add to it,
  // and the DER SET OF order the addition lands in is the sender's to choose. So the verdict is
  // taken against the certificate the certHash names, in both hint directions and at either order.
  function withCerts(tokenDer, list) {
    return surgery.patch(tokenDer, function (n) {
      if (n.tagClass !== "context" || n.tagNumber !== 0 || !n.constructed) return undefined;
      if (!n.children || n.children.length !== 1) return undefined;
      // A Certificate is a SEQUENCE of exactly three fields, which is what tells this `[0]` apart
      // from the ContentInfo's own `[0]` holding the SignedData.
      var kid = n.children[0];
      if (kid.tagClass !== "universal" || kid.tagNumber !== 16 || !kid.children ||
        kid.children.length !== 3) return undefined;
      return b.implicit(0, b.setOf(list.map(function (d) { return b.raw(d); })), true);
    });
  }
  // A shorter name sorts first, so this decoy is the one a reader taking the first match would pick.
  var decoyFirst = withCerts(skiToken, [cert, other]);
  check("T7g. a second certificate sharing the signer's subjectKeyIdentifier does not become the one the hint is compared against",
    has(pki.lint.tsp(withTsaHint(decoyFirst, subjectNameDer(other))), TSA_ID) &&
    !has(pki.lint.tsp(withTsaHint(decoyFirst, subjectNameDer(cert))), TSA_ID));
  // The same pair with the decoy's name long enough to sort last, so the verdict is shown not to
  // depend on which of them the SET OF order puts first.
  var longDecoy = await tsaCert("Some Other Authority With A Very Much Longer Name");
  var decoyLast = withCerts(skiToken, [cert, longDecoy]);
  check("T7h. and the verdict is the same when that certificate sorts last instead of first",
    has(pki.lint.tsp(withTsaHint(decoyLast, subjectNameDer(longDecoy))), TSA_ID) &&
    !has(pki.lint.tsp(withTsaHint(decoyLast, subjectNameDer(cert))), TSA_ID));
  // An element that hashes to nothing the ESS attribute names leaves the signer unresolved, which is
  // the same answer a token supplying its certificate out of band gets.
  check("T7i. a token carrying only a certificate the ESS certHash does not name is passed over",
    !has(pki.lint.tsp(withTsaHint(withCerts(skiToken, [strangerCert]), subjectNameDer(other))), TSA_ID));
  /** Replace the values SET of the signed attribute carrying `oidName`. */
  function reSignedAttr(tokenDer, oidName, valuesSet) {
    var wanted = b.oid(pki.oid.byName(oidName));
    return surgery.patch(tokenDer, function (n) {
      if (!n.constructed || n.tagNumber !== 16 || !n.children || n.children.length !== 2) return undefined;
      if (!wanted.equals(n.children[0].bytes)) return undefined;
      return b.sequence([b.raw(wanted), valuesSet]);
    });
  }
  // An ESS attribute whose value does not decode never reaches a rule: parseToken refuses the token,
  // so the operator gets the parser's own code. Asserted against that code rather than against the
  // row's silence, because a token that does not parse is silent about every row and asserting the
  // silence would pass whatever the reason.
  var essUnreadable = reSignedAttr(skiToken, "signingCertificateV2", b.set([b.integer(1n)]));
  var essRep = pki.lint.tsp(essUnreadable);
  check("T7j. a token whose ESS attribute value does not decode is refused by the parser, not graded",
    essRep.findings.length === 1 && essRep.findings[0].id === "lint/unparseable" &&
    essRep.findings[0].severity === "fatal" &&
    essRep.findings[0].context.code === "tsp/bad-token");
  // The hash naming an embedded element that is not a certificate DOES reach the row, and there is no
  // subject to compare a hint against. The element is given three children so it is shaped like a
  // Certificate to anything that counts children rather than reading one.
  var notACert = b.sequence([b.integer(1n), b.integer(2n), b.integer(3n)]);
  var notACertHash = crypto.createHash("sha256").update(notACert).digest();
  var essNamesJunk = reSignedAttr(withCerts(skiToken, [notACert]), "signingCertificateV2",
    b.set([b.sequence([b.sequence([b.sequence([b.octetString(notACertHash)])])])]));
  check("T7k. an ESS hash naming an embedded element that is not a certificate is passed over, and reports rather than throwing",
    !has(pki.lint.tsp(withTsaHint(essNamesJunk, subjectNameDer(other))), TSA_ID) &&
    !has(pki.lint.tsp(withTsaHint(essNamesJunk, subjectNameDer(cert))), TSA_ID));
  check("T7d. a dNSName hint differing only in case names the same host",
    !has(pki.lint.tsp(withTsaHintRaw(dnsToken, dnsHint("TSA.EXAMPLE.COM"))), TSA_ID) &&
    has(pki.lint.tsp(withTsaHintRaw(dnsToken, dnsHint("other.example.com"))), TSA_ID));

  // ---- T8-T9: the serial width, and an absent accuracy ----------------------------------------
  // "Time-Stamping users MUST be ready to accommodate integers up to 160 bits", so a serial wider
  // than that is one a conforming consumer need not accept.
  var wide = await token({ serialNumber: (1n << 200n) + 7n });
  check("T8. a serial number wider than 160 bits is reported at warn",
    sevOf(pki.lint.tsp(wide), "lint/rfc3161/serial-over-160-bits") === "warn" &&
    !has(cleanRep, "lint/rfc3161/serial-over-160-bits"));
  check("T8b. CONTROL: a serial of exactly 160 bits is not reported",
    !has(pki.lint.tsp(await token({ serialNumber: (1n << 159n) + 1n })),
      "lint/rfc3161/serial-over-160-bits"));
  // "When the accuracy optional field is not present, then the accuracy may be available through
  // other means, e.g., the TSAPolicyId", so its absence is a notice rather than a fault.
  check("T9. a token carrying no accuracy is a notice",
    sevOf(pki.lint.tsp(await pki.tsp.sign(imprint, { cert: cert, key: key },
      { policy: "1.2.3", serialNumber: 1 })), "lint/rfc3161/accuracy-absent") === "notice" &&
    !has(cleanRep, "lint/rfc3161/accuracy-absent"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
