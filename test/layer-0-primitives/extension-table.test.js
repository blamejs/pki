// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the public door onto the decoded extension table.
 *
 * `pki.schema.x509.parse` hands back an extension's raw extnValue octets, so a caller that wants
 * to know what a certificate actually asserts has to decode them itself, and four modules in this
 * toolkit did exactly that and each fell behind the shared reader. The door decodes them once,
 * under the rules the shared table carries.
 *
 * What it is held to here: it reports rather than refuses, it never loses the raw bytes, it does
 * not touch the parse result it was handed, and it tells the three outcomes apart with a field
 * rather than with a falsy value, because `ocspNoCheck` decodes VALIDLY to null.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("node:crypto");
var b = pki.asn1.build;

var kp = crypto.generateKeyPairSync("ed25519");
var SPKI = kp.publicKey.export({ format: "der", type: "spki" });

function algId() { return b.sequence([b.oid("1.3.101.112")]); }
function nameDer(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function ext(o, crit, val) {
  var kids = [b.oid(o)];
  if (crit) kids.push(b.boolean(true));
  kids.push(b.octetString(val));
  return b.sequence(kids);
}
/** A certificate built by hand, because the signer refuses to emit the non-conforming shapes the
 *  reporting arms exist for. */
function mkCert(exts) {
  var kids = [
    b.explicit(0, b.integer(2n)), b.integer(7n), algId(), nameDer("Issuer"),
    b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), b.utcTime(new Date("2030-01-01T00:00:00Z"))]),
    nameDer("Subject"), b.raw(SPKI),
  ];
  if (exts && exts.length) kids.push(b.explicit(3, b.sequence(exts)));
  var tbs = b.sequence(kids);
  return b.sequence([tbs, algId(), b.bitString(crypto.sign(null, tbs, kp.privateKey), 0)]);
}

var O = pki.oid.byName;
var BC = ext(O("basicConstraints"), true, b.sequence([b.boolean(true), b.integer(2n)]));
var KU = ext(O("keyUsage"), true, b.namedBitString([5, 6]));
var SKI = ext(O("subjectKeyIdentifier"), false, b.octetString(Buffer.alloc(20, 3)));
var SAN = ext(O("subjectAltName"), false, b.sequence([b.contextPrimitive(2, Buffer.from("a.example", "latin1"))]));

function rowFor(table, name) {
  for (var i = 0; i < table.length; i++) if (table[i].name === name) return table[i];
  return null;
}

function testAcceptsTheShapesARealCertificateTakes() {
  var der = mkCert([BC, KU, SKI, SAN]);
  var table = pki.schema.x509.decodeExtensions(der);
  check("1. every extension comes back as a row, in the order the SEQUENCE carries them",
    table.length === 4 && table[0].name === "basicConstraints" && table[3].name === "subjectAltName");
  check("2. each row names the scope it was read at and its position",
    table.every(function (r, i) { return r.scope === "certificate" && r.index === i; }));
  check("3. each known extension decoded", table.every(function (r) { return r.state === "decoded"; }));
  check("4. the decoded value is the structure the identifier names",
    rowFor(table, "basicConstraints").decoded.cA === true &&
    rowFor(table, "basicConstraints").decoded.pathLenConstraint === 2 &&
    rowFor(table, "keyUsage").decoded.keyCertSign === true);

  // Handed the parse result rather than the bytes, the answer is the same.
  var parsed = pki.schema.x509.parse(der);
  var fromParsed = pki.schema.x509.decodeExtensions(parsed);
  check("5. a parse result and its bytes give the same table",
    JSON.stringify(fromParsed) === JSON.stringify(table));

  // The door must not write on what it was handed: a parse result is marked as derived from one
  // byte string, and a verb that rebuilt or decorated it would be refused downstream.
  check("6. the parse result's own rows are untouched",
    parsed.extensions.every(function (e) {
      var keys = Object.keys(e).sort().join(",");
      return keys === "critical,name,oid,value" && Buffer.isBuffer(e.value);
    }));
  // A parse result is marked as derived from one byte string, and a verb that rebuilt or
  // decorated it would be refused by every consumer that asks for that mark. The linter is one.
  check("7. ...and a consumer that requires a parse result still accepts it afterwards",
    Array.isArray(pki.lint.certificate(parsed).findings));

  // Two calls hand back two arrays, so a caller that mutates one does not change the other.
  var again = pki.schema.x509.decodeExtensions(parsed);
  check("8. two calls are equal and are not the same array",
    again !== fromParsed && JSON.stringify(again) === JSON.stringify(fromParsed));

  var none = pki.schema.x509.decodeExtensions(mkCert(null));
  check("9. a certificate carrying no extensions is an empty table, not a throw",
    Array.isArray(none) && none.length === 0);
}

function testTheThreeStatesAreToldApartByAField() {
  // An OID no decoder is registered for. Never a throw, whatever its criticality, because a
  // reader that refused one could not open a certificate carrying a private critical extension.
  var priv = ext("1.3.6.1.4.1.99999.7", true, b.utf8("whatever this is"));
  var t1 = pki.schema.x509.decodeExtensions(mkCert([BC, priv]));
  var privRow = t1[1];
  check("10. an OID with no decoder is unrecognized rather than a fault",
    privRow.state === "unrecognized" && privRow.decoded === null && privRow.code === null);
  check("11. ...and it keeps its critical flag, which is the fact the RFC 5280 sec. 4.2 rule needs",
    privRow.critical === true);

  // A known OID whose value is not the structure it names.
  var badBc = ext(O("basicConstraints"), true, b.utf8("not a BasicConstraints"));
  var t2 = pki.schema.x509.decodeExtensions(mkCert([badBc]));
  check("12. a known OID whose value does not read is undecodable, with the typed code",
    t2[0].state === "undecodable" && t2[0].decoded === null &&
    typeof t2[0].code === "string" && t2[0].code.indexOf("x509/") === 0);

  // The three states are a FIELD, never a truthiness test on `decoded`: ocspNoCheck decodes
  // validly to null, so `decoded === null` cannot mean "did not decode".
  var noCheck = ext(O("ocspNoCheck"), false, b.nullValue());
  var t3 = pki.schema.x509.decodeExtensions(mkCert([noCheck]));
  check("13. ocspNoCheck decodes VALIDLY to null, so decoded is not the discriminator",
    t3[0].state === "decoded" && t3[0].decoded === null);
  check("14. ...which is the same decoded value an undecodable row carries",
    t2[0].decoded === t3[0].decoded && t2[0].state !== t3[0].state);
}

function testTheRawBytesSurviveEveryArm() {
  // A second basicConstraints is refused by the parse, so the undecodable arm here is a different
  // known identifier: a subjectKeyIdentifier whose value is not the OCTET STRING it names.
  var badSki = ext(O("subjectKeyIdentifier"), false, b.utf8("not a key identifier"));
  var priv = ext("1.3.6.1.4.1.99999.7", false, b.utf8("private"));
  var der = mkCert([BC, badSki, priv]);
  var parsed = pki.schema.x509.parse(der);
  var table = pki.schema.x509.decodeExtensions(parsed);
  check("15. every row carries the extnValue octets, byte-identical to the parse result's",
    table.every(function (r, i) { return r.value.equals(parsed.extensions[i].value); }));
  check("16. ...including the arm that could not decode and the arm nothing decodes",
    table[1].state === "undecodable" && Buffer.isBuffer(table[1].value) &&
    table[2].state === "unrecognized" && Buffer.isBuffer(table[2].value));
}

function nameConstraintsExt(critical) {
  return ext(O("nameConstraints"), critical,
    b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "latin1"))]))]));
}

function testTheCriticalityProfileIsReportedNeverEnforced() {
  // nameConstraints is fixed critical by RFC 5280 sec. 4.2.1.10. A non-critical one is
  // non-conforming and is REPORTED: enforcing at the door would make it impossible to open the
  // certificate that a linter exists to report on.
  var nc = nameConstraintsExt(false);
  var t = pki.schema.x509.decodeExtensions(mkCert([nc]));
  check("17. an extension against its fixed criticality still decodes",
    t[0].state === "decoded");
  check("18. ...and the deviation is reported with the clause that fixes it",
    t[0].profile !== null && t[0].profile.criticalExpected === true &&
    t[0].profile.deviates === true && /4\.2\.1\.10/.test(t[0].profile.citation));

  var ok = pki.schema.x509.decodeExtensions(mkCert([nameConstraintsExt(true)]));
  check("19. CONTROL: the conforming criticality does not deviate",
    ok[0].profile.deviates === false);

  // An OID whose criticality the CA chooses carries no profile row at all.
  var t2 = pki.schema.x509.decodeExtensions(mkCert([BC]));
  check("20. an extension whose criticality the CA chooses has no profile row",
    t2[0].profile === null);
  check("20b. a profile row carries the criticality, its clause and the deviation, and nothing else",
    Object.keys(rowFor(pki.schema.x509.decodeExtensions(mkCert([nameConstraintsExt(false)])), "nameConstraints").profile)
      .sort().join(",") === "citation,criticalExpected,deviates");

  // The RFC 6962 poison is the row that makes this load-bearing: its whole meaning is the
  // critical flag, and its decoded value reads as benign.
  var poison = ext(O("precertificatePoison"), true, b.nullValue());
  var tp = pki.schema.x509.decodeExtensions(mkCert([poison]));
  check("21. the precertificate poison carries its criticality and its citation",
    tp[0].critical === true && tp[0].profile !== null && /6962/.test(tp[0].profile.citation));
}

function testStrictTurnsOnlyTheUndecodableArmIntoAThrow() {
  var badBc = ext(O("basicConstraints"), true, b.utf8("not a BasicConstraints"));
  var priv = ext("1.3.6.1.4.1.99999.7", true, b.utf8("private"));

  var threw = null;
  try { pki.schema.x509.decodeExtensions(mkCert([badBc]), { strict: true }); }
  catch (e) { threw = e.code; }
  check("22. strict throws the decoder's own typed error on an undecodable value",
    typeof threw === "string" && threw.indexOf("x509/") === 0);

  // strict does NOT turn an unrecognized OID into a throw, at any scope: an OID nothing decodes
  // is not an error at all, and a critical one is the caller's rule to apply.
  var t = pki.schema.x509.decodeExtensions(mkCert([priv]), { strict: true });
  check("23. strict leaves an unrecognized critical extension as a row, not a throw",
    t.length === 1 && t[0].state === "unrecognized" && t[0].critical === true);
}

function testTheDoorRefusesWhatEveryOtherDoorRefuses() {
  check("24. an unknown option is refused rather than ignored",
    (function () {
      try { pki.schema.x509.decodeExtensions(mkCert([BC]), { strick: true }); return false; }
      catch (e) { return e.code === "x509/bad-input"; }
    })());
  check("25. bytes that are not a certificate are refused by the parse the door composes",
    (function () {
      try { pki.schema.x509.decodeExtensions(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])); return false; }
      catch (e) { return typeof e.code === "string" && e.isPkiError === true; }
    })());
}

// ---- the door at the other four scopes --------------------------------------------------------
// The same eleven-field row, the same three states, the same caps, at every scope the toolkit
// reads an extension at. A door covering one format and not the rest is the shape these vectors
// exist to refuse.

var ROW_FIELDS = "code,containerIndex,critical,decoded,index,name,oid,profile,scope,state,value";
function fieldsOf(row) { return Object.keys(row).sort().join(","); }

async function testTheCrlDoorReadsBothScopes() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var caCert = await pki.x509.sign({
    subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: key });
  var crlDer = await pki.crl.sign({
    thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 7n,
    revoked: [
      { serialNumber: 0x0a3fn, revocationDate: new Date("2026-01-15T00:00:00Z"), reason: "keyCompromise" },
      { serialNumber: 0x0a40n, revocationDate: new Date("2026-01-16T00:00:00Z"), invalidityDate: new Date("2026-01-14T00:00:00Z") },
    ],
  }, { cert: caCert, key: key });

  var rows = pki.schema.crl.decodeExtensions(crlDer);
  check("26. one array spans both CRL scopes, the CRL's own rows first",
    rows.length > 2 && rows[0].scope === "crl" &&
    rows.filter(function (r) { return r.scope === "crl-entry"; }).length >= 2);
  check("27. a CRL row names no container and an entry row names its entry",
    rows.filter(function (r) { return r.scope === "crl"; }).every(function (r) { return r.containerIndex === null; }) &&
    rows.filter(function (r) { return r.scope === "crl-entry"; }).every(function (r) { return typeof r.containerIndex === "number"; }));
  check("28. the two entries' rows are told apart by containerIndex",
    rowFor(rows, "reasonCode").containerIndex === 0 && rowFor(rows, "invalidityDate").containerIndex === 1);
  check("29. the CRL's cRLNumber decodes to the number it was signed with",
    rowFor(rows, "cRLNumber").decoded === 7n && rowFor(rows, "cRLNumber").state === "decoded");
  check("30. a row's value is the raw extnValue octets even where the parse decoded it in place",
    rows.every(function (r) { return Buffer.isBuffer(r.value); }));

  // The parse decodes cRLNumber, reasonCode and invalidityDate onto `value`, so the raw octets it
  // kept beside them are what makes the two routes agree byte for byte.
  var parsed = pki.schema.crl.parse(crlDer);
  function shot(rs) { return rs.map(function (r) { return r.scope + "|" + r.oid + "|" + r.state + "|" + String(r.decoded) + "|" + r.value.toString("hex"); }).join(";"); }
  check("31. a parse result and its bytes give the same table", shot(pki.schema.crl.decodeExtensions(parsed)) === shot(rows));
  check("32. the parse result carries the raw octets of every extension it decoded in place",
    parsed.crlExtensions.every(function (e) { return Buffer.isBuffer(e.valueBytes); }) &&
    parsed.revokedCertificates[0].crlEntryExtensions.every(function (e) { return Buffer.isBuffer(e.valueBytes); }));

  // v0.8.0 item 11 carried forward: the scope decides which table answers, so an extension met at
  // the wrong scope is simply unrecognized rather than a fault.
  var num = parsed.crlExtensions.filter(function (e) { return e.name === "cRLNumber"; })[0];
  var asRecord = { oid: num.oid, name: num.name, critical: num.critical, value: num.valueBytes };
  check("33. cRLNumber at CRL scope decodes", pki.schema.crl.decodeExtension(asRecord, { scope: "crl" }).state === "decoded");
  check("34. ...and at entry scope is unrecognized, because no decoder is registered there",
    pki.schema.crl.decodeExtension(asRecord, { scope: "crl-entry" }).state === "unrecognized");
  check("35. RFC 6960 sec. 4.4.5's OCSP scope reads the entry table and says so on the row",
    pki.schema.crl.decodeExtension(asRecord, { scope: "ocsp-single" }).scope === "ocsp-single");

  // Three scopes and no natural default, so the scope is required rather than guessed.
  check("36. the CRL single-extension verb requires a scope", (function () {
    try { pki.schema.crl.decodeExtension(asRecord); return false; }
    catch (e) { return e.code === "crl/bad-input"; }
  })());
  check("37. ...and refuses a scope no table answers for", (function () {
    try { pki.schema.crl.decodeExtension(asRecord, { scope: "certificate" }); return false; }
    catch (e) { return e.code === "crl/bad-input"; }
  })());
  check("38. every CRL row carries the same eleven fields every other scope's rows carry",
    rows.every(function (r) { return fieldsOf(r) === ROW_FIELDS; }));
}

async function testTheCsrDoorReadsWhatWasAskedFor() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var csrDer = await pki.csr.sign({
    subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey),
    extensionRequest: { subjectAltName: [{ dNSName: "req.example" }], basicConstraints: { cA: false } },
  }, { key: key });

  var rows = pki.schema.csr.decodeExtensions(csrDer);
  check("39. a request's extensions come back decoded, at the csr-requested scope",
    rows.length === 2 && rows.every(function (r) { return r.scope === "csr-requested" && r.state === "decoded"; }));
  check("40. each row names the attribute it came from",
    rows.every(function (r) { return r.containerIndex === 0; }));
  check("41. the row shape is the one every other scope uses",
    rows.every(function (r) { return fieldsOf(r) === ROW_FIELDS; }));
  check("42. a single requested extension reads the same through the one-row verb",
    pki.schema.csr.decodeExtension(pki.schema.csr.parse(csrDer).attributes[0].extensions[0]).state === "decoded");

  // RFC 2985 sec. 5.4.2 makes a request's criticality a request. The profile is reported, because
  // a CA honoring it as asked would issue a certificate against RFC 5280.
  check("43. a requested criticality against the certificate profile is reported, not refused",
    rows.every(function (r) { return r.profile === null || typeof r.profile.deviates === "boolean"; }));

  // Nothing in RFC 2985 says which of two extensionRequest attributes a CA should honor, and
  // `schema.implicitSetOf(0, ...)` puts no `unique` or `max` on the attribute set, so a request
  // carrying two parses. Picking one silently is the defect; refusing is the door's answer.
  var two = twoExtensionRequestCsr(csrDer);
  check("44. a request carrying two extensionRequest attributes is refused rather than resolved",
    (function () {
      try { pki.schema.csr.decodeExtensions(two); return false; }
      catch (e) { return e.code === "csr/ambiguous-extension-request"; }
    })());
  var groups = pki.schema.csr.decodeExtensions(two, { groups: true });
  check("45. ...and groups: true reads each one separately, each naming its attribute",
    groups.length === 2 && groups[0].attributeIndex !== groups[1].attributeIndex &&
    groups.every(function (g) { return g.extensions.every(function (r) { return r.containerIndex === g.attributeIndex; }); }));
  check("46. CONTROL: groups: true on a conforming request is one group",
    pki.schema.csr.decodeExtensions(csrDer, { groups: true }).length === 1);
  check("47. groups is offered by the door that has groups and by no other", (function () {
    try { pki.schema.x509.decodeExtensions(mkCert([BC]), { groups: true }); return false; }
    catch (e) { return e.code === "x509/bad-input"; }
  })());
}

/** Rebuild a signed CSR's CertificationRequestInfo with its one extensionRequest attribute
 *  repeated. The signature no longer covers the bytes, which `parse` does not check and this
 *  door does not either -- reading what a request asked for is not verifying it. */
function twoExtensionRequestCsr(csrDer) {
  var root = pki.asn1.decode(csrDer);
  var cri = root.children[0];
  var attrs = cri.children[3];
  var one = attrs.children[0].bytes;
  var dup = b.contextConstructed(0, Buffer.concat([one, one]));
  var newCri = b.sequence([cri.children[0].bytes, cri.children[1].bytes, cri.children[2].bytes, dup]);
  return b.sequence([newCri, root.children[1].bytes, root.children[2].bytes]);
}

async function testTheAttributeCertificateDoorReadsItsOwnTable() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var aaCert = await pki.x509.sign({
    subject: "Example AA", subjectPublicKey: await pki.key.export(pair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
  }, { key: key });
  var acDer = await pki.attrcert.sign({
    holder: { entityName: [{ directoryName: "CN=Holder" }] },
    attributes: { role: { roleName: "https://example.test/role/admin" } }, serialNumber: 1n,
    notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
    extensions: { noRevAvail: true },
  }, { cert: aaCert, key: key });

  var rows = pki.schema.attrcert.decodeExtensions(acDer);
  check("48. an attribute certificate's extensions decode at their own scope",
    rows.length >= 1 && rows.every(function (r) { return r.scope === "attribute-certificate" && r.state === "decoded"; }));
  check("49. the row shape is the one every other scope uses",
    rows.every(function (r) { return fieldsOf(r) === ROW_FIELDS && r.containerIndex === null; }));
  check("50. the criticality RFC 5755 fixes is reported with its clause",
    rowFor(rows, "noRevAvail").profile.criticalExpected === false &&
    rowFor(rows, "noRevAvail").profile.citation === "RFC 5755 sec. 4.3.6");
  check("51. the one-row verb answers the same",
    pki.schema.attrcert.decodeExtension(pki.schema.attrcert.parse(acDer).extensions[0]).state === "decoded");

  // The signer refuses to write an extension against its fixed criticality, and it reads the
  // criticality off the same table the door reports from, so the two cannot drift apart.
  var refused = null;
  try {
    await pki.attrcert.sign({
      holder: { entityName: [{ directoryName: "CN=Holder" }] },
      attributes: { role: { roleName: "https://example.test/role/admin" } }, serialNumber: 2n,
      notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
      extensions: [b.sequence([b.oid(pki.oid.byName("noRevAvail")), b.boolean(true), b.octetString(b.nullValue())])],
    }, { cert: aaCert, key: key });
  } catch (e) { refused = e; }
  check("52. the signer refuses the criticality the door reports as fixed, citing the same clause",
    refused !== null && refused.code === "attrcert/bad-input" &&
    refused.message.indexOf("RFC 5755 sec. 4.3.6") !== -1);

  // The three RFC 5280 extensions RFC 5755 sec. 4.3.3 to 4.3.5 profile for an AC read through the
  // certificate decoders, reached with no walk context: the signer validates a pre-encoded one
  // outside any parse, so that route has to answer too.
  var dpName = b.contextConstructed(0, b.contextConstructed(0,
    b.contextPrimitive(6, Buffer.from("http://crl.example/aa.crl", "latin1"))));
  var aki = b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")),
    b.octetString(b.sequence([b.sequence([dpName])]))]);
  var withAki = await pki.attrcert.sign({
    holder: { entityName: [{ directoryName: "CN=Holder" }] },
    attributes: { role: { roleName: "https://example.test/role/admin" } }, serialNumber: 3n,
    notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
    extensions: [aki],
  }, { cert: aaCert, key: key });
  check("52b. a pre-encoded certificate extension validates and decodes on both sides",
    rowFor(pki.schema.attrcert.decodeExtensions(withAki), "cRLDistributionPoints").state === "decoded");
  var badAki = b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")), b.octetString(b.utf8("not a DP"))]);
  var akiRefused = null;
  try {
    await pki.attrcert.sign({
      holder: { entityName: [{ directoryName: "CN=Holder" }] },
      attributes: { role: { roleName: "https://example.test/role/admin" } }, serialNumber: 4n,
      notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
      extensions: [badAki],
    }, { cert: aaCert, key: key });
  } catch (e) { akiRefused = e.code; }
  check("52c. ...and the signer refuses to emit one whose value does not read, with the decoder's code",
    akiRefused === "attrcert/bad-crl-distribution-points");
}

async function testTheCrmfDoorReadsEveryTemplate() {
  var pair = await pki.key.generate("Ed25519");
  var pub = await pki.key.export(pair.publicKey);
  var key = await pki.key.export(pair.privateKey);
  var der = await pki.crmf.build({
    messages: [
      { certReqId: 0, certTemplate: { subject: "one.example", publicKey: pub,
        extensions: { subjectAltName: [{ dNSName: "one.example" }] } } },
      { certReqId: 1, certTemplate: { subject: "two.example", publicKey: pub,
        extensions: { subjectAltName: [{ dNSName: "two.example" }], basicConstraints: { cA: false } } } },
    ],
  }, { key: key });

  var rows = pki.schema.crmf.decodeExtensions(der);
  check("53. every message's template contributes its rows, each naming its message",
    rows.length === 3 &&
    rows.filter(function (r) { return r.containerIndex === 0; }).length === 1 &&
    rows.filter(function (r) { return r.containerIndex === 1; }).length === 2);
  check("54. the rows read at the CRMF template scope and share the row shape",
    rows.every(function (r) { return r.scope === "crmf-template" && fieldsOf(r) === ROW_FIELDS; }));
  check("55. the one-row verb answers the same",
    pki.schema.crmf.decodeExtension(
      pki.schema.crmf.parse(der).messages[0].certReq.certTemplate.extensions[0]).name === "subjectAltName");
}

// ---- the properties that must hold at every scope ---------------------------------------------

async function testTheCapsAndTheRefusalsAreTheSameAtEveryDoor() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var certDer = await pki.x509.sign({
    subject: "leaf.example", subjectPublicKey: await pki.key.export(pair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: { subjectAltName: [{ dNSName: "a.example" }, { dNSName: "b.example" }, { dNSName: "c.example" }] },
  }, { key: key });

  // The caps bound the decoding THIS call performs, which is the whole reason they are offered on a
  // door whose input may already be parsed: a caller handed a parse result has no other way to
  // bound the work, because the parse that produced it is over. A decoder built against the
  // module's own namespace would carry the module's ceilings instead, and the table verb on bytes
  // is the ONE shape where the parse refuses first and hides that.
  var parsedCert = pki.schema.x509.parse(certDer);
  function refusedUnder(call) {
    try { call(); return null; }
    catch (e) { return e.code; }
  }
  check("56. the caps reach the decode when the door is handed a parse result",
    refusedUnder(function () { return pki.schema.x509.decodeExtensions(parsedCert, { maxItems: 2 }); }) === "x509/too-large");
  check("57. CONTROL: the same call under the default caps decodes all three names",
    pki.schema.x509.decodeExtensions(parsedCert)
      .filter(function (r) { return r.name === "subjectAltName"; })[0].decoded.names.length === 3);
  // The caps bound the decoding, so a cap smaller than the whole certificate but larger than the
  // extension value still decodes it. Re-deriving the parse result to prove its provenance is not
  // work this call asked for, and a cap applied there would refuse a value that fits.
  check("57b. a cap too small for the object but large enough for the value still decodes it",
    pki.schema.x509.decodeExtensions(parsedCert, { maxBytes: 100 })
      .filter(function (r) { return r.name === "subjectAltName"; })[0].state === "decoded");
  check("57c. CONTROL: the same cap on the BYTES is refused, because that parse is this call's work",
    refusedUnder(function () { return pki.schema.x509.decodeExtensions(certDer, { maxBytes: 100 }); }) === "x509/too-large");
  check("58. a cap above the built-in ceiling is refused, because a cap may only tighten",
    refusedUnder(function () { return pki.schema.x509.decodeExtensions(certDer, { maxBytes: pki.C.LIMITS.DER_MAX_BYTES + 1 }); }) === "x509/bad-input");

  // The single-extension verb has no parse in front of it at all, so it is where a table bound to
  // the module's namespace decodes a value the caller's caps forbid and reports it as decoded.
  var bcValue = Buffer.from("30030101ff", "hex");
  var singleDoors = [
    ["x509", pki.schema.x509.decodeExtension, { oid: O("basicConstraints"), name: "basicConstraints", critical: true, value: bcValue }, { maxBytes: 1, maxItems: 1 }, undefined],
    ["csr", pki.schema.csr.decodeExtension, { oid: O("basicConstraints"), name: "basicConstraints", critical: true, value: bcValue }, { maxBytes: 1, maxItems: 1 }, undefined],
    ["crmf", pki.schema.crmf.decodeExtension, { oid: O("basicConstraints"), name: "basicConstraints", critical: true, value: bcValue }, { maxBytes: 1, maxItems: 1 }, undefined],
    ["crl", pki.schema.crl.decodeExtension, { oid: O("cRLNumber"), name: "cRLNumber", critical: false, value: b.integer(7n) }, { scope: "crl", maxBytes: 1 }, { scope: "crl" }],
    ["attrcert", pki.schema.attrcert.decodeExtension, { oid: O("noRevAvail"), name: "noRevAvail", critical: false, value: b.nullValue() }, { maxBytes: 1 }, undefined],
  ];
  check("59. every single-extension verb refuses a value its caller's caps cannot afford",
    singleDoors.every(function (d) {
      return refusedUnder(function () { return d[1](d[2], d[3]); }) === d[0] + "/too-large";
    }));
  check("60. CONTROL: every one of them decodes that same value under the default caps",
    singleDoors.every(function (d) { return d[1](d[2], d[4]).state === "decoded"; }));

  // The one-row verbs take a record, not an object, and refuse a shape they cannot read rather
  // than reading a field off whatever they were handed.
  var doors = [
    ["x509", pki.schema.x509.decodeExtension, undefined],
    ["csr", pki.schema.csr.decodeExtension, undefined],
    ["attrcert", pki.schema.attrcert.decodeExtension, undefined],
    ["crmf", pki.schema.crmf.decodeExtension, undefined],
    ["crl", pki.schema.crl.decodeExtension, { scope: "crl" }],
  ];
  var refusedNonRecord = doors.every(function (d) {
    try { d[1]({ oid: "2.5.29.19", critical: true, value: "not bytes" }, d[2]); return false; }
    catch (e) { return e.code === d[0] + "/bad-input"; }
  });
  check("61. every one-row verb refuses a record whose value is not the raw octets", refusedNonRecord);
  var refusedNoOid = doors.every(function (d) {
    try { d[1]({ name: "basicConstraints", critical: true, value: Buffer.from([0x30, 0x00]) }, d[2]); return false; }
    catch (e) { return e.code === d[0] + "/bad-input"; }
  });
  check("62. ...and one with no identifier, which every OID-keyed lookup would miss", refusedNoOid);

  // A caller's mutable byte view is read once: the bytes the row reports are the bytes decoded.
  var live = new Uint8Array([0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02]);
  var row = pki.schema.x509.decodeExtension({ oid: O("basicConstraints"), name: "basicConstraints", critical: true, value: live });
  live[4] = 0x00;
  check("63. the row's bytes are the bytes that were decoded, not a later reading of the caller's array",
    row.decoded.cA === true && row.value[4] === 0xff);

  var tableDoors = [
    ["x509", pki.schema.x509.decodeExtensions],
    ["crl", pki.schema.crl.decodeExtensions],
    ["csr", pki.schema.csr.decodeExtensions],
    ["attrcert", pki.schema.attrcert.decodeExtensions],
    ["crmf", pki.schema.crmf.decodeExtensions],
  ];
  check("64. every table verb refuses an unknown option rather than ignoring it",
    tableDoors.every(function (d) {
      try { d[1](certDer, { strick: true }); return false; }
      catch (e) { return e.code === d[0] + "/bad-input"; }
    }));
  check("65. every table verb refuses bytes that are not its own format",
    tableDoors.slice(1).every(function (d) {
      try { d[1](certDer); return false; }
      catch (e) { return typeof e.code === "string" && e.isPkiError === true; }
    }));
}

// ---- the line between a shape fault and a profile violation -----------------------------------

async function testAProfileRuleSixProducersEnforceStaysARefusal() {
  // RFC 5280 sec. 4.2.1.9 permits `pathLenConstraint` beside an absent `cA` in the ASN.1 module and
  // forbids it in prose, so it reads as a profile violation the door could report rather than
  // refuse. It stays a refusal because the same decoder is what every signer validates a
  // pre-encoded extension through, and a reported violation there is an emitted one.
  var bad = ext(O("basicConstraints"), true, b.sequence([b.integer(3n)]));
  var row = pki.schema.x509.decodeExtensions(mkCert([bad]))[0];
  check("66. pathLenConstraint without cA is undecodable rather than a reported violation",
    row.state === "undecodable" && row.code === "x509/bad-basic-constraints");

  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var pub = await pki.key.export(pair.publicKey);
  async function refusedBy(sign) {
    try { await sign(); return null; }
    catch (e) { return e.code; }
  }
  check("67. the certificate signer refuses to emit it, through that same decoder",
    (await refusedBy(function () {
      return pki.x509.sign({ subject: "leaf.example", subjectPublicKey: pub,
        notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
        extensions: [bad] }, { key: key });
    })) === "x509/bad-basic-constraints");
  check("68. ...and so does the request signer, which shares it",
    (await refusedBy(function () {
      return pki.csr.sign({ subject: "req.example", subjectPublicKey: pub, extensionRequest: [bad] }, { key: key });
    })) === "csr/bad-basic-constraints");
  check("69. CONTROL: the conforming form is emitted and decodes",
    pki.schema.x509.decodeExtensions(await pki.x509.sign({ subject: "ca.example", subjectPublicKey: pub,
      notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
      extensions: { basicConstraints: { cA: true, pathLen: 3 }, keyUsage: ["keyCertSign"] } }, { key: key }))
      .filter(function (r) { return r.name === "basicConstraints"; })[0].decoded.pathLenConstraint === 3);
}

// ---- the decoders this cut adds to the tables -------------------------------------------------

function testTheTableGrewFiveDecoders() {
  // RFC 7633 sec. 4: Features ::= SEQUENCE OF INTEGER, each a TLS ExtensionType.
  var f = pki.schema.x509.decodeExtensions(mkCert([ext(O("tlsFeature"), false,
    b.sequence([b.integer(5n), b.integer(17n)]))]))[0];
  check("70. tlsFeature decodes to the features it lists", f.state === "decoded" &&
    f.decoded.features.length === 2 && f.decoded.features[0] === 5n && f.decoded.features[1] === 17n);
  // The type carries neither a SIZE constraint on the SEQUENCE OF nor a range on the INTEGER, so a
  // decoder refusing an empty list or a number outside the registry's 16-bit width would be
  // stricter than the module and would make an extension unreadable over a number's value. What
  // the RFC does fix is the type of each element.
  check("71. a Features that is empty or carries a number outside the registry width still decodes",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("tlsFeature"), false, b.sequence([b.integer(65536n)]))]))[0].decoded.features[0] === 65536n &&
    pki.schema.x509.decodeExtensions(mkCert([ext(O("tlsFeature"), false, b.sequence([]))]))[0].decoded.features.length === 0);
  check("71b. ...and an element that is not an INTEGER at all is refused",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("tlsFeature"), false, b.sequence([b.utf8("five")]))]))[0].state === "undecodable");

  // RFC 3779 sec. 2.2.3: an IPAddress is a BIT STRING whose length in bits is the prefix length.
  var v4 = b.sequence([b.octetString(Buffer.from([0x00, 0x01])),
    b.sequence([b.bitString(Buffer.from([10]), 0),
      b.sequence([b.bitString(Buffer.from([192, 0, 2]), 0), b.bitString(Buffer.from([192, 0, 2]), 0)])])]);
  var v6 = b.sequence([b.octetString(Buffer.from([0x00, 0x02])), b.nullValue()]);
  var ip = pki.schema.x509.decodeExtensions(mkCert([ext(O("ipAddrBlocks"), true, b.sequence([v4, v6]))]))[0];
  check("72. ipAddrBlocks reads the family, the prefix length and the range",
    ip.state === "decoded" && ip.decoded.families.length === 2 &&
    ip.decoded.families[0].afi === 1 && ip.decoded.families[0].safi === null &&
    ip.decoded.families[0].addressesOrRanges[0].addressPrefix.prefixLength === 8 &&
    ip.decoded.families[0].addressesOrRanges[1].kind === "addressRange");
  check("73. ...and an inherit family is the NULL arm, not an empty list",
    ip.decoded.families[1].inherit === true && ip.decoded.families[1].addressesOrRanges === null);
  // RFC 3779 sec. 2.1.2: the bits a range endpoint leaves off are zero in min and ONE in max, so a
  // max written out zero-filled names a different address from the one the range ends at. The
  // renderer is where that shows, and a range endpoint is an address rather than a prefix.
  var rendered = pki.inspect.certificate(mkCert([ext(O("ipAddrBlocks"), true, b.sequence([v4]))]));
  check("73b. a range's max is rendered with its omitted bits set, and neither endpoint as a prefix",
    rendered.indexOf("192.0.2.0 to 192.0.2.255") !== -1);
  check("73c. CONTROL: a prefix is still rendered as an address and its length in bits",
    rendered.indexOf("10.0.0.0/8") !== -1);

  check("74. an addressFamily outside the 2..3 octet size is refused",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("ipAddrBlocks"), true,
      b.sequence([b.sequence([b.octetString(Buffer.from([1])), b.nullValue()])]))]))[0].state === "undecodable");

  // RFC 3779 sec. 3.2.3, with both arms EXPLICIT because ASIdentifierChoice is a CHOICE.
  var asn = b.sequence([
    b.explicit(0, b.sequence([b.integer(64496n), b.sequence([b.integer(64500n), b.integer(64510n)])])),
    b.explicit(1, b.nullValue()),
  ]);
  var as = pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIds"), true, asn)]))[0];
  check("75. autonomousSysIds reads an id, a range and an inherit arm",
    as.state === "decoded" && as.decoded.asnum.asIdsOrRanges[0].id === 64496n &&
    as.decoded.asnum.asIdsOrRanges[1].min === 64500n && as.decoded.asnum.asIdsOrRanges[1].max === 64510n &&
    as.decoded.rdi.inherit === true);
  // ASId is a plain INTEGER, so an AS number past the 32 bits RFC 6793 gives the registry is a
  // number the caller judges rather than a value this reader refuses.
  check("75b. an AS number wider than the registry's 32 bits still decodes",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIds"), true,
      b.sequence([b.explicit(0, b.sequence([b.integer(4294967296n)]))]))]))[0]
      .decoded.asnum.asIdsOrRanges[0].id === 4294967296n);
  // Both arms are OPTIONAL, so an ASIdentifiers carrying neither is well-formed and decodes to two
  // absent arms. Their ORDER is a DER rule and is enforced.
  check("76. ASIdentifiers arms out of tag order are refused; an ASIdentifiers with neither is not",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIds"), true,
      b.sequence([b.explicit(1, b.nullValue()), b.explicit(0, b.nullValue())]))]))[0].state === "undecodable" &&
    pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIds"), true, b.sequence([]))]))[0].decoded.asnum === null);

  // RFC 8360 gives the same syntax new identifiers, so one decoder answers for both.
  // RFC 3779 sec. 2.2.2 and sec. 3.2.2 both fix these extensions critical, so a non-critical one is
  // a deviation the door reports and the certificate signer refuses to write.
  check("76b. the resource extensions carry the criticality their RFC fixes, and report a deviation",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("ipAddrBlocks"), true, b.sequence([v4]))]))[0].profile.deviates === false &&
    pki.schema.x509.decodeExtensions(mkCert([ext(O("ipAddrBlocks"), false, b.sequence([v4]))]))[0].profile.deviates === true &&
    pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIds"), false, asn)]))[0].profile.citation === "RFC 3779 sec. 3.2.2");

  // Every arm that refuses a value of the wrong type, driven. An RFC 3779 structure is nested four
  // deep, and a reader that fell through any one of these would hand a caller a record built from
  // whatever it found there.
  function refusesIp(value) {
    return pki.schema.x509.decodeExtensions(mkCert([ext(O("ipAddrBlocks"), true, value)]))[0].state === "undecodable";
  }
  function refusesAs(value) {
    return pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIds"), true, value)]))[0].state === "undecodable";
  }
  var afi4 = b.octetString(Buffer.from([0x00, 0x01]));
  check("76c. an IPAddressOrRange that is neither a prefix nor a two-element range is refused",
    refusesIp(b.sequence([b.sequence([afi4, b.sequence([b.integer(10n)])])])) &&
    refusesIp(b.sequence([b.sequence([afi4, b.sequence([b.sequence([b.bitString(Buffer.from([10]), 0)])])])])) &&
    refusesIp(b.sequence([b.sequence([afi4, b.sequence([b.sequence([b.bitString(Buffer.from([10]), 0), b.integer(11n)])])])])));
  check("76d. an IPAddressChoice that is neither the inherit NULL nor a SEQUENCE is refused",
    refusesIp(b.sequence([b.sequence([afi4, b.integer(1n)])])) &&
    refusesIp(b.sequence([b.sequence([afi4, b.sequence([]), b.integer(1n)])])));
  check("76e. an ASIdentifierChoice that is neither the inherit NULL nor a SEQUENCE is refused",
    refusesAs(b.sequence([b.explicit(0, b.integer(1n))])) &&
    refusesAs(b.sequence([b.explicit(0, b.sequence([b.utf8("64496")]))])) &&
    refusesAs(b.sequence([b.explicit(0, b.sequence([b.sequence([b.integer(1n), b.utf8("2")])]))])));
  check("76f. an ASIdentifiers component outside asnum [0] and rdi [1] is refused",
    refusesAs(b.sequence([b.explicit(2, b.nullValue())])) &&
    refusesAs(b.sequence([b.integer(1n)])));

  // The renderer is operator-facing, so every arm of it is driven: a feature the registry names and
  // one it does not, an inherit arm, a range, and an empty value.
  function renders(name, critical, value) {
    return pki.inspect.certificate(mkCert([ext(O(name), critical, value)]));
  }
  var feat = renders("tlsFeature", false, b.sequence([b.integer(5n), b.integer(4242n)]));
  check("76g. a named TLS feature renders with its name and a number, an unnamed one as its number",
    feat.indexOf("status_request (5)") !== -1 && feat.indexOf("4242") !== -1);
  check("76h. an empty Features renders as none rather than as an empty line",
    renders("tlsFeature", false, b.sequence([])).indexOf("(none)") !== -1);
  var asRender = renders("autonomousSysIds", true, b.sequence([
    b.explicit(0, b.sequence([b.integer(64496n), b.sequence([b.integer(64500n), b.integer(64510n)])])),
    b.explicit(1, b.nullValue()),
  ]));
  check("76i. an AS list renders its ids, its ranges and its inherit arm",
    asRender.indexOf("64496") !== -1 && asRender.indexOf("64500 to 64510") !== -1 &&
    asRender.indexOf("rdi: inherit") !== -1);
  check("76j. an ASIdentifiers with neither arm renders as none",
    renders("autonomousSysIds", true, b.sequence([])).indexOf("(none)") !== -1);
  var ipRender = renders("ipAddrBlocks", true, b.sequence([v4, v6]));
  check("76k. an address family renders its name, and an inherit family says so",
    ipRender.indexOf("IPv4") !== -1 && ipRender.indexOf("IPv6: inherit") !== -1);
  check("76l. a family with an empty address list renders as none, and an unregistered AFI by number",
    renders("ipAddrBlocks", true, b.sequence([b.sequence([b.octetString(Buffer.from([0x00, 0x63])), b.sequence([])])]))
      .indexOf("AFI 99: (none)") !== -1);

  check("77. the RFC 8360 V2 identifiers read through the same decoders",
    pki.schema.x509.decodeExtensions(mkCert([ext(O("ipAddrBlocksV2"), true, b.sequence([v4]))]))[0].decoded.families.length === 1 &&
    pki.schema.x509.decodeExtensions(mkCert([ext(O("autonomousSysIdsV2"), true, asn)]))[0].decoded.asnum.asIdsOrRanges.length === 2);
}

async function testTheCrlTableCarriesTheWholeSection5Profile() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var caCert = await pki.x509.sign({
    subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: key });
  var crlDer = await pki.crl.sign({
    thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 9n,
    revoked: [{ serialNumber: 1n, revocationDate: new Date("2026-01-02T00:00:00Z") }],
    extensions: {
      issuingDistributionPoint: { fullName: [{ uniformResourceIdentifier: "http://crl.example/a.crl" }], onlyContainsUserCerts: true },
      deltaCRLIndicator: 4n,
    },
  }, { cert: caCert, key: key });

  var rows = pki.schema.crl.decodeExtensions(crlDer);
  check("78. every extension RFC 5280 sec. 5.2 profiles decodes at the CRL scope",
    rows.filter(function (r) { return r.scope === "crl"; })
      .every(function (r) { return r.state === "decoded"; }));
  check("79. the issuingDistributionPoint reads its point and its scope flags",
    rowFor(rows, "issuingDistributionPoint").decoded.onlyContainsUserCerts === true &&
    rowFor(rows, "issuingDistributionPoint").decoded.indirectCRL === false &&
    rowFor(rows, "issuingDistributionPoint").decoded.distributionPoint.kind === "fullName");
  check("80. the delta indicator reads as the CRLNumber RFC 5280 sec. 5.2.4 defines it to be",
    rowFor(rows, "deltaCRLIndicator").decoded === 4n);

  // The refusal arms of the CRL-scope decoders, driven through the one-row verb, because the CRL
  // signer will not emit any of these shapes.
  function crlRow(name, scope, value) {
    return pki.schema.crl.decodeExtension(
      { oid: O(name), name: name, critical: false, value: value }, { scope: scope });
  }
  check("79b. a malformed issuingDistributionPoint is undecodable, with this format's own code",
    crlRow("issuingDistributionPoint", "crl", b.utf8("not an IDP")).state === "undecodable" &&
    crlRow("issuingDistributionPoint", "crl", b.utf8("not an IDP")).code === "crl/bad-extension-value");
  // The decoders a parse composes throw an untyped Error so the parse can wrap them in its own
  // code. The row carries a code in every arm, so the door wraps one here instead.
  check("79c. a decoder that throws untyped still gives its row this format's extension-value code",
    crlRow("cRLNumber", "crl", b.integer(-1n)).code === "crl/bad-extension-value");
  check("79d. certificateIssuer decodes at entry scope as the GeneralNames the CRL profile leaves raw",
    crlRow("certificateIssuer", "crl-entry",
      b.sequence([b.contextConstructed(4, nameDer("Other Issuer"))])).decoded.names.length === 1);

  // The parse must keep leaving the delta indicator opaque. A decoder there would stop the CRL
  // parsing, and the linter's value-syntax rule exists to report exactly that CRL.
  var parsed = pki.schema.crl.parse(crlDer);
  check("81. the parse still hands the delta indicator back as its bytes",
    Buffer.isBuffer(parsed.crlExtensions.filter(function (e) { return e.name === "deltaCRLIndicator"; })[0].value));
  check("82. ...so the linter can still open a CRL whose delta indicator does not read",
    Array.isArray(pki.lint.crl(crlDer).findings));
}

async function run() {
  testAcceptsTheShapesARealCertificateTakes();
  testTheThreeStatesAreToldApartByAField();
  testTheRawBytesSurviveEveryArm();
  testTheCriticalityProfileIsReportedNeverEnforced();
  testStrictTurnsOnlyTheUndecodableArmIntoAThrow();
  testTheDoorRefusesWhatEveryOtherDoorRefuses();
  await testTheCrlDoorReadsBothScopes();
  await testTheCsrDoorReadsWhatWasAskedFor();
  await testTheAttributeCertificateDoorReadsItsOwnTable();
  await testTheCrmfDoorReadsEveryTemplate();
  await testTheCapsAndTheRefusalsAreTheSameAtEveryDoor();
  await testAProfileRuleSixProducersEnforceStaysARefusal();
  testTheTableGrewFiveDecoders();
  await testTheCrlTableCarriesTheWholeSection5Profile();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
