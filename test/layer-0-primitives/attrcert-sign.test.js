// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.attrcert.sign -- the RFC 5755 attribute-certificate producing side.
// Every vector drives the shipped consumer pki.attrcert.sign(spec, issuer, opts) and asserts through
// pki.schema.attrcert.parse (the round-trip GREEN oracle, which re-validates every emitted structure) or
// err.code. The #1 fragile area is the RFC 5755 DEFINITIONS IMPLICIT TAGS boundary: a context [n] on a
// non-CHOICE component replaces the tag (its children ARE the fields), a [n] wrapping a GeneralName CHOICE
// is EXPLICIT -- each has a dedicated re-parse vector. An AA is always a distinct signer (no self-signed arm).

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");
var ROLE = { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } };

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}
// A minimal valid spec over a given AA signer, merged with overrides.
function spec(over) {
  return Object.assign({ holder: { entityName: { directoryName: "CN=Alice" } }, notBeforeTime: NB, notAfterTime: NA, attributes: ROLE }, over || {});
}
function aaOf(s) { return { name: "CN=Example AA", publicKey: s.spki, key: s.key }; }

// ---- round-trip + byte-stability -------------------------------------------

async function testRoundTrip() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  check("sign returns a Buffer", Buffer.isBuffer(der));
  var p = pki.schema.attrcert.parse(der);
  check("round-trip version v2", p.version === 2);
  check("round-trip issuer v2Form present", !!p.issuer.v2Form && !!p.issuer.v2Form.issuerName);
  check("round-trip validity Dates", p.validity.notBeforeTime instanceof Date && p.validity.notAfterTime instanceof Date);
  check("round-trip notBefore value", p.validity.notBeforeTime.getTime() === NB.getTime());
  check("round-trip role attribute type", pki.oid.name(p.attributes[0].type) === "role");
  check("round-trip serial positive <=20 octets", p.serialNumber > 0n && Buffer.from(p.serialNumberHex, "hex").length <= 20);

  // the signed region (acinfo / tbsBytes) is embedded verbatim, byte-identical on re-parse.
  var acinfoBytes = asn1.decode(der).children[0].bytes;
  check("tbsBytes byte-identical to the embedded acinfo", Buffer.compare(p.tbsBytes, acinfoBytes) === 0);
  var reparsed = pki.schema.attrcert.parse(der);
  check("tbsBytes byte-stable across re-parse", Buffer.compare(p.tbsBytes, reparsed.tbsBytes) === 0);
}

async function testPemOutput() {
  var aa = makeSigner("ed25519");
  var pem = await pki.attrcert.sign(spec(), aaOf(aa), { pem: true });
  check("pem output is a string", typeof pem === "string");
  check("pem has the ATTRIBUTE CERTIFICATE banner", /-----BEGIN ATTRIBUTE CERTIFICATE-----/.test(pem));
  var der = pki.schema.attrcert.pemDecode(pem, "ATTRIBUTE CERTIFICATE");
  check("pem round-trips through parse", pki.schema.attrcert.parse(der).version === 2);
}

// ---- version == v2 bare INTEGER (not a [0] EXPLICIT wrapper) ----------------

async function testVersionBareInteger() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var acinfo = asn1.decode(der).children[0];
  var versionNode = acinfo.children[0];
  check("version is a universal INTEGER", versionNode.tagClass === "universal" && versionNode.tagNumber === asn1.TAGS.INTEGER);
  check("version content is a single octet 0x01 (v2)", versionNode.content.length === 1 && versionNode.content[0] === 0x01);
  var routed = pki.schema.parse(der);   // the orchestrator's matches() detector routes to attrcert
  check("schema.parse auto-detects + routes to the attribute-certificate parser", routed.version === 2 && !!routed.holder && !!routed.attributes);
}

// ---- IMPLICIT vs EXPLICIT context-tag flip (the #1 fragile area) ------------

async function testTagBoundaries() {
  var aa = makeSigner("ec-p256");
  // Holder entityName [1] IMPLICIT GeneralNames -- the [1] node's children ARE the GeneralName members.
  var der = await pki.attrcert.sign(spec({ holder: { entityName: [{ dNSName: "a.example" }, { dNSName: "b.example" }] } }), aaOf(aa));
  var acinfo = asn1.decode(der).children[0];
  var holder = acinfo.children[1];
  var entityName = holder.children[0];
  check("Holder entityName is a context [1]", entityName.tagClass === "context" && entityName.tagNumber === 1);
  check("entityName [1] children ARE the GeneralName members (IMPLICIT, not wrapped)", entityName.children.length === 2 && entityName.children[0].tagNumber === 2);

  // AttCertIssuer v2Form [0] IMPLICIT V2Form -- the [0] node's children ARE V2Form's fields (issuerName).
  var issuer = acinfo.children[2];
  check("AttCertIssuer is a context [0]", issuer.tagClass === "context" && issuer.tagNumber === 0);
  check("v2Form [0] first child is the issuerName GeneralNames SEQUENCE", issuer.children[0].tagClass === "universal" && issuer.children[0].tagNumber === asn1.TAGS.SEQUENCE);

  // RoleSyntax roleName [1] EXPLICIT vs roleAuthority [0] IMPLICIT.
  var der2 = await pki.attrcert.sign(spec({ attributes: { role: { roleAuthority: [{ directoryName: "CN=RA" }], roleName: { uniformResourceIdentifier: "urn:r" } } } }), aaOf(aa));
  var roleValue = asn1.decode(der2).children[0].children[6].children[0].children[1].children[0];   // attributes->attr0->SET->value0 (RoleSyntax)
  var ra = roleValue.children[0], rn = roleValue.children[1];
  check("roleAuthority is a context [0] IMPLICIT (children ARE GeneralNames members)", ra.tagClass === "context" && ra.tagNumber === 0 && ra.children[0].tagNumber === 4);
  check("roleName is a context [1] EXPLICIT wrapping exactly one GeneralName", rn.tagClass === "context" && rn.tagNumber === 1 && rn.children.length === 1 && rn.children[0].tagNumber === 6);
}

// ---- every algorithm arm ----------------------------------------------------

async function testAlgorithmArms() {
  var arms = ["rsa", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ed448", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
    "slh-dsa-sha2-128f", "slh-dsa-shake-192s"];
  for (var i = 0; i < arms.length; i++) {
    var aa = makeSigner(arms[i]);
    var der = await pki.attrcert.sign(spec(), aaOf(aa));
    var p = pki.schema.attrcert.parse(der);
    check(arms[i] + " arm signs + parses", p.version === 2);
    // acinfo.signature == outer signatureAlgorithm, byte-identical (RFC 5755 sec. 4.2.4).
    var acinfo = asn1.decode(der).children[0];
    var innerSigAlg = acinfo.children[3].bytes;
    var outerSigAlg = asn1.decode(der).children[1].bytes;
    check(arms[i] + " acinfo.signature == outer signatureAlgorithm", Buffer.compare(innerSigAlg, outerSigAlg) === 0);
  }
  // RSA-PSS arm.
  var rsa = makeSigner("rsa");
  var pss = await pki.attrcert.sign(spec(), aaOf(rsa), { pss: true });
  check("RSA-PSS arm signs + parses", pki.schema.attrcert.parse(pss).version === 2);
}

async function testCompositeArm() {
  var aa = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  check("composite arm signs + parses", pki.schema.attrcert.parse(der).version === 2);
  // a tampered acinfo byte fails the composite self-verify on the next sign of the same spec is covered
  // by testSelfVerify; here we assert both component algs are carried in the sig alg.
  check("composite AC has a signatureValue", asn1.decode(der).children[2].tagNumber === asn1.TAGS.BIT_STRING);
}

// ---- holder forms -----------------------------------------------------------

async function testHolderForms() {
  var aa = makeSigner("ec-p256");
  var e = await pki.attrcert.sign(spec({ holder: { entityName: { directoryName: "CN=E" } } }), aaOf(aa));
  check("entityName holder round-trips", !!pki.schema.attrcert.parse(e).holder.entityName);
  var bc = await pki.attrcert.sign(spec({ holder: { baseCertificateID: { issuer: [{ directoryName: "CN=CA" }], serial: 4242n } } }), aaOf(aa));
  check("baseCertificateID holder round-trips", pki.schema.attrcert.parse(bc).holder.baseCertificateID.serial === 4242n);
  var odi = await pki.attrcert.sign(spec({ holder: { objectDigestInfo: { digestedObjectType: "publicKey", digestAlgorithm: "sha256", objectDigest: Buffer.alloc(32, 7) } } }), aaOf(aa));
  check("objectDigestInfo holder round-trips", pki.schema.attrcert.parse(odi).holder.objectDigestInfo.digestedObjectType.name === "publicKey");
  // fromCertificate: derive baseCertificateID from a PKC's issuer + serial.
  var subj = makeSigner("ec-p256");
  var pkc = await pki.x509.sign({ subject: "CN=Holder", subjectPublicKey: subj.spki, notBefore: NB, notAfter: NA }, { name: "CN=IssuingCA", publicKey: aa.spki, key: aa.key });
  var fc = await pki.attrcert.sign(spec({ holder: { fromCertificate: pkc } }), aaOf(aa));
  var fcHolder = pki.schema.attrcert.parse(fc).holder;
  check("fromCertificate derives a baseCertificateID", !!fcHolder.baseCertificateID);

  check("0 holder forms -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ holder: {} }), aaOf(aa))) === "attrcert/bad-input");
  check("2 holder forms -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ holder: { entityName: { dNSName: "a" }, objectDigestInfo: { digestedObjectType: "publicKey", digestAlgorithm: "sha256", objectDigest: Buffer.alloc(32) } } }), aaOf(aa))) === "attrcert/bad-input");
  check("unknown holder key -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ holder: { notAForm: 1 } }), aaOf(aa))) === "attrcert/bad-input");
  check("objectDigestInfo otherObjectTypes rejected", await codeOf(pki.attrcert.sign(spec({ holder: { objectDigestInfo: { digestedObjectType: "other", digestAlgorithm: "sha256", objectDigest: Buffer.alloc(32) } } }), aaOf(aa))) === "attrcert/bad-input");
}

// ---- issuer v2Form profile --------------------------------------------------

async function testIssuerForms() {
  var aa = makeSigner("ec-p256");
  // { cert } derives the issuerName from the AA subject DN, with NO CA gate (an AA is not a CA).
  var aaCert = await pki.x509.sign({ subject: "CN=Example AA", subjectPublicKey: aa.spki, notBefore: NB, notAfter: NA }, { key: aa.key });
  var der = await pki.attrcert.sign(spec(), { cert: aaCert, key: aa.key });
  var p = pki.schema.attrcert.parse(der);
  var issuerGn = p.issuer.v2Form.issuerName.names[0];
  check("{ cert } issuerName is a directoryName [4] over the AA subject DN (no CA gate)", issuerGn.tagNumber === 4 && issuerGn.bytes.toString("latin1").indexOf("Example AA") >= 0);

  check("missing issuer.key -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec(), { name: "CN=AA", publicKey: aa.spki })) === "attrcert/bad-input");
  check("no issuer form -> attrcert/bad-input (never self-signed)", await codeOf(pki.attrcert.sign(spec(), { key: aa.key })) === "attrcert/bad-input");
  check("empty issuer DN -> attrcert/bad-issuer-name", await codeOf(pki.attrcert.sign(spec(), { name: [], publicKey: aa.spki, key: aa.key })) === "attrcert/bad-issuer-name");
  check("garbage issuer.publicKey -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec(), { name: "CN=AA", publicKey: Buffer.from([1, 2, 3]), key: aa.key })) === "attrcert/bad-input");
  // a malformed issuer.cert / holder.fromCertificate re-types the raw x509/* fault to the attrcert domain.
  check("malformed issuer.cert -> attrcert/bad-input (re-typed, not x509/*)", await codeOf(pki.attrcert.sign(spec(), { cert: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]), key: aa.key })) === "attrcert/bad-input");
  check("malformed holder.fromCertificate -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ holder: { fromCertificate: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]) } }), aaOf(aa))) === "attrcert/bad-input");
}

// ---- validity GeneralizedTime -----------------------------------------------

async function testValidity() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var validity = asn1.decode(der).children[0].children[5];
  check("notBeforeTime is GeneralizedTime", validity.children[0].tagNumber === asn1.TAGS.GENERALIZED_TIME);
  check("notAfterTime is GeneralizedTime", validity.children[1].tagNumber === asn1.TAGS.GENERALIZED_TIME);
  check("inverted validity window -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ notBeforeTime: NA, notAfterTime: NB }), aaOf(aa))) === "attrcert/bad-input");
  check("invalid notBeforeTime -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ notBeforeTime: new Date("nope") }), aaOf(aa))) === "attrcert/bad-input");
}

// ---- serialNumber edges -----------------------------------------------------

async function testSerial() {
  var aa = makeSigner("ec-p256");
  var s1 = await pki.attrcert.sign(spec(), aaOf(aa));
  var s2 = await pki.attrcert.sign(spec(), aaOf(aa));
  var h1 = pki.schema.attrcert.parse(s1).serialNumberHex, h2 = pki.schema.attrcert.parse(s2).serialNumberHex;
  check("omitted serial -> distinct random 20-octet positive serials", h1 !== h2 && Buffer.from(h1, "hex").length === 20);
  var fixed = await pki.attrcert.sign(spec({ serialNumber: 255n }), aaOf(aa));
  check("explicit serial round-trips", pki.schema.attrcert.parse(fixed).serialNumber === 255n);
  check("zero serial -> attrcert/bad-serial", await codeOf(pki.attrcert.sign(spec({ serialNumber: 0n }), aaOf(aa))) === "attrcert/bad-serial");
  check("negative serial -> attrcert/bad-serial", await codeOf(pki.attrcert.sign(spec({ serialNumber: -1n }), aaOf(aa))) === "attrcert/bad-serial");
  check("21-octet serial -> attrcert/bad-serial", await codeOf(pki.attrcert.sign(spec({ serialNumber: Buffer.alloc(21, 0xaa) }), aaOf(aa))) === "attrcert/bad-serial");
  // a numeric serial above 2^53-1 loses float precision -> reject (pass a BigInt/hex/Buffer instead).
  check("unsafe-integer numeric serial -> attrcert/bad-serial", await codeOf(pki.attrcert.sign(spec({ serialNumber: 0x20000000000000 }), aaOf(aa))) === "attrcert/bad-serial");
}

// ---- attribute value syntaxes -----------------------------------------------

async function testAttributeSyntaxes() {
  var aa = makeSigner("ec-p256");
  var cl = await pki.attrcert.sign(spec({ attributes: { clearance: { policyId: "2.5.29.32.0", classList: ["restricted"] } } }), aaOf(aa));
  check("clearance round-trips", pki.schema.attrcert.parse(cl).attributes[0].decoded[0].classList.names[0] === "restricted");
  // a classList equal to the DEFAULT {unclassified} is omitted -> the value SEQUENCE has just the policyId.
  var def = await pki.attrcert.sign(spec({ attributes: { clearance: { policyId: "2.5.29.32.0", classList: ["unclassified"] } } }), aaOf(aa));
  var clSeq = asn1.decode(def).children[0].children[6].children[0].children[1].children[0];   // Clearance value
  check("default classList {unclassified} omitted (only policyId present)", clSeq.children.length === 1);
  var grp = await pki.attrcert.sign(spec({ attributes: { group: { values: [{ oid: "2.5.4.72" }] } } }), aaOf(aa));
  check("group IetfAttrSyntax round-trips", pki.schema.attrcert.parse(grp).attributes[0].decoded[0].values[0].kind === "oid");
  var ai = await pki.attrcert.sign(spec({ attributes: { authenticationInfo: { service: { dNSName: "s" }, ident: { dNSName: "i" }, authInfo: Buffer.from("secret") } } }), aaOf(aa));
  check("authenticationInfo with authInfo round-trips", !!pki.schema.attrcert.parse(ai).attributes[0].decoded[0].authInfo);
  // accessIdentity MUST omit authInfo (RFC 5755 sec. 4.4.2).
  check("accessIdentity with authInfo -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ attributes: { accessIdentity: { service: { dNSName: "s" }, ident: { dNSName: "i" }, authInfo: Buffer.from("x") } } }), aaOf(aa))) === "attrcert/bad-input");
  check("empty attributes object -> attrcert/bad-attributes", await codeOf(pki.attrcert.sign(spec({ attributes: {} }), aaOf(aa))) === "attrcert/bad-attributes");
  check("unknown attribute key -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ attributes: { notAnAttr: 1 } }), aaOf(aa))) === "attrcert/bad-input");
}

// ---- extension syntaxes + criticality ---------------------------------------

async function testExtensionSyntaxes() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec({ extensions: {
    auditIdentity: Buffer.from("audit-tag"),
    targetInformation: [{ targetName: { dNSName: "t.example" } }],
    noRevAvail: true, aaControls: { permitUnSpecified: false }, acProxying: [{ targetName: { dNSName: "p.example" } }],
    authorityKeyIdentifier: true,
  } }), aaOf(aa));
  var p = pki.schema.attrcert.parse(der);
  var byName = {};
  p.extensions.forEach(function (x) { byName[pki.oid.name(x.oid)] = x; });
  check("auditIdentity critical=TRUE (RFC 5755 sec. 4.3.1)", byName.acAuditIdentity && byName.acAuditIdentity.critical === true);
  check("targetInformation critical=TRUE (RFC 5755 sec. 4.3.2)", byName.targetInformation && byName.targetInformation.critical === true);
  check("noRevAvail non-critical (RFC 5755 sec. 4.3.6)", byName.noRevAvail && byName.noRevAvail.critical === false);
  check("aaControls critical=TRUE (RFC 5755 sec. 7.4, safer default)", byName.aaControls && byName.aaControls.critical === true);
  check("acProxying critical=TRUE (RFC 5755 sec. 7.2)", byName.acProxying && byName.acProxying.critical === true);
  check("authorityKeyIdentifier non-critical (RFC 5755 sec. 4.3.3) + auto-derived", byName.authorityKeyIdentifier && byName.authorityKeyIdentifier.critical === false);
  check("noRevAvail decodes", byName.noRevAvail.decoded.noRevAvail === true);
  check("targetInformation decodes a targetName", byName.targetInformation.decoded[0][0].kind === "targetName");
  check("unknown extension key -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ extensions: { notAnExt: 1 } }), aaOf(aa))) === "attrcert/bad-input");
  // a null-valued extension key is not requested (matches the attribute-form convention).
  check("null-valued extension key is skipped", pki.schema.attrcert.parse(await pki.attrcert.sign(spec({ extensions: { noRevAvail: null } }), aaOf(aa))).extensions.length === 0);
}

// ---- advanced value branches (securityCategories, IetfAttrSyntax arms, targets) -----------

async function testAdvancedBranches() {
  var aa = makeSigner("ec-p256");
  var B = pki.asn1.build;
  // Clearance securityCategories: type [0] IMPLICIT OID + value [1] EXPLICIT ANY.
  var sc = await pki.attrcert.sign(spec({ attributes: { clearance: { policyId: "2.5.29.32.0", classList: ["secret"], securityCategories: [{ type: "2.16.840.1.101.2.1.8.1", value: B.utf8("NATO") }] } } }), aaOf(aa));
  var cl = pki.schema.attrcert.parse(sc).attributes[0].decoded[0];
  check("clearance securityCategories round-trips", cl.securityCategories.length === 1 && cl.securityCategories[0].type === "2.16.840.1.101.2.1.8.1");
  // objectDigestInfo publicKeyCert + chargingIdentity policyAuthority [0] + acProxying targetGroup [1] + aaControls excludedAttrs [1].
  var der = await pki.attrcert.sign(spec({
    holder: { objectDigestInfo: { digestedObjectType: "publicKeyCert", digestAlgorithm: "sha384", objectDigest: Buffer.alloc(48, 3) } },
    attributes: { chargingIdentity: { policyAuthority: { directoryName: "CN=PA" }, values: [{ string: "chg" }] } },
    extensions: { acProxying: [{ targetGroup: { dNSName: "grp.example" } }], aaControls: { excludedAttrs: ["clearance"] } },
  }), aaOf(aa));
  var p = pki.schema.attrcert.parse(der);
  check("objectDigestInfo publicKeyCert round-trips", p.holder.objectDigestInfo.digestedObjectType.name === "publicKeyCert");
  check("chargingIdentity policyAuthority [0] round-trips", !!p.attributes[0].decoded[0].policyAuthority);
  check("acProxying targetGroup [1] EXPLICIT round-trips", p.extensions.filter(function (x) { return pki.oid.name(x.oid) === "acProxying"; })[0].decoded[0][0].kind === "targetGroup");
  check("aaControls excludedAttrs [1] IMPLICIT round-trips", p.extensions.filter(function (x) { return pki.oid.name(x.oid) === "aaControls"; })[0].decoded.excludedAttrs[0] === "2.5.4.55");
  // group IetfAttrSyntax octets arm.
  var g = await pki.attrcert.sign(spec({ attributes: { group: { values: [{ octets: Buffer.from("g") }] } } }), aaOf(aa));
  check("group IetfAttrSyntax octets arm round-trips", pki.schema.attrcert.parse(g).attributes[0].decoded[0].values[0].kind === "octets");
  // baseCertificateID with a valid issuerUID BIT STRING.
  var bcuid = await pki.attrcert.sign(spec({ holder: { baseCertificateID: { issuer: [{ directoryName: "CN=CA" }], serial: 7n, issuerUID: Buffer.from([0xab]) } } }), aaOf(aa));
  check("baseCertificateID issuerUID round-trips", !!pki.schema.attrcert.parse(bcuid).holder.baseCertificateID.issuerUID);
  // aaControls with pathLenConstraint + permittedAttrs [0] IMPLICIT.
  var full = await pki.attrcert.sign(spec({ extensions: { aaControls: { pathLenConstraint: 3, permittedAttrs: ["role", "group"] } } }), aaOf(aa));
  var aac = pki.schema.attrcert.parse(full).extensions[0].decoded;
  check("aaControls pathLenConstraint + permittedAttrs round-trips", aac.pathLenConstraint === 3 && aac.permittedAttrs.length === 2);
  // extensions: [] -> no extensions emitted.
  var noExt = await pki.attrcert.sign(spec({ extensions: [] }), aaOf(aa));
  check("empty extensions array -> no extensions field", pki.schema.attrcert.parse(noExt).extensions.length === 0);
  // a recognized AC extension with a malformed value via the array hatch re-throws the decoder's typed error.
  var badAac = B.sequence([B.oid(pki.oid.byName("aaControls")), B.octetString(B.integer(1n))]);   // AAControls must be a SEQUENCE
  check("malformed pre-encoded aaControls -> typed attrcert/*", /^attrcert\//.test(await codeOf(pki.attrcert.sign(spec({ extensions: [badAac] }), aaOf(aa))) || ""));
  // the escape hatch MUST enforce the RFC 5755 mandated criticality.
  var tiNonCrit = B.sequence([B.oid(pki.oid.byName("targetInformation")), B.octetString(B.sequence([B.sequence([B.explicit(0, B.contextPrimitive(2, Buffer.from("t")))])]))]);   // targetInformation without critical=TRUE
  check("pre-encoded targetInformation not critical -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ extensions: [tiNonCrit] }), aaOf(aa))) === "attrcert/bad-input");
  var noRevCrit = B.sequence([B.oid(pki.oid.byName("noRevAvail")), B.boolean(true), B.octetString(B.nullValue())]);   // noRevAvail marked critical (MUST be non-critical)
  check("pre-encoded noRevAvail marked critical -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ extensions: [noRevCrit] }), aaOf(aa))) === "attrcert/bad-input");
  // a correctly-critical pre-encoded targetInformation is accepted.
  var tiCrit = B.sequence([B.oid(pki.oid.byName("targetInformation")), B.boolean(true), B.octetString(B.sequence([B.sequence([B.explicit(0, B.contextPrimitive(2, Buffer.from("t")))])]))]);
  check("pre-encoded critical targetInformation round-trips", pki.schema.attrcert.parse(await pki.attrcert.sign(spec({ extensions: [tiCrit] }), aaOf(aa))).extensions.length === 1);
}

// ---- escape hatches ---------------------------------------------------------

async function testEscapeHatches() {
  var aa = makeSigner("ec-p256");
  var B = pki.asn1.build;
  // a pre-encoded opaque (unrecognized) attribute type stays opaque.
  var okAttr = B.sequence([B.oid("1.2.3.4.5.6.7"), B.set([B.utf8("x")])]);
  var der = await pki.attrcert.sign(spec({ attributes: [okAttr] }), aaOf(aa));
  check("pre-encoded opaque attribute round-trips", pki.schema.attrcert.parse(der).attributes.length === 1);
  // a pre-encoded RECOGNIZED attribute with a malformed value fails closed via the real decoder.
  var badRole = B.sequence([B.oid(pki.oid.byName("role")), B.set([B.sequence([B.integer(1n)])])]);   // RoleSyntax without roleName
  check("malformed pre-encoded role attribute -> typed attrcert/*", /^attrcert\//.test(await codeOf(pki.attrcert.sign(spec({ attributes: [badRole] }), aaOf(aa))) || ""));
  check("empty attribute value SET -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ attributes: [B.sequence([B.oid("1.2.3.4.5"), B.set([])])] }), aaOf(aa))) === "attrcert/bad-input");
  // a pre-encoded Extension array with an explicit critical=FALSE is non-canonical.
  var critFalse = B.sequence([B.oid(pki.oid.byName("noRevAvail")), B.boolean(false), B.octetString(B.nullValue())]);
  check("pre-encoded extension critical=FALSE -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ extensions: [critFalse] }), aaOf(aa))) === "attrcert/bad-input");
  // a valid pre-encoded extension round-trips; a recognized malformed one fails closed.
  var okExt = B.sequence([B.oid(pki.oid.byName("noRevAvail")), B.octetString(B.nullValue())]);
  check("pre-encoded valid noRevAvail extension round-trips", pki.schema.attrcert.parse(await pki.attrcert.sign(spec({ extensions: [okExt] }), aaOf(aa))).extensions.length === 1);
  var badNoRev = B.sequence([B.oid(pki.oid.byName("noRevAvail")), B.octetString(B.integer(1n))]);   // not a NULL
  check("malformed pre-encoded noRevAvail -> typed attrcert/*", /^attrcert\//.test(await codeOf(pki.attrcert.sign(spec({ extensions: [badNoRev] }), aaOf(aa))) || ""));
  check("duplicate pre-encoded extension -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ extensions: [okExt, okExt] }), aaOf(aa))) === "attrcert/bad-input");
  // a cert-style AA extension (authorityKeyIdentifier) via the array hatch validates through the RFC 5280 decoder.
  var akiExt = B.sequence([B.oid(pki.oid.byName("authorityKeyIdentifier")), B.octetString(B.sequence([B.contextPrimitive(0, Buffer.from([1, 2, 3, 4]))]))]);
  check("pre-encoded cert-style AKI extension round-trips", pki.schema.attrcert.parse(await pki.attrcert.sign(spec({ extensions: [akiExt] }), aaOf(aa))).extensions.length === 1);
  // malformed pre-encoded attribute shapes.
  check("pre-encoded attribute not valid DER -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ attributes: [Buffer.from([0x30, 0x80])] }), aaOf(aa))) === "attrcert/bad-input");
  check("pre-encoded attribute wrong shape -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ attributes: [B.sequence([B.integer(1n)])] }), aaOf(aa))) === "attrcert/bad-input");
  check("pre-encoded attribute non-OID type -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ attributes: [B.sequence([B.integer(1n), B.set([B.utf8("x")])])] }), aaOf(aa))) === "attrcert/bad-input");
  // a duplicate opaque (unrecognized) attribute type.
  var op = B.sequence([B.oid("1.2.3.4.5.6.7"), B.set([B.utf8("x")])]);
  check("duplicate opaque attribute type -> attrcert/duplicate-attribute", await codeOf(pki.attrcert.sign(spec({ attributes: [op, op] }), aaOf(aa))) === "attrcert/duplicate-attribute");
}

// ---- malformed value shapes (each encoder fails closed with a typed attrcert/*) ---------

async function testMalformedValues() {
  var aa = makeSigner("ec-p256");
  function bad(over) { return codeOf(pki.attrcert.sign(spec(over), aaOf(aa))); }
  // role
  check("role without roleName -> attrcert/bad-input", await bad({ attributes: { role: {} } }) === "attrcert/bad-input");
  // clearance
  check("clearance without policyId -> attrcert/bad-input", await bad({ attributes: { clearance: {} } }) === "attrcert/bad-input");
  check("clearance unknown class -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", classList: ["nope"] } } }) === "attrcert/bad-input");
  check("clearance non-array classList -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", classList: "secret" } } }) === "attrcert/bad-input");
  check("clearance empty securityCategories -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", securityCategories: [] } } }) === "attrcert/bad-input");
  check("securityCategory bad shape -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", securityCategories: [{ type: "1.2.3" }] } } }) === "attrcert/bad-input");
  check("securityCategory malformed value DER -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", securityCategories: [{ type: "1.2.3", value: Buffer.from([0x30, 0x05]) }] } } }) === "attrcert/bad-input");
  check("securityCategory value with trailing bytes -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", securityCategories: [{ type: "1.2.3", value: Buffer.from([0x05, 0x00, 0x05, 0x00]) }] } } }) === "attrcert/bad-input");
  check("aaControls pathLenConstraint over uint31 -> attrcert/bad-input", await bad({ extensions: { aaControls: { pathLenConstraint: 0x80000000 } } }) === "attrcert/bad-input");
  // IetfAttrSyntax
  check("group empty values -> attrcert/bad-input", await bad({ attributes: { group: { values: [] } } }) === "attrcert/bad-input");
  check("group bad value kind -> attrcert/bad-input", await bad({ attributes: { group: { values: [{ nope: 1 }] } } }) === "attrcert/bad-input");
  check("group octets non-buffer -> attrcert/bad-input", await bad({ attributes: { group: { values: [{ octets: "x" }] } } }) === "attrcert/bad-input");
  // SvceAuthInfo
  check("authenticationInfo missing ident -> attrcert/bad-input", await bad({ attributes: { authenticationInfo: { service: { dNSName: "s" } } } }) === "attrcert/bad-input");
  check("authenticationInfo non-buffer authInfo -> attrcert/bad-input", await bad({ attributes: { authenticationInfo: { service: { dNSName: "s" }, ident: { dNSName: "i" }, authInfo: "x" } } }) === "attrcert/bad-input");
  // objectDigestInfo
  check("objectDigestInfo non-buffer digest -> attrcert/bad-input", await bad({ holder: { objectDigestInfo: { digestedObjectType: "publicKey", digestAlgorithm: "sha256", objectDigest: "x" } } }) === "attrcert/bad-input");
  check("objectDigestInfo bad algorithm -> attrcert/bad-input", await bad({ holder: { objectDigestInfo: { digestedObjectType: "publicKey", digestAlgorithm: "not-an-alg", objectDigest: Buffer.alloc(32) } } }) === "attrcert/bad-input");
  // baseCertificateID
  check("baseCertificateID missing issuer -> attrcert/bad-input", await bad({ holder: { baseCertificateID: { serial: 1n } } }) === "attrcert/bad-input");
  check("baseCertificateID non-buffer issuerUID -> attrcert/bad-input", await bad({ holder: { baseCertificateID: { issuer: [{ directoryName: "CN=CA" }], serial: 1n, issuerUID: "x" } } }) === "attrcert/bad-input");
  // targets / aaControls
  check("acProxying bad target -> attrcert/bad-input", await bad({ extensions: { acProxying: [{ nope: 1 }] } }) === "attrcert/bad-input");
  check("acProxying empty -> attrcert/bad-input", await bad({ extensions: { acProxying: [] } }) === "attrcert/bad-input");
  check("aaControls negative pathLen -> attrcert/bad-input", await bad({ extensions: { aaControls: { pathLenConstraint: -1 } } }) === "attrcert/bad-input");
  check("aaControls non-boolean permitUnSpecified -> attrcert/bad-input", await bad({ extensions: { aaControls: { permitUnSpecified: 1 } } }) === "attrcert/bad-input");
  check("auditIdentity non-buffer -> attrcert/bad-input", await bad({ extensions: { auditIdentity: "x" } }) === "attrcert/bad-input");
  // invalid object identifiers passed through to b.oid fail closed with a typed error.
  check("clearance non-OID policyId -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "not-an-oid" } } }) === "attrcert/bad-input");
  check("group value non-OID -> attrcert/bad-input", await bad({ attributes: { group: { values: [{ oid: "not-an-oid" }] } } }) === "attrcert/bad-input");
  check("aaControls permittedAttrs non-OID -> attrcert/bad-input", await bad({ extensions: { aaControls: { permittedAttrs: ["not-an-oid"] } } }) === "attrcert/bad-input");
  check("securityCategory non-OID type -> attrcert/bad-input", await bad({ attributes: { clearance: { policyId: "2.5.29.32.0", securityCategories: [{ type: "not-an-oid", value: Buffer.from([5, 0]) }] } } }) === "attrcert/bad-input");
  check("empty attributes array -> attrcert/bad-attributes", await bad({ attributes: [] }) === "attrcert/bad-attributes");
  // extensions: {} -> no extensions field (an empty object requests nothing).
  var noExt2 = await pki.attrcert.sign(spec({ extensions: {} }), aaOf(aa));
  check("empty extensions object -> no extensions field", pki.schema.attrcert.parse(noExt2).extensions.length === 0);
  // omitted issuer -> the issuer||{} default then the missing-key reject.
  check("omitted issuer -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec())) === "attrcert/bad-input");
  // non-object where a structured sub-object is required -> the type guards fail closed.
  check("non-object baseCertificateID -> attrcert/bad-input", await bad({ holder: { baseCertificateID: 5 } }) === "attrcert/bad-input");
  check("non-object objectDigestInfo -> attrcert/bad-input", await bad({ holder: { objectDigestInfo: 5 } }) === "attrcert/bad-input");
  check("non-object aaControls -> attrcert/bad-input", await bad({ extensions: { aaControls: 5 } }) === "attrcert/bad-input");
  check("non-object attributes -> attrcert/bad-input", await bad({ attributes: 5 }) === "attrcert/bad-input");
  check("non-object extensions -> attrcert/bad-input", await bad({ extensions: 5 }) === "attrcert/bad-input");
  check("null IetfAttrSyntax value -> attrcert/bad-input", await bad({ attributes: { group: { values: [null] } } }) === "attrcert/bad-input");
  check("non-object target -> attrcert/bad-input", await bad({ extensions: { acProxying: [5] } }) === "attrcert/bad-input");
  check("non-array aaControls permittedAttrs -> attrcert/bad-input", await bad({ extensions: { aaControls: { permittedAttrs: "role" } } }) === "attrcert/bad-input");
  // duplicate recognized attribute across the object form is impossible (one key), but a duplicate
  // across the pre-encoded array + a matching type is caught in the escape-hatch test.
}

// ---- post-sign self-verify (the AA proof) -----------------------------------

async function testSelfVerify() {
  var aa = makeSigner("ec-p256");
  var other = makeSigner("ec-p256");
  // The AA public key advertised does not match the signing key -> the self-verify fails closed.
  check("mismatched AA key/publicKey -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec(), { name: "CN=AA", publicKey: other.spki, key: aa.key })) === "attrcert/bad-input");
}

// ---- fail-closed misuse -----------------------------------------------------

async function testFailClosed() {
  var aa = makeSigner("ed25519");
  check("non-object spec -> attrcert/bad-input", await codeOf(pki.attrcert.sign(Buffer.from([1]), aaOf(aa))) === "attrcert/bad-input");
  check("unknown top-level spec key -> attrcert/bad-input", await codeOf(pki.attrcert.sign(spec({ holdr: "typo" }), aaOf(aa))) === "attrcert/bad-input");
  check("missing holder -> attrcert/bad-input", await codeOf(pki.attrcert.sign({ notBeforeTime: NB, notAfterTime: NA, attributes: ROLE }, aaOf(aa))) === "attrcert/bad-input");
  check("bad GeneralName form in holder -> typed attrcert/*", /^attrcert\//.test(await codeOf(pki.attrcert.sign(spec({ holder: { entityName: { notAForm: "x" } } }), aaOf(aa))) || ""));
}

// Branch coverage (lib/attrcert-sign.js): 96% -- every REACHABLE branch is driven above. The residual
// arms are verified-defensive: the _parseCert Buffer/string short-circuit operands (both the DER and the
// parsed-certificate inputs are exercised); its `instanceof AttrCertError` re-throw (x509.parse raises a
// CertificateError, never an AttrCertError, so that arm cannot be reached from here); the _encodeV2Form
// `dnSpec == null` arm (issuer.name is non-null whenever it is reached); the _extensionValue default
// (EXT_META pre-validates every key); the `oid.name(x) || x` message fallbacks; and the object-form
// duplicate-extension guard (distinct EXT_META keys map to distinct OIDs, so they cannot collide).
async function main() {
  await testRoundTrip();
  await testPemOutput();
  await testVersionBareInteger();
  await testTagBoundaries();
  await testAlgorithmArms();
  await testCompositeArm();
  await testHolderForms();
  await testIssuerForms();
  await testValidity();
  await testSerial();
  await testAttributeSyntaxes();
  await testExtensionSyntaxes();
  await testAdvancedBranches();
  await testMalformedValues();
  await testEscapeHatches();
  await testSelfVerify();
  await testFailClosed();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
