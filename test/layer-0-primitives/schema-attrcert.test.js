// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.attrcert (X.509 Attribute Certificate parser, RFC 5755).
 * Spec-first conformance vectors: a valid v2 AttributeCertificate parses to the
 * documented shape; every malformed AttributeCertificateInfo is rejected
 * fail-closed with a typed attrcert/* (or leaf-level asn1/*) error; a legacy
 * AttributeCertificateV1 is recognized and deferred. The parser reuses the
 * shared signed-envelope, the GeneralName(s) validator, and the schema engine,
 * so it inherits the codec's fail-closed verdicts (trailing bytes, indefinite
 * length, non-minimal encodings) and the GeneralName grammar checks.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
// The matches / matchesV1 detectors are internal dispatch infrastructure (not on
// the curated pki.schema.attrcert surface), so reach them via the module directly.
var attrcertMod = require("../../lib/schema-attrcert");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.attrcert.parse(der); }); }
function parse(der) { return pki.schema.attrcert.parse(der); }

// ---- OIDs used in fixtures -------------------------------------------
var SIGALG = "1.2.840.10045.4.3.2";     // ecdsa-with-SHA256
var SIGALG2 = "1.2.840.113549.1.1.11";  // sha256WithRSAEncryption (for the mismatch vector)
var DIGALG = "2.16.840.1.101.3.4.2.1";  // sha256
var ROLE = "2.5.4.72";                  // id-at-role
var CLEARANCE = "2.5.4.55";             // id-at-clearance
var GROUP = "1.3.6.1.5.5.7.10.4";       // id-aca-group

// ---- GeneralName fixture builders ------------------------------------
function rdn(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function gnDirName(cn) { return b.explicit(4, rdn(cn)); }             // directoryName [4] EXPLICIT Name
function gnDns(s) { return b.contextPrimitive(2, Buffer.from(s, "latin1")); } // dNSName [2] IMPLICIT IA5String
function gnUri(s) { return b.contextPrimitive(6, Buffer.from(s, "latin1")); } // URI [6]
function gnIp(bytes) { return b.contextPrimitive(7, Buffer.from(bytes)); }    // iPAddress [7]
function gnRegId(oidStr) { return Buffer.concat([Buffer.from([0x88]), lenAndOid(oidStr)]); } // registeredID [8] IMPLICIT OID
function lenAndOid(oidStr) { var o = b.oid(oidStr); var content = o.slice(2); var l = Buffer.from([content.length]); return Buffer.concat([l, content]); }

// GeneralNames ::= SEQUENCE OF GeneralName (bare universal SEQUENCE).
function generalNames(gns) { return b.sequence(gns); }

// ---- structural fixture builders -------------------------------------
function algId(oidStr) { return b.sequence([b.oid(oidStr)]); }
function gt(iso) { return b.generalizedTime(new Date(iso)); }

// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial INTEGER, issuerUID? }.
// Content (children) only — wrapped by the caller with the right tag.
function issuerSerialContent(o) {
  var c = [generalNames(o.issuer || [gnDirName("Issuer")]), b.integer(o.serial === undefined ? 3 : o.serial)];
  if (o.uid) c.push(b.bitString(o.uid, 0));
  return c;
}
// ObjectDigestInfo content (children only).
function odiContent(o) {
  var c = [b.enumerated(o.type === undefined ? 0 : o.type)];
  if (o.otid) c.push(b.oid(o.otid));
  c.push(algId(o.alg || DIGALG));
  c.push(b.bitString(o.digest || Buffer.from([0xab, 0xcd]), o.digestUnused || 0));
  return c;
}

// Holder ::= SEQUENCE { baseCertificateID [0] IMPLICIT IssuerSerial OPTIONAL,
//   entityName [1] IMPLICIT GeneralNames OPTIONAL, objectDigestInfo [2] IMPLICIT
//   ObjectDigestInfo OPTIONAL } — all IMPLICIT, so each [n] tag replaces the
//   inner universal tag.
function holder(o) {
  o = o || {};
  var k = [];
  if (o.baseCertificateID) k.push(b.contextConstructed(0, Buffer.concat(issuerSerialContent(o.baseCertificateID))));
  if (o.baseCertificateIDPrimitive) k.push(b.contextPrimitive(0, Buffer.from([0x01]))); // malformed: [0] primitive
  if (o.entityName) k.push(b.contextConstructed(1, Buffer.concat(o.entityName)));
  if (o.objectDigestInfo) k.push(b.contextConstructed(2, Buffer.concat(odiContent(o.objectDigestInfo))));
  if (o.odiNode) k.push(o.odiNode);
  if (o.stray3) k.push(b.contextConstructed(3, Buffer.from([])));
  if (o.rawKids) k = o.rawKids;
  return b.sequence(k);
}
function holderDefault() { return holder({ entityName: [gnDirName("Alice")] }); }

// V2Form ::= SEQUENCE { issuerName GeneralNames OPTIONAL, baseCertificateID [0]
//   IMPLICIT OPTIONAL, objectDigestInfo [1] IMPLICIT OPTIONAL }.
function v2FormContent(o) {
  var c = [];
  if (o.issuerName) c.push(generalNames(o.issuerName));
  if (o.baseCertificateID) c.push(b.contextConstructed(0, Buffer.concat(issuerSerialContent(o.baseCertificateID))));
  if (o.objectDigestInfo) c.push(b.contextConstructed(1, Buffer.concat(odiContent(o.objectDigestInfo))));
  if (o.stray2) c.push(b.contextConstructed(2, Buffer.from([])));
  return c;
}
// AttCertIssuer ::= CHOICE { v1Form GeneralNames, v2Form [0] V2Form }.
function issuerV2(o) { return b.contextConstructed(0, Buffer.concat(v2FormContent(o || { issuerName: [gnDirName("Issuer CA")] }))); }
function issuerV1(gns) { return generalNames(gns || [gnDirName("Legacy Issuer")]); }
function issuerDefault() { return issuerV2({ issuerName: [gnDirName("Issuer CA")] }); }

function attribute(typeOid, valueNodes) { return b.sequence([b.oid(typeOid), b.set(valueNodes)]); }
function roleAttr() { return attribute(ROLE, [b.utf8("administrator")]); }
function attributesDefault() { return b.sequence([roleAttr()]); }

function ext(oidStr, valueBytes, critical) {
  var children = [b.oid(oidStr)];
  if (critical !== undefined) children.push(b.boolean(critical));
  children.push(b.octetString(valueBytes));
  return b.sequence(children);
}

// acinfo(o): assemble an AttributeCertificateInfo. Any field is overridable by a
// *Node override; o.acinfoChildren replaces the whole child array.
function acinfo(o) {
  o = o || {};
  if (o.acinfoChildren) return b.sequence(o.acinfoChildren);
  var k = [];
  k.push(o.versionNode || b.integer(o.version === undefined ? 1 : o.version));
  k.push(o.holderNode || holderDefault());
  k.push(o.issuerNode || issuerDefault());
  k.push(algId(o.sigOid || SIGALG));
  k.push(o.serialNode || b.integer(o.serial === undefined ? 7 : o.serial));
  k.push(o.validityNode || b.sequence([gt("2026-01-01T00:00:00Z"), gt("2027-01-01T00:00:00Z")]));
  k.push(o.attributesNode || attributesDefault());
  if (o.issuerUniqueID) k.push(b.bitString(o.issuerUniqueID, 0));
  if (o.extensions) k.push(b.sequence(o.extensions));
  else if (o.extensionsRaw) k.push(o.extensionsRaw);
  return b.sequence(k);
}

// attrCert(o): assemble the outer AttributeCertificate SEQUENCE-of-3.
function attrCert(o) {
  o = o || {};
  if (o.outerChildren) return b.sequence(o.outerChildren);
  var ai = o.acinfoNode || acinfo(o);
  return b.sequence([ai, algId(o.outerSigOid || o.sigOid || SIGALG), o.sigValNode || b.bitString(Buffer.from([0x00]), 0)]);
}

// legacy AttributeCertificateV1: acInfo leads with the subject CHOICE ([0]/[1]),
// version DEFAULT v1 omitted, issuer a bare GeneralNames.
function attrCertV1(o) {
  o = o || {};
  var subject = o.subjectBase
    ? b.contextConstructed(0, Buffer.concat(issuerSerialContent(o.subjectBase)))   // baseCertificateID [0]
    : b.contextConstructed(1, Buffer.concat([gnDirName("Legacy Subject")]));        // subjectName [1] GeneralNames
  var acInfo = b.sequence([
    subject,
    issuerV1([gnDirName("Legacy Issuer")]),   // issuer GeneralNames (bare universal SEQUENCE)
    algId(SIGALG),
    b.integer(5),
    b.sequence([gt("2026-01-01T00:00:00Z"), gt("2027-01-01T00:00:00Z")]),
    attributesDefault(),
  ]);
  return b.sequence([acInfo, algId(SIGALG), b.bitString(Buffer.from([0x00]), 0)]);
}

// ---- ACCEPT — v2 -----------------------------------------------------
function testAcceptV2() {
  var der = attrCert({});
  var m = parse(der);
  check("v2: version === 2", m.version === 2);
  check("v2: serialNumber BigInt", m.serialNumber === 7n);
  check("v2: serialNumberHex", m.serialNumberHex === "07");
  check("v2: holder.entityName decoded names", !!m.holder.entityName && Array.isArray(m.holder.entityName.names) && m.holder.entityName.names.length === 1);
  check("v2: holder.entityName name is directoryName [4]", m.holder.entityName.names[0].tagClass === "context" && m.holder.entityName.names[0].tagNumber === 4);
  check("v2: holder.baseCertificateID absent", m.holder.baseCertificateID === null);
  check("v2: holder.objectDigestInfo absent", m.holder.objectDigestInfo === null);
  check("v2: issuer form v2Form", m.issuer.form === "v2Form" && !!m.issuer.v2Form && m.issuer.v1Form === null);
  check("v2: issuer.v2Form.issuerName decoded", !!m.issuer.v2Form.issuerName && m.issuer.v2Form.issuerName.names.length === 1);
  check("v2: validity Dates", m.validity.notBeforeTime instanceof Date && m.validity.notAfterTime instanceof Date);
  check("v2: notBeforeTime value", m.validity.notBeforeTime.toISOString() === "2026-01-01T00:00:00.000Z");
  check("v2: attributes[0].type is id-at-role", m.attributes[0].type === ROLE && m.attributes[0].name === "role");
  check("v2: signature agreement surfaced", !!m.signatureAlgorithm && m.signatureAlgorithm.oid === SIGALG);
  check("v2: extensions default empty", Array.isArray(m.extensions) && m.extensions.length === 0);
  check("v2: signatureValue raw", !!m.signatureValue && Buffer.isBuffer(m.signatureValue.bytes));

  // RAW EXACTNESS: tbsBytes equals the exact acinfo TLV on the wire.
  var ai = acinfo({});
  var der2 = attrCert({ acinfoNode: ai });
  var m2 = parse(der2);
  check("v2: tbsBytes equals the acinfo TLV", m2.tbsBytes.equals(ai));
}

function testHolderVariants() {
  // Holder via baseCertificateID [0].
  var m = parse(attrCert({ holderNode: holder({ baseCertificateID: { issuer: [gnDns("ca.example")], serial: 42 } }) }));
  check("holder baseCertificateID: serial BigInt", m.holder.baseCertificateID.serial === 42n);
  check("holder baseCertificateID: issuer decoded", m.holder.baseCertificateID.issuer.names[0].tagNumber === 2);
  check("holder baseCertificateID: entityName null", m.holder.entityName === null);

  // Holder via objectDigestInfo [2].
  var m2 = parse(attrCert({ holderNode: holder({ objectDigestInfo: { type: 0 } }) }));
  check("holder objectDigestInfo: type publicKey", m2.holder.objectDigestInfo.digestedObjectType.code === 0 && m2.holder.objectDigestInfo.digestedObjectType.name === "publicKey");
  check("holder objectDigestInfo: digestAlgorithm named", m2.holder.objectDigestInfo.digestAlgorithm.oid === DIGALG);
  check("holder objectDigestInfo: objectDigest raw bits", Buffer.isBuffer(m2.holder.objectDigestInfo.objectDigest.bytes));
  // The objectDigest is a whole-octet digest; a non-octet-aligned BIT STRING is
  // malformed (RFC 5755 sec. 4.1) and has no verify layer to catch it later.
  check("holder objectDigestInfo: non-octet-aligned objectDigest rejected",
    parseCode(attrCert({ holderNode: holder({ objectDigestInfo: { type: 0, digest: Buffer.from([0xab, 0xc8]), digestUnused: 3 } }) })) === "attrcert/bad-object-digest-info");
}

function testIssuerProfile() {
  // RFC 5755 §4.2.3 — a conformant AC MUST use v2Form; the v1Form arm is
  // recognized and rejected with a precise verdict.
  check("issuer v1Form rejected (must use v2Form)", parseCode(attrCert({ issuerNode: issuerV1([gnDirName("V1 Issuer")]) })) === "attrcert/bad-issuer");
  // v2Form MUST carry issuerName — an empty V2Form identifies no issuer at all.
  check("empty v2Form rejected (issuerName required)", parseCode(attrCert({ issuerNode: b.contextConstructed(0, Buffer.alloc(0)) })) === "attrcert/bad-issuer-name");
  // issuerName MUST contain one and only one GeneralName ...
  check("two-name issuerName rejected", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [gnDirName("A"), gnDirName("B")] }) })) === "attrcert/bad-issuer-name");
  // ... which MUST be a directoryName ...
  check("non-directoryName issuerName rejected", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [gnDns("ca.example")] }) })) === "attrcert/bad-issuer-name");
  // ... containing a non-empty distinguished name.
  check("empty-DN directoryName issuerName rejected", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [b.explicit(4, b.sequence([]))] }) })) === "attrcert/bad-issuer-name");
  // baseCertificateID / objectDigestInfo MUST NOT be present in v2Form.
  check("v2Form baseCertificateID rejected", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [gnDirName("CA")], baseCertificateID: {} }) })) === "attrcert/bad-v2form");
  check("v2Form objectDigestInfo rejected", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [gnDirName("CA")], objectDigestInfo: { type: 0 } }) })) === "attrcert/bad-v2form");
}

function testOptionalTail() {
  // issuerUniqueID + a non-critical noRevAvail extension (NULL value).
  var m = parse(attrCert({
    issuerUniqueID: Buffer.from([0xde, 0xad]),
    extensions: [ext("2.5.29.56", b.nullValue(), undefined)],   // noRevAvail, critical omitted
  }));
  check("issuerUniqueID raw bits", !!m.issuerUniqueID && m.issuerUniqueID.bytes.equals(Buffer.from([0xde, 0xad])));
  check("extensions: noRevAvail named", m.extensions.length === 1 && m.extensions[0].name === "noRevAvail");
  check("extensions: critical false by default", m.extensions[0].critical === false);
}

function testTwoAttributes() {
  var m = parse(attrCert({ attributesNode: b.sequence([roleAttr(), attribute(GROUP, [b.utf8("eng")]), attribute(CLEARANCE, [b.utf8("secret")])]) }));
  check("three distinct attributes parse", m.attributes.length === 3 && m.attributes[1].name === "group" && m.attributes[2].name === "clearance");

  // clearance resolves by name on BOTH the RFC 5755 (2.5.4.55) and the legacy
  // RFC 3281 (2.5.1.5.55) arcs — RFC 5755 §4.4.6 says accept the legacy form for
  // decoding; the canonical name->OID reverse stays the RFC 5755 arc.
  var mc = parse(attrCert({ attributesNode: b.sequence([attribute("2.5.1.5.55", [b.utf8("topsecret")])]) }));
  check("legacy clearance arc names via the consumer path", mc.attributes[0].name === "clearance");
  check("both clearance arcs resolve to name", pki.oid.name("2.5.4.55") === "clearance" && pki.oid.name("2.5.1.5.55") === "clearance");
  check("clearance canonical reverse is the RFC 5755 arc", pki.oid.byName("clearance") === "2.5.4.55");

  // the id-aca family is registered COMPLETE per RFC 5755 (incl. §7.1 encAttrs; 5 reserved).
  var mg = parse(attrCert({ attributesNode: b.sequence([attribute("1.3.6.1.5.5.7.10.6", [b.octetString(Buffer.from([0x01]))])]) }));
  check("id-aca-encAttrs resolves by name via the consumer path", mg.attributes[0].name === "encAttrs");
  check("id-aca family complete", ["1.3.6.1.5.5.7.10.1", "1.3.6.1.5.5.7.10.2", "1.3.6.1.5.5.7.10.3", "1.3.6.1.5.5.7.10.4", "1.3.6.1.5.5.7.10.6"].every(function (o) { return typeof pki.oid.name(o) === "string"; }));
}

// ---- REJECT — version / envelope / DER -------------------------------
function testRejectVersionEnvelope() {
  check("version 0 (v1 value in v2 shape)", parseCode(attrCert({ version: 0 })) === "attrcert/bad-version");
  check("version 2 (undefined)", parseCode(attrCert({ version: 2 })) === "attrcert/bad-version");
  // A [0] EXPLICIT version makes the acinfo context-first — structurally a v1 AC (not
  // a bare-INTEGER v2), so it is rejected fail-closed (as the legacy diagnostic via the
  // v1 detector, or a leaf/bad-version if it reaches the v2 walk); never parsed as v2.
  var certShaped = parseCode(attrCert({ versionNode: b.explicit(0, b.integer(1)) }));
  check("version [0] EXPLICIT wrapper (cert-shaped) rejected fail-closed", certShaped === "attrcert/legacy-v1-not-supported" || certShaped.indexOf("asn1/") === 0 || certShaped === "attrcert/bad-version");
  check("signature-algorithm disagreement", parseCode(attrCert({ sigOid: SIGALG, outerSigOid: SIGALG2 })) === "attrcert/bad-signature-algorithm");

  var good = attrCert({});
  check("trailing garbage after outer SEQUENCE", parseCode(Buffer.concat([good, Buffer.from([0x00])])) === "attrcert/bad-der");
  // indefinite-length outer
  check("indefinite-length outer", parseCode(Buffer.concat([Buffer.from([0x30, 0x80]), good.slice(2), Buffer.from([0x00, 0x00])])) === "attrcert/bad-der");
  // non-minimal length (0x81 0x05 form for a short length)
  var ai = acinfo({});
  check("bad outer arity (2 children)", parseCode(attrCert({ outerChildren: [ai, algId(SIGALG)] })) === "attrcert/not-an-attribute-certificate");
}

// ---- REJECT — serialNumber / validity / attributes -------------------
function testRejectSerialValidity() {
  check("serialNumber negative", parseCode(attrCert({ serialNode: b.integer(-1) })) === "attrcert/bad-serial-number");
  check("serialNumber zero (not positive)", parseCode(attrCert({ serialNode: b.integer(0) })) === "attrcert/bad-serial-number");
  // 21 content octets (positive, leading 0x00 then 20 bytes = 21 octets)
  var big = Buffer.concat([Buffer.from([0x02, 0x15, 0x00]), Buffer.alloc(20, 0xff)]);
  check("serialNumber > 20 octets", parseCode(attrCert({ serialNode: big })) === "attrcert/bad-serial-number");

  check("validity notBefore UTCTime", parseCode(attrCert({ validityNode: b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), gt("2027-01-01T00:00:00Z")]) })) === "attrcert/bad-time");
  check("validity SEQUENCE of 1", parseCode(attrCert({ validityNode: b.sequence([gt("2026-01-01T00:00:00Z")]) })) === "attrcert/bad-validity");
  check("validity SEQUENCE of 3", parseCode(attrCert({ validityNode: b.sequence([gt("2026-01-01T00:00:00Z"), gt("2027-01-01T00:00:00Z"), gt("2028-01-01T00:00:00Z")]) })) === "attrcert/bad-validity");

  check("empty attributes SEQUENCE", parseCode(attrCert({ attributesNode: b.sequence([]) })) === "attrcert/bad-attributes");
  check("duplicate attribute type", parseCode(attrCert({ attributesNode: b.sequence([roleAttr(), roleAttr()]) })) === "attrcert/duplicate-attribute");
}

// ---- REJECT — Holder / AttCertIssuer / ObjectDigestInfo tag traps -----
function testRejectStructuralTraps() {
  check("Holder [0] encoded primitive", parseCode(attrCert({ holderNode: holder({ baseCertificateIDPrimitive: true }) })) === "attrcert/bad-issuer-serial");
  check("Holder trailing out of order ([1] before [0])", parseCode(attrCert({ holderNode: holder({ rawKids: [b.contextConstructed(1, Buffer.concat([gnDns("a.b")])), b.contextConstructed(0, Buffer.concat(issuerSerialContent({})))] }) })) === "attrcert/bad-holder");
  check("Holder unexpected [3]", parseCode(attrCert({ holderNode: holder({ entityName: [gnDns("a.b")], stray3: true }) })) === "attrcert/bad-holder");
  check("AttCertIssuer wrong tag [3]", parseCode(attrCert({ issuerNode: b.contextConstructed(3, Buffer.from([])) })) === "attrcert/bad-issuer");
  check("V2Form stray [2]", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [gnDirName("CA")], stray2: true }) })) === "attrcert/bad-v2form");
  check("ObjectDigestInfo digestedObjectType 3", parseCode(attrCert({ holderNode: holder({ objectDigestInfo: { type: 3 } }) })) === "attrcert/bad-digested-object-type");
  check("ObjectDigestInfo otherObjectTypes(2) forbidden (§7.3)", parseCode(attrCert({ holderNode: holder({ objectDigestInfo: { type: 2 } }) })) === "attrcert/bad-digested-object-type");
  // digestedObjectType encoded as INTEGER (0x02) not ENUMERATED (0x0a) → leaf asn1/*.
  var odiIntType = b.contextConstructed(2, Buffer.concat([b.integer(0), algId(DIGALG), b.bitString(Buffer.from([0xab]), 0)]));
  check("ObjectDigestInfo digestedObjectType as INTEGER", parseCode(attrCert({ holderNode: holder({ odiNode: odiIntType }) })).indexOf("asn1/") === 0);
  // otherObjectTypeID present with a non-otherObjectTypes type (forward constraint).
  check("ObjectDigestInfo otherObjectTypeID with type 0", parseCode(attrCert({ holderNode: holder({ objectDigestInfo: { type: 0, otid: "1.2.3.4" } }) })) === "attrcert/bad-object-digest-info");
}

// ---- REJECT — GeneralName grammar (the validate-not-surface-raw payoff) ----
function testRejectGeneralNames() {
  check("entityName with an invalid GeneralName tag [9]", parseCode(attrCert({ holderNode: holder({ entityName: [b.contextPrimitive(9, Buffer.from([1]))] }) })) === "attrcert/bad-entity-name");
  check("entityName dNSName [2] as constructed (must be primitive)", parseCode(attrCert({ holderNode: holder({ entityName: [b.contextConstructed(2, b.oid("1.2.3"))] }) })) === "attrcert/bad-entity-name");
  check("entityName iPAddress [7] wrong length (5 octets)", parseCode(attrCert({ holderNode: holder({ entityName: [gnIp([1, 2, 3, 4, 5])] }) })) === "attrcert/bad-entity-name");
  check("empty entityName GeneralNames", parseCode(attrCert({ holderNode: holder({ rawKids: [b.contextConstructed(1, Buffer.from([]))] }) })) === "attrcert/bad-entity-name");
  check("v2Form issuerName with a non-IA5 dNSName", parseCode(attrCert({ issuerNode: issuerV2({ issuerName: [b.contextPrimitive(2, Buffer.from([0x66, 0x80]))] }) })) === "attrcert/bad-issuer-name");
  check("valid dNSName entityName accepted", (function () { var m = parse(attrCert({ holderNode: holder({ entityName: [gnDns("a.example")] }) })); return m.holder.entityName.names[0].tagNumber === 2; })());
  // a multi-element GeneralNames of mixed valid alternatives (dNS + URI + registeredID).
  check("valid multi-alternative GeneralNames accepted", (function () {
    var m = parse(attrCert({ holderNode: holder({ entityName: [gnDns("a.example"), gnUri("https://a.example/x"), gnRegId("1.3.6.1.5.5.7.10.4")] }) }));
    return m.holder.entityName.names.length === 3 && m.holder.entityName.names[2].tagNumber === 8;
  })());
}

// ---- REJECT — extensions ---------------------------------------------
function testRejectExtensions() {
  check("empty extensions SEQUENCE", parseCode(attrCert({ extensionsRaw: b.sequence([]) })) === "attrcert/bad-extensions");
  check("critical present-and-FALSE", parseCode(attrCert({ extensions: [ext("2.5.29.56", b.nullValue(), false)] })) === "attrcert/bad-extension");
  check("duplicate extnID", parseCode(attrCert({ extensions: [ext("2.5.29.56", b.nullValue(), undefined), ext("2.5.29.56", b.nullValue(), undefined)] })) === "attrcert/duplicate-extension");
}

// ---- REJECT — legacy v1 + DISPATCH -----------------------------------
function testLegacyV1AndDispatch() {
  var v1 = attrCertV1({});
  var v1base = attrCertV1({ subjectBase: { issuer: [gnDirName("S")], serial: 1 } });
  // The direct parse entry gives the advertised stable legacy diagnostic on a v1 AC —
  // the same error family as the orchestrator, not a low-level asn1/* tag leak.
  check("direct parse on a v1 AC (subjectName [1]) gives the stable legacy code", parseCode(v1) === "attrcert/legacy-v1-not-supported");
  check("direct parse on a v1 AC (baseCertificateID [0]) too", parseCode(v1base) === "attrcert/legacy-v1-not-supported");
  check("parseV1 defers subjectName [1]", code(function () { attrcertMod.parseV1(v1); }) === "attrcert/legacy-v1-not-supported");
  check("parseV1 defers baseCertificateID [0]", code(function () { attrcertMod.parseV1(v1base); }) === "attrcert/legacy-v1-not-supported");

  // detector predicates
  var rootV2 = pki.asn1.decode(attrCert({}));
  var rootV1 = pki.asn1.decode(v1);
  check("attrcert.matches on v2 true", attrcertMod.matches(rootV2) === true);
  check("attrcert.matches on v1 false", attrcertMod.matches(rootV1) === false);
  check("attrcert.matchesV1 on v1 true", attrcertMod.matchesV1(rootV1) === true);
  check("attrcert.matchesV1 on v2 false", attrcertMod.matchesV1(rootV2) === false);

  // orchestrator routing
  var routed = pki.schema.parse(attrCert({}));
  check("orchestrator routes v2 AC to attrcert", routed.version === 2 && Array.isArray(routed.attributes));
  check("all() includes attrcert + attrcert-v1", pki.schema.all().indexOf("attrcert") !== -1 && pki.schema.all().indexOf("attrcert-v1") !== -1);
  check("orchestrator routes v1 AC to defer (not unknown-format)", code(function () { pki.schema.parse(v1base); }) === "attrcert/legacy-v1-not-supported");
}

function testInputCoercion() {
  var der = attrCert({});
  check("parse(Buffer) ok", parse(der).version === 2);
  check("parse(Uint8Array) ok", parse(new Uint8Array(der)).version === 2);
  check("parse(42) bad-input", parseCode(42) === "attrcert/bad-input");
  // The PEM path pins the OpenSSL label (RFC 7468 armor, ATTRIBUTE CERTIFICATE):
  // a string or a Buffer holding the armor parses; a foreign label is a
  // label-mismatch, not a first-block-of-anything acceptance.
  var pem = "-----BEGIN ATTRIBUTE CERTIFICATE-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END ATTRIBUTE CERTIFICATE-----\n";
  check("parse(PEM string) ok", parse(pem).version === 2);
  check("parse(PEM Buffer) ok", parse(Buffer.from(pem, "latin1")).version === 2);
  check("CERTIFICATE-labeled PEM rejected (label pinned)", parseCode(pem.replace(/ATTRIBUTE CERTIFICATE/g, "CERTIFICATE")) === "pem/label-mismatch");
  check("pemDecode round-trips", pki.schema.attrcert.pemDecode(pem).equals(der));
  check("pemEncode default label round-trips",
    pki.schema.attrcert.pemDecode(pki.schema.attrcert.pemEncode(der)).equals(der));
  // The OpenSSL armor label (ATTRIBUTE CERTIFICATE) is the default, matching the
  // labeled sibling formats: label-less pemDecode refuses a foreign first block;
  // an explicit null label opts into the any-block behavior.
  var foreign = pem.replace(/ATTRIBUTE CERTIFICATE/g, "CERTIFICATE");
  check("label-less pemDecode rejects a foreign first block", code(function () { pki.schema.attrcert.pemDecode(foreign); }) === "pem/label-mismatch");
  check("pemDecode(text, null) takes the first block of any type", pki.schema.attrcert.pemDecode(foreign, null).equals(der));
  check("missing envelope -> pem/no-block", parseCode("not a pem block") === "pem/no-block");
  check("bad base64 body -> pem/bad-base64", parseCode("-----BEGIN ATTRIBUTE CERTIFICATE-----\n@@@@\n-----END ATTRIBUTE CERTIFICATE-----\n") === "pem/bad-base64");
  // multi-defect fail-closed: never NO-THROW
  var multi = attrCert({ version: 0, validityNode: b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), gt("2027-01-01T00:00:00Z")]), attributesNode: b.sequence([roleAttr(), roleAttr()]) });
  var mc = parseCode(multi);
  check("multi-defect rejected (typed)", mc !== "NO-THROW" && (mc.indexOf("attrcert/") === 0 || mc.indexOf("asn1/") === 0));
}

// ---- runner ----------------------------------------------------------
testAcceptV2();
testHolderVariants();
testIssuerProfile();
testOptionalTail();
testTwoAttributes();
testRejectVersionEnvelope();
testRejectSerialValidity();
testRejectStructuralTraps();
testRejectGeneralNames();
testRejectExtensions();
testLegacyV1AndDispatch();
testInputCoercion();

if (require.main === module) console.log("CHECKS " + helpers.getChecks());
module.exports = {};
