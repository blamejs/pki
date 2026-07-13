// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.schema.csrattrs (RFC 8951 sec. 3.5 CsrAttrs + RFC 9908 templates).
 * Spec-first conformance vectors, RED-first: every valid CsrAttrs parses to the
 * documented shape; every malformed structure and every RFC 9908 semantic
 * violation is rejected fail-closed with a typed csrattrs/* (or leaf asn1/*)
 * code; unknown OIDs / attribute types are TOLERATED (surfaced raw, never a
 * fault -- RFC 8951 sec. 4.5.2 "the client MUST ignore any OID or attribute it
 * does not recognize"). RED baseline: pki.schema.csrattrs.parse is undefined
 * until the module lands, so every vector throws -- the suite drives it GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var csrattrsLib = require("../../lib/schema-csrattrs");  // non-curated exports (matches / csrAttrsSchema)

// ---- OIDs (dotted literals are fine in TEST fixtures) ----------------
var CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7";
var EC_PUBLIC_KEY      = "1.2.840.10045.2.1";
var SECP384R1          = "1.3.132.0.34";
var EXTENSION_REQUEST  = "1.2.840.113549.1.9.14";   // id-ExtensionReq
var MAC_ADDRESS        = "1.3.6.1.1.1.1.22";
var ECDSA_SHA384       = "1.2.840.10045.4.3.3";
var RSA_ENCRYPTION     = "1.2.840.113549.1.1.1";
var TEMPLATE           = "1.2.840.113549.1.9.16.2.61";  // id-aa-certificationRequestInfoTemplate
var EXT_REQ_TEMPLATE   = "1.2.840.113549.1.9.16.2.62";  // id-aa-extensionReqTemplate
var BASIC_CONSTRAINTS  = "2.5.29.19";
var SUBJECT_ALT_NAME   = "2.5.29.17";
var CN                 = "2.5.4.3";

// ---- fixture builders (compose pki.asn1.build) -----------------------
// Attribute ::= SEQUENCE { type OID, values SET OF ANY }
function attr(typeOid, valueNodes) { return b.sequence([b.oid(typeOid), b.set(valueNodes)]); }
// CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
function csrattrs(items) { return b.sequence(items || []); }
// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
function ext(oid, critical, valueDer) {
  var c = [b.oid(oid)];
  if (critical !== undefined) c.push(b.boolean(critical));
  c.push(b.octetString(valueDer || Buffer.from([0x30, 0x00])));
  return b.sequence(c);
}
function extensions(list) { return b.sequence(list); }             // Extensions ::= SEQUENCE OF Extension
function extReqAttr(exts) { return attr(EXTENSION_REQUEST, [extensions(exts)]); }
// A SET built in the GIVEN order (no DER sort) for order-reject vectors.
function rawSet(members) {
  var body = Buffer.concat(members), n = body.length, hdr;
  if (n < 0x80) hdr = Buffer.from([0x31, n]);
  else if (n < 0x100) hdr = Buffer.from([0x31, 0x81, n]);
  else hdr = Buffer.from([0x31, 0x82, (n >> 8) & 0xff, n & 0xff]);
  return Buffer.concat([hdr, body]);
}
// CertificationRequestInfoTemplate ::= SEQUENCE { version INTEGER, subject
//   NameTemplate OPTIONAL, subjectPKInfo [0] IMPLICIT OPTIONAL, attributes [1]
//   IMPLICIT Attributes }
function template(o) {
  o = o || {};
  var c = [o.version !== undefined ? o.version : b.integer(0n)];
  if (o.subject) c.push(o.subject);                                          // NameTemplate (universal SEQUENCE)
  if (o.subjectPKInfo) c.push(b.contextConstructed(0, o.subjectPKInfo));     // [0] IMPLICIT
  c.push(b.contextConstructed(1, o.attributesBody || Buffer.alloc(0)));      // [1] IMPLICIT Attributes (may be empty)
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}
function templateAttr(o) { return attr(TEMPLATE, [template(o)]); }
// SubjectPublicKeyInfoTemplate carried as subjectPKInfo [0] IMPLICIT: the [0] tag
// REPLACES the SEQUENCE tag, so this returns the CONTENT (algorithm + optional
// placeholder key) that template() wraps in contextConstructed(0, ...).
function spkiTemplate(algOid, placeholderKey) {
  var c = [b.sequence([b.oid(algOid)])];
  if (placeholderKey) c.push(b.bitString(placeholderKey, 0));
  return Buffer.concat(c);
}
// SingleAttributeTemplate ::= SEQUENCE { type OID, value ANY OPTIONAL }
function singleAttrTemplate(typeOid, valueNode) {
  var c = [b.oid(typeOid)];
  if (valueNode) c.push(valueNode);
  return b.sequence(c);
}
// NameTemplate ::= RDNSequence; RelativeDistinguishedNameTemplate ::= SET SIZE(1..MAX)
function nameTemplate(rdns) { return b.sequence(rdns); }
// ExtensionTemplate ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING OPTIONAL }
function extTemplate(oid, critical, valueDer) {
  var c = [b.oid(oid)];
  if (critical !== undefined) c.push(b.boolean(critical));
  if (valueDer !== undefined) c.push(b.octetString(valueDer));
  return b.sequence(c);
}
// ExtensionReqTemplate ::= SEQUENCE SIZE (1..MAX) OF ExtensionTemplate (RFC 9908 sec. 3.4).
function extReqTemplate(tpls) { return b.sequence(tpls); }

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.csrattrs.parse(der); }); }
function parse(der) { return pki.schema.csrattrs.parse(der); }

// ---- ACCEPT / known-answer -------------------------------------------
function testAccept() {
  // 1. empty CsrAttrs (30 00) -> [] (RFC 8951 sec. 3.5: "no additional information desired").
  check("1. empty CsrAttrs -> empty items", parse(csrattrs([])).items.length === 0);

  // 2. the RFC 7030 sec. 4.5.2 example puts a bare macAddress OID as the
  //    id-ExtensionReq value -- RFC 9908 sec. 4 declares that example "NOT
  //    CORRECT" (the value MUST be an Extensions SEQUENCE, sec. 3.2). A conformant
  //    parser rejects the malformed id-ExtensionReq fail-closed rather than
  //    inventing an extensions decode from a non-SEQUENCE value. (The well-formed
  //    accept path is vectors 3/4/5.)
  var exampleDer = Buffer.from("MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJBgcrBgEBAQEWBggqhkjOPQQDAw==", "base64");
  check("2. RFC 7030 example (RFC 9908 'NOT CORRECT') rejected fail-closed", parseCode(exampleDer) === "csrattrs/bad-extensions");
  // 2b. the same example with a WELL-FORMED id-ExtensionReq (value an Extensions
  //     wrapping the macAddress extnID) parses to four items, order preserved.
  var wellFormed = csrattrs([b.oid(CHALLENGE_PASSWORD), attr(EC_PUBLIC_KEY, [b.oid(SECP384R1)]), extReqAttr([ext(MAC_ADDRESS, undefined, Buffer.from([0x30, 0x00]))]), b.oid(ECDSA_SHA384)]);
  var ex = parse(wellFormed);
  check("2b. well-formed example: four items in order", ex.items.length === 4);
  check("2b. item[0] bare-oid challengePassword", ex.items[0].kind === "oid" && ex.items[0].oid === CHALLENGE_PASSWORD);
  check("2b. item[1] ecPublicKey attr, curve secp384r1", ex.items[1].kind === "attribute" && ex.items[1].oid === EC_PUBLIC_KEY && ex.items[1].curve === SECP384R1);
  check("2b. item[2] extensionRequest attr, one extension macAddress", ex.items[2].oid === EXTENSION_REQUEST && ex.items[2].extensions.length === 1 && ex.items[2].extensions[0].oid === MAC_ADDRESS);
  check("2b. item[3] bare-oid ecdsa-with-SHA384", ex.items[3].kind === "oid" && ex.items[3].oid === ECDSA_SHA384);

  // 3. two bare OIDs -> two {kind:"oid"} items.
  var oo = parse(csrattrs([b.oid(EC_PUBLIC_KEY), b.oid(RSA_ENCRYPTION)]));
  check("3. two bare OIDs", oo.items.length === 2 && oo.items.every(function (i) { return i.kind === "oid"; }));
  check("3. bare-oid name resolved", oo.items[0].oid === EC_PUBLIC_KEY && oo.items[0].name === "ecPublicKey");

  // 4. rsaEncryption {INTEGER 4096} -> decoded key size (RFC 9908 sec. 3.2).
  var rsa = parse(csrattrs([attr(RSA_ENCRYPTION, [b.integer(4096n)])]));
  check("4. rsa key size decoded", rsa.items[0].oid === RSA_ENCRYPTION && rsa.items[0].keySize === 4096);
  // 4b. a multi-valued key-type hint is ambiguous -> fail closed (never read values[0]).
  check("4b. multi-valued rsaEncryption rejected", parseCode(csrattrs([attr(RSA_ENCRYPTION, [b.integer(2048n), b.integer(4096n)])])) === "csrattrs/bad-key-type-attr");
  check("4c. multi-valued ecPublicKey rejected", parseCode(csrattrs([attr(EC_PUBLIC_KEY, [b.oid(SECP384R1), b.oid("1.2.840.10045.3.1.7")])])) === "csrattrs/bad-key-type-attr");
  // 4d. an EMPTY key-type values SET is valid -- "any key of this type" (RFC 9908 sec. 3.2).
  var ecAny = parse(csrattrs([attr(EC_PUBLIC_KEY, [])]));
  check("4d. empty ecPublicKey values accepted (any curve)", ecAny.items[0].oid === EC_PUBLIC_KEY && ecAny.items[0].curve === undefined);
  var rsaAny = parse(csrattrs([attr(RSA_ENCRYPTION, [])]));
  check("4e. empty rsaEncryption values accepted (any size)", rsaAny.items[0].oid === RSA_ENCRYPTION && rsaAny.items[0].keySize === undefined);
  // 4f-g. a recognized no-parameter key type beyond RSA/EC (Ed25519, ML-DSA) with an
  //       empty values SET is accepted -- RSA/EC are only the RFC 9908 sec. 3.2 examples.
  check("4f. empty Ed25519 key-type accepted", parse(csrattrs([attr("1.3.101.112", [])])).items[0].oid === "1.3.101.112");
  check("4g. empty ML-DSA key-type accepted", parse(csrattrs([attr("2.16.840.1.101.3.4.3.18", [])])).items[0].oid === "2.16.840.1.101.3.4.3.18");

  // 5. id-ExtensionReq with one Extensions value -> decoded extensions array.
  var er = parse(csrattrs([extReqAttr([ext(BASIC_CONSTRAINTS, undefined, Buffer.from([0x30, 0x00]))])]));
  check("5. extension-req decoded", er.items[0].oid === EXTENSION_REQUEST && er.items[0].extensions.length === 1 && er.items[0].extensions[0].oid === BASIC_CONSTRAINTS && er.items[0].extensions[0].critical === false);

  // 6. minimal template: version 0 + empty attributes [1]; subject/subjectPKInfo absent.
  var tm = parse(csrattrs([templateAttr({})]));
  check("6. template minimal parsed", tm.items[0].oid === TEMPLATE && tm.items[0].template.version === 0);
  check("6. template subject/subjectPKInfo absent", tm.items[0].template.subject === null && tm.items[0].template.subjectPKInfo === null);
  check("6. template attributes empty array", Array.isArray(tm.items[0].template.attributes) && tm.items[0].template.attributes.length === 0);

  // 7. full template: NameTemplate (value-absent CN), subjectPKInfo [0] {rsa,
  //    placeholder key}, attributes [1] {extensionReqTemplate w/ value-absent ext}.
  var rdn = b.set([singleAttrTemplate(CN)]);                     // value-absent SingleAttributeTemplate
  var subj = nameTemplate([rdn]);
  var spki = spkiTemplate(RSA_ENCRYPTION, Buffer.from([0x00, 0x01]));
  var innerExtReqTpl = attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate(SUBJECT_ALT_NAME)])]);  // SEQUENCE OF one value-absent ExtensionTemplate
  var full = parse(csrattrs([templateAttr({ subject: subj, subjectPKInfo: spki, attributesBody: innerExtReqTpl })]));
  var ft = full.items[0].template;
  check("7. template full: subject one RDN, value null", ft.subject.length === 1 && ft.subject[0][0].value === null);
  check("7. template full: subjectPKInfo alg + placeholder key", ft.subjectPKInfo.algorithm.oid === RSA_ENCRYPTION && Buffer.isBuffer(ft.subjectPKInfo.placeholderKey));
  check("7. template full: extensionReqTemplate value-absent extension", ft.extensionTemplates.length === 1 && ft.extensionTemplates[0].oid === SUBJECT_ALT_NAME && ft.extensionTemplates[0].value === null);
  // 7b. an ExtensionReqTemplate is a SEQUENCE OF ExtensionTemplate -> two decode to two.
  var twoTpl = attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate(BASIC_CONSTRAINTS), extTemplate(SUBJECT_ALT_NAME)])]);
  var ft7b = parse(csrattrs([templateAttr({ attributesBody: twoTpl })])).items[0].template;
  check("7b. extensionReqTemplate SEQUENCE OF two templates", ft7b.extensionTemplates.length === 2);
  // 7c. the non-standard single-ExtensionTemplate-as-value (not wrapped in the
  //     SEQUENCE OF) is now rejected (its first child is an OID, not a SEQUENCE).
  check("7c. bare ExtensionTemplate value rejected", parseCode(csrattrs([templateAttr({ attributesBody: attr(EXT_REQ_TEMPLATE, [extTemplate(SUBJECT_ALT_NAME)]) })])) === "csrattrs/bad-extension-template");
  // 7d. a template using a normal id-ExtensionReq exposes its decoded extensions
  //     (not just raw bytes) the way a top-level extensionRequest does.
  var tplExtReq = attr(EXTENSION_REQUEST, [extensions([ext(BASIC_CONSTRAINTS, undefined, Buffer.from([0x30, 0x00]))])]);
  var ft7d = parse(csrattrs([templateAttr({ attributesBody: tplExtReq })])).items[0].template;
  check("7d. template id-ExtensionReq decoded to .extensions", Array.isArray(ft7d.extensions) && ft7d.extensions.length === 1 && ft7d.extensions[0].oid === BASIC_CONSTRAINTS);
  // 7e. two id-ExtensionReq attributes in a template -> rejected, not last-one-wins.
  var twoExtReq = Buffer.concat([attr(EXTENSION_REQUEST, [extensions([ext(BASIC_CONSTRAINTS)])]), attr(EXTENSION_REQUEST, [extensions([ext(SUBJECT_ALT_NAME)])])].sort(Buffer.compare));
  check("7e. duplicate template id-ExtensionReq rejected", parseCode(csrattrs([templateAttr({ attributesBody: twoExtReq })])) === "csrattrs/bad-template-attrs");

  // 8. unknown attribute type -> raw values, parse succeeds (P9).
  var unk = parse(csrattrs([attr("1.3.99.1.2", [b.integer(7n), b.octetString(Buffer.from([1, 2]))].sort(Buffer.compare))]));
  check("8. unknown attr tolerated raw", unk.items[0].kind === "attribute" && unk.items[0].oid === "1.3.99.1.2" && unk.items[0].values.length === 2 && Buffer.isBuffer(unk.items[0].values[0]));

  // 9. round-trip: encode(schema, parsed) reproduces the input bytes byte-exact.
  var input = csrattrs([b.oid(CHALLENGE_PASSWORD), attr(RSA_ENCRYPTION, [b.integer(2048n)])]);
  var reencoded = pki.schema.engine.encode(csrattrsLib.csrAttrsSchema, parse(input).items);
  check("9. round-trip byte-exact", Buffer.isBuffer(reencoded) && reencoded.equals(input));
}

// ---- REJECT -- structure ---------------------------------------------
function testRejectStructure() {
  // 10. a child INTEGER (neither OID nor SEQUENCE) -> bad-attr-or-oid.
  check("10. bad arm (INTEGER child)", parseCode(csrattrs([b.integer(1n)])) === "csrattrs/bad-attr-or-oid");
  // 11. only the recognized NON-KEY attributes that require a value keep
  //     SET SIZE(1..MAX): an empty id-ExtensionReq fails closed.
  check("11. empty id-ExtensionReq values rejected", parseCode(csrattrs([attr(EXTENSION_REQUEST, [])])) === "csrattrs/bad-attribute-values");
  // 11b-c. a key-type hint's empty SET means "any" (4d/4e/4f/4g); an UNKNOWN OID --
  //        a key type this build does not know yet, or any other attribute -- is
  //        TOLERATED with an empty SET (RFC 8951: ignore what you don't recognize),
  //        surfaced raw rather than failing the whole response.
  check("11b. empty unknown-key-type OID tolerated", parse(csrattrs([attr("1.3.6.1.4.1.99999.42", [])])).items[0].oid === "1.3.6.1.4.1.99999.42");
  check("11c. empty unknown-attribute values tolerated", parse(csrattrs([attr("1.3.99.7.7", [])])).items[0].values.length === 0);
  // 12. Attribute SEQUENCE of 3 children -> rejected.
  check("12. attribute of 3 children rejected", parseCode(csrattrs([b.sequence([b.oid(RSA_ENCRYPTION), b.set([b.integer(1n)]), b.integer(9n)])])) !== "NO-THROW");
  // 13. values SET in descending DER order -> derSetOrder fault.
  var v1 = b.integer(1n), v2 = b.octetString(Buffer.from([0xff, 0xff]));
  var hi = Buffer.compare(v1, v2) < 0 ? v2 : v1, lo = Buffer.compare(v1, v2) < 0 ? v1 : v2;
  check("13. values SET wrong order rejected", parseCode(csrattrs([b.sequence([b.oid("1.3.99.9"), rawSet([hi, lo])])])) !== "NO-THROW");
  // 14. root SET (not SEQUENCE) -> shape fault.
  check("14. root SET rejected", parseCode(b.set([b.oid(RSA_ENCRYPTION)])) === "csrattrs/not-csrattrs");
  // 15. trailing byte after a valid CsrAttrs -> asn1/* codec verdict.
  check("15. trailing byte rejected", parseCode(Buffer.concat([csrattrs([b.oid(RSA_ENCRYPTION)]), Buffer.from([0x00])])) !== "NO-THROW");
  check("15b. indefinite length rejected", parseCode(Buffer.from([0x30, 0x80, 0x00, 0x00])) !== "NO-THROW");
}

// ---- REJECT -- RFC 9908 semantics ------------------------------------
function testRejectSemantics() {
  // 16. two id-ExtensionReq attributes -> duplicate-extension-req (P11).
  check("16. duplicate extension-req", parseCode(csrattrs([extReqAttr([ext(BASIC_CONSTRAINTS)]), extReqAttr([ext(SUBJECT_ALT_NAME)])])) === "csrattrs/duplicate-extension-req");
  // 17. extension-req values SET of 2 -> exactly-one fault (P11).
  check("17. extension-req two values", parseCode(csrattrs([attr(EXTENSION_REQUEST, [extensions([ext(BASIC_CONSTRAINTS)]), extensions([ext(SUBJECT_ALT_NAME)])])])) !== "NO-THROW");
  // 18. Extensions repeating an extnID -> duplicate-extension (via pkix.extensions).
  check("18. duplicate extnID", parseCode(csrattrs([extReqAttr([ext(BASIC_CONSTRAINTS), ext(BASIC_CONSTRAINTS)])])) !== "NO-THROW");
  // 19. explicit critical FALSE inside an extension -> DER DEFAULT fault.
  check("19. explicit critical FALSE", parseCode(csrattrs([extReqAttr([ext(BASIC_CONSTRAINTS, false, Buffer.from([0x30, 0x00]))])])) !== "NO-THROW");
  // 20. template version 1 -> bad-template-version (P13).
  check("20. template bad version", parseCode(csrattrs([templateAttr({ version: b.integer(1n) })])) === "csrattrs/bad-template-version");
  // 21. two template attributes -> rejected.
  check("21. duplicate template", parseCode(csrattrs([templateAttr({}), templateAttr({})])) !== "NO-THROW");
  // 22. template attributes carrying BOTH id-ExtensionReq and id-aa-extensionReqTemplate -> rejected.
  var mixedBody = Buffer.concat([attr(EXTENSION_REQUEST, [extensions([ext(BASIC_CONSTRAINTS)])]), attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate(SUBJECT_ALT_NAME)])])].sort(Buffer.compare));
  check("22. template mixed extension-req kinds", parseCode(csrattrs([templateAttr({ attributesBody: mixedBody })])) === "csrattrs/bad-template-attrs");
  // 23. extensionReqTemplate values SET of 2 -> rejected.
  check("23. extensionReqTemplate two values", parseCode(csrattrs([templateAttr({ attributesBody: attr(EXT_REQ_TEMPLATE, [extTemplate(BASIC_CONSTRAINTS), extTemplate(SUBJECT_ALT_NAME)]) })])) !== "NO-THROW");
  // 24. RelativeDistinguishedNameTemplate empty SET -> SIZE(1..MAX) fault.
  check("24. empty RDN template", parseCode(csrattrs([templateAttr({ subject: nameTemplate([b.set([])]) })])) !== "NO-THROW");
}

// ---- Orchestrator routing (mutual exclusivity) -----------------------
function testRouting() {
  // 25. a CsrAttrs routes to csrattrs; all() lists it between crmf and ocsp-request.
  var der = csrattrs([attr(RSA_ENCRYPTION, [b.integer(2048n)])]);
  var routed = pki.schema.parse(der);
  check("25. routes to csrattrs", routed && Array.isArray(routed.items));
  var all = pki.schema.all();
  check("25. all() includes csrattrs", all.indexOf("csrattrs") !== -1);
  check("25. csrattrs ordered between crmf and ocsp-request", all.indexOf("csrattrs") > all.indexOf("crmf") && all.indexOf("csrattrs") < all.indexOf("ocsp-request"));
  // 26. a one-Attribute CsrAttrs routes to csrattrs, NOT ocsp-request.
  check("26. single-attr routes csrattrs not ocsp", pki.schema.parse(csrattrs([attr(EC_PUBLIC_KEY, [b.oid(SECP384R1)])])).items !== undefined);
  // 29. empty 30 00 routes to csrattrs (previously schema/unknown-format).
  check("29. empty seq routes to csrattrs", Array.isArray(pki.schema.parse(csrattrs([])).items));
  // 28. csrattrs.matches false on a valid pkcs8 (INTEGER-first) fixture.
  var pk8 = b.sequence([b.integer(0n), b.sequence([b.oid("1.3.101.112")]), b.octetString(Buffer.from([1, 2, 3, 4]))]);
  check("28. matches false on pkcs8", csrattrsLib.matches(pki.asn1.decode(pk8)) === false);
}

// ---- Adversarial / edge branches (key-type, template, ExtensionTemplate) ----
function testEdgeBranches() {
  // 30. a key-type hint value that is not the expected leaf type is re-thrown as a
  //     typed key-type fault (never a raw asn1 leaf error leaking out): an
  //     ecPublicKey singleton that is an INTEGER, an rsaEncryption singleton OID.
  check("30. ecPublicKey non-OID value rejected", parseCode(csrattrs([attr(EC_PUBLIC_KEY, [b.integer(5n)])])) === "csrattrs/bad-key-type-attr");
  check("31. rsaEncryption non-INTEGER value rejected", parseCode(csrattrs([attr(RSA_ENCRYPTION, [b.oid(SECP384R1)])])) === "csrattrs/bad-key-type-attr");
  // 32. rsaEncryption key size out of the 1..65536-bit bound -> fail closed BEFORE
  //     the Number() narrow (both sides of the range guard).
  check("32. rsaEncryption key size 0 rejected", parseCode(csrattrs([attr(RSA_ENCRYPTION, [b.integer(0n)])])) === "csrattrs/bad-key-type-attr");
  check("33. rsaEncryption key size > 65536 rejected", parseCode(csrattrs([attr(RSA_ENCRYPTION, [b.integer(70000n)])])) === "csrattrs/bad-key-type-attr");
  // 34. the boundary 65536 is IN range (accepted, not an off-by-one reject).
  check("34. rsaEncryption key size 65536 accepted", parse(csrattrs([attr(RSA_ENCRYPTION, [b.integer(65536n)])])).items[0].keySize === 65536);

  // 35. a bare OID with no registry name resolves name -> null (not a fault).
  var bareUnknown = parse(csrattrs([b.oid("1.3.99.1.2")]));
  check("35. bare unknown OID name null", bareUnknown.items[0].kind === "oid" && bareUnknown.items[0].name === null);

  // 36. an Attribute SEQUENCE whose first child is not an OID has no readable type
  //     OID -> the attribute walk fails closed on the type leaf (asn1/unexpected-tag),
  //     never silently accepted with a null type.
  check("36. attr SEQUENCE non-OID first child rejected", parseCode(csrattrs([b.sequence([b.integer(1n), b.set([])])])) === "asn1/unexpected-tag");

  // 37. a top-level certificationRequestInfoTemplate attribute whose values SET holds
  //     two templates -> exactly-one fault (never last-one-wins).
  var t1 = template({});
  var t2 = template({ subject: nameTemplate([b.set([singleAttrTemplate(CN)])]) });
  check("37. template attr two values rejected", parseCode(csrattrs([attr(TEMPLATE, [t1, t2])])) === "csrattrs/bad-template");

  // 38. a template inner id-ExtensionReq whose values SET holds two Extensions ->
  //     exactly-one fault (the inner-attribute MUST, RFC 9908 sec. 3.2).
  var twoExtVals = attr(EXTENSION_REQUEST, [extensions([ext(BASIC_CONSTRAINTS)]), extensions([ext(SUBJECT_ALT_NAME)])]);
  check("38. template inner id-ExtensionReq two values rejected", parseCode(csrattrs([templateAttr({ attributesBody: twoExtVals })])) === "csrattrs/bad-template-attrs");

  // 39. a template carrying TWO id-aa-extensionReqTemplate attributes -> at-most-one
  //     fault (RFC 9908 sec. 3.4), not a silent concat.
  var tplA = attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate(BASIC_CONSTRAINTS)])]);
  var tplB = attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate(SUBJECT_ALT_NAME)])]);
  var twoTplBody = Buffer.concat([tplA, tplB].sort(Buffer.compare));
  check("39. template two extensionReqTemplate rejected", parseCode(csrattrs([templateAttr({ attributesBody: twoTplBody })])) === "csrattrs/bad-template-attrs");
}

// ---- ExtensionTemplate + SingleAttributeTemplate + SPKI-template branches ----
function testTemplateInnerBranches() {
  // 40. an ExtensionTemplate carrying an explicit critical TRUE + an extnValue +
  //     an UNKNOWN extnID surfaces critical:true, a raw value Buffer, and name:null
  //     (the boolean-present, value-present, and unresolved-name branches).
  var richTpl = attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate("1.3.99.5.5", true, Buffer.from([0x30, 0x00]))])]);
  var t40 = parse(csrattrs([templateAttr({ attributesBody: richTpl })])).items[0].template;
  check("40. ExtensionTemplate critical TRUE surfaced", t40.extensionTemplates[0].critical === true);
  check("40. ExtensionTemplate extnValue surfaced raw", Buffer.isBuffer(t40.extensionTemplates[0].value));
  check("40. ExtensionTemplate unknown extnID name null", t40.extensionTemplates[0].name === null);

  // 41. an ExtensionTemplate with an explicit critical FALSE is non-DER (BOOLEAN
  //     DEFAULT FALSE) -> fail closed.
  var falseCrit = attr(EXT_REQ_TEMPLATE, [extReqTemplate([extTemplate(SUBJECT_ALT_NAME, false, Buffer.from([0x30, 0x00]))])]);
  check("41. ExtensionTemplate explicit critical FALSE rejected", parseCode(csrattrs([templateAttr({ attributesBody: falseCrit })])) === "csrattrs/bad-extension-template");

  // 42. an ExtensionTemplate of {extnID, extnValue, extnValue} (a trailing element,
  //     no critical) -> unexpected-trailing fault, never a silent drop.
  var trailingTpl = b.sequence([b.oid(SUBJECT_ALT_NAME), b.octetString(Buffer.from([0x30, 0x00])), b.octetString(Buffer.from([0x30, 0x00]))]);
  var trailingBody = attr(EXT_REQ_TEMPLATE, [extReqTemplate([trailingTpl])]);
  check("42. ExtensionTemplate trailing element rejected", parseCode(csrattrs([templateAttr({ attributesBody: trailingBody })])) === "csrattrs/bad-extension-template");

  // 43. a value-PRESENT SingleAttributeTemplate surfaces value as raw bytes (the
  //     present branch; test 7 covers the value-absent -> null branch).
  var subjWithVal = nameTemplate([b.set([singleAttrTemplate(CN, b.integer(5n))])]);
  var t43 = parse(csrattrs([templateAttr({ subject: subjWithVal })])).items[0].template;
  check("43. SingleAttributeTemplate value present -> raw bytes", Buffer.isBuffer(t43.subject[0][0].value) && t43.subject[0][0].name === "commonName");

  // 44. a SubjectPublicKeyInfoTemplate with NO placeholder key surfaces
  //     placeholderKey:null (the absent branch; test 7 covers the present branch).
  var t44 = parse(csrattrs([templateAttr({ subjectPKInfo: spkiTemplate(RSA_ENCRYPTION) })])).items[0].template;
  check("44. SPKI template no placeholder key -> null", t44.subjectPKInfo.algorithm.oid === RSA_ENCRYPTION && t44.subjectPKInfo.placeholderKey === null);
}

// ---- matches(): structural detector arms -----------------------------
function testMatchesArms() {
  // 45. a bare-OID child is accepted by the detector's OID arm; a following
  //     well-formed Attribute keeps the whole root a CsrAttrs (the continue arm).
  var mixed = csrattrs([b.oid(RSA_ENCRYPTION), attr(RSA_ENCRYPTION, [b.integer(1n)])]);
  check("45. matches true: bare OID + Attribute", csrattrsLib.matches(pki.asn1.decode(mixed)) === true);
  // 46. an Attribute-arm child whose first element is not an OID -> not a CsrAttrs.
  var badFirst = b.sequence([b.sequence([b.integer(1n), b.set([])])]);
  check("46. matches false: attr first child not OID", csrattrsLib.matches(pki.asn1.decode(badFirst)) === false);
  // 47. an Attribute-arm child whose second element is not a SET -> not a CsrAttrs.
  var badSecond = b.sequence([b.sequence([b.oid(RSA_ENCRYPTION), b.integer(1n)])]);
  check("47. matches false: attr second child not SET", csrattrsLib.matches(pki.asn1.decode(badSecond)) === false);
}

function run() {
  testAccept();
  testRejectStructure();
  testRejectSemantics();
  testRouting();
  testEdgeBranches();
  testTemplateInnerBranches();
  testMatchesArms();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
