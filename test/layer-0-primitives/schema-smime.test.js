// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.smime (RFC 5035 ESS SigningCertificate / V2 + RFC 8551
 * SMIMECapabilities signed-attribute values). Spec-first conformance vectors,
 * RED-first: every valid attribute value decodes to the documented shape; every
 * malformed shape is rejected fail-closed with a typed smime/* (or leaf asn1/*)
 * error. These are the DER values of CMS signed attributes — a companion decoder
 * invoked by OID dispatch, NOT a schema.parse format (pinned by an orchestrator
 * exclusion vector).
 *
 * RED baseline: pki.schema.smime.* is undefined until the module lands, so every
 * vector throws — the suite drives the build to GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var smime = pki.schema.smime;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e && e.code ? e.code : ("RAW:" + (e && e.message)); } }
function O(n) { return pki.oid.byName(n); }
function gnDns(s) { return b.contextPrimitive(2, Buffer.from(s, "latin1")); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function gnDir(cn) { return b.explicit(4, name(cn)); }   // directoryName [4] GeneralName
// RFC 5035 §5: the IssuerSerial issuer is a single directoryName.
function issuerSerial(cn, serial) { return b.sequence([b.sequence([gnDir(cn)]), b.integer(BigInt(serial))]); }
function algId(nm) { return b.sequence([b.oid(O(nm))]); }

// ---- ACCEPT: SigningCertificate (ESS v1) -----------------------------
function testSigningCertificate() {
  var ess = b.sequence([b.octetString(Buffer.alloc(20, 0xAB)), issuerSerial("ca.example", 42)]);
  var sc = pki.schema.smime.parseSigningCertificate(b.sequence([b.sequence([ess])]));
  check("1. v1 certs surfaced", sc.certs.length === 1);
  check("2. v1 certHash raw 20 bytes", Buffer.isBuffer(sc.certs[0].certHash) && sc.certs[0].certHash.length === 20);
  check("3. v1 hashAlgorithm is the implied SHA-1", sc.certs[0].hashAlgorithm.name === "sha1" && sc.certs[0].hashAlgorithm.implied === true && sc.certs[0].hashAlgorithm.oid === O("sha1"));
  check("4. v1 issuerSerial serial as BigInt + hex", sc.certs[0].issuerSerial.serialNumber === 42n && sc.certs[0].issuerSerial.serialNumberHex === "2a");
  check("5. v1 issuerSerial issuer GeneralNames surfaced", sc.certs[0].issuerSerial.issuer.names.length === 1);
  check("6. v1 policies absent -> null", sc.policies === null);

  // issuerSerial OPTIONAL — absent
  var essNoIs = b.sequence([b.octetString(Buffer.alloc(20, 1))]);
  var scNoIs = smime.parseSigningCertificate(b.sequence([b.sequence([essNoIs])]));
  check("7. v1 issuerSerial optional (absent -> null)", scNoIs.certs[0].issuerSerial === null);

  // order preserved across multiple ESSCertIDs (first is the signing cert)
  var e1 = b.sequence([b.octetString(Buffer.alloc(20, 1))]);
  var e2 = b.sequence([b.octetString(Buffer.alloc(20, 2))]);
  var multi = smime.parseSigningCertificate(b.sequence([b.sequence([e1, e2])]));
  check("8. v1 certs order preserved", multi.certs.length === 2 && multi.certs[0].certHash[0] === 1 && multi.certs[1].certHash[0] === 2);

  // RFC 5035 §5: only certs[0] (the signing public-key cert) is narrowed to a
  // directoryName issuer; an ADDITIONAL cert (certs[1..]) may reference an
  // attribute certificate whose issuer is a non-directoryName GeneralNames.
  var signerCert = b.sequence([b.octetString(Buffer.alloc(20, 1)), issuerSerial("signer.ca", 1)]);   // directoryName
  var acCert = b.sequence([b.octetString(Buffer.alloc(20, 2)), b.sequence([b.sequence([gnDns("ac.example")]), b.integer(9n)])]);   // AC ref, dNSName issuer
  var withAc = smime.parseSigningCertificate(b.sequence([b.sequence([signerCert, acCert])]));
  check("8b. additional AC cert with a non-directoryName issuer accepted", withAc.certs.length === 2 && withAc.certs[1].issuerSerial.issuer.names[0].tagNumber === 2);

  // policies present
  var policy = b.sequence([b.oid(O("anyPolicy"))]);
  var scPol = smime.parseSigningCertificate(b.sequence([b.sequence([essNoIs]), b.sequence([policy])]));
  check("9. v1 policies decoded (policyIdentifier + name)", scPol.policies.length === 1 && scPol.policies[0].policyIdentifier === O("anyPolicy") && scPol.policies[0].name === "anyPolicy");
  // policies present-but-empty is legal (no SIZE bound)
  var scPolEmpty = smime.parseSigningCertificate(b.sequence([b.sequence([essNoIs]), b.sequence([])]));
  check("10. v1 empty policies list legal", Array.isArray(scPolEmpty.policies) && scPolEmpty.policies.length === 0);

  // policyQualifiers structure validated (RFC 5280 §4.2.1.4), qualifier body raw.
  var pqi = b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.octetString(Buffer.from("cps"))]);   // PolicyQualifierInfo { id-qt-cps, qualifier }
  var polGoodQ = b.sequence([b.oid(O("anyPolicy")), b.sequence([pqi])]);
  var scGoodQ = smime.parseSigningCertificate(b.sequence([b.sequence([essNoIs]), b.sequence([polGoodQ])]));
  check("10a. well-formed policyQualifiers accepted, surfaced raw", Buffer.isBuffer(scGoodQ.policies[0].policyQualifiers));
  // empty policyQualifiers SEQUENCE -> rejected (SIZE 1..MAX)
  var polEmptyQ = b.sequence([b.oid(O("anyPolicy")), b.sequence([])]);
  check("10b. empty policyQualifiers rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essNoIs]), b.sequence([polEmptyQ])])); }) === "smime/bad-policy-information");
  // a PolicyQualifierInfo that is not a two-field, OID-led SEQUENCE -> rejected
  var polBadPqi = b.sequence([b.oid(O("anyPolicy")), b.sequence([b.sequence([b.integer(1n)])])]);
  check("10c. malformed PolicyQualifierInfo rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essNoIs]), b.sequence([polBadPqi])])); }) === "smime/bad-policy-information");
}

// ---- ACCEPT: SigningCertificateV2 (ESS v2) ---------------------------
function testSigningCertificateV2() {
  // hashAlgorithm DEFAULT (absent) -> id-sha256, defaulted:true
  var essDef = b.sequence([b.octetString(Buffer.alloc(32, 2))]);
  var scDef = pki.schema.smime.parseSigningCertificateV2(b.sequence([b.sequence([essDef])]));
  check("11. v2 hashAlgorithm defaults to sha256", scDef.certs[0].hashAlgorithm.name === "sha256" && scDef.certs[0].hashAlgorithm.defaulted === true && scDef.certs[0].hashAlgorithm.oid === O("sha256"));

  // hashAlgorithm present, non-default (sha384) -> decoded, defaulted:false
  var essExp = b.sequence([algId("sha384"), b.octetString(Buffer.alloc(48, 3))]);
  var scExp = smime.parseSigningCertificateV2(b.sequence([b.sequence([essExp])]));
  check("12. v2 explicit non-default hashAlgorithm decoded", scExp.certs[0].hashAlgorithm.name === "sha384" && scExp.certs[0].hashAlgorithm.defaulted === false);

  // full v2 with issuerSerial
  var essFull = b.sequence([algId("sha512"), b.octetString(Buffer.alloc(64, 4)), issuerSerial("ca2.example", 7)]);
  var scFull = smime.parseSigningCertificateV2(b.sequence([b.sequence([essFull])]));
  check("13. v2 full ESSCertIDv2 (hashAlg + certHash + issuerSerial)", scFull.certs[0].hashAlgorithm.name === "sha512" && scFull.certs[0].issuerSerial.serialNumber === 7n);

  // The fourth pivot combination: hashAlgorithm DEFAULTED (absent) with
  // issuerSerial PRESENT — the two same-tag optionals sit on opposite sides of
  // the mandatory certHash OCTET STRING, so this is the shape where a greedy
  // leading-optional recognizer would misparse the trailing SEQUENCE.
  var essDefIs = b.sequence([b.octetString(Buffer.alloc(32, 7)), issuerSerial("ca3.example", 5)]);
  var scDefIs = smime.parseSigningCertificateV2(b.sequence([b.sequence([essDefIs])]));
  check("13b. v2 defaulted hashAlgorithm + present issuerSerial", scDefIs.certs[0].hashAlgorithm.defaulted === true && scDefIs.certs[0].issuerSerial.serialNumber === 5n);

  // present-and-byte-equal-to-default (explicit sha256, params absent) -> reject (X.690 §11.5)
  var essNc = b.sequence([algId("sha256"), b.octetString(Buffer.alloc(32, 5))]);
  check("14. v2 explicit hashAlgorithm equal to DEFAULT rejected", code(function () { smime.parseSigningCertificateV2(b.sequence([b.sequence([essNc])])); }) === "smime/non-canonical-default");

  // present sha256 WITH a redundant NULL params is NOT byte-equal to the params-absent default -> decodes
  var essSha256Null = b.sequence([b.sequence([b.oid(O("sha256")), b.nullValue()]), b.octetString(Buffer.alloc(32, 6))]);
  var scNull = smime.parseSigningCertificateV2(b.sequence([b.sequence([essSha256Null])]));
  check("15. v2 explicit sha256 with NULL params is a legal explicit encoding", scNull.certs[0].hashAlgorithm.name === "sha256" && scNull.certs[0].hashAlgorithm.defaulted === false && scNull.certs[0].hashAlgorithm.parameters !== null);
}

// ---- ACCEPT: SMIMECapabilities ---------------------------------------
function testSmimeCapabilities() {
  var caps = pki.schema.smime.parseSmimeCapabilities(b.sequence([
    b.sequence([b.oid(O("aes256-CBC"))]),
    b.sequence([b.oid(O("aes128-CBC")), b.integer(128n)]),
  ]));
  check("16. capabilities ordered (preference order preserved)", caps.capabilities.length === 2 && caps.capabilities[0].name === "aes256-CBC" && caps.capabilities[1].name === "aes128-CBC");
  check("17. capability parameters surfaced raw", caps.capabilities[0].parameters === null && Buffer.isBuffer(caps.capabilities[1].parameters));
  // empty capabilities list is legal
  var empty = smime.parseSmimeCapabilities(b.sequence([]));
  check("18. empty capabilities list legal", empty.capabilities.length === 0);
  // an unknown capability OID surfaces with a null name, not rejected
  var unk = smime.parseSmimeCapabilities(b.sequence([b.sequence([b.oid("1.2.3.4.5")])]));
  check("19. unknown capability OID surfaced (null name)", unk.capabilities[0].capabilityID === "1.2.3.4.5" && unk.capabilities[0].name === null);
}

// ---- decodeAttribute dispatch ----------------------------------------
function testDecodeAttribute() {
  // full attribute values: SigningCertificate(V2) -> certs -> ESSCertID -> certHash
  var essDef = b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(32, 2))])])]);
  var essV1 = b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(20, 1))])])]);
  var caps = b.sequence([b.sequence([b.oid(O("aes256-CBC"))])]);   // SMIMECapabilities -> SMIMECapability -> capabilityID

  check("20. dispatch signingCertificate", pki.schema.smime.decodeAttribute({ type: O("signingCertificate"), values: [essV1] }).kind === "signingCertificate");
  check("21. dispatch signingCertificateV2", smime.decodeAttribute({ type: O("signingCertificateV2"), values: [essDef] }).kind === "signingCertificateV2");
  check("22. dispatch smimeCapabilities", smime.decodeAttribute({ type: O("smimeCapabilities"), values: [caps] }).kind === "smimeCapabilities");

  // single-AttributeValue MUST (RFC 8551 §2.5.2): 0 or >=2 rejected
  check("23. zero values rejected", code(function () { smime.decodeAttribute({ type: O("smimeCapabilities"), values: [] }); }) === "smime/multi-valued-attribute");
  check("24. two values rejected", code(function () { smime.decodeAttribute({ type: O("signingCertificateV2"), values: [essDef, essDef] }); }) === "smime/multi-valued-attribute");

  // unknown attribute type -> recognize-and-defer with payload
  var unkErr;
  try { smime.decodeAttribute({ type: O("contentType"), values: [b.oid("1.2.3")] }); } catch (e) { unkErr = e; }
  check("25. unknown attribute -> smime/unsupported-attribute", unkErr && unkErr.code === "smime/unsupported-attribute");
  check("26. unsupported payload carries type/name/raw values", unkErr && unkErr.type === O("contentType") && unkErr.name === "contentType" && Array.isArray(unkErr.values));
  // a registered-but-not-decoded ESS attribute (timeStampToken) -> unsupported with its name
  var tsErr;
  try { smime.decodeAttribute({ type: O("timeStampToken"), values: [b.oid("1.2.3")] }); } catch (e) { tsErr = e; }
  check("27. registered-but-deferred attribute names itself", tsErr && tsErr.code === "smime/unsupported-attribute" && tsErr.name === "timeStampToken");
  // the single-value rule is specific to the KNOWN ESS / capabilities attributes:
  // an unknown / custom attribute with two values recognize-and-defers, not multi-valued.
  check("27b. unknown attribute with 2 values -> unsupported, not multi-valued", code(function () { smime.decodeAttribute({ type: O("contentType"), values: [b.oid("1.2.3"), b.oid("1.2.4")] }); }) === "smime/unsupported-attribute");

  // bad attribute shape -> smime/bad-input
  check("28. non-object attr rejected", code(function () { smime.decodeAttribute(42); }) === "smime/bad-input");
  check("29. non-array values rejected", code(function () { smime.decodeAttribute({ type: O("smimeCapabilities"), values: "x" }); }) === "smime/bad-input");
}

// ---- REJECT: structural / DER ----------------------------------------
function testReject() {
  // empty certs (SEQUENCE OF ESSCertID, min 1) -> smime/bad-certs
  check("30. empty certs rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([])])); }) === "smime/bad-certs");
  check("31. v2 empty certs rejected", code(function () { smime.parseSigningCertificateV2(b.sequence([b.sequence([])])); }) === "smime/bad-certs");
  // empty issuer GeneralNames (SIZE 1..MAX) -> smime/bad-general-names
  var essEmptyGn = b.sequence([b.octetString(Buffer.alloc(20, 1)), b.sequence([b.sequence([]), b.integer(1n)])]);
  check("32. empty issuer GeneralNames rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essEmptyGn])])); }) === "smime/bad-general-names");
  // malformed GeneralName arm (tag > 8) -> smime/bad-general-names
  var essBadGn = b.sequence([b.octetString(Buffer.alloc(20, 1)), b.sequence([b.sequence([b.contextPrimitive(9, Buffer.from([1]))]), b.integer(1n)])]);
  check("33. malformed GeneralName arm rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essBadGn])])); }) === "smime/bad-general-names");
  // RFC 5035 §5: a well-formed but non-directoryName issuer (e.g. dNSName) parses
  // as a GeneralName yet fails the ESS profile -> smime/bad-issuer-serial.
  var essDnsIssuer = b.sequence([b.octetString(Buffer.alloc(20, 1)), b.sequence([b.sequence([gnDns("ca.example")]), b.integer(1n)])]);
  check("33b. non-directoryName issuer rejected (RFC 5035 §5)", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essDnsIssuer])])); }) === "smime/bad-issuer-serial");
  // two directoryNames (SIZE>1) also fails the single-name ESS rule
  var essTwoDir = b.sequence([b.octetString(Buffer.alloc(20, 1)), b.sequence([b.sequence([gnDir("a"), gnDir("b")]), b.integer(1n)])]);
  check("33c. multi-name issuer rejected (RFC 5035 §5)", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essTwoDir])])); }) === "smime/bad-issuer-serial");
  // certHash not an OCTET STRING -> typed reject
  var essBadHash = b.sequence([b.integer(1n)]);
  check("34. certHash wrong type rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essBadHash])])); }).indexOf("smime/") === 0 || code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([essBadHash])])); }).indexOf("asn1/") === 0);
  // not a SEQUENCE at the top -> smime/bad-signing-certificate
  check("35. top not a SEQUENCE rejected", code(function () { smime.parseSigningCertificate(b.oid("1.2.3")); }) === "smime/bad-signing-certificate");
  // trailing bytes after the top TLV -> smime/bad-der
  var good = b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(20, 1))])])]);
  check("36. trailing bytes rejected", code(function () { smime.parseSigningCertificate(Buffer.concat([good, Buffer.from([0x00])])); }) === "smime/bad-der");
  // non-buffer input -> smime/bad-input
  check("37. non-buffer input rejected", code(function () { smime.parseSigningCertificate(42); }) === "smime/bad-input");
  // extra trailing child beyond the schema (SigningCertificate has 2 fields) -> reject
  check("38. extra trailing field rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(20, 1))])]), b.sequence([]), b.integer(9n)])); }).indexOf("smime/") === 0);
  // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber } — a SEQUENCE
  // of exactly two members (RFC 5035 Appendix A); both arity edges reject, on the
  // v1 path and (shared schema) the v2 path.
  var isThree = b.sequence([b.sequence([gnDir("ca")]), b.integer(1n), b.integer(2n)]);
  check("38b. IssuerSerial with a third element rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(20, 1)), isThree])])])); }) === "smime/bad-issuer-serial");
  var isOne = b.sequence([b.sequence([gnDir("ca")])]);
  check("38c. IssuerSerial missing serialNumber rejected", code(function () { smime.parseSigningCertificate(b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(20, 1)), isOne])])])); }) === "smime/bad-issuer-serial");
  check("38d. v2 IssuerSerial arity enforced via the shared schema", code(function () { smime.parseSigningCertificateV2(b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(32, 1)), isThree])])])); }) === "smime/bad-issuer-serial");
}

// ---- orchestrator exclusion: smime is NOT a schema.parse format ------
function testNotAFormat() {
  check("39. pki.schema.all() does not contain smime", pki.schema.all().indexOf("smime") === -1);
  // a SigningCertificate DER (a bare SEQUENCE) is not auto-routed by schema.parse
  var av = b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(20, 1))])])]);
  var routed = code(function () { pki.schema.parse(av); });
  check("40. schema.parse does not auto-route an ESS attribute value", routed !== "NO-THROW");
}

function run() {
  testSigningCertificate();
  testSigningCertificateV2();
  testSmimeCapabilities();
  testDecodeAttribute();
  testReject();
  testNotAFormat();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
