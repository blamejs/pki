// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.schema.c509.parse: C509 CBOR-encoded certificates (draft-ietf-cose-cbor-encoded-cert-20).
 * A C509Certificate is a deterministic-CBOR array of exactly 11 elements (10 TBS fields + the issuer
 * signature). Two modes: c509CertificateType 2 = natively-signed C509, 3 = a CBOR re-encoding of a DER
 * X.509 v3 certificate that MUST invert byte-for-byte to the original DER (so the original signature
 * verifies). Composes the shipped pki.cbor codec (core-deterministic, fail-closed) + the x509 model; it
 * decodes CBOR, not DER, so it is reached by explicit call, never auto-routed by pki.schema.parse. The
 * authoritative gate is the Appendix A.1 byte-exact KAT (both modes + the DER round-trip).
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var V = require("../helpers/c509-vectors");
var c509mod = require("../../lib/schema-c509");
var signing = require("../helpers/signing");

async function run() {
  // ==== A.1.1 -- the type-3 (CBOR re-encoded X.509) certificate decodes to the documented fields ====
  var c3 = pki.schema.c509.parse(V.A1.type3);
  check("1. type-3 A.1 decodes: certificateType 3", c3.certificateType === 3);
  check("2. serialNumberHex 01f50d (bare ~biguint)", c3.serialNumberHex === V.A1.serialHex);
  check("3. signatureAlgorithm resolves to ecdsaWithSHA256 (int 0)", c3.signatureAlgorithm.name === "ecdsaWithSHA256");
  check("4. issuer renders CN=RFC test CA", c3.issuer.dn === V.A1.issuerDn);
  check("5. validity notBefore/notAfter are the 2023/2026 Dates (bare ~time uints)", c3.validity.notBefore.getTime() === V.A1.notBefore.getTime() && c3.validity.notAfter.getTime() === V.A1.notAfter.getTime());
  check("6. subject is the tag-48 EUI-64 0123456789AB", Buffer.isBuffer(c3.subject.eui64) && c3.subject.eui64.equals(V.A1.subjectEui64));
  check("7. subjectPublicKeyAlgorithm resolves (int 1 = EC secp256r1)", /ec|prime256|secp256/i.test(c3.subjectPublicKeyAlgorithm.name || ""));
  check("8. one non-critical keyUsage(digitalSignature) extension from the int shortcut", c3.extensions.length === 1 && c3.extensions[0].name === "keyUsage" && c3.extensions[0].critical === false);
  check("9. issuerSignatureValue is the raw 64-byte r||s", Buffer.isBuffer(c3.signatureValue) && c3.signatureValue.length === V.A1.sigLen);

  // ==== the type-3 DER INVERTIBILITY: reconstruct the original DER byte-for-byte ====
  check("10. the reconstructed DER equals the original A.1 DER byte-for-byte (invertible)", Buffer.isBuffer(c3.reconstructedDer) && c3.reconstructedDer.equals(V.A1.der));
  check("11. x509.parse(reconstructed) matches x509.parse(original) -- serial + issuer + validity", (function () {
    var a = pki.schema.x509.parse(c3.reconstructedDer), o = pki.schema.x509.parse(V.A1.der);
    return a.serialNumberHex === o.serialNumberHex && a.issuer.dn === o.issuer.dn && a.validity.notAfter.getTime() === o.validity.notAfter.getTime();
  })());

  // ==== A.1.2 -- the type-2 natively-signed form ====
  var c2 = pki.schema.c509.parse(V.A1.type2);
  check("12. type-2 A.1 decodes: certificateType 2", c2.certificateType === 2);
  check("13. signedData is the raw byte range of TBS elements 0..9 (raw-exactness, not a re-encode)", Buffer.isBuffer(c2.signedData) && c2.signedData.length > 0 && V.A1.type2.indexOf(c2.signedData) === 1);
  check("14. type-2 subjectPublicKey keeps its SEC1 0x02/0x03/0x04 point form (not 0xFE/0xFD)", c2.subjectPublicKey[0] === 0x02 || c2.subjectPublicKey[0] === 0x03 || c2.subjectPublicKey[0] === 0x04);

  // ==== mode discrimination + structural fail-closed ====
  check("15. certificateType 0 -> c509/bad-certificate-type", code2(V.A1.type3, 1, 0x00) === "c509/bad-certificate-type");
  check("16. certificateType 4 -> c509/bad-certificate-type", code2(V.A1.type3, 1, 0x04) === "c509/bad-certificate-type");
  check("17. a non-array root (a CBOR map) -> c509/not-a-certificate", codeSync(function () { return pki.schema.c509.parse(Buffer.from([0xA0])); }) === "c509/not-a-certificate");
  check("18. an array of length != 11 -> c509/not-a-certificate or c509/bad-tbs", /^c509\/(not-a-certificate|bad-tbs)$/.test(codeSync(function () { return pki.schema.c509.parse(Buffer.from([0x82, 0x03, 0x00])); })));

  // ==== the deterministic-CBOR gate is inherited ====
  check("19. trailing bytes after the array -> a cbor/* or c509/* fault (deterministic gate)", /^(cbor|c509)\//.test(codeSync(function () { return pki.schema.c509.parse(Buffer.concat([V.A1.type3, Buffer.from([0x00])])); })));

  // ==== the DER orchestrator does NOT route to c509 (CBOR, not DER) ====
  check("20. pki.schema.parse(c509Bytes) does not route to c509 (non-DER)", /^(asn1|schema)\//.test(codeSync(function () { return pki.schema.parse(V.A1.type3); })));

  // ==== field-encoding reject vectors (fail-closed, typed) ====
  check("21. non-minimal serial (leading 0x00) -> c509/non-minimal-serial", codeSync(function () { return pki.schema.c509.parse(V.mk({ 1: "4300f50d" })); }) === "c509/non-minimal-serial");
  check("22. serial not a byte string -> c509/bad-serial", codeSync(function () { return pki.schema.c509.parse(V.mk({ 1: "1a0001f50d" })); }) === "c509/bad-serial");
  check("23. notBefore a negative (major-type-1) ~time -> c509/bad-validity", codeSync(function () { return pki.schema.c509.parse(V.mk({ 4: "3a63b0cd00" })); }) === "c509/bad-validity");
  check("24. an unknown signatureAlgorithm int -> c509/unknown-algorithm", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "18ff" })); }) === "c509/unknown-algorithm");
  check("25. an unknown subjectPublicKeyAlgorithm int -> c509/unknown-algorithm", codeSync(function () { return pki.schema.c509.parse(V.mk({ 7: "18ff" })); }) === "c509/unknown-algorithm");
  check("26. an EC subjectPublicKey that is not a byte string -> c509/bad-spki", codeSync(function () { return pki.schema.c509.parse(V.mk({ 8: "01" })); }) === "c509/bad-spki");
  check("27. a signatureValue that is not a byte string -> c509/bad-signature", codeSync(function () { return pki.schema.c509.parse(V.mk({ 10: "01" })); }) === "c509/bad-signature");
  check("28. an unresolved attribute type int -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 3: "82187b6141" })); }) === "c509/bad-name");

  // ==== name variants ====
  // null issuer (self-signed): issuer decodes to null and reconstructs as issuer == subject.
  var selfSigned = pki.schema.c509.parse(V.mk({ 3: "f6" }));
  check("29. null issuer decodes to null (self-signed)", selfSigned.issuer === null);
  check("30. self-signed reconstruction: issuer DN == subject DN", (function () { var x = pki.schema.x509.parse(selfSigned.reconstructedDer); return x.issuer.dn === x.subject.dn; })());
  // a negative attribute int -> a PrintableString value; a multi-attribute RDNSequence.
  var printable = pki.schema.c509.parse(V.mk({ 3: "82206141" }));   // [-1 (printable commonName), "A"]
  check("31. a negative attribute int -> a printableString reconstruction", (function () { var x = pki.schema.x509.parse(printable.reconstructedDer); return x.issuer.dn === "CN=A"; })());
  var multi = pki.schema.c509.parse(V.mk({ 3: "8401614108614f" }));  // [1,"A", 8,"O"]
  check("32. a multi-attribute issuer decodes both RDNs", multi.issuer.rdns.length === 2 && multi.issuer.rdns[1].type === "organizationName");

  // ==== algorithm variants (int / ~oid / [~oid, params]) ====
  // a ~oid signatureAlgorithm (bare OID content) resolves to the SAME name and reconstructs byte-exact.
  var oidAlg = pki.schema.c509.parse(V.mk({ 2: "482a8648ce3d040302" }));
  check("33. a ~oid signatureAlgorithm resolves + round-trips byte-exact", oidAlg.signatureAlgorithm.name === "ecdsaWithSHA256" && oidAlg.reconstructedDer.equals(V.A1.der));
  // an [~oid, params] algorithm array form decodes with surfaced parameters.
  var arrAlg = pki.schema.c509.parse(V.mk({ 2: "82482a8648ce3d04030240" }));
  check("34. an [~oid, params] algorithm array form decodes", arrAlg.signatureAlgorithm.name === "ecdsaWithSHA256");

  // ==== no-expiry validity (notAfter == null) ====
  var noExpiry = pki.schema.c509.parse(V.mk({ 5: "f6" }));
  check("35. notAfter == null decodes to null (no expiry)", noExpiry.validity.notAfter === null);
  check("36. no-expiry reconstruction uses the 99991231235959Z sentinel", pki.schema.x509.parse(noExpiry.reconstructedDer).validity.notAfter.getUTCFullYear() === 9999);

  // ==== RSA subjectPublicKey (rsaEncryption; the modulus-only exponent-65537 short form) ====
  var rsaMod = "50c0000000000000000000000000000001";   // byte string(16) modulus, high bit set (~biguint)
  var rsa = pki.schema.c509.parse(V.mk({ 7: "00", 8: rsaMod }));
  check("37. RSA modulus-only decodes with the implied exponent 65537", rsa.rsaPublicKey.exponent === 65537n && rsa.rsaPublicKey.modulus > 0n);
  check("38. RSA reconstruction produces a parseable rsaEncryption SPKI", pki.schema.x509.parse(rsa.reconstructedDer).subjectPublicKeyInfo.algorithm.name === "rsaEncryption");
  // the explicit [modulus, exponent] array form.
  var rsaArr = pki.schema.c509.parse(V.mk({ 7: "00", 8: "82" + rsaMod + "4303ffff" }));   // [modulus, exp 0x03ffff]
  check("39. RSA [modulus, exponent] array form decodes the explicit exponent", rsaArr.rsaPublicKey.exponent === 0x03ffffn);

  // ==== the matches() structural probe ====
  check("40. matches() accepts a c509 array, rejects a non-c509 shape", c509mod.matches(pki.cbor.decode(V.A1.type3)) === true && c509mod.matches(pki.cbor.decode(Buffer.from([0x82, 0x03, 0x00]))) === false);

  // ==== remaining structural rejects + the array-form extension paths ====
  check("41. an algorithm that is not int / ~oid / array -> c509/unknown-algorithm", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "f5" })); }) === "c509/unknown-algorithm");
  check("42. an attribute value that is not a SpecialText -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 3: "8201f5" })); }) === "c509/bad-name");
  check("43. an extensions field that is neither an array nor a keyUsage int -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "6141" })); }) === "c509/bad-extensions");
  // array-form extensions (int extensionID and ~oid extensionID) round-trip to the same keyUsage DER.
  check("44. an array-form int-id extension round-trips byte-exact", pki.schema.c509.parse(V.mk({ 9: "82024403020780" })).reconstructedDer.equals(V.A1.der));
  check("45. an array-form ~oid-id extension round-trips byte-exact", pki.schema.c509.parse(V.mk({ 9: "8243551d0f4403020780" })).reconstructedDer.equals(V.A1.der));
  // a subjectPublicKey algorithm outside the reconstruction covered set (Ed25519 via ~oid) fails closed.
  check("46. an unsupported subjectPublicKey algorithm (type-3) -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 7: "432b6570" })); }) === "c509/non-invertible");
  // a ~time beyond the ECMAScript Date window -> c509/bad-validity.
  check("47. a ~time outside the representable Date range -> c509/bad-validity", codeSync(function () { return pki.schema.c509.parse(V.mk({ 4: "1b0001000000000000" })); }) === "c509/bad-validity");
  // the keyUsage int-shortcut with a NEGATIVE int -> a CRITICAL keyUsage extension.
  var critKu = pki.schema.c509.parse(V.mk({ 9: "20" }));   // nint -1 -> critical keyUsage
  check("48. a negative keyUsage int-shortcut decodes as critical", critKu.extensions[0].critical === true && pki.schema.x509.parse(critKu.reconstructedDer).issuer.dn === "CN=RFC test CA");
  // a critical ~oid extension ([ bytes ] wrap) extracts the inner byte string as the value.
  var critOid = pki.schema.c509.parse(V.mk({ 9: "8243551d0f814403020780" }));
  check("49. a critical ~oid extension ([bytes] wrap) decodes critical with the inner value", critOid.extensions[0].critical === true && critOid.extensions[0].value.toString("hex") === "03020780");
  // an array int extension whose value is not a byte string cannot invert -> c509/non-invertible.
  check("50. an extension with a non-reconstructable value -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820418ff" })); }) === "c509/non-invertible");
  // a countryName attribute reconstructs as a PrintableString.
  var country = pki.schema.c509.parse(V.mk({ 3: "8204625553" }));   // [4 (countryName), "US"]
  check("51. a countryName attribute reconstructs as PrintableString", pki.schema.x509.parse(country.reconstructedDer).issuer.dn === "C=US");
  // a validity instant in 2050+ reconstructs as GeneralizedTime (RFC 5280 sec. 4.1.2.5).
  var future = pki.schema.c509.parse(V.mk({ 4: "1a967e7f80" }));   // notBefore 2050-01-01
  check("52. a >= 2050 validity instant reconstructs as GeneralizedTime", pki.schema.x509.parse(future.reconstructedDer).validity.notBefore.getUTCFullYear() === 2050);
  // an EC subjectPublicKey already uncompressed (0x04) is kept and round-trips byte-exact.
  var uncompressed = "5841" + "04b1216ab96e5b3b3340f5bdf02e693f16213a04525ed44450b1019c2dfd3838abac4e14d86c0983ed5e9eef2448c6861cc406547177e6026030d051f7792ac206";
  check("53. an uncompressed EC point (0x04) is kept and round-trips byte-exact", pki.schema.c509.parse(V.mk({ 8: uncompressed })).reconstructedDer.equals(V.A1.der));
  // an unrecognized EC point encoding (head 0x05) fails closed.
  check("54. an unrecognized EC point encoding -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 8: "582105" + "00".repeat(32) })); }) === "c509/non-invertible");
  // a keyUsage shortcut of 0 (no bits set) cannot invert.
  check("55. a keyUsage shortcut with no bits set -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "00" })); }) === "c509/non-invertible");
  // an RSA subjectPublicKey that is neither a ~biguint nor [modulus, exponent] fails closed.
  check("56. a malformed RSA subjectPublicKey -> c509/bad-spki", codeSync(function () { return pki.schema.c509.parse(V.mk({ 7: "00", 8: "01" })); }) === "c509/bad-spki");
  // an 8-byte tag-48 MAC (EUI-64 directly, no FF-FE insertion) decodes.
  var mac8 = pki.schema.c509.parse(V.mk({ 6: "d830" + "48" + "0123456789abcdef" }));   // tag(48) byte-string(8)
  check("57. an 8-byte tag-48 MAC decodes to a full EUI-64", pki.schema.x509.parse(mac8.reconstructedDer).subject.dn === "CN=01-23-45-67-89-AB-CD-EF");
  // a bare byte-string SpecialText (even-length-hex commonName optimization).
  var hexCn = pki.schema.c509.parse(V.mk({ 3: "42abcd" }));   // byte string "abcd" as a single commonName
  check("58. a bare byte-string commonName decodes via the hex optimization", hexCn.issuer.dn === "CN=abcd");
  // a Name that is neither null, a SpecialText, nor an array fails closed.
  check("59. a Name that is not null / SpecialText / array -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 3: "01" })); }) === "c509/bad-name");
  // an array extension with an unregistered int type fails closed.
  check("60. an array extension with an unregistered int type -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8218ff00" })); }) === "c509/bad-extensions");
  // a 0xFD-marked (was-odd-y) EC point de-compresses to a valid uncompressed point.
  var oddY = pki.schema.c509.parse(V.mk({ 8: "5821fd" + "b1216ab96e5b3b3340f5bdf02e693f16213a04525ed44450b1019c2dfd3838ab" }));
  check("59b. a 0xFD (was-odd-y) EC point de-compresses to a valid EC key", pki.schema.x509.parse(oddY.reconstructedDer).subjectPublicKeyInfo.algorithm.name === "ecPublicKey");
  // a ~oid algorithm for an OID not in the name registry surfaces the dotted string (the OID is explicit).
  // Driven on a type-2 (natively-signed) certificate so the non-ECDSA algorithm is not reconstructed.
  var unkOid = pki.schema.c509.parse(V.mk({ 0: "02", 2: "442b060102" }));   // type 2, ~oid 1.3.6.1.2 (unregistered)
  check("60b. an unregistered ~oid algorithm surfaces its dotted string", unkOid.signatureAlgorithm.name === "1.3.6.1.2");
  // Coverage residual (verified trivial): the remaining uncovered branches in schema-c509.js are
  // defensive `node.children || []` guards (a decoded CBOR array always has children), the cosmetic
  // _shortName OU/L/ST display fallbacks, the empty-tag-48 Buffer.alloc(0) guard, and the matches()
  // negative-int probe side -- none reachable through pki.schema.c509.parse without breaking a decoder
  // invariant, so they are left uncovered rather than forced with an assertionless test.

  // ==== conformance fixes: dangling pairs, algorithm parameters, empty-extensions wrapper ====
  // a Name array with an odd length (a dangling attribute type) fails closed.
  check("61. a Name array with a dangling attribute type -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 3: "8101" })); }) === "c509/bad-name");
  // an extensions array with an odd length (a dangling extension identifier) fails closed.
  check("62. an extensions array with a dangling identifier -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8102" })); }) === "c509/bad-extensions");
  // a [~oid, params] algorithm's parameters are PRESERVED in the reconstruction (not silently dropped).
  var withParams = pki.schema.c509.parse(V.mk({ 2: "82482a8648ce3d040302420500" }));   // [~oid ecdsa, NULL]
  check("63. a [~oid, params] algorithm preserves its parameters in the DER", withParams.reconstructedDer.toString("hex").indexOf("300c06082a8648ce3d0403020500") !== -1);
  // an empty C509 extensions array reconstructs to an OMITTED [3] field, not an empty SEQUENCE (RFC 5280).
  var emptyExt = pki.schema.c509.parse(V.mk({ 9: "80" }));
  check("64. empty extensions omit the [3] wrapper (no empty-SEQUENCE extensions)", (function () {
    var x = pki.schema.x509.parse(emptyExt.reconstructedDer);
    return (!x.extensions || x.extensions.length === 0) && emptyExt.reconstructedDer.toString("hex").indexOf("a3023000") === -1;
  })());

  // ==== conformance fixes round 2: signature algorithm + parameter/value type strictness ====
  // a type-3 certificate with a non-ECDSA signature algorithm cannot have its r||s re-wrapped.
  check("65. a non-ECDSA type-3 signature algorithm -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "432b6570" })); }) === "c509/non-invertible");
  // a malformed (odd-length) ECDSA signature is a typed C509 error, never a raw TypeError.
  check("66. an odd-length type-3 signature -> c509/bad-signature", codeSync(function () { return pki.schema.c509.parse(V.mk({ 10: "43010203" })); }) === "c509/bad-signature");
  // a [~oid, params] algorithm whose parameters are not a byte string fails closed.
  check("67. non-byte-string algorithm parameters -> c509/unknown-algorithm", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "82482a8648ce3d04030201" })); }) === "c509/unknown-algorithm");
  // a tag-48 MAC-address value that does not wrap a byte string fails closed.
  check("68. a tag-48 value not wrapping a byte string -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: "d83001" })); }) === "c509/bad-name");

  // ==== conformance fixes round 3: parameter DER validity + ECDSA signature width ====
  // supplied algorithm parameters that are not a single well-formed DER element fail closed.
  check("69. malformed algorithm parameters (trailing bytes) -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "82482a8648ce3d040302430500ff" })); }) === "c509/non-invertible");
  // an ECDSA signature whose width is not 2x a supported curve field size fails closed.
  check("70. a non-curve-width ECDSA signature -> c509/bad-signature", codeSync(function () { return pki.schema.c509.parse(V.mk({ 10: "583e" + "00".repeat(62) })); }) === "c509/bad-signature");
  // an EC point whose length does not match its curve field size fails closed.
  check("71. an EC point with a wrong length for its curve -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 8: "5820fe" + "00".repeat(31) })); }) === "c509/non-invertible");
  // a ~oid ecPublicKey algorithm carries no curve (the int form does), so it cannot be reconstructed.
  check("72. a ~oid ecPublicKey without a curve -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 7: "472a8648ce3d0201" })); }) === "c509/non-invertible");
  // a SEC1 0x02/0x03 compressed point of the wrong length fails closed.
  check("73. a wrong-length compressed (0x02) EC point -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 8: "582002" + "00".repeat(31) })); }) === "c509/non-invertible");
  // a correct-length SEC1 0x02 compressed point (type-3) is kept compressed in the reconstruction.
  var compressed = pki.schema.c509.parse(V.mk({ 8: "582102" + "b1216ab96e5b3b3340f5bdf02e693f16213a04525ed44450b1019c2dfd3838ab" }));
  check("74. a correct-length compressed EC point is kept in the reconstruction", pki.schema.x509.parse(compressed.reconstructedDer).subjectPublicKeyInfo.algorithm.name === "ecPublicKey");

  // ==== conformance fixes round 4: degenerate-value rejects (keyUsage, empty/oversized key material) ====
  // a keyUsage value beyond the 9 defined bits fails closed (also guards the 32-bit bitwise re-encoding).
  check("75. an out-of-range keyUsage value -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "190200" })); }) === "c509/non-invertible");
  // an empty EC subjectPublicKey byte string fails closed (never a raw read past the empty buffer).
  check("76. an empty EC subjectPublicKey -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 8: "40" })); }) === "c509/non-invertible");
  // a tag-48 MAC address that is not 6 or 8 bytes fails closed.
  check("77. a tag-48 MAC of an invalid length -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: "d830450102030405" })); }) === "c509/bad-name");
  // a zero RSA modulus fails closed.
  check("78. a zero RSA modulus -> c509/bad-spki", codeSync(function () { return pki.schema.c509.parse(V.mk({ 7: "00", 8: "40" })); }) === "c509/bad-spki");

  // ==== conformance fixes round 5: ~oid extension value shape ====
  // a non-critical ~oid extension whose value is not a byte string fails closed.
  check("79. a non-critical ~oid extension value that is not a byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8243551d0f01" })); }) === "c509/bad-extensions");
  // a critical ~oid extension whose [bytes] wrap does not hold a byte string fails closed.
  check("80. a critical ~oid extension not wrapping a byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8243551d0f8101" })); }) === "c509/bad-extensions");

  // ==== encode: the producing side (pki.schema.c509.encode, the byte-exact inverse of parse) ====
  // AUTHORITATIVE KAT: the forward transform of the Appendix A.1 DER yields the draft canonical type-3
  // (the MAC-address commonName compressed to a tag-48 EUI-48, the lone keyUsage as the int shortcut).
  check("81. encode(A.1 DER) == the draft type-3 C509 byte-for-byte", pki.schema.c509.encode(V.A1.der).equals(V.A1.type3));
  // re-emit: a parsed result re-encodes to identical bytes (both certificate types).
  check("82. encode(parse(type-3)) round-trips byte-exact", pki.schema.c509.encode(pki.schema.c509.parse(V.A1.type3)).equals(V.A1.type3));
  check("83. encode(parse(type-2)) round-trips byte-exact", pki.schema.c509.encode(pki.schema.c509.parse(V.A1.type2)).equals(V.A1.type2));
  // a NATIVE (type-2) certificate is signed over its raw CBOR fields, so re-emit preserves them VERBATIM:
  // a byte-string attribute value (which a re-derive would lossily render as text, invalidating the
  // signature) round-trips byte-for-byte.
  var t2bs = V.mk({ 0: "02", 6: "4401020304" });   // type-2, subject = a byte-string commonName
  check("83b. type-2 re-emit preserves a byte-string field verbatim", pki.schema.c509.encode(pki.schema.c509.parse(t2bs)).equals(t2bs));
  // a type-3 result re-emits its raw fields VERBATIM too -- a re-derivation of a byte-string attribute
  // (rendered as text) would change the reconstructed DER; the verbatim path keeps it byte-exact.
  var t3bs = V.mk({ 6: "4401020304" });   // type-3, subject = a byte-string commonName
  check("83c. type-3 re-emit preserves a byte-string field verbatim", pki.schema.c509.encode(pki.schema.c509.parse(t3bs)).equals(t3bs));
  // a Uint8Array parse input (not a Buffer) preserves the raw fields correctly (the field bytes come from
  // the decoded root, not offset arithmetic on the caller's input buffer).
  check("83d. Uint8Array parse input re-emits byte-exact", pki.schema.c509.encode(pki.schema.c509.parse(new Uint8Array(V.A1.type3))).equals(V.A1.type3));
  // the verbatim re-emit is not a blind byte copy: a caller who mutates the preserved raw fields to a
  // malformed shape gets a fail-closed verdict, not garbage. A tampered certificate-type octet re-parses
  // as an invalid type; a non-Buffer signatureValue is rejected at entry.
  var prMut = pki.schema.c509.parse(V.A1.type3); prMut._fieldBytes = Buffer.concat([Buffer.from([0x05]), prMut._fieldBytes.subarray(1)]);
  check("83e. a mutated re-emit field set fails closed (typed c509/*)", /^c509\//.test(codeSync(function () { return pki.schema.c509.encode(prMut); })));
  var prSig = pki.schema.c509.parse(V.A1.type3); prSig.signatureValue = "not-a-buffer";
  check("83f. a non-Buffer signatureValue re-emit -> c509/bad-input", codeSync(function () { return pki.schema.c509.encode(prSig); }) === "c509/bad-input");
  // the emission is canonical deterministic CBOR by construction (parse re-decodes it).
  check("84. encode output re-parses to the same certificate", pki.schema.c509.parse(pki.schema.c509.encode(V.A1.der)).certificateType === 3);
  // fail-closed on a non-cert input.
  check("85. encode of a non-cert non-result -> c509/bad-input", codeSync(function () { return pki.schema.c509.encode(5); }) === "c509/bad-input");
  check("86. encode of garbage DER -> a typed c509/*", /^c509\//.test(codeSync(function () { return pki.schema.c509.encode(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])); })));

  // the flagship forward transform across the EC arms: a v3 DER cert -> a smaller type-3 that reconstructs
  // the source DER byte-for-byte (so the original signature still verifies).
  var arms = ["ec-p256", "ec-p384", "ec-p521"];
  for (var ai = 0; ai < arms.length; ai++) {
    var s = signing.makeSigner(arms[ai]);
    var der = await pki.x509.sign({ subject: [{ commonName: "dev" }, { countryName: "US" }], subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"], basicConstraints: { cA: false } } }, { key: s.key });
    var c = pki.schema.c509.encode(der);
    check("87." + ai + " " + arms[ai] + " type-3 reconstructs the source DER byte-exact + is smaller", pki.schema.c509.parse(c).reconstructedDer.equals(der) && c.length < der.length);
  }
  // cross-curve: a P-384 CA signing a P-256 subject -- the signature r||s width is the ISSUER's curve (P-384,
  // from ecdsaWithSHA384), NOT the subject's P-256 key; the reconstruction must still be byte-exact.
  var caP384 = signing.makeSigner("ec-p384"), subP256 = signing.makeSigner("ec-p256");
  var xder = await pki.x509.sign({ subject: [{ commonName: "leaf" }], subjectPublicKey: subP256.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { name: [{ commonName: "CA" }], publicKey: caP384.spki, key: caP384.key });
  check("88. cross-curve (P-384 CA, P-256 subject) type-3 reconstructs byte-exact", pki.schema.c509.parse(pki.schema.c509.encode(xder)).reconstructedDer.equals(xder));

  // fail-closed: type-3 is X.509 v3-only (a v1 cert), and v1 covers EC-only (an RSA cert).
  var v1s = signing.makeSigner("ec-p256");
  var v1der = await pki.x509.sign({ subject: [{ commonName: "v1" }], subjectPublicKey: v1s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") }, { key: v1s.key });
  check("90. a v1 cert (no extensions) -> c509/non-invertible (type-3 is v3-only)", codeSync(function () { return pki.schema.c509.encode(v1der); }) === "c509/non-invertible");
  var rsas = signing.makeSigner("rsa");
  var rsader = await pki.x509.sign({ subject: [{ commonName: "r" }], subjectPublicKey: rsas.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: rsas.key });
  check("91. an RSA cert -> c509/non-invertible (v1 covers EC)", codeSync(function () { return pki.schema.c509.encode(rsader); }) === "c509/non-invertible");

  // secondary-form re-emit coverage: a variant C509 built with V.mk -> parse -> re-encode byte-exact,
  // exercising the encoder branches the A.1 KAT does not (null notAfter, printable / multi-attribute /
  // 8-byte-EUI names, RSA keys, ~oid + [~oid, params] algorithms, ~oid extensions).
  [["null notAfter", { 5: "f6" }],
   ["printable single-CN array", { 3: "82206b5246432074657374204341" }],
   ["multi-attribute Name array", { 6: "840162585823625553" }],
   ["8-byte EUI-64 tag-48 commonName", { 6: "d830480123456789abcdef" }],
   ["RSA bare-modulus key", { 0: "02", 7: "00", 8: "49010203040506070809" }],
   ["RSA [modulus, exponent] key", { 0: "02", 7: "00", 8: "82490102030405060708094103" }],
   ["~oid signatureAlgorithm", { 0: "02", 2: "432b6570" }],
   ["[~oid, params] algorithm", { 0: "02", 2: "82432b65704105" }],
   ["~oid extension non-critical", { 9: "82432b06014100" }],
   ["~oid extension critical", { 9: "82432b0601814100" }],
   ["critical keyUsage int-shortcut", { 9: "20" }],
  ].forEach(function (tc, i) {
    var cb = V.mk(tc[1]);
    check("92." + i + " re-emit " + tc[0] + " byte-exact", pki.schema.c509.encode(pki.schema.c509.parse(cb)).equals(cb));
  });

  console.log("CHECKS " + helpers.getChecks());
}

// A helper: patch one byte in a copy of `buf` (e.g. the certificateType) and return the parse error code.
function code2(buf, offset, value) {
  var c = Buffer.from(buf); c[offset] = value;
  return codeSync(function () { return pki.schema.c509.parse(c); });
}
function codeSync(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
