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
  // The int-id form carries the compact KeyUsage value (uint 1 = digitalSignature, draft-20 sec. 3.3).
  check("44. an array-form int-id extension round-trips byte-exact", pki.schema.c509.parse(V.mk({ 9: "820201" })).reconstructedDer.equals(V.A1.der));
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
  // a registered extension WITHOUT a compact value codec (subjectAltName awaits the general-name codec)
  // fails closed at decode when its int-form value is not a byte string (the compact form is unsupported).
  check("50. a registered-int extension with an unsupported compact value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820318ff" })); }) === "c509/bad-extensions");
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

  // ==== signature algorithm + parameter/value type strictness ====
  // a type-3 certificate with a non-ECDSA signature algorithm cannot have its r||s re-wrapped.
  check("65. a non-ECDSA type-3 signature algorithm -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "432b6570" })); }) === "c509/non-invertible");
  // a malformed (odd-length) ECDSA signature is a typed C509 error, never a raw TypeError.
  check("66. an odd-length type-3 signature -> c509/bad-signature", codeSync(function () { return pki.schema.c509.parse(V.mk({ 10: "43010203" })); }) === "c509/bad-signature");
  // a [~oid, params] algorithm whose parameters are not a byte string fails closed.
  check("67. non-byte-string algorithm parameters -> c509/unknown-algorithm", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: "82482a8648ce3d04030201" })); }) === "c509/unknown-algorithm");
  // a tag-48 MAC-address value that does not wrap a byte string fails closed.
  check("68. a tag-48 value not wrapping a byte string -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: "d83001" })); }) === "c509/bad-name");

  // ==== parameter DER validity + ECDSA signature width ====
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

  // ==== degenerate-value rejects (keyUsage, empty / oversized key material) ====
  // a keyUsage value beyond the 9 defined bits fails closed (also guards the 32-bit bitwise re-encoding).
  check("75. an out-of-range keyUsage value -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "190200" })); }) === "c509/non-invertible");
  // an empty EC subjectPublicKey byte string fails closed (never a raw read past the empty buffer).
  check("76. an empty EC subjectPublicKey -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 8: "40" })); }) === "c509/non-invertible");
  // a tag-48 MAC address that is not 6 or 8 bytes fails closed.
  check("77. a tag-48 MAC of an invalid length -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: "d830450102030405" })); }) === "c509/bad-name");
  // a zero RSA modulus fails closed.
  check("78. a zero RSA modulus -> c509/bad-spki", codeSync(function () { return pki.schema.c509.parse(V.mk({ 7: "00", 8: "40" })); }) === "c509/bad-spki");

  // ==== ~oid extension value shape ====
  // a non-critical ~oid extension whose value is not a byte string fails closed.
  check("79. a non-critical ~oid extension value that is not a byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8243551d0f01" })); }) === "c509/bad-extensions");
  // a critical ~oid extension whose [bytes] wrap does not hold a byte string fails closed.
  check("80. a critical ~oid extension not wrapping a byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8243551d0f8101" })); }) === "c509/bad-extensions");

  // ==== encode: the producing side (pki.schema.c509.encode, the byte-exact inverse of parse) ====
  // AUTHORITATIVE KAT: the forward transform of the Appendix A.1 DER yields the draft canonical type-3
  // (the MAC-address commonName compressed to a tag-48 EUI-48, the lone keyUsage as the int shortcut).
  check("81. encode(A.1 DER) == the draft type-3 C509 byte-for-byte", pki.schema.c509.encode(V.A1.der).equals(V.A1.type3));
  // a PEM string and a PEM-armored Buffer normalize to the same DER as the raw Buffer -- the self-verify
  // compares against the coerced certificate DER, not the PEM text bytes.
  var a1Pem = pki.schema.x509.pemEncode(V.A1.der, "CERTIFICATE");
  check("81b. encode(PEM string) == encode(DER)", pki.schema.c509.encode(a1Pem).equals(V.A1.type3));
  check("81c. encode(PEM-armored Buffer) == encode(DER)", pki.schema.c509.encode(Buffer.from(a1Pem, "utf8")).equals(V.A1.type3));
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
  // an incomplete result object (passes the certificateType gate but is missing structured fields) fails
  // closed with a typed verdict rather than a raw property-access crash.
  check("85b. an incomplete result object -> c509/bad-input", codeSync(function () { return pki.schema.c509.encode({ certificateType: 3 }); }) === "c509/bad-input");
  check("85c. a result missing signatureValue -> c509/bad-input", codeSync(function () { return pki.schema.c509.encode({ certificateType: 3, serialNumber: 1n, signatureAlgorithm: { name: "ecdsaWithSHA256" }, subjectPublicKeyAlgorithm: { name: "ecPublicKey", curve: "prime256v1" }, validity: { notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: null }, extensions: [] }); }) === "c509/bad-input");
  // a hand-built result (no preserved field bytes) whose fields individually encode but yield an unparseable
  // C509 (a non-minimal serial) fails closed via the structured-path self-verify, as the verbatim path does.
  var hbBad = pki.schema.c509.parse(V.A1.type3); delete hbBad._fieldBytes; hbBad.serialNumberHex = "0001";
  check("85d. a structured re-emit that cannot parse -> a typed c509/*", codeSync(function () { return pki.schema.c509.encode(hbBad); }) === "c509/non-minimal-serial");

  // ==== the X.509 version this format covers, and the omitted-extensions case ====================
  // Both C509 certificate types are defined over X.509 v3 and the encoding carries no version
  // field, so a v1 / v2 certificate is outside the FORMAT rather than a limit of this encoder --
  // and must say so, instead of falling through to the byte-exactness self-verify whose verdict
  // reads as a defect here. A v3 certificate whose extensions field is OMITTED is fully covered:
  // draft sec. 3.1.10 encodes an omitted 'extensions' field as an empty CBOR array.
  var vB = pki.asn1.build, vO = pki.oid.byName;
  var vk = signing.makeSigner("ec-p256");
  var vAlg = vB.sequence([vB.oid(vO("ecdsaWithSHA256"))]);
  var vName = vB.sequence([vB.set([vB.sequence([vB.oid(vO("commonName")), vB.utf8("version-scope")])])]);
  var vKey = require("crypto").createPrivateKey({ key: vk.key, format: "der", type: "pkcs8" });
  // Built by hand because pki.x509.sign derives the version from the field set (v3 only when
  // extensions are present), so it cannot express "v3 with no extensions" or a bare v1.
  function certOfVersion(versionField, withExtension) {
    var kids = [];
    if (versionField !== null) kids.push(vB.explicit(0, vB.integer(BigInt(versionField))));
    kids.push(vB.integer(7n), vAlg, vName,
      vB.sequence([vB.utcTime(new Date("2026-01-01T00:00:00Z")), vB.utcTime(new Date("2027-01-01T00:00:00Z"))]),
      vName, vk.spki);
    if (withExtension) kids.push(vB.explicit(3, vB.sequence([vB.sequence([vB.oid(vO("ocspNoCheck")), vB.octetString(vB.nullValue())])])));
    var tbs = vB.sequence(kids);
    return vB.sequence([tbs, vAlg, vB.bitString(require("crypto").sign("sha256", tbs, { key: vKey, dsaEncoding: "der" }), 0)]);
  }
  var v1Der = certOfVersion(null, false), v2Der = certOfVersion(1, false), v3NoExt = certOfVersion(2, false);
  check("85e. a v1 certificate is refused as outside the format, naming the version",
    (function () { try { pki.schema.c509.encode(v1Der); return false; }
      catch (e) { return e.code === "c509/non-invertible" && /X\.509 v3 certificates; got v1/.test(e.message); } })());
  check("85f. a v2 certificate is refused the same way",
    (function () { try { pki.schema.c509.encode(v2Der); return false; }
      catch (e) { return e.code === "c509/non-invertible" && /got v2/.test(e.message); } })());
  check("85g. a v3 certificate with the extensions field OMITTED encodes (sec. 3.1.10)",
    Buffer.isBuffer(pki.schema.c509.encode(v3NoExt)));
  check("85h. an omitted extensions field becomes an EMPTY CBOR array", (function () {
    var slot = pki.cbor.decode(pki.schema.c509.encode(v3NoExt)).children[9];
    return slot.majorType === 4 && (slot.children || []).length === 0;
  })());
  check("85i. the omitted-extensions certificate round-trips byte-exact",
    pki.schema.c509.parse(pki.schema.c509.encode(v3NoExt)).reconstructedDer.equals(v3NoExt));
  check("86. encode of garbage DER -> a typed c509/*", /^c509\//.test(codeSync(function () { return pki.schema.c509.encode(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])); })));

  // the flagship forward transform across the EC arms: a v3 DER cert -> a smaller type-3 that reconstructs
  // the source DER byte-for-byte (so the original signature still verifies).
  // These signers pair every curve with SHA-256 (a non-standard digest/curve pairing for P-384 / P-521), so
  // the issuer curve is not derivable from the certificate -- supply it via opts.issuerCurve.
  var arms = ["ec-p256", "ec-p384", "ec-p521"];
  var armCurve = { "ec-p256": "P-256", "ec-p384": "P-384", "ec-p521": "P-521" };
  for (var ai = 0; ai < arms.length; ai++) {
    var s = signing.makeSigner(arms[ai]);
    var der = await pki.x509.sign({ subject: [{ commonName: "dev" }, { countryName: "US" }], subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"], basicConstraints: { cA: false } } }, { key: s.key });
    var c = pki.schema.c509.encode(der, { issuerCurve: armCurve[arms[ai]] });
    check("87." + ai + " " + arms[ai] + " type-3 reconstructs the source DER byte-exact + is smaller", pki.schema.c509.parse(c).reconstructedDer.equals(der) && c.length < der.length);
  }
  // cross-curve: a P-384 CA signing a P-256 subject -- the signature r||s width is the ISSUER's curve (P-384),
  // NOT the subject's P-256 key. The issuer signs with ecdsaWithSHA256 (a non-standard digest/curve pairing),
  // so its curve is not derivable from the certificate and MUST be supplied via opts.issuerCurve; the
  // reconstruction is then byte-exact. Omitting it fails closed rather than guessing the width.
  var caP384 = signing.makeSigner("ec-p384"), subP256 = signing.makeSigner("ec-p256");
  var xder = await pki.x509.sign({ subject: [{ commonName: "leaf" }], subjectPublicKey: subP256.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { name: [{ commonName: "CA" }], publicKey: caP384.spki, key: caP384.key });
  check("88. cross-curve (P-384 CA, P-256 subject) with opts.issuerCurve reconstructs byte-exact", pki.schema.c509.parse(pki.schema.c509.encode(xder, { issuerCurve: "P-384" })).reconstructedDer.equals(xder));
  check("88b. the same cert accepts the OID-form issuer curve name", pki.schema.c509.parse(pki.schema.c509.encode(xder, { issuerCurve: "secp384r1" })).reconstructedDer.equals(xder));
  // a cert whose issuer curve is not derivable (r/s wider than the digest's standard curve) fails closed
  // instead of guessing an ambiguous width.
  check("88c. a non-standard digest/curve pairing without opts -> c509/non-invertible", codeSync(function () { return pki.schema.c509.encode(xder); }) === "c509/non-invertible");
  // an issuer curve too small to hold the signature r/s is rejected (a P-256 field cannot carry a P-384 r||s).
  check("88d. an issuer curve too small for the signature -> c509/non-invertible", codeSync(function () { return pki.schema.c509.encode(xder, { issuerCurve: "P-256" }); }) === "c509/non-invertible");
  // an unrecognized issuer curve is a config-time reject.
  check("88e. an unrecognized opts.issuerCurve -> c509/bad-input", codeSync(function () { return pki.schema.c509.encode(xder, { issuerCurve: "P-999" }); }) === "c509/bad-input");
  // the signature algorithm does not always uniquely determine the curve: an ecdsaWithSHA384 signature whose
  // r/s also fit the smaller P-256 field (a smaller-curve key signing with a larger digest) is ambiguous and
  // requires opts.issuerCurve rather than resolving to the digest's standard P-384.
  var ambS = signing.makeSigner("ec-p256");
  var ambDer = Buffer.from(await pki.x509.sign({ subject: [{ commonName: "amb" }], subjectPublicKey: ambS.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: ambS.key }));
  var oid256 = Buffer.from("06082a8648ce3d040302", "hex"); var ambPos = [];   // ecdsaWithSHA256; last byte 02 -> 03 retargets to ecdsaWithSHA384
  for (var op = ambDer.indexOf(oid256); op !== -1; op = ambDer.indexOf(oid256, op + 1)) ambPos.push(op);
  ambPos.forEach(function (o) { ambDer[o + 9] = 0x03; });
  check("88f. an ambiguous signature algorithm without opts -> c509/non-invertible", codeSync(function () { return pki.schema.c509.encode(ambDer); }) === "c509/non-invertible");
  check("88g. the ambiguous cert with opts.issuerCurve reconstructs byte-exact", pki.schema.c509.parse(pki.schema.c509.encode(ambDer, { issuerCurve: "P-256" })).reconstructedDer.equals(ambDer));

  // fail-closed: type-3 is X.509 v3-only (a v1 cert), and v1 covers EC-only (an RSA cert).
  var v1s = signing.makeSigner("ec-p256");
  var v1der = await pki.x509.sign({ subject: [{ commonName: "v1" }], subjectPublicKey: v1s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") }, { key: v1s.key });
  check("90. a v1 cert (no extensions) -> c509/non-invertible (type-3 is v3-only)", codeSync(function () { return pki.schema.c509.encode(v1der); }) === "c509/non-invertible");
  var rsas = signing.makeSigner("rsa");
  var rsader = await pki.x509.sign({ subject: [{ commonName: "r" }], subjectPublicKey: rsas.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: rsas.key });
  check("91. an RSA cert -> c509/non-invertible (v1 covers EC)", codeSync(function () { return pki.schema.c509.encode(rsader); }) === "c509/non-invertible");
  // fail-closed: a pre-epoch validity date cannot be a C509 ~time (a non-negative CBOR epoch uint).
  var preS = signing.makeSigner("ec-p256");
  var preDer = await pki.x509.sign({ subject: [{ commonName: "pre" }], subjectPublicKey: preS.spki, notBefore: new Date("1960-01-01T00:00:00Z"), notAfter: new Date("1969-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: preS.key });
  check("91b. a pre-epoch validity date -> c509/bad-validity", codeSync(function () { return pki.schema.c509.encode(preDer); }) === "c509/bad-validity");
  // a certificate whose ECDSA signature value is not a SEQUENCE of two INTEGERs (the r INTEGER tag flipped to
  // OCTET STRING) fails closed with a typed verdict rather than reading a non-INTEGER child's content.
  var bsS = signing.makeSigner("ec-p256");
  var bsDer = Buffer.from(await pki.x509.sign({ subject: [{ commonName: "badsig" }], subjectPublicKey: bsS.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: bsS.key }));
  var bsSig = pki.schema.x509.parse(bsDer).signatureValue.bytes;
  bsDer[bsDer.indexOf(bsSig) + 2] = 0x04;   // the signature SEQUENCE's first INTEGER (r) tag -> OCTET STRING
  check("91c. a non-INTEGER ECDSA signature child -> c509/bad-signature", codeSync(function () { return pki.schema.c509.encode(bsDer); }) === "c509/bad-signature");
  // a keyUsage extension whose BIT STRING is not well-formed (invalid unused-bits count) cannot take the
  // C509 keyUsage integer shortcut; the encoder falls back to a raw extension and still reconstructs exactly.
  var kuS = signing.makeSigner("ec-p256");
  var kuDer = Buffer.from(await pki.x509.sign({ subject: [{ commonName: "ku" }], subjectPublicKey: kuS.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: kuS.key }));
  kuDer[kuDer.indexOf(Buffer.from("03020780", "hex")) + 2] = 0x09;   // keyUsage BIT STRING unused-bits 7 -> 9 (malformed)
  check("91d. a malformed keyUsage BIT STRING falls back to a raw extension + reconstructs byte-exact", pki.schema.c509.parse(pki.schema.c509.encode(kuDer)).reconstructedDer.equals(kuDer));

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

  // ==== draft-20 alignment + compact per-extension value inversions (sec. 3.3 / 8.6 / 8.8) ====
  var b = pki.asn1.build, O = pki.oid.byName, CB = pki.cbor;
  var KID = Buffer.from("00112233445566778899aabbccddeeff00112233", "hex");
  async function certWithExts(extsArray) {
    var sk = signing.makeSigner("ec-p256");
    return Buffer.from(await pki.x509.sign({ subject: [{ commonName: "ext-test" }], subjectPublicKey: sk.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: extsArray }, { key: sk.key }));
  }
  // The [extID, value] pair for an int extID of magnitude absId in an encoded C509's extensions node.
  function extPair(enc, absId) {
    var kids = CB.decode(enc).children[9].children || [];
    for (var i = 0; i + 1 < kids.length; i += 2) { var id = kids[i]; if ((id.majorType === 0 || id.majorType === 1) && Math.abs(Number(CB.read.int(id))) === absId) return { id: id, val: kids[i + 1] }; }
    return null;
  }
  function extOidIds(enc) {   // the ~oid (byte-string) extension identifiers present
    var kids = CB.decode(enc).children[9].children || [], out = [];
    for (var i = 0; i + 1 < kids.length; i += 2) if (kids[i].majorType === 2) out.push(kids[i].content.toString("hex"));
    return out;
  }

  // all eight compact extensions on one cert: encode emits each specific value form + double-inversion.
  var allExts = [
    b.sequence([b.oid(O("basicConstraints")), b.boolean(true), b.octetString(b.sequence([b.boolean(true), b.integer(3n)]))]),
    b.sequence([b.oid(O("keyUsage")), b.boolean(true), b.octetString(b.namedBitString([0, 5]))]),
    b.sequence([b.oid(O("subjectKeyIdentifier")), b.octetString(b.octetString(KID))]),
    b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextPrimitive(0, KID)]))]),
    b.sequence([b.oid(O("extKeyUsage")), b.octetString(b.sequence([b.oid(O("serverAuth")), b.oid(O("clientAuth"))]))]),
    b.sequence([b.oid(O("inhibitAnyPolicy")), b.octetString(b.integer(2n))]),
    b.sequence([b.oid(O("ocspNoCheck")), b.octetString(b.nullValue())]),
    b.sequence([b.oid(O("tlsFeature")), b.octetString(b.sequence([b.integer(5n), b.integer(17n)]))]),
  ];
  var allDer = await certWithExts(allExts);
  var allEnc = pki.schema.c509.encode(allDer, { issuerCurve: "P-256" });
  check("100. all-8-ext cert double-inverts byte-exact", pki.schema.c509.parse(allEnc).reconstructedDer.equals(allDer));
  check("101. basicConstraints -> compact int (pathLen 3); keyUsage -> compact int", extPair(allEnc, 4).val.majorType <= 1 && Number(CB.read.int(extPair(allEnc, 4).val)) === 3 && extPair(allEnc, 2).val.majorType <= 1);
  check("102. subjectKeyIdentifier -> the bare key id byte string (not the DER OCTET STRING)", extPair(allEnc, 1).val.majorType === 2 && extPair(allEnc, 1).val.content.equals(KID));
  check("103. authorityKeyIdentifier is at draft-20 extID 7 (keyId bytes), never legacy 10", extPair(allEnc, 7) != null && extPair(allEnc, 7).val.content.equals(KID) && extPair(allEnc, 10) == null);
  check("104. extendedKeyUsage is at extID 8 with a CBOR array value (not ~oid)", extPair(allEnc, 8) != null && extPair(allEnc, 8).val.majorType === 4);
  check("105. inhibitAnyPolicy -> compact uint; ocspNoCheck -> CBOR null; tlsFeature -> array", extPair(allEnc, 30).val.majorType === 0 && extPair(allEnc, 36).val.majorType === 7 && extPair(allEnc, 38).val.majorType === 4);
  check("106. decode surfaces each extnValue as its DER bytes (basicConstraints SEQUENCE)", (function () { var e = pki.schema.c509.parse(allEnc).extensions.filter(function (x) { return x.name === "basicConstraints"; })[0]; return Buffer.isBuffer(e.value) && e.value[0] === 0x30 && pki.asn1.read.integer(pki.asn1.decode(e.value).children[1]) === 3n; })());
  check("107. the critical basicConstraints/keyUsage carry the NEGATIVE extID (criticality sign)", Number(CB.read.int(extPair(allEnc, 4).id)) === -4 && Number(CB.read.int(extPair(allEnc, 2).id)) === -2);

  // basicConstraints -2 / -1 / pathLen mapping.
  var bcFalse = await certWithExts([b.sequence([b.oid(O("basicConstraints")), b.octetString(b.sequence([]))])]);
  var bcCA = await certWithExts([b.sequence([b.oid(O("basicConstraints")), b.boolean(true), b.octetString(b.sequence([b.boolean(true)]))])]);
  check("108. basicConstraints cA=false -> int -2 (non-critical)", Number(CB.read.int(extPair(pki.schema.c509.encode(bcFalse, { issuerCurve: "P-256" }), 4).val)) === -2);
  check("109. basicConstraints cA=true no pathLen -> int -1", Number(CB.read.int(extPair(pki.schema.c509.encode(bcCA, { issuerCurve: "P-256" }), 4).val)) === -1);

  // non-canonical basicConstraints (explicit cA=false) is NOT representable as the compact int -> ~oid fallback,
  // still double-inverts. The round-trip guard rejects the lossy -2 that would drop the explicit BOOLEAN.
  // (x509.sign refuses to emit the non-canonical form, so patch a critical cA=true cert's BOOLEAN TRUE -> FALSE.)
  var bcCaCritDer = await certWithExts([b.sequence([b.oid(O("basicConstraints")), b.boolean(true), b.octetString(b.sequence([b.boolean(true)]))])]);
  var bcNonCanon = Buffer.from(bcCaCritDer);
  bcNonCanon[bcNonCanon.indexOf(Buffer.from("30030101ff", "hex")) + 4] = 0x00;   // SEQUENCE{BOOLEAN TRUE} -> explicit FALSE
  var bcNonCanonEnc = pki.schema.c509.encode(bcNonCanon, { issuerCurve: "P-256" });
  check("110. a non-canonical basicConstraints falls back to ~oid + bytes and double-inverts", extPair(bcNonCanonEnc, 4) == null && extOidIds(bcNonCanonEnc).indexOf("551d13") >= 0 && pki.schema.c509.parse(bcNonCanonEnc).reconstructedDer.equals(bcNonCanon));

  // extKeyUsage: a registered purpose -> int, an unregistered OID -> ~oid; a single purpose omits the array.
  var ekuMixed = await certWithExts([b.sequence([b.oid(O("extKeyUsage")), b.octetString(b.sequence([b.oid(O("serverAuth")), b.oid("1.3.6.1.4.1.99999.7")]))])]);
  var ekuMixedEnc = pki.schema.c509.encode(ekuMixed, { issuerCurve: "P-256" });
  var ekuArr = CB.decode(extPair(ekuMixedEnc, 8).val.bytes).children;
  check("111. extKeyUsage encodes serverAuth as int 1 and an unregistered purpose as ~oid", Number(CB.read.int(ekuArr[0])) === 1 && ekuArr[1].majorType === 2 && pki.schema.c509.parse(ekuMixedEnc).reconstructedDer.equals(ekuMixed));
  var ekuSingle = await certWithExts([b.sequence([b.oid(O("extKeyUsage")), b.octetString(b.sequence([b.oid(O("serverAuth"))]))])]);
  check("112. a single-purpose extKeyUsage omits the array (bare int)", (function () { var v = extPair(pki.schema.c509.encode(ekuSingle, { issuerCurve: "P-256" }), 8).val; return v.majorType <= 1 && Number(CB.read.int(v)) === 1; })());

  // the AKI 3-tuple form (keyIdentifier + authorityCertIssuer + serial) compacts to extID 7 [ keyId,
  // GeneralNames, serial ] and double-inverts byte-exact.
  var akiFull = await certWithExts([b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextPrimitive(0, KID), b.contextConstructed(1, b.contextConstructed(4, b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("CA")])])]))), b.contextPrimitive(2, Buffer.from([0x2a]))]))])]);
  var akiFullEnc = pki.schema.c509.encode(akiFull, { issuerCurve: "P-256" });
  check("113. the AKI 3-tuple compacts to extID 7 [ keyId, issuer, serial ] + double-inverts", (function () { var p = extPair(akiFullEnc, 7); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return a.length === 3 && a[0].content.equals(KID) && Number(CB.read.int(a[1].children[0])) === 4 && a[2].content.equals(Buffer.from([0x2a])) && pki.schema.c509.parse(akiFullEnc).reconstructedDer.equals(akiFull); })());

  // fail-closed decode: a compact value of the wrong CBOR type for the named extension -> c509/bad-extensions.
  check("114. basicConstraints with a text value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82046178" })); }) === "c509/bad-extensions");
  check("115. keyUsage with a byte-string value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82024103" })); }) === "c509/bad-extensions");
  check("116. ocspNoCheck with a non-null value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82182405" })); }) === "c509/bad-extensions");
  check("117. an extKeyUsage int with no registry row -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820881190100" })); }) === "c509/bad-extensions");

  // draft-20 sec. 8.6 RDN attribute numbering: localityName=5, stateOrProvinceName=6, streetAddress=7.
  var nameDer = await (async function () { var sk = signing.makeSigner("ec-p256"); return Buffer.from(await pki.x509.sign({ subject: [{ commonName: "n" }, { localityName: "NYC" }, { stateOrProvinceName: "NY" }, { streetAddress: "1 Main St" }], subjectPublicKey: sk.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: { keyUsage: ["digitalSignature"] } }, { key: sk.key })); })();
  var nameEnc = pki.schema.c509.encode(nameDer, { issuerCurve: "P-256" });
  check("118. locality/state/street RDN attributes use the draft-20 ints 5/6/7 + double-invert", (function () {
    var subjArr = CB.decode(nameEnc).children[6].children, ints = [];
    for (var i = 0; i < subjArr.length; i += 2) ints.push(Number(CB.read.int(subjArr[i])));
    return ints.indexOf(5) >= 0 && ints.indexOf(6) >= 0 && ints.indexOf(7) >= 0 && pki.schema.c509.parse(nameEnc).reconstructedDer.equals(nameDer);
  })());

  // a malformed extnValue (a basicConstraints SEQUENCE whose length is truncated) is not compact-encodable:
  // the encode-side decode faults and the extension falls back to the ~oid byte-string form, double-inverting.
  var bcMalformed = Buffer.from(bcCaCritDer);
  bcMalformed[bcMalformed.indexOf(Buffer.from("30030101ff", "hex")) + 1] = 0x05;   // SEQUENCE length 3 -> 5 (truncated)
  var bcMalformedEnc = pki.schema.c509.encode(bcMalformed, { issuerCurve: "P-256" });
  check("119. a malformed compact-ext DER value falls back to ~oid + bytes and double-inverts", extPair(bcMalformedEnc, 4) == null && extOidIds(bcMalformedEnc).indexOf("551d13") >= 0 && pki.schema.c509.parse(bcMalformedEnc).reconstructedDer.equals(bcMalformed));

  // more fail-closed decode vectors: a compact value of the wrong CBOR type for the byte-string / array exts.
  check("120. subjectKeyIdentifier with a non-byte-string value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820100" })); }) === "c509/bad-extensions");
  check("121. authorityKeyIdentifier with a non-byte-string value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820700" })); }) === "c509/bad-extensions");
  check("122. tlsFeature with a non-array value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82182600" })); }) === "c509/bad-extensions");
  check("123. an extKeyUsage KeyPurposeId that is neither int nor ~oid -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8208816161" })); }) === "c509/bad-extensions");
  // a valid compact basicConstraints pathLen decodes to the DER SEQUENCE { cA TRUE, pathLen }.
  check("124. a compact basicConstraints pathLen decodes to SEQUENCE { cA TRUE, pathLen }", (function () { var e = pki.schema.c509.parse(V.mk({ 9: "820405" })).extensions[0]; return e.name === "basicConstraints" && pki.asn1.read.boolean(pki.asn1.decode(e.value).children[0]) === true && pki.asn1.read.integer(pki.asn1.decode(e.value).children[1]) === 5n; })());
  // a compact basicConstraints cA-only (-1) and cA=false (-2) decode to the two shorter DER SEQUENCE forms.
  check("125. compact basicConstraints -1 -> cA-only, -2 -> empty SEQUENCE", (function () { var ca = pki.schema.c509.parse(V.mk({ 9: "820420" })).extensions[0], f = pki.schema.c509.parse(V.mk({ 9: "820421" })).extensions[0]; return ca.value.equals(Buffer.from("30030101ff", "hex")) && f.value.equals(Buffer.from("3000", "hex")); })());
  check("126. a compact basicConstraints int below -2 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820422" })); }) === "c509/bad-extensions");
  // a single (non-array) extKeyUsage KeyPurposeId decodes to a one-element SEQUENCE OF OID; an empty array fails closed.
  check("127. a bare (non-array) extKeyUsage int decodes to SEQUENCE { serverAuth }", (function () { var e = pki.schema.c509.parse(V.mk({ 9: "820801" })).extensions[0]; return e.name === "extKeyUsage" && pki.asn1.read.oid(pki.asn1.decode(e.value).children[0]) === pki.oid.byName("serverAuth"); })());
  check("128. an empty extKeyUsage array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820880" })); }) === "c509/bad-extensions");
  // encode-side: a basicConstraints whose extnValue is not a SEQUENCE (patched to an INTEGER) is not
  // compact-encodable and falls back to ~oid + bytes, double-inverting.
  var bcNotSeq = Buffer.from(bcCaCritDer);
  bcNotSeq[bcNotSeq.indexOf(Buffer.from("30030101ff", "hex"))] = 0x02;   // SEQUENCE tag -> INTEGER
  var bcNotSeqEnc = pki.schema.c509.encode(bcNotSeq, { issuerCurve: "P-256" });
  check("129. a non-SEQUENCE basicConstraints value falls back to ~oid + bytes and double-inverts", extPair(bcNotSeqEnc, 4) == null && extOidIds(bcNotSeqEnc).indexOf("551d13") >= 0 && pki.schema.c509.parse(bcNotSeqEnc).reconstructedDer.equals(bcNotSeq));
  // the same non-SEQUENCE fallback for the other structural compact extensions (AKI, extKeyUsage, tlsFeature):
  // an extnValue whose SEQUENCE tag is patched to INTEGER is not compact-encodable -> ~oid + bytes.
  var structCerts = [
    ["authorityKeyIdentifier", 7, b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextPrimitive(0, KID)]))])],
    ["extKeyUsage", 8, b.sequence([b.oid(O("extKeyUsage")), b.octetString(b.sequence([b.oid(O("serverAuth"))]))])],
    ["tlsFeature", 38, b.sequence([b.oid(O("tlsFeature")), b.octetString(b.sequence([b.integer(5n)]))])],
  ];
  for (var si = 0; si < structCerts.length; si++) {
    var scDer = await certWithExts([structCerts[si][2]]);
    var scEnt = pki.schema.x509.parse(scDer).extensions[0];
    var scPatched = Buffer.from(scDer);
    scPatched[scPatched.indexOf(scEnt.value)] = 0x02;   // the extnValue SEQUENCE tag -> INTEGER (non-compact)
    var scEnc = pki.schema.c509.encode(scPatched, { issuerCurve: "P-256" });
    check("130." + si + " a non-SEQUENCE " + structCerts[si][0] + " value falls back to ~oid and double-inverts", extPair(scEnc, structCerts[si][1]) == null && pki.schema.c509.parse(scEnc).reconstructedDer.equals(scPatched));
  }

  // a conformant single-dNSName subjectAltName is a BARE text string (draft-20 sec. 3.3): [3, "example.com"];
  // it decodes to the DER SEQUENCE { [2] IA5String dNSName } (the array and the int are omitted).
  check("131. a bare-text subjectAltName (single dNSName) decodes to SEQUENCE { [2] dNSName }", (function () { var e = pki.schema.c509.parse(V.mk({ 9: "82036b6578616d706c652e636f6d" })).extensions[0]; return e.name === "subjectAltName" && e.value.equals(Buffer.from("300d820b6578616d706c652e636f6d", "hex")); })());
  // a compact extKeyUsage array MUST hold 2+ purposes; a 1-element array is a non-canonical duplicate of the
  // bare-int form and is rejected (draft-20 sec. 3.3 ExtKeyUsageSyntax = [ 2* KeyPurposeId ] / KeyPurposeId).
  check("132. a 1-element extKeyUsage array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82088101" })); }) === "c509/bad-extensions");
  // a byte-string value under the subjectAltName int is non-conformant (sec. 3.3 defines the GeneralNames /
  // text value form; a native C509 never carries the raw DER extnValue under int 3) and fails closed.
  check("133. a byte-string subjectAltName value -> c509/bad-extensions (non-conformant; sec. 3.3)", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82034930078205612e636f6d" })); }) === "c509/bad-extensions");
  // a malformed ~oid extKeyUsage KeyPurposeId fails closed in the module's OWN domain (c509/bad-extensions),
  // never leaking an oid/* code onto the parse surface -- a non-minimal, an empty, and a truncated OID content.
  check("134. a non-minimal ~oid extKeyUsage purpose -> c509/bad-extensions (not oid/*)", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8208428001" })); }) === "c509/bad-extensions");
  check("135. an empty ~oid extKeyUsage purpose -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820840" })); }) === "c509/bad-extensions");
  check("136. a truncated ~oid extKeyUsage purpose (in a 2-array) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82088201428001" })); }) === "c509/bad-extensions");
  // the full draft-20 sec. 8.12 EKU registry: the SSH / Kerberos-PKINIT / CMC / Wi-SUN purposes encode as
  // their registry integers (not ~oid) and round-trip -- a conformant cert using those aliases decodes.
  var sshDer = await certWithExts([b.sequence([b.oid(O("extKeyUsage")), b.octetString(b.sequence([b.oid(O("secureShellClient")), b.oid(O("secureShellServer"))]))])]);
  var sshEnc = pki.schema.c509.encode(sshDer, { issuerCurve: "P-256" });
  check("137. SSH client/server extKeyUsage encode as integers 12/13 + round-trip", (function () { var a = CB.decode(extPair(sshEnc, 8).val.bytes).children; return Number(CB.read.int(a[0])) === 12 && Number(CB.read.int(a[1])) === 13 && pki.schema.c509.parse(sshEnc).reconstructedDer.equals(sshDer); })());
  var kdcDer = await certWithExts([b.sequence([b.oid(O("extKeyUsage")), b.octetString(b.sequence([b.oid(O("pkinitKdc"))]))])]);
  check("138. a single Kerberos-PKINIT-KDC extKeyUsage encodes as the bare integer 11 + round-trips", (function () { var v = extPair(pki.schema.c509.encode(kdcDer, { issuerCurve: "P-256" }), 8).val; return v.majorType <= 1 && Number(CB.read.int(v)) === 11 && pki.schema.c509.parse(pki.schema.c509.encode(kdcDer, { issuerCurve: "P-256" })).reconstructedDer.equals(kdcDer); })());

  // ==== the shared GeneralNames value codec (draft-20 sec. 3.3 / sec. 8.13) ====
  function dirName(cn) { return b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable(cn)])])]); }
  function sanExt(members) { return b.sequence([b.oid(O("subjectAltName")), b.octetString(b.sequence(members))]); }
  function gnInts(val) { var a = CB.decode(val.bytes).children, out = []; for (var i = 0; i < a.length; i += 2) out.push(Number(CB.read.int(a[i]))); return out; }

  // 1. a SAN of rfc822Name + dNSName + URI + iPAddress(4) + directoryName -> a flat [1,2,6,7,4] array + byte-exact.
  var sanMixed = await certWithExts([sanExt([
    b.contextPrimitive(1, Buffer.from("a@b.com", "latin1")), b.contextPrimitive(2, Buffer.from("ex.com", "latin1")),
    b.contextPrimitive(6, Buffer.from("https://x.io", "latin1")), b.contextPrimitive(7, Buffer.from([192, 0, 2, 1])),
    b.explicit(4, dirName("CA")),
  ])]);
  var sanMixedEnc = pki.schema.c509.encode(sanMixed, { issuerCurve: "P-256" });
  check("139. a mixed SAN encodes to a flat [1,2,6,7,4] GeneralNames array + double-inverts", extPair(sanMixedEnc, 3) != null && extPair(sanMixedEnc, 3).val.majorType === 4 && gnInts(extPair(sanMixedEnc, 3).val).join(",") === "1,2,6,7,4" && pki.schema.c509.parse(sanMixedEnc).reconstructedDer.equals(sanMixed));

  // 2. exactly one dNSName -> the bare-text shortcut; a single URI keeps the [6, text] array (dNSName-only predicate).
  var sanDns = await certWithExts([sanExt([b.contextPrimitive(2, Buffer.from("only.example", "latin1"))])]);
  var sanDnsEnc = pki.schema.c509.encode(sanDns, { issuerCurve: "P-256" });
  check("140. a single-dNSName SAN is a bare CBOR text (array + int omitted) + double-inverts", extPair(sanDnsEnc, 3).val.majorType === 3 && CB.read.textString(extPair(sanDnsEnc, 3).val) === "only.example" && pki.schema.c509.parse(sanDnsEnc).reconstructedDer.equals(sanDns));
  var sanUri = await certWithExts([sanExt([b.contextPrimitive(6, Buffer.from("https://only.uri", "latin1"))])]);
  var sanUriEnc = pki.schema.c509.encode(sanUri, { issuerCurve: "P-256" });
  check("141. a single-URI SAN keeps the [6, text] array (the text shortcut is dNSName-only)", extPair(sanUriEnc, 3).val.majorType === 4 && gnInts(extPair(sanUriEnc, 3).val).join(",") === "6" && pki.schema.c509.parse(sanUriEnc).reconstructedDer.equals(sanUri));

  // 3. a generic otherName (int 0) emits the [0, [~oid, bytes]] compact form (PROVE it is not fallen back).
  var sanOther = await certWithExts([sanExt([b.contextConstructed(0, Buffer.concat([b.oid("1.2.3.4"), b.explicit(0, b.utf8("hi"))]))])]);
  var sanOtherEnc = pki.schema.c509.encode(sanOther, { issuerCurve: "P-256" });
  check("142. a generic otherName SAN emits [0, [~oid, bytes]] (not fallen back) + double-inverts", extPair(sanOtherEnc, 3) != null && gnInts(extPair(sanOtherEnc, 3).val).join(",") === "0" && pki.schema.c509.parse(sanOtherEnc).reconstructedDer.equals(sanOther));

  // 4. the id-on specials: hardwareModuleName (-1), SmtpUTF8Mailbox (-2), MACAddress (-3, both 6 + 8 octet).
  var sanIdOn = await certWithExts([sanExt([
    b.contextConstructed(0, Buffer.concat([b.oid(O("hardwareModuleName")), b.explicit(0, b.sequence([b.oid("1.3.6.1.4.1.1"), b.octetString(Buffer.from([9, 9]))]))])),
    b.contextConstructed(0, Buffer.concat([b.oid(O("smtpUtf8Mailbox")), b.explicit(0, b.utf8("u@ex.com"))])),
    b.contextConstructed(0, Buffer.concat([b.oid(O("macAddress")), b.explicit(0, b.octetString(Buffer.from([1, 2, 3, 4, 5, 6])))])),
    b.contextConstructed(0, Buffer.concat([b.oid(O("macAddress")), b.explicit(0, b.octetString(Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])))])),
  ])]);
  var sanIdOnEnc = pki.schema.c509.encode(sanIdOn, { issuerCurve: "P-256" });
  check("143. the id-on otherName specials encode as [-1,-2,-3,-3] + double-invert", gnInts(extPair(sanIdOnEnc, 3).val).join(",") === "-1,-2,-3,-3" && pki.schema.c509.parse(sanIdOnEnc).reconstructedDer.equals(sanIdOn));

  // 5. an x400Address [3] (no sec. 8.13 row) makes the whole SAN fall back to ~oid + bytes (never a partial array).
  var sanX400 = await certWithExts([sanExt([b.contextConstructed(3, dirName("x"))])]);
  var sanX400Enc = pki.schema.c509.encode(sanX400, { issuerCurve: "P-256" });
  check("144. a SAN with an x400Address [3] falls back to ~oid + bytes and double-inverts", extPair(sanX400Enc, 3) == null && extOidIds(sanX400Enc).indexOf("551d11") >= 0 && pki.schema.c509.parse(sanX400Enc).reconstructedDer.equals(sanX400));
  // decode-side: a C509 SAN carrying GeneralName int 3 (x400) or int 5 (ediPartyName) has no registry row -> fail closed.
  check("145. a C509 SAN with GeneralName int 3 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8203820340" })); }) === "c509/bad-extensions");
  check("146. a C509 SAN with GeneralName int 5 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "8203820540" })); }) === "c509/bad-extensions");
  // an odd-length GeneralNames array (a dangling type with no value) fails closed.
  check("147. an odd-length GeneralNames array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82038102" })); }) === "c509/bad-extensions");

  // 6. issuerAltName rides the same codec under extID 25.
  var ianCert = await certWithExts([b.sequence([b.oid(O("issuerAltName")), b.octetString(b.sequence([b.contextPrimitive(6, Buffer.from("https://ian.io", "latin1"))]))])]);
  var ianEnc = pki.schema.c509.encode(ianCert, { issuerCurve: "P-256" });
  check("148. issuerAltName encodes under extID 25 + double-inverts", extPair(ianEnc, 25) != null && extPair(ianEnc, 25).val.majorType === 4 && pki.schema.c509.parse(ianEnc).reconstructedDer.equals(ianCert));

  // 7. AKI: keyId-only stays the bytes form; the 3-tuple compacts (test 113); an issuer+serial form (no keyId,
  //    valid per RFC 5280 sec. 4.2.1.1) is not one of the two compact shapes -> ~oid fallback.
  var akiNoKid = await certWithExts([b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextConstructed(1, b.explicit(4, dirName("CA"))), b.contextPrimitive(2, Buffer.from([0x2a]))]))])]);
  var akiNoKidEnc = pki.schema.c509.encode(akiNoKid, { issuerCurve: "P-256" });
  check("149. an AKI issuer + serial (no keyId) is not a compact shape -> ~oid fallback + double-inverts", extPair(akiNoKidEnc, 7) == null && extOidIds(akiNoKidEnc).indexOf("551d23") >= 0 && pki.schema.c509.parse(akiNoKidEnc).reconstructedDer.equals(akiNoKid));

  // 8. nameConstraints (extID 26): permitted dNSName + excluded directoryName.
  var ncNames = await certWithExts([b.sequence([b.oid(O("nameConstraints")), b.boolean(true), b.octetString(b.sequence([
    b.contextConstructed(0, b.sequence([b.contextPrimitive(2, Buffer.from(".ex.com", "latin1"))])),
    b.contextConstructed(1, b.sequence([b.explicit(4, dirName("CA"))])),
  ]))])]);
  var ncNamesEnc = pki.schema.c509.encode(ncNames, { issuerCurve: "P-256" });
  check("150. nameConstraints names -> [permitted, excluded] under extID 26 + double-inverts", (function () { var p = extPair(ncNamesEnc, 26); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return a.length === 2 && Number(CB.read.int(a[0].children[0])) === 2 && Number(CB.read.int(a[1].children[0])) === 4 && pki.schema.c509.parse(ncNamesEnc).reconstructedDer.equals(ncNames); })());

  // 9. nameConstraints RFC 9549 iPAddress prefix form: v4 /24 (5-octet CBOR <-> 8-octet DER), v6 /64, non-prefix mask fallback.
  var ncIp4 = await certWithExts([b.sequence([b.oid(O("nameConstraints")), b.boolean(true), b.octetString(b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(7, Buffer.from([192, 0, 2, 0, 255, 255, 255, 0]))]))]))])]);
  var ncIp4Enc = pki.schema.c509.encode(ncIp4, { issuerCurve: "P-256" });
  check("151. an NC iPAddress 192.0.2.0/24 encodes the subtree base as C0 00 02 00 18 + double-inverts", (function () { var perm = CB.decode(extPair(ncIp4Enc, 26).val.bytes).children[0].children; return perm[1].content.equals(Buffer.from("c000020018", "hex")) && pki.schema.c509.parse(ncIp4Enc).reconstructedDer.equals(ncIp4); })());
  var v6mask = Buffer.concat([Buffer.alloc(16), Buffer.from([0])]); for (var v6i = 0; v6i < 16; v6i++) v6mask[v6i] = 0x20;   // an IPv6 addr (0x20..) with a /64 mask
  var ncIp6base = Buffer.concat([Buffer.alloc(16), Buffer.alloc(16)]); for (var q = 0; q < 16; q++) ncIp6base[q] = 0x20; for (var q2 = 16; q2 < 24; q2++) ncIp6base[q2] = 0xff;
  var ncIp6 = await certWithExts([b.sequence([b.oid(O("nameConstraints")), b.boolean(true), b.octetString(b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(7, ncIp6base)]))]))])]);
  var ncIp6Enc = pki.schema.c509.encode(ncIp6, { issuerCurve: "P-256" });
  check("152. an NC IPv6 /64 subtree base is 17 CBOR octets (last = 64) + double-inverts", (function () { var perm = CB.decode(extPair(ncIp6Enc, 26).val.bytes).children[0].children; return perm[1].content.length === 17 && perm[1].content[16] === 64 && pki.schema.c509.parse(ncIp6Enc).reconstructedDer.equals(ncIp6); })());
  var ncBadMask = await certWithExts([b.sequence([b.oid(O("nameConstraints")), b.boolean(true), b.octetString(b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(7, Buffer.from([192, 0, 2, 0, 255, 0, 255, 0]))]))]))])]);
  var ncBadMaskEnc = pki.schema.c509.encode(ncBadMask, { issuerCurve: "P-256" });
  check("153. an NC iPAddress with a non-prefix mask (FF 00 FF 00) falls back to ~oid + double-inverts", extPair(ncBadMaskEnc, 26) == null && extOidIds(ncBadMaskEnc).indexOf("551d1e") >= 0 && pki.schema.c509.parse(ncBadMaskEnc).reconstructedDer.equals(ncBadMask));

  // 10. authorityInfoAccess (extID 9): id-ad-ocsp + id-ad-caIssuers URIs -> [1, uri, 2, uri]; SIA (extID 31) identical;
  //     an unregistered accessMethod -> ~oid; a non-URI accessLocation -> whole-ext fallback.
  var aiaCert = await certWithExts([b.sequence([b.oid(O("authorityInfoAccess")), b.octetString(b.sequence([
    b.sequence([b.oid(O("ocsp")), b.contextPrimitive(6, Buffer.from("http://o.io", "latin1"))]),
    b.sequence([b.oid(O("caIssuers")), b.contextPrimitive(6, Buffer.from("http://c.io", "latin1"))]),
  ]))])]);
  var aiaEnc = pki.schema.c509.encode(aiaCert, { issuerCurve: "P-256" });
  check("154. AIA (ocsp + caIssuers URIs) -> [1, uri, 2, uri] under extID 9 + double-inverts", (function () { var a = CB.decode(extPair(aiaEnc, 9).val.bytes).children; return Number(CB.read.int(a[0])) === 1 && Number(CB.read.int(a[2])) === 2 && pki.schema.c509.parse(aiaEnc).reconstructedDer.equals(aiaCert); })());
  var siaCert = await certWithExts([b.sequence([b.oid(O("subjectInfoAccess")), b.octetString(b.sequence([b.sequence([b.oid(O("id-ad-caRepository")), b.contextPrimitive(6, Buffer.from("http://r.io", "latin1"))])]))])]);
  var siaEnc = pki.schema.c509.encode(siaCert, { issuerCurve: "P-256" });
  check("155. subjectInfoAccess rides the same codec under extID 31 (caRepository int 5) + double-inverts", (function () { var p = extPair(siaEnc, 31); return p != null && Number(CB.read.int(CB.decode(p.val.bytes).children[0])) === 5 && pki.schema.c509.parse(siaEnc).reconstructedDer.equals(siaCert); })());
  var aiaOid = await certWithExts([b.sequence([b.oid(O("authorityInfoAccess")), b.octetString(b.sequence([b.sequence([b.oid("1.3.6.1.4.1.99999.7"), b.contextPrimitive(6, Buffer.from("http://x.io", "latin1"))])]))])]);
  var aiaOidEnc = pki.schema.c509.encode(aiaOid, { issuerCurve: "P-256" });
  check("156. an unregistered AIA accessMethod encodes as ~oid (not an int) + double-inverts", CB.decode(extPair(aiaOidEnc, 9).val.bytes).children[0].majorType === 2 && pki.schema.c509.parse(aiaOidEnc).reconstructedDer.equals(aiaOid));
  var aiaDirLoc = await certWithExts([b.sequence([b.oid(O("authorityInfoAccess")), b.octetString(b.sequence([b.sequence([b.oid(O("ocsp")), b.explicit(4, dirName("CA"))])]))])]);
  var aiaDirLocEnc = pki.schema.c509.encode(aiaDirLoc, { issuerCurve: "P-256" });
  check("157. an AIA with a non-URI (directoryName) accessLocation falls back to ~oid + double-inverts", extPair(aiaDirLocEnc, 9) == null && pki.schema.c509.parse(aiaDirLocEnc).reconstructedDer.equals(aiaDirLoc));
  check("158. a C509 AIA accessMethod int with no sec. 8.11 row -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82098218636178" })); }) === "c509/bad-extensions");

  // 11. cRLDistributionPoints (extID 5): 2-URI fullName + reasons(keyCompromise|cACompromise = 6) + cRLIssuer(directoryName).
  var crlFull = await certWithExts([b.sequence([b.oid(O("cRLDistributionPoints")), b.octetString(b.sequence([b.sequence([
    b.explicit(0, b.contextConstructed(0, Buffer.concat([b.contextPrimitive(6, Buffer.from("http://a.io", "latin1")), b.contextPrimitive(6, Buffer.from("http://b.io", "latin1"))]))),
    b.contextPrimitive(1, Buffer.from([5, 0x60])),
    b.contextConstructed(2, b.explicit(4, dirName("CA"))),
  ])]))])]);
  var crlFullEnc = pki.schema.c509.encode(crlFull, { issuerCurve: "P-256" });
  check("159. a full CRLDP (2 URIs + reasons + cRLIssuer) encodes under extID 5 + reasons uint 6 + double-inverts", (function () { var p = extPair(crlFullEnc, 5); if (p == null) return false; var dp = CB.decode(p.val.bytes).children[0].children; return dp[0].children.length === 2 && Number(CB.read.int(dp[1])) === 6 && dp[2].majorType !== 7 && pki.schema.c509.parse(crlFullEnc).reconstructedDer.equals(crlFull); })());

  // 12. the whole-ext text shortcut (one DP, one-URI fullName, no reasons, no cRLIssuer); freshestCRL (extID 29) identical.
  var crlText = await certWithExts([b.sequence([b.oid(O("cRLDistributionPoints")), b.octetString(b.sequence([b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://only.crl", "latin1"))))])]))])]);
  var crlTextEnc = pki.schema.c509.encode(crlText, { issuerCurve: "P-256" });
  check("160. a one-DP one-URI CRLDP is a bare CBOR text + double-inverts", extPair(crlTextEnc, 5).val.majorType === 3 && CB.read.textString(extPair(crlTextEnc, 5).val) === "http://only.crl" && pki.schema.c509.parse(crlTextEnc).reconstructedDer.equals(crlText));
  var freshCrl = await certWithExts([b.sequence([b.oid(O("freshestCRL")), b.octetString(b.sequence([b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://fresh.crl", "latin1"))))])]))])]);
  var freshCrlEnc = pki.schema.c509.encode(freshCrl, { issuerCurve: "P-256" });
  check("161. freshestCRL rides the same codec under extID 29 + double-inverts", extPair(freshCrlEnc, 29) != null && pki.schema.c509.parse(freshCrlEnc).reconstructedDer.equals(freshCrl));

  // 13. criticality: a critical general-name-bearing ext carries the NEGATIVE int extID and reconstructs critical.
  var sanCrit = await certWithExts([b.sequence([b.oid(O("nameConstraints")), b.boolean(true), b.octetString(b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(2, Buffer.from(".c.io", "latin1"))]))]))])]);
  var sanCritEnc = pki.schema.c509.encode(sanCrit, { issuerCurve: "P-256" });
  check("162. a critical nameConstraints carries the negative extID -26 + reconstructs critical", Number(CB.read.int(extPair(sanCritEnc, 26).id)) === -26 && pki.schema.x509.parse(pki.schema.c509.parse(sanCritEnc).reconstructedDer).extensions.filter(function (e) { return e.name === "nameConstraints"; })[0].critical === true);

  // 14. fail-closed decode: a SAN [4] directoryName value that is not a Name array -> c509/bad-name; a nameConstraints value
  //     that is not a 2-array -> c509/bad-extensions; a cRLDistributionPoints reasons past the 9 bits -> c509/bad-extensions.
  check("163. a SAN [4] directoryName with a non-Name value -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820382040a" })); }) === "c509/bad-name");
  check("164. a nameConstraints value that is not a 2-element array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "82181a80" })); }) === "c509/bad-extensions");

  // 15. the aggregate byte-exact oracle: one cert bearing SAN + IAN + AKI-3tuple + nameConstraints + AIA + CRLDP double-inverts.
  var aggregate = await certWithExts([
    sanExt([b.contextPrimitive(2, Buffer.from("a.ex", "latin1")), b.contextPrimitive(6, Buffer.from("https://b.ex", "latin1"))]),
    b.sequence([b.oid(O("issuerAltName")), b.octetString(b.sequence([b.contextPrimitive(1, Buffer.from("i@ex.com", "latin1"))]))]),
    b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextPrimitive(0, KID), b.contextConstructed(1, b.explicit(4, dirName("CA"))), b.contextPrimitive(2, Buffer.from([0x2a]))]))]),
    b.sequence([b.oid(O("nameConstraints")), b.boolean(true), b.octetString(b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(7, Buffer.from([10, 0, 0, 0, 255, 0, 0, 0]))]))]))]),
    b.sequence([b.oid(O("authorityInfoAccess")), b.octetString(b.sequence([b.sequence([b.oid(O("ocsp")), b.contextPrimitive(6, Buffer.from("http://ocsp.ex", "latin1"))])]))]),
    b.sequence([b.oid(O("cRLDistributionPoints")), b.octetString(b.sequence([b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://crl.ex", "latin1"))))])]))]),
  ]);
  var aggregateEnc = pki.schema.c509.encode(aggregate, { issuerCurve: "P-256" });
  check("165. a cert bearing SAN + IAN + AKI-3tuple + NC + AIA + CRLDP double-inverts byte-exact", pki.schema.c509.parse(aggregateEnc).reconstructedDer.equals(aggregate) && extPair(aggregateEnc, 3) != null && extPair(aggregateEnc, 25) != null && extPair(aggregateEnc, 7) != null && extPair(aggregateEnc, 26) != null && extPair(aggregateEnc, 9) != null && extPair(aggregateEnc, 5) != null);

  // 16. fail-closed decode of malformed compact general-name values (native C509 -> DER reconstruction, the
  //     fail-closed tier: a malformed CBOR value must throw a typed c509/* verdict, never a partial DER).
  function mkExt(cbufHex) { return V.mk({ 9: cbufHex }); }
  var CBb = CB.build;
  // a SAN GeneralNames is a FLAT array [int, value, ...]; sanVal wraps a single (int, value) general name.
  function sanVal(intVal, val) { return CB.build.array([CB.build.int(3n), CBb.array([CBb.int(BigInt(intVal)), val])]).toString("hex"); }
  check("166. a generic otherName (int 0) with a non-pair value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(0, CBb.uint(5n)))); }) === "c509/bad-extensions");
  check("167. a generic otherName (int 0) whose value element is not a byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(0, CBb.array([CBb.byteString(Buffer.from("2b06010401", "hex")), CBb.uint(5n)])))); }) === "c509/bad-extensions");
  check("168. a generic otherName (int 0) whose inner bytes are not a DER element -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(0, CBb.array([CBb.byteString(Buffer.from("2b06010401", "hex")), CBb.byteString(Buffer.from("ff", "hex"))])))); }) === "c509/bad-extensions");
  check("169. an id-on-hardwareModuleName (-1) whose serial element is not bytes -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(-1, CBb.array([CBb.byteString(Buffer.from("2b06010401", "hex")), CBb.uint(5n)])))); }) === "c509/bad-extensions");
  check("170. an id-on-SmtpUTF8Mailbox (-2) with a non-text value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(-2, CBb.uint(5n)))); }) === "c509/bad-extensions");
  check("171. an id-on-MACAddress (-3) with a wrong-length value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(-3, CBb.byteString(Buffer.from("010203", "hex"))))); }) === "c509/bad-extensions");
  check("172. a SAN iPAddress (7) with a wrong-length value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(7, CBb.byteString(Buffer.from("0102", "hex"))))); }) === "c509/bad-extensions");
  // nameConstraints (extID 26) value = [ permittedSubtrees, excludedSubtrees ]; a subtrees list is a FLAT [int, value].
  function ncVal(perm, excl) { return CB.build.array([CB.build.int(26n), CBb.array([perm, excl])]).toString("hex"); }
  check("173. an NC iPAddress with a non-5/17-octet value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(ncVal(CBb.array([CBb.int(7n), CBb.byteString(Buffer.from("c0000200", "hex"))]), CBb.nullValue()))); }) === "c509/bad-extensions");
  check("174. an NC iPAddress prefix length past the address width -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(ncVal(CBb.array([CBb.int(7n), CBb.byteString(Buffer.from("c0000200ff", "hex"))]), CBb.nullValue()))); }) === "c509/bad-extensions");
  check("175. an NC GeneralSubtrees value that is not an array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(ncVal(CBb.uint(5n), CBb.nullValue()))); }) === "c509/bad-extensions");
  // cRLDistributionPoints (extID 5): a DistributionPoint that is not a 3-element array; a reasons value past the 9 bits.
  function crlVal(inner) { return CB.build.array([CB.build.int(5n), inner]).toString("hex"); }
  check("176. a CRLDP DistributionPoint that is not a 3-element array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(crlVal(CBb.array([CBb.array([CBb.textString("http://x")])])))); }) === "c509/bad-extensions");
  check("177. a CRLDP reasons value past the 9 defined bits -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(crlVal(CBb.array([CBb.array([CBb.textString("http://x"), CBb.uint(0x400n), CBb.nullValue()])])))); }) === "c509/bad-extensions");

  // 17. encode-side fallback: a DER general name the compact codec cannot invert makes the WHOLE extension fall
  //     back to ~oid + byte-string (never a partial GeneralNames), and still double-inverts byte-exact.
  var sanMultiRdn = await certWithExts([sanExt([b.explicit(4, b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("A")]), b.sequence([b.oid(O("organizationName")), b.printable("B")])])]))])]);
  var sanMultiRdnEnc = pki.schema.c509.encode(sanMultiRdn, { issuerCurve: "P-256" });
  check("178. a SAN directoryName with a multi-value RDN falls back to ~oid + double-inverts", extPair(sanMultiRdnEnc, 3) == null && extOidIds(sanMultiRdnEnc).indexOf("551d11") >= 0 && pki.schema.c509.parse(sanMultiRdnEnc).reconstructedDer.equals(sanMultiRdn));
  var sanSmtpBad = await certWithExts([sanExt([b.contextConstructed(0, Buffer.concat([b.oid(O("smtpUtf8Mailbox")), b.explicit(0, b.printable("not-utf8"))]))])]);
  var sanSmtpBadEnc = pki.schema.c509.encode(sanSmtpBad, { issuerCurve: "P-256" });
  check("179. an SmtpUTF8Mailbox otherName with a non-UTF8String value falls back to ~oid + double-inverts", extPair(sanSmtpBadEnc, 3) == null && pki.schema.c509.parse(sanSmtpBadEnc).reconstructedDer.equals(sanSmtpBad));

  // 18. the AKI 3-tuple serial INTEGER content: a high-bit serial gets the 0x00 sign octet; a zero serial is 0x00.
  var akiHiSerial = await certWithExts([b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(b.sequence([b.contextPrimitive(0, KID), b.contextConstructed(1, b.explicit(4, dirName("CA"))), b.contextPrimitive(2, Buffer.from([0x00, 0x80]))]))])]);
  var akiHiSerialEnc = pki.schema.c509.encode(akiHiSerial, { issuerCurve: "P-256" });
  check("180. an AKI 3-tuple with a high-bit serial (00 80) round-trips its INTEGER sign octet byte-exact", extPair(akiHiSerialEnc, 7) != null && pki.schema.c509.parse(akiHiSerialEnc).reconstructedDer.equals(akiHiSerial));

  // 19. remaining fail-closed decode branches: an IA5 general name (rfc822/dNSName/URI) whose value is not
  //     7-bit ASCII text; an iPAddress value that is not a byte string; a CRLDP fullName of the wrong type.
  check("181. a SAN rfc822Name (1) with a non-text value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(1, CBb.uint(5n)))); }) === "c509/bad-extensions");
  check("182. a SAN dNSName (2) with a non-ASCII IA5String text -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(2, CBb.textString(String.fromCharCode(0xe9) + ".example")))); }) === "c509/bad-extensions");
  check("183. a SAN iPAddress (7) with a non-byte-string value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(7, CBb.uint(5n)))); }) === "c509/bad-extensions");
  check("184. an NC iPAddress with a non-byte-string value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(ncVal(CBb.array([CBb.int(7n), CBb.uint(5n)]), CBb.nullValue()))); }) === "c509/bad-extensions");
  check("185. a CRLDP fullName that is neither text nor an array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(crlVal(CBb.array([CBb.array([CBb.uint(5n), CBb.nullValue(), CBb.nullValue()])])))); }) === "c509/bad-extensions");
  // encode-side: an id-on-MACAddress otherName whose inner OCTET STRING is not 6/8 octets falls back to ~oid.
  var sanMacBad = await certWithExts([sanExt([b.contextConstructed(0, Buffer.concat([b.oid(O("macAddress")), b.explicit(0, b.octetString(Buffer.from([1, 2, 3, 4, 5, 6, 7])))]))])]);
  var sanMacBadEnc = pki.schema.c509.encode(sanMacBad, { issuerCurve: "P-256" });
  check("186. an id-on-MACAddress otherName with a wrong-length inner value falls back to ~oid + double-inverts", extPair(sanMacBadEnc, 3) == null && pki.schema.c509.parse(sanMacBadEnc).reconstructedDer.equals(sanMacBad));

  // 20. encode-side CRLDP fallbacks (non-compact but valid RFC 5280 DistributionPoints): a non-URI fullName
  //     member, a nameRelativeToCRLIssuer, a non-directoryName cRLIssuer -- each falls the whole ext back to ~oid.
  function crldpExt(dp) { return b.sequence([b.oid(O("cRLDistributionPoints")), b.octetString(b.sequence([dp]))]); }
  var dpDirFull = b.sequence([b.explicit(0, b.contextConstructed(0, b.explicit(4, dirName("CA"))))]);   // fullName [0] with a [4] directoryName
  var crlDirFull = await certWithExts([crldpExt(dpDirFull)]);
  var crlDirFullEnc = pki.schema.c509.encode(crlDirFull, { issuerCurve: "P-256" });
  check("187. a CRLDP fullName with a directoryName member falls back to ~oid + double-inverts", extPair(crlDirFullEnc, 5) == null && pki.schema.c509.parse(crlDirFullEnc).reconstructedDer.equals(crlDirFull));
  var dpUriIssuer = b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://a.io", "latin1")))), b.contextConstructed(2, b.contextPrimitive(6, Buffer.from("http://i.io", "latin1")))]);
  var crlUriIssuer = await certWithExts([crldpExt(dpUriIssuer)]);
  var crlUriIssuerEnc = pki.schema.c509.encode(crlUriIssuer, { issuerCurve: "P-256" });
  check("188. a CRLDP cRLIssuer that is a URI (not a directoryName) falls back to ~oid + double-inverts", extPair(crlUriIssuerEnc, 5) == null && pki.schema.c509.parse(crlUriIssuerEnc).reconstructedDer.equals(crlUriIssuer));
  var dpRelName = b.sequence([b.explicit(0, b.contextConstructed(1, b.sequence([b.oid(O("commonName")), b.printable("X")])))]);   // distributionPoint [0] EXPLICIT { nameRelativeToCRLIssuer [1] IMPLICIT RDN }
  var crlRelName = await certWithExts([crldpExt(dpRelName)]);
  var crlRelNameEnc = pki.schema.c509.encode(crlRelName, { issuerCurve: "P-256" });
  check("189. a CRLDP nameRelativeToCRLIssuer distributionPoint falls back to ~oid + double-inverts", extPair(crlRelNameEnc, 5) == null && pki.schema.c509.parse(crlRelNameEnc).reconstructedDer.equals(crlRelName));
  // encode-side: a hardwareModuleName otherName whose inner is not a 2-field SEQUENCE falls back to ~oid.
  var sanHwBad = await certWithExts([sanExt([b.contextConstructed(0, Buffer.concat([b.oid(O("hardwareModuleName")), b.explicit(0, b.sequence([b.oid("1.2.3"), b.octetString(Buffer.from([1])), b.octetString(Buffer.from([2]))]))]))])]);
  var sanHwBadEnc = pki.schema.c509.encode(sanHwBad, { issuerCurve: "P-256" });
  check("190. a hardwareModuleName otherName with a non-2-field inner falls back to ~oid + double-inverts", extPair(sanHwBadEnc, 3) == null && pki.schema.c509.parse(sanHwBadEnc).reconstructedDer.equals(sanHwBad));

  // 21. a C509 Name whose attributeType slot is not an integer fails in this module's domain (c509/bad-name),
  //     never leaking cbor.read.int's cbor/unexpected-major fault -- on BOTH the top-level Name and every
  //     sec. 8.13 directoryName general name (the attacker-controlled Name the compact codec newly routes here).
  check("191. a SAN directoryName with a non-integer attribute type -> c509/bad-name (not cbor/*)", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(4, CBb.array([CBb.textString("x"), CBb.textString("A")])))); }) === "c509/bad-name");
  check("192. a top-level subject Name with a non-integer attribute type -> c509/bad-name (not cbor/*)", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: "8261786141" })); }) === "c509/bad-name");

  // 22. an AKI whose authorityCertIssuer [1] is an EMPTY GeneralNames (a1 00) is a shape x509.sign refuses but
  //     x509.parse accepts; the empty GeneralNames is not compact-representable, so encode() must FALL BACK to
  //     the ~oid form (exercising the round-trip guard's fault path) rather than throw on a parseable cert.
  var emptyAkiSigner = signing.makeSigner("ec-p256");
  var emptyAkiPoint = pki.asn1.read.bitString(pki.asn1.decode(emptyAkiSigner.spki).children[1]).bytes;
  var emptyAkiName = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8("leaf")])])]);
  var emptyAkiVal = b.sequence([b.contextPrimitive(0, KID), b.contextConstructed(1, Buffer.alloc(0)), b.contextPrimitive(2, Buffer.from([0x2a]))]);
  var emptyAkiSigAlg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
  var emptyAkiTbs = b.sequence([
    b.explicit(0, b.integer(2n)), b.integer(1n), emptyAkiSigAlg, emptyAkiName,
    b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), b.utcTime(new Date("2027-01-01T00:00:00Z"))]),
    emptyAkiName, b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]), b.bitString(emptyAkiPoint, 0)]),
    b.explicit(3, b.sequence([b.sequence([b.oid(O("authorityKeyIdentifier")), b.octetString(emptyAkiVal)])])),
  ]);
  var emptyAkiSig = b.sequence([b.integer(BigInt("0x01" + "00".repeat(31))), b.integer(BigInt("0x01" + "00".repeat(31)))]);
  var emptyAkiDer = b.sequence([emptyAkiTbs, emptyAkiSigAlg, b.bitString(emptyAkiSig, 0)]);
  var emptyAkiEnc = pki.schema.c509.encode(emptyAkiDer, { issuerCurve: "P-256" });
  check("193. an AKI with an empty authorityCertIssuer [1] falls back to ~oid (not a throw) + double-inverts", extPair(emptyAkiEnc, 7) == null && extOidIds(emptyAkiEnc).indexOf("551d23") >= 0 && pki.schema.c509.parse(emptyAkiEnc).reconstructedDer.equals(emptyAkiDer));

  // 23. an IA5 general name (rfc822/dNSName/URI) with an EMPTY text is rejected, matching the shared pkix leaf.
  check("194. a SAN dNSName with an empty IA5String text -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(2, CBb.textString("")))); }) === "c509/bad-extensions");

  // 24. ReasonFlags bit 0 is reserved unused (RFC 5280 sec. 4.2.1.13; reason bits are 1..8): a native C509
  //     cRLDistributionPoints whose reasons uint sets bit 0 is not a valid ReasonFlags and fails closed on
  //     decode; a DER cert carrying such a ReasonFlags falls the whole ext back to ~oid on encode.
  check("195. a CRLDP reasons uint that sets the reserved bit 0 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(crlVal(CBb.array([CBb.array([CBb.textString("http://x"), CBb.uint(1n), CBb.nullValue()])])))); }) === "c509/bad-extensions");
  var dpBit0 = b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://x.io", "latin1")))), b.contextPrimitive(1, Buffer.from([7, 0x80]))]);   // ReasonFlags = only the reserved bit 0
  var crlBit0 = await certWithExts([crldpExt(dpBit0)]);
  var crlBit0Enc = pki.schema.c509.encode(crlBit0, { issuerCurve: "P-256" });
  check("196. a DER CRLDP ReasonFlags with the reserved bit 0 set falls back to ~oid + double-inverts", extPair(crlBit0Enc, 5) == null && pki.schema.c509.parse(crlBit0Enc).reconstructedDer.equals(crlBit0));

  // 25. RFC 9598 constrains SmtpUTF8Mailbox to SIZE (1..MAX): a native C509 SAN with an empty id-on-SmtpUTF8Mailbox
  //     value is not a valid otherName and fails closed rather than reconstructing an empty UTF8String.
  check("197. an id-on-SmtpUTF8Mailbox otherName with an empty text -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(-2, CBb.textString("")))); }) === "c509/bad-extensions");

  // ==== certificatePolicies compact value codec (draft-20 sec. 3.3 / 8.9 / 8.10, RFC 5280 sec. 4.2.1.4) ====
  function cpExt(pis, crit) { var f = [b.oid(O("certificatePolicies"))]; if (crit) f.push(b.boolean(true)); f.push(b.octetString(b.sequence(pis))); return b.sequence(f); }
  function pol(oidArg, quals) { var f = [typeof oidArg === "string" ? b.oid(oidArg) : oidArg]; if (quals) f.push(quals); return b.sequence(f); }
  function cpsQ(uri) { return b.sequence([b.oid(O("cps")), b.ia5(uri)]); }
  function unoticeQ(text) { return b.sequence([b.oid(O("unotice")), b.sequence([b.utf8(text)])]); }
  function cpVal(inner) { return CB.build.array([CB.build.int(6n), inner]).toString("hex"); }
  function encCp(der) { return pki.schema.c509.encode(der, { issuerCurve: "P-256" }); }
  function cpInts(val) { var a = CB.decode(val.bytes).children, out = []; for (var i = 0; i < a.length; i += 2) out.push(a[i].majorType === 2 ? "~oid" : Number(CB.read.int(a[i]))); return out; }

  // 1. a registered policy int + an unregistered ~oid policy; a bare policy carries an EMPTY qualifiers array.
  var cpMulti = await certWithExts([cpExt([pol(O("domain-validated")), pol("1.3.6.1.4.1.99999.1")])]);
  var cpMultiEnc = encCp(cpMulti);
  check("198. certificatePolicies encodes under extID 6, registered->int, unregistered->~oid, bare->[] + double-inverts", (function () { var p = extPair(cpMultiEnc, 6); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 1 && a[1].majorType === 4 && a[1].children.length === 0 && a[2].majorType === 2 && pki.schema.c509.parse(cpMultiEnc).reconstructedDer.equals(cpMulti); })());

  // 2/3/4. cps qualifier, unotice explicitText, and both on one policy.
  var cpCps = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([cpsQ("http://cps.example")]))])]);
  var cpCpsEnc = encCp(cpCps);
  check("199. a CPS qualifier -> [1, uri] + double-inverts", (function () { var q = CB.decode(extPair(cpCpsEnc, 6).val.bytes).children[1].children; return Number(CB.read.int(q[0])) === 1 && CB.read.textString(q[1]) === "http://cps.example" && pki.schema.c509.parse(cpCpsEnc).reconstructedDer.equals(cpCps); })());
  var cpUn = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([unoticeQ("Notice text")]))])]);
  var cpUnEnc = encCp(cpUn);
  check("200. a UserNotice explicitText utf8String -> [2, text] + double-inverts", (function () { var q = CB.decode(extPair(cpUnEnc, 6).val.bytes).children[1].children; return Number(CB.read.int(q[0])) === 2 && CB.read.textString(q[1]) === "Notice text" && pki.schema.c509.parse(cpUnEnc).reconstructedDer.equals(cpUn); })());
  var cpBoth = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([cpsQ("http://c.ex"), unoticeQ("N")]))])]);
  var cpBothEnc = encCp(cpBoth);
  check("201. cps + unotice on one policy -> a flat [1, uri, 2, text] qualifiers array + double-inverts", (function () { var q = CB.decode(extPair(cpBothEnc, 6).val.bytes).children[1].children; return q.length === 4 && Number(CB.read.int(q[0])) === 1 && Number(CB.read.int(q[2])) === 2 && pki.schema.c509.parse(cpBothEnc).reconstructedDer.equals(cpBoth); })());

  // 5/6/7. the three fallback triggers: a noticeRef, a non-UTF8 explicitText, an unregistered qualifier OID.
  var cpNoticeRef = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid(O("unotice")), b.sequence([b.sequence([b.utf8("Org"), b.sequence([b.integer(1n)])])])])]))])]);
  var cpNoticeRefEnc = encCp(cpNoticeRef);
  check("202. a UserNotice with a noticeRef falls back to ~oid + double-inverts", extPair(cpNoticeRefEnc, 6) == null && extOidIds(cpNoticeRefEnc).indexOf("551d20") >= 0 && pki.schema.c509.parse(cpNoticeRefEnc).reconstructedDer.equals(cpNoticeRef));
  var cpIa5Note = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid(O("unotice")), b.sequence([b.ia5("x")])])]))])]);
  var cpIa5NoteEnc = encCp(cpIa5Note);
  check("203. a UserNotice explicitText in the ia5String arm (not utf8String) falls back to ~oid + double-inverts", extPair(cpIa5NoteEnc, 6) == null && pki.schema.c509.parse(cpIa5NoteEnc).reconstructedDer.equals(cpIa5Note));
  var cpUnkQ = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid("1.3.6.1.4.1.99999.2"), b.ia5("z")])]))])]);
  var cpUnkQEnc = encCp(cpUnkQ);
  check("204. a qualifier OID outside sec. 8.10 falls back to ~oid + double-inverts", extPair(cpUnkQEnc, 6) == null && pki.schema.c509.parse(cpUnkQEnc).reconstructedDer.equals(cpUnkQ));

  // 8. double-inversion at scale + 10. the GSMA deep-arc / RPKI ints resolve to their sec. 8.9 integers.
  var cpScale = await certWithExts([cpExt([pol(O("id-rspRole-euicc")), pol(O("id-cp-ipAddr-asNumber"), b.sequence([cpsQ("http://r.ex")])), pol(O("anyPolicy"), b.sequence([cpsQ("http://a.ex"), unoticeQ("hi")]))])]);
  var cpScaleEnc = encCp(cpScale);
  check("205. GSMA (int 26) + RPKI (int 7) + anyPolicy w/ 2 quals on one cert double-inverts + int rows resolve", (function () { var p = extPair(cpScaleEnc, 6); return p != null && cpInts(p.val).join(",") === "26,7,0" && pki.schema.c509.parse(cpScaleEnc).reconstructedDer.equals(cpScale); })());

  // 9. criticality sign.
  var cpCrit = await certWithExts([cpExt([pol(O("anyPolicy"))], true)]);
  var cpCritEnc = encCp(cpCrit);
  check("206. a critical certificatePolicies carries extID -6 + reconstructs critical", Number(CB.read.int(extPair(cpCritEnc, 6).id)) === -6 && pki.schema.x509.parse(pki.schema.c509.parse(cpCritEnc).reconstructedDer).extensions.filter(function (e) { return e.name === "certificatePolicies"; })[0].critical === true);

  // 11-13. fail-closed decode (native C509): wrong value type, odd-length arrays, unregistered policy/qualifier ints.
  check("207. a certificatePolicies value that is not a CBOR array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: "820618ff" })); }) === "c509/bad-extensions");
  check("208. an odd-length certificatePolicies array (dangling policy) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n)])))); }) === "c509/bad-extensions");
  check("209. a qualifiers slot that is not an array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.uint(5n)])))); }) === "c509/bad-extensions");
  check("210. an odd-length qualifiers array (dangling qualifier) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(1n)])])))); }) === "c509/bad-extensions");
  check("211. a policy int with no sec. 8.9 row -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(5n), CBb.array([])])))); }) === "c509/bad-extensions");
  check("212. a ~oid / unregistered qualifierId in a native compact value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(9n), CBb.textString("x")])])))); }) === "c509/bad-extensions");

  // 14. a native compact value decodes to the DER SEQUENCE OF PolicyInformation.
  check("213. a native [0, [1, uri]] decodes to SEQUENCE { PolicyInformation { anyPolicy, { id-qt-cps, IA5String } } }", (function () { var e = pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(1n), CBb.textString("http://c")])])))).extensions[0]; if (e.name !== "certificatePolicies") return false; var pi = pki.asn1.decode(e.value).children[0]; return pki.asn1.read.oid(pi.children[0]) === pki.oid.byName("anyPolicy") && pki.asn1.read.oid(pi.children[1].children[0].children[0]) === pki.oid.byName("cps") && pki.asn1.read.string(pi.children[1].children[0].children[1]) === "http://c"; })());

  // 15. empty explicitText / empty CPSuri fail closed (DisplayText SIZE 1..200 floor + CPSuri parity).
  check("214. a UserNotice explicitText that is empty -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(2n), CBb.textString("")])])))); }) === "c509/bad-extensions");
  check("215. a CPSuri that is empty -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(1n), CBb.textString("")])])))); }) === "c509/bad-extensions");

  // 16. a bare policy with NO qualifiers stays compact ([int, []]), not a ~oid fallback.
  var cpBare = await certWithExts([cpExt([pol(O("anyPolicy"))])]);
  var cpBareEnc = encCp(cpBare);
  check("216. a bare policy (no qualifiers) stays compact as [int, []] + double-inverts", (function () { var p = extPair(cpBareEnc, 6); return p != null && CB.decode(p.val.bytes).children[1].children.length === 0 && pki.schema.c509.parse(cpBareEnc).reconstructedDer.equals(cpBare); })());
  // a CPS/unotice qualifier whose string BODY is malformed (a non-7-bit IA5String / a non-UTF-8 UTF8String --
  // x509.sign keeps the qualifier body opaque, so build the raw TLV) is not compact-representable: the whole
  // extension falls back to ~oid and double-inverts, never losing the malformed bytes.
  var cpBadIa5 = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid(O("cps")), b.raw(Buffer.from([0x16, 0x01, 0x80]))])]))])]);   // IA5String content 0x80 (high bit)
  var cpBadIa5Enc = encCp(cpBadIa5);
  check("217. a CPS qualifier with a non-7-bit IA5String body falls back to ~oid + double-inverts", extPair(cpBadIa5Enc, 6) == null && pki.schema.c509.parse(cpBadIa5Enc).reconstructedDer.equals(cpBadIa5));
  var cpBadUtf8 = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid(O("unotice")), b.sequence([b.raw(Buffer.from([0x0c, 0x01, 0x80]))])])]))])]);   // UTF8String content 0x80 (invalid UTF-8)
  var cpBadUtf8Enc = encCp(cpBadUtf8);
  check("218. a UserNotice explicitText with a non-UTF-8 UTF8String body falls back to ~oid + double-inverts", extPair(cpBadUtf8Enc, 6) == null && pki.schema.c509.parse(cpBadUtf8Enc).reconstructedDer.equals(cpBadUtf8));
  // more fail-closed decode (native C509): a non-7-bit CPSuri text, a ~oid (non-int) qualifierId, a non-text qualifier value.
  check("219. a native CPSuri text with a non-ASCII code point -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(1n), CBb.textString(String.fromCharCode(0xe9) + ".ex")])])))); }) === "c509/bad-extensions");
  check("220. a native policyQualifierId that is a ~oid (not a sec. 8.10 int) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.byteString(Buffer.from("2b06010505070201", "hex")), CBb.textString("x")])])))); }) === "c509/bad-extensions");
  check("221. a native policyQualifier value that is not a CBOR text -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([CBb.int(1n), CBb.uint(5n)])])))); }) === "c509/bad-extensions");
  // encode-side fallback: a CPS qualifier whose value is a UTF8String (not IA5String), and a UserNotice that is
  // not SEQUENCE { explicitText utf8String } (an empty UserNotice) -> the whole ext falls back to ~oid.
  var cpCpsUtf8 = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid(O("cps")), b.utf8("http://x")])]))])]);
  var cpCpsUtf8Enc = encCp(cpCpsUtf8);
  check("222. a CPS qualifier whose value is a UTF8String (not IA5String) falls back to ~oid + double-inverts", extPair(cpCpsUtf8Enc, 6) == null && pki.schema.c509.parse(cpCpsUtf8Enc).reconstructedDer.equals(cpCpsUtf8));
  var cpEmptyUn = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([b.sequence([b.oid(O("unotice")), b.sequence([])])]))])]);
  var cpEmptyUnEnc = encCp(cpEmptyUn);
  check("223. an empty UserNotice (not SEQUENCE { explicitText }) falls back to ~oid + double-inverts", extPair(cpEmptyUnEnc, 6) == null && pki.schema.c509.parse(cpEmptyUnEnc).reconstructedDer.equals(cpEmptyUn));
  // a policy OID MUST NOT appear more than once (RFC 5280 sec. 4.2.1.4); a native C509 that repeats one fails
  // closed rather than reconstructing a certificatePolicies extension the toolkit's own DER decoder rejects.
  check("224. a native certificatePolicies that repeats a policy OID -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(cpVal(CBb.array([CBb.int(0n), CBb.array([]), CBb.int(0n), CBb.array([])])))); }) === "c509/bad-extensions");
  // (a >200-char explicitText is NOT rejected: RFC 5280 sec. 4.2.1.4 directs users to gracefully handle it, and
  // draft-20 sec. 3.3's compact predicate is SIZE-silent -- so it stays compact and double-inverts byte-exact.)
  var longText = new Array(251).join("x");   // 250 chars
  var cpLong = await certWithExts([cpExt([pol(O("anyPolicy"), b.sequence([unoticeQ(longText)]))])]);
  var cpLongEnc = encCp(cpLong);
  check("225. a UserNotice explicitText over 200 chars stays compact + double-inverts (RFC 5280 graceful handling)", extPair(cpLongEnc, 6) != null && Number(CB.read.int(CB.decode(extPair(cpLongEnc, 6).val.bytes).children[1].children[0])) === 2 && pki.schema.c509.parse(cpLongEnc).reconstructedDer.equals(cpLong));

  // ==== policyMappings + policyConstraints compact value codecs (draft-20 sec. 3.3 / 8.8, RFC 5280 sec. 4.2.1.5 / 4.2.1.11) ====
  function pmExt(maps, crit) { var f = [b.oid(O("policyMappings"))]; if (crit) f.push(b.boolean(true)); f.push(b.octetString(b.sequence(maps))); return b.sequence(f); }
  function mapping(a, z) { return b.sequence([typeof a === "string" ? b.oid(a) : a, typeof z === "string" ? b.oid(z) : z]); }
  function pcExt(rep, ipm, crit) { var fl = []; if (rep != null) fl.push(b.implicit(0, b.integer(BigInt(rep)))); if (ipm != null) fl.push(b.implicit(1, b.integer(BigInt(ipm)))); var f = [b.oid(O("policyConstraints"))]; if (crit) f.push(b.boolean(true)); f.push(b.octetString(b.sequence(fl))); return b.sequence(f); }
  function pmVal(inner) { return CB.build.array([CB.build.int(27n), inner]).toString("hex"); }   // native policyMappings under extID 27
  function pcVal(inner) { return CB.build.array([CB.build.int(28n), inner]).toString("hex"); }   // native policyConstraints under extID 28

  // 1. a registered-int mapping + an unregistered ~oid mapping: registered members ride sec. 8.9 ints, the rest ~oid.
  var pmMulti = await certWithExts([pmExt([mapping(O("domain-validated"), O("organization-validated")), mapping("1.3.6.1.4.1.99999.1", "1.3.6.1.4.1.99999.2")])]);
  var pmMultiEnc = encCp(pmMulti);
  check("226. policyMappings encodes under extID 27, registered->int, unregistered->~oid + double-inverts", (function () { var p = extPair(pmMultiEnc, 27); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return a.length === 4 && Number(CB.read.int(a[0])) === 1 && Number(CB.read.int(a[1])) === 2 && a[2].majorType === 2 && a[3].majorType === 2 && pki.schema.c509.parse(pmMultiEnc).reconstructedDer.equals(pmMulti); })());

  // 2. anyPolicy in a mapping is ACCEPTED: RFC 5280 sec. 4.2.1.5 "MUST NOT map to/from anyPolicy" is a generation
  //    rule the toolkit's own DER decoder does not reject, so the reconstruct accepts exactly what the decoder accepts.
  var pmAny = await certWithExts([pmExt([mapping(O("anyPolicy"), O("domain-validated"))])]);
  var pmAnyEnc = encCp(pmAny);
  check("227. anyPolicy in a policyMapping is accepted (a generation MUST-NOT the verifier does not reject) + double-inverts", (function () { var p = extPair(pmAnyEnc, 27); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 0 && Number(CB.read.int(a[1])) === 1 && pki.schema.c509.parse(pmAnyEnc).reconstructedDer.equals(pmAny); })());

  // 3. double-inversion at scale: int/int, int/~oid, ~oid/~oid mappings on one cert stay a compact even-length array.
  var pmScale = await certWithExts([pmExt([mapping(O("domain-validated"), O("organization-validated")), mapping(O("anyPolicy"), "1.3.6.1.4.1.99999.3"), mapping("1.3.6.1.4.1.99999.4", "1.3.6.1.4.1.99999.5")])]);
  var pmScaleEnc = encCp(pmScale);
  check("228. three mappings (int/int, int/~oid, ~oid/~oid) stay a compact even-length array + double-inverts", (function () { var p = extPair(pmScaleEnc, 27); if (p == null || p.val.majorType !== 4) return false; return CB.decode(p.val.bytes).children.length === 6 && pki.schema.c509.parse(pmScaleEnc).reconstructedDer.equals(pmScale); })());

  // 4. criticality sign.
  var pmCrit = await certWithExts([pmExt([mapping(O("anyPolicy"), O("domain-validated"))], true)]);
  var pmCritEnc = encCp(pmCrit);
  check("229. a critical policyMappings carries extID -27 + reconstructs critical", Number(CB.read.int(extPair(pmCritEnc, 27).id)) === -27 && pki.schema.x509.parse(pki.schema.c509.parse(pmCritEnc).reconstructedDer).extensions.filter(function (e) { return e.name === "policyMappings"; })[0].critical === true);

  // 5. the GSMA deep-arc / RPKI sec. 8.9 ints resolve inside a mapping (the same policy dispatch certificatePolicies uses).
  var pmGsma = await certWithExts([pmExt([mapping(O("id-rspRole-euicc"), O("id-cp-ipAddr-asNumber"))])]);
  var pmGsmaEnc = encCp(pmGsma);
  check("230. a mapping of GSMA (int 26) -> RPKI (int 7) resolves both sec. 8.9 ints + double-inverts", (function () { var p = extPair(pmGsmaEnc, 27); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 26 && Number(CB.read.int(a[1])) === 7 && pki.schema.c509.parse(pmGsmaEnc).reconstructedDer.equals(pmGsma); })());

  // 6. a native compact value decodes to the DER SEQUENCE OF SEQUENCE { OID, OID }.
  check("231. a native policyMappings [0, 1] decodes to SEQUENCE { SEQUENCE { anyPolicy, domain-validated } }", (function () { var e = pki.schema.c509.parse(mkExt(pmVal(CBb.array([CBb.int(0n), CBb.int(1n)])))).extensions[0]; if (e.name !== "policyMappings") return false; var mp = pki.asn1.decode(e.value).children[0]; return pki.asn1.read.oid(mp.children[0]) === pki.oid.byName("anyPolicy") && pki.asn1.read.oid(mp.children[1]) === pki.oid.byName("domain-validated"); })());

  // 7-9. fail-closed decode (native C509): wrong CBOR type, odd-length / empty arrays, an unregistered policy int.
  check("232. a policyMappings value that is not a CBOR array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pmVal(CBb.uint(5n)))); }) === "c509/bad-extensions");
  check("233. an odd-length policyMappings array (dangling half-mapping) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pmVal(CBb.array([CBb.int(0n)])))); }) === "c509/bad-extensions");
  check("234. an empty policyMappings array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pmVal(CBb.array([])))); }) === "c509/bad-extensions");
  check("235. a policyMappings member int with no sec. 8.9 row -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pmVal(CBb.array([CBb.int(5n), CBb.int(0n)])))); }) === "c509/bad-extensions");

  // 10-12. policyConstraints: requireExplicitPolicy only, inhibitPolicyMapping only, both -- the fixed-2 [uint/null, uint/null].
  var pcRep = await certWithExts([pcExt(0, null)]);
  var pcRepEnc = encCp(pcRep);
  check("236. policyConstraints requireExplicitPolicy only encodes under extID 28 to [0, null] + double-inverts", (function () { var p = extPair(pcRepEnc, 28); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return a.length === 2 && Number(CB.read.int(a[0])) === 0 && a[1].majorType === 7 && a[1].ai === 22 && pki.schema.c509.parse(pcRepEnc).reconstructedDer.equals(pcRep); })());
  var pcIpm = await certWithExts([pcExt(null, 3)]);
  var pcIpmEnc = encCp(pcIpm);
  check("237. policyConstraints inhibitPolicyMapping only encodes to [null, 3] + double-inverts", (function () { var p = extPair(pcIpmEnc, 28); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return a[0].majorType === 7 && a[0].ai === 22 && Number(CB.read.int(a[1])) === 3 && pki.schema.c509.parse(pcIpmEnc).reconstructedDer.equals(pcIpm); })());
  var pcBoth = await certWithExts([pcExt(2, 5)]);
  var pcBothEnc = encCp(pcBoth);
  check("238. policyConstraints with both fields encodes to [2, 5] + double-inverts", (function () { var p = extPair(pcBothEnc, 28); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 2 && Number(CB.read.int(a[1])) === 5 && pki.schema.c509.parse(pcBothEnc).reconstructedDer.equals(pcBoth); })());

  // 13. IMPLICIT-tag exactness: the reconstructed [0]/[1] fields are context-primitive (0x80/0x81), not EXPLICIT/constructed.
  check("239. reconstructed policyConstraints uses IMPLICIT [0]/[1] primitive tags (not constructed)", (function () { var e = pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.uint(2n), CBb.uint(5n)])))).extensions[0]; if (e.name !== "policyConstraints") return false; var kids = pki.asn1.decode(e.value).children; return kids.length === 2 && kids[0].tagClass === "context" && kids[0].tagNumber === 0 && !kids[0].constructed && kids[1].tagClass === "context" && kids[1].tagNumber === 1 && !kids[1].constructed && pki.asn1.read.integerImplicit(kids[0], 0) === 2n && pki.asn1.read.integerImplicit(kids[1], 1) === 5n; })());

  // 14. criticality sign (RFC 5280 sec. 4.2.1.11 MUST be critical -- the sign carries it either way).
  var pcCrit = await certWithExts([pcExt(0, null, true)]);
  var pcCritEnc = encCp(pcCrit);
  check("240. a critical policyConstraints carries extID -28 + reconstructs critical", Number(CB.read.int(extPair(pcCritEnc, 28).id)) === -28 && pki.schema.x509.parse(pki.schema.c509.parse(pcCritEnc).reconstructedDer).extensions.filter(function (e) { return e.name === "policyConstraints"; })[0].critical === true);

  // 15. a native compact value decodes to the DER SEQUENCE { [0] SkipCerts }.
  check("241. a native policyConstraints [2, null] decodes to SEQUENCE { [0] INTEGER 2 }", (function () { var e = pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.uint(2n), CBb.nullValue()])))).extensions[0]; if (e.name !== "policyConstraints") return false; var kids = pki.asn1.decode(e.value).children; return kids.length === 1 && kids[0].tagClass === "context" && kids[0].tagNumber === 0 && pki.asn1.read.integerImplicit(kids[0], 0) === 2n; })());

  // 16-20. fail-closed decode (native C509): both-null empty PolicyConstraints, wrong length, non-uint / negative slot,
  //         a SkipCerts past 2^31-1 (the reconstruct applies the same guard.range.uint31 the DER decoder does), wrong type.
  check("242. a native policyConstraints [null, null] (empty PolicyConstraints) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.nullValue(), CBb.nullValue()])))); }) === "c509/bad-extensions");
  check("243. a 1-element policyConstraints array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.uint(0n)])))); }) === "c509/bad-extensions");
  check("244. a 3-element policyConstraints array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.uint(0n), CBb.nullValue(), CBb.uint(1n)])))); }) === "c509/bad-extensions");
  check("245. a policyConstraints slot that is neither uint nor null -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.textString("x"), CBb.nullValue()])))); }) === "c509/bad-extensions");
  check("246. a policyConstraints negative-int slot (SkipCerts is a uint) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.int(-1n), CBb.nullValue()])))); }) === "c509/bad-extensions");
  check("247. a policyConstraints SkipCerts past 2^31-1 -> c509/bad-extensions (reconstruct bounds via guard.range.uint31)", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.array([CBb.uint(4294967296n), CBb.nullValue()])))); }) === "c509/bad-extensions");
  check("248. a policyConstraints value that is not a CBOR array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(pcVal(CBb.uint(5n)))); }) === "c509/bad-extensions");

  // sibling INTEGER-bound reconstruct sites narrowed through the same guard.range.uint31 the toolkit's own DER decoders
  // apply (schema-pkix inhibitAnyPolicy / basicConstraints pathLen): a native count past 2^31-1 fails closed on decode,
  // never reconstructing a DER the toolkit's own decoder would reject. (x509.sign validates these extensions, so an
  // oversized DER cannot be built through it; the encode-side round-trip fallback on a reconstruct throw is covered
  // by test 193.)
  function iaVal(inner) { return CB.build.array([CB.build.int(30n), inner]).toString("hex"); }
  function bcVal(inner) { return CB.build.array([CB.build.int(4n), inner]).toString("hex"); }
  check("249. a native inhibitAnyPolicy SkipCerts past 2^31-1 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(iaVal(CBb.uint(4294967296n)))); }) === "c509/bad-extensions");
  check("250. a native basicConstraints pathLen past 2^31-1 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(bcVal(CBb.uint(4294967296n)))); }) === "c509/bad-extensions");

  // encode-side fallback: a MALFORMED policy-family extension (a cert x509.parse accepts but the compact codec
  // cannot represent -- there is no valid-but-non-compact policyMappings/policyConstraints, so these are hand-built)
  // falls the WHOLE ext back to the ~oid form + double-inverts, never throwing on a parseable cert or losing bytes.
  function handCertExt(extDer) {
    var s = signing.makeSigner("ec-p256");
    var point = pki.asn1.read.bitString(pki.asn1.decode(s.spki).children[1]).bytes;
    var nm = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8("leaf")])])]);
    var sigAlg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
    var tbs = b.sequence([b.explicit(0, b.integer(2n)), b.integer(1n), sigAlg, nm, b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), b.utcTime(new Date("2027-01-01T00:00:00Z"))]), nm, b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]), b.bitString(point, 0)]), b.explicit(3, b.sequence([extDer]))]);
    var sig = b.sequence([b.integer(BigInt("0x01" + "00".repeat(31))), b.integer(BigInt("0x01" + "00".repeat(31)))]);
    return b.sequence([tbs, sigAlg, b.bitString(sig, 0)]);
  }
  function fellBack(der, absId) { var enc = encCp(der); return extPair(enc, absId) == null && pki.schema.c509.parse(enc).reconstructedDer.equals(der); }
  check("252. a policyMappings extnValue that is not a SEQUENCE falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyMappings")), b.octetString(b.integer(5n))])), 27));
  check("253. a policyMappings mapping with other than 2 members falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyMappings")), b.octetString(b.sequence([b.sequence([b.oid(O("anyPolicy"))])]))])), 27));
  check("254. a policyConstraints extnValue that is not a SEQUENCE falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyConstraints")), b.octetString(b.integer(5n))])), 28));
  check("255. a policyConstraints with an unexpected [2] field falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyConstraints")), b.octetString(b.sequence([b.implicit(2, b.integer(1n))]))])), 28));
  check("256. a policyConstraints with a negative SkipCerts falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyConstraints")), b.octetString(b.sequence([b.implicit(0, b.integer(-1n))]))])), 28));
  check("257. a policyConstraints with descending [1] then [0] fields falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyConstraints")), b.octetString(b.sequence([b.implicit(1, b.integer(1n)), b.implicit(0, b.integer(2n))]))])), 28));
  check("258. a policyConstraints SEQUENCE with three fields falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("policyConstraints")), b.octetString(b.sequence([b.implicit(0, b.integer(1n)), b.implicit(1, b.integer(2n)), b.implicit(2, b.integer(3n))]))])), 28));

  // ==== subjectDirectoryAttributes compact value codec (draft-20 sec. 3.3 / 8.6 / 8.8, RFC 5280 sec. 4.2.1.8) ====
  function sdaExt(attrs, crit) { var f = [b.oid(O("subjectDirectoryAttributes"))]; if (crit) f.push(b.boolean(true)); f.push(b.octetString(b.sequence(attrs))); return b.sequence(f); }
  function sdaAttr(typeName, valueTlvs) { return b.sequence([b.oid(O(typeName)), b.set(valueTlvs)]); }
  function sdaVal(inner) { return CB.build.array([CB.build.int(24n), inner]).toString("hex"); }   // native SDA under extID 24

  // 1. single registered attribute, single value -> [10, ["Director"]] (title = sec. 8.6 int 10, positive = utf8String).
  var sdaTitle = await certWithExts([sdaExt([sdaAttr("title", [b.utf8("Director")])])]);
  var sdaTitleEnc = encCp(sdaTitle);
  check("259. subjectDirectoryAttributes encodes under extID 24, registered int + a value ARRAY (SDA-vs-Name) + double-inverts", (function () { var p = extPair(sdaTitleEnc, 24); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 10 && a[1].majorType === 4 && a[1].children.length === 1 && CB.read.textString(a[1].children[0]) === "Director" && pki.schema.c509.parse(sdaTitleEnc).reconstructedDer.equals(sdaTitle); })());

  // 2. multi-value SET (SIZE > 1) -- the core reason SDA is not the Name codec.
  var sdaMulti = await certWithExts([sdaExt([sdaAttr("organizationalUnitName", [b.utf8("Eng"), b.utf8("Ops")])])]);
  var sdaMultiEnc = encCp(sdaMulti);
  check("260. a subjectDirectoryAttributes attribute with a multi-value SET (SIZE > 1) round-trips + double-inverts", (function () { var p = extPair(sdaMultiEnc, 24); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 9 && a[1].majorType === 4 && a[1].children.length === 2 && pki.schema.c509.parse(sdaMultiEnc).reconstructedDer.equals(sdaMulti); })());

  // 3. printableString sign -- countryName is PrintableString-restricted -> negative int.
  var sdaCountry = await certWithExts([sdaExt([sdaAttr("countryName", [b.printable("US")])])]);
  var sdaCountryEnc = encCp(sdaCountry);
  check("261. a subjectDirectoryAttributes printableString attribute carries the negative sign + double-inverts", (function () { var p = extPair(sdaCountryEnc, 24); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === -4 && CB.read.textString(a[1].children[0]) === "US" && pki.schema.c509.parse(sdaCountryEnc).reconstructedDer.equals(sdaCountry); })());

  // 4. a per-attribute ~oid form (an unregistered type) keeps the ext compact (extID 24), not a whole-ext ~oid fallback.
  var sdaEmail = await certWithExts([sdaExt([sdaAttr("emailAddress", [b.ia5("a@b.example")])])]);
  var sdaEmailEnc = encCp(sdaEmail);
  // emailAddress is an IA5String-only attribute, so it rides its sec. 8.6 NON-NEGATIVE int (0) with text values
  // (draft sec. 3.1.4) -- its type, not a sign, fixes the string type -- and reconstructs the IA5String exactly.
  check("262. a subjectDirectoryAttributes emailAddress rides the sec. 8.6 int 0 with IA5String values + double-inverts", (function () { var p = extPair(sdaEmailEnc, 24); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return Number(CB.read.int(a[0])) === 0 && a[1].majorType === 4 && CB.read.textString(a[1].children[0]) === "a@b.example" && pki.schema.c509.parse(sdaEmailEnc).reconstructedDer.equals(sdaEmail); })());

  // 5. the headline trap: a mixed printable/utf8 SET cannot use one sign -> that attribute uses the ~oid+bytes form.
  var sdaMixed = await certWithExts([sdaExt([sdaAttr("title", [b.printable("A"), b.utf8("B")])])]);
  var sdaMixedEnc = encCp(sdaMixed);
  check("263. a subjectDirectoryAttributes attribute with a mixed printable/utf8 SET uses the ~oid form for that attribute + double-inverts", (function () { var p = extPair(sdaMixedEnc, 24); if (p == null) return false; var a = CB.decode(p.val.bytes).children; return a[0].majorType === 2 && pki.schema.c509.parse(sdaMixedEnc).reconstructedDer.equals(sdaMixed); })());

  // 6. multiple attributes, mixed forms -> a flat even-length compact array (extID 24, not a ~oid whole-ext fallback).
  var sdaMany = await certWithExts([sdaExt([sdaAttr("title", [b.utf8("Dir")]), sdaAttr("countryName", [b.printable("US")]), sdaAttr("emailAddress", [b.ia5("a@b.ex")])])]);
  var sdaManyEnc = encCp(sdaMany);
  check("264. multiple subjectDirectoryAttributes attributes (int/utf8, int/printable, ~oid) stay a flat compact array + double-inverts", (function () { var p = extPair(sdaManyEnc, 24); if (p == null || p.val.majorType !== 4) return false; var a = CB.decode(p.val.bytes).children; return a.length === 6 && Number(CB.read.int(a[0])) === 10 && pki.schema.c509.parse(sdaManyEnc).reconstructedDer.equals(sdaMany); })());

  // 7. criticality sign (accept, do not reject the RFC 5280 sec. 4.2.1.8 MUST-non-critical generation rule).
  var sdaCrit = await certWithExts([sdaExt([sdaAttr("title", [b.utf8("D")])], true)]);
  var sdaCritEnc = encCp(sdaCrit);
  check("265. a critical subjectDirectoryAttributes carries extID -24 + reconstructs critical", Number(CB.read.int(extPair(sdaCritEnc, 24).id)) === -24 && pki.schema.x509.parse(pki.schema.c509.parse(sdaCritEnc).reconstructedDer).extensions.filter(function (e) { return e.name === "subjectDirectoryAttributes"; })[0].critical === true);

  // 8/9. native compact value decodes to the DER SEQUENCE OF Attribute.
  check("266. a native subjectDirectoryAttributes [10, [text]] decodes to SEQUENCE { SEQUENCE { OID title, SET { UTF8String } } }", (function () { var e = pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(10n), CBb.array([CBb.textString("Director")])])))).extensions[0]; if (e.name !== "subjectDirectoryAttributes") return false; var attr = pki.asn1.decode(e.value).children[0]; return pki.asn1.read.oid(attr.children[0]) === pki.oid.byName("title") && attr.children[1].tagNumber === pki.asn1.TAGS.SET && pki.asn1.read.string(attr.children[1].children[0]) === "Director"; })());
  check("267. a native subjectDirectoryAttributes [10, [text, text]] reconstructs a 2-member SET", (function () { var e = pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(10n), CBb.array([CBb.textString("Eng"), CBb.textString("Ops")])])))).extensions[0]; if (e.name !== "subjectDirectoryAttributes") return false; var attr = pki.asn1.decode(e.value).children[0]; return attr.children[1].tagNumber === pki.asn1.TAGS.SET && attr.children[1].children.length === 2; })());

  // 10-15. fail-closed decode (native C509): wrong type, odd/empty outer array, empty SET, unregistered int, bad ~oid value, non-int/~oid type.
  check("268. a subjectDirectoryAttributes value that is not a CBOR array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.uint(5n)))); }) === "c509/bad-extensions");
  check("269. an odd-length subjectDirectoryAttributes array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(10n)])))); }) === "c509/bad-extensions");
  check("270. an empty subjectDirectoryAttributes array -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([])))); }) === "c509/bad-extensions");
  check("271. an empty attributeValue array (SET SIZE 0) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(10n), CBb.array([])])))); }) === "c509/bad-extensions");
  check("272. an attribute type int with no sec. 8.6 row -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(11n), CBb.array([CBb.textString("x")])])))); }) === "c509/bad-extensions");
  check("273. a ~oid-form value that is not a byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.byteString(pki.asn1.encodeOidContent("1.2.840.113549.1.9.1")), CBb.array([CBb.textString("x")])])))); }) === "c509/bad-extensions");
  check("274. a subjectDirectoryAttributes attribute type that is neither int nor ~oid -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.textString("title"), CBb.array([CBb.textString("x")])])))); }) === "c509/bad-extensions");

  // 16. native int-form fail-closed: a byte-string value under an int type (the int form is text-only).
  check("275. a native subjectDirectoryAttributes int-form value that is not a CBOR text string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(10n), CBb.array([CBb.byteString(Buffer.from("41", "hex"))])])))); }) === "c509/bad-extensions");
  // 17/18. per-attribute ~oid fallbacks that keep the WHOLE ext compact (extID 24): a registered type whose
  //        value is not utf8/printableString, and an unregistered OID type. Both stay a compact array, first element ~oid.
  var sdaIa5 = await certWithExts([sdaExt([sdaAttr("title", [b.ia5("x")])])]);
  var sdaIa5Enc = encCp(sdaIa5);
  check("276. a subjectDirectoryAttributes registered-type attribute with a non-utf8/printable value uses the per-attribute ~oid form + double-inverts", (function () { var p = extPair(sdaIa5Enc, 24); return p != null && p.val.majorType === 4 && CB.decode(p.val.bytes).children[0].majorType === 2 && pki.schema.c509.parse(sdaIa5Enc).reconstructedDer.equals(sdaIa5); })());
  var sdaUnk = await certWithExts([b.sequence([b.oid(O("subjectDirectoryAttributes")), b.octetString(b.sequence([b.sequence([b.oid("1.2.3.4"), b.set([b.utf8("x")])])]))])]);
  var sdaUnkEnc = encCp(sdaUnk);
  check("277. a subjectDirectoryAttributes attribute of an unregistered OID type uses the per-attribute ~oid form + double-inverts", (function () { var p = extPair(sdaUnkEnc, 24); return p != null && p.val.majorType === 4 && CB.decode(p.val.bytes).children[0].majorType === 2 && pki.schema.c509.parse(sdaUnkEnc).reconstructedDer.equals(sdaUnk); })());
  // 19-21. whole-ext ~oid fallbacks: a malformed SDA (a cert x509.parse accepts but the compact codec cannot
  //        represent) falls the whole extension back to ~oid + double-inverts, never throwing on a parseable cert.
  check("278. a subjectDirectoryAttributes extnValue that is not a SEQUENCE falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("subjectDirectoryAttributes")), b.octetString(b.integer(5n))])), 24));
  check("279. a subjectDirectoryAttributes attribute that is not a 2-child SEQUENCE falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("subjectDirectoryAttributes")), b.octetString(b.sequence([b.sequence([b.oid(O("title"))])]))])), 24));
  check("280. a subjectDirectoryAttributes attribute whose values is not a non-empty SET falls back to ~oid + double-inverts", fellBack(handCertExt(b.sequence([b.oid(O("subjectDirectoryAttributes")), b.octetString(b.sequence([b.sequence([b.oid(O("title")), b.utf8("x")])]))])), 24));

  // 22-24. the ~oid-form value MUST be exactly one non-empty DER AttributeValue TLV -- an empty byte string
  //         reconstructs an empty values SET (RFC 5280 sec. 4.2.1.8 SET OF SIZE 1..MAX) and a multi-TLV byte
  //         string fans one value into several members (draft sec. 3.3: one bytes = one AttributeValue); there
  //         is no downstream DER decoder (c509-only), so _sdaToDer self-enforces. And countryName/serialNumber
  //         are PrintableString-restricted -- a non-negative (utf8String) sign fails closed, not coerced.
  check("281. a ~oid-form subjectDirectoryAttributes value that is an EMPTY byte string -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.byteString(pki.asn1.encodeOidContent("1.2.3.4")), CBb.array([CBb.byteString(Buffer.alloc(0))])])))); }) === "c509/bad-extensions");
  check("282. a ~oid-form value byte string carrying more than one DER TLV -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.byteString(pki.asn1.encodeOidContent("1.2.3.4")), CBb.array([CBb.byteString(Buffer.concat([b.utf8("A"), b.utf8("B")]))])])))); }) === "c509/bad-extensions");
  // countryName / serialNumber carry a CHARACTER restriction (draft sec. 3.1.4 "SHALL contain only characters
  //   from the 74-character ASCII subset permitted by PrintableString"), NOT a sign override -- the sign still
  //   declares the string type, so the +N and -N encodings of one value must NOT reconstruct identical DER.
  check("283. an SDA countryName with the non-negative sign rides utf8String (the sign declares the type)", (function () { var e = pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(4n), CBb.array([CBb.textString("US")])])))).extensions[0]; var v = pki.asn1.decode(e.value).children[0].children[1].children[0]; return v.tagNumber === pki.asn1.TAGS.UTF8_STRING; })());
  check("283b. an SDA countryName whose characters leave the PrintableString subset -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(4n), CBb.array([CBb.textString("U@")])])))); }) === "c509/bad-extensions");
  check("284. a ~oid-form value byte string that is not well-formed DER -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.byteString(pki.asn1.encodeOidContent("1.2.3.4")), CBb.array([CBb.byteString(Buffer.from("04", "hex"))])])))); }) === "c509/bad-extensions");
  // 25. a native value invalid for its int-form string type (a printableString sign over a value with characters
  //     outside the PrintableString alphabet) fails in THIS module's domain (c509/bad-extensions), never leaking
  //     the b.printable Asn1Error (asn1/bad-printable-string) -- attacker-controlled native input, error-domain guard.
  check("285. a native subjectDirectoryAttributes value invalid for its PrintableString sign -> c509/bad-extensions (not asn1/*)", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(-10n), CBb.array([CBb.textString("a@b.example")])])))); }) === "c509/bad-extensions");
  // 26-28. a ~oid-form value must be a strict DER element, not merely well-framed: asn1.decode frames a reserved
  //         end-of-contents tag 0, an empty INTEGER, and an out-of-alphabet string, but a strict decoder rejects
  //         each -- the reconstruct must splice nothing such a decoder rejects (validate via the per-type reader).
  function sdaOidVal(hex) { return sdaVal(CBb.array([CBb.byteString(pki.asn1.encodeOidContent("1.2.3.4")), CBb.array([CBb.byteString(Buffer.from(hex, "hex"))])])); }
  check("286. a ~oid-form value that is the reserved end-of-contents encoding (tag 0) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("0000"))); }) === "c509/bad-extensions");
  check("287. a ~oid-form value that is an empty INTEGER -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("0200"))); }) === "c509/bad-extensions");
  check("288. a ~oid-form value that is an IA5String with a non-ASCII octet -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("1601ff"))); }) === "c509/bad-extensions");
  // a ~oid-form value that is a valid CONSTRUCTED DER element (a SEQUENCE) is a legitimately-typed ANY the codec
  //   has no single content reader for, so it passes on its framing and reconstructs (not every ANY is a string).
  check("289. a ~oid-form value that is a valid constructed DER element (SEQUENCE) is accepted as ANY + reconstructs", (function () { var e = pki.schema.c509.parse(mkExt(sdaOidVal("30020500"))).extensions[0]; if (e.name !== "subjectDirectoryAttributes") return false; var m = pki.asn1.decode(e.value).children[0].children[1].children[0]; return m.tagClass === "universal" && m.tagNumber === pki.asn1.TAGS.SEQUENCE; })());
  // a constructed ~oid value is recursively strict-validated: a malformed NESTED element (a SEQUENCE holding an
  //   empty INTEGER), and an out-of-order DER SET (X.690 sec. 11.6), each fail closed -- asn1.decode frames both.
  check("290. a ~oid-form constructed value with a nested malformed element (SEQUENCE with an empty INTEGER) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("30050200020101"))); }) === "c509/bad-extensions");
  check("291. a ~oid-form constructed value that is an unsorted DER SET -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("3106020102020101"))); }) === "c509/bad-extensions");
  // a universal primitive with NO strict content validator is rejected, not accepted on framing alone: asn1.decode
  //   frames a malformed NumericString (12 01 40, "@" is outside its alphabet) and a high-tag-number type happily.
  check("292. a ~oid-form value that is a MALFORMED NumericString -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("120140"))); }) === "c509/bad-extensions");
  // a VALID value of a type the codec can strictly validate stays usable -- an AttributeValue is ANY, so
  //   refusing every unhandled tag would reject conformant certificates (NumericString carries the X.520
  //   x121Address / internationalISDNNumber syntax).
  check("292b. a ~oid-form value that is a VALID NumericString is accepted + reconstructs", (function () { var e = pki.schema.c509.parse(mkExt(sdaOidVal("1203313233"))).extensions[0]; var v = pki.asn1.decode(e.value).children[0].children[1].children[0]; return v.tagNumber === pki.asn1.TAGS.NUMERIC_STRING && pki.asn1.read.numericString(v) === "123"; })());
  check("293. a ~oid-form value of a high-tag-number universal type -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("1f81000141"))); }) === "c509/bad-extensions");
  // a plain GeneralizedTime value rides the compact form; the X.690 sec. 11.7 fractional-seconds relaxation is
  //   deliberately scoped to the codec + RFC 3161 timestamping, so a fractional value is not compact-representable
  //   here and fails closed (on encode it degrades to the byte-exact ~oid form, losing nothing).
  check("294. a ~oid-form value that is a plain GeneralizedTime rides the compact form + reconstructs byte-exact", (function () {
    var s = "20260101000000Z", tlv = Buffer.concat([Buffer.from([0x18, s.length]), Buffer.from(s, "latin1")]);
    var e = pki.schema.c509.parse(mkExt(sdaOidVal(tlv.toString("hex")))).extensions[0];
    if (e.name !== "subjectDirectoryAttributes") return false;
    var v = pki.asn1.decode(e.value).children[0].children[1].children[0];
    return v.tagNumber === pki.asn1.TAGS.GENERALIZED_TIME && v.bytes.equals(tlv);
  })());
  check("294b. a ~oid-form fractional-seconds GeneralizedTime is not compact-representable -> c509/bad-extensions", (function () {
    var s = "20260101000000.5Z", tlv = Buffer.concat([Buffer.from([0x18, s.length]), Buffer.from(s, "latin1")]);
    return codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal(tlv.toString("hex")))); }) === "c509/bad-extensions";
  })());

  // ==== the shared strict-DER gate for every raw-spliced ANY value on the reconstruct path ====
  // AlgorithmIdentifier.parameters, a generic otherName's [0] EXPLICIT inner TLV, and a ~oid-form SDA
  // AttributeValue are all caller-supplied ANY bytes spliced verbatim. Framing alone (asn1.decode) admits an
  // empty INTEGER / reserved tag 0 / a non-minimal INTEGER, which reconstruct a certificate an independent
  // decoder refuses to load and this toolkit's own readers reject -- so all three route through one strict gate.
  function algField(paramsHex) { return "8248" + "2a8648ce3d040302" + (0x40 + paramsHex.length / 2).toString(16) + paramsHex; }
  check("295. type-3 algorithm parameters that are a framed-but-invalid DER element -> c509/non-invertible", codeSync(function () { return pki.schema.c509.parse(V.mk({ 2: algField("0200") })); }) === "c509/non-invertible");
  check("296. type-3 algorithm parameters that are a valid NULL still reconstruct (no over-rejection)", pki.schema.c509.parse(V.mk({ 2: algField("0500") })).reconstructedDer.length > 0);
  check("297. a generic otherName inner value that is a non-minimal INTEGER -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sanVal(0, CBb.array([CBb.byteString(Buffer.from("2b06010401", "hex")), CBb.byteString(Buffer.from("02020001", "hex"))])))); }) === "c509/bad-extensions");
  check("298. a ~oid-form value of a universal CONSTRUCTED type with no structure validator (EXTERNAL) -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("2800"))); }) === "c509/bad-extensions");
  // a nested SET's required order depends on a type the ANY does not carry (SET OF orders by octets, a structured
  //   SET by tag, and they differ across the constructed bit), so a value canonical under EITHER reading is
  //   accepted and only one canonical under NEITHER is refused -- a repeated tag proves SET OF, where octets bind.
  check("299. a ~oid-form SET ordered by TAG (a structured SET: SEQUENCE before PrintableString) is accepted", (function () { var e = pki.schema.c509.parse(mkExt(sdaOidVal("31053000130141"))).extensions[0]; return e.name === "subjectDirectoryAttributes" && e.value.length > 0; })());
  check("300. a ~oid-form SET ordered by OCTETS (the SET OF reading of the same members) is also accepted", (function () { var e = pki.schema.c509.parse(mkExt(sdaOidVal("31051301413000"))).extensions[0]; return e.name === "subjectDirectoryAttributes" && e.value.length > 0; })());
  // the declared attributeValue order must ALREADY be canonical: asn1.build.set sorts, so accepting a non-canonical
  //   order would silently rewrite it and let many distinct C509 encodings reconstruct one certificate.
  check("301. a subjectDirectoryAttributes attributeValue list in non-canonical order -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(10n), CBb.array([CBb.textString("B"), CBb.textString("A")])])))); }) === "c509/bad-extensions");
  // the c509CertificateType slot is guarded in this module's domain, never leaking the CBOR reader's fault.
  check("302. a non-integer c509CertificateType -> c509/bad-certificate-type (not cbor/*)", codeSync(function () { return pki.schema.c509.parse(V.mk({ 0: CB.build.textString("x").toString("hex") })); }) === "c509/bad-certificate-type");
  // tag order ranks by tag CLASS first (universal < application < context < private, X.680 sec. 8.6), so the
  //   comparison must use the class NUMBER -- the class NAMES do not sort in that order.
  check("303. a ~oid-form SET whose members ascend by tag CLASS (universal then context) is accepted", (function () { var e = pki.schema.c509.parse(mkExt(sdaOidVal("3106020101800141"))).extensions[0]; return e.name === "subjectDirectoryAttributes" && e.value.length > 0; })());
  check("304. a ~oid-form SET whose members descend by tag class AND octets -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaOidVal("3106800141020101"))); }) === "c509/bad-extensions");
  // emailAddress in a distinguished NAME rides the same sec. 8.6 int 0 / IA5String rule, in both directions:
  //   a certificate whose subject carries one encodes to the compact form and reconstructs byte-for-byte.
  var emailDnSigner = signing.makeSigner("ec-p256");
  var emailDnDer = Buffer.from(await pki.x509.sign({
    subject: [{ commonName: "mail leaf" }, { emailAddress: "a@b.example" }], subjectPublicKey: emailDnSigner.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: false } },
  }, { key: emailDnSigner.key }));
  check("305. a subject DN carrying an emailAddress encodes compactly and reconstructs byte-for-byte", (function () {
    var enc = encCp(emailDnDer);
    return pki.schema.c509.parse(enc).reconstructedDer.equals(emailDnDer) && pki.schema.c509.parse(enc).subject.dn.indexOf("a@b.example") >= 0;
  })());
  // an SDA emailAddress whose value is NOT an IA5String cannot use the int form (its type fixes the string type),
  //   so that attribute falls back to the per-attribute ~oid form and still double-inverts.
  var sdaEmailUtf8 = await certWithExts([sdaExt([sdaAttr("emailAddress", [b.utf8("a@b.example")])])]);
  var sdaEmailUtf8Enc = encCp(sdaEmailUtf8);
  check("306. an SDA emailAddress with a non-IA5String value uses the per-attribute ~oid form + double-inverts", (function () { var p = extPair(sdaEmailUtf8Enc, 24); return p != null && CB.decode(p.val.bytes).children[0].majorType === 2 && pki.schema.c509.parse(sdaEmailUtf8Enc).reconstructedDer.equals(sdaEmailUtf8); })());
  // a DN attribute whose string type contradicts its IA5-only-ness is refused with a precise verdict rather than
  //   encoded into an int form whose reconstruction would differ from the source bytes.
  function certWithDnAttr(attrOidName, valueTlv) {
    var hs = signing.makeSigner("ec-p256");
    var point = pki.asn1.read.bitString(pki.asn1.decode(hs.spki).children[1]).bytes;
    var nm = b.sequence([b.set([b.sequence([b.oid(O(attrOidName)), valueTlv])])]);
    var sigAlg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
    var tbs = b.sequence([b.explicit(0, b.integer(2n)), b.integer(1n), sigAlg, nm,
      b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), b.utcTime(new Date("2027-01-01T00:00:00Z"))]), nm,
      b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]), b.bitString(point, 0)]),
      b.explicit(3, b.sequence([b.sequence([b.oid(O("basicConstraints")), b.octetString(b.sequence([]))])]))]);
    var sig = b.sequence([b.integer(BigInt("0x01" + "00".repeat(31))), b.integer(BigInt("0x01" + "00".repeat(31)))]);
    return b.sequence([tbs, sigAlg, b.bitString(sig, 0)]);
  }
  // NOTE these assert the SPECIFIC verdict text, not just the code: without the attribute/string-type check the
  //   byte-exactness self-verify still throws c509/non-invertible, so a code-only assertion would pass either
  //   way and guard nothing. The message is what distinguishes the precise check from the generic mismatch.
  function encMsg(der) { try { pki.schema.c509.encode(der, { issuerCurve: "P-256" }); return "NO-THROW"; } catch (e) { return String(e.message || ""); } }
  check("307. a DN attribute carrying an IA5String value on a non-IA5-only type -> the sec. 8.6 int-form verdict", /attribute commonName carries a IA5String value/.test(encMsg(certWithDnAttr("commonName", b.ia5("leaf")))));
  check("308. a DN emailAddress carrying a non-IA5String value -> the sec. 8.6 int-form verdict", /attribute emailAddress carries a non-IA5String value/.test(encMsg(certWithDnAttr("emailAddress", b.utf8("a@b.example")))));
  // a native Name's (type, sign) pair DECLARES an X.509 string type, so its text must be valid for that type --
  //   checked at PARSE with the same builder the reconstruction uses, so a type-2 certificate (which never
  //   reconstructs) is held to the identical rule and the builder's asn1/* fault never reaches the parse surface.
  function nameField(intVal, text) { return CB.build.array([CB.build.int(BigInt(intVal)), CB.build.textString(text)]).toString("hex"); }
  var eAcute = String.fromCharCode(0xe9);
  check("309. a native Name emailAddress (int 0) with a non-ASCII value -> c509/bad-name (not asn1/*)", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: nameField(0, eAcute + "@b.example") })); }) === "c509/bad-name");
  check("310. a native Name printableString-sign attribute with a non-PrintableString value -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: nameField(-1, eAcute) })); }) === "c509/bad-name");
  check("311. a native Name countryName with a non-PrintableString value -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: nameField(-4, eAcute + "S") })); }) === "c509/bad-name");
  check("312. a native Name utf8String-sign attribute with a non-ASCII value stays valid", pki.schema.c509.parse(V.mk({ 6: nameField(1, eAcute) })).subject.dn === "CN=" + eAcute);
  // the tag-48 MAC SpecialText shortcut is only unambiguous for the BARE (always-commonName) Name form: inside the
  //   array form the attribute integer still declares the string type, so a MAC value rebuilds as THAT type.
  function macNameField(intVal) { return CB.build.array([CB.build.int(BigInt(intVal)), CB.build.tag(48, CB.build.byteString(Buffer.from("0123456789AB", "hex")))]).toString("hex"); }
  function dnValueTag(intVal) {
    var recon = pki.schema.c509.parse(V.mk({ 6: macNameField(intVal) })).reconstructedDer;
    return pki.asn1.decode(recon).children[0].children[5].children[0].children[0].children[1].tagNumber;
  }
  check("313. a tag-48 MAC value under emailAddress rebuilds as an IA5String (its declared type)", dnValueTag(0) === pki.asn1.TAGS.IA5_STRING);
  check("314. a tag-48 MAC value under a printableString-sign attribute rebuilds as a PrintableString", dnValueTag(-1) === pki.asn1.TAGS.PRINTABLE_STRING);
  check("315. a tag-48 MAC value under commonName still rebuilds as a UTF8String", dnValueTag(1) === pki.asn1.TAGS.UTF8_STRING);
  // an attribute's registered ASN.1 type carries a SIZE constraint as well as an alphabet: every
  //   DirectoryString-valued attribute and emailAddress are SIZE (1..MAX), and countryName SHALL have length 2
  //   (draft sec. 3.1.4 / X.520). Enforced in the one place the value is built, so DN and SDA cannot disagree.
  check("316. a native Name countryName whose value is not length 2 -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: nameField(-4, "USA") })); }) === "c509/bad-name");
  check("317. a native Name attribute with an empty value -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: nameField(1, "") })); }) === "c509/bad-name");
  check("318. a native Name countryName of length 2 stays valid", pki.schema.c509.parse(V.mk({ 6: nameField(-4, "US") })).subject.dn === "C=US");
  check("319. an SDA countryName whose value is not length 2 -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(-4n), CBb.array([CBb.textString("USA")])])))); }) === "c509/bad-extensions");
  check("320. an SDA emailAddress with an empty value -> c509/bad-extensions", codeSync(function () { return pki.schema.c509.parse(mkExt(sdaVal(CBb.array([CBb.int(0n), CBb.array([CBb.textString("")])])))); }) === "c509/bad-extensions");
  // symmetry: a certificate carrying such a value still ENCODES -- the extension degrades to the byte-exact
  //   ~oid form rather than emitting a compact value this decoder would reject.
  var sdaBadCountry = await certWithExts([sdaExt([sdaAttr("countryName", [b.printable("USA")])])]);
  check("321. an SDA countryName outside its SIZE falls back to the ~oid form on encode + double-inverts", fellBack(sdaBadCountry, 24));
  // the BARE single-commonName Name form is held to the same value rules as the array form -- proven on a
  //   NATIVELY-SIGNED (type-2) certificate, which never reconstructs and so is the path a decode-time check must
  //   cover; the array form alone would leave it unguarded.
  var t2Fields = CB.decode(V.A1.type2).children.map(function (c) { return c.bytes.toString("hex"); });
  function type2WithSubject(hex) { var g = t2Fields.slice(); g[6] = hex; return Buffer.from("8b" + g.join(""), "hex"); }
  check("322. a type-2 bare-form Name with an empty commonName -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(type2WithSubject(CB.build.textString("").toString("hex"))); }) === "c509/bad-name");
  check("323. a type-2 bare-form Name with an empty byte-string value -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(type2WithSubject(CB.build.byteString(Buffer.alloc(0)).toString("hex"))); }) === "c509/bad-name");
  check("324. a type-2 bare-form Name with a normal commonName stays valid", pki.schema.c509.parse(type2WithSubject(CB.build.textString("ok").toString("hex"))).subject.dn === "CN=ok");
  check("325. a type-2 bare-form tag-48 MAC commonName stays valid", pki.schema.c509.parse(type2WithSubject(CB.build.tag(48, CB.build.byteString(Buffer.from("0123456789AB", "hex"))).toString("hex"))).subject.eui64 != null);
  // The X.520 ub-* attribute MAXIMA are deliberately NOT enforced: pki.x509.sign issues, and pki.schema.x509.parse
  //   reads, a commonName longer than ub-common-name (64), so refusing one here would make encode reject a
  //   certificate this toolkit itself mints. Only the unambiguous bounds (non-empty, countryName exactly 2) bind.
  check("326. a commonName longer than the X.520 ub-common-name still parses (the maxima are not relying-party rejects)", pki.schema.c509.parse(V.mk({ 6: nameField(1, "A".repeat(70)) })).subject.dn === "CN=" + "A".repeat(70));
  // draft sec. 3.1.4: "in natively signed C509 certificates all CBOR ints SHALL be non-negative". The sign only
  //   exists to reproduce an original DER's string type, which a native certificate does not have.
  check("327. a type-2 Name attribute type integer that is negative -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(type2WithSubject(nameField(-1, "RFC test CA"))); }) === "c509/bad-name");
  check("328. a type-2 Name attribute type integer that is non-negative stays valid", pki.schema.c509.parse(type2WithSubject(nameField(1, "RFC test CA"))).subject.dn === "CN=RFC test CA");
  check("329. a type-3 Name attribute type integer may be negative (it selects printableString)", pki.schema.c509.parse(V.mk({ 6: nameField(-1, "x") })).subject.dn === "CN=x");
  // the sign DECLARES the string type for countryName/serialNumber too, so the +N and -N encodings of one value
  //   must reconstruct DIFFERENT DER -- otherwise one X.509 signature would cover two distinct C509 encodings.
  check("330. countryName +4 and -4 reconstruct DIFFERENT DER (no encoding malleability)", (function () {
    function valueTag(i) { var r = pki.schema.c509.parse(V.mk({ 6: nameField(i, "SE") })); return pki.asn1.decode(r.reconstructedDer).children[0].children[5].children[0].children[0].children[1].tagNumber; }
    return valueTag(-4) === pki.asn1.TAGS.PRINTABLE_STRING && valueTag(4) === pki.asn1.TAGS.UTF8_STRING;
  })());
  check("331. a countryName whose characters leave the PrintableString subset -> c509/bad-name regardless of sign", codeSync(function () { return pki.schema.c509.parse(V.mk({ 6: nameField(4, "S@") })); }) === "c509/bad-name");
  // the rendered dn is an RFC 4514 string: every value is escaped through the shared guard, so a single
  //   attribute containing a comma cannot render identically to a genuine multi-RDN name, and the string
  //   agrees with what x509.parse renders for the very same reconstructed DER.
  var dnSpoof = pki.schema.c509.parse(V.mk({ 6: nameField(1, "Good CA,O=Trusted") }));
  var dnTwoRdn = pki.schema.c509.parse(V.mk({ 6: CB.build.array([CB.build.int(1n), CB.build.textString("Good CA"), CB.build.int(8n), CB.build.textString("Trusted")]).toString("hex") }));
  check("332. a comma inside one attribute value is escaped, not confusable with a two-RDN name", dnSpoof.subject.dn !== dnTwoRdn.subject.dn && dnSpoof.subject.dn.indexOf("\\,") >= 0);
  check("333. the escaped VALUE matches what x509.parse renders for the same reconstructed DER", (function () { var x = pki.schema.x509.parse(dnSpoof.reconstructedDer).subject.dn; return x.indexOf("Good CA\\,O=Trusted") >= 0 && dnSpoof.subject.dn.indexOf("Good CA\\,O=Trusted") >= 0; })());
  // RFC 5280 sec. 4.1.2.4: the ISSUER must be a non-empty distinguished name (only the subject may be empty).
  //   Accepting an empty issuer produced a reconstructedDer this toolkit's OWN x509.parse refuses to load.
  check("335. an empty issuer Name -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 3: CB.build.array([]).toString("hex") })); }) === "c509/bad-name");
  // (the profile pairs an empty subject with a subjectAltName; this codec does not yet require that pairing,
  //  so this pins only that an empty subject is not rejected outright and still rebuilds a loadable certificate)
  check("336. an empty SUBJECT Name is not rejected and its reconstruction re-parses", (function () { var r = pki.schema.c509.parse(V.mk({ 6: CB.build.array([]).toString("hex") })); pki.schema.x509.parse(r.reconstructedDer); return true; })());
  // draft sec. 3.1.4 binds EVERY int in a natively signed certificate, so the rule must reach every NESTED Name
  //   too -- the sec. 8.13 directoryName inside subjectAltName / nameConstraints / authorityKeyIdentifier /
  //   cRLDistributionPoints, and the subjectDirectoryAttributes int form -- not only the top-level issuer/subject.
  var CBb2 = CB.build;
  function gnFlat(sign) { return [CBb2.int(4n), CBb2.array([CBb2.int(BigInt(sign)), CBb2.textString("evil")])]; }
  function nestedExt(kind, sign) {
    if (kind === "san") return CBb2.array([CBb2.int(3n), CBb2.array(gnFlat(sign))]).toString("hex");
    if (kind === "nc") return CBb2.array([CBb2.int(26n), CBb2.array([CBb2.array(gnFlat(sign)), CBb2.nullValue()])]).toString("hex");
    if (kind === "aki") return CBb2.array([CBb2.int(7n), CBb2.array([CBb2.byteString(Buffer.from("aabb", "hex")), CBb2.array(gnFlat(sign)), CBb2.byteString(Buffer.from("01", "hex"))])]).toString("hex");
    if (kind === "crldp") return CBb2.array([CBb2.int(5n), CBb2.array([CBb2.array([CBb2.textString("http://x/c.crl"), CBb2.nullValue(), CBb2.array([CBb2.int(BigInt(sign)), CBb2.textString("evil")])])])]).toString("hex");
    return CBb2.array([CBb2.int(24n), CBb2.array([CBb2.int(BigInt(sign < 0 ? -4 : 4)), CBb2.array([CBb2.textString("SE")])])]).toString("hex");
  }
  function type2WithExts(hex) { var g = t2Fields.slice(); g[9] = hex; return Buffer.from("8b" + g.join(""), "hex"); }
  ["san", "nc", "aki", "crldp", "sda"].forEach(function (kind, i) {
    check("337." + String.fromCharCode(97 + i) + " a type-2 negative attribute integer in a nested Name (" + kind + ") is rejected", /^c509\/bad-(name|extensions)$/.test(codeSync(function () { return pki.schema.c509.parse(type2WithExts(nestedExt(kind, -1))); })));
    check("338." + String.fromCharCode(97 + i) + " the same nested Name with a non-negative integer stays valid in a type-2 (" + kind + ")", codeSync(function () { return pki.schema.c509.parse(type2WithExts(nestedExt(kind, 1))); }) === "NO-THROW");
    check("339." + String.fromCharCode(97 + i) + " a type-3 may still carry the negative integer there (it selects printableString) (" + kind + ")", codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: nestedExt(kind, -1) })); }) === "NO-THROW");
  });
  // the empty-issuer rule binds the EFFECTIVE issuer: a CBOR-null issuer means issuer == subject.
  check("340. a self-signed C509 (null issuer) with an empty subject -> c509/bad-name", codeSync(function () { return pki.schema.c509.parse(V.mk({ 3: "f6", 6: "80" })); }) === "c509/bad-name");
  check("334. a control byte in a name value is escaped in the rendered dn (never emitted raw)", (function () { var d = pki.schema.c509.parse(V.mk({ 6: nameField(1, "a" + String.fromCharCode(13) + "b") })).subject.dn; return d.indexOf(String.fromCharCode(13)) < 0 && d.indexOf("\\0D") >= 0; })());

  // ==== RFC 3779 IPAddrBlocks / ASIdentifiers (ext ints 32-35, draft sec. 3.3) =================
  // The draft ships a complete worked vector for these in Appendix A.5, so the encode side is
  // pinned to the SPECIFICATION's own published CBOR rather than to this codec's own output.
  var CBB = pki.cbor.build;
  function ipBs(hex, unused) { return vB.bitString(Buffer.from(hex, "hex"), unused); }
  function r3779Ext(name, value, critical) {
    var f = [vB.oid(vO(name))];
    if (critical) f.push(vB.boolean(true));
    f.push(vB.octetString(value));
    return vB.sequence(f);
  }
  async function r3779Enc(extDer) {
    var der = Buffer.from(await pki.x509.sign({ subject: [{ commonName: "rfc3779" }], subjectPublicKey: vk.spki,
      notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: [extDer] }, { key: vk.key }));
    var enc = pki.schema.c509.encode(der);
    var kids = pki.cbor.decode(enc).children[9].children;
    return { der: der, enc: enc, id: kids[0], val: kids[1],
             exact: pki.schema.c509.parse(enc).reconstructedDer.equals(der) };
  }
  // An extension identifier is an int only while the compact form applies; on fallback it is the
  // ~oid byte string. Reading it with cbor.read.int directly would THROW on a regression and abort
  // the whole run, hiding every later check -- so a fallback reports null and the check just fails.
  function extIdInt(n) { return (n && (n.majorType === 0 || n.majorType === 1)) ? Number(pki.cbor.read.int(n)) : null; }
  function cborShape(n) {
    if (n.majorType === 7) return "null";
    if (n.majorType === 2) return "h" + n.content.toString("hex");
    if (n.majorType === 4) return "[" + (n.children || []).map(cborShape).join(", ") + "]";
    return pki.cbor.read.int(n).toString();
  }
  // Appendix A.5's own IPAddrBlocks: IPv4 (192.0.2.0/24, 198.51.100.0/28, 203.0.113.0/24) and
  // IPv6 (2001:db8:1234::/48 plus a range) -- int form, absent SAFI, and a nested range.
  var a5Fam4 = vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("c00002", 0), ipBs("c6336400", 4), ipBs("cb0071", 0)])]);
  var a5Fam6 = vB.sequence([vB.octetString(Buffer.from("0002", "hex")),
    vB.sequence([ipBs("20010db81234", 0), vB.sequence([ipBs("3fff06", 0), ipBs("3fff0f", 0)])])]);
  var a5 = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([a5Fam4, a5Fam6])));
  check("341. an IPAddrBlocks extension rides compact int 32", extIdInt(a5.id) === 32);
  check("342. its CBOR value is identical to the draft Appendix A.5 diagnostic",
    cborShape(a5.val) === "[1, null, [29360130, 24770733054, -24770012047], 2, null, [316663873933876, [-316663852962606, 9]]]");
  check("343. the A.5 certificate reconstructs byte-for-byte", a5.exact);
  // IPAddressFamily is a parenthesized CDDL group, so the triples splice FLAT, never nest.
  check("344. the value is one flat array of (AFI, SAFI, choice) triples", a5.val.majorType === 4 && a5.val.children.length === 6);
  var inh = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")), vB.nullValue()])])));
  check("345. an inherit address family encodes as null", cborShape(inh.val) === "[1, null, null]" && inh.exact);
  // One sequence past 8 octets selects the bytes form for the WHOLE family (sec. 3.3, a SHALL).
  var byt = await r3779Enc(r3779Ext("ipAddrBlocksV2", vB.sequence([vB.sequence([vB.octetString(Buffer.from("000201", "hex")),
    vB.sequence([ipBs("20010db8123456780000", 0)])])])));
  check("346. a present SAFI is carried and a >8-octet address selects the bytes form",
    extIdInt(byt.id) === 34 && cborShape(byt.val) === "[2, 1, [h0020010db8123456780000]]" && byt.exact);
  var asr = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(64496n), vB.sequence([vB.integer(64500n), vB.integer(64510n)])]))])));
  check("347. ASIdentifiers carries an id and a range, delta-coded", extIdInt(asr.id) === 33 && cborShape(asr.val) === "[64496, [4, 10]]" && asr.exact);
  var asi = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.nullValue())])));
  check("348. an ASIdentifiers asnum inherit encodes as null", cborShape(asi.val) === "null" && asi.exact);
  // RFC 3779 says both extensions SHOULD be critical, so the negative-int arm is the common case.
  var asc = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(64496n)]))]), true));
  check("349. a critical RFC 3779 extension carries the negative int", extIdInt(asc.id) === -33 && asc.exact);
  var asv2 = await r3779Enc(r3779Ext("autonomousSysIdsV2", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(7n)]))])));
  check("350. the RFC 8360 v2 twin rides int 35 through the same codec", extIdInt(asv2.id) === 35 && asv2.exact);

  // A shape the compact form cannot carry EXACTLY falls back to the ~oid byte-string form with the
  // original bytes intact -- it is never "corrected" into a conforming one, which would change the
  // bytes the signature covers and hide the defect from a validator.
  function r3779FellBack(r) { return r.id.majorType === 2 && r.exact; }
  var ord = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("0a40", 0), ipBs("0a20", 4)])])])));
  check("351. a non-ascending address list falls back, bytes preserved", r3779FellBack(ord));
  var ord2 = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("0a20", 4), ipBs("0a40", 0)])])])));
  check("352. the same two addresses in RFC 3779 order DO compact", extIdInt(ord2.id) === 32 && ord2.exact);
  // Sorting is only one third of the canonical form. RFC 3779 sec. 2.2.3.6 also forbids any pair of
  // entries OVERLAPPING and requires any CONTIGUOUS pair to have been combined already. All three
  // bind together, so an address list is compacted only when it satisfies every one -- otherwise
  // the compact form would be a second encoding of an address set that already has a canonical one.
  // 10.0.0.0/8 then 10.0.0.0/16 ascends by the sort key yet the second is contained in the first;
  // OpenSSL's own validator refuses it, so compacting it would launder a rejected certificate.
  var ovl = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("0a", 0), ipBs("0a00", 0)])])])));
  check("352a. an address list where one entry contains another falls back (no overlap)", r3779FellBack(ovl));
  // 10.0.0.0/8 and 10.0.0.0/16 share a LOW address, so the strictly-ascending test already rejects
  // them and the overlap test is never reached. A containment with a DIFFERING low address is the
  // only shape that isolates it: 10.1.0.0/16 sorts after 10.0.0.0/8 yet lies inside it.
  var ovl2 = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("0a", 0), ipBs("0a01", 0)])])])));
  check("352a1. an ascending entry that still lies inside the previous one falls back", r3779FellBack(ovl2));
  // ... and two genuinely disjoint, non-contiguous prefixes are unaffected by all three tests.
  var disj = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("0a00", 7), ipBs("0b", 0)])])])));
  check("352a2. two disjoint non-contiguous prefixes still compact", extIdInt(disj.id) === 32 && disj.exact);
  // A range whose min is above its max denotes no addresses at all; it is not representable as a
  // canonical entry, so the family declines rather than compacting an empty span.
  var revRange = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([vB.sequence([ipBs("0a40", 0), ipBs("0a20", 0)])])])])));
  check("352a3. a range whose min exceeds its max falls back", r3779FellBack(revRange));
  // 10.0.0.0/9 and 10.128.0.0/9 abut exactly, so they were required to be one /8.
  var adj = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0001", "hex")),
    vB.sequence([ipBs("0a00", 7), ipBs("0a80", 7)])])])));
  check("352b. two contiguous prefixes fall back (they had to be merged)", r3779FellBack(adj));
  // The canonical form cannot be checked for an address family whose width this codec does not
  // know, so such a family declines rather than compacting something unverifiable.
  var unkAfi = await r3779Enc(r3779Ext("ipAddrBlocks", vB.sequence([vB.sequence([vB.octetString(Buffer.from("0063", "hex")),
    vB.sequence([ipBs("0a20", 4)])])])));
  check("352c. an address family of unknown width falls back", r3779FellBack(unkAfi));

  var rdi = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(1n)])), vB.explicit(1, vB.sequence([vB.integer(2n)]))])));
  check("353. a present rdi has no compact form and falls back (sec. 3.3)", r3779FellBack(rdi));
  // RFC 3779 sec. 3.2.3.4 imposes the same three rules on AS identifiers, and they must hold ACROSS
  // members: checking only within a range would admit a descending or contiguous pair.
  var asDesc = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(64700n), vB.integer(64500n)]))])));
  check("353a. a descending AS list falls back (sorted by increasing value)", r3779FellBack(asDesc));
  var asAdj = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(64500n), vB.integer(64501n)]))])));
  check("353b. two contiguous AS ids fall back (they had to be one range)", r3779FellBack(asAdj));
  var asDup = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(64500n), vB.integer(64500n)]))])));
  check("353c. a duplicated AS id falls back (no overlap)", r3779FellBack(asDup));
  var asOvl = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.sequence([vB.integer(100n), vB.integer(200n)]), vB.integer(150n)]))])));
  check("353d. an AS id inside the previous range falls back", r3779FellBack(asOvl));
  // ... and a genuinely canonical list still compacts, so the gates are not simply refusing everything.
  var asOk = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.sequence([vB.integer(100n), vB.integer(200n)]), vB.integer(202n)]))])));
  check("353e. a sorted, non-overlapping, non-contiguous AS list still compacts", extIdInt(asOk.id) === 33 && asOk.exact);
  var bigAs = await r3779Enc(r3779Ext("autonomousSysIds", vB.sequence([vB.explicit(0, vB.sequence([vB.integer(4294967296n)]))])));
  check("354. an ASId past 2^32-1 falls back rather than being truncated", r3779FellBack(bigAs));

  // Decode side. The form choice is a SHALL, so accepting the wrong one would give one DER two CBOR
  // encodings; every reject below is a malleability or bounds gate on attacker-supplied CBOR.
  function extsHex(items) { return CBB.array(items).toString("hex"); }
  function r3779Reject(hex) { return codeSync(function () { return pki.schema.c509.parse(V.mk({ 9: hex })); }); }
  check("355. a bytes-form family whose addresses all fit 8 octets -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.byteString(Buffer.from("00c00002", "hex"))])])])) === "c509/bad-extensions");
  // The mixed member must EXCEED 8 octets, otherwise the "all fit 8 -> the int form was required"
  // gate above fires first and this vector would pass without the mixed-form check existing at all.
  check("356. a family mixing the int and bytes forms -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(29360130n), CBB.byteString(Buffer.from("0020010db8123456780000", "hex"))])])])) === "c509/bad-extensions");
  check("357. a triple count that is not a multiple of three -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue()])])) === "c509/bad-extensions");
  check("358. an empty IPAddrBlocks array -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([])])) === "c509/bad-extensions");
  check("359. an empty address choice -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([])])])) === "c509/bad-extensions");
  check("360. an AFI past two octets -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(65536n), CBB.nullValue(), CBB.array([CBB.uint(29360130n)])])])) === "c509/bad-extensions");
  // The integer is (unusedBits + 1) || value, so its leading octet must be 1..8; zero is not one.
  check("361. an IPAddress integer of zero -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(0n)])])])) === "c509/bad-extensions");
  // The bound is on the reconstructed ABSOLUTE, not the delta -- a chain can step out of range.
  check("362. a delta chain that walks below one -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(29360130n), CBB.int(-29360130n)])])])) === "c509/bad-extensions");
  check("363. an empty ASIdentifiers array -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([])])) === "c509/bad-extensions");
  // The DECODE-side ASId bound. Check 354 covers the encode direction, which has its own bound --
  // without these two, removing the decode bound changes nothing.
  // An address may not be wider than its family (RFC 3779 sec. 2.2.3.8). Both forms and both
  // directions bound it -- without the decode-side bound a native C509 would reconstruct into a DER
  // carrying an over-wide address, from CBOR this codec had accepted.
  check("362a. an over-wide address under AFI 1, int form -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(BigInt("0x01c0000201ff"))])])])) === "c509/bad-extensions");
  check("362b. an over-wide address under AFI 1, bytes form -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.byteString(Buffer.from("0020010db8123456780000", "hex"))])])])) === "c509/bad-extensions");
  check("362c. the same widths are legal under AFI 2 (IPv6)",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(2n), CBB.nullValue(), CBB.array([CBB.byteString(Buffer.from("0020010db8123456780000", "hex"))])])])) === "NO-THROW");
  // A CBOR major type 7 is the WHOLE simple/float space -- true, false, undefined, every simple
  // value and every float head. Only the simple value null (0xf6) means inherit, so testing the
  // major type alone would let six distinct encodings reconstruct one identical certificate, all
  // valid under its single signature. Every other null test in this module pins the simple value.
  function inheritWith(simpleByte) {
    return Buffer.concat([Buffer.from([0x82, 0x18, 0x20, 0x83, 0x01]), Buffer.from([simpleByte]), Buffer.from([0xf6])]).toString("hex");
  }
  check("362d. the canonical null (0xf6) is accepted in the SAFI slot", r3779Reject(inheritWith(0xf6)) === "NO-THROW");
  check("362e. no other CBOR simple value passes as null", [0xf4, 0xf5, 0xf7, 0xf0].every(function (v) {
    return r3779Reject(inheritWith(v)) === "c509/bad-extensions";
  }));
  // The SAFI slot is read first, so the same probe there would never reach the address-choice slot.
  // This puts a canonical null in SAFI and the impostor in the CHOICE slot, isolating that test.
  function choiceWith(simpleByte) {
    return Buffer.concat([Buffer.from([0x82, 0x18, 0x20, 0x83, 0x01, 0xf6]), Buffer.from([simpleByte])]).toString("hex");
  }
  check("362e1. the address-choice slot accepts only the canonical null",
    r3779Reject(choiceWith(0xf6)) === "NO-THROW" && [0xf4, 0xf5, 0xf7, 0xf0].every(function (v) {
      return r3779Reject(choiceWith(v)) === "c509/bad-extensions";
    }));
  // The DECODE direction must enforce the same RFC 3779 canonical form the encode direction does,
  // or a native C509 reconstructs a certificate an independent validator refuses -- from CBOR this
  // codec had accepted. Both directions must hold or the pair is not a bijection.
  // The ASIdentifiers value slot has its own inherit test, so it needs its own probe.
  function asnumWith(simpleByte) {
    return Buffer.concat([Buffer.from([0x82, 0x18, 0x21]), Buffer.from([simpleByte])]).toString("hex");
  }
  check("362e2. the ASIdentifiers slot accepts only the canonical null",
    r3779Reject(asnumWith(0xf6)) === "NO-THROW" && [0xf4, 0xf5, 0xf7, 0xf0].every(function (v) {
      return r3779Reject(asnumWith(v)) === "c509/bad-extensions";
    }));
  // RFC 3779 sec. 2.2.3.3 orders the FAMILIES too: unique per AFI/SAFI, ascending by addressFamily
  // octets, and a family without a SAFI precedes the one sharing its AFI. An unsigned octet-string
  // compare gives all three, because the two-octet form is a prefix of the three-octet one.
  function fams(triples) { return extsHex([CBB.uint(32n), CBB.array(triples)]); }
  var NUL = CBB.nullValue();
  check("362o. address families in descending order are refused",
    r3779Reject(fams([CBB.uint(2n), NUL, NUL, CBB.uint(1n), NUL, NUL])) === "c509/bad-extensions");
  check("362p. the same address family twice is refused",
    r3779Reject(fams([CBB.uint(1n), NUL, NUL, CBB.uint(1n), NUL, NUL])) === "c509/bad-extensions");
  check("362q. a SAFI-bearing family before the plain one sharing its AFI is refused",
    r3779Reject(fams([CBB.uint(1n), CBB.uint(1n), NUL, CBB.uint(1n), NUL, NUL])) === "c509/bad-extensions");
  check("362r. ascending families are accepted",
    r3779Reject(fams([CBB.uint(1n), NUL, NUL, CBB.uint(2n), NUL, NUL])) === "NO-THROW");
  check("362s. a plain family before the SAFI-bearing one sharing its AFI is accepted",
    r3779Reject(fams([CBB.uint(1n), NUL, NUL, CBB.uint(1n), CBB.uint(1n), NUL])) === "NO-THROW");
  check("362f. a descending address list is refused on decode",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(0x010a40n), CBB.uint(0x03FFE0n)])])])) === "c509/bad-extensions");
  check("362g. an overlapping address list is refused on decode",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(0x01n), CBB.uint(0x109n)])])])) === "c509/bad-extensions");
  check("362h. a contiguous address pair is refused on decode",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(0x080a00n), CBB.uint(0x80n)])])])) === "c509/bad-extensions");
  // The draft's CDDL makes the AS deltas uint precisely because sec. 3.2.3.4 sorts ascending.
  check("362i. a negative AS delta is refused on decode",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.uint(64700n), CBB.int(-200n)])])) === "c509/bad-extensions");
  check("362j. a duplicated AS id is refused on decode",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.uint(64500n), CBB.uint(0n)])])) === "c509/bad-extensions");
  check("362k. a contiguous AS pair is refused on decode",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.uint(64500n), CBB.uint(1n)])])) === "c509/bad-extensions");
  check("362l. a canonical AS list still decodes",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.uint(64500n), CBB.uint(2n)])])) === "NO-THROW");
  // DER requires a BIT STRING's declared unused bits to be zero. Enforced in this module so the
  // caller sees its verdict rather than an asn1/* fault surfacing out of a CBOR-layer decode.
  check("362m. an address whose declared unused bits are set -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(0x050a2fn)])])])) === "c509/bad-extensions");
  check("362n. the same address with those bits cleared is accepted",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(0x050a20n)])])])) === "NO-THROW");
  check("363a. a decoded ASId past 2^32-1 -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.uint(4294967296n)])])) === "c509/bad-extensions");
  check("363b. an AS delta chain that steps past 2^32-1 -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.uint(4000000000n), CBB.uint(1000000000n)])])) === "c509/bad-extensions");
  check("364. a non-ascending ASIdentifiers range -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(33n), CBB.array([CBB.array([CBB.uint(100n), CBB.uint(0n)])])])) === "c509/bad-extensions");
  check("365. the A.5 IPv4 family parses from a native C509",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(29360130n), CBB.uint(24770733054n), CBB.int(-24770012047n)])])])) === "NO-THROW");
  // The int domain reaches 2^64-1, so a Number narrowing anywhere in the chain would corrupt it.
  // The leading octet IS the unused-bit count + 1, so it must be 1..8; 0xFF is not a DER one.
  check("366. an IPAddress integer whose leading octet is not 1..8 -> c509/bad-extensions",
    r3779Reject(extsHex([CBB.uint(32n), CBB.array([CBB.uint(1n), CBB.nullValue(), CBB.array([CBB.uint(72057594037927935n)])])])) === "c509/bad-extensions");
  // 0x0120010db8123456 is a valid 7-octet IPv6 prefix and is well past 2^53, so any Number
  // narrowing in the delta chain or the bound would corrupt it before it reached the DER.
  check("366a. an IPAddress integer past 2^53 reconstructs without narrowing", (function () {
    var v = BigInt("0x0120010db8123456");
    var big = pki.schema.c509.parse(V.mk({ 9: extsHex([CBB.uint(32n), CBB.array([CBB.uint(2n), CBB.nullValue(), CBB.array([CBB.uint(v)])])]) }));
    return v > 9007199254740991n && Buffer.isBuffer(big.reconstructedDer);
  })());
  check("367. all four RFC 3779 OIDs round-trip through the registry",
    pki.oid.byName("ipAddrBlocks") === "1.3.6.1.5.5.7.1.7" && pki.oid.name("1.3.6.1.5.5.7.1.8") === "autonomousSysIds" &&
    pki.oid.byName("ipAddrBlocksV2") === "1.3.6.1.5.5.7.1.28" && pki.oid.name("1.3.6.1.5.5.7.1.29") === "autonomousSysIdsV2");

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
