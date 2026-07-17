// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Byte-exact C509 known-answer vectors from draft-ietf-cose-cbor-encoded-cert-20 Appendix A.1
// (the RFC 7925 profiled certificate). A.1.1 is the type-3 CBOR-re-encoding of the DER X.509 cert;
// A.1.2 is the type-2 natively-signed form. The DER is the original 316-byte certificate the type-3
// form must reconstruct byte-for-byte so the original ECDSA signature verifies.
function hex(s) { return Buffer.from(s.replace(/\s+/g, ""), "hex"); }

// The original DER-encoded X.509 certificate (Appendix A.1, 316 bytes).
var DER_A1 = hex(
  "308201383081dea003020102020301f50d300a06082a8648ce3d04030230163114301206" +
  "035504030c0b5246432074657374204341301e170d3233303130313030303030305a170d" +
  "3236303130313030303030305a30223120301e06035504030c1730312d32332d34352d46" +
  "462d46452d36372d38392d41423059301306072a8648ce3d020106082a8648ce3d030107" +
  "03420004b1216ab96e5b3b3340f5bdf02e693f16213a04525ed44450b1019c2dfd3838ab" +
  "ac4e14d86c0983ed5e9eef2448c6861cc406547177e6026030d051f7792ac206a30f300d" +
  "300b0603551d0f040403020780300a06082a8648ce3d0403020349003046022100d4320b" +
  "1d6849e309219d30037e138166f2508247dddae76cceea55053c108e90022100d551f6d6" +
  "0106f1abb484cfbe6256c178e4ac3314ea19191e8b607da5ae3bda16");

// A.1.1 -- the type-3 C509 certificate (141 bytes). Field 8 (subjectPublicKey) uses the C509 0xFE
// point-compression marker (an uncompressed EC point re-encoded compressed).
var C509_A1_TYPE3 = hex(
  "8B" +                                 // array(11)
  "03" +                                 // c509CertificateType = 3 (CBOR re-encoded X.509)
  "4301F50D" +                           // certificateSerialNumber ~biguint = 0x01F50D
  "00" +                                 // issuerSignatureAlgorithm int 0 = ecdsa-with-SHA256
  "6B 52464320746573742043 41" +         // issuer "RFC test CA"
  "1A 63B0CD00" +                        // validityNotBefore ~time = 1672531200 (2023-01-01)
  "1A 6955B900" +                        // validityNotAfter  ~time = 1767225600 (2026-01-01)
  "D830 46 0123456789AB" +               // subject tag(48) EUI-64 0123456789AB
  "01" +                                 // subjectPublicKeyAlgorithm int 1 = EC secp256r1
  "5821 FE B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB" +   // subjectPublicKey (0xFE marker + 32-byte x)
  "01" +                                 // extensions int 1 = non-critical keyUsage digitalSignature
  "5840 D4320B1D6849E309219D30037E138166F2508247DDDAE76CCEEA55053C108E90D551F6D60106F1ABB484CFBE6256C178E4AC3314EA19191E8B607DA5AE3BDA16");   // issuerSignatureValue (64-byte r||s)

// A.1.2 -- the type-2 natively-signed C509 certificate (141 bytes). Identical except type=2, the SEC1
// 0x02 point-compression prefix, and the native signature over the CBOR sequence of elements 0..9.
var C509_A1_TYPE2 = hex(
  "8B" +
  "02" +
  "4301F50D" +
  "00" +
  "6B 52464320746573742043 41" +
  "1A 63B0CD00" +
  "1A 6955B900" +
  "D830 46 0123456789AB" +
  "01" +
  "5821 02 B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB" +
  "01" +
  "5840 EB0D472731F689BC00F5880B12C68B3F9FD38B23FADFCA20950F3F241B60A202579CAC28CD3B7494D5FA5D8BBAB4600357E550AB9FA9A65D9BA2B3B82E668CC6");

// The 11 field encodings of the A.1 type-3 certificate, DERIVED from the decoded byte-exact fixture
// (each child's raw bytes) so a coverage vector can override one field and rebuild a valid-framed C509
// array without any hand-transcription risk (the fixtures are assembled from the decoded field bytes).
var _cborDet = require("../../lib/cbor-det");
var A1_FIELDS = _cborDet.decode(C509_A1_TYPE3).children.map(function (c) { return c.bytes.toString("hex"); });
// mk(overrides) -> a C509 CBOR array (0x8b array(11)) with the given zero-based field hex overridden.
function mk(overrides) {
  var f = A1_FIELDS.slice();
  Object.keys(overrides || {}).forEach(function (k) { f[Number(k)] = overrides[k]; });
  return hex("8b" + f.join(""));
}

module.exports = {
  hex: hex,
  mk: mk,
  A1: {
    der: DER_A1,
    type3: C509_A1_TYPE3,
    type2: C509_A1_TYPE2,
    serialHex: "01f50d",
    issuerDn: "CN=RFC test CA",
    subjectEui64: Buffer.from("0123456789AB", "hex"),
    notBefore: new Date("2023-01-01T00:00:00Z"),
    notAfter: new Date("2026-01-01T00:00:00Z"),
    // the 64-byte r||s ECDSA signature on the type-3 form (the original DER signature reconstructed).
    sigLen: 64,
  },
};
