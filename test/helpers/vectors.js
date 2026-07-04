// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/helpers/vectors — shared known-answer fixtures.
 *
 * The certificate is a real self-signed P-256 / ecdsa-with-SHA256 cert
 * for pkijs.com (generated with OpenSSL; the same bytes live at
 * test/fixtures/pkijs-selfsigned-ec.pem for interop harnesses). The OID
 * and DER vectors are hand-computed against X.690 so the codec is tested
 * against an independent oracle, not against itself.
 */

var CERT_EC_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "MIICIDCCAcWgAwIBAgIUCXFClIQYP/NHVFhmO3U2lyfSlmUwCgYIKoZIzj0EAwIw",
  "WzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAoMC2Js",
  "YW1lanMgcGtpMQ0wCwYDVQQLDARUZXN0MRIwEAYDVQQDDAlwa2lqcy5jb20wHhcN",
  "MjYwNzA0MDcwMDI3WhcNMzYwNzAxMDcwMDI3WjBbMQswCQYDVQQGEwJVUzETMBEG",
  "A1UECAwKQ2FsaWZvcm5pYTEUMBIGA1UECgwLYmxhbWVqcyBwa2kxDTALBgNVBAsM",
  "BFRlc3QxEjAQBgNVBAMMCXBraWpzLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH",
  "A0IABMTnJGMp81YUykU9Y6O/dw96+I7NeMvDlgoLKcRNyvtHXJ+dcCxwIyvQ0yNc",
  "tFz3oSUduIhzK4klN+pV31yeNyGjZzBlMCMGA1UdEQQcMBqCCXBraWpzLmNvbYIN",
  "d3d3LnBraWpzLmNvbTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAd",
  "BgNVHQ4EFgQUg5ExvjNCudg+SofjynQJ61Ym1FEwCgYIKoZIzj0EAwIDSQAwRgIh",
  "AL4A24mKKNfslinidyRUT/8hopIRrCsmwsFfoEhdkrpMAiEAg/BBJrHljE+gmCkn",
  "Cgk/pyTRcfIZFV/qLx9klGxRH58=",
  "-----END CERTIFICATE-----",
  "",
].join("\n");

// Expected fields, cross-checked with `openssl x509 -noout -text`.
var CERT_EC_EXPECT = {
  version:          3,
  serialHex:        "0971429484183ff3475458663b75369727d29665",
  subjectDn:        "C=US, ST=California, O=blamejs pki, OU=Test, CN=pkijs.com",
  issuerDn:         "C=US, ST=California, O=blamejs pki, OU=Test, CN=pkijs.com",
  notBeforeIso:     "2026-07-04T07:00:27.000Z",
  notAfterIso:      "2036-07-01T07:00:27.000Z",
  sigAlgOid:        "1.2.840.10045.4.3.2",
  sigAlgName:       "ecdsaWithSHA256",
  spkiAlgOid:       "1.2.840.10045.2.1",
  spkiAlgName:      "ecPublicKey",
  extnOids:         ["2.5.29.17", "2.5.29.19", "2.5.29.15", "2.5.29.14"],
  sanDnsNames:      ["pkijs.com", "www.pkijs.com"],
};

// OID <-> DER-content known answers (hex of the OBJECT IDENTIFIER content,
// i.e. the bytes after the tag+length).
var OID_CONTENT = [
  ["2.5.4.3",               "550403"],                  // commonName
  ["1.2.840.113549.1.1.11", "2a864886f70d01010b"],      // sha256WithRSAEncryption
  ["1.2.840.10045.2.1",     "2a8648ce3d0201"],          // ecPublicKey
  ["1.2.840.10045.4.3.2",   "2a8648ce3d040302"],        // ecdsaWithSHA256
  ["1.3.101.112",           "2b6570"],                  // Ed25519
  ["2.16.840.1.101.3.4.2.1","608648016503040201"],      // sha256
  ["2.16.840.1.101.3.4.3.19","608648016503040313"],     // id-ml-dsa-87
];

// Full-TLV DER known answers (hex of the complete tag+length+value).
var DER_TLV = [
  ["INTEGER 0",        "020100"],
  ["INTEGER 127",      "02017f"],
  ["INTEGER 128",      "02020080"],
  ["INTEGER 256",      "02020100"],
  ["INTEGER -128",     "020180"],
  ["BOOLEAN true",     "0101ff"],
  ["BOOLEAN false",    "010100"],
  ["NULL",             "0500"],
  ["SEQUENCE empty",   "3000"],
  ["OID sha256",       "0609608648016503040201"],
];

module.exports = {
  CERT_EC_PEM:    CERT_EC_PEM,
  CERT_EC_EXPECT: CERT_EC_EXPECT,
  OID_CONTENT:    OID_CONTENT,
  DER_TLV:        DER_TLV,
};
