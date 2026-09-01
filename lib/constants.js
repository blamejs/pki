// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.C
 * @nav        Core
 * @title      Constants
 * @fullname   Constants: size caps, time units and named bounds
 * @order      10
 * @featured   true
 * @slug       constants
 *
 * @intro
 *   Version-stable constant namespace for the toolkit. Scale values are
 *   FUNCTIONS, not pre-baked discrete numbers: `C.TIME.days(30)` reads
 *   at the call site and computes at boot, so a caller never hand-writes
 *   `30 * 24 * 60 * 60 * 1000` (a raw-literal the codebase gate refuses)
 *   and a reviewer never has to decode it.
 *
 *   Every scale helper is config-time / entry-point validation: it THROWS
 *   `ConstantsError` on a non-finite or negative argument, and on a product
 *   outside the safe-integer range, so an operator catches the typo at boot
 *   instead of shipping a silently-wrong window or an Infinity that would
 *   disable a size cap.
 *
 * @card
 *   Functional scale helpers (`C.TIME.*`, `C.BYTES.*`) plus the toolkit
 *   version and shared codec limits.
 */

var frameworkError = require("./framework-error");

var ConstantsError = frameworkError.ConstantsError;

function _positive(n, who) {
  if (typeof n !== "number" || !isFinite(n) || n < 0) {
    throw new ConstantsError(
      "constants/bad-scale",
      who + ": expected a finite number >= 0, got " + String(n)
    );
  }
  return n;
}

function _scale(n, who, factor) {
  var out = Math.round(_positive(n, who) * factor);
  if (!Number.isSafeInteger(out)) {
    throw new ConstantsError(
      "constants/bad-scale",
      who + ": the result " + String(out) + " is not a safe integer"
    );
  }
  return out;
}

var MS_PER_SECOND = 1000;
var SECONDS_PER_MINUTE = 60;
var MINUTES_PER_HOUR = 60;
var HOURS_PER_DAY = 24;
var DAYS_PER_WEEK = 7;

/**
 * @primitive  pki.C.TIME
 * @signature  C.TIME.days(n) -> milliseconds
 * @since      0.1.0
 * @status     stable
 * @spec       internal (design: functional time-scale helpers)
 *
 * Duration helpers. Each returns an integer count of milliseconds so the
 * value drops straight into `setTimeout`, a validity window, or an OCSP
 * `nextUpdate` computation. Composing reads naturally:
 * `C.TIME.days(365)` for a one-year certificate lifetime.
 *
 * @example
 *   var oneYear = pki.C.TIME.days(365);
 *   // -> 31536000000
 */
var TIME = {
  milliseconds: function (n) { return _scale(n, "C.TIME.milliseconds", 1); },
  seconds: function (n) { return _scale(n, "C.TIME.seconds", MS_PER_SECOND); },
  minutes: function (n) { return _scale(n, "C.TIME.minutes", SECONDS_PER_MINUTE * MS_PER_SECOND); },
  hours:   function (n) { return _scale(n, "C.TIME.hours", MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  days:    function (n) { return _scale(n, "C.TIME.days", HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  weeks:   function (n) { return _scale(n, "C.TIME.weeks", DAYS_PER_WEEK * HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
};

var BYTES_PER_KIB = 1024;

/**
 * @primitive  pki.C.BYTES
 * @signature  C.BYTES.mib(n) -> bytes
 * @since      0.1.0
 * @status     stable
 * @spec       IEC 80000-13
 *
 * Binary-magnitude size helpers. Each returns an integer byte count for
 * codec limits (max DER input, max PEM block) so a size bound reads as
 * `C.BYTES.mib(16)` instead of `16 * 1024 * 1024`.
 *
 * @example
 *   var cap = pki.C.BYTES.mib(16);
 *   // -> 16777216
 */
var BYTES = {
  b:   function (n) { return _scale(n, "C.BYTES.b", 1); },
  kib: function (n) { return _scale(n, "C.BYTES.kib", BYTES_PER_KIB); },
  mib: function (n) { return _scale(n, "C.BYTES.mib", BYTES_PER_KIB * BYTES_PER_KIB); },
  gib: function (n) { return _scale(n, "C.BYTES.gib", BYTES_PER_KIB * BYTES_PER_KIB * BYTES_PER_KIB); },
};

var LIMITS = {
  DER_MAX_BYTES: BYTES.mib(16),
  DER_MAX_DEPTH: 64,
  DER_MAX_ITEMS: 4000000,
  MAX_DECODE_DEPTH_CEILING: 256,
  PEM_MAX_BYTES: BYTES.mib(16),
  DER_MAX_INTEGER_BYTES: BYTES.kib(16),
  OID_MAX_SUBIDENTIFIER_BYTES: 32,
  HTTP_MAX_RESPONSE_BYTES: BYTES.mib(24),
  HTTP_AUTH_HEADER_MAX_BYTES: BYTES.kib(8),
  CBOR_MAX_BYTES: BYTES.mib(16),
  CBOR_MAX_DEPTH: 64,
  CBOR_MAX_BIGUINT_BYTES: BYTES.kib(16),
  CBOR_MAX_ITEMS: 1000000,
  SCT_MAX_BYTES: BYTES.kib(64) + 1,
  SCT_MAX_COUNT: 256,
  MERKLE_MAX_PROOF_NODES: 65,
  PATH_MAX_CERTS: 100,
  PATH_MAX_POLICY_NODES: 4096,
  PATH_BUILD_MAX_DEPTH: 20,
  PATH_BUILD_MAX_CANDIDATES: 1000,
  PATH_AIA_MAX_FETCHES: 10,
  PATH_AIA_MAX_PER_CERT: 3,
  PATH_AIA_MAX_RESPONSE_BYTES: BYTES.mib(1),
  PATH_AIA_MAX_CERTS_PER_RESPONSE: 16,
  PKCS12_MAX_ELEMENTS: 1024,
  PKCS12_MAX_REDECODES: 64,
  PKCS12_MAX_BAG_DEPTH: 16,
  BER_MAX_STRING_NESTING: 8,
  ATTRIBUTE_MAX_VALUES: 256,
  JSON_MAX_BYTES: BYTES.mib(1),
  JSON_MAX_DEPTH: 32,
  CT_LOG_LIST_MAX_BYTES: BYTES.mib(4),
  PBKDF2_MAX_ITERATIONS: 10000000,
  PBKDF2_MAX_SALT: 1024,
  MIME_MAX_BYTES: BYTES.mib(16),
  HEADER_LINE_MAX_OCTETS: 998,
  COMPRESS_MAX_BYTES: BYTES.mib(16),
  TLS_CERT_MSG_MAX_BYTES: BYTES.mib(16) - 1,
  TLS_CERT_MAX_ENTRIES: 100,
  MDS_BLOB_MAX_BYTES: BYTES.mib(32),
  MDS_BLOB_HEADER_MAX_BYTES: BYTES.kib(256),
  MDS_BLOB_SIG_MAX_BYTES: BYTES.kib(8),
  MDS_MAX_ENTRIES: 4096,
  MDS_MAX_STATUS_REPORTS_PER_ENTRY: 256,
  MDS_MAX_ANCHORS_PER_ENTRY: 16,
  MDS_MAX_KEY_IDS_PER_ENTRY: 64,
  WEBAUTHN_COMPOUND_MAX_STATEMENTS: 16,
  WEBAUTHN_X5C_MAX_CERTS: 10,
  SAFETYNET_JWS_MAX_BYTES: BYTES.kib(64),
  SAFETYNET_CERT_MAX_BYTES: BYTES.kib(64),
  ACME_TOKEN_MIN_CHARS: 22,
  SCEP_TRANSACTION_ID_MAX: 255,
  OCSP_MAX_CERTS: 32,
  HSS_MAX_LEVELS: 8,
  TRUST_MAX_BYTES: BYTES.mib(16),
  TRUST_MAX_OCTAL_BYTES: BYTES.kib(64),
  TRUST_MAX_OBJECTS: 10000,
  TRUST_MAX_CSV_ROWS: 10000,
  TRUST_MAX_CSV_FIELD_BYTES: BYTES.kib(64),
};

var NAMES = {
  DN_SHORT: {
    commonName: "CN", surname: "SN", serialNumber: "SERIALNUMBER", countryName: "C",
    localityName: "L", stateOrProvinceName: "ST", streetAddress: "STREET",
    organizationName: "O", organizationalUnitName: "OU", title: "title", givenName: "GN",
    initials: "initials", generationQualifier: "generationQualifier", distinguishedNameQualifier: "dnQualifier",
    pseudonym: "pseudonym", domainComponent: "DC", userId: "UID", emailAddress: "emailAddress",
    businessCategory: "businessCategory", postalCode: "postalCode", name: "name",
    jurisdictionCountryName: "jurisdictionC", jurisdictionStateOrProvinceName: "jurisdictionST",
    jurisdictionLocalityName: "jurisdictionL", organizationIdentifier: "organizationIdentifier",
  },
  EXTENSION: {
    basicConstraints: "X509v3 Basic Constraints", keyUsage: "X509v3 Key Usage",
    extKeyUsage: "X509v3 Extended Key Usage", subjectAltName: "X509v3 Subject Alternative Name",
    issuerAltName: "X509v3 Issuer Alternative Name", subjectKeyIdentifier: "X509v3 Subject Key Identifier",
    authorityKeyIdentifier: "X509v3 Authority Key Identifier", certificatePolicies: "X509v3 Certificate Policies",
    policyMappings: "X509v3 Policy Mappings", policyConstraints: "X509v3 Policy Constraints",
    inhibitAnyPolicy: "X509v3 Inhibit Any Policy", nameConstraints: "X509v3 Name Constraints",
    cRLDistributionPoints: "X509v3 CRL Distribution Points", freshestCRL: "X509v3 Freshest CRL",
    subjectInfoAccess: "Subject Information Access", authorityInfoAccess: "Authority Information Access",
    cRLNumber: "X509v3 CRL Number", deltaCRLIndicator: "X509v3 Delta CRL Indicator",
    issuingDistributionPoint: "X509v3 Issuing Distribution Point", cRLReason: "X509v3 CRL Reason Code",
    invalidityDate: "Invalidity Date", certificateIssuer: "X509v3 Certificate Issuer",
    signedCertificateTimestampList: "CT Precertificate SCTs", precertificatePoison: "CT Precertificate Poison",
  },
  KEY_USAGE: {
    digitalSignature: "Digital Signature", nonRepudiation: "Non Repudiation", keyEncipherment: "Key Encipherment",
    dataEncipherment: "Data Encipherment", keyAgreement: "Key Agreement", keyCertSign: "Certificate Sign",
    cRLSign: "CRL Sign", encipherOnly: "Encipher Only", decipherOnly: "Decipher Only",
  },
  EXT_KEY_USAGE: {
    anyExtendedKeyUsage: "Any Extended Key Usage", serverAuth: "TLS Web Server Authentication",
    clientAuth: "TLS Web Client Authentication", codeSigning: "Code Signing",
    emailProtection: "E-mail Protection", timeStamping: "Time Stamping", ocspSigning: "OCSP Signing",
  },
  GENERAL_NAME: { 0: "othername", 1: "email", 2: "DNS", 3: "X400Name", 4: "DirName", 5: "EdiPartyName", 6: "URI", 7: "IP Address", 8: "Registered ID" },
  NIST_CURVE: { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" },
  REASON_FLAGS: {
    1: "Key Compromise", 2: "CA Compromise", 3: "Affiliation Changed", 4: "Superseded",
    5: "Cessation Of Operation", 6: "Certificate Hold", 7: "Privilege Withdrawn", 8: "AA Compromise",
  },
  CRL_REASON: {
    "0": "unspecified", "1": "keyCompromise", "2": "cACompromise", "3": "affiliationChanged",
    "4": "superseded", "5": "cessationOfOperation", "6": "certificateHold",
    "8": "removeFromCRL", "9": "privilegeWithdrawn", "10": "aACompromise",
  },
  OCSP_STATUS: { "0": "successful", "1": "malformedRequest", "2": "internalError", "3": "tryLater", "5": "sigRequired", "6": "unauthorized" },
  OBJECT_DIGEST_TYPE: { "0": "publicKey", "1": "publicKeyCert", "2": "otherObjectTypes" },
  ALGORITHM: {
    rsaEncryption: "rsaEncryption", rsassaPss: "rsassaPss", rsaesOaep: "rsaesOaep", ecPublicKey: "id-ecPublicKey",
    ed25519: "ED25519", ed448: "ED448", x25519: "X25519", x448: "X448",
    "ML-DSA-44": "ML-DSA-44", "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87",
    "ML-KEM-512": "ML-KEM-512", "ML-KEM-768": "ML-KEM-768", "ML-KEM-1024": "ML-KEM-1024",
    "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
  },
};

Object.keys(NAMES).forEach(function (k) { Object.freeze(NAMES[k]); });
Object.freeze(NAMES);

var VERSION = require("../package.json").version;

module.exports = {
  TIME:    TIME,
  BYTES:   BYTES,
  LIMITS:  LIMITS,
  NAMES:   NAMES,
  version: VERSION,
};
