// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.oid
 * @nav        Core
 * @title      Object Identifiers
 * @fullname   OID registry: resolve object identifiers by name or dotted form
 * @order      40
 * @slug       oid
 *
 * @intro
 *   The object-identifier registry: a two-way map between dotted-decimal
 *   OID strings and their human names, plus arc conversion and DER
 *   encode/decode convenience. Every algorithm, attribute type, and
 *   extension in PKI is named by an OID, and resolving them through one
 *   registry, instead of scattering magic dotted strings across the
 *   codebase, is what lets a new algorithm be a data entry instead of a
 *   code change.
 *
 *   The seed set is declared by FAMILY: an OID belongs to a class with a
 *   shared base arc (the "starting variable": `2.5.4` for the RFC 5280
 *   attribute types, `2.5.29` for the extensions, `2.16.840.1.101.3.4` for
 *   the NIST algorithms), and each member names only its trailing arc. The
 *   full OID is derived from base + leaf at load, so the arc hierarchy that
 *   IS the OID namespace is modeled directly instead of re-spelled per
 *   entry. It covers the RFC 5280 attribute types and extensions, the
 *   classical signature / public-key / digest algorithms, and the
 *   NIST-assigned post-quantum arcs (ML-DSA, ML-KEM, SLH-DSA). Operators
 *   extend it with `register` (one OID) or `registerFamily` (a whole arc).
 *
 * @card
 *   Two-way OID <-> name registry with arc conversion, seeded by family from
 *   the RFC 5280 and NIST post-quantum object identifiers.
 */

var asn1 = require("./asn1-der");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");

var OidError = frameworkError.OidError;

function _oidError(c, m) { return new OidError(c, m); }

var FAMILIES = {
  attributeType: { base: [2, 5, 4], of: {
    commonName: 3, surname: 4, serialNumber: 5, countryName: 6,
    localityName: 7, stateOrProvinceName: 8, streetAddress: 9,
    organizationName: 10, organizationalUnitName: 11, title: 12, givenName: 42,
    clearance: 55, role: 72 } },

  certExtension: { base: [2, 5, 29], of: {
    subjectDirectoryAttributes: 9,
    subjectKeyIdentifier: 14, keyUsage: 15, subjectAltName: 17, issuerAltName: 18,
    basicConstraints: 19,
    cRLNumber: 20, reasonCode: 21, invalidityDate: 24, deltaCRLIndicator: 27,
    issuingDistributionPoint: 28, certificateIssuer: 29,
    nameConstraints: 30, cRLDistributionPoints: 31,
    certificatePolicies: 32, policyMappings: 33, authorityKeyIdentifier: 35,
    policyConstraints: 36, extKeyUsage: 37, freshestCRL: 46,
    inhibitAnyPolicy: 54,
    anyPolicy: [32, 0], anyExtendedKeyUsage: [37, 0],
    targetInformation: 55, noRevAvail: 56 } },

  pkixAccess: { base: [1, 3, 6, 1, 5, 5, 7, 1], of: {
    authorityInfoAccess: 1, acAuditIdentity: 4, aaControls: 6, acProxying: 10,
    acmeIdentifier: 31,
    subjectInfoAccess: 11,
    tlsFeature: 24,
    qcStatements: 3,
    ipAddrBlocks: 7, autonomousSysIds: 8, ipAddrBlocksV2: 28, autonomousSysIdsV2: 29 } },

  pkixQcSyntax: { base: [1, 3, 6, 1, 5, 5, 7, 11], of: { qcsPkixQCSyntaxV1: 1, qcsPkixQCSyntaxV2: 2 } },

  etsiQcs: { base: [0, 4, 0, 1862, 1], of: {
    qcCompliance: 1, qcLimitValue: 2, qcRetentionPeriod: 3, qcSSCD: 4, qcPDS: 5,
    qcType: 6, qcCClegislation: 7, qcIdentMethod: 8, qcQSCDlegislation: 9 } },

  etsiQcType: { base: [0, 4, 0, 1862, 1, 6], of: { qctEsign: 1, qctEseal: 2, qctWeb: 3 } },

  msEnrollment: { base: [1, 3, 6, 1, 4, 1, 311, 21], of: {
    msCaVersion: 1, msPreviousCertHash: 2, msCertificateTemplate: 7, msApplicationPolicies: 10 } },

  msEnrollmentLegacy: { base: [1, 3, 6, 1, 4, 1, 311, 20], of: { msEnrollCertType: 2 } },

  idAca: { base: [1, 3, 6, 1, 5, 5, 7, 10], of: {
    authenticationInfo: 1, accessIdentity: 2, chargingIdentity: 3, group: 4, encAttrs: 6 } },

  selectedAttrType: { base: [2, 5, 1, 5], of: { clearance: 55 } },

  adAccess: { base: [1, 3, 6, 1, 5, 5, 7, 48], of: { ocsp: 1, caIssuers: 2,
    "id-ad-timeStamping": 3, "id-ad-caRepository": 5, "id-ad-rpkiManifest": 10,
    "id-ad-signedObject": 11, "id-ad-rpkiNotify": 13, "id-ad-cmc": 12 } },

  idCmc: { base: [1, 3, 6, 1, 5, 5, 7, 7], of: {
    "id-cmc-statusInfo": 1, "id-cmc-identification": 2, "id-cmc-identityProof": 3,
    "id-cmc-dataReturn": 4, "id-cmc-transactionId": 5, "id-cmc-senderNonce": 6,
    "id-cmc-recipientNonce": 7, "id-cmc-addExtensions": 8, "id-cmc-encryptedPOP": 9,
    "id-cmc-decryptedPOP": 10, "id-cmc-lraPOPWitness": 11,
    "id-cmc-getCert": 15, "id-cmc-getCRL": 16, "id-cmc-revokeRequest": 17,
    "id-cmc-regInfo": 18, "id-cmc-responseInfo": 19,
    "id-cmc-queryPending": 21, "id-cmc-popLinkRandom": 22, "id-cmc-popLinkWitness": 23,
    "id-cmc-confirmCertAcceptance": 24, "id-cmc-statusInfoV2": 25, "id-cmc-trustedAnchors": 26,
    "id-cmc-authData": 27, "id-cmc-batchRequests": 28, "id-cmc-batchResponses": 29,
    "id-cmc-publishCert": 30, "id-cmc-modCertTemplate": 31, "id-cmc-controlProcessed": 32,
    "id-cmc-identityProofV2": 34, "id-cmc-popLinkWitnessV2": 33,
    "id-cmc-raIdentityWitness": 35, "id-cmc-changeSubjectName": 36, "id-cmc-responseBody": 37,
  } },

  idCct: { base: [1, 3, 6, 1, 5, 5, 7, 12], of: {
    "id-cct-PKIData": 2, "id-cct-PKIResponse": 3,
  } },

  pkixOn: { base: [1, 3, 6, 1, 5, 5, 7, 8], of: { hardwareModuleName: 4, smtpUtf8Mailbox: 9, macAddress: 12 } },

  cabfPolicy: { base: [2, 23, 140, 1], of: {
    "ev-guidelines": 1, "domain-validated": [2, 1], "organization-validated": [2, 2], "individual-validated": [2, 3] } },

  idCp: { base: [1, 3, 6, 1, 5, 5, 7, 14], of: { "id-cp-ipAddr-asNumber": 2, "id-cp-ipAddr-asNumber-v2": 3 } },

  gsmaRspRole: { base: [2, 23, 146, 1, 2, 1], of: {
    "id-rspRole-ci": 0, "id-rspRole-euicc-v2": 1, "id-rspRole-euicc": [0, 0, 0, 0, 0],
    "id-rspRole-eum-v2": 2, "id-rspRole-eum": [0, 0, 0],
    "id-rspRole-dp-tls-v2": 3, "id-rspRole-dp-tls": [0, 0, 1, 0],
    "id-rspRole-dp-auth-v2": 4, "id-rspRole-dp-auth": [0, 0, 1, 1],
    "id-rspRole-dp-pb-v2": 5, "id-rspRole-dp-pb": [0, 0, 1, 2],
    "id-rspRole-ds-tls-v2": 6, "id-rspRole-ds-tls": [0, 0, 2, 0],
    "id-rspRole-ds-auth-v2": 7, "id-rspRole-ds-auth": [0, 0, 2, 1] } },

  pkixQt: { base: [1, 3, 6, 1, 5, 5, 7, 2], of: { cps: 1, unotice: 2 } },

  ocsp: { base: [1, 3, 6, 1, 5, 5, 7, 48, 1], of: {
    ocspBasic: 1, ocspNonce: 2, ocspCrl: 3, ocspResponse: 4, ocspNoCheck: 5,
    ocspArchiveCutoff: 6, ocspServiceLocator: 7, ocspPrefSigAlgs: 8, ocspExtendedRevoke: 9 } },

  regCtrl: { base: [1, 3, 6, 1, 5, 5, 7, 5, 1], of: {
    regToken: 1, authenticator: 2, pkiPublicationInfo: 3, pkiArchiveOptions: 4, oldCertID: 5, protocolEncrKey: 6,
    altCertTemplate: 7, algId: 11, rsaKeyLen: 12 } },
  regInfo: { base: [1, 3, 6, 1, 5, 5, 7, 5, 2], of: { utf8Pairs: 1, certReq: 2 } },

  pkixKp: { base: [1, 3, 6, 1, 5, 5, 7, 3], of: {
    serverAuth: 1, clientAuth: 2, codeSigning: 3, emailProtection: 4, timeStamping: 8, ocspSigning: 9,
    secureShellClient: 21, secureShellServer: 22, cmcCA: 27, cmcRA: 28, cmcArchive: 29, cmKGA: 32, bundleSecurity: 35 } },

  pkinitKp: { base: [1, 3, 6, 1, 5, 2, 3], of: { pkinitClientAuth: 4, pkinitKdc: 5 } },

  wisun: { base: [1, 3, 6, 1, 4, 1, 45605], of: { fanDevice: 1 } },

  ct: { base: [1, 3, 6, 1, 4, 1, 11129, 2, 4], of: {
    signedCertificateTimestampList: 2, precertificatePoison: 3,
    precertificateSigningCert: 4, ocspSignedCertificateTimestampList: 5 } },

  fulcio: { base: [1, 3, 6, 1, 4, 1, 57264, 1], of: {
    issuerLegacy: 1, githubWorkflowTrigger: 2, githubWorkflowSha: 3,
    githubWorkflowName: 4, githubWorkflowRepository: 5, githubWorkflowRef: 6,
    otherName: 7, issuer: 8, buildSignerURI: 9, buildSignerDigest: 10,
    runnerEnvironment: 11, sourceRepositoryURI: 12, sourceRepositoryDigest: 13,
    sourceRepositoryRef: 14, sourceRepositoryIdentifier: 15,
    sourceRepositoryOwnerURI: 16, sourceRepositoryOwnerIdentifier: 17,
    buildConfigURI: 18, buildConfigDigest: 19, buildTrigger: 20,
    runInvocationURI: 21, sourceRepositoryVisibilityAtSigning: 22 } },

  rsa: { base: [1, 2, 840, 113549, 1, 1], of: {
    rsaEncryption: 1, rsaesOaep: 7, mgf1: 8, pSpecified: 9, rsassaPss: 10,
    sha256WithRSAEncryption: 11,
    sha384WithRSAEncryption: 12, sha512WithRSAEncryption: 13 } },

  pkcs7: { base: [1, 2, 840, 113549, 1, 7], of: {
    data: 1, signedData: 2, envelopedData: 3, signedAndEnvelopedData: 4,
    digestedData: 5, encryptedData: 6 } },

  pkcs9: { base: [1, 2, 840, 113549, 1, 9], of: {
    emailAddress: 1, contentType: 3, messageDigest: 4, signingTime: 5,
    countersignature: 6, challengePassword: 7, extensionRequest: 14,
    smimeCapabilities: 15, friendlyName: 20, localKeyId: 21 } },

  pkcs9CertTypes: { base: [1, 2, 840, 113549, 1, 9, 22], of: { x509Certificate: 1, sdsiCertificate: 2 } },
  pkcs9CrlTypes:  { base: [1, 2, 840, 113549, 1, 9, 23], of: { x509CRL: 1 } },

  pkcs5: { base: [1, 2, 840, 113549, 1, 5], of: { pbkdf2: 12, pbes2: 13, pbmac1: 14 } },

  idIt: { base: [1, 3, 6, 1, 5, 5, 7, 4], of: {
    caProtEncCert: 1, signKeyPairTypes: 2, encKeyPairTypes: 3, preferredSymmAlg: 4,
    caKeyUpdateInfo: 5, currentCRL: 6, unsupportedOIDs: 7, keyPairParamReq: 10,
    keyPairParamRep: 11, revPassphrase: 12, implicitConfirm: 13, confirmWaitTime: 14,
    origPKIMessage: 15, suppLangTags: 16, caCerts: 17, rootCaKeyUpdate: 18,
    certReqTemplate: 19, rootCaCert: 20, certProfile: 21, crlStatusList: 22,
    crls: 23, kemCiphertextInfo: 24 } },

  entrustAlg: { base: [1, 2, 840, 113533, 7, 66], of: {
    passwordBasedMac: 13, kemBasedMac: 16, dhBasedMac: 30 } },

  pkcs12BagTypes: { base: [1, 2, 840, 113549, 1, 12, 10, 1], of: {
    keyBag: 1, pkcs8ShroudedKeyBag: 2, certBag: 3, crlBag: 4, secretBag: 5, safeContentsBag: 6 } },

  pkcs12Pbe: { base: [1, 2, 840, 113549, 1, 12, 1], of: {
    pbeWithSHAAnd128BitRC4: 1, pbeWithSHAAnd40BitRC4: 2,
    "pbeWithSHAAnd3-KeyTripleDES-CBC": 3, "pbeWithSHAAnd2-KeyTripleDES-CBC": 4,
    "pbeWithSHAAnd128BitRC2-CBC": 5, "pbeWithSHAAnd40BitRC2-CBC": 6 } },

  rsadsiDigest: { base: [1, 2, 840, 113549, 2], of: {
    hmacWithSHA1: 7, hmacWithSHA224: 8, hmacWithSHA256: 9,
    hmacWithSHA384: 10, hmacWithSHA512: 11 } },

  smimeCt: { base: [1, 2, 840, 113549, 1, 9, 16, 1], of: { authData: 2, tSTInfo: 4, compressedData: 9, encKeyWithID: 21, authEnvelopedData: 23 } },

  smimeOri: { base: [1, 2, 840, 113549, 1, 9, 16, 13], of: { kem: 3 } },

  smimeAlg: { base: [1, 2, 840, 113549, 1, 9, 16, 3], of: {
    "id-alg-zlibCompress": 8, "id-alg-PWRI-KEK": 9,
    "id-rsa-kem": 14, "id-alg-hss-lms-hashsig": 17,
    "dhSinglePass-stdDH-hkdf-sha256-scheme": 19, "dhSinglePass-stdDH-hkdf-sha384-scheme": 20,
    "dhSinglePass-stdDH-hkdf-sha512-scheme": 21,
    hkdfWithSha256: 28, hkdfWithSha384: 29, hkdfWithSha512: 30, cekHkdfSha256: 31 } },

  secgStdDH: { base: [1, 3, 132, 1, 11], of: {
    "dhSinglePass-stdDH-sha224kdf-scheme": 0, "dhSinglePass-stdDH-sha256kdf-scheme": 1,
    "dhSinglePass-stdDH-sha384kdf-scheme": 2, "dhSinglePass-stdDH-sha512kdf-scheme": 3 } },
  secgCofactorDH: { base: [1, 3, 132, 1, 14], of: {
    "dhSinglePass-cofactorDH-sha224kdf-scheme": 0, "dhSinglePass-cofactorDH-sha256kdf-scheme": 1,
    "dhSinglePass-cofactorDH-sha384kdf-scheme": 2, "dhSinglePass-cofactorDH-sha512kdf-scheme": 3 } },
  x963Schemes: { base: [1, 3, 133, 16, 840, 63, 0], of: {
    "dhSinglePass-stdDH-sha1kdf-scheme": 2, "dhSinglePass-cofactorDH-sha1kdf-scheme": 3 } },

  pkixAlg: { base: [1, 3, 6, 1, 5, 5, 7, 6], of: {
    "id-alg-noSignature": 2,
    "id-RSASSA-PSS-SHAKE128": 30, "id-RSASSA-PSS-SHAKE256": 31,
    "id-alg-xmss-hashsig": 34, "id-alg-xmssmt-hashsig": 35,
    "id-MLDSA44-RSA2048-PSS-SHA256": 37, "id-MLDSA44-RSA2048-PKCS15-SHA256": 38,
    "id-MLDSA44-Ed25519-SHA512": 39, "id-MLDSA44-ECDSA-P256-SHA256": 40,
    "id-MLDSA65-RSA3072-PSS-SHA512": 41, "id-MLDSA65-RSA3072-PKCS15-SHA512": 42,
    "id-MLDSA65-RSA4096-PSS-SHA512": 43, "id-MLDSA65-RSA4096-PKCS15-SHA512": 44,
    "id-MLDSA65-ECDSA-P256-SHA512": 45, "id-MLDSA65-ECDSA-P384-SHA512": 46,
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512": 47, "id-MLDSA65-Ed25519-SHA512": 48,
    "id-MLDSA87-ECDSA-P384-SHA512": 49, "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512": 50,
    "id-MLDSA87-Ed448-SHAKE256": 51, "id-MLDSA87-RSA3072-PSS-SHA512": 52,
    "id-MLDSA87-RSA4096-PSS-SHA512": 53, "id-MLDSA87-ECDSA-P521-SHA512": 54,
    "id-MLKEM768-RSA2048-SHA3-256": 55, "id-MLKEM768-RSA3072-SHA3-256": 56,
    "id-MLKEM768-RSA4096-SHA3-256": 57, "id-MLKEM768-X25519-SHA3-256": 58,
    "id-MLKEM768-ECDH-P256-SHA3-256": 59, "id-MLKEM768-ECDH-P384-SHA3-256": 60,
    "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256": 61, "id-MLKEM1024-RSA3072-SHA3-256": 62,
    "id-MLKEM1024-ECDH-P384-SHA3-256": 63, "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256": 64,
    "id-MLKEM1024-X448-SHA3-256": 65, "id-MLKEM1024-ECDH-P521-SHA3-256": 66 } },

  iso18033: { base: [1, 0, 18033, 2, 2], of: { "id-kem-rsa": 4 } },

  pkixHmac: { base: [1, 3, 6, 1, 5, 5, 8, 1], of: { "hmac-SHA1": 2 } },

  smimeAa: { base: [1, 2, 840, 113549, 1, 9, 16, 2], of: {
    receiptRequest: 1, eSSSecurityLabel: 2, mlExpansionHistory: 3, contentHints: 4,
    msgSigDigest: 5, contentIdentifier: 7, equivalentLabels: 9, contentReference: 10,
    signingCertificate: 12, timeStampToken: 14, decryptKeyID: 37, signingCertificateV2: 47,
    cmcUnsignedData: 34,
    asymmDecryptKeyID: 54, certificationRequestInfoTemplate: 61, extensionReqTemplate: 62 } },

  ansiX962: { base: [1, 2, 840, 10045], of: {
    ecPublicKey: [2, 1], prime256v1: [3, 1, 7],
    ecdsaWithSHA256: [4, 3, 2], ecdsaWithSHA384: [4, 3, 3], ecdsaWithSHA512: [4, 3, 4] } },

  secg: { base: [1, 3, 132, 0], of: { secp384r1: 34, secp521r1: 35 } },

  brainpool: { base: [1, 3, 36, 3, 3, 2, 8, 1, 1], of: { brainpoolP256r1: 7, brainpoolP384r1: 11 } },

  edwards: { base: [1, 3, 101], of: { X25519: 110, X448: 111, Ed25519: 112, Ed448: 113 } },

  oiwSecsig: { base: [1, 3, 14, 3, 2], of: {
    sha1: 26,
    "md4WithRSA": 2, "md5WithRSA": 3, "md4WithRSAEncryption": 4, "rsaSignature": 11,
    "mdc2WithRSASignature": 14, "shaWithRSAEncryption": 15, "rsaKeyTransport": 22,
    "md2WithRSASignature": 24, "md5WithRSASignature": 25, "sha1WithRSASignature": 29 } },

  teletrustRsaSig: { base: [1, 3, 36, 3, 3, 1], of: { "rsaSignatureWithripemd160": 2 } },

  teletrustSigScheme: { base: [1, 3, 36, 3, 4], of: {
    "sigS-ISO9796-1": 1, "sigS-ISO9796-1-DFUE": [1, 1],
    "sigS-ISO9796-2": 2, "sigS-ISO9796-2Withrsa-even-exp": [2, 1], "sigS-ISO9796-2Withrsa": [2, 2],
    "sigS-ISO9796-2Withrsa-sha1": [2, 2, 1], "sigS-ISO9796-2Withrsa-ripemd160": [2, 2, 2],
    "sigS-ISO9796-2Withrsa-sha224": [2, 2, 3], "sigS-ISO9796-2Withrsa-sha256": [2, 2, 4],
    "sigS-ISO9796-2Withrsa-sha384": [2, 2, 5], "sigS-ISO9796-2Withrsa-sha512": [2, 2, 6],
    "sigS-ISO9796-2rnd": 3, "sigS-ISO9796-2rndWithrsa-even-exp": [3, 1], "sigS-ISO9796-2rndWithrsa": [3, 2],
    "sigS-ISO9796-2rndWithrsa-sha1": [3, 2, 1], "sigS-ISO9796-2rndWithrsa-ripemd160": [3, 2, 2],
    "sigS-ISO9796-2rndWithrsa-sha224": [3, 2, 3], "sigS-ISO9796-2rndWithrsa-sha256": [3, 2, 4],
    "sigS-ISO9796-2rndWithrsa-sha384": [3, 2, 5], "sigS-ISO9796-2rndWithrsa-sha512": [3, 2, 6] } },

  x509EncAlg: { base: [2, 5, 8, 1], of: { "rsa": 1 } },

  x509SigAlg: { base: [2, 5, 8, 3], of: { "sqMod-nWithRSA": 1, "mdc2WithRSA": 100 } },

  smAlg: { base: [1, 2, 156, 10197, 1], of: { "sm3WithRSAEncryption": 504 } },

  bsiTaRsa: { base: [0, 4, 0, 127, 0, 7, 2, 2, 2, 1], of: {
    "id-TA-RSA-v1-5-SHA-1": 1, "id-TA-RSA-v1-5-SHA-256": 2, "id-TA-RSA-PSS-SHA-1": 3,
    "id-TA-RSA-PSS-SHA-256": 4, "id-TA-RSA-v1-5-SHA-512": 5, "id-TA-RSA-PSS-SHA-512": 6 } },

  nistAes: { base: [2, 16, 840, 1, 101, 3, 4, 1], of: {
    "aes128-CBC": 2, "aes128-wrap": 5, "aes128-GCM": 6, "aes128-CCM": 7,
    "aes192-CBC": 22, "aes192-wrap": 25, "aes192-GCM": 26, "aes192-CCM": 27,
    "aes256-CBC": 42, "aes256-wrap": 45, "aes256-GCM": 46, "aes256-CCM": 47 } },

  nistHash: { base: [2, 16, 840, 1, 101, 3, 4, 2], of: {
    sha256: 1, sha384: 2, sha512: 3, "sha3-256": 8, "sha3-512": 10, shake128: 11, shake256: 12 } },

  nistSig: { base: [2, 16, 840, 1, 101, 3, 4, 3], of: {
    "id-rsassa-pkcs1-v1_5-with-sha3-224": 13, "id-rsassa-pkcs1-v1_5-with-sha3-256": 14,
    "id-rsassa-pkcs1-v1_5-with-sha3-384": 15, "id-rsassa-pkcs1-v1_5-with-sha3-512": 16,
    "id-ml-dsa-44": 17, "id-ml-dsa-65": 18, "id-ml-dsa-87": 19,
    "id-slh-dsa-sha2-128s": 20, "id-slh-dsa-sha2-128f": 21,
    "id-slh-dsa-sha2-192s": 22, "id-slh-dsa-sha2-192f": 23,
    "id-slh-dsa-sha2-256s": 24, "id-slh-dsa-sha2-256f": 25,
    "id-slh-dsa-shake-128s": 26, "id-slh-dsa-shake-128f": 27,
    "id-slh-dsa-shake-192s": 28, "id-slh-dsa-shake-192f": 29,
    "id-slh-dsa-shake-256s": 30, "id-slh-dsa-shake-256f": 31,
    "id-hash-slh-dsa-sha2-128s-with-sha256": 35, "id-hash-slh-dsa-sha2-128f-with-sha256": 36,
    "id-hash-slh-dsa-sha2-192s-with-sha512": 37, "id-hash-slh-dsa-sha2-192f-with-sha512": 38,
    "id-hash-slh-dsa-sha2-256s-with-sha512": 39, "id-hash-slh-dsa-sha2-256f-with-sha512": 40,
    "id-hash-slh-dsa-shake-128s-with-shake128": 41, "id-hash-slh-dsa-shake-128f-with-shake128": 42,
    "id-hash-slh-dsa-shake-192s-with-shake256": 43, "id-hash-slh-dsa-shake-192f-with-shake256": 44,
    "id-hash-slh-dsa-shake-256s-with-shake256": 45, "id-hash-slh-dsa-shake-256f-with-shake256": 46 } },

  nistKem: { base: [2, 16, 840, 1, 101, 3, 4, 4], of: {
    "id-ml-kem-512": 1, "id-ml-kem-768": 2, "id-ml-kem-1024": 3 } },

  datatype: { base: [0, 9, 2342, 19200300, 100, 1], of: { domainComponent: 25 } },

  fidoGenCe: { base: [1, 3, 6, 1, 4, 1, 45724, 1, 1], of: { idFidoGenCeAaguid: 4 } },

  androidKeystore: { base: [1, 3, 6, 1, 4, 1, 11129, 2, 1], of: { keyDescription: 17 } },

  appleAttest: { base: [1, 2, 840, 113635, 100, 8], of: { appleAnonymousAttestation: 2 } },

  tcgKp: { base: [2, 23, 133, 8], of: { tcgKpAikCertificate: 3 } },
  tcgAt: { base: [2, 23, 133, 2], of: { tpmManufacturer: 1, tpmModel: 2, tpmVersion: 3 } },

  scepAttribute: { base: [2, 16, 840, 1, 113733, 1, 9], of: {
    scepMessageType: 2, scepPkiStatus: 3, scepFailInfo: 4,
    scepSenderNonce: 5, scepRecipientNonce: 6, scepTransactionId: 7 } },
  scep: { base: [1, 3, 6, 1, 5, 5, 7, 24], of: { scepFailInfoText: 1 } },
};

var _byOid = new Map();
var _byName = new Map();

function _index(dotted, name) {
  _byOid.set(dotted, name);
  if (!_byName.has(name)) _byName.set(name, dotted);
}

function _isArc(a) {
  if (typeof a === "bigint") return a >= 0n;
  return typeof a === "number" && Number.isSafeInteger(a) && a >= 0;
}

Object.keys(FAMILIES).forEach(function (fam) {
  registerFamily(FAMILIES[fam].base, FAMILIES[fam].of);
});

function _assertDotted(dotted, who) {
  guard.identifier.assertCanonicalOid(dotted, _oidError, "oid/bad-input", who, null);
}

function _assertEncodable(dotted, who) {
  guard.identifier.assertCanonicalOid(dotted, _oidError, "oid/bad-input", who, "oid/bad-arc");
}

function _assertEncodableArcs(arcs, who) {
  if (arcs.length < 2) {
    throw new OidError("oid/bad-input", who + ": an OID must have at least 2 arcs");
  }
  var root = typeof arcs[0] === "bigint" ? arcs[0] : BigInt(arcs[0]);
  var second = typeof arcs[1] === "bigint" ? arcs[1] : BigInt(arcs[1]);
  if (root > 2n) throw new OidError("oid/bad-arc", who + ": the root arc must be 0, 1, or 2 (X.660)");
  if (root < 2n && second > 39n) throw new OidError("oid/bad-arc", who + ": the second arc must be 0..39 under roots 0 and 1 (X.660)");
}

/**
 * @primitive  pki.oid.name
 * @signature  pki.oid.name(dotted) -> string | undefined
 * @since      0.1.0
 * @status     stable
 * @spec       X.660, RFC 5280
 * @related    pki.oid.byName, pki.oid.register
 *
 * Resolve a dotted OID to its registered name. Returns `undefined` for an
 * unregistered OID (a caller that needs the raw arc keeps the dotted
 * string); throws `OidError` only when the argument isn't a dotted OID.
 *
 * @example
 *   pki.oid.name("1.2.840.113549.1.1.11"); // -> "sha256WithRSAEncryption"
 */
function name(dotted) {
  _assertDotted(dotted, "name");
  return _byOid.get(dotted);
}

function byName(n) {
  if (typeof n !== "string" || n.length === 0) throw new OidError("oid/bad-input", "byName: expected a name string");
  return _byName.get(n);
}

function isDottedDecimal(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  var i, c, sawDot = false, atomEmpty = true;
  for (i = 0; i < s.length; i += 1) {
    c = s.charCodeAt(i);
    if (c === 46) { if (atomEmpty) return false; sawDot = true; atomEmpty = true; }
    else if (c >= 48 && c <= 57) { atomEmpty = false; }
    else return false;
  }
  return sawDot && !atomEmpty;
}

function has(dotted) {
  _assertDotted(dotted, "has");
  return _byOid.has(dotted);
}

/**
 * @primitive  pki.oid.register
 * @signature  pki.oid.register(dotted, name) -> void
 * @since      0.1.0
 * @status     stable
 * @spec       X.660, RFC 5280
 * @related    pki.oid.registerFamily, pki.oid.name
 *
 * Add (or override) an OID -> name mapping so an operator's private or
 * newly-standardized arc resolves through the same registry as the seed
 * set. A later registration of the same OID replaces the forward name;
 * the reverse (name -> OID) keeps the first registration as canonical.
 *
 * @example
 *   pki.oid.register("1.3.6.1.4.1.99999.1", "acmeWidgetPolicy");
 */
function register(dotted, n) {
  _assertEncodable(dotted, "register");
  if (typeof n !== "string" || n.length === 0) throw new OidError("oid/bad-input", "register: name must be a non-empty string");
  _index(dotted, n);
}

/**
 * @primitive  pki.oid.registerFamily
 * @signature  pki.oid.registerFamily(base, members) -> void
 * @since      0.1.2
 * @status     stable
 * @spec       X.660
 * @related    pki.oid.register, pki.oid.name
 *
 * Register a whole OID family in one call. `base` is the shared arc prefix
 * (the starting variable a class of OIDs has in common) and `members` maps
 * each name to its trailing arc -- a number, or a short arc array for a
 * multi-level leaf. Each full OID is derived as `base` followed by the leaf,
 * so a family is declared as its hierarchy and no full path is re-spelled.
 * This is the primitive the built-in seed set itself is built from.
 *
 * @opts
 *   base:      number[],           // the shared arc prefix, e.g. [1,3,6,1,4,1,99999]
 *   members:   object,             // name -> number | number[] trailing arc
 *
 * @example
 *   pki.oid.registerFamily([1, 3, 6, 1, 4, 1, 99999], {
 *     widgetPolicy: 1,
 *     gadgetPolicy: [2, 4],
 *   });
 *   pki.oid.name("1.3.6.1.4.1.99999.2.4"); // -> "gadgetPolicy"
 */
function registerFamily(base, members) {
  if (!Array.isArray(base) || base.length < 1 || !base.every(_isArc)) {
    throw new OidError("oid/bad-input", "registerFamily: base must be a non-empty array of non-negative integer arcs");
  }
  if (!members || typeof members !== "object") {
    throw new OidError("oid/bad-input", "registerFamily: members must be an object of name -> leaf arc(s)");
  }
  Object.keys(members).forEach(function (nm) {
    if (typeof nm !== "string" || nm.length === 0) {
      throw new OidError("oid/bad-input", "registerFamily: member names must be non-empty strings");
    }
    var arcs = base.concat(members[nm]);
    if (!arcs.every(_isArc)) {
      throw new OidError("oid/bad-arc", "registerFamily: member " + JSON.stringify(nm) + " has a non-arc leaf");
    }
    _assertEncodableArcs(arcs, "registerFamily");
    _index(arcs.join("."), nm);
  });
}

function all() {
  var out = {};
  _byOid.forEach(function (v, k) { out[k] = v; });
  return out;
}

function toArcs(dotted) {
  _assertEncodable(dotted, "toArcs");
  return dotted.split(".").map(function (p) {
    var b = BigInt(p);
    return b <= 9007199254740991n ? Number(b) : b;
  });
}

function fromArcs(arcs) {
  if (!Array.isArray(arcs) || arcs.length < 2) throw new OidError("oid/bad-input", "fromArcs: expected an array of >= 2 arcs");
  return arcs.map(function (a) {
    if (typeof a === "bigint") {
      if (a < 0n) throw new OidError("oid/bad-arc", "fromArcs: arc " + String(a) + " is not a non-negative integer");
      return a.toString();
    }
    if (typeof a === "number" && Number.isSafeInteger(a) && a >= 0) return String(a);
    throw new OidError("oid/bad-arc", "fromArcs: arc " + String(a) + " is not a non-negative integer");
  }).join(".");
}

function toDER(dotted) { _assertEncodable(dotted, "toDER"); return asn1.build.oid(dotted); }
function fromDER(input) {
  var buf = guard.bytes.view(input, OidError, "oid/bad-input", "fromDER");
  var node = asn1.decode(buf);
  return asn1.read.oid(node);
}

var _PARAMS_ABSENT = new Set();
[
  "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87",
  "id-slh-dsa-sha2-128s", "id-slh-dsa-sha2-128f", "id-slh-dsa-sha2-192s",
  "id-slh-dsa-sha2-192f", "id-slh-dsa-sha2-256s", "id-slh-dsa-sha2-256f",
  "id-slh-dsa-shake-128s", "id-slh-dsa-shake-128f", "id-slh-dsa-shake-192s",
  "id-slh-dsa-shake-192f", "id-slh-dsa-shake-256s", "id-slh-dsa-shake-256f",
  "id-hash-slh-dsa-sha2-128s-with-sha256", "id-hash-slh-dsa-sha2-128f-with-sha256",
  "id-hash-slh-dsa-sha2-192s-with-sha512", "id-hash-slh-dsa-sha2-192f-with-sha512",
  "id-hash-slh-dsa-sha2-256s-with-sha512", "id-hash-slh-dsa-sha2-256f-with-sha512",
  "id-hash-slh-dsa-shake-128s-with-shake128", "id-hash-slh-dsa-shake-128f-with-shake128",
  "id-hash-slh-dsa-shake-192s-with-shake256", "id-hash-slh-dsa-shake-192f-with-shake256",
  "id-hash-slh-dsa-shake-256s-with-shake256", "id-hash-slh-dsa-shake-256f-with-shake256",
  "Ed25519", "Ed448", "X25519", "X448",
  "id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024",
  "hkdfWithSha256", "hkdfWithSha384", "hkdfWithSha512",
  "id-alg-hss-lms-hashsig", "id-alg-xmss-hashsig", "id-alg-xmssmt-hashsig",
  "id-MLDSA44-RSA2048-PSS-SHA256", "id-MLDSA44-RSA2048-PKCS15-SHA256",
  "id-MLDSA44-Ed25519-SHA512", "id-MLDSA44-ECDSA-P256-SHA256",
  "id-MLDSA65-RSA3072-PSS-SHA512", "id-MLDSA65-RSA3072-PKCS15-SHA512",
  "id-MLDSA65-RSA4096-PSS-SHA512", "id-MLDSA65-RSA4096-PKCS15-SHA512",
  "id-MLDSA65-ECDSA-P256-SHA512", "id-MLDSA65-ECDSA-P384-SHA512",
  "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "id-MLDSA65-Ed25519-SHA512",
  "id-MLDSA87-ECDSA-P384-SHA512", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512",
  "id-MLDSA87-Ed448-SHAKE256", "id-MLDSA87-RSA3072-PSS-SHA512",
  "id-MLDSA87-RSA4096-PSS-SHA512", "id-MLDSA87-ECDSA-P521-SHA512",
  "id-MLKEM768-RSA2048-SHA3-256", "id-MLKEM768-RSA3072-SHA3-256",
  "id-MLKEM768-RSA4096-SHA3-256", "id-MLKEM768-X25519-SHA3-256",
  "id-MLKEM768-ECDH-P256-SHA3-256", "id-MLKEM768-ECDH-P384-SHA3-256",
  "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256", "id-MLKEM1024-RSA3072-SHA3-256",
  "id-MLKEM1024-ECDH-P384-SHA3-256", "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
  "id-MLKEM1024-X448-SHA3-256", "id-MLKEM1024-ECDH-P521-SHA3-256",
].forEach(function (nm) {
  var d = byName(nm);
  if (typeof d !== "string") throw new OidError("oid/unknown-name", "paramsMustBeAbsent seed: " + JSON.stringify(nm) + " is not a registered name");
  _PARAMS_ABSENT.add(d);
});

/**
 * @primitive  pki.oid.paramsMustBeAbsent
 * @signature  pki.oid.paramsMustBeAbsent(dotted) -> boolean
 * @since      0.1.21
 * @status     stable
 * @spec       RFC 9909, RFC 9814, RFC 9881, RFC 8410
 * @related    pki.oid.name, pki.oid.byName
 *
 * True when an AlgorithmIdentifier bearing this OID MUST encode its `parameters`
 * field as ABSENT (not an explicit NULL, not any bytes). The post-quantum ML-DSA,
 * SLH-DSA, and ML-KEM families, the composite ML-DSA and composite ML-KEM
 * algorithms, HSS/LMS and XMSS, the HKDF key-derivation identifiers, and the
 * RFC 8410 Edwards / Montgomery curves all carry this MUST. The shared
 * AlgorithmIdentifier decoder consults this and fails closed on a
 * present-parameters violation, so every format inherits the rule.
 *
 * @example
 *   pki.oid.paramsMustBeAbsent(pki.oid.byName("id-slh-dsa-sha2-128s")); // -> true
 *   pki.oid.paramsMustBeAbsent(pki.oid.byName("rsaEncryption"));        // -> false
 */
function paramsMustBeAbsent(dotted) {
  return _PARAMS_ABSENT.has(dotted);
}

var KEM_PARAMS = Object.create(null);
[["id-ml-kem-512", 800, 1632, 768, 32],
  ["id-ml-kem-768", 1184, 2400, 1088, 32],
  ["id-ml-kem-1024", 1568, 3168, 1568, 32]].forEach(function (r) {
  var row = Object.freeze({ ek: r[1], dk: r[2], ct: r[3], ss: r[4] });
  KEM_PARAMS[byName(r[0])] = row;
  KEM_PARAMS[r[0]] = row;
});
Object.freeze(KEM_PARAMS);
function kemParams(oidOrName) { return KEM_PARAMS[oidOrName]; }

module.exports = {
  name:           name,
  byName:         byName,
  isDottedDecimal: isDottedDecimal,
  has:            has,
  paramsMustBeAbsent: paramsMustBeAbsent,
  kemParams:      kemParams,
  register:       register,
  registerFamily: registerFamily,
  all:            all,
  toArcs:         toArcs,
  fromArcs:       fromArcs,
  toDER:          toDER,
  fromDER:        fromDER,
};
