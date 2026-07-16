// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.oid
 * @nav        Core
 * @title      Object Identifiers
 * @order      40
 * @slug       oid
 *
 * @intro
 *   The object-identifier registry: a two-way map between dotted-decimal
 *   OID strings and their human names, plus arc conversion and DER
 *   encode/decode convenience. Every algorithm, attribute type, and
 *   extension in PKI is named by an OID, and resolving them through one
 *   registry -- rather than scattering magic dotted strings across the
 *   codebase -- is what lets a new algorithm be a data entry instead of a
 *   code change.
 *
 *   The seed set is declared by FAMILY: an OID belongs to a class with a
 *   shared base arc (the "starting variable" -- `2.5.4` for the RFC 5280
 *   attribute types, `2.5.29` for the extensions, `2.16.840.1.101.3.4` for
 *   the NIST algorithms), and each member names only its trailing arc. The
 *   full OID is derived from base + leaf at load, so the arc hierarchy that
 *   IS the OID namespace is modelled directly instead of re-spelled per
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

// (code, message) -> OidError, the factory shape the composed guards throw
// through so a malformed identifier keeps the oid/* typed verdict.
function _oidError(c, m) { return new OidError(c, m); }

// FAMILIES -- OIDs grouped by their shared base arc (the "similar starting
// variable" that defines a class). A member is `name: leaf`, where leaf is a
// trailing arc (number) or a short arc array for a multi-level leaf; the full
// arc is derived at load via base.concat(leaf). Declaring by family means no
// dotted-decimal OID literal appears in this source at all, and adding a
// member is one `name: leaf` line under its class -- no base to re-type.
var FAMILIES = {
  // RFC 5280 attribute types.
  attributeType: { base: [2, 5, 4], of: {
    commonName: 3, surname: 4, serialNumber: 5, countryName: 6,
    localityName: 7, stateOrProvinceName: 8, streetAddress: 9,
    organizationName: 10, organizationalUnitName: 11, title: 12, givenName: 42,
    // RFC 5755 sec. 4.4 attribute-certificate attribute types.
    clearance: 55, role: 72 } },

  // RFC 5280 certificate extensions.
  certExtension: { base: [2, 5, 29], of: {
    subjectKeyIdentifier: 14, keyUsage: 15, subjectAltName: 17, issuerAltName: 18,
    basicConstraints: 19,
    // CRL + CRL-entry extensions (RFC 5280 sec. 5.2, sec. 5.3)
    cRLNumber: 20, reasonCode: 21, invalidityDate: 24, deltaCRLIndicator: 27,
    issuingDistributionPoint: 28, certificateIssuer: 29,
    nameConstraints: 30, cRLDistributionPoints: 31,
    certificatePolicies: 32, policyMappings: 33, authorityKeyIdentifier: 35,
    policyConstraints: 36, extKeyUsage: 37, freshestCRL: 46,
    inhibitAnyPolicy: 54,
    // The two special-OID leaves under extension arcs (RFC 5280 sec. 4.2.1.4 /
    // sec. 4.2.1.12): the certificate-policies wildcard and the EKU wildcard.
    anyPolicy: [32, 0], anyExtendedKeyUsage: [37, 0],
    // RFC 5755 attribute-certificate extensions (sec. 4.3.2, sec. 4.3.6).
    targetInformation: 55, noRevAvail: 56 } },

  // PKIX private extensions on the id-pe arc (authorityInfoAccess et al, plus the
  // RFC 5755 attribute-certificate id-pe extensions: ac-auditIdentity sec. 4.3.1,
  // aaControls sec. 7.4, ac-proxying sec. 7.2).
  pkixAccess: { base: [1, 3, 6, 1, 5, 5, 7, 1], of: {
    authorityInfoAccess: 1, acAuditIdentity: 4, aaControls: 6, acProxying: 10,
    acmeIdentifier: 31 } },

  // id-aca -- RFC 5755 attribute-certificate attribute types on the id-pkix 10 arc:
  // authenticationInfo sec. 4.4.1 .. group sec. 4.4.4, plus encAttrs sec. 7.1 (the encrypted-
  // attribute wrapper, syntax ContentInfo). { id-aca 5 } is reserved.
  idAca: { base: [1, 3, 6, 1, 5, 5, 7, 10], of: {
    authenticationInfo: 1, accessIdentity: 2, chargingIdentity: 3, group: 4, encAttrs: 6 } },

  // The legacy RFC 3281 id-at-clearance on the X.501 selected-attribute-types arc.
  // RFC 5755 sec. 4.4.6 says implementations MUST NOT OUTPUT this form but SHOULD ACCEPT
  // it for decoding, so it is registered as an alias of "clearance". The canonical
  // name -> OID reverse stays the RFC 5755 attributeType-arc 2.5.4.55 (registered
  // first under attributeType, so it wins the reverse mapping).
  selectedAttrType: { base: [2, 5, 1, 5], of: { clearance: 55 } },

  // PKIX Access Descriptor methods (id-ad, RFC 5280 sec. 4.2.2.1/sec. 4.2.2.2). id-ad-ocsp
  // is the arc the OCSP responder OIDs hang under; id-ad-caIssuers names the AIA
  // CA-issuers access method.
  adAccess: { base: [1, 3, 6, 1, 5, 5, 7, 48], of: { ocsp: 1, caIssuers: 2 } },

  // OCSP (RFC 6960) on the id-pkix-ocsp arc (= id-ad-ocsp). id-pkix-ocsp-basic is
  // the ResponseBytes.responseType this build decodes; id-pkix-ocsp-nonce (sec. 4.4.1)
  // names the nonce extension; the remaining members name the other OCSP extensions
  // (CRL references, acceptable-response-types, archive-cutoff, service-locator,
  // preferred-signature-algorithms, extended-revoke -- RFC 6960 sec. 4.4, RFC 9654).
  ocsp: { base: [1, 3, 6, 1, 5, 5, 7, 48, 1], of: {
    ocspBasic: 1, ocspNonce: 2, ocspCrl: 3, ocspResponse: 4, ocspNoCheck: 5,
    ocspArchiveCutoff: 6, ocspServiceLocator: 7, ocspPrefSigAlgs: 8, ocspExtendedRevoke: 9 } },

  // CRMF (RFC 4211) registration controls (sec. 6) and registration info (sec. 7) on the
  // id-pkip arc (id-pkix 5). id-regCtrl (id-pkip 1) names the control types a
  // CertRequest carries; id-regInfo (id-pkip 2) names the registration-info types.
  // The parser surfaces each control/info value RAW keyed by these names.
  regCtrl: { base: [1, 3, 6, 1, 5, 5, 7, 5, 1], of: {
    regToken: 1, authenticator: 2, pkiPublicationInfo: 3, pkiArchiveOptions: 4, oldCertID: 5, protocolEncrKey: 6 } },
  regInfo: { base: [1, 3, 6, 1, 5, 5, 7, 5, 2], of: { utf8Pairs: 1, certReq: 2 } },

  // PKIX extended key purposes (id-kp, RFC 5280 sec. 4.2.1.12). timeStamping is required
  // -- critical and sole -- on an RFC 3161 TSA signing certificate (sec. 2.3).
  pkixKp: { base: [1, 3, 6, 1, 5, 5, 7, 3], of: {
    serverAuth: 1, clientAuth: 2, codeSigning: 3, emailProtection: 4, timeStamping: 8, ocspSigning: 9 } },

  // Google Certificate Transparency (RFC 6962) on the 1.3.6.1.4.1.11129.2.4 arc:
  // the SCT-list X.509 extension (sec. 3.3), the precertificate poison (sec. 3.1), the
  // precert-signing EKU (sec. 3.1, naming only), and the OCSP-delivered SCT list
  // (sec. 3.3). The SCT payload itself is TLS presentation language, not DER -- it is
  // parsed by lib/ct.js (pki.ct), never routed through the DER schema engine.
  ct: { base: [1, 3, 6, 1, 4, 1, 11129, 2, 4], of: {
    signedCertificateTimestampList: 2, precertificatePoison: 3,
    precertificateSigningCert: 4, ocspSignedCertificateTimestampList: 5 } },

  // Fulcio (Sigstore) X.509 certificate-extension arc. `.1.1`-`.1.6` are the
  // DEPRECATED members whose values are RAW UTF-8 strings (no DER wrapping);
  // `.1.7` is the OtherName SAN type; `.1.8` onward are DER-encoded ASN.1
  // UTF8String -- the decode MUST honor the raw-vs-DER split by member.
  fulcio: { base: [1, 3, 6, 1, 4, 1, 57264, 1], of: {
    issuerLegacy: 1, githubWorkflowTrigger: 2, githubWorkflowSha: 3,
    githubWorkflowName: 4, githubWorkflowRepository: 5, githubWorkflowRef: 6,
    otherName: 7, issuer: 8, buildSignerURI: 9, buildSignerDigest: 10,
    runnerEnvironment: 11, sourceRepositoryURI: 12, sourceRepositoryDigest: 13,
    sourceRepositoryRef: 14, sourceRepositoryIdentifier: 15,
    sourceRepositoryOwnerURI: 16, sourceRepositoryOwnerIdentifier: 17,
    buildConfigURI: 18, buildConfigDigest: 19, buildTrigger: 20,
    runInvocationURI: 21, sourceRepositoryVisibilityAtSigning: 22 } },

  // PKCS#1 RSA public-key + RSASSA signature algorithms.
  rsa: { base: [1, 2, 840, 113549, 1, 1], of: {
    rsaEncryption: 1, rsaesOaep: 7, mgf1: 8, pSpecified: 9, rsassaPss: 10,
    sha256WithRSAEncryption: 11,
    sha384WithRSAEncryption: 12, sha512WithRSAEncryption: 13 } },

  // PKCS#7 / CMS content types (RFC 5652 sec. 4, RFC 2315). id-signedData is the one
  // this toolkit structurally decodes; the rest are recognized-and-deferred.
  pkcs7: { base: [1, 2, 840, 113549, 1, 7], of: {
    data: 1, signedData: 2, envelopedData: 3, signedAndEnvelopedData: 4,
    digestedData: 5, encryptedData: 6 } },

  // PKCS#9 attribute types -- incl. the CMS signed-attribute OIDs (RFC 5652 sec. 11)
  // and the PKCS#12 bag attributes friendlyName / localKeyId (RFC 7292 sec. 4.2).
  pkcs9: { base: [1, 2, 840, 113549, 1, 9], of: {
    emailAddress: 1, contentType: 3, messageDigest: 4, signingTime: 5,
    countersignature: 6, challengePassword: 7, extensionRequest: 14,
    smimeCapabilities: 15, friendlyName: 20, localKeyId: 21 } },

  // PKCS#9 CertBag / CRLBag value discriminators (RFC 7292 sec. 4.2.3-sec. 4.2.4).
  pkcs9CertTypes: { base: [1, 2, 840, 113549, 1, 9, 22], of: { x509Certificate: 1, sdsiCertificate: 2 } },
  pkcs9CrlTypes:  { base: [1, 2, 840, 113549, 1, 9, 23], of: { x509CRL: 1 } },

  // PKCS#5 password-based schemes (RFC 8018) + the PBMAC1 MacData arm (RFC 9579).
  pkcs5: { base: [1, 2, 840, 113549, 1, 5], of: { pbkdf2: 12, pbes2: 13, pbmac1: 14 } },

  // CMP InfoTypeAndValue types -- id-it under id-pkix (RFC 9810 sec. 5.3.19; the
  // PKIXCMP-2023 module assigns these leaves, 8/9 unassigned).
  idIt: { base: [1, 3, 6, 1, 5, 5, 7, 4], of: {
    caProtEncCert: 1, signKeyPairTypes: 2, encKeyPairTypes: 3, preferredSymmAlg: 4,
    caKeyUpdateInfo: 5, currentCRL: 6, unsupportedOIDs: 7, keyPairParamReq: 10,
    keyPairParamRep: 11, revPassphrase: 12, implicitConfirm: 13, confirmWaitTime: 14,
    origPKIMessage: 15, suppLangTags: 16, caCerts: 17, rootCaKeyUpdate: 18,
    certReqTemplate: 19, rootCaCert: 20, certProfile: 21, crlStatusList: 22,
    crls: 23, kemCiphertextInfo: 24 } },

  // CMP message-protection MAC algorithms on the Entrust arc (RFC 9810
  // sec. 5.1.3.1/.2/.4; RFC 9481 sec. 6.1.1).
  entrustAlg: { base: [1, 2, 840, 113533, 7, 66], of: {
    passwordBasedMac: 13, kemBasedMac: 16, dhBasedMac: 30 } },

  // PKCS#12 bag types (RFC 7292 sec. 4.2, Appendix D).
  pkcs12BagTypes: { base: [1, 2, 840, 113549, 1, 12, 10, 1], of: {
    keyBag: 1, pkcs8ShroudedKeyBag: 2, certBag: 3, crlBag: 4, secretBag: 5, safeContentsBag: 6 } },

  // PKCS#12 password-based encryption schemes (RFC 7292 Appendix C) -- legacy
  // PBE identifiers still emitted by deployed exporters; recognized so a
  // shrouded bag's algorithm resolves to a name, never decrypted here.
  pkcs12Pbe: { base: [1, 2, 840, 113549, 1, 12, 1], of: {
    pbeWithSHAAnd128BitRC4: 1, pbeWithSHAAnd40BitRC4: 2,
    "pbeWithSHAAnd3-KeyTripleDES-CBC": 3, "pbeWithSHAAnd2-KeyTripleDES-CBC": 4,
    "pbeWithSHAAnd128BitRC2-CBC": 5, "pbeWithSHAAnd40BitRC2-CBC": 6 } },

  // RSADSI digest / HMAC algorithms (RFC 8018 sec. B.1) -- the PBKDF2 / PBMAC1 PRFs.
  rsadsiDigest: { base: [1, 2, 840, 113549, 2], of: {
    hmacWithSHA1: 7, hmacWithSHA224: 8, hmacWithSHA256: 9,
    hmacWithSHA384: 10, hmacWithSHA512: 11 } },

  // S/MIME content types on the PKCS#9 smime arc (RFC 5652, RFC 3161): id-ct.
  // authData is RFC 5652 sec. 9 AuthenticatedData; authEnvelopedData is RFC 5083.
  smimeCt: { base: [1, 2, 840, 113549, 1, 9, 16, 1], of: { authData: 2, tSTInfo: 4, authEnvelopedData: 23, encKeyWithID: 21 } },

  // S/MIME other-recipient-info types (id-ori, RFC 5652 sec. 6.2.5). id-ori-kem
  // carries a KEMRecipientInfo (RFC 9629) inside the ori [4] RecipientInfo arm.
  smimeOri: { base: [1, 2, 840, 113549, 1, 9, 16, 13], of: { kem: 3 } },

  // S/MIME algorithm identifiers (id-alg). The HKDF KDFs (RFC 8619) and the
  // CEK-HKDF content-encryption wrapper (RFC 9709) a KEMRecipientInfo names, plus
  // the RSA-KEM SPKI algorithm (RFC 9690). Parameters are absent for the HKDFs.
  smimeAlg: { base: [1, 2, 840, 113549, 1, 9, 16, 3], of: {
    "id-alg-PWRI-KEK": 9,
    "id-rsa-kem": 14, "id-alg-hss-lms-hashsig": 17,
    // RFC 8418 X25519/X448 key-agreement schemes (HKDF-based).
    "dhSinglePass-stdDH-hkdf-sha256-scheme": 19, "dhSinglePass-stdDH-hkdf-sha384-scheme": 20,
    "dhSinglePass-stdDH-hkdf-sha512-scheme": 21,
    hkdfWithSha256: 28, hkdfWithSha384: 29, hkdfWithSha512: 30, cekHkdfSha256: 31 } },

  // RFC 5753 ephemeral-static ECDH key-agreement schemes -- the keyEncryptionAlgorithm OID of a
  // kari, whose PARAMETER is the KeyWrapAlgorithm (so these are NOT params-absent). The X9.63 KDF
  // variants: stdDH (SECG arc 1.3.132.1.11) + cofactorDH (1.3.132.1.14) for SHA-224/256/384/512,
  // and the SHA-1 KDF pair on the ANSI-X9.63 arc (the OpenSSL default).
  secgStdDH: { base: [1, 3, 132, 1, 11], of: {
    "dhSinglePass-stdDH-sha224kdf-scheme": 0, "dhSinglePass-stdDH-sha256kdf-scheme": 1,
    "dhSinglePass-stdDH-sha384kdf-scheme": 2, "dhSinglePass-stdDH-sha512kdf-scheme": 3 } },
  secgCofactorDH: { base: [1, 3, 132, 1, 14], of: {
    "dhSinglePass-cofactorDH-sha224kdf-scheme": 0, "dhSinglePass-cofactorDH-sha256kdf-scheme": 1,
    "dhSinglePass-cofactorDH-sha384kdf-scheme": 2, "dhSinglePass-cofactorDH-sha512kdf-scheme": 3 } },
  x963Schemes: { base: [1, 3, 133, 16, 840, 63, 0], of: {
    "dhSinglePass-stdDH-sha1kdf-scheme": 2, "dhSinglePass-cofactorDH-sha1kdf-scheme": 3 } },

  // PKIX algorithms arc -- the stateful hash-based signature algorithm
  // identifiers (RFC 9802 sec. 4). HSS/LMS additionally has the SMIME
  // id-alg-hss-lms-hashsig OID above (RFC 9708 / RFC 9802 share it).
  pkixAlg: { base: [1, 3, 6, 1, 5, 5, 7, 6], of: {
    "id-alg-xmss-hashsig": 34, "id-alg-xmssmt-hashsig": 35,
    // Composite ML-DSA signature algorithms (draft-ietf-lamps-pq-composite-sigs
    // sec. 6): a PQ ML-DSA paired with a traditional RSA / ECDSA / EdDSA so the
    // certificate stays trustworthy if EITHER primitive is later broken.
    "id-MLDSA44-RSA2048-PSS-SHA256": 37, "id-MLDSA44-RSA2048-PKCS15-SHA256": 38,
    "id-MLDSA44-Ed25519-SHA512": 39, "id-MLDSA44-ECDSA-P256-SHA256": 40,
    "id-MLDSA65-RSA3072-PSS-SHA512": 41, "id-MLDSA65-RSA3072-PKCS15-SHA512": 42,
    "id-MLDSA65-RSA4096-PSS-SHA512": 43, "id-MLDSA65-RSA4096-PKCS15-SHA512": 44,
    "id-MLDSA65-ECDSA-P256-SHA512": 45, "id-MLDSA65-ECDSA-P384-SHA512": 46,
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512": 47, "id-MLDSA65-Ed25519-SHA512": 48,
    "id-MLDSA87-ECDSA-P384-SHA512": 49, "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512": 50,
    "id-MLDSA87-Ed448-SHAKE256": 51, "id-MLDSA87-RSA3072-PSS-SHA512": 52,
    "id-MLDSA87-RSA4096-PSS-SHA512": 53, "id-MLDSA87-ECDSA-P521-SHA512": 54 } },

  // RSA-KEM key-transport algorithm (RFC 9690, obsoletes RFC 5990) on the ISO
  // 18033-2 arc -- the kem OID an RSA KEMRecipientInfo carries (distinct from the
  // id-rsa-kem SPKI algorithm above).
  iso18033: { base: [1, 0, 18033, 2, 2], of: { "id-kem-rsa": 4 } },

  // RFC 3370 HMAC-SHA-1 MAC algorithm (the AuthenticatedData macAlgorithm on the
  // PKIX arc, distinct from the RSADSI hmacWithSHA1).
  pkixHmac: { base: [1, 3, 6, 1, 5, 5, 8, 1], of: { "hmac-SHA1": 2 } },

  // S/MIME authenticated attributes (id-aa, RFC 2634 / RFC 5035 / RFC 5816). The ESS
  // signing-certificate attributes bind a CMS / TSP SignerInfo to its signing cert;
  // signingCertificateV2 (ESSCertIDv2) carries a non-SHA-1 cert hash (RFC 5816 sec. 2.2.1).
  // The RFC 2634 originals (receiptRequest .. contentReference) are name-only: they
  // resolve to a name so an unsupported-attribute diagnostic is legible, not decoded.
  // decryptKeyID / asymmDecryptKeyID name the out-of-band key-encryption key a
  // /serverkeygen client references (RFC 4108 sec. 2.2.5 / RFC 7030 sec. 4.4.1);
  // certificationRequestInfoTemplate / extensionReqTemplate are the RFC 9908
  // CSR-attributes template carriers.
  smimeAa: { base: [1, 2, 840, 113549, 1, 9, 16, 2], of: {
    receiptRequest: 1, eSSSecurityLabel: 2, mlExpansionHistory: 3, contentHints: 4,
    msgSigDigest: 5, contentIdentifier: 7, equivalentLabels: 9, contentReference: 10,
    signingCertificate: 12, timeStampToken: 14, decryptKeyID: 37, signingCertificateV2: 47,
    asymmDecryptKeyID: 54, certificationRequestInfoTemplate: 61, extensionReqTemplate: 62 } },

  // ANSI X9.62 EC public key, named curve, and ECDSA signatures.
  ansiX962: { base: [1, 2, 840, 10045], of: {
    ecPublicKey: [2, 1], prime256v1: [3, 1, 7],
    ecdsaWithSHA256: [4, 3, 2], ecdsaWithSHA384: [4, 3, 3], ecdsaWithSHA512: [4, 3, 4] } },

  // SECG named curves.
  secg: { base: [1, 3, 132, 0], of: { secp384r1: 34, secp521r1: 35 } },

  // Edwards / Montgomery curves (RFC 8410).
  edwards: { base: [1, 3, 101], of: { X25519: 110, X448: 111, Ed25519: 112, Ed448: 113 } },

  // OIW Secsig SHA-1 (1.3.14.3.2.26) -- the most common OCSP CertID hashAlgorithm;
  // nistHash covers only SHA-256 and above.
  oiwSecsig: { base: [1, 3, 14, 3, 2], of: { sha1: 26 } },

  // NIST AES content-encryption algorithms (arc 2.16.840.1.101.3.4.1) -- the
  // modern PBES2 / CMS content ciphers a PKCS#12 or EnvelopedData names.
  nistAes: { base: [2, 16, 840, 1, 101, 3, 4, 1], of: {
    "aes128-CBC": 2, "aes128-wrap": 5, "aes128-GCM": 6, "aes128-CCM": 7,
    "aes192-CBC": 22, "aes192-wrap": 25, "aes192-GCM": 26, "aes192-CCM": 27,
    "aes256-CBC": 42, "aes256-wrap": 45, "aes256-GCM": 46, "aes256-CCM": 47 } },

  // NIST hash functions (SHA-2, SHA-3, SHAKE).
  nistHash: { base: [2, 16, 840, 1, 101, 3, 4, 2], of: {
    sha256: 1, sha384: 2, sha512: 3, "sha3-256": 8, "sha3-512": 10, shake128: 11, shake256: 12 } },

  // NIST signature algorithms -- FIPS 204 ML-DSA + FIPS 205 SLH-DSA share the
  // signature arc 2.16.840.1.101.3.4.3. RFC 9909 sec. 3 assigns the 12 Pure SLH-DSA
  // sets .20-.31 (SHA-2 .20-.25, SHAKE .26-.31) and the 12 pre-hash HashSLH-DSA
  // sets .35-.46, each pairing a parameter set with its message-digest hash. The
  // parameters MUST be absent for every one of them (enforced via paramsMustBeAbsent).
  nistSig: { base: [2, 16, 840, 1, 101, 3, 4, 3], of: {
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

  // NIST KEM -- FIPS 203 ML-KEM (arc 2.16.840.1.101.3.4.4).
  nistKem: { base: [2, 16, 840, 1, 101, 3, 4, 4], of: {
    "id-ml-kem-512": 1, "id-ml-kem-768": 2, "id-ml-kem-1024": 3 } },

  // Misc datatypes (RFC 4519 domainComponent).
  datatype: { base: [0, 9, 2342, 19200300, 100, 1], of: { domainComponent: 25 } },

  // FIDO Alliance generated-credential certificate extensions (arc
  // 1.3.6.1.4.1.45724.1.1). id-fido-gen-ce-aaguid carries the authenticator's
  // AAGUID -- a WebAuthn packed-attestation leaf-cert extension (WebAuthn L3 8.2.1)
  // whose OCTET STRING value MUST equal the attestedCredentialData aaguid.
  fidoGenCe: { base: [1, 3, 6, 1, 4, 1, 45724, 1, 1], of: { idFidoGenCeAaguid: 4 } },

  // Android Keystore key-attestation extension (arc 1.3.6.1.4.1.11129.2.1). The
  // keyDescription extension carries the hardware-backed KeyDescription SEQUENCE a
  // WebAuthn android-key attestation leaf cert asserts (WebAuthn L3 8.4.1).
  androidKeystore: { base: [1, 3, 6, 1, 4, 1, 11129, 2, 1], of: { keyDescription: 17 } },

  // Apple anonymous-attestation extension (arc 1.2.840.113635.100.8). The value in
  // a WebAuthn apple attestation leaf cert embeds the SHA-256 nonce over
  // authenticatorData || clientDataHash (WebAuthn L3 8.8).
  appleAttest: { base: [1, 2, 840, 113635, 100, 8], of: { appleAnonymousAttestation: 2 } },

  // TCG (Trusted Computing Group) TPM identifiers on the 2.23.133 arc. tcgKp
  // (id-tcg-kp) names the AIK-certificate extended key purpose a WebAuthn tpm
  // attestation leaf cert MUST carry; tcgAt (id-tcg-at) names the tpmManufacturer /
  // tpmModel / tpmVersion directory attributes its subjectAltName MUST carry
  // (WebAuthn L3 8.3.1).
  tcgKp: { base: [2, 23, 133, 8], of: { tcgKpAikCertificate: 3 } },
  tcgAt: { base: [2, 23, 133, 2], of: { tpmManufacturer: 1, tpmModel: 2, tpmVersion: 3 } },
};

var _byOid = new Map();
var _byName = new Map();

function _index(dotted, name) {
  _byOid.set(dotted, name);
  // First registration of a name wins as the canonical reverse entry.
  if (!_byName.has(name)) _byName.set(name, dotted);
}

// An arc is a non-negative integer. Large arcs (a 128-bit UUID-based arc
// exceeds 2^53) must be BigInt to survive without precision loss, so both
// a non-negative safe-integer Number and a non-negative BigInt are valid.
function _isArc(a) {
  if (typeof a === "bigint") return a >= 0n;
  return typeof a === "number" && Number.isSafeInteger(a) && a >= 0;
}

// Seed the registry family by family -- the built-in set is registered through
// the exact same primitive an operator uses (registerFamily), so there is one
// path from a declared family to indexed OIDs and no dotted literals anywhere.
Object.keys(FAMILIES).forEach(function (fam) {
  registerFamily(FAMILIES[fam].base, FAMILIES[fam].of);
});

function _assertDotted(dotted, who) {
  // SYNTAX only (canonical dotted form, no leading-zero arc that would round-trip
  // to a DIFFERENT OID). For the LOOKUP entry points (name / has): a well-formed
  // but non-encodable OID is simply not registered (a miss), not an error, so the
  // X.660 arc bounds are waived (boundsCode null).
  guard.identifier.assertCanonicalOid(dotted, _oidError, "oid/bad-input", who, null);
}

function _assertEncodable(dotted, who) {
  // SYNTAX and the X.660 arc bounds -- for the paths that assert / convert a real
  // encodable OID (toArcs / toDER / register), where an out-of-bounds arc is a
  // hard reject (oid/bad-arc), so the string form agrees with the DER form.
  guard.identifier.assertCanonicalOid(dotted, _oidError, "oid/bad-input", who, "oid/bad-arc");
}

// X.660 encodability: the root arc is 0..2 and, under roots 0 and 1, the
// second arc is 0..39 (the first two arcs pack into a single octet as
// 40*X+Y). An OID outside these bounds can never be DER-encoded, so a
// registration carrying one fails at config time rather than at first use.
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
  // _assertDotted now enforces the X.660 arc bounds on the string form too, so
  // the separate arc-based check register used to run is redundant here (it is
  // kept for registerFamily, which validates arcs it assembles, not a string).
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
 * so a family is declared as its hierarchy rather than as re-spelled full
 * paths. This is the primitive the built-in seed set itself is built from.
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

// toArcs / fromArcs -- dotted <-> numeric arc array. Arcs come back as
// Number where safe and BigInt where an arc exceeds 2^53 (rare, but a
// UUID-based OID arc can), so the round-trip never loses precision.
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

// DER convenience -- thin pass-throughs to the codec so callers reach for
// one namespace when they have a dotted string in hand.
function toDER(dotted) { _assertEncodable(dotted, "toDER"); return asn1.build.oid(dotted); }
function fromDER(input) {
  var buf = guard.bytes.view(input, OidError, "oid/bad-input", "fromDER");
  var node = asn1.decode(buf);
  return asn1.read.oid(node);
}

// Algorithm identifiers whose `parameters` field MUST be absent -- no explicit
// NULL, no bytes. The FIPS 204 ML-DSA and FIPS 205 SLH-DSA signature families
// and the RFC 8410 Edwards / Montgomery curves each carry this MUST: RFC 9909 sec. 3
// (SLH-DSA in X.509), RFC 9814 sec. 4 (SLH-DSA in CMS), RFC 9881 sec. 2 (ML-DSA in X.509),
// RFC 8410 sec. 3 (Ed25519 / Ed448 / X25519 / X448). Built by NAME through the same
// registry every caller uses, so a typo fails closed at load rather than silently
// dropping a member. One set drives the single shared AlgorithmIdentifier reject
// (schema-pkix), so every format consumer inherits the rule with no per-format code.
var _PARAMS_ABSENT = new Set();
[
  "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87",
  "id-slh-dsa-sha2-128s", "id-slh-dsa-sha2-128f", "id-slh-dsa-sha2-192s",
  "id-slh-dsa-sha2-192f", "id-slh-dsa-sha2-256s", "id-slh-dsa-sha2-256f",
  "id-slh-dsa-shake-128s", "id-slh-dsa-shake-128f", "id-slh-dsa-shake-192s",
  "id-slh-dsa-shake-192f", "id-slh-dsa-shake-256s", "id-slh-dsa-shake-256f",
  // Pre-hash HashSLH-DSA sets (RFC 9909 sec. 3) -- parameters MUST be absent too.
  "id-hash-slh-dsa-sha2-128s-with-sha256", "id-hash-slh-dsa-sha2-128f-with-sha256",
  "id-hash-slh-dsa-sha2-192s-with-sha512", "id-hash-slh-dsa-sha2-192f-with-sha512",
  "id-hash-slh-dsa-sha2-256s-with-sha512", "id-hash-slh-dsa-sha2-256f-with-sha512",
  "id-hash-slh-dsa-shake-128s-with-shake128", "id-hash-slh-dsa-shake-128f-with-shake128",
  "id-hash-slh-dsa-shake-192s-with-shake256", "id-hash-slh-dsa-shake-192f-with-shake256",
  "id-hash-slh-dsa-shake-256s-with-shake256", "id-hash-slh-dsa-shake-256f-with-shake256",
  "Ed25519", "Ed448", "X25519", "X448",
  // FIPS 203 ML-KEM (RFC 9935 sec. 3 certificates + RFC 9936 sec. 3 CMS: PARAMS ARE absent).
  "id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024",
  // HKDF key-derivation identifiers (RFC 8619 sec. 2: when any of these appear
  // within AlgorithmIdentifier, the parameters component SHALL be absent).
  "hkdfWithSha256", "hkdfWithSha384", "hkdfWithSha512",
  // Stateful hash-based signatures (RFC 9802 sec. 4 / RFC 9708): the parameters
  // field MUST be absent for HSS/LMS, XMSS, and XMSS^MT public keys and signatures.
  "id-alg-hss-lms-hashsig", "id-alg-xmss-hashsig", "id-alg-xmssmt-hashsig",
  // Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs sec. 5.3 + Figure 1:
  // the parameters field MUST be absent for every composite AlgorithmIdentifier).
  "id-MLDSA44-RSA2048-PSS-SHA256", "id-MLDSA44-RSA2048-PKCS15-SHA256",
  "id-MLDSA44-Ed25519-SHA512", "id-MLDSA44-ECDSA-P256-SHA256",
  "id-MLDSA65-RSA3072-PSS-SHA512", "id-MLDSA65-RSA3072-PKCS15-SHA512",
  "id-MLDSA65-RSA4096-PSS-SHA512", "id-MLDSA65-RSA4096-PKCS15-SHA512",
  "id-MLDSA65-ECDSA-P256-SHA512", "id-MLDSA65-ECDSA-P384-SHA512",
  "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "id-MLDSA65-Ed25519-SHA512",
  "id-MLDSA87-ECDSA-P384-SHA512", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512",
  "id-MLDSA87-Ed448-SHAKE256", "id-MLDSA87-RSA3072-PSS-SHA512",
  "id-MLDSA87-RSA4096-PSS-SHA512", "id-MLDSA87-ECDSA-P521-SHA512",
].forEach(function (nm) {
  var d = byName(nm);
  // A seed-list typo must fail at module load -- admitting undefined would
  // make paramsMustBeAbsent(byName(sameTypo)) return TRUE for every other
  // unregistered name (Set.has(undefined)), a fail-open guard.
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
 * field as ABSENT (not an explicit NULL, not any bytes): the FIPS 204 ML-DSA and
 * FIPS 205 SLH-DSA signature families and the RFC 8410 Edwards / Montgomery
 * curves. The shared AlgorithmIdentifier decoder consults this and fails closed
 * on a present-parameters violation, so every format inherits the rule.
 *
 * @example
 *   pki.oid.paramsMustBeAbsent(pki.oid.byName("id-slh-dsa-sha2-128s")); // -> true
 *   pki.oid.paramsMustBeAbsent(pki.oid.byName("rsaEncryption"));        // -> false
 */
function paramsMustBeAbsent(dotted) {
  return _PARAMS_ABSENT.has(dotted);
}

module.exports = {
  name:           name,
  byName:         byName,
  has:            has,
  paramsMustBeAbsent: paramsMustBeAbsent,
  register:       register,
  registerFamily: registerFamily,
  all:            all,
  toArcs:         toArcs,
  fromArcs:       fromArcs,
  toDER:          toDER,
  fromDER:        fromDER,
};
