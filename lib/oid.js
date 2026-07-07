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
 *   registry — rather than scattering magic dotted strings across the
 *   codebase — is what lets a new algorithm be a data entry instead of a
 *   code change.
 *
 *   The seed set is declared by FAMILY: an OID belongs to a class with a
 *   shared base arc (the "starting variable" — `2.5.4` for the RFC 5280
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
 *   Two-way OID ↔ name registry with arc conversion, seeded by family from
 *   the RFC 5280 and NIST post-quantum object identifiers.
 */

var asn1 = require("./asn1-der");
var frameworkError = require("./framework-error");

var OidError = frameworkError.OidError;

// FAMILIES — OIDs grouped by their shared base arc (the "similar starting
// variable" that defines a class). A member is `name: leaf`, where leaf is a
// trailing arc (number) or a short arc array for a multi-level leaf; the full
// arc is derived at load via base.concat(leaf). Declaring by family means no
// dotted-decimal OID literal appears in this source at all, and adding a
// member is one `name: leaf` line under its class — no base to re-type.
var FAMILIES = {
  // RFC 5280 attribute types.
  attributeType: { base: [2, 5, 4], of: {
    commonName: 3, surname: 4, serialNumber: 5, countryName: 6,
    localityName: 7, stateOrProvinceName: 8, streetAddress: 9,
    organizationName: 10, organizationalUnitName: 11, title: 12, givenName: 42,
    // RFC 5755 §4.4 attribute-certificate attribute types.
    clearance: 55, role: 72 } },

  // RFC 5280 certificate extensions.
  certExtension: { base: [2, 5, 29], of: {
    subjectKeyIdentifier: 14, keyUsage: 15, subjectAltName: 17, issuerAltName: 18,
    basicConstraints: 19,
    // CRL + CRL-entry extensions (RFC 5280 §5.2, §5.3)
    cRLNumber: 20, reasonCode: 21, invalidityDate: 24, deltaCRLIndicator: 27,
    issuingDistributionPoint: 28, certificateIssuer: 29,
    nameConstraints: 30, cRLDistributionPoints: 31,
    certificatePolicies: 32, policyMappings: 33, authorityKeyIdentifier: 35,
    policyConstraints: 36, extKeyUsage: 37, freshestCRL: 46,
    inhibitAnyPolicy: 54,
    // The two special-OID leaves under extension arcs (RFC 5280 §4.2.1.4 /
    // §4.2.1.12): the certificate-policies wildcard and the EKU wildcard.
    anyPolicy: [32, 0], anyExtendedKeyUsage: [37, 0],
    // RFC 5755 attribute-certificate extensions (§4.3.2, §4.3.6).
    targetInformation: 55, noRevAvail: 56 } },

  // PKIX private extensions on the id-pe arc (authorityInfoAccess et al, plus the
  // RFC 5755 attribute-certificate id-pe extensions: ac-auditIdentity §4.3.1,
  // aaControls §7.4, ac-proxying §7.2).
  pkixAccess: { base: [1, 3, 6, 1, 5, 5, 7, 1], of: {
    authorityInfoAccess: 1, acAuditIdentity: 4, aaControls: 6, acProxying: 10 } },

  // id-aca — RFC 5755 attribute-certificate attribute types on the id-pkix 10 arc:
  // authenticationInfo §4.4.1 .. group §4.4.4, plus encAttrs §7.1 (the encrypted-
  // attribute wrapper, syntax ContentInfo). { id-aca 5 } is reserved.
  idAca: { base: [1, 3, 6, 1, 5, 5, 7, 10], of: {
    authenticationInfo: 1, accessIdentity: 2, chargingIdentity: 3, group: 4, encAttrs: 6 } },

  // The legacy RFC 3281 id-at-clearance on the X.501 selected-attribute-types arc.
  // RFC 5755 §4.4.6 says implementations MUST NOT OUTPUT this form but SHOULD ACCEPT
  // it for decoding, so it is registered as an alias of "clearance". The canonical
  // name -> OID reverse stays the RFC 5755 attributeType-arc 2.5.4.55 (registered
  // first under attributeType, so it wins the reverse mapping).
  selectedAttrType: { base: [2, 5, 1, 5], of: { clearance: 55 } },

  // PKIX Access Descriptor methods (id-ad, RFC 5280 §4.2.2.1/§4.2.2.2). id-ad-ocsp
  // is the arc the OCSP responder OIDs hang under; id-ad-caIssuers names the AIA
  // CA-issuers access method.
  adAccess: { base: [1, 3, 6, 1, 5, 5, 7, 48], of: { ocsp: 1, caIssuers: 2 } },

  // OCSP (RFC 6960) on the id-pkix-ocsp arc (= id-ad-ocsp). id-pkix-ocsp-basic is
  // the ResponseBytes.responseType this build decodes; id-pkix-ocsp-nonce (§4.4.1)
  // names the nonce extension; the remaining members name the other OCSP extensions
  // (CRL references, acceptable-response-types, archive-cutoff, service-locator,
  // preferred-signature-algorithms, extended-revoke — RFC 6960 §4.4, RFC 9654).
  ocsp: { base: [1, 3, 6, 1, 5, 5, 7, 48, 1], of: {
    ocspBasic: 1, ocspNonce: 2, ocspCrl: 3, ocspResponse: 4, ocspNoCheck: 5,
    ocspArchiveCutoff: 6, ocspServiceLocator: 7, ocspPrefSigAlgs: 8, ocspExtendedRevoke: 9 } },

  // CRMF (RFC 4211) registration controls (§6) and registration info (§7) on the
  // id-pkip arc (id-pkix 5). id-regCtrl (id-pkip 1) names the control types a
  // CertRequest carries; id-regInfo (id-pkip 2) names the registration-info types.
  // The parser surfaces each control/info value RAW keyed by these names.
  regCtrl: { base: [1, 3, 6, 1, 5, 5, 7, 5, 1], of: {
    regToken: 1, authenticator: 2, pkiPublicationInfo: 3, pkiArchiveOptions: 4, oldCertID: 5, protocolEncrKey: 6 } },
  regInfo: { base: [1, 3, 6, 1, 5, 5, 7, 5, 2], of: { utf8Pairs: 1, certReq: 2 } },

  // PKIX extended key purposes (id-kp, RFC 5280 §4.2.1.12). timeStamping is required
  // — critical and sole — on an RFC 3161 TSA signing certificate (§2.3).
  pkixKp: { base: [1, 3, 6, 1, 5, 5, 7, 3], of: {
    serverAuth: 1, clientAuth: 2, codeSigning: 3, emailProtection: 4, timeStamping: 8, ocspSigning: 9 } },

  // PKCS#1 RSA public-key + RSASSA signature algorithms.
  rsa: { base: [1, 2, 840, 113549, 1, 1], of: {
    rsaEncryption: 1, rsaesOaep: 7, mgf1: 8, rsassaPss: 10,
    sha256WithRSAEncryption: 11,
    sha384WithRSAEncryption: 12, sha512WithRSAEncryption: 13 } },

  // PKCS#7 / CMS content types (RFC 5652 §4, RFC 2315). id-signedData is the one
  // this toolkit structurally decodes; the rest are recognized-and-deferred.
  pkcs7: { base: [1, 2, 840, 113549, 1, 7], of: {
    data: 1, signedData: 2, envelopedData: 3, signedAndEnvelopedData: 4,
    digestedData: 5, encryptedData: 6 } },

  // PKCS#9 attribute types — incl. the CMS signed-attribute OIDs (RFC 5652 §11)
  // and the PKCS#12 bag attributes friendlyName / localKeyId (RFC 7292 §4.2).
  pkcs9: { base: [1, 2, 840, 113549, 1, 9], of: {
    emailAddress: 1, contentType: 3, messageDigest: 4, signingTime: 5,
    challengePassword: 7, extensionRequest: 14, friendlyName: 20, localKeyId: 21 } },

  // PKCS#9 CertBag / CRLBag value discriminators (RFC 7292 §4.2.3-§4.2.4).
  pkcs9CertTypes: { base: [1, 2, 840, 113549, 1, 9, 22], of: { x509Certificate: 1, sdsiCertificate: 2 } },
  pkcs9CrlTypes:  { base: [1, 2, 840, 113549, 1, 9, 23], of: { x509CRL: 1 } },

  // PKCS#5 password-based schemes (RFC 8018) + the PBMAC1 MacData arm (RFC 9579).
  pkcs5: { base: [1, 2, 840, 113549, 1, 5], of: { pbkdf2: 12, pbes2: 13, pbmac1: 14 } },

  // PKCS#12 bag types (RFC 7292 §4.2, Appendix D).
  pkcs12BagTypes: { base: [1, 2, 840, 113549, 1, 12, 10, 1], of: {
    keyBag: 1, pkcs8ShroudedKeyBag: 2, certBag: 3, crlBag: 4, secretBag: 5, safeContentsBag: 6 } },

  // PKCS#12 password-based encryption schemes (RFC 7292 Appendix C) — legacy
  // PBE identifiers still emitted by deployed exporters; recognized so a
  // shrouded bag's algorithm resolves to a name, never decrypted here.
  pkcs12Pbe: { base: [1, 2, 840, 113549, 1, 12, 1], of: {
    pbeWithSHAAnd128BitRC4: 1, pbeWithSHAAnd40BitRC4: 2,
    "pbeWithSHAAnd3-KeyTripleDES-CBC": 3, "pbeWithSHAAnd2-KeyTripleDES-CBC": 4,
    "pbeWithSHAAnd128BitRC2-CBC": 5, "pbeWithSHAAnd40BitRC2-CBC": 6 } },

  // RSADSI digest / HMAC algorithms (RFC 8018 §B.1) — the PBKDF2 / PBMAC1 PRFs.
  rsadsiDigest: { base: [1, 2, 840, 113549, 2], of: {
    hmacWithSHA1: 7, hmacWithSHA224: 8, hmacWithSHA256: 9,
    hmacWithSHA384: 10, hmacWithSHA512: 11 } },

  // S/MIME content types on the PKCS#9 smime arc (RFC 5652, RFC 3161): id-ct.
  smimeCt: { base: [1, 2, 840, 113549, 1, 9, 16, 1], of: { authData: 2, tSTInfo: 4, encKeyWithID: 21 } },

  // S/MIME authenticated attributes (id-aa, RFC 2634 / RFC 5035 / RFC 5816). The ESS
  // signing-certificate attributes bind a CMS / TSP SignerInfo to its signing cert;
  // signingCertificateV2 (ESSCertIDv2) carries a non-SHA-1 cert hash (RFC 5816 §2.2.1).
  smimeAa: { base: [1, 2, 840, 113549, 1, 9, 16, 2], of: {
    signingCertificate: 12, timeStampToken: 14, signingCertificateV2: 47 } },

  // ANSI X9.62 EC public key, named curve, and ECDSA signatures.
  ansiX962: { base: [1, 2, 840, 10045], of: {
    ecPublicKey: [2, 1], prime256v1: [3, 1, 7],
    ecdsaWithSHA256: [4, 3, 2], ecdsaWithSHA384: [4, 3, 3], ecdsaWithSHA512: [4, 3, 4] } },

  // SECG named curves.
  secg: { base: [1, 3, 132, 0], of: { secp384r1: 34, secp521r1: 35 } },

  // Edwards / Montgomery curves (RFC 8410).
  edwards: { base: [1, 3, 101], of: { X25519: 110, X448: 111, Ed25519: 112, Ed448: 113 } },

  // OIW Secsig SHA-1 (1.3.14.3.2.26) — the most common OCSP CertID hashAlgorithm;
  // nistHash covers only SHA-256 and above.
  oiwSecsig: { base: [1, 3, 14, 3, 2], of: { sha1: 26 } },

  // NIST AES content-encryption algorithms (arc 2.16.840.1.101.3.4.1) — the
  // modern PBES2 / CMS content ciphers a PKCS#12 or EnvelopedData names.
  nistAes: { base: [2, 16, 840, 1, 101, 3, 4, 1], of: {
    "aes128-CBC": 2, "aes128-GCM": 6, "aes192-CBC": 22, "aes192-GCM": 26,
    "aes256-CBC": 42, "aes256-GCM": 46 } },

  // NIST hash functions (SHA-2, SHA-3, SHAKE).
  nistHash: { base: [2, 16, 840, 1, 101, 3, 4, 2], of: {
    sha256: 1, sha384: 2, sha512: 3, "sha3-256": 8, "sha3-512": 10, shake256: 12 } },

  // NIST signature algorithms — FIPS 204 ML-DSA + FIPS 205 SLH-DSA share the
  // signature arc 2.16.840.1.101.3.4.3. The 12 Pure SLH-DSA parameter sets are
  // assigned sequentially (RFC 9909 §3): the SHA-2 sets .20-.25, then the SHAKE
  // sets .26-.31.
  nistSig: { base: [2, 16, 840, 1, 101, 3, 4, 3], of: {
    "id-ml-dsa-44": 17, "id-ml-dsa-65": 18, "id-ml-dsa-87": 19,
    "id-slh-dsa-sha2-128s": 20, "id-slh-dsa-sha2-128f": 21,
    "id-slh-dsa-sha2-192s": 22, "id-slh-dsa-sha2-192f": 23,
    "id-slh-dsa-sha2-256s": 24, "id-slh-dsa-sha2-256f": 25,
    "id-slh-dsa-shake-128s": 26, "id-slh-dsa-shake-128f": 27,
    "id-slh-dsa-shake-192s": 28, "id-slh-dsa-shake-192f": 29,
    "id-slh-dsa-shake-256s": 30, "id-slh-dsa-shake-256f": 31 } },

  // NIST KEM — FIPS 203 ML-KEM (arc 2.16.840.1.101.3.4.4).
  nistKem: { base: [2, 16, 840, 1, 101, 3, 4, 4], of: {
    "id-ml-kem-512": 1, "id-ml-kem-768": 2, "id-ml-kem-1024": 3 } },

  // Misc datatypes (RFC 4519 domainComponent).
  datatype: { base: [0, 9, 2342, 19200300, 100, 1], of: { domainComponent: 25 } },
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

// Seed the registry family by family — the built-in set is registered through
// the exact same primitive an operator uses (registerFamily), so there is one
// path from a declared family to indexed OIDs and no dotted literals anywhere.
Object.keys(FAMILIES).forEach(function (fam) {
  registerFamily(FAMILIES[fam].base, FAMILIES[fam].of);
});

function _assertDotted(dotted, who) {
  if (typeof dotted !== "string" || !/^\d+(\.\d+)+$/.test(dotted)) {
    throw new OidError("oid/bad-input", who + ": expected a dotted-decimal OID string");
  }
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
 * Add (or override) an OID → name mapping so an operator's private or
 * newly-standardized arc resolves through the same registry as the seed
 * set. A later registration of the same OID replaces the forward name;
 * the reverse (name → OID) keeps the first registration as canonical.
 *
 * @example
 *   pki.oid.register("1.3.6.1.4.1.99999.1", "acmeWidgetPolicy");
 */
function register(dotted, n) {
  _assertDotted(dotted, "register");
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
 * each name to its trailing arc — a number, or a short arc array for a
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
    _index(arcs.join("."), nm);
  });
}

function all() {
  var out = {};
  _byOid.forEach(function (v, k) { out[k] = v; });
  return out;
}

// toArcs / fromArcs — dotted <-> numeric arc array. Arcs come back as
// Number where safe and BigInt where an arc exceeds 2^53 (rare, but a
// UUID-based OID arc can), so the round-trip never loses precision.
function toArcs(dotted) {
  _assertDotted(dotted, "toArcs");
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

// DER convenience — thin pass-throughs to the codec so callers reach for
// one namespace when they have a dotted string in hand.
function toDER(dotted) { _assertDotted(dotted, "toDER"); return asn1.build.oid(dotted); }
function fromDER(input) {
  var buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  var node = asn1.decode(buf);
  return asn1.read.oid(node);
}

module.exports = {
  name:           name,
  byName:         byName,
  has:            has,
  register:       register,
  registerFamily: registerFamily,
  all:            all,
  toArcs:         toArcs,
  fromArcs:       fromArcs,
  toDER:          toDER,
  fromDER:        fromDER,
};
