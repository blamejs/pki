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
    organizationName: 10, organizationalUnitName: 11, title: 12, givenName: 42 } },

  // RFC 5280 certificate extensions.
  certExtension: { base: [2, 5, 29], of: {
    subjectKeyIdentifier: 14, keyUsage: 15, subjectAltName: 17, issuerAltName: 18,
    basicConstraints: 19,
    // CRL + CRL-entry extensions (RFC 5280 §5.2, §5.3)
    cRLNumber: 20, reasonCode: 21, invalidityDate: 24, deltaCRLIndicator: 27,
    issuingDistributionPoint: 28, certificateIssuer: 29,
    nameConstraints: 30, cRLDistributionPoints: 31,
    certificatePolicies: 32, authorityKeyIdentifier: 35, extKeyUsage: 37,
    freshestCRL: 46 } },

  // PKIX private extensions (authorityInfoAccess et al).
  pkixAccess: { base: [1, 3, 6, 1, 5, 5, 7, 1], of: { authorityInfoAccess: 1 } },

  // PKCS#1 RSA public-key + RSASSA signature algorithms.
  rsa: { base: [1, 2, 840, 113549, 1, 1], of: {
    rsaEncryption: 1, rsassaPss: 10, sha256WithRSAEncryption: 11,
    sha384WithRSAEncryption: 12, sha512WithRSAEncryption: 13 } },

  // PKCS#9 attribute types.
  pkcs9: { base: [1, 2, 840, 113549, 1, 9], of: { emailAddress: 1 } },

  // ANSI X9.62 EC public key, named curve, and ECDSA signatures.
  ansiX962: { base: [1, 2, 840, 10045], of: {
    ecPublicKey: [2, 1], prime256v1: [3, 1, 7],
    ecdsaWithSHA256: [4, 3, 2], ecdsaWithSHA384: [4, 3, 3], ecdsaWithSHA512: [4, 3, 4] } },

  // SECG named curves.
  secg: { base: [1, 3, 132, 0], of: { secp384r1: 34, secp521r1: 35 } },

  // Edwards / Montgomery curves (RFC 8410).
  edwards: { base: [1, 3, 101], of: { X25519: 110, X448: 111, Ed25519: 112, Ed448: 113 } },

  // NIST hash functions (SHA-2, SHA-3, SHAKE).
  nistHash: { base: [2, 16, 840, 1, 101, 3, 4, 2], of: {
    sha256: 1, sha384: 2, sha512: 3, "sha3-256": 8, "sha3-512": 10, shake256: 12 } },

  // NIST signature algorithms — FIPS 204 ML-DSA + FIPS 205 SLH-DSA share the
  // signature arc 2.16.840.1.101.3.4.3.
  nistSig: { base: [2, 16, 840, 1, 101, 3, 4, 3], of: {
    "id-ml-dsa-44": 17, "id-ml-dsa-65": 18, "id-ml-dsa-87": 19,
    "id-slh-dsa-sha2-128s": 20, "id-slh-dsa-shake-128s": 24, "id-slh-dsa-shake-256s": 27 } },

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
