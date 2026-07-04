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
 *   The seed set covers the RFC 5280 attribute types and extensions, the
 *   classical signature / public-key / digest algorithms, and the
 *   NIST-assigned post-quantum arcs (ML-DSA, ML-KEM, SLH-DSA). Operators
 *   extend it with `register`.
 *
 * @card
 *   Two-way OID ↔ name registry with arc conversion, seeded with the
 *   RFC 5280 and NIST post-quantum object identifiers.
 */

var asn1 = require("./asn1-der");
var frameworkError = require("./framework-error");

var OidError = frameworkError.OidError;

// SEED — [dotted, canonicalName]. Kept as a flat table so it reads as
// data and diffs cleanly when an arc is added.
var SEED = [
  // --- RFC 5280 attribute types (2.5.4.*) ---
  ["2.5.4.3",  "commonName"],
  ["2.5.4.4",  "surname"],
  ["2.5.4.5",  "serialNumber"],
  ["2.5.4.6",  "countryName"],
  ["2.5.4.7",  "localityName"],
  ["2.5.4.8",  "stateOrProvinceName"],
  ["2.5.4.9",  "streetAddress"],
  ["2.5.4.10", "organizationName"],
  ["2.5.4.11", "organizationalUnitName"],
  ["2.5.4.12", "title"],
  ["2.5.4.42", "givenName"],
  ["0.9.2342.19200300.100.1.25", "domainComponent"],
  ["1.2.840.113549.1.9.1",       "emailAddress"],

  // --- Public-key + signature algorithms ---
  ["1.2.840.113549.1.1.1",  "rsaEncryption"],
  ["1.2.840.113549.1.1.10", "rsassaPss"],
  ["1.2.840.113549.1.1.11", "sha256WithRSAEncryption"],
  ["1.2.840.113549.1.1.12", "sha384WithRSAEncryption"],
  ["1.2.840.113549.1.1.13", "sha512WithRSAEncryption"],
  ["1.2.840.10045.2.1",     "ecPublicKey"],
  ["1.2.840.10045.4.3.2",   "ecdsaWithSHA256"],
  ["1.2.840.10045.4.3.3",   "ecdsaWithSHA384"],
  ["1.2.840.10045.4.3.4",   "ecdsaWithSHA512"],
  ["1.2.840.10045.3.1.7",   "prime256v1"],
  ["1.3.132.0.34",          "secp384r1"],
  ["1.3.132.0.35",          "secp521r1"],
  ["1.3.101.110",           "X25519"],
  ["1.3.101.111",           "X448"],
  ["1.3.101.112",           "Ed25519"],
  ["1.3.101.113",           "Ed448"],

  // --- Digests ---
  ["2.16.840.1.101.3.4.2.1",  "sha256"],
  ["2.16.840.1.101.3.4.2.2",  "sha384"],
  ["2.16.840.1.101.3.4.2.3",  "sha512"],
  ["2.16.840.1.101.3.4.2.8",  "sha3-256"],
  ["2.16.840.1.101.3.4.2.10", "sha3-512"],
  ["2.16.840.1.101.3.4.2.12", "shake256"],

  // --- RFC 5280 certificate extensions (2.5.29.*) ---
  ["2.5.29.14", "subjectKeyIdentifier"],
  ["2.5.29.15", "keyUsage"],
  ["2.5.29.17", "subjectAltName"],
  ["2.5.29.18", "issuerAltName"],
  ["2.5.29.19", "basicConstraints"],
  ["2.5.29.30", "nameConstraints"],
  ["2.5.29.31", "cRLDistributionPoints"],
  ["2.5.29.32", "certificatePolicies"],
  ["2.5.29.35", "authorityKeyIdentifier"],
  ["2.5.29.37", "extKeyUsage"],
  ["1.3.6.1.5.5.7.1.1", "authorityInfoAccess"],

  // --- NIST post-quantum algorithms ---
  // FIPS 204 ML-DSA (signature-algorithm arc 2.16.840.1.101.3.4.3.*).
  ["2.16.840.1.101.3.4.3.17", "id-ml-dsa-44"],
  ["2.16.840.1.101.3.4.3.18", "id-ml-dsa-65"],
  ["2.16.840.1.101.3.4.3.19", "id-ml-dsa-87"],
  // FIPS 203 ML-KEM (KEM arc 2.16.840.1.101.3.4.4.*).
  ["2.16.840.1.101.3.4.4.1",  "id-ml-kem-512"],
  ["2.16.840.1.101.3.4.4.2",  "id-ml-kem-768"],
  ["2.16.840.1.101.3.4.4.3",  "id-ml-kem-1024"],
  // FIPS 205 SLH-DSA (a representative slice of the SHAKE-256 family).
  ["2.16.840.1.101.3.4.3.20", "id-slh-dsa-sha2-128s"],
  ["2.16.840.1.101.3.4.3.24", "id-slh-dsa-shake-128s"],
  ["2.16.840.1.101.3.4.3.27", "id-slh-dsa-shake-256s"],
];

var _byOid = new Map();
var _byName = new Map();

function _index(dotted, name) {
  _byOid.set(dotted, name);
  // First registration of a name wins as the canonical reverse entry.
  if (!_byName.has(name)) _byName.set(name, dotted);
}

for (var _i = 0; _i < SEED.length; _i++) _index(SEED[_i][0], SEED[_i][1]);

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
 * @related    pki.oid.name
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
    if (typeof a === "bigint") return a.toString();
    if (typeof a === "number" && Number.isInteger(a) && a >= 0) return String(a);
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
  name:     name,
  byName:   byName,
  has:      has,
  register: register,
  all:      all,
  toArcs:   toArcs,
  fromArcs: fromArcs,
  toDER:    toDER,
  fromDER:  fromDER,
};
