// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.pkcs1
 * @nav        Schema
 * @title      PKCS#1
 * @fullname   PKCS#1 RSA keys, the RSA PRIVATE KEY and RSA PUBLIC KEY encodings
 * @order      145
 * @slug       pkcs1
 *
 * @intro
 *   The RSA key encodings of RFC 8017 Appendix A.1: `RSAPrivateKey` and
 *   `RSAPublicKey`, the `RSA PRIVATE KEY` and `RSA PUBLIC KEY` PEM blocks OpenSSL
 *   wrote by default for years and appliances still emit. `parse` and
 *   `parsePublic` read them into their components, and `encode` and `encodePublic`
 *   write them back.
 *
 *   Neither structure carries an algorithm identifier, which is what separates
 *   them from PKCS#8 and SubjectPublicKeyInfo. So what the key is used under is
 *   the caller's decision, never a default this module supplies, and nothing here
 *   routes through `pki.schema.parse`: a SEQUENCE of INTEGERs is a shape other
 *   structures take, and detecting by shape alone would be a guess.
 *
 *   Every relation the specification states between the components is checked, in
 *   the same pass that reads them. Appendix A.1 fixes the field order and the
 *   two-or-more-primes rule, sec. 3.1 requires the public exponent to be odd and
 *   between 3 and the modulus, and sec. 3.2 places the private exponent, the two
 *   CRT exponents and the coefficient below the modulus or their own prime. A
 *   component outside those describes no key, and the structure alone cannot say
 *   so.
 *
 * @card
 *   Read and write the RFC 8017 App. A.1 `RSAPrivateKey` and `RSAPublicKey`, DER
 *   or PEM, with every component relation the specification states checked and no
 *   algorithm inferred.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");

var Pkcs1Error = frameworkError.Pkcs1Error;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("pkcs1", Pkcs1Error, oid);

var PRIVATE_LABEL = "RSA PRIVATE KEY";
var PUBLIC_LABEL = "RSA PUBLIC KEY";

/** @internal RFC 8017 sec. 3.1 and sec. 3.2 state every component as a positive integer. A DER
 * INTEGER whose first content octet has its high bit set reads as a negative BigInt, and a
 * negative or zero component describes no key, so it is refused at the leaf rather than carried. */
function _positive(value, what) {
  if (typeof value !== "bigint" || value <= 0n) {
    throw NS.E("pkcs1/bad-component", what + " must be a positive integer (RFC 8017 sec. 3.1, sec. 3.2)");
  }
  return value;
}

/** @internal sec. 3.2: `d < n`, `dP < p`, `dQ < q` and `qInv < p`. Each is an equality the key's
 * own arithmetic depends on, and a value at or above its bound is not the value the specification
 * names. */
function _below(value, bound, what, boundName) {
  if (value >= bound) {
    throw NS.E("pkcs1/bad-component", what + " must be smaller than " + boundName + " (RFC 8017 sec. 3.2)");
  }
}

var OTHER_PRIME_INFO = schema.seq([
  schema.field("prime", schema.integerLeaf()),
  schema.field("exponent", schema.integerLeaf()),
  schema.field("coefficient", schema.integerLeaf()),
], {
  assert: "sequence", arity: { min: 3, max: 3 }, code: "pkcs1/bad-other-prime-infos", what: "OtherPrimeInfo",
  build: function (m) {
    /** @internal RFC 8017 sec. 3.2 derives an additional prime's exponent modulo `r_i - 1` and its
     * coefficient modulo `r_i`, so both are smaller than that prime, the same relation the first
     * two primes are held to. Checking positivity alone here would read a key the specification
     * does not describe. */
    var prime = _positive(m.fields.prime.value, "an other prime info's prime");
    var exponent = _positive(m.fields.exponent.value, "an other prime info's exponent");
    var coefficient = _positive(m.fields.coefficient.value, "an other prime info's coefficient");
    _below(exponent, prime, "an other prime info's exponent", "its prime");
    _below(coefficient, prime, "an other prime info's coefficient", "its prime");
    return { prime: prime, exponent: exponent, coefficient: coefficient };
  },
});

var RSA_PRIVATE_KEY = schema.seq([
  schema.field("version", schema.integerLeaf()),
  schema.field("modulus", schema.integerLeaf()),
  schema.field("publicExponent", schema.integerLeaf()),
  schema.field("privateExponent", schema.integerLeaf()),
  schema.field("prime1", schema.integerLeaf()),
  schema.field("prime2", schema.integerLeaf()),
  schema.field("exponent1", schema.integerLeaf()),
  schema.field("exponent2", schema.integerLeaf()),
  schema.field("coefficient", schema.integerLeaf()),
  /** @internal App. A.1.2 puts `otherPrimeInfos` last and untagged, so it is recognized by being
   * a universal SEQUENCE rather than by a context tag, and it is a SEQUENCE OF: the order is the
   * key's own and carries no DER SET ordering. */
  schema.optional("otherPrimeInfos", schema.seqOf(OTHER_PRIME_INFO, { min: 0, code: "pkcs1/bad-other-prime-infos", what: "otherPrimeInfos" }),
    { whenUniversal: [asn1.TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 9, max: 10 }, code: "pkcs1/not-an-rsa-private-key", what: "RSAPrivateKey",
  build: function (m) {
    var version = m.fields.version.value;
    if (version !== 0n && version !== 1n) {
      throw NS.E("pkcs1/bad-version", "an RSAPrivateKey is version 0 or 1 (RFC 8017 App. A.1.2), got " + version);
    }
    var multi = m.fields.otherPrimeInfos.present;
    var infos = multi
      ? intrinsic.map(m.fields.otherPrimeInfos.value.items, function (it) { return it.value.result; })
      : [];
    /** @internal App. A.1.2 ties the version to the prime count: "otherPrimeInfos ... shall be
     * omitted if version is 0 and shall contain at least one instance of OtherPrimeInfo if version
     * is 1". A key stating one and carrying the other states two different keys. */
    if (version === 0n && multi) {
      throw NS.E("pkcs1/bad-other-prime-infos", "a version-0 RSAPrivateKey carries no otherPrimeInfos (RFC 8017 App. A.1.2)");
    }
    if (version === 1n && !multi) {
      throw NS.E("pkcs1/bad-other-prime-infos", "a version-1 RSAPrivateKey carries at least one OtherPrimeInfo (RFC 8017 App. A.1.2)");
    }
    if (version === 1n && infos.length === 0) {
      throw NS.E("pkcs1/bad-other-prime-infos", "otherPrimeInfos is SIZE(1..MAX), so an empty one is refused (RFC 8017 App. A.1.2)");
    }

    var modulus = _positive(m.fields.modulus.value, "the modulus");
    var publicExponent = _positive(m.fields.publicExponent.value, "the public exponent");
    var privateExponent = _positive(m.fields.privateExponent.value, "the private exponent");
    var prime1 = _positive(m.fields.prime1.value, "prime1");
    var prime2 = _positive(m.fields.prime2.value, "prime2");
    var exponent1 = _positive(m.fields.exponent1.value, "exponent1");
    var exponent2 = _positive(m.fields.exponent2.value, "exponent2");
    var coefficient = _positive(m.fields.coefficient.value, "the coefficient");
    _assertExponent(publicExponent, modulus);
    _below(privateExponent, modulus, "the private exponent", "the modulus");
    _below(exponent1, prime1, "exponent1", "prime1");
    _below(exponent2, prime2, "exponent2", "prime2");
    _below(coefficient, prime1, "the coefficient", "prime1");
    return {
      version: intrinsic.Number(version), modulus: modulus, publicExponent: publicExponent,
      privateExponent: privateExponent, prime1: prime1, prime2: prime2,
      exponent1: exponent1, exponent2: exponent2, coefficient: coefficient,
      otherPrimeInfos: infos,
    };
  },
});

/** @internal sec. 3.1: "the RSA public exponent e ... 3 <= e < n". An even exponent has no
 * multiplicative inverse modulo a product of odd primes, so it names no key either. */
function _assertExponent(e, n) {
  if (e < 3n || e >= n) {
    throw NS.E("pkcs1/bad-exponent", "the public exponent must satisfy 3 <= e < n (RFC 8017 sec. 3.1)");
  }
  if ((e & 1n) === 0n) {
    throw NS.E("pkcs1/bad-exponent", "the public exponent must be odd (RFC 8017 sec. 3.1)");
  }
}

var RSA_PUBLIC_KEY = schema.seq([
  schema.field("modulus", schema.integerLeaf()),
  schema.field("publicExponent", schema.integerLeaf()),
], {
  assert: "sequence", arity: { min: 2, max: 2 }, code: "pkcs1/not-an-rsa-public-key", what: "RSAPublicKey",
  build: function (m) {
    var modulus = _positive(m.fields.modulus.value, "the modulus");
    var publicExponent = _positive(m.fields.publicExponent.value, "the public exponent");
    _assertExponent(publicExponent, modulus);
    return { modulus: modulus, publicExponent: publicExponent };
  },
});

var PRIVATE_OPTS = intrinsic.assign(intrinsic.create(null), {
  pemLabel: PRIVATE_LABEL, PemError: PemError, ErrorClass: Pkcs1Error, prefix: "pkcs1",
  what: "RSA private key", topSchema: RSA_PRIVATE_KEY, ns: NS,
});
var PUBLIC_OPTS = intrinsic.assign(intrinsic.create(null), {
  pemLabel: PUBLIC_LABEL, PemError: PemError, ErrorClass: Pkcs1Error, prefix: "pkcs1",
  what: "RSA public key", topSchema: RSA_PUBLIC_KEY, ns: NS,
});

/**
 * @primitive  pki.schema.pkcs1.parse
 * @signature  pki.schema.pkcs1.parse(input, opts) -> key
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 8017
 * @related    pki.schema.pkcs1.parsePublic, pki.schema.pkcs8.parse
 *
 * Read an RFC 8017 Appendix A.1.2 `RSAPrivateKey`, as DER bytes or an
 * `RSA PRIVATE KEY` PEM block, into `{ version, modulus, publicExponent,
 * privateExponent, prime1, prime2, exponent1, exponent2, coefficient,
 * otherPrimeInfos }`. Every component is a `BigInt`.
 *
 * The structure names no algorithm, so nothing here decides what the key is used
 * under. Read it and hand the components to the verb that does.
 *
 * Fail-closed on the specification's own relations: a version other than 0 or 1, a
 * version disagreeing with whether other prime infos are present, an
 * `OtherPrimeInfo` that is not three integers, a component that is not a positive
 * integer, a public exponent outside `3 <= e < n` or an even one, and a private
 * exponent, CRT exponent or coefficient at or above its bound are each refused
 * with their own `pkcs1/*` code.
 *
 * @example
 *   // requires: der -- an RSAPrivateKey, from `openssl genrsa` or an appliance that emits one
 *   var key = pki.schema.pkcs1.parse(der);
 *   key.version;          // 0
 *   key.publicExponent;   // 65537n
 */
var parse = pkix.makeParser(PRIVATE_OPTS);

/**
 * @primitive  pki.schema.pkcs1.parsePublic
 * @signature  pki.schema.pkcs1.parsePublic(input, opts) -> key
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 8017
 * @related    pki.schema.pkcs1.parse
 *
 * Read an RFC 8017 Appendix A.1.1 `RSAPublicKey`, as DER bytes or an
 * `RSA PUBLIC KEY` PEM block, into `{ modulus, publicExponent }`. A structure
 * carrying anything else, including a private key, is refused: the two encodings
 * are told apart by their shape and neither door reads the other's.
 *
 * @example
 *   // requires: der -- an RSAPrivateKey, from `openssl genrsa` or an appliance that emits one
 *   var priv = pki.schema.pkcs1.parse(der);
 *   var pubDer = pki.schema.pkcs1.encodePublic({ modulus: priv.modulus, publicExponent: priv.publicExponent });
 *   pki.schema.pkcs1.parsePublic(pubDer).publicExponent;   // 65537n
 */
var parsePublic = pkix.makeParser(PUBLIC_OPTS);

/**
 * @primitive  pki.schema.pkcs1.encode
 * @signature  pki.schema.pkcs1.encode(key) -> Buffer
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 8017
 * @related    pki.schema.pkcs1.parse
 *
 * Write an `RSAPrivateKey` back to DER from the shape `parse` returns. What `parse`
 * read is what this writes: a key read and written again produces the bytes it came
 * from.
 *
 * @example
 *   // requires: der -- an RSAPrivateKey, from `openssl genrsa` or an appliance that emits one
 *   pki.schema.pkcs1.encode(pki.schema.pkcs1.parse(der)).equals(der);   // true
 */
function encode(key) {
  if (key === null || typeof key !== "object") {
    throw NS.E("pkcs1/bad-input", "encode takes the object parse returns");
  }
  var kids = [asn1.build.integer(intrinsic.BigInt(key.version)), asn1.build.integer(key.modulus),
    asn1.build.integer(key.publicExponent), asn1.build.integer(key.privateExponent),
    asn1.build.integer(key.prime1), asn1.build.integer(key.prime2),
    asn1.build.integer(key.exponent1), asn1.build.integer(key.exponent2),
    asn1.build.integer(key.coefficient)];
  var infos = key.otherPrimeInfos;
  if (intrinsic.isArray(infos) && infos.length > 0) {
    var rows = [];
    for (var i = 0; i < infos.length; i++) {
      rows[i] = asn1.build.sequence([asn1.build.integer(infos[i].prime),
        asn1.build.integer(infos[i].exponent), asn1.build.integer(infos[i].coefficient)]);
    }
    kids[9] = asn1.build.sequence(rows);
  }
  return asn1.build.sequence(kids);
}

/**
 * @primitive  pki.schema.pkcs1.encodePublic
 * @signature  pki.schema.pkcs1.encodePublic(key) -> Buffer
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 8017
 * @related    pki.schema.pkcs1.parsePublic
 *
 * Write an `RSAPublicKey` back to DER from the shape `parsePublic` returns.
 *
 * @example
 *   // requires: der -- an RSAPrivateKey, from `openssl genrsa` or an appliance that emits one
 *   var priv = pki.schema.pkcs1.parse(der);
 *   var pubDer = pki.schema.pkcs1.encodePublic({ modulus: priv.modulus, publicExponent: priv.publicExponent });
 *   pki.schema.pkcs1.encodePublic(pki.schema.pkcs1.parsePublic(pubDer)).equals(pubDer);   // true
 */
function encodePublic(key) {
  if (key === null || typeof key !== "object") {
    throw NS.E("pkcs1/bad-input", "encodePublic takes the object parsePublic returns");
  }
  return asn1.build.sequence([asn1.build.integer(key.modulus), asn1.build.integer(key.publicExponent)]);
}

function pemDecode(text) { return pkix.pemDecode(text, PRIVATE_LABEL, PemError); }
function pemEncode(der) { return pkix.pemEncode(der, PRIVATE_LABEL, PemError); }
function pemDecodePublic(text) { return pkix.pemDecode(text, PUBLIC_LABEL, PemError); }
function pemEncodePublic(der) { return pkix.pemEncode(der, PUBLIC_LABEL, PemError); }

/** @internal RFC 8017 App. A.1.2: `RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent,
 * privateExponent, prime1, prime2, exponent1, exponent2, coefficient, otherPrimeInfos OPTIONAL }`,
 * so nine INTEGERs and an optional SEQUENCE. Structure alone does not separate this from every
 * other SEQUENCE of INTEGERs, which is why nothing routes to it from bare bytes; it answers for a
 * caller that already has the armor label saying what the bytes are meant to be. */
function matches(root) {
  var k = pkix.rootSequenceChildren(root, 9, 10);
  if (!k) return false;
  for (var i = 0; i < 9; i++) {
    if (!schema.isUniversal(k[i], asn1.TAGS.INTEGER)) return false;
  }
  return k.length === 9 || schema.isUniversal(k[9], asn1.TAGS.SEQUENCE);
}

/** @internal RFC 8017 App. A.1.1: `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`. */
function matchesPublic(root) {
  var k = pkix.rootSequenceChildren(root, 2, 2);
  return !!k && schema.isUniversal(k[0], asn1.TAGS.INTEGER) && schema.isUniversal(k[1], asn1.TAGS.INTEGER);
}

module.exports = {
  parse: parse,
  parsePublic: parsePublic,
  matches: matches,
  matchesPublic: matchesPublic,
  encode: encode,
  encodePublic: encodePublic,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  pemDecodePublic: pemDecodePublic,
  pemEncodePublic: pemEncodePublic,
};
