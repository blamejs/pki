// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.pkcs8
 * @nav        Schema
 * @title      PKCS#8
 * @order      140
 * @slug       pkcs8
 *
 * @intro
 *   PKCS#8 private-key handling per RFC 5208 §5 (PrivateKeyInfo) and RFC 5958 §2
 *   (OneAsymmetricKey). `parse` turns a DER or PEM (`PRIVATE KEY`) key into a
 *   structured object: version, the private-key algorithm identifier, the raw
 *   private-key bytes, the optional attributes, and — for a v2 OneAsymmetricKey —
 *   the optional public key. It composes the same schema engine and shared PKIX
 *   sub-schemas (AlgorithmIdentifier, Attribute) the other parsers use.
 *
 *   A PKCS#8 key is a container, not a signed structure: it has no signature, no
 *   distinguished name, and no to-be-signed region. The private-key OCTET STRING
 *   content is kept raw — the algorithm-specific inner key (an RSAPrivateKey, an
 *   ECPrivateKey, a CurvePrivateKey) is decoded by the caller using the surfaced
 *   algorithm OID, so an unknown or future key type never fails the parse. An
 *   `ENCRYPTED PRIVATE KEY` (EncryptedPrivateKeyInfo, RFC 5958 §3) is recognized
 *   and surfaced with its encryption algorithm and raw ciphertext; decrypting it
 *   needs a passphrase and is out of scope for structural parsing.
 *
 * @card
 *   Parse DER / PEM PKCS#8 private keys (RFC 5208 / 5958) into structured,
 *   validated fields — algorithm, raw key bytes, attributes, optional public key,
 *   fail-closed. Encrypted keys are recognized, not decrypted.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var Pkcs8Error = frameworkError.Pkcs8Error;
var PemError = frameworkError.PemError;

// The pkcs8 error namespace the schema engine walks under.
var NS = pkix.makeNS("pkcs8", Pkcs8Error, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var ATTRIBUTE = pkix.attribute(NS);

// version ::= INTEGER { v1(0), v2(1) } — 0 and 1 are both LEGAL (the divergence
// from every other reader; cert/CRL reject 0, CSR accepts only 0). Surface as the
// RFC's vN number.
var PKCS8_VERSION = pkix.versionReader(NS, { "0": 1, "1": 2 });

// PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm AlgorithmIdentifier,
//   privateKey OCTET STRING, attributes [0] IMPLICIT SET OF Attribute OPTIONAL,
//   publicKey [1] IMPLICIT BIT STRING OPTIONAL (v2 only) }. The two trailing
// context fields are modeled with `trailing` so they must appear in ascending tag
// order and an unknown trailing context tag is rejected (not bled into a field).
var PRIVATE_KEY_INFO = schema.seq([
  schema.field("version", PKCS8_VERSION),
  schema.field("privateKeyAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("privateKey", schema.octetString()),
  schema.trailing([
    { tag: 0, name: "attributes", schema: schema.implicitSetOf(0, ATTRIBUTE, { min: 0, code: "pkcs8/bad-attributes", what: "attributes" }) },
    { tag: 1, name: "publicKey", schema: schema.implicitBitString(1) },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "pkcs8/not-a-private-key-info", orderCode: "pkcs8/bad-order" }),
], {
  assert: "sequence", arity: { min: 3 }, code: "pkcs8/not-a-private-key-info", what: "PrivateKeyInfo",
  build: function (m) {
    var version = m.fields.version.value;              // 1 (v1) | 2 (v2)
    var hasPublicKey = m.fields.publicKey.present;
    // RFC 5958 §2 — publicKey present <=> version is v2. Enforce both directions.
    if (hasPublicKey && version !== 2) throw NS.E("pkcs8/bad-version", "a [1] publicKey is permitted only in a v2 OneAsymmetricKey");
    if (!hasPublicKey && version === 2) throw NS.E("pkcs8/bad-version", "a v2 OneAsymmetricKey must carry a [1] publicKey");
    return {
      version: version,
      privateKeyAlgorithm: m.fields.privateKeyAlgorithm.value.result,
      privateKey: m.fields.privateKey.value,           // raw OCTET STRING content (the inner key DER)
      attributes: m.fields.attributes.present ? m.fields.attributes.value.items.map(function (it) { return it.value.result; }) : [],
      publicKey: hasPublicKey ? m.fields.publicKey.value : null,
    };
  },
});

// EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier,
//   encryptedData OCTET STRING } (RFC 5958 §3). Recognized and surfaced; the raw
// ciphertext is kept for a later decryption layer (PBES2/PBKDF2 + a passphrase).
var ENCRYPTED_PRIVATE_KEY_INFO = schema.seq([
  schema.field("encryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedData", schema.octetString()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs8/not-an-encrypted-private-key-info", what: "EncryptedPrivateKeyInfo",
  build: function (m) {
    return {
      encryptionAlgorithm: m.fields.encryptionAlgorithm.value.result,
      encryptedData: m.fields.encryptedData.value,     // raw ciphertext
    };
  },
});

/**
 * @primitive  pki.schema.pkcs8.parse
 * @signature  pki.schema.pkcs8.parse(input) -> privateKey
 * @since      0.1.9
 * @status     stable
 * @spec       RFC 5208, RFC 5958
 * @related    pki.schema.parse, pki.schema.x509.parse
 *
 * Parse a DER `Buffer` or a PEM (`PRIVATE KEY`) string into a structured PKCS#8
 * key: `{ version, privateKeyAlgorithm, privateKey, attributes, publicKey }`. The
 * `privateKey` is the raw OCTET STRING content (the algorithm-specific inner key,
 * decoded by the caller using `privateKeyAlgorithm.oid`); `publicKey` is `null`
 * for a v1 key. A malformed PrivateKeyInfo throws a typed `Pkcs8Error` (`pkcs8/*`)
 * and a leaf-level codec fault surfaces as `asn1/*`.
 *
 * @example
 *   var key = pki.schema.pkcs8.parse(der);
 *   key.privateKeyAlgorithm.oid;   // -> "1.3.101.112" (Ed25519)
 *   key.privateKey;                // -> Buffer (the inner key encoding)
 */
var parse = pkix.makeParser({ pemLabel: "PRIVATE KEY", PemError: PemError, ErrorClass: Pkcs8Error, prefix: "pkcs8", what: "private key", topSchema: PRIVATE_KEY_INFO, ns: NS });

/**
 * @primitive  pki.schema.pkcs8.parseEncrypted
 * @signature  pki.schema.pkcs8.parseEncrypted(input) -> encrypted
 * @since      0.1.9
 * @status     stable
 * @spec       RFC 5958, RFC 5208
 * @related    pki.schema.pkcs8.parse
 *
 * Parse a DER `Buffer` or a PEM (`ENCRYPTED PRIVATE KEY`) string into an
 * EncryptedPrivateKeyInfo: `{ encryptionAlgorithm, encryptedData }`. The
 * ciphertext is surfaced raw; decrypting it (PBES2/PBKDF2 + a passphrase) is a
 * separate concern from structural validation.
 *
 * @example
 *   var enc = pki.schema.pkcs8.parseEncrypted(der);
 *   enc.encryptionAlgorithm.oid;   // -> "1.2.840.113549.1.5.13" (PBES2)
 */
var parseEncrypted = pkix.makeParser({ pemLabel: "ENCRYPTED PRIVATE KEY", PemError: PemError, ErrorClass: Pkcs8Error, prefix: "pkcs8", what: "encrypted private key", topSchema: ENCRYPTED_PRIVATE_KEY_INFO, ns: NS });

/**
 * @primitive  pki.schema.pkcs8.pemDecode
 * @signature  pki.schema.pkcs8.pemDecode(text, label?) -> Buffer
 * @since      0.1.9
 * @status     stable
 * @spec       RFC 7468, RFC 5958
 * @related    pki.schema.pkcs8.parse
 *
 * Extract the DER bytes from a PEM private-key block (default label `PRIVATE
 * KEY`). Throws `PemError` on a missing / mismatched envelope or a non-base64
 * body.
 *
 * @example
 *   var der = pki.schema.pkcs8.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "PRIVATE KEY", PemError); }

/**
 * @primitive  pki.schema.pkcs8.pemEncode
 * @signature  pki.schema.pkcs8.pemEncode(der, label?) -> string
 * @since      0.1.9
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.pkcs8.pemDecode
 *
 * Wrap DER bytes in a PEM private-key envelope (default label `PRIVATE KEY`).
 *
 * @example
 *   var pem = pki.schema.pkcs8.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "PRIVATE KEY", PemError); }

// A PKCS#8 PrivateKeyInfo root is a SEQUENCE whose first child is a universal
// INTEGER (version) and third child a universal OCTET STRING (privateKey) — a
// shape the signed-envelope trio (whose children[0] is a SEQUENCE and children[2]
// a BIT STRING) can never present, so the detectors are mutually exclusive
// regardless of registry order. Trailing context fields are [0]/[1] in ascending
// order.
function matches(root) {
  var TAGS = asn1.TAGS;
  var k = pkix.rootSequenceChildren(root, 3, 5);
  if (!k) return false;
  if (!schema.isUniversal(k[0], TAGS.INTEGER)) return false;
  if (!schema.isUniversal(k[1], TAGS.SEQUENCE)) return false;
  if (!schema.isUniversal(k[2], TAGS.OCTET_STRING)) return false;
  var last = -1;
  for (var i = 3; i < k.length; i++) {
    if (!schema.isContextInRange(k[i], 0, 1) || k[i].tagNumber <= last) return false;
    last = k[i].tagNumber;
  }
  return true;
}

// NOTE: there is intentionally no `matchesEncrypted` detector. An
// EncryptedPrivateKeyInfo is a SEQUENCE { SEQUENCE, OCTET STRING } — a shape it
// shares with a PKCS#1 DigestInfo and other AlgorithmIdentifier-plus-octets
// structures — so it cannot be classified from structure alone. The orchestrator
// does not auto-route it; an operator who knows a key is encrypted (e.g. from an
// 'ENCRYPTED PRIVATE KEY' PEM label) calls parseEncrypted directly. A structural
// auto-route can return once a validated encryption-algorithm discriminator (the
// PBES layer) exists.

// Validate a bare, already-decoded PrivateKeyInfo / EncryptedPrivateKeyInfo
// node — for a composer that holds a decoded node and must not re-parse its
// bytes (an RFC 7292 PFX key bag, whose wire encoding may be BER that the
// strict `parse` entry would refuse). Same contract as the CMS walkers: the
// node is the bare structure, typed pkcs8/* on rejection.
function walkPrivateKeyInfo(node) { return schema.walk(PRIVATE_KEY_INFO, node, NS).result; }
function walkEncryptedPrivateKeyInfo(node) { return schema.walk(ENCRYPTED_PRIVATE_KEY_INFO, node, NS).result; }

module.exports = {
  parse: parse,
  parseEncrypted: parseEncrypted,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  walkPrivateKeyInfo: walkPrivateKeyInfo,
  walkEncryptedPrivateKeyInfo: walkEncryptedPrivateKeyInfo,
};
