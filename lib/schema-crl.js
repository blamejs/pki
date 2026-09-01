// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.crl
 * @nav        Schema
 * @title      CRL
 * @order      120
 * @slug       crl
 *
 * @intro
 *   X.509 Certificate Revocation List handling per RFC 5280 sec. 5. `parse` turns a
 *   DER or PEM CRL into a structured, fully-decoded object: version, issuer
 *   distinguished name, this/next update as real `Date`s, the ordered list of
 *   revoked certificates (serial + revocation date + entry extensions), and the
 *   CRL extensions. It composes the same schema engine and shared PKIX
 *   sub-schemas (AlgorithmIdentifier, Name, Extension) the certificate parser
 *   uses, so the CertificateList inherits the identical fail-closed structural
 *   rules, and the raw `tbsCertList` bytes are returned for signature checking.
 *
 * @card
 *   Parse DER / PEM X.509 CRLs into structured, validated fields: revoked
 *   serials with real-`Date` revocation times, named extensions, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;

var CrlError = frameworkError.CrlError;
var PemError = frameworkError.PemError;
var TAGS = asn1.TAGS;


var CRL_REASONS = pkix.CRL_REASON_NAMES;

var OID_CRL_NUMBER = oid.byName("cRLNumber");
var OID_REASON_CODE = oid.byName("reasonCode");
var OID_INVALIDITY_DATE = oid.byName("invalidityDate");

var NS = pkix.makeNS("crl", CrlError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);
var EXTENSIONS = pkix.extensions(NS);
var TIME = pkix.time(NS);

var CRL_VERSION = pkix.versionReader(NS, { "1": 2 });

function decodeExt(ext) {
  var value = ext.value;
  try {
    if (ext.oid === OID_CRL_NUMBER) {
      value = asn1.read.integer(asn1.decode(ext.value));
      if (value < 0n) throw new Error("cRLNumber must be non-negative (INTEGER 0..MAX)");
    } else if (ext.oid === OID_REASON_CODE) {
      var reason = asn1.read.enumerated(asn1.decode(ext.value));
      if (!_hasOwn(CRL_REASONS, reason.toString())) throw new Error("undefined CRLReason " + reason.toString());
      value = Number(reason);
    } else if (ext.oid === OID_INVALIDITY_DATE) {
      var n = asn1.decode(ext.value);
      if (n.tagClass !== "universal" || n.tagNumber !== TAGS.GENERALIZED_TIME) {
        throw new Error("invalidityDate must be a GeneralizedTime");
      }
      value = asn1.read.time(n);
    }
  } catch (e) {
    throw NS.E("crl/bad-extension-value", "malformed " + (ext.name || ext.oid) + " extension value: " + ((e && e.message) || String(e)), e);
  }
  return { oid: ext.oid, name: ext.name, critical: ext.critical, value: value };
}

var REVOKED_ENTRY = schema.seq([
  schema.field("userCertificate", schema.integerLeaf()),
  schema.field("revocationDate", TIME),
  schema.optional("crlEntryExtensions", EXTENSIONS, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 2 }, code: "crl/bad-revoked-entry", what: "RevokedCertificate",
  build: function (m) {
    return {
      serialNumber: m.fields.userCertificate.value,
      serialNumberHex: m.fields.userCertificate.node.content.toString("hex"),
      revocationDate: m.fields.revocationDate.value,
      crlEntryExtensions: m.fields.crlEntryExtensions.present ? m.fields.crlEntryExtensions.value.result.map(decodeExt) : [],
    };
  },
});

var REVOKED_LIST = schema.seqOf(REVOKED_ENTRY, {
  assert: "sequence", min: 1, code: "crl/bad-revoked-certificates", what: "revokedCertificates",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// allow:schema-build-drops-parsed-field
var TBS_CERTLIST = schema.seq([
  schema.optional("version", CRL_VERSION, { whenUniversal: [TAGS.INTEGER] }),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("issuer", NAME),
  schema.field("thisUpdate", TIME),
  schema.optional("nextUpdate", TIME, { whenUniversal: [TAGS.UTC_TIME, TAGS.GENERALIZED_TIME] }),
  schema.optional("revokedCertificates", REVOKED_LIST, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.trailing([{ tag: 0, name: "crlExtensions", schema: EXTENSIONS, explicit: true, emptyCode: "crl/bad-extensions" }],
    { minTag: 0, maxTag: 0, unexpectedCode: "crl/bad-tbs", orderCode: "crl/bad-tbs" }),
], {
  assert: "sequence", code: "crl/bad-tbs", what: "tbsCertList",
  build: function (m) {
    return {
      version: m.fields.version.present ? m.fields.version.value : 1,
      issuer: m.fields.issuer.value.result,
      thisUpdate: m.fields.thisUpdate.value,
      nextUpdate: m.fields.nextUpdate.present ? m.fields.nextUpdate.value : null,
      revokedCertificates: m.fields.revokedCertificates.present ? m.fields.revokedCertificates.value.result : [],
      crlExtensions: m.fields.crlExtensions.present ? m.fields.crlExtensions.value.result.map(decodeExt) : [],
      crlExtensionsPresent: m.fields.crlExtensions.present,
    };
  },
});

var CERTIFICATE_LIST = pkix.signedEnvelope(NS, TBS_CERTLIST, {
  code: "crl/not-a-crl", what: "CertificateList",
  build: function (e) {
    var tbs = e.tbsMatch.result;
    if (!e.outerSignatureAlgorithmBytes.equals(e.tbsMatch.fields.signature.node.bytes)) {
      throw NS.E("crl/bad-signature-algorithm", "signatureAlgorithm must match tbsCertList.signature (RFC 5280 sec. 5.1.1.2)");
    }
    if (!tbs.issuer.rdns.length) {
      throw NS.E("crl/bad-issuer", "issuer must be a non-empty distinguished name");
    }
    var hasExtensions = tbs.crlExtensionsPresent ||
      tbs.revokedCertificates.some(function (r) { return r.crlEntryExtensions.length > 0; });
    if (hasExtensions && tbs.version !== 2) {
      throw NS.E("crl/bad-version", "crlExtensions / crlEntryExtensions are only permitted in a v2 CRL");
    }
    return {
      version: tbs.version,
      issuer: tbs.issuer,
      thisUpdate: tbs.thisUpdate,
      nextUpdate: tbs.nextUpdate,
      revokedCertificates: tbs.revokedCertificates,
      crlExtensions: tbs.crlExtensions,
      tbsBytes: e.tbsBytes,
      signatureAlgorithm: e.signatureAlgorithm,
      signatureValue: e.signatureValue,
    };
  },
});

/**
 * @primitive  pki.schema.crl.parse
 * @signature  pki.schema.crl.parse(input) -> crl
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 5280
 * @related    pki.schema.x509.parse, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM (`X509 CRL`) string into a structured CRL:
 * `{ version, issuer, thisUpdate, nextUpdate, revokedCertificates,
 * crlExtensions, tbsBytes, signatureAlgorithm, signatureValue }`. Every field is
 * validated on the way in; a malformed CertificateList / TBSCertList throws a
 * typed `CrlError` (`crl/*`) and a leaf-level codec fault surfaces as `asn1/*`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
 *   var der = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n,
 *     revoked: [{ serialNumber: 0x0a3fn, revocationDate: new Date("2026-01-15T00:00:00Z") }] },
 *     { cert: caCert, key: key });
 *   var crl = pki.schema.crl.parse(der);
 *   crl.revokedCertificates[0].serialNumberHex;  // -> "0a3f"
 */
var parse = pkix.makeRecordingParser({ pemLabel: "X509 CRL", PemError: PemError, ErrorClass: CrlError, prefix: "crl", what: "CRL", topSchema: CERTIFICATE_LIST, ns: NS }, "crl");

/**
 * @primitive  pki.schema.crl.pemDecode
 * @signature  pki.schema.crl.pemDecode(text, label?) -> Buffer
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.crl.parse
 *
 * Extract the DER bytes from a PEM CRL block (default label `X509 CRL`). Throws
 * `PemError` on a missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: key });
 *   var pemText = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
 *     { cert: caCert, key: key }, { pem: true });
 *   var der = pki.schema.crl.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "X509 CRL", PemError); }

/**
 * @primitive  pki.schema.crl.pemEncode
 * @signature  pki.schema.crl.pemEncode(der, label?) -> string
 * @since      0.1.23
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.crl.pemDecode
 *
 * Wrap CRL DER bytes in a PEM envelope with 64-column base64 lines (default
 * label `X509 CRL`, the RFC 7468 sec. 6 armor `pemDecode` expects back).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: key });
 *   var der = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
 *     { cert: caCert, key: key });
 *   var pem = pki.schema.crl.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "X509 CRL", PemError); }

function matches(root) {
  var tbs = pkix.signedEnvelopeTbs(root);
  if (!tbs) return false;
  if (tbs.children[0] && tbs.children[0].tagClass === "context") return false;
  var i = 0;
  if (schema.isUniversal(tbs.children[i], TAGS.INTEGER)) i++;
  i += 2;
  var pos = tbs.children[i];
  return schema.isUniversalOneOf(pos, [TAGS.UTC_TIME, TAGS.GENERALIZED_TIME]);
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
};
