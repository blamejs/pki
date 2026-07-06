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
 *   X.509 Certificate Revocation List handling per RFC 5280 §5. `parse` turns a
 *   DER or PEM CRL into a structured, fully-decoded object: version, issuer
 *   distinguished name, this/next update as real `Date`s, the ordered list of
 *   revoked certificates (serial + revocation date + entry extensions), and the
 *   CRL extensions. It composes the same schema engine and shared PKIX
 *   sub-schemas (AlgorithmIdentifier, Name, Extension) the certificate parser
 *   uses, so the CertificateList inherits the identical fail-closed structural
 *   rules, and the raw `tbsCertList` bytes are returned for signature checking.
 *
 * @card
 *   Parse DER / PEM X.509 CRLs into structured, validated fields — revoked
 *   serials with real-`Date` revocation times, named extensions, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CrlError = frameworkError.CrlError;
var PemError = frameworkError.PemError;
var TAGS = asn1.TAGS;


// CRLReason ::= ENUMERATED (RFC 5280 §5.3.1) — value 7 is unused/reserved.
var CRL_REASONS = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 8n, 9n, 10n];

// Extension-value decoding is keyed off the STABLE dotted OID (resolved once at
// load from the canonical name), not the mutable display name — a caller's
// pki.oid.register() display override must not change parse behaviour.
var OID_CRL_NUMBER = oid.byName("cRLNumber");
var OID_REASON_CODE = oid.byName("reasonCode");
var OID_INVALIDITY_DATE = oid.byName("invalidityDate");

// The crl error namespace the schema engine walks under. Shared PKIX sub-schemas
// are instantiated here under crl/* so a structural fault reports a crl code.
var NS = pkix.makeNS("crl", CrlError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);
var EXTENSIONS = pkix.extensions(NS);
var TIME = schema.time(NS);

// CRL Version ::= INTEGER { v1(0), v2(1) } — a BARE INTEGER (not [0] EXPLICIT).
// A CRL is at most v2; reject an explicit v1 (DER forbids the default) and any
// value >= 2. Do NOT reuse the certificate readVersion (it maps 2 -> v3).
var CRL_VERSION = pkix.versionReader(NS, { "1": 2 });

// The three cheap, high-value CRL extension values are decoded from their raw
// extnValue octets (RFC 5280 §5.2/§5.3); GeneralNames-based extensions
// (issuingDistributionPoint, certificateIssuer, authorityKeyIdentifier, …) stay
// raw with their bytes reachable. A malformed decoded value fails closed.
function decodeExt(ext) {
  var value = ext.value;
  try {
    if (ext.oid === OID_CRL_NUMBER) {         // cRLNumber ::= INTEGER (0..MAX)
      value = asn1.read.integer(asn1.decode(ext.value));
      if (value < 0n) throw new Error("cRLNumber must be non-negative (INTEGER 0..MAX)");
    } else if (ext.oid === OID_REASON_CODE) { // reasonCode ::= ENUMERATED (CRLReason)
      // read.enumerated asserts the ENUMERATED tag (a bare INTEGER is rejected) —
      // the codec owns the tag check, so this reader need not repeat it.
      var reason = asn1.read.enumerated(asn1.decode(ext.value));
      if (CRL_REASONS.indexOf(reason) === -1) throw new Error("undefined CRLReason " + reason.toString());
      value = Number(reason);
    } else if (ext.oid === OID_INVALIDITY_DATE) { // invalidityDate ::= GeneralizedTime
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

// RevokedCertificate ::= SEQUENCE { userCertificate CertificateSerialNumber,
//   revocationDate Time, crlEntryExtensions Extensions OPTIONAL }
var REVOKED_ENTRY = schema.seq([
  schema.field("userCertificate", schema.integerLeaf()),
  schema.field("revocationDate", TIME),
  schema.optional("crlEntryExtensions", EXTENSIONS, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 2 }, code: "crl/bad-revoked-entry", what: "RevokedCertificate",
  build: function (m) {
    return {
      serialNumber: m.fields.userCertificate.value,
      // Raw INTEGER content bytes (not a reserialized BigInt) so the hex matches
      // the X.509 parser's serialNumberHex and preserves DER sign padding
      // (a positive 0x80 serial encodes as content 00 80).
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

// TBSCertList ::= SEQUENCE { version Version OPTIONAL, signature AlgorithmIdentifier,
//   issuer Name, thisUpdate Time, nextUpdate Time OPTIONAL,
//   revokedCertificates SEQUENCE OF SEQUENCE {...} OPTIONAL,
//   crlExtensions [0] EXPLICIT Extensions OPTIONAL }.
// The three OPTIONAL universal-tagged fields (version=INTEGER, nextUpdate=Time,
// revokedCertificates=SEQUENCE) are disambiguated by their universal tag;
// crlExtensions is modeled as a trailing [0]..[0] so a stray non-[0] trailing
// context tag is REJECTED (crl/bad-tbs), not silently ignored.
// `signature` is consumed by the CERTIFICATE_LIST build (the §5.1.1.2
// outer==inner agreement check reads tbsMatch.fields.signature.node.bytes);
// the operator reads the surfaced outer signatureAlgorithm, which that
// check proves byte-identical.
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
      issuer: m.fields.issuer.value.result, // Name is a seqOf → field.value is the match; .result is the {rdns, dn} build
      thisUpdate: m.fields.thisUpdate.value,
      nextUpdate: m.fields.nextUpdate.present ? m.fields.nextUpdate.value : null,
      revokedCertificates: m.fields.revokedCertificates.present ? m.fields.revokedCertificates.value.result : [],
      crlExtensions: m.fields.crlExtensions.present ? m.fields.crlExtensions.value.result.map(decodeExt) : [],
      crlExtensionsPresent: m.fields.crlExtensions.present,
    };
  },
});

// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
// — the shared SIGNED envelope. The CRL-specific invariants (outer==inner
// signatureAlgorithm agreement, non-empty issuer, v2-only extensions) live in the
// build; the envelope owns the SEQUENCE-of-3 shape and signature extraction.
var CERTIFICATE_LIST = pkix.signedEnvelope(NS, TBS_CERTLIST, {
  code: "crl/not-a-crl", what: "CertificateList",
  build: function (e) {
    var tbs = e.tbsMatch.result;
    // RFC 5280 §5.1.1.2 — the outer signatureAlgorithm MUST equal tbsCertList.signature.
    if (!e.outerSignatureAlgorithmBytes.equals(e.tbsMatch.fields.signature.node.bytes)) {
      throw NS.E("crl/bad-signature-algorithm", "signatureAlgorithm must match tbsCertList.signature (RFC 5280 §5.1.1.2)");
    }
    // RFC 5280 §5.1.2.3 — the issuer MUST be a non-empty distinguished name.
    if (!tbs.issuer.rdns.length) {
      throw NS.E("crl/bad-issuer", "issuer must be a non-empty distinguished name");
    }
    // RFC 5280 §5.1.2.1 — crlExtensions / crlEntryExtensions appear only in a v2 CRL.
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
 * @status     experimental
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
 *   var crl = pki.schema.crl.parse(der);
 *   crl.revokedCertificates[0].serialNumberHex;  // → "0a3f…"
 */
var parse = pkix.makeParser({ pemLabel: "X509 CRL", PemError: PemError, ErrorClass: CrlError, prefix: "crl", what: "CRL", topSchema: CERTIFICATE_LIST, ns: NS });

/**
 * @primitive  pki.schema.crl.pemDecode
 * @signature  pki.schema.crl.pemDecode(text, label?) -> Buffer
 * @since      0.1.7
 * @status     experimental
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.crl.parse
 *
 * Extract the DER bytes from a PEM CRL block (default label `X509 CRL`). Throws
 * `PemError` on a missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var der = pki.schema.crl.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "X509 CRL", PemError); }

// Certificate and CertificateList share the outer SEQUENCE-of-3 shape; a CRL is
// distinguished by its tbsCertList — the first tbs element is a bare INTEGER
// (version) or an AlgorithmIdentifier (signature) SEQUENCE, and crucially the
// field at the certificate's Validity position is a bare Time (thisUpdate). The
// orchestrator uses `matches` to route; a cert's tbs leads with a [0] EXPLICIT
// version or an INTEGER serial FOLLOWED by an AlgorithmIdentifier and a Name,
// then a Validity SEQUENCE, never a bare Time at that depth.
function matches(root) {
  var tbs = pkix.signedEnvelopeTbs(root);
  if (!tbs) return false;
  // A certificate's tbs leads with [0] EXPLICIT version — a CRL never does.
  if (tbs.children[0] && tbs.children[0].tagClass === "context") return false;
  // Walk to the thisUpdate / validity position: skip an optional bare INTEGER
  // version, then signature (SEQUENCE) + issuer (SEQUENCE); the next element is
  // thisUpdate (Time) for a CRL, Validity (SEQUENCE) for a certificate.
  var i = 0;
  if (tbs.children[i] && tbs.children[i].tagClass === "universal" && tbs.children[i].tagNumber === TAGS.INTEGER) i++;
  i += 2; // signature + issuer
  var pos = tbs.children[i];
  return !!pos && pos.tagClass === "universal" && (pos.tagNumber === TAGS.UTC_TIME || pos.tagNumber === TAGS.GENERALIZED_TIME);
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  matches: matches,
};
