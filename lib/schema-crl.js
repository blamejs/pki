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
var constants = require("./constants");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CrlError = frameworkError.CrlError;
var PemError = frameworkError.PemError;
var TAGS = asn1.TAGS;

var PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

// The crl error namespace the schema engine walks under. Shared PKIX sub-schemas
// are instantiated here under crl/* so a structural fault reports a crl code.
var NS = { prefix: "crl", E: function (code, message, cause) { return new CrlError(code, message, cause); }, oid: oid };

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);
var EXTENSIONS = pkix.extensions(NS);
var TIME = schema.time(NS);

// CRL Version ::= INTEGER { v1(0), v2(1) } — a BARE INTEGER (not [0] EXPLICIT).
// A CRL is at most v2; reject an explicit v1 (DER forbids the default) and any
// value >= 2. Do NOT reuse the certificate readVersion (it maps 2 -> v3).
var CRL_VERSION = schema.decode(function (n) {
  var v = asn1.read.integer(n);
  if (v === 1n) return 2;
  if (v === 0n) throw NS.E("crl/bad-version", "DER forbids explicitly encoding the default version v1");
  throw NS.E("crl/bad-version", "unsupported CRL version " + v.toString() + " (a CRL is at most v2)");
});

// serialNumberHex: the certificate serial as an even-length lowercase hex string.
function serialHex(big) {
  var neg = big < 0n;
  var h = (neg ? -big : big).toString(16);
  if (h.length % 2) h = "0" + h;
  return neg ? "-" + h : h;
}

// The three cheap, high-value CRL extension values are decoded from their raw
// extnValue octets (RFC 5280 §5.2/§5.3); GeneralNames-based extensions
// (issuingDistributionPoint, certificateIssuer, authorityKeyIdentifier, …) stay
// raw with their bytes reachable. A malformed decoded value fails closed.
function decodeExt(ext) {
  var value = ext.value;
  try {
    if (ext.name === "cRLNumber") {           // cRLNumber ::= INTEGER
      value = asn1.read.integer(asn1.decode(ext.value));
    } else if (ext.name === "reasonCode") {   // reasonCode ::= ENUMERATED (CRLReason)
      var rn = asn1.decode(ext.value);
      if (rn.tagClass !== "universal" || rn.tagNumber !== TAGS.ENUMERATED) {
        throw new Error("reasonCode must be an ENUMERATED");
      }
      value = Number(asn1.read.integer(rn));
    } else if (ext.name === "invalidityDate") { // invalidityDate ::= GeneralizedTime
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
    var serial = m.fields.userCertificate.value;
    return {
      serialNumber: serial,
      serialNumberHex: serialHex(serial),
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
var CERTIFICATE_LIST = schema.seq([
  schema.field("tbsCertList", TBS_CERTLIST),
  schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("signatureValue", schema.bitString()),
], {
  assert: "sequence", arity: { exact: 3 }, code: "crl/not-a-crl", what: "CertificateList",
  build: function (m) {
    var tbsMatch = m.fields.tbsCertList.value;
    var tbs = tbsMatch.result;
    // RFC 5280 §5.1.1.2 — the outer signatureAlgorithm MUST equal tbsCertList.signature.
    if (!m.fields.signatureAlgorithm.node.bytes.equals(tbsMatch.fields.signature.node.bytes)) {
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
      tbsBytes: tbsMatch.node.bytes,
      signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
      signatureValue: { unusedBits: m.fields.signatureValue.value.unusedBits, bytes: m.fields.signatureValue.value.bytes },
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
function parse(input) {
  var der;
  if (Buffer.isBuffer(input)) der = input;
  else if (typeof input === "string") der = pemDecode(input);
  else throw new CrlError("crl/bad-input", "parse expects a DER Buffer or a PEM string");
  var root;
  try { root = asn1.decode(der); }
  catch (e) { throw new CrlError("crl/bad-der", "CRL DER did not decode: " + ((e && e.message) || String(e)), e); }
  return schema.walk(CERTIFICATE_LIST, root, NS).result;
}

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
function pemDecode(text, label) {
  if (Buffer.isBuffer(text)) text = text.toString("latin1");
  if (typeof text !== "string") throw new PemError("pem/bad-input", "pemDecode expects a string or Buffer");
  if (text.length > constants.LIMITS.PEM_MAX_BYTES) throw new PemError("pem/too-large", "PEM input exceeds size cap");
  var m = PEM_RE.exec(text);
  if (!m) throw new PemError("pem/no-block", "no PEM block found");
  var want = label || "X509 CRL";
  if (m[1] !== want) throw new PemError("pem/label-mismatch", "expected " + JSON.stringify(want) + " block, got " + JSON.stringify(m[1]));
  var b64 = m[2].replace(/[\r\n\t ]+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new PemError("pem/bad-base64", "PEM body is not valid base64");
  return Buffer.from(b64, "base64");
}

// Certificate and CertificateList share the outer SEQUENCE-of-3 shape; a CRL is
// distinguished by its tbsCertList — the first tbs element is a bare INTEGER
// (version) or an AlgorithmIdentifier (signature) SEQUENCE, and crucially the
// field at the certificate's Validity position is a bare Time (thisUpdate). The
// orchestrator uses `matches` to route; a cert's tbs leads with a [0] EXPLICIT
// version or an INTEGER serial FOLLOWED by an AlgorithmIdentifier and a Name,
// then a Validity SEQUENCE, never a bare Time at that depth.
function matches(root) {
  if (!root || root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE) return false;
  if (!root.children || root.children.length !== 3) return false;
  var tbs = root.children[0];
  if (!tbs.children || tbs.tagNumber !== TAGS.SEQUENCE) return false;
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
