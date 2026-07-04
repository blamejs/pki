// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.x509
 * @nav        Certificates
 * @title      X.509
 * @order      100
 * @featured   true
 * @slug       x509
 *
 * @intro
 *   X.509 certificate handling per RFC 5280. The seed surface is
 *   `parse` — turn a DER or PEM certificate into a structured,
 *   fully-decoded object: version, serial, signature algorithm, issuer
 *   and subject distinguished names, validity window (as real `Date`s),
 *   subject public-key info, and the extension list. The parser composes
 *   the strict DER codec and the OID registry, so every field is
 *   validated on the way in and every algorithm / attribute / extension
 *   is named where the registry knows it.
 *
 *   The raw `tbsCertificate` bytes are returned alongside the parsed
 *   fields so a signature-verification layer can hash exactly the bytes
 *   that were signed rather than re-encoding and hoping for round-trip
 *   fidelity.
 *
 * @card
 *   Parse DER / PEM X.509 certificates into structured, validated fields
 *   with named algorithms, extensions, and real-`Date` validity windows.
 */

var constants = require("./constants");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CertificateError = frameworkError.CertificateError;
var PemError = frameworkError.PemError;

var TAGS = asn1.TAGS;

// Distinguished-name attribute short labels (RFC 4514 §3 + common use).
var DN_SHORT = {
  commonName:             "CN",
  countryName:            "C",
  localityName:           "L",
  stateOrProvinceName:    "ST",
  streetAddress:          "STREET",
  organizationName:       "O",
  organizationalUnitName: "OU",
  domainComponent:        "DC",
  surname:                "SN",
  givenName:              "GN",
  serialNumber:           "SERIALNUMBER",
  emailAddress:           "emailAddress",
};

// ---- PEM -------------------------------------------------------------

var PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

/**
 * @primitive  pki.x509.pemDecode
 * @signature  pki.x509.pemDecode(text, label?) -> Buffer
 * @since      0.1.0
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.x509.pemEncode
 *
 * Extract the DER bytes from a PEM block. With `label` given (e.g.
 * `"CERTIFICATE"`) the block type must match; without it, the first block
 * is taken. Throws `PemError` on a missing / mismatched envelope or a
 * non-base64 body.
 *
 * @example
 *   var der = pki.x509.pemDecode(pemText, "CERTIFICATE");
 */
function pemDecode(text, label) {
  if (Buffer.isBuffer(text)) text = text.toString("latin1");
  if (typeof text !== "string") throw new PemError("pem/bad-input", "pemDecode expects a string or Buffer");
  if (text.length > constants.LIMITS.PEM_MAX_BYTES) throw new PemError("pem/too-large", "PEM input exceeds size cap");
  var m = PEM_RE.exec(text);
  if (!m) throw new PemError("pem/no-block", "no PEM block found");
  if (label && m[1] !== label) throw new PemError("pem/label-mismatch", "expected " + JSON.stringify(label) + " block, got " + JSON.stringify(m[1]));
  var b64 = m[2].replace(/[\r\n\t ]+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new PemError("pem/bad-base64", "PEM body is not valid base64");
  return Buffer.from(b64, "base64");
}

/**
 * @primitive  pki.x509.pemEncode
 * @signature  pki.x509.pemEncode(der, label) -> string
 * @since      0.1.0
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.x509.pemDecode
 *
 * Wrap DER bytes in a PEM envelope with 64-column base64 lines.
 *
 * @example
 *   var pem = pki.x509.pemEncode(der, "CERTIFICATE");
 */
function pemEncode(der, label) {
  if (typeof label !== "string" || label.length === 0) throw new PemError("pem/bad-label", "pemEncode requires a label");
  var buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  var b64 = buf.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
}

// ---- helpers ---------------------------------------------------------

function _algId(node) {
  if (node.tagClass !== "universal" || node.tagNumber !== TAGS.SEQUENCE || !node.children.length) {
    throw new CertificateError("x509/bad-algorithm-identifier", "AlgorithmIdentifier must be a non-empty SEQUENCE");
  }
  var dotted = asn1.read.oid(node.children[0]);
  return {
    oid: dotted,
    name: oid.name(dotted) || null,
    parameters: node.children.length > 1 ? node.children[1].bytes : null,
  };
}

function _attrValueToString(node) {
  try { return asn1.read.string(node); }
  catch (e) {
    // A malformed KNOWN string type (invalid UTF-8, a non-IA5 byte, a
    // PrintableString character outside its set, ...) is a malformed
    // certificate and must fail closed — do NOT hex-encode it away, or the
    // decoder's strict string validation is silently bypassed on the DN path.
    // Those surface as asn1/bad-* content errors; raise a CertificateError so
    // parse fails closed on the documented x509/* contract.
    //
    // A value that simply is not a decodable primitive string is NOT malformed
    // and must stay representable: an ANY-typed non-string tag
    // (asn1/expected-string) or a constructed universal type such as a SEQUENCE
    // (asn1/expected-primitive). Per RFC 4514 §2.4 it is rendered as "#" plus
    // the hex of its FULL DER encoding (tag + length + content — node.bytes),
    // so a constructed value round-trips intact rather than being dropped or
    // rejecting the whole certificate.
    if (!e || (e.code !== "asn1/expected-string" && e.code !== "asn1/expected-primitive")) {
      throw new CertificateError("x509/bad-atv", "malformed string in attribute value: " + ((e && e.message) || String(e)));
    }
    return "#" + node.bytes.toString("hex");
  }
}

function _escapeDnValue(v) {
  return v.replace(/([,+"\\<>;])/g, "\\$1");
}

function _parseName(node) {
  if (node.tagClass !== "universal" || node.tagNumber !== TAGS.SEQUENCE) {
    throw new CertificateError("x509/bad-name", "Name must be an RDNSequence (SEQUENCE)");
  }
  var rdns = [];
  var parts = [];
  for (var i = 0; i < node.children.length; i++) {
    var rdn = node.children[i];
    if (rdn.tagClass !== "universal" || rdn.tagNumber !== TAGS.SET) {
      throw new CertificateError("x509/bad-rdn", "RelativeDistinguishedName must be a SET");
    }
    var atvs = [];
    var atvParts = [];
    for (var j = 0; j < rdn.children.length; j++) {
      var atv = rdn.children[j];
      if (!atv.children || atv.children.length < 2) {
        throw new CertificateError("x509/bad-atv", "AttributeTypeAndValue must be a SEQUENCE of {type, value}");
      }
      var typeOid = asn1.read.oid(atv.children[0]);
      var typeName = oid.name(typeOid);
      var value = _attrValueToString(atv.children[1]);
      atvs.push({ type: typeOid, name: typeName || null, value: value });
      var label = (typeName && DN_SHORT[typeName]) || typeName || typeOid;
      atvParts.push(label + "=" + _escapeDnValue(value));
    }
    rdns.push(atvs);
    parts.push(atvParts.join("+"));
  }
  return { rdns: rdns, dn: parts.join(", ") };
}

function _parseValidityTime(node) {
  if (node.tagClass !== "universal" || (node.tagNumber !== TAGS.UTC_TIME && node.tagNumber !== TAGS.GENERALIZED_TIME)) {
    throw new CertificateError("x509/bad-time", "Validity time must be UTCTime or GeneralizedTime");
  }
  return asn1.read.time(node);
}

function _parseExtensions(seqNode) {
  // RFC 5280 §4.1.2.9 — Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
  // The wrapped value must be a SEQUENCE (not a primitive, which would read
  // seqNode.children as null and throw a raw TypeError) and must carry at
  // least one extension.
  if (seqNode.tagClass !== "universal" || seqNode.tagNumber !== TAGS.SEQUENCE || !seqNode.children) {
    throw new CertificateError("x509/bad-extensions", "extensions [3] must wrap a SEQUENCE");
  }
  if (seqNode.children.length === 0) {
    throw new CertificateError("x509/bad-extensions", "extensions SEQUENCE must contain at least one extension");
  }
  var out = [];
  var seen = new Set();
  for (var i = 0; i < seqNode.children.length; i++) {
    var ext = seqNode.children[i];
    if (!ext.children || ext.children.length < 2) {
      throw new CertificateError("x509/bad-extension", "Extension must be a SEQUENCE");
    }
    var extnID = asn1.read.oid(ext.children[0]);
    // RFC 5280 §4.2 — a certificate MUST NOT include more than one
    // instance of a particular extension.
    if (seen.has(extnID)) {
      throw new CertificateError("x509/duplicate-extension", "certificate repeats extension " + extnID);
    }
    seen.add(extnID);
    var critical = false;
    var valueNode;
    if (ext.children.length === 3) {
      critical = asn1.read.boolean(ext.children[1]);
      valueNode = ext.children[2];
    } else {
      valueNode = ext.children[1];
    }
    out.push({
      oid:      extnID,
      name:     oid.name(extnID) || null,
      critical: critical,
      value:    asn1.read.octetString(valueNode),
    });
  }
  return out;
}

// ---- parse -----------------------------------------------------------

/**
 * @primitive  pki.x509.parse
 * @signature  pki.x509.parse(input) -> certificate
 * @since      0.1.0
 * @status     stable
 * @spec       RFC 5280, X.509
 * @defends    malformed-certificate-parse (CWE-20)
 * @related    pki.asn1.decode, pki.oid.name
 *
 * Parse a DER `Buffer` or a PEM string/Buffer into a structured
 * certificate: `{ version, serialNumber, serialNumberHex,
 * signatureAlgorithm, issuer, subject, validity, subjectPublicKeyInfo,
 * extensions, tbsBytes, signatureValue }`. Distinguished names come back
 * both as a rendered `dn` string and as structured `rdns`; the validity
 * window is real `Date`s; `tbsBytes` is the exact signed byte range for a
 * downstream verifier.
 *
 * Throws `CertificateError` when the bytes are not a well-formed
 * certificate and `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var cert = pki.x509.parse(pemString);
 *   cert.subject.dn;                 // "CN=example.com, O=Example"
 *   cert.validity.notAfter;          // Date
 *   cert.signatureAlgorithm.name;    // "sha256WithRSAEncryption"
 */
function parse(input) {
  var der;
  if (typeof input === "string" || (Buffer.isBuffer(input) && input.length >= 5 && input.toString("latin1", 0, 5) === "-----")) {
    der = pemDecode(input, "CERTIFICATE");
  } else if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    der = Buffer.isBuffer(input) ? input : Buffer.from(input);
  } else {
    throw new CertificateError("x509/bad-input", "parse expects a DER Buffer or a PEM string");
  }

  var root;
  try {
    root = asn1.decode(der);
  } catch (e) {
    throw new CertificateError("x509/bad-der", "certificate DER did not decode: " + e.message, e);
  }
  if (root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE || !root.children || root.children.length !== 3) {
    throw new CertificateError("x509/not-a-certificate", "Certificate must be a SEQUENCE of {tbsCertificate, signatureAlgorithm, signature}");
  }

  var tbs = root.children[0];
  var outerSigAlg = root.children[1];
  var sigValueNode = root.children[2];
  if (!tbs.children || !tbs.children.length) {
    throw new CertificateError("x509/bad-tbs", "tbsCertificate is empty");
  }

  var idx = 0;
  var version;
  var first = tbs.children[0];
  if (first.tagClass === "context" && first.tagNumber === 0) {
    if (!first.children || !first.children.length) throw new CertificateError("x509/bad-version", "version [0] must wrap an INTEGER");
    // RFC 5280 §4.1.2.1 — version is INTEGER { v1(0), v2(1), v3(2) }; read
    // it as a BigInt so an out-of-range value can't be coerced to a float,
    // and reject an explicitly-encoded v1 (DER forbids encoding the DEFAULT).
    var versionValue = asn1.read.integer(first.children[0]);
    if (versionValue === 0n) {
      throw new CertificateError("x509/bad-version", "DER forbids explicitly encoding the default version v1");
    } else if (versionValue === 1n) {
      version = 2;
    } else if (versionValue === 2n) {
      version = 3;
    } else {
      throw new CertificateError("x509/bad-version", "unsupported certificate version " + versionValue.toString());
    }
    idx = 1;
  } else {
    version = 1;
  }

  // Six positional fields follow any [0] version; a shorter tbs would read
  // `undefined` and throw a raw TypeError on the first property access.
  if (tbs.children.length < idx + 6) {
    throw new CertificateError("x509/bad-tbs", "tbsCertificate is too short");
  }

  var serialNode = tbs.children[idx++];
  var serialNumber = asn1.read.integer(serialNode);
  var innerSigAlg = tbs.children[idx++];
  var issuer = _parseName(tbs.children[idx++]);
  var validityNode = tbs.children[idx++];
  var subject = _parseName(tbs.children[idx++]);
  var spkiNode = tbs.children[idx++];

  // RFC 5280 §4.1.1.2 — the outer signatureAlgorithm MUST contain the same
  // AlgorithmIdentifier (OID and parameters) as tbsCertificate.signature. A
  // mismatch is a signature-algorithm-substitution vector, so compare the full
  // DER of both fields rather than surfacing two disagreeing algorithms.
  if (!outerSigAlg.bytes.equals(innerSigAlg.bytes)) {
    throw new CertificateError("x509/bad-signature-algorithm", "signatureAlgorithm must match tbsCertificate.signature (RFC 5280 §4.1.1.2)");
  }

  // RFC 5280 §4.1.2.4 — the issuer field MUST contain a non-empty distinguished
  // name. (An empty subject is permitted when a subjectAltName carries the
  // identity — §4.1.2.6 — so only the issuer is required non-empty here.)
  if (!issuer.rdns.length) {
    throw new CertificateError("x509/bad-issuer", "issuer must be a non-empty distinguished name");
  }

  if (!validityNode.children || validityNode.children.length !== 2) {
    throw new CertificateError("x509/bad-validity", "Validity must be a SEQUENCE of {notBefore, notAfter}");
  }
  var validity = {
    notBefore: _parseValidityTime(validityNode.children[0]),
    notAfter:  _parseValidityTime(validityNode.children[1]),
  };

  if (!spkiNode.children || spkiNode.children.length !== 2) {
    throw new CertificateError("x509/bad-spki", "SubjectPublicKeyInfo must be a SEQUENCE of {algorithm, subjectPublicKey}");
  }
  var spkiBits = asn1.read.bitString(spkiNode.children[1]);
  var subjectPublicKeyInfo = {
    algorithm: _algId(spkiNode.children[0]),
    publicKey: { unusedBits: spkiBits.unusedBits, bytes: spkiBits.bytes },
    bytes:     spkiNode.bytes,
  };

  // Remaining tbs children: optional issuerUniqueID [1], subjectUniqueID
  // [2], and extensions [3] EXPLICIT. Only extensions are surfaced. RFC 5280
  // §4.1 fixes these as the trailing fields, each at most once and in strictly
  // increasing tag order; a repeated or out-of-order tag (or an unknown /
  // non-context field) is malformed. Without the monotonic guard a second [3]
  // silently overwrites the first, hiding its extensions and splitting
  // duplicate extension OIDs across two wrappers past the per-sequence check.
  var extensions = [];
  var hasExtensions = false;
  var lastTrailingTag = 0;
  for (; idx < tbs.children.length; idx++) {
    var t = tbs.children[idx];
    if (t.tagClass !== "context" || t.tagNumber < 1 || t.tagNumber > 3) {
      throw new CertificateError("x509/bad-tbs", "unexpected field after subjectPublicKeyInfo; tbsCertificate allows only issuerUniqueID [1], subjectUniqueID [2], extensions [3]");
    }
    if (t.tagNumber <= lastTrailingTag) {
      throw new CertificateError("x509/bad-tbs", "tbsCertificate trailing field [" + t.tagNumber + "] is repeated or out of order");
    }
    lastTrailingTag = t.tagNumber;
    if (t.tagNumber === 3) {
      hasExtensions = true;
      if (!t.children || !t.children.length) throw new CertificateError("x509/bad-extensions", "extensions [3] must wrap a SEQUENCE");
      extensions = _parseExtensions(t.children[0]);
    }
  }

  // RFC 5280 §4.1.2.9 — the extensions field appears only in a v3 cert.
  if (hasExtensions && version !== 3) {
    throw new CertificateError("x509/bad-version", "extensions are only permitted in a v3 certificate");
  }

  var sigBits = asn1.read.bitString(sigValueNode);

  return {
    version:            version,
    serialNumber:       serialNumber,
    serialNumberHex:    serialNode.content.toString("hex"),
    signatureAlgorithm: _algId(outerSigAlg),
    tbsSignatureAlgorithm: _algId(innerSigAlg),
    issuer:             issuer,
    subject:            subject,
    validity:           validity,
    subjectPublicKeyInfo: subjectPublicKeyInfo,
    extensions:         extensions,
    tbsBytes:           tbs.bytes,
    signatureValue:     { unusedBits: sigBits.unusedBits, bytes: sigBits.bytes },
  };
}

module.exports = {
  parse:     parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
};
