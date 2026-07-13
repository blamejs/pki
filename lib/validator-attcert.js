// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the verifier whose
// attestation-certificate handling composes this validator (pki.webauthn).
//
// validator-attcert -- the SINGLE home for "does this X.509 leaf meet the WebAuthn
// attestation-certificate profile" (WebAuthn sec. 8.2.1 packed, sec. 8.3.1 TPM AIK).
// Sibling to the guard family: a validator owns a decoded TYPE's COMPLETE conformance rule
// set once, so the packed and AIK profiles cannot drift apart or lose a gate (e.g. the v3
// check that previously lived split out in the tpm verifier rather than in the profile).
//
// The caller supplies its parsed certificate + an extension-accessor object `exts`
// { find(cert, oidName) -> rawExt|null, decode(cert, oidName) -> {critical, value}|null }
// so this validator stays decoupled from any one format's extension-decoder namespace, and
// its typed error CONSTRUCTOR E + domain code (a distinct mismatchCode for aaguidExt).
//
// Rule set (gap-checked verbatim against WebAuthn sec. 8.2.1 + sec. 8.3.1 + RFC 5280):
//   - requireV3:  the leaf MUST be X.509 v3 (packed 8.2.1, AIK 8.3.1).
//   - assertNotCa: the leaf MUST carry basicConstraints with cA=FALSE (present, not merely
//     "not cA=true": a genuine CA or unconstrained leaf must not be repurposed as a leaf).
//   - packedCert: v3 + non-CA + subject sets C, O, OU="Authenticator Attestation", CN.
//   - aikCert:    v3 + non-CA + EMPTY subject + EKU contains tcg-kp-AIKCertificate + SAN
//     directoryName carries tpmManufacturer/tpmModel/tpmVersion (TPMv2-EK-Profile 3.2.9).
//   - aaguidExt:  the id-fido-gen-ce-aaguid extension, if present, MUST NOT be critical and
//     MUST equal the authenticatorData aaguid (a 16-byte OCTET STRING inside the ext OCTET
//     STRING). Absence is tolerated; presence must match.

var oid = require("./oid");
var asn1 = require("./asn1-der");

// requireV3(cert, E, code) -- the leaf attestation certificate MUST be X.509 v3.
// @enforced-by behavioral -- a version-field check has no rename-proof code shape; the RED
// vector (a non-v3 attestation leaf rejected) is the guard.
function requireV3(cert, E, code) {
  if (cert.version !== 3) throw new E(code, "an attestation certificate must be X.509 version 3");
}

// assertNotCa(cert, exts, E, code) -- the leaf MUST carry basicConstraints with cA=FALSE.
// @enforced-by behavioral -- a basicConstraints cA gate has no rename-proof code shape; the
// RED vector (a CA-asserting or constraint-omitting attestation leaf rejected) is the guard.
function assertNotCa(cert, exts, E, code) {
  var bc = exts.decode(cert, "basicConstraints");
  if (!bc) throw new E(code, "an attestation leaf certificate MUST carry a basicConstraints extension (WebAuthn 8.2.1 / 8.3.1)");
  if (bc.value && bc.value.cA === true) throw new E(code, "an attestation leaf certificate MUST NOT be a CA (basicConstraints cA=true)");
}

// packedCert(cert, exts, E, code) -- the complete WebAuthn 8.2.1 packed attestation-cert
// profile (v3 + non-CA + the four subject attributes).
// @enforced-by behavioral -- the subject-attribute + OU-literal checks are WebAuthn 8.2.1
// business rules with no rename-proof code shape; the RED vectors (missing C/O/CN, wrong OU,
// CA=true, non-v3) are the guard.
function packedCert(cert, exts, E, code) {
  requireV3(cert, E, code);
  assertNotCa(cert, exts, E, code);
  var have = {};
  (cert.subject.rdns || []).forEach(function (rdn) { rdn.forEach(function (a) { have[a.type] = a.value; }); });
  if (have[oid.byName("countryName")] == null || have[oid.byName("organizationName")] == null || have[oid.byName("commonName")] == null) {
    throw new E(code, "the packed attestation certificate subject MUST set C, O, OU, and CN (WebAuthn 8.2.1)");
  }
  if (have[oid.byName("organizationalUnitName")] !== "Authenticator Attestation") {
    throw new E(code, "the packed attestation certificate subject OU MUST be \"Authenticator Attestation\" (WebAuthn 8.2.1)");
  }
}

// aikCert(cert, exts, E, code) -- the complete WebAuthn 8.3.1 TPM AIK attestation-cert
// profile (v3 + non-CA + empty subject + tcg-kp-AIKCertificate EKU + the tcg SAN attributes).
// @enforced-by behavioral -- the empty-subject + EKU + SAN-attribute checks are WebAuthn
// 8.3.1 business rules with no rename-proof code shape; the RED vectors are the guard.
function aikCert(cert, exts, E, code) {
  requireV3(cert, E, code);
  assertNotCa(cert, exts, E, code);
  if ((cert.subject.rdns || []).length !== 0) throw new E(code, "the tpm AIK certificate subject MUST be empty (WebAuthn 8.3.1)");
  var eku = exts.decode(cert, "extKeyUsage");
  if (!eku || !Array.isArray(eku.value) || eku.value.indexOf(oid.byName("tcgKpAikCertificate")) === -1) {
    throw new E(code, "the tpm AIK certificate lacks the tcg-kp-AIKCertificate extended key purpose (WebAuthn 8.3.1)");
  }
  var san = exts.decode(cert, "subjectAltName");
  var dirName = san && san.value && san.value.names && san.value.names.filter(function (n) { return n.tagNumber === 4; })[0];
  var types = {};
  if (dirName && dirName.value && dirName.value.rdns) {
    dirName.value.rdns.forEach(function (rdn) { rdn.forEach(function (a) { types[a.type] = true; }); });
  }
  if (!types[oid.byName("tpmManufacturer")] || !types[oid.byName("tpmModel")] || !types[oid.byName("tpmVersion")]) {
    throw new E(code, "the tpm AIK certificate subjectAltName lacks the required tcg attributes (WebAuthn 8.3.1)");
  }
}

// aaguidExt(cert, aaguid, exts, E, code, mismatchCode) -- the id-fido-gen-ce-aaguid
// extension, if present, MUST NOT be critical and MUST equal the authenticatorData aaguid.
// @enforced-by behavioral -- an optional-extension equality check has no rename-proof code
// shape; the RED vectors (a critical ext, a non-matching aaguid) are the guard.
function aaguidExt(cert, aaguid, exts, E, code, mismatchCode) {
  var ext = exts.find(cert, "idFidoGenCeAaguid");
  if (!ext) return;   // absence is tolerated; presence must match
  if (ext.critical) throw new E(code, "the id-fido-gen-ce-aaguid extension MUST NOT be critical (WebAuthn 8.2.1)");
  var val;
  try { val = asn1.read.octetString(asn1.decode(ext.value)); }
  catch (e) { throw new E(code, "the id-fido-gen-ce-aaguid extension value is not a valid OCTET STRING", e); }
  if (!val.equals(aaguid)) throw new E(mismatchCode, "the id-fido-gen-ce-aaguid extension value does not equal the authenticatorData aaguid");
}

module.exports = {
  requireV3: requireV3,
  assertNotCa: assertNotCa,
  packedCert: packedCert,
  aikCert: aikCert,
  aaguidExt: aaguidExt,
};
