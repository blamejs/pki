// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var oid = require("./oid");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");

var _asserts = guard.list.contains;

// @enforced-by behavioral -- a version-field check has no rename-proof code shape; the RED
function requireV3(cert, E, code) {
  if (cert.version !== 3) throw new E(code, "an attestation certificate must be X.509 version 3");
}

// @enforced-by behavioral -- a basicConstraints cA gate has no rename-proof code shape; the
function assertNotCa(cert, exts, E, code) {
  var bc = exts.decode(cert, "basicConstraints");
  if (!bc) throw new E(code, "an attestation leaf certificate MUST carry a basicConstraints extension (WebAuthn 8.2.1 / 8.3.1)");
  if (bc.value && bc.value.cA === true) throw new E(code, "an attestation leaf certificate MUST NOT be a CA (basicConstraints cA=true)");
}

// @enforced-by behavioral -- the subject-attribute + OU-literal checks are WebAuthn 8.2.1
function packedCert(cert, exts, E, code) {
  requireV3(cert, E, code);
  assertNotCa(cert, exts, E, code);
  var have = Object.create(null);
  (cert.subject.rdns || []).forEach(function (rdn) { rdn.forEach(function (a) { have[a.type] = a.value; }); });
  if (have[oid.byName("countryName")] == null || have[oid.byName("organizationName")] == null || have[oid.byName("commonName")] == null) {
    throw new E(code, "the packed attestation certificate subject MUST set C, O, OU, and CN (WebAuthn 8.2.1)");
  }
  if (have[oid.byName("organizationalUnitName")] !== "Authenticator Attestation") {
    throw new E(code, "the packed attestation certificate subject OU MUST be \"Authenticator Attestation\" (WebAuthn 8.2.1)");
  }
}

// @enforced-by behavioral -- the empty-subject + EKU + SAN-attribute checks are WebAuthn
function aikCert(cert, exts, E, code) {
  requireV3(cert, E, code);
  assertNotCa(cert, exts, E, code);
  if ((cert.subject.rdns || []).length !== 0) throw new E(code, "the tpm AIK certificate subject MUST be empty (WebAuthn 8.3.1)");
  var eku = exts.decode(cert, "extKeyUsage");
  if (!eku || !Array.isArray(eku.value) || !_asserts(eku.value, oid.byName("tcgKpAikCertificate"))) {
    throw new E(code, "the tpm AIK certificate lacks the tcg-kp-AIKCertificate extended key purpose (WebAuthn 8.3.1)");
  }
  var san = exts.decode(cert, "subjectAltName");
  var dirName = san && san.value && san.value.names && san.value.names.filter(function (n) { return n.tagNumber === 4; })[0];
  var types = Object.create(null);
  if (dirName && dirName.value && dirName.value.rdns) {
    dirName.value.rdns.forEach(function (rdn) { rdn.forEach(function (a) { types[a.type] = true; }); });
  }
  if (!types[oid.byName("tpmManufacturer")] || !types[oid.byName("tpmModel")] || !types[oid.byName("tpmVersion")]) {
    throw new E(code, "the tpm AIK certificate subjectAltName lacks the required tcg attributes (WebAuthn 8.3.1)");
  }
}

// @enforced-by behavioral -- an optional-extension equality check has no rename-proof code
function aaguidExt(cert, aaguid, exts, E, code, mismatchCode) {
  var ext = exts.find(cert, "idFidoGenCeAaguid");
  if (!ext) return;
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
