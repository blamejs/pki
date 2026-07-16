// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. This is lib composition only; the
// documented surface is the primitives whose type handling composes these validators.
//
// validator-all -- the validator-family orchestrator (schema-all's role for the
// validator family, guard-all's role for the guards). It assembles the per-type
// conformance validators into one namespaced surface every format module composes,
// so a format depends on the family rather than re-deriving a decoded type's rule set
// inline (the drift that leaks a spec MUST out one review round at a time):
//
//   validator.cose.credentialKey / .toSpki
//                                     -- the COMPLETE WebAuthn credential COSE_Key rule
//                                        set (RFC 9052/9053 + WebAuthn sec. 6.5.1 +
//                                        CTAP2 canonical + on-curve), one home
//   validator.sig.ecdsaDerToP1363     -- the COMPLETE order-aware DER ECDSA-Sig-Value
//                                        conformance (RFC 3279 + X.690 strict-DER +
//                                        FIPS 186-5 [1,n-1], CVE-2022-21449) + raw r||s
//   validator.attcert.packedCert / .aikCert / .aaguidExt / .requireV3 / .assertNotCa
//                                     -- the WebAuthn attestation-certificate profile
//                                        (sec. 8.2.1 packed, sec. 8.3.1 TPM AIK), one home
//   validator.keydesc.androidKeyDescription
//                                     -- the Android Key Attestation KeyDescription
//                                        (AOSP schema + WebAuthn sec. 8.4.1), one home
//   validator.tpm.parsePubArea / .parseCertInfo / .pubKeyEqualsCose
//                                     -- the TPM 2.0 pubArea/certInfo structure conformance
//                                        + key binding (WebAuthn sec. 8.3 + TCG Part 2), one home
//
// Each validator is enforced by the validator-reinlined codebase-patterns detector: a
// lib function that re-inlines a type's characteristic validation shape (declared on the
// validator via @validator-shape) is flagged, so a new format module cannot re-derive a
// partial subset and reintroduce the drift the validator exists to prevent.

var cose = require("./validator-cose");
var sig = require("./validator-sig");
var attcert = require("./validator-attcert");
var keydesc = require("./validator-keydesc");
var tpm = require("./validator-tpm");

module.exports = {
  cose: cose,
  sig: sig,
  attcert: attcert,
  keydesc: keydesc,
  tpm: tpm,
};
