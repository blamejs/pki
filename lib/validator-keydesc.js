// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the verifier whose
// android-key handling composes this validator (pki.webauthn).
//
// validator-keydesc -- the SINGLE home for the Android Key Attestation KeyDescription
// conformance (the AOSP key-attestation schema + WebAuthn sec. 8.4.1 authorization-list
// checks). Sibling to the guard family: a validator owns a decoded TYPE's COMPLETE
// conformance rule set once, so the four 8.4.1 checks cannot lose a gate to drift.
//
// The caller supplies its parsed certificate + an extension-accessor `exts`
// { find(cert, oidName) -> rawExt|null } + its typed error CONSTRUCTOR E with two codes: a
// STRUCTURAL `code` (a malformed KeyDescription is bad input) and a semantic `failCode` (a
// well-formed description that fails an 8.4.1 MUST is a failed verification).
//
// Rule set (gap-checked verbatim against WebAuthn sec. 8.4.1 + the AOSP KeyDescription
// schema):
//   - KeyDescription is a positional SEQUENCE; attestationChallenge (position 4) MUST equal
//     clientDataHash.
//   - allApplications (tag 600) MUST be absent from BOTH the softwareEnforced (position 6)
//     and teeEnforced (position 7) AuthorizationLists (the key MUST be scoped to the RP).
//   - origin (tag 702) MUST equal KM_ORIGIN_GENERATED (0): at least one list declares it,
//     and every list that declares one says GENERATED (a mixed IMPORTED/GENERATED key is
//     contradictory and rejected).
//   - purpose (tag 1) MUST be EXACTLY { KM_PURPOSE_SIGN (2) } over the union of the lists.

var asn1 = require("./asn1-der");

// The EXPLICIT-unwrapped value node for a [tag] field of an AuthorizationList (a SEQUENCE
// of context-tagged OPTIONAL fields with non-contiguous tag numbers), or null when absent.
function _alGet(seqNode, tag) {
  if (!seqNode || !seqNode.children) return null;
  for (var i = 0; i < seqNode.children.length; i++) {
    var c = seqNode.children[i];
    if (c.tagClass === "context" && c.tagNumber === tag) return c.children && c.children[0] ? c.children[0] : c;
  }
  return null;
}

function _alInt(node, E, code) {
  try { return asn1.read.integer(node); }
  catch (e) { throw new E(code, "an android KeyDescription authorization value is not an INTEGER", e); }
}

function _purposeUnion(a, b, E, code) {
  var out = [];
  [a, b].forEach(function (list) {
    var p = _alGet(list, 1);
    if (p && p.children) p.children.forEach(function (c) { var v = _alInt(c, E, code); if (out.indexOf(v) === -1) out.push(v); });
  });
  return out;
}

// androidKeyDescription(cert, clientDataHash, exts, E, code, failCode) -- the complete
// WebAuthn 8.4.1 KeyDescription gate. A verifier MUST route the android-key description
// through here, never re-derive a partial subset of the four checks inline.
// @enforced-by behavioral -- the challenge / allApplications / origin / purpose checks are
// WebAuthn 8.4.1 business rules with no rename-proof code shape; the RED vectors (challenge
// mismatch, allApplications present, origin != GENERATED, purpose != SIGN, and the empty-
// authorization-list spec vector) are the guard.
function androidKeyDescription(cert, clientDataHash, exts, E, code, failCode) {
  var ext = exts.find(cert, "keyDescription");
  if (!ext) throw new E(code, "the android-key attestation certificate is missing the key-description extension (WebAuthn 8.4.1)");
  var kd;
  try { kd = asn1.decode(ext.value); } catch (e) { throw new E(code, "the android KeyDescription is not decodable", e); }
  if (!kd.children || kd.children.length < 8) throw new E(code, "the android KeyDescription is not a positional 8-field SEQUENCE");
  // (1) attestationChallenge (position 4) == clientDataHash.
  var challenge;
  try { challenge = asn1.read.octetString(kd.children[4]); } catch (e) { throw new E(code, "the android attestationChallenge is not an OCTET STRING", e); }
  if (!challenge.equals(clientDataHash)) throw new E(failCode, "the android attestationChallenge does not equal clientDataHash");
  var softwareEnforced = kd.children[6], hardwareEnforced = kd.children[7];
  // (2) [600] allApplications MUST be ABSENT in both lists.
  if (_alGet(softwareEnforced, 600) || _alGet(hardwareEnforced, 600)) throw new E(failCode, "android allApplications MUST be absent (WebAuthn 8.4.1)");
  // (3) origin == KM_ORIGIN_GENERATED (0) over the union: at least one list declares it,
  // and every list that declares one says GENERATED.
  var origins = [_alGet(softwareEnforced, 702), _alGet(hardwareEnforced, 702)].filter(Boolean);
  if (!origins.length || !origins.every(function (o) { return _alInt(o, E, code) === 0n; })) {
    throw new E(failCode, "android key origin is not KM_ORIGIN_GENERATED in every authorization list that declares it (WebAuthn 8.4.1)");
  }
  // (4) purpose == exactly { KM_PURPOSE_SIGN (2) } over the union.
  var purposes = _purposeUnion(softwareEnforced, hardwareEnforced, E, code);
  if (purposes.length !== 1 || purposes[0] !== 2n) {
    throw new E(failCode, "android key purpose is not exactly KM_PURPOSE_SIGN (WebAuthn 8.4.1)");
  }
}

module.exports = { androidKeyDescription: androidKeyDescription };
