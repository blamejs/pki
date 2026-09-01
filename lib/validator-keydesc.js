// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");

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

// @enforced-by behavioral -- the challenge / allApplications / origin / purpose checks are
function androidKeyDescription(cert, clientDataHash, exts, E, code, failCode) {
  var ext = exts.find(cert, "keyDescription");
  if (!ext) throw new E(code, "the android-key attestation certificate is missing the key-description extension (WebAuthn 8.4.1)");
  var kd;
  try { kd = asn1.decode(ext.value); } catch (e) { throw new E(code, "the android KeyDescription is not decodable", e); }
  if (!kd.children || kd.children.length < 8) throw new E(code, "the android KeyDescription is not a positional 8-field SEQUENCE");
  var challenge;
  try { challenge = asn1.read.octetString(kd.children[4]); } catch (e) { throw new E(code, "the android attestationChallenge is not an OCTET STRING", e); }
  if (!challenge.equals(clientDataHash)) throw new E(failCode, "the android attestationChallenge does not equal clientDataHash");
  var softwareEnforced = kd.children[6], hardwareEnforced = kd.children[7];
  if (_alGet(softwareEnforced, 600) || _alGet(hardwareEnforced, 600)) throw new E(failCode, "android allApplications MUST be absent (WebAuthn 8.4.1)");
  var origins = [_alGet(softwareEnforced, 702), _alGet(hardwareEnforced, 702)].filter(Boolean);
  if (!origins.length || !origins.every(function (o) { return _alInt(o, E, code) === 0n; })) {
    throw new E(failCode, "android key origin is not KM_ORIGIN_GENERATED in every authorization list that declares it (WebAuthn 8.4.1)");
  }
  var purposes = _purposeUnion(softwareEnforced, hardwareEnforced, E, code);
  if (purposes.length !== 1 || purposes[0] !== 2n) {
    throw new E(failCode, "android key purpose is not exactly KM_PURPOSE_SIGN (WebAuthn 8.4.1)");
  }
}

module.exports = { androidKeyDescription: androidKeyDescription };
