// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 4211 certificate-request-message issuance via pki.crmf.build.
 *
 * The hostile surface is the ENCODER over an arbitrary request spec: pki.crmf.build must, for ANY derived
 * spec (certReqId, template fields, proof-of-possession mode, requester arm), EITHER throw a typed
 * pki.errors.PkiError OR produce a CertReqMessages that round-trips through the strict
 * pki.schema.crmf.parse decoder. The fuzz bytes drive certReqId, the subject, the template toggles
 * (validity / extensions / complete-vs-incomplete), the POP mode, and the requester arm. Keys are built once.
 *
 * Contract: a build() failure must be a PkiError, and a build() SUCCESS must parse -- an output the
 * producer's own strict parser rejects is a round-trip violation, and any non-PkiError throw is an
 * unguarded invariant break; either is a finding, so it propagates for jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var REQ = signing.makeSigner("ec-p256");
var REQ_ED = signing.makeSigner("ed25519");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  var flags = d.length ? d[0] : 0;
  var name = (d.length > 1 ? d.slice(1, Math.min(d.length, 33)).toString("latin1").replace(/[^\x20-\x7e]/g, "?") : "") || "req";
  var req = (flags & 64) ? REQ_ED : REQ;

  var template = { publicKey: req.spki };
  if (!(flags & 1)) template.subject = [{ commonName: name.replace(/[^A-Za-z0-9 ]/g, "x") || "req" }];   // omit subject -> incomplete
  if (flags & 2) template.validity = { notBefore: NB, notAfter: NA };
  if (flags & 4) template.extensions = { keyUsage: ["digitalSignature"] };
  if (flags & 8) template.version = 2;

  var spec = { certReqId: (flags & 16) ? -1 : (d.length > 33 ? d[33] : 0), certTemplate: template };
  if ((flags & 1) && !(flags & 32)) spec.pop = { type: "signature", sender: { dNSName: (name.replace(/[^A-Za-z0-9.-]/g, "x") || "h.example") } };
  if (flags & 32) { spec.pop = { type: "raVerified", raVerified: true }; }

  var der;
  try {
    der = (flags & 32) ? await pki.crmf.build(spec) : await pki.crmf.build(spec, { key: req.key });
  } catch (e) {
    if (isPki(e)) return;
    throw e;
  }
  // build() succeeded: the message MUST round-trip through the strict parser (any throw is a finding).
  pki.schema.crmf.parse(der);
};
