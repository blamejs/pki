// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: PKCS#10 certification-request issuance via pki.csr.sign.
 *
 * The hostile surface is the ENCODER over an arbitrary request spec: pki.csr.sign must, for ANY derived
 * spec (subject, requested extensions, challengePassword, signer arm), EITHER throw a typed
 * pki.errors.PkiError OR produce a request that round-trips through the strict pki.schema.csr.parse
 * decoder. The fuzz bytes drive the subject (sanitized to printable ASCII so the DN charset -- a separate
 * guard -- is not what is under test), the extension toggles, an optional challengePassword, and the
 * signer arm. Signer certificates + keys are built once.
 *
 * Contract: a sign() failure must be a PkiError, and a sign() SUCCESS must parse -- an output the
 * producer's own strict parser rejects is a round-trip violation, and any non-PkiError throw is an
 * unguarded invariant break; either is a finding, so it propagates for jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var SIGNER = signing.makeSigner("ec-p256");
var SIGNER_ED = signing.makeSigner("ed25519");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  var flags = d.length ? d[0] : 0;
  var subject = (d.length > 1 ? d.slice(1, Math.min(d.length, 33)).toString("latin1").replace(/[^\x20-\x7e]/g, "?") : "") || "Fuzz";
  var spec = { subject: subject, subjectPublicKey: (flags & 32) ? SIGNER_ED.spki : SIGNER.spki };
  var exts = {};
  if (flags & 1) exts.keyUsage = (flags & 2) ? ["keyCertSign", "cRLSign"] : ["digitalSignature"];
  if (flags & 4) exts.subjectKeyIdentifier = true;
  if (flags & 8) exts.subjectAltName = [{ dNSName: subject.replace(/[^A-Za-z0-9.-]/g, "x") || "h.example" }];
  if (flags & 1 || flags & 4 || flags & 8) spec.extensionRequest = exts;
  if (flags & 16) spec.challengePassword = subject.slice(0, 40) || "pw";
  var signer = (flags & 32) ? SIGNER_ED : SIGNER;

  var der;
  try {
    der = await pki.csr.sign(spec, { key: signer.key });
  } catch (e) {
    if (isPki(e)) return;
    throw e;
  }
  // sign() succeeded: the request MUST round-trip through the strict parser (any throw is a finding).
  pki.schema.csr.parse(der);
};
