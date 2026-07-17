// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: X.509 certificate issuance via pki.x509.sign.
 *
 * The hostile surface is the ENCODER over an arbitrary certificate spec: pki.x509.sign must, for ANY
 * derived spec (subject, serial, extension toggles, signer arm), EITHER throw a typed
 * pki.errors.PkiError OR produce a certificate that round-trips through the strict
 * pki.schema.x509.parse decoder. The fuzz bytes drive the subject (sanitized to printable ASCII so the
 * DN charset -- a separate guard -- is not what is under test), a serial slice (which may exceed 20
 * octets -> a fail-closed x509/bad-serial), the extension set, and the signer algorithm arm. Signer
 * certificates + keys are built once.
 *
 * Contract: a sign() failure must be a PkiError, and a sign() SUCCESS must parse -- an output the
 * producer's own strict parser rejects is a round-trip violation, and any non-PkiError throw is an
 * unguarded invariant break; either is a finding, so it propagates for jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var SIGNER = signing.makeSigner("ec-p256");
var SIGNER_ED = signing.makeSigner("ed25519");
var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2030-01-01T00:00:00Z");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  var flags = d.length ? d[0] : 0;
  // Printable-ASCII subject (the DN control-byte guard is enforced elsewhere; here the STRUCTURE is under test).
  var subject = (d.length > 1 ? d.slice(1, Math.min(d.length, 33)).toString("latin1").replace(/[^\x20-\x7e]/g, "?") : "") || "Fuzz";
  var serial = d.length > 4 ? d.slice(1, Math.min(d.length, 25)) : undefined;   // may be >20 octets -> x509/bad-serial
  var exts = {};
  if (flags & 1) exts.basicConstraints = { cA: !!(flags & 2) };
  if (flags & 4) exts.keyUsage = (flags & 2) ? ["keyCertSign", "cRLSign"] : ["digitalSignature"];
  if (flags & 8) exts.subjectKeyIdentifier = true;
  if (flags & 16) exts.subjectAltName = [{ dNSName: subject.replace(/[^A-Za-z0-9.-]/g, "x") || "h.example" }];
  var signer = (flags & 32) ? SIGNER_ED : SIGNER;

  var der;
  try {
    der = await pki.x509.sign({
      subject: subject, subjectPublicKey: signer.spki, notBefore: NB, notAfter: NA,
      serialNumber: serial, extensions: exts,
    }, { key: signer.key });
  } catch (e) {
    if (isPki(e)) return;   // a fail-closed rejection of the derived spec is acceptable
    throw e;                // a non-PkiError throw is an unguarded invariant break
  }
  // sign() succeeded: the certificate MUST round-trip through the strict parser (any throw is a finding).
  pki.schema.x509.parse(der);
};
