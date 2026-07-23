// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 5280 sec. 5 CRL issuance via pki.crl.sign.
 *
 * The hostile surface is the ENCODER over an arbitrary CRL spec: pki.crl.sign must, for ANY derived spec
 * (revoked entries with reason / invalidityDate, the CRL extensions, the issuer signer arm), EITHER throw a
 * typed pki.errors.PkiError OR produce a CertificateList that round-trips through the strict
 * pki.schema.crl.parse decoder AND verifies under the issuer key. The fuzz bytes drive the revoked-entry
 * count + serials, the revocation reasons, the extension toggles (cRLNumber / AKI / IDP / delta indicator),
 * whether nextUpdate is present, and the signer arm. Signer keys are built once.
 *
 * Contract: a sign() failure must be a PkiError, and a sign() SUCCESS must parse AND self-verify -- an
 * output the producer's own strict parser rejects, or a signature its own verifier rejects, is a round-trip
 * violation, and any non-PkiError throw is an unguarded invariant break; either is a finding, so it
 * propagates for jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var CA = signing.makeSigner("ec-p256", { ski: true });
var CA_ED = signing.makeSigner("ed25519");

var TU = new Date("2026-01-01T00:00:00Z");
var NU = new Date("2026-02-01T00:00:00Z");
var RD = new Date("2026-01-15T00:00:00Z");
var REASONS = ["keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "privilegeWithdrawn", "aACompromise"];

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  var flags = d.length ? d[0] : 0;
  var count = d.length > 1 ? (d[1] % 4) : 0;

  var revoked = [];
  for (var i = 0; i < count; i++) {
    var by = d.length > 2 + i ? d[2 + i] : i;
    var entry = { serialNumber: BigInt(1 + by), revocationDate: RD };
    if (flags & 1) entry.reason = REASONS[by % REASONS.length];
    if (flags & 2) entry.invalidityDate = new Date("2020-06-01T00:00:00Z");   // exercise the GeneralizedTime-only path
    revoked.push(entry);
  }

  var spec = { thisUpdate: TU, nextUpdate: (flags & 4) ? NU : null, revoked: revoked };
  if (flags & 8) spec.crlNumber = BigInt(1 + (d.length > 6 ? d[6] : 0));
  var exts = {};
  if (flags & 16) exts.authorityKeyIdentifier = true;
  if (flags & 32) exts.issuingDistributionPoint = { onlyContainsUserCerts: !!(flags & 64) };
  if (flags & 128) exts.deltaCRLIndicator = BigInt(1 + (d.length > 7 ? d[7] : 0));
  if (Object.keys(exts).length) spec.extensions = exts;

  var ca = (flags & 64) ? CA_ED : CA;

  var der;
  try {
    der = await pki.crl.sign(spec, { cert: ca.cert, key: ca.key });
  } catch (e) {
    if (isPki(e)) return;
    throw e;
  }
  // sign() succeeded: the CRL MUST round-trip through the strict parser AND verify under the issuer key.
  pki.schema.crl.parse(der);
  if ((await pki.crl.verify(der, { publicKey: ca.spki })) !== true) throw new Error("crl-sign fuzz: an emitted CRL failed self-verify under its issuer key");
};
