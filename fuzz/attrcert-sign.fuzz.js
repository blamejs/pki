// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 5755 attribute-certificate issuance via pki.attrcert.sign.
 *
 * The hostile surface is the ENCODER over an arbitrary certificate spec: pki.attrcert.sign must, for ANY
 * derived spec (holder form, requested attributes, extensions, AA signer arm), EITHER throw a typed
 * pki.errors.PkiError OR produce an attribute certificate that round-trips through the strict
 * pki.schema.attrcert.parse decoder. The fuzz bytes drive the holder form, the entity/subject name
 * (sanitized to printable ASCII so the DN charset -- a separate guard -- is not under test), the
 * attribute/extension toggles, and the AA signer arm. Signer keys are built once.
 *
 * Contract: a sign() failure must be a PkiError, and a sign() SUCCESS must parse -- an output the
 * producer's own strict parser rejects is a round-trip violation, and any non-PkiError throw is an
 * unguarded invariant break; either is a finding, so it propagates for jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var AA = signing.makeSigner("ec-p256");
var AA_ED = signing.makeSigner("ed25519");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  var flags = d.length ? d[0] : 0;
  var name = (d.length > 1 ? d.slice(1, Math.min(d.length, 33)).toString("latin1").replace(/[^\x20-\x7e]/g, "?") : "") || "Alice";

  var holder;
  switch (flags & 3) {
    case 0: holder = { entityName: { directoryName: "CN=" + name.replace(/[^A-Za-z0-9 ]/g, "x") } }; break;
    case 1: holder = { entityName: [{ dNSName: (name.replace(/[^A-Za-z0-9.-]/g, "x") || "h.example") }] }; break;
    case 2: holder = { baseCertificateID: { issuer: [{ directoryName: "CN=CA" }], serial: 42n } }; break;
    default: holder = { objectDigestInfo: { digestedObjectType: "publicKey", digestAlgorithm: "sha256", objectDigest: Buffer.alloc(32, flags) } }; break;
  }
  var attributes = {};
  if (flags & 4) attributes.role = { roleName: { uniformResourceIdentifier: "urn:role:" + (name.replace(/[^A-Za-z0-9]/g, "") || "x") } };
  if (flags & 8) attributes.clearance = { policyId: "2.5.29.32.0", classList: (flags & 16) ? ["secret"] : ["unclassified"] };
  if (!attributes.role && !attributes.clearance) attributes.role = { roleName: { uniformResourceIdentifier: "urn:role:default" } };
  var spec = { holder: holder, notBeforeTime: NB, notAfterTime: NA, attributes: attributes };
  if (flags & 32) spec.extensions = { noRevAvail: true, authorityKeyIdentifier: true };
  var aa = (flags & 64) ? AA_ED : AA;

  var der;
  try {
    der = await pki.attrcert.sign(spec, { name: "CN=Example AA", publicKey: aa.spki, key: aa.key });
  } catch (e) {
    if (isPki(e)) return;
    throw e;
  }
  // sign() succeeded: the attribute certificate MUST round-trip through the strict parser (any throw is a finding).
  pki.schema.attrcert.parse(der);
};
