// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Rebuild a PKIMessage pki.cmp.build produced with its header changed and the protection recomputed.
// pki.cmp.build fills a transactionID and a senderNonce it was not given and refuses a senderNonce
// under 128 bits, so a vector that needs a message WITHOUT one of them, or with a short one, is
// assembled here: the header's [4] transactionID and [5] senderNonce are dropped or replaced, and the
// protection is recomputed over the new ProtectedPart with the same key material the builder used.

var helpers = require("./index");
var pki = helpers.pki;
var asn1 = pki.asn1;
var b = asn1.build;
var pbes2 = require("../../lib/pbes2");
var cmpBuild = require("../../lib/cmp-build");
var signScheme = require("../../lib/sign-scheme");
var frameworkError = require("../../lib/framework-error");

var TXN_TAG = 4, NONCE_TAG = 5;

function _signE(kind, message, cause) { return new frameworkError.CmpError("cmp/" + kind, message, cause); }

// edit: { transactionID?: Buffer|null, senderNonce?: Buffer|null } -- a present key replaces the field
// (null removes it); an absent key leaves it as built.
function _editHeader(headerNode, edit) {
  var kids = [], byTag = Object.create(null);
  headerNode.children.forEach(function (c, i) {
    if (i < 3) { kids.push(b.raw(c.bytes)); return; }
    byTag[c.tagNumber] = c;
  });
  var replacements = Object.create(null);
  if (edit && Object.prototype.hasOwnProperty.call(edit, "transactionID")) replacements[TXN_TAG] = edit.transactionID;
  if (edit && Object.prototype.hasOwnProperty.call(edit, "senderNonce")) replacements[NONCE_TAG] = edit.senderNonce;
  for (var tag = 0; tag <= 8; tag++) {
    if (Object.prototype.hasOwnProperty.call(replacements, tag)) {
      if (replacements[tag] != null) kids.push(b.explicit(tag, b.octetString(replacements[tag])));
      continue;
    }
    if (byTag[tag]) kids.push(b.raw(byTag[tag].bytes));
  }
  return b.sequence(kids);
}

// protection: { key, cert, pss?, digestAlgorithm? } (signature) | { mac: { secret, salt, iterationCount, prf?, keyLength? } }
//           | { kem: { sharedSecret, transactionID?, kemContext?, len? } }
async function _protectionBits(protection, protectedPartDer) {
  if (protection.mac) {
    var m = protection.mac, prf = m.prf || "SHA-256";
    var mac = await pbes2.pbmac1(Buffer.isBuffer(m.secret) ? m.secret : Buffer.from(m.secret, "utf8"), m.salt, m.iterationCount, m.keyLength || 32, prf, prf, protectedPartDer);
    return b.bitString(mac, 0);
  }
  if (protection.kem) {
    var k = protection.kem;
    var shared = await cmpBuild.kemSharedKey(k.sharedSecret, k.len || 32, k.transactionID, k.kemContext || null);
    return b.bitString(await cmpBuild.kemMac(shared, protectedPartDer), 0);
  }
  var scheme = signScheme.resolveSignScheme(pki.schema.x509.parse(protection.cert), { combinedRsaSig: true, pss: protection.pss, digestAlgorithm: protection.digestAlgorithm }, true, _signE);
  var sig = await signScheme.signOverTbs(scheme, protection.key, protectedPartDer, _signE);
  return b.bitString(sig, 0);
}

async function reprotect(der, edit, protection) {
  var root = asn1.decode(der);
  var headerNode = root.children[0], bodyNode = root.children[1];
  var extraCerts = root.children.length > 3 ? root.children[3] : null;
  var newHeader = _editHeader(headerNode, edit);
  var protectedPart = b.sequence([b.raw(newHeader), b.raw(bodyNode.bytes)]);
  var bits = await _protectionBits(protection, protectedPart);
  var kids = [b.raw(newHeader), b.raw(bodyNode.bytes), b.explicit(0, bits)];
  if (extraCerts) kids.push(b.raw(extraCerts.bytes));
  return b.sequence(kids);
}

module.exports = { reprotect: reprotect };
