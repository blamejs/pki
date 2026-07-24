// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- CMS AuthenticatedData (pki.cms.authenticate) cross-implementation interop.
 *
 * OpenSSL's `cms` CLI has NO id-ct-authData (AuthenticatedData) produce or verify operation, so -- as
 * with the v0.3.13 countersignature Gate B -- the oracle is an INDEPENDENT HMAC recompute, not
 * `openssl cms`. For each HMAC-SHA-2 hash x { authenticated-attributes present, absent }:
 *   (a) recover the fresh MAC key by AES-KW-unwrapping a KEKRI recipient under the test KEK;
 *   (b) `openssl dgst -mac HMAC` over the EXACT sec. 9.2 preimage (the [2]->0x31 re-tagged authAttrs,
 *       or the raw eContent value octets) equals the transmitted `mac`;
 *   (c) pki.cms.decrypt verifies the MAC and returns the content with authenticated:true.
 * Negatives (independent): a flipped content byte -> our verify fails closed; a structural
 * `openssl asn1parse` confirms the ContentInfo / id-ct-authData framing.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var nodeCrypto = require("node:crypto");
var subtle = nodeCrypto.webcrypto.subtle;

var MSG = Buffer.from("CMS AuthenticatedData interop content -- MAC me");
var HASH_WC = { "hmac-sha256": "SHA-256", "hmac-sha384": "SHA-384", "hmac-sha512": "SHA-512" };
var HASH_SSL = { "hmac-sha256": "sha256", "hmac-sha384": "sha384", "hmac-sha512": "sha512" };

async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function preimageOf(parsed) {
  if (parsed.authAttrsBytes) { var r = Buffer.from(parsed.authAttrsBytes); r[0] = 0x31; return r; }
  return Buffer.from(parsed.encapContentInfo.eContent);
}
async function recoverMacKey(parsed, kek, mac) {
  var ek = parsed.recipientInfos[0].encryptedKey;
  var kk = await subtle.importKey("raw", kek, { name: "AES-KW" }, false, ["unwrapKey"]);
  var mk = await subtle.unwrapKey("raw", ek, kk, { name: "AES-KW" }, { name: "HMAC", hash: { name: HASH_WC[mac] } }, true, ["sign"]);
  return Buffer.from(await subtle.exportKey("raw", mk));
}
function opensslHmac(mac, keyHex, preimage) {
  var pre = ctx.tmpFile(preimage, "preimage.bin");
  try {
    var out = ctx.runOpenssl(["dgst", "-" + HASH_SSL[mac], "-mac", "HMAC", "-macopt", "hexkey:" + keyHex, pre], { allowNonZero: true });
    var m = /=\s*([0-9a-fA-F]+)\s*$/.exec(out.stdout || "");
    return m ? m[1].toLowerCase() : null;
  } finally { try { ctx.fs.unlinkSync(pre); } catch (_e) { /* best-effort */ } }
}

async function run() {
  var kek = Buffer.alloc(32, 0x5c);
  var hashes = ["hmac-sha256", "hmac-sha384", "hmac-sha512"];
  for (var h = 0; h < hashes.length; h++) {
    var mac = hashes[h];
    for (var mode = 0; mode < 2; mode++) {
      var present = mode === 0;
      var out = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], present ? { macAlgorithm: mac } : { macAlgorithm: mac, authenticatedAttributes: false });
      var parsed = pki.schema.cms.parse(out);
      var macKey = await recoverMacKey(parsed, kek, mac);
      var hex = opensslHmac(mac, macKey.toString("hex"), preimageOf(parsed));
      check("openssl HMAC " + mac + " (" + (present ? "attrs" : "bare") + ") == the transmitted mac", hex != null && hex === Buffer.from(parsed.mac).toString("hex"));
      var d = await pki.cms.decrypt(out, { kek: kek });
      check("decrypt " + mac + " (" + (present ? "attrs" : "bare") + ") -> authenticated + content", d.authenticated === true && Buffer.compare(d.content, MSG) === 0);
    }
  }
  // NEGATIVE: a flipped content byte -> the message-digest recompute fails, uniform verdict.
  var base = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], {});
  var flipped = Buffer.from(base); var idx = flipped.indexOf(MSG); flipped[idx] ^= 0xff;
  check("a flipped content byte -> our verify cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(flipped, { kek: kek }); })) === "cms/decrypt-failed");
  // STRUCTURAL: openssl asn1parse confirms the ContentInfo / id-ct-authData framing.
  var ap = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", ctx.tmpFile(base, "auth.der")], { allowNonZero: true });
  check("openssl asn1parse parses our AuthenticatedData structure", ap.code === 0);
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
