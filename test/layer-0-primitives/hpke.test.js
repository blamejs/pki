// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.hpke: RFC 9180 Hybrid Public Key Encryption.
 * Oracle: the CFRG RFC 9180 Appendix A known-answer vectors (test-vectors.json),
 * 128 vectors covering every classical DHKEM suite x KDF x AEAD x the four modes.
 * Each vector's fixed ephemeral drives setupS; the derived enc / shared_secret /
 * key / base_nonce / exporter_secret, every encryption (seq, aad, pt -> ct), and
 * every export (context, L -> value) must match byte-for-byte -- a single wrong
 * label byte / suite_id / I2OSP width fails these.
 */

var vectors = require("../fixtures/hpke/rfc9180-vectors.json");
var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;

function hx(s) { return Buffer.from(s || "", "hex"); }
function eq(a, b) { return Buffer.isBuffer(a) && a.toString("hex") === b; }

function testKat() {
  var fails = [], byMode = {}, n = 0;
  vectors.forEach(function (v) {
    var ids = { kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id };
    var mode = v.mode;
    var opts = {
      mode: mode, info: hx(v.info),
      psk: hx(v.psk), pskId: hx(v.psk_id),
      eph: { skm: hx(v.skEm), pkm: hx(v.pkEm) },
      senderKey: v.skSm ? { skm: hx(v.skSm), pkm: hx(v.pkSm) } : undefined,
    };
    var problems = [];
    try {
      var s = pki.hpke.setupS(ids, { pkm: hx(v.pkRm) }, opts);
      if (!eq(s.enc, v.enc)) problems.push("enc");
      if (!eq(s.sharedSecret, v.shared_secret)) problems.push("shared_secret");
      // Recipient side recovers the same context.
      var r = pki.hpke.setupR(ids, hx(v.enc), { skm: hx(v.skRm), pkm: hx(v.pkRm) },
        { mode: mode, info: hx(v.info), psk: hx(v.psk), pskId: hx(v.psk_id), senderPublicKey: v.pkSm ? { pkm: hx(v.pkSm) } : undefined });
      // Key-schedule outputs (exposed for the KAT via seal/open + export below).
      (v.encryptions || []).forEach(function (e) {
        var ct = s.context.seal(hx(e.aad), hx(e.pt));
        if (!eq(ct, e.ct)) problems.push("seal@seq" + s.context._seq);
        var pt = r.open(hx(e.aad), hx(e.ct));
        if (!eq(pt, e.pt)) problems.push("open");
      });
      (v.exports || []).forEach(function (x) {
        var val = s.context.export(hx(x.exporter_context), x.L);
        if (!eq(val, x.exported_value)) problems.push("export");
      });
    } catch (e) { problems.push("THREW:" + (e.code || e.message)); }
    var key = "mode" + mode + " kem" + v.kem_id.toString(16) + " kdf" + v.kdf_id + " aead" + v.aead_id;
    if (!byMode[key]) byMode[key] = 0;
    if (problems.length) { byMode[key]++; if (fails.length < 8) fails.push(key + ": " + problems.slice(0, 4).join(",")); }
    n++;
  });
  check("HPKE: all " + n + " RFC 9180 Appendix A vectors match" + (fails.length ? " -- " + fails.join("; ") : ""), fails.length === 0 && n === 128);
}

var S = pki.hpke.suites;
var IDS = { kem: S.KEM.DHKEM_X25519_HKDF_SHA256, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_256_GCM };
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testRobustness() {
  var kp = require("crypto").generateKeyPairSync("x25519");
  // Generated-key round-trip (the non-KAT path: fresh ephemeral).
  var o = pki.hpke.seal(IDS, kp.publicKey, {}, Buffer.from("aad"), Buffer.from("hello"));
  check("generated-key round-trip", pki.hpke.open(IDS, o.enc, kp.privateKey, {}, Buffer.from("aad"), o.ct).toString() === "hello");
  // A flipped ciphertext byte -> hpke/open-failed (no plaintext).
  var bad = Buffer.from(o.ct); bad[0] ^= 1;
  check("flipped ciphertext -> hpke/open-failed", codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, {}, Buffer.from("aad"), bad); }) === "hpke/open-failed");
  // Wrong AAD -> hpke/open-failed.
  check("wrong aad -> hpke/open-failed", codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, {}, Buffer.from("other"), o.ct); }) === "hpke/open-failed");
  // PSK inconsistency (RFC 9180 sec. 5.1): psk without psk_id, and a PSK in base mode.
  check("psk without psk_id -> hpke/inconsistent-psk", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { mode: S.MODE.PSK, psk: Buffer.from("0123456789abcdef0123456789abcdef") }); }) === "hpke/inconsistent-psk");
  check("psk in base mode -> hpke/inconsistent-psk", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { psk: Buffer.from("x"), pskId: Buffer.from("id") }); }) === "hpke/inconsistent-psk");
  check("psk mode without a psk -> hpke/inconsistent-psk", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { mode: S.MODE.PSK }); }) === "hpke/inconsistent-psk");
  // Unknown suite id -> hpke/unknown-suite (no default fall-through).
  check("unknown KEM id -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: 0x9999, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  // DHKEM(P-384) (0x0011) and HKDF-SHA384 (0x0002) are RFC 9180-registered but
  // Appendix A / the cited [TestVectors] file ship no known-answer vector, so
  // they are not offered: a request for either must fail closed, never run crypto
  // no test vector proves.
  check("P-384 KEM 0x0011 -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: 0x0011, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  check("HKDF-SHA384 KDF 0x0002 -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: IDS.kem, kdf: 0x0002, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  // An unknown mode must be rejected, not silently key-scheduled with a bad mode
  // byte (RFC 9180 sec. 5.1 defines exactly base / psk / auth / auth-psk).
  check("unknown mode (setupS) -> hpke/unknown-mode", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { mode: 7 }); }) === "hpke/unknown-mode");
  check("unknown mode (setupR) -> hpke/unknown-mode", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 0), kp.privateKey, { mode: 7 }); }) === "hpke/unknown-mode");
  // The serialized private-key form is { skm, pkm }; a bare buffer must fail
  // closed as a typed error, never a raw node createPublicKey throw.
  check("raw private-key buffer -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 0), Buffer.alloc(32), {}); }) === "hpke/bad-key");
  // Auth modes require the sender's key; its absence must be a clear typed error
  // (RFC 9180 sec. 5.1.3), never a raw throw out of the key-import path.
  check("auth setupS without senderKey -> hpke/auth-key-required", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { mode: S.MODE.AUTH }); }) === "hpke/auth-key-required");
  check("auth setupR without senderPublicKey -> hpke/auth-key-required", codeOf(function () { var o = pki.hpke.setupS(IDS, kp.publicKey, {}); return pki.hpke.setupR(IDS, o.enc, kp.privateKey, { mode: S.MODE.AUTH }); }) === "hpke/auth-key-required");
  // A missing / undefined recipient public key must fail closed as a typed error.
  check("undefined recipient public key -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(IDS, undefined, {}); }) === "hpke/bad-key");
  // A missing / non-object suiteIds must fail closed, not throw a raw TypeError.
  check("undefined suiteIds -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS(undefined, kp.publicKey, {}); }) === "hpke/unknown-suite");
  check("null suiteIds (setupR) -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupR(null, Buffer.alloc(32, 0), kp.privateKey, {}); }) === "hpke/unknown-suite");
  // A suiteIds missing a member (undefined code point) must report unknown-suite,
  // not crash the error path formatting an undefined id.
  check("suiteIds missing aead -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: IDS.kem, kdf: IDS.kdf }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  // export length must be a non-negative integer: a negative / fractional / NaN
  // length must fail closed, never silently return empty or throw raw.
  check("export negative length -> hpke/export-length", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, {}).context.export(Buffer.alloc(0), -1); }) === "hpke/export-length");
  check("export fractional length -> hpke/export-length", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, {}).context.export(Buffer.alloc(0), 1.5); }) === "hpke/export-length");
  // Role separation (RFC 9180 sec. 5.2): a sender and recipient derive the SAME
  // key + base_nonce, so a recipient must never seal (it would reuse the sender's
  // nonce) and a sender must never open. ContextS.seal / ContextR.open only.
  var sCtx = pki.hpke.setupS(IDS, kp.publicKey, {});
  var rCtx = pki.hpke.setupR(IDS, sCtx.enc, kp.privateKey, {});
  check("recipient context seal -> hpke/wrong-role", codeOf(function () { rCtx.seal(Buffer.alloc(0), Buffer.from("x")); }) === "hpke/wrong-role");
  check("sender context open -> hpke/wrong-role", codeOf(function () { sCtx.context.open(Buffer.alloc(0), Buffer.alloc(20)); }) === "hpke/wrong-role");
  // Export-only AEAD 0xFFFF: seal throws, export works.
  var exp = pki.hpke.setupS({ kem: IDS.kem, kdf: IDS.kdf, aead: S.AEAD.EXPORT_ONLY }, kp.publicKey, {});
  check("export-only seal -> hpke/export-only", codeOf(function () { exp.context.seal(Buffer.alloc(0), Buffer.from("x")); }) === "hpke/export-only");
  check("export-only export works", Buffer.isBuffer(exp.context.export(Buffer.from("ctx"), 32)) && exp.context.export(Buffer.from("ctx"), 32).length === 32);
  // Message limit (RFC 9180 sec. 5.2): a context at the max seq throws on the next seal.
  var ctx = pki.hpke.setupS(IDS, kp.publicKey, {}).context;
  ctx._seq = (1n << 96n) - 1n;
  check("seq overflow -> hpke/message-limit", codeOf(function () { ctx.seal(Buffer.alloc(0), Buffer.from("x")); }) === "hpke/message-limit");
  // A malformed encapsulated key (wrong length) -> hpke/bad-key.
  check("bad enc length -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(8), { skm: Buffer.alloc(32), pkm: Buffer.alloc(32) }, {}); }) === "hpke/bad-key");
  // A well-formed-length but low-order / invalid encapsulated point: the KEM
  // Diffie-Hellman fails during derivation. It must surface as a typed
  // hpke/bad-key, never a raw node ERR_OSSL_FAILED_DURING_DERIVATION escaping
  // the decap path (RFC 9180 sec. 4.1: Decap raises an error on DH failure).
  check("low-order enc point -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 0), kp.privateKey, {}); }) === "hpke/bad-key");
}

function testAdversarialBranches() {
  var crypto = require("crypto");
  var kp = crypto.generateKeyPairSync("x25519");
  var ecKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var P256 = { kem: S.KEM.DHKEM_P256_HKDF_SHA256, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM };
  // Fresh-ephemeral EC path (no injected eph): DHKEM(P-256) key generation +
  // SerializePublicKey (0x04 || x || y) + on-curve import must round-trip, so a
  // KeyObject recipient (public for setupS, private for setupR) also serializes.
  var ecOut = pki.hpke.seal(P256, ecKp.publicKey, {}, Buffer.from("aad"), Buffer.from("p256-msg"));
  check("P-256 fresh-ephemeral round-trip", pki.hpke.open(P256, ecOut.enc, ecKp.privateKey, {}, Buffer.from("aad"), ecOut.ct).toString() === "p256-msg");
  // A serialized EC public key of the right length but not an uncompressed 0x04
  // point must fail closed (RFC 9180 sec. 7.1.4), never be imported.
  check("P-256 non-0x04 point -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(P256, Buffer.alloc(65), {}); }) === "hpke/bad-key");
  // A 0x04-tagged EC point whose coordinates are not on the curve: node's key
  // import raises a raw error that must be surfaced as a typed hpke/bad-key.
  var offCurve = Buffer.alloc(65); offCurve[0] = 0x04;
  check("P-256 off-curve 0x04 point -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(P256, offCurve, {}); }) === "hpke/bad-key");
  // A serialized private key whose scalar is the wrong length yields malformed
  // PKCS#8 DER: node's createPrivateKey raises a raw error that must surface typed.
  check("short X25519 private scalar -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 0), { skm: Buffer.alloc(16), pkm: Buffer.alloc(32) }, {}); }) === "hpke/bad-key");
  // A non-buffer, non-{skm,pkm} value handed as the recipient private key must
  // fail closed as a typed error, never let node's createPublicKey throw raw.
  check("plain-object private key -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 0), {}, {}); }) === "hpke/bad-key");
  // ...and likewise for a non-buffer, non-{pkm} recipient public key.
  check("plain-object public key -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(IDS, {}, {}); }) === "hpke/bad-key");
  // Export length is bounded by RFC 5869 (255*Nh); a request past it fails closed
  // BEFORE any allocation, never truncates or returns short output. Nh=32 (SHA256).
  var ctxE = pki.hpke.setupS(IDS, kp.publicKey, {}).context;
  check("export length > 255*Nh -> hpke/export-length", codeOf(function () { ctxE.export(Buffer.alloc(0), 255 * 32 + 1); }) === "hpke/export-length");
  // A RECIPIENT context for an export-only AEAD must refuse open (role check first,
  // then export-only): the export-only guard must hold on the recipient side too.
  var expIds = { kem: IDS.kem, kdf: IDS.kdf, aead: S.AEAD.EXPORT_ONLY };
  var exS = pki.hpke.setupS(expIds, kp.publicKey, {});
  var exR = pki.hpke.setupR(expIds, exS.enc, kp.privateKey, {});
  check("export-only recipient open -> hpke/export-only", codeOf(function () { exR.open(Buffer.alloc(0), Buffer.alloc(20)); }) === "hpke/export-only");
  // A ciphertext shorter than the AEAD tag on a recipient context must fail closed
  // as hpke/open-failed, never index a negative-length tag subarray.
  var sc = pki.hpke.setupS(IDS, kp.publicKey, {});
  var rc = pki.hpke.setupR(IDS, sc.enc, kp.privateKey, {});
  check("recipient open ct shorter than tag -> hpke/open-failed", codeOf(function () { rc.open(Buffer.alloc(0), Buffer.alloc(5)); }) === "hpke/open-failed");
  // A node KeyObject on the WRONG curve for the suite (an X25519 key handed to a
  // P-256 suite): its JWK export lacks the coordinate the suite's
  // SerializePublicKey requires (an OKP key has no EC y), so the coordinate guard
  // raises a typed error. That HpkeError must be surfaced unchanged as
  // hpke/bad-key, never swallowed or re-wrapped as a raw node error.
  check("setupS curve-mismatched public KeyObject -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(P256, kp.publicKey, {}); }) === "hpke/bad-key");
  check("setupR curve-mismatched private KeyObject -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(P256, Buffer.alloc(65), kp.privateKey, {}); }) === "hpke/bad-key");
  // opts is optional (RFC 9180 base mode needs no info/psk/senderKey): omitting the
  // argument entirely on both setup calls must default cleanly and still round-trip.
  var sNo = pki.hpke.setupS(IDS, kp.publicKey);
  var rNo = pki.hpke.setupR(IDS, sNo.enc, kp.privateKey);
  check("setupS/setupR with opts omitted round-trip", rNo.open(Buffer.alloc(0), sNo.context.seal(Buffer.alloc(0), Buffer.from("no-opts"))).toString() === "no-opts");
}

function run() {
  testKat();
  testRobustness();
  testAdversarialBranches();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
