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
  // Every setup option narrows or authenticates. A misspelled `psk` leaves a psk-mode setup with no
  // pre-shared key and a misspelled `senderKey` leaves an auth-mode setup unauthenticated -- and
  // both then fail naming the field the caller believes they supplied, which is the least useful
  // thing to be told.
  check("an unknown seal option -> hpke/bad-input",
    codeOf(function () { pki.hpke.seal(IDS, kp.publicKey, { psks: Buffer.alloc(32) }, Buffer.alloc(0), Buffer.alloc(1)); }) === "hpke/bad-input");
  check("an unknown open option -> hpke/bad-input",
    codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, { senderPubKey: kp.publicKey }, Buffer.from("aad"), o.ct); }) === "hpke/bad-input");
  // The two ends read the same object from OPPOSITE sides, so each has its own table rather than
  // their union. A union recognizes every name at both ends and therefore accepts the one that can
  // do nothing where it was passed -- silently, which is the failure these tables exist to remove.
  // Handing the sender the recipient's option is usually a misdirected auth-mode setup: the caller
  // believes they authenticated, and a union would let them believe it.
  check("the RECIPIENT's senderPublicKey is refused at the sender end, not ignored",
    codeOf(function () { pki.hpke.seal(IDS, kp.publicKey, { mode: S.MODE.AUTH, senderPublicKey: kp.publicKey }, Buffer.alloc(0), Buffer.alloc(1)); }) === "hpke/bad-input");
  check("the SENDER's senderKey is refused at the recipient end, not ignored",
    codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, { senderKey: kp.privateKey }, Buffer.from("aad"), o.ct); }) === "hpke/bad-input");
  check("...and so is the sender-only test-vector seam `eph`",
    codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, { eph: kp }, Buffer.from("aad"), o.ct); }) === "hpke/bad-input");
  // An option that belongs to THIS end but to another mode is refused too, never left unused:
  // a senderKey in base mode is a caller who believes the exchange is authenticated.
  check("senderKey in base mode -> hpke/bad-input",
    codeOf(function () { pki.hpke.seal(IDS, kp.publicKey, { senderKey: kp.privateKey }, Buffer.alloc(0), Buffer.alloc(1)); }) === "hpke/bad-input");
  check("senderKey in psk mode -> hpke/bad-input",
    codeOf(function () { pki.hpke.seal(IDS, kp.publicKey, { mode: S.MODE.PSK, psk: Buffer.alloc(32, 1), pskId: Buffer.from("id"), senderKey: kp.privateKey }, Buffer.alloc(0), Buffer.alloc(1)); }) === "hpke/bad-input");
  check("senderPublicKey in base mode -> hpke/bad-input",
    codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, { senderPublicKey: kp.publicKey }, Buffer.from("aad"), o.ct); }) === "hpke/bad-input");
  check("senderKey: undefined and senderPublicKey: null in base mode are absent", (function () {
    var a = pki.hpke.setupS(IDS, kp.publicKey, { senderKey: undefined });
    var c = a.context.seal(Buffer.alloc(0), Buffer.from("absent"));
    return pki.hpke.setupR(IDS, a.enc, kp.privateKey, { senderPublicKey: null }).open(Buffer.alloc(0), c).toString() === "absent";
  })());
  // eph is { skm, pkm } or absent (undefined / null); a falsy junk value is not "absent".
  check("eph: 0 -> hpke/bad-input", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { eph: 0 }); }) === "hpke/bad-input");
  check("eph: \"\" -> hpke/bad-input", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { eph: "" }); }) === "hpke/bad-input");
  check("eph: null is absent (a fresh ephemeral is generated)", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { eph: null }); }) === "NO-THROW");
  // The message says where the option belongs, because "unknown option" about a real option name a
  // caller read in these docs is the least useful way to say it.
  var misdirected = (function () {
    try { pki.hpke.seal(IDS, kp.publicKey, { senderPublicKey: kp.publicKey }, Buffer.alloc(0), Buffer.alloc(1)); return ""; }
    catch (e) { return e.message; }
  })();
  check("...and the refusal says the option belongs to the other end",
    misdirected.indexOf("other end of the exchange") > 0);
  // Wrong AAD -> hpke/open-failed.
  check("wrong aad -> hpke/open-failed", codeOf(function () { pki.hpke.open(IDS, o.enc, kp.privateKey, {}, Buffer.from("other"), o.ct); }) === "hpke/open-failed");
  // PSK inconsistency (RFC 9180 sec. 5.1): psk without psk_id, and a PSK in base mode.
  check("psk without psk_id -> hpke/inconsistent-psk", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { mode: S.MODE.PSK, psk: Buffer.from("0123456789abcdef0123456789abcdef") }); }) === "hpke/inconsistent-psk");
  check("psk in base mode -> hpke/inconsistent-psk", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { psk: Buffer.from("x"), pskId: Buffer.from("id") }); }) === "hpke/inconsistent-psk");
  check("psk mode without a psk -> hpke/inconsistent-psk", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, { mode: S.MODE.PSK }); }) === "hpke/inconsistent-psk");
  // Unknown suite id -> hpke/unknown-suite (no default fall-through).
  check("unknown KEM id -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: 0x9999, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  check("unknown KDF id -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: IDS.kem, kdf: 0x9999, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  // DHKEM(P-384) (0x0011) is RFC 9180-registered but no known-answer vector pairs it
  // with an HKDF key schedule (draft-ietf-hpke-pq-05 A.8 runs it under the SHAKE256
  // KDF of the HPKE revision), so it is not offered: a request must fail closed,
  // never run crypto no test vector proves. HKDF-SHA384 (0x0002) IS offered: A.3
  // is its KAT (testMlKemKat), so a DHKEM suite may select it too.
  check("P-384 KEM 0x0011 -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: 0x0011, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  var sha384 = { kem: IDS.kem, kdf: S.KDF.HKDF_SHA384, aead: S.AEAD.AES_128_GCM };
  var o384 = pki.hpke.seal(sha384, kp.publicKey, {}, Buffer.from("aad"), Buffer.from("sha384"));
  check("HKDF-SHA384 KDF 0x0002 round-trips on a DHKEM suite", S.KDF.HKDF_SHA384 === 0x0002 &&
    pki.hpke.open(sha384, o384.enc, kp.privateKey, {}, Buffer.from("aad"), o384.ct).toString() === "sha384");
  // The PQ/T hybrid KEMs of draft-ietf-hpke-pq-05 sec. 4 are defined by moving CFRG
  // drafts; their code points must fail closed rather than run an unproven combiner.
  [0x0050, 0x0051, 0x647a].forEach(function (id) {
    check("hybrid KEM 0x" + id.toString(16) + " -> hpke/unknown-suite", codeOf(function () { pki.hpke.setupS({ kem: id, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM }, kp.publicKey, {}); }) === "hpke/unknown-suite");
  });
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
  check("null private key -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 0), null, {}); }) === "hpke/bad-key");
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

var pqVectors = require("../fixtures/hpke/draft-hpke-pq-05-vectors.json");
var ML768 = { kem: S.KEM.ML_KEM_768, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM };

function testMlKemKat() {
  // draft-ietf-hpke-pq-05 Appendix A.1 / A.2 / A.3 (ML-KEM-512 / -768 / -1024). The recipient
  // side is a complete known answer: the vector's enc decapsulated under its 64-byte seed, the
  // key schedule, all ten opens and all five exports. node:crypto takes no encapsulation
  // randomness, so the sender side is proven by round trip against the same seed.
  var fails = [], n = 0;
  pqVectors.forEach(function (v) {
    var ids = { kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id };
    var problems = [];
    try {
      var r = pki.hpke.setupR(ids, hx(v.enc), { skm: hx(v.skRm), pkm: hx(v.pkRm) }, { info: hx(v.info) });
      v.encryptions.forEach(function (e) { if (!eq(r.open(hx(e.aad), hx(e.ct)), e.pt)) problems.push("open@" + e.seq); });
      v.exports.forEach(function (x) { if (!eq(r.export(hx(x.exporter_context), x.L), x.exported_value)) problems.push("export"); });
      var s = pki.hpke.setupS(ids, hx(v.pkRm), { info: hx(v.info) });
      if (s.enc.length !== hx(v.enc).length) problems.push("enc-length");
      if (s.sharedSecret.length !== 32) problems.push("Nsecret");
      // pkm is optional for an ML-KEM recipient: the seed alone determines the encapsulation key.
      var r2 = pki.hpke.setupR(ids, s.enc, { skm: hx(v.skRm) }, { info: hx(v.info) });
      if (r2.open(Buffer.from("a"), s.context.seal(Buffer.from("a"), Buffer.from("pq"))).toString() !== "pq") problems.push("round-trip");
    } catch (e) { problems.push("THREW:" + (e.code || e.message)); }
    if (problems.length) fails.push(v.section + ": " + problems.slice(0, 4).join(","));
    n++;
  });
  check("HPKE ML-KEM: all " + n + " draft-ietf-hpke-pq-05 Appendix A pure-ML-KEM vectors match" + (fails.length ? " -- " + fails.join("; ") : ""), fails.length === 0 && n === 3);
  check("the ML-KEM code points are the IANA ones", S.KEM.ML_KEM_512 === 0x0040 && S.KEM.ML_KEM_768 === 0x0041 && S.KEM.ML_KEM_1024 === 0x0042);
}

function testMlKemRobustness() {
  var crypto = require("crypto");
  var v = pqVectors[1], pkRm = hx(v.pkRm), skRm = hx(v.skRm);
  var kp = crypto.generateKeyPairSync("ml-kem-768"), kp512 = crypto.generateKeyPairSync("ml-kem-512");
  var x = crypto.generateKeyPairSync("x25519");
  var A = Buffer.from("aad"), M = Buffer.from("ml-kem");
  function roundTrip(ids, pk, sk, opts) {
    var o = pki.hpke.seal(ids, pk, opts || {}, A, M);
    return pki.hpke.open(ids, o.enc, sk, opts || {}, A, o.ct).toString() === "ml-kem";
  }
  // Every recipient shape: a public KeyObject, a private KeyObject (its public half is taken),
  // { pkm }, and the raw encapsulation key; { skm } with and without pkm, and a private KeyObject.
  check("ML-KEM-768 round trip: public KeyObject -> private KeyObject", roundTrip(ML768, kp.publicKey, kp.privateKey));
  check("ML-KEM-768 round trip: private KeyObject as the recipient public key", roundTrip(ML768, kp.privateKey, kp.privateKey));
  check("ML-KEM-768 round trip: { pkm } -> { skm, pkm }", roundTrip(ML768, { pkm: pkRm }, { skm: skRm, pkm: pkRm }));
  check("ML-KEM-768 round trip: raw pk -> { skm }", roundTrip(ML768, pkRm, { skm: skRm }));
  // The mode and KDF/AEAD axes are not single-config on the new KEM.
  var psk = { mode: S.MODE.PSK, psk: Buffer.from("0123456789abcdef0123456789abcdef"), pskId: Buffer.from("id") };
  check("ML-KEM-768 psk mode round trip", roundTrip(ML768, pkRm, { skm: skRm }, psk));
  var ml1024 = { kem: S.KEM.ML_KEM_1024, kdf: S.KDF.HKDF_SHA512, aead: S.AEAD.CHACHA20_POLY1305 };
  check("ML-KEM-1024 / HKDF-SHA512 / ChaCha20Poly1305 round trip", roundTrip(ml1024, hx(pqVectors[2].pkRm), { skm: hx(pqVectors[2].skRm) }));
  var exportOnly = { kem: S.KEM.ML_KEM_512, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.EXPORT_ONLY };
  var exS = pki.hpke.setupS(exportOnly, hx(pqVectors[0].pkRm), {});
  var exR = pki.hpke.setupR(exportOnly, exS.enc, { skm: hx(pqVectors[0].skRm) }, {});
  check("ML-KEM-512 export-only: both ends export the same secret", exS.context.export(Buffer.from("c"), 48).equals(exR.export(Buffer.from("c"), 48)));
  // draft-ietf-hpke-pq-05 sec. 7.2: the ML-KEM KEMs define no AuthEncap / AuthDecap. Both
  // ends refuse the auth modes BEFORE asking for the key the mode would need, so the caller
  // learns the mode is unavailable rather than that a key is missing.
  check("auth setupS on ML-KEM -> hpke/auth-unsupported", codeOf(function () { pki.hpke.setupS(ML768, pkRm, { mode: S.MODE.AUTH }); }) === "hpke/auth-unsupported");
  check("auth-psk setupS on ML-KEM -> hpke/auth-unsupported", codeOf(function () { pki.hpke.setupS(ML768, pkRm, { mode: S.MODE.AUTH_PSK, senderKey: kp.privateKey }); }) === "hpke/auth-unsupported");
  var o = pki.hpke.setupS(ML768, pkRm, {});
  check("auth setupR on ML-KEM -> hpke/auth-unsupported", codeOf(function () { pki.hpke.setupR(ML768, o.enc, { skm: skRm }, { mode: S.MODE.AUTH }); }) === "hpke/auth-unsupported");
  check("auth-psk setupR on ML-KEM -> hpke/auth-unsupported", codeOf(function () { pki.hpke.setupR(ML768, o.enc, { skm: skRm }, { mode: S.MODE.AUTH_PSK, senderPublicKey: kp.publicKey }); }) === "hpke/auth-unsupported");
  // There is no fixed-ephemeral ML-KEM encapsulation: an `eph` on an ML-KEM suite is refused,
  // never ignored, so a caller cannot believe a vector drove the sender when the runtime did.
  check("eph on an ML-KEM suite -> hpke/bad-input", codeOf(function () { pki.hpke.setupS(ML768, pkRm, { eph: { skm: skRm, pkm: pkRm } }); }) === "hpke/bad-input");
  check("eph: 0 on an ML-KEM suite -> hpke/bad-input", codeOf(function () { pki.hpke.setupS(ML768, pkRm, { eph: 0 }); }) === "hpke/bad-input");
  check("eph: null on an ML-KEM suite is absent", codeOf(function () { pki.hpke.setupS(ML768, pkRm, { eph: null }); }) === "NO-THROW");
  // Encapsulation-key checks (FIPS 203 sec. 7.2): the length, the modulus (a coefficient equal
  // to q is not canonical), and a key of another parameter set.
  check("pkRm one byte short -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(ML768, pkRm.subarray(1), {}); }) === "hpke/bad-key");
  var q = Buffer.from(pkRm); q[0] = 0x01; q[1] = (q[1] & 0xf0) | 0x0d;
  check("pkRm with a coefficient equal to q -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(ML768, q, {}); }) === "hpke/bad-key");
  var qm1 = Buffer.from(pkRm); qm1[0] = 0x00; qm1[1] = (qm1[1] & 0xf0) | 0x0d;
  check("...while a coefficient of q-1 is canonical and accepted", codeOf(function () { pki.hpke.setupS(ML768, qm1, {}); }) === "NO-THROW");
  check("an ML-KEM-512 key under the ML-KEM-768 suite -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(ML768, hx(pqVectors[0].pkRm), {}); }) === "hpke/bad-key");
  check("an ML-KEM-512 KeyObject under the ML-KEM-768 suite -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(ML768, kp512.publicKey, {}); }) === "hpke/bad-key");
  check("an ML-KEM-512 private KeyObject under the ML-KEM-768 suite -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc, kp512.privateKey, {}); }) === "hpke/bad-key");
  check("an X25519 KeyObject under an ML-KEM suite (sender) -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(ML768, x.publicKey, {}); }) === "hpke/bad-key");
  check("an X25519 KeyObject under an ML-KEM suite (recipient) -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc, x.privateKey, {}); }) === "hpke/bad-key");
  check("an ML-KEM KeyObject under a DHKEM suite (sender) -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, {}); }) === "hpke/bad-key");
  check("an ML-KEM KeyObject under a DHKEM suite (recipient) -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, Buffer.alloc(32, 1), kp.privateKey, {}); }) === "hpke/bad-key");
  // Ciphertext check (FIPS 203 sec. 7.3): the length is refused typed; a right-length garbage
  // ciphertext is implicitly rejected into a wrong secret and the AEAD then refuses.
  check("enc one byte short -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc.subarray(1), { skm: skRm }, {}); }) === "hpke/bad-key");
  check("enc one byte long -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, Buffer.concat([o.enc, Buffer.alloc(1)]), { skm: skRm }, {}); }) === "hpke/bad-key");
  var ct = o.context.seal(A, M);
  check("right-length garbage enc -> hpke/open-failed", codeOf(function () { pki.hpke.open(ML768, Buffer.alloc(o.enc.length, 7), { skm: skRm }, {}, A, ct); }) === "hpke/open-failed");
  check("a flipped ML-KEM ciphertext byte -> hpke/open-failed", codeOf(function () { var bad = Buffer.from(o.enc); bad[100] ^= 1; pki.hpke.open(ML768, bad, { skm: skRm }, {}, A, ct); }) === "hpke/open-failed");
  // Seed checks: exactly 64 bytes, as a Buffer, inside { skm }.
  check("skm of 63 bytes -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc, { skm: skRm.subarray(1) }, {}); }) === "hpke/bad-key");
  check("skm of 65 bytes -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc, { skm: Buffer.concat([skRm, Buffer.alloc(1)]) }, {}); }) === "hpke/bad-key");
  check("skm as a hex string -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc, { skm: v.skRm }, {}); }) === "hpke/bad-key");
  var otherPk = kp.publicKey.export({ format: "der", type: "spki" }).subarray(-pkRm.length);
  check("{ skm, pkm } with another ML-KEM-768 encapsulation key -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(ML768, o.enc, { skm: skRm, pkm: otherPk }, {}); }) === "hpke/bad-key");
  var bare = (function () { try { pki.hpke.setupR(ML768, o.enc, skRm, {}); return ""; } catch (e) { return e.code + " " + e.message; } })();
  check("a bare seed buffer -> hpke/bad-key naming the { skm } seed shape", bare.indexOf("hpke/bad-key") === 0 && bare.indexOf("seed") > 0);
}

function testSerializedPrivateKeyDoor() {
  // { skm, pkm } is one door for every KEM: skm is the scalar or seed of exactly Nsk bytes, the
  // public key is derived from it, and a supplied pkm must be that key. Before this door a DHKEM
  // recipient given { skm } alone escaped as a raw TypeError, and a wrong-length or foreign pkm
  // was fed straight into kem_context, keying a context that could open nothing.
  var crypto = require("crypto");
  var x = crypto.generateKeyPairSync("x25519"), x2 = crypto.generateKeyPairSync("x25519");
  var skm = Buffer.from(x.privateKey.export({ format: "jwk" }).d, "base64url");
  var pkm = Buffer.from(x.publicKey.export({ format: "jwk" }).x, "base64url");
  var pkm2 = Buffer.from(x2.publicKey.export({ format: "jwk" }).x, "base64url");
  var o = pki.hpke.setupS(IDS, pkm, {});
  var ct = o.context.seal(Buffer.alloc(0), Buffer.from("door"));
  check("X25519 { skm } without pkm derives the public key and opens", pki.hpke.setupR(IDS, o.enc, { skm: skm }, {}).open(Buffer.alloc(0), ct).toString() === "door");
  check("X25519 { skm, pkm } of another key -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, o.enc, { skm: skm, pkm: pkm2 }, {}); }) === "hpke/bad-key");
  check("X25519 { skm, pkm } with a 31-byte pkm -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, o.enc, { skm: skm, pkm: pkm.subarray(1) }, {}); }) === "hpke/bad-key");
  check("X25519 skm of 33 bytes -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(IDS, o.enc, { skm: Buffer.concat([skm, Buffer.alloc(1)]), pkm: pkm }, {}); }) === "hpke/bad-key");
  var ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }), ec2 = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var P256 = { kem: S.KEM.DHKEM_P256_HKDF_SHA256, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_128_GCM };
  var ecJwk = ec.privateKey.export({ format: "jwk" }), ec2Jwk = ec2.publicKey.export({ format: "jwk" });
  var d = Buffer.from(ecJwk.d, "base64url");
  var point = Buffer.concat([Buffer.from([4]), Buffer.from(ecJwk.x, "base64url"), Buffer.from(ecJwk.y, "base64url")]);
  var point2 = Buffer.concat([Buffer.from([4]), Buffer.from(ec2Jwk.x, "base64url"), Buffer.from(ec2Jwk.y, "base64url")]);
  var oe = pki.hpke.setupS(P256, point, {});
  var cte = oe.context.seal(Buffer.alloc(0), Buffer.from("p256"));
  check("P-256 { skm } without pkm derives the public point and opens", pki.hpke.setupR(P256, oe.enc, { skm: d }, {}).open(Buffer.alloc(0), cte).toString() === "p256");
  check("P-256 { skm, pkm } of another key -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(P256, oe.enc, { skm: d, pkm: point2 }, {}); }) === "hpke/bad-key");
  // The same door guards the sender-side seams: the fixed ephemeral and the auth-mode sender key.
  check("eph { skm, pkm } of another key -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(IDS, pkm, { eph: { skm: skm, pkm: pkm2 } }); }) === "hpke/bad-key");
  check("senderKey { skm, pkm } of another key -> hpke/bad-key", codeOf(function () { pki.hpke.setupS(IDS, pkm, { mode: S.MODE.AUTH, senderKey: { skm: skm, pkm: pkm2 } }); }) === "hpke/bad-key");
  check("senderKey { skm } alone authenticates", (function () {
    var a = pki.hpke.setupS(IDS, pkm, { mode: S.MODE.AUTH, senderKey: { skm: skm } });
    var c = a.context.seal(Buffer.alloc(0), Buffer.from("auth"));
    return pki.hpke.setupR(IDS, a.enc, { skm: skm }, { mode: S.MODE.AUTH, senderPublicKey: pkm }).open(Buffer.alloc(0), c).toString() === "auth";
  })());
  // An EC scalar is a key only in [1, n-1]: zero and the group order are refused at the door
  // (node imports both and would reduce the order to zero inside the DH), n-1 is admitted.
  var n = Buffer.from("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "hex");
  var nm1 = Buffer.from(n); nm1[31] -= 1;
  check("P-256 zero scalar -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(P256, oe.enc, { skm: Buffer.alloc(32) }, {}); }) === "hpke/bad-key");
  check("P-256 scalar equal to n -> hpke/bad-key", codeOf(function () { pki.hpke.setupR(P256, oe.enc, { skm: n }, {}); }) === "hpke/bad-key");
  check("P-256 scalar n-1 is admitted", codeOf(function () { pki.hpke.setupR(P256, oe.enc, { skm: nm1 }, {}); }) === "NO-THROW");
  // The messages name what the door checked, so a refusal that node would also have produced
  // (a wrong-length key, a wrong-length ciphertext) still says which rule refused it.
  function msgOf(fn) { try { fn(); return ""; } catch (e) { return e.code + ": " + e.message; } }
  check("a wrong-length scalar names the byte count", msgOf(function () { pki.hpke.setupR(IDS, o.enc, { skm: skm.subarray(1) }, {}); }).indexOf("32-byte scalar") > 0);
  check("a wrong-length ML-KEM seed names the seed", msgOf(function () { pki.hpke.setupR(ML768, Buffer.alloc(1088), { skm: Buffer.alloc(63) }, {}); }).indexOf("64-byte seed") > 0);
  check("a wrong-length ML-KEM encapsulated key cites the FIPS 203 ciphertext check", msgOf(function () { pki.hpke.setupR(ML768, Buffer.alloc(1087), { skm: hx(pqVectors[1].skRm) }, {}); }).indexOf("FIPS 203 sec. 7.3") > 0);
  check("a wrong-length ML-KEM public key names the byte count", msgOf(function () { pki.hpke.setupS(ML768, Buffer.alloc(1183), {}); }).indexOf("1184 bytes") > 0);
  // A KeyObject is bound to the suite by what it is, not by what its export happens to yield:
  // a P-521 KeyObject under the P-256 suite and a public KeyObject where a private one is due.
  var p521 = crypto.generateKeyPairSync("ec", { namedCurve: "secp521r1" });
  check("a P-521 KeyObject under the P-256 suite (sender) names the mismatch", msgOf(function () { pki.hpke.setupS(P256, p521.publicKey, {}); }).indexOf("not a P-256 key") > 0);
  check("a P-521 KeyObject under the P-256 suite (recipient) names the mismatch", msgOf(function () { pki.hpke.setupR(P256, oe.enc, p521.privateKey, {}); }).indexOf("not a P-256 key") > 0);
  check("a public KeyObject as the DHKEM recipient private key -> hpke/bad-key naming the type", msgOf(function () { pki.hpke.setupR(IDS, o.enc, x.publicKey, {}); }).indexOf("public") > 0);
  var ml = crypto.generateKeyPairSync("ml-kem-768");
  check("a public KeyObject as the ML-KEM recipient private key -> hpke/bad-key naming the type", msgOf(function () { pki.hpke.setupR(ML768, Buffer.alloc(1088), ml.publicKey, {}); }).indexOf("public") > 0);
}

function testOptionsReadOnce() {
  // Every setup option is read once, into a snapshot, before anything decides on it. An accessor
  // that answers differently per read cannot pass one gate with one value and run with another.
  var crypto = require("crypto");
  var kp = crypto.generateKeyPairSync("x25519");
  var modeReads = 0;
  var flipping = {};
  Object.defineProperty(flipping, "mode", { enumerable: true, get: function () { modeReads++; return modeReads === 1 ? S.MODE.AUTH : S.MODE.BASE; } });
  check("a mode accessor answering auth then base is held to its first answer", codeOf(function () { pki.hpke.setupS(IDS, kp.publicKey, flipping); }) === "hpke/auth-key-required" && modeReads === 1);
  var keyReads = 0;
  var vanishing = { mode: S.MODE.AUTH };
  Object.defineProperty(vanishing, "senderKey", { enumerable: true, get: function () { keyReads++; return keyReads === 1 ? kp.privateKey : null; } });
  var a = pki.hpke.setupS(IDS, kp.publicKey, vanishing);
  var c = a.context.seal(Buffer.alloc(0), Buffer.from("once"));
  check("a senderKey accessor is read once and the exchange authenticates with it", keyReads === 1 &&
    pki.hpke.setupR(IDS, a.enc, kp.privateKey, { mode: S.MODE.AUTH, senderPublicKey: kp.publicKey }).open(Buffer.alloc(0), c).toString() === "once");
  // A private KeyObject handed where a public one is due yields its public half only.
  var o = pki.hpke.seal(IDS, kp.privateKey, {}, Buffer.alloc(0), Buffer.from("pub-half"));
  check("an X25519 private KeyObject as the recipient public key encrypts to its public half",
    pki.hpke.open(IDS, o.enc, kp.privateKey, {}, Buffer.alloc(0), o.ct).toString() === "pub-half");
}

function testExpandFailurePathWipes() {
  // A KDF block computed before a later block's HMAC fails is wiped on the failing path too.
  var crypto = require("crypto");
  var kp = crypto.generateKeyPairSync("x25519");
  var ctx = pki.hpke.setupS(IDS, kp.publicKey, {}).context;
  var real = crypto.createHmac, digests = [], calls = 0, threw = false;
  crypto.createHmac = function (hash, key) {
    var h = real.call(crypto, hash, key), n = ++calls;
    return {
      update: function (d) { if (n === 2) throw new Error("injected engine failure"); h.update(d); return this; },
      digest: function () { var b = h.digest(); digests.push(b); return b; },
    };
  };
  try { ctx.export(Buffer.from("ctx"), 64); }
  catch (e) { threw = e.message === "injected engine failure"; }
  finally { crypto.createHmac = real; }
  var wiped = digests.length === 1 && digests[0].every(function (b) { return b === 0; });
  check("a KDF block produced before an expand failure is wiped", threw && wiped);
}

function run() {
  testKat();
  testRobustness();
  testAdversarialBranches();
  testMlKemKat();
  testMlKemRobustness();
  testSerializedPrivateKeyDoor();
  testOptionsReadOnce();
  testExpandFailurePathWipes();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
