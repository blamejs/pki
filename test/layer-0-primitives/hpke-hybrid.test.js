// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for the HPKE PQ/T hybrid KEMs: MLKEM768-P256 (0x0050),
// MLKEM1024-P384 (0x0051) and MLKEM768-X25519 (0x647a), registered by draft-ietf-hpke-pq-05 and
// constructed by draft-irtf-cfrg-hybrid-kems-12 / draft-irtf-cfrg-concrete-hybrid-kems-04.
//
// A hybrid KEM combines a post-quantum KEM with a traditional group so that breaking it needs both
// broken. The CG framework builds it as follows (hybrid-kems sec. 5.1.1), where the decapsulation key
// IS a 32-byte seed and both component keys are expanded from it:
//
//   expandDecapsKeyG(seed):
//     seed_full = PRG(seed); (seed_PQ, seed_T) = split(KEM_PQ.Nseed, Group_T.Nseed, seed_full)
//     (dk_PQ, ek_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
//     dk_T = Group_T.RandomScalar(seed_T); ek_T = Group_T.Exp(Group_T.g, dk_T)
//
// and combines the two shared secrets with the C2PRI combiner:
//
//   ss = KDF(concat(ss_PQ, ss_T, ct_T, ek_T, label))
//
// What that combiner does NOT bind is the point: `ct_PQ` and `ek_PQ` are absent, because the PQ KEM is
// already ciphertext-collision-resistant. Using the UniversalCombiner, which binds all six, produces a
// different secret, so a vector pins the published value rather than the shape of the expression.
//
// The encapsulation key and the ciphertext are concatenated in (PQ, T) order.
//
// The vectors are Appendix B of draft-irtf-cfrg-concrete-hybrid-kems-04, reassembled from the draft
// text. They are known answers from the specification, not values this toolkit produced: each carries a
// seed, the two component keys it expands to, the concatenated encapsulation key, a ciphertext and the
// shared secret that ciphertext decapsulates to.

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }

// A committed fixture, so a fresh clone runs these. The rows are Appendix B of the draft, reassembled
// from its text, and are known answers from the specification rather than values this toolkit produced.
var ROWS = require("../fixtures/hpke/concrete-hybrid-kems-04-vectors.json");
var VECTORS = {};
ROWS.forEach(function (r) { VECTORS[r.suite] = r; });

var SUITES = [
  { name: "MLKEM768-P256", kem: 0x0050, kdf: 0x0001, aead: 0x0001, Npub: 1249, Nenc: 1153, Nsk: 32, Nsecret: 32 },
  { name: "MLKEM1024-P384", kem: 0x0051, kdf: 0x0002, aead: 0x0002, Npub: 1665, Nenc: 1665, Nsk: 32, Nsecret: 32 },
  { name: "MLKEM768-X25519", kem: 0x647a, kdf: 0x0001, aead: 0x0003, Npub: 1216, Nenc: 1120, Nsk: 32, Nsecret: 32 },
];

function testSurface() {
  ["generateKeyPair", "deriveKeyPair", "encap", "decap"].forEach(function (n) {
    check("pki.hpke." + n + " is exposed", typeof pki.hpke[n] === "function");
  });
  // The named constants are what a caller writes instead of a bare number, so each suite's id is
  // asserted through the name AND against the value the registry documents.
  var K = pki.hpke.suites.KEM;
  [["MLKEM768_P256", 0x0050], ["MLKEM1024_P384", 0x0051], ["MLKEM768_X25519", 0x647a]].forEach(function (r) {
    check("S: pki.hpke.suites.KEM." + r[0] + " is " + r[1], K[r[0]] === r[1]);
  });
}

// ---- the published known answers -------------------------------------------

function testKnownAnswers() {
  check("V0: the Appendix B fixture carries all three suites",
    ROWS.length === 3 && ROWS.every(function (r) { return r.source === "draft-irtf-cfrg-concrete-hybrid-kems-04"; }));

  SUITES.forEach(function (su, i) {
    var v = VECTORS[su.name];
    check("V" + (i + 1) + ".0: a vector exists for " + su.name, v !== undefined);
    if (v === undefined) return;
    var seed = Buffer.from(v.seed, "hex");

    // The vector's `seed` is the KEM's DECAPSULATION KEY, which the CG framework expands both component
    // keys from. It is NOT HPKE's DeriveKeyPair input: draft-ietf-hpke-pq sec. 4 derives the seed from an
    // ikm first, so deriveKeyPair would hash it again. The door that takes a decapsulation key as it
    // stands is `{ skm }`, and supplying `pkm` alongside it makes the verb check the public key it
    // derives against the published one, so keygen is asserted through the same call as decapsulation.
    var ek = Buffer.from(v.encapsulation_key, "hex");
    check("V" + (i + 1) + ".1: the published encapsulation key is " + su.Npub +
      " bytes, the PQ and traditional keys concatenated", ek.length === su.Npub);
    check("V" + (i + 1) + ".2: the seed is the " + su.Nsk + "-byte decapsulation key the framework defines",
      seed.length === su.Nsk);

    // Decapsulation of the published ciphertext yields the published shared secret. This is the check
    // that pins the combiner, including which values it does not bind.
    var ct = Buffer.from(v.ciphertext, "hex");
    check("V" + (i + 1) + ".3: the published ciphertext is " + su.Nenc + " bytes", ct.length === su.Nenc);
    var ss = pki.hpke.decap(su.kem, ct, { skm: seed, pkm: ek });
    check("V" + (i + 1) + ".4: the seed expands to the published encapsulation key, and the published " +
      "ciphertext decapsulates to the published shared secret",
      ss.toString("hex") === v.shared_secret);
    check("V" + (i + 1) + ".5: which is " + su.Nsecret + " bytes", ss.length === su.Nsecret);
    // The pkm check is load-bearing above, so it is shown to be capable of failing: one flipped bit in
    // the published encapsulation key must be refused. Without this, V.4 would pass even if the verb
    // ignored pkm and the key derivation were never asserted at all.
    var bentEk = Buffer.from(ek); bentEk[0] ^= 0x01;
    check("V" + (i + 1) + ".6: and a single flipped bit in that encapsulation key is refused",
      code(function () { return pki.hpke.decap(su.kem, ct, { skm: seed, pkm: bentEk }); }) === "hpke/bad-key");
  });
}

// ---- the KEM interface, both directions ------------------------------------

function testRoundTrip() {
  SUITES.forEach(function (su, i) {
    var kp = pki.hpke.generateKeyPair(su.kem);
    check("R" + (i + 1) + ".1: " + su.name + " generates a key pair of the registered sizes",
      kp.publicKey.length === su.Npub && kp.privateKey.length === su.Nsk);
    var e = pki.hpke.encap(su.kem, kp.publicKey);
    check("R" + (i + 1) + ".2: encapsulation produces an enc of the registered size",
      e.enc.length === su.Nenc && e.sharedSecret.length === su.Nsecret);
    var ss = pki.hpke.decap(su.kem, e.enc, { skm: kp.privateKey });
    check("R" + (i + 1) + ".3: decapsulation recovers the same shared secret",
      Buffer.compare(ss, e.sharedSecret) === 0);

    // Two encapsulations to one key differ, so the traditional half contributes fresh randomness.
    var e2 = pki.hpke.encap(su.kem, kp.publicKey);
    check("R" + (i + 1) + ".4: a second encapsulation differs, both in enc and in secret",
      Buffer.compare(e2.enc, e.enc) !== 0 && Buffer.compare(e2.sharedSecret, e.sharedSecret) !== 0);

    // A different recipient key does not recover the secret. Both halves are bound, so altering either
    // half of the ciphertext must break it.
    var other = pki.hpke.generateKeyPair(su.kem);
    var wrong = pki.hpke.decap(su.kem, e.enc, { skm: other.privateKey });
    check("R" + (i + 1) + ".5: another key decapsulates to a different secret rather than the same one",
      Buffer.compare(wrong, e.sharedSecret) !== 0);

    var pqTampered = Buffer.from(e.enc); pqTampered[0] ^= 0xff;
    var tTampered = Buffer.from(e.enc); tTampered[tTampered.length - 1] ^= 0xff;
    check("R" + (i + 1) + ".6: altering the PQ half of the ciphertext changes the secret",
      Buffer.compare(pki.hpke.decap(su.kem, pqTampered, { skm: kp.privateKey }), e.sharedSecret) !== 0);
    check("R" + (i + 1) + ".7: altering the traditional half changes the secret too, so both are bound",
      code(function () {
        var got = pki.hpke.decap(su.kem, tTampered, { skm: kp.privateKey });
        if (Buffer.compare(got, e.sharedSecret) === 0) throw new Error("unchanged");
        return got;
      }) !== "NO-CODE");

    // Determinism of derivation. deriveKeyPair takes an IKM, which draft-ietf-hpke-pq sec. 4 derives the
    // KEM's seed FROM, so handing it a decapsulation key derives a different pair rather than rebuilding
    // that one. The seed door is `{ skm }`, exercised above and in the known-answer vectors.
    var ikm = Buffer.alloc(48, 0x21);
    var once = pki.hpke.deriveKeyPair(su.kem, ikm);
    var again = pki.hpke.deriveKeyPair(su.kem, ikm);
    check("R" + (i + 1) + ".8: deriving from the same ikm twice gives the same key pair",
      Buffer.compare(again.publicKey, once.publicKey) === 0 &&
      Buffer.compare(again.privateKey, once.privateKey) === 0);
    var diff = pki.hpke.deriveKeyPair(su.kem, Buffer.alloc(48, 0x5a));
    check("R" + (i + 1) + ".9: a different ikm gives a different key pair",
      Buffer.compare(diff.publicKey, once.publicKey) !== 0);
    check("R" + (i + 1) + ".10: the derived private key is the " + su.Nsk + "-byte seed, and it works",
      once.privateKey.length === su.Nsk &&
      Buffer.compare(pki.hpke.decap(su.kem, pki.hpke.encap(su.kem, once.publicKey).enc,
        { skm: once.privateKey, pkm: once.publicKey }), Buffer.alloc(0)) !== 0);
  });
}

// ---- end to end through the shipped seal / open ----------------------------

function testSealOpen() {
  SUITES.forEach(function (su, i) {
    var ids = { kem: su.kem, kdf: su.kdf, aead: su.aead };
    var kp = pki.hpke.generateKeyPair(su.kem);
    var pt = Buffer.from("post-quantum and traditional, both", "utf8");
    var aad = Buffer.from("hybrid", "utf8");
    var sealed = pki.hpke.seal(ids, kp.publicKey, {}, aad, pt);
    check("E" + (i + 1) + ".1: " + su.name + " seals through the shipped verb", Buffer.isBuffer(sealed.ct));
    var opened = pki.hpke.open(ids, sealed.enc, { skm: kp.privateKey }, {}, aad, sealed.ct);
    check("E" + (i + 1) + ".2: and opens to the same plaintext", Buffer.compare(opened, pt) === 0);
    check("E" + (i + 1) + ".3: a wrong aad does not open",
      code(function () { return pki.hpke.open(ids, sealed.enc, { skm: kp.privateKey }, {}, Buffer.from("x"), sealed.ct); }) !== "NO-THROW");
    check("E" + (i + 1) + ".4: another recipient key does not open",
      code(function () { return pki.hpke.open(ids, sealed.enc, { skm: pki.hpke.generateKeyPair(su.kem).privateKey }, {}, aad, sealed.ct); }) !== "NO-THROW");

    // The psk mode composes, and the auth modes do not: a hybrid KEM defines no AuthEncap, for the same
    // reason ML-KEM does not.
    var psk = { mode: pki.hpke.suites.MODE.PSK, psk: Buffer.alloc(32, 9), pskId: Buffer.from("id") };
    var ps = pki.hpke.seal(ids, kp.publicKey, psk, aad, pt);
    check("E" + (i + 1) + ".5: the psk mode composes with a hybrid KEM",
      Buffer.compare(pki.hpke.open(ids, ps.enc, { skm: kp.privateKey }, psk, aad, ps.ct), pt) === 0);
    check("E" + (i + 1) + ".6: the auth mode is refused, a hybrid KEM defining no AuthEncap",
      code(function () {
        return pki.hpke.seal(ids, kp.publicKey,
          { mode: pki.hpke.suites.MODE.AUTH, senderKey: { skm: kp.privateKey } }, aad, pt);
      }) === "hpke/auth-unsupported");
  });
}

// ---- refusals --------------------------------------------------------------

function testRefusals() {
  // Every refusal is asked of all three suites. Asking only one leaves the other two answering for a
  // rule nothing drove them through, and the three differ in exactly the place a length or offset
  // mistake lands: the PQ halves are 1184/1568/1184 wide and the traditional halves 65/97/32.
  SUITES.forEach(function (su, i) {
    var g = "G" + (i + 1);
    var seed = Buffer.alloc(32, 0x09);
    var good = pki.hpke.deriveKeyPair(su.kem, seed);
    var enc = pki.hpke.encap(su.kem, good.publicKey).enc;
    // CONTROL. Without it a refusal below could be the suite failing for an unrelated reason.
    check(g + ".0: " + su.name + " accepts its own key pair and ciphertext",
      pki.hpke.decap(su.kem, enc, { skm: seed }).length === su.Nsecret);

    check(g + ".1: a private key that is not the 32-byte seed is refused",
      code(function () { return pki.hpke.decap(su.kem, enc, { skm: Buffer.alloc(31) }); }) === "hpke/bad-key");
    check(g + ".2: an encapsulation key one byte short is refused",
      code(function () { return pki.hpke.encap(su.kem, good.publicKey.subarray(0, su.Npub - 1)); }) === "hpke/bad-key");
    check(g + ".3: an encapsulation key one byte long is refused",
      code(function () { return pki.hpke.encap(su.kem, Buffer.concat([good.publicKey, Buffer.alloc(1)])); }) === "hpke/bad-key");
    check(g + ".4: a ciphertext of the wrong length is refused",
      code(function () { return pki.hpke.decap(su.kem, enc.subarray(0, su.Nenc - 1), { skm: seed }); }) === "hpke/bad-key");
    // deriveKeyPair takes an ikm of any length and derives the seed from it, so a short one is NOT a
    // refusal: draft-ietf-hpke-pq sec. 4 states the 32-byte minimum as "SHOULD be at least 32 bytes",
    // and promoting that to a rejection would refuse input the specification permits. The length rule
    // belongs to the seed door, which G.1 covers.
    check(g + ".5: a short ikm still derives a key pair, the 32-byte minimum being a SHOULD",
      code(function () { return pki.hpke.deriveKeyPair(su.kem, Buffer.alloc(16)); }) === "NO-THROW");
    check(g + ".5a: and an ikm that is not bytes at all is refused",
      code(function () { return pki.hpke.deriveKeyPair(su.kem, "not bytes"); }) === "hpke/bad-input");
    check(g + ".6: a public key whose PQ half is not a valid encapsulation key is refused",
      code(function () { return pki.hpke.encap(su.kem, Buffer.alloc(su.Npub, 0xff)); }) === "hpke/bad-key");
    check(g + ".7: a pkm that is not the derivation of the seed is refused",
      code(function () {
        var wrong = Buffer.from(good.publicKey); wrong[0] ^= 0xff;
        return pki.hpke.decap(su.kem, enc, { skm: seed, pkm: wrong });
      }) === "hpke/bad-key");
    check(g + ".8: deriveKeyPair and generateKeyPair agree on the private key length",
      pki.hpke.generateKeyPair(su.kem).privateKey.length === good.privateKey.length &&
      good.privateKey.length === su.Nsk);
  });

  // The traditional half, in both directions. The two directions are NOT the same offset: for
  // ML-KEM-768 the encapsulation key's PQ half is 1184 bytes and the ciphertext's is 1088, so one
  // offset used for both lands past the end of the shorter buffer and tests nothing.
  //
  // What a bad half IS depends on the group. A prime-curve half is an uncompressed SEC1 point, so
  // coordinates off the curve are an invalid encoding and the import refuses them. X25519 has no
  // invalid public keys: RFC 7748 sec. 5 makes every 32-byte string a valid u-coordinate, so the only
  // refusal the group offers is the all-zero agreement a small-order point produces. Asserting a
  // point check on X25519 would be asserting a rule the group does not have.
  var HALVES = [
    { name: "MLKEM768-P256", kem: 0x0050, pqPub: 1184, pqCt: 1088, curve: true },
    { name: "MLKEM1024-P384", kem: 0x0051, pqPub: 1568, pqCt: 1568, curve: true },
    { name: "MLKEM768-X25519", kem: 0x647a, pqPub: 1184, pqCt: 1088, curve: false },
  ];
  HALVES.forEach(function (h, i) {
    var g = "G" + (SUITES.length + i + 1);
    var seed = Buffer.alloc(32, 0x09);
    var kp = pki.hpke.deriveKeyPair(h.kem, seed);
    var enc = pki.hpke.encap(h.kem, kp.publicKey).enc;
    check(g + ".0: " + h.name + " halves are where the widths say they are",
      kp.publicKey.length > h.pqPub && enc.length > h.pqCt);

    function spoil(buf, offset, marker) {
      var out = Buffer.from(buf);
      out.fill(0xAA, offset);
      if (marker) out[offset] = 0x04;      // keep the uncompressed-point marker, break the coordinates
      return out;
    }
    if (h.curve) {
      check(g + ".1: an encapsulation key whose traditional half is off the curve is refused",
        code(function () { return pki.hpke.encap(h.kem, spoil(kp.publicKey, h.pqPub, true)); }) === "hpke/bad-key");
      check(g + ".2: a ciphertext whose traditional half is off the curve is refused",
        code(function () { return pki.hpke.decap(h.kem, spoil(enc, h.pqCt, true), { skm: seed }); }) === "hpke/bad-key");
    } else {
      check(g + ".1: an arbitrary 32-byte X25519 half is accepted, the group having no invalid keys",
        code(function () { return pki.hpke.encap(h.kem, spoil(kp.publicKey, h.pqPub, false)); }) === "NO-THROW");
      check(g + ".2: a ciphertext half driving the agreement to all zeros is refused",
        code(function () {
          var lowOrder = Buffer.from(enc);
          lowOrder.fill(0x00, h.pqCt);
          return pki.hpke.decap(h.kem, lowOrder, { skm: seed });
        }) === "hpke/bad-key");
    }
  });

  check("G7: an unknown KEM id is refused",
    code(function () { return pki.hpke.generateKeyPair(0x9999); }) === "hpke/unknown-suite");

  // The nominal-group seed widths, asserted directly. No published vector can distinguish P-256's
  // Nseed of 128 from 32: RandomScalar accepts its first 32-byte chunk unless that chunk is at or above
  // the curve order, which happens with probability about 2^-32, and SHAKE being an XOF means the first
  // 96 bytes of a 192-byte squeeze are the same bytes either way. Shortening it would silently remove
  // three of the four rejection attempts the draft budgets, so the constant is pinned here instead of
  // being inferred from an output that cannot show it.
  var G = pki.hpke.nominalGroups;
  [["P-256", 128, 32, 65, 32], ["P-384", 48, 48, 97, 48], ["X25519", 32, 32, 32, 32]].forEach(function (r) {
    check("G8." + r[0] + ": Nseed " + r[1] + ", Nscalar " + r[2] + ", Nelem " + r[3] + ", Nss " + r[4],
      G[r[0]].Nseed === r[1] && G[r[0]].Nscalar === r[2] && G[r[0]].Nelem === r[3] && G[r[0]].Nss === r[4]);
  });
  check("G9: P-256 budgets four rejection attempts and P-384 exactly one, which is what those widths mean",
    G["P-256"].Nseed / G["P-256"].Nscalar === 4 && G["P-384"].Nseed / G["P-384"].Nscalar === 1);
}

function run() {
  testSurface();
  testKnownAnswers();
  testRoundTrip();
  testSealOpen();
  testRefusals();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
