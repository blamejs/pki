// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#8 key export + RFC 8018 PBES2 encryption (pki.key) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's key-material producing side:
 *  (a) a plaintext PKCS#8 the toolkit exports parses under `openssl pkey -text` (RSA / EC / Ed25519), and an
 *      SPKI public key parses under `openssl pkey -pubin`;
 *  (b) an EncryptedPrivateKeyInfo the toolkit produces (`pki.key.encrypt`) is decrypted by
 *      `openssl pkcs8 -passin` -- across the cipher (AES-128/256-CBC) and prf (SHA-256/512) matrix, and with
 *      a non-ASCII UTF-8 password (identical UTF-8 encoding on both sides);
 *  (c) an EncryptedPrivateKeyInfo OpenSSL produces (`openssl pkcs8 -topk8 -v2`) is decrypted by
 *      `pki.key.decrypt`, recovering the exact original key;
 *  (d) a legacy PBES1 (`-v1 PBE-SHA1-3DES`) and a scrypt (`-scrypt`) encrypted key are REFUSED, fail-closed
 *      with key/unsupported-algorithm -- a deliberate boundary, not a crash.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var os = require("node:os");
var fs = require("node:fs");
var path = require("node:path");

var PW = "testpw";

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-key-"));
  try {
    // ---- (a) our plaintext PKCS#8 + SPKI parse under OpenSSL ----
    var arms = [
      { name: "rsa", genAlg: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" } },
      { name: "ec-p256", genAlg: { name: "ECDSA", namedCurve: "P-256" } },
      { name: "ed25519", genAlg: "Ed25519" },
    ];
    for (var i = 0; i < arms.length; i++) {
      var a = arms[i];
      var pair = await pki.key.generate(a.genAlg);
      var p8Pem = await pki.key.export(pair.privateKey, { format: "pem" });
      var spkiPem = await pki.key.export(pair.publicKey, { format: "pem" });
      var kf = path.join(dir, a.name + ".pem"); fs.writeFileSync(kf, p8Pem);
      var sf = path.join(dir, a.name + "-pub.pem"); fs.writeFileSync(sf, spkiPem);
      var pk = ctx.runOpenssl(["pkey", "-in", kf, "-noout", "-text"], { allowNonZero: true });
      check("openssl pkey parses the toolkit " + a.name + " PKCS#8", pk.code === 0);
      var pub = ctx.runOpenssl(["pkey", "-pubin", "-in", sf, "-noout", "-text"], { allowNonZero: true });
      check("openssl pkey -pubin parses the toolkit " + a.name + " SPKI", pub.code === 0);
    }

    // A reusable RSA key (as DER) for the PBES2 matrix -- our own key, OpenSSL is the decryptor.
    var rsaDer = signing.makeSigner("rsa").key;

    // ---- (b) our-encrypt decrypted by OpenSSL ----
    var matrix = [
      { cipher: "aes-256-cbc", prf: "hmacWithSHA256" },
      { cipher: "aes-128-cbc", prf: "hmacWithSHA256" },
      { cipher: "aes-256-cbc", prf: "hmacWithSHA512" },
    ];
    for (var m = 0; m < matrix.length; m++) {
      var enc = await pki.key.encrypt(rsaDer, PW, { cipher: matrix[m].cipher, prf: matrix[m].prf, pem: true });
      var ef = path.join(dir, "enc-" + m + ".pem"); fs.writeFileSync(ef, enc);
      var d = ctx.runOpenssl(["pkcs8", "-in", ef, "-passin", "pass:" + PW], { allowNonZero: true });
      check("openssl pkcs8 decrypts the toolkit " + matrix[m].cipher + "/" + matrix[m].prf + " EncryptedPrivateKeyInfo", d.code === 0 && /BEGIN PRIVATE KEY/.test(d.stdout));
    }

    // Non-ASCII UTF-8 password: OpenSSL decrypts our output (identical UTF-8 encoding on both sides). The
    // password is handed to OpenSSL through a FILE of raw UTF-8 bytes, not the command line -- argv on
    // Windows is re-encoded to the OS codepage, which would corrupt a non-ASCII password before OpenSSL
    // sees it, masking the UTF-8 parity the check exists to prove.
    var utf8pw = String.fromCharCode(0x70, 0xff, 0xe7, 0x2d, 0xe9);   // "p", U+00FF, U+00E7, "-", U+00E9
    var encU = await pki.key.encrypt(rsaDer, utf8pw, { pem: true });
    var uf = path.join(dir, "enc-utf8.pem"); fs.writeFileSync(uf, encU);
    var pwf = path.join(dir, "utf8.pw"); fs.writeFileSync(pwf, Buffer.concat([Buffer.from(utf8pw, "utf8"), Buffer.from("\n")]));
    var du = ctx.runOpenssl(["pkcs8", "-in", uf, "-passin", "file:" + pwf], { allowNonZero: true });
    check("openssl decrypts a toolkit key under a non-ASCII UTF-8 password", du.code === 0 && /BEGIN PRIVATE KEY/.test(du.stdout));

    // ---- (c) OpenSSL-encrypt decrypted by us ----
    var rsaPem = pki.schema.pkcs8.pemEncode(rsaDer, "PRIVATE KEY");
    var rf = path.join(dir, "rsa.pem"); fs.writeFileSync(rf, rsaPem);
    var osslMatrix = [["aes-256-cbc", "hmacWithSHA256"], ["aes-128-cbc", "hmacWithSHA512"]];
    for (var j = 0; j < osslMatrix.length; j++) {
      var of = path.join(dir, "ossl-" + j + ".pem");
      var e = ctx.runOpenssl(["pkcs8", "-topk8", "-v2", osslMatrix[j][0], "-v2prf", osslMatrix[j][1], "-in", rf, "-passout", "pass:" + PW, "-out", of], { allowNonZero: true });
      check("openssl produces a " + osslMatrix[j][0] + "/" + osslMatrix[j][1] + " EncryptedPrivateKeyInfo", e.code === 0);
      var recovered = await pki.key.decrypt(fs.readFileSync(of, "utf8"), PW);
      check("pki.key.decrypt recovers the OpenSSL " + osslMatrix[j][0] + " key to the exact PrivateKeyInfo", Buffer.compare(recovered, rsaDer) === 0);
    }

    // ---- (d) PBES1 + scrypt boundaries are REFUSED fail-closed ----
    var p1 = path.join(dir, "pbes1.pem");
    var e1 = ctx.runOpenssl(["pkcs8", "-topk8", "-v1", "PBE-SHA1-3DES", "-in", rf, "-passout", "pass:" + PW, "-out", p1], { allowNonZero: true });
    if (e1.code === 0) {
      var code1 = null; try { await pki.key.decrypt(fs.readFileSync(p1, "utf8"), PW); } catch (err) { code1 = err && err.code; }
      check("pki.key.decrypt REFUSES an OpenSSL PBES1 (PBE-SHA1-3DES) key with key/unsupported-algorithm", code1 === "key/unsupported-algorithm");
    } else { ctx.skip("openssl could not produce a PBES1 key (provider policy) -- PBES1 refusal not cross-checked"); }

    var sc = path.join(dir, "scrypt.pem");
    var es = ctx.runOpenssl(["pkcs8", "-topk8", "-scrypt", "-in", rf, "-passout", "pass:" + PW, "-out", sc], { allowNonZero: true });
    if (es.code === 0) {
      var codeS = null; try { await pki.key.decrypt(fs.readFileSync(sc, "utf8"), PW); } catch (err2) { codeS = err2 && err2.code; }
      check("pki.key.decrypt REFUSES an OpenSSL scrypt key fail-closed (typed KeyError)", codeS === "key/unsupported-algorithm" || codeS === "key/bad-algorithm-parameters");
    } else { ctx.skip("openssl could not produce a scrypt key -- scrypt refusal not cross-checked"); }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
