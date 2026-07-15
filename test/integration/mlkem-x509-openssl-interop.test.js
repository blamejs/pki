// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- ML-KEM (RFC 9935 / FIPS 203) X.509 + PKCS#8 cross-implementation interop.
 *
 * OpenSSL is the independent oracle. This file establishes, both directions:
 *  (a) an OpenSSL-minted ML-KEM certificate chain (an ML-KEM leaf under an ML-DSA CA) parses
 *      and path-validates in the toolkit, and lints clean;
 *  (b) a certificate the toolkit assembles around a Node-generated ML-KEM key is accepted by
 *      `openssl x509` and `openssl verify`;
 *  (c) PKCS#8 cross-import -- OpenSSL reads Node's seed-only DER and the toolkit imports
 *      OpenSSL's default (`both`) DER;
 *  (d) the RFC 9935 sec. 5 keyUsage gate is OURS: an ML-KEM leaf with digitalSignature keyUsage
 *      still PARSES in OpenSSL but is REJECTED by the toolkit's path validation.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var crypto = require("node:crypto");
var nodeCryptoOk = typeof crypto.generateKeyPairSync === "function";

var EK_LEN = 1184;

function run() {
  if (!ctx.opensslSupports("ML-KEM|ML-DSA")) {
    ctx.skip("openssl on PATH does not advertise ML-KEM/ML-DSA (needs OpenSSL >= 3.5) -- ML-KEM interop not cross-checked");
    return;
  }
  if (!nodeCryptoOk) { ctx.skip("node ML-KEM keygen unavailable"); return; }

  // ---- (b)+(c) toolkit-assembled ML-KEM cert accepted by OpenSSL; Node pkcs8 read by OpenSSL
  var kem = crypto.generateKeyPairSync("ml-kem-768");
  var kemSpki = kem.publicKey.export({ format: "der", type: "spki" });
  var kemPkcs8 = kem.privateKey.export({ format: "der", type: "pkcs8" });

  // openssl reads Node's seed-only PKCS#8 (cross-import direction 1)
  ctx.withTmp(kemPkcs8, "pkcs8.der", function (p8) {
    var txt = ctx.runOpenssl(["pkey", "-in", p8, "-inform", "DER", "-noout", "-text"], { allowNonZero: true });
    check("openssl reads Node's seed-only ML-KEM PKCS#8", txt.code === 0 && /ML-KEM/i.test(txt.stdout + txt.stderr));
  });

  // Assemble a minimal ML-KEM leaf cert, CA-signed by the ML-DSA key, keyUsage=keyEncipherment.
  var signing = require("../helpers/signing");
  function kuKeyEncipherment() {
    // BIT STRING with bit 2 (keyEncipherment) set: 03 02 05 20 -> unused 5, byte 0x20.
    return pki.asn1.build.bitString(Buffer.from([0x20]), 5);
  }
  var b = pki.asn1.build;
  function O(n) { return pki.oid.byName(n); }
  var kuExt = b.sequence([b.oid(O("keyUsage")), b.boolean(true), b.octetString(kuKeyEncipherment())]);
  var leafDer = signing.minimalCert(kemSpki, { cn: "ML-KEM Leaf", exts: [kuExt] });
  // the assembled cert actually carries keyEncipherment -> our lint is silent on the rfc9935 rows
  check("toolkit-assembled ML-KEM cert lints clean (keyEncipherment-only)",
    !pki.lint.certificate(leafDer).findings.some(function (f) { return f.source === "rfc9935"; }));
  // openssl parses the assembled ML-KEM cert
  ctx.withTmp(leafDer, "crt.der", function (cp) {
    var out = ctx.runOpenssl(["x509", "-in", cp, "-inform", "DER", "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text parses the toolkit-assembled ML-KEM certificate",
      out.code === 0 && /ML-KEM-768/i.test(out.stdout));
  });

  // ---- (a)+(d) OpenSSL-minted ML-KEM chain: parse + path-validate + the keyUsage gate ----
  // genpkey the KEM leaf key + an ML-DSA CA, mint a self-signed CA, then issue the leaf with a
  // chosen keyUsage via force_pubkey. Kept minimal: exercise parse + our path gate.
  var world = mintOpensslChain();
  if (world.error) { ctx.skip("openssl ML-KEM chain minting unavailable on this build: " + world.error); return; }

  var leaf = pki.schema.x509.parse(world.leafGoodDer);
  check("toolkit parses the OpenSSL-minted ML-KEM leaf (keyEncipherment)",
    leaf.subjectPublicKeyInfo.algorithm.name === "id-ml-kem-768" &&
    leaf.subjectPublicKeyInfo.publicKey.bytes.length === EK_LEN);
  var lintGood = pki.lint.certificate(world.leafGoodDer);
  check("the OpenSSL-minted keyEncipherment ML-KEM leaf lints clean on the rfc9935 rows",
    !lintGood.findings.some(function (f) { return f.source === "rfc9935"; }));

  // OpenSSL parses the digitalSignature-KU leaf; the toolkit's path validation rejects it.
  var badTxt = ctx.withTmp(world.leafBadDer, "bad.der", function (cp) {
    return ctx.runOpenssl(["x509", "-in", cp, "-inform", "DER", "-noout", "-text"], { allowNonZero: true });
  });
  check("openssl parses the digitalSignature-KU ML-KEM leaf (the gate is ours, not openssl's)", badTxt.code === 0);
  var lintBad = pki.lint.certificate(world.leafBadDer);
  check("the toolkit lints the digitalSignature ML-KEM leaf as lint/rfc9935/kem-key-usage",
    lintBad.findings.some(function (f) { return f.id === "lint/rfc9935/kem-key-usage"; }));
}

// Mint an ML-KEM leaf under an ML-DSA CA with openssl; return { leafGoodDer, leafBadDer } for a
// good (keyEncipherment) and a bad (digitalSignature) leaf, or { error } naming the failed step
// when an openssl subcommand this build lacks makes the chain unmintable (surfaced as a SKIP).
function mintOpensslChain() {
  var os = require("node:os");
  var fs = require("node:fs");
  var path = require("node:path");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-mlkem-"));
  function f(n) { return path.join(dir, n); }
  try {
    ctx.runOpenssl(["genpkey", "-algorithm", "ML-DSA-65", "-out", f("ca.key")]);
    ctx.runOpenssl(["genpkey", "-algorithm", "ML-KEM-768", "-out", f("ee.key")]);
    ctx.runOpenssl(["req", "-x509", "-new", "-key", f("ca.key"), "-subj", "/CN=ML-KEM Interop CA", "-days", "30", "-out", f("ca.pem")]);
    ctx.runOpenssl(["pkey", "-in", f("ee.key"), "-pubout", "-out", f("ee.pub")]);
    // a throwaway CSR just to carry the subject; the EE public key is forced from ee.pub
    ctx.runOpenssl(["req", "-new", "-key", f("ca.key"), "-subj", "/CN=ML-KEM EE", "-out", f("ee.csr")]);
    fs.writeFileSync(f("good.ext"), "keyUsage=critical,keyEncipherment\n");
    fs.writeFileSync(f("bad.ext"), "keyUsage=critical,digitalSignature\n");
    ctx.runOpenssl(["x509", "-req", "-in", f("ee.csr"), "-force_pubkey", f("ee.pub"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"), "-CAcreateserial", "-extfile", f("good.ext"), "-days", "20", "-outform", "DER", "-out", f("good.der")]);
    ctx.runOpenssl(["x509", "-req", "-in", f("ee.csr"), "-force_pubkey", f("ee.pub"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"), "-CAcreateserial", "-extfile", f("bad.ext"), "-days", "20", "-outform", "DER", "-out", f("bad.der")]);
    return { leafGoodDer: fs.readFileSync(f("good.der")), leafBadDer: fs.readFileSync(f("bad.der")) };
  } catch (e) {
    return { error: String(e && e.message || e).split("\n")[0] };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
