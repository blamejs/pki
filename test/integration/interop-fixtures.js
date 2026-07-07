// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/integration/interop-fixtures — the interop coverage a primitive
 * declares, keyed by its `@primitive` name (the same name the wiki comment
 * block carries). `auto-interop.test.js` discovers the primitive set from
 * the `@primitive` blocks in lib/ and runs whatever fixtures are registered
 * here for each discovered name — so adding a primitive that needs
 * cross-implementation coverage is a matter of adding its comment block and
 * a fixture under the matching key, never editing the runner.
 *
 * Each fixture is `{ desc, run(ctx) }`; `run` may be async and asserts via
 * `ctx.check`. `ctx` is test/integration/_interop-ctx.js (OpenSSL oracle +
 * temp-file plumbing).
 */

var path = require("node:path");

// --- helpers shared by the x509 fixtures ------------------------------

function _parseOpensslFields(text) {
  var out = {};
  String(text).split(/\r?\n/).forEach(function (line) {
    var m = /^(subject|issuer|serial|notBefore|notAfter)\s*=\s*(.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2].trim();
  });
  return out;
}

function _normDn(dn) {
  return String(dn)
    .replace(/^\s*(?:subject|issuer)\s*=\s*/i, "")
    .split(", ")
    .map(function (t) { return t.trim().replace(/\s*=\s*/, "="); })
    .filter(Boolean)
    .sort()
    .join(", ");
}

function _opensslDate(s) {
  var d = new Date(String(s).replace(/\s+/g, " ").trim());
  if (isNaN(d.getTime())) throw new Error("unparseable openssl date: " + s);
  return d.getTime();
}

module.exports = {
  // ---- pki.schema.x509.parse : agree with the `openssl x509` reading ----------
  "pki.schema.x509.parse": [
    {
      desc: "parse agrees with `openssl x509` on subject/issuer/serial/validity",
      run: function (ctx) {
        var fixture = path.join(ctx.FIXTURES_DIR, "pkijs-selfsigned-ec.pem");
        var cert = ctx.pki.schema.x509.parse(ctx.fs.readFileSync(fixture));
        var o = _parseOpensslFields(ctx.runOpenssl([
          "x509", "-noout", "-subject", "-issuer", "-serial", "-startdate", "-enddate", "-in", fixture,
        ]));
        ctx.check("subject agrees with openssl", _normDn(cert.subject.dn) === _normDn(o.subject));
        ctx.check("issuer agrees with openssl", _normDn(cert.issuer.dn) === _normDn(o.issuer));
        ctx.check("serial agrees with openssl", cert.serialNumberHex.toLowerCase() === o.serial.toLowerCase());
        ctx.check("notBefore agrees with openssl", cert.validity.notBefore.getTime() === _opensslDate(o.notBefore));
        ctx.check("notAfter agrees with openssl", cert.validity.notAfter.getTime() === _opensslDate(o.notAfter));
      },
    },
    {
      desc: "pemEncode(pemDecode(...)) reproduces DER that openssl still accepts",
      run: function (ctx) {
        var fixture = path.join(ctx.FIXTURES_DIR, "pkijs-selfsigned-ec.pem");
        var pem = ctx.fs.readFileSync(fixture);
        var der = ctx.pki.schema.x509.pemDecode(pem, "CERTIFICATE");
        var reencoded = ctx.pki.schema.x509.pemEncode(der, "CERTIFICATE");
        ctx.check("pem round-trip reproduces the DER", ctx.pki.schema.x509.pemDecode(reencoded, "CERTIFICATE").equals(der));
        ctx.withTmp(reencoded, "roundtrip.pem", function (p) {
          var o = _parseOpensslFields(ctx.runOpenssl(["x509", "-noout", "-serial", "-in", p]));
          ctx.check("openssl accepts the re-encoded PEM", ctx.pki.schema.x509.parse(pem).serialNumberHex.toLowerCase() === o.serial.toLowerCase());
        });
      },
    },
  ],

  // ---- pki.webcrypto.subtle : our key encodings parse in OpenSSL -------
  "pki.webcrypto.subtle": [
    {
      desc: "ECDSA P-256 SPKI + PKCS#8 export parse in openssl",
      run: async function (ctx) {
        var subtle = ctx.pki.webcrypto.subtle;
        var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        var spki = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
        ctx.withTmp(spki, "ec-spki.der", function (p) {
          var out = ctx.runOpenssl(["pkey", "-pubin", "-inform", "DER", "-in", p, "-noout", "-text"]);
          ctx.check("openssl reads our ECDSA SPKI as P-256", /prime256v1|P-256/.test(out));
        });
        var pkcs8 = Buffer.from(await subtle.exportKey("pkcs8", kp.privateKey));
        ctx.withTmp(pkcs8, "ec-pkcs8.der", function (p) {
          ctx.runOpenssl(["pkey", "-inform", "DER", "-in", p, "-noout"]);
          ctx.check("openssl accepts our ECDSA PKCS#8", true);
        });
      },
    },
    {
      desc: "ML-DSA-65 SPKI export parses in OpenSSL 3.5+ (post-quantum interop)",
      run: async function (ctx) {
        // ML-DSA lands in OpenSSL 3.5; CI runners and Alpine still ship
        // 3.0–3.3. When the oracle can't do ML-DSA, record a skip — the
        // gap is the oracle's, not ours (our own tests already prove the
        // sign/verify round-trip natively).
        if (!ctx.opensslSupports("ML-DSA")) {
          ctx.skip("ML-DSA SPKI interop — this OpenSSL predates 3.5 (no ML-DSA); the toolkit's own sign/verify round-trip is proven natively");
          return;
        }
        var subtle = ctx.pki.webcrypto.subtle;
        var kp = await subtle.generateKey({ name: "ML-DSA-65" }, true, ["sign", "verify"]);
        var spki = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
        ctx.withTmp(spki, "mldsa-spki.der", function (p) {
          var r = ctx.runOpenssl(["pkey", "-pubin", "-inform", "DER", "-in", p, "-noout"], { allowNonZero: true });
          ctx.check("openssl 3.5 accepts our ML-DSA-65 SPKI", r.code === 0);
        });
      },
    },
  ],

  // ---- pki.schema.pkcs12.parse : a real `openssl pkcs12 -export` store parses --
  "pki.schema.pkcs12.parse": [
    {
      desc: "parses an `openssl pkcs12 -export` store (default encoding, incl. BER)",
      run: function (ctx) {
        var keyPath = ctx.tmpFile(Buffer.alloc(0), "key.pem");
        var certPath = ctx.tmpFile(Buffer.alloc(0), "cert.pem");
        var p12Path = ctx.tmpFile(Buffer.alloc(0), "store.p12");
        try {
          ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes",
                          "-subj", "/CN=p12-interop"]);
          ctx.runOpenssl(["pkcs12", "-export", "-in", certPath, "-inkey", keyPath,
                          "-out", p12Path, "-passout", "pass:interop"]);
          var store = ctx.pki.schema.pkcs12.parse(ctx.fs.readFileSync(p12Path));
          ctx.check("openssl store parses to version 3", store.version === 3);
          ctx.check("openssl store is password-integrity", store.integrityMode === "password" && store.mac !== null);
          ctx.check("openssl store surfaces the MACed byte range", Buffer.isBuffer(store.macedBytes) && store.macedBytes.length > 0);
          ctx.check("openssl store MAC iterations surfaced", store.mac.iterations >= 1);
          // Default `-export` shrouds the key (a pkcs8ShroudedKeyBag in a plain
          // safe) and encrypts the cert safe (an id-encryptedData element).
          var shrouded = store.safeBags.filter(function (b) { return b.type === "pkcs8ShroudedKeyBag"; });
          ctx.check("openssl store carries a shrouded key bag", shrouded.length === 1);
          ctx.check("shrouded key algorithm surfaced, ciphertext opaque",
                    typeof shrouded[0].encrypted.encryptionAlgorithm.oid === "string" &&
                    Buffer.isBuffer(shrouded[0].encrypted.encryptedData));
          ctx.check("shrouded key carries its localKeyId", Buffer.isBuffer(shrouded[0].localKeyId));
          ctx.check("openssl store carries an encrypted cert safe",
                    store.encryptedSafes.length === 1 && store.encryptedSafes[0].type === "encryptedData");
          ctx.check("encrypted safe ciphertext surfaced raw",
                    Buffer.isBuffer(store.encryptedSafes[0].content.encryptedContentInfo.encryptedContent));
        } finally {
          [keyPath, certPath, p12Path].forEach(function (p) {
            try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ }
          });
        }
      },
    },
    {
      desc: "parses an `openssl pkcs12 -export -nomac` public/plain variant fail-closed",
      run: function (ctx) {
        // -nomac drops MacData while keeping the id-data authSafe — RFC 7292 §4
        // integrity coherence says that store is malformed; proving the reject
        // against real openssl output keeps the guard honest, not theoretical.
        var keyPath = ctx.tmpFile(Buffer.alloc(0), "key2.pem");
        var certPath = ctx.tmpFile(Buffer.alloc(0), "cert2.pem");
        var p12Path = ctx.tmpFile(Buffer.alloc(0), "store2.p12");
        try {
          ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes",
                          "-subj", "/CN=p12-nomac"]);
          ctx.runOpenssl(["pkcs12", "-export", "-nomac", "-in", certPath, "-inkey", keyPath,
                          "-out", p12Path, "-passout", "pass:interop"]);
          var codeThrown = null;
          try { ctx.pki.schema.pkcs12.parse(ctx.fs.readFileSync(p12Path)); }
          catch (e) { codeThrown = e.code; }
          ctx.check("a MAC-less id-data store rejects with the integrity-mode verdict",
                    codeThrown === "pkcs12/bad-integrity-mode");
        } finally {
          [keyPath, certPath, p12Path].forEach(function (p) {
            try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ }
          });
        }
      },
    },
  ],
};
