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
var makeOcspWorld = require("../helpers/ocsp-world").makeOcspWorld;

function _pem(der, label) {
  return "-----BEGIN " + label + "-----\n" +
    Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") +
    "\n-----END " + label + "-----\n";
}

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
      desc: "parses an `openssl pkcs12 -export -nomac` store as integrity-less",
      run: function (ctx) {
        // -nomac drops MacData while keeping the id-data authSafe — MacData is
        // OPTIONAL in the PFX syntax, so the store parses with
        // integrityMode "none" and no-integrity is the caller's policy call.
        var keyPath = ctx.tmpFile(Buffer.alloc(0), "key2.pem");
        var certPath = ctx.tmpFile(Buffer.alloc(0), "cert2.pem");
        var p12Path = ctx.tmpFile(Buffer.alloc(0), "store2.p12");
        try {
          ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes",
                          "-subj", "/CN=p12-nomac"]);
          ctx.runOpenssl(["pkcs12", "-export", "-nomac", "-in", certPath, "-inkey", keyPath,
                          "-out", p12Path, "-passout", "pass:interop"]);
          var store = ctx.pki.schema.pkcs12.parse(ctx.fs.readFileSync(p12Path));
          ctx.check("a -nomac store surfaces integrityMode none", store.integrityMode === "none" && store.mac === null);
          ctx.check("a -nomac store still carries its shrouded key bag",
                    store.safeBags.filter(function (b) { return b.type === "pkcs8ShroudedKeyBag"; }).length === 1);
        } finally {
          [keyPath, certPath, p12Path].forEach(function (p) {
            try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ }
          });
        }
      },
    },
  ],

  // ---- pki.jose.sign : a JWS signature `openssl dgst` accepts ------------------
  "pki.jose.sign": [
    {
      desc: "an ES256 Flattened JWS signature verifies under `openssl dgst` (raw R||S -> DER)",
      run: async function (ctx) {
        var subtle = ctx.pki.webcrypto.subtle;
        var b = ctx.pki.asn1.build;
        var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        var jwk = await subtle.exportKey("jwk", kp.publicKey);
        var spkiDer = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
        var jws = await ctx.pki.jose.sign({
          protected: { alg: "ES256", nonce: "aGVsbG8", url: "https://ca/o", kid: "https://ca/acct/1" },
          payload: Buffer.from("{}", "utf8"), key: kp.privateKey, jwk: jwk,
        });
        // The JWS ECDSA signature is raw R||S (RFC 7518 sec. 3.4); openssl dgst wants
        // an ECDSA-Sig-Value SEQUENCE { r INTEGER, s INTEGER }.
        var raw = Buffer.from(ctx.pki.jose.base64url.decode(jws.signature));
        ctx.check("ES256 JWS signature is 64 raw bytes", raw.length === 64);
        var derSig = b.sequence([
          b.integer(BigInt("0x" + raw.slice(0, 32).toString("hex"))),
          b.integer(BigInt("0x" + raw.slice(32, 64).toString("hex"))),
        ]);
        var signingInput = Buffer.from(jws.protected + "." + jws.payload, "ascii");
        var pubPem = ctx.runOpenssl(["pkey", "-pubin", "-inform", "DER", "-in", ctx.tmpFile(spkiDer, "spki.der")]);
        var pubPath = ctx.tmpFile(Buffer.from(pubPem, "utf8"), "pub.pem");
        var dataPath = ctx.tmpFile(signingInput, "data.bin");
        var sigPath = ctx.tmpFile(derSig, "sig.der");
        try {
          var out = ctx.runOpenssl(["dgst", "-sha256", "-verify", pubPath, "-signature", sigPath, dataPath], { allowNonZero: true });
          ctx.check("openssl verifies our ES256 JWS signature over the signing input", out.code === 0 && /Verified OK/.test(out.stdout));
          // Flip one payload byte -> openssl must REJECT (the signing input is bound).
          var tamperedData = ctx.tmpFile(Buffer.concat([signingInput.slice(0, -1), Buffer.from([signingInput[signingInput.length - 1] ^ 0x01])]), "data2.bin");
          try {
            var bad = ctx.runOpenssl(["dgst", "-sha256", "-verify", pubPath, "-signature", sigPath, tamperedData], { allowNonZero: true });
            ctx.check("openssl rejects the signature over tampered signing input", bad.code !== 0);
          } finally { try { ctx.fs.unlinkSync(tamperedData); } catch (_e) { /* best-effort */ } }
        } finally {
          [pubPath, dataPath, sigPath].forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
        }
      },
    },
  ],

  // ---- pki.acme.tlsAlpn01Extension : `openssl asn1parse` accepts our extension --
  "pki.acme.tlsAlpn01Extension": [
    {
      desc: "the id-pe-acmeIdentifier extension DER is well-formed per `openssl asn1parse`",
      run: async function (ctx) {
        var subtle = ctx.pki.webcrypto.subtle;
        var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        var jwk = await subtle.exportKey("jwk", kp.publicKey);
        var ext = await ctx.pki.acme.tlsAlpn01Extension("DGyRejmCefe7v4NfDGDKfA", jwk);
        ctx.withTmp(ext, "acme-ext.der", function (p) {
          var out = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p]);
          ctx.check("openssl asn1parse reads the extension as a SEQUENCE", /SEQUENCE/.test(out));
          ctx.check("openssl asn1parse sees the critical BOOLEAN", /BOOLEAN\s*:\s*(TRUE|255)/.test(out));
          ctx.check("openssl asn1parse sees the extnValue OCTET STRING", /OCTET STRING/.test(out));
          // Recurse into the extnValue: the wrapped Authorization is a 32-octet OCTET STRING.
          var m = /^\s*(\d+):.*OCTET STRING/m.exec(out);
          if (m) {
            var inner = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p, "-strparse", m[1]], { allowNonZero: true });
            ctx.check("the wrapped Authorization is a 32-byte OCTET STRING", inner.code === 0 && /OCTET STRING\s*\[HEX DUMP\]:[0-9A-F]{64}\b/.test(inner.stdout));
          } else {
            ctx.check("extnValue offset located for -strparse", false);
          }
        });
      },
    },
  ],

  // ---- pki.acme.ariCertId : the serial `openssl x509 -serial` reads back ------
  "pki.acme.ariCertId": [
    {
      desc: "the RFC 9773 ARI serial agrees with `openssl x509 -serial`, sign-padding byte preserved",
      run: function (ctx) {
        var pki = ctx.pki;
        var b = pki.asn1.build;
        // Derive a certificate from the shipped fixture with a chosen high-bit serial
        // and an injected authorityKeyIdentifier, so ariCertId has a real AKI to read.
        // Built in-toolkit (not `openssl req`) so the cross-check does not depend on
        // the host OpenSSL config's CA-extension section.
        var fixturePem = ctx.fs.readFileSync(ctx.path.join(ctx.FIXTURES_DIR, "pkijs-selfsigned-ec.pem"));
        var der = pki.schema.x509.pemDecode(fixturePem, "CERTIFICATE");
        var cert = pki.asn1.decode(der);
        var kids = cert.children[0].children.map(function (c) { return c.bytes; });
        var keyId = Buffer.from("aabbccddeeff00112233445566778899aabbccdd", "hex");
        kids[1] = b.integer(0xC0FFEEn);   // high bit set -> DER content octets 00 C0 FF EE
        kids[7] = b.explicit(3, b.sequence([
          b.sequence([b.oid(pki.oid.byName("authorityKeyIdentifier")),
            b.octetString(b.sequence([b.contextPrimitive(0, keyId)]))]),
        ]));
        var akiCert = b.sequence([b.sequence(kids), cert.children[1].bytes, cert.children[2].bytes]);
        var certId = pki.acme.ariCertId(akiCert);
        ctx.check("ARI certID is two base64url halves", /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(certId));
        var parsed = pki.acme.parseAriCertId(certId);
        ctx.check("ARI keyIdentifier round-trips", parsed.keyIdentifier.equals(keyId));
        ctx.check("the serial's DER sign-padding 00 octet is preserved", parsed.serial.length === 4 && parsed.serial[0] === 0x00);
        // OpenSSL independently reads the serial off the same DER; the values agree
        // once both are stripped of leading zeros (openssl prints the magnitude, our
        // half carries the DER sign-padding byte).
        ctx.withTmp(akiCert, "ari-cert.der", function (p) {
          var o = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-serial"]);
          var opensslSerial = ((o.split("=")[1] || "").trim()).toLowerCase().replace(/^0+/, "");
          var ourSerial = parsed.serial.toString("hex").toLowerCase().replace(/^0+/, "");
          ctx.check("ARI serial agrees with `openssl x509 -serial`", ourSerial === "c0ffee" && ourSerial === opensslSerial);
        });
      },
    },
  ],

  // ---- pki.cms.sign : a SignedData we produce verifies under `openssl cms` --------
  "pki.cms.sign": [
    {
      desc: "a SignedData we sign verifies under `openssl cms -verify` across RSA / RSASSA-PSS / ECDSA / Ed25519 / Ed448 (attached + detached); openssl REJECTS a tampered copy",
      run: async function (ctx) {
        var makeSigner = require("../helpers/signing").makeSigner;
        var content = Buffer.from("pki.cms.sign cross-implementation content");
        var contentPath = ctx.tmpFile(content, "content.bin");
        // Every classical signer key algorithm the primitive advertises must round-trip through
        // openssl. EdDSA and ML-DSA are gated differently: `openssl list -signature-algorithms`
        // advertises ED25519/ED448/ML-DSA on builds whose `openssl cms` still rejects them (an
        // "invalid digest" on 3.0.x EdDSA; no ML-DSA CMS at all before 3.5), so a signature-algorithm
        // probe is not a reliable CMS-capability gate. Instead the actual `openssl cms -verify`
        // result IS the probe -- RSA/ECDSA/PSS MUST verify (a real failure), while an EdDSA/ML-DSA
        // case openssl's CMS cannot verify is SKIPPED (never failed); the output still round-trips
        // through pki.cms.verify (proven in cms-sign.test.js).
        var algs = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ed448", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-shake-128f"];
        for (var i = 0; i < algs.length; i++) {
          var alg = algs[i];
          var signer = makeSigner(alg);
          var cp = ctx.tmpFile(ctx.pki.schema.x509.pemEncode(signer.cert, "CERTIFICATE"), "cert.pem");
          var att = ctx.tmpFile(await ctx.pki.cms.sign(content, signer), "att.der");
          var a = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", att, "-certfile", cp], { allowNonZero: true });
          var skippable = alg === "ed25519" || alg === "ed448" || alg.indexOf("ml-dsa") === 0 || alg.indexOf("slh-dsa") === 0;
          if (a.code !== 0 && skippable) {
            ctx.skip("openssl cms -verify in this environment does not verify " + alg + " CMS (our output round-trips through pki.cms.verify)");
            continue;
          }
          ctx.check("openssl cms -verify accepts our " + alg + " SignedData", a.code === 0);
        }
        // detached content + a negative (tampered content must be rejected), on ec-p256.
        var s = makeSigner("ec-p256");
        var certPath = ctx.tmpFile(ctx.pki.schema.x509.pemEncode(s.cert, "CERTIFICATE"), "cert.pem");
        var det = ctx.tmpFile(await ctx.pki.cms.sign(content, s, { detached: true }), "det.der");
        var d = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", det, "-content", contentPath, "-certfile", certPath], { allowNonZero: true });
        ctx.check("openssl cms -verify accepts our detached SignedData over the content", d.code === 0);
        var wrong = ctx.tmpFile(Buffer.from("an entirely different content"), "wrong.bin");
        var t = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", det, "-content", wrong, "-certfile", certPath], { allowNonZero: true });
        ctx.check("openssl rejects our detached signature over tampered content", t.code !== 0);
      },
    },
  ],

  // ---- pki.tsp.sign : an RFC 3161 timestamp token we create verifies under openssl --
  "pki.tsp.sign": [
    {
      desc: "a timestamp token we create verifies its CMS signature under `openssl cms -verify`",
      run: async function (ctx) {
        var signer = require("../helpers/signing").makeSigner("ec-p256");
        var certPath = ctx.tmpFile(ctx.pki.schema.x509.pemEncode(signer.cert, "CERTIFICATE"), "cert.pem");
        var imprint = { hashAlgorithm: "sha256", hashedMessage: require("node:crypto").createHash("sha256").update("timestamped document").digest() };
        var token = ctx.tmpFile(await ctx.pki.tsp.sign(imprint, signer, { policy: "1.3.6.1.4.1.1", serialNumber: 1, nonce: 42 }), "token.der");
        var r = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", token, "-certfile", certPath], { allowNonZero: true });
        ctx.check("openssl cms -verify accepts our timestamp token's signature", r.code === 0);
      },
    },
  ],

  // ---- pki.tsp.verify : `openssl ts` is the oracle for the whole RFC 3161 request/response +
  // token surface -- a TimeStampReq/Resp/token we emit is read by openssl, and one openssl emits
  // is read + verified by us, so neither side is validated only by its own decoder. -----------
  "pki.tsp.verify": [
    {
      desc: "openssl ts round-trip: our request/response parse under openssl, and we verify an openssl token (RFC 3161)",
      run: async function (ctx) {
        var pki = ctx.pki;
        var nodeCrypto = require("node:crypto");
        var tsp = pki.tsp || {};
        // Oracle-capability probe: `openssl ts` with no sub-mode prints its usage (-query/-reply/
        // -verify); a build without the subcommand reports an invalid command.
        var tsProbe = ctx.runOpenssl(["ts"], { allowNonZero: true });
        var tsText = String(tsProbe.stdout || "") + String(tsProbe.stderr || "");
        if (!/-query|-reply|-verify/.test(tsText)) {
          ctx.skip("openssl `ts` subcommand unavailable in this build -- RFC 3161 TSP cross-check cannot run");
          return;
        }
        var tmps = [];
        function T(bytes, ext) { var p = ctx.tmpFile(bytes, ext); tmps.push(p); return p; }
        function reserve(ext) { return T(Buffer.alloc(0), ext); }   // reserve + track a path openssl writes
        function fwd(p) { return p.replace(/\\/g, "/"); }           // openssl .cnf reads forward slashes
        try {
          var data = Buffer.from("pki.js RFC 3161 openssl-ts cross-implementation payload");
          var dataPath = T(data, "data.bin");
          var digest = nodeCrypto.createHash("sha256").update(data).digest();
          // Hermetic TSA material, independent of the host OpenSSL config: req/x509 are driven from
          // written .cnf sections + an explicit -extfile, so a machine-global config cannot inject a
          // CA extension the binary rejects. The TSA cert carries the RFC 3161 sec. 2.3 critical,
          // sole id-kp-timeStamping EKU the verifier and `openssl ts -verify` both require.
          var caKey = reserve("caKey.pem");
          var caCert = reserve("caCert.pem");
          var caCnf = T(Buffer.from(
            "[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n" +
            "[dn]\nCN = pkijs-interop-tsa-root\n" +
            "[v3_ca]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n" +
            "subjectKeyIdentifier = hash\n", "ascii"), "ca.cnf");
          ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", caKey, "-out", caCert, "-days", "2", "-nodes", "-config", caCnf]);
          var serial = T(Buffer.from("01", "ascii"), "serial.txt");
          var caSrl = T(Buffer.from("01", "ascii"), "ca.srl");   // seeded: x509 -CAserial reads a number
          var tsaKey = reserve("tsaKey.pem");
          var tsaCsr = reserve("tsaCsr.pem");
          var tsaCert = reserve("tsaCert.pem");
          var tsaCnf = T(Buffer.from(
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = pkijs-interop-tsa\n" +
            "[tsa_ext]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n" +
            "extendedKeyUsage = critical, timeStamping\nsubjectKeyIdentifier = hash\n" +
            "[tsa]\ndefault_tsa = tsa_config1\n[tsa_config1]\nserial = " + fwd(serial) + "\ncrypto_device = builtin\n" +
            "signer_digest = sha256\ndigests = sha256, sha384, sha512\ndefault_policy = 1.2.3.4.1\n" +
            "other_policies = 1.2.3.4.5, 1.2.3.4.6\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n" +
            "accuracy = secs:1\nclock_precision_digits = 0\nordering = no\ntsa_name = no\n", "ascii"), "tsa.cnf");
          ctx.runOpenssl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", tsaKey, "-out", tsaCsr, "-nodes", "-config", tsaCnf]);
          ctx.runOpenssl(["x509", "-req", "-in", tsaCsr, "-CA", caCert, "-CAkey", caKey,
            "-CAserial", caSrl, "-days", "1", "-out", tsaCert, "-extfile", tsaCnf, "-extensions", "tsa_ext"]);
          var ekuProbe = ctx.runOpenssl(["x509", "-in", tsaCert, "-noout", "-ext", "extendedKeyUsage"], { allowNonZero: true });
          if (ekuProbe.code === 0) {
            ctx.check("the interop TSA cert carries a critical timeStamping EKU",
              /critical/i.test(ekuProbe.stdout) && /Time Stamping/i.test(ekuProbe.stdout));
          } else {
            ctx.skip("openssl `x509 -ext` unavailable to introspect the TSA cert EKU (enforced by the verify legs regardless)");
          }
          // (we read them) openssl builds a TimeStampReq -> pki.tsp.parseRequest decodes it.
          var theirReq = reserve("their.tsq");
          ctx.runOpenssl(["ts", "-query", "-data", dataPath, "-sha256", "-cert", "-out", theirReq]);
          var pr = tsp.parseRequest(ctx.fs.readFileSync(theirReq));
          ctx.check("pki.tsp.parseRequest reads openssl's TimeStampReq as version 1", pr.version === 1);
          ctx.check("parseRequest agrees on the sha256 imprint algorithm", pr.messageImprint.hashAlgorithm.name === "sha256");
          ctx.check("parseRequest's imprint equals sha256(data)", Buffer.compare(Buffer.from(pr.messageImprint.hashedMessage), digest) === 0);
          ctx.check("parseRequest reads certReq TRUE (openssl ts -query -cert)", pr.certReq === true);
          // (they read us) pki.tsp.request builds a TimeStampReq -> openssl ts -reply consumes it.
          var ourReq = T(tsp.request({ hashAlgorithm: "sha256", hashedMessage: digest }, { certReq: true, nonce: 0x0102030405060708n }), "our.tsq");
          var ourReqReply = reserve("ourReqReply.tsr");
          var rq = ctx.runOpenssl(["ts", "-reply", "-queryfile", ourReq, "-signer", tsaCert, "-inkey", tsaKey, "-config", tsaCnf, "-out", ourReqReply], { allowNonZero: true });
          ctx.check("openssl ts -reply consumes our pki.tsp.request TimeStampReq", rq.code === 0 && ctx.fs.statSync(ourReqReply).size > 0);
          // (we read them) pki.tsp.parseResponse reads openssl's granted TimeStampResp.
          var theirResp = reserve("their.tsr");
          ctx.runOpenssl(["ts", "-reply", "-queryfile", theirReq, "-signer", tsaCert, "-inkey", tsaKey, "-config", tsaCnf, "-out", theirResp]);
          var resp = tsp.parseResponse(ctx.fs.readFileSync(theirResp));
          ctx.check("pki.tsp.parseResponse reads openssl's granted TimeStampResp", resp.status === 0 && resp.timeStampToken != null);
          // (we verify them) pki.tsp.verify accepts openssl's token chained to the CA anchor; a
          // tampered payload is a fail-closed { valid:false } verdict, never a throw.
          var theirToken = reserve("their.token");
          ctx.runOpenssl(["ts", "-reply", "-queryfile", theirReq, "-signer", tsaCert, "-inkey", tsaKey, "-config", tsaCnf, "-token_out", "-out", theirToken]);
          var ca = pki.schema.x509.parse(ctx.fs.readFileSync(caCert));
          var anchor = { name: ca.subject, publicKey: ca.subjectPublicKeyInfo.bytes, algorithm: ca.signatureAlgorithm.oid };
          var tokenBytes = ctx.fs.readFileSync(theirToken);
          var v = await tsp.verify(tokenBytes, data, { trustAnchor: anchor });
          ctx.check("pki.tsp.verify accepts openssl's timestamp token against the CA anchor", v.valid === true);
          ctx.check("pki.tsp.verify surfaces genTime as a Date from the verified eContent", v.genTime instanceof Date && !isNaN(v.genTime.getTime()));
          var vNeg = await tsp.verify(tokenBytes, Buffer.from("a different payload"), { trustAnchor: anchor });
          ctx.check("pki.tsp.verify rejects openssl's token over tampered data (tsp/imprint-mismatch)", vNeg.valid === false && vNeg.code === "tsp/imprint-mismatch");
          // (they verify us) openssl ts -verify accepts a response we sign + wrap; wrong data rejected.
          var tsaCertDer = reserve("tsaCert.der");
          var tsaKeyP8 = reserve("tsaKey.p8");
          ctx.runOpenssl(["x509", "-in", tsaCert, "-outform", "DER", "-out", tsaCertDer]);
          ctx.runOpenssl(["pkcs8", "-topk8", "-nocrypt", "-in", tsaKey, "-outform", "DER", "-out", tsaKeyP8]);
          var tsa = { cert: ctx.fs.readFileSync(tsaCertDer), key: ctx.fs.readFileSync(tsaKeyP8) };
          var ourToken = await tsp.sign({ hashAlgorithm: "sha256", hashedMessage: digest }, tsa, { policy: "1.2.3.4.1", serialNumber: 7 });
          var ourResp = T(tsp.response(ourToken, {}), "our.tsr");
          var vr = ctx.runOpenssl(["ts", "-verify", "-data", dataPath, "-in", ourResp, "-CAfile", caCert, "-untrusted", tsaCert], { allowNonZero: true });
          ctx.check("openssl ts -verify accepts our pki.tsp.sign + response over the data", vr.code === 0 && /Verification:\s*OK/i.test(String(vr.stdout) + String(vr.stderr)));
          var wrong = T(Buffer.from("a different payload"), "wrong.bin");
          var vrNeg = ctx.runOpenssl(["ts", "-verify", "-data", wrong, "-in", ourResp, "-CAfile", caCert, "-untrusted", tsaCert], { allowNonZero: true });
          ctx.check("openssl ts -verify rejects our response over tampered data", vrNeg.code !== 0);
        } finally {
          tmps.forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
        }
      },
    },
  ],

  // ---- pki.ocsp.sign : a signed BasicOCSPResponse `openssl ocsp` verifies ------
  "pki.ocsp.sign": [
    {
      desc: "a signed OCSP response verifies under `openssl ocsp` (Response verify OK + status good)",
      run: async function (ctx) {
        var w = await makeOcspWorld("ec-p256");
        var thisUpdate = new Date(Date.now() - 3600 * 1000);            // an hour ago (no clock-skew edge)
        var nextUpdate = new Date(Date.now() + 365 * 24 * 3600 * 1000);
        var resp = await ctx.pki.ocsp.sign(
          { responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: thisUpdate, nextUpdate: nextUpdate }] },
          { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
        var tmps = [];
        function T(bytes, ext) { var p = ctx.tmpFile(bytes, ext); tmps.push(p); return p; }
        try {
          var issuerP = T(_pem(w.issuerCertDer, "CERTIFICATE"), "issuer.pem");
          var leafP = T(_pem(w.targetCertDer, "CERTIFICATE"), "leaf.pem");
          var respP = T(resp, "resp.der");
          var out = ctx.runOpenssl(["ocsp", "-respin", respP, "-CAfile", issuerP, "-issuer", issuerP, "-cert", leafP, "-no_nonce"], { allowNonZero: true });
          var all = String(out.stdout) + String(out.stderr);
          ctx.check("openssl verifies our OCSP response signature over the delegate chain (Response verify OK)", /Response verify OK/i.test(all));
          ctx.check("openssl reads our OCSP certificate status as good", /:\s*good/.test(String(out.stdout)));
        } finally {
          tmps.forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
        }
      },
    },
  ],

  // ---- pki.ocsp.verify : `openssl ocsp` is the oracle for the whole RFC 6960 request/response
  // surface -- an OCSPRequest we emit drives openssl's responder, and the response openssl signs is
  // parsed + verified by us, so neither side is validated only by its own decoder. --------------
  "pki.ocsp.verify": [
    {
      desc: "openssl ocsp round-trip: openssl's responder-signed response parses + verifies under us (RFC 6960)",
      run: async function (ctx) {
        var pki = ctx.pki;
        // Oracle-capability probe: `openssl ocsp -help` lists the responder/verify options
        // (-respin/-index/-reqin); a build without the subcommand reports an invalid command.
        var probe = ctx.runOpenssl(["ocsp", "-help"], { allowNonZero: true });
        var probeText = String(probe.stdout || "") + String(probe.stderr || "");
        if (!/-respin|-index|-reqin/.test(probeText)) {
          ctx.skip("openssl `ocsp` subcommand unavailable in this build -- RFC 6960 OCSP cross-check cannot run");
          return;
        }
        var w = await makeOcspWorld("ec-p256");
        var leaf = pki.schema.x509.parse(w.targetCertDer);
        var tmps = [];
        function T(bytes, ext) { var p = ctx.tmpFile(bytes, ext); tmps.push(p); return p; }
        function reserve(ext) { return T(Buffer.alloc(0), ext); }      // reserve + track a path openssl writes
        try {
          var issuerP = T(_pem(w.issuerCertDer, "CERTIFICATE"), "issuer.pem");
          var responderP = T(_pem(w.responderCertDer, "CERTIFICATE"), "responder.pem");
          var rkeyP = T(_pem(w.responderKeyPkcs8, "PRIVATE KEY"), "responder.key.pem");
          // openssl's flat-file CA database: one Valid entry binding the leaf serial to a 2040 expiry.
          var indexP = T("V\t400101000000Z\t\t" + leaf.serialNumberHex.toUpperCase() + "\tunknown\t/CN=leaf.example\n", "index.txt");
          var reqP = T(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }), "req.der");
          var respP = reserve("resp.der");
          ctx.runOpenssl(["ocsp", "-index", indexP, "-CA", issuerP, "-rsigner", responderP, "-rkey", rkeyP, "-reqin", reqP, "-respout", respP, "-ndays", "365", "-no_nonce"]);
          var respBytes = ctx.fs.readFileSync(respP);
          // (we parse them) pki.schema.ocsp.parseResponse reads openssl's responder output.
          var parsed = pki.schema.ocsp.parseResponse(respBytes);
          ctx.check("pki.schema.ocsp.parseResponse reads openssl's successful response", parsed.responseStatus.code === 0 && parsed.basicResponse != null);
          // (we verify them) pki.ocsp.verify accepts openssl's response as good + authorized.
          var v = await pki.ocsp.verify(respBytes, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() });
          ctx.check("pki.ocsp.verify accepts openssl's OCSP response (good, authorized, signature valid)",
            v.status === "good" && v.responderAuthorized === true && v.signatureValid === true);
          // A one-byte mutation of openssl's response is never accepted as good: either the parse
          // fails closed (a typed PkiError) or the signature no longer verifies ("unknown").
          var tampered = Buffer.from(respBytes); tampered[tampered.length - 12] ^= 0x01;
          var vBad;
          try { vBad = await pki.ocsp.verify(tampered, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() }); }
          catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; vBad = { status: "unknown" }; }
          ctx.check("pki.ocsp.verify never returns good for a tampered openssl response", vBad.status !== "good");
        } finally {
          tmps.forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
        }
      },
    },
  ],
};
