// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 9483 sec. 4.1.6 centrally generated key delivery (pki.cmp.openKeyPackage)
 * cross-implementation interop.
 *
 * The container this verb opens is produced by a certification authority, never by this toolkit, so
 * the cross-check runs in the direction that matters: OpenSSL builds the layers and the toolkit reads
 * them.
 *  (a) OpenSSL signs the RFC 5958 AsymmetricKeyPackage into a CMS SignedData under the key generation
 *      authority's key, with the id-ct-KP-aKeyPackage content type and a subjectKeyIdentifier signer
 *      identifier -- an independent SignerInfo, signed-attribute set and signature for the toolkit's
 *      verify path to accept, and the layer the RFC's authorization rules are read off.
 *  (b) The toolkit seals that SignedData and opens the whole container, recovering the delivered
 *      private key byte-for-byte and reporting the authority chained.
 *  (c) OpenSSL reads the sealed container back: `cms -decrypt` under the end entity's key recovers the
 *      exact SignedData it produced, and `cms -verify` accepts that SignedData against the authority's
 *      certificate, so the outer layer the toolkit accepts is one an independent implementation
 *      produces and reads.
 *  (d) An authority certificate with no id-kp-cmKGA extended key usage is refused, over a container
 *      OpenSSL signed the same way, so the authorization rule holds against a foreign signer and not
 *      only against a toolkit-built one.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var nodeCrypto = require("node:crypto");
var b = pki.asn1.build;

var NB = new Date("2020-01-01T00:00:00Z"), NA = new Date("2040-01-01T00:00:00Z");
var A_KEY_PACKAGE = pki.oid.byName("aKeyPackage");

function pem(label, der) {
  var b64 = Buffer.from(der).toString("base64");
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return "-----BEGIN " + label + "-----\n" + lines.join("\n") + "\n-----END " + label + "-----\n";
}

async function selfSigned(kind, cn, extensions) {
  var kp = nodeCrypto.generateKeyPairSync.apply(nodeCrypto,
    kind === "rsa" ? ["rsa", { modulusLength: 2048 }] : ["ec", { namedCurve: "prime256v1" }]);
  var key = kp.privateKey.export({ format: "der", type: "pkcs8" });
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  return { key: key, keyPem: pem("PRIVATE KEY", key),
    cert: await pki.x509.sign({ subject: cn, subjectPublicKey: spki, notBefore: NB, notAfter: NA,
      extensions: extensions }, { key: key }) };
}

// runOpenssl decodes stdout as text, so a DER result is written to a file with `-out` and read back
// as bytes; `args` is completed with the output path.
function opensslDer(argsFor) {
  return ctx.withTmp(Buffer.alloc(0), "out.der", function (outPath) {
    ctx.runOpenssl(argsFor(outPath).concat(["-out", outPath]));
    return ctx.fs.readFileSync(outPath);
  });
}

// OpenSSL signs the key package: an independent SignedData for the toolkit's verify path to read.
function opensslSignPackage(pkgDer, kga) {
  return ctx.withTmp(Buffer.from(pkgDer), "akp.der", function (pkgPath) {
    return ctx.withTmp(Buffer.from(kga.keyPem, "utf8"), "kga.key.pem", function (keyPath) {
      return ctx.withTmp(Buffer.from(pem("CERTIFICATE", kga.cert), "utf8"), "kga.cert.pem", function (certPath) {
        return opensslDer(function () {
          return ["cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-keyid",
            "-md", "sha256", "-econtent_type", A_KEY_PACKAGE, "-in", pkgPath, "-inform", "DER",
            "-signer", certPath, "-inkey", keyPath, "-outform", "DER"];
        });
      });
    });
  });
}

async function run() {
  var KGA_EXTS = { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"],
    subjectKeyIdentifier: true };
  var kga = await selfSigned("ec", "OpenSSL Key Generation Authority",
    Object.assign({ extendedKeyUsage: ["cmKGA"] }, KGA_EXTS));
  var plain = await selfSigned("ec", "OpenSSL Signer Without The Purpose", KGA_EXTS);
  var ee = await selfSigned("rsa", "Enrolling client", { keyUsage: ["keyEncipherment"] });
  var delivered = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .privateKey.export({ format: "der", type: "pkcs8" });
  var pkgDer = b.sequence([b.raw(delivered)]);

  var signed = opensslSignPackage(pkgDer, kga);
  check("openssl produced a CMS SignedData over the AsymmetricKeyPackage", signed.length > 0);
  var parsedSigned = pki.schema.cms.parse(signed);
  check("and the toolkit reads it as a SignedData carrying id-ct-KP-aKeyPackage",
    parsedSigned.contentTypeName === "signedData" &&
    parsedSigned.encapContentInfo.eContentType === A_KEY_PACKAGE);

  var container = await pki.cms.encrypt(signed, [{ cert: ee.cert }],
    { contentEncryptionAlgorithm: "aes-256-cbc", contentType: "signedData" });
  var opened = await pki.cmp.openKeyPackage(container,
    { key: ee.key, cert: ee.cert, trustAnchors: [kga.cert] });
  check("pki.cmp.openKeyPackage opens an openssl-signed key package and recovers the delivered key",
    opened.keys.length === 1 && opened.keys[0].equals(delivered));
  check("and reports the openssl-issued authority certificate as the chained signer",
    opened.trusted === true && opened.kga.equals(kga.cert));

  // OpenSSL reads the sealed container back: decrypt recovers the exact SignedData, and verify
  // accepts that SignedData against the authority's certificate.
  var recovered = ctx.withTmp(Buffer.from(container), "container.der", function (envPath) {
    return ctx.withTmp(Buffer.from(ee.keyPem, "utf8"), "ee.key.pem", function (keyPath) {
      return ctx.withTmp(Buffer.from(pem("CERTIFICATE", ee.cert), "utf8"), "ee.cert.pem", function (certPath) {
        return opensslDer(function () {
          return ["cms", "-decrypt", "-binary", "-inform", "DER", "-in", envPath,
            "-recip", certPath, "-inkey", keyPath, "-outform", "DER"];
        });
      });
    });
  });
  check("openssl cms -decrypt recovers the exact SignedData from the sealed container",
    recovered.equals(signed));
  var verified = ctx.withTmp(Buffer.from(signed), "signed.der", function (sigPath) {
    return ctx.withTmp(Buffer.from(pem("CERTIFICATE", kga.cert), "utf8"), "anchor.pem", function (anchorPath) {
      return ctx.withTmp(Buffer.alloc(0), "verified.der", function (outPath) {
        return ctx.runOpenssl(["cms", "-verify", "-binary", "-inform", "DER", "-in", sigPath,
          "-CAfile", anchorPath, "-purpose", "any", "-out", outPath], { allowNonZero: true });
      });
    });
  });
  check("openssl cms -verify accepts the SignedData against the authority certificate",
    verified.code === 0);

  // The authorization rule holds against a foreign signer: openssl signs the identical package under a
  // certificate carrying no id-kp-cmKGA, and the container is refused with no key surfaced.
  var noPurpose = opensslSignPackage(pkgDer, plain);
  var refused = await pki.cms.encrypt(noPurpose, [{ cert: ee.cert }],
    { contentEncryptionAlgorithm: "aes-256-cbc", contentType: "signedData" });
  var code = null;
  try { await pki.cmp.openKeyPackage(refused, { key: ee.key, cert: ee.cert, trustAnchors: [plain.cert] }); }
  catch (e) { code = e && e.code; }
  check("an openssl-signed package whose signer does not assert id-kp-cmKGA is refused",
    code === "cmp/unauthorized-kga");
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
