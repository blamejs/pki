// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — documented-surface coverage. Walks every @module / @primitive block
 * (the SAME source-doc-parser walk the wiki pages + the comment-block validator
 * use) and enforces that the JSDoc is not just well-formed but TRUE:
 *
 *   1. RESOLVES  — every `@primitive pki.X.Y` path resolves to a defined export.
 *      A documented path that is `undefined` at runtime (a rename, a wrong
 *      namespace) is a broken public surface the wiki would render a dead page for.
 *
 *   2. EXECUTES  — every `@example` body actually RUNS (not just parses). Each is
 *      executed with `pki` + a per-namespace fixture (a real certificate and a
 *      minimal valid instance of each format) in scope; the contract is the fuzz
 *      contract — an example either completes or throws a `pki.errors.PkiError`.
 *      A ReferenceError / TypeError / SyntaxError (a non-resolving path used in the
 *      example, an undefined symbol, a wrong call shape) is a finding. This is what
 *      the comment-block validator's parse-only `@example` check cannot catch.
 *
 *   3. TESTED    — every `@primitive` is referenced by its full path from some
 *      *.test.js (advertised surface must be exercised by name).
 *
 *   4. README    — every `@module` namespace is described in README.md.
 */

var path = require("node:path");
var vm = require("node:vm");
var fs = require("node:fs");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var parser = require(path.join(__dirname, "..", "..", "examples", "wiki", "lib", "source-doc-parser"));

var ROOT = path.join(__dirname, "..", "..");

// ---- fixtures: a real cert + a minimal valid instance of each format ----
function algId(o) { return b.sequence([b.oid(o)]); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function iasn(cn, s) { return b.sequence([name(cn), b.integer(BigInt(s))]); }
function gt(iso) { return b.generalizedTime(new Date(iso)); }
function toPem(der, label) {
  var body = Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
}
var SIG = "1.2.840.10045.4.3.2", DATA = "1.2.840.113549.1.7.1", DIG = "2.16.840.1.101.3.4.2.1";
var CT_ATTR = "1.2.840.113549.1.9.3", MD_ATTR = "1.2.840.113549.1.9.4", TSTINFO = "1.2.840.113549.1.9.16.1.4";

var certPem = helpers.vectors.CERT_EC_PEM;
var certDer = pki.schema.x509.pemDecode(certPem, "CERTIFICATE");

// a CRL with one revoked entry (so crl.revokedCertificates[0].serialNumberHex resolves).
var revoked = b.sequence([b.sequence([b.integer(5n), b.utcTime(new Date("2026-01-01T00:00:00Z"))])]);
var crlDer = b.sequence([b.sequence([algId(SIG), name("CA"), b.utcTime(new Date("2026-01-01T00:00:00Z")), revoked]), algId(SIG), b.bitString(Buffer.from([0]), 0)]);
var spki = b.sequence([algId("1.2.840.10045.2.1"), b.bitString(Buffer.from([4, 1, 2]), 0)]);
// a CSR with one requested attribute (so csr.attributes[0].type resolves).
var csrAttrs = b.contextConstructed(0, Buffer.concat([b.sequence([b.oid("1.2.840.113549.1.9.14"), b.set([b.sequence([])])])]));
var csrDer = b.sequence([b.sequence([b.integer(0n), name("S"), spki, csrAttrs]), algId(SIG), b.bitString(Buffer.from([0]), 0)]);
var pkcs8Der = b.sequence([b.integer(0n), algId("1.2.840.10045.2.1"), b.octetString(Buffer.from([1, 2, 3]))]);
// A SignedData with one (IAS) signerInfo over id-data content, so the documented
// example's cms.signerInfos[0].sid.serialNumberHex resolves.
var cmsSigner = b.sequence([b.integer(1n), iasn("Signer", 7), algId(DIG), algId(SIG), b.octetString(Buffer.from([1, 2, 3]))]);
var cmsDer = b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, b.sequence([b.integer(1n), b.set([algId(DIG)]), b.sequence([b.oid(DATA)]), b.set([cmsSigner])]))]);
var ocspDer = b.sequence([b.sequence([b.sequence([b.sequence([b.sequence([algId(DIG), b.octetString(Buffer.from([1])), b.octetString(Buffer.from([2])), b.integer(5n)])])])])]);
var acinfo = b.sequence([b.integer(1n), b.sequence([b.contextConstructed(1, Buffer.concat([b.explicit(4, name("H"))]))]), b.contextConstructed(0, Buffer.concat([b.sequence([b.explicit(4, name("I"))])])), algId(SIG), b.integer(7n), b.sequence([gt("2026-01-01T00:00:00Z"), gt("2027-01-01T00:00:00Z")]), b.sequence([b.sequence([b.oid("2.5.4.72"), b.set([b.utf8("a")])])])]);
var attrcertDer = b.sequence([acinfo, algId(SIG), b.bitString(Buffer.from([0]), 0)]);

// A valid RFC 3161 timestamp token (CMS SignedData over an id-ct-TSTInfo eContent).
var tstInfo = b.sequence([b.integer(1n), b.oid("1.2.3.4"), b.sequence([algId(DIG), b.octetString(Buffer.alloc(32, 1))]), b.integer(9n), gt("2026-01-01T00:00:00Z")]);
var signedAttrs = b.contextConstructed(0, Buffer.concat([b.sequence([b.oid(CT_ATTR), b.set([b.oid(TSTINFO)])]), b.sequence([b.oid(MD_ATTR), b.set([b.octetString(Buffer.alloc(32, 2))])])].sort(Buffer.compare)));
var signerInfo = b.sequence([b.integer(1n), iasn("TSA", 7), algId(DIG), signedAttrs, algId(SIG), b.octetString(Buffer.from([1, 2, 3]))]);
var tstToken = b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, b.sequence([b.integer(3n), b.set([algId(DIG)]), b.sequence([b.oid(TSTINFO), b.explicit(0, b.octetString(tstInfo))]), b.set([signerInfo])]))]);
// a GRANTED TimeStampResp carrying that token (so tsp.parse's example resolves
// res.timeStampToken.tstInfo.genTime).
var tspDer = b.sequence([b.sequence([b.integer(0n)]), tstToken]);

// A one-message CertReqMessages (so crmf.parse's example resolves
// m.messages[0].certReq.certTemplate.subject.dn).
var certTemplate = b.sequence([b.explicit(5, name("req.example"))]);
var crmfDer = b.sequence([b.sequence([b.sequence([b.integer(1n), certTemplate])])]);

// A minimal valid RFC 6962 SCT-list extension value (the inner DER OCTET STRING
// wrapping the TLS list) so the pki.ct examples exercise the real parse path.
function _sctU16(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }
var _sctBody = Buffer.concat([
  Buffer.from([0]), Buffer.alloc(32, 0xAB), (function () { var t = Buffer.alloc(8); t.writeBigUInt64BE(1700000000000n); return t; })(),
  _sctU16(0), Buffer.from([4, 3]), _sctU16(5), Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]),
]);
var _sctSer = Buffer.concat([_sctU16(_sctBody.length), _sctBody]);
var sctListDer = b.octetString(Buffer.concat([_sctU16(_sctSer.length), _sctSer]));

// A minimal error PKIMessage (so cmp.parse's example resolves m.body.arm).
var cmpHeader = b.sequence([b.integer(2n), b.contextConstructed(4, b.sequence([])), b.contextConstructed(4, name("CA"))]);
var cmpBody = b.explicit(23, b.sequence([b.sequence([b.integer(2n)])]));
var cmpDer = b.sequence([cmpHeader, cmpBody]);

// A minimal password-integrity PFX with one certBag (so pkcs12.parse's example
// maps safeBags[].type).
var certBagValue = b.sequence([b.oid("1.2.840.113549.1.9.22.1"), b.explicit(0, b.octetString(certDer))]);
var safeBag = b.sequence([b.oid("1.2.840.113549.1.12.10.1.3"), b.explicit(0, certBagValue)]);
var authenticatedSafe = b.sequence([b.sequence([b.oid(DATA), b.explicit(0, b.octetString(b.sequence([safeBag])))])]);
var macData = b.sequence([b.sequence([algId(DIG), b.octetString(Buffer.alloc(32, 2))]), b.octetString(Buffer.alloc(8, 3)), b.integer(2048n)]);
var pkcs12Der = b.sequence([b.integer(3n), b.sequence([b.oid(DATA), b.explicit(0, b.octetString(authenticatedSafe))]), macData]);

// A valid EST CsrAttrs (so csrattrs.parse's example maps a.items[0].kind).
var csrattrsDer = b.sequence([b.oid("1.2.840.113549.1.9.7"), b.sequence([b.oid("1.2.840.113549.1.1.1"), b.set([b.integer(2048n)])])]);
// A certs-only CMS Simple PKI Response (so est.parseCertsOnly's example resolves
// r.certificates): SignedData v1, id-data no eContent, one cert, empty signerInfos.
var caCertsDer = b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, b.sequence([b.integer(1n), b.set([]), b.sequence([b.oid(DATA)]), b.contextConstructed(0, certDer), b.set([])]))]);

// pki.sigstore fixtures: a REAL npm provenance bundle + the public-good sigstore
// trust material, so verifyBundle's example runs the actual end-to-end verify.
var sigstoreBundle = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "sigstore", "npm-provenance-bundle.json"), "utf8"));
var sigstoreTrustRoot = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "sigstore", "trusted-root.json"), "utf8"));
var sigstoreTrust = {
  fulcioRoots: [],
  rekorKeys: (sigstoreTrustRoot.tlogs || []).map(function (t) { return { keyId: Buffer.from((t.logId && t.logId.keyId) || "", "base64"), spki: Buffer.from((t.publicKey && t.publicKey.rawBytes) || "", "base64") }; }),
};
(sigstoreTrustRoot.certificateAuthorities || []).forEach(function (ca) { ((ca.certChain && ca.certChain.certificates) || []).forEach(function (c) { sigstoreTrust.fulcioRoots.push(Buffer.from(c.rawBytes, "base64")); }); });

// pki.webauthn fixtures: a REAL packed attestation + its clientDataHash, so
// parseAttestationObject's and verify's examples run the actual decode + verify.
var webauthnKat = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "webauthn", "py-webauthn-kat.json"), "utf8"));
function _b64u(s) { var x = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (x.length % 4) x += "="; return Buffer.from(x, "base64"); }
var webauthnAttObj = _b64u(webauthnKat.formats.packed.attestationObject);
var webauthnClientHash = require("node:crypto").createHash("sha256").update(_b64u(webauthnKat.formats.packed.clientDataJSON)).digest();

// pki.cms fixtures: a REAL detached SignedData + its external content, so verify's
// example runs the actual RFC 5652 sec. 5.4 preimage + signature verification.
var cmsDetachedDer = fs.readFileSync(path.join(__dirname, "..", "fixtures", "cms", "rsa-detached.p7s"));
var cmsDetachedContent = Buffer.from("hello CMS SignedData verification");

// pki.cms.sign / pki.tsp.sign fixtures: a runtime signer (keypair + minimal cert, since a
// private key cannot be committed) + a message digest, so the signing examples run for real.
var signFixtureSigner = require("../helpers/signing").makeSigner("ec-p256");
var cmsSha256Digest = require("node:crypto").createHash("sha256").update("hello").digest();

// Per-namespace { der, pemText, label }. A parse example gets a format-appropriate
// valid input so the happy path actually runs; where a perfect input is heavy the
// worst case is a typed PkiError, which the contract allows.
var FMT = {
  "pki.schema.x509":     { der: certDer, label: "CERTIFICATE" },
  "pki.schema.crl":      { der: crlDer, label: "X509 CRL" },
  "pki.schema.csr":      { der: csrDer, label: "CERTIFICATE REQUEST" },
  "pki.schema.pkcs8":    { der: pkcs8Der, label: "PRIVATE KEY" },
  "pki.schema.cms":      { der: cmsDer, label: "CMS" },
  "pki.schema.ocsp":     { der: ocspDer, label: "OCSP REQUEST" },
  "pki.schema.tsp":      { der: tspDer, label: "TIMESTAMP" },
  "pki.schema.attrcert": { der: attrcertDer, label: "ATTRIBUTE CERTIFICATE" },
  "pki.schema.crmf":     { der: crmfDer, label: "CERTIFICATE REQUEST MESSAGE" },
  "pki.schema.pkcs12":   { der: pkcs12Der, label: "PKCS12" },
  "pki.schema.cmp":      { der: cmpDer, label: "CMP" },
  "pki.schema.csrattrs": { der: csrattrsDer, label: "CSRATTRS" },
};
function fixturesFor(tag) {
  var fmt = null;
  Object.keys(FMT).forEach(function (k) { if (tag.indexOf(k + ".") === 0) fmt = FMT[k]; });
  var der = fmt ? fmt.der : certDer;
  var label = fmt ? fmt.label : "CERTIFICATE";
  return {
    pki: pki, Buffer: Buffer, console: { log: function () {}, error: function () {} },
    der: der, input: der, bytes: der, node: pki.asn1.decode(certDer),
    pemText: toPem(der, label), pemString: toPem(der, label), pem: toPem(der, label),
    tokenDer: tstToken, tokenBytes: tstToken,
    // EST fixtures: a certs-only bag for est.parseCertsOnly's example.
    caCertsDer: caCertsDer, roundTripped: null,
    // RFC 6962 SCT-list extension value (inner DER OCTET STRING) for the pki.ct examples.
    sctExtValue: sctListDer,
    // the stand-in "your error class" some engine examples pass as ctx.E — a
    // PkiError factory so a thrown result still satisfies the fuzz-style contract.
    MyError: function (code, msg) { return new pki.errors.PkiError(msg, code); },
    // pki.jose / pki.acme fixtures. The pure examples run on a real static EC JWK
    // and a valid token; the builder examples reference `key`/`priv` as undefined
    // so the builder fails closed with a typed PkiError before any crypto (the
    // contract accepts a completed run OR a PkiError). certDer is a real cert with
    // no acmeIdentifier / AKI, so verifyTlsAlpn01 and ariCertId throw a typed fault.
    accountJwk: JOSE_EC_JWK, jwk: JOSE_EC_JWK, oldJwk: JOSE_EC_JWK, newJwk: JOSE_EC_JWK,
    token: "DGyRejmCefe7v4NfDGDKfA",
    orderObj: {}, jws: {}, hdr: {},
    key: undefined, priv: undefined, oldKey: undefined, newKey: undefined, macKey: undefined,
    nonce: "aGVsbG8", url: "https://ca/o", orderUrl: "https://ca/o/1", challUrl: "https://ca/chall/1",
    authzUrl: "https://ca/authz/1", kid: "https://ca/acct/1",
    certDer: certDer, csrDer: csrDer, identifiers: [{ type: "dns", value: "example.org" }],
    // pki.sigstore: a real bundle + trust material so verifyBundle's example runs
    // the full offline verification path.
    bundle: sigstoreBundle, sigstoreTrust: sigstoreTrust,
    // pki.webauthn: a real packed attestation + its clientDataHash so the parse
    // and verify examples run the actual decode + attestation-statement verify.
    attestationObject: webauthnAttObj, clientDataHash: webauthnClientHash,
    // pki.cms: a real detached SignedData + its external content so verify's example
    // runs the full parse + message-digest + signature verification path.
    p7sDer: cmsDetachedDer, detachedBytes: cmsDetachedContent,
    // pki.cms.sign / pki.tsp.sign: a real signer certificate + PKCS#8 key + a digest.
    signerCertDer: signFixtureSigner.cert, signerKeyPkcs8: signFixtureSigner.key, sha256Digest: cmsSha256Digest,
    // pki.ocsp: a leaf + issuer (the same real EC cert stands in for both) + a
    // responder cert/key, and a real signed BasicOCSPResponse (built in run()) so
    // buildRequest / sign / verify run the actual code path to a fail-closed verdict.
    leafDer: certDer, caDer: certDer,
    responderCertDer: signFixtureSigner.cert, responderPkcs8: signFixtureSigner.key,
    responseDer: ocspResponseDer,
    // pki.cms.encrypt / decrypt: a real RSA recipient + a real encrypted envelope so the examples
    // run the actual encrypt/decrypt path (built in run()).
    recipientCertDer: cmsRecipient && cmsRecipient.cert, recipientKeyPkcs8: cmsRecipient && cmsRecipient.key,
    envDer: cmsEnvDer,
    // pki.cms.decompress / pki.smime.decompress: a real CompressedData + compressed S/MIME message.
    compressedDer: cmsCompressedDer, compressedSmimeBytes: smimeCompressedBytes,
    // pki.smime.verify: a real signed multipart/signed S/MIME message.
    smimeMessageBytes: smimeMessageBytes,
  };
}
var cmsRecipient = null, cmsEnvDer = null, smimeMessageBytes = null;
var cmsCompressedDer = null, smimeCompressedBytes = null;
// A real signed BasicOCSPResponse for the pki.ocsp.verify @example, built at run()
// start (signing is async so it cannot be a module-load constant).
var ocspResponseDer = null;
// A real RFC 7515 Appendix A.3 P-256 public JWK — the jose/acme pure examples
// (thumbprint, key authorization, the challenge computations) run against it.
var JOSE_EC_JWK = { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" };

// Concatenated source of every test/**/*.test.js EXCEPT this harness, so a
// primitive path mentioned only here can never satisfy its own TESTED gate.
function _testSources() {
  var out = [];
  (function walkDir(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
      var full = path.join(dir, e.name);
      if (e.isDirectory()) { walkDir(full); return; }
      if (!e.name.endsWith(".test.js")) return;
      if (path.resolve(full) === path.resolve(__filename)) return;
      out.push(fs.readFileSync(full, "utf8"));
    });
  })(path.join(ROOT, "test"));
  return out.join("\n");
}

// ---- the walk --------------------------------------------------------
async function run() {
  ocspResponseDer = await pki.ocsp.sign(
    { responderID: "byName", responses: [{ cert: certDer, issuer: certDer, status: "good" }] },
    { cert: signFixtureSigner.cert, key: signFixtureSigner.key });
  cmsRecipient = require("../helpers/signing").makeRecipient("rsa");
  cmsEnvDer = await pki.cms.encrypt(Buffer.from("secret"), [{ cert: cmsRecipient.cert }]);
  cmsCompressedDer = await pki.cms.compress(Buffer.from("compress me"));
  smimeCompressedBytes = await pki.smime.compress(Buffer.from("compress this message"));
  smimeMessageBytes = await pki.smime.sign(Buffer.from("hello"), [{ cert: signFixtureSigner.cert, key: signFixtureSigner.key }]);

  var docs = parser.parseTree(path.join(ROOT, "lib"));

  var readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  var testSources = _testSources();

  var seenNs = {};
  var names = Object.keys(docs);
  for (var fi = 0; fi < names.length; fi++) {
    var rec = docs[names[fi]];

    // README coverage — per @module namespace.
    if (rec.module) {
      var ns = String(rec.module.tags.module || "").trim();
      if (ns && !seenNs[ns]) {
        seenNs[ns] = true;
        check("README describes namespace " + ns, readme.indexOf(ns) !== -1);
      }
    }

    for (var pi = 0; pi < rec.primitives.length; pi++) {
      var p = rec.primitives[pi];
      var tag = p.tags && p.tags.primitive;
      if (!tag) continue;

      // 1. the documented path resolves to a defined export.
      var resolved = tag.replace(/^pki\./, "").split(".").reduce(function (o, k) { return o == null ? o : o[k]; }, pki);
      check(tag + " resolves to a defined export", resolved !== undefined && resolved !== null);

      // 3. the advertised surface is exercised by name: some *.test.js
      // (other than this harness) references the primitive's full path.
      check(tag + " is referenced by full path from a *.test.js", testSources.indexOf(tag) !== -1);

      // 2. every @example executes (completes OR throws a typed PkiError).
      var exs = (p.tags && p.tags.examples) || [];
      for (var ei = 0; ei < exs.length; ei++) {
        var body = exs[ei];
        var verdict = "ok";
        try {
          var ctx = vm.createContext(fixturesFor(tag));
          var res = vm.runInContext("(async function () {\n" + body + "\n})()", ctx, { timeout: 8000, filename: tag + ".example.js" });
          await res;
        } catch (e) {
          verdict = (e instanceof pki.errors.PkiError) ? "ok" : ("RAW:" + (e && e.constructor && e.constructor.name) + ":" + (e && e.message || "").split("\n")[0]);
        }
        check(tag + " @example #" + (ei + 1) + " executes (completes or PkiError)", verdict === "ok");
      }
    }
  }
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error((e && e.stack) || String(e)); process.exit(1); }
  );
}
