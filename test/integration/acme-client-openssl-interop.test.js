// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- ACME client (RFC 8555) cross-implementation interop.
 *
 * There is no `openssl acme`, so the oracle drops to the COMPOSED layer: every authenticated ACME
 * request the client puts on the wire is a Flattened JWS (RFC 7515) signed with the account key, and
 * `openssl dgst -verify` is an independent verifier of that ES256 signature. The client is driven
 * against an INJECTED routing transport (no live CA), the JWS it emits for newAccount (jwk mode) and
 * newOrder (kid mode) is captured off transport.calls, and OpenSSL -- using ONLY the account public
 * key exported as SPKI -- must verify the signature over the exact `base64url(protected).base64url(payload)`
 * signing input. This proves the bytes our client signs are verifiable by an unrelated implementation,
 * and that each JWS is bound to its target URL (RFC 8555 sec. 6.4) and carries a fresh nonce (sec. 6.5).
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var A = require("../helpers/acme-transport");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var b = pki.asn1.build;

// An ES256 JOSE signature is the raw R||S pair (32 octets each); OpenSSL verifies a DER ECDSA-Sig-Value.
function joseSigToDer(raw) {
  var half = raw.length / 2;
  var r = BigInt("0x" + raw.subarray(0, half).toString("hex"));
  var s = BigInt("0x" + raw.subarray(half).toString("hex"));
  return b.sequence([b.integer(r), b.integer(s)]);
}
function toPubPem(spkiDer) {
  var body = Buffer.from(spkiDer).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
}
function jwsOf(callBody) { return JSON.parse(Buffer.isBuffer(callBody) ? callBody.toString("utf8") : String(callBody)); }
function headerOf(jws) { return JSON.parse(Buffer.from(jws.protected, "base64url").toString("utf8")); }

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-acme-"));
  function p(name) { return path.join(dir, name); }
  try {
    var acct = await A.makeAccount();
    fs.writeFileSync(p("acct-pub.pem"), toPubPem(acct.spki));

    var server = A.acmeServer({});
    var acme = pki.acme.client(A.URLS.directory, A.clientOpts(acct, server));
    await acme.newAccount({ termsOfServiceAgreed: true });
    await acme.newOrder({ identifiers: [{ type: "dns", value: "example.org" }] });

    // The captured POSTs: the first is newAccount (jwk mode), then newOrder (kid mode). Reads before
    // them are GET/HEAD (directory, new-nonce) with no JWS body.
    var posts = server.calls.filter(function (c) { return c.method === "POST" && c.body; });
    check("the client emitted at least the newAccount + newOrder JWS", posts.length >= 2);

    // openssl verifies a captured JWS signature over its exact signing input, using only the SPKI.
    function opensslVerifies(jws) {
      var signingInput = Buffer.from(jws.protected + "." + jws.payload, "ascii");
      var rawSig = Buffer.from(jws.signature, "base64url");
      check("the ES256 signature is a 64-octet raw R||S pair", rawSig.length === 64);
      fs.writeFileSync(p("input.bin"), signingInput);
      fs.writeFileSync(p("sig.der"), joseSigToDer(rawSig));
      var out = ctx.runOpenssl(["dgst", "-sha256", "-verify", p("acct-pub.pem"), "-signature", p("sig.der"), p("input.bin")]);
      return /Verified OK/.test(out);
    }

    // ---- Gate A: newAccount (jwk mode, RFC 8555 sec. 7.3) ----
    var acctJws = jwsOf(posts[0].body);
    var acctHdr = headerOf(acctJws);
    check("Gate A: OpenSSL verifies the newAccount JWS signature (ES256, account key)", opensslVerifies(acctJws));
    check("Gate A: the protected header is alg=ES256 with an embedded jwk, no kid (RFC 8555 sec. 6.2)",
      acctHdr.alg === "ES256" && acctHdr.jwk && acctHdr.jwk.kty === "EC" && acctHdr.kid === undefined);
    check("Gate A: the JWS is bound to the newAccount URL and carries a nonce (sec. 6.4/6.5)",
      acctHdr.url === A.URLS.newAccount && typeof acctHdr.nonce === "string" && acctHdr.nonce.length > 0);

    // ---- Gate B: newOrder (kid mode, RFC 8555 sec. 7.4) ----
    var orderJws = jwsOf(posts[1].body);
    var orderHdr = headerOf(orderJws);
    check("Gate B: OpenSSL verifies the newOrder JWS signature (ES256, account key)", opensslVerifies(orderJws));
    check("Gate B: the protected header is alg=ES256 with a kid, no embedded jwk (RFC 8555 sec. 6.2)",
      orderHdr.alg === "ES256" && orderHdr.kid === A.URLS.account && orderHdr.jwk === undefined);
    check("Gate B: the JWS is bound to the newOrder URL and carries a nonce (sec. 6.4/6.5)",
      orderHdr.url === A.URLS.newOrder && typeof orderHdr.nonce === "string" && orderHdr.nonce.length > 0);

    // The two nonces are distinct (each request consumes a fresh single-use anti-replay nonce, sec. 6.5).
    check("Gate B: newAccount and newOrder used distinct nonces", acctHdr.nonce !== orderHdr.nonce);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
