// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.tsp.sign (RFC 3161 timestamp token creation, the producing side of
 * pki.schema.tsp.parseToken). A TimeStampToken is a CMS SignedData over a TSTInfo, so the
 * output is asserted through BOTH the independent CMS verifier (pki.cms.verify -- the signature)
 * AND the TSP parser (pki.schema.tsp.parseToken -- the TSTInfo shape + the round-tripped
 * imprint, policy, serial, genTime, nonce, accuracy). Config-time misuse fails closed with a
 * typed tsp/* error.
 *
 * RED baseline: pki.tsp.sign is undefined until the module lands, so every vector throws.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeTsa = signing.makeTsa;

var DATA = Buffer.from("the document being timestamped");
function imprint(hashAlgorithm) {
  var hashedMessage = crypto.createHash(hashAlgorithm).update(DATA).digest();
  return { hashAlgorithm: hashAlgorithm, hashedMessage: hashedMessage };
}

async function rejects(label, fn, code) {
  var e = null;
  try { await fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}

// ---- round-trip: a full-featured token verifies and decodes ----
async function testRoundTrip() {
  var tsa = makeTsa("ec-p256");
  var mi = imprint("sha256");
  var token = await pki.tsp.sign(mi, tsa, {
    policy: "1.2.3.4.1", serialNumber: 42, genTime: new Date("2026-07-13T12:00:00Z"),
    nonce: 0xdeadbeefn, accuracy: { seconds: 1, millis: 500 }, ordering: true,
  });
  var v = await pki.cms.verify(token);
  check("timestamp token -> cms.verify valid", v.valid === true);
  var parsed = pki.schema.tsp.parseToken(token);
  var tst = parsed.tstInfo;
  check("token content is a TSTInfo v1", tst.version === 1);
  check("policy round-trips", tst.policy === "1.2.3.4.1");
  check("serialNumber round-trips", tst.serialNumber === 42n);
  check("messageImprint hash round-trips", Buffer.compare(tst.messageImprint.hashedMessage, mi.hashedMessage) === 0);
  // #68 A26: messageImprint.hashedMessage accepts the full BufferSource -- a caller holding a subtle.digest()
  // result as an ArrayBuffer signs the same imprint (its byte view IS the digest). RED before: hashedMessage
  // "must be a Buffer", or a length mismatch (an ArrayBuffer has no .length -> guard.bytes.lengthOf reads it).
  var digAB = new ArrayBuffer(mi.hashedMessage.length);
  new Uint8Array(digAB).set(mi.hashedMessage);
  var tokenAB = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: digAB }, tsa, { policy: "1.2.3.4.1", serialNumber: 43 });
  var tstAB = pki.schema.tsp.parseToken(tokenAB).tstInfo;
  check("hashedMessage as an ArrayBuffer signs the same imprint (#68 A26)", Buffer.compare(tstAB.messageImprint.hashedMessage, mi.hashedMessage) === 0);
  check("genTime round-trips", tst.genTime instanceof Date && tst.genTime.toISOString() === "2026-07-13T12:00:00.000Z");
  check("nonce round-trips", tst.nonce === 0xdeadbeefn);
  check("accuracy round-trips", tst.accuracy && tst.accuracy.seconds === 1n && tst.accuracy.millis === 500);
  // the signing-certificate attribute (RFC 3161 sec. 2.4.2) binds the token to the TSA cert.
  var si = pki.schema.cms.parse(token).signerInfos[0];
  var hasSignCert = si.signedAttrs.some(function (a) { return a.type === pki.oid.byName("signingCertificateV2"); });
  check("signing-certificate attribute present", hasSignCert);
}

// ---- unknown keys on the imprint and the options ----
// A dropped option here is a token that quietly lacks what was asked for: `odering` for `ordering`
// emitted a token with the flag unset, which is a claim about the timestamp the caller believes
// they made. All THREE caller-owned arguments are gated, including the TSA. A misspelling of the
// TSA's own two fields was always refused for what it left missing, but that is only half the
// class: a name belonging on the OPTIONS, written on the TSA instead, is read by nothing and
// dropped in silence -- `ordering` there emitted a token the same size as one that never asked
// for it, with the flag unset.
async function testUnknownSignKeys() {
  var tsa = makeTsa("ec-p256");
  async function code(fn) { try { await fn(); return null; } catch (e) { return e && e.code; } }

  check("an unknown messageImprint field -> tsp/bad-input",
    (await code(function () {
      return pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: imprint("sha256").hashedMessage, digest: 1 },
        tsa, { policy: "1.2.3", serialNumber: 1 });
    })) === "tsp/bad-input");
  check("an unknown option -> tsp/bad-input",
    (await code(function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, nonsenseOption: 1 }); })) === "tsp/bad-input");
  check("a one-letter option typo (odering) -> tsp/bad-input",
    (await code(function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, odering: true }); })) === "tsp/bad-input");
  check("the TSA's own two fields still sign",
    (await pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 3, ordering: true })) != null);
  // A signing OPTION misplaced onto the TSA. Without the door this signed, and the token was the
  // same length as one that never asked for ordering -- the flag was simply never set.
  check("a signing option misplaced onto the TSA -> tsp/bad-input",
    (await code(function () {
      return pki.tsp.sign(imprint("sha256"), { cert: tsa.cert, key: tsa.key, ordering: true },
        { policy: "1.2.3", serialNumber: 4 });
    })) === "tsp/bad-input");
  check("a key-store field on the TSA -> tsp/bad-input",
    (await code(function () {
      return pki.tsp.sign(imprint("sha256"), { cert: tsa.cert, key: tsa.key, keyObject: {} },
        { policy: "1.2.3", serialNumber: 5 });
    })) === "tsp/bad-input");

  // Accuracy is a nested descriptor whose three fields are all OPTIONAL, so `milis` emitted an
  // EMPTY Accuracy that parses back as zero seconds/millis/micros: the token understates its own
  // precision, which is a claim about the timestamp the caller believed they had made.
  check("an unknown accuracy field -> tsp/bad-input",
    (await code(function () {
      return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 21, accuracy: { milis: 500 } });
    })) === "tsp/bad-input");
  check("accuracy spelled correctly still signs",
    (await pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 22, accuracy: { seconds: 1, millis: 500 } })) != null);

  // The other two producing verbs in this module take the same door. Every option they encode is
  // OPTIONAL in the structure, so a misspelled name is missed by nothing and the artifact goes out
  // saying something the caller did not ask for. Both assert the ARTIFACT IS ABSENT, because the
  // failure being closed is that one was emitted.
  function emitted(fn) {
    var out = null, err = null;
    try { out = fn(); } catch (e) { err = e; }
    return { code: err && err.code, out: out };
  }

  // `nonce` misspelled emitted a request carrying NO nonce, and the caller then matched the reply
  // against a replay defense that was never on the wire.
  var badNonce = emitted(function () { return pki.tsp.request(imprint("sha256"), { noncce: 12345n }); });
  check("pki.tsp.request, a misspelled nonce -> tsp/bad-input", badNonce.code === "tsp/bad-input");
  check("...and NO request is emitted", badNonce.out === null);
  // The imprint is the request's OTHER caller-owned object, held to the same table sign uses: a
  // request option written on the imprint reaches nothing, so `nonce` there put a request on the
  // wire with no nonce while the caller believed they had asked for one.
  var badReqImprint = emitted(function () {
    return pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: imprint("sha256").hashedMessage, nonce: 7n }, {});
  });
  check("pki.tsp.request, a request option on the imprint -> tsp/bad-input", badReqImprint.code === "tsp/bad-input");
  check("...and NO request is emitted", badReqImprint.out === null);
  check("pki.tsp.request, an invented option -> tsp/bad-input",
    emitted(function () { return pki.tsp.request(imprint("sha256"), { nonsenseOption: 1 }); }).code === "tsp/bad-input");
  check("pki.tsp.request, every documented option is still accepted",
    pki.tsp.request(imprint("sha256"), { reqPolicy: "1.2.3", nonce: 7n, certReq: true }) != null);

  // `status` carries the verdict and defaults to granted(0), so a misspelling does not lose a
  // detail -- it inverts the answer. Without the door this emitted a GRANTED response.
  var tok = await pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 11 });
  var badStatus = emitted(function () { return pki.tsp.response(tok, { statu: 2 }); });
  check("pki.tsp.response, a misspelled status -> tsp/bad-input", badStatus.code === "tsp/bad-input");
  check("...and NO response is emitted", badStatus.out === null);
  check("pki.tsp.response, every documented option is still accepted",
    pki.tsp.response(tok, { status: 0, statusString: "ok" }) != null);
}

// ---- imprint hash algorithms + TSA key algorithms ----
async function testAlgorithms() {
  for (var h of ["sha256", "sha384", "sha512"]) {
    var t = await pki.tsp.sign(imprint(h), makeTsa("ec-p256"), { policy: "1.2.3", serialNumber: 1 });
    check("imprint " + h + " -> verifies", (await pki.cms.verify(t)).valid === true);
  }
  for (var alg of ["rsa", "ec-p384", "ed25519"]) {
    var t2 = await pki.tsp.sign(imprint("sha256"), makeTsa(alg), { policy: "1.2.3", serialNumber: 2 });
    check("TSA key " + alg + " -> verifies", (await pki.cms.verify(t2)).valid === true);
  }
  // a non-sha256 ESSCertIDv2 hash algorithm (carries an explicit hashAlgorithm).
  var t3 = await pki.tsp.sign(imprint("sha256"), makeTsa("ec-p256"), { policy: "1.2.3", serialNumber: 3, certHashAlgorithm: "sha512" });
  check("certHashAlgorithm sha512 -> verifies", (await pki.cms.verify(t3)).valid === true);
}

// ---- output passthrough: policy by name, PEM, sid ----
async function testPassthrough() {
  // policy as a registered OID name.
  var byName = await pki.tsp.sign(imprint("sha256"), makeTsa("ec-p256"), { policy: "sha256", serialNumber: 5 });
  check("policy by OID name -> verifies", (await pki.cms.verify(byName)).valid === true);
  // PEM output + a ski signer identifier passed through to cms.sign.
  var pem = await pki.tsp.sign(imprint("sha256"), makeTsa("ec-p256", { ski: true }), { policy: "1.2.3", serialNumber: 6, pem: true, sid: "ski" });
  check("pem:true -> a CMS PEM string", typeof pem === "string" && pem.indexOf("-----BEGIN CMS-----") === 0);
  check("PEM token verifies + ski sid", (await pki.cms.verify(pem)).signers[0].sid.subjectKeyIdentifier != null);

  // the TSA certificate supplied as a PEM string and as a Uint8Array.
  var tsa = makeTsa("ec-p256");
  var certPem = pki.schema.x509.pemEncode(tsa.cert, "CERTIFICATE");
  check("TSA cert as PEM -> verifies", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: certPem, key: tsa.key }, { policy: "1.2.3", serialNumber: 7 }))).valid === true);
  check("TSA cert as Uint8Array -> verifies", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: new Uint8Array(tsa.cert), key: tsa.key }, { policy: "1.2.3", serialNumber: 8 }))).valid === true);
  check("TSA cert as a PEM Buffer -> verifies", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: Buffer.from(certPem), key: tsa.key }, { policy: "1.2.3", serialNumber: 9 }))).valid === true);
  // #68: the TSA certificate accepts any BufferSource, not only a Buffer / Uint8Array / PEM. A DER
  // ArrayBuffer signs and verifies identically; before the widening it was refused as tsp/bad-input.
  var certAB = new ArrayBuffer(tsa.cert.length); new Uint8Array(certAB).set(tsa.cert);
  check("TSA cert as a DER ArrayBuffer -> verifies (#68)", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: certAB, key: tsa.key }, { policy: "1.2.3", serialNumber: 11 }))).valid === true);

  // a TSA cert as a Uint8Array of PEM bytes: the ESSCertIDv2 certHash is over the DECODED DER
  // certificate (matching the embedded cert), never the PEM text.
  var tok = await pki.tsp.sign(imprint("sha256"), { cert: new Uint8Array(Buffer.from(certPem)), key: tsa.key }, { policy: "1.2.3", serialNumber: 10 });
  var parsed = pki.schema.cms.parse(tok);
  var embedded = parsed.certificates[0].bytes;
  var scAttr = parsed.signerInfos[0].signedAttrs.filter(function (a) { return a.type === pki.oid.byName("signingCertificateV2"); })[0];
  var scDer = pki.asn1.decode(scAttr.values[0]);
  var certHash = pki.asn1.read.octetString(scDer.children[0].children[0].children[0]);
  var expected = crypto.createHash("sha256").update(embedded).digest();
  check("Uint8Array PEM TSA cert -> ESSCertIDv2 certHash matches the embedded DER cert", Buffer.compare(certHash, expected) === 0);
}

// ---- config-time misuse fails closed with a typed tsp/* error ----
async function testBadInput() {
  var tsa = makeTsa("ec-p256");
  await rejects("options not an object", function () { return pki.tsp.sign(imprint("sha256"), tsa, "nope"); }, "tsp/bad-input");
  await rejects("imprint without a hashAlgorithm", function () { return pki.tsp.sign({ hashedMessage: Buffer.alloc(32) }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/unsupported-algorithm");
  await rejects("imprint with an unsupported hash", function () { return pki.tsp.sign({ hashAlgorithm: "md5", hashedMessage: Buffer.alloc(16) }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/unsupported-algorithm");
  await rejects("imprint hashedMessage not a Buffer", function () { return pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: "x" }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("imprint hashedMessage wrong length for the hash", function () { return pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: Buffer.alloc(16) }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("no policy", function () { return pki.tsp.sign(imprint("sha256"), tsa, { serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("policy not a string", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: 123, serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("no serialNumber", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3" }); }, "tsp/bad-input");
  await rejects("no TSA certificate", function () { return pki.tsp.sign(imprint("sha256"), { key: tsa.key }, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("TSA cert a bad type", function () { return pki.tsp.sign(imprint("sha256"), { cert: 123, key: tsa.key }, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("TSA cert a non-CERTIFICATE PEM", function () { return pki.tsp.sign(imprint("sha256"), { cert: "-----BEGIN X-----\nAA\n-----END X-----", key: tsa.key }, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("unsupported certHashAlgorithm", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, certHashAlgorithm: "md5" }); }, "tsp/unsupported-algorithm");
  // Accuracy millis/micros MUST be 1..999 (RFC 3161 sec. 2.4.2); seconds must be non-negative.
  await rejects("Accuracy micros below 1", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, accuracy: { micros: -1 } }); }, "tsp/bad-input");
  await rejects("Accuracy millis above 999", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, accuracy: { millis: 1000 } }); }, "tsp/bad-input");
  await rejects("Accuracy millis zero", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, accuracy: { millis: 0 } }); }, "tsp/bad-input");
  await rejects("Accuracy seconds negative", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, accuracy: { seconds: -1 } }); }, "tsp/bad-input");
  await rejects("no options at all", function () { return pki.tsp.sign(imprint("sha256"), tsa); }, "tsp/bad-input");
  await rejects("a null messageImprint", function () { return pki.tsp.sign(null, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/unsupported-algorithm");
  await rejects("an invalid genTime Date", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, genTime: new Date("not a date") }); }, "tsp/bad-input");
  await rejects("a non-Date genTime", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, genTime: "2026-01-01" }); }, "tsp/bad-input");
  // A caller-authored INTEGER goes through the shared coercion, so a value that is not one is a
  // typed tsp/bad-input rather than a raw SyntaxError or RangeError from BigInt() -- an untyped
  // fault out of a public verb, which a caller handling tsp/* codes cannot catch.
  await rejects("a serialNumber that is not an integer", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: "not-a-number" }); }, "tsp/bad-input");
  await rejects("a fractional serialNumber", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1.5 }); }, "tsp/bad-input");
  await rejects("a nonce that is not an integer", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, nonce: {} }); }, "tsp/bad-input");
  await rejects("a request nonce that is not an integer", function () { return Promise.resolve().then(function () { return pki.tsp.request(imprint("sha256"), { nonce: "nope" }); }); }, "tsp/bad-input");
}

// ---- a pre-encoded request extension is validated, not spliced in raw ----
async function testRequestExtensions() {
  var b = pki.asn1.build;
  var san = b.sequence([b.oid(pki.oid.byName("subjectAltName")), b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "utf8"))]))]);

  // A well-formed extension still rides through, and the request its own parser reads back carries it.
  var ok = pki.tsp.request(imprint("sha256"), { extensions: [san] });
  check("a valid request extension is carried", (pki.tsp.parseRequest(ok).extensions || []).length === 1);

  // Every shape the encoder used to emit and its own parseRequest then refused. A caller relaying a
  // blob it did not author put fully chosen bytes inside [0]; the request builder now applies the
  // same pre-encoded-Extension gate every other request builder applies.
  await rejects("a request extension that is not an Extension SEQUENCE",
    function () { return Promise.resolve().then(function () { return pki.tsp.request(imprint("sha256"), { extensions: [Buffer.from("hello world")] }); }); }, "tsp/bad-input");
  await rejects("a duplicate request extension extnID",
    function () { return Promise.resolve().then(function () { return pki.tsp.request(imprint("sha256"), { extensions: [san, san] }); }); }, "tsp/bad-input");
  var critFalse = b.sequence([b.oid(pki.oid.byName("subjectAltName")), b.boolean(false), b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "utf8"))]))]);
  await rejects("a request extension with a non-canonical explicit critical=FALSE",
    function () { return Promise.resolve().then(function () { return pki.tsp.request(imprint("sha256"), { extensions: [critFalse] }); }); }, "tsp/bad-input");
}

async function run() {
  await testRoundTrip();
  await testAlgorithms();
  await testPassthrough();
  await testBadInput();
  await testRequestExtensions();
  await testUnknownSignKeys();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
