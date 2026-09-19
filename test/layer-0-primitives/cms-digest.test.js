// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.digest / pki.cms.verifyDigest (RFC 5652 sec. 7 DigestedData).
 *
 * DigestedData is the integrity-only CMS container: no signer, no key, no identity. It says
 * only that the content matches the digest carried beside it, which is worth exactly as much
 * as the channel the two traveled over. The verifying half therefore recomputes the digest
 * and compares it in constant time, and reports a mismatch as a typed refusal rather than a
 * falsy verdict.
 *
 * Oracle: the digest values are computed here with node:crypto directly, so the vectors do
 * not check the toolkit against itself.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

var CONTENT = Buffer.from("the content DigestedData covers");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || e.name; } }
async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || e.name; } }

async function testProduce() {
  var der = await pki.cms.digest(CONTENT);
  check("digest returns DER", Buffer.isBuffer(der));

  var parsed = pki.schema.cms.parse(der);
  check("it is a DigestedData", parsed.contentTypeName === "digestedData");
  check("version 0 over id-data (RFC 5652 sec. 7)", parsed.version === 0);
  check("the default digest algorithm is SHA-256", parsed.digestAlgorithm.name === "sha256");
  // The oracle: the digest is over the CONTENT octets, not over the DER of the OCTET STRING.
  check("the digest is SHA-256 of the content octets",
    parsed.digest.equals(nodeCrypto.createHash("sha256").update(CONTENT).digest()));
  check("the content is carried and comes back byte-exact",
    Buffer.from(parsed.encapContentInfo.eContent).equals(CONTENT));

  // Every digest the toolkit offers, so a caller is not silently narrowed to one.
  for (var alg of ["sha256", "sha384", "sha512"]) {
    var d = pki.schema.cms.parse(await pki.cms.digest(CONTENT, { digestAlgorithm: alg }));
    check(alg + " is offered and its digest matches the oracle",
      d.digestAlgorithm.name === alg &&
      d.digest.equals(nodeCrypto.createHash(alg).update(CONTENT).digest()));
  }

  // A non-data eContentType moves the version to 2, which sec. 7 pins.
  var tst = pki.schema.cms.parse(await pki.cms.digest(CONTENT, { contentType: "tSTInfo" }));
  check("a non-data eContentType is emitted at version 2", tst.version === 2);

  // Detached: the digest travels without the content it covers.
  var detachedDer = await pki.cms.digest(CONTENT, { detached: true });
  var detached = pki.schema.cms.parse(detachedDer);
  check("a detached DigestedData omits eContent", detached.encapContentInfo.eContent === null);
  check("and still carries the digest over the content",
    detached.digest.equals(nodeCrypto.createHash("sha256").update(CONTENT).digest()));

  check("pem: true wraps it", typeof (await pki.cms.digest(CONTENT, { pem: true })) === "string");
  check("an unknown option is named",
    (await codeOf(pki.cms.digest(CONTENT, { digestAlgoritm: "sha384" }))) === "cms/bad-input");
  check("an unknown digest algorithm is refused",
    (await codeOf(pki.cms.digest(CONTENT, { digestAlgorithm: "md5" }))) === "cms/unsupported-algorithm");
}

async function testVerify() {
  var der = await pki.cms.digest(CONTENT);
  var ok = await pki.cms.verifyDigest(der);
  check("verifyDigest returns a verdict", ok.valid === true);
  check("it surfaces the content it verified", Buffer.from(ok.content).equals(CONTENT));
  check("and the algorithm the digest was taken under", ok.digestAlgorithm === "sha256");

  // The whole point of the container: a content change is caught.
  var tampered = Buffer.from(der);
  var at = tampered.indexOf(CONTENT);
  check("CONTROL: the content is locatable in the DER", at > 0);
  tampered[at] = tampered[at] ^ 0x01;
  var bad = await pki.cms.verifyDigest(tampered);
  check("a flipped content bit is caught", bad.valid === false && bad.code === "cms/digest-mismatch");

  // Detached: the caller supplies the content the digest covers.
  var detachedDer = await pki.cms.digest(CONTENT, { detached: true });
  var det = await pki.cms.verifyDigest(detachedDer, { content: CONTENT });
  check("a detached DigestedData verifies against caller-supplied content", det.valid === true);
  var detBad = await pki.cms.verifyDigest(detachedDer, { content: Buffer.from("other content") });
  check("and the wrong content is caught",
    detBad.valid === false && detBad.code === "cms/digest-mismatch");
  check("a detached DigestedData with no content to check is refused",
    (await codeOf(pki.cms.verifyDigest(detachedDer))) === "cms/bad-input");

  // A DigestedData is not a signature, and the verdict must not read like one.
  check("the verdict carries no signer and no trust claim",
    ok.signers === undefined && ok.trusted === undefined);

  // Wrong content type in, typed refusal out.
  var signed = await pki.cms.digest(CONTENT);
  check("CONTROL: a real DigestedData verifies", (await pki.cms.verifyDigest(signed)).valid === true);
  check("a SignedData handed to verifyDigest is refused",
    (await codeOf(pki.cms.verifyDigest(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])))) !== "NO-THROW");

  await testDigestAlgorithmParameters();
}

// RFC 5754 sec. 2: a SHA-2 digest AlgorithmIdentifier carries its parameters absent, and an
// implementation that generates one MAY carry DER NULL. Anything else is not that algorithm,
// so a digest that matches under it is not evidence of anything.
async function testDigestAlgorithmParameters() {
  var b = pki.asn1.build;
  var digestOf = nodeCrypto.createHash("sha256").update(CONTENT).digest();

  function digestedData(paramsNode) {
    var algChildren = [b.oid(pki.oid.byName("sha256"))];
    if (paramsNode !== null) algChildren.push(paramsNode);
    var inner = b.sequence([
      b.integer(0n),
      b.sequence(algChildren),
      b.sequence([b.oid(pki.oid.byName("data")), b.contextConstructed(0, b.octetString(CONTENT))]),
      b.octetString(digestOf),
    ]);
    return b.sequence([b.oid(pki.oid.byName("digestedData")), b.contextConstructed(0, inner)]);
  }

  // Two passing controls, so a refusal below cannot be the envelope being rejected.
  check("CONTROL: absent parameters verify", (await pki.cms.verifyDigest(digestedData(null))).valid === true);
  check("CONTROL: DER NULL parameters verify",
    (await pki.cms.verifyDigest(digestedData(b.nullValue()))).valid === true);

  check("INTEGER digest-algorithm parameters are refused (RFC 5754 sec. 2)",
    (await codeOf(pki.cms.verifyDigest(digestedData(b.integer(123n))))) === "cms/unsupported-algorithm");
  check("OCTET STRING digest-algorithm parameters are refused",
    (await codeOf(pki.cms.verifyDigest(digestedData(b.octetString(Buffer.alloc(2)))))) === "cms/unsupported-algorithm");
  check("an empty SEQUENCE as digest-algorithm parameters is refused",
    (await codeOf(pki.cms.verifyDigest(digestedData(b.sequence([]))))) === "cms/unsupported-algorithm");
}

async function run() {
  await testProduce();
  await testVerify();
  void code;
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
