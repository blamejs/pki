// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- PKCS#1 RSA key structures (pki.schema.pkcs1).
 * RED conformance vectors for RFC 8017 Appendix A.1: the `RSA PRIVATE KEY` and
 * `RSA PUBLIC KEY` encodings OpenSSL wrote by default for years and appliances
 * still emit. The structure carries no algorithm identifier, so what it is read
 * as is the caller's decision and never a default. Every arithmetic relation the
 * specification states between the components is checked, because a component
 * outside it describes no key and the structure alone cannot say so.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var crypto = require("node:crypto");

var b = pki.asn1.build;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }

var KP = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
var PRIV_DER = KP.privateKey.export({ type: "pkcs1", format: "der" });
var PRIV_PEM = KP.privateKey.export({ type: "pkcs1", format: "pem" });
var PUB_DER = KP.publicKey.export({ type: "pkcs1", format: "der" });
var PUB_PEM = KP.publicKey.export({ type: "pkcs1", format: "pem" });

// A private key assembled component by component, so a vector can change one component without
// disturbing the rest. The values come from the real key above, so the arithmetic holds unless a
// vector deliberately breaks it.
function parts() {
  var k = pki.schema.pkcs1.parse(PRIV_DER);
  return {
    version: 0n, modulus: k.modulus, publicExponent: k.publicExponent, privateExponent: k.privateExponent,
    prime1: k.prime1, prime2: k.prime2, exponent1: k.exponent1, exponent2: k.exponent2, coefficient: k.coefficient,
  };
}
function build(p, extra) {
  var kids = [b.integer(p.version), b.integer(p.modulus), b.integer(p.publicExponent),
    b.integer(p.privateExponent), b.integer(p.prime1), b.integer(p.prime2),
    b.integer(p.exponent1), b.integer(p.exponent2), b.integer(p.coefficient)];
  if (extra) kids.push(extra);
  return b.sequence(kids);
}

// ---- accept ------------------------------------------------------------
function testAccepts() {
  var k = pki.schema.pkcs1.parse(PRIV_DER);
  check("1. a 2048-bit RSAPrivateKey reads its nine components",
    k.version === 0 && typeof k.modulus === "bigint" && k.publicExponent === 65537n &&
    typeof k.privateExponent === "bigint" && typeof k.prime1 === "bigint" &&
    typeof k.prime2 === "bigint" && typeof k.exponent1 === "bigint" &&
    typeof k.exponent2 === "bigint" && typeof k.coefficient === "bigint");
  check("2. the modulus is the 2048 bits the key was generated with",
    k.modulus.toString(16).length === 512);
  check("3. a version-0 key carries no other prime infos",
    Array.isArray(k.otherPrimeInfos) && k.otherPrimeInfos.length === 0);
  check("4. the same key as a PEM reads to the same components", (function () {
    var p = pki.schema.pkcs1.parse(PRIV_PEM);
    return p.modulus === k.modulus && p.coefficient === k.coefficient;
  })());
  check("5. an RSAPublicKey reads its two components and nothing else", (function () {
    var pub = pki.schema.pkcs1.parsePublic(PUB_DER);
    return pub.modulus === k.modulus && pub.publicExponent === 65537n &&
      pub.privateExponent === undefined;
  })());
  check("6. and the same as a PEM", pki.schema.pkcs1.parsePublic(PUB_PEM).modulus === k.modulus);
  check("7. writing the parsed private key back produces the bytes it was read from",
    pki.schema.pkcs1.encode(k).equals(PRIV_DER));
  check("8. and the same for the public key",
    pki.schema.pkcs1.encodePublic(pki.schema.pkcs1.parsePublic(PUB_DER)).equals(PUB_DER));
  check("9. the PEM label is the one OpenSSL writes", (function () {
    var pem = pki.schema.pkcs1.pemEncode(PRIV_DER);
    return pem.indexOf("-----BEGIN RSA PRIVATE KEY-----") === 0;
  })());
}

// ---- the version and the multi-prime rule ------------------------------
function testVersionRule() {
  var p = parts();
  check("10. a version this specification does not define is refused",
    code(function () { pki.schema.pkcs1.parse(build({ version: 2n, modulus: p.modulus, publicExponent: p.publicExponent, privateExponent: p.privateExponent, prime1: p.prime1, prime2: p.prime2, exponent1: p.exponent1, exponent2: p.exponent2, coefficient: p.coefficient })); }) === "pkcs1/bad-version");
  var twoPrime = b.sequence([b.sequence([b.integer(3n), b.integer(1n), b.integer(1n)])]);
  check("11. version 0 with other prime infos is refused, the two stating different keys",
    code(function () { pki.schema.pkcs1.parse(build(p, twoPrime)); }) === "pkcs1/bad-other-prime-infos");
  check("12. version 1 without them is refused for the same reason", (function () {
    var q = parts(); q.version = 1n;
    return code(function () { pki.schema.pkcs1.parse(build(q)); }) === "pkcs1/bad-other-prime-infos";
  })());
  check("13. version 1 with an empty list is refused, SIZE(1..MAX) admitting no empty one", (function () {
    var q = parts(); q.version = 1n;
    return code(function () { pki.schema.pkcs1.parse(build(q, b.sequence([]))); }) === "pkcs1/bad-other-prime-infos";
  })());
  check("14. an OtherPrimeInfo of two integers is refused, and one of four", (function () {
    var q = parts(); q.version = 1n;
    var two = code(function () { pki.schema.pkcs1.parse(build(q, b.sequence([b.sequence([b.integer(3n), b.integer(1n)])]))); });
    var four = code(function () { pki.schema.pkcs1.parse(build(q, b.sequence([b.sequence([b.integer(3n), b.integer(1n), b.integer(1n), b.integer(1n)])]))); });
    return two === "pkcs1/bad-other-prime-infos" && four === "pkcs1/bad-other-prime-infos";
  })());
  check("15. CONTROL: version 1 with a well-formed list parses, so the structure is readable", (function () {
    var q = parts(); q.version = 1n;
    var k = pki.schema.pkcs1.parse(build(q, twoPrime));
    return k.version === 1 && k.otherPrimeInfos.length === 1 && k.otherPrimeInfos[0].prime === 3n;
  })());
  // RFC 8017 sec. 3.2 derives an additional prime's exponent modulo `r_i - 1` and its coefficient
  // modulo `r_i`, so both are smaller than that prime, exactly as `exponent1` is smaller than
  // `prime1`. Holding the first two primes to that and not the rest reads a key the specification
  // does not describe.
  function otherPrime(p, d, t) {
    var q = parts(); q.version = 1n;
    return code(function () {
      pki.schema.pkcs1.parse(build(q, b.sequence([b.sequence([b.integer(p), b.integer(d), b.integer(t)])])));
    });
  }
  check("15a. an additional prime's exponent must be smaller than that prime",
    otherPrime(7n, 7n, 1n) === "pkcs1/bad-component" && otherPrime(7n, 9n, 1n) === "pkcs1/bad-component");
  check("15b. and so must its coefficient",
    otherPrime(7n, 1n, 7n) === "pkcs1/bad-component" && otherPrime(7n, 1n, 9n) === "pkcs1/bad-component");
  check("15c. CONTROL: components below that prime still parse", otherPrime(7n, 5n, 6n) === "NO-THROW");
  check("15d. a prime of 1 leaves nothing a component can be smaller than",
    otherPrime(1n, 1n, 1n) === "pkcs1/bad-component");
}

// ---- the shape ---------------------------------------------------------
function testShape() {
  var p = parts();
  check("16. eight integers is not an RSAPrivateKey", code(function () {
    pki.schema.pkcs1.parse(b.sequence([b.integer(0n), b.integer(p.modulus), b.integer(p.publicExponent),
      b.integer(p.privateExponent), b.integer(p.prime1), b.integer(p.prime2), b.integer(p.exponent1), b.integer(p.exponent2)]));
  }) === "pkcs1/not-an-rsa-private-key");
  // A child of the wrong TYPE is the leaf reader's verdict rather than the format's, which is how
  // every parser in this family answers: the format code names a shape fault, and the codec names
  // a tag fault, with the field it was reading in the message.
  check("17. a child that is not an integer is refused by the reader that expected one", code(function () {
    pki.schema.pkcs1.parse(b.sequence([b.integer(0n), b.octetString(Buffer.from([1])), b.integer(p.publicExponent),
      b.integer(p.privateExponent), b.integer(p.prime1), b.integer(p.prime2), b.integer(p.exponent1),
      b.integer(p.exponent2), b.integer(p.coefficient)]));
  }) === "asn1/unexpected-tag");
  check("18. a three-integer sequence is not an RSAPublicKey",
    code(function () { pki.schema.pkcs1.parsePublic(b.sequence([b.integer(1n), b.integer(2n), b.integer(3n)])); }) ===
      "pkcs1/not-an-rsa-public-key");
  check("19. and a private key is not one, so the public door does not read a private key",
    code(function () { pki.schema.pkcs1.parsePublic(PRIV_DER); }) === "pkcs1/not-an-rsa-public-key");
  check("20. a public key is not a private key at the private door",
    code(function () { pki.schema.pkcs1.parse(PUB_DER); }) === "pkcs1/not-an-rsa-private-key");
}

// ---- every component is a positive integer, and the relations hold -----
function testComponentRelations() {
  var p = parts();
  function withOne(name, value) {
    var q = parts(); q[name] = value;
    return code(function () { pki.schema.pkcs1.parse(build(q)); });
  }
  // RFC 8017 sec. 3.1 and sec. 3.2 state every component as a positive integer. A DER INTEGER
  // whose first content octet has the high bit set is negative, which describes no key.
  check("21. a negative modulus is refused", withOne("modulus", -p.modulus) === "pkcs1/bad-component");
  check("22. a negative prime is refused", withOne("prime1", -p.prime1) === "pkcs1/bad-component");
  check("23. a zero modulus is refused", withOne("modulus", 0n) === "pkcs1/bad-component");
  // sec. 3.1: the public exponent is odd and 3 <= e < n.
  // Zero is not a positive integer at all, so it is refused one step before the range is read.
  // The two verdicts are ordered, and each names the rule it broke.
  check("24.0 a public exponent of zero is refused for not being a positive integer",
    withOne("publicExponent", 0n) === "pkcs1/bad-component");
  [1n, 2n, 4n].forEach(function (e, i) {
    check("24." + (i + 1) + " a public exponent of " + e + " is outside 3 <= e < n or is even",
      withOne("publicExponent", e) === "pkcs1/bad-exponent");
  });
  check("25. a public exponent at the modulus is refused",
    withOne("publicExponent", p.modulus) === "pkcs1/bad-exponent");
  check("26. CONTROL: 3 is a public exponent this reader accepts", (function () {
    var q = parts(); q.publicExponent = 3n;
    return pki.schema.pkcs1.parse(build(q)).publicExponent === 3n;
  })());
  // sec. 3.2: d < n, dP < p, dQ < q, qInv < p.
  check("27. a private exponent at the modulus is refused",
    withOne("privateExponent", p.modulus) === "pkcs1/bad-component");
  check("28. exponent1 at prime1 is refused", withOne("exponent1", p.prime1) === "pkcs1/bad-component");
  check("29. exponent2 at prime2 is refused", withOne("exponent2", p.prime2) === "pkcs1/bad-component");
  check("30. the coefficient at prime1 is refused", withOne("coefficient", p.prime1) === "pkcs1/bad-component");
}

// ---- the structure names no algorithm ----------------------------------
function testWriter() {
  var k = pki.schema.pkcs1.parse(PRIV_DER);
  check("33. a value that is not an object is refused by both writers",
    code(function () { pki.schema.pkcs1.encode(null); }) === "pkcs1/bad-input" &&
    code(function () { pki.schema.pkcs1.encodePublic("key"); }) === "pkcs1/bad-input");
  check("34. a multi-prime key writes its other prime infos and reads back with them", (function () {
    var multi = {
      version: 1, modulus: k.modulus, publicExponent: k.publicExponent, privateExponent: k.privateExponent,
      prime1: k.prime1, prime2: k.prime2, exponent1: k.exponent1, exponent2: k.exponent2,
      coefficient: k.coefficient,
      otherPrimeInfos: [{ prime: 3n, exponent: 1n, coefficient: 1n }],
    };
    var back = pki.schema.pkcs1.parse(pki.schema.pkcs1.encode(multi));
    return back.version === 1 && back.otherPrimeInfos.length === 1 && back.otherPrimeInfos[0].prime === 3n;
  })());
}

function testCarriesNoAlgorithm() {
  var k = pki.schema.pkcs1.parse(PRIV_DER);
  check("31. the parsed key names no algorithm, the encoding carrying none (RFC 8017 App. A.1)",
    k.algorithm === undefined && k.algorithmIdentifier === undefined);
  check("32. and the orchestrator does not route a structure that names none", (function () {
    // Two INTEGERs and a SEQUENCE of nine are shapes other formats also take, so detection by
    // structure alone would be a guess. The reader is an explicit call.
    return pki.schema.detectFormat(PRIV_DER) !== "pkcs1";
  })());
}

function run() {
  testAccepts();
  testVersionRule();
  testShape();
  testComponentRelations();
  testWriter();
  testCarriesNoAlgorithm();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
