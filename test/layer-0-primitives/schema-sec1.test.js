// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- SEC1 EC private keys (pki.schema.sec1).
 * RED conformance vectors for RFC 5915: the `EC PRIVATE KEY` encoding OpenSSL
 * writes and appliances still emit. The scalar's width is fixed by the curve, so
 * a short one is refused rather than left-padded; the parameters field carries a
 * named curve and nothing else (RFC 5480 sec. 2.1.1 MUST NOT); and the stored
 * public key is data the caller may check rather than the key's identity.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var crypto = require("node:crypto");

var b = pki.asn1.build;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }

var CURVES = [
  { node: "prime256v1", name: "prime256v1", oid: "1.2.840.10045.3.1.7", scalar: 32 },
  { node: "secp384r1", name: "secp384r1", oid: "1.3.132.0.34", scalar: 48 },
  { node: "secp521r1", name: "secp521r1", oid: "1.3.132.0.35", scalar: 66 },
];
CURVES.forEach(function (c) {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: c.node });
  c.der = kp.privateKey.export({ type: "sec1", format: "der" });
  c.pem = kp.privateKey.export({ type: "sec1", format: "pem" });
  c.pkcs8 = kp.privateKey.export({ type: "pkcs8", format: "der" });
});
var P256 = CURVES[0];

function rebuild(parts) {
  var kids = [b.integer(parts.version), b.octetString(parts.scalar)];
  if (parts.curveOid !== null) kids.push(b.explicit(0, b.oid(parts.curveOid)));
  if (parts.point) kids.push(b.explicit(1, b.bitString(parts.point, 0)));
  return b.sequence(kids);
}
function partsOf(c) {
  var k = pki.schema.sec1.parse(c.der);
  return { version: 1n, scalar: k.privateKey, curveOid: c.oid, point: k.publicKey };
}

// ---- accept ------------------------------------------------------------
function testAccepts() {
  CURVES.forEach(function (c, i) {
    var k = pki.schema.sec1.parse(c.der);
    check("1." + i + " a " + c.name + " ECPrivateKey reads its version, scalar and curve",
      k.version === 1 && Buffer.isBuffer(k.privateKey) && k.privateKey.length === c.scalar &&
      k.curve === c.name && k.curveOid === c.oid);
    check("2." + i + " and its stored public key is an uncompressed point of the curve's width",
      Buffer.isBuffer(k.publicKey) && k.publicKey[0] === 0x04 &&
      k.publicKey.length === 1 + 2 * c.scalar);
    check("3." + i + " the same key as a PEM reads to the same scalar",
      pki.schema.sec1.parse(c.pem).privateKey.equals(k.privateKey));
    check("4." + i + " and writing it back produces the bytes it was read from",
      pki.schema.sec1.encode(k).equals(c.der));
  });
  check("5. the PEM label is the one OpenSSL writes",
    pki.schema.sec1.pemEncode(P256.der).indexOf("-----BEGIN EC PRIVATE KEY-----") === 0);
  check("6. a key with no stored public key still reads, the field being optional", (function () {
    var p = partsOf(P256); p.point = null;
    var k = pki.schema.sec1.parse(rebuild(p));
    return k.privateKey.equals(p.scalar) && k.publicKey === undefined;
  })());
}

// ---- the version and the curve -----------------------------------------
function testVersionAndCurve() {
  check("7. a version other than 1 is refused, which is what keeps a PKCS#8 body from reading here",
    code(function () { var p = partsOf(P256); p.version = 0n; pki.schema.sec1.parse(rebuild(p)); }) === "sec1/bad-version");
  check("8. a key with no parameters field is refused, the curve being what fixes the scalar width",
    code(function () { var p = partsOf(P256); p.curveOid = null; pki.schema.sec1.parse(rebuild(p)); }) === "sec1/missing-curve");
  check("9. a parameters field carrying a specified curve is refused (RFC 5480 sec. 2.1.1)",
    code(function () {
      pki.schema.sec1.parse(b.sequence([b.integer(1n), b.octetString(P256.der.subarray(0, 32)),
        b.explicit(0, b.sequence([b.integer(1n)]))]));
    }) === "sec1/bad-curve");
  check("10. and one carrying an implicit curve is refused too",
    code(function () {
      pki.schema.sec1.parse(b.sequence([b.integer(1n), b.octetString(P256.der.subarray(0, 32)),
        b.explicit(0, b.nullValue())]));
    }) === "sec1/bad-curve");
  check("11. a curve this toolkit does not know is refused by name",
    code(function () { var p = partsOf(P256); p.curveOid = "1.2.3.4.5"; pki.schema.sec1.parse(rebuild(p)); }) ===
      "sec1/unsupported-curve");
  // A curve the OID registry names but this reader holds no scalar width for is refused the same
  // way, and the message names it, so the operator reads a curve name and not a dotted OID.
  check("11a. a registered curve with no scalar width is refused, and the refusal names it", (function () {
    var p = partsOf(P256); p.curveOid = "1.3.132.0.33";   // secp224r1
    var message = "";
    try { pki.schema.sec1.parse(rebuild(p)); } catch (e) { message = e.message; }
    return message.indexOf("secp224r1") !== -1;
  })());
  check("11b. and an unregistered OID is refused without inventing a name for it", (function () {
    var p = partsOf(P256); p.curveOid = "1.2.3.4.5";
    var message = "";
    try { pki.schema.sec1.parse(rebuild(p)); } catch (e) { message = e.message; }
    return message.indexOf("1.2.3.4.5") !== -1 && message.indexOf("(") === -1;
  })());
  check("11c. a parameters field carrying neither an OID, a sequence nor a null is refused",
    code(function () {
      pki.schema.sec1.parse(b.sequence([b.integer(1n), b.octetString(Buffer.alloc(32, 7)),
        b.explicit(0, b.integer(7n))]));
    }) === "sec1/bad-curve");
}

// ---- the scalar is the curve's width -----------------------------------
function testScalarWidth() {
  check("12. a scalar shorter than the curve's width is refused rather than left-padded",
    code(function () {
      var p = partsOf(P256); p.scalar = p.scalar.subarray(1); return pki.schema.sec1.parse(rebuild(p));
    }) === "sec1/bad-private-key");
  check("13. and one longer than it is refused too",
    code(function () {
      var p = partsOf(P256); p.scalar = Buffer.concat([Buffer.from([0]), p.scalar]);
      return pki.schema.sec1.parse(rebuild(p));
    }) === "sec1/bad-private-key");
  check("14. an empty scalar is refused",
    code(function () { var p = partsOf(P256); p.scalar = Buffer.alloc(0); return pki.schema.sec1.parse(rebuild(p)); }) ===
      "sec1/bad-private-key");
  check("15. CONTROL: a scalar with a leading zero octet at the curve's width reads, the width being fixed",
    (function () {
      var p = partsOf(P256);
      p.scalar = Buffer.concat([Buffer.from([0]), p.scalar.subarray(1)]);
      return pki.schema.sec1.parse(rebuild(p)).privateKey.length === 32;
    })());
}

// ---- the stored point --------------------------------------------------
function testStoredPoint() {
  check("16. a point whose first octet names no form is refused", (function () {
    var p = partsOf(P256);
    var bad = Buffer.from(p.point); bad[0] = 0x05;
    p.point = bad;
    return code(function () { pki.schema.sec1.parse(rebuild(p)); }) === "sec1/bad-public-key";
  })());
  [0x06, 0x07].forEach(function (form, i) {
    check("17." + i + " the hybrid form 0x0" + form.toString(16) + " is refused by name (RFC 5480 sec. 2.2)",
      (function () {
        var p = partsOf(P256);
        var bad = Buffer.from(p.point); bad[0] = form;
        p.point = bad;
        return code(function () { pki.schema.sec1.parse(rebuild(p)); }) === "sec1/bad-public-key";
      })());
  });
  check("18. an uncompressed point of the wrong width is refused", (function () {
    var p = partsOf(P256); p.point = p.point.subarray(0, p.point.length - 1);
    return code(function () { pki.schema.sec1.parse(rebuild(p)); }) === "sec1/bad-public-key";
  })());
  check("19. a compressed point of the curve's width reads, the form being optional to support", (function () {
    var p = partsOf(P256);
    p.point = Buffer.concat([Buffer.from([0x02]), p.point.subarray(1, 33)]);
    var k = pki.schema.sec1.parse(rebuild(p));
    return k.publicKey.length === 33 && k.publicKey[0] === 0x02;
  })());
  check("19a. a compressed point of the wrong width is refused too", (function () {
    var p = partsOf(P256);
    p.point = Buffer.concat([Buffer.from([0x02]), p.point.subarray(1, 20)]);
    return code(function () { pki.schema.sec1.parse(rebuild(p)); }) === "sec1/bad-public-key";
  })());
  check("19b. an empty stored point is refused", (function () {
    var p = partsOf(P256); p.point = Buffer.alloc(0);
    return code(function () { pki.schema.sec1.parse(rebuild(p)); }) === "sec1/bad-public-key";
  })());
  // The builder refuses a non-zero unused-bit count and the DECODER accepts one, so this is built
  // as the encoding a hostile file would carry: a BIT STRING TLV assembled byte by byte.
  check("19c. a stored point whose BIT STRING does not hold whole octets is refused", (function () {
    var p = partsOf(P256);
    // DER requires the unused bits to be zero-VALUED, so the last octet's low three bits are
    // cleared: the encoding is valid DER carrying a count of 3, which is what reaches the rule
    // that a point holds whole octets.
    var padded = Buffer.from(p.point);
    padded[padded.length - 1] &= 0xf8;
    var bitStringTlv = pki.asn1.encode(0x00, false, pki.asn1.TAGS.BIT_STRING,
      Buffer.concat([Buffer.from([3]), padded]));
    return code(function () {
      pki.schema.sec1.parse(b.sequence([b.integer(1n), b.octetString(p.scalar),
        b.explicit(0, b.oid(P256.oid)), b.explicit(1, bitStringTlv)]));
    }) === "sec1/bad-public-key";
  })());
}

// ---- the writer -------------------------------------------------------
function testWriter() {
  var k = pki.schema.sec1.parse(P256.der);
  check("22. a value that is not an object is refused",
    code(function () { pki.schema.sec1.encode(null); }) === "sec1/bad-input" &&
    code(function () { pki.schema.sec1.encode("key"); }) === "sec1/bad-input");
  check("23. a key naming its curve by registry name writes, the OID being resolved from it", (function () {
    var der = pki.schema.sec1.encode({ privateKey: k.privateKey, curve: "prime256v1", publicKey: k.publicKey });
    return pki.schema.sec1.parse(der).curve === "prime256v1";
  })());
  check("24. and one naming neither is refused",
    code(function () { pki.schema.sec1.encode({ privateKey: k.privateKey }); }) === "sec1/bad-input");
  check("25. a key with no version stated is written as version 1, the only version there is", (function () {
    var der = pki.schema.sec1.encode({ privateKey: k.privateKey, curveOid: k.curveOid });
    return pki.schema.sec1.parse(der).version === 1;
  })());
}

// ---- the structure is not routed by shape ------------------------------
function testNotRouted() {
  // A PKCS#8 PrivateKeyInfo opens with an INTEGER like an ECPrivateKey does, and diverges at the
  // second field: an AlgorithmIdentifier SEQUENCE where this expects the scalar's OCTET STRING.
  // So the reader that expected the scalar is what refuses it, one field before the version rule
  // vector 7 pins would have been reached.
  check("20. a PKCS#8 EC key is not an ECPrivateKey at this door",
    code(function () { pki.schema.sec1.parse(P256.pkcs8); }) === "asn1/unexpected-tag");
  check("21. and the orchestrator does not route a structure that names no algorithm",
    pki.schema.detectFormat(P256.der) !== "sec1");
}

function run() {
  testAccepts();
  testVersionAndCurve();
  testScalarWidth();
  testStoredPoint();
  testWriter();
  testNotRouted();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
