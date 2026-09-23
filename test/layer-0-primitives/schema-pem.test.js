// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the multi-object PEM reader (pki.schema.pem).
 * RED conformance vectors for RFC 7468: a file of encapsulated blocks is walked
 * once from the front, explanatory text around the blocks is text, every line
 * ending a checkout produces is read, each object carries the label that named it,
 * and the file is bounded in both the number of objects and the bytes they decode
 * to. The oracle is RFC 7468 sec. 2 and sec. 3 plus the errata the section list
 * carries.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }

// Three structurally different objects, so a row's label and its bytes can be told apart.
var CERT_DER = pki.asn1.build.sequence([pki.asn1.build.integer(1n), pki.asn1.build.nullValue()]);
var KEY_DER = pki.asn1.build.sequence([pki.asn1.build.integer(0n)]);
var OTHER_DER = pki.asn1.build.sequence([pki.asn1.build.boolean(true)]);

function wrap(der, width) {
  var b64 = der.toString("base64"), out = [];
  for (var i = 0; i < b64.length; i += (width || 64)) out.push(b64.slice(i, i + (width || 64)));
  return out.join("\n");
}
function block(label, der, width) {
  return "-----BEGIN " + label + "-----\n" + wrap(der, width) + "\n-----END " + label + "-----\n";
}
function rewriteEol(text, eol) {
  var out = "", i;
  for (i = 0; i < text.length; i++) out += text.charAt(i) === "\n" ? eol : text.charAt(i);
  return out;
}
function labelsOf(rows) { return rows.map(function (r) { return r.label; }).join(","); }

// ---- the shapes a real bundle takes ------------------------------------
function testAcceptsRealBundles() {
  var pem = pki.schema.pem;
  var fullchain = block("CERTIFICATE", CERT_DER) + block("CERTIFICATE", KEY_DER) + block("CERTIFICATE", OTHER_DER);
  check("1. a three-block chain reads as three rows in file order", (function () {
    var rows = pem.decodeBundle(fullchain);
    return rows.length === 3 && rows[0].der.equals(CERT_DER) && rows[1].der.equals(KEY_DER) &&
      rows[2].der.equals(OTHER_DER) && labelsOf(rows) === "CERTIFICATE,CERTIFICATE,CERTIFICATE";
  })());
  check("2. each row carries the index and the byte offset its block started at", (function () {
    var rows = pem.decodeBundle(fullchain);
    return rows[0].index === 0 && rows[0].offset === 0 &&
      rows[1].index === 1 && rows[1].offset === fullchain.indexOf("-----BEGIN", 1) &&
      rows[2].index === 2;
  })());

  // A Mozilla-shaped bundle: a license header, then a subject line and a rule of equals signs
  // before each block. None of that is a block and none of it is a fault.
  var mozilla = "## This file is generated. Do not edit.\n##\n" +
    "Some Root CA\n=============\n" + block("CERTIFICATE", CERT_DER) +
    "\nAnother Root CA\n===============\n" + block("CERTIFICATE", KEY_DER) +
    "\n# end of file\n";
  check("3. explanatory text before, between and after the blocks is text", (function () {
    var rows = pem.decodeBundle(mozilla);
    return rows.length === 2 && rows[0].der.equals(CERT_DER) && rows[1].der.equals(KEY_DER);
  })());

  // Every line ending a checkout produces. A line-anchored scanner drops the bare-CR arm first.
  ["\r\n", "\r"].forEach(function (eol, i) {
    check("4." + i + " the same file with " + (eol === "\r\n" ? "CRLF" : "bare CR") + " line endings reads the same",
      (function () {
        var rows = pem.decodeBundle(rewriteEol(mozilla, eol));
        return rows.length === 2 && rows[0].der.equals(CERT_DER) && rows[1].der.equals(KEY_DER);
      })());
  });
  check("5. a file mixing LF and CRLF reads the same", (function () {
    var mixed = block("CERTIFICATE", CERT_DER) + rewriteEol(block("CERTIFICATE", KEY_DER), "\r\n");
    var rows = pem.decodeBundle(mixed);
    return rows.length === 2 && rows[0].der.equals(CERT_DER) && rows[1].der.equals(KEY_DER);
  })());

  check("6. a body wrapped at another width decodes to the same bytes, sec. 2 fixing no line size",
    pem.decodeBundle(block("CERTIFICATE", CERT_DER, 76))[0].der.equals(CERT_DER) &&
    pem.decodeBundle(block("CERTIFICATE", CERT_DER, 4096))[0].der.equals(CERT_DER));
  check("7. a blank line between the boundary and the body is spacing, not a fault",
    pem.decodeBundle("-----BEGIN CERTIFICATE-----\n\n" + wrap(CERT_DER) + "\n\n-----END CERTIFICATE-----\n")[0]
      .der.equals(CERT_DER));

  // Two files carrying the same two objects in opposite order. Acceptance cannot depend on which
  // one the writing tool put first.
  check("8. a key and a certificate read in either order, each under its own label", (function () {
    var a = pem.decodeBundle(block("PRIVATE KEY", KEY_DER) + block("CERTIFICATE", CERT_DER));
    var b = pem.decodeBundle(block("CERTIFICATE", CERT_DER) + block("PRIVATE KEY", KEY_DER));
    return labelsOf(a) === "PRIVATE KEY,CERTIFICATE" && labelsOf(b) === "CERTIFICATE,PRIVATE KEY" &&
      a[0].der.equals(KEY_DER) && b[0].der.equals(CERT_DER);
  })());
}

// ---- the label is data, not a filter -----------------------------------
function testLabelsAreCarried() {
  var pem = pki.schema.pem;
  check("9. a label the toolkit does not know is a row carrying that label",
    (function () {
      var rows = pem.decodeBundle(block("X-Y", CERT_DER));
      return rows.length === 1 && rows[0].label === "X-Y" && rows[0].der.equals(CERT_DER);
    })());
  check("10. a label is case-sensitive, so a lowercase one is its own label, not the known arm",
    (function () {
      var rows = pem.decodeBundle(block("Certificate", CERT_DER));
      return rows.length === 1 && rows[0].label === "Certificate";
    })());
  check("11. an empty label, which the ABNF admits, is a row carrying the empty label",
    (function () {
      var rows = pem.decodeBundle("-----BEGIN -----\n" + wrap(CERT_DER) + "\n-----END -----\n");
      return rows.length === 1 && rows[0].label === "";
    })());
  check("12. a routed read names the format each label claims", (function () {
    // A real certificate, since routing compares the label's claim against the structure.
    // Node's own store carries no trailing newline on the last line, which a file on disk has.
    var real = require("node:tls").rootCertificates[0] + "\n";
    var realDer = pki.schema.x509.pemDecode(real);
    var rows = pem.decodeBundle(real + block("X-Y", CERT_DER), { route: true });
    return rows.length === 2 && rows[0].format === "x509" && rows[0].der.equals(realDer) &&
      rows[1].format === null;
  })());
  check("13. an unrouted read carries no format at all, so nothing was decoded to produce one",
    Object.prototype.hasOwnProperty.call(pem.decodeBundle(block("CERTIFICATE", CERT_DER))[0], "format") === false);
}

// ---- the refusals ------------------------------------------------------
function testRefusals() {
  var pem = pki.schema.pem;
  check("14. a boundary opened and never closed is refused, not skipped",
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER) + "-----BEGIN CERTIFICATE-----\nnope\n"); }) ===
      "pem/unterminated-block");
  check("15. a block closed under another label is refused by label",
    code(function () {
      pem.decodeBundle("-----BEGIN TRUSTED CERTIFICATE-----\n" + wrap(CERT_DER) + "\n-----END CERTIFICATE-----\n");
    }) === "pem/end-mismatch");
  check("16. an RFC 1421 encrypted body is named rather than reported as a transfer fault",
    code(function () {
      pem.decodeBundle("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123\n\n" +
        wrap(CERT_DER) + "\n-----END RSA PRIVATE KEY-----\n");
    }) === "pem/legacy-headers");
  check("17. a body carrying a character outside the alphabet is a base64 fault naming its object",
    code(function () {
      pem.decodeBundle(block("CERTIFICATE", CERT_DER) + "-----BEGIN CERTIFICATE-----\n**\n-----END CERTIFICATE-----\n");
    }) === "pem/bad-base64");
  check("18. a boundary of six hyphens is text, and the one real block is still the only row",
    pem.decodeBundle("------BEGIN CERTIFICATE------\n" + block("CERTIFICATE", CERT_DER)).length === 1);
  check("19. and so is a boundary with two spaces in it",
    pem.decodeBundle("-----BEGIN  CERTIFICATE-----\n" + block("CERTIFICATE", CERT_DER)).length === 1);
  check("20. and so is a lowercase boundary, the keyword being case-sensitive (errata 4508)",
    pem.decodeBundle("-----begin certificate-----\n" + block("CERTIFICATE", CERT_DER)).length === 1);
  check("21. a file with no block at all is refused",
    code(function () { pem.decodeBundle("no blocks here\n"); }) === "pem/no-block");
  // The label grammar admits every printable character except the space and the hyphen, and admits
  // either of those only BETWEEN two of them. A line outside that is not a boundary.
  check("21a. a control character in a label is outside `labelchar`, so the line is text",
    code(function () {
      pem.decodeBundle("-----BEGIN A" + String.fromCharCode(9) + "B-----\n" + wrap(CERT_DER) + "\n-----END A-----\n");
    }) === "pem/no-block");
  check("21b. a label closing with a separator is outside the grammar too",
    code(function () { pem.decodeBundle("-----BEGIN A -----\n" + wrap(CERT_DER) + "\n-----END A -----\n"); }) === "pem/no-block");
  check("21c. CONTROL: the same separator BETWEEN two characters is a label",
    pem.decodeBundle("-----BEGIN A B-----\n" + wrap(CERT_DER) + "\n-----END A B-----\n")[0].label === "A B");
  check("21d. and a hyphen between two characters is a label",
    pem.decodeBundle(block("A-B", CERT_DER))[0].label === "A-B");
  // A byte-order mark is not part of the first line's content, on the unterminated path as well as
  // on the one that finds a block.
  check("21e. a file opening with a byte-order mark still names an unterminated block",
    code(function () {
      var bom = String.fromCharCode(0xef) + String.fromCharCode(0xbb) + String.fromCharCode(0xbf);
      pem.decodeBundle(bom + "-----BEGIN CERTIFICATE-----\n" + wrap(CERT_DER) + "\n");
    }) === "pem/unterminated-block");
  check("21g. a routed label over bytes that ARE a structure names the one they are", (function () {
    // A real certificate under a label that claims a CRL. Both halves of the refusal are named:
    // what the label claimed, and what the bytes turned out to be.
    var real = require("node:tls").rootCertificates[0] + "\n";
    var der = pki.schema.x509.pemDecode(real);
    var text = pki.schema.x509.pemEncode(der, "X509 CRL");
    var message = "";
    try { pem.decodeBundle(text, { route: true }); } catch (e) { message = e.message; }
    return message.indexOf("crl") !== -1 && message.indexOf("x509") !== -1;
  })());
  check("21f. a routed label over bytes that are no structure at all names that",
    code(function () {
      pem.decodeBundle("-----BEGIN CERTIFICATE-----\n" + Buffer.from([0x05, 0x00]).toString("base64") +
        "\n-----END CERTIFICATE-----\n", { route: true });
    }) === "pem/label-structure-mismatch");
  check("22. a routed read refuses a label whose claim the bytes do not support",
    code(function () { pem.decodeBundle(block("CERTIFICATE", KEY_DER), { route: true }); }) ===
      "pem/label-structure-mismatch");
}

// ---- the file is bounded in both directions ----------------------------
function testBounds() {
  var pem = pki.schema.pem;
  var C = require("../../lib/constants");
  check("23. the block count is bounded, and the bound is the one the constants name", (function () {
    var many = "";
    for (var i = 0; i < C.LIMITS.PEM_MAX_BLOCKS + 1; i++) many += block("CERTIFICATE", CERT_DER);
    return code(function () { pem.decodeBundle(many); }) === "pem/too-many-blocks";
  })());
  check("24. CONTROL: a file at the bound reads", (function () {
    var many = "";
    for (var i = 0; i < 64; i++) many += block("CERTIFICATE", CERT_DER);
    return pem.decodeBundle(many, { maxBlocks: 64 }).length === 64;
  })());
  check("25. a caller may tighten the block bound and is refused past it",
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER) + block("CERTIFICATE", KEY_DER), { maxBlocks: 1 }); }) ===
      "pem/too-many-blocks");
  check("25a. a bound that is not a positive whole number is refused before anything is read",
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER), { maxBlocks: 0 }); }) === "pem/bad-input" &&
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER), { maxBlocks: "3" }); }) === "pem/bad-input" &&
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER), { maxDecodedBytes: 1.5 }); }) === "pem/bad-input");
  check("26. a caller may not raise it above the ceiling the constants name",
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER), { maxBlocks: C.LIMITS.PEM_MAX_BLOCKS + 1 }); }) ===
      "pem/bad-input");
  check("27. the bytes the objects decode to are bounded across the whole file, not per object",
    code(function () {
      return pem.decodeBundle(block("CERTIFICATE", CERT_DER) + block("CERTIFICATE", KEY_DER), { maxDecodedBytes: 4 });
    }) === "pem/too-large");
  check("28. and that refusal is told apart from a malformed object, so a caller knows which to raise",
    code(function () { pem.decodeBundle(block("CERTIFICATE", CERT_DER), { maxDecodedBytes: 1 }); }) === "pem/too-large");
}

// ---- writing is the inverse --------------------------------------------
function testWritesBack() {
  var pem = pki.schema.pem;
  check("29. a list of objects writes to a file the reader reads back to the same list", (function () {
    var objects = [{ label: "CERTIFICATE", der: CERT_DER }, { label: "PRIVATE KEY", der: KEY_DER }];
    var text = pem.encodeBundle(objects);
    var rows = pem.decodeBundle(text);
    return rows.length === 2 && rows[0].label === "CERTIFICATE" && rows[0].der.equals(CERT_DER) &&
      rows[1].label === "PRIVATE KEY" && rows[1].der.equals(KEY_DER);
  })());
  check("30. and writing what was read produces the same text again", (function () {
    var once = pem.encodeBundle([{ label: "CERTIFICATE", der: CERT_DER }, { label: "CERTIFICATE", der: KEY_DER }]);
    return pem.encodeBundle(pem.decodeBundle(once)) === once;
  })());
  check("31. a label carrying a boundary cannot be written, so a value cannot inject a block",
    code(function () { pem.encodeBundle([{ label: "A-----BEGIN CERTIFICATE-----", der: CERT_DER }]); }) === "pem/bad-label");
  check("32. an object with no der is refused",
    code(function () { pem.encodeBundle([{ label: "CERTIFICATE" }]); }) === "pem/bad-input");
  check("33. a non-array is refused", code(function () { pem.encodeBundle("CERTIFICATE"); }) === "pem/bad-input");
  check("33a. an empty list is refused, a file of no objects being no file",
    code(function () { pem.encodeBundle([]); }) === "pem/bad-input");
  check("33b. an entry that is not an object is refused, naming its position",
    code(function () { pem.encodeBundle([{ label: "CERTIFICATE", der: CERT_DER }, null]); }) === "pem/bad-input" &&
    code(function () { pem.encodeBundle(["CERTIFICATE"]); }) === "pem/bad-input");
  check("33c. the writer is bounded by the same count the reader is", (function () {
    var C = require("../../lib/constants");
    var many = [];
    for (var i = 0; i < C.LIMITS.PEM_MAX_BLOCKS + 1; i++) many.push({ label: "CERTIFICATE", der: CERT_DER });
    return code(function () { pem.encodeBundle(many); }) === "pem/too-many-blocks";
  })());
}

// ---- the documented path is the path that is driven ---------------------
// Every vector above reaches these two verbs through a local alias. The advertised surface is the
// full path, so it is exercised by that name here: an alias proves the function works and says
// nothing about where an operator reading the documentation would find it.
function testTheDocumentedPath() {
  var text = pki.schema.pem.encodeBundle([{ label: "CERTIFICATE", der: CERT_DER }, { label: "PRIVATE KEY", der: KEY_DER }]);
  var rows = pki.schema.pem.decodeBundle(text);
  check("34. pki.schema.pem.encodeBundle and pki.schema.pem.decodeBundle are one round trip",
    rows.length === 2 && rows[0].label === "CERTIFICATE" && rows[0].der.equals(CERT_DER) &&
    rows[1].label === "PRIVATE KEY" && rows[1].der.equals(KEY_DER));
  check("35. and the documented options are read at that path",
    code(function () { pki.schema.pem.decodeBundle(text, { maxBlocks: 1 }); }) === "pem/too-many-blocks");
}

// ---- the single-object doors ------------------------------------------
// A verb that reads one object is handed a file holding several often enough that
// silence is the wrong answer: a fullchain pasted where a certificate was wanted
// leaves the rest of the file unread and unmentioned. Every door that takes PEM
// reaches the same scanner, so the count is decided once and every door inherits it.
function testSingleObjectDoorsRefuseAFile() {
  var one = block("CERTIFICATE", CERT_DER);
  var two = one + block("CERTIFICATE", KEY_DER);
  var three = two + block("CERTIFICATE", OTHER_DER);

  check("36. a single-object door reads a file holding one object",
    pki.schema.x509.pemDecode(one).equals(CERT_DER));
  check("37. ...and refuses one holding two, rather than reading the first",
    code(function () { pki.schema.x509.pemDecode(two); }) === "pem/multiple-blocks");
  check("38. the refusal names how many the file holds", (function () {
    try { pki.schema.x509.pemDecode(three); return "NO-THROW"; }
    catch (e) { return e.message.indexOf("3") !== -1 && e.message.indexOf("decodeBundle") !== -1; }
  })() === true);
  // The count is what decides, not the label: two objects of different kinds in one
  // file is the same question as two of the same kind.
  check("39. two objects under different labels refuse the same way",
    code(function () { pki.schema.x509.pemDecode(one + block("CERTIFICATE REQUEST", KEY_DER)); }) === "pem/multiple-blocks");
  // Explanatory text around a single block is still read, which is what an openssl
  // -text dump looks like. The rule added here is about objects, not about prose.
  check("40. explanatory text around one object is still text",
    pki.schema.x509.pemDecode("subject=CN=a\nissuer=CN=b\n" + one + "\ntrailing note\n").equals(CERT_DER));

  // Every door reaches the scanner, so none of them can disagree about a file of two
  // of the objects IT reads. Each is handed its own label, since a door refuses a
  // label it does not read before it counts anything.
  var doors = [
    ["schema.x509.pemDecode", "CERTIFICATE", function (t) { return pki.schema.x509.pemDecode(t); }],
    ["schema.crl.pemDecode", "X509 CRL", function (t) { return pki.schema.crl.pemDecode(t); }],
    ["schema.csr.pemDecode", "CERTIFICATE REQUEST", function (t) { return pki.schema.csr.pemDecode(t); }],
    ["schema.pkcs8.pemDecode", "PRIVATE KEY", function (t) { return pki.schema.pkcs8.pemDecode(t); }],
    ["schema.pkcs1.pemDecode", "RSA PRIVATE KEY", function (t) { return pki.schema.pkcs1.pemDecode(t); }],
    ["schema.sec1.pemDecode", "EC PRIVATE KEY", function (t) { return pki.schema.sec1.pemDecode(t); }],
    ["schema.cms.pemDecode", "CMS", function (t) { return pki.schema.cms.pemDecode(t); }],
    ["schema.parse", "CERTIFICATE", function (t) { return pki.schema.parse(t); }],
    ["schema.detectFormat", "CERTIFICATE", function (t) { return pki.schema.detectFormat(t); }],
  ];
  var disagreed = doors.filter(function (d) {
    var file = block(d[1], CERT_DER) + block(d[1], KEY_DER);
    return code(function () { d[2](file); }) !== "pem/multiple-blocks";
  });
  check("41. every door that takes PEM gives the same answer for a file of two objects" +
    (disagreed.length ? " (" + disagreed.map(function (d) { return d[0]; }).join(", ") + ")" : ""),
    disagreed.length === 0);

  // A boundary that opens after the first object and never closes is an object too.
  // Counting only what closes would take the first block and say nothing about what
  // the rest of the file was trying to be, which is the silence this rule is about.
  check("42. a second block that never closes is refused, not read past",
    code(function () { pki.schema.x509.pemDecode(one + "-----BEGIN CERTIFICATE-----\nAAAA\n"); }) === "pem/unterminated-block");
  // RFC 7468 sec. 3 writes the label as `[ labelchar *( ["-" / SP] labelchar ) ]`, so the
  // empty label is a label. A test that asks whether the unfinished block has a NAME reads
  // that one as absence and lets the file through, which is the shape this whole rule exists
  // to refuse.
  check("42a. a second block that opens under the empty label is still unfinished",
    code(function () { pki.schema.x509.pemDecode(one + "-----BEGIN -----\n"); }) === "pem/unterminated-block");
  check("42b. ...and one that opens under the empty label and closes is a second object",
    code(function () { pki.schema.x509.pemDecode(one + "-----BEGIN -----\nAAAA\n-----END -----\n"); }) === "pem/multiple-blocks");
  // The same reading on the other side of the comparison: asking for the empty label is
  // asking for that label, not asking for no label at all.
  check("42c. the empty label is a label a caller can ask for", (function () {
    var pkix = require("../../lib/schema-pkix");
    var empty = "-----BEGIN -----\n" + wrap(CERT_DER) + "\n-----END -----\n";
    return pkix.pemDecode(empty, "", pki.errors.PemError).equals(CERT_DER) &&
      code(function () { pkix.pemDecode(one, "", pki.errors.PemError); }) === "pem/label-mismatch";
  })());
  check("43. a second block closed under a different label is still a second object",
    code(function () {
      pki.schema.x509.pemDecode(one + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n");
    }) === "pem/multiple-blocks");
  // The verb that reads a file of objects is unaffected, and its name is what the
  // refusal above points at.
  check("44. the bundle reader still reads the same file",
    pki.schema.pem.decodeBundle(three).length === 3);
}

// ---- the verbs that take an entity as PEM ------------------------------
// pki.cms.sign, pki.cms.verify and pki.tsp.sign read a certificate or a message
// given as PEM through a second scanner, and that scanner searched the raw text
// rather than reading it by lines. So a boundary marker sitting inside explanatory
// text opened a block, a body carrying characters base64 does not use was repaired
// rather than refused, and a file of several objects was read as its first. Each of
// those is a file every parse door refuses, which is the disagreement: the same
// bytes are an object to one verb and malformed to the next.
async function testEntityDoorsReadTheSameFile() {
  var certPem = helpers.vectors.CERT_EC_PEM;
  var certDer = pki.schema.x509.pemDecode(certPem);
  var kp = require("crypto").generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var key = kp.privateKey.export({ format: "der", type: "pkcs8" });
  var signerDer = await pki.x509.sign({
    subject: [{ commonName: "pem-door-signer.example" }],
    subjectPublicKey: kp.publicKey.export({ format: "der", type: "spki" }),
    serialNumber: 77, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: { keyUsage: ["digitalSignature"], subjectKeyIdentifier: true },
  }, { key: key });
  var signerPem = pki.schema.x509.pemEncode(signerDer, "CERTIFICATE");
  var body = signerPem.slice(signerPem.indexOf("\n") + 1);

  async function signCode(cert) {
    try { await pki.cms.sign(Buffer.from("x"), { cert: cert, key: key }); return "NO-THROW"; }
    catch (e) { return e.code || e.name; }
  }

  check("43. a signer certificate given as one PEM block still signs",
    (await signCode(signerPem)) === "NO-THROW");
  check("44. a boundary opened mid-line is not an object at the signer door",
    (await signCode("note: -----BEGIN CERTIFICATE-----\n" + body)) === "cms/bad-input");
  check("45. ...and the parse doors already read that file the same way",
    code(function () { pki.schema.x509.pemDecode("note: -----BEGIN CERTIFICATE-----\n" + body); }) === "pem/no-block");
  check("46. a body carrying characters base64 does not use is refused, not repaired",
    (await signCode(signerPem.replace("\n", "\n!!"))) === "cms/bad-input");
  check("47. a file holding the signer and its issuer is refused rather than read as the first",
    (await signCode(signerPem + certPem)) === "cms/bad-input");

  // The message door: a CMS given as PEM. The timestamp signer reads its certificate
  // through the same helper and is held to this in tsp-sign.test.js, where the
  // conforming TSA certificate its own profile requires is already built.
  var signed = await pki.cms.sign(Buffer.from("x"), { cert: signerDer, key: key });
  var cmsPem = pki.schema.cms.pemEncode(signed, "CMS");
  async function verifyCode(text) {
    try { await pki.cms.verify(text); return "NO-THROW"; }
    catch (e) { return e.code || e.name; }
  }
  check("50. a CMS message given as one PEM block still verifies",
    (await verifyCode(cmsPem)) === "NO-THROW");
  // A message given as a string reaches the scanner through the shared coercion, so it
  // reports the PEM family directly, as it already does for a body that is not base64.
  check("51. two messages in one file are refused rather than read as the first",
    (await verifyCode(cmsPem + cmsPem)) === "pem/multiple-blocks");
  check("51a. ...the same family the door already answers with for a malformed body",
    (await verifyCode(cmsPem.replace("\n", "\n!!"))) === "pem/bad-base64");
  check("52. the certificate vector is unchanged by any of this",
    pki.schema.x509.parse(certDer).subject.bytes.length > 0);
}

// RFC 5958 gives the private-key encoding two structures, `PrivateKeyInfo` and
// `EncryptedPrivateKeyInfo`, with an armor label each (RFC 7468 sec. 10 and sec. 11). Routing
// both labels to the same structural check makes one of them unroutable and the other a test
// that passes for bytes it should refuse, so each label is checked against its own structure.
// A byte-order mark reaches the scanner in whichever form the caller's decode produced: the
// three bytes EF BB BF when the file was read as latin1 or handed over as a Buffer, and the
// single character U+FEFF when it was read as UTF-8. A scanner that knows one of them skips
// the first boundary line of the other, which drops the first object of the file in silence.
// RFC 7468 sec. 3 gives a strict generator grammar and a lax parser grammar, and the lax one
// writes `eolWSP = W* eol`: a boundary line may carry spaces and tabs after its closing
// hyphens. A reader that treats such a line as prose does more than refuse a file a real tool
// wrote: it makes the object behind that boundary invisible, so a single-object door hands
// back the first object of a two-object file without saying there was a second.
function testBoundaryTrailingWhitespace() {
  var one = block("CERTIFICATE", CERT_DER);
  function pad(text, ws) {
    var lines = text.split("\n"), out = [];
    for (var i = 0; i < lines.length; i++) {
      out.push(lines[i].slice(0, 5) === "-----" ? lines[i] + ws : lines[i]);
    }
    return out.join("\n");
  }
  var spaced = pad(one, " "), tabbed = pad(one, "\t"), both = pad(one, " \t ");
  check("71. a boundary carrying trailing spaces is a boundary",
    pki.schema.x509.pemDecode(spaced).equals(CERT_DER));
  check("72. ...and tabs, and a run of both",
    pki.schema.x509.pemDecode(tabbed).equals(CERT_DER) &&
    pki.schema.x509.pemDecode(both).equals(CERT_DER));
  check("73. a second object behind such a boundary is seen, not passed over",
    code(function () { pki.schema.x509.pemDecode(one + spaced); }) === "pem/multiple-blocks" &&
    code(function () { pki.schema.x509.pemDecode(spaced + one); }) === "pem/multiple-blocks");
  check("74. a bundle reads both objects",
    pki.schema.pem.decodeBundle(one + spaced).length === 2 &&
    pki.schema.pem.decodeBundle(spaced + tabbed).length === 2);
  check("75. trailing NON-whitespace still makes the line prose",
    code(function () { pki.schema.x509.pemDecode(pad(one, " x")); }) === "pem/no-block" &&
    code(function () { pki.schema.x509.pemDecode(pad(one, "-")); }) === "pem/no-block");
  check("76. an unterminated block whose boundary carries whitespace is still named",
    code(function () { pki.schema.pem.decodeBundle("-----BEGIN CERTIFICATE----- \nAAAA\n"); }) === "pem/unterminated-block");
  check("77. the label is read the same either way",
    pki.schema.pem.decodeBundle(spaced)[0].label === "CERTIFICATE");
  // A vertical tab or a form feed after the hyphens is whitespace too. Reading either as
  // content is the same fault as reading a space that way: the object goes missing.
  var vt = pad(one, "\u000b"), ff = pad(one, "\u000c");
  check("77a. a vertical tab and a form feed are whitespace, not content",
    pki.schema.x509.pemDecode(vt).equals(CERT_DER) && pki.schema.x509.pemDecode(ff).equals(CERT_DER));
  check("77b. and an object behind one of them is seen",
    code(function () { pki.schema.x509.pemDecode(one + vt); }) === "pem/multiple-blocks" &&
    code(function () { pki.schema.x509.pemDecode(one + ff); }) === "pem/multiple-blocks" &&
    pki.schema.pem.decodeBundle(one + vt).length === 2);
}

// The row says where in the text the object starts, and the text is what this reader read:
// a Buffer is decoded as latin1, so one character is one byte and the offset is the byte
// offset into the file. A caller handing in a string it decoded itself gets an offset into
// that string, which is why the field says what it counts.
// Whether a buffer is armored text is answered by walking it until the first byte no text file
// carries, which on DER is its first byte and on printable input is the whole of it. A buffer
// past every cap either arm could accept is refused for its size before that walk, so hostile
// input costs what a refusal costs rather than what reading it would.
function testOversizedInputIsRefusedBeforeItIsRead() {
  var cap = pki.constants.LIMITS.PEM_MAX_BYTES;
  var oversized = Buffer.alloc(cap + (1024 * 1024), 0x2d);
  var started = Date.now();
  var got = code(function () { pki.schema.x509.parse(oversized); });
  var took = Date.now() - started;
  check("50. a buffer past the ceiling is refused for its size", got === "x509/too-large");
  // The bound is one large input against a wall-clock ceiling rather than a ratio, which a
  // loaded machine makes meaningless. Reading 17 MiB of printable bytes took seconds.
  check("51. ...and the refusal does not read it first (" + took + "ms)", took < 2000);
  check("52. every parse door answers the same way",
    code(function () { pki.schema.crl.parse(oversized); }) === "crl/too-large" &&
    code(function () { pki.schema.cms.parse(oversized); }) === "cms/too-large");
  check("52a. CONTROL: a buffer inside the ceiling is still read",
    code(function () { pki.schema.x509.parse(Buffer.alloc(1024, 0x2d)); }) === "x509/bad-der");
}

function testRowOffsets() {
  var one = block("CERTIFICATE", CERT_DER);
  var file = "note\n" + one + block("CERTIFICATE", KEY_DER);
  var fromString = pki.schema.pem.decodeBundle(file);
  var fromBuffer = pki.schema.pem.decodeBundle(Buffer.from(file, "latin1"));
  check("78. the offsets agree between a latin1 string and the same bytes",
    fromString[0].offset === fromBuffer[0].offset && fromString[1].offset === fromBuffer[1].offset);
  check("79. the first object starts where the text says it does",
    fromBuffer[0].offset === 5 && file.slice(fromBuffer[0].offset, fromBuffer[0].offset + 11) === "-----BEGIN ");
  check("80. and so does the second",
    file.slice(fromBuffer[1].offset, fromBuffer[1].offset + 11) === "-----BEGIN ");
  check("81. a mark before the first object is part of the file, and the offset says so",
    Buffer.from("﻿" + one, "utf8").length === Buffer.from(one, "latin1").length + 3 &&
    pki.schema.pem.decodeBundle(Buffer.from("﻿" + one, "utf8"))[0].offset === 3);
}

function testBomInEitherForm() {
  var one = block("CERTIFICATE", CERT_DER);
  var latin1Bom = "ï»¿";
  check("58. a U+FEFF mark before the first boundary is a mark, not text",
    pki.schema.x509.pemDecode("﻿" + one).equals(CERT_DER));
  check("59. the three-byte form still is too",
    pki.schema.x509.pemDecode(latin1Bom + one).equals(CERT_DER) &&
    pki.schema.x509.pemDecode(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(one, "latin1")])).equals(CERT_DER));
  check("60. a bundle reads every object under either mark",
    pki.schema.pem.decodeBundle("﻿" + one + block("CERTIFICATE", KEY_DER)).length === 2 &&
    pki.schema.pem.decodeBundle(latin1Bom + one + block("CERTIFICATE", KEY_DER)).length === 2);
  check("61. a mark that is not at the front is text, and text is not a boundary",
    code(function () { pki.schema.x509.pemDecode("note\n﻿" + one); }) === "pem/no-block" ||
    pki.schema.x509.pemDecode("note\n" + one).equals(CERT_DER));
  check("62. a file that is only a mark holds no block",
    code(function () { pki.schema.pem.decodeBundle("﻿"); }) === "pem/no-block" &&
    code(function () { pki.schema.pem.decodeBundle(latin1Bom); }) === "pem/no-block");
  check("63. an unterminated block behind a U+FEFF mark is still named",
    code(function () { pki.schema.pem.decodeBundle("﻿-----BEGIN CERTIFICATE-----\nAAAA\n"); }) === "pem/unterminated-block");
}

// The key encodings this cut added have RFC 7468 labels of their own (sec. 10 for PKCS#8,
// and the legacy PKCS#1 and SEC1 armor operators still hold keys in). A label whose parser
// ships but whose row is missing routes to `null`, so the label/structure check the bundle
// reader promises never runs for it.
function testKeyLabelRouting() {
  var crypto = require("node:crypto");
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var rsaPriv = pki.schema.pkcs1.pemEncode(rsa.privateKey.export({ format: "der", type: "pkcs1" }));
  var rsaPub = pki.schema.pkcs1.pemEncodePublic(rsa.publicKey.export({ format: "der", type: "pkcs1" }));
  var ecPriv = pki.schema.sec1.pemEncode(ec.privateKey.export({ format: "der", type: "sec1" }));

  function fmt(text) { return pki.schema.pem.decodeBundle(text, { route: true })[0].format; }
  check("64. an RSA PRIVATE KEY routes to the PKCS#1 structure", fmt(rsaPriv) === "pkcs1");
  check("65. an RSA PUBLIC KEY routes to its own", fmt(rsaPub) === "pkcs1-public");
  check("66. an EC PRIVATE KEY routes to the SEC1 structure", fmt(ecPriv) === "sec1");
  check("67. bytes that are not that structure are refused under the label",
    code(function () {
      pki.schema.pem.decodeBundle("-----BEGIN RSA PRIVATE KEY-----\n" +
        pki.asn1.build.sequence([]).toString("base64") + "\n-----END RSA PRIVATE KEY-----\n", { route: true });
    }) === "pem/label-structure-mismatch");
  check("68. ...and so are the other two",
    code(function () {
      pki.schema.pem.decodeBundle("-----BEGIN EC PRIVATE KEY-----\n" +
        pki.asn1.build.sequence([]).toString("base64") + "\n-----END EC PRIVATE KEY-----\n", { route: true });
    }) === "pem/label-structure-mismatch" &&
    code(function () {
      pki.schema.pem.decodeBundle("-----BEGIN RSA PUBLIC KEY-----\n" +
        pki.asn1.build.sequence([]).toString("base64") + "\n-----END RSA PUBLIC KEY-----\n", { route: true });
    }) === "pem/label-structure-mismatch");
  check("69. a private key under the public label is refused, and the other way round",
    code(function () { pki.schema.pem.decodeBundle(pki.schema.pkcs1.pemEncodePublic(rsa.privateKey.export({ format: "der", type: "pkcs1" })), { route: true }); }) === "pem/label-structure-mismatch" &&
    code(function () { pki.schema.pem.decodeBundle(pki.schema.pkcs1.pemEncode(rsa.publicKey.export({ format: "der", type: "pkcs1" })), { route: true }); }) === "pem/label-structure-mismatch");
  check("70. a file holding all three reads as three rows",
    pki.schema.pem.decodeBundle(rsaPriv + rsaPub + ecPriv, { route: true })
      .map(function (r) { return r.format; }).join(",") === "pkcs1,pkcs1-public,sec1");
}

function testEncryptedPrivateKeyRouting() {
  var crypto = require("node:crypto");
  var encDer = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .privateKey.export({ format: "der", type: "pkcs8", cipher: "aes-256-cbc", passphrase: "pw" });
  var plainDer = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .privateKey.export({ format: "der", type: "pkcs8" });
  function armor(label, der) {
    var b64 = der.toString("base64"), out = [];
    for (var i = 0; i < b64.length; i += 64) out.push(b64.slice(i, i + 64));
    return "-----BEGIN " + label + "-----\n" + out.join("\n") + "\n-----END " + label + "-----\n";
  }
  var encPem = armor("ENCRYPTED PRIVATE KEY", encDer);
  var plainPem = armor("PRIVATE KEY", plainDer);

  check("53. an ENCRYPTED PRIVATE KEY routes, as its own parser already reads it", (function () {
    var rows = pki.schema.pem.decodeBundle(encPem, { route: true });
    return rows.length === 1 && rows[0].format === "pkcs8-encrypted";
  })());
  check("54. a PRIVATE KEY still routes to the unencrypted structure", (function () {
    var rows = pki.schema.pem.decodeBundle(plainPem, { route: true });
    return rows.length === 1 && rows[0].format === "pkcs8";
  })());
  check("55. encrypted bytes under the unencrypted label are refused",
    code(function () { pki.schema.pem.decodeBundle(armor("PRIVATE KEY", encDer), { route: true }); }) === "pem/label-structure-mismatch");
  check("56. unencrypted bytes under the encrypted label are refused",
    code(function () { pki.schema.pem.decodeBundle(armor("ENCRYPTED PRIVATE KEY", plainDer), { route: true }); }) === "pem/label-structure-mismatch");
  check("57. both read in one file", (function () {
    var rows = pki.schema.pem.decodeBundle(plainPem + encPem, { route: true });
    return rows.length === 2 && rows[0].format === "pkcs8" && rows[1].format === "pkcs8-encrypted";
  })());
}

async function run() {
  testOversizedInputIsRefusedBeforeItIsRead();
  testBoundaryTrailingWhitespace();
  testRowOffsets();
  testBomInEitherForm();
  testKeyLabelRouting();
  testEncryptedPrivateKeyRouting();
  testTheDocumentedPath();
  testAcceptsRealBundles();
  testLabelsAreCarried();
  testRefusals();
  testBounds();
  testWritesBack();
  testSingleObjectDoorsRefuseAFile();
  await testEntityDoorsReadTheSameFile();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
