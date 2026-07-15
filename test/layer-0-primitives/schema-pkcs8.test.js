// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.pkcs8 (PKCS#8 PrivateKeyInfo / OneAsymmetricKey parser,
 * RFC 5208 §5 + RFC 5958 §2/§3). Spec-first conformance vectors: valid keys parse
 * to the documented shape; every malformed PrivateKeyInfo is rejected fail-closed
 * with a typed pkcs8/* (or leaf-level asn1/*) error. Composes the shared
 * parse-entry + PKIX sub-schemas. The private-key OCTET STRING is kept RAW; there
 * is no signature, no Name, no signedEnvelope. version accepts {0,1} and the
 * publicKey [1] is permitted only in v2 (the version⇔publicKey biconditional).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var fs = require("fs");
var path = require("path");

var ED25519 = "1.3.101.112"; // id-Ed25519 (a byte-aligned key — simple fixtures)
var FRIENDLY = "1.2.840.113549.1.9.20"; // friendlyName (a PKCS#9 attribute type)

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.pkcs8.parse(der); }); }
function parse(der) { return pki.schema.pkcs8.parse(der); }

function algId(o) { return b.sequence([b.oid(o)]); }
function pk(o) {
  o = o || {};
  var c = [];
  c.push(o.version !== undefined ? o.version : b.integer(0n));
  c.push(o.alg || algId(ED25519));
  c.push(o.priv || b.octetString(Buffer.from([1, 2, 3, 4])));
  if (o.attrNode) c.push(o.attrNode);
  if (o.pubNode) c.push(o.pubNode);
  if (o.trailing) o.trailing.forEach(function (t) { c.push(t); });
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}
function attrs(list) { return b.contextConstructed(0, list.length ? Buffer.concat(list) : Buffer.alloc(0)); }
function attribute(t, vals) { return b.sequence([b.oid(t), b.set(vals)]); }
// [1] IMPLICIT (primitive) BIT STRING: 0x81, content = unused-bits(0x00) + body.
function pub(bytes) { return b.contextPrimitive(1, Buffer.concat([Buffer.from([0x00]), bytes])); }

function testValid() {
  var m = parse(pk({}));
  check("minimal v1: version 1", m.version === 1);
  check("minimal v1: raw privateKey content", Buffer.isBuffer(m.privateKey) && m.privateKey.length === 4);
  check("minimal v1: no attributes", Array.isArray(m.attributes) && m.attributes.length === 0);
  check("minimal v1: no publicKey", m.publicKey === null);
  check("minimal v1: privateKeyAlgorithm named", m.privateKeyAlgorithm.oid === ED25519);

  var a = parse(pk({ attrNode: attrs([attribute(FRIENDLY, [b.utf8("friendly")])]) }));
  check("v1 with [0] attributes", a.version === 1 && a.attributes.length === 1 && a.attributes[0].type === FRIENDLY);

  var v2 = parse(pk({ version: b.integer(1n), pubNode: pub(Buffer.from([0xAA, 0xBB, 0xCC])) }));
  check("v2 with [1] publicKey", v2.version === 2 && v2.publicKey.bytes.length === 3 && v2.publicKey.unusedBits === 0);

  var both = parse(pk({ version: b.integer(1n), attrNode: attrs([attribute(FRIENDLY, [b.utf8("x")])]), pubNode: pub(Buffer.from([1, 2])) }));
  check("v2 with [0] attributes then [1] publicKey", both.version === 2 && both.attributes.length === 1 && both.publicKey.bytes.length === 2);

  // Raw privateKey preserved byte-for-byte (the OCTET-STRING content, not the wrapper).
  var body = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x2A]);
  var rsa = parse(pk({ alg: b.sequence([b.oid("1.2.840.113549.1.1.1")]), priv: b.octetString(body) }));
  check("raw privateKey preserved across algorithms", rsa.privateKey.equals(body));
}

function testVersion() {
  check("version 2 rejected", parseCode(pk({ version: b.integer(2n) })) === "pkcs8/bad-version");
  check("version 255 rejected", parseCode(pk({ version: b.integer(255n) })) === "pkcs8/bad-version");
  check("version -1 rejected", parseCode(pk({ version: b.integer(-1n) })) === "pkcs8/bad-version");
  var c = parseCode(pk({ children: [b.explicit(0, b.integer(0n)), algId(ED25519), b.octetString(Buffer.from([1]))] }));
  check("cert-shaped [0] EXPLICIT version fails closed (PKCS#8 version is a bare INTEGER)", c !== "NO-THROW" && (c.indexOf("pkcs8/") === 0 || c.indexOf("asn1/") === 0));
  // version⇔publicKey biconditional (RFC 5958 §2).
  check("v1 WITH publicKey rejected", parseCode(pk({ version: b.integer(0n), pubNode: pub(Buffer.from([1, 2])) })) === "pkcs8/bad-version");
  check("v2 WITHOUT publicKey rejected", parseCode(pk({ version: b.integer(1n) })) === "pkcs8/bad-version");
}

function testOuterAndPrivateKey() {
  check("outer not a SEQUENCE rejected", parseCode(b.set([b.integer(0n), algId(ED25519), b.octetString(Buffer.from([1]))])) === "pkcs8/not-a-private-key-info");
  check("fewer than 3 elements rejected", parseCode(pk({ children: [b.integer(0n), algId(ED25519)] })) === "pkcs8/not-a-private-key-info");
  check("trailing byte after outer SEQUENCE rejected", parseCode(Buffer.concat([pk({}), Buffer.from([0x00])])) === "pkcs8/bad-der");
  var wrongTag = parseCode(pk({ priv: b.bitString(Buffer.from([1, 2]), 0) }));
  check("privateKey wrong tag (BIT STRING) rejected", wrongTag !== "NO-THROW" && (wrongTag.indexOf("asn1/") === 0 || wrongTag.indexOf("pkcs8/") === 0));
  // A constructed OCTET STRING (0x24) fails closed — the strict-DER codec rejects
  // a constructed encoding of a primitive-only type at decode (pkcs8/bad-der),
  // before the octetString leaf runs.
  var constructedOs = b.sequence([b.integer(0n), algId(ED25519), Buffer.from([0x24, 0x03, 0x04, 0x01, 0xAA])]);
  var cos = parseCode(constructedOs);
  check("constructed OCTET STRING privateKey rejected fail-closed", cos !== "NO-THROW" && (cos.indexOf("asn1/") === 0 || cos.indexOf("pkcs8/") === 0));
  var empty = parse(pk({ priv: b.octetString(Buffer.alloc(0)) }));
  check("zero-length privateKey surfaced (bytes preserved)", empty.privateKey.length === 0);
}

function testAlgIdAndAttributes() {
  check("privateKeyAlgorithm not a SEQUENCE rejected", parseCode(pk({ alg: b.integer(5n) })) === "pkcs8/bad-algorithm-identifier");
  // FIPS 203 ML-KEM AlgorithmIdentifier parameters MUST be absent — a KEM never
  // reaches the signature-verification path, so the shipped parse is the only
  // layer that can reject the violation.
  check("ML-KEM key with NULL algorithm parameters rejected (params MUST be absent)",
    parseCode(pk({ alg: b.sequence([b.oid("2.16.840.1.101.3.4.4.1"), b.nullValue()]) })) === "pkcs8/bad-algorithm-parameters");
  check("ML-KEM key without algorithm parameters parses",
    parseCode(pk({ alg: b.sequence([b.oid("2.16.840.1.101.3.4.4.1")]) })) === "NO-THROW");
  check("attributes [0] primitive rejected (must be constructed)", parseCode(pk({ attrNode: b.contextPrimitive(0, Buffer.from([1, 2, 3])) })) === "pkcs8/bad-attributes");
  check("unknown trailing context tag [2] rejected", parseCode(pk({ trailing: [b.contextConstructed(2, Buffer.alloc(0))] })) !== "NO-THROW");
  var descending = parseCode(pk({ children: [b.integer(1n), algId(ED25519), b.octetString(Buffer.from([1])), pub(Buffer.from([1])), attrs([attribute(FRIENDLY, [b.utf8("x")])])] }));
  check("[1] before [0] (descending) rejected", descending !== "NO-THROW");
  check("duplicated context tag [0] rejected", parseCode(pk({ trailing: [attrs([]), attrs([])] })) !== "NO-THROW");
  check("Attribute element not a SEQUENCE rejected", parseCode(pk({ attrNode: attrs([b.integer(1n)]) })) === "pkcs8/bad-attribute");
  check("Attribute empty values SET rejected", parseCode(pk({ attrNode: attrs([b.sequence([b.oid(FRIENDLY), b.set([])])]) })) === "pkcs8/bad-attribute-values");
}

function testPublicKey() {
  // [1] IMPLICIT BIT STRING is primitive; a constructed [1] (0xA1) is a leaf-level
  // shape fault surfaced as asn1/* (the codec's _expectPrimitive).
  var constructed = parseCode(pk({ version: b.integer(1n), pubNode: b.contextConstructed(1, Buffer.from([0x00, 0xAA])) }));
  check("publicKey [1] constructed rejected", constructed !== "NO-THROW" && (constructed.indexOf("asn1/") === 0 || constructed.indexOf("pkcs8/") === 0));
  var unused = parseCode(pk({ version: b.integer(1n), pubNode: b.contextPrimitive(1, Buffer.from([0x08, 0xAA])) }));
  check("publicKey unused-bits > 7 rejected", unused !== "NO-THROW" && (unused.indexOf("asn1/") === 0 || unused.indexOf("pkcs8/") === 0));
}

function testDispatch() {
  // A real certificate is NOT misclassified as PKCS#8.
  var certPem = fs.readFileSync(path.join(__dirname, "..", "fixtures", "pkijs-selfsigned-ec.pem"), "utf8");
  var cert = pki.schema.parse(certPem);
  check("a certificate is not misrouted to pkcs8", cert.version === 3 && cert.validity && cert.validity.notBefore instanceof Date);
  // A complete PKCS#8 routes to the pkcs8 member; all() lists it.
  var routed = pki.schema.parse(pk({ version: b.integer(1n), pubNode: pub(Buffer.from([1, 2, 3])) }));
  check("a PKCS#8 routes to pkcs8", routed.privateKey && routed.version === 2 && routed.validity === undefined);
  check("all() lists pkcs8", pki.schema.all().indexOf("pkcs8") !== -1);
  // An EncryptedPrivateKeyInfo is NOT auto-routed by pki.schema.parse — its
  // SEQUENCE{SEQUENCE, OCTET STRING} shape is ambiguous (a PKCS#1 DigestInfo has
  // the same shape), so structural detection alone cannot classify it. It is
  // parsed explicitly via pkcs8.parseEncrypted (the operator knows the key is
  // encrypted, e.g. from an 'ENCRYPTED PRIVATE KEY' PEM label).
  var enc = b.sequence([b.sequence([b.oid("1.2.840.113549.1.5.13")]), b.octetString(Buffer.from([0xDE, 0xAD]))]);
  check("an EncryptedPrivateKeyInfo is NOT auto-routed (ambiguous shape)", code(function () { pki.schema.parse(enc); }) === "schema/unknown-format");
  var em = pki.schema.pkcs8.parseEncrypted(enc);
  check("parseEncrypted parses it explicitly", em.encryptionAlgorithm.oid === "1.2.840.113549.1.5.13" && Buffer.isBuffer(em.encryptedData));
  // A PKCS#1 DigestInfo (SEQUENCE{AlgorithmIdentifier, OCTET STRING}) must NOT be
  // mis-classified as an encrypted key by the orchestrator.
  var digestInfo = b.sequence([b.sequence([b.oid("2.16.840.1.101.3.4.2.1")]), b.octetString(Buffer.from([0xAB, 0xCD]))]);
  check("a DigestInfo is not mis-classified as an encrypted key", code(function () { pki.schema.parse(digestInfo); }) === "schema/unknown-format");
}

function testInputCoercion() {
  var der = pk({});
  var pem = "-----BEGIN PRIVATE KEY-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END PRIVATE KEY-----";
  check("parse a DER Buffer", parseCode(der) === "NO-THROW");
  check("parse a PEM string", parseCode(pem) === "NO-THROW");
  check("parse a PEM Buffer", parseCode(Buffer.from(pem, "utf8")) === "NO-THROW");
  check("parse a PEM Buffer with a BOM", parseCode(Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(pem, "utf8")])) === "NO-THROW");
  check("parse a Uint8Array", parseCode(new Uint8Array(der)) === "NO-THROW");
  check("bad input type rejected", parseCode(42) === "pkcs8/bad-input");
  check("pemDecode yields DER", pki.schema.pkcs8.pemDecode(pem)[0] === 0x30);
}

function testMultiDefectFailClosed() {
  var c = parseCode(pk({ version: b.integer(9n), alg: b.integer(5n), priv: b.bitString(Buffer.from([1]), 0) }));
  check("multi-defect PKCS#8 stays fail-closed (typed, no raw crash)", c !== "NO-THROW" && c.indexOf("RAW:") !== 0);
}

// parseEncrypted's fail-closed envelope (RFC 5958 §3): EncryptedPrivateKeyInfo
// is a SEQUENCE of EXACTLY {AlgorithmIdentifier, OCTET STRING}, and the PEM
// entry enforces the ENCRYPTED PRIVATE KEY label.
function testParseEncryptedRejections() {
  var PBES2 = "1.2.840.113549.1.5.13";
  function encCode(input) { return code(function () { pki.schema.pkcs8.parseEncrypted(input); }); }
  var good = b.sequence([b.sequence([b.oid(PBES2)]), b.octetString(Buffer.from([0xDE, 0xAD]))]);

  check("parseEncrypted: 3-element SEQUENCE rejected (exactly two fields)",
    encCode(b.sequence([b.sequence([b.oid(PBES2)]), b.octetString(Buffer.from([0xDE])), b.integer(1n)])) === "pkcs8/not-an-encrypted-private-key-info");
  check("parseEncrypted: outer not a SEQUENCE (a SET) rejected",
    encCode(b.set([b.sequence([b.oid(PBES2)]), b.octetString(Buffer.from([0xDE]))])) === "pkcs8/not-an-encrypted-private-key-info");
  var bitStr = encCode(b.sequence([b.sequence([b.oid(PBES2)]), b.bitString(Buffer.from([0xDE]), 0)]));
  check("parseEncrypted: encryptedData as BIT STRING rejected",
    bitStr !== "NO-THROW" && (bitStr.indexOf("asn1/") === 0 || bitStr.indexOf("pkcs8/") === 0));
  check("parseEncrypted: encryptionAlgorithm not a SEQUENCE rejected",
    encCode(b.sequence([b.integer(1n), b.octetString(Buffer.from([0xDE]))])) === "pkcs8/bad-algorithm-identifier");

  var wrongLabelPem = "-----BEGIN PRIVATE KEY-----\n" + good.toString("base64") + "\n-----END PRIVATE KEY-----";
  check("parseEncrypted: a 'PRIVATE KEY' PEM label rejected (label enforcement)",
    encCode(wrongLabelPem) === "pem/label-mismatch");
  var pem = pki.schema.pkcs8.pemEncode(good, "ENCRYPTED PRIVATE KEY");
  var viaPem = pki.schema.pkcs8.parseEncrypted(pem);
  check("parseEncrypted: an ENCRYPTED PRIVATE KEY PEM round-trips",
    viaPem.encryptionAlgorithm.oid === PBES2 && viaPem.encryptedData.equals(Buffer.from([0xDE, 0xAD])));
}

function run() {
  testValid();
  testVersion();
  testOuterAndPrivateKey();
  testAlgIdAndAttributes();
  testPublicKey();
  testDispatch();
  testInputCoercion();
  testMultiDefectFailClosed();
  testParseEncryptedRejections();
  testMlKemPrivateKeys();
}

// ML-KEM PKCS#8 (RFC 9935 sec. 6): both real producer shapes parse -- Node's seed-only
// [0] arm (66-byte inner) and the published App C.1 seed/expandedKey/both arms across all
// three parameter sets. The parse surfaces the inner CHOICE as opaque octets (raw-by-design,
// algorithm-agnostic -- the CHOICE validation lives at the webcrypto import boundary), and
// the RFC 5958 version<->publicKey coupling holds on the ML-KEM shapes.
function testMlKemPrivateKeys() {
  var fs = require("fs");
  var path = require("path");
  var FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "mlkem", "rfc9935-appc.json"), "utf8")).vectors;
  function fx(n) { return Buffer.from(FIX[n].derHex, "hex"); }
  var b = pki.asn1.build;
  function O(n) { return pki.oid.byName(n); }
  [512, 768, 1024].forEach(function (set) {
    ["seed", "expanded", "both"].forEach(function (arm) {
      var der = fx("mlkem" + set + "-" + arm);
      var p = pki.schema.pkcs8.parse(der);
      check("ML-KEM-" + set + " " + arm + " arm (RFC 9935 C.1) parses",
        p.privateKeyAlgorithm.name === "id-ml-kem-" + set && Buffer.isBuffer(p.privateKey));
      check("ML-KEM-" + set + " " + arm + " orchestrator routes to pkcs8", (function () { var r = pki.schema.parse(der); return Buffer.isBuffer(r.privateKey) && r.validity === undefined && r.privateKeyAlgorithm.name === "id-ml-kem-" + set; })());
    });
    // Node's own emit shape (seed-only [0], 66-byte inner) parses identically.
    var nodeDer = require("node:crypto").generateKeyPairSync("ml-kem-" + set).privateKey.export({ format: "der", type: "pkcs8" });
    var np = pki.schema.pkcs8.parse(nodeDer);
    check("ML-KEM-" + set + " Node seed-only emit parses (66-byte [0] inner surfaced raw)",
      np.privateKey.length === 66 && np.privateKey[0] === 0x80);
  });
  // RFC 5958 version<->publicKey coupling on an ML-KEM shape: a v1 envelope carrying a
  // [1] publicKey (or v2 without one) is rejected -- re-pinned on this algorithm.
  var seedInner = Buffer.concat([Buffer.from([0x80, 0x40]), Buffer.alloc(64, 1)]);
  var v1WithPub = b.sequence([b.integer(0n), b.sequence([b.oid(O("id-ml-kem-768"))]), b.octetString(seedInner), b.contextPrimitive(1, Buffer.concat([Buffer.from([0x00]), Buffer.alloc(1184, 2)]))]);
  check("ML-KEM pkcs8 v1 carrying a [1] publicKey -> pkcs8/bad-version",
    code(function () { pki.schema.pkcs8.parse(v1WithPub); }) === "pkcs8/bad-version");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
