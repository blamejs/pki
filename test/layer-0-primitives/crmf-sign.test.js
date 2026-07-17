// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.crmf.build -- the RFC 4211 CertReqMessages producing side. Every vector
// drives the shipped consumer pki.crmf.build(spec, key, opts) and asserts through pki.schema.crmf.parse (the
// round-trip GREEN oracle) or err.code. The #1 fragile area is the CertTemplate [0]..[9] IMPLICIT tag
// boundary: each field tag REPLACES the base tag preserving the P/C bit (issuer[3]/subject[5]/publicKey[6]/
// extensions[9] constructed, version[0] primitive), with the OptionalValidity notBefore[0]/notAfter[1] Time
// as the EXPLICIT exceptions -- each has a dedicated re-parse vector asserting the exact identifier octet.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;
var nodeCrypto = require("node:crypto");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}
function parse(der) { return pki.schema.crmf.parse(der).messages; }
function tpl(spki, over) { return Object.assign({ subject: [{ commonName: "device" }], publicKey: spki }, over || {}); }

// Verify a POPOSigningKey signature over the parser-surfaced signed region under the requested key,
// dispatching on the key type (the sign-scheme registry matches the ECDSA digest to the curve).
function popVerifies(msg, spki, signedRegion) {
  var pub = nodeCrypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  var sig = msg.popo.signature.bytes;
  var kt = pub.asymmetricKeyType;
  if (kt === "ec") return nodeCrypto.verify("sha256", signedRegion, { key: pub, dsaEncoding: "der" }, sig);   // the registry's ECDSA default digest
  if (kt === "rsa" || kt === "rsa-pss") return nodeCrypto.verify("sha256", signedRegion, pub, sig);
  return nodeCrypto.verify(null, signedRegion, pub, sig);   // ed25519 / ed448 / ml-dsa / slh-dsa
}

// ---- round-trip + byte-stability + POP ------------------------------------

async function testRoundTrip() {
  var s = makeSigner("ec-p256");
  var der = await pki.crmf.build({ certReqId: 0, certTemplate: tpl(s.spki, { validity: { notBefore: NB, notAfter: NA }, extensions: { subjectAltName: [{ dNSName: "d.example" }] } }) }, { key: s.key });
  check("build returns a Buffer", Buffer.isBuffer(der));
  var m = parse(der)[0], cr = m.certReq;
  check("round-trip certReqId", cr.certReqId === 0n);
  check("round-trip subject", cr.certTemplate.subject.dn === "CN=device");
  check("round-trip publicKey", Buffer.compare(cr.certTemplate.publicKey.bytes, s.spki) === 0);
  check("round-trip validity Dates", cr.certTemplate.validity.notBefore instanceof Date && cr.certTemplate.validity.notAfter instanceof Date);
  check("round-trip extensions", cr.certTemplate.extensions.length === 1);
  check("complete template -> signature POP, no poposkInput", m.popo.type === "signature" && m.popo.poposkInput === null);
  // the POP signature covers the exact CertRequest bytes the parser surfaces (sec. 4.1).
  check("POP signature verifies over certReqBytes", popVerifies(m, s.spki, cr.certReqBytes) === true);
  check("certReqBytes byte-stable across re-parse", Buffer.compare(cr.certReqBytes, parse(der)[0].certReq.certReqBytes) === 0);
}

async function testPemOutput() {
  var s = makeSigner("ed25519");
  var pem = await pki.crmf.build({ certTemplate: tpl(s.spki) }, { key: s.key }, { pem: "CERTIFICATE REQUEST MESSAGE" });
  check("pem output is a string", typeof pem === "string");
  check("pem carries the label", /-----BEGIN CERTIFICATE REQUEST MESSAGE-----/.test(pem));
  check("pem round-trips", pki.schema.crmf.parse(pki.schema.crmf.pemDecode(pem, "CERTIFICATE REQUEST MESSAGE")).messages.length === 1);
  check("empty pem label -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki) }, { key: s.key }, { pem: "" })) === "crmf/bad-input");
}

// ---- CertTemplate IMPLICIT/EXPLICIT tag boundary (#1 fragile) ---------------

async function testTagBoundary() {
  var s = makeSigner("ec-p256");
  var der = await pki.crmf.build({ certTemplate: { issuer: "CA", subject: "d", publicKey: s.spki, validity: { notBefore: NB, notAfter: NA }, extensions: { keyUsage: ["digitalSignature"] } } }, { key: s.key });
  var certReq = asn1.decode(parse(der)[0].certReq.certReqBytes);
  var t = certReq.children[1];   // CertTemplate SEQUENCE
  var byTag = {};
  t.children.forEach(function (c) { byTag[c.tagNumber] = c; });
  check("issuer [3] is a constructed context tag (0xA3, IMPLICIT)", byTag[3].bytes[0] === 0xa3);
  check("validity [4] is a constructed context tag (0xA4, IMPLICIT)", byTag[4].bytes[0] === 0xa4);
  check("subject [5] is a constructed context tag (0xA5, IMPLICIT)", byTag[5].bytes[0] === 0xa5);
  check("publicKey [6] is a constructed context tag (0xA6, IMPLICIT)", byTag[6].bytes[0] === 0xa6);
  check("extensions [9] is a constructed context tag (0xA9, IMPLICIT)", byTag[9].bytes[0] === 0xa9);
  // issuer [3] IMPLICIT: its children ARE the RDN SETs (a universal SET leads), not a wrapped SEQUENCE.
  check("issuer [3] children ARE RDN SETs (IMPLICIT, not EXPLICIT-wrapped)", byTag[3].children[0].tagClass === "universal" && byTag[3].children[0].tagNumber === asn1.TAGS.SET);
  // OptionalValidity notBefore [0] / notAfter [1] are EXPLICIT (Time is a CHOICE) -> a [0]/[1] wrapping a time.
  var val = byTag[4];
  check("validity notBefore [0] is an EXPLICIT wrapper (0xA0)", val.children[0].bytes[0] === 0xa0 && val.children[0].children.length === 1);
  check("validity notBefore [0] wraps a UTCTime/GeneralizedTime", [asn1.TAGS.UTC_TIME, asn1.TAGS.GENERALIZED_TIME].indexOf(val.children[0].children[0].tagNumber) >= 0);
  // version [0] is a PRIMITIVE context tag (0x80) when emitted.
  var der2 = await pki.crmf.build({ certTemplate: { version: 2, subject: "d", publicKey: s.spki } }, { key: s.key });
  var v = asn1.decode(parse(der2)[0].certReq.certReqBytes).children[1].children[0];
  check("version [0] is a primitive context tag (0x80, IMPLICIT)", v.bytes[0] === 0x80);
}

// ---- algorithm arms --------------------------------------------------------

async function testAlgorithmArms() {
  var arms = ["rsa", "ec-p256", "ec-p521", "ed25519", "ed448", "ml-dsa-44", "ml-dsa-87", "slh-dsa-sha2-128f"];
  for (var i = 0; i < arms.length; i++) {
    var s = makeSigner(arms[i]);
    var der = await pki.crmf.build({ certTemplate: tpl(s.spki) }, { key: s.key });
    var m = parse(der)[0];
    check(arms[i] + " arm builds + parses", m.certReq.certReqId === 0n);
    check(arms[i] + " POP verifies over the CertRequest", popVerifies(m, s.spki, m.certReq.certReqBytes) === true);
  }
  var rsa = makeSigner("rsa");
  check("RSA-PSS arm builds + parses", parse(await pki.crmf.build({ certTemplate: tpl(rsa.spki) }, { key: rsa.key }, { pss: true }))[0].certReq.certReqId === 0n);
}

async function testCompositeArm() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var der = await pki.crmf.build({ certTemplate: tpl(s.spki) }, { key: s.key });
  check("composite arm builds + parses", parse(der)[0].certReq.certReqId === 0n);
}

// ---- certReqId edges -------------------------------------------------------

async function testCertReqId() {
  var s = makeSigner("ec-p256");
  check("default certReqId is 0", parse(await pki.crmf.build({ certTemplate: tpl(s.spki) }, { key: s.key }))[0].certReq.certReqId === 0n);
  check("negative -1 sentinel (RFC 9483) round-trips", parse(await pki.crmf.build({ certReqId: -1, certTemplate: tpl(s.spki) }, { key: s.key }))[0].certReq.certReqId === -1n);
  check("large certReqId round-trips", parse(await pki.crmf.build({ certReqId: 65537, certTemplate: tpl(s.spki) }, { key: s.key }))[0].certReq.certReqId === 65537n);
  check("BigInt certReqId round-trips", parse(await pki.crmf.build({ certReqId: 123456789012345678901234567890n, certTemplate: tpl(s.spki) }, { key: s.key }))[0].certReq.certReqId === 123456789012345678901234567890n);
  check("fractional certReqId -> crmf/bad-input", await codeOf(pki.crmf.build({ certReqId: 1.5, certTemplate: tpl(s.spki) }, { key: s.key })) === "crmf/bad-input");
  check("unsafe-integer certReqId -> crmf/bad-input", await codeOf(pki.crmf.build({ certReqId: 0x20000000000000, certTemplate: tpl(s.spki) }, { key: s.key })) === "crmf/bad-input");
}

// ---- validity --------------------------------------------------------------

async function testValidity() {
  var s = makeSigner("ec-p256");
  check("notBefore-only round-trips", parse(await pki.crmf.build({ certTemplate: tpl(s.spki, { validity: { notBefore: NB } }) }, { key: s.key }))[0].certReq.certTemplate.validity.notAfter === null);
  check("notAfter-only round-trips", parse(await pki.crmf.build({ certTemplate: tpl(s.spki, { validity: { notAfter: NA } }) }, { key: s.key }))[0].certReq.certTemplate.validity.notBefore === null);
  check("empty validity -> crmf/bad-validity", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki, { validity: {} }) }, { key: s.key })) === "crmf/bad-validity");
  check("inverted validity -> crmf/bad-validity", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki, { validity: { notBefore: NA, notAfter: NB } }) }, { key: s.key })) === "crmf/bad-validity");
}

// ---- proof of possession ---------------------------------------------------

async function testProofOfPossession() {
  var s = makeSigner("ec-p256");
  // incomplete template (publicKey without subject) -> poposkInput required, signed over POPOSigningKeyInput.
  var inc = await pki.crmf.build({ certTemplate: { publicKey: s.spki }, pop: { type: "signature", sender: { dNSName: "req.example" } } }, { key: s.key });
  var im = parse(inc)[0];
  check("incomplete template -> poposkInput present", !!im.popo.poposkInput);
  check("incomplete POP verifies over the POPOSigningKeyInput (signedBytes)", popVerifies(im, s.spki, im.popo.poposkInput.signedBytes) === true);
  check("incomplete template without pop.sender -> crmf/bad-popo", await codeOf(pki.crmf.build({ certTemplate: { publicKey: s.spki }, pop: { type: "signature" } }, { key: s.key })) === "crmf/bad-popo");
  // raVerified only on explicit opt-in.
  check("raVerified opt-in (no key) round-trips", parse(await pki.crmf.build({ certTemplate: tpl(s.spki), pop: { type: "raVerified", raVerified: true } }))[0].popo.type === "raVerified");
  check("raVerified without the explicit flag -> crmf/bad-popo", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), pop: { type: "raVerified" } })) === "crmf/bad-popo");
  check("unsupported pop type -> crmf/bad-popo", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), pop: { type: "keyEncipherment" } }, { key: s.key })) === "crmf/bad-popo");
  check("signature POP without a key -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), pop: { type: "signature" } })) === "crmf/bad-input");
  // wrong key (does not match the requested publicKey) -> the POP self-verify fails closed.
  var other = makeSigner("ec-p256");
  check("wrong requester key -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki) }, { key: other.key })) === "crmf/bad-input");
}

// ---- controls + regInfo ----------------------------------------------------

async function testControlsAndRegInfo() {
  var s = makeSigner("ec-p256");
  var der = await pki.crmf.build({ certTemplate: tpl(s.spki), controls: { regToken: "tok", authenticator: "maiden", oldCertID: { issuer: { directoryName: "CN=CA" }, serialNumber: 42n }, protocolEncrKey: s.spki }, regInfo: { utf8Pairs: "k?v" } }, { key: s.key });
  var m = parse(der)[0];
  check("controls round-trip (4 entries)", m.certReq.controls.length === 4);
  check("regInfo round-trips (1 entry)", m.regInfo.length === 1);
  check("regToken control decodes to the OID", m.certReq.controls.some(function (c) { return c.name === "regToken"; }));
  // controls (RFC 4211 sec. 6) and regInfo (sec. 7) are disjoint namespaces.
  check("a control name in regInfo -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), regInfo: { regToken: "x" } }, { key: s.key })) === "crmf/bad-input");
  check("a regInfo name in controls -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: { utf8Pairs: "x" } }, { key: s.key })) === "crmf/bad-input");
  check("empty controls object -> crmf/bad-controls", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: {} }, { key: s.key })) === "crmf/bad-controls");
  check("unknown control key -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: { notAControl: 1 } }, { key: s.key })) === "crmf/bad-input");
  check("duplicate control type -> crmf/bad-controls", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: [_atv("regToken", "a"), _atv("regToken", "b")] }, { key: s.key })) === "crmf/bad-controls");
  // pre-encoded AttributeTypeAndValue hatch.
  check("pre-encoded control round-trips", parse(await pki.crmf.build({ certTemplate: tpl(s.spki), controls: [_atv("regToken", "x")] }, { key: s.key }))[0].certReq.controls.length === 1);
  check("malformed pre-encoded control -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: [pki.asn1.build.integer(1n)] }, { key: s.key })) === "crmf/bad-input");
}
function _atv(name, val) { var B = pki.asn1.build; return B.sequence([B.oid(pki.oid.byName(name)), B.utf8(val)]); }

// ---- batch + version + CA-assigned fields ----------------------------------

async function testBatchAndVersion() {
  var s = makeSigner("ec-p256");
  var batch = await pki.crmf.build({ messages: [{ certReqId: 0, certTemplate: tpl(s.spki) }, { certReqId: 1, certTemplate: tpl(s.spki) }] }, { key: s.key });
  var mp = parse(batch);
  check("batch builds a SEQUENCE OF 2 CertReqMsg, order-preserved", mp.length === 2 && mp[0].certReq.certReqId === 0n && mp[1].certReq.certReqId === 1n);
  check("empty messages array -> crmf/bad-input", await codeOf(pki.crmf.build({ messages: [] }, { key: s.key })) === "crmf/bad-input");
  check("messages not an array -> crmf/bad-input", await codeOf(pki.crmf.build({ messages: 5 }, { key: s.key })) === "crmf/bad-input");
  // a batch envelope carries ONLY `messages` -- a stray field (e.g. a mis-nested certTemplate) is rejected.
  check("stray field beside messages -> crmf/bad-input", await codeOf(pki.crmf.build({ messages: [{ certTemplate: tpl(s.spki) }], certTemplate: tpl(s.spki) }, { key: s.key })) === "crmf/bad-input");
  check("nested messages in a batch element -> crmf/bad-input", await codeOf(pki.crmf.build({ messages: [{ messages: [] }] }, { key: s.key })) === "crmf/bad-input");
  check("version 2 round-trips", parse(await pki.crmf.build({ certTemplate: { version: 2, subject: "d", publicKey: s.spki } }, { key: s.key }))[0].certReq.certTemplate.version === 2n);
  check("version != 2 -> crmf/bad-version", await codeOf(pki.crmf.build({ certTemplate: { version: 1, subject: "d", publicKey: s.spki } }, { key: s.key })) === "crmf/bad-version");
  // CA-assigned / deprecated template fields are not accepted keys (a requester must not dictate them).
  check("serialNumber in template -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: { serialNumber: 5, subject: "d", publicKey: s.spki } }, { key: s.key })) === "crmf/bad-input");
  check("signingAlg in template -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: { signingAlg: "x", subject: "d", publicKey: s.spki } }, { key: s.key })) === "crmf/bad-input");
}

// ---- fail-closed misuse ----------------------------------------------------

async function testFailClosed() {
  var s = makeSigner("ec-p256");
  check("non-object spec -> crmf/bad-input", await codeOf(pki.crmf.build(Buffer.from([1]), { key: s.key })) === "crmf/bad-input");
  check("missing certTemplate -> crmf/bad-input", await codeOf(pki.crmf.build({ certReqId: 0 }, { key: s.key })) === "crmf/bad-input");
  check("unknown top-level spec key -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), bogus: 1 }, { key: s.key })) === "crmf/bad-input");
  check("garbage publicKey -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: { subject: "d", publicKey: Buffer.from([1, 2, 3]) } }, { key: s.key })) === "crmf/bad-input");
  check("unknown certTemplate field -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: { notAField: 1, subject: "d", publicKey: s.spki } }, { key: s.key })) === "crmf/bad-input");
  check("malformed pre-encoded extension -> typed crmf/*", /^crmf\//.test(await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki, { extensions: [pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("keyUsage")), pki.asn1.build.octetString(Buffer.from([0x30, 0x05]))]) ] }) }, { key: s.key })) || ""));
  // subjectKeyIdentifier auto-derive (true) with no template publicKey has no key to hash.
  check("SKI auto-derive without a template publicKey -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: { subject: "d", extensions: { subjectKeyIdentifier: true } }, pop: { type: "raVerified", raVerified: true } })) === "crmf/bad-input");
  // a Buffer key id does NOT need the public key (a template without publicKey can still carry an explicit SKI).
  check("SKI as a Buffer key id round-trips without a publicKey", parse(await pki.crmf.build({ certTemplate: { subject: "d", extensions: { subjectKeyIdentifier: Buffer.from([1, 2, 3, 4]) } }, pop: { type: "raVerified", raVerified: true } }))[0].certReq.certTemplate.extensions.length === 1);
}

// ---- coverage edges (reachable reject + omit branches) ---------------------

async function testCoverageEdges() {
  var s = makeSigner("ec-p256");
  var B = pki.asn1.build;
  // no POP requested AND no key -> the popo field is omitted (an RA supplies POP out of band).
  var noPop = await pki.crmf.build({ certTemplate: tpl(s.spki) });
  check("no key + no pop -> popo omitted", parse(noPop)[0].popo === null);
  // signature POP but the template omits publicKey.
  check("signature POP without certTemplate.publicKey -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: { subject: "d" }, pop: { type: "signature" } }, { key: s.key })) === "crmf/bad-input");
  // non-object structural inputs fail closed.
  check("non-object certTemplate -> crmf/bad-cert-template", await codeOf(pki.crmf.build({ certTemplate: 5 }, { key: s.key })) === "crmf/bad-cert-template");
  check("non-object validity -> crmf/bad-validity", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki, { validity: 5 }) }, { key: s.key })) === "crmf/bad-validity");
  check("non-object controls -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: 5 }, { key: s.key })) === "crmf/bad-input");
  check("empty controls array -> crmf/bad-controls", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: [] }, { key: s.key })) === "crmf/bad-controls");
  check("pre-encoded control not valid DER -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: [Buffer.from([0x30, 0x80])] }, { key: s.key })) === "crmf/bad-input");
  check("pre-encoded control type not an OID -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: [B.sequence([B.integer(1n), B.utf8("x")])] }, { key: s.key })) === "crmf/bad-input");
  // oldCertID shape guard.
  check("oldCertID missing serialNumber -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), controls: { oldCertID: { issuer: { directoryName: "CN=CA" } } } }, { key: s.key })) === "crmf/bad-input");
  // a batch element that is not an object.
  check("non-object batch message -> crmf/bad-input", await codeOf(pki.crmf.build({ messages: [5] }, { key: s.key })) === "crmf/bad-input");
}

// Branch coverage (lib/crmf-sign.js): 98.5% -- the residual arms are verified-defensive: the
// `oid.name(t) || t` message fallback (only an UNREGISTERED OID in a duplicate error takes the `|| t`
// arm), and the object-form duplicate-control guard (distinct control keys map to distinct OIDs, so a
// collision is unreachable in the object form; the array form's duplicate check IS driven above).
async function main() {
  await testRoundTrip();
  await testPemOutput();
  await testTagBoundary();
  await testAlgorithmArms();
  await testCompositeArm();
  await testCertReqId();
  await testValidity();
  await testProofOfPossession();
  await testControlsAndRegInfo();
  await testBatchAndVersion();
  await testCoverageEdges();
  await testFailClosed();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
