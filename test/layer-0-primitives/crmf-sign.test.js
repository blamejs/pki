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
  check("issuer [3] is a constructed context tag (0xA3)", byTag[3].bytes[0] === 0xa3);
  check("validity [4] is a constructed context tag (0xA4, IMPLICIT)", byTag[4].bytes[0] === 0xa4);
  check("subject [5] is a constructed context tag (0xA5)", byTag[5].bytes[0] === 0xa5);
  check("publicKey [6] is a constructed context tag (0xA6, IMPLICIT)", byTag[6].bytes[0] === 0xa6);
  check("extensions [9] is a constructed context tag (0xA9, IMPLICIT)", byTag[9].bytes[0] === 0xa9);
  // issuer [3] / subject [5] are EXPLICIT (Name is a CHOICE, X.680 sec. 31.2.7): the [3] wraps the
  // RDNSequence SEQUENCE (its single child is a universal SEQUENCE), it does not replace the tag.
  check("issuer [3] EXPLICIT-wraps the RDNSequence SEQUENCE (not IMPLICIT SET-led)", byTag[3].children.length === 1 && byTag[3].children[0].tagClass === "universal" && byTag[3].children[0].tagNumber === asn1.TAGS.SEQUENCE);
  check("subject [5] EXPLICIT-wraps the RDNSequence SEQUENCE", byTag[5].children.length === 1 && byTag[5].children[0].tagNumber === asn1.TAGS.SEQUENCE);
  // publicKey [6] IMPLICIT: its children ARE the SPKI fields (algorithm SEQUENCE leads), not a wrapped SPKI.
  check("publicKey [6] IMPLICIT: children ARE the SPKI fields", byTag[6].children[0].tagClass === "universal" && byTag[6].children[0].tagNumber === asn1.TAGS.SEQUENCE && byTag[6].children.length === 2);
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
  check("non-object pop selector -> crmf/bad-input", await codeOf(pki.crmf.build({ certTemplate: tpl(s.spki), pop: "signature" }, { key: s.key })) === "crmf/bad-input");
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
// ---- POPOPrivKey: the arms a key that cannot sign has to use ---------------
//
// RFC 4211 sec. 4.2 / 4.3, restated at RFC 9810 sec. 5.2.8.3. An encryption or key-agreement key
// cannot produce a POPOSigningKey, so without these arms an ML-KEM enrollment has no buildable
// proof at all and the only reachable alternative is raVerified, which is not one.
async function testPopoPrivKeyArms() {
  var s = makeSigner("ec-p256");
  var kem = await pki.key.generate("ML-KEM-768");
  var kemSpki = await pki.key.export(kem.publicKey);
  var kemPkcs8 = await pki.key.export(kem.privateKey);
  function spec(pop, over) {
    return Object.assign({ certReqId: 1n, certTemplate: tpl(kemSpki), pop: pop }, over || {});
  }

  // V1/V2 -- both SubsequentMessage values under both outer arms. Four cells, because the recurring
  // defect in this codebase is a rule that holds for one arm and not its sibling.
  var cells = [
    { type: "keyEncipherment", subsequentMessage: "encrCert" },
    { type: "keyEncipherment", subsequentMessage: "challengeResp" },
    { type: "keyAgreement", subsequentMessage: "encrCert" },
    { type: "keyAgreement", subsequentMessage: "challengeResp" },
  ];
  for (var i = 0; i < cells.length; i++) {
    var der = await pki.crmf.build(spec({ type: cells[i].type, method: "subsequentMessage", subsequentMessage: cells[i].subsequentMessage }));
    var m = parse(der)[0];
    check("POP " + cells[i].type + "/" + cells[i].subsequentMessage + " round-trips through the parser",
      m.popo && m.popo.type === cells[i].type && m.popo.method === "subsequentMessage");
  }

  // V3 -- the outer [2]/[3] tag is EXPLICIT (X.680 sec. 31.2.7: the field is CHOICE-typed). Emitted
  // IMPLICITLY the message still decodes as something, so the round-trip above cannot separate the
  // two encodings; only reading the tag structure can.
  var expDer = await pki.crmf.build(spec({ type: "keyEncipherment", method: "subsequentMessage", subsequentMessage: "encrCert" }));
  var popoNode = asn1.decode(parse(expDer)[0].popo.bytes);
  check("POP the keyEncipherment [2] wrapper is EXPLICIT around one context alternative",
    popoNode.tagClass === "context" && popoNode.tagNumber === 2 &&
    !!popoNode.children && popoNode.children.length === 1 &&
    popoNode.children[0].tagClass === "context" && popoNode.children[0].tagNumber === 1);

  // V4 -- SubsequentMessage is INTEGER { encrCert(0), challengeResp(1) }; nothing else is a value.
  check("POP an unknown subsequentMessage value is refused",
    (await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "subsequentMessage", subsequentMessage: "somethingElse" })))) === "crmf/bad-popo");

  // V5 -- the two arms the specification deprecates are refused by name, each naming its successor.
  check("POP thisMessage is refused as deprecated",
    (await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "thisMessage" })))) === "crmf/bad-popo");
  check("POP dhMAC is refused as deprecated",
    (await codeOf(pki.crmf.build(spec({ type: "keyAgreement", method: "dhMAC" })))) === "crmf/bad-popo");

  // V6 -- agreeMAC refuses TWICE for different reasons, and the pair is the point: under
  // keyEncipherment it is non-conforming (sec. 4.2 lists three methods, none of them a MAC), and
  // under keyAgreement it is conforming but not built here. One check blurring them would pass
  // while the builder disagreed with its own parser.
  var encMac = await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "agreeMAC" })));
  var agrMac = await codeOf(pki.crmf.build(spec({ type: "keyAgreement", method: "agreeMAC" })));
  check("POP agreeMAC under keyEncipherment is refused as non-conforming", encMac === "crmf/bad-popo");
  check("POP agreeMAC under keyAgreement is refused as not built", agrMac === "crmf/unsupported-popo");

  // V7 -- encryptedKey round-trips, including the parser's INDEPENDENT id-ct-encKeyWithID check.
  var recip = makeSigner("rsa");
  var encSpec = spec({ type: "keyEncipherment", method: "encryptedKey", privateKey: kemPkcs8,
    identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true });
  var encDer = await pki.crmf.build(encSpec);
  var encMsg = parse(encDer)[0];
  check("POP encryptedKey round-trips through the parser's own content-type check",
    encMsg.popo && encMsg.popo.type === "keyEncipherment" && encMsg.popo.method === "encryptedKey");

  // V8 -- the ASN.1 marks identifier OPTIONAL and sec. 4.2.1 then makes it MUST for a POP. A builder
  // derived from the module rather than the prose emits it absent and still round-trips.
  check("POP encryptedKey without an identifier is refused (RFC 4211 sec. 4.2.1)",
    (await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "encryptedKey", privateKey: kemPkcs8,
      recipients: [{ cert: recip.cert }], archive: true })))) === "crmf/bad-popo");

  // V9 -- sending the private key is reachable only on an explicit opt-in, the raVerified precedent.
  check("POP encryptedKey without the archival opt-in is refused (RFC 9810 sec. 5.2.8.3.1)",
    (await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "encryptedKey", privateKey: kemPkcs8,
      identifier: "device-42", recipients: [{ cert: recip.cert }] })))) === "crmf/bad-popo");

  // V9c -- the whole point of the arm. RFC 4211 sec. 4.2: encryptedKey carries "the encrypted private
  // key MATCHING THE PUBLIC KEY for which the certificate is to be issued". Enclosing an unrelated key
  // proves possession of something the request never asked to have certified, and every structural
  // check above still passes on it -- the message round-trips, the content type is right, the
  // identifier is there. Only comparing the two keys separates a proof from a decoration.
  var otherKem = await pki.key.generate("ML-KEM-768");
  var otherPkcs8 = await pki.key.export(otherKem.privateKey);
  check("POP encryptedKey enclosing a key other than the requested one is refused",
    (await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "encryptedKey", privateKey: otherPkcs8,
      identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true })))) === "crmf/bad-popo");
  // ...and the template has to name a key at all, or there is nothing for the enclosed one to match.
  check("POP encryptedKey with no certTemplate.publicKey is refused",
    (await codeOf(pki.crmf.build({ certReqId: 1n, certTemplate: { subject: [{ commonName: "device" }] },
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: kemPkcs8, identifier: "d",
        recipients: [{ cert: recip.cert }], archive: true } }))) === "crmf/bad-input");

  // V7b -- encryptedKey is legal under keyAgreement too, and the asymmetry with agreeMAC is the
  // specification's. RFC 4211 sec. 4.3: key-agreement POP has four methods and "the first three are
  // identical to those presented above for key encryption keys", the first of sec. 4.2's three being
  // "the private key can be provided to the CA/RA". Only the MAC is agreement-only. Pinned because
  // the pairing reads like an oversight, and the parser accepts it under both arms: narrowing the
  // builder would make the two directions disagree about one message.
  var agrEncDer = await pki.crmf.build(spec({ type: "keyAgreement", method: "encryptedKey",
    privateKey: kemPkcs8, identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true }));
  check("POP encryptedKey is accepted under keyAgreement (RFC 4211 sec. 4.3)",
    parse(agrEncDer)[0].popo.type === "keyAgreement" && parse(agrEncDer)[0].popo.method === "encryptedKey");

  // V9e -- one key has more than one legal SPKI. A P-256 key whose template carries the COMPRESSED
  // point is the same key as the uncompressed form publicFromPrivate derives, and the signature arm
  // already accepts such a template, so refusing it here would make one arm of the verb reject what
  // its sibling builds. The refusal must still hold for a genuinely different key, which the next
  // check pins so the fix cannot have widened into an acceptance.
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecPkcs8 = ec.privateKey.export({ format: "der", type: "pkcs8" });
  var ecJwk = ec.publicKey.export({ format: "jwk" });
  var ecX = Buffer.from(ecJwk.x, "base64url"), ecY = Buffer.from(ecJwk.y, "base64url");
  var compressedPoint = Buffer.concat([Buffer.from([(ecY[ecY.length - 1] & 1) ? 3 : 2]), ecX]);
  var ecAlgId = asn1.decode(ec.publicKey.export({ format: "der", type: "spki" })).children[0].bytes;
  var compressedSpki = asn1.build.sequence([asn1.build.raw(ecAlgId), asn1.build.bitString(compressedPoint, 0)]);
  var compDer = await pki.crmf.build({ certReqId: 1n, certTemplate: tpl(compressedSpki),
    pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: ecPkcs8, identifier: "device-42",
      recipients: [{ cert: recip.cert }], archive: true } });
  check("POP a compressed-point template is the same key as the derived uncompressed one",
    parse(compDer)[0].popo.method === "encryptedKey");
  var otherEc = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  check("POP ...and a different P-256 key under the same encoding is still refused",
    (await codeOf(pki.crmf.build({ certReqId: 1n, certTemplate: tpl(compressedSpki),
      pop: { type: "keyEncipherment", method: "encryptedKey",
        privateKey: otherEc.privateKey.export({ format: "der", type: "pkcs8" }), identifier: "d",
        recipients: [{ cert: recip.cert }], archive: true } }))) === "crmf/bad-popo");

  // V9f -- this arm is the one place the toolkit handles a caller's private key as plaintext, so the
  // copies it makes are cleared. The caller's own buffer is copied rather than borrowed, so it stays
  // intact; a wipe that reached it would destroy the caller's key.
  var wipeKey = Buffer.from(kemPkcs8);
  var wipeBefore = Buffer.from(wipeKey);
  await pki.crmf.build(spec({ type: "keyEncipherment", method: "encryptedKey", privateKey: wipeKey,
    identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true }));
  check("POP the caller's own private key buffer is left intact", wipeKey.equals(wipeBefore));

  // V9g -- the wipe has to cover the SYNCHRONOUS refusals too. An empty recipient list is rejected
  // after the arm has taken its own plaintext copy of the key, and cleanup attached to the promise
  // runs on none of those paths. Counted, not asserted as a boolean: the argument boundary makes its
  // own deep copy with identical bytes and clears that, so one cleared copy means this arm's snapshot
  // survived and two means it did not. Observed from a child process for the reason the helper states.
  var syncObs = require("node:child_process").spawnSync(process.execPath,
    [require("node:path").join(__dirname, "../helpers/observe-secret-wipe.js")],
    { encoding: "utf8", input: JSON.stringify({ op: "crmf-encryptedkey-sync-fail",
      key: Buffer.from(kemPkcs8).toString("base64"), spki: Buffer.from(kemSpki).toString("base64") }) });
  var syncRep = null;
  if (!syncObs.error && syncObs.status === 0) {
    try { syncRep = JSON.parse(String(syncObs.stdout).trim().split("\n").pop()); } catch (_e) { syncRep = null; }
  }
  check("POP the synchronous-refusal wipe observation ran (child exit " + syncObs.status + ")", syncRep !== null);
  var keyB64 = Buffer.from(kemPkcs8).toString("base64");
  var clearedCopies = syncRep ? syncRep.wiped.filter(function (w) { return w.before === keyB64; }).length : 0;
  check("POP a synchronous refusal still clears this arm's own key copy (cleared " + clearedCopies + ")",
    !!syncRep && syncRep.code === "crmf/bad-input" && clearedCopies >= 2);

  // V9d -- the arm composes the CMS producer, and that composition is invisible to the caller. A
  // malformed recipient or an algorithm CMS does not carry must still surface in this module's
  // namespace, or `pki.crmf.build`'s documented "throws a typed CrmfError" is untrue for one arm.
  var badRecip = await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "encryptedKey",
    privateKey: kemPkcs8, identifier: "d", recipients: [{ nonsense: true }], archive: true })));
  check("POP a malformed encryptedKey recipient surfaces as a CrmfError (got " + badRecip + ")",
    typeof badRecip === "string" && badRecip.indexOf("crmf/") === 0);
  var badCea = await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "encryptedKey",
    privateKey: kemPkcs8, identifier: "d", recipients: [{ cert: recip.cert }], archive: true,
    contentEncryptionAlgorithm: "aes-999-cbc" })));
  check("POP an unsupported content-encryption algorithm surfaces as a CrmfError (got " + badCea + ")",
    typeof badCea === "string" && badCea.indexOf("crmf/") === 0);

  // V9b -- every gate above is one a caller turns off by naming it, so a misspelled key must not read
  // as an omitted one: `archve: true` would withhold the archival consent while looking like it gave it.
  check("POP a misspelled pop field is refused rather than dropped",
    (await codeOf(pki.crmf.build(spec({ type: "keyEncipherment", method: "subsequentMessage",
      subsequentMessage: "encrCert", archve: true })))) === "crmf/bad-input");

  // V9h-pre -- `type` is not the only thing that picks the arm: a spec that supplies a key and omits
  // `type` selects the signature arm, and that arm reads pop.sender. Checking fields against an
  // unresolved arm would refuse a shape this verb has always built.
  var implicitSig = await pki.crmf.build({ certReqId: 1n, certTemplate: { publicKey: s.spki },
    pop: { sender: { dNSName: "h.example" } } }, { key: s.key });
  check("POP an implicit signature arm still reads pop.sender",
    parse(implicitSig)[0].popo.type === "signature");

  // V9h -- spec.pop is a CHOICE, so a field belonging to a DIFFERENT arm is refused rather than
  // accepted and ignored. Checked across the arms, not on one of them: a caller who supplies the key
  // material beside subsequentMessage believes they are sending the key, and gets a message that
  // declares a later exchange instead. Each cell names a field that is legal somewhere else.
  var CROSS_ARM = [
    { what: "privateKey beside subsequentMessage",
      pop: { type: "keyEncipherment", method: "subsequentMessage", subsequentMessage: "encrCert", privateKey: kemPkcs8 } },
    { what: "archive beside subsequentMessage",
      pop: { type: "keyAgreement", method: "subsequentMessage", subsequentMessage: "challengeResp", archive: true } },
    { what: "subsequentMessage beside encryptedKey",
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: kemPkcs8, identifier: "d",
        recipients: [{ cert: recip.cert }], archive: true, subsequentMessage: "encrCert" } },
    { what: "sender beside a POPOPrivKey arm",
      pop: { type: "keyEncipherment", method: "subsequentMessage", subsequentMessage: "encrCert", sender: { dNSName: "h.example" } } },
    { what: "raVerified beside a POPOPrivKey arm",
      pop: { type: "keyAgreement", method: "subsequentMessage", subsequentMessage: "encrCert", raVerified: true } },
    { what: "privateKey beside raVerified",
      pop: { type: "raVerified", raVerified: true, privateKey: kemPkcs8 } },
    { what: "method beside the signature arm",
      pop: { type: "signature", method: "encryptedKey" } },
  ];
  for (var ci = 0; ci < CROSS_ARM.length; ci++) {
    var cell = CROSS_ARM[ci];
    check("POP " + cell.what + " is refused, not silently ignored",
      (await codeOf(pki.crmf.build(spec(cell.pop)))) === "crmf/bad-input");
  }

  // V10 -- the signature arm still builds unchanged through the rewritten dispatch.
  var sigDer = await pki.crmf.build({ certReqId: 1n, certTemplate: tpl(s.spki) }, { key: s.key });
  check("POP the signature arm is unchanged by the POPOPrivKey dispatch",
    parse(sigDer)[0].popo.type === "signature");

  // V11 -- RFC 9810 sec. 5.2.8.3: "When using agreeMAC or encryptedKey choices, the pvno cmp2021(3)
  // MUST be used." That is a CMP header rule the CRMF layer cannot enforce for itself.
  var cmpHdr = { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" }, transactionID: Buffer.alloc(16, 7) };
  var cmpSig = { key: s.key, cert: s.cert };
  var cmpEnc = await pki.cmp.build({ header: cmpHdr, body: { ir: encSpec } }, cmpSig);
  check("POP a CMP request carrying an encryptedKey POP announces cmp2021(3)",
    pki.schema.cmp.parse(cmpEnc).header.pvno === 3);
  var cmpSub = await pki.cmp.build({ header: cmpHdr,
    body: { ir: spec({ type: "keyEncipherment", method: "subsequentMessage", subsequentMessage: "encrCert" }) } }, cmpSig);
  check("POP a subsequentMessage POP does not force the version up",
    pki.schema.cmp.parse(cmpSub).header.pvno === 2);
}

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
  await testPopoPrivKeyArms();
  // Dense caller-array hardening: a sparse controls array is a typed crmf/bad-controls, caught before the
  // map reaches the hole as a native concat error (reqDenseArray runs before any entry is validated).
  var _dzs = makeSigner("ec-p256");
  var _spCtrls = [1]; _spCtrls[2] = 1;   // own 0 and 2, hole at 1
  check("sparse controls -> typed crmf/bad-controls (not a native concat error)",
    (await codeOf(pki.crmf.build({ certReqId: 0, certTemplate: tpl(_dzs.spki), controls: _spCtrls }, { key: _dzs.key }))) === "crmf/bad-controls");

  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
