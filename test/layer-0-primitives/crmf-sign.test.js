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
var surgery = require("../helpers/der-surgery");
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
  check("POP agreeMAC under keyAgreement names what it needs", agrMac === "crmf/bad-popo");

  // V6b -- the RFC 2875 sec. 3 static Diffie-Hellman proof, which RFC 4211 sec. 4.3 requires every DH
  // implementation to support. The requester holds a certificate for the authority and a key on the
  // authority's own group; the secret they agree keys a MAC over the certReq.
  var caDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
  var eeDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
  var caDhSpki = caDh.publicKey.export({ format: "der", type: "spki" });
  var eeDhSpki = eeDh.publicKey.export({ format: "der", type: "spki" });
  var eeDhPk8 = eeDh.privateKey.export({ format: "der", type: "pkcs8" });
  // A DH key cannot sign, so the authority's certificate is issued rather than self-signed.
  var dhCaPair = await pki.key.generate("Ed25519");
  var dhCaKey = await pki.key.export(dhCaPair.privateKey);
  var dhRootCert = await pki.x509.sign({
    subject: "dh-root.example", subjectPublicKey: await pki.key.export(dhCaPair.publicKey),
    serialNumber: 20, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
  }, { key: dhCaKey });
  async function dhCertFor(spki, over) {
    return pki.x509.sign(Object.assign({
      subject: "dh-authority.example", subjectPublicKey: spki, serialNumber: 21,
      notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
      extensions: { keyUsage: ["keyAgreement"] },
    }, over || {}), { key: dhCaKey, cert: dhRootCert });
  }
  var dhCaCert = await dhCertFor(caDhSpki);
  var agreeSpec = {
    certReqId: 7n, certTemplate: tpl(eeDhSpki),
    pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert },
  };
  var agreeDer = await pki.crmf.build(agreeSpec);
  var agreeMsg = parse(agreeDer)[0];
  check("V6b. an agreeMAC proof builds and re-parses as the keyAgreement arm",
    agreeMsg.popo.type === "keyAgreement" && agreeMsg.popo.method === "agreeMAC");

  // The proof is checked from the RECIPIENT's side: the authority computes the same secret from the
  // request's own public key and its own private key. Re-running the builder would prove nothing,
  // since a wrong derivation reproduces itself exactly.
  // The BIT STRING carries a DhPopStatic SEQUENCE, not the raw MAC: RFC 2875 sec. 3 says the encoding
  // replaces "the raw output from 3d". Decoding it is what proves the proof is the one a conforming
  // recipient reads; comparing the BIT STRING to an HMAC would pass for a raw-bytes encoding too.
  function dhPopStaticOf(popoBytes) {
    var pkMacSeq = pki.asn1.decode(pki.asn1.decode(popoBytes).children[0].bytes);
    var inner = pki.asn1.decode(Buffer.from(pki.asn1.read.bitString(pkMacSeq.children[1]).bytes));
    return {
      alg: pki.asn1.read.oid(pkMacSeq.children[0].children[0]),
      issuerAndSerial: inner.children[0],
      hashValue: Buffer.from(pki.asn1.read.octetString(inner.children[1])),
    };
  }
  var agreeParts = dhPopStaticOf(agreeMsg.popo.bytes);
  var macAlg = agreeParts.alg;
  var macValue = agreeParts.hashValue;
  check("V6b. the BIT STRING carries a DhPopStatic naming the certificate the key came from",
    agreeParts.issuerAndSerial.children.length === 2 &&
    Buffer.from(agreeParts.issuerAndSerial.children[0].bytes).equals(pki.schema.x509.parse(dhCaCert).issuer.bytes) &&
    pki.asn1.read.integer(agreeParts.issuerAndSerial.children[1]) === pki.schema.x509.parse(dhCaCert).serialNumber);
  check("V6b. and names id-dhPop-static-HMAC-SHA1 (RFC 2875 sec. 4.4)",
    macAlg === pki.oid.byName("id-dhPop-static-HMAC-SHA1"));
  var parsedDhCa = pki.schema.x509.parse(dhCaCert);
  function recipientMac(caPrivate, caCertParsed, requestSpki, certReqBytes) {
    var zz = nodeCrypto.diffieHellman({
      privateKey: caPrivate,
      publicKey: nodeCrypto.createPublicKey({ key: requestSpki, format: "der", type: "spki" }),
    });
    var k = nodeCrypto.createHash("sha1")
      .update(caCertParsed.subject.bytes).update(zz).update(caCertParsed.issuer.bytes).digest();
    return nodeCrypto.createHmac("sha1", k).update(certReqBytes).digest();
  }
  check("V6b. and the authority reaches the same MAC from its own side of the agreement",
    macValue.equals(recipientMac(caDh.privateKey, parsedDhCa, eeDhSpki, agreeMsg.certReq.certReqBytes)));

  // sec. 4.3 admits this proof only when the subject can use the authority's parameters. A key on
  // another group agrees nothing with it, and that is refused rather than MACed under some other key.
  var otherGroup = nodeCrypto.generateKeyPairSync("dh", { group: "modp16" });
  check("V6b. a requester key on another group is refused",
    (await codeOf(pki.crmf.build({ certReqId: 8n, certTemplate: tpl(otherGroup.publicKey.export({ format: "der", type: "spki" })),
      pop: { type: "keyAgreement", method: "agreeMAC",
        key: otherGroup.privateKey.export({ format: "der", type: "pkcs8" }), caCert: dhCaCert } }))) === "crmf/bad-popo");
  // The agreed secret and the key derived from it never reach the caller, so both are the module's own
  // to clear. Counted from outside the toolkit, because a copy that is never wiped leaves nothing in
  // the record to inspect and only the number of distinct copies tells the two apart.
  var agreeWipe = require("node:child_process").spawnSync(process.execPath,
    [require("node:path").join(__dirname, "../helpers/observe-secret-wipe.js")],
    { encoding: "utf8", input: JSON.stringify({
      op: "crmf-agree-mac",
      key: Buffer.from(eeDhPk8).toString("base64"),
      csr: Buffer.from(eeDhSpki).toString("base64"),
      cert: Buffer.from(dhCaCert).toString("base64"),
    }) });
  var agreeReport = null;
  if (!agreeWipe.error && agreeWipe.status === 0) {
    try { agreeReport = JSON.parse(String(agreeWipe.stdout).trim().split("\n").pop()); } catch (_e) { agreeReport = null; }
  }
  check("V6b. every secret the proof derives is cleared, and the caller's key is left alone",
    agreeReport !== null && agreeReport.code === "NO-THROW" && agreeReport.callerKeyIntact === true &&
    agreeReport.wiped.length === 6 &&
    agreeReport.wiped.every(function (w) { return w.allZeroAfter === true && w.hadContent === true; }));

  // Rewriting an X9.42 key into the form the runtime reads makes a second copy of the private value,
  // and the import that follows can throw: a tiny group translates cleanly and is then refused by the
  // runtime. The copy has to be gone on that way out too, which is the way that leaves no record
  // unless the copies are counted.
  // 23 is prime, 11 is prime and divides 22, and 2 has order 11 mod 23, so this group is coherent
  // and reaches the rewrite. It is the modulus alone that the import that follows refuses, which is
  // what puts a built rewrite on a throwing path.
  var tinyX942Pk8 = pki.asn1.build.sequence([
    pki.asn1.build.integer(0n),
    pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
      pki.asn1.build.raw(pki.asn1.build.sequence([
        pki.asn1.build.integer(23n), pki.asn1.build.integer(2n), pki.asn1.build.integer(11n)]))]),
    pki.asn1.build.octetString(Buffer.from(pki.asn1.build.integer(7n))),
  ]);
  var failWipe = require("node:child_process").spawnSync(process.execPath,
    [require("node:path").join(__dirname, "../helpers/observe-secret-wipe.js")],
    { encoding: "utf8", input: JSON.stringify({
      op: "crmf-agree-mac",
      key: Buffer.from(tinyX942Pk8).toString("base64"),
      csr: Buffer.from(eeDhSpki).toString("base64"),
      cert: Buffer.from(dhCaCert).toString("base64"),
    }) });
  var failReport = null;
  if (!failWipe.error && failWipe.status === 0) {
    try { failReport = JSON.parse(String(failWipe.stdout).trim().split("\n").pop()); } catch (_e2) { failReport = null; }
  }
  check("V6b. the rewritten key is cleared when the import that follows it refuses the group",
    failReport !== null && failReport.code === "crmf/bad-popo" && failReport.callerKeyIntact === true &&
    failReport.wiped.length === 5 &&
    failReport.wiped.every(function (w) { return w.allZeroAfter === true; }));

  // sec. 4.3: "If either the subject or issuer name in the CA certificate is empty, then the
  // alternative name should be used in its place." An authority certificate with an empty subject and
  // a subjectAltName still keys the derivation, from the alternative name.
  var emptySubjectCa = await dhCertFor(caDhSpki, {
    subject: [], serialNumber: 22,
    extensions: { keyUsage: ["keyAgreement"], subjectAltName: [{ dNSName: "dh-authority.example" }] },
  });
  var altDer = await pki.crmf.build({
    certReqId: 13n, certTemplate: tpl(eeDhSpki),
    pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: emptySubjectCa },
  });
  var altMsg = parse(altDer)[0];
  var altMac = dhPopStaticOf(altMsg.popo.bytes).hashValue;
  var parsedAltCa = pki.schema.x509.parse(emptySubjectCa);
  var altSan = parsedAltCa.extensions.filter(function (e) { return e.name === "subjectAltName"; })[0];
  var altZz = nodeCrypto.diffieHellman({
    privateKey: caDh.privateKey,
    publicKey: nodeCrypto.createPublicKey({ key: eeDhSpki, format: "der", type: "spki" }),
  });
  var altK = nodeCrypto.createHash("sha1")
    .update(altSan.value).update(altZz).update(parsedAltCa.issuer.bytes).digest();
  check("V6b. an empty subject falls back to the alternative name, and the authority agrees",
    altMac.equals(nodeCrypto.createHmac("sha1", altK).update(altMsg.certReq.certReqBytes).digest()));
  // A certificate carrying NEITHER a name nor an alternative one is refused too, and that branch has
  // no vector here on purpose: pki.x509.sign will not mint one, because RFC 5280 sec. 4.1.2.6 makes a
  // critical subjectAltName mandatory when the subject is empty. Such a certificate can only arrive
  // from another implementation, so the refusal is reachable and unbuildable from this side.

  // The proof is about the key being certified. The authority derives ITS side from the template's
  // public key, so a private key from another pair agrees a secret with the authority perfectly well
  // and yields a MAC the authority cannot reproduce. That is a proof of possession of something this
  // request never asked to have certified, and it is refused rather than emitted.
  // A keyUsage extension restricts the certified key to the purposes it asserts, and this proof
  // agrees a secret with the authority's key. A certificate that states its purposes without stating
  // this one is refused; one carrying no keyUsage states no restriction.
  var noAgreeCa = await dhCertFor(caDhSpki, {
    serialNumber: 24, extensions: { keyUsage: ["digitalSignature"] },
  });
  check("V6b. an authority certificate whose keyUsage omits keyAgreement is refused",
    (await codeOf(pki.crmf.build({ certReqId: 19n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: noAgreeCa } }))) === "crmf/bad-popo");
  var noKuCa = await dhCertFor(caDhSpki, { serialNumber: 25, extensions: {} });
  check("V6b. an authority certificate carrying no keyUsage is still accepted",
    (await codeOf(pki.crmf.build({ certReqId: 20n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: noKuCa } }))) === null);

  // A finite-field key reaches a certificate in two encodings. This runtime classifies the PKCS#3
  // dhKeyAgreement form and imports the X9.42 dhpublicnumber form without classifying it, and refuses
  // to agree with what it did not classify. The refusal names the side it could not read rather than
  // reporting its absent type as though it were one.
  var x942Spki = (function () {
    var n = pki.asn1.decode(caDhSpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    var domain = pki.asn1.build.sequence([
      pki.asn1.build.integer(p), pki.asn1.build.integer(pki.asn1.read.integer(prm.children[1])),
      pki.asn1.build.integer((p - 1n) / 2n),
    ]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"), pki.asn1.build.raw(domain)]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  check("V6b. the X9.42 form really is the encoding this runtime does not classify",
    nodeCrypto.createPublicKey({ key: Buffer.from(x942Spki), format: "der", type: "spki" })
      .asymmetricKeyType === undefined);
  var x942Ca = await dhCertFor(x942Spki, { serialNumber: 23 });
  var x942Der = await pki.crmf.build({ certReqId: 18n, certTemplate: tpl(eeDhSpki),
    pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: x942Ca } });
  check("V6b. an X9.42 dhpublicnumber authority certificate agrees and proves",
    parse(x942Der)[0].popo.method === "agreeMAC");
  // The proof is the same secret either way: the two encodings name one key.
  check("V6b. the X9.42 and PKCS#3 spellings of one authority key MAC identically",
    dhPopStaticOf(parse(x942Der)[0].popo.bytes).hashValue.equals(
      dhPopStaticOf(parse(await pki.crmf.build({ certReqId: 18n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
          caCert: await dhCertFor(caDhSpki, { serialNumber: 23 }) } }))[0].popo.bytes).hashValue));

  // The requested key is read in both encodings on the same footing. A template naming the key in
  // the X9.42 form and a pop.key holding its PKCS#3 private half are one key.
  var eeX942Spki = (function () {
    var n = pki.asn1.decode(eeDhSpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    var domain = pki.asn1.build.sequence([
      pki.asn1.build.integer(p), pki.asn1.build.integer(pki.asn1.read.integer(prm.children[1])),
      pki.asn1.build.integer((p - 1n) / 2n),
    ]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"), pki.asn1.build.raw(domain)]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  // The template's p and g are the authority's, which the agreement forces it to share, but its q
  // and j are the caller's own and the conversion drops them. A request must not carry a subgroup
  // order its own key does not have, since whoever reads the request next reads those parameters.
  var templateBadQ = (function () {
    var n = pki.asn1.decode(eeX942Spki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.integer(3n)]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  check("V6b. a requested key stating a subgroup order its own group does not have is refused",
    (await codeOf(pki.crmf.build({ certReqId: 35n, certTemplate: tpl(templateBadQ),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === "crmf/bad-popo");

  check("V6b. a template naming the requested key in the X9.42 form is still proven",
    (await codeOf(pki.crmf.build({ certReqId: 22n, certTemplate: tpl(eeX942Spki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === null);

  // q arrives in the certificate, so it is held against p and g rather than believed. Each shape
  // below states an order the group does not have, or a cofactor its own p and q contradict.
  function x942With(pv, gv, qv, yv, extra) {
    var fields = [pki.asn1.build.integer(pv), pki.asn1.build.integer(gv), pki.asn1.build.integer(qv)];
    for (var i = 0; extra && i < extra.length; i++) fields.push(extra[i]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence(fields))]),
      pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(yv))),
    ]);
  }
  // Each case names the reason it is refused for, not just the code every refusal on this path
  // shares: the parameters are read before the runtime sees the key, so a case that stopped being
  // caught here would still be refused later and a code-only assertion would not notice.
  var x942Bad = [
    ["a generator whose order is not the stated q", x942With(23n, 5n, 11n, 4n),
      "state a subgroup order its own p and g do not have"],
    ["a generator equal to p-1", x942With(23n, 22n, 11n, 4n),
      "are not a Diffie-Hellman group"],
    ["a cofactor its own p and q contradict", x942With(23n, 2n, 11n, 4n, [pki.asn1.build.integer(3n)]),
      "cofactor does not match"],
    ["a validationParms field that is not a SEQUENCE",
      x942With(23n, 2n, 11n, 4n, [pki.asn1.build.integer(2n), pki.asn1.build.integer(9n)]),
      "not a seed BIT STRING with a pgenCounter INTEGER"],
    ["an empty validationParms",
      x942With(23n, 2n, 11n, 4n, [pki.asn1.build.sequence([])]),
      "not a seed BIT STRING with a pgenCounter INTEGER"],
    ["validationParms whose two fields are the wrong types",
      x942With(23n, 2n, 11n, 4n, [pki.asn1.build.sequence([
        pki.asn1.build.integer(1n), pki.asn1.build.bitString(Buffer.from([0x00]))])]),
      "not a seed BIT STRING with a pgenCounter INTEGER"],
    ["a fourth field that is neither a cofactor nor validationParms",
      x942With(23n, 2n, 11n, 4n, [pki.asn1.build.oid("1.2.3")]),
      "neither a cofactor nor validationParms"],
    // 15 = 3*5, with q = 2 prime and dividing 14, and 4*4 = 16 = 1 mod 15, so every relation above
    // holds and only the modulus itself is left to answer for.
    ["a modulus that is not prime", x942With(15n, 4n, 2n, 11n), "modulus is not prime"],
    // 31 is prime, 3 is prime and divides 30, and 5 and 25 both have order 3 mod 31, so this states
    // a subgroup that is real and far too small: a prime q makes the order exactly q, which is only
    // worth having when q is large.
    ["a subgroup too small to hide an exponent", x942With(31n, 5n, 3n, 25n), "too small to hide a private exponent"],
    // The codec admits a nonzero unused-bit count when the padding bits are zero, so one public
    // value has two spellings, and the conversion carries this BIT STRING through unchanged.
    ["a public key BIT STRING that is not octet-aligned", (function () {
      return pki.asn1.build.sequence([
        pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
          pki.asn1.build.raw(pki.asn1.build.sequence([pki.asn1.build.integer(23n),
            pki.asn1.build.integer(2n), pki.asn1.build.integer(11n)]))]),
        pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(4n)), 2),
      ]);
    }()), "must be octet-aligned"],
    // The cofactor is multiplied by q, so it is sized before that multiplication like the rest.
    ["a cofactor wider than any group", x942With(23n, 2n, 11n, 4n, [pki.asn1.build.integer(1n << 20000n)]),
      "larger than any Diffie-Hellman group"],
  ];
  for (var xb = 0; xb < x942Bad.length; xb++) {
    var xErr = null;
    try {
      await pki.crmf.build({ certReqId: 23n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
          caCert: await dhCertFor(x942Bad[xb][1], { serialNumber: 27 + xb }) } });
    } catch (e) { xErr = e; }
    check("V6b. X9.42 domain parameters stating " + x942Bad[xb][0] + " are refused for that reason",
      xErr !== null && xErr.code === "crmf/bad-popo" && xErr.message.indexOf(x942Bad[xb][2]) !== -1);
  }

  // j and validationParms are independently optional, so validationParms can stand where a reader
  // keying on position would expect the cofactor. Built over the real group so it reaches agreement.
  var x942WithVp = (function () {
    var n = pki.asn1.decode(x942Spki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.raw(prm.children[2].bytes),
          pki.asn1.build.sequence([pki.asn1.build.bitString(Buffer.from([0x00])), pki.asn1.build.integer(1n)]),
        ]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  check("V6b. X9.42 validationParms with no cofactor before it still agrees",
    (await codeOf(pki.crmf.build({ certReqId: 24n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(x942WithVp, { serialNumber: 33 }) } }))) === null);

  // The requested key reaches the same reader, and it is whatever the caller passed. A value that is
  // not DER at all, and one whose algorithm field holds no OID, are each read as "not the X9.42 form"
  // and fall through to the comparison, which refuses them for not being the requested key.
  check("V6b. a requested key that is not DER is refused at the door, before any key reader sees it",
    (await codeOf(pki.crmf.build({ certReqId: 26n, certTemplate: tpl(Buffer.from([0xff, 0xff])),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === "crmf/bad-input");

  // Every test on these parameters raises one of them to the power of another, so an operand wider
  // than any real group is a request for arbitrary work on this thread. q = 2^65535 with p = q+1 and
  // g = 2 passes divisibility and range, and reaching a verdict by computing takes seconds.
  var hugeQ = 1n << 65535n;
  var hugeStart = Date.now();
  var hugeErr = null;
  try {
    await pki.crmf.build({ certReqId: 28n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(x942With(hugeQ + 1n, 2n, hugeQ, 3n), { serialNumber: 40 }) } });
  } catch (e) { hugeErr = e; }
  check("V6b. an oversized X9.42 operand is refused on its size, not by computing with it",
    hugeErr !== null && hugeErr.code === "crmf/bad-popo" &&
    hugeErr.message.indexOf("larger than any Diffie-Hellman group") !== -1);
  check("V6b. and that refusal is immediate", (Date.now() - hugeStart) < 2000);

  // A container is read for the tag it carries, not for having children. A context-specific
  // constructed value in place of the DomainParameters SEQUENCE is not that SEQUENCE, and converting
  // one would rewrite a key the recipient's own reader refuses into a PKCS#3 key that imports, so the
  // request would go out carrying a public key nothing else can read.
  // Built over the REQUESTER's own group, so accepting the container yields a key that matches
  // pop.key and the request goes out; only refusing the container refuses the request.
  var ctxParams = (function () {
    var n = pki.asn1.decode(eeX942Spki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.implicit(0, pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.raw(prm.children[2].bytes)]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  check("V6b. a requested key whose parameters are not a DomainParameters SEQUENCE is not converted",
    (await codeOf(pki.crmf.build({ certReqId: 29n, certTemplate: tpl(ctxParams),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === "crmf/bad-popo");

  // The certificate parser surfaces an extension's bytes without running the decoder registered for
  // it, so a subjectAltName holding an EMPTY GeneralNames carries a length while naming nobody. The
  // builder refuses to make one, so the certificate is patched after signing, which is what an
  // authority certificate arriving from a peer can look like.
  var emptySanCa = (function () {
    var real = pki.schema.x509.parse(emptySubjectCa);
    var san = real.extensions.filter(function (e) { return e.name === "subjectAltName"; })[0];
    var swapped = surgery.replaceTlv(emptySubjectCa,
      pki.asn1.build.octetString(Buffer.from(san.value)),
      pki.asn1.build.octetString(Buffer.from(pki.asn1.build.sequence([]))));
    check("V6b. the empty-subjectAltName fixture really replaced one name list", swapped.count === 1);
    return swapped.der;
  }());
  check("V6b. an authority subjectAltName naming nobody is refused, not keyed from",
    (await codeOf(pki.crmf.build({ certReqId: 31n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: emptySanCa } }))) === "crmf/bad-popo");

  // A list holding something no arm of the GeneralName CHOICE covers names nobody either, and a
  // universal NULL is not a context-specific arm of it.
  var nullSanCa = (function () {
    var real = pki.schema.x509.parse(emptySubjectCa);
    var san = real.extensions.filter(function (e) { return e.name === "subjectAltName"; })[0];
    var swapped = surgery.replaceTlv(emptySubjectCa,
      pki.asn1.build.octetString(Buffer.from(san.value)),
      pki.asn1.build.octetString(Buffer.from(pki.asn1.build.sequence([pki.asn1.build.nullValue()]))));
    check("V6b. the NULL-subjectAltName fixture really replaced one name list", swapped.count === 1);
    return swapped.der;
  }());
  check("V6b. an authority subjectAltName holding a value that is not a GeneralName is refused",
    (await codeOf(pki.crmf.build({ certReqId: 32n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: nullSanCa } }))) === "crmf/bad-popo");

  // A one-byte iPAddress carries the right tag and is not an address. The shared GeneralNames
  // reader knows the arm's own rules, which a tag check does not.
  var badIpSanCa = (function () {
    var real = pki.schema.x509.parse(emptySubjectCa);
    var san = real.extensions.filter(function (e) { return e.name === "subjectAltName"; })[0];
    var swapped = surgery.replaceTlv(emptySubjectCa,
      pki.asn1.build.octetString(Buffer.from(san.value)),
      pki.asn1.build.octetString(Buffer.from([0x30, 0x03, 0x87, 0x01, 0x00])));
    check("V6b. the malformed-iPAddress fixture really replaced one name list", swapped.count === 1);
    return swapped.der;
  }());
  // ediPartyName [5] and x400Address [3] are read as non-empty constructed values and no further, so
  // a [5] holding a NULL is a name-shaped hole. The derivation keys from these bytes, so a list
  // offering nothing but those two arms names nobody it can answer for.
  var ediSanCa = (function () {
    var real = pki.schema.x509.parse(emptySubjectCa);
    var san = real.extensions.filter(function (e) { return e.name === "subjectAltName"; })[0];
    var swapped = surgery.replaceTlv(emptySubjectCa,
      pki.asn1.build.octetString(Buffer.from(san.value)),
      pki.asn1.build.octetString(Buffer.from([0x30, 0x04, 0xa5, 0x02, 0x05, 0x00])));
    check("V6b. the ediPartyName fixture really replaced one name list", swapped.count === 1);
    return swapped.der;
  }());
  check("V6b. an authority subjectAltName whose ediPartyName encodes no name is refused",
    (await codeOf(pki.crmf.build({ certReqId: 36n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: ediSanCa } }))) === "crmf/bad-popo");

  // Both arms are legitimate GeneralNames, so a well-formed one names somebody. The derivation
  // hashes these bytes rather than interpreting them, so an arm this does not read is still an arm
  // both sides hash alike.
  function sanCaHolding(sanContent) {
    var real = pki.schema.x509.parse(emptySubjectCa);
    var san = real.extensions.filter(function (e) { return e.name === "subjectAltName"; })[0];
    var swapped = surgery.replaceTlv(emptySubjectCa,
      pki.asn1.build.octetString(Buffer.from(san.value)),
      pki.asn1.build.octetString(Buffer.from(sanContent)));
    check("V6b. the fixture replaced exactly one name list", swapped.count === 1);
    return swapped.der;
  }
  // DirectoryString is a CHOICE, so partyName [1] is an EXPLICIT wrapper holding the string itself.
  // Built with explicit, not implicit: the implicit form retags the string and carries no wrapper,
  // which is the encoding a check reading only the tag would wave through.
  var goodEdi = sanCaHolding(pki.asn1.build.sequence([
    pki.asn1.build.implicit(5, pki.asn1.build.sequence([
      pki.asn1.build.explicit(1, Buffer.from([0x13, 0x02, 0x63, 0x61]))]))]));
  check("V6b. a well-formed ediPartyName names somebody",
    (await codeOf(pki.crmf.build({ certReqId: 37n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: goodEdi } }))) === null);
  // The same value nested under the required tag: [1] wrapping a NULL is tagged like a name and
  // holds none, so reading the tag alone is not reading the name.
  var nestedNullEdi = sanCaHolding(Buffer.from([0x30, 0x06, 0xa5, 0x04, 0xa1, 0x02, 0x05, 0x00]));
  check("V6b. an ediPartyName whose partyName wraps no string is refused",
    (await codeOf(pki.crmf.build({ certReqId: 39n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: nestedNullEdi } }))) === "crmf/bad-popo");

  // DirectoryString is SIZE (1..MAX), so a string carrying an accepted tag and no characters names
  // nobody, and neither does one whose bytes are not the encoding its tag claims.
  function ediHolding(stringTlv) {
    return pki.asn1.build.sequence([
      pki.asn1.build.implicit(5, pki.asn1.build.sequence([
        pki.asn1.build.explicit(1, Buffer.from(stringTlv))]))]);
  }
  var ediBad = [
    ["an empty string", ediHolding([0x0c, 0x00])],
    ["a PrintableString holding a character it cannot carry", ediHolding([0x13, 0x02, 0x40, 0x40])],
  ];
  for (var eb = 0; eb < ediBad.length; eb++) {
    check("V6b. an ediPartyName naming a party with " + ediBad[eb][0] + " is refused",
      (await codeOf(pki.crmf.build({ certReqId: 43n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
          caCert: sanCaHolding(ediBad[eb][1]) } }))) === "crmf/bad-popo");
  }
  // ORAddress opens with the BuiltInStandardAttributes SEQUENCE (X.411), so an arm whose first
  // element is not a sequence of attributes is not an address, however the shared reader reads it.
  function x400Holding(first) {
    return sanCaHolding(pki.asn1.build.sequence([
      pki.asn1.build.implicit(3, pki.asn1.build.sequence([first]))]));
  }
  check("V6b. an x400Address opening with a value that is not the standard attributes is refused",
    (await codeOf(pki.crmf.build({ certReqId: 38n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: x400Holding(pki.asn1.build.integer(1n)) } }))) === "crmf/bad-popo");
  check("V6b. an x400Address opening with no attributes at all is refused",
    (await codeOf(pki.crmf.build({ certReqId: 47n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: x400Holding(pki.asn1.build.sequence([])) } }))) === "crmf/bad-popo");
  // X.411 makes every built-in standard field optional, so an address can carry its naming data in
  // the domain-defined attributes that follow. An empty first component is not an empty address.
  var x400Domain = sanCaHolding(pki.asn1.build.sequence([
    pki.asn1.build.implicit(3, pki.asn1.build.sequence([
      pki.asn1.build.sequence([]),
      pki.asn1.build.sequence([pki.asn1.build.sequence([
        pki.asn1.build.raw(Buffer.from([0x13, 0x01, 0x54])),
        pki.asn1.build.raw(Buffer.from([0x13, 0x01, 0x56]))])])]))]));
  check("V6b. an x400Address named by its domain-defined attributes names somebody",
    (await codeOf(pki.crmf.build({ certReqId: 49n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: x400Domain } }))) === null);

  check("V6b. an x400Address opening with standard attributes names somebody",
    (await codeOf(pki.crmf.build({ certReqId: 48n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: x400Holding(pki.asn1.build.sequence([
          pki.asn1.build.implicit(2, Buffer.from([0x13, 0x02, 0x67, 0x62]))])) } }))) === null);

  // Name is a SEQUENCE OF RelativeDistinguishedName and permits none, which is exactly what the
  // subject field carried when this fallback was reached. An empty name for an empty name names
  // nobody, so it is refused; a directoryName holding one RDN names somebody.
  var emptyDirName = sanCaHolding(Buffer.from([0x30, 0x04, 0xa4, 0x02, 0x30, 0x00]));
  check("V6b. an authority subjectAltName whose directoryName is an empty Name is refused",
    (await codeOf(pki.crmf.build({ certReqId: 45n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: emptyDirName } }))) === "crmf/bad-popo");
  var goodDirName = sanCaHolding(pki.asn1.build.sequence([
    pki.asn1.build.explicit(4, pki.asn1.build.raw(pki.schema.x509.parse(dhCaCert).subject.bytes))]));
  check("V6b. a directoryName naming a directory entry names somebody",
    (await codeOf(pki.crmf.build({ certReqId: 46n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: goodDirName } }))) === null);

  check("V6b. an authority subjectAltName whose iPAddress is not an address is refused",
    (await codeOf(pki.crmf.build({ certReqId: 33n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: badIpSanCa } }))) === "crmf/bad-popo");

  // The request carries the caller's own template encoding under a MAC covering it, so a PKCS#3
  // template is read in place rather than passed through unexamined because it needs no conversion.
  // The public value is chosen rather than taken from the generated key, whose last byte is random:
  // INTEGER 4 ends in zero bits, so a nonzero unused-bit count is padding the codec accepts.
  var misalignedTemplate = pki.asn1.build.sequence([
    pki.asn1.build.raw(pki.asn1.decode(eeDhSpki).children[0].bytes),
    pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(4n)), 1),
  ]);
  var mtErr = null;
  try {
    await pki.crmf.build({ certReqId: 34n, certTemplate: tpl(misalignedTemplate),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } });
  } catch (e) { mtErr = e; }
  check("V6b. a PKCS#3 requested key whose BIT STRING is not octet-aligned is refused for that reason",
    mtErr !== null && mtErr.code === "crmf/bad-popo" && mtErr.message.indexOf("must be octet-aligned") !== -1);

  // The group is checked whichever encoding carried it. The PKCS#3 form needs no rewrite, so it
  // would otherwise arrive unexamined purely because it happened not to need converting. It states
  // no subgroup order, so the range on the public value is what bounds that value's order there.
  function pkcs3Spki(pv, gv, yv) {
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.113549.1.3.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.integer(pv), pki.asn1.build.integer(gv)]))]),
      pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(yv))),
    ]);
  }
  // DHParameter carries one optional field, privateValueLength, and it is an INTEGER. A third field
  // of another type is not that field, and this reader is the only thing that reads these bytes.
  var pkcs3WithBadPvl = pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.113549.1.3.1"),
      pki.asn1.build.raw(pki.asn1.build.sequence([
        pki.asn1.build.integer(23n), pki.asn1.build.integer(5n), pki.asn1.build.nullValue()]))]),
    pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(4n))),
  ]);
  // An INTEGER carries at least one content octet, so a field tagged as one holding none is not a
  // length. The tag alone does not say that; reading the value does.
  var pkcs3EmptyPvl = pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.113549.1.3.1"),
      pki.asn1.build.raw(pki.asn1.build.sequence([
        pki.asn1.build.integer(23n), pki.asn1.build.integer(5n), pki.asn1.build.raw(Buffer.from([0x02, 0x00]))]))]),
    pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(4n))),
  ]);
  // privateValueLength states how many bits the private value has, and a private value is less than
  // the modulus, so a length above the modulus's own bit count describes no value the group holds.
  // It is carried through unchanged, so the request would travel stating one.
  function pkcs3WithPvlOf(bits) {
    var n = pki.asn1.decode(caDhSpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.113549.1.3.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.integer(bits)]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }
  var caModulusBits = BigInt(pki.asn1.read.integer(pki.asn1.decode(
    pki.asn1.decode(pki.asn1.decode(caDhSpki).children[0].children[1].bytes).children[0].bytes)).toString(2).length);
  var pkcs3Bad = [
    ["a privateValueLength that is not an INTEGER", pkcs3WithBadPvl, "privateValueLength is not an INTEGER"],
    ["a privateValueLength carrying no octets", pkcs3EmptyPvl, "could not be read"],
    ["a privateValueLength one bit longer than its own modulus",
      pkcs3WithPvlOf(caModulusBits + 1n), "longer than its own modulus"],
    ["a privateValueLength far longer than any value the group holds",
      pkcs3WithPvlOf(999999n), "longer than its own modulus"],
    ["a modulus that is not prime", pkcs3Spki(15n, 4n, 11n), "modulus is not prime"],
    ["a public value of order one", pkcs3Spki(23n, 5n, 1n), "public value is outside the group"],
    ["a public value of order two", pkcs3Spki(23n, 5n, 22n), "public value is outside the group"],
    // 13 is prime and 12 = 2*2*3 is not twice a prime, so 3 has order 3 and sits inside the range.
    // Without a stated subgroup order, only the group being a safe prime bounds that value's order.
    ["a prime modulus that is not a safe prime", pkcs3Spki(13n, 2n, 3n), "is not a safe prime"],
    // 23 IS a safe prime, and its own subgroup has order 11. Being safe bounds the order to (p-1)/2,
    // which is only worth having when p is large, so the floor applies however the order was stated.
    ["a safe prime whose subgroup is tiny", pkcs3Spki(23n, 5n, 2n), "too small to hide a private exponent"],
    // A real 512-bit safe prime: its subgroup has 255 bits and clears the order floor, while the
    // group itself is reachable through the modulus rather than through the subgroup.
    ["a safe prime far too small to agree in", pkcs3Spki(
      BigInt("0x842edc61ba26a113f9ae44b26a9f3c3770f7ff0bcbb44190e5340b4232bc230fe517b78d38bb56d87b66c6858cf6e2128dcfdd035ad8fd5be15d068977346b5f"),
      2n,
      BigInt("0x386df24e0e8fa5ad6c72fc6bec40dfd7ecad7b954ad60039edf2f7521dc644f953dcf443241934e8b2d5ffd178ed3ec37dd1433e7b55900928fb380132152528")),
      "modulus is under"],
  ];
  for (var pb = 0; pb < pkcs3Bad.length; pb++) {
    var pErr = null;
    try {
      await pki.crmf.build({ certReqId: 30n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
          caCert: await dhCertFor(pkcs3Bad[pb][1], { serialNumber: 41 + pb }) } });
    } catch (e) { pErr = e; }
    check("V6b. a PKCS#3 authority certificate stating " + pkcs3Bad[pb][0] + " is refused for that reason",
      pErr !== null && pErr.code === "crmf/bad-popo" && pErr.message.indexOf(pkcs3Bad[pb][2]) !== -1);
  }

  // The conforming shapes each rule admits, written for the least obvious valid input rather than
  // the canonical one, since a suite of malformed inputs cannot fail when a rule is too strict.
  var eeX942Parts = (function () {
    var n = pki.asn1.decode(eeX942Spki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return { p: prm.children[0].bytes, g: prm.children[1].bytes, q: prm.children[2].bytes,
      pub: n.children[1].bytes };
  }());
  function x942Domain(extra) {
    var fields = [pki.asn1.build.raw(eeX942Parts.p), pki.asn1.build.raw(eeX942Parts.g),
      pki.asn1.build.raw(eeX942Parts.q)];
    for (var i = 0; extra && i < extra.length; i++) fields.push(extra[i]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence(fields))]),
      pki.asn1.build.raw(eeX942Parts.pub),
    ]);
  }
  var realP = pki.asn1.read.integer(pki.asn1.decode(eeX942Parts.p));
  var conforming = [
    ["domain parameters carrying no optional field at all", x942Domain(null)],
    ["a correct cofactor beside the order", x942Domain([pki.asn1.build.integer((realP - 1n) / ((realP - 1n) / 2n))])],
    ["validation parameters with no cofactor before them", x942Domain([
      pki.asn1.build.sequence([pki.asn1.build.bitString(Buffer.from([0x00])), pki.asn1.build.integer(1n)])])],
  ];
  for (var cf = 0; cf < conforming.length; cf++) {
    check("V6b. a requested key stating " + conforming[cf][0] + " is proven",
      (await codeOf(pki.crmf.build({ certReqId: 50n, certTemplate: tpl(conforming[cf][1]),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === null);
  }

  // The PKCS#3 optional field, present and well-formed: the form the refusal vectors above only
  // ever drive malformed.
  var pkcs3WithPvl = (function () {
    var n = pki.asn1.decode(caDhSpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.113549.1.3.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.integer(256n)]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  // The largest length the modulus admits is the modulus's own bit count, so it is the boundary the
  // refusals above sit one past and it still agrees.
  check("V6b. a privateValueLength exactly as long as the modulus still agrees",
    (await codeOf(pki.crmf.build({ certReqId: 65n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(pkcs3WithPvlOf(caModulusBits), { serialNumber: 75 }) } }))) === null);
  // The requested key is read by the same function, and a refusal has to name the key it is about
  // rather than the authority certificate, which this caller supplied correctly.
  var tplPvlErr = null;
  try {
    await pki.crmf.build({ certReqId: 66n, certTemplate: tpl(pkcs3WithPvlOf(999999n)),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } });
  } catch (e) { tplPvlErr = e; }
  check("V6b. a requested key stating an impossible privateValueLength is refused, naming that key",
    tplPvlErr !== null && tplPvlErr.code === "crmf/bad-popo" &&
    tplPvlErr.message.indexOf("longer than its own modulus") !== -1 &&
    tplPvlErr.message.indexOf("certTemplate.publicKey") !== -1);

  check("V6b. an authority key carrying a well-formed privateValueLength agrees",
    (await codeOf(pki.crmf.build({ certReqId: 51n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(pkcs3WithPvl, { serialNumber: 52 }) } }))) === null);

  // The requester's own key reaches this in both encodings too. Supporting X9.42 for everyone else's
  // key and not for the caller's would be the encoding half-supported.
  var eeX942Pk8 = (function () {
    var n = pki.asn1.decode(eeDhPk8);
    var prm = pki.asn1.decode(n.children[1].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    var domain = pki.asn1.build.sequence([
      pki.asn1.build.integer(p), pki.asn1.build.integer(pki.asn1.read.integer(prm.children[1])),
      pki.asn1.build.integer((p - 1n) / 2n),
    ]);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes),
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"), pki.asn1.build.raw(domain)]),
      pki.asn1.build.raw(n.children[2].bytes),
    ]);
  }());
  check("V6b. the X9.42 private encoding really is the one this runtime does not classify",
    nodeCrypto.createPrivateKey({ key: Buffer.from(eeX942Pk8), format: "der", type: "pkcs8" })
      .asymmetricKeyType === undefined);
  // The MAC covers the DER certReq, so the two requests are identical but for the key's encoding.
  var x942PrivDer = await pki.crmf.build({ certReqId: 53n, certTemplate: tpl(eeDhSpki),
    pop: { type: "keyAgreement", method: "agreeMAC", key: eeX942Pk8, caCert: dhCaCert } });
  var pkcs3PrivDer = await pki.crmf.build({ certReqId: 53n, certTemplate: tpl(eeDhSpki),
    pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } });
  // A PEM key now takes the decode-and-translate path, so the ordinary form has to still arrive:
  // the PKCS#3 key this runtime already read, which the translation leaves alone.
  check("V6b. an ordinary PKCS#3 key supplied as PEM still agrees",
    (await codeOf(pki.crmf.build({ certReqId: 54n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
        key: nodeCrypto.createPrivateKey({ key: Buffer.from(eeDhPk8), format: "der", type: "pkcs8" })
          .export({ format: "pem", type: "pkcs8" }) } }))) === null);

  // The same key as an already-imported key object, which the runtime holds without classifying.
  // Bytes, PEM and key object are three ways of handing over one key; admitting two is not support.
  check("V6b. a requester handing over its X9.42 key as a key object reaches the same proof",
    dhPopStaticOf(parse(await pki.crmf.build({ certReqId: 53n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
        key: nodeCrypto.createPrivateKey({ key: Buffer.from(eeX942Pk8), format: "der", type: "pkcs8" }) } }))[0].popo.bytes)
      .hashValue.equals(dhPopStaticOf(parse(await pki.crmf.build({ certReqId: 53n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeX942Pk8, caCert: dhCaCert } }))[0].popo.bytes).hashValue));

  // The same key under a PEM armor is the same key. Admitting one form and not the other would
  // support the encoding for a caller holding DER and refuse the caller holding identical bytes.
  var eeX942Pem = "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(eeX942Pk8).toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END PRIVATE KEY-----\n";
  check("V6b. a requester holding its X9.42 key as PEM reaches the same proof as its DER",
    dhPopStaticOf(parse(await pki.crmf.build({ certReqId: 53n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeX942Pem, caCert: dhCaCert } }))[0].popo.bytes)
      .hashValue.equals(dhPopStaticOf(parse(await pki.crmf.build({ certReqId: 53n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeX942Pk8, caCert: dhCaCert } }))[0].popo.bytes).hashValue));

  check("V6b. a requester holding its key in the X9.42 form reaches the same proof",
    dhPopStaticOf(parse(x942PrivDer)[0].popo.bytes).hashValue.equals(
      dhPopStaticOf(parse(pkcs3PrivDer)[0].popo.bytes).hashValue));

  // The requester's own parameters are read before the translation drops them, the same way the
  // public half's are. A field the translation does not read is a field it rewrites away unlooked-at,
  // so a key this runtime refuses in the encoding it was handed becomes one it accepts.
  var eePrivParts = (function () {
    var n = pki.asn1.decode(eeDhPk8);
    var prm = pki.asn1.decode(n.children[1].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    return { p: p, g: pki.asn1.read.integer(prm.children[1]), q: (p - 1n) / 2n };
  }());
  function x942PrivWith(fields) {
    var n = pki.asn1.decode(eeDhPk8);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes),
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence(fields))]),
      pki.asn1.build.raw(n.children[2].bytes),
    ]);
  }
  function privPgq(extra) {
    var fields = [pki.asn1.build.integer(eePrivParts.p), pki.asn1.build.integer(eePrivParts.g),
      pki.asn1.build.integer(eePrivParts.q)];
    for (var i = 0; extra && i < extra.length; i++) fields.push(extra[i]);
    return x942PrivWith(fields);
  }
  // The same p and g with the stated order itself replaced, for the cases about q rather than about
  // what follows it.
  function privPgq0(qAndAfter) {
    var fields = [pki.asn1.build.integer(eePrivParts.p), pki.asn1.build.integer(eePrivParts.g)];
    for (var i = 0; i < qAndAfter.length; i++) fields.push(qAndAfter[i]);
    return x942PrivWith(fields);
  }
  var goodVp = pki.asn1.build.sequence([
    pki.asn1.build.bitString(Buffer.from([0x00])), pki.asn1.build.integer(1n)]);
  var privBad = [
    ["an order that is not an INTEGER", x942PrivWith([pki.asn1.build.integer(eePrivParts.p),
      pki.asn1.build.integer(eePrivParts.g), pki.asn1.build.nullValue()]),
      "could not be read"],
    ["a field beyond the two optional ones",
      privPgq([pki.asn1.build.integer(1n), goodVp, pki.asn1.build.integer(7n)]),
      "not a DomainParameters SEQUENCE"],
    ["a fourth field that is neither a cofactor nor validationParms",
      privPgq([pki.asn1.build.oid("1.2.3")]), "neither a cofactor nor validationParms"],
    ["a field after validationParms", privPgq([goodVp, pki.asn1.build.integer(7n)]),
      "a field after validationParms"],
    ["validationParms that are not a seed with a counter", privPgq([pki.asn1.build.sequence([])]),
      "not a seed BIT STRING with a pgenCounter INTEGER"],
    ["parameters that are not a DomainParameters SEQUENCE at all",
      x942PrivWith([pki.asn1.build.integer(eePrivParts.p)]), "not a DomainParameters SEQUENCE"],
    // The order and cofactor are held to the p and g stated beside them, the same way the requested
    // key's are. The PKCS#3 form the conversion produces carries neither, so this is the last place
    // either is read, and a request whose own key states a group it does not have would go out.
    ["a negative order", privPgq0([pki.asn1.build.integer(-1n)]),
      "state a subgroup order its own p and g do not have"],
    ["an order its own p and g do not have",
      privPgq0([pki.asn1.build.integer(eePrivParts.q - 2n)]),
      "state a subgroup order its own p and g do not have"],
    ["a cofactor its own p and q contradict", privPgq([pki.asn1.build.integer(3n)]),
      "cofactor does not match"],
    ["an order wider than any group", privPgq0([pki.asn1.build.integer(1n << 20000n)]),
      "larger than any Diffie-Hellman group"],
  ];
  for (var pv = 0; pv < privBad.length; pv++) {
    var pvErr = null;
    try {
      await pki.crmf.build({ certReqId: 55n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: privBad[pv][1], caCert: dhCaCert } });
    } catch (e) { pvErr = e; }
    check("V6b. pop.key stating " + privBad[pv][0] + " is refused for that reason",
      pvErr !== null && pvErr.code === "crmf/bad-popo" &&
      pvErr.message.indexOf(privBad[pv][2]) !== -1);
  }
  // The same rule read the other way: the optional fields a conforming key carries still agree, so
  // the refusals above are not a reader that stopped at three fields.
  check("V6b. pop.key carrying a correct cofactor beside its order still agrees",
    (await codeOf(pki.crmf.build({ certReqId: 56n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
        key: privPgq([pki.asn1.build.integer((eePrivParts.p - 1n) / eePrivParts.q)]) } }))) === null);
  check("V6b. pop.key carrying validationParms with no cofactor before them still agrees",
    (await codeOf(pki.crmf.build({ certReqId: 57n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
        key: privPgq([goodVp]) } }))) === null);

  // RFC 2631 sec. 2.2: "X9.42 requires that the private key x be in the interval [2, (q - 2)]."
  // The excluded exponents are the ones whose agreed secret follows from the authority's certificate:
  // x = 0 agrees one, x = 1 agrees the authority's public value itself, and x = q-1 agrees its
  // inverse. A proof made with any of them demonstrates possession of nothing.
  function modPowT(b, e, m) { var r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
  function privWithExponent(x) {
    var n = pki.asn1.decode(eeDhPk8);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes), pki.asn1.build.raw(n.children[1].bytes),
      pki.asn1.build.octetString(Buffer.from(pki.asn1.build.integer(x))),
    ]);
  }
  function spkiForValue(y) {
    var n = pki.asn1.decode(eeDhSpki);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes),
      pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(y))),
    ]);
  }
  var expoOrder = (eePrivParts.p - 1n) / 2n;
  var expoBad = [
    ["one, so the secret it agrees is the authority's own public value", 1n],
    ["the order less one, so the secret it agrees is the inverse of that value", expoOrder - 1n],
  ];
  for (var xe = 0; xe < expoBad.length; xe++) {
    var xeY = modPowT(eePrivParts.g, expoBad[xe][1], eePrivParts.p);
    var xeErr = null;
    try {
      await pki.crmf.build({ certReqId: 58n, certTemplate: tpl(spkiForValue(xeY)),
        pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
          key: privWithExponent(expoBad[xe][1]) } });
    } catch (e) { xeErr = e; }
    check("V6b. a requester private exponent of " + expoBad[xe][0] + " is refused",
      xeErr !== null && xeErr.code === "crmf/bad-popo" &&
      xeErr.message.indexOf("[2, q-2]") !== -1);
  }
  // Zero is refused where the public value it produces is read, which is a different sentence, so it
  // is pinned separately rather than folded into the interval above.
  check("V6b. a requester private exponent of zero is refused on the value it produces",
    (await codeOf(pki.crmf.build({ certReqId: 59n, certTemplate: tpl(spkiForValue(1n)),
      pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
        key: privWithExponent(0n) } }))) === "crmf/bad-popo");
  // The same interval binds the authority's key, which is the other half of the same agreement. An
  // authority whose public value is g agrees the requester's own public value, and one whose value is
  // the inverse of g agrees its inverse; both appear in the request the proof travels in.
  var caParts = (function () {
    var n = pki.asn1.decode(caDhSpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    return { p: pki.asn1.read.integer(prm.children[0]), g: pki.asn1.read.integer(prm.children[1]) };
  }());
  var caBad = [
    ["g, so the secret it agrees is the requester's own public value", caParts.g],
    ["the inverse of g, so the secret it agrees is the inverse of that value",
      modPowT(caParts.g, caParts.p - 2n, caParts.p)],
  ];
  for (var cb = 0; cb < caBad.length; cb++) {
    var cbErr = null;
    try {
      await pki.crmf.build({ certReqId: 61n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
          caCert: await dhCertFor(pkcs3Spki(caParts.p, caParts.g, caBad[cb][1]),
            { serialNumber: 70 + cb }) } });
    } catch (e) { cbErr = e; }
    check("V6b. an authority public value of " + caBad[cb][0] + " is refused",
      cbErr !== null && cbErr.code === "crmf/bad-popo" && cbErr.message.indexOf("[2, q-2]") !== -1);
  }
  // A safe prime has element orders 1, 2, q and 2q, and the PKCS#3 form states no order, so a
  // generator of the full order 2q is admitted. Its square root of one is p-1, which reflects every
  // excluded value: g^(q+1) is p-g and g^(q-1) is p-g inverse. Both agree a secret that follows from
  // the authority's public value, and neither equals g or its inverse, so the interval has to be read
  // through that reflection rather than on the two values alone.
  var fullOrderG = (function () {
    for (var cand = 3n; cand < 200n; cand++) {
      if (modPowT(cand, expoOrder, eePrivParts.p) === eePrivParts.p - 1n) return cand;
    }
    return 0n;
  }());
  check("V6b. the full-order generator fixture really has order 2q, not q",
    fullOrderG > 2n && modPowT(fullOrderG, expoOrder, eePrivParts.p) === eePrivParts.p - 1n);
  function pkcs3PrivWith(gv, x) {
    return pki.asn1.build.sequence([pki.asn1.build.integer(0n),
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.113549.1.3.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.integer(eePrivParts.p), pki.asn1.build.integer(gv)]))]),
      pki.asn1.build.octetString(Buffer.from(pki.asn1.build.integer(x)))]);
  }
  var fullOrderCa = await dhCertFor(
    pkcs3Spki(eePrivParts.p, fullOrderG, modPowT(fullOrderG, 123456789n, eePrivParts.p)),
    { serialNumber: 74 });
  var reflected = [
    ["the order less one, whose public value is p minus the inverse of g", expoOrder - 1n],
    ["the order plus one, whose public value is p minus g", expoOrder + 1n],
  ];
  for (var rf = 0; rf < reflected.length; rf++) {
    var rfY = modPowT(fullOrderG, reflected[rf][1], eePrivParts.p);
    var rfErr = null;
    try {
      await pki.crmf.build({ certReqId: 63n,
        certTemplate: tpl(pkcs3Spki(eePrivParts.p, fullOrderG, rfY)),
        pop: { type: "keyAgreement", method: "agreeMAC", caCert: fullOrderCa,
          key: pkcs3PrivWith(fullOrderG, reflected[rf][1]) } });
    } catch (e) { rfErr = e; }
    check("V6b. a requester exponent of " + reflected[rf][0] + " is refused",
      rfErr !== null && rfErr.code === "crmf/bad-popo" && rfErr.message.indexOf("[2, q-2]") !== -1);
  }
  // Read the other way: an exponent this reflection does not name still agrees in that same group,
  // so the rule excludes the values whose secret follows with no search and not the small ones.
  check("V6b. an ordinary exponent in a full-order group still agrees",
    (await codeOf(pki.crmf.build({ certReqId: 64n,
      certTemplate: tpl(pkcs3Spki(eePrivParts.p, fullOrderG, modPowT(fullOrderG, 987654321n, eePrivParts.p))),
      pop: { type: "keyAgreement", method: "agreeMAC", caCert: fullOrderCa,
        key: pkcs3PrivWith(fullOrderG, 987654321n) } }))) === null);

  // One is refused where the range of the group is read, which is a different sentence, so it is
  // pinned separately rather than folded into the interval above.
  check("V6b. an authority public value of one is refused on the range it lies outside",
    (await codeOf(pki.crmf.build({ certReqId: 62n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(pkcs3Spki(caParts.p, caParts.g, 1n),
          { serialNumber: 73 }) } }))) === "crmf/bad-popo");

  // Read the other way: the smallest and largest exponents the interval admits still agree, so the
  // rule is the interval rather than a floor on how large an exponent has to be.
  var expoOk = [["two, the smallest the interval admits", 2n],
    ["the order less two, the largest it admits", expoOrder - 2n]];
  for (var xo = 0; xo < expoOk.length; xo++) {
    var xoY = modPowT(eePrivParts.g, expoOk[xo][1], eePrivParts.p);
    check("V6b. a requester private exponent of " + expoOk[xo][0] + " agrees",
      (await codeOf(pki.crmf.build({ certReqId: 60n, certTemplate: tpl(spkiForValue(xoY)),
        pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert,
          key: privWithExponent(expoOk[xo][1]) } }))) === null);
  }

  // A certificate stating q = p-1 satisfies every structural test: p-1 divides itself, and g^(p-1)
  // and y^(p-1) are 1 for the whole group by Fermat. Only q being prime makes the subgroup test say
  // anything, since y^q = 1 otherwise bounds the order of y to a divisor of q rather than to q.
  var vacuousQ = (function () {
    var n = pki.asn1.decode(x942Spki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.integer(p - 1n),
        ]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  var vqErr = null;
  try {
    await pki.crmf.build({ certReqId: 25n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(vacuousQ, { serialNumber: 34 }) } });
  } catch (e) { vqErr = e; }
  check("V6b. a stated subgroup order that is not prime is refused for that reason",
    vqErr !== null && vqErr.code === "crmf/bad-popo" &&
    vqErr.message.indexOf("subgroup order that is not prime") !== -1);

  // DomainParameters state the subgroup the key must live in, and the PKCS#3 form this is rewritten
  // into cannot carry it. A key outside that subgroup is refused while the parameter stating it is
  // still present, since agreeing with one leaks the private exponent modulo its true order.
  var badSubgroupSpki = (function () {
    function modPow(base, e, m) {
      var r = 1n, bb = base % m;
      while (e > 0n) { if (e & 1n) r = (r * bb) % m; e >>= 1n; bb = (bb * bb) % m; }
      return r;
    }
    var n = pki.asn1.decode(x942Spki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    var q = pki.asn1.read.integer(prm.children[2]);
    // Search rather than assume: a value is outside the order-q subgroup exactly when y^q != 1,
    // and whether any particular constant satisfies that depends on the group.
    var y = 0n;
    for (var cand = 2n; cand < 200n; cand++) {
      if (modPow(cand, q, p) !== 1n) { y = cand; break; }
    }
    check("V6b. the subgroup vector really is outside the subgroup",
      y > 1n && y < p - 1n && modPow(y, q, p) !== 1n);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes),
      pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(y))),
    ]);
  }());
  check("V6b. an authority public value outside its stated subgroup is refused",
    (await codeOf(pki.crmf.build({ certReqId: 21n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8,
        caCert: await dhCertFor(badSubgroupSpki, { serialNumber: 26 }) } }))) === "crmf/bad-popo");

  // pop.caCert reaches a decoder before anything reads it as a certificate. Every shape that decoder
  // refuses is a verdict on the caller's input, so each one names its reason instead of escaping as
  // whatever the runtime happened to throw.
  var caCertDoors = [
    ["malformed PEM", "-----BEGIN CERTIFICATE-----\nnot base64 !!!\n-----END CERTIFICATE-----"],
    ["a number", 12345],
    ["a plain object", { nope: true }],
    ["a PEM under another label", "-----BEGIN PRIVATE KEY-----\n" +
      Buffer.from(dhCaCert).toString("base64") + "\n-----END PRIVATE KEY-----"],
  ];
  for (var cd = 0; cd < caCertDoors.length; cd++) {
    check("V6b. pop.caCert as " + caCertDoors[cd][0] + " is refused as a typed verdict",
      (await codeOf(pki.crmf.build({ certReqId: 17n, certTemplate: tpl(eeDhSpki),
        pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: caCertDoors[cd][1] } }))) === "crmf/bad-popo");
  }

  // One finite-field key has more than one valid SubjectPublicKeyInfo, because a PKCS#3 DHParameter
  // carries an optional privateValueLength. The template may spell the key one way and the private
  // key export the other; they are the same key, and the proof is about the key.
  var dhParamsWithLen = (function () {
    var n = pki.asn1.decode(eeDhSpki);
    var alg = n.children[0], params = pki.asn1.decode(alg.children[1].bytes);
    var withLen = pki.asn1.build.sequence([
      pki.asn1.build.raw(params.children[0].bytes), pki.asn1.build.raw(params.children[1].bytes),
      pki.asn1.build.integer(BigInt(256)),
    ]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.raw(alg.children[0].bytes), pki.asn1.build.raw(withLen)]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  var reSpelled = nodeCrypto.createPublicKey({ key: dhParamsWithLen, format: "der", type: "spki" });
  check("V6b. the re-spelled SPKI really is the same key",
    reSpelled.asymmetricKeyType === "dh" &&
    !Buffer.from(dhParamsWithLen).equals(Buffer.from(eeDhSpki)));
  check("V6b. a template spelling the requested key another valid way is still proven",
    (await codeOf(pki.crmf.build({ certReqId: 16n, certTemplate: tpl(dhParamsWithLen),
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === null);

  var strayDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
  check("V6b. a pop.key from another pair than the requested key is refused",
    (await codeOf(pki.crmf.build({ certReqId: 12n, certTemplate: tpl(eeDhSpki),
      pop: { type: "keyAgreement", method: "agreeMAC",
        key: strayDh.privateKey.export({ format: "der", type: "pkcs8" }), caCert: dhCaCert } }))) === "crmf/bad-popo");

  // sec. 3 defines this proof over a finite-field group. An elliptic-curve or montgomery pair agrees a
  // secret through the same call, so a builder that only asked whether the two sides matched would
  // emit that agreement under an OID naming an operation the recipient is not performing.
  for (var ffCase of [["ec", { namedCurve: "prime256v1" }], ["x25519", undefined]]) {
    var ffPair = nodeCrypto.generateKeyPairSync(ffCase[0], ffCase[1]);
    var ffSpki = ffPair.publicKey.export({ format: "der", type: "spki" });
    var ffCert = await dhCertFor(ffSpki, { serialNumber: 30, subject: "ff-authority.example" });
    check("V6b. a " + ffCase[0] + " pair is refused: this proof is finite-field DH (RFC 2875 sec. 3)",
      (await codeOf(pki.crmf.build({ certReqId: 15n, certTemplate: tpl(ffSpki),
        pop: { type: "keyAgreement", method: "agreeMAC",
          key: ffPair.privateKey.export({ format: "der", type: "pkcs8" }), caCert: ffCert } }))) === "crmf/bad-popo");
  }

  // A key of another ALGORITHM is refused before any agreement is attempted, which is a different
  // reason from the group mismatch above: that one is caught by the agreement failing, this one by
  // the two keys not being the same kind of key at all.
  var ecReq = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  check("V6b. a requester key of another algorithm is refused before agreeing anything",
    (await codeOf(pki.crmf.build({ certReqId: 11n, certTemplate: tpl(ecReq.publicKey.export({ format: "der", type: "spki" })),
      pop: { type: "keyAgreement", method: "agreeMAC",
        key: ecReq.privateKey.export({ format: "der", type: "pkcs8" }), caCert: dhCaCert } }))) === "crmf/bad-popo");
  // The POPOPrivKey comment requires the certReq to carry both the subject and the publicKey.
  check("V6b. a certReq naming no publicKey is refused",
    (await codeOf(pki.crmf.build({ certReqId: 9n, certTemplate: { subject: [{ commonName: "device" }] },
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === "crmf/bad-popo");
  check("V6b. and one naming no subject is refused",
    (await codeOf(pki.crmf.build({ certReqId: 10n, certTemplate: { publicKey: eeDhSpki },
      pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8, caCert: dhCaCert } }))) === "crmf/bad-popo");
  check("V6b. and the two inputs it needs are each named when missing",
    (await codeOf(pki.crmf.build(Object.assign({}, agreeSpec, { pop: { type: "keyAgreement", method: "agreeMAC", caCert: dhCaCert } })))) === "crmf/bad-popo" &&
    (await codeOf(pki.crmf.build(Object.assign({}, agreeSpec, { pop: { type: "keyAgreement", method: "agreeMAC", key: eeDhPk8 } })))) === "crmf/bad-popo");

  // V7 -- encryptedKey round-trips, including the parser's INDEPENDENT id-ct-encKeyWithID check.
  var recip = makeSigner("rsa");
  var encSpec = spec({ type: "keyEncipherment", method: "encryptedKey", privateKey: kemPkcs8,
    identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true });
  var encDer = await pki.crmf.build(encSpec);
  var encMsg = parse(encDer)[0];
  check("POP encryptedKey round-trips through the parser's own content-type check",
    encMsg.popo && encMsg.popo.type === "keyEncipherment" && encMsg.popo.method === "encryptedKey");

  // The encryptedKey arm sends a private key to be archived and agrees nothing, so the group floors
  // the agreement needs do not apply to it. A legacy 1024-bit Diffie-Hellman key is exactly what
  // archival exists for, and the same key is still refused for a proof that agrees a secret.
  var legacyDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp2" });
  var legacySpki = legacyDh.publicKey.export({ format: "der", type: "spki" });
  var legacyPk8 = legacyDh.privateKey.export({ format: "der", type: "pkcs8" });
  var legacyX942 = (function () {
    var n = pki.asn1.decode(legacySpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.integer(p), pki.asn1.build.integer(pki.asn1.read.integer(prm.children[1])),
          pki.asn1.build.integer((p - 1n) / 2n)]))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }());
  check("V7. a legacy X9.42 key still archives through encryptedKey, which agrees nothing",
    (await codeOf(pki.crmf.build({ certReqId: 40n, certTemplate: tpl(legacyX942),
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: legacyPk8,
        identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } }))) === null);
  // The encryptedKey arm carries the caller's template too, so a PKCS#3 one is read in its own
  // right rather than passed through unexamined because it needed no conversion.
  var encMisaligned = pki.asn1.build.sequence([
    pki.asn1.build.raw(pki.asn1.decode(legacySpki).children[0].bytes),
    pki.asn1.build.bitString(Buffer.from(pki.asn1.build.integer(4n)), 1),
  ]);
  var emErr = null;
  try {
    await pki.crmf.build({ certReqId: 42n, certTemplate: tpl(encMisaligned),
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: legacyPk8,
        identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } });
  } catch (e) { emErr = e; }
  // This arm asks one question (RFC 4211 sec. 4.2): is the enclosed key the private half of the
  // requested one. It agrees no secret, so the group is not measured here and a key too large to
  // prove prime is not a key too large to archive. A 6144-bit group carries no agreement bound.
  var bigDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp17" });
  // Both sides in the X9.42 form: an enclosed key in that encoding derives its public half in it too,
  // so converting only the template would compare one encoding against the other and refuse a pair
  // that matches. The earlier legacy vector cannot see this, since its private key is PKCS#3.
  var legacyX942Pk8 = (function () {
    var n = pki.asn1.decode(legacyPk8);
    var prm = pki.asn1.decode(n.children[1].children[1].bytes);
    var p = pki.asn1.read.integer(prm.children[0]);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes),
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.integer(p), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.integer((p - 1n) / 2n)]))]),
      pki.asn1.build.raw(n.children[2].bytes),
    ]);
  }());
  check("V7. an enclosed key and a template both in the X9.42 form are recognized as one key",
    (await codeOf(pki.crmf.build({ certReqId: 45n, certTemplate: tpl(legacyX942),
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: legacyX942Pk8,
        identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } }))) === null);

  // The group is not measured on this arm, and what a stated order and cofactor say about the p and g
  // beside them is a separate question from how good that group is. The conversion drops both while
  // the request goes out carrying the caller's own encoding of them, so they are answered for here.
  // These tests cost a multiplication and a modulo, which is why they apply where a size bound cannot.
  function legacyX942With(qv, jv) {
    var n = pki.asn1.decode(legacySpki);
    var prm = pki.asn1.decode(n.children[0].children[1].bytes);
    var fields = [pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
      pki.asn1.build.integer(qv)];
    if (jv !== null) fields.push(pki.asn1.build.integer(jv));
    return pki.asn1.build.sequence([
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence(fields))]),
      pki.asn1.build.raw(n.children[1].bytes),
    ]);
  }
  var legacyP = pki.asn1.read.integer(pki.asn1.decode(
    pki.asn1.decode(pki.asn1.decode(legacySpki).children[0].children[1].bytes).children[0].bytes));
  var archBad = [
    ["a cofactor its own p and q contradict", legacyX942With((legacyP - 1n) / 2n, 999n),
      "cofactor does not match"],
    ["an order that does not divide p-1", legacyX942With((legacyP - 1n) / 2n - 1n, null),
      "state a subgroup order its own p and g do not have"],
    ["an order of one", legacyX942With(1n, null),
      "state a subgroup order its own p and g do not have"],
  ];
  for (var ab = 0; ab < archBad.length; ab++) {
    var abErr = null;
    try {
      await pki.crmf.build({ certReqId: 46n, certTemplate: tpl(archBad[ab][1]),
        pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: legacyPk8,
          identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } });
    } catch (e) { abErr = e; }
    check("V7. an archived template stating " + archBad[ab][0] + " is refused for that reason",
      abErr !== null && abErr.code === "crmf/bad-popo" &&
      abErr.message.indexOf(archBad[ab][2]) !== -1);
  }
  // The enclosed key states the same parameters, and its public half carries them into the archive
  // with it, so a template written correctly does not excuse an enclosed key that was not.
  var legacyX942Pk8Bad = (function () {
    var n = pki.asn1.decode(legacyPk8);
    var prm = pki.asn1.decode(n.children[1].children[1].bytes);
    return pki.asn1.build.sequence([
      pki.asn1.build.raw(n.children[0].bytes),
      pki.asn1.build.sequence([pki.asn1.build.oid("1.2.840.10046.2.1"),
        pki.asn1.build.raw(pki.asn1.build.sequence([
          pki.asn1.build.raw(prm.children[0].bytes), pki.asn1.build.raw(prm.children[1].bytes),
          pki.asn1.build.integer((legacyP - 1n) / 2n), pki.asn1.build.integer(999n)]))]),
      pki.asn1.build.raw(n.children[2].bytes),
    ]);
  }());
  var ekErr = null;
  try {
    await pki.crmf.build({ certReqId: 48n, certTemplate: tpl(legacyX942),
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: legacyX942Pk8Bad,
        identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } });
  } catch (e) { ekErr = e; }
  check("V7. an enclosed private key stating a cofactor its own p and q contradict is refused",
    ekErr !== null && ekErr.code === "crmf/bad-popo" &&
    ekErr.message.indexOf("cofactor does not match") !== -1);

  // Read the other way: the order this group really has, with its correct cofactor, still archives,
  // so the refusals above are not this arm having started to measure the group.
  check("V7. an archived template stating its real order and cofactor still archives",
    (await codeOf(pki.crmf.build({ certReqId: 47n,
      certTemplate: tpl(legacyX942With((legacyP - 1n) / 2n, 2n)),
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: legacyPk8,
        identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } }))) === null);

  check("V7. a group larger than any agreement would accept still archives",
    (await codeOf(pki.crmf.build({ certReqId: 44n,
      certTemplate: tpl(bigDh.publicKey.export({ format: "der", type: "spki" })),
      pop: { type: "keyEncipherment", method: "encryptedKey",
        privateKey: bigDh.privateKey.export({ format: "der", type: "pkcs8" }),
        identifier: "device-42", recipients: [{ cert: recip.cert }], archive: true } }))) === null);

  check("V7. a PKCS#3 template whose BIT STRING is not octet-aligned is refused on this arm too",
    emErr !== null && emErr.code === "crmf/bad-popo" && emErr.message.indexOf("must be octet-aligned") !== -1);

  check("V7. and the same key is refused for a proof that does agree a secret",
    (await codeOf(pki.crmf.build({ certReqId: 41n, certTemplate: tpl(legacyX942),
      pop: { type: "keyAgreement", method: "agreeMAC", key: legacyPk8,
        caCert: await dhCertFor(legacySpki, { serialNumber: 50 }) } }))) === "crmf/bad-popo");

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
