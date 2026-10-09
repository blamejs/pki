// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- every verdict a public verify verb returns is built by guard.verdict.of, so it owns
 * the fields it reports and ends the prototype lookup for `then` on itself.
 *
 * Resolving a promise reads `then` off the value it settles with. A verdict that does not own one
 * hands that lookup to Object.prototype, where an accessor runs with the verdict as its receiver
 * and can rewrite the decision on its way to the caller. Each vector below drives the shipped verb,
 * installs such an accessor while the verification is pending, and asserts the caller receives the
 * object the verb built, still reporting what it computed.
 *
 * This states the rule once for every verb a vector here drives, rather than in the suite of
 * whichever module happens to notice. Completeness across the tree is a separate mechanism: the
 * `unshielded-verdict-literal` detector in codebase-patterns reads the construction sites and fires
 * on a verdict literal returned without the guard anywhere in `lib/`, including in a module that
 * does not exist yet.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = require("../helpers/signing").makeSigner;

var hasOwn = Object.prototype.hasOwnProperty;

// A row inside a verdict is a verdict: a caller that awaits one crosses the same resolution, and
// the sentinel is what ends the lookup there too.
function ownsThen(label, value) {
  check(label + ": owns then, so the prototype's is never reached",
    value !== null && typeof value === "object" && hasOwn.call(value, "then") && value.then === undefined);
}

// Install a `then` getter that rewrites the decision, resolve the pending verdict through it, and
// report whether the caller got the verb's own object back unchanged.
async function survives(label, pending, field, expected) {
  var held, sameShape;
  Object.defineProperty(Object.prototype, "then", {
    configurable: true,
    get: function () {
      try { this[field] = !expected; } catch (_e) { /* a frozen verdict refuses the write */ }
      return undefined;
    },
  });
  try {
    var v = await pending;
    sameShape = hasOwn.call(v, "then") && v.then === undefined;
    held = sameShape && v[field] === expected;
  } finally { delete Object.prototype.then; }
  check(label + ": the verdict owns then and still reports " + field + " === " + expected, held);
}

async function testCsr() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "shield.example", subjectPublicKey: s.spki }, { key: s.key });
  await survives("pki.csr.verify", pki.csr.verify(der), "valid", true);
}

async function testCrl() {
  var s = makeSigner("ed25519");
  var crl = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"), crlNumber: 1n },
    { name: "Shield CRL Issuer", publicKey: s.spki, key: s.key });
  await survives("pki.crl.verify", pki.crl.verify(crl, { publicKey: s.spki }), "valid", true);
}

async function testCms() {
  var s = makeSigner("ed25519");
  var signed = await pki.cms.sign(Buffer.from("shield"), { cert: s.cert, key: s.key });
  await survives("pki.cms.verify", pki.cms.verify(signed), "valid", true);
}

async function testCrmf() {
  var s = makeSigner("ed25519");
  var req = await pki.crmf.build({ certReqId: 1n, certTemplate: { subject: "shield.example", publicKey: s.spki } }, { key: s.key });
  await survives("pki.crmf.verifyPop", pki.crmf.verifyPop(req), "valid", true);
}

async function testPkcs12() {
  var s = makeSigner("ed25519");
  var pfx = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "shield" });
  await survives("pki.pkcs12.verifyMac", pki.pkcs12.verifyMac(pfx, "shield"), "valid", true);
  await survives("pki.pkcs12.open", pki.pkcs12.open(pfx, "shield"), "valid", true);
}

async function testPath() {
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2028-01-01T00:00:00Z");
  var at = new Date("2027-01-01T00:00:00Z");
  var rootKey = makeSigner("ed25519");
  var rootDer = await pki.x509.sign({
    serialNumber: 1n, subject: "Shield Path Root", subjectPublicKey: rootKey.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: rootKey.key });
  var anchor = pki.path.anchorFromCert(rootDer);
  var leafKey = makeSigner("ed25519");
  var leaf = await pki.x509.sign({
    serialNumber: 42n, subject: "leaf.shield.example", subjectPublicKey: leafKey.spki, notBefore: NB, notAfter: NA,
  }, { key: rootKey.key, cert: rootDer });
  await survives("pki.path.validate", pki.path.validate([leaf], { time: at, trustAnchors: anchor }), "valid", true);
  await survives("pki.path.build", pki.path.build(leaf, { time: at, trustAnchors: [anchor] }), "valid", true);

  // The per-certificate results and the per-check rows inside them are appended from some thirty
  // places, two of them after the result itself is recorded, so the rows are asserted as well as
  // the verdict that carries them.
  var v = await pki.path.validate([leaf], { time: at, trustAnchors: anchor });
  check("pki.path.validate reports a result per certificate with checks on it",
    v.results.length === 1 && v.results[0].checks.length > 0);
  for (var r = 0; r < v.results.length; r++) {
    ownsThen("pki.path.validate results[" + r + "]", v.results[r]);
    for (var c = 0; c < v.results[r].checks.length; c++) {
      ownsThen("pki.path.validate results[" + r + "].checks[" + c + "]", v.results[r].checks[c]);
    }
  }
}

async function testTlog() {
  var s = makeSigner("ed25519");
  var raw = pki.asn1.read.bitString(pki.asn1.decode(s.spki).children[1]).bytes;
  var name = "shield.example/log";
  var text = name + "\n5\n" + Buffer.alloc(32, 0x11).toString("base64") + "\n";
  var sig = crypto.sign(null, Buffer.from(text, "utf8"), s.keyObject);
  var note = text + "\n" + String.fromCharCode(0x2014) + " " + name + " " +
    Buffer.concat([pki.tlog.keyId(name, raw), sig]).toString("base64") + "\n";
  var keys = [{ name: name, publicKey: raw }];
  await survives("pki.tlog.verifyNote", pki.tlog.verifyNote(note, keys), "verified", true);
  await survives("pki.tlog.verifyCheckpoint", pki.tlog.verifyCheckpoint(note, keys), "verified", true);
}

// A verb that answers synchronously is held to the same rule: a caller awaiting its result crosses
// the resolution, and which verbs are asynchronous is not something a caller has to track.
function testSyncResults() {
  // CONTROL: an object literal of the same shape does NOT own `then`, so the assertions below
  // discriminate the guard's work from the shape of the value.
  check("CONTROL a bare object of the same shape owns no then",
    !hasOwn.call({ status: "valid", contentType: "" }, "then"));
  ownsThen("pki.est.classifyResponse", pki.est.classifyResponse(200, {}, Buffer.alloc(0)));
  ownsThen("pki.jose.parseJson", pki.jose.parseJson("{\"status\":\"valid\"}"));
}

async function testAttrcert() {
  var aa = makeSigner("ed25519");
  var ac = await pki.attrcert.sign({
    holder: { entityName: { directoryName: "Shield Holder" } },
    notBeforeTime: new Date("2026-01-01T00:00:00Z"),
    notAfterTime: new Date("2027-01-01T00:00:00Z"),
    attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:shield" } } },
  }, { name: "Shield AA", publicKey: aa.spki, key: aa.key });
  await survives("pki.attrcert.verify",
    pki.attrcert.verify(ac, { name: "Shield AA", publicKey: aa.spki },
      { time: new Date("2026-06-01T00:00:00Z"), revocationStatus: "notRevoked" }),
    "valid", true);
}

async function testCmp() {
  var s = makeSigner("ed25519");
  var csr = await pki.csr.sign({ subject: [{ commonName: "shield" }], subjectPublicKey: s.spki }, { key: s.key });
  var msg = await pki.cmp.build({
    header: { sender: { directoryName: [{ commonName: "Test Signer" }] }, recipient: { directoryName: "Shield CA" },
      transactionID: Buffer.alloc(16, 1), senderNonce: Buffer.alloc(16, 2) },
    body: { p10cr: csr },
  }, { key: s.key, cert: s.cert });
  await survives("pki.cmp.verify", pki.cmp.verify(msg, { signerCert: s.cert }), "valid", true);
}

/* The mask has to be invisible to the toolkit's OWN option door. `pki.jose.parseJson` returns a
   shielded object, so a caller who parses a configuration document with it and passes the result as an
   options bag was told `then` was an unknown option, while the identical document through `JSON.parse`
   was accepted: the toolkit refusing its own output. A name holding `undefined` answers nothing to a
   reader either way, so the door passes over the mask and counts everything else. */
async function testOptionDoor() {
  async function doorCode(opts) {
    try { await pki.jose.verify("not.a.jws", opts); return "NO-THROW"; }
    catch (e) { return e.code || "?"; }
  }
  var document = '{"profile":"acme-outer"}';
  var shielded = await doorCode(pki.jose.parseJson(document));
  var plain = await doorCode(JSON.parse(document));
  check("a shielded parse result is accepted as an options bag, as the same document through " +
    "JSON.parse is (" + shielded + " / " + plain + ")",
  shielded === plain && shielded === "jose/bad-jws");
  /* CONTROLS: the door still reports every name that carries a value, including a `then` that does,
     in either visibility, and still reports an option it does not know. */
  var carriesThen = { profile: "acme-outer" };
  carriesThen.then = 42;
  var hiddenThen = { profile: "acme-outer" };
  Object.defineProperty(hiddenThen, "then", {
    value: 7, enumerable: false, configurable: true, writable: true,
  });
  check("CONTROL an own then that carries a value is still reported, visible or not",
    await doorCode(carriesThen) === "jose/bad-input" && await doorCode(hiddenThen) === "jose/bad-input");
  check("CONTROL an option the verb does not know is still reported",
    await doorCode({ nope: 1 }) === "jose/bad-input");
  /* And a parsed document that really carries `then` keeps it, which is the member the mask must not
     overwrite. */
  var kept = pki.jose.parseJson('{"then":42,"other":1}');
  check("CONTROL a parsed document carrying its own then keeps it",
    kept.then === 42 && kept.other === 1);
  /* The other half of the same question: a verb that COPIES a caller's options into a null-prototype
     object must not copy the mask in. That copy has no inherited `then` for a mask to stand in front
     of, and copying one made a hidden name holding `undefined` into a visible option the next door
     reports as unknown. */
  var guard = require("../../lib/guard-all.js");
  var copied = guard.identifier.ownOptions(pki.jose.parseJson('{"profile":"acme-outer"}'));
  check("a copy of a shielded object's own options does not carry the mask (" +
    JSON.stringify(Object.keys(copied)) + ")",
  Object.keys(copied).length === 1 && copied.profile === "acme-outer");
  check("CONTROL but a then that carries a value is copied",
    guard.identifier.ownOptions(kept).then === 42);
  /* Every door that enumerates names, not only the one a verb happened to be named in. A verb that
     builds its list of named forms from the options it was handed would otherwise find one more form
     than the caller carries. */
  check("the mask is invisible to the name list a verb builds its forms from (" +
    JSON.stringify(guard.identifier.optionNames(pki.jose.parseJson('{"profile":"x"}'))) + ")",
  guard.identifier.optionNames(pki.jose.parseJson('{"profile":"x"}')).length === 1 &&
    guard.identifier.optionNames(kept).indexOf("then") !== -1);
  /* And the exemption is for a DATA property. A descriptor carrying no `value` key is an accessor, and
     `{get: undefined, set: undefined}` is one whose reads answer `undefined`, which a test for the
     absence of a getter alone took for data. An accessor answers each read separately, which is the
     whole reason the shield replaces one rather than reading it. */
  var accessorThen = {};
  Object.defineProperty(accessorThen, "then", { get: undefined, set: undefined });
  check("an accessor then whose get and set are both undefined is still reported (" +
    JSON.stringify(guard.identifier.optionNames(accessorThen)) + ")",
  guard.identifier.optionNames(accessorThen).indexOf("then") !== -1 &&
    Object.keys(guard.identifier.ownOptions(accessorThen)).indexOf("then") !== -1 &&
    await doorCode(accessorThen) === "jose/bad-input");
  /* Forging the mask's exact shape on an object the toolkit never shielded conveys nothing, which is
     why the exemption tests the shape rather than where the object came from: the name it hides holds
     no value, so a reader that asks for it gets `undefined` either way. */
  var forged = { profile: "acme-outer" };
  Object.defineProperty(forged, "then", {
    value: undefined, enumerable: false, configurable: false, writable: false,
  });
  check("a forged mask hides a name that answers undefined, which is what its absence answers",
    await doorCode(forged) === "jose/bad-jws" && forged.then === undefined);
  /* The exemption is about a name NOTHING ASKED FOR. A caller that recognizes the name means it as
     content, so where a list of accepted names is supplied and carries it, the mask shape no longer
     stands aside. `option-named-then` in codebase-patterns keeps any verb from declaring such an
     option, so this is the boundary rather than a live case. */
  var masked = pki.jose.parseJson('{"profile":"x"}');
  check("a name an accepted-name list carries is not hidden by the mask shape (" +
    JSON.stringify(guard.identifier.optionNames(masked, { then: 1, profile: 1 })) + ")",
  guard.identifier.optionNames(masked).length === 1 &&
    guard.identifier.optionNames(masked, { then: 1, profile: 1 }).length === 2);
  /* And a descriptor only means what it says when a real object answers for it. A Proxy reports
     whatever its trap returns, so one reporting the mask's shape for a `then` that reads a value would
     have the name hidden and the value live. */
  var lying = new Proxy({}, {
    ownKeys: function () { return ["then"]; },
    getOwnPropertyDescriptor: function () {
      return { value: undefined, enumerable: false, configurable: true, writable: true };
    },
    get: function (_t, k) { return k === "then" ? 42 : undefined; },
    has: function () { return true; },
  });
  check("a Proxy reporting the mask's shape for a name that reads a value is not exempted (" +
    JSON.stringify(guard.identifier.optionNames(lying)) + ", reads " + lying.then + ")",
  guard.identifier.optionNames(lying).indexOf("then") !== -1 &&
    Object.keys(guard.identifier.ownOptions(lying)).indexOf("then") !== -1);
}

async function run() {
  await testCsr();
  await testCrl();
  await testCms();
  await testCrmf();
  await testPkcs12();
  await testPath();
  await testAttrcert();
  await testCmp();
  await testTlog();
  await testOptionDoor();
  testSyncResults();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
