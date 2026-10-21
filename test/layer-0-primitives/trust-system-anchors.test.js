// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.trust.systemAnchors, the host's own trust store. RED conformance vectors written
 * BEFORE the implementation, each driving the SHIPPED verb and asserting the observable result:
 * the anchors, the `source` naming WHICH set was read, or the typed trust/* code.
 *
 * The whole point of the verb is that an operator can tell what they got. Node's compiled-in
 * Mozilla set is not the host store, and returning it under the same label as a host CA bundle
 * would tell an operator their enterprise root is trusted when it is not. So `source` is asserted
 * on every accepting vector, and the platform with no readable bundle refuses rather than falling
 * back.
 *
 *   S1-S4   a PEM bundle read from a path: anchors, count, source, path
 *   S5-S7   what a bundle may carry: a non-certificate block, an unparseable one, an empty file
 *   S8-S9   no readable bundle -> typed refusal naming the export command, never a silent fallback
 *   S10-S11 opts.allowNodeBundle -> source "node-bundled", count matches tls.rootCertificates
 *   S12     the anchors drive pki.path.validate with no mapping by hand
 *   S13-S14 the read is capped; the returned value is the caller's own
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var tls = require("tls");
var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

function code(fn) {
  try { fn(); return "NO-THROW"; }
  catch (e) { return e && e.code ? e.code : (e && e.name); }
}

var TMP = fs.mkdtempSync(path.join(os.tmpdir(), "pki-sysanchors-"));
function writeBundle(name, text) {
  var p = path.join(TMP, name);
  fs.writeFileSync(p, text);
  return p;
}

async function run() {
  var kp = await pki.key.generate("Ed25519");
  var priv = await pki.key.export(kp.privateKey);
  var pub = await pki.key.export(kp.publicKey);
  var NB = new Date("2020-01-01Z"), NA = new Date("2040-01-01Z"), T = new Date("2025-01-01Z");

  var rootA = await pki.x509.sign({
    subject: "Root A", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: priv });
  var rootB = await pki.x509.sign({
    subject: "Root B", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: priv });
  var pemA = pki.schema.x509.pemEncode(rootA, "CERTIFICATE");
  var pemB = pki.schema.x509.pemEncode(rootB, "CERTIFICATE");

  // ---- S1-S4: a bundle read from an explicit path -----------------------------------------
  var twoRoots = writeBundle("two-roots.pem", pemA + pemB);
  var res = pki.trust.systemAnchors({ path: twoRoots });
  check("S1. a PEM bundle yields one anchor per certificate block", res.anchors.length === 2);
  check("S2. each anchor carries the tuple pki.path.validate consumes",
    res.anchors.every(function (a) {
      return a.name && a.publicKey && typeof a.algorithm === "string";
    }));
  check("S3. source names the bundle, not Node's set", res.source === "ca-bundle");
  check("S4. and the path read is reported", res.path === twoRoots);

  // ---- S5-S7: what a bundle may carry ------------------------------------------------------
  // A CA bundle is an operator-maintained file and picks up other block types. A key or a CRL is
  // not an anchor, and silently skipping it would hide a file the operator has mis-assembled.
  var withKey = writeBundle("with-key.pem", pemA + pki.schema.pkcs8.pemEncode(priv, "PRIVATE KEY"));
  var mixed = pki.trust.systemAnchors({ path: withKey });
  check("S5. a non-certificate PEM block is reported rather than silently skipped",
    mixed.anchors.length === 1 && mixed.skipped.length === 1 &&
    mixed.skipped[0].label === "PRIVATE KEY" &&
    String(mixed.skipped[0].reason).indexOf("/") > 0);

  // OpenSSL's TRUSTED CERTIFICATE is a Certificate plus an X509_CERT_AUX naming the purposes the
  // operator trusted it FOR. Reading the certificate and dropping the aux would turn a root
  // restricted to serverAuth into an unrestricted anchor, so it is reported with the conversion
  // to run. The bytes are the shape `openssl x509 -addtrust serverAuth -trustout` writes.
  var auxDer = Buffer.concat([rootA, pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("serverAuth"))]),
  ])]);
  var trusted = writeBundle("trusted.pem",
    "-----BEGIN TRUSTED CERTIFICATE-----\n" +
    auxDer.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n?$/, "\n") +
    "-----END TRUSTED CERTIFICATE-----\n" + pemB);
  var withAux = pki.trust.systemAnchors({ path: trusted });
  check("S5b. an OpenSSL trusted certificate is reported, never ingested without its purposes",
    withAux.anchors.length === 1 && withAux.skipped.length === 1 &&
    withAux.skipped[0].label === "TRUSTED CERTIFICATE" &&
    String(withAux.skipped[0].reason).indexOf("aux-not-read") !== -1);

  // A host CA bundle is distribution-managed, and real ones carry certificates this toolkit
  // refuses (see S11b). Refusing the whole file would leave the operator with no anchors over one
  // root they do not control, so the entry is reported with its reason and the rest still parse.
  var broken = writeBundle("broken.pem",
    pemA + "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n" + pemB);
  var partial = pki.trust.systemAnchors({ path: broken });
  check("S6. a certificate block that does not parse is reported with its reason, not dropped",
    partial.anchors.length === 2 && partial.skipped.length === 1 &&
    typeof partial.skipped[0].reason === "string" && partial.skipped[0].reason.indexOf("/") > 0);

  var empty = writeBundle("empty.pem", "");
  check("S7. a bundle carrying no certificate refuses rather than returning nothing",
    code(function () { pki.trust.systemAnchors({ path: empty }); }) === "trust/no-anchors");

  // ---- S8-S9: no readable bundle -----------------------------------------------------------
  var missing = path.join(TMP, "does-not-exist.pem");
  check("S8. a path that cannot be read refuses with a typed code",
    code(function () { pki.trust.systemAnchors({ path: missing }); }) === "trust/no-readable-store");
  var refusal = "";
  try { pki.trust.systemAnchors({ path: missing }); }
  catch (e) { refusal = String(e.message); }
  check("S9. ...and the refusal names what to run instead of silently using Node's set",
    refusal.indexOf("allowNodeBundle") !== -1 || refusal.indexOf("export") !== -1);

  // ---- S10-S11: Node's bundled set, labeled as itself ---------------------------------------
  var bundled = pki.trust.systemAnchors({ path: missing, allowNodeBundle: true });
  check("S10. opts.allowNodeBundle names the set it actually returned",
    bundled.source === "node-bundled" && bundled.path === null);
  check("S11. ...and accounts for every certificate Node carries, as an anchor or a skip",
    bundled.anchors.length + bundled.skipped.length === tls.rootCertificates.length);

  // Measured, not assumed: the Mozilla set Node ships carries "Certum Trusted Network CA 2",
  // whose validity dates are both before 2050 and both encoded as GeneralizedTime, against the
  // RFC 5280 sec. 4.1.2.5 MUST that such dates be UTCTime. A strict reader cannot ingest it, and
  // weakening the reader to admit it would weaken every other caller, so it is reported. This
  // vector is what says the reporting path is exercised by a REAL store rather than only by a
  // fixture, and it fails loudly if Node's bundle changes.
  check("S11b. a non-conforming root in Node's own set is reported rather than refusing the set",
    bundled.skipped.length >= 1 &&
    bundled.skipped.every(function (s) { return typeof s.reason === "string" && s.reason.length > 0; }));

  // ---- S12: the anchors are the ones path.validate takes -----------------------------------
  var leaf = await pki.x509.sign({
    subject: "leaf.example", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: false } },
  }, { cert: rootA, key: priv });
  var one = writeBundle("one-root.pem", pemA);
  var verdict = await pki.path.validate([leaf],
    { trustAnchors: pki.trust.systemAnchors({ path: one }).anchors, time: T });
  check("S12. the anchors drive pki.path.validate with no mapping by hand", verdict.valid === true);

  // ---- S15-S19: what discovery and the cap must not do -------------------------------------
  // macOS keeps its trust decisions in Keychain, and /etc/ssl/cert.pem exists there as OpenSSL's
  // own copy. Returning that file as "the host's anchors" is the misattribution this verb exists
  // to prevent, so automatic discovery runs only where the bundle IS the host's trust.
  check("S15. automatic discovery is gated by platform, not by a path existing",
    pki.trust.discoversBundles(process.platform) === (process.platform !== "darwin" && process.platform !== "win32"));
  check("S15b. ...and darwin is excluded even though /etc/ssl/cert.pem can exist there",
    pki.trust.discoversBundles("darwin") === false && pki.trust.discoversBundles("linux") === true);

  // The cap is a bound on what gets ALLOCATED, not a check after the fact: a file far above it
  // must not be read into memory first.
  var big = writeBundle("big.pem", pemA + pemB + "x".repeat(200000));
  check("S16. a bundle above the cap refuses without reading the whole file",
    code(function () { pki.trust.systemAnchors({ path: big, maxBytes: 64 }); }) === "trust/too-large");

  // A resource refusal must not silently hand back a DIFFERENT trust set. The caller asked about
  // this file; that it is too large is a fault about this file, not a reason to validate against
  // Node's roots instead.
  check("S17. opts.allowNodeBundle does not turn a too-large bundle into Node's set",
    code(function () { pki.trust.systemAnchors({ path: big, maxBytes: 64, allowNodeBundle: true }); })
      === "trust/too-large");

  // An indented boundary is not a PEM block under RFC 7468 sec. 2, so the decoder passes over it
  // as text. In a TRUST bundle that is a missing anchor with nothing said, which is the one thing
  // this verb promises not to do.
  var indented = writeBundle("indented.pem",
    pemA + pemB.split("\n").map(function (l) { return l ? " " + l : l; }).join("\n"));
  var ind = pki.trust.systemAnchors({ path: indented });
  check("S18. a boundary the decoder cannot use is reported, not passed over in silence",
    ind.anchors.length === 1 && ind.skipped.length === 1 &&
    String(ind.skipped[0].reason).indexOf("boundary") !== -1);

  // readSync may return fewer bytes than asked for. Taking one call's prefix as the whole file
  // drops the roots below the break with nothing reported, which is the silent short list this
  // verb exists to prevent. Driven by making readSync answer one byte at a time.
  var realRead = fs.readSync;
  var manyRoots = writeBundle("many.pem", pemA + pemB + pemA);
  var full = pki.trust.systemAnchors({ path: manyRoots }).anchors.length;
  fs.readSync = function (fd, buf, off, len, pos) { return realRead(fd, buf, off, len > 1 ? 1 : len, pos); };
  var underShortReads;
  try { underShortReads = pki.trust.systemAnchors({ path: manyRoots }).anchors.length; }
  finally { fs.readSync = realRead; }
  check("S19. a short read does not truncate the bundle (" + underShortReads + " of " + full + ")",
    underShortReads === full && full === 3);

  // ---- S13-S14: bounds and ownership -------------------------------------------------------
  check("S13. a bundle above the cap refuses rather than allocating",
    code(function () { pki.trust.systemAnchors({ path: twoRoots, maxBytes: 8 }); }) === "trust/too-large");
  var first = pki.trust.systemAnchors({ path: twoRoots });
  first.anchors.length = 0;
  check("S14. a second call does not hand back the first call's emptied array",
    pki.trust.systemAnchors({ path: twoRoots }).anchors.length === 2);

  // ---- S20-S23: a certificate that is not self-issued is not an anchor ---------------------
  // A Windows store export carries the Intermediate Certification Authorities store as well as
  // the roots, and that store is a cache of certificates the machine has seen. OpenSSL's default
  // verification needs a self-issued certificate at the top of a chain, so an intermediate there
  // helps build a chain and never ends one. Read as an anchor, it would be trusted on its own and
  // never revocation-checked.
  var ikp = await pki.key.generate("Ed25519");
  var ipriv = await pki.key.export(ikp.privateKey);
  var ipub = await pki.key.export(ikp.publicKey);
  var inter = await pki.x509.sign({
    subject: "Cached Intermediate", subjectPublicKey: ipub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { cert: rootA, key: priv });
  var underInter = await pki.x509.sign({
    subject: "leaf-under-cache.example", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: false } },
  }, { cert: inter, key: ipriv });
  var exported = writeBundle("exported-store.pem", pemA + pki.schema.x509.pemEncode(inter, "CERTIFICATE") + pemB);
  var exp = pki.trust.systemAnchors({ path: exported });
  check("S20. a certificate that is not self-issued is not returned as an anchor",
    exp.anchors.length === 2 && exp.anchors.every(function (a) { return a.name.dn !== "CN=Cached Intermediate"; }));
  check("S20b. ...it is reported in skipped with its reason",
    exp.skipped.length === 1 && exp.skipped[0].label === "CERTIFICATE" &&
    String(exp.skipped[0].reason).indexOf("trust/not-self-issued") === 0);
  check("S20c. ...and returned in intermediates, as DER, for chain building",
    Array.isArray(exp.intermediates) && exp.intermediates.length === 1 &&
    Buffer.isBuffer(exp.intermediates[0]) && exp.intermediates[0].equals(inter));
  var alone = await pki.path.validate([underInter], { trustAnchors: exp.anchors, time: T })
    .then(function (r) { return r.valid; }, function (e) { return e.code; });
  check("S21. a leaf under the cached intermediate does not validate against the anchors alone", alone !== true);
  var built = await pki.path.build(underInter, { trustAnchors: exp.anchors, candidates: exp.intermediates, time: T });
  check("S21b. ...and validates to the root when the intermediates are candidates", built.valid === true);
  var noInter = pki.trust.systemAnchors({ path: twoRoots });
  check("S21c. a bundle of roots reports an empty intermediates list", Array.isArray(noInter.intermediates) && noInter.intermediates.length === 0);

  // An operator excludes a root, or an intermediate, by the digest of its key.
  var dkp = await pki.key.generate("Ed25519");
  var dpub = await pki.key.export(dkp.publicKey);
  var dpriv = await pki.key.export(dkp.privateKey);
  var rootD = await pki.x509.sign({
    subject: "Root D", subjectPublicKey: dpub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: dpriv });
  var withD = writeBundle("with-d.pem", pemA + pki.schema.x509.pemEncode(rootD, "CERTIFICATE") +
    pki.schema.x509.pemEncode(inter, "CERTIFICATE"));
  var filtered = pki.trust.systemAnchors({ path: withD, distrustedKeys: [pki.trust.spkiDigest(rootD)] });
  check("S22. opts.distrustedKeys keeps a listed root out of the anchors",
    filtered.anchors.length === 1 && filtered.anchors[0].name.dn === "CN=Root A");
  check("S22b. ...and reports it as distrusted",
    filtered.skipped.some(function (s) { return String(s.reason).indexOf("trust/distrusted-key") === 0; }));
  var filteredInter = pki.trust.systemAnchors({ path: withD, distrustedKeys: [pki.trust.spkiDigest(inter)] });
  check("S22c. a listed intermediate is neither an anchor nor a chain-building candidate",
    filteredInter.intermediates.length === 0 && filteredInter.anchors.length === 2 &&
    filteredInter.skipped.some(function (s) { return String(s.reason).indexOf("trust/distrusted-key") === 0; }));
  var nodeAll = pki.trust.systemAnchors({ path: missing, allowNodeBundle: true });
  var nodeFiltered = pki.trust.systemAnchors({ path: missing, allowNodeBundle: true,
    distrustedKeys: [pki.trust.spkiDigest(tls.rootCertificates[0])] });
  check("S22d. the list applies to Node's set as well",
    nodeFiltered.anchors.length === nodeAll.anchors.length - 1 &&
    nodeFiltered.anchors.length + nodeFiltered.skipped.length === tls.rootCertificates.length);
  check("S23. a malformed distrustedKeys is trust/bad-input",
    code(function () { pki.trust.systemAnchors({ path: twoRoots, distrustedKeys: ["nope"] }); }) === "trust/bad-input");
  check("S23b. distrustedKeys: null reads as omitted",
    pki.trust.systemAnchors({ path: twoRoots, distrustedKeys: null }).anchors.length === 2);
  check("S23c. a list that removes every anchor refuses rather than returning none",
    code(function () { pki.trust.systemAnchors({ path: one, distrustedKeys: [pki.trust.spkiDigest(rootA)] }); }) === "trust/no-anchors");

  // A certificate whose name carries a control byte cannot be compared under RFC 5280 sec. 7.1, so
  // it is reported and is neither an anchor nor an intermediate. The byte is patched into the
  // encoded name after signing; systemAnchors reads names, not signatures.
  var ctl = Buffer.from(await pki.x509.sign({
    subject: "CtlMarker", subjectPublicKey: ipub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { cert: rootA, key: priv }));
  var at = ctl.indexOf(Buffer.from("CtlMarker", "latin1"));
  ctl[at + 3] = 0x01;
  var withCtl = pki.trust.systemAnchors({ path: writeBundle("with-ctl.pem", pemA + pki.schema.x509.pemEncode(ctl, "CERTIFICATE")) });
  check("S25. a certificate whose name cannot be compared is reported and offered as neither an anchor nor an intermediate",
    at > 0 && withCtl.anchors.length === 1 && withCtl.intermediates.length === 0 && withCtl.skipped.length === 1 &&
    String(withCtl.skipped[0].reason).indexOf("trust/bad-input") === 0 &&
    String(withCtl.skipped[0].reason).indexOf("control byte") !== -1);

  // ---- S24: allowNodeBundle is a boolean, and nothing else reads as one ---------------------
  check("S24. allowNodeBundle: \"true\" is refused rather than read as off",
    code(function () { pki.trust.systemAnchors({ path: missing, allowNodeBundle: "true" }); }) === "trust/bad-input");
  check("S24b. allowNodeBundle: 1 is refused",
    code(function () { pki.trust.systemAnchors({ path: missing, allowNodeBundle: 1 }); }) === "trust/bad-input");
  check("S24c. allowNodeBundle: null reads as omitted",
    code(function () { pki.trust.systemAnchors({ path: missing, allowNodeBundle: null }); }) === "trust/no-readable-store");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
