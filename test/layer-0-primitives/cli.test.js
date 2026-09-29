// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — the `pki` CLI (bin/pki.js). Spawns the SHIPPED command an operator
 * runs, so a public-API rename that leaves the CLI calling a removed export is
 * caught here (it crashed silently past the library tests once — the CLI still
 * called pki.x509.parse after that export moved to pki.schema.x509). Covers the
 * version / oid / parse core plus the inspect / lint / convert / verify commands
 * that compose pki.inspect, pki.lint, the PEM codecs, and pki.path.validate.
 */

var helpers = require("../helpers");
var check = helpers.check;
var path = require("path");
var fs = require("fs");
var os = require("os");
var spawnSync = require("child_process").spawnSync;
var pki = require("../../index.js");
var asn1 = require("../../lib/asn1-der");

var BIN = path.join(__dirname, "..", "..", "bin", "pki.js");
var FIXTURE = path.join(__dirname, "..", "fixtures", "pkijs-selfsigned-ec.pem");

function cli(args) {
  var r = spawnSync(process.execPath, [BIN].concat(args), { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}
function cliBuf(args) {
  var r = spawnSync(process.execPath, [BIN].concat(args), { encoding: null });
  return { status: r.status, stdout: r.stdout || Buffer.alloc(0) };
}

// A certificate derived from the fixture with its serialNumber swapped to a negative
// INTEGER -- a cert that lints with a `serial-not-positive` error (exit code 1).
function writeBadSerialCert(dir) {
  var der = pki.schema.x509.pemDecode(fs.readFileSync(FIXTURE, "utf8"), "CERTIFICATE");
  var cert = asn1.decode(der);
  var kids = cert.children[0].children.map(function (c) { return c.bytes; });
  kids[1] = asn1.build.integer(-1n);
  var bad = asn1.build.sequence([asn1.build.sequence(kids), cert.children[1].bytes, cert.children[2].bytes]);
  var p = path.join(dir, "bad-serial.der");
  fs.writeFileSync(p, bad);
  return p;
}

async function run() {
  var pkg = require("../../package.json");
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pki-cli-"));
  try {
    var v = cli(["version"]);
    check("pki version exits 0", v.status === 0);
    check("pki version prints the package version", v.stdout.indexOf(pkg.version) !== -1);

    var o = cli(["oid", "2.5.4.3"]);
    check("pki oid resolves a dotted OID to its name", o.status === 0 && /commonName/.test(o.stdout));

    var p = cli(["parse", FIXTURE]);
    check("pki parse exits 0 on a valid certificate", p.status === 0);
    check("pki parse emits parseable JSON with the cert fields", (function () {
      var j = JSON.parse(p.stdout);
      return j.version === 3 && typeof j.serialNumber === "string" && j.serialNumber.length > 0;
    })());

    var bad = cli(["parse", "/no/such/path/nope.pem"]);
    check("pki parse fails cleanly on a missing file (non-zero exit)", bad.status !== 0);

    var unknown = cli(["frobnicate"]);
    check("pki rejects an unknown command (non-zero exit)", unknown.status !== 0);

    // ---- inspect ----
    var ins = cli(["inspect", FIXTURE]);
    check("pki inspect renders a certificate as text", ins.status === 0 && /Certificate:/.test(ins.stdout) && /Signature Algorithm/.test(ins.stdout));
    // A non-certificate DER (a bare INTEGER) is not renderable -> non-zero.
    var notCert = path.join(tmp, "int.der");
    fs.writeFileSync(notCert, asn1.build.integer(5n));
    check("pki inspect fails on a non-certificate (non-zero exit)", cli(["inspect", notCert]).status !== 0);

    // ---- lint ----
    var lintClean = cli(["lint", FIXTURE]);
    check("pki lint exits 0 on a clean certificate", lintClean.status === 0);
    var lintJson = cli(["lint", FIXTURE, "--json"]);
    check("pki lint --json emits a parseable LintReport", (function () {
      var j = JSON.parse(lintJson.stdout);
      return Array.isArray(j.findings) && j.counts && typeof j.counts.error === "number";
    })());
    var badCert = writeBadSerialCert(tmp);
    var lintBad = cli(["lint", badCert]);
    check("pki lint exits non-zero and names the finding on an error certificate",
      lintBad.status === 1 && /serial-not-positive/.test(lintBad.stdout));
    var lintProf = cli(["lint", FIXTURE, "--profile", "does-not-exist"]);
    check("pki lint rejects an unknown profile (config error, non-zero exit)",
      lintProf.status !== 0 && /unknown-profile/.test(lintProf.stderr));
    // The linter's never-throw survey is preserved at the CLI: garbage bytes become a fatal
    // lint/unparseable finding (stable JSON), not a CLI hard-fail before the report.
    var garbage = path.join(tmp, "garbage.bin");
    fs.writeFileSync(garbage, Buffer.from([0xff, 0xff, 0x99, 0x01, 0x02]));
    var lintGarbage = cli(["lint", garbage, "--json"]);
    check("pki lint reports malformed input as a fatal finding, not a CLI error", (function () {
      var j = JSON.parse(lintGarbage.stdout);
      return lintGarbage.status === 1 && j.worst === "fatal" && j.findings[0].id === "lint/unparseable";
    })());
    // The command detects which structure the file holds and runs the matching profile: a CRL and
    // an OCSP response lint through their own verbs, as DER or as PEM, and a structure no profile
    // exists for is refused by name rather than linted as a certificate.
    var b = asn1.build, O = function (n) { return pki.oid.byName(n); };
    var ALG = b.sequence([b.oid(O("ecdsaWithSHA256"))]), SIG = b.bitString(Buffer.alloc(8, 1), 0);
    var DN = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8("CLI CA")])])]);
    var crlDer = b.sequence([b.sequence([b.integer(1n), ALG, DN, b.utcTime(new Date("2026-01-01T00:00:00Z")), b.utcTime(new Date("2026-02-01T00:00:00Z")),
      b.explicit(0, b.sequence([b.sequence([b.oid(O("cRLNumber")), b.octetString(b.integer(1n))])]))]), ALG, SIG]);
    var crlPath = path.join(tmp, "list.crl"), crlPemPath = path.join(tmp, "list.crl.pem");
    fs.writeFileSync(crlPath, crlDer);
    fs.writeFileSync(crlPemPath, pki.schema.crl.pemEncode(crlDer));
    var lintCrl = cli(["lint", crlPath, "--json"]);
    check("pki lint detects a CRL and runs the CRL profile (the missing AKI is its error)", (function () {
      var j = JSON.parse(lintCrl.stdout);
      return lintCrl.status === 1 && j.findings.some(function (f) { return f.id === "lint/rfc5280-crl/aki-missing"; });
    })());
    check("pki lint lints a PEM CRL the same as the DER", JSON.parse(cli(["lint", crlPemPath, "--json"]).stdout).findings.length === JSON.parse(lintCrl.stdout).findings.length);
    var gt = function (s) { return b.generalizedTime(new Date(s)); };
    var certId = b.sequence([b.sequence([b.oid(O("sha256")), b.nullValue()]), b.octetString(Buffer.alloc(32, 3)), b.octetString(Buffer.alloc(32, 4)), b.integer(1n)]);
    var single = b.sequence([certId, b.contextPrimitive(0, Buffer.alloc(0)), gt("2027-01-01T00:00:00Z"), b.explicit(0, gt("2028-01-01T00:00:00Z"))]);
    var rd = b.sequence([b.explicit(2, b.octetString(Buffer.alloc(20, 9))), gt("2027-01-01T00:00:00Z"), b.sequence([single])]);
    var ocspDer = b.sequence([b.enumerated(0n), b.explicit(0, b.sequence([b.oid(O("ocspBasic")), b.octetString(b.sequence([rd, ALG, SIG]))]))]);
    var ocspPath = path.join(tmp, "status.ors");
    fs.writeFileSync(ocspPath, ocspDer);
    var lintOcsp = cli(["lint", ocspPath, "--json"]);
    check("pki lint detects an OCSP response and runs the OCSP profile (clean, exit 0, the rfc6960 rows ran)", (function () {
      var j = JSON.parse(lintOcsp.stdout);
      return lintOcsp.status === 0 && j.findings.length === 0 && j.ran.some(function (id) { return id.indexOf("lint/rfc6960/") === 0; });
    })());
    var lintOcspLw = cli(["lint", ocspPath, "--profile", "rfc5019", "--json"]);
    check("pki lint --profile rfc5019 on an OCSP response runs the lightweight rows (byKey, one response: clean)", (function () {
      var j = JSON.parse(lintOcspLw.stdout);
      return lintOcspLw.status === 0 && j.ran.length === 4 && j.ran.every(function (id) { return id.indexOf("lint/rfc5019/") === 0; });
    })());
    check("pki lint with a CRL profile on a certificate is refused as a config error naming the verb",
      (function () { var r = cli(["lint", FIXTURE, "--profile", "rfc5280-crl"]); return r.status !== 0 && /unknown-profile/.test(r.stderr) && /CRL profile/.test(r.stderr); })());
    var csrDer = b.sequence([b.sequence([b.integer(0n), DN, b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]), b.bitString(Buffer.alloc(65, 4), 0)]), b.contextConstructed(0, Buffer.alloc(0))]), ALG, SIG]);
    var csrPath = path.join(tmp, "req.csr");
    fs.writeFileSync(csrPath, csrDer);
    check("pki lint lints a PKCS#10 request, which the library has a verb for",
      (function () { var r = cli(["lint", csrPath]); return /finding\(s\)/.test(r.stdout); })());
    /* A structure the detector NAMES but no lint verb covers is refused by that name rather than
     * linted as something else. A PKCS#8 key is the case: pki.lint ships no key profile, and the
     * refusal names the structures it does cover so the reader learns the set from the failure. */
    var keyOnlyPath = path.join(tmp, "key-only.der");
    fs.writeFileSync(keyOnlyPath, await pki.key.export((await pki.key.generate("Ed25519")).privateKey));
    check("pki lint refuses a structure no verb covers, naming what it found and what it covers",
      (function () {
        var r = cli(["lint", keyOnlyPath]);
        return r.status !== 0 && /pkcs8/.test(r.stderr) && /pki lint covers/.test(r.stderr) &&
          /x509/.test(r.stderr) && /attrcert/.test(r.stderr);
      })());

    // ---- convert ----
    var toDer = cliBuf(["convert", FIXTURE, "--to", "der"]);
    check("pki convert --to der emits raw DER (SEQUENCE tag)", toDer.status === 0 && toDer.stdout[0] === 0x30);
    var derPath = path.join(tmp, "c.der");
    fs.writeFileSync(derPath, toDer.stdout);
    var toPem = cli(["convert", derPath, "--to", "pem"]);
    check("pki convert --to pem wraps DER in a PEM CERTIFICATE armor", toPem.status === 0 && /-----BEGIN CERTIFICATE-----/.test(toPem.stdout));
    // Round-trip: DER -> PEM -> DER reproduces the exact bytes.
    var pemPath = path.join(tmp, "c.pem");
    fs.writeFileSync(pemPath, toPem.stdout);
    var back = cliBuf(["convert", pemPath, "--to", "der"]);
    check("pki convert round-trips DER->PEM->DER byte-identically", Buffer.compare(back.stdout, toDer.stdout) === 0);
    check("pki convert honors an explicit --label", /-----BEGIN X509 CRL-----/.test(cli(["convert", derPath, "--to", "pem", "--label", "X509 CRL"]).stdout));
    check("pki convert rejects an unknown --to target (non-zero exit)", cli(["convert", FIXTURE, "--to", "xml"]).status !== 0);
    // A raw DER value whose CONTENT contains the ASCII PEM marker must be treated as DER,
    // not misdetected as PEM (armor detection is anchored at the file boundary).
    var markerDer = asn1.build.octetString(Buffer.from("-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----", "ascii"));
    var markerPath = path.join(tmp, "marker.der");
    fs.writeFileSync(markerPath, markerDer);
    var markerOut = cliBuf(["convert", markerPath, "--to", "der"]);
    check("pki convert treats DER containing the PEM marker as DER (boundary-anchored detection)",
      markerOut.status === 0 && Buffer.compare(markerOut.stdout, markerDer) === 0);
    // A DER value whose LEADING bytes are whitespace in latin1 (a UTF8String, tag 0x0c =
    // form-feed; length byte 0x20 = space) and whose content starts with the marker is still
    // DER -- DER-first detection decodes it rather than misreading it as malformed PEM.
    var wsLeadDer = asn1.build.utf8("-----BEGIN CERTIFICATE-----XXXXX");
    var wsPath = path.join(tmp, "wslead.der");
    fs.writeFileSync(wsPath, wsLeadDer);
    var wsOut = cliBuf(["convert", wsPath, "--to", "der"]);
    check("pki convert treats a whitespace-leading DER value as DER, not malformed PEM",
      wsOut.status === 0 && Buffer.compare(wsOut.stdout, wsLeadDer) === 0);
    // A PEM carrying a BOM / explanatory preamble before its armor is still recognized as PEM.
    var bomPem = path.join(tmp, "bom.pem");
    fs.writeFileSync(bomPem, String.fromCharCode(0xFEFF) + "explanatory preamble line\n" + fs.readFileSync(FIXTURE, "utf8"));
    check("pki convert recognizes a PEM with a BOM/preamble before the armor",
      cli(["convert", bomPem, "--to", "der"]).status === 0);
    // A PEM with a non-base64 body is rejected, not decoded loosely into garbage.
    var badPem = path.join(tmp, "bad.pem");
    fs.writeFileSync(badPem, "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n");
    check("pki convert rejects a PEM with a non-base64 body (non-zero exit)", cli(["convert", badPem, "--to", "der"]).status !== 0);
    // A body that is alphabet-valid but NON-CANONICAL (trailing pad bits set, e.g. "AB==")
    // is rejected too -- the CLI matches the library's fail-closed canonical PEM policy.
    var nonCanon = path.join(tmp, "noncanon.pem");
    fs.writeFileSync(nonCanon, "-----BEGIN CERTIFICATE-----\nAB==\n-----END CERTIFICATE-----\n");
    check("pki convert rejects non-canonical PEM base64 (non-zero exit)", cli(["convert", nonCanon, "--to", "der"]).status !== 0);
    // A form-feed in the PEM body is not library-ignored whitespace (only CR/LF/TAB/space
    // are), so convert must reject it -- it composes the PEM codecs, not a looser path.
    var ffPem = path.join(tmp, "ff.pem");
    fs.writeFileSync(ffPem, "-----BEGIN CERTIFICATE-----\nMIIB" + String.fromCharCode(12) + "AA==\n-----END CERTIFICATE-----\n");
    check("pki convert rejects a form-feed in the PEM body (non-zero exit)", cli(["convert", ffPem, "--to", "der"]).status !== 0);
    // A lowercase / invalid --label is rejected rather than emitted into an unparseable file.
    check("pki convert rejects a lowercase --label (non-zero exit)", cli(["convert", derPath, "--to", "pem", "--label", "certificate"]).status !== 0);

    // ---- verify ----
    var vOk = cli(["verify", FIXTURE, "--anchor", FIXTURE, "--time", "2030-01-01T00:00:00Z"]);
    check("pki verify accepts a self-signed cert as its own anchor within validity", vOk.status === 0 && /valid/.test(vOk.stdout));
    var vBad = cli(["verify", FIXTURE, "--anchor", FIXTURE, "--time", "1990-01-01T00:00:00Z"]);
    check("pki verify rejects a path outside the validity window (non-zero exit)", vBad.status === 1 && /invalid/.test(vBad.stdout));
    check("pki verify requires an --anchor (non-zero exit)", cli(["verify", FIXTURE]).status !== 0);
    // A value-taking flag with no value is a usage error, not a silent `true` (which would
    // make --time parse as new Date(true) = a real 1970 timestamp).
    check("pki rejects a value-taking flag with no value (non-zero exit)",
      cli(["verify", FIXTURE, "--time", "--anchor", FIXTURE]).status !== 0);

    // ---- sign (pki.cms.sign) ----
    var signer = require("../helpers/signing").makeSigner("ec-p256");
    var certPath = path.join(tmp, "signer-cert.pem");
    var keyPath = path.join(tmp, "signer-key.pem");
    var contentPath = path.join(tmp, "to-sign.txt");
    fs.writeFileSync(certPath, pki.schema.x509.pemEncode(signer.cert, "CERTIFICATE"));
    fs.writeFileSync(keyPath, signer.keyObject.export({ format: "pem", type: "pkcs8" }));
    fs.writeFileSync(contentPath, "content signed through the pki CLI");
    var signed = cliBuf(["sign", contentPath, "--cert", certPath, "--key", keyPath]);
    check("pki sign exits 0", signed.status === 0);
    var parsedSigned = pki.schema.cms.parse(signed.stdout);
    check("pki sign emits a single-signer SignedData embedding the content",
      parsedSigned.signerInfos.length === 1 && parsedSigned.encapContentInfo.eContent != null);
    // --pem emits a CMS PEM block; --detached omits the embedded content.
    var signedPem = cli(["sign", contentPath, "--cert", certPath, "--key", keyPath, "--pem", "--detached"]);
    check("pki sign --pem --detached emits a detached CMS PEM", signedPem.status === 0 &&
      signedPem.stdout.indexOf("-----BEGIN CMS-----") === 0 &&
      pki.schema.cms.parse(signedPem.stdout).encapContentInfo.eContent == null);
    check("pki sign without --key is a usage error (non-zero exit)", cli(["sign", contentPath, "--cert", certPath]).status !== 0);

    /* ---- --help reaches every verb ----
     * The first flag anyone tries. Four verbs printed a usage line when their arguments were
     * missing and three took a bare positional, so `pki oid --help` answered "unknown OID name"
     * and `pki parse --help` tried to open a file called --help. The set is derived from the
     * usage banner rather than written out here, so a verb added later is covered by this vector
     * without an edit. */
    var banner = cli([]).stdout;
    var verbs = (/usage: pki <([a-z|-]+)>/.exec(banner) || [])[1];
    check("the usage banner names the verb set this vector derives from", typeof verbs === "string");
    var verbList = String(verbs).split("|").filter(function (v) { return v !== "version"; });
    var helpGaps = [];
    verbList.forEach(function (verb) {
      var h = cli([verb, "--help"]);
      var text = h.stdout + h.stderr;
      if (text.indexOf("usage: pki " + verb) === -1) {
        helpGaps.push(verb + " -> " + JSON.stringify((text.split("\n")[0] || "").slice(0, 60)));
      }
    });
    check("pki <verb> --help prints that verb's usage line, for every verb (" + verbList.length +
      " verbs): " + helpGaps.join("; "), helpGaps.length === 0);
    var missingArgGaps = [];
    verbList.forEach(function (verb) {
      var m = cli([verb]);
      if (m.status === 0) missingArgGaps.push(verb + " exited 0 with no arguments");
    });
    check("pki <verb> with no arguments exits non-zero: " + missingArgGaps.join("; "),
      missingArgGaps.length === 0);

    /* ---- inspect reaches every format the library renders ----
     * `pki inspect` called pki.inspect.certificate, so the CLI could not open a CRL, a CSR or a
     * CMS message the library already rendered. Routing it through pki.inspect.any carries every
     * format the library detects, and the set is read from the library so a format added there
     * needs no edit here. */
    var inspectCsr = path.join(tmp, "req.der");
    var csrKeys = await pki.key.generate("Ed25519");
    fs.writeFileSync(inspectCsr, await pki.csr.sign(
      { subject: "cli.example", subjectPublicKey: await pki.key.export(csrKeys.publicKey) },
      { key: await pki.key.export(csrKeys.privateKey) }));
    var iCsr = cli(["inspect", inspectCsr]);
    check("pki inspect renders a PKCS#10 request, not only a certificate",
      iCsr.status === 0 && /Certificate Request/i.test(iCsr.stdout));
    var inspectCms = path.join(tmp, "signed.der");
    fs.writeFileSync(inspectCms, signed.stdout);
    var iCms = cli(["inspect", inspectCms]);
    check("pki inspect renders a CMS message", iCms.status === 0 && /SignerInfo|Content Type/i.test(iCms.stdout));
    var iDump = cli(["inspect", FIXTURE, "--asn1"]);
    check("pki inspect --asn1 dumps the TLV tree instead of the field report",
      iDump.status === 0 && /^ASN\.1 structure: \d+ bytes, decoded as DER$/m.test(iDump.stdout) &&
        /^ +0:d=0 +hl=4 l= 544 cons: SEQUENCE$/m.test(iDump.stdout));
    /* The library's rule is that a report reached by format detection names a key without printing
     * it, and the CLI inherits that only while inspect routes through `any`. A terminal's scrollback
     * is a copy, so this is the vector that keeps the CLI from becoming the way a key escapes. */
    var keyFile = path.join(tmp, "key-report.der");
    var keyPair = await pki.key.generate("Ed25519");
    var keyDer = await pki.key.export(keyPair.privateKey);
    fs.writeFileSync(keyFile, keyDer);
    var iKey = cli(["inspect", keyFile]);
    var keyInner = pki.asn1.decode(keyDer).children[2].content;
    check("pki inspect on a private key names it and prints none of its bytes",
      iKey.status === 0 && /Private Key: present/.test(iKey.stdout) &&
        iKey.stdout.indexOf(keyInner.toString("hex")) === -1 &&
        iKey.stdout.indexOf(keyInner.toString("base64")) === -1);

    /* ---- lint reaches every verb the library ships ----
     * The CLI's table named three structures while pki.lint ships seven verbs. The expectation is
     * derived from the library's own surface, so a lint verb added there fails this vector until
     * the CLI's table names it. */
    /* The artifact set is derived, not listed: pki.lint.rules(null, name) returns that artifact's
     * rule rows and refuses a name that is not an artifact, which separates the seven lint verbs
     * from the two introspection exports without naming either group here. */
    var libLintVerbs = Object.keys(pki.lint).filter(function (k) {
      try { return pki.lint.rules(null, k).length > 0; } catch (e) { return e.code !== "lint/bad-input" && false; }
    });
    check("the derived lint-verb set is the artifacts and not the introspection exports",
      libLintVerbs.length >= 7 && libLintVerbs.indexOf("rules") === -1 &&
        libLintVerbs.indexOf("profiles") === -1);
    var cliLintUsage = cli(["lint"]).stderr;
    var lintGaps = libLintVerbs.filter(function (v) { return cliLintUsage.indexOf(v) === -1; });
    check("pki lint's usage names every lint verb the library ships (" + libLintVerbs.length +
      " verbs): missing " + lintGaps.join(", "), lintGaps.length === 0);
    var lintCsr = cli(["lint", inspectCsr]);
    check("pki lint lints a PKCS#10 request rather than refusing it as an uncovered structure",
      lintCsr.stderr.indexOf("pki lint covers") === -1);
    var lintCms = cli(["lint", inspectCms]);
    check("pki lint lints a CMS message rather than refusing it as an uncovered structure",
      lintCms.stderr.indexOf("pki lint covers") === -1);

    /* ---- keygen: the first verb that puts a private key on disk ----
     * Each check below is one of the decisions an operator inherits from it, and each fails loudly
     * rather than being a sentence in a help string. */
    var kgOut = path.join(tmp, "kg.key");
    var kgPub = path.join(tmp, "kg.pub");
    var kg = cli(["keygen", "--out", kgOut, "--pub", kgPub]);
    check("pki keygen exits 0 and writes the key file it was given", kg.status === 0 && fs.existsSync(kgOut));
    check("pki keygen writes a PKCS#8 private key the library parses",
      (function () { var k = pki.schema.pkcs8.parse(fs.readFileSync(kgOut)); return k.privateKeyAlgorithm != null; })());
    check("pki keygen writes the public half to a separate file, as an SPKI the library parses",
      fs.existsSync(kgPub) && pki.schema.x509.decodeExtensions !== undefined &&
        (function () { var n = pki.asn1.decode(fs.readFileSync(kgPub)); return n.tagNumber === 16; })());
    /* A terminal's scrollback is a copy of whatever it printed, and so is the shell history of the
     * pipeline it ran in, so the private key is never on stdout unless it was asked for. */
    var kgKeyBytes = pki.asn1.decode(fs.readFileSync(kgOut)).children[2].content;
    check("pki keygen puts no byte of the private key on stdout",
      kgKeyBytes.length > 8 &&
        kg.stdout.indexOf(kgKeyBytes.toString("hex")) === -1 &&
        kg.stdout.indexOf(kgKeyBytes.toString("base64")) === -1 &&
        kg.stdout.indexOf(fs.readFileSync(kgOut).toString("base64")) === -1);
    /* A key written over another key destroys the only copy of the first. */
    var before = fs.readFileSync(kgOut);
    var kgAgain = cli(["keygen", "--out", kgOut]);
    check("pki keygen refuses to write over an existing file, names it, and leaves it unchanged",
      kgAgain.status !== 0 && kgAgain.stderr.indexOf(kgOut) !== -1 &&
        Buffer.compare(fs.readFileSync(kgOut), before) === 0);
    check("pki keygen requires --out rather than defaulting to stdout",
      cli(["keygen"]).status !== 0 && /usage: pki keygen/.test(cli(["keygen"]).stderr));
    /* PQC-first: an ML-DSA key is as reachable as a classical one, and the default is one of the
     * suites the toolkit leads with. The default is read from the file rather than assumed. */
    var kgDefault = pki.schema.pkcs8.parse(fs.readFileSync(kgOut));
    check("pki keygen defaults to a post-quantum signature suite (" +
      kgDefault.privateKeyAlgorithm.name + ")",
    /^id-ml-dsa/.test(String(kgDefault.privateKeyAlgorithm.name)));
    var kgEd = path.join(tmp, "kg-ed.key");
    check("pki keygen --alg reaches a classical suite too",
      cli(["keygen", "--alg", "Ed25519", "--out", kgEd]).status === 0 &&
        pki.schema.pkcs8.parse(fs.readFileSync(kgEd)).privateKeyAlgorithm.name === "Ed25519");
    check("pki keygen refuses an algorithm the engine does not generate, naming it",
      (function () { var r = cli(["keygen", "--alg", "NOT-A-SUITE", "--out", path.join(tmp, "x.key")]);
        return r.status !== 0 && r.stderr.indexOf("NOT-A-SUITE") !== -1; })());
    /* The mode claim is checked against what the platform GIVES, not against an assumption: on
     * win32 a mode argument is not applied and the help text says so. */
    var kgMode = fs.statSync(kgOut).mode & 0o777;
    var kgHelp = cli(["keygen", "--help"]).stderr;
    check("the keygen help text's permission claim matches what this platform does (mode " +
      kgMode.toString(8) + " on " + process.platform + ")",
    process.platform === "win32"
      ? /not applied on Windows|Windows/.test(kgHelp)
      : kgMode === 0o600);
    check("pki keygen --pem writes an armored key rather than DER",
      (function () {
        var p = path.join(tmp, "kg.pem");
        var r = cli(["keygen", "--alg", "Ed25519", "--out", p, "--pem"]);
        return r.status === 0 && fs.readFileSync(p, "utf8").indexOf("-----BEGIN PRIVATE KEY-----") === 0;
      })());

    /* ---- csr: a request over a supplied key ---- */
    var reqKey = path.join(tmp, "req.key");
    check("keygen produced the key the request vectors sign with",
      cli(["keygen", "--alg", "Ed25519", "--out", reqKey]).status === 0);
    var reqOut = path.join(tmp, "req-cli.der");
    var csrRun = cli(["csr", "--key", reqKey, "--subject", "CN=req.example", "--san", "req.example,www.req.example", "--out", reqOut]);
    check("pki csr exits 0 and writes a request the library parses",
      csrRun.status === 0 && (function () {
        var c = pki.schema.csr.parse(fs.readFileSync(reqOut));
        return c.subject.dn === "CN=req.example";
      })());
    check("pki csr carries the requested names into the request's extensions",
      (function () {
        var rows = pki.schema.csr.decodeExtensions(pki.schema.csr.parse(fs.readFileSync(reqOut)));
        return rows.some(function (r) {
          return r.name === "subjectAltName" && JSON.stringify(r.decoded).indexOf("www.req.example") !== -1;
        });
      })());
    check("pki csr writes a request whose signature verifies, so a CA can act on it",
      await pki.csr.verify(fs.readFileSync(reqOut)).then(function (v) { return v === true || (v && v.valid === true); },
        function () { return false; }));
    check("pki csr requires a key and a subject", cli(["csr"]).status !== 0 &&
      /usage: pki csr/.test(cli(["csr"]).stderr) &&
      cli(["csr", "--key", reqKey]).status !== 0);

    /* ---- issue: self-signed, from a CA, and from a request ---- */
    var selfCert = path.join(tmp, "self.der");
    var issueSelf = cli(["issue", "--key", reqKey, "--subject", "CN=self.example", "--days", "30", "--out", selfCert]);
    check("pki issue self-signs when no issuer is given",
      issueSelf.status === 0 && (function () {
        var c = pki.schema.x509.parse(fs.readFileSync(selfCert));
        return c.subject.dn === "CN=self.example" && c.issuer.dn === "CN=self.example";
      })());
    check("pki issue honors --days in the validity window it writes",
      (function () {
        var c = pki.schema.x509.parse(fs.readFileSync(selfCert));
        var days = (c.validity.notAfter - c.validity.notBefore) / 86400000;
        return Math.round(days) === 30;
      })());
    var caKey = path.join(tmp, "ca.key");
    var caCert = path.join(tmp, "ca.der");
    check("pki issue --ca marks the certificate as a CA that may sign certificates",
      cli(["keygen", "--alg", "Ed25519", "--out", caKey]).status === 0 &&
        cli(["issue", "--key", caKey, "--subject", "CN=ca.example", "--ca", "--days", "365", "--out", caCert]).status === 0 &&
        (function () {
          var rows = pki.schema.x509.decodeExtensions(pki.schema.x509.parse(fs.readFileSync(caCert)));
          var bc = rows.filter(function (r) { return r.name === "basicConstraints"; })[0];
          var ku = rows.filter(function (r) { return r.name === "keyUsage"; })[0];
          return bc && bc.decoded.cA === true && ku && ku.decoded.keyCertSign === true;
        })());
    var leafCert = path.join(tmp, "leaf.der");
    var issueLeaf = cli(["issue", "--key", reqKey, "--subject", "CN=leaf.example",
      "--issuer-cert", caCert, "--issuer-key", caKey, "--days", "30", "--out", leafCert]);
    check("pki issue signs from a supplied issuer certificate and key",
      issueLeaf.status === 0 && (function () {
        var c = pki.schema.x509.parse(fs.readFileSync(leafCert));
        return c.subject.dn === "CN=leaf.example" && c.issuer.dn === "CN=ca.example";
      })());
    /* Asking for a CA-signed certificate and silently getting a self-signed one is the failure
     * mode this pair exists to prevent: half an issuer is a usage error, not a self-sign. */
    check("pki issue refuses an issuer certificate with no issuer key, rather than self-signing",
      (function () {
        var r = cli(["issue", "--key", reqKey, "--subject", "CN=half.example",
          "--issuer-cert", caCert, "--out", path.join(tmp, "half1.der")]);
        return r.status !== 0 && /--issuer-key/.test(r.stderr);
      })());
    check("pki issue refuses an issuer key with no issuer certificate",
      (function () {
        var r = cli(["issue", "--key", reqKey, "--subject", "CN=half.example",
          "--issuer-key", caKey, "--out", path.join(tmp, "half2.der")]);
        return r.status !== 0 && /--issuer-cert/.test(r.stderr);
      })());
    /* Certifying a request whose signature does not verify certifies a key the requester may not
     * hold, so the CSR path verifies before it issues. */
    var fromCsr = path.join(tmp, "from-csr.der");
    var issueCsr = cli(["issue", "--csr", reqOut, "--issuer-cert", caCert, "--issuer-key", caKey,
      "--days", "30", "--out", fromCsr]);
    check("pki issue --csr certifies the subject and key the request carries",
      issueCsr.status === 0 && (function () {
        var c = pki.schema.x509.parse(fs.readFileSync(fromCsr));
        return c.subject.dn === "CN=req.example" && c.issuer.dn === "CN=ca.example";
      })());
    var tamperedCsr = path.join(tmp, "tampered.der");
    fs.writeFileSync(tamperedCsr, (function () {
      var der = fs.readFileSync(reqOut);
      var node = pki.asn1.decode(der);
      var sig = Buffer.from(node.children[2].content);
      sig[sig.length - 1] ^= 0xff;
      return pki.asn1.build.sequence([pki.asn1.build.raw(node.children[0].bytes),
        pki.asn1.build.raw(node.children[1].bytes), pki.asn1.build.bitString(sig, 0)]);
    })());
    check("pki issue --csr refuses a request whose signature does not verify",
      (function () {
        var r = cli(["issue", "--csr", tamperedCsr, "--issuer-cert", caCert, "--issuer-key", caKey,
          "--out", path.join(tmp, "never.der")]);
        return r.status !== 0 && !fs.existsSync(path.join(tmp, "never.der"));
      })());
    check("pki issue refuses both --key and --csr at once, since they name the same thing twice",
      cli(["issue", "--key", reqKey, "--csr", reqOut, "--subject", "CN=x",
        "--out", path.join(tmp, "both.der")]).status !== 0);
    check("pki issue requires a subject source", cli(["issue"]).status !== 0 &&
      /usage: pki issue/.test(cli(["issue"]).stderr));
    /* The certificate the CLI issued validates against the CA the CLI issued, through the library's
     * own path validator: the two verbs compose or neither is usable. */
    var vChain = cli(["verify", leafCert, "--anchor", caCert]);
    check("a certificate pki issue signed validates against the anchor pki issue signed",
      vChain.status === 0 && /valid/.test(vChain.stdout));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
