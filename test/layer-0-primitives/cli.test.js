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
    /* A payload past any single-write boundary, over an output path that already exists, so the
     * overwrite goes through the descriptor rather than by name. A write that reported a short count
     * and was believed would leave a file this parse refuses. */
    var bigContent = path.join(tmp, "big-to-sign.bin");
    fs.writeFileSync(bigContent, Buffer.alloc(4 * 1024 * 1024, 0x61));
    var bigOut = path.join(tmp, "big.cms");
    fs.writeFileSync(bigOut, "stale");
    var bigRun = cli(["sign", bigContent, "--cert", certPath, "--key", keyPath, "--out", bigOut]);
    var bigBytes = fs.readFileSync(bigOut);
    check("pki sign writes a 4 MiB payload over an existing --out in full (" + bigBytes.length +
      " bytes, exit " + bigRun.status + ")",
    bigRun.status === 0 && bigBytes.length > 4 * 1024 * 1024 &&
      pki.schema.cms.parse(bigBytes).encapContentInfo.eContent.length === 4 * 1024 * 1024);
    fs.unlinkSync(bigOut);
    fs.unlinkSync(bigContent);

    /* ---- --help reaches every verb ----
     * The first flag anyone tries. Four verbs printed a usage line when their arguments were
     * missing and three took a bare positional, so `pki oid --help` answered "unknown OID name"
     * and `pki parse --help` tried to open a file called --help. The set is derived from the
     * usage banner rather than written out here, so a verb added later is covered by this vector
     * without an edit. */
    var banner = cli([]).stdout;
    var verbs = (/usage: pki <([a-z|-]+)>/.exec(banner) || [])[1];
    check("the usage banner names the verb set this vector derives from", typeof verbs === "string");
    // Every verb answers help; `version` alone requires no argument, so it is out of the vector
    // below that asks what a missing one does.
    var verbList = String(verbs).split("|");
    var argTakingVerbs = verbList.filter(function (v) { return v !== "version"; });
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
    argTakingVerbs.forEach(function (verb) {
      var m = cli([verb]);
      if (m.status === 0) missingArgGaps.push(verb + " exited 0 with no arguments");
    });
    check("pki <verb> with no arguments exits non-zero (" + argTakingVerbs.length + " verbs): " +
      missingArgGaps.join("; "), missingArgGaps.length === 0);

    /* ---- an answered help is not a failed command ----
     * Every verb reached its usage line through the check for a missing argument, which exits
     * non-zero on stderr. So `pki csr --help` answered the question and reported a command that
     * failed, while `pki --help` answered the same question and exited 0. A script reading the
     * status cannot tell the help it asked for from a csr that did not run. Both flags are asked
     * for, and both are asked of a verb whose arguments are otherwise COMPLETE, where the usage
     * check never fires: help is answered because it was asked for, not because something is
     * missing. */
    var helpStatusGaps = [];
    verbList.forEach(function (verb) {
      ["--help", "-h"].forEach(function (flag) {
        var h = cli([verb, flag]);
        if (h.status !== 0) helpStatusGaps.push(verb + " " + flag + " exited " + h.status);
        else if (h.stdout.indexOf("usage: pki " + verb) === -1) {
          helpStatusGaps.push(verb + " " + flag + " wrote its usage somewhere other than stdout");
        }
      });
    });
    check("pki <verb> --help and -h exit 0 with the usage line on stdout, for every verb (" +
      verbList.length + " verbs): " + helpStatusGaps.join("; "), helpStatusGaps.length === 0);
    var completeHelp = cli(["csr", "--key", keyPath, "--subject", "CN=complete", "--help"]);
    check("pki csr --help answers help even with every required argument supplied (exit " +
      completeHelp.status + ")",
    completeHelp.status === 0 && completeHelp.stdout.indexOf("usage: pki csr") === 0);
    var flagValueHelp = cli(["csr", "--key", "--help"]);
    check("a help flag standing where a flag's value belongs is still read as help (exit " +
      flagValueHelp.status + ")",
    flagValueHelp.status === 0 && flagValueHelp.stdout.indexOf("usage: pki csr") === 0);
    var missingStays = cli(["csr"]);
    check("a missing argument still fails, on stderr (exit " + missingStays.status + ")",
      missingStays.status !== 0 && missingStays.stdout === "" &&
      missingStays.stderr.indexOf("usage: pki csr") !== -1);

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
    /* A run that FAILS must leave no private key behind. The private half was written first and the
     * public half second, so a --pub that already exists reported failure with a freshly generated
     * secret sitting at --out, and the obvious retry then refused because --out existed. An operator
     * reading "pki: ... already exists" has no reason to look for a key file. */
    var txnOut = path.join(tmp, "txn.key");
    var txnPub = path.join(tmp, "txn.pub");
    fs.writeFileSync(txnPub, "already here");
    var txn = cli(["keygen", "--out", txnOut, "--pub", txnPub]);
    check("pki keygen leaves no private key behind when the public destination is taken (" +
      "exit " + txn.status + ", key file " + (fs.existsSync(txnOut) ? "LEFT" : "absent") + ")",
    txn.status !== 0 && fs.existsSync(txnOut) === false &&
      txn.stderr.indexOf(txnPub) !== -1);
    /* The product of keygen is the FILE. A stdout that cannot be written made a COMPLETED generation
     * exit non-zero with the key on disk, which looks exactly like the failure above while being the
     * opposite: the run did what it was asked. Driven with a READ-ONLY descriptor as stdout, which is
     * what a closed or full pipe amounts to here. */
    var fdOut = path.join(tmp, "fd.key");
    var roFd = fs.openSync(BIN, "r");
    var fdRun;
    try {
      fdRun = spawnSync(process.execPath, [BIN, "keygen", "--alg", "Ed25519", "--out", fdOut],
        { stdio: ["ignore", roFd, "pipe"], encoding: "utf8" });
    } finally { fs.closeSync(roFd); }
    check("pki keygen still reports success when the key was written and only stdout failed (" +
      "exit " + fdRun.status + ", key " + (fs.existsSync(fdOut) ? "present" : "ABSENT") + ")",
    fdRun.status === 0 && fs.existsSync(fdOut) &&
      /stdout could not be written/.test(String(fdRun.stderr || "")));
    check("and the key that run wrote is a usable private key",
      pki.schema.pkcs8.parse(fs.readFileSync(fdOut)).privateKeyAlgorithm.name === "Ed25519");
    /* The same rule for every verb whose product is a file, not just keygen: `csr` with --out writes
     * its request and then says so, and a broken stdout used to make that exit non-zero over a file
     * already on disk. */
    var csrKey = path.join(tmp, "fd-csr.key");
    cli(["keygen", "--alg", "Ed25519", "--out", csrKey]);
    var csrOut = path.join(tmp, "fd.csr");
    var roFd3 = fs.openSync(BIN, "r");
    var csrBroken;
    try {
      csrBroken = spawnSync(process.execPath,
        [BIN, "csr", "--key", csrKey, "--subject", "CN=fd.example", "--out", csrOut],
        { stdio: ["ignore", roFd3, "pipe"], encoding: "utf8" });
    } finally { fs.closeSync(roFd3); }
    check("a file-backed verb other than keygen also succeeds when only stdout failed (" +
      "exit " + csrBroken.status + ", csr " + (fs.existsSync(csrOut) ? "present" : "ABSENT") + ")",
    csrBroken.status === 0 && fs.existsSync(csrOut) &&
      pki.schema.csr.parse(fs.readFileSync(csrOut)) !== undefined);
    /* The other half of the same rule: for a verb whose product IS stdout, a stdout that cannot be
     * written is the command failing, and it says so as a `pki:` line rather than as the runtime's
     * own unhandled-error stack dump. */
    var roFd2 = fs.openSync(BIN, "r");
    var inspectBroken;
    try {
      inspectBroken = spawnSync(process.execPath, [BIN, "inspect", FIXTURE],
        { stdio: ["ignore", roFd2, "pipe"], encoding: "utf8" });
    } finally { fs.closeSync(roFd2); }
    check("a verb whose product is stdout still fails on a broken stdout, with a pki message (" +
      "exit " + inspectBroken.status + ")",
    inspectBroken.status !== 0 &&
      /^pki: stdout could not be written/.test(String(inspectBroken.stderr || "")) &&
      String(inspectBroken.stderr || "").indexOf("node:events") === -1);
    /* The mirror of the same rule, and the one reserving the public name first created: when --out is
     * the collision, the public destination has already been claimed, so a run that fails there must
     * not leave THAT behind either. Only files this invocation created are removed, never one that
     * was already there. */
    var mirrorOut = path.join(tmp, "mirror.key");
    var mirrorPub = path.join(tmp, "mirror.pub");
    fs.writeFileSync(mirrorOut, "already here");
    var mirror = cli(["keygen", "--out", mirrorOut, "--pub", mirrorPub]);
    check("pki keygen leaves no reserved public file behind when the private destination is taken (" +
      "exit " + mirror.status + ", pub " + (fs.existsSync(mirrorPub) ? "LEFT" : "absent") + ")",
    mirror.status !== 0 && fs.existsSync(mirrorPub) === false &&
      fs.readFileSync(mirrorOut, "utf8") === "already here");
    check("and that retry succeeds once the private destination is cleared",
      (function () {
        fs.unlinkSync(mirrorOut);
        var again = cli(["keygen", "--out", mirrorOut, "--pub", mirrorPub]);
        return again.status === 0 && fs.existsSync(mirrorOut) && fs.existsSync(mirrorPub);
      })());
    check("and the retry an operator would run next succeeds",
      (function () {
        fs.unlinkSync(txnPub);
        var again = cli(["keygen", "--out", txnOut, "--pub", txnPub]);
        return again.status === 0 && fs.existsSync(txnOut) && fs.existsSync(txnPub);
      })());
    /* The record that keeps the cleanup to this run's own files has to be of the file this run WROTE.
     * Taken by path after the descriptor closed, a writer who replaced the path in between had its
     * replacement measured instead, and the cleanup then deleted that replacement: the comparison
     * meant to prevent data loss was reading the wrong file. The preload performs the replacement at
     * the close, where the window is, and gives it the same bytes and the same timestamps, so nothing
     * but the inode distinguishes it. */
    var PRELOAD = path.join(__dirname, "..", "helpers", "swap-after-close-preload.js");
    function keygenUnder(env, args) {
      var r = spawnSync(process.execPath, ["-r", PRELOAD, BIN, "keygen"].concat(args),
        { encoding: "utf8", env: Object.assign({}, process.env, env) });
      return { status: r.status, stderr: String(r.stderr || "") };
    }
    var swapOut = path.join(tmp, "swap.key");
    var swapPub = path.join(tmp, "swap.pub");
    fs.writeFileSync(swapOut, "already here");
    var swapRun = keygenUnder({ PKI_SWAP_PATH: swapPub }, ["--out", swapOut, "--pub", swapPub]);
    if (swapRun.stderr.indexOf("reports no inode") !== -1) {
      helpers.skip("the filesystem under " + tmp + " reports no inode, so a replacement cannot be " +
        "told from the original by identity and only its size and timestamp are compared");
    } else {
      check("the preload replaced the reserved public file at the close (" +
        (swapRun.stderr.indexOf("replaced") !== -1 ? "swapped" : "NOT SWAPPED") + ")",
      swapRun.stderr.indexOf("replaced " + swapPub + " at close") !== -1);
      check("a file that replaced one this run created is left in place rather than deleted (" +
        "pub " + (fs.existsSync(swapPub) ? "present" : "DELETED") + ")",
      swapRun.status !== 0 && fs.existsSync(swapPub) === true &&
        swapRun.stderr.indexOf(swapPub + " was replaced since this run created it") !== -1);
      fs.unlinkSync(swapPub);
      /* The identity has to be on the record from the moment the NAME became ours, not from the moment
       * the content went in. A write that fails leaves nothing to measure, and a record with nothing
       * measured was deleted with no comparison at all, so a replacement arriving in that window was
       * the file removed. An unidentifiable file is exactly the one not to delete. */
      var failPub = path.join(tmp, "fail.pub");
      var failRun = keygenUnder({ PKI_SWAP_PATH: failPub, PKI_FAIL_WRITE: failPub },
        ["--out", path.join(tmp, "fail.key"), "--pub", failPub]);
      check("the preload failed the public write and replaced the file at the close (" +
        (failRun.stderr.indexOf("replaced") !== -1 ? "swapped" : "NOT SWAPPED") + ")",
      failRun.stderr.indexOf("ENOSPC") !== -1 &&
        failRun.stderr.indexOf("replaced " + failPub + " at close") !== -1);
      check("and a replacement is left in place even though the write this run attempted failed (" +
        "pub " + (fs.existsSync(failPub) ? "present" : "DELETED") + ")",
      failRun.status !== 0 && fs.existsSync(failPub) === true &&
        failRun.stderr.indexOf(failPub + " was replaced since this run created it") !== -1);
      fs.unlinkSync(failPub);
      check("and the private key the run never reached was not created",
        fs.existsSync(path.join(tmp, "fail.key")) === false);
      /* Unlinking a name whose content carries another link removes the name and keeps the bytes, so a
       * half-removal reports success over a key that is still readable through the other name. */
      var linkOut = path.join(tmp, "link.key");
      var linkPub = path.join(tmp, "link.pub");
      fs.writeFileSync(linkOut, "already here");
      var linkRun = keygenUnder({ PKI_SWAP_PATH: linkPub, PKI_SWAP_MODE: "link" },
        ["--out", linkOut, "--pub", linkPub]);
      if (linkRun.stderr.indexOf("linked " + linkPub + " at close") === -1) {
        helpers.skip("this filesystem did not add a hard link, so a name sharing content with " +
          "another cannot be driven here");
      } else {
        check("a file linked since this run created it is left in place rather than half-removed (" +
          "pub " + (fs.existsSync(linkPub) ? "present" : "DELETED") + ")",
        linkRun.status !== 0 && fs.existsSync(linkPub) === true &&
          linkRun.stderr.indexOf(linkPub + " has more than one link") !== -1);
        fs.unlinkSync(linkPub + ".link");
        fs.unlinkSync(linkPub);
      }
      fs.unlinkSync(linkOut);
      /* And the link count is asked of what is on disk NOW rather than compared against the count this
       * run recorded. Two names added before the record was taken and one removed afterwards make the
       * count go DOWN, so a comparison looking for growth sees none and clears the path while the other
       * name still holds the bytes. One name is what an exclusive create gives, so more than one at
       * cleanup is somebody else's. */
      var shrinkOut = path.join(tmp, "shrink.key");
      var shrinkPub = path.join(tmp, "shrink.pub");
      fs.writeFileSync(shrinkOut, "already here");
      var shrinkRun = keygenUnder({ PKI_SWAP_PATH: shrinkPub, PKI_SWAP_MODE: "linkshrink" },
        ["--out", shrinkOut, "--pub", shrinkPub]);
      if (shrinkRun.stderr.indexOf("link count for " + shrinkPub + " went to 2") === -1) {
        helpers.skip("this filesystem did not report a link count going from 3 to 2, so a record " +
          "holding a higher count than the cleanup sees cannot be driven here");
      } else {
        check("a file whose link count FELL since this run recorded it is still left in place (" +
          "pub " + (fs.existsSync(shrinkPub) ? "present" : "DELETED") + ")",
        shrinkRun.status !== 0 && fs.existsSync(shrinkPub) === true &&
          shrinkRun.stderr.indexOf(shrinkPub + " has more than one link") !== -1);
        fs.unlinkSync(shrinkPub + ".one");
        fs.unlinkSync(shrinkPub);
      }
      fs.unlinkSync(shrinkOut);
      /* A path that cannot be STATTED is not a path whose file is gone, and a file nobody could look at
       * is a file nobody removed. Passed over in silence, that left an operator with a file the run
       * created and never mentioned. */
      var blindOut = path.join(tmp, "blind.key");
      var blindPub = path.join(tmp, "blind.pub");
      fs.writeFileSync(blindOut, "already here");
      var blindRun = keygenUnder({ PKI_SWAP_PATH: blindPub, PKI_SWAP_MODE: "statfail" },
        ["--out", blindOut, "--pub", blindPub]);
      check("a file the cleanup could not examine is left in place and named (" +
        "pub " + (fs.existsSync(blindPub) ? "present" : "DELETED") + ")",
      blindRun.status !== 0 && fs.existsSync(blindPub) === true &&
        blindRun.stderr.indexOf(blindPub + " was created by this run and could not be examined") !== -1);
      fs.unlinkSync(blindPub);
      fs.unlinkSync(blindOut);
      /* An empty path is not proof the run's own file ceased to exist: moved to another name, the
       * bytes this run wrote are somewhere an operator has not been told about, and the path it was
       * asked to write is bare. Said rather than passed over. */
      var movedOut = path.join(tmp, "moved.key");
      var movedPub = path.join(tmp, "moved.pub");
      fs.writeFileSync(movedOut, "already here");
      var movedRun = keygenUnder({ PKI_SWAP_PATH: movedPub, PKI_SWAP_MODE: "rename" },
        ["--out", movedOut, "--pub", movedPub]);
      check("a created file moved away before the cleanup is reported rather than passed over (" +
        (fs.existsSync(movedPub + ".moved") ? "moved" : "NOT MOVED") + ")",
      movedRun.status !== 0 && fs.existsSync(movedPub) === false &&
        fs.existsSync(movedPub + ".moved") === true &&
        movedRun.stderr.indexOf(movedPub + " was created by this run and is no longer there") !== -1);
      fs.unlinkSync(movedPub + ".moved");
      fs.unlinkSync(movedOut);
      /* The verbs whose product is not a key write through the same tracked path. The rule arrived with
       * `keygen` and applied to keygen alone, so a write that failed part way through `csr --out` left
       * a file this run had just created with nobody tracking it. */
      var csrKeyT = path.join(tmp, "tracked.key");
      cli(["keygen", "--alg", "Ed25519", "--out", csrKeyT]);
      var csrOutT = path.join(tmp, "tracked.csr");
      var csrFail = spawnSync(process.execPath,
        ["-r", PRELOAD, BIN, "csr", "--key", csrKeyT, "--subject", "CN=tracked.example",
          "--out", csrOutT],
        { encoding: "utf8", env: Object.assign({}, process.env, { PKI_FAIL_WRITE: csrOutT }) });
      check("a csr write that fails part way leaves no file behind (exit " + csrFail.status + ", " +
        (fs.existsSync(csrOutT) ? "LEFT" : "absent") + ")",
      csrFail.status !== 0 && fs.existsSync(csrOutT) === false &&
        String(csrFail.stderr || "").indexOf("ENOSPC") !== -1);
      /* "The path is taken" and "the path is free" are answers about the moment they were given. An
       * overwrite that creates BY NAME after being told the path was taken makes a file this run owns
       * with nobody tracking it, so a failed write then leaves it behind. The overwrite arm opens the
       * path without permission to create it, and an answer of "not there" is retried as the exclusive
       * create it has become. */
      var raceOut = path.join(tmp, "race.csr");
      var raceRun = spawnSync(process.execPath,
        ["-r", PRELOAD, BIN, "csr", "--key", csrKeyT, "--subject", "CN=race.example",
          "--out", raceOut],
        { encoding: "utf8", env: Object.assign({}, process.env,
          { PKI_TOCTOU_PATH: raceOut, PKI_FAIL_WRITE: raceOut }) });
      check("the preload forced the taken-then-free window (" +
        (String(raceRun.stderr || "").indexOf("forced EEXIST") !== -1 ? "forced" : "NOT FORCED") + ")",
      String(raceRun.stderr || "").indexOf("forced EEXIST") !== -1 &&
        String(raceRun.stderr || "").indexOf("forced ENOENT") !== -1);
      check("a file created after that window is tracked, so a failed write leaves nothing (" +
        (fs.existsSync(raceOut) ? "LEFT" : "absent") + ")",
      raceRun.status !== 0 && fs.existsSync(raceOut) === false &&
        String(raceRun.stderr || "").indexOf("ENOSPC") !== -1);
      /* CONTROL: an output path that already exists is still overwritten, which is what these verbs
       * have always done and what distinguishes them from the key verbs. */
      fs.writeFileSync(csrOutT, "stale content");
      var csrOver = cli(["csr", "--key", csrKeyT, "--subject", "CN=tracked.example", "--out", csrOutT]);
      check("CONTROL an existing output path is still overwritten (exit " + csrOver.status + ")",
        csrOver.status === 0 &&
          pki.schema.csr.parse(fs.readFileSync(csrOutT)) !== undefined);
      /* And the overwrite empties the file first, which is what writing through a descriptor has to do
       * by hand. A SHORTER request over a longer one is the case that shows it: a write that only put
       * its own bytes at the front would leave the tail of the previous one behind, and the file would
       * carry trailing bytes the parser refuses. */
      var longReq = fs.readFileSync(csrOutT).length;
      cli(["csr", "--key", csrKeyT, "--subject", "CN=a-much-longer-subject-name.example",
        "--out", csrOutT]);
      var longer = fs.readFileSync(csrOutT).length;
      var shortRun = cli(["csr", "--key", csrKeyT, "--subject", "CN=b", "--out", csrOutT]);
      var shorter = fs.readFileSync(csrOutT);
      check("a shorter request over a longer one leaves no tail of the longer (" + longReq + " then " +
        longer + " then " + shorter.length + " bytes)",
      shortRun.status === 0 && shorter.length < longer &&
        pki.schema.csr.parse(shorter) !== undefined);
      /* A destination that is not a regular file has nothing to truncate, and an operator writes to
       * `/dev/null` and `/dev/stdout`. Truncating one unconditionally refused it, which is a
       * regression against the plain write these verbs used before. */
      if (process.platform === "win32" || !fs.existsSync("/dev/null")) {
        helpers.skip("this platform (" + process.platform + ") has no /dev/null, so an output " +
          "destination that is not a regular file cannot be driven here");
      } else {
        var nullRun = cli(["csr", "--key", csrKeyT, "--subject", "CN=devnull.example",
          "--out", "/dev/null"]);
        check("an output destination that is not a regular file is still written (exit " +
          nullRun.status + ")", nullRun.status === 0);
        /* A FIFO reaches a READER, it is not consumed by the writer. Opening an existing destination
           read-write makes this process its own reader, so the open succeeds with nobody listening and
           the bytes go into a pipe no one drains: the command reports success and the output is gone.
           A write-only open waits for a reader, which is what naming a FIFO asks for. Driven with a
           real reader so the vector asserts the bytes ARRIVED rather than that the call returned, and
           only where `mkfifo` exists. This cannot run on win32, which is why the defect reached a
           reviewer rather than this suite. */
        var fifoPath = path.join(tmp, "out.fifo");
        var haveFifo = false;
        try {
          require("node:child_process").execFileSync("mkfifo", [fifoPath], { stdio: "ignore" });
          haveFifo = fs.existsSync(fifoPath);
        } catch (_mk) { haveFifo = false; }
        if (!haveFifo) {
          helpers.skip("mkfifo is unavailable here, so a FIFO destination cannot be driven");
        } else {
          // The reader starts first and drains the pipe, which is what a write-only open waits for.
          var reader = require("node:child_process").spawn(process.execPath,
            ["-e", "process.stdout.write(String(require('fs').readFileSync(process.argv[1]).length))",
              fifoPath], { stdio: ["ignore", "pipe", "ignore"] });
          var readBytes = "";
          reader.stdout.on("data", function (d) { readBytes += d; });
          var fifoRun = cli(["csr", "--key", csrKeyT, "--subject", "CN=fifo.example", "--out", fifoPath]);
          await helpers.waitUntil(function () { return readBytes.length > 0; },
            { timeoutMs: 20000, label: "the FIFO reader to report what it drained" });
          check("a FIFO destination reaches a reader rather than being swallowed (exit " +
            fifoRun.status + ", reader drained " + readBytes + " bytes)",
          fifoRun.status === 0 && Number(readBytes) > 0);
          try { fs.unlinkSync(fifoPath); } catch (_rm) { /* allow:swallow-unverified the fixture is gone either way */ }
          /* And the case that DISTINGUISHES the two opens, which the one above does not: NO reader.
             With a reader present both a write-only and a read-write open deliver, so that check alone
             passes either way. Without one, a read-write open makes the writer its own reader and
             returns success having written into a pipe nobody drains, while a write-only open waits.
             So the question is whether the command can report SUCCESS with no reader: it must not. */
          var lonePath = path.join(tmp, "noreader.fifo");
          var haveLone = false;
          try {
            require("node:child_process").execFileSync("mkfifo", [lonePath], { stdio: "ignore" });
            haveLone = fs.existsSync(lonePath);
          } catch (_mk2) { haveLone = false; }
          if (haveLone) {
            var lone = spawnSync(process.execPath,
              [BIN, "csr", "--key", csrKeyT, "--subject", "CN=lonefifo.example", "--out", lonePath],
              { encoding: "utf8", timeout: 6000 });
            var blocked = !!(lone.error && lone.error.code === "ETIMEDOUT");
            check("a FIFO with no reader does not report success with the output discarded (" +
              (blocked ? "waited for a reader" : "exit " + lone.status) + ")",
            blocked || lone.status !== 0);
            try { fs.unlinkSync(lonePath); } catch (_rm2) { /* allow:swallow-unverified the fixture is gone either way */ }
          }
        }
      }
      fs.unlinkSync(csrOutT);
      fs.unlinkSync(csrKeyT);
      /* A path comes from the command line, and a report naming one has to stay one line: a newline in
       * the name would end the line early and put whatever follows where an operator reads the tool's
       * own output. Where a filesystem admits the byte at all. */
      var nlPub = path.join(tmp, "nl\na.pub");
      var nlAdmitted = true;
      try { fs.writeFileSync(nlPub, "probe"); fs.unlinkSync(nlPub); }
      catch (_nl) { nlAdmitted = false; }
      if (!nlAdmitted) {
        helpers.skip("this filesystem (" + process.platform + ") does not admit a newline in a file " +
          "name, so a report naming one cannot be driven here");
      } else {
        /* The collision has to be on the path that CARRIES the newline. Pre-creating the `--out` path
           instead made the refusal name THAT one, which holds no newline, so the vector drove a report
           that could never have broken a line and the escaping it was written to check went untested.
           Here `--pub` is the one that already exists, so the refusal names the newline-carrying path. */
        var nlOut = path.join(tmp, "nl.key");
        fs.writeFileSync(nlPub, "already here");
        var nlRun = cli(["keygen", "--out", nlOut, "--pub", nlPub]);
        var pkiLines = nlRun.stderr.split("\n").filter(function (l) { return l.indexOf("pki: ") === 0; });
        var rawNewlineInReport = nlRun.stderr.replace(/pki: /g, "").indexOf("\n") !==
          nlRun.stderr.replace(/pki: /g, "").trimEnd().length;
        check("a report naming a path that carries a newline is still one line (" +
          pkiLines.length + " pki line(s), escaped " + (nlRun.stderr.indexOf("\\x0a") !== -1) + ")",
        nlRun.status !== 0 && pkiLines.length === 1 && nlRun.stderr.indexOf("\\x0a") !== -1 &&
          !rawNewlineInReport);
        if (fs.existsSync(nlPub)) fs.unlinkSync(nlPub);
        if (fs.existsSync(nlOut)) fs.unlinkSync(nlOut);
        /* And the SUCCESS line, which names the caller's paths too and goes to STDOUT, where a script
           reading this tool's output is most likely to be parsing it. The escaping was applied to the
           refusals and not to the report of a completed write, so the rule reached the failing half of
           the verb and not the succeeding half. */
        var okOut = path.join(tmp, "nlok.key");
        var okPub = path.join(tmp, "nlok\nb.pub");
        var okRun = cli(["keygen", "--alg", "Ed25519", "--out", okOut, "--pub", okPub]);
        var okLines = okRun.stdout.replace(/\n$/, "").split("\n");
        check("the report of a completed write is one line too (" + okLines.length + " line(s), " +
          "escaped " + (okRun.stdout.indexOf("\\x0a") !== -1) + ")",
        okRun.status === 0 && okLines.length === 1 && okRun.stdout.indexOf("\\x0a") !== -1);
        if (fs.existsSync(okPub)) fs.unlinkSync(okPub);
        if (fs.existsSync(okOut)) fs.unlinkSync(okOut);
      }
    }
    /* Both halves at one name would put the private key where the public one was asked for. The
     * exclusive create already refuses the second write, so the refusal is about saying why. */
    var samePath = path.join(tmp, "same.key");
    var same = cli(["keygen", "--out", samePath, "--pub", samePath]);
    check("pki keygen refuses --out and --pub naming the same file (exit " + same.status + ")",
      same.status !== 0 && same.stderr.indexOf("name the same file") !== -1 &&
        fs.existsSync(samePath) === false);
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
    var kgHelp = cli(["keygen", "--help"]).stdout;
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
      "--days", "30", "--copy-requested-san", "--out", fromCsr]);
    check("pki issue --csr certifies the subject and key the request carries",
      issueCsr.status === 0 && (function () {
        var c = pki.schema.x509.parse(fs.readFileSync(fromCsr));
        return c.subject.dn === "CN=req.example" && c.issuer.dn === "CN=ca.example";
      })());

    /* ---- what a request asks for is answered, never dropped ----
     * `pki csr --san host.example` then `pki issue --csr` is the documented two-step, and it
     * issued a certificate with no subjectAltName: the issue path read the request's subject and
     * public key and built its extensions from --san alone, so the names the request asked for
     * reached nothing. A leaf with no subjectAltName does not match a host name, so the failure
     * arrives at whatever presents the certificate rather than at the command that made it.
     * RFC 2985 sec. 5.4.2 leaves to the CA which requested extensions to honor, so neither answer
     * is taken by default: the operator says which, and a request that asks for anything neither
     * flag accounts for is refused. */
    var sanRows = pki.schema.x509.decodeExtensions(pki.schema.x509.parse(fs.readFileSync(fromCsr)))
      .filter(function (r) { return r.name === "subjectAltName"; });
    var copiedNames = sanRows.length
      ? sanRows[0].decoded.names.map(function (n) { return n.value; }) : [];
    check("pki issue --copy-requested-san writes every name the request asked for (" +
      copiedNames.join(", ") + ")",
    copiedNames.length === 2 && copiedNames.indexOf("req.example") !== -1 &&
      copiedNames.indexOf("www.req.example") !== -1);
    var unanswered = cli(["issue", "--csr", reqOut, "--issuer-cert", caCert, "--issuer-key", caKey,
      "--days", "30", "--out", path.join(tmp, "unanswered.der")]);
    check("a request that asks for extensions is refused until the operator says what to do " +
      "with them, naming what was asked (exit " + unanswered.status + ")",
    unanswered.status !== 0 && /subjectAltName/.test(unanswered.stderr) &&
      /--copy-requested-san/.test(unanswered.stderr) &&
      /--ignore-requested-extensions/.test(unanswered.stderr) &&
      !fs.existsSync(path.join(tmp, "unanswered.der")));
    var ignored = path.join(tmp, "ignored.der");
    var ignoreRun = cli(["issue", "--csr", reqOut, "--issuer-cert", caCert, "--issuer-key", caKey,
      "--days", "30", "--ignore-requested-extensions", "--out", ignored]);
    check("pki issue --ignore-requested-extensions issues without what the request asked for",
      ignoreRun.status === 0 &&
        pki.schema.x509.decodeExtensions(pki.schema.x509.parse(fs.readFileSync(ignored)))
          .filter(function (r) { return r.name === "subjectAltName"; }).length === 0);
    /* A SAN-only request is the one shape whose subjectAltName MUST be critical: RFC 5280
     * sec. 4.2.1.6 requires it where the subject is empty, and this toolkit's own linter refuses
     * the non-critical form through `lint/rfc2986/san-not-critical-empty-subject`. So the only
     * conforming empty-subject request is a critical one, and refusing every critical request made
     * that request unissuable through --copy-requested-san. The criticality is not lost either: the
     * certificate builder takes it from the subject it encodes, so an empty subject writes the
     * critical form. The refusal belongs to the case where the request carries a subject, which is
     * where copying a critical SAN would answer a different request. The pre-encoded array form
     * builds the request, because the object form always writes the requested SAN non-critical. */
    var sanOnlyCsr = path.join(tmp, "san-only.csr.der");
    var sanOnlyLeaf = path.join(tmp, "san-only.leaf.der");
    var reqKeyBytes = fs.readFileSync(reqKey);
    var reqSpki = await pki.key.publicFromPrivate(reqKeyBytes);
    var critSanExt = b.sequence([b.oid(pki.oid.byName("subjectAltName")), b.boolean(true),
      b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("san-only.example"))]))]);
    fs.writeFileSync(sanOnlyCsr, await pki.csr.sign(
      { subject: [], subjectPublicKey: reqSpki, extensionRequest: [critSanExt] },
      { key: reqKeyBytes }));
    var sanOnlyRun = cli(["issue", "--csr", sanOnlyCsr, "--issuer-cert", caCert, "--issuer-key", caKey,
      "--days", "30", "--copy-requested-san", "--out", sanOnlyLeaf]);
    check("a SAN-only request's critical subjectAltName is issued, not refused",
      sanOnlyRun.status === 0 && fs.existsSync(sanOnlyLeaf));
    check("and the issued certificate keeps the empty subject and writes the SAN critical",
      sanOnlyRun.status === 0 && (function () {
        var der = fs.readFileSync(sanOnlyLeaf);
        var parsed = pki.schema.x509.parse(der);
        if (pki.asn1.decode(parsed.subject.bytes).children.length !== 0) return false;
        var row = pki.schema.x509.decodeExtensions(der)
          .filter(function (r) { return r.name === "subjectAltName"; })[0];
        return !!row && row.critical === true && row.decoded.names.length === 1 &&
          row.decoded.names[0].value === "san-only.example";
      })());
    /* The refusal still stands where it is true: beside a subject the builder writes the
     * non-critical form, so copying a critical request would answer a different request. */
    var withSubjectCsr = path.join(tmp, "crit-san-subject.csr.der");
    var withSubjectLeaf = path.join(tmp, "crit-san-subject.der");
    fs.writeFileSync(withSubjectCsr, await pki.csr.sign(
      { subject: [{ commonName: "crit.example" }], subjectPublicKey: reqSpki,
        extensionRequest: [critSanExt] }, { key: reqKeyBytes }));
    var critWithSubject = cli(["issue", "--csr", withSubjectCsr, "--issuer-cert", caCert,
      "--issuer-key", caKey, "--days", "30", "--copy-requested-san", "--out", withSubjectLeaf]);
    check("a critical subjectAltName requested BESIDE a subject is still refused",
      critWithSubject.status !== 0 && /CRITICAL subjectAltName/.test(critWithSubject.stderr) &&
        !fs.existsSync(withSubjectLeaf));
    check("--san and --copy-requested-san both name the subjectAltName, so passing both is refused",
      (function () {
        var r = cli(["issue", "--csr", reqOut, "--issuer-cert", caCert, "--issuer-key", caKey,
          "--copy-requested-san", "--san", "other.example", "--out", path.join(tmp, "two-san.der")]);
        return r.status !== 0 && /--copy-requested-san/.test(r.stderr) &&
          !fs.existsSync(path.join(tmp, "two-san.der"));
      })());
    check("both answers need a request to answer, so neither is accepted on the --key route",
      (function () {
        var r = cli(["issue", "--key", reqKey, "--subject", "CN=x", "--copy-requested-san",
          "--out", path.join(tmp, "no-req.der")]);
        var i = cli(["issue", "--key", reqKey, "--subject", "CN=x", "--ignore-requested-extensions",
          "--out", path.join(tmp, "no-req2.der")]);
        return r.status !== 0 && /--csr/.test(r.stderr) && i.status !== 0 && /--csr/.test(i.stderr);
      })());
    /* A request asking for an extension the CA assigns itself, or for a name form the copy does not
     * write, is named rather than dropped from the copy: a certificate carrying SOME of what was
     * asked for is a different certificate from the one that was asked for. */
    check("a requested extension other than the subjectAltName is named, not copied and not dropped",
      await (async function () {
        var pair = await pki.key.generate("Ed25519");
        var der = await pki.csr.sign({ subject: "ku.example",
          subjectPublicKey: await pki.key.export(pair.publicKey),
          extensionRequest: { keyUsage: ["digitalSignature"] } },
        { key: await pki.key.export(pair.privateKey) });
        var p = path.join(tmp, "ku-req.der");
        fs.writeFileSync(p, der);
        var r = cli(["issue", "--csr", p, "--issuer-cert", caCert, "--issuer-key", caKey,
          "--copy-requested-san", "--out", path.join(tmp, "ku.der")]);
        return r.status !== 0 && /keyUsage/.test(r.stderr) &&
          !fs.existsSync(path.join(tmp, "ku.der"));
      })());
    check("a requested name of a form the copy does not write refuses the issuance, naming the form",
      await (async function () {
        var pair = await pki.key.generate("Ed25519");
        var der = await pki.csr.sign({ subject: "dir.example",
          subjectPublicKey: await pki.key.export(pair.publicKey),
          extensionRequest: { subjectAltName: ["ok.example", { directoryName: "dir.example" }] } },
        { key: await pki.key.export(pair.privateKey) });
        var p = path.join(tmp, "dir-req.der");
        fs.writeFileSync(p, der);
        var r = cli(["issue", "--csr", p, "--issuer-cert", caCert, "--issuer-key", caKey,
          "--copy-requested-san", "--out", path.join(tmp, "dir.der")]);
        return r.status !== 0 && /\[4\]/.test(r.stderr) && !fs.existsSync(path.join(tmp, "dir.der"));
      })());
    /* Criticality is part of what a request asks for. The certificate builder's extensions object
     * writes a non-critical subjectAltName, which is the form RFC 5280 sec. 4.2.1.6 asks for beside a
     * non-empty subject, so a request asking for the critical one is asking for a certificate this
     * verb does not write. Copying the names and dropping the flag issued a certificate that differs
     * from the request in the field that decides whether a relying party must understand it. */
    check("a request asking for a critical subjectAltName is refused rather than copied non-critical",
      await (async function () {
        var pair = await pki.key.generate("Ed25519");
        var crit = pki.asn1.build.sequence([
          pki.asn1.build.oid(pki.oid.byName("subjectAltName")),
          pki.asn1.build.boolean(true),
          pki.asn1.build.octetString(pki.asn1.build.sequence([
            pki.asn1.build.contextPrimitive(2, Buffer.from("crit.example", "latin1"))])),
        ]);
        var der = await pki.csr.sign({ subject: "crit.example",
          subjectPublicKey: await pki.key.export(pair.publicKey), extensionRequest: [crit] },
        { key: await pki.key.export(pair.privateKey) });
        var p = path.join(tmp, "crit-req.der");
        fs.writeFileSync(p, der);
        var asked = pki.schema.csr.decodeExtensions(der)[0];
        var out = path.join(tmp, "crit.der");
        var r = cli(["issue", "--csr", p, "--issuer-cert", caCert, "--issuer-key", caKey,
          "--copy-requested-san", "--out", out]);
        return asked.critical === true && r.status !== 0 && /critical/i.test(r.stderr) &&
          !fs.existsSync(out);
      })());
    /* An address is a 4- or 16-octet value rather than text, so the copy carries the OCTETS the
     * request held: a copy that re-read the printed form would write a dNSName spelled like an
     * address, which matches nothing. */
    check("an address the request asked for is copied as an address",
      await (async function () {
        var pair = await pki.key.generate("Ed25519");
        var der = await pki.csr.sign({ subject: "ip.example",
          subjectPublicKey: await pki.key.export(pair.publicKey),
          extensionRequest: { subjectAltName: [{ iPAddress: "10.0.0.7" }, { rfc822Name: "a@b.example" },
            { uniformResourceIdentifier: "https://ip.example/p" }] } },
        { key: await pki.key.export(pair.privateKey) });
        var p = path.join(tmp, "ip-req.der");
        fs.writeFileSync(p, der);
        var out = path.join(tmp, "ip.der");
        var r = cli(["issue", "--csr", p, "--issuer-cert", caCert, "--issuer-key", caKey,
          "--copy-requested-san", "--out", out]);
        if (r.status !== 0) return false;
        var rows = pki.schema.x509.decodeExtensions(pki.schema.x509.parse(fs.readFileSync(out)))
          .filter(function (x) { return x.name === "subjectAltName"; });
        var byTag = {};
        rows[0].decoded.names.forEach(function (n) { byTag[n.tagNumber] = n.value; });
        return Buffer.isBuffer(byTag[7]) && byTag[7].length === 4 && byTag[7][3] === 7 &&
          byTag[1] === "a@b.example" && byTag[6] === "https://ip.example/p";
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

    /* ---- fetch ----
     * A fetched certificate is not a verified one, and the report must not read as though it were.
     * These run offline: a reserved TLD never resolves, so the failure is the verb's own and the
     * vector cannot depend on a network. */
    var fetchUsage = cli(["fetch"]);
    check("pki fetch requires a URL", fetchUsage.status !== 0 && /usage: pki fetch/.test(fetchUsage.stderr));
    var fetchBad = cli(["fetch", "https://nothing.invalid/"]);
    check("pki fetch against a host that does not resolve fails closed and does not hang",
      fetchBad.status !== 0 && fetchBad.stdout.indexOf("-----BEGIN") === -1);
    check("pki fetch reports the failure as the transport's typed fault",
      /transport\//.test(fetchBad.stderr));
    check("pki fetch refuses a URL that is not https, rather than fetching in the clear",
      (function () { var r = cli(["fetch", "http://nothing.invalid/"]);
        return r.status !== 0 && /insecure-url/.test(r.stderr); })());
    /* The verb says what the handshake checked and what it did not. Without that an operator reads
     * a printed chain as a validated one, which is the confusion `pki verify` exists to resolve. */
    var fetchHelp = cli(["fetch", "--help"]).stdout;
    check("pki fetch's help says it is not a verification and names the verb that is",
      /not a verification|does not verify/i.test(fetchHelp) && /pki verify/.test(fetchHelp));

    /* A file can be one complete DER value AND a well-formed PEM block at once, which the library
     * refuses rather than guessing. Its advice is "pass PEM as a string, or the DER value on its
     * own", and a reader holding a FILE cannot act on that, so the CLI names a command instead. */
    var ambiguousText = "\n-----BEGIN A-----\n" +
      pki.asn1.build.octetString(Buffer.alloc(17, 0x41)).toString("base64") + "\n-----END A-----\n";
    var ambiguousPath = path.join(tmp, "ambiguous.bin");
    fs.writeFileSync(ambiguousPath, Buffer.concat([Buffer.from([0x43, ambiguousText.length]),
      Buffer.from(ambiguousText, "latin1")]));
    var ambiguousGaps = [];
    ["parse", "inspect", "lint"].forEach(function (verb) {
      var r = cli([verb, ambiguousPath]);
      if (r.status === 0) { ambiguousGaps.push(verb + " exited 0 on an ambiguous file"); return; }
      if (!/pki convert/.test(r.stderr)) ambiguousGaps.push(verb + " gave no command to run: " + r.stderr.slice(0, 70));
    });
    check("a file that reads as both DER and PEM is refused with a command the reader can run: " +
      ambiguousGaps.join("; "), ambiguousGaps.length === 0);
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
