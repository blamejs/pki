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

function run() {
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
