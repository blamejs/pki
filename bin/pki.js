#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * pki — command-line front-end for @blamejs/pki.
 *
 *   pki version                          print the package version
 *   pki oid <dotted|name>                resolve an OID <-> name
 *   pki parse <cert>                      parse an X.509 certificate to JSON
 *   pki inspect <cert>                    render a certificate as text (openssl x509 -text style)
 *   pki lint <cert> [--profile P]         lint a certificate; exit non-zero on an error finding
 *              [--severity S] [--json]
 *   pki convert <file> --to der|pem       transcode a DER/PEM file between the two encodings
 *              [--label LABEL]
 *   pki verify <cert>... --anchor <cert>  validate an ordered certification path (anchor->target)
 *              [--time ISO]
 *
 * The CLI is a thin operator convenience over the library surface: it validates its
 * arguments (entry-point tier — bad input exits non-zero with a message) and never does
 * anything the public API cannot. inspect / lint / convert / verify compose pki.inspect,
 * pki.lint, the per-format PEM codecs, and pki.path.validate respectively.
 */

var fs  = require("node:fs");
var pki = require("../index.js");

function fail(msg) {
  process.stderr.write("pki: " + msg + "\n");
  process.exit(1);
}

// Minimal flag parser: collects `--flag value` / `--flag` (boolean) into `opts`, the rest
// into `_` (positionals). No clustering, no `=`; a flag with no following value is boolean.
var BOOLEAN_FLAGS = { json: 1 };
function parseArgs(argv) {
  var out = { _: [] };
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a.indexOf("--") === 0) {
      var key = a.slice(2);
      if (BOOLEAN_FLAGS[key] || i + 1 >= argv.length || argv[i + 1].indexOf("--") === 0) { out[key] = true; }
      else { out[key] = argv[++i]; }
    } else { out._.push(a); }
  }
  return out;
}

// Read a DER/PEM file and return its DER bytes (+ the PEM label when the input was PEM).
// A PEM armor is stripped generically (any label) so the four format-agnostic commands do
// not need to know the structure; a raw DER file is returned as-is.
function readInput(file) {
  var bytes;
  try { bytes = fs.readFileSync(file); } catch (e) { fail("cannot read " + file + ": " + e.message); }
  var text = bytes.toString("latin1");
  // Detect PEM only at the file BOUNDARY (armor at the start, after optional whitespace):
  // binary DER begins with a tag byte, never "-----BEGIN", so a DER value that merely
  // CONTAINS that ASCII marker (an OCTET STRING / DN string) is not misread as PEM.
  if (/^\s*-----BEGIN /.test(text)) {
    var m = /-----BEGIN ([A-Za-z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
    if (!m) fail(file + ": malformed PEM (no matching BEGIN/END block)");
    var b64 = m[2].replace(/[\s]+/g, "");
    // Validate canonical base64 BEFORE decoding: Node's base64 decoder silently drops
    // invalid characters and stops at the first bad byte, so a malformed body would decode
    // to partial/garbage DER instead of failing. Reject anything that is not the base64
    // alphabet with correct terminal padding and a multiple-of-four length.
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) fail(file + ": malformed PEM base64");
    return { der: Buffer.from(b64, "base64"), label: m[1] };
  }
  return { der: bytes, label: null };
}

function cmdVersion() {
  process.stdout.write("@blamejs/pki v" + pki.version + "\n");
}

function cmdOid(arg) {
  if (!arg) fail("usage: pki oid <dotted|name>");
  if (/^\d+(\.\d+)+$/.test(arg)) {
    var name = pki.oid.name(arg);
    process.stdout.write((name || "(unregistered)") + "\n");
  } else {
    var dotted = pki.oid.byName(arg);
    if (!dotted) fail("unknown OID name: " + arg);
    process.stdout.write(dotted + "\n");
  }
}

function cmdParse(file) {
  if (!file) fail("usage: pki parse <cert.pem|cert.der>");
  var cert;
  try { cert = pki.schema.x509.parse(readInput(file).der); } catch (e) { return fail(e.code + ": " + e.message); }
  var view = {
    version:            cert.version,
    serialNumber:       cert.serialNumberHex,
    subject:            cert.subject.dn,
    issuer:             cert.issuer.dn,
    notBefore:          cert.validity.notBefore.toISOString(),
    notAfter:           cert.validity.notAfter.toISOString(),
    signatureAlgorithm: cert.signatureAlgorithm.name || cert.signatureAlgorithm.oid,
    publicKeyAlgorithm: cert.subjectPublicKeyInfo.algorithm.name || cert.subjectPublicKeyInfo.algorithm.oid,
    extensions:         cert.extensions.map(function (e) { return { oid: e.oid, name: e.name, critical: e.critical }; }),
  };
  process.stdout.write(JSON.stringify(view, null, 2) + "\n");
}

// pki inspect <cert> -- the human-readable certificate render (pki.inspect.certificate),
// the pure-JS equivalent of `openssl x509 -text`.
function cmdInspect(file) {
  if (!file) fail("usage: pki inspect <cert.pem|cert.der>");
  try { process.stdout.write(pki.inspect.certificate(readInput(file).der)); }
  catch (e) { return fail(e.code + ": " + e.message); }
}

function pad(s, n) { while (s.length < n) s += " "; return s; }

// pki lint <cert> -- lint against pki.lint's profiles. Prints one line per finding and
// exits non-zero when any error/fatal finding is present (0 when the worst is advisory).
function cmdLint(args) {
  var file = args._[0];
  if (!file) fail("usage: pki lint <cert> [--profile <name>] [--severity <floor>] [--json]");
  var der = readInput(file).der;
  var report;
  // Config-time misuse (unknown profile / bad severity) throws a typed LintError; the data
  // path never throws (malformed bytes become a fatal lint/unparseable finding).
  try { report = pki.lint.certificate(der, { profile: args.profile, severity: args.severity }); }
  catch (e) { return fail(e.code + ": " + e.message); }
  if (args.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    report.findings.forEach(function (f) {
      process.stdout.write(pad(f.severity.toUpperCase(), 7) + " " + f.id + " -- " + f.message + "\n");
    });
    process.stdout.write("\n" + (report.findings.length || "no") + " finding(s); worst: " + (report.worst || "pass") + "\n");
  }
  // Set the exit CODE and let Node drain — process.exit() can truncate a buffered stdout
  // write to a pipe before it flushes.
  process.exitCode = (report.counts.error || report.counts.fatal) ? 1 : 0;
}

// pki convert <file> --to der|pem -- transcode between DER and PEM. The input encoding is
// auto-detected; the bytes must be well-formed DER (we never wrap/emit garbage).
function cmdConvert(args) {
  var file = args._[0], to = args.to;
  if (!file) fail("usage: pki convert <file> --to der|pem [--label LABEL]");
  if (to !== "der" && to !== "pem") fail("convert: --to must be 'der' or 'pem'");
  var input = readInput(file);
  try { pki.asn1.decode(input.der); } catch (e) { return fail("input is not well-formed DER: " + (e.code || e.message)); }
  if (to === "der") { process.stdout.write(input.der); return; }
  var label = args.label || input.label || "CERTIFICATE";
  var b64 = input.der.toString("base64").replace(/(.{1,64})/g, "$1\n");
  process.stdout.write("-----BEGIN " + label + "-----\n" + b64 + "-----END " + label + "-----\n");
}

// pki verify <cert>... --anchor <cert> -- validate an ordered certification path
// (anchor->target) against a trust anchor via pki.path.validate (RFC 5280 sec. 6.1).
function cmdVerify(args) {
  var certFiles = args._, anchorFile = args.anchor;
  if (!certFiles.length || !anchorFile) fail("usage: pki verify <cert>... --anchor <anchor-cert> [--time ISO]");
  var certs, anchor;
  try { certs = certFiles.map(function (f) { return pki.schema.x509.parse(readInput(f).der); }); }
  catch (e) { return fail("cannot parse a path certificate: " + (e.code || e.message)); }
  try { anchor = pki.schema.x509.parse(readInput(anchorFile).der); }
  catch (e2) { return fail("cannot parse the anchor certificate: " + (e2.code || e2.message)); }
  var time = args.time ? new Date(args.time) : new Date();
  if (isNaN(time.getTime())) fail("verify: --time must be an ISO-8601 date");
  var spki = anchor.subjectPublicKeyInfo;
  return pki.path.validate(certs, {
    time: time,
    trustAnchor: { name: anchor.subject, publicKey: spki.bytes, algorithm: spki.algorithm.oid, parameters: spki.algorithm.parameters },
  }).then(function (res) {
    process.stdout.write(res.valid ? "valid\n" : "invalid\n");
    if (!res.valid) {
      (res.results || []).forEach(function (r, i) {
        (r.checks || []).forEach(function (c) { if (c.ok === false) process.stdout.write("  cert[" + i + "] " + c.code + "\n"); });
      });
    }
    process.exitCode = res.valid ? 0 : 1;   // let Node flush stdout before it exits
  }, function (e) { return fail(e.code + ": " + e.message); });
}

var USAGE = "usage: pki <version|oid|parse|inspect|lint|convert|verify> [args]\n";

function main(argv) {
  var cmd = argv[0];
  switch (cmd) {
    case "version": case "--version": case "-v": return cmdVersion();
    case "oid":     return cmdOid(argv[1]);
    case "parse":   return cmdParse(argv[1]);
    case "inspect": return cmdInspect(argv[1]);
    case "lint":    return cmdLint(parseArgs(argv.slice(1)));
    case "convert": return cmdConvert(parseArgs(argv.slice(1)));
    case "verify":  return cmdVerify(parseArgs(argv.slice(1)));
    case undefined: case "help": case "--help": case "-h":
      process.stdout.write(USAGE);
      return;
    default:
      return fail("unknown command: " + cmd);
  }
}

Promise.resolve(main(process.argv.slice(2))).catch(function (e) { fail(e && (e.stack || e.message) || String(e)); });
