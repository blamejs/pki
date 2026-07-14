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
 *   pki sign <file> --cert <c> --key <k>  produce a CMS SignedData over the file (pki.cms.sign)
 *              [--detached] [--pss] [--digest D] [--pem] [--out F]
 *
 * The CLI is a thin operator convenience over the library surface: it validates its
 * arguments (entry-point tier — bad input exits non-zero with a message) and never does
 * anything the public API cannot. inspect / lint / convert / verify / sign compose pki.inspect,
 * pki.lint, the per-format PEM codecs, pki.path.validate, and pki.cms.sign respectively.
 */

var fs  = require("node:fs");
var pki = require("../index.js");

function fail(msg) {
  process.stderr.write("pki: " + msg + "\n");
  process.exit(1);
}

// Minimal flag parser: `--flag value` for value-taking flags, `--flag` for booleans, the
// rest are positionals in `_`. A value-taking flag whose value is absent or is itself another
// flag is a usage error (never silently coerced to `true`, which would make e.g. `--time`
// parse as `new Date(true)` = a real 1970 timestamp). No clustering, no `=value`.
var VALUE_FLAGS = { to: 1, profile: 1, severity: 1, label: 1, anchor: 1, time: 1, cert: 1, key: 1, digest: 1, out: 1 };
function parseArgs(argv) {
  var out = { _: [] };
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a.indexOf("--") === 0) {
      var key = a.slice(2);
      if (VALUE_FLAGS[key]) {
        if (i + 1 >= argv.length || argv[i + 1].indexOf("--") === 0) fail("--" + key + " requires a value");
        out[key] = argv[++i];
      } else { out[key] = true; }
    } else { out._.push(a); }
  }
  return out;
}

function readFileBytes(file) {
  try { return fs.readFileSync(file); } catch (e) { return fail("cannot read " + file + ": " + e.message); }
}

// For the library entry points (parse / inspect / lint / verify) that accept EITHER a DER
// Buffer or a PEM string and own the decode + error handling: hand a Buffer when the bytes
// are a well-formed DER structure, otherwise the text so the library pemDecodes it (and
// applies its own canonical-base64 policy). This defers ALL error handling to the library,
// which is what preserves the linter's never-throw survey -- malformed bytes become a fatal
// lint/unparseable finding rather than a CLI hard-fail. DER-first is unambiguous (a PEM file
// is ASCII text and never decodes as one DER TLV).
function readForLib(file) {
  var bytes = readFileBytes(file);
  try { pki.asn1.decode(bytes); return bytes; }
  catch (_derErr) { return bytes.toString("latin1"); }   // not DER -- let the library pemDecode / report it
}

// For `convert`, which transcodes RAW bytes and bypasses the library parse: extract DER
// explicitly (a well-formed DER file as-is, or a canonical PEM body), failing on anything
// else. Returns { der, label } where `label` is the PEM armor when the input was PEM.
function readDer(file) {
  var bytes = readFileBytes(file);
  try { pki.asn1.decode(bytes); return { der: bytes, label: null }; }
  catch (_derErr) { /* not a single well-formed DER structure -- try PEM */ }
  // Match the library's PEM grammar exactly (an uppercase A-Z0-9 label, and ONLY CR/LF/TAB/
  // space ignored in the body -- not every JS whitespace), so convert is not a looser
  // validation path than the codecs it composes.
  var m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(bytes.toString("latin1"));
  if (!m) return fail(file + ": input is neither a well-formed DER structure nor a PEM block");
  var b64 = m[2].replace(/[\r\n\t ]+/g, "");
  // Enforce CANONICAL base64 (RFC 4648 sec. 3.5), matching the library's fail-closed PEM
  // policy: Node's decoder silently drops invalid characters and tolerates non-canonical
  // trailing pad bits. Gate alphabet/length, then require that re-encoding reproduces the body.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) return fail(file + ": malformed PEM base64");
  var der = Buffer.from(b64, "base64");
  if (der.toString("base64") !== b64) return fail(file + ": non-canonical PEM base64");
  return { der: der, label: m[1] };
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
  try { cert = pki.schema.x509.parse(readForLib(file)); } catch (e) { return fail(e.code + ": " + e.message); }
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
  try { process.stdout.write(pki.inspect.certificate(readForLib(file))); }
  catch (e) { return fail(e.code + ": " + e.message); }
}

function pad(s, n) { while (s.length < n) s += " "; return s; }

// pki lint <cert> -- lint against pki.lint's profiles. Prints one line per finding and
// exits non-zero when any error/fatal finding is present (0 when the worst is advisory).
function cmdLint(args) {
  var file = args._[0];
  if (!file) fail("usage: pki lint <cert> [--profile <name>] [--severity <floor>] [--json]");
  var report;
  // Config-time misuse (unknown profile / bad severity) throws a typed LintError; the data
  // path never throws (malformed bytes become a fatal lint/unparseable finding).
  try { report = pki.lint.certificate(readForLib(file), { profile: args.profile, severity: args.severity }); }
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
  var input = readDer(file);
  try { pki.asn1.decode(input.der); } catch (e) { return fail("input is not well-formed DER: " + (e.code || e.message)); }
  if (to === "der") { process.stdout.write(input.der); return; }
  var label = args.label || input.label || "CERTIFICATE";
  // The armor label must be re-readable by the library's PEM grammar (uppercase A-Z0-9 words,
  // single spaces) -- reject a lowercase/invalid label rather than emit an unparseable file.
  if (!/^[A-Z0-9]+( [A-Z0-9]+)*$/.test(label)) return fail("convert: --label must be an uppercase A-Z0-9 label with single spaces (RFC 7468)");
  var b64 = input.der.toString("base64").replace(/(.{1,64})/g, "$1\n");
  process.stdout.write("-----BEGIN " + label + "-----\n" + b64 + "-----END " + label + "-----\n");
}

// pki verify <cert>... --anchor <cert> -- validate an ordered certification path
// (anchor->target) against a trust anchor via pki.path.validate (RFC 5280 sec. 6.1).
function cmdVerify(args) {
  var certFiles = args._, anchorFile = args.anchor;
  if (!certFiles.length || !anchorFile) fail("usage: pki verify <cert>... --anchor <anchor-cert> [--time ISO]");
  var certs, anchor;
  try { certs = certFiles.map(function (f) { return pki.schema.x509.parse(readForLib(f)); }); }
  catch (e) { return fail("cannot parse a path certificate: " + (e.code || e.message)); }
  try { anchor = pki.schema.x509.parse(readForLib(anchorFile)); }
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

// pki sign <content-file> --cert <cert> --key <key> -- produce a CMS SignedData over the file
// via pki.cms.sign. The signer key is a PKCS#8 DER or PEM private key; the certificate is DER or
// PEM. Output is a DER Buffer (or a PEM block with --pem) to --out or stdout.
function cmdSign(args) {
  var contentFile = args._[0];
  if (!contentFile || !args.cert || !args.key) {
    return fail("usage: pki sign <content-file> --cert <cert> --key <key.pkcs8> [--detached] [--pss] [--digest sha256|sha384|sha512] [--pem] [--out <file>]");
  }
  var content = readFileBytes(contentFile);
  var signer = { cert: _asPemOrDer(readFileBytes(args.cert)), key: _asPemOrDer(readFileBytes(args.key)) };
  if (args.pss) signer.pss = true;
  if (args.digest) signer.digestAlgorithm = args.digest;
  return pki.cms.sign(content, signer, { detached: !!args.detached, pem: !!args.pem }).then(function (out) {
    if (args.out) { try { fs.writeFileSync(args.out, out); } catch (e) { return fail("cannot write " + args.out + ": " + e.message); } }
    else { process.stdout.write(out); }   // process.exitCode (0) lets Node flush a piped stdout
  }, function (e) { return fail((e.code || "cms/sign-error") + ": " + e.message); });
}
// A PEM file (its first byte is '-') is passed to pki.cms.sign as a string; a DER file as its
// Buffer. cms.sign accepts either for the certificate and needs a string for a PEM private key.
function _asPemOrDer(buf) { return buf[0] === 0x2d ? buf.toString("latin1") : buf; }

var USAGE = "usage: pki <version|oid|parse|inspect|lint|convert|verify|sign> [args]\n";

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
    case "sign":    return cmdSign(parseArgs(argv.slice(1)));
    case undefined: case "help": case "--help": case "-h":
      process.stdout.write(USAGE);
      return;
    default:
      return fail("unknown command: " + cmd);
  }
}

Promise.resolve(main(process.argv.slice(2))).catch(function (e) { fail(e && (e.stack || e.message) || String(e)); });
