#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * pki — command-line front-end for @blamejs/pki.
 *
 *   pki version
 *   pki oid <dotted|name>          resolve an OID <-> name
 *   pki parse <cert.pem|cert.der>  parse an X.509 certificate and print
 *                                  its fields as JSON
 *
 * The CLI is a thin operator convenience over the library surface; it
 * validates its arguments (entry-point tier — bad input exits non-zero
 * with a message) and never does anything the public API can't.
 */

var fs  = require("node:fs");
var pki = require("../index.js");

function fail(msg) {
  process.stderr.write("pki: " + msg + "\n");
  process.exit(1);
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
  var bytes;
  try { bytes = fs.readFileSync(file); } catch (e) { return fail("cannot read " + file + ": " + e.message); }
  var cert;
  try { cert = pki.x509.parse(bytes); } catch (e) { return fail(e.code + ": " + e.message); }
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

function main(argv) {
  var cmd = argv[0];
  switch (cmd) {
    case "version": case "--version": case "-v": return cmdVersion();
    case "oid":     return cmdOid(argv[1]);
    case "parse":   return cmdParse(argv[1]);
    case undefined: case "help": case "--help": case "-h":
      process.stdout.write("usage: pki <version|oid|parse> [args]\n");
      return;
    default:
      return fail("unknown command: " + cmd);
  }
}

main(process.argv.slice(2));
