// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — the `pki` CLI (bin/pki.js). Spawns the SHIPPED command an operator
 * runs, so a public-API rename that leaves the CLI calling a removed export is
 * caught here (it crashed silently past the library tests once — the CLI still
 * called pki.x509.parse after that export moved to pki.schema.x509).
 */

var helpers = require("../helpers");
var check = helpers.check;
var path = require("path");
var spawnSync = require("child_process").spawnSync;

var BIN = path.join(__dirname, "..", "..", "bin", "pki.js");
var FIXTURE = path.join(__dirname, "..", "fixtures", "pkijs-selfsigned-ec.pem");

function cli(args) {
  var r = spawnSync(process.execPath, [BIN].concat(args), { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

function run() {
  var pkg = require("../../package.json");

  var v = cli(["version"]);
  check("pki version exits 0", v.status === 0);
  check("pki version prints the package version", v.stdout.indexOf(pkg.version) !== -1);

  var o = cli(["oid", "2.5.4.3"]);
  check("pki oid resolves a dotted OID to its name", o.status === 0 && /commonName/.test(o.stdout));

  var p = cli(["parse", FIXTURE]);
  check("pki parse exits 0 on a valid certificate", p.status === 0);
  // Direct parse: a crashed / non-JSON CLI throws here loudly (the real
  // diagnostic), never a swallowed false.
  check("pki parse emits parseable JSON with the cert fields", (function () {
    var j = JSON.parse(p.stdout);
    return j.version === 3 && typeof j.serialNumber === "string" && j.serialNumber.length > 0;
  })());

  var bad = cli(["parse", "/no/such/path/nope.pem"]);
  check("pki parse fails cleanly on a missing file (non-zero exit)", bad.status !== 0);

  var unknown = cli(["frobnicate"]);
  check("pki rejects an unknown command (non-zero exit)", unknown.status !== 0);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
