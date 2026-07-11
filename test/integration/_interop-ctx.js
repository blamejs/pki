// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/integration/_interop-ctx — the shared context every interop fixture
 * receives. It bundles the toolkit binding, the shared assertion counter,
 * and the OpenSSL cross-checker plumbing so a fixture only expresses WHAT
 * to cross-check, never HOW to spawn a subprocess or manage a temp file.
 *
 * `openssl` is the independent oracle: a structure the toolkit emits is
 * handed to a second, unrelated implementation and must be accepted /
 * read identically. `PKIJS_OPENSSL` overrides the binary.
 */

var helpers = require("../helpers");
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var spawnSync = require("node:child_process").spawnSync;

var FIXTURES_DIR = path.join(__dirname, "..", "fixtures");
var _tmpSeq = 0;

function opensslBin() { return process.env.PKIJS_OPENSSL || "openssl"; }

// OpenSSL honors the OPENSSL_CONF environment variable OVER the config compiled
// into the binary (OPENSSLDIR). A machine-global OPENSSL_CONF left by a
// DIFFERENT OpenSSL installation cross-contaminates the oracle: the on-PATH
// binary then parses a config written for another major version — e.g. an
// authorityKeyIdentifier option (`keyid:nonss`) a newer line defines but this
// binary's v2i_AUTHORITY_KEYID rejects — and every `req -x509` fixture dies
// before a certificate is generated. Spawn openssl with that variable stripped
// so the binary reads its own matching config; an operator pinning a config on
// purpose sets PKIJS_OPENSSL_CONF.
function opensslEnv() {
  var env = {};
  Object.keys(process.env).forEach(function (k) { if (k !== "OPENSSL_CONF") env[k] = process.env[k]; });
  if (process.env.PKIJS_OPENSSL_CONF) env.OPENSSL_CONF = process.env.PKIJS_OPENSSL_CONF;
  return env;
}

// opensslSupports(pattern) — does the cross-checker's OpenSSL advertise a
// signature algorithm matching `pattern` (case-insensitive)? Lets a fixture
// skip a cross-check the oracle can't perform — e.g. ML-DSA / SLH-DSA need
// OpenSSL 3.5+, while CI runners and Alpine still ship 3.0–3.3. An absent
// capability is a limit of the oracle, not a defect in the toolkit, so the
// fixture records a skip rather than failing.
function opensslSupports(pattern) {
  try {
    var rv = spawnSync(opensslBin(), ["list", "-signature-algorithms"], { encoding: "utf8", env: opensslEnv() });
    if (rv.status !== 0) return false;
    return new RegExp(pattern, "i").test(rv.stdout || "");
  } catch (_e) { return false; }
}

// runOpenssl(args, opts?) -> stdout. Throws on spawn error or non-zero
// exit, surfacing stderr so a fixture failure is legible. opts.input
// feeds stdin (DER/PEM bytes); opts.allowNonZero returns { code, stdout,
// stderr } instead of throwing (for "openssl should REJECT this" checks).
function runOpenssl(args, opts) {
  opts = opts || {};
  var rv = spawnSync(opensslBin(), args, {
    encoding: opts.input ? "buffer" : "utf8",
    input:    opts.input,
    env:      opensslEnv(),
  });
  if (rv.error) throw new Error("openssl spawn failed: " + rv.error.message);
  if (opts.allowNonZero) {
    return { code: rv.status, stdout: String(rv.stdout || ""), stderr: String(rv.stderr || "") };
  }
  if (rv.status !== 0) {
    throw new Error("openssl exited " + rv.status + ": " + String(rv.stderr || rv.stdout || "").trim());
  }
  return String(rv.stdout || "");
}

// tmpFile(bytes, ext?) -> path. Writes bytes to a unique temp file the
// caller is responsible for removing (use withTmp for auto-cleanup).
function tmpFile(bytes, ext) {
  var p = path.join(os.tmpdir(), "pkijs-interop-" + process.pid + "-" + (_tmpSeq++) + "-" + (ext || "bin"));
  fs.writeFileSync(p, bytes);
  return p;
}

// withTmp(bytes, ext, fn) — write bytes to a temp file, pass the path to
// fn, and always remove the file afterwards.
function withTmp(bytes, ext, fn) {
  var p = tmpFile(bytes, ext);
  try { return fn(p); }
  finally { try { fs.unlinkSync(p); } catch (_e) { /* best-effort */ } }
}

module.exports = {
  pki:          helpers.pki,
  check:        helpers.check,
  // skip(reason) — record a cross-check the OpenSSL oracle CANNOT perform (an
  // absent capability, not a toolkit defect) as a SKIP, not a pass. A skip must
  // never be faked with check(<reason>, true) — that inflates the pass count and
  // hides that the cross-check did not actually run.
  skip:         helpers.skip,
  fs:           fs,
  path:         path,
  FIXTURES_DIR: FIXTURES_DIR,
  opensslBin:   opensslBin,
  opensslSupports: opensslSupports,
  runOpenssl:   runOpenssl,
  tmpFile:      tmpFile,
  withTmp:      withTmp,
};
