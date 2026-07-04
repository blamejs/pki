// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/check-services.js
 *
 * Service-check gate for the interop integration harness. The toolkit has
 * no network backends — its "service" is a second, independent PKI
 * implementation used as a cross-checker. This gate confirms that oracle
 * is present before scripts/test-integration.js spawns any test file, so a
 * missing toolchain fails loudly here instead of surfacing as a confusing
 * per-file spawn error.
 *
 * OpenSSL (the `openssl` CLI) is REQUIRED — the shipped x509 interop test
 * uses it as the independent oracle. NSS (`certutil`) is reported as an
 * optional additional cross-checker when present; its absence is not a
 * failure.
 *
 * Override the openssl binary with PKIJS_OPENSSL.
 *
 * Exit codes:
 *   0 — required oracle(s) reachable
 *   1 — a required oracle is missing (install it, or bring up the
 *       docker-compose.test.yml interop service which bundles it)
 */

var spawnSync = require("node:child_process").spawnSync;

function _probe(bin, args) {
  var rv = spawnSync(bin, args, { encoding: "utf8" });
  if (rv.error) return { ok: false, detail: rv.error.message };
  if (rv.status !== 0) {
    return { ok: false, detail: "exit " + rv.status + ": " + ((rv.stderr || rv.stdout || "").trim()) };
  }
  return { ok: true, detail: (rv.stdout || rv.stderr || "").split(/\r?\n/)[0].trim() };
}

function main() {
  var opensslBin = process.env.PKIJS_OPENSSL || "openssl";
  var failures = 0;

  console.log("[check-services] probing interop cross-checkers...");

  // Required: OpenSSL.
  var ossl = _probe(opensslBin, ["version"]);
  if (ossl.ok) {
    console.log("  openssl   OK    " + ossl.detail);
  } else {
    failures += 1;
    console.error("  openssl   MISSING (required)  " + ossl.detail);
    console.error("            install openssl, or run inside the compose interop service:");
    console.error("            docker compose -f docker-compose.test.yml run --rm interop");
  }

  // Optional: NSS certutil. Informational only — never fails the gate.
  var nss = _probe("certutil", ["--version"]);
  if (nss.ok) {
    console.log("  certutil  OK    " + nss.detail + " (optional NSS oracle available)");
  } else {
    console.log("  certutil  absent (optional NSS oracle — interop still runs on openssl)");
  }

  if (failures > 0) {
    console.error("[check-services] " + failures + " required oracle(s) missing");
    process.exit(1);
  }
  console.log("[check-services] OK — required cross-checkers reachable");
  process.exit(0);
}

main();
