#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/validate-source-comment-blocks — toolkit-level static gate that
// runs the source-driven wiki's @module + @primitive comment-block
// validator from a clean checkout.
//
// Why: the wiki pages are generated from the JSDoc-style @module /
// @primitive blocks above each lib/ primitive. A drifted block (a missing
// @signature, a stale arity, an @example that no longer parses, an
// @related pointing at a member that was renamed) would only surface deep
// in the wiki e2e gate — which needs `cd examples/wiki && npm install`.
// Running the same engine here, alongside eslint / codebase-patterns,
// catches the drift pre-push in under five seconds.
//
// Pure script — no side effects, no network. Imports:
//   - examples/wiki/lib/source-comment-block-validator (the engine)
//   - examples/wiki/lib/source-doc-parser              (the parser)
//
// Exit codes:
//   0 — no findings
//   1 — findings present (each finding printed with its file + primitive)

var path = require("node:path");

var ROOT    = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");
var WIKI    = path.join(ROOT, "examples", "wiki");

var engine = require(path.join(WIKI, "lib", "source-comment-block-validator"));
var parser = require(path.join(WIKI, "lib", "source-doc-parser"));

function _report(findings) {
  if (findings.length === 0) {
    console.log("[validate-source-comment-blocks] OK - no findings");
    return 0;
  }
  console.log("[validate-source-comment-blocks] " + findings.length + " finding(s):");
  findings.forEach(function (f, i) {
    console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.file + (f.primitive ? " :: " + f.primitive : ""));
    console.log("     " + f.msg);
  });
  return 1;
}

var findings = engine.validate({
  libDir: LIB_DIR,
  parser: parser,
  // @spec is required on every primitive once it has been backfilled across
  // the whole surface; until then this stays opt-in so the gate is green.
  // Run with PKI_REQUIRE_SPEC=1 to measure the backfill gap, and flip the
  // default to true in the release that completes the backfill.
  requireSpec: process.env.PKI_REQUIRE_SPEC === "1",
});

process.exit(_report(findings));
