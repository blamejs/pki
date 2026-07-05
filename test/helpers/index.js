// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/helpers — shared infrastructure for the per-file test layout.
 *
 * Each test file imports the named helpers it needs:
 *
 *   var helpers = require("../helpers");
 *   var check   = helpers.check;
 *   var pki     = helpers.pki;
 *
 * This index re-exports every named helper so the common case (a single
 * require) covers most files. Files needing specific helpers can import
 * per-module to make their dependencies obvious.
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var pki  = require("../../index.js");

var _check   = require("./check");
var _wait    = require("./wait");
var _vectors = require("./vectors");

module.exports = {
  // Toolkit binding + Node stdlib re-exports for ergonomics.
  pki:  pki,
  fs:   fs,
  os:   os,
  path: path,

  // Assertion + counter
  check:              _check.check,
  skip:               _check.skip,
  getChecks:          _check.getChecks,
  getSkips:           _check.getSkips,
  getSkipReasons:     _check.getSkipReasons,
  resetChecksForTest: _check.resetChecksForTest,
  addExternalChecks:  _check.addExternalChecks,
  formatErr:          _check.formatErr,

  // Poll-until-condition — replaces fixed-budget setTimeout(r, N) sleeps.
  waitUntil:       _wait.waitUntil,
  waitUntilEqual:  _wait.waitUntilEqual,
  passiveObserve:  _wait.passiveObserve,
  withTestTimeout: _wait.withTestTimeout,

  // Shared test vectors / fixtures (real certificates, known-answer OIDs).
  vectors: _vectors,
};
