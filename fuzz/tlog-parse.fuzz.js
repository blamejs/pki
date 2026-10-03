// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.tlog.parseNote / parseCheckpoint / parseTilePath / parseTile / parseEntryBundle
 *
 * Runs under libFuzzer via jazzer.js. Every one of these reads bytes a log served, which is to say
 * bytes an attacker may have chosen: a note is text with a signature block, a checkpoint is a note
 * with a formatted body, a tile is a run of hashes, and an entry bundle is length-prefixed entries.
 *
 * Contract: parsing them may only RETURN a value or THROW a `pki.errors.PkiError`. Any other throw
 * is a finding. A RangeError or a raw TypeError means a reader walked past a bound, a stack
 * overflow means a recursion no cap held, and a hang means an offset that advanced by zero, which
 * is the one way a length-prefixed reader loops.
 *
 * The same bytes drive all five, because a mutator that finds an interesting note shape should get
 * to try it as a tile and a bundle too, and the path reader is driven from the text form.
 */

var pki = require("..");

function drive(fn, arg) {
  try {
    fn(arg);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
}

module.exports.fuzz = function (data) {
  var text = data.toString("latin1");
  drive(pki.tlog.parseNote, data);
  drive(pki.tlog.parseNote, text);
  drive(pki.tlog.parseCheckpoint, data);
  drive(pki.tlog.parseTilePath, text);
  drive(pki.tlog.parseTile, data);
  drive(pki.tlog.parseEntryBundle, data);
};
