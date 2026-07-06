// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// @status lifecycle driver — experimental primitives are surfaced for a
// graduation decision after REVIEW_AFTER releases, and a deprecation is failed
// once its remove-by is reached.

var helpers = require("../helpers");
var check = helpers.check;
var lifecycle = require("../../scripts/check-status-lifecycle.js");
var N = lifecycle.REVIEW_AFTER;

// A synthetic current version far enough past the fixtures' @since to trip the
// review threshold (patch delta == release age pre-1.0).
var CUR = "0." + "1." + (10 + N);   // e.g. REVIEW_AFTER 6 -> 0.1.16

function prim(name, status, since, removeBy) {
  return { primitive: name, status: status, since: since, removeBy: removeBy || null, file: "lib/x.js" };
}

function run() {
  // 1. An experimental primitive older than REVIEW_AFTER with NO ledger entry is DUE.
  var due = lifecycle.evaluate([prim("pki.x.old", "experimental", "0.1.10")], {}, CUR);
  check("overdue experimental with no ledger fails", due.failures.length === 1 && /graduation review/.test(due.failures[0]));

  // 2. A FULL dated keep-experimental decision (reason + reviewedAt + future
  //    reviewBy) acknowledges it.
  var full = { decision: "keep-experimental", reason: "interop harness pending", reviewedAt: "0.1.11", reviewBy: "9.9.9" };
  var ack = lifecycle.evaluate([prim("pki.x.old", "experimental", "0.1.10")], { "pki.x.old": full }, CUR);
  check("overdue experimental with a full dated keep-decision passes", ack.failures.length === 0);

  // 2b. A bare { decision, reviewBy } — no reason, no reviewedAt — is NOT a review.
  var bare = lifecycle.evaluate([prim("pki.x.old", "experimental", "0.1.10")],
    { "pki.x.old": { decision: "keep-experimental", reviewBy: "9.9.9" } }, CUR);
  check("keep-decision without a reason/date is not accepted", bare.failures.length === 1);
  var noReason = lifecycle.evaluate([prim("pki.x.old", "experimental", "0.1.10")],
    { "pki.x.old": { decision: "keep-experimental", reviewedAt: "0.1.11", reviewBy: "9.9.9" } }, CUR);
  check("keep-decision missing a reason is not accepted", noReason.failures.length === 1);

  // 3. A keep-decision whose reviewBy has been REACHED is due again.
  var stale = lifecycle.evaluate([prim("pki.x.old", "experimental", "0.1.10")],
    { "pki.x.old": { decision: "keep-experimental", reason: "x", reviewedAt: "0.1.10", reviewBy: "0.1.11" } }, CUR);
  check("keep-decision past its reviewBy is due again", stale.failures.length === 1);

  // 4. An experimental primitive YOUNGER than the threshold is not evaluated.
  var young = lifecycle.evaluate([prim("pki.x.new", "experimental", CUR)], {}, CUR);
  check("experimental under the threshold is not due", young.failures.length === 0);

  // 5. A stable primitive is never flagged.
  var stable = lifecycle.evaluate([prim("pki.x.done", "stable", "0.1.7")], {}, CUR);
  check("stable primitive is not flagged", stable.failures.length === 0);

  // 5b. A missing or misspelled @status FAILS — it cannot silently evade the gate.
  var noStatus = lifecycle.evaluate([prim("pki.x.q", null, "0.1.7")], {}, CUR);
  check("primitive with no @status fails", noStatus.failures.length === 1 && /unrecognized @status/.test(noStatus.failures[0]));
  var badStatus = lifecycle.evaluate([prim("pki.x.q", "experimntal", "0.1.7")], {}, CUR);
  check("primitive with a misspelled @status fails", badStatus.failures.length === 1);

  // 6. A deprecated primitive with NO remove-by fails.
  var depNoTarget = lifecycle.evaluate([prim("pki.x.gone", "deprecated", "0.1.7")], {}, CUR);
  check("deprecated with no remove-by fails", depNoTarget.failures.length === 1 && /remove-by/.test(depNoTarget.failures[0]));

  // 7. A deprecated primitive whose remove-by is REACHED must be removed (fail).
  var depReached = lifecycle.evaluate([prim("pki.x.gone", "deprecated", "0.1.7", "0.1.11")], {}, CUR);
  check("deprecated past remove-by fails (must remove)", depReached.failures.length === 1 && /remove it now/.test(depReached.failures[0]));

  // 8. A deprecated primitive with a FUTURE remove-by is a reminder, not a failure.
  var depFuture = lifecycle.evaluate([prim("pki.x.gone", "deprecated", "0.1.7", "9.9.9")], {}, CUR);
  check("deprecated with a future remove-by passes", depFuture.failures.length === 0 && depFuture.reminders.length >= 1);

  // 9. A ledger entry for a now-stable primitive is stale noise (reminder, not failure).
  var staleLedger = lifecycle.evaluate([prim("pki.x.done", "stable", "0.1.7")],
    { "pki.x.done": { decision: "keep-experimental", reviewBy: "9.9.9" } }, CUR);
  check("stale ledger entry for a graduated primitive is a reminder", staleLedger.failures.length === 0 && staleLedger.reminders.some(function (r) { return /stale/.test(r); }));

  // 10. The REAL repo tree passes (all overdue primitives graduated or ledgered).
  var realFail = false;
  try { require("child_process").execFileSync(process.execPath, ["scripts/check-status-lifecycle.js"], { stdio: "ignore" }); }
  catch (_e) { realFail = true; }
  check("the live lib/ tree has no overdue @status transitions", realFail === false);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
