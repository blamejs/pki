// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Does a Codex comment on a pull request report a FINISHED review of a given head?
 *
 * Codex keeps one summary comment per pull request and edits it in place, so the comment names the
 * commit it is currently working on. The sha appearing in it therefore says which commit is being
 * reviewed, not that the review is over: while one is in flight the row carrying that sha reads
 * `**Running**`. A gate that accepted the sha alone reported a reviewed head three minutes after a
 * push-fix, and the thread gate behind it then read the findings of the PREVIOUS head, so the pushed
 * code went unreviewed with every gate satisfied.
 *
 * The abbreviation length is Codex's to choose: the prose verdict prints ten characters and the
 * status table prints seven, so a fixed-width comparison matches one shape and blocks forever on the
 * other. Every hex run the comment carries is read instead, and one that is a PREFIX of this head is
 * accepted, which an unrelated sha cannot be.
 */

var RUN_IN_FLIGHT = "**Running**";
var HEX_RUN = /[0-9a-f]{7,40}/g;

/** One comment: does it report a finished review of `head`? */
function commentReportsFinishedReview(body, head) {
  if (typeof body !== "string" || typeof head !== "string" || head.length === 0) return false;
  if (body.indexOf(RUN_IN_FLIGHT) >= 0) return false;
  var runs = body.match(HEX_RUN) || [];
  for (var i = 0; i < runs.length; i++) {
    if (head.indexOf(runs[i]) === 0) return true;
  }
  return false;
}

/** The whole comment list, filtered to Codex's own. */
function anyCommentReportsFinishedReview(comments, head, isCodexLogin) {
  var list = comments || [];
  for (var i = 0; i < list.length; i++) {
    var c = list[i];
    if (!c || !c.author || !isCodexLogin(c.author.login)) continue;
    if (commentReportsFinishedReview(c.body, head)) return true;
  }
  return false;
}

module.exports = {
  commentReportsFinishedReview: commentReportsFinishedReview,
  anyCommentReportsFinishedReview: anyCommentReportsFinishedReview,
};
