// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// check-rfc-currency -- obsoleted RFC citations name their successor.
//
// A standards citation goes stale silently. The RFC does not change, so nothing
// breaks and no test fails; the document simply starts sending readers to a
// number that is no longer the current one for its subject. That is the whole
// failure mode, and it is invisible to every other gate here.
//
// The rule is not "never cite an obsoleted RFC". Citing one is often exactly
// right: it is the document a shipped surface was built against, or the origin
// of a construction that later documents carry forward, or a historical row
// sitting beside its successor. The rule is that a reader must not have to know
// the RFC index to find out. So: every obsoleted RFC this repository cites must
// have its successor named in the same document.
//
// OBSOLETED is the ledger of what is known stale, each entry listing the
// successor numbers that satisfy it. It is checked in both directions, so an
// entry for an RFC the docs no longer cite fails too, and the ledger cannot
// quietly accumulate rows for citations that are gone.
//
// Refresh it from the online validator in the technical-writing skill:
//   node scripts/validate_technical_refs.mjs ROADMAP.md
// which reports currency rather than mere existence. This gate is offline, so
// it runs in CI without reaching the network.

var fs = require("fs");
var path = require("path");

var REPO_ROOT = path.resolve(__dirname, "..");

// Documents whose citations an operator reads. A citation in lib/ sits beside
// the code implementing it and is checked by the comment-block validator.
var DOCS = ["ROADMAP.md", "README.md", "SECURITY.md"];

// obsoleted RFC -> the successors that satisfy it. Verified against the RFC
// index; the date is the successor's publication.
var OBSOLETED = {
  "2875": { by: ["6955"] },
  "3211": { by: ["3369", "3370"] },
  "3447": { by: ["8017"] },
  "4210": { by: ["9810"] },
  "5019": { by: ["9919"] },
  "5208": { by: ["5958"] },
  "5272": { by: ["10002"] },
  "5273": { by: ["10003"] },
  "5274": { by: ["10004"] },
  "6402": { by: ["10002", "10003", "10004"] },
  "6961": { by: ["8446", "9846"] },
  "6962": { by: ["9162"] },
  "7627": { by: ["9846"] },
  "8398": { by: ["9598"] },
  "8399": { by: ["9549"] },
  "8422": { by: ["9846"] },
  "8446": { by: ["9846"] },
  "8954": { by: ["9654"] },
  "9480": { by: ["9810", "9811"] },
  "9579": { by: ["9879"] },
};

function citedNumbers(text) {
  var found = {};
  var re = /RFC\s*(\d{1,5})\b/g;
  var m;
  while ((m = re.exec(text)) !== null) found[m[1]] = true;
  return found;
}

// A number reached only through an identifier such as rfc822Name is not a
// citation. Strip those spellings before reading the citations.
function stripFieldNames(text) {
  var out = text;
  Object.keys(OBSOLETED).forEach(function (num) {
    var fieldName = OBSOLETED[num].fieldName;
    if (fieldName) out = out.split(fieldName).join("__" + num + "_FIELD__");
  });
  return out;
}

function main() {
  var findings = [];
  var citedAnywhere = {};

  DOCS.forEach(function (rel) {
    var file = path.join(REPO_ROOT, rel);
    if (!fs.existsSync(file)) return;
    var text = stripFieldNames(fs.readFileSync(file, "utf8"));
    var cited = citedNumbers(text);
    Object.keys(cited).forEach(function (num) { citedAnywhere[num] = true; });

    Object.keys(OBSOLETED).forEach(function (num) {
      if (!cited[num]) return;
      var successors = OBSOLETED[num].by;
      var named = successors.filter(function (s) { return cited[s]; });
      if (named.length === 0) {
        findings.push("  " + rel + " cites RFC " + num + ", which is obsoleted, and never names " +
          (successors.length === 1 ? "RFC " + successors[0] : "any of RFC " + successors.join(", RFC ")) +
          ". A reader is sent to a number that is no longer current for its subject. Name the successor " +
          "beside the citation, in the form the neighboring rows use.");
      }
    });
  });

  Object.keys(OBSOLETED).forEach(function (num) {
    if (!citedAnywhere[num]) {
      findings.push("  the ledger carries RFC " + num + " and no tracked document cites it any more; " +
        "delete the entry so the ledger stays the set of citations actually in force.");
    }
  });

  if (findings.length) {
    findings.forEach(function (l) { console.error(l); });
    console.error("");
    console.error("[check-rfc-currency] " + findings.length + " finding(s).");
    process.exit(1);
  }
  console.log("[check-rfc-currency] OK -- " + Object.keys(OBSOLETED).length +
    " obsoleted citation(s) tracked, each naming its successor in the same document.");
}

main();
