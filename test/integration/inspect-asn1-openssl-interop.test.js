// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- pki.inspect.asn1 columns against openssl asn1parse, over every seed corpus.
 *
 * `pki.inspect.asn1` is shaped after `openssl asn1parse` and writes the offset, the nesting
 * depth, the header length, the content length and the constructed flag in the same fixed
 * columns. Those five numbers are the load-bearing part of the report and they come from a
 * second reader of DER headers, so they are checked against the independent parser rather
 * than against this toolkit's own decode.
 *
 * NOTHING here is a per-format list. The subjects are the seed corpora every parser already
 * ships plus the dump's own corpus, so a new format's corpus is picked up with no edit here.
 * Only canonical samples are compared: `openssl asn1parse` stops at the first byte it cannot
 * read and this report continues with a tolerant walk, which is the point of the walk and not
 * an agreement to assert. A sample OpenSSL refuses is recorded as a skip with its reason.
 *
 * The tag names and the rendered values are deliberately not compared. This report names OIDs
 * from the toolkit's own two-way registry, where `openssl` names only the OIDs its own table
 * carries, and it renders a time as the bytes on the wire where `openssl` prints its own form.
 *
 * One encoding diverges by design and is counted separately. X.690 sec. 8.1.5 gives the
 * end-of-contents value a zero length, so a tag-0 value carrying content is not one and does not
 * terminate the indefinite-length value it sits in. `openssl asn1parse` pops a level on the
 * identifier octet alone, so from that point its depth column reads one lower and the file ends
 * with an end-of-contents value that closes nothing. This report holds to the clause, which keeps
 * the values opened and the values closed balanced. A sample whose encoding carries such a value
 * is reported as a divergence with that reason, and every other sample must agree on all five
 * columns.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` before any
 * file runs.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var ctx     = require("./_interop-ctx");

var pki  = ctx.pki;
var path = ctx.path;
var fs   = ctx.fs;

var FUZZ_DIR = path.join(__dirname, "..", "..", "fuzz");

/** The five numeric columns read off one dump line. Both writers use the same layout, so the
 *  tuples compare directly and the comparison is exact rather than value-level. */
function columnsOf(text) {
  return String(text).split("\n").map(function (ln) {
    var m = /^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(cons|prim):/.exec(ln);
    return m === null ? null : m[1] + ":" + m[2] + ":" + m[3] + ":" + m[4] + ":" + m[5];
  }).filter(function (x) { return x !== null; });
}

/** The offset of the first tag-0 value carrying content, or null when the report has none. That
 *  value is the one encoding the two readers disagree on, and its offset is where the divergence
 *  can legitimately begin. */
function firstFalseEocOffset(report) {
  var ls = String(report).split("\n");
  for (var i = 0; i < ls.length; i++) {
    if (ls[i].indexOf("UNIVERSAL [0]") === -1) continue;
    var m = /^\s*(\d+):d=/.exec(ls[i]);
    if (m !== null) return Number(m[1]);
  }
  return null;
}

var CORPUS_SUFFIX = "_seed_corpus";

function corpusDirs() {
  var out = [];
  fs.readdirSync(FUZZ_DIR).forEach(function (name) {
    if (name.length <= CORPUS_SUFFIX.length || name.slice(-CORPUS_SUFFIX.length) !== CORPUS_SUFFIX) return;
    var full = path.join(FUZZ_DIR, name);
    if (fs.statSync(full).isDirectory()) out.push(full);
  });
  return out;
}

function run() {
  var dirs = corpusDirs();
  check("inspect-asn1 interop: seed corpora discovered on disk", dirs.length > 0);

  var compared = 0;
  var agreed = 0;
  var setAside = 0;
  var diverged = 0;
  var totalLines = 0;
  var disagreements = [];
  var misnamedDivergence = [];

  dirs.forEach(function (dir) {
    fs.readdirSync(dir).forEach(function (name) {
      var fp = path.join(dir, name);
      if (!fs.statSync(fp).isFile()) return;
      var der = fs.readFileSync(fp);

      var oss = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", fp], { allowNonZero: true });
      if (oss.code !== 0) { setAside += 1; return; }
      var theirs = columnsOf(oss.stdout);
      if (theirs.length === 0) { setAside += 1; return; }

      var report;
      try { report = pki.inspect.asn1(der); }
      catch (e) {
        disagreements.push(path.basename(dir) + "/" + name + " threw " + (e.code || e.constructor.name));
        return;
      }
      /* A report that stopped at a cap covers less of the file than openssl printed, which is
       * the cap doing its job rather than a disagreement. Compare the prefix it did cover.
       * A report covering NOTHING is a disagreement, not a prefix: without this the two column
       * lists would both be empty and a report of one line would agree with every sample. */
      var ours = columnsOf(report);
      if (ours.length === 0) {
        disagreements.push(path.basename(dir) + "/" + name + ": openssl printed " + theirs.length +
          " line(s) and the report printed none");
        return;
      }
      var lastLine = report.split("\n").pop();
      var partial = lastLine.indexOf("Incomplete:") === 0;
      if (partial) {
        theirs = theirs.slice(0, ours.length);
        setAside += 1;
      }
      compared += 1;
      totalLines += ours.length;
      if (theirs.join("|") === ours.join("|")) { agreed += 1; return; }
      var firstDiff = null;
      var firstDiffAt = -1;
      for (var d = 0; d < Math.max(theirs.length, ours.length); d++) {
        if (theirs[d] !== ours[d]) {
          firstDiff = "line " + d + " openssl " + JSON.stringify(theirs[d]) + " ours " + JSON.stringify(ours[d]);
          firstDiffAt = ours[d] === undefined ? Infinity : Number(String(ours[d]).split(":")[0]);
          break;
        }
      }
      /* A tag-0 value carrying content is the one encoding the two readers disagree on, and the
       * disagreement is stated in this file's header. The exemption holds only where the first
       * differing line is at or after such a value, so it cannot absorb an unrelated defect
       * earlier in the same file. */
      var falseEocAt = firstFalseEocOffset(report);
      if (falseEocAt !== null && firstDiffAt >= falseEocAt) {
        diverged += 1;
        compared -= 1;
        return;
      }
      if (falseEocAt !== null) {
        misnamedDivergence.push(path.basename(dir) + "/" + name + ": diverges at offset " +
          firstDiffAt + ", before the tag-0 value at offset " + falseEocAt);
      }
      disagreements.push(path.basename(dir) + "/" + name + ": " + theirs.length + " openssl line(s) vs " +
        ours.length + " ours; " + firstDiff);
    });
  });

  console.log("[inspect-asn1-interop] " + dirs.length + " corpus director(ies); " + compared +
    " sample(s) and " + totalLines + " rendered line(s) compared against openssl asn1parse; " +
    agreed + " sample(s) agreed on every column; " +
    diverged + " diverged on a tag-0 value carrying content (X.690 sec. 8.1.5); " +
    setAside + " set aside (openssl refused the bytes, or a cap bounded the report)");

  /* An absolute floor rather than a ratio: the corpora hold certificates, CMS messages and CRLs,
   * so a run that compared real structures clears several thousand lines. A degenerate report of
   * one line per sample cannot, which is what makes the agreement above worth reading. */
  var LINE_FLOOR = 2000;
  check("inspect-asn1 interop: the comparison covered " + totalLines + " rendered line(s), past the " +
    LINE_FLOOR + " a real corpus clears", compared > 0 && totalLines >= LINE_FLOOR);
  check("inspect-asn1 interop: every offset, depth, header length, content length and form " +
    "agrees with openssl asn1parse on " + compared + " sample(s): " + disagreements.slice(0, 5).join("; "),
  disagreements.length === 0 && agreed === compared);
  check("inspect-asn1 interop: every divergence begins at the tag-0 value that causes it: " +
    misnamedDivergence.slice(0, 5).join("; "), misnamedDivergence.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); console.log("SKIPS " + helpers.getSkips()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
