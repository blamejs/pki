// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// One spelling per word, across every tracked file.
//
// The documentation, the comments and error text that ship in lib/, and the
// test suite are all read by someone searching for a term. When the same word
// appears in two spellings, a search for one form silently misses the passages
// written in the other -- so the mix is a discoverability defect, not a style
// preference, and it is worth a gate rather than a habit.
//
// The check is WHOLE-WORD and CASE-INSENSITIVE, both deliberately. A substring
// match reports `publicEncrypt` as a misspelling; a case-sensitive match walks
// past a capitalized or upper-cased form while reporting the tree clean, which
// is exactly how the forms this gate now catches survived a hand scan that
// claimed to be complete.
//
// Two forms are allowed, each for a reason that is not preference:
//   - catalogue / catalogued / cataloguing -- the established form here.
//   - Enrolment -- ONLY inside RFC 8894's title, which is quoted as published.
//     Anywhere else it is a finding, so the allowance cannot spread.

var fs = require("fs");
var cp = require("child_process");
var os = require("os");
var path = require("path");

// Each entry is [nonPreferredForm, preferredForm]. Matched whole-word,
// case-insensitively. Derived forms are listed explicitly rather than by stem:
// a stem match is what produces the `publicEncrypt` class of false positive.
var FORMS = [
  ["behaviour", "behavior"], ["behaviours", "behaviors"],
  ["behavioural", "behavioral"], ["behaviourally", "behaviorally"],
  ["recognise", "recognize"], ["recognises", "recognizes"],
  ["recognised", "recognized"], ["recognising", "recognizing"],
  ["recognisable", "recognizable"],
  ["unrecognised", "unrecognized"], ["unrecognisable", "unrecognizable"],
  ["labelled", "labeled"], ["labelling", "labeling"],
  ["unlabelled", "unlabeled"],
  ["mislabelled", "mislabeled"], ["mislabelling", "mislabeling"],
  ["honour", "honor"], ["honours", "honors"],
  ["honoured", "honored"], ["honouring", "honoring"],
  ["licence", "license"], ["licences", "licenses"], ["licenced", "licensed"],
  ["defence", "defense"], ["defences", "defenses"],
  ["neighbour", "neighbor"], ["neighbours", "neighbors"],
  ["neighbouring", "neighboring"], ["neighbourhood", "neighborhood"],
  ["favour", "favor"], ["favours", "favors"],
  ["favoured", "favored"], ["favouring", "favoring"],
  ["favourable", "favorable"],
  ["analyse", "analyze"], ["analyses", "analyzes"],
  ["analysed", "analyzed"], ["analysing", "analyzing"],
  ["normalise", "normalize"], ["normalises", "normalizes"],
  ["normalised", "normalized"], ["normalising", "normalizing"],
  ["normalisation", "normalization"],
  ["organise", "organize"], ["organises", "organizes"],
  ["organised", "organized"], ["organising", "organizing"],
  ["organisation", "organization"], ["organisations", "organizations"],
  ["reorganise", "reorganize"], ["reorganising", "reorganizing"],
  ["initialise", "initialize"], ["initialises", "initializes"],
  ["initialised", "initialized"], ["initialising", "initializing"],
  ["initialisation", "initialization"],
  ["serialise", "serialize"], ["serialised", "serialized"],
  ["serialising", "serializing"], ["serialisation", "serialization"],
  ["utilise", "utilize"], ["utilised", "utilized"], ["utilising", "utilizing"],
  ["authorise", "authorize"], ["authorises", "authorizes"],
  ["authorised", "authorized"], ["authorising", "authorizing"],
  ["authorisation", "authorization"],
  ["colour", "color"], ["colours", "colors"],
  ["coloured", "colored"], ["colouring", "coloring"],
  ["centre", "center"], ["centres", "centers"], ["centred", "centered"],
  ["modelling", "modeling"], ["modelled", "modeled"],
  ["signalling", "signaling"], ["signalled", "signaled"],
  ["marshalling", "marshaling"], ["marshalled", "marshaled"],
  ["travelling", "traveling"], ["travelled", "traveled"],
  ["fulfil", "fulfill"], ["fulfils", "fulfills"],
  ["enrolment", "enrollment"], ["enrolments", "enrollments"]
];

// `Enrolment` is permitted only where the line carries RFC 8894's published
// title. Scoping the allowance to the quotation is what stops it becoming a
// blanket exemption for the word. A quotation wrapped across two source lines
// will therefore report -- rewrap it so the title sits on one line.
var RFC8894_TITLE = "Simple Certificate Enrolment Protocol";
var RFC8894_WORD_OFFSET = RFC8894_TITLE.indexOf("Enrolment");

// The offsets at which the allowed word sits INSIDE a quotation of the title on
// this line. Exempting the whole line instead would let an unrelated occurrence
// ride along beside the citation, which is the exemption spreading by another
// route.
function allowedOffsets(line) {
  var offsets = [];
  var from = 0;
  for (;;) {
    var at = line.indexOf(RFC8894_TITLE, from);
    if (at === -1) return offsets;
    offsets.push(at + RFC8894_WORD_OFFSET);
    from = at + 1;
  }
}

var SKIP_EXT = /\.(png|jpe?g|gif|ico|svg|pem|der|p12|pfx|crt|cer|key|woff2?|ttf|eot|zip|gz|tgz|pdf)$/i;

// The gate must never report on itself: this file names every non-preferred
// form by construction, and a check that flags its own word list is a check
// nobody can keep green.
var SELF = "scripts/check-spelling-consistency.js";

// Built at runtime rather than written as a literal. A raw control byte in the
// source makes git classify this file as binary, which costs line diffs, blame
// and review on every future change to the gate.
var NUL = String.fromCharCode(0);

function trackedFiles() {
  var out = cp.execFileSync("git", ["ls-files"], {
    encoding: "utf8", maxBuffer: 64 * 1024 * 1024
  });
  return out.split("\n").filter(function (f) {
    return f && !SKIP_EXT.test(f) && f !== SELF;
  });
}

var BY_LOWER = Object.create(null);
FORMS.forEach(function (p) { BY_LOWER[p[0]] = p[1]; });
var WORD_RE = /[A-Za-z]+/g;

function scanFile(file) {
  var src;
  try { src = fs.readFileSync(file, "utf8"); } catch (_e) { return []; }
  if (src.indexOf(NUL) !== -1) return [];      // binary that slipped the extension list
  var findings = [];
  var lines = src.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var allowed = allowedOffsets(line);
    var m;
    WORD_RE.lastIndex = 0;
    while ((m = WORD_RE.exec(line)) !== null) {
      var lower = m[0].toLowerCase();
      var want = BY_LOWER[lower];
      if (want === undefined) continue;
      if (allowed.indexOf(m.index) !== -1) continue;
      findings.push({ file: file, line: i + 1, found: m[0], want: want });
    }
  }
  return findings;
}

// Prove the scanner can still see a finding before trusting a clean report.
// A word list is one edit away from matching nothing, and a spelling gate that
// silently matches nothing reports exactly what a clean tree reports.
function canary() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-spell-"));
  var probe = path.join(dir, "probe.md");
  try {
    fs.writeFileSync(probe, "A NEIGHBOURING parser behaviour, and it is Recognising that.\n");
    var hits = scanFile(probe);
    var forms = hits.map(function (h) { return h.found; }).sort().join(",");
    if (forms !== "NEIGHBOURING,Recognising,behaviour") {
      throw new Error("canary: expected the three planted forms, got [" + forms + "]");
    }
    // The scoped allowance must hold, or every RFC 8894 reference becomes noise.
    fs.writeFileSync(probe, "See RFC 8894, " + RFC8894_TITLE + " (SCEP).\n");
    if (scanFile(probe).length !== 0) {
      throw new Error("canary: the RFC 8894 title should be allowed and was flagged");
    }
    // ...and must NOT hold elsewhere, or it is a blanket exemption.
    fs.writeFileSync(probe, "Device enrolment begins here.\n");
    if (scanFile(probe).length !== 1) {
      throw new Error("canary: the allowed word outside the RFC title should be flagged");
    }
    // ...including on the SAME line as the citation. A line-scoped exemption
    // would pass this file silently, which is how an exemption spreads.
    fs.writeFileSync(probe, RFC8894_TITLE + " governs device enrolment here.\n");
    var sameLine = scanFile(probe);
    if (sameLine.length !== 1 || sameLine[0].found !== "enrolment") {
      throw new Error("canary: an occurrence beside the RFC title should still be flagged, got " +
                      sameLine.length + " finding(s)");
    }
    // A binary file must be skipped, not decoded into spurious findings.
    fs.writeFileSync(probe, "behaviour" + NUL + "binary\n");
    if (scanFile(probe).length !== 0) {
      throw new Error("canary: a file containing a control byte should be skipped");
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* scratch dir */ }
  }
}

function main() {
  canary();
  console.log("[check-spelling-consistency] canary: OK - the scanner flags planted forms, " +
              "allows the RFC 8894 title, still flags that word elsewhere including beside " +
              "the title itself, and skips binary");

  var findings = [];
  trackedFiles().forEach(function (f) {
    findings = findings.concat(scanFile(f));
  });

  if (findings.length === 0) {
    console.log("[check-spelling-consistency] OK - one spelling per word across every tracked file.");
    return 0;
  }
  findings.forEach(function (f) {
    console.log(f.file + ":" + f.line + "  " + f.found + "  ->  " + f.want);
  });
  console.log("");
  console.log("[check-spelling-consistency] " + findings.length + " finding(s). " +
              "A reader searching for one form misses the passages written in the other.");
  console.log("[check-spelling-consistency] catalogue is the established form here and is not " +
              "checked; the RFC 8894 title is allowed only where that title appears.");
  return 1;
}

process.exit(main());
