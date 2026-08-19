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
// One form is allowed, and only where it is quoted: Enrolment, inside RFC
// 8894's published title. Anywhere else it is a finding, so the allowance
// cannot spread.
//
// `catalogue` is the exception to the US preference and therefore still needs a
// row, pointing the other way. Leaving the word out of the table entirely --
// the first attempt -- meant neither spelling was checked, so the tree carried
// both and the gate reported OK: an unchecked word is not a settled one.

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
  // `analyses` is deliberately absent: it is the plural of the noun `analysis`
  // in both dialects as well as the British verb form, and nothing here can
  // tell those apart. Flagging it would push an author into an error, so the
  // ambiguous member is left unchecked while its unambiguous siblings are not.
  ["analyse", "analyze"], ["analysed", "analyzed"], ["analysing", "analyzing"],
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
  ["enrolment", "enrollment"], ["enrolments", "enrollments"],
  // The one word where this repository's established form is the British one,
  // by 185 uses to 32. The direction is what the tree already says, not a
  // preference imported from the rest of the table.
  ["catalog", "catalogue"], ["catalogs", "catalogues"],
  ["cataloged", "catalogued"], ["cataloging", "cataloguing"]
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

// Binary and base64 key material only. Text formats stay in scope even when
// they are rarely prose today -- SVG carries `<title>` and `<desc>` a reader
// sees, so skipping it by extension would leave the next one unchecked. The
// control-byte test below, not this list, is what keeps binary out.
var SKIP_EXT = /\.(png|jpe?g|gif|ico|pem|der|p12|pfx|crt|cer|key|woff2?|ttf|eot|zip|gz|tgz|pdf|bin)$/i;

// A fuzz seed is an INPUT to a parser, not prose anybody reads, and its bytes
// are chosen to break a decoder rather than to say something. Most are binary,
// but nothing stops one being plain ASCII that happens to contain a word in the
// table -- and libFuzzer writes newly discovered inputs back into these
// directories, so the corpus grows without anyone writing a sentence. Scanning
// it can only ever produce a false finding that fails a workflow over a valid
// test input, so the corpus is excluded by PATH rather than left to the
// control-byte test, which an ASCII seed passes.
var SKIP_PATH = /(^|\/)[^/]*_seed_corpus\//;

function isDataPath(file) { return SKIP_EXT.test(file) || SKIP_PATH.test(file); }

// The gate must never report on itself: this file names every non-preferred
// form by construction, and a check that flags its own word list is a check
// nobody can keep green.
var SELF = "scripts/check-spelling-consistency.js";

// A line may opt out, but only by naming the WORD and SAYING WHY:
//   spelling-ok: <word> -- <reason>
// The case this exists for is a machine-readable value -- a discriminator a
// caller compares, a key a format pins -- where the word is an interface rather
// than prose, and rewriting it for consistency breaks something that reads it.
//
// It excuses that one word, not the line. A line-scoped opt-out would silently
// cover an unrelated regression that later joined the same line, which is the
// same defect as exempting a whole line because it quotes the RFC 8894 title.
//
// Both parts are mandatory: a marker missing the word or the reason does not
// suppress anything, so a half-written opt-out fails loudly instead of quietly
// widening. Suppressions are counted and printed on every run, pass or fail,
// because an opt-out nobody sees is where the defect this gate hunts ends up.
var SUPPRESS_RE = /spelling-ok:\s*([A-Za-z]+)\s*--\s*(\S.*?)\s*$/;

// Built at runtime rather than written as a literal. A raw control byte in the
// source makes git classify this file as binary, which costs line diffs, blame
// and review on every future change to the gate.
var NUL = String.fromCharCode(0);

// Every file this gate should read, which is the ones git tracks and the ones it does not yet.
//
// `git ls-files` alone answers for the committed tree, and a file written in this working session
// is not in it. So a brand-new file is invisible to the gate locally, is committed, and is read
// for the first time by CI, where the finding costs a whole run instead of a second. That is how
// a British spelling in a new test helper reached CI on a tree whose gates were green.
// `--others --exclude-standard` adds what is untracked and not ignored, which is the same set
// that is about to be committed, so the local run sees what CI will see.
function trackedFiles() {
  function ls(args) {
    return cp.execFileSync("git", ["ls-files"].concat(args), {
      encoding: "utf8", maxBuffer: 64 * 1024 * 1024
    }).split("\n");
  }
  var seen = Object.create(null);
  return ls([]).concat(ls(["--others", "--exclude-standard"])).filter(function (f) {
    if (!f || isDataPath(f) || f === SELF || seen[f]) return false;
    seen[f] = 1;
    return true;
  });
}

var BY_LOWER = Object.create(null);
FORMS.forEach(function (p) { BY_LOWER[p[0]] = p[1]; });
var WORD_RE = /[A-Za-z]+/g;

function scanFile(file, suppressed) {
  var src;
  try { src = fs.readFileSync(file, "utf8"); } catch (_e) { return []; }
  if (src.indexOf(NUL) !== -1) return [];      // binary that slipped the extension list
  var findings = [];
  var lines = src.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var opt = SUPPRESS_RE.exec(line);
    var excused = opt ? opt[1].toLowerCase() : null;
    var allowed = allowedOffsets(line);
    var m;
    WORD_RE.lastIndex = 0;
    while ((m = WORD_RE.exec(line)) !== null) {
      var lower = m[0].toLowerCase();
      var want = BY_LOWER[lower];
      if (want === undefined) continue;
      // A run of letters touching `_` or a digit is one part of an identifier,
      // not a word in a sentence -- `KIND_CATALOG`, `catalog_entry`, `sha1`.
      // Renaming an identifier for spelling changes what code refers to, which
      // is never what this gate is for. camelCase needs no rule: it is already
      // a single run, so `catalogEntry` never matches in the first place.
      var before = m.index > 0 ? line.charAt(m.index - 1) : "";
      var after = line.charAt(m.index + m[0].length);
      if (/[_0-9]/.test(before) || /[_0-9]/.test(after)) continue;
      if (allowed.indexOf(m.index) !== -1) continue;
      // Excuses THIS word only; anything else on the line is still a finding.
      if (excused !== null && lower === excused) {
        if (suppressed) suppressed.push({ file: file, line: i + 1, word: m[0], reason: opt[2] });
        continue;
      }
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
    // The plural noun must survive. If a later edit adds `analyses` to the
    // table, this fails rather than the gate quietly demanding a word that
    // would be wrong in the sentence it appears in.
    fs.writeFileSync(probe, "Both analyses agree, and the tool analyzes each input.\n");
    if (scanFile(probe).length !== 0) {
      throw new Error("canary: `analyses` is the plural of `analysis` and must not be flagged");
    }
    // A binary file must be skipped, not decoded into spurious findings.
    fs.writeFileSync(probe, "behaviour" + NUL + "binary\n");
    if (scanFile(probe).length !== 0) {
      throw new Error("canary: a file containing a control byte should be skipped");
    }
    // A fuzz seed is data, whatever its bytes look like. The ASCII case is the
    // one the control-byte test cannot catch, so the path rule has to.
    if (!isDataPath("fuzz/x509-parse_seed_corpus/plain.bin") ||
        !isDataPath("fuzz/cms-verify_seed_corpus/ascii-input") ||
        isDataPath("lib/webauthn.js") || isDataPath("docs/seed_corpus-notes.md")) {
      throw new Error("canary: the corpus path rule must cover a seed dir and nothing else");
    }
    // An identifier is not prose. Both halves of a snake_case name touch an
    // underscore, so neither is a word this gate may rewrite.
    fs.writeFileSync(probe, "KIND_CATALOG and catalog_entry and MAX_BEHAVIOUR_2 stay.\n");
    if (scanFile(probe).length !== 0) {
      throw new Error("canary: a word inside an identifier must not be flagged");
    }
    // ...but the same word standing alone in the same file still is.
    fs.writeFileSync(probe, "KIND_CATALOG holds the catalog value.\n");
    if (scanFile(probe).length !== 1) {
      throw new Error("canary: the identifier rule must not silence the bare word");
    }
    // The opt-out must name a word AND a reason. A half-written marker is a
    // free skip, and free skips are where the defect ends up.
    fs.writeFileSync(probe, "var KIND = \"catalog\";   // spelling-ok:\n");
    if (scanFile(probe).length !== 1) {
      throw new Error("canary: `spelling-ok:` with no word or reason must not suppress");
    }
    // No reason, so nothing is excused -- and the word appears twice on the
    // line, in the value and in the half-written marker, so both are findings.
    fs.writeFileSync(probe, "var KIND = \"catalog\";   // spelling-ok: catalog\n");
    if (scanFile(probe).length !== 2) {
      throw new Error("canary: `spelling-ok:` naming a word but no reason must not suppress");
    }
    fs.writeFileSync(probe, "var KIND = \"catalog\";   // spelling-ok: catalog -- machine value\n");
    var kept = [];
    if (scanFile(probe, kept).length !== 0 || kept.length !== 2 ||
        kept[0].reason !== "machine value") {
      throw new Error("canary: a complete `spelling-ok:` must suppress that word AND record it");
    }
    // ...and ONLY that word. An unrelated form joining the line is still a
    // finding, or the opt-out becomes a licence to regress the rest of the line.
    fs.writeFileSync(probe,
      "var KIND = \"catalog\";   // spelling-ok: catalog -- machine value, behaviour aside\n");
    var mixed = scanFile(probe);
    if (mixed.length !== 1 || mixed[0].found !== "behaviour") {
      throw new Error("canary: the opt-out must excuse its word only, got " +
                      mixed.map(function (f) { return f.found; }).join(","));
    }
    // The file list itself, which decides what any of the above ever runs on. A file written in
    // this working session is not in `git ls-files`, so a gate built on that alone reads the
    // committed tree and reports a clean one while the thing about to be committed carries the
    // defect. It is then read for the first time by CI, where the finding costs a whole run.
    // What is asserted is the SET: the untracked file is in it and a gitignored one is not.
    // At the repository root, because `git ls-files` reports paths relative to it and the
    // assertion below compares against exactly that name.
    //
    // The name carries this process's pid, and the file is written only after checking that
    // nothing is there. A fixed name would collide with whatever a developer happens to have at
    // that path, and clearing it first to be tidy would delete their file: a gate may not destroy
    // something it did not create in order to test itself. Nothing is removed here that this run
    // did not write.
    //
    // Its content is inert on purpose. Debris from a run that dies partway is then just an empty
    // module: still reported as untracked, still linted, but carrying no planted misspelling to
    // fail the next run with.
    // No leading dot: this repository ignores dotfiles by default, and `--exclude-standard`
    // would then leave the probe out of the very list under test, which passes for the wrong
    // reason rather than failing.
    var PROBE_BODY = "module.exports = 1;\n";
    var probeName = "check-spelling-canary-" + process.pid + ".js";
    var untracked = path.resolve(__dirname, "..", probeName);
    var probeLeft = null;
    // A probe left behind by a run that was killed before its cleanup. Its own removal is
    // insisted on below, so the only way one survives is a process that never reached that point,
    // and the next `git add -A` then commits it: three have reached a branch that way, and one
    // returns as a gate failure the day a run draws that pid again.
    //
    // Removed only where all three hold: the name has the shape this gate writes, the content is
    // exactly what it writes, and the process whose pid the name carries is gone. The name shape
    // is reserved for this gate, so a file matching it is its debris and no one else's; that is a
    // claim on the name space, and not a proof of authorship, which nothing readable off a file
    // could give. The content test is what keeps a developer who parks something at such a path
    // from losing it. The third condition keeps two gates running at once in one checkout from
    // deleting each other's live probe, which turns the other run's own listing assertion into a
    // failure.
    //
    // `process.kill(pid, 0)` signals nothing and reports whether the pid resolves. A pid that has
    // been recycled onto an unrelated process reads as alive, and the file is then left where it
    // is: erring toward keeping a file is the safe direction for a sweep.
    //
    // A probe carrying THIS pid is the one case the liveness test cannot decide, and skipping it
    // deadlocked the gate: an operating system reassigns a pid, so a run killed before its cleanup
    // could be followed by one drawing the same number. The old file then read as "this run's own,
    // handled below", the existence check refused to overwrite it, and every run failed until
    // somebody deleted it by hand. This sweep runs BEFORE the probe is written, so at this moment
    // this run has no probe: a file bearing its pid was left by a process that has already exited,
    // whatever the pid says now, and the content test still keeps a developer's own file safe.
    fs.readdirSync(path.resolve(__dirname, "..")).forEach(function (entry) {
      var named = /^check-spelling-canary-(\d+)\.js$/.exec(entry);
      if (!named) return;
      var owner = Number(named[1]);
      if (owner !== process.pid) {
        var alive = true;
        try { process.kill(owner, 0); } catch (e) { alive = e.code === "EPERM"; }
        if (alive) return;
      }
      var stale = path.resolve(__dirname, "..", entry);
      try {
        if (fs.readFileSync(stale, "utf8") !== PROBE_BODY) return;
        fs.rmSync(stale, { force: true });
      } catch (_e) { /* unreadable or already gone: left for the check below to report */ }
    });
    if (fs.existsSync(untracked)) {
      throw new Error("canary: " + probeName + " already exists and does not hold what this gate " +
                      "writes, so it will not be overwritten; remove it and run again");
    }
    try {
      fs.writeFileSync(untracked, PROBE_BODY);
      var listed = trackedFiles();
      if (listed.indexOf(probeName) === -1) {
        throw new Error("canary: an untracked file must be in the set this gate reads, or a new " +
                        "file is only ever read by CI");
      }
      if (listed.some(function (f) { return f.indexOf(".test-output/") === 0; })) {
        throw new Error("canary: a gitignored path must stay out of the set");
      }
    } finally {
      // Removal is retried over a wall-clock budget, and a failure that outlasts it is recorded for
      // the throw below. A single attempt whose failure is swallowed leaves the probe in the tree
      // while the gate reports success, and the next `git add -A` commits it. A sync-and-scan
      // client or an indexer can hold a lock on a file this new, and such a lock is measured in
      // tens of milliseconds, so the retries have to be spread over time to outlast one. A bare
      // count spins through every attempt inside a microsecond and lands in the same instant the
      // first one did.
      //
      // Recorded rather than thrown from here, because a throw inside a finally replaces whatever
      // the block was already failing with, and the canary's own verdict is the more useful one.
      var slot = new Int32Array(new SharedArrayBuffer(4));
      for (var waited = 0; waited < 5000 && fs.existsSync(untracked); waited += 25) {
        try { fs.rmSync(untracked, { force: true }); } catch (_e) { /* retried by the loop */ }
        // A synchronous wait, because this gate is synchronous throughout and a timer would need
        // the loop it is not running under. Waiting on a slot no one ever wakes runs the timeout.
        if (fs.existsSync(untracked)) Atomics.wait(slot, 0, 0, 25);
      }
      if (fs.existsSync(untracked)) probeLeft = probeName;
    }
    if (probeLeft) {
      throw new Error("canary: could not remove its own probe " + probeLeft + "; delete it " +
                      "before committing, since a gate must leave the tree as it found it");
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
  var suppressed = [];
  trackedFiles().forEach(function (f) {
    findings = findings.concat(scanFile(f, suppressed));
  });

  // Printed on every run, pass or fail. An opt-out that nobody sees accumulates.
  // One declaration can excuse several occurrences on its line -- the value and
  // the marker naming it, typically. Report the declarations, not the hits, or
  // the count reads as more opt-outs than anyone wrote.
  if (suppressed.length) {
    var seen = Object.create(null);
    var declared = [];
    suppressed.forEach(function (s) {
      var key = s.file + ":" + s.line + ":" + s.word.toLowerCase();
      if (seen[key]) { seen[key].hits++; return; }
      seen[key] = { s: s, hits: 1 };
      declared.push(key);
    });
    console.log("[check-spelling-consistency] " + declared.length + " opt-out(s) in force:");
    declared.forEach(function (key) {
      var d = seen[key];
      console.log("  " + d.s.file + ":" + d.s.line + "  " + d.s.word +
                  (d.hits > 1 ? " (x" + d.hits + ")" : "") + "  -- " + d.s.reason);
    });
  }

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
  console.log("[check-spelling-consistency] the preferred form is the US one for every word " +
              "except catalogue, which this repository settled the other way; the RFC 8894 " +
              "title is allowed only on a line carrying that title in full.");
  return 1;
}

process.exit(main());
