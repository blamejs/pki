// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * codebase-patterns — automated grep gates for code-shape bug classes.
 *
 * The toolkit accumulates a set of structural disciplines that a plain
 * unit test cannot express (they are about the SHAPE of the source, not
 * the behavior of one primitive). Each is encoded here as a scan over
 * the source tree so a regression is caught at commit time rather than
 * in review. The classes covered:
 *
 *   - SPDX license header + `"use strict"` present on every source file
 *   - top-of-file `require()` (no inline require in a function body
 *     without a documented circular-dep reason)
 *   - raw time / byte scale literals (`* 1000`, `* 1024`, `1 << N`) that
 *     must route through the `C.TIME.*` / `C.BYTES.*` helpers
 *   - AI / Claude / Anthropic / Co-Authored-By attribution tokens
 *   - deferral markers (TODO / FIXME / NOT_SUPPORTED / "// later")
 *   - fixed-budget `setTimeout` sleeps in tests (use helpers.waitUntil)
 *   - fail-open verify/parse shape (a `return true` inside a `catch`)
 *   - strong-signal duplicate code blocks (extract a shared primitive)
 *
 * The scan reads every `lib/**.js` (excluding `lib/vendor/`) and, for
 * the test-discipline classes, every `*.test.js` + non-underscore test
 * helper. A violation produces a `file:line:offending-text` line so the
 * author can fix it before commit; a single cumulative assertion at the
 * end fails the run if any class reported.
 *
 * **Exceptions** are documented at the violation site, not here. Two
 * shapes:
 *
 *   1. File-level header within the first 50 lines:
 *        // codebase-patterns:allow-file <class> — <reason>
 *      Skips every match for that class in the file.
 *
 *   2. Per-line inline marker on the same line or up to two lines above:
 *        ... // allow:<class> — <reason>
 *      Skips that single match.
 *
 * Both forms name a REGISTERED allow-class (see VALID_ALLOW_CLASSES); a
 * typo'd class suppresses nothing.
 */

var fs         = require("node:fs");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var check      = helpers.check;

var REPO_ROOT      = path.resolve(__dirname, "..", "..");
var LIB_ROOT       = path.resolve(REPO_ROOT, "lib");
var TEST_ROOT      = path.resolve(REPO_ROOT, "test");
var EXAMPLES_ROOT  = path.resolve(REPO_ROOT, "examples");

// ---------------------------------------------------------------------------
// File-tree walkers
// ---------------------------------------------------------------------------

function _walk(dir, files) {
  files = files || [];
  var base = path.basename(dir);
  if (base === "vendor" || base === "node_modules" || base === ".test-output") return files;
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var full = path.join(dir, entries[i].name);
    if (entries[i].isDirectory()) _walk(full, files);
    else if (/\.js$/.test(entries[i].name)) files.push(full);
  }
  return files;
}

function _relPath(absPath) {
  return path.relative(REPO_ROOT, absPath).replace(/\\/g, "/");
}

// Every shipped `lib/**.js` except the vendored stack.
function _libFiles() { return _walk(LIB_ROOT); }

// Test-tree walker. Detectors that need to scan tests (the
// setTimeout-as-condition-wait rule) declare `scanScope: "test"`.
//
// Scope: every `*.test.js` under `test/`, non-underscore-prefixed
// `test/helpers/*.js`, `test/smoke.js`, and every test file under
// `examples/*/test/`. Underscore-prefixed helpers (substrate consumed
// by other tests) and generated `.test-output/` logs are excluded.
function _testFiles() {
  var all = _walk(TEST_ROOT);
  try { all = all.concat(_walk(EXAMPLES_ROOT)); }
  catch (_e) { /* examples/ may be absent in some packaging */ }
  return all.filter(function (full) {
    var rel = _relPath(full);
    if (/^test\/helpers\/_/.test(rel)) return false;
    if (/^examples\/[^/]+\/node_modules\//.test(rel)) return false;
    if (/\/\.test-output\//.test(rel)) return false;
    if (/^test\/smoke\.js$/.test(rel)) return true;
    if (/^examples\/[^/]+\/test\/.*\.js$/.test(rel)) return true;
    return /\.test\.js$/.test(rel) || /\/helpers\/[^_].*\.js$/.test(rel);
  });
}

// Every Node script under scripts/ — the release / pinning / vendoring
// tooling. Detectors that guard tooling disciplines (child-process shell
// hygiene) declare `scanScope: "scripts"`.
function _scriptFiles() { return _walk(path.resolve(REPO_ROOT, "scripts")); }

// Every shell script the repo's tooling executes (scripts/, .clusterfuzzlite/).
// Same exclusions as the .js walk, plus the gitignored research dirs.
function _shellFiles() {
  var files = [];
  (function walkSh(dir) {
    var base = path.basename(dir);
    if (base === "vendor" || base === "node_modules" || base === ".test-output" ||
        base === ".git" || base === ".references" || base === ".scratch") return;
    var entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (_e) { return; }
    for (var i = 0; i < entries.length; i++) {
      var full = path.join(dir, entries[i].name);
      if (entries[i].isDirectory()) walkSh(full);
      else if (/\.sh$/.test(entries[i].name)) files.push(full);
    }
  })(REPO_ROOT);
  return files;
}

// ---------------------------------------------------------------------------
// Allow-marker filtering
// ---------------------------------------------------------------------------

// Every `// allow:<class>` suppression marker must name a REGISTERED
// detector allow-class. A typo'd or stale class suppresses NOTHING — the
// detector it claims to silence does not exist — so the violation ships
// unflagged. When you add a detector with a new allow-class, register it
// here so the marker-audit gate accepts it.
var VALID_ALLOW_CLASSES = {
  "spdx-header":                   1,
  "inline-require":                1,
  "raw-byte-literal":              1,
  "raw-time-literal":              1,
  "ai-attribution":                1,
  "defer-marker":                  1,
  "fail-open-verify":              1,
  "duplicate-block":               1,
  "test-promise-settimeout-sleep": 1,
  "comment-block-coverage":        1,
  "wiki-port-cross-artifact-drift": 1,
  "schema-build-drops-parsed-field": 1,
  "guard-shape-reinlined": 1,
  "guard-reads-runtime-live": 1,
  "ocsp-responder-auth-reinlined": 1,
  "constant-time-compare-short-circuited": 1,
  "guard-without-enforcement": 1,
  "validator-shape-reinlined": 1,
  "validator-without-enforcement": 1,
  "inline-structure-validator": 1,
  "nan-date-comparison-unguarded": 1,
  "eddsa-verify-without-loworder-gate": 1,
  "internal-provenance-in-comment": 1,
  // Enforced by scripts/check-swallow-coverage.js (the execution-traced swallow gate), not a
  // detector in this file; registered here so testAllowMarkersAreRegistered accepts the marker.
  "swallow-unverified": 1,
};

// Split content into lines, tolerant of CRLF vs LF (some helpers ship
// with CRLF endings).
function _lines(content) { return content.split(/\r?\n/); }

// _filterMarkers(matches, allowClass) — drop matches suppressed by a
// file-level `codebase-patterns:allow-file <class>` header (first 50
// lines) or a per-line `allow:<class>` marker on the match line or up
// to two lines above it.
function _filterMarkers(matches, allowClass) {
  var fileCache = {};
  var fileAllowCache = {};
  function _readContext(file) {
    if (!fileCache[file]) {
      try { fileCache[file] = _lines(fs.readFileSync(path.resolve(REPO_ROOT, file), "utf8")); }
      catch (_e) { fileCache[file] = []; }
    }
    return fileCache[file];
  }
  function _hasFileAllow(file) {
    if (Object.prototype.hasOwnProperty.call(fileAllowCache, file)) return fileAllowCache[file];
    var lines = _readContext(file).slice(0, 50);
    var re = new RegExp("codebase-patterns:allow-file\\s+" + allowClass + "\\b");
    var found = lines.some(function (l) { return re.test(l); });
    fileAllowCache[file] = found;
    return found;
  }
  function _hasLineAllow(file, lineNum) {
    var lines = _readContext(file);
    if (!lines.length) return false;
    var re = new RegExp("allow:" + allowClass + "\\b");
    return re.test(lines[lineNum - 1] || "") ||
           re.test(lines[lineNum - 2] || "") ||
           re.test(lines[lineNum - 3] || "");
  }
  return matches.filter(function (m) {
    if (_hasFileAllow(m.file)) return false;
    if (_hasLineAllow(m.file, m.line)) return false;
    return true;
  });
}

// ---------------------------------------------------------------------------
// Violation collection + reporting
// ---------------------------------------------------------------------------

var _allViolations = [];

function _report(label, matches) {
  // Collect into _allViolations rather than check()-ing per pattern so
  // every detector runs to completion and the operator sees the full
  // report; a single failing assertion at the end gates the build.
  if (matches.length > 0) {
    var preview = matches.map(function (m) {
      return "    " + m.file + ":" + m.line + ": " + String(m.content).slice(0, 120);
    }).join("\n");
    console.log("  " + label + ": " + matches.length + " violation(s):\n" + preview);
    _allViolations.push({ label: label, count: matches.length });
  } else {
    check(label, true);
  }
}

// Line-by-line lib scan. Skips comment-prefixed lines when
// opts.skipComments (the default). Returns { file, line, content }.
function _scanLib(regex, opts) {
  opts = opts || { skipComments: true };
  var matches = [];
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (opts.skipComments && /^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (regex.test(line)) {
        matches.push({ file: _relPath(files[i]), line: j + 1, content: line.trim() });
      }
    }
  }
  return matches;
}

// Strip `//` line comments, `/* */` block comments, and string/regex
// literals from source so a structural scan does not fire on prose in a
// docstring or a token that only appears inside a quoted example.
function _stripCommentsAndLiterals(content) {
  var out = content
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, "``");
  return out;
}

// Does this module take the guard-intrinsic captures? Asked of the LOADED MODULE GRAPH, not of the
// text. Node records what each module actually required, so this is the fact itself rather than a
// reading of the source, and no way of writing the import or of hiding one changes the answer: a
// commented-out or quoted require is not in the graph, and neither is a name that only appears in
// prose. Deciding it lexically needed a scanner that carried comment, string, template and regex
// state, and settling a regex against a division still wanted a real parser.
//
// guard-all deliberately does not re-export the captures, so a DIRECT require is the only way to
// reach them, and a direct require is exactly what shows up here as a child.
// The exported object literal of a module, whether or not it is handed to Object.freeze on the way
// out. The guard family freezes, so a pattern anchored on a bare `{` right after the `=` reads a
// frozen module as exporting nothing -- and a meta-check that then walks an empty list reports no
// findings while checking nothing, which is the one failure this file cannot afford. Every walk that
// reads a module's exported names off its source shares this one definition.
var EXPORT_LITERAL_RE = /module\.exports\s*=\s*(?:Object\.freeze\s*\(\s*)?\{([\s\S]*?)\}/;

function _takesCaptures(absPath) {
  var entry = require.cache[absPath];
  if (!entry) return false;   // never loaded: it cannot have taken them
  for (var i = 0; i < entry.children.length; i++) {
    if (/[\\/]guard-intrinsic\.js$/.test(entry.children[i].filename)) return true;
  }
  return false;
}


// ---------------------------------------------------------------------------
// (a) SPDX header + "use strict" on every source file
// ---------------------------------------------------------------------------

var SPDX_LINE_1 = "// SPDX-License-Identifier: Apache-2.0";
var SPDX_LINE_2 = "// Copyright (c) blamejs contributors";
var STRICT_LINE = '"use strict";';

function testSourceHeaders() {
  // class: spdx-header
  // Every .js under lib/ and every test .js MUST open with the exact
  // three-line preamble (SPDX identifier, copyright, "use strict") so the
  // license is machine-detectable in the published tarball and no file
  // runs in sloppy mode.
  var files = _libFiles().concat(_testFiles());
  var seen = {};
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (seen[rel]) continue;
    seen[rel] = true;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    if ((lines[0] || "").trim() !== SPDX_LINE_1 ||
        (lines[1] || "").trim() !== SPDX_LINE_2 ||
        (lines[2] || "").trim() !== STRICT_LINE) {
      bad.push({
        file: rel,
        line: 1,
        content: "missing/incorrect SPDX + copyright + \"use strict\" preamble (first three lines)",
      });
    }
  }
  bad = _filterMarkers(bad, "spdx-header");
  _report("every source file opens with the SPDX + copyright + use-strict preamble", bad);
}

function testShippedSourceIsAscii() {
  // class: non-ascii-source
  // Every byte of the SHIPPED source (lib/ + index.js) is ASCII. A code point
  // above 0x7F is either typographic-punctuation drift in a comment / message
  // (the house style is ASCII: '--', 'sec.', '->') or — the dangerous class —
  // a Unicode lookalike inside an identifier or string comparison (homoglyph /
  // Trojan-Source shapes), which reads identically in review while comparing
  // unequal at runtime. Byte-level and rename-proof: fires on ANY new instance
  // in any shipped file.
  var files = _libFiles().concat([path.join(REPO_ROOT, "index.js")]);
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var ln = 0; ln < lines.length; ln++) {
      for (var c = 0; c < lines[ln].length; c++) {
        if (lines[ln].codePointAt(c) > 0x7f) {
          bad.push({ file: rel, line: ln + 1, content: "non-ASCII code point U+" + lines[ln].codePointAt(c).toString(16).toUpperCase() + " in shipped source: " + lines[ln].trim().slice(0, 80) });
          break; // one report per line
        }
      }
    }
  }
  bad = _filterMarkers(bad, "non-ascii-source");
  _report("shipped source (lib/ + index.js) is pure ASCII", bad);
}

// ---------------------------------------------------------------------------
// (b) top-of-file requires — no inline require() in a function body
// ---------------------------------------------------------------------------

function testTopOfFileRequires() {
  // class: inline-require
  // A `require()` call at the top level of a module matches convention. An
  // inline `require("./foo")` in a function body is a smell unless a
  // circular-load reason is documented on the line — genuine cycles use a
  // lazy-require primitive; new code defaults to top-of-file.
  //
  // Heuristic: a `require(` call that is indented (inside some block) and
  // whose line is not a top-level `var x = require(...)` declaration. The
  // per-line `allow:inline-require` marker documents a real cycle.
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\brequire\s*\(/.test(line)) continue;
      // Top-of-file declaration form: column-0 `var/const/let NAME = require(...)`.
      if (/^(?:var|let|const)\s+[\w$]+\s*=\s*require\s*\(/.test(line)) continue;
      // A require that is indented (inside a function/block) is inline.
      if (/^\s+/.test(line)) {
        bad.push({ file: _relPath(files[i]), line: j + 1, content: line.trim() });
      }
    }
  }
  bad = _filterMarkers(bad, "inline-require");
  _report("require() calls live at top of file, not inside a function body", bad);
}

// ---------------------------------------------------------------------------
// (c) raw time / byte scale literals — route through C.TIME.* / C.BYTES.*
// ---------------------------------------------------------------------------

function testNoRawScaleLiterals() {
  // classes: raw-byte-literal (1024-scale, 1<<N size shift) +
  //          raw-time-literal (1000-scale)
  //
  // Byte-scale (`n * 1024`, `1 << 20`) and time-scale (`n * 1000`)
  // arithmetic must route through C.BYTES.kib/mib/gib(n) and
  // C.TIME.seconds/minutes/... so the toolkit's scale math has a single
  // source of truth and a reviewer never decodes a bare product. Only
  // 1000/1024-scale and the `1 << N` power-of-two size shift are flagged;
  // a bare multiple in any other context (an opcode, a field width, a
  // status count, a byte-assembly shift like `buf[i] << 16`) is NOT a
  // scale literal and is deliberately left alone.
  //
  // lib/constants.js DEFINES the scale helpers (it is the one place the
  // literals legitimately live) so it is excluded.
  var files = _libFiles();
  var badBytes = [];
  var badTime  = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/constants.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var stripped = line
        .replace(/"(?:[^"\\]|\\.)*"/g, "")
        .replace(/'(?:[^'\\]|\\.)*'/g, "")
        .replace(/`(?:[^`\\]|\\.)*`/g, "")
        .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, "")
        .replace(/0x[0-9a-fA-F]+/g, "");
      // Lines already routed through the helpers are the source of truth.
      if (/\bC\.(BYTES|TIME)\.\w+\(/.test(stripped)) continue;
      // Byte scale: `* 1024` or the power-of-two size shift `1 << N`.
      // `1 << N` anchors on a LITERAL 1 so it never matches a
      // byte-assembly shift (`buf[i] << 16`, `value << 7n`).
      if (/\*\s*1024\b/.test(stripped) || /\b1\s*<<\s*\d+\b/.test(stripped)) {
        badBytes.push({ file: rel, line: li + 1, content: line.trim() });
      }
      // Time scale: `* 1000` (seconds→ms). BigInt `* 1000n` is arbitrary-
      // precision arithmetic, not a millisecond scale, and is excluded.
      if (/\*\s*1000\b(?!n)/.test(stripped)) {
        badTime.push({ file: rel, line: li + 1, content: line.trim() });
      }
    }
  }
  badBytes = _filterMarkers(badBytes, "raw-byte-literal");
  badTime  = _filterMarkers(badTime, "raw-time-literal");
  _report("no raw byte-scale literals (use C.BYTES.kib/mib/gib)", badBytes);
  _report("no raw time-scale literals (use C.TIME.seconds/minutes/...)", badTime);
}

// ---------------------------------------------------------------------------
// (d) AI / Claude / Anthropic / Co-Authored-By attribution tokens
// ---------------------------------------------------------------------------

function testNoAiAttribution() {
  // class: ai-attribution
  // No AI / assistant attribution anywhere in shipped source or tests —
  // not in comments, not in strings. Operator-facing text describes the
  // change, never the tool that produced it.
  var re = /\b(claude|anthropic|co-authored-by|chatgpt|openai|copilot|gpt-[0-9]|llm-generated|ai-generated|sonnet|opus|haiku)\b/i;
  var files = _libFiles().concat(_testFiles());
  var seen = {};
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (seen[rel]) continue;
    seen[rel] = true;
    // This detector file names the tokens in its own regex — skip it.
    if (rel === "test/layer-0-primitives/codebase-patterns.test.js") continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var j = 0; j < lines.length; j++) {
      if (re.test(lines[j])) {
        bad.push({ file: rel, line: j + 1, content: lines[j].trim() });
      }
    }
  }
  bad = _filterMarkers(bad, "ai-attribution");
  _report("no AI / Claude / Anthropic / Co-Authored-By attribution tokens", bad);
}

// ---------------------------------------------------------------------------
// (e) deferral markers — TODO / FIXME / NOT_SUPPORTED / "// later"
// ---------------------------------------------------------------------------

function testNoDeferralMarkers() {
  // class: defer-marker
  // Every primitive ships v1-defensible in the same change; a TODO /
  // FIXME / HACK / XXX / NOT_IMPLEMENTED / "// later" marker is an
  // unfinished surface, not a shipped one.
  //
  // A lowercase `not-supported` / `unsupported` error CODE or message —
  // e.g. `throw new WebCryptoError("webcrypto/not-supported", ...)` or
  // "unsupported hash" — is the OPPOSITE of deferral: it is the complete,
  // spec-mandated runtime rejection of an unknown algorithm / OID /
  // format (WebCrypto's NotSupportedError idiom, which a codec/crypto
  // library throws constantly and correctly). Only the ALL-CAPS
  // `NOT_SUPPORTED` sentinel/constant form signals deferred work, so it
  // is matched case-sensitively; error strings are left alone.
  //
  // The SAME distinction applies to `not-implemented`, and for the same reason:
  // RFC 7030 sec. 4.3.2 defines an EST 404/501 on /fullcmc as "this service is
  // not implemented" — a runtime verdict about the SERVER we are talking to,
  // fully implemented on our side. A lowercase `not-implemented` status string is
  // therefore a shipped feature, while an ALL-CAPS NOT_IMPLEMENTED sentinel is
  // still deferred work here. Splitting them keeps the rule about OUR surface.
  var reMarker = /\b(TODO|FIXME|XXX|HACK)\b|\/\/\s*later\b/i;
  var reCapsSentinel = /\bNOT_SUPPORTED\b|\bNOT[ _-]?IMPLEMENTED\b|\bUNIMPLEMENTED\b/;
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var j = 0; j < lines.length; j++) {
      if (reMarker.test(lines[j]) || reCapsSentinel.test(lines[j])) {
        bad.push({ file: rel, line: j + 1, content: lines[j].trim() });
      }
    }
  }
  bad = _filterMarkers(bad, "defer-marker");
  _report("no TODO / FIXME / NOT_SUPPORTED / '// later' deferral markers in lib/", bad);
}

// ---------------------------------------------------------------------------
// (g) fail-open verify/parse shape — `return true` inside a catch
// ---------------------------------------------------------------------------

// The index just past the `}` that closes a block whose body starts at `from`. Falls back to the
// end of the string when the braces do not balance -- a scan that cannot find the end reports the
// whole remainder rather than nothing, so unparseable input is loud instead of silently exempt.
function _matchingBrace(text, from) {
  var depth = 1;
  for (var i = from; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return text.length;
}

function testNoFailOpenVerify() {
  // class: fail-open-verify
  // A verify / parse / validate routine that swallows an error and then
  // reports SUCCESS is fail-open: an attacker-crafted input that makes the
  // parser throw is treated as valid. The dangerous shape is a `catch`
  // block whose body returns a positive verdict — `return true`, a truthy
  // scalar, or a `{ valid: true }` / `{ verified: true }` object.
  //
  // Structural anchor: the `catch (...) {` opener, then the block's OWN span, found by matching
  // braces from that opener. The span is what makes the attribution right, and a regex cannot
  // compute it. The previous form tempered on a closing brace at the start of a line, which is the
  // shape of a brace that closes a MULTI-LINE block: a catch written on one line
  // (`catch (_e) { return null; }`) closes inline, the temper never fired there, and the scan ran
  // on into the enclosing function -- so a `return true` in an unrelated sibling was reported as
  // this catch's. Both forms are now bounded by the same rule, and the single-line catch is still
  // read, because it is the block that is found rather than a line shape.
  //
  // Comments and string literals are stripped first, so a docstring example or a quoted message
  // never trips the gate. Regex literals are NOT stripped (the walk deliberately leaves them), so a
  // `/\}/` inside a catch body could unbalance the count; an unbalanced scan therefore falls back
  // to the rest of the file rather than to nothing, because a detector that goes quiet on input it
  // cannot parse is the failure this class exists to prevent.
  var VERDICT = new RegExp("\\breturn\\s+(?:(?:true|1|valid|verified|isValid|ok)\\b" +
    "|\\{[^}]*\\b(?:valid|verified|ok|allowed|trusted)\\s*:\\s*true)");
  var CATCH_OPENER = /catch\s*\([^)]*\)\s*\{/g;
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var subject = _stripCommentsAndLiterals(content);
    CATCH_OPENER.lastIndex = 0;
    var opener;
    while ((opener = CATCH_OPENER.exec(subject)) !== null) {
      var bodyStart = opener.index + opener[0].length;
      var body = subject.slice(bodyStart, _matchingBrace(subject, bodyStart));
      if (!VERDICT.test(body)) continue;
      bad.push({
        file: _relPath(files[i]),
        line: subject.slice(0, opener.index).split(/\r?\n/).length,
        content: "fail-open verify: a catch block returns a positive verdict",
      });
      break;   // one report per file is enough to fail the gate and name the file
    }
  }
  bad = _filterMarkers(bad, "fail-open-verify");
  _report("no fail-open verify/parse (a catch that returns a success verdict)", bad);
}

// ---------------------------------------------------------------------------
// (h) comment-block coverage — every primitive is documented at its source
// ---------------------------------------------------------------------------

function testPrimitiveCommentBlocks() {
  // class: comment-block-coverage
  // Every lib primitive is documented at its source. The @module /
  // @primitive blocks feed three consumers: the generated wiki, the
  // comment-block-driven interop discovery (test/integration/auto-interop),
  // and operators reading the file. A lib source file with no @module block,
  // no @primitive block, or a @primitive whose name is not `pki.`-rooted is
  // an undocumented / mis-namespaced primitive that silently drops out of
  // all three. The authoritative, per-field check (tag ordering, signature
  // arity, @example parse) is scripts/validate-source-comment-blocks.js;
  // this is the fast structural guard in the discipline accumulator, so a
  // primitive shipped without its block fails here too.
  //
  // The parser is required lazily: it lives under the wiki example, and the
  // core discipline gate must still run in a checkout without examples/.
  var parser;
  try { parser = require("../../examples/wiki/lib/source-doc-parser"); }
  catch (_e) {
    check("comment-block coverage (source-doc-parser unavailable — skipped)", true);
    return;
  }
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    var src;
    try { src = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    // A lib module that exposes NO operator-facing namespace — shared factories
    // or helpers COMPOSED by the documented parsers (e.g. schema-pkix.js) —
    // declares `@internal` in its header and is exempt: its documented surface
    // is the modules that consume it, not itself. The declaration must be
    // explicit so the exemption is a conscious choice, never a silent omission
    // — scoped to the file HEADER (the same 50-line window the file-level
    // allow markers use), so a mid-file comment merely mentioning @internal
    // cannot drop the file out of the doc-coverage gate.
    if (/@internal\b/.test(_lines(src).slice(0, 50).join("\n"))) continue;
    var parsed = parser.parseFile(src, files[i]);
    if (!parsed.module) {
      bad.push({ file: rel, line: 1, content: "lib source file has no @module block" });
    }
    if (!parsed.primitives.length) {
      bad.push({ file: rel, line: 1, content: "lib source file has no @primitive block (undocumented primitive)" });
    }
    for (var j = 0; j < parsed.primitives.length; j++) {
      var nm = parsed.primitives[j].tags && parsed.primitives[j].tags.primitive;
      if (nm && nm.indexOf("pki.") !== 0) {
        bad.push({ file: rel, line: 1, content: "@primitive '" + nm + "' must be pki.-rooted" });
      }
    }
  }
  bad = _filterMarkers(bad, "comment-block-coverage");
  _report("every lib file documents its primitives (@module + a pki.-rooted @primitive block)", bad);
}

// ---------------------------------------------------------------------------
// (i) wiki port agrees across the Dockerfile + release-container smoke
// ---------------------------------------------------------------------------

function testWikiPortAgreesAcrossArtifacts() {
  // class: wiki-port-cross-artifact-drift
  // The wiki's HTTP port lives in examples/wiki/Dockerfile (ENV WIKI_PORT +
  // EXPOSE + HEALTHCHECK) AND in release-container.yml's post-publish smoke
  // (`-p X:X` + `curl localhost:X/healthz`). A silent mismatch ships a
  // container whose smoke curls a port nothing listens on — the release
  // passes CI but the published site is unreachable. Anchor on the
  // Dockerfile's ENV WIKI_PORT and assert every port token in the smoke
  // step matches it.
  var bad = [];
  var dockerfile;
  try { dockerfile = fs.readFileSync(path.join(REPO_ROOT, "examples/wiki/Dockerfile"), "utf8"); }
  catch (_e) { return; }
  var dfMatch = /WIKI_PORT\s*=\s*(\d+)/.exec(dockerfile);
  if (!dfMatch) return;
  var wikiPort = dfMatch[1];
  var workflowPath = ".github/workflows/release-container.yml";
  var workflow;
  try { workflow = fs.readFileSync(path.join(REPO_ROOT, workflowPath), "utf8"); }
  catch (_e) { return; }
  var lines = _lines(workflow);
  for (var i = 0; i < lines.length; i++) {
    var portMap = /-p\s+(\d+):(\d+)/.exec(lines[i]);
    if (portMap && (portMap[1] !== wikiPort || portMap[2] !== wikiPort)) {
      bad.push({ file: workflowPath, line: i + 1,
        content: "release-container.yml smoke `-p " + portMap[1] + ":" + portMap[2] +
                 "` doesn't match examples/wiki/Dockerfile WIKI_PORT=" + wikiPort });
    }
    var curlMatch = /localhost:(\d+)\/healthz/.exec(lines[i]);
    if (curlMatch && curlMatch[1] !== wikiPort) {
      bad.push({ file: workflowPath, line: i + 1,
        content: "release-container.yml smoke curls localhost:" + curlMatch[1] +
                 " but examples/wiki/Dockerfile WIKI_PORT=" + wikiPort });
    }
  }
  bad = _filterMarkers(bad, "wiki-port-cross-artifact-drift");
  _report("wiki port agrees across examples/wiki/Dockerfile + release-container.yml smoke step", bad);
}

// Extract the YAML job block (2-space-indented job key under `jobs:` through
// the last line before the next job key) whose body matches namePattern.
// Returns { key, lines } or null. Regex-lightweight, but anchored on the job's
// structural boundary (its key indent), not a frozen line count.
function _ymlJobBlock(yml, namePattern) {
  var lines = _lines(yml);
  var jobKeyRe = /^ {2}([A-Za-z0-9_.-]+):\s*$/;
  var blocks = [];
  var cur = null;
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(jobKeyRe);
    if (m) {
      if (cur) blocks.push(cur);
      cur = { key: m[1], lines: [] };
    }
    if (cur) cur.lines.push(lines[i]);
  }
  if (cur) blocks.push(cur);
  for (var b = 0; b < blocks.length; b++) {
    if (namePattern.test(blocks[b].lines.join("\n"))) return blocks[b];
  }
  return null;
}

function testPublishPathRunsCiStaticGates() {
  // class: publish-path-missing-static-gate
  // The npm-publish workflow triggers on a `v*` tag push, INDEPENDENTLY of the
  // pull_request CI that runs the static-gate battery. A gate wired only into
  // ci.yml therefore does not guard the tarball the publish path packs: a tree
  // that fails a static gate can still be packed and published from a tag push.
  // The gate set is DERIVED from ci.yml's static-gate job (not a frozen third
  // copy that silently drifts): every `run:` command in the job whose name
  // contains "Static gates" that is a correctness gate (an eslint invocation or
  // a `node scripts/…` / `node test/…` — setup like `npm ci` excluded). Each
  // derived gate must also appear in npm-publish.yml, so a gate added or renamed
  // in CI but not mirrored to the publish path fires here. A missing / renamed
  // workflow file or an unrecognizable static-gate job fails LOUDLY (a silent
  // return would mask exactly the drift this guards).
  var ciPath = ".github/workflows/ci.yml";
  var pubPath = ".github/workflows/npm-publish.yml";
  var ci, pub;
  try { ci = fs.readFileSync(path.join(REPO_ROOT, ciPath), "utf8"); }
  catch (_e) { check("ci.yml present for the publish-gate cross-check", false); return; }
  try { pub = fs.readFileSync(path.join(REPO_ROOT, pubPath), "utf8"); }
  catch (_e) { check("npm-publish.yml present for the publish-gate cross-check", false); return; }

  var job = _ymlJobBlock(ci, /name:\s*.*Static gates/i);
  if (!job) { check("ci.yml has an identifiable 'Static gates' job to derive the gate set from", false); return; }

  var isGate = function (cmd) { return /\beslint\b/.test(cmd) || /\bnode\s+(?:scripts|test)\//.test(cmd); };
  var gates = [];
  job.lines.forEach(function (ln) {
    var rm = ln.match(/^\s*run:\s*(\S.*)$/);
    if (!rm) return;
    var cmd = rm[1].trim();
    if (cmd === "|" || cmd === ">") return;            // block scalar — not a single-line gate
    if (isGate(cmd) && gates.indexOf(cmd) === -1) gates.push(cmd);
  });
  if (gates.length === 0) { check("ci.yml static-gate job yields at least one derived gate command", false); return; }

  var bad = [];
  gates.forEach(function (g) {
    if (pub.indexOf(g) === -1) {
      bad.push({ file: pubPath, line: 1,
        content: "static gate `" + g + "` runs in ci.yml's static-gate job but NOT in npm-publish.yml — a tag-push publish would pack a tree this gate never checked" });
    }
  });
  bad = _filterMarkers(bad, "publish-path-missing-static-gate");
  _report("publish path runs every static gate derived from ci.yml (" + gates.length + " gates)", bad);
}

function testFuzzSeedCorpusZipNaming() {
  // class: fuzz-seed-corpus-wrapper-name-drift
  // OSS-Fuzz's compile_javascript_fuzzer names each compiled wrapper with
  // `basename -s .js` (fuzz/<base>.fuzz.js -> $OUT/<base>.fuzz), and attaches a
  // seed corpus only when the archive is $OUT/<wrapper>_seed_corpus.zip — i.e.
  // <base>.fuzz_seed_corpus.zip. A zip written as <base>_seed_corpus.zip (the
  // `.fuzz` dropped) silently detaches the committed seeds when the canonical
  // .clusterfuzzlite build runs. Assert every seed-corpus zip target in build.sh
  // is named after the wrapper (ends in `.fuzz_seed_corpus.zip`).
  var bad = [];
  var p = ".clusterfuzzlite/build.sh";
  var src;
  try { src = fs.readFileSync(path.join(REPO_ROOT, p), "utf8"); }
  catch (_e) { return; }
  var lines = _lines(src);
  for (var i = 0; i < lines.length; i++) {
    if (/^\s*#/.test(lines[i])) continue; // a comment explaining the rule is not a violation
    var re = /(\S*?)_seed_corpus\.zip/g, m;
    while ((m = re.exec(lines[i])) !== null) {
      if (!/\.fuzz$/.test(m[1])) {
        bad.push({ file: p, line: i + 1,
          content: "seed-corpus zip '" + m[0] + "' is not named after the compiled wrapper (<base>.fuzz_seed_corpus.zip) — OSS-Fuzz / ClusterFuzzLite won't attach the seeds" });
      }
    }
  }
  bad = _filterMarkers(bad, "fuzz-seed-corpus-wrapper-name-drift");
  _report("fuzz seed-corpus zip named after the compiled wrapper (<base>.fuzz_seed_corpus.zip)", bad);
}

function testFuzzBuildInstallsJazzer() {
  // class: fuzz-build-missing-jazzer-install
  // compile_javascript_fuzzer generates each wrapper to resolve @jazzer.js/core
  // from the project's node_modules ($OUT/<project>/node_modules, copied from the
  // build root). If build.sh compiles without first installing jazzer, the
  // wrappers reference a module that isn't present and the fuzz targets can't run.
  // Two shapes satisfy the invariant before the first compile: an
  // `npm install`/`npm ci` line that names jazzer directly, or the
  // lockfile-driven form — `npm ci` against the fuzz workspace (whose
  // committed package-lock.json pins the engine with integrity hashes)
  // PLUS a step that places the verified tree at the repo root where the
  // wrappers resolve it. An `npm ci --prefix fuzz` with no root placement
  // still leaves the wrappers unresolvable, so both halves are required.
  var bad = [];
  var p = ".clusterfuzzlite/build.sh";
  var src;
  try { src = fs.readFileSync(path.join(REPO_ROOT, p), "utf8"); }
  catch (_e) { return; }
  var lines = _lines(src);
  var jazzerBeforeCompile = false, sawCompile = false, firstCompileLine = -1;
  var sawFuzzCi = false, fuzzTreeAtRoot = false;
  for (var i = 0; i < lines.length; i++) {
    if (/^\s*#/.test(lines[i])) continue; // comments describe the rule, they don't install
    if (/compile_javascript_fuzzer/.test(lines[i]) && firstCompileLine === -1) { firstCompileLine = i; sawCompile = true; }
    if (sawCompile) continue;
    if (/\bnpm\s+(install|ci)\b/.test(lines[i]) && /jazzer/.test(lines[i])) jazzerBeforeCompile = true;
    if (/\bnpm\s+ci\b/.test(lines[i]) && /--prefix[=\s]+["']?fuzz\b/.test(lines[i])) sawFuzzCi = true;
    if (sawFuzzCi && /\b(mv|cp)\b/.test(lines[i]) && /fuzz\/node_modules/.test(lines[i])) fuzzTreeAtRoot = true;
  }
  if (sawFuzzCi && fuzzTreeAtRoot) jazzerBeforeCompile = true;
  if (sawCompile && !jazzerBeforeCompile) {
    bad.push({ file: p, line: firstCompileLine + 1,
      content: "compile_javascript_fuzzer runs without a prior `npm install`/`npm ci` of @jazzer.js/core — the generated wrappers resolve jazzer from the (empty) project node_modules and cannot run" });
  }
  bad = _filterMarkers(bad, "fuzz-build-missing-jazzer-install");
  _report("fuzz build installs @jazzer.js/core before compile_javascript_fuzzer", bad);
}

function testNoUnpinnedNpmInShell() {
  // class: shell-npm-unpinned-download
  // Every npm download in repo shell tooling must be lockfile-driven
  // (`npm ci`) so the fetched tree is verified against the integrity
  // hashes a committed (or staged) package-lock.json records. A bare
  // `npm install <pkg>` / `npm update` fetches whatever the registry
  // serves at that moment — no integrity pin, and install scripts run by
  // default. The lockfile-RESOLUTION step (`npm install
  // --package-lock-only`) lives in Node scripts (scripts/pin-all.js,
  // scripts/vendor-stage.js) where it is metadata-only — no tarball is
  // fetched, no script runs — and feeds an integrity-verified `npm ci`;
  // shell files get no such exception. Comments and heredoc bodies are
  // skipped: text ADVISING an operator to `npm install @blamejs/pki` is
  // not a download. The verb is the first non-flag token after `npm`
  // so `npm --prefix x install` is caught and `npm uninstall` is not.
  var bad = [];
  var files = _shellFiles();
  for (var f = 0; f < files.length; f++) {
    var rel = _relPath(files[f]);
    var src;
    try { src = fs.readFileSync(files[f], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(src);
    var heredoc = null; // active terminator word, e.g. "EOF"
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (heredoc !== null) {
        if (line.replace(/^\t+/, "").trim() === heredoc) heredoc = null;
        continue;
      }
      if (/^\s*#/.test(line)) continue;
      var hd = /<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/.exec(line);
      if (hd) heredoc = hd[2];
      var toks = line.split(/\s+/);
      for (var t = 0; t < toks.length; t++) {
        if (toks[t] !== "npm") continue;
        var v = t + 1;
        while (v < toks.length && toks[v].charAt(0) === "-") v++;
        var verb = toks[v] || "";
        if (verb === "install" || verb === "i" || verb === "install-test" ||
            verb === "update" || verb === "add") {
          bad.push({ file: rel, line: i + 1,
            content: "`npm " + verb + "` in shell tooling downloads an unverified tree — drive the install from a package-lock.json via `npm ci` (resolve the lockfile in a Node script when one does not exist yet)" });
        }
      }
    }
  }
  bad = _filterMarkers(bad, "shell-npm-unpinned-download");
  _report("shell tooling installs npm packages only via lockfile-driven `npm ci`", bad);
}

function testSchemaBuildSurfacesEveryField() {
  // class: schema-build-drops-parsed-field
  // A schema.seq's build() is the ONLY surface a parsed field reaches the
  // operator through. A field declared in the seq (schema.field /
  // schema.optional / a trailing member's name:) whose name never appears
  // in the build body was parsed, validated, and thrown away — the
  // operator cannot see data the parser proved well-formed (the CMS
  // KeyTransRecipientInfo keyEncryptionAlgorithm shape: without it a
  // caller cannot select the unwrap algorithm for the encryptedKey it CAN
  // see). Every declared field must be referenced in the build — surfaced,
  // transformed, or consumed by a cross-field check. A seq with no build
  // hands its raw fields to the parent and is skipped. A DELIBERATE
  // non-surface takes an inline `// allow:schema-build-drops-parsed-field`
  // marker with the reason beside the seq.
  var bad = [];
  var files = _libFiles().filter(function (f) { return /schema-[^/\\]+\.js$/.test(f); });
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var src;
    try { src = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var starts = [];
    var re = /schema\.seq\(/g, sm;
    while ((sm = re.exec(src)) !== null) starts.push(sm.index + sm[0].length - 1);
    for (var s = 0; s < starts.length; s++) {
      // Bracket-walk from the opening paren to its match.
      var depth = 0, i = starts[s], end = -1;
      for (; i < src.length; i++) {
        var ch = src.charAt(i);
        if (ch === "(") depth++;
        else if (ch === ")") { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end === -1) continue;
      var span = src.slice(starts[s], end);
      // Blank nested schema.seq(...) spans so an inner seq's fields and
      // build are judged in their OWN iteration, not leaked into this one.
      var nested = /schema\.seq\(/g, nm;
      var blanked = span;
      while ((nm = nested.exec(span)) !== null) {
        if (nm.index === 0) continue;
        var nd = 0, j = nm.index + nm[0].length - 1, nEnd = -1;
        for (; j < span.length; j++) {
          var nch = span.charAt(j);
          if (nch === "(") nd++;
          else if (nch === ")") { nd--; if (nd === 0) { nEnd = j; break; } }
        }
        if (nEnd === -1) continue;
        blanked = blanked.slice(0, nm.index) + new Array(nEnd - nm.index + 1).join(" ") + blanked.slice(nEnd);
      }
      var names = [];
      var fre = /schema\.(?:field|optional)\(\s*"([A-Za-z0-9_]+)"/g, fm;
      while ((fm = fre.exec(blanked)) !== null) names.push(fm[1]);
      var tre = /schema\.trailing\(\s*\[([\s\S]*?)\]\s*,/g, tm;
      while ((tm = tre.exec(blanked)) !== null) {
        var nre = /name:\s*"([A-Za-z0-9_]+)"/g, nnm;
        while ((nnm = nre.exec(tm[1])) !== null) names.push(nnm[1]);
      }
      var buildAt = blanked.search(/\bbuild:\s*function/);
      if (buildAt === -1 || names.length === 0) continue;
      var buildBody = blanked.slice(buildAt);
      var line = src.slice(0, starts[s]).split(/\r?\n/).length;
      for (var n = 0; n < names.length; n++) {
        if (buildBody.indexOf(names[n]) === -1) {
          bad.push({ file: rel, line: line,
            content: "schema.seq declares field '" + names[n] + "' but its build() never references it — the field is parsed and dropped, invisible to the operator" });
        }
      }
    }
  }
  bad = _filterMarkers(bad, "schema-build-drops-parsed-field");
  _report("every schema.seq field is referenced by its build() (parsed data reaches the operator)", bad);
}

function testWorkflowScanFailureMasked() {
  // class: workflow-scan-failure-masked
  // A security scanner whose failure is silenced is indistinguishable from a
  // passing scan. Three shapes, each a real way a scan goes dark:
  //  (a) a scanner invocation ORed to true — an execution failure (bad token,
  //      network, config) paints the step green with no findings uploaded;
  //  (b) a SARIF upload without `actions: read` — on private/GHAS repos the
  //      upload fails a permission check and the findings never land;
  //  (c) the dependency-review config losing its zero-runtime-dep gate, its
  //      dev-scope coverage, or its default-DENY license posture.
  var wfDir = path.join(REPO_ROOT, ".github", "workflows");
  var bad = [];
  var files;
  try { files = fs.readdirSync(wfDir).filter(function (f) { return /\.ya?ml$/.test(f); }); }
  catch (_e) { return; }
  files.forEach(function (f) {
    var src = fs.readFileSync(path.join(wfDir, f), "utf8");
    var rel = ".github/workflows/" + f;
    var lines = _lines(src);
    for (var i = 0; i < lines.length; i++) {
      if (/\b(snyk|semgrep|gitleaks|osv-scanner|trivy|grype|zizmor|actionlint)\b/i.test(lines[i]) &&
          /\|\|\s*true\b/.test(lines[i])) {
        bad.push({ file: rel, line: i + 1,
          content: "a security scanner ORed to true — an execution failure reads as a clean scan; discriminate findings from failures on the exit code instead" });
      }
    }
    if (src.indexOf("upload-sarif") !== -1 && !/actions:\s*read/.test(src)) {
      bad.push({ file: rel, line: 0,
        content: "a SARIF upload without `actions: read` in the workflow permissions — the upload fails a permission check on private/GHAS repos and findings silently never land" });
    }
  });
  // (c) the dependency-review frozen config.
  var depReview;
  try { depReview = fs.readFileSync(path.join(wfDir, "dependency-review.yml"), "utf8"); }
  catch (_e) { depReview = null; }
  if (depReview !== null) {
    [
      ["optionalDependencies", "the zero-runtime-dep gate no longer sweeps every dependency field (dependencies/optional/peer/bundled)"],
      ["fail-on-scopes: runtime, development", "dependency review no longer covers the dev toolchain — in a zero-runtime-dep repo that is the entire dependency surface"],
      ["allow-licenses:", "the license gate is no longer default-DENY (an allowlist rejects every unenumerated copyleft variant; a denylist chases SPDX ids forever)"],
    ].forEach(function (t) {
      if (depReview.indexOf(t[0]) === -1) {
        bad.push({ file: ".github/workflows/dependency-review.yml", line: 0, content: t[1] });
      }
    });
  }
  bad = _filterMarkers(bad, "workflow-scan-failure-masked");
  _report("security-scan workflows fail loud (no ||-true masking, SARIF uploads carry actions: read, dependency-review keeps its zero-dep + dev-scope + default-DENY config)", bad);
}

function testSharedLeafOptionScope() {
  // class: shared-leaf-option-scope
  // An opt added to a shared codec leaf for ONE format loosens every sibling
  // that touches the leaf unless its use stays confined to the declaring
  // sites. allowFractional (RFC 3161 genTime sub-second precision) belongs to
  // the codec that implements it, the shared pkix.generalizedTime factory that
  // plumbs it as an option, and the TSP module that actually PASSES it true; a
  // format module other than TSP passing it means X.509/CRL validity times
  // silently start accepting fractional seconds (RFC 5280 forbids them) -- and
  // such a call, living in that format's own file, still trips this gate.
  var allowed = { "asn1-der.js": 1, "schema-pkix.js": 1, "schema-tsp.js": 1 };
  var bad = [];
  _libFiles().forEach(function (f) {
    var base = path.basename(f);
    if (allowed[base]) return;
    var src = fs.readFileSync(f, "utf8");
    var lines = _lines(src);
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf("allowFractional") !== -1) {
        bad.push({ file: path.relative(REPO_ROOT, f), line: i + 1,
          content: "allowFractional reached a module outside its declaring codec + TSP consumer — a shared-leaf relaxation must not creep into sibling formats (RFC 5280 times have no fractional seconds)" });
      }
    }
  });
  bad = _filterMarkers(bad, "shared-leaf-option-scope");
  _report("shared-leaf relaxations stay scoped to their declaring sites (allowFractional: codec + TSP only)", bad);
}

function testAlgorithmLookupNoDefault() {
  // class: algorithm-lookup-with-default
  // Resolving an algorithm OID through a registry table must throw on a miss.
  // A lookup that OR-defaults (`TABLE[oid] || "SHA-256"`), or a preset default
  // the lookup only conditionally overwrites, leaves a WEAKER algorithm
  // standing when a certificate names one the table does not know — the
  // attacker picks the fallback by naming an unknown OID. Two shapes:
  //  (a) any *_BY_OID / *_TABLE lookup OR-defaulted to a value;
  //  (b) a hash/algorithm var preset to a literal and later assigned from a
  //      table lookup without an intervening miss-throw.
  var bad = [];
  _libFiles().forEach(function (f) {
    var src = fs.readFileSync(f, "utf8");
    var rel = path.relative(REPO_ROOT, f);
    var lines = _lines(src);
    for (var i = 0; i < lines.length; i++) {
      if (/\w+_BY_OID\[[^\]]+\]\s*\|\|/.test(lines[i])) {
        bad.push({ file: rel, line: i + 1,
          content: "an algorithm-table lookup OR-defaulted — an unknown OID must throw, never fall back to a weaker algorithm the input selects by omission" });
      }
    }
    // (b): a quoted algorithm literal preset (any digest name or a dotted
    // OID string, case-insensitive), then a table lookup assignment to the
    // same var with no throw between them (the pre-set survives an unknown
    // OID). The scan is tempered at the enclosing function's closing brace
    // (column 0) so a lookup in a DIFFERENT function can never satisfy the
    // match; the {0,4000} is a ReDoS backstop, not the scope mechanism.
    var preset = /var\s+(\w+)\s*=\s*"(?:SHA-?\d+|MD-?\d|RIPEMD-?\d*|\d+(?:\.\d+)+)"(?:(?!throw)(?!\n\})[\s\S]){0,4000}?\1\s*=\s*\w+_BY_OID\[/i;
    if (preset.test(src)) {
      bad.push({ file: rel, line: 0,
        content: "an algorithm variable preset to a weak literal is only conditionally overwritten by a table lookup — an unknown OID leaves the weak preset standing; throw on the miss instead" });
    }
  });
  bad = _filterMarkers(bad, "algorithm-lookup-with-default");
  _report("algorithm-table lookups throw on a miss (no OR-defaults, no weak literal presets surviving unknown OIDs)", bad);
}

function testNoRemovedWebCryptoNamespace() {
  // class: removed-namespace-reference
  // pki.WebCrypto was removed in favor of pki.webcrypto.* — its classes now hang off
  // the ready Crypto instance. A lingering `pki.WebCrypto` reference in operator-facing
  // PROSE (a docstring, README, ARCHITECTURE) is a documented path that no longer
  // resolves — exactly the bug class the doc-example gate cannot see (it only runs
  // @example CODE, not prose). Anchored on the exact removed token (case-sensitive, so
  // pki.webcrypto is not matched). The surface is DERIVED, not a frozen file list:
  // every root-level `*.md` plus `index.js` plus every shipped `lib/**.js`, so a new
  // doc (MIGRATING.md, a new lib docstring) that resurrects the dead path is caught.
  // CHANGELOG.md is excluded — its record of the removal ("... pki.WebCrypto holder
  // is removed") is the correct historical note, not a live broken path.
  var rootMd = [];
  try {
    rootMd = fs.readdirSync(REPO_ROOT)
      .filter(function (n) { return /\.md$/i.test(n) && n.toLowerCase() !== "changelog.md"; })
      .map(function (n) { return n; });
  } catch (_e) { /* best-effort */ }
  var files = ["index.js"].concat(rootMd).concat(_libFiles().map(function (f) { return _relPath(f); }));
  var bad = [];
  files.forEach(function (rel) {
    var src;
    try { src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"); }
    catch (_e) { return; }
    var lines = src.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      if (/pki\.WebCrypto\b/.test(lines[i])) {
        bad.push({ file: rel, line: i + 1,
          content: "references the removed `pki.WebCrypto` namespace — the classes are now under `pki.webcrypto.*`; a stale reference is a documented path that does not resolve" });
      }
    }
  });
  bad = _filterMarkers(bad, "removed-namespace-reference");
  _report("no operator-facing file references the removed pki.WebCrypto namespace (classes moved under pki.webcrypto.*)", bad);
}

// ---------------------------------------------------------------------------
// (j) release.js waits for Codex before merge (closes the async-review race)
// ---------------------------------------------------------------------------

function testReleaseWaitsForCodex() {
  // class: release-codex-async-race
  // The review bot (chatgpt-codex-connector) reviews a PR a minute or two
  // AFTER the status checks go green; required_review_thread_resolution can
  // only block threads that EXIST at merge time, so a merge fired the
  // instant CI is green outruns the bot and ships its findings. The merge
  // path must wait for the bot to review the current head before the thread
  // gate runs. Anchors are the frozen external contract (the reviewer's
  // login string) plus rename-proof anti-pattern shapes — never a private
  // helper name, which a legitimate refactor can change without weakening
  // the gate.
  var bad = [];
  var src;
  try { src = fs.readFileSync(path.join(REPO_ROOT, "scripts/release.js"), "utf8"); }
  catch (_e) { return; }
  // Frozen contract: the reviewer's login is the one token the wait gate
  // cannot exist without. A helper rename keeps it (silent, correct);
  // removing the gate wholesale drops it (fires).
  if (src.indexOf("chatgpt-codex-connector") === -1) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "the bot-review wait gate is gone — the reviewer login (chatgpt-codex-connector) no longer appears, so nothing blocks the merge until the review of the current head lands" });
  }
  // Shape: the reviewer login arrives bare in GraphQL but "[bot]"-suffixed
  // in some REST surfaces; a strict `.login === <token>` comparison
  // misidentifies the bot and the gate silently passes un-reviewed.
  // Normalize the login (strip the suffix) before comparing.
  if (/\.login\s*===/.test(src)) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "a strict `.login ===` comparison — the bot login arrives bare in GraphQL but \"[bot]\"-suffixed in some REST surfaces; normalize the login before comparing or the gate misidentifies the reviewer and passes un-reviewed" });
  }
  // Shape: the current-head review is the NEWEST one; reviews(first:N)
  // fetches the OLDEST N, so on a PR with many review iterations the head
  // review falls outside the window and the gate falsely concludes the bot
  // hasn't reviewed.
  if (/reviews\(first:/.test(src)) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "fetch the newest reviews (reviews(last:N)) for the reviewed-head lookup — reviews(first:N) misses the current-head review on a many-iteration PR" });
  }
  bad = _filterMarkers(bad, "release-codex-async-race");
  _report("release.js waits for the review bot to review the head before merge (async-review race closed)", bad);
}

function testNoUnusedUnderscoreFunctions() {
  // class: dead-underscore-function
  // eslint no-unused-vars ALLOWS unused `_`-prefixed identifiers (the varsIgnore
  // pattern /^_/), so a `function _foo()` that is never called hides as dead
  // code the linter can't see — exactly how the _algId / _parseName /
  // _parseExtensions wrappers survived the L2 migration until the dup detector
  // caught them. A `_`-prefixed function must be intentional: referenced
  // (called, exported, or passed) at least once in its file, never an orphan.
  var bad = [];
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    var src;
    try { src = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var re = /function (_\w+)\s*\(/g, m;
    while ((m = re.exec(src)) !== null) {
      var nm = m[1];
      var refs = (src.match(new RegExp("\\b" + nm + "\\b", "g")) || []).length;
      if (refs <= 1) { // the declaration is the only occurrence — never used
        bad.push({ file: rel, line: src.slice(0, m.index).split("\n").length,
          content: "unused `_`-prefixed function " + nm + "() — dead code the eslint no-unused-vars `_` exemption hides; call it or remove it (functions must be intentional)" });
      }
    }
  }
  bad = _filterMarkers(bad, "dead-underscore-function");
  _report("no unused `_`-prefixed functions (they hide from eslint no-unused-vars)", bad);
}

function testNoRemovedNamespaceRefs() {
  // class: removed-namespace-ref
  // The v0.1.7 rename moved the x509 PARSE surface (parse / pemDecode / pemEncode) off pki.x509 to
  // pki.schema.x509, and pki.asn1.schema to pki.schema.engine, with no compat shim. A consumer left
  // calling a removed export crashes at runtime — the CLI (bin/pki.js) and the fuzz target both did,
  // because the rename sweep covered lib/test/examples but not bin/ or fuzz/. pki.x509 has since been
  // RE-INTRODUCED as the certificate-ISSUANCE producing namespace (pki.x509.sign), matching the
  // pki.cms.sign / pki.tsp.sign convention, so the guard targets the removed parse MEMBERS
  // specifically — pki.x509.{parse,pemDecode,pemEncode} still resolve nowhere and must never be
  // referenced; the sweep must be whole-repo.
  var bad = [];
  var files = _libFiles().slice();
  ["bin", "fuzz", "scripts"].forEach(function (dir) {
    try {
      fs.readdirSync(path.join(REPO_ROOT, dir)).forEach(function (f) {
        if (f.endsWith(".js")) files.push(path.join(REPO_ROOT, dir, f));
      });
    } catch (_e) { /* dir may be absent in some packagings */ }
  });
  var re = /pki\.x509\.(?:parse|pemDecode|pemEncode)\b|pki\.asn1\.schema\b/;
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    var src;
    try { src = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = src.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      if (re.test(lines[j])) {
        bad.push({ file: rel, line: j + 1,
          content: "references a removed parse export (pki.x509.parse/pemDecode/pemEncode -> pki.schema.x509, pki.asn1.schema -> pki.schema.engine) — the v0.1.7 rename left no compat shim; pki.x509.sign (issuance) is fine, but the parse members resolve nowhere; the sweep must catch bin/ and fuzz/, not only lib/test" });
      }
    }
  }
  bad = _filterMarkers(bad, "removed-namespace-ref");
  _report("no shipped source references the removed pki.x509 parse members / pki.asn1.schema namespace", bad);
}

function testFormatModulesComposeSchema() {
  // class: format-must-compose-schema
  // L2 — a format parser (x509, and later crl/cms) DECLARES a structure schema
  // and calls schema.walk; it must NOT hand-roll a positional-cursor decode
  // (node.children[idx++]) — the positional-read and duplicate-field bug classes
  // are the engine's job (lib/schema-engine.js), not a per-format loop. Reading a
  // specific field's raw bytes off a match node in a build/decode fn
  // (node.children[1]) is the legitimate escape hatch and is NOT flagged.
  var bad = [];
  var FORMAT_FILES = ["lib/schema-x509.js", "lib/schema-crl.js", "lib/schema-csr.js", "lib/schema-pkcs8.js", "lib/schema-cms.js", "lib/schema-ocsp.js", "lib/schema-tsp.js", "lib/schema-attrcert.js", "lib/schema-crmf.js", "lib/schema-pkcs12.js", "lib/schema-cmp.js", "lib/schema-smime.js", "lib/schema-csrattrs.js", "lib/schema-cmc.js"]; // + future format modules as they land
  for (var f = 0; f < FORMAT_FILES.length; f++) {
    var src;
    try { src = fs.readFileSync(path.join(REPO_ROOT, FORMAT_FILES[f]), "utf8"); }
    catch (_e) { continue; }
    var code = src.split(/\r?\n/).filter(function (l) { return !/^\s*(\/\/|\*)/.test(l); }).join("\n");
    if (/\.children\[\s*idx\b/.test(code)) {
      bad.push({ file: FORMAT_FILES[f], line: 0,
        content: FORMAT_FILES[f] + " hand-rolls a positional-cursor decode (children[idx++]) — declare a schema and schema.walk it; the engine owns positional reads / field ordering / uniqueness" });
    }
    // A format parses by composing the schema engine: schema.walk(...) directly,
    // the shared pkix.runParse(...), pkix.makeParser({ topSchema, … }) — the parser
    // factory that binds runParse to the format's identity — or its recording
    // sibling pkix.makeRecordingParser(...), which is that same factory plus the
    // provenance record a verdict verb re-derives from. All four keep the
    // coerce -> decode -> walk path in pkix, never a hand-written decoder.
    if (!/schema\.walk\(|pkix\.runParse\(|pkix\.makeParser\(|pkix\.makeRecordingParser\(/.test(code)) {
      bad.push({ file: FORMAT_FILES[f], line: 0,
        content: FORMAT_FILES[f] + " must parse by composing the schema engine — schema.walk(...), the shared pkix.runParse(...), pkix.makeParser(...) or pkix.makeRecordingParser(...), not a hand-written decoder" });
    }
    // Guard-parity: a format must NOT re-implement input coercion / PEM handling
    // / the size cap. Those live ONCE in pkix (coerceToDer / pemDecode / runParse)
    // so a new format cannot diverge on a guard the way the CRL first did (its
    // own pemDecode missed the size cap; its parse() missed PEM-buffer handling).
    if (/\bPEM_RE\s*=|input\.length\s*>=\s*5|LIMITS\.PEM_MAX_BYTES/.test(code)) {
      bad.push({ file: FORMAT_FILES[f], line: 0,
        content: FORMAT_FILES[f] + " hand-rolls PEM / input-coercion guards (PEM_RE / the '-----' sniff / the size cap) — compose pkix.pemDecode / pkix.runParse so guard parity is structural, not copied per format" });
    }
  }
  bad = _filterMarkers(bad, "format-must-compose-schema");
  _report("format parsers compose the schema engine (schema.walk), not a hand-rolled children[idx] loop (L2 must-compose)", bad);
}

function testAsn1TypesFromRegistry() {
  // class: asn1-universal-type-registry
  // L1 — the codec's universal-type metadata (tag + primitive/constructed form)
  // comes from ONE UNIVERSAL_TYPES descriptor registry; TAGS and the two
  // structural form-sets derive from it and the decode form checks consult the
  // derived sets. A flat TAGS literal or a hardcoded `=== TAGS.SEQUENCE` form
  // check reintroduces the per-type hand-coding the registry exists to remove.
  var bad = [];
  var src;
  try { src = fs.readFileSync(path.join(REPO_ROOT, "lib/asn1-der.js"), "utf8"); }
  catch (_e) { return; }
  if (!/var UNIVERSAL_TYPES\b/.test(src)) {
    bad.push({ file: "lib/asn1-der.js", line: 0,
      content: "the universal-type registry UNIVERSAL_TYPES must be the single source of tag + form metadata; TAGS and the primitive-only/constructed-only sets derive from it" });
  }
  if (/tagNumber === TAGS\.(?:SEQUENCE|SET)\b/.test(src)) {
    bad.push({ file: "lib/asn1-der.js", line: 0,
      content: "the constructed-only decode check must consult CONSTRUCTED_ONLY_UNIVERSAL_TAGS (derived from UNIVERSAL_TYPES), not a hardcoded `=== TAGS.SEQUENCE`" });
  }
  bad = _filterMarkers(bad, "asn1-universal-type-registry");
  _report("asn1 universal-type metadata is driven by the UNIVERSAL_TYPES registry (L1 descriptor engine)", bad);
}

// ---------------------------------------------------------------------------
// Allow-marker audit — every allow:<class> marker names a real detector
// ---------------------------------------------------------------------------

function testAllowMarkersAreRegistered() {
  var files = _libFiles().concat(_testFiles());
  var seen = {};
  var bad = [];
  var re = /allow:([a-z0-9][a-z0-9-]*)/g;
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    if (seen[rel]) continue;
    seen[rel] = true;
    // This file lists class ids in VALID_ALLOW_CLASSES + reasons.
    if (rel === "test/layer-0-primitives/codebase-patterns.test.js") continue;
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = _lines(content);
    for (var j = 0; j < lines.length; j++) {
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(lines[j])) !== null) {
        if (!VALID_ALLOW_CLASSES[m[1]]) {
          bad.push({ file: rel, line: j + 1, content: "unregistered allow-class '" + m[1] + "'" });
        }
      }
    }
  }
  _report("every allow:<class> marker names a registered detector class", bad);
}

// ---------------------------------------------------------------------------
// Known-antipattern catalogue — scanScope-routed regex detectors (n=1 gate)
// ---------------------------------------------------------------------------

// Each entry fires at n=1 — any file matching the regex (and not in the
// entry's allowlist, and not satisfying the companion `requires` shape)
// fails the gate with a pointer to the primitive that should replace it.
//
// Per-entry `scanScope` selects the file set:
//   - "lib"  (default) — every .js under lib/ except lib/vendor/
//   - "test"           — every *.test.js + non-underscore helper (the
//                        waitUntil-vs-setTimeout rule runs here)
var KNOWN_ANTIPATTERNS = [
  {
    // The one test-discipline detector carried in the unified catalogue:
    // a fixed-budget setTimeout sleep used as a condition-wait in a test.
    id: "test-promise-settimeout-sleep",
    primitive: "helpers.waitUntil(predicate, { timeoutMs, label }) for condition-waits OR helpers.passiveObserve(ms, label) to verify the ABSENCE of an event over a window",
    scanScope: "test",
    // Covers every callable Promise+setTimeout sleep form:
    //   await new Promise(r => setTimeout(r, 100));
    //   await new Promise((resolve) => { setTimeout(resolve, 100); });
    //   await new Promise(function (r) { setTimeout(r, 100); });
    regex: /new\s+Promise\s*\(\s*(?:function\s*[\w$]*\s*\([^)]*\)\s*\{|\([^)]*\)\s*=>\s*\{?|[\w$]+\s*=>\s*\{?)[\s\S]{0,200}?setTimeout\s*\(/,
    skipCommentLines: true,
    allowlist: [
      // helpers.waitUntil / passiveObserve ARE the polling primitives —
      // they have to use setTimeout internally. The wait module is their
      // home, not a condition-wait consumer.
      "test/helpers/wait.js",
      // This catalogue carries the bug pattern as a regex literal.
      "test/layer-0-primitives/codebase-patterns.test.js",
    ],
    reason: "Every 'passes alone, fails under SMOKE_PARALLEL=64 / macOS' test flake is the same root cause: a fixed-budget setTimeout sleep too short for runner-contention reality. helpers.waitUntil polls the actual condition every 25ms up to a 5000ms cap and exits early when the predicate is truthy — fast platforms finish in milliseconds, contended platforms get the full budget. helpers.passiveObserve(ms, label) is the sibling for verifying the ABSENCE of an event over a window. Convert a hand-tuned sleep to waitUntil rather than bumping N.",
  },

  {
    // A caught error discarded (underscore binding) and swallowed into a bare
    // `return` inside a test assertion. This is the lint-silence reflex: when
    // no-unused-vars flags `catch (e)`, renaming e->_e to pass the linter hides
    // that the try/catch itself was scaffolding — a throw from the code under
    // test becomes a bare `return false/null`, so a regression fails the check
    // WITHOUT the diagnostic error. Assert directly (let the throw surface), or
    // if the error is genuinely expected, capture it (`catch (e) { code = e.code }`).
    id: "test-catch-underscore-return-swallow",
    primitive: "assert directly and let a throw surface (more diagnostic), or capture the error you claim to expect — never rename catch(e)->catch(_e) to silence no-unused-vars around your own throw-capable call",
    scanScope: "test",
    regex: /catch\s*\(\s*_\w*\s*\)\s*\{\s*return\b/,
    skipCommentLines: true,
    allowlist: [
      // The scanner harness itself: its catch(_e){ return } guards skip files
      // that do not exist / do not parse during the sweep — scan robustness,
      // not a swallowed assertion. This file also carries the pattern literal.
      "test/layer-0-primitives/codebase-patterns.test.js",
    ],
    reason: "Renaming catch(e)->catch(_e) to clear no-unused-vars is a silence, not a fix: the `_`-prefix tells the linter the error is intentionally discarded, but a `catch (_e) { return <sentinel> }` around the code under test turns a real throw into a bare false/null, so a reintroduced bug fails the check with no underlying error. The no-unused signal means the binding (and usually the try/catch that introduced it) is dead — remove the catch and assert directly (the throw is the most diagnostic failure), or capture the error if you actually expect it. See feedback_rewrite_over_silence.",
  },
  {
    // A cross-check that could not run (an absent oracle capability) must be
    // recorded with ctx.skip / helpers.skip, NEVER faked as check(<skip msg>, true).
    id: "interop-skip-counted-as-pass",
    primitive: "record an un-runnable cross-check with ctx.skip(reason) / helpers.skip(reason) — never check(<skip message>, true), which tallies the skip as a pass and hides that the cross-check did not run",
    scanScope: "test",
    regex: /\.check\(\s*["'][^"']*(?:skip|Skip)[^"']*["']\s*,\s*true\s*\)/,
    skipCommentLines: true,
    allowlist: [
      // This file carries the pattern literal in its own reason/detector text.
      "test/layer-0-primitives/codebase-patterns.test.js",
    ],
    reason: "check(<reason>, true) as a skip is the skip-counted-as-pass bug: a run that skipped a cross-check (e.g. the OpenSSL interop oracle predates ML-DSA) reports the SAME 'N checks passed' as a run that actually performed it, so a coverage gap reads as coverage. helpers.skip / ctx.skip increments a separate skip counter (never `_checks`) and the interop runner + test-integration report skips distinctly.",
  },

  // (Per-format RFC-conformance rules — a version==N check, a status
  //  whitelist, a cross-field coherence rule — are guarded by the behavioral
  //  RED conformance vectors in each format's layer-0 test, which drive parse()
  //  on the malformed input and assert the reject. Those run in smoke and catch
  //  removal of the runtime check directly. A codebase-patterns detector here
  //  is reserved for a GENERAL, codebase-wide VECTOR shape that would fire on a
  //  new instance introduced ANYWHERE — not a frozen list of one format's
  //  error-code strings or a length-bounded regex over one named function,
  //  which drift on any legitimate rename / growth and detect nothing new.)

  // --- DER codec correctness (lib scope) ---
  {
    id: "asn1-quadratic-bigint-accumulator",
    primitive: "one-shot BigInt('0x'+hex) (base-256) or a bounded base-128 fold, with a C.LIMITS byte cap BEFORE the read — never a per-byte `<< n) | BigInt(` shift-accumulate",
    regex: /<<\s*[78]n\)\s*\|\s*BigInt\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A byte-at-a-time BigInt shift-accumulator over attacker-length content is O(n^2) in the content length — the quadratic decoder-DoS class (readInteger + decodeOidContent). The 16 MiB document cap does not bound a single value, so a ~2 MB INTEGER/OID pins a core for minutes. Build the magnitude in one pass and cap the per-value byte length.",
  },

  // --- WebCrypto access-control + conformance (lib scope) ---

  // --- X.509 parser fail-closed (lib scope) ---
  {
    id: "context-node-content-deref-no-primitive-reader",
    primitive: "read a context-tagged IMPLICIT primitive leaf through asn1.read.{octetStringImplicit,integerImplicit,nullImplicit,bitStringImplicit}(node, tag) — never Buffer.from(node.content) on a context node, whose content is null when the node is constructed",
    regex: /Buffer\.from\(\s*\w+\.content\s*\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A context-class node carrying an IMPLICIT primitive value (a keyIdentifier [0] OCTET STRING, a serial [2] INTEGER) is only guaranteed primitive if a reader enforces it. A constructed context node has children and a NULL content, so Buffer.from(node.content) throws a raw TypeError on hostile input (fuzz-found in the AKI extension decoder) instead of a typed fail-closed reject. Route every context-primitive read through the asn1.read.*Implicit reader, which asserts the primitive form and rejects the constructed shape with asn1/expected-primitive.",
  },
  {
    id: "x509-version-unvalidated-enum",
    primitive: "read the version as a BigInt and allowlist {0n,1n,2n} (reject explicit 0n as a DER DEFAULT, gate extensions on v3) — never `Number(read.integer(...)) + 1`",
    regex: /Number\(\s*asn1\.read\.integer\([\s\S]*?\)\s*\)\s*\+\s*1/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Number(readInteger())+1 as an enum accepts an arbitrary/negative/precision-losing version. Any small-enum INTEGER field (cert version, future CRL/OCSP version) needs a BigInt allowlist, not a coerce-and-offset.",
  },

  // --- OID + version single-source (lib scope) ---
  {
    id: "oid-fromarcs-bigint-sign-guard",
    primitive: "a `< 0n` sign guard before the bigint branch returns a.toString() — the number branch already enforces >= 0, so both branches must enforce the same non-negative contract",
    regex: /typeof\s+\w+\s*===\s*"bigint"\s*\)\s*return\s+\w+\.toString\(\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "fromArcs's bigint branch returning a.toString() with no sign check emits a malformed OID like \"2.-5.1\" while the number branch rejects a negative — a self-inconsistent contract that blows up late, away from the bad arc. (Anchored on `return X.toString()` so a bigint branch that returns a validating expression like `a >= 0n` is not flagged.)",
  },
  {
    id: "oid-dotted-decimal-literal",
    primitive: "declare OIDs by family via pki.oid.registerFamily(base, {name: leaf}) — a dotted-decimal OID literal in source both re-spells the arc hierarchy and reads as an IP to a supply-chain scanner",
    regex: /"[0-9]+(?:\.[0-9]+){3,}"/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A 4+-arc dotted-decimal string literal in executable lib code is an OID re-spelled as a full path (should be a family base + leaf) and matches a URL/IP heuristic (Socket 'URL strings'). Route OIDs through the family registry; dotted strings belong only in comments/@example and dotted<->arc format code.",
  },
  {
    id: "oid-arc-unsafe-integer",
    primitive: "OID arc validation must use Number.isSafeInteger (not Number.isInteger) — an integer above 2^53 is not representable precisely as a Number, so a large arc must be supplied as a BigInt",
    regex: /=== "number" && Number\.isInteger\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Number.isInteger accepts integers beyond MAX_SAFE_INTEGER that a Number cannot represent precisely — an OID arc validated that way silently loses precision. Use Number.isSafeInteger so a large arc must be a BigInt.",
  },
  {
    id: "asn1-integer-cap-ignores-sign-pad",
    primitive: "the INTEGER length cap must allow the DER sign octet (cap + 1) — a positive INTEGER at the magnitude cap with its top bit set carries a leading 0x00, so a bare `> DER_MAX_INTEGER_BYTES` rejects legitimate key material",
    // Any identifier's `.length > DER_MAX_INTEGER_BYTES` with no `+ 1` sign-octet
    // allowance — anchored on the frozen constant + the missing-`+ 1` lookahead,
    // NOT the `c` local (a refactor to `body`/`magnitude` must not go silently
    // green while dropping the sign pad).
    regex: /\w+\.length > constants\.LIMITS\.DER_MAX_INTEGER_BYTES(?!\s*\+\s*1)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A `<content>.length > DER_MAX_INTEGER_BYTES` cap with no `+ 1` for the DER sign octet rejects a positive INTEGER at the magnitude cap whose top bit is set (an RSA-131072 modulus). The cap bounds the magnitude; DER content may carry one leading 0x00 sign pad.",
  },

  // --- DER encoder/decoder canonical + range conformance (lib scope) ---
  {
    id: "asn1-utctime-year-window",
    primitive: "build.utcTime must reject a year outside 1950..2049 (RFC 5280 §4.1.2.5.1) before reducing it mod 100 — a bare %100 wraps 2050 to 1950",
    regex: /getUTCFullYear\(\)\s*%\s*100/, skipCommentLines: true, allowlist: [],
    reason: "UTCTime carries a 2-digit year and the reader pivots <50=>20YY else 19YY, so encoding a year outside 1950..2049 without a window guard silently shifts a security-critical validity timestamp a century. Range-check before %100.",
  },

  {
    // A child-process spawn that pairs an args ARRAY with a shell — the
    // shell form concatenates the arguments onto the command line WITHOUT
    // escaping (Node's DEP0190; the CVE-2024-27980 .cmd-shim mitigation is
    // why a shell is needed for npm/npx on Windows at all), so an argument
    // containing a space or shell metacharacter is reinterpreted by
    // cmd.exe / sh. The scan stops at the call's own `);` terminator so a
    // benign neighboring call can never satisfy the shell-token match.
    id: "spawn-args-array-with-shell",
    primitive: "one explicitly-quoted command STRING + shell:true with NO args array (scripts/release.js builds it via _quoteWinArg), or keep the args array and drop shell: entirely for direct-executable spawns",
    scanScope: "scripts",
    regex: /\b(?:spawnSync|spawn|execFileSync|execFile)\s*\(\s*[^,()]+,\s*(?:\[|[A-Za-z_$][\w$]*\s*,)(?:(?!\)\s*;)[\s\S]){0,600}?\bshell:\s*(?:true\b|process\.platform)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "spawnSync(cmd, argsArray, { shell: true }) does not escape the array — Node concatenates it onto the shell command line (DEP0190), so an argument with a space, quote, &, | or %VAR% is reinterpreted by the shell instead of arriving as one argv entry. Where a shell is unavoidable (Windows resolves npm/npx through .cmd shims that refuse to spawn shell-less since the CVE-2024-27980 hardening), build a single command string with each argument explicitly quoted and pass no args array; where the target is a real executable, drop shell: and keep the array.",
  },
  {
    // A NamedBitList BIT STRING (KeyUsage, PKIFailureInfo, ...) whose X.690 §11.2.2
    // minimal-encoding rule is re-derived inline instead of composing the shared
    // schema.assertMinimalNamedBits — the exact drift that let the trailing-zero
    // reject diverge across three formats (one omitted the trailing-all-zero-octet
    // check). Anchored on the lowest-used-bit test SHAPE `>> <ident>) & 1) !== 1`,
    // rename-proof and codebase-wide; the shared helper is the ONE allowed home.
    id: "named-bitlist-minimal-encoding-inlined",
    primitive: "schema.assertMinimalNamedBits(unusedBits, bytes, fail) — the single X.690 §11.2.2 NamedBitList trailing-zero-bit rule; never re-derive the `(last >> unusedBits) & 1) !== 1` test per format",
    regex: />>\s*[\w.]+\s*\)\s*&\s*1\s*\)\s*!==\s*1/,
    skipCommentLines: true,
    allowlist: [
      "lib/schema-engine.js",
    ],
    reason: "The X.690 §11.2.2 minimal-DER rule for a NamedBitList (drop every trailing zero bit, giving one canonical encoding per value) was re-implemented in three format modules with divergent strictness — one omitted the trailing-all-zero-octet reject — a DER-canonicalization bypass in which a non-minimal encoding of the same failInfo/keyUsage value decodes in one format and rejects in another. Centralized as schema.assertMinimalNamedBits so every format enforces the identical rule; a new inline `(last >> unusedBits) & 1) !== 1` re-derivation must compose the helper instead.",
  },
  {
    // A format matches()/detector that hand-rolls the root-SEQUENCE guard
    // (`root.tagClass !== "universal" ... root.tagNumber !== <ID>.SEQUENCE ...
    // return false`) instead of composing pkix.rootSequenceChildren — the shape
    // 8 detectors re-inlined before extraction. Anchored on the root-guard CODE
    // SHAPE (a `.tagClass !== "universal"` negative test tempered up to a
    // `return false`), not a function name (renameable), so it fires on a NEW
    // detector in a file never reviewed and stays silent once the guard routes
    // through pkix.
    id: "detector-reinlines-root-tag-guard",
    primitive: "pkix.rootSequenceChildren(root, minLen, maxLen) for a format detector's root universal-SEQUENCE + arity guard; the per-node probe composes schema.isUniversal/isContext/isUniversalOneOf/isContextOneOf/isContextInRange",
    regex: /\.tagClass\s*!==\s*"universal"(?:(?!\n\})[\s\S]){0,400}?return false/,
    skipCommentLines: true,
    allowlist: [
      "lib/schema-pkix.js",
    ],
    reason: "Every format's matches() detector re-inlined the root-SEQUENCE guard `!root || root.tagClass !== \"universal\" || root.tagNumber !== TAGS.SEQUENCE` and the per-node `x.tagClass === class && x.tagNumber === TAGS.Y` probe, with one module hand-rolling a local tag predicate twice. Centralized as pkix.rootSequenceChildren + the schema.is{Universal,Context}[OneOf|InRange] predicates so a detector composes them; a new detector re-inlining the root guard (a `.tagClass !== \"universal\"` test that returns false) must route through the shared helper. This replaces the KNOWN_CLUSTERS matches() whitelist — after extraction the seq/probe shingle dissolves.",
  },
];

function testKnownAntipatterns() {
  var libFiles  = null;
  var testFiles = null;
  var scriptFiles = null;
  var allBad = [];
  for (var ai = 0; ai < KNOWN_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_ANTIPATTERNS[ai];
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    var files;
    if (ap.scanScope === "test") {
      if (testFiles === null) testFiles = _testFiles();
      files = testFiles;
    } else if (ap.scanScope === "scripts") {
      if (scriptFiles === null) scriptFiles = _scriptFiles();
      files = scriptFiles;
    } else {
      if (libFiles === null) libFiles = _libFiles();
      files = libFiles;
    }
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      if (allowSet[rel]) continue;
      var content;
      try { content = fs.readFileSync(files[fi], "utf8"); }
      catch (_e) { continue; }
      var subject = content;
      if (ap.skipCommentLines === true) {
        subject = _lines(content).map(function (ln) {
          if (/^\s*(\*|\/\/|\/\*)/.test(ln)) return "";
          return ln;
        }).join("\n");
      }
      var m = ap.regex.exec(subject);
      if (!m) continue;
      if (ap.requires && ap.requires.test(content)) continue;
      var lineNum = subject.slice(0, m.index).split(/\r?\n/).length;
      bad.push({ file: rel, line: lineNum, content: "antipattern '" + ap.id + "' — use " + ap.primitive });
    }
    if (bad.length) {
      allBad = allBad.concat(bad);
      _report("known-antipattern '" + ap.id + "' — use " + ap.primitive, bad);
    }
  }
  if (allBad.length === 0) check("known-antipattern catalogue (n=1 gate)", true);
}

// ---------------------------------------------------------------------------
// Strong-signal duplicate-block detector (token-shingle clustering)
// ---------------------------------------------------------------------------

// A stable, paste-able cluster fingerprint: the canonical normalized
// token-block from the first cited site — sliced from the file at the
// recorded line range, comments stripped, whitespace collapsed, hashed
// and truncated. Operators paste it into KNOWN_CLUSTERS when allowlisting.
function _clusterFingerprint(site) {
  try {
    var src = _lines(fs.readFileSync(path.resolve(REPO_ROOT, site.file), "utf8"));
    var slice = src.slice(site.line - 1, site.endLine).join("\n");
    var stripped = slice
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .replace(/\/\/[^\n]*/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    return nodeCrypto.createHash("sha256").update(stripped).digest("hex").slice(0, 12);
  } catch (_e) {
    return "??????????";
  }
}

// Token normalizer: identifiers/strings/numbers/regexes collapse to
// placeholders so the SHAPE of a block matches regardless of naming or
// line layout. Keywords / well-known globals survive as themselves.
var _JS_KEYWORDS = {
  "var": 1, "let": 1, "const": 1, "function": 1, "return": 1, "if": 1,
  "else": 1, "for": 1, "while": 1, "do": 1, "switch": 1, "case": 1,
  "default": 1, "break": 1, "continue": 1, "try": 1, "catch": 1,
  "finally": 1, "throw": 1, "new": 1, "this": 1, "null": 1, "undefined": 1,
  "true": 1, "false": 1, "typeof": 1, "instanceof": 1, "in": 1, "of": 1,
  "delete": 1, "void": 1, "async": 1, "await": 1, "class": 1, "extends": 1,
  "super": 1, "import": 1, "export": 1, "from": 1, "as": 1, "with": 1,
  "yield": 1, "static": 1, "require": 1, "module": 1, "exports": 1,
  "Buffer": 1, "process": 1, "console": 1, "Promise": 1, "Object": 1,
  "Array": 1, "String": 1, "Number": 1, "Boolean": 1, "Date": 1,
  "RegExp": 1, "Error": 1, "Math": 1, "JSON": 1, "Symbol": 1, "Map": 1,
  "Set": 1, "BigInt": 1,
};

function _normalizeJsLine(line) {
  line = line.replace(/\/\/.*$/, "");
  line = line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "_STR");
  line = line.replace(/(^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\/((?:\\.|[^/\\\n])+)\/[gimsuy]*/g, "$1_RE");
  line = line.replace(/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?n?\b|0x[0-9a-fA-F]+n?/g, "_NUM");
  line = line.replace(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g, function (name) {
    if (name === "_STR" || name === "_NUM" || name === "_RE") return name;
    return Object.prototype.hasOwnProperty.call(_JS_KEYWORDS, name) ? name : "_ID";
  });
  line = line.replace(/([.(){}[\];,:?!&|^~<>=+\-*/%@])/g, " $1 ");
  line = line.replace(/\s+/g, " ").trim();
  return line;
}

function _tokenizeFile(absPath) {
  var content;
  try { content = fs.readFileSync(absPath, "utf8"); }
  catch (_e) { return null; }
  var lines = _lines(content);
  var tokens = [];
  for (var li = 0; li < lines.length; li++) {
    var rawLine = lines[li];
    if (/^\s*(\/\/|\*|\/\*)/.test(rawLine)) continue;
    var norm = _normalizeJsLine(rawLine);
    if (norm.length === 0) continue;
    var lineToks = norm.split(/\s+/).filter(function (t) { return t.length > 0; });
    for (var ti = 0; ti < lineToks.length; ti++) tokens.push({ tok: lineToks[ti], line: li + 1 });
  }
  return { rel: _relPath(absPath), tokens: tokens };
}

// Language-idiom filter: a shingle that is mostly declarations / require
// boilerplate / object-literal key-value runs is JS convention shared by
// every file, not an extractable primitive. Drop those before clustering.
function _isBoilerplate(slice) {
  var toks = slice.map(function (t) { return t.tok; });
  var joined = toks.join(" ");
  var requireCalls = (joined.match(/\brequire\s+\(\s+_STR\s+\)/g) || []).length;
  if (requireCalls >= 2) return true;
  if (requireCalls === 1 && slice.length <= 10) return true;
  if (/module\s+\.\s+exports\s+=\s+\{/.test(joined)) return true;
  // Object-literal key-value runs are JS convention every builder shares, not
  // extractable logic. Count a `key: <simple value>,` pair for ANY simple value —
  // an identifier, a `src.prop[.prop…]` access, a string / number / regexp, or a
  // boolean/null literal. A format parser's `return { … }` (fields mapped off one
  // source object) and its `makeParser({ pemLabel: "…", ErrorClass: …, … })`
  // config object are both this shape, so every format's output-assembly + wiring
  // matches without being a shared primitive — the parse LOGIC is already factored
  // into pkix.runParse / signedEnvelope / makeParser. (The prior regex counted
  // only identifier values, so string-valued config objects escaped the filter.)
  var kvPairs = (joined.match(/_ID\s+:\s+(?:_ID(?:\s+\.\s+_ID)*|_STR|_NUM|_RE|true|false|null)\s+,/g) || []).length;
  if (kvPairs >= 4) return true;
  // Module-init declaration runs — `var X = obj.factory(...)` / `var X = fn(...)` —
  // are the boilerplate every module's header shares: a format module instantiates
  // its pkix / schema sub-schemas this way (`var NAME = pkix.name(NS)`, `var TIME =
  // schema.time(NS)`), each under its own namespace, so the run matches in shape
  // without being an extractable primitive (the factories themselves already live
  // in pkix). Different factories per format = nothing more to extract.
  var factoryDecls = (joined.match(/\bvar\s+_ID\s+=\s+_ID(?:\s+\.\s+_ID)*\s+\(/g) || []).length;
  // A run of 3+ `var X = obj.method(...)` instantiations is a format module's
  // sub-schema glue (`var NS = pkix.makeNS(...)` + `var ALGORITHM_IDENTIFIER =
  // pkix.algorithmIdentifier(NS)` + `var ATTRIBUTE = pkix.attribute(NS)`, each
  // under its own namespace). The factories already live in pkix, so the run
  // repeats in shape without being extractable. (The shared cms/csr/pkcs8 header
  // prefix is exactly this 3-instantiation window; a format with more sub-schemas
  // has 4+.)
  if (factoryDecls >= 3) return true;
  // The module-header TRANSITION: a slice that mixes a top-of-file require with a
  // factory-instantiation run is the header every format module shares (the 5
  // requires flow into `var NS = pkix.makeNS(...)` + `var X = pkix.factory(NS)`).
  // require tokens only appear at the top of a file (the top-of-file-require rule),
  // so any window carrying a require plus >=2 factory decls is that header region,
  // not extractable logic — the factories already live in pkix. This catches the
  // csr/pkcs8/cms (and future ocsp/tsp) header cluster that lands between the
  // require-run and factory-run thresholds above (a format with 2-3 sub-schemas).
  if (requireCalls >= 1 && factoryDecls >= 2) return true;
  // Format-module FOOTER glue — the parse / PEM wiring block. `pemDecode` /
  // `pemEncode` are thin one-liners delegating to the shared pkix helpers, and the
  // `var parse = pkix.makeParser({ pemLabel, ... })` config object precedes them.
  // A window of 2+ such delegations, or the config-object tail (kv pairs) meeting
  // the first delegation, is that block — the parse LOGIC already lives in pkix, so
  // it repeats in shape without being extractable (the wrappers must stay
  // per-module for their @primitive wiki blocks; see KNOWN_CLUSTERS).
  var delegationReturns = (joined.match(/\breturn\s+_ID\s+\.\s+_ID\s+\(/g) || []).length;
  if (delegationReturns >= 2) return true;
  if (kvPairs >= 2 && delegationReturns >= 1) return true;
  if (/\bclass\s+_ID\s+extends\s+_ID/.test(joined)) return true;
  var declTokens = toks.filter(function (t) {
    return t === "=" || t === ";" || t === "," || t === ":" ||
           t === "_STR" || t === "_NUM" || t === "var" || t === "const";
  }).length;
  if (declTokens >= Math.floor(slice.length * 0.55)) return true;
  return false;
}

function _sliceFingerprintExact(slice) {
  return slice.map(function (t) { return t.tok; }).join(" ");
}

// Single-threaded shingle scan — the toolkit's source tree is small
// enough that the worker-thread fan-out the larger sibling framework uses
// would be pure overhead. Returns { "<size>": { fp -> [{file,line,endLine}] } }.
function _scanShingles(absFiles, opts) {
  var shingleSizes = opts.shingleSizes;
  var minDistinctTokens = opts.minDistinctTokens;
  var out = {};
  for (var s = 0; s < shingleSizes.length; s++) out[shingleSizes[s]] = {};
  for (var fi = 0; fi < absFiles.length; fi++) {
    var entry = _tokenizeFile(absFiles[fi]);
    if (!entry) continue;
    var tokens = entry.tokens;
    var rel = entry.rel;
    for (var si = 0; si < shingleSizes.length; si++) {
      var n = shingleSizes[si];
      if (tokens.length < n) continue;
      for (var ti = 0; ti + n <= tokens.length; ti++) {
        var slice = tokens.slice(ti, ti + n);
        var distinctMap = {};
        for (var di = 0; di < slice.length; di++) distinctMap[slice[di].tok] = true;
        if (Object.keys(distinctMap).length < minDistinctTokens) continue;
        if (_isBoilerplate(slice)) continue;
        var fp = _sliceFingerprintExact(slice);
        var bucket = out[n];
        if (!bucket[fp]) bucket[fp] = [];
        bucket[fp].push({ file: rel, line: slice[0].line, endLine: slice[slice.length - 1].line });
      }
    }
  }
  return out;
}

function testNoDuplicateCodeBlocks() {
  // class: duplicate-block
  // Cross-file exact token-shingles: a block whose normalized token
  // sequence repeats verbatim across STRONG_MIN_FILES+ files at
  // STRONG_MIN_SIZE+ tokens is a shared logic shape that wants extraction
  // into a common primitive, not N hand-maintained copies.
  var SHINGLE_SIZES = [60, 50, 40, 30, 22, 16, 12, 8];
  var MIN_DISTINCT_FILES = 2;
  var MIN_DISTINCT_TOKENS = 5;
  var STRONG_MIN_SIZE = 50;
  var STRONG_MIN_FILES = 3;

  // KNOWN_CLUSTERS — per-cluster allowlist for genuinely-different code
  // that happens to share a token shape. Each `files` entry is a
  // `path:fnName` string (use `<top>` for module-level code); a bare path
  // with no `:fn` qualifier is refused at parse so the audit trail records
  // exactly which function body shares the shape. HS_CLUSTER_MIGRATE=1
  // relaxes that refusal so partially-migrated entries can run.
  //
  //   { files: ["lib/a.js:fnA", "lib/b.js:fnB", ...],
  //     mode?: "family-subset",   // default: exact set match
  //     reason: "why these are not extractable" }
  var KNOWN_CLUSTERS = [
    {
      // The per-module capture header: a run of `var _x = intrinsic.y;` bindings taking what the
      // module reads from the runtime before any caller code can reach it. The uniformity IS the
      // point -- every module binds the same names to the same intrinsics, so a reader comparing two
      // of them sees one list in the same shape and can tell at a glance what each still reads
      // live. Extracting it further is not possible: each module binds a DIFFERENT subset (the byte
      // guard needs isView, the identifier guard needs ownKeys, a format module needs hasOwn), and a
      // shared object handed around would reintroduce the property read at the call site that the
      // capture exists to remove. The family spans guards, format modules and producing modules,
      // because taking the captures is what puts a module under the live-read gate at all.
      // family-subset so any 3+ of them match as more are swept.
      files: [
        "lib/guard-bytes.js:<top>", "lib/guard-identifier.js:<top>", "lib/guard-parsed.js:<top>",
        "lib/guard-compress.js:<top>", "lib/guard-encoding.js:<top>", "lib/guard-json.js:<top>",
        "lib/guard-header.js:<top>", "lib/guard-der.js:<top>", "lib/guard-limits.js:<top>",
        "lib/guard-range.js:<top>", "lib/guard-async.js:<top>", "lib/guard-time.js:<top>",
        "lib/guard-name.js:<top>", "lib/guard-text.js:<top>", "lib/guard-secret.js:<top>",
        "lib/cmp-verify.js:<top>", "lib/ocsp-verify.js:makeOcspVerify",
        "lib/jose.js:<top>", "lib/webcrypto.js:<top>",
        "lib/acme.js:<top>", "lib/est.js:<top>", "lib/webauthn.js:<top>", "lib/trust.js:<top>",
        "lib/webauthn-mds.js:<top>", "lib/attrcert-sign.js:<top>", "lib/http-digest.js:<top>",
        "lib/schema-pkix.js:<top>", "lib/ct.js:<top>", "lib/crl-sign.js:<top>",
        "lib/cmc-build.js:<top>", "lib/cmc-verify.js:<top>", "lib/hpke.js:<top>",
        "lib/schema-attrcert.js:<top>", "lib/tls-cert-compress.js:<top>",
        "lib/schema-crl.js:<top>", "lib/schema-ocsp.js:<top>",
        "lib/cmp-build.js:<top>", "lib/crmf-sign.js:<top>",
      ],
      mode: "family-subset",
      reason: "The per-module capture header binds each module's subset of guard-intrinsic to local names at load. The repeated shape is a deliberate convention so the set is comparable across modules; the subsets differ per module and a shared indirection would put back the call-site property read the capture removes.",
    },
    {
      // The per-format-module PEM footer: pemDecode / pemEncode are thin one-line
      // delegations to the shared pkix.pemDecode / pkix.pemEncode, differing only
      // in the default PEM label + error class. The parse LOGIC is already factored
      // into pkix; these wrappers must stay per-module (each carries its own
      // @primitive wiki block the doc generator reads), so the shape repeats across
      // every format without being further extractable. family-subset so any 3+ of
      // the format modules (incl. future ocsp / tsp) match.
      files: [
        "lib/schema-x509.js:pemDecode", "lib/schema-x509.js:pemEncode",
        "lib/schema-crl.js:pemDecode", "lib/schema-crl.js:pemEncode",
        "lib/schema-csr.js:pemDecode", "lib/schema-csr.js:pemEncode",
        "lib/schema-pkcs8.js:pemDecode", "lib/schema-pkcs8.js:pemEncode",
        "lib/schema-cms.js:pemDecode", "lib/schema-cms.js:pemEncode",
        "lib/schema-ocsp.js:pemDecode", "lib/schema-ocsp.js:pemEncode",
        "lib/schema-tsp.js:pemDecode", "lib/schema-tsp.js:pemEncode",
        "lib/schema-attrcert.js:pemDecode", "lib/schema-attrcert.js:pemEncode",
        "lib/schema-crmf.js:pemDecode", "lib/schema-crmf.js:pemEncode",
        "lib/schema-pkcs12.js:pemDecode", "lib/schema-pkcs12.js:pemEncode",
        "lib/schema-attrcert.js:<top>", "lib/schema-pkcs12.js:<top>",
        "lib/schema-cmp.js:pemDecode", "lib/schema-cmp.js:pemEncode", "lib/schema-cmp.js:<top>",
        "lib/schema-cmp.js:rawSequence",
      ],
      mode: "family-subset",
      reason: "pemDecode/pemEncode are per-module thin delegations to pkix.pemDecode/pemEncode (label + error class differ); kept separate for their per-function @primitive wiki blocks.",
    },
    {
      // The unknown-key door on an authoring spec: every producing module closes it
      // the same way -- `guard.identifier.assertKnownKeys(obj, TABLE, E, "<domain>/bad-input",
      // fn)` followed by a `Object.keys(...).forEach` that consumes the now-known
      // fields. The CHECK itself already lives once in guard-identifier; what repeats
      // is the call plus the message closure naming that spec's own fields, and each
      // binds a DIFFERENT table, error class and wording. Extracting the call would
      // just relocate the same three lines while hiding which table guards which
      // descriptor. family-subset so a new producer's door matches the cluster
      // instead of re-tripping it.
      files: [
        "lib/attrcert-sign.js:add", "lib/attrcert-sign.js:<top>",
        "lib/cmc-build.js:fixedRequestId", "lib/cmc-build.js:_build",
        "lib/pki-build.js:requestedExtensions", "lib/pki-build.js:<top>",
        // The same door on an OPTIONS object: the entry check that the argument is an object, then
        // the unknown-key refusal against that verb's own table. Same shape, different table.
        "lib/cms-sign.js:_sign", "lib/cms-sign.js:_countersign",
        "lib/cms-verify.js:_verify", "lib/tsp-sign.js:verify",
        // pki.key's six verbs, pki.path's two, pki.lint.certificate and pki.ocsp.verify. Each
        // binds its own table, error class and message. key.export names the verb that
        // encrypts, and path.validate and path.build name each other's anchor spelling, so the
        // wording carries the per-verb content and only the call repeats.
        "lib/key.js:encrypt", "lib/key.js:decrypt", "lib/key.js:export_",
        "lib/key.js:import_", "lib/key.js:generate", "lib/key.js:publicFromPrivate",
        "lib/path-validate.js:validate", "lib/path-validate.js:build",
        "lib/lint.js:certificate", "lib/ocsp.js:verify",
        "lib/ocsp.js:_buildRequest", "lib/ocsp.js:_sign",
        // The same door on a NESTED descriptor, where the spec is a tree rather than one object.
        // A PKCS#12 store nests safeContents -> bags -> the PBE descriptor, and each level carries
        // fields the level above cannot see, so each needs its own table and its own message; the
        // extensions builders are the same shape one level inside a certificate spec.
        "lib/pkcs12-build.js:_buildAuthSafeElement", "lib/pkcs12-build.js:_buildBag",
        "lib/pkcs12-build.js:_pbeOpts",
        "lib/attrcert-sign.js:_buildExtensions", "lib/x509-sign.js:_buildExtensions",
      ],
      mode: "family-subset",
      reason: "assertKnownKeys call-site glue: the check lives once in guard-identifier; each site binds a different key table, error class and message, so only the call and its closure repeat.",
    },
    {
      // Producing-module helper glue, surfaced rather than introduced. These seven functions do
      // unrelated jobs: an extensions list, a POP link witness, a PEM decode, a countersignature
      // preimage, a challengePassword attribute, a signingCertificateV2, and a critical-SAN test.
      // They share only the builder idiom every one of them is written in: read a spec field,
      // guard it, hand it to a b.* encoder. Nothing is extractable without inventing a helper
      // that would take a different shape per caller.
      //
      // It became visible when the entry preamble in cms-sign shrank by a line, sliding the
      // token windows in that file until a 60-token run lined up with the others. A duplicate
      // detector reports on alignment, so an edit anywhere in a file can surface a coincidence
      // that was always there; that is worth allowlisting rather than chasing.
      files: [
        "lib/attrcert-sign.js:_buildExtensions", "lib/cmc-build.js:popLinkWitnessV2",
        "lib/cms-sign.js:_pemToDer", "lib/cms-sign.js:_targetPreimage",
        "lib/csr-sign.js:_challengePassword", "lib/tsp-sign.js:_signingCertV2",
        "lib/x509-sign.js:_hasCriticalSan",
      ],
      mode: "family-subset",
      reason: "assertKnownKeys call-site glue: the check lives once in guard-identifier; each site binds a different key table, error class and message, so only the call and its closure repeat.",
    },
    {
      // Format-module schema-declaration / build glue: each module declares its
      // sub-schemas with the same combinator idiom (`var X = schema.seq([field(...),
      // optional(...)], { assert, arity, code, what, build })`) and shapes its output
      // in a build fn (`return { field: m.fields.field.value, serialNumberHex:
      // node.content.toString("hex"), ... }`). The combinators + the shared idioms
      // (serialNumberHex, whenUniversal optionals, the raw-signature octet-alignment
      // guard) already live in the engine / pkix / a per-module helper; each
      // declaration binds DIFFERENT fields + codes, so the shape recurs without being
      // further extractable. family-subset so any 3+ of the format modules match.
      files: [
        "lib/schema-cms.js:_expectedSignedDataVersion", "lib/schema-cms.js:_expectedEnvelopedDataVersion",
        "lib/schema-cms.js:makeSignerInfo",
        "lib/schema-ocsp.js:_rawSignature",
        "lib/schema-pkcs8.js:<top>", "lib/schema-tsp.js:<top>",
        "lib/schema-pkcs12.js:<top>", "lib/schema-crmf.js:popoPrivKey",
        "lib/schema-pkix.js:algorithmIdentifier", "lib/schema-pkix.js:attribute",
        "lib/schema-pkix.js:attributeTypeAndValue",
        "lib/schema-cmp.js:<top>", "lib/schema-ocsp.js:_shapeCertStatus",
        "lib/schema-crl.js:decodeExt", "lib/schema-crmf.js:mapControls",
        "lib/schema-attrcert.js:<top>", "lib/schema-tsp.js:<top>",
        "lib/schema-cmp.js:rawSequence", "lib/schema-smime.js:<top>",
        "lib/schema-ocsp.js:_shapeResponderID", "lib/schema-smime.js:assertSignerIssuerIsDirectoryName",
        "lib/schema-ocsp.js:_validateOcspExtensions",
        "lib/schema-csrattrs.js:<top>", "lib/schema-smime.js:signingCertificateSchema",
        "lib/schema-cmc.js:<top>", "lib/schema-cmc.js:rawList", "lib/schema-crmf.js:crmfName",
        "lib/schema-cms.js:keyIdentifierSchema",
      ],
      mode: "family-subset",
      reason: "per-format schema.seq/decode declarations + build-fn output assembly share the combinator idiom (different fields/codes each); the combinators live in the engine, nothing further to extract.",
    },
    {
      // The certificate/CMS/timestamp producing-module header: each signing module opens with the same
      // idiom -- require the codec + oid + sign-scheme resolver + guard + framework-error, then declare
      // the two per-domain error factories (`_err(code,msg,cause)` taking a full code + `_signE(kind,...)`
      // prepending the domain, the (code,msg)-factory shape guard.time.assertValid and resolveSignScheme
      // invoke) plus the `O(n) = oid.byName(n)` shorthand. The resolver + signer live once in
      // sign-scheme.js; each header binds a DIFFERENT domain (cms/ tsp/ x509/), so the glue recurs
      // without being further extractable. family-subset so any 3+ producing modules match.
      files: [
        "lib/cms-sign.js:<top>", "lib/tsp-sign.js:<top>", "lib/x509-sign.js:<top>", "lib/csr-sign.js:<top>", "lib/attrcert-sign.js:<top>", "lib/crmf-sign.js:<top>", "lib/cmp-build.js:<top>", "lib/crl-sign.js:<top>",
        "lib/cmc-build.js:<top>", "lib/cmc-verify.js:<top>", "lib/schema-cmc.js:<top>",
        "lib/cms-sign.js:_err", "lib/tsp-sign.js:_err", "lib/x509-sign.js:_err", "lib/csr-sign.js:_err", "lib/attrcert-sign.js:_err", "lib/crmf-sign.js:_err", "lib/cmp-build.js:_err", "lib/crl-sign.js:_err",
        // The run continues past the factories: makeNS(domain) then makeBuilder({...})
        // with that domain's error class and schemas. Same idiom, same reason -- the
        // builder itself lives once in pki-build.js and each module binds its own domain.
        "lib/cms-sign.js:_signE", "lib/tsp-sign.js:_signE", "lib/x509-sign.js:_signE", "lib/csr-sign.js:_signE", "lib/attrcert-sign.js:_signE", "lib/crmf-sign.js:_signE", "lib/cmp-build.js:_signE", "lib/crl-sign.js:_signE",
      ],
      mode: "family-subset",
      reason: "producing-module header: require(codec/oid/sign-scheme/guard/framework-error) + the two per-domain error factories (_err full-code, _signE domain-prefixed) + O()=oid.byName; the resolver/signer are shared in sign-scheme.js and each module binds a different domain -- nothing further extractable. Applies to the <top> require run and the shared _err factory shape.",
    },
    {
      // The producing-module public entry point: sign(spec, ..., opts) returns
      // Promise.resolve().then(function () { return _sign(...); }) so a synchronous config-time throw in
      // _sign rejects the returned promise instead of throwing from the call site (an async boundary the
      // callers await). A trivial three-line wrapper, identical by construction across producers -- the
      // CMP transfer verb (transfer -> _transfer) shares the same async-boundary wrapper.
      files: ["lib/attrcert-sign.js:sign", "lib/csr-sign.js:sign", "lib/x509-sign.js:sign", "lib/cms-sign.js:sign", "lib/tsp-sign.js:sign", "lib/cmp-build.js:transfer", "lib/cmc-build.js:build"],
      mode: "family-subset",
      reason: "producing-module / network-verb public entry: sign(...) (or cmp transfer(...)) wraps its _impl in Promise.resolve().then() so a config-time throw rejects the promise rather than throwing synchronously; a three-line async-boundary wrapper with nothing to extract.",
    },
    {
      // Producing-module structural-encoder + orchestrator bodies: each encodes a DIFFERENT ASN.1 structure
      // (a PKIHeader, a Holder, a CertReqMsg, a CertTemplate, a proof of possession, a challenge password)
      // with the same combinator glue -- validate the spec keys, build a `children` array, conditionally
      // push the present optionals, return `b.sequence(children)` -- plus the `_sign`/`_build` orchestrators
      // that `Promise.resolve().then` a config-time throw and await the shared sign-scheme. The structures
      // differ per domain; the glue is the shared pki-build combinator surface, not further extractable
      // without threading each structure's field set through a callback. family-subset so any 3+ producer
      // bodies match (a fifth producer, cmp-build, joined the family).
      files: [
        "lib/attrcert-sign.js:sign", "lib/attrcert-sign.js:_sign", "lib/attrcert-sign.js:_encodeHolder", "lib/attrcert-sign.js:_buildExtensions",
        "lib/cmp-build.js:_encodeHeader", "lib/cmp-build.js:_resolveProtection", "lib/cmp-build.js:_build",
        "lib/crmf-sign.js:_buildCertReqMsg", "lib/crmf-sign.js:_encodeCertTemplate", "lib/crmf-sign.js:_buildProofOfPossession",
        "lib/csr-sign.js:sign", "lib/csr-sign.js:_sign", "lib/csr-sign.js:_challengePassword", "lib/csr-sign.js:addAttr",
        "lib/x509-sign.js:sign", "lib/x509-sign.js:_sign",
        "lib/crl-sign.js:_sign", "lib/crl-sign.js:_idpValue", "lib/crl-sign.js:_buildCrlExtensions", "lib/crl-sign.js:_buildRevoked", "lib/crl-sign.js:_assertIssuerCanSignCrl",
        "lib/ct.js:fetchLogList",
        "lib/cmp-verify.js:_verify",
        "lib/cmp-session.js:session",
        "lib/cmc-build.js:_certReqIdOf", "lib/cmc-build.js:_claimRawElement",
        "lib/cmc-build.js:_asBigInt",
        "lib/cms-sign.js:_dedupe", "lib/pki-build.js:skiKeyId",
        "lib/cmp-build.js:_classifyCmpResponse", "lib/x509-sign.js:_hasCriticalSan",
      ],
      mode: "family-subset",
      reason: "producing-module structural-encoder + orchestrator bodies -- each encodes a different ASN.1 structure with the shared `build children[], push present optionals, return b.sequence` combinator glue plus the `Promise.resolve().then(_sign/_build)` async-boundary wrapper and the shared signOverTbs + assertSignatureVerifies + emit tail; the ct fetch verb shares the same validate-opts + async-orchestrate shingle (it composes rather than encodes, but the glue tokens coincide), cmp-verify's _verify shares the opts-key-whitelist + Promise.resolve().then async-boundary + ProtectedPart b.sequence glue (the verify-side orchestrator), and cmp-session's `session` constructor shares the same opts-key-whitelist + guard.limits.cap budget glue (the transaction-orchestrator constructor). The structures differ per domain and the glue is the pki-build / sign-scheme surface, not further extractable.",
    },
    {
      // The thin network-client entry + response body: pki.acme / pki.est / pki.cmp / pki.ct each validate
      // the request URL, apply the default-transport trust-anchor gate (no injected transport -> require an
      // explicit anchor or useSystemStore, else */no-trust-anchors, then build pki.transport.https), cap the
      // timeout + maxResponseBytes budgets via guard.limits.cap with the domain error factory, map opts.tls
      // -> the request tls shape, and issue the request over the shared transport; the response body is then
      // re-viewed through guard.bytes.view + size-rechecked identically (the _fetchBody / _sendFollowing /
      // _transfer response glue). The transport / guard / budget primitives live once (http-transport.js /
      // guard-limits.js); each client binds a DIFFERENT domain (acme/ est/ cmp/ ct/) and a different protocol
      // shape (a stateful session, functional verbs, a stateless transfer, a fetch-then-verify), so the
      // anchor-gate + budget + response-normalize glue recurs without being further extractable.
      files: ["lib/acme.js:client", "lib/acme.js:_sendFollowing", "lib/est.js:_client", "lib/cmp-build.js:_transfer", "lib/ct.js:fetchLogList", "lib/ct.js:_fetchBody", "lib/path-validate.js:build", "lib/path-validate.js:_aiaFetchOne"],
      mode: "family-subset",
      reason: "network-client entry + response glue: URL parse + default-transport trust-anchor gate (explicit anchor|useSystemStore else */no-trust-anchors, then pki.transport.https) + guard.limits.cap timeout/maxResponseBytes budgets + opts.tls->request.tls mapping + the response-body re-view (guard.bytes.view) and size recheck. The transport/guard/budget primitives are shared in http-transport.js / guard-limits.js; each client binds a different domain and protocol shape (acme stateful session, est functional verbs, cmp stateless transfer, ct fetch-then-verify, path-validate's opt-in AIA caIssuers fetch), so the glue recurs without being further extractable.",
    },
    {
      // The per-attribute uniqueness + assembly idiom: a dedup helper that rejects a repeated
      // AttributeType OID (seen[type]) then pushes Attribute ::= SEQUENCE { type OID, SET OF value }.
      // attrcert-sign's `add` and csr-sign's `addAttr` share it (different domain codes); pki-build's
      // assertValidExtension shares only the decode+throw shingle coincidentally. Each is a small
      // domain-local helper, not further extractable without threading a per-domain error callback.
      files: ["lib/attrcert-sign.js:add", "lib/csr-sign.js:addAttr", "lib/pki-build.js:assertValidExtension"],
      mode: "family-subset",
      reason: "attribute dedup+assembly idiom (reject a repeated AttributeType, push SEQUENCE{type, SET OF value}); attrcert `add` / csr `addAttr` share it with different domain codes, pki-build assertValidExtension shares only a coincidental decode+throw shingle -- domain-local, nothing cleanly extractable.",
    },
    {
      // The Promise-returning entry wrapper. Every verb documented `-> Promise<...>` opens the same
      // way: `return guard.async.deferred(function () { return _verb(args); })`, so a fault leaves as
      // a rejection rather than a throw past the caller's .catch, while the body still runs at entry
      // (which is what fixes the caller's arguments before they can change). The rule lives once in
      // guard-async and is enforced behaviorally by promise-contract.test.js; only the wrapper
      // repeats, and it cannot be extracted -- each one names its own inner function and arguments.
      files: [
        "lib/attrcert-sign.js:sign", "lib/cmp-build.js:transfer", "lib/cms-sign.js:sign",
        "lib/cms-sign.js:countersign", "lib/csr-sign.js:sign", "lib/ocsp.js:sign",
        "lib/tsp-sign.js:sign", "lib/x509-sign.js:sign", "lib/crl-sign.js:sign",
        "lib/crl-sign.js:verify", "lib/crmf-sign.js:build", "lib/cmp-build.js:build",
        "lib/cmp-verify.js:verify", "lib/cmc-verify.js:verify", "lib/webauthn-mds.js:verifyMetadataBlob",
        "lib/cms-verify.js:verify", "lib/cmc-build.js:build", "lib/attrcert-sign.js:<top>",
        "lib/cmp-build.js:<top>", "lib/cms-sign.js:<top>", "lib/crl-sign.js:<top>",
        "lib/crmf-sign.js:<top>", "lib/csr-sign.js:<top>", "lib/x509-sign.js:<top>",
        "lib/ocsp.js:<top>", "lib/tsp-sign.js:<top>", "lib/cmc-build.js:<top>",
        "lib/cmc-verify.js:<top>", "lib/cmp-verify.js:<top>", "lib/cms-verify.js:<top>",
        "lib/cms-compress.js:<top>", "lib/cms-decrypt.js:<top>", "lib/cmp-session.js:<top>",
        // The shingle starts a few tokens before the wrapper, so the enclosing-function attribution
        // lands on whatever function precedes it in each module. These are those neighbors.
        "lib/attrcert-sign.js:_buildExtensions", "lib/cmp-build.js:_classifyCmpResponse",
        "lib/cms-sign.js:_pemToDer", "lib/cms-sign.js:_targetPreimage",
        "lib/csr-sign.js:_challengePassword", "lib/ocsp.js:_normCertDer",
        "lib/tsp-sign.js:_signingCertV2", "lib/cmp-build.js:_transfer",
        "lib/x509-sign.js:_buildExtensions", "lib/crl-sign.js:_buildCrlExtensions",
        "lib/crmf-sign.js:_buildCertReqMsg", "lib/cmc-verify.js:_verify",
        "lib/cms-verify.js:_verify", "lib/webauthn-mds.js:_verifyMetadataBlob",
        // The producing verbs now open with the SAME two statements -- fixArguments over every
        // argument, then guard.async.deferred over the body, released in a .finally. That is the
        // whole point: one rule, written identically everywhere, with only the error class, the
        // domain code and the argument labels differing. There is nothing further to extract --
        // the copy lives in guard-bytes and the rejection contract in guard-async.
        "lib/pkcs12-build.js:build", "lib/ocsp.js:buildRequest",
        "lib/crmf-sign.js:_buildProofOfPossession", "lib/x509-sign.js:_hasCriticalSan",
        "lib/crl-sign.js:_sign", "lib/x509-sign.js:_sign", "lib/csr-sign.js:_sign",
        "lib/attrcert-sign.js:_sign", "lib/crmf-sign.js:_build", "lib/cmc-build.js:_build",
        "lib/cmp-build.js:_build", "lib/ocsp.js:_sign", "lib/tsp-sign.js:_sign",
        "lib/cms-sign.js:_sign", "lib/cms-sign.js:_countersign",
      ],
      mode: "family-subset",
      reason: "guard.async.deferred entry wrapper: the rule lives once in guard-async and is enforced by promise-contract.test.js; each wrapper names its own inner function and arguments, so only the shape repeats.",
    },
    {
      // The entry SNAPSHOT on a producing verb: `spec = guard.bytes.snapshotDeep(spec, <Domain>Error,
      // "<domain>/bad-input", "<what>")` as the first statement, so the object the checks below read
      // is one the caller can no longer reach. The copy itself lives once in guard-bytes; what
      // repeats is the call plus the domain error class, code and wording -- different at every site.
      files: [
        "lib/x509-sign.js:_sign", "lib/crl-sign.js:_sign", "lib/csr-sign.js:_sign",
        "lib/attrcert-sign.js:_sign", "lib/crmf-sign.js:_build", "lib/cmc-build.js:_build",
        "lib/cmp-build.js:_build", "lib/ocsp.js:buildRequest", "lib/ocsp.js:_sign",
        "lib/pkcs12-build.js:build", "lib/attrcert-sign.js:_err", "lib/cmp-build.js:_err",
        "lib/cms-sign.js:_err", "lib/crl-sign.js:_err", "lib/crmf-sign.js:_err",
        "lib/csr-sign.js:_err", "lib/x509-sign.js:_err", "lib/attrcert-sign.js:_signE",
        "lib/cmp-build.js:_signE", "lib/crmf-sign.js:_signE", "lib/csr-sign.js:_signE",
        "lib/tsp-sign.js:_sign", "lib/cms-sign.js:_sign",
      ],
      mode: "family-subset",
      reason: "entry-snapshot glue on a producing verb: the deep copy lives once in guard-bytes; each call binds a different error class, code and message, so only the call and the module's own error factory beside it repeat.",
    },
    {
      // The byte-input door on an authoring boundary: route a Buffer / Uint8Array through
      // guard.bytes.view (which owns the detached-backing-store reject) and throw the module's own
      // typed error for anything else. The CHECK itself lives once in guard-bytes; what repeats is
      // the call plus the domain error class, code and wording, and each site binds a DIFFERENT
      // three. Extracting the call would relocate one line while hiding which domain guards which
      // input. family-subset so a new module's door matches the cluster instead of re-tripping it.
      files: [
        "lib/cmc-build.js:_der", "lib/cms-sign.js:_toBuf", "lib/cms-verify.js:_toBuf",
        "lib/pki-build.js:reqDer", "lib/cms-compress.js:_toDer", "lib/cms-decrypt.js:_toDer",
        "lib/cms-encrypt.js:_normCertDer", "lib/cms-decrypt.js:_normCertDer",
        "lib/ocsp.js:_toDer", "lib/ocsp.js:_normCertDer", "lib/sign-scheme.js:_normPkcs8",
      ],
      mode: "family-subset",
      reason: "guard.bytes.view call-site glue: the detached-view check lives once in guard-bytes; each door binds a different error class, code and message, so only the call and its throw repeat.",
    },
    {
      // The pre-encoded-Extension-array handling idiom (decode -> assertValidExtension -> dedup extnID ->
      // re-validate a recognized value via the decoder table). pki-build's `requestedExtensions` is the
      // SHARED primitive csr/crmf compose; x509 `_buildExtensions` and attrcert `_buildExtensions` keep
      // their own array handlers because each layers EXTRA domain rules the shared helper does not do
      // (x509 the RFC 5280 CA cross-field gates keyCertSign=>cA + critical-BC; attrcert the RFC 5755
      // mandated per-extension criticality), so they share the decode/validate shingle without being
      // further extractable onto the shared helper.
      files: ["lib/pki-build.js:requestedExtensions", "lib/x509-sign.js:_buildExtensions", "lib/attrcert-sign.js:_buildExtensions", "lib/attrcert-sign.js:add", "lib/crl-sign.js:push", "lib/crl-sign.js:_buildCrlExtensions", "lib/crl-sign.js:_buildRevoked"],
      mode: "family-subset",
      reason: "pre-encoded-Extension-array decode+validate+dedup idiom; pki-build.requestedExtensions is the shared csr/crmf primitive, while x509/attrcert/crl keep their own handlers because each adds domain rules the shared helper omits (x509 CA cross-field gates, attrcert RFC 5755 criticality, crl the RFC 5280 sec. 5.2 per-extension fixed criticality + dup rejection) -- the shingle is shared, the extra rules are not extractable.",
    },
    // The v0.1.29 byte-input coercion-guard cluster is gone: the five boundaries
    // now delegate to lib/guard-bytes.js (guard.bytes.view / .source), so each
    // per-module coercion is a one-line call with no shared shape to cluster.
    // The detached-safe re-view lives in exactly one place, enforced by the
    // detached-view-buffer-not-via-guard detector.
    {
      // The extension-consuming modules each compose the SHARED RFC 5280 extension
      // decoder table the same way at the top of the file: `var NS = pkix.makeNS(prefix,
      // ErrorClass, oid); var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;` --
      // under their own namespace prefix + error class. The decoders + makeNS already
      // live in pkix (composed identically by path-validate); the two-line header repeats
      // in shape without being extractable (each binds a different prefix/error class).
      files: ["lib/inspect.js:<top>", "lib/lint.js:<top>", "lib/webauthn.js:<top>", "lib/cmp-verify.js:<top>", "lib/trust.js:<top>"],
      mode: "family-subset",
      reason: "consumer-module header run: require the codec/oid/schema/guard/framework-error core + declare a `var NS = pkix.makeNS(prefix, ErrorClass, oid)` namespace (inspect/lint/webauthn compose pkix.certExtensionDecoders under it; cmp-verify composes pkix.pbmac1Params under it; trust its own decoders). The makeNS + require idiom lives in pkix and each binds a different prefix/error class, so the header composition is not further extractable. family-subset so any 3+ match.",
    },
    {
      // The crypto-layer modules (cms-encrypt / cms-decrypt / ocsp producer / sign-scheme) each
      // carry a per-domain input normalizer -- _normCertDer / _normKeyDer / _toDer / _normPkcs8 --
      // that coerces a Buffer / Uint8Array / PEM string to DER through its OWN domain PEM decoder
      // (x509 / pkcs8 / schema-cms) and throws its OWN typed error code (cms/* vs ocsp/*). This is
      // the same thin-per-domain-wrapper class as the allowlisted pemDecode/pemEncode delegations:
      // the 3-line coerce shape recurs without being further extractable (each binds a different
      // decoder + error factory). Their <top> require headers share the same requires idiom for the
      // same reason. family-subset so any 3+ match.
      files: [
        "lib/cms-decrypt.js:_normCertDer", "lib/cms-decrypt.js:_normKeyDer", "lib/cms-decrypt.js:_toDer",
        "lib/cms-encrypt.js:_normCertDer", "lib/ocsp.js:_normCertDer", "lib/ocsp.js:_toDer",
        "lib/sign-scheme.js:_normPkcs8", "lib/cms-compress.js:_toDer",
        "lib/cms-decrypt.js:<top>", "lib/cms-encrypt.js:<top>", "lib/ocsp.js:<top>", "lib/cms-compress.js:<top>", "lib/key.js:<top>", "lib/pkcs12-build.js:<top>",
      ],
      mode: "family-subset",
      reason: "per-domain cert/key/input-to-DER normalizers (own PEM decoder + typed error code), the same thin-wrapper class as the allowlisted pemDecode/pemEncode; not further extractable.",
    },
    {
      // The PBKDF2 / PBMAC1 work-factor + params shingle shared across the PBES2 core and the two PBMAC1
      // verifiers (pkcs12 MacData, CMP protection). pbes2.parsePbkdf2Params reads the PBKDF2-params shape;
      // pkcs12-build._capWork and cmp-verify._capWork each bound the attacker-controlled iterationCount /
      // salt / keyLength BEFORE deriving, throwing their OWN domain code (pkcs12/* vs cmp/*) with their own
      // keyLength ceiling + hardCap. The PBMAC1-params DECODER is already shared (pkix.pbmac1Params); the
      // work-cap is a short domain-parameterized bound (E, code, hardCap, keyLen ceiling differ), not further
      // extractable without threading a per-domain error factory + bounds through a callback.
      files: ["lib/cmp-verify.js:_capWork", "lib/pbes2.js:parsePbkdf2Params", "lib/pkcs12-build.js:_capWork"],
      reason: "PBKDF2/PBMAC1 work-factor bounding (cap iterationCount/salt/keyLength before deriving) + the PBKDF2-params read shingle, shared across pbes2 / pkcs12 MacData / CMP protection; each throws its own domain code with its own ceilings -- domain-parameterized, the PBMAC1-params reader is already shared as pkix.pbmac1Params, nothing further cleanly extractable.",
    },
    {
      // The transport/verify orchestrator header run: cmp-session / cms-verify / est each open with a run of
      // `var X = require("./Y");` binding the shared core (oid, guard-all, constants, webcrypto, framework-error,
      // schema-cms/cmp, http-retry-after) that their orchestration composes. The requires + the modules they bind
      // live once each; the header run repeats in SHAPE (the same var-require idiom) while binding a different
      // module set per domain, so it is not further extractable. family-subset so any 3+ match.
      files: ["lib/cmp-session.js:<top>", "lib/cms-verify.js:<top>", "lib/est.js:<top>"],
      mode: "family-subset",
      reason: "transport/verify-orchestrator header run: a `var X = require(\"./Y\")` block binding the shared core (oid/guard/constants/webcrypto/framework-error/schema-cms|cmp/http-retry-after); the requires and the bound modules live once each, the run repeats in shape while binding a different module set per domain -- not further extractable. family-subset so any 3+ match.",
    },
    {
      // The deferring wrapper on a verb documented `-> Promise`: a one-line body forwarding the
      // verb's own arguments through guard.async.deferred to the implementation beside it. The
      // RULE lives once, in guard-async; what repeats is only the forwarding, and it cannot be
      // hoisted because each wrapper has to name its own implementation and pass its own
      // parameters -- a generic forwarder would erase the arity the documented signature states.
      // family-subset so any 3+ of the Promise-returning verbs match.
      files: [
        "lib/cms-sign.js:sign", "lib/cms-sign.js:countersign", "lib/cms-verify.js:verify",
        "lib/ocsp.js:sign", "lib/tsp-sign.js:sign",
      ],
      mode: "family-subset",
      reason: "the guard.async.deferred wrapper on a Promise-documented verb: a one-line forward of the verb's own arguments to the implementation beside it. The rule lives once in guard-async; only the forwarding repeats, and each wrapper must name its own implementation and parameters, so it is not further extractable.",
    },
    {
      // The per-format-module parser footer: `pkix.makeRecordingParser({ pemLabel, PemError,
      // ErrorClass, prefix, what, topSchema, ns }, kind)`. The parse logic and the provenance
      // record both live once, in schema-pkix and guard-parsed; each module supplies a different
      // label, error class, domain prefix, top-level schema and provenance kind, so the call
      // repeats in shape without being further extractable. family-subset so any 3+ match.
      files: [
        "lib/schema-cms.js:_expectedAuthDataVersion", "lib/schema-crl.js:decodeExt",
        "lib/schema-ocsp.js:_shapeResponderID", "lib/schema-x509.js:<top>",
        "lib/schema-pkcs12.js:<top>", "lib/schema-csr.js:<top>",
      ],
      mode: "family-subset",
      reason: "the per-format pkix.makeRecordingParser({ pemLabel, PemError, ErrorClass, prefix, what, topSchema, ns }, kind) footer: the parse logic lives once in schema-pkix and the provenance record once in guard-parsed, while each module supplies its own label, error class, domain prefix, top schema and provenance kind. Attribution names the nearest enclosing function because the call is module-level.",
    },
  ];

  var MIGRATE_MODE = !!process.env.HS_CLUSTER_MIGRATE;
  function _parseEntryMatchers(entry, idx) {
    var matchers = [];
    var seen = Object.create(null);
    for (var i = 0; i < entry.files.length; i++) {
      var raw = entry.files[i];
      if (typeof raw !== "string" || raw.length === 0) {
        throw new Error("KNOWN_CLUSTERS[" + idx + "].files[" + i + "] must be a non-empty `path:fnName` string");
      }
      var colon = raw.lastIndexOf(":");
      if (colon === -1) {
        if (MIGRATE_MODE) { matchers.push({ file: raw, fn: "*" }); continue; }
        throw new Error("KNOWN_CLUSTERS[" + idx + "].files[" + i + "] = " + JSON.stringify(raw) +
          " — missing `:fnName` qualifier. Name the function whose body shares the shape (use `<top>` for module-level code).");
      }
      var file = raw.slice(0, colon);
      var fn = raw.slice(colon + 1);
      if (file.length === 0 || fn.length === 0) {
        throw new Error("KNOWN_CLUSTERS[" + idx + "].files[" + i + "] = " + JSON.stringify(raw) + " — empty path or fn after `:`");
      }
      var key = file + ":" + fn;
      if (seen[key]) continue;
      seen[key] = true;
      matchers.push({ file: file, fn: fn });
    }
    return matchers;
  }
  var _exactEntries = [];
  var _familyEntries = [];
  KNOWN_CLUSTERS.forEach(function (e, idx) {
    var matchers = _parseEntryMatchers(e, idx);
    if (e.mode === "family-subset") _familyEntries.push(matchers);
    else _exactEntries.push(matchers);
  });

  // Enclosing-function index — the most-recent declaration before a
  // site's first line names the function whose body owns the shingle.
  var _FN_DECL_PATTERNS = [
    /^\s*(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/,
    /^\s*var\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(/,
    /^\s*(?:exports|module\.exports)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(/,
  ];
  var _fnIndexByFile = Object.create(null);
  function _buildFnIndex(rel) {
    var content;
    try { content = fs.readFileSync(path.resolve(REPO_ROOT, rel), "utf8"); }
    catch (_e) { return [{ startLine: 1, name: "<top>" }]; }
    var lines = _lines(content);
    var fns = [{ startLine: 1, name: "<top>" }];
    for (var li = 0; li < lines.length; li++) {
      var m = null;
      for (var pi = 0; pi < _FN_DECL_PATTERNS.length; pi++) {
        m = lines[li].match(_FN_DECL_PATTERNS[pi]);
        if (m) break;
      }
      if (!m) continue;
      fns.push({ startLine: li + 1, name: m[1] });
    }
    return fns;
  }
  function _enclosingFn(rel, line) {
    if (!_fnIndexByFile[rel]) _fnIndexByFile[rel] = _buildFnIndex(rel);
    var fns = _fnIndexByFile[rel];
    var best = fns[0];
    for (var i = 0; i < fns.length; i++) {
      if (fns[i].startLine <= line) best = fns[i];
      else break;
    }
    return best.name;
  }

  var files = _libFiles();
  var seen = _scanShingles(files, {
    shingleSizes: SHINGLE_SIZES,
    minDistinctTokens: MIN_DISTINCT_TOKENS,
  });

  // Aggregate per (file-set) into clusters, keeping the LARGEST shingle
  // observed for each file-set (it bounds the duplicated region best).
  var clusters = {};
  var sortedSizes = Object.keys(seen).map(Number).sort(function (a, b) { return b - a; });
  for (var szi = 0; szi < sortedSizes.length; szi++) {
    var n = sortedSizes[szi];
    var bucket = seen[String(n)];
    if (!bucket) continue;
    var fps = Object.keys(bucket).sort();
    for (var fpi = 0; fpi < fps.length; fpi++) {
      var occ = bucket[fps[fpi]];
      var distinctFiles = {};
      occ.forEach(function (o) { distinctFiles[o.file] = true; });
      var fileList = Object.keys(distinctFiles).sort();
      if (fileList.length < MIN_DISTINCT_FILES) continue;
      var key = fileList.join("|");
      if (!clusters[key]) {
        clusters[key] = { fileSet: fileList, bestSize: n, sites: occ.slice() };
      } else if (n > clusters[key].bestSize) {
        clusters[key].bestSize = n;
        clusters[key].sites = occ.slice();
      }
    }
  }

  var rows = Object.keys(clusters).map(function (k) { return clusters[k]; });
  rows.sort(function (a, b) {
    if (b.fileSet.length !== a.fileSet.length) return b.fileSet.length - a.fileSet.length;
    return b.bestSize - a.bestSize;
  });

  function _siteSetOf(r) {
    var seenSites = Object.create(null);
    var outSites = [];
    for (var i = 0; i < r.sites.length; i++) {
      var fn = _enclosingFn(r.sites[i].file, r.sites[i].line);
      var key = r.sites[i].file + ":" + fn;
      if (seenSites[key]) continue;
      seenSites[key] = true;
      outSites.push({ file: r.sites[i].file, fn: fn });
    }
    return outSites;
  }
  function _siteCoveredBy(site, matchers) {
    for (var i = 0; i < matchers.length; i++) {
      if (matchers[i].file !== site.file) continue;
      if (matchers[i].fn === "*" || matchers[i].fn === site.fn) return true;
    }
    return false;
  }

  var strong = rows.filter(function (r) {
    if (r.bestSize < STRONG_MIN_SIZE) return false;
    if (r.fileSet.length < STRONG_MIN_FILES) return false;

    var siteSet = _siteSetOf(r);
    // Always dump every strong cluster's (file, fn) tuples so an operator
    // can rewrite KNOWN_CLUSTERS entries straight from the log:
    //   MIGRATE-DUMP <sorted-fileset> :: <file:fn>,<file:fn>,...
    var fileKey = r.fileSet.slice().sort().join("|");
    var siteKey = siteSet.map(function (s) { return s.file + ":" + s.fn; }).sort().join(",");
    console.log("MIGRATE-DUMP " + fileKey + " :: " + siteKey);

    // Exact match: cluster siteSet equals one entry's matcher set.
    for (var ei = 0; ei < _exactEntries.length; ei++) {
      var matchers = _exactEntries[ei];
      if (matchers.length !== siteSet.length) continue;
      var allCovered = true;
      for (var sj = 0; sj < siteSet.length; sj++) {
        if (!_siteCoveredBy(siteSet[sj], matchers)) { allCovered = false; break; }
      }
      if (allCovered) return false;
    }
    // Family-subset: every site is covered by at least one matcher.
    for (var fi2 = 0; fi2 < _familyEntries.length; fi2++) {
      var fAll = true;
      for (var fj = 0; fj < siteSet.length; fj++) {
        if (!_siteCoveredBy(siteSet[fj], _familyEntries[fi2])) { fAll = false; break; }
      }
      if (fAll) return false;
    }
    return true;
  });

  if (strong.length > 0) {
    var strongMatches = strong.map(function (r) {
      var first = r.sites[0];
      var fp = _clusterFingerprint(first);
      return {
        file: first.file,
        line: first.line,
        content: "STRONG-DUP " + r.bestSize + "-tok in " + r.fileSet.length +
                 " files [fp:" + fp + "]: " + r.fileSet.slice(0, 5).join(", ") +
                 " — first @ " + first.file + ":" + first.line + "-" + first.endLine,
      };
    });
    strongMatches = _filterMarkers(strongMatches, "duplicate-block");
    _report("strong-signal duplicate code: " + STRONG_MIN_SIZE + "+ token exact shingle in " +
            STRONG_MIN_FILES + "+ files → extract a shared primitive", strongMatches);
  } else {
    check("strong-signal duplicate-block (no clusters)", true);
  }
}

function testNumberNarrowsUnboundedInteger() {
  // class: number-narrows-unbounded-integer
  // A CODEBASE-WIDE vector scan (not a per-format checklist): narrowing an
  // ASN.1 INTEGER / ENUMERATED read to a JS Number silently ROUNDS any value
  // past 2^53, so a caller comparing the result (a saltLength, a path-length or
  // policy-skip counter, an iteration count) acts on the wrong number. Every
  // `Number(v)` whose `v` comes from an integer read MUST be dominated by a
  // bound — a numeric upper limit (`v > Nn`), `Number.isSafeInteger`, a byte
  // mask, or membership in a small enumerated set (a `hasOwnProperty` / `indexOf`
  // whitelist). This fires on a NEW unbounded narrowing introduced ANYWHERE in
  // lib, including a spot never yet reviewed — the point the per-format frozen
  // lists missed. It is rename-proof: it matches the `Number(...)` shape and the
  // guard shapes, not any specific symbol, error code, or function.
  var INT_READ = /read\.integer\b|read\.integerImplicit\b|read\.enumerated\b|\breadInt\(|integerLeaf\(/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = path.relative(REPO_ROOT, f);
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      if (/^\s*(\/\/|\*)/.test(lines[i])) continue;
      var m = lines[i].match(/\bNumber\(\s*([A-Za-z_$][\w$.]*)\s*\)/);
      if (!m) continue;                                  // only Number(<ident>) — masks/literals/exprs excluded
      var id = m[1];
      // Scope = the enclosing function body (back to the nearest declaration at
      // a shallower-or-equal indent, or file start) — a real boundary, never a
      // fixed character count.
      var callIndent = (lines[i].match(/^\s*/) || [""])[0].length;
      var scopeStart = 0;
      for (var b = i - 1; b >= 0; b--) {
        var ind = (lines[b].match(/^\s*/) || [""])[0].length;
        if (/\bfunction\b/.test(lines[b]) && ind <= callIndent) { scopeStart = b; break; }
      }
      var scope = lines.slice(scopeStart, i + 1).join("\n");
      var idRe = id.replace(/[.$]/g, "\\$&");
      // The value must plausibly be an unbounded integer read to matter.
      var derivesFromRead = INT_READ.test(scope) &&
        (new RegExp(idRe + "\\s*=\\s*[^=]").test(scope) || INT_READ.test(m.input));
      if (!derivesFromRead) continue;
      var bounded =
        new RegExp(idRe + "\\s*>=?\\s*\\d").test(scope) ||          // id > Nn / id >= N
        new RegExp(idRe + "\\s*<=\\s*\\d").test(scope) ||           // id <= N
        /Number\.isSafeInteger/.test(scope) ||
        new RegExp(idRe + "\\s*&\\s*0x").test(scope) ||             // masked
        // Small-enum whitelist. Matched as a CALL, not as a bare word: the own-membership question
        // has several spellings in this tree (`_hasOwn(t, k)`, `intrinsic.hasOwn(t, k)`,
        // `Object.prototype.hasOwnProperty.call(t, k)`), and requiring the open paren keeps a
        // similarly-named identifier or a comment that merely mentions one from posing as a bound.
        /hasOwn\w*\s*(?:\.\s*call\s*)?\(|\.indexOf\(/.test(scope);
      if (!bounded) {
        bad.push({ file: rel, line: i + 1,
          content: "Number(" + id + ") narrows an ASN.1 integer read with no dominating bound — a value past 2^53 rounds silently; add a range check (id > Nn), Number.isSafeInteger, or a whitelist before narrowing (the RSASSA-PSS / PKCS#12 / CMP exact-or-rejected rule)" });
      }
    }
  });
  bad = _filterMarkers(bad, "number-narrows-unbounded-integer");
  _report("no Number() narrows an unbounded ASN.1 integer read (silent-rounding vector, codebase-wide)", bad);
}

function testNanDateComparisonUnguarded() {
  // class: nan-date-comparison-unguarded
  // A fail-open where an Invalid Date silently bypasses a time / window / validity
  // gate. `new Date(badString)` never throws -- it yields an Invalid Date that is
  // still `instanceof Date`, and EVERY relational comparison against its NaN
  // `.getTime()` (`NaN < x`, `NaN >= x`, `NaN <= x`, `NaN > x`) is false, so a gate
  // `if (t < start || t >= end) throw` NEVER fires and the out-of-window / expired
  // input is accepted. Any lib function comparing a `.getTime()` result with a
  // relational operator MUST reject `isNaN(getTime())` first -- OR take the Date
  // from a source that already rejects NaN (the codec `readTime`, the shared
  // `rfc3339.parse`, a Date literal), documented with an
  // `allow:nan-date-comparison-unguarded` marker naming the validated source.
  // Scope-aware (function-granular, like number-narrows); fires on a NEW unguarded
  // comparison ANYWHERE in lib, including a not-yet-written primitive. Rename-proof:
  // it matches the `.getTime()`-in-a-comparison shape, the equally-lenient
  // `Date.parse(...)`-in-a-comparison shape (Date.parse returns NaN for an unparseable
  // string, so `Date.parse(a) <= Date.parse(b)` is false-on-NaN just like getTime),
  // and the `isNaN(` guard shape -- never a symbol. This class is a 3-peat -- TSP
  // (v0.2.19), OCSP (v0.2.22), and the CT log-list temporal gate (v0.2.28) were each a
  // real fail-open of exactly this shape. The reusable safe primitive is guard.time.
  var CMP = /\.getTime\(\)\s*[<>]|[<>]=?\s*[A-Za-z_$][\w$.]*\.getTime\(\)|Date\.parse\s*\([^)]*\)\s*[<>]|[<>]=?\s*Date\.parse\s*\(/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = path.relative(REPO_ROOT, f);
    var src = fs.readFileSync(f, "utf8");
    _functionRegions(src).forEach(function (region) {
      var lines = _lines(region.body);
      var off = -1;
      for (var i = 0; i < lines.length; i++) {
        if (/^\s*(\/\/|\*|\/\*)/.test(lines[i])) continue;           // skip comment lines
        if (CMP.test(lines[i])) { off = i; break; }
      }
      if (off < 0) return;                                            // no getTime relational comparison
      if (/\bisNaN\s*\(/.test(region.body)) return;                   // the function guards NaN -> safe
      bad.push({ file: rel, line: region.startLine + off,
        content: "the function '" + region.name + "' compares a Date's .getTime() (or Date.parse()) against a bound with no isNaN guard -- an Invalid Date / unparseable string yields NaN, and every relational comparison against NaN is false, SILENTLY BYPASSING the gate; route through guard.time (assertValid/within) or reject isNaN() first, or mark allow:nan-date-comparison-unguarded when the value is source-validated (codec readTime / rfc3339.isValid / literal)" });
    });
  });
  bad = _filterMarkers(bad, "nan-date-comparison-unguarded");
  _report("no lib function compares a Date .getTime() against a bound without an isNaN guard (NaN-Date fail-open, codebase-wide)", bad);
}

// class: eddsa-verify-without-loworder-gate
// A public Ed25519/Ed448 (OKP) key reaches a signature VERIFY (or the createPublicKey import that
// feeds one) without first passing through the shared full-order / on-curve Edwards-point gate
// (edwards-point.validate / validateSpki). node imports a low-order (e.g. all-zeroes) OKP key WITHOUT
// complaint, and such a key VERIFIES a FORGED EdDSA signature (small-subgroup / twist). The gate is the
// single home; every EdDSA verify sink must route through it. This class was fixed BY HAND across
// webauthn (v0.2.6), composite-CMS + the path chain + jose (v0.2.18), and sigstore _pubFromSpki /
// _rawVerify (v0.2.31 / this cut) -- a 3+ release recurrence whose shared home was routed to purely by
// hand with NO tripwire, so a new verify sink in a never-reviewed file would fail open. Function-
// granular (model: ocsp-responder-auth-reinlined). The gate-fn names are DERIVED off edwards-point.js
// module.exports (single source of truth) so renaming validateSpki cannot silently green it. Rename-
// proof anchors, not locals: node's asymmetricKeyType returns the literal "ed25519"/"ed448"; the
// WebCrypto/COSE names are "Ed25519"/"Ed448"; the sinks are .verify( / subtle.verify / createPublicKey(.
// A sink whose caller provably pre-validates marks allow:eddsa-verify-without-loworder-gate.
function testEddsaVerifyGate() {
  var epSrc = fs.readFileSync(path.join(LIB_ROOT, "edwards-point.js"), "utf8");
  var epExports = (epSrc.match(EXPORT_LITERAL_RE) || ["", ""])[1];
  var gateFns = (epExports.match(/([A-Za-z_$][\w$]*)\s*:/g) || []).map(function (m) { return m.replace(/\s*:\s*$/, ""); });
  if (!gateFns.length) gateFns = ["validate", "validateSpki"];               // fallback if exports move
  var gateCall = new RegExp("\\b(?:" + gateFns.join("|") + ")\\s*\\(");
  var OKP = /\b(?:ed25519|ed448|Ed25519|Ed448)\b/;
  var SINK = /\.verify\s*\(|subtle\.verify|createPublicKey\s*\(/;
  // Excluded: edwards-point.js IS the gate; webcrypto.js is the thin SubtleCrypto ENGINE BELOW the gate
  // -- its import/verify primitives are gated by their CONSUMERS (a verifier validates the point before
  // handing the key to the engine), not by the engine, so gating inside it would be a layering inversion
  // and would wrongly gate X25519/X448 key-agreement keys. A stripComments helper keeps string literals.
  var SKIP = { "edwards-point.js": 1, "webcrypto.js": 1 };
  function _strip(body) { return body.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " "); }
  // Pass 1 (DERIVED): the gate is usually reached through a thin domain WRAPPER (webauthn
  // _requireValidEdPoint calls edwards-point.validate), not the gate export directly. Collect every
  // function that itself calls the gate; a verify sink that calls one of THEM is routed and safe. Reading
  // the routers off the tree keeps a wrapper rename from silently desyncing enforcement.
  var routers = {};
  _libFiles().forEach(function (f) {
    _functionRegions(fs.readFileSync(f, "utf8")).forEach(function (region) {
      if (gateCall.test(_strip(region.body))) routers[region.name] = 1;
    });
  });
  var gateRe = new RegExp("\\b(?:" + gateFns.concat(Object.keys(routers)).join("|") + ")\\s*\\(");
  var bad = [];
  _libFiles().forEach(function (f) {
    if (SKIP[path.basename(f)]) return;
    var rel = path.relative(REPO_ROOT, f);
    _functionRegions(fs.readFileSync(f, "utf8")).forEach(function (region) {
      var body = _strip(region.body);
      if (!OKP.test(body) || !SINK.test(body)) return;                       // only an OKP-handling verify/import sink
      if (gateRe.test(body)) return;                                         // routes through the gate (or a wrapper) -> safe
      bad.push({ file: rel, line: region.startLine,
        content: "the function '" + region.name + "' verifies or imports an Ed25519/Ed448 (OKP) key without routing it through the edwards-point low-order/on-curve gate (" + gateFns.join(" / ") + ") -- node imports a low-order OKP key silently and it verifies a FORGED EdDSA signature; route the key through edwards-point.validate / validateSpki (directly or via a wrapper that does) before the verify sink, or mark allow:eddsa-verify-without-loworder-gate when the caller provably pre-validates" });
    });
  });
  bad = _filterMarkers(bad, "eddsa-verify-without-loworder-gate");
  _report("no lib function verifies/imports an Ed25519/Ed448 key without the edwards-point low-order gate (EdDSA forged-signature fail-open, codebase-wide)", bad);
}

// Split a source file into top-level function regions [{ name, startLine, body }].
// A region spans from one function declaration to the next; a nested closure is
// lumped into its parent region -- a re-inline in a closure is still inside the
// parent, which is what the guard-shape walk wants.
function _functionRegions(src) {
  var lines = _lines(src);
  var starts = [];
  // A region begins at any named function -- a `function NAME(`, a `NAME = function`,
  // OR a `NAME = (...) =>` / `NAME = arg =>` arrow (the assignment form; an inline
  // anonymous arrow stays in its enclosing region, which is what the walk wants).
  var ARROW = "=\\s*(?:async\\s+)?(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>";
  var PATS = [
    /^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/,
    /^\s*(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b/,
    /^\s*([A-Za-z_$][\w$.]*)\s*=\s*(?:async\s+)?function\b/,
    new RegExp("^\\s*(?:var|const|let)\\s+([A-Za-z_$][\\w$]*)\\s*" + ARROW),
    new RegExp("^\\s*([A-Za-z_$][\\w$.]*)\\s*" + ARROW),
  ];
  for (var i = 0; i < lines.length; i++) {
    var m = null;
    for (var pi = 0; pi < PATS.length; pi++) { m = lines[i].match(PATS[pi]); if (m) break; }
    if (m) starts.push({ name: m[1], line: i });
  }
  var out = [];
  // A module-preamble region covers top-level code (requires, module-level const
  // arrows) BEFORE the first function, so no line escapes the function-scoped walk.
  var firstStart = starts.length ? starts[0].line : lines.length;
  if (firstStart > 0) out.push({ name: "<module>", startLine: 1, body: lines.slice(0, firstStart).join("\n") });
  for (var k = 0; k < starts.length; k++) {
    var s = starts[k].line;
    var e = (k + 1 < starts.length) ? starts[k + 1].line : lines.length;
    out.push({ name: starts[k].name, startLine: s + 1, body: lines.slice(s, e).join("\n") });
  }
  return out;
}

function testCborMapPairAccessOutsideCodec() {
  // class: cbor-map-pair-access-outside-codec
  // A CBOR node's `children` are [key, value] PAIRS only for a MAP (majorType 5). For an
  // ARRAY (majorType 4) the children are single value nodes, so reading a children element
  // as a pair -- node.children[i][0], or a node.children.forEach(kv => kv[0]) split -- yields
  // `undefined`, and dereferencing it (kv[0].majorType) throws a RAW TypeError on hostile
  // input (fuzz-found: a CBOR-array attStmt reaching the WebAuthn attestation-statement walk)
  // instead of a typed fail-closed reject. The codec owns the two safe accessors --
  // cbor.read.map(node) (asserts the major type, returns the pairs) and
  // cbor.read.mapGet(node, key) (asserted keyed lookup) -- so OUTSIDE lib/cbor-det.js a raw
  // pair access is a violation even when a local guard happens to precede it: the guarded
  // hand-roll is exactly the duplicate that drifts (the fuzz-found instance was the one
  // hand-roll among three that lost its guard). Pair access on read.map's RETURN value is
  // legitimate and does not match (the reader already asserted the type). Rename-proof:
  // it matches the `.children` pair-access SHAPE, no symbol.
  var CODEC_HOME = "cbor-det.js";
  // Form A -- an indexed pair access: children[<expr>][0] / children[<expr>][1].
  var INDEXED = /\.children\s*\[[^\]\n]+\]\s*\[\s*[01]\s*\]/;
  // Form B -- a .children iteration whose callback PARAMETER is then pair-indexed [0]/[1].
  var ITER = /\.children\s*\.\s*(?:forEach|map|some|every|filter|reduce|find|flatMap)\s*\(\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = path.relative(REPO_ROOT, f);
    if (path.basename(f) === CODEC_HOME) return;           // the codec is the accessors' home
    var src = fs.readFileSync(f, "utf8");
    _functionRegions(src).forEach(function (reg) {
      // Strip block + line comments so a doc-comment mention of the shape does not count.
      var body = reg.body.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
      var hit = INDEXED.test(body);
      if (!hit) {
        var im = body.match(ITER);
        if (im) {
          var param = im[1].replace(/[.$]/g, "\\$&");
          hit = new RegExp("\\b" + param + "\\s*\\[\\s*[01]\\s*\\]").test(body);
        }
      }
      if (hit) bad.push({ file: rel, line: reg.startLine,
        content: "cbor-map-pair-access-outside-codec in " + reg.name + "() -- a node.children element is read as a { key, value } pair outside the codec; route through cbor.read.map / cbor.read.mapGet, which assert majorType 5 (a non-map's children are single nodes, so a pair index throws a raw TypeError on hostile input)" });
    });
  });
  bad = _filterMarkers(bad, "cbor-map-pair-access-outside-codec");
  _report("no CBOR map-pair access outside the codec home (raw-TypeError fail-open vector, codebase-wide)", bad);
}

function testOcspResponderAuthReinlined() {
  // class: ocsp-responder-auth-reinlined
  // An OCSP response is only trustworthy if its signer is an AUTHORIZED responder:
  // the issuing CA directly, or a CA-issued delegate that asserts the id-kp-OCSPSigning
  // extendedKeyUsage AND carries the id-pkix-ocsp-nocheck extension (RFC 6960 sec.
  // 4.2.2.2 -- anyEKU / an absent EKU do NOT authorize, and a transport-free verifier
  // cannot otherwise confirm the responder cert is unrevoked). That out-of-path
  // signer-cert authorization is the single most security-critical, easiest-to-
  // under-enforce gate in the toolkit, so it lives in exactly ONE place --
  // lib/ocsp-verify.js's makeOcspVerify(...) core, which both the path validator's
  // ocspChecker and pki.ocsp.verify compose. A SECOND verify path that re-resolves
  // these two OIDs itself is re-inlining the authorization decision instead of routing
  // through that core -- the exact drift that reintroduces a fail-open responder.
  //
  // Rename-proof: it matches the co-occurrence of the two RFC-frozen OID registry
  // names (`ocspSigning` and `ocspNoCheck`, the arguments oid.byName resolves) within
  // one function body, comments stripped but string literals kept. A legitimate
  // consumer routes through the core and never names both OIDs, so it cannot match;
  // the OID registry (oid.js) and the display-name table (constants.js) DECLARE the
  // names without performing authorization and are the shape's declaration homes.
  var HOME = "lib/ocsp-verify.js";
  // Declaration homes NAME the two OIDs without performing authorization: the OID registry (oid.js), the
  // display-name table (constants.js), and the C509 int->name alias registries (schema-c509.js -- the
  // sec. 8.12 EKU table names ocspSigning, the sec. 8.8 extension table names ocspNoCheck).
  var DECL_HOMES = { "lib/oid.js": 1, "lib/constants.js": 1, "lib/schema-c509.js": 1 };
  var SIGNING = /\bocspSigning\b/, NOCHECK = /\bocspNoCheck\b/;
  function stripComments(s) {
    return s.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
  }
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (rel === HOME || DECL_HOMES[rel]) return;
    var src = fs.readFileSync(f, "utf8");
    _functionRegions(src).forEach(function (r) {
      var body = stripComments(r.body);
      if (SIGNING.test(body) && NOCHECK.test(body)) {
        bad.push({ file: rel, line: r.startLine,
          content: "function `" + r.name + "` resolves both the id-kp-OCSPSigning EKU and the id-pkix-ocsp-nocheck extension -- OCSP responder authorization re-inlined outside " + HOME + "; route it through ocspVerify.makeOcspVerify(...).evaluateResponse (the one place the out-of-path responder-cert authorization lives)" });
      }
    });
  });
  bad = _filterMarkers(bad, "ocsp-responder-auth-reinlined");
  _report("no lib function re-inlines OCSP responder authorization outside " + HOME, bad);
}

function testRawSecretExportIsWiped() {
  // class: raw-secret-export-unwiped
  // A no-argument `_handle.export()` returns a FRESH Buffer holding a secret key's raw
  // material -- an AES content key, a derived KEK, a KDF's input keying material. That
  // copy is the toolkit's own allocation, and left behind it keeps a full copy of the key
  // readable for the process lifetime, so it must be cleared once the operation has
  // consumed it (NIST SP 800-227 sec. 4.2, RFC 9629 sec. 7).
  //
  // The rule is "the function that takes the export also clears it" rather than "call a
  // particular helper": a check anchored on a helper's NAME goes silently green the moment
  // the helper is renamed, while this one keeps holding. It fires on a new export site in a
  // file nobody has written yet, which is the point -- the failure mode is one arm of a
  // dispatch clearing its export while a sibling arm on the same dispatch does not.
  //
  // Argument-bearing forms -- export({ format: "jwk" | "der" ... }) -- carry public or
  // already-encoded material and are deliberately not this shape.
  var RAW_EXPORT = /_handle\s*\.\s*export\s*\(\s*\)/;
  var WIPES = /guard\.secret\.zeroize/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var src = fs.readFileSync(f, "utf8");
    if (!RAW_EXPORT.test(_stripCommentsAndLiterals(src))) return;
    _functionRegions(src).forEach(function (r) {
      var body = _stripCommentsAndLiterals(r.body);
      if (RAW_EXPORT.test(body) && !WIPES.test(body)) {
        bad.push({ file: _relPath(f), line: r.startLine,
          content: "function `" + r.name + "` exports raw secret key material but never clears it — wipe the export once the operation has consumed it, so a copy of the key does not outlive the operation" });
      }
    });
  });
  bad = _filterMarkers(bad, "raw-secret-export-unwiped");
  _report("every function that exports raw secret key material also clears it (function-granular)", bad);
}

function testGuardShapeReinlined() {
  // class: guard-shape-reinlined
  // Function-granular, DERIVED guard enforcement. Each shape-enforced guard
  // declares its characteristic code pattern ON the guard function:
  //   @guard-shape <regex>        -- a pattern the guard encapsulates (repeat = ALL must match)
  //   @guard-via   <regex>        -- optional: a routing call; a match that ALSO has this ROUTES
  //   @guard-scope function|file  -- default function; `file` for a cross-function vector
  // This walks EVERY function (or file) of EVERY lib module and flags one that
  // re-inlines a guard's shape instead of routing through the guard. The shape
  // lives ON the guard (single source of truth -- it cannot drift from what the
  // guard actually does), and a NEW guard that declares @guard-shape is enforced
  // automatically, with no hand-written detector. Together with
  // testEveryGuardEnforced (which requires the @enforced-by declaration), a guard
  // can neither ship without enforcement nor let its enforcement drift from its
  // implementation. This replaces the hand-written detached-view-buffer /
  // constant-time-compare / decode-maxdepth detectors -- their shapes now live on
  // guard-bytes.view, guard-crypto.constantTimeEqual, guard-limits.depthCap.
  var guards = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (!/^lib\/guard-[a-z-]+\.js$/.test(rel) || rel === "lib/guard-all.js") return;
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      var fm = lines[i].match(/^function\s+([A-Za-z_$][\w$]*)\s*\(/);
      if (!fm) continue;
      var shapes = [], via = null, scope = "function";
      for (var b = i - 1; b >= 0 && /^\s*(?:\/\/|\*|\/\*)/.test(lines[b]); b--) {
        var sm = lines[b].match(/@guard-shape\s+(.+?)\s*$/); if (sm) shapes.unshift(sm[1]);
        var vm = lines[b].match(/@guard-via\s+(.+?)\s*$/);   if (vm) via = vm[1];
        var cm = lines[b].match(/@guard-scope\s+(\w+)/);     if (cm) scope = cm[1];
      }
      if (shapes.length) {
        var mod = rel.replace(/^lib\/guard-([a-z-]+)\.js$/, "$1");
        guards.push({ module: rel, ref: "guard." + mod + "." + fm[1], shapes: shapes, via: via, scope: scope });
      }
    }
  });
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    var src = fs.readFileSync(f, "utf8");
    var fileBody = _stripCommentsAndLiterals(src);
    var regions = null;
    guards.forEach(function (g) {
      if (g.module === rel) return;   // the guard's own module is the shape's home
      function isHit(body) {
        if (!g.shapes.every(function (s) { return new RegExp(s).test(body); })) return false;
        if (g.via && new RegExp(g.via).test(body)) return false;   // routes through the guard
        return true;
      }
      if (g.scope === "file") {
        if (!isHit(fileBody)) return;
        var lines = _lines(src), anchor = 1;
        for (var i = 0; i < lines.length; i++) {
          if (!/^\s*(\/\/|\*)/.test(lines[i]) && new RegExp(g.shapes[0]).test(lines[i])) { anchor = i + 1; break; }
        }
        bad.push({ file: rel, line: anchor,
          content: "re-inlines the " + g.ref + " shape (file-scope vector) — route the pattern through " + g.ref });
        return;
      }
      if (regions === null) regions = _functionRegions(src);
      regions.forEach(function (r) {
        if (isHit(_stripCommentsAndLiterals(r.body))) {
          bad.push({ file: rel, line: r.startLine,
            content: "function `" + r.name + "` re-inlines the " + g.ref + " shape — route it through " + g.ref + " (the one place its fail-closed defense lives)" });
        }
      });
    });
  });
  bad = _filterMarkers(bad, "guard-shape-reinlined");
  _report("no lib function re-inlines a guard shape instead of routing through the guard (function-granular, derived)", bad);
}

function testConstantTimeCompareShortCircuited() {
  // class: constant-time-compare-short-circuited
  // Two constant-time compares joined by && / || short-circuit the second: when
  // the first is false the second compare never runs, reopening the timing
  // side-channel the constant-time compare exists to close. Evaluate each into a
  // var, THEN combine. This is DISTINCT from constant-time-compare-not-via-guard:
  // that enforces the compare lives in guard-crypto; this catches short-circuiting
  // the guard's CALLS at any consumer. Two-pass, file-scoped. PASS 1 derives the
  // CT-token set = the frozen node:crypto `timingSafeEqual` PLUS the guard's
  // exported `constantTimeEqual` PLUS the name of any local function whose body
  // wraps either (recovers a `_ctEq`-style delegate WITHOUT hardcoding its name).
  // PASS 2 fires on TWO CT-token CALLS joined by &&/|| inside one expression,
  // bounded away from ; { } so a wrapper DEFINITION and two separate statements
  // combining already-evaluated vars do NOT match.
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    var stripped = _stripCommentsAndLiterals(fs.readFileSync(f, "utf8"));
    if (!/\btimingSafeEqual\b/.test(stripped) && !/\bconstantTimeEqual\b/.test(stripped)) return;
    // PASS 1: CT-token set = the two frozen compare names + wrapper fn names.
    var toks = { timingSafeEqual: true, constantTimeEqual: true };
    var wrapRe = /(?:function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)|(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\([^)]*\))\s*\{[^{}]*(?:timingSafeEqual|constantTimeEqual)/g;
    var wm;
    while ((wm = wrapRe.exec(stripped))) { toks[wm[1] || wm[2]] = true; }
    var alt = Object.keys(toks).sort(function (a, b) { return b.length - a.length; })
      .map(function (t) { return t.replace(/[$]/g, "\\$&"); }).join("|");
    var pairRe = new RegExp("\\b(?:" + alt + ")\\s*\\([^;{}]*?\\)\\s*(?:&&|\\|\\|)\\s*[^;{}]*?\\b(?:" + alt + ")\\s*\\(");
    // PASS 2 is line-scoped (skip comment lines); the class as it appears in real
    // code is one expression per line.
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      if (/^\s*(\/\/|\*)/.test(lines[i])) continue;
      if (pairRe.test(lines[i])) {
        bad.push({ file: rel, line: i + 1,
          content: "two constant-time compares joined by &&/|| short-circuit the second (a timing side-channel) — evaluate each into a var, then combine: " + lines[i].trim().slice(0, 80) });
      }
    }
  });
  bad = _filterMarkers(bad, "constant-time-compare-short-circuited");
  _report("no constant-time compare is short-circuited by &&/|| (codebase-wide)", bad);
}

// class: asn1-reader-does-not-exist
//
// A call to `asn1.read.<name>` naming a reader the codec does not export. The
// invariant: every leaf read goes through a reader that exists, so a decode path
// fails with the toolkit's typed PkiError rather than a raw TypeError.
//
// This shape is worth a detector precisely because nothing else catches it. It is
// not a syntax error, eslint sees a normal property access, and the call throws
// only when that exact branch executes -- so an OPTIONAL field decoded by a
// mistyped reader ships green through every gate until a peer sends the field. A
// raw `TypeError: asn1.read.utf8 is not a function` from a parser is also a
// fuzz-contract violation (hostile bytes may only succeed or throw a PkiError) and
// leaves a caller unable to tell malformed input from a broken decoder.
//
// DERIVED, so it cannot drift: the set of valid names is read OFF pki.asn1.read at
// run time rather than duplicated here, which means a reader added or removed
// tomorrow needs no edit, and a NEW format module typing `read.bmpString` is caught
// on its first commit.
function testAsn1ReaderExists() {
  var real = Object.keys(require("../../lib/asn1-der").read);
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = path.relative(REPO_ROOT, f);
    var src = fs.readFileSync(f, "utf8");
    // Comments stripped so a doc block naming a reader does not count as a call.
    var body = src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    var re = /\basn1\.read\.([A-Za-z_$][\w$]*)/g;
    var m;
    while ((m = re.exec(body))) {
      if (real.indexOf(m[1]) !== -1) continue;
      bad.push({ file: rel, line: body.slice(0, m.index).split("\n").length,
        content: "asn1-reader-does-not-exist: asn1.read." + m[1] + " is not exported by the codec, so this " +
          "decode throws a raw TypeError instead of a typed PkiError. Readers are: " + real.join(" ") });
    }
  });
  bad = _filterMarkers(bad, "asn1-reader-does-not-exist");
  _report("every asn1.read.<name> call names a reader the codec actually exports", bad);
}

function testGuardReadsRuntimeLive() {
  // class: guard-reads-runtime-live
  // Load the toolkit so the module graph the scope decision reads is populated. Requiring the entry
  // point pulls in every lib module, and a module the entry point never reaches cannot be taking
  // the captures in anything that ships.
  require("../../index.js");
  // A guard decides things, and it decides them with operations it reads from the runtime. Every
  // one of those is an ordinary writable property of a global, so reading it at the moment it runs
  // hands the decision to whoever last wrote it. The failures are silent and in the PASSING
  // direction: a `forEach` replaced with a no-op makes a scan report nothing over real keys and
  // the rule keyed on that scan then passes over an empty list; a `toLowerCase` returning a
  // constant makes every distinguished name equal to every other.
  //
  // This was found SIX times in a row, one reference at a time, each fix closing exactly the one
  // named and leaving the next tier live: the method, then the `.call` used to invoke it, then the
  // array test asked again deeper in, then the constructor a re-view built with, then the
  // re-encode half of a round trip whose decode half was captured, then the array and collection
  // prototypes. This detector exists so the seventh is found here rather than by a reviewer.
  //
  // The rule: inside lib/guard-*.js, a bare `Global.member(` or a bare `x.method(` on one of the
  // known-replaceable operation names is a live read. The safe spellings are a module-load capture
  // (a `_`-prefixed local bound from guard-intrinsic or from the prototype directly) and a call
  // through it. guard-intrinsic itself is where the captures are taken, so it is exempt.
  var LIVE_STATICS = [
    "Object\\.(?:create|keys|assign|freeze|getPrototypeOf|setPrototypeOf|getOwnPropertyNames|getOwnPropertyDescriptor|defineProperty|isExtensible)",
    "Array\\.isArray", "ArrayBuffer\\.isView", "Reflect\\.(?:ownKeys|apply)",
    "Buffer\\.(?:from|alloc|isBuffer|byteLength|concat|compare)",
    "Number\\.(?:isInteger|isSafeInteger|isNaN)", "String\\.fromCharCode",
    "JSON\\.stringify", "Math\\.(?:floor|ceil|min|max)", "Promise\\.(?:resolve|reject)",
  ];
  // `equals` and `compare` are Buffer.prototype's identity verbs, `toString` and `subarray` its
  // byte-to-text and byte-slice steps. Each decides something on its own: one `equals` answering
  // true matches any value against any other, and one `toString` returning a constant makes every
  // name equal every other name it is compared against.
  // The string and pattern verbs are here because an identity comparison is built out of them: where
  // a mailbox separator sits, which substring is the domain, whether a local-part is well-formed,
  // how a URI splits into scheme and authority. Each is one replaceable call, and moving any one of
  // them moves the boundary, so the name the verb ends up comparing is not the one on the wire.
  var LIVE_METHODS = "(?:forEach|map|filter|every|some|indexOf|sort|push|concat|join|" +
    "toLowerCase|toUpperCase|charAt|charCodeAt|fill|getTime|equals|compare|toString|subarray|" +
    "slice|lastIndexOf|search|test|exec|replace|split|trim|substring|substr|startsWith|endsWith|" +
    "includes|hasOwnProperty)";
  var staticRe = new RegExp("\\b(?:" + LIVE_STATICS.join("|") + ")\\s*\\(", "g");
  // A method call whose receiver is NOT a `_`-prefixed capture. The receiver may be a whole member
  // expression: `sanNode.bytes.equals(...)` dispatches off a prototype exactly as `bytes.equals(...)`
  // does, and matching only a bare identifier let that one through. What the leading `_` exclusion
  // has to apply to is the ROOT of the expression, since that is where a capture is named.
  // `intrinsic.x(` and `guard.x(` are module handles rather than prototypes, so they are excluded
  // by name below.
  var MODULE_HANDLES = /^(?:intrinsic|_intrinsic|guard|helpers|pkix|schema|oid|asn1|cbor|C|errors|util|crypto|os|fs|path|constants)$/;
  var methodRe = new RegExp(
    "(?:^|[^\\w.$])(?!_)([A-Za-z$][\\w$]*)((?:\\.[A-Za-z$][\\w$]*)*)\\." + LIVE_METHODS + "\\s*\\(", "g");
  // The same dispatch off a CALL RESULT rather than off a named chain. `_String(name).toUpperCase()`
  // reads `toUpperCase` from whatever the call returned, exactly as `name.toUpperCase()` does, and
  // the rule is the same -- but the pattern above needs an identifier before the dot, so four of
  // these survived a migration that had removed every other spelling. One of them decided which
  // hash a digest ran under, so a replaced case fold answered SHA-1 to a caller who asked for
  // SHA-256. The receiver is unnamed here, so the match is reported by its method alone.
  var callResultMethodRe = new RegExp("\\)\\s*\\." + LIVE_METHODS + "\\s*\\(", "g");
  // The conversions and predicates called as bare globals. They read as language rather than as
  // code, which is why they outlasted every other read here: an index test is
  // `String(Number(k)) === k`, an arc bound is a bound on `BigInt(part)`, a JSON number is refused
  // by `isFinite(v)`, and a default validation time is `new Date()`. Each is an ordinary writable
  // property of globalThis. A property access like `Number.isInteger` is not a call and is
  // excluded; `new Date(...)` IS included, because which constructor runs is the question.
  var convertRe =
    /(?:^|[^\w.$])(?:new\s+)?(String|Number|Boolean|BigInt|Date|isFinite|isNaN|parseInt|parseFloat|ArrayBuffer|Uint8Array|DataView|Object)\s*\(/g;
  // A prototype OBJECT used as an identity sentinel -- "is this plain", "is this a Buffer", "has
  // the chain walk reached the top". It is reached as a property of a replaceable global, so after
  // a replacement the sentinel is a different object and every comparison against it is false.
  // A `uncurry(X.prototype.m)` capture is a call-time-free read taken at load, so it is excluded.
  var protoRe = /(?:^|[^\w.$])(Object|Buffer|Array|Function|Promise)\.prototype(?!\s*\.\s*\w+\s*\))/g;
  // SCOPE, chosen so it needs no list to maintain. A module is IN once it takes the captures:
  // that is how it opts into the discipline, and once opted in it is held to it completely rather
  // than at the one site somebody happened to change. A module that has not opted in is out of
  // scope and stays out until it does, so the rule extends by the same edit that would otherwise
  // create a half-swept file. Naming the modules instead would be a judgment about which ones
  // decide things, and the seven rounds above are what that judgment is worth.
  //
  // Taking the captures has TWO spellings, and matching only the first left the rule satisfiable
  // around: a module that reached them through the guard orchestrator as `guard.intrinsic.<x>` got
  // the safe primitive at the site it changed and never entered scope, so its remaining live reads
  // were never named. Nine modules were in that state. Both spellings arm the check.
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (rel === "lib/guard-intrinsic.js") return;   // where the captures are taken
    var src = fs.readFileSync(f, "utf8");
    // The second spelling is matched WITHOUT naming its receiver. `guard` is what every module
    // calls the orchestrator today, and anchoring on that name would rebuild the same hole one
    // rename away: a module binding it as anything else would reach the captures and stay outside.
    //
    // Both are decided from EXECUTABLE source. Read off the raw file, a `.intrinsic.` written in a
    // comment or a documentation example enrolls a module that never touches the captures, and the
    // gate then demands a conversion that has nothing to do with what the file does. The two
    // spellings need different text: the require path IS a string literal, so it is matched with
    // comments removed and literals intact, while the property access is matched with both removed.
    // Decided from EXECUTABLE text, so neither spelling can be conjured by prose. A `.intrinsic.`
    // in a comment or a documentation string enrolls a module that never touches the captures and
    // the gate then demands conversions unrelated to anything the file does, while a commented-out
    // or quoted `require` does the same. Emptying every literal except an actual module path is
    // what separates the call from a quotation of it: `require("./guard-intrinsic")` keeps its
    // argument, and a string reading `"require('./guard-intrinsic')"` is one literal whose content
    // is something longer, so it collapses and takes the require wording inside it with it.
    if (!_takesCaptures(f)) return;
    var lines = _lines(src);
    for (var i = 0; i < lines.length; i++) {
      // A `*`-led line is the continuation of a block comment. The stripper works one line at a
      // time, so it cannot see the `/*` that opened it, and a `@example` block would otherwise be
      // read as code.
      if (/^\s*\*/.test(lines[i])) continue;
      var code = _stripCommentsAndLiterals(lines[i]);
      var m;
      staticRe.lastIndex = 0;
      while ((m = staticRe.exec(code)) !== null) {
        bad.push({ file: rel, line: i + 1,
          content: "reads `" + m[0].replace(/\s*\($/, "") + "` from the runtime at call time — " +
            "bind it at module load through guard-intrinsic, so a caller who replaces it afterwards " +
            "cannot decide what this guard concludes" });
      }
      methodRe.lastIndex = 0;
      while ((m = methodRe.exec(code)) !== null) {
        if (MODULE_HANDLES.test(m[1])) continue;
        bad.push({ file: rel, line: i + 1,
          content: "dispatches `" + m[0].trim() + "` through a live prototype — " +
            "use the uncurried capture from guard-intrinsic, so a replaced prototype method cannot " +
            "decide what this guard concludes" });
      }
      callResultMethodRe.lastIndex = 0;
      while ((m = callResultMethodRe.exec(code)) !== null) {
        bad.push({ file: rel, line: i + 1,
          content: "dispatches `" + m[0].trim() + "` off a call result through a live prototype — " +
            "use the uncurried capture from guard-intrinsic, so a replaced prototype method cannot " +
            "decide what this guard concludes" });
      }
      protoRe.lastIndex = 0;
      while ((m = protoRe.exec(code)) !== null) {
        bad.push({ file: rel, line: i + 1,
          content: "compares against the live `" + m[1] + ".prototype` — take the sentinel from " +
            "guard-intrinsic, so a replaced global cannot make the comparison answer about a " +
            "different object" });
      }
      convertRe.lastIndex = 0;
      while ((m = convertRe.exec(code)) !== null) {
        bad.push({ file: rel, line: i + 1,
          content: "converts through the live global `" + m[1] + "` — take it from guard-intrinsic, " +
            "so a replacement cannot decide what this value converts to" });
      }
    }
  });
  bad = _filterMarkers(bad, "guard-reads-runtime-live");

  // MIGRATING, a per-module budget rather than a skip list. A module enters the scope above the
  // moment it takes the captures, which arms the whole file at once while its reads are converted a
  // module at a time. A budget is not an exemption: it names an exact number, so a NEW live read in
  // one of these files pushes the module over its figure and fails the gate the same way a fresh
  // one would. The number is the only thing on this list -- there is no per-site allowance, so
  // nothing can hide behind "already dirty".
  //
  // It ratchets DOWN only. Converting sites without lowering the figure also fails, because a
  // budget nobody tightens is a number that stops meaning anything, and the next reader would take
  // it for the real count. A module reaching zero is deleted from the map and held to zero forever.
  var MIGRATING = {
    "lib/acme.js": 245,
    "lib/est.js": 203,
    "lib/cmp-build.js": 151,
    "lib/crmf-sign.js": 47,
    "lib/path-validate.js": 187,
    "lib/webauthn.js": 178,
    "lib/asn1-der.js": 135,
    "lib/trust.js": 111,
    "lib/cms-sign.js": 93,
    "lib/webauthn-mds.js": 92,
    "lib/attrcert-sign.js": 91,
    "lib/tsp-sign.js": 89,
    "lib/http-digest.js": 85,
    "lib/pkcs12-build.js": 78,
    "lib/ct.js": 78,
    "lib/cms-verify.js": 75,
    "lib/cms-encrypt.js": 73,
    "lib/crl-sign.js": 72,
    "lib/cmc-build.js": 64,
    "lib/pki-build.js": 56,
    "lib/hpke.js": 54,
    "lib/cms-decrypt.js": 53,
    "lib/cmc-verify.js": 39,
    "lib/x509-sign.js": 28,
    "lib/schema-attrcert.js": 26,
    "lib/tls-cert-compress.js": 19,
    "lib/schema-crl.js": 10,
    "lib/schema-ocsp.js": 9,
  };
  var counts = {};
  bad.forEach(function (b) { counts[b.file] = (counts[b.file] || 0) + 1; });
  var over = [];
  Object.keys(MIGRATING).forEach(function (f) {
    var actual = counts[f] || 0;
    if (actual > MIGRATING[f]) {
      over.push({ file: f, line: 1,
        content: "has " + actual + " live runtime reads against a declared budget of " +
          MIGRATING[f] + " — a new one was added to a file that is mid-conversion; convert it, or " +
          "convert an equal number of the existing reads in the same change" });
    } else if (actual < MIGRATING[f]) {
      over.push({ file: f, line: 1,
        content: "has " + actual + " live runtime reads against a stale budget of " + MIGRATING[f] +
          " — lower the figure in MIGRATING to " + actual + " (or delete the entry at zero), so the " +
          "number keeps naming the real count" });
    }
  });
  // A module with a budget reports only against that budget; everything else reports per site.
  bad = bad.filter(function (b) { return !Object.prototype.hasOwnProperty.call(MIGRATING, b.file); })
    .concat(over);
  _report("no module that takes the guard-intrinsic captures reads a replaceable runtime operation at call time", bad);
}

function testEveryGuardEnforced() {
  // class: guard-without-enforcement
  // Anti-drift META-check -- the guard-family analog of the @primitive comment-
  // block gate. It WALKS every EXPORTED function of every lib/guard-*.js module
  // (the orchestrator guard-all excepted) and requires each to declare, in its doc
  // comment, HOW its shape is kept from being re-inlined at a boundary: either
  //   @enforced-by <detector-class>          (a codebase-patterns enforcement detector), or
  //   @enforced-by behavioral -- <reason>    (a RED vector is the guard; no rename-proof shape).
  // A guard function with NO such tag is DRIFT: a fresh guard could ship whose
  // shape a boundary re-inlines with nothing catching it. A NAMED detector-class
  // must be REAL -- reported by a `_filterMarkers(bad, "<class>")` detector in this
  // file -- so the tag cannot reference a detector that does not exist. This is why
  // adding guard-range / guard-name / ... cannot silently skip its enforcement.
  var selfSrc = fs.readFileSync(path.join(REPO_ROOT, "test/layer-0-primitives/codebase-patterns.test.js"), "utf8");
  var bad = [];
  var guardFiles = _libFiles().filter(function (f) {
    var rel = _relPath(f);
    return /^lib\/guard-[a-z-]+\.js$/.test(rel) && rel !== "lib/guard-all.js";
  });
  guardFiles.forEach(function (f) {
    var rel = _relPath(f);
    var src = fs.readFileSync(f, "utf8");
    var lines = _lines(src);
    // Exported guard functions = the VALUES of module.exports = { key: fn, ... }.
    var expBlock = src.match(EXPORT_LITERAL_RE);
    var exported = Object.create(null);
    if (expBlock) {
      var er = /[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)/g, em;
      while ((em = er.exec(expBlock[1]))) exported[em[1]] = true;
    }
    for (var i = 0; i < lines.length; i++) {
      var m = lines[i].match(/^function\s+([A-Za-z_$][\w$]*)\s*\(/);
      if (!m || !exported[m[1]]) continue;
      var fn = m[1];
      // Walk up the contiguous comment block for the @enforced-by tag.
      var tag = null;
      for (var b = i - 1; b >= 0 && /^\s*(?:\/\/|\*|\/\*)/.test(lines[b]); b--) {
        var tm = lines[b].match(/@enforced-by\s+(\S+)/);
        if (tm) { tag = tm[1]; break; }
      }
      if (!tag) {
        bad.push({ file: rel, line: i + 1,
          content: "guard function `" + fn + "` has no `@enforced-by` tag -- declare its codebase-patterns enforcement detector, or `@enforced-by behavioral -- <reason>` if a RED vector is the guard (no silent drift: a guard shape a boundary could re-inline must be caught somewhere)" });
        continue;
      }
      if (tag !== "behavioral" && selfSrc.indexOf('_filterMarkers(bad, "' + tag + '")') === -1) {
        bad.push({ file: rel, line: i + 1,
          content: "guard function `" + fn + "` declares `@enforced-by " + tag + "` but no detector reporting that class exists in codebase-patterns.test.js -- a stale or typo'd enforcement reference" });
      }
    }
  });
  bad = _filterMarkers(bad, "guard-without-enforcement");
  _report("every guard function declares its codebase-patterns enforcement (@enforced-by)", bad);
}

function testEveryGuardExportFrozen() {
  // class: guard-export-writable
  // Anti-drift META-check. A boundary reaches its guard as `guard.<family>.<fn>(...)` at the call
  // itself, and the module registry hands every caller the same exports object, so a writable
  // export lets one assignment replace a fail-closed check in every module at once -- the
  // substitution the family exists to refuse, reached through the family's own front door rather
  // than around it. This LOADS each module and asks the runtime, so it cannot be satisfied by a
  // freeze that some later edit stops reaching; a new guard-*.js that ships writable fails here.
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (!/^lib\/guard-[a-z-]+\.js$/.test(rel)) return;
    var mod;
    try { mod = require(f); }
    catch (e) {
      bad.push({ file: rel, line: 1, content: "guard module did not load: " + ((e && e.message) || e) });
      return;
    }
    if (!Object.isFrozen(mod)) {
      bad.push({ file: rel, line: 1,
        content: "guard module exports a writable object -- wrap the literal in Object.freeze, so a " +
          "caller who reaches the family through the registry cannot replace a check instead of passing it" });
    }
  });
  bad = _filterMarkers(bad, "guard-export-writable");
  _report("every guard module freezes its exports", bad);
}

function testValidatorShapeReinlined() {
  // class: validator-shape-reinlined
  // The validator-family analog of guard-shape-reinlined (Layer A). Where a guard owns
  // a CVE-class fail-closed defense once, a VALIDATOR owns a decoded TYPE's COMPLETE
  // conformance rule set once (the COSE credential key, the attestation-cert profile,
  // the TPM pubArea). Each validator function declares its characteristic validation
  // shape ON the function:
  //   @validator-shape <regex>       -- a pattern the validator encapsulates (repeat = ALL match)
  //   @validator-via   <regex>       -- optional: a routing call; a match that ALSO has this ROUTES
  //   @validator-scope function|file -- default function; `file` for a cross-function vector
  // This walks EVERY function (or file) of EVERY lib module and flags one that re-inlines
  // a validator's shape instead of routing through the validator. The shape lives ON the
  // validator (single source of truth -- it cannot drift from what the validator does),
  // and a NEW validator that declares @validator-shape is enforced automatically. This is
  // the structural cure for the drift that leaks a spec MUST out one review round at a
  // time: a not-yet-written format module that re-derives COSE-key validation inline is
  // flagged the moment it lands, before a reviewer has to find the gap.
  var validators = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (!/^lib\/validator-[a-z-]+\.js$/.test(rel) || rel === "lib/validator-all.js") return;
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      var fm = lines[i].match(/^function\s+([A-Za-z_$][\w$]*)\s*\(/);
      if (!fm) continue;
      var shapes = [], via = null, scope = "function";
      for (var b = i - 1; b >= 0 && /^\s*(?:\/\/|\*|\/\*)/.test(lines[b]); b--) {
        var sm = lines[b].match(/@validator-shape\s+(.+?)\s*$/); if (sm) shapes.unshift(sm[1]);
        var vm = lines[b].match(/@validator-via\s+(.+?)\s*$/);   if (vm) via = vm[1];
        var cm = lines[b].match(/@validator-scope\s+(\w+)/);     if (cm) scope = cm[1];
      }
      if (shapes.length) {
        var mod = rel.replace(/^lib\/validator-([a-z-]+)\.js$/, "$1");
        validators.push({ module: rel, ref: "validator." + mod + "." + fm[1], shapes: shapes, via: via, scope: scope });
      }
    }
  });
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    var src = fs.readFileSync(f, "utf8");
    var fileBody = _stripCommentsAndLiterals(src);
    var regions = null;
    validators.forEach(function (g) {
      if (g.module === rel) return;   // the validator's own module is the shape's home
      function isHit(body) {
        if (!g.shapes.every(function (s) { return new RegExp(s).test(body); })) return false;
        if (g.via && new RegExp(g.via).test(body)) return false;   // routes through the validator
        return true;
      }
      if (g.scope === "file") {
        if (!isHit(fileBody)) return;
        var lines = _lines(src), anchor = 1;
        for (var i = 0; i < lines.length; i++) {
          if (!/^\s*(\/\/|\*)/.test(lines[i]) && new RegExp(g.shapes[0]).test(lines[i])) { anchor = i + 1; break; }
        }
        bad.push({ file: rel, line: anchor,
          content: "re-inlines the " + g.ref + " shape (file-scope vector) — route the pattern through " + g.ref });
        return;
      }
      if (regions === null) regions = _functionRegions(src);
      regions.forEach(function (r) {
        if (isHit(_stripCommentsAndLiterals(r.body))) {
          bad.push({ file: rel, line: r.startLine,
            content: "function `" + r.name + "` re-inlines the " + g.ref + " shape — route it through " + g.ref + " (the one place its type's conformance rule set lives)" });
        }
      });
    });
  });
  bad = _filterMarkers(bad, "validator-shape-reinlined");
  _report("no lib function re-inlines a validator shape instead of routing through the validator (function-granular, derived)", bad);
}

function testEveryValidatorEnforced() {
  // class: validator-without-enforcement
  // The validator-family analog of testEveryGuardEnforced. It WALKS every EXPORTED
  // function of every lib/validator-*.js module (the orchestrator validator-all excepted)
  // and requires each to declare, in its doc comment, HOW its shape is kept from being
  // re-inlined at a boundary: either
  //   @enforced-by <detector-class>          (a codebase-patterns enforcement detector), or
  //   @enforced-by behavioral -- <reason>    (a RED vector is the validator; no rename-proof shape).
  // A validator function with NO such tag is DRIFT: a fresh validator could ship whose
  // rule set a boundary re-derives inline with nothing catching it. A NAMED detector-class
  // must be REAL -- reported by a `_filterMarkers(bad, "<class>")` detector in this file.
  var selfSrc = fs.readFileSync(path.join(REPO_ROOT, "test/layer-0-primitives/codebase-patterns.test.js"), "utf8");
  var bad = [];
  var validatorFiles = _libFiles().filter(function (f) {
    var rel = _relPath(f);
    return /^lib\/validator-[a-z-]+\.js$/.test(rel) && rel !== "lib/validator-all.js";
  });
  validatorFiles.forEach(function (f) {
    var rel = _relPath(f);
    var src = fs.readFileSync(f, "utf8");
    var lines = _lines(src);
    var expBlock = src.match(EXPORT_LITERAL_RE);
    var exported = Object.create(null);
    if (expBlock) {
      var er = /[A-Za-z_$][\w$]*\s*:\s*([A-Za-z_$][\w$]*)/g, em;
      while ((em = er.exec(expBlock[1]))) exported[em[1]] = true;
    }
    for (var i = 0; i < lines.length; i++) {
      var m = lines[i].match(/^function\s+([A-Za-z_$][\w$]*)\s*\(/);
      if (!m || !exported[m[1]]) continue;
      var fn = m[1];
      var tag = null;
      for (var b = i - 1; b >= 0 && /^\s*(?:\/\/|\*|\/\*)/.test(lines[b]); b--) {
        var tm = lines[b].match(/@enforced-by\s+(\S+)/);
        if (tm) { tag = tm[1]; break; }
      }
      if (!tag) {
        bad.push({ file: rel, line: i + 1,
          content: "validator function `" + fn + "` has no `@enforced-by` tag -- declare its codebase-patterns enforcement detector, or `@enforced-by behavioral -- <reason>` if a RED vector is the validator (no silent drift: a type rule set a boundary could re-inline must be caught somewhere)" });
        continue;
      }
      if (tag !== "behavioral" && selfSrc.indexOf('_filterMarkers(bad, "' + tag + '")') === -1) {
        bad.push({ file: rel, line: i + 1,
          content: "validator function `" + fn + "` declares `@enforced-by " + tag + "` but no detector reporting that class exists in codebase-patterns.test.js -- a stale or typo'd enforcement reference" });
      }
    }
  });
  bad = _filterMarkers(bad, "validator-without-enforcement");
  _report("every validator function declares its codebase-patterns enforcement (@enforced-by)", bad);
}

function testInlineStructureValidatorCluster() {
  // class: inline-structure-validator
  // Layer B of the validator/guard family: a HARD gate on the shape a validator exists to
  // absorb -- a lib function that hand-rolls a binary-structure reader (`new ByteReader(`)
  // AND runs a dense cluster of field-validation throws inline. That shape is precisely what
  // validator-tpm's parsePubArea/parseCertInfo were BEFORE extraction: a decode-and-densely-
  // validate of one wire structure, sitting in a format module rather than in a single home.
  // When it recurs -- a NEW hand-rolled TPM/CBOR/TLS structure reader in a file no reviewer
  // has seen -- this fires, forcing the author to extract it to a validator-* (a decoded
  // TYPE's rule set) or guard-* (a fail-closed shape), or to justify keeping it inline with
  // an `allow:inline-structure-validator <reason>` marker.
  //
  // The trigger is `new ByteReader(` (a stable exported class -- rename-proof) PLUS >= 5
  // throws in the SAME function, scoped away from guard-*/validator-* (the extraction homes)
  // and byte-reader.js (the class itself). It is silent on the whole clean tree today: every
  // binary-reader structure validator already lives in a validator-*, and every schema-*
  // build callback validates through the schema engine, not a hand-rolled reader. Layer A
  // (validator-shape-reinlined) covers the COMPLEMENTARY drift -- re-inlining a KNOWN
  // validator's cbor/asn1 shape; together they close both extraction shapes.
  var THROW_THRESHOLD = 5;
  var EXCLUDE = /^lib\/guard-[a-z-]+\.js$|^lib\/validator-[a-z-]+\.js$|^lib\/byte-reader\.js$/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (EXCLUDE.test(rel)) return;
    var src = fs.readFileSync(f, "utf8");
    _functionRegions(src).forEach(function (r) {
      var body = _stripCommentsAndLiterals(r.body);
      if (!/new\s+ByteReader\s*\(/.test(body)) return;
      var throws = (body.match(/\bthrow\b/g) || []).length;
      if (throws < THROW_THRESHOLD) return;
      bad.push({ file: rel, line: r.startLine,
        content: "function `" + r.name + "` hand-rolls a binary-structure reader (new ByteReader) with " + throws + " inline field-validation throws -- extract the decode+validate into a validator-* (the type's rule set) or guard-* (a fail-closed shape), or mark `allow:inline-structure-validator <reason>` if it must stay inline" });
    });
  });
  bad = _filterMarkers(bad, "inline-structure-validator");
  _report("no lib function hand-rolls a binary-structure reader with a dense inline validation cluster (should be a validator/guard)", bad);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

function testBase64DecodeNotViaGuard() {
  // class: base64-decode-not-via-guard
  // A base64 / base64url decode of untrusted text must route through
  // guard.encoding.base64 / .base64url. Node's Buffer.from(x, "base64"|"base64url")
  // is LENIENT -- it silently drops the first invalid character (and everything
  // after), accepts non-canonical trailing bits, and tolerates missing/extra
  // padding -- so two distinct texts alias one byte string, or a malformed text
  // decodes to a shorter, DIFFERENT value (CWE-172 / CWE-20; the wrong-key-material
  // import class). The alphabet gate + canonical re-encode round-trip + size cap
  // live ONLY in guard-encoding, so a bare Buffer.from base64 decode anywhere else
  // re-inlines the fail-closed defense. (guard-shape-reinlined cannot enforce this:
  // the discriminator is a STRING LITERAL its comment/literal strip removes; this
  // detector scans source lines with only comment lines blanked, so the literal
  // survives. The hex sibling stays behavioral -- Buffer.from(x,"hex") has legit
  // non-decode uses -- see guard-encoding.js.)
  var re = /Buffer\.from\([^,)]*,\s*"base64(?:url)?"\)/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    if (rel === "lib/guard-encoding.js") return;
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      if (/^\s*(\*|\/\/|\/\*)/.test(lines[i])) continue;   // skip comment lines (the discriminator is a live literal)
      if (re.test(lines[i])) {
        bad.push({ file: rel, line: i + 1, content: "function decodes base64 via a bare Buffer.from -- route it through guard.encoding.base64 / .base64url (the canonical, capped, fail-closed decode)" });
      }
    }
  });
  bad = _filterMarkers(bad, "base64-decode-not-via-guard");
  _report("no lib file decodes base64/base64url via a bare lenient Buffer.from instead of guard.encoding", bad);
}

// Emphasis words that carry no technical meaning in capitals. An acronym or an
// identifier (RFC, DER, SET OF, ANY, TRUE as an ASN.1 value, MUST as an RFC 2119
// keyword) is excluded by not appearing here, so the count measures voice and
// never penalises a file for naming the standards it implements. TRUE / FALSE /
// ANY / AND / ALL / NONE are deliberately absent: each collides with an ASN.1
// type, a field value (`cA=TRUE`), or pseudo-code in a comment.
var _SHOUTED_EMPHASIS = ["NOT", "EVERY", "NEVER", "ALWAYS", "ONLY", "NOTHING", "WHICH",
  "SAME", "BOTH", "ONE", "RAW", "THIS", "THE", "FULL", "REAL", "BEFORE", "AFTER",
  "INSIDE", "OUTSIDE", "EXACTLY", "SILENTLY", "DELIBERATELY", "GENUINELY", "WHOLE",
  "EACH", "OWN", "KIND", "CONTENT", "MORE", "LESS", "FIRST", "LAST", "WITHOUT"];

// Spans where a capitalised word is technical, not emphatic: an inline code span,
// an RFC 2119 modal pair (`MUST NOT`, `SHALL NOT`), and a field value or key
// (`cA=TRUE`, `status: FAILED`). Removed before the emphasis count so the gate
// measures voice and cannot be satisfied by deleting a spec citation.
function _stripTechnicalCaps(s) {
  return s
    .replace(/`[^`]*`/g, " ")
    .replace(/\b(MUST|SHALL|SHOULD|MAY|CAN|NEED|WILL|DOES)\s+NOT\b/g, " ")
    .replace(/[=:]\s*[A-Z]{2,}\b/g, " ");
}

// Does this comment line BEGIN a prose unit, or continue a sentence the line
// above hard-wrapped? `prev` is the preceding comment line's text, or null when
// nothing precedes it in the run -- the start of a comment block, a blank comment
// line, and an intervening code line all break it. A list bullet and a doc tag
// open their own unit, and so does any line whose predecessor closed a sentence.
//
// Only a line that begins a unit can carry a definition head. Comments here are
// hard-wrapped, so without this the words that happen to land after a line break
// read as a short head and waive a mid-sentence pivot.
function _startsProseUnit(text, prev) {
  if (/^\s*(?:[-*]\s|@[a-z])/i.test(text)) return true;       // a bullet or a doc tag opens its own unit
  if (prev === null || /^[\s*]*$/.test(prev)) return true;    // nothing above it, or a bare docblock opener
  if (/^\s*@[a-z]/i.test(prev)) return true;                  // the line above was a doc tag
  return /[.:!?][`'")\]]?\s*$/.test(prev);                    // the line above closed its sentence
}

// Comment prose of one source file: the docblock and `//` narrative, with the
// `@example` bodies dropped because their text is code. Each kept line carries
// `head`, the structural fact of whether it begins a prose unit.
function _commentProse(text) {
  var lines = _lines(text);
  var kept = [], inExample = false, prev = null;
  for (var i = 0; i < lines.length; i++) {
    var raw = lines[i];
    if (/^\s*\*\s*@example\b/.test(raw)) { inExample = true; prev = null; continue; }
    if (inExample) {
      if (/^\s*\*\s*@[a-z]/i.test(raw)) inExample = false; else { prev = null; continue; }
    }
    var m = raw.match(/^\s*(?:\/\/|\*|\/\*)\s?(.*)$/);
    if (!m || !m[1]) { prev = null; continue; }
    kept.push({ line: i + 1, text: m[1], head: _startsProseUnit(m[1], prev) });
    prev = m[1];
  }
  return { lines: kept };
}

// Is a ` -- ` on this line the rhetorical construction, or a definition
// separator? The two look identical and only one is a voice tic:
//
//   `guard.bytes.view / .source    -- untrusted byte-source -> Buffer re-view`
//   `  - `allowUnbound` (boolean)  -- interpret a response nothing ties to ...`
//   `@internal -- no operator-facing namespace.`
//
// are a term and its gloss, which is how an aligned list, an `@opts` entry and a
// file-header title are written here. Counting those would score a file for its
// structure and push an author toward deleting documentation to pass, which is
// the opposite of the point. A dash is counted only MID-SENTENCE: exactly one
// space before it, and something other than a bare identifier ahead of it.
//
// A short run of words is not by itself a definition head, and treating it as one
// is how a real pivot escapes. Comments here are hard-wrapped, so a sentence that
// turns a few words into a continuation line presents the same shape as a term and
// its gloss. The distinguishing property is structural: a definition head OPENS its
// prose unit (`startsUnit`), so a wrapped continuation cannot claim to be one.
function _rhetoricalDashes(line, startsUnit) {
  // An allow-marker's `allow:<class> -- <reason>` is this suite's own documented
  // annotation format (see the file header). Its dash separates the machine-read
  // class from the human reason, so counting it would push an author to break the
  // convention the suite itself defines.
  if (/(?:codebase-patterns:allow-file|allow:[a-z0-9][a-z0-9-]*)\b/.test(line)) return 0;
  if (/\s{2,}--\s/.test(line)) return 0;              // aligned definition column
  // A term and its gloss at the start of a line: an identifier, a path, a tag, or
  // a full call signature `fn(a, b, c)`. The head must look like a name rather
  // than a sentence, so a comma inside parentheses is part of the term while a
  // comma in prose is not.
  var head = line.split(/\s--\s/)[0];
  if (startsUnit &&
      /^\s*[-*]?\s*[@`\w][\w.`'/ -]*(?:\([^)]*\))?[`\s]*$/.test(head) &&
      head.replace(/\([^)]*\)/, "").split(/\s+/).filter(Boolean).length <= 6) {
    return 0;
  }
  return (line.match(/\S -- /g) || []).length;
}

function testNoInternalProvenanceInComments() {
  // class: internal-provenance-in-comment
  //
  // A comment ships in the tarball, so it is operator-facing. It must state the
  // invariant and never where the invariant came from: an operator reading it
  // cannot open a private note file, a PR thread, or a review round, and a
  // pointer to one is dead weight that also dates the code.
  //
  // The shapes are rename-proof because each names an artifact outside the
  // repository: an auto-memory slug (`feedback_*` / `reference_*`), a path into
  // a gitignored working directory, a review-round or PR-number citation, or a
  // named external reviewer. The invariant survives; only the provenance goes.
  var SHAPES = [
    { re: /\b(?:feedback|reference)_[a-z0-9]+(?:_[a-z0-9]+)+\b/, what: "an auto-memory slug" },
    { re: /\.(?:references|scratch)\//, what: "a gitignored working-directory path" },
    { re: /\b(?:round|review) #?\d+\b/i, what: "a review-round citation" },
    { re: /\bcodex\b/i, what: "a named external reviewer" },
  ];
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      if (!/^\s*(\*|\/\/|\/\*)/.test(lines[i])) continue;   // comment lines only
      for (var s = 0; s < SHAPES.length; s++) {
        if (!SHAPES[s].re.test(lines[i])) continue;
        bad.push({ file: rel, line: i + 1,
          content: "comment cites " + SHAPES[s].what + ", which an operator reading the shipped " +
            "tarball cannot follow. State the invariant and drop the provenance." });
        break;
      }
    }
  });
  bad = _filterMarkers(bad, "internal-provenance-in-comment");
  _report("no shipped comment cites internal provenance (a memory slug, a working-directory path, a review round)", bad);
}

function testProseCadenceDensity() {
  // class: prose-cadence-density
  //
  // Comment prose ships in the tarball, so it is read by operators. Three
  // constructions express one rhetorical move -- the contrastive turn -- and a
  // fourth shouts for emphasis:
  //
  //   ` -- ` used as a colon, a pause, or a pair of interruptive appositives
  //   "rather than", the same pivot as a phrase
  //   a capitalised ordinary word standing in for typography
  //
  // Parallel negation ("X, not Y") is DELIBERATELY not counted. It is the same
  // rhetorical move, but a genuine contrast is the content -- "an inclusion
  // question, not a consistency question" says something the flattened version
  // does not -- and a counter that pressures an author to destroy it trades a
  // voice tic for a loss of meaning. Counting it also rewards the wrong fix:
  // contorting a sentence to dodge the token, which is the habit this gate
  // exists to catch.
  //
  // None is wrong once. Held at the density this measures they are a voice tic
  // that reads as generated, and the reason a ban on the em dash CHARACTER
  // changes nothing: `--` is the same construction wearing an ASCII glyph. So
  // the gate counts the construction per 1000 words of prose and not the
  // character, which is what makes it un-routed-around: every substitution for
  // the same move lands in the same counter.
  //
  // There is deliberately NO allow-marker for this class. A per-file opt-out
  // would become the bucket the habit lives in, which is the failure the gate
  // exists to prevent. The ceiling is the only tunable, and it ratchets down.
  var PIVOT_CEILING = 8;    // per 1000 words: roughly one per three paragraphs
  var CAPS_CEILING = 5;
  var MIN_WORDS = 150;      // below this a single instance swamps the ratio
  var shouted = new RegExp("\\b(" + _SHOUTED_EMPHASIS.join("|") + ")\\b", "g");
  var bad = [];
  _libFiles().forEach(function (f) {
    var prose = _commentProse(fs.readFileSync(f, "utf8"));
    var joined = prose.lines.map(function (l) { return l.text; }).join(" ");
    var words = (joined.match(/[A-Za-z][A-Za-z'-]*/g) || []).length;
    if (words < MIN_WORDS) return;
    var dash = prose.lines.reduce(function (a, l) { return a + _rhetoricalDashes(l.text, l.head); }, 0);
    var rather = (joined.match(/rather than/gi) || []).length;
    var caps = (_stripTechnicalCaps(joined).match(shouted) || []).length;
    var pivot = (dash + rather) * 1000 / words;
    var capsPer = caps * 1000 / words;
    if (pivot <= PIVOT_CEILING && capsPer <= CAPS_CEILING) return;
    // Point at the first counted construction so the author starts somewhere real.
    var at = 1;
    for (var i = 0; i < prose.lines.length; i++) {
      var t = prose.lines[i].text;
      if (_rhetoricalDashes(t, prose.lines[i].head) || /rather than|, not [a-z]/i.test(t)) { at = prose.lines[i].line; break; }
    }
    bad.push({
      file: _relPath(f), line: at,
      content: "comment prose reads as generated: pivot " + pivot.toFixed(1) + "/1k (ceiling " +
        PIVOT_CEILING + "; " + dash + " ` -- `, " + rather + " 'rather than'), " +
        "shouted emphasis " + capsPer.toFixed(1) + "/1k (ceiling " + CAPS_CEILING + "; " + caps + " words). " +
        "Rewrite the construction: a dash used as a colon becomes a colon, an interruptive " +
        "appositive becomes parentheses or its own sentence. Substituting one uniform token " +
        "for another scores the same.",
    });
  });
  _report("comment prose stays under the cadence ceiling (pivot <= " + PIVOT_CEILING +
    "/1k, shouted emphasis <= " + CAPS_CEILING + "/1k)", bad);
}

function testJsonParseNotViaGuard() {
  // class: json-parse-not-via-guard
  // JSON parsing of any input in lib must route through guard.json.parse. JSON.parse
  // silently resolves a DUPLICATE member last-wins (the smuggling / parser-differential
  // class, CWE-20 / CWE-436), caps neither size nor depth (CWE-770 / CWE-400), and over
  // a Buffer substitutes U+FFFD for invalid UTF-8. The strict bounded reader lives ONLY
  // in guard-json, so a bare JSON.parse anywhere in lib re-inlines the missing defense.
  // JSON.parse is a builtin (rename-proof); the token is the whole detector.
  var re = /JSON\.parse\s*\(/;
  var bad = [];
  _libFiles().forEach(function (f) {
    var rel = _relPath(f);
    var lines = _lines(fs.readFileSync(f, "utf8"));
    for (var i = 0; i < lines.length; i++) {
      if (/^\s*(\*|\/\/|\/\*)/.test(lines[i])) continue;   // skip comment lines
      if (re.test(lines[i])) {
        bad.push({ file: rel, line: i + 1, content: "uses bare JSON.parse -- route it through guard.json.parse (bounded, fatal-UTF-8, duplicate-member-rejecting)" });
      }
    }
  });
  bad = _filterMarkers(bad, "json-parse-not-via-guard");
  _report("no lib file parses JSON via a bare JSON.parse instead of guard.json", bad);
}

// ---------------------------------------------------------------------------
// factory-convention guards receive a (code, message) FACTORY, not an error CLASS
// ---------------------------------------------------------------------------

function testGuardErrorFactoryNotClass() {
  // class: guard-error-class-not-factory
  // The guard-*.js primitives that throw via the FACTORY convention -- `throw
  // E(code, message)` with no `new` (guard.name / json / limits / crypto /
  // encoding / identifier / range) -- MUST be handed a (code, message) FACTORY
  // (`_err`, `E`, `ns.E`, `ctx.E`), never a defineClass error CLASS. Passing a
  // class invokes it without `new` on the error path: a raw "Class constructor
  // cannot be invoked without 'new'" TypeError, a fail-open shape where hostile
  // input meant to REJECT crashes instead of failing closed. A bare
  // Capitalized*Error argument is a class -- flag it wherever it appears.
  var re = /guard\.(?:name|json|limits|crypto|encoding|identifier|range)\.\w+\([^;]{0,400}?,\s*[A-Z][A-Za-z0-9]*Error\b/;
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); } catch (_e) { continue; }
    var subject = _stripCommentsAndLiterals(content);
    var reG = new RegExp(re.source, "g");
    var m;
    while ((m = reG.exec(subject)) !== null) {
      var lineNum = subject.slice(0, m.index).split(/\r?\n/).length;
      bad.push({ file: _relPath(files[i]), line: lineNum, content: "factory-convention guard handed an error CLASS; pass the (code,message) factory (_err / E)" });
    }
  }
  bad = _filterMarkers(bad, "guard-error-class-not-factory");
  _report("factory-convention guards receive a (code,message) factory, not an error class", bad);
}

function run() {
  _allViolations = [];
  testSourceHeaders();
  testShippedSourceIsAscii();
  testTopOfFileRequires();
  testNoRawScaleLiterals();
  testNoAiAttribution();
  testNoDeferralMarkers();
  testNoFailOpenVerify();
  testPrimitiveCommentBlocks();
  testWikiPortAgreesAcrossArtifacts();
  testPublishPathRunsCiStaticGates();
  testFuzzSeedCorpusZipNaming();
  testFuzzBuildInstallsJazzer();
  testNoUnpinnedNpmInShell();
  testSchemaBuildSurfacesEveryField();
  testWorkflowScanFailureMasked();
  testSharedLeafOptionScope();
  testAlgorithmLookupNoDefault();
  testNumberNarrowsUnboundedInteger();
  testNanDateComparisonUnguarded();
  testEddsaVerifyGate();
  testCborMapPairAccessOutsideCodec();
  testOcspResponderAuthReinlined();
  testGuardShapeReinlined();
  testRawSecretExportIsWiped();
  testConstantTimeCompareShortCircuited();
  testAsn1ReaderExists();
  testGuardReadsRuntimeLive();
  testEveryGuardEnforced();
  testEveryGuardExportFrozen();
  testGuardErrorFactoryNotClass();
  testValidatorShapeReinlined();
  testEveryValidatorEnforced();
  testInlineStructureValidatorCluster();
  testBase64DecodeNotViaGuard();
  testJsonParseNotViaGuard();
  testNoInternalProvenanceInComments();
  testProseCadenceDensity();
  testNoRemovedWebCryptoNamespace();
  testReleaseWaitsForCodex();
  testNoUnusedUnderscoreFunctions();
  testNoRemovedNamespaceRefs();
  testFormatModulesComposeSchema();
  testAsn1TypesFromRegistry();
  testAllowMarkersAreRegistered();
  testKnownAntipatterns();
  testNoDuplicateCodeBlocks();

  // Cumulative gate — every detector is hard.
  check("zero codebase-pattern violations across all classes", _allViolations.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  // Persistent output to .test-output/codebase-patterns.log via
  // synchronous fd writes (mirroring test/smoke.js) so a failing run's
  // detail is on disk even if the process dies mid-run — read the log
  // instead of re-running.
  var OUT = path.join(REPO_ROOT, ".test-output");
  try { fs.mkdirSync(OUT, { recursive: true }); } catch (_e) { /* best-effort */ }
  var LOG_PATH = path.join(OUT, "codebase-patterns.log");
  try { fs.unlinkSync(LOG_PATH); } catch (_e) { /* fresh start */ }
  var _logFd = fs.openSync(LOG_PATH, "w");
  function _logWrite(chunk) {
    try {
      var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      fs.writeSync(_logFd, buf, 0, buf.length, null);
    } catch (_e) { /* best-effort */ }
  }
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, e, cb) { _logWrite(c); return origStdout(c, e, cb); };
  process.stderr.write = function (c, e, cb) { _logWrite(c); return origStderr(c, e, cb); };
  process.on("exit", function () { try { fs.closeSync(_logFd); } catch (_e) { /* best-effort */ } });
  console.log("output: " + LOG_PATH);
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
