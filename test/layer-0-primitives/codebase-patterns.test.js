// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * codebase-patterns — automated grep gates for code-shape bug classes.
 *
 * The toolkit accumulates a set of structural disciplines that a plain
 * unit test cannot express (they are about the SHAPE of the source, not
 * the behaviour of one primitive). Each is encoded here as a scan over
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
  var reMarker = /\b(TODO|FIXME|XXX|HACK|NOT[ _-]?IMPLEMENTED|UNIMPLEMENTED)\b|\/\/\s*later\b/i;
  var reCapsSentinel = /\bNOT_SUPPORTED\b/;
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

function testNoFailOpenVerify() {
  // class: fail-open-verify
  // A verify / parse / validate routine that swallows an error and then
  // reports SUCCESS is fail-open: an attacker-crafted input that makes the
  // parser throw is treated as valid. The dangerous shape is a `catch`
  // block whose body returns a positive verdict — `return true`, a truthy
  // scalar, or a `{ valid: true }` / `{ verified: true }` object.
  //
  // Structural anchor: the `catch (...) {` opener followed by a tempered
  // token that cannot cross the catch block's closing brace at column 0 —
  // `(?:(?!\n {0,4}\})[\s\S])` — then the positive-verdict
  // return. The tempering keeps a later, unrelated `return true` in a
  // sibling function from being attributed to the catch. Comments and
  // string/regex literals are stripped first so a docstring example or a
  // quoted message never trips the gate.
  var VERDICT = "(?:true|1|valid|verified|isValid|ok)\\b" +
                "|\\{[^}]*\\b(?:valid|verified|ok|allowed|trusted)\\s*:\\s*true";
  var failOpenRe = new RegExp(
    "catch\\s*\\([^)]*\\)\\s*\\{" +
    "(?:(?!\\n {0,4}\\})[\\s\\S]){0,600}?" +
    "\\breturn\\s+(?:" + VERDICT + ")",
    "m"
  );
  var files = _libFiles();
  var bad = [];
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var subject = _stripCommentsAndLiterals(content);
    var m = failOpenRe.exec(subject);
    if (m) {
      var lineNum = subject.slice(0, m.index).split(/\r?\n/).length;
      bad.push({
        file: _relPath(files[i]),
        line: lineNum,
        content: "fail-open verify: a catch block returns a positive verdict",
      });
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

// ---------------------------------------------------------------------------
// (j) release.js waits for Codex before merge (closes the async-review race)
// ---------------------------------------------------------------------------

function testReleaseWaitsForCodex() {
  // class: release-codex-async-race
  // Codex (chatgpt-codex-connector) reviews a PR a minute or two AFTER the
  // status checks go green; required_review_thread_resolution can only block
  // threads that EXIST at merge time, so a merge fired the instant CI is
  // green outruns Codex and ships its findings (this is how a P1 and a
  // version-drift P2 reached npm). The authoritative merge step must WAIT
  // for Codex to review the current head before the thread gate runs.
  var bad = [];
  var src;
  try { src = fs.readFileSync(path.join(REPO_ROOT, "scripts/release.js"), "utf8"); }
  catch (_e) { return; }
  if (!/function _waitForCodexReview\b/.test(src)) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "missing the _waitForCodexReview gate that closes the async bot-review race" });
  }
  var mergeBody = /function cmdMerge\b([\s\S]*?)\r?\nfunction /.exec(src);
  if (!mergeBody || mergeBody[1].indexOf("_waitForCodexReview(") === -1) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "cmdMerge must call _waitForCodexReview before the merge-state / thread gate" });
  }
  // The Codex reviewer login arrives bare in GraphQL but "[bot]"-suffixed in
  // some REST surfaces; a strict `.login === CODEX_LOGIN` misidentifies Codex
  // and the gate would silently pass un-reviewed. Require the tolerant match.
  if (/\.login\s*===\s*CODEX_LOGIN/.test(src) || !/function _isCodexLogin\b/.test(src)) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "match the Codex login via _isCodexLogin (tolerating the [bot] suffix), not a strict `.login === CODEX_LOGIN`" });
  }
  bad = _filterMarkers(bad, "release-codex-async-race");
  _report("release.js waits for Codex to review the head before merge (async-review race closed)", bad);
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
// Known-antipattern catalog — scanScope-routed regex detectors (n=1 gate)
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
    // The one test-discipline detector carried in the unified catalog:
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
      // This catalog carries the bug pattern as a regex literal.
      "test/layer-0-primitives/codebase-patterns.test.js",
    ],
    reason: "Every 'passes alone, fails under SMOKE_PARALLEL=64 / macOS' test flake is the same root cause: a fixed-budget setTimeout sleep too short for runner-contention reality. helpers.waitUntil polls the actual condition every 25ms up to a 5000ms cap and exits early when the predicate is truthy — fast platforms finish in milliseconds, contended platforms get the full budget. helpers.passiveObserve(ms, label) is the sibling for verifying the ABSENCE of an event over a window. Convert a hand-tuned sleep to waitUntil rather than bumping N.",
  },

  // --- DER codec correctness (lib scope) ---
  {
    id: "asn1-quadratic-bigint-accumulator",
    primitive: "one-shot BigInt('0x'+hex) (base-256) or a bounded base-128 fold, with a C.LIMITS byte cap BEFORE the read — never a per-byte `<< n) | BigInt(` shift-accumulate",
    regex: /<<\s*[78]n\)\s*\|\s*BigInt\(/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A byte-at-a-time BigInt shift-accumulator over attacker-length content is O(n^2) in the content length — the quadratic decoder-DoS class (readInteger + decodeOidContent). The 16 MiB document cap does not bound a single value, so a ~2 MB INTEGER/OID pins a core for minutes. Build the magnitude in one pass and cap the per-value byte length.",
  },
  {
    id: "asn1-time-utc-rollover",
    primitive: "a getUTC* component round-trip check after Date.UTC (throw asn1/bad-time on any field mismatch) — Date.UTC silently rolls Feb 30 / month 13 / hour 25",
    regex: /Date\.UTC\((?:(?!getUTCFullYear)[\s\S]){0,600}?return new Date\(t\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Date.UTC normalizes out-of-range calendar fields instead of returning NaN, so isNaN is an inadequate strictness gate — a malformed UTCTime/GeneralizedTime parses to a shifted validity instant (a cert-validity parser differential). Require every component to round-trip.",
  },
  {
    id: "asn1-time-year-remap",
    primitive: "build the Date via new Date(0) + setUTCFullYear(year, ...) — the Date.UTC(year,...) / new Date() constructors remap a year in 0..99 to 1900..1999, corrupting a GeneralizedTime year below 100",
    regex: /function readTime\b(?:(?!setUTCFullYear)[\s\S]){0,2000}?Date\.UTC\(\s*year\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "readTime reaching Date.UTC(year, ...) without a setUTCFullYear remaps a 4-digit GeneralizedTime year below 100 (0099 -> 1999) — the round-trip check only holds when the year is not silently shifted a century. setUTCFullYear takes the literal year and uses its own calendar.",
  },
  {
    id: "asn1-bitstring-unused-bits",
    primitive: "a final-octet `(c[c.length-1] & mask)` zero-check (mask = (1<<unusedBits)-1) — X.690 11.2.1 DER requires unused BIT STRING bits to be zero",
    regex: /if \(unusedBits > 7\)(?:(?!c\[c\.length - 1\] & mask)[\s\S]){0,600}?return \{ unusedBits: unusedBits, bytes: c\.subarray\(1\) \}/,
    skipCommentLines: true,
    allowlist: [],
    reason: "readBitString reaching its return with no tail-mask check admits non-canonical BIT STRING encodings (encoding malleability on signature/key-usage bits). The zero-unused-bits invariant is easy to drop on refactor.",
  },
  {
    id: "asn1-bitstring-empty-body-unused-bits",
    primitive: "build.bitString must reject an empty body with unusedBits>0 (X.690 8.6.2.3) — an empty BIT STRING has no bits to leave unused; the encoder must not emit what the decoder rejects",
    regex: /bitString: function \(buf, unusedBits\)(?:(?!body\.length === 0)[\s\S]){0,600}?return _universal\(TAGS\.BIT_STRING/,
    skipCommentLines: true,
    allowlist: [],
    reason: "build.bitString reaching its return with no `body.length === 0` guard lets it emit an empty BIT STRING declaring unused bits — invalid DER the reader rejects, an encode/decode asymmetry. Reject u>0 over an empty body.",
  },
  {
    id: "asn1-universalstring-scalar-range",
    primitive: "a `cp > 0x10FFFF || (cp>=0xD800 && cp<=0xDFFF)` guard before String.fromCodePoint (throw asn1/bad-universal-string) — keeps the Asn1Error-only contract and rejects lone surrogates",
    regex: /for \(var i = 0; i < buf\.length; i \+= 4\)(?:(?!0x10FFFF)[\s\S]){0,600}?String\.fromCodePoint\(cp\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "_decodeUtf32be calling String.fromCodePoint on an unvalidated 4-byte value throws a bare native RangeError (not Asn1Error) for cp>0x10FFFF and silently admits lone surrogates — a contract break on any code-point-to-string path over attacker bytes.",
  },

  // --- WebCrypto access-control + conformance (lib scope) ---
  {
    id: "webcrypto-unwrapkey-usage-dominance",
    primitive: "_requireUsage(unwrappingKey, \"unwrapKey\") at the TOP of unwrapKey, before the AES-KW branch fork (mirror wrapKey) — the _cloneWithUsage delegation is only sound below the gate",
    regex: /unwrapAlgorithm, "unwrapKey"\);(?:(?!_requireUsage\(unwrappingKey, "unwrapKey"\))[\s\S]){0,400}?if \(alg\.name === "AES-KW"\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "unwrapKey enforcing the usage only inside the AES-KW branch leaves the RSA-OAEP/AES-GCM else path fail-open (it injects 'decrypt' via _cloneWithUsage and delegates to this.decrypt). The usage gate must dominate the branch fork.",
  },
  {
    id: "webcrypto-derivekey-wrong-usage",
    primitive: "deriveKey calls _requireUsage(baseKey, \"deriveKey\") then _deriveBitsRaw — it must NOT delegate to this.deriveBits (which enforces the distinct 'deriveBits' usage)",
    regex: /this\.deriveBits\(algorithm, baseKey/,
    skipCommentLines: true,
    allowlist: [],
    reason: "deriveKey delegating to deriveBits inherits the wrong usage check: it false-rejects an idiomatic ['deriveKey'] key AND fail-open allows a ['deriveBits']-only key. An op that fulfils itself via a sibling subtle method must enforce its OWN usage first.",
  },
  {
    id: "webcrypto-hmac-verify-length-gate",
    primitive: "`var mac = hm.digest(); return mac.length === sig.length && timingSafeEqual(mac, sig)` — timingSafeEqual throws RangeError on an attacker-length mismatch",
    regex: /timingSafeEqual\(hm\.digest\(\), sig\)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "Passing a fresh hm.digest() straight to timingSafeEqual against an attacker-length signature throws RangeError instead of resolving false (WebCrypto verify must resolve false for any invalid signature) — an unhandled-rejection DoS surface driven purely by the supplied length.",
  },
  {
    id: "webcrypto-aesctr-length-guard",
    primitive: "_requireCtrLength128(alg) before the AES-CTR createCipheriv/createDecipheriv — node only honors a full 128-bit counter, so length!=128 must fail closed (webcrypto/not-supported)",
    regex: /if \(name === "AES-CTR"\) \{(?:(?!_requireCtrLength128)[\s\S]){0,120}?create(?:Cipher|Decipher)iv\("aes-" \+ key\.algorithm\.length \+ "-ctr"/,
    skipCommentLines: true,
    allowlist: [],
    reason: "The AES-CTR branch building the cipher without reading alg.length silently ignores a security-relevant, spec-required parameter — a length<128 diverges from a conformant WebCrypto past the counter wrap. Read or reject the parameter.",
  },

  // --- X.509 parser fail-closed (lib scope) ---
  {
    id: "x509-tbs-fixed-childcount-guard",
    primitive: "a version-aware tbs child-count guard (`< idx + 6`) throwing CertificateError — a fixed `< 6` ignores the slot an explicit version [0] consumes and dereferences undefined",
    regex: /children\.length\s*<\s*6\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A fixed tbs.children.length < 6 guard passes a 6-child tbs whose explicit version [0] leaves SPKI undefined, throwing a raw TypeError instead of the advertised CertificateError. Bounds-check positionally against the version-aware minimum.",
  },
  {
    id: "x509-extensions-no-uniqueness",
    primitive: "a Set of seen extnID OIDs in _parseExtensions (throw x509/duplicate-extension on a repeat) — RFC 5280 §4.2 forbids duplicate extensions",
    regex: /function _parseExtensions\b(?:(?!seen)[\s\S])*?out\.push\(/,
    skipCommentLines: false,
    allowlist: [],
    reason: "_parseExtensions pushing each parsed extension with no seen-OID tracking accepts duplicate extensions (extension-shadowing differential: first-hit vs last-hit consumers disagree on a security-critical extension). Reject the second occurrence of any extnID.",
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
    regex: /typeof\s+\w+\s*===\s*"bigint"\s*\)\s*return/,
    skipCommentLines: true,
    allowlist: [],
    reason: "fromArcs's bigint branch returning a.toString() with no sign check emits a malformed OID like \"2.-5.1\" while the number branch rejects a negative — a self-inconsistent contract that blows up late, away from the bad arc.",
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
    id: "constants-hardcoded-version-literal",
    primitive: "derive VERSION from require('../package.json').version — a hand-maintained semver literal drifts from the published package (0.1.1 shipped reporting 0.1.0)",
    regex: /var\s+VERSION\s*=\s*["'][0-9]+\.[0-9]+\.[0-9]+["']/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A hard-coded VERSION string literal decoupled from package.json makes drift the default outcome on any release that forgets to bump it. Single-source it from the manifest so pki.version can never disagree with the package.",
  },
  {
    id: "oid-subidentifier-cap-too-small",
    primitive: "OID_MAX_SUBIDENTIFIER_BYTES must be >= 19 — the largest standard OID sub-identifier is a 128-bit UUID-based arc (X.667), which is 19 base-128 bytes; a smaller cap rejects legitimate UUID OIDs",
    regex: /OID_MAX_SUBIDENTIFIER_BYTES:\s*(?:[0-9]|1[0-8])\b/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A per-value defense-in-depth cap set below the largest value it must legitimately admit turns into a false-reject. A 128-bit UUID OID arc needs 19 base-128 bytes, so a sub-identifier cap under 19 rejects valid DER. Keep the cap above the largest legitimate arc while still bounding a pathologically long one.",
  },
];

function testKnownAntipatterns() {
  var libFiles  = null;
  var testFiles = null;
  var allBad = [];
  for (var ai = 0; ai < KNOWN_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_ANTIPATTERNS[ai];
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    var files;
    if (ap.scanScope === "test") {
      if (testFiles === null) testFiles = _testFiles();
      files = testFiles;
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
  if (allBad.length === 0) check("known-antipattern catalog (n=1 gate)", true);
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
  var kvPairs = (joined.match(/_ID\s+:\s+_ID\s+,/g) || []).length;
  if (kvPairs >= 4) return true;
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
  var KNOWN_CLUSTERS = [];

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

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

function run() {
  _allViolations = [];
  testSourceHeaders();
  testTopOfFileRequires();
  testNoRawScaleLiterals();
  testNoAiAttribution();
  testNoDeferralMarkers();
  testNoFailOpenVerify();
  testPrimitiveCommentBlocks();
  testWikiPortAgreesAcrossArtifacts();
  testReleaseWaitsForCodex();
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
