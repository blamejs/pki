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
    // A lib module that exposes NO operator-facing namespace — shared factories
    // or helpers COMPOSED by the documented parsers (e.g. schema-pkix.js) —
    // declares `@internal` in its header and is exempt: its documented surface
    // is the modules that consume it, not itself. The declaration must be
    // explicit so the exemption is a conscious choice, never a silent omission.
    if (/@internal\b/.test(src)) continue;
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

function testPublishPathRunsCiStaticGates() {
  // class: publish-path-missing-static-gate
  // The npm-publish workflow triggers on a `v*` tag push, INDEPENDENTLY of the
  // pull_request CI that runs the static-gate battery. A gate wired only into
  // ci.yml therefore does not guard the tarball the publish path packs: a tree
  // that fails a static gate can still be packed and published from a tag push.
  // Every static correctness gate runs in BOTH the CI test job and the publish
  // `validate` job before `npm pack`. This list is the frozen contract — adding
  // a gate means adding it here and to both workflows, so the two paths can
  // never silently diverge.
  var GATES = [
    "--max-warnings 0",
    "node test/layer-0-primitives/codebase-patterns.test.js",
    "node scripts/validate-source-comment-blocks.js",
    "node scripts/check-api-snapshot.js",
    "node scripts/check-status-lifecycle.js",
    "node scripts/pin-all.js --check",
  ];
  var ciPath = ".github/workflows/ci.yml";
  var pubPath = ".github/workflows/npm-publish.yml";
  var ci, pub;
  try { ci = fs.readFileSync(path.join(REPO_ROOT, ciPath), "utf8"); } catch (_e) { return; }
  try { pub = fs.readFileSync(path.join(REPO_ROOT, pubPath), "utf8"); } catch (_e) { return; }
  var bad = [];
  GATES.forEach(function (g) {
    if (ci.indexOf(g) === -1) {
      bad.push({ file: ciPath, line: 1,
        content: "static gate `" + g + "` is in the frozen contract but missing from the CI test job" });
    }
    if (pub.indexOf(g) === -1) {
      bad.push({ file: pubPath, line: 1,
        content: "static gate `" + g + "` runs in ci.yml but NOT in the publish validate job — a tag-push publish would pack an ungated tree" });
    }
  });
  bad = _filterMarkers(bad, "publish-path-missing-static-gate");
  _report("publish validate job runs the full CI static-gate battery", bad);
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
  // the codec that implements it and the TSP module that consumes it; a third
  // consumer means X.509/CRL validity times silently start accepting
  // fractional seconds (RFC 5280 forbids them).
  var allowed = { "asn1-der.js": 1, "schema-tsp.js": 1 };
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
    // (b): a quoted algorithm literal preset, then a table lookup assignment
    // with no throw between them (the pre-set survives an unknown OID).
    var preset = /var\s+(\w+)\s*=\s*"SHA-1"(?:(?!throw)[\s\S]){0,400}?\1\s*=\s*\w+_BY_OID\[/;
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
  // pki.WebCrypto was removed in favour of pki.webcrypto.* — its classes now hang off
  // the ready Crypto instance. A lingering `pki.WebCrypto` reference in operator-facing
  // PROSE (a docstring, README, ARCHITECTURE) is a documented path that no longer
  // resolves — exactly the bug class the doc-example gate cannot see (it only runs
  // @example CODE, not prose). Anchored on the exact removed token (case-sensitive, so
  // pki.webcrypto is not matched).
  var files = ["lib/webcrypto.js", "index.js", "README.md", "ARCHITECTURE.md", "SECURITY.md"];
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
  // The current-head review is the NEWEST one; reviews(first:N) fetches the
  // OLDEST N, so on a PR with many review iterations the head review falls
  // outside the window and the gate falsely concludes Codex hasn't reviewed.
  if (/reviews\(first:/.test(src)) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "fetch the newest reviews (reviews(last:N)) for the Codex-reviewed-head lookup — reviews(first:N) misses the current-head review on a many-iteration PR" });
  }
  // Codex posts a CLEAN verdict as an issue comment citing the head sha, with
  // no formal review node — recognising only formal reviews times out on every
  // clean review (the common case), so the head lookup must also scan comments.
  var reviewedFn = /function _codexReviewedHead\b([\s\S]*?)\r?\nfunction /.exec(src);
  if (!reviewedFn || reviewedFn[1].indexOf("comments") === -1 || !/head\.slice\(/.test(reviewedFn[1])) {
    bad.push({ file: "scripts/release.js", line: 0,
      content: "_codexReviewedHead must also detect Codex's clean-verdict issue comment (cites the head sha) — recognising only formal review nodes times out on every clean review" });
  }
  bad = _filterMarkers(bad, "release-codex-async-race");
  _report("release.js waits for Codex to review the head before merge (async-review race closed)", bad);
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
  // The v0.1.7 rename removed pki.x509 (-> pki.schema.x509) and pki.asn1.schema
  // (-> pki.schema.engine) with no compat shim. A consumer left calling a
  // removed export crashes at runtime — the CLI (bin/pki.js) and the fuzz target
  // both did, because the rename sweep covered lib/test/examples but not bin/ or
  // fuzz/. No shipped source (lib + the consumer entry points) may reference the
  // removed names; the sweep must be whole-repo.
  var bad = [];
  var files = _libFiles().slice();
  ["bin", "fuzz", "scripts"].forEach(function (dir) {
    try {
      fs.readdirSync(path.join(REPO_ROOT, dir)).forEach(function (f) {
        if (f.endsWith(".js")) files.push(path.join(REPO_ROOT, dir, f));
      });
    } catch (_e) { /* dir may be absent in some packagings */ }
  });
  var re = /pki\.x509\b|pki\.asn1\.schema\b/;
  for (var i = 0; i < files.length; i++) {
    var rel = _relPath(files[i]);
    var src;
    try { src = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = src.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      if (re.test(lines[j])) {
        bad.push({ file: rel, line: j + 1,
          content: "references a removed namespace (pki.x509 -> pki.schema.x509, pki.asn1.schema -> pki.schema.engine) — the v0.1.7 rename left no compat shim; a whole-repo sweep must catch bin/ and fuzz/, not only lib/test" });
      }
    }
  }
  bad = _filterMarkers(bad, "removed-namespace-ref");
  _report("no shipped source references the removed pki.x509 / pki.asn1.schema namespaces", bad);
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
  var FORMAT_FILES = ["lib/schema-x509.js", "lib/schema-crl.js", "lib/schema-csr.js", "lib/schema-pkcs8.js", "lib/schema-cms.js", "lib/schema-ocsp.js", "lib/schema-tsp.js", "lib/schema-attrcert.js", "lib/schema-crmf.js", "lib/schema-pkcs12.js", "lib/schema-cmp.js"]; // + future format modules as they land
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
    // the shared pkix.runParse(...), or pkix.makeParser({ topSchema, … }) — the
    // parser factory that binds runParse to the format's identity (both keep the
    // coerce -> decode -> walk path in pkix, never a hand-written decoder).
    if (!/schema\.walk\(|pkix\.runParse\(|pkix\.makeParser\(/.test(code)) {
      bad.push({ file: FORMAT_FILES[f], line: 0,
        content: FORMAT_FILES[f] + " must parse by composing the schema engine — schema.walk(...), the shared pkix.runParse(...), or pkix.makeParser(...), not a hand-written decoder" });
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
    regex: /c\.length > constants\.LIMITS\.DER_MAX_INTEGER_BYTES(?!\s*\+\s*1)/,
    skipCommentLines: true,
    allowlist: [],
    reason: "A `c.length > DER_MAX_INTEGER_BYTES` cap with no `+ 1` for the DER sign octet rejects a positive INTEGER at the magnitude cap whose top bit is set (an RSA-131072 modulus). The cap bounds the magnitude; DER content may carry one leading 0x00 sign pad.",
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
        "lib/schema-ocsp.js:pemDecode", "lib/schema-tsp.js:pemDecode",
        "lib/schema-attrcert.js:pemDecode", "lib/schema-crmf.js:pemDecode",
        "lib/schema-pkcs12.js:pemDecode", "lib/schema-pkcs12.js:pemEncode",
        "lib/schema-attrcert.js:<top>", "lib/schema-pkcs12.js:<top>",
        "lib/schema-cmp.js:pemDecode", "lib/schema-cmp.js:pemEncode", "lib/schema-cmp.js:<top>",
        "lib/schema-cmp.js:rawSequence",
      ],
      mode: "family-subset",
      reason: "pemDecode/pemEncode are per-module thin delegations to pkix.pemDecode/pemEncode (label + error class differ); kept separate for their per-function @primitive wiki blocks.",
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
        "lib/schema-ocsp.js:_rawSignature",
        "lib/schema-pkcs8.js:<top>", "lib/schema-tsp.js:<top>",
        "lib/schema-pkcs12.js:<top>", "lib/schema-crmf.js:popoPrivKey",
        "lib/schema-pkix.js:algorithmIdentifier", "lib/schema-pkix.js:attribute",
        "lib/schema-pkix.js:attributeTypeAndValue",
        "lib/schema-cmp.js:<top>", "lib/schema-ocsp.js:_shapeCertStatus",
        "lib/schema-crl.js:decodeExt", "lib/schema-crmf.js:mapControls",
        "lib/schema-attrcert.js:<top>", "lib/schema-tsp.js:<top>",
        "lib/schema-cmp.js:rawSequence", "lib/schema-smime.js:<top>",
        "lib/schema-ocsp.js:_shapeResponderID",
      ],
      mode: "family-subset",
      reason: "per-format schema.seq/decode declarations + build-fn output assembly share the combinator idiom (different fields/codes each); the combinators live in the engine, nothing further to extract.",
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
        /hasOwnProperty|\.indexOf\(/.test(scope);                    // small-enum whitelist
      if (!bounded) {
        bad.push({ file: rel, line: i + 1,
          content: "Number(" + id + ") narrows an ASN.1 integer read with no dominating bound — a value past 2^53 rounds silently; add a range check (id > Nn), Number.isSafeInteger, or a whitelist before narrowing (the RSASSA-PSS / PKCS#12 / CMP exact-or-rejected rule)" });
      }
    }
  });
  bad = _filterMarkers(bad, "number-narrows-unbounded-integer");
  _report("no Number() narrows an unbounded ASN.1 integer read (silent-rounding vector, codebase-wide)", bad);
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
  testPublishPathRunsCiStaticGates();
  testFuzzSeedCorpusZipNaming();
  testFuzzBuildInstallsJazzer();
  testNoUnpinnedNpmInShell();
  testSchemaBuildSurfacesEveryField();
  testWorkflowScanFailureMasked();
  testSharedLeafOptionScope();
  testAlgorithmLookupNoDefault();
  testNumberNarrowsUnboundedInteger();
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
