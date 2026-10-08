// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the package's ESM surface: every namespace a `require` caller sees is also a NAMED
 * import for an ESM caller, so `import { x509 } from "@blamejs/pki"` works for all of them.
 *
 * Node reads a CommonJS module's named exports with `cjs-module-lexer`, a static reader that follows
 * `name: ident` and a shorthand and stops at anything else. It is not an evaluator: a member
 * expression, a nested object literal or a call ends the scan, and every entry after that point is
 * invisible. `version: constants.version` was the FIRST entry of the export object, so an ESM caller
 * saw `default`, `module.exports` and `version` and nothing else, for all 47 namespaces.
 *
 * Two checks, because one alone would not hold the property:
 *  - the BEHAVIORAL one imports the package in a child process as ESM and compares the named exports
 *    against what `require` gives, which is what an operator's `import` statement actually does;
 *  - the STRUCTURAL one reads index.js and requires every entry's value to be a bare identifier,
 *    which is what a namespace added later is held to. Without it the behavioral check would still
 *    pass for the namespaces that come BEFORE a newly added literal, and fail obscurely for the rest.
 */

var fs = require("node:fs");
var path = require("node:path");
var url = require("node:url");
var spawnSync = require("node:child_process").spawnSync;
var helpers = require("../helpers");
var check = helpers.check;

var REPO_ROOT = path.join(__dirname, "..", "..");
var INDEX = path.join(REPO_ROOT, "index.js");

/** @internal Comments and string bodies are blanked FIRST, preserving length, so the split that
 *  follows reads code and never comment prose. A stripper that does both at once carries the text it
 *  is removing into the thing it classifies. */
function blankCommentsAndStrings(s) {
  var out = s.split("");
  var mode = "code", quote = null;
  for (var i = 0; i < s.length; i++) {
    var c = s[i], n = s[i + 1];
    if (mode === "code") {
      if (c === "/" && n === "/") { mode = "line"; out[i] = " "; out[i + 1] = " "; i++; continue; }
      if (c === "/" && n === "*") { mode = "block"; out[i] = " "; out[i + 1] = " "; i++; continue; }
      if (c === '"' || c === "'" || c === "`") { mode = "string"; quote = c; }
      continue;
    }
    if (mode === "line") { if (c === "\n") { mode = "code"; continue; } out[i] = " "; continue; }
    if (mode === "block") {
      if (c === "*" && n === "/") { out[i] = " "; out[i + 1] = " "; i++; mode = "code"; continue; }
      if (c !== "\n") out[i] = " ";
      continue;
    }
    if (c === "\\") { out[i] = " "; out[i + 1] = " "; i++; continue; }
    if (c === quote) { mode = "code"; quote = null; continue; }
    out[i] = " ";
  }
  return out.join("");
}

function braceBalance(s) {
  var d = 0;
  for (var i = 0; i < s.length; i++) { if (s[i] === "{") d++; else if (s[i] === "}") d--; }
  return d;
}

/** @internal Every top-level entry of index.js's `module.exports` literal, as { key, value }, with
 *  the value taken from the blanked copy so a comment inside the literal cannot read as code. */
function exportEntries(src) {
  var blanked = blankCommentsAndStrings(src);
  var open = blanked.indexOf("module.exports = {");
  if (open < 0) return null;
  var bodyStart = blanked.indexOf("{", open) + 1;
  var depth = 1, start = bodyStart, spans = [];
  for (var j = bodyStart; j < blanked.length && depth > 0; j++) {
    var ch = blanked[j];
    if (ch === "{" || ch === "[" || ch === "(") depth++;
    else if (ch === "}" || ch === "]" || ch === ")") {
      depth--;
      if (depth === 0) { spans.push([start, j]); break; }
    } else if (ch === "," && depth === 1) { spans.push([start, j]); start = j + 1; }
  }
  var out = [];
  spans.forEach(function (sp) {
    var text = blanked.slice(sp[0], sp[1]);
    if (!text.trim()) return;
    var colon = text.indexOf(":");
    if (colon < 0) { out.push({ key: text.trim(), value: text.trim() }); return; }
    out.push({ key: text.slice(0, colon).trim(), value: text.slice(colon + 1).trim() });
  });
  return { blanked: blanked, entries: out };
}

function isBareIdentifier(v) {
  if (v.length === 0) return false;
  var first = v.charCodeAt(0);
  var ok = (first >= 65 && first <= 90) || (first >= 97 && first <= 122) || first === 95 || first === 36;
  if (!ok) return false;
  for (var i = 1; i < v.length; i++) {
    var c = v.charCodeAt(i);
    if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 36) continue;
    return false;
  }
  return true;
}

function run() {
  var src = fs.readFileSync(INDEX, "utf8");
  var parsed = exportEntries(src);
  check("index.js carries a module.exports object literal", parsed !== null);

  // CONTROL: the blanked copy has to be the same file, or every offset below is measured against a
  // different one and the entry list is fiction.
  check("CONTROL blanking preserves index.js's length and brace balance",
    parsed.blanked.length === src.length && braceBalance(parsed.blanked) === braceBalance(src));

  var entries = parsed.entries;
  check("the export literal has entries to check (" + entries.length + ")", entries.length > 20);

  var stopping = entries.filter(function (e) { return !isBareIdentifier(e.value); });
  check("every export entry's value is a bare identifier, so cjs-module-lexer follows the whole " +
    "literal" + (stopping.length ? " (stops at: " + stopping.map(function (e) { return e.key; }).join(", ") + ")" : ""),
  stopping.length === 0);

  // CONTROL that the structural check can fail at all: a member expression and an object literal are
  // both rejected by the same predicate the entries were judged with.
  check("CONTROL the identifier predicate rejects the shapes that stop the lexer",
    !isBareIdentifier("constants.version") && !isBareIdentifier("{ match: identity.match }") &&
    !isBareIdentifier("_webcryptoNamespace()") && isBareIdentifier("_webcryptoNs"));

  // ---- the behavioral half: what an `import` statement actually sees ----
  var indexUrl = url.pathToFileURL(INDEX).href;
  var probe =
    "import(" + JSON.stringify(indexUrl) + ").then(function (m) {" +
    "  process.stdout.write(JSON.stringify(Object.keys(m)));" +
    "}).catch(function (e) { process.stdout.write('ERR:' + e.message); });";
  var rv = spawnSync(process.execPath, ["--input-type=module", "-e", probe],
    { encoding: "utf8", cwd: REPO_ROOT });
  check("the ESM probe ran (" + (rv.status === 0 ? "ok" : "status " + rv.status) + ")", rv.status === 0);

  var named = [];
  var raw = (rv.stdout || "").trim();
  if (raw.indexOf("ERR:") === 0) named = [raw];
  else { try { named = JSON.parse(raw); } catch (_e) { named = ["UNPARSEABLE:" + raw.slice(0, 120)]; } }
  check("the probe returned a name list (" + named.length + " name(s))",
    named.length > 20 && named.indexOf("default") !== -1);

  var cjs = require(INDEX);
  var cjsNames = Object.keys(cjs);
  var missing = cjsNames.filter(function (n) { return named.indexOf(n) === -1; });
  check("every namespace a require caller sees is also a named ESM import (" + cjsNames.length +
    " checked" + (missing.length ? ", missing: " + missing.join(", ") : "") + ")", missing.length === 0);

  // A spot check on the names an operator is most likely to write, so the assertion above cannot
  // pass on an empty or degenerate list.
  var SPOT = ["x509", "csr", "crl", "cms", "path", "key", "asn1", "oid", "schema", "lint",
    "webcrypto", "transport", "errors", "version"];
  var spotMissing = SPOT.filter(function (n) { return named.indexOf(n) === -1; });
  check("the named imports an operator writes are present" +
    (spotMissing.length ? " (missing: " + spotMissing.join(", ") + ")" : ""), spotMissing.length === 0);

  // The default export stays what it was, so a `import pki from "@blamejs/pki"` caller is unmoved.
  var defaultProbe =
    "import(" + JSON.stringify(indexUrl) + ").then(function (m) {" +
    "  process.stdout.write(String(m.default === m['module.exports']) + ' ' +" +
    "    String(typeof m.default.x509.sign) + ' ' + String(Object.keys(m.default).length));" +
    "}).catch(function (e) { process.stdout.write('ERR:' + e.message); });";
  var rv2 = spawnSync(process.execPath, ["--input-type=module", "-e", defaultProbe],
    { encoding: "utf8", cwd: REPO_ROOT });
  check("the default export is still the whole namespace object (" + (rv2.stdout || "").trim() + ")",
    rv2.status === 0 && (rv2.stdout || "").indexOf("true function " + cjsNames.length) === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
