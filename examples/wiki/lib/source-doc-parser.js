// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// source-doc-parser — extract @module + @primitive wiki blocks from the
// toolkit's lib/*.js source files.
//
// Tag-ordering convention (enforced by source-comment-block-validator):
//
//   1. Single-line tags first: @module / @primitive, @signature, @since,
//      @status, @compliance, @related, @nav, @title, @order, @slug,
//      @featured, @exampleFile
//   2. Then the prose body (untagged lines — paragraphs separated by
//      blank lines).
//   3. Multi-line tags LAST: @intro, @card, @opts, @example, @section.
//      These accumulate every following line as their value until the
//      next @-tag or block end — so any prose that sneaks in after them
//      gets silently swallowed into the previous multi-line tag.
//
// Schema (lives in JSDoc-style /** */ comment blocks immediately
// preceding the function / namespace object, or at the top of a module):
//
//   /**
//    * @primitive   pki.asn1.decode
//    * @signature   pki.asn1.decode(bytes, opts?) -> node
//    * @since       0.1.0
//    * @status      stable
//    * @related     pki.asn1.encode
//    *
//    * Description prose. Multiple paragraphs separated by blank lines.
//    * Inline `code` and links pass through.
//    *
//    * @example
//    *   var node = pki.asn1.decode(der);
//    */
//   function decode(input, opts) { ... }
//
// Module-level block (one per file, tagged @module):
//
//   /**
//    * @module pki.oid
//    * @nav    Core
//    * @title  Object Identifiers
//    *
//    * @intro
//    *   Namespace-wide prose.
//    *
//    * @card
//    *   Home-page card description.
//    */
//
// The parser is intentionally regex-based — no AST dependency. Three
// passes:
//   1. extractBlocks(source)   - array of raw block strings
//   2. parseBlock(rawBlock)    - { kind, tags, prose }
//   3. parseFile(source, path) - { module?, primitives: [...] }

var path = require("node:path");
var fs   = require("node:fs");

var BLOCK_RE = /\/\*\*([\s\S]*?)\*\//g;

var SINGLE_LINE_TAGS = {
  primitive:   true,
  module:      true,
  title:       true,
  nav:         true,
  order:       true,
  slug:        true,
  featured:    true,
  signature:   true,
  since:       true,
  status:      true,
  compliance:  true,
  related:     true,
  exampleFile: true,
};

var MULTI_LINE_TAGS = {
  intro:       true,
  example:     true,
  opts:        true,
  section:     true,
  card:        true,
};

// Strip the smallest common leading-whitespace prefix from a block of
// lines (Python textwrap.dedent). Author indentation inside a multi-line
// @example shouldn't leak into the rendered <pre> block.
function _dedent(text) {
  if (!text) return text;
  var lines = text.split("\n");
  var minIndent = Infinity;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line.trim()) continue;
    var m = line.match(/^[ \t]*/);
    var indent = m ? m[0].length : 0;
    if (indent < minIndent) minIndent = indent;
  }
  if (!isFinite(minIndent) || minIndent === 0) return text;
  return lines.map(function (l) {
    return l.length >= minIndent ? l.slice(minIndent) : l;
  }).join("\n");
}

function _stripCommentMarker(line) {
  // Strip trailing \r FIRST so the tag regex's `$` anchor matches at
  // end-of-line (the regex doesn't treat \r as a line terminator).
  return line.replace(/\r$/, "").replace(/^\s*\*\s?/, "");
}

function _normalizeBlock(raw) {
  return String(raw).split("\n").map(_stripCommentMarker);
}

function parseBlock(raw) {
  var lines = _normalizeBlock(raw);
  var tags = {};
  var prose = [];
  var current = null;
  var sawMultiLineThenProse = false;
  var openedMultiLine = false;

  function _flushMulti() {
    if (!current) return;
    var key = current.tag;
    var joined = current.lines.join("\n").replace(/^\n+|\n+$/g, "");
    joined = joined.split("\n").map(function (l) {
      return l.replace(/\s+$/, "");
    }).join("\n").replace(/\n+$/, "");
    var value = _dedent(joined);
    if (key === "example") {
      if (!Array.isArray(tags.examples)) tags.examples = [];
      tags.examples.push(value);
    } else if (key === "section") {
      if (!Array.isArray(tags.sections)) tags.sections = [];
      var secLines = value.split("\n");
      var heading = secLines.shift();
      tags.sections.push({
        heading: (heading || "").replace(/^\s+|\s+$/g, ""),
        body:    secLines.join("\n").replace(/^\n+|\n+$/g, ""),
      });
    } else {
      tags[key] = value;
    }
    current = null;
  }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var tagMatch = line.match(/^\s*@([a-zA-Z][a-zA-Z0-9]*)\b\s*(.*)$/);
    if (tagMatch) {
      _flushMulti();
      var tag = tagMatch[1];
      var rest = tagMatch[2];
      if (SINGLE_LINE_TAGS[tag]) {
        tags[tag] = rest.trim();
      } else if (MULTI_LINE_TAGS[tag]) {
        current = { tag: tag, lines: rest ? [rest] : [] };
        openedMultiLine = true;
      } else {
        tags[tag] = rest.trim();
      }
      continue;
    }
    if (current) {
      current.lines.push(line);
      var trimmed = line.replace(/^\s+|\s+$/g, "");
      if (openedMultiLine && /^[A-Z]/.test(trimmed) && /[.!?]$/.test(trimmed)) {
        sawMultiLineThenProse = true;
      }
      continue;
    }
    prose.push(line);
  }
  _flushMulti();

  var kindFlags = [];
  if (tags.primitive) kindFlags.push("primitive");
  if (tags.module) kindFlags.push("module");
  var kind = kindFlags[0] || null;
  var mixedKind = kindFlags.length > 1 ? kindFlags : null;

  var proseText = prose.join("\n").replace(/^\n+|\n+$/g, "");

  return {
    kind:                kind,
    tags:                tags,
    prose:               proseText,
    proseAfterMultiLine: sawMultiLineThenProse,
    mixedKind:           mixedKind,
  };
}

function extractBlocks(source) {
  var blocks = [];
  BLOCK_RE.lastIndex = 0;
  var m;
  while ((m = BLOCK_RE.exec(source)) !== null) {
    blocks.push({ raw: m[1], startIdx: m.index });
  }
  return blocks;
}

function parseFile(source, sourcePath) {
  var blocks = extractBlocks(source);
  var module_ = null;
  var primitives = [];
  for (var i = 0; i < blocks.length; i++) {
    var parsed = parseBlock(blocks[i].raw);
    if (!parsed.kind) continue;
    if (parsed.kind === "module") {
      if (module_) {
        console.warn("[source-doc-parser] duplicate @module block in", sourcePath);
      }
      module_ = parsed;
    } else if (parsed.kind === "primitive") {
      primitives.push(parsed);
    }
  }
  return {
    sourcePath: sourcePath,
    module:     module_,
    primitives: primitives,
  };
}

function parseTree(rootDir) {
  var byPath = {};
  function _walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir); } catch (_e) { return; }
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i];
      // Vendored libs + node_modules aren't toolkit source.
      if (name === "vendor" || name === "node_modules") continue;
      var full = path.join(dir, name);
      var stat;
      try { stat = fs.statSync(full); } catch (_e) { continue; }
      if (stat.isDirectory()) { _walk(full); continue; }
      if (!stat.isFile()) continue;
      if (!/\.js$/.test(name)) continue;
      var src;
      try { src = fs.readFileSync(full, "utf8"); } catch (_e) { continue; }
      var parsed = parseFile(src, full);
      if (parsed.module || parsed.primitives.length > 0) {
        byPath[full] = parsed;
      }
    }
  }
  _walk(rootDir);
  return byPath;
}

module.exports = {
  parseBlock:    parseBlock,
  parseFile:     parseFile,
  parseTree:     parseTree,
  extractBlocks: extractBlocks,
};
