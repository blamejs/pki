// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// A small, zero-dependency Markdown -> HTML renderer, scoped to exactly the
// constructs the repository README uses: ATX headings, paragraphs, bold, inline
// code, fenced code blocks, GFM pipe tables, thematic breaks, unordered lists,
// links / images / image-links, and block-level raw-HTML passthrough (the
// centered header). It is deliberately NOT a general CommonMark engine -- the
// wiki ships no npm dependencies, and a bounded renderer over a known document
// is auditable where a full parser would be a supply-chain surface.
//
//   render(md, opts) -> html
//     opts.rewriteLink(href) -> href   remap a relative link/image target
//
// Everything user-derived is HTML-escaped before it reaches the output; the
// only raw HTML emitted is the source's own block-level tags (a README the
// maintainers author, not untrusted input).

var ent = require("./html-entities");
var esc = ent.escapeHtml;

// A line that opens/continues a block-level raw-HTML region the source authored
// (the centered header <div>, a standalone <img>, <br>, <sub>, <details>). Such
// lines pass through verbatim; markdown BETWEEN them (blank-line separated, as
// GitHub renders block HTML) is still processed.
var RAW_HTML_LINE = /^\s*<\/?(div|img|br|sub|sup|details|summary|p|span|hr|a|picture|source)\b[^>]*>?\s*$/i;
var HEADING = /^(#{1,6})\s+(.*)$/;
var HR = /^(?:-{3,}|_{3,}|\*{3,})\s*$/;
var UL_ITEM = /^[-*]\s+(.*)$/;
var TABLE_SEP = /^\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$/;

function _rewrite(href, opts) {
  if (opts && typeof opts.rewriteLink === "function") return opts.rewriteLink(href);
  return href;
}

// Inline rendering: image-links [![alt](src)](href), images ![alt](src), links
// [text](href), bold **x**, inline code `x`. The text is HTML-escaped first, so
// the regexes run over escaped prose (README URLs and link text carry no angle
// brackets); inline-code content is thereby escaped for display too.
function _inline(text, opts) {
  var out = esc(text);
  // The whole text is HTML-escaped above, so a captured src/href is ALREADY
  // escaped (a URL's `&` is `&amp;`). `_rewrite` remaps a relative target and
  // leaves an escaped absolute URL alone -- re-escaping here would double it
  // (`&amp;` -> `&amp;amp;`), breaking a badge URL's query string.
  // image-link: a badge/image wrapped in a link.
  out = out.replace(/\[!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)\]\(([^)\s]+)\)/g, function (_m, alt, src, href) {
    return '<a href="' + _rewrite(href, opts) + '"><img src="' + _rewrite(src, opts) + '" alt="' + alt + '"></a>';
  });
  // image.
  out = out.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, function (_m, alt, src) {
    return '<img src="' + _rewrite(src, opts) + '" alt="' + alt + '">';
  });
  // link.
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, function (_m, txt, href) {
    return '<a href="' + _rewrite(href, opts) + '">' + txt + "</a>";
  });
  // bold, then inline code (code last so ** inside a code span is left literal).
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
  return out;
}

function _splitRow(line) {
  var t = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  // Split on UNESCAPED pipes only: a `\|` is a literal pipe in the cell content
  // (GFM sec. 4.10, e.g. an inline `f(a \| b)` code span), not a column
  // delimiter. Then unescape it so the cell renders the pipe. A naive
  // split("|") would shatter such a cell into phantom columns and leak the
  // backslash, mangling the whole table.
  return t.split(/(?<!\\)\|/).map(function (c) { return c.replace(/\\\|/g, "|").trim(); });
}

function render(md, opts) {
  var lines = String(md).replace(/\r\n?/g, "\n").split("\n");
  var out = [];
  var para = [];
  var list = null;

  function flushPara() {
    if (para.length) { out.push("<p>" + _inline(para.join(" "), opts) + "</p>"); para = []; }
  }
  function flushList() {
    if (list) { out.push("<ul>" + list.join("") + "</ul>"); list = null; }
  }
  function flushAll() { flushPara(); flushList(); }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    // Fenced code block: capture verbatim until the closing fence.
    var fence = /^(\s*)(`{3,}|~{3,})(.*)$/.exec(line);
    if (fence) {
      flushAll();
      var marker = fence[2].charAt(0);
      // Fence info string -> a language class for the syntax highlighter
      // ("```js" -> class="language-js"); a bare fence stays classless.
      var langMatch = /^[A-Za-z0-9+-]+/.exec(fence[3].trim());
      var langCls = langMatch ? ' class="language-' + esc(langMatch[0].toLowerCase()) + '"' : "";
      var buf = [];
      i++;
      for (; i < lines.length; i++) {
        if (new RegExp("^\\s*" + marker + "{3,}\\s*$").test(lines[i])) break;
        buf.push(lines[i]);
      }
      out.push("<pre><code" + langCls + ">" + esc(buf.join("\n")) + "</code></pre>");
      continue;
    }

    // GFM pipe table: a header row immediately followed by a separator row.
    if (line.trim().indexOf("|") !== -1 && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      flushAll();
      var head = _splitRow(line);
      i += 2; // skip header + separator
      var rows = [];
      for (; i < lines.length; i++) {
        if (lines[i].trim() === "" || lines[i].trim().indexOf("|") === -1) { i--; break; }
        rows.push(_splitRow(lines[i]));
      }
      var thtml = "<table><thead><tr>" +
        head.map(function (c) { return "<th>" + _inline(c, opts) + "</th>"; }).join("") +
        "</tr></thead><tbody>" +
        rows.map(function (r) {
          return "<tr>" + r.map(function (c) { return "<td>" + _inline(c, opts) + "</td>"; }).join("") + "</tr>";
        }).join("") + "</tbody></table>";
      out.push(thtml);
      continue;
    }

    // Block-level raw HTML the source authored -> passthrough (logo/img src
    // rewritten so the wiki serves it locally).
    if (RAW_HTML_LINE.test(line)) {
      flushAll();
      out.push(line.replace(/(<img[^>]*\bsrc=")([^"]+)(")/i, function (_m, a, src, b) {
        return a + esc(_rewrite(src, opts)) + b;
      }));
      continue;
    }

    var h = HEADING.exec(line);
    if (h) {
      flushAll();
      var lvl = h[1].length;
      // GitHub-compatible heading id (lowercase, punctuation stripped,
      // spaces to dashes) so the source's own #anchor links keep working
      // in the wiki render.
      var hid = h[2].trim().toLowerCase()
        .replace(/`/g, "")
        .replace(/[^a-z0-9 -]/g, "")
        .replace(/ /g, "-");
      var idAttr = hid ? ' id="' + esc(hid) + '"' : "";
      out.push("<h" + lvl + idAttr + ">" + _inline(h[2].trim(), opts) + "</h" + lvl + ">");
      continue;
    }

    if (HR.test(line)) { flushAll(); out.push("<hr>"); continue; }

    var li = UL_ITEM.exec(line);
    if (li) {
      flushPara();
      if (!list) list = [];
      list.push("<li>" + _inline(li[1], opts) + "</li>");
      continue;
    }

    if (line.trim() === "") { flushAll(); continue; }

    // Prose: accumulate into the current paragraph (a list is broken by a blank
    // line above, so a non-item line ends the list).
    flushList();
    para.push(line.trim());
  }
  flushAll();
  return out.join("\n");
}

module.exports = { render: render };
