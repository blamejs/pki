// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// page-generator — build the source-driven documentation site entirely
// from the @module + @primitive comment blocks in the toolkit's lib/.
//
// build({ libDir, siteUrl? }) returns:
//
//   {
//     pages:        { "<path>": { title, h1, html, etag, cspScriptHashes } },
//     navGroups:    [ { group, items: [ { slug, title, path } ] } ],
//     groupForPath: function (path) -> group name | null,
//     entries:      the auto-derived site entries
//     assets:       { hrefs, files }     content-hashed CSS/JS (lib/assets)
//     searchIndex:  [ { path, title, headings, text } ]
//     symbolsJson:  the /symbols.json body
//     sitemapXml:   the /sitemap.xml body
//     robotsTxt:    the /robots.txt body
//   }
//
// The generator is pure aside from reading the source tree: it reads
// lib/ (and this example's concepts.js), never writes. server.js serves
// pages.html; test/e2e.js asserts every namespace page renders an <h1>
// and populated content. No runtime dependencies — the whole site is a
// function of the source comments.

var fs      = require("node:fs");
var path    = require("node:path");
var crypto  = require("node:crypto");
var parser  = require("./source-doc-parser");
var auto    = require("./auto-site-entries");
var ent     = require("./html-entities");
var markdown = require("./markdown");
var assets  = require("./assets");
var searchlib = require("./search");
var symbolIndex = require("./symbol-index");
var harvestErrors = require("./harvest-errors");
var site    = require("../site.config");

// The GitHub blob base for rewriting the README's repo-relative links so they
// resolve from the deployed wiki (a `.md` sibling or a bare repo path points at
// the source tree, not a wiki route).
var REPO_BLOB = "https://github.com/blamejs/pki/blob/main/";
var REPO_URL  = "https://github.com/blamejs/pki";
var NPM_URL   = "https://www.npmjs.com/package/@blamejs/pki";

// Rewrite one README link/image target for the wiki context: the logo asset is
// served locally; an in-page `#anchor` and any absolute URL pass through; a
// repo-relative path (ROADMAP.md, assets/..., LICENSE) points at the GitHub
// source tree.
function _readmeLink(href) {
  if (!href) return href;
  if (href.indexOf("assets/pkijs-logo.png") !== -1) return "/pkijs-logo.png";
  if (href.charAt(0) === "#") return href;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(href) || href.indexOf("mailto:") === 0) return href;
  return REPO_BLOB + href.replace(/^\.?\//, "");
}

var esc = ent.escapeHtml;

var BRAND = "pkijs.com";
var SITE_DESCRIPTION = "A pure-JavaScript PKI toolkit: X.509, ASN.1/DER, OID, CMS, OCSP, timestamping, EST, and PKCS formats — with an in-house, fail-closed DER codec, a post-quantum-first algorithm registry, and zero runtime dependencies.";

// A one-line meta description from prose: strip tags/whitespace, cap length.
function _metaDescription(src) {
  var text = String(src || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  if (text.length > 200) text = text.slice(0, 197).replace(/\s+\S*$/, "") + "…";
  return text || SITE_DESCRIPTION;
}

function _moduleNs(modTag) {
  return String(modTag || "").replace(/^\s*pki\./, "").trim();
}
function _bare(sig) {
  return String(sig)
    .replace(/->[\s\S]*$/, "")
    .replace(/\([^)]*\)/g, "")
    .replace(/\s+/g, "")
    .replace(/^pki\./, "");
}
function _anchor(bare) {
  return String(bare).replace(/\./g, "-");
}
function _slugify(text) {
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

// Render prose: escape HTML, turn `inline code` into <code>, split blank-
// line-separated paragraphs into <p>, collapse hard-wrapped single
// newlines into spaces within a paragraph.
function _renderProse(text) {
  if (!text) return "";
  var paras = String(text).replace(/\r/g, "").split(/\n[ \t]*\n/);
  return paras.map(function (para) {
    var body = esc(para.replace(/\n[ \t]*/g, " ").replace(/^\s+|\s+$/g, ""));
    body = body.replace(/`([^`]+)`/g, function (_m, code) { return "<code>" + code + "</code>"; });
    return "<p>" + body + "</p>";
  }).join("\n");
}

function _renderPre(text, lang) {
  var cls = lang ? ' class="language-' + esc(lang) + '"' : "";
  return '<pre class="code"><code' + cls + ">" + esc(String(text).replace(/\r/g, "")) + "</code></pre>";
}

// A concise @example may use top-level `await`. Wrap such a body in an async
// function for display, so the rendered snippet is copy-paste runnable in a plain
// script (not only in a REPL / ESM top-level-await context). An example that is
// already async (declares its own `async`) is left untouched.
function _wrapAsyncExample(text) {
  var body = String(text).replace(/\r/g, "");
  if (!/\bawait\b/.test(body) || /\basync\b/.test(body)) return body;
  var indented = body.split("\n").map(function (l) { return l ? "  " + l : l; }).join("\n");
  return "async function example() {\n" + indented + "\n}\nexample();";
}

function _badge(label, value, cls) {
  return '<span class="badge ' + cls + '">' + esc(label) + " " + esc(value) + "</span>";
}

// Build a global index of documented primitives so @related resolves to a
// page + anchor. Keyed by bare signature (e.g. "asn1.decode").
function _primitiveIndex(entries, docsByNs) {
  var byBare = {};
  var nsToSlug = {};
  entries.forEach(function (e) {
    e.namespaces.forEach(function (ns) { nsToSlug[ns] = e.slug; });
    var rec = docsByNs[e.namespaces[0]];
    if (!rec) return;
    rec.primitives.forEach(function (p) {
      var primTag = p.tags && p.tags.primitive;
      if (!primTag) return;
      var bare = _bare(primTag);
      byBare[bare] = { slug: e.slug, anchor: _anchor(bare), tag: primTag };
    });
  });
  return { byBare: byBare, nsToSlug: nsToSlug };
}

function _renderRelated(relatedTag, index) {
  var refs = String(relatedTag).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  var parts = refs.map(function (ref) {
    var bare = _bare(ref);
    var hit = index.byBare[bare];
    if (hit) {
      return '<a href="/' + esc(hit.slug) + "#" + esc(hit.anchor) + '"><code>' + esc(ref) + "</code></a>";
    }
    var ns = bare.split(".")[0];
    if (index.nsToSlug[ns] && bare === ns) {
      return '<a href="/' + esc(index.nsToSlug[ns]) + '"><code>' + esc(ref) + "</code></a>";
    }
    return "<code>" + esc(ref) + "</code>";
  });
  return parts.join(", ");
}

// Map an @spec / @defends reference to its canonical URL, or null when the
// source has no stable deep link (paywalled ISO/ANSI, internal, semver) —
// those render as plain <code>. Deep links: RFC section anchors on the IETF
// datatracker, FIPS/SP on NIST CSRC, X.NNN on ITU, W3C, CVE, CWE.
function _specUrl(ref) {
  var r = String(ref).trim();
  var m;
  if ((m = r.match(/^RFC (\d+)(?:\s+§([\w.]+))?/)))      return "https://datatracker.ietf.org/doc/html/rfc" + m[1] + (m[2] ? "#section-" + m[2] : "");
  if ((m = r.match(/^FIPS (\d+(?:-\d+)?)/)))             return "https://csrc.nist.gov/pubs/fips/" + m[1].toLowerCase() + "/final";
  if ((m = r.match(/^(?:NIST )?SP (800-\d+[A-Za-z]?)/))) return "https://csrc.nist.gov/publications/detail/sp/" + m[1].toLowerCase() + "/final";
  if ((m = r.match(/^(X\.\d+)/)))                        return "https://www.itu.int/rec/T-REC-" + m[1];
  if ((m = r.match(/^SEC (\d+)/)))                       return "https://www.secg.org/sec" + m[1] + "-v2.pdf";
  if (/^W3C WebCrypto/.test(r))                          return "https://www.w3.org/TR/WebCryptoAPI/";
  if ((m = r.match(/^CVE-(\d{4}-\d+)/)))                 return "https://www.cve.org/CVERecord?id=CVE-" + m[1];
  if ((m = r.match(/^CWE-(\d+)/)))                       return "https://cwe.mitre.org/data/definitions/" + m[1] + ".html";
  return null;
}

// Render @spec / @defends as a per-primitive "References" section: each entry
// linked to its normative source where one exists, so a reader (or auditor)
// jumps from the primitive to the clause it implements or the attack it guards.
function _renderReferences(tags) {
  var items = [];
  function add(tagVal, kind) {
    if (!tagVal) return;
    String(tagVal).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (ref) {
      var url = _specUrl(ref);
      var body = url
        ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(ref) + "</a>"
        : "<code>" + esc(ref) + "</code>";
      items.push('<li><span class="ref-kind">' + esc(kind) + "</span> " + body + "</li>");
    });
  }
  add(tags.spec, "spec");
  add(tags.defends, "defends");
  if (!items.length) return null;
  return '<h3 class="sub">References</h3><ul class="refs">' + items.join("") + "</ul>";
}

function _renderPrimitive(p, index) {
  var tags = p.tags || {};
  var primTag = tags.primitive;
  var bare = _bare(primTag);
  var anchor = _anchor(bare);
  var out = [];
  out.push('<section class="primitive" id="' + esc(anchor) + '">');
  out.push('<h2><a href="#' + esc(anchor) + '">' + esc(primTag) + "</a></h2>");

  var badges = [];
  if (tags.since)  badges.push(_badge("since", tags.since, "badge-since"));
  if (tags.originated) badges.push(_badge("originated", tags.originated, "badge-since"));
  if (tags.status) badges.push(_badge("", tags.status, "badge-status badge-" + esc(tags.status)));
  if (tags.compliance) {
    String(tags.compliance).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (c) {
      badges.push(_badge("", c, "badge-compliance"));
    });
  }
  if (badges.length) out.push('<div class="badges">' + badges.join(" ") + "</div>");

  if (tags.signature) out.push(_renderPre(tags.signature));
  out.push(_renderProse(p.prose));

  if (tags.opts) {
    out.push('<h3 class="sub">Options</h3>');
    out.push(_renderPre(tags.opts, "js"));
  }
  if (Array.isArray(tags.examples) && tags.examples.length) {
    out.push('<h3 class="sub">Example</h3>');
    tags.examples.forEach(function (ex) { out.push(_renderPre(_wrapAsyncExample(ex), "js")); });
  }
  if (tags.related) {
    out.push('<p class="related"><strong>See also:</strong> ' + _renderRelated(tags.related, index) + "</p>");
  }
  var refsHtml = _renderReferences(tags);
  if (refsHtml) out.push(refsHtml);
  out.push("</section>");
  return out.join("\n");
}

// JSON-LD structured data. Emitted as an inline <script type="application/
// ld+json"> whose sha256 the server adds to that page's script-src, so the
// CSP stays hash-strict with no 'unsafe-inline'.
function _jsonLd(kind, opts) {
  var data;
  if (kind === "website") {
    data = {
      "@context": "https://schema.org",
      "@type": "WebSite",
      "name": BRAND,
      "url": opts.siteUrl + "/",
      "description": SITE_DESCRIPTION,
    };
  } else {
    data = {
      "@context": "https://schema.org",
      "@type": "TechArticle",
      "headline": opts.title,
      "url": opts.canonical,
      "description": opts.description,
      "isPartOf": { "@type": "WebSite", "name": BRAND, "url": opts.siteUrl + "/" },
    };
  }
  // `<` is escaped inside the JSON so no value can close the script
  // element (`</script>`); the CSP hash is computed over the exact bytes
  // that ship between the tags.
  var json = JSON.stringify(data).replace(/</g, "\\u003c");
  var hash = crypto.createHash("sha256").update(json, "utf8").digest("base64");
  return {
    script: '<script type="application/ld+json">' + json + "</script>",
    cspHash: "'sha256-" + hash + "'",
  };
}

function _shell(opts) {
  // opts: { title, nav, main, siteUrl, path, description, assets, jsonLd }
  var siteUrl = (opts.siteUrl || "https://" + BRAND).replace(/\/+$/, "");
  var canonical = siteUrl + (opts.path || "/");
  var desc = String(opts.description || SITE_DESCRIPTION).replace(/\s+/g, " ").trim();
  var fullTitle = esc(opts.title) + " — " + BRAND;
  var ogImage = siteUrl + "/pkijs-logo.png";
  var hrefs = (opts.assets && opts.assets.hrefs) || {};
  var head = [
    "<!doctype html>",
    '<html lang="en"><head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>" + fullTitle + "</title>",
    '<meta name="description" content="' + esc(desc) + '">',
    '<meta name="robots" content="index,follow">',
    '<meta name="color-scheme" content="dark light">',
    '<link rel="canonical" href="' + esc(canonical) + '">',
    // Icons + PWA install surface.
    '<link rel="icon" href="/favicon.ico" sizes="any">',
    '<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">',
    '<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">',
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
    '<link rel="manifest" href="/manifest.webmanifest">',
    '<meta name="theme-color" content="#0d1117">',
    '<meta name="application-name" content="' + BRAND + '">',
    '<meta name="apple-mobile-web-app-title" content="' + BRAND + '">',
    '<meta name="apple-mobile-web-app-capable" content="yes">',
    '<meta name="mobile-web-app-capable" content="yes">',
    '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">',
    // Open Graph.
    '<meta property="og:type" content="website">',
    '<meta property="og:site_name" content="' + BRAND + '">',
    '<meta property="og:title" content="' + fullTitle + '">',
    '<meta property="og:description" content="' + esc(desc) + '">',
    '<meta property="og:url" content="' + esc(canonical) + '">',
    '<meta property="og:image" content="' + esc(ogImage) + '">',
    '<meta property="og:image:alt" content="' + BRAND + '">',
    '<meta property="og:locale" content="en_US">',
    // Twitter card.
    '<meta name="twitter:card" content="summary_large_image">',
    '<meta name="twitter:title" content="' + fullTitle + '">',
    '<meta name="twitter:description" content="' + esc(desc) + '">',
    '<meta name="twitter:image" content="' + esc(ogImage) + '">',
  ];
  if (hrefs.prismCss) head.push('<link rel="stylesheet" href="' + esc(hrefs.prismCss) + '">');
  if (hrefs.css)      head.push('<link rel="stylesheet" href="' + esc(hrefs.css) + '">');
  if (opts.jsonLd)    head.push(opts.jsonLd);
  head.push("</head><body>");

  var tail = [];
  tail.push('<a class="skip-link" href="#content">Skip to content</a>');
  tail.push('<div class="wrap">');
  tail.push(opts.nav);
  tail.push('<main id="content">' + opts.main);
  tail.push("<footer>" + esc(BRAND) + " — source-driven documentation, generated from the toolkit's own <code>@primitive</code> comment blocks. Zero runtime dependencies.</footer>");
  tail.push("</main></div>");
  if (hrefs.prismJs) tail.push('<script src="' + esc(hrefs.prismJs) + '" defer></script>');
  if (hrefs.js)      tail.push('<script src="' + esc(hrefs.js) + '" defer></script>');
  tail.push("</body></html>");

  return head.concat(tail).join("\n");
}

function _renderNav(navGroups, currentPath, activeGroup) {
  var out = [];
  out.push('<aside class="side">');
  out.push('<a class="brand" href="/"><img src="/pkijs-logo.png" alt="' + esc(BRAND) + '"><span>' + esc(BRAND) + "</span></a>");
  // Full-text search: a plain GET form — works without JavaScript.
  out.push('<form class="side-search" action="/search" method="get" role="search">');
  out.push('<label class="visually-hidden" for="q">Search documentation</label>');
  out.push('<input type="search" id="q" name="q" placeholder="Search docs" maxlength="200" autocomplete="off">');
  out.push("</form>");
  // Symbol autocomplete (progressive enhancement; inert without JS).
  out.push('<div class="sym-search">');
  out.push('<label class="visually-hidden" for="symq">Find a primitive</label>');
  out.push('<input type="search" id="symq" placeholder="Find pki.x.y  ( / )" autocomplete="off" autocapitalize="none" spellcheck="false" aria-controls="symq-results">');
  out.push('<ul id="symq-results" class="sym-results" role="listbox" hidden></ul>');
  out.push("</div>");
  out.push('<nav aria-label="Site">');
  navGroups.forEach(function (g) {
    var open = g.group === activeGroup ? " open" : "";
    out.push('<details class="navgrp"' + open + "><summary>" + esc(g.group) + "</summary><ul>");
    g.items.forEach(function (it) {
      var current = it.path === currentPath ? ' aria-current="page"' : "";
      out.push('<li><a href="' + esc(it.path) + '"' + current + ">" + esc(it.title) + "</a></li>");
    });
    out.push("</ul></details>");
  });
  out.push("</nav>");
  out.push('<div class="side-foot">');
  out.push('<a href="' + esc(REPO_URL) + '" target="_blank" rel="noopener noreferrer">GitHub</a> · ');
  out.push('<a href="' + esc(NPM_URL) + '" target="_blank" rel="noopener noreferrer">npm</a>');
  out.push("</div>");
  out.push("</aside>");
  return out.join("\n");
}

// ---- Concepts: narrative pages from the wiki's own concepts.js ----
// Each /** @concept */ block becomes a page: single-line tags (@concept,
// @title, @order, @related), prose, then @section blocks whose first line
// is the heading. Parsed with the same block parser the lib/ walk uses.
function _loadConcepts() {
  var conceptsPath = path.join(__dirname, "..", "concepts.js");
  var src;
  try { src = fs.readFileSync(conceptsPath, "utf8"); } catch (_e) { return []; }
  var out = [];
  parser.extractBlocks(src).forEach(function (b) {
    var parsed = parser.parseBlock(b.raw);
    var tags = parsed.tags || {};
    if (!tags.concept) return;
    var orderRaw = tags.order != null ? parseInt(tags.order, 10) : NaN;
    out.push({
      id:       String(tags.concept).trim(),
      title:    tags.title || String(tags.concept).trim(),
      order:    isFinite(orderRaw) ? orderRaw : 100,
      related:  tags.related || null,
      prose:    parsed.prose,
      sections: Array.isArray(tags.sections) ? tags.sections : [],
    });
  });
  out.sort(function (a, b) { return a.order - b.order || (a.id < b.id ? -1 : 1); });
  return out;
}

function _renderConcept(c, index) {
  var main = [];
  main.push("<h1>" + esc(c.title) + "</h1>");
  main.push('<div class="intro">' + _renderProse(c.prose).replace(/^<p>|<\/p>$/g, "") + "</div>");
  c.sections.forEach(function (s) {
    var anchor = _slugify(s.heading);
    main.push('<h2 id="' + esc(anchor) + '"><a href="#' + esc(anchor) + '">' + esc(s.heading) + "</a></h2>");
    main.push(_renderProse(s.body));
  });
  if (c.related) {
    main.push('<p class="related"><strong>See also:</strong> ' + _renderRelated(c.related, index) + "</p>");
  }
  return main.join("\n");
}

// ---- Reference: the auto-generated API index ----
function _renderApiIndex(entries, docsByNs) {
  var main = [];
  main.push("<h1>API index</h1>");
  var total = 0;
  var sections = [];
  entries.forEach(function (e) {
    var rec = docsByNs[e.namespaces[0]];
    if (!rec || !rec.primitives.length) return;
    var rows = [];
    rec.primitives.forEach(function (p) {
      var tags = p.tags || {};
      if (!tags.primitive) return;
      total += 1;
      var bare = _bare(tags.primitive);
      var anchor = _anchor(bare);
      var sig = tags.signature ? String(tags.signature).replace(/\s+/g, " ").trim() : tags.primitive;
      rows.push("<tr><td><a href=\"/" + esc(e.slug) + "#" + esc(anchor) + "\"><code>" + esc(sig) + "</code></a></td>" +
        "<td>" + (tags.since ? esc(tags.since) : "") + "</td>" +
        "<td>" + (tags.status ? esc(tags.status) : "") + "</td></tr>");
    });
    if (!rows.length) return;
    var hid = "ns-" + esc(e.slug);
    sections.push('<h2 id="' + hid + '"><a href="#' + hid + '">' + esc(e.title) + "</a></h2>" +
      '<table class="ref-table"><thead><tr><th>Primitive</th><th>Since</th><th>Status</th></tr></thead><tbody>' +
      rows.join("") + "</tbody></table>");
  });
  main.push('<div class="intro">Every documented primitive, grouped by namespace page — ' + total + " primitives. Generated from the same source comments that build the rest of this site.</div>");
  main.push(sections.join("\n"));
  return main.join("\n");
}

// ---- Reference: the error catalog ----
function _renderErrorCatalog(libDir) {
  var main = [];
  main.push("<h1>Error catalog</h1>");
  var data;
  try { data = harvestErrors.harvest(libDir); }
  catch (e) {
    main.push('<div class="callout"><span class="callout-label">Harvest failed</span>' + esc(String(e && e.message || e)) + "</div>");
    return main.join("\n");
  }
  main.push('<div class="intro">Every error class the toolkit throws and every stable <code>domain/reason</code> code, harvested from the source at boot — ' +
    data.classCount + " classes, " + data.codeCount + " codes. Each error extends <code>PkiError</code>: catch once with <code>err instanceof pki.errors.PkiError</code> and switch on <code>err.code</code>.</div>");

  main.push('<h2 id="classes"><a href="#classes">Error classes</a></h2>');
  var rows = data.classes.map(function (c) {
    return "<tr><td><code>" + esc(c.name) + "</code></td><td><code>" + esc(c.file) + "</code></td><td>" + esc(c.flags.join(", ")) + "</td></tr>";
  });
  main.push('<table class="ref-table"><thead><tr><th>Class</th><th>Declared in</th><th>Flags</th></tr></thead><tbody>' + rows.join("") + "</tbody></table>");

  data.domains.forEach(function (d) {
    var hid = "domain-" + esc(d.domain);
    main.push('<h2 id="' + hid + '"><a href="#' + hid + '"><code>' + esc(d.domain) + "/*</code></a></h2>");
    var codeRows = d.codes.map(function (c) {
      return "<tr><td><code>" + esc(c.code) + "</code></td><td>" + c.files.map(function (f) { return "<code>" + esc(f) + "</code>"; }).join(", ") + "</td></tr>";
    });
    main.push('<table class="ref-table"><thead><tr><th>Code</th><th>Thrown from</th></tr></thead><tbody>' + codeRows.join("") + "</tbody></table>");
  });
  return main.join("\n");
}

// ---- Search results page (rendered per-request by server.js) ----
function renderSearch(built, q) {
  var results = searchlib.search(built.searchIndex, q);
  var main = [];
  var qTrim = String(q || "").slice(0, searchlib.MAX_QUERY_CHARS);
  main.push("<h1>Search</h1>");
  if (!qTrim.trim()) {
    main.push('<div class="intro">Type a query into the search box — every page\'s full text is searched.</div>');
  } else {
    main.push('<div class="intro">' + results.length + (results.length === 1 ? " result" : " results") + ' for "' + esc(qTrim) + '"</div>');
    results.forEach(function (r) {
      main.push('<div class="search-hit">');
      main.push('<h2><a href="' + esc(r.path) + '">' + esc(r.title) + "</a></h2>");
      main.push('<div class="hit-path">' + esc(r.path) + "</div>");
      main.push('<p class="hit-excerpt">' + r.excerpt + "</p>");
      main.push("</div>");
    });
  }
  return _shell({
    title: "Search",
    path: "/search",
    description: "Full-text search over the pkijs.com documentation.",
    nav: _renderNav(built.navGroups, "/search", null),
    main: main.join("\n"),
    siteUrl: built.siteUrl,
    assets: built.assets,
  });
}

function _etag(html) {
  return '"' + crypto.createHash("sha256").update(html, "utf8").digest("hex").slice(0, 32) + '"';
}

function build(opts) {
  opts = opts || {};
  var libDir = opts.libDir || site.LIB_DIR;
  var siteUrl = opts.siteUrl || site.siteUrl;

  var docsByPath = parser.parseTree(libDir);
  var entries = auto.deriveFromLib(libDir);
  var shellAssets = assets.build();

  // Index parsed records by namespace for quick primitive lookup.
  var docsByNs = {};
  Object.keys(docsByPath).forEach(function (file) {
    var rec = docsByPath[file];
    if (!rec.module) return;
    var ns = _moduleNs(rec.module.tags && rec.module.tags.module);
    if (ns) docsByNs[ns] = rec;
  });

  var index = _primitiveIndex(entries, docsByNs);
  var concepts = _loadConcepts();

  // Nav groups: group -> items, preserving the auto-sorted entry order.
  var groupOrder = [];
  var groupMap = {};
  var pathToGroup = {};
  entries.forEach(function (e) {
    var item = { slug: e.slug, title: e.title, path: "/" + e.slug };
    if (!groupMap[e.group]) { groupMap[e.group] = []; groupOrder.push(e.group); }
    groupMap[e.group].push(item);
    pathToGroup["/" + e.slug] = e.group;
  });
  var navGroups = groupOrder.map(function (g) { return { group: g, items: groupMap[g] }; });

  // Concepts group right after Overview; Reference pinned last.
  if (concepts.length) {
    navGroups.unshift({
      group: "Concepts",
      items: concepts.map(function (c) {
        var slug = "concepts-" + c.id;
        pathToGroup["/" + slug] = "Concepts";
        return { slug: slug, title: c.title, path: "/" + slug };
      }),
    });
  }

  // ---- Overview: the repository README, rendered to HTML ----
  // A single curated top-level page (like Home) -- the README is the project's
  // front door, so the wiki carries it verbatim rather than a hand-maintained
  // second copy. Repo-relative links are rewritten for the wiki context.
  var overviewItem = { slug: "overview", title: "Overview", path: "/overview" };
  var readmePath = path.resolve(libDir, "..", "README.md");
  var readmeHtml;
  try { readmeHtml = markdown.render(fs.readFileSync(readmePath, "utf8"), { rewriteLink: _readmeLink }); }
  catch (_e) { readmeHtml = null; }
  if (readmeHtml) {
    navGroups.unshift({ group: "Overview", items: [overviewItem] });
    pathToGroup["/overview"] = "Overview";
  }

  // Reference: the auto-generated index + error catalog, pinned last.
  var referenceItems = [
    { slug: "api", title: "API index", path: "/api" },
    { slug: "reference-errors", title: "Error catalog", path: "/reference-errors" },
  ];
  navGroups.push({ group: "Reference", items: referenceItems });
  referenceItems.forEach(function (it) { pathToGroup[it.path] = "Reference"; });

  var pages = {};
  var searchIndexArr = [];

  // One place stamps every page: shell + etag + CSP hash + search text.
  function _addPage(pth, meta) {
    // meta: { title, h1, main, description, ldKind, headings }
    var canonical = siteUrl + pth;
    var ld = _jsonLd(meta.ldKind || "article", {
      siteUrl: siteUrl, title: meta.title, canonical: canonical,
      description: meta.description || SITE_DESCRIPTION,
    });
    var html = _shell({
      title: meta.title,
      path: pth,
      description: meta.description,
      nav: _renderNav(navGroups, pth, pathToGroup[pth] || null),
      main: meta.main,
      siteUrl: siteUrl,
      assets: shellAssets,
      jsonLd: ld.script,
    });
    pages[pth] = {
      title: meta.title,
      h1:    meta.h1 || meta.title,
      html:  html,
      etag:  _etag(html),
      cspScriptHashes: [ld.cspHash],
    };
    searchIndexArr.push({
      path:     pth,
      title:    meta.title,
      headings: meta.headings || "",
      text:     searchlib.extractText(meta.main),
    });
  }

  // ---- Home page ----
  var homeMain = [];
  homeMain.push('<div class="hero">');
  homeMain.push('<img src="/pkijs-logo.png" alt="' + esc(BRAND) + ' logo">');
  homeMain.push("<div><h1>" + esc(BRAND) + '</h1><div class="tag">A pure-JavaScript PKI toolkit that owns its stack — X.509, ASN.1/DER, OID, PQC-first.</div></div>');
  homeMain.push("</div>");
  homeMain.push('<div class="pills">');
  ["Zero npm dependencies", "PQC-first", "Fail-closed DER", "CommonJS, no transpilation", "Apache-2.0"].forEach(function (p) {
    homeMain.push('<span class="pill">' + esc(p) + "</span>");
  });
  homeMain.push("</div>");
  homeMain.push("<p class=\"intro\">Every page in this reference is generated from the toolkit's own source comments. Zero npm runtime dependencies — the cryptography runs on Node's native <code>node:crypto</code> (classical and FIPS post-quantum), nothing vendored.</p>");

  homeMain.push('<h2 id="quick-start"><a href="#quick-start">Quick start</a></h2>');
  homeMain.push(_renderPre("npm install @blamejs/pki", "sh"));
  homeMain.push(_renderPre(
    'var pki = require("@blamejs/pki");\n\n' +
    "var cert = pki.schema.x509.parse(pemText);\n" +
    'cert.subject.dn;                 // "CN=example.com, O=Example"\n' +
    "cert.validity.notAfter;          // Date\n" +
    'cert.signatureAlgorithm.name;    // "sha256WithRSAEncryption"', "js"));
  homeMain.push('<div class="callout callout-tip"><span class="callout-label">Tip</span>Parse without knowing the format first: <code>pki.schema.parse(der)</code> detects which of the toolkit\'s registered formats the bytes encode — certificate, CRL, CSR, CMS, OCSP, PKCS#8, PKCS#12, timestamp token, and the rest — and routes to the owning parser. <code>pki.schema.all()</code> lists the registered formats.</div>');

  homeMain.push('<h2 id="design-tenets"><a href="#design-tenets">Design tenets</a></h2>');
  homeMain.push('<ul class="tenets">');
  homeMain.push("<li><strong>Zero runtime dependencies.</strong> The published package's dependency object is empty; the cryptography is Node's own <code>node:crypto</code>.</li>");
  homeMain.push("<li><strong>Fail closed.</strong> Every verify path throws; malformed input is a typed <code>PkiError</code> with a stable <code>domain/reason</code> code.</li>");
  homeMain.push("<li><strong>Strict DER.</strong> The codec rejects every non-DER shape and enforces size and depth caps before it walks a byte.</li>");
  homeMain.push("<li><strong>Post-quantum first.</strong> ML-DSA, ML-KEM, and SLH-DSA resolve through the same OID-keyed registry as the classical algorithms.</li>");
  homeMain.push("<li><strong>Standards are the contract.</strong> Every structure maps to a named RFC, and a parser round-trips a valid input to identical bytes.</li>");
  homeMain.push("</ul>");

  var featured = entries.filter(function (e) { return e.featured; });
  var cardSet = featured.length ? featured : entries;
  homeMain.push('<h2 id="namespaces"><a href="#namespaces">Namespaces</a></h2>');
  homeMain.push('<div class="cards">');
  cardSet.forEach(function (e) {
    var desc = e.card ? e.card.description : "";
    homeMain.push('<a class="card" href="/' + esc(e.slug) + '"><h3>' + esc(e.title) + "</h3><p>" + esc(desc) + "</p></a>");
  });
  homeMain.push("</div>");
  _addPage("/", { title: "Home", h1: BRAND, main: homeMain.join("\n"), description: SITE_DESCRIPTION, ldKind: "website" });

  // ---- Overview page (rendered README) ----
  if (readmeHtml) {
    _addPage("/overview", {
      title: "Overview",
      h1: BRAND,
      main: '<div class="readme">' + readmeHtml + "</div>",
      description: SITE_DESCRIPTION,
    });
  }

  // ---- Concept pages ----
  concepts.forEach(function (c) {
    _addPage("/concepts-" + c.id, {
      title: c.title,
      main: _renderConcept(c, index),
      description: _metaDescription(_renderProse(c.prose)),
      headings: c.sections.map(function (s) { return s.heading; }).join(" "),
    });
  });

  // ---- Namespace pages ----
  entries.forEach(function (e) {
    var ns = e.namespaces[0];
    var rec = docsByNs[ns];
    if (!rec) return;
    var modTags = (rec.module && rec.module.tags) || {};
    var main = [];
    main.push("<h1>" + esc(e.title) + "</h1>");
    var introSrc = modTags.intro || (e.card && e.card.description) || "";
    if (introSrc) main.push('<div class="intro">' + _renderProse(introSrc).replace(/^<p>|<\/p>$/g, "") + "</div>");
    var headingParts = [];
    rec.primitives.forEach(function (p) {
      main.push(_renderPrimitive(p, index));
      if (p.tags && p.tags.primitive) headingParts.push(p.tags.primitive);
    });
    _addPage("/" + e.slug, {
      title: e.title,
      main: main.join("\n"),
      description: _metaDescription(introSrc),
      headings: headingParts.join(" "),
    });
  });

  // ---- Reference pages ----
  _addPage("/api", {
    title: "API index",
    main: _renderApiIndex(entries, docsByNs),
    description: "Every documented primitive in the toolkit, grouped by namespace, with since-version and stability.",
  });
  _addPage("/reference-errors", {
    title: "Error catalog",
    main: _renderErrorCatalog(libDir),
    description: "Every PkiError class and every stable domain/reason error code the toolkit throws, harvested from the source.",
  });

  // ---- Machine surfaces: symbols manifest, sitemap, robots ----
  var symbols = symbolIndex.build(entries, docsByNs, { bare: _bare, anchor: _anchor });
  var symbolsJson = JSON.stringify({ count: symbols.length, symbols: symbols });

  var today = new Date().toISOString().slice(0, 10);
  var sitemapEntries = Object.keys(pages).sort().map(function (p) {
    return "  <url><loc>" + esc(siteUrl + p) + "</loc><lastmod>" + today + "</lastmod>" +
      "<changefreq>weekly</changefreq><priority>" + (p === "/" ? "1.0" : "0.8") + "</priority></url>";
  });
  var sitemapXml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    sitemapEntries.join("\n") + "\n</urlset>\n";

  var robotsTxt = "User-agent: *\nAllow: /\n\nSitemap: " + siteUrl + "/sitemap.xml\n";

  function groupForPath(p) { return pathToGroup[p] || null; }

  return {
    pages:        pages,
    navGroups:    navGroups,
    groupForPath: groupForPath,
    entries:      entries,
    siteUrl:      siteUrl,
    assets:       shellAssets,
    searchIndex:  searchIndexArr,
    symbolsJson:  symbolsJson,
    sitemapXml:   sitemapXml,
    robotsTxt:    robotsTxt,
  };
}

module.exports = { build: build, specUrl: _specUrl, renderSearch: renderSearch };
