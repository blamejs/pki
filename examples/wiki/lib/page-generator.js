// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// page-generator — build the source-driven documentation site entirely
// from the @module + @primitive comment blocks in the toolkit's lib/.
//
// build({ libDir, siteUrl? }) returns:
//
//   {
//     pages:        { "<path>": { title, h1, html } },  // "/" is home
//     navGroups:    [ { group, items: [ { slug, title, path } ] } ],
//     groupForPath: function (path) -> group name | null,
//     entries:      the auto-derived site entries
//   }
//
// The generator is pure: it reads lib/ source, never writes. server.js
// serves pages.html; test/e2e.js asserts every namespace page renders an
// <h1> and populated content. No runtime dependencies — the whole site
// is a function of the source comments.

var parser  = require("./source-doc-parser");
var auto    = require("./auto-site-entries");
var ent     = require("./html-entities");
var site    = require("../site.config");

var esc = ent.escapeHtml;

var BRAND = "pkijs.com";

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

function _renderPre(text) {
  return '<pre class="code"><code>' + esc(String(text).replace(/\r/g, "")) + "</code></pre>";
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
    out.push(_renderPre(tags.opts));
  }
  if (Array.isArray(tags.examples) && tags.examples.length) {
    out.push('<h3 class="sub">Example</h3>');
    tags.examples.forEach(function (ex) { out.push(_renderPre(ex)); });
  }
  if (tags.related) {
    out.push('<p class="related"><strong>See also:</strong> ' + _renderRelated(tags.related, index) + "</p>");
  }
  var refsHtml = _renderReferences(tags);
  if (refsHtml) out.push(refsHtml);
  out.push("</section>");
  return out.join("\n");
}

function _shell(opts) {
  // opts: { title, nav, main, siteUrl }
  var css = [
    ":root{--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--muted:#9da7b3;--accent:#7c5cff;--accent2:#26c6da;--line:#232a34;--code:#0b0f14}",
    "*{box-sizing:border-box}html,body{margin:0;padding:0}",
    "body{background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}",
    "a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}",
    ".wrap{display:flex;min-height:100vh;align-items:stretch}",
    "aside{width:260px;flex:0 0 260px;background:var(--panel);border-right:1px solid var(--line);padding:20px 16px;overflow-y:auto}",
    "aside .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px;margin-bottom:18px;color:var(--ink)}",
    "aside .brand img{width:28px;height:28px;border-radius:6px}",
    "aside .grp{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:16px 0 6px}",
    "aside ul{list-style:none;margin:0 0 8px;padding:0}aside li{margin:2px 0}",
    "aside a{display:block;padding:4px 8px;border-radius:6px;color:var(--ink)}",
    "aside a:hover{background:#1f2733;text-decoration:none}",
    "main{flex:1 1 auto;max-width:900px;margin:0 auto;padding:36px 40px}",
    "h1{font-size:34px;margin:0 0 8px;letter-spacing:-.01em}",
    "main>.intro{color:var(--muted);font-size:18px;margin:0 0 28px;max-width:70ch}",
    "h2{font-size:22px;margin:34px 0 6px;border-bottom:1px solid var(--line);padding-bottom:6px}",
    "h2 a{color:var(--ink)}h3.sub{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:18px 0 6px}",
    "code{background:var(--code);border:1px solid var(--line);border-radius:4px;padding:1px 5px;font:13px/1.5 'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;color:#d6d3ff}",
    "pre.code{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:14px 16px;overflow-x:auto;margin:10px 0}",
    "pre.code code{background:none;border:none;padding:0;color:#cfe3ff}",
    ".badges{margin:6px 0 14px;display:flex;gap:6px;flex-wrap:wrap}",
    ".badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}",
    ".badge-status{text-transform:uppercase;letter-spacing:.05em}.badge-stable{color:#3fb950;border-color:#233b28}",
    ".badge-experimental{color:#d29922;border-color:#3b3320}.badge-deprecated{color:#f85149;border-color:#3b2323}",
    ".badge-since{color:var(--accent2)}.badge-compliance{color:var(--accent)}",
    ".primitive{margin-bottom:10px}.related{color:var(--muted);font-size:14px}",
    ".refs{list-style:none;margin:6px 0 4px;padding:0;font-size:14px}.refs li{margin:2px 0;color:var(--muted)}",
    ".ref-kind{display:inline-block;min-width:64px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--accent)}",
    ".hero{display:flex;align-items:center;gap:22px;margin:6px 0 30px}",
    ".hero img{width:96px;height:96px;border-radius:18px;box-shadow:0 8px 40px rgba(124,92,255,.25)}",
    ".hero h1{font-size:40px;margin:0}.hero .tag{color:var(--muted);font-size:18px;margin-top:4px}",
    ".cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;margin:22px 0}",
    ".card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;transition:border-color .15s}",
    ".card:hover{border-color:var(--accent)}.card h3{margin:0 0 6px;font-size:17px}.card p{margin:0;color:var(--muted);font-size:14px}",
    "footer{color:var(--muted);font-size:13px;margin-top:48px;border-top:1px solid var(--line);padding-top:16px}",
    "@media(max-width:720px){.wrap{flex-direction:column}aside{width:auto;flex:none;border-right:none;border-bottom:1px solid var(--line)}main{padding:24px 18px}}",
  ].join("");
  return [
    "<!doctype html>",
    '<html lang="en"><head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>" + esc(opts.title) + " — " + BRAND + "</title>",
    "<style>" + css + "</style>",
    "</head><body><div class=\"wrap\">",
    opts.nav,
    "<main>" + opts.main,
    "<footer>" + esc(BRAND) + " — source-driven documentation, generated from the toolkit's own <code>@primitive</code> comment blocks. Zero runtime dependencies.</footer>",
    "</main></div></body></html>",
  ].join("\n");
}

function _renderNav(navGroups, currentPath) {
  var out = [];
  out.push("<aside>");
  out.push('<a class="brand" href="/"><img src="/pkijs-logo.png" alt="' + esc(BRAND) + '"><span>' + esc(BRAND) + "</span></a>");
  navGroups.forEach(function (g) {
    out.push('<div class="grp">' + esc(g.group) + "</div><ul>");
    g.items.forEach(function (it) {
      var active = it.path === currentPath ? ' style="background:#1f2733"' : "";
      out.push('<li><a href="' + esc(it.path) + '"' + active + ">" + esc(it.title) + "</a></li>");
    });
    out.push("</ul>");
  });
  out.push("</aside>");
  return out.join("\n");
}

function build(opts) {
  opts = opts || {};
  var libDir = opts.libDir || site.LIB_DIR;
  var siteUrl = opts.siteUrl || site.siteUrl;

  var docsByPath = parser.parseTree(libDir);
  var entries = auto.deriveFromLib(libDir);

  // Index parsed records by namespace for quick primitive lookup.
  var docsByNs = {};
  Object.keys(docsByPath).forEach(function (file) {
    var rec = docsByPath[file];
    if (!rec.module) return;
    var ns = _moduleNs(rec.module.tags && rec.module.tags.module);
    if (ns) docsByNs[ns] = rec;
  });

  var index = _primitiveIndex(entries, docsByNs);

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

  var pages = {};

  // ---- Home page ----
  var homeMain = [];
  homeMain.push('<div class="hero">');
  homeMain.push('<img src="/pkijs-logo.png" alt="' + esc(BRAND) + ' logo">');
  homeMain.push("<div><h1>" + esc(BRAND) + '</h1><div class="tag">A pure-JavaScript PKI toolkit that owns its stack — X.509, ASN.1/DER, OID, PQC-first.</div></div>');
  homeMain.push("</div>");
  homeMain.push("<p class=\"intro\">Every page in this reference is generated from the toolkit's own source comments. Zero npm runtime dependencies — the cryptography runs on Node's native <code>node:crypto</code> (classical and FIPS post-quantum), nothing vendored.</p>");

  var featured = entries.filter(function (e) { return e.featured; });
  var cardSet = featured.length ? featured : entries;
  homeMain.push('<div class="cards">');
  cardSet.forEach(function (e) {
    var desc = e.card ? e.card.description : "";
    homeMain.push('<a class="card" href="/' + esc(e.slug) + '"><h3>' + esc(e.title) + "</h3><p>" + esc(desc) + "</p></a>");
  });
  homeMain.push("</div>");
  pages["/"] = {
    title: "Home",
    h1:    BRAND,
    html:  _shell({ title: "Home", nav: _renderNav(navGroups, "/"), main: homeMain.join("\n"), siteUrl: siteUrl }),
  };

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
    rec.primitives.forEach(function (p) {
      main.push(_renderPrimitive(p, index));
    });
    var pth = "/" + e.slug;
    pages[pth] = {
      title: e.title,
      h1:    e.title,
      html:  _shell({ title: e.title, nav: _renderNav(navGroups, pth), main: main.join("\n"), siteUrl: siteUrl }),
    };
  });

  function groupForPath(p) { return pathToGroup[p] || null; }

  return {
    pages:        pages,
    navGroups:    navGroups,
    groupForPath: groupForPath,
    entries:      entries,
  };
}

module.exports = { build: build, specUrl: _specUrl };
