// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/gen-migrating.js - generate MIGRATING.md from deprecate() calls
// across lib/. Walks the tree, finds every `deprecate.warn|wrap|alias`
// invocation, extracts the opts literal, groups by removeIn major.
//
// Re-run before each release; the file is committed so operators can read
// the diff against the prior tag.
//
// Limitation: opts must be an object literal (the common case). Calls that
// pass a variable as opts won't be captured - the script logs them with a
// [gen-migrating] note and the entry is skipped. Switch to a module-hook
// capture if that ever becomes the dominant pattern.

var fs   = require("node:fs");
var path = require("node:path");

var ROOT    = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");
var TARGET  = path.join(ROOT, "MIGRATING.md");

function _walk(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var full = path.join(dir, e.name);
    if (e.isDirectory()) {
      // Vendored bundles are third-party; never scan them for deprecations.
      if (e.name !== "vendor") _walk(full, out);
    } else if (e.isFile() && e.name.endsWith(".js")) {
      out.push(full);
    }
  });
  return out;
}

// Find the closing brace of an object literal that starts at index i
// (where src[i] === "{"). Tracks nesting + quoted strings + escapes.
// Returns the index AFTER the closing brace, or -1 if unterminated.
function _findObjectEnd(src, i) {
  var depth = 0;
  var inStr = null;
  var esc = false;
  for (; i < src.length; i++) {
    var c = src[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (c === "\\") esc = true;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === "\"" || c === "`") { inStr = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function _evalOpts(src) {
  try { return Function("return " + src)(); }
  catch (_e) { return null; }
}

function _extractDeprecations(src, fileLabel) {
  var out = [];

  // .warn("name", { ... })
  for (var m of src.matchAll(/(?:^|[^.\w])deprecate\.warn\s*\(\s*"([^"]+)"\s*,\s*\{/g)) {
    var braceAt = m.index + m[0].length - 1;
    var end = _findObjectEnd(src, braceAt);
    if (end < 0) continue;
    var opts = _evalOpts(src.slice(braceAt, end));
    if (!opts) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.warn(\"" + m[1] + "\")\n");
      continue;
    }
    out.push({ kind: "warn", name: m[1], opts: opts });
  }

  // .wrap(<fn>, "name", { ... })
  for (var w of src.matchAll(/(?:^|[^.\w])deprecate\.wrap\s*\(/g)) {
    var startW = w.index + w[0].length;
    var nameMatchW = src.slice(startW).match(/"([^"]+)"\s*,/);
    if (!nameMatchW) continue;
    var afterNameW = startW + nameMatchW.index + nameMatchW[0].length;
    var openBraceW = src.indexOf("{", afterNameW);
    if (openBraceW < 0) continue;
    var endW = _findObjectEnd(src, openBraceW);
    if (endW < 0) continue;
    var optsW = _evalOpts(src.slice(openBraceW, endW));
    if (!optsW) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.wrap(\"" + nameMatchW[1] + "\")\n");
      continue;
    }
    out.push({ kind: "wrap", name: nameMatchW[1], opts: optsW });
  }

  // .alias(<obj>, "old", "new", { ... })
  for (var a of src.matchAll(/(?:^|[^.\w])deprecate\.alias\s*\(/g)) {
    var startA = a.index + a[0].length;
    var aliasMatchA = src.slice(startA).match(/"([^"]+)"\s*,\s*"([^"]+)"\s*,/);
    if (!aliasMatchA) continue;
    var afterAliasA = startA + aliasMatchA.index + aliasMatchA[0].length;
    var openBraceA = src.indexOf("{", afterAliasA);
    if (openBraceA < 0) continue;
    var endA = _findObjectEnd(src, openBraceA);
    if (endA < 0) continue;
    var optsA = _evalOpts(src.slice(openBraceA, endA));
    if (!optsA) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.alias(\"" + aliasMatchA[1] + "\")\n");
      continue;
    }
    out.push({ kind: "alias", name: aliasMatchA[1], renamedTo: aliasMatchA[2], opts: optsA });
  }

  return out;
}

function _majorOf(version) {
  var m = String(version || "").match(/^(\d+)\.(\d+)/);
  if (!m) return null;
  return Number(m[1]) === 0 ? "v0.x" : "v" + m[1] + ".x";
}

function _gather() {
  var files = _walk(LIB_DIR, []);
  var entries = [];
  files.forEach(function (f) {
    var src = fs.readFileSync(f, "utf8");
    var rel = path.relative(ROOT, f).replace(/\\/g, "/");
    _extractDeprecations(src, rel).forEach(function (d) {
      if (!d.opts.since || !d.opts.removeIn) {
        process.stderr.write("[gen-migrating] " + rel + ": " + d.kind + " call for \"" + d.name + "\" missing since/removeIn \u2014 skipped\n");
        return;
      }
      entries.push({
        name:      d.name,
        kind:      d.kind,
        since:     d.opts.since,
        removeIn:  d.opts.removeIn,
        message:   d.opts.message || null,
        hint:      d.opts.hint || null,
        renamedTo: d.renamedTo || null,
        file:      rel,
      });
    });
  });
  return entries;
}

function _build() {
  var entries = _gather();
  var byRemove = new Map();
  entries.forEach(function (e) {
    var major = _majorOf(e.removeIn);
    if (!major) return;
    if (!byRemove.has(major)) byRemove.set(major, []);
    byRemove.get(major).push(e);
  });

  var lines = [];
  lines.push("# Migrating");
  lines.push("");
  lines.push("One migration recipe per breaking change. Every deprecated surface listed here also warns from the running process before its removal version, with `PKI_DEPRECATIONS=warn` set or by default outside production. This file ships in the repository, so you can diff it against the tag you are upgrading from.");
  lines.push("");
  lines.push("Some breaking changes cannot warn at runtime: an on-disk format break or a wire-encoding change has no in-process call to attach a warning to. Those are listed below alongside the runtime deprecations, so the full upgrade path is here rather than spread through the changelog.");
  lines.push("");

  if (entries.length === 0) {
    lines.push("## No active deprecations");
    lines.push("");
    lines.push("The toolkit has no `deprecate()`-marked surface awaiting removal.");
    lines.push("");
    _appendOutOfBand(lines);
    return lines.join("\n");
  }

  var majors = Array.from(byRemove.keys()).sort();
  majors.forEach(function (m) {
    lines.push("## Removed in " + m);
    lines.push("");
    var rows = byRemove.get(m).slice().sort(function (a, b) {
      if (a.since !== b.since) return a.since < b.since ? -1 : 1;
      return a.name < b.name ? -1 : 1;
    });
    rows.forEach(function (e) {
      lines.push("### `" + e.name + "`");
      lines.push("");
      lines.push("- **Since:** " + e.since);
      lines.push("- **Removed in:** " + e.removeIn);
      lines.push("- **Defined at:** [`" + e.file + "`](" + e.file + ")");
      if (e.kind === "alias" && e.renamedTo) {
        lines.push("- **Renamed to:** `" + e.renamedTo + "`");
      }
      if (e.message) {
        lines.push("");
        lines.push(e.message);
      }
      if (e.hint) {
        lines.push("");
        lines.push(e.hint);
      }
      lines.push("");
    });
  });

  _appendOutOfBand(lines);
  return lines.join("\n");
}

// OUT_OF_BAND_BREAKS - on-disk / wire-encoding breaks that can't be
// expressed via `deprecate()` because there is no in-process runtime
// surface to warn from. Append an entry as a release ships one.
//
// Each entry:
//   release:    git tag of the release that introduced the break
//   surface:    operator-visible API or on-disk artifact affected
//   summary:    one-line operator-facing description
//   migration:  multi-line markdown migration recipe
var OUT_OF_BAND_BREAKS = [
  {
    release: "v0.5.7",
    surface: "content that is an encoded SignedAttributes block",
    summary: "Signing or verifying such content WITHOUT signed attributes is refused as cms/ambiguous-content.",
    migration: [
      "A CMS signature does not commit to whether signed attributes were present, so a signature made",
      "over a SignedAttributes block can be re-presented as one made over content. The shape is now",
      "refused at both ends.",
      "",
      "This only affects you if your CMS content genuinely IS a DER SET OF Attribute carrying both a",
      "content-type and a message-digest attribute -- the shape RFC 5652 sec. 5.3 gives a",
      "SignedAttributes -- AND you sign it with `signedAttributes: false`. Ordinary content is",
      "unaffected, and so is a set of attributes missing either of those two.",
      "",
      "```js",
      "await pki.cms.sign(attrShapedContent, signer, { signedAttributes: false });  // cms/ambiguous-content",
      "await pki.cms.sign(attrShapedContent, signer);                              // signed attributes: fine",
      "```",
      "",
      "Signing it WITH signed attributes makes the message unambiguous and it verifies normally.",
      "Existing messages of this shape already in your archive will not verify; re-sign them with",
      "signed attributes.",
    ].join("\n"),
  },
  {
    release: "v0.5.6",
    surface: "try { pki.<verb>(...) } catch",
    summary: "A verb documented `-> Promise` rejects on a bad input instead of throwing before the promise exists.",
    migration: [
      "If you awaited the call, or attached `.catch`, nothing changes and there is nothing to do.",
      "",
      "What changes is the undocumented shape: a synchronous `try`/`catch` that never consumed the",
      "returned promise.",
      "",
      "```js",
      "try {",
      "  pki.cms.verify(bytes);            // no await, no .catch",
      "} catch (e) { /* used to fire on a malformed input */ }",
      "```",
      "",
      "That `catch` no longer runs, and the rejection surfaces as an unhandled one. It worked by",
      "accident on exactly the verbs where a check happened to run before the promise existed --",
      "`pki.cms.verify`, `pki.cms.sign`, `pki.cms.countersign`, `pki.ocsp.sign`, `pki.tsp.sign`, six",
      "`pki.acme` verbs, and nine verbs on the client `pki.acme.client(...)` returns. Which verbs",
      "those were was not visible from the call, which is why they are now uniform.",
      "",
      "```js",
      "await pki.cms.verify(bytes);        // or pki.cms.verify(bytes).catch(handleIt)",
      "```",
    ].join("\n"),
  },
  {
    release: "v0.5.6",
    surface: "pki.pkcs12.build(spec)",
    summary: "An omitted password is refused rather than encoded as the empty one.",
    migration: [
      "A store whose password option was missing or misspelled no longer builds silently under `\"\"`.",
      "",
      "```js",
      "await pki.pkcs12.build(spec);                    // now pkcs12/bad-input",
      "await pki.pkcs12.build(spec, { password: \"\" });  // the empty password, asked for",
      "```",
      "",
      "If you were relying on the default, the second form restores the previous output byte for",
      "byte. `opts.integrity.mode` is validated the same way: a spelling other than `\"public-key\"`",
      "is now `pkcs12/bad-integrity-mode` instead of silently selecting password integrity and",
      "dropping the signer.",
    ].join("\n"),
  },
  {
    release: "v0.5.5",
    surface: "require(\"@blamejs/pki/lib/...\")",
    summary: "The package resolves one entry point; a path into the package no longer resolves.",
    migration: [
      "`require(\"@blamejs/pki\")` and `import ... from \"@blamejs/pki\"` are unchanged. What no",
      "longer resolves is a path INTO the package:",
      "",
      "```",
      "require(\"@blamejs/pki/lib/schema-x509\")   // ERR_PACKAGE_PATH_NOT_EXPORTED",
      "```",
      "",
      "Every module under `lib/` carries `@internal` in its own header and none has ever appeared",
      "in the API snapshot that freezes the public surface. They were reachable because the package",
      "declared no `exports` map, not because they were offered -- and one of them mints the",
      "provenance record the OCSP and PKCS#12 integrity verbs rely on, which reachable from outside",
      "could be minted for any object.",
      "",
      "Everything the internals do is on `pki.*`: the decoders are `pki.schema.<format>.parse`, the",
      "codec is `pki.asn1`, the OID registry is `pki.oid`, the error classes are `pki.errors`. If you",
      "are reaching for something with no `pki.*` route, that is a gap worth reporting rather than a",
      "module worth importing -- the internals change shape between patch releases and carry no",
      "compatibility promise.",
      "",
      "`require(\"@blamejs/pki/package.json\")` still resolves, for tooling that reads the version.",
    ].join("\n"),
  },
];

function _appendOutOfBand(lines) {
  if (!OUT_OF_BAND_BREAKS.length) return;
  lines.push("---");
  lines.push("");
  lines.push("## Out-of-band breaking changes");
  lines.push("");
  lines.push("Listed newest-first.");
  lines.push("");
  // Semver-aware sort - `v0.9.10` must sort newer than `v0.9.9` (a naive
  // lexicographic compare would order the digit `1` before `9`). Strip the
  // leading `v`, split on `.`, compare each numeric component.
  function _semverCmp(a, b) {
    var as = String(a).replace(/^v/, "").split(".").map(Number);
    var bs = String(b).replace(/^v/, "").split(".").map(Number);
    for (var i = 0; i < Math.max(as.length, bs.length); i += 1) {
      var ai = i < as.length ? as[i] : 0;
      var bi = i < bs.length ? bs[i] : 0;
      if (ai !== bi) return ai - bi;
    }
    return 0;
  }
  var sorted = OUT_OF_BAND_BREAKS.slice().sort(function (a, b) {
    return _semverCmp(b.release, a.release);   // newest first
  });
  sorted.forEach(function (e) {
    lines.push("### " + e.release + " \u2014 `" + e.surface + "`");
    lines.push("");
    lines.push(e.summary);
    lines.push("");
    lines.push(e.migration);
    lines.push("");
  });
}

fs.writeFileSync(TARGET, _build(), "utf8");
process.stdout.write("[gen-migrating] wrote " + TARGET + "\n");
