// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * GitHub-Actions-currency gate — the CI/CD-supply-chain sibling of
 * `scripts/check-vendor-currency.js`.
 *
 * Walks every `.github/workflows/*.yml`, reads each SHA-pinned
 * `uses: owner/repo[/subpath]@<sha>  # vX.Y.Z` reference, and asserts the
 * pinned version (from the trailing comment the pinact discipline requires)
 * matches the latest upstream release. A stale action becomes a release
 * blocker HERE — caught in the pre-merge gate suite — instead of being
 * surfaced after-the-fact by a Dependabot PR.
 *
 * Actions listed under `ignore_actions` in `.pinact.yaml` are honored: the
 * SLSA reusable workflow (which MUST be tag-pinned) and
 * aquasecurity/trivy-action (whose org blocks the commits API from runner
 * IPs, so online re-resolution can't complete) are skipped here exactly as
 * pinact skips them.
 *
 * Run locally:
 *   node scripts/check-actions-currency.js
 *   node scripts/check-actions-currency.js --json     // structured output
 *   node scripts/check-actions-currency.js --warn     // exit 0, print only
 *   node scripts/check-actions-currency.js --fix       // rewrite stale pins
 *                                                       // to the latest SHA +
 *                                                       // version comment,
 *                                                       // then exit 0
 *
 * Run in CI: the workflow passes GITHUB_TOKEN so the GitHub API gives the
 * authenticated 5000/hour budget instead of the 60/hour unauthenticated
 * per-IP limit. `stale` fails the gate; transient `api-error` results are
 * advisory unless PKIJS_ACTIONS_CURRENCY_STRICT=1 converts them to hard
 * fails too.
 */

var fs    = require("node:fs");
var path  = require("node:path");
var https = require("node:https");

var ROOT          = path.join(__dirname, "..");
var WORKFLOWS_DIR = path.join(ROOT, ".github", "workflows");
var PINACT_PATH   = path.join(ROOT, ".pinact.yaml");

var WARN_ONLY  = process.argv.indexOf("--warn") !== -1;
var JSON_OUT   = process.argv.indexOf("--json") !== -1;
var DO_FIX     = process.argv.indexOf("--fix") !== -1;
var TIMEOUT_MS = 10000;

// Per-action overrides. Keyed by "owner/repo".
//   { type: "hold-major", major: N, reason: "..." } — only flag stale
//        WITHIN the pinned major; a newer major is an intentional hold.
//   { type: "skip", reason: "..." }                 — never flag.
var SPECIAL_MAP = {
  // (none — every pinned action tracks upstream latest; the tag-pinned
  // exceptions are carried by .pinact.yaml instead)
};

// ---- .pinact.yaml ignore parsing -----------------------------------------
//
// Minimal, targeted parser for the `ignore_actions:` list. pinact v3 treats
// both `name` and `ref` as regular expressions; a matching action is
// exempted from the online tag re-resolution this gate performs.
function _stripQuotes(s) {
  s = String(s).trim();
  if ((s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') ||
      (s.charAt(0) === "'" && s.charAt(s.length - 1) === "'")) {
    return s.slice(1, -1);
  }
  return s;
}

function _safeRegExp(src) {
  try { return new RegExp(src); }
  catch (_e) {
    // Fall back to a literal match if the pattern isn't valid regex.
    try { return new RegExp(src.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")); }
    catch (_e2) { return null; }
  }
}

function _loadPinactIgnores() {
  var text;
  try { text = fs.readFileSync(PINACT_PATH, "utf8"); }
  catch (_e) { return []; }
  var lines = text.split(/\r?\n/);
  var inIgnore = false;
  var entries = [];
  var cur = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\s*#/.test(line)) continue;
    var body = line.replace(/\s+#.*$/, "");
    if (/^ignore_actions\s*:/.test(body)) { inIgnore = true; continue; }
    if (!inIgnore) continue;
    // A new unindented, non-empty top-level key ends the block.
    if (/^\S/.test(body) && body.trim() !== "") { inIgnore = false; continue; }
    var mName = body.match(/^\s*-?\s*name\s*:\s*(.+?)\s*$/);
    if (mName) {
      var isNewItem = /^\s*-\s*name\s*:/.test(body);
      if (isNewItem) { if (cur) entries.push(cur); cur = { name: _stripQuotes(mName[1]), ref: ".*" }; }
      else if (cur) { cur.name = _stripQuotes(mName[1]); }
      continue;
    }
    var mRef = body.match(/^\s*ref\s*:\s*(.+?)\s*$/);
    if (mRef && cur) { cur.ref = _stripQuotes(mRef[1]); continue; }
  }
  if (cur) entries.push(cur);
  return entries.map(function (e) {
    var re = _safeRegExp(e.name);
    return re ? { nameRe: re, name: e.name } : null;
  }).filter(Boolean);
}

// Does any pinact ignore entry match this action? Test the bare owner/repo
// AND every full owner/repo[/subpath] form (pinact matches the full `uses:`
// action name, which may include a workflow subpath).
function _isPinactIgnored(ignores, ownerRepo, entry) {
  var candidates = [ownerRepo];
  (entry.refs || []).forEach(function (r) {
    if (r.subpath) candidates.push(ownerRepo + r.subpath);
  });
  for (var i = 0; i < ignores.length; i++) {
    for (var c = 0; c < candidates.length; c++) {
      if (ignores[i].nameRe.test(candidates[c])) return ignores[i];
    }
  }
  return null;
}

// ---- GitHub API ----------------------------------------------------------

function _githubGet(apiPath) {
  return new Promise(function (resolve, reject) {
    var headers = {
      "User-Agent": "pkijs-actions-currency/1",
      "Accept":     "application/vnd.github+json",
    };
    var token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) headers.Authorization = "Bearer " + token;
    var req = https.get("https://api.github.com" + apiPath, { timeout: TIMEOUT_MS, headers: headers }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        if (res.statusCode !== 200) {
          return reject(new Error("github " + apiPath + " status " + res.statusCode));
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("github " + apiPath + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

async function _resolveSha(ownerRepo, ref) {
  var c = await _githubGet("/repos/" + ownerRepo + "/commits/" + encodeURIComponent(ref));
  if (!c || typeof c.sha !== "string") throw new Error("could not resolve sha for " + ownerRepo + "@" + ref);
  return c.sha;
}

// Fetch the supply-chain review material for a bump: the commit range
// between the pinned SHA and the new SHA, plus the release notes for the new
// tag. A human reviews this before trusting the pin.
async function _releaseChangelog(ownerRepo, oldSha, newTag, newSha) {
  var out = {
    compareUrl: "https://github.com/" + ownerRepo + "/compare/" + oldSha + "..." + newSha,
    commits: [], files: [], body: "", compareError: null,
  };
  try {
    var cmp = await _githubGet("/repos/" + ownerRepo + "/compare/" + oldSha + "..." + newSha);
    if (cmp && cmp.html_url) out.compareUrl = cmp.html_url;
    if (cmp && Array.isArray(cmp.commits)) {
      out.commits = cmp.commits.map(function (c) {
        var msg = ((c.commit && c.commit.message) || "").split("\n")[0];
        var who = (c.author && c.author.login) || (c.commit && c.commit.author && c.commit.author.name) || "?";
        return (c.sha || "").slice(0, 10) + "  " + who + "  " + msg;
      });
    }
    if (cmp && Array.isArray(cmp.files)) {
      out.files = cmp.files.map(function (f) {
        return {
          name: f.filename, status: f.status,
          add: f.additions, del: f.deletions,
          patch: typeof f.patch === "string" ? f.patch : null,
        };
      });
    }
  } catch (e) { out.compareError = (e && e.message) || String(e); }
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/tags/" + encodeURIComponent(newTag));
    if (rel && typeof rel.body === "string") out.body = rel.body;
  } catch (_e) { /* action ships tags without a GitHub Release body */ }
  return out;
}

async function _latestVersion(ownerRepo) {
  var tag = null;
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/latest");
    if (rel && typeof rel.tag_name === "string" && _semverParse(rel.tag_name)) tag = rel.tag_name;
  } catch (_e) { /* fall through to tags */ }
  if (!tag) {
    var tags = await _githubGet("/repos/" + ownerRepo + "/tags?per_page=100");
    if (!Array.isArray(tags) || tags.length === 0) {
      throw new Error("no releases or tags for " + ownerRepo);
    }
    var best = null;
    for (var i = 0; i < tags.length; i++) {
      var p = _semverParse(tags[i].name);
      if (p && (!best || _semverCompare(p, best.parsed) > 0)) {
        best = { name: tags[i].name, parsed: p };
      }
    }
    if (!best) throw new Error("no semver-shaped tag for " + ownerRepo);
    tag = best.name;
  }
  return { tag: tag, sha: await _resolveSha(ownerRepo, tag) };
}

function _semverParse(v) {
  var m = String(v).match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2] || "0", 10), parseInt(m[3] || "0", 10)];
}

function _semverCompare(a, b) {
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

// Collect distinct SHA-pinned actions across every workflow file.
// Returns { "owner/repo": { version, sha, refs: [{ file, line, subpath }] } }.
function _collectPinnedActions() {
  var out = {};
  var files = fs.readdirSync(WORKFLOWS_DIR).filter(function (f) {
    return f.endsWith(".yml") || f.endsWith(".yaml");
  });
  var re = /uses:\s*([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@([0-9a-f]{40})\s*#\s*v?(\d+(?:\.\d+){0,2})/;
  for (var f = 0; f < files.length; f++) {
    var rel = ".github/workflows/" + files[f];
    var lines = fs.readFileSync(path.join(WORKFLOWS_DIR, files[f]), "utf8").split("\n");
    for (var L = 0; L < lines.length; L++) {
      var m = lines[L].match(re);
      if (!m) continue;
      var ownerRepo = m[1];
      var subpath   = m[2] || "";
      var sha       = m[3];
      var version   = m[4];
      if (!out[ownerRepo]) out[ownerRepo] = { version: version, sha: sha, refs: [] };
      out[ownerRepo].refs.push({ file: rel, line: L + 1, subpath: subpath });
      if (_semverCompare(_semverParse(version), _semverParse(out[ownerRepo].version)) < 0) {
        out[ownerRepo].version = version;
      }
    }
  }
  return out;
}

async function _checkOne(ownerRepo, entry) {
  var special = SPECIAL_MAP[ownerRepo];
  if (special && special.type === "skip") {
    return { action: ownerRepo, status: "skipped", reason: special.reason, pinned: entry.version };
  }
  var pinned = _semverParse(entry.version);
  try {
    var info = await _latestVersion(ownerRepo);
    var latest = _semverParse(info.tag);
    var cmp = _semverCompare(pinned, latest);
    var status = cmp >= 0 ? "current" : "stale";
    if (special && special.type === "hold-major" && latest && latest[0] > special.major) {
      status = "current";
    }
    return {
      action:    ownerRepo,
      pinned:    entry.version,
      oldSha:    entry.sha,
      latest:    info.tag,
      latestSha: info.sha,
      status:    status,
      refs:      entry.refs,
    };
  } catch (e) {
    return {
      action: ownerRepo,
      pinned: entry.version,
      status: "api-error",
      error:  (e && e.message) || String(e),
      refs:   entry.refs,
    };
  }
}

async function main() {
  var pinned  = _collectPinnedActions();
  var ignores = _loadPinactIgnores();
  var actions = Object.keys(pinned).sort();
  var results = [];
  for (var i = 0; i < actions.length; i++) {
    var name = actions[i];
    var ig = _isPinactIgnored(ignores, name, pinned[name]);
    if (ig) {
      results.push({ action: name, status: "skipped", reason: ".pinact.yaml ignore (" + ig.name + ")", pinned: pinned[name].version, refs: pinned[name].refs });
      continue;
    }
    results.push(await _checkOne(name, pinned[name]));
  }

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ results: results }, null, 2) + "\n");
  } else {
    process.stdout.write("[actions-currency] " + actions.length + " SHA-pinned action(s) inspected:\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"   ? "OK"
                : r.status === "stale"     ? "STALE"
                : r.status === "api-error" ? "ERR"
                : r.status === "skipped"   ? "skip"
                :                            r.status;
      var line = "  [" + label + "] " + r.action + "  " + r.pinned;
      if (r.latest) line += " -> " + r.latest;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (api: " + r.error + ")";
      process.stdout.write(line + "\n");
      if (r.status === "stale" && r.latestSha) {
        process.stdout.write("        pin:  " + r.action + "@" + r.latestSha + "  # " + r.latest + "\n");
        for (var rf = 0; rf < (r.refs || []).length; rf++) {
          process.stdout.write("        used: " + r.refs[rf].file + ":" + r.refs[rf].line + "\n");
        }
      }
    }
  }

  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var errored = results.filter(function (r) { return r.status === "api-error"; });

  if (DO_FIX) {
    var byFile = {};
    var fixable = stale.filter(function (r) { return r.latestSha && r.latest; });
    for (var fx = 0; fx < fixable.length; fx++) {
      var fr = fixable[fx];
      var tag = /^v/.test(fr.latest) ? fr.latest : "v" + fr.latest;
      var cl = await _releaseChangelog(fr.action, fr.oldSha, tag, fr.latestSha);
      process.stdout.write("\n=== " + fr.action + "  " + fr.pinned + " -> " + fr.latest + " ===\n");
      process.stdout.write("  old sha: " + fr.oldSha + "\n  new sha: " + fr.latestSha + "\n");
      process.stdout.write("  compare: " + cl.compareUrl + "\n");
      if (cl.commits.length) {
        process.stdout.write("  commits between the two SHAs (" + cl.commits.length + ") [sha  author  subject]:\n");
        for (var ci = 0; ci < cl.commits.length; ci++) process.stdout.write("    " + cl.commits[ci] + "\n");
      } else if (cl.compareError) {
        process.stdout.write("  commits: (compare unavailable: " + cl.compareError + ")\n");
      }
      if (cl.files.length) {
        process.stdout.write("  changed files (" + cl.files.length + "):\n");
        for (var sfi = 0; sfi < cl.files.length; sfi++) {
          var sf = cl.files[sfi];
          process.stdout.write("    [" + sf.status + " +" + sf.add + "/-" + sf.del + "] " + sf.name + "\n");
        }
        process.stdout.write("  code diff (per file, capped at 200 lines):\n");
        for (var dfi = 0; dfi < cl.files.length; dfi++) {
          var df = cl.files[dfi];
          process.stdout.write("    ----- " + df.name + " -----\n");
          if (df.patch === null) {
            process.stdout.write("      (patch omitted by GitHub — file too large / binary; inspect via the compare URL above)\n");
          } else {
            var dl = df.patch.split("\n");
            for (var dk = 0; dk < Math.min(dl.length, 200); dk++) process.stdout.write("      " + dl[dk] + "\n");
            if (dl.length > 200) process.stdout.write("      ... (" + (dl.length - 200) + " more diff line(s) — see compare URL)\n");
          }
        }
      }
      if (cl.body) {
        process.stdout.write("  release notes for " + tag + ":\n");
        var bl = cl.body.split("\n");
        for (var bi = 0; bi < Math.min(bl.length, 40); bi++) process.stdout.write("    " + bl[bi] + "\n");
        if (bl.length > 40) process.stdout.write("    ... (" + (bl.length - 40) + " more line(s))\n");
      }
      var esc = fr.action.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      var re2 = new RegExp("(" + esc + "(?:/[^@\\s]+)?@)[0-9a-f]{40}(\\s*#\\s*)v?\\d+(?:\\.\\d+){0,2}", "g");
      for (var rj = 0; rj < (fr.refs || []).length; rj++) {
        var abs = path.join(ROOT, fr.refs[rj].file);
        if (!(abs in byFile)) byFile[abs] = fs.readFileSync(abs, "utf8");
        byFile[abs] = byFile[abs].replace(re2, "$1" + fr.latestSha + "$2" + tag);
      }
    }
    Object.keys(byFile).forEach(function (abs) { fs.writeFileSync(abs, byFile[abs]); });
    process.stdout.write("\n[actions-currency] --fix: rewrote " + fixable.length + " stale action(s) across " +
      Object.keys(byFile).length + " workflow file(s). REVIEW the changelogs above for supply-chain integrity before committing; re-run without --fix to verify.\n");
    process.exit(0);
  }

  if (WARN_ONLY) {
    if (stale.length || errored.length) {
      process.stdout.write("[actions-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored — exit 0 anyway\n");
    }
    process.exit(0);
  }

  var strictErrors = process.env.PKIJS_ACTIONS_CURRENCY_STRICT === "1";
  if (stale.length > 0 || (strictErrors && errored.length > 0)) {
    process.stdout.write("[actions-currency] FAIL — " + stale.length + " stale, " +
      errored.length + " api-error(s). Bump the pinned SHA + version comment to the latest release.\n");
    process.exit(1);
  }
  process.stdout.write("[actions-currency] OK — every pinned action matches the latest upstream release (or is ignored by .pinact.yaml)\n");
  process.exit(0);
}

main().catch(function (e) {
  process.stderr.write("[actions-currency] script crashed: " + ((e && e.stack) || e) + "\n");
  process.exit(2);
});
