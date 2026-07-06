// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// source-comment-block-validator — shared validation engine for the
// source-driven wiki pipeline (`@module` + `@primitive` blocks in
// lib/*.js).
//
// Two consumers import it:
//
//   1. examples/wiki/test/e2e.js
//        — wiki e2e gate; boots the generated site and validates the
//          blocks that drive it.
//   2. scripts/validate-source-comment-blocks.js
//        — toolkit-level static gate. Runs from a clean checkout without
//          `examples/wiki && npm install`, alongside eslint /
//          codebase-patterns, so block drift is caught pre-push in <5s.
//
// The validate() entry takes a config object:
//
//   {
//     libDir:  absolute path to the toolkit's lib/   (required)
//     parser:  the source-doc-parser module          (required)
//   }
//
// Returns an array of finding objects: { kind, file, primitive?, msg }.
//
// Signature convention differs from a single-namespace framework: a
// primitive may be exposed through a namespace object (`pki.asn1.read.oid`
// documented under the `pki.asn1.readOid` function, `pki.asn1.build`
// documenting the `build.*` value builders) or via a constructor
// (`new PkiError(...)`). The engine therefore validates signature SHAPE
// and code ARITY rather than demanding the signature's dotted path equal
// the @primitive path.
//
// Pure module — no side effects at require-time.

var fs   = require("node:fs");
var path = require("node:path");
var vm   = require("node:vm");

var ROOT_RE = /^\s*pki\./;

var KNOWN_STATUSES = { stable: 1, experimental: 1, deprecated: 1 };

// Compliance-posture catalog. A PKI toolkit's compliance surface is the
// standards / assurance regimes a deployment answers to. Kept small and
// explicit — an unknown value is a typo, not a silent pass.
var KNOWN_POSTURES = {
  "soc2": 1, "iso-27001": 1, "fips-140-3": 1, "common-criteria": 1,
  "webpki": 1, "cabf-br": 1, "etsi-319-411": 1, "eidas": 1,
  "rfc-5280": 1, "rfc-3161": 1, "nist-800-52": 1, "cnsa-2-0": 1,
  "pci-dss": 1, "hipaa": 1, "gdpr": 1,
};

var SEMVER_RE = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/;

// Compare two X.Y.Z versions numerically (ignores any pre-release suffix):
// -1 if a < b, 0 if equal, 1 if a > b.
function _cmpSemver(a, b) {
  var pa = String(a).split("-")[0].split(".").map(Number);
  var pb = String(b).split("-")[0].split(".").map(Number);
  for (var i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0) ? -1 : 1;
  }
  return 0;
}

// @spec — the normative reference(s) a primitive is DERIVED FROM. For a
// standards-implementation library, every primitive traces to a standard;
// a citation is validated (not free text) so it can be linked in the wiki
// and so naming the clause forces opening the spec. A crypto primitive
// cites BOTH the algorithm standard (FIPS / SP 800 / SEC / ANSI X9) AND the
// PKIX/encoding profile (RFC / X.690) — this checks each entry's shape, not
// the pairing. A trailing `§clause` and/or `(label)` is allowed in any
// order; `internal (design: ...)` is the only escape for genuine
// infrastructure with no external standard.
var _SPEC_OPT = "(?:\\s+(?:§[\\w.]+|\\([^)]*\\)))*";
var SPEC_PATTERNS = [
  new RegExp("^FIPS \\d+(?:-\\d+)?" + _SPEC_OPT + "$"),
  new RegExp("^(?:NIST )?SP 800-\\d+[A-Za-z]?(?:\\s+Rev\\.?\\s*\\d+)?" + _SPEC_OPT + "$"),
  new RegExp("^RFC \\d+" + _SPEC_OPT + "$"),
  new RegExp("^X\\.\\d+(?:-\\d+)?" + _SPEC_OPT + "$"),
  new RegExp("^ISO/IEC \\d+(?:-\\d+)?" + _SPEC_OPT + "$"),
  new RegExp("^SEC \\d+" + _SPEC_OPT + "$"),
  new RegExp("^ANSI X9\\.\\d+" + _SPEC_OPT + "$"),
  new RegExp("^IEC \\d+(?:-\\d+)?" + _SPEC_OPT + "$"),
  new RegExp("^PKCS#\\d+" + _SPEC_OPT + "$"),
  new RegExp("^W3C \\S.*$"),
  new RegExp("^CA/Browser Forum\\b.*$"),
  new RegExp("^(?:SemVer|semver\\.org)\\b.*$"),
  new RegExp("^internal(?:\\s+\\([^)]*\\))?$"),
];
function _isValidSpecRef(ref) {
  var r = String(ref).trim();
  for (var i = 0; i < SPEC_PATTERNS.length; i++) if (SPEC_PATTERNS[i].test(r)) return true;
  return false;
}

// @defends — the attack CLASS / CVE / CWE a primitive guards.
function _isValidDefendsRef(ref) {
  var r = String(ref).trim();
  // A ref that announces itself as a CVE/CWE MUST match the strict id form,
  // so a malformed "CVE-14-1568" is rejected rather than waved through as a
  // "named class" by the permissive fallback below.
  if (/^CVE-/i.test(r)) return /^CVE-\d{4}-\d+$/.test(r);
  if (/^CWE-/i.test(r)) return /^CWE-\d+$/.test(r);
  // Otherwise a named class, optionally suffixed with the id it maps to.
  return /^[A-Za-z][A-Za-z0-9 /_.+-]*(?:\s+\((?:CVE-\d{4}-\d+|CWE-\d+)\))?$/.test(r);
}

// Placeholder patterns in @example bodies that signal unexecutable code.
var EXAMPLE_PLACEHOLDERS = [
  { id: "ascii-arrow",    re: /\/\/\s*>\s+/m,                  hint: 'use "// -> ..." for expected-result comments — "// > " reads as a shell prompt' },
  { id: "todo",           re: new RegExp("\\/\\/\\s*TO" + "DO\\b", "i"),  hint: "remove placeholder markers from shipping examples" },
  { id: "pseudocode",     re: /\/\/\s*pseudocode\b/i,          hint: "examples must be runnable code; remove pseudocode marker" },
  { id: "fill-in",        re: /\.\.\.\s*(fill|replace|your)/i, hint: "concretize the placeholder with a real value" },
  { id: "angle-bracket",  re: /<[A-Z][A-Z0-9_-]*>/,            hint: "<PLACEHOLDER> looks like an angle-bracket placeholder — concretize the value" },
  { id: "square-replace", re: /\[\s*REPLACE[-_ ]?ME\s*\]/i,    hint: "replace the [REPLACE-ME] placeholder with a real value" },
];

// Bare identifier path of a signature / primitive tag: drop the argument
// list, whitespace, any `-> returnType` suffix, and the `pki.` root.
function _bare(sig) {
  return String(sig)
    .replace(/->[\s\S]*$/, "")     // drop return-type annotation
    .replace(/\([^)]*\)/g, "")     // drop argument lists
    .replace(/\s+/g, "")
    .replace(/^pki\./, "");
}
function _moduleNs(modTag) {
  return String(modTag || "").replace(ROOT_RE, "").trim();
}
function _firstSegment(primTag) {
  return _bare(primTag).split(".")[0];
}

// Extract operator-facing export keys from a source file. Supports the
// object-literal (`module.exports = { foo: foo }`) and per-property
// (`module.exports.foo = foo`) shapes. The object-literal extractor uses
// bracket-counting so nested closing braces inside method bodies don't
// terminate the scan early. Underscore-prefixed names are conventionally
// private and skipped.
function _extractExportKeys(source) {
  var keys = {};

  var perPropRe = /\bmodule\.exports\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/g;
  var pm;
  while ((pm = perPropRe.exec(source)) !== null) keys[pm[1]] = true;

  var litMatch = source.match(/module\.exports\s*=\s*\{/);
  if (litMatch) {
    var openIdx = litMatch.index + litMatch[0].length - 1;
    _collectObjectKeys(source, openIdx).forEach(function (k) { keys[k] = true; });
  }

  return Object.keys(keys).filter(function (k) { return !/^_/.test(k); });
}

// Bracket-count the object literal whose opening `{` is at openIdx and
// return its top-level property names (string/comment-aware).
function _collectObjectKeys(source, openIdx) {
  var i = openIdx + 1;
  var depth = 1;
  var inStr = null;
  var inSlash = false;
  var inBlock = false;
  var prev = "";
  while (i < source.length && depth > 0) {
    var c = source[i];
    if (inSlash) {
      if (c === "\n") inSlash = false;
    } else if (inBlock) {
      if (prev === "*" && c === "/") inBlock = false;
    } else if (inStr) {
      if (c === "\\") { i += 2; prev = source[i - 1]; continue; }
      if (c === inStr) inStr = null;
    } else if (c === "/" && source[i + 1] === "/") {
      inSlash = true;
    } else if (c === "/" && source[i + 1] === "*") {
      inBlock = true;
    } else if (c === '"' || c === "'" || c === "`") {
      inStr = c;
    } else if (c === "{") {
      depth++;
    } else if (c === "}") {
      depth--;
    }
    prev = c;
    i++;
  }
  var found = [];
  if (depth !== 0) return found;
  var body = source.slice(openIdx + 1, i - 1);
  var depth2 = 0;
  var line = "";
  var lines = [];
  for (var j = 0; j < body.length; j++) {
    var ch = body[j];
    if (ch === "{" || ch === "(" || ch === "[") depth2++;
    else if (ch === "}" || ch === ")" || ch === "]") depth2--;
    if (depth2 === 0) {
      line += ch;
      if (ch === "," || ch === "\n") { lines.push(line); line = ""; }
    }
  }
  if (line) lines.push(line);
  lines.forEach(function (l) {
    var lm = l.match(/^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[:,]/);
    if (lm) found.push(lm[1]);
  });
  return found;
}

// Probe the universe of signatures available for @related resolution.
// Sources: every @primitive under lib/, plus every exported binding of
// each documented module (so a "see also" reference to a real export
// that has no @primitive block of its own — e.g. `pki.oid.byName` — still
// resolves, while a reference to a nonexistent member is caught as drift).
function _knownPrimitiveSet(docs, source_by_file) {
  var set = {};
  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    rec.primitives.forEach(function (p) {
      var sig = p.tags && p.tags.primitive;
      if (sig) set[_bare(sig)] = true;
    });
    var modNs = rec.module ? _moduleNs(rec.module.tags && rec.module.tags.module) : null;
    if (!modNs) return;
    var src = source_by_file[file] || "";
    _extractExportKeys(src).forEach(function (k) {
      set[modNs + "." + k] = true;
    });
  });
  return set;
}

// Count parameters in a signature's FIRST argument list, e.g.
// `pki.schema.x509.parse(input) -> cert` -> 1, `new PkiError(msg, code)` -> 2.
// The `?` optional marker is dropped before counting.
function _signatureArity(signature) {
  var m = String(signature).match(/\(([^)]*)\)/);
  if (!m) return 0;
  var inner = m[1].replace(/\s+/g, "").replace(/\?/g, "");
  if (!inner) return 0;
  return inner.split(",").filter(Boolean).length;
}

// Find the function declaration for `name` and return its declared arity,
// or -1 when no plain-function declaration exists (namespace objects,
// classes, and factory-built exports report -1 and skip the arity check).
function _functionArity(source, name) {
  var topLevelDecl = new RegExp("^function\\s+" + name + "\\s*\\(([^)]*)\\)", "m");
  var topLevelVar = new RegExp("^(?:var|let|const)\\s+" + name + "\\s*=\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)", "m");
  var exportAssign = new RegExp("module\\.exports\\." + name + "\\s*=\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)", "m");
  var anyDecl = new RegExp("function\\s+" + name + "\\s*\\(([^)]*)\\)", "m");
  var m = source.match(topLevelDecl)
       || source.match(topLevelVar)
       || source.match(exportAssign)
       || source.match(anyDecl);
  if (!m) return -1;
  var inner = m[1].replace(/\s+/g, "").replace(/\?/g, "");
  if (!inner) return 0;
  return inner.split(",").filter(Boolean).length;
}

// Parse-check an @example body. Wrapped as an async IIFE so top-level
// `var` / `await` is permitted. Returns null on success, error message
// on failure.
function _parseCheckExample(body) {
  var wrapped = "(async function () {\n" + body + "\n})();";
  try {
    new vm.Script(wrapped, { filename: "example.js" });
    return null;
  } catch (e) {
    return (e && e.message) || String(e);
  }
}

// validate(config) -> findings[]
function validate(config) {
  if (!config || !config.libDir) throw new TypeError("validate(): config.libDir is required");
  if (!config.parser) throw new TypeError("validate(): config.parser is required");

  var libDir = config.libDir;
  var parser = config.parser;

  var findings = [];
  var docs = parser.parseTree(libDir);

  var source_by_file = {};
  Object.keys(docs).forEach(function (file) {
    try { source_by_file[file] = fs.readFileSync(file, "utf8"); } catch (_e) { source_by_file[file] = ""; }
  });

  var known = _knownPrimitiveSet(docs, source_by_file);

  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    var rel = path.relative(libDir, file);
    var source = source_by_file[file] || "";
    var modNs = rec.module ? _moduleNs(rec.module.tags && rec.module.tags.module) : null;

    // ---- Pass: per-primitive checks ----
    rec.primitives.forEach(function (p) {
      var tags = p.tags || {};
      var primTag = tags.primitive;
      if (!primTag) {
        findings.push({ kind: "schema", file: rel, msg: "@primitive tag is empty" });
        return;
      }

      // 1. @primitive shape.
      if (!/^pki\.[a-zA-Z][a-zA-Z0-9_.]*$/.test(primTag)) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "@primitive must be `pki.X.Y` form" });
      }

      // 2. @signature present + shaped like a call / constructor.
      if (!tags.signature) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "missing @signature" });
      } else if (tags.signature.indexOf("(") === -1) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "@signature must show a call form with an argument list, e.g. `" + primTag + "(...)`" });
      }

      // 3. prose body.
      if (!p.prose || p.prose.replace(/\s/g, "").length < 12) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "prose body is empty or too short (<12 non-whitespace chars)" });
      }
      if (p.proseAfterMultiLine) {
        findings.push({
          kind: "ordering", file: rel, primitive: primTag,
          msg: "prose appears AFTER a multi-line tag (@opts/@example/@intro) — those greedily consume every following line. Move prose ABOVE the multi-line tags.",
        });
      }
      if (p.mixedKind) {
        findings.push({
          kind: "schema", file: rel, primitive: primTag,
          msg: "block declares multiple kinds (" + p.mixedKind.join(" + ") + ") — pick exactly one. Parser silently chose `" + p.kind + "`; the others are hidden.",
        });
      }

      // 4. @example present.
      var hasExample = (Array.isArray(tags.examples) && tags.examples.length > 0) || tags.exampleFile;
      if (!hasExample) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "missing @example or @exampleFile" });
      }

      // 5. @status catalog.
      if (tags.status && !KNOWN_STATUSES[tags.status]) {
        findings.push({
          kind: "catalog", file: rel, primitive: primTag,
          msg: "@status must be one of " + Object.keys(KNOWN_STATUSES).join(" / ") + " (got `" + tags.status + "`)",
        });
      }

      // 6. @since semver.
      if (tags.since && (tags.since.length > 32 || !SEMVER_RE.test(tags.since))) {
        findings.push({
          kind: "catalog", file: rel, primitive: primTag,
          msg: "@since does not look like semver (got `" + tags.since + "`)",
        });
      }

      // 6a. @originated (the earlier version the callable was already reachable, when
      // the documented path was later corrected) — semver, and not later than @since.
      if (tags.originated) {
        if (tags.originated.length > 32 || !SEMVER_RE.test(tags.originated)) {
          findings.push({
            kind: "catalog", file: rel, primitive: primTag,
            msg: "@originated does not look like semver (got `" + tags.originated + "`)",
          });
        } else if (tags.since && SEMVER_RE.test(tags.since) && _cmpSemver(tags.originated, tags.since) > 0) {
          findings.push({
            kind: "catalog", file: rel, primitive: primTag,
            msg: "@originated `" + tags.originated + "` is later than @since `" + tags.since + "` (the origin cannot post-date the corrected path)",
          });
        }
      }

      // 7. @compliance catalog.
      if (tags.compliance) {
        String(tags.compliance).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (p2) {
          if (!KNOWN_POSTURES[p2]) {
            findings.push({
              kind: "catalog", file: rel, primitive: primTag,
              msg: "@compliance value `" + p2 + "` not in posture catalog",
            });
          }
        });
      }

      // 7b. @spec — the normative reference(s) the primitive is derived from.
      //     Validated so a citation can't be free text; required on every
      //     primitive when config.requireSpec is set (a primitive with no
      //     named source is undocumented or unmoored from a standard).
      if (tags.spec) {
        String(tags.spec).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (ref) {
          if (!_isValidSpecRef(ref)) {
            findings.push({
              kind: "catalog", file: rel, primitive: primTag,
              msg: "@spec `" + ref + "` is not a recognized normative reference (FIPS / SP 800 / RFC / X.NNN / ISO/IEC / SEC / ANSI X9 / W3C / IEC / PKCS# / CA/Browser Forum / semver / internal)",
            });
          }
        });
      } else if (config.requireSpec) {
        findings.push({
          kind: "schema", file: rel, primitive: primTag,
          msg: "missing @spec — every primitive must name the normative reference it builds off of (or `@spec internal (design: ...)` for genuine infrastructure)",
        });
      }

      // 7c. @defends — the attack class / CVE / CWE the primitive guards.
      if (tags.defends) {
        String(tags.defends).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (ref) {
          if (!_isValidDefendsRef(ref)) {
            findings.push({
              kind: "catalog", file: rel, primitive: primTag,
              msg: "@defends `" + ref + "` must be a CVE-YYYY-N, CWE-N, or a named class optionally suffixed with `(CVE-.../CWE-...)`",
            });
          }
        });
      }

      // 8. @related resolution.
      if (tags.related) {
        String(tags.related).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (refSig) {
          var bare = _bare(refSig);
          if (known[bare]) return;                     // function-level ref resolved
          var refNs = bare.split(".")[0];
          var nsHasAnyDocs = Object.keys(known).some(function (k) { return k.split(".")[0] === refNs; });
          if (nsHasAnyDocs && bare === refNs) return;  // bare-namespace ref to a documented namespace
          if (nsHasAnyDocs) {
            findings.push({
              kind: "cross-ref", file: rel, primitive: primTag,
              msg: "@related `" + refSig + "` — namespace `pki." + refNs + "` is documented but this member isn't there (drift?)",
            });
          }
          // else: forward reference to a not-yet-documented namespace — allowed.
        });
      }

      // 9. @primitive namespace must sit under the file's @module (case-sensitive —
      // a primitive is used at its exact, case-correct export path).
      if (modNs) {
        var primBare = _bare(primTag);
        if (primBare !== modNs && primBare.indexOf(modNs + ".") !== 0) {
          findings.push({
            kind: "schema", file: rel, primitive: primTag,
            msg: "@primitive namespace `" + primBare + "` does not match the file's @module `" + modNs + "`",
          });
        }
      }

      // 10. Signature / code arity match (skips when no plain-function
      //     declaration matches the primitive's last segment — namespace
      //     objects and constructors report -1).
      if (tags.signature && source) {
        var fnName = _bare(primTag).split(".").pop();
        var declaredArity = _functionArity(source, fnName);
        var sigArity = _signatureArity(tags.signature);
        if (declaredArity !== -1 && declaredArity !== sigArity) {
          findings.push({
            kind: "code-mismatch", file: rel, primitive: primTag,
            msg: "@signature shows " + sigArity + " arg(s) but `function " + fnName + "(...)` declares " + declaredArity + " — keep the comment in sync with the code",
          });
        }
      }

      // 11. @example syntax + placeholder detectors.
      if (Array.isArray(tags.examples)) {
        tags.examples.forEach(function (ex, i) {
          var err = _parseCheckExample(ex);
          if (err) {
            findings.push({
              kind: "example-syntax", file: rel, primitive: primTag,
              msg: "@example #" + (i + 1) + " fails to parse as JavaScript: " + err,
            });
          }
          EXAMPLE_PLACEHOLDERS.forEach(function (det) {
            if (det.re.test(ex)) {
              findings.push({
                kind: "example-placeholder", file: rel, primitive: primTag,
                msg: "@example #" + (i + 1) + " contains `" + det.id + "` placeholder — " + det.hint,
              });
            }
          });
        });
      }

      // 12. @primitive first segment agrees with @signature namespace root
      //     when the signature uses the `pki.` call form. Constructor and
      //     terse-alias forms (`new PkiError`, `C.TIME.days`) are exempt.
      if (tags.signature && ROOT_RE.test(tags.signature)) {
        var sigRoot = _firstSegment(tags.signature);
        var primRoot = _firstSegment(primTag);
        if (sigRoot && primRoot && sigRoot !== primRoot) {
          findings.push({
            kind: "schema", file: rel, primitive: primTag,
            msg: "@signature namespace `pki." + sigRoot + "` does not match @primitive namespace `pki." + primRoot + "`",
          });
        }
      }
    });

    // ---- Pass: @module metadata completeness ----
    if (rec.module && rec.primitives.length > 0) {
      var modTags = rec.module.tags || {};
      if (!modTags.nav) {
        findings.push({
          kind: "metadata", file: rel, primitive: "@module pki." + modNs,
          msg: "@module block lacks @nav — namespace will land in the catch-all 'Other' sidebar group. Add `@nav <GroupName>`.",
        });
      }
      if (!modTags.card) {
        findings.push({
          kind: "metadata", file: rel, primitive: "@module pki." + modNs,
          msg: "@module block lacks @card — namespace won't render a card on the home page. Add a `@card` block with a 1-2 sentence description.",
        });
      }
      if (!modTags.title) {
        findings.push({
          kind: "metadata", file: rel, primitive: "@module pki." + modNs,
          msg: "@module block lacks @title — sidebar label defaults to `pki." + modNs + "`. Add `@title <Display Name>`.",
        });
      }
    }
  });

  return findings;
}

module.exports = {
  validate:             validate,
  KNOWN_STATUSES:       KNOWN_STATUSES,
  KNOWN_POSTURES:       KNOWN_POSTURES,
  EXAMPLE_PLACEHOLDERS: EXAMPLE_PLACEHOLDERS,
  isValidSpecRef:       _isValidSpecRef,
  isValidDefendsRef:    _isValidDefendsRef,
};
