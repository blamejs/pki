// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Shared runtime for @example execution.
 *
 * The comment-block validator only PARSE-checks each @example (it compiles the
 * body and never runs it), so an example can compile and still be semantically
 * dead: a renamed primitive, a removed option, an argument shape the code no
 * longer accepts. Those examples are not decoration -- they are generated onto
 * the wiki page for the primitive, so an operator copies them. This runtime is
 * the half that actually EXECUTES them.
 *
 * ---------------------------------------------------------------------------
 * Why this differs from the same gate in the blamejs framework, deliberately.
 *
 * That one skips any example matching a broad stateful/IO pattern -- including
 * `generateKey`, `.sign(`, `keypair`. In a web framework those start daemons and
 * touch a shared database. In a PKI toolkit they are the ENTIRE SUBJECT: copying
 * that skip list here would skip most of what needs checking and leave the gate
 * reporting a large, comfortable "skipped" number.
 *
 * The skip set below was derived by surveying this library's own corpus rather
 * than inherited: of 216 @examples, ZERO touch the filesystem and ZERO call
 * require(). The only genuinely unsafe thing an example here can do is reach the
 * network, which is why that is all this skips.
 * ---------------------------------------------------------------------------
 */

var path = require("path");

var ROOT = path.resolve(__dirname, "..", "..");
var pki  = require(ROOT);

// An example that would perform NETWORK I/O is not executed. These are the
// protocol client verbs -- they take a live directory / CA endpoint, and running
// one would either hang the suite or, worse, reach a real host from a test.
//
// Matched on the CALL, not the namespace: `pki.acme.keyAuthorization(...)` is a
// pure function that happens to live in a networked namespace, and skipping it
// because of its prefix would hide exactly the drift this gate exists to catch.
//
// Two patterns were deliberately NOT kept, because each skipped only pure
// functions and no networking one:
//   - a bare `.request(` matched `pki.tsp.request` -- a DER builder, not a client.
//   - a `https?://` URL literal matched `pki.est.paths` / `pki.cmp.wellKnownUrl`,
//     which BUILD urls and never dial them. A URL in an example is a string, so
//     it says nothing about whether the example performs I/O.
// Anything that does reach the network despite this list still cannot corrupt the
// run: classify() maps a connection failure to a "needs network" skip and the
// per-example timeout bounds a hang.
var NETWORK_CALL = new RegExp([
  "\\.transfer\\s*\\(", "\\.session\\s*\\(", "\\.newAccount\\s*\\(", "\\.newOrder\\s*\\(",
  "\\.newAuthz\\s*\\(", "\\.newNonce\\s*\\(", "\\.postAsGet\\s*\\(", "\\.finalize\\s*\\(",
  "\\.enroll\\s*\\(", "\\.cacerts\\s*\\(", "\\.simpleenroll\\s*\\(", "\\.simplereenroll\\s*\\(",
  "\\.serverkeygen\\s*\\(", "\\.csrattrs\\s*\\(", "\\.fullcmc\\s*\\(",
  "\\.fetch\\w*\\s*\\(", "\\.directory\\s*\\(", "pki\\.transport\\.",
].join("|"), "i");

// The builtins an example may reach. Nothing here can escape the process or
// touch the tree; anything else classifies as illustrative.
var SAFE_BUILTINS = {
  crypto: 1, "node:crypto": 1, path: 1, "node:path": 1, buffer: 1, "node:buffer": 1,
  util: 1, "node:util": 1, url: 1, "node:url": 1, assert: 1, "node:assert": 1,
  zlib: 1, "node:zlib": 1,
};

// require() as an example sees it: the package alias yields a FRESH object --
// never the live export, so an example that writes to it cannot mutate the real
// surface, and with no extra members, so an example calling something the
// shipped export does not have MUST fail. That drift is the whole point.
function exampleRequire(name) {
  if (name === "@blamejs/pki" || name === "pki") return Object.assign({}, pki);
  if (Object.prototype.hasOwnProperty.call(SAFE_BUILTINS, name)) return require(name);
  var e = new Error("example references external module " + JSON.stringify(name));
  e.code = "EXAMPLE_EXTERNAL_MODULE";
  throw e;
}

// An example may DECLARE the environment it assumes, as its first line:
//   // requires: a reachable ACME directory
// Such an example is not executed -- it describes a call against something that
// already exists rather than something it sets up.
//
// This marker lives in the DOCUMENTATION, not in an allowlist inside this file,
// and that is the point: it renders on the primitive's wiki page, so the operator
// reads the prerequisite too, and hiding a broken example behind it costs
// something visible. A silent skip list in here would cost nothing and mean
// nothing.
var DECLARES_PREREQUISITE = /^\s*\/\/\s*requires:/;
function declaresPrerequisite(body) {
  return DECLARES_PREREQUISITE.test(_firstLine(body));
}

// An example may also DECLARE that it demonstrates a REJECTION, as its first line:
//   // throws: shbs/bad-public-key -- an Ed25519 key is not an HSS public key
// Only such an example may end in a typed PkiError.
//
// Without this the gate has a hole big enough to drive the drift through: the
// library reports a wrong argument shape or a removed option as a typed
// PkiError, so treating every PkiError as an acceptable "fail-closed demo"
// silently passes exactly the broken documented calls this gate exists to catch.
// (Three real defects hid there while it did -- a `pem` option on the wrong
// argument, and two examples built on inputs the primitive does not accept.)
// Requiring the declaration in the DOCUMENTATION rather than an allowlist here
// keeps the cost visible: it renders on the primitive's wiki page, so the reader
// is told the call is expected to be refused.
// The marker MUST name the expected code, and the code is compared against the
// error actually raised. Accepting any PkiError from a `// throws:` example would
// reopen the hole one notch down: a call that regressed from its documented
// rejection into an unrelated argument or parse error would still pass.
var DECLARES_THROW = /^\s*\/\/\s*throws:\s*(\S*)/;
function declaresThrow(body) {
  return DECLARES_THROW.test(_firstLine(body));
}
// The declared code, or "" when the marker is present but names none (which is
// itself a finding -- see classify).
function declaredThrowCode(body) {
  var m = DECLARES_THROW.exec(_firstLine(body));
  return m ? m[1] : null;
}

function _firstLine(body) {
  return String(body || "").split("\n").find(function (l) { return l.trim() !== ""; }) || "";
}

// A throw is a DEFECT only when it says the documented API is wrong -- a renamed
// primitive, a removed export, an argument shape no longer accepted. Everything
// else an example can hit is illustrative, and counting it as a failure would
// make the gate unrunnable rather than strict.
function classify(e, opts) {
  opts = opts || {};
  var name = e && e.name;
  // An undefined identifier means the example is a FRAGMENT: an operator copying
  // it off the wiki page gets this same ReferenceError on the first line. That is
  // a documentation defect, so it fails.
  //
  // It was a skip while the corpus still held ~144 of them; every remaining case
  // where the input genuinely comes from outside (a browser's attestationObject,
  // FIDO's signed BLOB, a cosign bundle) now says so with a `// requires:` line,
  // which names the input on the rendered page. Leaving this as a skip would put
  // the next accidental fragment straight back into a silent bucket.
  if (name === "ReferenceError") {
    return {
      outcome: "fail",
      error: String(e.message || "ReferenceError") + " -- the example is not self-contained. Construct the " +
        "value from the library, or, if it can only come from outside (a browser, a CA, a signed feed), " +
        "declare it with a leading `// requires: <what> -- <where it comes from>` line.",
    };
  }
  if (e && e.code === "EXAMPLE_EXTERNAL_MODULE") return { outcome: "skip", reason: "external module" };
  if (e && /timed out/i.test(String(e.message || ""))) return { outcome: "skip", reason: "timeout" };
  // A typed PkiError is only acceptable from an example that DECLARED it throws
  // (the `// throws:` marker). Such an example ran to its documented conclusion,
  // so it counts as RAN, not as a skip -- it is covered, not excused.
  //
  // Any OTHER typed PkiError is a DEFECT and falls through to "fail" below: the
  // library raises one for a wrong argument shape or a removed option, which is
  // precisely the drift this gate exists to catch. The error code is carried into
  // the failure so the fix is obvious from the log.
  if (e && e.isPkiError) {
    var want = opts.declaredThrowCode;
    if (want) {
      if (e.code === want) return { outcome: "ran" };
      return {
        outcome: "fail",
        error: "declares `// throws: " + want + "` but raised " + (e.code || "an uncoded PkiError") +
          " (" + (e.message || "") + "). The documented rejection changed, or the example drifted onto a different one.",
      };
    }
    if (want === "") {
      return { outcome: "fail", error: "the `// throws:` marker must name the expected error code, e.g. `// throws: shbs/bad-public-key -- why`" };
    }
    return {
      outcome: "fail",
      error: "threw " + (e.code || "a typed PkiError") + " (" + (e.message || "") + "). If the example is " +
        "MEANT to demonstrate a rejection, declare it with a leading `// throws: <code> -- <why>` line.",
    };
  }
  if (e && /^E[A-Z]+$/.test(String(e.code || ""))) return { outcome: "skip", reason: "filesystem/OS error" };
  if (e && /fetch failed|ENOTFOUND|ECONNREFUSED/i.test(String(e.message || ""))) {
    return { outcome: "skip", reason: "needs network" };
  }
  return { outcome: "fail", error: (e && (e.stack || e.message)) || String(e) };
}

/**
 * runExample(body, opts) -- compile and await one @example.
 *
 * Runs in THIS realm rather than a vm context, on purpose. A vm context has its
 * own intrinsics, so a `new Date(...)`, a RegExp literal or an Array written
 * inside an example is not an instance of the library's Date/RegExp/Array, and
 * every `instanceof` the library performs on caller input fails -- the example is
 * then reported broken when it is the harness that is wrong. This library does
 * exactly that kind of check (`entry.revocationDate instanceof Date`), and the
 * examples are the repo's OWN checked-in comment blocks rather than untrusted
 * input, so the vm buys nothing and costs that.
 */
async function runExample(body, opts) {
  opts = opts || {};
  if (declaresPrerequisite(body)) return { outcome: "skip", reason: "declares a prerequisite" };
  if (NETWORK_CALL.test(body)) return { outcome: "skip", reason: "network call (not executed)" };
  var timeoutMs = opts.timeoutMs || 20000;
  var wrapped = "(async function () {\n" + body + "\n})();";
  try {
    await new Promise(function (resolve, reject) {
      var settled = false;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        reject(new Error("example timed out after " + timeoutMs + "ms"));
      }, timeoutMs);
      // Deliberately NOT unref'd. An example that returns a promise which never
      // settles and holds no referenced handle would otherwise let Node exit
      // cleanly while run() is still awaiting it -- the remaining examples and
      // every gate assertion would be skipped and the process would still exit 0.
      // The timer is cleared on both settle paths below, so it never outlives the
      // example it bounds.
      Promise.resolve()
        .then(function () {
          // The compiled string is an @example body read out of this repo's own
          // lib/ comment blocks -- it is the code under test, not input. There is
          // no untrusted value interpolated and no path by which one could be:
          // the parser's only source is the checked-in tree.
          var fn = new Function("pki", "require", "console", "\"use strict\";\nreturn " + wrapped);
          var quiet = function () {};
          return fn(Object.assign({}, pki), exampleRequire,
            { log: quiet, error: quiet, warn: quiet, info: quiet, debug: quiet });
        })
        .then(function (v) { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } },
          function (e) { if (!settled) { settled = true; clearTimeout(timer); reject(e); } });
    });
    return { outcome: "ran" };
  } catch (e) { return classify(e, { declaredThrowCode: declaredThrowCode(body) }); }
}

module.exports = {
  ROOT: ROOT,
  pki: pki,
  NETWORK_CALL: NETWORK_CALL,
  classify: classify,
  declaresPrerequisite: declaresPrerequisite,
  declaresThrow: declaresThrow,
  declaredThrowCode: declaredThrowCode,
  runExample: runExample,
};
