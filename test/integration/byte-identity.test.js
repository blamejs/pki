// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- registry-driven DER byte-identity, fully auto-derived.
 *
 * NOTHING here is a per-format list. The format set is the schema registry
 * (`pki.schema.all()`); the samples are the per-format seed corpora every parser
 * already ships (the build recipe mandates `fuzz/<x>-parse_seed_corpus/`); and the
 * independent oracle is `openssl asn1parse`, which decodes ANY DER, so no
 * per-format OpenSSL recipe is needed. A new `schema-<x>.js` -- which must ship a
 * seed corpus -- is picked up here automatically, with zero edits to this file.
 *
 * For every canonical sample (one the strict decoder accepts) the toolkit must
 * reproduce the exact bytes from a decode -> structural re-encode that rebuilds
 * each TLV purely from its DECODED components (tag class, constructed flag, tag
 * number, content/children), discarding the raw slice the decoder retained -- so
 * equality proves the toolkit's DER encoder (identifier + minimal length octets +
 * nesting) is byte-exact. The same bytes must then be accepted by OpenSSL's
 * independent ASN.1 parser. The corpora are real-world artifacts (many produced by
 * OpenSSL / NSS), so this doubles as cross-implementation agreement without wiring
 * a generator command per format. A malformed / negative fuzz seed (one the strict
 * decoder rejects) is not a canonical sample and is skipped.
 *
 * Runs under scripts/test-integration.js (each integration file as its own
 * process); the service-check gate confirms `openssl` before any file runs.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var ctx     = require("./_interop-ctx");

var pki  = ctx.pki;
var A    = pki.asn1;
var path = ctx.path;

var FUZZ_DIR = path.join(__dirname, "..", "..", "fuzz");

// The raw class bits the low-level TLV encoder expects, keyed by the decoder's
// symbolic tag class. Rebuilding from these (rather than the retained bytes) is
// what makes the round-trip a real encoder check.
var CLASS_BITS = { universal: 0x00, application: 0x40, context: 0x80, private: 0xc0 };

function reencode(node) {
  var content = node.constructed
    ? Buffer.concat((node.children || []).map(reencode))
    : node.content;
  return A.encode(CLASS_BITS[node.tagClass], node.constructed, node.tagNumber, content);
}

// Resolve a registry format key to its co-located seed corpus. The corpus is named
// for the fuzz target (`<x>-parse`); the compound OCSP request/response and the
// attribute-cert v1/v2 keys share one parser and one corpus, so strip those
// suffixes before matching. Returns null when no corpus is on disk.
function corpusDir(key) {
  var base = key.replace(/-request$|-response$/, "").replace(/-v1$/, "");
  var candidates = [key + "-parse", base + "-parse", key, base];
  for (var i = 0; i < candidates.length; i++) {
    var dir = path.join(FUZZ_DIR, candidates[i] + "_seed_corpus");
    try { if (ctx.fs.statSync(dir).isDirectory()) return dir; } catch (_e) { /* try next */ }
  }
  return null;
}

function run() {
  var formats = pki.schema.all();
  check("byte-identity: formats discovered from the schema registry", formats.length > 0);

  var samples = 0, identical = 0, oracleOk = 0, negatives = 0;
  formats.forEach(function (key) {
    var dir = corpusDir(key);
    // Every registered parser ships a seed corpus, so a missing one is a real gap
    // (a build-recipe violation), not a skip -- fail loudly rather than under-cover.
    check("byte-identity: " + key + " -- ships a seed corpus to sample from", !!dir);
    if (!dir) return;

    var decoded = 0, ident = 0, ok = 0;
    ctx.fs.readdirSync(dir).forEach(function (name) {
      var fp = path.join(dir, name), der, node;
      try { der = ctx.fs.readFileSync(fp); node = A.decode(der); }
      catch (e) {
        // A negative / malformed fuzz seed (or a non-file entry) is not a canonical
        // sample; record why it was set aside rather than silently dropping it.
        negatives += 1;
        if (e && e.code) helpers.skip("byte-identity: " + key + "/" + name + " is a non-canonical seed (" + e.code + ")");
        return;
      }
      decoded += 1;
      if (reencode(node).equals(der)) ident += 1;
      var r = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", fp], { allowNonZero: true });
      if (r.code === 0) ok += 1;
    });

    // Every canonical sample must round-trip byte-identically (the strict decoder
    // only accepts canonical DER, so a mismatch means an encoder or framing bug)
    // AND be accepted by OpenSSL's independent parser (structural interop).
    check("byte-identity: " + key + " -- every canonical sample re-encodes byte-identically (" + ident + "/" + decoded + ")",
      decoded > 0 && ident === decoded);
    check("byte-identity: " + key + " -- openssl asn1parse accepts every canonical sample (" + ok + "/" + decoded + ")",
      decoded > 0 && ok === decoded);
    samples += decoded; identical += ident; oracleOk += ok;
  });

  console.log("[byte-identity] " + formats.length + " registry format(s); " + samples +
    " canonical seed sample(s) (" + negatives + " non-canonical seed(s) set aside); " + identical +
    " re-encoded byte-identically; " + oracleOk + " accepted by openssl asn1parse");
  check("byte-identity: all canonical samples are byte-identical and openssl-accepted",
    samples > 0 && identical === samples && oracleOk === samples);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); console.log("SKIPS " + helpers.getSkips()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
