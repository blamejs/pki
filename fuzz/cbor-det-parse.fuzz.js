// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.cbor.decode + the read.* leaf readers
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: decoding hostile bytes
 * either succeeds or throws a pki.errors.PkiError -- any other throw (or a
 * hang) is a finding and is rethrown so the fuzzer records a reproducer. This
 * target exercises the RFC 8949 sec. 4.2 core-deterministic decode (the head
 * well-formedness + minimal-argument checks, the map ordering / uniqueness
 * verify, the shortest-float rule, the strict-UTF-8 gate, the size / depth /
 * bignum caps) in both whole-buffer and CBOR-Sequence (allowTrailing) modes,
 * and walks each decoded node through its type-appropriate reader so the
 * tagged-value paths (biguint / time / oid) are fuzzed too.
 */
var pki = require("..");

function walk(node) {
  var r = pki.cbor.read;
  switch (node.majorType) {
    case 0: r.uint(node); r.int(node); break;
    case 1: r.nint(node); r.int(node); break;
    case 2: r.byteString(node); break;
    case 3: r.textString(node); break;
    case 4: r.array(node).forEach(walk); break;
    case 5: r.map(node).forEach(function (p) { walk(p[0]); walk(p[1]); }); break;
    case 6:
      if (node.argument === 2n) r.biguint(node);
      else if (node.argument === 1n) r.time(node);
      else if (node.argument === 111n) r.oid(node);
      if (node.children) walk(node.children[0]);
      break;
    case 7:
      if (node.ai === 20 || node.ai === 21) r.boolean(node);
      else if (node.ai === 22) r.nullValue(node);
      else if (node.ai === 23) r.undefinedValue(node);
      else if (node.ai >= 25) r.float(node);
      break;
    default: break;
  }
}

function drive(data, opts) {
  try {
    walk(pki.cbor.decode(data, opts));
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
}

module.exports.fuzz = function (data) {
  drive(data, undefined);                    // strict: whole-buffer consumption
  drive(data, { allowTrailing: true });      // CBOR-Sequence: decode the first item
};
