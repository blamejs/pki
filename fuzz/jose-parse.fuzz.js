// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.jose.parseJson + pki.jose.base64url.decode + the JWS profile walk
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = async function (data). The contract for these
 * hostile-input codecs: each call either succeeds or throws a pki.errors.PkiError
 * (JoseError) -- any other throw (a bare RangeError from the recursive-descent
 * reader, a TypeError, a hang) is a finding and is rethrown so the fuzzer records
 * a reproducer. Exercises the RFC 8555 sec. 6.1 strict base64url decode (padding /
 * alphabet / non-canonical rejection), the bounded duplicate-key-rejecting JSON
 * reader (size + depth caps, UTF-8 validity), and -- when the bytes parse into a
 * JWS-shaped object -- the RFC 7515 profile walk in verify BEFORE any crypto call.
 */
var pki = require("..");

module.exports.fuzz = async function (data) {
  var s = data.toString("latin1");

  // The strict JSON reader on the raw hostile bytes.
  var parsed;
  try { parsed = pki.jose.parseJson(data); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }

  // The strict base64url decoder on a fuzz-derived candidate string.
  try { pki.jose.base64url.decode(s.slice(0, 512)); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }

  // If the bytes parsed into an object, drive the surfaces that consume one: the
  // thumbprint member walk and the JWS verify profile logic (the crypto step fails
  // on a junk key, but the header/alg/nonce/url/crit walk runs first).
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    try { await pki.jose.thumbprint(parsed); }
    catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
    try { await pki.jose.verify(parsed, { profile: "acme-outer", key: { kty: "oct", k: "AAAAAAAAAAAAAAAAAAAAAA" } }); }
    catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
  }
};
