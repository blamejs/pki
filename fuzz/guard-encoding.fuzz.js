// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the strict textual-encoding decoders (lib/guard-encoding), the
 * bounded text decode (lib/guard-text), and the canonical dotted-OID assert
 * (lib/guard-identifier), driven directly.
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The first input byte selects the arm;
 * the rest is the hostile text (latin1, so the fuzzer controls every char
 * 0..255 exactly).
 *
 * Contracts per arm:
 * - Throw contract everywhere: success or a pki.errors.PkiError; anything else
 *   is a finding.
 * - base64url / base64 two-sided canonicality oracle: on ACCEPT, the canonical
 *   re-encode of the decoded bytes must equal the input (RFC 4648 unique
 *   encoding); on REJECT, the input must NOT be its own canonical re-encode
 *   (a rejected canonical text is a false reject). Either violation is thrown
 *   as a plain Error so the fuzzer records a reproducer.
 * - hex accept oracle: an independent per-pair parseInt decode must agree with
 *   the guard's bytes (hex is case-tolerant, so only the accept side binds).
 * - OID consistency oracle: a string the guard accepts (bounds enforced) must
 *   be encodable by pki.asn1.encodeOidContent (which composes the same guard;
 *   only the sub-identifier byte cap may still reject, typed) and must
 *   round-trip decodeOidContent(encodeOidContent(text)) === text; a string the
 *   guard rejects must NOT encode successfully.
 */
var pki = require("..");
var encoding = require("../lib/guard-encoding");
var text = require("../lib/guard-text");
var identifier = require("../lib/guard-identifier");

var JoseError = pki.errors.JoseError;
var OidError = pki.errors.OidError;
function joseErr(c, m) { return new JoseError(c, m); }
function oidErr(c, m) { return new OidError(c, m); }

function pkiCodeOf(fn) {
  try { return { value: fn(), threw: false }; }
  catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
    return { threw: true, code: e.code };
  }
}

module.exports.fuzz = function (data) {
  if (data.length === 0) return;
  var arm = data[0] % 5;
  var payload = data.subarray(1);
  var s = payload.toString("latin1");

  if (arm === 0 || arm === 1) {
    var enc = arm === 0 ? "base64url" : "base64";
    var fn = arm === 0 ? encoding.base64url : encoding.base64;
    var r = pkiCodeOf(function () { return fn(s, null, joseErr, "jose/bad-base64url", "fuzz text"); });
    var canonical = Buffer.from(s, enc).toString(enc) === s;
    if (!r.threw && !canonical) throw new Error("guard-encoding." + enc + " accepted a non-canonical text");
    if (r.threw && canonical) throw new Error("guard-encoding." + enc + " rejected a canonical text (" + r.code + ")");
    return;
  }

  if (arm === 2) {
    var h = pkiCodeOf(function () { return encoding.hex(s, null, joseErr, "jose/bad-input", "fuzz hex"); });
    if (!h.threw) {
      var ref = Buffer.alloc(s.length / 2);
      for (var i = 0; i < ref.length; i++) ref[i] = parseInt(s.substr(i * 2, 2), 16);
      if (!h.value.equals(ref)) throw new Error("guard-encoding.hex bytes diverge from an independent decode");
    }
    return;
  }

  if (arm === 3) {
    // Bounded fatal-UTF-8 decode over the raw payload bytes (contract only: the
    // TextDecoder BOM strip makes a byte round-trip oracle unsound).
    pkiCodeOf(function () {
      return text.decode(payload, 1 << 16, JoseError, {
        charset: "utf-8", fatal: true,
        tooLarge: "jose/too-large", badDecode: "jose/bad-json", badInput: "jose/bad-input", label: "fuzz text",
      });
    });
    return;
  }

  // arm 4: canonical dotted-decimal OID (bounds enforced) + the encoder oracle.
  var o = pkiCodeOf(function () { return identifier.assertCanonicalOid(s, oidErr, "oid/bad-input", "fuzz OID", "oid/bad-arc"); });
  var e = pkiCodeOf(function () { return pki.asn1.encodeOidContent(s); });
  if (!o.threw) {
    if (e.threw && e.code !== "oid/subidentifier-too-large") {
      throw new Error("encodeOidContent rejected a guard-accepted OID (" + e.code + ")");
    }
    if (!e.threw && pki.asn1.decodeOidContent(e.value) !== s) {
      throw new Error("guard-accepted OID does not round-trip through the DER codec");
    }
  } else if (!e.threw) {
    throw new Error("encodeOidContent accepted a guard-rejected OID");
  }
};
