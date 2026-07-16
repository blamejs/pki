// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.cms.decompress (CMS CompressedData, RFC 3274).
 *
 * libFuzzer / jazzer.js harness. decompress parses a CMS ContentInfo over the strict pki.schema.cms
 * codec, gates version 0 + id-alg-zlibCompress + absent-or-NULL params, and BOUNDED-inflates the
 * RFC 1950 eContent -- every byte of which (the compressionAlgorithm, the eContentType, and the
 * attacker-controlled ZLIB stream) drives the parse + inflate path. The maxOutputLength cap guarantees
 * a malicious deflate cannot OOM the harness: a decompression bomb is a caught cms/decompress-too-large,
 * not a hang. No key material is needed -- the whole message is the attack surface.
 *
 * Contract: decompressing attacker-controlled bytes has exactly two acceptable outcomes -- a resolved
 * result, or a thrown/rejected `pki.errors.PkiError` (CmsError / Asn1Error / OidError / PemError). Any
 * other throw (RangeError, a bare TypeError, a stack overflow, an OOM, a hang) is an unguarded invariant
 * break -- rethrow so jazzer records the reproducer.
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var buf = Buffer.from(data);
  try {
    await pki.cms.decompress(buf);
  } catch (e) { if (!isPki(e)) throw e; }
};
