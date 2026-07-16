// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.smime
 * @nav        Messaging
 * @title      S/MIME
 * @order      175
 * @slug       smime
 *
 * @intro
 *   RFC 8551 S/MIME assembly + verification over the shipped CMS layer.
 *   `sign` wraps a MIME entity as a signed S/MIME message and `verify` unwraps
 *   and verifies one, in both forms: `multipart/signed` (clear-signed -- the
 *   content stays readable, a detached CMS signature rides alongside) and
 *   `application/pkcs7-mime` (opaque -- the whole entity is a base64 CMS
 *   SignedData). The crypto is entirely `pki.cms.sign` / `pki.cms.verify`; the
 *   new work is the MIME frame and the RFC 8551 sec. 3.1.1 canonicalization the
 *   detached signature is computed over -- signer and verifier share one
 *   canonicalizer (`lib/mime.js`) so their digests cannot diverge. Like
 *   `cms.verify`, `verify` returns the per-signer cryptographic verdict; chaining
 *   a signer to a trust anchor is the caller's `pki.path.validate` step.
 *
 * @card
 *   Assemble + verify RFC 8551 S/MIME signed messages (multipart/signed +
 *   application/pkcs7-mime) over any CMS signer -- shared canonicalization,
 *   fail-closed, algorithm-agnostic.
 */

var frameworkError = require("./framework-error.js");
var mime = require("./mime.js");
var cms = require("./cms-verify.js");
var schemaCms = require("./schema-cms.js");
var guard = require("./guard-all.js");
var C = require("./constants.js");
var nodeCrypto = require("crypto");

var SmimeError = frameworkError.SmimeError;

function _err(code, msg, cause) { return new SmimeError(code, msg, cause); }

// RFC 8551 uses application/pkcs7-<kind>; OpenSSL's legacy `smime` command emits the PKCS#7
// application/x-pkcs7-<kind>. Accept both on the RECEIVE side (we always EMIT the RFC 8551 form).
function _isPkcs7(type, kind) {
  var t = (type || "").toLowerCase();
  return t === "application/pkcs7-" + kind || t === "application/x-pkcs7-" + kind;
}

// The RFC 8551 sec. 3.4.3.2 micalg name for a CMS digest (schema-cms surfaces "sha256" etc.).
var MICALG = { sha1: "sha-1", sha256: "sha-256", sha384: "sha-384", sha512: "sha-512", md5: "md5" };

// The exact bytes to sign: the caller's content wrapped as a MIME entity (text/plain by default) in
// its canonical form, OR -- when opts.entity is set -- the caller's own complete MIME entity, canonical.
function _entityBytes(content, opts) {
  var raw = guard.bytes.view(content, SmimeError, "smime/bad-input", "content");
  if (opts.entity) return mime.canonicalize(raw, SmimeError, "smime/bad-mime");
  var ct = opts.contentType || "text/plain; charset=utf-8";
  var head = Buffer.from("Content-Type: " + ct + "\r\nContent-Transfer-Encoding: 7bit\r\n\r\n", "latin1");
  return mime.canonicalize(Buffer.concat([head, raw]), SmimeError, "smime/bad-mime");
}

// Map smime opts to cms.sign opts (the S/MIME layer is algorithm-agnostic -- it forwards any signer).
function _cmsSignOpts(opts, detached) {
  var o = { detached: detached };
  if (opts.signingTime !== undefined) o.signingTime = opts.signingTime;
  if (opts.sid) o.sid = opts.sid;
  if (opts.signedAttributes !== undefined) o.signedAttributes = opts.signedAttributes;
  if (opts.additionalSignedAttributes) o.additionalSignedAttributes = opts.additionalSignedAttributes;
  return o;
}

// Coverage residual: the defensive `|| default` fallbacks in the helpers below (a null media type, a
// non-standard SignerInfo digest name -> a derived micalg, an absent micalg -> "sha-256"/null, a
// non-Buffer cms.sign result) and the two catch arms (a CMS body that passed cms.verify yet fails a
// second schema-cms.parse) are belt-and-braces around the primary path the round-trips exercise; the
// producer never emits any of them.
function _micName(name) { return MICALG[name] || (name ? name.replace(/^sha/, "sha-") : null); }
// Normalize a micalg header value into the same sorted-distinct comma-joined form _micalgOf emits.
function _micalgSet(value) {
  var seen = [];
  String(value).split(",").forEach(function (m) { var t = m.trim().toLowerCase(); if (t && seen.indexOf(t) < 0) seen.push(t); });
  return seen.sort().join(",");
}
// The micalg for the SignedData -- RFC 8551 sec. 3.4.3.2: EVERY signer's message-digest algorithm,
// distinct, sorted, comma-separated (a multi-signer message with mixed digests lists them all).
function _micalgOf(p7Der) {
  var parsed;
  try { parsed = schemaCms.parse(guard.bytes.view(p7Der, SmimeError, "smime/bad-mime", "the CMS body")); }
  catch (e) { throw _err("smime/bad-mime", "the CMS SignedData body could not be parsed", e); }
  var out = [];
  (parsed.signerInfos || []).forEach(function (si) {
    var mic = _micName(si.digestAlgorithm && si.digestAlgorithm.name);
    if (mic && out.indexOf(mic) < 0) out.push(mic);
  });
  return out.length ? out.sort().join(",") : null;
}

// A fresh multipart boundary that cannot collide with the content (random, dashed, unique per call).
function _boundary() { return "----=_pki_smime_" + nodeCrypto.randomBytes(18).toString("hex"); }

function _base64Body(der) {
  return Buffer.from(der.toString("base64").replace(/(.{64})/g, "$1\r\n").replace(/\r\n$/, ""), "latin1");
}

/**
 * @primitive  pki.smime.sign
 * @signature  pki.smime.sign(content, signers, opts?) -> Promise<Buffer>
 * @since      0.2.25
 * @status     experimental
 * @spec       RFC 8551, RFC 5652
 * @related    pki.smime.verify, pki.cms.sign
 *
 * Assemble a signed S/MIME message (RFC 8551). `content` is the payload -- a raw body wrapped as a
 * `text/plain` entity by default, or the caller's own complete MIME entity when `opts.entity` is set;
 * `signers` is the `pki.cms.sign` signer array (any RSA / RSASSA-PSS / ECDSA / EdDSA / ML-DSA / SLH-DSA
 * signer -- the S/MIME layer is algorithm-agnostic). Two forms via `opts.form`:
 *   - `"multipart"` (default, clear-signed): a `multipart/signed` message carrying the canonical entity
 *     verbatim in the first part and a DETACHED CMS SignedData (`application/pkcs7-signature`) over its
 *     canonical form in the second, with `protocol="application/pkcs7-signature"` + a matching `micalg`.
 *   - `"pkcs7-mime"` (opaque): one `application/pkcs7-mime; smime-type=signed-data` entity whose base64
 *     body is an ATTACHED CMS SignedData over the canonical entity.
 * The signed bytes are the entity's RFC 8551 sec. 3.1.1 canonical form (CRLF line endings); the SAME
 * canonicalizer runs on verify. Returns the assembled message bytes. Fail-closed with `SmimeError`.
 *
 * @opts form        `"multipart"` (default) or `"pkcs7-mime"`.
 * @opts entity      treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType the wrapped entity's Content-Type (default `text/plain; charset=utf-8`).
 * @opts signingTime a `Date` for the CMS signing-time attribute, or false to omit it.
 * @example
 *   var msg = await pki.smime.sign(Buffer.from("hello"), [{ cert: signerCertDer, key: signerKeyPkcs8 }]);
 */
async function sign(content, signers, opts) {
  opts = opts || {};
  var entity = _entityBytes(content, opts);
  var form = opts.form || "multipart";
  if (form === "pkcs7-mime") {
    var p7m = await cms.sign(entity, signers, _cmsSignOpts(opts, false));
    var head = Buffer.from("Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7m\r\n\r\n", "latin1");
    return _capped(Buffer.concat([head, _base64Body(_toBuf(p7m)), mime.CRLF]));
  }
  if (form !== "multipart") throw _err("smime/bad-input", "form must be \"multipart\" or \"pkcs7-mime\"");
  var p7s = _toBuf(await cms.sign(entity, signers, _cmsSignOpts(opts, true)));
  var micalg = _micalgOf(p7s) || "sha-256";
  var boundary = _boundary();
  var head2 = Buffer.from("Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=" + micalg + "; boundary=\"" + boundary + "\"\r\n\r\n", "latin1");
  var sigPart = Buffer.concat([
    Buffer.from("Content-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7s\r\n\r\n", "latin1"),
    _base64Body(p7s),
  ]);
  var dl = Buffer.from("--" + boundary + "\r\n", "latin1"), close = Buffer.from("--" + boundary + "--\r\n", "latin1");
  return _capped(Buffer.concat([head2, dl, entity, mime.CRLF, dl, sigPart, mime.CRLF, close]));
}

// A produced message MUST stay within the same size ceiling verify enforces on receive, so sign never
// emits an S/MIME message our own verify would reject as too large (producer/consumer symmetry).
// Coverage residual: the throw only fires on a >16 MiB assembled message -- a real cap, exercised by no
// unit vector (driving it would sign 16 MiB).
function _capped(msg) {
  if (msg.length > C.LIMITS.MIME_MAX_BYTES) throw _err("smime/too-large", "the assembled S/MIME message (" + msg.length + " bytes) exceeds the " + C.LIMITS.MIME_MAX_BYTES + "-byte cap that verify enforces");
  return msg;
}

/**
 * @primitive  pki.smime.verify
 * @signature  pki.smime.verify(message, opts?) -> Promise<{ valid, signers, form, content, micalg }>
 * @since      0.2.25
 * @status     experimental
 * @spec       RFC 8551, RFC 5652
 * @related    pki.smime.sign, pki.cms.verify, pki.path.validate
 *
 * Unwrap and verify a signed S/MIME message (RFC 8551), both `multipart/signed` and
 * `application/pkcs7-mime; smime-type=signed-data`. For `multipart/signed` the detached CMS signature
 * is recomputed over the first part's RFC 8551 sec. 3.1.1 canonical form (the SAME canonicalizer the
 * signer used); for `application/pkcs7-mime` the base64 body is the attached CMS SignedData. Returns
 * `pki.cms.verify`'s `{ valid, signers }` verdict PLUS `form`, the recovered `content` (the signed MIME
 * entity bytes), and the `micalg`. Like `cms.verify`, this returns the cryptographic verdict only --
 * chaining a signer certificate to a trust anchor is the caller's `pki.path.validate` step. A `micalg`
 * that disagrees with the actual digest is advisory unless `opts.strictMicalg` (then `smime/micalg-mismatch`).
 *
 * @opts certs        extra signer certificates (DER `Buffer`s) to match, forwarded to `cms.verify`.
 * @opts strictMicalg reject a `multipart/signed` whose `micalg` disagrees with the SignerInfo digest.
 * @example
 *   var res = await pki.smime.verify(smimeMessageBytes);
 *   if (res.valid) { res.content; res.signers[0].sid; }
 */
async function verify(message, opts) {
  opts = opts || {};
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  var vOpts = {};
  if (opts.certs) vOpts.certs = opts.certs;
  if (_isPkcs7(ct.type, "mime")) {
    if (ct.params["smime-type"] && ct.params["smime-type"] !== "signed-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(ct.params["smime-type"]) + " (only signed-data)");
    var p7m = _decodeCms(ent);
    var res = await cms.verify(p7m, vOpts);
    var inner;
    try { inner = _toBuf(schemaCms.parse(p7m).encapContentInfo.eContent); }
    catch (e) { throw _err("smime/bad-mime", "the pkcs7-mime SignedData has no encapsulated content", e); }
    return { valid: res.valid, signers: res.signers, form: "pkcs7-mime", content: inner, micalg: null };
  }
  if (ct.type === "multipart/signed") {
    if (ct.params.protocol && !_isPkcs7(ct.params.protocol, "signature")) throw _err("smime/bad-multipart", "multipart/signed protocol must be application/pkcs7-signature");
    var parts = mime.splitMultipart(ent.body, ct.params.boundary, SmimeError, "smime/bad-multipart");
    if (parts.length !== 2) throw _err("smime/bad-multipart", "multipart/signed must have exactly two body parts, got " + parts.length);
    var sigEnt = mime.parse(parts[1], SmimeError, "smime/bad-mime");
    if (!_isPkcs7(sigEnt.contentType.type, "signature")) throw _err("smime/bad-multipart", "the second part must be application/pkcs7-signature");
    var p7s = _decodeCms(sigEnt);
    // RFC 8551 sec. 3.4 / RFC 1847: the multipart/signed signature is DETACHED -- the SignedData carries
    // NO encapsulated content, the first MIME part IS the signed unit. Reject an ATTACHED SignedData:
    // otherwise cms.verify would verify over the embedded eContent and IGNORE the first part, so an
    // attacker could pair any validly-signed attached blob with an arbitrary first part (a forgery).
    var sd;
    try { sd = schemaCms.parse(p7s); }
    catch (e) { throw _err("smime/bad-mime", "the pkcs7-signature part is not a CMS SignedData", e); }
    if (sd.encapContentInfo && sd.encapContentInfo.eContent != null) {
      throw _err("smime/bad-multipart", "the pkcs7-signature part must carry a DETACHED SignedData (no encapsulated content) (RFC 8551 sec. 3.4)");
    }
    var canon = mime.canonicalize(parts[0], SmimeError, "smime/bad-mime");
    var res2 = await cms.verify(p7s, Object.assign({}, vOpts, { content: canon }));
    var micalg = ct.params.micalg || null;
    // Compare micalg as an ORDER-INDEPENDENT set of digest names (RFC 8551 sec. 3.4.3.2 lists them
    // comma-separated, in no required order, possibly with whitespace).
    if (opts.strictMicalg && micalg && _micalgSet(micalg) !== (_micalgOf(p7s) || "")) {
      throw _err("smime/micalg-mismatch", "the multipart/signed micalg " + JSON.stringify(micalg) + " disagrees with the SignerInfo digests");
    }
    return { valid: res2.valid, signers: res2.signers, form: "multipart/signed", content: parts[0], micalg: micalg };
  }
  throw _err("smime/unsupported-type", "not a signed S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
}

// Decode a CMS body per its Content-Transfer-Encoding (base64 is the S/MIME norm; 7bit/8bit/binary pass through).
function _decodeCms(ent) {
  // guard.encoding.base64 is strict (no whitespace) and rejects via a (code,msg) FACTORY -- strip the
  // MIME line-wrapping whitespace first, and pass _err (not the SmimeError class).
  if (ent.cte === "base64") return guard.encoding.base64(ent.body.toString("latin1").replace(/[\r\n\t ]/g, ""), C.LIMITS.MIME_MAX_BYTES, _err, "smime/bad-mime", "the CMS body");
  return ent.body;
}

function _toBuf(v) { return Buffer.isBuffer(v) ? v : Buffer.from(v); }

module.exports = { sign: sign, verify: verify };
