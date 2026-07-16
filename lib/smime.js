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
 *   RFC 8551 S/MIME assembly + verification + encryption over the shipped CMS
 *   layer. `sign` wraps a MIME entity as a signed S/MIME message and `verify`
 *   unwraps and verifies one, in both forms: `multipart/signed` (clear-signed --
 *   the content stays readable, a detached CMS signature rides alongside) and
 *   `application/pkcs7-mime` (opaque -- the whole entity is a base64 CMS
 *   SignedData). `encrypt` envelopes a MIME entity as an opaque
 *   `application/pkcs7-mime` message and `decrypt` opens one -- `authEnveloped-data`
 *   (AES-GCM, confidentiality AND integrity, the default) or `enveloped-data`
 *   (AES-CBC, confidentiality only, so `decrypt` surfaces `authenticated:false`,
 *   the EFAIL / RFC 8551 sec. 3.3 no-integrity caveat). The crypto is entirely
 *   `pki.cms.sign` / `verify` / `encrypt` / `decrypt`; the new work is the MIME
 *   frame and the RFC 8551 sec. 3.1.1 canonicalization signer and verifier share
 *   one canonicalizer (`lib/mime.js`) so their digests cannot diverge. Like
 *   `cms.verify`, `verify` returns the per-signer cryptographic verdict; chaining
 *   a signer to a trust anchor is the caller's `pki.path.validate` step.
 *
 * @card
 *   Assemble, verify, and encrypt RFC 8551 S/MIME messages (signed:
 *   multipart/signed + application/pkcs7-mime; encrypted: enveloped-data +
 *   authEnveloped-data) over any CMS signer / recipient -- fail-closed,
 *   algorithm-agnostic.
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
// RFC 8551 sec. 3.4.3.2 micalg names, extended with the SHAKE names FIPS 204/205 CMS signers digest
// with (RFC 8702). An unknown digest passes through verbatim -- never regex-mangled (a blind
// `sha`->`sha-` would corrupt "shake256" into "sha-ke256").
var MICALG = { sha1: "sha-1", sha224: "sha-224", sha256: "sha-256", sha384: "sha-384", sha512: "sha-512", md5: "md5", shake128: "shake128", shake256: "shake256" };

// The exact bytes to sign: the caller's content wrapped as a MIME entity (text/plain by default) in
// its canonical form, OR -- when opts.entity is set -- the caller's own complete MIME entity, canonical.
function _entityBytes(content, opts) {
  var raw = guard.bytes.view(content, SmimeError, "smime/bad-input", "content");
  if (opts.entity) return mime.canonicalize(raw, SmimeError, "smime/bad-mime");
  var ct = opts.contentType || "text/plain; charset=utf-8";
  // Declare the honest Content-Transfer-Encoding: "7bit" requires every byte <= 127 (RFC 2045); a body
  // with any 8-bit byte is "8bit". Declaring 7bit for 8-bit content is a false claim a transport could act on.
  var cte = _is7bit(raw) ? "7bit" : "8bit";
  var head = Buffer.from("Content-Type: " + ct + "\r\nContent-Transfer-Encoding: " + cte + "\r\n\r\n", "latin1");
  return mime.canonicalize(Buffer.concat([head, raw]), SmimeError, "smime/bad-mime");
}
function _is7bit(buf) { for (var i = 0; i < buf.length; i++) if (buf[i] > 0x7f) return false; return true; }

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
function _micName(name) { return name ? (MICALG[name] || name) : null; }
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

// The application/pkcs7-mime header for an opaque S/MIME message (RFC 8551 sec. 3.2 / sec. 3.2.2). `name`
// is the smime.p7m (enveloped) / smime.p7z (compressed) file name for the media type + Content-Disposition.
function _pkcs7MimeHead(smimeType, name) {
  return Buffer.from("Content-Type: application/pkcs7-mime; smime-type=" + smimeType + "; name=" + name + "\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=" + name + "\r\n\r\n", "latin1");
}

// The smime-type for a CMS enveloped body, DERIVED from its OUTER content type (RFC 8551 sec. 3.2.2) --
// the single source of truth, never an opts guess: AuthEnvelopedData -> "authEnveloped-data" (AEAD,
// integrity), EnvelopedData -> "enveloped-data" (no integrity). Anything else is not an S/MIME enveloped
// message. Returns { smimeType, name } (name is the parsed contentTypeName). Throws smime/unsupported-type
// for a non-enveloped body (EncryptedData / SignedData carries no smime-type mapping here).
function _envelopedTypeOf(der, badParseCode) {
  var name;
  try { name = schemaCms.parse(guard.bytes.view(der, SmimeError, "smime/bad-mime", "the CMS body")).contentTypeName; }
  catch (e) { throw _err("smime/bad-mime", "the pkcs7-mime body is not a parseable CMS structure", e); }
  if (name === "authEnvelopedData") return "authEnveloped-data";
  if (name === "envelopedData") return "enveloped-data";
  throw _err(badParseCode, "the pkcs7-mime body is a " + name + ", not an EnvelopedData / AuthEnvelopedData");
}

// Map smime opts to cms.encrypt opts. The S/MIME layer is recipient-agnostic: it forwards the content
// -encryption choice + every recipient-shaping opt unchanged, and never emits PEM (the CMS body is base64
// inside a MIME frame). opts.contentType is the MIME media type of the INNER entity (handled by
// _entityBytes), NOT the CMS encapsulated content type -- it is deliberately not forwarded here.
function _cmsEncryptOpts(opts) {
  var o = {};
  if (opts.contentEncryptionAlgorithm !== undefined) o.contentEncryptionAlgorithm = opts.contentEncryptionAlgorithm;
  if (opts.oaepHash !== undefined) o.oaepHash = opts.oaepHash;
  if (opts.keyIdentifier !== undefined) o.keyIdentifier = opts.keyIdentifier;
  if (opts.ukm !== undefined) o.ukm = opts.ukm;
  return o;
}

/**
 * @primitive  pki.smime.encrypt
 * @signature  pki.smime.encrypt(content, recipients, opts?) -> Promise<Buffer>
 * @since      0.2.26
 * @status     experimental
 * @spec       RFC 8551, RFC 5652, RFC 5083
 * @related    pki.smime.decrypt, pki.cms.encrypt
 *
 * Envelope a MIME entity as an encrypted S/MIME message (RFC 8551 sec. 3.3 / sec. 3.4). `content` is the
 * payload -- a raw body wrapped as a `text/plain` entity by default, or the caller's own complete MIME
 * entity when `opts.entity` is set; `recipients` is the `pki.cms.encrypt` recipient array (any RSA-OAEP
 * ktri / EC or X25519/X448 kari / ML-KEM ori-KEM / password pwri / kek kekri -- the S/MIME layer is
 * recipient-agnostic; a single descriptor is accepted and normalized to a one-element array). Enveloping
 * has ONE form -- opaque `application/pkcs7-mime` with the whole entity base64-encoded. The `smime-type`
 * is derived from the produced CMS: AES-GCM (the default) yields an AuthEnvelopedData with
 * `smime-type=authEnveloped-data` (confidentiality AND integrity); a CBC choice yields an EnvelopedData
 * with `smime-type=enveloped-data` (confidentiality only -- no integrity, RFC 8551 sec. 3.3). Returns the
 * assembled message bytes. Fail-closed with `SmimeError`.
 *
 * @opts entity                     treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType                the wrapped entity's MIME Content-Type (default `text/plain; charset=utf-8`).
 * @opts contentEncryptionAlgorithm forwarded to cms.encrypt: `"aes-256-gcm"` (default) / `"aes-128-gcm"` / `"aes-256-cbc"` / `"aes-128-cbc"`.
 * @opts oaepHash                   forwarded: the RSAES-OAEP hash for ktri recipients.
 * @opts keyIdentifier              forwarded: `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts ukm                        forwarded: user keying material for kari / kemri recipients.
 * @example
 *   var enc = await pki.smime.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 */
async function encrypt(content, recipients, opts) {
  opts = opts || {};
  var entity = _entityBytes(content, opts);
  // Normalize a single descriptor to an array so cms.encrypt always takes the ENVELOPED path (an array of
  // RecipientInfos), never bare EncryptedData -- which is not an S/MIME construct (no smime-type maps to it).
  var recips = Array.isArray(recipients) ? recipients : [recipients];
  var der = _toBuf(await cms.encrypt(entity, recips, _cmsEncryptOpts(opts)));
  var head = _pkcs7MimeHead(_envelopedTypeOf(der, "smime/bad-mime"), "smime.p7m");
  return _capped(Buffer.concat([head, _base64Body(der), mime.CRLF]));
}

/**
 * @primitive  pki.smime.decrypt
 * @signature  pki.smime.decrypt(message, keyMaterial, opts?) -> Promise<{ content, smimeType, authenticated, recipientType, recipientIndex, contentEncryptionAlgorithm }>
 * @since      0.2.26
 * @status     experimental
 * @spec       RFC 8551, RFC 5652, RFC 5083
 * @related    pki.smime.encrypt, pki.cms.decrypt, pki.smime.verify
 *
 * Open an encrypted S/MIME message (RFC 8551 sec. 3.3 / sec. 3.4) -- an `application/pkcs7-mime` entity
 * whose base64 body is a CMS EnvelopedData or AuthEnvelopedData. `keyMaterial` is the `pki.cms.decrypt`
 * key material (`{ key, cert }`, `{ password }`, or `{ kek, kekId? }`). Returns the recovered inner MIME
 * entity as `content`, the `smimeType`, `authenticated` (true only for AuthEnvelopedData -- a CBC
 * `enveloped-data` message reports `false`, the RFC 8551 sec. 3.3 / EFAIL no-integrity caveat), and the
 * `recipientType` / `recipientIndex` / `contentEncryptionAlgorithm` from the CMS layer. Fail-closed and
 * oracle-free: every secret-dependent failure collapses to the uniform `cms/decrypt-failed` the CMS layer
 * emits (this layer only propagates it). A recovered `content` that is itself a signed S/MIME message is
 * returned as-is for the caller to feed back to `pki.smime.verify` (no auto-recursion). Accepts OpenSSL's
 * legacy `application/x-pkcs7-mime` and a missing `smime-type`.
 *
 * @opts recipientIndex  forwarded to cms.decrypt: explicitly select the recipient by index.
 * @opts maxIterations   forwarded to cms.decrypt: lower the PBKDF2 iteration cap (downward only).
 * @opts strictSmimeType reject a header `smime-type` that disagrees with the CMS body (`smime/smime-type-mismatch`).
 * @example
 *   var res = await pki.smime.decrypt(smimeMessageBytes, { key: recipientKeyPkcs8, cert: recipientCertDer });
 *   res.content;        // the recovered inner MIME entity
 *   res.authenticated;  // false for an enveloped-only (CBC) message -- no integrity
 */
async function decrypt(message, keyMaterial, opts) {
  opts = opts || {};
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  if (!_isPkcs7(ct.type, "mime")) throw _err("smime/unsupported-type", "not an encrypted S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
  // The smime-type header is advisory (the CMS body is authoritative), so compare it case-insensitively --
  // liberal on accept, strict on emit -- rather than rejecting a legitimate message over its parameter casing.
  var st = ct.params["smime-type"];
  var stLower = st ? st.toLowerCase() : st;
  if (st && stLower !== "enveloped-data" && stLower !== "authenveloped-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(st) + " (only enveloped-data / authEnveloped-data)");
  var der = _decodeCms(ent);
  var smimeType = _envelopedTypeOf(der, "smime/unsupported-type");
  if (opts.strictSmimeType && st && stLower !== smimeType.toLowerCase()) throw _err("smime/smime-type-mismatch", "the header smime-type " + JSON.stringify(st) + " disagrees with the CMS body (" + smimeType + ")");
  var cmsOpts = {};
  if (opts.recipientIndex !== undefined) cmsOpts.recipientIndex = opts.recipientIndex;
  if (opts.maxIterations !== undefined) cmsOpts.maxIterations = opts.maxIterations;
  var res = await cms.decrypt(der, keyMaterial, cmsOpts);
  return {
    content: res.content, smimeType: smimeType, authenticated: res.authenticated,
    recipientType: res.recipientType, recipientIndex: res.recipientIndex,
    contentEncryptionAlgorithm: res.contentEncryptionAlgorithm,
  };
}

/**
 * @primitive  pki.smime.compress
 * @signature  pki.smime.compress(content, opts?) -> Promise<Buffer>
 * @since      0.2.27
 * @status     experimental
 * @spec       RFC 8551, RFC 3274
 * @related    pki.smime.decompress, pki.cms.compress
 *
 * Compress a MIME entity as an opaque compressed S/MIME message (RFC 8551 sec. 3.6). `content` is the
 * payload -- a raw body wrapped as a `text/plain` entity by default, or the caller's own complete MIME
 * entity when `opts.entity` is set. The entity is canonicalized (RFC 8551 sec. 3.1) and ZLIB-compressed
 * into a CMS `CompressedData` (`pki.cms.compress`), carried opaque in one `application/pkcs7-mime;
 * smime-type=compressed-data; name=smime.p7z` entity (base64). Compression is a size transform with NO
 * integrity, confidentiality, or authentication (RFC 8551 sec. 2.4.5) -- sign or encrypt the result if
 * you need protection. Returns the assembled message bytes; fail-closed with `SmimeError`.
 *
 * @opts entity      treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType the wrapped entity's MIME Content-Type (default `text/plain; charset=utf-8`).
 * @opts level       forwarded to cms.compress: the DEFLATE compression level (an integer).
 * @example
 *   var z = await pki.smime.compress(Buffer.from("compress this message"));
 */
async function compress(content, opts) {
  opts = opts || {};
  var entity = _entityBytes(content, opts);
  var cOpts = {};
  if (opts.level !== undefined) cOpts.level = opts.level;
  var der = _toBuf(await cms.compress(entity, cOpts));
  var head = _pkcs7MimeHead("compressed-data", "smime.p7z");
  return _capped(Buffer.concat([head, _base64Body(der), mime.CRLF]));
}

/**
 * @primitive  pki.smime.decompress
 * @signature  pki.smime.decompress(message, opts?) -> Promise<{ content, contentType, contentTypeName, compressionAlgorithm }>
 * @since      0.2.27
 * @status     experimental
 * @spec       RFC 8551, RFC 3274
 * @related    pki.smime.compress, pki.cms.decompress, pki.smime.verify, pki.smime.decrypt
 *
 * Decompress a compressed S/MIME message (RFC 8551 sec. 3.6) -- an `application/pkcs7-mime` entity whose
 * base64 body is a CMS `CompressedData`. Returns the recovered inner MIME entity as `content` plus the
 * inner `contentType` / `contentTypeName` and the `compressionAlgorithm`. The inflate is BOUNDED (a
 * decompression-bomb defense, `cms/decompress-too-large`; `opts.maxOutputBytes` tightens it downward).
 * The verdict carries NO `authenticated` / `valid` field -- CompressedData is not a security assertion
 * (RFC 8551 sec. 2.4.5). A recovered content that is itself a signed or enveloped S/MIME message is
 * returned as-is for the caller to feed back to `pki.smime.verify` / `pki.smime.decrypt` (no
 * auto-recursion). Accepts OpenSSL's legacy `application/x-pkcs7-mime` and a missing `smime-type`.
 *
 * @opts maxOutputBytes forwarded to cms.decompress: lower the decompressed-output cap (a DoS bound; downward only).
 * @example
 *   var res = await pki.smime.decompress(compressedSmimeBytes);
 *   res.content;   // the recovered inner MIME entity
 */
async function decompress(message, opts) {
  opts = opts || {};
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  if (!_isPkcs7(ct.type, "mime")) throw _err("smime/unsupported-type", "not a compressed S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
  // The smime-type header is advisory (the CMS body is authoritative) -- compare case-insensitively.
  var st = ct.params["smime-type"];
  if (st && st.toLowerCase() !== "compressed-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(st) + " (only compressed-data)");
  var der = _decodeCms(ent);
  var dOpts = {};
  if (opts.maxOutputBytes !== undefined) dOpts.maxOutputBytes = opts.maxOutputBytes;
  var res = await cms.decompress(der, dOpts);
  return { content: res.content, contentType: res.contentType, contentTypeName: res.contentTypeName, compressionAlgorithm: res.compressionAlgorithm };
}

// Decode a CMS body per its Content-Transfer-Encoding (base64 is the S/MIME norm; 7bit/8bit/binary pass through).
function _decodeCms(ent) {
  // guard.encoding.base64 is strict (no whitespace) and rejects via a (code,msg) FACTORY -- strip the
  // MIME line-wrapping whitespace first, and pass _err (not the SmimeError class).
  if (ent.cte === "base64") return guard.encoding.base64(ent.body.toString("latin1").replace(/[\r\n\t ]/g, ""), C.LIMITS.MIME_MAX_BYTES, _err, "smime/bad-mime", "the CMS body");
  return ent.body;
}

function _toBuf(v) { return Buffer.isBuffer(v) ? v : Buffer.from(v); }

module.exports = { sign: sign, verify: verify, encrypt: encrypt, decrypt: decrypt, compress: compress, decompress: decompress };
