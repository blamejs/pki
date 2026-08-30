// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cms.sign implementation. So the pki.cms namespace has one @module home,
// the operator-facing @module pki.cms + the @primitive pki.cms.sign documentation block live in
// cms-verify.js, which re-exports this sign function.
//
// CMS SignedData signing (RFC 5652 sec. 5), the producing side of pki.cms.verify: composes the
// strict asn1 build layer (canonical DER, and build.set SET-OF-sorts the signed attributes for
// free), the WebCrypto sign surface over node:crypto, and the shared validator.sig.rawToEcdsaDer
// DER-ECDSA home -- emitting exactly the shapes cms.verify checks (NULL params for RSA, absent
// for ECDSA/EdDSA, the RSASSA-PSS params SEQUENCE), with the sign->verify round-trip (and OpenSSL
// cms -verify) as the guard.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var crlSchema = require("./schema-crl");
var pkix = require("./schema-pkix");
var frameworkError = require("./framework-error");

var webcrypto = require("./webcrypto");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var pkiBuild = require("./pki-build");   // the shared post-sign self-check, among other producing helpers
var cms = require("./schema-cms");

var subtle = webcrypto.webcrypto.subtle;
var CmsError = frameworkError.CmsError;
var b = asn1.build;
function _err(code, message, cause) { return new CmsError(code, message, cause); }
// The domain error factory the shared sign-scheme resolver/signer throws through (kind ->
// cms/<kind>), so its faults keep the cms/* codes.
function _signE(kind, message, cause) { return new CmsError("cms/" + kind, message, cause); }
function O(name) { return oid.byName(name); }

// Every option each verb READS, and nothing else. Derived from the signing paths themselves rather
// than from what callers happen to pass: an option this list omits is one the verb would ignore in
// silence, and the ones that matter most are the ones a caller would most expect to work.
// A misspelled option name is the shape this closes: it does not select the mode the caller meant,
// and without the gate the message is signed the other way with nothing said about it.
var KNOWN_SIGN_OPTS = {
  signedAttributes: 1, signingTime: 1, additionalSignedAttributes: 1, unsignedAttributes: 1,
  sid: 1, eContentType: 1, detached: 1, certificates: 1, pem: 1,
};
// The SIGNER descriptor has two forms, and every field it reads is named here so a caller that
// authors one can be held to the form it selects: a certificate signer, and the key-only signer
// RFC 5272 sec. 3.2 requires for a Full PKI Request, whose identity comes from `spki` +
// `keyIdentifier` instead. The signature parameters are read by both. Exported for the verbs that
// take signer descriptors as AUTHORING input and gate them at their own door -- pki.cms.sign takes
// them straight from its caller, where a bag carrying extra handles is an ordinary shape.
var KNOWN_SIGNER_CERT_KEYS = { cert: 1, key: 1, pss: 1, digestAlgorithm: 1, combinedRsaSig: 1 };
var KNOWN_SIGNER_KEY_ONLY_KEYS = { spki: 1, keyIdentifier: 1, key: 1, pss: 1, digestAlgorithm: 1, combinedRsaSig: 1 };
// Countersign has its own set: it takes signerIndex and countersignatureOf to SELECT which
// signature it attaches to, and has no content of its own, so eContentType, detached and
// unsignedAttributes are not among the options it reads.
var KNOWN_COUNTERSIGN_OPTS = {
  signerIndex: 1, countersignatureOf: 1, signingTime: 1, certificates: 1, pem: 1,
  signedAttributes: 1, additionalSignedAttributes: 1, sid: 1,
};
// The shared producing-side helpers, bound to this domain's error class. Only the
// post-sign self-check is used here (the same one every other signer in the
// toolkit runs), so a key-only signer's declared public key is bound by evidence
// and never by the caller's word.
var NS = pkix.makeNS("cms", CmsError, oid);
var _b = pkiBuild.makeBuilder({
  ErrorClass: CmsError, prefix: "cms", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: {},
});

// A digest-algorithm name -> the engine's hash name. The FIPS 202 extendable-output
// functions are message digests here at the lengths RFC 8702 sec. 4 fixes for that use,
// which the engine applies from the name alone.
var DIGEST_HASH = {
  sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512",
  shake128: "SHAKE128", shake256: "SHAKE256",
};

var OID_DATA = O("data");
var OID_PKI_DATA = O("id-cct-PKIData");   // the content type RFC 5272 sec. 3.2's signer rules govern
var OID_SIGNED_DATA = O("signedData");
var OID_SKI = O("subjectKeyIdentifier");


// The message digest of the content under the digest algorithm, resolved to a Buffer.
function _digest(digestName, content) {
  return subtle.digest(DIGEST_HASH[digestName], content).then(function (d) { return Buffer.from(d); });
}


// The cert's subjectKeyIdentifier extension value (the raw key id), or throws.
function _skiValue(cert) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (!ext) throw _err("cms/no-ski", "a subjectKeyIdentifier signer identifier requires the signer certificate to carry an SKI extension");
  try { return asn1.read.octetString(asn1.decode(ext.value)); }
  catch (e) { throw _err("cms/no-ski", "the signer certificate's subjectKeyIdentifier extension value is not an OCTET STRING", e); }
}


// The SignerInfo SignerIdentifier + its coupled CMSVersion (RFC 5652 sec. 5.3): a [0] IMPLICIT
// subjectKeyIdentifier => version 3, else an IssuerAndSerialNumber => version 1. Shared by the
// top-level signer and the sec. 11.4 countersignature (a countersignature IS a SignerInfo).
function _buildSid(cert, useSki) {
  var sid = useSki
    ? b.contextPrimitive(0, _skiValue(cert))                                       // [0] IMPLICIT SubjectKeyIdentifier
    : b.sequence([b.raw(pkiBuild.tbsNameField(cert, "issuer")), b.integer(cert.serialNumber)]);   // IssuerAndSerialNumber
  return { sid: sid, version: useSki ? 3 : 1 };
}

// Assemble a SignedAttributes SET from resolved attribute pairs (each { type: <dotted OID>, values:
// [<build node or DER Buffer>] }), returning { setOf, wire }: `setOf` is the canonical DER SET OF
// (tag 0x31, build.set SET-OF-sorts) the signature covers (RFC 5652 sec. 5.4); `wire` is the same
// bytes with the on-wire [0] IMPLICIT tag (0xA0). Each attribute type appears at most once (sec.
// 5.3), so a duplicate throws. Shared by the top-level signer (content-type + message-digest +
// signing-time + caller attrs) and the countersignature builder (message-digest over the target
// signature octets + signing-time, content-type omitted per sec. 11.4).
function _buildSignedAttrs(pairs) {
  var seenTypes = {};
  var attrs = intrinsic.map(pairs, function (p) {
    if (intrinsic.hasOwn(seenTypes, p.type)) throw _err("cms/bad-input", "signedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + p.type);
    seenTypes[p.type] = 1;
    return b.sequence([b.oid(p.type), b.set(p.values)]);
  });
  var setOf = b.set(attrs);   // SET OF (tag 0x31) -- the exact bytes the signature covers (sec. 5.4)
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA0;   // the on-wire [0] IMPLICIT tag
  return { setOf: setOf, wire: wire };
}

// Resolve caller-supplied additional signed attributes ({ type: OID name or dotted, values: [DER] })
// into the pair shape _buildSignedAttrs consumes; each MUST carry >= 1 value (Attribute values is
// SET SIZE (1..MAX)).
function _resolveAttrPairs(list, what) {
  return intrinsic.map(list || [], function (a) {
    var vals = intrinsic.map(a.values || [], function (v) { return _toBuf(v, what); });
    if (!vals.length) throw _err("cms/bad-input", "a signed attribute must carry at least one value (RFC 5652 -- Attribute values is SET SIZE (1..MAX))");
    return { type: oid.isDottedDecimal(a.type) ? a.type : O(a.type), values: vals };
  });
}

// content-type / message-digest / signing-time are content-binding signed attributes and MUST NOT
// appear as unsigned attributes (RFC 5652 sec. 11.1/11.2/11.3, the parser's ATTR_FORBIDDEN_IN).
var UNSIGNED_FORBIDDEN = {};
UNSIGNED_FORBIDDEN[O("contentType")] = "content-type";
UNSIGNED_FORBIDDEN[O("messageDigest")] = "message-digest";
UNSIGNED_FORBIDDEN[O("signingTime")] = "signing-time";

// Build the [1] IMPLICIT unsignedAttrs SET OF (on-wire tag 0xA1) from opts.unsignedAttributes
// (each { type, values: [DER] }, such as a countersignature or an RFC 3161 timestamp token), or null when
// absent/empty. Unsigned attributes sit outside the signature; a placement-forbidden type or a
// duplicate type (RFC 5652 sec. 11 / sec. 5.3) is a config-time cms/bad-input.
function _buildUnsignedAttrs(list) {
  if (list == null) return null;
  if (!intrinsic.isArray(list)) throw _err("cms/bad-input", "opts.unsignedAttributes must be an array of { type, values }");
  if (!list.length) return null;
  var pairs = _resolveAttrPairs(list, "an unsigned attribute value");
  var seen = {};
  intrinsic.forEach(pairs, function (p) {
    if (intrinsic.hasOwn(UNSIGNED_FORBIDDEN, p.type)) throw _err("cms/bad-input", "the " + UNSIGNED_FORBIDDEN[p.type] + " attribute must not appear as an unsigned attribute (RFC 5652 sec. 11)");
    if (intrinsic.hasOwn(seen, p.type)) throw _err("cms/bad-input", "unsignedAttrs must not repeat an attribute type (RFC 5652 sec. 5.3): " + p.type);
    seen[p.type] = 1;
  });
  var setOf = b.set(intrinsic.map(pairs, function (p) { return b.sequence([b.oid(p.type), b.set(p.values)]); }));
  var wire = intrinsic.bufferFrom(setOf); wire[0] = 0xA1;   // SET OF -> [1] IMPLICIT UnsignedAttributes
  return wire;
}

// Resolve, at entry and once, every field an emitted SignerInfo depends on (RFC 5652 sec. 5.3):
// the SignerIdentifier + version, the signature scheme, the private key reference, the declared
// public bytes, and the signer certificate DER. Nothing here defers, so the values are captured
// before any promise turn; the digest, the signature, and the self-check happen a turn later in
// _finishSignerInfo, off exactly these captured values. Buffered and streamed signing share this.
function _resolveSignerContext(signer, opts) {
  var so = signer || {};
  // A key-only signer: `{ key, spki, keyIdentifier }` with no certificate. RFC
  // 5272 sec. 3.2 requires exactly this when a Full PKI Request is signed with the
  // key of a certification request it carries: there is no certificate yet, the
  // sid MUST be the subjectKeyIdentifier form, and its value MUST be the SKI the
  // request itself declares. The scheme resolver only ever reads
  // `cert.subjectPublicKeyInfo.algorithm`, so the request's own parsed SPKI stands
  // in for the certificate that does not exist.
  var keyOnly = so.cert == null && so.spki != null;
  // Every field the emitted SignerInfo depends on is read ONCE, HERE, while
  // nothing has deferred yet. The SignerIdentifier is built from the certificate
  // or the key identifier on the lines below; the key signs, and is matched
  // against `spki`, a promise turn later. A descriptor whose `key` and `spki`
  // were swapped in that gap would emit a SignerInfo that names one public key
  // and carries a signature by another -- coherent to the match check, since
  // both halves moved together, and unverifiable to everyone else.
  //
  // The public bytes are COPIED, so an in-place rewrite cannot reach them
  // either. The private key is captured by reference: copying it would put a
  // second copy of key material in this function's hands, a secret it would then
  // own for the rest of the call, and the reference already pins which key
  // signs against the identifier that names it.
  var soKey = so.key;
  var soSpki = keyOnly ? guard.bytes.snapshotSource(so.spki, CmsError, "cms/bad-input", "a key-only signer's spki") : null;
  var certDer = keyOnly ? null : _normCertDer(so.cert);
  var cert = keyOnly ? _keyOnlyCertStandIn(soSpki) : x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var sidv = keyOnly
    ? { sid: b.contextPrimitive(0, _keyOnlyKeyId(so)), version: 3 }   // [0] IMPLICIT SubjectKeyIdentifier
    : _buildSid(cert, opts.sid === "ski");
  return { keyOnly: keyOnly, soKey: soKey, soSpki: soSpki, certDer: certDer, cert: cert,
    scheme: scheme, sid: sidv.sid, version: sidv.version };
}

// Finish a SignerInfo (RFC 5652 sec. 5.3) from a resolved context: build the SignedAttributes (or
// sign the content directly), sign them, self-check the signature against the declared key, and
// assemble the SignerInfo. `md` is the message digest of the content under `rc.scheme.digest`,
// already computed -- over a buffered content by _digest, or over a streamed content's chunks by the
// engine's single-pass digest. `content` is read ONLY on the signedAttributes:false path, where the
// signature covers the content directly and there is no digest attribute.
async function _finishSignerInfo(rc, md, content, eContentType, opts) {
  // await throughout, never a live Promise.resolve()/.then lookup: on the streamed path this runs after
  // the content's iterator has driven the digest, so a replaced global Promise.resolve or a replaced
  // Promise.prototype.then would otherwise let it disrupt the signing that completes here. await hooks
  // onto a native promise through the internal job, not the caller-replaceable prototype method.
  var toSign;
  if (opts.signedAttributes === false) {
    toSign = content;   // sign the content directly (no signed attributes)
  } else {
    // Signed attributes (RFC 5652 sec. 5.3): content-type == eContentType, message-digest ==
    // digest(content), and (by default) signing-time, plus any caller-supplied attribute.
    var pairs = [
      { type: O("contentType"), values: [b.oid(eContentType)] },
      { type: O("messageDigest"), values: [b.octetString(md)] },
    ];
    if (opts.signingTime !== false) intrinsic.push(pairs, { type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
    pairs = intrinsic.concat(pairs, _resolveAttrPairs(opts.additionalSignedAttributes, "a signed attribute value"));
    toSign = _buildSignedAttrs(pairs);
  }
  var signedBytes = toSign.setOf ? toSign.setOf : toSign;   // SET-OF form for signing (sec. 5.4)
  var sig = await signScheme.signOverTbs(rc.scheme, rc.soKey, signedBytes, _signE);
  await _assertKeyMatchesSpki(rc.keyOnly, rc.soKey, rc.soSpki, rc.scheme, sig, signedBytes, rc.cert);
  var fields = [b.integer(BigInt(rc.version)), rc.sid, rc.scheme.digestAlgId];
  if (toSign.wire) intrinsic.push(fields, toSign.wire);              // [0] IMPLICIT signedAttrs
  intrinsic.push(fields, rc.scheme.sigAlgId, b.octetString(sig));
  var ua = _buildUnsignedAttrs(opts.unsignedAttributes);
  if (ua) intrinsic.push(fields, ua);                                 // [1] IMPLICIT unsignedAttrs
  // certDer is null for a key-only signer, and the certificates [0] embedding below filters it out --
  // there is nothing to embed, which is the point.
  return { si: b.sequence(fields), digestAlgId: rc.scheme.digestAlgId, version: rc.version, certDer: rc.certDer };
}

// Build one SignerInfo (RFC 5652 sec. 5.3) over a buffered content and sign it: resolve the context,
// digest the content (unless it is signed directly), then finish.
function _buildSignerInfo(signer, content, eContentType, opts) {
  var rc = _resolveSignerContext(signer, opts);
  var mdP = opts.signedAttributes === false ? Promise.resolve(null) : _digest(rc.scheme.digest, content);
  return mdP.then(function (md) { return _finishSignerInfo(rc, md, content, eContentType, opts); });
}



// A SignerInfo names a public key -- as `spki` when the signer is key-only, and as
// the certificate it embeds otherwise -- while the signature comes from `key`. Two
// different keys make a well-formed SignerInfo nobody can verify: the recipient
// resolves the identifier to the declared key and checks a signature made by
// another. Neither form catches that by itself, so both are checked here.
//
// Proven from the SIGNATURE, not from the key. Deriving the public half and
// comparing it works only for key material this process can export, and the keys
// this signer serves are often exactly the ones that cannot be: a non-extractable
// CryptoKey, an HSM handle, or a composite `{ mldsa, trad }` pair that is two keys
// and not one. Every one of those can still be checked the direct way: the
// signature it just produced either verifies under the declared public key or it
// does not, so there is no key kind this has to take on trust.
//
// This is the same post-sign self-check every other signer in the toolkit runs,
// through the same shared helper. It costs one verification per SignerInfo, which
// is what a certificate, a CRL, a CSR and a CMP message have always paid here.
async function _assertKeyMatchesSpki(keyOnly, soKey, soSpki, scheme, sig, signedBytes, cert) {
  var declared = keyOnly ? soSpki : (cert && cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.bytes);
  // A parsed certificate that does not retain its SPKI bytes cannot be checked this
  // way. That is not a shape x509.parse produces, and if it ever were, refusing is
  // the answer, never skipping, since a skip is the fail-open this prevents.
  if (!declared) {
    throw _signE("bad-input",
      "a signer certificate did not surface its subjectPublicKeyInfo, so the signature it produced could " +
      "not be checked against the key the SignerInfo declares");
  }
  // await, never Promise.resolve()/.then: reached from _finishSignerInfo after a streamed content's
  // iterator ran, so a replaced global Promise.resolve would otherwise disrupt this self-check.
  try {
    await _b.assertSignatureVerifies(signedBytes, sig, declared, scheme);
  } catch (e) {
    if (e && typeof e.code === "string" && e.code.indexOf("cms/") === 0) throw e;
    throw _signE("bad-input",
      "a signer's `key` does not match the public key its SignerInfo declares (" +
      (keyOnly ? "`spki`" : "its certificate") + "): the signature it produced does not verify under that key", e);
  }
}

// A signing-time Time value: UTCTime before 2050, GeneralizedTime from 2050 (RFC 5652 sec. 11.3 /
// RFC 5280 sec. 4.1.2.5). A caller Date overrides; false omits the attribute (handled above). The
// DEFAULT instant is read from the captured Date intrinsic, never the live global: a streamed content's
// iterator runs during the digest, one turn before this attribute is built, and a replaced global Date
// would otherwise let it stamp the signature with an attacker-chosen instant (byte-identical, under a
// deterministic scheme, to signing with that instant explicitly).
function _timeValue(when) {
  var d = guard.time.isDate(when) ? when : new intrinsic.Date();
  return d.getUTCFullYear() < 2050 ? b.utcTime(d) : b.generalizedTime(d);
}

// Normalize a signer certificate input to its raw DER (DER Buffer / PEM string / Uint8Array).
// The same bytes drive scheme resolution and the certificates [0] embedding, so a parsed
// certificate (which does not retain its full DER) is rejected; pass DER or PEM.
// The stand-in a key-only signer resolves its signature scheme from: the parsed
// SubjectPublicKeyInfo of the key that will sign. Only `.subjectPublicKeyInfo` is
// read downstream, so this deliberately carries nothing else; a fuller fake
// would invite code to start trusting fields no certificate actually backs.
function _keyOnlyCertStandIn(spkiDer) {
  var alg;
  try {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    // The whole structure, not just the field this function goes on to read. For an
    // opaque key handle the derivation check downstream is deliberately skipped, so
    // this is the only thing standing between a caller's bytes and a SignerInfo that
    // declares them: a SEQUENCE carrying an algorithm and nothing else, or a third
    // field, would be emitted as the signer's public key and resolve to nothing for
    // anyone trying to verify. The key value is not interpreted, only that there
    // is one, in the field the structure reserves for it.
    var node = asn1.decode(spkiDer);
    if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children ||
        node.children.length !== 2) {
      throw _err("cms/bad-input",
        "a key-only signer's spki is SEQUENCE { algorithm, subjectPublicKey BIT STRING } (RFC 5280 sec. 4.1.2.7)");
    }
    var keyNode = node.children[1];
    if (keyNode.tagClass !== "universal" || keyNode.tagNumber !== asn1.TAGS.BIT_STRING) {
      throw _err("cms/bad-input",
        "a key-only signer's spki subjectPublicKey must be a BIT STRING (RFC 5280 sec. 4.1.2.7)");
    }
    asn1.read.bitString(keyNode);   // read, not tag-inspected: a malformed unused-bit count is refused here
    var algNode = node.children[0];
    if (algNode.tagClass !== "universal" || algNode.tagNumber !== asn1.TAGS.SEQUENCE ||
        !algNode.children || !algNode.children.length || algNode.children.length > 2) {
      throw _err("cms/bad-input",
        "a key-only signer's spki algorithm is SEQUENCE { algorithm OID, parameters OPTIONAL } (RFC 5280 sec. 4.1.1.2)");
    }
    // The same shape schema-x509 surfaces: the algorithm OID plus its parameters
    // as the raw TLV (or null when absent); the resolver re-decodes those bytes
    // for an EC named curve and for the RSASSA-PSS hash pinning, so handing it a
    // different representation here would break exactly those two algorithms.
    alg = {
      oid: asn1.read.oid(algNode.children[0]),
      parameters: algNode.children[1] ? algNode.children[1].bytes : null,
    };
  } catch (e) {
    // The shape refusals above already name what is wrong; only a decode failure
    // needs the generic message, so a precise verdict is not overwritten by it.
    if (e && typeof e.code === "string" && e.code.indexOf("cms/") === 0) throw e;
    throw _err("cms/bad-input", "a key-only signer's spki is not a SubjectPublicKeyInfo", e);
  }
  return { subjectPublicKeyInfo: { algorithm: alg } };
}

// The key identifier a key-only signer's sid carries. Required: without it there
// is no way for a verifier to find the key, and RFC 5272 sec. 3.2 makes the value
// the one the certification request declares.
function _keyOnlyKeyId(so) {
  if (so.keyIdentifier == null) {
    throw _err("cms/bad-input",
      "a key-only signer requires keyIdentifier -- the subjectKeyIdentifier the certification request declares (RFC 5272 sec. 3.2)");
  }
  // A key identifier is bytes, so the type is checked and never coerced. Buffer.from
  // accepts far more than it should mean here: Buffer.from(20) allocates twenty zero
  // octets and Buffer.from("a1b2") takes the ASCII of the text, not the two
  // octets a reader means by it. Either would emit a structurally valid
  // SignerIdentifier carrying an identifier the caller never asked for, which no
  // verifier can match back to the certification request (RFC 5272 sec. 3.2).
  var id = guard.bytes.view(so.keyIdentifier, CmsError, "cms/bad-input", "a key-only signer's keyIdentifier");
  if (!id.length) throw _err("cms/bad-input", "a key-only signer's keyIdentifier must not be empty");
  return id;
}

function _normCertDer(c) {
  if (c == null) throw _err("cms/bad-input", "each signer requires a certificate (cert)");
  if (guard.bytes.isByteSource(c)) {
    c = guard.bytes.snapshotSource(c, CmsError, "cms/bad-input", "a signer certificate");
    return c[0] === 0x30 ? c : _pemToDer(c.toString("latin1"));   // DER as-is, else PEM
  }
  if (typeof c === "string") return _pemToDer(c);
  throw _err("cms/bad-input", "a signer certificate must be a DER Buffer or a PEM string");
}
function _pemToDer(text) {
  var der = pkix.pemDecodeLenient(text, "CERTIFICATE");
  if (der === null) throw _err("cms/bad-input", "a signer certificate PEM is not a CERTIFICATE block");
  return der;
}

// pki.cms.sign -- documented by the @primitive block in cms-verify.js (the @module pki.cms home).
// Documented `-> Promise`, so a fault leaves as a REJECTION (guard-async). The stream/buffer routing
// classifies `content` at the door, which reads `content[Symbol.asyncIterator]` -- a caller accessor
// that can throw -- so the whole dispatch runs inside the rejection boundary rather than fixedCall's
// alone, which the classification precedes. The checks the impls run stay synchronous because they
// read the caller's mutable content and signer list.
function sign(content, signers, opts) {
  return guard.async.deferred(function () { return _signDispatch(content, signers, opts); });
}

function _signDispatch(content, signers, opts) {
  // The signer list and options are copied FIRST, before the content is classified. Classifying reads
  // content[Symbol.asyncIterator] -- a caller accessor that runs in-realm -- and a probe run before the
  // copy could mutate the still-uncopied signers/opts, or replace the Array.prototype method the copy
  // uses, and steer the emitted signature. With the copies taken first, the probe cannot reach them.
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [signers, "the signer list"], [opts, "pki.cms.sign options"],
  ], function (copiedSigners, copiedOpts) {
    // A streaming content is classified by guard.bytes.asyncStreamOf, which reads Symbol.asyncIterator a
    // single time and returns a LAZY stream (its underlying iterator is acquired only when the digest
    // engine drives it, so a pre-hash rejection never opens a resource to leak). The stream, consumed
    // exactly once, is passed through; it CANNOT be deep-copied itself. A byte source (or any
    // non-iterable) yields null here and takes the buffered path.
    var stream = guard.bytes.asyncStreamOf(content);
    if (stream) return _signStream(stream, copiedSigners, copiedOpts);
    // Buffered: the content byte source is copied too, so the value that decides the attribute-shaped-
    // content refusal and the value that gets signed are the same read.
    return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
      [content, "content"],
    ], function (copiedContent) { return _sign(copiedContent, copiedSigners, copiedOpts); });
  });
}

// Sign a streamed content (an async iterable of byte chunks) as a DETACHED SignedData. The payload
// is hashed once, incrementally, under every distinct SignerInfo digest algorithm (RFC 5652
// sec. 5.4), so an arbitrarily large content is never held whole and a single-use stream serves
// every signer in one pass. Detached is the only conformant streamed form: an attached SignedData
// embeds the content as a definite-length OCTET STRING, which needs the whole content buffered to
// state its length, and signed attributes are required (a stream cannot be signed directly, and the
// message-digest attribute is exactly what the streamed hash produces).
async function _signStream(stream, signers, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.sign options");
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "cms/bad-input", "unknown opts field ");
  if (opts.detached !== true) {
    throw _err("cms/bad-input", "a streaming (async-iterable) content requires opts.detached: true; an attached " +
      "SignedData embeds the content as a definite-length OCTET STRING, which cannot be produced without buffering it");
  }
  if (opts.signedAttributes === false) {
    throw _err("cms/bad-input", "a streaming content cannot be signed without signed attributes: the message-digest " +
      "attribute is the streamed hash, and there is no content to sign directly (RFC 5652 sec. 5.4)");
  }
  var list = intrinsic.isArray(signers) ? _b.reqDenseArray(signers, "the signer list") : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.sign requires at least one signer");
  var eContentType = opts.eContentType ? O(opts.eContentType) : OID_DATA;
  if (eContentType === OID_PKI_DATA && list.length > 1 &&
      intrinsic.some(list, function (s) { return s && s.cert == null && s.spki != null; })) {
    throw _err("cms/bad-input",
      "a key-only signer must be the ONLY SignerInfo in a Full PKI Request (RFC 5272 sec. 3.2)");
  }
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");
  // Resolve every signer's context first (no stream consumed yet): this yields each SignerInfo's
  // digest algorithm, so the stream can be hashed once under the distinct set.
  var rcs = intrinsic.map(list, function (s) { return _resolveSignerContext(s, opts); });
  var digestNames = [], seenDigest = {};
  intrinsic.forEach(rcs, function (r) { if (!seenDigest[r.scheme.digest]) { seenDigest[r.scheme.digest] = 1; intrinsic.push(digestNames, r.scheme.digest); } });
  var wcNames = intrinsic.map(digestNames, function (n) { return DIGEST_HASH[n]; });
  // `await`, not `.then`: the streamed content's iterator runs during digestStream and could replace
  // Promise.prototype.then (or Promise.all, whose spec-internal element handling dispatches through it)
  // to drop SignerInfos from the emitted DER or bypass the non-empty-signer check. await and a captured
  // await-each aggregation dispatch through no such caller-replaceable method.
  var digests;
  try {
    digests = await subtle.digestStream(wcNames, stream);
  } catch (e) {
    // The engine reports malformed streamed content in its own domain; report it in this verb's via the
    // shared guard, rather than leaking the engine code. The digest algorithm names are this module's own,
    // so a webcrypto/syntax here is never an algorithm fault.
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
  var byName = {};
  intrinsic.forEach(digestNames, function (n, i) { byName[n] = intrinsic.bufferFrom(digests[i]); });
  // Build each SignerInfo sequentially -- START it only as it is awaited -- rather than starting them
  // all and awaiting each: awaiting is the capture-safe combinator (no Promise.all/.then the streamed
  // content could replace), but starting all first would leave a later signer's rejection unobserved
  // if an earlier one rejects, which Node can escalate to an unhandled-rejection crash. Per-signer work
  // is small, so the sequential cost is negligible.
  var built = [];
  for (var _ip = 0; _ip < rcs.length; _ip++) {
    intrinsic.push(built, await _finishSignerInfo(rcs[_ip], byName[rcs[_ip].scheme.digest], null, eContentType, opts));
  }
  return _assembleSignedData(built, eContentType, opts, null);
}

function _sign(content, signers, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.sign options");
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "cms/bad-input", "unknown opts field ");
  // The arguments were copied at entry (see `sign` above), which is what makes the refusal below
  // hold: flipping signedAttributes from true to false after the call returns would otherwise skip
  // the attribute-shaped-content check while the signer signs that content directly, which is the
  // very signature the stripping attack needs.
  var contentBuf = _toBuf(content, "content");
  var list = Array.isArray(signers) ? _b.reqDenseArray(signers, "the signer list") : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.sign requires at least one signer");
  var eContentType = opts.eContentType ? O(opts.eContentType) : OID_DATA;
  // RFC 5272 sec. 3.2: "If the request key is used for signing, there MUST be only
  // one SignerInfo in the SignedData." That clause governs a Full PKI Request, so
  // it binds HERE only for that content type. CMS itself is happy with several
  // SignerInfos, and a key-only signer's certificate can reach a verifier by other
  // means -- applying the CMC rule to every content type would refuse ordinary
  // SignedData that nothing objects to. pki.cmc.build enforces the same rule on
  // the message it assembles, which is where the clause is really about.
  if (eContentType === OID_PKI_DATA && list.length > 1 &&
      list.some(function (s) { return s && s.cert == null && s.spki != null; })) {
    throw _err("cms/bad-input",
      "a key-only signer must be the ONLY SignerInfo in a Full PKI Request (RFC 5272 sec. 3.2)");
  }
  // RFC 5652 sec. 5.3: signed attributes MUST be present (carrying a content-type attribute)
  // whenever the encapsulated content type is not id-data, so signedAttributes:false is only
  // valid for id-data content. Refusing it here keeps cms.sign from emitting a non-conformant
  // SignedData (e.g. a timestamp token, id-ct-TSTInfo, with no signed attributes).
  if (opts.signedAttributes === false && eContentType !== OID_DATA) {
    throw _err("cms/bad-input", "signed attributes are required when eContentType is not id-data (RFC 5652 sec. 5.3)");
  }
  // The signer's half of the signed-attribute stripping problem
  // (draft-vangeest-lamps-cms-euf-cma-signeddata, Attack Type 2). Signing attribute-shaped content
  // without attributes produces a signature that can afterwards be promoted into an
  // attributes-present message, because the signature does not commit to which mode was used: the
  // attacker attaches the signed bytes as the SignedAttributes and swaps in whatever content their
  // message-digest attribute names. Refusing to mint the ambiguous signature is the only point at
  // which this direction can be stopped -- by the time it is a message, the damage is done.
  if (opts.signedAttributes === false && cms.looksLikeSignedAttributes(contentBuf)) {
    throw _err("cms/ambiguous-content", "this content is itself an encoded SignedAttributes block, so signing " +
      "it WITHOUT signed attributes would produce a signature that could be re-presented as one over " +
      "attributes (RFC 5652 sec. 5.4); sign it with signed attributes instead");
  }
  // A supplied signing-time MUST be a valid Date (or false to omit the attribute), never a
  // silently-ignored non-Date or an Invalid Date that would encode a garbage Time.
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");

  return Promise.all(list.map(function (s) { return _buildSignerInfo(s, contentBuf, eContentType, opts); }))
    .then(function (built) { return _assembleSignedData(built, eContentType, opts, contentBuf); });
}

// Assemble the SignedData ContentInfo (RFC 5652 sec. 5.1) from the built SignerInfos: the deduped
// digestAlgorithms set, the coupled CMSVersion, the EncapsulatedContentInfo (eContent omitted when
// detached, the only form a streamed content takes), the deduped certificates [0], and the
// signerInfos SET OF. `contentBuf` is the content bytes for the attached form, or null when detached.
function _assembleSignedData(built, eContentType, opts, contentBuf) {
  // digestAlgorithms: the distinct SignerInfo digestAlgorithm AlgorithmIdentifiers, deduped. Captured
  // enumeration throughout: this assembly runs after a streamed content's iterator may have replaced
  // Array.prototype.map / forEach / Buffer.prototype.toString, and a live one could drop SignerInfos
  // from the emitted CMS or mis-dedup the algorithm / certificate sets.
  var seen = {}, digestAlgs = [];
  intrinsic.forEach(built, function (x) { var k = intrinsic.bufToString(x.digestAlgId, "hex"); if (!seen[k]) { seen[k] = 1; intrinsic.push(digestAlgs, x.digestAlgId); } });
  // CMSVersion (RFC 5652 sec. 5.1): 3 if any SignerInfo is v3 (ski) or eContentType != id-data;
  // otherwise 1 (v1 emits only X.509 certificates, so the v4/v5 attribute-certificate cases
  // do not arise).
  var v3 = intrinsic.some(built, function (x) { return x.version === 3; }) || eContentType !== OID_DATA;
  var version = v3 ? 3 : 1;
  // EncapsulatedContentInfo: eContentType + [0] EXPLICIT eContent (omitted when detached).
  var encapFields = [b.oid(eContentType)];
  if (!opts.detached) intrinsic.push(encapFields, b.explicit(0, b.octetString(contentBuf)));
  var encap = b.sequence(encapFields);
  // certificates [0] IMPLICIT SET OF (the signer certs), deduped + SET-OF-ordered, when embedded.
  var sdFields = [b.integer(BigInt(version)), b.set(digestAlgs), encap];
  if (opts.certificates !== false) {
    // A key-only signer contributes no certificate (certDer is null), so the
    // set can end up EMPTY -- and an empty certificates [0] is not the same as
    // an absent one, so the field is omitted entirely in that case.
    var certDers = intrinsic.sort(_dedupe(intrinsic.filter(intrinsic.map(built, function (x) { return x.certDer; }),
      function (d) { return d != null; })), intrinsic.compare);        // X.690 sec. 11.6
    if (certDers.length) intrinsic.push(sdFields, b.contextConstructed(0, intrinsic.bufferConcat(certDers)));   // [0] IMPLICIT SET OF
  }
  intrinsic.push(sdFields, b.set(intrinsic.map(built, function (x) { return x.si; })));                 // signerInfos SET OF
  var signedData = b.sequence(sdFields);
  var contentInfo = b.sequence([b.oid(OID_SIGNED_DATA), b.explicit(0, signedData)]);   // ContentInfo
  return opts.pem ? pkix.pemEncode(contentInfo, "CMS", frameworkError.PemError) : contentInfo;
}

// Dedupe certificate DERs (two signers may share a cert, so embed it once).
function _dedupe(ders) {
  var seen = {}, out = [];
  intrinsic.forEach(ders, function (d) { var k = intrinsic.bufToString(d, "hex"); if (!seen[k]) { seen[k] = 1; intrinsic.push(out, d); } });
  return out;
}

// ---- pki.cms.certsOnly (RFC 8551 sec. 3.8 / RFC 5652 sec. 5.1) --------------
// A certificate-management ("certs-only") message: a degenerate SignedData that conveys
// certificates and/or CRLs and signs nothing. Documented by the @primitive block in cms-verify.js
// (the @module pki.cms home).
var KNOWN_CERTS_ONLY_OPTS = { crls: 1, pem: 1 };

// A single entity or an array of them -> a dense array (empty when the argument is nullish).
// reqDenseArray snapshots the array structure and refuses a sparse hole or a nullish entry
// (M15), so a caller array that mutates under iteration cannot reintroduce a hole.
function _certsOnlyList(v, what) {
  if (v == null) return [];
  return intrinsic.isArray(v) ? _b.reqDenseArray(v, what) : [v];
}

// Normalize one caller-supplied certificate/CRL to validated raw DER: snapshot the byte source at
// the door so a later mutation cannot swap the bytes (M15), accept a PEM block, then parse it with
// `parseFn` so a non-<thing> -- including a tagged CertificateChoices / RevocationInfoChoice
// alternative, whose first byte is a context tag rather than 0x30 -- is a typed cms/bad-input and is
// never embedded (M9/M10/M11). `pemLabel` is the PEM armor type.
function _normEntityDer(v, what, pemLabel, parseFn) {
  var der;
  if (guard.bytes.isByteSource(v)) {
    der = guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
    if (der[0] !== 0x30) {
      var decoded = pkix.pemDecodeLenient(intrinsic.bufToString(der, "latin1"), pemLabel);
      if (decoded === null) throw _err("cms/bad-input", what + " must be a plain DER " + pemLabel + " (a tagged alternative is not permitted) or a PEM block");
      der = decoded;
    }
  } else if (typeof v === "string") {
    var d2 = pkix.pemDecodeLenient(v, pemLabel);
    if (d2 === null) throw _err("cms/bad-input", what + " PEM is not a " + pemLabel + " block");
    der = d2;
  } else {
    throw _err("cms/bad-input", what + " must be a DER Buffer or a PEM string");
  }
  try { parseFn(der); }
  catch (e) { throw _err("cms/bad-input", what + " is not a valid " + pemLabel, e); }
  return der;
}
function _parseX509(der) { return x509.parse(der); }
function _parseCrl(der) { return crlSchema.parse(der); }

function certsOnly(certs, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.certsOnly options");
  guard.identifier.assertKnownKeys(opts, KNOWN_CERTS_ONLY_OPTS, _err, "cms/bad-input", "unknown opts field ");
  var certList = _certsOnlyList(certs, "certificates");
  var crlList = _certsOnlyList(opts.crls, "crls");
  // RFC 8551 sec. 3.8 conveys "certificates and/or CRLs"; a message with neither conveys nothing.
  if (!certList.length && !crlList.length) throw _err("cms/bad-input", "a certs-only message must carry at least one certificate or CRL (RFC 8551 sec. 3.8)");
  // Each entity validated + snapshotted at the door, then DER-sorted + deduped (X.690 sec. 11.6).
  var certDers = intrinsic.sort(_dedupe(intrinsic.map(certList, function (c) { return _normEntityDer(c, "a certificate", "CERTIFICATE", _parseX509); })), intrinsic.compare);
  var crlDers = intrinsic.sort(_dedupe(intrinsic.map(crlList, function (c) { return _normEntityDer(c, "a CRL", "X509 CRL", _parseCrl); })), intrinsic.compare);
  // The degenerate SignedData (RFC 5652 sec. 5.1): version 1 (all choices plain, id-data, no signer),
  // an empty digestAlgorithms + signerInfos, an id-data encapContentInfo with eContent ABSENT, and the
  // caller certificates [0] / crls [1]. The strict re-parse enforces the version<->contents coupling.
  var encap = b.sequence([b.oid(OID_DATA)]);
  var sdFields = [b.integer(1n), b.set([]), encap];
  if (certDers.length) intrinsic.push(sdFields, b.contextConstructed(0, intrinsic.bufferConcat(certDers)));   // [0] IMPLICIT SET OF
  if (crlDers.length) intrinsic.push(sdFields, b.contextConstructed(1, intrinsic.bufferConcat(crlDers)));     // [1] IMPLICIT SET OF
  intrinsic.push(sdFields, b.set([]));                                                                        // signerInfos SET OF {}
  var signedData = b.sequence(sdFields);
  var contentInfo = b.sequence([b.oid(OID_SIGNED_DATA), b.explicit(0, signedData)]);
  return opts.pem ? pkix.pemEncode(contentInfo, "CMS", frameworkError.PemError) : contentInfo;
}

function _toBuf(v, what) {
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmsError, "cms/bad-input", what);
  throw _err("cms/bad-input", what + " must be a Buffer");
}

// ---- pki.cms.countersign (RFC 5652 sec. 11.4) ------------------------------
// A countersignature is a SignerInfo (Countersignature ::= SignerInfo) over the contents of the
// countersigned SignerInfo's signature OCTET STRING, never the eContent, attached as the
// id-countersignature unsigned attribute. It reuses the whole build+sign flow (resolveSignScheme /
// _buildSid / _buildSignedAttrs / signOverTbs); only the preimage (the target signature octets) and
// the omitted content-type are the deltas, and the orchestrator splices the [1] unsignedAttrs into
// an existing SignedData while preserving the targeted SignerInfo's signed bytes BYTE-FOR-BYTE.

// Resolve opts.signerIndex (a number, an array of numbers, or "all"; default 0) to primary indices.
function _resolveSignerIndices(spec, n) {
  if (spec == null) { if (n < 1) throw _err("cms/bad-input", "the SignedData carries no SignerInfo to countersign"); return [0]; }
  if (spec === "all") { var all = []; for (var i = 0; i < n; i++) all.push(i); return all; }
  var arr = Array.isArray(spec) ? spec : [spec];
  if (!arr.length) throw _err("cms/bad-input", "signerIndex must select at least one signer");
  arr.forEach(function (i) { if (typeof i !== "number" || !Number.isInteger(i) || i < 0 || i >= n) throw _err("cms/bad-input", "signerIndex out of range: " + i); });
  return arr;
}

// Build one countersignature value (RFC 5652 sec. 11.4) over `targetSigOctets`: message-digest bound
// to digest(targetSigOctets) under the countersignature's own digestAlgorithm, content-type omitted,
// signed through the same per-algorithm scheme machinery as a top-level signer.
function _buildCountersignature(targetSigOctets, countersigner, opts) {
  var so = countersigner || {};
  var certDer = _normCertDer(so.cert);
  var cert = x509.parse(certDer);
  var scheme = signScheme.resolveSignScheme(cert, so, opts.signedAttributes === false, _signE);
  var sidv = _buildSid(cert, opts.sid === "ski");
  var soKey = so.key;   // read once, here -- the SignerIdentifier above is already fixed to `cert`
  return Promise.resolve().then(function () {
    if (opts.signedAttributes === false) return null;   // sign the target signature octets directly
    return _digest(scheme.digest, targetSigOctets).then(function (md) {
      var pairs = [{ type: O("messageDigest"), values: [b.octetString(md)] }];
      if (opts.signingTime !== false) pairs.push({ type: O("signingTime"), values: [_timeValue(opts.signingTime)] });
      var extra = _resolveAttrPairs(opts.additionalSignedAttributes, "a countersignature signed attribute value");
      extra.forEach(function (p) { if (p.type === O("contentType")) throw _err("cms/bad-input", "a countersignature must not carry a content-type attribute (RFC 5652 sec. 11.4)"); });
      return _buildSignedAttrs(pairs.concat(extra));
    });
  }).then(function (attrs) {
    return signScheme.signOverTbs(scheme, soKey, attrs ? attrs.setOf : targetSigOctets, _signE).then(function (sig) {
      var fields = [b.integer(BigInt(sidv.version)), sidv.sid, scheme.digestAlgId];
      if (attrs) fields.push(attrs.wire);          // [0] IMPLICIT signedAttrs
      fields.push(scheme.sigAlgId, b.octetString(sig));
      return { value: b.sequence(fields), certDer: certDer };
    });
  });
}

// Build the [1] IMPLICIT unsignedAttrs bytes for a SignerInfo, merging `newCsValues` into the single
// id-countersignature attribute (RFC 5652 sec. 11: one instance per type, multiple values), and
// keeping every other unsigned attribute and every existing countersignature value verbatim.
function _mergeCountersig(uaNode, newCsValues) {
  var CS = O("countersignature");
  var others = [], csValues = [];
  if (uaNode) uaNode.children.forEach(function (attr) {
    if (asn1.read.oid(attr.children[0]) === CS) attr.children[1].children.forEach(function (v) { csValues.push(v.bytes); });
    else others.push(attr.bytes);
  });
  newCsValues.forEach(function (v) { csValues.push(v); });
  var csAttr = b.sequence([b.oid(CS), b.set(csValues)]);
  var setOf = b.set(others.concat([csAttr]));
  var wire = Buffer.from(setOf); wire[0] = 0xA1;   // SET OF -> [1] IMPLICIT UnsignedAttributes
  return wire;
}

// Append countersignature values to a SignerInfo node, preserving version / sid / digestAlgorithm /
// signedAttrs / signatureAlgorithm / signature BYTE-FOR-BYTE (the signed preimage), only adding the
// [1] unsignedAttrs. Returns the new SignerInfo bytes.
function _appendCountersigs(siNode, newCsValues) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var hasUa = last.tagClass === "context" && last.tagNumber === 1;
  var base = (hasUa ? kids.slice(0, kids.length - 1) : kids).map(function (k) { return k.bytes; });
  base.push(_mergeCountersig(hasUa ? last : null, newCsValues));
  return b.sequence(base);
}

// Splice countersignature values into the j-th countersignature VALUE of a SignerInfo node (nested
// countersignature, RFC 5652 sec. 11.4). Returns the new SignerInfo bytes.
function _spliceNested(siNode, j, newCsValues) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var CS = O("countersignature");
  if (!last || last.tagClass !== "context" || last.tagNumber !== 1) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var found = false;
  var attrs = last.children.map(function (attr) {
    if (asn1.read.oid(attr.children[0]) !== CS) return attr.bytes;
    var values = attr.children[1].children;
    if (j < 0 || j >= values.length) throw _err("cms/bad-input", "countersignatureOf out of range: " + j);
    found = true;
    return b.sequence([b.oid(CS), b.set(values.map(function (v, vi) { return vi === j ? _appendCountersigs(v, newCsValues) : v.bytes; }))]);
  });
  if (!found) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var setOf = b.set(attrs); var wire = Buffer.from(setOf); wire[0] = 0xA1;
  var base = kids.slice(0, kids.length - 1).map(function (k) { return k.bytes; });
  base.push(wire);
  return b.sequence(base);
}

// The signature-value octets of a SignerInfo node: the last universal OCTET STRING, i.e. the last
// child unless a [1] IMPLICIT unsignedAttrs (a prior countersignature) follows it.
function _signatureOctets(siNode) {
  var kids = siNode.children;
  var last = kids[kids.length - 1];
  var sigNode = (last.tagClass === "context" && last.tagNumber === 1) ? kids[kids.length - 2] : last;
  return asn1.read.octetString(sigNode);
}

// The sec. 11.4 preimage for a target: the primary SignerInfo's signature octets, or (nested) the
// j-th countersignature value's signature octets.
function _targetPreimage(siNode, opts) {
  if (opts.countersignatureOf == null) return _signatureOctets(siNode);
  var last = siNode.children[siNode.children.length - 1];
  var CS = O("countersignature");
  if (!last || last.tagClass !== "context" || last.tagNumber !== 1) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var attr = last.children.filter(function (a) { return asn1.read.oid(a.children[0]) === CS; })[0];
  if (!attr) throw _err("cms/bad-input", "the target signer carries no countersignature to countersign");
  var values = attr.children[1].children;
  var j = opts.countersignatureOf;
  if (typeof j !== "number" || !Number.isInteger(j) || j < 0 || j >= values.length) throw _err("cms/bad-input", "countersignatureOf out of range: " + j);
  return _signatureOctets(values[j]);
}

// pki.cms.countersign -- documented by the @primitive block in cms-verify.js (the @module pki.cms home).
// Documented `-> Promise`, so a fault leaves as a rejection (guard-async).
function countersign(cmsInput, signers, opts) {
  // Every caller-owned argument copied at entry and released when the call settles; see the note
  // on the same call in x509-sign. `signerIndex` and `countersignatureOf` select which signature is
  // countersigned, so a late read could attach the countersignature to a different one.
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [cmsInput, "the CMS message"], [signers, "the signer list"], [opts, "pki.cms.countersign options"],
  ], _countersign);
}

function _countersign(cmsInput, signers, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "cms/bad-input", "pki.cms.countersign options");
  guard.identifier.assertKnownKeys(opts, KNOWN_COUNTERSIGN_OPTS, _err, "cms/bad-input", "unknown opts field ");
  var list = Array.isArray(signers) ? signers : [signers];
  if (!list.length) throw _err("cms/bad-input", "pki.cms.countersign requires at least one countersigner");
  if (opts.signingTime != null && opts.signingTime !== false) guard.time.assertValid(opts.signingTime, _err, "cms/bad-input", "signingTime");
  var der = pkix.coerceToDer(cmsInput, { pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CmsError, prefix: "cms" });
  // cms.parse throws a typed cms/* error on a malformed input (mirroring verify's own parse call); a
  // structurally-valid but non-SignedData CMS (an EnvelopedData) parses without a signerInfos array.
  var parsed = cms.parse(der);
  if (!Array.isArray(parsed.signerInfos)) throw _err("cms/bad-input", "pki.cms.countersign input is not a CMS SignedData");
  var targets = _resolveSignerIndices(opts.signerIndex, parsed.signerInfos.length);
  var root = asn1.decode(der);
  var sd = root.children[1].children[0];
  var sdKids = sd.children;
  var siSet = sdKids[sdKids.length - 1];

  // Build every countersignature value (target x countersigner), then splice into the node tree.
  var jobs = [];
  targets.forEach(function (t) {
    var preimage = _targetPreimage(siSet.children[t], opts);
    list.forEach(function (cs) { jobs.push({ t: t, p: _buildCountersignature(preimage, cs, opts) }); });
  });
  return Promise.all(jobs.map(function (j) { return j.p; })).then(function (built) {
    var byTarget = {}, certDers = [];
    built.forEach(function (res, i) { (byTarget[jobs[i].t] = byTarget[jobs[i].t] || []).push(res.value); certDers.push(res.certDer); });

    var newSiSet = b.set(siSet.children.map(function (siNode, idx) {
      if (!byTarget[idx]) return siNode.bytes;
      return opts.countersignatureOf == null ? _appendCountersigs(siNode, byTarget[idx]) : _spliceNested(siNode, opts.countersignatureOf, byTarget[idx]);
    }));

    // Rebuild SignedData: version, digestAlgorithms (unchanged, since a countersignature digest is not a
    // SignedData digestAlgorithm), encapContentInfo, certificates [0]?, crls [1]?, the new signerInfos.
    var certsNode = null, crlsNode = null;
    for (var i = 3; i < sdKids.length - 1; i++) {
      if (sdKids[i].tagClass === "context" && sdKids[i].tagNumber === 0) certsNode = sdKids[i];
      else if (sdKids[i].tagClass === "context" && sdKids[i].tagNumber === 1) crlsNode = sdKids[i];
    }
    var existing = [];
    if (certsNode) certsNode.children.forEach(function (c) { existing.push(c.bytes); });
    if (opts.certificates !== false) certDers.forEach(function (d) { existing.push(d); });
    var allCerts = _dedupe(existing).sort(Buffer.compare);   // X.690 sec. 11.6

    var newSdFields = [sdKids[0].bytes, sdKids[1].bytes, sdKids[2].bytes];   // version, digestAlgs, encap (raw)
    if (allCerts.length) newSdFields.push(b.contextConstructed(0, Buffer.concat(allCerts)));
    if (crlsNode) newSdFields.push(crlsNode.bytes);
    newSdFields.push(newSiSet);
    var newCi = b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(newSdFields))]);
    return opts.pem ? pkix.pemEncode(newCi, "CMS", frameworkError.PemError) : newCi;
  });
}

// Coverage residual: three defensive branches are unreachable through the shipped path.
//   * `_skiValue`'s `cert.extensions || []` fallback. x509.parse always surfaces `extensions`
//     as an array (empty when absent), so the `|| []` never fires.
//   * `_assertKeyMatchesScheme`'s `key.algorithm || {}`. A WebCrypto CryptoKey always carries
//     an `algorithm`, so the `|| {}` fallback never fires.
//   * `_assertKeyMatchesScheme`'s `!ka.hash` guard. An `imp.hash` is set only for an RSA
//     scheme, which requires `ka.name` to already equal the RSA name (else the earlier name
//     check throws); an RSA CryptoKey always carries a `hash`, so `!ka.hash` never fires.
// Countersign-side residuals also unreachable through the shipped path:
//   * `_resolveSignerIndices`'s `n < 1` throw. A parsed SignedData always carries at least one
//     SignerInfo, so the default index [0] is always in range.
//   * `_spliceNested`'s no-countersignature / index-out-of-range / not-found throws. The same node
//     is validated by `_targetPreimage` first (it computes the nested preimage before the build), so
//     by the time `_spliceNested` re-walks it those conditions cannot hold; the checks are
//     belt-and-suspenders against a future caller reordering the two.
//   * the `crls [1]` preservation branches in `countersign`. pki.cms.sign never emits a crls field,
//     so a store this producer countersigns never carries one to preserve.
module.exports = {
  sign: sign, countersign: countersign, certsOnly: certsOnly,
  // @internal -- the signer-descriptor field tables, for a verb that AUTHORS signer descriptors
  // from its own caller's options and gates them at its own door.
  KNOWN_SIGNER_CERT_KEYS: KNOWN_SIGNER_CERT_KEYS,
  KNOWN_SIGNER_KEY_ONLY_KEYS: KNOWN_SIGNER_KEY_ONLY_KEYS,
};
