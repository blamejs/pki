// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.tuf: The Update Framework metadata verification.
 *
 * The signing preimage here is a RE-SERIALIZATION, which is the one place this toolkit does that on
 * purpose: TUF signs the canonical JSON form of the `signed` object, so there is no raw byte range to
 * surface and the encoder IS the wire format. Every asymmetry between reading the transport bytes and
 * writing the canonical ones is therefore a signature bypass, which is why the encoder gets
 * known-answer vectors built from the rules rather than from the implementation.
 *
 * Canonical JSON, from the encoder the reference implementation ships:
 *   - object keys lexically sorted, compared by code point
 *   - no whitespace anywhere; `,` between members and `:` between key and value
 *   - in a string, ONLY `\` and `"` are escaped, each with a single backslash; a literal control
 *     character is emitted as itself
 *   - true / false / null as those literals, integers in decimal
 *   - a float is refused, not rounded
 *
 * A KEYID is "a hexdigest of the SHA-256 hash of the canonical form of the key", and the
 * specification says clients MUST calculate each one to verify it is correct for its key, so a
 * metadata file cannot list a key under an identifier that is not its own.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function codeAsync(p) { try { await p; return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function cj(v) { return pki.tuf.canonicalJson(v).toString("utf8"); }

// ---------------------------------------------------------------------------
// Canonical JSON, against answers written from the rules
// ---------------------------------------------------------------------------
function runCanonical() {
  var CASES = [
    ["an empty object", {}, "{}"],
    ["an empty array", [], "[]"],
    ["members in order", { a: 1, b: 2 }, '{"a":1,"b":2}'],
    ["members out of order are sorted", { b: 2, a: 1 }, '{"a":1,"b":2}'],
    ["nested objects are sorted at every level", { a: { c: 1, b: 2 } }, '{"a":{"b":2,"c":1}}'],
    ["arrays keep their order", [3, 1, 2], "[3,1,2]"],
    ["the three literals", [true, false, null], "[true,false,null]"],
    ["a negative integer", { v: -7 }, '{"v":-7}'],
    ["zero", { v: 0 }, '{"v":0}'],
    ["a quote is escaped", { a: 'x"y' }, '{"a":"x\\"y"}'],
    ["a backslash is escaped", { a: "x\\y" }, '{"a":"x\\\\y"}'],
    ["an empty string", { a: "" }, '{"a":""}'],
    ["no whitespace is emitted", { a: [1, { b: 2 }] }, '{"a":[1,{"b":2}]}'],
  ];
  CASES.forEach(function (c) {
    check("J: " + c[0], cj(c[1]) === c[2]);
  });

  /* Only backslash and quote are escaped. A literal control character is emitted
     as itself, which is what makes this encoding NOT JSON.stringify: that would
     write \n and the signature would be over different bytes. */
  var withLf = cj({ a: "one\ntwo" });
  check("J: a literal newline in a string is emitted raw, not as an escape",
    withLf === '{"a":"one\ntwo"}' && withLf.indexOf("\\n") === -1);
  check("J: and that is where JSON.stringify would differ",
    JSON.stringify({ a: "one\ntwo" }).indexOf("\\n") !== -1);
  var withTab = cj({ a: "one\ttwo" });
  check("J: a literal tab is emitted raw too", withTab === '{"a":"one\ttwo"}');

  /* Non-ASCII is emitted as UTF-8, never as a \u escape. */
  var utf8 = pki.tuf.canonicalJson({ a: "é" });
  check("J: a non-ASCII character is emitted as UTF-8 bytes",
    utf8.length === 10 && utf8[6] === 0xc3 && utf8[7] === 0xa9);

  /* Keys are compared by code point, which is not what a default sort does for a
     character outside the basic plane: a surrogate pair sorts below U+FFFF under
     UTF-16 code-unit comparison and above it by code point. */
  var astral = "\u{1F600}";        // U+1F600, a surrogate pair in UTF-16
  var bmpHigh = "�";          // U+FFFD, one code unit
  var sorted = cj((function () { var o = {}; o[astral] = 1; o[bmpHigh] = 2; return o; })());
  check("J: keys sort by code point, so an astral key follows a high BMP key",
    sorted.indexOf(bmpHigh) < sorted.indexOf(astral));
  check("J: and a default UTF-16 sort would have put them the other way",
    [astral, bmpHigh].sort()[0] === astral);

  /* A float is refused rather than rounded: the reference encoder cannot write
     one, so metadata a conforming signer produced never contains one. */
  check("J: a float is refused", code(function () { pki.tuf.canonicalJson({ a: 1.5 }); }) === "tuf/bad-input");
  check("J: a number past the exact-integer range is refused",
    code(function () { pki.tuf.canonicalJson({ a: Math.pow(2, 53) }); }) === "tuf/bad-input");
  check("J: NaN and Infinity are refused",
    code(function () { pki.tuf.canonicalJson({ a: NaN }); }) === "tuf/bad-input" &&
    code(function () { pki.tuf.canonicalJson({ a: Infinity }); }) === "tuf/bad-input");
  check("J: undefined is refused, since it has no encoding",
    code(function () { pki.tuf.canonicalJson({ a: undefined }); }) === "tuf/bad-input");
  check("J: a function is refused", code(function () { pki.tuf.canonicalJson({ a: function () {} }); }) === "tuf/bad-input");

  /* Canonical JSON admits objects, arrays, strings, integers, booleans and null, and this encoder already
     refuses a float, a function, undefined, a BigInt, NaN and Infinity. A built-in exotic is none of the
     admitted types either, and it was encoded as a plain object instead of refused: every own enumerable
     key, and nothing else. So a Date became "{}", a Map became "{}", and a Buffer became an index map of
     its bytes.
     This output is the preimage a TUF signature covers, so a field that encodes to "{}" is a field the
     signature does not cover while it remains in the caller's object: the signed form and the document
     the caller believes they signed differ, and nothing says so. Refusing is the only verdict that keeps
     the two the same. `guard.identifier.isPlainRecord` is the existing home for the distinction. */
  /* Enumerating the exotics to refuse loses: a denylist of the JS built-ins still admitted every HOST
     object, which have internal state and no enumerable keys, so a Blob, a stream, a CryptoKey, an
     X509Certificate, a WebAssembly object and a collection iterator each encoded as "{}" after the named
     built-ins were refused. The line is drawn by PROTOTYPE instead: canonical JSON encodes a plain record,
     which is an object whose prototype is Object.prototype or null, and nothing else. That admits every
     document TUF actually carries and refuses every class, named or not, including ones that do not exist
     yet. */
  var EXOTIC = [
    ["a Date", new Date(0)],
    ["a Map", new Map()],
    ["a Set", new Set()],
    ["a Buffer", Buffer.from("ab")],
    ["a Uint8Array", new Uint8Array(2)],
    ["a DataView", new DataView(new ArrayBuffer(2))],
    ["a RegExp", /x/],
    ["an Error", new Error("x")],
    ["a Promise", Promise.resolve(1)],
    ["a boxed String", new String("x")],
    ["a Map iterator", new Map([[1, 2]]).entries()],
    ["an array iterator", [1, 2][Symbol.iterator]()],
    ["a class instance", new (function Thing() { this.a = 1; })()],
    ["an X509Certificate", new (require("crypto").X509Certificate)(
      pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE"))],
    ["a WeakMap", new WeakMap()],
  ];
  if (typeof Blob === "function") EXOTIC.push(["a Blob", new Blob(["x"])]);
  // A host class reached off the global rather than named, since not every runtime carries it.
  var wasm = global.WebAssembly;
  if (wasm && wasm.Module) {
    EXOTIC.push(["a WebAssembly.Module", new wasm.Module(
      new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]))]);
  }
  var exoticRefused = 0;
  for (var ei = 0; ei < EXOTIC.length; ei++) {
    var val = EXOTIC[ei][1];
    if (code(function () { pki.tuf.canonicalJson({ a: val }); }) === "tuf/bad-input") exoticRefused++;
  }
  check("J2: every built-in exotic is refused rather than encoded as a plain object (" +
    exoticRefused + "/" + EXOTIC.length + ")", exoticRefused === EXOTIC.length);
  check("J2a: ...including at the TOP level, not only as a member",
    code(function () { pki.tuf.canonicalJson(new Date(0)); }) === "tuf/bad-input" &&
    code(function () { pki.tuf.canonicalJson(Buffer.from("ab")); }) === "tuf/bad-input");
  /* CONTROL: the admitted types still encode, so the refusal above did not narrow the format. A nested
     plain object and array are the shapes every TUF document is built from. */
  check("J2b: CONTROL a plain object, an array and a null-prototype record still encode",
    cj({ b: [1, { a: "x" }], a: null }) === "{\"a\":null,\"b\":[1,{\"a\":\"x\"}]}" &&
    cj(Object.assign(Object.create(null), { z: 1, a: 2 })) === "{\"a\":2,\"z\":1}");
  /* A subclassed Array is still an array: the array arm runs before the object arm and reads it by index,
     which is what canonical JSON asks for, so narrowing the OBJECT arm must not have narrowed that. */
  var SubArray = function () {};
  SubArray.prototype = Object.create(Array.prototype);
  var subbed = new Array(0); subbed.push(1, 2);
  check("J2c: CONTROL an array still encodes by index, the array arm running first",
    cj(subbed) === "[1,2]" && cj([]) === "[]");
  /* A revoked Proxy throws on every operation, including the prototype read the check makes, so the
     refusal has to be the module's own and not whatever the Proxy raised. */
  var revocable = Proxy.revocable({ a: 1 }, {});
  revocable.revoke();
  check("J2d: a revoked Proxy is refused with a typed error rather than its own TypeError",
    code(function () { pki.tuf.canonicalJson({ a: revocable.proxy }); }) === "tuf/bad-input");

  /* An unpaired surrogate has no UTF-8 encoding, and the conversion to bytes replaces it with U+FFFD
     rather than failing. Two documents that differ only in that code unit would then have IDENTICAL
     signing bytes, so a signature made over one verifies over the other while the parsed document a
     caller reads back is the other one. Both halves of the range are refused, and in keys as well as
     values, because a targets map is keyed by path and the key is what a client looks a target up by.
     A WELL-FORMED pair built from the same two halves must still encode, or the check would be
     refusing every non-BMP character rather than the malformed ones. */
  var HI = String.fromCharCode(0xd800), LO = String.fromCharCode(0xdc00);
  check("J: a lone high surrogate is refused as a value",
    code(function () { pki.tuf.canonicalJson({ a: HI }); }) === "tuf/bad-input");
  check("J: a lone low surrogate is refused as a value",
    code(function () { pki.tuf.canonicalJson({ a: LO }); }) === "tuf/bad-input");
  check("J: a lone high surrogate is refused as a KEY",
    code(function () { var o = {}; o[HI] = 1; return pki.tuf.canonicalJson(o); }) === "tuf/bad-input");
  check("J: a lone low surrogate is refused as a KEY",
    code(function () { var o = {}; o[LO] = 1; return pki.tuf.canonicalJson(o); }) === "tuf/bad-input");
  check("J: a reversed pair is refused, the low half coming first",
    code(function () { pki.tuf.canonicalJson({ a: LO + HI }); }) === "tuf/bad-input");
  check("J: a high surrogate at the end of a string is refused",
    code(function () { pki.tuf.canonicalJson({ a: "ok" + HI }); }) === "tuf/bad-input");
  /* CONTROL: the well-formed pair encodes to the four UTF-8 bytes of U+10000, and U+FFFD itself
     encodes, so the refusals above are about malformed sequences and not about these characters. */
  check("J: CONTROL a well-formed surrogate pair encodes to the code point's UTF-8",
    pki.tuf.canonicalJson(HI + LO).equals(Buffer.from("22f0908080" + "22", "hex")));
  check("J: CONTROL U+FFFD itself still encodes",
    pki.tuf.canonicalJson(String.fromCharCode(0xfffd)).equals(Buffer.from("22efbfbd22", "hex")));
  /* Depth is bounded, so a nested document cannot drive the recursion. */
  var deep = {}, cur = deep;
  for (var i = 0; i < 200; i++) { cur.a = {}; cur = cur.a; }
  check("J: a document deeper than the cap is refused",
    code(function () { pki.tuf.canonicalJson(deep); }) === "tuf/too-deep");
}

// ---------------------------------------------------------------------------
// Keys and key identifiers
// ---------------------------------------------------------------------------
function makeEd25519Key() {
  var kp = crypto.generateKeyPairSync("ed25519");
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var raw = pki.asn1.decode(spki).children[1].content.subarray(1);
  var key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: raw.toString("hex") } };
  return { kp: kp, key: key, keyId: pki.tuf.keyId(key) };
}
function makeEcdsaKey() {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var pem = kp.publicKey.export({ format: "pem", type: "spki" });
  var key = { keytype: "ecdsa", scheme: "ecdsa-sha2-nistp256", keyval: { public: pem } };
  return { kp: kp, key: key, keyId: pki.tuf.keyId(key) };
}

function runKeyIds() {
  var ed = makeEd25519Key();
  /* The identifier is the hex SHA-256 of the key's own canonical form, computed
     here independently of the library. */
  var want = crypto.createHash("sha256").update(pki.tuf.canonicalJson(ed.key)).digest("hex");
  check("K: a key identifier is the hex SHA-256 of the key's canonical form", ed.keyId === want);
  check("K: and it is 64 hex characters", ed.keyId.length === 64);
  /* A change anywhere in the key object changes the identifier, which is what
     makes listing a key under someone else's identifier detectable. */
  var altered = JSON.parse(JSON.stringify(ed.key));
  altered.scheme = "ed25519 ";
  check("K: altering any field changes the identifier", pki.tuf.keyId(altered) !== ed.keyId);
  check("K: a key missing keytype, scheme or keyval is refused",
    code(function () { pki.tuf.keyId({ scheme: "ed25519", keyval: { public: "00" } }); }) === "tuf/bad-key" &&
    code(function () { pki.tuf.keyId({ keytype: "ed25519", keyval: { public: "00" } }); }) === "tuf/bad-key" &&
    code(function () { pki.tuf.keyId({ keytype: "ed25519", scheme: "ed25519" }); }) === "tuf/bad-key");
}

// ---------------------------------------------------------------------------
// Metadata parsing and threshold verification
// ---------------------------------------------------------------------------
var EXPIRES = "2030-01-01T00:00:00Z";
var NOW = new Date("2027-01-01T00:00:00Z");

function signWith(signer, signedObj) {
  var preimage = pki.tuf.canonicalJson(signedObj);
  if (signer.key.keytype === "ed25519") {
    return crypto.sign(null, preimage, signer.kp.privateKey).toString("hex");
  }
  return crypto.sign("sha256", preimage, { key: signer.kp.privateKey, dsaEncoding: "der" }).toString("hex");
}
function metadataFor(signedObj, signers) {
  return Buffer.from(JSON.stringify({
    signatures: signers.map(function (s) { return { keyid: s.keyId, sig: signWith(s, signedObj) }; }),
    signed: signedObj,
  }));
}
function rootSigned(o) {
  o = o || {};
  var keys = {};
  (o.signers || []).forEach(function (s) { keys[s.keyId] = s.key; });
  return {
    _type: "root", spec_version: "1.0.31",
    version: o.version === undefined ? 1 : o.version,
    expires: o.expires || EXPIRES,
    consistent_snapshot: true,
    keys: keys,
    roles: o.roles || { root: { keyids: (o.signers || []).map(function (s) { return s.keyId; }),
      threshold: o.threshold === undefined ? 1 : o.threshold } },
  };
}

async function runVerify() {
  var a = makeEd25519Key(), b = makeEd25519Key(), c = makeEcdsaKey();

  var signed = rootSigned({ signers: [a] });
  var meta = pki.tuf.parseMetadata(metadataFor(signed, [a]));
  check("M1: metadata parses into its signed body and its signatures",
    meta.type === "root" && meta.version === 1 && meta.signatures.length === 1);
  check("M2: and the signed bytes are the canonical form of the signed body",
    Buffer.compare(meta.signedBytes, pki.tuf.canonicalJson(signed)) === 0);

  var v = await pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys, role: signed.roles.root });
  check("M3: a single signature meets a threshold of one", v.verified === true && v.keyIds.length === 1);

  /* `metadata.signedBytes` is a byte option, and the set the door admits has to be the set it handles.
     `guard.bytes.isByteSource` admits a DataView and an ArrayBuffer and the snapshot that copies these
     bytes took neither, so a caller who held the canonical bytes as the ArrayBuffer a fetch returned was
     refused for the container rather than for the content. Run on the VERIFYING metadata above, so the
     narrow operation is reached: the Buffer arm is the control that says so. */
  async function verifyWithSignedBytesAs(convert) {
    var m = { type: meta.type, version: meta.version, expires: meta.expires, signed: meta.signed,
      signatures: meta.signatures, signedBytes: convert(meta.signedBytes) };
    try {
      var r = await pki.tuf.verifySignatures({ metadata: m, keys: signed.keys, role: signed.roles.root });
      return r.verified === true ? "verified" : "unverified";
    } catch (e) { return (e && e.isPkiError === true) ? "throw:" + e.code : "UNTYPED:" + ((e && e.message) || e); }
  }
  var tufReps = [
    ["Buffer", await verifyWithSignedBytesAs(function (b) { return Buffer.from(b); })],
    ["Uint8Array", await verifyWithSignedBytesAs(function (b) { return new Uint8Array(Buffer.from(b)); })],
    ["DataView", await verifyWithSignedBytesAs(function (b) { var u = new Uint8Array(Buffer.from(b)); return new DataView(u.buffer); })],
    ["ArrayBuffer", await verifyWithSignedBytesAs(function (b) { return new Uint8Array(Buffer.from(b)).buffer; })],
  ];
  var tufBase = tufReps[0][1];
  var tufBad = tufReps.slice(1).filter(function (r) { return r[1] !== tufBase; });
  check("M3a: signedBytes verifies the same whichever byte representation holds it (" + tufBase +
    (tufBad.length ? "; diverged: " + tufBad.map(function (r) { return r[0] + " -> " + r[1]; }).join(" | ") : "") + ")",
    tufBase === "verified" && tufBad.length === 0);

  /* `opts.role` carries the authorization: which key ids may sign, and how many must. It is the CALLER's
     object, and an accessor answers every read separately. It was read four times: the presence check,
     the typeof, then `.keyids` and `.threshold`. A getter can therefore present a strict role to the
     checks and a lax one to the field reads, combining one role's authorized keys with another's
     threshold, so the verdict reports a document as meeting a threshold no role ever stated. The role is
     captured once and every field read comes off the capture. */
  var roleReads = 0;
  var strictRole = { keyids: signed.roles.root.keyids, threshold: 2 };
  var laxRole = { keyids: signed.roles.root.keyids, threshold: 1 };
  var sneakyOpts = { metadata: meta, keys: signed.keys };
  Object.defineProperty(sneakyOpts, "role", {
    enumerable: true,
    get: function () { roleReads += 1; return roleReads <= 3 ? strictRole : laxRole; },
  });
  var sneakyVerdict = null, sneakyCode = null;
  try { sneakyVerdict = await pki.tuf.verifySignatures(sneakyOpts); }
  catch (e) { sneakyCode = (e && e.code) || "NO-CODE"; }
  /* The document carries ONE signature. Read as the strict role it must fail the threshold of two; read
     as the lax one it meets a threshold of one. Whichever role the verb settles on, it must apply that
     SAME role's threshold, so a single read is the only outcome that is not a contradiction. */
  check("M3b: an accessor-backed role cannot pass the checks as one role and be applied as another (" +
    roleReads + " read(s), " + (sneakyCode || ("verified=" + sneakyVerdict.verified +
      " threshold=" + sneakyVerdict.threshold)) + ")",
    roleReads <= 1 && (sneakyCode !== null ||
      (sneakyVerdict.threshold === 2 && sneakyVerdict.verified === false)));
  /* CONTROL: a plain role object with a threshold of two still reports unmet rather than throwing, so the
     check above is reading a real verdict and not an unrelated refusal. */
  var twoThreshold = await pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
    role: { keyids: signed.roles.root.keyids, threshold: 2 } });
  check("M3c: CONTROL one signature against a threshold of two is reported unmet",
    twoThreshold.verified === false && twoThreshold.threshold === 2);

  /* TUF's canonical JSON admits no floating point, and every number the format carries is a version, a
     threshold or a length. A fractional token has to be refused while it is still TEXT: 1.0000000000000001
     converts to the Number 1, so an integer check after conversion sees a conforming document and the
     version reported is not the one the bytes state. The control is the same document with an integer. */
  var intBytes = metadataFor(signed, [a]);
  check("M3a: control -- the same document with an integer version parses",
    pki.tuf.parseMetadata(intBytes).version === 1);
  var fracBytes = Buffer.from(intBytes.toString("utf8").replace('"version":1', '"version":1.0000000000000001'));
  check("M3b: the fractional form was actually substituted, so M3c is not testing the same bytes",
    Buffer.compare(fracBytes, intBytes) !== 0 && fracBytes.toString("utf8").indexOf("1.0000000000000001") > 0);
  check("M3c: a fractional version is refused rather than rounded to an integer",
    code(function () { return pki.tuf.parseMetadata(fracBytes); }) === "tuf/bad-json");
  check("M3d: and an exponent-form integer is refused for the same reason",
    code(function () {
      return pki.tuf.parseMetadata(Buffer.from(intBytes.toString("utf8").replace('"version":1', '"version":1e0')));
    }) === "tuf/bad-json");

  /* An ECDSA key and an Ed25519 key in one role, both counted. */
  var two = rootSigned({ signers: [a, c], threshold: 2 });
  var vt = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(metadataFor(two, [a, c])),
    keys: two.keys, role: two.roles.root });
  check("M4: an Ed25519 and an ECDSA signature both count toward one threshold",
    vt.verified === true && vt.keyIds.length === 2);

  /* "each SIGNATURE which is counted towards the THRESHOLD MUST have a unique
     KEYID. Even if a KEYID is listed more than once ... a client MUST NOT count
     more than one verified SIGNATURE from that KEYID." */
  var dupSigned = rootSigned({ signers: [a, b], threshold: 2 });
  var dupBytes = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: signWith(a, dupSigned) }, { keyid: a.keyId, sig: signWith(a, dupSigned) }],
    signed: dupSigned,
  }));
  var dv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(dupBytes),
    keys: dupSigned.keys, role: dupSigned.roles.root });
  check("M5: one key signing twice counts once, so a threshold of two is not met",
    dv.verified === false && dv.keyIds.length === 1);

  /* A signature from a key the role does not list contributes nothing. */
  var outsider = makeEd25519Key();
  var oneSigner = rootSigned({ signers: [a] });
  var withOutsider = Buffer.from(JSON.stringify({
    signatures: [{ keyid: outsider.keyId, sig: signWith(outsider, oneSigner) }],
    signed: oneSigner,
  }));
  var ov = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(withOutsider),
    keys: oneSigner.keys, role: oneSigner.roles.root });
  check("M6: a signature from a key the role does not list counts for nothing",
    ov.verified === false && ov.keyIds.length === 0);

  /* A signature that does not verify counts for nothing, and does not throw:
     whether a threshold was met is a verdict about the metadata. */
  var badSig = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: "00".repeat(64) }], signed: oneSigner,
  }));
  var bv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(badSig),
    keys: oneSigner.keys, role: oneSigner.roles.root });
  check("M7: a signature that does not verify counts for nothing", bv.verified === false);

  /* The signature is over the canonical form, so altering the body anywhere
     breaks it -- including in a way that leaves the transport JSON valid. */
  var tampered = JSON.parse(metadataFor(oneSigner, [a]).toString("utf8"));
  tampered.signed.version = 2;
  var tv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(Buffer.from(JSON.stringify(tampered))),
    keys: tampered.signed.keys, role: tampered.signed.roles.root });
  check("M8: altering the signed body breaks the signature", tv.verified === false);

  /* A key listed under an identifier that is not its own is refused: the
     specification says a client MUST calculate each identifier. */
  var mislabeled = JSON.parse(JSON.stringify(oneSigner));
  mislabeled.keys = {}; mislabeled.keys[b.keyId] = a.key;
  mislabeled.roles.root.keyids = [b.keyId];
  check("M9: a key listed under an identifier that is not its own is refused",
    await codeAsync(pki.tuf.verifySignatures({
      metadata: pki.tuf.parseMetadata(metadataFor(mislabeled, [a])),
      keys: mislabeled.keys, role: mislabeled.roles.root,
    })) === "tuf/bad-key");

  /* Shape refusals on the wrapper. */
  check("M10: a document with no signatures array is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signed: oneSigner }))); }) === "tuf/bad-metadata");
  check("M11: a document with no signed body is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [] }))); }) === "tuf/bad-metadata");
  check("M12: a signed body with no _type is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [], signed: { version: 1, expires: EXPIRES } }))); }) === "tuf/bad-metadata");
  check("M13: a version that is not a positive integer is refused",
    code(function () { pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], version: 0 }), [a])); }) === "tuf/bad-metadata");
  check("M14: an expires that is not a date-time is refused",
    code(function () { pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], expires: "soon" }), [a])); }) === "tuf/bad-metadata");
  check("M15: a duplicate JSON member is refused before anything is read",
    code(function () { pki.tuf.parseMetadata(Buffer.from('{"signed":{},"signed":{}}')); }) === "tuf/duplicate-member");
  check("M16: a threshold that is not a positive integer is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: { keyids: [a.keyId], threshold: 0 } })) === "tuf/bad-input");

  /* Expiry is a separate question from signatures, asked against a caller instant. */
  check("M17: metadata within its expiry passes the expiry check",
    pki.tuf.checkExpiry(meta, NOW) === true);
  var stale = pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], expires: "2026-01-01T00:00:00Z" }), [a]));
  check("M18: metadata past its expiry is refused, which is the freeze-attack check",
    code(function () { pki.tuf.checkExpiry(stale, NOW); }) === "tuf/expired");
}

// ---------------------------------------------------------------------------
// Root rotation: the chain walk
// ---------------------------------------------------------------------------
async function runRootChain() {
  var k1 = makeEd25519Key(), k2 = makeEd25519Key(), k3 = makeEd25519Key();

  var r1 = rootSigned({ signers: [k1], version: 1 });
  var r1Bytes = metadataFor(r1, [k1]);

  /* "Version N+1 of the root metadata file MUST have been signed by: (1) a
     THRESHOLD of keys specified in the trusted root metadata file (version N),
     and (2) a THRESHOLD of keys specified in the new root metadata file." */
  var r2 = rootSigned({ signers: [k2], version: 2 });
  var r2BothBytes = metadataFor(r2, [k1, k2]);      // old key and new key
  var updated = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2BothBytes], now: NOW });
  check("T1: a root signed by both the old and the new keys is adopted",
    updated.version === 2 && updated.updated === true);

  var r2OldOnly = metadataFor(r2, [k1]);
  check("T2: a root signed only by the OLD keys is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2OldOnly], now: NOW })) === "tuf/root-unsigned");
  var r2NewOnly = metadataFor(r2, [k2]);
  check("T3: a root signed only by the NEW keys is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2NewOnly], now: NOW })) === "tuf/root-unsigned");

  /* "The version number of the new root metadata (version N+1) MUST be exactly
     the version in the trusted root metadata (version N) incremented by one." */
  var r3 = rootSigned({ signers: [k3], version: 3 });
  var r3Bytes = metadataFor(r3, [k2, k3]);
  check("T4: a root that skips a version is refused, so no intermediate is passed over",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r3Bytes], now: NOW })) === "tuf/bad-root-version");
  /* The full chain, walked in order. */
  var walked = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2BothBytes, r3Bytes], now: NOW });
  check("T5: the chain is walked to the latest root, each link verified against the one before",
    walked.version === 3 && walked.updated === true);
  check("T6: and the adopted root's keys are the LAST root's, not the first",
    Object.keys(walked.root.keys).indexOf(k3.keyId) !== -1 &&
    Object.keys(walked.root.keys).indexOf(k1.keyId) === -1);

  /* A candidate whose version goes backwards is a rollback attempt. */
  var r1Again = metadataFor(rootSigned({ signers: [k1], version: 1 }), [k1]);
  check("T7: a candidate at the version already trusted is refused as a rollback",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r2BothBytes, candidates: [r1Again], now: NOW })) === "tuf/bad-root-version");

  /* With no candidates the trusted root stands, and says it was not updated. */
  var none = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [], now: NOW });
  check("T8: with no candidate the trusted root stands and reports no update",
    none.version === 1 && none.updated === false);

  /* The candidate list is read and parsed before the first await, so a call made with no candidate cannot
     be handed a chain while the trusted root is being verified. Without that, the cap on the chain length
     was applied to the empty list and the walk then read whatever the array had grown to. */
  var growing = [];
  var grownPromise = pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: growing, now: NOW });
  growing.push(r2BothBytes, r3Bytes);
  var grown = await grownPromise;
  check("T8a: candidates appended while the trusted root is being verified are not adopted",
    grown.version === 1 && grown.updated === false && grown.walked.length === 0);
  /* The control: the same two candidates present before the call ARE adopted, so T8a is the late addition
     being ignored rather than the walk failing. */
  var pinnedFirst = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2BothBytes, r3Bytes], now: NOW });
  check("T8b: control -- the same candidates supplied before the call are adopted",
    pinnedFirst.version === 3 && pinnedFirst.updated === true);

  /* Expiry is checked on the root the walk ENDS on, which is step 5.3.10 of the specification: the
     freeze-attack check follows the chain walk of steps 5.3.2 to 5.3.9 rather than preceding it, and
     no step checks an intermediate root's expiry. Checking the trusted root first is what a client
     that has been offline runs into: its pinned root has lapsed, a correctly signed unexpired
     successor is sitting in front of it, and it cannot adopt it without replacing the anchor by
     some other means. With no candidates the root the walk ends on IS the trusted root, so an
     expired root with nothing to move to is still refused. */
  var expiredRoot = metadataFor(rootSigned({ signers: [k1], version: 1, expires: "2026-01-01T00:00:00Z" }), [k1]);
  check("T9: an expired trusted root with nothing to move to is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: expiredRoot, candidates: [], now: NOW })) === "tuf/expired");

  var expiredV1 = rootSigned({ signers: [k1], version: 1, expires: "2026-01-01T00:00:00Z" });
  var freshV2 = rootSigned({ signers: [k1], version: 2 });
  var recovered = await pki.tuf.updateRoot({
    trustedRoot: metadataFor(expiredV1, [k1]),
    candidates: [metadataFor(freshV2, [k1])], now: NOW,
  });
  check("T9a: an expired trusted root is superseded by an unexpired successor rather than blocking it",
    recovered.version === 2 && recovered.updated === true);

  /* And a lapsed root in the MIDDLE of the chain does not stop the catch-up either. */
  var midV2 = rootSigned({ signers: [k1], version: 2, expires: "2026-06-01T00:00:00Z" });
  var freshV3 = rootSigned({ signers: [k1], version: 3 });
  var acrossGap = await pki.tuf.updateRoot({
    trustedRoot: metadataFor(expiredV1, [k1]),
    candidates: [metadataFor(midV2, [k1]), metadataFor(freshV3, [k1])], now: NOW,
  });
  check("T9b: an expired intermediate root is walked through, no step checking its expiry",
    acrossGap.version === 3 && acrossGap.walked.length === 2);

  /* The check still bites where the specification puts it: on the root the chain ends on. */
  var expiredV2 = rootSigned({ signers: [k1], version: 2, expires: "2026-01-01T00:00:00Z" });
  check("T9c: a chain ending on an expired root is refused",
    await codeAsync(pki.tuf.updateRoot({
      trustedRoot: metadataFor(rootSigned({ signers: [k1], version: 1 }), [k1]),
      candidates: [metadataFor(expiredV2, [k1])], now: NOW,
    })) === "tuf/expired");

  /* A root whose own role threshold it does not meet is refused, which is the
     both-thresholds rule applied to the very first root a caller pins. */
  var underThreshold = rootSigned({ signers: [k1, k2], version: 1, threshold: 2 });
  var onlyOne = metadataFor(underThreshold, [k1]);
  check("T10: a trusted root that does not meet its own threshold is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: onlyOne, candidates: [], now: NOW })) === "tuf/root-unsigned");

  /* A root whose _type is not root is not a root. */
  var wrongType = rootSigned({ signers: [k1], version: 1 });
  wrongType._type = "targets";
  check("T11: a document whose _type is not root is refused as a root",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(wrongType, [k1]), candidates: [], now: NOW })) === "tuf/bad-metadata");
  /* A root with no root role cannot state who may sign it. */
  var noRole = rootSigned({ signers: [k1], version: 1 });
  delete noRole.roles.root;
  check("T12: a root that names no root role is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(noRole, [k1]), candidates: [], now: NOW })) === "tuf/bad-metadata");
}

// Every input guard, and the RSA key arm. A guard that never runs is a guard
// nobody has checked.
async function runGuards() {
  var a = makeEd25519Key();
  var signed = rootSigned({ signers: [a] });
  var meta = pki.tuf.parseMetadata(metadataFor(signed, [a]));

  /* An RSA key with the scheme the specification pairs with it. */
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaKey = { keytype: "rsa", scheme: "rsassa-pss-sha256",
    keyval: { public: rsa.publicKey.export({ format: "pem", type: "spki" }) } };
  var rsaId = pki.tuf.keyId(rsaKey);
  var rsaKeys = {}; rsaKeys[rsaId] = rsaKey;
  var rsaSigned = { _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES,
    keys: rsaKeys, roles: { root: { keyids: [rsaId], threshold: 1 } } };
  var rsaSig = crypto.sign("sha256", pki.tuf.canonicalJson(rsaSigned), {
    key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }).toString("hex");
  var rsaMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: rsaId, sig: rsaSig }], signed: rsaSigned })));
  var rv = await pki.tuf.verifySignatures({ metadata: rsaMeta, keys: rsaKeys, role: rsaSigned.roles.root });
  check("G1: an RSA key signing under RSASSA-PSS over SHA-256 verifies", rv.verified === true);
  /* The padding is not read from the document: a PKCS#1 v1.5 signature under the
     same key does not verify, since the scheme the specification pairs with an
     rsa key is PSS. */
  var v15 = crypto.sign("sha256", pki.tuf.canonicalJson(rsaSigned), rsa.privateKey).toString("hex");
  var v15Meta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: rsaId, sig: v15 }], signed: rsaSigned })));
  check("G2: a PKCS#1 v1.5 signature under the same RSA key does not verify",
    (await pki.tuf.verifySignatures({ metadata: v15Meta, keys: rsaKeys, role: rsaSigned.roles.root })).verified === false);
  /* An unreadable PEM, and a key type this build does not read. */
  var badPem = { keytype: "ecdsa", scheme: "ecdsa-sha2-nistp256", keyval: { public: "not a pem" } };
  var bpId = pki.tuf.keyId(badPem); var bpKeys = {}; bpKeys[bpId] = badPem;
  var bpSigned = { _type: "root", version: 1, expires: EXPIRES, keys: bpKeys,
    roles: { root: { keyids: [bpId], threshold: 1 } } };
  var bpMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: bpId, sig: "00" }], signed: bpSigned })));
  check("G3: a public key that is not a readable PEM is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: bpMeta, keys: bpKeys, role: bpSigned.roles.root })) === "tuf/bad-key");
  var alien = { keytype: "dilithium", scheme: "dilithium", keyval: { public: "00" } };
  var alId = pki.tuf.keyId(alien); var alKeys = {}; alKeys[alId] = alien;
  var alSigned = { _type: "root", version: 1, expires: EXPIRES, keys: alKeys,
    roles: { root: { keyids: [alId], threshold: 1 } } };
  var alMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: alId, sig: "00" }], signed: alSigned })));
  check("G4: a key type this build does not read is refused, not skipped",
    await codeAsync(pki.tuf.verifySignatures({ metadata: alMeta, keys: alKeys, role: alSigned.roles.root })) === "tuf/unsupported-key");
  /* An ed25519 key of the wrong length, and one that is not a full-order point. */
  var shortEd = { keytype: "ed25519", scheme: "ed25519", keyval: { public: "00".repeat(31) } };
  var seId = pki.tuf.keyId(shortEd); var seKeys = {}; seKeys[seId] = shortEd;
  var seSigned = { _type: "root", version: 1, expires: EXPIRES, keys: seKeys,
    roles: { root: { keyids: [seId], threshold: 1 } } };
  var seMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: seId, sig: "00".repeat(64) }], signed: seSigned })));
  check("G5: an ed25519 key that is not 32 bytes is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: seMeta, keys: seKeys, role: seSigned.roles.root })) === "tuf/bad-key");
  var lowOrder = { keytype: "ed25519", scheme: "ed25519", keyval: { public: "00".repeat(32) } };
  var loId = pki.tuf.keyId(lowOrder); var loKeys = {}; loKeys[loId] = lowOrder;
  var loSigned = { _type: "root", version: 1, expires: EXPIRES, keys: loKeys,
    roles: { root: { keyids: [loId], threshold: 1 } } };
  var loMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: loId, sig: "00".repeat(64) }], signed: loSigned })));
  check("G6: an ed25519 key that is not a full-order point is refused before any verify",
    await codeAsync(pki.tuf.verifySignatures({ metadata: loMeta, keys: loKeys, role: loSigned.roles.root })) === "tuf/bad-key");
  /* A signature that is not hex counts for nothing rather than throwing: it is a
     statement this build cannot read, and the metadata may carry another that it
     can. */
  var badHexMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: "zz" }], signed: signed })));
  check("G7: a signature that is not hex counts for nothing",
    (await pki.tuf.verifySignatures({ metadata: badHexMeta, keys: signed.keys, role: signed.roles.root })).verified === false);

  /* The input guards on each verb. */
  check("G8: keyId refuses a non-object", code(function () { pki.tuf.keyId("x"); }) === "tuf/bad-key" &&
    code(function () { pki.tuf.keyId([]); }) === "tuf/bad-key");
  check("G9: parseMetadata refuses a document that is not an object",
    code(function () { pki.tuf.parseMetadata(Buffer.from("[]")); }) === "tuf/bad-metadata");
  check("G10: parseMetadata refuses a signature entry missing keyid or sig",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [{ keyid: "a" }], signed: signed }))); }) === "tuf/bad-metadata" &&
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [7], signed: signed }))); }) === "tuf/bad-metadata");
  check("G11: checkExpiry refuses something that is not parsed metadata",
    code(function () { pki.tuf.checkExpiry({}, NOW); }) === "tuf/bad-input");
  check("G12: checkExpiry refuses an instant that is not a Date",
    code(function () { pki.tuf.checkExpiry(meta, "2027-01-01"); }) === "tuf/bad-input");
  check("G13: verifySignatures refuses a keys map that is not an object",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: [], role: signed.roles.root })) === "tuf/bad-input");
  check("G14: verifySignatures refuses a keyid that is not 64 characters",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: { keyids: ["short"], threshold: 1 } })) === "tuf/bad-metadata");
  check("G15: verifySignatures refuses a role naming a key the map does not carry",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: { keyids: ["ab".repeat(32)], threshold: 1 } })) === "tuf/bad-metadata");
  check("G16: verifySignatures refuses something that is not parsed metadata",
    await codeAsync(pki.tuf.verifySignatures({ metadata: {}, keys: signed.keys, role: signed.roles.root })) === "tuf/bad-input");

  /* updateRoot's own guards. */
  var rootBytes = metadataFor(rootSigned({ signers: [a], version: 1 }), [a]);
  check("G17: updateRoot refuses candidates that are not an array",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: "x", now: NOW })) === "tuf/bad-input");
  check("G18: updateRoot refuses an instant that is not a Date",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: [], now: 1 })) === "tuf/bad-input");
  check("G19: updateRoot omits candidates entirely and the trusted root stands",
    (await pki.tuf.updateRoot({ trustedRoot: rootBytes, now: NOW })).updated === false);
  check("G20: updateRoot refuses a chain past the cap", await (async function () {
    var many = []; for (var i = 0; i < 1100; i++) many.push(rootBytes);
    return await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: many, now: NOW }));
  })() === "tuf/bad-input");
  var k2 = makeEd25519Key();
  var dupVersion = metadataFor(rootSigned({ signers: [k2], version: 2 }), [a, k2]);
  check("G21: two candidates stating one version are refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: [dupVersion, dupVersion], now: NOW })) === "tuf/bad-root-version");
  var noKeys = rootSigned({ signers: [a], version: 1 });
  delete noKeys.keys;
  check("G22: a root carrying no keys map is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(noKeys, [a]), candidates: [], now: NOW })) === "tuf/bad-metadata");
  var noRoles = rootSigned({ signers: [a], version: 1 });
  delete noRoles.roles;
  check("G23: a root carrying no roles map is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(noRoles, [a]), candidates: [], now: NOW })) === "tuf/bad-metadata");

  /* The code-point comparison's own equal-prefix arm. */
  check("G24: a key that is a prefix of another sorts before it",
    cj((function () { var o = {}; o.ab = 1; o.a = 2; return o; })()) === '{"a":2,"ab":1}');
  check("G25: and two equal keys cannot both exist, so the comparison's equal arm is the same key",
    cj({ a: 1 }) === '{"a":1}');
}

// ---------------------------------------------------------------------------
// The declared algorithm binds the key that verifies
// ---------------------------------------------------------------------------
// A key names its own algorithm in `keytype` and `scheme`, and the identifier is the hash of the whole
// key object, so those two fields are as authenticated as the key material. What must not happen is the
// verification running under an algorithm the key material happens to support while the document says
// another: a key declared `ecdsa` whose PEM holds an RSA public key would otherwise verify an RSA
// signature, because importing a PEM and then verifying lets the key material pick the algorithm. The
// keytype/scheme pair the specification lists (section 4.2.2) is checked, and the imported key must
// actually be of that type.
// A key's identifier is checked against the key, and then the SAME key material must be what verifies.
// The signature loop awaits a verification per signature while the authorized map holds the caller's key
// objects, so a caller that replaces a later key's `keyval.public` in that window has the identifier
// checked against one key and the signature verified under another. A threshold can then be met by
// material nobody authorized: the identifier says B, the bytes say C, and C's signature counts as B's.
async function runKeyMaterialAcrossAwaits() {
  var a = makeEd25519Key(), b = makeEd25519Key(), c = makeEd25519Key();
  // B's key object is the one the caller may mutate; its identifier is computed from the ORIGINAL.
  var liveB = { keytype: "ed25519", scheme: "ed25519", keyval: { public: b.key.keyval.public } };
  var liveBId = pki.tuf.keyId(liveB);
  var signedObj = {
    _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES,
    consistent_snapshot: true,
    keys: (function () { var k = {}; k[a.keyId] = a.key; k[liveBId] = liveB; return k; })(),
    roles: { root: { keyids: [a.keyId, liveBId], threshold: 2 } },
  };
  var preimage = pki.tuf.canonicalJson(signedObj);
  var sigA = crypto.sign(null, preimage, a.kp.privateKey).toString("hex");
  var sigC = crypto.sign(null, preimage, c.kp.privateKey).toString("hex");   // C is NOT authorized
  var bytes = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: sigA }, { keyid: liveBId, sig: sigC }],
    signed: signedObj,
  }));
  var meta = pki.tuf.parseMetadata(bytes);

  var pending = pki.tuf.verifySignatures({ metadata: meta, keys: signedObj.keys, role: signedObj.roles.root });
  liveB.keyval.public = c.key.keyval.public;      // B's material becomes C's, mid-verification
  var got;
  try { got = await pending; } catch (_e) { got = null; }
  check("A10: a key whose material is replaced during verification does not count toward the threshold",
    got === null || got.keyIds.indexOf(liveBId) === -1);
  check("A11: so a two-key threshold is not met by one authorized signature and one unauthorized key",
    got === null || got.verified === false);

  /* CONTROLS. Two genuinely authorized signatures meet the threshold, and the same document with C
     properly listed and named verifies, so A10 and A11 are about the replacement. */
  var okSigned = {
    _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES, consistent_snapshot: true,
    keys: (function () { var k = {}; k[a.keyId] = a.key; k[b.keyId] = b.key; return k; })(),
    roles: { root: { keyids: [a.keyId, b.keyId], threshold: 2 } },
  };
  var okPre = pki.tuf.canonicalJson(okSigned);
  var okBytes = Buffer.from(JSON.stringify({
    signatures: [
      { keyid: a.keyId, sig: crypto.sign(null, okPre, a.kp.privateKey).toString("hex") },
      { keyid: b.keyId, sig: crypto.sign(null, okPre, b.kp.privateKey).toString("hex") },
    ],
    signed: okSigned,
  }));
  var okV = await pki.tuf.verifySignatures({
    metadata: pki.tuf.parseMetadata(okBytes), keys: okSigned.keys, role: okSigned.roles.root,
  });
  check("A12: CONTROL two authorized signatures meet a threshold of two",
    okV.verified === true && okV.keyIds.length === 2);

  /* The THRESHOLD is caller-owned too, and it is compared against the count at the very end, after a
     verification has been awaited per signature. Lowered during that window it would be the number the
     verdict is measured against, so a one-of-two document would report verified. */
  var oneOfTwo = {
    _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES, consistent_snapshot: true,
    keys: (function () { var k = {}; k[a.keyId] = a.key; k[b.keyId] = b.key; return k; })(),
    roles: { root: { keyids: [a.keyId, b.keyId], threshold: 2 } },
  };
  var onePre = pki.tuf.canonicalJson(oneOfTwo);
  var oneBytes = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: crypto.sign(null, onePre, a.kp.privateKey).toString("hex") }],
    signed: oneOfTwo,
  }));
  var liveRole = { keyids: [a.keyId, b.keyId], threshold: 2 };
  var rolePending = pki.tuf.verifySignatures({
    metadata: pki.tuf.parseMetadata(oneBytes), keys: oneOfTwo.keys, role: liveRole,
  });
  liveRole.threshold = 1;                        // lowered while the verification is in flight
  var roleGot;
  try { roleGot = await rolePending; } catch (_e) { roleGot = null; }
  check("A13: a threshold lowered during verification is not the threshold the verdict uses",
    roleGot === null || (roleGot.verified === false && roleGot.threshold === 2));
  /* CONTROL: the same single signature DOES meet a threshold of one when that is the threshold from the
     start, so A13 is about the mutation and not about the document. */
  var realOne = await pki.tuf.verifySignatures({
    metadata: pki.tuf.parseMetadata(oneBytes), keys: oneOfTwo.keys,
    role: { keyids: [a.keyId, b.keyId], threshold: 1 },
  });
  check("A14: CONTROL one authorized signature meets a threshold of one",
    realOne.verified === true && realOne.threshold === 1);

  /* The METADATA is the third caller-owned input to this verb, alongside the keys and the role, and the
     loop re-reads `signedBytes` for every signature with an await between. Two signatures over DIFFERENT
     documents can then each verify against the bytes that were present on their own turn, and together
     satisfy a threshold that no single document ever met. A carries version 1 and B carries version 2;
     the buffer is swapped to B's document immediately after the call. */
  var docV1 = {
    _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES, consistent_snapshot: true,
    keys: (function () { var k = {}; k[a.keyId] = a.key; k[b.keyId] = b.key; return k; })(),
    roles: { root: { keyids: [a.keyId, b.keyId], threshold: 2 } },
  };
  var docV2 = JSON.parse(JSON.stringify(docV1));
  docV2.version = 2;
  var preV1 = pki.tuf.canonicalJson(docV1), preV2 = pki.tuf.canonicalJson(docV2);
  check("A15: the two documents' canonical forms are the same length, so one overwrites the other",
    preV1.length === preV2.length);
  var mixed = {
    type: "root", version: 1,
    signedBytes: Buffer.from(preV1),
    signatures: [
      { keyid: a.keyId, sig: crypto.sign(null, preV1, a.kp.privateKey).toString("hex") },
      { keyid: b.keyId, sig: crypto.sign(null, preV2, b.kp.privateKey).toString("hex") },
    ],
  };
  var mixedPending = pki.tuf.verifySignatures({
    metadata: mixed, keys: docV1.keys, role: { keyids: [a.keyId, b.keyId], threshold: 2 },
  });
  preV2.copy(mixed.signedBytes);                 // the signed bytes become the other document's
  var mixedGot;
  try { mixedGot = await mixedPending; } catch (_e) { mixedGot = null; }
  check("A16: signatures over two different documents cannot together meet one threshold",
    mixedGot === null || mixedGot.verified === false);
  /* CONTROL: each signature does verify against its OWN document, so A16 is about the swap rather than
     either signature being bad. */
  var justA = await pki.tuf.verifySignatures({
    metadata: { type: "root", version: 1, signedBytes: Buffer.from(preV1),
      signatures: [{ keyid: a.keyId, sig: crypto.sign(null, preV1, a.kp.privateKey).toString("hex") }] },
    keys: docV1.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 },
  });
  var justB = await pki.tuf.verifySignatures({
    metadata: { type: "root", version: 2, signedBytes: Buffer.from(preV2),
      signatures: [{ keyid: b.keyId, sig: crypto.sign(null, preV2, b.kp.privateKey).toString("hex") }] },
    keys: docV1.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 },
  });
  check("A17: CONTROL each signature verifies against its own document",
    justA.verified === true && justB.verified === true);

  /* The instant is a caller-owned Date, and `updateRoot` read it twice: once to validate its type and once
     for the freeze-attack check at the end, with a signature verification awaited between. A Date is
     mutable, so the instant the expiry is judged at need not be the instant validation began at: a root
     that has expired by the supplied time passes if that Date is moved back while the chain is walked. */
  var expiredByThen = rootSigned({ signers: [a], version: 1, expires: "2030-01-01T00:00:00Z" });
  var lateBytes = metadataFor(expiredByThen, [a]);
  var movable = new Date("2040-01-01T00:00:00Z");     // the root has expired by this instant
  var latePending = pki.tuf.updateRoot({ trustedRoot: lateBytes, candidates: [], now: movable });
  movable.setTime(new Date("2027-01-01T00:00:00Z").getTime());   // moved back, mid-validation
  var lateCode = "NO-THROW";
  try { await latePending; } catch (e) { lateCode = e.code || e.message; }
  check("A18: expiry is judged at the instant supplied when validation began, not a later mutation of it",
    lateCode === "tuf/expired");
  /* CONTROLS: the same root passes at an instant before it expires and fails at one after, so A18 is
     about the mutation rather than about the root or either date. */
  check("A19: CONTROL the root is valid at an instant before it expires",
    (await pki.tuf.updateRoot({ trustedRoot: lateBytes, candidates: [],
      now: new Date("2027-01-01T00:00:00Z") })).version === 1);
  check("A20: CONTROL and expired at one after",
    (await codeAsync(pki.tuf.updateRoot({ trustedRoot: lateBytes, candidates: [],
      now: new Date("2040-01-01T00:00:00Z") }))) === "tuf/expired");
}

async function runAlgorithmBinding() {
  var ed = makeEd25519Key();

  function rootWith(key, keyid, sigHex) {
    var signedObj = {
      _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES,
      consistent_snapshot: true,
      keys: (function () { var k = {}; k[keyid] = key; return k; })(),
      roles: { root: { keyids: [keyid], threshold: 1 } },
    };
    var sig = sigHex === undefined ? null : sigHex;
    var bytes = Buffer.from(JSON.stringify({
      signatures: [{ keyid: keyid, sig: sig === null ? "00" : sig }], signed: signedObj,
    }));
    return { signedObj: signedObj, meta: pki.tuf.parseMetadata(bytes) };
  }

  // An RSA key wearing the ecdsa label, with a real RSA signature over the real preimage.
  var rsaKp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaPem = rsaKp.publicKey.export({ format: "pem", type: "spki" });
  var mislabeled = { keytype: "ecdsa", scheme: "ecdsa-sha2-nistp256", keyval: { public: rsaPem } };
  var mislabeledId = pki.tuf.keyId(mislabeled);
  var shell = rootWith(mislabeled, mislabeledId, "00");
  var rsaSig = crypto.sign("sha256", pki.tuf.canonicalJson(shell.signedObj), rsaKp.privateKey).toString("hex");
  var forged = rootWith(mislabeled, mislabeledId, rsaSig);
  var fCode = await codeAsync(pki.tuf.verifySignatures({
    metadata: forged.meta, keys: forged.signedObj.keys, role: forged.signedObj.roles.root,
  }));
  var fVerified = false;
  if (fCode === "NO-THROW") {
    var r = await pki.tuf.verifySignatures({
      metadata: forged.meta, keys: forged.signedObj.keys, role: forged.signedObj.roles.root,
    });
    fVerified = r.verified === true;
  }
  check("A1: an RSA key declared as ecdsa does not verify an RSA signature", fVerified === false);
  check("A2: and it is refused as a malformed key rather than counted as a failed signature",
    fCode === "tuf/bad-key");

  // The mirror: an EC key wearing the rsa label.
  var ecKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecAsRsa = { keytype: "rsa", scheme: "rsassa-pss-sha256",
    keyval: { public: ecKp.publicKey.export({ format: "pem", type: "spki" }) } };
  var ecAsRsaId = pki.tuf.keyId(ecAsRsa);
  var m2 = rootWith(ecAsRsa, ecAsRsaId, "00");
  check("A3: an EC key declared as rsa is refused",
    (await codeAsync(pki.tuf.verifySignatures({
      metadata: m2.meta, keys: m2.signedObj.keys, role: m2.signedObj.roles.root,
    }))) === "tuf/bad-key");

  // A scheme the keytype does not pair with, the key material being the right type.
  var wrongScheme = { keytype: "ecdsa", scheme: "ed25519",
    keyval: { public: ecKp.publicKey.export({ format: "pem", type: "spki" }) } };
  var wsId = pki.tuf.keyId(wrongScheme);
  var m3 = rootWith(wrongScheme, wsId, "00");
  check("A4: a scheme the keytype does not pair with is refused",
    (await codeAsync(pki.tuf.verifySignatures({
      metadata: m3.meta, keys: m3.signedObj.keys, role: m3.signedObj.roles.root,
    }))) === "tuf/bad-key");

  // A curve other than P-256 under the ecdsa-sha2-nistp256 scheme, which names its curve.
  var p384 = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  var wrongCurve = { keytype: "ecdsa", scheme: "ecdsa-sha2-nistp256",
    keyval: { public: p384.publicKey.export({ format: "pem", type: "spki" }) } };
  var wcId = pki.tuf.keyId(wrongCurve);
  var m4 = rootWith(wrongCurve, wcId, "00");
  check("A5: a P-384 key under the nistp256 scheme is refused, the scheme naming its curve",
    (await codeAsync(pki.tuf.verifySignatures({
      metadata: m4.meta, keys: m4.signedObj.keys, role: m4.signedObj.roles.root,
    }))) === "tuf/bad-key");

  // The specification's own floor: "All RSA keys MUST be at least 2048 bits."
  var rsa1024 = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
  var weak = { keytype: "rsa", scheme: "rsassa-pss-sha256",
    keyval: { public: rsa1024.publicKey.export({ format: "pem", type: "spki" }) } };
  var weakId = pki.tuf.keyId(weak);
  var m5 = rootWith(weak, weakId, "00");
  check("A6: an RSA key under 2048 bits is refused",
    (await codeAsync(pki.tuf.verifySignatures({
      metadata: m5.meta, keys: m5.signedObj.keys, role: m5.signedObj.roles.root,
    }))) === "tuf/bad-key");

  // CONTROLS. Each legitimate pair still verifies, or the refusals above would be a blanket reject.
  var okEd = rootSigned({ signers: [ed] });
  var okEdMeta = pki.tuf.parseMetadata(metadataFor(okEd, [ed]));
  check("A7: CONTROL an ed25519 key with the ed25519 scheme still verifies",
    (await pki.tuf.verifySignatures({ metadata: okEdMeta, keys: okEd.keys, role: okEd.roles.root })).verified === true);
  var ec = makeEcdsaKey();
  var okEc = rootSigned({ signers: [ec] });
  var okEcMeta = pki.tuf.parseMetadata(metadataFor(okEc, [ec]));
  check("A8: CONTROL a P-256 key with the nistp256 scheme still verifies",
    (await pki.tuf.verifySignatures({ metadata: okEcMeta, keys: okEc.keys, role: okEc.roles.root })).verified === true);

  // And a real RSA key under its own declared pair verifies, so the rsa arm is not simply unreachable.
  var rsaKey = { keytype: "rsa", scheme: "rsassa-pss-sha256", keyval: { public: rsaPem } };
  var rsaId = pki.tuf.keyId(rsaKey);
  var rshell = rootWith(rsaKey, rsaId, "00");
  var pssSig = crypto.sign("sha256", pki.tuf.canonicalJson(rshell.signedObj), {
    key: rsaKp.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }).toString("hex");
  var rok = rootWith(rsaKey, rsaId, pssSig);
  check("A9: CONTROL a 2048-bit RSA key with the rsassa-pss-sha256 scheme verifies its own PSS signature",
    (await pki.tuf.verifySignatures({
      metadata: rok.meta, keys: rok.signedObj.keys, role: rok.signedObj.roles.root,
    })).verified === true);
}

function testSurface() {
  ["canonicalJson", "keyId", "parseMetadata", "verifySignatures", "checkExpiry", "updateRoot"].forEach(function (n) {
    check("pki.tuf." + n + " is exposed", typeof pki.tuf[n] === "function");
  });
}

async function run() {
  testSurface();
  runCanonical();
  runKeyIds();
  await runVerify();
  await runRootChain();
  await runGuards();
  await runAlgorithmBinding();
  await runKeyMaterialAcrossAwaits();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
