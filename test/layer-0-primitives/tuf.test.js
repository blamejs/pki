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

var path = require("path");
var spawnSync = require("child_process").spawnSync;

/** The key imports and signature checks one `verifySignatures` call performs, counted in a child
 *  process because the toolkit captures those operations when it loads. See the driver for why a count
 *  rather than a time budget. */
function countOps(shape, records) {
  var r = spawnSync(process.execPath,
    [path.join(__dirname, "..", "helpers", "count-tuf-crypto-ops.js"), shape, String(records)],
    { encoding: "utf8" });
  var line = String(r.stdout || "").trim();
  var out = { line: line, imports: -1, checks: -1, verified: "", records: -1 };
  line.split(" ").forEach(function (tok) {
    var at = tok.indexOf("=");
    if (at === -1) return;
    var name = tok.slice(0, at), value = tok.slice(at + 1);
    out[name] = (name === "verified" || name === "error") ? value : Number(value);
  });
  return out;
}

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
  /* Escaping only those two means the canonical form of a document holding a PEM is NOT a document a
     strict JSON reader accepts: the newlines inside the key land as raw bytes. This is the encoding the
     specification states, so it is pinned rather than fixed, and it is the reason `verifySignatures`
     reads the specification version from the parsed object's own field instead of from the bytes the
     signatures cover, which would be the stronger place for it. */
  var pemish = { keyval: { public: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n" } };
  var pemCanonical = pki.tuf.canonicalJson(pemish);
  check("J: a string holding newlines is emitted with them raw, this being the stated encoding",
    pemCanonical.indexOf(0x0a) >= 0 &&
    code(function () {
      pki.tuf.parseMetadata(Buffer.concat([Buffer.from('{"signatures":[],"signed":'), pemCanonical,
        Buffer.from("}")]));
    }) === "tuf/bad-json");
  /* Depth is bounded, so a nested document cannot drive the recursion. */
  var deep = {}, cur = deep;
  for (var i = 0; i < 200; i++) { cur.a = {}; cur = cur.a; }
  check("J: a document deeper than the cap is refused",
    code(function () { pki.tuf.canonicalJson(deep); }) === "tuf/too-deep");

  /* Depth bounds the recursion and says nothing about the OUTPUT. A value that shares one subarray with
     itself is a graph rather than a tree, and the walk expands every reference independently: `v = [v, v]`
     repeated n times is n levels deep and 2 to the n leaves wide. Measured on the unbudgeted encoder, 24
     levels produced 67,108,861 bytes in 1.8 seconds and 25 killed a 2 GiB heap with a fatal
     out-of-memory, from an input of 25 arrays. A shared output budget refuses before accumulating, so the
     cost is bounded by the budget rather than by the shape of the input. */
  function dag(levels) {
    var v = 0;
    for (var i = 0; i < levels; i++) v = [v, v];
    return v;
  }
  check("J: CONTROL a small shared-subarray graph still encodes, every reference expanded",
    cj(dag(3)) === "[[[0,0],[0,0]],[[0,0],[0,0]]]");
  check("J: a graph whose expansion exceeds the output budget is refused, not accumulated",
    code(function () { pki.tuf.canonicalJson(dag(24)); }) === "tuf/too-large");
  check("J: and the budget is on the OUTPUT, so a wide document under it still encodes",
    cj(dag(10)).length === 4093);
  /* The budget is in UTF-8 BYTES, which is the unit the returned buffer is measured in. Charging
     `text.length` counted UTF-16 code units instead, so a string outside the Basic Latin range
     undercharged by its encoded width: 1,048,574 CJK code points produced 3,145,724 bytes against a
     1,048,576-byte budget, each costing three bytes and charged as one. */
  var CJK = String.fromCharCode(0x4e00);
  check("J: CONTROL a CJK string inside the budget encodes, three bytes to the code point",
    pki.tuf.canonicalJson(CJK.repeat(1000)).length === 3002);
  check("J: a CJK string whose UTF-8 form exceeds the budget is refused, not undercharged",
    code(function () { pki.tuf.canonicalJson(CJK.repeat(1048574)); }) === "tuf/too-large");
  check("J: CONTROL and the same budget still refuses an oversized ASCII string",
    code(function () { pki.tuf.canonicalJson("a".repeat(1048600)); }) === "tuf/too-large");
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
var SPEC = "1.0.31";

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
  var body = {
    _type: "root", spec_version: o.specVersion === undefined ? "1.0.31" : o.specVersion,
    version: o.version === undefined ? 1 : o.version,
    expires: o.expires || EXPIRES,
    consistent_snapshot: true,
    keys: keys,
    /* All four top-level roles, because the specification sec. 4.3 states "A role for each of "root",
       "snapshot", "targets", and "timestamp" MUST be specified in the roles object". The three beyond
       root carry the same keys here: these fixtures exercise the root chain, and what matters is that
       a conforming root states them at all. `o.roles` overrides the whole map for the vectors that
       drive an omission. */
    roles: o.roles || (function () {
      var ids = (o.signers || []).map(function (s) { return s.keyId; });
      var th = o.threshold === undefined ? 1 : o.threshold;
      return {
        root: { keyids: ids, threshold: th },
        targets: { keyids: ids, threshold: 1 },
        snapshot: { keyids: ids, threshold: 1 },
        timestamp: { keyids: ids, threshold: 1 },
      };
    })(),
  };
  // `specVersion: null` omits the field entirely, which is the case TAP 6 forbids and the one a client
  // cannot match against the version it implements.
  if (o.specVersion === null) delete body.spec_version;
  return body;
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
    var m = { type: meta.type, specVersion: meta.specVersion, version: meta.version,
      expires: meta.expires, signed: meta.signed,
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

  /* An identifier is only skipped once a signature under it has SUCCEEDED, so a document repeating one
     identical FAILING record used to re-derive the key's material identity and re-run the verify for
     every repetition. Measured over a 414 KB body, 1000 repetitions of a single all-zero signature cost
     2000 key imports, 1000 signature checks and 1617 ms, all on metadata nothing has authenticated yet.
     A whole-input budget is asserted rather than a per-record ratio, which is the form that catches an
     input made of many cheap-looking records. The budget is set well clear of the instrumentation the
     coverage run adds, since a GREEN pass here measures 5 ms and the RED one measured 1617: anything
     between those two separates them, and the looser figure is the one that does not report a slow
     runner as a defect. The counting checks below carry the precise form of the same property. */
  var wideBody = rootSigned({ signers: [a] });
  wideBody.padding = "p".repeat(200000);
  var repeated = [];
  for (var rpt = 0; rpt < 1000; rpt++) repeated.push({ keyid: a.keyId, sig: "00".repeat(64) });
  var repeatedBytes = Buffer.from(JSON.stringify({ signatures: repeated, signed: wideBody }));
  var t5 = process.hrtime.bigint();
  var rv5 = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(repeatedBytes),
    keys: wideBody.keys, role: wideBody.roles.root });
  var ms5 = Number(process.hrtime.bigint() - t5) / 1e6;
  check("M5a: 1000 repetitions of one failing signature cost a bounded time (" + ms5.toFixed(0) +
    " ms for " + repeatedBytes.length + " bytes, verified " + rv5.verified + ")",
    ms5 < 1000 && rv5.verified === false && rv5.keyIds.length === 0);
  /* An identifier names ONE signature, the first the document lists for it, and a later entry for that
     same identifier is passed over. The specification caps the count at "one verified SIGNATURE from
     that KEYID", so a second entry cannot change the verdict it allows; what it can do is cost another
     hash of the whole signed body, which is work the document chooses. A document that lists a wrong
     signature for a key ahead of a right one is therefore read as that key not having signed. */
  var afterBad = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: "00".repeat(64) }, { keyid: a.keyId, sig: signWith(a, dupSigned) }],
    signed: dupSigned,
  }));
  var abv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(afterBad),
    keys: dupSigned.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 } });
  check("M5b: the first signature an identifier carries is the one asked, so a second entry for it " +
    "neither counts nor costs a check",
  abv.verified === false && abv.keyIds.length === 0);
  /* CONTROL: the order is what decides it, not the presence of two entries. The same pair listed the
     other way round counts, which is how M5b is read as "the first one is asked" rather than as "a
     repeated identifier is refused". */
  var goodFirst = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: signWith(a, dupSigned) }, { keyid: a.keyId, sig: "00".repeat(64) }],
    signed: dupSigned,
  }));
  var gfv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(goodFirst),
    keys: dupSigned.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 } });
  check("M5b1: CONTROL the same two entries with the good one first count, and the document is read",
    gfv.verified === true && gfv.keyIds.length === 1 && gfv.keyIds[0] === a.keyId);
  /* The keys MAP is a caller record whose members are read inside a loop that awaits, so it gets the
     same door the metadata and the role already have: a plain object carrying plain values at every
     identifier the role names. Either a Proxy or an accessor would answer each read separately, and
     the identifier filed under a key is checked against the copy the first read produced. */
  var doorSigned = rootSigned({ signers: [a] });
  var doorMeta = pki.tuf.parseMetadata(metadataFor(doorSigned, [a]));
  var proxyKeys = new Proxy(JSON.parse(JSON.stringify(doorSigned.keys)), {});
  check("M5k: a keys map that is a Proxy is refused rather than read through its traps",
    await codeAsync(pki.tuf.verifySignatures({ metadata: doorMeta, keys: proxyKeys,
      role: doorSigned.roles.root })) === "tuf/bad-input");
  var getterKeys = {};
  Object.defineProperty(getterKeys, a.keyId, {
    enumerable: true, configurable: true,
    get: function () { return a.key; },
  });
  check("M5l: and one answering an identifier the role names through a getter likewise",
    await codeAsync(pki.tuf.verifySignatures({ metadata: doorMeta, keys: getterKeys,
      role: doorSigned.roles.root })) === "tuf/bad-input");
  /* CONTROL: the same document with a plain keys map verifies, so the two refusals are about how the
     map answers rather than about the document or the key. */
  check("M5m: CONTROL the same document with a plain keys map verifies",
    (await pki.tuf.verifySignatures({ metadata: doorMeta, keys: doorSigned.keys,
      role: doorSigned.roles.root })).verified === true);
  /* The THIRD walk in this verb with the same shape. A role's own identifiers are resolved to keys,
     and each resolution deep-copies the key and hashes its canonical form, so an identifier the role
     REPEATS asked for that work again although the answer was already filed. Measured, 7500
     repetitions beside a 500 KB key took 10.2 seconds, synchronously, before the first await and
     before anything had authenticated a byte. The budget sits between the measured GREEN of 6 ms and
     the measured RED of 2142 ms at this size, loose enough that a coverage run on a slow machine is
     not reported as a defect. */
  var fatKey = { keytype: "ed25519", scheme: "ed25519",
    keyval: { public: a.key.keyval.public }, comment: "c".repeat(500000) };
  var fatId = pki.tuf.keyId(fatKey);
  var fatKeys = {}; fatKeys[fatId] = fatKey;
  var fatBody = { _type: "targets", spec_version: SPEC, version: 1, expires: EXPIRES, targets: {} };
  var fatMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signed: fatBody, signatures: [],
  })));
  var repeatedIds = [];
  for (var fat = 0; fat < 2000; fat++) repeatedIds.push(fatId);
  var t5r = process.hrtime.bigint();
  var rv5r = await pki.tuf.verifySignatures({ metadata: fatMeta, keys: fatKeys,
    role: { keyids: repeatedIds, threshold: 1 } });
  var ms5r = Number(process.hrtime.bigint() - t5r) / 1e6;
  check("M5r: a role repeating one identifier 2000 times beside a 500 KB key costs a bounded time (" +
    ms5r.toFixed(0) + " ms, verified " + rv5r.verified + ")",
  ms5r < 1200 && rv5r.verified === false);
  /* And the question is named by the signature's VALUE rather than by its spelling. Hexadecimal is read
     in either case, so one 64-byte value has up to 2^128 spellings, and a repeat recognized by the text
     recognizes none of them: 1000 spellings of one value reopened the walk above in full.
     COUNTED rather than timed. An ed25519 signature whose S is not canonical is refused before the body
     is hashed, so the cheapest hostile value measures nothing, and the expensive one costs a couple of
     hundred milliseconds at the metadata size cap, which is too close to a passing run to assert on.
     The three shapes are counted against each other instead. */
  var opsRepeat = countOps("repeats", 1000);
  check("M5c: 1000 repetitions of one signature ask for one import and one check (" +
    opsRepeat.line + ")",
  opsRepeat.records === 1000 && opsRepeat.imports === 1 && opsRepeat.checks === 1 &&
    opsRepeat.verified === "false");
  var opsSpell = countOps("spellings", 1000);
  check("M5c1: and 1000 spellings of one signature ask for the same one check (" +
    opsSpell.line + ")",
  opsSpell.records === 1000 && opsSpell.imports === 1 && opsSpell.checks === 1 &&
    opsSpell.verified === "false");
  /* 1000 genuinely DIFFERENT signature values, all naming one key, cost one check. No memo recognizes
     them, each would hash the whole signed body, and a document carrying them is how a verifier reading
     the document's list was made to do a second of work on bytes nothing had authenticated. The walk
     reads the keys the ROLE names instead, so the document chooses which signature each key offers and
     the trusted side chooses how many are asked. */
  var opsDistinct = countOps("distinct", 1000);
  check("M5c2: 1000 different signature values under one key are one check, the specification " +
    "counting at most one signature from a key either way (" + opsDistinct.line + ")",
  opsDistinct.records === 1000 && opsDistinct.checks === 1 && opsDistinct.imports === 1 &&
    opsDistinct.verified === "false");
  /* CONTROL: the bound is the ROLE's key count, and every key it names is asked. A bound that dropped
     verifications instead would read a signed document as unsigned, which is the failure the check
     above must not be bought with. 40 keys, 40 signatures, 40 checks. */
  var opsKeys = countOps("keys", 40);
  check("M5c3: CONTROL one signature each for 40 keys the role names is 40 checks, all of them asked (" +
    opsKeys.line + ")",
  opsKeys.records === 40 && opsKeys.checks === 40 && opsKeys.imports === 40 &&
    opsKeys.verified === "false");
  /* CONTROL: reading the value rather than the text does not narrow what verifies. A good signature
     spelled in upper case is the same signature and still meets the threshold, so M5c1 is about the
     repeat being recognized and not about upper case being refused. */
  var upperOk = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: signWith(a, dupSigned).toUpperCase() }], signed: dupSigned,
  }));
  var uov = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(upperOk),
    keys: dupSigned.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 } });
  check("M5d: CONTROL a good signature spelled in upper case still counts",
    uov.verified === true && uov.keyIds.length === 1 && uov.keyIds[0] === a.keyId);
  /* A signature this build cannot read counts for nothing and does not throw, whatever shape it takes,
     and it does not stop the walk reaching the keys listed after it. The decode happens before the
     verify is asked, so these records are the ones that ask nothing at all. Each shape is driven with
     the unreadable value under one key and a good signature under ANOTHER, which is what separates "the
     walk went on" from "a second entry for one key was tried": a walk that threw, or that stopped at
     the first key it could not read, would hide the signature that met the threshold. */
  var unreadableSigs = ["", "zz", "abc", "0", "00", "00".repeat(500), "0f".repeat(31)];
  var unreadableGaps = [];
  for (var ui = 0; ui < unreadableSigs.length; ui++) {
    var uBytes = Buffer.from(JSON.stringify({
      signatures: [{ keyid: a.keyId, sig: unreadableSigs[ui] }, { keyid: b.keyId, sig: signWith(b, dupSigned) }],
      signed: dupSigned,
    }));
    var uv;
    try {
      uv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(uBytes),
        keys: dupSigned.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 } });
    } catch (ue) { unreadableGaps.push(JSON.stringify(unreadableSigs[ui].slice(0, 8)) + " threw " + ue.code); continue; }
    if (!(uv.verified === true && uv.keyIds.length === 1 && uv.keyIds[0] === b.keyId)) {
      unreadableGaps.push(JSON.stringify(unreadableSigs[ui].slice(0, 8)) + " -> " + JSON.stringify(uv.keyIds));
    }
  }
  check("M5e: " + unreadableSigs.length + " unreadable or wrong-length signatures neither throw nor " +
    "stop the walk reaching a key listed after them: " + unreadableGaps.join("; "),
  unreadableGaps.length === 0);
  /* And on their own they are a verdict rather than a fault: whether a threshold was met is a statement
     about the metadata, and a signature that cannot be read did not meet it. */
  var onlyUnreadable = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: unreadableSigs[0] }, { keyid: b.keyId, sig: unreadableSigs[1] }],
    signed: dupSigned,
  }));
  var ouv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(onlyUnreadable),
    keys: dupSigned.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 } });
  check("M5f: and on their own they resolve false rather than throwing",
    ouv.verified === false && ouv.keyIds.length === 0);
  /* `parseMetadata` holds a record's `sig` to being a string, so a non-string one arrives only on the
     hand-assembled route, which this verb also accepts. It is the same answer there: the record asks
     nothing, and it does not stop the walk reaching a key listed after it. */
  var dupPre = pki.tuf.canonicalJson(dupSigned);
  function verifyAssembled(sigs) {
    return pki.tuf.verifySignatures({
      metadata: { type: "root", specVersion: SPEC, version: 1, signed: dupSigned,
        signedBytes: Buffer.from(dupPre), signatures: sigs },
      keys: dupSigned.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 },
    });
  }
  var nonString = await verifyAssembled([
    { keyid: a.keyId, sig: null }, { keyid: b.keyId, sig: signWith(b, dupSigned) },
  ]);
  check("M5g: a signature that is not a string asks nothing on the hand-assembled route either (" +
    "verified " + nonString.verified + ", " + nonString.keyIds.length + " counted)",
  nonString.verified === true && nonString.keyIds.length === 1 && nonString.keyIds[0] === b.keyId);
  var onlyNonString = await verifyAssembled([
    { keyid: a.keyId, sig: null }, { keyid: b.keyId, sig: 1234 },
  ]);
  check("M5h: and two of them alone resolve false rather than throwing",
    onlyNonString.verified === false && onlyNonString.keyIds.length === 0);

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
  /* And that refusal does not depend on the hash the identifier is computed with being the live one.
     `update` and `digest` are ordinary writable properties of the hash prototype, so a replacement
     decided which key matched an authorized identifier: a different key filed under an authorized one
     was accepted and the metadata it signed reported `verified: true`. The digest is taken through the
     operations captured at load. */
  var mislabeledMeta = pki.tuf.parseMetadata(metadataFor(mislabeled, [a]));
  var hashProto = Object.getPrototypeOf(crypto.createHash("sha256"));
  var realHashUpdate = hashProto.update;
  var hashLive, stillRefused;
  try {
    Object.defineProperty(hashProto, "update", {
      value: function () { return this; }, writable: true, configurable: true,
    });
    // CONTROL, inside the window: a chained digest now covers nothing, so two inputs agree.
    hashLive = crypto.createHash("sha256").update(Buffer.from("abc")).digest()
      .equals(crypto.createHash("sha256").update(Buffer.from("def")).digest());
    stillRefused = await codeAsync(pki.tuf.verifySignatures({
      metadata: mislabeledMeta, keys: mislabeled.keys, role: mislabeled.roles.root,
    }));
  } finally {
    Object.defineProperty(hashProto, "update", { value: realHashUpdate, writable: true, configurable: true });
  }
  check("M9a: CONTROL the replaced hash update is live, so M9b exercises it", hashLive === true);
  check("M9b: a replaced hash cannot file a key under another key's identifier (" + stillRefused + ")",
    stillRefused === "tuf/bad-key");

  /* Shape refusals on the wrapper. */
  check("M10: a document with no signatures array is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signed: oneSigner }))); }) === "tuf/bad-metadata");
  check("M11: a document with no signed body is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [] }))); }) === "tuf/bad-metadata");
  check("M12: a signed body with no _type is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [], signed: { spec_version: SPEC, version: 1, expires: EXPIRES } }))); }) === "tuf/bad-metadata");
  check("M13: a version that is not a positive integer is refused",
    code(function () { pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], version: 0 }), [a])); }) === "tuf/bad-metadata");
  check("M14: an expires that is not a date-time is refused",
    code(function () { pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], expires: "soon" }), [a])); }) === "tuf/bad-metadata");
  /* The TUF specification sec. 4.2.3 fixes the format: "Metadata date-time follows the ISO 8601 standard.
     The expected format of the combined date and time string is "YYYY-MM-DDTHH:MM:SSZ". Time is always in
     UTC". `Date.parse` is far looser than that. It ROLLS an impossible date forward rather than refusing
     it, so a root whose expires reads 2026-02-30 was treated as usable until March 2, two days of trust
     the metadata does not state; and it accepts a date with no time and a time with no zone, where the
     instant then depends on the reader's own timezone. Each is refused on the format now, through the
     shared RFC 3339 scanner that already enforces calendar validity including leap years. */
  function expiresIs(v) {
    return code(function () {
      pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], expires: v }), [a]));
    });
  }
  check("M14a: CONTROL the format the specification states is accepted",
    expiresIs("2026-01-01T00:00:00Z") === "NO-THROW");
  check("M14b: an impossible calendar date is refused rather than rolled forward",
    expiresIs("2026-02-30T00:00:00Z") === "tuf/bad-metadata");
  check("M14c: and February 29 is accepted in a leap year and refused outside one",
    expiresIs("2028-02-29T00:00:00Z") === "NO-THROW" &&
    expiresIs("2027-02-29T00:00:00Z") === "tuf/bad-metadata");
  check("M14d: a date with no time is refused, the format being a combined date and time",
    expiresIs("2026-01-01") === "tuf/bad-metadata");
  check("M14e: a time with no zone is refused, since the instant would depend on the reader",
    expiresIs("2026-01-01T00:00:00") === "tuf/bad-metadata");
  check("M14f: and a locale spelling is refused",
    expiresIs("Jan 1 2026") === "tuf/bad-metadata");
  /* A zero offset is the same instant as Z and RFC 3339 admits both spellings, so it is accepted: the
     clause states the expected format rather than forbidding an equivalent one, and refusing it would
     promote a statement of form into a conformance rule the document does not make. */
  check("M14g: a zero numeric offset is accepted, denoting the same instant as Z",
    expiresIs("2026-01-01T00:00:00+00:00") === "NO-THROW" &&
    expiresIs("2026-01-01T00:00:00-00:00") === "NO-THROW");
  /* A NONZERO offset is a different matter. "Time is always in UTC" is the clause, and the shared RFC
     3339 scanner admits every numeric offset because RFC 3339 does. An expires of +01:00 names a real
     instant, so nothing about it is malformed as a date, but it is not the UTC the specification
     requires: a client reading the stated form refuses the document, and adopting it here means
     trusting metadata a conforming client would not. Refused on the offset, not on the date. */
  check("M14h: a nonzero numeric offset is refused, the specification putting the time in UTC",
    expiresIs("2026-01-01T01:00:00+01:00") === "tuf/bad-metadata" &&
    expiresIs("2026-01-01T00:00:00+05:30") === "tuf/bad-metadata" &&
    expiresIs("2025-12-31T23:00:00-01:00") === "tuf/bad-metadata");
  /* The rule belongs to BOTH doors. `checkExpiry` is reachable with a metadata object a caller
     assembled rather than one `parseMetadata` returned, so a rule enforced at the parse alone is a
     document one verb accepts and the other refuses. */
  function checkExpiryOf(v) {
    return code(function () {
      pki.tuf.checkExpiry(
        { signed: { _type: "root", spec_version: "1.0.31", version: 1, expires: v } },
        new Date("2026-01-01T00:00:00Z"));
    });
  }
  check("M14i: and checkExpiry reads the offset the same way the parse does",
    checkExpiryOf("2030-01-01T00:00:00Z") === "NO-THROW" &&
    checkExpiryOf("2030-01-01T00:00:00+00:00") === "NO-THROW" &&
    checkExpiryOf("2030-01-01T01:00:00+01:00") === "tuf/bad-metadata" &&
    checkExpiryOf("2030-01-01T00:00:00+05:30") === "tuf/bad-metadata");
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

  /* The expiry is read off the CALLER's object, and an accessor answers every read separately. A getter
     could pass the type check with a date string, hand the comparison a FUTURE date, and have
     `checkExpiry` return true for metadata whose real expiry is in the past. Expiry is the
     freeze-attack check, so a verdict of true on an expired document is the whole defense answering the
     wrong question. The value read is the signed body's, so that is where the accessor goes. */
  var expReads = 0;
  var sneakyBody = { _type: "root", spec_version: SPEC, version: 1 };
  Object.defineProperty(sneakyBody, "expires", {
    enumerable: true,
    get: function () {
      expReads += 1;
      // A valid date string every time, but the SECOND read, the one that is compared, is in the future.
      return expReads === 2 ? "2099-01-01T00:00:00Z" : "2026-01-01T00:00:00Z";
    },
  });
  var expiryVerdict = "NO-THROW";
  try { pki.tuf.checkExpiry({ signed: sneakyBody }, NOW); }
  catch (e) { expiryVerdict = (e && e.code) || "NO-CODE"; }
  check("M18a: an accessor-backed expiry cannot validate as one date and be compared as another (" +
    expReads + " read(s), " + expiryVerdict + ")",
    expReads <= 1 && (expiryVerdict === "tuf/expired" || expiryVerdict === "tuf/bad-input"));
  /* CONTROL: a plain body with the same expired date is still refused, and an unexpired one still
     passes, so holding the field to one read did not change either verdict. */
  function bodyExpiring(when) {
    return { signed: { _type: "root", spec_version: SPEC, version: 1, expires: when } };
  }
  check("M18b: CONTROL a plain expired body is still refused and an unexpired one still passes",
    code(function () { pki.tuf.checkExpiry(bodyExpiring("2026-01-01T00:00:00Z"), NOW); }) === "tuf/expired" &&
    pki.tuf.checkExpiry(bodyExpiring("2099-01-01T00:00:00Z"), NOW) === true);
  /* And the copy beside the body may not contradict it, in either direction: the verb answers about
     the document the signature covers, so a copy that disagrees is a caller describing another one. */
  check("M18b1: a stated expires that contradicts the body is refused rather than preferred",
    code(function () {
      var m = bodyExpiring("2026-01-01T00:00:00Z"); m.expires = "2099-01-01T00:00:00Z";
      return pki.tuf.checkExpiry(m, NOW);
    }) === "tuf/bad-input" &&
    code(function () {
      var m = bodyExpiring("2099-01-01T00:00:00Z"); m.expires = "2026-01-01T00:00:00Z";
      return pki.tuf.checkExpiry(m, NOW);
    }) === "tuf/bad-input");
  check("M18b2: CONTROL a copy that agrees with the body is read as before",
    (function () {
      var m = bodyExpiring("2099-01-01T00:00:00Z"); m.expires = "2099-01-01T00:00:00Z";
      return pki.tuf.checkExpiry(m, NOW);
    })() === true);

  /* `keyId` validates `keytype`, `scheme` and `keyval`, then hashes the key through `canonicalJson`,
     which reads every field AGAIN. The identifier is the identity a role's `keyids` list matches against,
     so an accessor could validate as one key shape and be hashed as another: the returned identifier would
     name a key that never passed validation. */
  var ktReads = 0;
  var sneakyKey = { scheme: "ed25519", keyval: { public: "00" } };
  Object.defineProperty(sneakyKey, "keytype", {
    enumerable: true,
    get: function () { ktReads += 1; return ktReads === 1 ? "ed25519" : 42; },
  });
  var idVerdict = "NO-THROW";
  try { pki.tuf.keyId(sneakyKey); } catch (e) { idVerdict = (e && e.code) || "NO-CODE"; }
  check("M18c: an accessor-backed keytype cannot validate as one value and be hashed as another (" +
    ktReads + " read(s), " + idVerdict + ")",
    ktReads <= 1 || idVerdict === "tuf/bad-key");
  /* CONTROL: an ordinary key still derives its identifier, and it is the same one as before, so holding
     the key to a single read did not change the identity any existing document states. */
  check("M18d: CONTROL an ordinary key still derives its stated identifier",
    pki.tuf.keyId(a.key) === a.keyId && a.keyId.length === 64);

  /* "Metadata is written according to version "spec_version" of the specification, and clients MUST
     verify that "spec_version" matches the expected version number". The clause is about metadata, not
     about root metadata, so it binds every role. `updateRoot` holds a root to it; `parseMetadata` is the
     only door the other three roles come through, and from there a document reaches `verifySignatures`
     and `checkExpiry`. Both of those answer under 1.x rules -- the key identifier is a hash of the
     canonical form this version defines, and the expiry format is the one this version states -- so a
     positive verdict on a document written to another major version is an answer about rules the
     document does not claim. Measured before the fix: a targets, snapshot or timestamp document
     declaring 2.0.0, and one declaring nothing at all, parsed; `checkExpiry` then returned true. */
  function parseRole(type, spec) {
    var body = { _type: type, version: 1, expires: EXPIRES };
    if (spec !== null) body.spec_version = spec;
    return code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [], signed: body }))); });
  }
  var ROLES = ["targets", "snapshot", "timestamp"];
  var controlOk = true, otherMajor = true, absent = true, notSemver = true, laterMinor = true;
  for (var ri = 0; ri < ROLES.length; ri++) {
    controlOk = controlOk && parseRole(ROLES[ri], "1.0.31") === "NO-THROW";
    laterMinor = laterMinor && parseRole(ROLES[ri], "1.9.7") === "NO-THROW";
    otherMajor = otherMajor && parseRole(ROLES[ri], "2.0.0") === "tuf/unsupported-spec-version";
    absent = absent && parseRole(ROLES[ri], null) === "tuf/bad-metadata";
    notSemver = notSemver && parseRole(ROLES[ri], "one point oh") === "tuf/bad-metadata";
  }
  check("M19a: CONTROL every role naming this build's major version parses", controlOk);
  check("M19b: and a later 1.x minor parses too, the match being the major version", laterMinor);
  check("M19c: every role naming another major version is refused, not only root", otherMajor);
  check("M19d: a document naming no spec_version is refused for every role, TAP 6 requiring it", absent);
  check("M19e: and a spec_version that is not a semantic version is malformed for every role", notSemver);
  /* "A string that contains the version number of the TUF specification. Its format follows the
     Semantic Versioning 2.0.0 (semver) specification" (specification sec. 4.3). So the WHOLE string is
     a semver value, and reading the leading major alone accepted a field that is not one: "1.", "1.foo"
     and "1.0.0oops" each parsed as supported 1.x metadata. A value that is not semver is malformed
     rather than a version this build does not implement, so it draws the malformed code and only a
     well-formed version with another major draws the unsupported one. */
  var MALFORMED = ["1.", "1.0", "1.foo", "1.0.0oops", "1.0.x", "01.0.0", "1.00.0", "1.0.0-", "1.0.0+",
    "1.0.0-rc..1", "1.0.0-01", "v1.0.0", " 1.0.0", "1.0.0 ", "", "1.0.0.0"];
  var malformedAll = true, malformedSaw = [];
  for (var mi = 0; mi < MALFORMED.length; mi++) {
    var got = parseRole("targets", MALFORMED[mi]);
    if (got !== "tuf/bad-metadata") { malformedAll = false; malformedSaw.push(MALFORMED[mi] + "->" + got); }
  }
  check("M19s: a spec_version that is not a semver 2.0.0 value is malformed, not an unsupported " +
    "version (" + (malformedSaw.length ? malformedSaw.join(", ") : "all refused") + ")", malformedAll);
  /* CONTROL: the forms semver DOES admit are still read, so the rule is about well-formedness rather
     than about rejecting anything unusual. A build identifier may carry leading zeros where a
     pre-release identifier may not, which is the one asymmetry in the grammar. */
  var SEMVER_OK = ["1.0.0", "1.0.31", "1.9.7", "1.0.0-rc.1", "1.0.0-alpha", "1.0.0-alpha.1",
    "1.0.0+build.5", "1.0.0-rc.1+build.007", "1.2.3+0010", "1.0.0-0a"];
  var okAll = true, okSaw = [];
  for (var oi = 0; oi < SEMVER_OK.length; oi++) {
    var g2 = parseRole("targets", SEMVER_OK[oi]);
    if (g2 !== "NO-THROW") { okAll = false; okSaw.push(SEMVER_OK[oi] + "->" + g2); }
  }
  check("M19t: CONTROL every well-formed 1.x semver value is read, pre-release and build included (" +
    (okSaw.length ? okSaw.join(", ") : "all accepted") + ")", okAll);
  check("M19u: and a well-formed version with another major is still the unsupported-version refusal",
    parseRole("targets", "2.0.0") === "tuf/unsupported-spec-version" &&
    parseRole("targets", "0.9.9") === "tuf/unsupported-spec-version" &&
    parseRole("targets", "10.0.0") === "tuf/unsupported-spec-version");
  /* A major version of any width is still a VERSION, so it draws the unsupported code rather than the
     malformed one. Converting the major to a number needed a digit cap to stay exact, and the cap
     answered "malformed" for a conforming document: the comparison is made on the digits instead, where
     a numeric identifier carries no leading zeros and so has one spelling per value. */
  check("M19v: a major version wider than a Number holds exactly is unsupported, not malformed",
    parseRole("targets", "1000000.0.0") === "tuf/unsupported-spec-version" &&
    parseRole("targets", "99999999999999999999.0.0") === "tuf/unsupported-spec-version" &&
    parseRole("targets", "1.99999999999999999999.0") === "NO-THROW");
  /* The rule is at the door, so no later verb can be handed a document written to another major
     version: there is no parsed object to pass on. */
  var reached;
  try {
    var alien = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [],
      signed: { _type: "targets", spec_version: "2.0.0", version: 1, expires: EXPIRES } })));
    reached = String(pki.tuf.checkExpiry(alien, NOW));
  } catch (e) { reached = (e && e.code) || "NO-CODE"; }
  check("M19f: checkExpiry cannot report on a 2.x document, the parse refusing it first (" + reached + ")",
    reached === "tuf/unsupported-spec-version");
  /* `_type`, `version` and `expires` are themselves rules of this specification version, so the match
     is made before any of them is read: a document decided on its version field first has been judged
     under rules it may not be written to. Each of these carries a value the 1.x rule below would
     refuse, and the version mismatch is what answers. */
  function withBoth(extra) {
    var body = { _type: "targets", spec_version: "2.0.0", version: 1, expires: EXPIRES };
    var keys = Object.keys(extra);
    for (var i = 0; i < keys.length; i++) body[keys[i]] = extra[keys[i]];
    return code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [], signed: body }))); });
  }
  check("M19g: the version match is made before the fields this version defines are read",
    withBoth({ _type: "" }) === "tuf/unsupported-spec-version" &&
    withBoth({ version: 0 }) === "tuf/unsupported-spec-version" &&
    withBoth({ expires: "soon" }) === "tuf/unsupported-spec-version");
  /* The canonical form admits no floating point at any version this build reads, so a fractional number
     is refused on the JSON before the document states anything: the version match cannot precede the
     read that makes the field addressable. */
  check("M19h: a fractional number is refused on the JSON whatever version the document declares",
    code(function () {
      pki.tuf.parseMetadata(Buffer.from('{"signatures":[],"signed":{"_type":"targets",' +
        '"spec_version":"2.0.0","version":1.5,"expires":"' + EXPIRES + '"}}'));
    }) === "tuf/bad-json");

  /* `verifySignatures` and `checkExpiry` take a metadata OBJECT, and both are reachable with one a
     caller assembled rather than one `parseMetadata` produced -- which is why `checkExpiry` already
     re-enforces the `expires` format there. Measured before the rule was carried across: a hand-built
     targets document declaring 2.0.0, 0.9.0, or nothing at all, carrying a REAL Ed25519 signature,
     was reported `verified` and `checkExpiry` returned true for it. A key identifier is a hash of the
     canonical form this version defines, so that verdict answers under rules the document does not
     claim. */
  function handBuilt(spec) {
    var body = { _type: "targets", version: 1, expires: EXPIRES };
    if (spec !== null) body.spec_version = spec;
    var canonical = pki.tuf.canonicalJson(body);
    var m = { type: body._type, version: body.version, expires: body.expires, signed: body,
      signatures: [{ keyid: a.keyId, sig: crypto.sign(null, canonical, a.kp.privateKey).toString("hex") }],
      signedBytes: canonical };
    if (spec !== null) m.specVersion = spec;
    return m;
  }
  async function verifyHand(spec) {
    var m = handBuilt(spec);
    try {
      var v = await pki.tuf.verifySignatures({ metadata: m, keys: signed.keys, role: signed.roles.root });
      return "verified=" + v.verified;
    } catch (e) { return (e && e.code) || "NO-CODE"; }
  }
  function expiryHand(spec) {
    return code(function () { pki.tuf.checkExpiry(handBuilt(spec), NOW); });
  }
  check("M19i: CONTROL a hand-built document naming this build's major version still verifies",
    await verifyHand(SPEC) === "verified=true" && expiryHand(SPEC) === "NO-THROW");
  check("M19j: verifySignatures refuses a hand-built document written to another major version",
    await verifyHand("2.0.0") === "tuf/unsupported-spec-version" &&
    await verifyHand("0.9.0") === "tuf/unsupported-spec-version");
  check("M19k: and one that names no version at all, which is the caller's object being incomplete",
    await verifyHand(null) === "tuf/bad-input");
  check("M19l: checkExpiry carries the same rule, so no verb answers about a 2.x document",
    expiryHand("2.0.0") === "tuf/unsupported-spec-version" &&
    expiryHand("0.9.0") === "tuf/unsupported-spec-version" &&
    expiryHand(null) === "tuf/bad-input");

  /* A parsed object is the CALLER's once it is returned, and its `signedBytes` is a Buffer whose contents
     can be overwritten. `specVersion` is filled from the document at parse time, so agreement between
     the two does not survive a mutation: the field names the document that was parsed while the bytes
     name the document that gets verified. This is A16's shape with `spec_version` in place of `version`,
     and it is answered the same way -- by deriving the bytes verified from ONE read of `signed`, so the
     version read and the document reported on are the same value. Both documents here are signed by a
     real key held by the role, which is what A16 assumes too: two validly signed documents and one
     buffer between them. */
  var specA = rootSigned({ signers: [a], version: 1, specVersion: "1.0.31" });
  var specB = rootSigned({ signers: [a], version: 1, specVersion: "2.0.31" });
  var preA = pki.tuf.canonicalJson(specA), preB = pki.tuf.canonicalJson(specB);
  check("M19m: the two documents' canonical forms are the same length, so one overwrites the other",
    preA.length === preB.length);
  var swapped = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  preB.copy(swapped.signedBytes);                       // the bytes become the 2.x document's
  swapped.signatures[0].sig = crypto.sign(null, preB, a.kp.privateKey).toString("hex");
  var swappedGot;
  try {
    swappedGot = await pki.tuf.verifySignatures({ metadata: swapped, keys: specA.keys,
      role: specA.roles.root });
  } catch (e) { swappedGot = (e && e.code) || "NO-CODE"; }
  check("M19n: overwriting signedBytes with a 2.x document cannot yield a verified verdict (" +
    (swappedGot && swappedGot.verified !== undefined ? "verified=" + swappedGot.verified : swappedGot) + ")",
    swappedGot === "tuf/bad-input" || swappedGot.verified === false);
  /* And with the signed body changed to agree with the bytes, so nothing is inconsistent any more, the
     document itself is one this build does not implement. */
  var agreed = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  preB.copy(agreed.signedBytes);
  agreed.signed.spec_version = "2.0.31";
  agreed.signatures[0].sig = crypto.sign(null, preB, a.kp.privateKey).toString("hex");
  var agreedGot;
  try {
    agreedGot = await pki.tuf.verifySignatures({ metadata: agreed, keys: specA.keys,
      role: specA.roles.root });
  } catch (e) { agreedGot = (e && e.code) || "NO-CODE"; }
  check("M19o: and a consistent 2.x document is refused on its version (" +
    (agreedGot && agreedGot.verified !== undefined ? "verified=" + agreedGot.verified : agreedGot) + ")",
    agreedGot === "tuf/unsupported-spec-version");
  /* CONTROL: the same object, unmutated, still verifies, so the two above are about the swap rather than
     about anything the derivation broke. */
  var untouched = await pki.tuf.verifySignatures({
    metadata: pki.tuf.parseMetadata(metadataFor(specA, [a])), keys: specA.keys, role: specA.roles.root });
  check("M19p: CONTROL the unmutated document still verifies", untouched.verified === true);
  /* The verdict is about the document as of the CALL. Both the body and the bytes are copied before the
     first await, so changing either afterwards cannot alter what was verified -- it leaves the caller's
     own object no longer matching the verdict it already holds, which is A16's reasoning applied to the
     body. What a mutation before the call does is get refused, which M19n and M19o pin. */
  var live = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  var livePending = pki.tuf.verifySignatures({ metadata: live, keys: specA.keys,
    role: specA.roles.root });
  live.signed.spec_version = "2.0.31";
  preB.copy(live.signedBytes);
  var liveGot = await livePending;
  check("M19q: a mutation after the call cannot change the document the verdict was about",
    liveGot.verified === true);
  /* The equal-length swap above is the hard case; a mismatch of LENGTH is the ordinary one, and the
     comparison has to answer it rather than throw an untyped error from a constant-time primitive
     handed two sizes. */
  var longer = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  var longerGot;
  try {
    longerGot = await pki.tuf.verifySignatures({
      metadata: { type: longer.type, specVersion: longer.specVersion, version: longer.version,
        expires: longer.expires, signed: longer.signed, signatures: longer.signatures,
        signedBytes: Buffer.concat([longer.signedBytes, Buffer.from("X")]) },
      keys: specA.keys, role: specA.roles.root });
    longerGot = "verified=" + longerGot.verified;
  } catch (e) { longerGot = (e && e.isPkiError === true) ? e.code : "UNTYPED:" + ((e && e.message) || e); }
  check("M19r: signedBytes of a different length is a typed refusal, not an untyped throw (" +
    longerGot + ")",
    longerGot === "tuf/bad-input");

  /* The freeze-attack check and the signature check have to be about ONE document. `expires` sits
     beside the signed body as a convenience copy, and the signature covers `signed.expires`, so an
     object carrying one of each had `verifySignatures` answer about the signed document while
     `checkExpiry` answered about the copy. Measured: metadata correctly signed with an expiry in 2020,
     with only the top-level `expires` moved to 2099, verified AND passed the expiry check at a 2026
     instant, which is the whole defense reporting on a date the document does not carry. */
  var lapsed = rootSigned({ signers: [a], version: 1, expires: "2020-01-01T00:00:00Z" });
  var lapsedMeta = pki.tuf.parseMetadata(metadataFor(lapsed, [a]));
  var stillVerifies = await pki.tuf.verifySignatures({ metadata: lapsedMeta, keys: lapsed.keys,
    role: lapsed.roles.root });
  check("M19w: CONTROL the lapsed document is correctly signed, so the expiry is the only thing wrong",
    stillVerifies.verified === true);
  check("M19x: CONTROL and its expiry is refused as it stands",
    code(function () { pki.tuf.checkExpiry(lapsedMeta, NOW); }) === "tuf/expired");
  lapsedMeta.expires = "2099-01-01T00:00:00Z";
  check("M19y: moving the convenience copy of expires cannot pass the freeze-attack check (" +
    code(function () { pki.tuf.checkExpiry(lapsedMeta, NOW); }) + ")",
    code(function () { pki.tuf.checkExpiry(lapsedMeta, NOW) ; }) !== "NO-THROW");

  /* The BODY is the authority, so it is copied before anything else on the object is read. Every other
     read is a chance for caller code to run: a getter on `signedBytes` fired while the body was still
     the caller's could set it to a supported version for the duration of the copy, and a getter on
     `specVersion` could put the unsupported one back, leaving an object that declares 2.0.31 before and
     after a `verified: true` about a document it never carried. The order is what closes it, which is
     the same rule the note verifier follows for its subject. */
  var steered = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  var heldBytes = steered.signedBytes;
  steered.signed.spec_version = "2.0.31";
  Object.defineProperty(steered, "signedBytes", {
    enumerable: true,
    get: function () { steered.signed.spec_version = "1.0.31"; return heldBytes; },
  });
  Object.defineProperty(steered, "specVersion", {
    enumerable: true,
    get: function () { steered.signed.spec_version = "2.0.31"; return "1.0.31"; },
  });
  var steeredGot;
  try {
    steeredGot = await pki.tuf.verifySignatures({ metadata: steered, keys: specA.keys,
      role: specA.roles.root });
    steeredGot = "verified=" + steeredGot.verified;
  } catch (e) { steeredGot = (e && e.code) || "NO-CODE"; }
  check("M19z: a getter cannot swap the body's version in for the duration of the copy (" +
    steeredGot + ", body now " + steered.signed.spec_version + ")",
    steeredGot === "tuf/bad-input");
  /* Ordering the reads only moves the lever to whichever field is read first, and the field read
     first IS the subject: a getter on `signed` that returns a body it has just restored hands over a
     document the object does not otherwise carry, and no read order defends against that. So no field
     of the object may be an accessor at all. Every field either verb reads is held to it, on both,
     and a conforming caller is unaffected because a parsed document carries plain values. */
  var FIELDS = ["signed", "signedBytes", "specVersion", "expires", "type", "version", "signatures"];
  var accessorRefused = [], accessorMissed = [];
  for (var fi = 0; fi < FIELDS.length; fi++) {
    var field = FIELDS[fi];
    var victim = pki.tuf.parseMetadata(metadataFor(specA, [a]));
    var held = victim[field];
    Object.defineProperty(victim, field, { enumerable: true, configurable: true,
      get: (function (v) { return function () { return v; }; })(held) });
    var vGot = await codeAsync(pki.tuf.verifySignatures({ metadata: victim, keys: specA.keys,
      role: specA.roles.root }));
    var eGot = code(function () { pki.tuf.checkExpiry(victim, NOW); });
    if (vGot === "tuf/bad-input" && eGot === "tuf/bad-input") accessorRefused.push(field);
    else accessorMissed.push(field + " -> verify " + vGot + ", expiry " + eGot);
  }
  check("M19aa: an accessor on any field either verb reads is refused, on both (" +
    (accessorMissed.length ? accessorMissed.join(" | ") : accessorRefused.length + " field(s)") + ")",
    accessorMissed.length === 0 && accessorRefused.length === FIELDS.length);
  /* CONTROL: the same objects with plain values still verify and still pass the expiry check, so the
     refusal is about the accessor rather than about anything else these fixtures carry. */
  var plain = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  /* `type` and `version` are convenience copies beside the signed body exactly as `specVersion` and
     `expires` are, and a caller reads `version` for a rollback comparison and `type` to choose which
     role a document belongs to. Cross-checking one copy and not the others left those two free to
     contradict the body while the verdict still read `verified`. Every copy is checked against the
     body now, so there is one document in the answer. */
  var COPIES = [["type", "snapshot"], ["version", 999], ["specVersion", "2.0.31"],
    ["expires", "2099-01-01T00:00:00Z"]];
  var contradicted = [];
  for (var ci = 0; ci < COPIES.length; ci++) {
    var copyName = COPIES[ci][0], value = COPIES[ci][1];
    var vicVerify = pki.tuf.parseMetadata(metadataFor(specA, [a]));
    vicVerify[copyName] = value;
    var vCode = await codeAsync(pki.tuf.verifySignatures({ metadata: vicVerify, keys: specA.keys,
      role: specA.roles.root }));
    var vicExpiry = pki.tuf.parseMetadata(metadataFor(specA, [a]));
    vicExpiry[copyName] = value;
    var eCode = code(function () { pki.tuf.checkExpiry(vicExpiry, NOW); });
    if (vCode !== "tuf/bad-input" || eCode !== "tuf/bad-input") {
      contradicted.push(copyName + " -> verify " + vCode + ", expiry " + eCode);
    }
  }
  check("M19af: a convenience copy that contradicts the signed body is refused by both verbs, for " +
    "every copy (" + (contradicted.length ? contradicted.join(" | ") : COPIES.length + " fields") + ")",
    contradicted.length === 0);
  /* `signedBytes` is a copy of the body too, in bytes rather than in a field, and the two verbs have to
     agree about which objects they will answer for at all: the expiry check read the body while the
     bytes beside it encoded another document, and returned true for it. It does not USE those bytes,
     which is why this went unnoticed, and that is the point: an object the signature check refuses
     should not be one the expiry check answers about. Absent bytes stay acceptable, a caller being
     free to ask only about an expiry. */
  var otherBody = rootSigned({ signers: [a], version: 2, specVersion: "1.0.31" });
  var mismatched = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  mismatched.signedBytes = pki.tuf.canonicalJson(otherBody);
  check("M19ag: signedBytes encoding another document is refused by the expiry check too (" +
    code(function () { pki.tuf.checkExpiry(mismatched, NOW); }) + ")",
    code(function () { pki.tuf.checkExpiry(mismatched, NOW); }) === "tuf/bad-input");
  /* A THRESHOLD COUNTS KEYS, and the verdict counted identifiers. A key identifier is a hash of the
     key's canonical form, so adding a member the hash covers and the cryptography ignores -- a
     `comment` here -- yields a SECOND identifier for the SAME public key. A role naming both with a
     threshold of two was then met by one key: the same signature bytes verify under both entries, and
     each counted once. What a threshold of two is for is two keys, so the count is over the key
     MATERIAL now and the aliases collapse to one. */
    var aliasKey = { keytype: a.key.keytype, scheme: a.key.scheme, keyval: a.key.keyval,
      comment: "alias" };
  var aliasId = pki.tuf.keyId(aliasKey);
  var aliasKeys = {};
  aliasKeys[a.keyId] = a.key;
  aliasKeys[aliasId] = aliasKey;
  var aliasBody = { _type: "targets", spec_version: SPEC, version: 1, expires: EXPIRES };
  var aliasBytes = pki.tuf.canonicalJson(aliasBody);
  var aliasSig = crypto.sign(null, aliasBytes, a.kp.privateKey).toString("hex");
  var aliasMeta = { type: "targets", specVersion: SPEC, version: 1, expires: EXPIRES,
    signed: aliasBody, signedBytes: aliasBytes,
    signatures: [{ keyid: a.keyId, sig: aliasSig }, { keyid: aliasId, sig: aliasSig }] };
  var aliasVerdict = await pki.tuf.verifySignatures({ metadata: aliasMeta, keys: aliasKeys,
    role: { keyids: [a.keyId, aliasId], threshold: 2 } });
  check("M19ai: CONTROL the two identifiers differ while the key material is the same",
    aliasId !== a.keyId && aliasKey.keyval.public === a.key.keyval.public);
  check("M19aj: one key under two identifiers does not meet a threshold of two (" +
    aliasVerdict.keyIds.length + " counted)",
    aliasVerdict.verified === false && aliasVerdict.keyIds.length === 1);
  /* CONTROL: two genuinely different keys still meet it, so the count collapses aliases rather than
     refusing a second signer. */
  var twoReal = {};
  twoReal[a.keyId] = a.key;
  twoReal[c.keyId] = c.key;
  var twoBody = { _type: "targets", spec_version: SPEC, version: 1, expires: EXPIRES };
  var twoBytes = pki.tuf.canonicalJson(twoBody);
  var twoMeta = { type: "targets", specVersion: SPEC, version: 1, expires: EXPIRES,
    signed: twoBody, signedBytes: twoBytes,
    signatures: [{ keyid: a.keyId, sig: crypto.sign(null, twoBytes, a.kp.privateKey).toString("hex") },
      { keyid: c.keyId, sig: signWith(c, twoBody) }] };
  var twoVerdict = await pki.tuf.verifySignatures({ metadata: twoMeta, keys: twoReal,
    role: { keyids: [a.keyId, c.keyId], threshold: 2 } });
  check("M19ak: CONTROL two different keys still meet a threshold of two",
    twoVerdict.verified === true && twoVerdict.keyIds.length === 2);
  /* The `comment` above is one spelling of five. A key identifier covers the whole key object, so a
     PEM with CRLF line endings, a space before each newline, an EC point written compressed rather
     than uncompressed, and the `ecdsa-sha2-nistp256` keytype where another entry says `ecdsa` each
     yield a different identifier for the same point. MEASURED, the exported SPKI does NOT collapse
     them: Node preserves a compressed point on export, 59 bytes against 91. The JWK coordinates do,
     which is why the fingerprint comes from there. Each row asserts the two entries really are one
     key, so a count of one cannot come from a broken fixture. */
  var ecPem = c.kp.publicKey.export({ type: "spki", format: "pem" });
  function ecEntry(pem, keytype) {
    return { keytype: keytype || "ecdsa", scheme: "ecdsa-sha2-nistp256", keyval: { public: pem } };
  }
  function ecCompressedPem() {
    var spki = c.kp.publicKey.export({ type: "spki", format: "der" });
    var jwk = c.kp.publicKey.export({ format: "jwk" });
    var xb = Buffer.from(jwk.x, "base64url"), yb = Buffer.from(jwk.y, "base64url");
    var point = Buffer.concat([Buffer.from([(yb[yb.length - 1] & 1) ? 3 : 2]), xb]);
    var build = pki.asn1.build;
    var der = build.sequence([build.raw(pki.asn1.decode(spki).children[0].bytes),
      build.bitString(point, 0)]);
    return crypto.createPublicKey({ key: der, format: "der", type: "spki" })
      .export({ type: "spki", format: "pem" });
  }
  function jwkOf(pem) { return crypto.createPublicKey(pem).export({ format: "jwk" }); }
  var ecBase = ecEntry(ecPem);
  var ecBaseId = pki.tuf.keyId(ecBase);
  var ecBody = { _type: "targets", spec_version: SPEC, version: 1, expires: EXPIRES };
  var ecBytes = pki.tuf.canonicalJson(ecBody);
  var ecSig = crypto.sign("sha256", ecBytes, { key: c.kp.privateKey, dsaEncoding: "der" })
    .toString("hex");
  var SPELLINGS = [
    ["CRLF line endings", ecEntry(ecPem.replace(/\n/g, "\r\n"))],
    ["a space before each newline", ecEntry(ecPem.replace(/\n/g, " \n"))],
    ["a compressed EC point", ecEntry(ecCompressedPem())],
    ["the ecdsa-sha2-nistp256 keytype alias", ecEntry(ecPem, "ecdsa-sha2-nistp256")],
  ];
  var spelled = [];
  for (var si = 0; si < SPELLINGS.length; si++) {
    var alias2 = SPELLINGS[si][1];
    var aliasId2 = pki.tuf.keyId(alias2);
    var ks2 = {};
    ks2[ecBaseId] = ecBase;
    ks2[aliasId2] = alias2;
    var jb = jwkOf(ecBase.keyval.public), ja = jwkOf(alias2.keyval.public);
    var v3 = await pki.tuf.verifySignatures({
      metadata: { type: "targets", specVersion: SPEC, version: 1, expires: EXPIRES, signed: ecBody,
        signedBytes: ecBytes,
        signatures: [{ keyid: ecBaseId, sig: ecSig }, { keyid: aliasId2, sig: ecSig }] },
      keys: ks2, role: { keyids: [ecBaseId, aliasId2], threshold: 2 } });
    var onePoint = jb.x === ja.x && jb.y === ja.y;
    if (!onePoint || aliasId2 === ecBaseId || v3.verified !== false || v3.keyIds.length !== 1) {
      spelled.push(SPELLINGS[si][0] + " -> samePoint " + onePoint + ", counted " + v3.keyIds.length +
        ", verified " + v3.verified);
    }
  }
  check("M19al: every spelling of one key collapses to one against a threshold of two (" +
    (spelled.length ? spelled.join(" | ") : SPELLINGS.length + " spellings") + ")",
    spelled.length === 0);
  check("M19ah: CONTROL an object carrying no signedBytes at all still answers about its expiry",
    pki.tuf.checkExpiry({ signed: { _type: "root", spec_version: SPEC, version: 1,
      expires: "2099-01-01T00:00:00Z" } }, NOW) === true);
  /* The native verifier itself was read live, once per signature, so a replacement installed after
     the package loaded decided the threshold: `crypto.verify` returning true made metadata carrying a
     64-byte all-zero signature pass against a genuine pinned key. That is the whole verdict, not a
     detail of it. */
  var realVerify = crypto.verify;
  var zeroSigned = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: "00".repeat(64) }], signed: signed })));
  var underReplacedVerify, verifyReplacementLive;
  try {
    crypto.verify = function () { return true; };
    verifyReplacementLive = crypto.verify(null, Buffer.from("x"), {}, Buffer.from("y")) === true;
    underReplacedVerify = await pki.tuf.verifySignatures({ metadata: zeroSigned, keys: signed.keys,
      role: signed.roles.root });
  } catch (e) {
    underReplacedVerify = { verified: "threw:" + ((e && e.code) || e) };
  } finally { crypto.verify = realVerify; }
  check("M19am: CONTROL the replaced native verifier is live, so the next check exercises it",
    verifyReplacementLive === true);
  check("M19an: a replaced native verifier cannot make an all-zero signature meet a threshold (" +
    underReplacedVerify.verified + ")", underReplacedVerify.verified === false);
  check("M19ao: CONTROL the same document is still unverified with the real verifier, and a genuine " +
    "one still verifies",
    (await pki.tuf.verifySignatures({ metadata: zeroSigned, keys: signed.keys,
      role: signed.roles.root })).verified === false &&
    (await pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: signed.roles.root })).verified === true);
  check("M19ab: CONTROL a plain parsed document is unaffected by the refusal",
    (await pki.tuf.verifySignatures({ metadata: plain, keys: specA.keys,
      role: specA.roles.root })).verified === true &&
    pki.tuf.checkExpiry(plain, NOW) === true);
  /* A Proxy answers from a trap rather than from a descriptor, so a field check cannot see it: one
     handing over a supported body when asked, while carrying an unsupported one otherwise, had both
     verbs answer positively about a document the object never held. The object has to be a plain
     record, which is the refusal the rest of the toolkit already applies to a caller record. */
  var badBody = { _type: "root", spec_version: "2.0.31", version: 1, expires: "2020-01-01T00:00:00Z",
    keys: specA.keys, roles: specA.roles };
  var target = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  var goodBody = target.signed;
  target.signed = badBody;
  var masked = new Proxy(target, {
    get: function (t, k, recv) { return k === "signed" ? goodBody : Reflect.get(t, k, recv); },
  });
  var proxyVerify = await codeAsync(pki.tuf.verifySignatures({ metadata: masked, keys: specA.keys,
    role: specA.roles.root }));
  var proxyExpiry = code(function () { pki.tuf.checkExpiry(masked, NOW); });
  check("M19ac: a Proxy metadata object is refused rather than answered (" + proxyVerify + ", " +
    proxyExpiry + ")",
    proxyVerify === "tuf/bad-input" && proxyExpiry === "tuf/bad-input");
  /* The signature records are caller objects too, and their fields are read inside the loop that
     verifies: a getter on `sig` runs there and could change the carried document while verification is
     still resolving. Each record is held to being a plain object with plain fields. */
  var sigGetter = pki.tuf.parseMetadata(metadataFor(specA, [a]));
  var heldSig = sigGetter.signatures[0].sig;
  Object.defineProperty(sigGetter.signatures[0], "sig", {
    enumerable: true, configurable: true,
    get: function () { sigGetter.signed.spec_version = "2.0.31"; return heldSig; },
  });
  check("M19ad: an accessor on a signature record's own field is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: sigGetter, keys: specA.keys,
      role: specA.roles.root })) === "tuf/bad-metadata");
  check("M19ae: and a signature record that is a Proxy is refused as well",
    await codeAsync(pki.tuf.verifySignatures({
      metadata: (function () {
        var m = pki.tuf.parseMetadata(metadataFor(specA, [a]));
        m.signatures[0] = new Proxy(m.signatures[0], { get: function (t, k, rc) { return Reflect.get(t, k, rc); } });
        return m;
      })(),
      keys: specA.keys, role: specA.roles.root })) === "tuf/bad-metadata");
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

  /* "Metadata is written according to version "spec_version" of the specification, and clients MUST verify
     that "spec_version" matches the expected version number", with adopters free to decide what counts as
     a match. This build implements 1.x, so the MAJOR version is the match: a later 1.x document is written
     to rules that extend these, while a 2.x document is written to rules this build does not have. A root
     naming no version states nothing to match and TAP 6 makes the field mandatory, so it is refused rather
     than assumed to be this one. Without this, a root omitting the field or declaring 2.0.0 was adopted
     and read under 1.x rules. */
  function adopt(specVersion) {
    var cand = rootSigned({ signers: [k2], version: 2, specVersion: specVersion });
    return codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [metadataFor(cand, [k1, k2])], now: NOW }));
  }
  check("T3a: CONTROL a candidate naming this build's major version is adopted",
    await adopt("1.0.31") === "NO-THROW");
  check("T3b: and a later 1.x minor is adopted too, the match being the major version",
    await adopt("1.9.7") === "NO-THROW");
  check("T3c: a candidate naming another major version is refused",
    await adopt("2.0.0") === "tuf/unsupported-spec-version");
  check("T3d: a candidate naming no spec_version at all is refused, TAP 6 requiring the field",
    await adopt(null) === "tuf/bad-metadata");
  /* A value that is not a semantic version is MALFORMED rather than a version this build does not
     implement: the specification sec. 4.3 states the field's format as "the Semantic Versioning 2.0.0
     (semver) specification", so a field that is not one states no version to match at all. */
  check("T3e: and a spec_version that is not a semantic version is malformed",
    await adopt("one point oh") === "tuf/bad-metadata" &&
    await adopt("1.") === "tuf/bad-metadata" &&
    await adopt("1.0.0oops") === "tuf/bad-metadata");
  /* The trusted root is a separate route into the same rule: it is the caller's own anchor rather than
     a document fetched from the repository, and a chain anchored in a root this build cannot read is
     walked under rules that root does not state. */
  function anchoredIn(specVersion) {
    var anchor = rootSigned({ signers: [k1], version: 1, specVersion: specVersion });
    return codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(anchor, [k1]), candidates: [], now: NOW }));
  }
  check("T3f: CONTROL an anchor naming this build's major version is read",
    await anchoredIn("1.0.31") === "NO-THROW");
  check("T3g: a trusted root naming another major version is refused, as a candidate is",
    await anchoredIn("2.0.0") === "tuf/unsupported-spec-version" &&
    await anchoredIn(null) === "tuf/bad-metadata");

  /* "A role for each of "root", "snapshot", "targets", and "timestamp" MUST be specified in the roles
     object" (specification sec. 4.3), and "The role of "mirror" is OPTIONAL". A root carrying only its
     own role was adopted, which leaves the client holding a trust anchor that cannot authenticate any
     other metadata the repository publishes: there is no keyids list or threshold to check targets,
     snapshot or timestamp against. Each of the four is held to naming a keyids array and a positive
     integer threshold, those being what makes the record usable rather than merely present. */
  function rolesMissing(drop) {
    var full = {
      root: { keyids: [k1.keyId], threshold: 1 },
      targets: { keyids: [k1.keyId], threshold: 1 },
      snapshot: { keyids: [k1.keyId], threshold: 1 },
      timestamp: { keyids: [k1.keyId], threshold: 1 },
    };
    if (drop) delete full[drop];
    var anchor = rootSigned({ signers: [k1], version: 1, roles: full });
    return codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(anchor, [k1]), candidates: [],
      now: NOW }));
  }
  check("T3h: CONTROL a root naming all four top-level roles is read",
    await rolesMissing(null) === "NO-THROW");
  var missing = [];
  for (var rm = 0; rm < 3; rm++) {
    var role = ["targets", "snapshot", "timestamp"][rm];
    var got = await rolesMissing(role);
    if (got !== "tuf/bad-metadata") missing.push(role + " -> " + got);
  }
  check("T3i: a root omitting targets, snapshot or timestamp is refused (" +
    (missing.length ? missing.join(", ") : "all three refused") + ")", missing.length === 0);
  /* A role that is present but states no keyids or no usable threshold is the same gap with an extra
     step: the record exists and still cannot authenticate anything. */
  function rolesWith(role, record) {
    var full = {
      root: { keyids: [k1.keyId], threshold: 1 },
      targets: { keyids: [k1.keyId], threshold: 1 },
      snapshot: { keyids: [k1.keyId], threshold: 1 },
      timestamp: { keyids: [k1.keyId], threshold: 1 },
    };
    full[role] = record;
    var anchor = rootSigned({ signers: [k1], version: 1, roles: full });
    return codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(anchor, [k1]), candidates: [],
      now: NOW }));
  }
  /* A FRACTIONAL threshold is not in this list on purpose: canonical JSON admits no floating point,
     so the signer refuses to encode one and the parse's own `integersOnly` refuses it as
     `tuf/bad-json` before any role record is read. It is unreachable here rather than unchecked. */
  check("T3j: a top-level role with no keyids array, or a threshold that is not a positive integer, " +
    "is refused",
    await rolesWith("snapshot", { threshold: 1 }) === "tuf/bad-metadata" &&
    await rolesWith("snapshot", { keyids: "not-an-array", threshold: 1 }) === "tuf/bad-metadata" &&
    await rolesWith("targets", { keyids: [k1.keyId] }) === "tuf/bad-metadata" &&
    await rolesWith("targets", { keyids: [k1.keyId], threshold: 0 }) === "tuf/bad-metadata" &&
    await rolesWith("timestamp", { keyids: [k1.keyId], threshold: -1 }) === "tuf/bad-metadata");
  check("T3k: and the optional mirrors role is not required, the specification calling it OPTIONAL",
    await rolesMissing("mirrors") === "NO-THROW");
  /* A role can be PRESENT and still state no signer this root carries, which is the same gap wearing a
     well-formed shape. Two of these are the specification's own words and two are this toolkit
     refusing a record that cannot be used, with the specification silent:
       - "The identifier of the key signing the ROLE object, which is a hexdigest of the SHA-256 hash
         of the canonical form of the key", so a keyid that is not a string is not a KEYID; and
         "A positive integer number of keys (>=1)" for the threshold.
       - An EMPTY keyids list, and a keyid with no entry in the root's own `keys` map, name no key that
         exists. A threshold above the number of keys the role names can never be met. The
         specification does not say so, and the refusals say which of the two they are. */
  var unusable = [];
  var UNUSABLE = [
    ["a keyid that is not a string", { keyids: [7], threshold: 1 }],
    ["a null keyid", { keyids: [null], threshold: 1 }],
    ["an object keyid", { keyids: [{}], threshold: 1 }],
    ["an empty keyids list", { keyids: [], threshold: 1 }],
    ["a keyid the keys map does not carry", { keyids: ["00".repeat(32)], threshold: 1 }],
    ["a threshold above the number of keys named", { keyids: [k1.keyId], threshold: 2 }],
    /* A DUPLICATE inflates the count the threshold is compared against, so a role naming one key
       twice for a threshold of two reads as reachable and is not: a verdict counts each key id once,
       so one signature is all that list can ever produce. */
    ["one key named twice for a threshold of two", { keyids: [k1.keyId, k1.keyId], threshold: 2 }],
  ];
  for (var ui = 0; ui < UNUSABLE.length; ui++) {
    var got2 = await rolesWith("targets", UNUSABLE[ui][1]);
    if (got2 !== "tuf/bad-metadata") unusable.push(UNUSABLE[ui][0] + " -> " + got2);
  }
  check("T3l: a role present but naming no usable signer is refused (" +
    (unusable.length ? unusable.join(" | ") : UNUSABLE.length + " forms refused") + ")",
    unusable.length === 0);
  /* EXISTENCE IS NOT IDENTITY. A role can name a 64-character identifier the keys map does carry while
     the key filed there hashes to a different one, which is the same "a key listed under an identifier
     that is not its own" M9 refuses where a role is VERIFIED. Only the root role is verified during a
     rotation, so a targets, snapshot or timestamp role naming a mis-filed key was adopted and failed
     later, when the client tried to use the root it had already trusted. Every identifier a mandatory
     role names is recomputed from the key filed under it, at adoption. */
  var misfiled = {};
  misfiled[k1.keyId] = k1.key;
  misfiled[k2.keyId] = k1.key;             // k1's key filed under k2's identifier
  var misfiledRoot = {
    _type: "root", spec_version: SPEC, version: 1, expires: EXPIRES, consistent_snapshot: true,
    keys: misfiled,
    roles: {
      root: { keyids: [k1.keyId], threshold: 1 },
      targets: { keyids: [k2.keyId], threshold: 1 },
      snapshot: { keyids: [k1.keyId], threshold: 1 },
      timestamp: { keyids: [k1.keyId], threshold: 1 },
    },
  };
  var misfiledCode = await codeAsync(pki.tuf.updateRoot({
    trustedRoot: metadataFor(misfiledRoot, [k1]), candidates: [], now: NOW }));
  check("T3n: a role naming a key filed under an identifier that is not its own is refused (" +
    misfiledCode + ")", misfiledCode === "tuf/bad-key");
  /* A key can be filed under its own identifier and still verify nothing, because the identifier is a
     hash of the key's canonical form and says nothing about whether the material imports. Only the
     root role is verified during a rotation, so a targets role naming such a key was adopted and the
     client found out at first use. Every key a mandatory role names is held to the same checks the
     verify applies before it looks at a signature: the material imports, the declared type matches
     what imported, and an ed25519 point is on the curve. */
  function roleKeyIs(badKey) {
    var ks = {};
    ks[k1.keyId] = k1.key;
    var badId = pki.tuf.keyId(badKey);
    ks[badId] = badKey;
    var body = {
      _type: "root", spec_version: SPEC, version: 1, expires: EXPIRES, consistent_snapshot: true,
      keys: ks,
      roles: {
        root: { keyids: [k1.keyId], threshold: 1 },
        targets: { keyids: [badId], threshold: 1 },
        snapshot: { keyids: [k1.keyId], threshold: 1 },
        timestamp: { keyids: [k1.keyId], threshold: 1 },
      },
    };
    return codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(body, [k1]), candidates: [],
      now: NOW }));
  }
  check("T3p: a role naming a key whose material does not import is refused at adoption",
    await roleKeyIs({ keytype: "rsa", scheme: "rsassa-pss-sha256",
      keyval: { public: "not a PEM" } }) === "tuf/bad-key");
  check("T3q: and an ed25519 key that is the wrong length, or not a full-order point, likewise",
    await roleKeyIs({ keytype: "ed25519", scheme: "ed25519",
      keyval: { public: "00".repeat(31) } }) === "tuf/bad-key" &&
    await roleKeyIs({ keytype: "ed25519", scheme: "ed25519",
      keyval: { public: "00".repeat(32) } }) === "tuf/bad-key");
  check("T3r: and a keytype this build does not read is refused rather than carried",
    await roleKeyIs({ keytype: "dilithium", scheme: "dilithium",
      keyval: { public: "00" } }) === "tuf/unsupported-key");

  /* CONTROL: the same root with the key filed under its own identifier is read, so the refusal is
     about the identity rather than about anything else this fixture carries. */
  var filedRight = {};
  filedRight[k1.keyId] = k1.key;
  filedRight[k2.keyId] = k2.key;
  var rightRoot = JSON.parse(JSON.stringify(misfiledRoot));
  rightRoot.keys = filedRight;
  check("T3o: CONTROL the same root with each key under its own identifier is read",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(rightRoot, [k1]), candidates: [],
      now: NOW })) === "NO-THROW");

  /* The CANDIDATE route as well as the anchor route, since a rotation is where an unusable role would
     arrive from a repository rather than from the caller's own pin. */
  var candRoles = {
    root: { keyids: [k2.keyId], threshold: 1 },
    targets: { keyids: [], threshold: 1 },
    snapshot: { keyids: [k2.keyId], threshold: 1 },
    timestamp: { keyids: [k2.keyId], threshold: 1 },
  };
  var candBad = rootSigned({ signers: [k2], version: 2, roles: candRoles });
  check("T3m: and a candidate carrying an unusable role is refused on the rotation route too",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes,
      candidates: [metadataFor(candBad, [k1, k2])], now: NOW })) === "tuf/bad-metadata");

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
  var bpSigned = { _type: "root", spec_version: SPEC, version: 1, expires: EXPIRES, keys: bpKeys,
    roles: { root: { keyids: [bpId], threshold: 1 } } };
  var bpMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: bpId, sig: "00" }], signed: bpSigned })));
  check("G3: a public key that is not a readable PEM is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: bpMeta, keys: bpKeys, role: bpSigned.roles.root })) === "tuf/bad-key");
  var alien = { keytype: "dilithium", scheme: "dilithium", keyval: { public: "00" } };
  var alId = pki.tuf.keyId(alien); var alKeys = {}; alKeys[alId] = alien;
  var alSigned = { _type: "root", spec_version: SPEC, version: 1, expires: EXPIRES, keys: alKeys,
    roles: { root: { keyids: [alId], threshold: 1 } } };
  var alMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: alId, sig: "00" }], signed: alSigned })));
  check("G4: a key type this build does not read is refused, not skipped",
    await codeAsync(pki.tuf.verifySignatures({ metadata: alMeta, keys: alKeys, role: alSigned.roles.root })) === "tuf/unsupported-key");
  /* An ed25519 key of the wrong length, and one that is not a full-order point. */
  var shortEd = { keytype: "ed25519", scheme: "ed25519", keyval: { public: "00".repeat(31) } };
  var seId = pki.tuf.keyId(shortEd); var seKeys = {}; seKeys[seId] = shortEd;
  var seSigned = { _type: "root", spec_version: SPEC, version: 1, expires: EXPIRES, keys: seKeys,
    roles: { root: { keyids: [seId], threshold: 1 } } };
  var seMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: seId, sig: "00".repeat(64) }], signed: seSigned })));
  check("G5: an ed25519 key that is not 32 bytes is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: seMeta, keys: seKeys, role: seSigned.roles.root })) === "tuf/bad-key");
  var lowOrder = { keytype: "ed25519", scheme: "ed25519", keyval: { public: "00".repeat(32) } };
  var loId = pki.tuf.keyId(lowOrder); var loKeys = {}; loKeys[loId] = lowOrder;
  var loSigned = { _type: "root", spec_version: SPEC, version: 1, expires: EXPIRES, keys: loKeys,
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
    type: "root", specVersion: SPEC, version: 1, signed: docV1,
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
  /* A17: `signedBytes` is bounded before it is copied. These bytes must equal the canonical form of a
     body that itself came from a document no larger than the cap, so anything above it cannot match,
     and copying it first paid an allocation the size of whatever arrived to reach that conclusion:
     measured, a 32 MiB value allocated 32 MiB before the comparison rejected it. MEASURED by
     allocation, `arrayBuffers` counting exactly the pool a Buffer copy comes from. */
  var oversizeSigned = Buffer.alloc(pki.C.LIMITS.JSON_MAX_BYTES * 8, 0x41);
  var allocBefore = process.memoryUsage().arrayBuffers;
  var oversizeCode = await pki.tuf.verifySignatures({
    metadata: { type: "root", specVersion: SPEC, version: 1, signed: docV1,
      signedBytes: oversizeSigned, signatures: [] },
    keys: {}, role: { keyids: [], threshold: 1 },
  }).then(function () { return "NO-THROW"; }, function (e) { return e.code; });
  var allocGrewMiB = (process.memoryUsage().arrayBuffers - allocBefore) / (1024 * 1024);
  check("A17: a signedBytes above the document cap is refused without being copied (" + oversizeCode +
    ", " + allocGrewMiB.toFixed(1) + " MiB)",
  oversizeCode === "tuf/too-large" && allocGrewMiB < 1);
  /* CONTROL: a signedBytes WITHIN the cap is still read and still compared, so A17 bounds the copy
     rather than narrowing what the verb accepts. */
  var withinCap = await pki.tuf.verifySignatures({
    metadata: { type: "root", specVersion: SPEC, version: 1, signed: docV1,
      signedBytes: Buffer.from(preV1), signatures: [] },
    keys: {}, role: { keyids: [], threshold: 1 },
  }).then(function (v) { return v.verified === false ? "read" : "verified"; }, function (e) { return e.code; });
  check("A17a: CONTROL a signedBytes within the cap is still read and compared (" + withinCap + ")",
    withinCap === "read");
  /* A17b: and the SAME field on the expiry route, which carries its own copy of that comparison. The
     bound was applied to the verify path alone, so the same oversized value still allocated here: the
     rule reached one of the two verbs that compare this field. */
  var expiryBefore = process.memoryUsage().arrayBuffers;
  var expiryCode;
  try {
    pki.tuf.checkExpiry({ type: "root", specVersion: SPEC, version: 1, signed: docV1,
      signedBytes: oversizeSigned, signatures: [] }, new Date());
    expiryCode = "NO-THROW";
  } catch (e) { expiryCode = e.code; }
  var expiryGrewMiB = (process.memoryUsage().arrayBuffers - expiryBefore) / (1024 * 1024);
  check("A17b: checkExpiry bounds the same field before copying it (" + expiryCode + ", " +
    expiryGrewMiB.toFixed(1) + " MiB)",
  expiryCode === "tuf/too-large" && expiryGrewMiB < 1);
  /* CONTROL: each signature does verify against its OWN document, so A16 is about the swap rather than
     either signature being bad. */
  var justA = await pki.tuf.verifySignatures({
    metadata: { type: "root", specVersion: SPEC, version: 1, signed: docV1,
      signedBytes: Buffer.from(preV1),
      signatures: [{ keyid: a.keyId, sig: crypto.sign(null, preV1, a.kp.privateKey).toString("hex") }] },
    keys: docV1.keys, role: { keyids: [a.keyId, b.keyId], threshold: 1 },
  });
  var justB = await pki.tuf.verifySignatures({
    metadata: { type: "root", specVersion: SPEC, version: 2, signed: docV2,
      signedBytes: Buffer.from(preV2),
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

  // The salt length is the signer's to choose and the scheme name does not state it. `rsassa-pss-sha256`
  // fixes the hash and the padding and says nothing about the salt, and the reference implementation
  // signs with the longest salt the modulus allows, so metadata in the wild carries one. A verifier that
  // insists on a digest-length salt rejects it and the root rotation it carries stops.
  var maxSaltSig = crypto.sign("sha256", pki.tuf.canonicalJson(rshell.signedObj), {
    key: rsaKp.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
  }).toString("hex");
  var rmax = rootWith(rsaKey, rsaId, maxSaltSig);
  // CONTROL: the two signatures really do differ in salt length, so A9a is not a second A9. A
  // digest-salt signature verifies under either rule, so only the maximum-salt one distinguishes them.
  check("A9a: CONTROL the maximum-salt signature is not the digest-salt one",
    maxSaltSig !== pssSig &&
    crypto.verify("sha256", pki.tuf.canonicalJson(rshell.signedObj), {
      key: rsaKp.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, Buffer.from(maxSaltSig, "hex")) === false);
  check("A9b: a PSS signature made with the longest salt the key allows verifies",
    (await pki.tuf.verifySignatures({
      metadata: rmax.meta, keys: rmax.signedObj.keys, role: rmax.signedObj.roles.root,
    })).verified === true);
  // And reading the salt from the signature does not loosen the hash or the padding: a PKCS#1 v1.5
  // signature under the same key is still refused, which is the thing the scheme name does fix.
  var v15Sig = crypto.sign("sha256", pki.tuf.canonicalJson(rshell.signedObj), rsaKp.privateKey).toString("hex");
  var rv15 = rootWith(rsaKey, rsaId, v15Sig);
  check("A9c: and a PKCS#1 v1.5 signature under that same key is still refused",
    (await pki.tuf.verifySignatures({
      metadata: rv15.meta, keys: rv15.signedObj.keys, role: rv15.signedObj.roles.root,
    })).verified === false);
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
