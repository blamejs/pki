// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// A minted FIDO Metadata Service BLOB and the trust material to verify it.
//
// The live FIDO BLOB cannot be a committed fixture: it is signed by a root this project does not
// hold, it expires, and its sequence number moves, so every vector built on it would rot. Minting
// one keeps the whole shape under test -- the JWS, the x5c chain to a root, the payload, the status
// reports, the per-entry attestation anchors -- with every field a vector needs to break.
//
// One builder, so a vector breaks exactly one thing and everything else stays conformant. Every
// option defaults to the valid value; passing one substitutes a single defect.

var pki = require("../../index.js");

function b64u(buf) { return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

async function mint(o) {
  o = o || {};
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2027-01-01T00:00:00Z");
  var ec = { name: "ECDSA", namedCurve: "P-256" };
  async function pair() {
    var kp = await pki.webcrypto.subtle.generateKey(ec, true, ["sign", "verify"]);
    return { kp: kp, spki: Buffer.from(await pki.webcrypto.subtle.exportKey("spki", kp.publicKey)) };
  }
  async function ca(name, k) {
    return pki.x509.sign({ subject: [{ commonName: name }], subjectPublicKey: k.spki, serialNumber: Buffer.from([1]),
      notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
    }, { key: k.kp.privateKey, name: [{ commonName: name }], publicKey: k.spki });
  }
  var root = await pair(), leaf = await pair(), other = await pair(), attRoot = await pair();
  var rootDer = await ca("Test FIDO Metadata Root", root);
  var otherDer = await ca("Unrelated Root", other);
  var attRootDer = await ca("Test Attestation Root", attRoot);
  var leafDer = await pki.x509.sign({
    subject: [{ commonName: "Test MDS Signer" }], subjectPublicKey: leaf.spki, serialNumber: Buffer.from([2]),
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] },
  }, { key: root.kp.privateKey, name: [{ commonName: "Test FIDO Metadata Root" }], publicKey: root.spki });

  // `aaguid: null` omits it entirely -- the U2F shape, where the authenticator declares no model
  // identity and the catalogue keys it by its attestation certificates instead.
  //
  // MDS v3.0 sec. 3.1.1 puts `attestationCertificateKeyIdentifiers` on the ENTRY, a sibling of
  // `metadataStatement`. `keyIdentifiers` places it there, which is what a conforming BLOB looks
  // like; `statementExtra` still reaches inside the statement, for the sec. 3.2 copy live entries
  // also carry. A fixture that only ever populated the statement would validate an implementation
  // that reads the wrong level against itself.
  var entry = {
    statusReports: o.statusReports || [{ status: "FIDO_CERTIFIED_L1", effectiveDate: "2026-01-01" }],
    timeOfLastStatusChange: "2026-01-01",
    metadataStatement: Object.assign({ attestationRootCertificates: o.anchors || [attRootDer.toString("base64")] }, o.statementExtra || {}) };
  if (o.aaguid !== null) entry.aaguid = o.aaguid || "01020304-0506-0708-090a-0b0c0d0e0f10";
  if (o.keyIdentifiers !== undefined) entry.attestationCertificateKeyIdentifiers = o.keyIdentifiers;
  var payload = Object.assign({ legalHeader: "Test metadata, not for production use.",
    no: o.no === undefined ? 42 : o.no, nextUpdate: o.nextUpdate === undefined ? "2027-06-01" : o.nextUpdate,
    entries: o.entries || [entry] }, o.payloadExtra || {});
  (o.payloadOmit || []).forEach(function (k) { delete payload[k]; });
  // crossSignRoot terminates the chain in a CROSS-SIGNED form of this fixture's own root: a
  // certificate carrying the root's subject and public key but issued by an unrelated CA, so it is
  // not self-issued. The signer leaf is unchanged and the chain is still anchored by the root's key
  // -- only the certificate that carries that key is a different one. Built here, inside the mint,
  // because it has to be the SAME root the returned rootDer anchors to.
  // x5cSelfOnly signs the BLOB with the ROOT's own key and presents only the root: a chain that IS
  // the anchor, with nothing left to chain once the anchor is recognised.
  var chain = o.x5c || [leafDer, rootDer];
  var selfOnlyDer = null;
  if (o.x5cSelfOnly) {
    // A self-signed certificate that both signs the BLOB and IS the pinned anchor, so it asserts
    // digitalSignature as well as certificate signing -- a CA certificate restricted to signing
    // certificates may not sign a JWS, and the verifier is right to refuse one that tries.
    selfOnlyDer = await pki.x509.sign({
      subject: [{ commonName: "Test Self-Anchored Signer" }], subjectPublicKey: root.spki,
      serialNumber: Buffer.from([55]), notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["digitalSignature", "keyCertSign", "cRLSign"] },
    }, { key: root.kp.privateKey, name: [{ commonName: "Test Self-Anchored Signer" }], publicKey: root.spki });
    chain = [selfOnlyDer];
  }
  if (o.crossSignRoot) {
    var xCa = await pair();
    var crossDer = await pki.x509.sign({
      subject: [{ commonName: "Test FIDO Metadata Root" }], subjectPublicKey: root.spki,
      serialNumber: Buffer.from([44]), notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
    }, { key: xCa.kp.privateKey, name: [{ commonName: "Cross Signing CA" }], publicKey: xCa.spki });
    chain = [leafDer, crossDer];
  }
  var header = Object.assign({ alg: o.alg || "ES256", typ: "JWT",
    x5c: o.x5cRaw || chain.map(function (d) { return d.toString("base64"); }) }, o.headerExtra || {});

  // headerRaw / payloadRaw substitute the serialized JSON wholesale, for a vector whose defect is
  // the JSON's own shape (a valid document that is not an object) rather than any field in it.
  // payloadRaw64 substitutes the encoded segment itself, for a segment that is not decodable at all
  // -- and because the signature is computed over the segments as written, the BLOB still verifies,
  // so the fault surfaces at the payload reader instead of being masked by the signature gate.
  var h64 = b64u(Buffer.from(o.headerRaw === undefined ? JSON.stringify(header) : o.headerRaw, "utf8"));
  var p64 = o.payloadRaw64 !== undefined ? o.payloadRaw64
    : b64u(Buffer.from(o.payloadRaw === undefined ? JSON.stringify(payload) : o.payloadRaw, "utf8"));
  var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    ((o.signWithRoot || o.x5cSelfOnly) ? root.kp : leaf.kp).privateKey, Buffer.from(h64 + "." + p64, "ascii")));
  // signerKey is the leaf's private half: a consumer that mutates the payload can re-sign, so a
  // mutation arrives past the signature gate instead of being rejected ahead of the payload reader.
  return { blob: Buffer.from(h64 + "." + p64 + "." + b64u(o.badSig ? Buffer.alloc(sig.length, 9) : sig), "utf8"),
    rootDer: selfOnlyDer || rootDer, otherDer: otherDer, attRootDer: attRootDer, aaguid: entry.aaguid || null,
    signerKey: leaf.kp.privateKey };
}

// A fido-u2f attestation minted end to end, with its own root.
//
// The real u2f attestation in the test vectors chains to a vendor root this project does not hold,
// so it cannot be used for a vector that requires the trust path to actually VALIDATE to a
// registered anchor. This mints the same shape with a root under test control: a U2F authenticator
// declares no AAGUID (its authenticatorData carries all zeroes), which is exactly the case the
// metadata catalogue keys by attestation-certificate key identifier instead.
//
// The authenticatorData is taken from the real vector, so the credential public key, the flags and
// the rpIdHash are genuine; only the attestation certificate and the signature over the
// verificationData are re-made, which is what the anchor check reads.
async function mintU2fAttestation() {
  var nodeCrypto = require("node:crypto");
  var fs = require("fs"), path = require("path");
  var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "webauthn", "py-webauthn-kat.json"), "utf8"));
  function kb64u(s) { var b = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (b.length % 4) b += "="; return Buffer.from(b, "base64"); }

  var att = pki.webauthn.parseAttestationObject(kb64u(KAT.formats.fido_u2f.attestationObject));
  var authDataBytes = att.authDataBytes;
  var clientDataHash = nodeCrypto.createHash("sha256").update(kb64u(KAT.formats.fido_u2f.clientDataJSON)).digest();

  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2027-01-01T00:00:00Z");
  var ec = { name: "ECDSA", namedCurve: "P-256" };
  async function pair() {
    var kp = await pki.webcrypto.subtle.generateKey(ec, true, ["sign", "verify"]);
    return { kp: kp, spki: Buffer.from(await pki.webcrypto.subtle.exportKey("spki", kp.publicKey)) };
  }
  var root = await pair(), attKey = await pair();
  var rootDer = await pki.x509.sign({
    subject: [{ commonName: "Test U2F Root CA" }], subjectPublicKey: root.spki, serialNumber: Buffer.from([1]),
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: root.kp.privateKey, name: [{ commonName: "Test U2F Root CA" }], publicKey: root.spki });
  var attCertDer = await pki.x509.sign({
    subject: [{ commonName: "Test U2F Attestation" }], subjectPublicKey: attKey.spki, serialNumber: Buffer.from([2]),
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] },
  }, { key: root.kp.privateKey, name: [{ commonName: "Test U2F Root CA" }], publicKey: root.spki });

  // WebAuthn sec. 8.6: the signature covers 0x00 || rpIdHash || clientDataHash || credentialId ||
  // publicKeyU2F, where publicKeyU2F is the uncompressed EC point of the credential key.
  var ad = att.authData;
  var ck = ad.credentialPublicKey;
  var pubU2F = Buffer.concat([Buffer.from([0x04]), Buffer.from(ck.x), Buffer.from(ck.y)]);
  var verificationData = Buffer.concat([Buffer.from([0x00]), Buffer.from(ad.rpIdHash),
    clientDataHash, Buffer.from(ad.credentialId), pubU2F]);
  // fido-u2f carries a DER ECDSA signature (sec. 8.6), while WebCrypto produces the raw r||s pair,
  // so the pair is re-encoded as the SEQUENCE the format expects. Encoding through the toolkit's own
  // INTEGER builder keeps the minimal, non-negative form a strict decoder requires.
  var raw = Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    attKey.kp.privateKey, verificationData));
  var ab = pki.asn1.build;
  var sig = ab.sequence([
    ab.integer(BigInt("0x" + raw.subarray(0, raw.length / 2).toString("hex"))),
    ab.integer(BigInt("0x" + raw.subarray(raw.length / 2).toString("hex"))),
  ]);

  var b = pki.cbor.build;
  function assemble(ad) {
    return b.map([
      [b.textString("fmt"), b.textString("fido-u2f")],
      [b.textString("attStmt"), b.map([
        [b.textString("sig"), b.byteString(sig)],
        [b.textString("x5c"), b.array([b.byteString(attCertDer)])],
      ])],
      [b.textString("authData"), b.byteString(ad)],
    ]);
  }
  // withAaguid rewrites the 16 AAGUID bytes and reuses the SAME signature -- which is the whole
  // point, and why it needs no key. The fido-u2f signature covers
  // 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F, which does NOT include the
  // AAGUID, so anyone holding a genuine attestation can rewrite that field and it still verifies. A
  // verifier that reports the field as an identity, or resolves an unlisted value out of some other
  // key space, is vouching for bytes nothing signed. AAGUID sits at offset 37 of authenticatorData:
  // rpIdHash(32) + flags(1) + signCount(4).
  function withAaguid(hex) {
    var ad = Buffer.from(authDataBytes);
    Buffer.from(hex.replace(/-/g, ""), "hex").copy(ad, 37);
    return assemble(ad);
  }
  return { attestationObject: assemble(authDataBytes), clientDataHash: clientDataHash,
    rootDer: rootDer, attCertDer: attCertDer, withAaguid: withAaguid };
}

// A compound (sec. 8.9) whose two certificate-bearing elements use DIFFERENT formats: one packed,
// whose AAGUID is covered by its signature, and one fido-u2f, whose AAGUID is not.
//
// This shape is what distinguishes a per-element identifier choice from a single choice made for
// the whole statement. Both elements are minted here and signed over the SAME authenticatorData --
// which is what sec. 8.9 requires -- carrying a NON-zero AAGUID, so the packed element has a real
// model identity to be looked up by while the u2f element's copy of that field is unsigned.
async function mintMixedCompound(aaguidHex, splitRoots) {
  var nodeCrypto = require("node:crypto");
  var fs = require("fs"), path = require("path");
  var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "webauthn", "py-webauthn-kat.json"), "utf8"));
  function kb64u(s) { var b = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (b.length % 4) b += "="; return Buffer.from(b, "base64"); }

  var src = pki.webauthn.parseAttestationObject(kb64u(KAT.formats.fido_u2f.attestationObject));
  var clientDataHash = nodeCrypto.createHash("sha256").update(kb64u(KAT.formats.fido_u2f.clientDataJSON)).digest();
  // The AAGUID lives at offset 37: rpIdHash(32) + flags(1) + signCount(4).
  var authDataBytes = Buffer.from(src.authDataBytes);
  Buffer.from(aaguidHex.replace(/-/g, ""), "hex").copy(authDataBytes, 37);
  var ad = pki.webauthn.parseAttestationObject(kb64u(KAT.formats.fido_u2f.attestationObject)).authData;

  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2027-01-01T00:00:00Z");
  var ec = { name: "ECDSA", namedCurve: "P-256" };
  async function pair() {
    var kp = await pki.webcrypto.subtle.generateKey(ec, true, ["sign", "verify"]);
    return { kp: kp, spki: Buffer.from(await pki.webcrypto.subtle.exportKey("spki", kp.publicKey)) };
  }
  function derSig(raw) {
    var ab = pki.asn1.build;
    return ab.sequence([
      ab.integer(BigInt("0x" + raw.subarray(0, raw.length / 2).toString("hex"))),
      ab.integer(BigInt("0x" + raw.subarray(raw.length / 2).toString("hex"))),
    ]);
  }
  var root = await pair(), u2fKey = await pair(), packedKey = await pair();
  var rootDer = await pki.x509.sign({
    subject: [{ commonName: "Test Mixed Root CA" }], subjectPublicKey: root.spki, serialNumber: Buffer.from([1]),
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: root.kp.privateKey, name: [{ commonName: "Test Mixed Root CA" }], publicKey: root.spki });
  // A SECOND, unrelated root. The default keeps both elements under one root, which is what
  // most vectors want; `splitRoots` issues the u2f element under this one instead, so a
  // compound can hold two elements whose chains reach DIFFERENT roots. That separation is
  // what lets a test tell "each element anchored by its own route" apart from "both happened
  // to share a root", which a single-root fixture cannot distinguish.
  var root2 = await pair();
  var root2Der = await pki.x509.sign({
    subject: [{ commonName: "Test Mixed Root CA 2" }], subjectPublicKey: root2.spki, serialNumber: Buffer.from([9]),
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: root2.kp.privateKey, name: [{ commonName: "Test Mixed Root CA 2" }], publicKey: root2.spki });
  async function leafUnder(issuer, issuerCn, k, cn, serial) {
    return pki.x509.sign({
      subject: [{ countryName: "US" }, { organizationName: "Test" }, { organizationalUnitName: "Authenticator Attestation" }, { commonName: cn }],
      subjectPublicKey: k.spki, serialNumber: Buffer.from([serial]), notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { critical: true, cA: false } },
    }, { key: issuer.kp.privateKey, name: [{ commonName: issuerCn }], publicKey: issuer.spki });
  }
  function leafFor(k, cn, serial) { return leafUnder(root, "Test Mixed Root CA", k, cn, serial); }
  var u2fCertDer = splitRoots
    ? await leafUnder(root2, "Test Mixed Root CA 2", u2fKey, "Test U2F Attestation", 2)
    : await leafFor(u2fKey, "Test U2F Attestation", 2);
  var packedCertDer = await leafFor(packedKey, "Test Packed Attestation", 3);

  // fido-u2f (sec. 8.6): 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F.
  var ck = ad.credentialPublicKey;
  var pubU2F = Buffer.concat([Buffer.from([0x04]), Buffer.from(ck.x), Buffer.from(ck.y)]);
  var u2fSig = derSig(Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, u2fKey.kp.privateKey,
    Buffer.concat([Buffer.from([0x00]), Buffer.from(ad.rpIdHash), clientDataHash, Buffer.from(ad.credentialId), pubU2F]))));
  // packed (sec. 8.2): the signature covers authenticatorData || clientDataHash.
  var packedSig = derSig(Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, packedKey.kp.privateKey,
    Buffer.concat([authDataBytes, clientDataHash]))));

  var b = pki.cbor.build;
  function element(fmt, attStmt) { return b.map([[b.textString("fmt"), b.textString(fmt)], [b.textString("attStmt"), attStmt]]); }
  var attestationObject = b.map([
    [b.textString("fmt"), b.textString("compound")],
    [b.textString("attStmt"), b.array([
      element("packed", b.map([
        [b.textString("alg"), b.int(-7)],
        [b.textString("sig"), b.byteString(packedSig)],
        [b.textString("x5c"), b.array([b.byteString(packedCertDer)])],
      ])),
      element("fido-u2f", b.map([
        [b.textString("sig"), b.byteString(u2fSig)],
        [b.textString("x5c"), b.array([b.byteString(u2fCertDer)])],
      ])),
    ])],
    [b.textString("authData"), b.byteString(authDataBytes)],
  ]);
  return { attestationObject: attestationObject, clientDataHash: clientDataHash, rootDer: rootDer,
    root2Der: root2Der, packedCertDer: packedCertDer, u2fCertDer: u2fCertDer };
}

module.exports = { mint: mint, b64u: b64u, mintU2fAttestation: mintU2fAttestation, mintMixedCompound: mintMixedCompound };
