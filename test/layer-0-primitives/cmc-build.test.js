// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cmc.build (RFC 5272 sec. 3.2, 6.2.1, 6.3.1.1; RFC 6402).
 *
 * The producing half of the CMC message layer: assemble a Full PKI Request
 * (PKIData), attach its controls, and sign it into a CMS SignedData whose
 * encapsulated content type is id-cct-PKIData. Spec-first vectors, RED-first --
 * pki.cmc.build is undefined until the module lands.
 *
 * The rules this file exists to pin:
 *   - PD2: all FOUR sequences are emitted, each possibly empty.
 *   - PD8: body part identifiers are unique across the WHOLE message and 0 is
 *     reserved, so the allocator never issues it and a caller-supplied clash is
 *     refused rather than silently renumbered.
 *   - IP1: the Identity Proof witness is computed over the reqSequence bytes
 *     "encoded exactly as it appears in the Full PKI Request including the
 *     sequence type and length". The vector re-slices those bytes out of the
 *     EMITTED DER and recomputes -- a witness taken over a re-serialization
 *     would still agree with itself, so only the emitted-bytes check can tell
 *     the two apart.
 *   - PL1: a POP Link Witness requires the POP Link Random control to be present
 *     in the same request; R is >= 512 bits.
 *   - PD5: a renewal omits Identification / Identity Proof.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var surgery = require("../helpers/der-surgery");

// Flip one content byte of a PKCS#10's signatureValue (the LAST BIT STRING) so its proof-of-possession
// no longer verifies, while the request stays valid DER that parses.
function corruptCsrPop(csr) {
  var count = 0;
  surgery.patch(csr, function (n) { if (n.tagClass === "universal" && n.tagNumber === 3 && !n.constructed) count++; return undefined; });
  var seen = 0;
  return surgery.patch(csr, function (n) {
    if (n.tagClass === "universal" && n.tagNumber === 3 && !n.constructed) {
      seen++;
      if (seen === count) { var v = Buffer.from(n.value != null ? n.value : n.content); v[v.length - 1] ^= 0x01; return b.bitString(v.subarray(1), v[0]); }
    }
    return undefined;
  });
}

var ID_CCT_PKI_DATA = "1.3.6.1.5.5.7.12.2";
var ID_CMC_IDENTITY_PROOF_V2 = "1.3.6.1.5.5.7.7.34";   // RFC 5272 sec. 6.2.1 body + its own module
var ID_CMC_POP_LINK_RANDOM = "1.3.6.1.5.5.7.7.22";
var ID_CMC_IDENTIFICATION = "1.3.6.1.5.5.7.7.2";
var ID_CMC_TRANSACTION_ID = "1.3.6.1.5.5.7.7.5";
var ID_CMC_SENDER_NONCE = "1.3.6.1.5.5.7.7.6";
var SECRET = "a-shared-secret-at-least-16-chars";

async function acode(fn) {
  try { await fn(); return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); }
}

// Runs one verb in a child process that records every wipe. See test/helpers/observe-secret-wipe.js
// for why the observation cannot be installed in this process.
function observeWipe(payload) {
  var enc = { op: payload.op };
  ["cert", "key", "csr", "secret", "identity"].forEach(function (k) {
    if (payload[k] !== undefined) enc[k] = Buffer.from(payload[k]).toString("base64");
  });
  var r = require("node:child_process").spawnSync(process.execPath,
    [require("node:path").join(__dirname, "../helpers/observe-secret-wipe.js")],
    { encoding: "utf8", input: JSON.stringify(enc) });
  var report = null;
  if (!r.error && r.status === 0) {
    try { report = JSON.parse(String(r.stdout).trim().split("\n").pop()); } catch (_e) { report = null; }
  }
  return { status: r.status, report: report };
}

async function signer() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var spki = await pki.key.export(pair.publicKey);
  var cert = await pki.x509.sign({
    subject: "cmc-client.example", subjectPublicKey: spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
  }, { key: key });
  return { key: key, spki: spki, cert: cert };
}

async function csrFor(s, opts) {
  return await pki.csr.sign(Object.assign({ subject: "cmc-client.example", subjectPublicKey: s.spki }, opts || {}),
    { key: s.key });
}

// Re-slice the reqSequence TLV out of an EMITTED request, independently of the
// parser's own surfaced range, so IP1 is checked against the bytes on the wire.
function reqSequenceOf(der) {
  return pki.schema.cmc.parse(der).reqSequenceBytes;
}

async function run() {
  var s = await signer();
  var csrDer = await csrFor(s);

  // ---- PD1 / PD2: the envelope and the four sequences -------------------
  var basic = await pki.cmc.build({ requests: [{ tcr: csrDer }] }, { cert: s.cert, key: s.key });
  var parsed = pki.schema.cmc.parse(basic);
  check("F1. a built request is a SignedData over id-cct-PKIData that cms.verify accepts",
    parsed.kind === "pkiData" &&
    parsed.cms.encapContentInfo.eContentType === ID_CCT_PKI_DATA);
  check("F1b. the signature verifies through the shipped consumer path",
    (await pki.cms.verify(basic)).valid === true);

  // Copying the signer key to close the swap window makes a SECOND copy of a secret, so that
  // copy is cleared once signing settles rather than left for the collector. The caller's own
  // key staying untouched does not show this -- the allocated copy is what must be observed --
  // so the clear is watched where the toolkit performs it: each buffer must hold key material
  // when handed over and be all-zero afterwards. The caller's key is checked to be intact too,
  // since wiping the wrong buffer would destroy it.
  // Observed from a child process: the wipe runs through a fill captured at module load and the
  // guard family freezes its exports, so a test that wrapped the guard in-process would be doing
  // the very thing both defenses refuse -- and would report success by doing it.
  var buildObs = observeWipe({ op: "cmc-build", cert: s.cert, key: s.key, csr: csrDer });
  check("F1d. the wipe observation ran (child exit " + buildObs.status + ")", buildObs.report !== null);
  check("F1d. the signer key copy is wiped once signing settles",
    !!buildObs.report && buildObs.report.wiped.length > 0 &&
      buildObs.report.wiped.some(function (e) { return e.hadContent; }) &&
      buildObs.report.wiped.every(function (e) { return e.allZeroAfter; }));
  check("F1e. ...and the caller's own key is left intact", !!buildObs.report && buildObs.report.callerKeyIntact === true);
  check("F1c. the tcr arm round-trips to the CSR that went in",
    parsed.requests.length === 1 && parsed.requests[0].arm === "tcr" &&
    Buffer.compare(parsed.requests[0].certificationRequestBytes, csrDer) === 0);
  check("F1d. all four sequences are emitted, the unused ones empty (PD2)",
    parsed.controls.length === 0 && parsed.cmsSequence.length === 0 && parsed.otherMsgs.length === 0);

  // ---- PD8: identity allocation ----------------------------------------
  var two = await pki.cmc.build({
    requests: [{ tcr: csrDer }, { tcr: csrDer }],
    controls: [{ type: "id-cmc-transactionId", value: b.integer(7n) }],
  }, { cert: s.cert, key: s.key });
  var p2 = pki.schema.cmc.parse(two);
  var ids = p2.requests.map(function (r) { return r.bodyPartID; })
    .concat(p2.controls.map(function (c) { return c.bodyPartID; }));
  check("F1e. allocated body part identifiers are unique and never 0 (PD8)",
    ids.length === 3 && new Set(ids).size === 3 && ids.indexOf(0) === -1);

  check("F7. a caller assigning the same bodyPartID twice is refused, never renumbered",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer, bodyPartID: 5 }, { tcr: csrDer, bodyPartID: 5 }] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F7b. a caller assigning the reserved bodyPartID 0 is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer, bodyPartID: 0 }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // F7c/F7d -- the cmsSequence and otherMsgSequence elements carry body part
  // identities too (RFC 5272 sec. 3.2.1.3 / 3.2.1.4), so they draw from the SAME
  // space. Passing them through without claiming their identifiers lets the
  // builder emit a PKIData that its own parser refuses -- the producing-side
  // mirror of the whole-message uniqueness rule.
  var tci = function (id) {
    return b.sequence([b.integer(BigInt(id)),
      b.sequence([b.oid("1.2.840.113549.1.7.1"), b.explicit(0, b.octetString(Buffer.from([1])))])]);
  };
  var om = function (id) {
    return b.sequence([b.integer(BigInt(id)), b.oid("1.3.6.1.4.1.99999.3"), b.octetString(Buffer.from([9]))]);
  };

  check("F7c. a cmsSequence element colliding with a control is refused at build time",
    (await acode(function () {
      return pki.cmc.build({
        requests: [{ tcr: csrDer, bodyPartID: 8 }],
        cmsSequence: [tci(8)],
      }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F7d. an otherMsgSequence element colliding with a cmsSequence element is refused",
    (await acode(function () {
      return pki.cmc.build({
        requests: [{ tcr: csrDer }],
        cmsSequence: [tci(21)], otherMsgSequence: [om(21)],
      }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // F7g/F7h -- the SAME ordering rule inside the requests list. Every identifier
  // the CALLER determines must be reserved before any is generated, and there are
  // FOUR sources of those: an explicit request bodyPartID, a crm arm's fixed
  // certReqId, a cmsSequence element, an otherMsgSequence element. Reserving only
  // some of them makes acceptance depend on the order the caller happened to
  // write the list in.
  var orderedReq = await pki.cmc.build({
    requests: [{ tcr: csrDer }, { tcr: csrDer, bodyPartID: 1 }],
  }, { cert: s.cert, key: s.key });
  var orq = pki.schema.cmc.parse(orderedReq);
  check("F7g. an auto-id request before an explicit id=1 request does not steal it",
    orq.requests.length === 2 && orq.requests[1].bodyPartID === 1 && orq.requests[0].bodyPartID !== 1);

  var crmFixed = await pki.crmf.build({ certReqId: 3, certTemplate: { subject: "crm.example", publicKey: s.spki } },
    { key: s.key });
  var crmFirst = await pki.cmc.build({
    requests: [{ tcr: csrDer }, { crm: crmFixed }],   // its certReqId is 3, and fixed
  }, { cert: s.cert, key: s.key });
  var cfq = pki.schema.cmc.parse(crmFirst);
  check("F7h. an auto-id request does not steal a crm arm's fixed certReqId",
    cfq.requests[1].bodyPartID === 3 && cfq.requests[0].bodyPartID !== 3);

  // F7f -- allocation ORDER. The caller pinned nothing that conflicts: request 1,
  // a cmsSequence element at 2, and a generated control that could take 3. If the
  // allocator hands out numbers before reserving what the caller already spent,
  // the control takes 2 and the caller's own element then "collides" with it --
  // rejecting a spec that was never ambiguous.
  var ordered = await pki.cmc.build({
    requests: [{ tcr: csrDer, bodyPartID: 1 }],
    identityProof: { secret: SECRET },
    cmsSequence: [tci(2)],
  }, { cert: s.cert, key: s.key });
  var op2 = pki.schema.cmc.parse(ordered);
  check("F7f. a generated control does not steal an identifier a caller-supplied element already uses",
    op2.requests[0].bodyPartID === 1 && op2.cmsSequence.length === 1 &&
    op2.controls.every(function (c) { return c.bodyPartID !== 1 && c.bodyPartID !== 2; }));

  // ...and the accepting side: distinct identities across all four kinds build
  // AND re-parse, which is what proves the two sides agree.
  var allFour = await pki.cmc.build({
    requests: [{ tcr: csrDer, bodyPartID: 31 }],
    controls: [{ type: "id-cmc-transactionId", value: b.integer(1n) }],
    cmsSequence: [tci(32)], otherMsgSequence: [om(33)],
  }, { cert: s.cert, key: s.key });
  var af = pki.schema.cmc.parse(allFour);
  check("F7e. a message using all four element kinds with distinct identities builds and re-parses",
    af.requests.length === 1 && af.controls.length === 1 &&
    af.cmsSequence.length === 1 && af.otherMsgs.length === 1);

  // ---- IP1: the witness is over the EMITTED reqSequence bytes -----------
  var proofed = await pki.cmc.build({
    requests: [{ tcr: csrDer }],
    identityProof: { secret: SECRET },
  }, { cert: s.cert, key: s.key });
  var pp = pki.schema.cmc.parse(proofed);
  var proofControl = pp.controls.filter(function (c) { return c.attrType === ID_CMC_IDENTITY_PROOF_V2; })[0];
  check("F6. an identityProof request carries an Identity Proof V2 control", !!proofControl);

  // Recompute independently: key = SHA-256(secret as UTF-8), witness =
  // HMAC-SHA256(reqSequence bytes, key).
  var ipv2 = pki.asn1.decode(proofControl.values[0]);
  var witness = pki.asn1.read.octetString(ipv2.children[2]);
  var macKey = nodeCrypto.createHash("sha256").update(SECRET, "utf8").digest();
  var expect = nodeCrypto.createHmac("sha256", macKey).update(reqSequenceOf(proofed)).digest();
  check("F6b. the witness equals HMAC(emitted reqSequence TLV, hash(secret)) (RFC 5272 sec. 6.2.1)",
    Buffer.compare(witness, expect) === 0);

  // The mutation half: a DIFFERENT request must move the witness. A witness
  // computed over a re-serialization would agree with itself either way, so this
  // is what distinguishes "over the emitted bytes" from "over something equal".
  var csr2 = await csrFor(s, { subject: "other.example" });
  var proofed2 = await pki.cmc.build({ requests: [{ tcr: csr2 }], identityProof: { secret: SECRET } },
    { cert: s.cert, key: s.key });
  var pc2 = pki.schema.cmc.parse(proofed2).controls
    .filter(function (c) { return c.attrType === ID_CMC_IDENTITY_PROOF_V2; })[0];
  var witness2 = pki.asn1.read.octetString(pki.asn1.decode(pc2.values[0]).children[2]);
  check("F6c. changing a request changes the witness (it tracks the emitted bytes)",
    Buffer.compare(witness, witness2) !== 0);

  // F6e -- RFC 5272 sec. 6.2.3: the Identification control is OPTIONAL ("servers
  // MAY require" it), but when it IS present "the derivation of the key in Step 2
  // is altered so that the hash of the concatenation of the shared-secret and the
  // UTF8 identity value (without the type and length bytes) are hashed rather
  // than just the shared-secret". Same control set, DIFFERENT key -- a producer
  // that ignores the alteration emits a witness a conforming server rejects.
  var IDENTITY = "device-4711";
  var identified = await pki.cmc.build({
    requests: [{ tcr: csrDer }],
    identityProof: { secret: SECRET, identity: IDENTITY },
  }, { cert: s.cert, key: s.key });
  var ip = pki.schema.cmc.parse(identified);
  var idControl = ip.controls.filter(function (c) { return c.attrType === ID_CMC_IDENTIFICATION; })[0];
  check("F6e. an identityProof with an identity emits the Identification control carrying it",
    !!idControl && pki.asn1.read.string(pki.asn1.decode(idControl.values[0])) === IDENTITY);

  var idProof = ip.controls.filter(function (c) { return c.attrType === ID_CMC_IDENTITY_PROOF_V2; })[0];
  var idWitness = pki.asn1.read.octetString(pki.asn1.decode(idProof.values[0]).children[2]);
  var alteredKey = nodeCrypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from(SECRET, "utf8"), Buffer.from(IDENTITY, "utf8")])).digest();
  var alteredExpect = nodeCrypto.createHmac("sha256", alteredKey).update(reqSequenceOf(identified)).digest();
  check("F6f. the MAC key is hash(shared-secret || identity), not hash(shared-secret) (sec. 6.2.3)",
    Buffer.compare(idWitness, alteredExpect) === 0);

  // ...and the two derivations really differ, so F6f is not passing by accident.
  var plainKey = nodeCrypto.createHash("sha256").update(SECRET, "utf8").digest();
  check("F6g. the altered derivation differs from the plain one",
    Buffer.compare(alteredKey, plainKey) !== 0);

  // F6h -- the derivation input carries the shared secret in the clear, and with an identity
  // present the concatenation leaves two further copies of it. Clearing the derived key alone
  // would clear the cheapest copy and keep the rest, so the clear is observed where the toolkit
  // performs it: every buffer handed over must have held content and read all-zero afterwards.
  // The identity arm is used because it is the one that allocates all three.
  var derivObs = observeWipe({ op: "cmc-build-identity", cert: s.cert, key: s.key, csr: csrDer,
    secret: SECRET, identity: IDENTITY });
  check("F6h. the derivation wipe observation ran (child exit " + derivObs.status + ")", derivObs.report !== null);
  check("F6h. every copy of the shared secret the derivation allocated is cleared",
    !!derivObs.report && derivObs.report.wiped.length >= 3 &&
      derivObs.report.wiped.some(function (e) { return e.hadContent; }) &&
      derivObs.report.wiped.every(function (e) { return e.allZeroAfter; }));

  // F6d -- sec. 6.2.1's "Implementations MUST be able to support tokens at least
  // 16 characters long" is a requirement on what this code must ACCEPT, not a
  // floor every token must clear. Enforcing it as a minimum would invert the
  // clause and refuse a shorter secret a CA legitimately provisioned, whose
  // strength is that CA's policy to set.
  check("F6d. a short shared secret provisioned by the CA is accepted, not second-guessed",
    pki.schema.cmc.parse(await pki.cmc.build(
      { requests: [{ tcr: csrDer }], identityProof: { secret: "short" } },
      { cert: s.cert, key: s.key })).kind === "pkiData");

  check("F6d2. a token of exactly the length sec. 6.2.1 names is supported",
    // The capability the clause actually requires.
    pki.schema.cmc.parse(await pki.cmc.build(
      { requests: [{ tcr: csrDer }], identityProof: { secret: "0123456789abcdef" } },
      { cert: s.cert, key: s.key })).kind === "pkiData");

  check("F6d3. an empty secret is still refused -- that is not a credential",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], identityProof: { secret: "" } },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // ---- PL1: the POP Link Witness needs its Random in the same request ----
  var linked = await pki.cmc.build({
    requests: [{ tcr: csrDer }],
    popLink: { secret: SECRET },
  }, { cert: s.cert, key: s.key });
  var lp = pki.schema.cmc.parse(linked);
  var randomControl = lp.controls.filter(function (c) { return c.attrType === ID_CMC_POP_LINK_RANDOM; })[0];
  check("F8. a popLink request carries the POP Link Random control (PL1: it MUST be included)",
    !!randomControl);
  var R = pki.asn1.read.octetString(pki.asn1.decode(randomControl.values[0]));
  check("F8b. R is at least 512 bits by default (PL1 SHOULD)", R.length >= 64);

  // ---- PD5: a renewal omits Identification / Identity Proof -------------
  var renewal = await pki.cmc.build({ requests: [{ tcr: csrDer }], renewal: true }, { cert: s.cert, key: s.key });
  var rp = pki.schema.cmc.parse(renewal);
  check("F10. a renewal emits no Identification and no Identity Proof control (PD5)",
    rp.controls.every(function (c) {
      return c.attrType !== ID_CMC_IDENTIFICATION && c.attrType !== ID_CMC_IDENTITY_PROOF_V2;
    }));
  // sec. 3.2 (a) says "The Identification and Identity Proof controls are
  // absent" -- Identity Proof covers BOTH the v1 control (id-cmc 3) and V2
  // (id-cmc 34). A denylist naming only one leaves the other emittable.
  check("F10c. a renewal carrying the v1 Identity Proof control is refused (PD5 covers both versions)",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], renewal: true,
        controls: [{ type: "id-cmc-identityProof", value: b.octetString(Buffer.from([1])) }] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  check("F10d. a renewal carrying the V2 Identity Proof control is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], renewal: true,
        controls: [{ type: "id-cmc-identityProofV2", value: b.octetString(Buffer.from([1])) }] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  check("F10e. a renewal carrying the Identification control is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], renewal: true,
        controls: [{ type: "id-cmc-identification", value: b.utf8("me") }] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F10b. a renewal that ALSO asks for an identityProof is refused (PD5)",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], renewal: true, identityProof: { secret: SECRET } },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // ---- the crm / orm arms ----------------------------------------------
  var crmDer = await pki.crmf.build({ certReqId: 3, certTemplate: { subject: "crm.example", publicKey: s.spki } },
    { key: s.key });
  var withCrm = await pki.cmc.build({ requests: [{ crm: crmDer }] }, { cert: s.cert, key: s.key });
  var cp = pki.schema.cmc.parse(withCrm);
  check("C2f. the crm arm is emitted IMPLICIT and its certReqId is the body part identity",
    cp.requests[0].arm === "crm" && cp.requests[0].bodyPartID === 3);
  // A crm identity comes from its CertReqMsg's own certReqId and cannot be
  // overridden. Taking the certReqId while quietly discarding a supplied
  // bodyPartID is the same silent-drop the unknown-field door exists to stop --
  // the only reason to state an identity is that something already references it,
  // so the message would be signed with a control pointing at no request in it.
  check("C2f2. a crm request whose bodyPartID disagrees with its certReqId is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ crm: crmDer, bodyPartID: 9 }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("C2f3. and one that AGREES is accepted -- the caller is confirming, not overriding",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ crm: crmDer, bodyPartID: 3 }] },
      { cert: s.cert, key: s.key })).requests[0].bodyPartID === 3);

  check("C2g. the emitted CertReqMsg re-parses through pki.schema.crmf",
    pki.schema.crmf.parse(b.sequence([cp.requests[0].certReqMsgBytes]))
      .messages[0].certReq.certTemplate.subject.dn === "CN=crm.example");

  var withOrm = await pki.cmc.build({
    requests: [{ orm: { type: "1.3.6.1.4.1.99999.7", value: b.octetString(Buffer.from([1, 2, 3])) } }],
  }, { cert: s.cert, key: s.key });
  var op = pki.schema.cmc.parse(withOrm);
  check("C3b. the orm arm is emitted with its type and raw value",
    op.requests[0].arm === "orm" && op.requests[0].requestMessageType === "1.3.6.1.4.1.99999.7");

  // C3c: an orm arm is { type, value } -- a request missing either field is refused at build time
  // rather than emitted as a malformed request message a server cannot read (RFC 6402 sec. 2.5).
  check("C3c. an orm request missing its value is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ orm: { type: "1.3.6.1.4.1.99999.7" } }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  check("C3c. an orm request missing its type is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ orm: { value: b.octetString(Buffer.from([1, 2, 3])) } }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // ---- control placement (RFC 6402 sec. 2.6) ----------------------------
  check("E8b. a responseBody control asked for in a PKIData is refused at build time",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "id-cmc-responseBody", value: b.octetString(Buffer.from([1])) }] },
        { cert: s.cert, key: s.key });
    })) === "cmc/control-misplaced");

  // ---- input discipline -------------------------------------------------
  check("B1c. a request naming two arms at once is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer, crm: crmDer }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("B1d. a request naming no arm is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{}] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("B1e. a non-object spec is refused",
    (await acode(function () { return pki.cmc.build(7, { cert: s.cert, key: s.key }); })) === "cmc/bad-input");

  // ---- F11: the round trip ----------------------------------------------
  var full = await pki.cmc.build({
    requests: [{ tcr: csrDer }],
    controls: [
      { type: "id-cmc-transactionId", value: b.integer(99n) },
      { type: "id-cmc-senderNonce", value: b.octetString(Buffer.alloc(16, 5)) },
    ],
  }, { cert: s.cert, key: s.key });
  var fp = pki.schema.cmc.parse(full);
  check("F11. every control that went in comes back out, in order",
    fp.controls.length === 2 && fp.controls[0].attrType === ID_CMC_TRANSACTION_ID &&
    fp.controls[1].attrType === ID_CMC_SENDER_NONCE);

  // ---- the two halves meet ---------------------------------------------
  // The producing and interpreting sides share one transaction: build a request
  // carrying a transactionId + senderNonce, then have verify accept the response
  // that echoes exactly those. This is the only vector that proves the two
  // modules agree about what a transaction IS, rather than each being
  // self-consistent.
  var TXN = 20260811;
  var NONCE = nodeCrypto.randomBytes(16);
  var req = await pki.cmc.build({
    requests: [{ tcr: csrDer }],
    controls: [
      { type: "id-cmc-transactionId", value: b.integer(BigInt(TXN)) },
      { type: "id-cmc-senderNonce", value: b.octetString(NONCE) },
    ],
  }, { cert: s.cert, key: s.key });

  var sentControls = pki.schema.cmc.parse(req).controls;
  var sentTxn = pki.asn1.read.integer(pki.asn1.decode(
    sentControls.filter(function (c) { return c.attrType === ID_CMC_TRANSACTION_ID; })[0].values[0]));
  var sentNonce = pki.asn1.read.octetString(pki.asn1.decode(
    sentControls.filter(function (c) { return c.attrType === ID_CMC_SENDER_NONCE; })[0].values[0]));
  check("F12. the emitted transactionId and senderNonce are the ones the caller asked for",
    sentTxn === BigInt(TXN) && Buffer.compare(sentNonce, NONCE) === 0);

  // The CA's reply, echoing them back the way RFC 5272 sec. 6.6 requires.
  function attr(id, type, values) { return b.sequence([b.integer(BigInt(id)), b.oid(type), b.set(values)]); }
  var respBody = b.sequence([
    b.sequence([
      attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TXN))]),
      attr(2, "1.3.6.1.5.5.7.7.7", [b.octetString(sentNonce)]),          // recipientNonce echo
    ]),
    b.sequence([]), b.sequence([]),
  ]);
  var respDer = await pki.cms.sign(respBody, { cert: s.cert, key: s.key },
    { eContentType: "id-cct-PKIResponse" });
  // Real verification here, not the opt-out: this response is genuinely signed,
  // so the vector proves the whole chain -- build, sign, parse, authenticate,
  // bind, interpret -- rather than only the interpretation half.
  var verdict = await pki.cmc.verify(respDer,
    { transactionId: Number(sentTxn), senderNonce: sentNonce, certs: [s.cert] });
  check("F13. pki.cmc.verify accepts the response to a pki.cmc.build request (the two halves agree)",
    verdict.outcome === "issued" && verdict.signatureVerified === true);

  // ...and rejects the same response against a DIFFERENT transaction, which is
  // what makes the previous check mean something.
  check("F13b. the same response is refused for a different transaction",
    (await acode(function () {
      return pki.cmc.verify(respDer, { transactionId: Number(sentTxn) + 1, senderNonce: sentNonce, certs: [s.cert] });
    })) === "cmc/transaction-mismatch");

  // F15 -- a crm arm's certReqId is caller-determined, so it is RESERVED up front
  // like every other caller-chosen identifier; the reservation then has to be
  // CLAIMED when the arm is encoded. Without the claim the reservation is still
  // outstanding when a cmsSequence element asks for the same number, that element
  // is taken for the reservation's owner, and the builder emits a PKIData carrying
  // the identifier twice -- which its own parser refuses. A collision must be
  // refused at build time, not discovered by the recipient.
  var crmId5 = await pki.crmf.build(
    { certReqId: 5, certTemplate: { subject: "crm.example", publicKey: s.spki } }, { key: s.key });
  var tciId5 = b.sequence([b.integer(5n), b.raw(await pki.cms.sign(Buffer.from("x"), { cert: s.cert, key: s.key }))]);
  check("F15. a cmsSequence element colliding with a crm arm's certReqId is refused at build time",
    // The build-side collision code, the same one every other caller-supplied
    // clash raises -- not the parse-side cmc/duplicate-body-part-id, which is the
    // recipient discovering what the producer should never have emitted.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ crm: crmId5 }], cmsSequence: [tciId5] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // F16 -- the builder must not sign a message its own parser refuses. Every arm
  // splices caller-supplied DER, so the assembled body is read back before
  // signing: whatever the parser rejects is a build-time refusal rather than a
  // request whose recipient cannot decode it.
  var innerCms = await pki.cms.sign(Buffer.from("inner"), { cert: s.cert, key: s.key });

  check("F16. a tcr that is not a CertificationRequest is refused at build time",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: b.octetString(Buffer.from([1, 2, 3])) }] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F16a. an empty SEQUENCE is not a CertificationRequest either",
    // The right TAG is not the same as the right structure: the readback checks
    // the CMC shape around the request, so the request itself has to be parsed.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: b.sequence([]) }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F16d. a crm arm that is not a CertReqMsg is refused, like a tcr that is not a CSR",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ crm: b.sequence([b.integer(1n)]) }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F18b. rewriting the signer's key BYTES after the call does not change who signed",
    // Re-pointing signer.key is one way to change who signs; rewriting the PKCS#8
    // buffer it already points at is the other.
    await (async function () {
      var pooledKey = Buffer.from(s.key);
      var p = pki.cmc.build({ requests: [{ tcr: csrDer }] }, { cert: s.cert, key: pooledKey });
      pooledKey.fill(0x41);
      return (await pki.cms.verify(await p, { certs: [s.cert] })).valid === true;
    })());

  check("F16b. a TaggedContentInfo with the wrong field count is refused",
    (await acode(function () {
      // { bodyPartID, contentInfo, EXTRA } -- a shape the parser does not accept.
      var bad = b.sequence([b.integer(60n), b.raw(innerCms), b.integer(1n)]);
      return pki.cmc.build({ requests: [{ tcr: csrDer }], cmsSequence: [bad] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F16c. an otherMsg missing its value is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        otherMsgSequence: [b.sequence([b.integer(61n), b.oid("1.3.6.1.4.1.99999.1")])] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // F17 -- the message is assembled at the CALL, so a caller reusing a pooled
  // request buffer on the next line cannot have something else signed in its place.
  var pooled = Buffer.from(csrDer);
  var pending = pki.cmc.build({ requests: [{ tcr: pooled }] }, { cert: s.cert, key: s.key });
  pooled.fill(0x41);
  check("F17. a request buffer rewritten right after the call does not change what was signed",
    pki.schema.cmc.parse(await pending).requests.length === 1);

  // F18 -- the signer is fixed at the call too. cms.sign reads the key inside its
  // own promise chain, so swapping it afterwards would sign with the replacement
  // while the original certificate stayed embedded -- a message whose signature
  // does not belong to the certificate beside it.
  var other18 = await signer();
  var liveSigner = { cert: s.cert, key: s.key };
  var signing = pki.cmc.build({ requests: [{ tcr: csrDer }] }, liveSigner);
  liveSigner.key = other18.key;                       // swapped on the next line
  var signedWith = await signing;
  check("F18. a signer mutated after the call does not change who signed",
    (await pki.cms.verify(signedWith, { certs: [s.cert] })).valid === true);

  // ---- F19: the exchange binding is a NAMED spec field, not hand-encoded ----
  // pki.cmc.verify checks a response against transactionId / senderNonce / dataReturn.
  // If the builder does not take those by name, a caller writes the natural thing,
  // the fields are silently dropped, and the request ships with no replay defense --
  // which neither side can then detect, because verify only enforces the halves the
  // client says it sent.
  var bindNonce = Buffer.alloc(16, 0x5a);
  var bound = await pki.cmc.build(
    { requests: [{ tcr: csrDer }], transactionId: 4242, senderNonce: bindNonce, dataReturn: Buffer.from("st8") },
    { cert: s.cert, key: s.key });
  var bp = pki.schema.cmc.parse(bound);
  check("F19. transactionId / senderNonce / dataReturn are emitted as controls",
    bp.controls.length === 3 &&
    bp.controls.some(function (c) { return c.attrType === pki.oid.byName("id-cmc-transactionId"); }) &&
    bp.controls.some(function (c) { return c.attrType === pki.oid.byName("id-cmc-senderNonce"); }) &&
    bp.controls.some(function (c) { return c.attrType === pki.oid.byName("id-cmc-dataReturn"); }));

  check("F19b. an unknown spec field is refused rather than silently dropped",
    // The failure this guards is invisible: the message builds and signs, and simply
    // does not carry what was asked for.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], transactionID: 1 }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // F19c -- the SAME door on every descriptor nested in a spec, not only on the
  // spec itself. Each of these silently changes what gets signed: a misspelled
  // bodyPartID leaves the request auto-allocated a different identifier from the
  // one a control references; a bodyPartID written on a control is never honored
  // at all; and a misspelled `identity` drops the Identification control that
  // tells the server to derive the Identity Proof key from secret AND identity.
  // F19f -- a status control reports a SERVER's verdict on a request, so it has no
  // meaning written into the request itself (RFC 5272 sec. 6.1). The builder refuses
  // to emit one; the decoder still reads them wherever they appear, because the spec
  // states a placement MUST for id-cmc-responseBody alone and refusing the rest on
  // the wire would reject a message the ASN.1 permits.
  check("F19f1. a CMC Status Info control in a REQUEST is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "id-cmc-statusInfo", value: b.sequence([b.integer(0n), b.sequence([b.integer(1n)])]) }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/control-misplaced");

  check("F19f2. and the Extended one likewise",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "id-cmc-statusInfoV2",
          value: b.sequence([b.integer(0n), b.sequence([b.sequence([b.integer(1n)])])]) }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/control-misplaced");

  // F19e -- a hand-encoded binding control must carry the type the toolkit READS.
  // The CMC parser keeps control values raw, so nothing downstream objects; but
  // these three are compared against the response and read back out of the request
  // before it is sent, so the wrong type signs a request this client will refuse to
  // send. Refused at authoring time instead.
  check("F19e1. a hand-encoded transactionId that is not an INTEGER is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "id-cmc-transactionId", value: b.octetString(Buffer.from([1, 2])) }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19e2. nor a senderNonce that is not an OCTET STRING",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "id-cmc-senderNonce", value: b.integer(7n) }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19e3. and a correctly typed hand-encoded binding control still builds",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: csrDer }],
      controls: [{ type: "id-cmc-senderNonce", value: b.octetString(bindNonce) }] },
    { cert: s.cert, key: s.key })).controls.length === 1);

  check("F19c1. an unknown field on a REQUEST is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer, bodyPartId: 7 }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19c2. an unknown field on a CONTROL is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "id-cmc-senderNonce", value: b.octetString(bindNonce), bodyPartID: 9 }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19c3. an unknown field on identityProof is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], identityProof: { secret: "s3cret", identtiy: "alice" } },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19c4. an unknown field on popLink is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], popLink: { secret: "s3cret", random: 8 } },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19d. a key the table lists but nothing reads would defeat the guard, so there is none",
    // `identification` is attached through identityProof.identity. Listing it as a
    // spec field of its own would put it back through the door and leave it out of
    // the message -- accepted and silently absent, which is what this guard exists
    // to stop.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], identification: "device" },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19e. the documented route to an Identification control still works",
    // identityProof.identity emits it, which is why the standalone key is not needed.
    pki.schema.cmc.parse(await pki.cmc.build(
      { requests: [{ tcr: csrDer }], identityProof: { secret: "s3cret", identity: "device" } },
      { cert: s.cert, key: s.key })).controls.length === 2);

  check("F19f. a named binding field and a hand-encoded control of the same type collide",
    // Emitting both would put two of the control in one message, and two values
    // means the response can be bound to neither -- this toolkit's own /fullcmc
    // refuses exactly that shape on arrival.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], transactionId: 1,
        controls: [{ type: "1.3.6.1.5.5.7.7.5", value: b.integer(2n) }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19g. two hand-encoded copies collide the same way",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }],
        controls: [{ type: "1.3.6.1.5.5.7.7.6", value: b.octetString(Buffer.alloc(4, 1)) },
          { type: "1.3.6.1.5.5.7.7.6", value: b.octetString(Buffer.alloc(4, 2)) }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("F19c. a transactionId that is not an integer is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }], transactionId: 1.5 }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // ---- F14: signing with the request's own key (RFC 5272 sec. 3.2) ------
  // The case the key-only signer exists for: enrolling a brand-new key, so there
  // is no certificate to identify the signer by. Sec. 3.2 then requires (a) the
  // certification request to carry a Subject Key Identifier extension, (b) the
  // subjectKeyIdentifier form of SignerIdentifier, and (c) its value to be the
  // one that request declares. (b) is structural; (a) and (c) are agreement
  // between the signer and the requests beside it, and are checked at build time
  // because a mismatch produces a signed request no CA can act on.
  var ski = Buffer.alloc(20, 0xab);
  var csrWithSki = await csrFor(s, { extensionRequest: { subjectKeyIdentifier: ski } });

  var keyOnly = await pki.cmc.build({ requests: [{ tcr: csrWithSki }] },
    { key: s.key, spki: s.spki, keyIdentifier: ski });
  var koParsed = pki.schema.cmc.parse(keyOnly);
  check("F14. a request signed by its own requested key builds, carrying no certificate",
    koParsed.kind === "pkiData" && koParsed.requests.length === 1 &&
    (koParsed.cms.certificates || []).length === 0);

  // The signer's public byte fields (keyIdentifier, spki) accept any BufferSource, not only
  // a Buffer/Uint8Array: an ArrayBuffer names the same identifier and binds the same key.
  // Before the fix the ArrayBuffer keyIdentifier/spki was mangled to an empty object by the
  // signer copy and the binding was refused; the caller-facing behavior must be identical.
  function _toAB(b) { var ab = new ArrayBuffer(b.length); new Uint8Array(ab).set(b); return ab; }
  var keyOnlyAB = await pki.cmc.build({ requests: [{ tcr: csrWithSki }] },
    { key: s.key, spki: _toAB(s.spki), keyIdentifier: _toAB(ski) });
  var koParsedAB = pki.schema.cmc.parse(keyOnlyAB);
  check("F14a. a key-only signer accepts an ArrayBuffer keyIdentifier and spki, binding identically (#68 A15/A16)",
    koParsedAB.kind === "pkiData" && koParsedAB.requests.length === 1 &&
    (koParsedAB.cms.certificates || []).length === 0);

  check("F14b. a key-only signer naming an identifier no request declares is refused (sec. 3.2c)",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrWithSki }] },
        { key: s.key, spki: s.spki, keyIdentifier: Buffer.alloc(20, 0xcd) });
    })) === "cmc/bad-signer");

  check("F14c. a request with no Subject Key Identifier extension cannot carry a key-only signer (sec. 3.2a)",
    // The CSR here declares nothing, so there is no value the SignerInfo could
    // legitimately name -- which is exactly what sec. 3.2a forbids.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrDer }] },
        { key: s.key, spki: s.spki, keyIdentifier: ski });
    })) === "cmc/bad-signer");

  // Sec. 3.2 names BOTH key-bearing arms -- the signing key may belong to a
  // request "included in the TaggedRequest tcr or crm fields" -- so a CRMF
  // enrollment of a brand-new key is the same flow and must build.
  var crmWithSki = await pki.crmf.build(
    { certReqId: 7, certTemplate: { subject: "crm.example", publicKey: s.spki,
      extensions: { subjectKeyIdentifier: ski } } }, { key: s.key });
  check("F14e. the crm arm supports a key-only signer on the same terms as tcr (sec. 3.2)",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ crm: crmWithSki }] },
      { key: s.key, spki: s.spki, keyIdentifier: ski })).kind === "pkiData");

  check("F14f. a crm arm declaring a different identifier is still refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ crm: crmWithSki }] },
        { key: s.key, spki: s.spki, keyIdentifier: Buffer.alloc(20, 0xcd) });
    })) === "cmc/bad-signer");

  // A key-only signer (no certificate, an spki present) must NAME the request's Subject Key
  // Identifier as bytes and CARRY its own spki as bytes: the SignerInfo it produces is resolved by
  // a CA against those exact fields, so a missing or non-byte identifier, or a non-byte spki, is a
  // signed request no CA can act on and is refused at build time (sec. 3.2), not emitted.
  check("F14i. a key-only signer that names no Subject Key Identifier is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrWithSki }] }, { key: s.key, spki: s.spki });
    })) === "cmc/bad-signer");
  check("F14j. a key-only signer whose keyIdentifier is not DER bytes is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrWithSki }] }, { key: s.key, spki: s.spki, keyIdentifier: "ab" });
    })) === "cmc/bad-signer");
  check("F14k. a key-only signer whose spki is not DER bytes is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrWithSki }] }, { key: s.key, spki: "notbytes", keyIdentifier: ski });
    })) === "cmc/bad-signer");

  // F14h -- the identifier says WHICH request; the KEY is what makes the claim
  // true. A Subject Key Identifier is caller-chosen, so a signer holding one key
  // can name the identifier of a request asking to certify a different one. The
  // CA would then resolve the SID to the requested key and be unable to verify
  // the carrier at all, so the signature must be by the key the request names.
  var other = await signer();
  var csrOtherKeySameSki = await pki.csr.sign(
    { subject: "other.example", subjectPublicKey: other.spki, extensionRequest: { subjectKeyIdentifier: ski } },
    { key: other.key });
  check("F14h. a key-only signer whose key is not the one that request asks to certify is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrOtherKeySameSki }] },
        { key: s.key, spki: s.spki, keyIdentifier: ski });   // identifier agrees, key does not
    })) === "cmc/bad-signer");

  check("F14i. the same request signed by the key it actually names builds",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: csrOtherKeySameSki }] },
      { key: other.key, spki: other.spki, keyIdentifier: ski })).kind === "pkiData");

  check("F14j. a renewal may not be signed key-only (sec. 6.3.3)",
    // A renewal carries no Identity Proof; what stands in for it is the signature
    // by the certificate being renewed, which associates the original identity
    // with the request. A key-only signer has no certificate, so a renewal signed
    // that way leaves the CA nothing to authenticate the renewal against.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrWithSki }], renewal: true },
        { key: s.key, spki: s.spki, keyIdentifier: ski });
    })) === "cmc/bad-signer");

  check("F14k. the same renewal signed by a certificate builds",
    pki.schema.cmc.parse(await pki.cmc.build(
      { requests: [{ tcr: csrWithSki }], renewal: true }, { cert: s.cert, key: s.key })).kind === "pkiData");

  check("F14g. a key-only signer may not sign alongside others (sec. 3.2: one SignerInfo)",
    // A request key has no certificate and so no independent identity; signing
    // beside another signer would leave the CA a signer set it cannot reason
    // about. Checked across the WHOLE array, not just its first element.
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: csrWithSki }] },
        [{ cert: s.cert, key: s.key }, { key: s.key, spki: s.spki, keyIdentifier: ski }]);
    })) === "cmc/bad-signer");

  check("F14d. a signer WITH a certificate is untouched by the rule",
    // Sec. 3.2's three rules apply only when the signature is made with a
    // request's key; a certified signer identifies itself by its certificate.
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: csrDer }] },
      { cert: s.cert, key: s.key })).kind === "pkiData");

  // Dense caller-array hardening: a sparse requests array is a typed cmc/bad-input, caught before the
  // forEach/map reach the hole as a native concat error.
  var _spReq = [{ tcr: csrDer }]; _spReq[2] = _spReq[0];
  var _cmcCode = function (spec) { return pki.cmc.build(spec, { cert: s.cert, key: s.key }).then(function () { return "NO-THROW"; }, function (e) { return e && e.code; }); };
  check("sparse cmc requests -> typed cmc/bad-input (not a native concat error)",
    (await _cmcCode({ requests: _spReq })) === "cmc/bad-input");
  var _spCms = [1]; _spCms[2] = 1;
  check("sparse cmc cmsSequence -> typed cmc/bad-input", (await _cmcCode({ requests: [{ tcr: csrDer }], cmsSequence: _spCms })) === "cmc/bad-input");
  var _spOther = [1]; _spOther[2] = 1;
  check("sparse cmc otherMsgSequence -> typed cmc/bad-input", (await _cmcCode({ requests: [{ tcr: csrDer }], otherMsgSequence: _spOther })) === "cmc/bad-input");

  // Proof-of-possession: an embedded tcr (PKCS#10) request is verified before it is signed into the CMC
  // message. A CSR whose self-signature does not verify under its own subject key is one the CA will
  // reject (RFC 5272 sec. 4.1 / RFC 6402), so the producer refuses it rather than signing it.
  check("PoP1. a tcr with a valid proof-of-possession builds",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: await csrFor(s) }] }, { cert: s.cert, key: s.key })).kind === "pkiData");
  var badPopCsr = corruptCsrPop(await csrFor(s));
  check("PoP2. a tcr whose proof-of-possession does not verify is refused (cmc/bad-popo)",
    (await _cmcCode({ requests: [{ tcr: badPopCsr }] })) === "cmc/bad-popo");
  check("PoP3. a valid tcr alongside a bad-PoP tcr still fails the whole build (no partial acceptance)",
    (await _cmcCode({ requests: [{ tcr: await csrFor(s) }, { tcr: badPopCsr }] })) === "cmc/bad-popo");

  // A Full PKI Request is carried in a SignedData or an AuthenticatedData (RFC 5272 sec. 3.2). The
  // second is what a client enrolling under a shared secret uses: the MAC authenticates the request in
  // place of a signature, so no key or certificate is needed to send one.
  var MAC_IDENTITY = "cmc-client-17";
  var MAC_SECRET = "a-shared-secret-at-least-16-chars";
  var macProt = { mac: { identifier: MAC_IDENTITY, secret: MAC_SECRET } };
  var macCsr = await csrFor(s);
  var macDer = await pki.cmc.build({ requests: [{ tcr: macCsr }] }, macProt);
  var macCms = pki.schema.cms.parse(macDer);
  check("AD1. a shared-secret request is carried in an AuthenticatedData encapsulating a PKIData",
    macCms.contentTypeName === "authData" &&
    (macCms.encapContentInfo.eContentTypeName || macCms.encapContentInfo.eContentType) === ID_CCT_PKI_DATA);
  // RFC 5272 sec. 3.2(a): the Password Recipient Info option MUST be used.
  check("AD2. its recipient is a PasswordRecipientInfo",
    macCms.recipientInfos.length === 1 && macCms.recipientInfos[0].type === "pwri");
  // RFC 5652 sec. 9.1: a non-data encapsulated type carries authenticated attributes.
  check("AD3. it carries authenticated attributes naming the encapsulated type",
    Array.isArray(macCms.authAttrs) && macCms.authAttrs.length >= 2);
  // A PasswordRecipientInfo names no recipient, so the request itself has to say whose secret it is or
  // an authority holding many cannot select one (RFC 5272 sec. 6.2.3).
  var macControls = pki.schema.cmc.parse(macDer).controls;
  var macIdent = macControls.filter(function (c) { return c.attrType === ID_CMC_IDENTIFICATION; });
  check("AD4b. the request names the client whose secret authenticates it",
    macIdent.length === 1 && pki.asn1.read.string(pki.asn1.decode(macIdent[0].values[0])) === MAC_IDENTITY);
  // The same name may also arrive through identityProof; two different names for one client is refused
  // rather than picked between, and the matching pair emits one control, not two.
  var bothDer = await pki.cmc.build({ requests: [{ tcr: macCsr }],
    identityProof: { secret: MAC_SECRET, identity: MAC_IDENTITY } }, macProt);
  check("AD4c. the same name given twice still emits one Identification control",
    pki.schema.cmc.parse(bothDer).controls.filter(function (c) { return c.attrType === ID_CMC_IDENTIFICATION; }).length === 1);
  check("AD4d. two different names for one client is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }],
        identityProof: { secret: MAC_SECRET, identity: "a-different-name" } }, macProt);
    })) === "cmc/bad-input");
  // The name can also be written straight into spec.controls, which is the third place one request can
  // name its client from. All three are held to the same name.
  var identControl = function (name) { return { type: "id-cmc-identification", value: b.utf8(name) }; };
  check("AD4e. an Identification control the caller wrote naming a different client is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }], controls: [identControl("bob")] }, macProt);
    })) === "cmc/bad-input");
  var sameDer = await pki.cmc.build({ requests: [{ tcr: macCsr }], controls: [identControl(MAC_IDENTITY)] }, macProt);
  check("AD4f. one the caller wrote naming the same client is kept, and not duplicated",
    pki.schema.cmc.parse(sameDer).controls.filter(function (c) { return c.attrType === ID_CMC_IDENTIFICATION; }).length === 1);
  check("AD4g. one whose value does not read as the client's name is refused rather than assumed to agree",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }],
        controls: [{ type: "id-cmc-identification", value: b.integer(7n) }] }, macProt);
    })) === "cmc/bad-input");
  // Every supplied name is compared, not just the last one seen.
  check("AD4h. a second control naming a different client is refused whichever order they arrive in",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }],
        controls: [identControl("bob"), identControl(MAC_IDENTITY)] }, macProt);
    })) === "cmc/bad-input");
  // The control is a UTF8String, so the same characters in another string type is a different value on
  // the wire and cannot stand in for the one the request needs.
  check("AD4i. a PrintableString carrying the same characters is not accepted as the name",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }],
        controls: [{ type: "id-cmc-identification", value: b.printable(MAC_IDENTITY) }] }, macProt);
    })) === "cmc/bad-input");
  // And one request names its client once, however the pieces were assembled.
  check("AD4j. naming the client through both a control and identityProof is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }], controls: [identControl(MAC_IDENTITY)],
        identityProof: { secret: MAC_SECRET, identity: MAC_IDENTITY } }, macProt);
    })) === "cmc/bad-input");
  // A control is a caller object, so its value is read once: what the name is checked against has to be
  // what the request carries. A value that answers differently on a second read cannot slip a different
  // name into the message than the one the check saw.
  var twoFaced = { type: "id-cmc-identification" };
  var reads = 0;
  Object.defineProperty(twoFaced, "value", {
    enumerable: true,
    get: function () { reads += 1; return reads === 1 ? b.utf8("bob") : b.utf8(MAC_IDENTITY); },
  });
  check("AD4k. a control whose value answers differently on a second read cannot pass the name check",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }], controls: [twoFaced] }, macProt);
    })) === "cmc/bad-input");
  check("AD4. the message reads back as the same PKIData a signed carrier would carry",
    pki.schema.cmc.parse(macDer).kind === "pkiData" &&
    pki.schema.cmc.parse(macDer).requests.length === 1);
  // RFC 5272 sec. 3.2(c): the derivation input is the identifier and the shared secret together, so
  // changing either one alone must fail to authenticate.
  // The authority authenticates the request through the CMS layer, keyed by what sec. 3.2(c) derives.
  // Pinning it byte-for-byte is what proves the derivation is the identifier AND the secret: an
  // implementation that concatenated them itself reaches the same key.
  var derived = Buffer.concat([Buffer.from(MAC_IDENTITY, "utf8"), Buffer.from(MAC_SECRET, "utf8")]);
  check("AD5. the authority authenticates it under the identifier and secret concatenated",
    (await pki.cms.decrypt(macDer, { password: derived })).authenticated === true);
  check("AD6. a different identifier with the same secret does not authenticate",
    (await acode(function () {
      return pki.cms.decrypt(macDer, { password: Buffer.concat([Buffer.from("someone-else", "utf8"), Buffer.from(MAC_SECRET, "utf8")]) });
    })) !== "NO-THROW");
  check("AD7. a different secret with the same identifier does not authenticate",
    (await acode(function () {
      return pki.cms.decrypt(macDer, { password: Buffer.concat([Buffer.from(MAC_IDENTITY, "utf8"), Buffer.from("another-shared-secret-16", "utf8")]) });
    })) !== "NO-THROW");
  // The secret alone is NOT the key, which is the half of sec. 3.2(c) an implementation forgets.
  check("AD8. the secret alone does not authenticate it",
    (await acode(function () { return pki.cms.decrypt(macDer, { password: Buffer.from(MAC_SECRET, "utf8") }); })) !== "NO-THROW");
  check("AD9. a tampered encapsulated byte does not authenticate",
    (await acode(function () {
      var t = Buffer.from(macDer);
      t[t.length - 1] ^= 0x01;
      return pki.cms.decrypt(t, { password: derived });
    })) !== "NO-THROW");
  // One carrier per request, and the shared secret is refused unless it can key a derivation.
  check("AD10. naming both a signature and a shared secret is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }] },
        { cert: s.cert, key: s.key, mac: { identifier: MAC_IDENTITY, secret: MAC_SECRET } });
    })) === "cmc/bad-input");
  // The secret may arrive as bytes rather than a string, which is what a caller holding it in a
  // buffer passes; it derives the same key as the string spelling of the same bytes.
  var macBytesDer = await pki.cmc.build({ requests: [{ tcr: macCsr }] },
    { mac: { identifier: MAC_IDENTITY, secret: Buffer.from(MAC_SECRET, "utf8") } });
  check("AD12. a secret given as bytes derives the same key as the same bytes given as a string",
    (await pki.cms.decrypt(macBytesDer, { password: derived })).authenticated === true);
  // A renewal's identity is the certificate it is signed with, which is why it carries no Identification
  // or Identity Proof control (RFC 5272 sec. 3.2(a)). A shared secret names no certificate, so it cannot
  // stand in for one: the combination is refused rather than producing a renewal asserting nothing.
  check("AD13. a renewal cannot be carried by a shared secret",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }], renewal: true }, macProt);
    })) === "cmc/bad-signer");
  check("AD13b. the same renewal signed with the certificate being renewed still builds",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: macCsr }], renewal: true },
      { cert: s.cert, key: s.key })).kind === "pkiData");
  // Every copy the toolkit takes of a byte-valued shared secret is cleared, observed in a child
  // process because the wipe cannot be watched from inside this one. The verify case is the one that
  // matters most: the options snapshot owns its copy from before the response is parsed, so the copy
  // exists even on an exit that never reaches the MAC.
  var macBuildObs = observeWipe({ op: "cmc-build-mac", key: s.key, csr: macCsr, secret: Buffer.from(MAC_SECRET, "utf8") });
  check("AD14. the wipe observation ran for the shared-secret build (child exit " + macBuildObs.status + ")",
    macBuildObs.report !== null);
  check("AD14b. every copy the shared-secret build takes is cleared",
    !!macBuildObs.report && macBuildObs.report.wiped.length > 0 &&
      macBuildObs.report.wiped.some(function (e) { return e.hadContent; }) &&
      macBuildObs.report.wiped.every(function (e) { return e.allZeroAfter; }));
  var macVerifyObs = observeWipe({ op: "cmc-verify-mac", key: s.key, csr: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]),
    secret: Buffer.from(MAC_SECRET, "utf8") });
  check("AD15. the wipe observation ran for a verification that never reaches the MAC (child exit " + macVerifyObs.status + ")",
    macVerifyObs.report !== null);
  check("AD15b. the secret copy is cleared even when the response never parses",
    !!macVerifyObs.report && macVerifyObs.report.wiped.length > 0 &&
      macVerifyObs.report.wiped.some(function (e) { return e.hadContent; }) &&
      macVerifyObs.report.wiped.every(function (e) { return e.allZeroAfter; }));
  // The narrowest window of all: the snapshot takes the secret copy and the next step of the same
  // synchronous prologue throws, before any promise exists to attach cleanup to.
  var macDetachedObs = observeWipe({ op: "cmc-verify-mac-detached", key: s.key, csr: macCsr,
    secret: Buffer.from(MAC_SECRET, "utf8") });
  check("AD16. the wipe observation ran for a prologue failure (child exit " + macDetachedObs.status + ")",
    macDetachedObs.report !== null);
  check("AD16b. the secret copy is cleared when the prologue fails after taking it",
    !!macDetachedObs.report && macDetachedObs.report.wiped.length > 0 &&
      macDetachedObs.report.wiped.some(function (e) { return e.hadContent; }) &&
      macDetachedObs.report.wiped.every(function (e) { return e.allZeroAfter; }));
  // Furthest out: the LAST option the snapshot reads throws, several steps after the secret copy was
  // taken. Everything from the copy to the return is protected, so this clears it too.
  var macLateObs = observeWipe({ op: "cmc-verify-mac-late-throw", key: s.key,
    csr: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]), secret: Buffer.from(MAC_SECRET, "utf8") });
  check("AD17. the wipe observation ran for a throw in the last option read (child exit " + macLateObs.status + ")",
    macLateObs.report !== null);
  check("AD17b. the secret copy is cleared when a later option read throws",
    !!macLateObs.report && macLateObs.report.wiped.length > 0 &&
      macLateObs.report.wiped.some(function (e) { return e.hadContent; }) &&
      macLateObs.report.wiped.every(function (e) { return e.allZeroAfter; }));
  // Carrying an Identification control changes how an Identity Proof witness is derived: the hash is
  // over the secret and the identity together rather than the secret alone (RFC 5272 sec. 6.2.3). A
  // shared-secret request always carries that control, so the witness has to be derived that way even
  // when the caller named no identity on identityProof itself.
  var proofDer = await pki.cmc.build({ requests: [{ tcr: macCsr }], identityProof: { secret: MAC_SECRET } }, macProt);
  var namedProofDer = await pki.cmc.build({ requests: [{ tcr: macCsr }],
    identityProof: { secret: MAC_SECRET, identity: MAC_IDENTITY } },
  { cert: s.cert, key: s.key });
  var witnessOf = function (der) {
    return pki.schema.cmc.parse(der).controls
      .filter(function (c) { return c.attrType === ID_CMC_IDENTITY_PROOF_V2; })[0].values[0].toString("hex");
  };
  check("AD18. the witness is derived with the name the request carries, not with none",
    witnessOf(proofDer) === witnessOf(namedProofDer));
  // One client, one secret: the carrier's MAC and the Identity Proof are keyed from the same credential.
  check("AD19. a request cannot carry one secret for its MAC and another for its Identity Proof",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: macCsr }],
        identityProof: { identity: MAC_IDENTITY, secret: "a-different-secret-16-chars" } }, macProt);
    })) === "cmc/bad-input");
  check("AD19b. the same secret on both sides builds, whether the carrier's was given as bytes or a string",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: macCsr }],
      identityProof: { identity: MAC_IDENTITY, secret: MAC_SECRET } },
    { mac: { identifier: MAC_IDENTITY, secret: Buffer.from(MAC_SECRET, "utf8") } })).kind === "pkiData");
  // A comparison that refuses still copied. When one of the two secrets turns out unusable, the copy of
  // the other one is cleared rather than left behind by the early exit.
  var macCmpObs = observeWipe({ op: "cmc-build-mac-compare-reject", key: s.key, csr: macCsr,
    secret: Buffer.from(MAC_SECRET, "utf8") });
  check("AD20. the wipe observation ran for a refused secret comparison (child exit " + macCmpObs.status + ")",
    macCmpObs.report !== null);
  var secretB64 = Buffer.from(MAC_SECRET, "utf8").toString("base64");
  // Counted, not matched: the argument boundary clears its own copy of the same bytes, so only the
  // NUMBER of cleared copies distinguishes a comparison that cleaned up from one that did not.
  var secretWipes = !macCmpObs.report ? 0 : macCmpObs.report.wiped.filter(function (e) {
    return e.before === secretB64 && e.allZeroAfter;
  }).length;
  check("AD20b. the comparison clears the copy it made of the secret even when it refuses",
    secretWipes >= 2);
  var BAD_MACS = [
    ["a non-object", "just-a-string"],
    ["an array", ["identifier", "secret"]],
    ["a buffer", Buffer.from("both")],
    ["no identifier", { secret: MAC_SECRET }],
    ["an empty identifier", { identifier: "", secret: MAC_SECRET }],
    ["a non-string identifier", { identifier: 42, secret: MAC_SECRET }],
    ["no secret", { identifier: MAC_IDENTITY }],
    ["an empty secret", { identifier: MAC_IDENTITY, secret: "" }],
    ["an unknown field", { identifier: MAC_IDENTITY, secret: MAC_SECRET, bogus: 1 }],
  ];
  for (var bm = 0; bm < BAD_MACS.length; bm++) {
    check("AD11. a shared secret with " + BAD_MACS[bm][0] + " is refused",
      (await acode((function (m) {
        return function () { return pki.cmc.build({ requests: [{ tcr: macCsr }] }, { mac: m }); };
      }(BAD_MACS[bm][1])))) === "cmc/bad-input");
  }

  // ===== the challenge-response proof of possession (RFC 5272 sec. 6.7) =====
  // A server that cannot check a signature proof, because the key being certified cannot sign, sends
  // the proof value encrypted to that key and asks the client to MAC the request with it. The client
  // half is: decrypt, check the witness, answer. The witness check is not optional, so the answer is
  // only ever produced by the path that performs it.
  var ID_CMC_DECRYPTED_POP = "1.3.6.1.5.5.7.7.10";
  var HMAC_SHA256_OID = "1.2.840.113549.2.9";
  var SHA256_OID = "2.16.840.1.101.3.4.2.1";
  var ENVELOPED_DATA_OID = "1.2.840.113549.1.7.3";
  var NO_SIGNATURE_OID = pki.oid.byName("id-alg-noSignature");
  // The challenge is encrypted TO the key being certified, so these fixtures use a key that can
  // receive one. That is the case the control exists for: a key that cannot sign for itself.
  var signingHelper = require("../helpers/signing");
  var popKey = signingHelper.makeSigner("ec-p256", { cn: "pop-client.example" });
  var otherKey = signingHelper.makeSigner("ec-p256", { cn: "pop-other.example" });
  // A certificate carrying a subject key identifier, so the challenge can be addressed the way sec. 6.7
  // says it should be. The CLIENT never uses this certificate: it decrypts with the key alone, which is
  // the situation the control exists for.
  popKey.skiCert = await pki.x509.sign({ subject: "pop-client.example", subjectPublicKey: popKey.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { subjectKeyIdentifier: true } }, { key: popKey.key });
  var popCsr = await csrFor(s);
  var popTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), popCsr]));

  // The server's half, built here so the client's answer can be checked against an independent
  // computation rather than against the same code path.
  async function popChallengeFor(proofValue, opts) {
    opts = opts || {};
    var witnessAlg = opts.witnessAlg || "sha256";
    var witness = nodeCrypto.createHash(witnessAlg).update(proofValue).digest();
    // Addressed by subject key identifier, which is what sec. 6.7 says a challenge SHOULD use, because
    // the key being certified has no certificate for an issuer-and-serial to name.
    var envelope = await pki.cms.encrypt(proofValue,
      [{ cert: popKey.skiCert, keyIdentifier: "subjectKeyIdentifier" }],
      { contentEncryptionAlgorithm: "aes-256-cbc" });
    return b.sequence([
      opts.tagged || popTagged,
      envelope,
      b.sequence([b.oid(opts.popAlg || HMAC_SHA256_OID)]),
      b.sequence([b.oid(opts.witnessOid || SHA256_OID)]),
      b.octetString(opts.witness || witness),
    ]);
  }
  function expectedPop(proofValue, data) {
    var key = proofValue.length > 64 ? proofValue.subarray(0, 64) : proofValue;
    return nodeCrypto.createHmac("sha256", key).update(data).digest();
  }
  function decryptedPopOf(der) {
    return pki.schema.cmc.parse(der).controls
      .filter(function (c) { return c.attrType === ID_CMC_DECRYPTED_POP; })[0].decryptedPOP;
  }

  var proof = Buffer.alloc(48, 0x21);
  var challenge = await popChallengeFor(proof);
  var answered = await pki.cmc.build({ requests: [{ tcr: popCsr }],
    popChallenge: { challenge: challenge, recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  var dp = decryptedPopOf(answered);
  check("EP1. answering a challenge carries a Decrypted POP control",
    !!dp && dp.thePOP.length === 32);
  // The proof is a MAC over the request the challenge carried, keyed by the decrypted proof value,
  // checked against a value computed with node:crypto rather than by the same code.
  check("EP2. the proof is the MAC of the carried request under the decrypted proof value",
    dp.thePOP.equals(expectedPop(proof, popTagged)));
  check("EP3. the algorithm is copied from the challenge, not chosen by the client",
    dp.thePOPAlgID.oid === HMAC_SHA256_OID);
  check("EP4. the body part names the request in the NEW request",
    typeof dp.bodyPartID === "number" && dp.bodyPartID > 0);
  // The clause an implementation misses: a proof value longer than 64 bytes is truncated to 64 for
  // the key, so two values sharing their first 64 bytes answer the same challenge identically.
  var long65 = Buffer.concat([Buffer.alloc(64, 0x33), Buffer.from([0x99])]);
  var long64 = long65.subarray(0, 64);
  var longAnswer = await pki.cmc.build({ requests: [{ tcr: popCsr }],
    popChallenge: { challenge: await popChallengeFor(long65), recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  check("EP5. a proof value over 64 bytes is truncated to 64 for the MAC key",
    decryptedPopOf(longAnswer).thePOP.equals(nodeCrypto.createHmac("sha256", long64).update(popTagged).digest()));
  // The witness check is the client's abort condition, so a challenge whose witness does not match the
  // decrypted value is refused rather than answered.
  check("EP6. a challenge whose witness does not match the proof value is refused",
    (await acode(function () {
      return popChallengeFor(proof, { witness: Buffer.alloc(32, 0x77) }).then(function (bad) {
        return pki.cmc.build({ requests: [{ tcr: popCsr }],
          popChallenge: { challenge: bad, recipient: { key: popKey.key } } },
        { cert: s.cert, key: s.key });
      });
    })) === "cmc/pop-failed");
  check("EP7. a challenge that does not decrypt under the caller's key is refused the same way",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }],
        popChallenge: { challenge: challenge, recipient: { key: otherKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/pop-failed");
  // RFC 5274 sec. 4.2 makes SHA-1 and HMAC-SHA1 the MUST-implement pair, so both are answered.
  var sha1Challenge = await popChallengeFor(proof, { witnessAlg: "sha1", witnessOid: "1.3.14.3.2.26",
    popAlg: "1.2.840.113549.2.7" });
  var sha1Answer = await pki.cmc.build({ requests: [{ tcr: popCsr }],
    popChallenge: { challenge: sha1Challenge, recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  check("EP8. the algorithms RFC 5274 requires of a conforming client are answered",
    decryptedPopOf(sha1Answer).thePOP.equals(nodeCrypto.createHmac("sha1", proof).update(popTagged).digest()));
  check("EP9. an algorithm outside the required set is refused rather than silently defaulted",
    (await acode(function () {
      return popChallengeFor(proof, { popAlg: "1.2.840.113549.2.5" }).then(function (md5) {
        return pki.cmc.build({ requests: [{ tcr: popCsr }],
          popChallenge: { challenge: md5, recipient: { key: popKey.key } } },
        { cert: s.cert, key: s.key });
      });
    })) === "cmc/bad-pop-challenge");

  // The door refuses what it cannot read as a challenge, rather than reaching the decrypt with it.
  var BAD_CHALLENGES = [
    ["a non-object popChallenge", "not-an-object"],
    ["an array", [1, 2]],
    ["a buffer", Buffer.from("challenge")],
    ["an unknown field", { challenge: challenge, recipient: { key: popKey.key, cert: popKey.cert }, bogus: 1 }],
  ];
  for (var bc = 0; bc < BAD_CHALLENGES.length; bc++) {
    check("EP12. " + BAD_CHALLENGES[bc][0] + " is refused",
      (await acode((function (v) {
        return function () {
          return pki.cmc.build({ requests: [{ tcr: popCsr }], popChallenge: v }, { cert: s.cert, key: s.key });
        };
      }(BAD_CHALLENGES[bc][1])))) === "cmc/bad-input");
  }
  // The proof covers the request the challenge carried. Sending it alongside a DIFFERENT request would
  // name one request while proving possession for another, so the two are compared.
  // The request the challenge quotes can be a CRMF message rather than a PKCS#10 one, and the answer
  // binds to it the same way. The crm arm is [1] IMPLICIT, so the context tag replaces the SEQUENCE tag
  // and the content is the CertReqMsg's own elements.
  var popCrmMessages = await pki.crmf.build({ certReqId: 11n,
    certTemplate: { subject: [{ commonName: "pop-crm.example" }], publicKey: popKey.spki },
    pop: { type: "raVerified", raVerified: true } });
  var popCrmMsgNode = pki.asn1.decode(popCrmMessages).children[0];
  var popCrmTagged = b.contextConstructed(1, Buffer.concat(popCrmMsgNode.children.map(function (c) {
    return c.bytes;
  })));
  var crmAnswered = await pki.cmc.build({ requests: [{ crm: popCrmMessages }],
    popChallenge: { challenge: await popChallengeFor(proof, { tagged: popCrmTagged }),
      recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  check("EP15. a challenge quoting a CRMF request is answered for the CRMF request carried",
    decryptedPopOf(crmAnswered).thePOP.equals(expectedPop(proof, popCrmTagged)));
  check("EP16. a challenge quoting a different request than the CRMF one carried is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ crm: popCrmMessages }],
        popChallenge: { challenge: challenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // The enrollment this control exists for: a key that can only decrypt cannot sign the request that
  // asks for its certificate, so the request carries id-alg-noSignature and the challenge carries the
  // proof (RFC 5272 App. C.1).
  function noSignatureCsr(csrDer, params) {
    var criBytes = pki.asn1.decode(csrDer).children[0].bytes;
    var alg = params === undefined
      ? b.sequence([b.oid(NO_SIGNATURE_OID), b.nullValue()])
      : b.sequence([b.oid(NO_SIGNATURE_OID)].concat(params));
    return b.sequence([b.raw(criBytes), alg,
      b.bitString(b.octetString(nodeCrypto.createHash("sha256").update(criBytes).digest()), 0)]);
  }
  // The request asks for the key the challenge is encrypted to, which is what makes opening it a proof
  // of possession of that key. A request for any other key is not proven by opening this challenge.
  var popKeyCsr = await csrFor(popKey, { subject: "pop-client.example" });
  var nsCsr = noSignatureCsr(popKeyCsr);
  var nsTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), nsCsr]));
  var nsAnswered = await pki.cmc.build({ requests: [{ tcr: nsCsr }],
    popChallenge: { challenge: await popChallengeFor(proof, { tagged: nsTagged }),
      recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  check("EP19. a request that carries no signature is accepted when the challenge proves the key",
    decryptedPopOf(nsAnswered).thePOP.equals(expectedPop(proof, nsTagged)));
  check("EP20. the same request without an answered challenge is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: nsCsr }] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");
  check("EP21. a challenge proving a different request does not license an unsigned one",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: nsCsr }],
        popChallenge: { challenge: challenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  // A challenge a password opens is answerable, since the proof value still comes back and the witness
  // still decides. It just does not identify any key, so it cannot stand in for a missing signature.
  var pwChallengeFor = async function (tagged) {
    return b.sequence([tagged,
      await pki.cms.encrypt(proof, [{ password: "a-challenge-password" }],
        { contentEncryptionAlgorithm: "aes-256-cbc" }),
      b.sequence([b.oid(HMAC_SHA256_OID)]), b.sequence([b.oid(SHA256_OID)]),
      b.octetString(nodeCrypto.createHash("sha256").update(proof).digest())]);
  };
  var pwSigned = await pki.cmc.build({ requests: [{ tcr: popCsr }],
    popChallenge: { challenge: await pwChallengeFor(popTagged),
      recipient: { password: "a-challenge-password" } } },
  { cert: s.cert, key: s.key });
  check("EP19c. a challenge a password opens is answered for a request that signs for itself",
    decryptedPopOf(pwSigned).thePOP.equals(expectedPop(proof, popTagged)));
  var pwNsTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), nsCsr]));
  var pwNsChallenge = await pwChallengeFor(pwNsTagged);
  check("EP19d. a password-opened challenge does not stand in for a missing signature",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: nsCsr }],
        popChallenge: { challenge: pwNsChallenge, recipient: { password: "a-challenge-password" } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");

  // What proved possession is the decryption that happened, not the key material that came along with
  // it: a password opens this challenge, so a private key passed beside it did not answer anything.
  check("EP19e. a key passed alongside the password that opened it does not become the proof",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: nsCsr }],
        popChallenge: { challenge: pwNsChallenge,
          recipient: { password: "a-challenge-password", key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");

  // The request names a key, not an encoding of one. A curve point written in compressed form is the
  // same key as the uncompressed form the private key derives, and it enrolls the same way.
  var compressedSpki = (function () {
    var jwk = nodeCrypto.createPublicKey({ key: popKey.spki, format: "der", type: "spki" })
      .export({ format: "jwk" });
    var x = Buffer.from(jwk.x, "base64url"), y = Buffer.from(jwk.y, "base64url");
    var point = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 0x03 : 0x02]), x]);
    var algBytes = pki.asn1.decode(popKey.spki).children[0].bytes;
    return b.sequence([b.raw(algBytes), b.bitString(point, 0)]);
  })();
  var compressedCsr = noSignatureCsr(await csrFor(popKey,
    { subject: "pop-client.example", subjectPublicKey: compressedSpki }));
  var compressedTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), compressedCsr]));
  var compressedAnswered = await pki.cmc.build({ requests: [{ tcr: compressedCsr }],
    popChallenge: { challenge: await popChallengeFor(proof, { tagged: compressedTagged }),
      recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  check("EP19g. a compressed curve point in the request is the same key the challenge opened with",
    decryptedPopOf(compressedAnswered).thePOP.equals(expectedPop(proof, compressedTagged)));

  // The other-message arm binds the same way, on the type together with the value: a value alone
  // could belong to a different request type.
  var ormType = "1.3.6.1.5.5.7.7.9";
  var ormValue = b.octetString(Buffer.from("an out-of-band request"));
  var ormTagged = b.contextConstructed(2, Buffer.concat([b.integer(11n), b.oid(ormType), ormValue]));
  var ormChallenge = await popChallengeFor(proof, { tagged: ormTagged });
  var ormAnswered = await pki.cmc.build({ requests: [{ orm: { type: ormType,
    value: ormValue }, bodyPartID: 11 }],
  popChallenge: { challenge: ormChallenge, recipient: { key: popKey.key } } },
  { cert: s.cert, key: s.key });
  check("EP19h. a challenge quoting an other-message request is answered for it",
    decryptedPopOf(ormAnswered).thePOP.equals(expectedPop(proof, ormTagged)));
  check("EP19i. an other-message request of a different type is not the request the challenge quoted",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ orm: { type: "1.3.6.1.5.5.7.7.10",
        value: ormValue }, bodyPartID: 11 }],
      popChallenge: { challenge: ormChallenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  check("EP19f. a challenge with no recipient key material is an input error, not a POP failure",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }], popChallenge: { challenge: challenge } },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  var unrelatedNsCsr = noSignatureCsr(popCsr);
  var unrelatedNsTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), unrelatedNsCsr]));
  var unrelatedChallenge = await popChallengeFor(proof, { tagged: unrelatedNsTagged });
  check("EP19b. a challenge opened by a key other than the one being certified is not a proof of it",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: unrelatedNsCsr }],
        popChallenge: { challenge: unrelatedChallenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");
  // App. C.1 defines the value as "NoSignatureValue ::= OCTET STRING", so a signature field carrying
  // something else is a request an authority would reject.
  function noSignatureCsrWithValue(csrDer, valueDer) {
    var criBytes = pki.asn1.decode(csrDer).children[0].bytes;
    return b.sequence([b.raw(criBytes),
      b.sequence([b.oid(NO_SIGNATURE_OID), b.nullValue()]), b.bitString(valueDer, 0)]);
  }
  var rawValueCsr = noSignatureCsrWithValue(popKeyCsr,
    nodeCrypto.createHash("sha256").update(pki.asn1.decode(popKeyCsr).children[0].bytes).digest());
  var rawValueTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), rawValueCsr]));
  var rawValueChallenge = await popChallengeFor(proof, { tagged: rawValueTagged });
  check("EP19j. a no-signature value that is not an OCTET STRING is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: rawValueCsr }],
        popChallenge: { challenge: rawValueChallenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");

  var bareNsCsr = noSignatureCsr(popKeyCsr, []);
  var bareNsTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), bareNsCsr]));
  var popChallengePromise = await popChallengeFor(proof, { tagged: bareNsTagged });
  var corruptedPopCsr = corruptCsrPop(popCsr);
  check("EP22. id-alg-noSignature without its NULL parameters is refused, challenge or not",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: bareNsCsr }],
        popChallenge: { challenge: popChallengePromise, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");
  // Answering a challenge licenses only the request that carries no signature at all. One that does
  // is still held to it.
  var badPopTagged = b.contextConstructed(0, Buffer.concat([b.integer(11n), corruptedPopCsr]));
  var badPopChallenge = await popChallengeFor(proof, { tagged: badPopTagged });
  check("EP23. a signed request is still held to its own signature when a challenge is answered",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: corruptedPopCsr }],
        popChallenge: { challenge: badPopChallenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-popo");

  // A control the builder computes is not also accepted hand-encoded: the message would carry two
  // proofs of the same thing, and the authority has no rule for choosing between them.
  var handDecryptedPop = { type: "id-cmc-decryptedPOP",
    value: b.sequence([b.integer(11n), b.sequence([b.oid(HMAC_SHA256_OID)]),
      b.octetString(Buffer.alloc(32, 7))]) };
  check("EP24. a hand-encoded Decrypted POP alongside popChallenge is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }], controls: [handDecryptedPop],
        popChallenge: { challenge: challenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  var handIdentityProof = { type: "id-cmc-identityProofV2",
    value: b.sequence([b.sequence([b.oid(SHA256_OID)]), b.sequence([b.oid(HMAC_SHA256_OID)]),
      b.octetString(Buffer.alloc(32, 7))]) };
  check("EP25. a hand-encoded Identity Proof alongside spec.identityProof is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }], controls: [handIdentityProof],
        identityProof: { secret: "a-shared-secret", identity: "id-1" } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  // A spec field the builder reads as absent computes nothing, so a hand-encoded control beside it is
  // the message's only one. The refusal follows what the builder emits, not what the field is set to.
  check("EP25c. a hand-encoded control is carried when the field that would compute one is off",
    !!(await pki.cmc.build({ requests: [{ tcr: popCsr }], controls: [handIdentityProof],
      identityProof: false }, { cert: s.cert, key: s.key })).length);
  // A shared-secret carrier computes the message authentication and the Identification name, not the
  // Identity Proof, so a hand-encoded one beside it is the message's only proof and is carried.
  check("EP25b. a hand-encoded Identity Proof is carried under a shared-secret carrier",
    !!(await pki.cmc.build({ requests: [{ tcr: popCsr }], controls: [handIdentityProof] },
      { mac: { secret: "a-shared-secret", identifier: "id-1" } })).length);
  check("EP26. a hand-encoded POP Link Witness alongside popLink is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }], popLink: { secret: "a-shared-secret" },
        controls: [{ type: "id-cmc-popLinkWitnessV2",
          value: b.sequence([b.sequence([b.oid(SHA256_OID)]), b.sequence([b.oid(HMAC_SHA256_OID)]),
            b.octetString(Buffer.alloc(32, 7))]) }] },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  check("EP27b. two hand-encoded Decrypted POP controls naming one request are refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }],
        controls: [handDecryptedPop, handDecryptedPop] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  // Sec. 6.7 gives each Decrypted POP the body part it answers for, so one per request is not a
  // duplicate. Only two naming the SAME request leave the authority two proofs of one thing.
  var handDecryptedPop2 = { type: "id-cmc-decryptedPOP",
    value: b.sequence([b.integer(12n), b.sequence([b.oid(HMAC_SHA256_OID)]),
      b.octetString(Buffer.alloc(32, 8))]) };
  // A value that names no readable request cannot be told apart from another that names none either,
  // so a second one is refused rather than passed through as a distinct proof.
  var unreadableDecryptedPop = { type: "id-cmc-decryptedPOP", value: b.octetString(Buffer.alloc(4)) };
  check("EP27d. two Decrypted POP controls naming no readable request are refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }],
        controls: [unreadableDecryptedPop, unreadableDecryptedPop] }, { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  check("EP27e. one such control is left to the assembled message to refuse",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }], controls: [unreadableDecryptedPop] },
        { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  // Several signers carry no shared secret between them, so there is no mac to conflict with.
  check("EP27f. a hand-encoded control is carried when the signer is a list rather than a mac carrier",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: popCsr }],
      controls: [handDecryptedPop] }, [{ cert: s.cert, key: s.key }, { cert: s.cert, key: s.key }]))
      .controls.filter(function (c) { return c.attrType === ID_CMC_DECRYPTED_POP; }).length === 1);
  check("EP27c. two Decrypted POP controls naming different requests are carried",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: popCsr }],
      controls: [handDecryptedPop, handDecryptedPop2] }, { cert: s.cert, key: s.key })).controls
      .filter(function (c) { return c.attrType === ID_CMC_DECRYPTED_POP; }).length === 2);
  check("EP27. the same hand-encoded control is still carried when the builder computes none",
    pki.schema.cmc.parse(await pki.cmc.build({ requests: [{ tcr: popCsr }], controls: [handDecryptedPop] },
      { cert: s.cert, key: s.key })).controls
      .filter(function (c) { return c.attrType === ID_CMC_DECRYPTED_POP; }).length === 1);

  // The number of recipients to try is counted off the envelope's own structure, so a content that
  // names none is refused rather than read as an envelope with nothing to open.
  async function popCodeWithEnvelope(envelope) {
    return acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }],
        popChallenge: { challenge: b.sequence([popTagged, envelope,
          b.sequence([b.oid(HMAC_SHA256_OID)]), b.sequence([b.oid(SHA256_OID)]),
          b.octetString(nodeCrypto.createHash("sha256").update(proof).digest())]),
        recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    });
  }
  check("EP17. a challenge whose ContentInfo carries no content is refused",
    (await popCodeWithEnvelope(b.sequence([b.oid(ENVELOPED_DATA_OID)]))) === "cmc/bad-pop-challenge");
  check("EP18. a challenge whose envelope holds no recipient set is refused",
    (await popCodeWithEnvelope(b.sequence([b.oid(ENVELOPED_DATA_OID),
      b.explicit(0, b.sequence([b.integer(0n)]))]))) === "cmc/bad-pop-challenge");

  var otherCsr = await csrFor(s, { subject: "a-different-subject.example" });
  check("EP14. a challenge for one request cannot answer for a different one",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: otherCsr }],
        popChallenge: { challenge: challenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");
  // One answer covers one request, so a request carrying two is refused rather than answered for the
  // one this side happens to pick.
  check("EP13. a request carrying more than one certification request is refused",
    (await acode(function () {
      return pki.cmc.build({ requests: [{ tcr: popCsr }, { tcr: macCsr }],
        popChallenge: { challenge: challenge, recipient: { key: popKey.key } } },
      { cert: s.cert, key: s.key });
    })) === "cmc/bad-input");

  // The decrypted proof value and the MAC key derived from it are the toolkit's own copies, so both
  // are cleared once the answer is built. Counted, because the argument boundary clears copies of the
  // same bytes and only the number distinguishes the toolkit's own cleanup from that one.
  var popWipeObs = observeWipe({ op: "cmc-pop-challenge", key: popKey.key, cert: popKey.cert,
    csr: popCsr, secret: challenge, identity: popKey.key });
  check("EP10. the wipe observation ran for an answered challenge (child exit " + popWipeObs.status + ")",
    popWipeObs.report !== null);
  var proofB64 = proof.toString("base64");
  var proofWipes = !popWipeObs.report ? 0 : popWipeObs.report.wiped.filter(function (e) {
    return e.before === proofB64 && e.allZeroAfter;
  }).length;
  check("EP11. the decrypted proof value and the key derived from it are both cleared",
    proofWipes >= 2);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
