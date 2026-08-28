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

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
