// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.webauthn.verifyMetadataBlob / metadataFor / metadataAnchors -- the
// FIDO Metadata Service v3 reader. Every vector drives the shipped verb on a BLOB minted here and
// really signed, so the signature and certificate-chain gates are exercised rather than mocked.
//
// The ordering property is the one worth stating: the signature and its chain are established
// BEFORE the payload is read at all, so a BLOB that does not verify never reaches the JSON reader,
// the entry walk, or any per-entry certificate decode.

var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;

var T = new Date("2026-06-01T00:00:00Z");
async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

// The BLOB fixture builder is a shared helper: the doc-example harness verifies the same minted
// BLOB, so the documented example and these vectors cannot drift apart.
var mint = require("../helpers/mds-blob").mint;

async function run() {
  async function codeFor(mintOpts, over) {
    var f = await mint(mintOpts || {});
    var opts = Object.assign({ rootCertificates: [f.rootDer], time: T }, over || {});
    if (over && over._otherRoot) { opts.rootCertificates = [f.otherDer]; delete opts._otherRoot; }
    try { return await pki.webauthn.verifyMetadataBlob(f.blob, opts); } catch (e) { return e.code || e.constructor.name; }
  }

  // ---- accept ----
  var base = await mint({});
  var md = await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [base.rootDer], time: T });
  check("mds: a signed BLOB anchored to the supplied root verifies", md.no === 42 && md.entries.length === 1 && md.stale === false);
  check("mds: the legalHeader is surfaced, never compared", typeof md.legalHeader === "string");
  check("mds: an entry is found by its aaguid", !!pki.webauthn.metadataFor(md, base.aaguid));
  check("mds: the lookup is case-insensitive on the aaguid", !!pki.webauthn.metadataFor(md, base.aaguid.toUpperCase()));
  // The all-zero aaguid means "no model identity" and must never resolve to an entry.
  check("mds: the all-zero aaguid never matches", pki.webauthn.metadataFor(md, "00000000-0000-0000-0000-000000000000") === null);
  check("mds: an unknown aaguid returns null", pki.webauthn.metadataFor(md, "ffffffff-ffff-ffff-ffff-ffffffffffff") === null);
  check("mds: an entry's attestation roots decode on demand",
    pki.webauthn.metadataAnchors(pki.webauthn.metadataFor(md, base.aaguid)).length === 1);

  // ---- the caller supplies the anchor; nothing is bundled ----
  check("mds: no root is a config-time fault", (await codeFor({}, { rootCertificates: undefined })) === "webauthn/metadata-no-root");
  check("mds: an empty root list is a config-time fault", (await codeFor({}, { rootCertificates: [] })) === "webauthn/metadata-no-root");
  check("mds: an unknown opts key is a config-time fault", (await codeFor({}, { nope: 1 })) === "webauthn/bad-input");
  check("mds: requireRollbackCheck without previousNo is a config-time fault",
    (await codeFor({}, { requireRollbackCheck: true })) === "webauthn/metadata-no-baseline");
  check("mds: a negative previousNo is a config-time fault", (await codeFor({}, { previousNo: -1 })) === "webauthn/bad-input");

  // ---- the envelope, established BEFORE the payload is read ----
  check("mds: a signature that does not verify is refused", (await codeFor({ badSig: true })) === "webauthn/verify-failed");
  check("mds: a signature by a key other than the x5c leaf is refused", (await codeFor({ signWithRoot: true })) === "webauthn/verify-failed");
  check("mds: an unsupported alg is refused", (await codeFor({ alg: "HS256" })) === "webauthn/unsupported-algorithm");
  // Taking the scheme from the token and the key from the chain without checking they agree is the
  // JWS algorithm-confusion class: an RSA alg over an EC leaf must not proceed.
  check("mds: an alg whose family disagrees with the leaf key is refused",
    (await codeFor({ alg: "RS256" })) === "webauthn/unsupported-algorithm");
  // x5u names a chain to FETCH; this verifier performs no retrieval, so it cannot anchor such a BLOB.
  check("mds: an x5u header is refused rather than ignored",
    (await codeFor({ headerExtra: { x5u: "https://example.test/chain" } })) === "webauthn/bad-metadata-blob");
  check("mds: a header with no x5c is refused", (await codeFor({ x5cRaw: [] })) === "webauthn/bad-metadata-blob");
  check("mds: a chain that does not reach the supplied root is refused",
    (await codeFor({}, { _otherRoot: true })) === "webauthn/metadata-untrusted");

  // ---- the payload, read only once the envelope holds ----
  check("mds: a payload with no legalHeader is refused", (await codeFor({ payloadOmit: ["legalHeader"] })) === "webauthn/bad-metadata-blob");
  check("mds: a non-integer no is refused", (await codeFor({ no: "42" })) === "webauthn/bad-metadata-blob");
  check("mds: a malformed nextUpdate is refused", (await codeFor({ nextUpdate: "2027-13-01" })) === "webauthn/bad-metadata-blob");
  // nextUpdate is a full-date; a date-time is a different production and is not accepted for it.
  check("mds: a date-time nextUpdate is refused", (await codeFor({ nextUpdate: "2027-06-01T00:00:00Z" })) === "webauthn/bad-metadata-blob");
  check("mds: a non-array entries is refused", (await codeFor({ payloadExtra: { entries: {} } })) === "webauthn/bad-metadata-blob");
  check("mds: an entry with no statusReports is refused",
    (await codeFor({ entries: [{ aaguid: "01020304-0506-0708-090a-0b0c0d0e0f10" }] })) === "webauthn/bad-metadata-blob");
  check("mds: an entry with a malformed aaguid is refused",
    (await codeFor({ entries: [{ aaguid: "not-a-guid", statusReports: [{ status: "FIDO_CERTIFIED" }] }] })) === "webauthn/bad-metadata-blob");
  // Two entries claiming one authenticator give the lookup a choice the specification does not
  // define, so it is refused rather than resolved by position.
  var dup = { aaguid: "01020304-0506-0708-090a-0b0c0d0e0f10", statusReports: [{ status: "FIDO_CERTIFIED" }] };
  check("mds: two entries claiming one aaguid are refused",
    (await codeFor({ entries: [dup, dup] })) === "webauthn/duplicate-metadata-entry");

  // ---- rollback + freshness ----
  // A BLOB older than the one already held would reinstate authenticators whose trust was withdrawn.
  check("mds: a no that does not exceed previousNo is refused as a rollback",
    (await codeFor({ no: 10 }, { previousNo: 10 })) === "webauthn/metadata-rollback");
  check("mds: a newer no is accepted", (await codeFor({ no: 11 }, { previousNo: 10 })).no === 11);
  check("mds: a BLOB past its nextUpdate is refused", (await codeFor({ nextUpdate: "2026-01-01" })) === "webauthn/metadata-stale");
  var staleOk = await codeFor({ nextUpdate: "2026-01-01" }, { allowStale: true });
  check("mds: allowStale accepts it and still reports it stale", staleOk.no === 42 && staleOk.stale === true);

  // ---- the status gate ----
  // Any disqualifying report denies, wherever it sits: the array is not stated to be chronological,
  // effectiveDate is optional, and in the live metadata some entries are not in date order.
  var revoked = await mint({ statusReports: [{ status: "REVOKED", effectiveDate: "2026-02-01" }, { status: "FIDO_CERTIFIED", effectiveDate: "2026-03-01" }] });
  var mdRevoked = await pki.webauthn.verifyMetadataBlob(revoked.blob, { rootCertificates: [revoked.rootDer], time: T });
  var revokedEntry = pki.webauthn.metadataFor(mdRevoked, revoked.aaguid);
  check("mds: a BLOB listing a revoked authenticator still verifies (the BLOB is valid)", mdRevoked.no === 42);
  check("mds: a REVOKED report denies trust even when a later report is clean",
    require("../../lib/webauthn-mds.js").statusDenied(revokedEntry, mdRevoked) === true);
  // The status gate is on the ROUTE, not only inside the attestation verifier. An operator who
  // anchors an attestation themselves goes metadataFor -> metadataAnchors -> pki.path.validate, and
  // nothing along that route consulted the status reports: a REVOKED model's registered roots were
  // handed back and the path validated against them. A model the catalogue has disqualified
  // registers no anchors to trust.
  check("mds: a revoked entry hands back no anchors to chain to", (function () {
    try { pki.webauthn.metadataAnchors(revokedEntry); return false; }
    catch (e) { return e.code === "webauthn/metadata-status"; }
  })());
  check("mds: ...and says so through the verified result too", (function () {
    try { pki.webauthn.metadataAnchors(revokedEntry, { metadata: mdRevoked, time: T }); return false; }
    catch (e) { return e.code === "webauthn/metadata-status"; }
  })());
  // The caller's own reading governs when it is supplied, exactly as it does inside the verifier --
  // the two must not answer differently about the same entry.
  var byDateEarly = await pki.webauthn.verifyMetadataBlob(revoked.blob,
    { rootCertificates: [revoked.rootDer], time: T, statusPolicy: "latest-by-date" });
  check("mds: a caller's own status policy governs the anchors it is handed",
    pki.webauthn.metadataAnchors(pki.webauthn.metadataFor(byDateEarly, revoked.aaguid),
      { metadata: byDateEarly, time: T }).length === 1);
  // A report dated after the instant being judged has not taken effect yet, so anchors judged
  // before that date are still handed over -- and refused from the date the report names.
  var scheduled = await mint({ statusReports: [{ status: "REVOKED", effectiveDate: "2026-09-01" }] });
  var mdScheduled = await pki.webauthn.verifyMetadataBlob(scheduled.blob, { rootCertificates: [scheduled.rootDer], time: T });
  var scheduledEntry = pki.webauthn.metadataFor(mdScheduled, scheduled.aaguid);
  check("mds: a revocation dated in the future does not yet withhold the anchors",
    pki.webauthn.metadataAnchors(scheduledEntry, { metadata: mdScheduled, time: T }).length === 1);
  check("mds: ...and does withhold them from the date it names", (function () {
    try { pki.webauthn.metadataAnchors(scheduledEntry, { metadata: mdScheduled, time: new Date("2026-10-01T00:00:00Z") }); return false; }
    catch (e) { return e.code === "webauthn/metadata-status"; }
  })());
  // The rollback rule leaves a trace, as the freshness rule beside it does. It runs only when a
  // caller supplies the sequence number it holds, so a result that does not say whether it ran
  // cannot be told apart from one where it was skipped -- and showing the catalogue never went
  // backwards is the entire point of the rule.
  // A BLOB is retrieved over the network, and the ordinary way to hold a fetched body is an
  // ArrayBuffer -- the one byte form this refused, in the verb most likely to be handed one.
  function toAb(buf) { var u = new Uint8Array(buf.length); u.set(buf); return u.buffer; }
  check("mds: a BLOB arrives as an ArrayBuffer, the form a fetched body takes",
    (await pki.webauthn.verifyMetadataBlob(toAb(base.blob), { rootCertificates: [base.rootDer], time: T })).no === 42);
  check("mds: ...and as a DataView",
    (await pki.webauthn.verifyMetadataBlob(new DataView(toAb(base.blob)), { rootCertificates: [base.rootDer], time: T })).no === 42);
  // A trust anchor is bytes too, and identical DER is the identical certificate whichever container
  // the caller received it in. An accepted set that depends on how the file was read is not a
  // statement about the certificate.
  check("mds: a root certificate arrives in any byte form",
    (await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [toAb(base.rootDer)], time: T })).no === 42 &&
    (await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [new DataView(toAb(base.rootDer))], time: T })).no === 42);
  check("mds: the size ceiling still bites on a byte form that is not a Buffer",
    (await codeOf(function () {
      return pki.webauthn.verifyMetadataBlob(new Uint8Array(pki.C.LIMITS.MDS_BLOB_MAX_BYTES + 1).buffer,
        { rootCertificates: [base.rootDer], time: T });
    })) === "webauthn/too-large");

  check("mds: a result says the rollback rule was not requested", md.rollbackChecked === false && md.previousNo === null);
  var rolled = await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [base.rootDer], time: T, previousNo: 41 });
  check("mds: ...and says it ran, against the baseline it was given",
    rolled.rollbackChecked === true && rolled.previousNo === 41 && rolled.no === 42);
  check("mds: a baseline of zero is a baseline, not an absent one",
    (await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [base.rootDer], time: T, previousNo: 0 })).rollbackChecked === true);
  check("mds: a BLOB that does not advance past the baseline is refused",
    (await codeFor({}, { previousNo: 42 })) === "webauthn/metadata-rollback");

  // Verified provenance says the supplied catalogue is real; it does not say the ENTRY came out of
  // it. A process holding two catalogues could otherwise pair an entry from one with the other, and
  // the second's statusPolicy and freshness would decide about the first's status reports -- a
  // by-date reading handing back anchors the entry's own catalogue records as revoked.
  var otherCat = await mint({ statusReports: [{ status: "FIDO_CERTIFIED_L1", effectiveDate: "2026-01-01" }] });
  var mdOther = await pki.webauthn.verifyMetadataBlob(otherCat.blob,
    { rootCertificates: [otherCat.rootDer], time: T, statusPolicy: "latest-by-date" });
  check("mds: an entry may only be judged against the catalogue it came out of", (function () {
    try { pki.webauthn.metadataAnchors(revokedEntry, { metadata: mdOther, time: T }); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: ...and its own catalogue still judges it",
    pki.webauthn.metadataAnchors(pki.webauthn.metadataFor(mdOther, otherCat.aaguid),
      { metadata: mdOther, time: T }).length === 1);

  check("mds: an unknown metadataAnchors option is a config-time fault", (function () {
    try { pki.webauthn.metadataAnchors(revokedEntry, { metdata: mdRevoked }); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: a metadataAnchors time that is not a valid instant is a config-time fault", (function () {
    try { pki.webauthn.metadataAnchors(scheduledEntry, { time: new Date("nope") }); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());

  // ... and the by-date reading, which a caller must ask for, takes only the newest.
  var byDate = await pki.webauthn.verifyMetadataBlob(revoked.blob,
    { rootCertificates: [revoked.rootDer], time: T, statusPolicy: "latest-by-date" });
  check("mds: the latest-by-date policy takes only the newest report",
    require("../../lib/webauthn-mds.js").statusDenied(pki.webauthn.metadataFor(byDate, revoked.aaguid), byDate) === false);
  // An unrecognised status is IGNORED for the gate -- the specification requires a verifier not to
  // fail on one -- unless the caller opts into refusing it.
  var unknown = await mint({ statusReports: [{ status: "SOME_FUTURE_STATUS" }] });
  var mdUnknown = await pki.webauthn.verifyMetadataBlob(unknown.blob, { rootCertificates: [unknown.rootDer], time: T });
  check("mds: an unrecognised status does not deny trust by default",
    require("../../lib/webauthn-mds.js").statusDenied(pki.webauthn.metadataFor(mdUnknown, unknown.aaguid), mdUnknown) === false);
  var mdStrict = await pki.webauthn.verifyMetadataBlob(unknown.blob,
    { rootCertificates: [unknown.rootDer], time: T, rejectUnknownStatus: true });
  check("mds: rejectUnknownStatus opts into refusing an unrecognised status",
    require("../../lib/webauthn-mds.js").statusDenied(pki.webauthn.metadataFor(mdStrict, unknown.aaguid), mdStrict) === true);

  // ---- anchors decode per entry, not for the whole BLOB ----
  // Some real attestation roots do not parse under a strict decoder; decoding everything up front
  // would let one vendor's malformed certificate refuse the entire BLOB for every authenticator.
  var badAnchor = await mint({ anchors: ["bm90LWEtY2VydA=="] });
  var mdBad = await pki.webauthn.verifyMetadataBlob(badAnchor.blob, { rootCertificates: [badAnchor.rootDer], time: T });
  check("mds: a BLOB carrying an undecodable attestation root still verifies", mdBad.entries.length === 1);
  check("mds: the fault surfaces only when that entry's anchors are asked for", (function () {
    try { pki.webauthn.metadataAnchors(pki.webauthn.metadataFor(mdBad, badAnchor.aaguid)); return false; }
    catch (e) { return e.code === "webauthn/bad-metadata-entry"; }
  })());
  var noAnchor = await mint({ anchors: [] });
  var mdNone = await pki.webauthn.verifyMetadataBlob(noAnchor.blob, { rootCertificates: [noAnchor.rootDer], time: T });
  check("mds: an entry registering no attestation root yields no anchors",
    pki.webauthn.metadataAnchors(pki.webauthn.metadataFor(mdNone, noAnchor.aaguid)).length === 0);

  // ---- the verify hook ----
  check("mds: opts.metadata must be a verified result, not raw bytes", (await codeOf(function () {
    return pki.webauthn.verify(attObjNone(), Buffer.alloc(32), { metadata: base.blob });
  })) === "webauthn/bad-input");
  // An attestation with no trust path cannot be anchored, so a caller who asked for metadata
  // enforcement is told it could not be applied rather than handed a pass that looks like one.
  check("mds: a none attestation with metadata requested is refused as not applicable",
    (await codeOf(function () { return pki.webauthn.verify(attObjNone(), noneHash(), { metadata: md }); })) === "webauthn/metadata-not-applicable");

  // ---- the entry boundary: every argument shape a caller can get wrong ----
  // Each of these is a config-time reject. The reason they are worth pinning individually is that
  // the failure mode of a MISSING one is silent: an option that is not validated is an option that
  // quietly does nothing, and a caller who asked for a stricter check never learns it was ignored.
  var mds = require("../../lib/webauthn-mds.js");
  check("mds: no opts at all is refused for want of a root",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob); })) === "webauthn/metadata-no-root");
  check("mds: a non-object opts is refused",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob, "roots"); })) === "webauthn/bad-input");
  check("mds: an array opts is refused (an array is not an options object)",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob, []); })) === "webauthn/bad-input");
  check("mds: an unknown opts key is refused rather than ignored",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [base.rootDer], allowStail: true }); })) === "webauthn/bad-input");
  check("mds: a root that is not a decodable certificate is refused",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [Buffer.from("nope")], time: T }); })) === "webauthn/bad-input");
  // An already-parsed certificate is accepted as a root: a caller who already holds one should not
  // have to re-serialize it, and re-parsing would be a second decode of bytes already trusted.
  var parsedRoot = pki.schema.x509.parse(base.rootDer);
  check("mds: an already-parsed certificate is accepted as a root",
    (await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [parsedRoot], time: T })).no === 42);

  // The BLOB itself, in the shapes an operator hands over.
  check("mds: the BLOB may be supplied as a string",
    (await pki.webauthn.verifyMetadataBlob(base.blob.toString("utf8"), { rootCertificates: [base.rootDer], time: T })).no === 42);
  check("mds: a BLOB above the byte ceiling is refused before it is decoded",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(Buffer.alloc(pki.C.LIMITS.MDS_BLOB_MAX_BYTES + 1, 0x41), { rootCertificates: [base.rootDer], time: T }); })) === "webauthn/too-large");
  check("mds: a BLOB that is not a three-part JWS is refused",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob("only.two", { rootCertificates: [base.rootDer], time: T }); })) === "webauthn/bad-metadata-blob");
  check("mds: an undecodable header segment is refused",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob("!!!.eyJhIjoxfQ.AAAA", { rootCertificates: [base.rootDer], time: T }); })) === "webauthn/bad-metadata-blob");
  check("mds: a header that is valid JSON but not an object is refused",
    (await codeFor({ headerRaw: "[1,2,3]" })) === "webauthn/bad-metadata-blob");
  check("mds: a non-string alg is refused as unsupported",
    (await codeFor({ alg: 256 })) === "webauthn/unsupported-algorithm");
  check("mds: an x5c above the certificate ceiling is refused before any parse",
    (await codeFor({ x5cRaw: new Array(pki.C.LIMITS.WEBAUTHN_X5C_MAX_CERTS + 1).fill(base.rootDer.toString("base64")) })) === "webauthn/too-large");
  check("mds: an x5c entry that is not a string is refused",
    (await codeFor({ x5cRaw: [42] })) === "webauthn/bad-metadata-blob");
  check("mds: an x5c entry that is not canonical base64 is refused",
    (await codeFor({ x5cRaw: ["not!base64"] })) === "webauthn/bad-metadata-blob");
  check("mds: an x5c entry that is not a decodable certificate is refused",
    (await codeFor({ x5cRaw: ["bm90LWEtY2VydA=="] })) === "webauthn/bad-att-cert");

  // Algorithm confusion: the alg names a signature scheme, the leaf carries a key. Taking the
  // scheme from the token and the key from the chain without checking they agree is the JWS
  // algorithm-confusion class, so a mismatch is refused rather than attempted.
  check("mds: an RSA alg over an EC leaf key is refused as a family mismatch",
    (await codeFor({ alg: "RS256" })) === "webauthn/unsupported-algorithm");

  // The payload, reached only behind a verified signature -- which is why each of these needs a
  // re-signed BLOB rather than a hand-edited one.
  check("mds: a payload that is valid JSON but not an object is refused",
    (await codeFor({ payloadRaw: "[]" })) === "webauthn/bad-metadata-blob");
  check("mds: an undecodable payload segment is refused",
    (await codeFor({ payloadRaw64: "!!!" })) === "webauthn/bad-metadata-blob");
  check("mds: an entry that is not an object is refused",
    (await codeFor({ entries: [42] })) === "webauthn/bad-metadata-blob");
  // No vector for the "no usable instant" guard in _parsePayload: it is unreachable by
  // construction, because both operands are gated by throwing guards ahead of it (opts.time by
  // guard.time.assertValid, nextUpdate by rfc3339.parseDate, which refuses a date that does not
  // exist). Reaching it would mean weakening one of those, which is the opposite of the point.
  check("mds: an invalid opts.time is refused at the entry, before any comparison",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [base.rootDer], time: new Date("nope") }); })) === "webauthn/bad-input");
  check("mds: a nextUpdate naming a date that does not exist is refused, not rolled over",
    (await codeFor({ nextUpdate: "2027-02-30" })) === "webauthn/bad-metadata-blob");
  check("mds: more entries than the ceiling is refused",
    (await codeFor({ entries: new Array(pki.C.LIMITS.MDS_MAX_ENTRIES + 1).fill({ aaguid: "01020304-0506-0708-090a-0b0c0d0e0f10", statusReports: [{ status: "FIDO_CERTIFIED" }] }) })) === "webauthn/too-large");

  // ---- the lookup and anchor verbs, on the shapes a caller can pass ----
  check("mds: metadataFor refuses anything that is not a verified result", (function () {
    try { pki.webauthn.metadataFor({ entries: [] }, base.aaguid); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: metadataFor on a non-string aaguid is a miss, not a throw",
    pki.webauthn.metadataFor(md, Buffer.alloc(16)) === null);
  check("mds: metadataFor on an aaguid the BLOB does not list is a miss",
    pki.webauthn.metadataFor(md, "ffffffff-ffff-ffff-ffff-ffffffffffff") === null);
  check("mds: metadataAnchors refuses anything that is not an entry", (function () {
    try { pki.webauthn.metadataAnchors(null); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: an entry with no metadataStatement yields no anchors",
    pki.webauthn.metadataAnchors({ index: 0, metadataStatement: null }).length === 0);
  check("mds: an attestationRootCertificates that is not an array yields no anchors",
    pki.webauthn.metadataAnchors({ index: 0, metadataStatement: { attestationRootCertificates: "nope" } }).length === 0);
  check("mds: more attestation roots than the ceiling is refused", (function () {
    var many = new Array(pki.C.LIMITS.MDS_MAX_ANCHORS_PER_ENTRY + 1).fill(base.rootDer.toString("base64"));
    try { pki.webauthn.metadataAnchors({ index: 0, metadataStatement: { attestationRootCertificates: many } }); return false; }
    catch (e) { return e.code === "webauthn/too-large"; }
  })());
  check("mds: an attestation root that is not canonical base64 is refused", (function () {
    try { pki.webauthn.metadataAnchors({ index: 0, metadataStatement: { attestationRootCertificates: ["not!base64"] } }); return false; }
    catch (e) { return e.code === "webauthn/bad-metadata-entry"; }
  })());

  // ---- the status gate, across every policy shape ----
  check("mds: a revoked status denies trust under the default policy", mds.statusDenied(revokedEntry, mdRevoked) === true);
  check("mds: statusDenied with no metadata falls back to the default policy", mds.statusDenied(revokedEntry, null) === true);
  check("mds: an entry carrying no statusReports at all denies nothing", mds.statusDenied({ index: 0 }, md) === false);
  check("mds: a report whose status is not a string is ignored, not a throw",
    mds.statusDenied({ index: 0, statusReports: [{ status: 7 }, null] }, md) === false);
  // A caller's own predicate decides, and only a literal true denies -- a truthy return from a
  // predicate that meant to return a reason must not read as a denial.
  check("mds: a function policy decides",
    mds.statusDenied(revokedEntry, { statusPolicy: function (r) { return r.length > 0; } }) === true);
  check("mds: a function policy returning a truthy non-true does not deny",
    mds.statusDenied(revokedEntry, { statusPolicy: function () { return "yes"; } }) === false);
  // A caller's predicate receives the entry's reports AS GIVEN. Filtering them first would defeat
  // the entry-wide policies a predicate exists for -- "deny whenever any attestation key is
  // compromised" would be evaluated against an array with exactly those reports removed.
  var mineCert = (await require("../helpers/mds-blob").mintU2fAttestation()).attCertDer;
  var theirCert = (await require("../helpers/mds-blob").mintU2fAttestation()).attCertDer;
  var scopedReports = [{ status: "ATTESTATION_KEY_COMPROMISE", certificate: theirCert.toString("base64") }];
  var sawRaw = null;
  mds.statusDenied({ index: 0, statusReports: scopedReports },
    { statusPolicy: function (r) { sawRaw = r; return false; } }, pki.schema.x509.parse(mineCert));
  check("mds: a function policy sees the reports as given, not a scope-filtered copy",
    sawRaw !== null && sawRaw.length === 1 && sawRaw[0].status === "ATTESTATION_KEY_COMPROMISE");
  // latest-by-date: the array is not stated to be chronological, and in the live metadata several
  // entries are not in date order -- one of them flipping its verdict between "last element" and
  // "newest by date", in the direction that matters.
  var remediated = { index: 0, statusReports: [
    { status: "REVOKED", effectiveDate: "2026-01-01" },
    { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-03-01" },
  ] };
  check("mds: the default policy denies on any disqualifying report, wherever it sits",
    mds.statusDenied(remediated, { statusPolicy: "any" }) === true);
  check("mds: latest-by-date lets a later remediation clear an earlier revocation",
    mds.statusDenied(remediated, { statusPolicy: "latest-by-date" }) === false);
  // Reversed in the array, the verdict must not change: the DATE decides, not the position.
  check("mds: latest-by-date is decided by date, not array position",
    mds.statusDenied({ index: 0, statusReports: remediated.statusReports.slice().reverse() }, { statusPolicy: "latest-by-date" }) === false);
  check("mds: latest-by-date with no usable date falls back to every report",
    mds.statusDenied({ index: 0, statusReports: [{ status: "REVOKED" }] }, { statusPolicy: "latest-by-date" }) === true);
  // effectiveDate is optional, so a report without a usable one cannot be shown to be OLDER than
  // anything -- and dropping it would let an entry clear a REVOKED simply by adding a dated clean
  // report. Where the ordering cannot be established, the report still counts.
  check("mds: a report whose date is malformed is still considered under latest-by-date",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "REVOKED", effectiveDate: "2026-02-30" },
      { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-01-01" },
    ] }, { statusPolicy: "latest-by-date" }) === true);
  check("mds: an undated report is still considered under latest-by-date",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "REVOKED" },
      { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-05-01" },
    ] }, { statusPolicy: "latest-by-date" }) === true);
  // The remediation case still works, because there both reports carry usable dates.
  check("mds: a dated remediation still clears a dated revocation under latest-by-date",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "REVOKED", effectiveDate: "2026-01-01" },
      { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-03-01" },
    ] }, { statusPolicy: "latest-by-date" }) === false);

  // ---- the authenticator with no AAGUID (U2F), keyed by attestation-certificate key identifier ----
  // A U2F authenticator's AAGUID is all zeroes, so an AAGUID-only lookup finds nothing and every
  // such registration would be refused as unlisted -- on an authenticator the catalogue does
  // describe. The catalogue keys these by attestationCertificateKeyIdentifiers instead.
  var attLeaf = pki.schema.x509.parse(base.attRootDer);
  var leafKeyId = mds.certKeyIdentifier(attLeaf);
  check("mds: a key identifier is RFC 5280 method 1 -- 40 hex over the subjectPublicKey BIT STRING contents",
    /^[0-9a-f]{40}$/.test(leafKeyId) &&
    leafKeyId === crypto.createHash("sha1").update(attLeaf.subjectPublicKeyInfo.publicKey.bytes).digest("hex"));
  // The oracle for method 1 is a real certificate's OWN subjectKeyIdentifier extension: the
  // computation must reproduce it. That is what proves the digest is taken over the BIT STRING
  // contents and not over the whole SubjectPublicKeyInfo -- a value that is also 40 hex digits, so
  // a shape check alone would pass while matching nothing in the catalogue.
  var oracleCert = pki.schema.x509.parse(pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE"));
  var skiExt = (oracleCert.extensions || []).filter(function (e) { return e.name === "subjectKeyIdentifier"; })[0];
  var skiRaw = Buffer.from(skiExt.value.data || skiExt.value);
  check("mds: the computed key identifier reproduces a real certificate's own subjectKeyIdentifier",
    skiRaw.subarray(2).toString("hex") === mds.certKeyIdentifier(oracleCert));
  check("mds: and it is NOT the digest of the whole SubjectPublicKeyInfo",
    mds.certKeyIdentifier(oracleCert) !== crypto.createHash("sha1").update(oracleCert.subjectPublicKeyInfo.bytes).digest("hex"));
  check("mds: certKeyIdentifier refuses anything that is not a parsed certificate", (function () {
    try { mds.certKeyIdentifier(base.attRootDer); return false; } catch (e) { return e.code === "webauthn/bad-input"; }
  })());

  var u2fLike = await mint({ aaguid: null, keyIdentifiers: [leafKeyId.toUpperCase()] });
  var mdU2f = await pki.webauthn.verifyMetadataBlob(u2fLike.blob, { rootCertificates: [u2fLike.rootDer], time: T });
  check("mds: an entry is found by attestation-certificate key identifier",
    !!mds.metadataForKeyIdentifier(mdU2f, leafKeyId));
  check("mds: the key-identifier lookup is case-insensitive, as the catalogue's own casing varies",
    !!mds.metadataForKeyIdentifier(mdU2f, leafKeyId.toUpperCase()));
  check("mds: a key identifier the BLOB does not list is a miss",
    mds.metadataForKeyIdentifier(mdU2f, "00".repeat(20)) === null);
  check("mds: metadataForKeyIdentifier refuses anything that is not a verified result", (function () {
    try { mds.metadataForKeyIdentifier({ byAaguid: {} }, leafKeyId); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: a non-string key identifier is a miss, not a throw",
    mds.metadataForKeyIdentifier(mdU2f, 42) === null);
  // One public verb covers both key spaces, dispatching on the identifier's shape.
  check("mds: metadataFor also resolves a key identifier", !!pki.webauthn.metadataFor(mdU2f, leafKeyId));
  check("mds: metadataFor on an identifier of neither shape is a miss",
    pki.webauthn.metadataFor(mdU2f, "neither-shape") === null);
  check("mds: an aaguid-shaped identifier is not looked up among key identifiers",
    pki.webauthn.metadataFor(mdU2f, "01020304-0506-0708-090a-0b0c0d0e0f10") === null);
  check("mds: a key identifier that is not 40 hex is refused when the BLOB is read",
    (await codeFor({ keyIdentifiers: ["zz"] })) === "webauthn/bad-metadata-blob");
  check("mds: a non-array attestationCertificateKeyIdentifiers is refused",
    (await codeFor({ keyIdentifiers: leafKeyId })) === "webauthn/bad-metadata-blob");
  check("mds: more key identifiers than the ceiling is refused",
    (await codeFor({ keyIdentifiers: new Array(pki.C.LIMITS.MDS_MAX_KEY_IDS_PER_ENTRY + 1).fill(leafKeyId) })) === "webauthn/too-large");
  // Two entries claiming one key identifier give the lookup the same undefined choice a duplicate
  // aaguid does, so it is refused for the same reason.
  check("mds: two entries claiming one key identifier are refused", (await codeFor({ entries: [
    { statusReports: [{ status: "FIDO_CERTIFIED" }], attestationCertificateKeyIdentifiers: [leafKeyId] },
    { statusReports: [{ status: "FIDO_CERTIFIED" }], attestationCertificateKeyIdentifiers: [leafKeyId] },
  ] })) === "webauthn/duplicate-metadata-entry");

  // ---- end to end through the shipped verb, on a u2f attestation with its own root ----
  // A U2F authenticator's aaguid is all zeroes, so an aaguid-only dispatch finds no entry and
  // refuses it as unlisted. These drive pki.webauthn.verify itself: the lookup functions agreeing
  // in isolation says nothing about the verb, and the anchor check is the part that decides trust.
  var u2f = await require("../helpers/mds-blob").mintU2fAttestation();
  var u2fRes = await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, {});
  var u2fKeyId = mds.certKeyIdentifier(u2fRes.trustPath[u2fRes.trustPath.length - 1]);
  check("mds: the u2f attestation declares no aaguid, which is why it needs the key identifier",
    u2fRes.aaguid.equals(Buffer.alloc(16)) && /^[0-9a-f]{40}$/.test(u2fKeyId));

  var u2fMeta = await mint({ aaguid: null, anchors: [u2f.rootDer.toString("base64")],
    keyIdentifiers: [u2fKeyId] });
  var mdU2fReal = await pki.webauthn.verifyMetadataBlob(u2fMeta.blob, { rootCertificates: [u2fMeta.rootDer], time: T });
  var bound = await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdU2fReal, time: T });
  check("mds: a u2f attestation binds to the entry keyed by its attestation certificate",
    bound.attestationVerified === true && bound.metadata.anchors === 1 && bound.metadata.aaguid === null);

  // The anchor check must VALIDATE the path, not merely recognise a name: an entry registering a
  // different root must not match, even though that root is a perfectly good certificate.
  var u2fWrongRoot = await mint({ aaguid: null, anchors: [base.attRootDer.toString("base64")],
    keyIdentifiers: [u2fKeyId] });
  var mdWrong = await pki.webauthn.verifyMetadataBlob(u2fWrongRoot.blob, { rootCertificates: [u2fWrongRoot.rootDer], time: T });
  check("mds: a u2f attestation whose registered root it does not reach is refused",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdWrong, time: T }); })) === "webauthn/metadata-untrusted");

  // An authenticator the catalogue lists under neither key space is refused, naming the identifier
  // that was actually looked for rather than reporting a null aaguid.
  check("mds: a u2f attestation the catalogue does not list is refused as not found",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: md, time: T }); })) === "webauthn/metadata-not-found");
  check("mds: and the refusal names the key identifier it looked for, not a null aaguid",
    await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: md, time: T })
      .then(function () { return false; }, function (e) { return e.message.indexOf(u2fKeyId) !== -1; }));

  // A disqualifying status denies on the key-identifier path exactly as it does on the aaguid path.
  var u2fRevoked = await mint({ aaguid: null, anchors: [u2f.rootDer.toString("base64")],
    statusReports: [{ status: "REVOKED", effectiveDate: "2026-02-01" }],
    keyIdentifiers: [u2fKeyId] });
  var mdU2fRevoked = await pki.webauthn.verifyMetadataBlob(u2fRevoked.blob, { rootCertificates: [u2fRevoked.rootDer], time: T });
  check("mds: a revoked u2f model is refused on the key-identifier path too",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdU2fRevoked, time: T }); })) === "webauthn/metadata-status");
  // An entry that registers no attestation root at all cannot anchor anything, so a caller who
  // asked for metadata enforcement is told so rather than handed a pass.
  var u2fNoAnchor = await mint({ aaguid: null, anchors: [],
    keyIdentifiers: [u2fKeyId] });
  var mdNoAnchor = await pki.webauthn.verifyMetadataBlob(u2fNoAnchor.blob, { rootCertificates: [u2fNoAnchor.rootDer], time: T });
  check("mds: an entry registering no attestation root is refused, not treated as unconstrained",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdNoAnchor, time: T }); })) === "webauthn/metadata-no-anchor");

  // ---- the remaining decode and chain arms ----
  // A segment that IS valid base64url but whose contents are not JSON reaches the shared bounded
  // reader, which raises the typed error itself -- so the wrapper must re-throw that verdict rather
  // than replacing it with a vaguer one of its own.
  check("mds: a header that decodes but is not JSON keeps the reader's own verdict",
    (await codeFor({ headerRaw: "{not json" })) === "webauthn/bad-metadata-blob");
  check("mds: a payload that decodes but is not JSON keeps the reader's own verdict",
    (await codeFor({ payloadRaw: "{not json" })) === "webauthn/bad-metadata-blob");

  // A leaf key of a family no JWS signature algorithm here names cannot be matched to any alg, so
  // it is refused rather than attempted -- the same gate as an alg/leaf mismatch, from the other side.
  var edKp = await pki.webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var edSpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", edKp.publicKey));
  var edCert = await pki.x509.sign({
    subject: [{ commonName: "Ed25519 Signer" }], subjectPublicKey: edSpki, serialNumber: Buffer.from([9]),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: edKp.privateKey, name: [{ commonName: "Ed25519 Signer" }], publicKey: edSpki });
  check("mds: a leaf key of a family no supported alg names is refused",
    (await codeFor({ x5cRaw: [edCert.toString("base64")] })) === "webauthn/unsupported-algorithm");

  // ---- the algorithm table is the toolkit's, not a copy of it ----
  //
  // A BLOB really signed under RSASSA-PSS verifies. The table this reader resolves `alg` through is
  // DERIVED from pki.jose's JWS registry, so an algorithm the toolkit verifies as a JWS signature
  // cannot be one this reader refuses: a second table maintained beside the first is how PS256 came
  // to be accepted in one place and rejected in the other.
  for (var pssAlg of ["PS256", "PS384", "PS512"]) {
    var pssFix = await mint({ signAlg: pssAlg });
    var pssMd = await pki.webauthn.verifyMetadataBlob(pssFix.blob, { rootCertificates: [pssFix.rootDer], time: T });
    check("mds: a BLOB signed under " + pssAlg + " verifies", pssMd.no === 42);
  }
  var rsFix = await mint({ signAlg: "RS256" });
  check("mds: a BLOB signed under RS256 verifies",
    (await pki.webauthn.verifyMetadataBlob(rsFix.blob, { rootCertificates: [rsFix.rootDer], time: T })).no === 42);
  // An X.509 SubjectPublicKeyInfo carries an Edwards key (RFC 8410) and an ML-DSA key (RFC 9881) as
  // readily as an EC one, so a BLOB signed under those algorithms is a conformant JWS -- not a
  // theoretical one to be excused from the table. EdDSA is one algorithm name over two key types,
  // and the certificate is what says which, so both are driven.
  for (var edAlg of ["EdDSA-Ed25519", "EdDSA-Ed448"]) {
    var edFix = await mint({ signAlg: edAlg });
    check("mds: a BLOB signed under " + edAlg.replace("EdDSA-", "EdDSA over ") + " verifies",
      (await pki.webauthn.verifyMetadataBlob(edFix.blob, { rootCertificates: [edFix.rootDer], time: T })).no === 42);
  }
  // An Edwards leaf key is validated on-curve and full-order before it is imported. The identity
  // point verifies a trivial signature over ANY message, so a leaf carrying one authenticates
  // whatever payload it is shown -- and chaining to the pinned root does not help, because such a
  // certificate is malformed rather than unissued and can be perfectly well signed. Every other
  // Edwards key in the toolkit passes this gate; a new verification route must not be the exception.
  check("mds: an Ed25519 leaf carrying the identity point is refused before it is imported",
    (await codeFor({ signAlg: "EdDSA-Ed25519", lowOrderPoint: 32 })) === "webauthn/bad-att-cert");
  check("mds: ...and an Ed448 leaf likewise",
    (await codeFor({ signAlg: "EdDSA-Ed448", lowOrderPoint: 57 })) === "webauthn/bad-att-cert");
  for (var mlAlg of ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) {
    var mlFix = await mint({ signAlg: mlAlg });
    check("mds: a BLOB signed under " + mlAlg + " verifies",
      (await pki.webauthn.verifyMetadataBlob(mlFix.blob, { rootCertificates: [mlFix.rootDer], time: T })).no === 42);
  }
  // The derivation is the guard; this asserts it is TOTAL over the registry, so a row added there
  // cannot reach one reader and not the other. An X.509 SubjectPublicKeyInfo carries a key of every
  // type the registry names, so there is no algorithm to excuse.
  var joseSigAlgs = pki.jose.sigAlgs();
  var mdsAlgs = require("../../lib/webauthn-mds.js").BLOB_ALGS;
  function schemeOf(r) {
    if (r.kty === "EC") return "ECDSA";
    if (r.kty === "RSA") return r.saltLength ? "RSA-PSS" : "RSASSA-PKCS1-v1_5";
    if (r.kty === "OKP") return "EdDSA";
    return r.alg;                                     // AKP: the algorithm fixes its own parameter set
  }
  var ktysSeen = {};
  joseSigAlgs.forEach(function (r) { ktysSeen[r.kty] = 1; });
  check("mds: every JWS algorithm the toolkit verifies has a BLOB row",
    // All four key types are represented, so the walk cannot pass by having nothing to walk -- and
    // the bound is on the FAMILIES rather than a row count, which a new algorithm would move.
    Object.keys(ktysSeen).sort().join(",") === "AKP,EC,OKP,RSA" && joseSigAlgs.every(function (r) {
      var row = mdsAlgs[r.alg];
      return !!row && row.scheme === schemeOf(r) &&
        (r.hash ? row.hash === r.hash : true) &&
        (r.saltLength ? row.ver.saltLength === r.saltLength : true);
    }));
  // `HS256` is not a signature algorithm, and listing it beside RS256 is how the key-confusion class
  // starts; it is absent from the registry this table derives from, so it cannot appear here either.
  check("mds: no MAC algorithm has a BLOB row", mdsAlgs.HS256 === undefined && mdsAlgs.none === undefined);
  // EdDSA's WebCrypto algorithm is not fixed by the algorithm name, so its row says the certificate
  // supplies it rather than carrying parameters that would be right for only one of the two curves.
  check("mds: the EdDSA row takes its curve from the certificate",
    mdsAlgs.EdDSA.fromLeaf === true && mdsAlgs.EdDSA.imp === undefined);
  check("mds: an ML-DSA row carries the parameter set its own algorithm fixes",
    mdsAlgs["ML-DSA-65"].imp.name === "ML-DSA-65" && mdsAlgs["ML-DSA-65"].fromLeaf === undefined);
  // The map is keyed by the name the certificate parser REPORTS for a leaf's SPKI algorithm. A key
  // that is not that exact string is a row that never matches -- silently, since the miss reads as
  // "this leaf cannot do this scheme". Read the names off real certificates rather than assume them.
  var spkiNames = {};
  for (var nameAlg of ["ES256", "RS256", "EdDSA-Ed25519", "EdDSA-Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) {
    var nf = await mint({ signAlg: nameAlg });
    var nh = JSON.parse(Buffer.from(nf.blob.toString("ascii").split(".")[0].replace(/-/g, "+").replace(/_/g, "/") + "==", "base64").toString("utf8"));
    spkiNames[nameAlg] = pki.schema.x509.parse(Buffer.from(nh.x5c[0], "base64")).subjectPublicKeyInfo.algorithm.name;
  }
  check("mds: the leaf-scheme map is keyed by the names the certificate parser really reports",
    spkiNames.ES256 === "ecPublicKey" && spkiNames.RS256 === "rsaEncryption" &&
    spkiNames["EdDSA-Ed25519"] === "Ed25519" && spkiNames["EdDSA-Ed448"] === "Ed448" &&
    spkiNames["ML-DSA-44"] === "id-ml-dsa-44" && spkiNames["ML-DSA-65"] === "id-ml-dsa-65" &&
    spkiNames["ML-DSA-87"] === "id-ml-dsa-87");
  // Algorithm confusion, on the newly reachable rows: an EdDSA header over a leaf that holds no
  // Edwards key is refused at the scheme check, before any key is imported or signature examined.
  check("mds: an EdDSA header over an EC leaf is refused",
    (await codeFor({ signAlg: "ES256", alg: "EdDSA" })) === "webauthn/unsupported-algorithm");
  check("mds: an ML-DSA header over an Edwards leaf is refused",
    (await codeFor({ signAlg: "EdDSA-Ed25519", alg: "ML-DSA-44" })) === "webauthn/unsupported-algorithm");
  check("mds: an ML-DSA header naming a different parameter set than its leaf is refused",
    (await codeFor({ signAlg: "ML-DSA-44", alg: "ML-DSA-87" })) === "webauthn/unsupported-algorithm");

  // ---- an id-RSASSA-PSS certificate restricts its own key (RFC 4055 sec. 1.2 / 3.1) ----
  //
  // The restriction belongs to the CERTIFICATE, so it outranks the header: a key whose certificate
  // says RSASSA-PSS must not verify an RS* signature, and one pinned to a single hash must not
  // verify a signature made under another.
  var pssKeyFix = await mint({ signAlg: "PS256", pssRestricted: true });
  check("mds: an id-RSASSA-PSS leaf verifies a PS256 BLOB",
    (await pki.webauthn.verifyMetadataBlob(pssKeyFix.blob, { rootCertificates: [pssKeyFix.rootDer], time: T })).no === 42);
  check("mds: an id-RSASSA-PSS leaf refuses an RS256 header",
    (await codeFor({ signAlg: "PS256", pssRestricted: true, alg: "RS256" })) === "webauthn/unsupported-algorithm");
  var pinnedFix = await mint({ signAlg: "PS256", pssRestricted: true, pssPinHash: { name: "sha256", salt: 32 } });
  check("mds: an id-RSASSA-PSS leaf pinned to SHA-256 verifies its own PS256 BLOB",
    (await pki.webauthn.verifyMetadataBlob(pinnedFix.blob, { rootCertificates: [pinnedFix.rootDer], time: T })).no === 42);
  check("mds: an id-RSASSA-PSS leaf pinned to SHA-256 refuses a PS512 BLOB",
    (await codeFor({ signAlg: "PS512", pssRestricted: true, pssPinHash: { name: "sha256", salt: 32 } })) === "webauthn/unsupported-algorithm");
  // A pin this toolkit cannot read is a restriction it cannot honor, so it fails closed rather than
  // being treated as no restriction at all.
  check("mds: an id-RSASSA-PSS leaf pinned to an unimplemented hash is refused",
    (await codeFor({ signAlg: "PS256", pssRestricted: true, pssPinHash: { name: "sha1", salt: 20 } })) === "webauthn/unsupported-algorithm");
  // RFC 4055 sec. 3.1 draws the line at whether the parameters are THERE: absent, they restrict
  // nothing. Present, they restrict -- and `hashAlgorithm` is `[0] ... DEFAULT sha1Identifier`, so a
  // params SEQUENCE that omits it NAMES SHA-1 rather than declining to name anything. Reading the
  // omission as "unrestricted" would let a key its certificate confines to SHA-1 verify a SHA-512
  // signature.
  check("mds: an id-RSASSA-PSS leaf with an empty params SEQUENCE is restricted to the SHA-1 default",
    (await codeFor({ signAlg: "PS256", pssRestricted: true, pssPinHash: "empty-params" })) === "webauthn/unsupported-algorithm");
  // A rejection handler attached to the IMPORT alone leaves whatever the verify itself rejects with
  // to escape raw. RSASSA-PSS parameters demanding a longer salt than the algorithm supplies import
  // cleanly and then fail inside OpenSSL, so this returns a platform Error rather than a typed
  // verdict -- out of a verb whose contract is that every failure carries a webauthn/* code.
  var saltTooLong = await codeFor({ signAlg: "PS256", pssRestricted: true, pssPinHash: { name: "sha256", salt: 64 } });
  check("mds: a salt restriction the algorithm cannot satisfy is a typed verdict, not a platform error",
    saltTooLong === "webauthn/verify-error");
  // ...and absent parameters really do restrict nothing, which is the other half of the same clause.
  var unpinned = await mint({ signAlg: "PS512", pssRestricted: true });
  check("mds: an id-RSASSA-PSS leaf with no parameters restricts no hash",
    (await pki.webauthn.verifyMetadataBlob(unpinned.blob, { rootCertificates: [unpinned.rootDer], time: T })).no === 42);

  // Several roots may be held across a rotation, and the walk stops at the first that anchors the
  // chain rather than continuing to validate against the rest.
  check("mds: the first anchor that validates ends the search",
    (await pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [base.rootDer, base.otherDer], time: T })).no === 42);

  // The aaguid conversion is fed straight from authenticatorData, so a field of the wrong size means
  // "no model identity" rather than a truncated identifier that would match the wrong entry.
  check("mds: an aaguid that is not 16 bytes is no identity at all", mds.aaguidToString(Buffer.alloc(4)) === null);
  check("mds: a non-buffer aaguid is no identity at all", mds.aaguidToString("0102") === null);

  // ---- the two key spaces stay disjoint at the dispatch, not only at the lookup ----
  // The fido-u2f signature does not cover the AAGUID field, so those 16 bytes are editable by
  // anyone holding a genuine attestation. If a declared-but-unlisted AAGUID fell back to the
  // key-identifier lookup, such an attestation would be accepted under some OTHER authenticator's
  // entry while res.aaguid reported a model identity nothing vouched for.
  var forged = u2f.withAaguid("99999999-9999-9999-9999-999999999999");
  check("mds: the forged attestation still verifies on its own (the signature does not cover the aaguid)",
    (await pki.webauthn.verify(forged, u2f.clientDataHash, {})).attestationVerified === true);
  // The forged field is IGNORED for this format rather than trusted, so the attestation still binds
  // to its own entry through the certificate -- the forgery buys nothing instead of redirecting the
  // lookup.
  check("mds: a forged aaguid is ignored for a format that does not sign it, and the true entry still binds",
    (await pki.webauthn.verify(forged, u2f.clientDataHash, { metadata: mdU2fReal, time: T })).metadata.anchors === 1);
  // For fido-u2f the aaguid is not under the signature at all, so it must not select the entry even
  // when the value IS listed: pointing it at a listed model that shares the vendor's registered root
  // would resolve to that model's entry and skip the real U2F entry's status reports, letting a
  // revoked authenticator present itself as its healthy sibling. The certificate decides instead --
  // so the refusal names the key identifier, and a forged listed aaguid changes nothing.
  // The decisive case: the forged aaguid names an entry the catalogue DOES list, whose registered
  // root the u2f certificate also chains to. Keying on the certificate is what refuses it.
  var siblingModel = await mint({ aaguid: "99999999-9999-9999-9999-999999999999",
    anchors: [u2f.rootDer.toString("base64")], statusReports: [{ status: "FIDO_CERTIFIED_L2" }] });
  var mdSibling = await pki.webauthn.verifyMetadataBlob(siblingModel.blob, { rootCertificates: [siblingModel.rootDer], time: T });
  check("mds: a u2f attestation cannot borrow a LISTED model's entry by forging its aaguid",
    (await codeOf(function () { return pki.webauthn.verify(forged, u2f.clientDataHash, { metadata: mdSibling, time: T }); })) === "webauthn/metadata-not-found");

  // ---- verify's own option boundary ----
  // Every option here gates the verdict or supplies trust material, so a typo is not a no-op: a
  // misspelled `metadata` leaves the whole catalogue gate switched off and returns a pass the
  // caller believes was checked.
  check("verify: a misspelled metadata key is refused, never silently ignored",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metdata: mdU2fReal }); })) === "webauthn/bad-input");
  check("verify: an unknown opts key is refused",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { nope___: 1 }); })) === "webauthn/bad-input");
  check("verify: a non-object opts is refused",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, "later"); })) === "webauthn/bad-input");
  // An invalid instant is a caller configuration fault. Without this it reaches the path validator,
  // whose rejection is absorbed by the chain walk and reported as an authenticator trust failure --
  // fail-closed, but the wrong verdict, with the real cause buried in the cause chain.
  check("verify: an invalid opts.time is a config fault, not a trust failure",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { time: new Date("nope"), metadata: mdU2fReal }); })) === "webauthn/bad-input");
  check("verify: a non-Date opts.time is refused",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { time: 1780000000000 }); })) === "webauthn/bad-input");

  // ---- the bounded JSON reader's own verdicts keep this module's codes ----
  // A code the spec omits falls back to the framework default, so the module's headline defences --
  // duplicate-member smuggling, the depth cap -- would surface under a generic code that no
  // webauthn/* consumer can switch on.
  check("mds: a duplicate member in the payload is refused under this module's code",
    (await codeFor({ payloadRaw: '{"legalHeader":"x","no":42,"no":43,"nextUpdate":"2027-06-01","entries":[]}' })) === "webauthn/bad-metadata-blob");
  check("mds: a duplicate member in the header is refused under this module's code",
    (await codeFor({ headerRaw: '{"alg":"ES256","alg":"none","x5c":[]}' })) === "webauthn/bad-metadata-blob");
  var deep = "[".repeat(300) + "]".repeat(300);
  check("mds: JSON nested past the depth cap is refused under this module's code",
    (await codeFor({ payloadRaw: deep })) === "webauthn/bad-metadata-blob");

  // ---- RFC 7515 sec. 4.1.11: crit names parameters the reader MUST process ----
  // Ignoring crit is the same fault as ignoring x5u, one parameter over: the producer said "refuse
  // this unless you handle it", and nothing here processes an extension parameter.
  check("mds: a crit naming an unprocessed parameter is refused",
    (await codeFor({ headerExtra: { crit: ["exp"] } })) === "webauthn/bad-metadata-blob");
  check("mds: a crit naming a standard header parameter is refused",
    (await codeFor({ headerExtra: { crit: ["alg"] } })) === "webauthn/bad-metadata-blob");
  check("mds: an empty crit is refused", (await codeFor({ headerExtra: { crit: [] } })) === "webauthn/bad-metadata-blob");
  check("mds: a non-array crit is refused", (await codeFor({ headerExtra: { crit: "exp" } })) === "webauthn/bad-metadata-blob");

  // ---- the ceilings, at every layer that declares a count ----
  check("mds: a header above its own ceiling is refused before the signature check",
    (await codeFor({ headerExtra: { pad: "A".repeat(pki.C.LIMITS.MDS_BLOB_HEADER_MAX_BYTES + 1) } })) === "webauthn/too-large");
  // The signature is read before anything is authenticated and every supported algorithm has a
  // tightly bounded signature, so an oversized segment is refused before it is decoded rather than
  // materialized and handed to the verifier.
  check("mds: a signature segment above its ceiling is refused before it is decoded",
    (await codeOf(function () {
      var parts = base.blob.toString("ascii").split(".");
      var huge = parts[0] + "." + parts[1] + "." + "A".repeat(pki.C.LIMITS.MDS_BLOB_SIG_MAX_BYTES * 2);
      return pki.webauthn.verifyMetadataBlob(huge, { rootCertificates: [base.rootDer], time: T });
    })) === "webauthn/too-large");
  check("mds: more status reports than the ceiling is refused", (await codeFor({
    statusReports: new Array(pki.C.LIMITS.MDS_MAX_STATUS_REPORTS_PER_ENTRY + 1).fill({ status: "FIDO_CERTIFIED" }),
  })) === "webauthn/too-large");
  // The ceiling is measured on the input, not on a copy of it -- measuring the converted buffer
  // means materializing an oversized input in order to discover it should have been refused.
  // A string's length counts UTF-16 code units, not the UTF-8 bytes the conversion produces, so a
  // string of multi-byte characters can sit under a character-count ceiling and expand past the
  // byte ceiling during the copy -- the allocation the bound exists to prevent.
  check("mds: a multi-byte string is measured in bytes, not characters",
    (await codeOf(function () {
      // Built at runtime so this file stays pure ASCII: U+00E9 encodes to two UTF-8 bytes.
      var twoByte = String.fromCharCode(0xe9);
      var chars = Math.floor(pki.C.LIMITS.MDS_BLOB_MAX_BYTES / 2) + 1;   // under the char count...
      return pki.webauthn.verifyMetadataBlob(twoByte.repeat(chars), { rootCertificates: [base.rootDer], time: T });
    })) === "webauthn/too-large");                                        // ...but over it in bytes
  check("mds: an oversized string BLOB is refused",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob("A".repeat(pki.C.LIMITS.MDS_BLOB_MAX_BYTES + 1), { rootCertificates: [base.rootDer], time: T }); })) === "webauthn/too-large");

  // ---- an anchor is recognised on every field it is later read for ----
  // A looser test lets something merely certificate-SHAPED through, which then raises a raw,
  // untyped error from inside the path validator rather than a verdict.
  check("mds: a certificate-shaped object literal is not accepted as an anchor",
    (await codeOf(function () {
      return pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [{ subject: {}, subjectPublicKeyInfo: {} }], time: T });
    })) === "webauthn/bad-input");
  // A certification request carries a subject, a public key and a signature algorithm too, so the
  // recognition test must name something only a certificate has -- otherwise a parsed CSR is
  // silently installed as a trust anchor.
  var csrShaped = { subject: {}, subjectPublicKeyInfo: { bytes: Buffer.alloc(8) }, signatureAlgorithm: { oid: "1.2.840.10045.4.3.2" } };
  check("mds: a request-shaped object (no validity) is not accepted as an anchor",
    (await codeOf(function () { return pki.webauthn.verifyMetadataBlob(base.blob, { rootCertificates: [csrShaped], time: T }); })) === "webauthn/bad-input");

  // ---- only a catalogue this toolkit verified may decide anything ----
  // A result restored from a cache has the right property names but has been through none of the
  // signature and chain checks that give a catalogue its authority, and an attacker who can write
  // that cache would be choosing which roots an authenticator may chain to.
  var roundTripped = JSON.parse(JSON.stringify(md));
  check("mds: a catalogue restored from a cache is not a verified result", (function () {
    try { pki.webauthn.metadataFor(roundTripped, base.aaguid); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: and it cannot be used to enforce metadata on an attestation",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: roundTripped, time: T }); })) === "webauthn/bad-input");
  check("mds: a hand-built lookalike is refused", (function () {
    try { pki.webauthn.metadataFor({ byAaguid: {}, byKeyIdentifier: {}, entries: [] }, base.aaguid); return false; }
    catch (e) { return e.code === "webauthn/bad-input"; }
  })());
  check("mds: the genuine result still works", !!pki.webauthn.metadataFor(md, base.aaguid));
  // Provenance alone would not be enough: the verified catalogue is handed to the caller, so
  // anything holding a reference could rewrite the very fields the gates checked and the object
  // would still pass the identity test. It is frozen, so the catalogue that decides a later
  // verification is the one the signature covered.
  var frozenEntry = pki.webauthn.metadataFor(md, base.aaguid);
  check("mds: the verified catalogue is frozen", Object.isFrozen(md));
  check("mds: and so are its entries and their statements",
    Object.isFrozen(frozenEntry) && Object.isFrozen(frozenEntry.metadataStatement) &&
    Object.isFrozen(frozenEntry.statusReports));
  check("mds: rewriting the freshness opt-out does not take", (function () {
    try { md.allowStale = true; } catch (_e) { /* strict-mode throw is also a refusal */ }
    return md.allowStale === false;
  })());
  check("mds: rewriting an entry's registered roots does not take", (function () {
    var before = frozenEntry.metadataStatement.attestationRootCertificates.length;
    try { frozenEntry.metadataStatement.attestationRootCertificates = []; } catch (_e) { /* ditto */ }
    return frozenEntry.metadataStatement.attestationRootCertificates.length === before;
  })());
  check("mds: and a status report cannot be swapped for a clean one", (function () {
    try { frozenEntry.statusReports[0] = { status: "FIDO_CERTIFIED_L3" }; } catch (_e) { /* ditto */ }
    return frozenEntry.statusReports[0].status === "FIDO_CERTIFIED_L1";
  })());

  // ---- a report dated in the future has not taken effect ----
  // Letting a future-dated report be "the latest" would allow a clean report filed for next month
  // to displace a revocation that is in force today.
  var future = [{ status: "REVOKED", effectiveDate: "2026-03-01" },
    { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-12-01" }];
  check("mds: a future-dated clean report does not displace a revocation in force",
    mds.statusDenied({ index: 0, statusReports: future }, { statusPolicy: "latest-by-date" }, null, T) === true);
  // Once that date arrives, the same catalogue reads the other way.
  check("mds: and once it takes effect, it governs",
    mds.statusDenied({ index: 0, statusReports: future }, { statusPolicy: "latest-by-date" }, null,
      new Date("2027-01-01T00:00:00Z")) === false);
  // The rule holds under EVERY policy, not just latest-by-date: a scheduled revocation must deny
  // from the date it names, not from the moment the catalogue is published.
  check("mds: a future-dated revocation does not deny before its effective date under the default policy",
    mds.statusDenied({ index: 0, statusReports: [{ status: "REVOKED", effectiveDate: "2026-12-01" }] }, md, null, T) === false);
  check("mds: and it denies once that date arrives",
    mds.statusDenied({ index: 0, statusReports: [{ status: "REVOKED", effectiveDate: "2026-12-01" }] }, md, null,
      new Date("2027-01-01T00:00:00Z")) === true);
  // When every dated report is still in the future, none of them is in force -- not all of them.
  check("mds: an entry whose only reports are future-dated denies nothing yet",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "REVOKED", effectiveDate: "2026-11-01" },
      { status: "USER_VERIFICATION_BYPASS", effectiveDate: "2026-12-01" },
    ] }, { statusPolicy: "latest-by-date" }, null, T) === false);
  // A historical verdict does not get the benefit of reports filed after the instant asked about.
  check("mds: a historical instant does not see later reports",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "REVOKED", effectiveDate: "2026-05-01" },
      { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-05-15" },
    ] }, { statusPolicy: "latest-by-date" }, null, new Date("2026-05-10T00:00:00Z")) === true);

  // ---- a report that names one certificate is about THAT certificate ----
  // A whole batch of authenticators is listed under one entry, so a key-compromise report naming a
  // single attestation certificate must not deny every device the entry covers -- while a report
  // that names nothing, or names something unreadable, still applies to all of them.
  var u2fLeaf = pki.schema.x509.parse(u2f.attCertDer);
  var otherLeafDer = (await require("../helpers/mds-blob").mintU2fAttestation()).attCertDer;
  var scoped = { index: 0, statusReports: [{ status: "ATTESTATION_KEY_COMPROMISE",
    certificate: otherLeafDer.toString("base64") }] };
  check("mds: a key-compromise report naming another certificate does not deny this one",
    mds.statusDenied(scoped, md, u2fLeaf) === false);
  check("mds: a key-compromise report naming THIS certificate denies it",
    mds.statusDenied({ index: 0, statusReports: [{ status: "ATTESTATION_KEY_COMPROMISE",
      certificate: u2f.attCertDer.toString("base64") }] }, md, u2fLeaf) === true);
  check("mds: a report naming no certificate applies to the whole entry",
    mds.statusDenied({ index: 0, statusReports: [{ status: "ATTESTATION_KEY_COMPROMISE" }] }, md, u2fLeaf) === true);
  // An unreadable scope is not a narrower scope: the report keeps applying.
  check("mds: a report whose named certificate does not decode still applies",
    mds.statusDenied({ index: 0, statusReports: [{ status: "ATTESTATION_KEY_COMPROMISE",
      certificate: "bm90LWEtY2VydA==" }] }, md, u2fLeaf) === true);
  check("mds: with no certificate to compare against, the report applies",
    mds.statusDenied(scoped, md, null) === true);
  // The qualifier narrows only the status the specification gives it meaning for. Every other
  // disqualifying status is about the MODEL, so a certificate attached to one of those is a
  // nonconforming field -- reading it as a narrower scope would let a malformed REVOKED excuse the
  // authenticator it names as revoked.
  check("mds: a REVOKED report carrying another certificate still denies",
    mds.statusDenied({ index: 0, statusReports: [{ status: "REVOKED",
      certificate: otherLeafDer.toString("base64") }] }, md, u2fLeaf) === true);
  check("mds: a USER_VERIFICATION_BYPASS report carrying another certificate still denies",
    mds.statusDenied({ index: 0, statusReports: [{ status: "USER_VERIFICATION_BYPASS",
      certificate: otherLeafDer.toString("base64") }] }, md, u2fLeaf) === true);
  // Scope is settled BEFORE recency. A newer report about someone else's certificate must not be
  // selected as "the latest" and thereby displace an older revocation that does apply -- the entry
  // would be cleared by a report that was never about this authenticator at all.
  check("mds: a newer report about another certificate cannot displace an applicable revocation",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "REVOKED", effectiveDate: "2026-01-01" },
      { status: "ATTESTATION_KEY_COMPROMISE", effectiveDate: "2026-05-01", certificate: otherLeafDer.toString("base64") },
    ] }, { statusPolicy: "latest-by-date" }, u2fLeaf) === true);
  // And a newer report that DOES concern this certificate still governs.
  check("mds: a newer report about this certificate governs under latest-by-date",
    mds.statusDenied({ index: 0, statusReports: [
      { status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-01-01" },
      { status: "ATTESTATION_KEY_COMPROMISE", effectiveDate: "2026-05-01", certificate: u2f.attCertDer.toString("base64") },
    ] }, { statusPolicy: "latest-by-date" }, u2fLeaf) === true);

  // ---- an anchor is recognised by name AND key, so a cross-signed root still anchors ----
  // The same root reissued by a cross-signing CA carries the anchor's subject and public key but is
  // not self-issued. Identifying it by self-issuedness would leave it in the path, where it cannot
  // verify under an anchor that never issued it -- refusing a chain that is in fact anchored.
  var crossed = await mint({ crossSignRoot: true });
  var crossTerminal = pki.schema.x509.parse(Buffer.from(JSON.parse(
    Buffer.from(crossed.blob.toString("ascii").split(".")[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
  ).x5c[1], "base64"));
  var selfSignedRoot = pki.schema.x509.parse(crossed.rootDer);
  check("mds: the cross certificate carries the anchor's name and key but is not self-issued",
    crossTerminal.subjectPublicKeyInfo.bytes.equals(selfSignedRoot.subjectPublicKeyInfo.bytes) &&
    crossTerminal.issuer.dn !== crossTerminal.subject.dn);
  check("mds: a chain terminating in a cross-signed form of the root still anchors to it",
    (await pki.webauthn.verifyMetadataBlob(crossed.blob, { rootCertificates: [crossed.rootDer], time: T })).no === 42);
  // A chain that is ONLY the anchor is anchored: the signature was verified under that certificate's
  // key, and the certificate carries the anchor's name and key, so there is nothing left to chain.
  // It is still refused when the identity does not hold -- an empty path is trusted only because
  // the anchor itself was stripped from it, never merely because it ended up empty.
  var soleAnchor = await mint({ x5cSelfOnly: true });
  check("mds: an x5c consisting only of the anchor is directly trusted",
    (await pki.webauthn.verifyMetadataBlob(soleAnchor.blob, { rootCertificates: [soleAnchor.rootDer], time: T })).no === 42);
  check("mds: and the same single-certificate chain is refused against an unrelated root",
    (await codeOf(function () {
      return pki.webauthn.verifyMetadataBlob(soleAnchor.blob, { rootCertificates: [soleAnchor.otherDer], time: T });
    })) === "webauthn/metadata-untrusted");

  // ---- a verified catalogue expires at the point of USE, not only at parse ----
  // The result is a plain object a caller may hold indefinitely, so a catalogue fetched while fresh
  // and reused after its nextUpdate would keep authorizing an authenticator whose status reports
  // have since revoked it -- exactly what nextUpdate exists to prevent.
  var shortLived = await mint({ aaguid: null, keyIdentifiers: [u2fKeyId],
    anchors: [u2f.rootDer.toString("base64")], nextUpdate: "2026-06-02" });
  var mdShort = await pki.webauthn.verifyMetadataBlob(shortLived.blob, { rootCertificates: [shortLived.rootDer], time: T });
  check("mds: the catalogue verifies while it is current", mdShort.stale === false);
  check("mds: and it still governs at a time within its validity",
    (await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdShort, time: T })).attestationVerified === true);
  check("mds: but a catalogue reused after its nextUpdate is refused",
    (await codeOf(function () {
      return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdShort, time: new Date("2026-07-01T00:00:00Z") });
    })) === "webauthn/metadata-stale");
  // The caller's original opt-out rides on the result rather than having to be repeated: a
  // catalogue verified with allowStale stays usable, which is what the operator asked for.
  var staleAccepted = await pki.webauthn.verifyMetadataBlob(shortLived.blob,
    { rootCertificates: [shortLived.rootDer], time: T, allowStale: true });
  check("mds: a catalogue verified with allowStale keeps governing past its nextUpdate",
    (await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
      { metadata: staleAccepted, time: new Date("2026-07-01T00:00:00Z") })).attestationVerified === true);

  // ---- each path answers to its OWN entry ----
  // The status gate must consult the entry that governs the path being checked. Resolving one entry
  // for the whole statement and reusing it lets an unsigned ordering decide whose status report is
  // read -- for a compound, a healthy element listed first would suppress a revoked sibling's.
  // Driven here through the single-path case, which is the same code: the entry that governs the
  // u2f path is the one whose status denies, whatever else the catalogue also lists.
  var revokedU2f = await mint({ aaguid: null, keyIdentifiers: [u2fKeyId],
    anchors: [u2f.rootDer.toString("base64")],
    statusReports: [{ status: "REVOKED", effectiveDate: "2026-02-01" }],
    entries: [
      { aaguid: "01020304-0506-0708-090a-0b0c0d0e0f10", statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
        metadataStatement: { attestationRootCertificates: [] } },
      { attestationCertificateKeyIdentifiers: [u2fKeyId], statusReports: [{ status: "REVOKED", effectiveDate: "2026-02-01" }],
        metadataStatement: { attestationRootCertificates: [u2f.rootDer.toString("base64")] } },
    ] });
  var mdMixed = await pki.webauthn.verifyMetadataBlob(revokedU2f.blob, { rootCertificates: [revokedU2f.rootDer], time: T });
  check("mds: a catalogue holding a healthy entry alongside a revoked one still denies the revoked path",
    (await codeOf(function () { return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { metadata: mdMixed, time: T }); })) === "webauthn/metadata-status");

  // ---- the identifier lives on the ENTRY; the statement's copy is read too ----
  // sec. 3.1.1 puts attestationCertificateKeyIdentifiers on the entry, a sibling of
  // metadataStatement. sec. 3.2 defines the same field inside the statement and live entries carry
  // both, so the union is indexed -- and an identifier repeated across the two is one entry naming
  // itself twice, not two entries claiming one authenticator.
  var inStatement = await mint({ aaguid: null, statementExtra: { attestationCertificateKeyIdentifiers: [leafKeyId] } });
  var mdInStatement = await pki.webauthn.verifyMetadataBlob(inStatement.blob, { rootCertificates: [inStatement.rootDer], time: T });
  check("mds: the metadataStatement copy of the identifier is indexed too",
    !!mds.metadataForKeyIdentifier(mdInStatement, leafKeyId));
  var bothLevels = await mint({ aaguid: null, keyIdentifiers: [leafKeyId],
    statementExtra: { attestationCertificateKeyIdentifiers: [leafKeyId] } });
  var mdBoth = await pki.webauthn.verifyMetadataBlob(bothLevels.blob, { rootCertificates: [bothLevels.rootDer], time: T });
  check("mds: one identifier on both levels is one entry, not a duplicate claim",
    !!mds.metadataForKeyIdentifier(mdBoth, leafKeyId) && mdBoth.entries[0].keyIdentifiers.length === 1);

  // ---- the BLOB's signing certificate must be allowed to sign ----
  // RFC 5280 sec. 4.2.1.3: a certificate carrying keyUsage may only be used as it asserts. The path
  // validation that follows checks the CHAIN, not the target's application-level usage, so nothing
  // else would catch a leaf restricted to, say, key encipherment being used to sign the catalogue.
  var noSignKp = await pki.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var noSignSpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", noSignKp.publicKey));
  var noSignCert = await pki.x509.sign({
    subject: [{ commonName: "No Signing Usage" }], subjectPublicKey: noSignSpki, serialNumber: Buffer.from([7]),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: { keyUsage: ["keyAgreement"] },
  }, { key: noSignKp.privateKey, name: [{ commonName: "No Signing Usage" }], publicKey: noSignSpki });
  check("mds: an x5c leaf whose keyUsage omits digitalSignature may not sign the BLOB",
    (await codeFor({ x5cRaw: [noSignCert.toString("base64")] })) === "webauthn/bad-att-cert");

  // ---- a malformed status report is refused, not read as a clean bill of health ----
  // The gate treats a missing status as "nothing disqualifying", so a report that omits it would
  // silently vouch for the authenticator whose status it was supposed to carry.
  check("mds: a status report that is not an object is refused",
    (await codeFor({ statusReports: [42] })) === "webauthn/bad-metadata-blob");
  check("mds: a status report with no status is refused",
    (await codeFor({ statusReports: [{ effectiveDate: "2026-01-01" }] })) === "webauthn/bad-metadata-blob");
  check("mds: a status report whose status is not a string is refused",
    (await codeFor({ statusReports: [{ status: 7 }] })) === "webauthn/bad-metadata-blob");

  // ---- latest-by-date must not resolve a tie by array position ----
  // Two reports on the same date are equally current, so a disqualifying one among them cannot be
  // dropped because of where the catalogue happened to list it.
  var tie = [{ status: "FIDO_CERTIFIED_L2", effectiveDate: "2026-03-01" }, { status: "REVOKED", effectiveDate: "2026-03-01" }];
  check("mds: a same-day disqualifying report denies under latest-by-date",
    mds.statusDenied({ index: 0, statusReports: tie }, { statusPolicy: "latest-by-date" }) === true);
  check("mds: and the verdict does not change when the tie is listed the other way round",
    mds.statusDenied({ index: 0, statusReports: tie.slice().reverse() }, { statusPolicy: "latest-by-date" }) === true);

  // ---- a policy option supplied in the wrong type must not read as "off" ----
  // A caller writing rejectUnknownStatus: "true" from a config file is asking for the stricter
  // behaviour; comparing against `true` would record it as disabled and accept the authenticator.
  check("mds: a non-boolean rejectUnknownStatus is refused, not coerced to off",
    (await codeFor({}, { rejectUnknownStatus: "true" })) === "webauthn/bad-input");
  check("mds: a non-boolean allowStale is refused", (await codeFor({}, { allowStale: 1 })) === "webauthn/bad-input");
  check("mds: a non-boolean requireRollbackCheck is refused", (await codeFor({}, { requireRollbackCheck: "yes" })) === "webauthn/bad-input");
  check("mds: an unrecognised statusPolicy is refused rather than degrading silently",
    (await codeFor({}, { statusPolicy: "newest" })) === "webauthn/bad-input");

  console.log("CHECKS " + helpers.getChecks());
}

// A `none` attestation built from a real KAT's authenticatorData.
var fs = require("fs"), path = require("path"), crypto = require("crypto");
var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "webauthn", "py-webauthn-kat.json"), "utf8"));
function kb64u(s) { var b = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (b.length % 4) b += "="; return Buffer.from(b, "base64"); }
function noneHash() { return crypto.createHash("sha256").update(kb64u(KAT.formats.packed.clientDataJSON)).digest(); }
function attObjNone() {
  var m = pki.cbor.read.map(pki.cbor.decode(kb64u(KAT.formats.packed.attestationObject)));
  var authData = null;
  m.forEach(function (kv) { if (pki.cbor.read.textString(kv[0]) === "authData") authData = kv[1].content; });
  var B = pki.cbor.build;
  return B.map([[B.textString("fmt"), B.textString("none")], [B.textString("attStmt"), B.map([])],
    [B.textString("authData"), B.byteString(authData)]]);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(function () {}, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
