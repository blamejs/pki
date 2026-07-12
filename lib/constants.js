// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.C
 * @nav        Core
 * @title      Constants
 * @order      10
 * @featured   true
 * @slug       constants
 *
 * @intro
 *   Version-stable constant namespace for the toolkit. Scale values are
 *   FUNCTIONS, not pre-baked discrete numbers: `C.TIME.days(30)` reads
 *   at the call site and computes at boot, so a caller never hand-writes
 *   `30 * 24 * 60 * 60 * 1000` (a raw-literal the codebase gate refuses)
 *   and a reviewer never has to decode it.
 *
 *   Every scale helper is config-time / entry-point validation: it THROWS
 *   `ConstantsError` on a non-finite or negative argument, and on a product
 *   outside the safe-integer range, so an operator catches the typo at boot
 *   rather than shipping a silently-wrong window or an Infinity that would
 *   disable a size cap.
 *
 * @card
 *   Functional scale helpers (`C.TIME.*`, `C.BYTES.*`) plus the toolkit
 *   version and shared codec limits.
 */

var frameworkError = require("./framework-error");

var ConstantsError = frameworkError.ConstantsError;

// _positive(n, who) -- the shared guard every scale helper runs. Config-
// time tier: a bad scale argument is an authoring bug, so it throws.
function _positive(n, who) {
  if (typeof n !== "number" || !isFinite(n) || n < 0) {
    throw new ConstantsError(
      "constants/bad-scale",
      who + ": expected a finite number >= 0, got " + String(n)
    );
  }
  return n;
}

// _scale(n, who, factor) -- validate the argument AND the product. A finite
// operand can still overflow the multiplication (days(1e304) -> Infinity),
// and an Infinity handed onward silently disables any bound compared
// against it (`len > Infinity` is always false) -- so a product outside the
// safe-integer range throws instead of returning.
function _scale(n, who, factor) {
  var out = Math.round(_positive(n, who) * factor);
  if (!Number.isSafeInteger(out)) {
    throw new ConstantsError(
      "constants/bad-scale",
      who + ": the result " + String(out) + " is not a safe integer"
    );
  }
  return out;
}

var MS_PER_SECOND = 1000;
var SECONDS_PER_MINUTE = 60;
var MINUTES_PER_HOUR = 60;
var HOURS_PER_DAY = 24;
var DAYS_PER_WEEK = 7;

/**
 * @primitive  pki.C.TIME
 * @signature  C.TIME.days(n) -> milliseconds
 * @since      0.1.0
 * @status     stable
 * @spec       internal (design: functional time-scale helpers)
 *
 * Duration helpers. Each returns an integer count of milliseconds so the
 * value drops straight into `setTimeout`, a validity window, or an OCSP
 * `nextUpdate` computation. Composing reads naturally:
 * `C.TIME.days(365)` for a one-year certificate lifetime.
 *
 * @example
 *   var oneYear = pki.C.TIME.days(365);
 *   // -> 31536000000
 */
var TIME = {
  milliseconds: function (n) { return _scale(n, "C.TIME.milliseconds", 1); },
  seconds: function (n) { return _scale(n, "C.TIME.seconds", MS_PER_SECOND); },
  minutes: function (n) { return _scale(n, "C.TIME.minutes", SECONDS_PER_MINUTE * MS_PER_SECOND); },
  hours:   function (n) { return _scale(n, "C.TIME.hours", MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  days:    function (n) { return _scale(n, "C.TIME.days", HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  weeks:   function (n) { return _scale(n, "C.TIME.weeks", DAYS_PER_WEEK * HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
};

var BYTES_PER_KIB = 1024;

/**
 * @primitive  pki.C.BYTES
 * @signature  C.BYTES.mib(n) -> bytes
 * @since      0.1.0
 * @status     stable
 * @spec       IEC 80000-13
 *
 * Binary-magnitude size helpers. Each returns an integer byte count for
 * codec limits (max DER input, max PEM block) so a size bound reads as
 * `C.BYTES.mib(16)` instead of `16 * 1024 * 1024`.
 *
 * @example
 *   var cap = pki.C.BYTES.mib(16);
 *   // -> 16777216
 */
var BYTES = {
  b:   function (n) { return _scale(n, "C.BYTES.b", 1); },
  kib: function (n) { return _scale(n, "C.BYTES.kib", BYTES_PER_KIB); },
  mib: function (n) { return _scale(n, "C.BYTES.mib", BYTES_PER_KIB * BYTES_PER_KIB); },
  gib: function (n) { return _scale(n, "C.BYTES.gib", BYTES_PER_KIB * BYTES_PER_KIB * BYTES_PER_KIB); },
};

// LIMITS -- shared codec ceilings. A DER document larger than this, or
// nested deeper than this, is refused before the parser walks it: an
// unbounded length prefix or a pathologically-nested SEQUENCE is a
// classic decoder-DoS, so the bound is a fail-closed default rather
// than a tunable an operator must remember to set.
//
// DER_MAX_INTEGER_BYTES and OID_MAX_SUBIDENTIFIER_BYTES are per-value
// ceilings the whole-document cap can't provide: a single INTEGER or OID
// sub-identifier under the 16 MiB limit can still carry hundreds of KiB,
// so a value reader that scales super-linearly in its content length is a
// decoder-DoS the document cap does not stop. 16 KiB covers any real key
// material (an RSA-131072 modulus), and 32 bytes covers any real OID arc:
// the largest standard sub-identifier is a 128-bit UUID-based arc (X.667,
// e.g. 2.25.<uuid>), which is 19 base-128 bytes -- so the cap must exceed
// that, not sit at 16. Anything larger than 32 bytes is refused as hostile.
var LIMITS = {
  DER_MAX_BYTES: BYTES.mib(16),
  DER_MAX_DEPTH: 64,
  // Total decoded-node ceiling: the DER decoder builds an eager node tree, so a
  // dense run of tiny TLVs (a 2-byte NULL is a node) fans a small input into a
  // huge tree -- ~350 B/node, so a 16 MiB input of NULLs is ~8M nodes ~= 2.8 GiB.
  // 4M sits well above the largest realistic structure (a full 16 MiB CRL carries
  // ~500k revoked entries ~= 2.5M nodes) and below the dense-bomb count; the
  // operator may override via opts.maxItems. (The CBOR sibling caps at 1M, too
  // low for DER's legitimate large CRLs.)
  DER_MAX_ITEMS: 4000000,
  // Hard stack-safe ceiling on the recursion depth of the DER / CBOR
  // decoders, independent of the (operator-tunable) maxDepth. Both decoders
  // are recursive descent; a maxDepth raised above the engine's native call-
  // stack limit would let deeply nested input overflow the C stack with a raw
  // RangeError instead of the typed too-deep verdict, defeating the fail-closed
  // contract. A maxDepth above this ceiling is refused at config time. 256 is
  // four times the default cap and far deeper than any real PKI / CBOR nesting
  // (a certificate is ~6 levels; the deepest bounded re-decode is 16), while
  // staying well below the overflow threshold on any supported platform.
  MAX_DECODE_DEPTH_CEILING: 256,
  PEM_MAX_BYTES: BYTES.mib(16),
  DER_MAX_INTEGER_BYTES: BYTES.kib(16),
  OID_MAX_SUBIDENTIFIER_BYTES: 32,
  // Deterministic-CBOR codec ceilings (RFC 8949), the DER neighbours' siblings:
  // a whole-document cap refused before the walk, a nesting cap, and a per-value
  // bignum ceiling the document cap can't provide. Unlike DER_MAX_INTEGER_BYTES,
  // the bignum cap carries NO +1 sign octet -- a CBOR tag-2/3 bignum body is pure
  // unsigned big-endian magnitude (RFC 8949 sec. 3.4.3), so 16 KiB is the exact
  // byte ceiling (covers an RSA-131072 modulus).
  CBOR_MAX_BYTES: BYTES.mib(16),
  CBOR_MAX_DEPTH: 64,
  CBOR_MAX_BIGUINT_BYTES: BYTES.kib(16),
  // Total decoded-item ceiling. A definite-length array or map can declare a
  // huge element count that stays under the byte cap yet allocates one node per
  // element -- e.g. a 16 MiB input of `9a00fffffb` followed by ~16 million
  // one-byte items would build ~16 million nodes and exhaust memory before a
  // typed verdict. The decoder counts every item it builds and refuses past this
  // cap, so a high-fanout bomb fails closed with cbor/too-many-items instead of
  // OOM-ing. 1,000,000 is far above any real CBOR-encoded PKI structure (a C509
  // certificate or COSE message is hundreds of items) while bounding the tree.
  CBOR_MAX_ITEMS: 1000000,
  // Certificate Transparency SCT-list bounds (RFC 6962 sec. 3.3). The outer sct_list
  // vector carries a 2-byte length prefix, so a well-formed list body is at most
  // 2^16-1 = 65535 bytes and the full TLS blob (prefix + body) is at most 65537.
  // The byte cap sits at that structural maximum, so the largest conforming list
  // is accepted while an oversized inner OCTET STRING (up to the DER document cap)
  // is refused BEFORE the list is walked. The per-list count cap is asserted per
  // element DURING the walk (an element count is unknowable before walking
  // variable-length elements), bounding total work at SCT_MAX_COUNT+1 elements
  // regardless of a hostile length prefix (the CVE-2022-0778 class: crafted bytes
  // inside a certificate extension pinning a validator). A real chain carries
  // 2-5 SCTs; 256 is far above policy.
  SCT_MAX_BYTES: BYTES.kib(64) + 1,
  SCT_MAX_COUNT: 256,
  // Merkle-proof node-count ceiling (RFC 6962 / RFC 9162). A DoS backstop that
  // rejects a pathologically long proof array BEFORE the O(log n) fold does any
  // digest work. 65 is the exact structural maximum: a tree size is a uint64, so
  // an audit (inclusion) path is at most ceil(log2(2^64)) = 64 nodes, but a
  // consistency proof is at most ceil(log2(newSize)) + 1 = 65 nodes (the extra
  // node is the SUBPROOF terminal for a non-power-of-two old size near 2^64). Real
  // CT logs are 2^30-2^40 (30-40-node proofs), so 65 is generous headroom while
  // still bounding hostile work. The PRECISE per-proof guard is the geometry
  // check in each verify (the node count must equal what the coordinates require);
  // this is the coarse cap. A node count, not a byte size.
  MERKLE_MAX_PROOF_NODES: 65,
  // Certification-path length ceiling: bounds the per-cert asymmetric verify
  // work on an untrusted certificate bundle (a real chain is well under this;
  // the operator may override via opts.maxPathCerts).
  PATH_MAX_CERTS: 100,
  // Valid-policy-tree node ceiling: bounds the RFC 5280 6.1.3(d) tree a
  // policy-rich hostile chain can grow (the CVE-2023-0464 class). A real
  // chain's tree holds a handful of nodes; the operator may override via
  // opts.maxPolicyNodes.
  PATH_MAX_POLICY_NODES: 4096,
  // PKCS#12 container ceilings. A PFX carries lists at three altitudes
  // (ContentInfos per AuthenticatedSafe, SafeBags per SafeContents,
  // attributes per bag) and can chain fresh DER blobs inside OCTET STRINGs,
  // where every re-decode would otherwise restart the depth cap from zero.
  // A real keystore holds a handful of keys and certificates; thousands of
  // elements or dozens of chained re-decodes is hostile input, not a store.
  PKCS12_MAX_ELEMENTS: 1024,
  PKCS12_MAX_REDECODES: 64,
  PKCS12_MAX_BAG_DEPTH: 16,
  // BER constructed-string reassembly copies each nesting level's payload, so
  // nesting multiplies transient memory. Real producers segment one level
  // deep; nesting past this cap is amplification, not a store.
  BER_MAX_STRING_NESTING: 8,
  // A single attribute's value SET -- no deployed attribute carries more than
  // a handful of values; a list at this scale is amplification.
  ATTRIBUTE_MAX_VALUES: 256,
  // JSON message bounds for the JOSE / ACME layer (RFC 8555). Directories and
  // resource objects are small (certificates travel as PEM, not JSON); 1 MiB is
  // generous headroom. Depth 32 clears the deepest real nesting (a problem
  // document's subproblems nest one level) with margin below any stack risk;
  // enforced BEFORE parsing so a hostile document is refused up front.
  JSON_MAX_BYTES: BYTES.mib(1),
  JSON_MAX_DEPTH: 32,
  // ACME challenge token entropy floor (RFC 8555 sec. 8, errata 6950): >= 128
  // bits of base64url is >= 22 characters. A shorter token is refused before use.
  ACME_TOKEN_MIN_CHARS: 22,
  // OCSP embedded-certificate ceiling. A BasicOCSPResponse (or an OCSP request
  // Signature) carries the responder / requestor certificate plus at most a short
  // chain; the delegated-responder authorization loop verifies each candidate
  // BEFORE the response signature is checked, so an attacker-crafted stapled /
  // relayed response with a huge certs list would drive unbounded pre-auth
  // signature verifies. 32 is generous headroom over a real chain.
  OCSP_MAX_CERTS: 32,
  // HSS hierarchy depth (RFC 8554 sec. 6.1: L is 1..8). The HSS verifier caps
  // its per-level parse loop at this from the registry, never at the blob's own
  // Nspk, so a hostile signature cannot drive an unbounded level walk.
  HSS_MAX_LEVELS: 8,
  // Trust-store ingestion ceilings (Mozilla/NSS certdata.txt + CCADB CSV).
  // Every cap is refused BEFORE the offending allocation with a typed trust/*
  // error -- never a silent truncate. A live certdata.txt is a few MiB and a
  // CCADB all-records export a few MiB more, so 16 MiB whole-input headroom
  // matches the codec siblings. A root certificate (or a CCADB PEM cell) is a
  // few KiB; a MULTILINE_OCTAL blob or CSV field past 64 KiB is amplification,
  // not a root. The real store is ~150 roots x 2 object blocks (and one CCADB
  // row per root), so 10000 objects / rows is generous headroom while bounding
  // a block/row bomb.
  TRUST_MAX_BYTES: BYTES.mib(16),
  TRUST_MAX_OCTAL_BYTES: BYTES.kib(64),
  TRUST_MAX_OBJECTS: 10000,
  TRUST_MAX_CSV_ROWS: 10000,
  TRUST_MAX_CSV_FIELD_BYTES: BYTES.kib(64),
};

// Single-sourced from the package manifest so the reported version can
// never drift from the published package (package.json is always present
// in the installed tarball). A hand-maintained literal here silently
// shipped 0.1.0 on a 0.1.1 release.
var VERSION = require("../package.json").version;

module.exports = {
  TIME:    TIME,
  BYTES:   BYTES,
  LIMITS:  LIMITS,
  version: VERSION,
};
