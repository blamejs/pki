// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the RFC 9618 valid_policy_graph.
 *
 * RFC 5280 sec. 6.1.3 step (d)(1)(i) creates one child per matching parent, so a chain where several
 * issuer policies map to one subject policy multiplies the structure at every level. RFC 9618
 * replaces it with a graph holding at most one node per (depth, policy identifier) and giving that
 * node several parents instead. The information is the same and the size is linear.
 *
 * What is held here: the four graph invariants RFC 9618 sec. 5.2 states, each replacement step, the
 * wrap-up procedure sec. 5.5 rewrites, and the conforming chain the tree could not validate inside
 * `C.LIMITS.PATH_MAX_POLICY_NODES`. Every vector drives `pki.path.validate` with real signed
 * certificates.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

var ARC = "1.3.6.1.4.1.99999.1.";
function pol(j) { return ARC + j; }
var ANY = pki.oid.byName("anyPolicy");
var T = new Date("2027-01-01T00:00:00Z");
var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2036-01-01T00:00:00Z");

var KEY = null;
async function keys() {
  if (KEY === null) {
    var pair = await pki.key.generate("Ed25519");
    KEY = { key: await pki.key.export(pair.privateKey), pub: await pki.key.export(pair.publicKey) };
  }
  return KEY;
}

/**
 * A chain of `depth` certificates under a root, each level carrying `spec(d)` extensions. The whole
 * chain shares one key pair, so only the names chain; that is enough for every policy vector here
 * and keeps the build fast.
 */
async function chainOf(depth, rootExtensions, spec) {
  var k = await keys();
  var root = await pki.x509.sign({
    subject: "CN=Root", subjectPublicKey: k.pub, notBefore: NB, notAfter: NA,
    extensions: rootExtensions,
  }, { key: k.key });
  var certs = [], issuer = root;
  for (var d = 1; d <= depth; d++) {
    var cert = await pki.x509.sign({
      subject: "CN=Level " + d, subjectPublicKey: k.pub, notBefore: NB, notAfter: NA,
      extensions: spec(d, d === depth),
    }, { cert: issuer, key: k.key });
    certs.push(cert);
    issuer = cert;
  }
  return { certs: certs, root: root };
}

/** Every CA carries k policies and maps each of them to every one of them, so each policy at the
 *  next depth matches k parents. This is the shape RFC 9618 sec. 3.2 names as the exponential one. */
async function fanOutChain(depth, k) {
  var policies = [], mappings = [];
  for (var j = 0; j < k; j++) policies.push({ oid: pol(j) });
  for (var a = 0; a < k; a++) for (var b = 0; b < k; b++) mappings.push({ issuerDomainPolicy: pol(a), subjectDomainPolicy: pol(b) });
  return chainOf(depth,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: policies },
    function (d, isLeaf) {
      var ext = { basicConstraints: isLeaf ? { cA: false } : { cA: true }, certificatePolicies: policies };
      if (!isLeaf) { ext.keyUsage = ["keyCertSign"]; ext.policyMappings = mappings; }
      return ext;
    });
}

function graphOf(res) { return res.validPolicyGraph; }
/** The graph is a flat node list linked by index, so every node appears exactly once however many
 *  parents reach it. */
function allNodes(graph) { return graph ? graph.nodes : []; }
function codesOf(res) {
  var out = [];
  res.results.forEach(function (r) {
    r.checks.forEach(function (c) { if (c.ok === false && out.indexOf(c.code) === -1) out.push(c.code); });
  });
  return out;
}
async function validate(built, opts) {
  var o = { trustAnchors: [built.root], time: T };
  if (opts) Object.keys(opts).forEach(function (kk) { o[kk] = opts[kk]; });
  return pki.path.validate(built.certs, o);
}

// ---- the chain the tree could not validate ----------------------------------------------------

async function testAConformingChainTheTreeRefused() {
  // Measured on the tree: k=4 depth=5 wants 1365 nodes and validates; depth=6 wants 5461, hits the
  // 4096 cap, and the path is refused. The graph wants 1 + 4*6 = 25.
  var five = await validate(await fanOutChain(5, 4));
  check("1. CONTROL: the chain one level shallower validated before this change and still does",
    five.valid === true && five.userConstrainedPolicySet.length === 4);

  var six = await validate(await fanOutChain(6, 4));
  check("2. a conforming chain the exponential tree could not hold now validates",
    six.valid === true && codesOf(six).indexOf("path/policy-tree-cap") === -1);
  check("3. ...and reports the four policies its certificates actually assert",
    six.userConstrainedPolicySet.slice().sort().join(",") === [pol(0), pol(1), pol(2), pol(3)].sort().join(","));
  check("4. the graph is linear in the path length, where the tree was exponential",
    allNodes(graphOf(six)).length === 1 + 4 * 6);

  // k=3 depth=8 was the other measured refusal: 3280 nodes at depth 7, capped at depth 8.
  var deep = await validate(await fanOutChain(8, 3));
  check("5. the same holds at the other measured boundary", deep.valid === true &&
    allNodes(graphOf(deep)).length === 1 + 3 * 8);
}

// ---- the four invariants RFC 9618 sec. 5.2 states ---------------------------------------------

function invariantReport(graph) {
  var nodes = allNodes(graph);
  function parentsOf(n) { return n.parents.map(function (id) { return nodes[id]; }); }
  // The two link lists must agree, or every invariant below is read off a structure the caller
  // cannot navigate the other way.
  var asymmetric = [];
  nodes.forEach(function (n) {
    n.children.forEach(function (cid) { if (nodes[cid].parents.indexOf(n.id) === -1) asymmetric.push(n.id + "->" + cid); });
    n.parents.forEach(function (pid) { if (nodes[pid].children.indexOf(n.id) === -1) asymmetric.push(pid + "->" + n.id); });
  });
  var perDepth = Object.create(null), dupes = [], anyBadParent = [], mixed = [], anyBadExpected = [];
  nodes.forEach(function (n) {
    var key = n.depth + "|" + n.validPolicy;
    if (perDepth[key]) dupes.push(key); else perDepth[key] = true;
    var ps = parentsOf(n);
    if (n.validPolicy === ANY) {
      if (!(n.expectedPolicySet.length === 1 && n.expectedPolicySet[0] === ANY)) anyBadExpected.push(key);
      if (n.depth > 0 && !(ps.length === 1 && ps[0].validPolicy === ANY && ps[0].depth === n.depth - 1)) anyBadParent.push(key);
    }
    if (n.depth > 0) {
      var anyParents = ps.filter(function (p) { return p.validPolicy === ANY; }).length;
      if (anyParents > 0 && anyParents !== ps.length) mixed.push(key);
      if (anyParents === ps.length && ps.length > 1) mixed.push(key);
    }
  });
  return { dupes: dupes, anyBadParent: anyBadParent, mixed: mixed, anyBadExpected: anyBadExpected,
    asymmetric: asymmetric, nodes: nodes, parentsOf: parentsOf };
}

async function testTheGraphInvariantsHold() {
  var res = await validate(await fanOutChain(6, 4));
  var r = invariantReport(graphOf(res));
  check("6. at most one node per depth and policy identifier", r.dupes.length === 0);
  check("7. an anyPolicy node above depth zero has exactly one parent, the anyPolicy above it",
    r.anyBadParent.length === 0);
  check("8. no node has both an anyPolicy parent and a non-anyPolicy parent, and a single anyPolicy parent is its only one",
    r.mixed.length === 0);
  check("9. an anyPolicy node's expected policy set is exactly anyPolicy", r.anyBadExpected.length === 0);
  check("10. a node carries its parents as a list, since one node may be reached from several",
    r.nodes.every(function (n) { return Array.isArray(n.parents); }) && r.nodes[0].parents.length === 0);
  check("11. the two link lists agree, so the graph reads the same in both directions",
    r.asymmetric.length === 0);
  // A graph handed back as a root to walk re-expands into the exponential structure the moment
  // anything recurses into every child, JSON.stringify included. A flat list linked by index is
  // linear however it is read, and carries no cycle.
  var serialized;
  try { serialized = JSON.stringify(graphOf(res)); }
  catch (e) { serialized = "threw " + e.name; }
  check("11b. the graph serializes, and its serialized size is linear rather than exponential",
    serialized.indexOf("threw ") !== 0 && serialized.length < 20000);
}

// ---- the replacement steps ---------------------------------------------------------------------

async function testStepD1JoinsParentsRatherThanMultiplying() {
  // Two issuer policies both mapping to one subject policy: the tree makes two nodes for it, the
  // graph makes one with two parents.
  var built = await chainOf(2,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: pol(0) }, { oid: pol(1) }] },
    function (d, isLeaf) {
      if (!isLeaf) {
        return { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
          certificatePolicies: [{ oid: pol(0) }, { oid: pol(1) }],
          policyMappings: [{ issuerDomainPolicy: pol(0), subjectDomainPolicy: pol(9) },
            { issuerDomainPolicy: pol(1), subjectDomainPolicy: pol(9) }] };
      }
      return { basicConstraints: { cA: false }, certificatePolicies: [{ oid: pol(9) }] };
    });
  var res = await validate(built);
  var r = invariantReport(graphOf(res));
  var joined = r.nodes.filter(function (n) { return n.validPolicy === pol(9); });
  check("12. a policy two parents both expect is ONE node", joined.length === 1);
  check("13. ...carrying both of them as its parents",
    r.parentsOf(joined[0]).length === 2 &&
    r.parentsOf(joined[0]).map(function (p) { return p.validPolicy; }).sort().join(",") === [pol(0), pol(1)].sort().join(","));
  check("14. and the path validates on it", res.valid === true);
}

async function testStepD1iiAndD2UseTheAnyPolicyNode() {
  // The root asserts anyPolicy, so a policy no node expects is parented to the anyPolicy node.
  var built = await chainOf(2,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }] },
    function (d, isLeaf) {
      if (!isLeaf) {
        return { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }] };
      }
      return { basicConstraints: { cA: false }, certificatePolicies: [{ oid: pol(5) }] };
    });
  var res = await validate(built);
  var r = invariantReport(graphOf(res));
  var five = r.nodes.filter(function (n) { return n.validPolicy === pol(5); });
  check("15. a policy no node expects is parented to the anyPolicy node above it",
    five.length === 1 && r.parentsOf(five[0]).length === 1 &&
    r.parentsOf(five[0])[0].validPolicy === ANY);
  check("16. ...and it reaches the user-constrained set, since its only parent is anyPolicy",
    res.valid === true && res.userConstrainedPolicySet.indexOf(pol(5)) !== -1);
}

async function testStepD2MakesOneNodePerExpectedPolicy() {
  // Two named policies at depth 1, then anyPolicy at depth 2: step (d)(2) creates one node per OID
  // in the union of the depth-1 expected sets, not one per parent.
  var built = await chainOf(2,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }] },
    function (d, isLeaf) {
      if (!isLeaf) {
        return { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
          certificatePolicies: [{ oid: pol(0) }, { oid: pol(1) }] };
      }
      return { basicConstraints: { cA: false }, certificatePolicies: [{ oid: ANY }] };
    });
  var res = await validate(built);
  var r = invariantReport(graphOf(res));
  var deep = r.nodes.filter(function (n) { return n.depth === 2; });
  check("17. anyPolicy in a certificate makes one node per expected policy at the depth below",
    deep.length === 2 &&
    deep.map(function (n) { return n.validPolicy; }).sort().join(",") === [pol(0), pol(1)].sort().join(","));
  check("18. each of those nodes carries the one parent that expected it",
    deep.every(function (n) {
      var ps = r.parentsOf(n);
      return ps.length === 1 && ps[0].validPolicy === n.validPolicy;
    }));
  check("19. the path validates and reports both policies", res.valid === true &&
    res.userConstrainedPolicySet.slice().sort().join(",") === [pol(0), pol(1)].sort().join(","));
}

async function testPolicyMappingSteps() {
  // (b)(2): the issuerDomainPolicy has no node of its own, but an anyPolicy node exists, so a child
  // of the depth i-1 anyPolicy node is generated for it.
  var built = await chainOf(2,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }] },
    function (d, isLeaf) {
      if (!isLeaf) {
        return { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }],
          policyMappings: [{ issuerDomainPolicy: pol(0), subjectDomainPolicy: pol(1) }] };
      }
      return { basicConstraints: { cA: false }, certificatePolicies: [{ oid: pol(1) }] };
    });
  var res = await validate(built);
  // The policy that reaches the caller is the ISSUER domain policy, which is what mapping is for:
  // the relying party asked about the anchor's policy space and the mapping translates down the
  // chain, so pol(0) survives and the subject domain policy pol(1) it was mapped to does not.
  check("20. a mapping from a policy with no node generates one under the anyPolicy node",
    res.valid === true && res.userConstrainedPolicySet.join(",") === pol(0));
  var r = invariantReport(graphOf(res));
  var mapped = r.nodes.filter(function (n) { return n.validPolicy === pol(0) && n.depth === 1; });
  check("21. ...at depth i, parented to the anyPolicy node at depth i-1",
    mapped.length === 1 && r.parentsOf(mapped[0]).length === 1 &&
    r.parentsOf(mapped[0])[0].validPolicy === ANY && r.parentsOf(mapped[0])[0].depth === 0);

  // (b)(3): with mapping inhibited, the node for each mapped-from policy is deleted and its now
  // childless ancestors go with it, so nothing reaches the user-constrained set.
  var fan = await fanOutChain(3, 2);
  var inhibited = await validate(fan, { initialPolicyMappingInhibit: true });
  check("22. inhibiting policy mapping deletes the mapped-from nodes, emptying the policy set",
    inhibited.userConstrainedPolicySet.length === 0);
  check("23. CONTROL: the same chain with mapping allowed reports both policies",
    (await validate(fan)).userConstrainedPolicySet.length === 2);
  // An emptied graph is only a refusal where the path requires an explicit policy, which is the
  // RFC 5280 sec. 6.1.5 condition RFC 9618 leaves in place.
  var required = await validate(fan, { initialPolicyMappingInhibit: true, initialExplicitPolicy: true });
  check("24. ...and the path is refused once an explicit policy is required",
    required.valid === false && codesOf(required).indexOf("path/policy-required") !== -1);
}

// ---- the wrap-up procedure RFC 9618 sec. 5.5 rewrites -----------------------------------------

async function testTheWrapUpReadsTheGraphNotTheLeaves() {
  // A node whose single parent is the anyPolicy node reaches the user-constrained set, and RFC 9618
  // step (g)(2) does not restrict that to depth n. Here the leaf asserts anyPolicy, so the policy
  // that survives comes from a node ABOVE the deepest one.
  var built = await chainOf(2,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }] },
    function (d, isLeaf) {
      if (!isLeaf) {
        return { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: pol(3) }] };
      }
      return { basicConstraints: { cA: false }, certificatePolicies: [{ oid: pol(3) }] };
    });
  var res = await validate(built);
  check("25. a node whose only parent is anyPolicy reaches the user-constrained set",
    res.valid === true && res.userConstrainedPolicySet.join(",") === pol(3));

  // (g)(6)(ii): anyPolicy reaches the authority-constrained set, and a user-initial-policy-set OID
  // that is not already there is added under the anyPolicy qualifiers.
  var everyLevelAny = await chainOf(2,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], certificatePolicies: [{ oid: ANY }] },
    function (d, isLeaf) {
      var ext = { basicConstraints: isLeaf ? { cA: false } : { cA: true }, certificatePolicies: [{ oid: ANY }] };
      if (!isLeaf) ext.keyUsage = ["keyCertSign"];
      return ext;
    });
  var constrained = await validate(everyLevelAny, { userInitialPolicySet: [pol(7), pol(8)] });
  check("26. anyPolicy in the authority-constrained set expands to the caller's initial policy set",
    constrained.valid === true &&
    constrained.userConstrainedPolicySet.slice().sort().join(",") === [pol(7), pol(8)].sort().join(","));
  var unconstrained = await validate(everyLevelAny);
  check("27. CONTROL: with no initial policy set the answer is anyPolicy itself",
    unconstrained.valid === true && unconstrained.userConstrainedPolicySet.join(",") === ANY);

  // The intersection arm: a policy the path asserts but the caller did not ask for is dropped.
  var named = await validate(await fanOutChain(3, 2), { userInitialPolicySet: [pol(0)] });
  check("28. a policy outside the caller's initial set is dropped from the user-constrained set",
    named.valid === true && named.userConstrainedPolicySet.join(",") === pol(0));
}

// ---- the cap stays a backstop ------------------------------------------------------------------

async function testTheNodeCapRemains() {
  // The cap stays, and what it bounds changes with the structure. The graph grows with the number
  // of distinct policies and mappings the path actually names, so a path reaches the cap by naming
  // that many policies rather than by being long: the fan-out chains above walk past the depth the
  // tree could not survive and never come near it.
  check("29. the node cap is still published", pki.C.LIMITS.PATH_MAX_POLICY_NODES === 4096);
  var tiny = await validate(await fanOutChain(4, 3), { maxPolicyNodes: 4 });
  check("30. a caller may tighten it, and the refusal keeps its frozen code",
    tiny.valid === false && codesOf(tiny).indexOf("path/policy-tree-cap") !== -1);
  var ample = await validate(await fanOutChain(4, 3));
  check("31. CONTROL: the same chain under the default cap validates", ample.valid === true);

  // The default cap is still reachable, by a certificate that names that many policies. This is
  // what the cap now measures, and it is worth pinning so the claim is not read as "unreachable".
  var k = await keys();
  var pols = [];
  for (var j = 0; j < 4096; j++) pols.push({ oid: "1.3.6.1.4.1.99999.2." + j });
  var wide = await chainOf(1,
    { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
    function () { return { basicConstraints: { cA: false }, certificatePolicies: pols }; });
  void k;
  var wideRes = await validate(wide);
  check("32. a certificate naming more policies than the cap still fails closed",
    wideRes.valid === false && codesOf(wideRes).indexOf("path/policy-tree-cap") !== -1);
  var raised = await validate(wide, { maxPolicyNodes: 5000 });
  check("33. ...and raising the cap to fit them validates it, one node per policy plus the root",
    raised.valid === true && allNodes(graphOf(raised)).length === 4097);
}

async function run() {
  await testAConformingChainTheTreeRefused();
  await testTheGraphInvariantsHold();
  await testStepD1JoinsParentsRatherThanMultiplying();
  await testStepD1iiAndD2UseTheAnyPolicyNode();
  await testStepD2MakesOneNodePerExpectedPolicy();
  await testPolicyMappingSteps();
  await testTheWrapUpReadsTheGraphNotTheLeaves();
  await testTheNodeCapRemains();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
