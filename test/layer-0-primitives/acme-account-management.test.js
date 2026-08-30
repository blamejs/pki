// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.acme.client account management: updateAccount (RFC 8555 sec. 7.3.2) + listOrders
 * (sec. 7.1.2.1). Driven through the shipped consumer path (pki.acme.client(...).updateAccount / .listOrders)
 * over the routing fake transport (no socket). updateAccount refuses the server-ignored fields at the door
 * (status / termsOfServiceAgreed / orders / externalAccountBinding) rather than emit a silently-dropped
 * payload; listOrders follows the sec. 7.1.2.1 `Link: rel="next"` pagination bounded by a page cap and an
 * origin gate (the untrusted header steers an account-key-signed POST-as-GET, so it is confined to the
 * orders URL's origin, deduped against loops, and capped against fetch amplification).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var A = require("../helpers/acme-transport");

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }
function jwsProtected(bodyStr) { return JSON.parse(Buffer.from(JSON.parse(bodyStr).protected, "base64").toString("latin1")); }
function jwsPayload(bodyStr) { var p = JSON.parse(bodyStr).payload; return p === "" ? "" : JSON.parse(Buffer.from(p, "base64").toString("latin1")); }
function postsTo(s, path) { return s.calls.filter(function (c) { return c.method === "POST" && new URL(c.url).pathname === path; }).length; }
function fetchedOrigin(s, origin) { return s.calls.some(function (c) { return new URL(c.url).origin === origin; }); }

var ACCT;
var ACCT_URL = A.URLS.base + "/acct/1";
var ORDERS_URL = A.URLS.base + "/acct/1/orders";
var U1 = A.URLS.base + "/order/1", U2 = A.URLS.base + "/order/2", U3 = A.URLS.base + "/order/3";

async function mkClient(serverOpts, extra, noAccount) {
  var s = A.acmeServer(serverOpts || {});
  var acme = pki.acme.client(A.URLS.directory, A.clientOpts(ACCT, s, extra));
  if (!noAccount) await acme.newAccount({});   // sets kid = /acct/1
  return { acme: acme, s: s };
}

async function run() {
  ACCT = await A.makeAccount();

  // ================= updateAccount (RFC 8555 sec. 7.3.2) =================

  // 1. accept: a kid-signed POST to the account URL with payload exactly { contact: [...] }.
  var c1 = await mkClient({ accountAfter: { status: "valid", contact: ["mailto:new@example.org"] } });
  var acct1 = await c1.acme.updateAccount({ contact: ["mailto:new@example.org"] });
  var post1 = c1.s.calls.filter(function (c) { return c.method === "POST" && new URL(c.url).pathname === "/acct/1"; }).pop();
  var prot1 = jwsProtected(post1.body), pay1 = jwsPayload(post1.body);
  check("1. updateAccount posts a kid-signed JWS to the account URL", prot1.url === ACCT_URL && typeof prot1.kid === "string" && prot1.kid === ACCT_URL);
  check("1a. the payload is exactly { contact: [...] } and nothing else", JSON.stringify(pay1) === JSON.stringify({ contact: ["mailto:new@example.org"] }));
  check("1b. it returns the validated account object", acct1.status === "valid" && acct1.contact[0] === "mailto:new@example.org");

  // 2. contact hygiene: a bad mailto is refused.
  var c2 = await mkClient({ accountAfter: { status: "valid" } });
  check("2. a bad mailto contact -> acme/bad-contact", (await codeOf(c2.acme.updateAccount({ contact: ["mailto:a@b?subject=x"] }))) === "acme/bad-contact");
  check("2a. a two-@ mailto -> acme/bad-contact", (await codeOf(c2.acme.updateAccount({ contact: ["mailto:a@b@c"] }))) === "acme/bad-contact");

  // 3. refuse the server-ignored / wrong-verb fields at the door (no POST emitted).
  var c3 = await mkClient({ accountAfter: { status: "valid" } });
  var before3 = postsTo(c3.s, "/acct/1");
  check("3. updateAccount({status}) -> acme/bad-input", (await codeOf(c3.acme.updateAccount({ status: "deactivated" }))) === "acme/bad-input");
  check("3a. updateAccount({termsOfServiceAgreed}) -> acme/bad-input", (await codeOf(c3.acme.updateAccount({ termsOfServiceAgreed: true }))) === "acme/bad-input");
  check("3b. updateAccount({orders}) -> acme/bad-input", (await codeOf(c3.acme.updateAccount({ orders: ORDERS_URL }))) === "acme/bad-input");
  check("3c. updateAccount({externalAccountBinding}) -> acme/bad-input", (await codeOf(c3.acme.updateAccount({ externalAccountBinding: {} }))) === "acme/bad-input");
  check("3d. NO POST to the account URL was emitted for the refused fields (the gate ran before the network)", postsTo(c3.s, "/acct/1") === before3);

  // 4. no account: updateAccount before newAccount.
  var c4 = await mkClient({}, undefined, true);
  check("4. updateAccount before newAccount -> acme/no-account", (await codeOf(c4.acme.updateAccount({ contact: ["mailto:x@example.org"] }))) === "acme/no-account");

  // 5. near-miss option.
  var c5 = await mkClient({ accountAfter: { status: "valid" } });
  check("5. updateAccount({contactz}) -> acme/bad-input", (await codeOf(c5.acme.updateAccount({ contactz: ["mailto:x@example.org"] }))) === "acme/bad-input");

  // 6. non-200 / problem: the ToS-changed path is a server problem, not a re-agreement; a 202 is unexpected.
  var c6 = await mkClient({ problemOn: { "/acct/1": A.problem(403, "userActionRequired", "the terms of service have changed") } });
  check("6. a 403 userActionRequired -> acme/server-problem (ToS change is not a client update)", (await codeOf(c6.acme.updateAccount({ contact: ["mailto:x@example.org"] }))) === "acme/server-problem");
  var c6b = await mkClient({ problemOn: { "/acct/1": A.json(202, { status: "valid" }) } });
  check("6a. a 202 (not 200) -> acme/unexpected-status", (await codeOf(c6b.acme.updateAccount({ contact: ["mailto:x@example.org"] }))) === "acme/unexpected-status");

  // 7. empty contact clears contacts.
  var c7 = await mkClient({ accountAfter: { status: "valid" } });
  await c7.acme.updateAccount({ contact: [] });
  var post7 = c7.s.calls.filter(function (c) { return c.method === "POST" && new URL(c.url).pathname === "/acct/1"; }).pop();
  check("7. updateAccount({contact:[]}) posts { contact: [] } (clears contacts)", JSON.stringify(jwsPayload(post7.body)) === JSON.stringify({ contact: [] }));

  // 8. the message-layer builder pki.acme.updateAccount is usable without the stateful client.
  var jwsUpd = await pki.acme.updateAccount({ key: ACCT.key, alg: "ES256", nonce: "oFvnlFP1wIhRlYS2jTaXbA", url: ACCT_URL, kid: ACCT_URL, contact: ["mailto:x@example.org"] });
  check("8. pki.acme.updateAccount builds a JWS carrying { contact }", JSON.stringify(JSON.parse(Buffer.from(jwsUpd.payload, "base64").toString("latin1"))) === JSON.stringify({ contact: ["mailto:x@example.org"] }));
  check("8a. pki.acme.updateAccount() with no options fails closed", (await codeOf(pki.acme.updateAccount())) === "acme/bad-input");
  check("8b. pki.acme.updateAccount with a bad contact -> acme/bad-contact", (await codeOf(pki.acme.updateAccount({ key: ACCT.key, alg: "ES256", nonce: "oFvnlFP1wIhRlYS2jTaXbA", url: ACCT_URL, kid: ACCT_URL, contact: ["mailto:a@b?x=1"] }))) === "acme/bad-contact");

  // ================= listOrders (RFC 8555 sec. 7.1.2.1) =================

  // 1. accept: a POST-as-GET (empty payload) to the orders URL returns the aggregated list.
  var l1 = await mkClient({ ordersByUrl: { "/acct/1/orders": { orders: [U1, U2] } } });
  var r1 = await l1.acme.listOrders(ORDERS_URL);
  check("L1. listOrders returns { orders, pages: 1, truncated: false }", JSON.stringify(r1.orders) === JSON.stringify([U1, U2]) && r1.pages === 1 && r1.truncated === false);
  var opost = l1.s.calls.filter(function (c) { return c.method === "POST" && new URL(c.url).pathname === "/acct/1/orders"; }).pop();
  check("L1a. the request was a POST-as-GET (empty JWS payload) to the orders URL", jwsPayload(opost.body) === "" && jwsProtected(opost.body).kid === ACCT_URL);

  // 2. shape faults.
  var l2 = await mkClient({ ordersByUrl: { "/acct/1/orders": { body: { orders: "not-an-array" } } } });
  check("L2. { orders: <non-array> } -> acme/bad-orders-list", (await codeOf(l2.acme.listOrders(ORDERS_URL))) === "acme/bad-orders-list");
  var l2b = await mkClient({ ordersByUrl: { "/acct/1/orders": { body: { orders: ["not a url"] } } } });
  check("L2a. a non-URL order element -> acme/bad-orders-list", (await codeOf(l2b.acme.listOrders(ORDERS_URL))) === "acme/bad-orders-list");
  var l2c = await mkClient({ ordersByUrl: { "/acct/1/orders": { body: { foo: 1 } } } });
  check("L2b. a missing orders field -> acme/missing-field", (await codeOf(l2c.acme.listOrders(ORDERS_URL))) === "acme/missing-field");

  // 3. pagination: page1 rel="next" -> page2; aggregate.
  var l3 = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1, U2], link: "<" + ORDERS_URL + "?cursor=2>;rel=\"next\"" },
    "/acct/1/orders?cursor=2": { orders: [U3] },
  } });
  var r3 = await l3.acme.listOrders(ORDERS_URL);
  check("L3. rel=next pagination aggregates across pages", JSON.stringify(r3.orders) === JSON.stringify([U1, U2, U3]) && r3.pages === 2 && r3.truncated === false);

  // 4. SSRF: an off-origin next is refused and never fetched.
  var l4 = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<https://evil.example/acct/1/orders?cursor=2>;rel=\"next\"" },
  } });
  check("L4. an off-origin rel=next -> acme/bad-link (SSRF guard)", (await codeOf(l4.acme.listOrders(ORDERS_URL))) === "acme/bad-link");
  check("L4a. the off-origin page was never fetched", fetchedOrigin(l4.s, "https://evil.example") === false);

  // 5. loop + cap.
  var l5 = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<" + ORDERS_URL + "?cursor=2>;rel=\"next\"" },
    "/acct/1/orders?cursor=2": { orders: [U2], link: "<" + ORDERS_URL + "?cursor=3>;rel=\"next\"" },
    "/acct/1/orders?cursor=3": { orders: [U3], link: "<" + ORDERS_URL + "?cursor=4>;rel=\"next\"" },
  } });
  var r5 = await l5.acme.listOrders(ORDERS_URL, { maxPages: 2 });
  check("L5. a next chain longer than maxPages stops with truncated: true", r5.pages === 2 && r5.truncated === true && r5.orders.length === 2);
  var l5b = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<" + ORDERS_URL + ">;rel=\"next\"" },   // next points back to itself
  } });
  var r5b = await l5b.acme.listOrders(ORDERS_URL);
  check("L5a. a next pointing back to a visited page stops (no infinite loop)", r5b.pages === 1 && r5b.truncated === false);
  var l5c = await mkClient({ ordersByUrl: { "/acct/1/orders": { orders: [U1] } } });
  check("L5b. listOrders({maxPagesz}) -> acme/bad-input", (await codeOf(l5c.acme.listOrders(ORDERS_URL, { maxPagesz: 2 }))) === "acme/bad-input");
  var l5d = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<" + ORDERS_URL + "?cursor=2>;rel=\"next\"" },
    "/acct/1/orders?cursor=2": { orders: [U2], link: "<" + ORDERS_URL + ">;rel=\"next\"" },   // a next back to the first (visited) page
  } });
  var r5d = await l5d.acme.listOrders(ORDERS_URL);
  check("L5c. a next back to an earlier visited page stops the loop (2-cycle)", r5d.pages === 2 && r5d.truncated === false && JSON.stringify(r5d.orders) === JSON.stringify([U1, U2]));
  // A cycle back to a visited page that lands EXACTLY on the page cap is NOT truncated: the list is
  // complete (the next names nothing new), so the visited check must run before the cap decision.
  var l5e = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<" + ORDERS_URL + "?cursor=2>;rel=\"next\"" },
    "/acct/1/orders?cursor=2": { orders: [U2], link: "<" + ORDERS_URL + ">;rel=\"next\"" },
  } });
  var r5e = await l5e.acme.listOrders(ORDERS_URL, { maxPages: 2 });
  check("L5d. a cycle back to a visited page at the cap is complete, not truncated", r5e.pages === 2 && r5e.truncated === false && JSON.stringify(r5e.orders) === JSON.stringify([U1, U2]));

  // 6. https gate.
  var l6 = await mkClient({ ordersByUrl: { "/acct/1/orders": { orders: [U1] } } });
  check("L6. a non-https orders URL -> acme/insecure-url (rejection, not sync throw)", (await codeOf(l6.acme.listOrders("http://acme.example/acct/1/orders"))) === "acme/insecure-url");
  var l6b = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<http://acme.example/acct/1/orders?cursor=2>;rel=\"next\"" },
  } });
  check("L6a. a non-https rel=next -> acme/bad-link", (await codeOf(l6b.acme.listOrders(ORDERS_URL))) === "acme/bad-link");

  // 7. malformed next Link.
  var l7 = await mkClient({ ordersByUrl: { "/acct/1/orders": { orders: [U1], link: "not-a-link-value;rel=\"next\"" } } });
  check("L7. a malformed next Link value -> acme/bad-link", (await codeOf(l7.acme.listOrders(ORDERS_URL))) === "acme/bad-link");
  var l7b = await mkClient({ ordersByUrl: {
    "/acct/1/orders": { orders: [U1], link: "<" + ORDERS_URL + "?cursor=2>;rel=\"next\", <" + ORDERS_URL + "?cursor=9>;rel=\"next\"" },
  } });
  check("L7a. two distinct rel=next targets (RFC 8288 singleton) -> acme/bad-link", (await codeOf(l7b.acme.listOrders(ORDERS_URL))) === "acme/bad-link");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
