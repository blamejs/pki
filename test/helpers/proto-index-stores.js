// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Counts stores at `Array.prototype` indexes while an operation runs.
 *
 * A fresh array has no own property at any index, so `arr[i] = v` and `arr.push(v)` are [[Set]]s
 * that walk the prototype chain looking for a setter. An accessor at an array index therefore
 * receives each element as it is appended and can answer with something else when the index is read
 * back. Appending with `defineProperty` creates the own slot outright and consults no setter.
 *
 * The setter installed here DEFINES the own property the store was meant to create, so no element is
 * lost and the operation under test runs to its normal result: the only thing measured is whether a
 * store happened at all. That is what makes the accessor safe to leave installed across an await,
 * node's own internals included.
 *
 * `countIndexStores(upTo, fn)` returns `{ stores, value }` -- the number of stores seen at indexes
 * 0 .. upTo-1, and whatever `fn` returned (awaited when it is a promise). The accessors are removed
 * before it returns, including when `fn` throws.
 */

function _install(upTo, onStore) {
  for (var i = 0; i < upTo; i++) {
    Object.defineProperty(Array.prototype, String(i), {
      configurable: true,
      get: function () { return undefined; },
      set: (function (index) {
        return function (v) {
          onStore(index);
          Object.defineProperty(this, index, { value: v, writable: true, enumerable: true, configurable: true });
        };
      })(i),
    });
  }
}

function _remove(upTo) {
  for (var i = 0; i < upTo; i++) delete Array.prototype[String(i)];
}

async function countIndexStores(upTo, fn) {
  var stores = 0;
  var seen = [];
  function onStore(index) { stores += 1; if (seen.length < 8) Object.defineProperty(seen, seen.length, { value: index, writable: true, enumerable: true, configurable: true }); }
  var value;
  _install(upTo, onStore);
  try { value = await fn(); }
  finally { _remove(upTo); }
  return { stores: stores, indexes: seen, value: value };
}

module.exports = { countIndexStores: countIndexStores };
