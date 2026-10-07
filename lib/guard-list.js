// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _freeze = require("./guard-intrinsic").freeze;
var _defineProperty = require("./guard-intrinsic").defineProperty;
var _isArray = require("./guard-intrinsic").isArray;
var _arrSort = require("./guard-intrinsic").sort;
var _isSafeInteger = require("./guard-intrinsic").isSafeInteger;
var _hasOwn = require("./guard-intrinsic").hasOwn;

var MAX_ARRAY_LENGTH = 4294967295;

/** @internal The receiver's length, NARROWED to a number rather than merely captured. `Array.isArray`
 * is true for a Proxy whose target is an array, and a `get` trap can answer `length` with an OBJECT:
 * capturing an object captures no value, so every later use coerces it again and each coercion may
 * answer differently. MEASURED through `pki.merkle.root`, whose captured count was handed to the leaf
 * cap as 0 and then walked as 4, returning a four-leaf root the cap had approved as empty and clearing
 * `MERKLE_MAX_LEAVES` the same way. A length that is not already a non-negative safe integer describes
 * no array any of these walks can take, so it is refused rather than coerced. Every walk below takes
 * its count from here, so none of them can hold a value that changes between two reads.
 *
 * Exported, because the walks in `guard-bytes` and `guard-identifier` take a caller's list too, and one
 * of them is a DOOR: a Proxy over `["a", "secret"]` whose length coerced to 2 and then to 0 walked
 * `refuseAccessorFields` past the accessor named `secret` and returned as though it had checked it. A
 * door that can be walked past is not a door, so the three families share this one narrow.
 *
 * @enforced-by behavioral -- `x.length` has no rename-proof shape that separates a caller's list from
 * a local array, and the RED vectors are the shrinking and object-valued lengths each walk is driven
 * with.
 */
function _count(list, verb) {
  var n = list.length;
  if (typeof n !== "number" || !_isSafeInteger(n) || n < 0) {
    throw new TypeError("guard.list." + verb + ": the receiver's length is not a non-negative integer");
  }
  return n;
}

// @enforced-by guard-shape-reinlined
// @guard-shape defineProperty\(\s*\w+\s*,\s*\w+\.length\s*,\s*\{\s*value:
// @guard-via guard\.list\.append\(
function append(list, value) {
  if (!_isArray(list)) throw new TypeError("guard.list.append: the receiver must be an array");
  var n = _count(list, "append");
  if (n >= MAX_ARRAY_LENGTH) throw new RangeError("guard.list.append: the array is at its maximum length");
  _defineProperty(list, n, { value: value, writable: true, enumerable: true, configurable: true });
  return list;
}

// @enforced-by behavioral -- `.indexOf(x) !== -1` has no rename-proof form that separates a
function contains(list, value) {
  if (!list) return false;
  for (var i = 0, n = _count(list, "contains"); i < n; i++) if (list[i] === value) return true;
  return false;
}

// @enforced-by behavioral -- the composition of contains() has no rename-proof shape of its own;
function containsAll(list, values) {
  if (!values) return true;
  for (var i = 0, n = _count(values, "containsAll"); i < n; i++) if (!contains(list, values[i])) return false;
  return true;
}

// @enforced-by behavioral -- `.some(` has legitimate non-rule siblings (building a list, reporting
function anyMatches(list, predicate) {
  if (!list) return false;
  for (var i = 0, n = _count(list, "anyMatches"); i < n; i++) if (predicate(list[i], i)) return true;
  return false;
}

// @enforced-by behavioral -- see anyMatches; the RED vector (an untrusted signer keeps
function allMatch(list, predicate) {
  if (!list) return true;
  for (var i = 0, n = _count(list, "allMatch"); i < n; i++) if (!predicate(list[i], i)) return false;
  return true;
}

/** @internal The first element a predicate selects, or null. Written as `list.filter(p)[0]`, the
 * selection is a fresh array that is empty when nothing matched, and reading index 0 of an empty
 * array answers from the array prototype: an accessor there becomes the selected element in a
 * selection that selected nothing, which reads at every call site as "found one". `filter` also
 * builds its result through the receiver's `Symbol.species`, so the array indexed is not necessarily
 * one this toolkit made. This walks the own indexes and returns null when nothing matched, so a
 * caller's `if (!found)` test answers for the list rather than for the prototype.
 *
 * @enforced-by behavioral -- `filter(...)[0]` has no rename-proof shape of its own beyond the method
 * name, which the captured-operation budget already counts; the RED vectors are the empty-selection
 * ones each consumer carries (a signedAttrs with no message-digest attribute, a certificate with no
 * subject key identifier).
 */
function firstMatch(list, predicate) {
  if (!list) return null;
  for (var i = 0, n = _count(list, "firstMatch"); i < n; i++) {
    if (!_hasOwn(list, i)) continue;
    /** @internal One read of the element, tested and returned. Read again after the predicate, an
     * own accessor at the index answers the test with one value and the caller with another, and a
     * getter that deletes its own slot leaves the second read falling through to the prototype. */
    var element = list[i];
    if (predicate(element, i)) return element;
  }
  return null;
}

/** @internal Remove the element at `index`, shifting the ones after it down by defining each slot
 * and then truncating through the array's own `length`. `splice` is the ordinary way to write this
 * and it is not usable here: it returns the removed elements, so it builds that result through
 * `ArraySpeciesCreate`, which reads the receiver's `constructor` and then its `Symbol.species`. A
 * getter installed on `Array.prototype.constructor` receives the real array as its `this`, which
 * hands caller code a reference to the list being edited and to every record in it, in the middle of
 * the edit. Nothing is returned here, so nothing is constructed.
 *
 * @enforced-by behavioral -- `splice(i, 1)` has no rename-proof shape beyond the method name, which
 * the captured-operation budget counts; the RED vector is the policy-node removal driven with a
 * `constructor` getter installed.
 */
function removeAt(list, index) {
  if (!_isArray(list)) throw new TypeError("guard.list.removeAt: the receiver must be an array");
  var n = _count(list, "removeAt");
  if (!_isSafeInteger(index) || index < 0 || index >= n) {
    throw new RangeError("guard.list.removeAt: the index must be a position the array holds");
  }
  /** @internal A hole stays a hole, and is never read through. `splice` leaves an absent element
   * absent, so a shift that defined every slot would turn one into an own `undefined`; and reading
   * `list[i + 1]` at a hole answers from the prototype, which is the value this family exists to
   * keep out. Each source slot is tested for own-ness once and read once. */
  for (var i = index; i < n - 1; i++) {
    if (_hasOwn(list, i + 1)) {
      _defineProperty(list, i, { value: list[i + 1], writable: true, enumerable: true, configurable: true });
    } else if (_hasOwn(list, i)) {
      delete list[i];
    }
  }
  /** @internal `length` is an array's own writable property, so assigning it consults no prototype
   * and the assignment deletes the tail slot the shift left behind. */
  list.length = n - 1;
  return list;
}

// @enforced-by caller-array-copied-live
function snapshot(list) {
  if (!_isArray(list)) throw new TypeError("guard.list.snapshot: the receiver must be an array");
  var n = _count(list, "snapshot");
  var out = [];
  for (var i = 0; i < n; i++) {
    _defineProperty(out, i, { value: list[i], writable: true, enumerable: true, configurable: true });
  }
  return out;
}

/** @internal A sorted COPY, taken and ordered through the captured operations. A DER SET OF is ordered
 *  by its encoded bytes, so the sort decides the bytes emitted and the comparison decides the order:
 *  MEASURED, replacing either `Array.prototype.slice` or `Array.prototype.sort` made a certification
 *  request's attribute set encode a member other than the one that had just been validated, on a path
 *  whose output is then signed. The snapshot comes first, so the caller's array is never reordered.
 *
 * @enforced-by behavioral -- `x.slice().sort(cmp)` has no rename-proof shape of its own beyond the two
 * method names, and the conformance vector is the SET-OF ordering one each format already carries.
 */
function sortedCopy(list, compare) {
  var out = snapshot(list);
  return _arrSort(out, compare);
}

/** @internal `onCount`, where a caller passes one, is handed the count this walk will use, before any
 *  slot is read. It is how a caller caps the length WITHOUT reading it a second time. A caller that read
 *  `list.length` itself to cap it and then called this had two reads of one quantity, and they can
 *  disagree: `Array.isArray` is true for a Proxy whose target is an array, and a `get` trap answers
 *  "length" afresh each time, so MEASURED, a cap that saw 0 passed while the walk below saw 1 and the
 *  caller committed to a one-element result the cap had approved as empty. The caller keeps its own typed
 *  error and its own message; only the number is the guard's to hand over. */
// @enforced-by caller-array-copied-live
function copyMap(list, fn, onCount) {
  if (!_isArray(list)) throw new TypeError("guard.list.copyMap: the receiver must be an array");
  if (typeof fn !== "function") throw new TypeError("guard.list.copyMap: the second argument must be a function");
  if (onCount !== undefined && typeof onCount !== "function") {
    throw new TypeError("guard.list.copyMap: onCount must be a function when supplied");
  }
  var n = _count(list, "copyMap");
  if (onCount !== undefined) onCount(n);
  var out = [];
  for (var i = 0; i < n; i++) {
    _defineProperty(out, i, { value: fn(list[i], i), writable: true, enumerable: true, configurable: true });
  }
  return out;
}

module.exports = _freeze({
  count: _count,
  append: append,
  sortedCopy: sortedCopy,
  contains: contains,
  containsAll: containsAll,
  anyMatches: anyMatches,
  allMatch: allMatch,
  firstMatch: firstMatch,
  removeAt: removeAt,
  snapshot: snapshot,
  copyMap: copyMap,
});
