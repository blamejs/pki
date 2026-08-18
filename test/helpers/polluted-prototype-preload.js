// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A preload that plants recognized OPTION NAMES on Object.prototype before anything is required,
 * for tests that spawn a suite under `node -r`.
 *
 * The plant has to precede the require: the guard snapshots what a clean Object.prototype holds
 * as it loads, and a table consulted by truthiness answers for an inherited name from the first
 * read onward. Both are decided at load, so a plant applied afterwards tests neither.
 *
 * `softFail` is a RECOGNIZED option of the verb under test, on purpose. An unrecognized name is
 * refused outright, which is fail-closed and settles nothing; and on a bag that does not mention
 * the name at all, an inherited value is what `opts.softFail` genuinely answers, so honoring it
 * is correct rather than a defect. The case that needs pinning is the one in between: the caller
 * states their OWN value, and it has to win over the planted one.
 *
 * `softFail` decides whether an undetermined revocation result passes, so a caller who writes
 * `softFail: false` and gets the planted `true` receives a valid path they had asked it to refuse.
 *
 * Non-enumerable, because that is the shape a real pollution takes and the shape that walks past
 * an `Object.keys` reading of the same object.
 */
// `maxDepth` is the other half of the same question. It is BUILD-ONLY, so it is deliberately
// excluded from the set forwarded to validate; a bag that could still inherit it would hand
// validate a name validate does not accept, and the build would fail on a runtime carrying it.
["softFail", "maxDepth"].forEach(function (name) {
  Object.defineProperty(Object.prototype, name, {
    value: name === "maxDepth" ? 5 : true, writable: true, configurable: true, enumerable: false
  });
});
