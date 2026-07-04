// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// nav — thin re-export of the navigation derived from site.config.js.
// Single source of truth for nav + curation: site.config.js, which in
// turn derives every entry from the @module blocks in lib/.

var site = require("../site.config");

module.exports = {
  NAV_GROUPS:   site.navGroups(),
  groupForPath: site.groupForPath,
};
