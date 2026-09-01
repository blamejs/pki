// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// validator via @validator-shape) is flagged, so a new format module cannot re-derive a

var cose = require("./validator-cose");
var sig = require("./validator-sig");
var attcert = require("./validator-attcert");
var keydesc = require("./validator-keydesc");
var tpm = require("./validator-tpm");
var tls = require("./validator-tls");

module.exports = {
  cose: cose,
  sig: sig,
  attcert: attcert,
  keydesc: keydesc,
  tpm: tpm,
  tls: tls,
};
