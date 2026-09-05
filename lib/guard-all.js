// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _freeze = require("./guard-intrinsic").freeze;
var bytes  = require("./guard-bytes");
var text   = require("./guard-text");
var limits = require("./guard-limits");
var crypto = require("./guard-crypto");
var list = require("./guard-list");
var range  = require("./guard-range");
var time   = require("./guard-time");
var name   = require("./guard-name");
var encoding = require("./guard-encoding");
var der = require("./guard-der");
var json   = require("./guard-json");
var identifier = require("./guard-identifier");
var header = require("./guard-header");
var compress = require("./guard-compress");
var secret = require("./guard-secret");
var parsed = require("./guard-parsed");
var verdict = require("./guard-verdict");
var async_ = require("./guard-async");

module.exports = _freeze({
  bytes:  bytes,
  text:   text,
  limits: limits,
  crypto: crypto,
  list: list,
  range:  range,
  time:   time,
  name:   name,
  encoding: encoding,
  der:    der,
  json:   json,
  identifier: identifier,
  header: header,
  compress: compress,
  secret: secret,
  parsed: parsed,
  verdict: verdict,
  async:  async_,
});
