// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A preload that interferes with one file at the instant its descriptor is closed, for tests that
 * spawn the CLI under `node -r`.
 *
 * The CLI creates a file through an exclusive descriptor, records what it wrote so its exit handler
 * can tell its own file from one that replaced it, and closes the descriptor. A writer that reaches
 * the path between the close and the cleanup is the case that record exists for, and the window is
 * too narrow to hit from a sibling process. This widens nothing: it acts at the close, which is where
 * the window opens.
 *
 * `PKI_SWAP_PATH` names the file to act on. The descriptor being closed is matched to it by inode, so
 * a close of any other file is passed straight through. Where the platform reports no inode the action
 * cannot be aimed, and the preload says so on stderr instead of acting on the wrong file.
 *
 * `PKI_SWAP_MODE` picks what happens:
 *
 *   - `replace` (the default) deletes the file and writes a new one carrying the SAME bytes and the
 *     SAME timestamps, so a record taken by path after the close reads as unchanged. Only the inode
 *     differs, which is what tells one file from another.
 *   - `link` leaves the file alone and adds a second name for its content, so unlinking the original
 *     name would remove the name and keep the bytes.
 *   - `linkshrink` adds two names before the content is written and removes one at the close, so the
 *     link count a record taken mid-write holds is HIGHER than the count at cleanup. A comparison
 *     looking for growth sees none and lets the unlink through while a second name still holds the
 *     bytes.
 *   - `statfail` makes the path unstattable after the close, which is not the same as the file being
 *     gone.
 *   - `rename` moves the file to another name, so the path is empty while the content this run wrote
 *     is still somewhere.
 *
 * `PKI_FAIL_WRITE` names a file whose content write fails, which is the other way a record ends up
 * with no size: the descriptor was created and the bytes never went in. Descriptors are mapped back
 * to their paths through `openSync`, since the content is written through the descriptor alone.
 */

var fs = require("node:fs");

var target = process.env.PKI_SWAP_PATH;
var mode = process.env.PKI_SWAP_MODE || "replace";
var failWrite = process.env.PKI_FAIL_WRITE;

/**
 * `PKI_TOCTOU_PATH` forces the window between "this path is taken" and "this path is free". The first
 * exclusive create of that path answers EEXIST as though something were there, the open that follows
 * answers ENOENT as though it had just gone, and every later call is real. A writer that treats the
 * second answer as permission to create by name makes a file nobody is tracking.
 */
var toctou = process.env.PKI_TOCTOU_PATH;
var toctouStep = 0;

var realOpen = fs.openSync;
var realWrite = fs.writeFileSync;
var realClose = fs.closeSync;
var realStat = fs.statSync;
var pathOfFd = Object.create(null);
var acted = false;
var blockStat = false;

fs.statSync = function (file, options) {
  if (blockStat && String(file) === target) {
    var e = new Error("EACCES: permission denied, stat '" + target + "'");
    e.code = "EACCES";
    throw e;
  }
  return realStat.call(fs, file, options);
};

fs.openSync = function (file, flags, modeArg) {
  if (toctou && String(file) === toctou && toctouStep < 2) {
    toctouStep++;
    var forced = new Error(toctouStep === 1
      ? "EEXIST: file already exists, open '" + toctou + "'"
      : "ENOENT: no such file or directory, open '" + toctou + "'");
    forced.code = toctouStep === 1 ? "EEXIST" : "ENOENT";
    process.stderr.write("swap-preload: forced " + forced.code + " on open " + String(flags) + "\n");
    throw forced;
  }
  var fd = realOpen.call(fs, file, flags, modeArg);
  if (typeof fd === "number") pathOfFd[String(fd)] = String(file);
  return fd;
};

fs.writeFileSync = function (file, data, options) {
  if (failWrite && typeof file === "number" && pathOfFd[String(file)] === failWrite) {
    var e = new Error("ENOSPC: no space left on device, write");
    e.code = "ENOSPC";
    throw e;
  }
  // Between the claim and the seal, which is where a link count recorded mid-write is taken.
  if (mode === "linkshrink" && !acted && typeof file === "number" &&
      pathOfFd[String(file)] === target) {
    fs.linkSync(target, target + ".one");
    fs.linkSync(target, target + ".two");
  }
  return realWrite.call(fs, file, data, options);
};

fs.closeSync = function (fd) {
  var before = null;
  if (!acted && target) {
    try { before = fs.fstatSync(fd); } catch (_e) { before = null; }
  }
  var out = realClose.call(fs, fd);
  delete pathOfFd[String(fd)];
  if (acted || !target || before === null) return out;
  if (before.ino === 0) {
    acted = true;
    process.stderr.write("swap-preload: this platform reports no inode; nothing done\n");
    return out;
  }
  if (!fs.existsSync(target)) return out;
  var atPath = fs.statSync(target);
  if (atPath.ino !== before.ino || atPath.dev !== before.dev) return out;
  acted = true;
  if (mode === "link") {
    fs.linkSync(target, target + ".link");
    process.stderr.write("swap-preload: linked " + target + " at close\n");
    return out;
  }
  if (mode === "linkshrink") {
    fs.unlinkSync(target + ".two");
    process.stderr.write("swap-preload: link count for " + target + " went to " +
      realStat.call(fs, target).nlink + " at close\n");
    return out;
  }
  if (mode === "statfail") {
    blockStat = true;
    process.stderr.write("swap-preload: " + target + " is unstattable from the close on\n");
    return out;
  }
  if (mode === "rename") {
    fs.renameSync(target, target + ".moved");
    process.stderr.write("swap-preload: moved " + target + " away at close\n");
    return out;
  }
  var bytes = fs.readFileSync(target);
  fs.unlinkSync(target);
  fs.writeFileSync(target, bytes);
  fs.utimesSync(target, atPath.atime, atPath.mtime);
  process.stderr.write("swap-preload: replaced " + target + " at close\n");
  return out;
};
