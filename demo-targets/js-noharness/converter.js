'use strict';
// js-noharness — a CommonJS Node target that ships NO fuzz harness.
// `convert(spec)` builds a shell command from the operator's string by concatenation and runs it
// with execSync (the SHELL form): a command injection (CWE-78). `echo` is used so the demo runs
// anywhere and a short/benign spec ("10m") echoes back harmlessly. RAKSHA discovers `convert`,
// synthesizes the jssinkguard harness, finds the injection, fixes it and proves the fix changes
// nothing for legitimate input.
const { execSync } = require('child_process');

function convert(spec) {
  return execSync('echo converting: ' + spec).toString();   // BUG: input interpolated into a shell line
}

module.exports = { convert };
