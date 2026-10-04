'use strict';
/*
 * jssinkguard.js — a dependency-free dynamic sink sanitizer for the synthesized Node harness.
 *
 * This is the JavaScript mirror of raksha/harness/sinkguard.py. A command injection in Node does
 * not crash — it quietly runs the injected command, so a fuzzer that only watches for thrown
 * exceptions never sees it. Jazzer.js solves this with sanitizer hooks, but Jazzer.js needs a
 * network install; this is the honest, built-ins-only version of the same idea for a sealed node:
 * monkeypatch the dangerous shell / eval / code-loading sinks BEFORE the target is loaded, so a
 * call carrying injected shell metacharacters is REPORTED (in a banner the JsSinkOracle parses) and
 * BLOCKED rather than executed. Blocking matters — we feed adversarial input and will not actually
 * run `rm -rf` to prove a sink was reachable.
 *
 * (The richer "take-lane" alternative is Jazzer.js with its command-injection sanitizer; when its
 * runtime is bundled on the node it plugs in behind the same oracle banner. It is NOT used here
 * because it requires `npm install`, which this environment forbids.)
 *
 * It fires only when a shell metacharacter that the UNTRUSTED input introduced reaches a shell
 * sink, so a benign input (no injected metacharacter, e.g. "10m") passes untouched — which is
 * exactly what the harness quality gate needs.
 *
 * Harness contract (mirrors the Python harness): `node jssinkguard.js <input-file>` reads the input
 * bytes, installs the guard, requires the target module named by RAKSHA_JS_MODULE, and calls the
 * entry point named by RAKSHA_JS_SYMBOL with the input as its single string argument. The target's
 * return value is written to stdout (so the gate's differential check compares real behaviour).
 */

const fs = require('fs');
const path = require('path');
const child_process = require('child_process');
const vm = require('vm');

// Shell metacharacters that turn a string argument into additional commands. `$(` is matched as a
// two-char token; a bare `$` without it (e.g. "${x}") is left to the plainer metacharacters.
const SHELL_META = [';', '|', '&', '`', '$(', '\n', '>', '<'];

// The current untrusted input for this run. A metacharacter that appears in BOTH the input and the
// shell command string is one the input introduced — the command-injection signature.
let TAINT = '';

function asCommandString(arg) {
  if (typeof arg === 'string') return arg;
  if (Array.isArray(arg)) return arg.join(' ');
  return String(arg == null ? '' : arg);
}

// Returns the injected metacharacter (or null). A sink reached with the untrusted input present but
// unquoted also counts — close to PySecSan's command-injection semantics.
function injectedMeta(cmd) {
  const s = asCommandString(cmd);
  for (const m of SHELL_META) {
    if (s.includes(m) && TAINT.includes(m)) return m;
  }
  if (TAINT && s.includes(TAINT)) {
    for (const m of SHELL_META) {
      if (TAINT.includes(m)) return m;
    }
  }
  return null;
}

// true when a child_process call runs through a shell. exec/execSync are always shell; spawn/
// spawnSync are a shell only with {shell: true} (or a shell string as the command).
function usesShell(name, args) {
  if (name === 'exec' || name === 'execSync') return true;
  const opts = args.length >= 2 && args[args.length - 1] && typeof args[args.length - 1] === 'object'
    ? args[args.length - 1] : (args.length >= 2 && typeof args[1] === 'object' ? args[1] : null);
  return !!(opts && opts.shell);
}

function callSiteFrame() {
  // Parse the first stack frame that belongs to the target rather than to this guard or a Node
  // internal, and render its path relative to cwd (the target root) so the fix site and a repair
  // diff share the path the gate applies against.
  const stack = (new Error().stack || '').split('\n').slice(1);
  const FRAME = /^\s*at\s+(?:(?<sym>[^\s(]+)\s+\()?(?<file>[^():]+):(?<line>\d+):\d+\)?/;
  for (const line of stack) {
    const m = line.match(FRAME);
    if (!m) continue;
    const file = m.groups.file;
    if (!file || file.startsWith('node:') || file.includes('jssinkguard.js') || file.includes('internal/')) {
      continue;
    }
    let rel = file;
    try { rel = path.relative(process.cwd(), file) || file; } catch (e) { /* keep absolute */ }
    const sym = m.groups.sym || '<anonymous>';
    return `  at ${sym} (${rel}:${m.groups.line})`;
  }
  return '  at <unknown> (<unknown>:0)';
}

function report(sink) {
  // Banner format the JsSinkOracle parses, plus a target-owned call-site frame. Then exit 99
  // (non-zero) WITHOUT running the sink — the harness reports a crash; nothing executed.
  process.stderr.write(
    '=== BUG DETECTED: JsSec: command injection ===\n' +
    'JsSec: command injection detected in ' + sink + '\n' +
    callSiteFrame() + '\n');
  process.exit(99);
}

function install() {
  if (install._done) return;
  install._done = true;

  for (const name of ['exec', 'execSync', 'spawn', 'spawnSync']) {
    const original = child_process[name];
    if (typeof original !== 'function') continue;
    child_process[name] = function (...args) {
      if (usesShell(name, args) && injectedMeta(args[0]) !== null) {
        report('child_process.' + name);
      }
      return original.apply(this, args);
    };
  }

  // `new Function(body)` — arbitrary code construction from a string.
  const OriginalFunction = global.Function;
  function GuardedFunction(...args) {
    const body = args.length ? String(args[args.length - 1]) : '';
    if (injectedMeta(body) !== null || /\b(require|process|child_process|global)\b/.test(body) && TAINT && body.includes(TAINT)) {
      report('new Function');
    }
    return OriginalFunction.apply(this, args);
  }
  GuardedFunction.prototype = OriginalFunction.prototype;
  try { global.Function = GuardedFunction; } catch (e) { /* non-writable in some runtimes */ }

  // global.eval — indirect eval of a constructed string.
  const originalEval = global.eval;
  if (typeof originalEval === 'function') {
    global.eval = function (code) {
      if (typeof code === 'string' && TAINT && code.includes(TAINT)
          && (injectedMeta(code) !== null || /\b(require|process|global)\b/.test(code))) {
        report('eval');
      }
      return originalEval(code);
    };
  }

  // vm.runInNewContext / vm.runInThisContext — code loading sinks.
  for (const name of ['runInNewContext', 'runInThisContext']) {
    const original = vm[name];
    if (typeof original !== 'function') continue;
    vm[name] = function (code, ...rest) {
      if (typeof code === 'string' && TAINT && code.includes(TAINT)) {
        report('vm.' + name);
      }
      return original.call(this, code, ...rest);
    };
  }
}

function main() {
  const inputFile = process.argv[2];
  if (!inputFile) {
    process.stderr.write('usage: node jssinkguard.js <input-file>\n');
    process.exit(2);
  }
  let data = '';
  try {
    data = fs.readFileSync(inputFile, 'utf8');
  } catch (e) {
    process.exit(0);                 // no input: nothing to drive; a clean no-op, not a crash
  }
  TAINT = data;

  install();                         // install the sink oracle BEFORE the target loads

  const moduleSpec = process.env.RAKSHA_JS_MODULE;
  const symbol = process.env.RAKSHA_JS_SYMBOL;
  if (!moduleSpec || !symbol) {
    process.stderr.write('jssinkguard: set RAKSHA_JS_MODULE and RAKSHA_JS_SYMBOL\n');
    process.exit(2);
  }
  const resolved = moduleSpec.startsWith('.') || moduleSpec.startsWith('/')
    ? path.resolve(process.cwd(), moduleSpec)
    : moduleSpec;

  let mod;
  try {
    mod = require(resolved);
  } catch (e) {
    // A load error is a harness failure on a benign input, not a bug in the target's sink. Exit 0
    // so the quality gate rejects the harness rather than the fuzzer logging a false crash.
    process.stderr.write('jssinkguard: cannot load target: ' + (e && e.message) + '\n');
    process.exit(0);
  }
  // Accept `module.exports = { name }`, `exports.name = ...`, or `module.exports = fn`.
  let fn = mod && typeof mod[symbol] === 'function' ? mod[symbol]
         : (typeof mod === 'function' ? mod : null);
  if (typeof fn !== 'function') {
    process.stderr.write('jssinkguard: entry point ' + symbol + ' not found\n');
    process.exit(0);
  }

  try {
    const out = fn(data);            // a shell sink carrying injected metacharacters aborts here (exit 99)
    if (out !== undefined && out !== null) {
      process.stdout.write(String(out));
    }
    process.exit(0);
  } catch (e) {
    // The target itself threw on this input. Not a sink detection; let the one-shot replay / gate
    // treat a non-zero exit as a plain error (the differential check handles baseline behaviour).
    process.stderr.write(String((e && e.stack) || e) + '\n');
    process.exit(1);
  }
}

main();
