#!/usr/bin/env node
// specter-guard: check the lockfile before `npm install`.
//
//   specter-guard npm install <pkg> [npm flags] [guard flags]
//
// Resolves the dependency tree WITHOUT running any package code
// (`npm install --package-lock-only --ignore-scripts`), sends the lockfile to
// the Specter check API, and only runs the real install if it passes.
// Zero dependencies; needs Node 18+ (built-in fetch). npm only.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const DEFAULT_API_URL = 'https://specter-seven.vercel.app';
const EXIT = { OK: 0, BLOCKED: 1, ERROR: 2 };
const MAX_ROUNDS = 6; // re-asks while the API still reports `pending` packages
const ROUND_WAIT_MS = 3000;

const HELP = `specter-guard — check the lockfile before \`npm install\`

Usage
  specter-guard npm install [packages...] [npm flags] [options]
  specter-guard npm ci [options]
  (the word "npm" is optional: \`specter-guard install lodash\` works too)

Options
  --warn-only          Report problems but never stop the install
  --allow <pkg@ver>    Accept one specific version (repeatable), e.g. --allow lodash@4.17.21
  --json               Print the report as JSON on stdout (npm output goes to stderr)
  --api-url <url>      Check API base URL (default: $SPECTER_API_URL or ${DEFAULT_API_URL})
  -h, --help           Show this help

Exit codes
  0  checked and installed (or nothing to install)
  1  stopped: a package was blocked
  2  could not check (API unreachable, bad lockfile, rate limited) or usage error

Verdicts are risk signals, not guarantees. Anything not on the allow list that
scores "block" stops the install unless --warn-only is set.`;

// ── Argument parsing ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = { warnOnly: false, json: false, allow: new Set(), apiUrl: process.env.SPECTER_API_URL || DEFAULT_API_URL, help: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = (flag) => {
      if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) fail(`${flag} needs a value`);
      return v;
    };
    if (a === '--warn-only') opts.warnOnly = true;
    else if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--allow' || a.startsWith('--allow=')) opts.allow.add(parseAllow(value('--allow')));
    else if (a === '--api-url' || a.startsWith('--api-url=')) opts.apiUrl = value('--api-url');
    else rest.push(a);
  }
  opts.apiUrl = opts.apiUrl.replace(/\/+$/, '');
  return { opts, rest };
}

function parseAllow(spec) {
  const at = spec.lastIndexOf('@');
  if (at <= 0 || at === spec.length - 1) fail(`--allow expects <name>@<version>, got "${spec}"`);
  return spec;
}

/** Thrown instead of exiting on the spot: see the note in main() about process.exit() on Windows. */
class CliError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

function fail(message, code = EXIT.ERROR) {
  throw new CliError(message, code);
}

// ── npm ──────────────────────────────────────────────────────────────────

/** Prefer running npm's own CLI script with this node: no shell, so version specs like foo@^1 aren't mangled by cmd.exe. */
function npmInvocation(args) {
  const candidates = [
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'), // Windows
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'), // unix
  ];
  const cli = candidates.find(existsSync);
  return cli
    ? { cmd: process.execPath, args: [cli, ...args], shell: false }
    : { cmd: 'npm', args, shell: process.platform === 'win32' };
}

function runNpm(args, { quiet, stdout } = {}) {
  const { cmd, args: full, shell } = npmInvocation(args);
  return new Promise((done) => {
    const child = spawn(cmd, full, {
      shell,
      stdio: quiet ? ['ignore', 'pipe', 'pipe'] : ['inherit', stdout ?? 'inherit', 'inherit'],
    });
    let err = '';
    child.stderr?.on('data', (d) => (err += d));
    child.on('error', (e) => done({ code: EXIT.ERROR, stderr: String(e) }));
    child.on('close', (code) => done({ code: code ?? EXIT.ERROR, stderr: err }));
  });
}

// ── Lockfile resolution (no scripts run) ─────────────────────────────────

/**
 * Runs `npm install --package-lock-only --ignore-scripts <args>` in place and
 * returns the resulting lockfile. That command rewrites package.json (for a
 * new package) and package-lock.json, so both are snapshotted first and always
 * restored: a blocked package must never be left in the project.
 */
async function resolveLockfile(installArgs) {
  const files = ['package.json', 'package-lock.json'].map((f) => resolve(f));
  const snapshot = files.map((f) => (existsSync(f) ? readFileSync(f) : null));
  const restore = () =>
    files.forEach((f, i) => {
      if (snapshot[i] !== null) writeFileSync(f, snapshot[i]);
      else if (existsSync(f)) unlinkSync(f);
    });
  const onSignal = () => {
    restore();
    process.exit(130);
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  try {
    const res = await runNpm(['install', '--package-lock-only', '--ignore-scripts', ...installArgs], { quiet: true });
    if (res.code !== 0) {
      console.error(res.stderr.trim());
      fail(`npm could not resolve the dependency tree (exit ${res.code}); nothing was installed.`, EXIT.ERROR);
    }
    return JSON.parse(readFileSync(files[1], 'utf8'));
  } finally {
    restore();
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
  }
}

// ── Check API ────────────────────────────────────────────────────────────

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function checkLockfile(apiUrl, lockfile, log) {
  let last;
  for (let round = 1; round <= MAX_ROUNDS; round++) {
    let res;
    try {
      res = await fetch(`${apiUrl}/api/v1/check/lockfile`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(lockfile),
        signal: AbortSignal.timeout(90_000),
      });
    } catch (e) {
      throw new Error(`could not reach ${apiUrl} (${e.cause?.code ?? e.message})`);
    }
    const body = await res.json().catch(() => null);
    if (res.status === 200 || res.status === 202) {
      last = body;
      if (res.status === 200) return body;
      log(`  ${body.counts.pending} package(s) still being analyzed, asking again (${round}/${MAX_ROUNDS})…`);
      await sleep(ROUND_WAIT_MS);
      continue;
    }
    const hint = res.status === 404 ? ` (is the Specter API deployed at ${apiUrl}? Set SPECTER_API_URL or pass --api-url)` : '';
    throw new Error(`API returned ${res.status}: ${body?.message ?? 'no details'}${hint}`);
  }
  return last; // still incomplete after every round: reported as such
}

// ── Report ───────────────────────────────────────────────────────────────

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = paint('31'), yellow = paint('33'), green = paint('32'), dim = paint('2'), bold = paint('1');

/** Accepted versions leave the report and the overall verdict is recomputed without them. */
function applyAllowList(report, allow) {
  const allowed = report.packages.filter((p) => allow.has(`${p.name}@${p.version}`));
  const packages = report.packages.filter((p) => !allow.has(`${p.name}@${p.version}`));
  const count = (v) => packages.filter((p) => p.verdict === v).length;
  const counts = { allow: count('allow') + allowed.length, warn: count('warn'), block: count('block'), pending: count('pending') };
  const verdict = counts.block > 0 ? 'block' : counts.warn > 0 || counts.pending > 0 ? 'warn' : 'allow';
  return { ...report, verdict, counts, packages, allowed: allowed.map((p) => `${p.name}@${p.version}`) };
}

function printReport(report, log) {
  const flagged = report.packages.filter((p) => p.verdict === 'block' || p.verdict === 'warn');
  for (const p of flagged) {
    const tag = p.verdict === 'block' ? red('BLOCK') : yellow('WARN ');
    log(`  ${tag}  ${bold(`${p.name}@${p.version}`)}`);
    for (const s of p.signals.filter((s) => s.severity !== 'info').slice(0, 3)) {
      const id = s.advisoryId && !s.title.includes(s.advisoryId) ? dim(` (${s.advisoryId})`) : '';
      log(`         ${dim(`[${s.severity}]`)} ${s.title}${id}`);
    }
    if (p.review?.status === 'ok') log(`         ${dim(`LLM review: ${p.review.malicious}`)}`);
    else if (p.review?.status === 'failed') log(`         ${dim('LLM review failed; verdict based on the other checks')}`);
  }
  if (report.counts.pending > 0) log(`  ${yellow('?')} ${report.counts.pending} package(s) could not be analyzed in time and are unchecked.`);
  if (report.skipped > 0) log(dim(`  ${report.skipped} lockfile entr${report.skipped === 1 ? 'y' : 'ies'} skipped (workspace links, git or private-registry sources).`));
}

// ── Main ─────────────────────────────────────────────────────────────────

async function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  if (opts.help || rest.length === 0) {
    console.log(HELP);
    process.exit(rest.length === 0 && !opts.help ? EXIT.ERROR : EXIT.OK);
  }
  // `specter-guard install foo` is shorthand for `specter-guard npm install foo`
  if (['install', 'i', 'add', 'ci'].includes(rest[0])) rest.unshift('npm');
  const [tool, sub, ...npmArgs] = rest;
  if (tool !== 'npm') fail(`only \`npm\` is supported (got "${tool}"). Try: specter-guard npm install <pkg>`);
  if (!['install', 'i', 'add', 'ci'].includes(sub)) fail(`only \`npm install\` and \`npm ci\` are guarded (got "npm ${sub ?? ''}").`);
  if (!existsSync('package.json')) fail('no package.json in the current directory.');

  const log = opts.json ? console.error : console.log;
  const isCi = sub === 'ci';

  let lockfile;
  if (isCi) {
    if (!existsSync('package-lock.json')) fail('`npm ci` needs an existing package-lock.json.');
    lockfile = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  } else {
    log(dim('specter-guard: resolving the dependency tree (no scripts are run)…'));
    lockfile = await resolveLockfile(npmArgs);
  }

  let report;
  try {
    log(dim(`specter-guard: checking against ${opts.apiUrl}…`));
    report = await checkLockfile(opts.apiUrl, lockfile, log);
  } catch (e) {
    // Fail closed by default: a guard that lets everything through when it can't check is no guard.
    if (opts.warnOnly) {
      console.error(`specter-guard: ${e.message}. Continuing because --warn-only is set.`);
      process.exitCode = (await runNpm([sub, ...npmArgs], { stdout: opts.json ? 2 : undefined })).code;
      return;
    }
    fail(`${e.message}. Nothing was installed (use --warn-only to install anyway).`);
  }

  report = applyAllowList(report, opts.allow);
  const stopped = report.verdict === 'block' && !opts.warnOnly;

  if (opts.json) {
    const flagged = report.packages.filter((p) => p.verdict !== 'allow');
    console.log(JSON.stringify({ verdict: report.verdict, stopped, complete: report.complete, counts: report.counts, checked: report.checked, skipped: report.skipped, allowed: report.allowed, packages: flagged }, null, 2));
  } else {
    printReport(report, log);
    const n = report.checked;
    if (report.verdict === 'allow') log(green(`✓ ${n} package(s) checked, nothing to flag.`));
    else if (stopped) log(red(`✗ Install stopped: ${report.counts.block} blocked package(s) out of ${n}. Use --allow <pkg@ver> to accept one, or --warn-only.`));
    else log(yellow(`! ${n} package(s) checked; ${report.counts.block + report.counts.warn} flagged. Continuing.`));
  }

  // Set the exit code and let the event loop drain instead of calling process.exit():
  // on Windows, exiting while fetch still has sockets open trips a libuv assertion
  // and the real code (1 = blocked) is lost to a crash code.
  if (stopped) {
    process.exitCode = EXIT.BLOCKED;
    return;
  }
  const res = await runNpm([sub, ...npmArgs], { stdout: opts.json ? 2 : undefined });
  process.exitCode = res.code;
}

main().catch((e) => {
  console.error(`specter-guard: ${e?.message ?? String(e)}`);
  process.exitCode = e instanceof CliError ? e.code : EXIT.ERROR;
});
