// Turns a shell command ("cd web && npm i -D a b@2") into the packages it
// would fetch from the npm registry. Shared by the MCP tools, the Claude Code
// hook and the PATH shims, so all three agree on what a command installs.
//
// A target is one of:
//   { kind: 'package',     manager, name, spec, raw, cwd, exec }  registry package; spec '' = latest
//   { kind: 'lockfile',    manager, path, raw, cwd }              bare `npm install` / `npm ci`
//   { kind: 'unsupported', manager, raw, reason, cwd }            something we cannot check

import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';

// npm's own name rule, same as src/lib/packages/validate.ts
const NAME_RE = /^(?:@[a-z0-9-*~][a-z0-9-*._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

export function isValidPackageName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= 214 && NAME_RE.test(name);
}

// ── Shell tokenizing ─────────────────────────────────────────────────────

const OPERATORS = ['&&', '||', ';', '|', '&', '\n', '(', ')'];

/**
 * Splits a command line into segments (one per simple command) of word
 * tokens. Handles single/double quotes and backslash escapes, and splits on
 * && || ; | & ( ) and newlines outside quotes. It is not a full shell parser:
 * anything it cannot see through (eval, $(...) contents, scripts) is simply
 * not recognised as an install.
 */
export function splitCommands(command) {
  const segments = [];
  let tokens = [];
  let cur = '';
  let inToken = false;
  let quote = null;
  const endToken = () => {
    if (inToken) tokens.push(cur);
    cur = '';
    inToken = false;
  };
  const endSegment = () => {
    endToken();
    if (tokens.length) segments.push(tokens);
    tokens = [];
  };

  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === quote) quote = null;
      // Inside double quotes a backslash only escapes $ ` " \ and newline (so C:\path survives)
      else if (c === '\\' && quote === '"' && '$`"\\\n'.includes(command[i + 1] ?? '')) cur += command[++i];
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      inToken = true;
      continue;
    }
    if (c === '\\' && i + 1 < command.length) {
      const next = command[++i];
      if (next !== '\n') {
        cur += next;
        inToken = true;
      }
      continue;
    }
    const op = OPERATORS.find((o) => command.startsWith(o, i));
    if (op) {
      endSegment();
      i += op.length - 1;
      continue;
    }
    if (/\s/.test(c)) {
      endToken();
      continue;
    }
    cur += c;
    inToken = true;
  }
  endSegment();
  return segments;
}

// ── Package specs ────────────────────────────────────────────────────────

const NON_REGISTRY_SPEC = /^(git\+|git:|github:|gitlab:|bitbucket:|gist:|file:|link:|workspace:|portal:|patch:|jsr:|https?:|ssh:)/i;
const PATHLIKE = /^(\.{1,2}[\\/]|[\\/]|~[\\/]|[A-Za-z]:[\\/])/;
const TARBALL = /\.(tgz|tar\.gz|tar)$/i;

/**
 * "lodash" → { name: 'lodash', spec: '' }, "@s/p@^1" → { name: '@s/p', spec: '^1' },
 * "x@npm:y@2" (alias) → { name: 'y', spec: '2' }. Non-registry sources
 * (git, URLs, paths, tarballs, workspace:) come back as { nonRegistry }.
 */
export function parseSpec(token) {
  if (NON_REGISTRY_SPEC.test(token) || PATHLIKE.test(token) || TARBALL.test(token)) {
    return { nonRegistry: `"${token}" is not a registry package (git, URL, path or tarball)` };
  }
  let name = token;
  let spec = '';
  const at = token.indexOf('@', token.startsWith('@') ? 1 : 0);
  if (at > 0) {
    name = token.slice(0, at);
    spec = token.slice(at + 1);
  }
  // GitHub shorthand: user/repo (an unscoped name never contains "/")
  if (!name.startsWith('@') && name.includes('/')) {
    return { nonRegistry: `"${token}" is a GitHub shorthand, not a registry package` };
  }
  if (spec.startsWith('npm:')) {
    const inner = parseSpec(spec.slice(4));
    return inner.nonRegistry ? inner : { ...inner, alias: name };
  }
  if (NON_REGISTRY_SPEC.test(spec)) {
    return { nonRegistry: `"${token}" points at a non-registry source (${spec.split(':')[0]}:)` };
  }
  if (!isValidPackageName(name)) return { invalid: `"${name}" is not a valid npm package name` };
  return { name, spec };
}

// ── Per-manager grammar ──────────────────────────────────────────────────

const NPM_INSTALL = new Set(['install', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall', 'add', 'install-test', 'it']);
const NPM_CI = new Set(['ci', 'clean-install', 'ic', 'install-clean', 'isntall-clean', 'install-ci-test', 'cit']);
const NPM_EXEC = new Set(['exec', 'x']);

// Flags that take a separate value ("--prefix dir"); everything else is treated as boolean.
const VALUE_FLAGS = {
  npm: new Set(['--prefix', '--registry', '-w', '--workspace', '--tag', '--omit', '--include', '--install-strategy', '--cache', '--userconfig', '--globalconfig', '--loglevel', '--save-prefix', '--before', '--cpu', '--os', '--libc', '-C', '--call', '-c']),
  pnpm: new Set(['-C', '--dir', '--filter', '-F', '--reporter', '--registry', '--store-dir', '--virtual-store-dir', '--loglevel', '--config', '--workspace-concurrency', '--resolution-mode', '--node-linker']),
  yarn: new Set(['--cwd', '--registry', '--modules-folder', '--cache-folder', '--mutex', '--network-timeout', '--link-folder', '--global-folder', '--use-yarnrc']),
  bun: new Set(['--cwd', '--registry', '--cache-dir', '--backend', '-c', '--config', '--omit', '--filter']),
};

/** Splits args into positionals and { flag: value } pairs; stops flag parsing at `--`. */
function scanArgs(args, manager) {
  const valueFlags = VALUE_FLAGS[manager];
  const positionals = [];
  const flags = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith('-') && a.length > 1) {
      const eq = a.indexOf('=');
      if (eq > 0) flags.push([a.slice(0, eq), a.slice(eq + 1)]);
      else if (valueFlags.has(a) && i + 1 < args.length) flags.push([a, args[++i]]);
      else flags.push([a, true]);
      continue;
    }
    positionals.push(a);
  }
  return { positionals, flags };
}

const flagValues = (flags, ...names) => flags.filter(([f]) => names.includes(f)).map(([, v]) => v).filter((v) => typeof v === 'string');

/** Is `bin` already installed locally (node_modules/.bin in cwd or a parent)? Then npx runs it without fetching. */
function hasLocalBin(bin, cwd) {
  let dir = cwd;
  for (;;) {
    const binDir = join(dir, 'node_modules', '.bin');
    if (['', '.cmd', '.ps1', '.exe'].some((ext) => existsSync(join(binDir, bin + ext)))) return true;
    const parent = dirname(dir);
    if (parent === dir) return false;
    dir = parent;
  }
}

function packageTargets(tokens, manager, cwd, exec = false) {
  return tokens.map((raw) => {
    const s = parseSpec(raw);
    if (s.nonRegistry) return { kind: 'unsupported', manager, raw, cwd, reason: `Cannot verify a non-registry source: ${s.nonRegistry}.` };
    if (s.invalid) return { kind: 'unsupported', manager, raw, cwd, reason: s.invalid };
    return { kind: 'package', manager, name: s.name, spec: s.spec, raw, cwd, exec };
  });
}

/** `npx pkg args`, `npm exec -p a -- cmd`, `pnpm dlx`, `yarn dlx`, `bunx`: only the fetched package(s). */
function execTargets(args, manager, cwd) {
  const valueFlags = VALUE_FLAGS[manager];
  const pkgs = [];
  let command = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') {
      command = args[i + 1] ?? null;
      break;
    }
    if (a === '-p' || a === '--package') {
      if (i + 1 < args.length) pkgs.push(args[++i]);
      continue;
    }
    if (a.startsWith('--package=')) {
      pkgs.push(a.slice('--package='.length));
      continue;
    }
    if (a === '-c' || a === '--call') return []; // runs a shell string, which fetches nothing by itself
    if (a.startsWith('-') && a.length > 1) {
      if (!a.includes('=') && valueFlags.has(a)) i++;
      continue;
    }
    command = a;
    break;
  }
  if (pkgs.length > 0) return packageTargets(pkgs, manager, cwd, true);
  if (!command) return [];
  const s = parseSpec(command);
  // npx prefers an already-installed binary: that runs local code, nothing is fetched
  if (!s.nonRegistry && !s.invalid && !s.spec && hasLocalBin(s.name, cwd)) return [];
  return packageTargets([command], manager, cwd, true);
}

function lockfileTarget(manager, cwd, raw) {
  if (manager !== 'npm') {
    return [{ kind: 'unsupported', manager, raw, cwd, reason: `\`${raw}\` installs from a ${manager} lockfile, which Specter cannot check yet (npm package-lock.json only).` }];
  }
  const path = join(cwd, 'package-lock.json');
  if (!existsSync(path)) {
    return [{ kind: 'unsupported', manager, raw, cwd, reason: `\`${raw}\` has no package-lock.json to check in ${cwd}, so npm will resolve versions that were never verified.` }];
  }
  return [{ kind: 'lockfile', manager, path, raw, cwd }];
}

/**
 * Targets for one invocation of a package manager, given as argv (without
 * the binary). Used directly by the PATH shims, which already have argv.
 */
export function parseArgv(tool, args, cwd = process.cwd()) {
  const manager = tool === 'npx' ? 'npm' : tool === 'bunx' ? 'bun' : tool;
  if (!VALUE_FLAGS[manager]) return [];
  const raw = [tool, ...args].join(' ');
  if (tool === 'npx' || tool === 'bunx') return execTargets(args, manager, cwd);

  // Global flags may come before the subcommand; a --prefix/--dir/--cwd changes the project directory
  const { positionals, flags } = scanArgs(args, manager);
  const dirFlag = flagValues(flags, '--prefix', '-C', '--dir', '--cwd').at(-1);
  const projectDir = dirFlag ? resolve(cwd, dirFlag) : cwd;
  let [sub, ...rest] = positionals;
  if (manager === 'yarn' && sub === 'global') [sub, ...rest] = rest;

  // Index of the subcommand in the original args, so exec parsing sees its flags too
  const afterSub = () => args.slice(args.indexOf(sub) + 1);

  switch (manager) {
    case 'npm':
      if (NPM_EXEC.has(sub)) return execTargets(afterSub(), manager, projectDir);
      if (NPM_CI.has(sub)) return lockfileTarget(manager, projectDir, raw);
      if (NPM_INSTALL.has(sub)) {
        if (rest.length > 0) return packageTargets(rest, manager, projectDir);
        return flags.some(([f]) => f === '-g' || f === '--global') ? [] : lockfileTarget(manager, projectDir, raw);
      }
      return [];
    case 'pnpm':
      if (sub === 'dlx') return execTargets(afterSub(), manager, projectDir);
      if (sub === 'add') return packageTargets(rest, manager, projectDir);
      if (sub === 'install' || sub === 'i') return rest.length ? packageTargets(rest, manager, projectDir) : lockfileTarget(manager, projectDir, raw);
      return [];
    case 'yarn':
      if (sub === 'dlx') return execTargets(afterSub(), manager, projectDir);
      if (sub === 'add') return packageTargets(rest, manager, projectDir);
      if (sub === undefined || sub === 'install') return lockfileTarget(manager, projectDir, raw);
      return [];
    case 'bun':
      if (sub === 'x') return execTargets(afterSub(), manager, projectDir);
      if (sub === 'add' || sub === 'a') return packageTargets(rest, manager, projectDir);
      if (sub === 'install' || sub === 'i') return rest.length ? packageTargets(rest, manager, projectDir) : lockfileTarget(manager, projectDir, raw);
      return [];
    default:
      return [];
  }
}

const WRAPPERS = new Set(['sudo', 'env', 'time', 'nohup', 'command', 'exec', 'nice', 'doas']);
const TOOLS = new Set(['npm', 'npx', 'pnpm', 'yarn', 'bun', 'bunx']);

/** "C:\\nodejs\\npm.cmd" → "npm" */
function toolName(token) {
  const base = token.split(/[\\/]/).pop().toLowerCase().replace(/\.(cmd|exe|ps1|bat|js)$/, '');
  return TOOLS.has(base) ? base : null;
}

/** Every package-manager target in a full command line. `cd` segments move the working directory for the ones after. */
export function parseInstallCommand(command, cwd = process.cwd()) {
  const targets = [];
  let dir = cwd;
  for (const seg of splitCommands(command)) {
    let i = 0;
    while (i < seg.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(seg[i]) || WRAPPERS.has(seg[i]))) i++;
    const words = seg.slice(i);
    if (words[0] === 'cd' || words[0] === 'pushd') {
      const to = words[1];
      if (to && to !== '-' && !to.startsWith('$') && !to.startsWith('~')) dir = isAbsolute(to) ? to : resolve(dir, to);
      continue;
    }
    const tool = words[0] && toolName(words[0]);
    if (tool) targets.push(...parseArgv(tool, words.slice(1), dir));
  }
  return targets;
}
