// PATH shims: small npm/npx/pnpm/yarn/bun/bunx scripts placed first on PATH,
// so every install, by any agent or human, is checked before it runs.
//
//   specter-guard-mcp shim install [--dir <dir>]   writes the shims
//   specter-guard-mcp shim uninstall [--dir <dir>]
//   specter-guard-mcp shim-exec <tool> [args...]   what each shim runs
//
// A non-install command passes straight through to the real binary. An
// install is checked first: `block` stops it (exit 1), a failed check stops it
// (exit 2, fail closed), `warn` is printed and the install continues, the same
// policy as specter-guard. SPECTER_GUARD=off (set by the user) disables the
// check; SPECTER_GUARD=warn-only reports but never stops.

import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkTargets, configFromEnv } from './api.mjs';
import { toText } from './format.mjs';
import { parseArgv } from './parseCommand.mjs';

export const SHIM_TOOLS = ['npm', 'npx', 'pnpm', 'yarn', 'bun', 'bunx'];
const ENTRY = fileURLToPath(new URL('../specter-mcp.mjs', import.meta.url));
const WIN = process.platform === 'win32';

export const defaultShimDir = () => process.env.SPECTER_SHIM_DIR || join(homedir(), '.specter', 'bin');

export function installShims(dir = defaultShimDir()) {
  mkdirSync(dir, { recursive: true });
  for (const tool of SHIM_TOOLS) {
    // POSIX script (also what Git Bash on Windows runs) and a .cmd for cmd/PowerShell
    const sh = join(dir, tool);
    writeFileSync(sh, `#!/bin/sh\n# specter-guard-mcp shim\nexec "${process.execPath}" "${ENTRY}" shim-exec ${tool} "$@"\n`);
    chmodSync(sh, 0o755);
    writeFileSync(join(dir, `${tool}.cmd`), `@rem specter-guard-mcp shim\r\n@"${process.execPath}" "${ENTRY}" shim-exec ${tool} %*\r\n`);
  }
  return dir;
}

export function uninstallShims(dir = defaultShimDir()) {
  for (const tool of SHIM_TOOLS) {
    for (const f of [tool, `${tool}.cmd`]) rmSync(join(dir, f), { force: true });
  }
  return dir;
}

const norm = (p) => (WIN ? resolve(p).toLowerCase() : resolve(p));

/** The real binary: first match on PATH that isn't in the shim directory. */
export function findRealBinary(tool, shimDir = defaultShimDir(), pathEnv = process.env.PATH ?? process.env.Path ?? '') {
  const skip = norm(shimDir);
  const exts = WIN ? ['.cmd', '.exe', '.bat', ''] : [''];
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir || norm(dir) === skip) continue;
    for (const ext of exts) {
      const candidate = join(dir, tool + ext);
      try {
        if (statSync(candidate).isFile()) return candidate;
      } catch {
        // not here
      }
    }
  }
  return null;
}

/** cmd.exe quoting: inside double quotes ^ & | < > are literal, so foo@^1 survives. */
const quoteWin = (a) => `"${String(a).replace(/"/g, '""')}"`;

function run(bin, args, env) {
  const viaCmd = WIN && /\.(cmd|bat)$/i.test(bin);
  const child = viaCmd
    ? spawn(`"${bin}" ${args.map(quoteWin).join(' ')}`, { stdio: 'inherit', shell: true, env })
    : spawn(bin, args, { stdio: 'inherit', env });
  return new Promise((done) => {
    child.on('error', (e) => {
      console.error(`specter-guard: could not run ${bin}: ${e.message}`);
      done(2);
    });
    child.on('close', (code) => done(code ?? 1));
  });
}

/** specter-guard does the full-tree check for npm install/ci, when it is available (repo checkout or SPECTER_GUARD_CLI). */
function findSpecterGuard() {
  const candidates = [process.env.SPECTER_GUARD_CLI, join(dirname(ENTRY), '..', 'cli', 'specter-guard.mjs')].filter(Boolean);
  return candidates.find((p) => existsSync(p)) ?? null;
}

const NPM_GUARDED = new Set(['install', 'i', 'add', 'ci']);

export async function shimExec(tool, args) {
  const shimDir = defaultShimDir();
  const real = findRealBinary(tool, shimDir);
  if (!real) {
    console.error(`specter-guard: no real \`${tool}\` found on PATH outside ${shimDir}.`);
    return 127;
  }
  // Our own child processes (and the install we already checked) pass straight through
  const env = { ...process.env, SPECTER_SHIM_ACTIVE: '1' };
  const mode = (process.env.SPECTER_GUARD ?? '').toLowerCase();
  if (mode === 'off' || process.env.SPECTER_SHIM_ACTIVE === '1') return run(real, args, env);

  const targets = parseArgv(tool, args, process.cwd());
  if (targets.length === 0) return run(real, args, env);

  const config = configFromEnv();
  const guard = findSpecterGuard();
  if (guard && tool === 'npm' && NPM_GUARDED.has(args[0])) {
    const guardArgs = [guard, 'npm', ...args, '--api-url', config.apiUrl, ...(mode === 'warn-only' ? ['--warn-only'] : [])];
    return run(process.execPath, guardArgs, env);
  }

  console.error(`specter-guard: checking ${targets.length} target(s) against ${config.apiUrl}…`);
  const result = await checkTargets(targets, { config, deadline: Date.now() + 90_000 });
  console.error(toText(result));

  const couldNotCheck = result.packages.some((p) => p.reasons.some((r) => r.type === 'unverified'));
  if (mode !== 'warn-only') {
    if (result.verdict === 'block') {
      console.error('specter-guard: install stopped (blocked package). Set SPECTER_GUARD=off yourself to override.');
      return 1;
    }
    if (couldNotCheck) {
      console.error('specter-guard: install stopped because it could not be verified. Set SPECTER_GUARD=warn-only to continue anyway.');
      return 2;
    }
  }
  return run(real, args, env);
}
