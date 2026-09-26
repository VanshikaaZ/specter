// Full-tree resolution for `--deep`: what would `npm install <args>` put in
// the lockfile, including transitive dependencies (the event-stream →
// flatmap-stream shape)? Same approach as specter-guard
// (`npm install --package-lock-only --ignore-scripts`), but run in a temporary
// copy of the project so the real package.json and lockfile are never touched.

import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

/** npm's own CLI script run with this node: no shell, so specs like foo@^1 survive cmd.exe. */
export function npmInvocation(args, script = 'npm-cli.js') {
  const candidates = [
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', script), // Windows
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', script), // unix
  ];
  const cli = candidates.find(existsSync);
  const bin = script === 'npx-cli.js' ? 'npx' : 'npm';
  return cli
    ? { cmd: process.execPath, args: [cli, ...args], shell: false }
    : { cmd: bin, args, shell: process.platform === 'win32' };
}

/**
 * Returns the resolved lockfile object, or throws with npm's error. `deadline`
 * is an absolute time; npm is killed if it runs past it.
 */
export async function resolveTree(projectDir, installArgs, deadline) {
  if (!existsSync(join(projectDir, 'package.json'))) throw new Error(`no package.json in ${projectDir}`);
  const tmp = mkdtempSync(join(tmpdir(), 'specter-deep-'));
  try {
    for (const f of ['package.json', 'package-lock.json', '.npmrc']) {
      if (existsSync(join(projectDir, f))) copyFileSync(join(projectDir, f), join(tmp, f));
    }
    const { cmd, args, shell } = npmInvocation(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', ...installArgs]);
    const { code, stderr } = await new Promise((done) => {
      const child = spawn(cmd, args, { cwd: tmp, shell, stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, SPECTER_SHIM_ACTIVE: '1' } });
      let err = '';
      child.stderr.on('data', (d) => (err += d));
      const timer = setTimeout(() => child.kill(), Math.max(deadline - Date.now(), 1000));
      child.on('error', (e) => { clearTimeout(timer); done({ code: -1, stderr: String(e) }); });
      child.on('close', (c) => { clearTimeout(timer); done({ code: c ?? -1, stderr: err }); });
    });
    if (code !== 0) throw new Error(`npm could not resolve the tree: ${stderr.trim().split('\n').slice(-2).join(' ') || `exit ${code}`}`);
    return JSON.parse(readFileSync(join(tmp, 'package-lock.json'), 'utf8'));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
