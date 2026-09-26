import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findRealBinary, installShims, uninstallShims, SHIM_TOOLS } from '../lib/shim.mjs';
import { startStub } from './stub.mjs';

const ENTRY = fileURLToPath(new URL('../specter-mcp.mjs', import.meta.url));
const WIN = process.platform === 'win32';
let stub, shimDir, realDir, marker;

before(async () => {
  stub = await startStub();
  shimDir = mkdtempSync(join(tmpdir(), 'specter-shim-'));
  realDir = mkdtempSync(join(tmpdir(), 'specter-real-'));
  marker = join(realDir, 'ran.txt');
  // A fake "real" pnpm that records its arguments instead of installing anything
  for (const tool of ['pnpm', 'npx']) {
    if (WIN) writeFileSync(join(realDir, `${tool}.cmd`), `@echo ${tool} %*> "${marker}"\r\n`);
    else {
      writeFileSync(join(realDir, tool), `#!/bin/sh\necho "${tool} $*" > "${marker}"\n`);
      chmodSync(join(realDir, tool), 0o755);
    }
  }
});
after(() => stub.close());

function shimExec(args, extraEnv = {}) {
  rmSync(marker, { force: true });
  return new Promise((done) => {
    const child = spawn(process.execPath, [ENTRY, 'shim-exec', ...args], {
      env: { ...process.env, ...stub.env, SPECTER_SHIM_DIR: shimDir, PATH: `${shimDir}${delimiter}${realDir}`, Path: undefined, SPECTER_SHIM_ACTIVE: '', ...extraEnv },
    });
    let err = '';
    child.stderr.on('data', (d) => (err += d));
    // A .cmd sees %* with our cmd.exe quoting still on; the real tool's own .cmd strips it
    const ran = () => readFileSync(marker, 'utf8').trim().replace(/"/g, '');
    child.on('close', (code) => done({ code, err, ran: existsSync(marker) ? ran() : null }));
  });
}

test('install/uninstall writes a POSIX script and a .cmd per tool', () => {
  installShims(shimDir);
  for (const t of SHIM_TOOLS) {
    assert.match(readFileSync(join(shimDir, t), 'utf8'), /shim-exec/);
    assert.match(readFileSync(join(shimDir, `${t}.cmd`), 'utf8'), /shim-exec/);
  }
  assert.equal(findRealBinary('pnpm', shimDir, `${shimDir}${delimiter}${realDir}`), join(realDir, WIN ? 'pnpm.cmd' : 'pnpm'));
  uninstallShims(shimDir);
  assert.ok(!existsSync(join(shimDir, 'pnpm')));
});

test('non-install commands pass straight through', async () => {
  const r = await shimExec(['pnpm', 'run', 'build']);
  assert.equal(r.code, 0);
  assert.equal(r.ran, 'pnpm run build');
});

test('a blocked package stops the install before the real binary runs', async () => {
  const r = await shimExec(['pnpm', 'add', 'bad-pkg']);
  assert.equal(r.code, 1);
  assert.equal(r.ran, null);
  assert.match(r.err, /BLOCK {2}bad-pkg@6\.6\.6/);
});

test('allow runs the real install, and version specs reach it intact', async () => {
  const r = await shimExec(['pnpm', 'add', 'good-pkg@^1.0.0']);
  assert.equal(r.code, 0);
  assert.equal(r.ran, 'pnpm add good-pkg@^1.0.0');
});

test('warn is reported and the install continues', async () => {
  const r = await shimExec(['npx', 'warn-pkg@1.0.0']);
  assert.equal(r.code, 0);
  assert.match(r.err, /WARN/);
  assert.equal(r.ran, 'npx warn-pkg@1.0.0');
});

test('fail closed when the API is down; SPECTER_GUARD=warn-only and =off override', async () => {
  const down = { SPECTER_API_URL: 'http://127.0.0.1:9' };
  assert.equal((await shimExec(['pnpm', 'add', 'good-pkg@1.0.0'], down)).code, 2);
  assert.equal((await shimExec(['pnpm', 'add', 'good-pkg@1.0.0'], { ...down, SPECTER_GUARD: 'warn-only' })).code, 0);
  const off = await shimExec(['pnpm', 'add', 'bad-pkg'], { SPECTER_GUARD: 'off' });
  assert.equal(off.code, 0);
  assert.equal(off.ran, 'pnpm add bad-pkg');
});
