// Runs one package in a throwaway Docker container and returns what it did.
//
// Two containers per run, sharing one scratch volume (a Docker-managed volume,
// not a host folder):
//
//   1. INSTALL  network on, no scripts.  `npm install --ignore-scripts` downloads
//               the package and its dependencies. No package code runs, and this
//               container holds no fake or real secrets.
//   2. RUN      network OFF, fake credentials planted, under strace.  Install
//               scripts are run, the package is require()d, then it idles. Any
//               attempt to reach the network fails, but is still recorded.
//
// Both containers: unprivileged user, every capability dropped, no-new-privileges,
// CPU / memory / process / file-size limits, no host mounts, no Docker socket.
// Both are removed afterwards, along with the volume.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeTrace } from './analyze-trace.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const IMAGE = process.env.SANDBOX_IMAGE || 'specter-sandbox';
export const NAME_PREFIX = 'specter-sbx-';

const INSTALL_TIMEOUT_MS = Number(process.env.SANDBOX_INSTALL_TIMEOUT_MS) || 120_000;
const RUN_TIMEOUT_MS = Number(process.env.SANDBOX_RUN_TIMEOUT_MS) || 90_000;
const MAX_TRACE_BYTES = 40 * 1024 * 1024;

const PACKAGE_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$/i;

/** Flags shared by both containers. Nothing here may be loosened without a good reason. */
const HARDENING = [
  '--user=sandbox',
  '--cap-drop=ALL',
  '--security-opt=no-new-privileges',
  '--memory=512m', '--memory-swap=512m',
  '--cpus=1',
  '--pids-limit=256',
  '--ulimit=nofile=1024',
  '--ulimit=fsize=209715200',
];

/**
 * `docker run` arguments for the container that executes the package. Exported so
 * the isolation tests (scripts/sandbox-test.mts) check the very flags used here.
 */
export function runArgs({ name, volume, canary, command }) {
  return [
    'run', '--rm', '--name', name, ...HARDENING,
    '--network=none',
    // Point name lookups at loopback: the query is then sent (and traced, host name included) instead of failing on an unreachable resolver
    '--dns=127.0.0.1',
    '--read-only',
    '--tmpfs=/tmp:rw,size=64m,mode=1777',
    '--tmpfs=/home/sandbox:rw,size=64m,uid=10001,gid=10001,mode=700',
    '-v', `${volume}:/work`,
    '-e', 'HOME=/home/sandbox',
    '-e', `SPECTER_CANARY=${canary}`,
    '-e', `NPM_TOKEN=${canary}-npm-env`,
    '-e', `GITHUB_TOKEN=${canary}-github-env`,
    '-e', `AWS_ACCESS_KEY_ID=${canary}-aws-id-env`,
    '-e', `AWS_SECRET_ACCESS_KEY=${canary}-aws-secret-env`,
    '--entrypoint', 'sh',
    IMAGE,
    ...command,
  ];
}

// ── docker CLI ───────────────────────────────────────────────────────────

/** Runs `docker <args>`. Output past `maxBytes` is dropped (and flagged) so a noisy package can't fill memory. */
export function docker(args, { timeoutMs = 60_000, maxBytes = 2 * 1024 * 1024, input } = {}) {
  return new Promise((resolve) => {
    const child = spawn('docker', args, { stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], windowsHide: true });
    if (input !== undefined) child.stdin.on('error', () => {}).end(input);
    const out = { stdout: '', stderr: '', truncated: false, timedOut: false, code: null };
    const collect = (key) => (chunk) => {
      if (out[key].length + chunk.length > maxBytes) out.truncated = true;
      else out[key] += chunk;
    };
    child.stdout.setEncoding('utf8').on('data', collect('stdout'));
    child.stderr.setEncoding('utf8').on('data', collect('stderr'));
    const timer = setTimeout(() => { out.timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    child.on('error', (err) => { clearTimeout(timer); resolve({ ...out, code: -1, stderr: out.stderr + String(err) }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ ...out, code }); });
  });
}

export async function dockerAvailable() {
  const r = await docker(['version', '--format', '{{.Server.Version}}'], { timeoutMs: 15_000 });
  return r.code === 0;
}

let imageReady = null;
/** Builds the sandbox image on first use. */
export function ensureImage() {
  imageReady ??= (async () => {
    if ((await docker(['image', 'inspect', IMAGE], { timeoutMs: 15_000 })).code === 0) return;
    console.log(`[sandbox] building image ${IMAGE} (first run only)...`);
    const build = await docker(['build', '-t', IMAGE, HERE], { timeoutMs: 600_000 });
    if (build.code !== 0) throw new Error(`docker build failed: ${build.stderr.slice(-500)}`);
  })().catch((err) => { imageReady = null; throw err; });
  return imageReady;
}

/** Removes containers and volumes a crashed earlier run left behind. */
export async function cleanupLeftovers() {
  const containers = await docker(['ps', '-aq', '--filter', `name=${NAME_PREFIX}`]);
  const ids = containers.stdout.split('\n').filter(Boolean);
  if (ids.length) await docker(['rm', '-f', ...ids]);
  const volumes = await docker(['volume', 'ls', '-q', '--filter', `name=${NAME_PREFIX}`]);
  const names = volumes.stdout.split('\n').filter(Boolean);
  if (names.length) await docker(['volume', 'rm', '-f', ...names]);
}

// ── one run ──────────────────────────────────────────────────────────────

/**
 * @param {{name?: string, version?: string, fixture?: string}} target
 *   A registry package, or (tests only) a folder under fixtures/.
 */
export async function runSandbox(target) {
  const started = Date.now();
  const id = randomBytes(6).toString('hex');
  const volume = `${NAME_PREFIX}${id}`;
  const installName = `${NAME_PREFIX}${id}-install`;
  const runName = `${NAME_PREFIX}${id}-run`;
  const canary = `specter-canary-${randomBytes(6).toString('hex')}`;

  const result = { target: '', phases: {}, events: [], truncated: false };
  try {
    await ensureImage();
    await docker(['volume', 'create', volume]);

    // ── phase 1: install, no scripts ──
    let installSpec;
    if (target.fixture) {
      if (!/^[a-z0-9-]+$/i.test(target.fixture)) throw new BadRequest('invalid fixture');
      result.target = `fixture:${target.fixture}`;
      await stageFixture(target.fixture, volume);
      installSpec = './fixture-src';
    } else {
      if (!PACKAGE_NAME.test(target.name ?? '') || !VERSION.test(target.version ?? '')) throw new BadRequest('invalid package name or version');
      result.target = `${target.name}@${target.version}`;
      installSpec = `${target.name}@${target.version}`;
    }
    const install = await docker([
      'run', '--rm', '--name', installName, ...HARDENING,
      // The container must not reach services on the host it runs on
      '--add-host=host.docker.internal:127.0.0.1',
      '-v', `${volume}:/work`,
      IMAGE,
      'npm', 'install', '--prefix', '/work', '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock',
      '--install-links', '--loglevel=error', installSpec,
    ], { timeoutMs: INSTALL_TIMEOUT_MS });
    result.phases.install = {
      ok: install.code === 0,
      timedOut: install.timedOut,
      error: install.code === 0 ? undefined : (install.stderr.trim().split('\n').slice(-3).join(' ').slice(0, 300) || 'install failed'),
    };
    if (install.code !== 0) return finish(result, started);

    // ── phase 2: run, no network, honeypots planted ──
    const pkgName = target.fixture ? await fixtureName(target.fixture) : target.name;
    const run = await docker(
      runArgs({ name: runName, volume, canary, command: ['/opt/specter/entry.sh', pkgName] }),
      { timeoutMs: RUN_TIMEOUT_MS, maxBytes: MAX_TRACE_BYTES },
    );

    result.phases.run = { ok: run.code === 0 && !run.timedOut, timedOut: run.timedOut, exitCode: run.code };
    result.truncated = run.truncated;
    result.events = run.stderr.split('\n')
      .filter((l) => l.startsWith('@@SPECTER '))
      .map((l) => { try { return JSON.parse(l.slice('@@SPECTER '.length)); } catch { return null; } })
      .filter(Boolean)
      .slice(0, 100);
    if (process.env.SANDBOX_DEBUG_TRACE) await (await import('node:fs/promises')).writeFile(process.env.SANDBOX_DEBUG_TRACE, run.stdout);
    Object.assign(result, analyzeTrace(run.stdout, { canary }));
    return finish(result, started);
  } finally {
    await docker(['rm', '-f', installName, runName]);
    await docker(['volume', 'rm', '-f', volume]);
  }
}

export class BadRequest extends Error {}

function finish(result, started) {
  result.durationMs = Date.now() - started;
  return result;
}

// ── fixtures (tests only; the server refuses them unless SANDBOX_ENABLE_FIXTURES=1) ──

const fixtureDir = (name) => join(HERE, 'fixtures', name);

async function fixtureName(fixture) {
  const { readFile } = await import('node:fs/promises');
  return JSON.parse(await readFile(join(fixtureDir(fixture), 'package.json'), 'utf8')).name;
}

/** Writes a fixture folder into the volume as /work/fixture-src, as the sandbox user (files travel over stdin as JSON). */
async function stageFixture(fixture, volume) {
  const { readdir, readFile } = await import('node:fs/promises');
  const root = fixtureDir(fixture);
  const files = {};
  for (const entry of await readdir(root, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const full = join(entry.parentPath, entry.name);
    files[full.slice(root.length + 1).split(sep).join('/')] = await readFile(full, 'utf8');
  }
  const writer = 'const fs=require("fs"),p=require("path");const f=JSON.parse(require("fs").readFileSync(0,"utf8"));' +
    'for(const[k,v]of Object.entries(f)){const t=p.join("/work/fixture-src",k);fs.mkdirSync(p.dirname(t),{recursive:true});fs.writeFileSync(t,v)}';
  const stage = await docker(['run', '--rm', '-i', ...HARDENING, '--network=none', '-v', `${volume}:/work`, IMAGE, 'node', '-e', writer],
    { input: JSON.stringify(files) });
  if (stage.code !== 0) throw new Error(`fixture staging failed: ${stage.stderr.slice(-300)}`);
}
