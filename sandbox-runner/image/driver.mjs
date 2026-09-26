// Runs inside the sandbox container, under strace, with no network.
//
//   node driver.mjs <package-name>
//
// 1. Runs the install-time scripts (preinstall / install / postinstall) of every
//    package the earlier `npm install --ignore-scripts` put in /work, the
//    target last. Scripts are run directly rather than through npm: npm reads
//    ~/.npmrc itself, which would trip the honeypot on every benign package.
// 2. require()s the target, falling back to import() for ESM-only packages.
// 3. Idles for a few seconds so timers and delayed payloads get a chance to fire.
//
// Progress goes to stderr as `@@SPECTER {json}` lines (stdout carries the strace
// trace). Nothing here decides whether the package is bad: the runner reads the
// trace for that.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const WORK = '/work';
const MODULES = join(WORK, 'node_modules');
const IDLE_MS = Number(process.env.SPECTER_IDLE_MS) || 5000;
const SCRIPT_TIMEOUT_MS = 30_000;
const LOAD_TIMEOUT_MS = 20_000;
const HOOKS = ['preinstall', 'install', 'postinstall'];

const target = process.argv[2];
if (!target) throw new Error('usage: driver.mjs <package-name>');

const emit = (event) => process.stderr.write(`@@SPECTER ${JSON.stringify(event)}\n`);

const firstLine = (buf) => buf?.toString().trim().split('\n')[0]?.slice(0, 200) || undefined;

function readManifest(dir) {
  try {
    return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  } catch {
    return null;
  }
}

/** Every installed package directory, including nested node_modules. */
function packageDirs(modulesDir, out = []) {
  let names;
  try {
    names = readdirSync(modulesDir);
  } catch {
    return out;
  }
  for (const name of names) {
    if (name.startsWith('.')) continue;
    const scoped = name.startsWith('@');
    for (const sub of scoped ? readdirSync(join(modulesDir, name)) : [null]) {
      const dir = scoped ? join(modulesDir, name, sub) : join(modulesDir, name);
      if (!existsSync(join(dir, 'package.json'))) continue;
      out.push(dir);
      packageDirs(join(dir, 'node_modules'), out);
    }
  }
  return out;
}

const dirs = packageDirs(MODULES);
const targetDir = join(MODULES, target);
dirs.sort((a, b) => Number(a === targetDir) - Number(b === targetDir));

const PATH = [join(MODULES, '.bin'), process.env.PATH].filter(Boolean).join(':');

for (const dir of dirs) {
  const manifest = readManifest(dir);
  if (!manifest?.scripts) continue;
  for (const hook of HOOKS) {
    const command = manifest.scripts[hook];
    if (typeof command !== 'string') continue;
    const result = spawnSync('sh', ['-c', command], {
      cwd: dir,
      env: {
        ...process.env,
        PATH: join(dir, 'node_modules', '.bin') + ':' + PATH,
        npm_lifecycle_event: hook,
        npm_package_name: manifest.name,
        npm_package_version: manifest.version,
      },
      timeout: SCRIPT_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    emit({
      event: 'script', package: manifest.name, hook, command: command.slice(0, 200),
      status: result.status, signal: result.signal,
      timedOut: result.error?.code === 'ETIMEDOUT',
      error: result.status ? firstLine(result.stderr) : undefined,
    });
  }
}

// Load the target in a child process so a crash or process.exit() in the
// package can't end the run early, then idle inside it.
const loader = `
const name = ${JSON.stringify(target)};
const done = () => setTimeout(() => process.exit(0), ${IDLE_MS});
try { require(name); done(); }
catch (err) {
  if (err && (err.code === 'ERR_REQUIRE_ESM' || err.code === 'ERR_REQUIRE_ASYNC_MODULE')) {
    import(name).then(done, (e) => { console.error(String(e && e.message || e)); done(); });
  } else { console.error(String(err && err.message || err)); done(); }
}`;
const load = spawnSync(process.execPath, ['-e', loader], {
  cwd: WORK,
  env: { ...process.env, PATH },
  timeout: LOAD_TIMEOUT_MS,
  maxBuffer: 1024 * 1024,
  stdio: ['ignore', 'pipe', 'pipe'],
});
emit({
  event: 'load', package: target, status: load.status, signal: load.signal,
  timedOut: load.error?.code === 'ETIMEDOUT',
  error: load.stderr?.toString().trim().split('\n')[0]?.slice(0, 200) || undefined,
});
emit({ event: 'done' });
